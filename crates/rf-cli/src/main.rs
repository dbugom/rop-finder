//! rop-finder — ROPgadget-compatible CLI (Phase 1: ELF, PE, Mach-O,
//! Universal/fat Mach-O, and raw blobs; all supported architectures).
//!
//! Format dispatch mirrors ROPgadget's `binary.py`: `--rawArch` forces the
//! raw loader regardless of magic bytes; otherwise magic-byte dispatch via
//! `rf_core::Binary::load`. Universal (fat Mach-O) binaries follow
//! ROPgadget's `universal.py`: every slice's executable regions are
//! concatenated and scanned with the FIRST slice's arch/mode/endianness
//! (universal.py:92-108 returns "whatever is in the first binary").
//!
//! Exit codes: 0 success, 1 usage error, 2 malformed/unsupported binary.

use std::process::ExitCode;

use clap::Parser;
use rf_core::{Arch, Binary, Endianness, Image, LoadedBinary, RawBinary, Section, UniversalBinary};
use rf_scan::{Gadget, ScanOptions};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(
    name = "rop-finder",
    version,
    about = "Fast Rust ROP/JOP/SYS gadget finder (ROPgadget rewrite)"
)]
struct Cli {
    /// Specify a binary filename to analyze
    #[arg(long)]
    binary: String,

    /// Depth for search engine (default 10)
    #[arg(long, default_value_t = 10)]
    depth: usize,

    /// Disable ROP search engine
    #[arg(long)]
    norop: bool,

    /// Disable JOP search engine
    #[arg(long)]
    nojop: bool,

    /// Disable SYS search engine
    #[arg(long)]
    nosys: bool,

    /// Enable multiple branch gadgets
    #[arg(long)]
    multibr: bool,

    /// Only show specific instructions (e.g. "pop|ret|mov")
    #[arg(long)]
    only: Option<String>,

    /// Suppress specific mnemonics (suffix match, e.g. "leave|enter")
    #[arg(long)]
    filter: Option<String>,

    /// Search between two addresses (0x...-0x...)
    #[arg(long)]
    range: Option<String>,

    /// Rejects specific bytes in the gadget's address (e.g. "0a|0d" or "00-1f")
    #[arg(long)]
    badbytes: Option<String>,

    /// Specify an offset for gadget addresses (hex)
    #[arg(long)]
    offset: Option<String>,

    /// Rebase the binary to this image base at load time (hex)
    #[arg(long)]
    base: Option<String>,

    /// Use the thumb mode for the search engine (ARM only)
    #[arg(long)]
    thumb: bool,

    /// Specify an arch for a raw file: x86|arm|arm64|sparc|mips|ppc|riscv
    #[arg(long = "rawArch", value_name = "<arch>")]
    raw_arch: Option<String>,

    /// Specify a mode for a raw file: 32|64|arm|thumb|riscv
    #[arg(long = "rawMode", value_name = "<mode>")]
    raw_mode: Option<String>,

    /// Specify an endianness for a raw file: little|big
    #[arg(long = "rawEndian", value_name = "<endian>")]
    raw_endian: Option<String>,

    /// Emit a JSON array of {vaddr, bytes, text} instead of human output
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct JsonGadget {
    vaddr: String,
    bytes: String,
    text: String,
    /// Scan architecture — present for Universal (multi-slice) binaries.
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<&'static str>,
}

fn parse_hex(s: &str, what: &str) -> Result<u64, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).map_err(|e| format!("invalid {what} {s:?}: {e}"))
}

/// ROPgadget --range syntax: "0xSTART-0xEND". "0x0-0x0" means no range.
fn parse_range(s: &str) -> Result<Option<(u64, u64)>, String> {
    let (a, b) = s
        .split_once('-')
        .ok_or_else(|| format!("invalid --range {s:?} (expected 0x...-0x...)"))?;
    let start = parse_hex(a, "--range start")?;
    let end = parse_hex(b, "--range end")?;
    if start == 0 && end == 0 {
        return Ok(None);
    }
    if start > end {
        return Err(format!("invalid --range {s:?} (start > end)"));
    }
    Ok(Some((start, end)))
}

/// ROPgadget --badbytes syntax: "bb|bb|lo-hi" (hex bytes, ranges inclusive).
fn parse_badbytes(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for part in s.split('|') {
        if part.is_empty() {
            continue; // ROPgadget ignores empty items
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo = parse_hex(lo, "--badbytes range low")?;
            let hi = parse_hex(hi, "--badbytes range high")?;
            if lo > 0xff || hi > 0xff || lo > hi {
                return Err(format!("invalid --badbytes range {part:?}"));
            }
            out.extend((lo as u8)..=(hi as u8));
        } else {
            let b = parse_hex(part, "--badbytes byte")?;
            if b > 0xff {
                return Err(format!("invalid --badbytes byte {part:?}"));
            }
            out.push(b as u8);
        }
    }
    Ok(out)
}

/// ROPgadget's raw-loader argument validation (args.py:114-128) and the
/// raw.py arch/mode/endian mapping, resolved to the rf-core contract.
/// Returns (arch, endianness, thumb) when a raw load was requested.
fn parse_raw_spec(cli: &Cli) -> Result<Option<(Arch, Endianness, bool)>, String> {
    if cli.thumb && cli.raw_mode.is_some() && cli.raw_mode.as_deref() != Some("thumb") {
        return Err("--rawMode is conflicting with --thumb".to_string());
    }
    if cli.raw_arch.is_none() && cli.raw_mode.is_some() {
        return Err("Specify --rawArch".to_string());
    }
    if cli.raw_arch.is_none() && cli.raw_endian.is_some() {
        return Err("Specify --rawArch".to_string());
    }
    let Some(arch_s) = cli.raw_arch.as_deref() else {
        return Ok(None);
    };
    // args.py:123 — --thumb implies rawMode=thumb.
    let mode_s = if cli.thumb {
        Some("thumb")
    } else {
        cli.raw_mode.as_deref()
    };
    let Some(mode_s) = mode_s else {
        return Err("Specify --rawMode".to_string());
    };
    if !["32", "64", "arm", "thumb", "riscv"].contains(&mode_s) {
        return Err(format!(
            "invalid --rawMode {mode_s:?} (32|64|arm|thumb|riscv)"
        ));
    }
    if cli.raw_endian.is_none() && arch_s != "x86" {
        return Err("Specify --rawEndian".to_string());
    }
    let endian = match cli.raw_endian.as_deref() {
        None | Some("little") => Endianness::Little,
        Some("big") => Endianness::Big,
        Some(e) => return Err(format!("invalid --rawEndian {e:?} (little|big)")),
    };
    // raw.py:71-72 — x86 is always little-endian.
    let endian = if arch_s == "x86" {
        Endianness::Little
    } else {
        endian
    };
    // raw.py mode/endian interplay with gadgets.py's per-arch mode
    // overrides: arm64 always lands in CS_MODE_ARM, sparc in mode 0, riscv
    // in RV64|RISCVC regardless of the requested 32/64 (gadgets.py:178,
    // 191, 202), so those accept any listed mode.
    let (arch, thumb) = match (arch_s, mode_s) {
        ("x86", "32") => (Arch::X86, false),
        ("x86", "64") => (Arch::X64, false),
        ("arm", "thumb") => (Arch::ArmThumb, true),
        ("arm", _) => (Arch::Arm, false),
        ("arm64", _) => (Arch::Arm64, false),
        ("sparc", _) => (Arch::Sparc, false),
        ("mips", "32") => (Arch::Mips32, false),
        ("mips", "64") => (Arch::Mips64, false),
        ("ppc", "32") => (Arch::Ppc32, false),
        ("ppc", "64") => (Arch::Ppc64, false),
        ("riscv", _) => (Arch::RiscV64, false),
        (a, m) => {
            return Err(format!(
                "unsupported --rawArch {a:?} / --rawMode {m:?} combination"
            ))
        }
    };
    Ok(Some((arch, endian, thumb)))
}

fn arch_name(arch: Arch) -> &'static str {
    match arch {
        Arch::X86 => "x86",
        Arch::X64 => "x64",
        Arch::Arm => "arm",
        Arch::ArmThumb => "arm-thumb",
        Arch::Arm64 => "arm64",
        Arch::Mips32 => "mips32",
        Arch::Mips64 => "mips64",
        Arch::Ppc32 => "ppc32",
        Arch::Ppc64 => "ppc64",
        Arch::Sparc => "sparc",
        Arch::Sparc64 => "sparc64",
        Arch::SparcV9 => "sparcv9",
        Arch::RiscV32 => "riscv32",
        Arch::RiscV64 => "riscv64",
    }
}

/// ROPgadget UNIVERSAL semantics (loaders/universal.py:77-108): the exec
/// regions of every slice concatenated into one scan, using the FIRST
/// slice's arch/mode/endianness — getArch/getArchMode/getEndian "just
/// return whatever is in the first binary". Single "Gadgets information"
/// block, exactly like the oracle.
struct UniversalView {
    arch: Arch,
    endian: Endianness,
    base: u64,
    entry: u64,
    regions: Vec<Section>,
}

impl UniversalView {
    fn from(u: &UniversalBinary) -> Self {
        let first = &u.slices()[0];
        UniversalView {
            arch: first.arch(),
            endian: first.endianness(),
            base: first.image_base(),
            entry: first.entry(),
            regions: u.all_exec_scan_regions().into_iter().cloned().collect(),
        }
    }
}

impl Image for UniversalView {
    fn arch(&self) -> Arch {
        self.arch
    }
    fn endianness(&self) -> Endianness {
        self.endian
    }
    fn image_base(&self) -> u64 {
        self.base
    }
    fn entry(&self) -> u64 {
        self.entry
    }
    fn exec_sections(&self) -> Vec<&Section> {
        self.regions.iter().collect()
    }
    fn exec_scan_regions(&self) -> &[Section] {
        &self.regions
    }
    /// Uniform slide of all slices (our --base extension; ROPgadget has no
    /// --base for Universal).
    fn rebase(&mut self, new_base: u64) {
        let delta = new_base.wrapping_sub(self.base);
        for s in &mut self.regions {
            s.vaddr = s.vaddr.wrapping_add(delta);
        }
        self.base = new_base;
    }
}

/// Everything scannable: one image plus its display parameters.
struct ScanResult {
    gadgets: Vec<Gadget>,
    addr_size: usize,
    /// Some(arch) for Universal binaries (JSON arch field).
    universal_arch: Option<Arch>,
}

fn scan_image<B: Image>(
    bin: &mut B,
    base: &Option<String>,
    opts: &ScanOptions,
) -> Result<ScanResult, String> {
    if let Some(base) = base {
        bin.rebase(parse_hex(base, "--base")?);
    }
    let gadgets = rf_scan::scan_binary(bin, opts).map_err(|e| e.to_string())?;
    Ok(ScanResult {
        gadgets,
        addr_size: bin.addr_size(),
        universal_arch: None,
    })
}

fn run(cli: Cli) -> Result<i32, String> {
    if cli.depth < 2 {
        return Err("--depth must be >= 2".to_string());
    }
    let bytes =
        std::fs::read(&cli.binary).map_err(|e| format!("cannot read {}: {e}", cli.binary))?;
    let raw_spec = parse_raw_spec(&cli)?;

    let mut opts = ScanOptions {
        depth: cli.depth,
        rop: !cli.norop,
        jop: !cli.nojop,
        sys: !cli.nosys,
        multibr: cli.multibr,
        only: cli
            .only
            .as_deref()
            .map(|s| s.split('|').map(|x| x.to_string()).collect()),
        range: match &cli.range {
            Some(r) => parse_range(r)?,
            None => None,
        },
        badbytes: match &cli.badbytes {
            Some(b) => parse_badbytes(b)?,
            None => Vec::new(),
        },
        filter: cli
            .filter
            .as_deref()
            .map(|s| s.split('|').map(|x| x.to_string()).collect())
            .unwrap_or_default(),
        offset: match &cli.offset {
            Some(o) => parse_hex(o, "--offset")?,
            None => 0,
        },
        thumb: cli.thumb,
        parallel: true,
    };

    // binary.py:32-49 — --rawArch wins over magic-byte detection.
    let result = if let Some((arch, endian, raw_thumb)) = raw_spec {
        opts.thumb = opts.thumb || raw_thumb;
        let mut bin = RawBinary::new(&bytes, arch, endian);
        scan_image(&mut bin, &cli.base, &opts)
    } else {
        match Binary::load(&bytes) {
            Err(e) => {
                eprintln!("[Error] {e}");
                return Ok(2);
            }
            Ok(LoadedBinary::Elf(mut b)) => scan_image(&mut b, &cli.base, &opts),
            Ok(LoadedBinary::Pe(mut b)) => scan_image(&mut b, &cli.base, &opts),
            Ok(LoadedBinary::MachO(mut b)) => scan_image(&mut b, &cli.base, &opts),
            Ok(LoadedBinary::Raw(mut b)) => scan_image(&mut b, &cli.base, &opts),
            Ok(LoadedBinary::Universal(u)) => {
                let mut view = UniversalView::from(&u);
                let mut r = scan_image(&mut view, &cli.base, &opts)?;
                r.universal_arch = Some(view.arch());
                Ok(r)
            }
        }
    };
    let result = match result {
        Ok(r) => r,
        Err(e) => {
            // Scan-time Unsupported errors (e.g. capstone mode) are
            // binary-level failures, like ROPgadget's loader errors.
            eprintln!("[Error] {e}");
            return Ok(2);
        }
    };

    if cli.json {
        print_json(&result);
    } else {
        print_human(&result);
    }
    Ok(0)
}

fn fmt_addr(vaddr: u64, addr_size: usize) -> String {
    match addr_size {
        4 => format!("0x{vaddr:08x}"),
        _ => format!("0x{vaddr:016x}"),
    }
}

fn print_human(res: &ScanResult) {
    println!("Gadgets information");
    println!("============================================================");
    for g in &res.gadgets {
        println!("{} : {}", fmt_addr(g.vaddr, res.addr_size), g.text());
    }
    println!("\nUnique gadgets found: {}", res.gadgets.len());
}

fn print_json(res: &ScanResult) {
    let arch = res.universal_arch.map(arch_name);
    let out: Vec<JsonGadget> = res
        .gadgets
        .iter()
        .map(|g| JsonGadget {
            vaddr: fmt_addr(g.vaddr, res.addr_size),
            bytes: g.bytes_hex(),
            text: g.text(),
            arch,
        })
        .collect();
    // Serialization of this simple structure cannot fail.
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // clap exit code 2 -> our usage exit code 1
            let _ = e.print();
            return ExitCode::from(1);
        }
    };
    match run(cli) {
        Ok(code) => ExitCode::from(code as u8),
        Err(msg) => {
            eprintln!("[Error] {msg}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli_with(
        thumb: bool,
        raw_arch: Option<&str>,
        raw_mode: Option<&str>,
        raw_endian: Option<&str>,
    ) -> Cli {
        Cli {
            binary: "x".into(),
            depth: 10,
            norop: false,
            nojop: false,
            nosys: false,
            multibr: false,
            only: None,
            filter: None,
            range: None,
            badbytes: None,
            offset: None,
            base: None,
            thumb,
            raw_arch: raw_arch.map(Into::into),
            raw_mode: raw_mode.map(Into::into),
            raw_endian: raw_endian.map(Into::into),
            json: false,
        }
    }

    #[test]
    fn badbytes_parsing() {
        assert_eq!(parse_badbytes("0a|0d").unwrap(), vec![0x0a, 0x0d]);
        // Ranges are inclusive (ropgadget/options.py:134, range(low, high+1)).
        assert_eq!(parse_badbytes("00-03|ff").unwrap(), vec![0, 1, 2, 3, 0xff]);
        assert_eq!(parse_badbytes("0a|").unwrap(), vec![0x0a]); // trailing | ok
        assert!(parse_badbytes("0x100").is_err());
        assert!(parse_badbytes("zz").is_err());
    }

    #[test]
    fn range_parsing() {
        assert_eq!(parse_range("0x0-0x0").unwrap(), None);
        assert_eq!(
            parse_range("0x1000-0x2000").unwrap(),
            Some((0x1000, 0x2000))
        );
        assert!(parse_range("0x2000-0x1000").is_err());
        assert!(parse_range("nonsense").is_err());
    }

    #[test]
    fn hex_parsing() {
        assert_eq!(parse_hex("0x41414141", "x").unwrap(), 0x41414141);
        assert_eq!(parse_hex("ff", "x").unwrap(), 0xff);
        assert!(parse_hex("0xz", "x").is_err());
    }

    #[test]
    fn raw_spec_validation_mirrors_args_py() {
        // no raw flags at all → no raw load
        assert!(parse_raw_spec(&cli_with(false, None, None, None))
            .unwrap()
            .is_none());
        // rawMode/rawEndian without rawArch
        assert!(parse_raw_spec(&cli_with(false, None, Some("32"), None)).is_err());
        assert!(parse_raw_spec(&cli_with(false, None, None, Some("big"))).is_err());
        // rawArch without mode
        assert!(parse_raw_spec(&cli_with(false, Some("x86"), None, None)).is_err());
        // rawArch non-x86 without endian
        assert!(parse_raw_spec(&cli_with(false, Some("arm"), Some("arm"), None)).is_err());
        // thumb conflicting with rawMode
        assert!(parse_raw_spec(&cli_with(true, Some("arm"), Some("arm"), Some("little"))).is_err());
        // unknown mode / arch+mode combo
        assert!(parse_raw_spec(&cli_with(false, Some("x86"), Some("v99"), None)).is_err());
        assert!(
            parse_raw_spec(&cli_with(false, Some("mips"), Some("thumb"), Some("big"))).is_err()
        );
        assert!(parse_raw_spec(&cli_with(false, Some("s390"), Some("64"), Some("big"))).is_err());
    }

    #[test]
    fn raw_spec_mapping() {
        let (a, e, t) = parse_raw_spec(&cli_with(false, Some("x86"), Some("32"), None))
            .unwrap()
            .unwrap();
        assert_eq!((a, e, t), (Arch::X86, Endianness::Little, false));
        // x86 forces little-endian even if big requested (raw.py:71-72)
        let (_, e, _) = parse_raw_spec(&cli_with(false, Some("x86"), Some("64"), Some("big")))
            .unwrap()
            .unwrap();
        assert_eq!(e, Endianness::Little);
        let (a, _, t) =
            parse_raw_spec(&cli_with(false, Some("arm"), Some("thumb"), Some("little")))
                .unwrap()
                .unwrap();
        assert_eq!((a, t), (Arch::ArmThumb, true));
        // --thumb implies rawMode=thumb (args.py:123)
        let (a, _, t) = parse_raw_spec(&cli_with(true, Some("arm"), None, Some("big")))
            .unwrap()
            .unwrap();
        assert_eq!((a, t), (Arch::ArmThumb, true));
        let (a, e, _) = parse_raw_spec(&cli_with(false, Some("mips"), Some("64"), Some("big")))
            .unwrap()
            .unwrap();
        assert_eq!((a, e), (Arch::Mips64, Endianness::Big));
        let (a, _, _) = parse_raw_spec(&cli_with(
            false,
            Some("riscv"),
            Some("riscv"),
            Some("little"),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(a, Arch::RiscV64);
    }
}
