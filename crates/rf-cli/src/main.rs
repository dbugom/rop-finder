//! rop-finder — ROPgadget-compatible CLI.
//!
//! Phase 1: ELF, PE, Mach-O, Universal/fat Mach-O, and raw blobs; all
//! supported architectures. Format dispatch mirrors ROPgadget's
//! `binary.py`: `--rawArch` forces the raw loader regardless of magic
//! bytes; otherwise magic-byte dispatch via `rf_core::Binary::load`.
//! Universal (fat Mach-O) binaries follow ROPgadget's `universal.py`:
//! every slice's executable regions are concatenated and scanned with the
//! FIRST slice's arch/mode/endianness (universal.py:92-108 returns
//! "whatever is in the first binary").
//!
//! Phase 2 (PLAN.md §6.3/§6.4):
//!   * `--section <glob>` — restrict the scan to named executable sections
//!     (repeatable, comma-separated, `*` globbing).
//!   * `--base <hex>` — rebase the image at load time (rf-core `rebase`).
//!   * `--info` — dump image metadata as JSON without scanning.
//!
//! Exit codes: 0 success, 1 usage error, 2 malformed/unsupported binary.

use std::process::ExitCode;

use clap::Parser;
use globset::{Glob, GlobSetBuilder};
use rf_core::{
    Arch, Binary, Endianness, Image, LoadedBinary, MachOBinary, RawBinary, Section, UniversalBinary,
};
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

    /// Rejects specific bytes in the gadget's FINAL address, after --base
    /// rebase and --offset (e.g. "0a|0d" or "00-1f")
    #[arg(long)]
    badbytes: Option<String>,

    /// Specify an offset ADDED to gadget addresses after any --base rebase
    /// (hex)
    #[arg(long)]
    offset: Option<String>,

    /// Rebase the binary to this image base at load time, before scanning
    /// and before --offset is applied (hex). Use 0 for RVA-style addresses
    #[arg(long)]
    base: Option<String>,

    /// Dump image metadata (format/arch/sections/imports) as JSON and exit
    /// without scanning
    #[arg(long)]
    info: bool,

    /// Scan only the named executable section(s); repeatable and
    /// comma-separated, `*` globbing allowed (e.g. --section .text or
    /// --section ".init*,.plt")
    #[arg(long = "section", value_delimiter = ',')]
    section: Vec<String>,

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
    /// Name of the section containing the gadget — present when --section
    /// was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    section: Option<String>,
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
        return Err("Specify --rawArch".to_string());
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

fn endian_name(e: Endianness) -> &'static str {
    match e {
        Endianness::Little => "little",
        Endianness::Big => "big",
    }
}

/// A loaded binary before it is flattened into a scan view.
enum Target {
    Elf(rf_core::ElfBinary),
    Pe(rf_core::PeBinary),
    MachO(MachOBinary),
    Universal(UniversalBinary),
    Raw(RawBinary),
}

/// Format-agnostic scan view over a loaded image.
///
/// For single-image binaries `regions` is exactly the image's
/// `exec_scan_regions()` (ROPgadget parity path). For Universal binaries
/// ROPgadget UNIVERSAL semantics apply (loaders/universal.py:77-108): the
/// exec regions of every slice concatenated into one scan, using the FIRST
/// slice's arch/mode/endianness — getArch/getArchMode/getEndian "just
/// return whatever is in the first binary".
///
/// `named_exec` holds the named executable sections (`exec_sections()`)
/// used by `--section` filtering and by the JSON `section` field. When
/// `--section` is given, `regions` is replaced with the matching subset of
/// `named_exec`.
struct RegionView {
    arch: Arch,
    endian: Endianness,
    base: u64,
    entry: u64,
    regions: Vec<Section>,
    named_exec: Vec<Section>,
    /// True for Universal (multi-slice) binaries (JSON arch field).
    universal: bool,
}

fn build_view(target: &Target) -> RegionView {
    match target {
        Target::Elf(b) => RegionView::single(
            Image::arch(b),
            Image::endianness(b),
            b.image_base(),
            b.entry(),
            b.exec_scan_regions(),
            b.exec_sections(),
        ),
        Target::Pe(b) => RegionView::single(
            Image::arch(b),
            Image::endianness(b),
            b.image_base(),
            b.entry(),
            b.exec_scan_regions(),
            b.exec_sections(),
        ),
        Target::MachO(b) => RegionView::single(
            Image::arch(b),
            Image::endianness(b),
            b.image_base(),
            b.entry(),
            b.exec_scan_regions(),
            b.exec_sections(),
        ),
        Target::Raw(b) => RegionView::single(
            Image::arch(b),
            Image::endianness(b),
            b.image_base(),
            b.entry(),
            b.exec_scan_regions(),
            b.exec_sections(),
        ),
        Target::Universal(u) => {
            let first = &u.slices()[0];
            RegionView {
                arch: first.arch(),
                endian: first.endianness(),
                base: first.image_base(),
                entry: first.entry(),
                regions: u.all_exec_scan_regions().into_iter().cloned().collect(),
                named_exec: u
                    .slices()
                    .iter()
                    .flat_map(|s| s.exec_sections().into_iter().cloned())
                    .collect(),
                universal: true,
            }
        }
    }
}

impl RegionView {
    fn single(
        arch: Arch,
        endian: Endianness,
        base: u64,
        entry: u64,
        regions: &[Section],
        named_exec: Vec<&Section>,
    ) -> Self {
        RegionView {
            arch,
            endian,
            base,
            entry,
            regions: regions.to_vec(),
            named_exec: named_exec.into_iter().cloned().collect(),
            universal: false,
        }
    }
}

impl Image for RegionView {
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
        self.named_exec.iter().collect()
    }
    fn exec_scan_regions(&self) -> &[Section] {
        &self.regions
    }
    /// Uniform slide of the whole view (for Universal: all slices slide by
    /// the same delta — our --base extension; ROPgadget has no --base for
    /// Universal).
    fn rebase(&mut self, new_base: u64) {
        let delta = new_base.wrapping_sub(self.base);
        for s in &mut self.regions {
            s.vaddr = s.vaddr.wrapping_add(delta);
        }
        for s in &mut self.named_exec {
            s.vaddr = s.vaddr.wrapping_add(delta);
        }
        self.entry = self.entry.wrapping_add(delta);
        self.base = new_base;
    }
}

/// `--section` selection: keep the named exec sections whose name matches
/// any glob pattern. Returns the matched sections plus a flag telling
/// whether the binary only has synthetic fallback names (`PT_LOAD#n`,
/// i.e. a stripped ELF without a section table).
fn select_sections(
    named_exec: &[Section],
    patterns: &[String],
) -> Result<(Vec<Section>, bool), String> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        let glob = Glob::new(p).map_err(|e| format!("invalid --section pattern {p:?}: {e}"))?;
        builder.add(glob);
    }
    let set = builder
        .build()
        .map_err(|e| format!("invalid --section patterns: {e}"))?;
    let matched: Vec<Section> = named_exec
        .iter()
        .filter(|s| set.is_match(&s.name))
        .cloned()
        .collect();
    let fallback_names =
        !named_exec.is_empty() && named_exec.iter().all(|s| s.name.starts_with("PT_LOAD#"));
    if matched.is_empty() {
        let available = named_exec
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "no executable section matches {patterns:?}; available executable sections: {available}"
        ));
    }
    Ok((matched, fallback_names))
}

/// Everything scannable: one image's gadgets plus its display parameters.
struct ScanResult {
    gadgets: Vec<Gadget>,
    addr_size: usize,
    /// Some(arch) for Universal binaries (JSON arch field).
    universal_arch: Option<Arch>,
    /// Sections selected by --section as (name, vaddr, size), used for the
    /// JSON `section` field. None when --section was not used.
    selected_sections: Option<Vec<(String, u64, u64)>>,
}

fn hexs(v: u64) -> String {
    format!("0x{v:x}")
}

fn section_json(s: &Section, delta: u64) -> serde_json::Value {
    serde_json::json!({
        "name": s.name,
        "vaddr": hexs(s.vaddr.wrapping_add(delta)),
        "size": s.size,
        "executable": s.executable,
        "writable": s.writable,
    })
}

/// Rebase delta for `--info`: `new_base - image_base` (wrapping, so
/// `wrapping_add(delta)` reproduces `Image::rebase`).
fn rebase_delta(image_base: u64, new_base: Option<u64>) -> u64 {
    new_base.map_or(0, |n| n.wrapping_sub(image_base))
}

/// Everything `--info` needs to describe one image.
struct InfoView<'a> {
    format: &'static str,
    arch: Arch,
    endian: Endianness,
    image_base: u64,
    entry: u64,
    sections: &'a [Section],
    imports: Vec<serde_json::Value>,
    delta: u64,
}

fn image_info(v: InfoView) -> serde_json::Value {
    serde_json::json!({
        "format": v.format,
        "arch": arch_name(v.arch),
        "endianness": endian_name(v.endian),
        "addr_size": v.arch.addr_size(),
        "image_base": hexs(v.image_base.wrapping_add(v.delta)),
        "entry": hexs(v.entry.wrapping_add(v.delta)),
        "sections": v.sections.iter().map(|s| section_json(s, v.delta)).collect::<Vec<_>>(),
        "imports": v.imports,
    })
}

fn macho_info(b: &MachOBinary, delta: u64) -> serde_json::Value {
    image_info(InfoView {
        format: "macho",
        arch: b.arch(),
        endian: b.endianness(),
        image_base: b.image_base(),
        entry: b.entry(),
        sections: b.sections(),
        imports: Vec::new(),
        delta,
    })
}

/// PLAN.md §6.4: `--info` payload. Addresses are hex strings (consistent
/// with gadget vaddrs), sizes are numbers. `--base` is honoured so the
/// printed addresses match what a scan would emit.
fn info_json(target: &Target, new_base: Option<u64>) -> serde_json::Value {
    match target {
        Target::Elf(b) => image_info(InfoView {
            format: "elf",
            arch: Image::arch(b),
            endian: Image::endianness(b),
            image_base: b.image_base(),
            entry: b.entry(),
            sections: b.sections(),
            imports: Vec::new(),
            delta: rebase_delta(b.image_base(), new_base),
        }),
        Target::Pe(b) => {
            let delta = rebase_delta(b.image_base(), new_base);
            let imports = b
                .imports()
                .iter()
                .map(|i| {
                    serde_json::json!({
                        "dll": i.dll,
                        "symbol": i.name,
                        "iat_vaddr": hexs(i.thunk_vaddr.wrapping_add(delta)),
                    })
                })
                .collect();
            image_info(InfoView {
                format: "pe",
                arch: Image::arch(b),
                endian: Image::endianness(b),
                image_base: b.image_base(),
                entry: b.entry(),
                sections: b.sections(),
                imports,
                delta,
            })
        }
        Target::MachO(b) => macho_info(b, rebase_delta(b.image_base(), new_base)),
        Target::Raw(b) => image_info(InfoView {
            format: "raw",
            arch: Image::arch(b),
            endian: Image::endianness(b),
            image_base: b.image_base(),
            entry: b.entry(),
            sections: std::slice::from_ref(b.section()),
            imports: Vec::new(),
            delta: rebase_delta(b.image_base(), new_base),
        }),
        Target::Universal(u) => {
            // Same convention as RegionView: the view base is the FIRST
            // slice's image base, so --base slides every slice by
            // new_base - first_base.
            let first_base = u.slices()[0].image_base();
            let delta = rebase_delta(first_base, new_base);
            serde_json::json!({
                "format": "universal",
                "slices": u.slices().iter().map(|s| macho_info(s, delta)).collect::<Vec<_>>(),
            })
        }
    }
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
    let target = if let Some((arch, endian, raw_thumb)) = raw_spec {
        opts.thumb = opts.thumb || raw_thumb;
        Target::Raw(RawBinary::new(&bytes, arch, endian))
    } else {
        match Binary::load(&bytes) {
            Err(e) => {
                eprintln!("[Error] {e}");
                return Ok(2);
            }
            Ok(LoadedBinary::Elf(b)) => Target::Elf(b),
            Ok(LoadedBinary::Pe(b)) => Target::Pe(b),
            Ok(LoadedBinary::MachO(b)) => Target::MachO(b),
            Ok(LoadedBinary::Raw(b)) => Target::Raw(b),
            Ok(LoadedBinary::Universal(u)) => Target::Universal(u),
        }
    };

    // --info: metadata only, no scanning. --base is honoured.
    if cli.info {
        let new_base = cli
            .base
            .as_deref()
            .map(|b| parse_hex(b, "--base"))
            .transpose()?;
        println!(
            "{}",
            serde_json::to_string_pretty(&info_json(&target, new_base)).unwrap()
        );
        return Ok(0);
    }

    let mut view = build_view(&target);
    if let Some(base) = &cli.base {
        view.rebase(parse_hex(base, "--base")?);
    }
    let universal_arch = view.universal.then_some(view.arch());

    // --section: narrow the scan regions to the selected named sections.
    let mut selected_sections = None;
    if !cli.section.is_empty() {
        let (sections, fallback_names) = select_sections(&view.named_exec, &cli.section)?;
        if fallback_names {
            eprintln!(
                "[Warning] binary has no section names (stripped ELF?); \
                 executable segments are named PT_LOAD#n"
            );
        }
        selected_sections = Some(
            sections
                .iter()
                .map(|s| (s.name.clone(), s.vaddr, s.size))
                .collect(),
        );
        view.regions = sections;
    }

    let gadgets = match rf_scan::scan_binary(&view, &opts) {
        Ok(g) => g,
        Err(e) => {
            // Scan-time Unsupported errors (e.g. capstone mode) are
            // binary-level failures, like ROPgadget's loader errors.
            eprintln!("[Error] {e}");
            return Ok(2);
        }
    };
    let result = ScanResult {
        gadgets,
        addr_size: view.addr_size(),
        universal_arch,
        selected_sections,
    };

    if cli.json {
        print_json(&result, opts.offset);
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

/// Name of the selected section containing `vaddr` (a scan-view address,
/// i.e. after --base but before --offset), if any.
fn section_of(selected: &[(String, u64, u64)], vaddr: u64) -> Option<String> {
    selected
        .iter()
        .find(|(_, s_vaddr, s_size)| vaddr >= *s_vaddr && vaddr < s_vaddr.wrapping_add(*s_size))
        .map(|(name, _, _)| name.clone())
}

fn to_json(res: &ScanResult, offset: u64) -> Vec<JsonGadget> {
    let arch = res.universal_arch.map(arch_name);
    res.gadgets
        .iter()
        .map(|g| JsonGadget {
            vaddr: fmt_addr(g.vaddr, res.addr_size),
            bytes: g.bytes_hex(),
            text: g.text(),
            arch,
            section: res
                .selected_sections
                .as_deref()
                .and_then(|s| section_of(s, g.vaddr.wrapping_sub(offset))),
        })
        .collect()
}

fn print_json(res: &ScanResult, offset: u64) {
    // Serialization of this simple structure cannot fail.
    println!(
        "{}",
        serde_json::to_string_pretty(&to_json(res, offset)).unwrap()
    );
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
            info: false,
            section: Vec::new(),
            thumb,
            raw_arch: raw_arch.map(Into::into),
            raw_mode: raw_mode.map(Into::into),
            raw_endian: raw_endian.map(Into::into),
            json: false,
        }
    }

    fn fixture_bytes(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn load_target(bytes: &[u8]) -> Target {
        match Binary::load(bytes).unwrap() {
            LoadedBinary::Elf(b) => Target::Elf(b),
            LoadedBinary::Pe(b) => Target::Pe(b),
            LoadedBinary::MachO(b) => Target::MachO(b),
            LoadedBinary::Raw(b) => Target::Raw(b),
            LoadedBinary::Universal(u) => Target::Universal(u),
        }
    }

    fn default_opts() -> ScanOptions {
        ScanOptions {
            depth: 10,
            rop: true,
            jop: true,
            sys: true,
            multibr: false,
            only: None,
            range: None,
            badbytes: Vec::new(),
            filter: Vec::new(),
            offset: 0,
            thumb: false,
            parallel: true,
        }
    }

    /// Scan `fixture` with the given view mutations; returns (view, gadgets).
    fn scan_fixture(
        fixture: &str,
        base: Option<u64>,
        sections: &[&str],
        configure: impl Fn(&mut ScanOptions),
    ) -> (RegionView, Vec<Gadget>) {
        let bytes = fixture_bytes(fixture);
        let target = load_target(&bytes);
        let mut view = build_view(&target);
        if let Some(b) = base {
            view.rebase(b);
        }
        if !sections.is_empty() {
            let pats: Vec<String> = sections.iter().map(|s| s.to_string()).collect();
            let (secs, _) = select_sections(&view.named_exec, &pats).unwrap();
            view.regions = secs;
        }
        let mut opts = default_opts();
        configure(&mut opts);
        let gadgets = rf_scan::scan_binary(&view, &opts).unwrap();
        (view, gadgets)
    }

    fn make_section(name: &str, vaddr: u64, size: u64) -> Section {
        Section {
            name: name.to_string(),
            vaddr,
            offset: 0,
            size,
            bytes: vec![0u8; size as usize],
            executable: true,
            writable: false,
        }
    }

    /// vaddr of the dedup-stable bare "ret" gadget (traversal order is
    /// base-invariant, so the survivor is the same gadget across rebases).
    fn bare_ret_vaddr(gadgets: &[Gadget]) -> Option<u64> {
        gadgets.iter().find(|g| g.text() == "ret").map(|g| g.vaddr)
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

    // ---- Phase 2: --section selection (PLAN.md §6.3) ----

    #[test]
    fn select_sections_glob_and_fallback_flag() {
        let secs = vec![
            make_section(".init", 0x1000, 0x10),
            make_section(".plt", 0x1010, 0x20),
            make_section(".text", 0x2000, 0x100),
        ];
        // exact match
        let (m, fb) = select_sections(&secs, &[".text".to_string()]).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, ".text");
        assert!(!fb);
        // glob match
        let (m, _) = select_sections(&secs, &[".p*".to_string()]).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, ".plt");
        // multiple patterns
        let (m, _) = select_sections(&secs, &[".init".to_string(), ".plt".to_string()]).unwrap();
        assert_eq!(m.len(), 2);
        // zero matches → error listing available names
        let err = select_sections(&secs, &[".nope".to_string()]).unwrap_err();
        assert!(err.contains(".text"), "error lists available: {err}");
        assert!(err.contains(".plt"), "error lists available: {err}");
        // stripped-ELF fallback names detected
        let stripped = vec![
            make_section("PT_LOAD#0", 0x1000, 0x10),
            make_section("PT_LOAD#1", 0x2000, 0x20),
        ];
        let (m, fb) = select_sections(&stripped, &["PT_LOAD#*".to_string()]).unwrap();
        assert_eq!(m.len(), 2);
        assert!(fb);
        // invalid glob
        assert!(select_sections(&secs, &["[".to_string()]).is_err());
    }

    #[test]
    fn section_filter_pe_matches_default_scan() {
        // PE exec scan regions == exec sections, so --section .text must
        // reproduce the default scan exactly, with every vaddr inside .text.
        let (_, all) = scan_fixture("pe-x64-cmd-v6.1.7601", None, &[], |_| {});
        let (view, filtered) = scan_fixture("pe-x64-cmd-v6.1.7601", None, &[".text"], |_| {});
        assert!(!filtered.is_empty());
        assert_eq!(all.len(), filtered.len());
        let text = &view.named_exec.iter().find(|s| s.name == ".text").unwrap();
        for g in &filtered {
            assert!(
                g.vaddr >= text.vaddr && g.vaddr < text.vaddr + text.size,
                "gadget {:#x} outside .text",
                g.vaddr
            );
        }
    }

    #[test]
    fn section_filter_elf_multi_and_glob() {
        // ELF: exec sections (.init/.plt/.text/.fini) are a subset of the
        // PT_LOAD scan regions, so filtering narrows coverage (intended,
        // PLAN §6.3).
        let (view, plt) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[".p*"], |_| {});
        assert!(!plt.is_empty());
        let plt_sec = view.named_exec.iter().find(|s| s.name == ".plt").unwrap();
        for g in &plt {
            assert!(
                g.vaddr >= plt_sec.vaddr && g.vaddr < plt_sec.vaddr + plt_sec.size,
                "gadget {:#x} outside .plt",
                g.vaddr
            );
        }
        // comma-style multi selection (clap splits commas; here two pats)
        let (_, multi) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[".init", ".plt"], |_| {});
        let init_sec = view.named_exec.iter().find(|s| s.name == ".init").unwrap();
        assert!(multi.len() > plt.len(), ".init adds gadgets");
        for g in &multi {
            let in_plt = g.vaddr >= plt_sec.vaddr && g.vaddr < plt_sec.vaddr + plt_sec.size;
            let in_init = g.vaddr >= init_sec.vaddr && g.vaddr < init_sec.vaddr + init_sec.size;
            assert!(
                in_plt || in_init,
                "gadget {:#x} outside .init/.plt",
                g.vaddr
            );
        }
        // filtered scan finds strictly fewer gadgets than the default
        let (_, all) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[], |_| {});
        assert!(multi.len() < all.len());
    }

    #[test]
    fn section_unknown_name_is_usage_error() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let target = load_target(&bytes);
        let view = build_view(&target);
        let err = select_sections(&view.named_exec, &[".nonexistent".to_string()]).unwrap_err();
        assert!(err.contains(".text"), "lists available sections: {err}");
    }

    #[test]
    fn stripped_elf_falls_back_to_segment_names() {
        // Zero e_shoff (0x28, 8 bytes) and e_shnum (0x3c, 2 bytes) of an
        // ELF64 fixture copy — the loader must fall back to PT_LOAD#n names.
        let mut bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        assert_eq!(&bytes[0..4], b"\x7fELF");
        assert_eq!(bytes[4], 2, "fixture must be ELF64");
        bytes[0x28..0x30].fill(0);
        bytes[0x3c..0x3e].fill(0);
        let target = load_target(&bytes);
        let view = build_view(&target);
        assert!(!view.named_exec.is_empty());
        assert!(view
            .named_exec
            .iter()
            .all(|s| s.name.starts_with("PT_LOAD#")));
        let (matched, fallback) =
            select_sections(&view.named_exec, &["PT_LOAD#*".to_string()]).unwrap();
        assert!(fallback, "warning flag set for fallback names");
        assert_eq!(matched.len(), view.named_exec.len());
    }

    #[test]
    fn range_composes_with_section() {
        // --range applies to whatever regions the view exposes (here: the
        // selected .text section only).
        let (view, _) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[".text"], |_| {});
        let text = view.named_exec.iter().find(|s| s.name == ".text").unwrap();
        let mid = text.vaddr + text.size / 2;
        let (_, gadgets) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[".text"], |o| {
            o.range = Some((text.vaddr, mid));
        });
        assert!(!gadgets.is_empty());
        for g in &gadgets {
            assert!(g.vaddr >= text.vaddr && g.vaddr < mid);
        }
    }

    #[test]
    fn json_gadgets_carry_section_name() {
        let (view, gadgets) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[".plt"], |_| {});
        let res = ScanResult {
            gadgets,
            addr_size: view.addr_size(),
            universal_arch: None,
            selected_sections: Some(
                view.regions
                    .iter()
                    .map(|s| (s.name.clone(), s.vaddr, s.size))
                    .collect(),
            ),
        };
        let json = to_json(&res, 0);
        assert!(!json.is_empty());
        for g in &json {
            assert_eq!(g.section.as_deref(), Some(".plt"));
        }
        // offset is subtracted before the section lookup: with an offset
        // of 0x10 the lookup keys shift 16 bytes down, so gadgets at the
        // very start of .plt (if any) fall out; with a huge offset every
        // key lands below the section and the section is None.
        let huge = to_json(&res, 0x8000_0000);
        assert!(huge.iter().all(|g| g.section.is_none()));
    }

    // ---- Phase 2: --base hardening (PLAN.md §6.4) ----

    #[test]
    fn base_zero_pe_gives_rvas() {
        let bytes = fixture_bytes("pe-x64-cmd-v6.1.7601");
        let target = load_target(&bytes);
        let orig_base = build_view(&target).base;
        let (_, default) = scan_fixture("pe-x64-cmd-v6.1.7601", None, &[], |_| {});
        let (_, rebased) = scan_fixture("pe-x64-cmd-v6.1.7601", Some(0), &[], |_| {});
        let ret_default = bare_ret_vaddr(&default).expect("bare ret in default scan");
        let ret_base0 = bare_ret_vaddr(&rebased).expect("bare ret in base-0 scan");
        assert_eq!(ret_base0, ret_default - orig_base);
        // PLAN §6.4 review point: rebasing changes address-dependent
        // operand text, so the text SETS differ even though the traversal
        // is identical.
        let texts_default: std::collections::BTreeSet<_> =
            default.iter().map(|g| g.text()).collect();
        let texts_base0: std::collections::BTreeSet<_> = rebased.iter().map(|g| g.text()).collect();
        assert_ne!(texts_default, texts_base0);
    }

    #[test]
    fn base_shift_pie_elf() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let target = load_target(&bytes);
        let orig_base = build_view(&target).base;
        let (_, default) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[], |_| {});
        let (_, rebased) = scan_fixture("elf-x64-bash-v4.1.5.1", Some(0x55550000), &[], |_| {});
        let ret_default = bare_ret_vaddr(&default).expect("bare ret in default scan");
        let ret_shifted = bare_ret_vaddr(&rebased).expect("bare ret in rebased scan");
        assert_eq!(ret_shifted, ret_default - orig_base + 0x55550000);
    }

    #[test]
    fn badbytes_check_final_rebased_address() {
        // After --base 0x55550000 every gadget address contains byte 0x55,
        // so --badbytes 55 eliminates everything.
        let (_, filtered) = scan_fixture("elf-x64-bash-v4.1.5.1", Some(0x55550000), &[], |o| {
            o.badbytes = vec![0x55];
        });
        assert!(filtered.is_empty(), "badbytes apply after rebase");
        // Same rebase without badbytes finds gadgets.
        let (_, plain) = scan_fixture("elf-x64-bash-v4.1.5.1", Some(0x55550000), &[], |_| {});
        assert!(!plain.is_empty());
        // At the default base (0x400000-ish) 0x55 bytes are rare → gadgets
        // survive.
        let (_, default) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[], |o| {
            o.badbytes = vec![0x55];
        });
        assert!(!default.is_empty());
    }

    #[test]
    fn base_and_offset_compose() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let target = load_target(&bytes);
        let orig_base = build_view(&target).base;
        let (_, default) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[], |_| {});
        let ret_default = bare_ret_vaddr(&default).unwrap();
        // offset applies AFTER rebase: vaddr == default - orig + B + O
        let (_, composed) = scan_fixture("elf-x64-bash-v4.1.5.1", Some(0x70000000), &[], |o| {
            o.offset = 0x1000;
        });
        let ret_composed = bare_ret_vaddr(&composed).unwrap();
        assert_eq!(ret_composed, ret_default - orig_base + 0x70000000 + 0x1000);
        // Same for PE.
        let bytes = fixture_bytes("pe-x64-cmd-v6.1.7601");
        let target = load_target(&bytes);
        let orig_base = build_view(&target).base;
        let (_, default) = scan_fixture("pe-x64-cmd-v6.1.7601", None, &[], |_| {});
        let ret_default = bare_ret_vaddr(&default).unwrap();
        let (_, composed) = scan_fixture("pe-x64-cmd-v6.1.7601", Some(0x80000000), &[], |o| {
            o.offset = 0x2000;
        });
        let ret_composed = bare_ret_vaddr(&composed).unwrap();
        assert_eq!(ret_composed, ret_default - orig_base + 0x80000000 + 0x2000);
    }

    // ---- Phase 2: --info (PLAN.md §6.4) ----

    #[test]
    fn info_pe_shape() {
        let bytes = fixture_bytes("pe-x64-cmd-v6.1.7601");
        let target = load_target(&bytes);
        let Target::Pe(ref pe) = target else {
            panic!("expected PE")
        };
        let expect_base = hexs(pe.image_base());
        let info = info_json(&target, None);
        assert_eq!(info["format"], "pe");
        assert_eq!(info["arch"], "x64");
        assert_eq!(info["endianness"], "little");
        assert_eq!(info["addr_size"], 8);
        assert_eq!(info["image_base"], serde_json::json!(expect_base));
        let sections = info["sections"].as_array().unwrap();
        let text = sections
            .iter()
            .find(|s| s["name"] == ".text")
            .expect(".text section");
        assert_eq!(text["executable"], true);
        assert_eq!(text["writable"], false);
        let imports = info["imports"].as_array().unwrap();
        assert!(!imports.is_empty());
        assert!(imports.iter().any(|i| i["dll"]
            .as_str()
            .unwrap()
            .to_uppercase()
            .contains("KERNEL32")));
        assert!(imports[0]["symbol"].is_string());
        assert!(imports[0]["iat_vaddr"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn info_elf_shape() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let target = load_target(&bytes);
        let info = info_json(&target, None);
        assert_eq!(info["format"], "elf");
        assert_eq!(info["arch"], "x64");
        assert_eq!(info["imports"].as_array().unwrap().len(), 0);
        let sections = info["sections"].as_array().unwrap();
        assert!(sections.iter().any(|s| s["name"] == ".text"));
        assert!(info["entry"].as_str().unwrap().starts_with("0x"));
    }

    #[test]
    fn info_honours_base() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let target = load_target(&bytes);
        let Target::Elf(ref elf) = target else {
            panic!("expected ELF")
        };
        let orig_base = elf.image_base();
        let orig_entry = elf.entry();
        let info = info_json(&target, Some(0x55550000));
        assert_eq!(info["image_base"], "0x55550000");
        assert_eq!(
            info["entry"],
            serde_json::json!(hexs(orig_entry - orig_base + 0x55550000))
        );
    }

    #[test]
    fn info_universal_and_raw() {
        let bytes = fixture_bytes("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let target = load_target(&bytes);
        let Target::Universal(ref u) = target else {
            panic!("expected Universal")
        };
        let n_slices = u.slices().len();
        let info = info_json(&target, None);
        assert_eq!(info["format"], "universal");
        let slices = info["slices"].as_array().unwrap();
        assert_eq!(slices.len(), n_slices);
        assert!(slices.iter().all(|s| s["format"] == "macho"));

        let raw = RawBinary::new(&fixture_bytes("raw-x86.raw"), Arch::X86, Endianness::Little);
        let info = info_json(&Target::Raw(raw), None);
        assert_eq!(info["format"], "raw");
        assert_eq!(info["arch"], "x86");
        assert_eq!(info["image_base"], "0x0");
    }
}
