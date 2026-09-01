//! rop-finder — ROPgadget-compatible CLI library.
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
//! Phase 3 (PLAN.md §6.1): the scan orchestration (`ScanRequest` →
//! [`scan_bytes`] / [`info_bytes`]) is library API so the `rf-mcp` MCP
//! server reuses it without shelling out to the CLI.
//!
//! Exit codes: 0 success, 1 usage error, 2 malformed/unsupported binary.

use std::fmt;
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
pub struct Cli {
    /// Specify a binary filename to analyze
    #[arg(long)]
    pub binary: String,

    /// Depth for search engine (default 10)
    #[arg(long, default_value_t = 10)]
    pub depth: usize,

    /// Disable ROP search engine
    #[arg(long)]
    pub norop: bool,

    /// Disable JOP search engine
    #[arg(long)]
    pub nojop: bool,

    /// Disable SYS search engine
    #[arg(long)]
    pub nosys: bool,

    /// Enable multiple branch gadgets
    #[arg(long)]
    pub multibr: bool,

    /// Only show specific instructions (e.g. "pop|ret|mov")
    #[arg(long)]
    pub only: Option<String>,

    /// Suppress specific mnemonics (suffix match, e.g. "leave|enter")
    #[arg(long)]
    pub filter: Option<String>,

    /// Search between two addresses (0x...-0x...)
    #[arg(long)]
    pub range: Option<String>,

    /// Rejects specific bytes in the gadget's FINAL address, after --base
    /// rebase and --offset (e.g. "0a|0d" or "00-1f")
    #[arg(long)]
    pub badbytes: Option<String>,

    /// Specify an offset ADDED to gadget addresses after any --base rebase
    /// (hex)
    #[arg(long)]
    pub offset: Option<String>,

    /// Rebase the binary to this image base at load time, before scanning
    /// and before --offset is applied (hex). Use 0 for RVA-style addresses
    #[arg(long)]
    pub base: Option<String>,

    /// Dump image metadata (format/arch/sections/imports) as JSON and exit
    /// without scanning
    #[arg(long)]
    pub info: bool,

    /// Generate a ROP chain; default output is the Python exploit script,
    /// with --json the JSON Chain IR. Target selection via --chain
    #[arg(long)]
    pub ropchain: bool,

    /// Chain target for --ropchain: linux-execve (ELF x86/x64, default) or
    /// windows-virtualprotect (PE x86/x64)
    #[arg(long, default_value = "linux-execve")]
    pub chain: String,

    /// Runtime address of the target API for windows-virtualprotect (hex).
    /// Primary resolution path; without it the PE must import the API
    /// (IAT dereference)
    #[arg(long)]
    pub api_addr: Option<String>,

    /// Runtime address the shellcode will occupy for windows-virtualprotect
    /// (hex; default: the binary's writable .data section)
    #[arg(long)]
    pub shellcode_addr: Option<String>,

    /// dwSize argument for windows-virtualprotect (hex; default 0x1000)
    #[arg(long)]
    pub shellcode_size: Option<String>,

    /// CFG/CET-aware scan: keep only gadgets whose entry is an
    /// endbr64/endbr32 instruction (x86/x64)
    #[arg(long)]
    pub cfg_aware: bool,

    /// Scan only the named executable section(s); repeatable and
    /// comma-separated, `*` globbing allowed (e.g. --section .text or
    /// --section ".init*,.plt")
    #[arg(long = "section", value_delimiter = ',')]
    pub section: Vec<String>,

    /// Use the thumb mode for the search engine (ARM only)
    #[arg(long)]
    pub thumb: bool,

    /// Specify an arch for a raw file: x86|arm|arm64|sparc|mips|ppc|riscv
    #[arg(long = "rawArch", value_name = "<arch>")]
    pub raw_arch: Option<String>,

    /// Specify a mode for a raw file: 32|64|arm|thumb|riscv
    #[arg(long = "rawMode", value_name = "<mode>")]
    pub raw_mode: Option<String>,

    /// Specify an endianness for a raw file: little|big
    #[arg(long = "rawEndian", value_name = "<endian>")]
    pub raw_endian: Option<String>,

    /// Emit a JSON array of {vaddr, bytes, text} instead of human output
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct JsonGadget {
    vaddr: String,
    bytes: String,
    text: String,
    /// Scan architecture — present for Universal (multi-slice) binaries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<&'static str>,
    /// Name of the section containing the gadget — present when --section
    /// was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    section: Option<String>,
}

pub fn parse_hex(s: &str, what: &str) -> Result<u64, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(t, 16).map_err(|e| format!("invalid {what} {s:?}: {e}"))
}

/// ROPgadget --range syntax: "0xSTART-0xEND". "0x0-0x0" means no range.
pub fn parse_range(s: &str) -> Result<Option<(u64, u64)>, String> {
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
pub fn parse_badbytes(s: &str) -> Result<Vec<u8>, String> {
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

pub fn arch_name(arch: Arch) -> &'static str {
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

pub fn endian_name(e: Endianness) -> &'static str {
    match e {
        Endianness::Little => "little",
        Endianness::Big => "big",
    }
}

/// A loaded binary before it is flattened into a scan view.
pub enum Target {
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
pub struct RegionView {
    arch: Arch,
    pub endian: Endianness,
    pub base: u64,
    pub entry: u64,
    pub regions: Vec<Section>,
    pub named_exec: Vec<Section>,
    /// True for Universal (multi-slice) binaries (JSON arch field).
    pub universal: bool,
}

pub fn build_view(target: &Target) -> RegionView {
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
pub fn select_sections(
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
pub struct ScanResult {
    pub gadgets: Vec<Gadget>,
    pub addr_size: usize,
    /// Some(arch) for Universal binaries (JSON arch field).
    pub universal_arch: Option<Arch>,
    /// Sections selected by --section as (name, vaddr, size), used for the
    /// JSON `section` field. None when --section was not used.
    pub selected_sections: Option<Vec<(String, u64, u64)>>,
}

pub fn hexs(v: u64) -> String {
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
pub fn info_json(target: &Target, new_base: Option<u64>) -> serde_json::Value {
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

// ---------------------------------------------------------------------------
// Library API (Phase 3): string-level scan requests shared by the CLI and
// the rf-mcp MCP server. Error precedence mirrors the CLI exactly:
// depth/file/raw-spec checks, then option parsing, then binary load, then
// --base parsing, then --section selection, then the scan itself.
// ---------------------------------------------------------------------------

/// Structured failure for library callers. The CLI maps `Usage` to exit 1
/// and `Binary` to exit 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// Bad arguments (unparsable hex/range/badbytes, unknown section, ...).
    Usage(String),
    /// Malformed/unsupported binary or scan-time failure.
    Binary(String),
    /// Chain generation failure (unsupported target, missing gadgets,
    /// violated IR invariant). Maps to CLI exit 1.
    Chain(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Usage(m) | ScanError::Binary(m) | ScanError::Chain(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ScanError {}

/// Raw-loader spec: (arch, endianness, thumb) as resolved by the CLI's
/// `--rawArch/--rawMode/--rawEndian/--thumb` validation.
pub type RawSpec = (Arch, Endianness, bool);

/// Scan inputs at the same string level as the CLI flags, so both front
/// ends share parsing and validation.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub depth: usize,
    pub rop: bool,
    pub jop: bool,
    pub sys: bool,
    pub multibr: bool,
    pub only: Option<String>,
    pub filter: Option<String>,
    pub range: Option<String>,
    pub badbytes: Option<String>,
    pub offset: Option<String>,
    pub base: Option<String>,
    pub section: Vec<String>,
    pub thumb: bool,
    /// CFG/CET-aware scan (Phase 4b): keep only endbr64/endbr32-entering
    /// gadgets.
    pub cfg_aware: bool,
}

impl Default for ScanRequest {
    fn default() -> Self {
        ScanRequest {
            depth: 10,
            rop: true,
            jop: true,
            sys: true,
            multibr: false,
            only: None,
            filter: None,
            range: None,
            badbytes: None,
            offset: None,
            base: None,
            section: Vec::new(),
            thumb: false,
            cfg_aware: false,
        }
    }
}

/// Everything a scan produces, plus the resolved options (needed for the
/// offset-aware JSON `section` lookup) and the stripped-ELF warning flag.
pub struct ScanOutcome {
    pub result: ScanResult,
    pub opts: ScanOptions,
    /// True when --section matched only synthetic `PT_LOAD#n` names.
    pub fallback_names: bool,
}

impl From<LoadedBinary> for Target {
    fn from(l: LoadedBinary) -> Self {
        match l {
            LoadedBinary::Elf(b) => Target::Elf(b),
            LoadedBinary::Pe(b) => Target::Pe(b),
            LoadedBinary::MachO(b) => Target::MachO(b),
            LoadedBinary::Raw(b) => Target::Raw(b),
            LoadedBinary::Universal(u) => Target::Universal(u),
        }
    }
}

/// Load `bytes` into a [`Target`]; `raw` forces the raw loader
/// (binary.py:32-49 — --rawArch wins over magic-byte detection).
pub fn load_target(bytes: &[u8], raw: Option<RawSpec>) -> Result<Target, ScanError> {
    if let Some((arch, endian, _)) = raw {
        return Ok(Target::Raw(RawBinary::new(bytes, arch, endian)));
    }
    Binary::load(bytes)
        .map(Target::from)
        .map_err(|e| ScanError::Binary(e.to_string()))
}

fn request_options(req: &ScanRequest, raw: Option<RawSpec>) -> Result<ScanOptions, ScanError> {
    if req.depth < 2 {
        return Err(ScanError::Usage("--depth must be >= 2".to_string()));
    }
    let usage = |e: String| ScanError::Usage(e);
    let mut opts = ScanOptions {
        depth: req.depth,
        rop: req.rop,
        jop: req.jop,
        sys: req.sys,
        multibr: req.multibr,
        only: req
            .only
            .as_deref()
            .map(|s| s.split('|').map(|x| x.to_string()).collect()),
        range: match &req.range {
            Some(r) => parse_range(r).map_err(usage)?,
            None => None,
        },
        badbytes: match &req.badbytes {
            Some(b) => parse_badbytes(b).map_err(usage)?,
            None => Vec::new(),
        },
        filter: req
            .filter
            .as_deref()
            .map(|s| s.split('|').map(|x| x.to_string()).collect())
            .unwrap_or_default(),
        offset: match &req.offset {
            Some(o) => parse_hex(o, "--offset").map_err(usage)?,
            None => 0,
        },
        thumb: req.thumb,
        cfg_aware: req.cfg_aware,
        parallel: true,
    };
    if let Some((_, _, raw_thumb)) = raw {
        opts.thumb = opts.thumb || raw_thumb;
    }
    Ok(opts)
}

/// Build the scan view for `target`, applying `--base` rebase and
/// Selected-section table entry: (name, vaddr, size) — used for the JSON
/// `section` field lookup.
pub type SectionEntry = (String, u64, u64);

/// Result of [`prepare_view`]: the scan view, the selected-section table
/// (when `--section` was used), and the stripped-ELF fallback-name flag.
pub struct PreparedView {
    pub view: RegionView,
    pub selected_sections: Option<Vec<SectionEntry>>,
    pub fallback_names: bool,
}

/// Build the scan view for `target`, applying `--base` rebase and
/// `--section` selection.
pub fn prepare_view(
    target: &Target,
    base: Option<u64>,
    sections: &[String],
) -> Result<PreparedView, ScanError> {
    let mut view = build_view(target);
    if let Some(base) = base {
        view.rebase(base);
    }
    let mut selected_sections = None;
    let mut fallback_names = false;
    if !sections.is_empty() {
        let (matched, fb) =
            select_sections(&view.named_exec, sections).map_err(ScanError::Usage)?;
        fallback_names = fb;
        selected_sections = Some(
            matched
                .iter()
                .map(|s| (s.name.clone(), s.vaddr, s.size))
                .collect(),
        );
        view.regions = matched;
    }
    Ok(PreparedView {
        view,
        selected_sections,
        fallback_names,
    })
}

/// Full scan pipeline over in-memory bytes: options → load → view → scan.
pub fn scan_bytes(
    bytes: &[u8],
    raw: Option<RawSpec>,
    req: &ScanRequest,
) -> Result<ScanOutcome, ScanError> {
    let opts = request_options(req, raw)?;
    let target = load_target(bytes, raw)?;
    let base = req
        .base
        .as_deref()
        .map(|b| parse_hex(b, "--base"))
        .transpose()
        .map_err(ScanError::Usage)?;
    let prepared = prepare_view(&target, base, &req.section)?;
    let view = prepared.view;
    let selected_sections = prepared.selected_sections;
    let fallback_names = prepared.fallback_names;
    let universal_arch = view.universal.then_some(view.arch());
    let gadgets =
        rf_scan::scan_binary(&view, &opts).map_err(|e| ScanError::Binary(e.to_string()))?;
    Ok(ScanOutcome {
        result: ScanResult {
            gadgets,
            addr_size: view.addr_size(),
            universal_arch,
            selected_sections,
        },
        opts,
        fallback_names,
    })
}

/// `--info` pipeline over in-memory bytes. `new_base` is the already-parsed
/// `--base` value (parse errors are usage errors on the caller side).
pub fn info_bytes(
    bytes: &[u8],
    raw: Option<RawSpec>,
    new_base: Option<u64>,
) -> Result<serde_json::Value, ScanError> {
    let target = load_target(bytes, raw)?;
    Ok(info_json(&target, new_base))
}

// ---------------------------------------------------------------------------
// --ropchain (Phases 4a/4b, PLAN.md sec. 6.2): chain generation.
// ---------------------------------------------------------------------------

/// Format name for chain dispatch / errors.
pub fn target_format(target: &Target) -> &'static str {
    match target {
        Target::Elf(_) => "elf",
        Target::Pe(_) => "pe",
        Target::MachO(_) => "macho",
        Target::Universal(_) => "universal",
        Target::Raw(_) => "raw",
    }
}

/// Chain target + Windows parameters (the CLI's `--chain`, `--api-addr`,
/// `--shellcode-addr`, `--shellcode-size`; MCP passes the same).
#[derive(Debug, Clone, Default)]
pub struct ChainSpec {
    /// "linux-execve" (default) or "windows-virtualprotect".
    pub target: String,
    pub api_addr: Option<String>,
    pub shellcode_addr: Option<String>,
    pub shellcode_size: Option<String>,
}

impl ChainSpec {
    /// Default when `--ropchain` is given without `--chain`.
    pub fn linux() -> Self {
        ChainSpec {
            target: "linux-execve".to_string(),
            ..ChainSpec::default()
        }
    }
}

/// A generated chain plus the scan it was built from.
pub struct ChainOutcome {
    pub chain: rf_chain::RopChain,
    pub outcome: ScanOutcome,
}

fn chain_err(e: rf_chain::ChainError) -> ScanError {
    match e {
        rf_chain::ChainError::Unsupported { .. } => ScanError::Usage(e.to_string()),
        other => ScanError::Chain(other.to_string()),
    }
}

/// Parse the Windows chain parameters (hex strings → WinChainOpts).
fn win_opts(spec: &ChainSpec) -> Result<rf_chain::WinChainOpts, ScanError> {
    let usage = |e: String| ScanError::Usage(e);
    Ok(rf_chain::WinChainOpts {
        api_addr: spec
            .api_addr
            .as_deref()
            .map(|a| parse_hex(a, "--api-addr"))
            .transpose()
            .map_err(usage)?,
        shellcode_addr: spec
            .shellcode_addr
            .as_deref()
            .map(|a| parse_hex(a, "--shellcode-addr"))
            .transpose()
            .map_err(usage)?,
        shellcode_size: match &spec.shellcode_size {
            Some(s) => parse_hex(s, "--shellcode-size").map_err(usage)?,
            None => rf_chain::windows::DEFAULT_SHELLCODE_SIZE,
        },
        ..rf_chain::WinChainOpts::default()
    })
}

/// `--ropchain` pipeline: options → load → dispatch on `--chain` target →
/// rebase → scan → chain build.
///
///   * `linux-execve` (default): ELF x86/x64, mirroring ropmaker.py:23-40.
///   * `windows-virtualprotect`: PE x86/x64 (Phase 4b, PLAN sec. 6.2).
pub fn chain_bytes(
    bytes: &[u8],
    raw: Option<RawSpec>,
    req: &ScanRequest,
    spec: &ChainSpec,
) -> Result<ChainOutcome, ScanError> {
    let opts = request_options(req, raw)?;
    let mut target = load_target(bytes, raw)?;

    let format = target_format(&target);
    let arch = match &target {
        Target::Elf(b) => Image::arch(b),
        Target::Pe(b) => Image::arch(b),
        t => Image::arch(&build_view(t)), // others: only used for the error
    };

    // Target dispatch: format gates the chain family.
    match spec.target.as_str() {
        "linux-execve" => {
            if !matches!(&target, Target::Elf(_)) || !matches!(arch, Arch::X86 | Arch::X64) {
                return Err(chain_err(rf_chain::ChainError::Unsupported {
                    arch: rf_chain::arch_name(arch),
                    format: format.to_string(),
                }));
            }
        }
        "windows-virtualprotect" => {
            if !matches!(&target, Target::Pe(_)) || !matches!(arch, Arch::X86 | Arch::X64) {
                return Err(chain_err(rf_chain::ChainError::Unsupported {
                    arch: rf_chain::arch_name(arch),
                    format: format.to_string(),
                }));
            }
        }
        other => {
            return Err(ScanError::Usage(format!(
                "unknown chain target {other:?}; supported: linux-execve, windows-virtualprotect"
            )));
        }
    }

    // Rebase the TARGET (not just the view) so the writable sections used
    // for the string write / lpflOldProtect carry the rebased vaddrs too.
    let base = req
        .base
        .as_deref()
        .map(|b| parse_hex(b, "--base"))
        .transpose()
        .map_err(ScanError::Usage)?;
    match &mut target {
        Target::Elf(b) => {
            if let Some(base) = base {
                b.rebase(base);
            }
        }
        Target::Pe(b) => {
            if let Some(base) = base {
                b.rebase(base);
            }
        }
        _ => {}
    }

    // CFG/CET guidance (PLAN sec. 6.2 #6): a GUARD_CF-marked PE scanned
    // without --cfg-aware produces chains that are DOA under enforced IBT.
    if let Target::Pe(b) = &target {
        if b.guard_cf() && !req.cfg_aware {
            eprintln!(
                "[Warning] PE is GUARD_CF-marked (CFG/CET); generated chains may be blocked \
                 under enforced IBT — consider --cfg-aware"
            );
        }
    }

    let prepared = prepare_view(&target, None, &req.section)?;
    let universal_arch = prepared.view.universal.then_some(prepared.view.arch());
    let gadgets = rf_scan::scan_binary(&prepared.view, &opts)
        .map_err(|e| ScanError::Binary(e.to_string()))?;

    let sections: &[rf_core::Section] = match &target {
        Target::Elf(b) => b.sections(),
        Target::Pe(b) => b.sections(),
        _ => unreachable!("dispatched above"),
    };
    // ROPgadget's getDataSections (elf.py:323-334): non-executable
    // sections; .data is picked by name inside the builders.
    let data_sections: Vec<rf_chain::DataSection> = sections
        .iter()
        .filter(|s| !s.executable)
        .map(|s| rf_chain::DataSection {
            name: s.name.clone(),
            // + opts.offset mirrors ropmaker's liboffset (the --offset
            // emission-time slide applies to .data too).
            vaddr: s.vaddr.wrapping_add(opts.offset),
            writable: s.writable,
        })
        .collect();

    let chain = match spec.target.as_str() {
        "linux-execve" => {
            rf_chain::build_linux_execve(&gadgets, &data_sections, arch, format, &opts.badbytes)
                .map_err(chain_err)?
        }
        "windows-virtualprotect" => {
            let Target::Pe(pe) = &target else {
                unreachable!("dispatched above")
            };
            rf_chain::build_windows_virtualprotect(
                &gadgets,
                &data_sections,
                pe.imports(),
                arch,
                format,
                &win_opts(spec)?,
                &opts.badbytes,
            )
            .map_err(chain_err)?
        }
        _ => unreachable!("validated above"),
    };

    Ok(ChainOutcome {
        chain,
        outcome: ScanOutcome {
            result: ScanResult {
                gadgets,
                addr_size: prepared.view.addr_size(),
                universal_arch,
                selected_sections: prepared.selected_sections,
            },
            opts,
            fallback_names: prepared.fallback_names,
        },
    })
}

fn run(cli: Cli) -> Result<i32, String> {
    // Error precedence mirrors the pre-refactor CLI exactly: depth → file
    // read → raw spec → option parsing → binary load → (--info | --base →
    // --section → scan).
    if cli.depth < 2 {
        return Err("--depth must be >= 2".to_string());
    }
    let bytes =
        std::fs::read(&cli.binary).map_err(|e| format!("cannot read {}: {e}", cli.binary))?;
    let raw = parse_raw_spec(&cli)?;

    let req = ScanRequest {
        depth: cli.depth,
        rop: !cli.norop,
        jop: !cli.nojop,
        sys: !cli.nosys,
        multibr: cli.multibr,
        only: cli.only.clone(),
        filter: cli.filter.clone(),
        range: cli.range.clone(),
        badbytes: cli.badbytes.clone(),
        offset: cli.offset.clone(),
        base: cli.base.clone(),
        section: cli.section.clone(),
        thumb: cli.thumb,
        cfg_aware: cli.cfg_aware,
    };
    let opts = match request_options(&req, raw) {
        Ok(o) => o,
        Err(ScanError::Usage(e)) => return Err(e),
        Err(ScanError::Binary(e) | ScanError::Chain(e)) => return Err(e), // unreachable
    };
    let target = match load_target(&bytes, raw) {
        Ok(t) => t,
        Err(ScanError::Binary(e)) => {
            eprintln!("[Error] {e}");
            return Ok(2);
        }
        Err(ScanError::Usage(e) | ScanError::Chain(e)) => return Err(e), // unreachable
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

    // --ropchain: chain generation (--chain selects the target). Unlike
    // ROPgadget, which dumps the gadget list and step logs first, we print
    // only the exploit script (or the JSON Chain IR with --json).
    if cli.ropchain {
        let spec = ChainSpec {
            target: cli.chain.clone(),
            api_addr: cli.api_addr.clone(),
            shellcode_addr: cli.shellcode_addr.clone(),
            shellcode_size: cli.shellcode_size.clone(),
        };
        let outcome = match chain_bytes(&bytes, raw, &req, &spec) {
            Ok(o) => o,
            Err(ScanError::Usage(e)) | Err(ScanError::Chain(e)) => return Err(e),
            Err(ScanError::Binary(e)) => {
                eprintln!("[Error] {e}");
                return Ok(2);
            }
        };
        if outcome.outcome.fallback_names {
            eprintln!(
                "[Warning] binary has no section names (stripped ELF?);                  executable segments are named PT_LOAD#n"
            );
        }
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&outcome.chain.to_json()).unwrap()
            );
        } else {
            print!("{}", outcome.chain.to_python());
        }
        return Ok(0);
    }

    let base = cli
        .base
        .as_deref()
        .map(|b| parse_hex(b, "--base"))
        .transpose()?;
    let prepared = match prepare_view(&target, base, &cli.section) {
        Ok(v) => v,
        Err(ScanError::Usage(e)) => return Err(e),
        Err(ScanError::Binary(e) | ScanError::Chain(e)) => return Err(e), // unreachable
    };
    let view = prepared.view;
    if prepared.fallback_names {
        eprintln!(
            "[Warning] binary has no section names (stripped ELF?); \
             executable segments are named PT_LOAD#n"
        );
    }
    let universal_arch = view.universal.then_some(view.arch());

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
        selected_sections: prepared.selected_sections,
    };

    if cli.json {
        print_json(&result, opts.offset);
    } else {
        print_human(&result);
    }
    Ok(0)
}

pub fn fmt_addr(vaddr: u64, addr_size: usize) -> String {
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
pub fn section_of(selected: &[(String, u64, u64)], vaddr: u64) -> Option<String> {
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

pub fn main_entry() -> ExitCode {
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
            ropchain: false,
            chain: "linux-execve".into(),
            api_addr: None,
            shellcode_addr: None,
            shellcode_size: None,
            cfg_aware: false,
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
            cfg_aware: false,
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

    // -- --ropchain (Phase 4a) ------------------------------------------------

    fn chain_fixture(fixture: &str) -> ChainOutcome {
        match chain_bytes(
            &fixture_bytes(fixture),
            None,
            &ScanRequest::default(),
            &ChainSpec::linux(),
        ) {
            Ok(o) => o,
            Err(e) => panic!("chain build failed for {fixture}: {e}"),
        }
    }

    /// vaddr universe for `RopChain::validate`: the scan's gadget vaddrs.
    fn scan_universe(out: &ChainOutcome) -> std::collections::HashSet<u64> {
        out.outcome
            .result
            .gadgets
            .iter()
            .map(|g| g.vaddr.wrapping_add(out.outcome.opts.offset))
            .collect()
    }

    #[test]
    fn chain_builds_on_linux_x64() {
        let out = chain_fixture("elf-Linux-x64");
        let chain = &out.chain;
        assert_eq!(chain.arch, "x64");
        assert_eq!(chain.word_size, 8);
        chain.validate(&scan_universe(&out), &[]).unwrap();
        // Renderers: python script has the ropmaker header; every word
        // except string immediates renders as a pack line (padding is
        // tab-indented); JSON exposes the full IR.
        let py = chain.to_python();
        assert!(py.starts_with("#!/usr/bin/env python3\n# execve generated by ROPgadget\n"));
        assert!(py.contains("p += b'/bin//sh'"));
        assert_eq!(
            py.matches("p += pack('<Q',").count(),
            chain
                .words
                .iter()
                .filter(|w| w.kind != rf_chain::WordKind::Immediate)
                .count()
        );
        let json = chain.to_json();
        assert_eq!(json["arch"], "x64");
        assert_eq!(json["words"].as_array().unwrap().len(), chain.words.len());
    }

    #[test]
    fn chain_builds_on_linux_x86() {
        let out = chain_fixture("elf-Linux-x86");
        let chain = &out.chain;
        assert_eq!(chain.arch, "x86");
        assert_eq!(chain.word_size, 4);
        chain.validate(&scan_universe(&out), &[]).unwrap();
        assert!(chain.to_python().contains("pack('<I',"));
    }

    #[test]
    fn chain_gadget_addrs_come_from_scan() {
        // Property test: every GadgetAddr word references a vaddr the scan
        // actually produced, and the chain's gadget table agrees.
        let out = chain_fixture("elf-Linux-x64");
        let universe = scan_universe(&out);
        for w in &out.chain.words {
            if w.kind == rf_chain::WordKind::GadgetAddr {
                let g = &out.chain.gadgets[w.source_gadget.unwrap()];
                assert_eq!(g.vaddr, w.value);
                assert!(
                    universe.contains(&w.value),
                    "chain gadget {:#x} not in scan output",
                    w.value
                );
            }
        }
        // The execve chain must end in a syscall gadget.
        let last = out.chain.gadgets.last().unwrap();
        assert!(last.text.contains("syscall"));
    }

    #[test]
    fn chain_rejects_unsupported_targets() {
        // PE x64 → Usage error ("not supported"), mirroring ropmaker.py's
        // dispatch which only knows ELF x86/x64.
        let err = match chain_bytes(
            &fixture_bytes("pe-x64-cmd-v6.1.7601"),
            None,
            &ScanRequest::default(),
            &ChainSpec::linux(),
        ) {
            Err(e) => e,
            Ok(_) => panic!("PE chain build unexpectedly succeeded"),
        };
        match err {
            ScanError::Usage(m) => assert!(m.contains("not supported"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
        // ELF but wrong arch (ARM64) → same structured refusal.
        let err = match chain_bytes(
            &fixture_bytes("elf-ARM64-bash"),
            None,
            &ScanRequest::default(),
            &ChainSpec::linux(),
        ) {
            Err(e) => e,
            Ok(_) => panic!("ARM64 chain build unexpectedly succeeded"),
        };
        assert!(matches!(err, ScanError::Usage(_)));
    }

    #[test]
    fn chain_missing_gadgets_is_structured_error() {
        // elf-x64-bash lacks a "mov qword ptr [r64], r64" gadget — ROPgadget
        // prints "Can't find ..." and gives up; we return ScanError::Chain.
        let err = match chain_bytes(
            &fixture_bytes("elf-x64-bash-v4.1.5.1"),
            None,
            &ScanRequest::default(),
            &ChainSpec::linux(),
        ) {
            Err(e) => e,
            Ok(_) => panic!("bash chain build unexpectedly succeeded"),
        };
        match err {
            ScanError::Chain(m) => assert!(m.contains("mov qword ptr"), "{m}"),
            other => panic!("expected Chain, got {other:?}"),
        }
    }

    #[test]
    fn chain_honours_badbytes() {
        // elf-Linux-x64's image base is 0x400000; banning 0x40 must make
        // the build fail (every gadget address contains it), proving the
        // badbytes constraint reaches the chain builder.
        let req = ScanRequest {
            badbytes: Some("40".into()),
            ..ScanRequest::default()
        };
        let res = chain_bytes(
            &fixture_bytes("elf-Linux-x64"),
            None,
            &req,
            &ChainSpec::linux(),
        );
        assert!(matches!(res, Err(ScanError::Chain(_))));
    }

    // -- --chain windows-virtualprotect (Phase 4b) ---------------------------

    fn win_spec() -> ChainSpec {
        ChainSpec {
            target: "windows-virtualprotect".into(),
            api_addr: Some("0x7fff12340000".into()),
            shellcode_addr: None,
            shellcode_size: None,
        }
    }

    #[test]
    fn chain_windows_x86_stdcall_full_chain() {
        // pe-x86-cmd: stdcall needs no gadgets — the chain is
        // [api][ret→shellcode][4 args] and VirtualProtect's ret 0x10
        // continues into the shellcode (second-stack frame).
        let out = chain_bytes(
            &fixture_bytes("pe-x86-cmd-v6.1.7600"),
            None,
            &ScanRequest::default(),
            &win_spec(),
        )
        .unwrap();
        let chain = &out.chain;
        assert_eq!(chain.arch, "x86");
        assert_eq!(chain.word_size, 4);
        let values: Vec<u64> = chain.words.iter().map(|w| w.value).collect();
        assert_eq!(values.len(), 6);
        assert_eq!(values[0], 0x7fff12340000, "api addr (--api-addr)");
        assert_eq!(
            values[1], values[2],
            "return-to and lpAddress both = shellcode"
        );
        assert_eq!(values[3], 0x1000, "default dwSize");
        assert_eq!(values[4], 0x40, "PAGE_EXECUTE_READWRITE");
        // shellcode defaults to the PE's writable .data
        assert!(chain.description.contains("VirtualProtect"));
        chain
            .validate(&std::collections::HashSet::new(), &[])
            .unwrap();
        // python renderer: 6 pack('<I') words
        assert_eq!(chain.to_python().matches("pack('<I',").count(), 6);
    }

    #[test]
    fn chain_windows_x64_cmd_reports_spike_scarcity() {
        // The spike finding: pe-x64-cmd has NO ret-terminated gadget that
        // writes rdx/r8/r9. The builder must fail with a structured error
        // naming the unpopulatable register and the strategies tried.
        let err = chain_bytes(
            &fixture_bytes("pe-x64-cmd-v6.1.7601"),
            None,
            &ScanRequest::default(),
            &win_spec(),
        )
        .err()
        .expect("x64 cmd cannot sustain a VirtualProtect chain (spike report)");
        match err {
            ScanError::Chain(m) => {
                assert!(m.contains("cannot populate rdx"), "{m}");
                assert!(m.contains("pop rdx"), "{m}");
                assert!(m.contains("mov rdx, rax"), "{m}");
            }
            other => panic!("expected Chain, got {other:?}"),
        }
    }

    #[test]
    fn chain_windows_x64_ntoskrnl_full_chain() {
        // ring0 target from PLAN sec. 6.2 #5; the spike binary is
        // gitignored, so skip gracefully when absent.
        let path = format!(
            "{}/../../tests/spike-binaries/ntoskrnl.exe",
            env!("CARGO_MANIFEST_DIR")
        );
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: tests/spike-binaries/ntoskrnl.exe not present");
            return;
        };
        let out = chain_bytes(&bytes, None, &ScanRequest::default(), &win_spec()).unwrap();
        let chain = &out.chain;
        assert_eq!(chain.arch, "x64");
        assert_eq!(chain.word_size, 8);

        // Structure: 4×(pop gadget + arg word), transfer at an EVEN index
        // (alignment invariant), then return-to-shellcode + 4 shadow words.
        let call_idx = chain
            .words
            .iter()
            .position(|w| w.comment.contains("--api-addr"))
            .unwrap();
        assert_eq!(call_idx % 2, 0, "alignment invariant");
        assert_eq!(chain.words.len(), call_idx + 1 + 1 + 4);
        assert_eq!(chain.words[call_idx].value, 0x7fff12340000);
        assert_eq!(
            chain.words[call_idx + 1].value,
            chain.words[1].value,
            "return address = shellcode (arg1)"
        );
        assert!(chain.words[call_idx + 2..]
            .iter()
            .all(|w| w.kind == rf_chain::WordKind::Padding));

        // Property: every gadget word references a real scan gadget.
        let universe: std::collections::HashSet<u64> = out
            .outcome
            .result
            .gadgets
            .iter()
            .map(|g| g.vaddr.wrapping_add(out.outcome.opts.offset))
            .collect();
        for w in &chain.words {
            if w.kind == rf_chain::WordKind::GadgetAddr {
                assert!(universe.contains(&w.value), "{:#x} not in scan", w.value);
            }
        }
        chain.validate(&universe, &[]).unwrap();
    }

    #[test]
    fn chain_windows_rejects_wrong_format_and_unknown_target() {
        // windows-virtualprotect on an ELF → structured "not supported".
        let err = chain_bytes(
            &fixture_bytes("elf-Linux-x64"),
            None,
            &ScanRequest::default(),
            &win_spec(),
        )
        .err()
        .unwrap();
        match err {
            ScanError::Usage(m) => assert!(m.contains("not supported"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
        // unknown --chain value → usage error naming valid targets.
        let err = chain_bytes(
            &fixture_bytes("elf-Linux-x64"),
            None,
            &ScanRequest::default(),
            &ChainSpec {
                target: "plan9-forkbomb".into(),
                ..ChainSpec::default()
            },
        )
        .err()
        .unwrap();
        match err {
            ScanError::Usage(m) => assert!(m.contains("linux-execve"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }
}
