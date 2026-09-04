//! rf-api — the front-end-agnostic request layer of rop-finder.
//!
//! Everything both front ends need in order to turn *strings a user typed*
//! into *a scan, an image report or a ROP chain*: [`ScanRequest`] and its
//! option building ([`request_options`]), the loader dispatch
//! ([`load_target`], [`prepare_view`]), the three pipelines
//! ([`scan_bytes`], [`info_bytes`], [`chain_bytes`]) with their cancellable
//! twin ([`scan_bytes_cancellable`]), and the v0.4 constraint query layer
//! ([`query`]).
//!
//! # Why this crate exists
//!
//! It used to live in `rf-cli`, which is a **binary** crate, and `rf-mcp`
//! depended on it there. That is not publishable (a binary crate has no
//! usable library API for a third party), and it had already cost the
//! project two real defects: the MCP server had to re-implement the option
//! mapping and the cache key because the CLI's were private, and the
//! `--align` post-filter (ANCH-02) and the cache char-boundary panic
//! (ROB-04) each existed in two slightly different copies. `rf-cache` was
//! split out for the second pair; this crate is the first pair, and it is
//! the reason `cargo tree -p rop-finder-mcp` no longer mentions `rf-cli`.
//!
//! `rf-cli` re-exports everything here, so `rf_cli::ScanRequest` and
//! `rf_api::ScanRequest` are the same type.
//!
//! # Layers
//!
//! ```text
//!   rf-core   loaders, sections, mitigations
//!   rf-scan   the gadget engine (ScanOptions -> Vec<Gadget>)
//!   rf-classify  semantics over one gadget
//!   rf-chain  chain builders over a gadget set
//!        |
//!   rf-api   <-- strings in, results out; no I/O policy, no output format
//!      |  \
//!   rf-cli   rf-mcp
//! ```
//!
//! This crate deliberately holds **no output formatting** (human text, CSV,
//! the MCP wire shapes) and **no I/O policy** (the cache directory, path
//! confinement, the interactive console). Those differ per front end and
//! are exactly the things that should not be shared.
//!
//! # Semver policy
//!
//! See [`docs/API-STABILITY.md`](https://github.com/rop-finder/rop-finder/blob/main/docs/API-STABILITY.md).
//! In short: the item signatures below are covered by semver; the *text* of
//! an error message, the exact JSON produced by [`info_json`] /
//! [`plan_json`], and anything marked `#[doc(hidden)]` are not. Pin
//! `rf-api = "1"` and treat error strings as diagnostics, not as an API.
//!
//! # Example
//!
//! Scan a raw x86-64 blob and print what came back. `pop rdi ; ret` is
//! `5f c3`; a real caller passes `std::fs::read("/bin/ls")?` instead of a
//! byte literal.
//!
//! ```
//! use rf_api::{scan_bytes, ScanRequest};
//! use rf_core::{Arch, Endianness};
//!
//! let bytes = [0x5fu8, 0xc3];
//! let req = ScanRequest {
//!     depth: 4,
//!     ..ScanRequest::default()
//! };
//! let out = scan_bytes(&bytes, Some((Arch::X64, Endianness::Little, false)), &req)?;
//! let texts: Vec<String> = out.result.gadgets.iter().map(|g| g.text()).collect();
//! assert!(texts.iter().any(|t| t == "pop rdi ; ret"));
//! # Ok::<(), rf_api::ScanError>(())
//! ```

// ENG-08: every public item carries documentation.
#![warn(missing_docs)]

use std::fmt;

use globset::{Glob, GlobSetBuilder};
use rf_core::{
    Arch, Binary, Endianness, Image, LoadedBinary, MachOBinary, Mitigations, RawBinary, Section,
    UniversalBinary,
};
use rf_scan::{CancelToken, Gadget, ScanOptions};

mod info;
// CHWIN-08 #3: the export directory rf-core does not parse.
pub mod pe_exports;
pub mod query;

/// ROB-06 default input cap: 512 MiB.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// Parse a byte count with an optional binary `K`/`M`/`G` suffix
/// (`--max-file-size`, `--max-memory`). Plain decimal, never hex: these
/// are sizes a human types, and `--max-file-size 10M` must not silently
/// become 0x10.
pub fn parse_size(s: &str, what: &str) -> Result<u64, String> {
    let t = s.trim();
    if t.is_empty() {
        return Err(format!("invalid {what} {s:?}: empty"));
    }
    let (digits, mult) = match t.as_bytes()[t.len() - 1] {
        b'k' | b'K' => (&t[..t.len() - 1], 1024u64),
        b'm' | b'M' => (&t[..t.len() - 1], 1024 * 1024),
        b'g' | b'G' => (&t[..t.len() - 1], 1024 * 1024 * 1024),
        _ => (t, 1),
    };
    let n: u64 = digits
        .trim()
        .parse()
        .map_err(|e| format!("invalid {what} {s:?}: {e}"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("invalid {what} {s:?}: overflows a u64"))
}

/// ROB-06: decide whether `path` may be read at all, from its metadata
/// alone — BEFORE a byte is allocated.
///
/// Two refusals, both of which `std::fs::read` performs instead of
/// diagnosing: a non-regular file (character device, FIFO, directory,
/// socket) has no length, so `read_to_end` grows the buffer until the OS
/// kills the process (`--binary /dev/zero`: 8.6 GB RSS at 1 s, measured in
/// ROB-06); and a regular file larger than the cap is materialised in full
/// before the format is even sniffed.
///
/// Split out from [`read_input_file`] so it is unit-testable without a
/// character device, which Windows CI does not have.
pub fn check_input_metadata(
    path: &str,
    meta: &std::fs::Metadata,
    max_bytes: u64,
) -> Result<(), String> {
    if !meta.is_file() {
        let kind = if meta.is_dir() {
            "a directory"
        } else {
            "not a regular file (character device, FIFO, socket or symlink loop?)"
        };
        return Err(format!(
            "cannot read {path}: {kind}; rop-finder reads whole files into memory and \
             refuses inputs with no fixed length"
        ));
    }
    let len = meta.len();
    if len > max_bytes {
        return Err(format!(
            "cannot read {path}: {len} bytes exceeds the --max-file-size limit of \
             {max_bytes} bytes; re-run with --max-file-size {len} to allow it"
        ));
    }
    Ok(())
}

/// ROB-06: stat, then read. Never `std::fs::read` a path the caller has
/// not bounded.
pub fn read_input_file(path: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    check_input_metadata(path, &meta, max_bytes)?;
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    // TOCTOU: the file may have grown between the stat and the read.
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "cannot read {path}: file grew past the --max-file-size limit of {max_bytes} bytes \
             while it was being read"
        ));
    }
    Ok(bytes)
}

/// Parse a hexadecimal integer, with an optional `0x`/`0X` prefix.
///
/// ALWAYS base 16, prefix or not: `--offset 16` means 0x16, exactly as
/// ROPgadget reads it. `what` names the flag in the error message.
///
/// ```
/// assert_eq!(rf_api::parse_hex("0x401000", "--base")?, 0x401000);
/// assert_eq!(rf_api::parse_hex("16", "--offset")?, 0x16);
/// assert!(rf_api::parse_hex("zz", "--base").is_err());
/// # Ok::<(), String>(())
/// ```
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

/// rop-finder's own architecture spelling, as it appears in `--info` and
/// in JSON gadget records: `"x86"`, `"x64"`, `"arm-thumb"`, `"mips32"`.
///
/// Distinct from [`rf_core::Arch::slice_name`], which is the Mach-O
/// spelling `--arch` accepts (`i386`, `x86_64`).
///
/// ```
/// use rf_core::Arch;
/// assert_eq!(rf_api::arch_name(Arch::X64), "x64");
/// assert_eq!(Arch::X64.slice_name(), "x86_64");
/// ```
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

/// `"little"` or `"big"`, as `--info` spells it.
pub fn endian_name(e: Endianness) -> &'static str {
    match e {
        Endianness::Little => "little",
        Endianness::Big => "big",
    }
}

/// A loaded binary before it is flattened into a scan view.
pub enum Target {
    /// An ELF image.
    Elf(rf_core::ElfBinary),
    /// A PE/COFF image.
    Pe(rf_core::PeBinary),
    /// A single-architecture Mach-O image.
    MachO(MachOBinary),
    /// A fat (Universal) Mach-O container; pick a slice with
    /// [`resolve_arch`] before scanning.
    Universal(UniversalBinary),
    /// A flat blob loaded with an explicit architecture.
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
    /// The byte order gadgets are decoded with.
    pub endian: Endianness,
    /// The view's image base, after any `--base` rebase.
    pub base: u64,
    /// The image's entry point, after any `--base` rebase.
    pub entry: u64,
    /// The regions the scanner walks. Replaced by the `--section` subset
    /// when `--section` was given.
    pub regions: Vec<Section>,
    /// Every named executable section, for `--section` matching and for the
    /// JSON `section` field.
    pub named_exec: Vec<Section>,
    /// True for Universal (multi-slice) binaries (JSON arch field).
    pub universal: bool,
}

/// CORE-03/CORE-05 — resolve `--arch` against a loaded target.
///
/// Returns the architecture whose slice should be scanned, or a usage
/// error. The three refusals are all deliberate:
///
///   * a multi-slice fat Mach-O with no `--arch` is REFUSED, not guessed.
///     ROPgadget concatenates every slice's executable regions and
///     disassembles the lot with the FIRST slice's decoder
///     (`universal.py:92-108`). On an Apple-silicon x86_64+arm64e binary
///     that means the arm64 slice is read as x86-64: measured on
///     `/bin/ls`, 202 of 491 gadgets (41% of the output) are x86
///     misreadings of ARM64 instructions, printed at addresses in the same
///     range as the genuine ones so the user cannot separate them.
///   * `--arch` naming a slice the container does not hold is an error
///     that lists what it does hold (rf-core's message).
///   * `--arch` on a non-fat image is accepted only when it agrees with
///     the image's own architecture, so it can be left in a script without
///     silently selecting nothing.
pub fn resolve_arch(
    target: &Target,
    arch: Option<&str>,
    compat: bool,
) -> Result<Option<Arch>, ScanError> {
    let named = match arch {
        Some(a) => Some(Arch::from_slice_name(a).ok_or_else(|| {
            ScanError::Usage(format!(
                "unknown --arch {a:?}; expected an architecture slice name such as \
                 x86_64, i386, arm64, arm, ppc, ppc64"
            ))
        })?),
        None => None,
    };
    match target {
        Target::Universal(u) => match named {
            Some(a) => {
                u.select(a).map_err(|e| ScanError::Usage(e.to_string()))?;
                Ok(Some(a))
            }
            None => {
                if u.needs_arch_selection() && !compat {
                    let available = u
                        .slice_infos()
                        .iter()
                        .map(|s| s.name())
                        .collect::<Vec<_>>()
                        .join(", ");
                    Err(ScanError::Usage(format!(
                        "universal (fat Mach-O) binary holds {} architecture slices \
                         ({available}); pass --arch <slice> to choose one. Refusing to scan \
                         the concatenation: the slices' virtual address ranges overlap and \
                         every slice but the first would be disassembled with the wrong \
                         decoder, so most of the output would be fabricated",
                        u.slices().len()
                    )))
                } else {
                    Ok(None)
                }
            }
        },
        other => match named {
            None => Ok(None),
            Some(a) => {
                let actual = build_view(other).arch();
                if a == actual {
                    Ok(Some(a))
                } else {
                    Err(ScanError::Usage(format!(
                        "--arch {} does not match this binary: it is {}. --arch selects a \
                         slice of a fat (Universal) Mach-O; it does not reinterpret a \
                         single-architecture image (use --rawArch for that)",
                        a.slice_name(),
                        actual.slice_name()
                    )))
                }
            }
        },
    }
}

/// [`build_view`] with a fat-Mach-O slice already chosen. `arch` comes
/// from [`resolve_arch`]; `None` keeps the legacy whole-container view,
/// which is only reachable for a single-slice container.
pub fn build_view_selected(target: &Target, arch: Option<Arch>) -> RegionView {
    match (target, arch) {
        (Target::Universal(u), Some(a)) => match u.select(a) {
            Ok(slice) => RegionView {
                arch: slice.arch(),
                endian: slice.endianness(),
                base: slice.image_base(),
                entry: slice.entry(),
                regions: slice.exec_scan_regions().to_vec(),
                named_exec: slice.exec_sections().into_iter().cloned().collect(),
                // Still flagged universal so the JSON output keeps naming
                // the architecture the gadgets were decoded with.
                universal: true,
            },
            // resolve_arch validated the slice exists; if it somehow did
            // not, fall back rather than panic.
            Err(_) => build_view(target),
        },
        _ => build_view(target),
    }
}

/// Flatten a loaded [`Target`] into the [`RegionView`] the scanner walks.
///
/// For a fat Mach-O this takes ROPgadget's whole-container view; use
/// [`build_view_selected`] with a slice from [`resolve_arch`] instead.
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
    /// The gadgets, in the engine's deterministic order.
    pub gadgets: Vec<Gadget>,
    /// 4 or 8 - the width addresses are printed at.
    pub addr_size: usize,
    /// Some(arch) for Universal binaries (JSON arch field).
    pub universal_arch: Option<Arch>,
    /// Sections selected by --section as (name, vaddr, size), used for the
    /// JSON `section` field. None when --section was not used.
    pub selected_sections: Option<Vec<(String, u64, u64)>>,
}

/// `0x`-prefixed lowercase hex, unpadded - the spelling every JSON address
/// field uses.
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
    /// ECO-06: the exploit mitigations, as
    /// `{name: {enabled: bool|"unknown", evidence, detail}}`.
    mitigations: &'a Mitigations,
    /// ECO-06: the symbol table, when the loader has one. `None` (rather
    /// than `[]`) for a format whose symbols rf-core does not read yet, so
    /// "no symbols in this file" and "not implemented for this format" are
    /// distinguishable — the exact confusion the hardcoded empty `imports`
    /// list created.
    symbols: Option<Vec<serde_json::Value>>,
    delta: u64,
}

fn image_info(v: InfoView) -> serde_json::Value {
    let mut o = serde_json::json!({
        "format": v.format,
        "arch": arch_name(v.arch),
        "endianness": endian_name(v.endian),
        "addr_size": v.arch.addr_size(),
        "image_base": hexs(v.image_base.wrapping_add(v.delta)),
        "entry": hexs(v.entry.wrapping_add(v.delta)),
        "sections": v.sections.iter().map(|s| section_json(s, v.delta)).collect::<Vec<_>>(),
        "imports": v.imports,
        "mitigations": info::mitigations_json(v.mitigations),
        "mitigations_order": info::mitigation_order_json(v.mitigations),
    });
    let map = o.as_object_mut().expect("json! built an object");
    // An empty mitigation set is a fact with a reason (a raw blob has no
    // headers); rendering `{}` alone would read as "nothing is enabled".
    if let Some(note) = v.mitigations.note() {
        map.insert("mitigations_note".into(), note.into());
    }
    if let Some(syms) = v.symbols {
        map.insert("symbol_count".into(), syms.len().into());
        map.insert("symbols".into(), syms.into());
    }
    o
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
        mitigations: b.mitigations(),
        symbols: None,
        delta,
    })
}

/// PLAN.md §6.4: `--info` payload. Addresses are hex strings (consistent
/// with gadget vaddrs), sizes are numbers. `--base` is honoured so the
/// printed addresses match what a scan would emit.
pub fn info_json(target: &Target, new_base: Option<u64>) -> serde_json::Value {
    match target {
        Target::Elf(b) => {
            let delta = rebase_delta(b.image_base(), new_base);
            image_info(InfoView {
                format: "elf",
                arch: Image::arch(b),
                endian: Image::endianness(b),
                image_base: b.image_base(),
                entry: b.entry(),
                sections: b.sections(),
                // ECO-06: this was `Vec::new()` — README documented it as
                // "PE only; [] otherwise" — so ret2plt/ret2libc needed a
                // second tool on every ELF. It is now the SHN_UNDEF subset
                // of .dynsym/.symtab, with the DT_JMPREL GOT slot and a
                // PLT address where one is provable.
                imports: b
                    .imports()
                    .iter()
                    .map(|s| info::elf_import_json(s, delta))
                    .collect(),
                mitigations: b.mitigations(),
                symbols: Some(
                    b.symbols()
                        .iter()
                        .map(|s| info::symbol_json(s, delta))
                        .collect(),
                ),
                delta,
            })
        }
        Target::Pe(b) => {
            let delta = rebase_delta(b.image_base(), new_base);
            let imports = b
                .imports()
                .iter()
                .map(|i| {
                    // CHWIN-03: `iat_vaddr` is the IAT slot the loader
                    // patches (deref this); `hint_name_vaddr` is the
                    // IMAGE_IMPORT_BY_NAME record holding the name string.
                    // Before the fix `iat_vaddr` carried the latter.
                    serde_json::json!({
                        "dll": i.dll,
                        "symbol": i.name,
                        "iat_vaddr": hexs(i.iat_slot_vaddr.wrapping_add(delta)),
                        "hint_name_vaddr": hexs(i.hint_name_vaddr.wrapping_add(delta)),
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
                mitigations: b.mitigations(),
                symbols: None,
                delta,
            })
        }
        Target::MachO(b) => macho_info(b, rebase_delta(b.image_base(), new_base)),
        Target::Raw(b) => {
            // `RawBinary::mitigations()` returns by value (an empty set
            // carrying its note), so it has to outlive the borrow.
            let m = b.mitigations();
            image_info(InfoView {
                format: "raw",
                arch: Image::arch(b),
                endian: Image::endianness(b),
                image_base: b.image_base(),
                entry: b.entry(),
                sections: std::slice::from_ref(b.section()),
                imports: Vec::new(),
                mitigations: &m,
                symbols: None,
                delta: rebase_delta(b.image_base(), new_base),
            })
        }
        Target::Universal(u) => {
            // Same convention as RegionView: the view base is the FIRST
            // slice's image base, so --base slides every slice by
            // new_base - first_base.
            let first_base = u.slices()[0].image_base();
            let delta = rebase_delta(first_base, new_base);
            // CORE-03: each slice also carries the name `--arch` accepts.
            // `arch` is rop-finder's internal spelling ("x64"), `slice` is
            // the Mach-O one ("x86_64"); without both, `--info` tells you a
            // fat binary has two slices and not what to type to pick one.
            let slices: Vec<serde_json::Value> = u
                .slices()
                .iter()
                .zip(u.slice_infos())
                .map(|(s, info)| {
                    let mut v = macho_info(s, delta);
                    if let Some(o) = v.as_object_mut() {
                        o.insert("slice".into(), info.name().into());
                        o.insert("slice_offset".into(), hexs(info.offset).into());
                        o.insert("slice_size".into(), info.size.into());
                    }
                    v
                })
                .collect();
            serde_json::json!({
                "format": "universal",
                "fat64": u.is_fat64(),
                "arch_selection_required": u.needs_arch_selection(),
                "slices": slices,
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
    /// `--depth`: how many bytes back from an anchor a gadget may start.
    pub depth: usize,
    /// Search the ROP anchor table (`--norop` clears it).
    pub rop: bool,
    /// Search the JOP anchor table (`--nojop` clears it).
    pub jop: bool,
    /// Search the SYS anchor table (`--nosys` clears it).
    pub sys: bool,
    /// `--multibr`: allow branches in the middle of a gadget.
    pub multibr: bool,
    /// `--only`: a `|`-separated mnemonic set; every instruction must match.
    pub only: Option<String>,
    /// `--filter`: a `|`-separated regex alternation, full-matched against
    /// each mnemonic; a gadget with a match is dropped.
    pub filter: Option<String>,
    /// `--range`: `"0xSTART-0xEND"`. `"0x0-0x0"` means no range.
    pub range: Option<String>,
    /// `--badbytes`: `"bb|bb|lo-hi"`, rejected in the FINAL address.
    pub badbytes: Option<String>,
    /// `--offset` (hex): added to gadget addresses at emission.
    pub offset: Option<String>,
    /// `--base` (hex): the image base to rebase to before scanning.
    pub base: Option<String>,
    /// `--section`: glob patterns naming the executable sections to scan.
    pub section: Vec<String>,
    /// `--thumb`: decode 32-bit ARM in T32 mode.
    pub thumb: bool,
    /// CFG/CET-aware scan (Phase 4b): keep only endbr64/endbr32-entering
    /// gadgets.
    pub cfg_aware: bool,
    /// ROPgadget --align: anchor-stepping alignment override (engine
    /// semantics, gadgets.py:66-67 — NOT a post-filter).
    pub align: Option<usize>,
    /// ROPgadget --callPreceded: capture prev bytes for the CLI filter.
    pub call_preceded: bool,
    /// ROPgadget --all: skip dedup.
    pub all: bool,
    /// ROPgadget --noinstr: skip dedup and sort; print bare addresses.
    pub noinstr: bool,
    /// Fat Mach-O slice selection (CORE-03/CORE-05), as the `--arch`
    /// spelling (`x86_64`, `arm64`, ...). `None` on a multi-slice container
    /// is a REFUSAL, not a guess.
    pub arch: Option<String>,
    /// PERF-05 `--max-gadgets`: abort with a budget error once this many
    /// gadgets have been accepted. `None` = unbounded.
    pub max_gadgets: Option<usize>,
    /// PERF-05 `--max-memory`: abort with a budget error once the retained
    /// gadgets are estimated to exceed this many heap bytes.
    pub max_memory: Option<usize>,
    /// `--compat`: reproduce ROPgadget bug-for-bug where rop-finder
    /// deliberately differs (today: scan a multi-slice fat Mach-O as the
    /// concatenation instead of refusing it).
    pub compat: bool,
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
            align: None,
            call_preceded: false,
            all: false,
            noinstr: false,
            arch: None,
            max_gadgets: None,
            max_memory: None,
            compat: false,
        }
    }
}

/// Everything a scan produces, plus the resolved options (needed for the
/// offset-aware JSON `section` lookup) and the stripped-ELF warning flag.
pub struct ScanOutcome {
    /// The gadgets and their display parameters.
    pub result: ScanResult,
    /// The engine options the request resolved to - carry these into a
    /// cache key or a JSON `section` lookup rather than re-deriving them.
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

/// Cancellation and resource limits layered on top of a [`ScanRequest`].
///
/// A [`ScanRequest`] describes *what to scan*; this describes *how far the
/// caller is willing to let it run*. The CLI never sets one (it has a
/// process to kill); the MCP server always does, because a request that
/// cannot be stopped is a denial of service against the host (MCP-03).
///
/// `max_gadgets`/`max_memory` here OVERRIDE the request's own budgets when
/// they are `Some`, so a server can cap a client that asked for more.
///
/// ```
/// use rf_api::ScanBudget;
/// use rf_scan::CancelToken;
///
/// let cancel = CancelToken::new();
/// let budget = ScanBudget {
///     cancel: cancel.clone(),
///     max_gadgets: Some(10_000),
///     ..ScanBudget::default()
/// };
/// assert_eq!(budget.max_gadgets, Some(10_000));
/// cancel.cancel(); // from another thread, mid-scan
/// ```
#[derive(Debug, Clone, Default)]
pub struct ScanBudget {
    /// Observed by [`rf_scan::scan_bounded`]'s hot loops. Default: a token
    /// that is never set.
    pub cancel: CancelToken,
    /// Hard cap on accepted gadgets; overrides [`ScanRequest::max_gadgets`].
    pub max_gadgets: Option<usize>,
    /// Hard cap on estimated retained bytes; overrides
    /// [`ScanRequest::max_memory`].
    pub max_memory: Option<usize>,
}

/// Turn a [`ScanRequest`] into engine [`ScanOptions`], with no budget and
/// no cancellation.
///
/// This is where every string field of the request is parsed
/// (`--range`, `--badbytes`, `--offset`, the `|`-separated `--only` and
/// `--filter` alternations), so a malformed value is a
/// [`ScanError::Usage`] before any file is read.
///
/// ```
/// use rf_api::{request_options, ScanRequest};
///
/// let req = ScanRequest {
///     depth: 6,
///     badbytes: Some("0a|0d".to_string()),
///     offset: Some("0x1000".to_string()),
///     ..ScanRequest::default()
/// };
/// let opts = request_options(&req, None)?;
/// assert_eq!(opts.depth, 6);
/// assert_eq!(opts.badbytes, vec![0x0a, 0x0d]);
/// assert_eq!(opts.offset, 0x1000);
/// # Ok::<(), rf_api::ScanError>(())
/// ```
pub fn request_options(req: &ScanRequest, raw: Option<RawSpec>) -> Result<ScanOptions, ScanError> {
    request_options_with(req, raw, &ScanBudget::default())
}

/// [`request_options`] with a [`ScanBudget`] wired in.
///
/// The MCP server used to carry its own copy of this mapping because the
/// CLI's was private and hard-coded `CancelToken::never()`; the copy was
/// guarded by a test that scanned four request shapes both ways and
/// compared the gadget lists. The mapping is now written once and that
/// test still runs against it.
pub fn request_options_with(
    req: &ScanRequest,
    raw: Option<RawSpec>,
    budget: &ScanBudget,
) -> Result<ScanOptions, ScanError> {
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
        align: req.align,
        call_preceded: req.call_preceded,
        all: req.all,
        noinstr: req.noinstr,
        parallel: true,
        // The CLI splits --filter on '|' above; rf-scan rejoins the parts
        // and compiles ROPgadget's anchored `({...})$` itself, so there is
        // nothing to pre-compile here.
        filter_re: None,
        cancel: budget.cancel.clone(),
        max_gadgets: budget.max_gadgets.or(req.max_gadgets),
        max_memory: budget.max_memory.or(req.max_memory),
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
    /// The view to scan.
    pub view: RegionView,
    /// The `--section` table, when `--section` was used.
    pub selected_sections: Option<Vec<SectionEntry>>,
    /// True when `--section` matched only synthetic `PT_LOAD#n` names.
    pub fallback_names: bool,
}

/// Build the scan view for `target`, applying `--arch` slice selection,
/// `--base` rebase and `--section` selection.
pub fn prepare_view(
    target: &Target,
    base: Option<u64>,
    sections: &[String],
    arch: Option<&str>,
    compat: bool,
) -> Result<PreparedView, ScanError> {
    let slice = resolve_arch(target, arch, compat)?;
    let mut view = build_view_selected(target, slice);
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
    let prepared = prepare_view(&target, base, &req.section, req.arch.as_deref(), req.compat)?;
    let view = prepared.view;
    let selected_sections = prepared.selected_sections;
    let fallback_names = prepared.fallback_names;
    let universal_arch = view.universal.then_some(view.arch());
    let gadgets = run_scan_engine(&view, &opts).map_err(ScanError::Binary)?;
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

/// Everything a cancellable scan produced.
///
/// The same facts [`ScanOutcome`] carries, minus the resolved
/// [`ScanOptions`] and plus the `--offset` on its own, because a caller
/// that is streaming gadgets back to a client needs the offset (to map an
/// address to its section) and nothing else from the option set.
pub struct ScanProduct {
    /// The gadgets, in the engine's deterministic order.
    pub gadgets: Vec<Gadget>,
    /// 4 or 8 — the width addresses are printed at.
    pub addr_size: usize,
    /// `Some(arch)` when the image was a fat Mach-O.
    pub universal_arch: Option<Arch>,
    /// The `--section` table, when `--section` was used.
    pub selected_sections: Option<Vec<SectionEntry>>,
    /// True when `--section` matched only synthetic `PT_LOAD#n` names.
    pub fallback_names: bool,
    /// The resolved `--offset`; gadget ids are keyed on the UNSLID vaddr.
    pub offset: u64,
}

/// How [`scan_bytes_cancellable`] failed.
///
/// Two halves, because a front end reports them differently: a
/// [`ScanError`] is the caller's fault (a bad `--range`, an unsupported
/// container) and an [`rf_scan::Error`] happened to a scan that had already
/// started — cancelled, or over budget.
#[derive(Debug)]
pub enum ScanFailure {
    /// The request could not be turned into a scan.
    Request(ScanError),
    /// The engine stopped: cancelled, over budget, or a decode failure.
    Engine(rf_scan::Error),
}

impl From<ScanError> for ScanFailure {
    fn from(e: ScanError) -> Self {
        ScanFailure::Request(e)
    }
}

impl fmt::Display for ScanFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanFailure::Request(e) => write!(f, "{e}"),
            ScanFailure::Engine(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ScanFailure {}

/// [`scan_bytes`] with a [`ScanBudget`] threaded into the engine, so the
/// scan can be stopped from another thread and capped in gadgets and
/// memory.
///
/// This routes through [`rf_scan::scan_bounded`], one of the two entry
/// points that observe the cancel token; [`scan_bytes`] uses the unbounded
/// `scan_binary` when no budget is set. The two agree gadget for gadget on
/// the same request — `rf-mcp`'s `scan_matches_the_cli_pipeline` test scans
/// four request shapes both ways and requires identical lists.
///
/// The raw-loader spec is not a parameter: a cancellable scan is what a
/// server runs, and `--rawArch` reinterpretation is a local-shell decision.
///
/// ```
/// use rf_api::{scan_bytes_cancellable, ScanBudget, ScanRequest};
/// use rf_scan::CancelToken;
///
/// let cancel = CancelToken::new();
/// cancel.cancel(); // already cancelled: the scan stops immediately
/// let budget = ScanBudget { cancel, ..ScanBudget::default() };
/// let elf = std::fs::read(concat!(
///     env!("CARGO_MANIFEST_DIR"),
///     "/../../tests/fixtures/elf-Linux-x64"
/// ));
/// if let Ok(bytes) = elf {
///     let err = scan_bytes_cancellable(&bytes, &ScanRequest::default(), &budget)
///         .err()
///         .expect("a cancelled scan cannot succeed");
///     assert!(matches!(err, rf_api::ScanFailure::Engine(rf_scan::Error::Cancelled)));
/// }
/// ```
pub fn scan_bytes_cancellable(
    bytes: &[u8],
    req: &ScanRequest,
    budget: &ScanBudget,
) -> Result<ScanProduct, ScanFailure> {
    let opts = request_options_with(req, None, budget)?;
    let target = load_target(bytes, None)?;
    let base = req
        .base
        .as_deref()
        .map(|b| parse_hex(b, "--base"))
        .transpose()
        .map_err(ScanError::Usage)?;
    let prepared = prepare_view(&target, base, &req.section, req.arch.as_deref(), req.compat)?;
    let view = prepared.view;
    let universal_arch = view.universal.then(|| Image::arch(&view));
    let gadgets = rf_scan::scan_bounded(&view, &opts).map_err(ScanFailure::Engine)?;
    Ok(ScanProduct {
        gadgets,
        addr_size: view.addr_size(),
        universal_arch,
        selected_sections: prepared.selected_sections,
        fallback_names: prepared.fallback_names,
        offset: opts.offset,
    })
}

/// Everything the user has to be told BEFORE reading a gadget listing.
///
/// Each of these existed as a silent behaviour before v0.2.0, and each one
/// makes the listing mean something different from what it looks like:
///
///   * CRIT-01 — `--cfg-aware` on a binary with no `endbr32`/`endbr64`
///     landing pads at all. The flag then constrains nothing, and a user
///     who believes it does will conclude the JOP surface is empty when it
///     is merely unmarked. `rf_scan::ibt_applicable` answers this; it is
///     false for all 24 repository fixtures.
///   * CORE-07 — an ELF whose `e_machine` and `EI_CLASS` disagree about
///     the register width (x32, ELFCLASS64 + EM_386, AArch64 ILP32).
///     rop-finder decodes by `e_machine` and ROPgadget decodes by
///     `EI_CLASS`, so the two tools' output legitimately differs here and
///     the user is told which one they are looking at.
///   * CLI-11/`--compat` — the fat Mach-O concatenation the refusal
///     normally prevents.
pub fn scan_warnings(
    target: &Target,
    view: &RegionView,
    cfg_aware: bool,
    compat: bool,
) -> Vec<String> {
    let mut out = Vec::new();
    if cfg_aware && !rf_scan::ibt_applicable(view) {
        out.push(
            "[Warning] --cfg-aware: this binary contains no endbr32/endbr64 landing pads, \
             so Intel CET/IBT is not enforced on it and the flag constrains nothing. \
             (PE GUARD_CF is a different mitigation and is not what --cfg-aware models.)"
                .to_string(),
        );
    }
    if let Target::Elf(b) = target {
        if let Some(d) = b.mode_divergence() {
            out.push(format!(
                "[Warning] ELF e_machine {:#x} declares {}-bit code but EI_CLASS says \
                 {}-bit. rop-finder decodes it as {}-bit (the width the instruction \
                 encodings actually use); ROPgadget decodes it as {}-bit. Gadget text and \
                 counts will differ from the oracle on this file.",
                d.machine, d.rf_bits, d.oracle_bits, d.rf_bits, d.oracle_bits
            ));
        }
    }
    if compat {
        if let Target::Universal(u) = target {
            if u.needs_arch_selection() {
                out.push(format!(
                    "[Warning] --compat: scanning all {} slices of this fat Mach-O \
                     concatenated and decoding every one of them as {}, exactly as \
                     ROPgadget does. Every slice but the first is decoded with the WRONG \
                     architecture: its listing mixes FABRICATED gadgets — misreadings of \
                     another architecture's instructions, at addresses indistinguishable \
                     from the genuine ones — with real gadgets it silently drops. Use \
                     --arch <slice> for a trustworthy listing.",
                    u.slices().len(),
                    view.arch().slice_name()
                ));
            }
        }
    }
    out
}

/// PERF-05: run the engine, choosing the bounded (streaming-sink) entry
/// point when `--max-gadgets` / `--max-memory` asked for one.
///
/// `scan_binary` collects into an unbounded `Vec`; `scan_bounded` drives a
/// [`rf_scan::BoundedSink`] that aborts the scan the moment either budget is
/// crossed, so the residual cost after the limit is one atomic load per
/// remaining work item rather than the gadgets it would have produced.
/// The two agree gadget-for-gadget while no budget is set, so the default
/// path is left exactly as it was.
pub fn run_scan_engine(view: &RegionView, opts: &ScanOptions) -> Result<Vec<Gadget>, String> {
    if opts.max_gadgets.is_none() && opts.max_memory.is_none() {
        return rf_scan::scan_binary(view, opts).map_err(|e| e.to_string());
    }
    rf_scan::scan_bounded(view, opts).map_err(scan_error_message)
}

/// The user-facing wording for a scan-time failure.
///
/// Shared by the buffered and the streaming (`--format jsonl`) paths so that
/// the same `--max-gadgets` produces the same sentence whichever format it
/// was asked for; the raw `Error::Budget` Display says what happened but not
/// what to do about it.
pub fn scan_error_message(e: rf_scan::Error) -> String {
    match e {
        rf_scan::Error::Budget { produced, limit } => format!(
            "scan budget exhausted after {produced} gadgets (limit {limit}); raise \
             --max-gadgets/--max-memory, lower --depth, or narrow the scan with --section"
        ),
        other => other.to_string(),
    }
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
/// `--api-name`, `--shellcode-addr`, `--shellcode-size`, `--chain-base`,
/// `--prot`; MCP passes the same).
#[derive(Debug, Clone, Default)]
pub struct ChainSpec {
    /// "linux-execve" (default) or "windows-virtualprotect".
    pub target: String,
    /// `--api-addr` (hex): the runtime address of the API to call. A
    /// comma-separated list supplies one address per `--api-name`.
    pub api_addr: Option<String>,
    /// CHWIN-06: which API to resolve and whose argument recipe to use.
    /// `None` = the builder's default, VirtualProtect.
    pub api_name: Option<String>,
    /// `--shellcode-addr` (hex): where the shellcode will live.
    pub shellcode_addr: Option<String>,
    /// `--shellcode-size` (hex): the `dwSize` / length argument.
    pub shellcode_size: Option<String>,
    /// CHWIN-04: "aligned" or "return-address"/"return_address".
    /// `None` = the builder's default, return_address.
    pub chain_base: Option<String>,
    /// flNewProtect / flProtect (hex). `None` = 0x40 on Windows, 7
    /// (PROT_READ|WRITE|EXEC) for `linux-mprotect`.
    pub prot: Option<String>,
    /// `--syscall <n>`: decimal, or hex with an explicit `0x`.
    pub syscall: Option<String>,
    /// `--syscall-args rdi=..,rsi=..`.
    pub syscall_args: Option<String>,
    /// `--chain-pivot <addr>` (CHWIN-08).
    pub pivot: Option<String>,
    /// `--stage <hex>` (CHWIN-08).
    pub stage: Option<String>,
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
    /// The chain itself, as the Chain IR.
    pub chain: rf_chain::RopChain,
    /// The scan the chain was built from.
    pub outcome: ScanOutcome,
    /// CHWIN-04: what the Windows builder assumed about the world the
    /// chain will run in — the chain-base parity, the API recipe, and the
    /// two addresses CHWIN-02 keeps apart. `None` for a Linux chain, which
    /// makes none of these assumptions.
    pub assumptions: Option<rf_chain::windows::WinAssumptions>,
}

/// The Chain IR as JSON, plus the `assumptions` object a Windows chain
/// carries (CHWIN-04). The IR itself is `rf_chain`'s serialisation,
/// untouched; the assumptions sit beside it as their own key so a reader
/// gets the layout AND what the layout took for granted from one document.
/// ECO-04: parse `--syscall-args rdi=0x1000,rsi=8` into `(reg, value)`
/// pairs. Register names are validated by the builder against the ABI, so
/// the error here is only about the SHAPE.
pub fn parse_syscall_args(spec: &str) -> Result<Vec<(String, u64)>, String> {
    let mut out = Vec::new();
    for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (reg, value) = item.split_once('=').ok_or_else(|| {
            format!("invalid --syscall-args item {item:?}: expected <reg>=<value>")
        })?;
        let reg = reg.trim().to_ascii_lowercase();
        if reg.is_empty() {
            return Err(format!(
                "invalid --syscall-args item {item:?}: empty register name"
            ));
        }
        let value = parse_hex(value.trim(), "--syscall-args")?;
        out.push((reg, value));
    }
    Ok(out)
}

/// `--syscall <n>`: DECIMAL by default (a syscall number is written in
/// decimal everywhere from the kernel table to strace), hexadecimal only
/// with an explicit `0x` — the same rule `parse_align` applies for the same
/// reason (ANCH-02).
pub fn parse_syscall_nr(v: &str) -> Result<u64, String> {
    let t = v.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).map_err(|e| format!("invalid --syscall {v:?}: {e}"));
    }
    t.parse::<u64>()
        .map_err(|e| format!("invalid --syscall {v:?}: {e}"))
}

/// `--stage 9090cc` -> the bytes to write.
pub fn parse_hex_bytes(v: &str, flag: &str) -> Result<Vec<u8>, String> {
    let t: String = v
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if t.is_empty() {
        return Err(format!("{flag}: no bytes given"));
    }
    if t.len() % 2 != 0 {
        return Err(format!(
            "{flag} {v:?}: hex byte string has an odd number of digits"
        ));
    }
    (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).map_err(|e| format!("{flag} {v:?}: {e}")))
        .collect()
}

/// Parse the Linux chain parameters (`ECO-04` / `CHLX-07`).
pub fn linux_opts(spec: &ChainSpec) -> Result<rf_chain::LinuxChainOpts, ScanError> {
    use rf_chain::LinuxTarget;
    let usage = ScanError::Usage;
    let target = LinuxTarget::parse(&spec.target).ok_or_else(|| {
        ScanError::Usage(format!(
            "unknown Linux chain target {:?}; supported: {}",
            spec.target,
            LinuxTarget::NAMES.join(", ")
        ))
    })?;
    Ok(rf_chain::LinuxChainOpts {
        target,
        syscall_nr: spec
            .syscall
            .as_deref()
            .map(parse_syscall_nr)
            .transpose()
            .map_err(usage)?,
        syscall_args: spec
            .syscall_args
            .as_deref()
            .map(parse_syscall_args)
            .transpose()
            .map_err(usage)?
            .unwrap_or_default(),
        func_addr: spec
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
            None => rf_chain::linux::DEFAULT_LINUX_LEN,
        },
        prot: match &spec.prot {
            Some(s) => parse_hex(s, "--prot").map_err(usage)?,
            None => rf_chain::linux::DEFAULT_LINUX_PROT,
        },
    })
}

/// The Chain IR as pretty JSON, with the Windows `assumptions` object
/// beside it (`null` for a target that makes none).
pub fn chain_json(outcome: &ChainOutcome) -> String {
    let mut value = outcome.chain.to_json();
    if let Some(obj) = value.as_object_mut() {
        // Always present, `null` when the target makes no such assumptions
        // — the same rule rf-mcp's schema.rs states, so a parser written
        // against one surface does not break on the other.
        obj.insert(
            "assumptions".to_string(),
            match outcome.assumptions.as_ref() {
                Some(a) => serde_json::to_value(a).unwrap_or(serde_json::Value::Null),
                None => serde_json::Value::Null,
            },
        );
    }
    serde_json::to_string_pretty(&value).unwrap()
}

fn chain_err(e: rf_chain::ChainError) -> ScanError {
    match e {
        rf_chain::ChainError::Unsupported { .. } => ScanError::Usage(e.to_string()),
        other => ScanError::Chain(other.to_string()),
    }
}

/// Parse the Windows chain parameters (hex strings → WinChainOpts).
///
/// `--api-name` and `--chain-base` are validated HERE rather than deep in
/// the builder so a typo is a usage error naming the accepted values, and
/// so the MCP (which calls the same function through `chain_bytes`) rejects
/// the same set the CLI does — the ECO-02 property `capability_matrix.py`
/// gates.
pub fn win_opts(spec: &ChainSpec) -> Result<rf_chain::WinChainOpts, ScanError> {
    use rf_chain::windows::{ApiRecipe, ChainBaseParity};
    let usage = ScanError::Usage;
    // CHWIN-08 #2: `--api-name A,B` composes two calls into one chain, and
    // `--api-addr` then takes one address per name. One name and one
    // address is the ordinary single-call case, unchanged.
    let raw_names: Vec<&str> = match spec.api_name.as_deref().map(str::trim) {
        None | Some("") => vec![],
        Some(v) => v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect(),
    };
    let canonical = |name: &str| -> Result<String, ScanError> {
        ApiRecipe::NAMES
            .iter()
            .find(|n| n.eq_ignore_ascii_case(name))
            .map(|n| (*n).to_string())
            .ok_or_else(|| {
                ScanError::Usage(format!(
                    "--api-name {name:?}: supported values are {} (their argument recipes                      differ, so an unmodelled API cannot be called correctly)",
                    ApiRecipe::NAMES.join(", ")
                ))
            })
    };
    let names: Vec<String> = if raw_names.is_empty() {
        vec![rf_chain::WinChainOpts::default().api_name]
    } else {
        raw_names
            .iter()
            .map(|n| canonical(n))
            .collect::<Result<Vec<_>, _>>()?
    };

    let addrs: Vec<u64> = match spec.api_addr.as_deref().map(str::trim) {
        None | Some("") => Vec::new(),
        Some(v) => v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|a| parse_hex(a, "--api-addr"))
            .collect::<Result<Vec<_>, _>>()
            .map_err(usage)?,
    };
    if !addrs.is_empty() && addrs.len() != names.len() {
        return Err(ScanError::Usage(format!(
            "--api-addr has {} address(es) but --api-name names {} API(s): a composed chain              needs one runtime address per call, or none at all (IAT resolution)",
            addrs.len(),
            names.len()
        )));
    }
    let addr_of = |i: usize| addrs.get(i).copied();

    let chain_base = match spec.chain_base.as_deref().map(str::trim) {
        None | Some("") => ChainBaseParity::default(),
        Some(v) => ChainBaseParity::parse(v).ok_or_else(|| {
            ScanError::Usage(format!(
                "--chain-base {v:?}: supported values are {}",
                ChainBaseParity::VALUES.join(", ")
            ))
        })?,
    };
    Ok(rf_chain::WinChainOpts {
        api_name: names[0].clone(),
        api_addr: addr_of(0),
        extra_calls: names
            .iter()
            .enumerate()
            .skip(1)
            .map(|(i, n)| (n.clone(), addr_of(i)))
            .collect(),
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
        new_protect: match &spec.prot {
            Some(s) => parse_hex(s, "--prot").map_err(usage)?,
            None => rf_chain::windows::DEFAULT_PROTECT,
        },
        chain_base,
        pivot: spec
            .pivot
            .as_deref()
            .map(|a| parse_hex(a, "--chain-pivot"))
            .transpose()
            .map_err(usage)?,
        stage: spec
            .stage
            .as_deref()
            .map(|h| parse_hex_bytes(h, "--stage"))
            .transpose()
            .map_err(usage)?
            .unwrap_or_default(),
        // Image data, not a flag: `chain_bytes` / `plan_once` fill it in
        // from the file they already hold (CHWIN-08 #3).
        exports: Vec::new(),
    })
}

/// Every `--chain` value, in help order. `linux-*` need an ELF x86/x64,
/// `windows-virtualprotect` a PE x86/x64.
pub fn chain_targets() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = rf_chain::LinuxTarget::NAMES.to_vec();
    v.push("windows-virtualprotect");
    v
}

/// Format/arch gate for a chain target. Shared by `chain_bytes` and
/// `plan_chain_bytes` so the two cannot disagree about what is dispatchable.
fn check_chain_target(
    name: &str,
    target: &Target,
    arch: Arch,
    format: &str,
) -> Result<(), ScanError> {
    let unsupported = || {
        Err(chain_err(rf_chain::ChainError::Unsupported {
            arch: rf_chain::arch_name(arch),
            format: format.to_string(),
        }))
    };
    match name {
        t if rf_chain::LinuxTarget::parse(t).is_some() => {
            if !matches!(target, Target::Elf(_)) || !matches!(arch, Arch::X86 | Arch::X64) {
                return unsupported();
            }
        }
        "windows-virtualprotect" => {
            if !matches!(target, Target::Pe(_)) || !matches!(arch, Arch::X86 | Arch::X64) {
                return unsupported();
            }
        }
        other => {
            return Err(ScanError::Usage(format!(
                "unknown chain target {other:?}; supported: {}",
                chain_targets().join(", ")
            )));
        }
    }
    Ok(())
}

/// `ECO-04`: one probe run — load, scan, and ask the target's planner.
///
/// Separate from [`plan_chain_bytes`] because the relaxation search runs it
/// several times with different scan parameters and compares the answers.
fn plan_once(
    bytes: &[u8],
    raw: Option<RawSpec>,
    req: &ScanRequest,
    spec: &ChainSpec,
) -> Result<(rf_chain::ChainPlan, Vec<rf_scan::Gadget>, u64), ScanError> {
    let opts = request_options(req, raw)?;
    let mut target = load_target(bytes, raw)?;
    let format = target_format(&target);
    let arch = match &target {
        Target::Elf(b) => Image::arch(b),
        Target::Pe(b) => Image::arch(b),
        t => Image::arch(&build_view(t)),
    };
    // ECO-04: `plan_chain` ALWAYS succeeds, so the format/arch gate that
    // `chain_bytes` applies is NOT applied here — "this builder does not
    // cover PE x64 / linux-execve" is a REQUIREMENT the probe reports
    // (`target_supported`), not an error the caller has to parse. Only an
    // unknown target NAME is a usage error, because there is then nothing
    // to plan for.
    if !chain_targets().contains(&spec.target.as_str()) {
        return Err(ScanError::Usage(format!(
            "unknown chain target {:?}; supported: {}",
            spec.target,
            chain_targets().join(", ")
        )));
    }

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
    let prepared = prepare_view(&target, None, &req.section, req.arch.as_deref(), req.compat)?;
    let gadgets = rf_scan::scan_binary(&prepared.view, &opts)
        .map_err(|e| ScanError::Binary(e.to_string()))?;
    let sections: &[rf_core::Section] = match &target {
        Target::Elf(b) => b.sections(),
        Target::Pe(b) => b.sections(),
        // A Mach-O or raw target hosts neither chain family; the probe
        // says so through `target_supported` and needs no sections.
        _ => &[],
    };
    let data_sections: Vec<rf_chain::DataSection> = sections
        .iter()
        .filter(|s| !s.executable)
        .map(|s| rf_chain::DataSection {
            name: s.name.clone(),
            vaddr: s.vaddr.wrapping_add(opts.offset),
            writable: s.writable,
        })
        .collect();

    let plan = match (&target, spec.target.as_str()) {
        (_, "windows-virtualprotect") => {
            let mut wopts = win_opts(spec)?;
            if let Target::Pe(pe) = &target {
                wopts.exports = pe_exports::parse_pe_exports(bytes, pe.image_base());
            }
            rf_chain::plan_windows(
                &gadgets,
                &data_sections,
                match &target {
                    Target::Pe(pe) => pe.imports(),
                    _ => &[],
                },
                arch,
                format,
                &wopts,
                &opts.badbytes,
            )
        }
        _ => {
            let lopts = linux_opts(spec)?;
            rf_chain::plan_linux(
                &gadgets,
                &data_sections,
                arch,
                format,
                &opts.badbytes,
                &lopts,
            )
        }
    };
    Ok((plan, gadgets, opts.offset))
}

/// `ECO-04`: the feasibility report, with COMPUTED relaxations.
///
/// The relaxation loop is the point. For every requirement the base scan
/// could not satisfy, the same probe is re-run against a scan taken with one
/// parameter changed — `depth` doubled, then `--multibr` on — and
/// `would_help` records what that re-run actually measured. Nothing here
/// predicts; a `would_help: true` means a scan was taken and the gadget was
/// there.
///
/// The re-scans are skipped entirely when the base plan is already feasible,
/// which is the common case and the one where they would cost the most.
pub fn plan_chain_bytes(
    bytes: &[u8],
    raw: Option<RawSpec>,
    req: &ScanRequest,
    spec: &ChainSpec,
) -> Result<ChainPlanOutcome, ScanError> {
    let (mut plan, gadgets, offset) = plan_once(bytes, raw, req, spec)?;
    if plan.requirements.iter().any(|r| !r.satisfied) {
        let deeper = ScanRequest {
            depth: req.depth.saturating_mul(2),
            ..req.clone()
        };
        if let Ok((v, _, _)) = plan_once(bytes, raw, &deeper, spec) {
            plan.merge_relaxation(
                &v,
                "depth",
                &req.depth.to_string(),
                &deeper.depth.to_string(),
            );
        }
        let multibr = ScanRequest {
            multibr: true,
            ..req.clone()
        };
        if !req.multibr {
            if let Ok((v, _, _)) = plan_once(bytes, raw, &multibr, spec) {
                plan.merge_relaxation(&v, "multibr", "false", "true");
            }
        }
    }
    Ok(ChainPlanOutcome {
        plan,
        gadgets,
        offset,
    })
}

/// `--plan-chain`'s document.
///
/// `gadget_id` stays `null` on the CLI: the stable id is the MCP's handle
/// for referring to a gadget across tool calls, and a shell's handle is the
/// address (the same asymmetry `tests/capability_matrix.py` records for the
/// `ids` parameter). `vaddr` and `text` are here, which is what a shell
/// pipeline needs.
pub fn plan_json(outcome: &ChainPlanOutcome) -> String {
    serde_json::to_string_pretty(&outcome.plan.to_json()).unwrap()
}

/// A plan plus the scan it was measured on, so a front end can turn the
/// satisfying gadgets into the stable ids `get_gadgets` resolves.
pub struct ChainPlanOutcome {
    /// The feasibility report.
    pub plan: rf_chain::ChainPlan,
    /// The scan the plan was measured on.
    pub gadgets: Vec<rf_scan::Gadget>,
    /// `--offset` applied to the scan; ids are keyed on the UNSLID vaddr.
    pub offset: u64,
}

impl ChainPlanOutcome {
    /// The bytes of the gadget at `vaddr`, for a caller computing ids.
    pub fn gadget_bytes(&self, vaddr: u64) -> Option<&[u8]> {
        self.gadgets
            .iter()
            .find(|g| g.vaddr == vaddr)
            .map(|g| g.bytes.as_slice())
    }
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
    check_chain_target(&spec.target, &target, arch, format)?;

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

    let prepared = prepare_view(&target, None, &req.section, req.arch.as_deref(), req.compat)?;
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

    // CHLX-08: the symmetric warning to the PE GUARD_CF one. Every address
    // in a chain built against an ET_DYN image is a LINK-TIME offset, and
    // the tool already knows both facts it needs to say so.
    if let Target::Elf(b) = &target {
        // ET_DYN is exactly what rf-core's `pie` mitigation decides, and it
        // decides it from `e_type` — so the warning and `--info` /
        // get_mitigations cannot disagree about whether a target is PIE.
        let is_dyn = b.mitigations().enabled(rf_core::mitigations::PIE)
            == rf_core::mitigations::Enabled::Yes;
        if let Some(w) = rf_chain::linux::pie_chain_warning(is_dyn, b.image_base(), opts.offset) {
            eprintln!("[Warning] {w}");
        }
    }

    let mut assumptions = None;
    let chain = match spec.target.as_str() {
        t if rf_chain::LinuxTarget::parse(t).is_some() => {
            let lopts = linux_opts(spec)?;
            rf_chain::build_linux(
                &gadgets,
                &data_sections,
                arch,
                format,
                &opts.badbytes,
                &lopts,
            )
            .map_err(chain_err)?
        }
        "windows-virtualprotect" => {
            let Target::Pe(pe) = &target else {
                unreachable!("dispatched above")
            };
            let mut wopts = win_opts(spec)?;
            // CHWIN-08 #3: strategy (c). Parsed from the bytes we already
            // hold, and rebased with the image, so an export resolves to
            // the same address the rest of the chain uses.
            wopts.exports = pe_exports::parse_pe_exports(bytes, pe.image_base());
            let chain = rf_chain::build_windows_virtualprotect(
                &gadgets,
                &data_sections,
                pe.imports(),
                arch,
                format,
                &wopts,
                &opts.badbytes,
            )
            .map_err(chain_err)?;
            // CHWIN-04: the same computation the builder ran, reported back
            // so the assumption is in the artefact rather than only in the
            // source. Never a second, drifting derivation.
            assumptions = Some(
                rf_chain::windows::windows_assumptions(&data_sections, arch, &wopts)
                    .map_err(chain_err)?,
            );
            chain
        }
        _ => unreachable!("validated above"),
    };

    Ok(ChainOutcome {
        chain,
        assumptions,
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

/// Image base of a target (first slice for Universal) — the pre-rebase
/// view base, used to compute the `--base` slide for the search sections.
///
/// ```
/// use rf_api::{load_target, target_base};
/// use rf_core::{Arch, Endianness};
///
/// // A raw blob is based at 0 until it is rebased.
/// let t = load_target(&[0x5f, 0xc3], Some((Arch::X64, Endianness::Little, false)))?;
/// assert_eq!(target_base(&t), 0);
/// # Ok::<(), rf_api::ScanError>(())
/// ```
pub fn target_base(target: &Target) -> u64 {
    match target {
        Target::Elf(b) => b.image_base(),
        Target::Pe(b) => b.image_base(),
        Target::MachO(b) => b.image_base(),
        Target::Raw(b) => b.image_base(),
        Target::Universal(u) => u.slices()[0].image_base(),
    }
}

/// A gadget address, zero-padded to the image's address width.
///
/// ```
/// assert_eq!(rf_api::fmt_addr(0x401000, 8), "0x0000000000401000");
/// assert_eq!(rf_api::fmt_addr(0x8048000, 4), "0x08048000");
/// ```
pub fn fmt_addr(vaddr: u64, addr_size: usize) -> String {
    match addr_size {
        4 => format!("0x{vaddr:08x}"),
        _ => format!("0x{vaddr:016x}"),
    }
}

/// Name of the selected section containing `vaddr` (a scan-view address,
/// i.e. after --base but before --offset), if any.
pub fn section_of(selected: &[(String, u64, u64)], vaddr: u64) -> Option<String> {
    selected
        .iter()
        .find(|(_, s_vaddr, s_size)| vaddr >= *s_vaddr && vaddr < s_vaddr.wrapping_add(*s_size))
        .map(|(name, _, _)| name.clone())
}
