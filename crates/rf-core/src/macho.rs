//! Mach-O loading via goblin.
//!
//! Semantics ported from ROPgadget's `loaders/macho.py`:
//! - Arch from `cputype` (macho.py:306-318).
//! - Executable sections carry `S_ATTR_SOME_INSTRUCTIONS` or
//!   `S_ATTR_PURE_INSTRUCTIONS` (macho.py:283).
//! - Entry = address of the first section whose name starts with `__text`
//!   (macho.py:275-278).
//! - Section file offset recomputed as `segment.fileoff + addr - vmaddr`
//!   (macho.py:263, 271) rather than trusting the stored `offset` field —
//!   this is what the parity oracle reads.
//! - Endianness from the magic (macho.py:209-217): `feedface`/`feedfacf`
//!   stored MSB-first means big-endian.
//!
//! Conscious deviations:
//! - `image_base` = the load address of the first real mapping (see
//!   [`text_image_base`]). ROPgadget's Mach-O loader has no image-base
//!   concept at all; min *section* vaddr was considered and rejected because
//!   sections can sit below their segment's vmaddr.
//! - `writable` is always false: Mach-O sections have no writable flag and
//!   ROPgadget infers "data" sections only as the complement of the
//!   instruction-attribute test (macho.py:293-304).

use goblin::mach::constants::cputype;
use goblin::mach::constants::{S_ATTR_PURE_INSTRUCTIONS, S_ATTR_SOME_INSTRUCTIONS};

use crate::util::{cstr_lossy, ByteBudget};
use crate::{Arch, Endianness, Error, Section};

/// A parsed Mach-O binary (single architecture slice).
#[derive(Debug)]
pub struct MachOBinary {
    /// Mach-O `cputype` (e.g. `CPU_TYPE_X86_64`).
    cpu_type: u32,
    arch: Arch,
    is_64: bool,
    little_endian: bool,
    entry: u64,
    /// Load address of the first real mapping — see [`text_image_base`].
    image_base: u64,
    sections: Vec<Section>,
    /// ROPgadget-compatible scan regions: sections with instruction attrs.
    exec_regions: Vec<Section>,
    /// ECO-06 — MH_PIE, stack/heap execute flags, code signature and
    /// hardened runtime (see `macho_info.rs`).
    mitigations: crate::mitigations::Mitigations,
}

impl MachOBinary {
    /// Parse a Mach-O binary, returning a structured error on malformed input.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let macho = goblin::mach::MachO::parse(bytes, 0)?;
        Self::from_goblin(&macho, bytes)
    }

    /// Build from an already-parsed goblin Mach-O and the byte buffer it was
    /// parsed from (slice-local: `bytes[0]` is the Mach-O header). Used by
    /// the Universal loader for each fat slice.
    pub(crate) fn from_goblin(macho: &goblin::mach::MachO, bytes: &[u8]) -> Result<Self, Error> {
        let cpu_type = macho.header.cputype();
        let is_64 = macho.is_64;
        let arch = match cpu_type {
            cputype::CPU_TYPE_X86 => Arch::X86,
            cputype::CPU_TYPE_X86_64 => Arch::X64,
            cputype::CPU_TYPE_ARM => Arch::Arm,
            cputype::CPU_TYPE_ARM64 => Arch::Arm64,
            cputype::CPU_TYPE_MIPS => {
                if is_64 {
                    Arch::Mips64
                } else {
                    Arch::Mips32
                }
            }
            cputype::CPU_TYPE_POWERPC => Arch::Ppc32,
            cputype::CPU_TYPE_POWERPC64 => Arch::Ppc64,
            other => return Err(Error::Unsupported(format!("Mach-O cputype {other:#x}"))),
        };

        let mut sections = Vec::new();
        let mut exec_regions = Vec::new();
        let mut entry = 0u64;
        let mut budget = ByteBudget::for_file(bytes.len());
        // Section header sizes: segment_command is 56/72 bytes, each
        // section header is 68/80 bytes (32/64-bit Mach-O).
        let seg_hdr: u64 = if is_64 { 72 } else { 56 };
        let sect_hdr: u64 = if is_64 { 80 } else { 68 };
        for segment in macho.segments.iter() {
            // Defensive bound, checked BEFORE iterating: goblin's
            // SectionIterator runs `nsects` times even when every section
            // read fails out of bounds, so a mutated `nsects` (a u32, up to
            // ~4 billion) turns the loop below into a multi-minute hang.
            // In a valid Mach-O the section headers live inside the segment
            // load command inside the file, so `nsects` is bounded by both
            // the command size and the file length. Anything else is
            // malformed: quick structured Err, never a hang.
            let cmdsize = u64::from(segment.cmdsize);
            let nsects = u64::from(segment.nsects);
            let fits_cmd = cmdsize >= seg_hdr && nsects <= (cmdsize - seg_hdr) / sect_hdr;
            let fits_file = nsects.saturating_mul(sect_hdr) <= bytes.len() as u64;
            if !(fits_cmd && fits_file) {
                return Err(Error::Malformed(format!(
                    "Mach-O segment declares {nsects} section headers with \
                     cmdsize {cmdsize:#x} in a {}-byte file",
                    bytes.len()
                )));
            }
            for item in segment {
                // Best-effort: skip sections that fail to parse.
                let Ok((sec, _data)) = item else { continue };
                // macho.py:263,271 — recompute the file offset from the
                // segment mapping. ROPgadget stores this in a c_uint, so
                // truncate to 32 bits to mirror the oracle exactly.
                let offset = segment
                    .fileoff
                    .wrapping_add(sec.addr)
                    .wrapping_sub(segment.vmaddr)
                    & 0xffff_ffff;
                let content = budget.take(bytes, offset, sec.size, "Mach-O section headers")?;
                // CORE-04 — the declared size, as the oracle reports it
                // (macho.py:263-272 stores `section.size`); `content` stays
                // clamped to what the file holds.
                let size = sec.size;
                // 16-byte sectname, not guaranteed NUL-terminated.
                let name = cstr_lossy(&sec.sectname);
                // macho.py:275-278 — entry is the first __text* section addr.
                if entry == 0 && name.starts_with("__text") {
                    entry = sec.addr;
                }
                // macho.py:283.
                let executable =
                    sec.flags & (S_ATTR_SOME_INSTRUCTIONS | S_ATTR_PURE_INSTRUCTIONS) != 0;
                let section = Section {
                    name,
                    vaddr: sec.addr,
                    offset,
                    size,
                    bytes: content,
                    executable,
                    writable: false,
                    allocated: true,
                };
                if executable {
                    exec_regions.push(section.clone());
                }
                sections.push(section);
            }
        }

        let image_base = text_image_base(macho);

        Ok(MachOBinary {
            cpu_type,
            arch,
            is_64,
            little_endian: macho.little_endian,
            entry,
            image_base,
            sections,
            exec_regions,
            mitigations: crate::macho_info::report(&crate::macho_info::facts(macho, bytes)),
        })
    }

    /// ECO-06 — the mitigation report for this slice.
    ///
    /// Keys, in report order: `pie`, `nx_stack`, `nx_heap`,
    /// `code_signature`, `hardened_runtime`. A fat binary reports per slice
    /// — the flags genuinely differ between them.
    pub fn mitigations(&self) -> &crate::mitigations::Mitigations {
        &self.mitigations
    }

    /// Mach-O `cputype`.
    pub fn cpu_type(&self) -> u32 {
        self.cpu_type
    }

    /// Architecture from `cputype` (macho.py:306-318).
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Endianness from the Mach-O magic (macho.py:209-217).
    pub fn endianness(&self) -> Endianness {
        if self.little_endian {
            Endianness::Little
        } else {
            Endianness::Big
        }
    }

    /// 64-bit slice (`LC_SEGMENT_64`)?
    pub fn is_64(&self) -> bool {
        self.is_64
    }

    /// Entry point: address of the first `__text*` section (macho.py:275-278).
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// All sections, in load-command order.
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Executable sections (instruction-attribute flags).
    pub fn exec_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.executable).collect()
    }

    /// ROPgadget-compatible scan regions (macho.py:280-291).
    pub fn exec_scan_regions(&self) -> &[Section] {
        &self.exec_regions
    }

    /// Load address of the image — see [`text_image_base`]. Captured at
    /// parse time.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Rebase the binary to `new_base`: shifts every section vaddr and the
    /// entry point by `new_base - image_base()`.
    pub fn rebase(&mut self, new_base: u64) {
        let delta = new_base.wrapping_sub(self.image_base);
        for s in &mut self.sections {
            s.vaddr = s.vaddr.wrapping_add(delta);
        }
        for s in &mut self.exec_regions {
            s.vaddr = s.vaddr.wrapping_add(delta);
        }
        self.entry = self.entry.wrapping_add(delta);
        self.image_base = new_base;
    }
}

/// CORE-02 — the Mach-O load address, which is NOT the minimum segment
/// `vmaddr`.
///
/// Every Mach-O *executable* carries a `__PAGEZERO` segment mapped at
/// vmaddr 0 (its whole job is to make the first pages unmapped), so taking
/// the minimum `vmaddr` over LC_SEGMENT/LC_SEGMENT_64 commands returned 0
/// for every executable ever loaded. `--info` then reported
/// `"image_base": "0x0"` where the real `__TEXT` base is 0x100000000, and
/// `rebase(new)` computed `delta = new - 0`, so the documented `--base 0`
/// ASLR workflow was a no-op and `--base <leaked base>` doubled the address.
///
/// The rule here, in order:
///
/// 1. The `__TEXT` segment's `vmaddr`, if there is one. This is the segment
///    the loader maps the image at, and it is what `otool -l` readers,
///    `lldb` and `lipo` all call the load address.
/// 2. Otherwise the first segment in load-command order that is not
///    `__PAGEZERO`.
/// 3. Otherwise the minimum `vmaddr`, or 0 for a file with no segments.
///
/// Step 1 exists because "first non-`__PAGEZERO` segment with a NONZERO
/// vmaddr" — the obvious phrasing — is wrong for dylibs: in
/// `UNIVERSAL-x86-x64-libSystem.B.dylib` both slices map `__TEXT` at vmaddr
/// 0x0 and `__DATA` at 0x2000, so a nonzero test picks `__DATA` and reports
/// a load address 0x2000 above the truth. A dylib's `__TEXT` at 0 is the
/// correct answer, and step 1 gives it.
fn text_image_base(macho: &goblin::mach::MachO) -> u64 {
    let mut first_mapped: Option<u64> = None;
    for seg in macho.segments.iter() {
        let name = cstr_lossy(&seg.segname);
        if name == "__TEXT" {
            return seg.vmaddr;
        }
        if name != "__PAGEZERO" && first_mapped.is_none() {
            first_mapped = Some(seg.vmaddr);
        }
    }
    first_mapped
        .or_else(|| macho.segments.iter().map(|s| s.vmaddr).min())
        .unwrap_or(0)
}

impl crate::Image for MachOBinary {
    fn arch(&self) -> Arch {
        self.arch()
    }

    fn endianness(&self) -> Endianness {
        self.endianness()
    }

    fn image_base(&self) -> u64 {
        self.image_base()
    }

    fn entry(&self) -> u64 {
        self.entry()
    }

    fn exec_sections(&self) -> Vec<&Section> {
        self.exec_sections()
    }

    fn exec_scan_regions(&self) -> &[Section] {
        self.exec_scan_regions()
    }

    fn rebase(&mut self, new_base: u64) {
        self.rebase(new_base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixture_path(name)).expect("fixture should exist")
    }

    #[test]
    fn parses_real_macho_x86() {
        let bytes = load_fixture("macho-x86-ls");
        let bin = MachOBinary::parse(&bytes).expect("should parse");
        assert_eq!(bin.arch(), Arch::X86);
        assert!(!bin.is_64());
        assert_eq!(bin.cpu_type(), cputype::CPU_TYPE_X86);
        assert_eq!(bin.endianness(), Endianness::Little);
        let exec = bin.exec_scan_regions();
        assert!(!exec.is_empty());
        assert!(exec.iter().any(|s| s.name == "__text"));
        for s in exec {
            assert!(s.executable);
            assert!(!s.bytes.is_empty());
            // CORE-04: declared size, never below the materialised bytes.
            assert!(s.size >= s.bytes.len() as u64);
        }
        // entry = __text section address (macho.py:275-278)
        assert_eq!(bin.entry(), bin.exec_scan_regions()[0].vaddr);
    }

    #[test]
    fn parses_real_macho_x64() {
        let bytes = load_fixture("macho-x64-ls");
        let bin = MachOBinary::parse(&bytes).expect("should parse");
        assert_eq!(bin.arch(), Arch::X64);
        assert!(bin.is_64());
        assert_eq!(bin.cpu_type(), cputype::CPU_TYPE_X86_64);
        assert!(!bin.exec_scan_regions().is_empty());
    }

    #[test]
    fn parses_real_macho_ppc_big_endian() {
        let bytes = load_fixture("macho-ppc-openssl");
        let bin = MachOBinary::parse(&bytes).expect("should parse");
        assert_eq!(bin.arch(), Arch::Ppc32);
        assert_eq!(bin.cpu_type(), cputype::CPU_TYPE_POWERPC);
        assert_eq!(bin.endianness(), Endianness::Big);
        assert!(!bin.exec_scan_regions().is_empty());
        assert!(bin.entry() != 0);
    }

    /// CORE-02. The old rule (min vmaddr over all LC_SEGMENT commands)
    /// returned 0 on every one of these, because each carries __PAGEZERO at
    /// vmaddr 0. The expected values below were read out of the fixtures by
    /// hand with a struct-by-struct parse of the load commands.
    #[test]
    fn image_base_is_the_text_segment_not_pagezero() {
        for (name, want) in [
            ("macho-x64-ls", 0x1_0000_0000u64),
            ("macho-x86-ls", 0x1000),
            ("macho-ppc-openssl", 0x1000),
        ] {
            let bytes = load_fixture(name);
            let bin = MachOBinary::parse(&bytes).unwrap();
            assert_eq!(
                bin.image_base(),
                want,
                "{name}: image_base {:#x}, want {want:#x}",
                bin.image_base()
            );
            assert!(bin.exec_scan_regions()[0].vaddr >= bin.image_base());
            // __PAGEZERO really is present and really is at vmaddr 0, so
            // the old min-vmaddr rule would have returned 0 here.
            let macho = goblin::mach::MachO::parse(&bytes, 0).unwrap();
            let min = macho.segments.iter().map(|s| s.vmaddr).min().unwrap();
            assert_eq!(min, 0, "{name} must carry a __PAGEZERO at vmaddr 0");
        }
    }

    /// CORE-02, the case that rules out "first segment with a NONZERO
    /// vmaddr": a dylib maps __TEXT at 0 and __DATA at 0x2000, and 0 is the
    /// right answer.
    #[test]
    fn dylib_image_base_is_text_at_zero_not_the_first_nonzero_segment() {
        let bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let uni = crate::UniversalBinary::parse(&bytes).unwrap();
        for slice in uni.slices() {
            assert_eq!(slice.image_base(), 0, "dylib __TEXT is mapped at 0");
        }
    }

    /// `--base 0` must be a real shift on a Mach-O executable, which it was
    /// not while image_base was 0.
    #[test]
    fn rebase_zero_yields_text_relative_addresses() {
        let bytes = load_fixture("macho-x64-ls");
        let mut bin = MachOBinary::parse(&bytes).unwrap();
        let base = bin.image_base();
        assert_eq!(base, 0x1_0000_0000);
        let vaddr0 = bin.exec_scan_regions()[0].vaddr;
        let entry0 = bin.entry();
        bin.rebase(0);
        assert_eq!(bin.image_base(), 0);
        assert_eq!(bin.exec_scan_regions()[0].vaddr, vaddr0 - base);
        assert_eq!(bin.entry(), entry0 - base);
        assert!(bin.exec_scan_regions()[0].vaddr < 0x1_0000_0000);
    }

    #[test]
    fn rebase_shifts_vaddrs_and_entry() {
        let bytes = load_fixture("macho-x86-ls");
        let mut bin = MachOBinary::parse(&bytes).unwrap();
        let base0 = bin.image_base();
        let entry0 = bin.entry();
        let vaddr0 = bin.exec_scan_regions()[0].vaddr;
        bin.rebase(0x1000_0000);
        let delta = 0x1000_0000u64.wrapping_sub(base0);
        assert_eq!(bin.image_base(), 0x1000_0000);
        assert_eq!(bin.entry(), entry0.wrapping_add(delta));
        assert_eq!(bin.exec_scan_regions()[0].vaddr, vaddr0.wrapping_add(delta));
    }

    /// ROB-02's byte budget and de-overlap must not change what a
    /// well-formed Mach-O materialises: every section still holds its
    /// declared size, clamped to the file.
    #[test]
    fn every_macho_fixture_still_loads_with_full_content() {
        for name in ["macho-x86-ls", "macho-x64-ls", "macho-ppc-openssl"] {
            let bytes = load_fixture(name);
            let bin = MachOBinary::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!bin.sections().is_empty(), "{name}");
            for s in bin.sections() {
                let start = usize::try_from(s.offset).unwrap_or(usize::MAX);
                let expect = usize::try_from(s.size)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len().saturating_sub(start));
                assert_eq!(s.bytes.len(), expect, "{name} section {}", s.name);
            }
        }
    }

    #[test]
    fn truncations_never_panic() {
        for name in ["macho-x86-ls", "macho-ppc-openssl"] {
            let bytes = load_fixture(name);
            // Every truncation length in the header region must return
            // (Ok or Err), never panic.
            for n in 0..=512usize.min(bytes.len()) {
                let _ = MachOBinary::parse(&bytes[..n]);
            }
            // ~200 coarse truncation lengths over the whole file.
            let step = (bytes.len() / 200).max(1);
            for n in (512..bytes.len()).step_by(step) {
                let _ = MachOBinary::parse(&bytes[..n]);
            }
        }
    }

    #[test]
    fn mutated_bytes_never_panic() {
        let bytes = load_fixture("macho-x64-ls");
        // Bit-flip mutations across the header and load commands.
        for i in 0..512usize.min(bytes.len()) {
            let mut m = bytes.clone();
            m[i] ^= 0xff;
            let _ = MachOBinary::parse(&m);
        }
        // Pseudo-random single-byte flips across the rest of the file.
        let mut state = 0x4528_21e6_38d0_1377u64;
        for _ in 0..200 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let idx = (state >> 33) as usize % bytes.len();
            let mut m = bytes.clone();
            m[idx] ^= (state >> 11) as u8 | 1;
            let _ = MachOBinary::parse(&m);
        }
    }

    #[test]
    fn garbage_returns_err_not_panic() {
        assert!(MachOBinary::parse(b"").is_err());
        assert!(MachOBinary::parse(&[0u8; 256]).is_err());
        assert!(MachOBinary::parse(b"not a mach-o").is_err());
        // Valid LE magic, garbage everything else.
        let mut g = vec![0u8; 256];
        g[0..4].copy_from_slice(&[0xce, 0xfa, 0xed, 0xfe]);
        let _ = MachOBinary::parse(&g); // must not panic
    }
}
