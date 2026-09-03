//! PE loading via goblin.
//!
//! Semantics ported from ROPgadget's `loaders/pe.py`:
//! - Arch from the COFF `Machine` field (pe.py:220-226), extended with ARM64
//!   (0xaa64) which ROPgadget predates.
//! - Entry = `ImageBase + AddressOfEntryPoint` (pe.py:191-192).
//! - Section vaddr = `VirtualAddress + ImageBase` (pe.py:202, 215).
//! - Executable = `IMAGE_SCN_MEM_EXECUTE` (pe.py:210), writable =
//!   `IMAGE_SCN_MEM_WRITE` (pe.py:197).
//! - ROPgadget scans PE *sections* directly (`getExecSections`), so
//!   `exec_scan_regions` is exactly the executable sections — no separate
//!   segment model exists in PE.
//!
//! Conscious deviation: ROPgadget reports `size = SizeOfRawData` even when
//! the file is shorter; we clamp `bytes`/`size` to what the file actually
//! contains (same defensive convention as the ELF loader).

use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};

use crate::util::{cstr_lossy, slice_clamped};
use crate::{Arch, Endianness, Error, Section};

// COFF machine types (ropgadget/loaders/pe.py:17-20, plus ARM64).
const IMAGE_MACHINE_INTEL_386: u16 = 0x014c;
const IMAGE_MACHINE_AMD_8664: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
const IMAGE_FILE_MACHINE_ARMV7: u16 = 0x01c4;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

/// One imported symbol, resolved to its IAT thunk location.
///
/// Not part of the [`crate::Image`] trait — Phase 4 (Windows chain building)
/// consumes this. Parsing is best-effort: a PE without an import directory
/// (or with one goblin cannot resolve) simply yields an empty list.
#[derive(Debug, Clone)]
pub struct PeImport {
    /// DLL the symbol comes from (e.g. `KERNEL32.dll`).
    pub dll: String,
    /// Symbol name (or ordinal string for ordinal imports).
    pub name: String,
    /// RVA of the IAT thunk that will hold the resolved address.
    pub thunk_rva: u64,
    /// `image_base + thunk_rva` at parse time (shifted by [`PeBinary::rebase`]).
    pub thunk_vaddr: u64,
}

/// A parsed PE binary.
#[derive(Debug)]
pub struct PeBinary {
    /// COFF `Machine` field.
    machine: u16,
    arch: Arch,
    /// PE32+ (64-bit optional header)?
    is_64: bool,
    entry: u64,
    image_base: u64,
    sections: Vec<Section>,
    /// ROPgadget-compatible scan regions: sections with IMAGE_SCN_MEM_EXECUTE.
    exec_regions: Vec<Section>,
    imports: Vec<PeImport>,
    /// Optional-header DllCharacteristics (GUARD_CF etc.).
    dll_characteristics: u16,
}

impl PeBinary {
    /// Parse a PE binary, returning a structured error on malformed input.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let pe = goblin::pe::PE::parse(bytes)?;

        let machine = pe.header.coff_header.machine;
        let arch = match machine {
            IMAGE_MACHINE_INTEL_386 => Arch::X86,
            IMAGE_MACHINE_AMD_8664 => Arch::X64,
            IMAGE_FILE_MACHINE_ARM => Arch::Arm,
            IMAGE_FILE_MACHINE_ARMV7 => Arch::ArmThumb,
            IMAGE_FILE_MACHINE_ARM64 => Arch::Arm64,
            other => return Err(Error::Unsupported(format!("PE machine {other:#06x}"))),
        };

        let is_64 = pe.is_64;
        let image_base = pe.image_base;
        // pe.py:191-192 — goblin's `pe.entry` is the entry *RVA*.
        let entry = image_base.wrapping_add(u64::from(pe.entry));

        let mut sections = Vec::with_capacity(pe.sections.len());
        let mut exec_regions = Vec::new();
        for sec in &pe.sections {
            let content = slice_clamped(
                bytes,
                u64::from(sec.pointer_to_raw_data),
                u64::from(sec.size_of_raw_data),
            );
            let size = content.len() as u64;
            let executable = sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0;
            let section = Section {
                // 8-byte field, not guaranteed NUL-terminated (pe.py:126).
                name: cstr_lossy(&sec.name),
                // pe.py:202, 215 — VirtualAddress + ImageBase.
                vaddr: image_base.wrapping_add(u64::from(sec.virtual_address)),
                offset: u64::from(sec.pointer_to_raw_data),
                size,
                bytes: content,
                executable,
                writable: sec.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                allocated: true,
            };
            if executable {
                exec_regions.push(section.clone());
            }
            sections.push(section);
        }

        // Best-effort import table (groundwork for Phase 4 Windows chains).
        let imports = pe
            .imports
            .iter()
            .map(|imp| PeImport {
                dll: imp.dll.to_string(),
                name: imp.name.to_string(),
                thunk_rva: imp.rva as u64,
                thunk_vaddr: image_base.wrapping_add(imp.rva as u64),
            })
            .collect();

        let dll_characteristics = pe
            .header
            .optional_header
            .map(|o| o.windows_fields.dll_characteristics)
            .unwrap_or(0);

        Ok(PeBinary {
            machine,
            arch,
            is_64,
            entry,
            image_base,
            sections,
            exec_regions,
            imports,
            dll_characteristics,
        })
    }

    /// COFF `Machine` field (e.g. 0x8664 for AMD64).
    pub fn machine(&self) -> u16 {
        self.machine
    }

    /// Architecture from the COFF `Machine` field (pe.py:220-226, plus ARM64).
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// PE32+ (64-bit optional header)?
    pub fn is_64(&self) -> bool {
        self.is_64
    }

    /// Entry point: `ImageBase + AddressOfEntryPoint` (pe.py:191-192).
    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// All sections, in header order.
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Executable sections (IMAGE_SCN_MEM_EXECUTE).
    pub fn exec_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.executable).collect()
    }

    /// ROPgadget-compatible scan regions: the executable PE sections
    /// (pe.py:207-218 — ROPgadget scans PE sections directly).
    pub fn exec_scan_regions(&self) -> &[Section] {
        &self.exec_regions
    }

    /// Optional-header ImageBase, captured at parse time.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Imported symbols with their IAT thunk addresses. Best-effort: empty
    /// when the binary has no resolvable import directory.
    pub fn imports(&self) -> &[PeImport] {
        &self.imports
    }

    /// IMAGE_DLL_CHARACTERISTICS_GUARD_CF (0x4000): the PE advertises
    /// Control Flow Guard. Goblin does not parse the load-config directory
    /// (where the CET/IBT compat flag lives), so this CFG bit is the
    /// available hardening marker for `--cfg-aware` guidance.
    pub fn guard_cf(&self) -> bool {
        self.dll_characteristics & 0x4000 != 0
    }

    /// Rebase the binary to `new_base`: shifts every section vaddr, the
    /// entry point, and the import thunk vaddrs by `new_base - image_base()`.
    /// `rebase(0)` therefore yields RVA-style addresses.
    pub fn rebase(&mut self, new_base: u64) {
        let delta = new_base.wrapping_sub(self.image_base);
        for s in &mut self.sections {
            s.vaddr = s.vaddr.wrapping_add(delta);
        }
        for s in &mut self.exec_regions {
            s.vaddr = s.vaddr.wrapping_add(delta);
        }
        for imp in &mut self.imports {
            imp.thunk_vaddr = imp.thunk_vaddr.wrapping_add(delta);
        }
        self.entry = self.entry.wrapping_add(delta);
        self.image_base = new_base;
    }
}

impl crate::Image for PeBinary {
    fn arch(&self) -> Arch {
        self.arch
    }

    /// PE is little-endian only (pe.py:236-238).
    fn endianness(&self) -> Endianness {
        Endianness::Little
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
    use crate::Image;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixture_path(name)).expect("fixture should exist")
    }

    #[test]
    fn parses_real_pe_x86() {
        let bytes = load_fixture("pe-x86-cmd-v6.1.7600");
        let bin = PeBinary::parse(&bytes).expect("should parse");
        assert_eq!(bin.arch(), Arch::X86);
        assert!(!bin.is_64());
        assert_eq!(bin.machine(), IMAGE_MACHINE_INTEL_386);
        assert_eq!(bin.endianness(), Endianness::Little);
        let exec = bin.exec_scan_regions();
        assert!(!exec.is_empty());
        assert!(exec.iter().any(|s| s.name == ".text"));
        for s in exec {
            assert!(s.executable);
            assert!(!s.bytes.is_empty());
            assert_eq!(s.size, s.bytes.len() as u64);
        }
        // entry sits inside the image
        assert!(bin.entry() >= bin.image_base());
        // cmd.exe imports from KERNEL32 et al.
        let imports = bin.imports();
        assert!(!imports.is_empty());
        assert!(imports
            .iter()
            .any(|i| i.dll.to_ascii_uppercase().contains("KERNEL32")));
        for i in imports {
            assert_eq!(i.thunk_vaddr, bin.image_base() + i.thunk_rva);
        }
    }

    #[test]
    fn parses_real_pe_x64() {
        let bytes = load_fixture("pe-x64-cmd-v6.1.7601");
        let bin = PeBinary::parse(&bytes).expect("should parse");
        assert_eq!(bin.arch(), Arch::X64);
        assert!(bin.is_64());
        assert_eq!(bin.machine(), IMAGE_MACHINE_AMD_8664);
        assert!(!bin.exec_scan_regions().is_empty());
        assert!(!bin.imports().is_empty());
    }

    #[test]
    fn parses_real_pe_armv7_thumb() {
        let bytes = load_fixture("pe-Windows-ARMv7-Thumb2LE-HelloWorld");
        let bin = PeBinary::parse(&bytes).expect("should parse");
        assert_eq!(bin.machine(), IMAGE_FILE_MACHINE_ARMV7);
        assert_eq!(bin.arch(), Arch::ArmThumb);
        assert!(!bin.exec_scan_regions().is_empty());
    }

    #[test]
    fn section_vaddrs_include_image_base() {
        let bytes = load_fixture("pe-x64-cmd-v6.1.7601");
        let bin = PeBinary::parse(&bytes).unwrap();
        assert!(bin.image_base() > 0);
        for s in bin.sections() {
            assert!(s.vaddr >= bin.image_base(), "{} @ {:#x}", s.name, s.vaddr);
        }
    }

    #[test]
    fn rebase_zero_yields_rvas() {
        let bytes = load_fixture("pe-x64-cmd-v6.1.7601");
        let mut bin = PeBinary::parse(&bytes).unwrap();
        let base = bin.image_base();
        let entry0 = bin.entry();
        let vaddr0 = bin.exec_scan_regions()[0].vaddr;
        bin.rebase(0);
        assert_eq!(bin.image_base(), 0);
        assert_eq!(bin.entry(), entry0 - base);
        assert_eq!(bin.exec_scan_regions()[0].vaddr, vaddr0 - base);
        for i in bin.imports() {
            assert_eq!(i.thunk_vaddr, i.thunk_rva);
        }
    }

    #[test]
    fn rebase_roundtrip() {
        let bytes = load_fixture("pe-x86-cmd-v6.1.7600");
        let mut bin = PeBinary::parse(&bytes).unwrap();
        let base = bin.image_base();
        let entry0 = bin.entry();
        bin.rebase(0);
        bin.rebase(base);
        assert_eq!(bin.image_base(), base);
        assert_eq!(bin.entry(), entry0);
    }

    #[test]
    fn truncations_never_panic() {
        for name in [
            "pe-x86-cmd-v6.1.7600",
            "pe-Windows-ARMv7-Thumb2LE-HelloWorld",
        ] {
            let bytes = load_fixture(name);
            // Every truncation length in the header region must return
            // (Ok or Err), never panic.
            for n in 0..=512usize.min(bytes.len()) {
                let _ = PeBinary::parse(&bytes[..n]);
            }
            // ~200 coarse truncation lengths over the whole file.
            let step = (bytes.len() / 200).max(1);
            for n in (512..bytes.len()).step_by(step) {
                let _ = PeBinary::parse(&bytes[..n]);
            }
        }
    }

    #[test]
    fn mutated_bytes_never_panic() {
        let bytes = load_fixture("pe-x64-cmd-v6.1.7601");
        // Bit-flip mutations across the DOS/PE headers and section table.
        for i in 0..512usize.min(bytes.len()) {
            let mut m = bytes.clone();
            m[i] ^= 0xff;
            let _ = PeBinary::parse(&m);
        }
        // Pseudo-random single-byte flips across the rest of the file.
        let mut state = 0x243f_6a88_85a3_08d3u64;
        for _ in 0..200 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let idx = (state >> 33) as usize % bytes.len();
            let mut m = bytes.clone();
            m[idx] ^= (state >> 11) as u8 | 1;
            let _ = PeBinary::parse(&m);
        }
    }

    #[test]
    fn garbage_returns_err_not_panic() {
        assert!(PeBinary::parse(b"").is_err());
        assert!(PeBinary::parse(b"MZ").is_err());
        assert!(PeBinary::parse(&[0u8; 512]).is_err());
        assert!(PeBinary::parse(b"not a pe at all").is_err());
        // Valid magic, garbage everything else.
        let mut g = vec![0u8; 512];
        g[0..2].copy_from_slice(b"MZ");
        let _ = PeBinary::parse(&g); // must not panic
    }
}
