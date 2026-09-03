//! ELF loading via goblin.

use goblin::elf::program_header::{PF_W, PF_X, PT_LOAD};
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS};

use crate::util::slice_clamped;
use crate::Error;

/// ELF class (32- or 64-bit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Bit32,
    Bit64,
}

impl ElfClass {
    /// Bytes in a packed virtual address (used by --badbytes).
    pub fn addr_size(self) -> usize {
        match self {
            ElfClass::Bit32 => 4,
            ElfClass::Bit64 => 8,
        }
    }
}

/// A loadable, named view of executable or data bytes.
///
/// Names come from section headers; for ELFs without section headers we
/// synthesize `PT_LOAD#n` names from program headers.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    /// Virtual address of the first byte.
    pub vaddr: u64,
    /// File offset of the first byte.
    pub offset: u64,
    /// Length of `bytes` (clamped to what the file actually contains).
    pub size: u64,
    /// Section content (empty for `SHT_NOBITS`).
    pub bytes: Vec<u8>,
    /// `SHF_EXECINSTR` (or `PF_X` for the segment fallback).
    pub executable: bool,
    /// `SHF_WRITE` (or `PF_W` for the segment fallback).
    pub writable: bool,
    /// `SHF_ALLOC` — occupies memory at runtime. Always true for
    /// PE/Mach-O/raw sections and the ELF segment fallback. ROPgadget's
    /// `getDataSections` (elf.py:323-334) requires it.
    pub allocated: bool,
}

/// A parsed ELF binary.
#[derive(Debug)]
pub struct ElfBinary {
    class: ElfClass,
    /// `e_machine` (e.g. `EM_386`, `EM_X86_64`).
    machine: u16,
    /// Little-endian?
    little_endian: bool,
    entry: u64,
    /// Minimum `p_vaddr` over all `PT_LOAD` program headers.
    image_base: u64,
    sections: Vec<Section>,
    /// ROPgadget-compatible scan regions: program headers with `PF_X`.
    exec_regions: Vec<Section>,
}

impl ElfBinary {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let elf = goblin::elf::Elf::parse(bytes)?;

        let class = match elf.header.e_ident[goblin::elf::header::EI_CLASS] {
            goblin::elf::header::ELFCLASS32 => ElfClass::Bit32,
            goblin::elf::header::ELFCLASS64 => ElfClass::Bit64,
            other => {
                return Err(Error::Unsupported(format!("ELF class {other}")));
            }
        };
        let little_endian = elf.little_endian;
        let machine = elf.header.e_machine;
        let entry = elf.header.e_entry;

        let sections = if !elf.section_headers.is_empty() {
            sections_from_headers(&elf, bytes)
        } else {
            sections_from_segments(&elf, bytes)
        };

        let image_base = elf
            .program_headers
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| p.p_vaddr)
            .min()
            .unwrap_or(0);

        // ROPgadget's ELF loader (`loaders/elf.py:getExecSections`) scans
        // every program header with PF_X, reading `p_memsz` file bytes from
        // `p_offset` (Python slicing silently clamps at EOF and happily reads
        // past `p_filesz` into subsequent file bytes). Port that exactly —
        // it is what the parity oracle scans.
        let mut exec_regions = Vec::new();
        let mut n = 0usize;
        for phdr in &elf.program_headers {
            if phdr.p_flags & PF_X == 0 {
                continue;
            }
            let content = slice_clamped(bytes, phdr.p_offset, phdr.p_memsz);
            let size = content.len() as u64;
            exec_regions.push(Section {
                name: format!("PT_LOAD#{n}"),
                vaddr: phdr.p_vaddr,
                offset: phdr.p_offset,
                size,
                bytes: content,
                executable: true,
                writable: phdr.p_flags & PF_W != 0,
                allocated: true,
            });
            n += 1;
        }

        Ok(ElfBinary {
            class,
            machine,
            little_endian,
            entry,
            image_base,
            sections,
            exec_regions,
        })
    }

    pub fn class(&self) -> ElfClass {
        self.class
    }

    pub fn machine(&self) -> u16 {
        self.machine
    }

    pub fn is_64(&self) -> bool {
        self.class == ElfClass::Bit64
    }

    pub fn little_endian(&self) -> bool {
        self.little_endian
    }

    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// All sections (header order, or program-header order for the fallback).
    pub fn sections(&self) -> &[Section] {
        &self.sections
    }

    /// Executable sections in deterministic traversal order.
    pub fn exec_sections(&self) -> Vec<&Section> {
        self.sections.iter().filter(|s| s.executable).collect()
    }

    /// ROPgadget-compatible executable scan regions: every program header
    /// with the `PF_X` flag, in program-header order, named `PT_LOAD#n`.
    /// This is what the parity oracle scans (it ignores section headers);
    /// use [`exec_sections`](Self::exec_sections) for the section model.
    pub fn exec_scan_regions(&self) -> &[Section] {
        &self.exec_regions
    }

    /// Image base: minimum `p_vaddr` over all `PT_LOAD` program headers,
    /// captured at parse time.
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

    /// Map `e_machine` + ELF class to the shared [`Arch`] contract.
    pub fn arch(&self) -> Result<crate::Arch, Error> {
        use crate::Arch::*;
        use goblin::elf::header as h;
        let is64 = self.is_64();
        Ok(match self.machine {
            h::EM_386 => X86,
            h::EM_X86_64 => X64,
            h::EM_ARM => Arm,
            h::EM_AARCH64 => Arm64,
            h::EM_MIPS => {
                if is64 {
                    Mips64
                } else {
                    Mips32
                }
            }
            h::EM_PPC => Ppc32,
            h::EM_PPC64 => Ppc64,
            h::EM_SPARC | h::EM_SPARC32PLUS => Sparc,
            h::EM_SPARCV9 => SparcV9,
            h::EM_RISCV => {
                if is64 {
                    RiscV64
                } else {
                    RiscV32
                }
            }
            other => return Err(Error::Unsupported(format!("e_machine {other}"))),
        })
    }
}

impl crate::Image for ElfBinary {
    fn arch(&self) -> crate::Arch {
        self.arch().unwrap_or(crate::Arch::X86)
    }

    fn endianness(&self) -> crate::Endianness {
        if self.little_endian {
            crate::Endianness::Little
        } else {
            crate::Endianness::Big
        }
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

fn sections_from_headers(elf: &goblin::elf::Elf, bytes: &[u8]) -> Vec<Section> {
    let mut out = Vec::with_capacity(elf.section_headers.len());
    for shdr in &elf.section_headers {
        let name = elf
            .shdr_strtab
            .get_at(shdr.sh_name)
            .unwrap_or("")
            .to_string();
        let content = if shdr.sh_type == SHT_NOBITS {
            Vec::new()
        } else {
            slice_clamped(bytes, shdr.sh_offset, shdr.sh_size)
        };
        let size = content.len() as u64;
        out.push(Section {
            name,
            vaddr: shdr.sh_addr,
            offset: shdr.sh_offset,
            size,
            bytes: content,
            executable: shdr.sh_flags & u64::from(SHF_EXECINSTR) != 0,
            writable: shdr.sh_flags & u64::from(SHF_WRITE) != 0,
            allocated: shdr.sh_flags & u64::from(SHF_ALLOC) != 0,
        });
    }
    out
}

/// Fallback for ELFs without section headers: executable-ness and
/// writability come from `PT_LOAD` segment flags, names are synthesized.
fn sections_from_segments(elf: &goblin::elf::Elf, bytes: &[u8]) -> Vec<Section> {
    let mut out = Vec::new();
    let mut n = 0usize;
    for phdr in &elf.program_headers {
        if phdr.p_type != PT_LOAD {
            continue;
        }
        let content = slice_clamped(bytes, phdr.p_offset, phdr.p_filesz);
        let size = content.len() as u64;
        out.push(Section {
            name: format!("PT_LOAD#{n}"),
            vaddr: phdr.p_vaddr,
            offset: phdr.p_offset,
            size,
            bytes: content,
            executable: phdr.p_flags & PF_X != 0,
            writable: phdr.p_flags & PF_W != 0,
            allocated: true,
        });
        n += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Binary;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixture_path(name)).expect("fixture should exist")
    }

    #[test]
    fn parses_real_elf64() {
        let bytes = load_fixture("elf-x64-bash-v4.1.5.1");
        let bin = Binary::parse(&bytes).expect("should parse");
        assert_eq!(bin.class(), ElfClass::Bit64);
        assert!(bin.little_endian());
        assert_eq!(bin.machine(), goblin::elf::header::EM_X86_64);
        let exec = bin.exec_sections();
        assert!(!exec.is_empty());
        assert!(exec.iter().any(|s| s.name == ".text"));
        for s in &exec {
            assert!(s.executable);
            assert!(!s.bytes.is_empty());
            assert_eq!(s.size, s.bytes.len() as u64);
        }
        // image base of a classic ET_EXEC x86-64 binary
        assert_eq!(bin.image_base(), 0x400000, "got {:#x}", bin.image_base());
    }

    #[test]
    fn parses_real_elf32() {
        let bytes = load_fixture("elf-x86-bash-v4.1.5.1");
        let bin = Binary::parse(&bytes).expect("should parse");
        assert_eq!(bin.class(), ElfClass::Bit32);
        assert_eq!(bin.machine(), goblin::elf::header::EM_386);
        assert!(!bin.exec_sections().is_empty());
    }

    #[test]
    fn rebase_shifts_vaddrs_and_entry() {
        let bytes = load_fixture("elf-x64-bash-v4.1.5.1");
        let mut bin = Binary::parse(&bytes).unwrap();
        let base0 = bin.image_base();
        let entry0 = bin.entry();
        let vaddr0 = bin.exec_sections()[0].vaddr;
        bin.rebase(0x5555_5555_0000);
        let delta = 0x5555_5555_0000u64 - base0;
        assert_eq!(bin.image_base(), 0x5555_5555_0000);
        assert_eq!(bin.entry(), entry0 + delta);
        assert_eq!(bin.exec_sections()[0].vaddr, vaddr0 + delta);
    }

    #[test]
    fn truncations_never_panic() {
        let bytes = load_fixture("elf-x64-bash-v4.1.5.1");
        // Mini mutation loop: every truncation length in the header region
        // must return (Ok or Err), never panic.
        for n in 0..=512usize {
            let _ = Binary::parse(&bytes[..n]);
        }
        // And a coarse sweep over the whole file.
        for n in (1024..bytes.len()).step_by(4096) {
            let _ = Binary::parse(&bytes[..n]);
        }
    }

    #[test]
    fn garbage_returns_err_not_panic() {
        assert!(Binary::parse(b"").is_err());
        assert!(Binary::parse(b"\x7fELF").is_err());
        assert!(Binary::parse(&[0u8; 64]).is_err());
        assert!(Binary::parse(b"not an elf at all").is_err());
        // Valid magic, garbage everything else.
        let mut g = vec![0u8; 256];
        g[0..4].copy_from_slice(b"\x7fELF");
        g[4] = 2; // ELFCLASS64
        g[5] = 1; // LSB
        let _ = Binary::parse(&g); // must not panic
    }

    #[test]
    fn mutated_bytes_never_panic() {
        let bytes = load_fixture("elf-Linux-x86");
        // Bit-flip mutations across the header and program/section headers.
        for i in 0..256usize {
            let mut m = bytes.clone();
            m[i] ^= 0xff;
            let _ = Binary::parse(&m);
        }
    }
}
