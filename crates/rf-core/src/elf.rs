//! ELF loading via goblin.

use goblin::elf::program_header::{pt_to_str, PF_W, PF_X, PT_LOAD};
use goblin::elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS};

use crate::util::ByteBudget;
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
    /// DECLARED size of the region: ELF `p_memsz` / `sh_size`, PE
    /// `SizeOfRawData`, Mach-O `section.size` (CORE-04).
    ///
    /// This is the oracle's `section['size']`, and it is not dead metadata:
    /// ROPgadget's `core.py:_sectionInRange` computes
    /// `sectionEnd = vaddr + size` and trims the opcode buffer against it,
    /// so reporting the clamped byte count here made `--range` disagree with
    /// the oracle on every binary whose declared extent exceeds its on-disk
    /// extent (e.g. `elf-SparcV8-bash` program header 3: `p_filesz` 0x4d4c,
    /// `p_memsz` 0x967c, on-disk remainder 0x52a4).
    ///
    /// `bytes` is still clamped to what the file actually contains, so
    /// `size >= bytes.len()` and the two are equal only when the file holds
    /// the whole declared extent.
    pub size: u64,
    /// Section content, clamped to the file (empty for `SHT_NOBITS`, and
    /// empty for a header that re-declares a file range another header in
    /// the same view already materialised — see `util::ByteBudget`).
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

/// A disagreement between the width rop-finder decodes an ELF with and the
/// width the parity oracle decodes it with (CORE-07).
///
/// See [`ElfBinary::mode_divergence`] for which side rop-finder takes and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeDivergence {
    /// `e_machine`, the field rop-finder derives its decode width from.
    pub machine: u16,
    /// `EI_CLASS`, the field ROPgadget derives its decode width from.
    pub class: ElfClass,
    /// Width in bits rop-finder disassembles with (from `e_machine`).
    pub rf_bits: u32,
    /// Width in bits ROPgadget disassembles with (from `EI_CLASS`).
    pub oracle_bits: u32,
}

/// A parsed ELF binary.
#[derive(Debug)]
pub struct ElfBinary {
    class: ElfClass,
    /// `e_machine` (e.g. `EM_386`, `EM_X86_64`).
    machine: u16,
    /// Architecture resolved at parse time. An `e_machine` that does not map
    /// makes [`ElfBinary::parse`] fail (CORE-01) — this field is never a
    /// fallback guess.
    arch: crate::Arch,
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

        // CORE-01 — refuse an `e_machine` we cannot disassemble, here in the
        // loader, so no caller can ever be handed a fabricated architecture.
        // The oracle does the same (`loaders/elf.py:260` calls `getArch()`
        // from the header parser and `core.py:33` then aborts): verified
        // live, an ELF with `e_machine` 0x9999 makes ROPgadget 7.7 print
        // "[Error] ELF.getArch() - Architecture not supported" and exit 1
        // with zero gadgets.
        let arch = arch_for(machine, class)?;

        // The single program-header enumeration (CORE-06). Both the segment
        // fallback view and the scan regions are cut from this one list, so
        // the name `PT_LOAD#n` can never denote two different headers.
        let segments = segments_view(&elf, bytes)?;

        let sections = if !elf.section_headers.is_empty() {
            sections_from_headers(&elf, bytes)?
        } else {
            segments.clone()
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
        let exec_regions: Vec<Section> =
            segments.iter().filter(|s| s.executable).cloned().collect();

        Ok(ElfBinary {
            class,
            machine,
            arch,
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
    /// with the `PF_X` flag, in program-header order.
    ///
    /// This is what the parity oracle scans (it ignores section headers);
    /// use [`exec_sections`](Self::exec_sections) for the section model.
    ///
    /// CORE-06: for a stripped ELF these regions and the synthetic section
    /// view are literally the same `Section` values, so `--section
    /// PT_LOAD#n` selects exactly the header the default scan calls
    /// `PT_LOAD#n`, with exactly the same extent.
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

    /// Map `e_machine` + ELF class to the shared [`Arch`](crate::Arch)
    /// contract.
    ///
    /// Infallible in practice since Phase 2: [`parse`](Self::parse) has
    /// already refused an `e_machine` that does not map, so this only ever
    /// returns `Ok`. The `Result` is retained for API compatibility.
    pub fn arch(&self) -> Result<crate::Arch, Error> {
        Ok(self.arch)
    }

    /// CORE-07 — does rop-finder disassemble this ELF in a different width
    /// than the parity oracle does?
    ///
    /// # The divergence, and which side rop-finder takes
    ///
    /// ROPgadget derives the two halves of its capstone configuration from
    /// two *different* header fields: `getArch()` (loaders/elf.py:336-352)
    /// maps `e_machine` to a `CS_ARCH_*`, while `getArchMode()`
    /// (loaders/elf.py:354-360) maps `EI_CLASS` to `CS_MODE_32`/`CS_MODE_64`.
    /// For the x32 ABI (Debian x32, `gcc -mx32`: `ELFCLASS32` +
    /// `EM_X86_64`) that yields `CS_ARCH_X86` + `CS_MODE_32`, i.e. the
    /// oracle decodes an x32 binary as 32-bit code. The mirror case
    /// (`ELFCLASS64` + `EM_386`) diverges the same way in the other
    /// direction, as does `ELFCLASS32` + `EM_AARCH64` (the AArch64 ILP32
    /// ABI).
    ///
    /// **rop-finder deliberately does not match the oracle here.** It
    /// derives both architecture and width from `e_machine`, because that is
    /// the field that describes the *instruction encodings* in the file: an
    /// x32 binary contains genuine x86-64 machine code (REX prefixes, 64-bit
    /// operands) and only its pointers are 32-bit. Decoding it in
    /// `CS_MODE_32` misreads every REX-prefixed instruction. `EI_CLASS`
    /// describes the data model, not the ISA.
    ///
    /// The cost of choosing correctness over parity is that gadget sets on
    /// such a binary differ from ROPgadget's, so this method exists to make
    /// that visible rather than silent: it returns `Some` exactly when the
    /// two fields disagree, carrying both widths, and the CLI is expected to
    /// print an explicit warning naming the ABI.
    pub fn mode_divergence(&self) -> Option<ModeDivergence> {
        let rf_bits = (self.arch.addr_size() * 8) as u32;
        let oracle_bits = (self.class.addr_size() * 8) as u32;
        if rf_bits == oracle_bits {
            return None;
        }
        Some(ModeDivergence {
            machine: self.machine,
            class: self.class,
            rf_bits,
            oracle_bits,
        })
    }
}

/// CORE-01: `e_machine` -> [`Arch`](crate::Arch), or a refusal naming the
/// machine type. There is no fallback branch, by design.
fn arch_for(machine: u16, class: ElfClass) -> Result<crate::Arch, Error> {
    use crate::Arch::*;
    use goblin::elf::header as h;
    let is64 = class == ElfClass::Bit64;
    Ok(match machine {
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
        other => {
            return Err(Error::UnsupportedArch {
                machine: u64::from(other),
            })
        }
    })
}

impl crate::Image for ElfBinary {
    /// Infallible by construction: [`ElfBinary::parse`] refuses an
    /// unrecognised `e_machine` (CORE-01), so this is never a guess.
    fn arch(&self) -> crate::Arch {
        self.arch
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

fn sections_from_headers(elf: &goblin::elf::Elf, bytes: &[u8]) -> Result<Vec<Section>, Error> {
    let mut budget = ByteBudget::for_file(bytes.len());
    let mut out = Vec::new();
    for shdr in &elf.section_headers {
        let name = elf
            .shdr_strtab
            .get_at(shdr.sh_name)
            .unwrap_or("")
            .to_string();
        let content = if shdr.sh_type == SHT_NOBITS {
            Vec::new()
        } else {
            budget.take(bytes, shdr.sh_offset, shdr.sh_size, "ELF section headers")?
        };
        out.push(Section {
            name,
            vaddr: shdr.sh_addr,
            offset: shdr.sh_offset,
            // CORE-04 — the declared size, as the oracle reports it.
            size: shdr.sh_size,
            bytes: content,
            executable: shdr.sh_flags & u64::from(SHF_EXECINSTR) != 0,
            writable: shdr.sh_flags & u64::from(SHF_WRITE) != 0,
            allocated: shdr.sh_flags & u64::from(SHF_ALLOC) != 0,
        });
    }
    Ok(out)
}

/// The one program-header enumeration (CORE-06).
///
/// Before Phase 2 there were two: `sections_from_segments` numbered only
/// `PT_LOAD` headers and read `p_filesz`, while the scan-region builder
/// numbered only `PF_X` headers and read `p_memsz`. The string `PT_LOAD#1`
/// therefore denoted a different program header in each view — on 5 of the
/// 16 ELF fixtures, because a `PF_X` `PT_PHDR` shifted one enumeration by
/// one — and for the same header the two views held different byte counts,
/// so `--section PT_LOAD#1` scanned less than the default scan did for what
/// looked like the same region.
///
/// Now there is one list, and both views are cut from it:
///
/// * One entry per program header that is `PT_LOAD` **or** carries `PF_X`,
///   in program-header table order. The `PF_X` non-`PT_LOAD` headers
///   (`PT_PHDR`, `PT_GNU_RELRO`) that the scanner really walks are therefore
///   visible to `--info`/`--section` instead of invisible.
/// * `#n` is the header's index in the program-header *table*, not a
///   per-view counter, so the same header always gets the same name.
/// * Extent is `p_memsz` for every entry, matching what the default scan
///   reads (`loaders/elf.py:311-321`).
///
/// Names keep the established `PT_LOAD#` prefix (documented in README.md and
/// MANUAL.md, and used by rf-cli to detect a stripped binary); an entry that
/// is not actually a `PT_LOAD` is spelled `PT_LOAD#n(PT_PHDR)` so the name
/// stays truthful about which header it names.
fn segments_view(elf: &goblin::elf::Elf, bytes: &[u8]) -> Result<Vec<Section>, Error> {
    let mut budget = ByteBudget::for_file(bytes.len());
    let mut out = Vec::new();
    for (i, phdr) in elf.program_headers.iter().enumerate() {
        let executable = phdr.p_flags & PF_X != 0;
        if phdr.p_type != PT_LOAD && !executable {
            continue;
        }
        let name = if phdr.p_type == PT_LOAD {
            format!("PT_LOAD#{i}")
        } else {
            format!("PT_LOAD#{i}({})", pt_to_str(phdr.p_type))
        };
        let content = budget.take(bytes, phdr.p_offset, phdr.p_memsz, "ELF program headers")?;
        out.push(Section {
            name,
            vaddr: phdr.p_vaddr,
            offset: phdr.p_offset,
            // CORE-04 — the declared extent (`p_memsz`), which is also the
            // extent the default scan reads.
            size: phdr.p_memsz,
            bytes: content,
            executable,
            writable: phdr.p_flags & PF_W != 0,
            allocated: true,
        });
    }
    Ok(out)
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

    /// A minimal but structurally valid ELF, built by hand so the tests can
    /// set fields no fixture carries. `class` is 1 (ELFCLASS32) or 2
    /// (ELFCLASS64); one PF_X PT_LOAD program header covers `code`.
    fn synth_elf(class: u8, machine: u16, code: &[u8]) -> Vec<u8> {
        let is64 = class == 2;
        let ehsize: usize = if is64 { 64 } else { 52 };
        let phentsize: usize = if is64 { 56 } else { 32 };
        let code_off = ehsize + phentsize;
        let mut out = Vec::new();
        out.extend_from_slice(b"\x7fELF");
        out.push(class);
        out.push(1); // ELFDATA2LSB
        out.push(1); // EV_CURRENT
        out.extend_from_slice(&[0u8; 9]);
        out.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
        out.extend_from_slice(&machine.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes()); // e_version
        let vaddr: u64 = 0x40_0000;
        let filesz = (code_off + code.len()) as u64;
        if is64 {
            out.extend_from_slice(&(vaddr + code_off as u64).to_le_bytes()); // e_entry
            out.extend_from_slice(&(ehsize as u64).to_le_bytes()); // e_phoff
            out.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        } else {
            out.extend_from_slice(&((vaddr + code_off as u64) as u32).to_le_bytes());
            out.extend_from_slice(&(ehsize as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        out.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        out.extend_from_slice(&(ehsize as u16).to_le_bytes());
        out.extend_from_slice(&(phentsize as u16).to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        out.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        assert_eq!(out.len(), ehsize);
        // One PT_LOAD, PF_R | PF_X.
        if is64 {
            out.extend_from_slice(&1u32.to_le_bytes()); // p_type
            out.extend_from_slice(&5u32.to_le_bytes()); // p_flags
            out.extend_from_slice(&0u64.to_le_bytes()); // p_offset
            out.extend_from_slice(&vaddr.to_le_bytes()); // p_vaddr
            out.extend_from_slice(&vaddr.to_le_bytes()); // p_paddr
            out.extend_from_slice(&filesz.to_le_bytes()); // p_filesz
            out.extend_from_slice(&filesz.to_le_bytes()); // p_memsz
            out.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
        } else {
            out.extend_from_slice(&1u32.to_le_bytes()); // p_type
            out.extend_from_slice(&0u32.to_le_bytes()); // p_offset
            out.extend_from_slice(&(vaddr as u32).to_le_bytes()); // p_vaddr
            out.extend_from_slice(&(vaddr as u32).to_le_bytes()); // p_paddr
            out.extend_from_slice(&(filesz as u32).to_le_bytes()); // p_filesz
            out.extend_from_slice(&(filesz as u32).to_le_bytes()); // p_memsz
            out.extend_from_slice(&5u32.to_le_bytes()); // p_flags
            out.extend_from_slice(&0x1000u32.to_le_bytes()); // p_align
        }
        assert_eq!(out.len(), code_off);
        out.extend_from_slice(code);
        out
    }

    // ---- CORE-01 ---------------------------------------------------------

    #[test]
    fn unknown_e_machine_is_refused_naming_the_machine() {
        // ROPgadget 7.7 on the same input: "[Error] ELF.getArch() -
        // Architecture not supported", exit 1, zero gadgets. rop-finder must
        // refuse too, rather than decoding foreign machine code as x86.
        for class in [1u8, 2u8] {
            let bytes = synth_elf(class, 0x9999, &[0x58, 0xc3, 0x5d, 0xc3]);
            let err = ElfBinary::parse(&bytes).expect_err("must refuse e_machine 0x9999");
            assert!(
                matches!(err, Error::UnsupportedArch { machine: 0x9999 }),
                "expected UnsupportedArch, got {err:?}"
            );
            let msg = err.to_string();
            assert!(
                msg.contains("0x9999") && msg.contains("39321"),
                "message must name the machine type: {msg}"
            );
            // And the whole dispatch path refuses, not just the ELF loader.
            assert!(Binary::load(&bytes).is_err());
            assert!(Binary::parse(&bytes).is_err());
        }
    }

    #[test]
    fn unknown_e_machine_refused_for_a_sample_of_real_unsupported_machines() {
        // s390x (22), SuperH (42), m68k (4), Hexagon (164), LoongArch (258).
        for machine in [22u16, 42, 4, 164, 258] {
            let bytes = synth_elf(2, machine, &[0x58, 0xc3]);
            let err = ElfBinary::parse(&bytes).expect_err("must refuse");
            assert!(
                matches!(err, Error::UnsupportedArch { machine: m } if m == u64::from(machine)),
                "e_machine {machine}: {err:?}"
            );
        }
    }

    #[test]
    fn known_e_machine_still_parses() {
        // The control for the refusal test: EM_X86_64 with the same shape.
        let bytes = synth_elf(2, goblin::elf::header::EM_X86_64, &[0x58, 0xc3]);
        let bin = ElfBinary::parse(&bytes).expect("EM_X86_64 must parse");
        assert_eq!(bin.arch().unwrap(), crate::Arch::X64);
        assert!(bin.mode_divergence().is_none());
    }

    // ---- CORE-07 ---------------------------------------------------------

    #[test]
    fn x32_abi_reports_a_mode_divergence_from_the_oracle() {
        // ELFCLASS32 + EM_X86_64 = the x32 ABI. rop-finder decodes 64-bit
        // (the instruction encodings really are x86-64); ROPgadget's
        // getArchMode() reads EI_CLASS and decodes 32-bit.
        let bytes = synth_elf(1, goblin::elf::header::EM_X86_64, &[0x58, 0xc3]);
        let bin = ElfBinary::parse(&bytes).expect("x32 ELF must parse");
        assert_eq!(bin.arch().unwrap(), crate::Arch::X64);
        let d = bin.mode_divergence().expect("x32 must report a divergence");
        assert_eq!(d.rf_bits, 64);
        assert_eq!(d.oracle_bits, 32);
        assert_eq!(d.class, ElfClass::Bit32);
        assert_eq!(d.machine, goblin::elf::header::EM_X86_64);
    }

    #[test]
    fn mirror_case_elfclass64_em_386_also_diverges() {
        let bytes = synth_elf(2, goblin::elf::header::EM_386, &[0x58, 0xc3]);
        let bin = ElfBinary::parse(&bytes).expect("must parse");
        let d = bin.mode_divergence().expect("must report a divergence");
        assert_eq!((d.rf_bits, d.oracle_bits), (32, 64));
    }

    #[test]
    fn real_fixtures_report_no_mode_divergence() {
        for name in [
            "elf-x64-bash-v4.1.5.1",
            "elf-x86-bash-v4.1.5.1",
            "elf-ARM64-bash",
            "elf-Linux-RISCV_32",
            "elf-Linux-RISCV_64",
            "elf-SparcV8-bash",
        ] {
            let bytes = load_fixture(name);
            let bin = ElfBinary::parse(&bytes).unwrap();
            assert!(bin.mode_divergence().is_none(), "{name}");
        }
    }

    // ---- CORE-04 / CORE-06 ----------------------------------------------

    #[test]
    fn section_size_is_the_declared_size_not_the_clamped_byte_count() {
        // elf-SparcV8-bash program header 3: p_offset 0xcbf0c, p_filesz
        // 0x4d4c, p_memsz 0x967c in a 0xd11b0-byte file, so only 0x52a4
        // bytes exist on disk. The oracle reports size = p_memsz and trims
        // --range against vaddr + 0x967c.
        let bytes = load_fixture("elf-SparcV8-bash");
        let bin = ElfBinary::parse(&bytes).unwrap();
        let seg = bin
            .exec_scan_regions()
            .iter()
            .find(|s| s.offset == 0xcbf0c && s.size == 0x967c)
            .expect("the memsz > on-disk segment must be present with its declared size");
        assert_eq!(seg.size, 0x967c);
        assert_eq!(seg.bytes.len(), 0xd11b0 - 0xcbf0c, "bytes clamped to file");
        assert!(seg.size > seg.bytes.len() as u64);
    }

    #[test]
    fn one_enumeration_for_both_segment_views() {
        // CORE-06: elf-x64-bash has PF_X on program headers 0 (PT_PHDR) and
        // 2 (PT_LOAD). Stripped, the section view and the scan regions must
        // agree on name AND extent for every shared entry.
        let mut bytes = load_fixture("elf-x64-bash-v4.1.5.1");
        assert_eq!(bytes[4], 2, "fixture must be ELF64");
        bytes[0x28..0x30].fill(0); // e_shoff
        bytes[0x3c..0x3e].fill(0); // e_shnum
        let bin = ElfBinary::parse(&bytes).unwrap();

        let exec = bin.exec_scan_regions();
        assert_eq!(exec.len(), 2, "PT_PHDR + PT_LOAD carry PF_X");
        assert_eq!(exec[0].name, "PT_LOAD#0(PT_PHDR)");
        assert_eq!(exec[1].name, "PT_LOAD#2");

        // Every scan region is present in the section view with the same
        // name, extent and bytes — this is the property that was false.
        for r in exec {
            let s = bin
                .sections()
                .iter()
                .find(|s| s.name == r.name)
                .unwrap_or_else(|| panic!("{} missing from the section view", r.name));
            assert_eq!(s.offset, r.offset, "{}", r.name);
            assert_eq!(s.size, r.size, "{}", r.name);
            assert_eq!(s.bytes.len(), r.bytes.len(), "{}", r.name);
            assert_eq!(s.vaddr, r.vaddr, "{}", r.name);
        }
        // Names still carry the documented PT_LOAD# prefix so rf-cli's
        // stripped-binary detection keeps working.
        assert!(bin
            .sections()
            .iter()
            .all(|s| s.name.starts_with("PT_LOAD#")));
        // Every name is unique: #n is the program-header table index.
        let mut names: Vec<&str> = bin.sections().iter().map(|s| s.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "PT_LOAD#n names must be unique");
    }

    #[test]
    fn stripped_section_view_and_scan_regions_agree_on_every_elf_fixture() {
        for entry in std::fs::read_dir(fixture_path("")).unwrap() {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            if bytes.len() < 4 || &bytes[..4] != b"\x7fELF" {
                continue;
            }
            let Ok(bin) = ElfBinary::parse(&bytes) else {
                continue;
            };
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            // The scan regions are always cut from the segment view, so they
            // are a subset of the stripped section view by construction.
            let stripped = {
                let elf = goblin::elf::Elf::parse(&bytes).unwrap();
                segments_view(&elf, &bytes).unwrap()
            };
            for r in bin.exec_scan_regions() {
                let s = stripped
                    .iter()
                    .find(|s| s.name == r.name)
                    .unwrap_or_else(|| panic!("{name}: {} missing", r.name));
                assert_eq!((s.offset, s.size), (r.offset, r.size), "{name} {}", r.name);
            }
        }
    }

    // ---- ROB-02 ----------------------------------------------------------

    #[test]
    fn cloned_elf_section_headers_do_not_amplify_allocation() {
        // The ELF half of ROB-02: a section table whose entries all point at
        // the same big .text. Load must either fail cleanly or materialise
        // bytes proportional to the file, never N copies.
        const CLONES: usize = 4000;
        let base = load_fixture("elf-x64-bash-v4.1.5.1");
        let elf = goblin::elf::Elf::parse(&base).unwrap();
        let text = elf
            .section_headers
            .iter()
            .find(|s| elf.shdr_strtab.get_at(s.sh_name) == Some(".text"))
            .expect(".text")
            .clone();
        let shstrtab = elf.section_headers[elf.header.e_shstrndx as usize].clone();
        let shentsize = elf.header.e_shentsize as usize;
        assert_eq!(shentsize, 64, "ELF64 section header");

        let shdr = |sh: &goblin::elf::SectionHeader| {
            let mut e = vec![0u8; shentsize];
            e[0..4].copy_from_slice(&(sh.sh_name as u32).to_le_bytes());
            e[4..8].copy_from_slice(&sh.sh_type.to_le_bytes());
            e[8..16].copy_from_slice(&sh.sh_flags.to_le_bytes());
            e[16..24].copy_from_slice(&sh.sh_addr.to_le_bytes());
            e[24..32].copy_from_slice(&sh.sh_offset.to_le_bytes());
            e[32..40].copy_from_slice(&sh.sh_size.to_le_bytes());
            e[48..56].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
            e
        };

        let mut bytes = base.clone();
        let shoff = bytes.len() as u64;
        // Section 0 stays the real .shstrtab so e_shstrndx = 0 resolves and
        // every clone's sh_name still reads ".text"; sections 1..=CLONES are
        // identical copies of the .text header.
        bytes.extend_from_slice(&shdr(&shstrtab));
        let clone_entry = shdr(&text);
        for _ in 0..CLONES {
            bytes.extend_from_slice(&clone_entry);
        }
        bytes[0x28..0x30].copy_from_slice(&shoff.to_le_bytes()); // e_shoff
        bytes[0x3c..0x3e].copy_from_slice(&((CLONES + 1) as u16).to_le_bytes()); // e_shnum
        bytes[0x3e..0x40].copy_from_slice(&0u16.to_le_bytes()); // e_shstrndx

        let file_len = bytes.len();
        let naive = text.sh_size * CLONES as u64;
        assert!(
            naive > 100 * file_len as u64,
            "the attack must be a real amplification: {naive} vs {file_len}"
        );

        let bin = ElfBinary::parse(&bytes).expect("the crafted ELF must actually load");
        assert_eq!(bin.sections().len(), CLONES + 1, "all headers are reported");
        assert!(
            bin.sections().iter().filter(|s| s.name == ".text").count() == CLONES,
            "every clone is present as a section"
        );
        let materialised: usize = bin.sections().iter().map(|s| s.bytes.len()).sum::<usize>()
            + bin
                .exec_scan_regions()
                .iter()
                .map(|s| s.bytes.len())
                .sum::<usize>();
        assert!(
            materialised <= 4 * file_len,
            "materialised {materialised} bytes from a {file_len}-byte file              ({CLONES} cloned headers); naive cost would be {naive}"
        );
        // The content is not lost, just not copied 4000 times.
        assert!(
            bin.sections()
                .iter()
                .any(|s| s.name == ".text" && s.bytes.len() as u64 == text.sh_size),
            ".text content is still materialised once"
        );
    }

    // ---- pre-existing coverage ------------------------------------------

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
            // Declared size is never less than what the file holds.
            assert!(s.size >= s.bytes.len() as u64);
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
    fn every_elf_fixture_still_loads() {
        let mut seen = 0;
        for entry in std::fs::read_dir(fixture_path("")).unwrap() {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            if bytes.len() < 4 || &bytes[..4] != b"\x7fELF" {
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let bin = ElfBinary::parse(&bytes)
                .unwrap_or_else(|e| panic!("{name} must still load, got {e}"));
            assert!(!bin.exec_scan_regions().is_empty(), "{name}");
            // ROB-02's de-overlap must never empty a real region on a
            // well-formed file: every scan region (program headers, so never
            // NOBITS) still holds exactly p_memsz clamped to the file. This
            // is what would break if two PF_X headers shared a raw range.
            for s in bin.exec_scan_regions() {
                let start = usize::try_from(s.offset).unwrap_or(usize::MAX);
                let expect = usize::try_from(s.size)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len().saturating_sub(start));
                assert_eq!(s.bytes.len(), expect, "{name} region {}", s.name);
            }
            seen += 1;
        }
        assert!(seen >= 16, "expected the ELF fixture set, saw {seen}");
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
