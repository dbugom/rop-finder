//! Shared architecture contract between rf-core (loaders) and rf-scan
//! (multi-arch scan engine). Pinned in Phase 1 so the loader workstream and
//! the scanner workstream can proceed independently.
//!
//! The variant set mirrors ROPgadget's architecture support
//! (ropgadget/gadgets.py): x86, x64, ARM (ARM + Thumb), ARM64, MIPS,
//! PowerPC, SPARC, RISC-V — 32/64-bit and endianness variants where
//! ROPgadget distinguishes them.

/// Target architecture + mode of a loaded binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    X86,
    X64,
    Arm,
    ArmThumb,
    Arm64,
    Mips32,
    Mips64,
    Ppc32,
    Ppc64,
    Sparc,
    Sparc64,
    SparcV9,
    RiscV32,
    RiscV64,
}

impl Arch {
    /// Address width in bytes (4 or 8). Used by bad-byte address packing.
    pub fn addr_size(self) -> usize {
        use Arch::*;
        match self {
            X64 | Arm64 | Mips64 | Ppc64 | Sparc64 | SparcV9 | RiscV64 => 8,
            _ => 4,
        }
    }

    /// True for x86/x64 — the variable-length ISA scanned with iced-x86.
    pub fn is_x86_family(self) -> bool {
        matches!(self, Arch::X86 | Arch::X64)
    }
}

/// Byte order of the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endianness {
    Little,
    Big,
}

/// Format-agnostic view of a loaded executable image, consumed by rf-scan.
///
/// Every loader (ELF, PE, Mach-O, Universal slice, Raw) implements this.
/// Semantics match ROPgadget:
/// - [`Image::exec_scan_regions`] — the regions the scanner walks (ROPgadget
///   parity: executable *program headers/segments*).
/// - [`Image::exec_sections`] — named executable *sections*, used by the
///   Phase 2 `--section` filter.
pub trait Image {
    fn arch(&self) -> Arch;
    fn endianness(&self) -> Endianness;
    fn addr_size(&self) -> usize {
        self.arch().addr_size()
    }
    /// Preferred load address (PE ImageBase, ELF min PT_LOAD p_vaddr,
    /// Mach-O __TEXT segment vmaddr, Raw 0).
    fn image_base(&self) -> u64;
    fn entry(&self) -> u64;
    /// Named executable sections (for `--section` filtering).
    fn exec_sections(&self) -> Vec<&crate::Section>;
    /// ROPgadget-compatible scan regions actually walked by the scanner.
    fn exec_scan_regions(&self) -> &[crate::Section];
    /// Load-time rebase: shift all vaddrs so the image base becomes
    /// `new_base` (the Phase 2 `--base` feature).
    fn rebase(&mut self, new_base: u64);
}
