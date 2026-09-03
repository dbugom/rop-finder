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

    /// Canonical short name, matching what `lipo -archs` and `otool` print
    /// for a Mach-O slice. This is the spelling `--arch` should accept and
    /// echo back when selecting a fat-Mach-O slice (CORE-03).
    pub fn slice_name(self) -> &'static str {
        use Arch::*;
        match self {
            X86 => "i386",
            X64 => "x86_64",
            Arm => "arm",
            ArmThumb => "thumb",
            Arm64 => "arm64",
            Mips32 => "mips",
            Mips64 => "mips64",
            Ppc32 => "ppc",
            Ppc64 => "ppc64",
            Sparc => "sparc",
            Sparc64 => "sparc64",
            SparcV9 => "sparcv9",
            RiscV32 => "riscv32",
            RiscV64 => "riscv64",
        }
    }

    /// Parse an architecture name for `--arch`. Case-insensitive, and it
    /// accepts the common aliases as well as [`slice_name`](Self::slice_name)
    /// (so `arm64`, `aarch64` and `arm64e` all select the ARM64 slice).
    pub fn from_slice_name(name: &str) -> Option<Arch> {
        use Arch::*;
        let n = name.trim().to_ascii_lowercase();
        Some(match n.as_str() {
            "x86" | "i386" | "i486" | "i586" | "i686" | "x86_32" | "x86-32" => X86,
            "x64" | "x86_64" | "x86-64" | "amd64" | "x86_64h" => X64,
            "arm" | "armv6" | "armv7" | "armv7s" | "armv7k" | "arm32" => Arm,
            "thumb" | "armv7-thumb" | "thumb2" => ArmThumb,
            "arm64" | "aarch64" | "arm64e" | "arm64_32" | "armv8" => Arm64,
            "mips" | "mips32" => Mips32,
            "mips64" => Mips64,
            "ppc" | "powerpc" | "ppc32" => Ppc32,
            "ppc64" | "powerpc64" => Ppc64,
            "sparc" | "sparc32" => Sparc,
            "sparc64" => Sparc64,
            "sparcv9" | "sparc9" => SparcV9,
            "riscv32" | "riscv-32" | "rv32" => RiscV32,
            "riscv64" | "riscv-64" | "rv64" => RiscV64,
            _ => return None,
        })
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
