use thiserror::Error;

/// Errors returned by the binary loader. Never a panic.
#[derive(Debug, Error)]
pub enum Error {
    /// The input could not be parsed as an ELF file.
    #[error("malformed binary: {0}")]
    Malformed(String),

    /// The ELF is well-formed but uses a feature rop-finder does not support
    /// (e.g. an architecture other than x86/x64 for the scanner).
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// The container parsed, but its declared machine type is not one
    /// rop-finder can disassemble (CORE-01).
    ///
    /// The loader REFUSES such a file rather than guessing an architecture:
    /// a guess produces a complete, confident, entirely fabricated gadget
    /// listing. ROPgadget refuses the same input (`loaders/elf.py:336-352`
    /// prints `[Error] ELF.getArch() - Architecture not supported` and
    /// `core.py:33` then aborts with exit 1 and zero gadgets).
    #[error("unsupported architecture: machine type {machine:#x} ({machine}) is not one rop-finder can disassemble; refusing rather than emitting fabricated gadgets")]
    UnsupportedArch { machine: u64 },
}

impl From<goblin::error::Error> for Error {
    fn from(e: goblin::error::Error) -> Self {
        Error::Malformed(e.to_string())
    }
}
