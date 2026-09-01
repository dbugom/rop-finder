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
}

impl From<goblin::error::Error> for Error {
    fn from(e: goblin::error::Error) -> Self {
        Error::Malformed(e.to_string())
    }
}
