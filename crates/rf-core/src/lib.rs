//! rf-core — binary loading (ELF, PE, Mach-O, Universal, Raw via goblin),
//! the section model, and rebasing.
//!
//! All malformed input produces a structured [`Error`] — the loaders never
//! panic.
//!
//! Section model: names and flags come from each format's section headers
//! (ELF `SHF_EXECINSTR`, PE `IMAGE_SCN_MEM_EXECUTE`, Mach-O instruction
//! attributes). Scan regions mirror ROPgadget's loaders: executable
//! `PT_LOAD` *segments* for ELF, executable *sections* for PE/Mach-O/Raw.

#![forbid(unsafe_code)]

mod arch;
mod binary;
mod elf;
mod error;
mod macho;
mod pe;
mod raw;
mod universal;
mod util;

pub use arch::{Arch, Endianness, Image};
pub use binary::{Binary, Format, LoadedBinary};
pub use elf::{ElfBinary, ElfClass, Section};
pub use error::Error;
pub use macho::MachOBinary;
pub use pe::{PeBinary, PeImport};
pub use raw::RawBinary;
pub use universal::UniversalBinary;
