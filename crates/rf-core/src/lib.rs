//! rf-core — binary loading (ELF, PE, Mach-O, Universal, Raw via goblin),
//! the section model, and rebasing.
//!
//! All malformed input produces a structured [`Error`] — the loaders never
//! panic.
//!
//! **The loader refuses rather than fabricates.** If a container declares a
//! machine type rop-finder cannot disassemble, [`Binary::load`] and the
//! per-format `parse` functions return [`Error::UnsupportedArch`] (ELF) or
//! [`Error::Unsupported`] (PE, Mach-O) instead of guessing an architecture.
//! That is why [`Image::arch`] is infallible: by the time a caller holds an
//! image, its architecture came from the file, never from a fallback.
//!
//! **Declared vs materialised.** [`Section::size`] is the size the file
//! *declares* (`p_memsz`/`sh_size`, `SizeOfRawData`, Mach-O `section.size`),
//! which is what the parity oracle reports and trims `--range` against;
//! [`Section::bytes`] is clamped to what the file actually contains, and the
//! total materialised per view is bounded so a header table cannot multiply
//! a small file into gigabytes of copies.
//!
//! **Mitigations and symbols (ECO-06).** Every loader also reports what a
//! `checksec` run would tell you — [`ElfBinary::mitigations`],
//! [`PeBinary::mitigations`], [`MachOBinary::mitigations`],
//! [`RawBinary::mitigations`] — as `{name: {enabled, evidence, detail}}`
//! where `enabled` is the tri-state [`Enabled`]. A reader that cannot see
//! the deciding bytes answers [`Enabled::Unknown`] with a stated reason
//! rather than defaulting to a boolean. [`ElfBinary::symbols`] adds the
//! `.dynsym`/`.symtab` listing, with the GOT slot (and, where provable, the
//! PLT stub) of every PLT-called import. See the [`mitigations`] module for
//! the report contract and the divergences from `checksec.sh`.
//!
//! Section model: names and flags come from each format's section headers
//! (ELF `SHF_EXECINSTR`, PE `IMAGE_SCN_MEM_EXECUTE`, Mach-O instruction
//! attributes). Scan regions mirror ROPgadget's loaders: executable
//! `PT_LOAD` *segments* for ELF, executable *sections* for PE/Mach-O/Raw.

#![forbid(unsafe_code)]

mod arch;
mod binary;
mod elf;
mod elf_info;
mod error;
mod macho;
mod macho_info;
pub mod mitigations;
mod pe;
mod pe_info;
mod raw;
mod symbols;
mod universal;
mod util;

pub use arch::{Arch, Endianness, Image};
pub use binary::{Binary, Format, LoadedBinary};
pub use elf::{ElfBinary, ElfClass, ModeDivergence, Section};
pub use error::Error;
pub use macho::MachOBinary;
pub use mitigations::{Enabled, Mitigation, Mitigations};
pub use pe::{PeBinary, PeImport};
pub use raw::RawBinary;
pub use symbols::{Symbol, SymbolTable};
pub use universal::{SliceInfo, UniversalBinary};
