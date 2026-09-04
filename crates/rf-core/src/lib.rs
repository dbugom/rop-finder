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
//!
//! # Getting started
//!
//! [`Binary::load`] sniffs the container and hands back a [`LoadedBinary`];
//! every variant's payload implements [`Image`], which is the whole
//! contract [`rf_scan`](https://docs.rs/rf-scan) needs in order to scan it.
//!
//! ```
//! use rf_core::{Arch, Binary, Endianness, Image, LoadedBinary, RawBinary};
//!
//! // A real caller starts from a file:
//! //     let bytes = std::fs::read("/bin/ls")?;
//! //     let loaded = Binary::load(&bytes)?;
//! // A doctest starts from a flat blob, which needs no container at all.
//! // These two bytes are `pop rdi ; ret`.
//! let blob = RawBinary::new(&[0x5f, 0xc3], Arch::X64, Endianness::Little);
//! let loaded = LoadedBinary::Raw(blob);
//!
//! // Format-agnostic questions go through `Image`.
//! let image: &dyn Image = match &loaded {
//!     LoadedBinary::Elf(b) => b,
//!     LoadedBinary::Pe(b) => b,
//!     LoadedBinary::MachO(b) => b,
//!     LoadedBinary::Raw(b) => b,
//!     LoadedBinary::Universal(_) => panic!("pick a slice first"),
//! };
//! assert_eq!(image.arch(), Arch::X64);
//! assert_eq!(image.addr_size(), 8);
//!
//! // The regions a scanner walks. For ELF these are the executable
//! // PT_LOAD segments; for PE/Mach-O/Raw the executable sections.
//! let total: u64 = image.exec_scan_regions().iter().map(|s| s.size).sum();
//! assert_eq!(total, 2);
//! ```
//!
//! # Semver policy
//!
//! Covered by semver from 1.0: the item signatures below, the variants of
//! [`Arch`], [`Format`] and [`LoadedBinary`], the fields of [`Section`],
//! and the [`Image`] trait's method set.
//!
//! **Not** covered, and free to change in a patch release: the exact text
//! of any [`Error`] or [`Mitigation::evidence`] string, the *contents* of a
//! mitigation report for a given file (a better reader may turn an
//! [`Enabled::Unknown`] into a decided answer), the order of
//! [`Mitigations::names`] beyond the guarantee that it is stable within a
//! release, and anything marked `#[doc(hidden)]`. Adding an [`Arch`] or
//! [`Format`] variant is a minor release — match exhaustively at your own
//! risk. Pin `rf-core = "1"`.
//!
//! See `docs/API-STABILITY.md` in the repository for the workspace-wide
//! statement.

#![forbid(unsafe_code)]
// ENG-08: every public item carries documentation. This lint is the gate
// that keeps it that way.
#![warn(missing_docs)]

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
