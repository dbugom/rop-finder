//! rf-core — binary loading (ELF via goblin), the section model, and rebasing.
//!
//! Phase 0 scope: ELF32/ELF64, little- and big-endian, parsed with goblin.
//! All malformed input produces a structured [`Error`] — the loader never
//! panics.
//!
//! Section model: names and flags come from the ELF section headers
//! (`executable` = `SHF_EXECINSTR`, `writable` = `SHF_WRITE`). For ELFs
//! without section headers we fall back to executable `PT_LOAD` segments with
//! synthesized names (`PT_LOAD#n`).
//!
//! Note on scan granularity: ROPgadget's ELF loader scans executable
//! `PT_LOAD` *segments*; rop-finder scans `SHF_EXECINSTR` *sections* (with the
//! segment fallback above). See README "Semantic notes".

#![forbid(unsafe_code)]

mod elf;
mod error;

pub use elf::{Binary, ElfBinary, ElfClass, Section};
pub use error::Error;
