//! rf-scan — the gadget scanning engine (multi-arch, parallel).
//!
//! Pipeline: memchr-accelerated anchor scan (tables ported from ROPgadget's
//! `gadgets.py`) → clean-decode validity (`total decoded size == end -
//! start`) → passClean port → output dedup by gadget text
//! (first-occurrence-wins in deterministic traversal order: section → table
//! (ROP/JOP/SYS) → anchor pattern → anchor-hit offset → depth, decided by
//! the [`trie`] index) → post-dedup filters (`--only`, `--badbytes`) →
//! alphabetical sort. `--range` truncates sections pre-scan; `--offset`
//! slides vaddrs at emission without affecting disassembly.
//!
//! Dispatch (`scan_binary` over `impl rf_core::Image`): x86/x64 → iced-x86
//! ([`x86`]); all other architectures → capstone ([`cs`]). Scanning runs
//! over slices of each anchor's hit list — overlapping byte ranges of the
//! region — optionally under rayon with deterministic output
//! (`ScanOptions::parallel`).
//!
//! The "per-start decode cache" this crate was once described by is gone
//! (PERF-03): it had a 0.8% hit rate and cost more than the decodes it
//! avoided. On the fixed-width architectures a single resumable region
//! decode ([`cs::RegionIndex`]) replaces it and answers each candidate with
//! an array lookup; on x86/x64 each candidate is simply decoded, over
//! exactly its own bytes.
//!
//! # Getting started
//!
//! [`scan_binary`] takes anything that implements [`rf_core::Image`] and a
//! [`ScanOptions`], and hands back the finished listing: deduplicated,
//! filtered and sorted the way ROPgadget sorts it.
//!
//! ```
//! use rf_core::{Arch, Endianness, RawBinary};
//! use rf_scan::{scan_binary, ScanOptions};
//!
//! // A real caller loads a file with `rf_core::Binary::load`. These bytes
//! // are `xor eax, eax ; ret` followed by `pop rdi ; ret`.
//! let image = RawBinary::new(&[0x31, 0xc0, 0xc3, 0x5f, 0xc3], Arch::X64, Endianness::Little);
//!
//! let opts = ScanOptions {
//!     depth: 4,
//!     ..ScanOptions::default()
//! };
//! let gadgets = scan_binary(&image, &opts)?;
//!
//! let texts: Vec<String> = gadgets.iter().map(|g| g.text()).collect();
//! assert!(texts.iter().any(|t| t == "pop rdi ; ret"));
//! assert!(texts.iter().any(|t| t == "xor eax, eax ; ret"));
//! // The listing is sorted and deduplicated.
//! let mut sorted = texts.clone();
//! sorted.sort();
//! assert_eq!(texts, sorted);
//! # Ok::<(), rf_core::Error>(())
//! ```
//!
//! ## Filtering
//!
//! Filters are engine options, not a post-pass over the listing, because
//! several of them (`align`, `cfg_aware`) change which candidate starts are
//! generated at all:
//!
//! ```
//! use rf_core::{Arch, Endianness, RawBinary};
//! use rf_scan::{scan_binary, ScanOptions};
//!
//! let image = RawBinary::new(&[0x31, 0xc0, 0xc3, 0x5f, 0xc3], Arch::X64, Endianness::Little);
//! let opts = ScanOptions {
//!     depth: 4,
//!     // ROPgadget `--only`: every mnemonic must be in this set.
//!     only: Some(["pop".to_string(), "ret".to_string()].into_iter().collect()),
//!     ..ScanOptions::default()
//! };
//! let texts: Vec<String> = scan_binary(&image, &opts)?.iter().map(|g| g.text()).collect();
//! // `xor eax, eax ; ret` is gone: `xor` is not in the set.
//! assert_eq!(texts, vec!["pop rdi ; ret".to_string(), "ret".to_string()]);
//! # Ok::<(), rf_core::Error>(())
//! ```
//!
//! ## Bounding and cancelling a scan
//!
//! [`scan_binary`] is unbounded and uncancellable by construction — it
//! resets the budget fields before it runs, so no caller can be surprised
//! by one. To bound a scan, use [`scan_bounded`]; to stop one from another
//! thread, put a [`CancelToken`] in the options and use either
//! [`scan_bounded`] or [`scan_binary_into`], which are the two entry points
//! that observe it.
//!
//! ```
//! use rf_core::{Arch, Endianness, RawBinary};
//! use rf_scan::{scan_bounded, CancelToken, Error, ScanOptions};
//!
//! let image = RawBinary::new(&[0x31, 0xc0, 0xc3, 0x5f, 0xc3], Arch::X64, Endianness::Little);
//! let cancel = CancelToken::new();
//! cancel.cancel(); // in practice: from another thread, or on a timeout
//! let opts = ScanOptions {
//!     depth: 4,
//!     cancel,
//!     max_gadgets: Some(1_000_000),
//!     ..ScanOptions::default()
//! };
//! assert!(matches!(scan_bounded(&image, &opts), Err(Error::Cancelled)));
//! ```
//!
//! ## Streaming
//!
//! For a listing too large to hold, implement [`GadgetSink`] and call
//! [`scan_binary_into`], which never builds a `Vec`. The stream is in raw
//! traversal order: run [`post_process`] over what you collected if you
//! want the deduplicated, sorted listing.
//!
//! # Semver policy
//!
//! Covered by semver from 1.0: the signatures of [`scan_binary`],
//! [`scan_binary_into`], [`scan_bounded`], [`post_process`] and
//! [`scan_section`]; the [`GadgetSink`] trait; and the fields of
//! [`ScanOptions`] and [`Gadget`].
//!
//! **Not** covered, and free to change in a patch release: **the exact
//! disassembly text** in [`Gadget::insns`] and [`Gadget::text`] — it is
//! whatever iced-x86 and the linked capstone print, both of which drift
//! between releases, which is why `tests/parity.py` re-measures it rather
//! than asserting it; which gadgets a given binary yields (a decode fix
//! changes the set, and that is the point of a fix); and the text of any
//! [`Error`]. Adding a field to [`ScanOptions`] is a minor release, so
//! construct it with `..ScanOptions::default()` rather than exhaustively.
//! Pin `rf-scan = "1"`.
//!
//! See `docs/API-STABILITY.md` in the repository for the workspace-wide
//! statement.

#![forbid(unsafe_code)]
// ENG-08: every public item carries documentation.
#![warn(missing_docs)]

pub mod anchors;
pub mod cancel;
pub mod cs;
pub mod detail;
mod engine;
pub mod sink;
pub mod trie;
pub mod x86;

pub use anchors::TableKind;
pub use cancel::{CancelToken, Error};
pub use detail::{Access, Detailer, InsnDetail, InsnGroups, MemRef, Operand, OperandInfo};
pub use engine::{
    ibt_applicable, is_call_preceded, post_process, scan_binary, scan_binary_into, scan_bounded,
    scan_section, Gadget, ScanOptions, PREV_BYTES,
};
pub use sink::{BoundedSink, GadgetSink, VecSink};
pub use trie::GadgetTrie;

/// The capstone C library this build is linked against, as `"major.minor"`.
///
/// Reported by the library itself at runtime (`cs_version()`, wrapped by
/// capstone-rs as `Capstone::lib_version`), not by the crate version — so
/// it stays true if the pin in Cargo.toml ever moves or a distributor
/// links a system capstone. capstone's C API returns only major and
/// minor: `CS_VERSION_EXTRA` is a compile-time macro that `cs_version()`
/// does not hand back, so there is no patch level to print and none is
/// invented here (CLAIM-10; PLAN.md:262 wants this recorded because
/// disassembly text drifts between capstone releases and that drift is
/// the project's #1 parity risk).
///
/// Only the non-x86 architectures decode through capstone; x86/x64 go
/// through iced-x86, which exposes no runtime version at all.
pub fn capstone_version() -> String {
    let (major, minor) = capstone::Capstone::lib_version();
    format!("{major}.{minor}")
}

#[cfg(test)]
mod tests {
    /// The pinned `capstone = "=0.13.0"` bundles the capstone 5.0 C core;
    /// if a future bump changes what the linked library reports, this
    /// fails and `--version` has to be re-checked rather than silently
    /// printing something new.
    #[test]
    fn capstone_version_is_the_linked_library_version() {
        assert_eq!(super::capstone_version(), "5.0");
    }
}
