//! rf-scan — the gadget scanning engine (Phase 1a: multi-arch + parallel).
//!
//! Pipeline: memchr-accelerated anchor scan (tables ported from ROPgadget's
//! `gadgets.py`) → per-start decode cache → clean-decode validity
//! (`total decoded size == end - start`) → passClean port → output dedup by
//! gadget text (first-occurrence-wins in deterministic traversal order:
//! section → table (ROP/JOP/SYS) → anchor pattern → anchor-hit offset →
//! depth) → post-dedup filters (`--only`, `--badbytes`) → alphabetical
//! sort. `--range` truncates sections pre-scan; `--offset` slides vaddrs at
//! emission without affecting disassembly.
//!
//! Dispatch (`scan_binary` over `impl rf_core::Image`): x86/x64 → iced-x86
//! ([`x86`]); all other architectures → capstone ([`cs`]). Scanning runs
//! over (region × anchor) work items, optionally under rayon with
//! deterministic output (`ScanOptions::parallel`).

#![forbid(unsafe_code)]

pub mod anchors;
pub mod cancel;
pub mod cs;
mod engine;
pub mod sink;
pub mod x86;

pub use anchors::TableKind;
pub use cancel::{CancelToken, Error};
pub use engine::{
    ibt_applicable, is_call_preceded, post_process, scan_binary, scan_binary_into, scan_bounded,
    scan_section, Gadget, ScanOptions, PREV_BYTES,
};
pub use sink::{BoundedSink, GadgetSink, VecSink};

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
