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
pub mod cs;
mod engine;
pub mod x86;

pub use engine::{post_process, scan_binary, scan_section, Gadget, ScanOptions};
