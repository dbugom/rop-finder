//! rf-scan — the gadget scanning engine (Phase 0: x86/x64 only).
//!
//! Pipeline: memchr-accelerated anchor scan (tables ported from ROPgadget's
//! `gadgets.py`) → per-start decode cache (iced-x86) → clean-decode validity
//! (`total decoded size == end - start`) → `passCleanX86` port → output
//! dedup by gadget text (first-occurrence-wins in deterministic traversal
//! order: section → table (ROP/JOP/SYS) → anchor pattern → anchor-hit offset
//! → depth) → post-dedup filters (`--only`, `--badbytes`) → alphabetical
//! sort. `--range` truncates sections pre-scan; `--offset` slides vaddrs at
//! emission without affecting disassembly.

#![forbid(unsafe_code)]

pub mod anchors;
mod engine;
pub mod x86;

pub use engine::{post_process, scan_binary, scan_section, Gadget, ScanOptions};
