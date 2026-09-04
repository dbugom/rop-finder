//! The **sampler** for CLS-09's ground-truth verification.
//!
//! This produces the candidate list in `tests/ground-truth/x86-sample.jsonl`.
//! Like `sample_corpus.rs` it is `#[ignore]`d, takes no arguments, writes
//! nothing, and prints JSONL to stdout, so running the default suite cannot
//! modify the source tree.
//!
//! ```text
//! cargo test -p rop-finder-classify --test effect_sample -- --ignored --nocapture \
//!   > crates/rf-classify/tests/ground-truth/x86-sample.jsonl
//! ```
//!
//! # The sampling rule, in full
//!
//! Two fixtures, one per x86 mode:
//!
//! | fixture | arch | bits |
//! |---|---|---|
//! | `tests/fixtures/elf-Linux-x64` | x86-64 | 64 |
//! | `tests/fixtures/elf-Linux-x86` | i386 | 32 |
//!
//! For each, scan with `ScanOptions { depth: 10, ..Default::default() }` —
//! the tool's own default depth — and keep the scanner's own emission order,
//! which is deterministic for a given binary and depth. From that list take
//! every `stride`-th gadget starting at index `SEED % stride`, where
//! `stride = max(1, total / 600)` and `SEED = 0x5eed_c1a9` is a fixed
//! constant written into this file. Stop after `CANDIDATES_PER_FIXTURE`
//! gadgets.
//!
//! Striding rather than sampling with a PRNG is what makes the rule
//! reproducible from the source alone: there is no generator state to record,
//! and re-running this test on the same fixture always yields the same list.
//! The oracle (`tests/ground-truth/oracle_unicorn.py`) then keeps the first
//! 250 per fixture that emulate cleanly, which is the 500-gadget sample the
//! Phase 4 exit criterion names.
//!
//! No field of `rf_classify::Classification` appears in the output: the
//! sample is a list of *gadgets*, and the ground truth for each is derived by
//! executing it, never by asking the code under test.

use std::path::{Path, PathBuf};

/// Fixed, and written down rather than passed in, so the rule is auditable.
const SEED: usize = 0x5eed_c1a9;
const DEPTH: usize = 10;
const CANDIDATES_PER_FIXTURE: usize = 600;

const FIXTURES: &[(&str, u32)] = &[("elf-Linux-x64", 64), ("elf-Linux-x86", 32)];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn scan(name: &str) -> (rf_core::Arch, Vec<rf_scan::Gadget>) {
    let path = repo_root().join("tests/fixtures").join(name);
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let opts = rf_scan::ScanOptions {
        depth: DEPTH,
        ..Default::default()
    };
    match rf_core::Binary::load(&data).unwrap_or_else(|e| panic!("parse {name}: {e}")) {
        rf_core::LoadedBinary::Elf(b) => (
            rf_core::Image::arch(&b),
            rf_scan::scan_binary(&b, &opts).unwrap(),
        ),
        other => panic!("{name}: unsupported container {other:?}"),
    }
}

#[test]
#[ignore = "sampling tool: writes nothing, prints JSONL to stdout; run with --ignored"]
fn dump_sample() {
    for (name, bits) in FIXTURES {
        let (arch, gadgets) = scan(name);
        let total = gadgets.len();
        let stride = (total / CANDIDATES_PER_FIXTURE).max(1);
        let start = SEED % stride;
        eprintln!(
            "fixture={name} arch={} bits={bits} depth={DEPTH} total={total} stride={stride} start={start}",
            arch.slice_name()
        );
        let mut kept = 0usize;
        let mut i = start;
        while i < total && kept < CANDIDATES_PER_FIXTURE {
            let g = &gadgets[i];
            println!(
                "{}",
                serde_json::json!({
                    "fixture": name,
                    "arch": arch.slice_name(),
                    "bits": bits,
                    "index": i,
                    "vaddr": format!("0x{:x}", g.vaddr),
                    "bytes": g.bytes_hex(),
                    "text": g.text(),
                })
            );
            kept += 1;
            i += stride;
        }
        eprintln!("kept={kept}");
    }
}
