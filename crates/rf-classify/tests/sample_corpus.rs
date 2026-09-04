//! The corpus **sampler** (CLS-10, CLS-11).
//!
//! This is the tool that produced the candidate gadgets in
//! `tests/classify-corpus/`. It is `#[ignore]`d, it takes every parameter
//! from the environment, and it writes **nothing**: it prints JSONL to
//! stdout. Running the default test suite therefore cannot modify the source
//! tree, which is half of CLS-11.
//!
//! It is committed so the sampling rule is auditable and re-runnable rather
//! than a sentence in a document. Every corpus record carries the exact
//! invocation that produced it in its `provenance` object.
//!
//! ```text
//! RF_SAMPLE_FIXTURE=elf-x64-bash-v4.1.5.1 RF_SAMPLE_STRIDE=757 \
//!   cargo test -p rop-finder-classify --test sample_corpus -- --ignored --nocapture
//! ```
//!
//! | variable | meaning | default |
//! |---|---|---|
//! | `RF_SAMPLE_FIXTURE` | file name under `tests/fixtures` | required |
//! | `RF_SAMPLE_DEPTH` | `ScanOptions::depth` | 10 |
//! | `RF_SAMPLE_STRIDE` | keep every k-th gadget of the filtered list | 1 |
//! | `RF_SAMPLE_OFFSET` | index of the first kept gadget | 0 |
//! | `RF_SAMPLE_LIMIT` | stop after this many kept gadgets | unlimited |
//! | `RF_SAMPLE_ENDS_INDIRECT` | keep only gadgets whose LAST instruction is a `jmp`/`call`/`bx`/`blx`/`jr`/`jalr`/`bctr`/`blr`-style indirect branch | off |
//! | `RF_SAMPLE_CONTAINS` | keep only gadgets whose text contains this substring | off |
//! | `RF_SAMPLE_MIN_INSNS` | keep only gadgets with at least this many instructions | 0 |
//!
//! The three filters are *textual* (a mnemonic test, a substring test and an
//! instruction count) and are applied to the scanner's own output before
//! striding. They contain no classification logic and never call
//! `rf_classify`, so an enriched stratum is still independent of the thing
//! being measured — but it is not a random sample of a binary either, so
//! class frequencies within one say nothing about how common a class is.
//! The exact filter and stride used for every committed stratum are in
//! `tests/classify-corpus/README.md` and in each record's `provenance`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn env_usize(key: &str, default: usize) -> usize {
    match std::env::var(key) {
        Ok(v) => v
            .trim()
            .parse()
            .unwrap_or_else(|e| panic!("{key}={v}: {e}")),
        Err(_) => default,
    }
}

/// Textual test for "the last instruction is an indirect branch". Purely
/// syntactic: mnemonic in the branch set, and the operand is not a bare
/// immediate. No decoder metadata, no classifier.
fn ends_indirect(insns: &[String]) -> bool {
    let Some(last) = insns.last() else {
        return false;
    };
    let mut it = last.split_whitespace();
    let Some(m) = it.next() else { return false };
    let branchy = matches!(
        m,
        "jmp" | "call" | "bx" | "blx" | "br" | "blr" | "jr" | "jalr" | "bctr" | "bctrl" | "bctrl+"
    ) || m.starts_with("jmp")
        || m.starts_with("call");
    if !branchy {
        return false;
    }
    let rest = last[m.len()..].trim();
    // A bare immediate target (`jmp 0x400340`) is direct; anything else
    // (`jmp rax`, `jmp qword ptr [rdx]`, `blr`, `bx lr`) is indirect.
    !(rest.starts_with("0x") && rest.split_whitespace().count() == 1)
}

fn scan(name: &str, depth: usize) -> (rf_core::Arch, Vec<rf_scan::Gadget>) {
    let path = repo_root().join("tests/fixtures").join(name);
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let loaded = rf_core::Binary::load(&data).unwrap_or_else(|e| panic!("parse {name}: {e}"));
    let opts = rf_scan::ScanOptions {
        depth,
        ..Default::default()
    };
    match &loaded {
        rf_core::LoadedBinary::Elf(b) => (
            rf_core::Image::arch(b),
            rf_scan::scan_binary(b, &opts).unwrap(),
        ),
        rf_core::LoadedBinary::Pe(b) => (
            rf_core::Image::arch(b),
            rf_scan::scan_binary(b, &opts).unwrap(),
        ),
        rf_core::LoadedBinary::MachO(b) => (
            rf_core::Image::arch(b),
            rf_scan::scan_binary(b, &opts).unwrap(),
        ),
        other => panic!("{name}: unsupported container: {other:?}"),
    }
}

#[test]
#[ignore = "sampling tool: writes nothing, prints JSONL to stdout; run with --ignored"]
fn dump_candidates() {
    let name = std::env::var("RF_SAMPLE_FIXTURE")
        .expect("set RF_SAMPLE_FIXTURE to a file name under tests/fixtures");
    let depth = env_usize("RF_SAMPLE_DEPTH", 10);
    let stride = env_usize("RF_SAMPLE_STRIDE", 1).max(1);
    let offset = env_usize("RF_SAMPLE_OFFSET", 0);
    let limit = env_usize("RF_SAMPLE_LIMIT", usize::MAX);
    let want_indirect = std::env::var("RF_SAMPLE_ENDS_INDIRECT").is_ok();
    let contains = std::env::var("RF_SAMPLE_CONTAINS").ok();
    let min_insns = env_usize("RF_SAMPLE_MIN_INSNS", 0);

    let (arch, gadgets) = scan(&name, depth);
    let filtered: Vec<&rf_scan::Gadget> = gadgets
        .iter()
        .filter(|g| !want_indirect || ends_indirect(&g.insns))
        .filter(|g| g.insns.len() >= min_insns)
        .filter(|g| match &contains {
            Some(s) => g.text().contains(s.as_str()),
            None => true,
        })
        .collect();

    eprintln!(
        "fixture={name} arch={} depth={depth} total={} filtered={} stride={stride} offset={offset}",
        arch.slice_name(),
        gadgets.len(),
        filtered.len()
    );

    let mut kept = 0usize;
    for (i, g) in filtered.iter().enumerate() {
        if i < offset || (i - offset) % stride != 0 {
            continue;
        }
        if kept >= limit {
            break;
        }
        kept += 1;
        println!(
            "{}",
            serde_json::json!({
                "fixture": name,
                "arch": arch.slice_name(),
                "depth": depth,
                "index": i,
                "vaddr": format!("0x{:x}", g.vaddr),
                "bytes": g.bytes_hex(),
                "text": g.text(),
                "delay_slot": g.delay_slot,
            })
        );
    }
    eprintln!("kept={kept}");
}
