//! `#[ignore]`d review tool: prints every disagreement between the frozen
//! corpus in `tests/classify-corpus/` and what `rf_classify` currently says,
//! so a human (or the next agent) can audit them one by one instead of
//! reading an aggregate number.
//!
//! ```text
//! cargo test -p rop-finder-classify --test corpus_diff -- --ignored --nocapture
//! ```
//!
//! It writes nothing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rf_core::Arch;
use rf_scan::{Gadget, TableKind};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Record {
    arch: String,
    vaddr: String,
    bytes: String,
    text: String,
    delay_slot: bool,
    truth_primary: String,
    truth_labels: Vec<String>,
    uncertain: bool,
    labels_uncertain: bool,
    why: String,
    stratum: String,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
#[ignore = "review tool: prints corpus/classifier disagreements; run with --ignored --nocapture"]
fn print_disagreements() {
    let dir = repo_root().join("tests/classify-corpus");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().map(|x| x == "jsonl").unwrap_or(false)).then_some(p)
        })
        .collect();
    files.sort();

    let mut primary_diffs = 0usize;
    let mut label_diffs = 0usize;
    let mut n = 0usize;
    for f in files {
        for line in std::fs::read_to_string(&f).unwrap().lines() {
            if line.trim().is_empty() {
                continue;
            }
            let r: Record = serde_json::from_str(line).unwrap();
            n += 1;
            let g = Gadget {
                vaddr: u64::from_str_radix(r.vaddr.trim_start_matches("0x"), 16).unwrap(),
                bytes: (0..r.bytes.len() / 2)
                    .map(|i| u8::from_str_radix(&r.bytes[i * 2..i * 2 + 2], 16).unwrap())
                    .collect(),
                insns: r.text.split(" ; ").map(str::to_string).collect(),
                delay_slot: r.delay_slot,
                prev: None,
                table: TableKind::Rop,
            };
            let arch = Arch::from_slice_name(&r.arch).unwrap();
            let c = rf_classify::classify(&g, arch);
            let pred_labels: BTreeSet<&str> = c.labels.iter().map(|l| l.name()).collect();
            let truth_labels: BTreeSet<&str> = r.truth_labels.iter().map(String::as_str).collect();
            let p_bad = !r.uncertain && c.primary.name() != r.truth_primary;
            let l_bad = !r.labels_uncertain && pred_labels != truth_labels;
            if !p_bad && !l_bad {
                continue;
            }
            if p_bad {
                primary_diffs += 1;
            }
            if l_bad {
                label_diffs += 1;
            }
            println!(
                "\n[{}] {} {} ({}{})\n  {}\n  truth  primary={:<11} labels={:?}\n  model  primary={:<11} labels={:?} regs_written={:?}\n  why: {}",
                r.arch,
                r.vaddr,
                if p_bad { "PRIMARY" } else { "labels" },
                r.stratum,
                if c.low_confidence { ", TEXT PATH" } else { "" },
                r.text,
                r.truth_primary,
                truth_labels,
                c.primary.name(),
                pred_labels,
                c.regs_written,
                r.why
            );
        }
    }
    println!(
        "\n{n} records: {primary_diffs} primary-class disagreements, {label_diffs} label-set disagreements"
    );
}
