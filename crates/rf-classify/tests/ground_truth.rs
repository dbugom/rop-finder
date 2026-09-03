//! CLS-09's exit criterion, as a test that can go red.
//!
//! > Stack delta and clobber set are verified against ground truth on a
//! > 500-gadget sample with zero mismatches; every gadget where the rsp
//! > effect is non-constant reports None rather than a number.
//!
//! `tests/ground-truth/x86-truth.jsonl` is the output of
//! `tests/ground-truth/oracle_unicorn.py`, which EXECUTES each gadget six
//! times under the Unicorn CPU emulator with a different uncontrolled machine
//! state each time and an identical chain payload, and reports what the
//! machine did. No part of that oracle reads, imports or transliterates
//! `rf-classify` — which is the whole difference between this and the
//! self-agreement harness CLAIM-05/CLS-11 recorded.
//!
//! This file re-derives nothing. It rebuilds each sampled gadget from its
//! bytes, classifies it, and compares four things against the recording:
//!
//! * `stack_delta` — including, in both directions, that `None` appears
//!   exactly where the six trials disagreed;
//! * `clobbers` — registers whose final value varied with the uncontrolled
//!   state;
//! * `sets` — registers written to a value the payload decided;
//! * `stack_offset_of` — for every register that ended up holding one of the
//!   payload's marker words, the offset it came from.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rf_core::Arch;
use rf_scan::{Gadget, TableKind};

/// The size of the verified sample, as the exit criterion states it. The
/// oracle keeps 250 gadgets per fixture from a 600-per-fixture deterministic
/// stride; if either number moves, this must move with it deliberately.
const SAMPLE_SIZE: usize = 500;

fn truth_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ground-truth/x86-truth.jsonl")
}

#[derive(Debug)]
struct Truth {
    fixture: String,
    bits: u32,
    vaddr: u64,
    bytes: Vec<u8>,
    text: String,
    stack_delta: Option<i64>,
    sets: Vec<String>,
    clobbers: Vec<String>,
    stack_offsets: BTreeMap<String, i64>,
}

fn load() -> Vec<Truth> {
    let path = truth_path();
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}\nrun tests/ground-truth/oracle_unicorn.py with the venv interpreter that has unicorn", path.display()));
    data.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("truth line is JSON");
            let hex = v["bytes"].as_str().unwrap();
            Truth {
                fixture: v["fixture"].as_str().unwrap().to_string(),
                bits: v["bits"].as_u64().unwrap() as u32,
                vaddr: u64::from_str_radix(
                    v["vaddr"].as_str().unwrap().trim_start_matches("0x"),
                    16,
                )
                .unwrap(),
                bytes: (0..hex.len() / 2)
                    .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
                    .collect(),
                text: v["text"].as_str().unwrap().to_string(),
                stack_delta: v["stack_delta"].as_i64(),
                sets: strings(&v["sets"]),
                clobbers: strings(&v["clobbers"]),
                stack_offsets: v["stack_offsets"]
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| (k.clone(), v.as_i64().unwrap()))
                            .collect()
                    })
                    .unwrap_or_default(),
            }
        })
        .collect()
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| a.iter().map(|s| s.as_str().unwrap().to_string()).collect())
        .unwrap_or_default()
}

fn gadget(t: &Truth) -> Gadget {
    Gadget {
        vaddr: t.vaddr,
        bytes: t.bytes.clone(),
        insns: t.text.split(" ; ").map(str::to_string).collect(),
        delay_slot: false,
        prev: None,
        table: TableKind::Rop,
    }
}

/// The exit criterion.
#[test]
fn stack_delta_and_clobbers_match_emulated_ground_truth() {
    let truth = load();
    assert_eq!(
        truth.len(),
        SAMPLE_SIZE,
        "the recorded sample is not {SAMPLE_SIZE} gadgets"
    );
    let mut per_fixture: BTreeMap<&str, usize> = BTreeMap::new();
    for t in &truth {
        *per_fixture.entry(t.fixture.as_str()).or_default() += 1;
    }
    assert_eq!(
        per_fixture.len(),
        2,
        "the sample must span both x86 modes: {per_fixture:?}"
    );

    let mut mismatches: Vec<String> = Vec::new();
    let mut non_constant = 0usize;
    for t in &truth {
        let arch = if t.bits == 64 { Arch::X64 } else { Arch::X86 };
        let g = gadget(t);
        let c = rf_classify::classify(&g, arch);

        if t.stack_delta.is_none() {
            non_constant += 1;
        }
        if c.stack_delta != t.stack_delta {
            mismatches.push(format!(
                "{:#x} {:?}: stack_delta {:?}, emulator says {:?}",
                t.vaddr, t.text, c.stack_delta, t.stack_delta
            ));
        }
        if c.clobbers != t.clobbers {
            mismatches.push(format!(
                "{:#x} {:?}: clobbers {:?}, emulator says {:?}",
                t.vaddr, t.text, c.clobbers, t.clobbers
            ));
        }
        if c.sets != t.sets {
            mismatches.push(format!(
                "{:#x} {:?}: sets {:?}, emulator says {:?}",
                t.vaddr, t.text, c.sets, t.sets
            ));
        }
        for (reg, off) in &t.stack_offsets {
            if c.stack_offset_of(reg) != Some(*off) {
                mismatches.push(format!(
                    "{:#x} {:?}: {reg} stack offset {:?}, emulator says {off}",
                    t.vaddr,
                    t.text,
                    c.stack_offset_of(reg)
                ));
            }
        }
        // And the other direction: a claimed payload provenance the emulator
        // did not observe. The emulator can only recognise a payload marker in
        // a register it also called `set`, so the check is scoped to those —
        // but within that scope a claim of "rdi came from [rsp+8]" that the
        // marker words contradict is a real defect, and this is what catches
        // it.
        for reg in &t.sets {
            if let Some(off) = c.stack_offset_of(reg) {
                if t.stack_offsets.get(reg) != Some(&off) {
                    mismatches.push(format!(
                        "{:#x} {:?}: claims {reg} <- [rsp+{off}], emulator saw {:?}",
                        t.vaddr,
                        t.text,
                        t.stack_offsets.get(reg)
                    ));
                }
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} mismatches against emulated ground truth over {} gadgets ({} of which have a \
         non-constant rsp effect):\n{}",
        mismatches.len(),
        truth.len(),
        non_constant,
        mismatches
            .iter()
            .take(60)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );

    // The sample has to actually contain the hard case, or "zero mismatches"
    // is a statement about arithmetic the analysis never had to do.
    assert!(
        non_constant > 0,
        "no gadget in the sample has a non-constant rsp effect, so the None path is untested"
    );
    eprintln!(
        "verified {} gadgets, {} with a non-constant rsp effect (expected None)",
        truth.len(),
        non_constant
    );
}

/// The skipped population, stated rather than hidden.
///
/// A verification that quietly drops what it cannot measure is worth very
/// little, so the oracle records why each candidate it declined was declined,
/// and this test makes those counts part of the suite: they cannot drift
/// without someone editing the numbers here on purpose.
#[test]
fn the_skipped_population_is_accounted_for() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ground-truth/x86-truth-stats.json");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("stats file")).expect("JSON");
    assert_eq!(v["verified"].as_u64(), Some(SAMPLE_SIZE as u64));
    assert_eq!(v["candidates_read"].as_u64(), Some(1200));
    assert_eq!(v["trials_per_gadget"].as_u64(), Some(6));

    let by_reason = v["skipped_by_reason"].as_object().expect("reason map");
    let total: u64 = by_reason.values().map(|n| n.as_u64().unwrap()).sum();
    assert_eq!(total, v["skipped"].as_u64().unwrap());
    // Every declined candidate falls into one of exactly four stated
    // categories, and each is a limit of the MEASUREMENT, never a case where
    // the expectation was bent to fit the code:
    //
    //  * `not faithfully emulated` — the gadget contains a syscall/interrupt
    //    gate, a ring-0 instruction, or a non-deterministic reader
    //    (`rdtsc`/`rdrand`/`cpuid`) that a bare CPU with no kernel does not
    //    reproduce;
    //  * `early transfer` — control leaves the gadget before its own
    //    terminator, so running a fixed instruction count measures the branch
    //    target's stack effect, not this gadget's;
    //  * `ret imm16 >= 0x8000` — QEMU sign-extends the immediate where the
    //    Intel SDM, the AMD APM, iced-x86 and Bochs treat it as an unsigned
    //    byte count; the oracle declines to adjudicate rather than record a
    //    number it cannot vouch for;
    //  * `emu_start` — the emulator itself refused the instruction stream.
    let mut names: Vec<&str> = by_reason.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "early transfer",
            "emu_start",
            "not faithfully emulated",
            "ret imm16 >= 0x8000"
        ],
        "a new skip category appeared; it must be understood and documented, not absorbed"
    );
    assert!(
        v["skipped"].as_u64().unwrap() < SAMPLE_SIZE as u64,
        "more candidates were declined than verified"
    );
}
