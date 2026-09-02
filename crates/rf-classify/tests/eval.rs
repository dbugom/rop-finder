//! Evaluation harness for the classification gate (PLAN sec.5.1).
//!
//! Samples >= 1000 real gadgets from the committed fixtures, labels them with
//! an INDEPENDENT rule implementation (written directly against iced-x86
//! metadata, sharing no code with `rf-classify`), and measures per-class
//! precision/recall plus macro-averaged precision on a held-out half.
//!
//! Writes `tests/fixtures-labeled.jsonl` (the labeled sample) and
//! `tests/fixtures-eval.json` (the metrics report) at the repository root.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};

const CLASSES: [&str; 8] = [
    "reg-write",
    "stack-pivot",
    "mem-read",
    "mem-write",
    "arithmetic",
    "syscall",
    "dispatcher",
    "other",
];

// ---------------------------------------------------------------------------
// Independent labeler: a fresh implementation of the TAXONOMY.md decision
// rules, written only against iced metadata. No rf-classify code is reused.
// ---------------------------------------------------------------------------

fn is_sys(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Syscall
            | Mnemonic::Sysenter
            | Mnemonic::Sysexit
            | Mnemonic::Sysret
            | Mnemonic::Int
            | Mnemonic::Int1
            | Mnemonic::Into
    )
}

fn is_terminator(insn: &Instruction) -> bool {
    match insn.flow_control() {
        FlowControl::IndirectBranch
        | FlowControl::IndirectCall
        | FlowControl::Return
        | FlowControl::UnconditionalBranch => true,
        FlowControl::Call => is_sys(insn.mnemonic()),
        _ => false,
    }
}

/// Independent implementation of the R8 dispatcher heuristic: the gadget's
/// final instruction is a register-indirect jump (`jmp [reg]`/`jmp [reg+off]`)
/// or `jmp reg` where an earlier instruction arithmetically modifies `reg`.
fn dispatcher_check(insns: &[Instruction], factory: &mut InstructionInfoFactory) -> bool {
    let Some(last) = insns.last() else {
        return false;
    };
    if last.mnemonic() != Mnemonic::Jmp {
        return false;
    }
    // jmp qword ptr [reg] / [reg+off] — register-indirect.
    if last.op_count() > 0 && last.op_kind(0) == OpKind::Memory {
        let base = last.memory_base();
        return base != Register::None && !matches!(base, Register::RIP | Register::EIP);
    }
    // jmp reg with an earlier arithmetic modification of reg.
    if last.op_count() > 0 && last.op_kind(0) == OpKind::Register {
        let target = last.op_register(0);
        for prev in &insns[..insns.len() - 1] {
            if !matches!(
                prev.mnemonic(),
                Mnemonic::Add
                    | Mnemonic::Sub
                    | Mnemonic::Adc
                    | Mnemonic::Sbb
                    | Mnemonic::Inc
                    | Mnemonic::Dec
                    | Mnemonic::Neg
                    | Mnemonic::Not
                    | Mnemonic::And
                    | Mnemonic::Or
                    | Mnemonic::Xor
                    | Mnemonic::Shl
                    | Mnemonic::Shr
                    | Mnemonic::Sar
                    | Mnemonic::Sal
                    | Mnemonic::Rol
                    | Mnemonic::Ror
                    | Mnemonic::Imul
                    | Mnemonic::Mul
                    | Mnemonic::Lea
                    | Mnemonic::Cmp
                    | Mnemonic::Test
            ) {
                continue;
            }
            let info = factory.info(prev);
            if info.used_registers().iter().any(|u| {
                u.register() == target
                    && matches!(
                        u.access(),
                        OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    )
            }) {
                return true;
            }
        }
    }
    false
}

/// Independent label-set computation for one gadget's bytes.
fn independent_labels(bytes: &[u8], vaddr: u64) -> BTreeSet<&'static str> {
    let mut dec = Decoder::with_ip(64, bytes, vaddr, DecoderOptions::NONE);
    let mut factory = InstructionInfoFactory::new();
    let mut insns: Vec<Instruction> = Vec::new();
    let mut insn = Instruction::default();
    while dec.can_decode() {
        dec.decode_out(&mut insn);
        insns.push(insn);
    }
    let n = insns.len();
    let mut labels = BTreeSet::new();
    for (idx, insn) in insns.iter().enumerate() {
        // R8 dispatcher check applies to the final jump only.
        if idx == n - 1 && dispatcher_check(&insns, &mut factory) {
            labels.insert("dispatcher");
        }
        let m = insn.mnemonic();
        // R10: skip the FINAL control-transfer anchor (syscall gates are
        // payload, exempt per R2) and nops.
        let anchor = idx == n - 1 && is_terminator(insn) && !is_sys(m);
        if anchor || m == Mnemonic::Nop {
            continue;
        }
        let info = factory.info(insn);
        // R1: mnemonics whose rsp effect is chain mechanism.
        let implicit_sp = matches!(
            m,
            Mnemonic::Push
                | Mnemonic::Pop
                | Mnemonic::Pusha
                | Mnemonic::Popa
                | Mnemonic::Call
                | Mnemonic::Ret
                | Mnemonic::Retf
                | Mnemonic::Enter
                | Mnemonic::Leave
                | Mnemonic::Iret
                | Mnemonic::Iretd
                | Mnemonic::Iretq
        );
        let is_sp = |r: Register| matches!(r, Register::SP | Register::ESP | Register::RSP);
        let is_gpr = |r: Register| {
            (r.is_gpr8() || r.is_gpr16() || r.is_gpr32() || r.is_gpr64()) && !is_sp(r)
        };
        let mut mr = false;
        let mut mw = false;
        let mut rw = false;
        let mut pivot = false;
        // R5 explicit pivot forms.
        if m == Mnemonic::Leave {
            pivot = true;
        }
        if m == Mnemonic::Pop
            && insn.op_count() > 0
            && insn.op_kind(0) == OpKind::Register
            && is_sp(insn.op_register(0))
        {
            pivot = true;
        }
        if m == Mnemonic::Xchg
            && ((insn.op_kind(0) == OpKind::Register && is_sp(insn.op_register(0)))
                || (insn.op_count() > 1
                    && insn.op_kind(1) == OpKind::Register
                    && is_sp(insn.op_register(1))))
        {
            pivot = true;
        }
        // Register uses (R1: implicit rsp effects excluded).
        for u in info.used_registers() {
            let r = u.register();
            let writes = matches!(
                u.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            );
            if !writes {
                continue;
            }
            if is_sp(r) {
                // R5: any EXPLICIT rsp/esp write is a pivot (no delta test);
                // R1-implicit effects (push/pop/call/ret) are not.
                if !implicit_sp {
                    pivot = true;
                }
            } else if is_gpr(r) {
                rw = true;
            }
        }
        // Memory uses (R1: stack operands excluded). RMW accesses
        // (ReadWrite / ReadCondWrite) count as BOTH read and write.
        for um in info.used_memory() {
            if is_sp(um.base()) || is_sp(um.segment()) || implicit_sp {
                continue;
            }
            let a = um.access();
            if matches!(
                a,
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            ) {
                mr = true;
            }
            if matches!(
                a,
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                mw = true;
            }
        }
        if mw {
            labels.insert("mem-write");
        }
        // R4: read-modify-write earns BOTH mem-read and mem-write.
        if mr {
            labels.insert("mem-read");
        }
        if pivot {
            labels.insert("stack-pivot");
        }
        if is_sys(m) {
            labels.insert("syscall");
        }
        // R6 arithmetic/logical set.
        if matches!(
            m,
            Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::Adc
                | Mnemonic::Sbb
                | Mnemonic::Inc
                | Mnemonic::Dec
                | Mnemonic::Neg
                | Mnemonic::Not
                | Mnemonic::And
                | Mnemonic::Or
                | Mnemonic::Xor
                | Mnemonic::Shl
                | Mnemonic::Shr
                | Mnemonic::Sar
                | Mnemonic::Sal
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Imul
                | Mnemonic::Mul
                | Mnemonic::Lea
                | Mnemonic::Cmp
                | Mnemonic::Test
        ) {
            labels.insert("arithmetic");
        }
        // R7: writes a GPR, no non-stack memory operand, not a gate.
        if rw && !mr && !mw && !is_sys(m) {
            labels.insert("reg-write");
        }
    }
    labels
}

// ---------------------------------------------------------------------------
// Fixture loading + scanning (minimal copy of rf-cli's pipeline).
// ---------------------------------------------------------------------------

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn scan_fixture(name: &str, depth: usize) -> (rf_core::Arch, Vec<rf_scan::Gadget>) {
    let path = repo_root().join("tests/fixtures").join(name);
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let loaded = rf_core::Binary::load(&data).unwrap_or_else(|e| panic!("parse {name}: {e}"));
    let opts = rf_scan::ScanOptions {
        depth,
        ..Default::default()
    };
    // The concrete binary types implement rf_core::Image directly; scanning
    // them is equivalent to rf-cli's RegionView for a full-binary scan.
    let (arch, gadgets) = match &loaded {
        rf_core::LoadedBinary::Elf(b) => (
            rf_core::Image::arch(b),
            rf_scan::scan_binary(b, &opts).unwrap_or_else(|e| panic!("scan {name}: {e}")),
        ),
        rf_core::LoadedBinary::Pe(b) => (
            rf_core::Image::arch(b),
            rf_scan::scan_binary(b, &opts).unwrap_or_else(|e| panic!("scan {name}: {e}")),
        ),
        rf_core::LoadedBinary::MachO(b) => (
            rf_core::Image::arch(b),
            rf_scan::scan_binary(b, &opts).unwrap_or_else(|e| panic!("scan {name}: {e}")),
        ),
        other => panic!("{name}: unsupported container for eval: {other:?}"),
    };
    (arch, gadgets)
}

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

struct Sample {
    file: String,
    vaddr: u64,
    text: String,
    truth: BTreeSet<&'static str>,
    pred: BTreeSet<String>,
    primary: String,
    split: &'static str, // "dev" or "held-out"
}

#[test]
fn classification_gate() {
    // (fixture, depth, sample every k-th)
    let plan = [
        ("elf-x64-bash-v4.1.5.1", 10usize, 45usize),
        ("pe-x64-cmd-v6.1.7601", 10usize, 40usize),
        ("elf-Linux-x64", 10usize, 10usize),
    ];
    let mut samples: Vec<Sample> = Vec::new();
    for (name, depth, stride) in plan {
        let (arch, gadgets) = scan_fixture(name, depth);
        for (i, g) in gadgets.iter().enumerate() {
            if i % stride != 0 {
                continue;
            }
            let truth = independent_labels(&g.bytes, g.vaddr);
            let c = rf_classify::classify(g, arch);
            let pred: BTreeSet<String> = c.labels.iter().map(|cl| cl.name().to_string()).collect();
            samples.push(Sample {
                file: name.to_string(),
                vaddr: g.vaddr,
                text: g.text(),
                truth,
                pred,
                primary: c.primary.name().to_string(),
                split: if samples.len() % 2 == 0 {
                    "dev"
                } else {
                    "held-out"
                },
            });
        }
    }
    assert!(
        samples.len() >= 1000,
        "need >= 1000 labeled gadgets, got {}",
        samples.len()
    );

    // Confusion accumulation per class, per split.
    let mut tp = [0usize; 8];
    let mut fp = [0usize; 8];
    let mut fn_ = [0usize; 8];
    for s in samples.iter().filter(|s| s.split == "held-out") {
        let truth_other = s.truth.is_empty();
        let pred_other = s.pred.is_empty();
        for (ci, class) in CLASSES.iter().enumerate() {
            let in_truth = if *class == "other" {
                truth_other
            } else {
                s.truth.contains(class)
            };
            let in_pred = if *class == "other" {
                pred_other
            } else {
                s.pred.contains(*class)
            };
            match (in_truth, in_pred) {
                (true, true) => tp[ci] += 1,
                (false, true) => fp[ci] += 1,
                (true, false) => fn_[ci] += 1,
                (false, false) => {}
            }
        }
    }

    let mut report = String::new();
    writeln!(
        report,
        "samples={} held_out={}",
        samples.len(),
        samples.len() / 2
    )
    .unwrap();
    writeln!(
        report,
        "{:<12} {:>6} {:>6} {:>6} {:>8} {:>8}",
        "class", "tp", "fp", "fn", "prec", "rec"
    )
    .unwrap();
    let mut precisions = Vec::new();
    let mut recalls = Vec::new();
    let mut class_metrics = Vec::new();
    for (ci, class) in CLASSES.iter().enumerate() {
        let prec = if tp[ci] + fp[ci] > 0 {
            tp[ci] as f64 / (tp[ci] + fp[ci]) as f64
        } else {
            1.0
        };
        let rec = if tp[ci] + fn_[ci] > 0 {
            tp[ci] as f64 / (tp[ci] + fn_[ci]) as f64
        } else {
            1.0
        };
        precisions.push(prec);
        recalls.push(rec);
        writeln!(
            report,
            "{:<12} {:>6} {:>6} {:>6} {:>8.4} {:>8.4}",
            class, tp[ci], fp[ci], fn_[ci], prec, rec
        )
        .unwrap();
        class_metrics.push(serde_json::json!({
            "class": class, "tp": tp[ci], "fp": fp[ci], "fn": fn_[ci],
            "precision": (prec * 10000.0).round() / 10000.0,
            "recall": (rec * 10000.0).round() / 10000.0,
        }));
    }
    let macro_p: f64 = precisions.iter().sum::<f64>() / precisions.len() as f64;
    let macro_r: f64 = recalls.iter().sum::<f64>() / recalls.len() as f64;
    writeln!(report, "macro-avg precision = {macro_p:.4}").unwrap();
    writeln!(report, "macro-avg recall    = {macro_r:.4}").unwrap();
    eprintln!("\n{report}");

    // Write the labeled sample (jsonl) — this is the committed labeled set.
    let mut jsonl = String::new();
    for s in &samples {
        let truth: Vec<&str> = if s.truth.is_empty() {
            vec!["other"]
        } else {
            s.truth.iter().copied().collect()
        };
        let line = serde_json::json!({
            "file": s.file,
            "vaddr": format!("0x{:x}", s.vaddr),
            "text": s.text,
            "labels": truth,
            "primary": s.primary,
            "split": s.split,
        });
        jsonl.push_str(&serde_json::to_string(&line).unwrap());
        jsonl.push('\n');
    }
    std::fs::write(repo_root().join("tests/fixtures-labeled.jsonl"), jsonl).unwrap();

    // Metrics report.
    let metrics = serde_json::json!({
        "samples": samples.len(),
        "held_out": samples.len() / 2,
        "per_class": class_metrics,
        "macro_precision": (macro_p * 10000.0).round() / 10000.0,
        "macro_recall": (macro_r * 10000.0).round() / 10000.0,
        "gate": "macro_precision >= 0.90",
        "passed": macro_p >= 0.90,
    });
    std::fs::write(
        repo_root().join("tests/fixtures-eval.json"),
        serde_json::to_string_pretty(&metrics).unwrap() + "\n",
    )
    .unwrap();

    // Falsifiable gate from PLAN sec.5.1.
    assert!(
        macro_p >= 0.90,
        "GATE FAILED: held-out macro-avg precision {macro_p:.4} < 0.90\n{report}"
    );
}
