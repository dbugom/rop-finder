//! Unit tests for the classifier and the ranking function.
//!
//! The fixture-driven tests here are the Phase 3 exit criteria for this
//! workstream; each one fails against the pre-remediation classifier.

use super::*;
use rf_core::{Binary, Image, LoadedBinary};
use rf_scan::{ScanOptions, TableKind};
use std::collections::BTreeMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn gadget(text: &str) -> Gadget {
    Gadget {
        vaddr: 0x1000,
        bytes: Vec::new(),
        insns: text.split(" ; ").map(|s| s.to_string()).collect(),
        delay_slot: false,
        prev: None,
        table: TableKind::Rop,
    }
}

fn x86_gadget(bytes: &[u8], text: &str) -> Gadget {
    Gadget {
        vaddr: 0x401000,
        bytes: bytes.to_vec(),
        insns: text.split(" ; ").map(|s| s.to_string()).collect(),
        delay_slot: false,
        prev: None,
        table: TableKind::Rop,
    }
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn scan_fixture(name: &str, depth: usize) -> (Arch, Vec<Gadget>) {
    let path = fixtures_dir().join(name);
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let opts = ScanOptions {
        depth,
        ..Default::default()
    };
    match Binary::load(&data).unwrap_or_else(|e| panic!("parse {name}: {e}")) {
        LoadedBinary::Elf(b) => (
            Image::arch(&b),
            rf_scan::scan_binary(&b, &opts).unwrap_or_else(|e| panic!("scan {name}: {e}")),
        ),
        other => panic!("{name}: unsupported container {other:?}"),
    }
}

fn classify_all(name: &str, depth: usize) -> (Arch, Vec<Gadget>, Vec<Classification>) {
    let (arch, gs) = scan_fixture(name, depth);
    let c = Classifier::new(arch);
    let cs = gs.iter().map(|g| c.classify(g)).collect();
    (arch, gs, cs)
}

fn class_counts(cs: &[Classification]) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::new();
    for c in cs {
        *m.entry(c.primary.name()).or_insert(0) += 1;
    }
    m
}

/// Sort indices into `gs` by the default (rank) order.
fn ranked(gs: &[Gadget], cs: &[Classification]) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..gs.len()).collect();
    idx.sort_by_key(|&i| rank_key(&cs[i], &gs[i]));
    idx
}

// ---------------------------------------------------------------------------
// CLS-02 — popfq is not a stack pivot
// ---------------------------------------------------------------------------

#[test]
fn popfq_is_not_a_stack_pivot() {
    // 9d c3 = popfq ; ret
    let c = classify(&x86_gadget(b"\x9d\xc3", "popfq ; ret"), Arch::X64);
    assert!(
        !c.labels.contains(&Class::StackPivot),
        "popfq ; ret must not be a stack pivot: {c:?}"
    );
    assert!(
        !c.regs_written.contains(&"rsp".to_string()),
        "popfq's implicit rsp step is not a payload write: {c:?}"
    );
    // 9c c3 = pushfq ; ret — the mirror case.
    let c = classify(&x86_gadget(b"\x9c\xc3", "pushfq ; ret"), Arch::X64);
    assert!(!c.labels.contains(&Class::StackPivot), "{c:?}");
}

#[test]
fn real_pivots_still_fire() {
    // 48 94 c3 = xchg rsp, rax ; ret
    let c = classify(
        &x86_gadget(b"\x48\x94\xc3", "xchg rsp, rax ; ret"),
        Arch::X64,
    );
    assert_eq!(c.primary, Class::StackPivot);
    // 5c c3 = pop rsp ; ret
    let c = classify(&x86_gadget(b"\x5c\xc3", "pop rsp ; ret"), Arch::X64);
    assert_eq!(c.primary, Class::StackPivot);
    // c9 c3 = leave ; ret
    let c = classify(&x86_gadget(b"\xc9\xc3", "leave ; ret"), Arch::X64);
    assert_eq!(c.primary, Class::StackPivot);
    // 48 83 c4 10 c3 = add rsp, 0x10 ; ret
    let c = classify(
        &x86_gadget(b"\x48\x83\xc4\x10\xc3", "add rsp, 0x10 ; ret"),
        Arch::X64,
    );
    assert!(c.labels.contains(&Class::StackPivot), "{c:?}");
}

// ---------------------------------------------------------------------------
// CLS-03 — dispatcher means self-advancing indirect branch
// ---------------------------------------------------------------------------

#[test]
fn bare_indirect_jump_is_not_a_dispatcher() {
    // ff 20 = jmp qword ptr [rax]
    let c = classify(&x86_gadget(b"\xff\x20", "jmp qword ptr [rax]"), Arch::X64);
    assert!(
        !c.dispatcher,
        "a bare jmp [rax] is a functional JOP gadget, not a dispatcher"
    );
    // ff e0 = jmp rax
    let c = classify(&x86_gadget(b"\xff\xe0", "jmp rax"), Arch::X64);
    assert!(!c.dispatcher);
    // 5a ff 22 = pop rdx ; jmp qword ptr [rdx] — loads a fresh pointer, does
    // not advance one.
    let c = classify(
        &x86_gadget(b"\x5a\xff\x22", "pop rdx ; jmp qword ptr [rdx]"),
        Arch::X64,
    );
    assert!(!c.dispatcher, "{c:?}");
}

#[test]
fn self_advancing_indirect_branch_is_a_dispatcher() {
    // 48 83 c2 08 ff 22 = add rdx, 8 ; jmp qword ptr [rdx]  — the canonical
    // JOP dispatcher, which the old rule could not distinguish from jmp [rax].
    let c = classify(
        &x86_gadget(
            b"\x48\x83\xc2\x08\xff\x22",
            "add rdx, 8 ; jmp qword ptr [rdx]",
        ),
        Arch::X64,
    );
    assert!(c.dispatcher, "{c:?}");
    assert!(c.labels.contains(&Class::Dispatcher));
    // 48 83 c0 08 ff e0 = add rax, 8 ; jmp rax
    let c = classify(
        &x86_gadget(b"\x48\x83\xc0\x08\xff\xe0", "add rax, 8 ; jmp rax"),
        Arch::X64,
    );
    assert!(c.dispatcher, "{c:?}");
}

#[test]
fn call_form_dispatcher_is_recognised() {
    // 48 83 c2 08 ff 12 = add rdx, 8 ; call qword ptr [rdx] — the COP form,
    // which the old rule excluded entirely because it only matched Jmp.
    let c = classify(
        &x86_gadget(
            b"\x48\x83\xc2\x08\xff\x12",
            "add rdx, 8 ; call qword ptr [rdx]",
        ),
        Arch::X64,
    );
    assert!(c.dispatcher, "{c:?}");
    assert_eq!(c.terminator(), Terminator::Call);
}

// ---------------------------------------------------------------------------
// CLS-12 — R6's arithmetic set
// ---------------------------------------------------------------------------

#[test]
fn widened_arithmetic_set() {
    let cases: &[(&[u8], &str)] = &[
        (b"\x48\xf7\xf3\xc3", "div rbx ; ret"),
        (b"\x48\xf7\xfb\xc3", "idiv rbx ; ret"),
        (b"\x48\x0f\xc1\xd8\xc3", "xadd rax, rbx ; ret"),
        (b"\x48\x0f\xa3\xd8\xc3", "bt rax, rbx ; ret"),
        (b"\x48\x0f\xc8\xc3", "bswap rax ; ret"),
        (b"\x48\x0f\xa5\xd8\xc3", "shld rax, rbx, cl ; ret"),
        (b"\x48\x87\xd8\xc3", "xchg rax, rbx ; ret"),
    ];
    for (bytes, text) in cases {
        let c = classify(&x86_gadget(bytes, text), Arch::X64);
        assert!(
            c.labels.contains(&Class::Arithmetic),
            "{text} must be arithmetic: {c:?}"
        );
    }
    // `bt` writes only CF, so it used to earn no label at all and land in
    // `other` despite having a real effect.
    let c = classify(
        &x86_gadget(b"\x48\x0f\xa3\xd8\xc3", "bt rax, rbx ; ret"),
        Arch::X64,
    );
    assert_eq!(c.primary, Class::Arithmetic);
}

#[test]
fn flags_only_compares_are_not_arithmetic() {
    // 48 39 d8 c3 = cmp rax, rbx ; ret
    let c = classify(
        &x86_gadget(b"\x48\x39\xd8\xc3", "cmp rax, rbx ; ret"),
        Arch::X64,
    );
    assert!(!c.labels.contains(&Class::Arithmetic), "{c:?}");
    // 48 85 d8 c3 = test rax, rbx ; ret
    let c = classify(
        &x86_gadget(b"\x48\x85\xd8\xc3", "test rax, rbx ; ret"),
        Arch::X64,
    );
    assert!(!c.labels.contains(&Class::Arithmetic), "{c:?}");
}

// ---------------------------------------------------------------------------
// CLS-13 — push-ret and `ret imm16`
// ---------------------------------------------------------------------------

#[test]
fn push_ret_is_labeled() {
    // 50 c3 = push rax ; ret — the classic push-ret gadget, equivalent to
    // `call rax`; it used to be `other` with an empty label set.
    let c = classify(&x86_gadget(b"\x50\xc3", "push rax ; ret"), Arch::X64);
    assert_ne!(c.primary, Class::Other, "{c:?}");
    assert!(c.labels.contains(&Class::MemWrite), "{c:?}");
    assert!(c.regs_read.contains(&"rax".to_string()), "{c:?}");
    assert_eq!(c.side_effects, 1);
}

#[test]
fn ret_imm16_is_a_stack_adjustment() {
    // c2 10 00 = ret 0x10 — the standard stdcall stack adjuster, equivalent
    // to `add rsp, 0x10 ; ret`, which IS stack-pivot.
    let c = classify(&x86_gadget(b"\xc2\x10\x00", "ret 0x10"), Arch::X64);
    assert_eq!(c.primary, Class::StackPivot, "{c:?}");
    assert_eq!(c.terminator(), Terminator::RetImm);
    // A bare `ret` still carries nothing.
    let c = classify(&x86_gadget(b"\xc3", "ret"), Arch::X64);
    assert_eq!(c.primary, Class::Other);
    assert_eq!(c.side_effects, 0);
    assert_eq!(c.terminator(), Terminator::Ret);
}

// ---------------------------------------------------------------------------
// x86 regression set carried over from the original module tests
// ---------------------------------------------------------------------------

#[test]
fn pop_rdi_is_clean_reg_write() {
    let c = classify(&x86_gadget(b"\x5f\xc3", "pop rdi ; ret"), Arch::X64);
    assert_eq!(c.primary, Class::RegWrite);
    assert_eq!(c.labels, vec![Class::RegWrite]);
    assert_eq!(c.regs_written, vec!["rdi"]);
    assert_eq!(c.regs_from_stack, vec!["rdi"]);
    assert!(!c.regs_written.contains(&"rsp".to_string()));
    assert!(!c.regs_read.contains(&"rsp".to_string()));
    assert_eq!(c.side_effects, 1);
    assert_eq!(c.quality, 100);
    assert!(!c.low_confidence);
    assert_eq!(usability(&c, &x86_gadget(b"\x5f\xc3", "pop rdi ; ret")), 3);
}

#[test]
fn mov_store_is_mem_write() {
    let c = classify(
        &x86_gadget(b"\x48\x89\x07\xc3", "mov qword ptr [rdi], rax ; ret"),
        Arch::X64,
    );
    assert_eq!(c.primary, Class::MemWrite);
    assert!(c.regs_read.contains(&"rax".to_string()));
    assert!(c.regs_read.contains(&"rdi".to_string()));
    assert!(!c.labels.contains(&Class::RegWrite));
}

#[test]
fn xor_self_is_regwrite_and_arithmetic() {
    let c = classify(
        &x86_gadget(b"\x48\x31\xc0\xc3", "xor rax, rax ; ret"),
        Arch::X64,
    );
    assert!(c.labels.contains(&Class::RegWrite));
    assert!(c.labels.contains(&Class::Arithmetic));
    assert_eq!(c.primary, Class::Arithmetic);
}

#[test]
fn syscall_is_labeled_even_as_anchor() {
    let c = classify(&x86_gadget(b"\x0f\x05", "syscall"), Arch::X64);
    assert_eq!(c.primary, Class::Syscall);
    assert_eq!(c.terminator(), Terminator::Syscall);
}

#[test]
fn primary_is_last_side_effect() {
    let c = classify(
        &x86_gadget(b"\x58\x48\x01\xd8\xc3", "pop rax ; add rax, rbx ; ret"),
        Arch::X64,
    );
    assert_eq!(c.primary, Class::Arithmetic);
    assert_eq!(c.side_effects, 2);
}

// ---------------------------------------------------------------------------
// CLS-07 — quality, usability, rank
// ---------------------------------------------------------------------------

#[test]
fn quality_no_longer_rewards_doing_nothing() {
    // The defect: side_effects was clamped up to 1, so 0 and 1 scored alike.
    assert_eq!(quality_score(1, 2), 100);
    assert!(
        quality_score(0, 2) < quality_score(1, 2),
        "a gadget with no side effects must not score like one with exactly one"
    );
    assert_eq!(quality_score(0, 2), 85);
    assert_eq!(quality_score(2, 3), 82);
    assert_eq!(quality_score(10, 12), 0);
    // Clobbers cost.
    assert!(quality_score_full(1, 2, 3, 0) < quality_score_full(1, 2, 1, 0));
    // A gadget that needs an attacker-controlled pointer already in a
    // register is worth less than one that does not.
    assert!(quality_score_full(1, 2, 1, 1) < quality_score_full(1, 2, 1, 0));
}

#[test]
fn usability_tiers() {
    let pop = x86_gadget(b"\x5f\xc3", "pop rdi ; ret");
    assert_eq!(usability(&classify(&pop, Arch::X64), &pop), 3);

    let store = x86_gadget(b"\x48\x89\x07\xc3", "mov qword ptr [rdi], rax ; ret");
    assert_eq!(usability(&classify(&store, Arch::X64), &store), 2);

    let retimm = x86_gadget(b"\xc2\x10\x00", "ret 0x10");
    assert_eq!(usability(&classify(&retimm, Arch::X64), &retimm), 1);

    // cb = retf, no side effects at all -> pure control flow.
    let retf = x86_gadget(b"\xcb", "retf");
    assert_eq!(usability(&classify(&retf, Arch::X64), &retf), 0);

    let bare = x86_gadget(b"\xc3", "ret");
    assert_eq!(usability(&classify(&bare, Arch::X64), &bare), 0);

    // f4 c3 = hlt ; ret — privileged.
    let hlt = x86_gadget(b"\xf4\xc3", "hlt ; ret");
    assert_eq!(usability(&classify(&hlt, Arch::X64), &hlt), 0);

    // 50 ff e0 = push rax ; jmp rax — useful class, but a jmp terminator.
    let jop = x86_gadget(b"\x50\xff\xe0", "push rax ; jmp rax");
    assert_eq!(usability(&classify(&jop, Arch::X64), &jop), 1);
}

#[test]
fn rank_key_orders_best_first() {
    let good = x86_gadget(b"\x5f\xc3", "pop rdi ; ret");
    let junk = x86_gadget(b"\xcb", "retf");
    let gk = rank_key(&classify(&good, Arch::X64), &good);
    let jk = rank_key(&classify(&junk, Arch::X64), &junk);
    assert!(
        gk < jk,
        "ascending rank key must be best-first: {gk:?} {jk:?}"
    );
}

/// The headline exit criterion: the default order has to put the gadgets a
/// chain author actually wants at the top. Before this change `pop rdi ; ret`
/// ranked 246th of 16,707 by `sort_by: quality` and three `retf`/`ret imm`
/// gadgets sat in the top 12.
#[test]
fn rank_puts_useful_gadgets_first() {
    let (_, gs, cs) = classify_all("elf-Linux-x64", 4);
    let idx = ranked(&gs, &cs);
    let top: Vec<String> = idx.iter().take(20).map(|&i| gs[i].text()).collect();
    for want in ["pop rdi ; ret", "pop rsi ; ret"] {
        assert!(
            top.iter().any(|t| t == want),
            "`{want}` must be in the top 20 of the default order; got {top:#?}"
        );
    }
    for t in &top {
        assert!(
            !t.contains("retf") && !t.starts_with("ret 0x") && !t.contains("; ret 0x"),
            "no retf / ret imm16 gadget may be in the top 20: {t}"
        );
    }
}

/// Exit criterion: the ranking must actually discriminate. The metric is the
/// (usability, quality) score histogram — the same shape as the "92 % tie at
/// quality 100" measurement in CLS-07 — over the default scan depth.
#[test]
fn no_rank_bucket_holds_more_than_a_quarter() {
    let (_, gs, cs) = classify_all("elf-x64-bash-v4.1.5.1", 10);
    let mut hist: BTreeMap<(u8, i32), usize> = BTreeMap::new();
    for (g, c) in gs.iter().zip(&cs) {
        *hist.entry((usability(c, g), c.quality)).or_insert(0) += 1;
    }
    let total = gs.len();
    let (bucket, n) = hist.iter().max_by_key(|(_, n)| **n).unwrap();
    let pct = 100.0 * *n as f64 / total as f64;
    assert!(
        pct <= 25.0,
        "largest (usability, quality) bucket {bucket:?} holds {n}/{total} = {pct:.2}% \
         (limit 25%); full histogram: {hist:?}"
    );
}

// ---------------------------------------------------------------------------
// CLS-04 — the non-x86 taxonomy no longer collapses to one class
// ---------------------------------------------------------------------------

#[test]
fn non_x86_fixtures_populate_at_least_four_classes() {
    for (name, depth) in [
        ("elf-Mips-Defcon-20-pwn100", 4usize),
        ("elf-PowerPC-bash", 4),
        ("elf-PPC64-bash", 4),
        ("elf-Linux-RISCV_64", 6),
        ("elf-Linux-RISCV_32", 6),
        ("elf-ARM64-bash", 4),
        ("elf-ARMv7-ls", 4),
        ("elf-SparcV8-bash", 4),
    ] {
        let (arch, _, cs) = classify_all(name, depth);
        let counts = class_counts(&cs);
        assert!(
            counts.len() >= 4,
            "{name} ({arch:?}): only {} distinct classes: {counts:?}",
            counts.len()
        );
        assert!(
            !cs.iter().any(|c| c.low_confidence),
            "{name}: capstone detail metadata must be available for every gadget"
        );
    }
}

/// The specific collapse CLS-04 reports: on the MIPS fixture the entire
/// binary contained zero mem-read, zero mem-write and zero stack-pivot.
#[test]
fn load_store_architectures_report_memory_and_pivots() {
    for name in [
        "elf-Mips-Defcon-20-pwn100",
        "elf-PowerPC-bash",
        "elf-PPC64-bash",
        "elf-ARM64-bash",
        "elf-SparcV8-bash",
    ] {
        let (_, _, cs) = classify_all(name, 4);
        let counts = class_counts(&cs);
        for want in ["mem-read", "mem-write"] {
            assert!(
                counts.get(want).copied().unwrap_or(0) > 0,
                "{name}: zero `{want}` gadgets in the whole binary: {counts:?}"
            );
        }
        let pivots = cs
            .iter()
            .filter(|c| c.labels.contains(&Class::StackPivot))
            .count();
        assert!(pivots > 0, "{name}: zero stack-pivot labels: {counts:?}");
    }
}

// ---------------------------------------------------------------------------
// CLS-05 — regs_written is register names, not operand debris
// ---------------------------------------------------------------------------

/// The exit-criterion grammar, as written in docs/REMEDIATION.md:
/// `^(r[0-9]+|x[0-9]+|w[0-9]+|e?[a-z]{2}|sp|lr|pc|fp|ip|sl|sb)$`.
fn matches_arm_register_grammar(t: &str) -> bool {
    let numbered = |p: char| {
        t.strip_prefix(p)
            .is_some_and(|r| !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit()))
    };
    let two_letters = |s: &str| s.len() == 2 && s.bytes().all(|c| c.is_ascii_lowercase());
    numbered('r')
        || numbered('x')
        || numbered('w')
        || matches!(t, "sp" | "lr" | "pc" | "fp" | "ip" | "sl" | "sb")
        || two_letters(t)
        || t.strip_prefix('e').is_some_and(two_letters)
}

/// No token may begin with `{`, `#` or `[` on ANY fixture — that half of the
/// criterion is architecture-independent, and it is the half that was broken
/// (`{r4`, `#0x12e44` on ARM; bare immediates such as `0xad5a0` on SPARC and
/// `8` on PowerPC).
#[test]
fn regs_written_contains_no_operand_debris() {
    let fixtures = [
        ("elf-ARMv7-ls", 4usize),
        ("elf-ARM64-bash", 4),
        ("elf-Mips-Defcon-20-pwn100", 4),
        ("elf-PowerPC-bash", 4),
        ("elf-PPC64-bash", 4),
        ("elf-SparcV8-bash", 4),
        ("elf-Linux-RISCV_32", 6),
        ("elf-Linux-RISCV_64", 6),
        ("elf-Linux-x64", 4),
        ("elf-Linux-x86", 4),
    ];
    let mut violations: Vec<String> = Vec::new();
    for (name, depth) in fixtures {
        let (_, _, cs) = classify_all(name, depth);
        for c in &cs {
            for t in c.regs_written.iter().chain(c.regs_read.iter()) {
                let bad = t.is_empty()
                    || t.starts_with('{')
                    || t.starts_with('#')
                    || t.starts_with('[')
                    || t.starts_with('$')
                    || t.starts_with('%')
                    || t.starts_with(|c: char| c.is_ascii_digit())
                    || !t
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
                if bad && violations.len() < 20 {
                    violations.push(format!("{name}: {t:?}"));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "register-name violations: {violations:?}"
    );
}

/// The ARM/ARM64 fixtures additionally satisfy the literal grammar from the
/// exit criterion. (It is not stated for x86-64, where it cannot hold: `rax`
/// matches none of its alternatives.)
#[test]
fn arm_regs_written_match_the_documented_grammar() {
    for name in ["elf-ARMv7-ls", "elf-ARM64-bash"] {
        let (_, _, cs) = classify_all(name, 4);
        let mut bad: Vec<String> = Vec::new();
        for c in &cs {
            for t in &c.regs_written {
                if !matches_arm_register_grammar(t) && bad.len() < 20 {
                    bad.push(t.clone());
                }
            }
        }
        assert!(bad.is_empty(), "{name}: non-register tokens {bad:?}");
    }
}

// ---------------------------------------------------------------------------
// text fallback (R13) — the same two bugs, in the path that has no metadata
// ---------------------------------------------------------------------------

#[test]
fn text_path_rejects_operand_debris() {
    use crate::text::{register_token, register_tokens};
    assert_eq!(register_token("{r4"), Some("r4".to_string()));
    assert_eq!(register_token("pc}"), Some("pc".to_string()));
    assert_eq!(register_token("r7}!"), Some("r7".to_string()));
    assert_eq!(register_token("#0x12e44"), None);
    assert_eq!(register_token("[r0]"), None);
    assert_eq!(register_token("0xad5a0"), None);
    assert_eq!(register_token("8"), None);
    assert_eq!(register_token("$t6"), Some("t6".to_string()));
    assert_eq!(register_token("%o0"), Some("o0".to_string()));
    assert_eq!(
        register_tokens("{r4-r7, lr}"),
        vec!["r4", "r5", "r6", "r7", "lr"]
    );
}

#[test]
fn text_path_sees_off_reg_memory() {
    use crate::text::memory_shape;
    assert_eq!(memory_shape("$v0, 0x10($sp)"), Some(Some("sp".to_string())));
    assert_eq!(memory_shape("r3, 8(r31)"), Some(Some("r31".to_string())));
    assert_eq!(memory_shape("x0, [x1, #8]"), Some(Some("x1".to_string())));
    assert_eq!(memory_shape("x0, x1"), None);
}

#[test]
fn text_path_knows_conditional_branches() {
    use crate::text::is_branch_mnemonic;
    for m in [
        "bhi", "bne", "beq", "blezl", "b.eq", "cbz", "cbnz", "tbz", "tbnz",
    ] {
        assert!(is_branch_mnemonic(m), "{m} must be a branch");
    }
    for m in ["bic", "bfi", "bswap", "add"] {
        assert!(!is_branch_mnemonic(m), "{m} must not be a branch");
    }
}

#[test]
fn text_path_still_classifies_without_metadata() {
    // Empty `bytes` means no capstone mode can reproduce the text, so this
    // exercises the fallback.
    let c = classify(&gadget("mov x0, x1 ; ret"), Arch::Arm64);
    assert!(c.low_confidence);
    assert_eq!(c.primary, Class::RegWrite);
    let c = classify(&gadget("ldr x0, [x1] ; ret"), Arch::Arm64);
    assert_eq!(c.primary, Class::MemRead);
    let c = classify(&gadget("svc #0 ; ret"), Arch::Arm64);
    assert_eq!(c.primary, Class::Syscall);
    let c = classify(&gadget("add sp, sp, #0x20 ; ret"), Arch::Arm64);
    assert!(c.labels.contains(&Class::StackPivot));
    // CLS-04's MIPS stack adjustment, which matched none of the old patterns.
    let c = classify(&gadget("addiu $sp, $sp, 0x38 ; jr $ra ; nop"), Arch::Mips32);
    assert!(c.labels.contains(&Class::StackPivot), "{c:?}");
    // CLS-05's two junk tokens must not appear.
    let c = classify(&gadget("pop {r4, r5, pc}"), Arch::Arm);
    assert!(
        c.regs_written.iter().all(|r| !r.starts_with('{')),
        "{:?}",
        c.regs_written
    );
    let c = classify(&gadget("bhi #0x12e44 ; bx lr"), Arch::Arm);
    assert!(
        c.regs_written.is_empty(),
        "a conditional branch writes no register: {:?}",
        c.regs_written
    );
}

// ---------------------------------------------------------------------------
// metadata path spot checks (ECO-05)
// ---------------------------------------------------------------------------

#[test]
fn capstone_metadata_populates_registers() {
    // mov x0, x1 ; ret  (ARM64, LE)
    let g = Gadget {
        vaddr: 0x4000,
        bytes: vec![0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6],
        insns: vec!["mov x0, x1".into(), "ret".into()],
        delay_slot: false,
        prev: None,
        table: TableKind::Rop,
    };
    let c = classify(&g, Arch::Arm64);
    assert!(!c.low_confidence, "ECO-05: metadata must be available");
    assert_eq!(c.regs_written, vec!["x0"]);
    assert!(c.regs_read.contains(&"x1".to_string()));
    assert_eq!(c.primary, Class::RegWrite);
    assert_eq!(c.terminator(), Terminator::Ret);

    // lw $v0, 0x10($sp) ; jr $ra ; nop  (MIPS32, BE) — a stack load.
    let g = Gadget {
        vaddr: 0x400000,
        bytes: vec![
            0x8f, 0xa2, 0x00, 0x10, 0x03, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        ],
        insns: vec!["lw $v0, 0x10($sp)".into(), "jr $ra".into(), "nop".into()],
        delay_slot: true,
        prev: None,
        table: TableKind::Rop,
    };
    let c = classify(&g, Arch::Mips32);
    assert!(!c.low_confidence);
    assert_eq!(c.regs_written, vec!["v0"]);
    assert_eq!(c.regs_from_stack, vec!["v0"]);
    assert_eq!(c.primary, Class::RegWrite);
    assert_eq!(c.terminator(), Terminator::Ret);
    assert_eq!(usability(&c, &g), 3);
}

#[test]
fn classifier_is_reusable_and_reports_metadata_availability() {
    let c = Classifier::new(Arch::Mips32);
    assert!(c.has_metadata());
    assert!(Classifier::new(Arch::X64).has_metadata());
}

// ---------------------------------------------------------------------------
// CLS-09: stack delta, register transfers, clobber set, terminator class.
//
// The 500-gadget emulated verification lives in `tests/ground_truth.rs`.
// These are the named cases the finding itself calls out, plus the shapes
// where `None` is the whole point.
// ---------------------------------------------------------------------------

/// Build an x86 gadget from a hex byte string and its disassembly.
fn hexg(hex: &str, text: &str) -> Gadget {
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    x86_gadget(&bytes, text)
}

fn cls64(hex: &str, text: &str) -> Classification {
    classify(&hexg(hex, text), Arch::X64)
}

fn cls32(hex: &str, text: &str) -> Classification {
    classify(&hexg(hex, text), Arch::X86)
}

/// The headline of CLS-09: `add rsp, 0x28 ; ret` and `xchg rsp, rax ; ret`
/// were both the bare label `stack-pivot` with no number. One of them has a
/// number; the other must not acquire one.
#[test]
fn stack_delta_is_a_number_or_honestly_absent() {
    assert_eq!(
        cls64("4883c428c3", "add rsp, 0x28 ; ret").stack_delta,
        Some(0x30)
    );
    assert_eq!(cls64("4894c3", "xchg rsp, rax ; ret").stack_delta, None);
    // Both are still stack pivots; the difference is now expressible.
    assert_eq!(
        cls64("4883c428c3", "add rsp, 0x28 ; ret").primary,
        Class::StackPivot
    );
    assert_eq!(
        cls64("4894c3", "xchg rsp, rax ; ret").primary,
        Class::StackPivot
    );
}

#[test]
fn stack_delta_counts_the_return_address_the_gadget_consumes() {
    assert_eq!(cls64("c3", "ret").stack_delta, Some(8));
    assert_eq!(cls64("5fc3", "pop rdi ; ret").stack_delta, Some(16));
    assert_eq!(
        cls64("5f5ec3", "pop rdi ; pop rsi ; ret").stack_delta,
        Some(24)
    );
    assert_eq!(cls64("57c3", "push rdi ; ret").stack_delta, Some(0));
    // `ret imm16` releases imm16 bytes on top of the return address. iced,
    // Bochs, the Intel SDM and the AMD APM all treat the operand as an
    // unsigned byte count; QEMU sign-extends it, which is why
    // `oracle_unicorn.py` declines to verify imm16 >= 0x8000.
    assert_eq!(cls64("c21000", "ret 0x10").stack_delta, Some(0x18));
    // 32-bit: a slot is 4 bytes, and inc/dec esp are provable offsets.
    assert_eq!(cls32("5bc3", "pop ebx ; ret").stack_delta, Some(8));
    assert_eq!(
        cls32("83c410c3", "add esp, 0x10 ; ret").stack_delta,
        Some(0x14)
    );
    assert_eq!(cls32("4cc3", "dec esp ; ret").stack_delta, Some(3));
}

/// Every shape where the rsp effect is not provably constant. A number here
/// would silently corrupt a chain layout, which is exactly what the finding
/// says must not happen.
#[test]
fn non_constant_rsp_effects_report_none() {
    for (hex, text) in [
        ("4894c3", "xchg rsp, rax ; ret"),
        ("5cc3", "pop rsp ; ret"),
        // `leave` is `mov rsp, rbp ; pop rbp`: rsp becomes rbp + 8.
        ("c9c3", "leave ; ret"),
        // The adjustment is a register, not an immediate.
        ("4801c4c3", "add rsp, rax ; ret"),
        // An alignment mask is not an offset.
        ("4883e4f0c3", "and rsp, 0xfffffffffffffff0 ; ret"),
        ("4889ecc3", "mov rsp, rbp ; ret"),
    ] {
        assert_eq!(
            cls64(hex, text).stack_delta,
            None,
            "{text} must not report a stack delta"
        );
    }
    // A 32-bit write to ESP in 64-bit code TRUNCATES rsp; it does not offset
    // it, and on a real 64-bit stack the result is not even close.
    assert_eq!(cls64("83c410c3", "add esp, 0x10 ; ret").stack_delta, None);
    // The same encoding in 32-bit code is a plain offset.
    assert_eq!(
        cls32("83c410c3", "add esp, 0x10 ; ret").stack_delta,
        Some(0x14)
    );
}

/// CLS-09's own example: `mov qword ptr [rdi], rax ; ret` (a controlled
/// arbitrary write) and `add byte ptr [rax], al ; ret` (a byte increment
/// through an uncontrolled pointer) "are both just mem-write today, quality
/// 100, and sort adjacent".
#[test]
fn the_two_mem_writes_the_finding_names_are_now_distinguishable() {
    let write = cls64("488907c3", "mov qword ptr [rdi], rax ; ret");
    let increment = cls64("0000c3", "add byte ptr [rax], al ; ret");
    // Still the same class, as they should be.
    assert_eq!(write.primary, Class::MemWrite);
    assert_eq!(increment.primary, Class::MemWrite);

    let w = write.memory_writes().next().expect("a memory write");
    assert_eq!(w.dst.pointer_dep(), Some("rdi"));
    assert_eq!(w.src, ValueSrc::Register { reg: "rax".into() });
    assert_eq!(w.width, Some(8));
    assert!(!w.rmw, "a plain store places a chosen value");
    assert_eq!(w.needs, vec!["rdi".to_string()]);

    let i = increment.memory_writes().next().expect("a memory write");
    assert_eq!(i.dst.pointer_dep(), Some("rax"));
    assert_eq!(i.src, ValueSrc::Register { reg: "al".into() });
    assert_eq!(i.width, Some(1));
    assert!(i.rmw, "a read-modify-write cannot place a chosen value");
}

/// The source-kind distinction that makes `--from-stack` mean something.
#[test]
fn transfer_sources_distinguish_stack_register_memory_and_immediate() {
    let pop = cls64("5f5ec3", "pop rdi ; pop rsi ; ret");
    assert_eq!(pop.stack_offset_of("rdi"), Some(0));
    assert_eq!(pop.stack_offset_of("rsi"), Some(8));
    assert!(pop.reg_from_stack("rdi") && pop.reg_from_stack("rsi"));
    assert!(pop.sets_reg("rdi") && !pop.clobbers_reg("rdi"));

    let mov = cls64("4889c7c3", "mov rdi, rax ; ret");
    assert_eq!(
        mov.last_transfer_to("rdi").map(|t| t.src.clone()),
        Some(ValueSrc::Register { reg: "rax".into() })
    );
    assert!(!mov.reg_from_stack("rdi"));
    // The gadget writes rdi but does not choose what lands there — and the
    // transfer says which register a chain would have to control first.
    assert!(mov.clobbers_reg("rdi") && !mov.sets_reg("rdi"));

    let load = cls64("488b7e08c3", "mov rdi, qword ptr [rsi + 8] ; ret");
    let t = load.last_transfer_to("rdi").expect("a transfer into rdi");
    assert_eq!(
        t.src,
        ValueSrc::Memory {
            base: Some("rsi".into()),
            index: None,
            disp: 8
        }
    );
    assert_eq!(t.src.pointer_dep(), Some("rsi"), "rsi must be set up first");
    assert!(load.clobbers_reg("rdi"));

    let imm = cls64("48c7c034120000c3", "mov rax, 0x1234 ; ret");
    assert_eq!(
        imm.last_transfer_to("rax").map(|t| t.src.clone()),
        Some(ValueSrc::Immediate { value: 0x1234 })
    );
    // Predictable from the payload alone, so `set` — but not from-stack.
    assert!(imm.sets_reg("rax") && !imm.reg_from_stack("rax"));
}

#[test]
fn clobbers_and_sets_partition_the_registers_written() {
    // `xor eax, eax` gives rax a value the chain author picked.
    let z = cls64("31c0c3", "xor eax, eax ; ret");
    assert_eq!(z.sets, vec!["rax".to_string()]);
    assert!(z.clobbers.is_empty());

    // Store forwarding: the value rbx ends up with is rax's, not the payload.
    let fwd = cls64("505bc3", "push rax ; pop rbx ; ret");
    assert_eq!(
        fwd.last_transfer_to("rbx").map(|t| t.src.clone()),
        Some(ValueSrc::Register { reg: "rax".into() })
    );
    assert!(
        fwd.clobbers_reg("rbx"),
        "rax is not this gadget's to choose"
    );
    assert!(!fwd.reg_from_stack("rbx"));
    assert_eq!(fwd.stack_delta, Some(8));

    // --no-clobber in one call.
    assert!(fwd.clobbers_any(["rsi", "rbx"]));
    assert!(!fwd.clobbers_any(["rsi", "rdx"]));
}

/// The partition invariant, over a whole binary rather than a hand-picked
/// gadget: on the metadata paths every full-width register a gadget writes is
/// in exactly one of `sets` and `clobbers`, and the stack pointer is in
/// neither.
#[test]
fn sets_and_clobbers_are_disjoint_across_a_whole_fixture() {
    for (fixture, depth) in [("elf-Linux-x64", 6), ("elf-Linux-x86", 6)] {
        let (_, gs, cs) = classify_all(fixture, depth);
        assert!(gs.len() > 1000, "{fixture}: only {} gadgets", gs.len());
        let mut with_delta = 0usize;
        for c in &cs {
            for r in &c.sets {
                assert!(
                    !c.clobbers.contains(r),
                    "{fixture}: {r} is both set and clobbered"
                );
                assert!(!matches!(r.as_str(), "rsp" | "esp" | "sp"));
            }
            for r in &c.clobbers {
                assert!(!matches!(r.as_str(), "rsp" | "esp" | "sp"));
            }
            if c.stack_delta.is_some() {
                with_delta += 1;
            }
        }
        assert!(
            with_delta > cs.len() / 2,
            "{fixture}: only {with_delta}/{} gadgets got a stack delta",
            cs.len()
        );
    }
}

#[test]
fn terminator_class_splits_jmp_and_call_by_target() {
    let cases = [
        ("c3", "ret", TerminatorClass::Ret),
        ("c21000", "ret 0x10", TerminatorClass::RetImm),
        ("ffe0", "jmp rax", TerminatorClass::JmpReg),
        ("ff20", "jmp qword ptr [rax]", TerminatorClass::JmpMem),
        ("ffd0", "call rax", TerminatorClass::CallReg),
        (
            "ff5308",
            "call qword ptr [rbx + 8]",
            TerminatorClass::CallMem,
        ),
        ("0f05", "syscall", TerminatorClass::Syscall),
        ("cb", "retf", TerminatorClass::Far),
    ];
    for (hex, text, want) in cases {
        let c = cls64(hex, text);
        assert_eq!(c.terminator_class(), want, "{text}");
        assert_eq!(c.terminator_class().name(), want.name());
        assert_eq!(TerminatorClass::parse(want.name()), Some(want));
    }
    // The v0.3 spellings are untouched, which is what keeps the MCP
    // outputSchema and the CLI --json record byte-identical.
    assert_eq!(cls64("ffe0", "jmp rax").terminator().name(), "jmp");
    assert_eq!(cls64("ffd0", "call rax").terminator().kind(), "call");
    assert_eq!(
        cls64("ff20", "jmp qword ptr [rax]")
            .terminator_target
            .register(),
        Some("rax")
    );
}

/// The non-x86 stack-delta subset, and the architectures that never compute
/// one. See `crate::generic_effect` for why each row is where it is.
#[test]
fn capstone_families_compute_only_what_they_can_prove() {
    fn g(bytes: &[u8], text: &str, arch: Arch) -> Classification {
        classify(
            &Gadget {
                vaddr: 0x1000,
                bytes: bytes.to_vec(),
                insns: text.split(" ; ").map(str::to_string).collect(),
                delay_slot: false,
                prev: None,
                table: TableKind::Rop,
            },
            arch,
        )
    }
    // ARM: `pop {r4, pc}` is two 4-byte slots.
    let c = g(&[0x10, 0x80, 0xbd, 0xe8], "pop {r4, pc}", Arch::Arm);
    assert!(!c.low_confidence);
    assert_eq!(c.stack_delta, Some(8));
    assert_eq!(c.stack_offset_of("r4"), Some(0));
    let c = g(
        &[0x08, 0xd0, 0x8d, 0xe2, 0x10, 0x80, 0xbd, 0xe8],
        "add sp, sp, #8 ; pop {r4, pc}",
        Arch::Arm,
    );
    assert_eq!(c.stack_delta, Some(16));
    let c = g(
        &[0x04, 0x00, 0x9d, 0xe4, 0x1e, 0xff, 0x2f, 0xe1],
        "pop {r0} ; bx lr",
        Arch::Arm,
    );
    assert_eq!(c.stack_delta, Some(4), "a printed pop is unambiguous");

    // ARM64: an immediate stack adjustment, and no return-address slot.
    let c = g(
        &[0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6],
        "add sp, sp, #0x10 ; ret",
        Arch::Arm64,
    );
    assert_eq!(c.stack_delta, Some(0x10));
    let c = g(
        &[0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6],
        "mov x0, x1 ; ret",
        Arch::Arm64,
    );
    assert_eq!(c.stack_delta, Some(0));
    assert!(c.clobbers_reg("x0"), "x1 is not this gadget's to choose");

    // MIPS: no write-back addressing exists, so `addiu $sp, $sp, imm` is the
    // whole story and the delay slot is counted.
    let c = g(
        &[
            0x27, 0xbd, 0x00, 0x20, 0x03, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        ],
        "addiu $sp, $sp, 0x20 ; jr $ra ; nop",
        Arch::Mips32,
    );
    assert_eq!(c.stack_delta, Some(0x20));

    // PowerPC.
    let c = g(
        &[0x38, 0x21, 0x00, 0x10, 0x4e, 0x80, 0x00, 0x20],
        "addi r1, r1, 0x10 ; blr",
        Arch::Ppc32,
    );
    assert_eq!(c.stack_delta, Some(0x10));

    // SPARC: never. A register window is not an offset.
    let c = g(
        &[0x81, 0xc3, 0xe0, 0x08, 0x01, 0x00, 0x00, 0x00],
        "retl ; nop",
        Arch::Sparc,
    );
    assert!(!c.low_confidence, "the detail path must have been used");
    assert_eq!(c.stack_delta, None);
}

/// The text fallback path claims nothing: a `low_confidence` stack delta
/// would be exactly the confident wrong number the field exists to avoid.
#[test]
fn the_text_path_claims_no_semantics() {
    let c = classify(&gadget("pop {r4, r5, pc}"), Arch::Arm);
    assert!(c.low_confidence, "no bytes, so no decoder metadata");
    assert_eq!(c.stack_delta, None);
    assert!(c.transfers.is_empty());
    assert!(c.sets.is_empty() && c.clobbers.is_empty());
    assert_eq!(c.terminator_target, TerminatorTarget::Implicit);
}

/// A decode that disagrees with the text the scanner printed is not the
/// gadget the user is looking at, so nothing is claimed about it.
#[test]
fn a_decode_that_contradicts_the_scanner_claims_nothing() {
    // Two real instructions, but the recorded text says three.
    let g = x86_gadget(&[0x5f, 0xc3], "pop rdi ; nop ; ret");
    let c = classify(&g, Arch::X64);
    assert_eq!(c.stack_delta, None);
    assert!(c.sets.is_empty());
    assert!(c.transfers.is_empty());
}

/// Every new field serializes, and none of the v0.3 field names moved.
#[test]
fn classification_serializes_additively() {
    let c = cls64("5fc3", "pop rdi ; ret");
    let v: serde_json::Value = serde_json::to_value(&c).unwrap();
    for old in [
        "primary",
        "labels",
        "regs_written",
        "regs_read",
        "regs_from_stack",
        "side_effects",
        "mem_pointer_deps",
        "mid_branches",
        "quality",
        "dispatcher",
        "terminator",
        "privileged",
        "low_confidence",
    ] {
        assert!(v.get(old).is_some(), "v0.3 field {old} disappeared");
    }
    assert_eq!(v["stack_delta"], serde_json::json!(16));
    assert_eq!(v["sets"], serde_json::json!(["rdi"]));
    assert_eq!(v["clobbers"], serde_json::json!([]));
    assert_eq!(
        v["transfers"][0],
        serde_json::json!({
            "dst": {"kind": "register", "reg": "rdi"},
            "src": {"kind": "stack", "offset": 0},
            "needs": [],
            "rmw": false,
            "width": 8
        })
    );
    assert_eq!(v["terminator"], serde_json::json!("ret"));
    assert_eq!(
        v["terminator_target"],
        serde_json::json!({"kind": "implicit"})
    );
}
