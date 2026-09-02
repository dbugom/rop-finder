//! rf-classify — semantic gadget classification and quality ranking
//! (Phase 5, PLAN sec. 5.1). The decision rules live in
//! [`TAXONOMY.md`](../../../TAXONOMY.md); rule numbers (R1-R13) are cited
//! inline. x86/x64 classification decodes with iced-x86 and consumes
//! `InstructionInfoFactory` register/memory metadata (high confidence);
//! other architectures fall back to mnemonic text heuristics
//! (`low_confidence: true`).

#![forbid(unsafe_code)]

use rf_core::Arch;
use rf_scan::Gadget;
use serde::Serialize;

mod x86;

/// Semantic classes (TAXONOMY.md table). `Other` is the fallback for
/// gadgets with no labeled instruction (pure control flow, nop).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    RegWrite,
    StackPivot,
    MemRead,
    MemWrite,
    Arithmetic,
    Syscall,
    Dispatcher,
    Other,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Class::RegWrite => "reg-write",
            Class::StackPivot => "stack-pivot",
            Class::MemRead => "mem-read",
            Class::MemWrite => "mem-write",
            Class::Arithmetic => "arithmetic",
            Class::Syscall => "syscall",
            Class::Dispatcher => "dispatcher",
            Class::Other => "other",
        }
    }
}

/// Precedence when one instruction earns several labels (R10):
/// mem-write > mem-read > stack-pivot > dispatcher > syscall >
/// arithmetic > reg-write.
pub(crate) const PRECEDENCE: &[Class] = &[
    Class::MemWrite,
    Class::MemRead,
    Class::StackPivot,
    Class::Dispatcher,
    Class::Syscall,
    Class::Arithmetic,
    Class::RegWrite,
];

/// Per-gadget semantic classification (R1-R13).
#[derive(Debug, Clone, Serialize)]
pub struct Classification {
    /// Primary class: class of the last side-effecting instruction (R10).
    pub primary: Class,
    /// Full multi-label set (R9), sorted by name for determinism.
    pub labels: Vec<Class>,
    /// Registers written by the gadget (R1-normalized: implicit rsp
    /// effects of push/pop/call/ret excluded), lowercase, deduped,
    /// first-appearance order.
    pub regs_written: Vec<String>,
    pub regs_read: Vec<String>,
    /// Instructions earning at least one label (R11).
    pub side_effects: usize,
    /// Deterministic quality score (R12); higher = cleaner gadget.
    pub quality: i32,
    /// JOP dispatcher heuristic (R8) — also reflected as the
    /// `dispatcher` label when it fires.
    pub dispatcher: bool,
    /// True for non-x86 architectures (mnemonic heuristics, R13).
    pub low_confidence: bool,
}

/// R12: `max(0, 100 - 15*(side_effects-1) - 3*(n_insns-2))`.
pub fn quality_score(side_effects: usize, n_insns: usize) -> i32 {
    let se = side_effects.max(1) as i32;
    let ni = n_insns.max(2) as i32;
    (100 - 15 * (se - 1) - 3 * (ni - 2)).max(0)
}

/// Classify one gadget. Dispatch: x86/x64 → iced metadata path; every
/// other arch → text heuristics with `low_confidence`.
pub fn classify(g: &Gadget, arch: Arch) -> Classification {
    match arch {
        Arch::X86 => x86::classify_x86(g, 32),
        Arch::X64 => x86::classify_x86(g, 64),
        _ => classify_heuristic(g),
    }
}

/// Best-effort mnemonic-text classification for non-x86 arches (R13).
/// Same label vocabulary; operand parsing is string-based and shallow.
fn classify_heuristic(g: &Gadget) -> Classification {
    let mut labels = Vec::new();
    let mut regs_written = Vec::new();
    let regs_read = Vec::new();
    let mut side_effects = 0usize;
    let mut last_class: Option<Class> = None;

    let n = g.insns.len();
    for (i, insn) in g.insns.iter().enumerate() {
        let mnemonic = insn.split_whitespace().next().unwrap_or("").to_lowercase();
        let is_last_control = i == n - 1 && is_control_mnemonic(&mnemonic);
        if is_last_control || mnemonic == "nop" {
            continue;
        }
        let mut insn_labels = Vec::new();
        // R2
        if matches!(
            mnemonic.as_str(),
            "svc" | "swi" | "syscall" | "sysenter" | "int" | "break" | "ta"
        ) {
            insn_labels.push(Class::Syscall);
        }
        // R3/R4: bracketed memory operands; stack ops excluded (R1).
        let operands = insn.split_once(' ').map(|x| x.1).unwrap_or("");
        let has_mem = operands.contains('[');
        let stack_mem = operands.contains("sp]")
            || operands.contains("sp,")
            || operands.contains("sp+")
            || operands.contains("sp-");
        if matches!(
            mnemonic.as_str(),
            "str" | "strb" | "strh" | "st" | "stb" | "sth" | "sw" | "sh" | "sb" | "std"
        ) && has_mem
            && !stack_mem
        {
            insn_labels.push(Class::MemWrite);
        } else if matches!(
            mnemonic.as_str(),
            "ldr" | "ldrb" | "ldrh" | "ld" | "ldw" | "ldh" | "lb" | "lw" | "lh" | "ldd"
        ) && has_mem
            && !stack_mem
        {
            insn_labels.push(Class::MemRead);
        }
        // R5
        if operands.starts_with("sp,")
            || operands.starts_with("sp ")
            || mnemonic == "leave"
            || (matches!(mnemonic.as_str(), "mov" | "add" | "sub" | "xchg")
                && operands.split(',').next().map(|d| d.trim()) == Some("sp"))
        {
            insn_labels.push(Class::StackPivot);
        }
        // R6
        if matches!(
            mnemonic.as_str(),
            "add"
                | "sub"
                | "adc"
                | "sbc"
                | "and"
                | "or"
                | "orr"
                | "xor"
                | "eor"
                | "neg"
                | "not"
                | "mvn"
                | "lsl"
                | "lsr"
                | "asr"
                | "ror"
                | "mul"
                | "cmp"
                | "tst"
                | "inc"
                | "dec"
                | "shl"
                | "shr"
                | "sar"
                | "sal"
                | "rol"
                | "lea"
                | "test"
        ) {
            insn_labels.push(Class::Arithmetic);
        }
        // R7: writes a GPR without non-stack memory operands
        let writes_reg = !insn_labels.contains(&Class::MemRead)
            && !insn_labels.contains(&Class::MemWrite)
            && !matches!(
                mnemonic.as_str(),
                "b" | "bl"
                    | "br"
                    | "blr"
                    | "ret"
                    | "jmp"
                    | "j"
                    | "jr"
                    | "jal"
                    | "jalr"
                    | "beq"
                    | "bne"
                    | "blt"
                    | "bgt"
                    | "ble"
                    | "bge"
                    | "cbz"
                    | "cbnz"
                    | "cmp"
                    | "tst"
                    | "test"
                    | "nop"
            )
            && !operands.is_empty();
        if writes_reg && !insn_labels.contains(&Class::Syscall) {
            insn_labels.push(Class::RegWrite);
            if let Some(dst) = operands.split(',').next() {
                let dst = dst.trim().to_lowercase();
                if !dst.is_empty() && !dst.contains('[') && dst != "sp" {
                    push_unique(&mut regs_written, dst);
                }
            }
        }
        if !insn_labels.is_empty() {
            side_effects += 1;
            last_class = PRECEDENCE
                .iter()
                .find(|c| insn_labels.contains(c))
                .copied()
                .or(last_class);
            for c in insn_labels {
                push_unique_class(&mut labels, c);
            }
        }
    }

    let dispatcher = false; // R8 heuristic is x86/x64-only for now
    let primary = last_class.unwrap_or(Class::Other);
    labels.sort_by_key(|c| c.name());
    Classification {
        primary,
        labels,
        regs_written,
        regs_read,
        side_effects,
        quality: quality_score(side_effects, g.insns.len()),
        dispatcher,
        low_confidence: true,
    }
}

fn is_control_mnemonic(m: &str) -> bool {
    m == "ret"
        || m == "retf"
        || m == "iret"
        || m == "iretd"
        || m == "iretq"
        || m.starts_with('j')
        || m == "call"
        || m == "b"
        || m == "br"
        || m == "blr"
        || m == "bx"
        || m == "blx"
        || m == "eret"
        || m.starts_with("b.") // ARM64 conditional: b.eq, b.ne, ...
}

pub(crate) fn push_unique(v: &mut Vec<String>, s: String) {
    if !v.contains(&s) {
        v.push(s);
    }
}

pub(crate) fn push_unique_class(v: &mut Vec<Class>, c: Class) {
    if !v.contains(&c) {
        v.push(c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gadget(text: &str) -> Gadget {
        Gadget {
            vaddr: 0x1000,
            bytes: Vec::new(),
            insns: text.split(" ; ").map(|s| s.to_string()).collect(),
            delay_slot: false,
        }
    }

    #[test]
    fn heuristic_marks_low_confidence() {
        let c = classify(&gadget("mov x0, x1 ; ret"), Arch::Arm64);
        assert!(c.low_confidence);
        assert_eq!(c.primary, Class::RegWrite);
        let c = classify(&gadget("ldr x0, [x1] ; ret"), Arch::Arm64);
        assert_eq!(c.primary, Class::MemRead);
        let c = classify(&gadget("svc #0 ; ret"), Arch::Arm64);
        assert_eq!(c.primary, Class::Syscall);
        let c = classify(&gadget("add sp, sp, #0x20 ; ret"), Arch::Arm64);
        assert!(c.labels.contains(&Class::StackPivot));
    }

    #[test]
    fn quality_formula_matches_r12() {
        assert_eq!(quality_score(1, 2), 100);
        assert_eq!(quality_score(2, 3), 82);
        assert_eq!(quality_score(10, 12), 0);
    }
}
