//! Text-only fallback classification (R13).
//!
//! Reached only when no capstone mode reproduces a gadget's recorded text, so
//! decoder metadata is unavailable. It carries `low_confidence: true` and it
//! is deliberately conservative: it would rather emit no label than a wrong
//! register name.
//!
//! The two bugs this file exists to not repeat:
//!
//! * **CLS-04** — the memory test used to be `operands.contains('[')`. MIPS,
//!   PowerPC, RISC-V and SPARC print `disp(base)`, so it never fired. Here
//!   [`memory_shape`] recognises both spellings.
//! * **CLS-05** — the destination used to be the first comma-separated token
//!   taken verbatim, so ARM `pop {r4, r5, pc}` yielded the register name
//!   `{r4` and `bhi #0x12e44` yielded `#0x12e44` (branch mnemonics were not in
//!   the eleven-entry blocklist). Here [`register_tokens`] strips `{}!^$%`,
//!   expands `{r4-r7}` ranges and rejects anything that is not shaped like a
//!   register name, and [`is_branch_mnemonic`] covers the conditional forms.

use rf_core::Arch;
use rf_scan::Gadget;

use crate::{push_unique, push_unique_class, Class, Classification, Terminator, PRECEDENCE};

/// Is `tok` shaped like a register name on any supported architecture?
///
/// Deliberately a grammar over shapes rather than a per-architecture register
/// list: the text path does not know which mode produced the text. It rejects
/// everything CLS-05 complained about — `#`-prefixed immediates, `[`/`(`
/// bracketed memory, bare numbers, and anything with punctuation left in it.
pub(crate) fn looks_like_register(tok: &str) -> bool {
    if tok.is_empty() || tok.len() > 6 {
        return false;
    }
    let b = tok.as_bytes();
    if !b[0].is_ascii_lowercase() {
        return false;
    }
    if !b
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    {
        return false;
    }
    // A register name is letters then (optionally) digits: r4, x20, eax, rdi,
    // sp, o7, t9. Never digits-then-letters, never a bare number.
    let digits_start = b.iter().position(|c| c.is_ascii_digit());
    match digits_start {
        None => true,
        Some(i) => b[i..].iter().all(|c| c.is_ascii_digit()) && i > 0,
    }
}

/// Normalize one operand token to a candidate register name, or `None`.
///
/// Strips ARM register-list braces and writeback/user-mode suffixes
/// (`{`, `}`, `!`, `^`), MIPS `$` and SPARC `%` sigils, and any trailing
/// comma; rejects immediates (`#…`, `0x…`) and memory (`[…]`, `…(…)`).
pub(crate) fn register_token(raw: &str) -> Option<String> {
    let t = raw.trim().trim_end_matches(',');
    if t.starts_with('#') || t.starts_with('[') || t.contains('(') || t.contains(')') {
        return None;
    }
    let t = t.trim_matches(|c| matches!(c, '{' | '}' | '!' | '^' | ' '));
    let t = t.trim_start_matches(['$', '%']);
    let t = t.to_ascii_lowercase();
    looks_like_register(&t).then_some(t)
}

/// Every register an operand string mentions, with ARM register-list ranges
/// expanded: `{r4-r7, lr}` -> `r4, r5, r6, r7, lr`.
pub(crate) fn register_tokens(operands: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in operands.split(',') {
        let part = part.trim();
        if let Some((lo, hi)) = part
            .trim_matches(|c| matches!(c, '{' | '}' | '!' | '^' | ' '))
            .split_once('-')
        {
            if let (Some(lo), Some(hi)) = (register_token(lo), register_token(hi)) {
                if let Some(range) = expand_range(&lo, &hi) {
                    for r in range {
                        push_unique(&mut out, r);
                    }
                    continue;
                }
            }
        }
        if let Some(r) = register_token(part) {
            push_unique(&mut out, r);
        }
    }
    out
}

/// `r4`..`r7` -> `[r4, r5, r6, r7]`; `None` when the endpoints do not share a
/// letter prefix or run backwards.
fn expand_range(lo: &str, hi: &str) -> Option<Vec<String>> {
    let split = |s: &str| -> Option<(String, u32)> {
        let i = s.find(|c: char| c.is_ascii_digit())?;
        Some((s[..i].to_string(), s[i..].parse().ok()?))
    };
    let (lp, ln) = split(lo)?;
    let (hp, hn) = split(hi)?;
    if lp != hp || hn < ln || hn - ln > 31 {
        return None;
    }
    Some((ln..=hn).map(|n| format!("{lp}{n}")).collect())
}

/// Does `operands` reference memory, and if so through which base register?
///
/// Handles both spellings: `[r0, #4]` / `[x1]` (ARM, ARM64) and `8(r1)` /
/// `0x10($sp)` (MIPS, PowerPC, RISC-V), plus SPARC's `[%o0 + 8]`.
pub(crate) fn memory_shape(operands: &str) -> Option<Option<String>> {
    if let Some(open) = operands.find('[') {
        let close = operands[open..].find(']').map(|i| open + i)?;
        let inner = &operands[open + 1..close];
        let base = inner.split([',', '+', '-', ' ']).find_map(register_token);
        return Some(base);
    }
    if let Some(open) = operands.rfind('(') {
        let close = operands[open..].find(')').map(|i| open + i)?;
        let inner = &operands[open + 1..close];
        return Some(register_token(inner));
    }
    None
}

fn is_stack_reg(r: &str) -> bool {
    matches!(r, "sp" | "r13" | "r1" | "o6" | "x2" | "29")
}

/// Branch mnemonics, including every conditional form CLS-05 found missing.
pub(crate) fn is_branch_mnemonic(m: &str) -> bool {
    const EXACT: &[&str] = &[
        "b", "bl", "blx", "bx", "br", "blr", "bctr", "bctrl", "bclr", "bdnz", "bdz", "ret", "retl",
        "return", "eret", "rfi", "rfe", "j", "jr", "jal", "jalr", "jr.hb", "jalx", "call", "jmp",
        "jmpl", "cbz", "cbnz", "tbz", "tbnz", "bal", "b.n", "b.w",
    ];
    if EXACT.contains(&m) {
        return true;
    }
    // ARM64 `b.eq`, ARM `beq`/`bhi`/`bne`/`blt`…, MIPS `beq`/`bne`/`blez`/
    // `blezl`/`bgtzl`…, PowerPC `beq`/`bne`/`blt`…, RISC-V `beq`/`bge`/`bltu`.
    if let Some(rest) = m.strip_prefix("b.") {
        return !rest.is_empty();
    }
    if let Some(rest) = m.strip_prefix('b') {
        const CC: &[&str] = &[
            "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt",
            "gt", "le", "al", "gez", "gtz", "lez", "ltz", "eqz", "nez", "ltu", "geu", "gez",
        ];
        let rest = rest.trim_end_matches('l'); // MIPS likely branches: beql, blezl
        return CC.contains(&rest);
    }
    false
}

fn is_control_mnemonic(m: &str) -> bool {
    is_branch_mnemonic(m)
        || m.starts_with('j')
        || matches!(
            m,
            "retf" | "iret" | "iretd" | "iretq" | "pop" | "ldm" | "ldmia"
        )
}

/// Best-effort mnemonic-text classification (R13).
pub(crate) fn classify_text(g: &Gadget, _arch: Arch) -> Classification {
    let mut labels = Vec::new();
    let mut regs_written: Vec<String> = Vec::new();
    let mut regs_read: Vec<String> = Vec::new();
    let mut regs_from_stack: Vec<String> = Vec::new();
    let mut side_effects = 0usize;
    let mut last_class: Option<Class> = None;
    let mut privileged = false;
    let mut pointer_deps = 0usize;
    let mut mid_branches = 0usize;

    let n = g.insns.len();
    let mut terminator = Terminator::None;
    for (i, insn) in g.insns.iter().enumerate() {
        let mnemonic = insn.split_whitespace().next().unwrap_or("").to_lowercase();
        let operands = insn.split_once(' ').map(|x| x.1).unwrap_or("");
        let is_last_control = i == n - 1 && is_control_mnemonic(&mnemonic);
        if is_last_control {
            terminator = text_terminator(&mnemonic, operands);
        }
        if matches!(
            mnemonic.as_str(),
            "hlt" | "ud2" | "int3" | "cli" | "sti" | "wfi" | "wfe"
        ) {
            privileged = true;
        }
        if !is_last_control && is_branch_mnemonic(&mnemonic) {
            mid_branches += 1;
        }
        if is_last_control || mnemonic == "nop" {
            continue;
        }
        let mut insn_labels = Vec::new();
        // R2
        if matches!(
            mnemonic.as_str(),
            "svc" | "swi" | "syscall" | "sysenter" | "int" | "break" | "ta" | "ecall" | "sc"
        ) {
            insn_labels.push(Class::Syscall);
        }

        // R3/R4 (CLS-04): both `[base, …]` and `disp(base)` spellings.
        let store = mnemonic.starts_with("st")
            || mnemonic.starts_with("sw")
            || mnemonic.starts_with("sh")
            || mnemonic.starts_with("sb")
            || mnemonic.starts_with("sd")
            || mnemonic.starts_with("push")
            || mnemonic == "mov"
                && operands
                    .split_once(',')
                    .is_some_and(|(d, _)| d.contains('[') || d.contains('('));
        let mem = memory_shape(operands);
        let on_stack = mem
            .as_ref()
            .and_then(|b| b.as_deref())
            .is_some_and(is_stack_reg);
        let mut stack_load = false;
        if let Some(base) = &mem {
            if store {
                insn_labels.push(Class::MemWrite);
            } else if on_stack {
                stack_load = true;
            } else {
                insn_labels.push(Class::MemRead);
            }
            if !on_stack && base.is_some() {
                pointer_deps += 1;
            }
        }
        if matches!(mnemonic.as_str(), "push" | "pop") || mnemonic.starts_with("stm") {
            if mnemonic == "pop" {
                stack_load = true;
            } else {
                push_unique_class(&mut insn_labels, Class::MemWrite);
            }
        }
        if mnemonic.starts_with("ldm") {
            stack_load = true;
        }

        let dest_first = register_tokens(operands.split(',').next().unwrap_or(""));
        let all_regs = register_tokens(operands);

        // R5: an explicit write of the stack pointer.
        let writes_sp = dest_first.iter().any(|r| is_stack_reg(r))
            || mnemonic == "leave"
            || (mnemonic == "pop" && all_regs.iter().any(|r| is_stack_reg(r)));
        if writes_sp && !matches!(mnemonic.as_str(), "push" | "cmp" | "tst") {
            insn_labels.push(Class::StackPivot);
        }

        // R6
        if crate::generic::is_arithmetic(&mnemonic) {
            insn_labels.push(Class::Arithmetic);
        }

        // R7: a register destination, when the instruction is not a branch,
        // a comparison, a store or a gate.
        let writes_reg = !insn_labels.contains(&Class::MemRead)
            && !insn_labels.contains(&Class::MemWrite)
            && !insn_labels.contains(&Class::Syscall)
            && !is_branch_mnemonic(&mnemonic)
            && !matches!(
                mnemonic.as_str(),
                "nop" | "cmp" | "tst" | "test" | "teq" | "cmn"
            )
            && !store;
        let written: Vec<String> = if mnemonic == "pop" || mnemonic.starts_with("ldm") {
            all_regs.clone()
        } else {
            dest_first.clone()
        };
        let written: Vec<String> = written
            .into_iter()
            .filter(|r| !is_stack_reg(r) && !matches!(r.as_str(), "pc" | "zero" | "xzr" | "wzr"))
            .collect();
        if writes_reg && !written.is_empty() {
            insn_labels.push(Class::RegWrite);
        }
        if writes_reg {
            for r in &written {
                push_unique(&mut regs_written, r.clone());
                if stack_load {
                    push_unique(&mut regs_from_stack, r.clone());
                }
            }
        }
        for r in all_regs {
            push_unique(&mut regs_read, r);
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

    let primary = last_class.unwrap_or(Class::Other);
    labels.sort_by_key(|c| c.name());
    Classification {
        primary,
        labels,
        quality: crate::quality_score_full(
            side_effects,
            g.insns.len(),
            regs_written.len(),
            pointer_deps + mid_branches,
        ),
        regs_written,
        regs_read,
        regs_from_stack,
        side_effects,
        mem_pointer_deps: pointer_deps,
        mid_branches,
        dispatcher: false,
        terminator,
        // CLS-09: the text path has no decoder metadata, so it has no way to
        // prove a stack-pointer effect, a value flow or a clobber. It says so
        // rather than guessing — a `low_confidence` stack delta would be
        // exactly the confident wrong number the field exists to avoid.
        terminator_target: crate::TerminatorTarget::Implicit,
        stack_delta: None,
        transfers: Vec::new(),
        sets: Vec::new(),
        clobbers: Vec::new(),
        privileged,
        low_confidence: true,
    }
}

fn text_terminator(mnemonic: &str, operands: &str) -> Terminator {
    match mnemonic {
        "ret" | "retl" | "return" | "blr" | "bctr" if !operands.contains("0x") => Terminator::Ret,
        "ret" => Terminator::RetImm,
        "retf" => Terminator::Retf,
        "iret" | "iretd" | "iretq" | "eret" | "rfi" | "rfe" => Terminator::Iret,
        "bx" | "jr" | "b" | "j" if operands.contains("lr") || operands.contains("ra") => {
            Terminator::Ret
        }
        "pop" | "ldm" | "ldmia" if operands.contains("pc") => Terminator::Ret,
        "call" | "bl" | "blx" | "jal" | "jalr" | "bctrl" | "bctrl+" => Terminator::Call,
        _ => Terminator::Jmp,
    }
}
