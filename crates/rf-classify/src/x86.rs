//! x86/x64 classification via iced-x86 `InstructionInfoFactory`
//! (TAXONOMY.md R1-R12, high confidence).

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfo, InstructionInfoFactory,
    Mnemonic, OpAccess, OpKind, Register,
};
use rf_scan::Gadget;

use crate::x86_effect::Analyzer;
use crate::{
    push_unique, push_unique_class, quality_score_full, Class, Classification, Terminator,
    PRECEDENCE,
};

/// R6 arithmetic/logical mnemonic set, widened per CLS-12.
///
/// Added: division (`div`, `idiv`), exchange-add (`xadd`), the bit-test group
/// (`bt`, `bts`, `btr`, `btc`), byte-swap (`bswap`), double-precision shifts
/// (`shld`, `shrd`) and `xchg`.
///
/// Removed: `cmp` and `test`. They compute nothing into any register, they
/// are useless as arithmetic gadgets, and they were the single largest
/// contributor to what was already the largest class.
fn is_arithmetic(m: Mnemonic) -> bool {
    matches!(
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
            | Mnemonic::Rcl
            | Mnemonic::Rcr
            | Mnemonic::Imul
            | Mnemonic::Mul
            | Mnemonic::Div
            | Mnemonic::Idiv
            | Mnemonic::Xadd
            | Mnemonic::Xchg
            | Mnemonic::Bt
            | Mnemonic::Bts
            | Mnemonic::Btr
            | Mnemonic::Btc
            | Mnemonic::Bswap
            | Mnemonic::Shld
            | Mnemonic::Shrd
            | Mnemonic::Lea
    )
}

/// R2 syscall-gate mnemonics.
fn is_syscall(m: Mnemonic) -> bool {
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

/// Instructions that fault, trap or require ring 0 — a gadget containing one
/// cannot appear in a user-mode chain (usability tier 0).
fn is_privileged_or_undefined(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Hlt
            | Mnemonic::Ud0
            | Mnemonic::Ud1
            | Mnemonic::Ud2
            | Mnemonic::Cli
            | Mnemonic::Sti
            | Mnemonic::In
            | Mnemonic::Insb
            | Mnemonic::Insw
            | Mnemonic::Insd
            | Mnemonic::Out
            | Mnemonic::Outsb
            | Mnemonic::Outsw
            | Mnemonic::Outsd
            | Mnemonic::Lgdt
            | Mnemonic::Lidt
            | Mnemonic::Lldt
            | Mnemonic::Ltr
            | Mnemonic::Lmsw
            | Mnemonic::Clts
            | Mnemonic::Invd
            | Mnemonic::Wbinvd
            | Mnemonic::Invlpg
            | Mnemonic::Rdmsr
            | Mnemonic::Wrmsr
            | Mnemonic::Rsm
            | Mnemonic::Vmcall
            | Mnemonic::Vmlaunch
            | Mnemonic::Vmresume
            | Mnemonic::Vmxoff
            | Mnemonic::Int3
    )
}

/// R1: mnemonics whose stack-pointer effect is chain mechanism, not payload.
///
/// CLS-02: the flags forms were missing. iced gives `popfq` its own mnemonic,
/// so it never matched `Mnemonic::Pop`, `implicit_sp` stayed false, and R5 saw
/// popfq's implicit `rsp` increment as an EXPLICIT stack-pointer write —
/// which is why `popfq ; ret` came out as a stack pivot with
/// `regs_written: ["rsp"]`, indistinguishable from `xchg rsp, rax ; ret`.
fn has_implicit_sp(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Pusha
            | Mnemonic::Pushad
            | Mnemonic::Popa
            | Mnemonic::Popad
            | Mnemonic::Pushf
            | Mnemonic::Pushfd
            | Mnemonic::Pushfq
            | Mnemonic::Popf
            | Mnemonic::Popfd
            | Mnemonic::Popfq
            | Mnemonic::Call
            | Mnemonic::Ret
            | Mnemonic::Retf
            | Mnemonic::Enter
            | Mnemonic::Leave
            | Mnemonic::Iret
            | Mnemonic::Iretd
            | Mnemonic::Iretq
    )
}

/// Pop-family: the value written to the register comes off the stack, so it
/// is chain-controlled. `popf*` is excluded — it writes rflags, not a GPR.
fn is_pop_family(m: Mnemonic) -> bool {
    matches!(m, Mnemonic::Pop | Mnemonic::Popa | Mnemonic::Popad)
}

fn is_sp(r: Register) -> bool {
    matches!(r, Register::SP | Register::ESP | Register::RSP)
}

fn reg_name(r: Register) -> String {
    crate::x86_effect::reg_str(r).to_string()
}

fn access_reads(a: OpAccess) -> bool {
    matches!(
        a,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn access_writes(a: OpAccess) -> bool {
    matches!(
        a,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

/// Final control-transfer anchors (their control effects are skipped for
/// side-effect accounting, R10 — but any payload they also carry is kept,
/// which is CLS-13's `ret imm16` case).
fn is_control_anchor(flow: FlowControl) -> bool {
    matches!(
        flow,
        FlowControl::Return
            | FlowControl::Call
            | FlowControl::IndirectCall
            | FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
    )
}

/// What kind of terminator the gadget's last instruction is.
fn terminator_of(insn: &Instruction) -> Terminator {
    let far = matches!(insn.op0_kind(), OpKind::FarBranch16 | OpKind::FarBranch32)
        || matches!(
            insn.mnemonic(),
            Mnemonic::Retf | Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq
        );
    match insn.mnemonic() {
        Mnemonic::Ret => {
            if insn.op_count() > 0 && insn.immediate(0) != 0 {
                Terminator::RetImm
            } else {
                Terminator::Ret
            }
        }
        Mnemonic::Retf => Terminator::Retf,
        Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq => Terminator::Iret,
        m if is_syscall(m) => Terminator::Syscall,
        Mnemonic::Jmp if far => Terminator::Far,
        Mnemonic::Call if far => Terminator::Far,
        Mnemonic::Jmp => Terminator::Jmp,
        Mnemonic::Call => Terminator::Call,
        _ if is_control_anchor(insn.flow_control()) => Terminator::Jmp,
        _ => Terminator::None,
    }
}

/// Everything one instruction contributes.
#[derive(Default)]
struct InsnEffect {
    labels: Vec<Class>,
    written: Vec<String>,
    read: Vec<String>,
    from_stack: Vec<String>,
    /// Memory operands whose base/index register must already hold an
    /// attacker-controlled pointer.
    pointer_deps: usize,
}

/// Labels one decoded instruction.
///
/// `anchor` is true for the gadget's terminating control transfer: its
/// control effects (the transfer, the return-address pop, the branch-target
/// fetch) are mechanism and are dropped, but a stack adjustment it also
/// performs is payload and is kept — `ret 0x10` advances rsp by 0x18 exactly
/// as `add rsp, 0x10 ; ret` does, and used to be `other` while the other was
/// `stack-pivot` (CLS-13).
fn effect_of(insn: &Instruction, info: &InstructionInfo, anchor: bool) -> InsnEffect {
    let m = insn.mnemonic();
    let mut e = InsnEffect::default();
    if m == Mnemonic::Nop {
        return e;
    }
    if anchor {
        // The only payload a control-transfer anchor carries is a fixed stack
        // adjustment: `ret imm16` / `retf imm16`.
        if matches!(m, Mnemonic::Ret | Mnemonic::Retf)
            && insn.op_count() > 0
            && insn.immediate(0) != 0
        {
            e.labels.push(Class::StackPivot);
        }
        return e;
    }

    if is_syscall(m) {
        e.labels.push(Class::Syscall);
    }

    // Register effects (R1: implicit stack-pointer effects of
    // push/pop/pushf/popf/call/ret excluded; RIP excluded — RIP-relative
    // addressing is not a payload read).
    let implicit_sp = has_implicit_sp(m);
    for u in info.used_registers() {
        let r = u.register();
        if r == Register::None || matches!(r, Register::RIP | Register::EIP) {
            continue;
        }
        if is_sp(r) && implicit_sp {
            continue;
        }
        if access_reads(u.access()) {
            push_unique(&mut e.read, reg_name(r));
        }
        if access_writes(u.access()) {
            push_unique(&mut e.written, reg_name(r));
        }
    }

    // Memory effects. R1 keeps stack READS out of `mem-read` — the value they
    // deliver is already reported as a register write — but a stack WRITE is
    // a controlled value going into memory, which is precisely the `push rax`
    // primitive that used to earn no label at all (CLS-13).
    let mut mem_read = false;
    let mut mem_write = false;
    let mut stack_load = false;
    // `leave` and `enter` touch memory through rbp purely to move the frame;
    // that access is mechanism in exactly the sense R1 means, and treating it
    // as a payload read would rank `leave ; ret` as mem-read rather than the
    // stack pivot it is.
    let frame_mechanism = matches!(m, Mnemonic::Leave | Mnemonic::Enter);
    for u in info.used_memory() {
        if frame_mechanism {
            stack_load = true;
            continue;
        }
        let stack = is_sp(u.base()) || is_sp(u.segment());
        if access_writes(u.access()) {
            mem_write = true;
        }
        if access_reads(u.access()) {
            if stack {
                stack_load = true;
            } else {
                mem_read = true;
            }
        }
        // A memory operand reached through a base or index register needs
        // that register to already hold an attacker-controlled pointer before
        // the gadget can be used; an absolute or RIP-relative operand does
        // not. CLS-07 names this as one of the things the quality score
        // ignores.
        if !stack && (u.base() != Register::None || u.index() != Register::None) {
            e.pointer_deps += 1;
        }
    }
    if mem_write {
        e.labels.push(Class::MemWrite);
    }
    if mem_read {
        e.labels.push(Class::MemRead);
    }

    // R5 (CLS-02): a stack-pivot needs an rsp-TARGETING write — rsp has to
    // appear as an explicit register operand that the instruction writes, or
    // the instruction has to be `leave`. An instruction that merely steps rsp
    // as part of its own mechanism is not a pivot.
    let sp_is_operand = (0..insn.op_count())
        .any(|k| insn.op_kind(k) == OpKind::Register && is_sp(insn.op_register(k)));
    let sp_written = info
        .used_registers()
        .iter()
        .any(|u| is_sp(u.register()) && access_writes(u.access()));
    let leave = m == Mnemonic::Leave;
    if (sp_is_operand && sp_written && !matches!(m, Mnemonic::Push)) || leave {
        e.labels.push(Class::StackPivot);
    }

    if is_arithmetic(m) {
        e.labels.push(Class::Arithmetic);
    }

    // R7: writes a GPR (8/16/32/64 general-purpose register — excludes the
    // flags register, xmm/ymm, segments, and rsp handled above), no non-stack
    // memory operand, not a control/gate instruction.
    let mut wrote_gpr = false;
    for u in info.used_registers() {
        let r = u.register();
        if !(r.is_gpr8() || r.is_gpr16() || r.is_gpr32() || r.is_gpr64())
            || is_sp(r)
            || !access_writes(u.access())
        {
            continue;
        }
        wrote_gpr = true;
        if stack_load || is_pop_family(m) || m == Mnemonic::Leave {
            push_unique(&mut e.from_stack, reg_name(r));
        }
    }
    if wrote_gpr && !mem_read && !mem_write && !is_syscall(m) {
        e.labels.push(Class::RegWrite);
    }
    e
}

/// R8 dispatcher heuristic, redefined per CLS-03.
///
/// A JOP/COP **dispatcher** is a gadget that advances a dispatch-table
/// pointer and then branches through it: `add rdx, 8 ; jmp [rdx]`. The
/// distinguishing property is a *self-advancing* index register — one the
/// gadget both reads and writes arithmetically — that the terminating
/// indirect branch then uses as its target or as its target's base.
///
/// The rule this replaces answered "is the terminator `jmp [reg]`?" and
/// nothing else, which labeled 865 gadgets on bash of which 6 were
/// dispatcher-shaped, and it was restricted to `Mnemonic::Jmp`, so the
/// call-oriented form `call qword ptr [reg]` — which rf-scan does emit as a
/// JOP gadget — could never be labeled.
fn dispatcher_heuristic(insns: &[Instruction], factory: &mut InstructionInfoFactory) -> bool {
    let Some(last) = insns.last() else {
        return false;
    };
    if !matches!(last.mnemonic(), Mnemonic::Jmp | Mnemonic::Call) {
        return false;
    }
    // The branch has to be indirect through a register, either directly
    // (`jmp rdx`) or through memory based on one (`jmp [rdx + 8]`).
    let mut targets: Vec<Register> = Vec::new();
    if last.op_count() > 0 {
        match last.op_kind(0) {
            OpKind::Register => targets.push(last.op_register(0)),
            OpKind::Memory => {
                let base = last.memory_base();
                if base != Register::None && !matches!(base, Register::RIP | Register::EIP) {
                    targets.push(base);
                }
                let index = last.memory_index();
                if index != Register::None {
                    targets.push(index);
                }
            }
            _ => {}
        }
    }
    if targets.is_empty() {
        return false;
    }
    // Some earlier instruction must ADVANCE one of those registers: an
    // arithmetic instruction that both reads and writes it. `pop rdx ;
    // jmp [rdx]` loads a fresh pointer and is a functional JOP gadget, not a
    // dispatcher; `add rdx, 8 ; jmp [rdx]` walks a table and is.
    insns[..insns.len() - 1].iter().any(|insn| {
        if !is_arithmetic(insn.mnemonic()) {
            return false;
        }
        let info = factory.info(insn);
        targets.iter().any(|t| {
            info.used_registers().iter().any(|u| {
                u.register() == *t && access_writes(u.access()) && access_reads(u.access())
            })
        })
    })
}

/// Full x86/x64 classification (R1-R12).
pub(crate) fn classify_x86(g: &Gadget, bits: u32) -> Classification {
    let mut decoder = Decoder::with_ip(bits, &g.bytes, g.vaddr, DecoderOptions::NONE);
    let mut insns = Vec::new();
    let mut insn = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        insns.push(insn);
    }

    let mut factory = InstructionInfoFactory::new();
    let mut labels: Vec<Class> = Vec::new();
    let mut regs_read = Vec::new();
    let mut regs_written = Vec::new();
    let mut regs_from_stack = Vec::new();
    let mut side_effects = 0usize;
    let mut last_class: Option<Class> = None;
    let mut privileged = false;
    let mut pointer_deps = 0usize;
    let mut mid_branches = 0usize;

    let n = insns.len();
    let mut terminator = Terminator::None;
    // CLS-09. The decode this analysis needs is the one already in hand, and
    // the `InstructionInfo` it needs is the one `effect_of` already asks for,
    // so both consume the same single `factory.info()` call per instruction:
    // the semantic layer rides along on the classification pass instead of
    // adding one of its own.
    //
    // `g.insns` is the text the *scanner* printed. If this decode does not
    // reproduce it instruction for instruction, the gadget in front of the
    // user is not the one being analysed, and nothing is claimed about it.
    let trustworthy = !insns.is_empty() && (g.insns.is_empty() || insns.len() == g.insns.len());
    let mut analyzer = Analyzer::new(bits, trustworthy);
    for (i, insn) in insns.iter().enumerate() {
        // R10: the final control-transfer anchor is the gadget mechanism.
        // iced marks syscall as FlowControl::Call — syscall gates are payload,
        // not mechanism, and are exempt (R2).
        let anchor =
            i == n - 1 && is_control_anchor(insn.flow_control()) && !is_syscall(insn.mnemonic());
        if anchor {
            terminator = terminator_of(insn);
        }
        privileged |= is_privileged_or_undefined(insn.mnemonic());
        if !anchor && insn.flow_control() == FlowControl::ConditionalBranch {
            mid_branches += 1;
        }
        let info = factory.info(insn);
        analyzer.step(insn, info, anchor, i + 1 == n);
        let e = effect_of(insn, info, anchor);
        pointer_deps += e.pointer_deps;
        for r in e.read {
            push_unique(&mut regs_read, r);
        }
        for r in e.from_stack {
            push_unique(&mut regs_from_stack, r);
        }
        if e.labels.is_empty() {
            continue;
        }
        for r in e.written {
            push_unique(&mut regs_written, r);
        }
        side_effects += 1;
        last_class = PRECEDENCE
            .iter()
            .find(|c| e.labels.contains(c))
            .copied()
            .or(last_class);
        for c in e.labels {
            push_unique_class(&mut labels, c);
        }
    }
    if terminator == Terminator::None {
        if let Some(last) = insns.last() {
            if is_syscall(last.mnemonic()) {
                terminator = Terminator::Syscall;
            }
        }
    }

    // R8
    let dispatcher = dispatcher_heuristic(&insns, &mut factory);
    if dispatcher {
        push_unique_class(&mut labels, Class::Dispatcher);
        if last_class.is_none() {
            last_class = Some(Class::Dispatcher);
        }
    }

    let primary = last_class.unwrap_or(Class::Other);
    labels.sort_by_key(|c| c.name());
    let eff = analyzer.finish();
    Classification {
        primary,
        labels,
        quality: quality_score_full(
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
        dispatcher,
        terminator,
        terminator_target: eff.target,
        stack_delta: eff.stack_delta,
        transfers: eff.transfers,
        sets: eff.sets,
        clobbers: eff.clobbers,
        privileged,
        low_confidence: false,
    }
}
