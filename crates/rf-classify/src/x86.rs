//! x86/x64 classification via iced-x86 `InstructionInfoFactory`
//! (TAXONOMY.md R1-R12, high confidence).

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use rf_scan::Gadget;

use crate::{push_unique, push_unique_class, quality_score, Class, Classification, PRECEDENCE};

/// R6 arithmetic/logical mnemonic set.
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
            | Mnemonic::Imul
            | Mnemonic::Mul
            | Mnemonic::Lea
            | Mnemonic::Cmp
            | Mnemonic::Test
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

/// R1: mnemonics whose rsp effect is chain mechanism, not payload.
fn has_implicit_sp(m: Mnemonic) -> bool {
    matches!(
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
    )
}

fn is_sp(r: Register) -> bool {
    matches!(r, Register::SP | Register::ESP | Register::RSP)
}

fn reg_name(r: Register) -> String {
    format!("{r:?}").to_lowercase()
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

/// Final control-transfer anchors (skipped for side-effect accounting,
/// R10 — except the dispatcher check, R8).
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

/// Labels one decoded instruction; also feeds regs_read/regs_written.
/// Returns the label set for this instruction.
fn labels_for_insn(
    insn: &Instruction,
    factory: &mut InstructionInfoFactory,
    regs_read: &mut Vec<String>,
    regs_written: &mut Vec<String>,
) -> Vec<Class> {
    let m = insn.mnemonic();
    let mut labels = Vec::new();
    let info = factory.info(insn);

    // R2
    if is_syscall(m) {
        labels.push(Class::Syscall);
    }

    // Register effects (R1: implicit rsp of push/pop/call/ret excluded;
    // RIP excluded — RIP-relative addressing is not a payload read).
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
            push_unique(regs_read, reg_name(r));
        }
        if access_writes(u.access()) {
            push_unique(regs_written, reg_name(r));
        }
    }

    // Memory effects (R1: stack operands excluded — RSP/ESP-based, and
    // any operand of a push/pop family instruction).
    let mut mem_read = false;
    let mut mem_write = false;
    for u in info.used_memory() {
        let stack_op = is_sp(u.base()) || is_sp(u.segment()) || implicit_sp;
        if stack_op {
            continue;
        }
        if access_reads(u.access()) {
            mem_read = true;
        }
        if access_writes(u.access()) {
            mem_write = true;
        }
    }
    // R3/R4
    if mem_write {
        labels.push(Class::MemWrite);
    }
    if mem_read {
        labels.push(Class::MemRead);
    }

    // R5: explicit rsp destination (mov/xchg/add/sub/pop rsp, leave).
    let writes_sp_explicit = !implicit_sp
        && info
            .used_registers()
            .iter()
            .any(|u| is_sp(u.register()) && access_writes(u.access()));
    let pop_sp = m == Mnemonic::Pop
        && insn.op_count() > 0
        && insn.op_kind(0) == OpKind::Register
        && is_sp(insn.op_register(0));
    let xchg_sp = m == Mnemonic::Xchg
        && ((insn.op_kind(0) == OpKind::Register && is_sp(insn.op_register(0)))
            || (insn.op_count() > 1
                && insn.op_kind(1) == OpKind::Register
                && is_sp(insn.op_register(1))));
    let leave = m == Mnemonic::Leave;
    if writes_sp_explicit || pop_sp || xchg_sp || leave {
        labels.push(Class::StackPivot);
    }

    // R6
    if is_arithmetic(m) {
        labels.push(Class::Arithmetic);
    }

    // R7: writes a GPR (8/16/32/64 general-purpose register — excludes the
    // flags register, xmm/ymm, segments, and rsp handled above), no
    // non-stack memory operand, not a control/gate instruction.
    let writes_gpr = info.used_registers().iter().any(|u| {
        let r = u.register();
        (r.is_gpr8() || r.is_gpr16() || r.is_gpr32() || r.is_gpr64())
            && !is_sp(r)
            && access_writes(u.access())
    });
    if writes_gpr && !mem_read && !mem_write && !is_syscall(m) {
        labels.push(Class::RegWrite);
    }

    labels
}

/// R8 dispatcher heuristic: register-indirect jump anchor, or `jmp reg`
/// where an earlier instruction arithmetically modifies `reg`.
fn dispatcher_heuristic(insns: &[Instruction], factory: &mut InstructionInfoFactory) -> bool {
    let Some(last) = insns.last() else {
        return false;
    };
    if last.mnemonic() != Mnemonic::Jmp {
        return false;
    }
    // jmp qword ptr [reg] / [reg+off] — register-indirect
    if last.op_count() > 0 && last.op_kind(0) == OpKind::Memory {
        let base = last.memory_base();
        if base != Register::None && !matches!(base, Register::RIP | Register::EIP) {
            return true;
        }
    }
    // jmp reg with an earlier arithmetic modification of reg
    if last.op_count() > 0 && last.op_kind(0) == OpKind::Register {
        let target = last.op_register(0);
        for insn in &insns[..insns.len() - 1] {
            if !is_arithmetic(insn.mnemonic()) {
                continue;
            }
            let info = factory.info(insn);
            if info
                .used_registers()
                .iter()
                .any(|u| u.register() == target && access_writes(u.access()))
            {
                return true;
            }
        }
    }
    false
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
    let mut side_effects = 0usize;
    let mut last_class: Option<Class> = None;

    let n = insns.len();
    for (i, insn) in insns.iter().enumerate() {
        // R10: skip the final control-transfer anchor and nops for
        // side-effect accounting (the anchor is the gadget mechanism).
        // iced marks syscall as FlowControl::Call — syscall gates are
        // payload, not mechanism, and are exempt (R2).
        let is_anchor =
            i == n - 1 && is_control_anchor(insn.flow_control()) && !is_syscall(insn.mnemonic());
        if is_anchor || insn.mnemonic() == Mnemonic::Nop {
            continue;
        }
        let insn_labels = labels_for_insn(insn, &mut factory, &mut regs_read, &mut regs_written);
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
    Classification {
        primary,
        labels,
        regs_written,
        regs_read,
        side_effects,
        quality: quality_score(side_effects, g.insns.len()),
        dispatcher,
        low_confidence: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify;
    use rf_core::Arch;

    fn gadget(bytes: &[u8], text: &str) -> Gadget {
        Gadget {
            vaddr: 0x401000,
            bytes: bytes.to_vec(),
            insns: text.split(" ; ").map(|s| s.to_string()).collect(),
            delay_slot: false,
        }
    }

    #[test]
    fn pop_rdi_is_clean_reg_write() {
        // 5f c3 = pop rdi ; ret
        let c = classify(&gadget(b"\x5f\xc3", "pop rdi ; ret"), Arch::X64);
        assert_eq!(c.primary, Class::RegWrite);
        assert_eq!(c.labels, vec![Class::RegWrite]);
        assert_eq!(c.regs_written, vec!["rdi"]);
        // R1: implicit rsp effect of pop is normalized away
        assert!(!c.regs_written.contains(&"rsp".to_string()));
        assert!(!c.regs_read.contains(&"rsp".to_string()));
        assert_eq!(c.side_effects, 1);
        assert_eq!(c.quality, 100);
        assert!(!c.low_confidence);
    }

    #[test]
    fn mov_store_is_mem_write() {
        // 48 89 07 c3 = mov qword ptr [rdi], rax ; ret
        let c = classify(
            &gadget(b"\x48\x89\x07\xc3", "mov qword ptr [rdi], rax ; ret"),
            Arch::X64,
        );
        assert_eq!(c.primary, Class::MemWrite);
        assert!(c.regs_read.contains(&"rax".to_string()));
        assert!(c.regs_read.contains(&"rdi".to_string()));
        assert!(!c.labels.contains(&Class::RegWrite));
    }

    #[test]
    fn xor_self_is_regwrite_and_arithmetic() {
        // 48 31 c0 c3 = xor rax, rax ; ret  (multi-label, R6+R7)
        let c = classify(
            &gadget(b"\x48\x31\xc0\xc3", "xor rax, rax ; ret"),
            Arch::X64,
        );
        assert!(c.labels.contains(&Class::RegWrite));
        assert!(c.labels.contains(&Class::Arithmetic));
        // R10 precedence: arithmetic > reg-write
        assert_eq!(c.primary, Class::Arithmetic);
    }

    #[test]
    fn syscall_is_labeled_even_as_anchor() {
        // 0f 05 = syscall
        let c = classify(&gadget(b"\x0f\x05", "syscall"), Arch::X64);
        assert_eq!(c.primary, Class::Syscall);
    }

    #[test]
    fn pivots() {
        // 48 94 c3 = xchg rsp, rax ; ret
        let c = classify(&gadget(b"\x48\x94\xc3", "xchg rsp, rax ; ret"), Arch::X64);
        assert_eq!(c.primary, Class::StackPivot);
        // 5c c3 = pop rsp ; ret
        let c = classify(&gadget(b"\x5c\xc3", "pop rsp ; ret"), Arch::X64);
        assert_eq!(c.primary, Class::StackPivot);
        // c9 c3 = leave ; ret
        let c = classify(&gadget(b"\xc9\xc3", "leave ; ret"), Arch::X64);
        assert_eq!(c.primary, Class::StackPivot);
    }

    #[test]
    fn primary_is_last_side_effect() {
        // 58 48 01 d8 c3 = pop rax ; add rax, rbx ; ret
        let c = classify(
            &gadget(b"\x58\x48\x01\xd8\xc3", "pop rax ; add rax, rbx ; ret"),
            Arch::X64,
        );
        assert_eq!(c.primary, Class::Arithmetic);
        assert_eq!(c.side_effects, 2);
        assert_eq!(c.quality, 82); // 100 - 15*1 - 3*1
    }

    #[test]
    fn dispatcher_indirect_jmp_mem() {
        // ff 20 = jmp qword ptr [rax]
        let c = classify(&gadget(b"\xff\x20", "jmp qword ptr [rax]"), Arch::X64);
        assert!(c.dispatcher);
        assert_eq!(c.primary, Class::Dispatcher);
    }

    #[test]
    fn dispatcher_loop_form() {
        // 48 83 c0 08 ff e0 = add rax, 8 ; jmp rax
        let c = classify(
            &gadget(b"\x48\x83\xc0\x08\xff\xe0", "add rax, 0x8 ; jmp rax"),
            Arch::X64,
        );
        assert!(c.dispatcher);
        assert!(c.labels.contains(&Class::Dispatcher));
    }

    #[test]
    fn plain_jmp_reg_is_not_dispatcher() {
        // ff e0 = jmp rax (no arithmetic on rax)
        let c = classify(&gadget(b"\xff\xe0", "jmp rax"), Arch::X64);
        assert!(!c.dispatcher);
        assert_eq!(c.primary, Class::Other);
    }
}
