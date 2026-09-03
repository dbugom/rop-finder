//! x86/x64 stack delta, register-transfer relations and clobber set
//! (CLS-09), computed inside the decode pass the classifier already runs.
//!
//! # Stack delta
//!
//! The number reported is **the net change of the stack pointer from the
//! first byte of the gadget to the moment the terminating transfer has
//! completed** — exactly what a concrete execution of the gadget's whole
//! instruction sequence leaves in `rsp`. `pop rdi ; ret` is therefore `+16`
//! on x86-64 (8 for the pop, 8 for the return address the `ret` consumes),
//! not `+8`: what a chain author needs is how many payload bytes the gadget
//! eats, and the return address is one of them. It is also the definition an
//! emulator can *measure* rather than re-derive, which is what
//! `tests/ground-truth/oracle_unicorn.py` does.
//!
//! Contributions:
//!
//! * every push/pop-family instruction, `call`, `ret`, `ret imm16`, `retf`,
//!   `retf imm16`, `pusha`/`popa`, `pushf`/`popf` and `enter` — through
//!   iced's own `Instruction::stack_pointer_increment`, which encodes the
//!   operand-size rules (`push ax` is 2, `push rax` is 8) that a hand-written
//!   width table gets wrong;
//! * `inc`/`dec rsp`, `add`/`sub rsp, imm` and `lea rsp, [rsp + disp]`, which
//!   iced reports as 0 because they are not stack instructions.
//!
//! # `None` is an answer, not a failure
//!
//! A confident wrong stack delta silently corrupts a chain layout, so `None`
//! is reported for every gadget whose stack-pointer effect this analysis
//! cannot *prove* constant:
//!
//! | case | why |
//! |---|---|
//! | `xchg rsp, rax`, `mov rsp, rbp`, `pop rsp` | the new `rsp` is a value, not an offset |
//! | `add rsp, rax`, `and rsp, 0xfffffff0` | the adjustment is not an immediate |
//! | `leave` | `rsp <- rbp + 8`; iced deliberately reports 0 for it |
//! | `iret`/`iretd`/`iretq` | the pop count depends on a privilege change |
//! | `add esp, 8` in 64-bit code | a 32-bit write truncates `rsp`, it does not offset it |
//! | any branch before the last instruction | the executed sequence is not the printed one |
//! | an undecodable byte, or a decode that disagrees with the scanner's own text | there is no instruction stream to reason about |
//!
//! # Clobbered versus set
//!
//! A register the gadget writes is **set** when the value it ends up holding
//! is decided by the chain payload or by a constant — the chain author can
//! choose it, or at least predict it, from nothing but the bytes they are
//! about to write. It is **clobbered** when the value depends on the incoming
//! register state, on non-stack memory, or on the incoming flags: the write
//! happens either way, but the author does not get to say what lands there.
//!
//! `mov rdi, rax ; ret` therefore *clobbers* rdi — this gadget does not
//! control rax — while recording the transfer `rdi <- rax`, which is what
//! tells a chain builder it can control rdi by controlling rax first. Two
//! different questions, both answered.
//!
//! The lattice is four-valued and deliberately tiny: `Stack` (straight off
//! the payload, with the entry-relative offset), `Const` (a folded immediate,
//! including the `xor r, r` / `sub r, r` / `and r, 0` zeroing idioms),
//! `Derived` (a known function of payload and constants) and `Unknown`.
//! Anything joined with `Unknown` is `Unknown`, and a join over *no* sources
//! is `Unknown` — which is why `rdtsc` clobbers rather than sets.
//!
//! Three things sit beside it, and every one of them is here because the
//! emulated ground truth in `tests/ground-truth/` caught the analysis being
//! wrong without them:
//!
//! * **store forwarding** ([`Analyzer::stack_read`]). A stack slot the gadget
//!   itself wrote is not the chain payload. Without it
//!   `push qword ptr [rbp + 2] ; pop rbx ; ret` claimed rbx was a controlled
//!   load; with it, the value that was pushed is forwarded, so
//!   `push rax ; pop rbx ; ret` also becomes the transfer `rbx <- rax` it
//!   actually is.
//! * **known-zero bits** ([`zero_bits`]). `and al, 0x68 ; … ; and eax, 1`
//!   leaves eax holding exactly 0, which the four-valued lattice alone cannot
//!   see. The same domain is what makes `and al, 0xff` an identity rather than
//!   a clobber.
//! * **a stack read at an unknown offset is `Unknown`, not `Stack`**. After
//!   `add esp, 0x120` in 64-bit code the running delta is gone, and a `pop`
//!   from wherever rsp now points is not the payload the author laid out.
//!
//! Register names in `sets`/`clobbers` are **architectural full-width** names
//! (`rax` in 64-bit code, `eax` in 32-bit), because `mov al, [rsp]` leaves the
//! top 56 bits of rax holding whatever they held before: al is controlled and
//! rax is not, and the question a chain author asks is about rax.
//! `regs_written` keeps the operand's own spelling and is unchanged.
//!
//! # Cost
//!
//! Measured by `tests/effect_cost.rs` on this machine, release, depth 10:
//! classifying `elf-x64-bash-v4.1.5.1` takes 1027 ns/gadget with this pass
//! and 659 ns/gadget with `Analyzer::step` stubbed out — so the semantic
//! layer costs about 0.37 µs per *classified* gadget. It shares the
//! classifier's decode and its single `InstructionInfoFactory::info` call per
//! instruction, and `Vec::new()` does not allocate, so a gadget with nothing
//! to report costs three null pointers. `rf_scan` never calls the classifier,
//! so a scan that is not classified pays none of it.

use std::collections::BTreeMap;

use iced_x86::{
    Code, FlowControl, Instruction, InstructionInfo, Mnemonic, OpAccess, OpKind, Register,
};

use crate::effect::{TerminatorTarget, Transfer, ValueDst, ValueSrc};

/// Everything this pass produces for one gadget.
pub(crate) struct Effects {
    pub stack_delta: Option<i64>,
    pub transfers: Vec<Transfer>,
    pub sets: Vec<String>,
    pub clobbers: Vec<String>,
    pub target: TerminatorTarget,
}

/// The value lattice. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Val {
    /// Loaded straight off the chain payload, at this entry-relative offset.
    /// A stack read whose offset is NOT known — because the running delta
    /// stopped being constant — is `Unknown`, not `Stack`: a value read from
    /// wherever `rsp` happens to point after `xchg rsp, rax` is not the
    /// payload the chain author laid out.
    Stack(i64),
    /// A compile-time constant.
    Const(i64),
    /// A known function of payload bytes and constants.
    Derived,
    /// Depends on incoming registers, incoming flags, or non-stack memory.
    Unknown,
}

impl Val {
    fn controlled(self) -> bool {
        !matches!(self, Val::Unknown)
    }
}

fn join(a: Val, b: Val) -> Val {
    if a.controlled() && b.controlled() {
        Val::Derived
    } else {
        Val::Unknown
    }
}

fn is_sp(r: Register) -> bool {
    matches!(r, Register::SP | Register::ESP | Register::RSP)
}

fn is_ip(r: Register) -> bool {
    matches!(r, Register::RIP | Register::EIP)
}

/// The architectural full-width register `r` is part of, or `None` when `r`
/// is not a general-purpose register this analysis tracks (flags, segments,
/// xmm, rip) or is the stack pointer — whose movement is the stack delta, not
/// a clobber.
fn canon(r: Register, bits: u32) -> Option<Register> {
    if !(r.is_gpr8() || r.is_gpr16() || r.is_gpr32() || r.is_gpr64()) {
        return None;
    }
    let full = if bits == 64 {
        r.full_register()
    } else {
        r.full_register32()
    };
    if is_sp(full) {
        return None;
    }
    Some(full)
}

/// Does a write to `r` replace the whole architectural register? A 32-bit
/// write zero-extends in 64-bit mode, so it does; an 8- or 16-bit write
/// leaves the upper bits alone, so it does not.
fn is_full_write(r: Register, bits: u32) -> bool {
    if bits == 64 {
        r.is_gpr64() || r.is_gpr32()
    } else {
        r.is_gpr32()
    }
}

/// All-ones mask for a value `size` bytes wide.
fn width_mask(size: usize) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// `ah`/`ch`/`dh`/`bh` live in bits 8..15 of their full register rather than
/// the low byte. Rather than carry a shifted window through the whole
/// analysis, a write to one is modelled as "those bits become unknown", which
/// is sound and costs one rare gadget shape.
fn is_high_byte(r: Register) -> bool {
    matches!(r, Register::AH | Register::CH | Register::DH | Register::BH)
}

/// Lowercase register names, built once and indexed by discriminant.
///
/// The obvious spelling — `format!("{r:?}").to_lowercase()`, which is what
/// `x86::reg_name` did — runs the whole `core::fmt` machinery and two
/// allocations for a string that is ASCII and fixed at compile time. A
/// register name is produced for every entry of `regs_written`, `regs_read`,
/// `sets`, `clobbers` and both ends of every transfer, which made this the
/// hottest thing in the classifier; the table turns it into an index and one
/// short `to_string`.
pub(crate) fn reg_str(r: Register) -> &'static str {
    static NAMES: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    let table = NAMES.get_or_init(|| {
        let mut v: Vec<String> = Vec::new();
        for reg in Register::values() {
            let i = reg as usize;
            if v.len() <= i {
                v.resize(i + 1, String::new());
            }
            let mut s = format!("{reg:?}");
            s.make_ascii_lowercase();
            v[i] = s;
        }
        v
    });
    table.get(r as usize).map_or("", String::as_str)
}

fn name(r: Register) -> String {
    reg_str(r).to_string()
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

/// A conditional or read-modify-write access keeps the destination's previous
/// value in play, so the old value has to join into the new one.
fn access_keeps_old(a: OpAccess) -> bool {
    matches!(
        a,
        OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}

fn is_syscall(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Syscall
            | Mnemonic::Sysenter
            | Mnemonic::Sysexit
            | Mnemonic::Sysret
            | Mnemonic::Int
            | Mnemonic::Int1
            | Mnemonic::Int3
            | Mnemonic::Into
    )
}

fn is_immediate_kind(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// The immediate value of operand `k`, or `None` when it is not an immediate.
/// iced zero-extends the fixed-width forms and sign-extends the `*to*` forms,
/// which is what the encoding means.
fn imm_of(insn: &Instruction, k: u32) -> Option<i64> {
    insn.try_immediate(k).ok().map(|v| v as i64)
}

/// The signed displacement of the instruction's memory operand. For an
/// `EIP`/`RIP`-relative operand iced stores the resolved absolute address
/// here; callers test the base register before using the value as an offset.
fn mem_disp(insn: &Instruction, bits: u32) -> i64 {
    if bits == 64 {
        insn.memory_displacement64() as i64
    } else {
        insn.memory_displacement32() as i32 as i64
    }
}

fn opt_reg(r: Register) -> Option<String> {
    if r == Register::None || is_ip(r) {
        None
    } else {
        Some(name(r))
    }
}

/// Width in bytes of the value the instruction moves, when the decoder states
/// it.
fn transfer_width(insn: &Instruction) -> Option<u32> {
    if (0..insn.op_count()).any(|k| insn.op_kind(k) == OpKind::Memory) {
        let s = insn.memory_size().size();
        if s > 0 {
            return Some(s as u32);
        }
    }
    for k in 0..insn.op_count() {
        if insn.op_kind(k) == OpKind::Register {
            let s = insn.op_register(k).size();
            if s > 0 {
                return Some(s as u32);
            }
        }
    }
    None
}

/// Constant folding for the handful of forms that actually appear as gadget
/// bodies. `None` when the result is not provably constant.
fn fold(m: Mnemonic, a: i64, b: i64) -> Option<i64> {
    Some(match m {
        Mnemonic::Add => a.wrapping_add(b),
        Mnemonic::Sub => a.wrapping_sub(b),
        Mnemonic::And => a & b,
        Mnemonic::Or => a | b,
        Mnemonic::Xor => a ^ b,
        _ => return None,
    })
}

/// Zeroing and identity idioms. These decide whether a register a gadget
/// "writes" is actually controlled: `xor eax, eax` gives rax a value the
/// chain author picked, and `or rax, rax` does not write it at all.
enum Idiom {
    /// The destination is left bit-for-bit unchanged.
    Identity,
    /// The destination becomes this constant regardless of its old value.
    Constant(i64),
    None,
}

/// `opmask` is the all-ones mask of the destination operand's width, which is
/// what makes `and al, 0xff` an identity and `and eax, 0xffffffff` an
/// identity while `and rax, 0xffffffff` is not.
fn idiom(insn: &Instruction, opmask: u64) -> Idiom {
    let m = insn.mnemonic();
    if insn.op_count() != 2 {
        return Idiom::None;
    }
    if insn.op_kind(0) == OpKind::Register
        && insn.op_kind(1) == OpKind::Register
        && insn.op_register(0) == insn.op_register(1)
    {
        return match m {
            Mnemonic::Xor | Mnemonic::Sub => Idiom::Constant(0),
            Mnemonic::Mov | Mnemonic::And | Mnemonic::Or | Mnemonic::Xchg => Idiom::Identity,
            _ => Idiom::None,
        };
    }
    if insn.op_kind(0) == OpKind::Register {
        if let Some(imm) = imm_of(insn, 1) {
            let i = (imm as u64) & opmask;
            return match m {
                Mnemonic::And if i == 0 => Idiom::Constant(0),
                Mnemonic::And if i == opmask => Idiom::Identity,
                Mnemonic::Or if i == opmask => Idiom::Constant(opmask as i64),
                Mnemonic::Or
                | Mnemonic::Xor
                | Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Shl
                | Mnemonic::Shr
                | Mnemonic::Sar
                    if i == 0 =>
                {
                    Idiom::Identity
                }
                _ => Idiom::None,
            };
        }
    }
    Idiom::None
}

/// Bits of the result that are provably zero, for the two-operand forms whose
/// bit behaviour is simple enough to state. Everything else returns 0 — "no
/// bit is known" — which is always sound.
///
/// This tiny domain exists because the four-valued lattice alone cannot see
/// that `and al, 0x68 ; … ; and eax, 1` leaves eax holding exactly 0: the
/// first `and` proves bit 0 of eax is zero, and the second masks eax down to
/// that bit. Without it the analysis reports a false clobber, which is a
/// gadget lost rather than a chain corrupted — but the emulator sees the
/// truth, so the analysis has to as well.
fn zero_bits(m: Mnemonic, old_zero: u64, src_zero: u64, imm: Option<u64>, opmask: u64) -> u64 {
    let z = match (m, imm) {
        (Mnemonic::Mov, Some(i)) => !i,
        (Mnemonic::Mov, None) => src_zero,
        (Mnemonic::And, Some(i)) => !i | old_zero,
        (Mnemonic::And, None) => src_zero | old_zero,
        (Mnemonic::Or, Some(i)) => old_zero & !i,
        (Mnemonic::Or, None) => old_zero & src_zero,
        (Mnemonic::Xor, Some(i)) => old_zero & !i,
        (Mnemonic::Xor, None) => old_zero & src_zero,
        (Mnemonic::Shl, Some(i)) => {
            let n = (i & 63) as u32;
            (old_zero << n) | ((1u64 << n) - 1)
        }
        (Mnemonic::Shr, Some(i)) => {
            let n = (i & 63) as u32;
            ((old_zero & opmask) >> n) | (opmask & !(opmask >> n))
        }
        (Mnemonic::Sar, Some(i)) => ((old_zero & opmask) >> ((i & 63) as u32)) & opmask,
        _ => 0,
    };
    z & opmask
}

/// One stack slot this gadget wrote, and what went into it.
struct StackWrite {
    start: i64,
    end: i64,
    val: Val,
    /// How to describe the stored value to a consumer, when it is known.
    src: Option<ValueSrc>,
}

/// The analysis state, stepped one instruction at a time by
/// [`Analyzer::step`] from inside the classifier's own decode loop — so the
/// `InstructionInfoFactory` is consulted exactly once per instruction, not
/// twice.
pub(crate) struct Analyzer {
    bits: u32,
    /// Running net stack-pointer delta from gadget entry, `None` once it
    /// stops being provably constant.
    sp: Option<i64>,
    /// The delta as it stood *before* the instruction being stepped — what a
    /// payload offset is measured from.
    sp_at: Option<i64>,
    /// Full-width registers the gadget has written, and what they hold. A
    /// register absent from the map has never been written and still holds
    /// the caller's incoming value.
    vals: BTreeMap<Register, Val>,
    /// Per full-width register, the mask of bits provably zero. See
    /// [`zero_bits`].
    zeros: BTreeMap<Register, u64>,
    /// Stack slots, in gadget-entry-relative offsets, that this gadget has
    /// WRITTEN, and what it put there. A read from one of them is not the
    /// chain payload — it is the gadget's own value — which is how
    /// `push qword ptr [rbp + 2] ; pop rbx ; ret` stops looking like a
    /// controlled load of rbx, and how `push rax ; pop rbx ; ret` becomes the
    /// register transfer `rbx <- rax` that it actually is.
    dirty: Vec<StackWrite>,
    /// A stack write at an offset that was not constant: every later stack
    /// read is suspect.
    dirty_all: bool,
    /// The flags register, tracked so `sbb rax, rax` and `cmovz` join in the
    /// right uncontrolled dependency.
    flags: Val,
    transfers: Vec<Transfer>,
    /// Set when the instruction stream stops being trustworthy (an
    /// undecodable byte, a mid-gadget branch, a decode that disagrees with
    /// the scanner's text). Nothing further is recorded and the stack delta
    /// is `None`.
    bail: bool,
    target: TerminatorTarget,
}

impl Analyzer {
    /// `trustworthy` is false when the decode does not agree with the text
    /// the scanner printed for this gadget, in which case nothing is claimed.
    pub(crate) fn new(bits: u32, trustworthy: bool) -> Analyzer {
        Analyzer {
            bits,
            sp: if trustworthy { Some(0) } else { None },
            sp_at: None,
            vals: BTreeMap::new(),
            zeros: BTreeMap::new(),
            dirty: Vec::new(),
            dirty_all: !trustworthy,
            flags: Val::Unknown,
            transfers: Vec::new(),
            bail: !trustworthy,
            target: TerminatorTarget::Implicit,
        }
    }

    pub(crate) fn finish(self) -> Effects {
        let mut sets = Vec::new();
        let mut clobbers = Vec::new();
        for (r, v) in &self.vals {
            if v.controlled() {
                sets.push(name(*r));
            } else {
                clobbers.push(name(*r));
            }
        }
        sets.sort_unstable();
        clobbers.sort_unstable();
        Effects {
            stack_delta: self.sp,
            transfers: self.transfers,
            sets,
            clobbers,
            target: self.target,
        }
    }

    fn get(&self, full: Register) -> Val {
        self.vals.get(&full).copied().unwrap_or(Val::Unknown)
    }

    fn reg_val(&self, r: Register) -> Val {
        canon(r, self.bits).map_or(Val::Unknown, |f| self.get(f))
    }

    fn zero_of(&self, r: Register) -> u64 {
        canon(r, self.bits).map_or(0, |f| *self.zeros.get(&f).unwrap_or(&0))
    }

    /// The all-ones mask of an architectural register on this target.
    fn full_mask(&self) -> u64 {
        if self.bits == 64 {
            u64::MAX
        } else {
            0xFFFF_FFFF
        }
    }

    /// What a read of `w` bytes at entry-relative stack offset `off` yields.
    ///
    /// Untouched stack is the chain payload. A slot this gadget wrote returns
    /// what the gadget wrote — forwarded exactly when the widths line up, and
    /// opaque when they only partially overlap.
    fn stack_read(&self, off: Option<i64>, w: i64) -> (Option<ValueSrc>, Val) {
        let Some(o) = off else {
            return (None, Val::Unknown);
        };
        if self.dirty_all {
            return (Some(ValueSrc::Computed), Val::Unknown);
        }
        let w = w.max(1);
        let mut hit: Option<(Option<ValueSrc>, Val)> = None;
        for sw in &self.dirty {
            if o < sw.end && o + w > sw.start {
                hit = Some(if sw.start == o && sw.end == o + w {
                    (sw.src.clone(), sw.val)
                } else {
                    (Some(ValueSrc::Computed), Val::Unknown)
                });
            }
        }
        hit.unwrap_or((None, Val::Stack(o)))
    }

    fn mark_dirty(&mut self, off: Option<i64>, w: Option<u32>, val: Val, src: Option<ValueSrc>) {
        match off {
            Some(o) => {
                let w = i64::from(w.unwrap_or(1)).max(1);
                self.dirty.push(StackWrite {
                    start: o,
                    end: o + w,
                    val,
                    src,
                });
            }
            None => self.dirty_all = true,
        }
    }

    /// Record a write of `v` to `r`, widening a partial write correctly.
    ///
    /// `zbits` is the mask of result bits provably zero, expressed in the
    /// destination operand's own width.
    fn write(&mut self, r: Register, v: Val, zbits: u64) {
        let Some(full) = canon(r, self.bits) else {
            return;
        };
        let fullmask = self.full_mask();
        let high_byte = is_high_byte(r);
        let opmask = if high_byte {
            0xFF00
        } else {
            width_mask(r.size()) & fullmask
        };
        let zbits = if high_byte { 0 } else { zbits & opmask };
        let old_zero = *self.zeros.get(&full).unwrap_or(&0);
        let full_write = is_full_write(r, self.bits);
        let new_zero = if self.bail {
            0
        } else if full_write {
            // A 32-bit write in 64-bit mode zero-extends, so the top half is
            // provably zero.
            zbits | (fullmask & !opmask)
        } else {
            (old_zero & !opmask) | zbits
        };
        self.zeros.insert(full, new_zero);

        let v = if self.bail {
            Val::Unknown
        } else if new_zero == fullmask {
            // Every bit of the register is provably zero, so its value is 0
            // however it got there.
            Val::Const(0)
        } else if full_write {
            v
        } else {
            // The untouched upper bits carry the old value forward.
            join(self.get(full), v)
        };
        self.vals.insert(full, v);
    }

    fn emit(&mut self, t: Transfer) {
        if !self.bail {
            self.transfers.push(t);
        }
    }

    /// One instruction. `anchor` marks the gadget's terminating control
    /// transfer (its value effects are mechanism, its stack effect is not);
    /// `last` says whether it is the final instruction.
    pub(crate) fn step(
        &mut self,
        insn: &Instruction,
        info: &InstructionInfo,
        anchor: bool,
        last: bool,
    ) {
        if insn.code() == Code::INVALID {
            self.bail = true;
            self.sp = None;
            return;
        }
        if anchor {
            self.target = terminator_target(insn, self.bits);
        }
        // A transfer of control that is not the gadget's own terminator means
        // the instructions printed after it may never run. Syscall gates are
        // exempt: iced models `syscall` as FlowControl::Call, but it returns.
        if !last && insn.flow_control() != FlowControl::Next && !is_syscall(insn.mnemonic()) {
            self.bail = true;
            self.sp = None;
        }
        self.sp_at = self.sp;
        self.step_stack(insn, info);
        if !anchor {
            self.step_values(insn, info);
        }
    }

    // -- stack delta ------------------------------------------------------

    fn step_stack(&mut self, insn: &Instruction, info: &InstructionInfo) {
        let Some(d) = self.sp else { return };
        let m = insn.mnemonic();
        // `leave` is `mov rsp, rbp ; pop rbp`: the new rsp is rbp + 8, not an
        // offset from the old rsp. iced deliberately reports 0 for it, which
        // would be a confident wrong answer.
        if m == Mnemonic::Leave {
            self.sp = None;
            return;
        }
        // iced's own documentation: the increment "assumes the instruction
        // doesn't change the privilege level (eg. IRET/D/Q)".
        if matches!(m, Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq) {
            self.sp = None;
            return;
        }
        let sp_operand_written = (0..insn.op_count()).any(|k| {
            insn.op_kind(k) == OpKind::Register
                && is_sp(insn.op_register(k))
                && access_writes(info.op_access(k))
        });
        if !sp_operand_written {
            // Only the implicit push/pop/call/ret mechanism moved it, and
            // iced knows the width rules.
            self.sp = Some(d + i64::from(insn.stack_pointer_increment()));
            return;
        }
        self.sp = sp_adjust(insn, self.bits).map(|adj| d + adj);
    }

    // -- value flow -------------------------------------------------------

    fn mem_source(&self, insn: &Instruction) -> (ValueSrc, Val) {
        let base = insn.memory_base();
        let index = insn.memory_index();
        let disp = mem_disp(insn, self.bits);
        if is_ip(base) {
            // Statically addressed data: its address is known, its contents
            // are whatever the image or the runtime put there.
            return (
                ValueSrc::Memory {
                    base: None,
                    index: opt_reg(index),
                    disp,
                },
                Val::Unknown,
            );
        }
        if is_sp(base) && index == Register::None {
            let off = self.sp_at.map(|d| d + disp);
            let (src, v) = self.stack_read(off, insn.memory_size().size() as i64);
            return (src.unwrap_or(ValueSrc::Stack { offset: off }), v);
        }
        (
            ValueSrc::Memory {
                base: opt_reg(base),
                index: opt_reg(index),
                disp,
            },
            Val::Unknown,
        )
    }

    fn mem_dest(&self, insn: &Instruction) -> ValueDst {
        let base = insn.memory_base();
        let index = insn.memory_index();
        let disp = mem_disp(insn, self.bits);
        if is_sp(base) && index == Register::None {
            return ValueDst::Stack {
                offset: self.sp_at.map(|d| d + disp),
            };
        }
        ValueDst::Memory {
            base: if is_ip(base) { None } else { opt_reg(base) },
            index: opt_reg(index),
            disp,
        }
    }

    fn operand_source(&self, insn: &Instruction, k: u32) -> (ValueSrc, Val) {
        match insn.op_kind(k) {
            OpKind::Register => {
                let r = insn.op_register(k);
                // The stack pointer's value is an address, not a payload
                // byte: nothing in the chain chooses it. A segment SELECTOR,
                // on the other hand, is a fixed constant of the running
                // process — `push cs ; pop eax` puts a value in eax the chain
                // author cannot choose but can predict, which is the
                // definition of "set" here, and is what the emulator observes.
                let v = if is_sp(r) {
                    Val::Unknown
                } else if r.is_segment_register() {
                    Val::Derived
                } else {
                    self.reg_val(r)
                };
                (ValueSrc::Register { reg: name(r) }, v)
            }
            OpKind::Memory => self.mem_source(insn),
            kind if is_immediate_kind(kind) => {
                let v = imm_of(insn, k).unwrap_or(0);
                (ValueSrc::Immediate { value: v }, Val::Const(v))
            }
            _ => (ValueSrc::Computed, Val::Unknown),
        }
    }

    fn needs_of(&self, insn: &Instruction) -> Vec<String> {
        let mut v = Vec::new();
        for r in [insn.memory_base(), insn.memory_index()] {
            if r == Register::None || is_sp(r) {
                continue;
            }
            if let Some(n) = opt_reg(r) {
                if !v.contains(&n) {
                    v.push(n);
                }
            }
        }
        v
    }

    fn step_values(&mut self, insn: &Instruction, info: &InstructionInfo) {
        let m = insn.mnemonic();
        if m == Mnemonic::Nop {
            return;
        }
        let sp_before = self.sp_at;

        match m {
            Mnemonic::Pop => {
                // The SLOT the pop consumes is `stack_pointer_increment` wide,
                // which is not the operand width: `pop es` moves a 2-byte
                // selector out of a 4-byte slot, and reading the slot as 2
                // bytes makes a preceding `push es` look like a partial
                // overlap rather than the exact store it is.
                let slot = insn.stack_pointer_increment().unsigned_abs().max(1);
                let width = Some(slot);
                let (fwd, v) = self.stack_read(sp_before, i64::from(slot));
                let src = fwd.unwrap_or(ValueSrc::Stack { offset: sp_before });
                match insn.op_kind(0) {
                    OpKind::Register => {
                        let r = insn.op_register(0);
                        if canon(r, self.bits).is_some() {
                            self.write(r, v, 0);
                            self.emit(Transfer {
                                dst: ValueDst::Register { reg: name(r) },
                                src,
                                needs: Vec::new(),
                                rmw: false,
                                width,
                            });
                        }
                    }
                    OpKind::Memory => {
                        let dst = self.mem_dest(insn);
                        if let ValueDst::Stack { offset } = dst {
                            self.mark_dirty(offset, width, v, Some(src.clone()));
                        }
                        let needs = self.needs_of(insn);
                        self.emit(Transfer {
                            dst,
                            src,
                            needs,
                            rmw: false,
                            width,
                        });
                    }
                    _ => {}
                }
                return;
            }
            Mnemonic::Popa | Mnemonic::Popad => {
                let v = if sp_before.is_some() && !self.dirty_all && self.dirty.is_empty() {
                    Val::Derived
                } else {
                    Val::Unknown
                };
                self.generic_write(insn, info, Some(v));
                return;
            }
            Mnemonic::Push => {
                let width = Some((insn.stack_pointer_increment().unsigned_abs()).max(1));
                let (src, pushed) = self.operand_source(insn, 0);
                let needs = if insn.op_kind(0) == OpKind::Memory {
                    self.needs_of(insn)
                } else {
                    Vec::new()
                };
                let step = i64::from(insn.stack_pointer_increment());
                let offset = sp_before.map(|d| d + step);
                self.mark_dirty(offset, width, pushed, Some(src.clone()));
                self.emit(Transfer {
                    dst: ValueDst::Stack { offset },
                    src,
                    needs,
                    rmw: false,
                    width,
                });
                return;
            }
            Mnemonic::Xchg
                if insn.op_count() == 2
                    && insn.op_kind(0) == OpKind::Register
                    && insn.op_kind(1) == OpKind::Register =>
            {
                let (a, b) = (insn.op_register(0), insn.op_register(1));
                if a == b {
                    return;
                }
                let (va, vb) = (self.reg_val(a), self.reg_val(b));
                let (za, zb) = (self.zero_of(a), self.zero_of(b));
                let opmask = width_mask(a.size());
                self.write(a, vb, zb & opmask);
                self.write(b, va, za & opmask);
                let width = transfer_width(insn);
                self.emit(Transfer {
                    dst: ValueDst::Register { reg: name(a) },
                    src: ValueSrc::Register { reg: name(b) },
                    needs: Vec::new(),
                    rmw: false,
                    width,
                });
                self.emit(Transfer {
                    dst: ValueDst::Register { reg: name(b) },
                    src: ValueSrc::Register { reg: name(a) },
                    needs: Vec::new(),
                    rmw: false,
                    width,
                });
                return;
            }
            Mnemonic::Lea if insn.op_count() == 2 && insn.op_kind(1) == OpKind::Memory => {
                let base = insn.memory_base();
                let index = insn.memory_index();
                let disp = mem_disp(insn, self.bits);
                let rip_rel = is_ip(base);
                let v = if (base == Register::None && index == Register::None) || rip_rel {
                    // A link-time-fixed absolute address.
                    Val::Const(disp)
                } else {
                    let mut acc = Val::Const(disp);
                    for r in [base, index] {
                        if r == Register::None {
                            continue;
                        }
                        let rv = if is_sp(r) {
                            Val::Unknown
                        } else {
                            self.reg_val(r)
                        };
                        acc = join(acc, rv);
                    }
                    acc
                };
                let dst = insn.op_register(0);
                self.write(dst, v, 0);
                self.emit(Transfer {
                    dst: ValueDst::Register { reg: name(dst) },
                    src: ValueSrc::Address {
                        base: if rip_rel { None } else { opt_reg(base) },
                        index: opt_reg(index),
                        disp,
                    },
                    needs: Vec::new(),
                    rmw: false,
                    width: transfer_width(insn),
                });
                return;
            }
            _ => {}
        }

        // Two-operand forms with a single destination — the shape that
        // carries almost every interesting gadget.
        if insn.op_count() == 2
            && matches!(insn.op_kind(0), OpKind::Register | OpKind::Memory)
            && access_writes(info.op_access(0))
        {
            let rmw = access_keeps_old(info.op_access(0));
            let (src_desc, src_val) = self.operand_source(insn, 1);
            let width = transfer_width(insn);
            let needs = if insn.op_kind(0) == OpKind::Memory || insn.op_kind(1) == OpKind::Memory {
                self.needs_of(insn)
            } else {
                Vec::new()
            };
            if insn.op_kind(0) == OpKind::Register {
                let dst = insn.op_register(0);
                let opmask = if is_high_byte(dst) {
                    0
                } else {
                    width_mask(dst.size()) & self.full_mask()
                };
                let (v, zbits) = match idiom(insn, opmask) {
                    Idiom::Identity => {
                        // Nothing is written: `or rax, rax`, `and al, 0xff`.
                        self.flags = self.flags_after(insn);
                        return;
                    }
                    Idiom::Constant(c) => (Val::Const(c), !(c as u64) & opmask),
                    Idiom::None => {
                        let v = if rmw {
                            let old = self.reg_val(dst);
                            match (old, src_val) {
                                (Val::Const(a), Val::Const(b)) => {
                                    fold(m, a, b).map_or(join(old, src_val), Val::Const)
                                }
                                _ => join(old, src_val),
                            }
                        } else {
                            src_val
                        };
                        let src_zero = match insn.op_kind(1) {
                            OpKind::Register => self.zero_of(insn.op_register(1)),
                            _ => 0,
                        };
                        let src_zero = match m {
                            // `movzx r, r/m8` zero-extends: everything above
                            // the source's own width is provably zero.
                            Mnemonic::Movzx => {
                                let sw = match insn.op_kind(1) {
                                    OpKind::Register => width_mask(insn.op_register(1).size()),
                                    _ => width_mask(insn.memory_size().size()),
                                };
                                (src_zero & sw) | !sw
                            }
                            _ => src_zero,
                        };
                        let m2 = if m == Mnemonic::Movzx {
                            Mnemonic::Mov
                        } else {
                            m
                        };
                        (
                            v,
                            zero_bits(
                                m2,
                                self.zero_of(dst),
                                src_zero,
                                imm_of(insn, 1).map(|i| i as u64),
                                opmask,
                            ),
                        )
                    }
                };
                let v = if insn.rflags_read() != 0 {
                    join(v, self.flags)
                } else {
                    v
                };
                self.write(dst, v, zbits);
                self.emit(Transfer {
                    dst: ValueDst::Register { reg: name(dst) },
                    src: src_desc,
                    needs,
                    rmw,
                    width,
                });
            } else {
                let dst = self.mem_dest(insn);
                if let ValueDst::Stack { offset } = dst {
                    let (v, s) = if rmw {
                        (Val::Unknown, None)
                    } else {
                        (src_val, Some(src_desc.clone()))
                    };
                    self.mark_dirty(offset, width, v, s);
                }
                self.emit(Transfer {
                    dst,
                    src: src_desc,
                    needs,
                    rmw,
                    width,
                });
            }
            self.flags = self.flags_after(insn);
            return;
        }

        self.generic_write(insn, info, None);
    }

    /// The fallback: join every source the instruction reads and assign it to
    /// every full-width register it writes. A join over *no* sources is
    /// `Unknown`, which is why `rdtsc` and `cpuid` clobber rather than set.
    fn generic_write(&mut self, insn: &Instruction, info: &InstructionInfo, forced: Option<Val>) {
        let mut acc: Option<Val> = None;
        if forced.is_none() {
            for u in info.used_registers() {
                let r = u.register();
                if !access_reads(u.access()) || is_ip(r) {
                    continue;
                }
                let v = if is_sp(r) {
                    Val::Unknown
                } else {
                    self.reg_val(r)
                };
                acc = Some(acc.map_or(v, |a| join(a, v)));
            }
            for k in 0..insn.op_count() {
                let v = match insn.op_kind(k) {
                    OpKind::Memory => self.mem_source(insn).1,
                    kind if is_immediate_kind(kind) => Val::Const(imm_of(insn, k).unwrap_or(0)),
                    _ => continue,
                };
                acc = Some(acc.map_or(v, |a| join(a, v)));
            }
            if insn.rflags_read() != 0 {
                let f = self.flags;
                acc = Some(acc.map_or(f, |a| join(a, f)));
            }
        }
        let base = forced.or(acc).unwrap_or(Val::Unknown);

        // `info` borrows the factory, not `self`, so the writes can be applied
        // as they are read rather than collected into a Vec first.
        let writes = info
            .used_registers()
            .iter()
            .filter(|u| access_writes(u.access()) && !is_ip(u.register()))
            .map(|u| (u.register(), u.access()));
        for (r, access) in writes {
            let v = if access_keeps_old(access) {
                let old = self.reg_val(r);
                join(old, base)
            } else {
                base
            };
            self.write(r, v, 0);
        }
        // A memory write through the stack pointer puts the gadget's own data
        // where the payload was.
        if info
            .used_memory()
            .iter()
            .any(|u| access_writes(u.access()) && is_sp(u.base()))
        {
            let off = self.sp_at.map(|d| d + mem_disp(insn, self.bits));
            self.mark_dirty(off, transfer_width(insn), Val::Unknown, None);
        }
        self.flags = self.flags_after(insn);
    }

    /// What the flags hold after `insn`, for the instructions that write
    /// them.
    fn flags_after(&self, insn: &Instruction) -> Val {
        if insn.rflags_modified() == 0 {
            return self.flags;
        }
        let mut acc: Option<Val> = None;
        for k in 0..insn.op_count() {
            let v = match insn.op_kind(k) {
                OpKind::Register => {
                    let r = insn.op_register(k);
                    if is_sp(r) {
                        Val::Unknown
                    } else {
                        self.reg_val(r)
                    }
                }
                OpKind::Memory => self.mem_source(insn).1,
                kind if is_immediate_kind(kind) => Val::Const(imm_of(insn, k).unwrap_or(0)),
                _ => Val::Unknown,
            };
            acc = Some(acc.map_or(v, |a| join(a, v)));
        }
        acc.unwrap_or(Val::Unknown)
    }
}

fn terminator_target(insn: &Instruction, bits: u32) -> TerminatorTarget {
    if insn.op_count() == 0 {
        return TerminatorTarget::Implicit;
    }
    match insn.op_kind(0) {
        OpKind::Register => TerminatorTarget::Register {
            reg: name(insn.op_register(0)),
        },
        OpKind::Memory => {
            let base = insn.memory_base();
            TerminatorTarget::Memory {
                base: if is_ip(base) { None } else { opt_reg(base) },
                index: opt_reg(insn.memory_index()),
                disp: mem_disp(insn, bits),
            }
        }
        _ => TerminatorTarget::Direct,
    }
}

/// The provable `rsp` adjustment of `add rsp, imm`, `sub rsp, imm` and
/// `lea rsp, [rsp + disp]`. `None` for every other explicit stack-pointer
/// write — `pop rsp`, `mov rsp, rbp`, `xchg rsp, rax`, `and rsp, -16`,
/// `add rsp, rax`.
fn sp_adjust(insn: &Instruction, bits: u32) -> Option<i64> {
    if insn.op_count() == 0 || insn.op_kind(0) != OpKind::Register {
        return None;
    }
    let dst = insn.op_register(0);
    // `add esp, 8` in 64-bit code writes ESP and zero-extends into RSP: that
    // truncates the stack pointer, it does not offset it.
    let want = if bits == 64 {
        Register::RSP
    } else {
        Register::ESP
    };
    if dst != want {
        return None;
    }
    match insn.mnemonic() {
        // `inc esp` / `dec esp` are the one-operand spelling of `add esp, 1`.
        Mnemonic::Inc if insn.op_count() == 1 => Some(1),
        Mnemonic::Dec if insn.op_count() == 1 => Some(-1),
        Mnemonic::Add if insn.op_count() == 2 => imm_of(insn, 1),
        Mnemonic::Sub if insn.op_count() == 2 => imm_of(insn, 1).map(|v| -v),
        Mnemonic::Lea if insn.op_count() == 2 && insn.op_kind(1) == OpKind::Memory => {
            let base = insn.memory_base();
            if !is_sp(base) || insn.memory_index() != Register::None {
                return None;
            }
            Some(mem_disp(insn, bits))
        }
        _ => None,
    }
}
