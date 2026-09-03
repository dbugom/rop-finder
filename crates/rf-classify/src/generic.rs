//! Classification for the eight architectures that decode through capstone
//! (ARM, ARM64, MIPS 32/64, PowerPC 32/64, SPARC, RISC-V 32/64).
//!
//! Two paths share the rules in this module:
//!
//! * the **metadata path** ([`classify_detail`]), driven by capstone detail
//!   mode via [`rf_scan::Detailer`] — real operands, real memory references,
//!   real instruction groups (ECO-05);
//! * the **text path** ([`crate::text`]), a fallback for a gadget whose bytes
//!   no capstone mode reproduces.
//!
//! ## Why this is not one `contains('[')` test (CLS-04)
//!
//! The previous heuristic asked whether the operand string contained `[`.
//! MIPS, PowerPC, RISC-V and SPARC print memory as `disp(base)` or
//! `[%reg + %reg]`, so the test was false for every gadget on those targets:
//! on `tests/fixtures/elf-Mips-Defcon-20-pwn100` 40,683 of 41,142 gadgets
//! (98.9 %) came out `reg-write` and the binary contained zero `mem-read`,
//! zero `mem-write` and zero `stack-pivot`. Here a memory operand is whatever
//! capstone *says* is a memory operand, and load/store is decided from the
//! mnemonic — which is the only thing that decides it on a load/store ISA.

use rf_core::Arch;
use rf_scan::{Gadget, InsnDetail};

use crate::{push_unique, push_unique_class, Class, Terminator};

/// Architectures grouped by their register-naming and operand conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    Arm,
    Arm64,
    Mips,
    Ppc,
    Sparc,
    RiscV,
}

pub(crate) fn family(arch: Arch) -> Option<Family> {
    Some(match arch {
        Arch::Arm | Arch::ArmThumb => Family::Arm,
        Arch::Arm64 => Family::Arm64,
        Arch::Mips32 | Arch::Mips64 => Family::Mips,
        Arch::Ppc32 | Arch::Ppc64 => Family::Ppc,
        Arch::Sparc | Arch::Sparc64 | Arch::SparcV9 => Family::Sparc,
        Arch::RiscV32 | Arch::RiscV64 => Family::RiscV,
        Arch::X86 | Arch::X64 => return None,
    })
}

impl Family {
    /// SPARC prints `op src1, src2, dst`; every other family here prints the
    /// destination first. Getting this backwards is what made SPARC's
    /// `regs_written` full of immediates (`0xad5a0`) in the text path.
    fn dest_is_last(self) -> bool {
        self == Family::Sparc
    }

    /// Stack-pointer names, normalized (no `$`/`%` sigil).
    fn sp_names(self) -> &'static [&'static str] {
        match self {
            Family::Arm => &["sp", "r13"],
            Family::Arm64 => &["sp", "wsp"],
            Family::Mips => &["sp", "29"],
            Family::Ppc => &["r1"],
            Family::Sparc => &["sp", "o6"],
            Family::RiscV => &["sp", "x2"],
        }
    }

    /// The return-address / link register, as the terminator test uses it.
    fn link_names(self) -> &'static [&'static str] {
        match self {
            Family::Arm => &["lr", "r14"],
            Family::Arm64 => &["lr", "x30"],
            Family::Mips => &["ra", "31"],
            Family::Ppc => &["lr"],
            Family::Sparc => &["o7", "i7"],
            Family::RiscV => &["ra", "x1"],
        }
    }

    /// Registers hardwired to zero: writing them is architecturally a no-op,
    /// so they must not earn a `reg-write` label or appear in `regs_written`.
    fn is_zero_reg(self, n: &str) -> bool {
        match self {
            Family::Arm64 => n == "xzr" || n == "wzr",
            Family::Mips => n == "zero" || n == "0",
            Family::Sparc => n == "g0",
            Family::RiscV => n == "zero" || n == "x0",
            Family::Arm | Family::Ppc => false,
        }
    }

    fn is_sp(self, n: &str) -> bool {
        self.sp_names().contains(&n)
    }

    fn is_pc(self, n: &str) -> bool {
        matches!(n, "pc" | "r15" | "npc")
    }

    /// General-purpose (integer) registers only: float, vector, condition and
    /// status registers are not what a chain author allocates, and letting
    /// them through is what put `cr1eq`, `f2` and `vs0` into `regs_written`.
    fn is_gpr(self, n: &str) -> bool {
        let numbered = |p: char, max: u32| -> bool {
            n.strip_prefix(p)
                .and_then(|r| r.parse::<u32>().ok())
                .is_some_and(|v| v < max)
        };
        match self {
            Family::Arm => {
                numbered('r', 16) || matches!(n, "sp" | "lr" | "pc" | "ip" | "fp" | "sl" | "sb")
            }
            Family::Arm64 => {
                numbered('x', 32)
                    || numbered('w', 32)
                    || matches!(n, "sp" | "wsp" | "lr" | "fp" | "xzr" | "wzr")
            }
            Family::Mips => {
                n.parse::<u32>().is_ok_and(|v| v < 32)
                    || matches!(n, "zero" | "at" | "gp" | "sp" | "fp" | "ra" | "hi" | "lo")
                    || matches!(n.as_bytes().first(), Some(b'v' | b'a' | b't' | b's' | b'k'))
                        && n.len() == 2
                        && n.as_bytes()[1].is_ascii_digit()
            }
            Family::Ppc => numbered('r', 32) || matches!(n, "lr" | "ctr"),
            Family::Sparc => {
                (matches!(n.as_bytes().first(), Some(b'g' | b'o' | b'l' | b'i'))
                    && n.len() == 2
                    && n.as_bytes()[1].is_ascii_digit())
                    || matches!(n, "sp" | "fp")
            }
            Family::RiscV => {
                numbered('x', 32)
                    || matches!(n, "zero" | "ra" | "sp" | "gp" | "tp" | "fp")
                    || (matches!(n.as_bytes().first(), Some(b't' | b's' | b'a'))
                        && n.len() >= 2
                        && n[1..].parse::<u32>().is_ok())
            }
        }
    }
}

/// A memory-touching instruction is a store iff its mnemonic says so.
///
/// On every load/store ISA in this module the mnemonic is the only carrier of
/// direction (capstone fills `cs_ac_type` for ARM and ARM64 only). The
/// prefix strips handle the compressed (`c.sw`), floating (`fsd`, `stfd`) and
/// vector (`vstr`) spellings, and are safe because this test is only reached
/// for an instruction that already has a memory operand — `sub`, `sll`,
/// `slt` and friends never get here.
fn is_store(mnemonic: &str) -> bool {
    let m = mnemonic.trim_end_matches(['.', '!']);
    let m = m.strip_prefix("c.").unwrap_or(m);
    let m = m.strip_prefix('v').unwrap_or(m);
    let m = m.strip_prefix('f').unwrap_or(m);
    m.starts_with("st")
        || m.starts_with("sw")
        || m.starts_with("sh")
        || m.starts_with("sb")
        || m.starts_with("sd")
        || m.starts_with("sc")
        || m.starts_with("push")
        || m.starts_with("swap")
        || m.starts_with("usw")
}

/// Push/pop-style instructions whose stack traffic is implicit (no memory
/// operand is printed): the R1 "chain mechanism, not payload" set.
fn is_stack_list(mnemonic: &str) -> bool {
    let m = mnemonic;
    m == "push"
        || m == "pop"
        || m.starts_with("stm")
        || m.starts_with("ldm")
        || m.starts_with("push")
        || m.starts_with("pop")
        || m == "srs"
        || m == "rfe"
}

fn is_pop_list(mnemonic: &str) -> bool {
    mnemonic == "pop" || mnemonic.starts_with("pop") || mnemonic.starts_with("ldm")
}

/// R2 gate mnemonics across the capstone architectures.
fn is_syscall_mnemonic(m: &str) -> bool {
    matches!(
        m,
        // NB: ARM's `teq` is a flags-only compare, not a trap; MIPS's `teq`
        // IS a conditional trap. capstone's CS_GRP_INT settles the ambiguous
        // spellings, so only the unambiguous ones are listed here.
        "svc"
            | "swi"
            | "syscall"
            | "sc"
            | "ecall"
            | "scall"
            | "ta"
            | "break"
            | "int"
            | "hvc"
            | "smc"
            | "sysenter"
            | "trap"
    )
}

/// R6 (widened per CLS-12): mnemonics that COMPUTE a value.
///
/// Flags-only comparisons (`cmp`, `cmn`, `tst`, `cmpw`, ...) are deliberately
/// absent: they put nothing into a register and are useless as arithmetic
/// gadgets, which is exactly why CLS-12 asks for them to be dropped.
/// Set-on-comparison (`slt`, `sltu`) IS here, because it does write a
/// register.
pub(crate) fn is_arithmetic(m: &str) -> bool {
    const SET: &[&str] = &[
        // add / subtract
        "add",
        "addi",
        "addis",
        "addiu",
        "addu",
        "adds",
        "addw",
        "addiw",
        "adc",
        "adcs",
        "adde",
        "addic",
        "addze",
        "addme",
        "addc",
        "daddu",
        "daddiu",
        "dadd",
        "sub",
        "subi",
        "subu",
        "subiu",
        "subs",
        "subw",
        "sbc",
        "sbcs",
        "subf",
        "subfic",
        "subfe",
        "subfc",
        "subfze",
        "rsb",
        "rsbs",
        "rsc",
        "dsub",
        "dsubu",
        "neg",
        "negu",
        "nego",
        "negs",
        "abs", // multiply / divide (CLS-12: division was missing)
        "mul",
        "mulw",
        "mult",
        "multu",
        "mulh",
        "mulhu",
        "mulhsu",
        "mullw",
        "mulld",
        "mulli",
        "mulhw",
        "muls",
        "mla",
        "mls",
        "madd",
        "maddu",
        "msub",
        "msubu",
        "smull",
        "umull",
        "smlal",
        "umlal",
        "mneg",
        "dmult",
        "dmultu",
        "div",
        "divw",
        "divd",
        "divu",
        "divwu",
        "divdu",
        "ddiv",
        "ddivu",
        "sdiv",
        "udiv",
        "rem",
        "remu",
        "remw",
        "remuw", // logic
        "and",
        "andi",
        "andc",
        "ands",
        "or",
        "ori",
        "oris",
        "orr",
        "orn",
        "orc",
        "nor",
        "xor",
        "xori",
        "xoris",
        "eor",
        "eon",
        "nand",
        "bic",
        "bics",
        "not",
        "mvn",
        "eqv",
        // shifts and rotates
        "sll",
        "sllv",
        "srl",
        "srlv",
        "sra",
        "srav",
        "slli",
        "srli",
        "srai",
        "slliw",
        "srliw",
        "sraiw",
        "sllw",
        "srlw",
        "sraw",
        "srad",
        "dsll",
        "dsrl",
        "dsra",
        "dsll32",
        "dsrl32",
        "dsra32",
        "lsl",
        "lsr",
        "asr",
        "ror",
        "rrx",
        "rol",
        "rlwinm",
        "rlwnm",
        "rldicl",
        "rldicr",
        "rldic",
        "rldimi",
        "rlwimi",
        "slw",
        "srw",
        "sld",
        "srd",
        "extr",
        "asrv",
        "lslv",
        "lsrv",
        "rorv", // bit test / manipulation / byte swap (CLS-12)
        "rev",
        "rev16",
        "rev32",
        "rev64",
        "rbit",
        "clz",
        "cls",
        "cntlzw",
        "cntlzd",
        "cnttzw",
        "cnttzd",
        "popcnt",
        "popcntw",
        "popcntd",
        "wsbh",
        "seb",
        "seh",
        "sext.w",
        "zext.w",
        "ubfm",
        "sbfm",
        "ubfx",
        "sbfx",
        "bfi",
        "bfc",
        "bfxil",
        "ins",
        "ext",
        "bset",
        "bclr",
        "binv",
        "bexti",
        "bext", // exchange / atomic read-modify-write
        "xchg",
        "swap",
        "swp",
        "swpb",
        "cas",
        "casa",
        "amoadd.w",
        "amoadd.d",
        "amoswap.w",
        "amoswap.d",
        "amoor.w",
        "amoor.d",
        "amoand.w",
        "amoand.d",
        "amoxor.w",
        "amoxor.d",
        // set-on-comparison: unlike cmp, these write a register
        "slt",
        "slti",
        "sltu",
        "sltiu",
        "seq",
        "sne",
        "sgt",
        "sle",
        "movz",
        "movn",
    ];
    SET.contains(&m)
}

/// Mnemonics that write no register at all: flags-only comparisons and
/// barriers. Branches are NOT listed here — they are identified from
/// capstone's instruction groups instead, which is what makes `bhi`, `blezl`,
/// `cbz` and `tbnz` stop being treated as register writes (CLS-05: the old
/// blocklist was eleven hand-written mnemonics, so every conditional branch
/// fell through the R7 catch-all and contributed its branch target immediate
/// to `regs_written`).
fn writes_nothing(m: &str) -> bool {
    m.starts_with("cmp")
        || m.starts_with("cmn")
        || matches!(
            m,
            "tst" | "teq" | "nop" | "sync" | "isb" | "dsb" | "dmb" | "eieio" | "fence"
        )
}

/// Everything one instruction contributes, before precedence is applied.
#[derive(Default)]
pub(crate) struct InsnEffect {
    pub labels: Vec<Class>,
    pub written: Vec<String>,
    pub read: Vec<String>,
    /// Memory operands reached through a base register other than the stack
    /// pointer: the gadget needs that pointer set up before it can be used.
    pub pointer_deps: usize,
    /// Registers this instruction loads out of the stack (a pop, or a load
    /// whose base is the stack pointer). Feeds usability tier 3.
    pub from_stack: Vec<String>,
    pub privileged: bool,
}

/// Label one instruction from capstone detail metadata.
///
/// `is_terminator` marks the gadget's control transfer: its *control* effects
/// (the jump itself, the link-register write, the branch-target fetch, the
/// implicit stack-pointer step) are mechanism and are dropped, but any
/// payload it also carries is kept — that is how `pop {r4, r5, pc}` keeps its
/// two register loads instead of vanishing the way `ret` does.
pub(crate) fn effect_of(f: Family, d: &InsnDetail, _is_terminator: bool) -> InsnEffect {
    let mut e = InsnEffect {
        privileged: d.groups.privileged,
        ..Default::default()
    };
    let m = d.mnemonic.as_str();
    if m == "nop" {
        return e;
    }

    if is_syscall_mnemonic(m) || d.groups.int {
        e.labels.push(Class::Syscall);
    }

    // --- memory -----------------------------------------------------------
    // R1: a stack READ is the mechanism that delivers a register value (the
    // value shows up as a register write instead); a stack WRITE puts a
    // controlled value into memory and is real (CLS-13's push-ret case).
    let store = is_store(m);
    let mut mem_read = false;
    let mut mem_write = false;
    let mut stack_load = false;
    for mr in d.mem_refs() {
        let on_stack = mr.base.as_deref().is_some_and(|b| f.is_sp(b));
        if store {
            mem_write = true;
        } else if on_stack {
            stack_load = true;
        } else {
            mem_read = true;
        }
        if !on_stack && mr.base.is_some() {
            e.pointer_deps += 1;
        }
        if let Some(b) = &mr.base {
            push_unique(&mut e.read, b.clone());
        }
        if let Some(i) = &mr.index {
            push_unique(&mut e.read, i.clone());
        }
    }
    if is_stack_list(m) {
        // push {r4, lr} / stmdb sp!, {...}: the memory operand is implicit.
        if !is_pop_list(m) {
            mem_write = true;
        } else {
            stack_load = true;
        }
    }
    if mem_write {
        e.labels.push(Class::MemWrite);
    }
    if mem_read {
        e.labels.push(Class::MemRead);
    }

    // --- registers --------------------------------------------------------
    // ARM and ARM64 are the only capstone architectures that implement
    // cs_regs_access, so they get real implicit+explicit sets; the rest are
    // derived from the operand list and the family's destination position.
    let mut written: Vec<String> = Vec::new();
    let mut read: Vec<String> = Vec::new();
    if !d.regs_written.is_empty() || !d.regs_read.is_empty() {
        written.extend(d.regs_written.iter().cloned());
        read.extend(d.regs_read.iter().cloned());
    }
    let regs: Vec<&str> = d.reg_operands().collect();
    let derive = written.is_empty() && !regs.is_empty();
    if derive && is_pop_list(m) {
        // Every register in the list is loaded.
        written.extend(regs.iter().map(|r| r.to_string()));
    } else if derive && !writes_nothing(m) && !store && !d.groups.control() {
        if f.dest_is_last() {
            written.push(regs[regs.len() - 1].to_string());
            read.extend(regs[..regs.len() - 1].iter().map(|r| r.to_string()));
        } else {
            written.push(regs[0].to_string());
            read.extend(regs[1..].iter().map(|r| r.to_string()));
        }
    } else if written.is_empty() {
        read.extend(regs.iter().map(|r| r.to_string()));
    }

    // R5: an explicit, register-operand-targeting write of the stack pointer.
    // The implicit step every push/pop/call/return makes is NOT a pivot —
    // that is the x86 side of CLS-02, and the same rule applies here.
    let sp_is_operand = regs.iter().any(|r| f.is_sp(r));
    let sp_written = written.iter().any(|r| f.is_sp(r));
    if sp_is_operand && sp_written && !is_stack_list(m) {
        e.labels.push(Class::StackPivot);
    }

    let control_write = |n: &str| f.is_pc(n) || (d.groups.call && f.link_names().contains(&n));
    let mut wrote_gpr = false;
    for r in &written {
        if f.is_sp(r) || f.is_zero_reg(r) || control_write(r) || !f.is_gpr(r) {
            continue;
        }
        wrote_gpr = true;
        push_unique(&mut e.written, r.clone());
        if stack_load {
            push_unique(&mut e.from_stack, r.clone());
        }
    }
    for r in &read {
        if !f.is_gpr(r) || f.is_pc(r) {
            continue;
        }
        push_unique(&mut e.read, r.clone());
    }

    if is_arithmetic(m) {
        e.labels.push(Class::Arithmetic);
    }
    // R7
    if wrote_gpr && !mem_read && !mem_write && !e.labels.contains(&Class::Syscall) {
        e.labels.push(Class::RegWrite);
    }
    e
}

/// Which instruction terminates the gadget, and in what form.
///
/// Returns `(index, terminator)`. The index is the *control transfer*, which
/// on a delay-slot ISA is not the last instruction: ROPgadget prints MIPS
/// gadgets as `jr $ra ; <delay slot>`, and the delay slot really executes, so
/// it stays in the side-effect accounting.
pub(crate) fn terminator_of(f: Family, det: &[InsnDetail]) -> (Option<usize>, Terminator) {
    // capstone does not fill instruction groups on every architecture — SPARC
    // reports none at all, so `retl` would otherwise look like an ordinary
    // instruction and every SPARC gadget would come back with no terminator.
    // The mnemonic test is the fallback, not the primary.
    let Some(i) = det.iter().rposition(|d| {
        d.groups.control()
            || d.groups.int
            || is_syscall_mnemonic(&d.mnemonic)
            || crate::text::is_branch_mnemonic(&d.mnemonic)
            || pops_pc(f, d)
    }) else {
        return (None, Terminator::None);
    };
    let d = &det[i];
    let m = d.mnemonic.as_str();
    let target_is_link = d
        .reg_operands()
        .any(|r| f.link_names().contains(&r) || f.is_pc(r));
    // The spellings capstone does not group as returns: PowerPC's
    // branch-to-link-register, SPARC's window returns, ARM64's `ret`, and
    // ARM's `pop {…, pc}`. (PowerPC `blr` and ARM64 `blr` are opposites —
    // return vs branch-and-link — so this has to be per family.)
    let is_return = pops_pc(f, d)
        || match f {
            Family::Ppc => matches!(m, "blr" | "bclr" | "blrl"),
            Family::Sparc => matches!(m, "ret" | "retl" | "return"),
            Family::Arm64 => m == "ret",
            _ => false,
        };
    let t = if is_syscall_mnemonic(m) || d.groups.int {
        Terminator::Syscall
    } else if d.groups.iret || matches!(m, "eret" | "rfi" | "rfe") {
        Terminator::Iret
    } else if is_return {
        Terminator::Ret
    } else if d.groups.call || is_call_mnemonic(f, m) {
        Terminator::Call
    } else if d.groups.ret || target_is_link {
        Terminator::Ret
    } else {
        Terminator::Jmp
    };
    (Some(i), t)
}

/// Branch-and-link forms, for the architectures where capstone leaves
/// `CS_GRP_CALL` unset.
fn is_call_mnemonic(f: Family, m: &str) -> bool {
    match f {
        Family::Arm | Family::Arm64 => matches!(m, "bl" | "blx" | "blr"),
        Family::Ppc => matches!(m, "bl" | "bla" | "bctrl" | "blrl" | "bcctrl" | "bclrl"),
        Family::Mips => matches!(m, "jal" | "jalr" | "jalx" | "bal" | "bgezal" | "bltzal"),
        Family::RiscV => matches!(m, "jal" | "c.jal" | "c.jalr"),
        Family::Sparc => matches!(m, "call"),
    }
}

/// `pop {…, pc}` / `ldmia sp!, {…, pc}` — ARM's return-by-load.
fn pops_pc(f: Family, d: &InsnDetail) -> bool {
    matches!(f, Family::Arm) && is_pop_list(&d.mnemonic) && d.reg_operands().any(|r| f.is_pc(r))
}

/// R8 (CLS-03) for the capstone architectures: a dispatcher is a
/// register-indirect branch whose target register was ADVANCED by an earlier
/// instruction in the same gadget that both reads and writes it.
pub(crate) fn dispatcher(f: Family, det: &[InsnDetail], term: Option<usize>) -> bool {
    let Some(ti) = term else { return false };
    let d = &det[ti];
    if !(d.groups.jump || d.groups.call) {
        return false;
    }
    let mut targets: Vec<String> = d
        .reg_operands()
        .filter(|r| !f.link_names().contains(r))
        .map(str::to_string)
        .collect();
    for mr in d.mem_refs() {
        if let Some(b) = &mr.base {
            targets.push(b.clone());
        }
    }
    if targets.is_empty() {
        return false;
    }
    det[..ti].iter().any(|prev| {
        if !is_arithmetic(&prev.mnemonic) {
            return false;
        }
        let e = effect_of(f, prev, false);
        targets
            .iter()
            .any(|t| e.written.contains(t) && e.read.contains(t))
    })
}

/// Full metadata-backed classification for one non-x86 gadget.
pub(crate) fn classify_detail(g: &Gadget, arch: Arch, det: &[InsnDetail]) -> crate::Classification {
    let f = family(arch).expect("classify_detail is never reached for x86/x64");
    let (term_idx, terminator) = terminator_of(f, det);

    let mut labels: Vec<Class> = Vec::new();
    let mut regs_written: Vec<String> = Vec::new();
    let mut regs_read: Vec<String> = Vec::new();
    let mut from_stack: Vec<String> = Vec::new();
    let mut side_effects = 0usize;
    let mut last_class: Option<Class> = None;
    let mut privileged = false;
    let mut pointer_deps = 0usize;
    let mut mid_branches = 0usize;

    for (i, d) in det.iter().enumerate() {
        let is_term = Some(i) == term_idx;
        if !is_term && (d.groups.jump || crate::text::is_branch_mnemonic(&d.mnemonic)) {
            mid_branches += 1;
        }
        let e = effect_of(f, d, is_term);
        privileged |= e.privileged;
        pointer_deps += e.pointer_deps;
        for r in e.read {
            push_unique(&mut regs_read, r);
        }
        for r in &e.from_stack {
            push_unique(&mut from_stack, r.clone());
        }
        if e.labels.is_empty() {
            continue;
        }
        for r in e.written {
            push_unique(&mut regs_written, r);
        }
        side_effects += 1;
        last_class = crate::PRECEDENCE
            .iter()
            .find(|c| e.labels.contains(c))
            .copied()
            .or(last_class);
        for c in e.labels {
            push_unique_class(&mut labels, c);
        }
    }

    let dispatcher = dispatcher(f, det, term_idx);
    if dispatcher {
        push_unique_class(&mut labels, Class::Dispatcher);
        if last_class.is_none() {
            last_class = Some(Class::Dispatcher);
        }
    }
    let primary = last_class.unwrap_or(Class::Other);
    labels.sort_by_key(|c| c.name());
    crate::Classification {
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
        regs_from_stack: from_stack,
        side_effects,
        mem_pointer_deps: pointer_deps,
        mid_branches,
        dispatcher,
        terminator,
        privileged,
        low_confidence: false,
    }
}
