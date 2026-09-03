//! rf-classify — semantic gadget classification and the ranking function
//! (Phase 5, PLAN sec. 5.1; Phase 3 remediation for CLS-02..CLS-13, ECO-05).
//!
//! The decision rules live in [`TAXONOMY.md`](../../../TAXONOMY.md); rule
//! numbers (R1-R13) are cited inline.
//!
//! Three decode paths, one rule set:
//!
//! | arch | decoder | metadata |
//! |---|---|---|
//! | x86 / x64 | iced-x86 `InstructionInfoFactory` | full |
//! | ARM, ARM64, MIPS, PPC, SPARC, RISC-V | capstone **detail mode** ([`rf_scan::Detailer`]) | full |
//! | anything whose bytes no capstone mode reproduces | disassembly text | best effort, `low_confidence` |
//!
//! Before this release the middle row did not exist: `cs::open` never called
//! `set_detail(true)` (ECO-05), so eight of the ten supported architectures
//! fell through to the text path, `regs_written` was populated by splitting
//! the operand string on `,` — which is where `{r4` and `#0x12e44` came from
//! (CLS-05) — and the memory test was `operands.contains('[')`, which is
//! false for every `off(reg)` architecture, so MIPS, PowerPC and RISC-V
//! reported zero `mem-read`, zero `mem-write` and zero `stack-pivot` across
//! an entire binary (CLS-04).
//!
//! ## Ranking (CLS-07)
//!
//! [`quality_score`] alone cannot order gadgets: it is a function of two
//! integers that are both tiny for almost every gadget, so 92 % of a real
//! binary ties at 100. [`usability`] adds the dimension that actually
//! separates `pop rdi ; ret` from `retf 0xce39` — what the gadget's
//! *terminator* is and whether it loads a register off the stack — and
//! [`rank_key`] is the full order the CLI and the MCP server sort by.

#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::rc::Rc;

use rf_core::Arch;
use rf_scan::{Detailer, Gadget, InsnDetail};
use serde::Serialize;

mod generic;
mod text;
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

/// How a gadget hands control on — the single most important thing about it
/// for chain construction, and the field the MCP surface filters on.
///
/// `Ret` means a **bare** return: `ret`, ARM64 `ret`, ARM `bx lr` and
/// `pop {…, pc}`, MIPS `jr $ra`, PowerPC `blr`, SPARC `retl`, RISC-V
/// `c.jr ra`. Everything that returns but also moves the stack pointer by a
/// fixed amount (`ret imm16`), changes privilege or segment (`retf`, `iret`,
/// a far transfer), or needs separate dispatch machinery (`jmp`, `call`) is a
/// distinct variant, because those are the differences that decide whether a
/// gadget can be dropped into a `ret`-driven chain at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Terminator {
    Ret,
    RetImm,
    Retf,
    Iret,
    Far,
    Jmp,
    Call,
    Syscall,
    None,
}

impl Terminator {
    /// Full name, as serialized (`"ret"`, `"ret-imm"`, `"retf"`, …).
    pub fn name(self) -> &'static str {
        match self {
            Terminator::Ret => "ret",
            Terminator::RetImm => "ret-imm",
            Terminator::Retf => "retf",
            Terminator::Iret => "iret",
            Terminator::Far => "far",
            Terminator::Jmp => "jmp",
            Terminator::Call => "call",
            Terminator::Syscall => "syscall",
            Terminator::None => "none",
        }
    }

    /// Coarse kind for the MCP `terminator: "ret"|"jmp"|"call"|"syscall"`
    /// filter: every returning form collapses to `"ret"`.
    pub fn kind(self) -> &'static str {
        match self {
            Terminator::Ret
            | Terminator::RetImm
            | Terminator::Retf
            | Terminator::Iret
            | Terminator::Far => "ret",
            Terminator::Jmp => "jmp",
            Terminator::Call => "call",
            Terminator::Syscall => "syscall",
            Terminator::None => "none",
        }
    }

    /// A plain near return with no stack adjustment, no privilege change and
    /// no dispatch requirement — the only terminator a `ret`-driven chain can
    /// use without extra machinery.
    pub fn is_bare_return(self) -> bool {
        self == Terminator::Ret
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
    /// Registers written by the gadget (R1-normalized: implicit stack-pointer
    /// effects of push/pop/call/ret excluded; hardwired-zero registers,
    /// float/vector/condition registers and the program counter excluded),
    /// lowercase and sigil-free (`$sp` -> `sp`, `%o0` -> `o0`), deduped, in
    /// first-appearance order.
    pub regs_written: Vec<String>,
    pub regs_read: Vec<String>,
    /// The subset of `regs_written` whose value comes off the stack — a
    /// `pop`, or a load whose base register is the stack pointer. This is the
    /// property that makes a gadget *controllable* from the chain payload,
    /// and it is what separates usability tier 3 from tier 2.
    pub regs_from_stack: Vec<String>,
    /// Instructions earning at least one label (R11).
    pub side_effects: usize,
    /// Memory operands whose base or index register must already hold an
    /// attacker-controlled pointer before the gadget is usable — an
    /// `add byte ptr [rax], al` needs rax set up first, an absolute or
    /// RIP-relative operand does not. Counted per instruction.
    pub mem_pointer_deps: usize,
    /// Conditional branches sitting in the MIDDLE of the gadget: the tail
    /// executes only if the flags happen to be right, so the gadget's effect
    /// is not guaranteed. Counted per instruction.
    pub mid_branches: usize,
    /// Deterministic quality score (R12); higher = cleaner gadget.
    pub quality: i32,
    /// JOP/COP dispatcher heuristic (R8) — also reflected as the
    /// `dispatcher` label when it fires.
    pub dispatcher: bool,
    /// How the gadget hands control on.
    pub terminator: Terminator,
    /// The gadget contains a privileged or undefined instruction (`hlt`,
    /// `ud2`, `int3`, `cli`, `in`/`out`, `lgdt`, …): it faults or traps in
    /// user mode, so it cannot appear in a chain.
    pub privileged: bool,
    /// True when the classification came from disassembly TEXT rather than
    /// decoder metadata (R13) — now only reachable when no capstone mode
    /// reproduces the gadget's recorded text.
    pub low_confidence: bool,
}

impl Classification {
    /// How the gadget hands control on. (Accessor mirroring the field, so
    /// consumers that hold a `&Classification` behind an abstraction do not
    /// need field access.)
    pub fn terminator(&self) -> Terminator {
        self.terminator
    }
}

/// R12 (revised for CLS-07): `max(0, 100 - 15*|side_effects - 1| - 3*(n_insns - 2))`.
///
/// The original spelling clamped `side_effects` up to 1, so a gadget with NO
/// side effects — `ret`, `jmp 0x400340`, `retf 0xce39` — scored exactly the
/// same 100 as `pop rdi ; ret`. The ideal gadget does *exactly one* thing, so
/// the penalty is the distance from one side effect in either direction,
/// which costs the same 15 per step the rule already charged for an extra
/// side effect. Measured effect on `tests/fixtures/elf-x64-bash-v4.1.5.1` at
/// depth 10: the largest quality bucket falls from 47.17 % to a value
/// recorded in the workstream report.
pub fn quality_score(side_effects: usize, n_insns: usize) -> i32 {
    quality_score_full(side_effects, n_insns, 0, 0)
}

/// [`quality_score`] plus the two terms CLS-07 names as missing:
///
/// * `regs_written` — each register clobbered beyond the first costs **5**, a
///   third of a side effect, because a clobber constrains the surrounding
///   chain without adding a behaviour to reason about;
/// * `preconditions` — each thing that has to already be true for the gadget
///   to do what it says costs **10**, two thirds of a side effect: a memory
///   operand needing an attacker-controlled pointer already in a register
///   ([`Classification::mem_pointer_deps`]) turns a one-gadget step into a
///   two-gadget one, and a conditional branch in the middle of the gadget
///   ([`Classification::mid_branches`]) means the tail runs only if the flags
///   happen to cooperate.
///
/// Both weights are stated as fractions of R12's own 15-per-side-effect
/// constant rather than fitted; their measured effect on the score
/// distribution is recorded in the workstream report.
///
/// The two dimensions CLS-07 names that are NOT here are the stack delta,
/// which is assigned to ECO-07/CLS-09 in a later wave, and bad bytes in the
/// address, which depends on scan parameters and so cannot live in a
/// parameter-independent score.
pub fn quality_score_full(
    side_effects: usize,
    n_insns: usize,
    regs_written: usize,
    preconditions: usize,
) -> i32 {
    let se = side_effects as i32;
    let ni = n_insns.max(2) as i32;
    let extra_regs = (regs_written as i32 - 1).max(0);
    (100 - 15 * (se - 1).abs() - 3 * (ni - 2) - 5 * extra_regs - 10 * preconditions as i32).max(0)
}

/// Usability tier, 0..=3 — the dimension that makes ranking work (CLS-07).
///
/// * **3** — bare return terminator, at least one register loaded off the
///   stack, and at most two side effects. `pop rdi ; ret`.
/// * **2** — bare return terminator and a useful class. `mov [rdi], rax ; ret`.
/// * **1** — the gadget does something, but getting to the next gadget costs
///   extra: `ret imm16`, `retf`, `iret`, a far transfer, or a `jmp`/`call`
///   terminator that needs JOP/COP dispatch machinery; or the class is
///   `other`, meaning nothing was identified.
/// * **0** — the gadget contains a privileged or undefined instruction, or it
///   has no side effects at all (pure control flow: `ret`, `jmp 0x400340`,
///   `retf 0xce39`).
///
/// Deviation from the design note, recorded deliberately: the note lists
/// `jmp`/`call` terminators nowhere. They are placed in tier 1 alongside the
/// other non-bare terminators, because a JOP gadget cannot be used from a
/// `ret`-driven chain without a dispatcher, which is exactly the property
/// tier 1 already encodes.
pub fn usability(c: &Classification, _g: &Gadget) -> u8 {
    if c.privileged || c.side_effects == 0 {
        return 0;
    }
    if !c.terminator.is_bare_return() || c.primary == Class::Other {
        return 1;
    }
    if !c.regs_from_stack.is_empty() && c.side_effects <= 2 {
        3
    } else {
        2
    }
}

/// The default gadget order: **ascending `RankKey` is best-first**.
///
/// Key, in priority order: usability tier (descending), quality
/// (descending), instruction count (ascending), side-effect count
/// (ascending), address (ascending). The address is a deterministic final
/// tie-break so the order is total and reproducible across runs, processes
/// and platforms — which is what a cursor needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct RankKey {
    pub usability: u8,
    pub quality: i32,
    pub n_insns: usize,
    pub side_effects: usize,
    pub vaddr: u64,
}

impl Ord for RankKey {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .usability
            .cmp(&self.usability)
            .then_with(|| other.quality.cmp(&self.quality))
            .then_with(|| self.n_insns.cmp(&other.n_insns))
            .then_with(|| self.side_effects.cmp(&other.side_effects))
            .then_with(|| self.vaddr.cmp(&other.vaddr))
    }
}

impl PartialOrd for RankKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Build the [`RankKey`] for one classified gadget.
pub fn rank_key(c: &Classification, g: &Gadget) -> RankKey {
    RankKey {
        usability: usability(c, g),
        quality: c.quality,
        n_insns: g.insns.len(),
        side_effects: c.side_effects,
        vaddr: g.vaddr,
    }
}

/// A reusable classifier for one architecture.
///
/// Holds the capstone detail handles for every mode that could have produced
/// gadgets for its architecture (at most four; none for x86/x64) and picks
/// per gadget the one that reproduces the gadget's recorded text. Prefer this
/// over [`classify`] when classifying many gadgets: [`classify`] reaches the
/// same handles through a thread-local cache, which costs a hash lookup per
/// call.
///
/// `Classifier` is **not** `Send`/`Sync`: capstone handles are not. Construct
/// one per worker thread.
pub struct Classifier {
    arch: Arch,
    detailers: RefCell<Vec<Detailer>>,
}

impl std::fmt::Debug for Classifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Classifier")
            .field("arch", &self.arch)
            .field("detail_modes", &self.detailers.borrow().len())
            .finish()
    }
}

impl Classifier {
    pub fn new(arch: Arch) -> Self {
        Classifier {
            arch,
            detailers: RefCell::new(Detailer::all_candidates(arch)),
        }
    }

    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// True when this architecture has decoder metadata available — i.e. when
    /// results will not be `low_confidence`.
    pub fn has_metadata(&self) -> bool {
        self.arch.is_x86_family() || !self.detailers.borrow().is_empty()
    }

    pub fn classify(&self, g: &Gadget) -> Classification {
        match self.arch {
            Arch::X86 => x86::classify_x86(g, 32),
            Arch::X64 => x86::classify_x86(g, 64),
            _ => match self.detail(g) {
                Some(det) => generic::classify_detail(g, self.arch, &det),
                None => text::classify_text(g, self.arch),
            },
        }
    }

    /// Decode `g` with the first detail mode that reproduces its text,
    /// promoting that mode to the front so a whole-binary pass pays the
    /// search once.
    fn detail(&self, g: &Gadget) -> Option<Vec<InsnDetail>> {
        let mut ds = self.detailers.borrow_mut();
        for i in 0..ds.len() {
            if let Some(d) = ds[i].decode_checked(g) {
                if i > 0 {
                    ds.swap(0, i);
                }
                return Some(d);
            }
        }
        None
    }
}

thread_local! {
    /// Per-thread `Classifier` cache: capstone handles are `!Send`, and
    /// re-opening up to four of them per gadget would dominate the cost of
    /// classification.
    static CLASSIFIERS: RefCell<HashMap<Arch, Rc<Classifier>>> =
        RefCell::new(HashMap::new());
}

/// Classify one gadget.
pub fn classify(g: &Gadget, arch: Arch) -> Classification {
    let c = CLASSIFIERS.with(|m| {
        m.borrow_mut()
            .entry(arch)
            .or_insert_with(|| Rc::new(Classifier::new(arch)))
            .clone()
    });
    c.classify(g)
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
mod tests;
