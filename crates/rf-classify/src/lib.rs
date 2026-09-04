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
//!
//! # Getting started
//!
//! One gadget in, one [`Classification`] out. The interesting part is not
//! the label — it is the semantic fields underneath it, which are what let
//! you ask "a gadget that loads rdi from the stack and clobbers neither rsi
//! nor rdx" without re-parsing disassembly text.
//!
//! ```
//! use rf_classify::{classify, Class, Terminator};
//! use rf_core::{Arch, Endianness, RawBinary};
//! use rf_scan::{scan_binary, ScanOptions};
//!
//! // `pop rdi ; ret`
//! let image = RawBinary::new(&[0x5f, 0xc3], Arch::X64, Endianness::Little);
//! let gadgets = scan_binary(&image, &ScanOptions { depth: 4, ..ScanOptions::default() })?;
//! let g = gadgets.iter().find(|g| g.text() == "pop rdi ; ret").expect("pop rdi ; ret");
//!
//! let c = classify(g, Arch::X64);
//! assert_eq!(c.primary, Class::RegWrite);
//! assert_eq!(c.terminator, Terminator::Ret);
//! assert_eq!(c.regs_written, ["rdi"]);
//! assert_eq!(c.regs_from_stack, ["rdi"]);
//! // The stack pointer moves 16 bytes: 8 for the pop, 8 for the return.
//! assert_eq!(c.stack_delta, Some(16));
//! # Ok::<(), rf_core::Error>(())
//! ```
//!
//! ## Asking a real question
//!
//! The predicates on [`Classification`] are the query vocabulary both front
//! ends expose (`--set-reg`, `--from-stack`, `--no-clobber`, `--terminator`),
//! so a filter written against them means the same thing as the flag:
//!
//! ```
//! use rf_classify::{Classifier, TerminatorClass};
//! use rf_core::{Arch, Endianness, RawBinary};
//! use rf_scan::{scan_binary, ScanOptions};
//!
//! // `pop rdi ; ret`, `pop rsi ; ret`, `xor eax, eax ; ret`
//! let bytes = [0x5f, 0xc3, 0x5e, 0xc3, 0x31, 0xc0, 0xc3];
//! let image = RawBinary::new(&bytes, Arch::X64, Endianness::Little);
//! let gadgets = scan_binary(&image, &ScanOptions { depth: 4, ..ScanOptions::default() })?;
//!
//! // One classifier for the whole listing: it holds the open decoders.
//! let cls = Classifier::new(Arch::X64);
//! let hits: Vec<String> = gadgets
//!     .iter()
//!     .filter(|g| {
//!         let c = cls.classify(g);
//!         c.sets_reg("rdi")
//!             && c.reg_from_stack("rdi")
//!             && !c.clobbers_any(["rsi", "rdx"])
//!             && c.terminator_class() == TerminatorClass::Ret
//!     })
//!     .map(|g| g.text())
//!     .collect();
//! assert_eq!(hits, ["pop rdi ; ret"]);
//! # Ok::<(), rf_core::Error>(())
//! ```
//!
//! ## Ranking
//!
//! ```
//! use rf_classify::{classify, rank_key};
//! use rf_core::{Arch, Endianness, RawBinary};
//! use rf_scan::{scan_binary, ScanOptions};
//!
//! // `pop rdi ; ret` and a bare `ret`.
//! let image = RawBinary::new(&[0x5f, 0xc3], Arch::X64, Endianness::Little);
//! let mut gadgets = scan_binary(&image, &ScanOptions { depth: 4, ..ScanOptions::default() })?;
//! gadgets.sort_by_key(|g| rank_key(&classify(g, Arch::X64), g));
//! // RankKey orders best-first, so the useful gadget comes first.
//! assert_eq!(gadgets[0].text(), "pop rdi ; ret");
//! # Ok::<(), rf_core::Error>(())
//! ```
//!
//! # Semver policy
//!
//! Covered by semver from 1.0: the fields of [`Classification`] and its
//! predicate methods, the [`Class`], [`Terminator`] and [`TerminatorClass`]
//! variant sets and their [`Class::name`] spellings, and the signatures of
//! [`classify`], [`quality_score`], [`usability`] and [`rank_key`].
//!
//! **Not** covered, and free to change in a minor release: **the numeric
//! output of [`quality_score`] / [`quality_score_full`] and the tier
//! boundaries of [`usability`]** — these are a heuristic that is expected to
//! be re-tuned against measured precision, so compare ranks, never absolute
//! scores; and which class a *particular* gadget earns, since a rule fix
//! changes it (that is what TAXONOMY.md's rule numbers are for — cite the
//! rule, not the outcome). Adding a [`Class`] or [`Terminator`] variant is a
//! minor release. Pin `rf-classify = "1"`.
//!
//! See `docs/API-STABILITY.md` in the repository for the workspace-wide
//! statement.

#![forbid(unsafe_code)]
// ENG-08: every public item carries documentation.
#![warn(missing_docs)]

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::rc::Rc;

use rf_core::Arch;
use rf_scan::{Detailer, Gadget, InsnDetail};
use serde::Serialize;

mod effect;
mod generic;
mod generic_effect;
mod text;
mod x86;
mod x86_effect;

pub use effect::{TerminatorClass, TerminatorTarget, Transfer, ValueDst, ValueSrc};

/// Semantic classes (TAXONOMY.md table). `Other` is the fallback for
/// gadgets with no labeled instruction (pure control flow, nop).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// Writes a general-purpose register (`"reg-write"`).
    RegWrite,
    /// Moves the stack pointer to a value the payload controls
    /// (`"stack-pivot"`).
    StackPivot,
    /// Loads from memory (`"mem-read"`).
    MemRead,
    /// Stores to memory (`"mem-write"`).
    MemWrite,
    /// Computes on registers (`"arithmetic"`).
    Arithmetic,
    /// Contains a syscall/trap instruction (`"syscall"`).
    Syscall,
    /// Branches through a register — a JOP dispatcher (`"dispatcher"`).
    Dispatcher,
    /// No labeled instruction: pure control flow, or a nop (`"other"`).
    Other,
}

impl Class {
    /// The kebab-case name used on both the CLI and the MCP surface, and in
    /// serialized output. This is the vocabulary `--class` accepts.
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
    /// A bare near return.
    Ret,
    /// `ret imm16` — returns and adds a fixed amount to the stack pointer.
    RetImm,
    /// A far return (`retf`).
    Retf,
    /// An interrupt return (`iret`).
    Iret,
    /// A far transfer (far `jmp`/`call`).
    Far,
    /// An indirect jump.
    Jmp,
    /// An indirect call.
    Call,
    /// A syscall or trap instruction.
    Syscall,
    /// The gadget does not transfer control at its end.
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
    /// Registers the gadget reads, normalized the same way as
    /// [`Classification::regs_written`].
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
    /// How the terminating transfer picks its target — the register/memory
    /// distinction [`Terminator`] deliberately does not carry, so that the
    /// v0.3 spellings of `terminator` stayed byte-identical (CLS-09).
    /// Combined with `terminator` by
    /// [`Classification::terminator_class`].
    ///
    /// Default for the text path and for gadgets with no terminator:
    /// [`TerminatorTarget::Implicit`].
    pub terminator_target: TerminatorTarget,
    /// **Net change of the stack pointer across the whole gadget**, in bytes,
    /// or `None` when the effect is not provably constant (CLS-09).
    ///
    /// The terminating transfer is included, because the payload bytes it
    /// consumes are payload bytes: `pop rdi ; ret` is `Some(16)` on x86-64,
    /// `ret` alone is `Some(8)`, `add rsp, 0x28 ; ret` is `Some(0x30)`. This
    /// is what a concrete execution of the gadget would leave in `rsp`, which
    /// is how `tests/ground-truth/oracle_unicorn.py` measures it.
    ///
    /// **`None` is a real answer.** A confident wrong stack delta silently
    /// corrupts a chain layout, so every gadget whose rsp effect depends on a
    /// register, on memory, or on a path not taken reports `None` rather than
    /// a number: `xchg rsp, rax`, `pop rsp`, `mov rsp, rbp`, `add rsp, rax`,
    /// `and rsp, -16`, `leave` (rsp becomes rbp+8), `iret*` (the pop count
    /// depends on a privilege change), `add esp, 8` in 64-bit code (a 32-bit
    /// write truncates rsp), and any gadget with a branch before its last
    /// instruction or a byte that does not decode.
    ///
    /// **Which architectures compute it.**
    ///
    /// | arch | computed |
    /// |---|---|
    /// | arch | computed for |
    /// |---|---|
    /// | x86, x86-64 | **fully**, via iced-x86: the pop/push family, `call`, `ret`, `ret imm16`, `retf`, `pusha`/`popa`, `pushf`/`popf`, `enter`, `inc`/`dec rsp`, `add`/`sub rsp, imm`, `lea rsp, [rsp+d]` |
    /// | ARM, ARM-Thumb | `push {…}` / `pop {…}` register lists, and `add`/`sub sp, sp, #imm`. **`ldm`/`stm` are `None`**, because their base register is printed inside the same operand list as the transfer list |
    /// | ARM64 | `add`/`sub sp, sp, #imm` only. **`ldp`/`stp`/`ldr`/`str` through `sp` are `None`**: `rf_scan::InsnDetail` does not carry capstone's write-back flag, so `ldr x0, [sp], #16` and `ldr x0, [sp, #16]` are indistinguishable here and they differ by 16 |
    /// | MIPS 32/64, RISC-V 32/64 | `addi(u)`/`daddi(u)`/`addiw`/`c.addi`/`c.addi16sp` on the stack pointer. Loads and stores through the stack pointer contribute 0, which is sound because neither ISA has a write-back addressing mode |
    /// | PowerPC 32/64 | `addi r1, r1, imm` and the `stwu`/`stdu`/`lwzu`/… *update* forms based on `r1`. The indexed update forms (`stwux`) are `None`; plain `r1`-based loads and stores contribute 0 |
    /// | SPARC (all) | **never**, not even 0 — `save`/`restore` rotate a register window, so they move the stack pointer without naming it and "this instruction does not mention `%sp`" proves nothing |
    /// | any gadget on the text fallback path | **never** — no decoder metadata |
    ///
    /// On every architecture, anything not in that list that names the stack
    /// pointer as an operand, or reaches memory through it, yields `None`.
    pub stack_delta: Option<i64>,
    /// Value movements inside the gadget, in program order (CLS-09).
    ///
    /// This is the field `--from-stack` is built on: it distinguishes
    /// `rdi <- [rsp+8]` from `rdi <- rax` from `rdi <- [rbx+0x10]` (naming
    /// rbx as the register that must already be attacker-controlled) from
    /// `rdi <- 0x1234`. A register written twice appears twice; the last
    /// entry for a destination is the one that survives.
    ///
    /// Empty on the text fallback path, and for instruction shapes the
    /// analysis does not model.
    pub transfers: Vec<Transfer>,
    /// Registers the gadget writes with a value the chain payload decides —
    /// a pop, an rsp-relative load, a folded constant, or any known function
    /// of those (CLS-09).
    ///
    /// Names are architectural full-width (`rax` in 64-bit code, `eax` in
    /// 32-bit, `x0` rather than `w0` on ARM64), because `mov al, [rsp]`
    /// controls al but not rax and the question a chain author asks is about
    /// rax. `sets` and [`Classification::clobbers`] partition the full-width
    /// registers the gadget writes; neither ever contains the stack pointer,
    /// whose movement is [`Classification::stack_delta`].
    pub sets: Vec<String>,
    /// Registers the gadget writes with a value the chain payload does *not*
    /// decide — it came from an incoming register, from non-stack memory, or
    /// from the incoming flags (CLS-09).
    ///
    /// This is what `--no-clobber rsi,rdx` filters on, and it is a strictly
    /// stronger statement than "the register appears in `regs_written`":
    /// `pop rsi ; ret` writes rsi and clobbers nothing, `mov rsi, rax ; ret`
    /// writes rsi and clobbers it. When a clobber has a known source, the
    /// corresponding [`Transfer`] names it, so a chain builder can decide to
    /// control the source instead of rejecting the gadget.
    pub clobbers: Vec<String>,
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

    /// The nine-way `ret / ret-imm / jmp-reg / jmp-mem / call-reg / call-mem
    /// / syscall / far / other` classification the query layer filters on
    /// (CLS-09).
    ///
    /// Derived from [`Classification::terminator`] and
    /// [`Classification::terminator_target`] rather than stored, so there is
    /// one source of truth. A *direct* `jmp 0x400340` or `call 0x401120` is
    /// `Other`: neither is reachable from a chain without the address being
    /// what you wanted anyway.
    pub fn terminator_class(&self) -> TerminatorClass {
        match self.terminator {
            Terminator::Ret => TerminatorClass::Ret,
            Terminator::RetImm => TerminatorClass::RetImm,
            Terminator::Retf | Terminator::Iret | Terminator::Far => TerminatorClass::Far,
            Terminator::Syscall => TerminatorClass::Syscall,
            Terminator::Jmp => match self.terminator_target {
                TerminatorTarget::Register { .. } => TerminatorClass::JmpReg,
                TerminatorTarget::Memory { .. } => TerminatorClass::JmpMem,
                _ => TerminatorClass::Other,
            },
            Terminator::Call => match self.terminator_target {
                TerminatorTarget::Register { .. } => TerminatorClass::CallReg,
                TerminatorTarget::Memory { .. } => TerminatorClass::CallMem,
                _ => TerminatorClass::Other,
            },
            Terminator::None => TerminatorClass::Other,
        }
    }

    /// Does the gadget write `reg` with a value the chain payload decides?
    /// The predicate behind `--set-reg`.
    ///
    /// `reg` is matched case-insensitively against the full-width names in
    /// [`Classification::sets`].
    pub fn sets_reg(&self, reg: &str) -> bool {
        self.sets.iter().any(|r| r.eq_ignore_ascii_case(reg))
    }

    /// Does the gadget write `reg` with a value the chain payload does *not*
    /// decide? The predicate behind `--no-clobber`.
    pub fn clobbers_reg(&self, reg: &str) -> bool {
        self.clobbers.iter().any(|r| r.eq_ignore_ascii_case(reg))
    }

    /// Does the gadget clobber any of `regs`? `--no-clobber rsi,rdx` is
    /// `!c.clobbers_any(["rsi", "rdx"])`.
    pub fn clobbers_any<I, S>(&self, regs: I) -> bool
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        regs.into_iter().any(|r| self.clobbers_reg(r.as_ref()))
    }

    /// Is `reg`'s final value loaded straight off the chain payload — a pop,
    /// or a load whose base is the stack pointer? The predicate behind
    /// `--from-stack`, and strictly stronger than [`Classification::sets_reg`]:
    /// `xor rdi, rdi ; ret` sets rdi without taking it from the stack.
    ///
    /// Uses the *last* transfer that writes `reg`, so
    /// `pop rdi ; mov rdi, rax ; ret` is not from-stack.
    pub fn reg_from_stack(&self, reg: &str) -> bool {
        self.last_transfer_to(reg)
            .is_some_and(Transfer::is_stack_load)
    }

    /// The payload offset, in bytes from the stack pointer at gadget entry,
    /// that supplies `reg` — `Some(0)` for rdi in `pop rdi ; pop rsi ; ret`
    /// and `Some(8)` for rsi. `None` when `reg` is not loaded from the stack
    /// or the offset is not constant.
    pub fn stack_offset_of(&self, reg: &str) -> Option<i64> {
        match &self.last_transfer_to(reg)?.src {
            ValueSrc::Stack { offset } => *offset,
            _ => None,
        }
    }

    /// The last [`Transfer`] whose destination is register `reg`.
    pub fn last_transfer_to(&self, reg: &str) -> Option<&Transfer> {
        self.transfers.iter().rev().find(|t| {
            t.dst
                .register()
                .is_some_and(|d| d.eq_ignore_ascii_case(reg))
        })
    }

    /// Every memory write the gadget performs, as `(destination, source)`
    /// pairs — the write-what-where primitive a chain builder looks for.
    pub fn memory_writes(&self) -> impl Iterator<Item = &Transfer> {
        self.transfers.iter().filter(|t| t.dst.is_memory())
    }

    /// Is `reg` an *input* of this gadget? The predicate behind
    /// `--reads-reg` / `reads_reg`.
    ///
    /// No single field answers this, which is why it lives here rather than
    /// being re-derived per front end — it was, and the two spellings
    /// disagreed by 741 gadgets on `elf-Linux-x64` at depth 4 because one of
    /// them left the terminator out. Three sources are unioned:
    ///
    /// 1. [`Classification::regs_read`], the v0.3 list. It keeps the
    ///    *operand's* spelling (`al`, `edi`), so on its own `reads_reg("rax")`
    ///    would miss `add al, cl`.
    /// 2. The transfer relations, which carry full-width names: a register
    ///    read as a value source ([`ValueSrc::Register`]), as an address
    ///    component (base or index, on either side), as a declared dependency
    ///    ([`Transfer::needs`]), or as the destination of a read-modify-write.
    /// 3. The terminator's own target register. `jmp rax` reads rax — it is
    ///    the branch target, and a chain builder asking which gadgets consume
    ///    rax must be given the JOP dispatchers.
    ///
    /// Matching is case-insensitive on every source.
    pub fn reads_reg(&self, reg: &str) -> bool {
        if self.regs_read.iter().any(|r| r.eq_ignore_ascii_case(reg)) {
            return true;
        }
        if self
            .terminator_target
            .register()
            .is_some_and(|r| r.eq_ignore_ascii_case(reg))
        {
            return true;
        }
        let hit = |o: &Option<String>| o.as_deref().is_some_and(|r| r.eq_ignore_ascii_case(reg));
        self.transfers.iter().any(|t| {
            t.needs.iter().any(|r| r.eq_ignore_ascii_case(reg))
                || match &t.src {
                    ValueSrc::Register { reg: r } => r.eq_ignore_ascii_case(reg),
                    ValueSrc::Memory { base, index, .. }
                    | ValueSrc::Address { base, index, .. } => hit(base) || hit(index),
                    _ => false,
                }
                || match &t.dst {
                    ValueDst::Memory { base, index, .. } => hit(base) || hit(index),
                    // A read-modify-write reads its destination register.
                    ValueDst::Register { reg: r } => t.rmw && r.eq_ignore_ascii_case(reg),
                    _ => false,
                }
        })
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
    /// The usability tier, 0-3; see [`usability`].
    pub usability: u8,
    /// The quality score; see [`quality_score`].
    pub quality: i32,
    /// Instruction count, terminator included.
    pub n_insns: usize,
    /// Side-effect count (TAXONOMY.md R11).
    pub side_effects: usize,
    /// The gadget's address — the deterministic final tie-break.
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
    /// Build a classifier for `arch`, opening every capstone detail mode
    /// that could have produced a gadget for it.
    ///
    /// Reuse one classifier across a whole listing: opening the detail
    /// handles is the expensive part, and [`Classifier::classify`] takes
    /// `&self`.
    pub fn new(arch: Arch) -> Self {
        Classifier {
            arch,
            detailers: RefCell::new(Detailer::all_candidates(arch)),
        }
    }

    /// The architecture this classifier was built for.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// True when this architecture has decoder metadata available — i.e. when
    /// results will not be `low_confidence`.
    pub fn has_metadata(&self) -> bool {
        self.arch.is_x86_family() || !self.detailers.borrow().is_empty()
    }

    /// Classify one gadget.
    ///
    /// Prefer this over the free [`classify`] function when classifying
    /// more than one gadget: this reuses the open decoder handles.
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
