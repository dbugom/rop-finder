//! The semantic layer a constraint search needs and no consumer can derive
//! from gadget text (CLS-09).
//!
//! Four things live here:
//!
//! 1. **Stack delta** — [`Classification::stack_delta`](crate::Classification::stack_delta),
//!    documented on that field. `Option<i64>`, and `None` is a first-class
//!    answer, not a failure: see [`stack_delta`](crate::Classification::stack_delta).
//! 2. **Register-transfer relations** — [`Transfer`], with the source kind
//!    ([`ValueSrc`]) distinguished, so `--from-stack` can mean "the value came
//!    off the chain payload" rather than "the register ended up written
//!    somehow".
//! 3. **The clobber set** — [`Classification::clobbers`](crate::Classification::clobbers)
//!    versus [`Classification::sets`](crate::Classification::sets), documented
//!    on those fields.
//! 4. **A filterable terminator classification** — [`TerminatorClass`], the
//!    nine-way `ret / ret-imm / jmp-reg / jmp-mem / call-reg / call-mem /
//!    syscall / far / other` split the query layer filters on. It is derived
//!    from the existing [`Terminator`](crate::Terminator) plus
//!    [`TerminatorTarget`]; the v0.3 enum and its serialized spellings are
//!    unchanged.
//!
//! Everything here is *additive*: no existing field, name or serialization
//! changed, so the v0.3 MCP `outputSchema` and the CLI's `--json` record are
//! byte-identical until a consumer opts in.

use serde::Serialize;

/// Where a value came from.
///
/// The `Stack` / `Register` / `Memory` / `Immediate` split is the point of
/// this type: a chain builder needs to know that `pop rdi` takes rdi from the
/// payload while `mov rdi, rax` takes it from whatever rax happened to hold,
/// and both are "rdi was written" to every consumer that only sees
/// [`Classification::regs_written`](crate::Classification::regs_written).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ValueSrc {
    /// The chain payload: a pop, or a load whose base register is the stack
    /// pointer.
    ///
    /// `offset` is the byte offset from the stack pointer's value at gadget
    /// **entry** — so `pop rdi ; pop rsi ; ret` reports rdi from offset 0 and
    /// rsi from offset 8 — and is `None` when the running stack-pointer delta
    /// stopped being constant before this instruction.
    Stack { offset: Option<i64> },
    /// Another register's incoming value (`mov rax, rbx`).
    Register { reg: String },
    /// Memory that is *not* on the stack. `base` is the register that must
    /// already hold an attacker-controlled pointer for the operand to be
    /// usable; it is `None` for an absolute or PC-relative address, which
    /// needs no set-up at all.
    Memory {
        base: Option<String>,
        index: Option<String>,
        disp: i64,
    },
    /// The *address* of a memory operand rather than its contents — x86
    /// `lea`, and the address-forming half of a load/store.
    Address {
        base: Option<String>,
        index: Option<String>,
        disp: i64,
    },
    /// An instruction immediate.
    Immediate { value: i64 },
    /// A combination this analysis does not decompose further (`mul`, a
    /// three-input arithmetic form, a conditional move).
    Computed,
}

impl ValueSrc {
    /// True for a value that came off the chain payload — the predicate
    /// behind `--from-stack`.
    pub fn is_from_stack(&self) -> bool {
        matches!(self, ValueSrc::Stack { .. })
    }

    /// The register that must already hold an attacker-controlled pointer
    /// before this source can be read, if any.
    pub fn pointer_dep(&self) -> Option<&str> {
        match self {
            ValueSrc::Memory { base, .. } => base.as_deref(),
            _ => None,
        }
    }
}

/// Where a value went.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ValueDst {
    Register {
        reg: String,
    },
    /// A stack slot, at a byte offset from the stack pointer's value at
    /// gadget entry (`push rax` on entry writes offset -8 on x86-64).
    Stack {
        offset: Option<i64>,
    },
    /// Non-stack memory. `base` is the register that must already hold an
    /// attacker-controlled pointer — this is the field that separates
    /// `mov qword ptr [rdi], rax` (a controlled arbitrary write) from
    /// `add byte ptr [rax], al` (a byte increment through the pointer it is
    /// incrementing with).
    Memory {
        base: Option<String>,
        index: Option<String>,
        disp: i64,
    },
}

impl ValueDst {
    pub fn register(&self) -> Option<&str> {
        match self {
            ValueDst::Register { reg } => Some(reg.as_str()),
            _ => None,
        }
    }

    /// The register that must already hold an attacker-controlled pointer for
    /// the write to land where intended.
    pub fn pointer_dep(&self) -> Option<&str> {
        match self {
            ValueDst::Memory { base, .. } => base.as_deref(),
            _ => None,
        }
    }

    pub fn is_memory(&self) -> bool {
        matches!(self, ValueDst::Memory { .. })
    }
}

/// One value movement inside a gadget: `dst <- src`.
///
/// Transfers are recorded in program order, one per modelled instruction. A
/// register written twice produces two entries; the **last** entry for a
/// destination is the one that survives the gadget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Transfer {
    pub dst: ValueDst,
    pub src: ValueSrc,
    /// Registers that must already hold attacker-controlled values for this
    /// transfer to be usable — the base and index registers of whichever of
    /// `dst`/`src` is a non-stack memory operand. Empty for a pure
    /// register-to-register move.
    pub needs: Vec<String>,
    /// The destination is read as well as written: `add rax, rbx`,
    /// `add byte ptr [rax], al`. A read-modify-write cannot *place* a chosen
    /// value; it can only perturb whatever is already there.
    pub rmw: bool,
    /// Width of the moved value in bytes, when the decoder states it.
    pub width: Option<u32>,
}

impl Transfer {
    /// `dst <- src` where the destination is a register and the source is the
    /// chain payload.
    pub fn is_stack_load(&self) -> bool {
        !self.rmw && self.dst.register().is_some() && self.src.is_from_stack()
    }
}

/// How the terminating control transfer picks its target.
///
/// Split out from [`Terminator`](crate::Terminator) rather than folded into
/// it so that no existing variant, name or serialized string changes: v0.3's
/// `terminator` field still reads `"ret"`, `"jmp"`, `"call"`, and the
/// register/memory distinction the query layer wants arrives beside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TerminatorTarget {
    /// The target is an immediate encoded in the instruction
    /// (`jmp 0x400340`, `call 0x401120`).
    Direct,
    /// Indirect through a register (`jmp rax`, `blr x16`, `bctr`).
    Register { reg: String },
    /// Indirect through memory (`jmp qword ptr [rax + 8]`).
    Memory {
        base: Option<String>,
        index: Option<String>,
        disp: i64,
    },
    /// The target is not an operand: it comes off the stack (`ret`) or out of
    /// a link register (`bx lr`, `jr $ra`, `blr`), or there is no terminator.
    Implicit,
}

impl TerminatorTarget {
    /// The register the transfer goes through, for `--dispatcher`-style
    /// queries.
    pub fn register(&self) -> Option<&str> {
        match self {
            TerminatorTarget::Register { reg } => Some(reg.as_str()),
            TerminatorTarget::Memory { base, .. } => base.as_deref(),
            _ => None,
        }
    }
}

/// The nine-way terminator classification the query layer filters on.
///
/// This is the vocabulary CLS-09 asks for. It is *derived*, not stored:
/// [`Classification::terminator_class`](crate::Classification::terminator_class)
/// folds [`Terminator`](crate::Terminator) together with
/// [`TerminatorTarget`], so there is exactly one source of truth for what a
/// gadget's terminator is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TerminatorClass {
    /// A bare near return.
    Ret,
    /// `ret imm16` — returns, and also advances the stack pointer.
    RetImm,
    /// `jmp reg`.
    JmpReg,
    /// `jmp [mem]`.
    JmpMem,
    /// `call reg`.
    CallReg,
    /// `call [mem]`.
    CallMem,
    /// A syscall/interrupt gate.
    Syscall,
    /// A far or privilege-changing transfer: `retf`, `iret`, `jmp far`,
    /// `call far`.
    Far,
    /// Anything else — a direct `jmp`/`call` to a fixed address, or no
    /// terminator at all.
    Other,
}

impl TerminatorClass {
    /// The serialized spelling: `"ret"`, `"ret-imm"`, `"jmp-reg"`,
    /// `"jmp-mem"`, `"call-reg"`, `"call-mem"`, `"syscall"`, `"far"`,
    /// `"other"`.
    pub fn name(self) -> &'static str {
        match self {
            TerminatorClass::Ret => "ret",
            TerminatorClass::RetImm => "ret-imm",
            TerminatorClass::JmpReg => "jmp-reg",
            TerminatorClass::JmpMem => "jmp-mem",
            TerminatorClass::CallReg => "call-reg",
            TerminatorClass::CallMem => "call-mem",
            TerminatorClass::Syscall => "syscall",
            TerminatorClass::Far => "far",
            TerminatorClass::Other => "other",
        }
    }

    /// Every accepted value, for a parameter-validation error message.
    pub const ALL: &'static [&'static str] = &[
        "ret", "ret-imm", "jmp-reg", "jmp-mem", "call-reg", "call-mem", "syscall", "far", "other",
    ];

    /// Parse the serialized spelling.
    pub fn parse(s: &str) -> Option<TerminatorClass> {
        Some(match s {
            "ret" => TerminatorClass::Ret,
            "ret-imm" => TerminatorClass::RetImm,
            "jmp-reg" => TerminatorClass::JmpReg,
            "jmp-mem" => TerminatorClass::JmpMem,
            "call-reg" => TerminatorClass::CallReg,
            "call-mem" => TerminatorClass::CallMem,
            "syscall" => TerminatorClass::Syscall,
            "far" => TerminatorClass::Far,
            "other" => TerminatorClass::Other,
            _ => return None,
        })
    }
}
