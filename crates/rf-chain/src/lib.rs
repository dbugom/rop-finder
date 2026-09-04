//! rf-chain — ROP chain builders (Phase 4a, PLAN.md §6.2).
//!
//! **Chain IR first** (the review-driven design): builders produce a
//! structured [`RopChain`] — a `Vec<ChainWord>` where every word knows its
//! kind, its comment, and which gadget it came from — and renderers turn
//! the IR into ROPgadget-compatible Python exploit text, JSON, or raw
//! little-endian bytes. ROPgadget's stdout-text design is why nothing can
//! consume its chains programmatically; the IR is the fix.
//!
//! Invariants are checked at build/validation time and reported as
//! structured [`ChainError`]s, never panics:
//!   * every `GadgetAddr` word's value is the vaddr of an actually-reported
//!     gadget (checked against the scan's vaddr universe);
//!   * every non-gadget word (`Immediate` / `DataAddr` / `Padding`) must be
//!     badbyte-free when bad bytes are configured — bad bytes are a
//!     property of the final packed word (PLAN.md §6.4);
//!   * per-target invariant hooks ([`ChainInvariant`]) are the Phase 4b
//!     extension point — the Win64 16-byte stack-alignment invariant lands
//!     there; Linux execve needs no extra invariants.
//!
//! # Getting started
//!
//! ```
//! use rf_chain::{build_linux, DataSection, LinuxChainOpts, WordKind};
//! use rf_core::{Arch, Binary, Image};
//! use rf_scan::{scan_binary, ScanOptions};
//!
//! # fn demo(bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! let elf = Binary::parse(bytes)?;
//! let gadgets = scan_binary(&elf, &ScanOptions::default())?;
//! let data: Vec<DataSection> = elf
//!     .sections()
//!     .iter()
//!     .filter(|s| !s.executable)
//!     .map(|s| DataSection { name: s.name.clone(), vaddr: s.vaddr, writable: s.writable })
//!     .collect();
//!
//! let chain = build_linux(
//!     &gadgets,
//!     &data,
//!     Image::arch(&elf),
//!     "elf",
//!     &[],
//!     &LinuxChainOpts::default(),
//! )?;
//!
//! // The IR is the point: every word knows what it is.
//! assert!(chain.words.iter().any(|w| w.kind == WordKind::GadgetAddr));
//! let _python = chain.to_python();
//! let _json = chain.to_json();
//! let _bytes = chain.to_bytes();
//! # Ok(())
//! # }
//! ```
//!
//! # Semver policy
//!
//! Covered by semver from 1.0: the signatures of [`build_linux`],
//! [`build_windows_virtualprotect`], [`plan_linux`] and [`plan_windows`];
//! the fields of [`RopChain`], [`ChainWord`], [`GadgetRef`] and
//! [`plan::ChainPlan`]; the [`WordKind`] and [`ChainError`] variant sets;
//! and the `--chain` target names in [`LinuxTarget::NAMES`].
//!
//! **Not** covered, and free to change in a patch release: **which gadgets
//! a chain picks and therefore its exact byte payload** — a better strategy
//! is a bug fix, and the emulator harness (`tests/emulate.py`) is what
//! holds the behaviour, not the byte sequence; the exact Python script text
//! beyond the ROPgadget-compatible header; and every error and comment
//! string. Adding a [`WordKind`] variant or a chain target is a minor
//! release. Pin `rf-chain = "1"`.
//!
//! See `docs/API-STABILITY.md` in the repository for the workspace-wide
//! statement.

#![warn(missing_docs)]

use rf_core::Arch;
use serde::Serialize;
use std::collections::HashSet;

pub mod linux;
pub mod plan;
pub mod windows;

pub use linux::plan_linux;
pub use linux::{build_linux, build_linux_execve, DataSection, LinuxChainOpts, LinuxTarget};
pub use plan::{
    ChainPlan, PlanAssumptions, Relaxation, Requirement, SatisfiedRequirement, Strategy,
};
pub use windows::plan_windows;
pub use windows::{build_windows_virtualprotect, PeExport, WinChainOpts};

/// What a chain word is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WordKind {
    /// Address of a gadget in the scanned binary.
    GadgetAddr,
    /// Immediate constant rendered as a Python bytes literal (e.g. the
    /// packed "/bin//sh" string).
    Immediate,
    /// Address-like constant rendered as a `pack()` word: data-section
    /// locations (`@ .data`), and on Windows also numeric stack arguments.
    DataAddr,
    /// Control-flow target that is not a gadget from this binary: an API
    /// entry address (`--api-addr`), a shellcode/return address. Rendered
    /// as a `pack()` word; badbyte-checked like DataAddr.
    CodeAddr,
    /// Filler consumed by a `pop` in a gadget's tail, shadow space, or a
    /// stack-alignment word.
    Padding,
}

fn hex_u64<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{v:x}"))
}

/// One machine word of the chain (8 bytes on x64, 4 on x86).
#[derive(Debug, Clone, Serialize)]
pub struct ChainWord {
    /// The word's value, serialized as a hex string.
    #[serde(serialize_with = "hex_u64")]
    pub value: u64,
    /// What this word IS - the distinction the emulator harness checks.
    pub kind: WordKind,
    /// Human-readable note, emitted beside the word in the Python script.
    pub comment: String,
    /// Index into [`RopChain::gadgets`] for `GadgetAddr` words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_gadget: Option<usize>,
}

/// A gadget referenced by the chain.
#[derive(Debug, Clone, Serialize)]
pub struct GadgetRef {
    /// The gadget's address, serialized as a hex string.
    #[serde(serialize_with = "hex_u64")]
    pub vaddr: u64,
    /// The gadget's disassembly text.
    pub text: String,
}

/// A generated ROP chain in target-independent form.
#[derive(Debug, Clone, Serialize)]
pub struct RopChain {
    /// e.g. "x86" / "x64".
    pub arch: String,
    /// Human-readable summary of what the chain does.
    pub description: String,
    /// Second line of the python script header. Linux builders keep
    /// "# execve generated by ROPgadget" verbatim for byte parity; Windows
    /// builders use their own comment.
    pub script_comment: String,
    /// Bytes per word (4 or 8).
    pub word_size: usize,
    /// The chain payload, one machine word per entry, in stack order.
    pub words: Vec<ChainWord>,
    /// Distinct gadgets referenced by `GadgetAddr` words, in order of
    /// first reference; `ChainWord::source_gadget` indexes this list.
    pub gadgets: Vec<GadgetRef>,
}

/// Structured chain-building failure. Builders never panic and never emit
/// partial garbage: any missing gadget or violated invariant is an `Err`.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// Mirrors ropmaker.py:23-40 dispatch: only ELF x86/x64 are supported.
    #[error("arch {arch} / format {format} not supported yet for the rop chain generation")]
    Unsupported {
        /// The architecture that was asked for.
        arch: String,
        /// The container format that was asked for.
        format: String,
    },
    /// A required gadget is absent from the scan output.
    #[error("can't find a suitable gadget: {0}")]
    MissingGadget(String),
    /// No `.data` (and no fallback writable section) for the string write.
    #[error("can't find a writable section")]
    NoWritableSection,
    /// An IR invariant was violated (see [`RopChain::validate`]).
    #[error("chain word {index} (0x{value:016x}, {kind:?}): {reason}")]
    InvalidWord {
        /// Index into [`RopChain::words`].
        index: usize,
        /// The offending word's value.
        value: u64,
        /// The offending word's kind.
        kind: WordKind,
        /// Which invariant it violated.
        reason: String,
    },
}

/// Per-target invariant hook (Phase 4b extension point). Receives the full
/// chain; returns `Err` to reject it. Example for Phase 4b (Win64):
/// "rsp must be 16-byte aligned at the VirtualProtect call site".
pub type ChainInvariant<'a> = &'a dyn Fn(&RopChain) -> Result<(), ChainError>;

/// What consumed a stack word, as reconstructed by
/// [`RopChain::verify_stack_accounting`].
///
/// In a ret-chain every word has exactly one consumer. There is no such
/// thing as a word the machine skips over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WordRole {
    /// A `ret` (or the initial pivot) loaded this word into the instruction
    /// pointer.
    ControlTransfer,
    /// A `pop` in the preceding gadget took this word (or a `ret <imm>`
    /// stack adjustment discarded it).
    PopOperand,
    /// Past the point where control leaves the chain — an API entry, a
    /// `jmp reg`, a `syscall`. Return addresses, Win64 shadow space and
    /// stdcall arguments live here. Static accounting cannot model an
    /// opaque callee, so it stops and says so instead of guessing.
    CalleeFrame,
}

/// The outcome of the static stack-word accounting walk (CHLX-04).
#[derive(Debug, Clone, Serialize)]
pub struct StackAccounting {
    /// One entry per word of the chain, in order.
    pub roles: Vec<WordRole>,
    /// Index of the first word the walk could no longer account for, i.e.
    /// the start of the callee's frame. `None` when the chain accounts for
    /// every word it emits.
    pub callee_frame_from: Option<usize>,
    /// Why the walk stopped ("chain fully accounted", "control left the
    /// chain at word 8 via `jmp rax`", ...).
    pub stop_reason: String,
    /// `CHWIN-08`: the index of the word a `pop rsp` / `pop esp` consumed
    /// as the new stack pointer, when the chain pivots. The walk continues
    /// past a pivot rather than abstaining, because the builder's pivot
    /// layout contract (`WinAssumptions::pivot_addr` / `pivot_words`) says
    /// the body sits at that address, i.e. exactly where the IR continues.
    pub pivot_at: Option<usize>,
}

impl StackAccounting {
    /// Words the walk verified (everything before the callee frame).
    pub fn words_verified(&self) -> usize {
        self.callee_frame_from.unwrap_or(self.roles.len())
    }
}

/// Split a gadget's rendered text into instructions. `Gadget::text()` joins
/// with `" ; "` (rf-scan engine.rs), and the Chain IR carries that same
/// string, so the verifier reads the same text a user reads.
fn gadget_insns(text: &str) -> Vec<&str> {
    text.split(" ; ").map(str::trim).collect()
}

/// `ret 0x10` / `ret 16` -> the immediate; `ret` -> `None`.
fn ret_immediate(insn: &str) -> Option<u64> {
    let arg = insn.strip_prefix("ret ")?.trim();
    match arg.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => arg.parse::<u64>().ok(),
    }
}

/// Instructions that move rsp by an amount the verifier does not model.
/// None of the current builders emit one; a stack pivot (CHWIN-08) will, and
/// when it does the walk must stop rather than report a confident wrong
/// answer.
fn unmodelled_stack_effect(insn: &str) -> bool {
    let mut parts = insn.splitn(2, ' ');
    let head = parts.next().unwrap_or("");
    if matches!(
        head,
        "leave" | "enter" | "push" | "pusha" | "pushad" | "pushal" | "popa" | "popad" | "popal"
    ) {
        return true;
    }
    // `pop rsp` / `pop esp` IS modelled -- see the pivot arm of
    // `verify_stack_accounting` (CHWIN-08) -- so it is not unmodelled here.
    if insn == "pop rsp" || insn == "pop esp" {
        return false;
    }
    // Anything else whose destination operand IS the stack pointer:
    // `add rsp, 0x18`, `xchg rsp, rax`, `mov esp, ebp`.
    let dst = parts
        .next()
        .unwrap_or("")
        .split(',')
        .next()
        .unwrap_or("")
        .trim();
    matches!(dst, "rsp" | "esp" | "sp")
}

impl RopChain {
    /// Check the build-time invariants:
    ///   * every `GadgetAddr` word points at a real reported gadget
    ///     (`universe` = the scan's vaddr set) and its `source_gadget`
    ///     index agrees;
    ///   * every non-gadget word is badbyte-free (packed at `word_size`).
    pub fn validate(&self, universe: &HashSet<u64>, badbytes: &[u8]) -> Result<(), ChainError> {
        self.validate_with(universe, badbytes, &[])
    }

    /// [`validate`](Self::validate) plus per-target invariant hooks.
    pub fn validate_with(
        &self,
        universe: &HashSet<u64>,
        badbytes: &[u8],
        hooks: &[ChainInvariant],
    ) -> Result<(), ChainError> {
        for (i, w) in self.words.iter().enumerate() {
            let invalid = |reason: String| ChainError::InvalidWord {
                index: i,
                value: w.value,
                kind: w.kind,
                reason,
            };
            match w.kind {
                WordKind::GadgetAddr => {
                    let idx = w
                        .source_gadget
                        .ok_or_else(|| invalid("gadget word without source_gadget".to_string()))?;
                    let g = self
                        .gadgets
                        .get(idx)
                        .ok_or_else(|| invalid(format!("source_gadget {idx} out of range")))?;
                    if g.vaddr != w.value {
                        return Err(invalid(format!(
                            "value {:#x} != gadgets[{idx}].vaddr {:#x}",
                            w.value, g.vaddr
                        )));
                    }
                    if !universe.contains(&w.value) {
                        return Err(invalid(format!(
                            "vaddr {:#x} is not in the scan output",
                            w.value
                        )));
                    }
                }
                WordKind::Immediate
                | WordKind::DataAddr
                | WordKind::CodeAddr
                | WordKind::Padding => {
                    if !badbytes.is_empty() {
                        let packed = &w.value.to_le_bytes()[..self.word_size];
                        if let Some(b) = packed.iter().find(|b| badbytes.contains(b)) {
                            return Err(invalid(format!(
                                "packed word contains bad byte 0x{b:02x}"
                            )));
                        }
                    }
                }
            }
        }
        // CHLX-04: the words are well-formed; are they a chain that RUNS?
        // A refusal, not a warning — "chains that are emitted must be
        // runnable or not emitted".
        self.verify_stack_accounting()?;
        for hook in hooks {
            hook(self)?;
        }
        Ok(())
    }

    /// Static semantic verification: walk the chain the way the machine
    /// will, and account for every stack word (CHLX-04).
    ///
    /// `RopChain::validate` only ever answered "do these words point at real
    /// gadgets, and are they badbyte-free?" — a chain whose words are all of
    /// the right *kind* but whose layout is dead passes it. This walk asks
    /// the next question. In a ret-chain every stack word is consumed by
    /// exactly one thing: a `pop` inside a gadget, or the `ret` that ends
    /// one. There is no filler the machine skips over, so the model is
    /// exact rather than approximate:
    ///
    /// 1. the pivot's `ret` loads word 0 into rip;
    /// 2. a `GadgetAddr` word's gadget consumes one word per `pop` it
    ///    contains, then its terminator decides what happens next —
    ///    a bare `ret` transfers to the following word, `ret <imm>`
    ///    additionally discards `imm/word_size` words, and anything else
    ///    (`syscall`, `int 0x80`, `jmp reg`, `call reg`) hands control to
    ///    something this chain does not describe;
    /// 3. a `CodeAddr` word is an entry point outside the chain (an API
    ///    address, a shellcode address) — same thing.
    ///
    /// From (2)/(3) onwards the remaining words are the callee's frame — a
    /// return address, Win64 shadow space, stdcall arguments — and are
    /// reported as [`WordRole::CalleeFrame`] rather than guessed at. The
    /// emulator covers that half; this walk covers the half a static check
    /// can actually decide.
    ///
    /// Two shapes are rejected, and both are real inherited defects:
    ///
    /// * **a data word in control position** — the preceding gadget's `ret`
    ///   consumes an `Immediate`/`DataAddr`/`Padding` word as its next
    ///   instruction pointer. That is CHWIN-01 exactly: an inert
    ///   `0x4141414141414141` alignment pad inserted before the API
    ///   transfer word is not skipped, it is *jumped to*. A stack-alignment
    ///   pad has to be the address of a bare `ret` gadget, which consumes
    ///   itself and advances rsp by one word.
    /// * **a gadget address in pop position** — a `pop` swallows a word the
    ///   IR itself labelled `GadgetAddr`, which means the padding count and
    ///   the emitted word count have drifted apart (a missing padding word
    ///   shifts every later word left by one). A code pointer that is
    ///   *meant* to be popped as data should be emitted as `CodeAddr`.
    pub fn verify_stack_accounting(&self) -> Result<StackAccounting, ChainError> {
        let n = self.words.len();
        let mut roles: Vec<WordRole> = Vec::with_capacity(n);
        let mut callee_frame_from = None;
        let mut stop_reason = String::from("chain fully accounted: every word is consumed");
        let mut sp = 0usize;
        let mut pending_drop = 0usize;
        let mut pivot_at: Option<usize> = None;

        let invalid = |i: usize, reason: String| {
            let w = &self.words[i];
            ChainError::InvalidWord {
                index: i,
                value: w.value,
                kind: w.kind,
                reason,
            }
        };

        while sp < n {
            let here = sp;
            let w = &self.words[here];
            roles.push(WordRole::ControlTransfer);
            sp += 1;
            // A `ret <imm>` that transferred here also discarded imm bytes.
            for _ in 0..pending_drop {
                if sp >= n {
                    break;
                }
                roles.push(WordRole::PopOperand);
                sp += 1;
            }
            pending_drop = 0;

            let text = match w.kind {
                WordKind::GadgetAddr => {
                    let idx = w.source_gadget.ok_or_else(|| {
                        invalid(here, "gadget word without source_gadget".to_string())
                    })?;
                    self.gadgets
                        .get(idx)
                        .ok_or_else(|| invalid(here, format!("source_gadget {idx} out of range")))?
                        .text
                        .clone()
                }
                WordKind::CodeAddr => {
                    callee_frame_from = Some(sp);
                    stop_reason = format!(
                        "control leaves the chain at word {here} ({:#x} is an entry point \
                         outside this binary's gadget set); words {sp}.. are the callee's frame",
                        w.value
                    );
                    break;
                }
                WordKind::Immediate | WordKind::DataAddr | WordKind::Padding => {
                    return Err(invalid(
                        here,
                        format!(
                            "static stack accounting (CHLX-04): control transfers here — the \
                             preceding `ret` loads this word into rip — but it is a {:?} word, \
                             not a gadget or code address. In a ret-chain there is no filler the \
                             machine skips over: a stack alignment pad must be the ADDRESS OF A \
                             BARE `ret` GADGET, which consumes itself and advances rsp by one \
                             word (CHWIN-01)",
                            w.kind
                        ),
                    ));
                }
            };

            let insns = gadget_insns(&text);
            let mut terminal: Option<String> = None;
            for insn in &insns {
                if unmodelled_stack_effect(insn) {
                    terminal = Some(format!("`{insn}` moves rsp by an unmodelled amount"));
                    break;
                }
                if *insn == "pop rsp" || *insn == "pop esp" {
                    // CHWIN-08: a stack pivot. The word this takes is the
                    // NEW stack pointer; the gadget's own `ret` then reads
                    // its target from there, which the chain IR places
                    // immediately after by the pivot layout contract
                    // (`WinAssumptions::pivot_addr` / `pivot_words`). So
                    // the walk continues instead of abstaining -- and it
                    // records where, because a reader of the accounting
                    // needs to know the words after this point live at a
                    // different address.
                    if sp >= n {
                        return Err(invalid(
                            here,
                            format!(
                                "static stack accounting (CHLX-04): the pivot gadget `{text}`                                  pops the stack pointer past the end of the chain"
                            ),
                        ));
                    }
                    if pivot_at.is_some() {
                        terminal = Some(format!(
                            "`{insn}` is a SECOND stack pivot; one relocation of the chain body                              is a declared layout, two is not modelled"
                        ));
                        break;
                    }
                    roles.push(WordRole::PopOperand);
                    pivot_at = Some(sp);
                    sp += 1;
                    continue;
                }
                if insn.starts_with("pop ") {
                    if sp >= n {
                        return Err(invalid(
                            here,
                            format!(
                                "static stack accounting (CHLX-04): gadget `{text}` pops past the \
                                 end of the chain — only {} word(s) follow it, and it needs one \
                                 per `pop`",
                                n - here - 1
                            ),
                        ));
                    }
                    if self.words[sp].kind == WordKind::GadgetAddr {
                        return Err(invalid(
                            sp,
                            format!(
                                "static stack accounting (CHLX-04): `{insn}` in the gadget at \
                                 word {here} consumes this word as data, but the IR labels it a \
                                 gadget address — the emitted word \
                                 count and the gadget's pop count have drifted apart (a missing \
                                 padding word shifts every later word left). Emit a code pointer \
                                 that is meant to be popped as `CodeAddr` (CHLX-04)"
                            ),
                        ));
                    }
                    roles.push(WordRole::PopOperand);
                    sp += 1;
                    continue;
                }
            }
            if let Some(why) = terminal {
                callee_frame_from = Some(sp);
                stop_reason = format!(
                    "stopped at word {here}: {why}; words {sp}.. are not statically accounted"
                );
                break;
            }

            match insns.last().copied().unwrap_or("") {
                // `repz ret` / `rep ret` is the AMD-K8 branch-prediction
                // spelling of a plain near return; `rf_classify` reports it
                // as `Terminator::Ret`, `linux.rs::is_bare_ret` accepts it,
                // and elf-x64-bash-v4.1.5.1's only route to rdx is
                // `pop rdx ; repz ret` -- so a walk that did not know the
                // spelling abstained on real emitted chains.
                "ret" | "repz ret" | "rep ret" | "ret 0" | "ret 0x0" => {}
                other if ret_immediate(other).is_some() => {
                    let imm = ret_immediate(other).unwrap_or(0) as usize;
                    pending_drop = imm / self.word_size.max(1);
                }
                other => {
                    callee_frame_from = Some(sp);
                    stop_reason = format!(
                        "control leaves the chain at word {here} via `{other}`; \
                         words {sp}.. are the callee's frame"
                    );
                    break;
                }
            }
        }

        while roles.len() < n {
            roles.push(WordRole::CalleeFrame);
        }
        Ok(StackAccounting {
            roles,
            pivot_at,
            callee_frame_from,
            stop_reason,
        })
    }

    /// The scan's vaddr universe, for [`validate`](Self::validate).
    pub fn universe_from(gadgets: &[rf_scan::Gadget]) -> HashSet<u64> {
        gadgets.iter().map(|g| g.vaddr).collect()
    }

    fn pack_char(&self) -> (char, usize) {
        match self.word_size {
            4 => ('I', 8),
            _ => ('Q', 16),
        }
    }

    /// ROPgadget-compatible Python exploit script (ropmakerx64.py output
    /// structure: the `from struct import pack` header, `p = b''`, and
    /// `p += pack('<Q', 0x...) # ...` lines; string immediates render as
    /// `p += b'...'`). The header comment line comes from
    /// [`RopChain::script_comment`].
    ///
    /// Every line is emitted at column 0 (ROB-05: ropmaker indents padding
    /// lines with a literal tab, which makes the script an
    /// `IndentationError` at module level — we deliberately diverge), and
    /// every comment goes through [`py_comment`] first (ROB-01: comment
    /// text is derived from the analysed binary, so a newline in it would
    /// otherwise close the comment and inject top-level Python).
    pub fn to_python(&self) -> String {
        let (c, w) = self.pack_char();
        let mask = if self.word_size >= 8 {
            u64::MAX
        } else {
            (1u64 << (self.word_size * 8)) - 1
        };
        let mut header = py_comment(&self.script_comment);
        if !header.starts_with('#') {
            header.insert_str(0, "# ");
        }
        let mut out = format!(
            "#!/usr/bin/env python3\n{header}\n\nfrom struct import pack\n\n# Padding goes here\np = b''\n\n"
        );
        for word in &self.words {
            let value = word.value & mask;
            match word.kind {
                WordKind::Immediate => {
                    let bytes = &value.to_le_bytes()[..self.word_size];
                    out.push_str(&format!("p += b'{}'\n", py_bytes_escape(bytes)));
                }
                WordKind::GadgetAddr
                | WordKind::DataAddr
                | WordKind::CodeAddr
                | WordKind::Padding => {
                    out.push_str(&format!(
                        "p += pack('<{c}', 0x{:0w$x}) # {}\n",
                        value,
                        py_comment(&word.comment)
                    ));
                }
            }
        }
        out
    }

    /// JSON form of the IR.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap()
    }

    /// Raw little-endian bytes of the chain (what `p` contains at runtime).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.words.len() * self.word_size);
        for w in &self.words {
            out.extend_from_slice(&w.value.to_le_bytes()[..self.word_size]);
        }
        out
    }
}

/// Maximum length of a comment rendered into the generated Python script.
pub const PY_COMMENT_MAX: usize = 64;

/// Sanitise a string for use inside a `#` comment of the generated Python
/// script (ROB-01).
///
/// Comment text is derived from the analysed binary — the PE import DLL
/// name ([`rf_core::PeImport::dll`], copied verbatim out of the import
/// descriptor) and the disassembled gadget text both end up here. A
/// newline in such a string terminates the `#` comment and turns whatever
/// follows into top-level Python that the user then executes, so every
/// character outside printable ASCII (`0x20..=0x7e`) — newlines and
/// carriage returns included — is dropped rather than escaped, and the
/// result is truncated to [`PY_COMMENT_MAX`] characters.
pub fn py_comment(s: &str) -> String {
    s.chars()
        .filter(|c| (' '..='~').contains(c))
        .take(PY_COMMENT_MAX)
        .collect()
}

/// Render bytes as a Python `b'...'` literal body (ROPgadget only ever
/// emits printable ASCII here, but escape defensively).
fn py_bytes_escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'\'' => out.push_str("\\'"),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

/// Arch display name used in the IR (`"x86"` / `"x64"` / ...).
pub fn arch_name(arch: Arch) -> String {
    match arch {
        Arch::X86 => "x86",
        Arch::X64 => "x64",
        Arch::Arm => "arm",
        Arch::ArmThumb => "arm-thumb",
        Arch::Arm64 => "arm64",
        Arch::Mips32 => "mips32",
        Arch::Mips64 => "mips64",
        Arch::Ppc32 => "ppc32",
        Arch::Ppc64 => "ppc64",
        Arch::Sparc => "sparc",
        Arch::Sparc64 => "sparc64",
        Arch::SparcV9 => "sparcv9",
        Arch::RiscV32 => "riscv32",
        Arch::RiscV64 => "riscv64",
    }
    .to_string()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Pure-Rust "is this a flat, un-injected script?" check, shared with
    /// the windows builder tests. Every generated script is a flat
    /// sequence of top-level statements, so every line must be blank, a
    /// comment, one of the two fixed header statements, or a `p += …`
    /// append — and no line may be indented (ROB-05) or introduce a
    /// statement of its own (ROB-01). A script that passes this also
    /// parses as Python.
    pub(crate) fn assert_flat_python_script(py: &str) {
        let mut lines = py.lines();
        assert_eq!(lines.next(), Some("#!/usr/bin/env python3"));
        let header = lines.next().unwrap_or("");
        assert!(
            header.starts_with('#'),
            "header is not a comment: {header:?}"
        );
        for (i, line) in py.lines().enumerate() {
            assert!(
                !(line.starts_with(' ') || line.starts_with('\t')),
                "line {i} is indented at module level: {line:?}"
            );
            let ok = line.is_empty()
                || line.starts_with('#')
                || line == "from struct import pack"
                || line == "p = b''"
                || line.starts_with("p += ");
            assert!(ok, "line {i} is not a header or append statement: {line:?}");
        }
    }

    /// Assert `needle` never occurs in statement position: on every line
    /// that contains it, the line's first `#` comes first.
    pub(crate) fn assert_only_in_comment(py: &str, needle: &str) {
        for line in py.lines() {
            let Some(at) = line.find(needle) else {
                continue;
            };
            let hash = line
                .find('#')
                .unwrap_or_else(|| panic!("{needle:?} outside any comment: {line:?}"));
            assert!(hash < at, "{needle:?} in statement position: {line:?}");
        }
    }

    /// The interpreter to cross-check generated scripts with:
    /// `$RF_CHAIN_PYTHON` when set, else `python`, else `python3`.
    /// Candidates are probed with `-c "import ast"` so a non-working stub
    /// (the Windows Store alias) counts as absent.
    fn python_interpreter() -> Option<String> {
        let candidates = match std::env::var("RF_CHAIN_PYTHON") {
            Ok(p) => vec![p],
            Err(_) => vec!["python".to_string(), "python3".to_string()],
        };
        candidates.into_iter().find(|exe| {
            std::process::Command::new(exe)
                .args(["-c", "import ast"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
    }

    /// Optional cross-check: `ast.parse` the generated script with a real
    /// interpreter. A no-op when no interpreter can be spawned, so the
    /// suite never depends on a Python installation — the pure-Rust
    /// [`assert_flat_python_script`] is the load-bearing assertion.
    pub(crate) fn assert_python_parses(py: &str) {
        let Some(exe) = python_interpreter() else {
            return;
        };
        // pid + a per-process counter: tests run in parallel threads.
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("rf-chain-script-{}-{n}.py", std::process::id()));
        std::fs::write(&path, py).unwrap();
        let out = std::process::Command::new(&exe)
            .args(["-c", "import ast,sys;ast.parse(open(sys.argv[1]).read())"])
            .arg(&path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            out.status.success(),
            "{exe} rejected the generated script: {}\n--- script ---\n{py}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A KNOWN-GOOD chain, in the sense CHLX-04 means it: every word is
    /// consumed by exactly one `pop` or `ret`, and control ends at a
    /// terminator rather than running off the end.
    ///
    ///   word 0  pop rdi ; pop rbx ; ret   <- the pivot's `ret` lands here
    ///   word 1  @ .data                   <- popped into rdi
    ///   word 2  padding                   <- popped into rbx
    ///   word 3  syscall                   <- the `ret` lands here; terminal
    ///
    /// The corruption tests below start from this and break it one way each.
    fn chain_fixture() -> RopChain {
        RopChain {
            arch: "x64".to_string(),
            description: "test".to_string(),
            script_comment: "# execve generated by ROPgadget".to_string(),
            word_size: 8,
            gadgets: vec![
                GadgetRef {
                    vaddr: 0x401000,
                    text: "pop rdi ; pop rbx ; ret".to_string(),
                },
                GadgetRef {
                    vaddr: 0x401100,
                    text: "syscall".to_string(),
                },
            ],
            words: vec![
                ChainWord {
                    value: 0x401000,
                    kind: WordKind::GadgetAddr,
                    comment: "pop rdi ; pop rbx ; ret".to_string(),
                    source_gadget: Some(0),
                },
                ChainWord {
                    value: 0x6bc080,
                    kind: WordKind::DataAddr,
                    comment: "@ .data".to_string(),
                    source_gadget: None,
                },
                ChainWord {
                    value: 0x4141414141414141,
                    kind: WordKind::Padding,
                    comment: "padding".to_string(),
                    source_gadget: None,
                },
                ChainWord {
                    value: 0x401100,
                    kind: WordKind::GadgetAddr,
                    comment: "syscall".to_string(),
                    source_gadget: Some(1),
                },
            ],
        }
    }

    fn fixture_universe() -> HashSet<u64> {
        [0x401000, 0x401100].into_iter().collect()
    }

    #[test]
    fn validate_accepts_wellformed() {
        let c = chain_fixture();
        c.validate(&fixture_universe(), &[]).unwrap();
    }

    /// CHLX-04, the headline: a chain that passes the word-kind checks but
    /// cannot run must be REFUSED, not warned about.
    ///
    /// The corruption is the one CHWIN-01 ships: an inert padding word
    /// spliced in front of a control word. Every word in the result is still
    /// of a legal kind, every gadget address is still real, no bad byte
    /// appears — `validate`'s pre-CHLX-04 checks all pass — and the chain
    /// still dies at 0x4141414141414141, because the `ret` before the gap
    /// loads the gap into rip.
    #[test]
    fn padding_gap_is_refused_not_warned() {
        let good = chain_fixture();
        good.validate(&fixture_universe(), &[]).unwrap();
        let acct = good.verify_stack_accounting().unwrap();
        assert_eq!(
            acct.roles,
            vec![
                WordRole::ControlTransfer, // the pivot's ret lands on the gadget
                WordRole::PopOperand,      // pop rdi
                WordRole::PopOperand,      // pop rbx
                WordRole::ControlTransfer, // the gadget's ret lands on `syscall`
            ]
        );
        // `syscall` is the terminator AND the last word, so the callee frame
        // is empty: every word the chain emits is accounted for.
        assert_eq!(acct.callee_frame_from, Some(4), "{}", acct.stop_reason);
        assert_eq!(acct.words_verified(), acct.roles.len());

        let mut corrupt = good.clone();
        corrupt.words.insert(
            3,
            ChainWord {
                value: 0x4141414141414141,
                kind: WordKind::Padding,
                comment: "stack alignment word".to_string(),
                source_gadget: None,
            },
        );
        let err = corrupt
            .validate(&fixture_universe(), &[])
            .expect_err("a chain with a padding gap must be refused");
        match err {
            ChainError::InvalidWord { index, kind, .. } => {
                assert_eq!(index, 3);
                assert_eq!(kind, WordKind::Padding);
            }
            other => panic!("wrong error: {other}"),
        }
        assert!(
            err_text(&corrupt).contains("BARE `ret` GADGET"),
            "the refusal must say how to fix it: {}",
            err_text(&corrupt)
        );
    }

    /// The other half of "no inherited padding gaps": a MISSING padding
    /// word. `pop rdi ; pop rbx ; ret` needs two operand words; delete one
    /// and the second `pop` swallows the next gadget address, so the chain
    /// runs one word out of phase from there on.
    #[test]
    fn missing_padding_word_is_refused() {
        let mut corrupt = chain_fixture();
        corrupt.words.remove(2); // the `pop rbx` operand
        let err = corrupt
            .validate(&fixture_universe(), &[])
            .expect_err("a chain that is one padding word short must be refused");
        let text = err.to_string();
        assert!(text.contains("consumes this word as data"), "{text}");
        assert!(text.contains("CHLX-04"), "{text}");
    }

    /// A gadget whose pops run off the end of the chain.
    #[test]
    fn pops_past_the_end_are_refused() {
        let mut corrupt = chain_fixture();
        corrupt.words.truncate(2); // gadget + one of its two operands
        let err = corrupt
            .validate(&fixture_universe(), &[])
            .expect_err("a chain that pops past its own end must be refused");
        assert!(err.to_string().contains("pops past the"), "{err}");
    }

    /// Accounting stops — honestly, and with a reason — where control leaves
    /// the chain. The words after an API entry are the callee's frame (a
    /// return address, Win64 shadow space): no static walk can model them,
    /// so the verifier reports them rather than pretending to check them.
    #[test]
    fn callee_frame_is_reported_not_guessed() {
        let mut c = chain_fixture();
        c.words[3] = ChainWord {
            value: 0x7fff_1234_0000,
            kind: WordKind::CodeAddr,
            comment: "VirtualProtect (--api-addr)".to_string(),
            source_gadget: None,
        };
        c.words.push(ChainWord {
            value: 0x140003000,
            kind: WordKind::CodeAddr,
            comment: "return address: shellcode".to_string(),
            source_gadget: None,
        });
        for _ in 0..4 {
            c.words.push(ChainWord {
                value: 0x4141414141414141,
                kind: WordKind::Padding,
                comment: "shadow space (Win64 ABI)".to_string(),
                source_gadget: None,
            });
        }
        c.gadgets.truncate(1);
        c.validate(&fixture_universe(), &[]).unwrap();
        let acct = c.verify_stack_accounting().unwrap();
        assert_eq!(acct.callee_frame_from, Some(4));
        assert_eq!(acct.words_verified(), 4);
        assert!(acct.roles[4..].iter().all(|r| *r == WordRole::CalleeFrame));
        assert!(
            acct.stop_reason.contains("callee's frame"),
            "{}",
            acct.stop_reason
        );
    }

    /// `ret <imm>` discards `imm` bytes of stack after taking its return
    /// address — the stdcall shape. The walk accounts for those words too.
    #[test]
    fn ret_imm_discards_its_operands() {
        let c = RopChain {
            arch: "x86".to_string(),
            description: "test".to_string(),
            script_comment: "#".to_string(),
            word_size: 4,
            gadgets: vec![
                GadgetRef {
                    vaddr: 0x8048000,
                    text: "pop eax ; ret 0x8".to_string(),
                },
                GadgetRef {
                    vaddr: 0x8048100,
                    text: "int 0x80".to_string(),
                },
            ],
            words: vec![
                ChainWord {
                    value: 0x8048000,
                    kind: WordKind::GadgetAddr,
                    comment: "pop eax ; ret 0x8".to_string(),
                    source_gadget: Some(0),
                },
                ChainWord {
                    value: 0xb,
                    kind: WordKind::DataAddr,
                    comment: "eax".to_string(),
                    source_gadget: None,
                },
                ChainWord {
                    value: 0x8048100,
                    kind: WordKind::GadgetAddr,
                    comment: "int 0x80".to_string(),
                    source_gadget: Some(1),
                },
                ChainWord {
                    value: 0x41414141,
                    kind: WordKind::Padding,
                    comment: "discarded by ret 0x8".to_string(),
                    source_gadget: None,
                },
                ChainWord {
                    value: 0x41414141,
                    kind: WordKind::Padding,
                    comment: "discarded by ret 0x8".to_string(),
                    source_gadget: None,
                },
            ],
        };
        let acct = c.verify_stack_accounting().unwrap();
        assert_eq!(
            acct.roles,
            vec![
                WordRole::ControlTransfer,
                WordRole::PopOperand,
                WordRole::ControlTransfer,
                WordRole::PopOperand,
                WordRole::PopOperand,
            ]
        );
    }

    /// A stack pivot moves rsp by an amount the walk does not model. It must
    /// STOP and say so, not silently report a wrong verdict — CHWIN-08 adds
    /// pivots, and a verifier that guesses there is worse than one that
    /// abstains.
    #[test]
    fn unmodelled_stack_effect_stops_the_walk() {
        let mut c = chain_fixture();
        c.gadgets[0].text = "add rsp, 0x18 ; ret".to_string();
        c.words[0].comment = "add rsp, 0x18 ; ret".to_string();
        c.validate(&fixture_universe(), &[]).unwrap();
        let acct = c.verify_stack_accounting().unwrap();
        assert_eq!(acct.callee_frame_from, Some(1));
        assert!(
            acct.stop_reason.contains("unmodelled"),
            "{}",
            acct.stop_reason
        );
    }

    fn err_text(c: &RopChain) -> String {
        c.validate(&fixture_universe(), &[])
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn validate_rejects_unknown_gadget_addr() {
        let mut c = chain_fixture();
        c.words[0].value = 0xdead0000;
        let universe: HashSet<u64> = [0x401000].into_iter().collect();
        let err = c.validate(&universe, &[]).unwrap_err();
        assert!(matches!(err, ChainError::InvalidWord { index: 0, .. }));
    }

    #[test]
    fn validate_rejects_source_mismatch_and_missing_index() {
        let universe: HashSet<u64> = [0x401000, 0x401002].into_iter().collect();
        let mut c = chain_fixture();
        c.words[0].value = 0x401002; // in universe but != gadgets[0].vaddr
        assert!(c.validate(&universe, &[]).is_err());
        let mut c = chain_fixture();
        c.words[0].source_gadget = None;
        assert!(c.validate(&universe, &[]).is_err());
        let mut c = chain_fixture();
        c.words[0].source_gadget = Some(7);
        assert!(c.validate(&universe, &[]).is_err());
    }

    #[test]
    fn validate_rejects_badbyte_immediates_and_data_addrs() {
        let c = chain_fixture();
        let universe = fixture_universe();
        // 0x6bc080 packs to 80 c0 6b 00 ... — byte 00 is bad
        let err = c.validate(&universe, &[0x00]).unwrap_err();
        assert!(matches!(err, ChainError::InvalidWord { index: 1, .. }));
        // 0x41 in the padding constant
        let err = c.validate(&universe, &[0x41]).unwrap_err();
        assert!(matches!(err, ChainError::InvalidWord { index: 2, .. }));
        // gadget words are not re-checked (they passed scan-time badbytes)
        c.validate(&universe, &[0x10]).unwrap();
    }

    #[test]
    fn invariant_hooks_run() {
        let c = chain_fixture();
        let universe = fixture_universe();
        let reject: ChainInvariant = &|_| {
            Err(ChainError::InvalidWord {
                index: 0,
                value: 0,
                kind: WordKind::GadgetAddr,
                reason: "hook says no".to_string(),
            })
        };
        let err = c.validate_with(&universe, &[], &[reject]).unwrap_err();
        assert!(err.to_string().contains("hook says no"));
    }

    #[test]
    fn python_renderer_matches_ropmaker_format() {
        let c = chain_fixture();
        let py = c.to_python();
        assert!(py.starts_with(
            "#!/usr/bin/env python3\n# execve generated by ROPgadget\n\nfrom struct import pack\n\n# Padding goes here\np = b''\n\n"
        ));
        assert!(py.contains("p += pack('<Q', 0x0000000000401000) # pop rdi ; pop rbx ; ret\n"));
        assert!(py.contains("p += pack('<Q', 0x00000000006bc080) # @ .data\n"));
    }

    /// ROB-05: ropmaker indents padding lines with a literal tab, which
    /// makes every script with a padding word an `IndentationError`. We
    /// deliberately diverge — every line is at column 0.
    #[test]
    fn padding_lines_are_not_indented() {
        let c = chain_fixture();
        let py = c.to_python();
        assert!(py.contains("p += pack('<Q', 0x4141414141414141) # padding\n"));
        assert!(!py.contains('\t'), "{py}");
        assert_flat_python_script(&py);
        assert_python_parses(&py);
    }

    #[test]
    fn x86_pack_format() {
        let mut c = chain_fixture();
        c.word_size = 4;
        let py = c.to_python();
        assert!(py.contains("pack('<I', 0x00401000)"));
        assert!(py.contains("p += pack('<I', 0x41414141) # padding\n"));
        assert!(!py.contains('\t'), "{py}");
        // raw bytes are 4-byte LE words
        let raw = c.to_bytes();
        assert_eq!(raw.len(), 16);
        assert_eq!(&raw[0..4], &0x401000u32.to_le_bytes());
    }

    #[test]
    fn immediate_renders_as_python_bytes() {
        let mut c = chain_fixture();
        c.words.push(ChainWord {
            value: u64::from_le_bytes(*b"/bin//sh"),
            kind: WordKind::Immediate,
            comment: String::new(),
            source_gadget: None,
        });
        let py = c.to_python();
        assert!(py.contains("p += b'/bin//sh'\n"));
        let raw = c.to_bytes();
        assert_eq!(&raw[32..40], b"/bin//sh");
    }

    /// ROB-01: the sanitiser itself.
    #[test]
    fn py_comment_strips_control_chars_and_truncates() {
        assert_eq!(
            py_comment("@ IAT VirtualProtect (KERNEL32.dll)"),
            "@ IAT VirtualProtect (KERNEL32.dll)"
        );
        // newlines, carriage returns and tabs are removed, not escaped
        assert_eq!(
            py_comment("KERNEL32\nimport os\r\nx\t.dll"),
            "KERNEL32import osx.dll"
        );
        // everything else outside 0x20..=0x7e goes too (NUL, DEL, non-ASCII)
        assert_eq!(py_comment("a\u{0}b\u{7f}c\u{e9}d\u{1f600}"), "abcd");
        assert_eq!(py_comment(&"A".repeat(4096)).len(), PY_COMMENT_MAX);
    }

    /// ROB-01: a comment carried in the IR cannot break out of the `#`,
    /// whichever word kind or the script header carries it.
    #[test]
    fn tainted_comments_cannot_escape_the_python_comment() {
        let mut c = chain_fixture();
        c.script_comment = "# hdr\nimport os\nos.system('id')".to_string();
        c.words[0].comment = "pop rdi ; ret\nimport os\nos.system('id')".to_string();
        c.words[1].comment = "@ .data\nimport os\nos.system('id')".to_string();
        c.words[2].comment = "padding\nimport os\nos.system('id')".to_string();
        let py = c.to_python();
        assert!(py.contains("os.system('id')"), "{py}");
        for line in py.lines() {
            assert!(
                !line.starts_with("import os"),
                "injected statement: {line:?}"
            );
        }
        assert_only_in_comment(&py, "import os");
        assert_only_in_comment(&py, "os.system('id')");
        assert_flat_python_script(&py);
        assert_python_parses(&py);
    }

    /// A `script_comment` that is not already a comment still renders as
    /// one, so the second line of the script is never a statement.
    #[test]
    fn script_comment_is_forced_into_a_comment() {
        let mut c = chain_fixture();
        c.script_comment = "os.system('id')".to_string();
        let py = c.to_python();
        assert!(
            py.starts_with("#!/usr/bin/env python3\n# os.system('id')\n"),
            "{py}"
        );
        assert_flat_python_script(&py);
    }

    #[test]
    fn json_renderer_roundtrips() {
        let c = chain_fixture();
        let v = c.to_json();
        assert_eq!(v["arch"], "x64");
        assert_eq!(v["word_size"], 8);
        assert_eq!(v["words"][0]["value"], "0x401000");
        assert_eq!(v["words"][0]["kind"], "gadget_addr");
        assert_eq!(v["gadgets"][0]["text"], "pop rdi ; pop rbx ; ret");
    }
}
