//! CLS-09's semantic layer for the eight capstone architectures.
//!
//! Everything here is deliberately narrower than the x86 analysis in
//! [`crate::x86_effect`], for one reason: [`rf_scan::InsnDetail`] does not
//! carry capstone's *write-back* flag, so on ARM and ARM64 the
//! post-/pre-indexed forms `ldr r0, [sp], #4` and `ldr r0, [sp, #4]` are
//! indistinguishable here — the first moves the stack pointer by 4 and the
//! second does not. Rather than guess, this module reports `None` for any
//! gadget containing a stack-pointer memory operand it does not recognise.
//!
//! ## What computes a stack delta, and what never does
//!
//! | family | recognised | everything else |
//! |---|---|---|
//! | ARM / Thumb | `push {…}` / `pop {…}` (4 bytes per listed register), `add`/`sub sp, sp, #imm`, `add`/`sub sp, #imm` | `None` — including `ldm`/`stm`, whose base register is printed inside the same operand list as the transfer list |
//! | ARM64 | `add`/`sub sp, sp, #imm` | `None` — `ldp`/`stp`/`ldr`/`str` through `sp` cannot be told apart from their write-back forms |
//! | MIPS 32/64 | `addi(u)`/`daddi(u) $sp, $sp, imm` | loads and stores through `$sp` contribute 0, because MIPS has no write-back addressing at all; anything else naming `$sp` is `None` |
//! | RISC-V 32/64 | `addi`/`addiw`/`c.addi`/`c.addi16sp` on `sp` | same: no write-back addressing, so `sp`-based loads and stores contribute 0 |
//! | PowerPC 32/64 | `addi r1, r1, imm`, and the `stwu`/`stdu`/`lwzu`/… *update* forms based on `r1` | indexed update forms (`stwux`) are `None`; plain `r1`-based loads and stores contribute 0 |
//! | SPARC | **nothing** | always `None`: `save`/`restore` rotate a register window, which is not an offset |
//!
//! ## Sets versus clobbers
//!
//! Same definition as x86 ([`crate::x86_effect`]), one grain coarser: a
//! written register is **set** when its value came off the stack, came only
//! from immediates, or came from registers this gadget has already set; it is
//! **clobbered** otherwise. There is no constant folding, so
//! `mov x0, x1 ; ret` clobbers x0 (correctly) and a hypothetical
//! `mov x0, #1 ; add x0, x0, #1` reports x0 as set (also correctly, by the
//! all-immediate rule) without knowing the value is 2.
//!
//! ARM64 register names are widened to their 64-bit spelling (`w0` -> `x0`),
//! because a `w`-register write zeroes the top half and the question a chain
//! author asks is about `x0`.

use rf_scan::{InsnDetail, Operand};

use crate::effect::{TerminatorTarget, Transfer, ValueDst, ValueSrc};
use crate::generic::Family;

/// Everything this pass produces for one gadget.
pub(crate) struct Effects {
    pub stack_delta: Option<i64>,
    pub transfers: Vec<Transfer>,
    pub sets: Vec<String>,
    pub clobbers: Vec<String>,
    pub target: TerminatorTarget,
}

/// Widen a register name to the one a chain author allocates: ARM64 `w0` is
/// the low half of `x0`, and writing it zeroes the rest of `x0`.
pub(crate) fn widen(f: Family, n: &str) -> String {
    if f == Family::Arm64 {
        if let Some(rest) = n.strip_prefix('w') {
            if rest.parse::<u32>().is_ok() {
                return format!("x{rest}");
            }
            if rest == "sp" || rest == "zr" {
                return n.to_string();
            }
        }
    }
    n.to_string()
}

fn is_push_list(m: &str) -> bool {
    m == "push" || m == "push.w" || m == "vpush"
}

fn is_pop_list(m: &str) -> bool {
    m == "pop" || m == "pop.w" || m == "vpop"
}

/// PowerPC load/store *update* forms: the base register is written back with
/// `base + disp`. The indexed spellings (`stwux`) add a register instead and
/// are not constant, so they are excluded here and rejected by the caller.
fn ppc_update(m: &str) -> bool {
    matches!(
        m,
        "stwu"
            | "stdu"
            | "sthu"
            | "stbu"
            | "stfsu"
            | "stfdu"
            | "lwzu"
            | "ldu"
            | "lwau"
            | "lhzu"
            | "lhau"
            | "lbzu"
            | "lfsu"
            | "lfdu"
    )
}

fn imm_operands(d: &InsnDetail) -> Vec<i64> {
    d.operands
        .iter()
        .filter_map(|o| match &o.op {
            Operand::Imm(i) => Some(*i),
            _ => None,
        })
        .collect()
}

/// The stack-pointer effect of one instruction: `Some(delta)`, or `None` when
/// it is not provably constant. See the module table.
fn sp_effect(f: Family, d: &InsnDetail, word: i64) -> Option<i64> {
    let m = d.mnemonic.as_str();
    let regs: Vec<&str> = d.reg_operands().collect();
    let touches_sp_reg = regs.iter().any(|r| f.is_sp(r));
    let sp_mem = d
        .mem_refs()
        .any(|mr| mr.base.as_deref().is_some_and(|b| f.is_sp(b)));

    // Family::Sparc never computes, not even 0. `save` and `restore` rotate
    // a register window: they move the stack pointer without naming it, so
    // "this instruction does not mention %sp" proves nothing on SPARC the way
    // it does everywhere else.
    if f == Family::Sparc {
        return None;
    }

    if f == Family::Arm {
        if is_push_list(m) {
            return Some(-(regs.len() as i64) * word);
        }
        if is_pop_list(m) {
            return Some((regs.len() as i64) * word);
        }
    }

    // `add sp, sp, #imm` / `sub sp, sp, #imm`, and the two-operand Thumb and
    // ARM64 spellings `add sp, #imm`.
    if matches!(
        m,
        "add"
            | "addi"
            | "addiu"
            | "daddi"
            | "daddiu"
            | "addiw"
            | "c.addi"
            | "c.addi16sp"
            | "sub"
            | "subi"
            | "subiu"
            | "addis"
    ) && !regs.is_empty()
        && f.is_sp(regs[0])
    {
        let others_are_sp = regs[1..].iter().all(|r| f.is_sp(r));
        let imms = imm_operands(d);
        if others_are_sp && regs.len() <= 2 && imms.len() == 1 && m != "addis" {
            let v = imms[0];
            return Some(if m.starts_with("sub") { -v } else { v });
        }
        return None;
    }

    if touches_sp_reg {
        // The stack pointer appears as a register operand of an instruction
        // this analysis does not model. It may or may not be written; either
        // way nothing is provable.
        return None;
    }

    if sp_mem {
        return match f {
            // ARM and ARM64 hide write-back from `InsnDetail`.
            Family::Arm | Family::Arm64 => None,
            // MIPS and RISC-V have no write-back addressing mode: a
            // stack-relative load or store cannot move the stack pointer.
            Family::Mips | Family::RiscV => Some(0),
            Family::Ppc => {
                if ppc_update(m) {
                    let mr = d.mem_refs().next()?;
                    if mr.index.is_some() {
                        return None;
                    }
                    Some(mr.disp)
                } else if m.ends_with('x') {
                    None
                } else {
                    Some(0)
                }
            }
            Family::Sparc => None,
        };
    }
    Some(0)
}

/// The nine-way terminator target for the capstone families.
fn target_of(f: Family, d: &InsnDetail) -> TerminatorTarget {
    if let Some(mr) = d.mem_refs().next() {
        return TerminatorTarget::Memory {
            base: mr.base.clone(),
            index: mr.index.clone(),
            disp: mr.disp,
        };
    }
    for r in d.reg_operands() {
        if f.link_names().contains(&r) || f.is_pc(r) {
            continue;
        }
        return TerminatorTarget::Register { reg: r.to_string() };
    }
    // A branch whose only operand is an immediate goes to a fixed address.
    if d.operands.iter().any(|o| matches!(o.op, Operand::Imm(_)))
        && (d.groups.jump || d.groups.call)
    {
        return TerminatorTarget::Direct;
    }
    TerminatorTarget::Implicit
}

/// Full CLS-09 analysis for one capstone-decoded gadget.
///
/// `word` is the architecture's stack slot size in bytes; `term_idx` is the
/// index of the control transfer as [`crate::generic::terminator_of`] found
/// it, which on a delay-slot ISA is not the last instruction.
pub(crate) fn analyze(
    f: Family,
    det: &[InsnDetail],
    term_idx: Option<usize>,
    word: i64,
) -> Effects {
    let mut sp: Option<i64> = Some(0);
    let mut transfers: Vec<Transfer> = Vec::new();
    // Full-width register name -> is its value decided by the payload?
    let mut vals: std::collections::BTreeMap<String, bool> = std::collections::BTreeMap::new();

    for (i, d) in det.iter().enumerate() {
        let is_term = Some(i) == term_idx;
        // Anything before the control transfer that is itself a branch means
        // the printed sequence is not the executed one.
        if !is_term && (d.groups.control() || crate::text::is_branch_mnemonic(&d.mnemonic)) {
            sp = None;
        }
        let sp_before = sp;
        if let Some(cur) = sp {
            sp = sp_effect(f, d, word).map(|delta| cur + delta);
        }
        step_values(f, d, is_term, sp_before, word, &mut transfers, &mut vals);
    }

    let mut sets = Vec::new();
    let mut clobbers = Vec::new();
    for (r, controlled) in &vals {
        if *controlled {
            sets.push(r.clone());
        } else {
            clobbers.push(r.clone());
        }
    }
    sets.sort_unstable();
    clobbers.sort_unstable();
    Effects {
        stack_delta: sp,
        transfers,
        sets,
        clobbers,
        target: term_idx.map_or(TerminatorTarget::Implicit, |i| target_of(f, &det[i])),
    }
}

#[allow(clippy::too_many_arguments)]
fn step_values(
    f: Family,
    d: &InsnDetail,
    is_term: bool,
    sp_before: Option<i64>,
    word: i64,
    transfers: &mut Vec<Transfer>,
    vals: &mut std::collections::BTreeMap<String, bool>,
) {
    let m = d.mnemonic.as_str();
    let e = crate::generic::effect_of(f, d, is_term);
    let regs: Vec<&str> = d.reg_operands().collect();

    // --- transfers --------------------------------------------------------
    if f == Family::Arm && is_pop_list(m) {
        for (k, r) in regs.iter().enumerate() {
            if f.is_pc(r) {
                continue;
            }
            transfers.push(Transfer {
                dst: ValueDst::Register { reg: widen(f, r) },
                src: ValueSrc::Stack {
                    offset: sp_before.map(|b| b + k as i64 * word),
                },
                needs: Vec::new(),
                rmw: false,
                width: Some(word as u32),
            });
        }
    } else if f == Family::Arm && is_push_list(m) {
        for (k, r) in regs.iter().enumerate() {
            transfers.push(Transfer {
                dst: ValueDst::Stack {
                    offset: sp_before.map(|b| b - (regs.len() as i64 - k as i64) * word),
                },
                src: ValueSrc::Register { reg: widen(f, r) },
                needs: Vec::new(),
                rmw: false,
                width: Some(word as u32),
            });
        }
    } else if let Some(mr) = d.mem_refs().next() {
        let on_stack = mr.base.as_deref().is_some_and(|b| f.is_sp(b));
        let needs: Vec<String> = mr
            .base
            .iter()
            .chain(mr.index.iter())
            .filter(|b| !f.is_sp(b))
            .cloned()
            .collect();
        // The transferred register is the destination on a load and the
        // source on a store; on every family here it is the first register
        // operand either way (SPARC prints `st %g1, [%sp+8]` the same way).
        if let Some(reg) = regs.first() {
            let store =
                !e.written.iter().any(|w| w == reg) || e.labels.contains(&crate::Class::MemWrite);
            if store {
                transfers.push(Transfer {
                    dst: if on_stack {
                        ValueDst::Stack {
                            offset: sp_before.map(|b| b + mr.disp),
                        }
                    } else {
                        ValueDst::Memory {
                            base: mr.base.clone(),
                            index: mr.index.clone(),
                            disp: mr.disp,
                        }
                    },
                    src: ValueSrc::Register { reg: widen(f, reg) },
                    needs,
                    rmw: false,
                    width: None,
                });
            } else {
                transfers.push(Transfer {
                    dst: ValueDst::Register { reg: widen(f, reg) },
                    src: if on_stack {
                        ValueSrc::Stack {
                            offset: sp_before.map(|b| b + mr.disp),
                        }
                    } else {
                        ValueSrc::Memory {
                            base: mr.base.clone(),
                            index: mr.index.clone(),
                            disp: mr.disp,
                        }
                    },
                    needs,
                    rmw: false,
                    width: None,
                });
            }
        }
    } else if matches!(m, "mov" | "mv" | "movs" | "mr" | "fmr") && regs.len() == 2 {
        let (dst, src) = if f.dest_is_last() {
            (regs[1], regs[0])
        } else {
            (regs[0], regs[1])
        };
        transfers.push(Transfer {
            dst: ValueDst::Register { reg: widen(f, dst) },
            src: ValueSrc::Register { reg: widen(f, src) },
            needs: Vec::new(),
            rmw: false,
            width: None,
        });
    } else if matches!(m, "mov" | "movz" | "movw" | "li" | "lis" | "movs") && regs.len() == 1 {
        if let Some(v) = imm_operands(d).first() {
            transfers.push(Transfer {
                dst: ValueDst::Register {
                    reg: widen(f, regs[0]),
                },
                src: ValueSrc::Immediate { value: *v },
                needs: Vec::new(),
                rmw: false,
                width: None,
            });
        }
    }

    // --- sets vs clobbers -------------------------------------------------
    // A written register is controlled when its value came off the stack,
    // came only from immediates, or came from registers already controlled.
    let non_stack_mem_read = d
        .mem_refs()
        .any(|mr| !mr.base.as_deref().is_some_and(|b| f.is_sp(b)))
        && !e.labels.contains(&crate::Class::MemWrite);
    let src_regs: Vec<&String> = e
        .read
        .iter()
        .filter(|r| !e.written.iter().any(|w| w == *r))
        .collect();
    let sources_controlled = !non_stack_mem_read
        && src_regs
            .iter()
            .all(|r| *vals.get(&widen(f, r)).unwrap_or(&false));
    for r in &e.written {
        let full = widen(f, r);
        let controlled = e.from_stack.iter().any(|s| s == r) || sources_controlled;
        // A register written twice keeps the last verdict.
        vals.insert(full, controlled);
    }
}
