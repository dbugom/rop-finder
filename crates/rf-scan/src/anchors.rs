//! Anchor tables for all architectures, ported faithfully from ROPgadget's
//! `ropgadget/gadgets.py` (x86: `addROPGadgets` lines 137-145, `addJOPGadgets`
//! lines 217-274, `addSYSGadgets` lines 407-420; other arches: lines 147-202,
//! 275-392, 422-479).
//!
//! Each anchor is a pattern of byte matchers. Matching replicates Python
//! `re.finditer` semantics per pattern: matches are leftmost and
//! **non-overlapping** — after a match at `p` of length `L`, scanning resumes
//! at `p + L`.
//!
//! NOTE: an anchor's *gadget size* (`size`, ROPgadget's `gad_size`) can differ
//! from its *pattern length*: the Thumb `ldm.w`/`ldmdb` anchors match 6 bytes
//! but the gadget ends 4 bytes after the anchor start (gadgets.py:337-338,
//! 345-346 — the trailing `[\x00-\xff]{4}` is a ROPgadget quirk, ported
//! verbatim). `align` is ROPgadget's `gad_align` used for aligned backward
//! stepping (gadgets.py:74-89).

use std::borrow::Cow;

use rf_core::{Arch, Endianness};

/// A single pattern position: fixed byte, wildcard, or a set of inclusive
/// byte ranges (regex character class).
#[derive(Debug, Clone, Copy)]
pub enum BytePat {
    /// This byte and no other.
    Fixed(u8),
    /// Any byte (`.` in the oracle's regex).
    Any,
    /// Any byte inside one of these inclusive ranges (a character class).
    Ranges(&'static [(u8, u8)]),
}

impl BytePat {
    fn matches(&self, b: u8) -> bool {
        match self {
            BytePat::Fixed(x) => *x == b,
            BytePat::Any => true,
            BytePat::Ranges(rs) => rs.iter().any(|(lo, hi)| *lo <= b && b <= *hi),
        }
    }
}

/// One anchor pattern (one entry of ROPgadget's per-table `gadgets` lists).
#[derive(Debug, Clone)]
pub struct Anchor {
    /// Human-readable comment from the Python source.
    pub name: &'static str,
    /// The byte pattern, one [`BytePat`] per position.
    pub pattern: Cow<'static, [BytePat]>,
    /// Gadget size (`gad_size`): gadget end = anchor offset + size. May be
    /// smaller than `pattern.len()` (Thumb ldm.w/ldmdb quirk, see module docs).
    pub size: usize,
    /// Backward-stepping alignment (`gad_align`): candidate starts are
    /// `anchor_pos - i*align` (aligned path, gadgets.py:75-81).
    pub align: usize,
}

impl Anchor {
    /// The gadget size (`gad_size`); see the [`size`](Self::size) field.
    pub fn size(&self) -> usize {
        self.size
    }
    /// The backward-stepping alignment (`gad_align`); see the
    /// [`align`](Self::align) field.
    pub fn align(&self) -> usize {
        self.align
    }
}

const fn f(b: u8) -> BytePat {
    BytePat::Fixed(b)
}
const ANY: BytePat = BytePat::Any;

/// Promote a pattern literal to `&'static [BytePat]` (array literals of
/// const-fn calls are not const-promoted, so route through a `const` item).
macro_rules! pat {
    ($($e:expr),* $(,)?) => {{
        const P: &[BytePat] = &[$($e),*];
        P
    }};
}

/// x86 anchor constructor: gadget size == pattern length, align == 1
/// (all x86 tables in gadgets.py use align 1).
fn a(name: &'static str, pattern: &'static [BytePat]) -> Anchor {
    Anchor {
        name,
        size: pattern.len(),
        pattern: Cow::Borrowed(pattern),
        align: 1,
    }
}

/// Multi-arch anchor constructor: explicit gadget size and align.
fn m(name: &'static str, pattern: &'static [BytePat], size: usize, align: usize) -> Anchor {
    Anchor {
        name,
        pattern: Cow::Borrowed(pattern),
        size,
        align,
    }
}

/// ROP anchors (`gadgets.py:137-145`). Same for x86 and x64.
pub fn rop_anchors() -> Vec<Anchor> {
    vec![
        a("ret", pat!(f(0xc3))),
        a("ret <imm>", pat!(f(0xc2), ANY, ANY)),
        a("retf", pat!(f(0xcb))),
        a("retf <imm>", pat!(f(0xca), ANY, ANY)),
        // MPX — decodes as "bnd ret", always rejected by passCleanX86 (as in ROPgadget)
        a("ret (MPX bnd)", pat!(f(0xf2), f(0xc3))),
        a("ret <imm> (MPX bnd)", pat!(f(0xf2), f(0xc2), ANY, ANY)),
    ]
}

/// JOP anchors (`gadgets.py:217-274`). `is64` adds the `\x41`-prefixed
/// (R8-R15) variants.
pub fn jop_anchors(is64: bool) -> Vec<Anchor> {
    // call/jmp reg        d0-d7=call, e0-e7=jmp
    const REG: &[(u8, u8)] = &[(0xd0, 0xd7), (0xe0, 0xe7)];
    // call/jmp [reg]      10-13,16-17=call, 20-23,26-27=jmp
    const MEM: &[(u8, u8)] = &[(0x10, 0x13), (0x16, 0x17), (0x20, 0x23), (0x26, 0x27)];
    // call/jmp [esp/rsp]  14=call, 24=jmp
    const MEM_SP: &[(u8, u8)] = &[(0x14, 0x14), (0x24, 0x24)];
    // call/jmp [reg + disp8]
    const MEM_D8: &[(u8, u8)] = &[(0x50, 0x53), (0x55, 0x57), (0x60, 0x63), (0x65, 0x67)];
    // call/jmp [esp/rsp + disp8]
    const MEM_SP_D8: &[(u8, u8)] = &[(0x54, 0x54), (0x64, 0x64)];
    // call/jmp [reg + disp32]
    const MEM_D32: &[(u8, u8)] = &[(0x90, 0x93), (0x95, 0x97), (0xa0, 0xa3), (0xa5, 0xa7)];
    // call/jmp [esp/rsp + disp32]
    const MEM_SP_D32: &[(u8, u8)] = &[(0x94, 0x94), (0xa4, 0xa4)];

    let mut v: Vec<Anchor> = vec![
        a("call/jmp reg", pat!(f(0xff), BytePat::Ranges(REG))),
        a("call/jmp [reg]", pat!(f(0xff), BytePat::Ranges(MEM))),
        a(
            "call/jmp [esp]",
            pat!(f(0xff), BytePat::Ranges(MEM_SP), f(0x24)),
        ),
        a(
            "call/jmp [reg + disp8]",
            pat!(f(0xff), BytePat::Ranges(MEM_D8), ANY),
        ),
        a(
            "call/jmp [esp + disp8]",
            pat!(f(0xff), BytePat::Ranges(MEM_SP_D8), f(0x24), ANY),
        ),
        a(
            "call/jmp [reg + disp32]",
            pat!(f(0xff), BytePat::Ranges(MEM_D32), ANY, ANY, ANY, ANY),
        ),
        a(
            "call/jmp [esp + disp32]",
            pat!(
                f(0xff),
                BytePat::Ranges(MEM_SP_D32),
                f(0x24),
                ANY,
                ANY,
                ANY,
                ANY
            ),
        ),
    ];
    if is64 {
        // \x41 (REX.B) prefix converts r[abcd]x..rdi forms to r8-r15 forms.
        // Inserted after the base forms, exactly as ROPgadget's
        // `gadgets += [(b"\x41" + op, ...)]`.
        let base = v.clone();
        for anchor in base {
            let mut p = Vec::with_capacity(anchor.pattern.len() + 1);
            p.push(f(0x41));
            p.extend_from_slice(&anchor.pattern);
            v.push(Anchor {
                name: anchor.name,
                size: anchor.size + 1,
                pattern: Cow::Owned(p),
                align: anchor.align,
            });
        }
    }
    // Extra sequences common to x86 and x64.
    v.extend([
        a("jmp rel8", pat!(f(0xeb), ANY)),
        a("jmp rel32", pat!(f(0xe9), ANY, ANY, ANY, ANY)),
        // MPX — decode as "bnd jmp"/"bnd call", always rejected by passCleanX86
        a(
            "bnd jmp [reg]",
            pat!(
                f(0xf2),
                f(0xff),
                BytePat::Ranges(&[(0x20, 0x23), (0x26, 0x27)])
            ),
        ),
        a(
            "bnd jmp reg",
            pat!(
                f(0xf2),
                f(0xff),
                BytePat::Ranges(&[(0xe0, 0xe4), (0xe6, 0xe7)])
            ),
        ),
        a(
            "bnd jmp [reg] (2)",
            pat!(
                f(0xf2),
                f(0xff),
                BytePat::Ranges(&[(0x10, 0x13), (0x16, 0x17)])
            ),
        ),
        a(
            "bnd call reg",
            pat!(
                f(0xf2),
                f(0xff),
                BytePat::Ranges(&[(0xd0, 0xd4), (0xd6, 0xd7)])
            ),
        ),
    ]);
    v
}

/// SYS anchors (`gadgets.py:407-420`). All fixed bytes.
pub fn sys_anchors() -> Vec<Anchor> {
    vec![
        a("int 0x80", pat!(f(0xcd), f(0x80))),
        a("sysenter", pat!(f(0x0f), f(0x34))),
        a("syscall", pat!(f(0x0f), f(0x05))),
        a(
            "call DWORD PTR gs:0x10",
            pat!(
                f(0x65),
                f(0xff),
                f(0x15),
                f(0x10),
                f(0x00),
                f(0x00),
                f(0x00)
            ),
        ),
        a("int 0x80 ; ret", pat!(f(0xcd), f(0x80), f(0xc3))),
        a("sysenter ; ret", pat!(f(0x0f), f(0x34), f(0xc3))),
        a("syscall ; ret", pat!(f(0x0f), f(0x05), f(0xc3))),
        a(
            "call DWORD PTR gs:0x10 ; ret",
            pat!(
                f(0x65),
                f(0xff),
                f(0x15),
                f(0x10),
                f(0x00),
                f(0x00),
                f(0x00),
                f(0xc3)
            ),
        ),
        a("sysret", pat!(f(0x0f), f(0x07))),
        a("sysret (rex.w)", pat!(f(0x48), f(0x0f), f(0x07))),
        a("iret", pat!(f(0xcf))),
    ]
}

/// Largest anchor size across all tables (decode-window sizing).
pub const MAX_ANCHOR_SIZE: usize = 8;

/* ===================== multi-arch tables (capstone path) =====================
 *
 * Ported from gadgets.py `addROPGadgets`/`addJOPGadgets`/`addSYSGadgets` for
 * the non-x86 arches: MIPS (147-148, 275-297, 422-430), PPC (149-163,
 * 298-306, 431-441), SPARC (165-178, 308-317, 443-444), ARM64 (182-191,
 * 318-329, 445-446), ARM/Thumb (180-181, 330-362, 447-467), RISCV
 * (193-202, 363-392, 468-479). Byte order variants follow ROPgadget's
 * `arch_endian` branches. SPARC SYS and ARM64 SYS are empty in ROPgadget
 * (marked TODO there) — replicated as empty tables.
 */

/// Which ROPgadget anchor table (`addROPGadgets` / `addJOPGadgets` /
/// `addSYSGadgets`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableKind {
    /// `addROPGadgets` — return-terminated gadgets.
    Rop,
    /// `addJOPGadgets` — indirect-branch-terminated gadgets.
    Jop,
    /// `addSYSGadgets` — syscall/trap-terminated gadgets.
    Sys,
}

/// The anchor table for one (kind, arch, endianness, thumb) combination,
/// in ROPgadget's table order. Empty where ROPgadget's table is empty.
pub fn table(kind: TableKind, arch: Arch, endian: Endianness, thumb: bool) -> Vec<Anchor> {
    let be = endian == Endianness::Big;
    use TableKind::*;
    match arch {
        Arch::X86 | Arch::X64 => {
            let is64 = arch == Arch::X64;
            match kind {
                Rop => rop_anchors(),
                Jop => jop_anchors(is64),
                Sys => sys_anchors(),
            }
        }
        Arch::Arm | Arch::ArmThumb => match kind {
            Rop => vec![], // gadgets.py:180-181 — ARM has no RET
            Jop => arm_jop(thumb, be),
            Sys => arm_sys(thumb, be),
        },
        Arch::Arm64 => match kind {
            // gadgets.py:182-191
            Rop => {
                if be {
                    vec![m("ret", pat!(f(0xd6), f(0x5f), f(0x03), f(0xc0)), 4, 4)]
                } else {
                    vec![m("ret", pat!(f(0xc0), f(0x03), f(0x5f), f(0xd6)), 4, 4)]
                }
            }
            Jop => arm64_jop(be),
            // ANCH-03. ROPgadget leaves this table EMPTY (gadgets.py:445-446
            // is a bare `TODO`), so `--sys` finds nothing at all on AArch64 —
            // no `svc` gadget, on the architecture where a syscall gadget is
            // the whole point of a SYS search. We populate it, which is a
            // deliberate, RECORDED divergence from the oracle: see
            // tests/known-divergences.json (kind "extra-anchor-table").
            //
            // `SVC #imm16` is `0xd4000001 | (imm16 << 5)`: bits 31..21 are
            // fixed at 0b11010100000, bits 20..5 hold the immediate and bits
            // 4..0 are 0b00001. In little-endian byte order that pins byte 3
            // to 0xd4, constrains byte 2 to 0x00..0x1f (its top three bits
            // are part of the fixed field) and byte 0 to the eight values
            // whose low five bits are 0b00001.
            Sys => arm64_sys(be),
        },
        Arch::Mips32 | Arch::Mips64 => match kind {
            Rop => vec![], // gadgets.py:147-148 — MIPS has no RET
            Jop => mips_jop(be),
            Sys => {
                // gadgets.py:422-430
                if be {
                    vec![m("syscall", pat!(f(0x00), f(0x00), f(0x00), f(0x0c)), 4, 4)]
                } else {
                    vec![m("syscall", pat!(f(0x0c), f(0x00), f(0x00), f(0x00)), 4, 4)]
                }
            }
        },
        Arch::Ppc32 | Arch::Ppc64 => match kind {
            Rop => ppc_rop(be),
            Jop => {
                // gadgets.py:298-306
                if be {
                    vec![m("bl", pat!(f(0x48), ANY, ANY, ANY), 4, 4)]
                } else {
                    vec![m("bl", pat!(ANY, ANY, ANY, f(0x48)), 4, 4)]
                }
            }
            Sys => {
                // gadgets.py:431-441
                if be {
                    vec![
                        m("sc", pat!(f(0x44), f(0x00), f(0x00), f(0x02)), 4, 4),
                        m("scv", pat!(f(0x44), f(0x00), f(0x00), f(0x03)), 4, 4),
                    ]
                } else {
                    vec![
                        m("sc", pat!(f(0x02), f(0x00), f(0x00), f(0x44)), 4, 4),
                        m("scv", pat!(f(0x03), f(0x00), f(0x00), f(0x44)), 4, 4),
                    ]
                }
            }
        },
        Arch::Sparc | Arch::Sparc64 | Arch::SparcV9 => match kind {
            Rop => sparc_rop(be),
            Jop => {
                // gadgets.py:308-317 — jmp %g[0-3]
                if be {
                    vec![m(
                        "jmp %g[0-3]",
                        pat!(
                            f(0x81),
                            f(0xc0),
                            r(&[(0x00, 0x00), (0x40, 0x40), (0x80, 0x80), (0xc0, 0xc0)]),
                            f(0x00)
                        ),
                        4,
                        4,
                    )]
                } else {
                    vec![m(
                        "jmp %g[0-3]",
                        pat!(
                            f(0x00),
                            r(&[(0x00, 0x00), (0x40, 0x40), (0x80, 0x80), (0xc0, 0xc0)]),
                            f(0xc0),
                            f(0x81)
                        ),
                        4,
                        4,
                    )]
                }
            }
            // ANCH-03, same deliberate divergence as ARM64: ROPgadget's
            // table is a `TODO (ta inst)` comment (gadgets.py:443-444).
            // SPARC's software trap is `Ticc` with cond=1000 (always):
            // `ta %g0 + imm7` is `0x91d02000 | imm7` — `ta 0x10` is the
            // Solaris/Linux syscall gate. Recorded in
            // tests/known-divergences.json.
            Sys => sparc_sys(be),
        },
        Arch::RiscV32 | Arch::RiscV64 => match kind {
            // gadgets.py:193-202 — ROPgadget uses the same table for RV32/RV64
            Rop => {
                if be {
                    vec![m("c.ret", pat!(f(0x80), f(0x82)), 2, 1)]
                } else {
                    vec![m("c.ret", pat!(f(0x82), f(0x80)), 2, 1)]
                }
            }
            Jop => riscv_jop(be),
            Sys => {
                // gadgets.py:468-479
                if be {
                    vec![m("syscall", pat!(f(0x00), f(0x00), f(0x00), f(0x73)), 4, 2)]
                } else {
                    vec![m("syscall", pat!(f(0x73), f(0x00), f(0x00), f(0x00)), 4, 2)]
                }
            }
        },
    }
}

/// ARM64 SYS anchors (ANCH-03 — ROPgadget's table is empty).
/// `svc #imm16` = `0xd4000001 | (imm16 << 5)`.
fn arm64_sys(be: bool) -> Vec<Anchor> {
    /// The low byte's possible values: `0b000` | `imm[2:0] << 5` | `0b00001`.
    const SVC_LOW: &[(u8, u8)] = &[
        (0x01, 0x01),
        (0x21, 0x21),
        (0x41, 0x41),
        (0x61, 0x61),
        (0x81, 0x81),
        (0xa1, 0xa1),
        (0xc1, 0xc1),
        (0xe1, 0xe1),
    ];
    /// Byte 2 holds `imm[15:11]` in its low five bits; the top three are 0.
    const SVC_HIGH: &[(u8, u8)] = &[(0x00, 0x1f)];
    if be {
        vec![m("svc", pat!(f(0xd4), r(SVC_HIGH), ANY, r(SVC_LOW)), 4, 4)]
    } else {
        vec![m("svc", pat!(r(SVC_LOW), ANY, r(SVC_HIGH), f(0xd4)), 4, 4)]
    }
}

/// SPARC SYS anchors (ANCH-03 — ROPgadget's table is empty).
/// `ta %g0 + imm7` = `0x91d02000 | imm7` (Ticc, cond = always, i = 1,
/// rs1 = %g0); `ta 0x10` is the Linux/Solaris syscall trap.
fn sparc_sys(be: bool) -> Vec<Anchor> {
    const IMM7: &[(u8, u8)] = &[(0x00, 0x7f)];
    if be {
        vec![m("ta", pat!(f(0x91), f(0xd0), f(0x20), r(IMM7)), 4, 4)]
    } else {
        vec![m("ta", pat!(r(IMM7), f(0x20), f(0xd0), f(0x91)), 4, 4)]
    }
}

/// Shorthand for a character-class matcher.
const fn r(rs: &'static [(u8, u8)]) -> BytePat {
    BytePat::Ranges(rs)
}

/// MIPS register-field byte sets shared by the jalr/jr anchors
/// (gadgets.py:278-283, 289-294).
mod mips_sets {
    /// $v[0-1] | $a[0-3]
    pub const V0_A3: &[(u8, u8)] = &[
        (0x40, 0x40),
        (0x60, 0x60),
        (0x80, 0x80),
        (0xa0, 0xa0),
        (0xc0, 0xc0),
        (0xe0, 0xe0),
    ];
    /// $t[0-7] | $s[0-7]
    pub const T0_S7: &[(u8, u8)] = &[
        (0x00, 0x00),
        (0x20, 0x20),
        (0x40, 0x40),
        (0x60, 0x60),
        (0x80, 0x80),
        (0xa0, 0xa0),
        (0xc0, 0xc0),
        (0xe0, 0xe0),
    ];
    /// $t[8-9] | $s8 | $ra
    pub const T8_RA: &[(u8, u8)] = &[(0x00, 0x00), (0x20, 0x20), (0xc0, 0xc0), (0xe0, 0xe0)];
    /// $t[0-1] selector byte (high byte of the rs field word half)
    pub const R01_02: &[(u8, u8)] = &[(0x01, 0x02)];
}

/// MIPS JOP anchors (gadgets.py:275-297). All size 8 (jump + delay slot),
/// align 4.
fn mips_jop(be: bool) -> Vec<Anchor> {
    use mips_sets::*;
    if be {
        vec![
            m(
                "jalr $v[0-1]|$a[0-3]",
                pat!(f(0x00), r(V0_A3), f(0xf8), f(0x09), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jalr $t[0-7]|$s[0-7]",
                pat!(r(R01_02), r(T0_S7), f(0xf8), f(0x09), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jalr $t[8-9]|$s8|$ra",
                pat!(f(0x03), r(T8_RA), f(0xf8), f(0x09), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jr $v[0-1]|$a[0-3]",
                pat!(f(0x00), r(V0_A3), f(0x00), f(0x08), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jr $t[0-7]|$s[0-7]",
                pat!(r(R01_02), r(T0_S7), f(0x00), f(0x08), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jr $t[8-9]|$s8|$ra",
                pat!(f(0x03), r(T8_RA), f(0x00), f(0x08), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jal addr",
                pat!(r(&[(0x0c, 0x0f)]), ANY, ANY, ANY, ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "j addr",
                pat!(r(&[(0x08, 0x0b)]), ANY, ANY, ANY, ANY, ANY, ANY, ANY),
                8,
                4,
            ),
        ]
    } else {
        vec![
            m(
                "jalr $v[0-1]|$a[0-3]",
                pat!(f(0x09), f(0xf8), r(V0_A3), f(0x00), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jalr $t[0-7]|$s[0-7]",
                pat!(f(0x09), f(0xf8), r(T0_S7), r(R01_02), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jalr $t[8-9]|$s8|$ra",
                pat!(f(0x09), f(0xf8), r(T8_RA), f(0x03), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jr $v[0-1]|$a[0-3]",
                pat!(f(0x08), f(0x00), r(V0_A3), f(0x00), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jr $t[0-7]|$s[0-7]",
                pat!(f(0x08), f(0x00), r(T0_S7), r(R01_02), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jr $t[8-9]|$s8|$ra",
                pat!(f(0x08), f(0x00), r(T8_RA), f(0x03), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "jal addr",
                pat!(ANY, ANY, ANY, r(&[(0x0c, 0x0f)]), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
            m(
                "j addr",
                pat!(ANY, ANY, ANY, r(&[(0x08, 0x0b)]), ANY, ANY, ANY, ANY),
                8,
                4,
            ),
        ]
    }
}

/// PPC ROP anchors (gadgets.py:149-163): blr/blrl/bctr/bctrl.
fn ppc_rop(be: bool) -> Vec<Anchor> {
    if be {
        vec![
            m("blr", pat!(f(0x4e), f(0x80), f(0x00), f(0x20)), 4, 4),
            m("blrl", pat!(f(0x4e), f(0x80), f(0x00), f(0x21)), 4, 4),
            m("bctr", pat!(f(0x4e), f(0x80), f(0x04), f(0x20)), 4, 4),
            m("bctrl", pat!(f(0x4e), f(0x80), f(0x04), f(0x21)), 4, 4),
        ]
    } else {
        vec![
            m("blr", pat!(f(0x20), f(0x00), f(0x80), f(0x4e)), 4, 4),
            m("blrl", pat!(f(0x21), f(0x00), f(0x80), f(0x4e)), 4, 4),
            m("bctr", pat!(f(0x20), f(0x04), f(0x80), f(0x4e)), 4, 4),
            m("bctrl", pat!(f(0x21), f(0x04), f(0x80), f(0x4e)), 4, 4),
        ]
    }
}

/// SPARC ROP anchors (gadgets.py:165-177): retl/ret/restore.
fn sparc_rop(be: bool) -> Vec<Anchor> {
    if be {
        vec![
            m("retl", pat!(f(0x81), f(0xc3), f(0xe0), f(0x08)), 4, 4),
            m("ret", pat!(f(0x81), f(0xc7), f(0xe0), f(0x08)), 4, 4),
            m("restore", pat!(f(0x81), f(0xe8), f(0x00), f(0x00)), 4, 4),
        ]
    } else {
        vec![
            m("retl", pat!(f(0x08), f(0xe0), f(0xc3), f(0x81)), 4, 4),
            m("ret", pat!(f(0x08), f(0xe0), f(0xc7), f(0x81)), 4, 4),
            m("restore", pat!(f(0x00), f(0x00), f(0xe8), f(0x81)), 4, 4),
        ]
    }
}

/// ARM64 JOP anchors (gadgets.py:318-329): br/blr reg.
fn arm64_jop(be: bool) -> Vec<Anchor> {
    // [\x1f\x5f] (N field), [\x00-\x03], register byte set.
    const N: &[(u8, u8)] = &[(0x1f, 0x1f), (0x5f, 0x5f)];
    const Z: &[(u8, u8)] = &[(0x00, 0x03)];
    const RN: &[(u8, u8)] = &[
        (0x00, 0x00),
        (0x20, 0x20),
        (0x40, 0x40),
        (0x60, 0x60),
        (0x80, 0x80),
        (0xa0, 0xa0),
        (0xc0, 0xc0),
        (0xe0, 0xe0),
    ];
    if be {
        vec![
            m("br reg", pat!(f(0xd6), r(N), r(Z), r(RN)), 4, 4),
            m("blr reg", pat!(f(0xd6), f(0x3f), r(Z), r(RN)), 4, 4),
        ]
    } else {
        vec![
            m("br reg", pat!(r(RN), r(Z), r(N), f(0xd6)), 4, 4),
            m("blr reg", pat!(r(RN), r(Z), f(0x3f), f(0xd6)), 4, 4),
        ]
    }
}

/// ARM (A32 and Thumb) JOP anchors (gadgets.py:330-362).
///
/// Thumb quirk ported verbatim: the `ldm.w`/`ldmdb` patterns match 6 bytes
/// but `gad_size` is 4 — the trailing `[\x00-\xff]{4}` only gates the match
/// (gadgets.py:337-338, 345-346).
fn arm_jop(thumb: bool, be: bool) -> Vec<Anchor> {
    if thumb {
        const BX: &[(u8, u8)] = &[
            (0x00, 0x00),
            (0x08, 0x08),
            (0x10, 0x10),
            (0x18, 0x18),
            (0x20, 0x20),
            (0x28, 0x28),
            (0x30, 0x30),
            (0x38, 0x38),
            (0x40, 0x40),
            (0x48, 0x48),
            (0x70, 0x70),
        ];
        const BLX: &[(u8, u8)] = &[
            (0x80, 0x80),
            (0x88, 0x88),
            (0x90, 0x90),
            (0x98, 0x98),
            (0xa0, 0xa0),
            (0xa8, 0xa8),
            (0xb0, 0xb0),
            (0xb8, 0xb8),
            (0xc0, 0xc0),
            (0xc8, 0xc8),
            (0xf0, 0xf0),
        ];
        const LDM_W: &[(u8, u8)] = &[(0x90, 0x9f), (0xb0, 0xbf)];
        const LDMDB: &[(u8, u8)] = &[(0x10, 0x1f), (0x30, 0x3f)];
        if be {
            vec![
                m("bx reg", pat!(f(0x47), r(BX)), 2, 2),
                m("blx reg", pat!(f(0x47), r(BLX)), 2, 2),
                m("pop {,pc}", pat!(f(0xbd), ANY), 2, 2),
                m(
                    "ldm.w reg{!}, {,pc}",
                    pat!(f(0xe8), r(LDM_W), ANY, ANY, ANY, ANY),
                    4,
                    2,
                ),
                m(
                    "ldmdb reg{!}, {,pc}",
                    pat!(f(0xe9), r(LDMDB), ANY, ANY, ANY, ANY),
                    4,
                    2,
                ),
            ]
        } else {
            vec![
                m("bx reg", pat!(r(BX), f(0x47)), 2, 2),
                m("blx reg", pat!(r(BLX), f(0x47)), 2, 2),
                m("pop {,pc}", pat!(ANY, f(0xbd)), 2, 2),
                m(
                    "ldm.w reg{!}, {,pc}",
                    pat!(r(LDM_W), f(0xe8), ANY, ANY, ANY, ANY),
                    4,
                    2,
                ),
                m(
                    "ldmdb reg{!}, {,pc}",
                    pat!(r(LDMDB), f(0xe9), ANY, ANY, ANY, ANY),
                    4,
                    2,
                ),
            ]
        }
    } else {
        const BX: &[(u8, u8)] = &[(0x10, 0x19), (0x1e, 0x1e)];
        const BLX: &[(u8, u8)] = &[(0x30, 0x39), (0x3e, 0x3e)];
        const E8_E9: &[(u8, u8)] = &[(0xe8, 0xe9)];
        const LDM_MID: &[(u8, u8)] = &[
            (0x10, 0x1e),
            (0x30, 0x3e),
            (0x50, 0x5e),
            (0x70, 0x7e),
            (0x90, 0x9e),
            (0xb0, 0xbe),
            (0xd0, 0xde),
            (0xf0, 0xfe),
        ];
        const HI: &[(u8, u8)] = &[(0x80, 0xff)];
        if be {
            vec![
                m("bx reg", pat!(f(0xe1), f(0x2f), f(0xff), r(BX)), 4, 4),
                m("blx reg", pat!(f(0xe1), f(0x2f), f(0xff), r(BLX)), 4, 4),
                m("ldm {,pc}", pat!(r(E8_E9), r(LDM_MID), r(HI), ANY), 4, 4),
            ]
        } else {
            vec![
                m("bx reg", pat!(r(BX), f(0xff), f(0x2f), f(0xe1)), 4, 4),
                m("blx reg", pat!(r(BLX), f(0xff), f(0x2f), f(0xe1)), 4, 4),
                m("ldm {,pc}", pat!(ANY, r(HI), r(LDM_MID), r(E8_E9)), 4, 4),
            ]
        }
    }
}

/// ARM (A32 and Thumb) SYS anchors (gadgets.py:447-467): svc.
fn arm_sys(thumb: bool, be: bool) -> Vec<Anchor> {
    if thumb {
        if be {
            vec![m("svc imm8", pat!(f(0xdf), ANY), 2, 2)]
        } else {
            vec![m("svc imm8", pat!(ANY, f(0xdf)), 2, 2)]
        }
    } else {
        // svc{cond} imm24: condition nibble 0x0f..0xef in the top byte.
        const SVC: &[(u8, u8)] = &[
            (0x0f, 0x0f),
            (0x1f, 0x1f),
            (0x2f, 0x2f),
            (0x3f, 0x3f),
            (0x4f, 0x4f),
            (0x5f, 0x5f),
            (0x6f, 0x6f),
            (0x7f, 0x7f),
            (0x8f, 0x8f),
            (0x9f, 0x9f),
            (0xaf, 0xaf),
            (0xbf, 0xbf),
            (0xcf, 0xcf),
            (0xdf, 0xdf),
            (0xef, 0xef),
        ];
        if be {
            vec![m("svc{cond} imm24", pat!(r(SVC), ANY, ANY, ANY), 4, 4)]
        } else {
            vec![m("svc{cond} imm24", pat!(ANY, ANY, ANY, r(SVC)), 4, 4)]
        }
    }
}

/// RISC-V JOP anchors (gadgets.py:363-392). Size 4 align 2 for 32-bit forms,
/// size 2 align 2 for the compressed forms.
fn riscv_jop(be: bool) -> Vec<Anchor> {
    const JALR: &[(u8, u8)] = &[(0x67, 0x67), (0x6f, 0x6f), (0xe7, 0xe7), (0xef, 0xef)];
    const BR: &[(u8, u8)] = &[(0x63, 0x63), (0xe3, 0xe3)];
    const A0_FF: &[(u8, u8)] = &[(0xa0, 0xff)];
    // c.j | c.beqz | c.bnez selector bytes (three tables in gadgets.py).
    const CJ1: &[(u8, u8)] = &[
        (0xa1, 0xa1),
        (0xa5, 0xa5),
        (0xa9, 0xa9),
        (0xad, 0xad),
        (0xb1, 0xb1),
        (0xb5, 0xb5),
        (0xb9, 0xb9),
        (0xbd, 0xbd),
        (0xc1, 0xc1),
        (0xc5, 0xc5),
        (0xc9, 0xc9),
        (0xcd, 0xcd),
        (0xd1, 0xd1),
        (0xd5, 0xd5),
        (0xd9, 0xd9),
        (0xdd, 0xdd),
        (0xe1, 0xe1),
        (0xe5, 0xe5),
        (0xe9, 0xe9),
        (0xed, 0xed),
        (0xf1, 0xf1),
        (0xf5, 0xf5),
        (0xf9, 0xf9),
        (0xfd, 0xfd),
    ];
    const CJ2: &[(u8, u8)] = &[
        (0x01, 0x01),
        (0x05, 0x05),
        (0x09, 0x09),
        (0x0d, 0x0d),
        (0x11, 0x11),
        (0x15, 0x15),
        (0x19, 0x19),
        (0x1d, 0x1d),
        (0x21, 0x21),
        (0x25, 0x25),
        (0x29, 0x29),
        (0x2d, 0x2d),
        (0x31, 0x31),
        (0x35, 0x35),
        (0x39, 0x39),
        (0x3d, 0x3d),
        (0x41, 0x41),
        (0x45, 0x45),
        (0x49, 0x49),
        (0x4d, 0x4d),
        (0x51, 0x51),
        (0x55, 0x55),
        (0x59, 0x59),
        (0x5d, 0x5d),
    ];
    const CJ3: &[(u8, u8)] = &[
        (0x61, 0x61),
        (0x65, 0x65),
        (0x69, 0x69),
        (0x6d, 0x6d),
        (0x71, 0x71),
        (0x75, 0x75),
        (0x79, 0x79),
        (0x7d, 0x7d),
        (0x81, 0x81),
        (0x85, 0x85),
        (0x89, 0x89),
        (0x8d, 0x8d),
        (0x91, 0x91),
        (0x95, 0x95),
        (0x99, 0x99),
        (0x9d, 0x9d),
    ];
    const CJR_RD: &[(u8, u8)] = &[(0x02, 0x02), (0x82, 0x82)];
    const CJR_RS1: &[(u8, u8)] = &[(0x81, 0x8f)];
    const CJALR_RS1: &[(u8, u8)] = &[(0x91, 0x9f)];
    if be {
        vec![
            m("jalr/j/jal reg, off", pat!(ANY, ANY, ANY, r(JALR)), 4, 2),
            m("branch reg, off", pat!(ANY, ANY, ANY, r(BR)), 4, 2),
            m("c.j|c.beqz|c.bnez (1)", pat!(r(A0_FF), r(CJ1)), 2, 2),
            m("c.j|c.beqz|c.bnez (2)", pat!(r(A0_FF), r(CJ2)), 2, 2),
            m("c.j|c.beqz|c.bnez (3)", pat!(r(A0_FF), r(CJ3)), 2, 2),
            m("c.jr register", pat!(r(CJR_RS1), r(CJR_RD)), 2, 2),
            m("c.jalr register", pat!(r(CJALR_RS1), r(CJR_RD)), 2, 2),
        ]
    } else {
        vec![
            m("jalr/j/jal reg, off", pat!(r(JALR), ANY, ANY, ANY), 4, 2),
            m("branch reg, off", pat!(r(BR), ANY, ANY, ANY), 4, 2),
            m("c.j|c.beqz|c.bnez (1)", pat!(r(CJ1), r(A0_FF)), 2, 2),
            m("c.j|c.beqz|c.bnez (2)", pat!(r(CJ2), r(A0_FF)), 2, 2),
            m("c.j|c.beqz|c.bnez (3)", pat!(r(CJ3), r(A0_FF)), 2, 2),
            m("c.jr register", pat!(r(CJR_RD), r(CJR_RS1)), 2, 2),
            m("c.jalr register", pat!(r(CJR_RD), r(CJALR_RS1)), 2, 2),
        ]
    }
}

/// Find all non-overlapping matches of `anchor` in `code`, ascending
/// (Python `re.finditer` semantics: resume at `match_end` after a hit).
///
/// memchr-accelerated when the pattern starts with a fixed byte; falls back
/// to a linear scan when it starts with a wildcard/class (many fixed-width
/// ISA anchors do — the buffers are small and anchors are scanned in
/// parallel, so this stays cheap).
pub fn find_matches(code: &[u8], anchor: &Anchor) -> Vec<usize> {
    match anchor.pattern.first() {
        Some(BytePat::Fixed(first)) => find_matches_fixed_head(code, anchor, *first),
        _ => find_matches_linear(code, anchor),
    }
}

/// Every position in `lo..hi` where `anchor` matches — **including
/// overlapping ones**, unlike [`find_matches`].
///
/// PERF-04 needs the hit list of one (region, anchor) pair to be computable
/// in pieces, because on the MIPS fixture a single anchor holds 92% of the
/// hits and finding them is 27 ms that no amount of anchor-level parallelism
/// can split. Python's `re.finditer` is stateful — after a match it resumes
/// at `match_end` — so a sub-range cannot reproduce its output on its own:
/// a range starting inside a match the previous range consumed would emit a
/// hit the whole-buffer scan never had.
///
/// The state is recovered exactly by separating the two halves of what
/// `finditer` does. This function does the stateless half (every position
/// that matches); [`merge_finditer`] does the stateful half in one cheap
/// serial pass, and leftmost-greedy selection over all matching positions is
/// precisely `finditer`. `find_matches_agrees_with_chunked_scan` asserts the
/// identity over every anchor table in the project.
pub fn find_matches_in(code: &[u8], anchor: &Anchor, lo: usize, hi: usize) -> Vec<usize> {
    let len = anchor.pattern.len();
    let mut hits = Vec::new();
    if len == 0 || code.len() < len {
        return hits;
    }
    let last = code.len() - len; // last position a full match can start at
    let hi = hi.min(last + 1);
    let mut pos = lo;
    let fixed_head = match anchor.pattern.first() {
        Some(BytePat::Fixed(b)) => Some(*b),
        _ => None,
    };
    while pos < hi {
        let p = match fixed_head {
            Some(first) => match memchr::memchr(first, &code[pos..hi]) {
                Some(o) => pos + o,
                None => break,
            },
            None => pos,
        };
        // memchr has already established `pattern[0]` when the head is
        // fixed; when it is a wildcard or a class, nothing has, so the
        // whole pattern is tested (this is the bug the chunked-vs-whole
        // property test caught: skipping byte 0 on a wildcard head admits
        // matches `find_matches` never had).
        let from = usize::from(fixed_head.is_some());
        if anchor.pattern[from..]
            .iter()
            .enumerate()
            .all(|(i, bp)| bp.matches(code[p + from + i]))
        {
            hits.push(p);
        }
        pos = p + 1;
    }
    hits
}

/// Leftmost-greedy selection over ascending, possibly overlapping match
/// positions — the stateful half of `re.finditer` (`pos = match_end`).
pub fn merge_finditer(all: &[usize], anchor: &Anchor) -> Vec<usize> {
    let len = anchor.pattern.len();
    let mut out = Vec::with_capacity(all.len());
    let mut next = 0usize;
    for &p in all {
        if p >= next {
            out.push(p);
            next = p + len;
        }
    }
    out
}

fn find_matches_fixed_head(code: &[u8], anchor: &Anchor, first: u8) -> Vec<usize> {
    let len = anchor.pattern.len();
    let mut hits = Vec::new();
    let mut pos = 0usize;
    while pos < code.len() {
        let off = match memchr::memchr(first, &code[pos..]) {
            Some(o) => o,
            None => break,
        };
        let p = pos + off;
        if p + len > code.len() {
            break;
        }
        let ok = anchor.pattern[1..]
            .iter()
            .enumerate()
            .all(|(i, bp)| bp.matches(code[p + 1 + i]));
        if ok {
            hits.push(p);
            pos = p + len; // non-overlapping, like re.finditer
        } else {
            pos = p + 1;
        }
    }
    hits
}

fn find_matches_linear(code: &[u8], anchor: &Anchor) -> Vec<usize> {
    let len = anchor.pattern.len();
    let mut hits = Vec::new();
    let mut pos = 0usize;
    while pos + len <= code.len() {
        let ok = anchor
            .pattern
            .iter()
            .enumerate()
            .all(|(i, bp)| bp.matches(code[pos + i]));
        if ok {
            hits.push(pos);
            pos += len; // non-overlapping, like re.finditer
        } else {
            pos += 1;
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finditer_non_overlapping_semantics() {
        // \xc2[\x00-\xff]{2} at 0 consumes bytes 0..3, so the \xc2 at
        // offset 1 is NOT an anchor (Python re.finditer behavior).
        let anchors = rop_anchors();
        let ret_imm = &anchors[1];
        let code = [0xc2, 0xc2, 0x00, 0x00, 0xc2, 0x00, 0x00];
        assert_eq!(find_matches(&code, ret_imm), vec![0, 4]);
    }

    #[test]
    fn single_byte_anchors_find_all() {
        let anchors = rop_anchors();
        let code = [0x00, 0xc3, 0xc3, 0x00];
        assert_eq!(find_matches(&code, &anchors[0]), vec![1, 2]);
    }

    /// PERF-04's parallel anchor search is only sound if cutting the byte
    /// range and re-applying `re.finditer`'s leftmost-greedy rule reproduces
    /// the single-sweep hit list EXACTLY — a hit that appears or disappears
    /// changes the gadget set, and near a chunk boundary is precisely where
    /// `pos = match_end` state would be lost.
    ///
    /// This ran red before `find_matches_in` tested `pattern[0]` on a
    /// wildcard-headed anchor: `elf-ARMv7-ls` went from 3,782 raw gadgets to
    /// 4,779.
    #[test]
    fn find_matches_agrees_with_chunked_scan() {
        // A deterministic pseudo-random buffer: dense enough in every byte
        // value that the ARM/MIPS/PPC/SPARC/RISC-V class-headed anchors and
        // the x86 fixed-headed ones all hit, many of them overlapping.
        let mut code = vec![0u8; 8192];
        let mut x: u32 = 0x1234_5678;
        for b in code.iter_mut() {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (x >> 16) as u8;
        }
        let mut tables: Vec<Anchor> = Vec::new();
        tables.extend(rop_anchors());
        tables.extend(jop_anchors(true));
        tables.extend(sys_anchors());
        for arch in [
            Arch::Arm,
            Arch::ArmThumb,
            Arch::Arm64,
            Arch::Mips32,
            Arch::Mips64,
            Arch::Ppc32,
            Arch::Ppc64,
            Arch::Sparc,
            Arch::RiscV32,
            Arch::RiscV64,
        ] {
            for endian in [Endianness::Little, Endianness::Big] {
                for thumb in [false, true] {
                    for kind in [TableKind::Rop, TableKind::Jop, TableKind::Sys] {
                        tables.extend(table(kind, arch, endian, thumb));
                    }
                }
            }
        }
        // Chunk sizes chosen to land boundaries inside multi-byte patterns.
        for &step in &[1usize, 2, 3, 5, 7, 64, 1000] {
            for anchor in &tables {
                let whole = find_matches(&code, anchor);
                let mut all = Vec::new();
                let mut lo = 0usize;
                while lo < code.len() {
                    let hi = (lo + step).min(code.len());
                    all.extend(find_matches_in(&code, anchor, lo, hi));
                    lo = hi;
                }
                assert_eq!(
                    whole,
                    merge_finditer(&all, anchor),
                    "anchor {:?} at chunk step {step}",
                    anchor.name
                );
            }
        }
    }

    #[test]
    fn jop_table_shape() {
        assert_eq!(jop_anchors(false).len(), 7 + 6);
        assert_eq!(jop_anchors(true).len(), 7 + 7 + 6);
        assert_eq!(rop_anchors().len(), 6);
        assert_eq!(sys_anchors().len(), 11);
        // x41-prefixed variant matches `41 ff d0` (call r8)
        let jops = jop_anchors(true);
        let rex_reg = &jops[7];
        assert_eq!(find_matches(&[0x41, 0xff, 0xd0], rex_reg), vec![0]);
    }
}
