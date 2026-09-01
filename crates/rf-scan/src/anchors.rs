//! x86/x64 anchor tables, ported faithfully from ROPgadget's
//! `ropgadget/gadgets.py` (`addROPGadgets` lines 137-145, `addJOPGadgets`
//! lines 217-274, `addSYSGadgets` lines 407-420).
//!
//! Each anchor is a pattern of byte matchers. Matching replicates Python
//! `re.finditer` semantics per pattern: matches are leftmost and
//! **non-overlapping** — after a match at `p` of length `L`, scanning resumes
//! at `p + L`.

use std::borrow::Cow;

/// A single pattern position: fixed byte, wildcard, or a set of inclusive
/// byte ranges (regex character class).
#[derive(Debug, Clone, Copy)]
pub enum BytePat {
    Fixed(u8),
    Any,
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
    pub pattern: Cow<'static, [BytePat]>,
}

impl Anchor {
    pub fn size(&self) -> usize {
        self.pattern.len()
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

fn a(name: &'static str, pattern: &'static [BytePat]) -> Anchor {
    Anchor {
        name,
        pattern: Cow::Borrowed(pattern),
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
        a("call/jmp [esp]", pat!(f(0xff), BytePat::Ranges(MEM_SP), f(0x24))),
        a("call/jmp [reg + disp8]", pat!(f(0xff), BytePat::Ranges(MEM_D8), ANY)),
        a("call/jmp [esp + disp8]", pat!(f(0xff), BytePat::Ranges(MEM_SP_D8), f(0x24), ANY)),
        a("call/jmp [reg + disp32]", pat!(f(0xff), BytePat::Ranges(MEM_D32), ANY, ANY, ANY, ANY)),
        a("call/jmp [esp + disp32]", pat!(f(0xff), BytePat::Ranges(MEM_SP_D32), f(0x24), ANY, ANY, ANY, ANY)),
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
                pattern: Cow::Owned(p),
            });
        }
    }
    // Extra sequences common to x86 and x64.
    v.extend([
        a("jmp rel8", pat!(f(0xeb), ANY)),
        a("jmp rel32", pat!(f(0xe9), ANY, ANY, ANY, ANY)),
        // MPX — decode as "bnd jmp"/"bnd call", always rejected by passCleanX86
        a("bnd jmp [reg]", pat!(f(0xf2), f(0xff), BytePat::Ranges(&[(0x20, 0x23), (0x26, 0x27)]))),
        a("bnd jmp reg", pat!(f(0xf2), f(0xff), BytePat::Ranges(&[(0xe0, 0xe4), (0xe6, 0xe7)]))),
        a("bnd jmp [reg] (2)", pat!(f(0xf2), f(0xff), BytePat::Ranges(&[(0x10, 0x13), (0x16, 0x17)]))),
        a("bnd call reg", pat!(f(0xf2), f(0xff), BytePat::Ranges(&[(0xd0, 0xd4), (0xd6, 0xd7)]))),
    ]);
    v
}

/// SYS anchors (`gadgets.py:407-420`). All fixed bytes.
pub fn sys_anchors() -> Vec<Anchor> {
    vec![
        a("int 0x80", pat!(f(0xcd), f(0x80))),
        a("sysenter", pat!(f(0x0f), f(0x34))),
        a("syscall", pat!(f(0x0f), f(0x05))),
        a("call DWORD PTR gs:0x10", pat!(f(0x65), f(0xff), f(0x15), f(0x10), f(0x00), f(0x00), f(0x00))),
        a("int 0x80 ; ret", pat!(f(0xcd), f(0x80), f(0xc3))),
        a("sysenter ; ret", pat!(f(0x0f), f(0x34), f(0xc3))),
        a("syscall ; ret", pat!(f(0x0f), f(0x05), f(0xc3))),
        a("call DWORD PTR gs:0x10 ; ret", pat!(f(0x65), f(0xff), f(0x15), f(0x10), f(0x00), f(0x00), f(0x00), f(0xc3))),
        a("sysret", pat!(f(0x0f), f(0x07))),
        a("sysret (rex.w)", pat!(f(0x48), f(0x0f), f(0x07))),
        a("iret", pat!(f(0xcf))),
    ]
}

/// Largest anchor size across all tables (decode-window sizing).
pub const MAX_ANCHOR_SIZE: usize = 8;

/// Find all non-overlapping matches of `anchor` in `code`, ascending
/// (Python `re.finditer` semantics: resume at `match_end` after a hit).
pub fn find_matches(code: &[u8], anchor: &Anchor) -> Vec<usize> {
    let first = match anchor.pattern.first() {
        Some(BytePat::Fixed(b)) => *b,
        _ => unreachable!("all x86 anchors start with a fixed byte"),
    };
    let len = anchor.size();
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
