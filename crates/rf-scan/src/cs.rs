//! Capstone decode path for the fixed-width ISAs (everything except
//! x86/x64, which uses iced-x86 in [`crate::x86`]).
//!
//! Semantics ported from ROPgadget's `gadgets.py`:
//!  - aligned backward stepping with byte-fallback (`__gadgetsFinding`,
//!    gadgets.py:73-89): candidate starts are `ref - i*gad_align` when that
//!    lands on a `gad_align` boundary in *virtual address* space, else
//!    `ref - i` when that does; candidates failing both are skipped.
//!  - clean-decode rule (gadgets.py:104-107): the candidate is valid iff the
//!    bytes `start..end` decode contiguously — `total_size == expected_size`.
//!    Because the decode starts at `start` and stops at the first invalid
//!    instruction, this is equivalent to "`end` coincides with an instruction
//!    boundary of the decode from `start`" (same formulation as the x86
//!    engine's total_size rule, gadgets.py:100-103).
//!  - RISC-V last-instruction size check (gadgets.py:109-112): the last
//!    decoded instruction must be exactly `gad_size` bytes, rejecting
//!    candidates whose final 2 bytes alias a compressed instruction.
//!  - `passClean` (gadgets.py:488-498): for non-x86 arches there is NO
//!    branch-in-middle rejection; only the mnemonic filter runs (built-in
//!    `brk|smc|hvc` for ARM64, gadgets.py:34-35, plus user `--filter`).
//!
//! Text is `"{mnemonic} {op_str}"` per instruction (gadgets.py:118-119),
//! including ROPgadget's single-pass `.replace("  ", " ")`.
//!
//! capstone-rs 0.13 `Capstone` is `!Send`/`!Sync`, so every work item
//! constructs its own handle (cheap: one `cs_open` per anchor scan).

use std::collections::HashMap;
use std::rc::Rc;

use capstone::{Arch as CsArch, Capstone, Endian as CsEndian, ExtraMode, Mode};

use rf_core::{Arch, Endianness, Error};

use crate::anchors::{self, Anchor};
use crate::engine::{Gadget, ScanOptions};

/// Static per-arch capstone configuration.
#[derive(Debug, Clone, Copy)]
pub struct CsSpec {
    pub arch: CsArch,
    pub mode: Mode,
    pub endian: Option<CsEndian>,
    pub riscv_compressed: bool,
    /// RISC-V last-instruction size check (gadgets.py:109-112).
    pub is_riscv: bool,
    /// Built-in exact-match mnemonic filter (gadgets.py:34-35): ARM64 only.
    pub builtin_filter: &'static [&'static str],
}

/// Map the rf-core arch contract to capstone arch/mode/endianness,
/// replicating gadgets.py's mode overrides:
///  - SPARC: `arch_mode = 0` (gadgets.py:178, 317) — plain mode + endian.
///  - ARM64: `arch_mode = CS_MODE_ARM = 0` (gadgets.py:191, 329).
///  - ARM: `CS_MODE_ARM` or `CS_MODE_THUMB` (gadgets.py:348, 362, 457, 467).
///  - MIPS/PPC: ELF class mode (`CS_MODE_32`/`CS_MODE_64`) — ROPgadget's
///    `getArchMode` (loaders/elf.py:354-360) is pure ELF-class based.
///  - RISCV: always `RISCV64 | RISCVC`, even for RV32 binaries
///    (gadgets.py:202, 392, 479).
pub fn spec(arch: Arch, endian: Endianness, thumb: bool) -> Result<CsSpec, Error> {
    let cs_endian = match endian {
        Endianness::Little => None, // CS_MODE_LITTLE_ENDIAN == 0 (default)
        Endianness::Big => Some(CsEndian::Big),
    };
    let (cs_arch, mode, rvc) = match arch {
        Arch::X86 | Arch::X64 => {
            return Err(Error::Unsupported(
                "x86/x64 use the iced-x86 path, not capstone".to_string(),
            ))
        }
        Arch::Arm | Arch::ArmThumb => (
            CsArch::ARM,
            if thumb { Mode::Thumb } else { Mode::Arm },
            false,
        ),
        Arch::Arm64 => (CsArch::ARM64, Mode::Arm, false),
        Arch::Mips32 => (CsArch::MIPS, Mode::Mips32, false),
        Arch::Mips64 => (CsArch::MIPS, Mode::Mips64, false),
        Arch::Ppc32 => (CsArch::PPC, Mode::Mode32, false),
        Arch::Ppc64 => (CsArch::PPC, Mode::Mode64, false),
        Arch::Sparc => (CsArch::SPARC, Mode::Default, false),
        // ROPgadget's ELF loader only maps EM_SPARCv8p; EM_SPARCV9 and
        // 64-bit SPARC get V9 mode here (capstone's only 64-bit SPARC mode).
        Arch::Sparc64 | Arch::SparcV9 => (CsArch::SPARC, Mode::V9, false),
        Arch::RiscV32 | Arch::RiscV64 => (CsArch::RISCV, Mode::RiscV64, true),
    };
    let builtin_filter: &'static [&'static str] = match arch {
        Arch::Arm64 => &["brk", "smc", "hvc"], // gadgets.py:34-35
        _ => &[],
    };
    Ok(CsSpec {
        arch: cs_arch,
        mode,
        endian: cs_endian,
        riscv_compressed: rvc,
        is_riscv: matches!(arch, Arch::RiscV32 | Arch::RiscV64),
        builtin_filter,
    })
}

/// Construct a capstone handle for `spec`.
pub fn open(spec: &CsSpec) -> Result<Capstone, Error> {
    let extra: Vec<ExtraMode> = if spec.riscv_compressed {
        vec![ExtraMode::RiscVC]
    } else {
        Vec::new()
    };
    Capstone::new_raw(spec.arch, spec.mode, extra.into_iter(), spec.endian).map_err(|e| {
        Error::Unsupported(format!(
            "capstone cannot open {:?}/{:?}: {e}",
            spec.arch, spec.mode
        ))
    })
}

/// Compact per-instruction record inside a decode window (string-free).
#[derive(Debug, Clone, Copy)]
pub struct WinInsn {
    /// Offset (in the scanned buffer) one past this instruction's last byte.
    pub end: usize,
    /// Instruction length in bytes.
    pub size: usize,
    /// capstone instruction id (for lazy mnemonic lookup).
    pub id: u32,
}

/// Decode a window starting at `start`, recording instruction boundaries
/// until the first undecodable instruction or `max_end` (capstone's
/// `disasm` stops at the first invalid instruction when SKIPDATA is off,
/// which is what ROPgadget relies on for the clean-decode rule).
pub fn decode_window(
    cs: &Capstone,
    code: &[u8],
    start: usize,
    vaddr: u64,
    max_end: usize,
) -> Vec<WinInsn> {
    let limit = max_end.min(code.len());
    if start >= limit {
        return Vec::new();
    }
    let slice = &code[start..limit];
    let addr = vaddr.wrapping_add(start as u64);
    let insns = match cs.disasm_all(slice, addr) {
        Ok(i) => i,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut off = start;
    for insn in insns.iter() {
        let size = insn.len();
        if size == 0 {
            break;
        }
        off += size;
        out.push(WinInsn {
            end: off,
            size,
            id: insn.id().0,
        });
    }
    out
}

/// Format instruction texts for an accepted candidate (bytes `start..end`,
/// known to decode cleanly). Mirrors gadgets.py:118-119:
/// `"{mnemonic} {op_str}"` (space omitted when op_str is empty), with the
/// single-pass double-space squash applied per instruction (equivalent to
/// ROPgadget applying it to the joined gadget text: the " ; " joiner can
/// never create a double space across instruction boundaries).
pub fn format_gadget(
    cs: &Capstone,
    code: &[u8],
    start: usize,
    end: usize,
    vaddr: u64,
) -> Vec<String> {
    let slice = &code[start..end];
    let addr = vaddr.wrapping_add(start as u64);
    let insns = match cs.disasm_all(slice, addr) {
        Ok(i) => i,
        Err(_) => return Vec::new(),
    };
    insns
        .iter()
        .map(|i| {
            let m = i.mnemonic().unwrap_or("");
            let o = i.op_str().unwrap_or("");
            squash_double_spaces(if o.is_empty() {
                m.to_string()
            } else {
                format!("{m} {o}")
            })
        })
        .collect()
}

/// Python `"{}".replace("  ", " ")`: one left-to-right pass, non-overlapping
/// (gadgets.py:119). Only ASCII spaces are removed, so UTF-8 validity is
/// preserved.
fn squash_double_spaces(s: String) -> String {
    if !s.contains("  ") {
        return s;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b' ' && b[i + 1] == b' ' {
            out.push(b' ');
            i += 2;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Port of ROPgadget's `passClean` for non-x86 arches (gadgets.py:488-498):
/// reject empty decodes; reject if any decoded instruction's mnemonic is in
/// the built-in filter list (ARM64 `brk|smc|hvc`) or matches a user
/// `--filter` suffix. NO branch-in-middle rejection — that exists only in
/// `__passCleanX86` (gadgets.py:43-53).
///
/// Note: ROPgadget anchors the user `--filter` regex at both ends
/// (`re.match("(…)$")`, i.e. full-mnemonic equality); like the x86 engine we
/// apply the documented Phase-0 suffix matcher instead (see ScanOptions).
pub fn pass_clean(
    cs: &Capstone,
    decodes: &[WinInsn],
    builtin: &[&str],
    filter_suffixes: &[String],
) -> bool {
    if decodes.is_empty() {
        return true;
    }
    if builtin.is_empty() && filter_suffixes.is_empty() {
        return false;
    }
    for d in decodes {
        let Some(m) = cs.insn_name(capstone::InsnId(d.id)) else {
            continue;
        };
        if builtin.contains(&m.as_str()) {
            return true;
        }
        if filter_suffixes
            .iter()
            .any(|s| !s.is_empty() && m.ends_with(s.as_str()))
        {
            return true;
        }
    }
    false
}

/// Scan one anchor over one buffer, appending accepted gadgets in traversal
/// order (anchor-hit offset order → depth order, shortest first).
///
/// Replicates `__gadgetsFinding`'s stepping exactly (gadgets.py:69-114):
/// per hit, `end = ref + gad_size`; per depth `i`, the aligned start
/// `ref - i*gad_align` is used when it is in bounds and aligned in virtual
/// address space; otherwise the byte-stepped `ref - i` is used when in
/// bounds and aligned; otherwise the candidate is skipped.
#[allow(clippy::too_many_arguments)]
pub fn scan_anchor(
    cs: &Capstone,
    spec: &CsSpec,
    code: &[u8],
    sec_vaddr: u64,
    anchor: &Anchor,
    opts: &ScanOptions,
    delay_slot: bool,
    out: &mut Vec<Gadget>,
) {
    let align = opts.align.unwrap_or_else(|| anchor.align());
    // Max decode window: from the deepest candidate start to the gadget end.
    let window = opts.depth.saturating_sub(1) * align.max(1) + anchor.size();
    // Per-start decode cache (memoization only — does not affect output).
    let mut cache: HashMap<usize, Rc<Vec<WinInsn>>> = HashMap::new();

    for ref_pos in anchors::find_matches(code, anchor) {
        let end = ref_pos + anchor.size();
        if end > code.len() {
            continue; // gadgets.py:71
        }
        for i in 0..opts.depth {
            let stepped = i * align;
            // Aligned path (gadgets.py:75-81).
            let aligned_ok = align != 0 && ref_pos >= stepped && {
                let s = ref_pos - stepped;
                s < code.len() && (sec_vaddr.wrapping_add(s as u64)) % align as u64 == 0
            };
            let start = if aligned_ok {
                ref_pos - stepped
            } else {
                // Byte-by-byte fallback (gadgets.py:82-89).
                if ref_pos < i {
                    continue;
                }
                let s = ref_pos - i;
                if s >= code.len() {
                    continue;
                }
                if align != 0 && (sec_vaddr.wrapping_add(s as u64)) % align as u64 != 0 {
                    continue;
                }
                s
            };
            let insns = cache
                .entry(start)
                .or_insert_with(|| {
                    Rc::new(decode_window(cs, code, start, sec_vaddr, start + window))
                })
                .clone();
            // Clean-decode rule ⇔ an instruction boundary lands exactly on
            // `end` (see module docs).
            let n = insns.partition_point(|r| r.end < end);
            if n >= insns.len() || insns[n].end != end {
                continue;
            }
            let decodes = &insns[..=n];
            if spec.is_riscv && decodes[decodes.len() - 1].size != anchor.size() {
                continue; // gadgets.py:109-112
            }
            if pass_clean(cs, decodes, spec.builtin_filter, &opts.filter) {
                continue;
            }
            out.push(Gadget {
                vaddr: opts
                    .offset
                    .wrapping_add(sec_vaddr)
                    .wrapping_add(start as u64),
                bytes: code[start..end].to_vec(),
                insns: format_gadget(cs, code, start, end, sec_vaddr),
                delay_slot,
                prev: opts
                    .call_preceded
                    .then(|| code[start.saturating_sub(9)..start].to_vec()),
            });
        }
    }
}

/// Scan a buffer for one arch (test helper and serial driver): all enabled
/// tables in ROP/JOP/SYS order, anchors in table order.
pub fn scan_buffer(
    spec: &CsSpec,
    code: &[u8],
    sec_vaddr: u64,
    tables: &[Vec<Anchor>],
    opts: &ScanOptions,
    delay_slot: bool,
    out: &mut Vec<Gadget>,
) -> Result<(), Error> {
    let cs = open(spec)?;
    for table in tables {
        for anchor in table {
            scan_anchor(&cs, spec, code, sec_vaddr, anchor, opts, delay_slot, out);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchors::{self, TableKind};

    fn opts() -> ScanOptions {
        ScanOptions::default()
    }

    fn tables_for(
        kind_enabled: (bool, bool, bool),
        arch: Arch,
        endian: Endianness,
        thumb: bool,
    ) -> Vec<Vec<Anchor>> {
        [
            kind_enabled
                .0
                .then(|| anchors::table(TableKind::Rop, arch, endian, thumb)),
            kind_enabled
                .1
                .then(|| anchors::table(TableKind::Jop, arch, endian, thumb)),
            kind_enabled
                .2
                .then(|| anchors::table(TableKind::Sys, arch, endian, thumb)),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    fn scan(
        code: &[u8],
        vaddr: u64,
        arch: Arch,
        endian: Endianness,
        thumb: bool,
        o: &ScanOptions,
    ) -> Vec<Gadget> {
        let spec = spec(arch, endian, thumb).unwrap();
        let delay_slot = matches!(
            arch,
            Arch::Mips32 | Arch::Mips64 | Arch::Sparc | Arch::Sparc64 | Arch::SparcV9
        );
        let tables = tables_for((o.rop, o.jop, o.sys), arch, endian, thumb);
        let mut out = Vec::new();
        scan_buffer(&spec, code, vaddr, &tables, o, delay_slot, &mut out).unwrap();
        out
    }

    fn texts(g: &[Gadget]) -> Vec<String> {
        g.iter().map(|x| x.text()).collect()
    }

    #[test]
    fn arm_bx_lr_gadgets() {
        // mov r0, r1 ; bx lr  (LE)
        let code = [0x01, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1];
        let g = scan(&code, 0x1000, Arch::Arm, Endianness::Little, false, &opts());
        let t = texts(&g);
        assert!(t.contains(&"bx lr".to_string()), "{t:?}");
        assert!(t.contains(&"mov r0, r1 ; bx lr".to_string()), "{t:?}");
        let bx = g.iter().find(|x| x.text() == "bx lr").unwrap();
        assert_eq!(bx.vaddr, 0x1004);
        assert!(!bx.delay_slot);
    }

    #[test]
    fn arm_alignment_uses_virtual_address() {
        // Alignment is checked in VIRTUAL address space (gadgets.py:78:
        // `(sec_vaddr + start) % gad_align == 0`). At the misaligned vaddr
        // 0x1001, buffer offsets 0/4 would produce gadgets at 0x1001/0x1005
        // if alignment were computed on offsets; with vaddr alignment every
        // emitted gadget address must be 4-aligned instead.
        let code = [0x01, 0x00, 0xa0, 0xe1, 0x1e, 0xff, 0x2f, 0xe1];
        for vaddr in [0x1001u64, 0x1002, 0x1003] {
            let g = scan(&code, vaddr, Arch::Arm, Endianness::Little, false, &opts());
            for x in &g {
                assert_eq!(
                    x.vaddr % 4,
                    0,
                    "gadget at {:#x} violates vaddr alignment (base {vaddr:#x}): {}",
                    x.vaddr,
                    x.text()
                );
            }
        }
        // Concretely: the svc anchor matching at buffer offset 3 IS aligned
        // when the base is 0x1001 (0x1001 + 3 == 0x1004).
        let g = scan(&code, 0x1001, Arch::Arm, Endianness::Little, false, &opts());
        assert!(
            g.iter()
                .any(|x| x.vaddr == 0x1004 && x.text().starts_with("svc")),
            "{:?}",
            texts(&g)
        );
        // And at an aligned base the bx lr gadget appears (anchor hit 4).
        let g = scan(&code, 0x1000, Arch::Arm, Endianness::Little, false, &opts());
        assert!(g.iter().any(|x| x.vaddr == 0x1004 && x.text() == "bx lr"));
    }

    #[test]
    fn arm_clean_decode_rejects_invalid_prefix() {
        // 0xffffffff does not decode in ARM mode; the candidate spanning it
        // must be rejected while the aligned bx lr gadget survives.
        let code = [0xff, 0xff, 0xff, 0xff, 0x1e, 0xff, 0x2f, 0xe1];
        let g = scan(&code, 0x1000, Arch::Arm, Endianness::Little, false, &opts());
        let t = texts(&g);
        assert!(t.contains(&"bx lr".to_string()), "{t:?}");
        assert!(
            g.iter()
                .all(|x| x.bytes.len() <= 4 || !x.bytes.starts_with(&[0xff; 4])),
            "{t:?}"
        );
    }

    #[test]
    fn thumb_pop_pc_and_svc() {
        // pop {pc} ; bx lr ; svc #0 (Thumb, LE). Thumb mode comes only from
        // the thumb flag — an ArmThumb arch tag alone must not enable it
        // (ROPgadget scans ARMv7/Thumb2 PEs in ARM mode without --thumb).
        let code = [0x00, 0xbd, 0x70, 0x47, 0x00, 0xdf];
        let g = scan(
            &code,
            0x2000,
            Arch::ArmThumb,
            Endianness::Little,
            true,
            &opts(),
        );
        let t = texts(&g);
        assert!(t.contains(&"pop {pc}".to_string()), "{t:?}");
        assert!(t.contains(&"bx lr".to_string()), "{t:?}");
        assert!(t.iter().any(|x| x.starts_with("svc")), "{t:?}");
        // Same bytes, thumb=false → ARM mode: no thumb gadgets.
        let g = scan(
            &code,
            0x2000,
            Arch::ArmThumb,
            Endianness::Little,
            false,
            &opts(),
        );
        assert!(texts(&g).iter().all(|x| x != "pop {pc}"));
    }

    #[test]
    fn arm64_ret_and_brk_filter() {
        // mov x0, x1 ; ret ; brk #0 ; ret
        let code = [
            0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6, 0x00, 0x00, 0x20, 0xd4, 0xc0, 0x03,
            0x5f, 0xd6,
        ];
        let g = scan(
            &code,
            0x4000,
            Arch::Arm64,
            Endianness::Little,
            false,
            &opts(),
        );
        let t = texts(&g);
        assert!(t.contains(&"ret".to_string()), "{t:?}");
        assert!(t.contains(&"mov x0, x1 ; ret".to_string()), "{t:?}");
        // brk|smc|hvc built-in filter (gadgets.py:34-35): no gadget may
        // contain a brk instruction.
        assert!(t.iter().all(|x| !x.contains("brk")), "{t:?}");
    }

    #[test]
    fn arm64_jop_br_blr() {
        // br x8  = 0xd61f0100 (LE: 00 01 1f d6); blr x9 = 0xd63f0120 (LE: 20 01 3f d6)
        let code = [0x00, 0x01, 0x1f, 0xd6, 0x20, 0x01, 0x3f, 0xd6];
        let mut o = opts();
        o.rop = false;
        o.sys = false;
        let g = scan(&code, 0x8000, Arch::Arm64, Endianness::Little, false, &o);
        let t = texts(&g);
        assert!(t.contains(&"br x8".to_string()), "{t:?}");
        assert!(t.contains(&"blr x9".to_string()), "{t:?}");
    }

    #[test]
    fn mips_be_jr_ra_with_delay_slot() {
        // jr $ra ; nop  (BE) — anchor size 8 includes the delay slot.
        let code = [0x03, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
        let g = scan(
            &code,
            0x400000,
            Arch::Mips32,
            Endianness::Big,
            false,
            &opts(),
        );
        let t = texts(&g);
        assert!(t.contains(&"jr $ra ; nop".to_string()), "{t:?}");
        let jr = g.iter().find(|x| x.text() == "jr $ra ; nop").unwrap();
        assert!(jr.delay_slot, "MIPS gadgets must carry delay_slot=true");
        assert_eq!(jr.bytes, code);
    }

    #[test]
    fn mips_be_clean_decode_rejects_invalid_prefix() {
        // 0xffffffff does not decode in MIPS32; nop ; jr $ra ; nop survives.
        let code = [
            0xff, 0xff, 0xff, 0xff, 0x03, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
        ];
        let g = scan(
            &code,
            0x400000,
            Arch::Mips32,
            Endianness::Big,
            false,
            &opts(),
        );
        let t = texts(&g);
        assert!(t.contains(&"jr $ra ; nop".to_string()), "{t:?}");
        assert!(
            g.iter().all(|x| !x.bytes.starts_with(&[0xff; 4])),
            "candidate spanning the invalid word must be rejected: {t:?}"
        );
    }

    #[test]
    fn mips_be_syscall_sys_table() {
        // syscall (0x0000000c BE) with a nop delay slot for the 4-byte align.
        let code = [0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00];
        let mut o = opts();
        o.rop = false;
        o.jop = false;
        let g = scan(&code, 0x400000, Arch::Mips32, Endianness::Big, false, &o);
        let t = texts(&g);
        assert!(t.contains(&"syscall".to_string()), "{t:?}");
    }

    #[test]
    fn riscv_c_ret_anchor() {
        // c.jr ra (capstone 5 spelling of 0x8082) alone.
        let code = [0x82, 0x80];
        let g = scan(
            &code,
            0x1000,
            Arch::RiscV64,
            Endianness::Little,
            false,
            &opts(),
        );
        let t = texts(&g);
        assert!(t.contains(&"c.jr ra".to_string()), "{t:?}");
    }

    #[test]
    fn riscv_last_insn_size_rule() {
        // gadgets.py:109-112: bytes 67 80 82 80 decode from 0 as ONE 4-byte
        // instruction (jalr); the c.ret anchor at offset 2 (gad_size 2) with
        // depth i=2 would otherwise accept the 4-byte span starting at 0.
        let code = [0x67, 0x80, 0x82, 0x80];
        let mut o = opts();
        o.jop = false; // keep the JOP jalr anchor out of the way
        o.sys = false;
        let g = scan(&code, 0x1000, Arch::RiscV64, Endianness::Little, false, &o);
        let t = texts(&g);
        assert!(t.contains(&"c.jr ra".to_string()), "{t:?}");
        let cret = g.iter().find(|x| x.text() == "c.jr ra").unwrap();
        assert_eq!(cret.vaddr, 0x1002);
        // The 4-byte candidate ending at the c.ret anchor is rejected.
        assert!(
            g.iter().all(|x| x.bytes != code),
            "4-byte-last candidate must be rejected by the size rule: {t:?}"
        );
    }

    #[test]
    fn riscv_jop_jalr() {
        // jalr zero, t0, -0x7f8 (67 80 82 80) — JOP anchor [67 6f e7 ef].
        let code = [0x67, 0x80, 0x82, 0x80];
        let mut o = opts();
        o.rop = false;
        o.sys = false;
        let g = scan(&code, 0x1000, Arch::RiscV64, Endianness::Little, false, &o);
        let t = texts(&g);
        assert!(
            t.iter().any(|x| x.starts_with("jalr")),
            "expected jalr gadget, got {t:?}"
        );
    }

    #[test]
    fn ppc_be_blr() {
        let code = [0x4e, 0x80, 0x00, 0x20];
        let g = scan(&code, 0x10000, Arch::Ppc32, Endianness::Big, false, &opts());
        let t = texts(&g);
        assert!(t.contains(&"blr".to_string()), "{t:?}");
    }

    #[test]
    fn sparc_be_retl_with_delay_slot() {
        // retl ; nop (BE). The SPARC anchor size is 4 (gadgets.py:165-177),
        // so — unlike MIPS — the delay-slot nop is NOT part of the gadget;
        // the delay_slot flag records that the executed path includes it.
        let code = [0x81, 0xc3, 0xe0, 0x08, 0x01, 0x00, 0x00, 0x00];
        let g = scan(&code, 0x10000, Arch::Sparc, Endianness::Big, false, &opts());
        let t = texts(&g);
        assert!(t.contains(&"retl".to_string()), "{t:?}");
        let retl = g.iter().find(|x| x.text() == "retl").unwrap();
        assert_eq!(retl.bytes, [0x81, 0xc3, 0xe0, 0x08]);
        assert!(retl.delay_slot, "SPARC gadgets must carry delay_slot=true");
    }

    #[test]
    fn depth_and_alignment_stepping() {
        // ARM: 3 nops + bx lr. With depth 2 the aligned path steps by 4, so
        // only "bx lr" and "nop ; bx lr" appear (movs at 0 requires i=2).
        let mut code = vec![];
        code.extend_from_slice(&[0x00, 0x00, 0xa0, 0xe1]); // mov r0, r0
        code.extend_from_slice(&[0x00, 0x00, 0xa0, 0xe1]);
        code.extend_from_slice(&[0x00, 0x00, 0xa0, 0xe1]);
        code.extend_from_slice(&[0x1e, 0xff, 0x2f, 0xe1]); // bx lr
        let mut o = opts();
        o.depth = 2;
        let g = scan(&code, 0x1000, Arch::Arm, Endianness::Little, false, &o);
        let t = texts(&g);
        assert!(t.contains(&"bx lr".to_string()), "{t:?}");
        assert!(t.contains(&"mov r0, r0 ; bx lr".to_string()), "{t:?}");
        assert!(
            !t.contains(&"mov r0, r0 ; mov r0, r0 ; mov r0, r0 ; bx lr".to_string()),
            "{t:?}"
        );
    }
}
