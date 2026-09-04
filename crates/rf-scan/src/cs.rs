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
//! capstone-rs `Capstone` is `!Send`/`!Sync`, so a handle is built per rayon
//! worker (`map_init`) rather than per work item, and the region-index
//! builder makes one per slot chunk.

use capstone::{Arch as CsArch, Capstone, Endian as CsEndian, ExtraMode, Mode};
use rayon::prelude::*;
use regex::Regex;

use rf_core::{Arch, Endianness, Error};

use crate::anchors::{Anchor, TableKind};
use crate::engine::{
    step_back, Gadget, ScanCtx, CANCEL_CHECK_CANDIDATES, CANCEL_CHECK_HITS, PREV_BYTES,
};

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
///  - RISCV: ROPgadget hardcodes `CS_MODE_RISCV64 | CS_MODE_RISCVC` even
///    for RV32 (gadgets.py:202, 392, 479). We select RV32 for an ELFCLASS32
///    RISC-V image instead (ANCH-04): RV64-only text (`sd`, `ld`, `addiw`,
///    `c.ldsp`, the `x`-register widths) does not exist on RV32, so the
///    oracle's mode prints instructions the target cannot execute. This is
///    a deliberate, recorded divergence — see tests/known-divergences.json.
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
        Arch::RiscV32 => (CsArch::RISCV, Mode::RiscV32, true),
        Arch::RiscV64 => (CsArch::RISCV, Mode::RiscV64, true),
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

/// Construct a capstone handle for `spec`, **without** detail mode.
///
/// The scan path wants exactly this: it decodes one window per candidate and
/// keeps only instruction boundaries, ids and text, so paying for `cs_detail`
/// on every candidate would be pure overhead. Measured over the scanner's own
/// [`decode_window`] loop across each fixture's largest executable region,
/// detail mode costs 1.09x-1.17x the decode time (PPC32 1.10x, MIPS32 1.17x,
/// ARM64 1.09x), which is +14% to +27% on top of a full depth-10 scan.
/// Semantics are decoded on demand from the accepted gadget's bytes instead —
/// see [`crate::detail`], which pays that cost per *classified gadget* rather
/// than per *candidate considered*.
pub fn open(spec: &CsSpec) -> Result<Capstone, Error> {
    open_detail(spec, false)
}

/// Construct a capstone handle for `spec`, optionally with detail mode
/// (`cs_option(CS_OPT_DETAIL, CS_OPT_ON)`) enabled.
///
/// Detail mode populates `regs_read`/`regs_write`, instruction groups and
/// per-architecture operands — the metadata `rf-classify` needs on the eight
/// architectures that do not go through iced-x86 (ECO-05). It does not change
/// the disassembly TEXT capstone produces, which is what the parity gate
/// compares; [`crate::detail::Detailer::decode_checked`] asserts that
/// invariant per gadget at runtime and `detail_mode_does_not_change_text`
/// asserts it over the fixture corpus.
pub fn open_detail(spec: &CsSpec, detail: bool) -> Result<Capstone, Error> {
    let extra: Vec<ExtraMode> = if spec.riscv_compressed {
        vec![ExtraMode::RiscVC]
    } else {
        Vec::new()
    };
    let mut cs =
        Capstone::new_raw(spec.arch, spec.mode, extra.into_iter(), spec.endian).map_err(|e| {
            Error::Unsupported(format!(
                "capstone cannot open {:?}/{:?}: {e}",
                spec.arch, spec.mode
            ))
        })?;
    if detail {
        cs.set_detail(true).map_err(|e| {
            Error::Unsupported(format!(
                "capstone cannot enable detail mode for {:?}/{:?}: {e}",
                spec.arch, spec.mode
            ))
        })?;
    }
    Ok(cs)
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
    insns.iter().map(insn_text).collect()
}

/// One instruction's ROPgadget-format text (`gadgets.py:118-119`).
pub fn insn_text(i: &capstone::Insn) -> String {
    let m = i.mnemonic().unwrap_or("");
    let o = i.op_str().unwrap_or("");
    squash_double_spaces(if o.is_empty() {
        m.to_string()
    } else {
        format!("{m} {o}")
    })
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
/// SCAN-01/CLI-02: ROPgadget anchors the `--filter` regex at both ends
/// (`re.match("({})$")`), i.e. a FULL match against the mnemonic — never a
/// suffix test. `builtin` (ARM64's `brk|smc|hvc`) is the other half of that
/// same alternation and stays an exact-equality check so the common
/// no-filter path allocates nothing extra.
pub fn pass_clean(
    cs: &Capstone,
    decodes: &[WinInsn],
    builtin: &[&str],
    filter: Option<&Regex>,
) -> bool {
    if decodes.is_empty() {
        return true;
    }
    if builtin.is_empty() && filter.is_none() {
        return false;
    }
    for d in decodes {
        let Some(m) = cs.insn_name(capstone::InsnId(d.id)) else {
            continue;
        };
        if builtin.contains(&m.as_str()) {
            return true;
        }
        if filter.is_some_and(|re| re.is_match(&m)) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// PERF-09: one resumable decode per region, instead of one per (hit, depth)
// ---------------------------------------------------------------------------

/// Instruction width in bytes for the ISAs whose instruction boundaries do
/// NOT depend on where the decode started, or `None` when the mode is
/// variable-length.
///
/// This is the precondition for [`RegionIndex`]: on A64, A32, MIPS, PowerPC
/// and SPARC every instruction is exactly 4 bytes, so the boundary set of a
/// decode is a property of the region and the alignment phase alone, and a
/// single pass over the region answers every candidate. Thumb (2 or 4) and
/// RISC-V with the C extension (2 or 4) are excluded: there the boundaries
/// really do move with the start, and each candidate has to be decoded.
pub fn fixed_width(spec: &CsSpec) -> Option<usize> {
    match spec.arch {
        CsArch::ARM64 => Some(4),
        CsArch::ARM => (spec.mode == Mode::Arm).then_some(4),
        CsArch::MIPS => matches!(spec.mode, Mode::Mips32 | Mode::Mips64).then_some(4),
        CsArch::PPC => matches!(spec.mode, Mode::Mode32 | Mode::Mode64).then_some(4),
        CsArch::SPARC => matches!(spec.mode, Mode::Default | Mode::V9).then_some(4),
        _ => None,
    }
}

/// Slots decoded per capstone call while building an index. Bounds the peak
/// memory of the C-side instruction array (capstone materialises the whole
/// run it decodes) without materially changing the per-call amortisation:
/// 4096 slots is 16 KB of code and one `cs_disasm` per 4096 instructions,
/// against one per candidate before.
const INDEX_CHUNK_SLOTS: usize = 4096;

/// Build the index only when the region is probed at least this densely —
/// `candidate starts >= region slots / INDEX_DENSITY`. A whole-region decode
/// costs one instruction per slot whether or not anything looks at it, so on
/// a large region with almost no anchor hits (a 100 MB blob with one `ret`)
/// decoding per candidate is genuinely cheaper. Every fixture in the corpus
/// is far above this line; the constant exists to stop a pathological input
/// from paying for an index it never reads.
const INDEX_DENSITY: usize = 32;

/// A start-independent decode of one region, for a fixed-width ISA.
///
/// PERF-09 — `cs::scan_anchor` used to call `cs_disasm` once per (anchor hit,
/// depth index): 47,030 C calls on `elf-ARM64-bash` and 973,944 on
/// `elf-Mips-Defcon-20-pwn100`, each with its own allocation, each redoing
/// work the previous call had already done, and each followed by a
/// `cs.insn_name()` per instruction that returns an owned `String`. Because
/// the boundaries are start-independent here, one resumable pass over the
/// region answers all of them.
///
/// What is stored is not the instruction list but the only question the scan
/// ever asks of it: **how many consecutive slots from here are acceptable**,
/// where acceptable means "decodes" AND "is not rejected by `passClean`'s
/// mnemonic filter". A candidate `[start, end)` is then accepted iff
/// `run[slot(start)] >= (end - start) / width` — one load and one compare,
/// with no decode and no string.
///
/// Resumable is the operative word: `cs_disasm` stops at the first
/// undecodable instruction, so the builder marks that slot unacceptable and
/// restarts one slot later, which is what makes a single pass equivalent to
/// the per-candidate decodes it replaces.
pub struct RegionIndex {
    /// Instruction width; every slot is this many bytes.
    width: usize,
    /// Byte offset of slot 0: the first offset whose VIRTUAL address is
    /// `width`-aligned, which is the only phase `step_back` can produce when
    /// the anchor's align is a multiple of the width.
    base: usize,
    /// Run lengths are saturated here; no candidate can span more slots.
    cap: u32,
    run: Vec<u32>,
}

impl RegionIndex {
    /// `Some(true)`/`Some(false)`: the candidate is accepted/rejected.
    /// `None`: this candidate is outside the index's alignment phase or
    /// longer than its saturation cap — decode it instead.
    pub fn decide(&self, start: usize, end: usize) -> Option<bool> {
        if start < self.base || (start - self.base) % self.width != 0 {
            return None; // a phase this index does not cover
        }
        if end <= start {
            return Some(false);
        }
        let span = end - start;
        if span % self.width != 0 {
            // From a width-aligned start every boundary is width-aligned, so
            // no instruction can end exactly on `end`: the clean-decode rule
            // fails without decoding anything.
            return Some(false);
        }
        let need = span / self.width;
        if need > self.cap as usize {
            return None;
        }
        let k = (start - self.base) / self.width;
        match self.run.get(k) {
            None => Some(false),
            Some(&r) => Some(r as usize >= need),
        }
    }

    /// Slots in the index (test/diagnostic accessor).
    pub fn len(&self) -> usize {
        self.run.len()
    }

    pub fn is_empty(&self) -> bool {
        self.run.is_empty()
    }
}

/// Decide whether each region gets an index, and build the ones that do.
pub(crate) fn build_indexes(
    spec: &CsSpec,
    regions: &[crate::engine::Region<'_>],
    lists: &[crate::engine::AnchorHits<'_>],
    ctx: &ScanCtx<'_>,
    max_span: usize,
) -> Vec<Option<RegionIndex>> {
    let parallel = ctx.opts.parallel;
    let Some(width) = fixed_width(spec) else {
        return regions.iter().map(|_| None).collect();
    };
    let build = |(i, r): (usize, &crate::engine::Region<'_>)| -> Option<RegionIndex> {
        let code: &[u8] = &r.code;
        let base = ((width - (r.vaddr % width as u64) as usize) % width).min(code.len());
        let slots = code.len().saturating_sub(base) / width;
        if slots == 0 {
            return None;
        }
        // Which slots will anyone actually ask about? A whole-region decode
        // is the wrong shape for a large region with a handful of anchor
        // hits — 854 KB of SPARC `.text` for 8,960 raw gadgets is the corpus
        // case, and a 100 MB firmware image is the real one. Marking the
        // slots each hit can reach turns "decode the region" into "decode
        // the parts of it the scan reads", which is never more work than the
        // per-candidate decodes it replaces: each covered slot is decoded
        // once instead of once per candidate that spans it.
        let mut needed = vec![false; slots];
        let mut covered = 0usize;
        for l in lists.iter().filter(|l| l.region == i) {
            if ctx.opts.cancel.is_cancelled() {
                return None;
            }
            let span = ctx.opts.depth.saturating_sub(1) * ctx.opts.effective_align(l.anchor).max(1);
            for h in l.hits.iter().copied() {
                let end = h + l.anchor.size();
                if end > code.len() {
                    continue;
                }
                let lo = h.saturating_sub(span).max(base);
                let lo_slot = (lo - base) / width;
                let hi_slot = ((end - base).div_ceil(width)).min(slots);
                for slot in needed.iter_mut().take(hi_slot).skip(lo_slot) {
                    if !*slot {
                        *slot = true;
                        covered += 1;
                    }
                }
            }
        }
        if covered == 0 {
            return None;
        }
        // Memory backstop, not a time one: `run` costs 4 bytes per slot of
        // the WHOLE region even when the covered part is a sliver, so a
        // region that is almost entirely unreachable keeps the per-candidate
        // path rather than allocating an index it barely reads.
        if covered.saturating_mul(INDEX_DENSITY) < slots {
            return None;
        }
        let cap = u32::try_from(max_span / width + 1).ok()?;
        build_index(
            spec, code, r.vaddr, width, base, &needed, cap, ctx, parallel,
        )
    };
    // The index build IS the region decode, so it must not become the serial
    // prologue that caps the scan's scaling (Amdahl: on the MIPS fixture it
    // is a large fraction of the remaining work). Regions are walked in order
    // — there are one or two of them — and the parallelism is inside, across
    // the slot chunks of a single region.
    regions.iter().enumerate().map(build).collect()
}

/// Decode `code` once and record, per slot, how many consecutive slots from
/// there are acceptable.
#[allow(clippy::too_many_arguments)]
fn build_index(
    spec: &CsSpec,
    code: &[u8],
    vaddr: u64,
    width: usize,
    base: usize,
    needed: &[bool],
    cap: u32,
    ctx: &ScanCtx<'_>,
    parallel: bool,
) -> Option<RegionIndex> {
    use std::sync::atomic::{AtomicBool, Ordering};

    let filter = ctx.filter.as_ref();
    let slots = needed.len();
    // Set if capstone ever returns an instruction that is not `width` bytes.
    // That would falsify the start-independence this whole structure rests
    // on, so the index is discarded and every candidate is decoded instead.
    let mismatch = AtomicBool::new(false);
    let mut ok: Vec<bool> = vec![false; slots];
    let filtering = !spec.builtin_filter.is_empty() || filter.is_some();

    let fill = |cs: &mut Option<Capstone>, ((ci, out), want): ((usize, &mut [bool]), &[bool])| {
        let Some(cs) = cs.as_ref() else {
            mismatch.store(true, Ordering::Relaxed);
            return;
        };
        // The region decode is the one phase with no per-candidate loop to
        // hang a cancellation check on, and on a big MIPS image it is long
        // enough to dominate the observed cancel latency. One relaxed load
        // per 16 KB chunk fixes that; a cancelled build is discarded whole.
        if ctx.opts.cancel.is_cancelled() {
            mismatch.store(true, Ordering::Relaxed);
            return;
        }
        // Per-chunk mnemonic verdict memo: `insn_name` returns an owned
        // String, and there are a few hundred distinct ids against thousands
        // of instructions. 0 = unknown, 1 = acceptable, 2 = filtered out.
        let mut verdict: Vec<u8> = Vec::new();
        let chunk_base = base + ci * INDEX_CHUNK_SLOTS * width;
        let mut slot = 0usize;
        while slot < want.len() {
            if !want[slot] {
                slot += 1;
                continue;
            }
            // One decode per maximal covered run, resumed past every word
            // capstone cannot decode.
            let run_end = want[slot..]
                .iter()
                .position(|w| !w)
                .map_or(want.len(), |n| slot + n);
            let lo = chunk_base + slot * width;
            let hi = chunk_base + run_end * width;
            let mut off = lo;
            while off < hi {
                let insns = match cs.disasm_all(&code[off..hi], vaddr.wrapping_add(off as u64)) {
                    Ok(i) => i,
                    Err(_) => {
                        off += width;
                        continue;
                    }
                };
                let mut consumed = 0usize;
                for insn in insns.iter() {
                    if insn.len() != width {
                        mismatch.store(true, Ordering::Relaxed);
                        return;
                    }
                    let acceptable = if !filtering {
                        true
                    } else {
                        let id = insn.id().0 as usize;
                        if verdict.len() <= id {
                            verdict.resize(id + 1, 0);
                        }
                        if verdict[id] == 0 {
                            let rejected = match cs.insn_name(insn.id()) {
                                Some(m) => {
                                    spec.builtin_filter.contains(&m.as_str())
                                        || filter.is_some_and(|re| re.is_match(&m))
                                }
                                None => false,
                            };
                            verdict[id] = if rejected { 2 } else { 1 };
                        }
                        verdict[id] == 1
                    };
                    out[(off + consumed - chunk_base) / width] = acceptable;
                    consumed += width;
                }
                // `ok` starts false, so the slot `cs_disasm` stopped on is
                // already marked unacceptable; RESUME one slot past it —
                // that is what makes one pass equal to the per-candidate
                // decodes it replaces.
                off += consumed + if consumed < hi - off { width } else { 0 };
            }
            slot = run_end;
        }
    };

    if parallel && slots > INDEX_CHUNK_SLOTS {
        ok.par_chunks_mut(INDEX_CHUNK_SLOTS)
            .enumerate()
            .zip(needed.par_chunks(INDEX_CHUNK_SLOTS))
            .for_each_init(|| open(spec).ok(), fill);
    } else {
        let mut handle = open(spec).ok();
        for ((ci, chunk), want) in ok
            .chunks_mut(INDEX_CHUNK_SLOTS)
            .enumerate()
            .zip(needed.chunks(INDEX_CHUNK_SLOTS))
        {
            fill(&mut handle, ((ci, chunk), want));
        }
    }
    if mismatch.load(Ordering::Relaxed) {
        return None;
    }

    // Backward pass: run[k] = min(cap, ok[k] ? 1 + run[k+1] : 0). Slots
    // outside the covered set are `ok == false`, which is correct rather
    // than merely safe: no candidate's byte range can leave the coverage of
    // the hit that produced it, so a run is never truncated by a slot
    // someone was going to ask about.
    let mut run = vec![0u32; slots];
    let mut acc = 0u32;
    for k in (0..slots).rev() {
        acc = if ok[k] { (acc + 1).min(cap) } else { 0 };
        run[k] = acc;
    }
    Some(RegionIndex {
        width,
        base,
        cap,
        run,
    })
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
pub(crate) fn scan_hits(
    cs: &Capstone,
    spec: &CsSpec,
    code: &[u8],
    sec_vaddr: u64,
    anchor: &Anchor,
    kind: TableKind,
    hit_list: &[usize],
    index: Option<&RegionIndex>,
    ctx: &ScanCtx<'_>,
    delay_slot: bool,
    out: &mut Vec<Gadget>,
) {
    let opts = ctx.opts;
    let align = opts.effective_align(anchor);
    let mut hits = 0usize;
    let mut candidates = 0usize;
    let mut item_bytes = 0usize;

    for &ref_pos in hit_list {
        hits += 1;
        if hits % CANCEL_CHECK_HITS == 0 && opts.cancel.is_cancelled() {
            return;
        }
        let end = ref_pos + anchor.size();
        if end > code.len() {
            continue; // gadgets.py:71
        }
        for i in 0..opts.depth {
            candidates += 1;
            if candidates % CANCEL_CHECK_CANDIDATES == 0 {
                if opts.cancel.is_cancelled() {
                    return;
                }
                if let Some(cap) = ctx.item_cap {
                    if out.len() >= cap {
                        return;
                    }
                }
            }
            // gadgets.py:73-89, shared with the x86 path.
            let Some(start) = step_back(ref_pos, i, align, sec_vaddr, code.len()) else {
                continue;
            };
            // PERF-09: on a fixed-width ISA the whole candidate test — the
            // clean-decode rule AND `passClean` — is one array lookup in the
            // region index. `decide` returns `None` only for a candidate the
            // index cannot express (a start off the index's alignment phase,
            // reachable via `--align 1`), which falls through to the decode.
            match index.and_then(|ix| ix.decide(start, end)) {
                Some(false) => continue,
                Some(true) => {}
                None => {
                    let insns = decode_window(cs, code, start, sec_vaddr, end);
                    // Clean-decode rule ⇔ an instruction boundary lands
                    // exactly on `end` (see module docs).
                    let n = insns.partition_point(|r| r.end < end);
                    if n >= insns.len() || insns[n].end != end {
                        continue;
                    }
                    let decodes = &insns[..=n];
                    if spec.is_riscv && decodes[decodes.len() - 1].size != anchor.size() {
                        continue; // gadgets.py:109-112
                    }
                    if pass_clean(cs, decodes, spec.builtin_filter, ctx.filter.as_ref()) {
                        continue;
                    }
                }
            }
            let g = Gadget {
                vaddr: opts
                    .offset
                    .wrapping_add(sec_vaddr)
                    .wrapping_add(start as u64),
                bytes: code[start..end].to_vec(),
                insns: format_gadget(cs, code, start, end, sec_vaddr),
                delay_slot,
                prev: opts
                    .call_preceded
                    .then(|| code[start.saturating_sub(PREV_BYTES)..start].to_vec()),
                table: kind,
            };
            if let Some(cap) = ctx.item_byte_cap {
                item_bytes += crate::sink::gadget_bytes(&g);
                if item_bytes > cap {
                    out.push(g);
                    return;
                }
            }
            out.push(g);
        }
    }
}

/// Scan a buffer for one arch (test helper and serial driver): all enabled
/// tables in ROP/JOP/SYS order, anchors in table order.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_buffer(
    spec: &CsSpec,
    code: &[u8],
    sec_vaddr: u64,
    tables: &[(TableKind, Vec<Anchor>)],
    opts: &crate::engine::ScanOptions,
    delay_slot: bool,
    use_index: bool,
    out: &mut Vec<Gadget>,
) -> Result<(), Error> {
    let cs = open(spec)?;
    let ctx = ScanCtx {
        opts,
        filter: opts.compiled_filter().map_err(rf_core::Error::from)?,
        item_cap: opts.max_gadgets,
        item_byte_cap: opts.max_memory,
    };
    // `index = None` forces the per-candidate decode path; the paired test
    // `region_index_agrees_with_per_candidate_decode` runs the same buffer
    // both ways and asserts the two agree gadget for gadget.
    let index = if use_index {
        match fixed_width(spec) {
            None => None,
            Some(width) => {
                let base = ((width - (sec_vaddr % width as u64) as usize) % width).min(code.len());
                let slots = code.len().saturating_sub(base) / width;
                let span = tables
                    .iter()
                    .flat_map(|(_, t)| t.iter())
                    .map(|a| {
                        opts.depth.saturating_sub(1) * opts.effective_align(a).max(1) + a.size()
                    })
                    .max()
                    .unwrap_or(0);
                // Whole buffer covered: the point of the test helper is to
                // exercise the index everywhere, not to reproduce the
                // coverage heuristic.
                build_index(
                    spec,
                    code,
                    sec_vaddr,
                    width,
                    base,
                    &vec![true; slots],
                    (span / width + 1) as u32,
                    &ctx,
                    false,
                )
            }
        }
    } else {
        None
    };
    for (kind, table) in tables {
        for anchor in table {
            let hits = crate::anchors::find_matches(code, anchor);
            scan_hits(
                &cs,
                spec,
                code,
                sec_vaddr,
                anchor,
                *kind,
                &hits,
                index.as_ref(),
                &ctx,
                delay_slot,
                out,
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchors;
    use crate::engine::ScanOptions;

    fn opts() -> ScanOptions {
        ScanOptions::default()
    }

    fn tables_for(
        kind_enabled: (bool, bool, bool),
        arch: Arch,
        endian: Endianness,
        thumb: bool,
    ) -> Vec<(TableKind, Vec<Anchor>)> {
        [
            kind_enabled.0.then(|| {
                (
                    TableKind::Rop,
                    anchors::table(TableKind::Rop, arch, endian, thumb),
                )
            }),
            kind_enabled.1.then(|| {
                (
                    TableKind::Jop,
                    anchors::table(TableKind::Jop, arch, endian, thumb),
                )
            }),
            kind_enabled.2.then(|| {
                (
                    TableKind::Sys,
                    anchors::table(TableKind::Sys, arch, endian, thumb),
                )
            }),
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
        // PERF-09: every capstone unit test runs BOTH decision paths — the
        // per-candidate decode and the whole-region index — and asserts they
        // agree gadget for gadget. On a variable-width mode (Thumb, RISC-V C)
        // `fixed_width` is `None` and the two are the same path.
        let mut out = Vec::new();
        scan_buffer(&spec, code, vaddr, &tables, o, delay_slot, false, &mut out).unwrap();
        let mut indexed = Vec::new();
        scan_buffer(
            &spec,
            code,
            vaddr,
            &tables,
            o,
            delay_slot,
            true,
            &mut indexed,
        )
        .unwrap();
        assert_eq!(
            out.iter()
                .map(|g| (g.vaddr, g.bytes.clone(), g.text()))
                .collect::<Vec<_>>(),
            indexed
                .iter()
                .map(|g| (g.vaddr, g.bytes.clone(), g.text()))
                .collect::<Vec<_>>(),
            "region index disagrees with the per-candidate decode"
        );
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
