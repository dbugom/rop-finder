//! The scanning engine: anchor scan → per-start decode cache → clean-decode
//! validity → passClean → dedup → filters.
//!
//! Traversal order (deterministic, matching ROPgadget's pipeline):
//! **section order → table order (ROP, JOP, SYS within each section) →
//! anchor-table order → anchor-hit offset order → depth order**
//! (`i = 0..depth`, i.e. shortest gadget first).
//!
//! Output dedup is by gadget **text**, first-occurrence-wins in that order
//! (ropgadget/rgutils.py:9-18). Because our formatter is iced-x86 rather than
//! capstone, text — and therefore dedup survivor identity in rare ties — can
//! differ cosmetically; parity is judged on (vaddr, bytes) sets.
//!
//! Parallelism (Phase 1a): scanning is split into work items of
//! `(scan region, anchor)` in exactly the traversal order above. `rayon`
//! maps over the indexed work list and the per-item result vectors are
//! concatenated in index order, so the merged output — and therefore the
//! text-dedup survivor — is byte-identical to the serial run regardless of
//! thread scheduling. `ScanOptions::parallel = false` selects the serial
//! path (tests).

use std::collections::HashMap;
use std::collections::HashSet;
use std::rc::Rc;

use rayon::prelude::*;

use rf_core::{Arch, Error, Image};

use crate::anchors::{self, Anchor, TableKind};
use crate::cs;
use crate::x86::{self, WinInsn};

/// Scanner configuration.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// ROPgadget --depth: candidate starts are `anchor_pos - i` for
    /// `i in 0..depth` (shortest gadget first).
    pub depth: usize,
    pub rop: bool,
    pub jop: bool,
    pub sys: bool,
    /// ROPgadget --multibr: allow branch instructions in the middle of a
    /// gadget (ret-family still always rejected in the middle).
    pub multibr: bool,
    /// ROPgadget --only: keep gadgets whose every instruction mnemonic
    /// (first whitespace-separated token) is in this set.
    pub only: Option<Vec<String>>,
    /// ROPgadget --range: sections are truncated to `[start, end)` before
    /// scanning (as `core.py:_sectionInRange`).
    pub range: Option<(u64, u64)>,
    /// ROPgadget --badbytes: reject gadgets whose packed little-endian
    /// address (4 bytes for ELF32, 8 for ELF64, after --offset) contains any
    /// of these bytes.
    pub badbytes: Vec<u8>,
    /// ROPgadget --filter: reject gadgets containing an instruction whose
    /// mnemonic ends with any of these strings (Phase 0 suffix matcher).
    pub filter: Vec<String>,
    /// ROPgadget --offset: additive slide applied at emission; disassembly
    /// is unaffected.
    pub offset: u64,
    /// ROPgadget --thumb: disassemble ARM binaries in Thumb mode.
    /// This flag is the ONLY source of Thumb mode: `Arch::ArmThumb` (e.g. a
    /// PE built for ARMv7/Thumb2) does NOT imply it, because ROPgadget
    /// scans such binaries in ARM mode unless --thumb is given
    /// (gadgets.py:331, 448).
    pub thumb: bool,
    /// Phase 4b `--cfg-aware` (PLAN sec. 6.2 #6): keep only gadgets whose
    /// entry is an `endbr64`/`endbr32` instruction (CET/IBT-valid indirect
    /// branch targets). Applied unconditionally when set — goblin does not
    /// expose the load-config CET flag, so callers decide (the CLI warns
    /// when a PE's DLL characteristics advertise GUARD_CF and the flag is
    /// absent). x86/x64 only; a no-op for other architectures.
    pub cfg_aware: bool,
    /// ROPgadget --align: override every anchor's backward-stepping
    /// alignment (gadgets.py:66-67). `Some(0)` means "no alignment
    /// constraint" (oracle treats 0 as falsy → byte stepping without the
    /// alignment filter); None keeps the anchor table's own align.
    pub align: Option<usize>,
    /// ROPgadget --callPreceded: capture up to 9 section bytes preceding
    /// each gadget start into [`Gadget::prev`] (gadgets.py:57,120-124).
    /// The filter itself runs at the CLI boundary (options.py:100-120).
    pub call_preceded: bool,
    /// ROPgadget --all: skip duplicate-gadget removal
    /// (core.py:87-88); alphabetical sort still applies.
    pub all: bool,
    /// ROPgadget --noinstr: skip BOTH dedup and the alphabetical sort
    /// (core.py:87-95); the CLI prints bare addresses.
    pub noinstr: bool,
    /// Scan (region × anchor) work items with rayon. Output is identical
    /// either way; serial exists for tests and debugging.
    pub parallel: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            depth: 10,
            rop: true,
            jop: true,
            sys: true,
            multibr: false,
            only: None,
            range: None,
            badbytes: Vec::new(),
            filter: Vec::new(),
            offset: 0,
            thumb: false,
            cfg_aware: false,
            align: None,
            call_preceded: false,
            all: false,
            noinstr: false,
            parallel: true,
        }
    }
}

/// One gadget. Text is produced once at the output boundary.
#[derive(Debug, Clone)]
pub struct Gadget {
    pub vaddr: u64,
    pub bytes: Vec<u8>,
    /// Full formatted text per instruction (mnemonic + operands).
    pub insns: Vec<String>,
    /// True on delay-slot ISAs (MIPS, SPARC — PLAN.md §4): the instruction
    /// after the control transfer still executes before the jump takes
    /// effect, so classification/chains must not treat the text as the full
    /// executed path. (ROPgadget includes the delay slot in the gadget text
    /// for MIPS — anchor size 8 — but not for SPARC — anchor size 4.)
    pub delay_slot: bool,
    /// Up to 9 section bytes preceding the gadget start — captured only
    /// when `ScanOptions::call_preceded` is set (gadgets.py:120-124,
    /// PREV_BYTES=9). Note the oracle reads these with the --offset slide
    /// mixed in (a latent oracle bug with --offset --callPreceded); we
    /// always read the true preceding bytes.
    pub prev: Option<Vec<u8>>,
}

impl Gadget {
    /// ROPgadget-style " ; "-joined text (`gadgets.py:118-119`).
    pub fn text(&self) -> String {
        self.insns.join(" ; ")
    }

    pub fn bytes_hex(&self) -> String {
        let mut s = String::with_capacity(self.bytes.len() * 2);
        for b in &self.bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// Scan a loaded binary of any supported architecture. Dispatch: x86/x64 →
/// iced-x86 path; every other [`Arch`] → the capstone path.
///
/// Works over the format-agnostic [`Image`] contract so ELF, PE, Mach-O and
/// raw images all share this entry point. Returns gadgets deduplicated by
/// text and sorted alphabetically (ROPgadget's `alphaSortgadgets`).
pub fn scan_binary<B: Image + ?Sized>(bin: &B, opts: &ScanOptions) -> Result<Vec<Gadget>, Error> {
    let arch = bin.arch();
    let endian = bin.endianness();
    // PLAN.md §4: delay-slot ISAs.
    let delay_slot = matches!(
        arch,
        Arch::Mips32 | Arch::Mips64 | Arch::Sparc | Arch::Sparc64 | Arch::SparcV9
    );

    // Scan ROPgadget-compatible regions (executable program headers for ELF),
    // range-truncated up front (core.py:_sectionInRange).
    let mut regions: Vec<(Vec<u8>, u64)> = Vec::new();
    for sec in bin.exec_scan_regions() {
        let r = match opts.range {
            None => Some((sec.bytes.clone(), sec.vaddr)),
            Some(_) => apply_range(sec, opts.range),
        };
        if let Some(r) = r {
            regions.push(r);
        }
    }

    let thumb = opts.thumb;
    let all = if arch.is_x86_family() {
        let bits = if arch == Arch::X64 { 64 } else { 32 };
        let tables = x86_tables(bits, opts);
        scan_work(&regions, &tables, opts, |code, vaddr, anchor, out| {
            x86_scan_anchor(code, vaddr, bits, opts, anchor, out);
        })
    } else {
        let spec = cs::spec(arch, endian, thumb)?;
        // Validate the capstone mode once up front so a bad combination is a
        // clean error rather than empty per-thread results.
        let _probe = cs::open(&spec)?;
        let tables: Vec<Vec<Anchor>> = [
            opts.rop
                .then(|| anchors::table(TableKind::Rop, arch, endian, thumb)),
            opts.jop
                .then(|| anchors::table(TableKind::Jop, arch, endian, thumb)),
            opts.sys
                .then(|| anchors::table(TableKind::Sys, arch, endian, thumb)),
        ]
        .into_iter()
        .flatten()
        .collect();
        scan_work(&regions, &tables, opts, |code, vaddr, anchor, out| {
            // capstone-rs 0.13 Capstone is !Send/!Sync: one handle per work
            // item (already validated above; a failure here yields nothing).
            if let Ok(handle) = cs::open(&spec) {
                cs::scan_anchor(&handle, &spec, code, vaddr, anchor, opts, delay_slot, out);
            }
        })
    };
    Ok(post_process(all, opts, bin.addr_size()))
}

/// Enabled x86 anchor tables in ROP/JOP/SYS order.
fn x86_tables(bits: u32, opts: &ScanOptions) -> Vec<Vec<Anchor>> {
    [
        opts.rop.then(anchors::rop_anchors),
        opts.jop.then(|| anchors::jop_anchors(bits == 64)),
        opts.sys.then(anchors::sys_anchors),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Run the (region × anchor) work list, serially or under rayon.
///
/// Work items are enumerated in ROPgadget traversal order (region → table →
/// anchor); each item's output preserves (anchor-hit, depth) order. Rayon
/// `collect` over an indexed parallel iterator preserves item order, and the
/// per-item vectors are concatenated in index order — so the merged stream
/// is identical to the serial traversal and the text-dedup survivor is
/// deterministic regardless of thread scheduling (PLAN.md §3.3 invariant).
fn scan_work(
    regions: &[(Vec<u8>, u64)],
    tables: &[Vec<Anchor>],
    opts: &ScanOptions,
    f: impl Fn(&[u8], u64, &Anchor, &mut Vec<Gadget>) + Sync,
) -> Vec<Gadget> {
    let work: Vec<(&(Vec<u8>, u64), &Anchor)> = regions
        .iter()
        .flat_map(|r| {
            tables
                .iter()
                .flat_map(move |t| t.iter().map(move |a| (r, a)))
        })
        .collect();
    let run = |item: &(&(Vec<u8>, u64), &Anchor)| {
        let ((bytes, vaddr), anchor) = *item;
        let mut out = Vec::new();
        f(bytes, *vaddr, anchor, &mut out);
        out
    };
    let chunks: Vec<Vec<Gadget>> = if opts.parallel && work.len() > 1 {
        work.par_iter().map(run).collect()
    } else {
        work.iter().map(run).collect()
    };
    chunks.into_iter().flatten().collect()
}

/// Dedup (text, first-wins) → --only → --badbytes → alphabetical sort.
/// Split out of `scan_binary` so it can be unit-tested on synthetic gadgets.
pub fn post_process(mut all: Vec<Gadget>, opts: &ScanOptions, addr_size: usize) -> Vec<Gadget> {
    // Compute the dedup/sort key ONCE per gadget (text() joins strings;
    // calling it inside sort comparisons is O(n log n) allocations).
    let mut keyed: Vec<(String, Gadget)> = all.drain(..).map(|g| (g.text(), g)).collect();

    // Dedup by text, first-occurrence-wins in traversal order
    // (rgutils.deleteDuplicateGadgets). --all and --noinstr both skip it
    // (core.py:87-88).
    if !opts.all && !opts.noinstr {
        let mut seen: HashSet<String> = HashSet::new();
        keyed.retain(|(text, _)| seen.insert(text.clone()));
    }

    // Post-dedup filters (ropgadget/options.py).
    if let Some(only) = &opts.only {
        keyed.retain(|(_, g)| {
            g.insns
                .iter()
                .all(|ins| only.iter().any(|o| o == first_token(ins)))
        });
    }
    if !opts.badbytes.is_empty() {
        keyed.retain(|(_, g)| {
            let packed = g.vaddr.to_le_bytes();
            !opts
                .badbytes
                .iter()
                .any(|b| packed[..addr_size].contains(b))
        });
    }
    if opts.cfg_aware {
        keyed.retain(|(_, g)| is_endbr_entry(g));
    }

    // Alphabetical sort by gadget text (rgutils.alphaSortgadgets) —
    // skipped with --noinstr (core.py:94-95).
    if !opts.noinstr {
        keyed.sort_by(|a, b| a.0.cmp(&b.0));
    }
    keyed.into_iter().map(|(_, g)| g).collect()
}

fn first_token(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or("")
}

/// `--cfg-aware`: the gadget's first bytes are `endbr64` (f3 0f 1e fa) or
/// `endbr32` (f3 0f 1e fb). Bytes, not text, so non-x86 gadgets (whose
/// bytes never match) are filtered out too — the flag is x86/x64-only by
/// contract.
fn is_endbr_entry(g: &Gadget) -> bool {
    g.bytes.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]) || g.bytes.starts_with(&[0xf3, 0x0f, 0x1e, 0xfb])
}

/// ROPgadget `core.py:_sectionInRange`: truncate the section to the range
/// before scanning. Returns (bytes, new_vaddr).
fn apply_range(sec: &rf_core::Section, range: Option<(u64, u64)>) -> Option<(Vec<u8>, u64)> {
    let (range_start, range_end) = range?;
    let mut vaddr = sec.vaddr;
    let mut offset = sec.offset;
    let mut size = sec.size;
    let sec_end = sec.vaddr.wrapping_add(sec.size);

    if range_end < sec.vaddr || range_start > sec_end {
        return None;
    }
    if range_start > vaddr {
        let diff = range_start - vaddr;
        vaddr += diff;
        offset += diff;
        size -= diff;
    }
    if range_end < sec_end {
        size -= sec_end - range_end;
    }
    if size == 0 {
        return None;
    }
    let byte_start = usize::try_from(offset - sec.offset).ok()?;
    let byte_end = byte_start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
    let byte_end = byte_end.min(sec.bytes.len());
    if byte_start >= byte_end {
        return None;
    }
    Some((sec.bytes[byte_start..byte_end].to_vec(), vaddr))
}

/// Scan one executable buffer (x86/x64, serial). Gadgets are appended in
/// traversal order. This is the serial per-section entry point used by
/// tests; `scan_binary` drives the same per-anchor routine over its work
/// list (in parallel when `ScanOptions::parallel` is set).
pub fn scan_section(
    code: &[u8],
    sec_vaddr: u64,
    bits: u32,
    opts: &ScanOptions,
    out: &mut Vec<Gadget>,
) {
    for table in x86_tables(bits, opts) {
        for anchor in &table {
            x86_scan_anchor(code, sec_vaddr, bits, opts, anchor, out);
        }
    }
}

/// Scan one x86 anchor over one buffer.
///
/// Per-start decode cache: decode each candidate start position ONCE
/// through the maximal window; all anchor-terminated candidates from that
/// start are derived from the recorded instruction-boundary list
/// (PLAN.md §3.4). The cache is pure memoization — serial and parallel
/// runs produce identical output.
fn x86_scan_anchor(
    code: &[u8],
    sec_vaddr: u64,
    bits: u32,
    opts: &ScanOptions,
    anchor: &Anchor,
    out: &mut Vec<Gadget>,
) {
    let mut cache: HashMap<usize, Rc<Vec<WinInsn>>> = HashMap::new();
    let mut fmt = x86::make_formatter();
    let window = opts.depth.saturating_sub(1) + anchors::MAX_ANCHOR_SIZE;

    for ref_pos in anchors::find_matches(code, anchor) {
        let end = ref_pos + anchor.size();
        if end > code.len() {
            continue;
        }
        for i in 0..opts.depth {
            if ref_pos < i {
                continue; // start would be negative
            }
            let start = ref_pos - i;
            // --align: keep only aligned starts (gadgets.py:78,87 — on x86
            // the aligned stepping ref-i*align is a subset of the byte
            // stepping, so a pure filter is faithful). Some(0) = no
            // constraint (oracle treats 0 as falsy).
            if let Some(a) = opts.align {
                if a > 0 && sec_vaddr.wrapping_add(start as u64) % a as u64 != 0 {
                    continue;
                }
            }
            let insns = cache
                .entry(start)
                .or_insert_with(|| {
                    Rc::new(x86::decode_window(
                        code,
                        start,
                        sec_vaddr,
                        bits,
                        start + window,
                    ))
                })
                .clone();
            if let Some(g) =
                try_candidate(code, sec_vaddr, bits, start, end, &insns, opts, &mut fmt)
            {
                out.push(g);
            }
        }
    }
}

/// A candidate is valid iff the bytes `start..end` decode cleanly
/// (total decoded size == end - start, gadgets.py:100-103 — equivalently:
/// `end` coincides with an instruction boundary of the decode from `start`)
/// and `passCleanX86` accepts it. Instruction text is formatted only here,
/// for accepted candidates.
#[allow(clippy::too_many_arguments)]
fn try_candidate(
    code: &[u8],
    sec_vaddr: u64,
    bits: u32,
    start: usize,
    end: usize,
    window: &[WinInsn],
    opts: &ScanOptions,
    fmt: &mut iced_x86::FastFormatter,
) -> Option<Gadget> {
    // Instruction ends are strictly increasing; find the prefix ending at
    // exactly `end`.
    let n = window.partition_point(|r| r.end < end);
    if n >= window.len() || window[n].end != end {
        return None;
    }
    let decodes = &window[..=n];
    if x86::pass_clean(decodes, opts.multibr, &opts.filter) {
        return None;
    }
    Some(Gadget {
        vaddr: opts
            .offset
            .wrapping_add(sec_vaddr)
            .wrapping_add(start as u64),
        bytes: code[start..end].to_vec(),
        insns: x86::format_gadget(code, start, end, sec_vaddr, bits, fmt),
        delay_slot: false, // x86/x64 have no delay slots
        prev: opts
            .call_preceded
            .then(|| code[start.saturating_sub(9)..start].to_vec()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ScanOptions {
        ScanOptions::default()
    }

    fn scan(code: &[u8], vaddr: u64, bits: u32, o: &ScanOptions) -> Vec<Gadget> {
        let mut out = Vec::new();
        scan_section(code, vaddr, bits, o, &mut out);
        out
    }

    #[test]
    fn decodes_simple_function() {
        // push ebp ; mov ebp, esp ; ret
        let g = scan(b"\x55\x89\xe5\xc3", 0x1000, 32, &opts());
        let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
        assert!(texts.contains(&"ret".to_string()), "{texts:?}");
        assert!(
            texts.contains(&"mov ebp, esp ; ret".to_string()),
            "{texts:?}"
        );
        assert!(
            texts.contains(&"push ebp ; mov ebp, esp ; ret".to_string()),
            "{texts:?}"
        );
        // vaddr of the full prologue gadget
        let full = g
            .iter()
            .find(|x| x.text() == "push ebp ; mov ebp, esp ; ret")
            .unwrap();
        assert_eq!(full.vaddr, 0x1000);
        assert_eq!(full.bytes, b"\x55\x89\xe5\xc3");
    }

    #[test]
    fn anchor_start_need_not_be_a_boundary() {
        // 66 0f 05 decodes as one 3-byte syscall; the SYS anchor sits at
        // offset 1, mid-instruction. ROPgadget accepts this (clean-decode
        // rule only constrains the gadget END).
        let g = scan(b"\x66\x0f\x05", 0x2000, 64, &opts());
        assert!(
            g.iter().any(|x| x.text() == "syscall" && x.vaddr == 0x2000),
            "{:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn depth_limits_gadget_length() {
        // 9 nops + ret: with depth 2 only "nop ; ret" and "ret" appear.
        let mut code = vec![0x90u8; 9];
        code.push(0xc3);
        let mut o = opts();
        o.depth = 2;
        let g = scan(&code, 0x1000, 32, &o);
        let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
        assert!(texts.contains(&"ret".to_string()));
        assert!(texts.contains(&"nop ; ret".to_string()));
        assert!(!texts.contains(&"nop ; nop ; ret".to_string()));
    }

    #[test]
    fn multibr_controls_middle_branches() {
        // call rel32 ; ret  (plus a lone ret)
        let code = b"\xe8\x00\x00\x00\x00\xc3";
        let g = scan(code, 0x1000, 32, &opts());
        assert!(
            !g.iter().any(|x| x.text().contains("call")),
            "middle call must be rejected without --multibr: {:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
        let mut o = opts();
        o.multibr = true;
        let g = scan(code, 0x1000, 32, &o);
        assert!(
            g.iter()
                .any(|x| x.text().starts_with("call") && x.text().ends_with("ret")),
            "--multibr must keep it: {:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn bnd_ret_is_rejected_like_ropgadget() {
        // f2 c3 = "bnd ret" which is NOT in ROPgadget's branch list, so the
        // MPX anchor produces no gadget ending at those bytes.
        let g = scan(b"\xf2\xc3", 0x1000, 64, &opts());
        assert!(
            g.iter().all(|x| !x.bytes.ends_with(b"\xf2\xc3")),
            "{:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn int3_is_filtered() {
        // int3 ; ret — middle int3 rejected by the built-in db|int3 filter
        let g = scan(b"\xcc\xc3", 0x1000, 32, &opts());
        let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
        assert!(!texts.iter().any(|t| t.contains("int3")), "{texts:?}");
        assert!(texts.contains(&"ret".to_string()));
    }

    #[test]
    fn bad_decode_rejects_candidate() {
        // 0f 0b (ud2) then c3: "ud2 ; ret" — ud2 decodes fine but is not a
        // problem; use a genuinely invalid sequence instead: 0f ff is
        // invalid (ud0-ish). Candidate start at 0 must fail clean decode.
        let g = scan(b"\x0f\xff\xc3", 0x1000, 64, &opts());
        // Only the bare "ret" from anchor at 2 with i=0 survives; nothing
        // starting at 0 or 1 that spans the invalid bytes.
        assert!(g
            .iter()
            .all(|x| x.vaddr == 0x1002 || !x.bytes.starts_with(&[0x0f, 0xff])),);
    }

    #[test]
    fn offset_slides_vaddr_not_text() {
        let mut o = opts();
        o.offset = 0x10_0000;
        let g = scan(b"\x58\xc3", 0x1000, 32, &o);
        let pop = g.iter().find(|x| x.text() == "pop eax ; ret").unwrap();
        assert_eq!(pop.vaddr, 0x10_1000);
        let plain = scan(b"\x58\xc3", 0x1000, 32, &opts());
        let pop0 = plain.iter().find(|x| x.text() == "pop eax ; ret").unwrap();
        assert_eq!(pop0.vaddr, 0x1000);
        assert_eq!(pop.text(), pop0.text());
    }

    #[test]
    fn jop_and_sys_anchors_work() {
        // jmp rax ; (padding) ; int 0x80
        let mut o = opts();
        o.rop = false;
        let g = scan(b"\xff\xe0\x90\xcd\x80", 0x4000, 64, &o);
        let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
        assert!(texts.contains(&"jmp rax".to_string()), "{texts:?}");
        assert!(texts.contains(&"int 0x80".to_string()), "{texts:?}");
        // with norop, no "ret"-ending gadgets appear
        assert!(texts.iter().all(|t| !t.ends_with("ret")), "{texts:?}");
    }

    #[test]
    fn only_filter_keeps_whitelisted_mnemonics() {
        let mut o = opts();
        o.only = Some(vec!["pop".to_string(), "ret".to_string()]);
        // pop eax ; ret  |  mov eax, ebx ; ret
        let g = scan(b"\x58\xc3\x89\xd8\xc3", 0x1000, 32, &o);
        assert!(!g.is_empty());
        // apply the same predicate scan_binary uses:
        let only = o.only.clone().unwrap();
        let kept: Vec<&Gadget> = g
            .iter()
            .filter(|g| {
                g.insns
                    .iter()
                    .all(|ins| only.iter().any(|o| o == first_token(ins)))
            })
            .collect();
        let texts: Vec<String> = kept.iter().map(|x| x.text()).collect();
        assert!(texts.contains(&"pop eax ; ret".to_string()), "{texts:?}");
        // "mov eax, ebx" is not whitelisted
        assert!(!texts.iter().any(|t| t.contains("mov")), "{texts:?}");
    }

    fn gadget(vaddr: u64, bytes: &[u8], insns: &[&str]) -> Gadget {
        Gadget {
            vaddr,
            bytes: bytes.to_vec(),
            insns: insns.iter().map(|s| s.to_string()).collect(),
            delay_slot: false,
            prev: None,
        }
    }

    #[test]
    fn dedup_keeps_first_occurrence_in_traversal_order() {
        // Same text at two vaddrs: the first in traversal order survives.
        let all = vec![
            gadget(0x2000, b"\x89\xc0\xc3", &["mov eax, eax", "ret"]),
            gadget(0x1000, b"\x8b\xc0\xc3", &["mov eax, eax", "ret"]),
            gadget(0x3000, b"\xc3", &["ret"]),
        ];
        let out = post_process(all, &opts(), 4);
        assert_eq!(out.len(), 2);
        let m = out
            .iter()
            .find(|g| g.text() == "mov eax, eax ; ret")
            .unwrap();
        assert_eq!(m.vaddr, 0x2000, "first occurrence must win");
        assert_eq!(m.bytes, b"\x89\xc0\xc3");
        // sorted alphabetically: "mov..." < "ret"
        assert_eq!(out[0].text(), "mov eax, eax ; ret");
        assert_eq!(out[1].text(), "ret");
    }

    #[test]
    fn badbytes_rejects_packed_le_address() {
        // Distinct texts so both survive dedup (dedup runs before badbytes,
        // exactly like ROPgadget's Options pass).
        let all = vec![
            gadget(0x100a, b"\xc3", &["ret"]),
            gadget(0x100b, b"\xcb", &["retf"]),
        ];
        let mut o = opts();
        o.badbytes = vec![0x0a];
        let out = post_process(all.clone(), &o, 4);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].vaddr, 0x100b);
        // 64-bit packing checks all 8 LE bytes; 0x10 rejects both.
        o.badbytes = vec![0x10];
        assert!(post_process(all, &o, 8).is_empty());
    }

    #[test]
    fn cfg_aware_keeps_only_endbr_entries() {
        let all = vec![
            gadget(
                0x1000,
                b"\xf3\x0f\x1e\xfa\x59\xc3",
                &["endbr64", "pop rcx", "ret"],
            ),
            gadget(0x1010, b"\xf3\x0f\x1e\xfb\xc3", &["endbr32", "ret"]),
            gadget(0x1020, b"\x59\xc3", &["pop rcx", "ret"]), // no endbr
            gadget(0x1030, b"\xc3", &["ret"]),
        ];
        let mut o = opts();
        o.cfg_aware = true;
        let out = post_process(all.clone(), &o, 8);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|g| g.bytes.starts_with(&[0xf3, 0x0f, 0x1e])));
        // off by default
        assert_eq!(post_process(all, &opts(), 8).len(), 4);
    }

    #[test]
    fn range_truncates_sections() {
        let sec = rf_core::Section {
            name: ".text".into(),
            vaddr: 0x1000,
            offset: 0x200,
            size: 8,
            bytes: vec![1, 2, 3, 4, 5, 6, 7, 8],
            executable: true,
            writable: false,
            allocated: true,
        };
        let (bytes, vaddr) = apply_range(&sec, Some((0x1002, 0x1006))).unwrap();
        assert_eq!(vaddr, 0x1002);
        assert_eq!(bytes, vec![3, 4, 5, 6]);
        assert!(apply_range(&sec, Some((0x2000, 0x3000))).is_none());
        assert!(apply_range(&sec, Some((0x0, 0x0))).is_none());
    }

    #[test]
    fn scans_real_fixture() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/elf-Linux-x64"
        );
        let bytes = std::fs::read(path).unwrap();
        let bin = rf_core::Binary::parse(&bytes).unwrap();
        let g = scan_binary(&bin, &opts()).unwrap();
        assert!(
            g.len() > 1000,
            "expected thousands of gadgets, got {}",
            g.len()
        );
        assert!(g.iter().any(|x| x.text() == "ret"));
        // every gadget vaddr lies inside some scanned exec region
        let exec = bin.exec_scan_regions();
        for x in &g {
            assert!(
                exec.iter()
                    .any(|s| s.vaddr <= x.vaddr && x.vaddr < s.vaddr + s.size),
                "gadget {:#x} outside exec sections",
                x.vaddr
            );
        }
        // property test (PLAN §4): every gadget's bytes re-disassemble to
        // exactly its instruction list
        let mut fmt = crate::x86::make_formatter();
        for x in g.iter().step_by(97) {
            let retexts =
                crate::x86::format_gadget(&x.bytes, 0, x.bytes.len(), x.vaddr, 64, &mut fmt);
            assert_eq!(
                retexts, x.insns,
                "gadget {:#x} bytes do not re-decode",
                x.vaddr
            );
        }
    }

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/");
        std::fs::read(format!("{path}{name}")).unwrap()
    }

    /// Parallel and serial scans must produce byte-identical output
    /// (deterministic text-dedup survivor) on real fixtures — x64 (iced-x86
    /// path) and ARM64 (capstone path).
    #[test]
    fn parallel_matches_serial_on_real_fixtures() {
        for fixture in ["elf-Linux-x64", "elf-ARM64-bash"] {
            let bytes = fixture_bytes(fixture);
            let bin = rf_core::Binary::parse(&bytes).unwrap();
            let mut serial_opts = opts();
            serial_opts.parallel = false;
            let serial = scan_binary(&bin, &serial_opts).unwrap();
            let parallel = scan_binary(&bin, &opts()).unwrap();
            assert!(!serial.is_empty(), "{fixture}: no gadgets");
            let key = |g: &Gadget| (g.vaddr, g.bytes.clone(), g.text());
            let s: Vec<_> = serial.iter().map(key).collect();
            let p: Vec<_> = parallel.iter().map(key).collect();
            assert_eq!(s, p, "{fixture}: parallel output differs from serial");
        }
    }

    /// Multi-arch smoke test: the capstone path scans real non-x86 fixtures
    /// and finds gadgets of the expected anchor families.
    #[test]
    fn scans_non_x86_real_fixtures() {
        let cases: &[(&str, &str)] = &[
            ("elf-ARM64-bash", "ret"),
            ("elf-ARMv7-ls", "bx"),
            ("elf-Mips-Defcon-20-pwn100", "jr"),
            ("elf-PowerPC-bash", "blr"),
            ("elf-SparcV8-bash", "retl"),
        ];
        for (name, want_mnem) in cases {
            let bytes = fixture_bytes(name);
            let bin = rf_core::Binary::parse(&bytes).unwrap();
            let mut o = opts();
            o.parallel = false; // keep test output deterministic to debug
            let g = scan_binary(&bin, &o).unwrap();
            assert!(
                g.iter().any(|x| x.text().contains(want_mnem)),
                "{name}: no gadget containing {want_mnem:?} in {} gadgets",
                g.len()
            );
            // Every gadget vaddr lies inside a scanned exec region.
            let exec = bin.exec_scan_regions();
            for x in &g {
                assert!(
                    exec.iter()
                        .any(|s| s.vaddr <= x.vaddr && x.vaddr < s.vaddr + s.size),
                    "{name}: gadget {:#x} outside exec regions",
                    x.vaddr
                );
            }
        }
    }

    /// RISC-V fixtures exercise the compressed-instruction size rule on real
    /// code; also validates the RV32 (ELFCLASS32) capstone mode override.
    #[test]
    fn scans_riscv_real_fixtures() {
        for name in ["elf-Linux-RISCV_32", "elf-Linux-RISCV_64"] {
            let bytes = fixture_bytes(name);
            let bin = rf_core::Binary::parse(&bytes).unwrap();
            let mut o = opts();
            o.parallel = false;
            let g = scan_binary(&bin, &o).unwrap();
            assert!(!g.is_empty(), "{name}: no gadgets found");
        }
    }
}
