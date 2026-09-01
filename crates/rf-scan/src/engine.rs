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

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use rf_core::{ElfBinary, Error};

use crate::anchors::{self, Anchor};
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

/// Scan a parsed binary. Returns gadgets deduplicated by text and sorted
/// alphabetically by text (ROPgadget's `alphaSortgadgets`).
pub fn scan_binary(bin: &ElfBinary, opts: &ScanOptions) -> Result<Vec<Gadget>, Error> {
    use goblin::elf::header::{EM_386, EM_X86_64};
    let bits = match (bin.machine(), bin.is_64()) {
        (EM_386, false) => 32,
        (EM_X86_64, true) => 64,
        // goblin reports EM_X86_64 for both; treat other combos by class.
        (EM_386 | EM_X86_64, is64) => {
            if is64 {
                64
            } else {
                32
            }
        }
        (m, _) => {
            return Err(Error::Unsupported(format!(
                "machine {m:#x} (Phase 0 supports x86/x64 only)"
            )))
        }
    };

    let mut all = Vec::new();
    // Scan ROPgadget-compatible regions (executable program headers), not
    // SHF_EXECINSTR sections — the parity oracle ignores section headers.
    for sec in bin.exec_scan_regions() {
        let (bytes, vaddr) = match opts.range {
            None => (sec.bytes.clone(), sec.vaddr),
            Some(_) => match apply_range(sec, opts.range) {
                Some(x) => x,
                None => continue,
            },
        };
        scan_section(&bytes, vaddr, bits, opts, &mut all);
    }
    Ok(post_process(all, opts, bin.class().addr_size()))
}

/// Dedup (text, first-wins) → --only → --badbytes → alphabetical sort.
/// Split out of `scan_binary` so it can be unit-tested on synthetic gadgets.
pub fn post_process(mut all: Vec<Gadget>, opts: &ScanOptions, addr_size: usize) -> Vec<Gadget> {
    // Compute the dedup/sort key ONCE per gadget (text() joins strings;
    // calling it inside sort comparisons is O(n log n) allocations).
    let mut keyed: Vec<(String, Gadget)> = all.drain(..).map(|g| (g.text(), g)).collect();

    // Dedup by text, first-occurrence-wins in traversal order
    // (rgutils.deleteDuplicateGadgets).
    let mut seen: HashSet<String> = HashSet::new();
    keyed.retain(|(text, _)| seen.insert(text.clone()));

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
            !opts.badbytes.iter().any(|b| packed[..addr_size].contains(b))
        });
    }

    // Alphabetical sort by gadget text (rgutils.alphaSortgadgets).
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.into_iter().map(|(_, g)| g).collect()
}

fn first_token(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or("")
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

/// Scan one executable buffer. Gadgets are appended in traversal order.
pub fn scan_section(
    code: &[u8],
    sec_vaddr: u64,
    bits: u32,
    opts: &ScanOptions,
    out: &mut Vec<Gadget>,
) {
    // Anchor tables are built once per section (cheap) so the \x41-prefixed
    // JOP variants aren't leaked per call.
    let tables: Vec<Vec<Anchor>> = [
        opts.rop.then(anchors::rop_anchors),
        opts.jop.then(|| anchors::jop_anchors(bits == 64)),
        opts.sys.then(anchors::sys_anchors),
    ]
    .into_iter()
    .flatten()
    .collect();

    // Per-start decode cache: decode each candidate start position ONCE
    // through the maximal window; all anchor-terminated candidates from that
    // start are derived from the recorded instruction-boundary list
    // (PLAN.md §3.4).
    let mut cache: HashMap<usize, Rc<Vec<WinInsn>>> = HashMap::new();
    let mut fmt = x86::make_formatter();
    let window = opts.depth.saturating_sub(1) + anchors::MAX_ANCHOR_SIZE;

    for table in &tables {
        for anchor in table {
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
                    let insns = cache
                        .entry(start)
                        .or_insert_with(|| {
                            Rc::new(x86::decode_window(code, start, sec_vaddr, bits, start + window))
                        })
                        .clone();
                    if let Some(g) = try_candidate(code, sec_vaddr, bits, start, end, &insns, opts, &mut fmt)
                    {
                        out.push(g);
                    }
                }
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
        vaddr: opts.offset.wrapping_add(sec_vaddr).wrapping_add(start as u64),
        bytes: code[start..end].to_vec(),
        insns: x86::format_gadget(code, start, end, sec_vaddr, bits, fmt),
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
        assert!(texts.contains(&"mov ebp, esp ; ret".to_string()), "{texts:?}");
        assert!(
            texts.contains(&"push ebp ; mov ebp, esp ; ret".to_string()),
            "{texts:?}"
        );
        // vaddr of the full prologue gadget
        let full = g.iter().find(|x| x.text() == "push ebp ; mov ebp, esp ; ret").unwrap();
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
            g.iter().any(|x| x.text().starts_with("call") && x.text().ends_with("ret")),
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
        assert!(g.iter().all(|x| x.vaddr == 0x1002 || !x.bytes.starts_with(&[0x0f, 0xff])),);
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
        let m = out.iter().find(|g| g.text() == "mov eax, eax ; ret").unwrap();
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
    fn range_truncates_sections() {
        let sec = rf_core::Section {
            name: ".text".into(),
            vaddr: 0x1000,
            offset: 0x200,
            size: 8,
            bytes: vec![1, 2, 3, 4, 5, 6, 7, 8],
            executable: true,
            writable: false,
        };
        let (bytes, vaddr) = apply_range(&sec, Some((0x1002, 0x1006))).unwrap();
        assert_eq!(vaddr, 0x1002);
        assert_eq!(bytes, vec![3, 4, 5, 6]);
        assert!(apply_range(&sec, Some((0x2000, 0x3000))).is_none());
        assert!(apply_range(&sec, Some((0x0, 0x0))).is_none());
    }

    #[test]
    fn scans_real_fixture() {
        let path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/elf-Linux-x64");
        let bytes = std::fs::read(path).unwrap();
        let bin = rf_core::Binary::parse(&bytes).unwrap();
        let g = scan_binary(&bin, &opts()).unwrap();
        assert!(g.len() > 1000, "expected thousands of gadgets, got {}", g.len());
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
            assert_eq!(retexts, x.insns, "gadget {:#x} bytes do not re-decode", x.vaddr);
        }
    }
}
