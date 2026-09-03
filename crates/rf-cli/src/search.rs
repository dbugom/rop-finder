//! Phase 6: ROPgadget's non-gadget search modes (`--string`, `--opcode`,
//! `--memstr`), the `--re` / `--callPreceded` gadget post-filters, and
//! `--mipsrop`. Line formats mirror core.py:118-227 and
//! options.py:64-120 byte-for-byte; section sets mirror the loaders'
//! `getExecSections` / `getDataSections`.

use std::io::Write;

use regex::bytes::Regex as ByteRegex;
use regex::bytes::RegexBuilder as ByteRegexBuilder;
use regex::Regex;
use rf_core::{Arch, Section};
use rf_scan::Gadget;

use crate::Target;

/// 60-column rule used by the Strings/Opcodes/Gadgets/MIPS headers.
pub const RULE60: &str = "============================================================";
/// 55-column rule used by the Memory-bytes header (core.py:212 — yes, 55).
pub const RULE55: &str = "=======================================================";

/// Search-mode address width (core.py:113: `8 if arch == CS_MODE_32 else
/// 16`). For structured binaries the loaders return CS_MODE_32 exactly for
/// 32-bit pointer size (elf.py:354-358, pe.py:228-232, macho.py:320-324),
/// i.e. `addr_size == 4`. For RAW arm/thumb the oracle's mode is
/// CS_MODE_ARM (0) / CS_MODE_THUMB (16) → 16 digits even though the
/// pointer size is 4 (raw.py:54-67).
pub fn search_width8(target: &Target, arch: Arch) -> bool {
    if matches!(target, Target::Raw(_)) && matches!(arch, Arch::Arm | Arch::ArmThumb) {
        return false;
    }
    arch.addr_size() == 4
}

pub fn fmt_search_addr(vaddr: u64, width8: bool) -> String {
    if width8 {
        format!("0x{vaddr:08x}")
    } else {
        format!("0x{vaddr:016x}")
    }
}

/// ROPgadget getDataSections: ELF SHF_ALLOC && !SHF_EXECINSTR
/// (elf.py:323-334), PE writable (pe.py:194-205), Mach-O
/// !S_ATTR_SOME/PURE_INSTRUCTIONS (macho.py:293-304), Raw none
/// (raw.py:35-36), Universal = concat of slices (universal.py:83-87).
pub fn data_sections(target: &Target) -> Vec<Section> {
    match target {
        Target::Elf(b) => b
            .sections()
            .iter()
            .filter(|s| s.allocated && !s.executable)
            .cloned()
            .collect(),
        Target::Pe(b) => b
            .sections()
            .iter()
            .filter(|s| s.writable)
            .cloned()
            .collect(),
        Target::MachO(b) => b
            .sections()
            .iter()
            .filter(|s| !s.executable)
            .cloned()
            .collect(),
        Target::Raw(_) => Vec::new(),
        Target::Universal(u) => u
            .slices()
            .iter()
            .flat_map(|m| m.sections().iter().filter(|s| !s.executable).cloned())
            .collect(),
    }
}

/// ROPgadget getExecSections: ELF = PF_X program headers (elf.py:311-321 —
/// our `exec_scan_regions`), PE/Mach-O/Raw = executable sections
/// (pe.py:207-218, macho.py:280-291, raw.py:32-33), Universal = concat
/// (universal.py:77-81).
pub fn exec_search_sections(target: &Target) -> Vec<Section> {
    match target {
        Target::Elf(b) => b.exec_scan_regions().to_vec(),
        Target::Pe(b) => b.exec_scan_regions().to_vec(),
        Target::MachO(b) => b.exec_scan_regions().to_vec(),
        Target::Raw(b) => vec![b.section().clone()],
        Target::Universal(u) => u.all_exec_scan_regions().into_iter().cloned().collect(),
    }
}

/// core.py:37-64 `_sectionInRange`: truncate a section's byte window to the
/// `--range` interval (None = the "0x0-0x0" no-range case). Returns the
/// truncated (vaddr, bytes) or None when the section falls outside.
fn section_in_range(vaddr: u64, bytes: &[u8], range: Option<(u64, u64)>) -> Option<(u64, &[u8])> {
    let Some((range_start, range_end)) = range else {
        return Some((vaddr, bytes));
    };
    let mut size = bytes.len() as u64;
    let section_end = vaddr + size;
    if range_end < vaddr || range_start > section_end {
        return None;
    }
    let mut start = vaddr;
    let mut ops = bytes;
    if range_start > start {
        let diff = range_start - start;
        ops = &ops[diff as usize..];
        start += diff;
        size -= diff;
    }
    if range_end < start + size {
        let diff = (start + size) - range_end;
        ops = &ops[..ops.len() - diff as usize];
        size -= diff;
    }
    if size == 0 {
        return None;
    }
    Some((start, ops))
}

/// core.py:172-174 — `string.printable` bytes (0x09-0x0d, 0x20-0x7e)
/// survive, everything else becomes '.'.
fn printable_mapped(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0x09..=0x0d | 0x20..=0x7e => b as char,
            _ => '.',
        })
        .collect()
}

/// Compile a pattern with PYTHON `bytes`-regex semantics.
///
/// CLI-05: `re.finditer(s.encode(), opcodes)` in `core.py:171` compiles a
/// *bytes* pattern, where `.` is "any byte except a newline" and
/// `\w`/`\d`/`\s` are the ASCII classes. `regex::bytes::Regex::new`
/// defaults to Unicode mode, where `.` is "any UTF-8 encoded codepoint
/// except a newline" and will not match a byte that cannot begin (or
/// continue) a valid UTF-8 sequence. That difference is not theoretical:
/// on `tests/fixtures/elf-ARM64-bash`, `--string "m..n"` matches the
/// bytes `6d be b6 6e` at 0x404147 in `.gnu.hash` for the oracle and did not
/// match here, so rop-finder silently returned 286 hits where ROPgadget
/// returns 287. `unicode(false)` makes the two engines agree byte for byte.
fn byte_regex(pattern: &str) -> Result<ByteRegex, regex::Error> {
    ByteRegexBuilder::new(pattern).unicode(false).build()
}

/// Where a search hit lives, for the structured output.
///
/// The shared v0.4 query spec requires every non-gadget search result to
/// name its section and that section's permissions, because "is this string
/// writable?" is the question a write-what-where chain actually asks. The
/// human output is unchanged - it is byte-compared against ROPgadget, which
/// prints only the address and the match.
#[derive(Debug, Clone)]
pub struct HitSite {
    /// Section name, or `None` for a raw blob's single unnamed region.
    pub section: Option<String>,
    pub writable: bool,
    pub executable: bool,
}

impl HitSite {
    fn of(sec: &Section) -> HitSite {
        HitSite {
            section: (!sec.name.is_empty()).then(|| sec.name.clone()),
            writable: sec.writable,
            executable: sec.executable,
        }
    }
}

pub struct StringHit {
    pub vaddr: u64,
    pub matched: String,
    pub site: HitSite,
}

pub struct OpcodeHit {
    pub vaddr: u64,
    pub site: HitSite,
}

pub struct MemStrHit {
    pub vaddr: u64,
    pub ch: char,
    pub site: HitSite,
}

/// `--compat` (CLI-11): re-materialise a section's content the way
/// ROPgadget does, from the FILE rather than from what the section really
/// holds at runtime.
///
/// `elf.py:332` is `bytes(self.__binary[sh_offset : sh_offset + sh_size])`,
/// with no check that the section has any file content at all. For an
/// `SHT_NOBITS` section — `.bss`, which is zero-filled at runtime and
/// occupies no file bytes — `sh_offset` points at whatever happens to
/// follow, so the oracle searches `.comment`/`.symtab`/`.strtab` and
/// reports the hits at `.bss` addresses that hold zeros in the running
/// process. On tests/fixtures/elf-Linux-x86 that is exactly one phantom
/// `--string "m..n"` hit, `0x080f4de0 : mmen`, in bytes that are not there.
///
/// rf-core clamps `Section::bytes` to the file content a section actually
/// owns, which is the truthful answer and stays the default. This function
/// exists so `--compat` can reproduce the oracle bug for bug when a user is
/// diffing the two tools. Python slicing clamps out of range, so this does
/// too, and the slice is never longer than the file.
fn compat_bytes<'a>(sec: &'a Section, file: Option<&'a [u8]>) -> std::borrow::Cow<'a, [u8]> {
    let Some(file) = file else {
        return std::borrow::Cow::Borrowed(&sec.bytes);
    };
    if sec.bytes.len() as u64 >= sec.size {
        return std::borrow::Cow::Borrowed(&sec.bytes);
    }
    let start = (sec.offset as usize).min(file.len());
    let end = sec.offset.saturating_add(sec.size).min(file.len() as u64) as usize;
    if end <= start {
        return std::borrow::Cow::Borrowed(&sec.bytes);
    }
    std::borrow::Cow::Borrowed(&file[start..end])
}

/// core.py:159-180 `__lookingForAString`: the pattern is a BYTE regex over
/// the data sections; each hit prints the `pattern.len()` bytes at the
/// match start, printable-mapped. `delta` is the --base rebase slide;
/// `offset` is --offset. `compat_file` is `Some(the raw input)` under
/// `--compat` — see [`compat_bytes`].
pub fn find_string(
    target: &Target,
    delta: u64,
    offset: u64,
    range: Option<(u64, u64)>,
    pattern: &str,
    compat_file: Option<&[u8]>,
) -> Result<Vec<StringHit>, String> {
    let re =
        byte_regex(pattern).map_err(|e| format!("invalid --string byte regex {pattern:?}: {e}"))?;
    let mut hits = Vec::new();
    for sec in data_sections(target) {
        let content = compat_bytes(&sec, compat_file);
        let sec = Section {
            bytes: content.into_owned(),
            ..sec
        };
        let site = HitSite::of(&sec);
        let vaddr = sec.vaddr.wrapping_add(delta);
        let Some((start, ops)) = section_in_range(vaddr, &sec.bytes, range) else {
            continue;
        };
        for m in re.find_iter(ops) {
            let r = m.start();
            // oracle: opcodes[ref:ref + len(s)] — `len` of the PATTERN
            // *string*, which in Python 3 counts CHARACTERS, not bytes.
            let end = (r + pattern.chars().count()).min(ops.len());
            hits.push(StringHit {
                vaddr: offset.wrapping_add(start).wrapping_add(r as u64),
                matched: printable_mapped(&ops[r..end]),
                site: site.clone(),
            });
        }
    }
    Ok(hits)
}

/// core.py:182-200 `__lookingForOpcodes`: literal byte search
/// (re.escape(unhexlify(s))) over the executable sections.
pub fn find_opcode(
    target: &Target,
    delta: u64,
    offset: u64,
    range: Option<(u64, u64)>,
    hexstr: &str,
) -> Result<Vec<OpcodeHit>, String> {
    let raw = crate::hex_decode(hexstr)
        .ok_or_else(|| format!("invalid --opcode {hexstr:?} (even-length hex expected)"))?;
    let mut hits = Vec::new();
    for sec in exec_search_sections(target) {
        let site = HitSite::of(&sec);
        let vaddr = sec.vaddr.wrapping_add(delta);
        let Some((start, ops)) = section_in_range(vaddr, &sec.bytes, range) else {
            continue;
        };
        let mut push = |r: usize| {
            hits.push(OpcodeHit {
                vaddr: offset.wrapping_add(start).wrapping_add(r as u64),
                site: site.clone(),
            });
        };
        if raw.is_empty() {
            // unhexlify("") == b"" — Python finditer(b"", data) matches at
            // every position, including the end.
            for r in 0..=ops.len() {
                push(r);
            }
            continue;
        }
        for (r, w) in ops.windows(raw.len()).enumerate() {
            if w == raw.as_slice() {
                push(r);
            }
        }
    }
    Ok(hits)
}

/// core.py:202-227 `__lookingForMemStr`: for each CHAR of the string, the
/// char's UTF-8 bytes are used AS A REGEX over exec-then-data sections and
/// only the FIRST hit (first section, first match) prints — the bare
/// `raise` quirk. A char whose bytes are an invalid regex (e.g. '[')
/// raises inside the try and is silently skipped.
pub fn find_memstr(
    target: &Target,
    delta: u64,
    offset: u64,
    range: Option<(u64, u64)>,
    memstr: &str,
    compat_file: Option<&[u8]>,
) -> Vec<MemStrHit> {
    let mut sections = exec_search_sections(target);
    sections.extend(data_sections(target));
    if compat_file.is_some() {
        sections = sections
            .into_iter()
            .map(|sec| Section {
                bytes: compat_bytes(&sec, compat_file).into_owned(),
                ..sec
            })
            .collect();
    }
    let mut hits = Vec::new();
    for ch in memstr.chars() {
        let mut buf = [0u8; 4];
        let pat = ch.encode_utf8(&mut buf);
        let Ok(re) = byte_regex(pat) else {
            continue; // oracle: re.error swallowed by `except: pass`
        };
        'sections: for sec in &sections {
            let vaddr = sec.vaddr.wrapping_add(delta);
            let Some((start, ops)) = section_in_range(vaddr, &sec.bytes, range) else {
                continue;
            };
            if let Some(m) = re.find(ops) {
                hits.push(MemStrHit {
                    vaddr: offset.wrapping_add(start).wrapping_add(m.start() as u64),
                    ch,
                    site: HitSite::of(sec),
                });
                break 'sections; // the bare `raise`: first match only
            }
        }
    }
    hits
}

/// Human output for the three search modes (headers print even with zero
/// hits; there is no count line). Called only when not --silent.
pub fn print_string_hits(hits: &[StringHit], width8: bool, out: &mut dyn Write) {
    let _ = writeln!(out, "Strings information\n{RULE60}");
    for h in hits {
        let _ = writeln!(out, "{} : {}", fmt_search_addr(h.vaddr, width8), h.matched);
    }
}

pub fn print_opcode_hits(hits: &[OpcodeHit], hexstr: &str, width8: bool, out: &mut dyn Write) {
    let _ = writeln!(out, "Opcodes information\n{RULE60}");
    for h in hits {
        let _ = writeln!(out, "{} : {}", fmt_search_addr(h.vaddr, width8), hexstr);
    }
}

pub fn print_memstr_hits(hits: &[MemStrHit], width8: bool, out: &mut dyn Write) {
    let _ = writeln!(out, "Memory bytes information\n{RULE55}");
    for h in hits {
        let _ = writeln!(out, "{} : '{}'", fmt_search_addr(h.vaddr, width8), h.ch);
    }
}

/// JSON output (rop-finder extension; the oracle has no --json). vaddr is
/// the search-width-formatted hex string, matching the human output.
/// Column order for the CSV rendering of each search mode, and the field
/// order a reader can rely on.
///
/// CLI-05 / ECO-02: the shared v0.4 query spec fixes this vocabulary for
/// both front ends - `{vaddr, section, length, escaped preview, writable,
/// executable}`. `match` / `opcode` / `char` is the "escaped preview" slot,
/// named after what it previews; for `--string` it is already
/// printable-escaped by `printable_mapped`, exactly as the human line is.
pub const STRING_COLUMNS: &[&str] = &[
    "vaddr",
    "section",
    "length",
    "match",
    "writable",
    "executable",
];
pub const OPCODE_COLUMNS: &[&str] = &[
    "vaddr",
    "section",
    "length",
    "opcode",
    "writable",
    "executable",
];
pub const MEMSTR_COLUMNS: &[&str] = &[
    "vaddr",
    "section",
    "length",
    "char",
    "writable",
    "executable",
];

fn hit_object(
    vaddr: u64,
    width8: bool,
    length: usize,
    key: &str,
    value: serde_json::Value,
    site: &HitSite,
) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert("vaddr".into(), fmt_search_addr(vaddr, width8).into());
    m.insert("length".into(), length.into());
    m.insert(key.into(), value);
    m.insert(
        "section".into(),
        match &site.section {
            Some(n) => serde_json::Value::String(n.clone()),
            None => serde_json::Value::Null,
        },
    );
    m.insert("writable".into(), site.writable.into());
    m.insert("executable".into(), site.executable.into());
    serde_json::Value::Object(m)
}

pub fn search_json_string(hits: &[StringHit], width8: bool) -> serde_json::Value {
    hits.iter()
        .map(|h| {
            hit_object(
                h.vaddr,
                width8,
                h.matched.chars().count(),
                "match",
                h.matched.clone().into(),
                &h.site,
            )
        })
        .collect::<Vec<_>>()
        .into()
}

pub fn search_json_opcode(hits: &[OpcodeHit], hexstr: &str, width8: bool) -> serde_json::Value {
    let len = hexstr.len() / 2;
    hits.iter()
        .map(|h| hit_object(h.vaddr, width8, len, "opcode", hexstr.into(), &h.site))
        .collect::<Vec<_>>()
        .into()
}

pub fn search_json_memstr(hits: &[MemStrHit], width8: bool) -> serde_json::Value {
    hits.iter()
        .map(|h| {
            hit_object(
                h.vaddr,
                width8,
                h.ch.len_utf8(),
                "char",
                h.ch.to_string().into(),
                &h.site,
            )
        })
        .collect::<Vec<_>>()
        .into()
}

// ---------------------------------------------------------------------------
// Gadget post-filters (options.py).
// ---------------------------------------------------------------------------

/// options.py:64-98 `__reOption`. Split rule: if the pattern contains '|',
/// split on ' | ' (with spaces); when that yields one piece, split on '|'.
/// A gadget is kept iff EVERY pattern matches at least one instruction.
/// Invalid regex: the oracle dies with an uncaught re.error (exit 1); we
/// return a usage error (exit 1) — same code, clean message.
pub fn apply_re_filter(gadgets: &mut Vec<Gadget>, re: &str) -> Result<(), String> {
    let f = ReFilter::compile(re)?;
    gadgets.retain(|g| {
        let text = g.text();
        let insns: Vec<&str> = text.split(" ; ").collect();
        f.matches(&insns)
    });
    Ok(())
}

/// `--re`, compiled once.
///
/// ECO-09's streaming path applies `--re` per gadget as the scan runs, so
/// the patterns cannot be rebuilt inside the retain closure any more. This
/// is the same predicate [`apply_re_filter`] uses — it *is* what
/// `apply_re_filter` uses — so the streaming and buffered paths cannot
/// disagree about what `--re` means.
#[derive(Debug)]
pub struct ReFilter {
    pats: Vec<Regex>,
}

impl ReFilter {
    pub fn compile(re: &str) -> Result<ReFilter, String> {
        let pieces: Vec<&str> = if re.contains('|') {
            let spaced: Vec<&str> = re.split(" | ").collect();
            if spaced.len() == 1 {
                re.split('|').collect()
            } else {
                spaced
            }
        } else {
            vec![re]
        };
        let mut pats = Vec::with_capacity(pieces.len());
        for p in pieces {
            pats.push(Regex::new(p).map_err(|e| format!("invalid --re pattern {p:?}: {e}"))?);
        }
        Ok(ReFilter { pats })
    }

    /// Every pattern must match at least one instruction.
    pub fn matches(&self, insns: &[&str]) -> bool {
        self.pats
            .iter()
            .all(|p| insns.iter().any(|i| p.is_match(i)))
    }
}

/// options.py:100-120 `__isGadgetCallPreceded`, re-exported from the engine.
///
/// CLI-04/ECO-03: this used to be a second, subtly WRONG copy of the
/// predicate. `options.py:110` is `\xff` followed by FOUR wildcard bytes,
/// i.e. `0xff` five bytes back; the copy here tested four bytes back, so it
/// accepted `ff ?? ?? ??` (nothing ROPgadget calls a call) and rejected the
/// real five-byte `ff /r disp32` form. The engine owns the predicate now —
/// it also owns the `prev` bytes it is applied to, so the two halves cannot
/// drift apart again (rf-scan `engine.rs`).
pub use rf_scan::is_call_preceded;

// ---------------------------------------------------------------------------
// --mipsrop (core.py:118-157).
// ---------------------------------------------------------------------------

/// core.py:125-136 — the per-mode instruction regexes. `tails` has two; a
/// gadget matching both prints (and counts) twice.
pub fn mips_regexes(mode: &str) -> Option<Vec<&'static str>> {
    match mode {
        "stackfinder" => Some(vec![r"addiu .*, \$sp"]),
        "system" => Some(vec![r"addiu \$a0, \$sp"]),
        "tails" => Some(vec![
            r"lw \$t[0-9], 0x[0-9a-z]{0,4}\(\$s[0-9]",
            r"move \$t9, \$(s|a|v)",
        ]),
        "lia0" => Some(vec![r"li \$a0"]),
        "registers" => Some(vec![r"lw \$ra, 0x[0-9a-z]{0,4}\(\$sp"]),
        _ => None,
    }
}

pub fn compile_mips_regexes(mode: &str) -> Option<Vec<Regex>> {
    mips_regexes(mode).map(|rs| {
        rs.iter()
            .map(|r| Regex::new(r).expect("static mips regex compiles"))
            .collect()
    })
}

/// core.py:138-156 — the gadget loop (header printed by the caller BEFORE
/// the scan; count = matching prints, with tails double-counts).
pub fn print_mips_gadgets(
    gadgets: &[Gadget],
    regexes: &[Regex],
    dump: bool,
    width8: bool,
    out: &mut dyn Write,
) {
    let mut count = 0usize;
    for g in gadgets {
        let text = g.text();
        let insts = if text.is_empty() {
            String::new()
        } else {
            format!(" : {text}")
        };
        let bytes_str = if dump {
            format!(" // {}", g.bytes_hex())
        } else {
            String::new()
        };
        for re in regexes {
            if re.is_match(&text) {
                let _ = writeln!(
                    out,
                    "{}{}{}",
                    fmt_search_addr(g.vaddr, width8),
                    insts,
                    bytes_str
                );
                count += 1;
            }
        }
    }
    let _ = writeln!(out, "\nUnique gadgets found: {count}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_split_rule_mirrors_options_py() {
        // ' | ' split when it produces pieces; bare '|' otherwise.
        let mut gs = vec![];
        // no |: single pattern
        apply_re_filter(&mut gs, "pop").unwrap();
        // These would panic on invalid-regex pieces if split wrongly.
        apply_re_filter(&mut gs, "pop.*|mov.*").unwrap();
        apply_re_filter(&mut gs, "pop.* | mov.*").unwrap();
        assert!(apply_re_filter(&mut gs, "pop(").is_err());
    }

    #[test]
    fn call_preceded_suffixes() {
        // e8 at eff-5 and eff-9
        assert!(is_call_preceded(&[0xe8, 1, 2, 3, 4]));
        assert!(is_call_preceded(&[0xe8, 1, 2, 3, 4, 5, 6, 7, 8]));
        // ...but e8 at eff-3 is not a call pattern
        assert!(!is_call_preceded(&[1, 2, 3, 4, 5, 6, 0xe8, 8, 9]));
        // ff at eff-2
        assert!(is_call_preceded(&[9, 9, 0xff, 0x14]));
        // ff at eff-3 and eff-5 — options.py:108-111 is \xff followed by
        // 1, 2, 4 or 8 wildcard bytes, so eff-4 is NOT a call pattern.
        assert!(is_call_preceded(&[0xff, 1, 2]));
        assert!(!is_call_preceded(&[0xff, 1, 2, 3]));
        assert!(is_call_preceded(&[0xff, 1, 2, 3, 4]));
        // ff at eff-9
        assert!(is_call_preceded(&[0xff, 1, 2, 3, 4, 5, 6, 7, 8]));
        // no match
        assert!(!is_call_preceded(&[0x90, 0x90]));
        assert!(!is_call_preceded(&[]));
        // Python `$` also matches before a trailing 0x0a.
        assert!(is_call_preceded(&[0xff, 0x14, 0x0a]));
        // ...and the 0x0a itself still counts as a normal byte at the end.
        assert!(is_call_preceded(&[0xff, 0x0a]));
        assert!(!is_call_preceded(&[0x0a]));
    }

    #[test]
    fn section_in_range_truncation() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8];
        // no range → untouched
        assert_eq!(
            section_in_range(0x1000, &bytes, None),
            Some((0x1000, &bytes[..]))
        );
        // outside → None
        assert_eq!(
            section_in_range(0x1000, &bytes, Some((0x2000, 0x3000))),
            None
        );
        // start-truncation
        let (v, b) = section_in_range(0x1000, &bytes, Some((0x1002, 0x2000))).unwrap();
        assert_eq!(v, 0x1002);
        assert_eq!(b, &[3, 4, 5, 6, 7, 8]);
        // end-truncation (rangeEnd < sectionEnd cuts diff bytes)
        let (v, b) = section_in_range(0x1000, &bytes, Some((0x0, 0x1005))).unwrap();
        assert_eq!(v, 0x1000);
        assert_eq!(b, &[1, 2, 3, 4, 5]);
        // empty result → None
        assert_eq!(
            section_in_range(0x1000, &bytes, Some((0x1008, 0x1008))),
            None
        );
    }
}
