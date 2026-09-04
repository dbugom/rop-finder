//! CLI-05 / ECO-02, the MCP half — string, opcode and memory-string search,
//! confined to the MAPPED SECTIONS of the loaded image.
//!
//! # Why this is allowed now, and was not before
//!
//! The v0.2 flag allowlist blanket-rejects `--string` and `--memstr` on the
//! grounds that they are a file-read primitive: hand an agent a regex over
//! a file and it can exfiltrate the file. That reasoning was already
//! obsolete when it was written. `find_gadgets` returns the bytes of every
//! executable region of the binary, hex-encoded, one gadget at a time — an
//! agent that wants the .text of a confined file already has it. The ban
//! therefore cost a core capability (you cannot ask where `/bin/sh` is) and
//! bought nothing.
//!
//! What DOES hold the line the allowlist was drawn to protect is the scope
//! of the search, and it is enforced here rather than asserted:
//!
//! * The input is the LOADED IMAGE, never the file. Every candidate byte
//!   window comes from a [`rf_core::Section`] the loader materialised, so
//!   a match can only ever land inside a section that is mapped at runtime.
//! * There is no raw-file mode, no `--compat` (which is exactly the
//!   ROPgadget bug of reading `sh_offset` for an `SHT_NOBITS` section, i.e.
//!   bytes outside the section), and no way to name a file offset.
//! * Headers, symbol tables, string tables, debug info and everything else
//!   that is in the file but not in a mapped section are unreachable: they
//!   are not in any `Section` the loaders return.
//! * `range` and `offset` are honoured with the oracle's own
//!   `_sectionInRange` arithmetic, so a caller can only ever NARROW the
//!   window, never widen it.
//!
//! The confinement boundary itself is untouched: `binary_path` still goes
//! through [`crate::confine`], the file is still opened once as a handle,
//! and the size cap still applies.
//!
//! # Which sections, and why those
//!
//! Mirrors ROPgadget's own section sets (loaders/*.py), which is what makes
//! the MCP answer and the CLI answer the same answer:
//!
//! * `string` → the DATA sections: ELF `SHF_ALLOC && !SHF_EXECINSTR`, PE
//!   writable, Mach-O non-executable, raw none.
//! * `opcode` → the EXECUTABLE regions: the same regions the gadget scan
//!   walks.
//! * `memstr` → executable first, then data, and only the FIRST hit for
//!   each character (ROPgadget's bare `raise`).

use rf_core::Section;
use serde::{Deserialize, Serialize};

use crate::schema::ErrorCode;
use crate::ToolError;

/// The three search modes, as the wire spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `--string`: byte regex over the DATA sections.
    String,
    /// `--memstr`: each character located separately, first hit only, over
    /// executable-then-data sections.
    MemStr,
    /// `--opcode`: a hex byte sequence (with `??` wildcards) over the
    /// EXECUTABLE regions.
    Opcode,
}

impl Mode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::String => "string",
            Mode::MemStr => "memstr",
            Mode::Opcode => "opcode",
        }
    }
}

/// One match, in the shape ECO-02 asks for.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Hit {
    /// Zero-padded hex address, padded to the target's pointer width.
    pub vaddr: String,
    /// The same address as a number; do arithmetic on this, never on
    /// `vaddr`.
    pub vaddr_u64: u64,
    /// Name of the mapped section the match lies in. `null` only for a
    /// container whose sections are unnamed (a raw blob), never because
    /// the match was outside one — a match outside a section cannot exist.
    pub section: Option<String>,
    /// Length of the match in bytes.
    pub length: u64,
    /// The matched bytes, printable-escaped: printable ASCII verbatim,
    /// everything else as `\xNN` (and `\\` for a literal backslash), so the
    /// value is safe to print and unambiguous to parse. Capped at
    /// [`MAX_PREVIEW_BYTES`] source bytes.
    pub preview: String,
    /// The matched bytes, lowercase hex. Same cap as `preview`.
    pub bytes: String,
    /// Is the containing section writable at runtime? This is the field
    /// that decides whether an address is usable as a scratch buffer.
    pub writable: bool,
    /// Is the containing section executable at runtime?
    pub executable: bool,
    /// `memstr` only: the character this hit locates. `null` in every other
    /// mode — the field is always present, so one parser reads every
    /// response.
    pub matched_char: Option<String>,
}

/// The response of `find_string` and `find_bytes`.
///
/// Paged exactly like a gadget scan (ECO-09): `total_count` is the whole
/// match set, `hits` is one page of it, `next_cursor` walks the rest, and
/// `resource_uri` names the WHOLE set as NDJSON so an agent with its own
/// tools can stream it instead of making N calls.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchHitsResponse {
    /// This page of matches.
    pub hits: Vec<Hit>,
    /// `string`, `memstr` or `opcode` — which search ran.
    pub mode: String,
    /// The pattern, echoed as given.
    pub query: String,
    /// Matches before paging.
    pub total_count: u64,
    /// Matches in this page.
    pub returned: u64,
    /// Index of this page's first match within the ordered result.
    pub offset: u64,
    /// `total_count > offset + returned`.
    pub truncated: bool,
    /// Opaque token for the next page; `null` on the last one. Send it back
    /// as `cursor` with the SAME query parameters.
    pub next_cursor: Option<String>,
    /// The MAPPED sections this search actually read, in order — the
    /// confinement claim in the tool description, made checkable in the
    /// response. Nothing outside these windows was examined.
    pub sections_searched: Vec<String>,
    /// SHA-256 of the analysed file.
    pub binary_sha256: String,
    /// The binary's path relative to its allow root.
    pub binary_label: String,
    /// Non-fatal facts. Always present; `[]` when there are none.
    pub warnings: Vec<crate::schema::Warning>,
    /// `ropfinder://search/<key>/hits.ndjson` — the whole match set, one
    /// `Hit` per line, readable with `resources/read`. Present only when
    /// the result was paged.
    pub resource_uri: Option<String>,
    /// The same NDJSON as a real file, when the server was started with
    /// `--workspace-dir`.
    pub workspace_file: Option<String>,
}

/// Longest match rendered into `preview` / `bytes`. A `--string` regex can
/// match an arbitrarily long run; a record is a result, not a file dump.
pub const MAX_PREVIEW_BYTES: usize = 64;

/// Longest `string` / `memstr` pattern accepted. A regex is compiled with a
/// size limit as well; this bound is on the input itself.
pub const MAX_PATTERN_BYTES: usize = 1024;

/// Compiled-regex size cap, so a pathological pattern cannot be turned into
/// a large automaton inside the guard.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

fn usage(msg: impl Into<String>, details: serde_json::Value) -> ToolError {
    ToolError::with_details(ErrorCode::UsageError, msg, details)
}

/// Printable-escape a byte window.
#[must_use]
pub fn escape_preview(bytes: &[u8]) -> String {
    let take = bytes.len().min(MAX_PREVIEW_BYTES);
    let mut out = String::with_capacity(take + 8);
    for &b in bytes.iter().take(take) {
        match b {
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    if bytes.len() > take {
        out.push_str("...");
    }
    out
}

fn hex_of(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(MAX_PREVIEW_BYTES)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// ROPgadget `core.py:_sectionInRange` — narrow a section's window to
/// `range`, or drop it. `None` is "no range", which is the oracle's
/// `0x0-0x0` case.
fn section_in_range(vaddr: u64, bytes: &[u8], range: Option<(u64, u64)>) -> Option<(u64, &[u8])> {
    let Some((range_start, range_end)) = range else {
        return Some((vaddr, bytes));
    };
    let size = bytes.len() as u64;
    let section_end = vaddr.saturating_add(size);
    if range_end < vaddr || range_start > section_end {
        return None;
    }
    let mut start = vaddr;
    let mut ops = bytes;
    if range_start > start {
        let diff = usize::try_from(range_start - start).ok()?;
        ops = ops.get(diff..)?;
        start = range_start;
    }
    let end = start.saturating_add(ops.len() as u64);
    if range_end < end {
        let diff = usize::try_from(end - range_end).ok()?;
        ops = ops.get(..ops.len().checked_sub(diff)?)?;
    }
    if ops.is_empty() {
        return None;
    }
    Some((start, ops))
}

/// A mapped section, already slid by `--base` and paired with the flags a
/// hit reports.
pub struct Window {
    pub name: Option<String>,
    pub vaddr: u64,
    pub bytes: Vec<u8>,
    pub writable: bool,
    pub executable: bool,
}

fn window(sec: &Section, delta: u64) -> Window {
    Window {
        name: (!sec.name.is_empty()).then(|| sec.name.clone()),
        vaddr: sec.vaddr.wrapping_add(delta),
        bytes: sec.bytes.clone(),
        writable: sec.writable,
        executable: sec.executable,
    }
}

/// The DATA sections of a loaded image, in loader order (ROPgadget
/// `getDataSections`).
///
/// `slice` is the chosen Mach-O slice of a fat container. When it is
/// `Some` it is the ONLY thing searched, which is what stops a fat
/// container's overlapping address ranges from being concatenated into one
/// meaningless list (CORE-03).
#[must_use]
pub fn data_windows(
    target: &rf_api::Target,
    slice: Option<&rf_core::MachOBinary>,
    delta: u64,
) -> Vec<Window> {
    use rf_api::Target;
    if let Some(m) = slice {
        return m
            .sections()
            .iter()
            .filter(|s| !s.executable)
            .map(|s| window(s, delta))
            .collect();
    }
    match target {
        Target::Elf(b) => b
            .sections()
            .iter()
            .filter(|s| s.allocated && !s.executable)
            .map(|s| window(s, delta))
            .collect(),
        Target::Pe(b) => b
            .sections()
            .iter()
            .filter(|s| s.writable)
            .map(|s| window(s, delta))
            .collect(),
        Target::MachO(b) => b
            .sections()
            .iter()
            .filter(|s| !s.executable)
            .map(|s| window(s, delta))
            .collect(),
        // raw.py:35-36 — a raw blob declares no data sections.
        Target::Raw(_) => Vec::new(),
        Target::Universal(u) => u
            .slices()
            .iter()
            .flat_map(|m| m.sections().iter().filter(|s| !s.executable))
            .map(|s| window(s, delta))
            .collect(),
    }
}

/// The EXECUTABLE regions of a loaded image (ROPgadget `getExecSections`) —
/// exactly the regions the gadget scan walks.
#[must_use]
pub fn exec_windows(
    target: &rf_api::Target,
    slice: Option<&rf_core::MachOBinary>,
    delta: u64,
) -> Vec<Window> {
    use rf_api::Target;
    if let Some(m) = slice {
        return m
            .exec_scan_regions()
            .iter()
            .map(|s| window(s, delta))
            .collect();
    }
    match target {
        Target::Elf(b) => b
            .exec_scan_regions()
            .iter()
            .map(|s| window(s, delta))
            .collect(),
        Target::Pe(b) => b
            .exec_scan_regions()
            .iter()
            .map(|s| window(s, delta))
            .collect(),
        Target::MachO(b) => b
            .exec_scan_regions()
            .iter()
            .map(|s| window(s, delta))
            .collect(),
        Target::Raw(b) => vec![window(b.section(), delta)],
        Target::Universal(u) => u
            .all_exec_scan_regions()
            .into_iter()
            .map(|s| window(s, delta))
            .collect(),
    }
}

/// The names of the windows a search read, for
/// [`SearchHitsResponse::sections_searched`]. An unnamed region is reported
/// by its address so the list is never silently short.
#[must_use]
pub fn window_names(windows: &[Window]) -> Vec<String> {
    windows
        .iter()
        .map(|w| match &w.name {
            Some(n) => n.clone(),
            None => format!("0x{:x}", w.vaddr),
        })
        .collect()
}

/// A parsed `opcode` pattern: one entry per byte, `None` for a `??`
/// wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePattern(Vec<Option<u8>>);

impl BytePattern {
    /// Parse a hex byte sequence. `??` (or `..`) is a wildcard for one
    /// whole byte; spaces are ignored so `c9 c3` and `c9c3` are the same.
    /// Nibble-level wildcards are refused rather than silently widened.
    pub fn parse(spec: &str) -> Result<BytePattern, ToolError> {
        let compact: String = spec.chars().filter(|c| !c.is_whitespace()).collect();
        if compact.is_empty() {
            return Err(usage(
                "opcode must not be empty; pass a hex byte sequence such as \"c9c3\" \
                 (`??` matches any one byte)",
                serde_json::json!({"parameter": "opcode"}),
            ));
        }
        if compact.len() % 2 != 0 {
            return Err(usage(
                format!("opcode {spec:?} has an odd number of hex digits; bytes are two digits"),
                serde_json::json!({"parameter": "opcode", "got": spec}),
            ));
        }
        let chars: Vec<char> = compact.chars().collect();
        let mut out = Vec::with_capacity(chars.len() / 2);
        for pair in chars.chunks(2) {
            let (a, b) = (
                pair.first().copied().unwrap_or('?'),
                pair.get(1).copied().unwrap_or('?'),
            );
            if matches!((a, b), ('?', '?') | ('.', '.')) {
                out.push(None);
                continue;
            }
            let hi = a.to_digit(16);
            let lo = b.to_digit(16);
            match (hi, lo) {
                (Some(h), Some(l)) => out.push(Some((h as u8) << 4 | l as u8)),
                _ => {
                    return Err(usage(
                        format!(
                            "opcode {spec:?}: {a}{b} is not a hex byte and not the `??` \
                             wildcard; a wildcard covers a whole byte, not one nibble"
                        ),
                        serde_json::json!({"parameter": "opcode", "got": spec}),
                    ))
                }
            }
        }
        Ok(BytePattern(out))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Does this window of bytes match?
    #[must_use]
    pub fn matches(&self, w: &[u8]) -> bool {
        w.len() == self.0.len()
            && self
                .0
                .iter()
                .zip(w)
                .all(|(p, b)| p.is_none_or(|want| want == *b))
    }
}

/// Compile a `string` / `memstr` pattern as a BYTE regex, the way
/// ROPgadget does (`re.search` over `bytes`).
fn byte_regex(pattern: &str, parameter: &str) -> Result<regex::bytes::Regex, ToolError> {
    if pattern.is_empty() {
        return Err(usage(
            format!("{parameter} must not be empty"),
            serde_json::json!({"parameter": parameter}),
        ));
    }
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(usage(
            format!(
                "{parameter} is {} bytes; the limit is {MAX_PATTERN_BYTES}",
                pattern.len()
            ),
            serde_json::json!({"parameter": parameter, "limit": MAX_PATTERN_BYTES}),
        ));
    }
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| {
            usage(
                format!("{parameter} {pattern:?} is not a valid regex: {e}"),
                serde_json::json!({"parameter": parameter, "got": pattern}),
            )
        })
}

/// How a hit's address is rendered and how far the search may reach.
pub struct SearchOpts {
    /// `--base` slide already resolved to a delta.
    pub delta: u64,
    /// `--offset`, added to every reported address.
    pub offset: u64,
    /// `--range`, as `(start, end)` after the slide.
    pub range: Option<(u64, u64)>,
    /// Address padding width: 8 hex digits on a 32-bit target, 16 on a
    /// 64-bit one.
    pub addr_size: usize,
    /// Stop after this many hits and report the truncation.
    pub max_hits: usize,
}

fn fmt_addr(vaddr: u64, addr_size: usize) -> String {
    if addr_size == 4 {
        format!("0x{vaddr:08x}")
    } else {
        format!("0x{vaddr:016x}")
    }
}

fn hit(w: &Window, at: u64, bytes: &[u8], opts: &SearchOpts, ch: Option<char>) -> Hit {
    let vaddr = opts.offset.wrapping_add(at);
    Hit {
        vaddr: fmt_addr(vaddr, opts.addr_size),
        vaddr_u64: vaddr,
        section: w.name.clone(),
        length: bytes.len() as u64,
        preview: escape_preview(bytes),
        bytes: hex_of(bytes),
        writable: w.writable,
        executable: w.executable,
        matched_char: ch.map(|c| c.to_string()),
    }
}

/// `--string`: a byte regex over the DATA sections.
///
/// Each hit reports `pattern.len()` bytes from the match start, which is
/// ROPgadget's own `opcodes[ref:ref + len(s)]` — the pattern length, not
/// the match length, so `m..n` reports four bytes.
pub fn find_string(
    windows: &[Window],
    pattern: &str,
    opts: &SearchOpts,
) -> Result<(Vec<Hit>, u64), ToolError> {
    let re = byte_regex(pattern, "string")?;
    let mut hits = Vec::new();
    let mut total = 0u64;
    for w in windows {
        let Some((start, ops)) = section_in_range(w.vaddr, &w.bytes, opts.range) else {
            continue;
        };
        for m in re.find_iter(ops) {
            total += 1;
            if hits.len() >= opts.max_hits {
                continue;
            }
            let end = m.start().saturating_add(pattern.len()).min(ops.len());
            let window_bytes = ops.get(m.start()..end).unwrap_or_default();
            hits.push(hit(
                w,
                start.wrapping_add(m.start() as u64),
                window_bytes,
                opts,
                None,
            ));
        }
    }
    Ok((hits, total))
}

/// `--memstr`: locate each CHARACTER of the string separately, first hit
/// only, over executable-then-data sections.
///
/// A character whose bytes are not a valid regex is skipped, which is the
/// oracle's swallowed `re.error`.
pub fn find_memstr(windows: &[Window], memstr: &str, opts: &SearchOpts) -> (Vec<Hit>, u64) {
    let mut hits = Vec::new();
    for ch in memstr.chars() {
        let mut buf = [0u8; 4];
        let pat = ch.encode_utf8(&mut buf);
        let Ok(re) = regex::bytes::RegexBuilder::new(pat)
            .size_limit(REGEX_SIZE_LIMIT)
            .build()
        else {
            continue;
        };
        for w in windows {
            let Some((start, ops)) = section_in_range(w.vaddr, &w.bytes, opts.range) else {
                continue;
            };
            if let Some(m) = re.find(ops) {
                hits.push(hit(
                    w,
                    start.wrapping_add(m.start() as u64),
                    m.as_bytes(),
                    opts,
                    Some(ch),
                ));
                break; // the bare `raise`: first section, first match
            }
        }
    }
    let total = hits.len() as u64;
    hits.truncate(opts.max_hits);
    (hits, total)
}

/// `--opcode`: a byte sequence, `??`-wildcards allowed, over the
/// EXECUTABLE regions.
pub fn find_opcode(windows: &[Window], pat: &BytePattern, opts: &SearchOpts) -> (Vec<Hit>, u64) {
    let mut hits = Vec::new();
    let mut total = 0u64;
    for w in windows {
        let Some((start, ops)) = section_in_range(w.vaddr, &w.bytes, opts.range) else {
            continue;
        };
        if pat.len() > ops.len() {
            continue;
        }
        for (i, win) in ops.windows(pat.len()).enumerate() {
            if !pat.matches(win) {
                continue;
            }
            total += 1;
            if hits.len() >= opts.max_hits {
                continue;
            }
            hits.push(hit(w, start.wrapping_add(i as u64), win, opts, None));
        }
    }
    (hits, total)
}

/// One NDJSON line per hit, for the streaming resource (ECO-09).
#[must_use]
pub fn render_ndjson(hits: &[Hit]) -> String {
    let mut out = String::with_capacity(hits.len() * 160);
    for h in hits {
        if let Ok(line) = serde_json::to_string(h) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    // Panicking on a bad index is the desired behaviour in a test; the
    // crate-level deny exists to keep it out of the server.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    fn win(name: &str, vaddr: u64, bytes: &[u8], w: bool, x: bool) -> Window {
        Window {
            name: Some(name.to_string()),
            vaddr,
            bytes: bytes.to_vec(),
            writable: w,
            executable: x,
        }
    }

    fn opts() -> SearchOpts {
        SearchOpts {
            delta: 0,
            offset: 0,
            range: None,
            addr_size: 8,
            max_hits: 100,
        }
    }

    #[test]
    fn a_string_hit_reports_its_section_and_flags() {
        let ws = vec![win(".data", 0x600000, b"xx/bin/sh\0yy", true, false)];
        let (hits, total) = find_string(&ws, "/bin/sh", &opts()).unwrap();
        assert_eq!(total, 1);
        assert_eq!(hits.len(), 1);
        let h = &hits[0];
        assert_eq!(h.vaddr_u64, 0x600002);
        assert_eq!(h.vaddr, "0x0000000000600002");
        assert_eq!(h.section.as_deref(), Some(".data"));
        assert_eq!(h.length, 7);
        assert_eq!(h.preview, "/bin/sh");
        assert_eq!(h.bytes, "2f62696e2f7368");
        assert!(h.writable);
        assert!(!h.executable);
        assert!(h.matched_char.is_none());
    }

    /// The oracle reports `len(pattern)` bytes from the match start, not
    /// the match's own length — a regex like `m..n` prints four.
    #[test]
    fn the_reported_window_is_the_pattern_length() {
        let ws = vec![win(".rodata", 0x1000, b"__mmen__", false, false)];
        let (hits, _) = find_string(&ws, "m..n", &opts()).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].length, 4);
        assert_eq!(hits[0].preview, "mmen");
    }

    #[test]
    fn non_printable_bytes_are_escaped_unambiguously() {
        assert_eq!(escape_preview(b"a\x00b"), "a\\x00b");
        assert_eq!(escape_preview(b"a\\b"), "a\\\\b");
        assert_eq!(escape_preview(b"\t\n\r"), "\\t\\n\\r");
        let long = vec![b'A'; MAX_PREVIEW_BYTES + 10];
        let s = escape_preview(&long);
        assert!(s.ends_with("..."), "{s}");
        assert_eq!(s.len(), MAX_PREVIEW_BYTES + 3);
    }

    #[test]
    fn opcode_wildcards_cover_a_whole_byte() {
        let p = BytePattern::parse("c9??c3").unwrap();
        assert_eq!(p.len(), 3);
        assert!(p.matches(&[0xc9, 0x00, 0xc3]));
        assert!(p.matches(&[0xc9, 0xff, 0xc3]));
        assert!(!p.matches(&[0xc8, 0xff, 0xc3]));
        // Spacing is irrelevant.
        assert_eq!(
            BytePattern::parse("c9 c3").unwrap(),
            BytePattern::parse("c9c3").unwrap()
        );
        // A nibble wildcard is refused rather than silently widened.
        for bad in ["c?", "c9c", "zz", ""] {
            assert!(BytePattern::parse(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn opcode_searches_only_the_windows_it_is_given() {
        let ws = vec![
            win(".text", 0x401000, &[0x90, 0xc9, 0xc3, 0x90], false, true),
            win(".init", 0x400f00, &[0xc9, 0xc3], false, true),
        ];
        let p = BytePattern::parse("c9c3").unwrap();
        let (hits, total) = find_opcode(&ws, &p, &opts());
        assert_eq!(total, 2);
        let addrs: Vec<u64> = hits.iter().map(|h| h.vaddr_u64).collect();
        assert_eq!(addrs, vec![0x401001, 0x400f00]);
        assert!(hits.iter().all(|h| h.executable));
    }

    /// `range` can only narrow. A section entirely outside it disappears;
    /// one that straddles it is trimmed.
    #[test]
    fn range_narrows_and_never_widens() {
        let ws = vec![win(".data", 0x1000, b"AAAA/bin/shBBBB", true, false)];
        let mut o = opts();
        o.range = Some((0x1000, 0x1004));
        let (hits, _) = find_string(&ws, "/bin/sh", &o).unwrap();
        assert!(hits.is_empty(), "{hits:?}");
        o.range = Some((0x2000, 0x3000));
        let (hits, _) = find_string(&ws, "/bin/sh", &o).unwrap();
        assert!(hits.is_empty(), "{hits:?}");
        o.range = Some((0x1000, 0x1020));
        let (hits, _) = find_string(&ws, "/bin/sh", &o).unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn offset_shifts_reported_addresses() {
        let ws = vec![win(".data", 0x1000, b"/bin/sh", true, false)];
        let mut o = opts();
        o.offset = 0x10000;
        let (hits, _) = find_string(&ws, "/bin/sh", &o).unwrap();
        assert_eq!(hits[0].vaddr_u64, 0x11000);
    }

    /// `memstr` locates each character once, in the order the string gives
    /// them, taking the first section that has it.
    #[test]
    fn memstr_takes_the_first_hit_per_character() {
        let ws = vec![
            win(".text", 0x400000, b"..s..", false, true),
            win(".data", 0x600000, b"sh", true, false),
        ];
        let (hits, total) = find_memstr(&ws, "sh", &opts());
        assert_eq!(total, 2);
        assert_eq!(hits[0].matched_char.as_deref(), Some("s"));
        assert_eq!(hits[0].vaddr_u64, 0x400002, "exec section wins");
        assert_eq!(hits[1].matched_char.as_deref(), Some("h"));
        assert_eq!(hits[1].vaddr_u64, 0x600001);
    }

    /// A character that is nowhere simply has no hit; the call still
    /// succeeds, because "not present" is an answer.
    #[test]
    fn a_missing_character_is_not_an_error() {
        let ws = vec![win(".data", 0x1000, b"abc", true, false)];
        let (hits, _) = find_memstr(&ws, "az", &opts());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].matched_char.as_deref(), Some("a"));
    }

    #[test]
    fn max_hits_truncates_but_still_counts() {
        let ws = vec![win(".text", 0x1000, &[0x90; 100], false, true)];
        let mut o = opts();
        o.max_hits = 5;
        let p = BytePattern::parse("90").unwrap();
        let (hits, total) = find_opcode(&ws, &p, &o);
        assert_eq!(hits.len(), 5);
        assert_eq!(total, 100);
    }

    #[test]
    fn an_invalid_regex_is_a_usage_error_not_a_panic() {
        let ws = vec![win(".data", 0x1000, b"x", true, false)];
        let e = find_string(&ws, "([", &opts()).unwrap_err();
        assert_eq!(e.code, ErrorCode::UsageError);
        assert!(e.message.contains("not a valid regex"), "{e:?}");
        let e = find_string(&ws, "", &opts()).unwrap_err();
        assert_eq!(e.code, ErrorCode::UsageError);
    }

    #[test]
    fn ndjson_is_one_hit_per_line() {
        let ws = vec![win(".text", 0x1000, &[0x90, 0x90], false, true)];
        let p = BytePattern::parse("90").unwrap();
        let (hits, _) = find_opcode(&ws, &p, &opts());
        let text = render_ndjson(&hits);
        assert_eq!(text.lines().count(), 2);
        let first: Hit = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first.vaddr_u64, 0x1000);
    }
}
