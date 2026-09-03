//! ECO-09: output formats — `--format {human,json,jsonl,csv,raw}` — and the
//! streaming JSON-lines sink.
//!
//! # Why jsonl is not "json with newlines"
//!
//! `--format json` cannot start writing until the scan has finished, because
//! the listing is sorted alphabetically by gadget text (`rgutils.alphaSort`,
//! reproduced by [`rf_scan::post_process`]) and a sort has no first element
//! until it has every element. It then builds a second full copy of the
//! listing as `Vec<GadgetRecord>` and a third as one giant `String` before a
//! byte reaches the pipe. On a 600 K-gadget image that is what ECO-09 calls
//! "buffer and parse a multi-hundred-megabyte JSON array".
//!
//! `--format jsonl` gives up the alphabetical order — the one thing that
//! genuinely cannot be streamed — and keeps everything else. [`JsonlSink`]
//! is a [`rf_scan::GadgetSink`], so the scan hands it gadgets in traversal
//! order and each one is filtered, classified, serialized and written before
//! the next arrives. Nothing but the dedup key set is retained.
//!
//! **The order is the only difference.** The record *set* is identical to
//! `--format json`'s, and `jsonl_matches_json_as_a_set` in the crate's tests
//! is the thing that keeps it identical: dedup, `--only`, `--range`,
//! `--badbytes` and `--cfg-aware` are not reimplemented here, they are
//! [`rf_scan::post_process`] applied one gadget at a time.
//!
//! # What still buffers
//!
//! `--rank`, `--cache` and `--mipsrop` each need the whole listing before
//! they can emit anything (a global sort, a stored `Vec`, a header printed
//! before the count). Combined with `--format jsonl` they produce the same
//! JSONL bytes from the buffered path, in ranked/alphabetical order. That is
//! a fallback, not a silent one: [`can_stream`] is the single predicate that
//! decides, and the manual says so.

use std::collections::HashSet;
use std::io::Write;

use rf_classify::Classification;
use rf_core::Arch;
use rf_scan::{Gadget, GadgetSink, ScanOptions};
use serde::Serialize;

use crate::query::Query;
use crate::search::ReFilter;

/// `--format`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutFormat {
    /// ROPgadget's text listing (`Gadgets information`, the 60-column rule,
    /// `Unique gadgets found: N`). The default, and the only format the
    /// oracle has.
    #[default]
    Human,
    /// One pretty-printed JSON array.
    Json,
    /// One JSON object per line, streamed — see the module docs.
    Jsonl,
    /// RFC 4180 CSV with a fixed header row.
    Csv,
    /// Undecorated listing: no header, no rule, no count line, one gadget
    /// per line. `--format raw --noinstr` is the address-only mode ECO-09
    /// asks for; the two flags stay orthogonal rather than growing a third.
    Raw,
}

impl OutFormat {
    pub const ALL: &'static [&'static str] = &["human", "json", "jsonl", "csv", "raw"];

    pub fn parse(s: &str) -> Option<OutFormat> {
        Some(match s {
            "human" => OutFormat::Human,
            "json" => OutFormat::Json,
            "jsonl" => OutFormat::Jsonl,
            "csv" => OutFormat::Csv,
            "raw" => OutFormat::Raw,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            OutFormat::Human => "human",
            OutFormat::Json => "json",
            OutFormat::Jsonl => "jsonl",
            OutFormat::Csv => "csv",
            OutFormat::Raw => "raw",
        }
    }

    /// Does this format carry the `--classify` fields and the `section` /
    /// `arch` columns? (`human` and `raw` are line-oriented text.)
    pub fn is_structured(self) -> bool {
        matches!(self, OutFormat::Json | OutFormat::Jsonl | OutFormat::Csv)
    }
}

/// `--chain-format`: how `--ropchain` renders its result (ECO-09 part 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChainFormat {
    /// The generated Python exploit script.
    #[default]
    Python,
    /// The JSON Chain IR.
    Json,
    /// [`rf_chain::RopChain::to_bytes`] — the packed little-endian payload,
    /// written to stdout as bytes. Documented at MANUAL.md since v0.1 and
    /// reachable from no interface until now.
    Raw,
}

impl ChainFormat {
    pub const ALL: &'static [&'static str] = &["python", "json", "raw"];

    pub fn parse(s: &str) -> Option<ChainFormat> {
        Some(match s {
            "python" => ChainFormat::Python,
            "json" => ChainFormat::Json,
            "raw" => ChainFormat::Raw,
            _ => return None,
        })
    }
}

/// One gadget as the structured formats see it.
///
/// The v0.3 field set is unchanged and still gated on `--classify`; the
/// v0.4 additions are the semantic fields a constraint query filters on, so
/// that `--set-reg rdi --from-stack --format json --classify` can be checked
/// by reading its own output instead of trusting the filter.
#[derive(Serialize)]
pub struct GadgetRecord<'a> {
    pub vaddr: String,
    pub bytes: String,
    pub text: String,
    /// Scan architecture — present for Universal (multi-slice) binaries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<&'static str>,
    /// Name of the section containing the gadget — present when --section
    /// was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// Phase 5 --classify fields (TAXONOMY.md).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regs_written: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regs_read: Option<&'a [String]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side_effects: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quality: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatcher: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low_confidence: Option<bool>,
    // ---- v0.4 (CLS-09) semantic fields, additive ----
    /// Registers whose final value the chain payload decides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sets: Option<&'a [String]>,
    /// Registers written with a value the payload does *not* decide. Not a
    /// synonym for "unusable": `mov rdi, rax ; ret` clobbers rdi and still
    /// records the transfer `rdi <- rax`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clobbers: Option<&'a [String]>,
    /// Registers loaded straight off the payload (`--from-stack`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regs_from_stack: Option<&'a [String]>,
    /// Bytes the stack pointer moves, terminator included. `null` means
    /// *unknown*, never zero.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_delta: Option<Option<i64>>,
    /// v0.3's coarse terminator (`ret`, `jmp`, `call`, `syscall`, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminator: Option<&'static str>,
    /// CLS-09's nine-way terminator classification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminator_class: Option<&'static str>,
}

/// Everything a record needs that is not the gadget itself.
pub struct RecordCtx<'a> {
    pub addr_size: usize,
    /// `--offset`, already applied to `Gadget::vaddr`; subtracted again to
    /// look a gadget up in the `--section` table.
    pub offset: u64,
    pub universal_arch: Option<Arch>,
    pub selected_sections: Option<&'a [(String, u64, u64)]>,
    /// `--classify`: emit the semantic fields.
    pub classify: bool,
}

pub fn record<'a>(
    g: &Gadget,
    c: Option<&'a Classification>,
    ctx: &RecordCtx<'a>,
) -> GadgetRecord<'a> {
    let c = c.filter(|_| ctx.classify);
    GadgetRecord {
        vaddr: crate::fmt_addr(g.vaddr, ctx.addr_size),
        bytes: g.bytes_hex(),
        text: g.text(),
        arch: ctx.universal_arch.map(crate::arch_name),
        section: ctx
            .selected_sections
            .and_then(|s| crate::section_of(s, g.vaddr.wrapping_sub(ctx.offset))),
        class: c.map(|c| c.primary.name()),
        labels: c.map(|c| c.labels.iter().map(|l| l.name()).collect()),
        regs_written: c.map(|c| c.regs_written.as_slice()),
        regs_read: c.map(|c| c.regs_read.as_slice()),
        side_effects: c.map(|c| c.side_effects),
        quality: c.map(|c| c.quality),
        dispatcher: c.map(|c| c.dispatcher),
        low_confidence: c.map(|c| c.low_confidence),
        sets: c.map(|c| c.sets.as_slice()),
        clobbers: c.map(|c| c.clobbers.as_slice()),
        regs_from_stack: c.map(|c| c.regs_from_stack.as_slice()),
        stack_delta: c.map(|c| c.stack_delta),
        terminator: c.map(|c| c.terminator().name()),
        terminator_class: c.map(|c| c.terminator_class().name()),
    }
}

/// The CSV header. Fixed, so a consumer can bind columns by position; a
/// column that does not apply to this run is an empty cell, never absent.
pub const CSV_HEADER: &str = "vaddr,bytes,text,arch,section,class,labels,regs_written,regs_read,\
sets,clobbers,regs_from_stack,side_effects,quality,stack_delta,terminator,terminator_class,\
dispatcher,low_confidence";

/// RFC 4180 field quoting: quote when the value contains `"`, `,`, CR or LF,
/// doubling any embedded quote.
fn csv_field(s: &str) -> String {
    if s.contains(['"', ',', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

fn join(v: Option<&[String]>) -> String {
    v.map(|v| v.join(" ")).unwrap_or_default()
}

/// Join pre-escaped cells into one RFC 4180 row.
pub fn csv_join(cells: &[String]) -> String {
    cells
        .iter()
        .map(|c| csv_field(c))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn csv_row(r: &GadgetRecord<'_>) -> String {
    let cells: Vec<String> = vec![
        r.vaddr.clone(),
        r.bytes.clone(),
        r.text.clone(),
        r.arch.unwrap_or("").to_string(),
        r.section.clone().unwrap_or_default(),
        r.class.unwrap_or("").to_string(),
        r.labels.as_ref().map(|l| l.join(" ")).unwrap_or_default(),
        join(r.regs_written),
        join(r.regs_read),
        join(r.sets),
        join(r.clobbers),
        join(r.regs_from_stack),
        r.side_effects.map(|v| v.to_string()).unwrap_or_default(),
        r.quality.map(|v| v.to_string()).unwrap_or_default(),
        // Flatten Option<Option<i64>>: absent (no --classify) and unknown
        // both render as an empty cell, which is CSV's only null.
        r.stack_delta
            .flatten()
            .map(|v| v.to_string())
            .unwrap_or_default(),
        r.terminator.unwrap_or("").to_string(),
        r.terminator_class.unwrap_or("").to_string(),
        r.dispatcher.map(|v| v.to_string()).unwrap_or_default(),
        r.low_confidence.map(|v| v.to_string()).unwrap_or_default(),
    ];
    csv_join(&cells)
}

/// One `--format raw` line: `<addr>[ : text][ // bytes]`, no decoration.
pub fn raw_line(g: &Gadget, addr_size: usize, noinstr: bool, dump: bool) -> String {
    let mut s = crate::fmt_addr(g.vaddr, addr_size);
    if !noinstr {
        s.push_str(" : ");
        s.push_str(&g.text());
    }
    if dump {
        s.push_str(" // ");
        s.push_str(&g.bytes_hex());
    }
    s
}

/// The per-gadget half of the post-scan pipeline, shared by the streaming
/// and buffered paths so the two cannot answer differently.
pub struct GadgetFilters<'a> {
    /// `--re`, pre-compiled.
    pub re: Option<&'a ReFilter>,
    /// `--callPreceded`, already known to be applicable to this arch.
    pub call_preceded: bool,
    /// The v0.3 + v0.4 constraint query.
    pub query: &'a Query,
    /// Classify every gadget (needed by `--classify` output as well as by a
    /// non-empty query).
    pub classify: Option<&'a rf_classify::Classifier>,
}

impl GadgetFilters<'_> {
    /// Apply `--re`, `--callPreceded` and the constraint query to one
    /// gadget, returning its classification when one was computed.
    ///
    /// `None` means "dropped".
    pub fn keep(&self, g: &Gadget) -> Option<Option<Classification>> {
        let text = g.text();
        let insns: Vec<&str> = text.split(" ; ").collect();
        if let Some(re) = self.re {
            if !re.matches(&insns) {
                return None;
            }
        }
        if self.call_preceded && !g.prev.as_deref().is_some_and(rf_scan::is_call_preceded) {
            return None;
        }
        let Some(classifier) = self.classify else {
            return Some(None);
        };
        let c = classifier.classify(g);
        if !self.query.matches(&c, &insns) {
            return None;
        }
        Some(Some(c))
    }
}

/// Is the streaming path available for this run?
///
/// `--format jsonl` is the only streaming format (the others are ordered
/// alphabetically and a sort cannot start early), and three flags each need
/// the whole listing in hand: `--rank` sorts globally, `--cache` stores and
/// replays a `Vec`, and `--mipsrop` prints its own header and count.
pub fn can_stream(format: OutFormat, rank: bool, cache: bool, mipsrop: bool) -> bool {
    format == OutFormat::Jsonl && !rank && !cache && !mipsrop
}

/// A [`GadgetSink`] that writes one JSON object per accepted gadget, in scan
/// order, and keeps nothing but the dedup key set.
pub struct JsonlSink<'a> {
    out: &'a mut dyn Write,
    opts: &'a ScanOptions,
    addr_size: usize,
    ctx: RecordCtx<'a>,
    filters: GadgetFilters<'a>,
    /// Dedup keys. `first-occurrence-wins in traversal order` is exactly
    /// what a set-insert over the sink's input stream does, so this is the
    /// same rule `post_process` applies — not an approximation of it.
    seen: HashSet<String>,
    dedup: bool,
    /// Every gadget the scan offered, which is what `--max-gadgets` and
    /// `--max-memory` are counted against on the buffered path too.
    offered: usize,
    retained_bytes: usize,
    /// `--callPreceded`'s "Filtered out N" line is a count over the whole
    /// listing, so it can only be printed at the end here.
    call_preceded_dropped: usize,
}

impl<'a> JsonlSink<'a> {
    pub fn new(
        out: &'a mut dyn Write,
        opts: &'a ScanOptions,
        addr_size: usize,
        ctx: RecordCtx<'a>,
        filters: GadgetFilters<'a>,
    ) -> Self {
        JsonlSink {
            out,
            opts,
            addr_size,
            ctx,
            filters,
            seen: HashSet::new(),
            dedup: !opts.all && !opts.noinstr,
            offered: 0,
            retained_bytes: 0,
            call_preceded_dropped: 0,
        }
    }

    pub fn call_preceded_dropped(&self) -> usize {
        self.call_preceded_dropped
    }

    /// The engine-owned filters (`--only`, the second `--range` pass,
    /// `--badbytes`, `--cfg-aware`), applied one gadget at a time.
    ///
    /// This calls [`rf_scan::post_process`] rather than reimplementing it.
    /// A second copy of those four predicates in the front end is the exact
    /// defect shape CLI-04/ECO-03 found in the `--callPreceded` heuristic,
    /// and a `--badbytes` mask that disagreed with the buffered path would
    /// be invisible in review.
    fn engine_filters(&self, g: Gadget) -> Option<Gadget> {
        rf_scan::post_process(vec![g], self.opts, self.addr_size)
            .ok()?
            .pop()
    }
}

impl GadgetSink for JsonlSink<'_> {
    fn accept(&mut self, g: Gadget) -> Result<(), rf_scan::Error> {
        self.offered += 1;
        // `--max-gadgets` / `--max-memory` count what the scan produced, as
        // `BoundedSink` does, so the same command reports the same budget
        // whichever format it is asked for.
        if let Some(limit) = self.opts.max_gadgets {
            if self.offered > limit {
                return Err(rf_scan::Error::Budget {
                    produced: self.offered - 1,
                    limit,
                });
            }
        }
        let add = rf_scan::sink::gadget_bytes(&g);
        if let Some(limit) = self.opts.max_memory {
            if self.retained_bytes + add > limit {
                return Err(rf_scan::Error::Budget {
                    produced: self.offered - 1,
                    limit,
                });
            }
        }
        self.retained_bytes += add;

        // Dedup BEFORE the address-dependent filters, because that is the
        // order `post_process` uses: two gadgets with the same text but
        // different addresses collapse to the first, and if that first one
        // is then rejected by `--badbytes` the text is gone. Filtering first
        // would resurrect the second and silently return a gadget the
        // buffered path does not.
        if self.dedup && !self.seen.insert(g.text()) {
            return Ok(());
        }
        let Some(g) = self.engine_filters(g) else {
            return Ok(());
        };
        let cp = self.filters.call_preceded;
        let Some(c) = self.filters.keep(&g) else {
            if cp && !g.prev.as_deref().is_some_and(rf_scan::is_call_preceded) {
                self.call_preceded_dropped += 1;
            }
            return Ok(());
        };
        let r = record(&g, c.as_ref(), &self.ctx);
        // Serialization of this structure cannot fail; a write failure is
        // recorded by `Out` and surfaced once, at the end of the run.
        if let Ok(line) = serde_json::to_string(&r) {
            let _ = writeln!(self.out, "{line}");
        }
        Ok(())
    }

    fn accepted(&self) -> usize {
        self.offered
    }

    fn remaining(&self) -> Option<usize> {
        self.opts
            .max_gadgets
            .map(|m| m.saturating_sub(self.offered))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_vocabulary_round_trips() {
        for name in OutFormat::ALL {
            let f = OutFormat::parse(name).expect(name);
            assert_eq!(f.name(), *name);
        }
        assert_eq!(OutFormat::parse("yaml"), None);
        assert_eq!(OutFormat::default(), OutFormat::Human);
        assert_eq!(ChainFormat::parse("raw"), Some(ChainFormat::Raw));
        assert_eq!(ChainFormat::parse("c"), None);
        assert_eq!(ChainFormat::default(), ChainFormat::Python);
    }

    #[test]
    fn csv_quotes_what_rfc4180_requires() {
        assert_eq!(csv_field("ret"), "ret");
        // Gadget text contains commas: `mov rax, rbx`.
        assert_eq!(csv_field("mov rax, rbx"), "\"mov rax, rbx\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("a\nb"), "\"a\nb\"");
        // The header must have exactly as many columns as a row.
        let g = Gadget {
            vaddr: 0x401648,
            bytes: vec![0x5f, 0xc3],
            insns: vec!["pop rdi".into(), "ret".into()],
            delay_slot: false,
            prev: None,
            table: rf_scan::TableKind::Rop,
        };
        let ctx = RecordCtx {
            addr_size: 8,
            offset: 0,
            universal_arch: None,
            selected_sections: None,
            classify: false,
        };
        let row = csv_row(&record(&g, None, &ctx));
        // `pop rdi ; ret` has no comma, so no cell is quoted here and a
        // plain split is a faithful column count.
        assert!(!row.contains('"'), "{row}");
        assert_eq!(
            row.split(',').count(),
            CSV_HEADER.split(',').count(),
            "row {row} does not have {} columns",
            CSV_HEADER.split(',').count()
        );
        // ...and a gadget whose text DOES contain a comma still produces
        // exactly one cell for it.
        let g2 = Gadget {
            insns: vec!["mov rax, rbx".into(), "ret".into()],
            ..g
        };
        let row2 = csv_row(&record(&g2, None, &ctx));
        assert!(row2.contains("\"mov rax, rbx ; ret\""), "{row2}");
    }

    #[test]
    fn raw_line_is_undecorated_and_composes_with_noinstr() {
        let g = Gadget {
            vaddr: 0x401648,
            bytes: vec![0x5f, 0xc3],
            insns: vec!["pop rdi".into(), "ret".into()],
            delay_slot: false,
            prev: None,
            table: rf_scan::TableKind::Rop,
        };
        assert_eq!(
            raw_line(&g, 8, false, false),
            "0x0000000000401648 : pop rdi ; ret"
        );
        // ECO-09's "address-only mode", composed rather than added.
        assert_eq!(raw_line(&g, 8, true, false), "0x0000000000401648");
        assert_eq!(raw_line(&g, 8, true, true), "0x0000000000401648 // 5fc3");
    }

    #[test]
    fn streaming_is_refused_where_it_would_be_wrong() {
        assert!(can_stream(OutFormat::Jsonl, false, false, false));
        assert!(!can_stream(OutFormat::Json, false, false, false));
        assert!(!can_stream(OutFormat::Jsonl, true, false, false));
        assert!(!can_stream(OutFormat::Jsonl, false, true, false));
        assert!(!can_stream(OutFormat::Jsonl, false, false, true));
    }
}
