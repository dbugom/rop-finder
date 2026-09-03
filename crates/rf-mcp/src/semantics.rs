//! CLS-08 — the classification, kept rather than thrown away, and made
//! queryable.
//!
//! `rf_classify` computes a primary class, a full label set, `regs_written`,
//! `regs_read`, `regs_from_stack`, a side-effect count, a terminator, a
//! quality score and a usability tier for every gadget. The server computed
//! all of that at scan time, stored exactly two fields of it, and exposed
//! none of it as a filter — so the tool's most common real question ("a
//! gadget that loads rdi from the stack without touching rsi or rdx") could
//! only be answered by pulling thousands of gadgets into the agent's context
//! and filtering them there, which is the failure mode an MCP server exists
//! to prevent.
//!
//! This module holds the per-gadget semantic record, the predicate over it,
//! and the orderings. It also removes the on-demand reclassification path
//! that `sort_by: "quality"` used, which is where the ROB-04 char-boundary
//! panic lived: nothing here ever re-derives semantics from a response.

use rf_cache::{CachedGadget, CachedScan};
use rf_classify::{Class, Classification, Classifier, RankKey, TerminatorClass};
use rf_core::Arch;
use serde_json::json;

use crate::schema::ErrorCode;
use crate::ToolError;

/// Every value the `class` filter accepts — `rf_classify::Class::name()`.
pub const CLASS_NAMES: &[&str] = &[
    "reg-write",
    "stack-pivot",
    "mem-read",
    "mem-write",
    "arithmetic",
    "syscall",
    "dispatcher",
    "other",
];

/// Every value the `terminator` filter accepts. These are
/// `Terminator::kind()` values — every returning form (`ret`, `ret imm16`,
/// `retf`, `iret`, a far transfer) collapses to `ret`, because the question
/// an agent asks is "can this gadget hand control to the next word of my
/// chain", not "which encoding".
pub const TERMINATOR_KINDS: &[&str] = &["ret", "jmp", "call", "syscall", "none", "any"];

/// The FINE terminator vocabulary the `terminator` parameter also accepts
/// (CLS-09's [`TerminatorClass`]): `ret-imm`, `jmp-reg`, `jmp-mem`,
/// `call-reg`, `call-mem`, `far`, `other`.
///
/// `terminator` therefore takes a union: the six coarse kinds above answer
/// "can this hand control to the next word of my chain", and these answer
/// "how, exactly" — `jmp-reg` is a JOP dispatcher target and `jmp-mem` is
/// not, and no coarse kind separates them. A value is looked up in the
/// coarse set first, so `ret` keeps meaning *every* returning form and
/// `ret-imm` narrows it.
pub const TERMINATOR_CLASSES: &[&str] = TerminatorClass::ALL;

/// The spelling for the NARROW near return, [`TerminatorClass::Ret`].
///
/// `ret` is taken by the coarse kind — deliberately, because the shared
/// query spec names `ret` and a user typing the spec's word must never
/// silently get less than every returning form. That leaves
/// `TerminatorClass::Ret` (the bare `c3`, excluding `ret imm16`, `retf`
/// and `iret`) with no name at all, which is a capability the CLI had and
/// this surface did not: `--terminator bare-ret` answered on one side and
/// was a usage error on the other. Same token, same meaning, both sides.
pub const TERMINATOR_BARE_RET: &str = "bare-ret";

/// Every accepted `terminator` value, coarse then fine, for an error
/// message.
#[must_use]
pub fn terminator_vocabulary() -> Vec<&'static str> {
    let mut v: Vec<&'static str> = TERMINATOR_KINDS.to_vec();
    v.push(TERMINATOR_BARE_RET);
    for f in TERMINATOR_CLASSES {
        if !v.contains(f) {
            v.push(f);
        }
    }
    v
}

// ---------------------------------------------------------------------------
// The per-gadget record
// ---------------------------------------------------------------------------

/// Everything the classifier learned about one cached gadget, plus its
/// stable id and its rank key.
///
/// Index-aligned with [`CachedScan::gadgets`]: `sems[i]` describes
/// `scan.gadgets[i]`.
#[derive(Debug, Clone)]
pub struct Semantics {
    /// Stable id (`crate::schema::gadget_id`).
    pub id: String,
    pub vaddr: u64,
    /// Raw gadget bytes, kept because `get_gadgets` and the NDJSON resource
    /// both need them and re-decoding the hex per request is pure waste.
    pub bytes: Vec<u8>,
    pub insns: Vec<String>,
    pub delay_slot: bool,
    /// `None` when the record could not be reconstructed (a corrupt cache
    /// entry) or the architecture has no classifier.
    pub class: Option<Classification>,
    /// The default order's key. Tier 0 / quality 0 for an unclassifiable
    /// gadget, so it sorts last rather than first.
    pub rank: RankKey,
}

/// Fixed cost charged to every [`Semantics`] record by
/// [`Semantics::heap_bytes`]: the struct plus the allocation headers for
/// its four owned collections. The same estimating convention as
/// [`rf_cache::GADGET_OVERHEAD_BYTES`], which exists for the same reason —
/// a budget only has to be proportional to what is really retained and
/// never smaller than the fixed per-record cost.
pub const SEMANTICS_OVERHEAD_BYTES: usize = 160;

impl Semantics {
    /// Retained heap size, the eviction weight of the pinned-scan store.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        let strs = |v: &[String]| v.iter().map(|s| s.len() + 24).sum::<usize>();
        SEMANTICS_OVERHEAD_BYTES
            + self.id.len()
            + self.bytes.len()
            + strs(&self.insns)
            + self.class.as_ref().map_or(0, |c| {
                strs(&c.regs_written)
                    + strs(&c.regs_read)
                    + strs(&c.regs_from_stack)
                    + strs(&c.sets)
                    + strs(&c.clobbers)
                    + c.labels.len() * 8
                    + c.transfers.len() * 96
            })
    }

    #[must_use]
    pub fn labels(&self) -> Vec<&'static str> {
        self.class
            .as_ref()
            .map(|c| c.labels.iter().map(|l| l.name()).collect())
            .unwrap_or_default()
    }

    #[must_use]
    pub fn primary(&self) -> Option<&'static str> {
        self.class.as_ref().map(|c| c.primary.name())
    }

    #[must_use]
    pub fn regs_written(&self) -> &[String] {
        self.class.as_ref().map_or(&[], |c| &c.regs_written)
    }

    #[must_use]
    pub fn regs_read(&self) -> &[String] {
        self.class.as_ref().map_or(&[], |c| &c.regs_read)
    }

    /// The `reads_reg` predicate, which is NOT `regs_read().contains()`.
    ///
    /// `regs_read` keeps the operand's own spelling (`al`, not `rax`) and
    /// says nothing about the terminator, so the containment test this used
    /// to be missed every JOP dispatcher: `jmp rax` reads rax and did not
    /// answer `reads_reg: "rax"`. Measured against the CLI's `--reads-reg`
    /// on elf-Linux-x64 at depth 4, the two surfaces returned 2147 and 2888
    /// gadgets for the same question. Both now call the one predicate on
    /// [`rf_classify::Classification`].
    #[must_use]
    pub fn reads_reg(&self, reg: &str) -> bool {
        self.class.as_ref().is_some_and(|c| c.reads_reg(reg))
    }

    #[must_use]
    pub fn regs_from_stack(&self) -> &[String] {
        self.class.as_ref().map_or(&[], |c| &c.regs_from_stack)
    }

    #[must_use]
    pub fn side_effects(&self) -> u32 {
        self.class
            .as_ref()
            .map_or(0, |c| u32::try_from(c.side_effects).unwrap_or(u32::MAX))
    }

    #[must_use]
    pub fn quality(&self) -> i32 {
        self.class.as_ref().map_or(0, |c| c.quality)
    }

    #[must_use]
    pub fn low_confidence(&self) -> bool {
        self.class.as_ref().is_none_or(|c| c.low_confidence)
    }

    #[must_use]
    pub fn dispatcher(&self) -> bool {
        self.class.as_ref().is_some_and(|c| c.dispatcher)
    }

    #[must_use]
    pub fn privileged(&self) -> bool {
        self.class.as_ref().is_some_and(|c| c.privileged)
    }

    /// Full terminator spelling (`ret-imm`, `retf`, …).
    #[must_use]
    pub fn terminator(&self) -> &'static str {
        self.class
            .as_ref()
            .map_or("none", |c| c.terminator().name())
    }

    /// Coarse terminator kind (`ret`, `jmp`, `call`, `syscall`, `none`).
    #[must_use]
    pub fn terminator_kind(&self) -> &'static str {
        self.class
            .as_ref()
            .map_or("none", |c| c.terminator().kind())
    }

    /// CLS-09's nine-way terminator class (`ret`, `ret-imm`, `jmp-reg`,
    /// `jmp-mem`, `call-reg`, `call-mem`, `syscall`, `far`, `other`).
    #[must_use]
    pub fn terminator_class(&self) -> &'static str {
        self.class
            .as_ref()
            .map_or("other", |c| c.terminator_class().name())
    }

    /// CLS-09 `sets`: registers written with a value the chain payload
    /// decides. NOT `regs_written` — see [`Semantics::clobbers`].
    #[must_use]
    pub fn sets(&self) -> &[String] {
        self.class.as_ref().map_or(&[], |c| &c.sets)
    }

    /// CLS-09 `clobbers`: registers written with a value the payload does
    /// not decide. `mov rdi, rax ; ret` clobbers rdi — which does not make
    /// the gadget unusable, only dependent on rax.
    #[must_use]
    pub fn clobbers(&self) -> &[String] {
        self.class.as_ref().map_or(&[], |c| &c.clobbers)
    }

    /// CLS-09 net stack-pointer movement. `None` is UNKNOWN, never zero.
    #[must_use]
    pub fn stack_delta(&self) -> Option<i64> {
        self.class.as_ref().and_then(|c| c.stack_delta)
    }

    /// Does the payload decide `reg`'s final value (`--set-reg`)?
    #[must_use]
    pub fn sets_reg(&self, reg: &str) -> bool {
        self.class.as_ref().is_some_and(|c| c.sets_reg(reg))
    }

    /// Is `reg` loaded straight off the chain payload (`--from-stack`)?
    #[must_use]
    pub fn reg_from_stack(&self, reg: &str) -> bool {
        self.class.as_ref().is_some_and(|c| c.reg_from_stack(reg))
    }

    /// Payload offset, in bytes from entry sp, that supplies `reg`.
    #[must_use]
    pub fn stack_offset_of(&self, reg: &str) -> Option<i64> {
        self.class.as_ref().and_then(|c| c.stack_offset_of(reg))
    }

    /// Does the gadget clobber `reg` (`--no-clobber`)?
    #[must_use]
    pub fn clobbers_reg(&self, reg: &str) -> bool {
        self.class.as_ref().is_some_and(|c| c.clobbers_reg(reg))
    }
}

/// Everything the stable id is computed from besides the gadget itself.
///
/// `offset` is `--offset`, which the engine has already ADDED to every
/// reported address. Subtracting it again is what makes an id independent
/// of that parameter: the same gadget scanned with and without
/// `--offset 0x1000` gets one id. `--base` is deliberately NOT undone — it
/// relabels the whole image, and two different base addresses really are
/// two different address spaces to reason about.
#[derive(Debug, Clone, Copy)]
pub struct IdContext<'a> {
    pub binary_sha256: &'a str,
    pub offset: u64,
}

impl IdContext<'_> {
    fn id(&self, vaddr: u64, bytes: &[u8]) -> String {
        crate::schema::gadget_id(self.binary_sha256, vaddr.wrapping_sub(self.offset), bytes)
    }
}

/// Classify a whole cached scan once.
///
/// Uses one [`Classifier`] for the entire list rather than
/// `rf_classify::classify` per gadget: the classifier holds capstone
/// handles, and constructing them per call is the expensive part. This runs
/// on the scan worker thread, which is the only place a `!Send` classifier
/// can live.
#[must_use]
pub fn classify_scan(
    scan: &CachedScan,
    binary_sha256: &str,
    offset: u64,
    arch: Option<Arch>,
) -> Vec<Semantics> {
    let classifier = arch.map(Classifier::new);
    let ctx = IdContext {
        binary_sha256,
        offset,
    };
    scan.gadgets
        .iter()
        .map(|g| one(g, &ctx, classifier.as_ref()))
        .collect()
}

/// The scan-time path: the [`Classification`] is already in hand, so
/// nothing is classified twice.
#[must_use]
pub fn from_scan_gadget(
    g: &rf_scan::Gadget,
    class: Option<Classification>,
    ctx: &IdContext,
) -> Semantics {
    let rank = match &class {
        Some(c) => rf_classify::rank_key(c, g),
        None => RankKey {
            usability: 0,
            quality: 0,
            n_insns: g.insns.len(),
            side_effects: 0,
            vaddr: g.vaddr,
        },
    };
    Semantics {
        id: ctx.id(g.vaddr, &g.bytes),
        vaddr: g.vaddr,
        bytes: g.bytes.clone(),
        insns: g.insns.clone(),
        delay_slot: g.delay_slot,
        class,
        rank,
    }
}

fn one(g: &CachedGadget, ctx: &IdContext, classifier: Option<&Classifier>) -> Semantics {
    match g.to_scan_gadget() {
        Some(sg) => {
            let class = classifier.map(|c| c.classify(&sg));
            from_scan_gadget(&sg, class, ctx)
        }
        // A record that does not reconstruct cannot be classified and must
        // still get an id and a place in the order — it sorts last.
        None => {
            let vaddr = rf_cache::parse_hex_u64(&g.vaddr).unwrap_or(0);
            Semantics {
                id: ctx.id(vaddr, &[]),
                vaddr,
                bytes: Vec::new(),
                insns: Vec::new(),
                delay_slot: g.delay_slot,
                class: None,
                rank: RankKey {
                    usability: 0,
                    quality: 0,
                    n_insns: usize::MAX,
                    side_effects: usize::MAX,
                    vaddr,
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Ordering (MCP-DESIGN fix #8 part A)
// ---------------------------------------------------------------------------

/// Result ordering. The default is [`Order::Rank`].
///
/// Before this the default was the engine's traversal order, which
/// `post_process` has already sorted alphabetically by text — so
/// `find_gadgets` with `max_results: 3` on elf-Linux-x64 returned
/// `adc al, 0x89 ; retf 0xc281` and two like it out of 2789, and
/// `sort_by: "quality"` did not help because 92 % of gadgets tied at 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// `rf_classify::rank_key`: usability tier, then quality, then fewest
    /// instructions, then fewest side effects, then address. Best first.
    Rank,
    /// Address ascending.
    Address,
    /// Quality descending, address ascending. Kept because `sort_by:
    /// "quality"` used to mean this.
    Quality,
    /// Gadget text, then address — the old default.
    Text,
    /// The order the caller's `ids` were given in (`get_gadgets` only).
    Ids,
}

/// Every `order` an agent may ask for, in the error message's order.
pub const ORDER_NAMES: &[&str] = &["rank", "address", "quality", "text"];

impl Order {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Order::Rank => "rank",
            Order::Address => "address",
            Order::Quality => "quality",
            Order::Text => "text",
            Order::Ids => "ids",
        }
    }

    /// Parse an `order` parameter, listing the valid set on failure.
    ///
    /// The old code rejected an unknown `sort_by` without saying what was
    /// accepted, which leaves an agent guessing.
    pub fn parse(v: &str) -> Result<Order, ToolError> {
        match v {
            "rank" => Ok(Order::Rank),
            "address" => Ok(Order::Address),
            "quality" => Ok(Order::Quality),
            "text" => Ok(Order::Text),
            other => Err(ToolError::with_details(
                ErrorCode::UsageError,
                format!(
                    "unknown order {other:?}; valid values are {}",
                    ORDER_NAMES.join(", ")
                ),
                json!({"parameter": "order", "valid": ORDER_NAMES, "got": other}),
            )),
        }
    }
}

/// Order `idx` (indices into `scan.gadgets` / `sems`) in place.
pub fn sort_indices(idx: &mut [usize], order: Order, scan: &CachedScan, sems: &[Semantics]) {
    let sem = |i: usize| sems.get(i);
    let text = |i: usize| scan.gadgets.get(i).map(|g| g.text.as_str()).unwrap_or("");
    match order {
        // `RankKey`'s `Ord` is best-first ASCENDING, so a plain sort is the
        // default order. The vaddr tail makes it total, which is what the
        // cursor needs: two pages of the same query must not interleave.
        Order::Rank => idx.sort_by_key(|&i| sem(i).map(|s| s.rank)),
        Order::Address => idx.sort_by_key(|&i| sem(i).map_or(u64::MAX, |s| s.vaddr)),
        Order::Quality => idx.sort_by(|&a, &b| {
            let (qa, qb) = (
                sem(a).map_or(0, Semantics::quality),
                sem(b).map_or(0, Semantics::quality),
            );
            qb.cmp(&qa).then_with(|| {
                sem(a)
                    .map_or(u64::MAX, |s| s.vaddr)
                    .cmp(&sem(b).map_or(u64::MAX, |s| s.vaddr))
            })
        }),
        Order::Text => idx.sort_by(|&a, &b| {
            text(a).cmp(text(b)).then_with(|| {
                sem(a)
                    .map_or(u64::MAX, |s| s.vaddr)
                    .cmp(&sem(b).map_or(u64::MAX, |s| s.vaddr))
            })
        }),
        // `get_gadgets` builds the list in the caller's order already.
        Order::Ids => {}
    }
}

// ---------------------------------------------------------------------------
// The semantic predicate (CLS-08 / MCP-DESIGN fix #9)
// ---------------------------------------------------------------------------

/// Normalize a register name the way `rf_classify` does: lowercase, and
/// without the `$`/`%` sigil MIPS and SPARC disassembly carries. An agent
/// that types `--writes-reg $t6` and one that types `t6` must get the same
/// answer.
fn norm_reg(s: &str) -> String {
    let t = s.trim();
    let t = t
        .strip_prefix('$')
        .or_else(|| t.strip_prefix('%'))
        .unwrap_or(t);
    t.to_ascii_lowercase()
}

/// Split every element of a list parameter, so `["rsi", "rdx"]` and
/// `["rsi,rdx"]` are the same request. The MCP spelling of `no_clobber` is
/// an array (`{"no_clobber": ["rsi","rdx"]}`); the CLI spelling is one
/// comma-separated value (`--no-clobber rsi,rdx`), and an agent that
/// transliterates the flag straight into the array must not silently ask
/// for a register called "rsi,rdx".
fn split_each(v: &[String]) -> Vec<String> {
    v.iter()
        .flat_map(|s| s.split([',', '|']))
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

fn split_list(v: Option<&str>) -> Vec<String> {
    v.map(|s| {
        s.split([',', '|'])
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

/// The semantic filter applied over an already-scanned gadget set.
///
/// Every field is a pure predicate over [`Semantics`], so this costs one
/// pass over a cached list and never a rescan.
#[derive(Debug, Clone, Default)]
pub struct GadgetFilter {
    /// Primary class must be one of these. Empty = no constraint.
    pub classes: Vec<String>,
    /// The gadget must carry at least one of these labels.
    pub labels: Vec<String>,
    /// The gadget must write ALL of these registers.
    pub writes_regs: Vec<String>,
    /// The gadget must read ALL of these registers.
    pub reads_regs: Vec<String>,
    /// The gadget must write NONE of these registers.
    pub preserves_regs: Vec<String>,
    /// Every register in `writes_regs` must be loaded off the stack (a
    /// `pop`, or a load based on the stack pointer). With no `writes_regs`,
    /// at least one register must be.
    pub from_stack: bool,
    /// Coarse terminator kinds ([`Terminator::kind`]); any-of. Empty means
    /// no constraint, and so does a value of `"any"`.
    ///
    /// `terminator` is a comma-separated any-of list, exactly as the CLI's
    /// `--terminator` is: `"ret,jmp"` is one question, not a usage error,
    /// and the two surfaces are compared value by value by
    /// `tests/capability_matrix.py`.
    pub terminator_kinds: Vec<String>,
    /// The FINE terminator classes ([`TerminatorClass`]) named in the same
    /// list; any-of, unioned with [`Self::terminator_kinds`].
    pub terminator_classes: Vec<String>,
    pub max_side_effects: Option<u32>,
    pub max_insns: Option<u32>,

    // ---- ECO-01 / CLS-09, v0.4 ------------------------------------------
    /// `set_reg`: the gadget must SET all of these — write them with a
    /// value the chain payload decides. Strictly stronger than
    /// `writes_regs`, which is satisfied by `xor rdi, rdi`.
    pub set_regs: Vec<String>,
    /// `no_clobber`: none of these may be CLOBBERED. Matched against
    /// `Classification::clobbers`, not `regs_written` — `mov rdi, rax`
    /// clobbers rdi, and `pop rdi` does not.
    pub no_clobber: Vec<String>,
    /// `max_stack_delta`: the gadget's net stack movement must be KNOWN
    /// and at most this. An unknown delta is rejected, never treated as 0
    /// (CLS-09: `xchg rsp, rax ; ret` has an unknown delta and must not
    /// silently pass a layout budget).
    pub max_stack_delta: Option<i64>,
    /// `pivot`: the ECO-12 preset — the gadget carries the `stack-pivot`
    /// label (as a primary class or as a secondary one).
    pub pivot: bool,
    /// `search`: the ropper-style wildcard instruction-sequence matcher.
    pub search: Option<crate::pattern::SeqPattern>,
}

/// The filter parameters exactly as the request carries them, before any
/// validation. A struct rather than nine arguments so the three query types
/// that carry these fields can hand them over in one move.
#[derive(Debug, Clone, Copy, Default)]
pub struct RawFilter<'a> {
    pub class: Option<&'a str>,
    pub label: Option<&'a str>,
    pub writes_reg: Option<&'a str>,
    pub reads_reg: Option<&'a str>,
    pub preserves_regs: Option<&'a str>,
    pub from_stack: Option<bool>,
    pub terminator: Option<&'a str>,
    pub max_side_effects: Option<u32>,
    pub max_insns: Option<u32>,
    // ECO-01 / CLS-09, v0.4.
    pub set_reg: Option<&'a str>,
    pub no_clobber: &'a [String],
    pub max_stack_delta: Option<i64>,
    pub pivot: Option<bool>,
    pub search: Option<&'a str>,
}

impl GadgetFilter {
    /// Build from the raw request strings, rejecting unknown class, label
    /// and terminator names with the valid set in the error.
    pub fn parse(raw: &RawFilter) -> Result<Self, ToolError> {
        let classes = split_list(raw.class);
        let labels = split_list(raw.label);
        for (param, values) in [("class", &classes), ("label", &labels)] {
            for v in values {
                if !CLASS_NAMES.contains(&v.as_str()) {
                    return Err(ToolError::with_details(
                        ErrorCode::UsageError,
                        format!(
                            "unknown {param} {v:?}; valid values are {}",
                            CLASS_NAMES.join(", ")
                        ),
                        json!({"parameter": param, "valid": CLASS_NAMES, "got": v}),
                    ));
                }
            }
        }
        // `terminator` accepts the coarse kind first (so `ret` keeps
        // meaning every returning form) and CLS-09's fine class second.
        let mut terminator_kinds: Vec<String> = Vec::new();
        let mut terminator_classes: Vec<String> = Vec::new();
        let mut terminator_any = false;
        // Comma-separated any-of, trimmed and lowercased — the same
        // normalisation the CLI applies to `--terminator`. Before this,
        // `terminator: "RET"` was a usage_error here and a working query
        // there, and `"ret,jmp"` likewise.
        for t in split_list(raw.terminator) {
            let t = t.to_ascii_lowercase();
            if t == "any" {
                terminator_any = true;
            } else if TERMINATOR_KINDS.contains(&t.as_str()) {
                terminator_kinds.push(t);
            } else if t == TERMINATOR_BARE_RET {
                terminator_classes.push(TerminatorClass::Ret.name().to_string());
            } else if TerminatorClass::parse(&t).is_some() {
                terminator_classes.push(t);
            } else {
                let vocab = terminator_vocabulary();
                return Err(ToolError::with_details(
                    ErrorCode::UsageError,
                    format!(
                        "unknown terminator {t:?}; valid values are {}",
                        vocab.join(", ")
                    ),
                    json!({"parameter": "terminator", "valid": vocab, "got": t}),
                ));
            }
        }
        if terminator_any {
            // `any` is "no constraint" and wins over anything beside it, as
            // `--terminator any,ret` does on the CLI.
            terminator_kinds.clear();
            terminator_classes.clear();
        }
        let search = match raw.search {
            Some(pat) => Some(crate::pattern::SeqPattern::parse(pat).map_err(|e| {
                ToolError::with_details(
                    ErrorCode::UsageError,
                    e,
                    json!({"parameter": "search", "got": pat}),
                )
            })?),
            None => None,
        };
        Ok(GadgetFilter {
            classes,
            labels,
            writes_regs: split_list(raw.writes_reg)
                .iter()
                .map(|r| norm_reg(r))
                .collect(),
            reads_regs: split_list(raw.reads_reg)
                .iter()
                .map(|r| norm_reg(r))
                .collect(),
            preserves_regs: split_list(raw.preserves_regs)
                .iter()
                .map(|r| norm_reg(r))
                .collect(),
            from_stack: raw.from_stack.unwrap_or(false),
            terminator_kinds,
            terminator_classes,
            max_side_effects: raw.max_side_effects,
            max_insns: raw.max_insns,
            set_regs: split_list(raw.set_reg)
                .iter()
                .map(|r| norm_reg(r))
                .collect(),
            no_clobber: split_each(raw.no_clobber)
                .iter()
                .map(|r| norm_reg(r))
                .collect(),
            max_stack_delta: raw.max_stack_delta,
            pivot: raw.pivot.unwrap_or(false),
            search,
        })
    }

    /// True when nothing is constrained, so the caller can skip the pass.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
            && self.labels.is_empty()
            && self.writes_regs.is_empty()
            && self.reads_regs.is_empty()
            && self.preserves_regs.is_empty()
            && !self.from_stack
            && self.terminator_kinds.is_empty()
            && self.terminator_classes.is_empty()
            && self.max_side_effects.is_none()
            && self.max_insns.is_none()
            && self.set_regs.is_empty()
            && self.no_clobber.is_empty()
            && self.max_stack_delta.is_none()
            && !self.pivot
            && self.search.is_none()
    }

    /// Does this gadget satisfy every constraint?
    #[must_use]
    pub fn matches(&self, s: &Semantics) -> bool {
        if !self.classes.is_empty() {
            match s.primary() {
                Some(p) if self.classes.iter().any(|c| c == p) => {}
                _ => return false,
            }
        }
        if !self.labels.is_empty() {
            let have = s.labels();
            if !self.labels.iter().any(|l| have.contains(&l.as_str())) {
                return false;
            }
        }
        let written = s.regs_written();
        if !self.writes_regs.iter().all(|r| written.contains(r)) {
            return false;
        }
        if !self.reads_regs.iter().all(|r| s.reads_reg(r)) {
            return false;
        }
        if self.preserves_regs.iter().any(|r| written.contains(r)) {
            return false;
        }
        // CLS-09 `sets` — a payload-decided write, which `regs_written`
        // does not distinguish: `xor rdi, rdi ; ret` writes rdi and sets
        // nothing.
        if !self.set_regs.iter().all(|r| s.sets_reg(r)) {
            return false;
        }
        // CLS-09 `clobbers` — NOT `regs_written`. `pop rdi ; ret` writes
        // rdi and clobbers nothing, so `no_clobber: ["rdi"]` keeps it,
        // while `mov rdi, rax ; ret` is dropped.
        if self.no_clobber.iter().any(|r| s.clobbers_reg(r)) {
            return false;
        }
        if self.from_stack {
            // Anchored on `set_reg` when there is one (CLS-09's
            // `reg_from_stack`), on `writes_reg` otherwise (the v0.3
            // spelling), and on "anything at all" when neither is given.
            let anchor = if self.set_regs.is_empty() {
                &self.writes_regs
            } else {
                &self.set_regs
            };
            if anchor.is_empty() {
                if s.regs_from_stack().is_empty() {
                    return false;
                }
            } else if !anchor.iter().all(|r| s.reg_from_stack(r)) {
                return false;
            }
        }
        if self.pivot && !s.labels().contains(&"stack-pivot") {
            return false;
        }
        if let Some(max) = self.max_stack_delta {
            // `None` is UNKNOWN. Accepting it here is the mistake CLS-09
            // names: it would put `xchg rsp, rax ; ret` inside a layout
            // budget it does not respect.
            match s.stack_delta() {
                Some(d) if d <= max => {}
                _ => return false,
            }
        }
        if !(self.terminator_kinds.is_empty() && self.terminator_classes.is_empty()) {
            let kind = s.terminator_kind();
            let class = s.terminator_class();
            let ok = self.terminator_kinds.iter().any(|t| t == kind)
                || self.terminator_classes.iter().any(|t| t == class);
            if !ok {
                return false;
            }
        }
        if let Some(pat) = &self.search {
            if !pat.matches(&s.insns) {
                return false;
            }
        }
        if let Some(m) = self.max_side_effects {
            if s.side_effects() > m {
                return false;
            }
        }
        if let Some(m) = self.max_insns {
            if s.insns.len() as u64 > u64::from(m) {
                return false;
            }
        }
        true
    }
}

/// The class names this crate advertises must be exactly the classifier's.
/// Grown apart, the filter would silently reject a class the classifier
/// still emits.
#[must_use]
pub fn class_names_match_rf_classify() -> bool {
    let real = [
        Class::RegWrite,
        Class::StackPivot,
        Class::MemRead,
        Class::MemWrite,
        Class::Arithmetic,
        Class::Syscall,
        Class::Dispatcher,
        Class::Other,
    ];
    real.len() == CLASS_NAMES.len() && real.iter().all(|c| CLASS_NAMES.contains(&c.name()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;

    fn cached(vaddr: &str, bytes: &str, text: &str) -> CachedGadget {
        CachedGadget {
            vaddr: vaddr.into(),
            bytes: bytes.into(),
            text: text.into(),
            ..CachedGadget::default()
        }
    }

    fn scan() -> CachedScan {
        CachedScan {
            gadgets: vec![
                cached("0x401648", "5fc3", "pop rdi ; ret"),
                cached("0x401650", "5ec3", "pop rsi ; ret"),
                cached("0x401660", "c3", "ret"),
                cached("0x401670", "ca3901", "retf 0x139"),
                cached("0x401680", "4889c7c3", "mov rdi, rax ; ret"),
            ],
            ..CachedScan::default()
        }
    }

    const SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn sems() -> Vec<Semantics> {
        classify_scan(&scan(), SHA, 0, Some(Arch::X64))
    }

    #[test]
    fn class_names_are_the_classifiers() {
        assert!(class_names_match_rf_classify());
    }

    /// The tier that makes ranking work: `pop rdi ; ret` outranks a bare
    /// `ret` and a `retf`, which the R12 quality score alone cannot do.
    #[test]
    fn rank_puts_a_stack_load_above_bare_control_flow() {
        let s = sems();
        let sc = scan();
        let mut idx: Vec<usize> = (0..sc.gadgets.len()).collect();
        sort_indices(&mut idx, Order::Rank, &sc, &s);
        let ordered: Vec<&str> = idx.iter().map(|&i| sc.gadgets[i].text.as_str()).collect();
        assert_eq!(ordered[0], "pop rdi ; ret", "{ordered:?}");
        assert_eq!(ordered[1], "pop rsi ; ret", "{ordered:?}");
        // Pure control flow sorts below everything that does work: a bare
        // `ret` earns no label, so it is tier 0 and comes LAST — below even
        // `retf 0x139`, whose immediate is a stack adjustment (CLS-13) and
        // so puts it in tier 1.
        let bare = ordered.iter().position(|t| *t == "ret").unwrap();
        let mov = ordered
            .iter()
            .position(|t| *t == "mov rdi, rax ; ret")
            .unwrap();
        let retf = ordered.iter().position(|t| *t == "retf 0x139").unwrap();
        assert!(mov < retf && retf < bare, "{ordered:?}");
        assert_eq!(*ordered.last().unwrap(), "ret", "{ordered:?}");
    }

    #[test]
    fn address_and_text_orders_are_total() {
        let s = sems();
        let sc = scan();
        for order in [Order::Address, Order::Text, Order::Quality, Order::Rank] {
            let mut a: Vec<usize> = (0..sc.gadgets.len()).collect();
            let mut b: Vec<usize> = (0..sc.gadgets.len()).rev().collect();
            sort_indices(&mut a, order, &sc, &s);
            sort_indices(&mut b, order, &sc, &s);
            assert_eq!(a, b, "{} is not a total order", order.as_str());
        }
        let mut idx: Vec<usize> = (0..sc.gadgets.len()).rev().collect();
        sort_indices(&mut idx, Order::Address, &sc, &s);
        assert_eq!(idx, vec![0, 1, 2, 3, 4]);
    }

    /// The exit criterion's question, as a predicate: set rdi from the
    /// stack, preserve rsi and rdx, at most one side effect, clean ret.
    #[test]
    fn the_real_question_selects_exactly_one_gadget() {
        let s = sems();
        let f = GadgetFilter::parse(&RawFilter {
            writes_reg: Some("rdi"),
            preserves_regs: Some("rsi,rdx"),
            from_stack: Some(true),
            terminator: Some("ret"),
            max_side_effects: Some(1),
            ..RawFilter::default()
        })
        .unwrap();
        let hits: Vec<&str> = s
            .iter()
            .enumerate()
            .filter(|(_, sem)| f.matches(sem))
            .map(|(i, _)| scan().gadgets[i].text.clone())
            .map(|t| Box::leak(t.into_boxed_str()) as &str)
            .collect();
        assert_eq!(hits, ["pop rdi ; ret"], "{hits:?}");
        // `mov rdi, rax ; ret` writes rdi but not from the stack.
        let no_stack = GadgetFilter::parse(&RawFilter {
            writes_reg: Some("rdi"),
            terminator: Some("ret"),
            ..RawFilter::default()
        })
        .unwrap();
        let n = s.iter().filter(|sem| no_stack.matches(sem)).count();
        assert_eq!(n, 2, "both rdi writers match without from_stack");
    }

    #[test]
    fn register_names_are_matched_sigil_free() {
        let f = GadgetFilter::parse(&RawFilter {
            writes_reg: Some("$RDI"),
            ..RawFilter::default()
        })
        .unwrap();
        assert_eq!(f.writes_regs, ["rdi"]);
    }

    #[test]
    fn unknown_filter_values_list_the_valid_set() {
        let e = GadgetFilter::parse(&RawFilter {
            class: Some("nonsense"),
            ..RawFilter::default()
        })
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::UsageError);
        assert!(e.message.contains("stack-pivot"), "{e:?}");
        let e = GadgetFilter::parse(&RawFilter {
            terminator: Some("sideways"),
            ..RawFilter::default()
        })
        .unwrap_err();
        assert_eq!(e.code, ErrorCode::UsageError);
        assert!(e.message.contains("syscall"), "{e:?}");
        let e = Order::parse("sideways").unwrap_err();
        assert_eq!(e.code, ErrorCode::UsageError);
        for name in ORDER_NAMES {
            assert!(e.message.contains(name), "{e:?} omits {name}");
        }
    }

    /// A record that does not reconstruct still gets an id and a place in
    /// every order — it must not panic and must not sort first.
    #[test]
    fn an_unreconstructable_record_sorts_last_without_panicking() {
        let sc = CachedScan {
            gadgets: vec![
                cached("0x1", "€€", "ret"),
                cached("0x401648", "5fc3", "pop rdi ; ret"),
            ],
            ..CachedScan::default()
        };
        let s = classify_scan(&sc, SHA, 0, Some(Arch::X64));
        assert!(s[0].class.is_none());
        assert!(s[0].id.starts_with("g_"));
        let mut idx = vec![0usize, 1];
        sort_indices(&mut idx, Order::Rank, &sc, &s);
        assert_eq!(idx, vec![1, 0]);
    }
}
