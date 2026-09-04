//! ECO-01 / ECO-12: the constraint query layer.
//!
//! v0.3 let you ask for a gadget's *label*. This asks the question a
//! practitioner actually has — "a gadget that loads rdi from the stack and
//! clobbers neither rsi nor rdx" — by filtering on the semantic fields
//! CLS-09 put on [`rf_classify::Classification`]: the register-transfer
//! relations, the stack delta, the `sets`/`clobbers` partition and the
//! nine-way terminator classification.
//!
//! Nothing here re-derives semantics from gadget text. That is the whole
//! point: a filter that parsed `pop rdi ; ret` itself would be a second,
//! subtly different classifier living in the front end, which is the defect
//! shape CLI-04/ECO-03 already caught once.
//!
//! # The same vocabulary on both surfaces
//!
//! Every predicate here is one CLI flag and one `find_gadgets_by_effect`
//! parameter with the same name in snake_case, because ECO-02's finding is
//! that the CLI and its own MCP server diverge. The mapping is exactly:
//!
//! | CLI | MCP | predicate |
//! |---|---|---|
//! | `--set-reg R` | `set_reg` | [`Classification::sets_reg`] |
//! | `--from-stack` | `from_stack` | [`Classification::reg_from_stack`] |
//! | `--no-clobber a,b` | `no_clobber` | `!`[`Classification::clobbers_any`] |
//! | `--reads-reg R` | `reads_reg` | `regs_read` plus transfer dependencies |
//! | `--max-stack-delta N` | `max_stack_delta` | [`Classification::stack_delta`] |
//! | `--max-side-effects N` | `max_side_effects` | `side_effects` |
//! | `--max-insns N` | `max_insns` | instruction count |
//! | `--terminator K` | `terminator` | [`Classification::terminator_class`] |
//! | `--search "pop rdi; ret"` | `search` | [`SeqPattern`] |
//! | `--pivot` | `pivot` | the `stack-pivot` label |
//! | `--class` / `--label` / `--writes-reg` | same | v0.3, unchanged |

use rf_classify::{Classification, TerminatorClass};

/// A gadget-sequence pattern in the ropper `--search` spelling.
///
/// `pop rdi; ret` is a sequence of two instruction patterns; a gadget
/// matches when its instruction list contains that sequence **contiguously**,
/// so `xor eax, eax ; pop rdi ; ret` matches and `pop rdi ; pop rsi ; ret`
/// does not. Inside one instruction, `?` stands for exactly one character
/// and `%` for any run of characters; runs of whitespace in the pattern
/// match runs of whitespace in the instruction, so `pop  rdi` and `pop rdi`
/// are the same query. Matching is case-insensitive.
///
/// The wildcards are deliberately *not* a raw regex — `--re` already exists
/// for that and has ROPgadget's per-instruction-conjunction semantics, which
/// is a different question ("does some instruction match each of these")
/// from this one ("do these instructions appear in this order").
#[derive(Debug)]
pub struct SeqPattern {
    pieces: Vec<regex::Regex>,
}

impl SeqPattern {
    /// Compile a `--search` pattern. `;` separates instructions, `?` is any
    /// one character and `%` any run of characters within one instruction.
    ///
    /// ```
    /// use rf_api::query::SeqPattern;
    ///
    /// let p = SeqPattern::parse("pop rdi; ret")?;
    /// assert!(p.matches(&["xor eax, eax", "pop rdi", "ret"]));
    /// assert!(!p.matches(&["pop rdi", "pop rsi", "ret"]));
    /// assert!(SeqPattern::parse("   ").is_err());
    /// # Ok::<(), String>(())
    /// ```
    pub fn parse(pattern: &str) -> Result<SeqPattern, String> {
        let mut pieces = Vec::new();
        for raw in pattern.split(';') {
            let piece = raw.trim();
            if piece.is_empty() {
                continue;
            }
            let re = regex::Regex::new(&format!("(?i)^{}$", translate(piece)))
                .map_err(|e| format!("invalid --search pattern {pattern:?}: {e}"))?;
            pieces.push(re);
        }
        if pieces.is_empty() {
            return Err(format!(
                "--search pattern {pattern:?} is empty; expected e.g. 'pop rdi; ret'"
            ));
        }
        Ok(SeqPattern { pieces })
    }

    /// Does `insns` contain this pattern as a contiguous subsequence?
    pub fn matches(&self, insns: &[&str]) -> bool {
        if self.pieces.len() > insns.len() {
            return false;
        }
        (0..=insns.len() - self.pieces.len()).any(|start| {
            self.pieces
                .iter()
                .zip(&insns[start..])
                .all(|(re, ins)| re.is_match(ins.trim()))
        })
    }
}

/// Translate one wildcard instruction pattern into a regex body.
///
/// `?` becomes `.`, `%` becomes `.*`, a run of whitespace becomes `\s+`, and
/// every other character is escaped so that `[`, `+` and `.` in
/// `mov rax, [rbx+8]` are literals rather than regex syntax.
fn translate(piece: &str) -> String {
    let mut out = String::with_capacity(piece.len() * 2);
    let mut chars = piece.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '?' => out.push('.'),
            '%' => out.push_str(".*"),
            c if c.is_whitespace() => {
                while chars.peek().is_some_and(|n| n.is_whitespace()) {
                    chars.next();
                }
                out.push_str(r"\s+");
            }
            c => out.push_str(&regex::escape(c.encode_utf8(&mut [0u8; 4]))),
        }
    }
    out
}

/// Normalize a register name the way every register-valued flag does:
/// trim, drop a `$`/`%` sigil, lowercase.
pub fn norm_reg(r: &str) -> String {
    let t = r.trim();
    let t = t
        .strip_prefix('$')
        .or_else(|| t.strip_prefix('%'))
        .unwrap_or(t);
    t.to_ascii_lowercase()
}

/// The separators every comma-separated flag on this surface accepts.
///
/// `,` is the documented spelling and `|` is accepted beside it because the
/// MCP twin of each of these flags splits on both — a value that is a
/// working query on one surface must not be a usage error on the other, and
/// `tests/capability_matrix.py` compares the two vocabularies value by
/// value. Widening is safe: neither a register name, a class name nor a
/// terminator spelling has ever contained a `|`, so nothing that used to
/// parse changes meaning.
pub const LIST_SEPARATORS: [char; 2] = [',', '|'];

fn split_list(v: Option<&str>) -> Vec<String> {
    v.map(|s| {
        s.split(LIST_SEPARATORS)
            .map(norm_reg)
            .filter(|x| !x.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

/// One `--terminator` value.
///
/// The shared query spec's vocabulary is the coarse `ret|jmp|call|syscall`,
/// which is what v0.3's MCP `terminator` filter already means
/// ([`rf_classify::Terminator::kind`]). CLS-09's nine-way
/// [`TerminatorClass`] is finer, and both are useful, so both are accepted.
/// They collide on exactly one token: coarse `ret` includes `ret imm16`,
/// `retf` and `iret`, while [`TerminatorClass::Ret`] is the *bare* return
/// only. Coarse wins for `ret` — it is the spec's spelling and the superset,
/// so a user who types the spec's word never gets a silently narrower answer
/// — and `bare-ret` is the spelling for the narrow one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TermQuery {
    /// `ret` / `jmp` / `call` / `syscall` / `none` — `Terminator::kind()`.
    Kind(&'static str),
    /// One of the nine [`TerminatorClass`] values.
    Class(TerminatorClass),
    /// `any` - no constraint. The MCP `terminator` parameter accepts it
    /// (a JSON field that is present but unconstrained needs a value), so
    /// it is accepted here too rather than being a usage error on one
    /// surface and a no-op on the other.
    Any,
}

impl TermQuery {
    const KINDS: &'static [&'static str] = &["ret", "jmp", "call", "syscall", "none"];

    fn parse(s: &str) -> Option<TermQuery> {
        if s == "any" {
            return Some(TermQuery::Any);
        }
        if let Some(k) = Self::KINDS.iter().find(|k| **k == s) {
            return Some(TermQuery::Kind(k));
        }
        if s == "bare-ret" {
            return Some(TermQuery::Class(TerminatorClass::Ret));
        }
        // "ret" and "syscall" were taken above; the rest are unambiguous.
        TerminatorClass::parse(s).map(TermQuery::Class)
    }

    fn matches(self, c: &Classification) -> bool {
        match self {
            TermQuery::Any => true,
            TermQuery::Kind(k) => c.terminator().kind() == k,
            TermQuery::Class(t) => c.terminator_class() == t,
        }
    }

    /// Every accepted spelling, for the usage error.
    fn vocabulary() -> String {
        let mut v: Vec<&str> = Self::KINDS.to_vec();
        v.push("any");
        v.push("bare-ret");
        for t in TerminatorClass::ALL {
            if !v.contains(t) {
                v.push(t);
            }
        }
        v.join(", ")
    }
}

/// Everything the v0.3 `--class`/`--label`/`--writes-reg` filter and the
/// v0.4 constraint flags ask of one gadget.
///
/// Constructed once per run and applied per gadget, so the streaming
/// (`--format jsonl`) path and the buffered path share one predicate.
#[derive(Debug, Default)]
pub struct Query {
    /// v0.3. Primary class must be one of these.
    classes: Vec<String>,
    /// v0.3. At least one of these labels must be present.
    labels: Vec<String>,
    /// v0.3. ALL of these registers must appear in `regs_written`.
    writes_regs: Vec<String>,
    /// `--set-reg`: ALL of these registers must be in `sets`.
    ///
    /// Comma-separated, like every other register-valued flag. The shared
    /// spec spells the flag `--set-reg <REG>` and this was a single value,
    /// while the MCP twin already split on commas and required all of them
    /// — so `--set-reg rdi,rsi` silently matched nothing here (the whole
    /// string was one register name that no gadget has) and answered a real
    /// question there. `tests/capability_matrix.py` now asks every
    /// list-valued flag a two-register question.
    set_regs: Vec<String>,
    /// `--from-stack`.
    from_stack: bool,
    /// `--no-clobber`: none of these may be in `clobbers`.
    no_clobber: Vec<String>,
    /// `--reads-reg`: ALL of these registers must be read. Comma-separated,
    /// for the same reason as [`Self::set_regs`].
    reads_regs: Vec<String>,
    /// `--max-stack-delta`.
    max_stack_delta: Option<i64>,
    /// `--max-side-effects`.
    max_side_effects: Option<usize>,
    /// `--max-insns`.
    max_insns: Option<usize>,
    /// `--terminator`: any of these.
    terminators: Vec<TermQuery>,
    /// `--search`.
    search: Option<SeqPattern>,
}

/// The raw flag values, so [`Query::parse`] has one argument rather than
/// thirteen and a caller cannot transpose two `Option<&str>`s silently.
#[derive(Debug, Default, Clone)]
pub struct QuerySpec<'a> {
    /// `--class` / `class`: keep gadgets whose PRIMARY class is one of these.
    pub class: Option<&'a str>,
    /// `--label` / `label`: keep gadgets carrying at least one of these.
    pub label: Option<&'a str>,
    /// `--writes-reg` / `writes_reg`: every named register must be written.
    pub writes_reg: Option<&'a str>,
    /// `--set-reg` / `set_reg`: every named register must be SET (written
    /// with a payload-decided value), not merely clobbered.
    pub set_reg: Option<&'a str>,
    /// `--from-stack` / `from_stack`: narrow the write to one that
    /// originates in a pop or a stack-pointer-relative load.
    pub from_stack: bool,
    /// `--no-clobber` / `no_clobber`: reject gadgets clobbering any of these.
    pub no_clobber: Option<&'a str>,
    /// `--reads-reg` / `reads_reg`: every named register must be read.
    pub reads_reg: Option<&'a str>,
    /// `--max-stack-delta` / `max_stack_delta`: an unprovable delta is
    /// REJECTED, never treated as 0.
    pub max_stack_delta: Option<i64>,
    /// `--max-side-effects` / `max_side_effects` (TAXONOMY.md R11).
    pub max_side_effects: Option<usize>,
    /// `--max-insns` / `max_insns`; the terminator counts.
    pub max_insns: Option<usize>,
    /// `--terminator` / `terminator`: the 13-value coarse+fine vocabulary.
    pub terminator: Option<&'a str>,
    /// `--search` / `search`: a [`SeqPattern`] over the instruction list.
    pub search: Option<&'a str>,
    /// `--pivot` / `pivot`: the preset for `label = stack-pivot`.
    pub pivot: bool,
}

/// The `stack-pivot` label `--pivot` is a preset over (ECO-12).
pub const PIVOT_LABEL: &str = "stack-pivot";

impl Query {
    /// Compile a [`QuerySpec`] into a predicate.
    ///
    /// Every unknown class, label or terminator spelling is a usage error
    /// naming the accepted set, so a typo costs a message rather than an
    /// empty result. An all-default spec compiles to a predicate that
    /// accepts everything, which [`Query::is_empty`] reports.
    ///
    /// ```
    /// use rf_api::query::{Query, QuerySpec};
    ///
    /// assert!(Query::parse(&QuerySpec::default())?.is_empty());
    /// assert!(!Query::parse(&QuerySpec { set_reg: Some("rdi"), ..QuerySpec::default() })?
    ///     .is_empty());
    /// assert!(Query::parse(&QuerySpec { class: Some("nonsense"), ..QuerySpec::default() })
    ///     .is_err());
    /// # Ok::<(), String>(())
    /// ```
    pub fn parse(spec: &QuerySpec<'_>) -> Result<Query, String> {
        let valid: Vec<&str> = [
            rf_classify::Class::RegWrite,
            rf_classify::Class::StackPivot,
            rf_classify::Class::MemRead,
            rf_classify::Class::MemWrite,
            rf_classify::Class::Arithmetic,
            rf_classify::Class::Syscall,
            rf_classify::Class::Dispatcher,
            rf_classify::Class::Other,
        ]
        .iter()
        .map(|c| c.name())
        .collect();
        let split_names = |v: Option<&str>| -> Vec<String> {
            v.map(|s| {
                s.split(LIST_SEPARATORS)
                    .map(str::trim)
                    .filter(|x| !x.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
        };
        let classes = split_names(spec.class);
        let mut labels = split_names(spec.label);
        for (flag, values) in [("--class", &classes), ("--label", &labels)] {
            for v in values {
                if !valid.contains(&v.as_str()) {
                    return Err(format!(
                        "invalid {flag} value {v:?}; valid values are {}",
                        valid.join(", ")
                    ));
                }
            }
        }
        // ECO-12: `--pivot` is exactly `--label stack-pivot`, not a second
        // spelling of the rule. A gadget can carry several labels, so the
        // label set is the right side to ask — `--class stack-pivot` would
        // miss `pop rsp ; pop rdi ; ret`, whose primary class is reg-write.
        if spec.pivot && !labels.iter().any(|l| l == PIVOT_LABEL) {
            labels.push(PIVOT_LABEL.to_string());
        }
        let mut terminators = Vec::new();
        for t in split_names(spec.terminator) {
            let t = t.to_ascii_lowercase();
            terminators.push(TermQuery::parse(&t).ok_or_else(|| {
                format!(
                    "invalid --terminator value {t:?}; valid values are {}",
                    TermQuery::vocabulary()
                )
            })?);
        }
        Ok(Query {
            classes,
            labels,
            writes_regs: split_list(spec.writes_reg),
            set_regs: split_list(spec.set_reg),
            from_stack: spec.from_stack,
            no_clobber: split_list(spec.no_clobber),
            reads_regs: split_list(spec.reads_reg),
            max_stack_delta: spec.max_stack_delta,
            max_side_effects: spec.max_side_effects,
            max_insns: spec.max_insns,
            terminators,
            search: spec.search.map(SeqPattern::parse).transpose()?,
        })
    }

    /// True when no constraint was requested, so the caller can skip
    /// classification entirely.
    pub fn is_empty(&self) -> bool {
        self.classes.is_empty()
            && self.labels.is_empty()
            && self.writes_regs.is_empty()
            && self.set_regs.is_empty()
            && !self.from_stack
            && self.no_clobber.is_empty()
            && self.reads_regs.is_empty()
            && self.max_stack_delta.is_none()
            && self.max_side_effects.is_none()
            && self.max_insns.is_none()
            && self.terminators.is_empty()
            && self.search.is_none()
    }

    /// Does this gadget satisfy every constraint?
    ///
    /// `insns` is the gadget's instruction list, which the caller already
    /// has; it is passed in rather than re-split from `text()` so the
    /// streaming path does not allocate twice per gadget.
    pub fn matches(&self, c: &Classification, insns: &[&str]) -> bool {
        if !self.classes.is_empty() && !self.classes.iter().any(|n| n == c.primary.name()) {
            return false;
        }
        if !self.labels.is_empty()
            && !self
                .labels
                .iter()
                .any(|n| c.labels.iter().any(|l| l.name() == n))
        {
            return false;
        }
        // v0.3 semantics: `regs_written` keeps the operand's own spelling.
        if !self
            .writes_regs
            .iter()
            .all(|r| c.regs_written.iter().any(|w| w == r))
        {
            return false;
        }
        if !self.set_regs.iter().all(|r| c.sets_reg(r)) {
            return false;
        }
        if self.from_stack {
            // Anchored on --set-reg when there is one, on --writes-reg
            // otherwise, and on "anything at all" when neither is given.
            let anchor = if self.set_regs.is_empty() {
                &self.writes_regs
            } else {
                &self.set_regs
            };
            let ok = if anchor.is_empty() {
                !c.regs_from_stack.is_empty()
            } else {
                anchor.iter().all(|r| c.reg_from_stack(r))
            };
            if !ok {
                return false;
            }
        }
        // CLS-09: `clobbers` is the full-width partition, NOT `regs_written`.
        // `--no-clobber rax` must not be defeated by a gadget that writes
        // `al`, and must not reject `mov rdi, rax ; ret` for touching rax.
        if c.clobbers_any(&self.no_clobber) {
            return false;
        }
        if !self.reads_regs.iter().all(|r| reads_reg(c, r)) {
            return false;
        }
        if let Some(limit) = self.max_stack_delta {
            // `None` is *unknown*, not zero (CLS-09). `xchg rsp, rax ; ret`
            // reports None; accepting it here would silently put an
            // unbounded pivot into a fixed chain layout.
            match c.stack_delta {
                Some(d) if d <= limit => {}
                _ => return false,
            }
        }
        if let Some(limit) = self.max_side_effects {
            if c.side_effects > limit {
                return false;
            }
        }
        if let Some(limit) = self.max_insns {
            if insns.len() > limit {
                return false;
            }
        }
        if !self.terminators.is_empty() && !self.terminators.iter().any(|t| t.matches(c)) {
            return false;
        }
        if let Some(p) = &self.search {
            if !p.matches(insns) {
                return false;
            }
        }
        true
    }
}

/// `--reads-reg`: is `reg` an input of this gadget?
///
/// The union of `regs_read`, the transfer relations and the terminator's
/// target register used to be spelled out here AND, differently, in
/// `rf_mcp::semantics` — the MCP side left the terminator out, so
/// `--reads-reg rax` and `reads_reg: "rax"` returned different gadget sets
/// (2888 vs 2147 on elf-Linux-x64 at depth 4). It is now one predicate on
/// [`Classification`], and `tests/capability_matrix.py` compares the two
/// surfaces' answers so the copies cannot come back.
fn reads_reg(c: &Classification, reg: &str) -> bool {
    c.reads_reg(reg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rf_classify::Transfer;

    fn seq(p: &str) -> SeqPattern {
        SeqPattern::parse(p).expect("pattern compiles")
    }

    /// A real classification of `ret`, so the tests below start from what
    /// the classifier actually produces rather than a hand-built struct
    /// that could drift from it.
    fn classified_ret() -> Classification {
        let g = rf_scan::Gadget {
            vaddr: 0x1000,
            bytes: vec![0xc3],
            insns: vec!["ret".to_string()],
            delay_slot: false,
            prev: None,
            table: rf_scan::TableKind::Rop,
        };
        rf_classify::classify(&g, rf_core::Arch::X64)
    }

    #[test]
    fn search_matches_a_contiguous_subsequence() {
        let p = seq("pop rdi; ret");
        assert!(p.matches(&["pop rdi", "ret"]));
        assert!(p.matches(&["xor eax, eax", "pop rdi", "ret"]));
        // not contiguous
        assert!(!p.matches(&["pop rdi", "pop rsi", "ret"]));
        // shorter than the pattern
        assert!(!p.matches(&["ret"]));
    }

    #[test]
    fn search_wildcards_and_metacharacters() {
        assert!(seq("pop r?i; ret").matches(&["pop rdi", "ret"]));
        assert!(!seq("pop r?i; ret").matches(&["pop rsp", "ret"]));
        assert!(seq("%; ret").matches(&["anything at all", "ret"]));
        assert!(seq("mov %, rax; ret").matches(&["mov rbx, rax", "ret"]));
        // '[' and '+' are literals, not regex syntax — this must compile
        // AND match, which a naive regex build would fail to do.
        assert!(seq("mov [rbx+8], rax").matches(&["mov [rbx+8], rax"]));
        assert!(!seq("mov [rbx+8], rax").matches(&["mov [rbx+9], rax"]));
        // whitespace runs are equivalent, matching is case-insensitive
        assert!(seq("POP    rdi").matches(&["pop rdi"]));
    }

    #[test]
    fn search_rejects_an_empty_pattern() {
        assert!(SeqPattern::parse(" ; ; ").is_err());
        assert!(SeqPattern::parse("").is_err());
    }

    #[test]
    fn terminator_vocabulary_accepts_both_spellings() {
        assert_eq!(TermQuery::parse("ret"), Some(TermQuery::Kind("ret")));
        assert_eq!(
            TermQuery::parse("bare-ret"),
            Some(TermQuery::Class(TerminatorClass::Ret))
        );
        assert_eq!(
            TermQuery::parse("jmp-reg"),
            Some(TermQuery::Class(TerminatorClass::JmpReg))
        );
        assert_eq!(TermQuery::parse("jmp"), Some(TermQuery::Kind("jmp")));
        assert_eq!(TermQuery::parse("nonsense"), None);
        let v = TermQuery::vocabulary();
        for w in [
            "ret", "jmp", "call", "syscall", "bare-ret", "ret-imm", "far",
        ] {
            assert!(v.contains(w), "{w} missing from {v}");
        }
    }

    #[test]
    fn pivot_is_the_stack_pivot_label() {
        let q = Query::parse(&QuerySpec {
            pivot: true,
            ..Default::default()
        })
        .unwrap();
        assert!(!q.is_empty());
        assert_eq!(q.labels, vec![PIVOT_LABEL.to_string()]);
    }

    #[test]
    fn register_names_lose_their_sigil() {
        assert_eq!(norm_reg(" $RDI "), "rdi");
        assert_eq!(norm_reg("%eax"), "eax");
        assert_eq!(split_list(Some("rsi, rdx")), vec!["rsi", "rdx"]);
        assert_eq!(split_list(Some("")), Vec::<String>::new());
    }

    #[test]
    fn an_unknown_stack_delta_never_satisfies_a_bound() {
        let q = Query::parse(&QuerySpec {
            max_stack_delta: Some(64),
            ..Default::default()
        })
        .unwrap();
        let mut c = classified_ret();
        c.stack_delta = None;
        assert!(!q.matches(&c, &["ret"]), "None must not read as 0");
        c.stack_delta = Some(64);
        assert!(q.matches(&c, &["ret"]));
        c.stack_delta = Some(65);
        assert!(!q.matches(&c, &["ret"]));
    }

    /// `--set-reg` and `--reads-reg` are comma-separated ALL-of lists, and
    /// a comma is not part of a register name.
    ///
    /// Regression guard for the Phase 4 integration. The shared spec spells
    /// these `<REG>` and this surface took them literally while the MCP twin
    /// already split on commas, so `--set-reg rdi,rsi` looked for one
    /// register called "rdi,rsi" (0 gadgets, silently) where
    /// `set_reg: "rdi,rsi"` required both (45 gadgets on elf-Linux-x64 at
    /// depth 4 for the `--reads-reg` case). Both surfaces now split.
    #[test]
    fn register_flags_are_comma_separated_all_of_lists() {
        let q = Query::parse(&QuerySpec {
            set_reg: Some("rdi, RSI"),
            reads_reg: Some("rax|rcx"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(q.set_regs, vec!["rdi".to_string(), "rsi".to_string()]);
        assert_eq!(q.reads_regs, vec!["rax".to_string(), "rcx".to_string()]);

        let mut c = classified_ret();
        c.sets = vec!["rdi".to_string()];
        assert!(
            !q.matches(&c, &["ret"]),
            "ALL of the named registers must be set, not any of them"
        );
        c.sets = vec!["rdi".to_string(), "rsi".to_string()];
        c.regs_read = vec!["rax".to_string(), "rcx".to_string()];
        assert!(q.matches(&c, &["ret"]));

        // A single value keeps meaning exactly what it did.
        let one = Query::parse(&QuerySpec {
            set_reg: Some("rdi"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(one.set_regs, vec!["rdi".to_string()]);
    }

    /// `--from-stack` anchors on the whole `--set-reg` list.
    #[test]
    fn from_stack_requires_every_named_register_to_come_off_the_payload() {
        let q = Query::parse(&QuerySpec {
            set_reg: Some("rdi,rsi"),
            from_stack: true,
            ..Default::default()
        })
        .unwrap();
        let mut c = classified_ret();
        c.sets = vec!["rdi".to_string(), "rsi".to_string()];
        c.regs_from_stack = vec!["rdi".to_string()];
        c.transfers = vec![Transfer {
            dst: rf_classify::ValueDst::Register {
                reg: "rdi".to_string(),
            },
            src: rf_classify::ValueSrc::Stack { offset: Some(0) },
            needs: Vec::new(),
            rmw: false,
            width: Some(8),
        }];
        assert!(
            !q.matches(&c, &["ret"]),
            "rsi is set but not from the stack, so the gadget must not match"
        );
    }

    #[test]
    fn invalid_values_name_the_vocabulary() {
        let err = Query::parse(&QuerySpec {
            terminator: Some("returns"),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("--terminator"), "{err}");
        assert!(err.contains("syscall"), "{err}");
        let err = Query::parse(&QuerySpec {
            class: Some("pivot"),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("stack-pivot"), "{err}");
    }
}
