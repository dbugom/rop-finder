//! `ECO-04`: machine-readable chain feasibility.
//!
//! `build_rop_chain` answers a yes/no question and, on "no", hands back one
//! prose sentence:
//!
//! ```text
//! cannot populate rdx: no 'pop rdx' gadget and no 'pop rax' + 'mov rdx, rax' fallback
//! ```
//!
//! An agent can neither act on that nor learn from it. It does not say which
//! of the other requirements *were* met (so it cannot tell "nearly there"
//! from "hopeless"), it does not say how many candidates each strategy had
//! (so it cannot tell "no such gadget" from "the ones that exist have dirty
//! tails"), and it does not say what to change.
//!
//! [`ChainPlan`] is the structured answer. It ALWAYS succeeds: infeasibility
//! is a result, not an error. Every requirement carries the strategies the
//! synthesizer actually tried and how many candidates each had, and the
//! satisfied ones carry the gadget that satisfied them, addressable by the
//! same stable id `get_gadgets` round-trips.
//!
//! **Relaxations are computed, never guessed.** A relaxation entry's
//! `would_help` is filled in by RE-RUNNING the same probe against a scan
//! taken with that parameter changed (depth doubled, `--multibr` on) and
//! observing whether the requirement becomes satisfiable. The front end owns
//! the re-scan — this crate never scans — and merges the answers back with
//! [`ChainPlan::merge_relaxation`].

use serde::Serialize;

use crate::hex_u64;

/// One gadget shape the synthesizer asked for, and how many gadgets in this
/// scan answered it.
///
/// `pattern` is written in the same vocabulary the CLI's `--re` and the
/// MCP's `search_gadgets_by_pattern` accept, so a caller can re-run the
/// query itself and look at the candidates -- and, because `candidates`
/// counts only the ones the builder could actually USE (clean-tailed, and
/// modelled by the constraint layer), a re-run that returns more hits than
/// `candidates` is telling the caller exactly which gadgets were rejected
/// and why.
#[derive(Debug, Clone, Serialize)]
pub struct Strategy {
    /// The gadget pattern tried, in the `search` wildcard language.
    pub pattern: String,
    /// How many scanned gadgets the builder could actually USE for this.
    pub candidates: usize,
    /// What the strategy does, for a reader who does not know the pattern
    /// language.
    pub description: String,
}

impl Strategy {
    /// Record one strategy the builder tried.
    pub fn new(
        pattern: impl Into<String>,
        candidates: usize,
        description: impl Into<String>,
    ) -> Self {
        Strategy {
            pattern: pattern.into(),
            candidates,
            description: description.into(),
        }
    }
}

/// A parameter change and whether it would make an unsatisfied requirement
/// satisfiable. `would_help` is measured, not predicted.
#[derive(Debug, Clone, Serialize)]
pub struct Relaxation {
    /// The scan parameter that was changed (`depth`, `multibr`).
    pub param: String,
    /// Its value in the base scan.
    pub from: String,
    /// Its value in the re-scan.
    pub to: String,
    /// What the re-scan MEASURED: true when the requirement was satisfied
    /// with the parameter changed. Never a prediction.
    pub would_help: bool,
}

/// One thing the chain needs.
#[derive(Debug, Clone, Serialize)]
pub struct Requirement {
    /// Stable, machine-friendly: `set_rdx`, `write_primitive`, `api_transfer`.
    pub id: String,
    /// What the requirement means, for a human reader.
    pub description: String,
    /// Whether this binary meets it.
    pub satisfied: bool,
    /// Every strategy the builder tried, with its candidate count.
    pub strategies_tried: Vec<Strategy>,
    /// Measured parameter changes that would (or would not) help.
    pub relaxations: Vec<Relaxation>,
}

/// A requirement that IS met, and the gadget that meets it.
#[derive(Debug, Clone, Serialize)]
pub struct SatisfiedRequirement {
    /// The [`Requirement::id`] this satisfies.
    pub id: String,
    /// The stable id `find_gadgets` / `get_gadgets` use. Filled in by the
    /// front end, which is the only layer that knows the file hash; `null`
    /// when the requirement is met by something that is not a gadget of
    /// this binary (an `--api-addr`, a writable section).
    pub gadget_id: Option<String>,
    /// The satisfying gadget's address, or 0 when it is not a gadget.
    #[serde(serialize_with = "hex_u64")]
    pub vaddr: u64,
    /// The satisfying gadget's disassembly text.
    pub text: String,
}

/// What the plan took for granted.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PlanAssumptions {
    /// Windows x64 only: `aligned` / `return_address`. `null` elsewhere.
    pub chain_base_parity: Option<String>,
    /// The address the chain writes into, and the section it belongs to.
    pub write_target: Option<String>,
    /// Does this chain need a runtime address the tool cannot compute from
    /// the file alone (an ASLR leak, a libc base, a `--api-addr`)?
    pub needs_leak: bool,
}

/// The answer to "can this binary host this chain, and if not, why not?".
#[derive(Debug, Clone, Serialize)]
pub struct ChainPlan {
    /// The `--chain` target this plan is for.
    pub target: String,
    /// The architecture, as [`crate::arch_name`] spells it.
    pub arch: String,
    /// The container format (`elf`, `pe`).
    pub format: String,
    /// Ground truth: the real builder was run and it succeeded. The
    /// requirement list explains the verdict; it does not decide it, so a
    /// probe that drifts from the builder shows up as a contradiction
    /// rather than as a wrong answer.
    pub feasible: bool,
    /// Every requirement, satisfied or not, in builder order.
    pub requirements: Vec<Requirement>,
    /// The satisfied ones, with the gadget that satisfies each.
    pub satisfied_requirements: Vec<SatisfiedRequirement>,
    /// What the plan took for granted.
    pub assumptions: PlanAssumptions,
    /// The builder's structured refusal, when there was one.
    pub error: Option<String>,
    /// Words in the chain when `feasible`.
    pub word_count: Option<usize>,
}

impl ChainPlan {
    /// An empty plan for `(target, arch, format)`; requirements are added
    /// by the per-target probes.
    pub fn new(
        target: impl Into<String>,
        arch: impl Into<String>,
        format: impl Into<String>,
    ) -> Self {
        ChainPlan {
            target: target.into(),
            arch: arch.into(),
            format: format.into(),
            feasible: false,
            requirements: Vec::new(),
            satisfied_requirements: Vec::new(),
            assumptions: PlanAssumptions::default(),
            error: None,
            word_count: None,
        }
    }

    /// Is `id` unsatisfied in this plan?
    pub fn unsatisfied(&self, id: &str) -> bool {
        self.requirements.iter().any(|r| r.id == id && !r.satisfied)
    }

    /// The requirement with this id, if the plan has one.
    pub fn requirement(&self, id: &str) -> Option<&Requirement> {
        self.requirements.iter().find(|r| r.id == id)
    }

    /// Record a computed relaxation: `variant` is the SAME probe run against
    /// a scan taken with `param` changed from `from` to `to`.
    ///
    /// Only unsatisfied requirements get an entry — telling a caller that
    /// doubling the depth would also satisfy something already satisfied is
    /// noise — and `would_help` is whatever the re-run measured.
    pub fn merge_relaxation(&mut self, variant: &ChainPlan, param: &str, from: &str, to: &str) {
        for req in self.requirements.iter_mut().filter(|r| !r.satisfied) {
            let would_help = variant
                .requirement(&req.id)
                .map(|r| r.satisfied)
                .unwrap_or(false);
            req.relaxations.push(Relaxation {
                param: param.to_string(),
                from: from.to_string(),
                to: to.to_string(),
                would_help,
            });
        }
    }

    /// Attach the front end's stable gadget ids. `f` maps a vaddr to the id
    /// `find_gadgets` handed out for that gadget, or `None`.
    pub fn attach_gadget_ids(&mut self, f: impl Fn(u64) -> Option<String>) {
        for s in &mut self.satisfied_requirements {
            if s.vaddr != 0 {
                s.gadget_id = f(s.vaddr);
            }
        }
    }

    /// The plan as JSON - the document `--plan-chain` prints.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

/// Builder helper shared by the two probes: record a requirement and, when
/// it is satisfied, the gadget that satisfies it.
pub(crate) struct PlanBuilder {
    pub(crate) plan: ChainPlan,
}

impl PlanBuilder {
    pub(crate) fn new(plan: ChainPlan) -> Self {
        PlanBuilder { plan }
    }

    /// `hit`: `Some((vaddr, text))` when the requirement is met.
    pub(crate) fn require(
        &mut self,
        id: &str,
        description: String,
        strategies: Vec<Strategy>,
        hit: Option<(u64, String)>,
    ) {
        self.plan.requirements.push(Requirement {
            id: id.to_string(),
            description,
            satisfied: hit.is_some(),
            strategies_tried: strategies,
            relaxations: Vec::new(),
        });
        if let Some((vaddr, text)) = hit {
            self.plan.satisfied_requirements.push(SatisfiedRequirement {
                id: id.to_string(),
                gadget_id: None,
                vaddr,
                text,
            });
        }
    }
}
