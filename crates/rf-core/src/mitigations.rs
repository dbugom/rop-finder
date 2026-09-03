//! Exploit-mitigation reporting (ECO-06).
//!
//! Before an agent decides ROP is even the right technique it has to know
//! whether the stack is executable, whether the image moves, whether the GOT
//! is writable and whether a canary sits between the overflow and the saved
//! return address. `--info` used to answer none of that, so the answer had to
//! come from a human running `checksec`.
//!
//! The loaders own this: they already hold the headers, so the front ends
//! only render. Every reader is a pure function of the container headers —
//! there is no heuristic and no probe.
//!
//! # The report shape, and why it is a tri-state
//!
//! Every mitigation is `{enabled: true | false | "unknown", evidence: "…"}`.
//! **"unknown" with a stated reason is worth more to an agent than a
//! confident wrong boolean**, so a reader that cannot see the deciding bytes
//! says so instead of defaulting. Three shapes recur:
//!
//! * The header that carries the answer is absent — an ELF with no
//!   `PT_GNU_STACK` does not state its stack permission; the kernel's ABI
//!   default applies. `checksec.sh` prints "NX enabled" there because it only
//!   greps for a `GNU_STACK` line carrying `RWE`; that is a guess, and this
//!   crate reports [`Enabled::Unknown`] instead.
//! * There is nothing to read at all — a fully stripped ELF with neither
//!   `.dynsym` nor `.symtab` cannot be asked about `__stack_chk_fail`.
//! * The evidence is real but does not carry the conclusion — a statically
//!   linked binary whose `.symtab` defines `__memcpy_chk` proves the linked
//!   libc *provides* the fortified variant, not that this program's own call
//!   sites were compiled against it.
//!
//! [`Mitigation::detail`] carries the sub-answer a boolean cannot: RELRO's
//! `partial` vs `full`, PIE's `pie-executable` vs `shared-object`, PE
//! `GuardFlags`.
//!
//! # Divergences from `checksec.sh`, stated once
//!
//! | case | `checksec.sh` | this crate |
//! |---|---|---|
//! | no `PT_GNU_STACK` | `NX enabled` | `nx` = unknown, reason stated |
//! | no symbol table at all | `No canary found` | `canary` = unknown, reason stated |
//! | static binary defining `*_chk` | `FORTIFY` heuristic over a libc list | `fortify` = unknown, reason stated |
//! | `ET_DYN` without interp/`DT_DEBUG` | `DSO` | `pie` = true, detail `shared-object` |
//!
//! Every other field matches `checksec.sh` exactly; see
//! `crates/rf-core/tests/mitigations.rs`, whose expected values were derived
//! from an independent `pyelftools`/`pefile` parse rather than from this code.

use std::fmt;

/// Tri-state answer to "is this mitigation on?".
///
/// [`Unknown`](Enabled::Unknown) is a first-class answer, not an error: it
/// means the container does not carry the deciding bytes, and the paired
/// [`Mitigation::evidence`] always says which bytes were missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Enabled {
    Yes,
    No,
    Unknown,
}

impl Enabled {
    /// `Some(true|false)` for a decided answer, `None` for
    /// [`Unknown`](Enabled::Unknown). This is the JSON contract: serialise
    /// `Some(b)` as the bool `b` and `None` as the string `"unknown"`.
    pub fn as_bool(self) -> Option<bool> {
        match self {
            Enabled::Yes => Some(true),
            Enabled::No => Some(false),
            Enabled::Unknown => None,
        }
    }

    /// `"true"` / `"false"` / `"unknown"` — the human rendering.
    pub fn as_str(self) -> &'static str {
        match self {
            Enabled::Yes => "true",
            Enabled::No => "false",
            Enabled::Unknown => "unknown",
        }
    }

    /// True only for [`Yes`](Enabled::Yes). Deliberately *not* `PartialEq`
    /// sugar: `Unknown` must never silently read as "off".
    pub fn is_yes(self) -> bool {
        self == Enabled::Yes
    }
}

impl From<bool> for Enabled {
    fn from(b: bool) -> Self {
        if b {
            Enabled::Yes
        } else {
            Enabled::No
        }
    }
}

impl fmt::Display for Enabled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One mitigation reading: the answer, the header bytes it rests on, and an
/// optional sub-answer a boolean cannot express.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mitigation {
    /// Tri-state verdict.
    pub enabled: Enabled,
    /// Why. Always names the concrete header field, segment or symbol that
    /// decided it — or, for [`Enabled::Unknown`], the one that was missing.
    /// Never empty.
    pub evidence: String,
    /// Sub-answer where the boolean is lossy: `"partial"` / `"full"` for
    /// RELRO, `"pie-executable"` / `"shared-object"` for PIE, the decoded
    /// `GuardFlags` for PE Control Flow Guard.
    pub detail: Option<String>,
}

impl Mitigation {
    pub(crate) fn new(enabled: Enabled, evidence: impl Into<String>) -> Self {
        Mitigation {
            enabled,
            evidence: evidence.into(),
            detail: None,
        }
    }

    pub(crate) fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// The mitigation report for one loaded image: an ordered, name-keyed set.
///
/// Order is the loader's declaration order and is stable across runs, so a
/// front end can render it directly without sorting. Names are stable API —
/// see the per-format constants in this module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mitigations {
    entries: Vec<(&'static str, Mitigation)>,
    note: Option<String>,
}

impl Mitigations {
    /// A report for a container that carries no mitigation metadata at all
    /// (a raw blob). Empty, but with a stated reason — the same contract as
    /// [`Enabled::Unknown`], one level up.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Mitigations {
            entries: Vec::new(),
            note: Some(reason.into()),
        }
    }

    pub(crate) fn push(&mut self, name: &'static str, m: Mitigation) {
        debug_assert!(!m.evidence.is_empty(), "{name}: evidence must not be empty");
        self.entries.push((name, m));
    }

    /// Iterate in loader declaration order.
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &Mitigation)> + '_ {
        self.entries.iter().map(|(n, m)| (*n, m))
    }

    /// Look one mitigation up by its stable name.
    pub fn get(&self, name: &str) -> Option<&Mitigation> {
        self.entries
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, m)| m)
    }

    /// The verdict for `name`, or [`Enabled::Unknown`] when this container
    /// does not report that mitigation at all.
    pub fn enabled(&self, name: &str) -> Enabled {
        self.get(name).map_or(Enabled::Unknown, |m| m.enabled)
    }

    /// Why the set is empty, for a container with no mitigation metadata.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Stable names, in report order. Handy for capability-matrix tests.
    pub fn names(&self) -> Vec<&'static str> {
        self.entries.iter().map(|(n, _)| *n).collect()
    }
}

impl<'a> IntoIterator for &'a Mitigations {
    type Item = (&'static str, &'a Mitigation);
    type IntoIter = Box<dyn Iterator<Item = (&'static str, &'a Mitigation)> + 'a>;
    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

// ---------------------------------------------------------------------------
// Stable mitigation names.
// ---------------------------------------------------------------------------

/// ELF: non-executable stack, from `PT_GNU_STACK`.
pub const NX: &str = "nx";
/// ELF/Mach-O: position independence.
pub const PIE: &str = "pie";
/// ELF: `PT_GNU_RELRO` (+ bind-now for `full`).
pub const RELRO: &str = "relro";
/// ELF: stack-protector, from a `__stack_chk_fail` reference.
pub const CANARY: &str = "canary";
/// ELF: `_FORTIFY_SOURCE`, from `__*_chk` references.
pub const FORTIFY: &str = "fortify";
/// ELF: `DT_RPATH` present.
pub const RPATH: &str = "rpath";
/// ELF: `DT_RUNPATH` present.
pub const RUNPATH: &str = "runpath";

/// PE: `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE`.
pub const ASLR: &str = "aslr";
/// PE: `IMAGE_DLLCHARACTERISTICS_NX_COMPAT`.
pub const DEP: &str = "dep";
/// PE: `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA`.
pub const HIGH_ENTROPY_VA: &str = "high_entropy_va";
/// PE: `IMAGE_DLLCHARACTERISTICS_GUARD_CF` (+ load-config `GuardFlags`).
pub const GUARD_CF: &str = "guard_cf";
/// PE: CET shadow-stack compatibility, from the `EX_DLLCHARACTERISTICS`
/// debug-directory entry. Distinct from [`GUARD_CF`] — see CRIT-01.
pub const CET_COMPAT: &str = "cet_compat";
/// PE: SafeSEH, from the load-config `SEHandlerTable`.
pub const SAFE_SEH: &str = "safe_seh";
/// PE: `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY`.
pub const FORCE_INTEGRITY: &str = "force_integrity";

/// Mach-O: stack is not marked executable (`MH_ALLOW_STACK_EXECUTION` clear).
pub const NX_STACK: &str = "nx_stack";
/// Mach-O: heap is not executable.
pub const NX_HEAP: &str = "nx_heap";
/// Mach-O: an `LC_CODE_SIGNATURE` load command is present.
pub const CODE_SIGNATURE: &str = "code_signature";
/// Mach-O: hardened runtime (`CS_RUNTIME` in the CodeDirectory flags).
pub const HARDENED_RUNTIME: &str = "hardened_runtime";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_tri_state_never_collapses_unknown_to_false() {
        assert_eq!(Enabled::Yes.as_bool(), Some(true));
        assert_eq!(Enabled::No.as_bool(), Some(false));
        assert_eq!(Enabled::Unknown.as_bool(), None);
        assert!(Enabled::Yes.is_yes());
        assert!(!Enabled::No.is_yes());
        assert!(!Enabled::Unknown.is_yes());
        assert_eq!(Enabled::Unknown.as_str(), "unknown");
        assert_eq!(Enabled::from(true), Enabled::Yes);
        assert_eq!(Enabled::from(false), Enabled::No);
    }

    #[test]
    fn unavailable_carries_a_reason() {
        let m = Mitigations::unavailable("raw blob: no container headers");
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
        assert_eq!(m.note(), Some("raw blob: no container headers"));
        // A missing entry reads as unknown, never as "off".
        assert_eq!(m.enabled(NX), Enabled::Unknown);
        assert!(m.get(NX).is_none());
    }

    #[test]
    fn set_preserves_declaration_order_and_details() {
        let mut m = Mitigations::default();
        m.push(NX, Mitigation::new(Enabled::Yes, "PT_GNU_STACK RW"));
        m.push(
            RELRO,
            Mitigation::new(Enabled::Yes, "PT_GNU_RELRO").with_detail("partial"),
        );
        assert_eq!(m.names(), vec![NX, RELRO]);
        assert_eq!(m.get(RELRO).unwrap().detail.as_deref(), Some("partial"));
        assert_eq!(m.get(NX).unwrap().detail, None);
        assert_eq!(m.iter().count(), 2);
        assert!(m.note().is_none());
    }
}
