//! ECO-06, the MCP half — `get_mitigations`, a `checksec` an agent can run
//! for itself.
//!
//! Before an agent decides ROP is even the right technique it has to know
//! whether the stack is executable, whether the image is PIE (so its
//! addresses are offsets), whether RELRO closed the GOT, and — on Windows —
//! whether CFG or a shadow stack is going to reject the chain. Today it has
//! to ask a human to run `checksec`.
//!
//! The report is rf-core's [`rf_core::Mitigations`], rendered verbatim:
//! this module decides NOTHING about a binary. Every `enabled` is the
//! loader's verdict and every `evidence` is the loader's sentence,
//! including the four places where rf-core deliberately disagrees with
//! `checksec.sh` and says so.
//!
//! **`unknown` is a first-class answer.** `Enabled::Unknown` serialises as
//! the string `"unknown"`, never as `false`. "No `PT_GNU_STACK`, so the
//! kernel default applies and I cannot tell you" is a far more useful thing
//! to hand an agent than a confident wrong boolean it will plan around.
//!
//! **Order is the loader's.** rf-core emits each format's keys in a fixed
//! declaration order (ELF: nx, pie, relro, canary, fortify, rpath, runpath;
//! PE: aslr, dep, high_entropy_va, guard_cf, cet_compat, safe_seh,
//! force_integrity; Mach-O: pie, nx_stack, nx_heap, code_signature,
//! hardened_runtime) and that order is meaningful. It is preserved by
//! reporting an ARRAY of named records rather than a JSON object: this
//! crate's responses are serialised through `serde_json::Value`, whose maps
//! are sorted, so an object would silently alphabetise the report. `name`
//! is the stable key an agent should match on.

use rf_core::{Enabled, Mitigations};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// `true` / `false` / `"unknown"` — the JSON contract ECO-06 names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum EnabledValue {
    /// A header field decided it.
    Known(bool),
    /// Nothing in the file decides it; `evidence` says why.
    Unknown(UnknownTag),
}

/// The single string `"unknown"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UnknownTag {
    Unknown,
}

impl From<Enabled> for EnabledValue {
    fn from(e: Enabled) -> Self {
        match e.as_bool() {
            Some(b) => EnabledValue::Known(b),
            None => EnabledValue::Unknown(UnknownTag::Unknown),
        }
    }
}

/// One mitigation, with the evidence that decided it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MitigationRecord {
    /// The stable key: `nx`, `pie`, `relro`, `canary`, `fortify`, `rpath`,
    /// `runpath` (ELF); `aslr`, `dep`, `high_entropy_va`, `guard_cf`,
    /// `cet_compat`, `safe_seh`, `force_integrity` (PE); `pie`, `nx_stack`,
    /// `nx_heap`, `code_signature`, `hardened_runtime` (Mach-O).
    pub name: String,
    /// `true`, `false`, or `"unknown"` — never `false` standing in for
    /// "could not tell".
    pub enabled: EnabledValue,
    /// The header field that decided it, or the one whose absence made the
    /// answer unknown. Never empty.
    pub evidence: String,
    /// The refinement, from a closed vocabulary: `full`/`partial`/`none`
    /// for relro, `pie-executable`/`shared-object`/`fixed-address-executable`
    /// for pie, the `__*_chk` names for fortify, the GuardFlags word for
    /// guard_cf, the path for rpath/runpath.
    pub detail: Option<String>,
}

/// One slice of a fat (Universal) Mach-O.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SliceMitigations {
    /// rop-finder's arch spelling (`x64`), the one `find_gadgets` reports.
    pub arch: String,
    /// The Mach-O spelling (`x86_64`) — this is the value `arch` takes.
    pub slice: String,
    /// This slice's report, in loader order.
    pub mitigations: Vec<MitigationRecord>,
}

/// `get_mitigations`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MitigationsResponse {
    /// `elf`, `pe`, `macho`, `universal` or `raw`.
    pub format: String,
    /// rop-finder's arch spelling; `null` for a fat container, whose
    /// slices disagree.
    pub arch: Option<String>,
    /// The report, in the loader's own order. Empty for a raw blob (see
    /// `note`) and for a fat Mach-O (see `slices`) — never empty because a
    /// mitigation was skipped.
    pub mitigations: Vec<MitigationRecord>,
    /// Why the report is EMPTY, when it is. `null` otherwise.
    pub note: Option<String>,
    /// One report per slice of a fat Mach-O; `[]` for every other
    /// container. The flags genuinely differ between slices.
    pub slices: Vec<SliceMitigations>,
    /// SHA-256 of the analysed file.
    pub binary_sha256: String,
    /// The binary's path relative to its allow root — what the audit log
    /// records, never the caller's spelling.
    pub binary_label: String,
    /// Non-fatal facts. Always present; `[]` when there are none.
    pub warnings: Vec<crate::schema::Warning>,
}

fn records(m: &Mitigations) -> Vec<MitigationRecord> {
    m.iter()
        .map(|(name, v)| MitigationRecord {
            name: name.to_string(),
            enabled: v.enabled.into(),
            evidence: v.evidence.clone(),
            detail: v.detail.clone(),
        })
        .collect()
}

/// Build the report for a loaded target.
///
/// `binary_sha256` / `binary_label` are the caller's; everything else comes
/// from rf-core.
#[must_use]
pub fn report(
    target: &rf_cli::Target,
    binary_sha256: String,
    binary_label: String,
) -> MitigationsResponse {
    use rf_cli::Target;
    use rf_core::Image;

    let mut warnings = Vec::new();
    let (format, arch, mitigations, note, slices) = match target {
        Target::Elf(b) => {
            let m = b.mitigations();
            (
                "elf",
                Some(rf_cli::arch_name(Image::arch(b)).to_string()),
                records(m),
                m.note().map(str::to_string),
                Vec::new(),
            )
        }
        Target::Pe(b) => {
            let m = b.mitigations();
            (
                "pe",
                Some(rf_cli::arch_name(Image::arch(b)).to_string()),
                records(m),
                m.note().map(str::to_string),
                Vec::new(),
            )
        }
        Target::MachO(b) => {
            let m = b.mitigations();
            (
                "macho",
                Some(rf_cli::arch_name(Image::arch(b)).to_string()),
                records(m),
                m.note().map(str::to_string),
                Vec::new(),
            )
        }
        Target::Raw(b) => {
            let m = b.mitigations();
            (
                "raw",
                Some(rf_cli::arch_name(Image::arch(b)).to_string()),
                records(&m),
                m.note().map(str::to_string),
                Vec::new(),
            )
        }
        // The one shape that is deliberately not flat: a fat container's
        // slices really do disagree (the shipped libSystem fixture's
        // x86_64 and i386 slices differ on nx_heap), so reporting one
        // merged answer would be a lie about at least one of them.
        Target::Universal(u) => {
            let slices: Vec<SliceMitigations> = u
                .slices()
                .iter()
                .zip(u.slice_infos())
                .map(|(s, info)| SliceMitigations {
                    arch: rf_cli::arch_name(Image::arch(s)).to_string(),
                    slice: info.name().to_string(),
                    mitigations: records(s.mitigations()),
                })
                .collect();
            warnings.push(crate::schema::Warning::new(
                "per_slice_mitigations",
                "this is a fat (Universal) Mach-O; the mitigation flags are per slice and are \
                 reported in `slices`, not in `mitigations`",
            ));
            (
                "universal",
                None,
                Vec::new(),
                Some(format!(
                    "fat (Universal) Mach-O with {} slices; each slice carries its own flags, \
                     so there is no single report for the container",
                    slices.len()
                )),
                slices,
            )
        }
    };

    if mitigations.is_empty() && slices.is_empty() && note.is_none() {
        warnings.push(crate::schema::Warning::new(
            "no_mitigation_report",
            "this container reported no mitigations and gave no reason",
        ));
    }

    MitigationsResponse {
        format: format.to_string(),
        arch,
        mitigations,
        note,
        slices,
        binary_sha256,
        binary_label,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_serializes_as_the_string_and_never_as_false() {
        let v: EnabledValue = Enabled::Unknown.into();
        assert_eq!(
            serde_json::to_value(v).unwrap(),
            serde_json::json!("unknown")
        );
        let v: EnabledValue = Enabled::Yes.into();
        assert_eq!(serde_json::to_value(v).unwrap(), serde_json::json!(true));
        let v: EnabledValue = Enabled::No.into();
        assert_eq!(serde_json::to_value(v).unwrap(), serde_json::json!(false));
    }

    #[test]
    fn a_raw_blob_reports_an_empty_set_with_its_reason() {
        // A raw blob is whatever bytes you hand it; 8 NOPs will do.
        let target = rf_cli::load_target(
            &[0x90u8; 8],
            Some((rf_core::Arch::X64, rf_core::Endianness::Little, false)),
        )
        .expect("raw target");
        let r = report(&target, "sha".into(), "label".into());
        assert_eq!(r.format, "raw");
        assert!(r.mitigations.is_empty());
        let note = r.note.expect("a raw blob must say why the set is empty");
        assert!(note.contains("no container headers"), "{note}");
        assert!(r.slices.is_empty());
    }
}
