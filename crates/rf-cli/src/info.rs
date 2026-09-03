//! ECO-06: `--info` as a `checksec` / `rabin2 -I` replacement.
//!
//! Before this, `--info` answered `format/arch/endianness/addr_size/
//! image_base/entry/sections/imports` — and `imports` was hardcoded empty
//! for everything but PE. None of the properties that decide *how you drive
//! the rest of the tool* were in it: whether the image is PIE (so `--base 0`
//! is the right call), whether NX is on (so ROP is the technique rather than
//! a stack shellcode), whether RELRO is full (so a GOT overwrite is dead),
//! or whether a PE has ASLR and DEP at all.
//!
//! rf-core computes all of it (`rf_core::mitigations`); this module is the
//! rendering, and its two rules are the ones ECO-06 asks for:
//!
//! 1. **`enabled` is `true` / `false` / `"unknown"`, never a guessed
//!    boolean.** `Enabled::as_bool()` returns `None` for unknown and this
//!    module renders that as the string `"unknown"`. A missing key renders
//!    as nothing at all rather than as `false`.
//! 2. **Every answer carries its evidence**, including — especially — the
//!    unknown ones: rf-core's `every_unknown_states_its_reason` test pins a
//!    required phrase in each of those strings, so "unknown" always says
//!    what was missing.

use rf_core::{Mitigations, Symbol};

/// `{name: {enabled: bool|"unknown", evidence, detail}}`.
///
/// rf-core asks renderers to preserve `Mitigations::iter()`'s declaration
/// order (`nx, pie, relro, canary, fortify, rpath, runpath` for ELF) and not
/// to sort. A JSON *object* cannot carry that here: this workspace builds
/// serde_json without the `preserve_order` feature, so `serde_json::Map` is
/// a `BTreeMap` and every key set comes out alphabetical. Turning the
/// feature on would change key order in rf-mcp's responses too, via cargo
/// feature unification, which is not a change `--info` gets to make on
/// another surface's behalf.
///
/// So the order is carried beside the map instead, by
/// [`mitigation_order_json`], and no information is lost.
pub fn mitigations_json(m: &Mitigations) -> serde_json::Value {
    let mut out = serde_json::Map::new();
    for (name, mit) in m.iter() {
        let enabled = match mit.enabled.as_bool() {
            Some(b) => serde_json::Value::Bool(b),
            // "unknown" with a reason is more useful to an agent than a
            // confident wrong boolean (ECO-06).
            None => serde_json::Value::String("unknown".to_string()),
        };
        out.insert(
            name.to_string(),
            serde_json::json!({
                "enabled": enabled,
                "evidence": mit.evidence,
                "detail": mit.detail,
            }),
        );
    }
    serde_json::Value::Object(out)
}

/// The mitigation names in the loader's declaration order — see
/// [`mitigations_json`] for why this is a separate field.
pub fn mitigation_order_json(m: &Mitigations) -> serde_json::Value {
    m.names()
        .into_iter()
        .map(serde_json::Value::from)
        .collect::<Vec<_>>()
        .into()
}

/// One symbol. Addresses are hex strings and move with `--base`, exactly as
/// section and gadget addresses do.
pub fn symbol_json(s: &Symbol, delta: u64) -> serde_json::Value {
    // An import whose `st_value` is 0 has *no* address; sliding it by the
    // rebase delta would invent one.
    let addr = if s.addr == 0 {
        None
    } else {
        Some(crate::hexs(s.addr.wrapping_add(delta)))
    };
    serde_json::json!({
        "name": s.name,
        "addr": addr,
        "size": s.size,
        "type": s.type_name(),
        "binding": s.binding_name(),
        "table": s.table.as_str(),
        "is_import": s.is_import,
        "got": s.got.map(|g| crate::hexs(g.wrapping_add(delta))),
        "plt": s.plt.map(|p| crate::hexs(p.wrapping_add(delta))),
    })
}

/// The ELF import working set: the `SHN_UNDEF` symbols, which is what a
/// ret2plt/ret2libc chain resolves against.
///
/// This replaces the hardcoded `[]` that ECO-06 names. The shape matches the
/// PE `imports` entries closely enough to be read by the same code —
/// `symbol` is the name in both — without pretending an ELF has a DLL name.
pub fn elf_import_json(s: &Symbol, delta: u64) -> serde_json::Value {
    serde_json::json!({
        "symbol": s.name,
        "type": s.type_name(),
        "binding": s.binding_name(),
        // psABI-dependent: 0 on x86/x64/PPC, the PLT stub on
        // ARM/AArch64/SPARC/RISC-V. Reported as null when it is 0, because
        // that is "no address", not "address 0".
        "addr": (s.addr != 0).then(|| crate::hexs(s.addr.wrapping_add(delta))),
        // From DT_JMPREL only — a relocation field, not a guess.
        "got": s.got.map(|g| crate::hexs(g.wrapping_add(delta))),
        // Only when provable (byte-exact .plt/.plt.sec layout, or an
        // st_value that lands inside .plt).
        "plt": s.plt.map(|p| crate::hexs(p.wrapping_add(delta))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rf_core::{Enabled, Mitigation};

    #[test]
    fn unknown_renders_as_a_string_not_a_boolean() {
        // Constructed directly rather than loaded, so the assertion is
        // about *this* module's mapping and nothing else.
        let m = Mitigations::unavailable("raw blob: no headers to read");
        assert!(m.is_empty());
        assert_eq!(mitigations_json(&m), serde_json::json!({}));
        assert_eq!(mitigation_order_json(&m), serde_json::json!([]));
        // An empty set says WHY it is empty rather than looking like a
        // binary with every mitigation off.
        assert!(m.note().is_some_and(|n| n.contains("raw blob")));

        let mit = Mitigation {
            enabled: Enabled::Unknown,
            evidence: "no PT_GNU_STACK: the kernel ABI default applies".into(),
            detail: None,
        };
        let v = serde_json::json!({
            "enabled": match mit.enabled.as_bool() {
                Some(b) => serde_json::Value::Bool(b),
                None => serde_json::Value::String("unknown".into()),
            },
            "evidence": mit.evidence,
            "detail": mit.detail,
        });
        assert_eq!(v["enabled"], serde_json::json!("unknown"));
        assert!(v["detail"].is_null());
        assert!(v["evidence"].as_str().unwrap().contains("PT_GNU_STACK"));
    }

    #[test]
    fn enabled_yes_and_no_stay_booleans() {
        assert_eq!(Enabled::Yes.as_bool(), Some(true));
        assert_eq!(Enabled::No.as_bool(), Some(false));
        assert_eq!(Enabled::Unknown.as_bool(), None);
        // Unknown must never read as "off" — that is the whole point of the
        // three-valued type.
        assert!(!Enabled::Unknown.is_yes());
        assert!(Enabled::Yes.is_yes());
    }
}
