//! ECO-06 on the real server — `get_mitigations`, the checksec an agent
//! can run before it decides ROP is the right technique at all.
//!
//! The finding: `--info` reported format/arch/sections and nothing that
//! decides how you drive the rest of the tool. There was no way, anywhere
//! in the product, for an agent to learn whether the stack was executable
//! or the image was PIE — it had to ask a human to run `checksec`.
//!
//! The contract these tests pin is the one ECO-06 states: `{enabled: bool |
//! "unknown", evidence}`, with `"unknown"` a first-class answer that never
//! degrades into `false`.

mod support;

use serde_json::{json, Value};

use support::{fixtures_dir, structured, McpChild};

fn by_name<'a>(body: &'a Value, name: &str) -> Option<&'a Value> {
    body["mitigations"]
        .as_array()?
        .iter()
        .find(|m| m["name"] == name)
}

/// An ELF reports the seven ELF keys, in the loader's order, each with its
/// evidence.
#[tokio::test]
async fn an_elf_reports_the_seven_elf_mitigations() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let r = mcp
        .call_tool(1, "get_mitigations", json!({"binary_path": elf}))
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    assert_eq!(body["format"], "elf", "{body}");
    assert_eq!(body["arch"], "x64", "{body}");
    assert!(body["slices"].as_array().unwrap().is_empty(), "{body}");

    let names: Vec<&str> = body["mitigations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    println!("elf-Linux-x64 mitigations, in loader order: {names:?}");
    assert_eq!(
        names,
        ["nx", "pie", "relro", "canary", "fortify", "rpath", "runpath"],
        "the loader's declaration order is the report's order"
    );

    for m in body["mitigations"].as_array().unwrap() {
        println!(
            "  {:<8} {:<8} {}",
            m["name"].as_str().unwrap(),
            m["enabled"].to_string(),
            m["evidence"].as_str().unwrap()
        );
        // The ECO-06 contract, per record.
        assert!(
            m["enabled"].is_boolean() || m["enabled"] == "unknown",
            "enabled must be a bool or the string \"unknown\": {m}"
        );
        let ev = m["evidence"].as_str().unwrap_or_else(|| panic!("{m}"));
        assert!(!ev.is_empty(), "evidence is never empty: {m}");
        assert!(m.get("detail").is_some(), "detail is always present: {m}");
    }

    // This fixture is a statically linked non-PIE executable.
    let pie = by_name(body, "pie").expect("pie");
    assert_eq!(pie["enabled"], false, "{pie}");
    assert_eq!(pie["detail"], "fixed-address-executable", "{pie}");
}

/// `unknown` is an answer, not a missing field — and it always says why.
///
/// The four fixtures rf-core names have no `PT_GNU_STACK`, so the kernel's
/// ABI default applies and nothing in the file decides NX. `checksec.sh`
/// prints "NX enabled" here; that is a guess, and a guess is worse than
/// `unknown` for something planning around it.
#[tokio::test]
async fn unknown_is_reported_as_unknown_with_a_reason() {
    let mut mcp = McpChild::spawn().await;
    let mut seen_unknown = 0;
    for (id, fixture) in [
        (1u64, "elf-ARM64-bash"),
        (2, "elf-FreeBSD-x86"),
        (3, "elf-Linux-RISCV_64"),
        (4, "elf-Mips-Defcon-20-pwn100"),
    ] {
        let r = mcp
            .call_tool(
                id,
                "get_mitigations",
                json!({"binary_path": fixtures_dir().join(fixture)}),
            )
            .await;
        assert_eq!(r["result"]["isError"], false, "{fixture}: {r}");
        let body = structured(&r);
        let nx = by_name(body, "nx").unwrap_or_else(|| panic!("{fixture}: no nx: {body}"));
        println!(
            "{fixture}: nx = {} — {}",
            nx["enabled"],
            nx["evidence"].as_str().unwrap()
        );
        assert_eq!(
            nx["enabled"], "unknown",
            "{fixture}: no PT_GNU_STACK must read as unknown, never as a boolean: {nx}"
        );
        assert!(
            !nx["evidence"].as_str().unwrap().is_empty(),
            "{fixture}: an unknown with no reason is useless: {nx}"
        );
        seen_unknown += 1;
    }
    assert_eq!(seen_unknown, 4);
}

/// CRIT-01's honesty fix, reaching an agent: `guard_cf` and `cet_compat`
/// are SEPARATE answers from separate directories, and the CFG evidence
/// says out loud that it does not validate a `ret`.
#[tokio::test]
async fn a_pe_separates_cfg_from_cet() {
    let mut mcp = McpChild::spawn().await;
    let pe = fixtures_dir().join("pe-x64-cmd-v6.1.7601");
    let r = mcp
        .call_tool(1, "get_mitigations", json!({"binary_path": pe}))
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    assert_eq!(body["format"], "pe", "{body}");
    let names: Vec<&str> = body["mitigations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["name"].as_str().unwrap())
        .collect();
    println!("pe-x64-cmd mitigations: {names:?}");
    assert_eq!(
        names,
        [
            "aslr",
            "dep",
            "high_entropy_va",
            "guard_cf",
            "cet_compat",
            "safe_seh",
            "force_integrity"
        ]
    );
    for m in body["mitigations"].as_array().unwrap() {
        println!(
            "  {:<16} {:<8} {}",
            m["name"].as_str().unwrap(),
            m["enabled"].to_string(),
            m["evidence"].as_str().unwrap()
        );
    }
    let cfg = by_name(body, "guard_cf").unwrap();
    let cet = by_name(body, "cet_compat").unwrap();
    assert_ne!(
        cfg["evidence"], cet["evidence"],
        "CFG and CET must not share one verdict: {cfg} / {cet}"
    );
    // The two are read from DIFFERENT directories — DllCharacteristics plus
    // the load config for CFG, the IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
    // record for CET — and each evidence says which.
    assert!(
        cfg["evidence"]
            .as_str()
            .unwrap()
            .contains("DllCharacteristics"),
        "{cfg}"
    );
    let cet_ev = cet["evidence"].as_str().unwrap().to_lowercase();
    assert!(
        cet_ev.contains("shadow stack") && cet_ev.contains("guard_cf"),
        "the CET evidence must be the one that distinguishes backward-edge \
         protection from CFG's forward-edge-only check: {cet}"
    );
    // v0.2's CRIT-01 warning conflated the two; it now cannot, because they
    // are separate keys with separate verdicts.
    assert!(
        !cfg["evidence"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("shadow stack"),
        "the CFG verdict must not claim anything about a shadow stack: {cfg}"
    );
}

/// A fat Mach-O reports one set per slice, because the slices disagree.
#[tokio::test]
async fn a_fat_macho_reports_one_set_per_slice() {
    let mut mcp = McpChild::spawn().await;
    let fat = fixtures_dir().join("UNIVERSAL-x86-x64-libSystem.B.dylib");
    let r = mcp
        .call_tool(1, "get_mitigations", json!({"binary_path": fat}))
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    assert_eq!(body["format"], "universal", "{body}");
    assert!(body["arch"].is_null(), "{body}");
    assert!(
        body["mitigations"].as_array().unwrap().is_empty(),
        "a container-level answer would be a lie about at least one slice: {body}"
    );
    assert!(body["note"].is_string(), "{body}");
    let slices = body["slices"].as_array().unwrap();
    assert!(slices.len() >= 2, "{body}");
    for s in slices {
        let names: Vec<&str> = s["mitigations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["name"].as_str().unwrap())
            .collect();
        println!(
            "slice {} ({}): {names:?}",
            s["slice"].as_str().unwrap(),
            s["arch"].as_str().unwrap()
        );
        assert_eq!(
            names,
            [
                "pie",
                "nx_stack",
                "nx_heap",
                "code_signature",
                "hardened_runtime"
            ]
        );
    }
    let codes: Vec<&str> = body["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"per_slice_mitigations"), "{codes:?}");
}

/// Every shipped fixture answers, and no answer is malformed: `enabled` is
/// always a bool or `"unknown"`, `evidence` is never empty, and nothing is
/// silently absent.
#[tokio::test]
async fn every_fixture_reports_a_well_formed_set() {
    let mut mcp = McpChild::spawn().await;
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .expect("fixtures")
        .filter_map(|e| {
            let e = e.ok()?;
            let n = e.file_name().to_string_lossy().into_owned();
            (e.file_type().ok()?.is_file() && n != "MANIFEST.sha256" && n != "PROVENANCE.md")
                .then_some(n)
        })
        .collect();
    names.sort();
    assert_eq!(names.len(), 24, "{names:?}");

    let mut id = 1u64;
    let (mut ok, mut unknowns, mut records) = (0usize, 0usize, 0usize);
    for fixture in &names {
        let r = mcp
            .call_tool(
                id,
                "get_mitigations",
                json!({"binary_path": fixtures_dir().join(fixture)}),
            )
            .await;
        id += 1;
        if r["result"]["isError"] == Value::Bool(true) {
            // An unsupported container is a clean error, not a panic.
            let code = structured(&r)["error"]["code"].as_str().unwrap();
            println!("{fixture}: {code}");
            assert_eq!(code, "unsupported_binary", "{fixture}: {r}");
            continue;
        }
        ok += 1;
        let body = structured(&r);
        let sets = std::iter::once(body["mitigations"].as_array().unwrap()).chain(
            body["slices"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["mitigations"].as_array().unwrap()),
        );
        let mut n = 0;
        for set in sets {
            for m in set {
                assert!(
                    m["enabled"].is_boolean() || m["enabled"] == "unknown",
                    "{fixture}: {m}"
                );
                if m["enabled"] == "unknown" {
                    unknowns += 1;
                }
                assert!(
                    !m["evidence"].as_str().unwrap_or_default().is_empty(),
                    "{fixture}: {m}"
                );
                n += 1;
                records += 1;
            }
        }
        // An empty report must carry its reason.
        if n == 0 {
            assert!(
                body["note"].is_string(),
                "{fixture}: an empty report with no note: {body}"
            );
        }
    }
    println!(
        "every_fixture_reports_a_well_formed_set: {ok} of {} fixtures reported, \
         {records} mitigation records, {unknowns} of them \"unknown\"",
        names.len()
    );
    assert!(ok >= 20, "only {ok} fixtures reported");
    assert!(unknowns > 0, "no fixture exercised the unknown path");
}

/// ECO-06's other half: ELF symbols and PLT/GOT reach the agent.
///
/// `get_binary_info`'s `imports` was hardcoded `[]` for every ELF, so
/// building a ret2plt chain meant leaving rop-finder for a second tool.
/// Now a dynamic ELF reports its `.dynsym`/`.symtab`, its SHN_UNDEF subset
/// as `imports`, and — where the layout proves it — a GOT slot and a PLT
/// stub per import.
#[tokio::test]
async fn a_dynamic_elf_reports_symbols_imports_and_got() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("Linux_lib64.so");
    // Symbols are opt-in since DEFAULT_MAX_SYMBOLS = 0 (a 2169-entry symtab
    // was an 80k-token first call); `max_symbols` is how an agent asks.
    let r = mcp
        .call_tool(
            1,
            "get_binary_info",
            json!({"binary_path": elf, "max_symbols": 4096}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    let symbols = body["symbols"].as_array().unwrap();
    let imports = body["imports"].as_array().unwrap();
    let count = body["symbol_count"].as_u64();
    println!(
        "Linux_lib64.so: symbol_count {count:?}, {} symbols reported, {} imports",
        symbols.len(),
        imports.len()
    );
    assert!(count.is_some(), "an ELF's symbols are read: {body}");
    assert!(!symbols.is_empty(), "a dynamic ELF has a .dynsym: {body}");
    assert!(
        !imports.is_empty(),
        "a dynamic ELF has undefined symbols: {body}"
    );

    // The record shape is fixed: every key present, null where unknown.
    for s in symbols.iter().take(50) {
        for key in [
            "name",
            "addr",
            "size",
            "sym_type",
            "binding",
            "table",
            "is_import",
            "got",
            "plt",
        ] {
            assert!(s.get(key).is_some(), "symbol is missing {key}: {s}");
        }
        assert!(!s["name"].as_str().unwrap().is_empty(), "{s}");
        assert!(
            matches!(s["table"].as_str(), Some("dynsym" | "symtab")),
            "{s}"
        );
    }
    for i in imports.iter().take(50) {
        for key in [
            "dll",
            "symbol",
            "iat_vaddr",
            "hint_name_vaddr",
            "addr",
            "got",
            "plt",
            "sym_type",
            "binding",
        ] {
            assert!(i.get(key).is_some(), "import is missing {key}: {i}");
        }
        // An ELF import has no DLL and no IAT — those are PE concepts, and
        // reporting "" for them would be a lie rather than an absence.
        assert!(i["dll"].is_null(), "{i}");
        assert!(i["iat_vaddr"].is_null(), "{i}");
    }
    let with_got = imports.iter().filter(|i| i["got"].is_string()).count();
    let with_plt = imports.iter().filter(|i| i["plt"].is_string()).count();
    println!(
        "  of {} imports, {with_got} carry a GOT slot and {with_plt} a PLT stub",
        imports.len()
    );
    assert!(with_got > 0, "DT_JMPREL gave no GOT slots at all: {body}");

    // A PE keeps the PE shape, and reports no ELF symbol table rather than
    // an empty one that would read as "this file has none".
    let pe = fixtures_dir().join("pe-x64-cmd-v6.1.7601");
    let r = mcp
        .call_tool(2, "get_binary_info", json!({"binary_path": pe}))
        .await;
    let body = structured(&r);
    assert!(
        body["symbol_count"].is_null(),
        "a PE's symbols are not read; null says so, [] would not: {}",
        body["symbol_count"]
    );
    assert!(body["symbols"].as_array().unwrap().is_empty(), "{body}");
    let first = &body["imports"][0];
    assert!(first["dll"].is_string(), "{first}");
    assert!(first["iat_vaddr"].is_string(), "{first}");
    assert!(first["got"].is_null(), "{first}");
}

/// `max_symbols` truncates the array and says so, while `symbol_count`
/// keeps telling the truth — the same contract `max_sections` has.
#[tokio::test]
async fn max_symbols_truncates_visibly() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("Linux_lib64.so");
    let full = structured(
        &mcp.call_tool(
            1,
            "get_binary_info",
            json!({"binary_path": elf, "max_symbols": 4096}),
        )
        .await,
    )
    .clone();
    let total = full["symbol_count"].as_u64().unwrap();
    assert!(total > 2, "the fixture must have several symbols: {total}");

    let cut = structured(
        &mcp.call_tool(
            2,
            "get_binary_info",
            json!({"binary_path": elf, "max_symbols": 2}),
        )
        .await,
    )
    .clone();
    assert_eq!(cut["symbols"].as_array().unwrap().len(), 2, "{cut}");
    assert_eq!(
        cut["symbol_count"], total,
        "the count must stay true even when the array is cut"
    );
    let w = cut["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "symbols_truncated")
        .unwrap_or_else(|| panic!("no symbols_truncated warning: {cut}"));
    println!("max_symbols=2 of {total}: {w}");
    assert_eq!(w["returned"], 2, "{w}");
    assert_eq!(w["total"], total, "{w}");
}

/// The symbol table is OPT-IN, and the response says so.
///
/// Regression guard for the Phase 4 integration: shipping `symbols` at the
/// 4096 default took `get_binary_info`'s first-call response on
/// `elf-Linux-x64` from ~10 KB to ~331 KB (about 83k estimated tokens) and
/// broke the 10,000-token whole-task budget `tests/mcp_workability.py`
/// gates on. Symbols still reach an agent that asks; what may not happen
/// again is a default response that spends a task's entire context on a
/// symbol table nobody requested.
///
/// The two halves that make the default honest are asserted here: the true
/// total is still reported, and the warning names the parameter — so a
/// default-shaped response can never be read as "this ELF has no symbols".
#[tokio::test]
async fn symbols_are_opt_in_and_the_response_says_so() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");

    let body = structured(
        &mcp.call_tool(1, "get_binary_info", json!({"binary_path": elf}))
            .await,
    )
    .clone();
    let default_symbols = body["symbols"].as_array().unwrap().len();
    let total = body["symbol_count"].as_u64().unwrap();
    assert_eq!(default_symbols, 0, "symbols must be opt-in: {body}");
    assert!(
        total > 1000,
        "the fixture must have a symbol table worth withholding: {total}"
    );

    // `imports` is the ret2plt working set and is NOT withheld.
    let imports = body["imports"].as_array().unwrap();
    println!(
        "elf-Linux-x64: symbol_count {total}, imports {}",
        imports.len()
    );

    let w = body["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|w| w["code"] == "symbols_truncated")
        .unwrap_or_else(|| panic!("the default must announce the withheld table: {body}"));
    assert_eq!(w["returned"], 0, "{w}");
    assert_eq!(w["total"], total, "{w}");
    let detail = w["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("max_symbols"),
        "the warning must name the parameter that produces them: {w}"
    );

    // And asking produces them.
    let asked = structured(
        &mcp.call_tool(
            2,
            "get_binary_info",
            json!({"binary_path": elf, "max_symbols": 8}),
        )
        .await,
    )
    .clone();
    assert_eq!(asked["symbols"].as_array().unwrap().len(), 8, "{asked}");
    assert_eq!(asked["symbol_count"].as_u64().unwrap(), total);
}
