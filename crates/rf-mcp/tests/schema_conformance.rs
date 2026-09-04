//! CRIT-03's exit criterion: for every fixture and every tool, drive the
//! REAL server over stdio and validate each `structuredContent` against
//! that tool's OWN declared `outputSchema`, with
//! `additionalProperties: false` so an added field fails as loudly as a
//! missing one.
//!
//! The four shapes that used to differ are asserted to be identical:
//! elf-Linux-x64, the same binary with `section: ".text"`, the MIPS fixture
//! (whose gadgets carry `delay_slot: true`, a field no interface emitted at
//! all), and the fat Mach-O (whose records are the only ones with `arch`
//! set). Before this, `section` appeared only when the section parameter
//! was passed, `arch` only for a universal binary, and `delay_slot` never.

mod support;

use std::collections::BTreeSet;

use serde_json::{json, Value};

use support::jsonschema::validate;
use support::{fixtures_dir, structured, McpChild};

/// Every binary in tests/fixtures, in a stable order. The two metadata
/// files are not binaries.
fn fixtures() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .expect("fixtures dir")
        .filter_map(|e| {
            let e = e.ok()?;
            if !e.file_type().ok()?.is_file() {
                return None;
            }
            let n = e.file_name().to_string_lossy().into_owned();
            (n != "MANIFEST.sha256" && n != "PROVENANCE.md").then_some(n)
        })
        .collect();
    names.sort();
    names
}

/// Field names of a JSON object, sorted.
fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

/// The tool calls made against every fixture. `arch` is supplied only for
/// the fat Mach-O, which is REFUSED without it (CORE-03) — that refusal is
/// itself a response the error schema has to accept.
fn calls(binary: &Value, fixture: &str) -> Vec<(&'static str, Value)> {
    let mut arch = json!({});
    if fixture.starts_with("UNIVERSAL") {
        arch = json!({"arch": "x86_64"});
    }
    let merge = |extra: Value| -> Value {
        let mut v = json!({"binary_path": binary});
        for src in [&arch, &extra] {
            if let (Some(dst), Some(src)) = (v.as_object_mut(), src.as_object()) {
                for (k, val) in src {
                    dst.insert(k.clone(), val.clone());
                }
            }
        }
        v
    };
    vec![
        ("find_gadgets", merge(json!({"depth": 4, "max_results": 5}))),
        (
            "find_jop_gadgets",
            merge(json!({"depth": 4, "max_results": 5})),
        ),
        (
            "find_syscall_gadgets",
            merge(json!({"depth": 4, "max_results": 5})),
        ),
        (
            "search_gadgets_by_pattern",
            merge(json!({"depth": 4, "max_results": 5, "pattern": "ret"})),
        ),
        (
            "run_ropgadget_command",
            merge(json!({"args": ["--depth", "4"], "max_results": 5})),
        ),
        (
            "get_gadgets",
            merge(json!({"depth": 4, "ids": ["g_aaaaaaaaaaaaaaaa"]})),
        ),
        ("get_binary_info", merge(json!({}))),
        (
            "build_rop_chain",
            merge(json!({"depth": 4, "target": "linux-execve"})),
        ),
        // v0.4. `find_gadgets_by_effect` refuses an unconstrained call, so
        // it is given the cheapest real constraint; the two searches and
        // the mitigation report take a pattern that exists in some
        // fixtures and not others, which is the point — both outcomes have
        // to validate.
        (
            "find_gadgets_by_effect",
            merge(json!({"depth": 4, "max_results": 5, "terminator": "ret"})),
        ),
        (
            "find_string",
            merge(json!({"string": "lib", "max_results": 5})),
        ),
        (
            "find_bytes",
            merge(json!({"opcode": "c3", "max_results": 5})),
        ),
        ("get_mitigations", merge(json!({}))),
        // v0.5, ECO-04. `plan_chain` ALWAYS succeeds, so every fixture --
        // including the ones where the target is not even dispatchable --
        // has to produce a schema-valid PlanResponse.
        (
            "plan_chain",
            merge(json!({"depth": 4, "target": "linux-execve"})),
        ),
    ]
}

/// How many tools `calls` exercises per fixture.
const CALLS_PER_FIXTURE: usize = 13;

/// Every fixture × every tool, validated against the declared schema.
#[tokio::test]
async fn schema_conformance() {
    let mut mcp = McpChild::spawn().await;
    let list = mcp.rpc(1, "tools/list", json!({})).await;
    let tools = list["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), 15, "unexpected tool count");

    // The schemas as the SERVER declares them, not as this test imagines.
    let mut schemas = std::collections::HashMap::new();
    for t in tools {
        let name = t["name"].as_str().unwrap().to_string();
        let s = t["outputSchema"].clone();
        assert_eq!(s["type"], "object", "{name} declares no outputSchema");
        assert_eq!(
            s["additionalProperties"],
            Value::Bool(false),
            "{name}'s outputSchema permits extra fields, so this test would pass a \
             response with an added key"
        );
        schemas.insert(name, s);
    }
    // Errors have a fixed shape too; it is not a tool's outputSchema
    // because per the MCP spec an outputSchema describes a SUCCESSFUL
    // result.
    let error_schema: Value =
        serde_json::to_value(rf_mcp::schema::error_output_schema().as_ref()).unwrap();

    let fixtures = fixtures();
    assert_eq!(fixtures.len(), 24, "{fixtures:?}");

    let mut id = 100u64;
    let mut ok_bodies = 0usize;
    let mut err_bodies = 0usize;
    for fixture in &fixtures {
        let path = fixtures_dir().join(fixture);
        let binary = json!(path);
        for (tool, args) in calls(&binary, fixture) {
            let r = mcp.call_tool(id, tool, args.clone()).await;
            id += 1;
            let body = structured(&r);
            let is_error = r["result"]["isError"] == Value::Bool(true);
            let schema = if is_error {
                &error_schema
            } else {
                schemas.get(tool).expect(tool)
            };
            let errs = validate(body, schema, schema);
            assert!(
                errs.is_empty(),
                "{fixture} / {tool} ({}) does not match its declared schema:\n  {}\nbody: {body}",
                if is_error { "error" } else { "ok" },
                errs.join("\n  ")
            );
            if is_error {
                err_bodies += 1;
            } else {
                ok_bodies += 1;
                // rf-cli's --info payload is mapped field by field; a field
                // this build does not model would be dropped, so the mapper
                // announces it. It must never fire on a shipped fixture.
                if tool == "get_binary_info" {
                    for w in body["warnings"].as_array().unwrap() {
                        assert_ne!(
                            w["code"], "unmapped_info_fields",
                            "{fixture}: get_binary_info dropped fields: {w}"
                        );
                    }
                }
            }
        }
    }
    println!(
        "schema_conformance: {} fixtures x {CALLS_PER_FIXTURE} tools = {} responses \
         ({ok_bodies} ok, {err_bodies} error), all valid against the declared schemas",
        fixtures.len(),
        ok_bodies + err_bodies
    );
    assert_eq!(ok_bodies + err_bodies, fixtures.len() * CALLS_PER_FIXTURE);

    // The two parameterless tools.
    for (tool, args) in [
        ("get_server_config", json!({})),
        ("get_server_stats", json!({})),
    ] {
        let r = mcp.call_tool(id, tool, args).await;
        id += 1;
        assert_eq!(r["result"]["isError"], false, "{tool}: {r}");
        let schema = schemas.get(tool).expect(tool);
        let errs = validate(structured(&r), schema, schema);
        assert!(errs.is_empty(), "{tool}: {}", errs.join("\n  "));
    }
}

/// The four responses whose gadget records used to have DIFFERENT field
/// sets now have identical ones — and each still carries the fact that made
/// it different.
#[tokio::test]
async fn the_four_shapes_that_differed_are_now_one() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let mips = fixtures_dir().join("elf-Mips-Defcon-20-pwn100");
    let fat = fixtures_dir().join("UNIVERSAL-x86-x64-libSystem.B.dylib");

    let mut shapes: Vec<(&str, Value)> = Vec::new();
    // The MIPS fixture's ROP set is empty at this depth and its JOP set is
    // the 40,872-gadget one the design note names, so that is the tool the
    // MIPS shape is taken from. Both return the same declared type, which
    // is the point.
    for (id, label, tool, args) in [
        (
            1u64,
            "plain",
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "max_results": 5}),
        ),
        (
            2,
            "section=.text",
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "max_results": 5, "section": ".text"}),
        ),
        (
            3,
            "mips",
            "find_jop_gadgets",
            json!({"binary_path": mips, "depth": 4, "max_results": 200}),
        ),
        (
            4,
            "universal",
            "find_gadgets",
            json!({"binary_path": fat, "depth": 4, "max_results": 5, "arch": "x86_64"}),
        ),
    ] {
        let r = mcp.call_tool(id, tool, args).await;
        assert_eq!(r["result"]["isError"], false, "{label}: {r}");
        let body = structured(&r).clone();
        assert!(
            !body["gadgets"].as_array().unwrap().is_empty(),
            "{label} found nothing, so it proves nothing"
        );
        shapes.push((label, body));
    }

    // Identical field sets, top level and per record.
    let (_, first) = &shapes[0];
    let want_top = keys(first);
    let want_rec = keys(&first["gadgets"][0]);
    // 22 in v0.3; v0.4 adds `explanation` (ECO-01).
    assert_eq!(want_rec.len(), 23, "{want_rec:?}");
    assert!(want_rec.contains("explanation"), "{want_rec:?}");
    for (label, body) in &shapes {
        assert_eq!(
            keys(body),
            want_top,
            "{label} has a different response shape"
        );
        for g in body["gadgets"].as_array().unwrap() {
            assert_eq!(
                keys(g),
                want_rec,
                "{label} has a different record shape: {g}"
            );
        }
    }

    // ...and each shape still carries what made it different.
    let plain = &shapes[0].1;
    for g in plain["gadgets"].as_array().unwrap() {
        assert!(
            g["section"].is_null(),
            "no section filter, so no section: {g}"
        );
        assert!(g["arch"].is_null(), "not a fat binary: {g}");
        assert_eq!(g["delay_slot"], false, "x86-64 has no delay slots: {g}");
    }
    for g in shapes[1].1["gadgets"].as_array().unwrap() {
        assert_eq!(g["section"], ".text", "{g}");
    }
    // CRIT-03: `delay_slot` is computed by rf_scan and was dropped at every
    // output boundary, so a MIPS gadget reached the agent with no sign that
    // its last instruction executes BEFORE the branch.
    let mips_body = &shapes[2].1;
    let delayed = mips_body["gadgets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["delay_slot"] == Value::Bool(true))
        .count();
    println!(
        "delay_slot: {delayed} of {} MIPS gadgets, 0 of the x86-64 ones",
        mips_body["gadgets"].as_array().unwrap().len()
    );
    assert!(delayed > 0, "no MIPS gadget reported a delay slot");
    for g in shapes[3].1["gadgets"].as_array().unwrap() {
        assert_eq!(g["arch"], "x64", "the selected fat slice is named: {g}");
    }
    let codes: Vec<&str> = shapes[3].1["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"universal_slice_selected"), "{codes:?}");
}
