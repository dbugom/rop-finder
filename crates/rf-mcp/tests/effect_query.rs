//! ECO-01 / ECO-12 on the real server — `find_gadgets_by_effect`.
//!
//! MCP-DESIGN's usefulness bar, item 15: "An agent can express 'set rdi
//! from the stack, preserve rsi and rdx, at most one side effect, clean
//! ret' in ONE call and get a small correct answer — not 1000
//! alphabetically-ordered records beginning with `adc al, 0x89 ; retf
//! 0xc281`."
//!
//! The v0.3 test next door (`effect_search.rs`) asks the same question with
//! the coarse `writes_reg` / `preserves_regs` filters, which are satisfied
//! by any write. This file asks it in the CLS-09 vocabulary — `set_reg`
//! (the payload decides the value) and `no_clobber` (matched against
//! `clobbers`, not `regs_written`) — which is the difference between "this
//! gadget touches rdi" and "this gadget loads rdi from my chain".

mod support;

use serde_json::{json, Value};

use support::{fixtures_dir, structured, McpChild};

fn texts(body: &Value) -> Vec<String> {
    body["gadgets"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|g| g["text"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// THE EXIT CRITERION. One call, a small set, `pop rdi ; ret` in it, and
/// nothing in it whose `regs_written` touches rsi or rdx.
#[tokio::test]
async fn the_exit_criterion_question_in_one_call() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");

    // The unfiltered scan, for the "not 1000 records" half of the claim.
    let all = mcp
        .call_tool(
            1,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 10, "max_results": 1}),
        )
        .await;
    let total = structured(&all)["total_count"].as_u64().unwrap();

    let r = mcp
        .call_tool(
            2,
            "find_gadgets_by_effect",
            json!({"binary_path": elf, "depth": 10,
                   "set_reg": "rdi",
                   "from_stack": true,
                   "no_clobber": ["rsi", "rdx"],
                   "max_side_effects": 1,
                   "terminator": "ret"}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    let gadgets = body["gadgets"].as_array().unwrap();
    println!(
        "find_gadgets_by_effect(set_reg=rdi, from_stack, no_clobber=rsi/rdx, \
         max_side_effects=1, terminator=ret) on elf-Linux-x64 depth 10: {} of {total} gadgets",
        body["total_count"]
    );
    for g in gadgets {
        println!(
            "  {} {:<40} {}",
            g["vaddr"].as_str().unwrap(),
            g["text"].as_str().unwrap(),
            g["explanation"]["why"].as_str().unwrap()
        );
    }

    assert!(!gadgets.is_empty(), "no answer at all: {body}");
    assert!(
        gadgets.len() <= 5,
        "{} gadgets is not a SMALL answer out of {total}",
        gadgets.len()
    );
    assert!(
        texts(body).iter().any(|t| t == "pop rdi ; ret"),
        "the canonical answer is missing: {:?}",
        texts(body)
    );

    for g in gadgets {
        // Nothing here writes rsi or rdx at all — the stronger claim the
        // brief asks for, checked against `regs_written` rather than
        // against the field the filter used.
        let written: Vec<&str> = g["regs_written"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(
            !written.contains(&"rsi") && !written.contains(&"rdx"),
            "regs_written intersects the preserved set: {g}"
        );
        // The filter's own claims hold, in the filter's own vocabulary.
        let e = &g["explanation"];
        assert!(
            e["sets"].as_array().unwrap().iter().any(|v| v == "rdi"),
            "{g}"
        );
        assert!(
            !e["clobbers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "rsi" || v == "rdx"),
            "{g}"
        );
        assert_eq!(e["terminator"], "ret", "{g}");
        assert!(g["side_effects"].as_u64().unwrap() <= 1, "{g}");
        assert!(
            g["regs_from_stack"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "rdi"),
            "{g}"
        );
    }
}

/// The explanation is the point of the tool: an agent can justify the
/// choice without re-reading the gadget text. On the criterion gadget it
/// carries the exact numbers CLS-09 verified.
#[tokio::test]
async fn the_explanation_states_the_payload_layout() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let r = mcp
        .call_tool(
            1,
            "find_gadgets_by_effect",
            json!({"binary_path": elf, "depth": 10,
                   "search": "pop rdi; ret", "max_results": 20}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    let g = body["gadgets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["text"] == "pop rdi ; ret")
        .unwrap_or_else(|| panic!("no `pop rdi ; ret`: {body}"));
    println!("pop rdi ; ret at {}: {}", g["vaddr"], g["explanation"]);

    // CLS-09's verified values for elf-Linux-x64 0x401648.
    assert_eq!(g["stack_delta"], 16, "{g}");
    let e = &g["explanation"];
    assert_eq!(e["sets"], json!(["rdi"]), "{e}");
    assert_eq!(e["clobbers"], json!([]), "{e}");
    assert_eq!(e["stack_delta"], 16, "{e}");
    assert_eq!(e["terminator"], "ret", "{e}");
    let why = e["why"].as_str().unwrap();
    assert!(why.contains("stack[+0]"), "{why}");
    assert!(why.contains("clobbers nothing"), "{why}");
    assert!(why.contains("+16"), "{why}");

    // Every record carries the object, always — a fixed shape, not a
    // conditionally-present extra.
    for g in body["gadgets"].as_array().unwrap() {
        for key in [
            "sets",
            "reads",
            "clobbers",
            "stack_delta",
            "terminator",
            "why",
        ] {
            assert!(
                g["explanation"].get(key).is_some(),
                "explanation is missing {key}: {g}"
            );
        }
    }
}

/// `set_reg` is strictly stronger than `writes_reg`, and `no_clobber` is
/// strictly different from `preserves_regs`. Both distinctions are the
/// whole reason CLS-09 exists, and both are observable here.
#[tokio::test]
async fn set_is_not_write_and_clobber_is_not_write() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let base = json!({"binary_path": elf, "depth": 8, "max_results": 50000});

    let mut writes = base.clone();
    writes["writes_reg"] = json!("rdi");
    let n_writes = structured(&mcp.call_tool(1, "find_gadgets_by_effect", writes).await)
        ["total_count"]
        .as_u64()
        .unwrap();

    let mut sets = base.clone();
    sets["set_reg"] = json!("rdi");
    let r = mcp.call_tool(2, "find_gadgets_by_effect", sets).await;
    let body = structured(&r);
    let n_sets = body["total_count"].as_u64().unwrap();
    println!("elf-Linux-x64 depth 8: writes_reg=rdi {n_writes}, set_reg=rdi {n_sets}");
    assert!(n_sets > 0, "set_reg found nothing");
    assert!(
        n_sets < n_writes,
        "set_reg={n_sets} did not narrow writes_reg={n_writes}; \
         `xor rdi, rdi` writes rdi and sets nothing"
    );
    for g in body["gadgets"].as_array().unwrap() {
        assert!(
            g["explanation"]["sets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "rdi"),
            "{g}"
        );
    }

    // `no_clobber: ["rdi"]` must KEEP `pop rdi ; ret` — a payload-decided
    // write is not a clobber — while `preserves_regs: "rdi"` drops it,
    // because that one is matched against `regs_written`.
    let mut nc = base.clone();
    nc["no_clobber"] = json!(["rdi"]);
    nc["search"] = json!("pop rdi; ret");
    let kept = structured(&mcp.call_tool(3, "find_gadgets_by_effect", nc).await).clone();
    assert!(
        texts(&kept).iter().any(|t| t == "pop rdi ; ret"),
        "no_clobber rejected a gadget that only SETS the register: {:?}",
        texts(&kept)
    );

    let mut pr = base;
    pr["preserves_regs"] = json!("rdi");
    pr["search"] = json!("pop rdi; ret");
    let dropped = structured(&mcp.call_tool(4, "find_gadgets_by_effect", pr).await).clone();
    assert!(
        !texts(&dropped).iter().any(|t| t == "pop rdi ; ret"),
        "preserves_regs is supposed to be the coarse regs_written filter: {:?}",
        texts(&dropped)
    );
}

/// `max_stack_delta` treats an unknown delta as UNKNOWN, not as zero —
/// CLS-09's explicit warning. `xchg rsp, rax ; ret` must never appear
/// inside a layout budget.
#[tokio::test]
async fn an_unknown_stack_delta_is_rejected_not_assumed_zero() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-x64-bash-v4.1.5.1");
    let r = mcp
        .call_tool(
            1,
            "find_gadgets_by_effect",
            json!({"binary_path": elf, "depth": 8,
                   "max_stack_delta": 32, "max_results": 50000}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    let n = body["total_count"].as_u64().unwrap();
    assert!(n > 0, "no gadget has a known delta at all: {body}");
    let mut checked = 0;
    for g in body["gadgets"].as_array().unwrap() {
        let d = g["stack_delta"].as_i64().unwrap_or_else(|| {
            panic!("a gadget with an UNKNOWN stack delta passed max_stack_delta: {g}")
        });
        assert!(d <= 32, "{g}");
        checked += 1;
    }
    println!(
        "max_stack_delta=32 on elf-x64-bash depth 8: {n} gadgets, {checked} on this page, \
              every one with a known delta"
    );

    // ...and the unfiltered scan really does contain unknown deltas, so
    // the assertion above is not vacuous.
    let all = mcp
        .call_tool(
            2,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 8, "max_results": 2000}),
        )
        .await;
    let unknown = structured(&all)["gadgets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|g| g["stack_delta"].is_null())
        .count();
    println!("of the first 2000 unfiltered gadgets, {unknown} have an unknown delta");
    assert!(
        unknown > 0,
        "no unknown deltas exist, so the test proves nothing"
    );
}

/// ECO-12: the stack-pivot preset, which is the whole finding.
#[tokio::test]
async fn the_pivot_preset_returns_pivots_and_only_pivots() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let r = mcp
        .call_tool(
            1,
            "find_gadgets_by_effect",
            json!({"binary_path": elf, "depth": 8, "pivot": true, "max_results": 50}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    let n = body["total_count"].as_u64().unwrap();
    for g in body["gadgets"].as_array().unwrap() {
        let labels: Vec<&str> = g["labels"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(labels.contains(&"stack-pivot"), "{g}");
    }

    // The preset is the LABEL set, not the primary class: a gadget whose
    // last side effect is something else still moves rsp, and a chain
    // builder that only saw `class == "stack-pivot"` would miss it. Both
    // numbers are reported so the difference is visible rather than
    // implied.
    let all = mcp
        .call_tool(
            2,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 8, "max_results": 1}),
        )
        .await;
    let total = structured(&all)["total_count"].as_u64().unwrap();
    let primary = structured(
        &mcp.call_tool(
            3,
            "find_gadgets_by_effect",
            json!({"binary_path": elf, "depth": 8, "class": "stack-pivot", "max_results": 1}),
        )
        .await,
    )["total_count"]
        .as_u64()
        .unwrap();
    println!(
        "elf-Linux-x64 depth 8: {total} gadgets, {n} carry the stack-pivot LABEL \
         (pivot: true), {primary} have it as their PRIMARY class"
    );
    assert!(n > 0, "no stack pivots at all: {body}");
    assert!(n < total, "the pivot preset narrowed nothing");
    assert!(
        primary <= n,
        "the primary-class set must be a subset of the label set: {primary} > {n}"
    );
}

/// The wildcard sequence matcher, and the fine terminator vocabulary.
#[tokio::test]
async fn search_wildcards_and_fine_terminators() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-x64-bash-v4.1.5.1");

    let r = mcp
        .call_tool(
            1,
            "find_gadgets_by_effect",
            json!({"binary_path": elf, "depth": 8,
                   "search": "pop r?i; ret", "max_results": 200}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let hits = texts(structured(&r));
    println!("search 'pop r?i; ret': {} gadgets", hits.len());
    assert!(!hits.is_empty(), "the wildcard matched nothing");
    for t in &hits {
        assert!(
            t.contains("pop rdi ; ret") || t.contains("pop rsi ; ret"),
            "{t} is not a `pop r?i ; ret`"
        );
    }

    // `jmp-reg` is a JOP dispatcher target; no coarse kind separates it
    // from `jmp [mem]`.
    let r = mcp
        .call_tool(
            2,
            "find_gadgets_by_effect",
            json!({"binary_path": elf, "depth": 6,
                   "terminator": "jmp-reg", "max_results": 200}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    println!("terminator jmp-reg: {} gadgets", body["total_count"]);
    assert!(body["total_count"].as_u64().unwrap() > 0, "{body}");
    for g in body["gadgets"].as_array().unwrap() {
        assert_eq!(g["explanation"]["terminator"], "jmp-reg", "{g}");
    }

    // An unknown value names BOTH vocabularies.
    let r = mcp
        .call_tool(
            3,
            "find_gadgets_by_effect",
            json!({"binary_path": elf, "depth": 4, "terminator": "sideways"}),
        )
        .await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    let e = &structured(&r)["error"];
    assert_eq!(e["code"], "usage_error", "{e}");
    let msg = e["message"].as_str().unwrap();
    for want in ["ret", "jmp", "syscall", "jmp-reg", "call-mem", "far"] {
        assert!(msg.contains(want), "{msg} omits {want}");
    }

    // An empty search pattern is refused rather than matching everything.
    let r = mcp
        .call_tool(
            4,
            "find_gadgets_by_effect",
            json!({"binary_path": elf, "depth": 4, "search": " ; "}),
        )
        .await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    assert_eq!(structured(&r)["error"]["code"], "usage_error");
}

/// A call with no constraint is refused with the vocabulary named, rather
/// than quietly returning the whole scan under a name that promises a
/// filtered answer.
#[tokio::test]
async fn an_unconstrained_effect_query_is_refused() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let r = mcp
        .call_tool(
            1,
            "find_gadgets_by_effect",
            json!({"binary_path": elf, "depth": 4}),
        )
        .await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    let e = &structured(&r)["error"];
    assert_eq!(e["code"], "usage_error", "{e}");
    let msg = e["message"].as_str().unwrap();
    for want in [
        "set_reg",
        "no_clobber",
        "max_stack_delta",
        "pivot",
        "find_gadgets",
    ] {
        assert!(msg.contains(want), "{msg} omits {want}");
    }
}

/// ECO-09: the effect query pages and streams like every other gadget tool,
/// because it IS one — same cursor, same NDJSON resource.
#[tokio::test]
async fn the_effect_query_pages_and_streams() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-x64-bash-v4.1.5.1");
    let q = json!({"binary_path": elf, "depth": 8, "terminator": "ret", "max_results": 25});

    let first = mcp.call_tool(1, "find_gadgets_by_effect", q.clone()).await;
    let body = structured(&first);
    let total = body["total_count"].as_u64().unwrap();
    assert!(total > 25, "not enough gadgets to page: {total}");
    assert_eq!(body["returned"], 25, "{body}");
    assert_eq!(body["truncated"], true, "{body}");
    let cursor = body["next_cursor"]
        .as_str()
        .expect("a next_cursor")
        .to_string();
    let uri = body["resource_uri"]
        .as_str()
        .expect("a resource_uri")
        .to_string();
    assert!(uri.starts_with("ropfinder://scan/"), "{uri}");

    let mut second = q;
    second["cursor"] = json!(cursor);
    let r = mcp.call_tool(2, "find_gadgets_by_effect", second).await;
    let body2 = structured(&r);
    assert_eq!(body2["offset"], 25, "{body2}");
    assert_eq!(body2["total_count"], total, "{body2}");
    let a: Vec<&str> = body["gadgets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["id"].as_str().unwrap())
        .collect();
    let b: Vec<&str> = body2["gadgets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["id"].as_str().unwrap())
        .collect();
    assert!(a.iter().all(|id| !b.contains(id)), "pages overlap");
    println!("find_gadgets_by_effect paged {total} gadgets, resource {uri}");
}
