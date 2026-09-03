//! CLS-08 on the real server: the question an exploit developer actually
//! asks, answered in ONE call with a handful of gadgets.
//!
//! "Classification is computed but not queryable" was the finding: the
//! server ran `rf_classify` over every gadget at scan time, kept two fields
//! of the result, and exposed none of it as a filter — so the only way to
//! ask "which gadget sets rdi from the stack without clobbering rsi or
//! rdx" was to pull thousands of gadgets into the agent's context and
//! filter them there.
//!
//! MCP-DESIGN fix #9 item 4 spells this as a separate
//! `find_gadgets_by_effect` tool. It is implemented here as parameters on
//! the gadget-returning tools instead, deliberately: the predicate is a
//! pure filter over the same cached set, a second tool would need the same
//! twelve scan parameters, the same cursor and the same ordering, and
//! ECO-01 (v0.4) is where the constraint-search surface — `--set-reg`,
//! `--no-clobber`, `--max-stack-delta`, the wildcard matcher — is designed
//! as a whole. Every filter below is available on find_gadgets,
//! find_jop_gadgets, find_syscall_gadgets, search_gadgets_by_pattern and
//! run_ropgadget_command.

mod support;

use serde_json::json;

use support::{fixtures_dir, structured, McpChild};

/// Re-derive the registers a gadget writes from its TEXT, independently of
/// the classifier, for the handful of forms this test can see. Returns
/// `None` for a form it does not model, so a mismatch is only ever
/// reported for something it genuinely understands.
fn regs_written_from_text(text: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    for insn in text.split(" ; ") {
        let (mnemonic, rest) = match insn.split_once(' ') {
            Some((m, r)) => (m, r.trim()),
            None => (insn, ""),
        };
        match mnemonic {
            "ret" | "repz" | "nop" | "endbr64" | "endbr32" => {}
            "pop" => out.push(rest.to_string()),
            "mov" | "movabs" | "lea" | "add" | "sub" | "xor" | "or" | "and" => {
                let dst = rest.split(',').next()?.trim();
                // Only a bare register destination; a memory destination is
                // a different rule and this test does not model it.
                if dst.contains('[') || dst.is_empty() {
                    return None;
                }
                out.push(dst.to_string());
            }
            _ => return None,
        }
    }
    out.sort();
    out.dedup();
    Some(out)
}

/// One call, one gadget: rdi from the stack, rsi and rdx untouched, at most
/// one side effect, a clean `ret`.
#[tokio::test]
async fn the_real_question_is_answered_in_one_call() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let r = mcp
        .call_tool(
            1,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 10,
                   "writes_reg": "rdi",
                   "from_stack": true,
                   "preserves_regs": "rsi,rdx",
                   "max_side_effects": 1,
                   "terminator": "ret"}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    let gadgets = body["gadgets"].as_array().unwrap();
    println!(
        "set rdi from the stack, preserve rsi/rdx, <=1 side effect, clean ret: {} of {} \
         gadgets",
        body["returned"], body["total_count"]
    );
    for g in gadgets {
        println!("  {} {}", g["vaddr"].as_str().unwrap(), g["text"]);
    }
    assert!(!gadgets.is_empty(), "no answer at all: {body}");
    // A SMALL answer. The unfiltered depth-10 scan of this fixture is
    // thousands of gadgets; the point of the filter is that this one is not.
    assert!(
        gadgets.len() <= 5,
        "{} gadgets is not a small answer",
        gadgets.len()
    );
    assert!(
        gadgets.iter().any(|g| g["text"] == "pop rdi ; ret"),
        "the canonical answer is missing: {body}"
    );

    for g in gadgets {
        // The filter's own claims hold.
        let written: Vec<&str> = g["regs_written"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(written.contains(&"rdi"), "{g}");
        assert!(
            !written.contains(&"rsi") && !written.contains(&"rdx"),
            "{g}"
        );
        let from_stack: Vec<&str> = g["regs_from_stack"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(from_stack.contains(&"rdi"), "{g}");
        assert!(g["side_effects"].as_u64().unwrap() <= 1, "{g}");
        assert_eq!(g["terminator"], "ret", "{g}");

        // ...and an INDEPENDENT reading of the gadget text agrees.
        let text = g["text"].as_str().unwrap();
        if let Some(mut derived) = regs_written_from_text(text) {
            let mut reported: Vec<String> = written.iter().map(|s| (*s).to_string()).collect();
            reported.sort();
            derived.retain(|r| r != "rsp");
            assert_eq!(
                derived, reported,
                "re-deriving {text:?} from its text disagrees with regs_written"
            );
        }
    }
}

/// Each filter narrows, none of them invents, and an unknown value is
/// refused with the valid set named.
#[tokio::test]
async fn class_label_and_register_filters_narrow_correctly() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let base = json!({"binary_path": elf, "depth": 8, "max_results": 50000});

    let all = mcp.call_tool(1, "find_gadgets", base.clone()).await;
    let total = structured(&all)["total_count"].as_u64().unwrap();

    let mut narrowed = base.clone();
    narrowed["class"] = json!("stack-pivot");
    let r = mcp.call_tool(2, "find_gadgets", narrowed).await;
    let body = structured(&r);
    let pivots = body["total_count"].as_u64().unwrap();
    assert!(pivots > 0, "no stack pivots at all: {body}");
    assert!(pivots < total, "the class filter narrowed nothing");
    for g in body["gadgets"].as_array().unwrap() {
        assert_eq!(g["class"], "stack-pivot", "{g}");
    }

    let mut labelled = base.clone();
    labelled["label"] = json!("mem-read,mem-write");
    let r = mcp.call_tool(3, "find_gadgets", labelled).await;
    for g in structured(&r)["gadgets"].as_array().unwrap() {
        let labels: Vec<&str> = g["labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(
            labels.contains(&"mem-read") || labels.contains(&"mem-write"),
            "{g}"
        );
    }

    // `writes_reg` takes several registers and requires ALL of them.
    let mut both = base.clone();
    both["writes_reg"] = json!("rbx,rbp");
    let r = mcp.call_tool(4, "find_gadgets", both).await;
    for g in structured(&r)["gadgets"].as_array().unwrap() {
        let w: Vec<&str> = g["regs_written"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(w.contains(&"rbx") && w.contains(&"rbp"), "{g}");
    }

    // An unknown class names the valid set instead of leaving the agent to
    // guess.
    let mut bad = base;
    bad["class"] = json!("stack_pivot");
    let r = mcp.call_tool(5, "find_gadgets", bad).await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    let e = &structured(&r)["error"];
    assert_eq!(e["code"], "usage_error", "{e}");
    for valid in ["reg-write", "stack-pivot", "mem-read", "dispatcher"] {
        assert!(
            e["message"].as_str().unwrap().contains(valid),
            "{e} omits {valid}"
        );
    }
}

/// CLS-05 as it reaches an agent: no register name the MCP surface returns
/// is disassembly punctuation. `{r4` and `#0x12e44` were real values.
#[tokio::test]
async fn no_register_name_is_disassembly_punctuation() {
    let mut mcp = McpChild::spawn().await;
    let mut checked = 0;
    for (id, fixture) in [
        (1u64, "elf-ARMv7-ls"),
        (2, "elf-ARM64-bash"),
        (3, "elf-Mips-Defcon-20-pwn100"),
        (4, "elf-SparcV8-bash"),
        (5, "elf-PowerPC-bash"),
        (6, "elf-Linux-RISCV_64"),
    ] {
        let r = mcp
            .call_tool(
                id,
                "find_gadgets",
                json!({"binary_path": fixtures_dir().join(fixture),
                       "depth": 6, "max_results": 300}),
            )
            .await;
        assert_eq!(r["result"]["isError"], false, "{fixture}: {r}");
        for g in structured(&r)["gadgets"].as_array().unwrap() {
            for key in ["regs_written", "regs_read", "regs_from_stack"] {
                for v in g[key].as_array().unwrap() {
                    let name = v.as_str().unwrap();
                    assert!(!name.is_empty(), "{fixture}: empty {key} token in {g}");
                    let first = name.chars().next().unwrap();
                    assert!(
                        !"{}[]#!^$%".contains(first),
                        "{fixture}: {key} token {name:?} is punctuation, not a register: {g}"
                    );
                    assert!(
                        name.chars()
                            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                        "{fixture}: {key} token {name:?} is not a plain register name: {g}"
                    );
                    checked += 1;
                }
            }
        }
    }
    println!("no_register_name_is_disassembly_punctuation: {checked} tokens checked");
    assert!(checked > 100, "only {checked} register names were examined");
}
