//! CLS-07 / MCP-DESIGN fix #8 part A, on the real server: the default
//! order puts gadgets an exploit developer would actually use at the top.
//!
//! The measured baseline this replaces: `find_gadgets` with
//! `max_results: 3` on elf-Linux-x64 returned `adc al, 0x89 ; retf 0xc281`
//! and two like it, because the engine's traversal order is alphabetical
//! by text after `post_process`. `sort_by: "quality"` did not help — its
//! top eight were `ret`, `add esp, 0x8 ; ret`, `retf 0x2bbc`,
//! `ret 0x2bbc`, `retf 0xce39`… all tied at quality 100, with
//! `pop rdi ; ret` nowhere near.

mod support;

use serde_json::{json, Value};

use support::{fixtures_dir, structured, McpChild};

fn texts(body: &Value) -> Vec<String> {
    body["gadgets"]
        .as_array()
        .expect("gadgets")
        .iter()
        .map(|g| g["text"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// The two gadgets every x86-64 chain starts with are in the top 20 of the
/// DEFAULT order, and nothing that needs a stack fix-up to return is.
#[tokio::test]
async fn rank_puts_useful_gadgets_first() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let r = mcp
        .call_tool(
            1,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 10, "max_results": 20}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    assert_eq!(body["order"], "rank", "this is the DEFAULT order");
    let top = texts(body);
    assert_eq!(top.len(), 20);
    println!("top 20 by default order on elf-Linux-x64 depth 10:");
    for (i, t) in top.iter().enumerate() {
        println!("  {:2}. {t}", i + 1);
    }

    for want in ["pop rdi ; ret", "pop rsi ; ret"] {
        assert!(
            top.iter().any(|t| t == want),
            "{want:?} is not in the top 20: {top:#?}"
        );
    }
    // No gadget that returns through a stack adjustment, a segment change
    // or an interrupt frame: those all need extra machinery, which is what
    // usability tier 1 encodes and what keeps them out of the head.
    for t in &top {
        assert!(
            !t.contains("retf") && !t.contains("iret"),
            "a far/interrupt return is in the top 20: {t:?} in {top:#?}"
        );
        // `ret 0x10` and friends — `ret` followed by an operand.
        let ret_imm = t
            .split(" ; ")
            .any(|i| i.starts_with("ret ") && !i.starts_with("ret ;"));
        assert!(!ret_imm, "a `ret imm16` is in the top 20: {t:?}");
    }

    // Every record in the top 20 carries the classification that produced
    // the order, so an agent can see WHY it is there.
    for g in body["gadgets"].as_array().unwrap() {
        assert!(g["usability"].as_u64().is_some(), "{g}");
        assert!(g["quality"].as_i64().is_some(), "{g}");
        assert_eq!(g["terminator"], "ret", "{g}");
        assert!(!g["regs_from_stack"].as_array().unwrap().is_empty(), "{g}");
    }
}

/// The orders are genuinely different, and every one of them is echoed.
#[tokio::test]
async fn every_order_is_selectable_and_echoed() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let mut heads = Vec::new();
    for (id, order) in [(1u64, "rank"), (2, "address"), (3, "quality"), (4, "text")] {
        let r = mcp
            .call_tool(
                id,
                "find_gadgets",
                json!({"binary_path": elf, "depth": 6, "max_results": 5, "order": order}),
            )
            .await;
        assert_eq!(r["result"]["isError"], false, "{order}: {r}");
        let body = structured(&r);
        assert_eq!(body["order"], order, "the applied order is echoed");
        heads.push((order, texts(body)));
    }
    let rank = &heads[0].1;
    for (order, head) in heads.iter().skip(1) {
        assert_ne!(
            rank, head,
            "{order} produced the same head as rank, so one of them is not applied"
        );
    }
    // `address` really is address-ascending.
    let r = mcp
        .call_tool(
            5,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 6, "max_results": 200, "order": "address"}),
        )
        .await;
    let addrs: Vec<u64> = structured(&r)["gadgets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["vaddr_u64"].as_u64().unwrap())
        .collect();
    assert!(addrs.windows(2).all(|w| w[0] <= w[1]), "not ascending");
    // ...and `vaddr_u64` agrees with the human string it sits beside.
    for g in structured(&r)["gadgets"].as_array().unwrap() {
        let s = g["vaddr"].as_str().unwrap();
        let n = u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
        assert_eq!(n, g["vaddr_u64"].as_u64().unwrap(), "{g}");
    }
}
