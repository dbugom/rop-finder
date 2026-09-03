//! MCP-DESIGN fix #8 parts B and C, driven over stdio against the real
//! server: the cursor walks a result set exactly once, and a cursor from
//! one query cannot page another.
//!
//! Before this, `find_gadgets` with `max_results: 3` on elf-Linux-x64
//! returned three gadgets out of 2789 with no way to ask for the next
//! three, and the MIPS fixture's 40,872 JOP gadgets were simply
//! unreachable past the first page.

mod support;

use std::collections::HashSet;

use serde_json::{json, Value};

use support::{fixtures_dir, structured, McpChild};

/// Every id in the response, in order.
fn ids(body: &Value) -> Vec<String> {
    body["gadgets"]
        .as_array()
        .expect("gadgets array")
        .iter()
        .map(|g| {
            g["id"]
                .as_str()
                .unwrap_or_else(|| panic!("every record has an id: {g}"))
                .to_string()
        })
        .collect()
}

/// Page elf-Linux-x64 at depth 4 with `max_results: 100` until `next_cursor`
/// is null, and require the concatenation to be EXACTLY the one-shot list:
/// same ids, same order, no duplicates, no gaps.
#[tokio::test]
async fn cursor_walks_the_whole_set_exactly_once() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");

    // One shot: the whole ordered set.
    let all = mcp
        .call_tool(
            1,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "max_results": 50000}),
        )
        .await;
    let all = structured(&all);
    let total = all["total_count"].as_u64().expect("total_count") as usize;
    let want = ids(all);
    assert_eq!(want.len(), total, "the one-shot call was itself truncated");
    assert_eq!(all["order"], "rank", "the default order is echoed");
    assert_eq!(all["truncated"], false);
    assert!(all["next_cursor"].is_null(), "nothing left to page");
    assert!(
        all["resource_uri"].is_null(),
        "an unpaged scan names no resource"
    );

    // Paged: 100 at a time, following next_cursor.
    let mut got: Vec<String> = Vec::new();
    let mut cursor = Value::Null;
    let mut pages = 0usize;
    let mut id = 100u64;
    loop {
        let mut args = json!({"binary_path": elf, "depth": 4, "max_results": 100});
        if !cursor.is_null() {
            args["cursor"] = cursor.clone();
        }
        let r = mcp.call_tool(id, "find_gadgets", args).await;
        assert_eq!(r["result"]["isError"], false, "{r}");
        let body = structured(&r);
        pages += 1;
        id += 1;

        assert_eq!(body["order"], "rank");
        assert_eq!(
            body["offset"].as_u64().unwrap() as usize,
            got.len(),
            "page {pages} does not start where the last one ended"
        );
        assert_eq!(body["total_count"].as_u64().unwrap() as usize, total);
        let page = ids(body);
        assert_eq!(
            body["returned"].as_u64().unwrap() as usize,
            page.len(),
            "returned disagrees with the array it describes"
        );
        // A paged scan hands the agent the whole set as a resource.
        if body["truncated"] == Value::Bool(true) {
            let uri = body["resource_uri"]
                .as_str()
                .expect("resource_uri on a paged scan");
            assert!(uri.starts_with("ropfinder://scan/"), "{uri}");
            assert!(uri.ends_with("/gadgets.ndjson"), "{uri}");
        }
        got.extend(page);
        cursor = body["next_cursor"].clone();
        if cursor.is_null() {
            break;
        }
        assert!(pages < 1000, "next_cursor never became null");
    }

    println!("cursor_walks_the_whole_set_exactly_once: {total} gadgets, {pages} pages of 100");
    let unique: HashSet<&String> = got.iter().collect();
    assert_eq!(unique.len(), got.len(), "the walk returned a duplicate id");
    assert_eq!(got.len(), total, "the walk did not cover the whole set");
    assert_eq!(
        got, want,
        "the walk's order differs from the one-shot order"
    );
    assert_eq!(pages, total.div_ceil(100), "unexpected page count");
}

/// A cursor is bound to the query that produced it. Paging a depth-6 query
/// with a depth-4 cursor is refused, retryably, with the patch that fixes
/// it — never answered with a page of the wrong set.
#[tokio::test]
async fn a_depth_4_cursor_is_refused_by_a_depth_6_query() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");

    let first = mcp
        .call_tool(
            1,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "max_results": 10}),
        )
        .await;
    let cursor = structured(&first)["next_cursor"]
        .as_str()
        .expect("a 10-of-many page has a next_cursor")
        .to_string();

    let r = mcp
        .call_tool(
            2,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 6, "max_results": 10, "cursor": cursor}),
        )
        .await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    let e = &structured(&r)["error"];
    assert_eq!(e["code"], "cursor_expired", "{e}");
    assert_eq!(e["retryable"], true, "{e}");
    assert!(
        e["suggestion"]["arguments_patch"]["cursor"].is_null(),
        "the suggestion must clear the cursor: {e}"
    );
    // The same cursor still works against the query it belongs to, so the
    // rejection is about the mismatch and not about the cursor being stale.
    let ok = mcp
        .call_tool(
            3,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "max_results": 10,
                   "cursor": structured(&first)["next_cursor"].clone()}),
        )
        .await;
    assert_eq!(ok["result"]["isError"], false, "{ok}");
    assert_eq!(structured(&ok)["offset"], 10);
}

/// Changing the ORDER also invalidates a cursor: an offset into a
/// rank-ordered list means something else in an address-ordered one, and
/// silently reusing it would interleave two orders.
#[tokio::test]
async fn a_cursor_is_bound_to_its_order_and_its_binary() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let other = fixtures_dir().join("elf-Linux-x86");

    let first = mcp
        .call_tool(
            1,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "max_results": 10}),
        )
        .await;
    let cursor = structured(&first)["next_cursor"].clone();

    for (id, args) in [
        (
            2u64,
            json!({"binary_path": elf, "depth": 4, "max_results": 10,
                   "order": "address", "cursor": cursor}),
        ),
        (
            3,
            json!({"binary_path": other, "depth": 4, "max_results": 10,
                   "cursor": structured(&first)["next_cursor"].clone()}),
        ),
    ] {
        let r = mcp.call_tool(id, "find_gadgets", args).await;
        assert_eq!(r["result"]["isError"], true, "{r}");
        assert_eq!(structured(&r)["error"]["code"], "cursor_expired", "{r}");
    }

    // Garbage is the same refusal, not a panic and not a wrong page.
    let r = mcp
        .call_tool(
            4,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "cursor": "not-a-cursor!!"}),
        )
        .await;
    assert_eq!(structured(&r)["error"]["code"], "cursor_expired", "{r}");
}

/// Stable ids are the same across processes and independent of the scan
/// parameters that do not change which bytes a gadget is made of.
#[tokio::test]
async fn ids_are_stable_across_processes_and_scan_parameters() {
    let elf = fixtures_dir().join("elf-Linux-x64");
    let args = json!({"binary_path": elf, "depth": 4, "max_results": 20, "order": "address"});

    let mut a = McpChild::spawn().await;
    let first = structured(&a.call_tool(1, "find_gadgets", args.clone()).await).clone();
    drop(a);

    // A DIFFERENT server process, and a deeper scan that is a superset.
    let mut b = McpChild::spawn().await;
    let deeper = structured(
        &b.call_tool(
            1,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 8, "max_results": 50000,
                   "order": "address"}),
        )
        .await,
    )
    .clone();
    // And the same scan with --offset, which shifts every reported address.
    let shifted = structured(
        &b.call_tool(
            2,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "max_results": 50000,
                   "offset": "0x1000", "order": "address"}),
        )
        .await,
    )
    .clone();

    let deep_ids: HashSet<String> = ids(&deeper).into_iter().collect();
    let shifted_ids: HashSet<String> = ids(&shifted).into_iter().collect();
    let mut carried = 0;
    for g in first["gadgets"].as_array().unwrap() {
        let id = g["id"].as_str().unwrap();
        assert!(id.starts_with("g_"), "{id}");
        assert_eq!(id.len(), 18, "{id}");
        assert!(
            deep_ids.contains(id),
            "id {id} ({}) did not survive a deeper scan in another process",
            g["text"]
        );
        assert!(
            shifted_ids.contains(id),
            "id {id} ({}) changed when --offset shifted the addresses",
            g["text"]
        );
        carried += 1;
    }
    assert_eq!(carried, 20);

    // ...and get_gadgets resolves them back.
    let want: Vec<String> = ids(&first).into_iter().take(3).collect();
    let r = b
        .call_tool(
            3,
            "get_gadgets",
            json!({"binary_path": elf, "depth": 4, "ids": want.clone()}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    assert_eq!(ids(body), want, "resolved in the order asked for");
    assert_eq!(body["order"], "ids");

    // An id that does not resolve is a warning, not a failed call.
    let mut mixed = want.clone();
    mixed.push("g_aaaaaaaaaaaaaaaa".to_string());
    let r = b
        .call_tool(
            4,
            "get_gadgets",
            json!({"binary_path": elf, "depth": 4, "ids": mixed}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    let body = structured(&r);
    assert_eq!(body["returned"], 3);
    let codes: Vec<&str> = body["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"ids_not_found"), "{body}");
}
