//! MCP-06 — `get_binary_info` is bounded like every other tool.
//!
//! It was the ONE tool with neither a timeout nor a cap, and the only one
//! that did its blocking work — a whole-file `std::fs::read` plus a goblin
//! parse — directly in the async handler rather than on a worker. It also
//! had no cap on the arrays it emits, so a hostile PE with a million
//! import entries could produce a gigabyte of JSON straight into an
//! agent's context.

mod support;

use serde_json::json;

use support::{fixtures_dir, structured, McpChild};

/// A truncated array is ANNOUNCED. A silently short list is
/// indistinguishable from a binary with few imports, which is the
/// difference between a cap and a lie.
#[tokio::test]
async fn oversized_arrays_are_capped_and_the_truncation_is_announced() {
    let mut mcp = McpChild::spawn().await;
    let pe = fixtures_dir().join("pe-x64-cmd-v6.1.7601");

    // Uncapped: the real counts, and an empty `warnings` array that is
    // ALWAYS present, so the response shape does not depend on the data.
    let full = mcp
        .call_tool(1, "get_binary_info", json!({"binary_path": pe}))
        .await;
    let full = structured(&full);
    let all_sections = full["sections"].as_array().unwrap().len();
    let all_imports = full["imports"].as_array().unwrap().len();
    assert!(all_imports > 1, "the fixture must have several imports");
    assert_eq!(full["warnings"], json!([]), "{full}");
    assert_eq!(full["binary_sha256"].as_str().unwrap().len(), 64);

    // Capped.
    let cut = mcp
        .call_tool(
            2,
            "get_binary_info",
            json!({"binary_path": pe, "max_imports": 1, "max_sections": 1}),
        )
        .await;
    let cut = structured(&cut);
    assert_eq!(cut["imports"].as_array().unwrap().len(), 1);
    assert_eq!(cut["sections"].as_array().unwrap().len(), 1);
    let warnings = cut["warnings"].as_array().unwrap();
    let codes: Vec<&str> = warnings
        .iter()
        .map(|w| w["code"].as_str().unwrap())
        .collect();
    assert!(codes.contains(&"imports_truncated"), "{cut}");
    assert!(codes.contains(&"sections_truncated"), "{cut}");
    let imp = warnings
        .iter()
        .find(|w| w["code"] == "imports_truncated")
        .unwrap();
    assert_eq!(imp["returned"], 1);
    assert_eq!(imp["total"], all_imports);
    let sec = warnings
        .iter()
        .find(|w| w["code"] == "sections_truncated")
        .unwrap();
    assert_eq!(sec["total"], all_sections);
}

/// `get_binary_info` accepts `timeout_secs`, and the server's own cap is
/// the ceiling for it.
#[tokio::test]
async fn info_accepts_a_timeout() {
    let mut mcp = McpChild::spawn().await;
    let pe = fixtures_dir().join("pe-x64-cmd-v6.1.7601");
    let r = mcp
        .call_tool(
            1,
            "get_binary_info",
            json!({"binary_path": pe, "timeout_secs": 30}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    assert_eq!(structured(&r)["format"], "pe");

    // A caller cannot buy more than HARD_MAX_TIMEOUT_SECS with it.
    let r = mcp
        .call_tool(
            2,
            "get_binary_info",
            json!({"binary_path": pe, "timeout_secs": 99999}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
}

/// A file over `--max-file-bytes` is refused before a byte is read, and
/// the refusal names the limit.
#[tokio::test]
async fn an_oversized_file_is_refused_by_info() {
    let mut mcp = McpChild::spawn_with(&["--max-file-bytes", "1024"]).await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let r = mcp
        .call_tool(1, "get_binary_info", json!({"binary_path": elf}))
        .await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    let e = &structured(&r)["error"];
    // CRIT-03 closed the code set: `file_too_large` was one of the
    // invented-at-the-call-site spellings and is now `resource_exhausted`
    // with `details.limit` naming which bound was hit. The finer reason
    // survives in the audit log's `code` field.
    assert_eq!(e["code"], "resource_exhausted", "{e}");
    assert_eq!(e["details"]["limit"], "max_file_bytes");
    assert_eq!(e["details"]["limit_value"], 1024);
    assert_eq!(e["details"]["got"], 863_316);
}
