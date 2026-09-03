//! A paged scan is also a file.
//!
//! The MIPS fixture has 40,872 JOP gadgets. Paging them 1,000 at a time is
//! 41 tool calls and 41 context loads; handing the agent one NDJSON file it
//! can grep with its own tools is one. Any scan whose `total_count` exceeds
//! `returned` therefore also names
//! `ropfinder://scan/<cache_key>/gadgets.ndjson`, and with
//! `--workspace-dir` the same bytes exist as a real file.

mod support;

use serde_json::{json, Value};

use support::jsonschema::validate;
use support::{fixtures_dir, plain, structured, McpChild, TempTree};

/// The resource is declared, listed, readable, and every line of it is a
/// complete gadget record.
#[tokio::test]
async fn a_paged_scan_is_also_a_readable_resource() {
    let mut mcp = McpChild::spawn().await;

    // The capability has to be declared or a host never asks.
    let init = mcp.rpc(2, "tools/list", json!({})).await;
    assert!(init["result"]["tools"].is_array());

    let elf = fixtures_dir().join("elf-Linux-x64");
    let r = mcp
        .call_tool(
            3,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 6, "max_results": 5}),
        )
        .await;
    let body = structured(&r);
    assert_eq!(body["truncated"], true, "this scan must be paged: {body}");
    let uri = body["resource_uri"]
        .as_str()
        .expect("a paged scan names a resource")
        .to_string();
    assert_eq!(
        uri,
        format!(
            "ropfinder://scan/{}/gadgets.ndjson",
            body["cache_key"].as_str().unwrap()
        )
    );
    let total = body["total_count"].as_u64().unwrap();

    // resources/list names it.
    let list = mcp.rpc(4, "resources/list", json!({})).await;
    let resources = list["result"]["resources"].as_array().expect("resources");
    assert!(
        resources.iter().any(|r| r["uri"] == uri.as_str()),
        "{uri} is not listed: {list}"
    );

    // resources/read serves it, and every line validates against the
    // record schema the tools declare.
    let read = mcp
        .rpc(5, "resources/read", json!({"uri": uri.clone()}))
        .await;
    let contents = &read["result"]["contents"][0];
    assert_eq!(contents["uri"], uri.as_str(), "{read}");
    assert_eq!(contents["mimeType"], "application/x-ndjson");
    let text = contents["text"].as_str().expect("text");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.len() as u64,
        total,
        "the resource holds the WHOLE scan, not the page"
    );

    let tools = mcp.rpc(6, "tools/list", json!({})).await;
    let schema = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "find_gadgets")
        .unwrap()["outputSchema"]
        .clone();
    let record_schema = json!({
        "$ref": "#/$defs/GadgetRecord",
        "$defs": schema["$defs"].clone(),
    });
    for (i, line) in lines.iter().enumerate().take(50) {
        let v: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("line {i} is not JSON: {line} ({e})"));
        let errs = validate(&v, &record_schema, &record_schema);
        assert!(errs.is_empty(), "line {i}: {}", errs.join("\n  "));
    }
    // The first line is the top-ranked gadget, so the file is usable
    // head-first as well as greppable.
    let first: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["id"], body["gadgets"][0]["id"], "{first}");

    // A URI that is not a scan, and a scan that is not held, are both
    // refused rather than answered.
    for bad in [
        "ropfinder://scan/../../etc/passwd/gadgets.ndjson",
        "file:///etc/passwd",
        "ropfinder://scan/deadbeefdeadbeef/gadgets.ndjson",
    ] {
        let r = mcp.rpc(7, "resources/read", json!({"uri": bad})).await;
        assert!(r.get("error").is_some(), "{bad} was served: {r}");
    }
}

/// `--workspace-dir` materializes the same bytes as a real file, next to a
/// schema for one line.
#[tokio::test]
async fn workspace_dir_materializes_the_ndjson() {
    let ws = TempTree::new("workspace");
    let dir = plain(ws.path()).display().to_string();
    let mut mcp = McpChild::spawn_with(&["--workspace-dir", &dir]).await;

    let cfg = structured(&mcp.call_tool(1, "get_server_config", json!({})).await).clone();
    assert_eq!(cfg["workspace_dir"], dir.as_str(), "{cfg}");

    let elf = fixtures_dir().join("elf-Linux-x64");
    let r = mcp
        .call_tool(
            2,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 6, "max_results": 5}),
        )
        .await;
    let body = structured(&r);
    let path = body["workspace_file"]
        .as_str()
        .expect("a paged scan writes a workspace file");
    let text = std::fs::read_to_string(path).expect("the file exists");
    assert_eq!(
        text.lines().count() as u64,
        body["total_count"].as_u64().unwrap()
    );
    let uri = body["resource_uri"].as_str().unwrap().to_string();
    let read = mcp.rpc(3, "resources/read", json!({"uri": uri})).await;
    assert_eq!(
        read["result"]["contents"][0]["text"].as_str().unwrap(),
        text,
        "the file and the resource must be the same bytes"
    );

    // The line schema is written beside it.
    let key = body["cache_key"].as_str().unwrap();
    let schema_path = ws.path().join(format!("{key}.schema.json"));
    let schema: Value =
        serde_json::from_str(&std::fs::read_to_string(&schema_path).unwrap()).unwrap();
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], Value::Bool(false));

    // An UNPAGED scan writes nothing: there is nothing an agent could not
    // already see in the response.
    let r = mcp
        .call_tool(
            4,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 6, "max_results": 50000}),
        )
        .await;
    assert!(structured(&r)["workspace_file"].is_null());
    assert!(structured(&r)["resource_uri"].is_null());
}

/// The workspace directory is where the server WRITES, so it must not be
/// somewhere the agent can ask the server to READ — otherwise an agent can
/// feed the server's own output back in, and the trust boundary the
/// allowlist draws is gone.
#[tokio::test]
async fn workspace_dir_inside_an_allow_root_is_refused() {
    let inside = fixtures_dir().join("ws-should-be-refused");
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_rop-finder-mcp"))
        .arg("--allow-dir")
        .arg(fixtures_dir())
        .arg("--workspace-dir")
        .arg(&inside)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .expect("spawn");
    assert!(!out.status.success(), "the server started anyway");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--workspace-dir"), "{err}");
    assert!(err.contains("inside the allow root"), "{err}");
    assert!(!inside.exists(), "it created the directory anyway");
}
