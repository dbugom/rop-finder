//! MCP-09 — the audit trail, and the probing signal it exists to record.
//!
//! Before this the server's only output was one startup line on stderr,
//! which MCP hosts discard. Nothing recorded which binaries were scanned,
//! which chains were built, or which paths were refused — and the refusal
//! count is precisely the signal that reveals the filesystem probing the
//! audit demonstrated against the live server.

mod support;

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use support::{fixtures_dir, structured, McpChild, TempTree};

/// Exactly the keys an audit line may carry. Asserting the SET, not merely
/// the presence of the documented ones, is how "no gadget text and no file
/// bytes" is proved structurally: the record has no field that could carry
/// one.
const AUDIT_KEYS: &[&str] = &[
    "ts",
    "session",
    "req_id",
    "tool",
    "binary",
    "binary_sha256",
    "params_hash",
    "verdict",
    "code",
    "duration_ms",
    "total_count",
    "returned",
    "cache",
    "bytes_read",
    "probing_suspected",
];

fn lines(path: &std::path::Path) -> Vec<Value> {
    let body = std::fs::read_to_string(path).expect("audit log");
    body.lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap_or_else(|e| panic!("{l:?}: {e}")))
        .collect()
}

/// Every tool call — the allowed scan, the denial and the timeout alike —
/// produces exactly ONE audit line, with the resolved path and a verdict.
#[tokio::test]
async fn every_call_produces_exactly_one_audit_line() {
    let dir = TempTree::new("audit-one-line");
    let log = dir.path().join("calls.jsonl");
    let mut mcp = McpChild::spawn_with(&[
        "--audit-log",
        &log.display().to_string(),
        "--max-gadgets",
        "0",
    ])
    .await;
    let elf = fixtures_dir().join("elf-Linux-x64");

    // 1. an allowed scan
    let ok = mcp
        .call_tool(
            10,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "max_results": 5}),
        )
        .await;
    assert_eq!(ok["result"]["isError"], false, "{ok}");
    let gadget_texts: Vec<String> = structured(&ok)["gadgets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["text"].as_str().unwrap().to_string())
        .collect();
    assert!(!gadget_texts.is_empty());

    // 2. a denied path
    let denied = mcp
        .call_tool(
            11,
            "find_gadgets",
            json!({"binary_path": "/etc/shadow", "depth": 4}),
        )
        .await;
    assert_eq!(
        structured(&denied)["error"]["code"],
        "path_denied",
        "{denied}"
    );

    // 3. a timeout
    let slow = fixtures_dir().join("elf-Mips-Defcon-20-pwn100");
    let timed_out = mcp
        .call_tool(
            12,
            "run_ropgadget_command",
            json!({"binary_path": slow, "args": ["--depth", "64", "--all"],
                   "max_results": 1, "timeout_secs": 2}),
        )
        .await;
    assert_eq!(structured(&timed_out)["error"]["code"], "timeout");

    // 4. get_server_config, which takes no binary at all
    mcp.call_tool(13, "get_server_config", json!({})).await;

    let recs = lines(&log);
    assert_eq!(recs.len(), 4, "one line per call, got:\n{recs:#?}");

    let mut session = None;
    for r in &recs {
        let obj = r.as_object().expect("object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want = AUDIT_KEYS.to_vec();
        want.sort_unstable();
        assert_eq!(keys, want, "unexpected audit fields in {r}");
        let s = r["session"].as_str().expect("session uuid");
        assert_eq!(s.len(), 36, "session is a uuid: {s}");
        assert_eq!(*session.get_or_insert(s.to_string()), s);
        assert!(r["duration_ms"].is_u64(), "{r}");
    }

    let by_id = |id: &str| recs.iter().find(|r| r["req_id"] == id).expect(id);
    let ok_line = by_id("10");
    assert_eq!(ok_line["verdict"], "ok");
    assert_eq!(ok_line["tool"], "find_gadgets");
    // The resolved, ROOT-RELATIVE label, not the caller's spelling.
    assert_eq!(ok_line["binary"], "elf-Linux-x64");
    assert_eq!(ok_line["binary_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(ok_line["cache"], "miss");
    assert_eq!(ok_line["returned"], 5);
    assert!(ok_line["total_count"].as_u64().unwrap() > 5);
    assert_eq!(ok_line["bytes_read"], 863_316);

    let denied_line = by_id("11");
    assert_eq!(denied_line["verdict"], "denied");
    assert_eq!(denied_line["code"], "path_denied");
    // The REQUESTED path, verbatim — that is the whole point of the log.
    assert_eq!(denied_line["binary"], "/etc/shadow");
    assert_eq!(denied_line["binary_sha256"], Value::Null);
    assert_eq!(denied_line["bytes_read"], 0);

    let timeout_line = by_id("12");
    assert_eq!(timeout_line["verdict"], "timeout");
    assert_eq!(timeout_line["code"], "timeout");
    assert_eq!(timeout_line["binary"], "elf-Mips-Defcon-20-pwn100");

    let cfg_line = by_id("13");
    assert_eq!(cfg_line["verdict"], "ok");
    assert_eq!(cfg_line["binary"], Value::Null);

    // NO gadget text and NO file bytes anywhere in the file.
    let body = std::fs::read_to_string(&log).unwrap();
    for t in &gadget_texts {
        assert!(!body.contains(t.as_str()), "gadget text {t:?} leaked");
    }
    assert!(!body.contains(" ; "), "gadget text separator in the log");
}

/// Two identical queries against different binaries share a `params_hash`,
/// and a different query does not — which is what makes the log greppable
/// without it becoming a second copy of the request.
#[tokio::test]
async fn params_hash_identifies_the_query_not_the_binary() {
    let dir = TempTree::new("audit-params");
    let log = dir.path().join("calls.jsonl");
    let mut mcp = McpChild::spawn_with(&["--audit-log", &log.display().to_string()]).await;
    let a = fixtures_dir().join("elf-Linux-x64");
    let b = fixtures_dir().join("elf-x64-bash-v4.1.5.1");
    mcp.call_tool(1, "find_gadgets", json!({"binary_path": a, "depth": 4}))
        .await;
    mcp.call_tool(2, "find_gadgets", json!({"binary_path": b, "depth": 4}))
        .await;
    mcp.call_tool(3, "find_gadgets", json!({"binary_path": a, "depth": 5}))
        .await;
    let recs = lines(&log);
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[0]["params_hash"], recs[1]["params_hash"]);
    assert_ne!(recs[0]["params_hash"], recs[2]["params_hash"]);
    assert_ne!(recs[0]["binary"], recs[1]["binary"]);
}

/// MCP-09's probing signal. A run of `path_denied` results trips
/// `probing_suspected`, delays every subsequent response by 250 ms, and is
/// visible in both the audit log and `get_server_stats`.
///
/// It is a clean signal precisely because `get_server_config` tells a
/// legitimate agent the allow roots, so a legitimate agent generates no
/// denials at all.
#[tokio::test]
async fn a_run_of_denials_is_flagged_and_slowed() {
    let dir = TempTree::new("audit-probe");
    let log = dir.path().join("calls.jsonl");
    let mut mcp = McpChild::spawn_with(&[
        "--audit-log",
        &log.display().to_string(),
        "--probe-threshold",
        "3",
    ])
    .await;

    let mut timings = Vec::new();
    for (i, path) in [
        "/etc/shadow",
        "/root/.ssh/id_rsa",
        "/home/x/.aws/credentials",
    ]
    .iter()
    .enumerate()
    {
        let t0 = Instant::now();
        let r = mcp
            .call_tool(100 + i as u64, "find_gadgets", json!({"binary_path": path}))
            .await;
        timings.push(t0.elapsed());
        assert_eq!(structured(&r)["error"]["code"], "path_denied", "{r}");
    }

    let recs = lines(&log);
    assert_eq!(recs.len(), 3);
    assert_eq!(recs[0]["probing_suspected"], false);
    assert_eq!(recs[1]["probing_suspected"], false);
    assert_eq!(recs[2]["probing_suspected"], true, "{:#?}", recs[2]);
    // Each requested path is on the record.
    assert_eq!(recs[0]["binary"], "/etc/shadow");
    assert_eq!(recs[1]["binary"], "/root/.ssh/id_rsa");
    assert_eq!(recs[2]["binary"], "/home/x/.aws/credentials");

    // The third response was deliberately delayed.
    let third = timings.get(2).copied().unwrap();
    assert!(
        third >= Duration::from_millis(240),
        "the flagged response took {third:?}, so it was not delayed"
    );

    let s = mcp.stats(200).await;
    assert_eq!(s["probing_suspected"], true, "{s}");
    assert_eq!(s["denied_total"], 3, "{s}");
    assert_eq!(s["denied_consecutive"], 3, "{s}");

    // One legitimate call ends the run...
    let elf = fixtures_dir().join("elf-Linux-x64");
    mcp.call_tool(
        201,
        "find_gadgets",
        json!({"binary_path": elf, "depth": 3, "max_results": 1}),
    )
    .await;
    let s = mcp.stats(202).await;
    assert_eq!(s["denied_consecutive"], 0, "{s}");
    // ...but the session-level flag and the high-water mark are sticky, so
    // an operator reading the stats later still sees what happened.
    assert_eq!(s["probing_suspected"], true, "{s}");
    assert_eq!(s["denied_consecutive_max"], 3, "{s}");
}

/// `get_server_stats` reports every counter the design names.
#[tokio::test]
async fn server_stats_reports_the_documented_counters() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    mcp.call_tool(
        1,
        "find_gadgets",
        json!({"binary_path": elf, "depth": 4, "max_results": 2}),
    )
    .await;
    let s = mcp.stats(2).await;
    for key in [
        "requests_total",
        "requests_by_tool",
        "ok_total",
        "denied_total",
        "denied_consecutive",
        "timeout_total",
        "cancelled_total",
        "wedged_total",
        "busy_total",
        "error_total",
        "bytes_read_total",
        "inflight",
        "probing_suspected",
        "cache",
    ] {
        assert!(s.get(key).is_some(), "missing {key} in {s}");
    }
    for key in [
        "hits",
        "misses",
        "entries",
        "cache_bytes",
        "cache_mem_max_bytes",
        "cache_ttl_secs",
        "evictions",
        "disk",
    ] {
        assert!(s["cache"].get(key).is_some(), "missing cache.{key} in {s}");
    }
    assert_eq!(s["requests_by_tool"]["find_gadgets"], 1);
    assert_eq!(s["bytes_read_total"], 863_316);
    assert_eq!(s["inflight"], 0);
    assert_eq!(s["cache"]["entries"], 1);
    assert!(s["cache"]["cache_bytes"].as_u64().unwrap() > 0);
}

/// MCP-09: warnings reach the OPERATOR, not just a stderr stream the host
/// throws away. The probing signal is forwarded as `notifications/message`
/// under the declared `logging` capability, and `logging/setLevel` gates it.
#[tokio::test]
async fn operator_warnings_are_forwarded_as_notifications() {
    let mut mcp = McpChild::spawn_with(&["--probe-threshold", "1"]).await;

    let mut seen = Vec::new();
    mcp.send_tool(1, "find_gadgets", json!({"binary_path": "/etc/shadow"}))
        .await;
    let r = mcp
        .await_id_with(1, Duration::from_secs(30), &mut seen)
        .await
        .expect("denial answered");
    assert_eq!(structured(&r)["error"]["code"], "path_denied");

    // The notification is fire-and-forget, so give it a moment to land if
    // it has not already overtaken the (deliberately delayed) response.
    let _ = mcp
        .await_id_with(u64::MAX, Duration::from_millis(800), &mut seen)
        .await;

    let note = seen
        .iter()
        .find(|v| v["method"] == "notifications/message")
        .unwrap_or_else(|| panic!("no notifications/message in {seen:#?}"));
    assert_eq!(note["params"]["level"], "warning", "{note}");
    assert_eq!(note["params"]["logger"], "rop-finder-mcp", "{note}");
    assert_eq!(note["params"]["data"]["code"], "path_probing", "{note}");
    // The REQUESTED path rides along, because that is the evidence.
    assert_eq!(
        note["params"]["data"]["detail"]["requested"], "/etc/shadow",
        "{note}"
    );
    // ...and no gadget text or file content could be in it: the payload is
    // a fixed {code, message, detail} shape.
    let keys: Vec<&str> = note["params"]["data"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["code", "detail", "message"], "{note}");
}

/// `logging/setLevel` is honoured, not merely advertised: raising the floor
/// to `error` stops the warning being forwarded at all.
#[tokio::test]
async fn set_level_silences_the_forwarded_warnings() {
    let mut mcp = McpChild::spawn_with(&["--probe-threshold", "1"]).await;
    let ack = mcp
        .rpc(50, "logging/setLevel", json!({"level": "error"}))
        .await;
    assert!(ack.get("error").is_none(), "setLevel refused: {ack}");

    let mut seen = Vec::new();
    mcp.send_tool(51, "find_gadgets", json!({"binary_path": "/etc/shadow"}))
        .await;
    mcp.await_id_with(51, Duration::from_secs(30), &mut seen)
        .await
        .expect("denial answered");
    let _ = mcp
        .await_id_with(u64::MAX, Duration::from_millis(800), &mut seen)
        .await;
    assert!(
        !seen.iter().any(|v| v["method"] == "notifications/message"),
        "a warning was forwarded below the requested level: {seen:#?}"
    );
    // The signal is still recorded where an operator can find it.
    let s = mcp.stats(52).await;
    assert_eq!(s["probing_suspected"], true, "{s}");
}
