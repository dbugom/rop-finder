//! MCP-09's cheapest guard: stdout carries JSON-RPC 2.0 and nothing else.
//!
//! stdout is the transport. One stray `println!` — a debug print, a
//! `dbg!`, a warning that took the wrong writer — corrupts the session,
//! and there is no error anywhere: the host simply stops understanding the
//! server. This test drives a full session that exercises every path that
//! writes a diagnostic — a denial, an unknown tool, malformed arguments, a
//! file over `--max-file-bytes`, a timeout, a client cancellation, and a
//! TAMPERED on-disk cache entry (the path that used to `eprintln!` from
//! inside the cache, and before v0.2 could panic the worker outright) —
//! then asserts that every raw line the server wrote parses as JSON-RPC
//! 2.0.

mod support;

use std::time::Duration;

use serde_json::{json, Value};

use support::{fixtures_dir, McpChild, TempTree};

fn assert_jsonrpc(line: &str) {
    let v: Value =
        serde_json::from_str(line).unwrap_or_else(|e| panic!("non-JSON on stdout: {line:?} ({e})"));
    assert_eq!(
        v["jsonrpc"], "2.0",
        "line is JSON but not JSON-RPC 2.0: {line}"
    );
    let is_response =
        v.get("id").is_some() && (v.get("result").is_some() || v.get("error").is_some());
    let is_notification = v.get("method").is_some();
    assert!(
        is_response || is_notification,
        "line is neither a response nor a notification: {line}"
    );
}

#[tokio::test]
async fn stdout_is_pure_jsonrpc() {
    let cachedir = TempTree::new("purity-cache");
    let auditdir = TempTree::new("purity-audit");
    let log = auditdir.path().join("calls.jsonl");
    let cache_arg = cachedir.path().display().to_string();
    let audit_arg = log.display().to_string();
    let elf = fixtures_dir().join("elf-Linux-x64");
    let slow = fixtures_dir().join("elf-Mips-Defcon-20-pwn100");
    let scan_args = json!({"binary_path": elf, "depth": 4, "max_results": 3});

    let mut raw: Vec<String> = Vec::new();
    let mut ignored: Vec<Value> = Vec::new();

    // --- session 1: errors of every shape, plus a populated cache -------
    {
        let mut mcp = McpChild::spawn_with(&[
            "--cache-dir",
            &cache_arg,
            "--audit-log",
            &audit_arg,
            "--probe-threshold",
            "2",
            "--max-gadgets",
            "0",
        ])
        .await;

        // two denials, enough to trip the probing signal at threshold 2
        for (i, p) in ["/etc/shadow", "/etc/passwd"].iter().enumerate() {
            mcp.send_tool(3 + i as u64, "find_gadgets", json!({"binary_path": p}))
                .await;
            mcp.await_id_with(3 + i as u64, Duration::from_secs(30), &mut ignored)
                .await
                .expect("denial answered");
        }

        // an unknown tool and a malformed argument set
        mcp.send(
            5,
            "tools/call",
            json!({"name": "no_such_tool", "arguments": {}}),
        )
        .await;
        mcp.await_id_with(5, Duration::from_secs(30), &mut ignored)
            .await
            .expect("unknown tool answered");
        mcp.send_tool(6, "find_gadgets", json!({"depth": "not a number"}))
            .await;
        mcp.await_id_with(6, Duration::from_secs(30), &mut ignored)
            .await
            .expect("malformed args answered");

        // a timeout
        mcp.send_tool(
            7,
            "run_ropgadget_command",
            json!({"binary_path": slow, "args": ["--depth", "64", "--all"],
                   "max_results": 1, "timeout_secs": 2}),
        )
        .await;
        let r = mcp
            .await_id_with(7, Duration::from_secs(60), &mut ignored)
            .await
            .expect("timeout answered");
        assert_eq!(r["result"]["isError"], true, "{r}");

        // a request the client cancels: no response, by specification
        mcp.send_tool(
            8,
            "run_ropgadget_command",
            json!({"binary_path": slow, "args": ["--depth", "64", "--all"],
                   "max_results": 1, "timeout_secs": 120}),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        mcp.notify("notifications/cancelled", json!({"requestId": 8}))
            .await;
        // Give the cancellation time to land and anything it emits time to
        // arrive on stdout.
        let _ = mcp
            .await_id_with(u64::MAX, Duration::from_secs(4), &mut ignored)
            .await;

        // a successful scan, so the on-disk cache has an entry to poison
        mcp.send_tool(9, "find_gadgets", scan_args.clone()).await;
        let r = mcp
            .await_id_with(9, Duration::from_secs(60), &mut ignored)
            .await
            .expect("scan answered");
        assert_eq!(r["result"]["isError"], false, "{r}");
        raw.append(&mut mcp.raw);
    }

    // --- poison the cache entry ----------------------------------------
    let entry = std::fs::read_dir(cachedir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|x| x == "rfc"))
        .expect("a cache entry was written");
    // Bare JSON with a fabricated gadget: the shape the pre-v0.2 cache
    // accepted, and the exact poison served through the live server at
    // 0xdeadbeefcafe0000.
    std::fs::write(
        &entry,
        br#"{"version":2,"gadgets":[{"vaddr":"0xdeadbeefcafe0000","bytes":"5fc3","text":"pop rdi ; ret"}],"fallback_names":false}"#,
    )
    .unwrap();

    // --- session 2: read the poisoned entry, plus an oversized file -----
    {
        let mut mcp = McpChild::spawn_with(&[
            "--cache-dir",
            &cache_arg,
            "--audit-log",
            &audit_arg,
            "--max-file-bytes",
            "1024",
        ])
        .await;
        mcp.send_tool(20, "find_gadgets", scan_args.clone()).await;
        let r = mcp
            .await_id_with(20, Duration::from_secs(60), &mut ignored)
            .await
            .expect("answered over a poisoned cache");
        // The file is over --max-file-bytes here, so the refusal comes
        // before the cache is even consulted: both diagnostics, one call.
        let body = r.to_string();
        assert!(
            !body.contains("deadbeefcafe0000"),
            "a tampered cache entry was served: {body}"
        );
        assert_eq!(r["result"]["isError"], true, "{r}");
        raw.append(&mut mcp.raw);
    }

    // --- session 3: the poisoned entry is a MISS, not a result ----------
    {
        let mut mcp =
            McpChild::spawn_with(&["--cache-dir", &cache_arg, "--audit-log", &audit_arg]).await;
        mcp.send_tool(30, "find_gadgets", scan_args).await;
        let r = mcp
            .await_id_with(30, Duration::from_secs(60), &mut ignored)
            .await
            .expect("answered over a poisoned cache");
        assert_eq!(r["result"]["isError"], false, "{r}");
        let s = r["result"]["structuredContent"].clone();
        assert_eq!(s["cache"], "miss", "the poisoned entry was served: {s}");
        let body = r.to_string();
        assert!(
            !body.contains("deadbeefcafe0000"),
            "a tampered cache entry was served: {body}"
        );

        // ...and the server is still alive and answering.
        let alive = mcp.call_tool(99, "get_server_config", json!({})).await;
        assert_eq!(alive["result"]["isError"], false, "{alive}");
        raw.append(&mut mcp.raw);
    }

    assert!(raw.len() >= 12, "only {} stdout lines seen", raw.len());
    for line in &raw {
        assert_jsonrpc(line);
    }
    println!(
        "stdout_is_pure_jsonrpc: {} lines, all JSON-RPC 2.0",
        raw.len()
    );
}
