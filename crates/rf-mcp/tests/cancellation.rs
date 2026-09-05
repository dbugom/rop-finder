//! MCP-03 / PERF-06 — the cancellation tests, which are MEASUREMENTS.
//!
//! What was measured on the live pre-fix server:
//!
//!   * a `depth=u64::MAX` request with `timeout_secs=2` returned a tidy
//!     timeout error at t=2.00 s, and the process then held 395-400% CPU
//!     indefinitely;
//!   * a `depth=100000` request the client had already cancelled with
//!     `notifications/cancelled` reached 54,873 MB RSS thirteen seconds
//!     later, and no response ever arrived.
//!
//! `tokio::time::timeout` wrapped `spawn_blocking`, so it abandoned the
//! await and never the work, and the closure had no cancellation point.
//! Both of those are now [`rf_mcp::guard::Guard::run`].
//!
//! The workload is `--depth 64 --all` on the 6 MB MIPS fixture: 57.8 s in
//! this profile's build, so a 2 s timeout is unambiguous. `--all` skips
//! dedup, which is what makes it big rather than merely slow.
//!
//! Sampling is `Get-Process -Id` on Windows (`TotalProcessorTime.Ticks`,
//! which is `GetProcessTimes`' user+kernel sum, and `WorkingSet64`) and
//! `/proc/<pid>/stat` on Linux. See `support::sample`.

mod support;

use std::time::{Duration, Instant};

use serde_json::json;

use support::{fixtures_dir, mib, sample, structured, McpChild};

/// The fixture and flags that will not finish inside any test's patience.
const SLOW_FIXTURE: &str = "elf-Mips-Defcon-20-pwn100";
fn slow_args() -> serde_json::Value {
    json!(["--depth", "64", "--all"])
}

/// A timed-out request leaves NO work running.
///
/// The client gets its error, and then the server's processor time stops
/// moving. The pre-fix baseline for the same shape of request is 398-400%
/// CPU held for as long as the process lives.
#[tokio::test]
async fn timeout_actually_stops_the_work() {
    let mut mcp = McpChild::spawn_with(&["--max-gadgets", "0"]).await;
    let pid = mcp.pid();
    let bin = fixtures_dir().join(SLOW_FIXTURE);

    let before = sample(pid).expect("sample the server process");
    let t0 = Instant::now();
    let resp = mcp
        .call_tool(
            10,
            "run_ropgadget_command",
            json!({"binary_path": bin, "args": slow_args(),
                   "max_results": 1, "timeout_secs": 2}),
        )
        .await;
    let elapsed = t0.elapsed();
    assert_eq!(resp["result"]["isError"], true, "{resp}");
    let code = structured(&resp)["error"]["code"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(code, "timeout", "{resp}");
    // The reply is prompt: the join happened, it did not take the 5 s
    // hard-join window.
    assert!(
        elapsed < Duration::from_secs(7),
        "timeout reply took {elapsed:?}"
    );

    // The work really was running, so the interesting number is what
    // happens NEXT.
    let during = sample(pid).expect("sample");
    assert!(
        during.cpu_secs > before.cpu_secs,
        "the scan never ran: {before:?} -> {during:?}"
    );

    tokio::time::sleep(Duration::from_secs(3)).await;
    let at3 = sample(pid).expect("sample at +3 s");
    tokio::time::sleep(Duration::from_secs(5)).await;
    let at8 = sample(pid).expect("sample at +8 s");

    let cpu_delta = at8.cpu_secs - at3.cpu_secs;
    let rss_growth = at8.rss_bytes.saturating_sub(at3.rss_bytes);
    println!(
        "timeout_actually_stops_the_work: reply after {elapsed:?}\n\
         CPU  before={:.3}s during={:.3}s +3s={:.3}s +8s={:.3}s  delta(+3..+8)={cpu_delta:.3}s\n\
         RSS  before={:.1} during={:.1} +3s={:.1} +8s={:.1} MiB  growth={:.1} MiB",
        before.cpu_secs,
        during.cpu_secs,
        at3.cpu_secs,
        at8.cpu_secs,
        mib(before.rss_bytes),
        mib(during.rss_bytes),
        mib(at3.rss_bytes),
        mib(at8.rss_bytes),
        mib(rss_growth),
    );
    assert!(
        cpu_delta < 0.2,
        "server burned {cpu_delta:.3} s of CPU between +3 s and +8 s after the timeout \
         (before={:.3} during={:.3} at3={:.3} at8={:.3})",
        before.cpu_secs,
        during.cpu_secs,
        at3.cpu_secs,
        at8.cpu_secs
    );
    assert!(
        rss_growth < 50 * 1024 * 1024,
        "RSS grew {:.1} MiB between +3 s and +8 s (at3={:.1} at8={:.1})",
        mib(rss_growth),
        mib(at3.rss_bytes),
        mib(at8.rss_bytes)
    );

    // ...and the server counted it rather than merely surviving it.
    let s = mcp.stats(11).await;
    assert_eq!(s["timeout_total"], 1, "{s}");
    assert_eq!(s["wedged_total"], 0, "a worker did not stop in time: {s}");
    assert_eq!(s["inflight"], 0, "the permit was not released: {s}");
}

/// `notifications/cancelled` stops the work.
///
/// NOTE on what is asserted. The MCP specification says a cancelled
/// request MUST NOT be responded to, and rmcp enforces it: once the
/// notification arrives the request id is removed from its pool and any
/// response the handler produces is dropped (`service.rs`, "dropping
/// response for cancelled request"). So the observable is not a
/// `cancelled` response body — no protocol-conformant server can send one
/// — it is that the work STOPS, promptly, and says so: `cancelled_total`
/// goes to 1, `inflight` returns to 0, the audit line for that request
/// carries `verdict: "cancelled"`, and the CPU goes quiet. Before this
/// fix, none of those happened and the scan ran on to 54.8 GB.
#[tokio::test]
async fn cancellation_notification_is_honoured() {
    let audit = support::TempTree::new("cancel-audit");
    let log = audit.path().join("calls.jsonl");
    let mut mcp = McpChild::spawn_with(&[
        "--max-gadgets",
        "0",
        "--audit-log",
        &log.display().to_string(),
    ])
    .await;
    let pid = mcp.pid();
    let bin = fixtures_dir().join(SLOW_FIXTURE);

    mcp.send_tool(
        20,
        "run_ropgadget_command",
        json!({"binary_path": bin, "args": slow_args(),
               "max_results": 1, "timeout_secs": 120}),
    )
    .await;
    // Let it get well inside the scan loops.
    tokio::time::sleep(Duration::from_millis(700)).await;
    let running = sample(pid).expect("sample");

    let cancelled_at = Instant::now();
    mcp.notify("notifications/cancelled", json!({"requestId": 20}))
        .await;

    // Within 3 s the server must report the work as stopped.
    let mut stopped_after = None;
    for id in 21..40u64 {
        let s = mcp.stats(id).await;
        assert!(s["inflight"].as_u64().unwrap() <= 1, "{s}");
        if s["cancelled_total"] == 1 && s["inflight"] == 0 {
            stopped_after = Some(cancelled_at.elapsed());
            break;
        }
        if cancelled_at.elapsed() > Duration::from_secs(3) {
            panic!("still not cancelled after 3 s: {s}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stopped_after = stopped_after.expect("cancellation was never observed");
    assert!(stopped_after < Duration::from_secs(3), "{stopped_after:?}");

    // CPU returns to idle.
    let a = sample(pid).expect("sample");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let b = sample(pid).expect("sample");
    let delta = b.cpu_secs - a.cpu_secs;
    println!(
        "cancellation_notification_is_honoured: stopped {stopped_after:?} after the \
         notification\nCPU while running={:.3}s, then {:.3}s -> {:.3}s over 2 s \
         (delta={delta:.3}s); RSS {:.1} -> {:.1} MiB",
        running.cpu_secs,
        a.cpu_secs,
        b.cpu_secs,
        mib(a.rss_bytes),
        mib(b.rss_bytes),
    );
    assert!(
        delta < 0.2,
        "server burned {delta:.3} s of CPU in the 2 s after cancellation \
         (running={:.3})",
        running.cpu_secs
    );

    // The audit trail records it, which is the only durable evidence a
    // spec-conformant server can leave for a cancelled request.
    let body = std::fs::read_to_string(&log).expect("audit log");
    let line = body
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect(l))
        .find(|v| v["req_id"] == "20")
        .unwrap_or_else(|| panic!("no audit line for request 20 in:\n{body}"));
    assert_eq!(line["verdict"], "cancelled", "{line}");
    assert_eq!(line["tool"], "run_ropgadget_command");
    assert_eq!(line["code"], "cancelled");

    // ...and no response for id 20 was ever sent, per the spec.
    let mut seen = Vec::new();
    let late = mcp
        .await_id_with(20, Duration::from_millis(500), &mut seen)
        .await;
    assert!(late.is_none(), "a cancelled request was answered: {late:?}");
}

/// MCP-06: `get_binary_info` no longer does its whole-file read plus
/// goblin parse INLINE on the async runtime, so four of them at once do
/// not stop the server answering anything else.
#[tokio::test]
async fn info_does_not_block_the_runtime() {
    let mut mcp = McpChild::spawn().await;
    let bin = fixtures_dir().join(SLOW_FIXTURE);
    for id in 30..34u64 {
        mcp.send_tool(id, "get_binary_info", json!({"binary_path": bin}))
            .await;
    }
    let t0 = Instant::now();
    mcp.send(40, "tools/list", json!({})).await;
    let mut seen = Vec::new();
    let resp = mcp
        .await_id_with(40, Duration::from_secs(10), &mut seen)
        .await
        .expect("tools/list answered");
    let took = t0.elapsed();
    assert!(resp["result"]["tools"].is_array(), "{resp}");

    // THE PROPERTY, measured by ordering rather than by a clock. `seen` holds
    // every response that arrived ahead of tools/list. A blocked runtime cannot
    // answer id 40 until the four get_binary_info calls are done, so all four
    // would be sitting in `seen`. An unblocked one answers while they are still
    // in flight. This is exact and identical on every machine.
    let inflight_first = ids_in(&seen, 30, 33);
    println!(
        "info_does_not_block_the_runtime: tools/list answered in {took:?}, {inflight_first} of 4 get_binary_info calls had answered first"
    );
    assert!(
        inflight_first < 4,
        "all four get_binary_info calls answered before tools/list did, which is exactly what a blocked runtime looks like (took {took:?})"
    );
    assert!(
        took < cheap_tool_budget(),
        "tools/list took {took:?} behind four get_binary_info calls"
    );
}

/// How long a *cheap* tool may take while expensive work is in flight.
///
/// The property under test is that the async runtime is not blocked: a blocked
/// server cannot answer `tools/list` until the scans holding its threads
/// finish, which is seconds (the scans below run with `timeout_secs: 4`). A
/// healthy server answers in single-digit milliseconds — 3.1 ms measured on
/// the development machine.
///
/// This is now a BACKSTOP, not the property. The property is the ordering
/// assertion in each test: a blocked runtime answers the in-flight work before
/// it answers `tools/list`, and that is exact on every machine.
///
/// The clock is kept only to catch a server that is slow without being blocked,
/// and its number has been wrong twice. 100 ms was a fast-workstation figure and
/// failed immediately. 1 s then failed at 1.0355007 s on windows-2022 -- over by
/// 35 ms. That is not a bug it caught; it is the measurement being unfit. Note
/// that `took` is not tools/list's latency: `await_id_with` drains the stream
/// until the matching id appears, so it also includes reading anything queued
/// ahead of it. Five seconds is loose enough to stop measuring the runner and
/// tight enough to notice a genuine stall. `RF_CHEAP_TOOL_BUDGET_MS` tightens it
/// where the machine is known.
fn cheap_tool_budget() -> Duration {
    let ms = std::env::var("RF_CHEAP_TOOL_BUDGET_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);
    Duration::from_millis(ms)
}

/// The same property with the *expensive* tool: two long scans hold both
/// inflight permits, and the server still answers its cheap tools.
#[tokio::test]
async fn a_saturated_server_still_answers_cheap_tools() {
    let mut mcp = McpChild::spawn_with(&["--max-concurrent", "2", "--max-gadgets", "0"]).await;
    let bin = fixtures_dir().join(SLOW_FIXTURE);
    for id in 50..52u64 {
        mcp.send_tool(
            id,
            "run_ropgadget_command",
            json!({"binary_path": bin, "args": slow_args(),
                   "max_results": 1, "timeout_secs": 4}),
        )
        .await;
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    let t0 = Instant::now();
    mcp.send(60, "tools/list", json!({})).await;
    let mut seen = Vec::new();
    let resp = mcp
        .await_id_with(60, Duration::from_secs(10), &mut seen)
        .await
        .expect("tools/list answered");
    let took = t0.elapsed();
    assert!(resp["result"]["tools"].is_array(), "{resp}");

    // Same ordering property as above: both scans hold permits and run for
    // `timeout_secs: 4`, so a blocked server answers them before it answers
    // tools/list. Neither should have finished first.
    let scans_first = ids_in(&seen, 50, 51);
    println!(
        "a_saturated_server_still_answers_cheap_tools: tools/list answered in {took:?}, {scans_first} of 2 scans had answered first"
    );
    assert!(
        scans_first < 2,
        "both scans answered before tools/list did, with both slots busy (took {took:?})"
    );
    assert!(
        took < cheap_tool_budget(),
        "tools/list took {took:?} with both scan slots busy"
    );
}

/// `--scan-threads` really sizes the pool every scan runs inside, so the
/// server cannot take every core on the operator's machine.
#[tokio::test]
async fn the_scan_pool_is_sized_by_the_flag() {
    let mut mcp = McpChild::spawn_with(&["--scan-threads", "1"]).await;
    let cfg = mcp.call_tool(1, "get_server_config", json!({})).await;
    // config_json reads the POOL's thread count, not the flag, so this
    // fails if the flag never reaches the pool.
    assert_eq!(structured(&cfg)["scan_threads"], 1, "{cfg}");

    // ...and a scan still works on one thread.
    let elf = fixtures_dir().join("elf-Linux-x64");
    let r = mcp
        .call_tool(
            2,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "max_results": 3}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");

    let mut mcp = McpChild::spawn().await;
    let cfg = mcp.call_tool(1, "get_server_config", json!({})).await;
    let n = structured(&cfg)["scan_threads"].as_u64().unwrap();
    let cores = std::thread::available_parallelism()
        .map(|c| c.get())
        .unwrap_or(2) as u64;
    assert!(n >= 1 && n < cores.max(2), "default {n} of {cores} cores");
}

/// `--max-gadgets` is the other half of the bound: cancellation alone does
/// not stop a scan that is legitimately huge, and the engine budget does.
#[tokio::test]
async fn the_gadget_budget_stops_a_huge_scan() {
    let mut mcp = McpChild::spawn_with(&["--max-gadgets", "500"]).await;
    let cfg = mcp.call_tool(1, "get_server_config", json!({})).await;
    assert_eq!(structured(&cfg)["max_gadgets"], 500, "{cfg}");

    let elf = fixtures_dir().join("elf-x64-bash-v4.1.5.1");
    let r = mcp
        .call_tool(
            2,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 20, "max_results": 1, "timeout_secs": 60}),
        )
        .await;
    assert_eq!(r["result"]["isError"], true, "{r}");
    let e = &structured(&r)["error"];
    assert_eq!(e["code"], "resource_exhausted", "{e}");
    assert_eq!(e["details"]["limit"], "max_gadgets");
    assert_eq!(e["details"]["limit_value"], 500);

    // It is a budget, not a crash: the server is still serving, and the
    // failure is recorded as an error rather than a timeout or a denial.
    let ok = mcp
        .call_tool(3, "get_binary_info", json!({"binary_path": elf}))
        .await;
    assert_eq!(ok["result"]["isError"], false, "{ok}");
    let s = mcp.stats(4).await;
    assert_eq!(s["error_total"], 1, "{s}");
    assert_eq!(s["timeout_total"], 0, "{s}");
    assert_eq!(s["inflight"], 0, "{s}");

    // ...and the same scan under the default budget succeeds, so the
    // refusal was the budget and not the binary.
    let mut roomy = McpChild::spawn().await;
    let big = roomy
        .call_tool(
            1,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 20, "max_results": 1, "timeout_secs": 120}),
        )
        .await;
    assert_eq!(big["result"]["isError"], false, "{big}");
    assert!(structured(&big)["total_count"].as_u64().unwrap() > 500);
}

/// How many responses with ids in `lo..=hi` arrived before the one we awaited.
///
/// `McpChild::await_id_with` collects them in order, so this counts the in-flight
/// work that finished ahead of the cheap call -- the thing that distinguishes a
/// blocked runtime from a merely slow machine.
fn ids_in(seen: &[serde_json::Value], lo: u64, hi: u64) -> usize {
    seen.iter()
        .filter(|v| {
            v.get("id")
                .and_then(|i| i.as_u64())
                .is_some_and(|i| i >= lo && i <= hi)
        })
        .count()
}
