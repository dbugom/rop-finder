//! MCP-05 / ROB-07 — the in-memory scan cache is bounded.
//!
//! Measured on the live pre-fix server: twelve depth-varying scans of one
//! 900 KB binary walked RSS from 5 MB to 84 MB *monotonically* with
//! `max_results: 1` on every call — so the response cap does not bound
//! retention — and one depth-40 scan pinned 2.57 GB for the life of the
//! process. The cache was `Mutex<HashMap<String, Arc<CachedScan>>>` with
//! `get` and `put` and nothing else.

mod support;

use std::time::Duration;

use serde_json::json;

use support::{fixtures_dir, mib, sample, structured, McpChild};

/// Forty distinct scans against a 64 MiB budget: `cache_bytes` stays under
/// it, entries are actually evicted, and RSS stops climbing.
#[tokio::test]
async fn cache_is_bounded() {
    let budget_mib = 64u64;
    let budget = budget_mib * 1024 * 1024;
    let mut mcp = McpChild::spawn_with(&["--cache-mem-mb", &budget_mib.to_string()]).await;
    let pid = mcp.pid();
    let elf = fixtures_dir().join("elf-Linux-x64");

    let baseline = sample(pid).expect("sample the server process");
    let mut peak_cache = 0u64;
    let mut peak_rss = baseline.rss_bytes;
    let mut entries_seen = 0u64;

    // Forty DIFFERENT depths, so every call is a distinct cache key and
    // nothing is served from an earlier entry.
    for (n, depth) in (2..=41u64).enumerate() {
        let r = mcp
            .call_tool(
                1000 + n as u64,
                "find_gadgets",
                json!({"binary_path": elf, "depth": depth, "max_results": 1}),
            )
            .await;
        assert_eq!(r["result"]["isError"], false, "depth {depth}: {r}");
        assert_eq!(structured(&r)["cache"], "miss", "depth {depth} was not new");

        let s = mcp.stats(2000 + n as u64).await;
        let bytes = s["cache"]["cache_bytes"].as_u64().unwrap();
        entries_seen = s["cache"]["entries"].as_u64().unwrap();
        peak_cache = peak_cache.max(bytes);
        assert!(
            bytes <= budget,
            "cache_bytes {} MiB over the {budget_mib} MiB budget after depth {depth}",
            mib(bytes)
        );
        if let Some(p) = sample(pid) {
            peak_rss = peak_rss.max(p.rss_bytes);
        }
    }

    let s = mcp.stats(9000).await;
    let evicted = s["cache"]["evictions"].as_u64().unwrap();
    let final_bytes = s["cache"]["cache_bytes"].as_u64().unwrap();
    let final_rss = sample(pid).map(|p| p.rss_bytes).unwrap_or(0);

    // Report the real numbers whichever way the assertions go.
    println!(
        "cache_is_bounded: 40 scans, budget {budget_mib} MiB\n\
         peak cache_bytes  = {:.1} MiB\n\
         final cache_bytes = {:.1} MiB across {entries_seen} entries\n\
         evictions         = {evicted}\n\
         RSS baseline      = {:.1} MiB\n\
         RSS peak          = {:.1} MiB\n\
         RSS final         = {:.1} MiB",
        mib(peak_cache),
        mib(final_bytes),
        mib(baseline.rss_bytes),
        mib(peak_rss),
        mib(final_rss),
    );

    assert!(
        final_bytes <= budget,
        "{:.1} MiB retained",
        mib(final_bytes)
    );
    assert!(
        evicted > 0,
        "nothing was ever evicted, so the budget was never reached — the test binary is \
         too small to exercise MCP-05 (final {:.1} MiB)",
        mib(final_bytes)
    );
    assert!(
        entries_seen < 40,
        "all 40 entries were retained: {entries_seen}"
    );
    // A backstop against CATASTROPHIC runaway, and deliberately nothing more.
    //
    // This bound was baseline + 600 MiB, and it failed on macos-15 with the
    // cache demonstrably working: peak cache_bytes 64.0 MiB (exactly the
    // budget), 29 evictions, 11 of 40 entries retained, RSS peak 743.8 MiB.
    // Process RSS here is dominated by scan working memory and by an allocator
    // that does not return freed pages to the OS, neither of which is the cache.
    //
    // It cannot be repaired by picking a better number. The regression it named
    // -- 40 entries retained instead of 11, roughly +170 MiB -- is SMALLER than
    // the run-to-run scan noise it is measured through, so any threshold tight
    // enough to catch that regression flakes, and any threshold loose enough to
    // be stable cannot catch it. The four assertions above already catch it
    // exactly, from the server's own accounting, which is what MCP-05 is
    // actually about.
    //
    // So this now guards only the failure mode RSS genuinely can see: the
    // pre-fix cancellation blowup reached 54.8 GB (see cancellation.rs). Two
    // gigabytes separates that from any healthy run on any platform.
    // RF_CACHE_RSS_CEILING_MIB tightens it where the environment is known.
    let ceiling = rss_ceiling_bytes(baseline.rss_bytes);
    assert!(
        final_rss < ceiling,
        "RSS grew from {:.1} MiB to {:.1} MiB, past the {:.1} MiB runaway ceiling",
        mib(baseline.rss_bytes),
        mib(final_rss),
        mib(ceiling)
    );
}

/// A cache entry that cannot fit the whole budget is served and dropped,
/// never retained: ROB-07's 2.57 GB, refused.
#[tokio::test]
async fn an_entry_larger_than_the_budget_is_never_retained() {
    let mut mcp = McpChild::spawn_with(&["--cache-mem-mb", "1"]).await;
    let elf = fixtures_dir().join("elf-x64-bash-v4.1.5.1");
    let r = mcp
        .call_tool(
            1,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 12, "max_results": 1}),
        )
        .await;
    assert_eq!(r["result"]["isError"], false, "{r}");
    assert!(structured(&r)["total_count"].as_u64().unwrap() > 10_000);

    let s = mcp.stats(2).await;
    println!(
        "1 MiB budget: entries={} cache_bytes={} too_large={}",
        s["cache"]["entries"], s["cache"]["cache_bytes"], s["cache"]["too_large"]
    );
    assert_eq!(s["cache"]["entries"], 0, "{s}");
    assert_eq!(s["cache"]["cache_bytes"], 0, "{s}");
    assert_eq!(s["cache"]["too_large"], 1, "{s}");

    // The same request again is a MISS, not a stale hit.
    let again = mcp
        .call_tool(
            3,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 12, "max_results": 1}),
        )
        .await;
    assert_eq!(structured(&again)["cache"], "miss");
}

/// A zero TTL makes every entry a miss, which is the other half of the
/// bound: an entry nobody asks for again does not live for ever.
#[tokio::test]
async fn the_ttl_expires_entries() {
    let mut mcp = McpChild::spawn_with(&["--cache-ttl-secs", "1"]).await;
    let elf = fixtures_dir().join("elf-Linux-x64");
    let args = json!({"binary_path": elf, "depth": 4, "max_results": 1});
    let a = mcp.call_tool(1, "find_gadgets", args.clone()).await;
    assert_eq!(structured(&a)["cache"], "miss");
    let b = mcp.call_tool(2, "find_gadgets", args.clone()).await;
    assert_eq!(structured(&b)["cache"], "hit", "the cache works at all");

    tokio::time::sleep(Duration::from_millis(2200)).await;
    let c = mcp.call_tool(3, "find_gadgets", args).await;
    assert_eq!(structured(&c)["cache"], "miss", "TTL did not expire it");
    let s = mcp.stats(4).await;
    assert!(s["cache"]["expired"].as_u64().unwrap() >= 1, "{s}");
}

/// Ceiling for [`cache_is_bounded`]'s runaway backstop: baseline RSS plus 2 GiB
/// by default, or `RF_CACHE_RSS_CEILING_MIB` megabytes over baseline if set.
///
/// Two gigabytes is not a tolerance for normal growth -- normal growth is bounded
/// by the cache budget and asserted directly above. It is the gap between a
/// healthy run (743.8 MiB peak measured on macos-15) and the 54.8 GB the
/// pre-fix server reached when work escaped cancellation.
fn rss_ceiling_bytes(baseline: u64) -> u64 {
    let over_mib: u64 = std::env::var("RF_CACHE_RSS_CEILING_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2048);
    baseline + over_mib * 1024 * 1024
}
