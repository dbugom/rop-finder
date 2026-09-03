//! MCP-05/ROB-07 — the server's two-level scan cache, both levels bounded.
//!
//! The in-memory half used to be `Mutex<HashMap<String, Arc<CachedScan>>>`
//! with exactly `get` and `put`: no capacity, no TTL, no eviction.
//! Measured on the live server, twelve depth-varying scans of one 900 KB
//! binary walked RSS from 5 MB to 84 MB monotonically with
//! `max_results: 1` on every call — the response cap does not bound
//! retention — and one depth-40 scan pinned 2.57 GB for the life of the
//! process.
//!
//! It is now [`rf_cache::MemCache`], a byte-weighted LRU with a TTL, and
//! it lives in rf-cache rather than here so the CLI shares the same bound
//! (CLI-08/PERF-12 is the same finding on the other front end).
//!
//! The on-disk half is v0.2's [`rf_cache::DiskCache`] unchanged: HMAC over
//! `key || 0x00 || body` with a per-directory random key, 0600 entries in
//! a 0700 directory, `create_new` + rename for atomicity, and a size cap.
//! An entry that does not authenticate is a miss plus a counter, never a
//! result.
//!
//! A third store lives here as well, and it is not a duplicate of the first
//! two: the **pinned-scan store**. A cursor (MCP-DESIGN fix #8 part B)
//! names a result set that must still be there when the next page is asked
//! for, and the semantic records the filters and the `rank` order run over
//! ([`crate::semantics::Semantics`]) are derived from a scan rather than
//! stored in it — recomputing them costs a full reclassification of the
//! gadget list. So each completed scan is pinned with its semantics for
//! `--cursor-ttl-secs`, and the store is bounded exactly like the other
//! two: by bytes (the same `--cache-mem-mb` budget, with an over-budget
//! entry refused outright), by age (`min(--cursor-ttl-secs,
//! --cache-ttl-secs)`, so a cursor can never outlive the operator's
//! freshness policy), and by eviction of the least recently used.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rf_cache::{CachedScan, MemCache, MemLimits};
use serde_json::{json, Value};

use crate::semantics::Semantics;

/// Default `--cursor-ttl-secs`: how long a scan stays pinned so an
/// outstanding cursor can page it.
pub const DEFAULT_CURSOR_TTL: Duration = Duration::from_secs(300);

/// A scan held open for an outstanding cursor, with the semantics derived
/// from it.
struct Pinned {
    key: String,
    scan: Arc<CachedScan>,
    sems: Arc<Vec<Semantics>>,
    bytes: usize,
    touched: Instant,
}

/// A pinned scan handed back to a request.
#[derive(Clone)]
pub struct PinnedScan {
    pub scan: Arc<CachedScan>,
    pub sems: Arc<Vec<Semantics>>,
}

/// Bounded store of pinned scans. Not an LRU cache of convenience: it is
/// what makes a cursor's next page cheap and what stops the semantics from
/// being recomputed on every page of a 40,872-gadget walk.
struct Pins {
    entries: Mutex<Vec<Pinned>>,
    max_bytes: u64,
    ttl: Duration,
}

impl Pins {
    fn get(&self, key: &str) -> Option<PinnedScan> {
        let mut e = self.entries.lock().ok()?;
        self.expire(&mut e);
        let p = e.iter_mut().find(|p| p.key == key)?;
        p.touched = Instant::now();
        Some(PinnedScan {
            scan: p.scan.clone(),
            sems: p.sems.clone(),
        })
    }

    fn put(&self, key: &str, scan: Arc<CachedScan>, sems: Arc<Vec<Semantics>>) {
        let bytes =
            sems.iter().map(Semantics::heap_bytes).sum::<usize>() + rf_cache::SCAN_OVERHEAD_BYTES;
        let Ok(mut e) = self.entries.lock() else {
            return;
        };
        // An entry that cannot fit the whole budget is NOT pinned. ROB-07's
        // 2.57 GB single scan is exactly this case, and a pin that ignored
        // the budget would hand it straight back. The cost is that paging
        // such a scan under a tiny --cache-mem-mb re-scans per page, which
        // is the operator's choice to make.
        self.expire(&mut e);
        e.retain(|p| p.key != key);
        if bytes as u64 > self.max_bytes {
            return;
        }
        e.push(Pinned {
            key: key.to_string(),
            scan,
            sems,
            bytes,
            touched: Instant::now(),
        });
        // Evict least-recently-touched first until under budget.
        while !e.is_empty() && self.total(&e) > self.max_bytes {
            if let Some(i) = Self::coldest(&e) {
                e.remove(i);
            } else {
                break;
            }
        }
    }

    fn expire(&self, e: &mut Vec<Pinned>) {
        let ttl = self.ttl;
        e.retain(|p| p.touched.elapsed() < ttl);
    }

    fn coldest(e: &[Pinned]) -> Option<usize> {
        e.iter()
            .enumerate()
            .min_by_key(|(_, p)| p.touched)
            .map(|(i, _)| i)
    }

    fn total(&self, e: &[Pinned]) -> u64 {
        e.iter().map(|p| p.bytes as u64).sum()
    }

    fn stats(&self) -> (u64, u64) {
        match self.entries.lock() {
            Ok(e) => (e.len() as u64, self.total(&e)),
            Err(_) => (0, 0),
        }
    }

    fn keys(&self) -> Vec<(String, u64)> {
        match self.entries.lock() {
            Ok(e) => e
                .iter()
                .map(|p| (p.key.clone(), p.scan.gadgets.len() as u64))
                .collect(),
            Err(_) => Vec::new(),
        }
    }
}

/// Both halves of the cache, plus the pinned-scan store.
pub struct Cache {
    mem: MemCache,
    /// `None` when `--cache-dir` was not given, and also when the
    /// directory could not be trusted: MCP-04 means an untrustworthy cache
    /// is *disabled*, never downgraded to unauthenticated reads.
    disk: Option<rf_cache::DiskCache>,
    pins: Pins,
}

impl Default for Cache {
    fn default() -> Self {
        Cache::new(None, MemLimits::default(), DEFAULT_CURSOR_TTL)
    }
}

impl Cache {
    /// `cursor_ttl` only ever SHORTENS how long a scan stays pinned: the
    /// effective pin lifetime is `min(cursor_ttl, mem_limits.ttl)`, because
    /// `--cache-ttl-secs` is the operator's statement about how long a scan
    /// result may be served at all and a cursor must not outlive it.
    #[must_use]
    pub fn new(dir: Option<PathBuf>, mem_limits: MemLimits, cursor_ttl: Duration) -> Self {
        let disk = dir.and_then(|dir| {
            match rf_cache::DiskCache::open(&dir, rf_cache::CacheLimits::from_env()) {
                Ok(c) => Some(c),
                Err(e) => {
                    // stderr via tracing, never stdout: stdout is the
                    // JSON-RPC transport.
                    tracing::warn!(error = %e, "on-disk cache disabled");
                    None
                }
            }
        });
        Cache {
            mem: MemCache::new(mem_limits),
            disk,
            pins: Pins {
                entries: Mutex::new(Vec::new()),
                max_bytes: mem_limits.max_bytes,
                ttl: cursor_ttl.min(mem_limits.ttl),
            },
        }
    }

    /// A scan pinned for an outstanding cursor, with its semantics.
    #[must_use]
    pub fn pinned(&self, key: &str) -> Option<PinnedScan> {
        self.pins.get(key)
    }

    /// Pin a completed scan and its semantics for the cursor window.
    pub fn pin(&self, key: &str, scan: Arc<CachedScan>, sems: Arc<Vec<Semantics>>) {
        self.pins.put(key, scan, sems);
    }

    /// The pinned scans, as `(cache_key, gadget_count)` — exactly the set
    /// `resources/list` can serve.
    #[must_use]
    pub fn pinned_keys(&self) -> Vec<(String, u64)> {
        self.pins.keys()
    }

    pub fn get(&self, key: &str) -> Option<Arc<CachedScan>> {
        if let Some(hit) = self.mem.get(key) {
            return Some(hit);
        }
        // `load` authenticates the entry against the directory's key and
        // validates every record before it returns: a tampered or corrupt
        // entry is a warning plus a counter plus a miss (MCP-04, ROB-04).
        let scan = Arc::new(self.disk.as_ref()?.load(key)?);
        self.mem.put_arc(key, scan.clone());
        Some(scan)
    }

    pub fn put(&self, key: &str, scan: CachedScan) -> Arc<CachedScan> {
        let scan = self.mem.put(key, scan);
        if let Some(disk) = &self.disk {
            if let Err(e) = disk.store(key, &scan) {
                tracing::warn!(error = %e, "cache entry not written");
            }
        }
        scan
    }

    /// Retained bytes in the memory half — MCP-05's bound, observable.
    #[must_use]
    pub fn mem_bytes(&self) -> u64 {
        self.mem.bytes()
    }

    #[must_use]
    pub fn mem_stats(&self) -> rf_cache::MemStats {
        self.mem.stats()
    }

    /// Integrity and eviction counters for the on-disk half; `None` when
    /// there is no on-disk half.
    #[must_use]
    pub fn disk_stats(&self) -> Option<rf_cache::CacheStats> {
        self.disk.as_ref().map(rf_cache::DiskCache::stats)
    }

    /// The `cache` object inside `get_server_stats` (MCP-09).
    #[must_use]
    pub fn stats_json(&self) -> Value {
        let m = self.mem.stats();
        let limits = self.mem.limits();
        let (pinned_entries, pinned_bytes) = self.pins.stats();
        let disk = match self.disk_stats() {
            None => Value::Null,
            Some(d) => json!({
                "hits": d.hits,
                "misses": d.misses,
                "tamper": d.tampered,
                "malformed": d.malformed,
                "expired": d.expired,
                "stored": d.stored,
                "store_errors": d.store_errors,
                "evictions": d.evicted,
                "evicted_bytes": d.evicted_bytes,
            }),
        };
        json!({
            "hits": m.hits,
            "misses": m.misses,
            "entries": m.entries,
            "cache_bytes": m.bytes,
            "cache_mem_max_bytes": limits.max_bytes,
            "cache_ttl_secs": limits.ttl.as_secs(),
            "evictions": m.evicted,
            "evicted_bytes": m.evicted_bytes,
            "expired": m.expired,
            "too_large": m.too_large,
            // The pinned-scan store (MCP-DESIGN fix #8 part B), bounded by
            // the same byte budget and by --cursor-ttl-secs.
            "pinned_entries": pinned_entries,
            "pinned_bytes": pinned_bytes,
            "cursor_ttl_secs": self.pins.ttl.as_secs(),
            // The on-disk half's counters, `tamper` included: non-zero
            // only when a file in the cache directory carried a body the
            // cache did not write.
            "disk": disk,
        })
    }
}

#[cfg(test)]
mod tests {
    // Panicking on a bad index is the desired behaviour in a test; the
    // crate-level deny exists to keep it out of the server.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use rf_cache::CachedGadget;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let raw = std::env::temp_dir().join(format!(
                "rf-mcp-cache-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&raw);
            std::fs::create_dir_all(&raw).unwrap();
            TempDir(raw.canonicalize().unwrap())
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scan_of(n: usize) -> CachedScan {
        CachedScan {
            gadgets: (0..n)
                .map(|i| CachedGadget {
                    vaddr: format!("0x{i:08x}"),
                    bytes: "5fc3".into(),
                    text: "pop rdi ; ret".into(),
                    ..CachedGadget::default()
                })
                .collect(),
            ..CachedScan::default()
        }
    }

    fn one_ret() -> CachedScan {
        scan_of(1)
    }

    #[test]
    fn cache_roundtrip_mem_and_disk() {
        let t = TempDir::new("roundtrip");
        let cache = Cache::new(Some(t.0.clone()), MemLimits::default(), DEFAULT_CURSOR_TTL);
        cache.put("k1", one_ret());
        assert_eq!(cache.get("k1").unwrap().gadgets.len(), 1);
        assert!(t.0.join("k1.rfc").is_file());
        let cold = Cache::new(Some(t.0.clone()), MemLimits::default(), DEFAULT_CURSOR_TTL);
        assert!(cold.get("k1").is_some());
        assert!(cold.get("absent").is_none());
        assert_eq!(cold.disk_stats().unwrap().tampered, 0);
    }

    /// MCP-05/ROB-07 through the server's own wrapper: forty distinct
    /// scans against a 64 MiB budget leave `cache_bytes` under it.
    #[test]
    fn the_memory_half_is_bounded() {
        let budget = 64 * 1024 * 1024;
        let cache = Cache::new(
            None,
            MemLimits {
                max_bytes: budget,
                ..MemLimits::default()
            },
            DEFAULT_CURSOR_TTL,
        );
        for i in 0..40 {
            // ~2 MiB per entry: 40 of them is ~80 MiB, over the budget.
            cache.put(&format!("k{i}"), scan_of(28_000));
            assert!(
                cache.mem_bytes() <= budget,
                "over budget at {i}: {}",
                cache.mem_bytes()
            );
        }
        let s = cache.mem_stats();
        assert!(s.evicted > 0, "nothing was ever evicted: {s:?}");
        let j = cache.stats_json();
        assert!(j["cache_bytes"].as_u64().unwrap() <= budget);
        assert_eq!(j["cache_mem_max_bytes"], budget);
        assert_eq!(j["disk"], Value::Null);
    }

    /// MCP-DESIGN fix #8B: an outstanding cursor pins its scan, and the pin
    /// is bounded on both axes.
    ///
    /// Three claims, none of which the paging tests can isolate because a
    /// 28-page walk finishes long before anything is under pressure:
    ///
    /// 1. A pinned scan survives eviction from the memory half. That is the
    ///    entire reason the pin store exists — without it, page 2 of a walk
    ///    whose scan has aged out either rescans the binary or answers
    ///    `cursor_expired`, and the cursor stops being a cursor.
    /// 2. The pin expires with `--cursor-ttl-secs`. Without this half a
    ///    single cursored request retains its scan for the life of the
    ///    process, which is ROB-07 wearing a different hat.
    /// 3. A scan larger than the whole budget is refused *outright* rather
    ///    than pinned and then evicted. Both routes leave it unpinned, so
    ///    ROB-07's 2.57 GB scan cannot re-enter through the store that was
    ///    added to defeat eviction — but only the early refusal leaves the
    ///    pins that were already there alone. Evicting toward a target that
    ///    can never be met empties the store, so one oversized request would
    ///    invalidate every *other* agent's outstanding cursor. That is the
    ///    claim the third block below pins down.
    #[test]
    fn a_pin_survives_eviction_and_is_bounded_in_time_and_size() {
        let sems_of = |s: &CachedScan| Arc::new(crate::semantics::classify_scan(s, "00", 0, None));

        // 1. Survives eviction.
        let cache = Cache::new(
            None,
            MemLimits {
                max_bytes: 1024 * 1024,
                ..MemLimits::default()
            },
            DEFAULT_CURSOR_TTL,
        );
        let paged = scan_of(500);
        let arc = cache.put("cursored", paged.clone());
        cache.pin("cursored", arc, sems_of(&paged));
        assert!(cache.get("cursored").is_some(), "not even cached");
        for i in 0..200 {
            cache.put(&format!("other{i}"), scan_of(500));
        }
        assert!(
            cache.get("cursored").is_none(),
            "the memory half never evicted, so this proves nothing about the pin"
        );
        let p = cache
            .pinned("cursored")
            .expect("an outstanding cursor must outlive memory-cache eviction");
        assert_eq!(p.scan.gadgets.len(), 500);
        // The semantics ride along, which is what stops a 28-page walk from
        // re-classifying the whole set once per page.
        assert_eq!(p.sems.len(), 500);
        assert_eq!(cache.pinned_keys(), vec![("cursored".to_string(), 500)]);

        // 2. Expires with the cursor TTL.
        let expired = Cache::new(None, MemLimits::default(), Duration::ZERO);
        let small = scan_of(4);
        expired.pin("k", Arc::new(small.clone()), sems_of(&small));
        assert!(expired.pinned("k").is_none(), "a pin outlived its TTL");
        assert!(expired.pinned_keys().is_empty());

        // 3. An over-budget scan is refused without disturbing the pins
        //    that are already there. The budget is derived from the small
        //    scan's own measured size rather than guessed, so the test
        //    cannot drift when `heap_bytes` changes.
        let bytes_of = |s: &Arc<Vec<Semantics>>| {
            s.iter().map(Semantics::heap_bytes).sum::<usize>() + rf_cache::SCAN_OVERHEAD_BYTES
        };
        let small = scan_of(4);
        let small_sems = sems_of(&small);
        let big = scan_of(64);
        let big_sems = sems_of(&big);
        let budget = bytes_of(&small_sems) as u64;
        assert!(
            bytes_of(&big_sems) as u64 > budget,
            "the oversized scan has to be oversized for this to test anything"
        );
        let tiny = Cache::new(
            None,
            MemLimits {
                max_bytes: budget,
                ..MemLimits::default()
            },
            DEFAULT_CURSOR_TTL,
        );
        tiny.pin("small", Arc::new(small.clone()), small_sems);
        assert!(
            tiny.pinned("small").is_some(),
            "a scan that exactly fits the budget was not pinned"
        );
        tiny.pin("big", Arc::new(big.clone()), big_sems);
        assert!(
            tiny.pinned("big").is_none(),
            "a scan larger than the budget was pinned anyway"
        );
        assert!(
            tiny.pinned("small").is_some(),
            "an over-budget pin attempt evicted an outstanding cursor's pin: \
             eviction toward an unreachable target empties the store"
        );
    }

    #[test]
    fn stats_json_carries_the_documented_keys() {
        let t = TempDir::new("stats");
        let cache = Cache::new(Some(t.0.clone()), MemLimits::default(), DEFAULT_CURSOR_TTL);
        cache.put("k", one_ret());
        assert!(cache.get("k").is_some());
        let j = cache.stats_json();
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
            assert!(j.get(key).is_some(), "missing {key} in {j}");
        }
        for key in ["hits", "misses", "tamper", "evictions"] {
            assert!(j["disk"].get(key).is_some(), "missing disk.{key} in {j}");
        }
    }
}
