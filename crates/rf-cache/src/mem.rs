//! The in-memory half of the scan cache: a byte-weighted LRU with a TTL.
//!
//! MCP-05/ROB-07. The MCP server's memory cache was
//! `Mutex<HashMap<String, Arc<CachedScan>>>` with exactly two operations,
//! `get` and `put`. No capacity, no eviction, no TTL. Measured on the live
//! server: twelve depth-varying scans of one 900 KB binary walked RSS from
//! 5 MB to 84 MB *monotonically* while every request carried
//! `max_results: 1` — which is the point, because the *response* cap bounds
//! what is sent, never what is retained. One depth-40 scan pinned 2.57 GB
//! for the life of the process.
//!
//! Three properties make this a bound rather than a hint:
//!
//!   * **Weighted by bytes, not entries.** A cap of "1000 entries" means
//!     nothing when one entry is 2.57 GB. The weight is
//!     [`CachedScan::heap_bytes`], the retained size of the record, and
//!     eviction runs until the total is under budget.
//!   * **Evicted on insert, not on a timer.** There is no background task
//!     to fail to start; the budget is restored by the operation that
//!     breached it.
//!   * **An entry larger than the whole budget is never stored.** Storing
//!     it would evict everything else and still be over, so it is counted
//!     (`too_large`) and dropped.
//!
//! Recency is a monotonic sequence number in a `BTreeMap`, so the least
//! recently used entry is the first key in O(log n) and no intrusive
//! linked list (and no `unsafe`) is needed.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::record::CachedScan;

/// Default `--cache-mem-mb`, in bytes (512 MiB).
pub const DEFAULT_MEM_MAX_BYTES: u64 = 512 * 1024 * 1024;
/// Default `--cache-ttl-secs` (24 h).
pub const DEFAULT_MEM_TTL: Duration = Duration::from_secs(86_400);

/// Budget for [`MemCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemLimits {
    /// Total retained bytes across all entries.
    pub max_bytes: u64,
    /// An entry older than this is a miss and is dropped on sight.
    pub ttl: Duration,
}

impl Default for MemLimits {
    fn default() -> Self {
        MemLimits {
            max_bytes: DEFAULT_MEM_MAX_BYTES,
            ttl: DEFAULT_MEM_TTL,
        }
    }
}

/// Counters for `get_server_stats` (MCP-09).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemStats {
    pub hits: u64,
    pub misses: u64,
    /// Entries dropped because they were older than the TTL.
    pub expired: u64,
    pub inserted: u64,
    /// Entries dropped to stay under `max_bytes`.
    pub evicted: u64,
    pub evicted_bytes: u64,
    /// Entries never stored because one of them exceeds the whole budget.
    pub too_large: u64,
    /// Live values, filled in by [`MemCache::stats`].
    pub entries: u64,
    pub bytes: u64,
}

#[derive(Debug)]
struct Entry {
    scan: Arc<CachedScan>,
    bytes: u64,
    created_unix: u64,
    /// Recency key into [`Inner::order`].
    seq: u64,
}

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<String, Entry>,
    /// `seq -> key`, ascending: the first entry is the least recently used.
    order: BTreeMap<u64, String>,
    next_seq: u64,
    bytes: u64,
    stats: MemStats,
}

/// Byte-weighted, TTL'd LRU over [`CachedScan`] values.
///
/// Shared by the MCP server and the CLI so the bound is written once —
/// the duplication of this cache is what MCP-05 and CLI-08 have in common.
#[derive(Debug)]
pub struct MemCache {
    limits: MemLimits,
    inner: Mutex<Inner>,
}

impl Default for MemCache {
    fn default() -> Self {
        MemCache::new(MemLimits::default())
    }
}

/// Seconds since the epoch, saturating rather than panicking on a clock
/// that predates it.
#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl MemCache {
    #[must_use]
    pub fn new(limits: MemLimits) -> Self {
        MemCache {
            limits,
            inner: Mutex::new(Inner::default()),
        }
    }

    #[must_use]
    pub fn limits(&self) -> MemLimits {
        self.limits
    }

    /// A panic anywhere else must not disable the cache for the rest of the
    /// session: every operation below is a single consistent update, so
    /// recovering a poisoned guard cannot expose a half-applied insert.
    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Look up `key`, refreshing its recency. An entry older than the TTL
    /// is removed and reported as a miss.
    pub fn get(&self, key: &str) -> Option<Arc<CachedScan>> {
        let now = now_unix();
        let ttl = self.limits.ttl.as_secs();
        let mut g = self.inner();
        let found = g.map.get(key).map(|e| {
            (
                e.seq,
                e.scan.clone(),
                now.saturating_sub(e.created_unix) > ttl,
            )
        });
        match found {
            None => {
                g.stats.misses += 1;
                None
            }
            Some((_, _, true)) => {
                g.remove(key);
                g.stats.expired += 1;
                g.stats.misses += 1;
                None
            }
            Some((seq, scan, false)) => {
                let next = g.bump();
                g.order.remove(&seq);
                g.order.insert(next, key.to_string());
                if let Some(e) = g.map.get_mut(key) {
                    e.seq = next;
                }
                g.stats.hits += 1;
                Some(scan)
            }
        }
    }

    /// Insert (or replace) `key`, then evict least-recently-used entries
    /// until the total is within budget.
    ///
    /// Returns the stored value so the caller can use it whether or not it
    /// was retained: an entry bigger than the whole budget is *served* but
    /// not *kept*.
    pub fn put(&self, key: &str, scan: CachedScan) -> Arc<CachedScan> {
        self.put_arc(key, Arc::new(scan))
    }

    /// [`MemCache::put`] for a value the caller already shares.
    pub fn put_arc(&self, key: &str, scan: Arc<CachedScan>) -> Arc<CachedScan> {
        let cost = scan.heap_bytes() as u64;
        let mut g = self.inner();
        g.remove(key);
        if cost > self.limits.max_bytes {
            // Keeping it would evict every other entry and still breach the
            // budget. Serve it; do not retain it.
            g.stats.too_large += 1;
            return scan;
        }
        let seq = g.bump();
        g.order.insert(seq, key.to_string());
        g.bytes += cost;
        g.map.insert(
            key.to_string(),
            Entry {
                scan: scan.clone(),
                bytes: cost,
                created_unix: now_unix(),
                seq,
            },
        );
        g.stats.inserted += 1;
        while g.bytes > self.limits.max_bytes {
            let Some(victim) = g.order.values().next().cloned() else {
                break;
            };
            let freed = g.remove(&victim);
            if freed == 0 {
                break;
            }
            g.stats.evicted += 1;
            g.stats.evicted_bytes += freed;
        }
        scan
    }

    /// Drop every entry older than the TTL. `get` does this lazily; this is
    /// for a caller that wants the bytes back without a lookup.
    pub fn sweep_expired(&self) -> u64 {
        let now = now_unix();
        let ttl = self.limits.ttl.as_secs();
        let mut g = self.inner();
        let stale: Vec<String> = g
            .map
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.created_unix) > ttl)
            .map(|(k, _)| k.clone())
            .collect();
        let mut n = 0;
        for k in stale {
            if g.remove(&k) > 0 {
                g.stats.expired += 1;
                n += 1;
            }
        }
        n
    }

    /// Counters plus the live `entries`/`bytes`.
    #[must_use]
    pub fn stats(&self) -> MemStats {
        let g = self.inner();
        MemStats {
            entries: g.map.len() as u64,
            bytes: g.bytes,
            ..g.stats
        }
    }

    /// Retained bytes right now.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.inner().bytes
    }

    /// Entries retained right now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner().map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        let mut g = self.inner();
        g.map.clear();
        g.order.clear();
        g.bytes = 0;
    }
}

impl Inner {
    fn bump(&mut self) -> u64 {
        self.next_seq += 1;
        self.next_seq
    }

    /// Remove `key`, returning the bytes it was costing (0 if absent).
    fn remove(&mut self, key: &str) -> u64 {
        match self.map.remove(key) {
            None => 0,
            Some(e) => {
                self.order.remove(&e.seq);
                self.bytes = self.bytes.saturating_sub(e.bytes);
                e.bytes
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::CachedGadget;

    /// A scan whose retained size grows linearly in `n`.
    fn scan_of(n: usize) -> CachedScan {
        CachedScan {
            gadgets: (0..n)
                .map(|i| CachedGadget {
                    vaddr: format!("0x{i:08x}"),
                    bytes: "5fc3".to_string(),
                    text: "pop rdi ; ret".to_string(),
                    ..CachedGadget::default()
                })
                .collect(),
            ..CachedScan::default()
        }
    }

    #[test]
    fn heap_bytes_grows_with_the_gadget_count() {
        let fixed = crate::SCAN_OVERHEAD_BYTES;
        let one = scan_of(1).heap_bytes() - fixed;
        // Strictly linear in the gadget count, which is the axis MCP-05's
        // 2.57 GB grew along.
        assert_eq!(scan_of(1000).heap_bytes() - fixed, 1000 * one);
        assert_eq!(scan_of(0).heap_bytes(), fixed);
        // Every gadget costs at least the fixed per-record overhead, so a
        // million tiny gadgets cannot look free.
        assert!(one >= crate::GADGET_OVERHEAD_BYTES, "{one}");
    }

    /// MCP-05: the sequence that walked 5 MB -> 84 MB monotonically now
    /// stops at the budget.
    #[test]
    fn insert_evicts_until_under_budget() {
        let one = scan_of(200).heap_bytes() as u64;
        let cache = MemCache::new(MemLimits {
            max_bytes: one * 3,
            ttl: DEFAULT_MEM_TTL,
        });
        for i in 0..40 {
            cache.put(&format!("k{i}"), scan_of(200));
            assert!(
                cache.bytes() <= one * 3,
                "over budget at {i}: {} > {}",
                cache.bytes(),
                one * 3
            );
        }
        assert_eq!(cache.len(), 3);
        let s = cache.stats();
        assert_eq!(s.inserted, 40);
        assert_eq!(s.evicted, 37);
        assert!(s.evicted_bytes >= 37 * one);
        // ...and it is the LEAST RECENTLY USED that went.
        assert!(cache.get("k39").is_some());
        assert!(cache.get("k0").is_none());
    }

    #[test]
    fn a_hit_refreshes_recency() {
        let one = scan_of(50).heap_bytes() as u64;
        let cache = MemCache::new(MemLimits {
            max_bytes: one * 2,
            ttl: DEFAULT_MEM_TTL,
        });
        cache.put("a", scan_of(50));
        cache.put("b", scan_of(50));
        // Touch `a`, so `b` becomes the eviction victim.
        assert!(cache.get("a").is_some());
        cache.put("c", scan_of(50));
        assert!(cache.get("a").is_some(), "a was refreshed");
        assert!(cache.get("b").is_none(), "b was the LRU");
        assert!(cache.get("c").is_some());
    }

    /// ROB-07: one depth-40 scan pinned 2.57 GB. An entry that cannot fit
    /// the budget is served and dropped, never retained.
    #[test]
    fn an_oversized_entry_is_served_but_never_retained() {
        let cache = MemCache::new(MemLimits {
            max_bytes: 1024,
            ttl: DEFAULT_MEM_TTL,
        });
        let out = cache.put("huge", scan_of(1000));
        assert_eq!(out.gadgets.len(), 1000, "still usable by this caller");
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.bytes(), 0);
        assert_eq!(cache.stats().too_large, 1);
        assert!(cache.get("huge").is_none());
    }

    #[test]
    fn an_expired_entry_is_a_miss_and_its_bytes_come_back() {
        let cache = MemCache::new(MemLimits {
            max_bytes: 1 << 30,
            ttl: Duration::from_secs(60),
        });
        cache.put("k", scan_of(20));
        assert!(cache.bytes() > 0);
        // Backdate the entry past the TTL.
        {
            let mut g = cache.inner();
            if let Some(e) = g.map.get_mut("k") {
                e.created_unix = now_unix().saturating_sub(3600);
            }
        }
        assert!(cache.get("k").is_none());
        assert_eq!(cache.bytes(), 0);
        assert_eq!(cache.len(), 0);
        let s = cache.stats();
        assert_eq!(s.expired, 1);
        assert_eq!(s.misses, 1);
    }

    #[test]
    fn replacing_a_key_does_not_double_count_its_bytes() {
        let cache = MemCache::new(MemLimits::default());
        cache.put("k", scan_of(100));
        let first = cache.bytes();
        cache.put("k", scan_of(100));
        assert_eq!(cache.bytes(), first);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn sweep_expired_reclaims_without_a_lookup() {
        let cache = MemCache::new(MemLimits {
            max_bytes: 1 << 30,
            ttl: Duration::from_secs(60),
        });
        for i in 0..5 {
            cache.put(&format!("k{i}"), scan_of(10));
        }
        {
            let mut g = cache.inner();
            for e in g.map.values_mut() {
                e.created_unix = now_unix().saturating_sub(3600);
            }
        }
        assert_eq!(cache.sweep_expired(), 5);
        assert_eq!(cache.bytes(), 0);
        assert!(cache.is_empty());
    }

    #[test]
    fn stats_report_live_entries_and_bytes() {
        let cache = MemCache::new(MemLimits::default());
        assert_eq!(cache.stats(), MemStats::default());
        cache.put("a", scan_of(3));
        let s = cache.stats();
        assert_eq!(s.entries, 1);
        assert_eq!(s.bytes, cache.bytes());
        assert_eq!(s.inserted, 1);
        assert!(cache.get("a").is_some());
        assert_eq!(cache.stats().hits, 1);
        assert!(cache.get("nope").is_none());
        assert_eq!(cache.stats().misses, 1);
    }
}
