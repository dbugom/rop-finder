//! MCP-09 — the counters behind `get_server_stats`.
//!
//! Everything an operator needs to answer "is this server healthy, and is
//! something walking my filesystem through it?" without reading the audit
//! log. Four of these exist specifically because of a v0.1/v0.2 finding:
//!
//!   * `wedged_total` — workers that did NOT stop within 5 s of being
//!     cancelled. It is the direct health signal for the MCP-03 fix: if
//!     this is non-zero the cancellation points are not where they need
//!     to be, and the number says so instead of the operator having to
//!     notice 400% CPU.
//!   * `denied_consecutive` / `probing_suspected` — a rising refusal
//!     count is the specific signal that reveals a prompt-injected agent
//!     enumerating paths. Because `get_server_config` TELLS a legitimate
//!     agent the allow roots, a legitimate agent produces zero denials,
//!     so the signal is clean.
//!   * `cache_tamper` — non-zero only when a file in the cache directory
//!     carried a body the cache did not write (MCP-04).
//!   * `cache_bytes` — MCP-05's bound, observable rather than asserted.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use serde_json::{json, Value};

/// How a request ended. One of these is recorded for every tool call, and
/// it is the `verdict` field of the audit line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Ok,
    Denied,
    Timeout,
    Cancelled,
    Error,
}

impl Verdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Denied => "denied",
            Verdict::Timeout => "timeout",
            Verdict::Cancelled => "cancelled",
            Verdict::Error => "error",
        }
    }

    /// Map an error code onto the audit verdict. The mapping is total on
    /// purpose: a new code defaults to `error` rather than vanishing.
    #[must_use]
    pub fn for_code(code: &str) -> Verdict {
        match code {
            "path_denied" => Verdict::Denied,
            "timeout" | "timeout_hard" => Verdict::Timeout,
            "cancelled" => Verdict::Cancelled,
            _ => Verdict::Error,
        }
    }
}

#[derive(Debug, Default)]
pub struct ServerStats {
    /// Calls per tool name, in tool-name order.
    by_tool: Mutex<BTreeMap<String, u64>>,
    pub requests_total: AtomicU64,
    pub ok_total: AtomicU64,
    pub denied_total: AtomicU64,
    /// Consecutive `path_denied` results; reset by any non-denied result.
    pub denied_consecutive: AtomicU64,
    /// High-water mark of the above, so a burst that has since been reset
    /// is still visible.
    pub denied_consecutive_max: AtomicU64,
    pub timeout_total: AtomicU64,
    pub cancelled_total: AtomicU64,
    /// Workers that did not stop within the hard-join window after being
    /// cancelled. The MCP-03 health signal.
    pub wedged_total: AtomicU64,
    pub busy_total: AtomicU64,
    pub error_total: AtomicU64,
    pub bytes_read_total: AtomicU64,
    /// Requests currently holding an inflight permit.
    pub inflight: AtomicU64,
    pub probing_suspected: AtomicBool,
}

impl ServerStats {
    fn tools(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, u64>> {
        self.by_tool.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Count a call to `tool`. Called once, at entry, so a request that
    /// panics is still counted.
    pub fn record_request(&self, tool: &str) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        *self.tools().entry(tool.to_string()).or_insert(0) += 1;
    }

    /// Count the outcome and maintain the consecutive-denial run.
    ///
    /// Returns `true` when the run has reached `probe_threshold`, i.e. the
    /// caller should apply the probing delay and log `probing_suspected`.
    pub fn record_verdict(&self, v: Verdict, probe_threshold: u64) -> bool {
        match v {
            Verdict::Ok => {
                self.ok_total.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Denied => {
                self.denied_total.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Timeout => {
                self.timeout_total.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Cancelled => {
                self.cancelled_total.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Error => {
                self.error_total.fetch_add(1, Ordering::Relaxed);
            }
        }
        let run = if v == Verdict::Denied {
            let n = self.denied_consecutive.fetch_add(1, Ordering::Relaxed) + 1;
            self.denied_consecutive_max.fetch_max(n, Ordering::Relaxed);
            n
        } else {
            // Any other outcome ends the run. A legitimate agent that has
            // read get_server_config never starts one.
            self.denied_consecutive.store(0, Ordering::Relaxed);
            0
        };
        let suspected = probe_threshold > 0 && run >= probe_threshold;
        if suspected {
            self.probing_suspected.store(true, Ordering::Relaxed);
        }
        suspected
    }

    pub fn add_bytes_read(&self, n: u64) {
        self.bytes_read_total.fetch_add(n, Ordering::Relaxed);
    }

    #[must_use]
    pub fn denied_consecutive_now(&self) -> u64 {
        self.denied_consecutive.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn wedged_now(&self) -> u64 {
        self.wedged_total.load(Ordering::Relaxed)
    }

    /// The `get_server_stats` payload. `cache` is supplied by the caller
    /// because the cache is not owned here.
    #[must_use]
    pub fn snapshot(&self, cache: Value) -> Value {
        let load = |a: &AtomicU64| a.load(Ordering::Relaxed);
        let by_tool: BTreeMap<String, u64> = self.tools().clone();
        json!({
            "requests_total": load(&self.requests_total),
            "requests_by_tool": by_tool,
            "ok_total": load(&self.ok_total),
            "denied_total": load(&self.denied_total),
            "denied_consecutive": load(&self.denied_consecutive),
            "denied_consecutive_max": load(&self.denied_consecutive_max),
            "timeout_total": load(&self.timeout_total),
            "cancelled_total": load(&self.cancelled_total),
            "wedged_total": load(&self.wedged_total),
            "busy_total": load(&self.busy_total),
            "error_total": load(&self.error_total),
            "bytes_read_total": load(&self.bytes_read_total),
            "inflight": load(&self.inflight),
            "probing_suspected": self.probing_suspected.load(Ordering::Relaxed),
            "cache": cache,
        })
    }
}

#[cfg(test)]
mod tests {
    // Panicking on a bad index is the desired behaviour in a test; the
    // crate-level deny exists to keep it out of the server.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn verdict_mapping_is_total() {
        assert_eq!(Verdict::for_code("path_denied"), Verdict::Denied);
        assert_eq!(Verdict::for_code("timeout"), Verdict::Timeout);
        assert_eq!(Verdict::for_code("timeout_hard"), Verdict::Timeout);
        assert_eq!(Verdict::for_code("cancelled"), Verdict::Cancelled);
        for other in [
            "usage_error",
            "binary_error",
            "busy",
            "internal",
            "brand_new",
        ] {
            assert_eq!(Verdict::for_code(other), Verdict::Error, "{other}");
        }
    }

    /// MCP-09: N consecutive denials trip the probing signal, and ONE
    /// legitimate call clears the run. `get_server_config` tells an agent
    /// the roots, so a legitimate agent never starts a run at all.
    #[test]
    fn consecutive_denials_trip_the_probe_signal_and_a_success_clears_it() {
        let s = ServerStats::default();
        for i in 1..20 {
            assert!(!s.record_verdict(Verdict::Denied, 20), "tripped at {i}");
        }
        assert!(s.record_verdict(Verdict::Denied, 20), "20th denial trips");
        assert_eq!(s.denied_consecutive_now(), 20);
        assert!(s.probing_suspected.load(Ordering::Relaxed));

        // A real result ends the run...
        assert!(!s.record_verdict(Verdict::Ok, 20));
        assert_eq!(s.denied_consecutive_now(), 0);
        // ...but the high-water mark and the session flag are sticky, so
        // an operator reading stats later still sees what happened.
        assert_eq!(s.denied_consecutive_max.load(Ordering::Relaxed), 20);
        assert!(s.probing_suspected.load(Ordering::Relaxed));
        assert_eq!(s.denied_total.load(Ordering::Relaxed), 20);
    }

    #[test]
    fn a_timeout_also_ends_the_denial_run() {
        let s = ServerStats::default();
        s.record_verdict(Verdict::Denied, 3);
        s.record_verdict(Verdict::Denied, 3);
        assert_eq!(s.denied_consecutive_now(), 2);
        s.record_verdict(Verdict::Timeout, 3);
        assert_eq!(s.denied_consecutive_now(), 0);
        assert_eq!(s.timeout_total.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn threshold_zero_disables_the_signal() {
        let s = ServerStats::default();
        for _ in 0..100 {
            assert!(!s.record_verdict(Verdict::Denied, 0));
        }
        assert!(!s.probing_suspected.load(Ordering::Relaxed));
    }

    #[test]
    fn snapshot_carries_every_documented_counter() {
        let s = ServerStats::default();
        s.record_request("find_gadgets");
        s.record_request("find_gadgets");
        s.record_request("get_binary_info");
        s.record_verdict(Verdict::Ok, 20);
        s.add_bytes_read(4096);
        let v = s.snapshot(json!({"bytes": 0}));
        for key in [
            "requests_total",
            "requests_by_tool",
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
            assert!(v.get(key).is_some(), "missing {key} in {v}");
        }
        assert_eq!(v["requests_total"], 3);
        assert_eq!(v["requests_by_tool"]["find_gadgets"], 2);
        assert_eq!(v["requests_by_tool"]["get_binary_info"], 1);
        assert_eq!(v["bytes_read_total"], 4096);
    }
}
