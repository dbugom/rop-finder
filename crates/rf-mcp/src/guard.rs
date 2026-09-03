//! MCP-03/PERF-06 — the one place a request's work is bounded.
//!
//! The bug this replaces was small and total: `tokio::time::timeout`
//! wrapped `spawn_blocking`, so it abandoned the **await** and never the
//! **work**, and the closure had no cancellation point to abandon it at.
//! Measured against the live server: a `depth=u64::MAX` request with
//! `timeout_secs=2` returned a tidy timeout error at t=2.00 s and the
//! process then held 395-400% CPU indefinitely; a `depth=100000` request
//! the client had already cancelled via `notifications/cancelled` reached
//! 54,873 MB RSS thirteen seconds later, and no response ever arrived.
//!
//! Three ad-hoc timeout blocks became [`Guard::run`]. What it does, in the
//! order that matters:
//!
//! 1. **Acquire a permit** from a `tokio::sync::Semaphore` sized by
//!    `--max-concurrent`.
//! 2. **Create a [`CancelToken`]** — v0.2's engine token, with real check
//!    points in the anchor-hit and depth loops.
//! 3. **Bridge the MCP cancellation notification** to it in a spawned
//!    task, so `notifications/cancelled` — which the server accepted and
//!    ignored — finally does something.
//! 4. `select!` between the join handle and a sleep.
//! 5. On timeout: set the token, **and then JOIN the handle** rather than
//!    abandoning it.
//!
//! Step 5 is the load-bearing one. Awaiting the join after cancelling is
//! what makes the semaphore a bound on concurrent *work* rather than on
//! outstanding *awaits*: the permit is released only once the worker has
//! really stopped. Without it, a timed-out request frees a slot while its
//! orphaned worker keeps burning a core — which is exactly the measured
//! 398% runaway. If the join does not complete within
//! [`HARD_JOIN`], `wedged_total` is incremented and the caller gets a
//! distinct `timeout_hard`, because at that point the server is lying if
//! it claims the work stopped.
//!
//! Every scan also runs inside an explicit rayon pool sized by
//! `--scan-threads` (default `num_cpus - 1`), so the server cannot consume
//! every core on the operator's machine.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use rf_scan::CancelToken;
use serde_json::json;

use crate::schema::ErrorCode;
use crate::stats::ServerStats;
use crate::ToolError;

/// How long [`Guard::run`] waits for a cancelled worker to actually stop
/// before declaring it wedged.
pub const HARD_JOIN: Duration = Duration::from_secs(5);

/// Default `--scan-threads` fallback when the platform will not report a
/// core count.
pub const FALLBACK_SCAN_THREADS: usize = 2;

/// A future that resolves when the client cancels the request.
///
/// Boxed rather than typed so this module does not have to name
/// `tokio_util::sync::CancellationToken` (and so the crate does not have
/// to depend on `tokio-util` to spell rmcp's `RequestContext::ct`).
pub type CancelSignal = Pin<Box<dyn Future<Output = ()> + Send>>;

/// `--scan-threads` default: one fewer than the machine's parallelism, so
/// an operator running the server next to their own work keeps a core.
#[must_use]
pub fn default_scan_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(1).max(1))
        .unwrap_or(FALLBACK_SCAN_THREADS)
}

/// Concurrency bound + cancellation + the scan thread pool.
#[derive(Debug)]
pub struct Guard {
    inflight: Arc<tokio::sync::Semaphore>,
    pool: Arc<rayon::ThreadPool>,
    max_concurrent: usize,
    stats: Arc<ServerStats>,
}

impl Guard {
    pub fn new(
        max_concurrent: usize,
        scan_threads: usize,
        stats: Arc<ServerStats>,
    ) -> Result<Self, String> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(scan_threads.max(1))
            .thread_name(|i| format!("rf-scan-{i}"))
            .build()
            .map_err(|e| format!("cannot build the scan thread pool: {e}"))?;
        let permits = max_concurrent.max(1);
        Ok(Guard {
            inflight: Arc::new(tokio::sync::Semaphore::new(permits)),
            pool: Arc::new(pool),
            max_concurrent: permits,
            stats,
        })
    }

    /// Threads in the scan pool (`--scan-threads`).
    #[must_use]
    pub fn scan_threads(&self) -> usize {
        self.pool.current_num_threads()
    }

    /// Acquire an inflight permit, waiting at most `timeout`.
    ///
    /// The wait is capped so a queued request fails fast with `busy`
    /// instead of hanging behind a scan that has its own budget.
    async fn permit(
        &self,
        timeout: Duration,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ToolError> {
        match tokio::time::timeout(timeout, self.inflight.clone().acquire_owned()).await {
            Ok(Ok(p)) => Ok(p),
            Ok(Err(_)) => Err(ToolError::new(
                ErrorCode::Internal,
                "server is shutting down",
            )),
            Err(_) => {
                self.stats.busy_total.fetch_add(1, Ordering::Relaxed);
                Err(ToolError::with_details(
                    ErrorCode::ResourceExhausted,
                    format!(
                        "all {} concurrent scan slots are in use; retry, or start the server \
                         with a larger --max-concurrent",
                        self.max_concurrent
                    ),
                    json!({"limit": "max_concurrent", "limit_value": self.max_concurrent}),
                )
                .with_kind("busy")
                .retryable(true))
            }
        }
    }

    /// Run `f` on a blocking worker inside the scan pool, bounded by
    /// `timeout` and cancellable both by that timeout and by `cancel`
    /// (the client's `notifications/cancelled`).
    pub async fn run<T, F>(
        &self,
        cancel: Option<CancelSignal>,
        timeout: Duration,
        f: F,
    ) -> Result<T, ToolError>
    where
        T: Send + 'static,
        F: FnOnce(CancelToken) -> Result<T, ToolError> + Send + 'static,
    {
        let permit = self.permit(timeout).await?;
        self.stats.inflight.fetch_add(1, Ordering::Relaxed);
        let token = CancelToken::new();

        // The bridge is why `notifications/cancelled` stops meaning
        // nothing: rmcp cancels `RequestContext::ct`, and this hands that
        // through to the engine token the scan loops poll.
        let bridge = cancel.map(|signal| {
            let t = token.clone();
            tokio::spawn(async move {
                signal.await;
                t.cancel();
            })
        });

        let worker_token = token.clone();
        let pool = self.pool.clone();
        let mut handle = tokio::task::spawn_blocking(move || pool.install(move || f(worker_token)));

        let out = tokio::select! {
            joined = &mut handle => match joined {
                Ok(v) => v,
                Err(e) => Err(ToolError::new(
                    ErrorCode::Internal,
                    format!("worker failed: {e}"),
                )),
            },
            () = tokio::time::sleep(timeout) => {
                token.cancel();
                // JOIN, do not abandon. The permit below is released only
                // after this returns, so --max-concurrent bounds work and
                // not merely outstanding awaits.
                match tokio::time::timeout(HARD_JOIN, handle).await {
                    Ok(_) => Err(ToolError::with_details(
                        ErrorCode::Timeout,
                        format!(
                            "the request exceeded its {} s timeout and the scan was stopped",
                            timeout.as_secs()
                        ),
                        json!({"limit": "timeout_secs", "limit_value": timeout.as_secs()}),
                    )),
                    Err(_) => {
                        self.stats.wedged_total.fetch_add(1, Ordering::Relaxed);
                        Err(ToolError::with_details(
                            ErrorCode::Timeout,
                            format!(
                                "the request exceeded its {} s timeout and the worker did not \
                                 stop within {} s of being cancelled; the server is degraded \
                                 (see get_server_stats.wedged_total)",
                                timeout.as_secs(),
                                HARD_JOIN.as_secs()
                            ),
                            json!({"limit": "timeout_secs",
                                   "limit_value": timeout.as_secs(),
                                   "hard_join_secs": HARD_JOIN.as_secs()}),
                        )
                        .with_kind("timeout_hard"))
                    }
                }
            }
        };

        if let Some(b) = bridge {
            b.abort();
        }
        self.stats.inflight.fetch_sub(1, Ordering::Relaxed);
        drop(permit);
        out
    }
}

#[cfg(test)]
mod tests {
    // Panicking on a bad index is the desired behaviour in a test; the
    // crate-level deny exists to keep it out of the server.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    fn guard(max_concurrent: usize) -> (Guard, Arc<ServerStats>) {
        let stats = Arc::new(ServerStats::default());
        (Guard::new(max_concurrent, 2, stats.clone()).unwrap(), stats)
    }

    /// A worker that polls the token the way the engine does.
    fn spin_until_cancelled(
        seen: Arc<AtomicUsize>,
    ) -> impl FnOnce(CancelToken) -> Result<u32, ToolError> {
        move |t: CancelToken| {
            while !t.is_cancelled() {
                seen.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(ToolError::new(ErrorCode::Cancelled, "stopped"))
        }
    }

    #[tokio::test]
    async fn the_happy_path_returns_the_workers_value() {
        let (g, _s) = guard(2);
        let v = g
            .run(None, Duration::from_secs(5), |_t| Ok(41 + 1))
            .await
            .unwrap();
        assert_eq!(v, 42);
    }

    /// MCP-03/PERF-06: the timeout SETS the token and JOINS.
    ///
    /// The worker here takes 300 ms to wind down after it notices the
    /// token — which is what a real scan does, since the cancellation
    /// checks are strided and the last work item still has to unwind. The
    /// assertion is that `run` has NOT returned until that is over. Delete
    /// the join and this fails: the caller is told the request stopped
    /// while the worker is still on a core.
    #[tokio::test]
    async fn a_timeout_cancels_the_worker_and_waits_for_it() {
        let (g, _s) = guard(2);
        let seen = Arc::new(AtomicUsize::new(0));
        let finished = Arc::new(AtomicUsize::new(0));
        let started = Instant::now();
        let err = g
            .run(None, Duration::from_millis(200), {
                let seen = seen.clone();
                let finished = finished.clone();
                move |t: CancelToken| {
                    while !t.is_cancelled() {
                        seen.fetch_add(1, Ordering::Relaxed);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    std::thread::sleep(Duration::from_millis(300));
                    finished.fetch_add(1, Ordering::SeqCst);
                    Err::<u32, _>(ToolError::new(ErrorCode::Cancelled, "stopped"))
                }
            })
            .await
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Timeout);
        assert_eq!(err.kind, "timeout");
        assert!(seen.load(Ordering::Relaxed) > 0, "the worker never ran");
        assert_eq!(
            finished.load(Ordering::SeqCst),
            1,
            "run() returned while the worker was still winding down"
        );
        assert!(started.elapsed() < HARD_JOIN, "{:?}", started.elapsed());
    }

    /// The permit is released only after the worker stops, so
    /// `--max-concurrent` is a bound on WORK. With one permit and a worker
    /// that ignores its timeout for 300 ms, the second request cannot
    /// start before the first has finished.
    #[tokio::test]
    async fn the_permit_outlives_the_timeout_not_the_await() {
        let (g, _s) = guard(1);
        let g = Arc::new(g);
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..3 {
            let g = g.clone();
            let running = running.clone();
            let peak = peak.clone();
            tasks.push(tokio::spawn(async move {
                let _ = g
                    .run(None, Duration::from_millis(120), move |t: CancelToken| {
                        let n = running.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(n, Ordering::SeqCst);
                        while !t.is_cancelled() {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        // Winding down still counts as running: this is
                        // the window a released-too-early permit lets the
                        // next worker overlap into.
                        std::thread::sleep(Duration::from_millis(300));
                        running.fetch_sub(1, Ordering::SeqCst);
                        Err::<u8, _>(ToolError::new(ErrorCode::Cancelled, "stopped"))
                    })
                    .await;
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), 1, "workers overlapped");
        assert_eq!(running.load(Ordering::SeqCst), 0);
    }

    /// A worker that never observes the token is reported as `timeout_hard`
    /// and counted in `wedged_total`, rather than being silently
    /// abandoned while the caller is told everything is fine.
    #[tokio::test]
    async fn an_unstoppable_worker_is_reported_wedged() {
        let (g, stats) = guard(2);
        let err = g
            .run(None, Duration::from_millis(50), |_t: CancelToken| {
                std::thread::sleep(HARD_JOIN + Duration::from_millis(500));
                Ok(0u8)
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind, "timeout_hard");
        assert!(err.is_hard_timeout(), "{err:?}");
        assert_eq!(stats.wedged_now(), 1);
        let d = err.details.expect("structured details");
        assert_eq!(d["hard_join_secs"], HARD_JOIN.as_secs());
    }

    /// The cancellation bridge: an external signal reaches the engine
    /// token. This is `notifications/cancelled` with rmcp's plumbing
    /// removed.
    #[tokio::test]
    async fn an_external_cancel_signal_reaches_the_worker() {
        let (g, _s) = guard(2);
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let signal: CancelSignal = Box::pin(async move {
            let _ = rx.await;
        });
        let seen = Arc::new(AtomicUsize::new(0));
        let handle = tokio::spawn({
            let seen = seen.clone();
            let g = Arc::new(g);
            async move {
                g.run(
                    Some(signal),
                    Duration::from_secs(30),
                    spin_until_cancelled(seen),
                )
                .await
            }
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
        tx.send(()).unwrap();
        let started = Instant::now();
        let err = tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .expect("run() must return promptly after cancellation")
            .unwrap()
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(seen.load(Ordering::Relaxed) > 0, "worker never ran");
    }

    /// All permits busy: a queued request fails fast with `busy` rather
    /// than hanging.
    #[tokio::test]
    async fn a_queued_request_fails_fast_with_busy() {
        let (g, stats) = guard(1);
        let g = Arc::new(g);
        let hold = {
            let g = g.clone();
            tokio::spawn(async move {
                g.run(None, Duration::from_millis(400), |t: CancelToken| {
                    while !t.is_cancelled() {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err::<u8, _>(ToolError::new(ErrorCode::Cancelled, "stopped"))
                })
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(60)).await;
        let err = g
            .run(None, Duration::from_millis(50), |_t| Ok(1u8))
            .await
            .unwrap_err();
        assert_eq!(err.kind, "busy");
        assert!(err.retryable, "a busy server is worth retrying: {err:?}");
        assert_eq!(stats.busy_total.load(Ordering::Relaxed), 1);
        let _ = hold.await;
    }

    #[test]
    fn the_scan_pool_is_sized_and_never_zero() {
        let (g, _s) = guard(2);
        assert_eq!(g.scan_threads(), 2);
        let stats = Arc::new(ServerStats::default());
        let g = Guard::new(1, 0, stats).unwrap();
        assert!(g.scan_threads() >= 1);
        assert!(default_scan_threads() >= 1);
    }
}
