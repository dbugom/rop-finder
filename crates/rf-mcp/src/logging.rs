//! MCP-09 — stderr logs the operator can read, and MCP notifications the
//! operator can actually *see*.
//!
//! Two rules govern everything here.
//!
//! 1. **Nothing may touch stdout.** stdout is the JSON-RPC transport; one
//!    stray `println!` corrupts the session, and there is no error — the
//!    host simply stops understanding the server. The stderr writer is
//!    pinned explicitly rather than left to a default, and
//!    `stdout_is_pure_jsonrpc` is the standing test.
//! 2. **stderr is not enough.** MCP hosts discard the server's stderr, so
//!    warnings that matter to an operator — a tampered cache entry, a
//!    wedged worker, suspected path probing — are also forwarded as
//!    `notifications/message` under the declared `logging` capability.
//!
//! The peer is only available from inside a request, so [`Notifier`] holds
//! a slot for it, buffers a bounded number of messages until the first
//! request registers one, and drops the oldest beyond that. A log that
//! grows without bound to describe a server whose bug was growing without
//! bound would be a poor joke.

// rmcp deprecated the whole `logging` capability in 2.0 (SEP-2577) while
// still implementing it, and it remains the only channel that reaches an
// MCP operator. The alternative is stderr, which hosts discard — that is
// the finding. Confined to this module so nothing else silently uses a
// deprecated API.
#![allow(deprecated)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, PoisonError};

use rmcp::model::{LoggingLevel, LoggingMessageNotificationParam};
use rmcp::{Peer, RoleServer};
use serde_json::{json, Value};

/// Messages buffered before a peer exists. Small on purpose: the operator
/// wants the recent ones, and this is a diagnostic channel, not a queue.
const MAX_PENDING: usize = 64;

/// Install the process-wide stderr subscriber.
///
/// Level comes from `RUST_LOG`, defaulting to `warn`. Idempotent: a second
/// call (a test spawning the library in-process) is a no-op rather than a
/// panic.
pub fn init_tracing(default_directives: &str) {
    use tracing_subscriber::filter::EnvFilter;
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directives));
    let _ = tracing_subscriber::fmt()
        // The load-bearing line in this file.
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(false)
        .try_init();
}

fn level_rank(l: LoggingLevel) -> u8 {
    match l {
        LoggingLevel::Debug => 0,
        LoggingLevel::Info => 1,
        LoggingLevel::Notice => 2,
        LoggingLevel::Warning => 3,
        LoggingLevel::Error => 4,
        LoggingLevel::Critical => 5,
        LoggingLevel::Alert => 6,
        LoggingLevel::Emergency => 7,
    }
}

/// Forwards warn/error events to the MCP client as `notifications/message`.
#[derive(Debug, Default)]
pub struct Notifier {
    peer: Mutex<Option<Peer<RoleServer>>>,
    pending: Mutex<VecDeque<LoggingMessageNotificationParam>>,
    /// Minimum level to forward; raised or lowered by `logging/setLevel`.
    min: AtomicU8,
    /// Everything ever handed to [`Notifier::emit`], for tests and for the
    /// shutdown summary.
    emitted: std::sync::atomic::AtomicU64,
}

impl Notifier {
    #[must_use]
    pub fn new() -> Self {
        Notifier {
            min: AtomicU8::new(level_rank(LoggingLevel::Warning)),
            ..Notifier::default()
        }
    }

    /// Remember the peer (idempotent, cheap) and flush anything buffered
    /// before it existed.
    pub fn register(&self, peer: &Peer<RoleServer>) {
        {
            let mut slot = self.peer.lock().unwrap_or_else(PoisonError::into_inner);
            if slot.is_some() {
                return;
            }
            *slot = Some(peer.clone());
        }
        let backlog: Vec<LoggingMessageNotificationParam> = {
            let mut q = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            q.drain(..).collect()
        };
        for p in backlog {
            self.send(p);
        }
    }

    /// `logging/setLevel`.
    pub fn set_level(&self, level: LoggingLevel) {
        self.min.store(level_rank(level), Ordering::Relaxed);
    }

    #[must_use]
    pub fn emitted(&self) -> u64 {
        self.emitted.load(Ordering::Relaxed)
    }

    /// Log to stderr AND forward to the operator.
    ///
    /// `data` is structured, never free text with a path interpolated into
    /// it: the host renders it as JSON and an incident responder greps it.
    pub fn notify(&self, level: LoggingLevel, code: &str, message: &str, data: Value) {
        let detail = data.to_string();
        match level {
            LoggingLevel::Error
            | LoggingLevel::Critical
            | LoggingLevel::Alert
            | LoggingLevel::Emergency => tracing::error!(code, detail, "{message}"),
            LoggingLevel::Warning => tracing::warn!(code, detail, "{message}"),
            _ => tracing::info!(code, detail, "{message}"),
        }
        let payload = json!({"code": code, "message": message, "detail": data});
        if level_rank(level) < self.min.load(Ordering::Relaxed) {
            return;
        }
        self.emitted.fetch_add(1, Ordering::Relaxed);
        let param =
            LoggingMessageNotificationParam::new(level, payload).with_logger("rop-finder-mcp");
        let have_peer = self
            .peer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some();
        if have_peer {
            self.send(param);
        } else {
            let mut q = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            if q.len() >= MAX_PENDING {
                q.pop_front();
            }
            q.push_back(param);
        }
    }

    pub fn warn(&self, code: &str, message: &str, data: Value) {
        self.notify(LoggingLevel::Warning, code, message, data);
    }

    pub fn error(&self, code: &str, message: &str, data: Value) {
        self.notify(LoggingLevel::Error, code, message, data);
    }

    fn send(&self, param: LoggingMessageNotificationParam) {
        let peer = {
            let slot = self.peer.lock().unwrap_or_else(PoisonError::into_inner);
            match slot.as_ref() {
                None => return,
                Some(p) => p.clone(),
            }
        };
        // Fire and forget: a notification the client will not accept must
        // never block, and must never take the request with it.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = peer.notify_logging_message(param).await {
                    tracing::debug!(error = %e, "logging notification not delivered");
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    // Panicking on a bad index is the desired behaviour in a test; the
    // crate-level deny exists to keep it out of the server.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    #[test]
    fn levels_are_ordered_and_warning_is_the_default_floor() {
        assert!(level_rank(LoggingLevel::Debug) < level_rank(LoggingLevel::Warning));
        assert!(level_rank(LoggingLevel::Warning) < level_rank(LoggingLevel::Error));
        let n = Notifier::new();
        assert_eq!(
            n.min.load(Ordering::Relaxed),
            level_rank(LoggingLevel::Warning)
        );
    }

    /// With no peer yet, messages buffer — and the buffer is bounded, so a
    /// server nobody ever calls does not grow a log in memory.
    #[test]
    fn messages_buffer_until_a_peer_exists_and_the_buffer_is_bounded() {
        let n = Notifier::new();
        for i in 0..(MAX_PENDING + 50) {
            n.warn("probe", "suspected probing", json!({"i": i}));
        }
        let q = n.pending.lock().unwrap();
        assert_eq!(q.len(), MAX_PENDING);
        // The OLDEST were dropped: the newest message is still there.
        let last = q.back().unwrap();
        assert_eq!(last.data["detail"]["i"], (MAX_PENDING + 49) as u64);
        assert_eq!(n.emitted(), (MAX_PENDING + 50) as u64);
    }

    /// `logging/setLevel` raises the floor: an info event stops being
    /// forwarded, an error still is.
    #[test]
    fn set_level_gates_what_is_forwarded() {
        let n = Notifier::new();
        n.notify(LoggingLevel::Info, "c", "m", json!({}));
        assert_eq!(n.emitted(), 0, "info is below the warning floor");
        n.set_level(LoggingLevel::Error);
        n.warn("c", "m", json!({}));
        assert_eq!(n.emitted(), 0, "warning is below an error floor");
        n.error("c", "m", json!({}));
        assert_eq!(n.emitted(), 1);
        n.set_level(LoggingLevel::Debug);
        n.notify(LoggingLevel::Info, "c", "m", json!({}));
        assert_eq!(n.emitted(), 2);
    }

    #[test]
    fn the_payload_is_structured_not_prose() {
        let n = Notifier::new();
        n.warn("path_probing", "20 consecutive denials", json!({"n": 20}));
        let q = n.pending.lock().unwrap();
        let p = q.back().unwrap();
        assert_eq!(p.level, LoggingLevel::Warning);
        assert_eq!(p.data["code"], "path_probing");
        assert_eq!(p.data["detail"]["n"], 20);
        assert_eq!(p.logger.as_deref(), Some("rop-finder-mcp"));
    }
}
