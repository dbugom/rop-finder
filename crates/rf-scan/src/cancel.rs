//! Cooperative cancellation and the scan-time resource budget.
//!
//! A [`CancelToken`] is a shared flag the caller can set from any thread; the
//! scanner polls it inside the loops it already runs (the anchor-hit loop
//! every 1024 hits, the depth loop every 256 candidates, the work-item
//! dispatcher before each item, and [`crate::post_process`] on entry and
//! before the sort). Polling is a relaxed atomic load, so the cost is a
//! single uncontended read per few hundred candidates.
//!
//! The point of the token is bounded *residual* cost: after a cancel, what
//! remains is at most one partially-scanned work item plus one relaxed load
//! per remaining item — not the contents of those items.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A shared "stop now" flag. Cheap to clone; every clone observes the same
/// flag.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A fresh, un-cancelled token.
    pub fn new() -> Self {
        CancelToken(Arc::new(AtomicBool::new(false)))
    }

    /// A token that can never be cancelled. Semantically identical to
    /// [`CancelToken::new`]; it exists so callers that do not want
    /// cancellation say so at the call site (and so the delegating
    /// [`crate::scan_binary`] reads honestly).
    pub fn never() -> Self {
        CancelToken::new()
    }

    /// Request cancellation. Idempotent, callable from any thread.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Has cancellation been requested?
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// `Err(Error::Cancelled)` if cancellation was requested.
    pub fn check(&self) -> Result<(), Error> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Failure of a cancellable / budgeted scan.
///
/// Distinct from [`rf_core::Error`] on purpose: loading a binary and running
/// out of a caller-imposed budget are different kinds of event, and the MCP
/// server has to tell a client which one happened. `Core` carries the
/// loader/decoder errors unchanged.
#[derive(Debug)]
pub enum Error {
    /// The [`CancelToken`] was set while the scan was running.
    Cancelled,
    /// `ScanOptions::max_gadgets` or `max_memory` was exceeded. `produced`
    /// is what had been accepted when the limit was hit; `limit` is the
    /// limit that tripped (gadgets or bytes — see the message).
    Budget {
        /// Gadgets accepted before the limit tripped.
        produced: usize,
        /// The limit that tripped — gadgets or bytes, see the message.
        limit: usize,
    },
    /// A loader or decoder error from rf-core.
    Core(rf_core::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Cancelled => write!(f, "scan cancelled"),
            Error::Budget { produced, limit } => {
                write!(
                    f,
                    "scan budget exceeded after {produced} gadgets (limit {limit})"
                )
            }
            Error::Core(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

/// `rf_core::Error` is neither `Clone` nor `PartialEq`, so the `Core` arm is
/// compared by rendered message. Only tests rely on this.
impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Error::Cancelled, Error::Cancelled) => true,
            (
                Error::Budget {
                    produced: a,
                    limit: b,
                },
                Error::Budget {
                    produced: c,
                    limit: d,
                },
            ) => a == c && b == d,
            (Error::Core(a), Error::Core(b)) => a.to_string() == b.to_string(),
            _ => false,
        }
    }
}

impl From<rf_core::Error> for Error {
    fn from(e: rf_core::Error) -> Self {
        Error::Core(e)
    }
}

impl From<Error> for rf_core::Error {
    /// Lossy on purpose: the infallible-by-construction entry points
    /// ([`crate::scan_binary`]) keep their `rf_core::Error` signature, and a
    /// `Cancelled`/`Budget` cannot reach them (they pass
    /// [`CancelToken::never`] and no limits).
    fn from(e: Error) -> Self {
        match e {
            Error::Core(e) => e,
            other => rf_core::Error::Unsupported(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_shared_across_clones_and_threads() {
        let t = CancelToken::new();
        assert!(!t.is_cancelled());
        assert!(t.check().is_ok());
        let t2 = t.clone();
        std::thread::spawn(move || t2.cancel()).join().unwrap();
        assert!(t.is_cancelled());
        assert_eq!(t.check(), Err(Error::Cancelled));
    }

    #[test]
    fn never_token_stays_unset() {
        let t = CancelToken::never();
        assert!(!t.is_cancelled());
    }
}
