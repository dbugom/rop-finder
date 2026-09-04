//! The cancellable scan pipeline the MCP server runs.
//!
//! MCP-03's fix needs a [`CancelToken`] to reach the engine's hot loops,
//! and [`rf_api::scan_bytes`] cannot carry one: it routes an unbudgeted
//! request through `rf_scan::scan_binary`, which resets the token.
//! [`rf_api::scan_bytes_cancellable`] is the twin that can, and this module
//! is now only the mapping from its failure onto the MCP wire error.
//!
//! It used to be more than that. Until v1.0 the option mapping —
//! `ScanRequest` field by `ScanOptions` field — existed **twice**, here and
//! in `rf-cli`, because the CLI's copy was private and hard-coded
//! `CancelToken::never()`. That duplication was guarded rather than
//! trusted: `scan_matches_the_cli_pipeline` scans four request shapes both
//! ways and requires bit-identical gadget lists. ENG-08's extraction of
//! `rf-api` deleted the copy, and the test stays — it now proves that the
//! bounded and the unbounded entry point agree, which is the property that
//! actually mattered.

use rf_api::{ScanBudget, ScanFailure};
use rf_scan::CancelToken;

use crate::schema::ErrorCode;
use crate::ToolError;

/// Everything [`rf_api::ScanOutcome`] carries that the MCP surface uses.
///
/// Defined in `rf-api` and re-exported here so the tool handlers keep
/// naming it `scan::ScanProduct`.
pub use rf_api::ScanProduct;

/// How a cancellable scan failed.
pub enum ScanFail {
    /// The request could not be turned into a scan.
    Cli(rf_api::ScanError),
    /// The engine stopped: cancelled, over budget, or a decode failure.
    Engine(rf_scan::Error),
}

impl From<rf_api::ScanError> for ScanFail {
    fn from(e: rf_api::ScanError) -> Self {
        ScanFail::Cli(e)
    }
}

impl From<ScanFailure> for ScanFail {
    fn from(e: ScanFailure) -> Self {
        match e {
            ScanFailure::Request(e) => ScanFail::Cli(e),
            ScanFailure::Engine(e) => ScanFail::Engine(e),
        }
    }
}

impl ScanFail {
    /// Map onto the wire error. `Cancelled` is its own code, distinct from
    /// `timeout`: the client asked for this one.
    #[must_use]
    pub fn to_tool_error(self) -> ToolError {
        match self {
            ScanFail::Cli(e) => crate::scan_err_to_tool(e),
            ScanFail::Engine(rf_scan::Error::Cancelled) => ToolError::new(
                ErrorCode::Cancelled,
                "the scan was cancelled at the client's request and has stopped",
            ),
            ScanFail::Engine(rf_scan::Error::Budget { produced, limit }) => {
                ToolError::with_details(
                    ErrorCode::ResourceExhausted,
                    format!(
                        "the scan exceeded the server's gadget budget after {produced} gadgets                          (limit {limit}); lower depth, or narrow the scan with section/range"
                    ),
                    serde_json::json!({"limit": "max_gadgets",
                                       "limit_value": limit,
                                       "produced": produced}),
                )
            }
            ScanFail::Engine(rf_scan::Error::Core(e)) => {
                ToolError::new(ErrorCode::UnsupportedBinary, e.to_string())
                    .with_kind("binary_error")
            }
        }
    }
}

/// [`rf_api::scan_bytes`] with a [`CancelToken`] threaded into the engine.
///
/// A delegate to [`rf_api::scan_bytes_cancellable`]; the argument shape is
/// kept as the server's handlers already spell it (`cancel` and the two
/// budgets separately) rather than as a [`ScanBudget`].
pub fn scan_bytes_cancellable(
    bytes: &[u8],
    req: &rf_api::ScanRequest,
    cancel: &CancelToken,
    max_gadgets: Option<usize>,
    max_memory: Option<usize>,
) -> Result<ScanProduct, ScanFail> {
    let budget = ScanBudget {
        cancel: cancel.clone(),
        max_gadgets,
        max_memory,
    };
    rf_api::scan_bytes_cancellable(bytes, req, &budget).map_err(ScanFail::from)
}

#[cfg(test)]
mod tests {
    // Panicking on a bad index is the desired behaviour in a test; the
    // crate-level deny exists to keep it out of the server.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn fixture(name: &str) -> Vec<u8> {
        let p =
            PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures")).join(name);
        std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    fn req(depth: usize) -> rf_api::ScanRequest {
        rf_api::ScanRequest {
            depth,
            ..rf_api::ScanRequest::default()
        }
    }

    /// THE GUARD ON THE DUPLICATION. The locally-assembled pipeline must
    /// produce exactly what `rf_api::scan_bytes` produces: same gadgets,
    /// same order, same addr_size, same section table. If `request_options`
    /// gains a field this file does not mirror, this fails.
    #[test]
    fn scan_matches_the_cli_pipeline() {
        let bytes = fixture("elf-Linux-x64");
        let shapes: Vec<rf_api::ScanRequest> = vec![
            req(4),
            rf_api::ScanRequest {
                depth: 6,
                only: Some("pop|ret".to_string()),
                ..req(6)
            },
            rf_api::ScanRequest {
                depth: 5,
                section: vec![".text".to_string()],
                badbytes: Some("0a|0d".to_string()),
                offset: Some("0x1000".to_string()),
                ..req(5)
            },
            rf_api::ScanRequest {
                depth: 8,
                align: Some(4),
                all: true,
                jop: false,
                sys: false,
                ..req(8)
            },
        ];
        let never = CancelToken::never();
        for (n, r) in shapes.iter().enumerate() {
            let want = rf_api::scan_bytes(&bytes, None, r).expect("cli scan");
            let got = scan_bytes_cancellable(&bytes, r, &never, None, None)
                .unwrap_or_else(|_| panic!("shape {n} failed"));
            assert_eq!(
                got.gadgets.len(),
                want.result.gadgets.len(),
                "shape {n}: gadget count"
            );
            let a: Vec<(u64, String)> = got.gadgets.iter().map(|g| (g.vaddr, g.text())).collect();
            let b: Vec<(u64, String)> = want
                .result
                .gadgets
                .iter()
                .map(|g| (g.vaddr, g.text()))
                .collect();
            assert_eq!(a, b, "shape {n}: gadget list diverged from rf_cli");
            assert_eq!(got.addr_size, want.result.addr_size, "shape {n}");
            assert_eq!(
                got.selected_sections.is_some(),
                want.result.selected_sections.is_some(),
                "shape {n}"
            );
            assert_eq!(got.offset, want.opts.offset, "shape {n}");
            assert_eq!(got.fallback_names, want.fallback_names, "shape {n}");
        }
    }

    /// The token reaches the engine: setting it from another thread stops
    /// a scan that would otherwise run for a long time.
    #[test]
    fn a_scan_stops_when_the_token_is_set() {
        let bytes = fixture("elf-x64-bash-v4.1.5.1");
        let cancel = CancelToken::new();
        let started = Arc::new(AtomicBool::new(false));
        let watcher = {
            let cancel = cancel.clone();
            let started = started.clone();
            std::thread::spawn(move || {
                // Give the scan time to be well inside its loops.
                while !started.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                std::thread::sleep(Duration::from_millis(50));
                cancel.cancel();
            })
        };
        let r = req(64);
        started.store(true, Ordering::Relaxed);
        let t0 = Instant::now();
        let out = scan_bytes_cancellable(&bytes, &r, &cancel, None, None);
        let elapsed = t0.elapsed();
        watcher.join().unwrap();
        match out {
            Err(ScanFail::Engine(rf_scan::Error::Cancelled)) => {}
            Err(_) => panic!("wrong error"),
            Ok(_) => panic!("depth-64 bash scan finished before the token was set"),
        }
        assert!(elapsed < Duration::from_secs(20), "{elapsed:?}");
    }

    /// The budget is the other half of the bound: cancellation alone does
    /// not stop a scan that is legitimately huge.
    #[test]
    fn max_gadgets_stops_the_scan_with_resource_exhausted() {
        let bytes = fixture("elf-x64-bash-v4.1.5.1");
        let err = scan_bytes_cancellable(&bytes, &req(10), &CancelToken::never(), Some(100), None)
            .err()
            .expect("budget must trip")
            .to_tool_error();
        assert_eq!(err.code, ErrorCode::ResourceExhausted);
        let d = err.details.expect("details");
        assert_eq!(d["limit"], "max_gadgets");
        assert_eq!(d["limit_value"], 100);
    }

    #[test]
    fn a_cancelled_scan_maps_to_the_cancelled_code() {
        let e = ScanFail::Engine(rf_scan::Error::Cancelled).to_tool_error();
        assert_eq!(e.code, ErrorCode::Cancelled);
        let e = ScanFail::Cli(rf_api::ScanError::Usage("x".into())).to_tool_error();
        assert_eq!(e.code, ErrorCode::UsageError);
    }

    #[test]
    fn depth_below_two_is_a_usage_error() {
        // Asserted through the delegate rather than through the mapping
        // function directly, because there is no longer a second mapping
        // function here to get this wrong.
        let e = scan_bytes_cancellable(&[], &req(1), &CancelToken::never(), None, None)
            .err()
            .expect("depth 1 must be refused");
        assert!(matches!(e, ScanFail::Cli(rf_api::ScanError::Usage(_))));
    }
}
