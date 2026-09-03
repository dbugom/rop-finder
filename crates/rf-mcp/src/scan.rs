//! The cancellable scan pipeline the MCP server runs.
//!
//! MCP-03's fix needs a [`CancelToken`] to reach the engine's hot loops.
//! `rf_cli::scan_bytes` cannot carry one: its private `request_options`
//! hard-codes `cancel: CancelToken::never()` (rf-cli/src/lib.rs:1186) and
//! `run_scan_engine` routes an unbudgeted request through
//! `rf_scan::scan_binary`, which explicitly resets the token. So this
//! module assembles the same pipeline out of rf-cli's *public* parts —
//! [`rf_cli::load_target`], [`rf_cli::prepare_view`] and its `parse_*`
//! helpers — and finishes with [`rf_scan::scan_bounded`], which is one of
//! the two entry points that observe the token.
//!
//! The duplication is the option mapping and nothing else, and it is
//! guarded rather than trusted: `scan_matches_the_cli_pipeline` scans four
//! request shapes both ways and requires bit-identical gadget lists, so a
//! future change to `request_options` that this file does not mirror fails
//! a test instead of silently giving the MCP server a different scan from
//! the CLI's. When rf-cli grows the `scan_bytes_cancellable` mirror that
//! MCP-DESIGN fix #4 part C specifies, [`scan_bytes_cancellable`] here
//! becomes a one-line delegate and the mapping below is deleted.

use rf_core::Image;
use rf_scan::{CancelToken, ScanOptions};

use crate::schema::ErrorCode;
use crate::ToolError;

/// Everything `rf_cli::ScanOutcome` carries that the MCP surface uses.
pub struct ScanProduct {
    pub gadgets: Vec<rf_scan::Gadget>,
    pub addr_size: usize,
    pub universal_arch: Option<rf_core::Arch>,
    pub selected_sections: Option<Vec<rf_cli::SectionEntry>>,
    pub fallback_names: bool,
    /// `--offset`, needed to map a gadget address back to its section.
    pub offset: u64,
}

/// Build [`ScanOptions`] for `req` with `cancel` and the server's budget
/// wired in.
///
/// A mirror of `rf_cli::request_options`, which is private. Keep the field
/// order identical to that function so a diff between the two is readable.
pub fn scan_options(
    req: &rf_cli::ScanRequest,
    cancel: &CancelToken,
    max_gadgets: Option<usize>,
    max_memory: Option<usize>,
) -> Result<ScanOptions, rf_cli::ScanError> {
    if req.depth < 2 {
        return Err(rf_cli::ScanError::Usage("--depth must be >= 2".to_string()));
    }
    let usage = rf_cli::ScanError::Usage;
    Ok(ScanOptions {
        depth: req.depth,
        rop: req.rop,
        jop: req.jop,
        sys: req.sys,
        multibr: req.multibr,
        only: req
            .only
            .as_deref()
            .map(|s| s.split('|').map(|x| x.to_string()).collect()),
        range: match &req.range {
            Some(r) => rf_cli::parse_range(r).map_err(usage)?,
            None => None,
        },
        badbytes: match &req.badbytes {
            Some(b) => rf_cli::parse_badbytes(b).map_err(usage)?,
            None => Vec::new(),
        },
        filter: req
            .filter
            .as_deref()
            .map(|s| s.split('|').map(|x| x.to_string()).collect())
            .unwrap_or_default(),
        offset: match &req.offset {
            Some(o) => rf_cli::parse_hex(o, "--offset").map_err(usage)?,
            None => 0,
        },
        thumb: req.thumb,
        cfg_aware: req.cfg_aware,
        align: req.align,
        call_preceded: req.call_preceded,
        all: req.all,
        noinstr: req.noinstr,
        parallel: true,
        // rf-scan rejoins the `--filter` parts and compiles ROPgadget's
        // anchored `({...})$` itself, so there is nothing to pre-compile.
        filter_re: None,
        // The three fields that make this file exist.
        cancel: cancel.clone(),
        max_gadgets: max_gadgets.or(req.max_gadgets),
        max_memory: max_memory.or(req.max_memory),
    })
}

/// How a cancellable scan failed.
pub enum ScanFail {
    Cli(rf_cli::ScanError),
    Engine(rf_scan::Error),
}

impl From<rf_cli::ScanError> for ScanFail {
    fn from(e: rf_cli::ScanError) -> Self {
        ScanFail::Cli(e)
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
                        "the scan exceeded the server's gadget budget after {produced} gadgets \
                         (limit {limit}); lower depth, or narrow the scan with section/range"
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

/// `rf_cli::scan_bytes` with a [`CancelToken`] threaded into the engine.
pub fn scan_bytes_cancellable(
    bytes: &[u8],
    req: &rf_cli::ScanRequest,
    cancel: &CancelToken,
    max_gadgets: Option<usize>,
    max_memory: Option<usize>,
) -> Result<ScanProduct, ScanFail> {
    let opts = scan_options(req, cancel, max_gadgets, max_memory)?;
    let target = rf_cli::load_target(bytes, None)?;
    let base = req
        .base
        .as_deref()
        .map(|b| rf_cli::parse_hex(b, "--base"))
        .transpose()
        .map_err(rf_cli::ScanError::Usage)?;
    let prepared =
        rf_cli::prepare_view(&target, base, &req.section, req.arch.as_deref(), req.compat)?;
    let view = prepared.view;
    let universal_arch = view.universal.then(|| Image::arch(&view));
    let gadgets = rf_scan::scan_bounded(&view, &opts).map_err(ScanFail::Engine)?;
    Ok(ScanProduct {
        gadgets,
        addr_size: view.addr_size(),
        universal_arch,
        selected_sections: prepared.selected_sections,
        fallback_names: prepared.fallback_names,
        offset: opts.offset,
    })
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

    fn req(depth: usize) -> rf_cli::ScanRequest {
        rf_cli::ScanRequest {
            depth,
            ..rf_cli::ScanRequest::default()
        }
    }

    /// THE GUARD ON THE DUPLICATION. The locally-assembled pipeline must
    /// produce exactly what `rf_cli::scan_bytes` produces: same gadgets,
    /// same order, same addr_size, same section table. If `request_options`
    /// gains a field this file does not mirror, this fails.
    #[test]
    fn scan_matches_the_cli_pipeline() {
        let bytes = fixture("elf-Linux-x64");
        let shapes: Vec<rf_cli::ScanRequest> = vec![
            req(4),
            rf_cli::ScanRequest {
                depth: 6,
                only: Some("pop|ret".to_string()),
                ..req(6)
            },
            rf_cli::ScanRequest {
                depth: 5,
                section: vec![".text".to_string()],
                badbytes: Some("0a|0d".to_string()),
                offset: Some("0x1000".to_string()),
                ..req(5)
            },
            rf_cli::ScanRequest {
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
            let want = rf_cli::scan_bytes(&bytes, None, r).expect("cli scan");
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
        let e = ScanFail::Cli(rf_cli::ScanError::Usage("x".into())).to_tool_error();
        assert_eq!(e.code, ErrorCode::UsageError);
    }

    #[test]
    fn depth_below_two_is_a_usage_error() {
        let e = scan_options(&req(1), &CancelToken::never(), None, None).unwrap_err();
        assert!(matches!(e, rf_cli::ScanError::Usage(_)));
    }
}
