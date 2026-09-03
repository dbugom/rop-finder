//! MCP resources: a whole scan as a file an agent can grep.
//!
//! The MIPS fixture has 40,872 JOP gadgets. No agent can hold that in
//! context, and paging 1,000 at a time through 41 calls is barely better.
//! Agents are much better served by being handed a file they can grep with
//! their own tools, so any scan that had to be paged also names
//! `ropfinder://scan/<cache_key>/gadgets.ndjson`, one
//! [`crate::schema::GadgetRecord`] per line, readable with `resources/read`.
//!
//! **What the resource contains, precisely.** The *whole* gadget set of that
//! scan, in the default `rank` order, with NO semantic filter and no `--re`
//! applied — so its content depends only on `cache_key`, which already folds
//! in the file's SHA-256 and every scan parameter. That is deliberate: a
//! resource whose bytes changed depending on which request last touched it
//! would be a trap, and an agent that has a whole-scan file can apply its own
//! predicate with `grep` far more flexibly than the `class`/`label` filters
//! allow. It follows that the line count is the scan's total, which is
//! `total_count` only when the response carried no filter.
//!
//! With `--workspace-dir` the same NDJSON is written to a real file whose
//! path is returned, next to a `.schema.json` describing a line. The
//! directory must lie OUTSIDE every allow root — otherwise the agent could
//! read the server's own output back through `binary_path`, and worse, seed
//! it.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use rf_cache::CachedScan;

use crate::schema::GadgetRecord;
use crate::semantics::{sort_indices, Order, Semantics};

/// URI scheme + prefix for a scan's NDJSON.
pub const SCAN_URI_PREFIX: &str = "ropfinder://scan/";
/// Suffix of a scan NDJSON URI.
pub const SCAN_URI_SUFFIX: &str = "/gadgets.ndjson";
/// MIME type reported for the resource.
pub const NDJSON_MIME: &str = "application/x-ndjson";

/// The URI for a cached scan.
#[must_use]
pub fn scan_uri(cache_key: &str) -> String {
    format!("{SCAN_URI_PREFIX}{cache_key}{SCAN_URI_SUFFIX}")
}

/// The cache key named by a `ropfinder://scan/<key>/gadgets.ndjson` URI.
///
/// Returns `None` for anything else, and for a key that is not the
/// hexadecimal `rf_cache` produces — the key is used as a FILE NAME under
/// `--workspace-dir`, so a URI carrying `..` or a separator must never get
/// that far.
#[must_use]
pub fn cache_key_of(uri: &str) -> Option<&str> {
    let key = uri
        .strip_prefix(SCAN_URI_PREFIX)?
        .strip_suffix(SCAN_URI_SUFFIX)?;
    // `rf_cache::make_key` produces `v<schema>-<64 hex>--<64 hex>`, which is
    // 133 characters; the cap is generous but finite because the key
    // becomes a FILE NAME under --workspace-dir.
    let ok = !key.is_empty()
        && key.len() <= 200
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    ok.then_some(key)
}

/// Render the whole scan as NDJSON in the default `rank` order.
#[must_use]
pub fn render_ndjson(scan: &CachedScan, sems: &[Semantics]) -> String {
    let mut idx: Vec<usize> = (0..scan.gadgets.len()).collect();
    sort_indices(&mut idx, Order::Rank, scan, sems);
    let mut out = String::with_capacity(idx.len() * 256);
    for i in idx {
        let (Some(g), Some(s)) = (scan.gadgets.get(i), sems.get(i)) else {
            continue;
        };
        let rec = GadgetRecord::build(g, s);
        // A record of owned scalars and strings cannot fail to serialize.
        if let Ok(line) = serde_json::to_string(&rec) {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// JSON Schema of one NDJSON line, written beside the file so an agent can
/// see the shape without calling `tools/list`.
#[must_use]
pub fn line_schema_json() -> String {
    let schema = rmcp::handler::server::common::schema_for_output::<GadgetRecord>();
    serde_json::to_string_pretty(schema.as_ref()).unwrap_or_else(|_| "{}".to_string())
}

/// The workspace file for a scan, rendering it only if it is not there.
///
/// A cache key names an immutable result, so an existing file is already
/// the right bytes. Rendering the MIPS fixture's 40,872 records costs about
/// 12 MB of string building; doing it on every page of a walk would make
/// pagination slower than not paging at all.
pub fn ensure_file<F: FnOnce() -> String>(
    dir: &Path,
    cache_key: &str,
    render: F,
) -> Option<PathBuf> {
    let path = dir.join(format!("{cache_key}.ndjson"));
    if path.is_file() {
        return Some(path);
    }
    materialize(dir, cache_key, &render())
}

/// Materialize the NDJSON under `--workspace-dir`, returning the path.
///
/// Failure is not an error for the request: the response simply carries
/// `workspace_file: null` and the resource URI still works. An agent that
/// cannot get a file falls back to paging; a scan that fails because a disk
/// filled up would be worse.
pub fn materialize(dir: &Path, cache_key: &str, ndjson: &str) -> Option<PathBuf> {
    std::fs::create_dir_all(dir).ok()?;
    let path = dir.join(format!("{cache_key}.ndjson"));
    write_atomic(&path, ndjson.as_bytes())?;
    let schema = dir.join(format!("{cache_key}.schema.json"));
    if !schema.exists() {
        write_atomic(&schema, line_schema_json().as_bytes());
    }
    Some(path)
}

/// Write via a temporary file and rename, so a reader never sees a
/// half-written NDJSON.
fn write_atomic(path: &Path, bytes: &[u8]) -> Option<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp).ok()?;
        f.write_all(bytes).ok()?;
        f.sync_all().ok()?;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Some(()),
        Err(_) => {
            // Windows refuses a rename onto an existing file.
            let _ = std::fs::remove_file(path);
            let r = std::fs::rename(&tmp, path).ok();
            let _ = std::fs::remove_file(&tmp);
            r
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use rf_cache::CachedGadget;

    const SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn scan() -> CachedScan {
        CachedScan {
            gadgets: vec![
                CachedGadget {
                    vaddr: "0x401660".into(),
                    bytes: "c3".into(),
                    text: "ret".into(),
                    ..CachedGadget::default()
                },
                CachedGadget {
                    vaddr: "0x401648".into(),
                    bytes: "5fc3".into(),
                    text: "pop rdi ; ret".into(),
                    ..CachedGadget::default()
                },
            ],
            ..CachedScan::default()
        }
    }

    /// A URI is only ever a cache key, and a cache key is only ever
    /// `[A-Za-z0-9-]`. It becomes a FILE NAME under --workspace-dir, so a
    /// traversal attempt must be rejected at the parse, not at the join.
    #[test]
    fn only_a_real_cache_key_parses_out_of_a_uri() {
        assert_eq!(
            cache_key_of("ropfinder://scan/abc123/gadgets.ndjson"),
            Some("abc123")
        );
        for bad in [
            "ropfinder://scan/../../etc/passwd/gadgets.ndjson",
            "ropfinder://scan//gadgets.ndjson",
            "ropfinder://scan/a b/gadgets.ndjson",
            "ropfinder://scan/a/b/gadgets.ndjson",
            r"ropfinder://scan/a\b/gadgets.ndjson",
            "ropfinder://scan/abc123/other.ndjson",
            "file:///etc/passwd",
            "ropfinder://scan/abc123",
        ] {
            assert_eq!(cache_key_of(bad), None, "{bad} must not parse");
        }
        assert_eq!(cache_key_of(&scan_uri("deadbeef")), Some("deadbeef"));
    }

    /// One record per line, ranked, and every line is a complete
    /// `GadgetRecord` — that is the whole contract an agent greps against.
    #[test]
    fn ndjson_is_one_ranked_record_per_line() {
        let sc = scan();
        let sems = crate::semantics::classify_scan(&sc, SHA, 0, Some(rf_core::Arch::X64));
        let out = render_ndjson(&sc, &sems);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        let first: GadgetRecord = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first.text, "pop rdi ; ret", "rank order, not file order");
        let second: GadgetRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second.text, "ret");
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn materialize_writes_the_file_and_its_schema() {
        let dir = std::env::temp_dir().join(format!("rf-mcp-ws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = materialize(&dir, "k1", "{\"a\":1}\n").expect("written");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"a\":1}\n");
        let schema = dir.join("k1.schema.json");
        assert!(schema.is_file());
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&schema).unwrap()).unwrap();
        assert_eq!(v["type"], "object");
        // Rewriting is idempotent, including on Windows where rename onto
        // an existing file fails.
        assert!(materialize(&dir, "k1", "{\"a\":2}\n").is_some());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"a\":2}\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
