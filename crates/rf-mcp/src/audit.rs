//! MCP-09 — the JSONL audit trail.
//!
//! The server's only output before this was one startup line on stderr,
//! which MCP hosts discard. For a tool the project itself classifies as
//! dual-use that is the cheapest missing control: nothing recorded which
//! binaries were scanned, which chains were built, or which paths were
//! refused — and the refusal count is precisely the signal that reveals
//! the filesystem probing the audit demonstrated.
//!
//! One JSON object per line, opened append/create, mode 0600 on Unix,
//! rotated at `--audit-log-max-mb`.
//!
//! What is deliberately *not* in a line:
//!
//!   * **no gadget text and no file bytes.** An audit log that quotes the
//!     tool's output is a second copy of the tool's output, with none of
//!     the access control. `total_count`/`returned` say how much came
//!     back; `binary_sha256` says from what.
//!   * **no OS error strings for a refused path.** The refusal taxonomy
//!     is an existence oracle (MCP-07); the log records the path that was
//!     asked for and the single `path_denied` code, which is what an
//!     incident responder needs.
//!
//! What IS in a line for a denial is the **requested path, verbatim**.
//! That is the whole point of the log: the sequence of paths a
//! prompt-injected agent walked is the evidence.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// Default `--audit-log-max-mb`.
pub const DEFAULT_AUDIT_MAX_MB: u64 = 64;
/// Rotations kept: `<path>.1` and `<path>.2`.
pub const ROTATIONS: u32 = 2;

/// One audit line.
///
/// Every field is filled in by the tool boundary, so a call cannot be
/// half-logged: the record is built up as the request proceeds and written
/// exactly once, in the same place, whatever the outcome.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub req_id: String,
    pub tool: &'static str,
    /// Root-relative label for an allowed path; the REQUESTED path,
    /// verbatim, for a denial.
    pub binary: Option<String>,
    pub binary_sha256: Option<String>,
    pub params_hash: String,
    pub verdict: &'static str,
    pub code: Option<String>,
    pub duration_ms: u64,
    pub total_count: Option<u64>,
    pub returned: Option<u64>,
    pub cache: Option<&'static str>,
    pub bytes_read: u64,
    pub probing_suspected: bool,
}

impl AuditRecord {
    #[must_use]
    pub fn new(req_id: String, tool: &'static str, params_hash: String) -> Self {
        AuditRecord {
            req_id,
            tool,
            binary: None,
            binary_sha256: None,
            params_hash,
            verdict: "error",
            code: None,
            duration_ms: 0,
            total_count: None,
            returned: None,
            cache: None,
            bytes_read: 0,
            probing_suspected: false,
        }
    }

    #[must_use]
    pub fn to_json(&self, session: &str) -> Value {
        json!({
            "ts": rfc3339_millis_utc(SystemTime::now()),
            "session": session,
            "req_id": self.req_id,
            "tool": self.tool,
            "binary": self.binary,
            "binary_sha256": self.binary_sha256,
            "params_hash": self.params_hash,
            "verdict": self.verdict,
            "code": self.code,
            "duration_ms": self.duration_ms,
            "total_count": self.total_count,
            "returned": self.returned,
            "cache": self.cache,
            "bytes_read": self.bytes_read,
            "probing_suspected": self.probing_suspected,
        })
    }
}

/// An open audit log.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    max_bytes: u64,
    session: String,
    /// `None` only after an unrecoverable write failure, which is reported
    /// once and then stops the log rather than the server.
    file: Mutex<Option<File>>,
    written: AtomicU64,
    lines: AtomicU64,
}

impl AuditLog {
    /// Open (creating) `path` for append.
    ///
    /// The caller has already refused a path inside an allow root: the
    /// agent must not be able to read, and through the log's own rotation
    /// influence, the server's record of itself.
    pub fn open(path: &Path, max_mb: u64, session: String) -> std::io::Result<Self> {
        let file = append_private(path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(AuditLog {
            path: path.to_path_buf(),
            max_bytes: max_mb.max(1).saturating_mul(1024 * 1024),
            session,
            file: Mutex::new(Some(file)),
            written: AtomicU64::new(written),
            lines: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lines this process has written. Test and shutdown-summary hook.
    #[must_use]
    pub fn lines_written(&self) -> u64 {
        self.lines.load(Ordering::Relaxed)
    }

    /// Append one record. Failures are logged once to `tracing` and never
    /// propagated: an audit log that cannot be written must not take the
    /// server down, but it must not be silent either.
    pub fn write(&self, rec: &AuditRecord) {
        let mut line = rec.to_json(&self.session).to_string();
        line.push('\n');
        let bytes = line.as_bytes();
        let mut guard = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        if self.written.load(Ordering::Relaxed) + bytes.len() as u64 > self.max_bytes {
            if let Err(e) = self.rotate(&mut guard) {
                tracing::warn!(error = %e, path = %self.path.display(), "audit log rotation failed");
            }
        }
        let Some(f) = guard.as_mut() else { return };
        match f.write_all(bytes).and_then(|()| f.flush()) {
            Ok(()) => {
                self.written
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
                self.lines.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::error!(error = %e, path = %self.path.display(),
                                "audit log write failed; auditing stops for this session");
                *guard = None;
            }
        }
    }

    /// `<path>.1` becomes `<path>.2`, `<path>` becomes `<path>.1`, and a
    /// fresh `<path>` is opened. Renames, so a reader tailing the old
    /// inode sees a complete file.
    fn rotate(&self, guard: &mut Option<File>) -> std::io::Result<()> {
        *guard = None; // close before renaming: Windows will not rename an open file
        for n in (1..=ROTATIONS).rev() {
            let from = if n == 1 {
                self.path.clone()
            } else {
                rotated(&self.path, n - 1)
            };
            let to = rotated(&self.path, n);
            if from.exists() {
                let _ = std::fs::remove_file(&to);
                std::fs::rename(&from, &to)?;
            }
        }
        let f = append_private(&self.path)?;
        self.written.store(0, Ordering::Relaxed);
        *guard = Some(f);
        Ok(())
    }
}

fn rotated(path: &Path, n: u32) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

#[cfg(unix)]
fn append_private(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)?;
    // `mode` only applies at creation; tighten an existing file too, so a
    // log left behind by an earlier, laxer run does not stay world-readable.
    use std::os::unix::fs::PermissionsExt;
    let meta = f.metadata()?;
    if meta.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

#[cfg(not(unix))]
fn append_private(path: &Path) -> std::io::Result<File> {
    // Windows: a file created under the operator's profile inherits that
    // profile's DACL. There is no portable chmod and building a DACL by
    // hand needs the Win32 security APIs; this is the documented
    // best-effort half, exactly as in rf-cache's entry writer.
    OpenOptions::new().append(true).create(true).open(path)
}

/// `2026-09-03T10:11:12.345Z`, computed without a date library.
///
/// The audit line has to be sortable and machine-parseable; pulling in a
/// calendar crate for one format string is not worth the supply-chain
/// edge, and `SystemTime` gives the epoch seconds this needs.
#[must_use]
pub fn rfc3339_millis_utc(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let millis = d.subsec_millis();
    let (y, mo, da) = civil_from_days((secs / 86_400) as i64);
    let sod = secs % 86_400;
    format!(
        "{y:04}-{mo:02}-{da:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Howard Hinnant's `civil_from_days`, the standard branch-free epoch-day
/// to (y, m, d) conversion.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    // Panicking on a bad index is the desired behaviour in a test; the
    // crate-level deny exists to keep it out of the server.
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use std::io::Read;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "rf-mcp-audit-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn rec(tool: &'static str, verdict: &'static str) -> AuditRecord {
        let mut r = AuditRecord::new("7".to_string(), tool, "ph".to_string());
        r.verdict = verdict;
        r
    }

    fn read(p: &Path) -> String {
        let mut s = String::new();
        File::open(p).unwrap().read_to_string(&mut s).unwrap();
        s
    }

    #[test]
    fn every_line_is_one_json_object_with_the_documented_keys() {
        let t = Tmp::new("keys");
        let p = t.0.join("calls.jsonl");
        let log = AuditLog::open(&p, 64, "sess-1".to_string()).unwrap();
        let mut r = rec("find_gadgets", "ok");
        r.binary = Some("elf-Linux-x64".to_string());
        r.binary_sha256 = Some("a".repeat(64));
        r.total_count = Some(2789);
        r.returned = Some(1000);
        r.cache = Some("miss");
        r.bytes_read = 901_234;
        r.duration_ms = 37;
        log.write(&r);
        log.write(&rec("get_binary_info", "denied"));

        let body = read(&p);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "{body}");
        assert_eq!(log.lines_written(), 2);
        for l in &lines {
            let v: Value = serde_json::from_str(l).expect(l);
            for key in [
                "ts",
                "session",
                "req_id",
                "tool",
                "binary",
                "binary_sha256",
                "params_hash",
                "verdict",
                "code",
                "duration_ms",
                "total_count",
                "returned",
                "cache",
                "bytes_read",
                "probing_suspected",
            ] {
                assert!(v.get(key).is_some(), "missing {key} in {l}");
            }
            assert_eq!(v["session"], "sess-1");
        }
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["verdict"], "ok");
        assert_eq!(first["total_count"], 2789);
        assert!(first["ts"].as_str().unwrap().ends_with('Z'));
    }

    /// The denial line carries the REQUESTED path — that is the point of
    /// the log — and no line ever carries gadget text or file bytes.
    #[test]
    fn a_denial_records_the_requested_path_and_nothing_from_the_file() {
        let t = Tmp::new("denial");
        let p = t.0.join("calls.jsonl");
        let log = AuditLog::open(&p, 64, "s".to_string()).unwrap();
        let mut r = rec("find_gadgets", "denied");
        r.binary = Some("/etc/shadow".to_string());
        r.code = Some("path_denied".to_string());
        log.write(&r);
        let body = read(&p);
        assert!(body.contains("/etc/shadow"), "{body}");
        assert!(body.contains("\"verdict\":\"denied\""), "{body}");
        for forbidden in ["pop rdi", "ret", "c3", "\\u00"] {
            // `ret` would appear inside a gadget text; the record has no
            // field that could carry one.
            assert!(
                !body.contains(&format!("\"{forbidden}\"")),
                "{forbidden} leaked: {body}"
            );
        }
    }

    #[test]
    fn rotation_keeps_the_log_bounded() {
        let t = Tmp::new("rotate");
        let p = t.0.join("calls.jsonl");
        // 1 MiB is the floor; write enough lines to cross it several times.
        let log = AuditLog::open(&p, 1, "s".to_string()).unwrap();
        let mut r = rec("find_gadgets", "ok");
        r.binary = Some("x".repeat(4096));
        for _ in 0..900 {
            log.write(&r);
        }
        let cur = std::fs::metadata(&p).unwrap().len();
        assert!(cur <= 1024 * 1024, "current log is {cur} bytes");
        assert!(rotated(&p, 1).exists(), "no .1 rotation");
        // Nothing beyond .2 is kept.
        assert!(!rotated(&p, 3).exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_log_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let t = Tmp::new("mode");
        let p = t.0.join("calls.jsonl");
        let log = AuditLog::open(&p, 64, "s".to_string()).unwrap();
        log.write(&rec("find_gadgets", "ok"));
        let mode = std::fs::metadata(&p).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode {:o}", mode & 0o777);
    }

    #[test]
    fn timestamps_are_rfc3339_utc() {
        // Cross-checked against `datetime.fromtimestamp(..., timezone.utc)`.
        let t = UNIX_EPOCH + std::time::Duration::from_millis(1_788_437_472_345);
        assert_eq!(rfc3339_millis_utc(t), "2026-09-03T12:11:12.345Z");
        assert_eq!(rfc3339_millis_utc(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let leap = UNIX_EPOCH + std::time::Duration::from_secs(951_782_400);
        assert_eq!(rfc3339_millis_utc(leap), "2000-02-29T00:00:00.000Z");
    }
}
