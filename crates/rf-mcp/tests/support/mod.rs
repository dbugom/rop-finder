//! Shared harness for the MCP integration tests: spawn the real
//! `rop-finder-mcp` binary and speak JSON-RPC 2.0 (newline-delimited) over
//! its stdio pipes, exactly like an MCP host would — plus the process
//! sampler the MCP-03 exit criterion is written in terms of.
//!
//! It lives here rather than in one test file because four test binaries
//! need it, and because `timeout_actually_stops_the_work` is a MEASUREMENT:
//! its assertion is about the server process's CPU time and RSS *after*
//! the client has been told the request timed out, which is precisely the
//! thing the old code got wrong (a tidy 2.00 s timeout error, then 395-400%
//! CPU held indefinitely).

#![allow(dead_code)]

pub mod jsonschema;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

/// Strip a Windows verbatim (`\\?\`) prefix.
///
/// `canonicalize` yields verbatim paths on Windows, and the server refuses
/// those outright (they bypass Win32 path normalization). An agent sends the
/// ordinary absolute paths the server publishes in `allow_roots`, so the
/// harness must too.
pub fn plain(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy().into_owned();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => p.to_path_buf(),
    }
}

pub fn fixtures_dir() -> PathBuf {
    plain(
        &Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures"))
            .canonicalize()
            .unwrap(),
    )
}

/// Unique temp directory, removed on drop.
pub struct TempTree(PathBuf);

impl TempTree {
    pub fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("rf-mcp-it-{}-{}-{}", tag, std::process::id(), n));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempTree(plain(&p.canonicalize().unwrap()))
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub struct McpChild {
    /// Held for kill-on-drop.
    pub child: Child,
    pub stdin: ChildStdin,
    pub lines: Lines<BufReader<ChildStdout>>,
    /// The server's working directory, deliberately chosen and deliberately
    /// NOT in the allowlist. It holds `probe.bin`, a byte-for-byte copy of a
    /// real ELF fixture: before MCP-02 was fixed the cwd was always allowed,
    /// so `get_binary_info` on it succeeded.
    pub cwd: TempTree,
    /// EVERY raw line this harness has read from the server's stdout, in
    /// order. `stdout_is_pure_jsonrpc` asserts over the bytes rather than
    /// over re-serialized values, because the failure it guards against —
    /// a stray `println!` — is a property of the bytes.
    pub raw: Vec<String>,
}

impl McpChild {
    pub async fn spawn() -> Self {
        Self::spawn_with(&[]).await
    }

    pub async fn spawn_with(extra: &[&str]) -> Self {
        let cwd = TempTree::new("cwd");
        std::fs::copy(
            fixtures_dir().join("elf-Linux-x64"),
            cwd.path().join("probe.bin"),
        )
        .expect("stage probe.bin in the server cwd");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rop-finder-mcp"));
        cmd.arg("--allow-dir")
            .arg(fixtures_dir())
            .args(extra)
            .current_dir(cwd.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);
        let child = cmd.spawn().expect("spawn rop-finder-mcp");
        Self::adopt(child, cwd).await
    }

    /// Wrap an already-spawned child and complete the MCP handshake.
    pub async fn adopt(mut child: Child, cwd: TempTree) -> Self {
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut mcp = McpChild {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
            cwd,
            raw: Vec::new(),
        };
        mcp.rpc(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "rf-mcp-test", "version": "0.1.0"},
            }),
        )
        .await;
        mcp.notify("notifications/initialized", json!({})).await;
        mcp
    }

    pub fn pid(&self) -> u32 {
        self.child.id().expect("server still running")
    }

    pub async fn notify(&mut self, method: &str, params: Value) {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        self.write(&msg).await;
    }

    /// Send a request WITHOUT waiting for its response.
    pub async fn send(&mut self, id: u64, method: &str, params: Value) {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.write(&msg).await;
    }

    pub async fn send_tool(&mut self, id: u64, name: &str, arguments: Value) {
        self.send(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
        .await;
    }

    async fn write(&mut self, msg: &Value) {
        self.stdin
            .write_all(msg.to_string().as_bytes())
            .await
            .unwrap();
        self.stdin.write_all(b"\n").await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// Read lines until the response with `id` arrives. Every line seen on
    /// the way is handed to `seen`, which is how the stdout-purity and
    /// notification assertions get their raw material.
    pub async fn await_id_with(
        &mut self,
        id: u64,
        budget: Duration,
        seen: &mut Vec<Value>,
    ) -> Option<Value> {
        let read = async {
            while let Some(line) = self.lines.next_line().await.unwrap() {
                self.raw.push(line.clone());
                let v: Value = serde_json::from_str(&line)
                    .unwrap_or_else(|e| panic!("non-JSON line on stdout: {line:?} ({e})"));
                if v.get("id").and_then(Value::as_u64) == Some(id) {
                    return Some(v);
                }
                seen.push(v);
            }
            None
        };
        tokio::time::timeout(budget, read).await.ok().flatten()
    }

    /// Send a request and read lines until the matching response arrives.
    pub async fn rpc(&mut self, id: u64, method: &str, params: Value) -> Value {
        self.send(id, method, params).await;
        let mut seen = Vec::new();
        self.await_id_with(id, Duration::from_secs(120), &mut seen)
            .await
            .unwrap_or_else(|| panic!("no response to {method} (id {id})"))
    }

    pub async fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.rpc(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
        .await
    }

    /// `get_server_stats`, unwrapped.
    pub async fn stats(&mut self, id: u64) -> Value {
        let r = self.call_tool(id, "get_server_stats", json!({})).await;
        structured(&r).clone()
    }
}

/// Extract the tool result's structured content, asserting the envelope.
pub fn structured(resp: &Value) -> &Value {
    let result = resp
        .get("result")
        .unwrap_or_else(|| panic!("no result: {resp}"));
    result
        .get("structuredContent")
        .unwrap_or_else(|| panic!("no structuredContent: {resp}"))
}

// ---------------------------------------------------------------------------
// Process sampling — the MCP-03 measurement
// ---------------------------------------------------------------------------

/// One observation of the server process.
#[derive(Debug, Clone, Copy)]
pub struct ProcSample {
    /// Total processor time (user + kernel) consumed since process start.
    pub cpu_secs: f64,
    /// Resident set / working set, in bytes.
    pub rss_bytes: u64,
}

/// Sample `pid`.
///
/// Windows: `Get-Process -Id`, whose `TotalProcessorTime` is
/// `GetProcessTimes`' user+kernel sum and whose `WorkingSet64` is the
/// resident size. Linux: `/proc/<pid>/stat` fields 14/15 (utime, stime) and
/// field 24 (rss, in pages). Anything else: `ps`.
pub fn sample(pid: u32) -> Option<ProcSample> {
    #[cfg(windows)]
    {
        sample_windows(pid)
    }
    #[cfg(target_os = "linux")]
    {
        sample_proc(pid)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        sample_ps(pid)
    }
}

#[cfg(windows)]
fn sample_windows(pid: u32) -> Option<ProcSample> {
    // Both values are printed as INTEGERS — processor-time ticks (100 ns)
    // and bytes — so no locale's decimal separator can get into the
    // measurement.
    let out = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "$p = Get-Process -Id {pid} -ErrorAction Stop; \
                 $p.TotalProcessorTime.Ticks; $p.WorkingSet64"
            ),
        ])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut it = s.split_whitespace();
    let ticks: u64 = it.next()?.parse().ok()?;
    let rss: u64 = it.next()?.parse().ok()?;
    Some(ProcSample {
        cpu_secs: ticks as f64 / 10_000_000.0,
        rss_bytes: rss,
    })
}

#[cfg(target_os = "linux")]
fn sample_proc(pid: u32) -> Option<ProcSample> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm can contain spaces and parentheses; everything after the last
    // ')' is fixed-position.
    let rest = stat.rsplit_once(')')?.1;
    let f: Vec<&str> = rest.split_whitespace().collect();
    // rest[0] is field 3 (state), so field N is rest[N - 3].
    let utime: f64 = f.get(11)?.parse().ok()?;
    let stime: f64 = f.get(12)?.parse().ok()?;
    let rss_pages: f64 = f.get(21)?.parse().ok()?;
    let hz = 100.0; // USER_HZ is 100 on every Linux this runs on
    Some(ProcSample {
        cpu_secs: (utime + stime) / hz,
        rss_bytes: (rss_pages * 4096.0) as u64,
    })
}

#[cfg(not(any(windows, target_os = "linux")))]
fn sample_ps(pid: u32) -> Option<ProcSample> {
    let out = std::process::Command::new("ps")
        .args(["-o", "time=,rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let mut it = s.split_whitespace();
    let time = it.next()?; // [[dd-]hh:]mm:ss
    let rss_kb: f64 = it.next()?.parse().ok()?;
    let mut secs = 0.0;
    for part in time.replace('-', ":").split(':') {
        secs = secs * 60.0 + part.parse::<f64>().ok()?;
    }
    Some(ProcSample {
        cpu_secs: secs,
        rss_bytes: (rss_kb * 1024.0) as u64,
    })
}

/// Human-readable MiB, for assertion messages that have to be believable.
pub fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}
