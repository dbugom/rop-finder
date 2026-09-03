//! MCP-01 regression: the rename race that turned the MCP server into an
//! arbitrary-file-read primitive.
//!
//! This *is* the harness from the audit (docs/MCP-DESIGN.md fix #1): a
//! background thread swaps the name `allowed/target.bin` between a decoy
//! hardlink and a symlink pointing at a file outside the allowlist, while the
//! foreground fires 400 sequential `find_gadgets` calls at that name. The
//! measured baseline before the fix was 323 successful out-of-allowlist reads
//! out of 400; the assertion here is ZERO.
//!
//! The server is launched with `cwd=/`, which under the pre-MCP-02 code put
//! the whole filesystem in the allowlist as well.
//!
//! Unix only: it needs `symlink(2)`, `link(2)` and the guarantee that
//! `rename(2)` atomically replaces a name. Creating a symlink on Windows
//! requires either Developer Mode or SeCreateSymbolicLinkPrivilege, and the
//! Windows confinement path is proved differently (the opened HANDLE's
//! `GetFinalPathNameByHandleW` must still lie under the root), so the
//! equivalent Windows coverage lives in the `confine::tests` unit tests.
#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const REQUESTS: usize = 400;

fn fixtures_dir() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures"))
        .canonicalize()
        .unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

struct TempTree(PathBuf);
impl TempTree {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("rf-mcp-race-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempTree(p.canonicalize().unwrap())
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct McpChild {
    #[allow(dead_code)]
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
}

impl McpChild {
    async fn spawn(allow_dir: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rop-finder-mcp"))
            .arg("--allow-dir")
            .arg(allow_dir)
            .arg("--i-accept-a-wide-allowlist")
            // The audit ran the server from "/", which under the old code
            // put every path on the machine in the allowlist.
            .current_dir("/")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn rop-finder-mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut mcp = McpChild {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
        };
        mcp.rpc(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "rf-mcp-race", "version": "0.1.0"},
            }),
        )
        .await;
        let msg = json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}});
        mcp.send(&msg).await;
        mcp
    }

    async fn send(&mut self, msg: &Value) {
        self.stdin
            .write_all(msg.to_string().as_bytes())
            .await
            .unwrap();
        self.stdin.write_all(b"\n").await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    async fn rpc(&mut self, id: u64, method: &str, params: Value) -> Value {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.send(&msg).await;
        let read = async {
            while let Some(line) = self.lines.next_line().await.unwrap() {
                let v: Value = serde_json::from_str(&line).unwrap();
                if v.get("id").and_then(Value::as_u64) == Some(id) {
                    return v;
                }
            }
            panic!("server closed stdout before answering id {id}");
        };
        tokio::time::timeout(Duration::from_secs(120), read)
            .await
            .unwrap_or_else(|_| panic!("timeout waiting for response to {method} (id {id})"))
    }
}

/// 400 sequential requests against a name being swapped underneath them
/// must never read the file outside the allowlist.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rename_race_never_reads_outside_the_allowlist() {
    let tree = TempTree::new("tree");
    let allowed = tree.path().join("allowed");
    let outside = tree.path().join("outside");
    std::fs::create_dir_all(&allowed).unwrap();
    std::fs::create_dir_all(&outside).unwrap();

    // The decoy is a real, scannable binary inside the allowlist.
    let decoy = allowed.join("decoy.bin");
    std::fs::copy(fixtures_dir().join("elf-Linux-x64"), &decoy).unwrap();
    let decoy_hash = sha256_hex(&std::fs::read(&decoy).unwrap());

    // The secret is a DIFFERENT real binary outside it, so a successful
    // escape produces a successful scan with a distinguishable hash.
    let secret = outside.join("secret.bin");
    {
        let mut f = std::fs::File::create(&secret).unwrap();
        f.write_all(&std::fs::read(fixtures_dir().join("elf-Linux-x86")).unwrap())
            .unwrap();
    }
    let secret_hash = sha256_hex(&std::fs::read(&secret).unwrap());
    assert_ne!(decoy_hash, secret_hash);

    let target = allowed.join("target.bin");
    std::fs::hard_link(&decoy, &target).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let (stop, allowed, decoy, secret) =
            (stop.clone(), allowed.clone(), decoy.clone(), secret.clone());
        std::thread::spawn(move || {
            // rename(2) replaces the name atomically, so the server never
            // sees a missing target — only a decoy or a symlink out.
            let staging = allowed.join(".staging");
            let swapped = allowed.join("target.bin");
            while !stop.load(Ordering::Relaxed) {
                let _ = std::fs::remove_file(&staging);
                if std::fs::hard_link(&decoy, &staging).is_ok() {
                    let _ = std::fs::rename(&staging, &swapped);
                }
                let _ = std::fs::remove_file(&staging);
                if std::os::unix::fs::symlink(&secret, &staging).is_ok() {
                    let _ = std::fs::rename(&staging, &swapped);
                }
            }
        })
    };

    let mut mcp = McpChild::spawn(&allowed).await;
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for i in 0..REQUESTS {
        let resp = mcp
            .rpc(
                1000 + i as u64,
                "tools/call",
                json!({"name": "find_gadgets",
                       "arguments": {"binary_path": target, "depth": 3, "max_results": 1}}),
            )
            .await;
        let body = &resp["result"]["structuredContent"];
        let outcome = if resp["result"]["isError"] == Value::Bool(true) {
            body["error"]["code"].as_str().unwrap_or("?").to_string()
        } else {
            body["binary_sha256"].as_str().unwrap_or("?").to_string()
        };
        *outcomes.entry(outcome).or_default() += 1;
    }
    stop.store(true, Ordering::Relaxed);
    let _ = swapper.join();

    assert_eq!(
        outcomes.get(&secret_hash).copied().unwrap_or(0),
        0,
        "read the out-of-allowlist file; outcomes: {outcomes:?}"
    );
    // Every outcome is either the decoy's own bytes or a refusal.
    for key in outcomes.keys() {
        assert!(
            key == &decoy_hash || key == "path_denied",
            "unexpected outcome {key:?}; outcomes: {outcomes:?}"
        );
    }
    // And the harness actually exercised the race rather than trivially
    // failing every request.
    assert!(
        outcomes.values().sum::<usize>() == REQUESTS,
        "outcomes: {outcomes:?}"
    );
}
