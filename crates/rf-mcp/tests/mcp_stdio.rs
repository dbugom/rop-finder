//! End-to-end MCP-over-stdio integration tests: spawn the real
//! `rop-finder-mcp` binary and speak JSON-RPC 2.0 (newline-delimited) over
//! its stdio pipes, exactly like an MCP host would.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const SCHEMA_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/expected_tools_schema.json"
);

/// Strip a Windows verbatim (`\\?\`) prefix.
///
/// `canonicalize` yields verbatim paths on Windows, and the server refuses
/// those outright (they bypass Win32 path normalization). An agent sends the
/// ordinary absolute paths the server publishes in `allow_roots`, so the
/// harness must too.
fn plain(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy().into_owned();
    match s.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => p.to_path_buf(),
    }
}

fn fixtures_dir() -> PathBuf {
    plain(
        &Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures"))
            .canonicalize()
            .unwrap(),
    )
}

/// Unique temp directory, removed on drop.
struct TempTree(PathBuf);

impl TempTree {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("rf-mcp-it-{}-{}-{}", tag, std::process::id(), n));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempTree(plain(&p.canonicalize().unwrap()))
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
    /// Held for kill-on-drop.
    #[allow(dead_code)]
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    /// The server's working directory, deliberately chosen and deliberately
    /// NOT in the allowlist. It holds `probe.bin`, a byte-for-byte copy of a
    /// real ELF fixture: before MCP-02 was fixed the cwd was always allowed,
    /// so `get_binary_info` on it succeeded.
    cwd: TempTree,
}

impl McpChild {
    async fn spawn() -> Self {
        Self::spawn_with(&[]).await
    }

    async fn spawn_with(extra: &[&str]) -> Self {
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
        let mut child = cmd.spawn().expect("spawn rop-finder-mcp");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut mcp = McpChild {
            child,
            stdin,
            lines: BufReader::new(stdout).lines(),
            cwd,
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

    async fn notify(&mut self, method: &str, params: Value) {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        self.stdin
            .write_all(msg.to_string().as_bytes())
            .await
            .unwrap();
        self.stdin.write_all(b"\n").await.unwrap();
        self.stdin.flush().await.unwrap();
    }

    /// Send a request and read lines until the matching response arrives.
    async fn rpc(&mut self, id: u64, method: &str, params: Value) -> Value {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.stdin
            .write_all(msg.to_string().as_bytes())
            .await
            .unwrap();
        self.stdin.write_all(b"\n").await.unwrap();
        self.stdin.flush().await.unwrap();
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

    async fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.rpc(
            id,
            "tools/call",
            json!({"name": name, "arguments": arguments}),
        )
        .await
    }
}

/// Extract the tool result's structured content, asserting the envelope.
fn structured(resp: &Value) -> &Value {
    let result = resp
        .get("result")
        .unwrap_or_else(|| panic!("no result: {resp}"));
    result
        .get("structuredContent")
        .unwrap_or_else(|| panic!("no structuredContent: {resp}"))
}

#[tokio::test]
async fn mcp_stdio_end_to_end() {
    let mut mcp = McpChild::spawn().await;

    // tools/list: the six PLAN §6.1 scan tools, build_rop_chain (§6.2) and
    // get_server_config (MCP-02 fix #2 item 6)
    let resp = mcp.rpc(2, "tools/list", json!({})).await;
    let tools = resp["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for want in [
        "find_gadgets",
        "find_jop_gadgets",
        "find_syscall_gadgets",
        "get_binary_info",
        "search_gadgets_by_pattern",
        "run_ropgadget_command",
        "build_rop_chain",
        "get_server_config",
    ] {
        assert!(names.contains(&want), "missing tool {want}: {names:?}");
    }
    assert_eq!(tools.len(), 8, "unexpected extra tools: {names:?}");
    for t in tools {
        assert!(t["description"].is_string());
        assert_eq!(t["inputSchema"]["type"], "object");
    }

    let elf = fixtures_dir().join("elf-x64-bash-v4.1.5.1");
    let pe = fixtures_dir().join("pe-x64-cmd-v6.1.7601");

    // find_gadgets on an ELF fixture
    let resp = mcp
        .call_tool(
            3,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 6, "max_results": 50}),
        )
        .await;
    let body = structured(&resp);
    assert_eq!(resp["result"]["isError"], Value::Bool(false));
    let gadgets = body["gadgets"].as_array().unwrap();
    assert_eq!(gadgets.len(), 50);
    assert_eq!(body["returned"], 50);
    assert!(body["total_count"].as_u64().unwrap() > 50);
    assert_eq!(body["truncated"], true);
    assert!(gadgets[0]["vaddr"].as_str().unwrap().starts_with("0x"));
    assert!(gadgets[0]["text"].as_str().unwrap().contains("ret"));
    assert!(body["binary_sha256"].as_str().unwrap().len() == 64);
    assert_eq!(body["cache"], "miss");

    // second identical call → cache hit
    let resp = mcp
        .call_tool(
            4,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 6, "max_results": 50}),
        )
        .await;
    assert_eq!(structured(&resp)["cache"], "hit");

    // --section composes: every gadget reports the section
    let resp = mcp
        .call_tool(
            5,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 6, "section": ".plt", "max_results": 10}),
        )
        .await;
    let body = structured(&resp);
    for g in body["gadgets"].as_array().unwrap() {
        assert_eq!(g["section"], ".plt");
    }

    // sort_by quality: quality/class fields present, descending order
    let resp = mcp
        .call_tool(
            50,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 6, "max_results": 50, "sort_by": "quality"}),
        )
        .await;
    let body = structured(&resp);
    let gadgets = body["gadgets"].as_array().unwrap();
    assert_eq!(gadgets.len(), 50);
    let mut prev: Option<i64> = None;
    for g in gadgets {
        let q = g["quality"].as_i64().expect("quality field present");
        assert!(g["class"].as_str().is_some(), "class field present");
        if let Some(p) = prev {
            assert!(p >= q, "quality descending: {p} then {q}");
        }
        prev = Some(q);
    }
    // the top of a quality-sorted list is a clean 100-score gadget
    assert_eq!(gadgets[0]["quality"], 100);

    // unsupported sort_by is rejected as a usage error
    let resp = mcp
        .call_tool(
            51,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 6, "sort_by": "vaddr"}),
        )
        .await;
    assert_eq!(resp["result"]["isError"], Value::Bool(true));
    assert!(resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("sort_by"));

    // get_binary_info on a PE fixture
    let resp = mcp
        .call_tool(6, "get_binary_info", json!({"binary_path": pe}))
        .await;
    let info = structured(&resp);
    assert_eq!(info["format"], "pe");
    assert_eq!(info["arch"], "x64");
    assert!(info["sections"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["name"] == ".text"));
    assert!(!info["imports"].as_array().unwrap().is_empty());

    // JOP and SYS anchor families
    let resp = mcp
        .call_tool(
            7,
            "find_jop_gadgets",
            json!({"binary_path": elf, "depth": 6, "max_results": 5}),
        )
        .await;
    assert!(structured(&resp)["total_count"].as_u64().unwrap() > 0);
    let resp = mcp
        .call_tool(
            8,
            "find_syscall_gadgets",
            json!({"binary_path": elf, "depth": 6, "max_results": 5}),
        )
        .await;
    let body = structured(&resp);
    // bash has SYS gadgets; each ends in a sys anchor (incl. iret-family)
    for g in body["gadgets"].as_array().unwrap() {
        let t = g["text"].as_str().unwrap();
        assert!(
            t.contains("syscall")
                || t.contains("sysenter")
                || t.contains("int 0x")
                || t.contains("iret"),
            "SYS gadget text: {t}"
        );
    }

    // pattern search
    let resp = mcp
        .call_tool(
            9,
            "search_gadgets_by_pattern",
            json!({"binary_path": elf, "pattern": "^pop rdi ; ret$", "depth": 6}),
        )
        .await;
    let body = structured(&resp);
    assert!(body["total_count"].as_u64().unwrap() > 0, "pop rdi ; ret");
    for g in body["gadgets"].as_array().unwrap() {
        assert_eq!(g["text"], "pop rdi ; ret");
    }

    // flag passthrough with allowlisted flags
    let resp = mcp
        .call_tool(
            10,
            "run_ropgadget_command",
            json!({"binary_path": elf,
                   "args": ["--nojop", "--nosys", "--only", "pop|ret", "--depth", "6"],
                   "max_results": 10}),
        )
        .await;
    let body = structured(&resp);
    assert!(body["total_count"].as_u64().unwrap() > 0);
    for g in body["gadgets"].as_array().unwrap() {
        assert!(g["text"].as_str().unwrap().contains("pop"));
    }

    // build_rop_chain on a fixture with a complete gadget set
    let linux = fixtures_dir().join("elf-Linux-x64");
    let resp = mcp
        .call_tool(
            11,
            "build_rop_chain",
            json!({"binary_path": linux, "target": "linux-execve"}),
        )
        .await;
    assert_eq!(resp["result"]["isError"], Value::Bool(false));
    let body = structured(&resp);
    assert_eq!(body["arch"], "x64");
    let py = body["python"].as_str().unwrap();
    assert!(py.starts_with("#!/usr/bin/env python3\n# execve generated by ROPgadget\n"));
    assert!(py.contains("p += b'/bin//sh'"));
    assert_eq!(
        body["chain"]["words"].as_array().unwrap().len(),
        body["word_count"].as_u64().unwrap() as usize
    );
    assert!(body["description"].as_str().unwrap().contains("execve"));

    // unknown chain target → clean usage_error; windows target on an ELF →
    // also usage_error ("not supported" dispatch)
    for (id, tgt) in [(12u64, "plan9-forkbomb"), (17, "windows-virtualprotect")] {
        let resp = mcp
            .call_tool(
                id,
                "build_rop_chain",
                json!({"binary_path": linux, "target": tgt}),
            )
            .await;
        assert_eq!(resp["result"]["isError"], true);
        assert_eq!(
            resp["result"]["structuredContent"]["error"]["code"], "usage_error",
            "target {tgt}"
        );
    }

    // bash lacks the write-what-where gadget → structured chain_error
    let resp = mcp
        .call_tool(
            13,
            "build_rop_chain",
            json!({"binary_path": elf, "target": "linux-execve"}),
        )
        .await;
    assert_eq!(resp["result"]["isError"], true);
    let err = &resp["result"]["structuredContent"]["error"];
    assert_eq!(err["code"], "chain_error");
    assert!(err["message"].as_str().unwrap().contains("mov qword ptr"));

    // windows-virtualprotect: pe-x86-cmd stdcall chain via api_addr
    let pe86 = fixtures_dir().join("pe-x86-cmd-v6.1.7600");
    let resp = mcp
        .call_tool(
            14,
            "build_rop_chain",
            json!({"binary_path": pe86, "target": "windows-virtualprotect",
                   "api_addr": "0x7fff12340000"}),
        )
        .await;
    assert_eq!(resp["result"]["isError"], Value::Bool(false));
    let body = structured(&resp);
    assert_eq!(body["arch"], "x86");
    assert_eq!(body["word_count"], 6);
    let py = body["python"].as_str().unwrap();
    assert!(py.contains("VirtualProtect @ 0x7fff12340000"));
    assert!(py.contains("ret 0x10"));
    let words = body["chain"]["words"].as_array().unwrap();
    assert_eq!(words[0]["kind"], "code_addr");

    // pe-x64-cmd cannot populate rdx/r8/r9 (spike finding) → chain_error
    let resp = mcp
        .call_tool(
            15,
            "build_rop_chain",
            json!({"binary_path": pe, "target": "windows-virtualprotect",
                   "api_addr": "0x7fff12340000"}),
        )
        .await;
    assert_eq!(resp["result"]["isError"], true);
    let err = &resp["result"]["structuredContent"]["error"];
    assert_eq!(err["code"], "chain_error");
    assert!(err["message"]
        .as_str()
        .unwrap()
        .contains("cannot populate rdx"));

    // pe-x86-cmd without api_addr imports VirtualAlloc but not
    // VirtualProtect → clean chain_error naming the resolution failure
    let resp = mcp
        .call_tool(
            16,
            "build_rop_chain",
            json!({"binary_path": pe86, "target": "windows-virtualprotect"}),
        )
        .await;
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(
        resp["result"]["structuredContent"]["error"]["code"],
        "chain_error"
    );
}

#[tokio::test]
async fn mcp_rejects_traversal_and_disallowed_flags() {
    let mut mcp = McpChild::spawn().await;
    let fixtures = fixtures_dir();

    // ".." escape: fixtures/../../Cargo.toml exists but is outside the allowlist
    let traversal = fixtures.join("../../Cargo.toml");
    let resp = mcp
        .call_tool(20, "get_binary_info", json!({"binary_path": traversal}))
        .await;
    let result = &resp["result"];
    assert_eq!(result["isError"], true);
    let err = &result["structuredContent"]["error"];
    assert_eq!(err["code"], "path_denied", "{result}");

    // absolute path outside the allowlist (workspace-root Cargo.toml)
    let outside = plain(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../Cargo.toml")
            .canonicalize()
            .unwrap(),
    );
    let resp = mcp
        .call_tool(21, "find_gadgets", json!({"binary_path": outside}))
        .await;
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(
        resp["result"]["structuredContent"]["error"]["code"],
        "path_denied"
    );

    // nonexistent path
    let resp = mcp
        .call_tool(
            22,
            "find_gadgets",
            json!({"binary_path": fixtures.join("no-such.bin")}),
        )
        .await;
    // MCP-07: an absent path inside the allowlist is refused with the SAME
    // code as one outside it. Nothing distinguishes absent from denied.
    assert_eq!(
        resp["result"]["structuredContent"]["error"]["code"],
        "path_denied"
    );

    // side-channel flags are rejected
    for (i, flag) in ["--string", "--dump", "--console", "--memstr"]
        .iter()
        .enumerate()
    {
        let resp = mcp
            .call_tool(
                30 + i as u64,
                "run_ropgadget_command",
                json!({"binary_path": fixtures.join("elf-x64-bash-v4.1.5.1"),
                       "args": [flag]}),
            )
            .await;
        let err = &resp["result"]["structuredContent"]["error"];
        assert_eq!(err["code"], "invalid_flag", "{flag}: {err}");
    }

    // malformed binary inside the allowlist → clean tool error, no panic
    let resp = mcp
        .call_tool(
            40,
            "get_binary_info",
            json!({"binary_path": fixtures.join("raw-x86.raw")}),
        )
        .await;
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(
        resp["result"]["structuredContent"]["error"]["code"],
        "binary_error"
    );

    // server is still alive and working after all the errors
    let resp = mcp
        .call_tool(
            41,
            "find_gadgets",
            json!({"binary_path": fixtures.join("elf-x64-bash-v4.1.5.1"),
                   "depth": 4, "max_results": 3}),
        )
        .await;
    assert_eq!(resp["result"]["isError"], Value::Bool(false));
}

#[tokio::test]
async fn tools_schema_snapshot() {
    let mut mcp = McpChild::spawn().await;
    let resp = mcp.rpc(2, "tools/list", json!({})).await;
    let tools = &resp["result"]["tools"];

    // Record mode: UPDATE_SCHEMA=1 rewrites the committed snapshot.
    if std::env::var("UPDATE_SCHEMA").is_ok() {
        std::fs::write(SCHEMA_FILE, serde_json::to_string_pretty(tools).unwrap()).unwrap();
        return;
    }
    let expected: Value =
        serde_json::from_str(&std::fs::read_to_string(SCHEMA_FILE).expect(SCHEMA_FILE)).unwrap();
    assert_eq!(
        *tools, expected,
        "tools/list schema drifted from {SCHEMA_FILE}; regenerate with UPDATE_SCHEMA=1"
    );
}

// ---------------------------------------------------------------------------
// MCP-02 — the allowlist is exactly --allow-dir, and nothing else
// ---------------------------------------------------------------------------

/// The server's working directory is NOT in the allowlist.
///
/// Before this fix `ServerConfig::default()` seeded `allow_dirs` with the
/// process cwd and `main.rs` only appended to it, so `--allow-dir` could
/// never narrow anything. The old `mcp_rejects_traversal_and_disallowed_flags`
/// only appeared to test this: it passed because the harness's cwd
/// (`crates/rf-mcp`) happened not to contain the probe file. Here the cwd is
/// chosen deliberately and does contain a readable ELF.
#[tokio::test]
async fn allowlist_is_exactly_allow_dir() {
    let mut mcp = McpChild::spawn().await;
    let probe = mcp.cwd.path().join("probe.bin");
    assert!(probe.is_file(), "probe.bin must exist in the server cwd");

    for (id, tool) in [(70u64, "get_binary_info"), (71, "find_gadgets")] {
        let resp = mcp.call_tool(id, tool, json!({"binary_path": probe})).await;
        assert_eq!(resp["result"]["isError"], true, "{tool}: {resp}");
        assert_eq!(
            resp["result"]["structuredContent"]["error"]["code"], "path_denied",
            "{tool}: {resp}"
        );
    }

    // ...and the allowlist the server publishes is exactly --allow-dir.
    let resp = mcp.call_tool(72, "get_server_config", json!({})).await;
    let cfg = structured(&resp);
    let roots: Vec<&str> = cfg["allow_roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert_eq!(roots.len(), 1, "{cfg}");
    assert!(
        Path::new(roots[0]).ends_with("fixtures"),
        "allow_roots is the --allow-dir value: {cfg}"
    );
    assert_eq!(cfg["max_depth"], 64);
    assert_eq!(cfg["max_concurrent"], 2);
    assert!(cfg["max_file_bytes"].as_u64().unwrap() > 0);
    assert!(cfg["version"].is_string());
}

/// The effective allowlist also rides in `initialize`'s instructions, so a
/// legitimate agent never has to guess a path.
#[tokio::test]
async fn initialize_instructions_name_the_allowlist() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rop-finder-mcp"))
        .arg("--allow-dir")
        .arg(fixtures_dir())
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
        cwd: TempTree::new("instr"),
    };
    let resp = mcp
        .rpc(
            1,
            "initialize",
            json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "rf-mcp-test", "version": "0.1.0"},
            }),
        )
        .await;
    let instructions = resp["result"]["instructions"].as_str().unwrap_or_default();
    assert!(
        instructions.contains(&fixtures_dir().display().to_string())
            || instructions.contains("fixtures"),
        "instructions must name the effective allowlist: {instructions}"
    );
    assert!(instructions.contains("get_server_config"), "{instructions}");
}

/// Failing closed: with no root at all the server must not come up.
#[tokio::test]
async fn no_allow_dir_refuses_to_start() {
    let out = Command::new(env!("CARGO_BIN_EXE_rop-finder-mcp"))
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .expect("run rop-finder-mcp");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("refusing to start"), "{stderr}");
    assert!(stderr.contains("--allow-dir"), "{stderr}");
}

/// A filesystem/drive root is refused without the explicit wide-allowlist
/// opt-in.
#[tokio::test]
async fn a_wide_allowlist_needs_an_explicit_opt_in() {
    #[cfg(windows)]
    let wide = "C:\\";
    #[cfg(not(windows))]
    let wide = "/";
    let out = Command::new(env!("CARGO_BIN_EXE_rop-finder-mcp"))
        .arg("--allow-dir")
        .arg(wide)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .expect("run rop-finder-mcp");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("refusing to start"), "{stderr}");
    assert!(stderr.contains("--i-accept-a-wide-allowlist"), "{stderr}");
}

/// A cache directory inside a scannable root muddles the trust boundary.
#[tokio::test]
async fn cache_dir_inside_an_allow_root_is_refused() {
    let out = Command::new(env!("CARGO_BIN_EXE_rop-finder-mcp"))
        .arg("--allow-dir")
        .arg(fixtures_dir())
        .arg("--cache-dir")
        .arg(fixtures_dir().join("rf-cache"))
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .expect("run rop-finder-mcp");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("--cache-dir"), "{stderr}");
    assert!(
        !fixtures_dir().join("rf-cache").exists(),
        "the refused cache dir must not have been created"
    );
}

// ---------------------------------------------------------------------------
// MCP-07 — the error taxonomy is not an existence oracle
// ---------------------------------------------------------------------------

/// An existing file, an existing directory and an absent path — all outside
/// the allowlist — must be indistinguishable.
///
/// The old taxonomy answered `not_a_file` for a directory, `path_not_allowed`
/// for an existing file and `path_not_found` (echoing errno) for an absent
/// one, for ANY absolute path on the machine. That is a whole-filesystem
/// existence oracle; it was confirmed live against ~/.ssh and ~/.aws.
#[tokio::test]
async fn error_taxonomy_is_not_an_existence_oracle() {
    let outside = TempTree::new("oracle");
    std::fs::create_dir_all(outside.path().join("a-directory")).unwrap();
    std::fs::write(outside.path().join("a-file"), b"\x7fELF").unwrap();

    let mut mcp = McpChild::spawn().await;
    let mut bodies = Vec::new();
    for (i, name) in ["a-file", "a-directory", "absent"].iter().enumerate() {
        let resp = mcp
            .call_tool(
                80 + i as u64,
                "get_binary_info",
                json!({"binary_path": outside.path().join(name)}),
            )
            .await;
        assert_eq!(resp["result"]["isError"], true, "{name}: {resp}");
        bodies.push(resp["result"]["structuredContent"].clone());
    }

    // Byte-identical: same code, same message, same details. The input is
    // not echoed at all, so there is nothing left to differ.
    assert_eq!(bodies[0], bodies[1], "file vs directory must not differ");
    assert_eq!(bodies[1], bodies[2], "directory vs absent must not differ");
    for b in &bodies {
        let text = b.to_string();
        assert_eq!(b["error"]["code"], "path_denied", "{text}");
        for leak in [
            "No such file",
            "os error",
            "canonicalize",
            "is not a regular file",
        ] {
            assert!(!text.contains(leak), "leaked {leak:?}: {text}");
        }
    }

    // The same holds inside the allowlist: an absent fixture is refused with
    // exactly the body an out-of-allowlist path gets.
    let resp = mcp
        .call_tool(
            83,
            "get_binary_info",
            json!({"binary_path": fixtures_dir().join("no-such.bin")}),
        )
        .await;
    assert_eq!(resp["result"]["structuredContent"], bodies[0]);
}

// ---------------------------------------------------------------------------
// MCP-03 (interim) — depth is bounded at the request boundary
// ---------------------------------------------------------------------------

/// `depth=100000` is REJECTED, not silently clamped: an agent that quietly
/// received depth 64 would draw wrong conclusions from the result. This is
/// the request that reached 54.8 GB RSS against the live server.
#[tokio::test]
async fn depth_over_max_is_rejected_not_clamped() {
    let mut mcp = McpChild::spawn().await;
    let elf = fixtures_dir().join("elf-x64-bash-v4.1.5.1");

    let calls = [
        (
            90u64,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 100000}),
        ),
        (
            91,
            "find_jop_gadgets",
            json!({"binary_path": elf, "depth": 100000}),
        ),
        (
            92,
            "find_syscall_gadgets",
            json!({"binary_path": elf, "depth": 100000}),
        ),
        (
            93,
            "search_gadgets_by_pattern",
            json!({"binary_path": elf, "pattern": "ret", "depth": 100000}),
        ),
        (
            94,
            "build_rop_chain",
            json!({"binary_path": elf, "target": "linux-execve", "depth": 100000}),
        ),
        (
            95,
            "run_ropgadget_command",
            json!({"binary_path": elf, "args": ["--depth", "100000"]}),
        ),
    ];
    for (id, tool, argsv) in calls {
        let resp = mcp.call_tool(id, tool, argsv).await;
        assert_eq!(resp["result"]["isError"], true, "{tool}: {resp}");
        let err = &resp["result"]["structuredContent"]["error"];
        assert_eq!(err["code"], "usage_error", "{tool}: {err}");
        assert_eq!(err["details"]["limit"], "max_depth", "{tool}: {err}");
        assert_eq!(err["details"]["limit_value"], 64, "{tool}: {err}");
        assert_eq!(err["details"]["got"], 100000, "{tool}: {err}");
    }

    // The server is unharmed and still answers a legal request.
    let resp = mcp
        .call_tool(
            96,
            "find_gadgets",
            json!({"binary_path": elf, "depth": 4, "max_results": 3}),
        )
        .await;
    assert_eq!(resp["result"]["isError"], Value::Bool(false));
}

/// `--max-concurrent` is a real bound: the permit is held for the lifetime
/// of the blocking worker, so overlapping scans serialize instead of
/// multiplying.
#[tokio::test]
async fn concurrent_requests_queue_rather_than_multiply() {
    let mut mcp = McpChild::spawn_with(&["--max-concurrent", "1"]).await;
    let elf = fixtures_dir().join("elf-x64-bash-v4.1.5.1");
    let resp = mcp.call_tool(100, "get_server_config", json!({})).await;
    assert_eq!(structured(&resp)["max_concurrent"], 1);

    for id in 101..103u64 {
        let resp = mcp
            .call_tool(
                id,
                "find_gadgets",
                json!({"binary_path": elf, "depth": 4, "max_results": 3}),
            )
            .await;
        assert_eq!(resp["result"]["isError"], Value::Bool(false), "{resp}");
    }
}

/// `--allow-cwd` is the deliberate opt-in that restores the old, implicit
/// behaviour for `cargo run` and CI. It has to be asked for by name.
#[tokio::test]
async fn allow_cwd_is_an_explicit_opt_in() {
    let cwd = TempTree::new("allow-cwd");
    std::fs::copy(
        fixtures_dir().join("elf-Linux-x64"),
        cwd.path().join("probe.bin"),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_rop-finder-mcp"))
        .arg("--allow-cwd")
        .current_dir(cwd.path())
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
        cwd: TempTree::new("allow-cwd-unused"),
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

    let resp = mcp
        .call_tool(
            200,
            "get_binary_info",
            json!({"binary_path": cwd.path().join("probe.bin")}),
        )
        .await;
    assert_eq!(resp["result"]["isError"], Value::Bool(false), "{resp}");
    assert_eq!(structured(&resp)["format"], "elf");
}

/// `--audit-log` is validated for containment but refuses to start rather
/// than accepting a flag that would silently record nothing.
#[tokio::test]
async fn audit_log_is_validated_and_refused_as_unimplemented() {
    // Inside an allow root: the containment refusal wins and names the flag.
    let out = Command::new(env!("CARGO_BIN_EXE_rop-finder-mcp"))
        .arg("--allow-dir")
        .arg(fixtures_dir())
        .arg("--audit-log")
        .arg(fixtures_dir().join("calls.jsonl"))
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .expect("run rop-finder-mcp");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("--audit-log"), "{stderr}");
    assert!(stderr.contains("inside the allow root"), "{stderr}");

    // Outside every root: still refused, but for being unimplemented.
    let elsewhere = TempTree::new("audit");
    let out = Command::new(env!("CARGO_BIN_EXE_rop-finder-mcp"))
        .arg("--allow-dir")
        .arg(fixtures_dir())
        .arg("--audit-log")
        .arg(elsewhere.path().join("calls.jsonl"))
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .expect("run rop-finder-mcp");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("not implemented"), "{stderr}");
}
// ---------------------------------------------------------------------------
// ANCH-02 - --align is the engine's alignment, decimal, not an address
// post-filter parsed as hex
// ---------------------------------------------------------------------------

/// End to end, through the real server: `--align N` must be ROPgadget's
/// scan-time alignment.
///
/// Two independent defects are asserted dead here.
///
/// 1. It used to be an ADDRESS POST-FILTER over a normal align=1 scan.
///    That is not what `gadgets.py:66-67` does: the oracle also multiplies
///    the backward depth stride by N, so an `--align 4 --depth 10` run
///    walks back up to 36 bytes while post-filtering a depth-10 align=1 run
///    can never expose a gadget reaching more than 9 bytes back. The test
///    reproduces the old post-filter from the align=1 result and requires
///    the real answer to be strictly bigger.
/// 2. The value used to go through `rf_cli::parse_hex`, which always parses
///    base 16, so `--align 16` meant 0x16 = 22. The test pins 16 and 22 to
///    different answers and requires "16" and "0x10" to agree.
#[tokio::test]
async fn align_is_scan_time_alignment_parsed_as_decimal() {
    let mut mcp = McpChild::spawn().await;
    let bin = fixtures_dir().join("macho-x64-ls");

    async fn scan(mcp: &mut McpChild, id: u64, bin: &Path, extra: &[&str]) -> Value {
        let mut args: Vec<String> = vec!["--depth".into(), "10".into()];
        args.extend(extra.iter().map(|s| s.to_string()));
        let resp = mcp
            .call_tool(
                id,
                "run_ropgadget_command",
                json!({"binary_path": bin, "args": args, "max_results": 50000}),
            )
            .await;
        assert_eq!(resp["result"]["isError"], Value::Bool(false), "{resp}");
        structured(&resp).clone()
    }

    let plain = scan(&mut mcp, 90, &bin, &[]).await;
    let a4 = scan(&mut mcp, 91, &bin, &["--align", "4"]).await;
    let a16 = scan(&mut mcp, 92, &bin, &["--align", "16"]).await;
    let a16hex = scan(&mut mcp, 93, &bin, &["--align", "0x10"]).await;
    let a22 = scan(&mut mcp, 94, &bin, &["--align", "22"]).await;

    let count = |v: &Value| v["total_count"].as_u64().expect("total_count");
    let addrs = |v: &Value| -> Vec<u64> {
        v["gadgets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| {
                u64::from_str_radix(g["vaddr"].as_str().unwrap().trim_start_matches("0x"), 16)
                    .unwrap()
            })
            .collect()
    };

    // (1) The engine option beats the post-filter it replaced.
    let post_filter_4 = addrs(&plain).iter().filter(|v| *v % 4 == 0).count() as u64;
    assert!(
        count(&a4) > post_filter_4,
        "--align 4 through the engine ({}) must find more than the old address \
         post-filter over an align=1 scan ({post_filter_4})",
        count(&a4)
    );
    // Every result really is 4-aligned, so this is not just "more gadgets".
    assert!(addrs(&a4).iter().all(|v| v % 4 == 0));

    // (2) 16 means sixteen. If it were parsed as hex it would equal 22.
    assert_eq!(
        count(&a16),
        count(&a16hex),
        "\"16\" and \"0x10\" must name the same alignment"
    );
    assert_ne!(
        count(&a16),
        count(&a22),
        "--align 16 must not be read as 0x16 = 22"
    );
    assert!(addrs(&a16).iter().all(|v| v % 16 == 0));

    // A bad value is a usage error, not a silent alignment of 0.
    let bad = mcp
        .call_tool(
            95,
            "run_ropgadget_command",
            json!({"binary_path": bin, "args": ["--align", "eight"]}),
        )
        .await;
    assert_eq!(bad["result"]["isError"], Value::Bool(true), "{bad}");
}

/// CORE-03 mirrored onto the MCP surface: a multi-slice fat Mach-O is
/// refused unless the caller names a slice, and `arch` picks one.
#[tokio::test]
async fn fat_macho_requires_an_arch_on_the_mcp_surface() {
    let mut mcp = McpChild::spawn().await;
    let bin = fixtures_dir().join("UNIVERSAL-x86-x64-libSystem.B.dylib");

    let refused = mcp
        .call_tool(80, "find_gadgets", json!({"binary_path": bin, "depth": 6}))
        .await;
    assert_eq!(refused["result"]["isError"], Value::Bool(true), "{refused}");
    let text = refused.to_string();
    assert!(text.contains("arch"), "{text}");
    assert!(text.contains("x86_64"), "{text}");

    let ok = mcp
        .call_tool(
            81,
            "find_gadgets",
            json!({"binary_path": bin, "depth": 6, "arch": "x86_64"}),
        )
        .await;
    assert_eq!(ok["result"]["isError"], Value::Bool(false), "{ok}");
    assert!(structured(&ok)["total_count"].as_u64().unwrap() > 0);

    // The two slices are different scans, and the server never falls back
    // to ROPgadget's concatenation.
    let other = mcp
        .call_tool(
            82,
            "find_gadgets",
            json!({"binary_path": bin, "depth": 6, "arch": "i386"}),
        )
        .await;
    assert_eq!(other["result"]["isError"], Value::Bool(false), "{other}");
    // Compare the gadget SETS, not the counts: two different slices of a
    // 32/64-bit pair can coincidentally return the same number.
    let keys = |v: &Value| -> std::collections::BTreeSet<String> {
        v["gadgets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| format!("{}|{}", g["vaddr"], g["bytes"]))
            .collect()
    };
    assert_ne!(
        keys(structured(&ok)),
        keys(structured(&other)),
        "the two slices must not produce the same gadget set"
    );

    // A slice the container does not hold is an error naming what it holds.
    let missing = mcp
        .call_tool(
            83,
            "find_gadgets",
            json!({"binary_path": bin, "depth": 6, "arch": "arm64"}),
        )
        .await;
    assert_eq!(missing["result"]["isError"], Value::Bool(true), "{missing}");
}
