//! End-to-end MCP-over-stdio integration tests: spawn the real
//! `rop-finder-mcp` binary and speak JSON-RPC 2.0 (newline-delimited) over
//! its stdio pipes, exactly like an MCP host would.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const SCHEMA_FILE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/expected_tools_schema.json"
);

fn fixtures_dir() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures"))
        .canonicalize()
        .unwrap()
}

struct McpChild {
    /// Held for kill-on-drop.
    #[allow(dead_code)]
    child: Child,
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
}

impl McpChild {
    async fn spawn() -> Self {
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

    // tools/list: the six PLAN §6.1 scan tools plus build_rop_chain (§6.2)
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
    ] {
        assert!(names.contains(&want), "missing tool {want}: {names:?}");
    }
    assert_eq!(tools.len(), 7, "unexpected extra tools: {names:?}");
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
    assert_eq!(err["code"], "path_not_allowed", "{result}");

    // absolute path outside the allowlist (workspace-root Cargo.toml:
    // outside both the fixtures dir and the server's cwd, crates/rf-mcp)
    let outside = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../Cargo.toml")
        .canonicalize()
        .unwrap();
    let resp = mcp
        .call_tool(21, "find_gadgets", json!({"binary_path": outside}))
        .await;
    assert_eq!(resp["result"]["isError"], true);
    assert_eq!(
        resp["result"]["structuredContent"]["error"]["code"],
        "path_not_allowed"
    );

    // nonexistent path
    let resp = mcp
        .call_tool(
            22,
            "find_gadgets",
            json!({"binary_path": fixtures.join("no-such.bin")}),
        )
        .await;
    assert_eq!(
        resp["result"]["structuredContent"]["error"]["code"],
        "path_not_found"
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
