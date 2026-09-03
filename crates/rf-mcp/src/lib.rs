//! rf-mcp — MCP (Model Context Protocol) server wrapping rop-finder
//! (PLAN.md §6.1).
//!
//! stdio transport only (v1): no network attack surface. The server exposes
//! eight tools, all returning structured JSON:
//!
//!   * `find_gadgets` / `find_jop_gadgets` / `find_syscall_gadgets` —
//!     gadget scans restricted to one anchor family.
//!   * `get_binary_info` — the CLI's `--info` payload.
//!   * `search_gadgets_by_pattern` — regex (or substring) over gadget text.
//!   * `run_ropgadget_command` — flag passthrough restricted to the PLAN
//!     §6.1 allowlist.
//!   * `build_rop_chain` — the PLAN §6.2 chain builder.
//!   * `get_server_config` — the effective allowlist and caps, so an agent
//!     never has to guess a path.
//!
//! Security model (hardened per PLAN §6.1, review-driven):
//!   * `binary_path` is confined to a directory allowlist built *only* from
//!     `--allow-dir` (MCP-02: there is no cwd default; the server refuses to
//!     start without one). Confinement is enforced by [`confine`], which
//!     opens the file from a directory handle pinned at startup and hands the
//!     rest of the server a HANDLE, never a path — so nothing can be swapped
//!     between the check and the read (MCP-01).
//!   * Every rejected path returns exactly one code, `path_denied`, with no
//!     OS error text, so the error taxonomy cannot be used to enumerate the
//!     filesystem (MCP-07). `--verbose-path-errors` restores detail inside
//!     allowed roots only.
//!   * `run_ropgadget_command` rejects any flag outside the allowlist —
//!     side-channel flags (`--dump`, `--string`, `--memstr`, `--console`)
//!     are never accepted.
//!   * Resource caps: `max_results` (default 1000, hard max 50000), a
//!     per-request timeout (default 60 s), `--max-depth` (default 64,
//!     over-large values are *rejected*, not clamped), `--max-file-bytes`
//!     (default 256 MiB, enforced by fstat on the confined handle) and
//!     `--max-concurrent` (default 2, a semaphore held for the lifetime of
//!     the blocking worker). Together those bound the MCP-03 runaway; real
//!     cancellation needs the v0.2 engine token and is NOT here.
//!   * Content-hash cache (SHA-256 of file + parameters): in-memory, with
//!     an optional on-disk spill via `--cache-dir`.
//!   * Responses are sampled: up to `max_results` gadgets plus
//!     `total_count` and `truncated`. (PLAN calls for "top-N by quality
//!     rank"; ranking lands in Phase 5, so v1 returns the first N in the
//!     engine's deterministic traversal order.)
//!   * Errors are structured JSON `{error: {code, message, details?}}` with
//!     the MCP `isError` flag; the server never panics on malformed input.

pub mod confine;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Digest;

pub use confine::{AllowRoot, ConfinedFile};

pub const DEFAULT_MAX_RESULTS: usize = 1000;
pub const HARD_MAX_RESULTS: usize = 50000;
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;
pub const HARD_MAX_TIMEOUT_SECS: u64 = 300;
/// Default `--max-depth`. A request asking for more is rejected with a
/// `usage_error`, never silently clamped: an agent that quietly gets depth
/// 64 when it asked for 100000 draws wrong conclusions from the result.
pub const DEFAULT_MAX_DEPTH: usize = 64;
/// Default `--max-file-bytes` (256 MiB), enforced by fstat on the confined
/// handle before a single byte is read.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
/// Default `--max-concurrent`: how many scans may run at once.
pub const DEFAULT_MAX_CONCURRENT: usize = 2;

/// PLAN §6.1 flag allowlist for `run_ropgadget_command`.
const ALLOWED_FLAGS: &[&str] = &[
    "depth", "norop", "nojop", "nosys", "only", "filter", "re", "range", "section", "base",
    "offset", "badbytes", "align", "multibr", "json",
];
/// Allowlisted flags that take a value (the rest are boolean switches).
const VALUE_FLAGS: &[&str] = &[
    "depth", "only", "filter", "re", "range", "section", "base", "offset", "badbytes", "align",
];

// ---------------------------------------------------------------------------
// Configuration & path confinement
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Canonicalized allowed directories. MCP-02: EMPTY by default. The MCP
    /// host chooses this process's working directory, so seeding the
    /// allowlist with the cwd granted access to whatever the host happened
    /// to pick and `--allow-dir` could never narrow it. `--allow-dir` (or
    /// the explicit `--allow-cwd`) is now the only source.
    pub allow_dirs: Vec<PathBuf>,
    /// Optional on-disk cache spill directory.
    pub cache_dir: Option<PathBuf>,
    pub timeout: Duration,
    pub max_results: usize,
    /// Largest accepted `depth`. Larger values are rejected, not clamped.
    pub max_depth: usize,
    /// Largest binary the server will read, enforced by fstat on the
    /// confined handle.
    pub max_file_bytes: u64,
    /// Concurrently running scans.
    pub max_concurrent: usize,
    /// Restore per-reason path error detail INSIDE allowed roots only.
    pub verbose_path_errors: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            allow_dirs: Vec::new(),
            cache_dir: None,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_results: DEFAULT_MAX_RESULTS,
            max_depth: DEFAULT_MAX_DEPTH,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            verbose_path_errors: false,
        }
    }
}

/// Structured tool error, rendered as `{error: {code, message, details?}}`.
#[derive(Debug)]
pub struct ToolError {
    pub code: &'static str,
    pub message: String,
    /// Machine-readable specifics (allow roots, breached limits). Never
    /// carries an OS error string for a path outside the allowlist.
    pub details: Option<Value>,
}

impl ToolError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        ToolError {
            code,
            message: message.into(),
            details: None,
        }
    }
    fn with_details(code: &'static str, message: impl Into<String>, details: Value) -> Self {
        ToolError {
            code,
            message: message.into(),
            details: Some(details),
        }
    }
    fn to_json(&self) -> Value {
        match &self.details {
            Some(d) => {
                json!({"error": {"code": self.code, "message": self.message, "details": d}})
            }
            None => json!({"error": {"code": self.code, "message": self.message}}),
        }
    }
}

// ---------------------------------------------------------------------------
// Cache (content-hash → gadget list)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedGadget {
    vaddr: String,
    bytes: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    section: Option<String>,
    /// Phase 5 quality score (TAXONOMY.md R12), computed once at scan
    /// time; enables `sort_by: "quality"` without rescanning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quality: Option<i32>,
    /// Phase 5 primary class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    class: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CachedScan {
    gadgets: Vec<CachedGadget>,
    fallback_names: bool,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

#[derive(Default)]
pub struct Cache {
    mem: Mutex<HashMap<String, Arc<CachedScan>>>,
    dir: Option<PathBuf>,
}

impl Cache {
    pub fn new(dir: Option<PathBuf>) -> Self {
        Cache {
            mem: Mutex::new(HashMap::new()),
            dir,
        }
    }

    fn get(&self, key: &str) -> Option<Arc<CachedScan>> {
        if let Some(hit) = self.mem.lock().unwrap().get(key) {
            return Some(hit.clone());
        }
        if let Some(dir) = &self.dir {
            let path = dir.join(format!("{key}.json"));
            if let Ok(text) = std::fs::read_to_string(&path) {
                if let Ok(scan) = serde_json::from_str::<CachedScan>(&text) {
                    let scan = Arc::new(scan);
                    self.mem
                        .lock()
                        .unwrap()
                        .insert(key.to_string(), scan.clone());
                    return Some(scan);
                }
            }
        }
        None
    }

    fn put(&self, key: &str, scan: CachedScan) -> Arc<CachedScan> {
        let scan = Arc::new(scan);
        self.mem
            .lock()
            .unwrap()
            .insert(key.to_string(), scan.clone());
        if let Some(dir) = &self.dir {
            let path = dir.join(format!("{key}.json"));
            if let Ok(text) = serde_json::to_string(&*scan) {
                let _ = std::fs::write(path, text);
            }
        }
        scan
    }
}

// ---------------------------------------------------------------------------
// Shared parameter structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GadgetQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// Search depth (default 10).
    pub depth: Option<usize>,
    /// Executable section name(s) to scan; comma-separated, `*` globbing
    /// (e.g. ".text" or ".init*,.plt").
    pub section: Option<String>,
    /// Rebase the image base at load time (hex string, e.g. "0x400000";
    /// "0" for RVA-style addresses).
    pub base: Option<String>,
    /// Offset added to gadget addresses after any rebase (hex string).
    pub offset: Option<String>,
    /// Keep only gadgets containing these instructions (e.g. "pop|ret").
    pub only: Option<String>,
    /// Address range to scan, "0xSTART-0xEND".
    pub range: Option<String>,
    /// Reject gadgets whose final address contains these bytes
    /// (e.g. "0a|0d" or "00-1f").
    pub badbytes: Option<String>,
    /// Maximum gadgets returned (default 1000, hard max 50000).
    pub max_results: Option<usize>,
    /// Result ordering before sampling: "quality" sorts by the Phase 5
    /// quality score (best gadgets first, ties by address). Anything
    /// else is rejected.
    pub sort_by: Option<String>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

/// Scan architecture of a loaded binary (for on-demand classification).
fn arch_from_bytes(bytes: &[u8]) -> Option<rf_core::Arch> {
    use rf_core::{Image, LoadedBinary};
    match rf_core::Binary::load(bytes).ok()? {
        LoadedBinary::Elf(b) => Some(Image::arch(&b)),
        LoadedBinary::Pe(b) => Some(Image::arch(&b)),
        LoadedBinary::MachO(b) => Some(Image::arch(&b)),
        LoadedBinary::Universal(u) => Some(Image::arch(&u.slices()[0])),
        LoadedBinary::Raw(b) => Some(Image::arch(&b)),
    }
}

/// Reconstruct a scan gadget from its cached form (for on-demand
/// classification of cache entries that predate quality caching).
fn gadget_from_cached(c: &CachedGadget) -> Option<rf_scan::Gadget> {
    if c.bytes.len() % 2 != 0 {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..c.bytes.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&c.bytes[i..i + 2], 16).ok())
        .collect();
    let vaddr = u64::from_str_radix(c.vaddr.trim_start_matches("0x"), 16).ok()?;
    Some(rf_scan::Gadget {
        vaddr,
        bytes: bytes?,
        insns: c.text.split(" ; ").map(str::to_string).collect(),
        delay_slot: false,
        prev: None,
    })
}

/// Order gadgets by Phase 5 quality (descending, vaddr-ascending ties,
/// R12). Quality missing from a cache entry (old cache file) is computed
/// on demand from the cached bytes; unclassifiable entries sort last.
fn sort_by_quality(gadgets: Vec<&CachedGadget>, arch: Option<rf_core::Arch>) -> Vec<&CachedGadget> {
    let mut keyed: Vec<(i32, &CachedGadget)> = gadgets
        .into_iter()
        .map(|g| {
            let q = g.quality.or_else(|| {
                arch.and_then(|a| {
                    gadget_from_cached(g).map(|rg| rf_classify::classify(&rg, a).quality)
                })
            });
            (q.unwrap_or(0), g)
        })
        .collect();
    keyed.sort_by(|(qa, ga), (qb, gb)| qb.cmp(qa).then(ga.vaddr.cmp(&gb.vaddr)));
    keyed.into_iter().map(|(_, g)| g).collect()
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// Regex matched against gadget text (e.g. "pop r.*; ret"); if the
    /// pattern is not a valid regex it is matched as a literal substring.
    pub pattern: String,
    /// Search depth (default 10).
    pub depth: Option<usize>,
    /// Executable section name(s); comma-separated, `*` globbing.
    pub section: Option<String>,
    /// Rebase the image base at load time (hex string).
    pub base: Option<String>,
    /// Offset added to gadget addresses (hex string).
    pub offset: Option<String>,
    /// Address range to scan, "0xSTART-0xEND".
    pub range: Option<String>,
    /// Reject gadgets whose final address contains these bytes.
    pub badbytes: Option<String>,
    /// Maximum gadgets returned (default 1000, hard max 50000).
    pub max_results: Option<usize>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RawCommandQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// ROPgadget-style flags, e.g. ["--depth", "6", "--only", "pop|ret"].
    /// Restricted to the allowlist: --depth --norop --nojop --nosys --only
    /// --filter --re --range --section --base --offset --badbytes --align
    /// --multibr --json. Anything else is rejected.
    pub args: Vec<String>,
    /// Maximum gadgets returned (default 1000, hard max 50000).
    pub max_results: Option<usize>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InfoQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// Rebase the image base before reporting addresses (hex string).
    pub base: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ChainQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// Chain target: "linux-execve" (ELF x86/x64) or
    /// "windows-virtualprotect" (PE x86/x64).
    pub target: String,
    /// Search depth (default 10).
    pub depth: Option<usize>,
    /// Rebase the image base at load time (hex string, e.g. "0x400000").
    pub base: Option<String>,
    /// Offset added to gadget and data-section addresses (hex string).
    pub offset: Option<String>,
    /// Reject chain words whose packed value contains these bytes
    /// (e.g. "0a|0d" or "00-1f").
    pub badbytes: Option<String>,
    /// CFG/CET-aware scan: keep only endbr64/endbr32-entering gadgets.
    pub cfg_aware: Option<bool>,
    /// windows-virtualprotect: runtime address of the API (hex). Primary
    /// resolution path; without it the PE must import the API (IAT).
    pub api_addr: Option<String>,
    /// windows-virtualprotect: runtime shellcode address (hex; default:
    /// the binary's writable .data section).
    pub shellcode_addr: Option<String>,
    /// windows-virtualprotect: dwSize argument (hex; default 0x1000).
    pub shellcode_size: Option<String>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

// ---------------------------------------------------------------------------
// Request shaping helpers (unit-tested)
// ---------------------------------------------------------------------------

fn clamp_max_results(req: Option<usize>, default: usize) -> usize {
    req.unwrap_or(default).clamp(1, HARD_MAX_RESULTS)
}

fn clamp_timeout(req: Option<u64>, default: Duration) -> Duration {
    req.map(|s| Duration::from_secs(s.clamp(1, HARD_MAX_TIMEOUT_SECS)))
        .unwrap_or(default)
}

/// Parsed + validated `run_ropgadget_command` arguments.
#[derive(Debug)]
pub struct ParsedArgs {
    pub request: rf_cli::ScanRequest,
    /// --re post-filter (regex over gadget text).
    pub re: Option<String>,
    /// --align post-filter (address alignment).
    pub align: Option<u64>,
}

/// Validate `args` against the PLAN §6.1 allowlist and map them onto a
/// [`rf_cli::ScanRequest`]. Anything outside the allowlist is rejected.
pub fn parse_ropgadget_args(args: &[String]) -> Result<ParsedArgs, ToolError> {
    let mut req = rf_cli::ScanRequest::default();
    let mut re = None;
    let mut align = None;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let Some(stripped) = arg.strip_prefix("--") else {
            return Err(ToolError::new(
                "invalid_flag",
                format!("unexpected positional argument {arg:?}; only --flags are accepted"),
            ));
        };
        let (name, inline_val) = match stripped.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (stripped, None),
        };
        if !ALLOWED_FLAGS.contains(&name) {
            return Err(ToolError::new(
                "invalid_flag",
                format!(
                    "flag --{name} is not allowed; allowlist: {}",
                    ALLOWED_FLAGS
                        .iter()
                        .map(|f| format!("--{f}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
            ));
        }
        let takes_value = VALUE_FLAGS.contains(&name);
        let value = if takes_value {
            match inline_val {
                Some(v) => Some(v),
                None => {
                    i += 1;
                    let Some(v) = args.get(i) else {
                        return Err(ToolError::new(
                            "invalid_flag",
                            format!("flag --{name} requires a value"),
                        ));
                    };
                    if v.starts_with("--") {
                        return Err(ToolError::new(
                            "invalid_flag",
                            format!("flag --{name} requires a value (got {v:?})"),
                        ));
                    }
                    Some(v.clone())
                }
            }
        } else {
            if inline_val.is_some() {
                return Err(ToolError::new(
                    "invalid_flag",
                    format!("flag --{name} does not take a value"),
                ));
            }
            None
        };
        match name {
            "depth" => {
                req.depth = value.unwrap().parse().map_err(|_| {
                    ToolError::new("usage_error", "invalid --depth value".to_string())
                })?;
            }
            "norop" => req.rop = false,
            "nojop" => req.jop = false,
            "nosys" => req.sys = false,
            "multibr" => req.multibr = true,
            "json" => {} // MCP responses are always JSON
            "only" => req.only = value,
            "filter" => req.filter = value,
            "range" => req.range = value,
            "section" => req.section.extend(split_sections(value.as_deref())),
            "base" => req.base = value,
            "offset" => req.offset = value,
            "badbytes" => req.badbytes = value,
            "re" => re = value,
            "align" => {
                let v = value.unwrap();
                align = Some(
                    rf_cli::parse_hex(&v, "--align")
                        .or_else(|_| v.parse::<u64>().map_err(|e| format!("{e}")))
                        .map_err(|e| {
                            ToolError::new("usage_error", format!("invalid --align {v:?}: {e}"))
                        })?,
                );
            }
            _ => unreachable!("allowlist checked above"),
        }
        i += 1;
    }
    Ok(ParsedArgs {
        request: req,
        re,
        align,
    })
}

fn split_sections(section: Option<&str>) -> Vec<String> {
    section
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn query_to_request(q: &GadgetQuery, rop: bool, jop: bool, sys: bool) -> rf_cli::ScanRequest {
    rf_cli::ScanRequest {
        depth: q.depth.unwrap_or(10),
        rop,
        jop,
        sys,
        multibr: false,
        only: q.only.clone(),
        filter: None,
        range: q.range.clone(),
        badbytes: q.badbytes.clone(),
        offset: q.offset.clone(),
        base: q.base.clone(),
        section: split_sections(q.section.as_deref()),
        thumb: false,
        cfg_aware: false,
        align: None,
        call_preceded: false,
        all: false,
        noinstr: false,
    }
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

/// Post-scan options applied over the cached gadget set.
#[derive(Default)]
struct PostOpts {
    /// Regex/substring filter over gadget text (`--re`).
    re: Option<String>,
    /// Address alignment filter (`--align`).
    align: Option<u64>,
    /// Ordering before sampling; only "quality" is supported.
    sort_by: Option<String>,
}

#[derive(Clone)]
pub struct RopFinderMcp {
    config: Arc<ServerConfig>,
    cache: Arc<Cache>,
    /// Allow roots with their directory handles pinned for the lifetime of
    /// the process (MCP-01).
    roots: Arc<Vec<AllowRoot>>,
    /// MCP-03 interim bound: at most `max_concurrent` scans run at once.
    /// The permit is moved INTO the blocking closure, so it is released
    /// when the work actually stops rather than when the await returns —
    /// otherwise a timed-out request would free a slot while its orphaned
    /// worker kept burning CPU, which is the measured 398% runaway.
    inflight: Arc<tokio::sync::Semaphore>,
}

impl RopFinderMcp {
    /// Build the server, opening and pinning every `config.allow_dirs`
    /// entry. Fails if a root cannot be opened.
    pub fn new(config: ServerConfig) -> std::io::Result<Self> {
        let mut roots = Vec::with_capacity(config.allow_dirs.len());
        for d in &config.allow_dirs {
            let root = AllowRoot::open(d)?;
            if roots.iter().any(|r: &AllowRoot| r.id() == root.id()) {
                continue;
            }
            roots.push(root);
        }
        let cache = Cache::new(config.cache_dir.clone());
        let permits = config.max_concurrent.max(1);
        Ok(RopFinderMcp {
            config: Arc::new(config),
            cache: Arc::new(cache),
            roots: Arc::new(roots),
            inflight: Arc::new(tokio::sync::Semaphore::new(permits)),
        })
    }

    /// Open `binary_path` confined to the pinned allow roots.
    fn open_confined(&self, binary_path: &str) -> Result<ConfinedFile, ToolError> {
        confine::open_confined_with(
            &self.roots,
            binary_path,
            self.config.max_file_bytes,
            self.config.verbose_path_errors,
        )
    }

    /// MCP-03 interim: reject an over-large `depth` instead of clamping it.
    fn check_depth(&self, depth: Option<usize>) -> Result<usize, ToolError> {
        let d = depth.unwrap_or(10);
        if d > self.config.max_depth {
            return Err(ToolError::with_details(
                "usage_error",
                format!(
                    "depth {d} exceeds the server's max_depth of {}; \
                     re-send with depth <= {}",
                    self.config.max_depth, self.config.max_depth
                ),
                json!({"limit": "max_depth",
                       "limit_value": self.config.max_depth,
                       "got": d}),
            ));
        }
        Ok(d)
    }

    /// The effective configuration an agent is entitled to know, so it
    /// never has to guess a path (which is what made the error taxonomy
    /// worth probing in the first place — MCP-07).
    fn config_json(&self) -> Value {
        json!({
            "allow_roots": self.root_paths(),
            "max_depth": self.config.max_depth,
            "max_file_bytes": self.config.max_file_bytes,
            "max_results": self.config.max_results,
            "max_concurrent": self.config.max_concurrent,
            "timeout_secs": self.config.timeout.as_secs(),
            "cache": self.config.cache_dir.is_some(),
            "version": env!("CARGO_PKG_VERSION"),
        })
    }

    /// The effective allow roots, in operator-facing form.
    pub fn root_paths(&self) -> Vec<String> {
        self.roots
            .iter()
            .map(|r| r.display_path().display().to_string())
            .collect()
    }

    /// [`query_to_request`] with the request-boundary depth check applied.
    fn gadget_request(
        &self,
        q: &GadgetQuery,
        rop: bool,
        jop: bool,
        sys: bool,
    ) -> Result<rf_cli::ScanRequest, ToolError> {
        let depth = self.check_depth(q.depth)?;
        let mut req = query_to_request(q, rop, jop, sys);
        req.depth = depth;
        Ok(req)
    }

    /// Acquire an inflight permit, waiting at most `timeout`.
    ///
    /// The permit is then held until the worker stops, not until the await
    /// returns — that is what makes `--max-concurrent` a real bound on work
    /// in flight rather than on outstanding awaits. The wait is capped so a
    /// queued request fails fast with `busy` instead of hanging: until real
    /// cancellation lands (v0.2 engine token, MCP-03), a worker abandoned by
    /// its own timeout keeps its permit until it finishes on its own.
    async fn permit(
        &self,
        timeout: Duration,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ToolError> {
        match tokio::time::timeout(timeout, self.inflight.clone().acquire_owned()).await {
            Ok(Ok(p)) => Ok(p),
            Ok(Err(_)) => Err(ToolError::new("internal", "server is shutting down")),
            Err(_) => Err(ToolError::with_details(
                "busy",
                format!(
                    "all {} concurrent scan slots are in use; retry, or start the server \
                     with a larger --max-concurrent",
                    self.config.max_concurrent
                ),
                json!({"limit": "max_concurrent", "limit_value": self.config.max_concurrent}),
            )),
        }
    }

    /// Run a scan with confinement + caps + cache + timeout. Everything
    /// blocking happens on a worker thread so a timeout can abandon it.
    async fn run_scan(
        &self,
        req: rf_cli::ScanRequest,
        binary_path: &str,
        post: PostOpts,
        max_results: Option<usize>,
        timeout_secs: Option<u64>,
    ) -> Result<Value, ToolError> {
        let PostOpts {
            re: post_re,
            align: post_align,
            sort_by,
        } = post;
        if let Some(sb) = &sort_by {
            if sb != "quality" {
                return Err(ToolError::new(
                    "usage",
                    format!("unsupported sort_by {sb:?}; only \"quality\" is available"),
                ));
            }
        }
        // MCP-01: an open HANDLE, not a name, crosses into spawn_blocking.
        let confined = self.open_confined(binary_path)?;
        let max = clamp_max_results(max_results, self.config.max_results);
        let timeout = clamp_timeout(timeout_secs, self.config.timeout);
        let cache = self.cache.clone();
        let max_file_bytes = self.config.max_file_bytes;
        let permit = self.permit(timeout).await?;

        let work = move || -> Result<Value, ToolError> {
            let _permit = permit;
            let bytes = confined.read_all(max_file_bytes)?;
            let file_hash = sha256_hex(&bytes);
            // base and cfg_aware change the scan output too — they must be
            // part of the key or different requests would share a cache
            // entry (cache poisoning).
            let param_hash = sha256_hex(
                format!(
                    "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{:?}|{}|{}|{}",
                    req.depth,
                    req.rop,
                    req.jop,
                    req.sys,
                    req.multibr,
                    req.only.as_deref().unwrap_or(""),
                    req.filter.as_deref().unwrap_or(""),
                    req.range.as_deref().unwrap_or(""),
                    req.badbytes.as_deref().unwrap_or(""),
                    req.offset.as_deref().unwrap_or(""),
                    req.section,
                    req.thumb,
                    req.base.as_deref().unwrap_or(""),
                    req.cfg_aware
                )
                .as_bytes(),
            );
            // "--" separator: ':' is not allowed in Windows file names.
            let key = format!("{file_hash}--{param_hash}");
            let (scan, cache_status) = match cache.get(&key) {
                Some(hit) => (hit, "hit"),
                None => {
                    let outcome =
                        rf_cli::scan_bytes(&bytes, None, &req).map_err(scan_err_to_tool)?;
                    let res = &outcome.result;
                    let offset = outcome.opts.offset;
                    let arch = res.universal_arch.map(rf_cli::arch_name);
                    // Phase 5: classify once at scan time so quality/class
                    // ride in the cache (sort_by quality needs no rescan).
                    let class_arch = arch_from_bytes(&bytes);
                    let gadgets = res
                        .gadgets
                        .iter()
                        .map(|g| {
                            let cls = class_arch.map(|a| rf_classify::classify(g, a));
                            CachedGadget {
                                vaddr: rf_cli::fmt_addr(g.vaddr, res.addr_size),
                                bytes: g.bytes_hex(),
                                text: g.text(),
                                arch: arch.map(str::to_string),
                                section: res.selected_sections.as_deref().and_then(|s| {
                                    rf_cli::section_of(s, g.vaddr.wrapping_sub(offset))
                                }),
                                quality: cls.as_ref().map(|c| c.quality),
                                class: cls.as_ref().map(|c| c.primary.name().to_string()),
                            }
                        })
                        .collect();
                    (
                        cache.put(
                            &key,
                            CachedScan {
                                gadgets,
                                fallback_names: outcome.fallback_names,
                            },
                        ),
                        "miss",
                    )
                }
            };

            // Post-filters (--re, --align) run over the cached set.
            let mut gadgets: Vec<&CachedGadget> = scan.gadgets.iter().collect();
            if let Some(re) = &post_re {
                match regex::Regex::new(re) {
                    Ok(re) => gadgets.retain(|g| re.is_match(&g.text)),
                    Err(_) => gadgets.retain(|g| g.text.contains(re.as_str())),
                }
            }
            if let Some(align) = post_align {
                if align > 1 {
                    gadgets.retain(|g| {
                        u64::from_str_radix(g.vaddr.trim_start_matches("0x"), 16)
                            .map(|v| v % align == 0)
                            .unwrap_or(false)
                    });
                }
            }
            // Phase 5: quality ordering before sampling (top-N by quality).
            if sort_by.is_some() {
                gadgets = sort_by_quality(gadgets, arch_from_bytes(&bytes));
            }

            let total_count = gadgets.len();
            let truncated = total_count > max;
            let sampled: Vec<&CachedGadget> = gadgets.into_iter().take(max).collect();
            Ok(json!({
                "gadgets": sampled,
                "total_count": total_count,
                "returned": sampled.len(),
                "truncated": truncated,
                "binary_sha256": file_hash,
                "cache": cache_status,
                "fallback_section_names": scan.fallback_names,
            }))
        };

        match tokio::time::timeout(timeout, tokio::task::spawn_blocking(work)).await {
            Ok(Ok(v)) => v,
            Ok(Err(join_err)) => Err(ToolError::new(
                "internal",
                format!("scan worker failed: {join_err}"),
            )),
            Err(_) => Err(ToolError::new(
                "timeout",
                format!("scan exceeded the {} s timeout", timeout.as_secs()),
            )),
        }
    }

    /// Build a ROP chain with confinement + timeout. Unlike scans, chain
    /// builds are not cache-backed (a chain is a single compact artifact,
    /// and its inputs — the scan — would have to be re-validated anyway).
    async fn run_chain(&self, q: ChainQuery) -> Result<Value, ToolError> {
        if !matches!(q.target.as_str(), "linux-execve" | "windows-virtualprotect") {
            return Err(ToolError::new(
                "usage_error",
                format!(
                    "unknown chain target {:?}; supported: linux-execve, windows-virtualprotect",
                    q.target
                ),
            ));
        }
        let depth = self.check_depth(q.depth)?;
        let confined = self.open_confined(&q.binary_path)?;
        let timeout = clamp_timeout(q.timeout_secs, self.config.timeout);
        let max_file_bytes = self.config.max_file_bytes;
        let req = rf_cli::ScanRequest {
            depth,
            rop: true,
            jop: true,
            sys: true,
            multibr: false,
            only: None,
            filter: None,
            range: None,
            badbytes: q.badbytes.clone(),
            offset: q.offset.clone(),
            base: q.base.clone(),
            section: Vec::new(),
            thumb: false,
            cfg_aware: q.cfg_aware.unwrap_or(false),
            align: None,
            call_preceded: false,
            all: false,
            noinstr: false,
        };
        let spec = rf_cli::ChainSpec {
            target: q.target.clone(),
            api_addr: q.api_addr.clone(),
            shellcode_addr: q.shellcode_addr.clone(),
            shellcode_size: q.shellcode_size.clone(),
        };

        let permit = self.permit(timeout).await?;
        let work = move || -> Result<Value, ToolError> {
            let _permit = permit;
            let bytes = confined.read_all(max_file_bytes)?;
            let outcome =
                rf_cli::chain_bytes(&bytes, None, &req, &spec).map_err(scan_err_to_tool)?;
            let chain = &outcome.chain;
            Ok(json!({
                "chain": chain.to_json(),
                "python": chain.to_python(),
                "arch": chain.arch,
                "description": chain.description,
                "word_count": chain.words.len(),
                "binary_sha256": sha256_hex(&bytes),
            }))
        };

        match tokio::time::timeout(timeout, tokio::task::spawn_blocking(work)).await {
            Ok(Ok(v)) => v,
            Ok(Err(join_err)) => Err(ToolError::new(
                "internal",
                format!("chain worker failed: {join_err}"),
            )),
            Err(_) => Err(ToolError::new(
                "timeout",
                format!("chain build exceeded the {} s timeout", timeout.as_secs()),
            )),
        }
    }
}

fn scan_err_to_tool(e: rf_cli::ScanError) -> ToolError {
    match e {
        rf_cli::ScanError::Usage(m) => ToolError::new("usage_error", m),
        rf_cli::ScanError::Binary(m) => ToolError::new("binary_error", m),
        rf_cli::ScanError::Chain(m) => ToolError::new("chain_error", m),
    }
}

fn tool_error(err: ToolError) -> Result<CallToolResult, McpError> {
    let body = err.to_json();
    let mut r = CallToolResult::error(vec![ContentBlock::text(body.to_string())]);
    r.structured_content = Some(body);
    Ok(r)
}

fn tool_ok(value: Value) -> Result<CallToolResult, McpError> {
    let mut r = CallToolResult::success(vec![ContentBlock::text(value.to_string())]);
    r.structured_content = Some(value);
    Ok(r)
}

#[tool_router]
impl RopFinderMcp {
    /// Find ROP gadgets (return-oriented; ends in ret-like control flow).
    #[tool(
        description = "Find ROP gadgets in a binary (ret-terminated). Returns up to \
        max_results gadgets (default 1000) plus total_count and a truncated flag. Set \
        sort_by=\"quality\" to rank gadgets by the Phase 5 quality score (cleanest first) \
        before sampling. binary_path must be an absolute path inside one of the server's \
        allow_roots (call get_server_config to list them); anything else returns \
        path_denied. depth above max_depth is rejected, not clamped."
    )]
    async fn find_gadgets(
        &self,
        Parameters(q): Parameters<GadgetQuery>,
    ) -> Result<CallToolResult, McpError> {
        let req = match self.gadget_request(&q, true, false, false) {
            Ok(r) => r,
            Err(e) => return tool_error(e),
        };
        match self
            .run_scan(
                req,
                &q.binary_path,
                PostOpts {
                    sort_by: q.sort_by.clone(),
                    ..Default::default()
                },
                q.max_results,
                q.timeout_secs,
            )
            .await
        {
            Ok(v) => tool_ok(v),
            Err(e) => tool_error(e),
        }
    }

    /// Find JOP gadgets (jump-oriented; ends in jmp/call).
    #[tool(
        description = "Find JOP gadgets in a binary (jmp/call-terminated). Same parameters \
        and caps as find_gadgets."
    )]
    async fn find_jop_gadgets(
        &self,
        Parameters(q): Parameters<GadgetQuery>,
    ) -> Result<CallToolResult, McpError> {
        let req = match self.gadget_request(&q, false, true, false) {
            Ok(r) => r,
            Err(e) => return tool_error(e),
        };
        match self
            .run_scan(
                req,
                &q.binary_path,
                PostOpts {
                    sort_by: q.sort_by.clone(),
                    ..Default::default()
                },
                q.max_results,
                q.timeout_secs,
            )
            .await
        {
            Ok(v) => tool_ok(v),
            Err(e) => tool_error(e),
        }
    }

    /// Find SYS gadgets (syscall/int/sysenter entry points).
    #[tool(
        description = "Find SYS gadgets in a binary (syscall/sysenter/int). Same parameters \
        and caps as find_gadgets."
    )]
    async fn find_syscall_gadgets(
        &self,
        Parameters(q): Parameters<GadgetQuery>,
    ) -> Result<CallToolResult, McpError> {
        let req = match self.gadget_request(&q, false, false, true) {
            Ok(r) => r,
            Err(e) => return tool_error(e),
        };
        match self
            .run_scan(
                req,
                &q.binary_path,
                PostOpts {
                    sort_by: q.sort_by.clone(),
                    ..Default::default()
                },
                q.max_results,
                q.timeout_secs,
            )
            .await
        {
            Ok(v) => tool_ok(v),
            Err(e) => tool_error(e),
        }
    }

    /// Binary metadata without scanning (the CLI's --info payload).
    #[tool(
        description = "Get binary metadata as JSON: format, arch, endianness, addr_size, \
        image_base, entry, sections (name/vaddr/size/executable/writable) and PE imports. No \
        scan is performed."
    )]
    async fn get_binary_info(
        &self,
        Parameters(q): Parameters<InfoQuery>,
    ) -> Result<CallToolResult, McpError> {
        let result = async {
            let confined = self.open_confined(&q.binary_path)?;
            let base = q
                .base
                .as_deref()
                .map(|b| rf_cli::parse_hex(b, "--base"))
                .transpose()
                .map_err(|e| ToolError::new("usage_error", e))?;
            let _permit = self.permit(self.config.timeout).await?;
            let bytes = confined.read_all(self.config.max_file_bytes)?;
            rf_cli::info_bytes(&bytes, None, base).map_err(scan_err_to_tool)
        }
        .await;
        match result {
            Ok(v) => tool_ok(v),
            Err(e) => tool_error(e),
        }
    }

    /// The effective allowlist and caps, so an agent never has to guess.
    #[tool(
        description = "Report the server's effective configuration: allow_roots (the only \
        directories binary_path may name), max_depth, max_file_bytes, max_results, \
        max_concurrent, timeout_secs, whether an on-disk cache is enabled, and the server \
        version. Call this first: paths outside allow_roots are refused with a single \
        path_denied code that deliberately reveals nothing about the target."
    )]
    async fn get_server_config(&self) -> Result<CallToolResult, McpError> {
        tool_ok(self.config_json())
    }

    /// Regex/substring search over the gadget text of a full scan.
    #[tool(
        description = "Search gadgets by pattern: regex matched against gadget text \
        (e.g. \"pop r.*; ret\"); invalid regexes fall back to literal substring match. Runs a \
        full ROP+JOP+SYS scan, then filters. Same caps as find_gadgets."
    )]
    async fn search_gadgets_by_pattern(
        &self,
        Parameters(q): Parameters<SearchQuery>,
    ) -> Result<CallToolResult, McpError> {
        let depth = match self.check_depth(q.depth) {
            Ok(d) => d,
            Err(e) => return tool_error(e),
        };
        let req = rf_cli::ScanRequest {
            depth,
            rop: true,
            jop: true,
            sys: true,
            multibr: false,
            only: None,
            filter: None,
            range: q.range.clone(),
            badbytes: q.badbytes.clone(),
            offset: q.offset.clone(),
            base: q.base.clone(),
            section: split_sections(q.section.as_deref()),
            thumb: false,
            cfg_aware: false,
            align: None,
            call_preceded: false,
            all: false,
            noinstr: false,
        };
        match self
            .run_scan(
                req,
                &q.binary_path,
                PostOpts {
                    re: Some(q.pattern.clone()),
                    ..Default::default()
                },
                q.max_results,
                q.timeout_secs,
            )
            .await
        {
            Ok(v) => tool_ok(v),
            Err(e) => tool_error(e),
        }
    }

    /// Build a Linux execve("/bin/sh") ROP chain (ELF x86/x64 only).
    #[tool(
        description = "Build a ROP chain. target must be \"linux-execve\" (ELF x86/x64 only, \
        ported from ROPgadget's ropmaker: x86 int 0x80 / x64 syscall, \"/bin//sh\" written \
        to a writable section). Returns the chain IR as JSON (words with kinds gadget / \
        immediate / data / padding plus the referenced gadget table), the equivalent python \
        exploit script, arch, description and word_count. Fails with a structured chain_error \
        when the binary lacks the required gadgets. Chain builds bypass the gadget cache."
    )]
    async fn build_rop_chain(
        &self,
        Parameters(q): Parameters<ChainQuery>,
    ) -> Result<CallToolResult, McpError> {
        match self.run_chain(q).await {
            Ok(v) => tool_ok(v),
            Err(e) => tool_error(e),
        }
    }

    /// Flag passthrough restricted to the PLAN §6.1 allowlist.
    #[tool(
        description = "Run a ROPgadget-style scan with explicit flags. args is a list like \
        [\"--depth\", \"6\", \"--only\", \"pop|ret\"]. Allowlist: --depth --norop --nojop \
        --nosys --only --filter --re --range --section --base --offset --badbytes --align \
        --multibr --json; anything else (--string, --dump, --console, ...) is rejected. \
        Output is always structured JSON."
    )]
    async fn run_ropgadget_command(
        &self,
        Parameters(q): Parameters<RawCommandQuery>,
    ) -> Result<CallToolResult, McpError> {
        let parsed = match parse_ropgadget_args(&q.args) {
            Ok(p) => p,
            Err(e) => return tool_error(e),
        };
        // MCP-03 interim: --depth is unbounded in ROPgadget's own CLI, so
        // the passthrough is exactly where `--depth 100000` arrived.
        if let Err(e) = self.check_depth(Some(parsed.request.depth)) {
            return tool_error(e);
        }
        match self
            .run_scan(
                parsed.request,
                &q.binary_path,
                PostOpts {
                    re: parsed.re,
                    align: parsed.align,
                    sort_by: None,
                },
                q.max_results,
                q.timeout_secs,
            )
            .await
        {
            Ok(v) => tool_ok(v),
            Err(e) => tool_error(e),
        }
    }
}

#[tool_handler(name = "rop-finder-mcp", version = "0.1.0")]
impl ServerHandler for RopFinderMcp {
    /// `instructions` is built at runtime rather than baked into the macro
    /// so it can name the *effective* allowlist. An agent that is told the
    /// roots has no reason to guess paths, which is what turned the old
    /// error taxonomy into a filesystem oracle (MCP-07).
    fn get_info(&self) -> rmcp::model::ServerInfo {
        rmcp::model::ServerInfo::new(
            rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .build(),
        )
        .with_server_info(rmcp::model::Implementation::new("rop-finder-mcp", "0.1.0"))
        .with_instructions(self.instructions())
    }
}

impl RopFinderMcp {
    /// The initialize-time `instructions` string, including the effective
    /// allowlist and caps.
    pub fn instructions(&self) -> String {
        let roots = self.root_paths();
        let allowed = if roots.is_empty() {
            "(none — every binary_path will be refused)".to_string()
        } else {
            roots.join(", ")
        };
        format!(
            "ROP/JOP/SYS gadget search via rop-finder, plus Linux execve ROP chain \
             generation (build_rop_chain, ELF x86/x64).\n\
             binary_path MUST be an absolute path inside one of these directories: {allowed}. \
             Anything else — including a path that merely starts with one of those strings, a \
             relative path, or one containing \"..\" — is refused with a single `path_denied` \
             code that deliberately reveals nothing about the target, so probing for files is \
             pointless. Call get_server_config for the machine-readable allowlist and caps.\n\
             Caps: depth <= {} (larger values are REJECTED, not clamped), binaries <= {} bytes, \
             max_results default {} (hard max {}), {} scan(s) at a time, default timeout {} s.\n\
             All tools return structured JSON with gadgets sampled to max_results plus \
             total_count/truncated; errors are {{error: {{code, message, details?}}}}.",
            self.config.max_depth,
            self.config.max_file_bytes,
            self.config.max_results,
            HARD_MAX_RESULTS,
            self.config.max_concurrent,
            self.config.timeout.as_secs(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique temp dir per test, cleaned up on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let raw =
                std::env::temp_dir().join(format!("rf-mcp-test-{}-{}", tag, std::process::id()));
            let _ = std::fs::remove_dir_all(&raw);
            std::fs::create_dir_all(&raw).unwrap();
            TempDir(raw.canonicalize().unwrap())
        }
        fn canon(&self) -> &PathBuf {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// MCP-02: the default configuration allows NOTHING. Seeding the
    /// allowlist with the process cwd is what made `--allow-dir` unable to
    /// narrow anything; a default of "nothing" fails closed instead.
    #[test]
    fn default_config_allows_nothing() {
        let c = ServerConfig::default();
        assert!(c.allow_dirs.is_empty());
        assert_eq!(c.max_depth, DEFAULT_MAX_DEPTH);
        assert_eq!(c.max_concurrent, DEFAULT_MAX_CONCURRENT);
        assert_eq!(c.max_file_bytes, DEFAULT_MAX_FILE_BYTES);
        assert!(!c.verbose_path_errors);

        let server = RopFinderMcp::new(c).unwrap();
        assert!(server.root_paths().is_empty());
        // Every path is refused, with the one code and no OS text.
        let err = server.open_confined("/etc/shadow").unwrap_err();
        assert_eq!(err.code, "path_denied");
        assert!(!err.message.contains("os error"), "{err:?}");
    }

    /// MCP-03 interim: an over-large depth is REJECTED, not clamped, so an
    /// agent cannot mistake a depth-64 result for a depth-100000 one.
    #[test]
    fn depth_over_max_is_rejected_not_clamped() {
        let server = RopFinderMcp::new(ServerConfig::default()).unwrap();
        assert_eq!(server.check_depth(None).unwrap(), 10);
        assert_eq!(server.check_depth(Some(64)).unwrap(), 64);
        let err = server.check_depth(Some(100_000)).unwrap_err();
        assert_eq!(err.code, "usage_error");
        let d = err.details.expect("structured details");
        assert_eq!(d["limit"], "max_depth");
        assert_eq!(d["limit_value"], 64);
        assert_eq!(d["got"], 100_000);
        // usize::MAX, the value the audit actually sent, is rejected too.
        assert_eq!(
            server.check_depth(Some(usize::MAX)).unwrap_err().code,
            "usage_error"
        );
    }

    /// Duplicate `--allow-dir` entries naming the same directory collapse
    /// to one root, so the published allowlist is not misleading.
    #[test]
    fn duplicate_roots_collapse() {
        let t = TempDir::new("dup-roots");
        let c = ServerConfig {
            allow_dirs: vec![t.canon().clone(), t.canon().clone()],
            ..Default::default()
        };
        let server = RopFinderMcp::new(c).unwrap();
        assert_eq!(server.root_paths().len(), 1);
    }

    /// The allowlist and the caps are published, so a legitimate agent
    /// never has to guess a path (MCP-07's pressure valve).
    #[test]
    fn server_config_and_instructions_publish_the_allowlist() {
        let t = TempDir::new("publish");
        let c = ServerConfig {
            allow_dirs: vec![t.canon().clone()],
            ..Default::default()
        };
        let server = RopFinderMcp::new(c).unwrap();
        let cfg = server.config_json();
        for key in [
            "allow_roots",
            "max_depth",
            "max_file_bytes",
            "max_results",
            "max_concurrent",
            "cache",
            "version",
        ] {
            assert!(cfg.get(key).is_some(), "missing {key} in {cfg}");
        }
        assert_eq!(cfg["allow_roots"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["cache"], false);
        let root = server.root_paths()[0].clone();
        assert!(server.instructions().contains(&root));
        assert!(server.instructions().contains("get_server_config"));
    }

    #[test]
    fn allowlist_accepts_documented_flags() {
        let p = parse_ropgadget_args(&args(&[
            "--depth",
            "6",
            "--norop",
            "--nojop",
            "--nosys",
            "--multibr",
            "--json",
            "--only",
            "pop|ret",
            "--filter",
            "leave",
            "--re",
            "pop.*ret",
            "--range",
            "0x1000-0x2000",
            "--section",
            ".text,.plt",
            "--base",
            "0x400000",
            "--offset",
            "0x1000",
            "--badbytes",
            "0a|0d",
            "--align",
            "0x10",
        ]))
        .unwrap();
        assert_eq!(p.request.depth, 6);
        assert!(!p.request.rop && !p.request.jop && !p.request.sys && p.request.multibr);
        assert_eq!(p.request.only.as_deref(), Some("pop|ret"));
        assert_eq!(p.request.filter.as_deref(), Some("leave"));
        assert_eq!(p.request.range.as_deref(), Some("0x1000-0x2000"));
        assert_eq!(p.request.section, vec![".text", ".plt"]);
        assert_eq!(p.request.base.as_deref(), Some("0x400000"));
        assert_eq!(p.request.offset.as_deref(), Some("0x1000"));
        assert_eq!(p.request.badbytes.as_deref(), Some("0a|0d"));
        assert_eq!(p.re.as_deref(), Some("pop.*ret"));
        assert_eq!(p.align, Some(0x10));
        // --flag=value form also works
        let p = parse_ropgadget_args(&args(&["--depth=8"])).unwrap();
        assert_eq!(p.request.depth, 8);
    }

    #[test]
    fn allowlist_rejects_side_channel_and_unknown_flags() {
        for bad in ["--string", "--dump", "--console", "--memstr", "--unknown"] {
            let err = parse_ropgadget_args(&args(&[bad])).unwrap_err();
            assert_eq!(err.code, "invalid_flag", "{bad}");
            assert!(err.message.contains("--depth"), "lists allowlist: {err:?}");
        }
        // even with a value
        let err = parse_ropgadget_args(&args(&["--string", "password"])).unwrap_err();
        assert_eq!(err.code, "invalid_flag");
        // positional argument
        let err = parse_ropgadget_args(&args(&["/etc/passwd"])).unwrap_err();
        assert_eq!(err.code, "invalid_flag");
        // missing value
        let err = parse_ropgadget_args(&args(&["--depth"])).unwrap_err();
        assert_eq!(err.code, "invalid_flag");
        // boolean flag with value
        let err = parse_ropgadget_args(&args(&["--norop=1"])).unwrap_err();
        assert_eq!(err.code, "invalid_flag");
        // bad depth value
        let err = parse_ropgadget_args(&args(&["--depth", "x"])).unwrap_err();
        assert_eq!(err.code, "usage_error");
    }

    #[test]
    fn caps_are_clamped() {
        assert_eq!(clamp_max_results(None, 1000), 1000);
        assert_eq!(clamp_max_results(Some(5), 1000), 5);
        assert_eq!(clamp_max_results(Some(999_999), 1000), HARD_MAX_RESULTS);
        assert_eq!(clamp_max_results(Some(0), 1000), 1);
        assert_eq!(
            clamp_timeout(Some(999_999), Duration::from_secs(60)),
            Duration::from_secs(HARD_MAX_TIMEOUT_SECS)
        );
        assert_eq!(
            clamp_timeout(None, Duration::from_secs(60)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn sort_by_quality_orders_desc_with_vaddr_ties() {
        let mk = |vaddr: &str, bytes: &str, text: &str, quality: Option<i32>| CachedGadget {
            vaddr: vaddr.into(),
            bytes: bytes.into(),
            text: text.into(),
            arch: None,
            section: None,
            quality,
            class: None,
        };
        let cached = vec![
            // messy multi-effect gadget: quality 79
            mk(
                "0x1000",
                "504801d859c3",
                "push rax ; add rax, rbx ; pop rcx ; ret",
                None,
            ),
            // clean: quality 100
            mk("0x2000", "58c3", "pop rax ; ret", None),
            // pre-cached quality rides along without reclassification
            mk("0x3000", "c3", "ret", Some(85)),
            // tie on quality 100: lower vaddr first
            mk("0x0500", "5fc3", "pop rdi ; ret", None),
        ];
        let refs: Vec<&CachedGadget> = cached.iter().collect();
        let sorted = sort_by_quality(refs, Some(rf_core::Arch::X64));
        let order: Vec<&str> = sorted.iter().map(|g| g.vaddr.as_str()).collect();
        assert_eq!(order, ["0x0500", "0x2000", "0x3000", "0x1000"]);
        // None arch + missing quality -> q=0 entries sort last by vaddr
        let refs: Vec<&CachedGadget> = cached.iter().collect();
        let sorted = sort_by_quality(refs, None);
        let order: Vec<&str> = sorted.iter().map(|g| g.vaddr.as_str()).collect();
        assert_eq!(order, ["0x3000", "0x0500", "0x1000", "0x2000"]);
    }

    #[test]
    fn cache_roundtrip_mem_and_disk() {
        let t = TempDir::new("cache");
        let cache = Cache::new(Some(t.canon().clone()));
        let scan = CachedScan {
            gadgets: vec![CachedGadget {
                vaddr: "0x1".into(),
                bytes: "c3".into(),
                text: "ret".into(),
                arch: None,
                section: None,
                quality: None,
                class: None,
            }],
            fallback_names: false,
        };
        cache.put("k1", scan);
        assert_eq!(cache.get("k1").unwrap().gadgets.len(), 1);
        // persisted to disk
        assert!(t.canon().join("k1.json").is_file());
        // a fresh cache over the same dir reads the disk entry
        let cold = Cache::new(Some(t.canon().clone()));
        assert!(cold.get("k1").is_some());
        assert!(cold.get("absent").is_none());
    }
}
