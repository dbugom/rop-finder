//! rf-mcp — MCP (Model Context Protocol) server wrapping rop-finder
//! (PLAN.md §6.1).
//!
//! stdio transport only (v1): no network attack surface. The server exposes
//! six tools, all returning structured JSON:
//!
//!   * `find_gadgets` / `find_jop_gadgets` / `find_syscall_gadgets` —
//!     gadget scans restricted to one anchor family.
//!   * `get_binary_info` — the CLI's `--info` payload.
//!   * `search_gadgets_by_pattern` — regex (or substring) over gadget text.
//!   * `run_ropgadget_command` — flag passthrough restricted to the PLAN
//!     §6.1 allowlist.
//!
//! Security model (hardened per PLAN §6.1, review-driven):
//!   * `binary_path` is confined to a directory allowlist (default: server
//!     cwd; extend with `--allow-dir`). Paths are canonicalized (symlinks
//!     and `..` resolved) and must stay inside an allowed directory.
//!   * `run_ropgadget_command` rejects any flag outside the allowlist —
//!     side-channel flags (`--dump`, `--string`, `--memstr`, `--console`)
//!     are never accepted.
//!   * Resource caps: `max_results` (default 1000, hard max 50000) and a
//!     per-request timeout (default 60 s); scans run on blocking worker
//!     threads so a timed-out request returns while the orphan thread
//!     finishes in the background.
//!   * Content-hash cache (SHA-256 of file + parameters): in-memory, with
//!     an optional on-disk spill via `--cache-dir`.
//!   * Responses are sampled: up to `max_results` gadgets plus
//!     `total_count` and `truncated`. (PLAN calls for "top-N by quality
//!     rank"; ranking lands in Phase 5, so v1 returns the first N in the
//!     engine's deterministic traversal order.)
//!   * Errors are structured JSON `{error: {code, message}}` with the MCP
//!     `isError` flag; the server never panics on malformed input.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Digest;

pub const DEFAULT_MAX_RESULTS: usize = 1000;
pub const HARD_MAX_RESULTS: usize = 50000;
pub const DEFAULT_TIMEOUT_SECS: u64 = 60;
pub const HARD_MAX_TIMEOUT_SECS: u64 = 300;

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
    /// Canonicalized allowed directories (default: server process cwd).
    pub allow_dirs: Vec<PathBuf>,
    /// Optional on-disk cache spill directory.
    pub cache_dir: Option<PathBuf>,
    pub timeout: Duration,
    pub max_results: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let cwd = std::env::current_dir()
            .and_then(|p| p.canonicalize())
            .unwrap_or_else(|_| PathBuf::from("."));
        ServerConfig {
            allow_dirs: vec![cwd],
            cache_dir: None,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_results: DEFAULT_MAX_RESULTS,
        }
    }
}

/// Structured tool error, rendered as `{error: {code, message}}`.
#[derive(Debug)]
pub struct ToolError {
    pub code: &'static str,
    pub message: String,
}

impl ToolError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        ToolError {
            code,
            message: message.into(),
        }
    }
    fn to_json(&self) -> Value {
        json!({"error": {"code": self.code, "message": self.message}})
    }
}

/// Confine `input` to the allowlist: canonicalize (resolving symlinks and
/// `..`), require an existing regular file, require containment in one of
/// `allow_dirs` (themselves canonicalized).
pub fn confine_path(allow_dirs: &[PathBuf], input: &str) -> Result<PathBuf, ToolError> {
    let canon = Path::new(input).canonicalize().map_err(|e| {
        ToolError::new(
            "path_not_found",
            format!("cannot canonicalize {input:?}: {e}"),
        )
    })?;
    if !canon.is_file() {
        return Err(ToolError::new(
            "not_a_file",
            format!("{input:?} is not a regular file"),
        ));
    }
    if allow_dirs.iter().any(|d| canon.starts_with(d)) {
        Ok(canon)
    } else {
        Err(ToolError::new(
            "path_not_allowed",
            format!(
                "{input:?} is outside the allowed directories; start the server with \
                 --allow-dir to grant access"
            ),
        ))
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
    /// Path to the binary; must be inside an allowed directory.
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
    /// Path to the binary; must be inside an allowed directory.
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
    /// Path to the binary; must be inside an allowed directory.
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
    /// Path to the binary; must be inside an allowed directory.
    pub binary_path: String,
    /// Rebase the image base before reporting addresses (hex string).
    pub base: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ChainQuery {
    /// Path to the binary; must be inside an allowed directory.
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
}

impl RopFinderMcp {
    pub fn new(config: ServerConfig) -> Self {
        let cache = Cache::new(config.cache_dir.clone());
        RopFinderMcp {
            config: Arc::new(config),
            cache: Arc::new(cache),
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
        let path = confine_path(&self.config.allow_dirs, binary_path)?;
        let max = clamp_max_results(max_results, self.config.max_results);
        let timeout = clamp_timeout(timeout_secs, self.config.timeout);
        let cache = self.cache.clone();

        let work = move || -> Result<Value, ToolError> {
            let bytes = std::fs::read(&path)
                .map_err(|e| ToolError::new("io_error", format!("cannot read {path:?}: {e}")))?;
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
        let path = confine_path(&self.config.allow_dirs, &q.binary_path)?;
        let timeout = clamp_timeout(q.timeout_secs, self.config.timeout);
        let req = rf_cli::ScanRequest {
            depth: q.depth.unwrap_or(10),
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

        let work = move || -> Result<Value, ToolError> {
            let bytes = std::fs::read(&path)
                .map_err(|e| ToolError::new("io_error", format!("cannot read {path:?}: {e}")))?;
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
        before sampling. The binary path must be inside an allowed directory (server cwd \
        by default)."
    )]
    async fn find_gadgets(
        &self,
        Parameters(q): Parameters<GadgetQuery>,
    ) -> Result<CallToolResult, McpError> {
        let req = query_to_request(&q, true, false, false);
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
        let req = query_to_request(&q, false, true, false);
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
        let req = query_to_request(&q, false, false, true);
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
        let result = confine_path(&self.config.allow_dirs, &q.binary_path).and_then(|path| {
            let base = q
                .base
                .as_deref()
                .map(|b| rf_cli::parse_hex(b, "--base"))
                .transpose()
                .map_err(|e| ToolError::new("usage_error", e))?;
            let bytes = std::fs::read(&path)
                .map_err(|e| ToolError::new("io_error", format!("cannot read {path:?}: {e}")))?;
            rf_cli::info_bytes(&bytes, None, base).map_err(scan_err_to_tool)
        });
        match result {
            Ok(v) => tool_ok(v),
            Err(e) => tool_error(e),
        }
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
        let req = rf_cli::ScanRequest {
            depth: q.depth.unwrap_or(10),
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

#[tool_handler(
    name = "rop-finder-mcp",
    version = "0.1.0",
    instructions = "ROP/JOP/SYS gadget search via rop-finder, plus Linux execve ROP chain \
        generation (build_rop_chain, ELF x86/x64). binary_path values are confined \
        to allowed directories (server cwd by default, extend with --allow-dir). All tools \
        return structured JSON with gadgets sampled to max_results plus total_count/truncated; \
        errors are {error: {code, message}}."
)]
impl ServerHandler for RopFinderMcp {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique temp dir per test, cleaned up on drop.
    struct TempDir(PathBuf, PathBuf); // (raw, canonical)
    impl TempDir {
        fn new(tag: &str) -> Self {
            let raw =
                std::env::temp_dir().join(format!("rf-mcp-test-{}-{}", tag, std::process::id()));
            let _ = std::fs::remove_dir_all(&raw);
            std::fs::create_dir_all(&raw).unwrap();
            let canon = raw.canonicalize().unwrap();
            TempDir(raw, canon)
        }
        fn canon(&self) -> &PathBuf {
            &self.1
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn confine_path_accepts_inside_allowlist() {
        let t = TempDir::new("confine-ok");
        let f = t.canon().join("a.bin");
        std::fs::write(&f, b"MZ").unwrap();
        let got = confine_path(std::slice::from_ref(t.canon()), f.to_str().unwrap()).unwrap();
        assert_eq!(got, f.canonicalize().unwrap());
    }

    #[test]
    fn confine_path_rejects_traversal_and_outside() {
        let outer = TempDir::new("confine-outer");
        let allowed = outer.1.join("allowed");
        let other = outer.1.join("other");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let inside = allowed.join("in.bin");
        let outside = other.join("out.bin");
        std::fs::write(&inside, b"x").unwrap();
        std::fs::write(&outside, b"x").unwrap();
        let allowed = allowed.canonicalize().unwrap();
        let outside_canon = outside.canonicalize().unwrap();

        // ../.. escape attempt (built from the RAW temp path: Windows
        // canonicalize() rejects verbatim \\?\ paths containing "..").
        let raw_allowed = outer.0.join("allowed");
        let traversal = format!("{}/../other/out.bin", raw_allowed.display());
        let err = confine_path(std::slice::from_ref(&allowed), &traversal).unwrap_err();
        assert_eq!(err.code, "path_not_allowed", "{err:?}");

        // absolute path outside the allowlist
        let err = confine_path(
            std::slice::from_ref(&allowed),
            outside_canon.to_str().unwrap(),
        )
        .unwrap_err();
        assert_eq!(err.code, "path_not_allowed");

        // nonexistent path
        let err = confine_path(std::slice::from_ref(&allowed), "no/such/file.bin").unwrap_err();
        assert_eq!(err.code, "path_not_found");

        // directory is not a file
        let err =
            confine_path(std::slice::from_ref(&allowed), allowed.to_str().unwrap()).unwrap_err();
        assert_eq!(err.code, "not_a_file");
    }

    #[test]
    fn confine_path_rejects_symlink_escape() {
        let outer = TempDir::new("confine-symlink");
        let allowed = outer.canon().join("allowed");
        let secret = outer.canon().join("secret");
        std::fs::create_dir_all(&allowed).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        let target = secret.join("s.bin");
        std::fs::write(&target, b"x").unwrap();
        let link = allowed.join("link.bin");
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&target, &link);
        #[cfg(not(windows))]
        let linked = std::os::unix::fs::symlink(&target, &link);
        match linked {
            Ok(()) => {
                let allowed = allowed.canonicalize().unwrap();
                let err = confine_path(std::slice::from_ref(&allowed), link.to_str().unwrap())
                    .unwrap_err();
                assert_eq!(err.code, "path_not_allowed", "symlink resolved outside");
            }
            Err(e) => eprintln!("symlink creation unavailable ({e}); skipping"),
        }
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
