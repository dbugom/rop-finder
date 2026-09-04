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
//!     (default 256 MiB, enforced by fstat on the confined handle),
//!     `--max-gadgets` (default 5 000 000, enforced in the engine) and
//!     `--max-concurrent` (default 2). Every tool without exception runs
//!     through [`guard::Guard::run`], which cancels the *work* on timeout
//!     and JOINS it before releasing the permit (MCP-03/PERF-06), and
//!     inside an explicit rayon pool sized by `--scan-threads`.
//!   * Content-hash cache (SHA-256 of file + parameters): a byte-weighted
//!     LRU with a TTL (`--cache-mem-mb`, `--cache-ttl-secs`), with an
//!     optional authenticated on-disk spill via `--cache-dir`.
//!   * Observability: `tracing` to **stderr only**, `--audit-log` (one
//!     JSON object per line, mode 0600, rotated), the `get_server_stats`
//!     tool, and the MCP `logging` capability so warnings reach an
//!     operator who never sees stderr (MCP-09).
//!   * Responses are sampled: up to `max_results` gadgets plus
//!     `total_count` and `truncated`. (PLAN calls for "top-N by quality
//!     rank"; ranking lands in Phase 5, so v1 returns the first N in the
//!     engine's deterministic traversal order.)
//!   * Errors are structured JSON `{error: {code, message, details?}}` with
//!     the MCP `isError` flag; the server never panics on malformed input.

// ROB-04. The char-boundary panic (`&c.bytes[i..i + 2]` on a `&str`) was
// reachable from a poisoned cache entry through the live server. Denying
// the two lints that permit it means the bug class cannot come back by
// accident; the checked decoders in `rf_cache` are the way to write it.
#![deny(clippy::indexing_slicing, clippy::string_slice)]

// `confine` predates this rule and has four indexing sites of its own; the
// attribute on the module declaration keeps them compiling without editing
// a file this change has no other business in. Its own wave removes them.
#[allow(clippy::indexing_slicing)]
pub mod confine;

pub mod audit;
pub mod cache;
pub mod checksec;
pub mod cursor;
pub mod find;
pub mod guard;
pub mod logging;
pub mod pattern;
pub mod resources;
pub mod scan;
pub mod schema;
pub mod semantics;
pub mod stats;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rf_cache::{CachedGadget, CachedScan};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::service::RequestContext;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, RoleServer, ServerHandler};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;

pub use audit::{AuditLog, AuditRecord};
pub use cache::Cache;
pub use confine::{AllowRoot, ConfinedFile};
pub use cursor::Cursor;
pub use guard::Guard;
pub use logging::Notifier;
pub use schema::{
    ChainResponse, ErrorCode, GadgetRecord, InfoResponse, ScanResponse, ToolErrorBody, Warning,
};
pub use semantics::{GadgetFilter, Order, Semantics};
pub use stats::{ServerStats, Verdict};

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
/// Default `--max-gadgets`, enforced in the engine (MCP-DESIGN fix #4 E).
/// Cancellation alone does not bound a scan that is legitimately huge;
/// this is what bounds RSS.
pub const DEFAULT_MAX_GADGETS: usize = 5_000_000;
/// Default `--cache-mem-mb`, in bytes.
pub const DEFAULT_CACHE_MEM_BYTES: u64 = rf_cache::DEFAULT_MEM_MAX_BYTES;
/// Default `--cache-ttl-secs`.
pub const DEFAULT_CACHE_TTL: Duration = rf_cache::DEFAULT_MEM_TTL;
/// Default `--cursor-ttl-secs`: how long a paged scan stays pinned against
/// eviction so an outstanding cursor can walk it (MCP-DESIGN fix #8 B).
pub const DEFAULT_CURSOR_TTL: Duration = cache::DEFAULT_CURSOR_TTL;
/// Default `--probe-threshold`: consecutive `path_denied` results in one
/// session before responses are delayed and `probing_suspected` is logged.
pub const DEFAULT_PROBE_THRESHOLD: u64 = 20;
/// How long a response is delayed once probing is suspected.
pub const PROBE_DELAY: Duration = Duration::from_millis(250);
/// Default cap on `get_binary_info`'s `sections` and `imports` arrays, so
/// a hostile PE with a million import entries cannot produce a gigabyte of
/// JSON (MCP-06).
pub const DEFAULT_MAX_INFO_ITEMS: usize = 4096;

/// Default cap on `get_binary_info`'s `symbols` array: symbols are OPT-IN.
///
/// `sections` and `imports` are bounded by the file's own structure — 30 and
/// 46 on `elf-Linux-x64` — so `DEFAULT_MAX_INFO_ITEMS` never bites there. A
/// symbol table is not: that same fixture has 2169, and reporting them by
/// default took `get_binary_info`'s rendered response from 10,410 characters
/// to 331,338 (2,602 -> 82,834 estimated tokens), which blew the 10,000-token
/// whole-task budget `tests/mcp_workability.py` gates on by 8x on the FIRST
/// call of the loop. The symbol table is a query target, not an overview, so
/// an agent asks for it by name; `symbol_count` still reports the true total
/// and a `symbols_truncated` warning names the parameter, so a default-shaped
/// response can never be mistaken for "this ELF has no symbols".
///
/// `imports` — the SHN_UNDEF subset a ret2plt chain resolves against, with
/// its GOT/PLT addresses — is unaffected and still reported by default.
pub const DEFAULT_MAX_SYMBOLS: usize = 0;

/// PLAN §6.1 flag allowlist for `run_ropgadget_command`.
const ALLOWED_FLAGS: &[&str] = &[
    "depth",
    "norop",
    "nojop",
    "nosys",
    "only",
    "filter",
    "re",
    "range",
    "section",
    "base",
    "offset",
    "badbytes",
    "align",
    "multibr",
    "json",
    "arch",
    "all",
    "callPreceded",
];
/// Allowlisted flags that take a value (the rest are boolean switches).
const VALUE_FLAGS: &[&str] = &[
    "depth", "only", "filter", "re", "range", "section", "base", "offset", "badbytes", "align",
    "arch",
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
    /// Threads in the scan pool (`--scan-threads`). Default
    /// `num_cpus - 1`, so the server never takes every core.
    pub scan_threads: usize,
    /// Engine gadget budget (`--max-gadgets`). `None` = unbounded.
    pub max_gadgets: Option<usize>,
    /// In-memory cache budget (`--cache-mem-mb`) and entry lifetime
    /// (`--cache-ttl-secs`) — MCP-05/ROB-07.
    pub cache_mem_bytes: u64,
    pub cache_ttl: Duration,
    /// How long a scan stays pinned so an outstanding cursor can page it
    /// (`--cursor-ttl-secs`).
    pub cursor_ttl: Duration,
    /// `--workspace-dir`: where a paged scan's NDJSON is materialized as a
    /// real file. Must lie OUTSIDE every allow root, which `main.rs`
    /// enforces at startup.
    pub workspace_dir: Option<PathBuf>,
    /// JSONL call/denial log (`--audit-log`), and its rotation size.
    pub audit_log: Option<PathBuf>,
    pub audit_log_max_mb: u64,
    /// Consecutive `path_denied` results before the probing signal trips.
    /// 0 disables it.
    pub probe_threshold: u64,
    /// Cap on `get_binary_info`'s `sections`/`imports` arrays.
    pub max_info_items: usize,
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
            scan_threads: guard::default_scan_threads(),
            max_gadgets: Some(DEFAULT_MAX_GADGETS),
            cache_mem_bytes: DEFAULT_CACHE_MEM_BYTES,
            cache_ttl: DEFAULT_CACHE_TTL,
            cursor_ttl: DEFAULT_CURSOR_TTL,
            workspace_dir: None,
            audit_log: None,
            audit_log_max_mb: audit::DEFAULT_AUDIT_MAX_MB,
            probe_threshold: DEFAULT_PROBE_THRESHOLD,
            max_info_items: DEFAULT_MAX_INFO_ITEMS,
            verbose_path_errors: false,
        }
    }
}

/// Structured tool error, rendered as
/// `{error: {code, message, retryable, details, suggestion}}`.
///
/// CRIT-03: `code` is the CLOSED [`ErrorCode`] set, and every field of the
/// rendered body is always present. `kind` is a FINER tag that never
/// reaches the client: it is what the audit log records, so collapsing
/// `file_too_large` and `busy` into one wire code loses the operator
/// nothing. The two spellings the audit found — `usage` in one place and
/// `usage_error` everywhere else — cannot recur, because there is no longer
/// a place to write a code as a free string.
#[derive(Debug)]
pub struct ToolError {
    pub code: ErrorCode,
    /// Finer-grained internal reason, for the audit log and for the two
    /// places the server branches on it. Defaults to `code.as_str()`.
    pub kind: &'static str,
    pub message: String,
    /// Machine-readable specifics (allow roots, breached limits). Never
    /// carries an OS error string for a path outside the allowlist.
    pub details: Option<Value>,
    /// Whether re-sending the same request could succeed.
    pub retryable: bool,
    /// An arguments patch that would make the call work.
    pub suggestion: Option<Value>,
}

impl ToolError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        ToolError {
            code,
            kind: code.as_str(),
            message: message.into(),
            details: None,
            retryable: code.default_retryable(),
            suggestion: None,
        }
    }

    pub(crate) fn with_details(
        code: ErrorCode,
        message: impl Into<String>,
        details: Value,
    ) -> Self {
        ToolError {
            details: Some(details),
            ..ToolError::new(code, message)
        }
    }

    /// Record a finer reason than the wire code carries.
    #[must_use]
    pub(crate) fn with_kind(mut self, kind: &'static str) -> Self {
        self.kind = kind;
        self
    }

    #[must_use]
    pub(crate) fn retryable(mut self, yes: bool) -> Self {
        self.retryable = yes;
        self
    }

    #[must_use]
    pub(crate) fn with_suggestion(mut self, suggestion: Value) -> Self {
        self.suggestion = Some(suggestion);
        self
    }

    /// The `timeout` a worker did not stop for. Distinguished here rather
    /// than by a separate wire code, so the closed set stays closed.
    #[must_use]
    pub fn is_hard_timeout(&self) -> bool {
        self.code == ErrorCode::Timeout && self.kind == "timeout_hard"
    }

    fn to_json(&self) -> Value {
        json!({"error": {
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "details": self.details.clone().unwrap_or_else(|| json!({})),
            "suggestion": self.suggestion.clone().unwrap_or(Value::Null),
        }})
    }
}

// ---------------------------------------------------------------------------
// Cache (content-hash → gadget list)
// ---------------------------------------------------------------------------

// `CachedGadget` and `CachedScan` are `rf_cache`'s, not this crate's —
// see the `use` at the top of the file. The record, the checked hex
// decoder, the `validate()` that runs on every deserialize, and the
// on-disk half of this cache are shared with rf-cli. That sharing is the
// point of the change: the ROB-04 char-boundary panic existed here *and*
// at rf-cli/src/lib.rs because there were two copies of the same twenty
// lines. The serialized shape is unchanged — the fields only rf-cli fills
// are skipped when empty, so a gadget in a tool response still carries
// exactly vaddr/bytes/text plus the optional arch/section/quality/class.

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

// [`Cache`] itself is [`cache::Cache`]: both halves bounded, the memory
// half a byte-weighted LRU that lives in rf-cache so the CLI shares it
// (MCP-05/ROB-07, CLI-08/PERF-12).

// ---------------------------------------------------------------------------
// Shared parameter structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
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
    /// Maximum gadgets returned per page (default 1000, hard max 50000).
    pub max_results: Option<usize>,
    /// Result ordering, applied BEFORE paging. "rank" (the default) is
    /// usability tier, then quality, then fewest instructions, then fewest
    /// side effects, then address — it is what puts `pop rdi ; ret` at the
    /// top instead of `adc al, 0x89 ; retf 0xc281`. Also "address",
    /// "quality" and "text" (the pre-0.3 default). Anything else is
    /// rejected with the valid set in the error.
    pub order: Option<String>,
    /// Deprecated alias for `order`, kept because it used to be the only
    /// way to ask for anything but traversal order. Ignored when `order`
    /// is given.
    pub sort_by: Option<String>,
    /// `next_cursor` from a previous page of THIS query. Re-send every
    /// other parameter unchanged; `max_results` and `timeout_secs` may
    /// change. A cursor from a different query returns `cursor_expired`.
    pub cursor: Option<String>,
    /// Keep only gadgets whose primary class is one of these
    /// (comma-separated): reg-write, stack-pivot, mem-read, mem-write,
    /// arithmetic, syscall, dispatcher, other.
    pub class: Option<String>,
    /// Keep only gadgets carrying at least one of these labels (same
    /// vocabulary as `class`; a gadget can earn several).
    pub label: Option<String>,
    /// Keep only gadgets that write ALL of these registers
    /// (comma-separated, e.g. "rdi"). Names are matched lowercase and
    /// without a `$`/`%` sigil.
    pub writes_reg: Option<String>,
    /// Keep only gadgets that read ALL of these registers.
    pub reads_reg: Option<String>,
    /// Keep only gadgets that write NONE of these registers — "do not
    /// clobber rsi or rdx".
    pub preserves_regs: Option<String>,
    /// Require the `writes_reg` registers to be loaded off the STACK (a
    /// pop, or a stack-based load), which is what makes them controllable
    /// from the chain payload. With no `writes_reg`, requires at least one
    /// stack-loaded register.
    pub from_stack: Option<bool>,
    /// Keep only gadgets with this terminator. Comma-separated any-of,
    /// case-insensitive: the coarse kind "ret"
    /// (every returning form), "jmp", "call", "syscall", "none", "any"
    /// (no constraint), or a CLS-09 class -- "bare-ret" (the plain near
    /// return, which coarse "ret" is a superset of), "ret-imm",
    /// "jmp-reg", "jmp-mem", "call-reg", "call-mem", "far", "other".
    pub terminator: Option<String>,
    /// Keep only gadgets with at most this many side effects.
    pub max_side_effects: Option<u32>,
    /// Keep only gadgets with at most this many instructions.
    pub max_insns: Option<u32>,
    /// ECO-01: keep only gadgets that SET all of these registers — write
    /// them with a value the chain PAYLOAD decides. Strictly stronger than
    /// `writes_reg`: `xor rdi, rdi ; ret` writes rdi and sets nothing.
    pub set_reg: Option<String>,
    /// ECO-01: none of these registers may be CLOBBERED — written with a
    /// value the payload does not decide. Matched against the classifier's
    /// `clobbers`, NOT `regs_written`: `pop rdi ; ret` survives
    /// `no_clobber: ["rdi"]` and `mov rdi, rax ; ret` does not. Elements
    /// may also be comma-separated.
    pub no_clobber: Option<Vec<String>>,
    /// ECO-01: keep only gadgets whose net stack movement is KNOWN and at
    /// most this many bytes (the terminator's own pop included, so
    /// `pop rdi ; ret` is 16 on x86-64). A gadget whose delta is unknown is
    /// REJECTED, never assumed to be 0.
    pub max_stack_delta: Option<i64>,
    /// ECO-12: the stack-pivot preset — keep only gadgets carrying the
    /// `stack-pivot` label.
    pub pivot: Option<bool>,
    /// ECO-01: ropper-style wildcard matcher over the instruction
    /// SEQUENCE, e.g. "pop rdi; ret". `?` is one character, `%` is any run
    /// inside one instruction (so a bare `%` is any single instruction).
    /// The instructions must appear as a contiguous run, so
    /// "pop rdi; ret" also matches "xor eax, eax ; pop rdi ; ret".
    pub search: Option<String>,
    /// Architecture slice for a fat (Universal) Mach-O, e.g. "x86_64",
    /// "arm64", "i386". REQUIRED for a multi-slice container: without it
    /// the scan is refused rather than concatenating slices whose virtual
    /// address ranges overlap (CORE-03).
    pub arch: Option<String>,
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
        // `.first()`, not `[0]`: a fat container with no slices is a
        // malformed input, not a reason to abort the server.
        LoadedBinary::Universal(u) => u.slices().first().map(Image::arch),
        LoadedBinary::Raw(b) => Some(Image::arch(&b)),
    }
}

// Ordering used to live here as `sort_by_quality`, which re-derived a
// missing quality score from the cached bytes on every call. That path is
// gone: [`semantics::classify_scan`] computes the whole classification once
// per scan and the pinned-scan store keeps it, so nothing re-classifies
// inside a response any more. ROB-04's char-boundary panic lived on exactly
// that path.

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
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
    /// Maximum gadgets returned per page (default 1000, hard max 50000).
    pub max_results: Option<usize>,
    /// Result ordering; see find_gadgets. Default "rank".
    pub order: Option<String>,
    /// `next_cursor` from a previous page of THIS query.
    pub cursor: Option<String>,
    /// Keep only gadgets whose primary class is one of these.
    pub class: Option<String>,
    /// Keep only gadgets carrying at least one of these labels.
    pub label: Option<String>,
    /// Keep only gadgets that write ALL of these registers.
    pub writes_reg: Option<String>,
    /// Keep only gadgets that read ALL of these registers.
    pub reads_reg: Option<String>,
    /// Keep only gadgets that write NONE of these registers.
    pub preserves_regs: Option<String>,
    /// Require the `writes_reg` registers to come off the stack.
    pub from_stack: Option<bool>,
    /// Terminator kind: "ret", "jmp", "call", "syscall", "none", "any",
    /// or a CLS-09 class ("bare-ret", "ret-imm", "jmp-reg", "jmp-mem",
    /// "call-reg", "call-mem", "far", "other").
    pub terminator: Option<String>,
    pub max_side_effects: Option<u32>,
    pub max_insns: Option<u32>,
    /// ECO-01: keep only gadgets that SET all of these registers — write
    /// them with a value the chain PAYLOAD decides. Strictly stronger than
    /// `writes_reg`: `xor rdi, rdi ; ret` writes rdi and sets nothing.
    pub set_reg: Option<String>,
    /// ECO-01: none of these registers may be CLOBBERED — written with a
    /// value the payload does not decide. Matched against the classifier's
    /// `clobbers`, NOT `regs_written`: `pop rdi ; ret` survives
    /// `no_clobber: ["rdi"]` and `mov rdi, rax ; ret` does not. Elements
    /// may also be comma-separated.
    pub no_clobber: Option<Vec<String>>,
    /// ECO-01: keep only gadgets whose net stack movement is KNOWN and at
    /// most this many bytes (the terminator's own pop included, so
    /// `pop rdi ; ret` is 16 on x86-64). A gadget whose delta is unknown is
    /// REJECTED, never assumed to be 0.
    pub max_stack_delta: Option<i64>,
    /// ECO-12: the stack-pivot preset — keep only gadgets carrying the
    /// `stack-pivot` label.
    pub pivot: Option<bool>,
    /// ECO-01: ropper-style wildcard matcher over the instruction
    /// SEQUENCE, e.g. "pop rdi; ret". `?` is one character, `%` is any run
    /// inside one instruction (so a bare `%` is any single instruction).
    /// The instructions must appear as a contiguous run, so
    /// "pop rdi; ret" also matches "xor eax, eax ; pop rdi ; ret".
    pub search: Option<String>,
    /// Architecture slice for a fat (Universal) Mach-O, e.g. "x86_64",
    /// "arm64", "i386". REQUIRED for a multi-slice container: without it
    /// the scan is refused rather than concatenating slices whose virtual
    /// address ranges overlap (CORE-03).
    pub arch: Option<String>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

/// ECO-01 — the constraint search, as one call.
///
/// This is MCP-DESIGN's usefulness bar item 15: "set rdi from the stack,
/// preserve rsi and rdx, at most one side effect, clean ret" expressed
/// once and answered with a small correct set, instead of a thousand
/// alphabetically-ordered records beginning with `adc al, 0x89 ; retf
/// 0xc281`.
///
/// Every filter here is also available on `find_gadgets`; this tool exists
/// because a *named* tool whose whole parameter list is the question is
/// what an agent finds, and because it scans ROP+JOP+SYS together so
/// `terminator` decides the family instead of the tool name doing it.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EffectQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// Search depth (default 10).
    pub depth: Option<usize>,

    // ---- the constraint vocabulary (shared with the CLI's long flags) ----
    /// The gadget must SET this register — write it with a value the chain
    /// PAYLOAD decides. Several may be given, comma-separated, and all are
    /// required. Strictly stronger than `writes_reg`: `xor rdi, rdi ; ret`
    /// writes rdi and sets nothing.
    pub set_reg: Option<String>,
    /// The `set_reg` write must ORIGINATE on the stack — a pop, or a load
    /// through the stack pointer — rather than in an arbitrary
    /// computation. With no `set_reg` it falls back to `writes_reg`, and
    /// with neither it means "at least one register comes off the stack".
    pub from_stack: Option<bool>,
    /// None of these registers may be CLOBBERED. Matched against the
    /// classifier's `clobbers`, NOT `regs_written`, which is the
    /// difference between "this gadget destroys rdi" and "this gadget
    /// loads rdi from your payload". Elements may be comma-separated.
    pub no_clobber: Option<Vec<String>>,
    /// The gadget must read ALL of these registers.
    pub reads_reg: Option<String>,
    /// Net stack movement must be KNOWN and at most this many bytes, the
    /// terminator's own pop included (`pop rdi ; ret` is 16 on x86-64). An
    /// unknown delta is REJECTED, never read as 0 — `xchg rsp, rax ; ret`
    /// must not slip into a layout budget.
    pub max_stack_delta: Option<i64>,
    /// At most this many side effects (instructions that earn a label).
    pub max_side_effects: Option<u32>,
    /// At most this many instructions.
    pub max_insns: Option<u32>,
    /// Terminator: the coarse kind "ret" (every returning form), "jmp",
    /// "call", "syscall", "none", "any"; or the CLS-09 class "ret-imm",
    /// "jmp-reg", "jmp-mem", "call-reg", "call-mem", "far", "other".
    pub terminator: Option<String>,
    /// Ropper-style wildcard matcher over the instruction SEQUENCE, e.g.
    /// "pop rdi; ret". `?` is one character, `%` is any run inside one
    /// instruction (a bare `%` is any single instruction). The pattern must
    /// appear as a CONTIGUOUS run, so it also matches
    /// "xor eax, eax ; pop rdi ; ret".
    pub search: Option<String>,
    /// ECO-12: the stack-pivot preset — only gadgets carrying the
    /// `stack-pivot` label. Combine with `max_stack_delta` to rank pivots
    /// by reach.
    pub pivot: Option<bool>,
    /// Primary class: reg-write, stack-pivot, mem-read, mem-write,
    /// arithmetic, syscall, dispatcher, other (comma-separated).
    pub class: Option<String>,
    /// At least one of these labels (same vocabulary as `class`).
    pub label: Option<String>,
    /// The gadget must WRITE all of these registers — the v0.3 spelling,
    /// satisfied by any write. `set_reg` is the one you usually want.
    pub writes_reg: Option<String>,
    /// The gadget must write NONE of these registers, matched against
    /// `regs_written`. Coarser than `no_clobber` and kept because every
    /// other gadget tool has it.
    pub preserves_regs: Option<String>,

    // ---- scan shaping, identical to find_gadgets ----
    /// Executable section name(s); comma-separated, `*` globbing.
    pub section: Option<String>,
    /// Rebase the image base at load time (hex string).
    pub base: Option<String>,
    /// Offset added to gadget addresses after any rebase (hex string).
    pub offset: Option<String>,
    /// Address range to scan, "0xSTART-0xEND".
    pub range: Option<String>,
    /// Reject gadgets whose final address contains these bytes.
    pub badbytes: Option<String>,
    /// Maximum gadgets returned per page (default 1000, hard max 50000).
    pub max_results: Option<usize>,
    /// Result ordering; see find_gadgets. Default "rank".
    pub order: Option<String>,
    /// `next_cursor` from a previous page of THIS query.
    pub cursor: Option<String>,
    /// Architecture slice for a fat (Universal) Mach-O. REQUIRED for a
    /// multi-slice container.
    pub arch: Option<String>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RawCommandQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// ROPgadget-style flags, e.g. ["--depth", "6", "--only", "pop|ret"].
    /// Restricted to the allowlist: --depth --norop --nojop --nosys --only
    /// --filter --re --range --section --base --offset --badbytes --align
    /// --multibr --json. Anything else is rejected.
    pub args: Vec<String>,
    /// Maximum gadgets returned per page (default 1000, hard max 50000).
    pub max_results: Option<usize>,
    /// Result ordering; see find_gadgets. Default "rank".
    pub order: Option<String>,
    /// `next_cursor` from a previous page of THIS query.
    pub cursor: Option<String>,
    /// Keep only gadgets whose primary class is one of these.
    pub class: Option<String>,
    /// Keep only gadgets carrying at least one of these labels.
    pub label: Option<String>,
    /// Keep only gadgets that write ALL of these registers.
    pub writes_reg: Option<String>,
    /// Keep only gadgets that read ALL of these registers.
    pub reads_reg: Option<String>,
    /// Keep only gadgets that write NONE of these registers.
    pub preserves_regs: Option<String>,
    /// Require the `writes_reg` registers to come off the stack.
    pub from_stack: Option<bool>,
    /// Terminator kind: "ret", "jmp", "call", "syscall", "none", "any",
    /// or a CLS-09 class ("bare-ret", "ret-imm", "jmp-reg", ...).
    pub terminator: Option<String>,
    pub max_side_effects: Option<u32>,
    pub max_insns: Option<u32>,
    /// ECO-01: keep only gadgets that SET all of these registers — write
    /// them with a value the chain PAYLOAD decides. Strictly stronger than
    /// `writes_reg`: `xor rdi, rdi ; ret` writes rdi and sets nothing.
    pub set_reg: Option<String>,
    /// ECO-01: none of these registers may be CLOBBERED — written with a
    /// value the payload does not decide. Matched against the classifier's
    /// `clobbers`, NOT `regs_written`: `pop rdi ; ret` survives
    /// `no_clobber: ["rdi"]` and `mov rdi, rax ; ret` does not. Elements
    /// may also be comma-separated.
    pub no_clobber: Option<Vec<String>>,
    /// ECO-01: keep only gadgets whose net stack movement is KNOWN and at
    /// most this many bytes (the terminator's own pop included, so
    /// `pop rdi ; ret` is 16 on x86-64). A gadget whose delta is unknown is
    /// REJECTED, never assumed to be 0.
    pub max_stack_delta: Option<i64>,
    /// ECO-12: the stack-pivot preset — keep only gadgets carrying the
    /// `stack-pivot` label.
    pub pivot: Option<bool>,
    /// ECO-01: ropper-style wildcard matcher over the instruction
    /// SEQUENCE, e.g. "pop rdi; ret". `?` is one character, `%` is any run
    /// inside one instruction (so a bare `%` is any single instruction).
    /// The instructions must appear as a contiguous run, so
    /// "pop rdi; ret" also matches "xor eax, eax ; pop rdi ; ret".
    pub search: Option<String>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

/// `get_gadgets` — resolve stable ids back to full records.
///
/// This is what lets an agent say "build a chain from g_ab12 and g_cd34"
/// rather than re-sending gadget text and hoping the server parses it the
/// same way.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct IdsQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// Stable gadget ids, as returned in `gadgets[].id` (e.g.
    /// "g_ab12cd34ef56gh78"). Ids that do not resolve are reported in
    /// `warnings` rather than failing the call.
    pub ids: Vec<String>,
    /// Search depth the ids were found at (default 10). An id from a
    /// depth-10 scan will not resolve in a depth-4 one.
    pub depth: Option<usize>,
    /// Rebase the image base at load time (hex string). Must match the
    /// scan the ids came from: an id is independent of every scan
    /// parameter EXCEPT `base`, which relabels the whole address space.
    pub base: Option<String>,
    /// Offset added to gadget addresses after any rebase (hex string).
    pub offset: Option<String>,
    /// Executable section name(s); comma-separated, `*` globbing.
    pub section: Option<String>,
    /// Architecture slice for a fat (Universal) Mach-O.
    pub arch: Option<String>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

/// CLI-05 / ECO-02 — `find_string`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct StringQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// The pattern, as a BYTE regex (ROPgadget's `--string` semantics), so
    /// "/bin/sh" is a literal and "m..n" is four bytes. Matched only
    /// against MAPPED sections.
    pub string: String,
    /// ROPgadget's `--memstr` instead of `--string`: locate each CHARACTER
    /// of `string` separately and report only the FIRST place each one
    /// occurs, searching executable sections before data ones. This is how
    /// you assemble a string you cannot find contiguously. Default false.
    pub memstr: Option<bool>,
    /// Rebase the image base before reporting addresses (hex string, e.g.
    /// "0x400000"; "0" for RVAs).
    pub base: Option<String>,
    /// Offset added to reported addresses after any rebase (hex string).
    pub offset: Option<String>,
    /// Restrict the search to this address range, "0xSTART-0xEND". It can
    /// only ever NARROW the mapped windows, never widen them.
    pub range: Option<String>,
    /// Maximum hits returned per page (default 1000, hard max 50000).
    pub max_results: Option<usize>,
    /// `next_cursor` from a previous page of THIS query.
    pub cursor: Option<String>,
    /// Architecture slice for a fat (Universal) Mach-O. REQUIRED for a
    /// multi-slice container, whose slices' addresses overlap.
    pub arch: Option<String>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

/// CLI-05 / ECO-02 — `find_bytes`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct BytesQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// The byte sequence as hex, e.g. "c9c3" or "c9 c3". `??` matches any
    /// one byte, so "ff??e0" finds `jmp rax` through `jmp r15`. A nibble
    /// wildcard is refused rather than silently widened.
    pub opcode: String,
    /// Rebase the image base before reporting addresses (hex string).
    pub base: Option<String>,
    /// Offset added to reported addresses after any rebase (hex string).
    pub offset: Option<String>,
    /// Restrict the search to this address range, "0xSTART-0xEND".
    pub range: Option<String>,
    /// Maximum hits returned per page (default 1000, hard max 50000).
    pub max_results: Option<usize>,
    /// `next_cursor` from a previous page of THIS query.
    pub cursor: Option<String>,
    /// Architecture slice for a fat (Universal) Mach-O. REQUIRED for a
    /// multi-slice container.
    pub arch: Option<String>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

/// ECO-06 — `get_mitigations`.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MitigationsQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct InfoQuery {
    /// Absolute path to the binary; must be inside one of the server's
    /// allow_roots (get_server_config lists them).
    pub binary_path: String,
    /// Rebase the image base before reporting addresses (hex string).
    pub base: Option<String>,
    /// Maximum sections reported (default 4096). A larger array is
    /// truncated and `warnings` carries `sections_truncated`.
    pub max_sections: Option<usize>,
    /// Maximum imports reported (default 4096). A larger array is
    /// truncated and `warnings` carries `imports_truncated`.
    pub max_imports: Option<usize>,
    /// Maximum ELF symbols reported. Symbols are OPT-IN: the default is 0
    /// because a symbol table is unbounded by the file's structure (2169 on
    /// elf-Linux-x64) where `sections` and `imports` are not, and returning
    /// it by default cost 80k tokens on the first call of a task. Pass a
    /// number to get them, up to max_info_items (4096). `symbol_count`
    /// always reports the true total and `warnings` carries
    /// `symbols_truncated`, so a short list is never indistinguishable from
    /// a binary with few symbols. `imports` is NOT affected by this.
    pub max_symbols: Option<usize>,
    /// Per-request timeout in seconds (default 60, max 300).
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
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
    /// windows-virtualprotect: which API to call — "VirtualProtect"
    /// (default) or "VirtualAlloc". Picks the IAT import to resolve and
    /// the argument recipe; the two do not take the same four arguments.
    pub api_name: Option<String>,
    /// windows-virtualprotect: runtime shellcode address (hex; default:
    /// the binary's writable .data section).
    pub shellcode_addr: Option<String>,
    /// windows-virtualprotect: dwSize argument (hex; default 0x1000).
    pub shellcode_size: Option<String>,
    /// windows-virtualprotect (x64): what the alignment invariant may
    /// assume about the chain's first word — "return_address" (default)
    /// or "aligned". Echoed back in `assumptions`.
    pub chain_base: Option<String>,
    /// flNewProtect / flProtect (hex; default 0x40 =
    /// PAGE_EXECUTE_READWRITE) for windows-virtualprotect, or
    /// linux-mprotect's `prot` (default 7 = PROT_READ|WRITE|EXEC).
    pub prot: Option<String>,
    /// linux-syscall: the syscall number to invoke, and the syscall the
    /// linux-srop frame carries. Decimal, or hex with an explicit "0x".
    pub syscall: Option<String>,
    /// linux-syscall / linux-srop: argument registers, e.g.
    /// "rdi=0x404000,rsi=0x1000,rdx=7" (values are hex).
    pub syscall_args: Option<String>,
    /// CHWIN-08: pivot the stack pointer here before the chain body runs
    /// (hex). The chain is then in two pieces — `assumptions.pivot_words`
    /// leading words go at the overflow point, the rest at this address.
    pub chain_pivot: Option<String>,
    /// CHWIN-08: shellcode bytes (hex, e.g. "9090cc") to WRITE into the
    /// region at shellcode_addr with write-what-where gadgets instead of
    /// assuming they are already there.
    pub stage: Option<String>,
    /// Architecture slice for a fat (Universal) Mach-O, e.g. "x86_64",
    /// "arm64", "i386". REQUIRED for a multi-slice container: without it
    /// the scan is refused rather than concatenating slices whose virtual
    /// address ranges overlap (CORE-03).
    pub arch: Option<String>,
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
    /// --re post-filter (regex over gadget text). This one really is a
    /// post-filter in ROPgadget too (options.py:22-33).
    pub re: Option<String>,
}

/// ANCH-02 - parse `--align` the way ROPgadget's argparse does.
///
/// ROPgadget declares `--align` as `type=int`, i.e. DECIMAL. rf-mcp used to
/// hand the value to `rf_cli::parse_hex`, which strips an optional `0x` and
/// then always parses base 16, so `--align 16` meant 0x16 = 22 - a
/// different, and for a power-of-two request nonsensical, alignment.
/// Decimal first; hexadecimal only when the caller writes an explicit `0x`,
/// which no ROPgadget user would but an MCP client echoing an address
/// literal might.
pub fn parse_align(v: &str) -> Result<usize, String> {
    let t = v.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        if hex.is_empty() {
            return Err(format!("invalid --align {v:?}: no digits after 0x"));
        }
        return usize::from_str_radix(hex, 16).map_err(|e| format!("invalid --align {v:?}: {e}"));
    }
    t.parse::<usize>()
        .map_err(|e| format!("invalid --align {v:?}: {e}"))
}

/// Validate `args` against the PLAN §6.1 allowlist and map them onto a
/// [`rf_cli::ScanRequest`]. Anything outside the allowlist is rejected.
pub fn parse_ropgadget_args(args: &[String]) -> Result<ParsedArgs, ToolError> {
    let mut req = rf_cli::ScanRequest::default();
    let mut re = None;
    let mut i = 0;
    while i < args.len() {
        let Some(arg) = args.get(i) else { break };
        let Some(stripped) = arg.strip_prefix("--") else {
            return Err(usage_flag(format!(
                "unexpected positional argument {arg:?}; only --flags are accepted"
            )));
        };
        let (name, inline_val) = match stripped.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (stripped, None),
        };
        if !ALLOWED_FLAGS.contains(&name) {
            return Err(usage_flag(format!(
                "flag --{name} is not allowed; allowlist: {}",
                ALLOWED_FLAGS
                    .iter()
                    .map(|f| format!("--{f}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )));
        }
        let takes_value = VALUE_FLAGS.contains(&name);
        let value = if takes_value {
            match inline_val {
                Some(v) => Some(v),
                None => {
                    i += 1;
                    let Some(v) = args.get(i) else {
                        return Err(usage_flag(format!("flag --{name} requires a value")));
                    };
                    if v.starts_with("--") {
                        return Err(usage_flag(format!(
                            "flag --{name} requires a value (got {v:?})"
                        )));
                    }
                    Some(v.clone())
                }
            }
        } else {
            if inline_val.is_some() {
                return Err(usage_flag(format!("flag --{name} does not take a value")));
            }
            None
        };
        match name {
            "depth" => {
                req.depth = value.unwrap().parse().map_err(|_| {
                    ToolError::new(ErrorCode::UsageError, "invalid --depth value".to_string())
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
            "arch" => req.arch = value,
            "all" => req.all = true,
            "callPreceded" => req.call_preceded = true,
            "align" => {
                // ANCH-02: a real engine option, not an address post-filter.
                let v = value.unwrap();
                req.align =
                    Some(parse_align(&v).map_err(|e| ToolError::new(ErrorCode::UsageError, e))?);
            }
            _ => unreachable!("allowlist checked above"),
        }
        i += 1;
    }
    Ok(ParsedArgs { request: req, re })
}

/// Collect the semantic filter parameters out of a query.
///
/// `GadgetQuery`, `SearchQuery`, `RawCommandQuery` and `EffectQuery` carry
/// the same fields under the same names — the nine CLS-08 ones plus v0.4's
/// `set_reg` / `no_clobber` / `max_stack_delta` / `pivot` / `search`
/// (ECO-01, ECO-12) — so one spelling covers all four without a trait whose
/// only job is to re-export fourteen getters. Keeping them uniform is what
/// makes `find_gadgets_by_effect` a preset over the same predicate rather
/// than a second, divergent filter.
macro_rules! raw_filter {
    ($q:expr) => {
        semantics::RawFilter {
            class: $q.class.as_deref(),
            label: $q.label.as_deref(),
            writes_reg: $q.writes_reg.as_deref(),
            reads_reg: $q.reads_reg.as_deref(),
            preserves_regs: $q.preserves_regs.as_deref(),
            from_stack: $q.from_stack,
            terminator: $q.terminator.as_deref(),
            max_side_effects: $q.max_side_effects,
            max_insns: $q.max_insns,
            set_reg: $q.set_reg.as_deref(),
            no_clobber: $q.no_clobber.as_deref().unwrap_or(&[]),
            max_stack_delta: $q.max_stack_delta,
            pivot: $q.pivot,
            search: $q.search.as_deref(),
        }
    };
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
        arch: q.arch.clone(),
        max_gadgets: None,
        max_memory: None,
        // The MCP server never runs the bug-for-bug ROPgadget fallback: an
        // agent cannot inspect the output to notice that most of it is
        // fabricated, so a fat Mach-O without `arch` is always refused.
        compat: false,
    }
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

/// Everything [`RopFinderMcp::run_find`] needs, so the two search tools
/// differ by a `mode` and a pattern rather than by twelve arguments.
struct FindRequest {
    binary_path: String,
    mode: find::Mode,
    /// The pattern as the caller wrote it, echoed back in `query`.
    query: String,
    base: Option<String>,
    offset: Option<String>,
    range: Option<String>,
    arch: Option<String>,
    max_results: Option<usize>,
    cursor: Option<String>,
    params_hash: String,
    timeout_secs: Option<u64>,
}

/// Address padding width for a search hit, in bytes.
///
/// ROPgadget's search modes pad to 8 hex digits on `CS_MODE_32` and 16
/// otherwise (core.py:113), which is the pointer size everywhere except a
/// RAW arm/thumb blob, whose capstone mode is `CS_MODE_ARM`/`CS_MODE_THUMB`
/// rather than `CS_MODE_32` — so those print 16 digits despite 4-byte
/// pointers (raw.py:54-67). Reproduced so a hit's address column matches
/// the CLI's and the oracle's.
fn search_addr_size(target: &rf_cli::Target, arch: rf_core::Arch) -> usize {
    if matches!(target, rf_cli::Target::Raw(_))
        && matches!(arch, rf_core::Arch::Arm | rf_core::Arch::ArmThumb)
    {
        return 8;
    }
    arch.addr_size()
}

/// Post-scan options applied over the cached gadget set.
struct PostOpts {
    /// Regex/substring filter over gadget text (`--re`).
    ///
    /// `--align` used to live here as an address post-filter. It does not
    /// any more (ANCH-02): dropping unaligned addresses out of an align=1
    /// scan is not what ROPgadget's `--align` does - the oracle also
    /// multiplies the backward depth stride by N, so post-filtering a
    /// depth-10 align-1 run can never expose a gadget reaching more than 9
    /// bytes back. `--align` is now `ScanRequest::align`, which reaches
    /// `rf_scan::ScanOptions::align` and steps the scan itself.
    re: Option<String>,
    /// Ordering applied before paging. Default [`Order::Rank`].
    order: Order,
    /// The semantic predicate (CLS-08).
    filter: GadgetFilter,
    /// `cursor` as the client sent it, still to be validated.
    cursor: Option<String>,
    /// Fingerprint of the parameters that decide the result set, so a
    /// cursor from another query is refused rather than spliced in.
    params_hash: String,
    /// Response page size (`max_results`), clamped to the server cap.
    max_results: Option<usize>,
    /// Per-request timeout, clamped to the server cap.
    timeout_secs: Option<u64>,
    /// `get_gadgets` only: resolve exactly these stable ids, in this order.
    ids: Option<Vec<String>>,
}

impl Default for PostOpts {
    fn default() -> Self {
        PostOpts {
            re: None,
            order: Order::Rank,
            filter: GadgetFilter::default(),
            cursor: None,
            params_hash: String::new(),
            max_results: None,
            timeout_secs: None,
            ids: None,
        }
    }
}

#[derive(Clone)]
pub struct RopFinderMcp {
    config: Arc<ServerConfig>,
    cache: Arc<Cache>,
    /// Allow roots with their directory handles pinned for the lifetime of
    /// the process (MCP-01).
    roots: Arc<Vec<AllowRoot>>,
    /// MCP-03/PERF-06: the concurrency bound, the cancellation bridge and
    /// the scan thread pool. Every tool goes through it.
    guard: Arc<Guard>,
    stats: Arc<ServerStats>,
    /// MCP-09: the JSONL call/denial log, when `--audit-log` was given.
    audit: Option<Arc<AuditLog>>,
    /// MCP-09: warn/error forwarded as `notifications/message`, because
    /// MCP hosts discard the server's stderr.
    notifier: Arc<Notifier>,
    /// One uuid per process, stamped on every audit line.
    session: Arc<str>,
}

impl RopFinderMcp {
    /// Build the server, opening and pinning every `config.allow_dirs`
    /// entry. Fails if a root cannot be opened, if the scan pool cannot be
    /// built, or if `--audit-log` cannot be written — an audit log the
    /// operator asked for and did not get is worse than none.
    pub fn new(config: ServerConfig) -> std::io::Result<Self> {
        let mut roots = Vec::with_capacity(config.allow_dirs.len());
        for d in &config.allow_dirs {
            let root = AllowRoot::open(d)?;
            if roots.iter().any(|r: &AllowRoot| r.id() == root.id()) {
                continue;
            }
            roots.push(root);
        }
        let session: Arc<str> = Arc::from(uuid::Uuid::new_v4().to_string().as_str());
        let audit = match &config.audit_log {
            None => None,
            Some(p) => Some(Arc::new(AuditLog::open(
                p,
                config.audit_log_max_mb,
                session.to_string(),
            )?)),
        };
        let cache = Cache::new(
            config.cache_dir.clone(),
            rf_cache::MemLimits {
                max_bytes: config.cache_mem_bytes,
                ttl: config.cache_ttl,
            },
            config.cursor_ttl,
        );
        let stats = Arc::new(ServerStats::default());
        let guard = Guard::new(config.max_concurrent, config.scan_threads, stats.clone())
            .map_err(std::io::Error::other)?;
        Ok(RopFinderMcp {
            config: Arc::new(config),
            cache: Arc::new(cache),
            roots: Arc::new(roots),
            guard: Arc::new(guard),
            stats,
            audit,
            notifier: Arc::new(Notifier::new()),
            session,
        })
    }

    /// The session uuid stamped on every audit line.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session
    }

    /// Counters, for tests and for `get_server_stats`.
    #[must_use]
    pub fn stats(&self) -> &ServerStats {
        &self.stats
    }

    #[must_use]
    pub fn notifier(&self) -> &Notifier {
        &self.notifier
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
                ErrorCode::UsageError,
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
    ///
    /// It also publishes the two enumerations CRIT-03 closed: every `order`
    /// and every `ErrorCode`. An agent that can read the taxonomy does not
    /// have to discover it by provoking failures.
    fn config_response(&self) -> schema::ConfigResponse {
        schema::ConfigResponse {
            allow_roots: self.root_paths(),
            max_depth: self.config.max_depth as u64,
            max_file_bytes: self.config.max_file_bytes,
            max_results: self.config.max_results as u64,
            hard_max_results: HARD_MAX_RESULTS as u64,
            max_concurrent: self.config.max_concurrent as u64,
            scan_threads: self.guard.scan_threads() as u64,
            max_gadgets: self.config.max_gadgets.map(|g| g as u64),
            max_sections: self.config.max_info_items as u64,
            max_imports: self.config.max_info_items as u64,
            timeout_secs: self.config.timeout.as_secs(),
            cache: self.config.cache_dir.is_some(),
            cache_mem_max_bytes: self.config.cache_mem_bytes,
            cache_ttl_secs: self.config.cache_ttl.as_secs(),
            cursor_ttl_secs: self.config.cursor_ttl.as_secs(),
            workspace_dir: self
                .config
                .workspace_dir
                .as_ref()
                .map(|p| p.display().to_string()),
            audit_log: self.audit.is_some(),
            probe_threshold: self.config.probe_threshold,
            orders: semantics::ORDER_NAMES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            error_codes: ErrorCode::all()
                .iter()
                .map(|c| c.as_str().to_string())
                .collect(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
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

    /// A future that resolves when the client sends
    /// `notifications/cancelled` for this request.
    ///
    /// rmcp cancels `RequestContext::ct`; [`guard::Guard::run`] bridges that
    /// to the engine's [`rf_scan::CancelToken`]. Before this the server
    /// accepted the notification and did nothing with it, and the
    /// depth-100000 request that had already been cancelled was at
    /// 54,873 MB RSS thirteen seconds later.
    fn cancel_signal(ctx: &RequestContext<RoleServer>) -> guard::CancelSignal {
        let ct = ctx.ct.clone();
        Box::pin(async move {
            ct.cancelled().await;
        })
    }

    /// Start a tool call: register the peer for operator notifications,
    /// count the request, and open the audit record that will be written
    /// exactly once whatever happens next.
    fn begin(
        &self,
        ctx: &RequestContext<RoleServer>,
        tool: &'static str,
        params_hash: String,
    ) -> (AuditRecord, Instant) {
        self.notifier.register(&ctx.peer);
        self.stats.record_request(tool);
        let req_id = ctx.id.to_string();
        tracing::debug!(tool, req_id = %req_id, "tool call");
        (AuditRecord::new(req_id, tool, params_hash), Instant::now())
    }

    /// Finish a tool call: classify the outcome, maintain the probing
    /// signal, write the ONE audit line, and render the response.
    async fn finish<T: Serialize>(
        &self,
        mut rec: AuditRecord,
        started: Instant,
        out: Result<T, ToolError>,
    ) -> Result<CallToolResult, McpError> {
        let verdict = match &out {
            Ok(_) => Verdict::Ok,
            Err(e) => {
                // The audit records the FINE reason (`file_too_large`,
                // `timeout_hard`, `busy`), not the closed wire code, so
                // collapsing the taxonomy for the agent costs the operator
                // nothing.
                rec.code = Some(e.kind.to_string());
                Verdict::for_code(e.kind)
            }
        };
        rec.verdict = verdict.as_str();
        let suspected = self
            .stats
            .record_verdict(verdict, self.config.probe_threshold);
        rec.probing_suspected = suspected;
        rec.duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;

        // The operator, who never sees stderr, is told about the two
        // conditions that mean something is wrong with the server or with
        // the client driving it.
        if let Err(e) = &out {
            if e.is_hard_timeout() {
                self.notifier.error(
                    "worker_wedged",
                    "a cancelled scan did not stop within the hard-join window",
                    json!({"tool": rec.tool, "wedged_total": self.stats.wedged_now()}),
                );
            }
        }
        if suspected {
            self.notifier.warn(
                "path_probing",
                "consecutive path_denied results suggest an agent is enumerating the filesystem",
                json!({"denied_consecutive": self.stats.denied_consecutive_now(),
                       "threshold": self.config.probe_threshold,
                       "requested": rec.binary}),
            );
        }

        if let Some(log) = &self.audit {
            log.write(&rec);
        }

        // MCP-09: once probing is suspected every response is delayed, so
        // a filesystem walk costs the caller wall-clock time. A legitimate
        // agent has read get_server_config and generates no denials, so it
        // never pays this.
        if suspected {
            tokio::time::sleep(PROBE_DELAY).await;
        }

        match out {
            Ok(v) => tool_ok(&v),
            Err(e) => tool_error(e),
        }
    }

    /// Run a scan with confinement + caps + cache, on the shared guard,
    /// then filter, order and page the result (CLS-08, CRIT-03,
    /// MCP-DESIGN fix #8).
    ///
    /// MCP-03/PERF-06: `guard.run` cancels the WORK on timeout and joins
    /// it before releasing the permit. The three ad-hoc
    /// `tokio::time::timeout(_, spawn_blocking(_))` blocks this replaces
    /// abandoned the await and left the scan running.
    async fn run_scan(
        &self,
        ctx: &RequestContext<RoleServer>,
        rec: &mut AuditRecord,
        req: rf_cli::ScanRequest,
        binary_path: &str,
        post: PostOpts,
    ) -> Result<ScanResponse, ToolError> {
        let PostOpts {
            re: post_re,
            order,
            filter,
            cursor: cursor_in,
            params_hash,
            max_results,
            timeout_secs,
            ids,
        } = post;
        // MCP-01: an open HANDLE, not a name, crosses into the worker.
        rec.binary = Some(binary_path.to_string());
        let confined = self.open_confined(binary_path)?;
        // Inside a root: log the root-relative label, not the caller's
        // spelling of the path.
        rec.binary = Some(confined.label.clone());
        let binary_label = confined.label.clone();
        let declared_len = confined.len;
        let max = clamp_max_results(max_results, self.config.max_results);
        let timeout = clamp_timeout(timeout_secs, self.config.timeout);
        let cache = self.cache.clone();
        let max_file_bytes = self.config.max_file_bytes;
        let max_gadgets = self.config.max_gadgets;
        let workspace = self.config.workspace_dir.clone();

        let work =
            move |cancel: rf_scan::CancelToken| -> Result<(ScanResponse, ScanFacts), ToolError> {
                let bytes = confined.read_all(max_file_bytes)?;
                let file_hash = sha256_hex(&bytes);
                // CLI-01/ENG-05, the MCP half: every parameter that can change
                // the output is in the key, or two different requests share an
                // entry and one of them is served the other's answer. `align`
                // and `arch` change WHAT IS SCANNED (ANCH-02, CORE-03);
                // `max_gadgets`/`max_memory` TRUNCATE a result, so a bounded
                // scan must never be served for an unbounded query; `compat`
                // decides whether a multi-slice container is scanned at all.
                // `rf_cache::make_key` folds in the key-schema version, so the
                // next addition to this list makes old entries MISS.
                //
                // `rec=3` is this crate's own record version, and it is here
                // because v0.3 started storing `delay_slot` in the MCP cache
                // record. A v0.2 entry has the field absent, which deserializes
                // to `false` — and `false` is a MEANINGFUL value on MIPS. The
                // discriminator makes every pre-0.3 entry miss rather than
                // report a wrong delay slot.
                let key = rf_cache::make_key(
                    &file_hash,
                    &format!(
                        "depth={}|rop={}|jop={}|sys={}|multibr={}|only={}|filter={}|range={}|\
                     badbytes={}|offset={}|section={:?}|thumb={}|base={}|cfg_aware={}|\
                     align={:?}|arch={}|all={}|noinstr={}|call_preceded={}|\
                     max_gadgets={:?}|max_memory={:?}|compat={}|rec=3",
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
                        req.cfg_aware,
                        req.align,
                        req.arch.as_deref().unwrap_or(""),
                        req.all,
                        req.noinstr,
                        req.call_preceded,
                        req.max_gadgets.or(max_gadgets),
                        req.max_memory,
                        req.compat,
                    ),
                );
                // The id is computed over the address with `--offset` undone,
                // so it does not change when the caller shifts the reported
                // addresses.
                let offset = match &req.offset {
                    Some(o) => rf_cli::parse_hex(o, "--offset")
                        .map_err(|e| ToolError::new(ErrorCode::UsageError, e))?,
                    None => 0,
                };
                let class_arch = arch_from_bytes(&bytes);
                let mut warnings: Vec<Warning> = Vec::new();

                // Three ways to get the gadget set, cheapest first. The pinned
                // store is what a cursor's next page hits: it holds the scan
                // AND its semantics, so paging a 40,872-gadget walk does not
                // reclassify the set once per page.
                let (scan, sems, cache_status) = if let Some(p) = cache.pinned(&key) {
                    // A pinned entry is a cache hit that also kept its semantics; the
                    // difference is invisible to the caller and observable to an
                    // operator as `cache.pinned_entries`.
                    (p.scan, p.sems, "hit")
                } else if let Some(hit) = cache.get(&key) {
                    let sems = Arc::new(semantics::classify_scan(
                        &hit, &file_hash, offset, class_arch,
                    ));
                    cache.pin(&key, hit.clone(), sems.clone());
                    (hit, sems, "hit")
                } else {
                    let product =
                        scan::scan_bytes_cancellable(&bytes, &req, &cancel, max_gadgets, None)
                            .map_err(scan::ScanFail::to_tool_error)?;
                    let arch = product.universal_arch.map(rf_cli::arch_name);
                    let addr_size = product.addr_size;
                    let selected = product.selected_sections;
                    let id_ctx = semantics::IdContext {
                        binary_sha256: &file_hash,
                        offset,
                    };
                    // CLS-08: classify ONCE, here, and keep all of it. The old
                    // code classified in exactly this loop and then stored two
                    // fields of the result.
                    let classifier = class_arch.map(rf_classify::Classifier::new);
                    let mut gadgets = Vec::with_capacity(product.gadgets.len());
                    let mut built = Vec::with_capacity(product.gadgets.len());
                    for g in &product.gadgets {
                        let cls = classifier.as_ref().map(|c| c.classify(g));
                        gadgets.push(CachedGadget {
                            vaddr: rf_cli::fmt_addr(g.vaddr, addr_size),
                            bytes: g.bytes_hex(),
                            text: g.text(),
                            arch: arch.map(str::to_string),
                            section: selected
                                .as_deref()
                                .and_then(|s| rf_cli::section_of(s, g.vaddr.wrapping_sub(offset))),
                            quality: cls.as_ref().map(|c| c.quality),
                            class: cls.as_ref().map(|c| c.primary.name().to_string()),
                            // CRIT-03: `delay_slot` is computed by the engine
                            // and was dropped at every output boundary, so a
                            // MIPS gadget reached the agent with no sign that
                            // its last instruction runs BEFORE the branch.
                            delay_slot: g.delay_slot,
                            ..CachedGadget::default()
                        });
                        built.push(semantics::from_scan_gadget(g, cls, &id_ctx));
                    }
                    let arc = cache.put(
                        &key,
                        CachedScan {
                            gadgets,
                            fallback_names: product.fallback_names,
                            ..CachedScan::default()
                        },
                    );
                    let sems = Arc::new(built);
                    cache.pin(&key, arc.clone(), sems.clone());
                    (arc, sems, "miss")
                };

                // ---- select -------------------------------------------------
                let mut idx: Vec<usize> = match &ids {
                    Some(want) => {
                        let mut by_id: std::collections::HashMap<&str, usize> =
                            std::collections::HashMap::with_capacity(sems.len());
                        for (i, s) in sems.iter().enumerate() {
                            by_id.entry(s.id.as_str()).or_insert(i);
                        }
                        let mut out = Vec::with_capacity(want.len());
                        let mut missing: Vec<&str> = Vec::new();
                        for id in want {
                            match by_id.get(id.as_str()) {
                                Some(&i) => out.push(i),
                                None => missing.push(id.as_str()),
                            }
                        }
                        if !missing.is_empty() {
                            warnings.push(
                                Warning::truncation(
                                    "ids_not_found",
                                    "gadgets",
                                    out.len(),
                                    want.len(),
                                )
                                .with_detail(missing.join(",")),
                            );
                        }
                        out
                    }
                    None => (0..scan.gadgets.len()).collect(),
                };
                // The only surviving text post-filter is --re, which is a
                // post-filter in ROPgadget too. --align is an engine option
                // (ANCH-02) and has already been applied by the scan above.
                if let Some(re) = &post_re {
                    match regex::Regex::new(re) {
                        Ok(re) => idx
                            .retain(|&i| scan.gadgets.get(i).is_some_and(|g| re.is_match(&g.text))),
                        Err(_) => idx.retain(|&i| {
                            scan.gadgets
                                .get(i)
                                .is_some_and(|g| g.text.contains(re.as_str()))
                        }),
                    }
                }
                if !filter.is_empty() {
                    idx.retain(|&i| sems.get(i).is_some_and(|s| filter.matches(s)));
                }
                semantics::sort_indices(&mut idx, order, &scan, &sems);

                // ---- page ---------------------------------------------------
                let total = idx.len() as u64;
                let start = match &cursor_in {
                    Some(raw) => Cursor::decode(raw, &key, order.as_str(), &params_hash)?.offset,
                    None => 0,
                };
                let page: Vec<usize> = idx
                    .iter()
                    .skip(usize::try_from(start).unwrap_or(usize::MAX))
                    .take(max)
                    .copied()
                    .collect();
                let gadgets: Vec<GadgetRecord> = page
                    .iter()
                    .filter_map(|&i| Some(GadgetRecord::build(scan.gadgets.get(i)?, sems.get(i)?)))
                    .collect();
                let returned = gadgets.len() as u64;
                let truncated = start.saturating_add(returned) < total;

                // ---- warnings ------------------------------------------------
                if scan.fallback_names {
                    warnings.push(Warning::new(
                        "fallback_section_names",
                        "the binary has no section names; synthetic PT_LOAD#n names were matched \
                     instead, so `section` values are positional rather than real",
                    ));
                }
                if let Some(slice) = scan.gadgets.first().and_then(|g| g.arch.clone()) {
                    warnings.push(
                        Warning::new(
                            "universal_slice_selected",
                            "this is one slice of a fat (Universal) Mach-O; addresses are that \
                         slice's",
                        )
                        .with_detail(slice),
                    );
                }
                if gadgets.iter().any(|g| g.low_confidence) {
                    warnings.push(Warning::new(
                        "low_confidence_classification",
                        "some gadgets were classified from disassembly text rather than decoder \
                     metadata; treat class/labels/regs on those as advisory",
                    ));
                }
                if truncated {
                    warnings.push(Warning::truncation(
                        "truncated",
                        "gadgets",
                        usize::try_from(returned).unwrap_or(usize::MAX),
                        usize::try_from(total).unwrap_or(usize::MAX),
                    ));
                }

                // ---- resources -----------------------------------------------
                let paged = total > returned;
                let resource_uri = paged.then(|| resources::scan_uri(&key));
                let workspace_file = match (&workspace, paged) {
                    (Some(dir), true) => {
                        resources::ensure_file(dir, &key, || resources::render_ndjson(&scan, &sems))
                            .map(|p| p.display().to_string())
                    }
                    _ => None,
                };

                let facts = ScanFacts {
                    sha256: file_hash.clone(),
                    bytes_read: bytes.len() as u64,
                    cache: cache_status,
                    total_count: total,
                    returned,
                };
                Ok((
                    ScanResponse {
                        gadgets,
                        total_count: total,
                        returned,
                        offset: start,
                        truncated,
                        next_cursor: Cursor::next(
                            &key,
                            order.as_str(),
                            &params_hash,
                            start,
                            returned,
                            total,
                        ),
                        order: order.as_str().to_string(),
                        binary_sha256: file_hash,
                        binary_label,
                        cache: cache_status.to_string(),
                        cache_key: key,
                        fallback_section_names: scan.fallback_names,
                        warnings,
                        resource_uri,
                        workspace_file,
                    },
                    facts,
                ))
            };

        let out = self
            .guard
            .run(Some(Self::cancel_signal(ctx)), timeout, work)
            .await;
        match out {
            Ok((v, facts)) => {
                facts.apply(rec);
                self.stats.add_bytes_read(facts.bytes_read);
                Ok(v)
            }
            Err(e) => {
                // The read never completed, so nothing was read; the
                // declared size is still worth recording for a timeout.
                rec.bytes_read = 0;
                tracing::debug!(code = e.kind, declared_len, "tool call failed");
                Err(e)
            }
        }
    }

    /// CLI-05 / ECO-02 — the body of `find_string` and `find_bytes`.
    ///
    /// Everything a gadget scan gets, a search gets: the same confined
    /// handle, the same guard (so it is cancellable, timed out and
    /// semaphore-bounded), the same cursor contract and the same NDJSON
    /// resource (ECO-09). What it does NOT get is the file: every byte it
    /// examines comes out of a [`rf_core::Section`] the loader
    /// materialised, which is the property that makes exposing this
    /// through the MCP safe at all (see [`crate::find`]).
    async fn run_find(
        &self,
        ctx: &RequestContext<RoleServer>,
        rec: &mut AuditRecord,
        opts: FindRequest,
    ) -> Result<find::SearchHitsResponse, ToolError> {
        let FindRequest {
            binary_path,
            mode,
            query,
            base,
            offset,
            range,
            arch,
            max_results,
            cursor: cursor_in,
            params_hash,
            timeout_secs,
        } = opts;

        // A bad pattern is the caller's mistake, so it is diagnosed BEFORE
        // a file is opened, a permit is taken or a byte is read.
        let byte_pattern = match mode {
            find::Mode::Opcode => Some(find::BytePattern::parse(&query)?),
            _ => None,
        };

        rec.binary = Some(binary_path.clone());
        let confined = self.open_confined(&binary_path)?;
        rec.binary = Some(confined.label.clone());
        let binary_label = confined.label.clone();
        let base_value = base
            .as_deref()
            .map(|b| rf_cli::parse_hex(b, "base"))
            .transpose()
            .map_err(|e| ToolError::new(ErrorCode::UsageError, e))?;
        let offset_value = offset
            .as_deref()
            .map(|o| rf_cli::parse_hex(o, "offset"))
            .transpose()
            .map_err(|e| ToolError::new(ErrorCode::UsageError, e))?
            .unwrap_or(0);
        let range_value = range
            .as_deref()
            .map(rf_cli::parse_range)
            .transpose()
            .map_err(|e| ToolError::new(ErrorCode::UsageError, e))?
            .flatten();
        let page = clamp_max_results(max_results, self.config.max_results);
        let timeout = clamp_timeout(timeout_secs, self.config.timeout);
        let max_file_bytes = self.config.max_file_bytes;
        let workspace = self.config.workspace_dir.clone();
        let cache = self.cache.clone();

        let work = move |_cancel: rf_scan::CancelToken| -> Result<
            (find::SearchHitsResponse, ScanFacts),
            ToolError,
        > {
            let bytes = confined.read_all(max_file_bytes)?;
            let file_hash = sha256_hex(&bytes);
            let target = rf_cli::load_target(&bytes, None).map_err(scan_err_to_tool)?;
            // CORE-03: a fat container is refused rather than searched as a
            // concatenation, exactly as a scan of one is.
            let selected = rf_cli::resolve_arch(&target, arch.as_deref(), false)
                .map_err(scan_err_to_tool)?;
            let slice = match (&target, selected) {
                (rf_cli::Target::Universal(u), Some(a)) => {
                    Some(u.select(a).map_err(|e| {
                        ToolError::new(ErrorCode::UsageError, e.to_string())
                    })?)
                }
                _ => None,
            };
            let view = rf_cli::build_view_selected(&target, selected);
            let image_base = view.base;
            let delta = base_value.map_or(0, |b| b.wrapping_sub(image_base));
            let opts = find::SearchOpts {
                delta,
                offset: offset_value,
                range: range_value,
                addr_size: search_addr_size(&target, rf_core::Image::arch(&view)),
                // Collect up to the hard cap so `total_count` and the
                // cursor walk agree; the PAGE is `max_results`.
                max_hits: HARD_MAX_RESULTS,
            };
            let windows = match mode {
                find::Mode::String => find::data_windows(&target, slice, delta),
                find::Mode::Opcode => find::exec_windows(&target, slice, delta),
                // core.py:202-227 — exec sections first, then data.
                find::Mode::MemStr => {
                    let mut w = find::exec_windows(&target, slice, delta);
                    w.extend(find::data_windows(&target, slice, delta));
                    w
                }
            };
            let sections_searched = find::window_names(&windows);
            let mut warnings: Vec<Warning> = Vec::new();
            if windows.is_empty() {
                warnings.push(Warning::new(
                    "no_mapped_sections",
                    "this container exposes no mapped section of the kind this search reads, \
                     so the answer is empty by construction rather than by absence",
                ));
            }

            let (all_hits, total) = match (mode, &byte_pattern) {
                (find::Mode::String, _) => find::find_string(&windows, &query, &opts)?,
                (find::Mode::MemStr, _) => find::find_memstr(&windows, &query, &opts),
                (find::Mode::Opcode, Some(p)) => find::find_opcode(&windows, p, &opts),
                // `byte_pattern` is built above for exactly this mode.
                (find::Mode::Opcode, None) => {
                    return Err(ToolError::new(
                        ErrorCode::Internal,
                        "the opcode pattern was not compiled",
                    ))
                }
            };
            if total > all_hits.len() as u64 {
                warnings.push(Warning::truncation(
                    "hits_capped",
                    "hits",
                    all_hits.len(),
                    usize::try_from(total).unwrap_or(usize::MAX),
                ));
            }

            // The cursor key names this exact result set: the file, the
            // mode and every parameter that decides which bytes were read.
            let key = format!(
                "s{}",
                rf_cache::sha256_hex(
                    format!(
                        "{file_hash}|{}|{query}|base={base_value:?}|offset={offset_value}|\
                         range={range_value:?}|arch={}",
                        mode.as_str(),
                        arch.as_deref().unwrap_or("")
                    )
                    .as_bytes()
                )
            );
            let walkable = all_hits.len() as u64;
            let start = match &cursor_in {
                Some(raw) => Cursor::decode(raw, &key, "address", &params_hash)?.offset,
                None => 0,
            };
            let hits: Vec<find::Hit> = all_hits
                .iter()
                .skip(usize::try_from(start).unwrap_or(usize::MAX))
                .take(page)
                .cloned()
                .collect();
            let returned = hits.len() as u64;
            let truncated = start.saturating_add(returned) < total;
            if truncated {
                warnings.push(Warning::truncation(
                    "truncated",
                    "hits",
                    usize::try_from(returned).unwrap_or(usize::MAX),
                    usize::try_from(total).unwrap_or(usize::MAX),
                ));
            }

            // ECO-09: a paged answer also names the WHOLE set as NDJSON,
            // pinned in the same bounded store a paged scan uses.
            let paged = walkable > returned;
            let (resource_uri, workspace_file) = if paged {
                let ndjson = find::render_ndjson(&all_hits);
                cache.pin_text(&key, &ndjson);
                let file = workspace
                    .as_deref()
                    .and_then(|dir| resources::ensure_file(dir, &key, || ndjson.clone()))
                    .map(|p| p.display().to_string());
                (Some(resources::search_uri(&key)), file)
            } else {
                (None, None)
            };

            let facts = ScanFacts {
                sha256: file_hash.clone(),
                bytes_read: bytes.len() as u64,
                cache: "none",
                total_count: total,
                returned,
            };
            Ok((
                find::SearchHitsResponse {
                    hits,
                    mode: mode.as_str().to_string(),
                    query: query.clone(),
                    total_count: total,
                    returned,
                    offset: start,
                    truncated,
                    next_cursor: Cursor::next(
                        &key,
                        "address",
                        &params_hash,
                        start,
                        returned,
                        walkable,
                    ),
                    sections_searched,
                    binary_sha256: file_hash,
                    binary_label,
                    warnings,
                    resource_uri,
                    workspace_file,
                },
                facts,
            ))
        };

        match self
            .guard
            .run(Some(Self::cancel_signal(ctx)), timeout, work)
            .await
        {
            Ok((v, facts)) => {
                facts.apply(rec);
                self.stats.add_bytes_read(facts.bytes_read);
                Ok(v)
            }
            Err(e) => {
                rec.bytes_read = 0;
                Err(e)
            }
        }
    }

    /// ECO-06 — the body of `get_mitigations`.
    async fn run_mitigations(
        &self,
        ctx: &RequestContext<RoleServer>,
        rec: &mut AuditRecord,
        q: &MitigationsQuery,
    ) -> Result<checksec::MitigationsResponse, ToolError> {
        rec.binary = Some(q.binary_path.clone());
        let confined = self.open_confined(&q.binary_path)?;
        rec.binary = Some(confined.label.clone());
        let label = confined.label.clone();
        let timeout = clamp_timeout(q.timeout_secs, self.config.timeout);
        let max_file_bytes = self.config.max_file_bytes;

        let work = move |_cancel: rf_scan::CancelToken| -> Result<
            (checksec::MitigationsResponse, ScanFacts),
            ToolError,
        > {
            let bytes = confined.read_all(max_file_bytes)?;
            let file_hash = sha256_hex(&bytes);
            let target = rf_cli::load_target(&bytes, None).map_err(scan_err_to_tool)?;
            let out = checksec::report(&target, file_hash.clone(), label);
            let facts = ScanFacts {
                sha256: file_hash,
                bytes_read: bytes.len() as u64,
                cache: "none",
                total_count: 0,
                returned: 0,
            };
            Ok((out, facts))
        };

        match self
            .guard
            .run(Some(Self::cancel_signal(ctx)), timeout, work)
            .await
        {
            Ok((v, facts)) => {
                rec.binary_sha256 = Some(facts.sha256.clone());
                rec.bytes_read = facts.bytes_read;
                rec.cache = Some("none");
                self.stats.add_bytes_read(facts.bytes_read);
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }

    /// `get_binary_info` (MCP-06): the one tool that used to have neither a
    /// timeout nor a cap, and that did its whole-file read plus goblin
    /// parse INLINE on the async runtime, occupying a tokio worker.
    async fn run_info(
        &self,
        ctx: &RequestContext<RoleServer>,
        rec: &mut AuditRecord,
        q: &InfoQuery,
    ) -> Result<InfoResponse, ToolError> {
        rec.binary = Some(q.binary_path.clone());
        let confined = self.open_confined(&q.binary_path)?;
        rec.binary = Some(confined.label.clone());
        let base = q
            .base
            .as_deref()
            .map(|b| rf_cli::parse_hex(b, "--base"))
            .transpose()
            .map_err(|e| ToolError::new(ErrorCode::UsageError, e))?;
        let timeout = clamp_timeout(q.timeout_secs, self.config.timeout);
        let max_file_bytes = self.config.max_file_bytes;
        let cap = self.config.max_info_items;
        let max_sections = q.max_sections.unwrap_or(cap).clamp(1, cap);
        let max_imports = q.max_imports.unwrap_or(cap).clamp(1, cap);
        let max_symbols = q.max_symbols.unwrap_or(DEFAULT_MAX_SYMBOLS).min(cap);

        let work =
            move |_cancel: rf_scan::CancelToken| -> Result<(InfoResponse, ScanFacts), ToolError> {
                let bytes = confined.read_all(max_file_bytes)?;
                let file_hash = sha256_hex(&bytes);
                let mut v = rf_cli::info_bytes(&bytes, None, base).map_err(scan_err_to_tool)?;
                let warnings = truncate_info(&mut v, max_sections, max_imports, max_symbols);
                let out = InfoResponse::from_value(v, file_hash.clone(), warnings);
                let facts = ScanFacts {
                    sha256: file_hash,
                    bytes_read: bytes.len() as u64,
                    cache: "none",
                    total_count: 0,
                    returned: 0,
                };
                Ok((out, facts))
            };

        match self
            .guard
            .run(Some(Self::cancel_signal(ctx)), timeout, work)
            .await
        {
            Ok((v, facts)) => {
                rec.binary_sha256 = Some(facts.sha256.clone());
                rec.bytes_read = facts.bytes_read;
                rec.cache = Some("none");
                self.stats.add_bytes_read(facts.bytes_read);
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }

    /// Build a ROP chain with confinement + the shared guard. Unlike scans,
    /// chain builds are not cache-backed (a chain is a single compact
    /// artifact, and its inputs — the scan — would have to be re-validated
    /// anyway).
    async fn run_chain(
        &self,
        ctx: &RequestContext<RoleServer>,
        rec: &mut AuditRecord,
        q: ChainQuery,
    ) -> Result<ChainResponse, ToolError> {
        if !rf_cli::chain_targets().contains(&q.target.as_str()) {
            return Err(ToolError::new(
                ErrorCode::UsageError,
                format!(
                    "unknown chain target {:?}; supported: {}",
                    q.target,
                    rf_cli::chain_targets().join(", ")
                ),
            ));
        }
        let depth = self.check_depth(q.depth)?;
        rec.binary = Some(q.binary_path.clone());
        let confined = self.open_confined(&q.binary_path)?;
        rec.binary = Some(confined.label.clone());
        let label = confined.label.clone();
        let timeout = clamp_timeout(q.timeout_secs, self.config.timeout);
        let max_file_bytes = self.config.max_file_bytes;
        let req = chain_scan_request(&q, depth, self.config.max_gadgets);
        let spec = chain_spec(&q);
        // ECO-02: the target's parameters are validated by the SAME
        // functions the CLI uses, before the scan, so an unknown api_name /
        // chain_base / syscall_args value is a usage error on both surfaces
        // with the same accepted set (tests/capability_matrix.py gates it).
        if spec.target == "windows-virtualprotect" {
            rf_cli::win_opts(&spec).map_err(scan_err_to_tool)?;
        } else {
            rf_cli::linux_opts(&spec).map_err(scan_err_to_tool)?;
        }

        // NOTE (MCP-03, residual): `rf_cli::chain_bytes` runs its own scan
        // and has no token seam, so a chain build is bounded by the
        // timeout and the join rather than interrupted mid-scan. `depth`
        // is already capped at `--max-depth`, and a worker that does not
        // stop within the hard-join window is reported as `timeout_hard`
        // and counted in `wedged_total` rather than silently orphaned.
        // The seam closes when rf-cli grows `chain_bytes_cancellable`
        // (MCP-DESIGN fix #4 part C).
        let binary_label = label.clone();
        let offset_hex = q.offset.clone();
        let work =
            move |_cancel: rf_scan::CancelToken| -> Result<(ChainResponse, ScanFacts), ToolError> {
                let bytes = confined.read_all(max_file_bytes)?;
                let file_hash = sha256_hex(&bytes);
                let outcome =
                    rf_cli::chain_bytes(&bytes, None, &req, &spec).map_err(scan_err_to_tool)?;
                let offset = match &offset_hex {
                    Some(o) => rf_cli::parse_hex(o, "--offset")
                        .map_err(|e| ToolError::new(ErrorCode::UsageError, e))?,
                    None => 0,
                };
                let facts = ScanFacts {
                    sha256: file_hash.clone(),
                    bytes_read: bytes.len() as u64,
                    cache: "bypass",
                    total_count: outcome.chain.words.len() as u64,
                    returned: outcome.chain.words.len() as u64,
                };
                let out = chain_response(&outcome, file_hash, binary_label, offset);
                Ok((out, facts))
            };

        match self
            .guard
            .run(Some(Self::cancel_signal(ctx)), timeout, work)
            .await
        {
            Ok((v, facts)) => {
                facts.apply(rec);
                self.stats.add_bytes_read(facts.bytes_read);
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }

    /// `ECO-04`: the feasibility report. Never fails for a reason the
    /// binary is responsible for — an infeasible chain is a `feasible:
    /// false` document with the requirement that failed, what was tried,
    /// and which parameter changes the server MEASURED would help.
    async fn run_plan(
        &self,
        ctx: &RequestContext<RoleServer>,
        rec: &mut AuditRecord,
        q: ChainQuery,
    ) -> Result<schema::PlanResponse, ToolError> {
        if !rf_cli::chain_targets().contains(&q.target.as_str()) {
            return Err(ToolError::new(
                ErrorCode::UsageError,
                format!(
                    "unknown chain target {:?}; supported: {}",
                    q.target,
                    rf_cli::chain_targets().join(", ")
                ),
            ));
        }
        let depth = self.check_depth(q.depth)?;
        rec.binary = Some(q.binary_path.clone());
        let confined = self.open_confined(&q.binary_path)?;
        rec.binary = Some(confined.label.clone());
        let label = confined.label.clone();
        let timeout = clamp_timeout(q.timeout_secs, self.config.timeout);
        let max_file_bytes = self.config.max_file_bytes;
        let req = chain_scan_request(&q, depth, self.config.max_gadgets);
        let spec = chain_spec(&q);
        if spec.target == "windows-virtualprotect" {
            rf_cli::win_opts(&spec).map_err(scan_err_to_tool)?;
        } else {
            rf_cli::linux_opts(&spec).map_err(scan_err_to_tool)?;
        }
        let binary_label = label.clone();
        let offset_hex = q.offset.clone();
        let work = move |_cancel: rf_scan::CancelToken| -> Result<
            (schema::PlanResponse, ScanFacts),
            ToolError,
        > {
            let bytes = confined.read_all(max_file_bytes)?;
            let file_hash = sha256_hex(&bytes);
            let offset = match &offset_hex {
                Some(o) => rf_cli::parse_hex(o, "--offset")
                    .map_err(|e| ToolError::new(ErrorCode::UsageError, e))?,
                None => 0,
            };
            let outcome =
                rf_cli::plan_chain_bytes(&bytes, None, &req, &spec).map_err(scan_err_to_tool)?;
            let out = plan_response(&outcome, file_hash.clone(), binary_label, offset);
            let facts = ScanFacts {
                sha256: file_hash,
                bytes_read: bytes.len() as u64,
                cache: "bypass",
                total_count: out.requirements.len() as u64,
                returned: out.satisfied_requirements.len() as u64,
            };
            Ok((out, facts))
        };
        match self
            .guard
            .run(Some(Self::cancel_signal(ctx)), timeout, work)
            .await
        {
            Ok((v, facts)) => {
                facts.apply(rec);
                self.stats.add_bytes_read(facts.bytes_read);
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }
}

/// What a worker learned that the audit line needs and the response body
/// does not carry in a fixed place.
struct ScanFacts {
    sha256: String,
    bytes_read: u64,
    cache: &'static str,
    total_count: u64,
    returned: u64,
}

impl ScanFacts {
    fn apply(&self, rec: &mut AuditRecord) {
        rec.binary_sha256 = Some(self.sha256.clone());
        rec.bytes_read = self.bytes_read;
        rec.cache = Some(self.cache);
        rec.total_count = Some(self.total_count);
        rec.returned = Some(self.returned);
    }
}

/// MCP-06: cap `sections` and `imports`, returning the `warnings` entries.
///
/// A hostile PE with a million import entries must not be able to make the
/// server serialize a gigabyte of JSON into an agent's context. Truncation
/// is announced rather than silent: an agent that sees
/// `imports_truncated` knows the list is partial, where a silently short
/// list would be indistinguishable from a binary with few imports.
fn truncate_info(
    v: &mut Value,
    max_sections: usize,
    max_imports: usize,
    max_symbols: usize,
) -> Vec<Warning> {
    let mut warnings = Vec::new();
    let Some(obj) = v.as_object_mut() else {
        return warnings;
    };
    for (field, cap, code) in [
        ("sections", max_sections, "sections_truncated"),
        ("imports", max_imports, "imports_truncated"),
        // ECO-06: `symbol_count` is deliberately NOT truncated with the
        // array, so the response always states how many there really were.
        ("symbols", max_symbols, "symbols_truncated"),
    ] {
        let Some(Value::Array(a)) = obj.get_mut(field) else {
            continue;
        };
        let total = a.len();
        if total > cap {
            a.truncate(cap);
            let mut w = Warning::truncation(code, field, cap, total);
            if field == "symbols" {
                // The symbols default is 0 (see DEFAULT_MAX_SYMBOLS), so this
                // warning is the ONLY thing telling an agent the table exists
                // and how to ask for it. Say so rather than leaving `returned:
                // 0` to be read as "there are none".
                w.detail = Some(
                    "symbols are opt-in: pass max_symbols (up to 4096) to include them.                      `imports` (the SHN_UNDEF subset, with GOT/PLT) is reported regardless."
                        .to_string(),
                );
            }
            warnings.push(w);
        }
    }
    warnings
}

/// `ChainQuery` is `Deserialize` but not `Clone` (it is a wire type, and
/// deriving `Clone` on it would put a second copy of every future field in
/// the schema's derive chain). `build_rop_chain` needs one extra copy to
/// re-probe with, so the copy is spelled out here where a new field makes
/// it a compile error rather than a silently dropped parameter.
fn clone_query(q: &ChainQuery) -> ChainQuery {
    ChainQuery {
        binary_path: q.binary_path.clone(),
        target: q.target.clone(),
        depth: q.depth,
        base: q.base.clone(),
        offset: q.offset.clone(),
        badbytes: q.badbytes.clone(),
        cfg_aware: q.cfg_aware,
        api_addr: q.api_addr.clone(),
        api_name: q.api_name.clone(),
        shellcode_addr: q.shellcode_addr.clone(),
        shellcode_size: q.shellcode_size.clone(),
        chain_base: q.chain_base.clone(),
        prot: q.prot.clone(),
        syscall: q.syscall.clone(),
        syscall_args: q.syscall_args.clone(),
        chain_pivot: q.chain_pivot.clone(),
        stage: q.stage.clone(),
        arch: q.arch.clone(),
        timeout_secs: q.timeout_secs,
    }
}

/// The `ScanRequest` a chain build / plan runs its scan with. One place,
/// so `build_rop_chain` and `plan_chain` cannot answer about two different
/// gadget universes.
fn chain_scan_request(
    q: &ChainQuery,
    depth: usize,
    max_gadgets: Option<usize>,
) -> rf_cli::ScanRequest {
    rf_cli::ScanRequest {
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
        arch: q.arch.clone(),
        max_gadgets,
        max_memory: None,
        compat: false,
    }
}

/// The `ChainSpec` for a query. Shared by `build_rop_chain` and
/// `plan_chain`, and identical field for field to what the CLI builds from
/// its flags (ECO-02).
fn chain_spec(q: &ChainQuery) -> rf_cli::ChainSpec {
    rf_cli::ChainSpec {
        target: q.target.clone(),
        api_addr: q.api_addr.clone(),
        api_name: q.api_name.clone(),
        shellcode_addr: q.shellcode_addr.clone(),
        shellcode_size: q.shellcode_size.clone(),
        chain_base: q.chain_base.clone(),
        prot: q.prot.clone(),
        syscall: q.syscall.clone(),
        syscall_args: q.syscall_args.clone(),
        pivot: q.chain_pivot.clone(),
        stage: q.stage.clone(),
    }
}

/// `ECO-04`: the plan, with every satisfying gadget carrying the same
/// stable id `find_gadgets` handed out — so `get_gadgets` resolves it.
fn plan_response(
    outcome: &rf_cli::ChainPlanOutcome,
    binary_sha256: String,
    binary_label: String,
    offset: u64,
) -> schema::PlanResponse {
    let mut plan = outcome.plan.clone();
    let sha = binary_sha256.clone();
    plan.attach_gadget_ids(|vaddr| {
        outcome
            .gadget_bytes(vaddr)
            .map(|b| schema::gadget_id(&sha, vaddr.wrapping_sub(offset), b))
    });
    schema::PlanResponse::from_plan(&plan, binary_sha256, binary_label)
}

/// Build the chain response, giving every referenced gadget the same stable
/// id `find_gadgets` would.
///
/// The chain IR carries only `{vaddr, text}` per gadget, and an id needs the
/// gadget's BYTES — so they are recovered from the scan the chain was built
/// from, which `rf_cli::chain_bytes` hands back. Where a gadget cannot be
/// matched the id is `null` rather than fabricated.
fn chain_response(
    outcome: &rf_cli::ChainOutcome,
    binary_sha256: String,
    binary_label: String,
    offset: u64,
) -> ChainResponse {
    let chain = &outcome.chain;
    let by_vaddr: std::collections::HashMap<u64, &[u8]> = outcome
        .outcome
        .result
        .gadgets
        .iter()
        .map(|g| (g.vaddr, g.bytes.as_slice()))
        .collect();
    let gadgets = chain
        .gadgets
        .iter()
        .map(|g| schema::ChainGadgetRef {
            vaddr: format!("0x{:x}", g.vaddr),
            vaddr_u64: g.vaddr,
            text: g.text.clone(),
            id: by_vaddr
                .get(&g.vaddr)
                .map(|b| schema::gadget_id(&binary_sha256, g.vaddr.wrapping_sub(offset), b)),
        })
        .collect();
    let words = chain
        .words
        .iter()
        .map(|w| schema::ChainWordRecord {
            value: format!("0x{:x}", w.value),
            kind: match w.kind {
                rf_chain::WordKind::GadgetAddr => "gadget_addr",
                rf_chain::WordKind::Immediate => "immediate",
                rf_chain::WordKind::DataAddr => "data_addr",
                rf_chain::WordKind::CodeAddr => "code_addr",
                rf_chain::WordKind::Padding => "padding",
            }
            .to_string(),
            comment: w.comment.clone(),
            source_gadget: w.source_gadget.map(|i| i as u64),
        })
        .collect();
    ChainResponse {
        assumptions: outcome
            .assumptions
            .as_ref()
            .map(|a| schema::ChainAssumptions {
                api_name: a.api_name.clone(),
                pivot_addr: a.pivot_addr.map(|v| format!("0x{v:x}")),
                pivot_words: a.pivot_words as u64,
                chain_base_parity: a.chain_base_parity.to_string(),
                chain_base_mod16: a.chain_base_mod16,
                shellcode_addr: format!("0x{:x}", a.shellcode_addr),
                old_protect_addr: a.old_protect_addr.map(|v| format!("0x{v:x}")),
            }),
        chain: schema::ChainIr {
            arch: chain.arch.clone(),
            description: chain.description.clone(),
            script_comment: chain.script_comment.clone(),
            word_size: chain.word_size as u64,
            words,
            gadgets,
        },
        python: chain.to_python(),
        arch: chain.arch.clone(),
        description: chain.description.clone(),
        word_count: chain.words.len() as u64,
        binary_sha256,
        binary_label,
        warnings: Vec::new(),
    }
}

/// SHA-256 of a tool's parameters, minus `binary_path` (which is logged in
/// its own field). Two identical queries against different binaries share
/// a `params_hash`, which is what makes the audit log greppable.
fn params_hash<T: serde::Serialize>(q: &T) -> String {
    let mut v = serde_json::to_value(q).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.remove("binary_path");
    }
    sha256_hex(v.to_string().as_bytes())
}

/// CRIT-03: map rf-cli's three failure kinds onto the closed wire set.
///
/// `binary_error` becomes `unsupported_binary`; `chain_error` becomes
/// `not_found`, because every chain failure the builders produce is "this
/// binary does not contain a gadget I need". The precise reason survives in
/// the message and in the audit line's `kind`.
fn scan_err_to_tool(e: rf_cli::ScanError) -> ToolError {
    match e {
        rf_cli::ScanError::Usage(m) => ToolError::new(ErrorCode::UsageError, m),
        rf_cli::ScanError::Binary(m) => {
            ToolError::new(ErrorCode::UnsupportedBinary, m).with_kind("binary_error")
        }
        rf_cli::ScanError::Chain(m) => {
            ToolError::with_details(ErrorCode::NotFound, m, json!({"what": "chain_gadget"}))
                .with_kind("chain_error")
        }
    }
}

/// A `usage_error` for a flag the allowlist refused, tagged `invalid_flag`
/// in the audit log so the operator still sees which kind it was.
fn usage_flag(message: String) -> ToolError {
    ToolError::new(ErrorCode::UsageError, message).with_kind("invalid_flag")
}

fn tool_error(err: ToolError) -> Result<CallToolResult, McpError> {
    let body = err.to_json();
    let mut r = CallToolResult::error(vec![ContentBlock::text(body.to_string())]);
    r.structured_content = Some(body);
    Ok(r)
}

/// Render a typed response. Serialization of these structs cannot fail —
/// they are owned scalars, strings and vectors with no map keys that are
/// not strings — but a `Null` body would still be a valid JSON document, so
/// the fallback is an `internal` error rather than a silent empty result.
fn tool_ok<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
    let Ok(v) = serde_json::to_value(value) else {
        return tool_error(ToolError::new(
            ErrorCode::Internal,
            "the response could not be serialized",
        ));
    };
    let mut r = CallToolResult::success(vec![ContentBlock::text(v.to_string())]);
    r.structured_content = Some(v);
    Ok(r)
}

#[tool_router]
impl RopFinderMcp {
    /// Find ROP gadgets (return-oriented; ends in ret-like control flow).
    #[tool(
        description = "Find ROP gadgets in a binary (ret-terminated). Results are RANKED by \
        default (order=\"rank\": usability tier, then quality, then fewest instructions, then \
        fewest side effects, then address), so the first page is the useful gadgets rather \
        than the alphabetical head; order=\"address\"|\"quality\"|\"text\" are also accepted. \
        Every record carries a stable id, the classification (class, labels, regs_written, \
        regs_read, regs_from_stack, side_effects, terminator, usability) and delay_slot. \
        Filter server-side with class/label/writes_reg/reads_reg/preserves_regs/from_stack/\
        terminator/max_side_effects/max_insns instead of pulling gadgets into context. Page \
        with next_cursor. binary_path must be an absolute path inside one of the server's \
        allow_roots (call get_server_config to list them); anything else returns path_denied. \
        depth above max_depth is rejected, not clamped. A request that exceeds timeout_secs is \
        STOPPED, not orphaned, and notifications/cancelled stops it too.",
        output_schema = crate::schema::scan_output_schema()
    )]
    async fn find_gadgets(
        &self,
        Parameters(q): Parameters<GadgetQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "find_gadgets", params_hash(&q));
        let out = self
            .gadget_scan(&ctx, &mut rec, &q, true, false, false)
            .await;
        self.finish(rec, t0, out).await
    }

    /// Find JOP gadgets (jump-oriented; ends in jmp/call).
    #[tool(
        description = "Find JOP gadgets in a binary (jmp/call-terminated). Same parameters, \
        ranking, filters, cursor and caps as find_gadgets.",
        output_schema = crate::schema::scan_output_schema()
    )]
    async fn find_jop_gadgets(
        &self,
        Parameters(q): Parameters<GadgetQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "find_jop_gadgets", params_hash(&q));
        let out = self
            .gadget_scan(&ctx, &mut rec, &q, false, true, false)
            .await;
        self.finish(rec, t0, out).await
    }

    /// Find SYS gadgets (syscall/int/sysenter entry points).
    #[tool(
        description = "Find SYS gadgets in a binary (syscall/sysenter/int). Same parameters, \
        ranking, filters, cursor and caps as find_gadgets.",
        output_schema = crate::schema::scan_output_schema()
    )]
    async fn find_syscall_gadgets(
        &self,
        Parameters(q): Parameters<GadgetQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "find_syscall_gadgets", params_hash(&q));
        let out = self
            .gadget_scan(&ctx, &mut rec, &q, false, false, true)
            .await;
        self.finish(rec, t0, out).await
    }

    /// ECO-01 / ECO-12 — the constraint search, as one call.
    #[tool(
        description = "Find gadgets by their EFFECT, not their text: \"set rdi from the stack, \
        preserve rsi and rdx, at most one side effect, a clean ret\" is one call. Constraints: \
        set_reg (the register is written with a value YOUR PAYLOAD decides — stronger than \
        writes_reg, which `xor rdi, rdi` also satisfies), from_stack (that write must come off \
        the stack), no_clobber (matched against the classifier's `clobbers`, so `pop rdi` \
        survives no_clobber:[\"rdi\"] and `mov rdi, rax` does not), reads_reg, \
        max_stack_delta (net rsp movement, terminator included; a gadget whose delta is UNKNOWN \
        is rejected, never assumed 0), max_side_effects, max_insns, terminator \
        (ret|jmp|call|syscall|none|any, or the finer bare-ret|ret-imm|jmp-reg|jmp-mem|call-reg|call-mem|\
        far|other), search (ropper-style wildcards over the instruction sequence, e.g. \
        \"pop rdi; ret\"; `?` is one character, `%` any run), pivot (the stack-pivot preset), \
        plus class/label/writes_reg/preserves_regs. Scans ROP+JOP+SYS together, so `terminator` \
        chooses the family. EVERY result carries an `explanation` object — sets, reads, \
        clobbers, stack_delta, terminator and a one-line `why` — so a choice can be justified \
        without re-deriving semantics from gadget text. Ranked, paged with next_cursor, and a \
        paged result names an NDJSON resource with the whole set.",
        output_schema = crate::schema::scan_output_schema()
    )]
    async fn find_gadgets_by_effect(
        &self,
        Parameters(q): Parameters<EffectQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "find_gadgets_by_effect", params_hash(&q));
        let out = async {
            let depth = self.check_depth(q.depth)?;
            let req = rf_cli::ScanRequest {
                depth,
                // All three families: the question is about the effect, and
                // `terminator` is how a caller narrows it. A `jmp-reg`
                // constraint on a ROP-only scan would silently return
                // nothing.
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
                arch: q.arch.clone(),
                max_gadgets: None,
                max_memory: None,
                compat: false,
            };
            let filter = GadgetFilter::parse(&raw_filter!(q))?;
            if filter.is_empty() {
                return Err(ToolError::with_details(
                    ErrorCode::UsageError,
                    "find_gadgets_by_effect was given no constraint; it would return the whole \
                     scan. Pass at least one of set_reg, from_stack, no_clobber, reads_reg, \
                     writes_reg, preserves_regs, max_stack_delta, max_side_effects, max_insns, \
                     terminator, search, pivot, class or label — or call find_gadgets if an \
                     unfiltered ranked list is what you want",
                    json!({"parameter": "set_reg"}),
                ));
            }
            self.run_scan(
                &ctx,
                &mut rec,
                req,
                &q.binary_path,
                PostOpts {
                    order: Order::parse(q.order.as_deref().unwrap_or("rank"))?,
                    filter,
                    cursor: q.cursor.clone(),
                    params_hash: cursor::params_fingerprint(&q),
                    max_results: q.max_results,
                    timeout_secs: q.timeout_secs,
                    ..Default::default()
                },
            )
            .await
        }
        .await;
        self.finish(rec, t0, out).await
    }

    /// CLI-05 / ECO-02 — strings inside the mapped image.
    #[tool(
        description = "Find a string in the binary's MAPPED DATA sections — where \"/bin/sh\" \
        lives, and at what address. `string` is a BYTE regex (ROPgadget's --string semantics), \
        so \"/bin/sh\" is a literal and \"m..n\" matches four bytes. Set memstr:true for \
        ROPgadget's --memstr instead: each CHARACTER is located separately and only its first \
        occurrence is reported, searching executable sections before data ones, which is how \
        you assemble a string the binary does not contain contiguously. Each hit gives vaddr, \
        section, length, an escaped preview, the raw hex, and whether the section is writable \
        and executable — `writable` is what tells you an address is usable as scratch space. \
        SCOPE, and it is enforced rather than promised: only bytes inside sections the loader \
        MAPS are ever examined. There is no file-offset mode; headers, symbol and string \
        tables and debug data are unreachable because they are in no mapped section, and \
        `range` can only narrow the windows. `sections_searched` in the response names exactly \
        what was read. Paged with next_cursor; a paged result also names an NDJSON resource.",
        output_schema = crate::schema::search_output_schema()
    )]
    async fn find_string(
        &self,
        Parameters(q): Parameters<StringQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "find_string", params_hash(&q));
        let params_fp = cursor::params_fingerprint(&q);
        let mode = if q.memstr.unwrap_or(false) {
            find::Mode::MemStr
        } else {
            find::Mode::String
        };
        let out = self
            .run_find(
                &ctx,
                &mut rec,
                FindRequest {
                    binary_path: q.binary_path.clone(),
                    mode,
                    query: q.string.clone(),
                    base: q.base.clone(),
                    offset: q.offset.clone(),
                    range: q.range.clone(),
                    arch: q.arch.clone(),
                    max_results: q.max_results,
                    cursor: q.cursor.clone(),
                    params_hash: params_fp,
                    timeout_secs: q.timeout_secs,
                },
            )
            .await;
        self.finish(rec, t0, out).await
    }

    /// CLI-05 / ECO-02 — a byte sequence inside the mapped executable image.
    #[tool(
        description = "Find a byte sequence in the binary's MAPPED EXECUTABLE regions — the \
        same regions find_gadgets walks. `opcode` is hex (\"c9c3\", or \"c9 c3\"), and `??` \
        matches any one byte, so \"ff??e0\" finds `jmp rax` through `jmp r15`. A one-nibble \
        wildcard is refused rather than silently widened. Each hit gives vaddr, section, \
        length, an escaped preview, the raw hex and the section's writable/executable flags. \
        SCOPE: only bytes inside mapped executable sections are examined — there is no \
        file-offset mode and nothing outside a section is reachable; `sections_searched` names \
        exactly what was read, and `range` can only narrow it. Paged with next_cursor; a paged \
        result also names an NDJSON resource with the whole match set.",
        output_schema = crate::schema::search_output_schema()
    )]
    async fn find_bytes(
        &self,
        Parameters(q): Parameters<BytesQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "find_bytes", params_hash(&q));
        let params_fp = cursor::params_fingerprint(&q);
        let out = self
            .run_find(
                &ctx,
                &mut rec,
                FindRequest {
                    binary_path: q.binary_path.clone(),
                    mode: find::Mode::Opcode,
                    query: q.opcode.clone(),
                    base: q.base.clone(),
                    offset: q.offset.clone(),
                    range: q.range.clone(),
                    arch: q.arch.clone(),
                    max_results: q.max_results,
                    cursor: q.cursor.clone(),
                    params_hash: params_fp,
                    timeout_secs: q.timeout_secs,
                },
            )
            .await;
        self.finish(rec, t0, out).await
    }

    /// ECO-06 — checksec, for an agent.
    #[tool(
        description = "Report the binary's exploit mitigations, so an agent can decide whether \
        ROP is even the right technique before it scans. ELF: nx (PT_GNU_STACK), pie \
        (ET_DYN + DF_1_PIE/PT_INTERP/DT_DEBUG, distinguishing a PIE executable from a shared \
        object), relro, canary, fortify, rpath, runpath. PE: aslr, dep, high_entropy_va, \
        guard_cf and cet_compat as SEPARATE answers read from separate directories (CFG \
        validates indirect CALL targets and does NOT check a ret; only cet_compat means a \
        shadow stack), safe_seh, force_integrity. Mach-O: pie, nx_stack, nx_heap, \
        code_signature, hardened_runtime — per SLICE for a fat container, in `slices`, because \
        the slices genuinely disagree. Every entry is {name, enabled, evidence, detail} where \
        `enabled` is true, false, or the string \"unknown\" — never false standing in for \
        \"could not tell\" — and `evidence` names the header field that decided it, or the \
        one whose absence made it unknown. The order is the loader's and is meaningful; `name` \
        is the stable key. No scan is performed.",
        output_schema = crate::schema::mitigations_output_schema()
    )]
    async fn get_mitigations(
        &self,
        Parameters(q): Parameters<MitigationsQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "get_mitigations", params_hash(&q));
        let out = self.run_mitigations(&ctx, &mut rec, &q).await;
        self.finish(rec, t0, out).await
    }

    /// Resolve stable gadget ids back to full records.
    #[tool(
        description = "Resolve stable gadget ids (the `id` field of any gadget record, e.g. \
        \"g_ab12cd34ef56gh78\") back to full records, so a plan can name gadgets instead of \
        re-sending their text. Rescans the binary at `depth` (default 10) and matches by id; \
        an id is independent of every scan parameter except `base`, so pass the same `base` \
        the ids came from. Ids that do not resolve are reported in warnings.ids_not_found \
        rather than failing the call. Results are returned in the order the ids were given.",
        output_schema = crate::schema::scan_output_schema()
    )]
    async fn get_gadgets(
        &self,
        Parameters(q): Parameters<IdsQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "get_gadgets", params_hash(&q));
        let out = async {
            if q.ids.is_empty() {
                return Err(ToolError::new(
                    ErrorCode::UsageError,
                    "ids must not be empty; pass the `id` field of gadgets you already have",
                ));
            }
            let depth = self.check_depth(q.depth)?;
            let req = rf_cli::ScanRequest {
                depth,
                rop: true,
                jop: true,
                sys: true,
                multibr: false,
                only: None,
                filter: None,
                range: None,
                badbytes: None,
                offset: q.offset.clone(),
                base: q.base.clone(),
                section: split_sections(q.section.as_deref()),
                thumb: false,
                cfg_aware: false,
                align: None,
                call_preceded: false,
                all: false,
                noinstr: false,
                arch: q.arch.clone(),
                max_gadgets: None,
                max_memory: None,
                compat: false,
            };
            self.run_scan(
                &ctx,
                &mut rec,
                req,
                &q.binary_path,
                PostOpts {
                    order: Order::Ids,
                    ids: Some(q.ids.clone()),
                    params_hash: cursor::params_fingerprint(&q),
                    max_results: Some(q.ids.len().clamp(1, HARD_MAX_RESULTS)),
                    timeout_secs: q.timeout_secs,
                    ..Default::default()
                },
            )
            .await
        }
        .await;
        self.finish(rec, t0, out).await
    }

    /// Binary metadata without scanning (the CLI's --info payload).
    #[tool(
        description = "Get binary metadata as JSON: format, arch, endianness, addr_size, \
        image_base, entry, sections (name/vaddr/size/executable/writable), PE imports \
        (iat_vaddr is the IAT slot the loader patches; hint_name_vaddr is the \
        IMAGE_IMPORT_BY_NAME record; an ELF import instead carries addr/got/plt/type/binding, which         is what a ret2plt chain resolves against), the ELF symbol table (`symbols`, OPT-IN: pass max_symbols to get it; symbol_count is always the true total, and null means this format's symbols are not read at all), fat Mach-O slices,         binary_sha256 and warnings. The \
        shape is fixed: an ELF reports slices: [] and a fat Mach-O reports sections: []. Exploit \
        mitigations are NOT here: call get_mitigations, which types them and keeps the loader's \
        order. No scan is performed. Bounded like every other tool: timeout_secs (default 60), \
        --max-file-bytes, and max_sections/max_imports (default 4096 each) and max_symbols (default 0, max 4096) — a truncated \
        array is announced in warnings, never silently short.",
        output_schema = crate::schema::info_output_schema()
    )]
    async fn get_binary_info(
        &self,
        Parameters(q): Parameters<InfoQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "get_binary_info", params_hash(&q));
        let out = self.run_info(&ctx, &mut rec, &q).await;
        self.finish(rec, t0, out).await
    }

    /// The effective allowlist and caps, so an agent never has to guess.
    #[tool(
        description = "Report the server's effective configuration: allow_roots (the only \
        directories binary_path may name), max_depth, max_file_bytes, max_results, \
        max_concurrent, scan_threads, max_gadgets, timeout_secs, cursor_ttl_secs, whether an \
        on-disk cache and a workspace directory are enabled, the complete list of `order` \
        values, the complete list of error codes, and the server version. Call this first: \
        paths outside allow_roots are refused with a single path_denied code that \
        deliberately reveals nothing about the target, and a run of refusals is treated as \
        filesystem probing.",
        output_schema = crate::schema::config_output_schema()
    )]
    async fn get_server_config(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (rec, t0) = self.begin(&ctx, "get_server_config", String::new());
        let out = Ok(self.config_response());
        self.finish(rec, t0, out).await
    }

    /// MCP-09: the counters an operator needs to see the server's health.
    #[tool(
        description = "Report this session's counters: requests_total and requests_by_tool, \
        ok/denied/timeout/cancelled/error totals, denied_consecutive and probing_suspected \
        (a run of path_denied results is the signal that an agent is enumerating the \
        filesystem), wedged_total (workers that did not stop within 5 s of being \
        cancelled), busy_total, inflight, bytes_read_total, and the cache's \
        hit/miss/eviction/tamper counters with its live cache_bytes against \
        cache_mem_max_bytes.",
        output_schema = crate::schema::stats_output_schema()
    )]
    async fn get_server_stats(
        &self,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (rec, t0) = self.begin(&ctx, "get_server_stats", String::new());
        let out = self.stats_response();
        self.finish(rec, t0, out).await
    }

    /// Regex/substring search over the gadget text of a full scan.
    #[tool(
        description = "Search gadgets by pattern: regex matched against gadget text \
        (e.g. \"pop r.*; ret\"); invalid regexes fall back to literal substring match. Runs a \
        full ROP+JOP+SYS scan, then filters. Same ranking, semantic filters, cursor and caps \
        as find_gadgets.",
        output_schema = crate::schema::scan_output_schema()
    )]
    async fn search_gadgets_by_pattern(
        &self,
        Parameters(q): Parameters<SearchQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "search_gadgets_by_pattern", params_hash(&q));
        let out = async {
            let depth = self.check_depth(q.depth)?;
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
                arch: q.arch.clone(),
                max_gadgets: None,
                max_memory: None,
                compat: false,
            };
            self.run_scan(
                &ctx,
                &mut rec,
                req,
                &q.binary_path,
                PostOpts {
                    re: Some(q.pattern.clone()),
                    order: Order::parse(q.order.as_deref().unwrap_or("rank"))?,
                    filter: GadgetFilter::parse(&raw_filter!(q))?,
                    cursor: q.cursor.clone(),
                    params_hash: cursor::params_fingerprint(&q),
                    max_results: q.max_results,
                    timeout_secs: q.timeout_secs,
                    ids: None,
                },
            )
            .await
        }
        .await;
        self.finish(rec, t0, out).await
    }

    /// Build a Linux execve("/bin/sh") ROP chain (ELF x86/x64 only).
    #[tool(
        description = "Build a ROP chain. target must be \"linux-execve\" (ELF x86/x64 only, \
        ported from ROPgadget's ropmaker: x86 int 0x80 / x64 syscall, \"/bin//sh\" written \
        to a writable section), \"linux-mprotect\" (the NX answer: page-aligns the region \
        and calls mprotect), \"linux-syscall\" (any syscall -- pass `syscall` and \
        `syscall_args`), \"linux-ret2libc\" (calls `api_addr` with \"/bin//sh\": SysV arg1 \
        in rdi on x64, cdecl stack argument on x86), \"linux-srop\" (x86-64: rt_sigreturn \
        plus a sigcontext frame, so only `pop rax` and a trap are needed) or \
        \"windows-virtualprotect\". Every one of those has been EXECUTED under the emulator \
        harness on a shipped fixture; call plan_chain first to find out whether THIS binary \
        can host the one you want. Returns the chain IR as JSON \
        (words with kinds gadget_addr / immediate / data_addr / code_addr / padding plus the \
        referenced gadget table, each entry carrying the same stable id find_gadgets \
        returns), the equivalent python exploit script, arch, description and word_count. A \
        binary that lacks a required gadget fails with not_found. Chain builds bypass the \
        gadget cache.",
        output_schema = crate::schema::chain_output_schema()
    )]
    async fn build_rop_chain(
        &self,
        Parameters(q): Parameters<ChainQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "build_rop_chain", params_hash(&q));
        let probe = ChainQuery { ..clone_query(&q) };
        let out = match self.run_chain(&ctx, &mut rec, q).await {
            Ok(v) => Ok(v),
            // ECO-04: one contract. A refusal carries the SAME document
            // plan_chain returns, in `details.plan`, so a caller never has
            // to parse a prose sentence to find out which requirement
            // failed or what would fix it. The message is unchanged.
            Err(e) if matches!(e.code, ErrorCode::NotFound | ErrorCode::UsageError) => {
                let mut probe_rec = rec.clone();
                let detail = self.run_plan(&ctx, &mut probe_rec, probe).await.ok();
                Err(match detail {
                    Some(plan) => {
                        // MERGE, never replace: `details.what` /
                        // `details.limit` are part of the CRIT-03 error
                        // contract and other callers branch on them.
                        let mut d = match e.details.clone() {
                            Some(Value::Object(m)) => m,
                            _ => serde_json::Map::new(),
                        };
                        d.insert(
                            "plan".to_string(),
                            serde_json::to_value(&plan).unwrap_or(Value::Null),
                        );
                        ToolError {
                            details: Some(Value::Object(d)),
                            ..e
                        }
                    }
                    None => e,
                })
            }
            Err(e) => Err(e),
        };
        self.finish(rec, t0, out).await
    }

    /// ECO-04: feasibility, not a chain.
    #[tool(
        description = "Ask whether this binary can host a ROP chain for `target`, and if not,         exactly why. ALWAYS succeeds: infeasibility is a result. Returns {feasible,         requirements[{id, description, satisfied, strategies_tried[{pattern, candidates}],         relaxations[{param, from, to, would_help}]}], satisfied_requirements[{id, gadget_id,         vaddr}], assumptions{chain_base_parity, write_target, needs_leak}}. Requirement ids         are stable (set_rdx, write_primitive, api_transfer, syscall_trap, stack_align).         `candidates` counts the gadgets the builder could actually USE for that strategy         (clean-tailed, and modelled by the constraint layer), so 0 means the strategy had         nothing to work with, while a non-zero count with satisfied:false means something         else rejected them. `would_help` is         MEASURED, not guessed: the server re-scans at double depth and with multibr and         re-runs the same probe. Every gadget_id resolves through get_gadgets.         build_rop_chain returns this same document in its error details when it refuses.",
        output_schema = crate::schema::plan_output_schema()
    )]
    async fn plan_chain(
        &self,
        Parameters(q): Parameters<ChainQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "plan_chain", params_hash(&q));
        let out = self.run_plan(&ctx, &mut rec, q).await;
        self.finish(rec, t0, out).await
    }

    /// Flag passthrough restricted to the PLAN §6.1 allowlist.
    #[tool(
        description = "Run a ROPgadget-style scan with explicit flags. args is a list like \
        [\"--depth\", \"6\", \"--only\", \"pop|ret\"]. Allowlist: --depth --norop --nojop \
        --nosys --only --filter --re --range --section --base --offset --badbytes --align \
        --multibr --json --arch --all --callPreceded; anything else (--string, --dump, \
        --console, ...) is rejected. --align is ROPgadget's real scan-time alignment \
        (decimal, as in ROPgadget's argparse; write 0x.. only if you mean hex), not an \
        address post-filter. --arch names a fat Mach-O slice and is REQUIRED for a \
        multi-slice binary. The result is ordered, filtered and paged exactly like \
        find_gadgets.",
        output_schema = crate::schema::scan_output_schema()
    )]
    async fn run_ropgadget_command(
        &self,
        Parameters(q): Parameters<RawCommandQuery>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let (mut rec, t0) = self.begin(&ctx, "run_ropgadget_command", params_hash(&q));
        let out = async {
            let parsed = parse_ropgadget_args(&q.args)?;
            // --depth is unbounded in ROPgadget's own CLI, so the
            // passthrough is exactly where `--depth 100000` arrived.
            self.check_depth(Some(parsed.request.depth))?;
            self.run_scan(
                &ctx,
                &mut rec,
                parsed.request,
                &q.binary_path,
                PostOpts {
                    re: parsed.re,
                    order: Order::parse(q.order.as_deref().unwrap_or("rank"))?,
                    filter: GadgetFilter::parse(&raw_filter!(q))?,
                    cursor: q.cursor.clone(),
                    params_hash: cursor::params_fingerprint(&q),
                    max_results: q.max_results,
                    timeout_secs: q.timeout_secs,
                    ids: None,
                },
            )
            .await
        }
        .await;
        self.finish(rec, t0, out).await
    }
}

impl RopFinderMcp {
    /// The body shared by `find_gadgets` / `find_jop_gadgets` /
    /// `find_syscall_gadgets`, which differ only in the anchor family.
    async fn gadget_scan(
        &self,
        ctx: &RequestContext<RoleServer>,
        rec: &mut AuditRecord,
        q: &GadgetQuery,
        rop: bool,
        jop: bool,
        sys: bool,
    ) -> Result<ScanResponse, ToolError> {
        let req = self.gadget_request(q, rop, jop, sys)?;
        // `sort_by` is the pre-0.3 spelling and accepted only as a fallback
        // for `order`, so an agent written against the old surface keeps
        // working and one written against the new one is never surprised by
        // a stale parameter it did not send.
        let order = Order::parse(
            q.order
                .as_deref()
                .or(q.sort_by.as_deref())
                .unwrap_or("rank"),
        )?;
        let filter = GadgetFilter::parse(&raw_filter!(q))?;
        self.run_scan(
            ctx,
            rec,
            req,
            &q.binary_path,
            PostOpts {
                order,
                filter,
                cursor: q.cursor.clone(),
                params_hash: cursor::params_fingerprint(q),
                max_results: q.max_results,
                timeout_secs: q.timeout_secs,
                ..Default::default()
            },
        )
        .await
    }

    /// `get_server_stats`, as the declared type.
    fn stats_response(&self) -> Result<schema::StatsResponse, ToolError> {
        let v = self.stats.snapshot(self.cache.stats_json());
        serde_json::from_value(v).map_err(|e| {
            ToolError::new(
                ErrorCode::Internal,
                format!("the counters do not match the declared schema: {e}"),
            )
        })
    }
}

// rmcp deprecated the `logging` capability in 2.0 (SEP-2577) while still
// implementing it, and it is the only channel that reaches an MCP
// operator — stderr, the alternative, is what hosts discard, which is
// MCP-09 itself. Scoped to this impl.
#[allow(deprecated)]
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
                // MCP-09: the operator never sees this process's stderr, so
                // warnings that matter to them — a tampered cache entry, a
                // wedged worker, suspected path probing — are forwarded as
                // notifications/message. Declaring the capability is what
                // makes a host deliver them.
                .enable_logging()
                // A paged scan also names an NDJSON resource holding the
                // WHOLE ordered set. An agent with its own tools greps one
                // file instead of making 41 tool calls.
                .enable_resources()
                .build(),
        )
        .with_server_info(rmcp::model::Implementation::new("rop-finder-mcp", "0.1.0"))
        .with_instructions(self.instructions())
    }

    /// `logging/setLevel`. Declaring the capability without honouring the
    /// level would leave a host unable to turn the stream down.
    async fn set_level(
        &self,
        request: rmcp::model::SetLevelRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.notifier.set_level(request.level);
        Ok(())
    }

    /// The scans currently pinned, each as one NDJSON resource.
    ///
    /// The list is the pinned-scan store, so it names exactly the results a
    /// `resources/read` can still serve. It carries no path and no file
    /// content — only the cache key, which the client was already told.
    async fn list_resources(
        &self,
        _request: Option<rmcp::model::PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ListResourcesResult, McpError> {
        let resources = self
            .cache
            .pinned_keys()
            .into_iter()
            .map(|(key, count)| {
                // A search key is minted as `s<hex>` by run_find; a scan key
                // is `rf_cache::make_key`'s `v<n>-<hex>--<hex>`. The two
                // namespaces are disjoint by construction, and each URI form
                // is parsed only by its own reader.
                if key.starts_with('s') && !key.contains("--") {
                    rmcp::model::Resource::new(resources::search_uri(&key), format!("search {key}"))
                        .with_mime_type(resources::NDJSON_MIME)
                        .with_description(format!(
                            "{count} search hits, one JSON object per line, in address order"
                        ))
                } else {
                    rmcp::model::Resource::new(resources::scan_uri(&key), format!("scan {key}"))
                        .with_mime_type(resources::NDJSON_MIME)
                        .with_description(format!(
                            "{count} gadget records, one JSON object per line, in rank order"
                        ))
                }
            })
            .collect();
        Ok(rmcp::model::ListResourcesResult::with_all_items(resources))
    }

    /// Serve `ropfinder://scan/<cache_key>/gadgets.ndjson`.
    ///
    /// The URI is parsed into a cache key by [`resources::cache_key_of`],
    /// which accepts only `[A-Za-z0-9-]`, and the key is looked up in the
    /// pinned store — it is never joined to a path here, and there is no
    /// path in a URI to begin with. A key that is not pinned is
    /// `resource_not_found`, never a rescan: reading a resource must not be
    /// a way to make the server do unbounded work outside the guard.
    async fn read_resource(
        &self,
        request: rmcp::model::ReadResourceRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<rmcp::model::ReadResourceResponse, McpError> {
        let uri = request.uri.clone();
        // ECO-09: two namespaces, each parsed by its own reader, so a scan
        // key can never be served as a search body or the reverse.
        let text = if let Some(key) = resources::search_key_of(&uri) {
            let Some(body) = self.cache.pinned_text(key) else {
                return Err(McpError::resource_not_found(
                    "that search is no longer held; re-run it to get a fresh resource_uri",
                    Some(json!({"uri": uri, "cursor_ttl_secs": self.config.cursor_ttl.as_secs()})),
                ));
            };
            body.to_string()
        } else {
            let Some(key) = resources::cache_key_of(&uri) else {
                return Err(McpError::resource_not_found(
                    "not a rop-finder resource; the forms are \
                     ropfinder://scan/<cache_key>/gadgets.ndjson and \
                     ropfinder://search/<key>/hits.ndjson",
                    Some(json!({"uri": uri})),
                ));
            };
            let Some(p) = self.cache.pinned(key) else {
                return Err(McpError::resource_not_found(
                    "that scan is no longer held; re-run the scan to get a fresh resource_uri",
                    Some(json!({"uri": uri, "cursor_ttl_secs": self.config.cursor_ttl.as_secs()})),
                ));
            };
            resources::render_ndjson(&p.scan, &p.sems)
        };
        Ok(rmcp::model::ReadResourceResult::new(vec![
            rmcp::model::ResourceContents::TextResourceContents {
                uri,
                mime_type: Some(resources::NDJSON_MIME.to_string()),
                text,
                meta: None,
            },
        ])
        .into())
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
             Gadget results are RANKED by default (order=\"rank\"), carry a stable `id` you can \
             pass back to get_gadgets, and are paged with `next_cursor`. Prefer the server-side \
             filters — class, label, writes_reg, reads_reg, preserves_regs, from_stack, \
             terminator, max_side_effects, max_insns, and v0.4's set_reg, no_clobber, \
             max_stack_delta, pivot and search — over reading gadgets to filter them \
             yourself. find_gadgets_by_effect takes all of them at once and returns an \
             `explanation` with every gadget. find_string and find_bytes locate strings and \
             byte sequences, and read ONLY bytes inside MAPPED sections — never a file offset. \
             get_mitigations is checksec: nx/pie/relro/canary or aslr/dep/guard_cf/cet_compat, \
             each with its evidence, and \"unknown\" where the file does not say. A paged scan \
             or search also names an NDJSON resource holding the whole set.\n\
             Every tool declares an outputSchema; every response has a FIXED field set, with \
             null rather than a missing key. Errors are {{error: {{code, message, retryable, \
             details, suggestion}}}} and `code` is one of: {}.",
            self.config.max_depth,
            self.config.max_file_bytes,
            self.config.max_results,
            HARD_MAX_RESULTS,
            self.config.max_concurrent,
            self.config.timeout.as_secs(),
            ErrorCode::all()
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        )
    }
}

#[cfg(test)]
mod tests {
    // Panicking on a bad index is the desired behaviour in a test; the
    // crate-level deny exists to keep it out of the server.
    #![allow(clippy::indexing_slicing)]

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

    // -----------------------------------------------------------------
    // ANCH-02 - --align is an engine option, parsed as DECIMAL
    // -----------------------------------------------------------------

    /// ROPgadget's `--align` is argparse `type=int`. rf-mcp parsed it with
    /// `rf_cli::parse_hex`, which always parses base 16, so `--align 16`
    /// meant 0x16 = 22 and `--align 10` meant 16. Decimal first; hex only
    /// with an explicit `0x`.
    #[test]
    fn align_is_parsed_as_decimal_first_hex_only_with_a_prefix() {
        assert_eq!(parse_align("16").unwrap(), 16);
        assert_eq!(parse_align("0x10").unwrap(), 16);
        assert_eq!(parse_align("0X10").unwrap(), 16);
        assert_eq!(parse_align(" 4 ").unwrap(), 4);
        assert_eq!(parse_align("10").unwrap(), 10);
        assert_eq!(parse_align("0").unwrap(), 0);
        for bad in ["", "0x", "-4", "abcd", "0xzz", "4.5"] {
            assert!(parse_align(bad).is_err(), "{bad:?} must not parse");
        }
        // The old behaviour, spelled out so a regression is unmistakable:
        // parse_hex("16") is 22, and that is what this test forbids.
        assert_eq!(rf_cli::parse_hex("16", "x").unwrap(), 22);
        assert_ne!(parse_align("16").unwrap() as u64, 22);
    }

    /// The parsed value reaches `ScanRequest::align`, i.e. the ENGINE's
    /// alignment stepping, and no post-filter survives to re-implement it.
    /// Post-filtering an align=1 depth-10 scan can only ever expose gadgets
    /// reaching 9 bytes back, which is why it under-reported by ~53%.
    #[test]
    fn align_reaches_the_engine_not_a_post_filter() {
        let p = parse_ropgadget_args(&args(&["--align", "16"])).unwrap();
        assert_eq!(p.request.align, Some(16));
        let p = parse_ropgadget_args(&args(&["--align=4"])).unwrap();
        assert_eq!(p.request.align, Some(4));
        // A bad value is a usage error, not a silent 0.
        let e = parse_ropgadget_args(&args(&["--align", "nope"])).unwrap_err();
        assert_eq!(e.code, ErrorCode::UsageError);
    }

    /// CORE-03 mirrored onto the MCP surface: `--arch` selects a fat
    /// Mach-O slice, and the new engine switches are reachable.
    #[test]
    fn arch_all_and_call_preceded_are_allowlisted_and_plumbed() {
        let p =
            parse_ropgadget_args(&args(&["--arch", "arm64", "--all", "--callPreceded"])).unwrap();
        assert_eq!(p.request.arch.as_deref(), Some("arm64"));
        assert!(p.request.all);
        assert!(p.request.call_preceded);
        // The MCP server never opts into ROPgadget's fat-Mach-O
        // concatenation: an agent cannot see that the output is fabricated.
        assert!(!p.request.compat);
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
        assert_eq!(err.code, ErrorCode::PathDenied);
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
        assert_eq!(err.code, ErrorCode::UsageError);
        let d = err.details.expect("structured details");
        assert_eq!(d["limit"], "max_depth");
        assert_eq!(d["limit_value"], 64);
        assert_eq!(d["got"], 100_000);
        // usize::MAX, the value the audit actually sent, is rejected too.
        assert_eq!(
            server.check_depth(Some(usize::MAX)).unwrap_err().code,
            ErrorCode::UsageError
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
        let cfg = serde_json::to_value(server.config_response()).unwrap();
        for key in [
            "allow_roots",
            "max_depth",
            "max_file_bytes",
            "max_results",
            "max_concurrent",
            "cache",
            "cursor_ttl_secs",
            "orders",
            "error_codes",
            "version",
        ] {
            assert!(cfg.get(key).is_some(), "missing {key} in {cfg}");
        }
        assert_eq!(cfg["allow_roots"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["cache"], false);
        // CRIT-03: the two taxonomies are PUBLISHED, so an agent never has
        // to discover them by provoking failures.
        assert_eq!(cfg["orders"], json!(["rank", "address", "quality", "text"]));
        assert_eq!(cfg["error_codes"].as_array().unwrap().len(), 9);
        let root = server.root_paths()[0].clone();
        assert!(server.instructions().contains(&root));
        assert!(server.instructions().contains("get_server_config"));
        assert!(server.instructions().contains("cursor_expired"));
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
        // ANCH-02: --align is an ENGINE option now, and an explicit 0x
        // prefix still means hexadecimal.
        assert_eq!(p.request.align, Some(16));
        // --flag=value form also works
        let p = parse_ropgadget_args(&args(&["--depth=8"])).unwrap();
        assert_eq!(p.request.depth, 8);
    }

    #[test]
    fn allowlist_rejects_side_channel_and_unknown_flags() {
        for bad in ["--string", "--dump", "--console", "--memstr", "--unknown"] {
            let err = parse_ropgadget_args(&args(&[bad])).unwrap_err();
            assert_eq!(err.code, ErrorCode::UsageError, "{bad}");
            assert_eq!(err.kind, "invalid_flag", "{bad}");
            assert!(err.message.contains("--depth"), "lists allowlist: {err:?}");
        }
        // even with a value
        let err = parse_ropgadget_args(&args(&["--string", "password"])).unwrap_err();
        assert_eq!(err.kind, "invalid_flag");
        // positional argument
        let err = parse_ropgadget_args(&args(&["/etc/passwd"])).unwrap_err();
        assert_eq!(err.kind, "invalid_flag");
        // missing value
        let err = parse_ropgadget_args(&args(&["--depth"])).unwrap_err();
        assert_eq!(err.kind, "invalid_flag");
        // boolean flag with value
        let err = parse_ropgadget_args(&args(&["--norop=1"])).unwrap_err();
        assert_eq!(err.kind, "invalid_flag");
        // bad depth value
        let err = parse_ropgadget_args(&args(&["--depth", "x"])).unwrap_err();
        assert_eq!(err.code, ErrorCode::UsageError);
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

    /// The default order is `rank`, and it is the tier — not R12's quality
    /// score — that puts a usable gadget first. `sort_by: "quality"` used to
    /// be the only ordering, and its top of the list was `ret`,
    /// `add esp, 0x8 ; ret`, `retf 0x2bbc`.
    #[test]
    fn rank_beats_quality_at_putting_a_usable_gadget_first() {
        let mk = |vaddr: &str, bytes: &str, text: &str| CachedGadget {
            vaddr: vaddr.into(),
            bytes: bytes.into(),
            text: text.into(),
            ..CachedGadget::default()
        };
        let scan = CachedScan {
            gadgets: vec![
                mk(
                    "0x1000",
                    "504801d859c3",
                    "push rax ; add rax, rbx ; pop rcx ; ret",
                ),
                mk("0x2000", "58c3", "pop rax ; ret"),
                mk("0x3000", "c3", "ret"),
                mk("0x0500", "5fc3", "pop rdi ; ret"),
                mk("0x4000", "cabc2b", "retf 0x2bbc"),
            ],
            ..CachedScan::default()
        };
        let sems = semantics::classify_scan(&scan, "00", 0, Some(rf_core::Arch::X64));
        let order_of = |o: Order| {
            let mut idx: Vec<usize> = (0..scan.gadgets.len()).collect();
            semantics::sort_indices(&mut idx, o, &scan, &sems);
            idx.iter()
                .map(|&i| scan.gadgets[i].vaddr.as_str())
                .collect::<Vec<_>>()
        };
        // Rank: the two stack loads first (tier 3, lower vaddr wins the
        // tie), then the multi-effect gadget (tier 2), then `retf 0x2bbc`
        // — CLS-13 makes its immediate a stack adjustment, so it has one
        // side effect and a non-bare terminator: tier 1 — and last the
        // bare `ret`, which does nothing at all (tier 0).
        assert_eq!(
            order_of(Order::Rank),
            ["0x0500", "0x2000", "0x1000", "0x4000", "0x3000"]
        );
        // Address and text are total and independent of it.
        assert_eq!(
            order_of(Order::Address),
            ["0x0500", "0x1000", "0x2000", "0x3000", "0x4000"]
        );
        // Quality alone cannot separate `ret` from `pop rdi ; ret` well
        // enough to be a default: a bare `ret` outranks the multi-effect
        // gadget on it, which is why the tier exists.
        let q = order_of(Order::Quality);
        assert_eq!(q[0], "0x0500", "{q:?}");
        assert!(
            q.iter().position(|v| *v == "0x3000").unwrap()
                < q.iter().position(|v| *v == "0x1000").unwrap(),
            "{q:?}"
        );
    }

    fn one_ret() -> CachedScan {
        CachedScan {
            gadgets: vec![CachedGadget {
                vaddr: "0x1".into(),
                bytes: "c3".into(),
                text: "ret".into(),
                ..CachedGadget::default()
            }],
            ..CachedScan::default()
        }
    }

    #[test]
    fn cache_roundtrip_mem_and_disk() {
        let t = TempDir::new("cache");
        let cache = Cache::new(
            Some(t.canon().clone()),
            rf_cache::MemLimits::default(),
            DEFAULT_CURSOR_TTL,
        );
        cache.put("k1", one_ret());
        assert_eq!(cache.get("k1").unwrap().gadgets.len(), 1);
        // persisted to disk, authenticated
        assert!(t.canon().join("k1.rfc").is_file());
        // a fresh cache over the same dir reads the disk entry
        let cold = Cache::new(
            Some(t.canon().clone()),
            rf_cache::MemLimits::default(),
            DEFAULT_CURSOR_TTL,
        );
        assert!(cold.get("k1").is_some());
        assert!(cold.get("absent").is_none());
        assert_eq!(cold.disk_stats().unwrap().tampered, 0);
    }

    /// MCP-04. The audit served a fabricated
    /// `pop rdi ; ret @ 0xdeadbeefcafe0000` through the live server by
    /// writing one 0644 JSON file. Now: a miss, a counter, no result.
    #[test]
    fn a_poisoned_disk_entry_is_a_miss_not_a_result() {
        let t = TempDir::new("poison");
        {
            let cache = Cache::new(
                Some(t.canon().clone()),
                rf_cache::MemLimits::default(),
                DEFAULT_CURSOR_TTL,
            );
            cache.put("k1", one_ret());
        }
        let fabricated = br#"{"version":2,"gadgets":[{"vaddr":"0xdeadbeefcafe0000","bytes":"5fc3","text":"pop rdi ; ret"}],"fallback_names":false}"#;
        // Bare JSON, the shape the pre-v0.2 cache accepted...
        std::fs::write(t.canon().join("k1.rfc"), fabricated).unwrap();
        let cache = Cache::new(
            Some(t.canon().clone()),
            rf_cache::MemLimits::default(),
            DEFAULT_CURSOR_TTL,
        );
        assert!(cache.get("k1").is_none());
        assert_eq!(cache.disk_stats().unwrap().tampered, 1);

        // ...and framed with a wrong tag, so only the HMAC rejects it.
        let mut framed = Vec::from(b"RFCACHE\x02".as_slice());
        framed.extend_from_slice(&[0u8; 32]);
        framed.extend_from_slice(fabricated);
        std::fs::write(t.canon().join("k1.rfc"), &framed).unwrap();
        let cache = Cache::new(
            Some(t.canon().clone()),
            rf_cache::MemLimits::default(),
            DEFAULT_CURSOR_TTL,
        );
        assert!(cache.get("k1").is_none());
        assert_eq!(cache.disk_stats().unwrap().tampered, 1);
    }

    /// ROB-04 as it reached this crate: `"€€"` in a cached `bytes` field
    /// panicked the server at `gadget_from_cached`. It is a miss now, and
    /// the reclassification path that used it cannot panic either.
    #[test]
    fn a_non_ascii_bytes_field_never_panics() {
        let t = TempDir::new("charboundary");
        {
            let cache = Cache::new(
                Some(t.canon().clone()),
                rf_cache::MemLimits::default(),
                DEFAULT_CURSOR_TTL,
            );
            cache.put("k1", one_ret());
        }
        let key = std::fs::read(t.canon().join(".cachekey")).unwrap();
        let body = r#"{"version":2,"gadgets":[{"vaddr":"0x1","bytes":"€€","text":"ret"}],"fallback_names":false}"#;
        let mut msg = Vec::from(b"k1\0".as_slice());
        msg.extend_from_slice(body.as_bytes());
        let mut framed = Vec::from(b"RFCACHE\x02".as_slice());
        framed.extend_from_slice(&rf_cache::hmac_sha256(&key, &msg));
        framed.extend_from_slice(body.as_bytes());
        std::fs::write(t.canon().join("k1.rfc"), &framed).unwrap();

        let cache = Cache::new(
            Some(t.canon().clone()),
            rf_cache::MemLimits::default(),
            DEFAULT_CURSOR_TTL,
        );
        assert!(cache.get("k1").is_none(), "authenticated but unusable");
        assert_eq!(cache.disk_stats().unwrap().malformed, 1);
        assert_eq!(cache.disk_stats().unwrap().tampered, 0);

        // The same value straight through the reclassification path.
        let g = CachedGadget {
            vaddr: "0x1".into(),
            bytes: "€€".into(),
            text: "ret".into(),
            ..CachedGadget::default()
        };
        assert!(g.to_scan_gadget().is_none());
        // ...and straight through the classification path, which is where
        // the reconstruction now happens: an id, no class, sorts last.
        let poisoned = CachedScan {
            gadgets: vec![g],
            ..CachedScan::default()
        };
        let sems = semantics::classify_scan(&poisoned, "00", 0, Some(rf_core::Arch::X64));
        assert_eq!(sems.len(), 1);
        assert!(sems[0].class.is_none());
        assert!(sems[0].id.starts_with("g_"));
    }
}
