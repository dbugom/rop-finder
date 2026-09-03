//! `rop-finder-mcp` binary — stdio MCP server (PLAN.md §6.1). All logic
//! lives in the rf-mcp library.
//!
//! MCP-02: the allowlist comes from `--allow-dir` and nothing else. There is
//! no cwd default, because an MCP host — not the operator — chooses this
//! process's working directory, and `claude_desktop_config.json` has no cwd
//! key. Starting with no root is a hard failure (exit 2), and a
//! pathologically wide root is refused unless the operator explicitly opts
//! in with `--i-accept-a-wide-allowlist`.

use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use rf_mcp::{RopFinderMcp, ServerConfig};
use rmcp::{transport::stdio, ServiceExt};

/// Exit code for a refused startup configuration.
const EXIT_CONFIG: u8 = 2;

#[derive(Parser, Debug)]
#[command(
    name = "rop-finder-mcp",
    version,
    about = "rop-finder MCP server (stdio transport only)"
)]
struct ServerCli {
    /// Directory the agent may read binaries from (repeatable). This is the
    /// ONLY source of the allowlist; the server refuses to start without it.
    #[arg(long = "allow-dir", value_name = "<path>")]
    allow_dir: Vec<PathBuf>,

    /// Deliberately serve the process working directory. Explicit opt-in for
    /// `cargo run` and CI; the MCP host, not the operator, picks the cwd.
    #[arg(long = "allow-cwd")]
    allow_cwd: bool,

    /// Accept an allow root that covers a filesystem root, a home directory
    /// or a system directory. Almost never what you want.
    #[arg(long = "i-accept-a-wide-allowlist")]
    accept_wide_allowlist: bool,

    /// Optional on-disk cache directory (content-hash keyed). Must not fall
    /// inside an allow root.
    #[arg(long = "cache-dir", value_name = "<path>")]
    cache_dir: Option<PathBuf>,

    /// JSONL call/denial log (MCP-09). One JSON object per line, opened
    /// append/create, mode 0600, rotated at --audit-log-max-mb. Must not
    /// fall inside an allow root: the agent must not be able to read the
    /// server's record of it.
    #[arg(long = "audit-log", value_name = "<path>")]
    audit_log: Option<PathBuf>,

    /// Rotate the audit log at this size, keeping <path>.1 and <path>.2.
    #[arg(long = "audit-log-max-mb", default_value_t = rf_mcp::audit::DEFAULT_AUDIT_MAX_MB)]
    audit_log_max_mb: u64,

    /// Threads in the scan pool. Default num_cpus-1, so the server never
    /// consumes every core on the operator's machine.
    #[arg(long = "scan-threads", value_name = "<n>")]
    scan_threads: Option<usize>,

    /// In-memory scan-cache budget in MiB (MCP-05/ROB-07). Entries are
    /// evicted least-recently-used until the total is under it.
    #[arg(long = "cache-mem-mb", default_value_t = rf_mcp::DEFAULT_CACHE_MEM_BYTES / (1024 * 1024))]
    cache_mem_mb: u64,

    /// In-memory scan-cache entry lifetime, in seconds.
    #[arg(long = "cache-ttl-secs", default_value_t = rf_mcp::DEFAULT_CACHE_TTL.as_secs())]
    cache_ttl_secs: u64,

    /// How long a paged scan stays pinned against eviction so an
    /// outstanding cursor can walk it (MCP-DESIGN fix #8 part B).
    #[arg(long = "cursor-ttl-secs", default_value_t = rf_mcp::DEFAULT_CURSOR_TTL.as_secs())]
    cursor_ttl_secs: u64,

    /// Materialize each paged scan as an NDJSON file here, so an agent
    /// with filesystem tools can grep the whole result instead of paging
    /// it. Must NOT fall inside an allow root: the agent must not be able
    /// to feed the server's own output back in as a binary.
    #[arg(long = "workspace-dir", value_name = "<path>")]
    workspace_dir: Option<PathBuf>,

    /// Engine gadget budget: a scan that accepts more than this stops with
    /// resource_exhausted. 0 disables the budget.
    #[arg(long = "max-gadgets", default_value_t = rf_mcp::DEFAULT_MAX_GADGETS)]
    max_gadgets: usize,

    /// Consecutive path_denied results in one session before responses are
    /// delayed by 250 ms and `probing_suspected` is logged. 0 disables it.
    #[arg(long = "probe-threshold", default_value_t = rf_mcp::DEFAULT_PROBE_THRESHOLD)]
    probe_threshold: u64,

    /// Default per-request timeout in seconds (1-300)
    #[arg(long, default_value_t = rf_mcp::DEFAULT_TIMEOUT_SECS)]
    timeout_secs: u64,

    /// Default max gadgets returned per request (hard max 50000)
    #[arg(long, default_value_t = rf_mcp::DEFAULT_MAX_RESULTS)]
    max_results: usize,

    /// Largest accepted `depth`. Requests above it are REJECTED with a
    /// usage_error, never silently clamped.
    #[arg(long, default_value_t = rf_mcp::DEFAULT_MAX_DEPTH)]
    max_depth: usize,

    /// Largest binary the server will read, in bytes (default 256 MiB).
    #[arg(long, default_value_t = rf_mcp::DEFAULT_MAX_FILE_BYTES)]
    max_file_bytes: u64,

    /// Scans allowed to run at once (default 2).
    #[arg(long, default_value_t = rf_mcp::DEFAULT_MAX_CONCURRENT)]
    max_concurrent: usize,

    /// Report why a path inside an allowed root could not be opened.
    /// Never applies outside a root, and off by default: the distinction
    /// between absent, directory and unreadable is an existence oracle.
    #[arg(long = "verbose-path-errors")]
    verbose_path_errors: bool,
}

/// Directories that are never a sensible allow root. A root is refused when
/// it IS one of these or is an ANCESTOR of one — not when it merely lives
/// inside one. `C:\Users\me\exploit-work` and `/usr/lib/x86_64-linux-gnu`
/// are ordinary, legitimate places to point the agent at; `C:\Users` and
/// `/usr` are not.
const WIDE_ROOTS: &[&str] = &[
    "/etc",
    "/usr",
    "/var",
    "/System",
    "/Library",
    "/home",
    "/Users",
    "/root",
    "/private/etc",
    "/private/var",
    r"C:\Users",
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
];

/// Strip a Windows `\\?\` verbatim prefix for display and for comparison
/// against the ordinary paths in [`WIDE_ROOTS`].
fn plain(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy().into_owned();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match s.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => p.to_path_buf(),
    }
}

/// Number of `Normal` components — the "how specific is this path" measure.
/// `/`, `C:\`, `/home` and `C:\Users` all score below 2.
fn depth_of(p: &Path) -> usize {
    p.components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count()
}

fn components_eq(a: &Component<'_>, b: &Component<'_>) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        let (x, y) = (a.as_os_str(), b.as_os_str());
        x.len() == y.len()
            && x.to_string_lossy()
                .eq_ignore_ascii_case(&y.to_string_lossy())
    } else {
        a == b
    }
}

/// `true` when `p` is `ancestor` or lives underneath it (component-wise, so
/// `/allowed-evil` is not under `/allowed`).
fn is_at_or_under(p: &Path, ancestor: &Path) -> bool {
    let a: Vec<Component<'_>> = ancestor.components().collect();
    let b: Vec<Component<'_>> = p.components().collect();
    !a.is_empty() && b.len() >= a.len() && a.iter().zip(b.iter()).all(|(x, y)| components_eq(x, y))
}

/// Why a proposed allow root is too wide to accept silently, if it is.
fn too_wide(root: &Path) -> Option<String> {
    let root = plain(root);
    if depth_of(&root) < 2 {
        return Some(format!(
            "{} has fewer than two path components, so it covers a filesystem root, a drive \
             root or a whole system directory",
            root.display()
        ));
    }
    if let Some(home) = home_dir() {
        let home = plain(&home);
        if is_at_or_under(&home, &root) {
            return Some(format!(
                "{} is your home directory or an ancestor of it ({})",
                root.display(),
                home.display()
            ));
        }
    }
    for wide in WIDE_ROOTS {
        // `is_at_or_under(w, root)` is true when root IS `w` or contains it.
        if is_at_or_under(Path::new(wide), &root) {
            return Some(format!(
                "{} is, or contains, the system directory {wide}",
                root.display()
            ));
        }
    }
    None
}

fn home_dir() -> Option<PathBuf> {
    for key in ["HOME", "USERPROFILE"] {
        if let Some(v) = std::env::var_os(key) {
            if !v.is_empty() {
                return Path::new(&v).canonicalize().ok().or(Some(PathBuf::from(v)));
            }
        }
    }
    None
}

/// Resolve the roots from the CLI, or explain why we refuse to start.
fn resolve_roots(cli: &ServerCli) -> Result<Vec<PathBuf>, String> {
    let mut requested: Vec<PathBuf> = cli.allow_dir.clone();
    if cli.allow_cwd {
        match std::env::current_dir() {
            Ok(d) => requested.push(d),
            Err(e) => {
                return Err(format!(
                    "--allow-cwd: cannot read the working directory: {e}"
                ))
            }
        }
    }
    if requested.is_empty() {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        return Err(format!(
            "refusing to start with no --allow-dir. The MCP host chooses this process's \
             working directory, so defaulting to it would grant access to whatever the host \
             happened to pick (currently: {}). Pass --allow-dir <dir> for each directory of \
             binaries you want the agent to analyse, or --allow-cwd to deliberately serve the \
             working directory.",
            plain(&cwd).display()
        ));
    }

    let mut roots = Vec::with_capacity(requested.len());
    for d in &requested {
        let canon = match d.canonicalize() {
            Ok(c) => c,
            Err(e) => return Err(format!("--allow-dir {}: {e}", d.display())),
        };
        if !canon.is_dir() {
            return Err(format!("--allow-dir {} is not a directory", d.display()));
        }
        if !cli.accept_wide_allowlist {
            if let Some(why) = too_wide(&canon) {
                return Err(format!(
                    "refusing to start: {why}. If that really is what you want, re-run with \
                     --i-accept-a-wide-allowlist; the agent will then be able to read every \
                     file under it."
                ));
            }
        }
        roots.push(canon);
    }
    Ok(roots)
}

/// A cache file or audit log inside a scannable root muddles the trust
/// boundary: the agent could read (and, through the cache, influence) the
/// server's own state.
fn reject_writable_paths_inside_roots(cli: &ServerCli, roots: &[PathBuf]) -> Result<(), String> {
    for (flag, path) in [
        ("--cache-dir", cli.cache_dir.as_ref()),
        ("--audit-log", cli.audit_log.as_ref()),
        ("--workspace-dir", cli.workspace_dir.as_ref()),
    ] {
        let Some(p) = path else { continue };
        // The path need not exist yet; canonicalize the nearest existing
        // ancestor so a not-yet-created cache dir is still checked.
        let mut probe = p.as_path();
        let resolved = loop {
            if let Ok(c) = probe.canonicalize() {
                break Some(c);
            }
            match probe.parent() {
                Some(parent) if parent != probe => probe = parent,
                _ => break None,
            }
        };
        let Some(resolved) = resolved else { continue };
        for root in roots {
            if is_at_or_under(&plain(&resolved), &plain(root)) {
                return Err(format!(
                    "refusing to start: {flag} {} is inside the allow root {}. Put it \
                     somewhere the agent cannot read.",
                    p.display(),
                    plain(root).display()
                ));
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = ServerCli::parse();

    let roots = match resolve_roots(&cli) {
        Ok(r) => r,
        Err(msg) => {
            eprintln!("rop-finder-mcp: {msg}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    if let Err(msg) = reject_writable_paths_inside_roots(&cli, &roots) {
        eprintln!("rop-finder-mcp: {msg}");
        return ExitCode::from(EXIT_CONFIG);
    }

    let mut config = ServerConfig {
        allow_dirs: roots,
        ..Default::default()
    };
    if let Some(dir) = &cli.cache_dir {
        match std::fs::create_dir_all(dir) {
            Ok(()) => config.cache_dir = Some(dir.clone()),
            Err(e) => {
                eprintln!("rop-finder-mcp: --cache-dir {}: {e}", dir.display());
                return ExitCode::from(EXIT_CONFIG);
            }
        }
    }
    config.timeout = Duration::from_secs(cli.timeout_secs.clamp(1, rf_mcp::HARD_MAX_TIMEOUT_SECS));
    config.max_results = cli.max_results.clamp(1, rf_mcp::HARD_MAX_RESULTS);
    config.max_depth = cli.max_depth.max(1);
    config.max_file_bytes = cli.max_file_bytes.max(1);
    config.max_concurrent = cli.max_concurrent.max(1);
    config.scan_threads = cli
        .scan_threads
        .map(|n| n.max(1))
        .unwrap_or_else(rf_mcp::guard::default_scan_threads);
    config.max_gadgets = (cli.max_gadgets > 0).then_some(cli.max_gadgets);
    config.cache_mem_bytes = cli.cache_mem_mb.saturating_mul(1024 * 1024);
    config.cache_ttl = Duration::from_secs(cli.cache_ttl_secs);
    config.cursor_ttl = Duration::from_secs(cli.cursor_ttl_secs);
    if let Some(dir) = &cli.workspace_dir {
        match std::fs::create_dir_all(dir) {
            Ok(()) => config.workspace_dir = Some(dir.clone()),
            Err(e) => {
                eprintln!("rop-finder-mcp: --workspace-dir {}: {e}", dir.display());
                return ExitCode::from(EXIT_CONFIG);
            }
        }
    }
    config.audit_log = cli.audit_log.clone();
    config.audit_log_max_mb = cli.audit_log_max_mb.max(1);
    config.probe_threshold = cli.probe_threshold;
    config.verbose_path_errors = cli.verbose_path_errors;

    // MCP-09. stderr, never stdout: stdout is the JSON-RPC transport and a
    // single stray write corrupts the session with no error anywhere.
    rf_mcp::logging::init_tracing("warn");

    let server = match RopFinderMcp::new(config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("rop-finder-mcp: cannot start: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };

    eprintln!(
        "rop-finder-mcp serving on stdio; session {}; allowed dirs: {}",
        server.session_id(),
        server.root_paths().join(", ")
    );
    if cli.accept_wide_allowlist {
        // A startup warning that reaches the audit log and the operator,
        // not just a terminal nobody is watching.
        tracing::warn!(
            roots = %server.root_paths().join(", "),
            "--i-accept-a-wide-allowlist is in effect: the agent can read every file under \
             the allow roots"
        );
    }
    if let Some(p) = &cli.audit_log {
        eprintln!("rop-finder-mcp: auditing to {}", p.display());
    }

    match server.serve(stdio()).await {
        Ok(running) => {
            if let Err(e) = running.waiting().await {
                eprintln!("[Error] MCP server failed: {e}");
                return ExitCode::from(EXIT_CONFIG);
            }
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("[Error] MCP initialization failed: {e}");
            ExitCode::from(EXIT_CONFIG)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shallow_and_system_roots_are_too_wide() {
        // Fewer than two components, on either platform's parsing rules.
        for p in ["/", "/home", "/Users", r"C:\"] {
            assert!(too_wide(Path::new(p)).is_some(), "{p} should be refused");
        }
        #[cfg(windows)]
        let named = [r"C:\Users", r"C:\Windows", r"C:\Program Files"];
        #[cfg(not(windows))]
        let named = ["/etc", "/usr", "/var", "/System", "/Library"];
        for p in named {
            assert!(too_wide(Path::new(p)).is_some(), "{p} should be refused");
        }
    }

    /// A root is refused for \EING a system directory or containing one —
    /// not for merely living inside one. `C:\Users\me\work` and
    /// `/usr/lib/x86_64-linux-gnu` are exactly where a real operator points
    /// the agent, so refusing them would make the flag unusable.
    ///
    /// Paths are parsed by the host platform's rules, so a Windows path only
    /// decomposes into components on Windows.
    #[test]
    fn a_specific_work_directory_is_accepted() {
        #[cfg(windows)]
        let ok = [
            r"C:\exploit-work\binaries",
            r"D:\samples\one",
            r"C:\Users\someone\exploit-work",
            r"C:\Windows\System32",
        ];
        #[cfg(not(windows))]
        let ok = [
            "/srv/exploit-work/binaries",
            "/opt/samples/one",
            "/usr/lib/x86_64-linux-gnu",
        ];
        for p in ok {
            assert!(too_wide(Path::new(p)).is_none(), "{p} should be accepted");
        }
    }

    /// $HOME itself, and anything containing it, is still refused — but a
    /// subdirectory of $HOME is a perfectly normal place to keep binaries.
    #[test]
    fn home_and_its_ancestors_are_refused() {
        let Some(home) = home_dir() else {
            eprintln!("no HOME/USERPROFILE; skipping");
            return;
        };
        let home = plain(&home);
        if depth_of(&home) < 2 {
            // Already covered by the component-count rule.
            return;
        }
        assert!(too_wide(&home).is_some(), "{}", home.display());
        let parent = home.parent().unwrap().to_path_buf();
        assert!(too_wide(&parent).is_some(), "{}", parent.display());
        assert!(too_wide(&home.join("rf-exploit-work")).is_none());
    }

    /// Component-wise, so `/allowed-evil` is not under `/allowed`.
    #[test]
    fn containment_is_component_wise() {
        assert!(is_at_or_under(
            Path::new("/allowed/x"),
            Path::new("/allowed")
        ));
        assert!(is_at_or_under(Path::new("/allowed"), Path::new("/allowed")));
        assert!(!is_at_or_under(
            Path::new("/allowed-evil/x"),
            Path::new("/allowed")
        ));
    }

    #[test]
    fn depth_counts_only_normal_components() {
        assert_eq!(depth_of(Path::new("/")), 0);
        assert_eq!(depth_of(Path::new("/home")), 1);
        assert_eq!(depth_of(Path::new("/home/user")), 2);
    }
}
