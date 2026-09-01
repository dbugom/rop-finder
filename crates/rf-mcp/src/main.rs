//! `rop-finder-mcp` binary — stdio MCP server (PLAN.md §6.1). All logic
//! lives in the rf-mcp library.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use rf_mcp::{RopFinderMcp, ServerConfig};
use rmcp::{transport::stdio, ServiceExt};

#[derive(Parser, Debug)]
#[command(
    name = "rop-finder-mcp",
    version,
    about = "rop-finder MCP server (stdio transport only)"
)]
struct ServerCli {
    /// Additional directory to allow binary paths from (repeatable; the
    /// server process working directory is always allowed)
    #[arg(long = "allow-dir", value_name = "<path>")]
    allow_dir: Vec<PathBuf>,

    /// Optional on-disk cache directory (content-hash keyed)
    #[arg(long = "cache-dir", value_name = "<path>")]
    cache_dir: Option<PathBuf>,

    /// Default per-request timeout in seconds (1-300)
    #[arg(long, default_value_t = rf_mcp::DEFAULT_TIMEOUT_SECS)]
    timeout_secs: u64,

    /// Default max gadgets returned per request (hard max 50000)
    #[arg(long, default_value_t = rf_mcp::DEFAULT_MAX_RESULTS)]
    max_results: usize,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = ServerCli::parse();

    let mut config = ServerConfig::default();
    for d in &cli.allow_dir {
        match d.canonicalize() {
            Ok(c) if c.is_dir() => config.allow_dirs.push(c),
            Ok(_) => {
                eprintln!("[Error] --allow-dir {d:?} is not a directory");
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("[Error] --allow-dir {d:?}: {e}");
                return ExitCode::from(1);
            }
        }
    }
    if let Some(dir) = &cli.cache_dir {
        match std::fs::create_dir_all(dir) {
            Ok(()) => config.cache_dir = Some(dir.clone()),
            Err(e) => {
                eprintln!("[Error] --cache-dir {dir:?}: {e}");
                return ExitCode::from(1);
            }
        }
    }
    config.timeout = Duration::from_secs(cli.timeout_secs.clamp(1, rf_mcp::HARD_MAX_TIMEOUT_SECS));
    config.max_results = cli.max_results.clamp(1, rf_mcp::HARD_MAX_RESULTS);

    eprintln!(
        "rop-finder-mcp serving on stdio; allowed dirs: {}",
        config
            .allow_dirs
            .iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let server = RopFinderMcp::new(config);
    match server.serve(stdio()).await {
        Ok(running) => {
            if let Err(e) = running.waiting().await {
                eprintln!("[Error] MCP server failed: {e}");
                return ExitCode::from(2);
            }
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("[Error] MCP initialization failed: {e}");
            ExitCode::from(2)
        }
    }
}
