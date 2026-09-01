//! `rop-finder` binary — thin shell; all logic lives in the `rf_cli`
//! library so the `rf-mcp` MCP server can reuse it (PLAN.md §6.1).

fn main() -> std::process::ExitCode {
    rf_cli::main_entry()
}
