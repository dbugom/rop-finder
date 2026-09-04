# rop-finder-mcp

The [rop-finder](https://docs.rs/rop-finder) gadget engine as an MCP (Model
Context Protocol) server, for agent hosts. **stdio transport only — there is
deliberately no network listener.**

```sh
cargo install rop-finder-mcp
rop-finder-mcp --allow-dir /abs/path/to/binaries
```

`--allow-dir` takes absolute paths and is the *only* source of the file
allowlist; started with none, the server exits 2 rather than defaulting to
its working directory.

## The tools

Fifteen of them: `find_gadgets`, `find_jop_gadgets`, `find_syscall_gadgets`,
`find_gadgets_by_effect`, `find_bytes`, `find_string`, `get_gadgets`,
`get_binary_info`, `get_mitigations`, `get_server_config`,
`get_server_stats`, `search_gadgets_by_pattern`, `run_ropgadget_command`,
`plan_chain` and `build_rop_chain`.

Every tool returns structured JSON with a declared `outputSchema`; errors are
`{error: {code, message, retryable, details, suggestions}}` with the MCP
`isError` flag. The generated schema block, with every parameter, is in the
repository's `MANUAL.md` and is regenerated from the server's own
`tools/list` by a test, so it cannot drift.

## What the server enforces

* **Path confinement by open-then-verify handle**, not by canonicalizing a
  string: `openat(O_NOFOLLOW)` per component on Unix, handle validation via
  `GetFinalPathNameByHandleW` on Windows. The open handle, not a path,
  crosses into the worker, so there is no check-then-read window.
* **One denial code** (`path_denied`) with no OS error text, so the server is
  not a whole-filesystem existence oracle.
* **Hard caps**: results, depth, file size, concurrency, per-request timeout,
  engine gadget budget and thread count — readable back through
  `get_server_config`.
* **Cancellation that stops work.** A timed-out request cancels its scan; a
  worker that has not stopped within 5 s is reported and counted, not
  silently orphaned.
* **An audit trail** (`--audit-log`): one JSON line per call, denials and
  timeouts included, carrying hashes and counts — never gadget text or file
  bytes.

Read the repository README's "What this does NOT protect against" list before
running it. The short version: confinement is exactly as narrow as the roots
you pass, and the binary's bytes reaching the agent is the product, not a
leak.

## Notes

* MSRV 1.88; a C toolchain is required (vendored capstone).
* The package is `rop-finder-mcp`; the executable is `rop-finder-mcp`; the
  internal library target is `rf_mcp` and is not a published API.
* BSD-2-Clause (`LICENSE`); see `NOTICE` in the repository.
