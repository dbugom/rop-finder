# Linux verification — 2026-09-04

The whole six-release programme was engineered and tested on one Windows box.
`docs/REMEDIATION-OUTCOME.md` names that as the qualification it would not waive:
the entire `#[cfg(unix)]` half of the suite had never executed anywhere, including
`crates/rf-mcp/tests/confine_race.rs` — the only executable proof for MCP-01, a
HIGH-severity arbitrary-file-read.

This document records the first execution of that code on Linux.

## How

No Linux CI runner and no `sudo` on this host, so:

* WSL2 Ubuntu (kernel 6.6.87.2, 24 logical CPUs) had `cargo`/`rustc` 1.89.0 but
  **no C compiler at all** — `cc`, `gcc`, `clang`, `make`, `cmake` all absent, and
  `sudo` requires a password, so `apt install build-essential` was not available.
* Installed **zig 0.13.0** into `~/zig` — a self-contained toolchain needing no root —
  and shimmed it as both the C compiler and the Rust linker:
      CC / CXX                                        -> ~/bin/zcc, ~/bin/zxx
      CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER    -> ~/bin/zcc
      RUSTFLAGS="-C linker=~/bin/zcc"
* The shim rewrites the target triple: `cc-rs` and `rustc` emit
  `--target=x86_64-unknown-linux-gnu`, which zig rejects with
  `UnknownOperatingSystem`. It is rewritten to zig's `x86_64-linux-gnu` form.

THIS SHIM IS A WORKAROUND FOR THIS MACHINE, NOT A PROJECT REQUIREMENT. An ordinary
Linux runner with `build-essential` needs none of it, and `.github/workflows/ci.yml`
assumes exactly that.

## Result — `cargo test -p rop-finder-mcp` on Linux

    18 test binaries, 237 passed, 0 failed.

The row that matters:

    Running tests/confine_race.rs
    test result: ok. 1 passed; 0 failed; 0 ignored

That is MCP-01's 400-iteration rename race — a background thread swapping an allowed
hardlink for a symlink pointing outside the allowlist while the server is driven at
the same path. Against the pre-v0.1.1 server this harness measured **323 of 400
requests (81%) returning a scan of a file OUTSIDE the allowlist**. It now passes on
the platform where the `O_NOFOLLOW` openat-from-a-pinned-dirfd walk actually applies.
On Windows this file is `#![cfg(unix)]` and reports "running 0 tests" — a SKIP, not
a pass, which is why this run was necessary.

Also executing for the first time on Linux, all green:

    audit_log 10 | cache_bounds 7 | cancellation 10 | effect_query 12 | effect_search 7
    info_caps 7 | manual_schema 5 | mcp_stdio 20 | mitigations 12 | nongadget_search 13
    paging 8 | rank 6 | resources 7 | schema_conformance 6 | stdout_purity 5
    lib 96 | main 5 | confine_race 1

`schema_conformance` drives the real server over stdio across all 24 fixtures;
`stdout_purity` asserts every stdout line of a full session parses as JSON-RPC 2.0.

## What is still NOT verified on Linux

`cargo test --workspace` did not complete. The WSL distribution failed to start on
three separate attempts under sustained build load
(`Wsl/Service/CreateInstance/E_FAIL`, and once `Input/output error` on `/usr/bin/grep`
mid-run), which is a host-level fault, not a code fault. One earlier run reported
`error: test failed, to rerun pass -p rop-finder --bin rop-finder`; that was collateral
from the VM dying — the target was re-run on a healthy instance and has **zero tests
and passes**. It is recorded here because a reader who saw the first log should know it
was investigated and disproved rather than ignored.

Before that failure the non-MCP crates had reached `83 passed, 0 failed` in one binary.
The remaining Unix-gated assertions — the 0700/0600 cache-permission enforcement, the
group/world-readable `.cachekey` refusal, and the FIFO rejection in `confine.rs` — are
therefore still unexecuted. One CI run on a real Linux runner closes them.
