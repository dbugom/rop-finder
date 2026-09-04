# rop-finder-api

The front-end-agnostic API of [rop-finder](https://docs.rs/rop-finder). If
you are embedding gadget search in your own tool, **this is the crate to
depend on**: it is what the `rop-finder` CLI and the `rop-finder-mcp` server
both call, with no stdout scraping between them.

```toml
[dependencies]
rop-finder-api = "1"
```

```rust
use rf_api::{scan_bytes, ScanRequest};

let bytes = std::fs::read("/bin/ls").unwrap();
let req = ScanRequest { depth: 8, ..ScanRequest::default() };
let out = scan_bytes(&bytes, None, &req).unwrap();
for g in &out.result.gadgets {
    println!("0x{:x} : {}", g.vaddr, g.text());
}
```

**The package is `rop-finder-api`; the library it provides is `rf_api`.**

## What is in it

* `ScanRequest` → `scan_bytes` / `info_bytes` / `chain_bytes` /
  `plan_chain_bytes`, and `scan_bytes_cancellable` for a caller that must be
  able to stop a scan (a timeout, a cancelled request, a Ctrl-C).
* `ScanBudget` and `request_options_with` — the one mapping from a request to
  `rf_scan::ScanOptions`. It is public because it being private is what made
  the MCP server keep its own 55-line copy of it, which is how two front ends
  drifted apart.
* `query` — the v0.4 constraint layer: `sets`, `clobbers`, `reads`,
  `stack_delta`, `transfers`, `terminator`, expressed as a `Query` a caller
  can build directly instead of grepping disassembly text.
* Loading and views (`load_target`, `build_view`, `select_sections`), the
  `--info` JSON (`info_json`), and the PE export table reader.

`ScanError` distinguishes `Usage` from `Binary` from `Chain`; that
distinction is covered by semver, the message strings are not.

## Stability

Covered: item signatures, and the error kinds. Not covered: the JSON
documents' exact shape (they GAIN fields — parse permissively), all message
text, and which gadgets a given binary yields. See
`docs/API-STABILITY.md`.

Construct `ScanRequest` and `ScanOptions` with `..Default::default()`; new
fields are added in minor releases.

## Building and testing

MSRV 1.88, and a C toolchain for the vendored capstone that
`rop-finder-scan` builds.

BSD-2-Clause. See `LICENSE`.
