# rop-finder-scan

The gadget engine behind [rop-finder](https://docs.rs/rop-finder): anchor
tables per architecture, a resumable region decode, trie-indexed dedup, and
the ROPgadget-compatible filters. `ScanOptions` in, `Gadget`s out.

```toml
[dependencies]
rop-finder-scan = "1"
```

```rust
use rf_scan::{scan_binary, Gadget, GadgetSink, ScanOptions};
```

**The package is `rop-finder-scan`; the library it provides is `rf_scan`.**
See `rop-finder-core` for why the package names carry the product prefix.

## What is in it

* `ScanOptions` — depth, ROP/JOP/SYS selection, `align`, `multibr`,
  `call_preceded`, filters, a gadget budget and a cancellation token.
  Construct it as `ScanOptions { depth: 8, ..Default::default() }`: fields
  are added in minor releases.
* `GadgetSink` — stream a scan that is too large to hold in memory. The
  engine never materializes a `Vec` you did not ask for.
* `CancelToken` — a scan stops when the token is set, in bounded time. This
  is what the MCP server's timeout uses.
* x86/x64 decode via iced-x86; every other architecture via capstone, pinned
  exactly (`capstone = "=0.14.0"`) because disassembly text drifts between
  releases and the parity numbers are measured against a specific one.

Architectures: x86, x64, ARM (incl. Thumb), ARM64, MIPS32/64, PPC32/64,
SPARC(V9), RISC-V 32/64.

## Stability

Covered: item signatures, the `GadgetSink` trait, the `TableKind` variant
set, and the distinction between `Error::Cancelled`, `Error::Budget` and
`Error::Core`.

**Not covered: the exact gadget text, and which gadgets a given binary
yields.** `Gadget::text` is whatever iced-x86 or the linked capstone prints,
and a decode or anchor-table fix changes the set — that is a fix landing, and
`tests/parity.py` re-measures it rather than freezing it. Full list in
`docs/API-STABILITY.md`.

## Building and testing

MSRV 1.88. A C toolchain is required: `capstone-sys` builds the vendored C
capstone. The corpus-driven tests need the repository's fixtures, which the
published `.crate` does not contain — see `docs/PUBLISHING.md`.

BSD-2-Clause. See `LICENSE`.
