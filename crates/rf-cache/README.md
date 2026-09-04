# rop-finder-cache

The one scan cache shared by [rop-finder](https://docs.rs/rop-finder) and
`rop-finder-mcp`: integrity-tagged records, one key schema, an LRU/TTL memory
tier and a bounded on-disk tier.

```toml
[dependencies]
rop-finder-cache = "1"
```

```rust
use rf_cache::{make_key, MemCache, MemLimits};
```

**The package is `rop-finder-cache`; the library it provides is
`rf_cache`.**

## What is in it

* `make_key` — SHA-256 of the file plus *every* parameter that changes what
  a scan returns. `CLI-01`/`ENG-05` existed because a key omitted
  `--rawArch`, so a raw x86 scan could be served from an ARM entry.
* Entry authentication — each cache directory carries a 32-byte key and each
  record a MAC, so a tampered or truncated entry is a miss, never a wrong
  answer.
* `MemCache` with `MemLimits` — byte-bounded with LRU eviction and a TTL.
* Directory ownership checks (`CLI-07`/`MCP-04`) before a pre-existing cache
  directory is used.

It exists as its own crate because the duplication *was* the finding: the
align post-filter and a char-boundary panic each existed twice, once per
front end.

## Stability

The Rust API follows the workspace policy. **The on-disk format explicitly
does not**: `CACHE_FORMAT_VERSION` and the key schema version are folded into
both the hashed material and the file name precisely so that a format change
MISSES rather than mismatching. A format change is a cold cache, never a
wrong answer, and so it is not a breaking change.

## Building and testing

MSRV 1.88. BSD-2-Clause; see `LICENSE`.
