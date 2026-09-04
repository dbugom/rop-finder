# rop-finder-core

Binary loading for [rop-finder](https://docs.rs/rop-finder): ELF, PE, Mach-O,
fat Mach-O and raw blobs, behind one `Image` trait — sections and segments,
load-time rebasing, mitigations (NX, PIE, RELRO, canary, CFG, ASLR) and
symbol/import recovery.

```toml
[dependencies]
rop-finder-core = "1"
```

```rust
use rf_core::{Binary, LoadedBinary};
```

**The package is `rop-finder-core`; the library it provides is `rf_core`.**
Cargo names the extern after the library target, so the `use` line stays
`rf_core`. The package had to be renamed at 1.0.0 because `rf-core` on
crates.io is an unrelated crate belonging to someone else.

## What is in it

* `Binary::detect` / `Binary::load` — format sniffing by magic bytes and the
  loader dispatch. Unrecognized machine types are refused rather than scanned
  with a guessed decoder (`CORE-01`).
* The `Image` trait — executable regions, section table, image base, entry,
  architecture and endianness. This is what the scan engine consumes, and its
  method set is covered by semver.
* `rebase` on each loader — the `--base` model: every address becomes
  `vaddr - original_base + base`.
* `mitigations` and `symbols` — the `--info` report's raw material.

## Stability

`rop-finder-core` follows the workspace policy in `docs/API-STABILITY.md`.
Item signatures, the `Image` method set, and the `Arch` / `Format` /
`LoadedBinary` variant sets are covered by semver; message text is not, and a
new `Arch` variant is a minor release — match with a `_ =>` arm.

Pin the same major on every `rop-finder-*` crate you use: `rf_core` types
appear in `rf_scan`'s signatures, so two majors in one graph are two
incompatible type sets.

## Building and testing

MSRV 1.88 (declared in the workspace manifest and enforced by a CI job). The
unit tests in this crate read the repository's fixture corpus, which is not
part of the published `.crate` and cannot be redistributed — run them from a
git checkout. `docs/PUBLISHING.md` explains why.

BSD-2-Clause. See `LICENSE`, and `NOTICE` in the repository for the
attribution this project owes ROPgadget.
