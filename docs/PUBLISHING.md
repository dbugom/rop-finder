# Publishing

Closes the packaging half of `ENG-08` / `ECO-10`. `docs/API-STABILITY.md`
says what the published crates *promise*; this file says what is published,
under which name, in which order, and what a maintainer has to do before the
first upload. Everything below was executed on 2026-09-04 with
`cargo 1.89.0 (c24e10642 2025-06-23)` on Windows 11.

> **Nothing in this repository has been uploaded.** Every command here was run
> with `--dry-run`. The exit criterion for v1.0.0 is that the dry run
> succeeds, not that anything reached crates.io.

## 1. What is published, and what is not

Nine crates, eight published. Each line is a decision, not a default.

| Package | Directory | Library target | Published? | Why |
|---|---|---|---|---|
| `rop-finder` | `crates/rf-cli` | `rf_cli` | **yes** | The product. `cargo install rop-finder` is PLAN's own exit criterion, and a binary nobody can install is the whole of `ENG-08`. Its library half ships because a package cannot suppress one target, but `docs/API-STABILITY.md` excludes it from every promise. |
| `rop-finder-mcp` | `crates/rf-mcp` | `rf_mcp` | **yes** | The second front end, installed the same way (`cargo install rop-finder-mcp`) by anyone wiring an agent host. Publishing it is also the proof that `ENG-08` is fixed: it could not be published at all while it depended on the `rf-cli` **binary** crate. |
| `rop-finder-api` | `crates/rf-api` | `rf_api` | **yes** | The answer to "a library a third party can build against". This is the layer both front ends call, so publishing anything else without it would leave a consumer re-implementing the request/option mapping — the exact duplication `ENG-08` was filed about. |
| `rop-finder-core` | `crates/rf-core` | `rf_core` | **yes** | Useful on its own: a loader for ELF/PE/Mach-O/fat/raw with a section model and a mitigations report, no gadget machinery attached. Also a hard dependency of everything above. |
| `rop-finder-scan` | `crates/rf-scan` | `rf_scan` | **yes** | The engine. `ECO-10`'s complaint is precisely that `cargo add rf-scan` was impossible. |
| `rop-finder-classify` | `crates/rf-classify` | `rf_classify` | **yes** | Separable and independently useful — a caller with its own scanner can still ask what a gadget does. Required by `rop-finder-chain`. |
| `rop-finder-chain` | `crates/rf-chain` | `rf_chain` | **yes** | The Chain IR is the typed interface `ECO-10` says downstream tools have no versioned way to reach. |
| `rop-finder-cache` | `crates/rf-cache` | `rf_cache` | **yes** | Published because it must be: `rop-finder` and `rop-finder-mcp` depend on it, and a published crate cannot depend on an unpublished one. Its Rust API is semver'd; its on-disk format explicitly is not (`docs/API-STABILITY.md`). |
| `rf-bench` | `crates/rf-bench` | `rf_bench` | **no — `publish = false`** | A benchmark harness, not a library: criterion benches plus the `probe` binary CI's regression checker drives, over an empty lib. It is useless without the fixture corpus, which cannot be redistributed (§5), and nothing outside this workspace could depend on it for anything. `ECO-10` counts an *unstated* intent as the defect, so the key is set explicitly rather than left off. |

`rf-bench` keeps its short name because it is never uploaded, so it cannot
collide with anything.

## 2. The names changed at 1.0.0, and why

The directories and every `use` line are unchanged. The **package** names —
the names on crates.io — are not.

```
crates/rf-core/      package rop-finder-core       lib rf_core
crates/rf-scan/      package rop-finder-scan       lib rf_scan
crates/rf-classify/  package rop-finder-classify   lib rf_classify
crates/rf-chain/     package rop-finder-chain      lib rf_chain
crates/rf-cache/     package rop-finder-cache      lib rf_cache
crates/rf-api/       package rop-finder-api        lib rf_api
crates/rf-cli/       package rop-finder            lib rf_cli   bin rop-finder
crates/rf-mcp/       package rop-finder-mcp        lib rf_mcp   bin rop-finder-mcp
crates/rf-bench/     package rf-bench (unpublished)
```

Two reasons, in order of force.

**The old names are taken.** Not "might be" — checked, on 2026-09-04:

```
$ cargo info rf-core
Downloaded rf-core v0.6.0
The core library for the RuFi framework

$ cargo info rf-cli
Downloaded rf-cli v1.0.0-rc.18
RavenFabric — CLI client (rf)

$ cargo info rop-finder
error: could not find `rop-finder` in registry `https://github.com/rust-lang/crates.io-index`
```

Every `rop-finder*` name reports that same "could not find" — i.e. is free —
and `rf-core` and `rf-cli` belong to other people. Publishing this workspace
under the old names is not a preference, it is impossible. (`rf-scan`,
`rf-chain`, `rf-classify`, `rf-cache`, `rf-api` and `rf-mcp` happen to be
free today; taking them would still leave the family split across two naming
schemes, and would still not give `cargo install rop-finder` a package to
install.)

**`cargo install rop-finder` needs a *package* called `rop-finder`.** A
`[[bin]] name = "rop-finder"` inside a package called something else does not
satisfy it; `cargo install` takes a package name.

Cargo names an extern after the **library target**, not the package, so
`[lib] name = "rf_core"` keeps every `use rf_core::…` in this workspace — and
in anyone's code — compiling unchanged. A consumer writes:

```toml
[dependencies]
rop-finder-api = "1"
```

```rust
use rf_api::{scan_bytes, ScanRequest};
```

That mapping is stated in each crate's own README and at the top of its
manifest, because it is the one thing about these packages a reader cannot
guess.

**Reading older documents.** Dated evidence files — `docs/measured-2026-09.md`,
`docs/chain-regressions.md`, `docs/gate-mutation.md`,
`docs/classifier-eval.md`, `docs/AUDIT-FINDINGS.md`,
`tests/parity-baseline/README.md` — quote commands as they were run at the
time, with `-p rf-cli`, `-p rf-mcp`, `-p rf-classify`. They are records of
past runs and were deliberately not rewritten; translate them through the
table above. Live instructions (README, MANUAL, `dist/README.md`,
`docs/API-STABILITY.md`, CI, and the doc comments that tell you how to re-run
a test) were updated.

## 3. Versions and internal requirements

`[workspace.package] version = "1.0.0"`, inherited by all nine members. The
internal dependency requirements live once in the root
`[workspace.dependencies]`:

```toml
rop-finder-core = { path = "crates/rf-core", version = "1.0.0" }
```

Both keys are required. `path` is what the workspace builds against; `version`
is what the *published* crate resolves against, and `cargo publish` refuses a
dependency that has only the former. The requirement is a caret, not `=1.0.0`,
because these crates release in lockstep and what matters is that a consumer's
graph unifies on one 1.x of each — `rf_scan::Gadget` appears in
`rf_classify`'s and `rf_chain`'s signatures, so two majors in one graph are
two incompatible types.

Removing the bare path deps is also what let `deny.toml` go back to
`wildcards = "deny"`: cargo-deny counts a version-less path dependency as a
wildcard, and `allow-wildcard-paths` does not apply to a publishable crate.
`cargo deny check advisories licenses bans sources` now reports
`advisories ok, bans ok, licenses ok, sources ok`.

## 4. Before the first real publish

1. **Set `repository`.** `[workspace.package] repository` is
   `https://github.com/dbugom/rop-finder` (set 2026-09-05). This working copy had no git
   remote at all, so there is no URL to put there, and inventing a github.com
   path would point crates.io and docs.rs at a repository that either does not
   exist or belongs to somebody else. `.invalid` is reserved by RFC 2606 so a
   placeholder can never resolve to a stranger's property. Replace it — one
   line, inherited by all nine crates. Nothing else is blocked on it, and
   `cargo publish --dry-run` does not check it.
2. Own the names. Publishing claims a name **permanently**; a mistake cannot
   be undone, only yanked. Re-run the `cargo info` checks in §2 first.
3. Green tree: the full `cargo test --workspace`, all eight gates,
   `cargo deny check`, `cargo audit`, `cargo fmt --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`.
4. Tag the release commit, so the `.cargo_vcs_info.json` inside each tarball
   points at a real commit.

## 5. What is in the tarball, and what is not

Measured with `cargo package --list` and the dry runs of 2026-09-04:

| Package | Files | Size (compressed) |
|---|---:|---:|
| `rop-finder-core` | 22 | 245.7 KiB (69.5 KiB) |
| `rop-finder-scan` | 19 | 324.2 KiB (92.9 KiB) |
| `rop-finder-classify` | 25 | 614.5 KiB (137.5 KiB) |
| `rop-finder-chain` | 10 | 318.7 KiB (81.9 KiB) |
| `rop-finder-cache` | 13 | 109.2 KiB (32.3 KiB) |
| `rop-finder-api` | 10 | 135.3 KiB (40.4 KiB) |
| `rop-finder` | 15 | 306.6 KiB (84.1 KiB) |
| `rop-finder-mcp` | 41 | 972.9 KiB (228.0 KiB) |

Each carries its own `README.md` — the crates.io front page — and a copy of
`LICENSE`, because a tarball is a redistribution and BSD-2-Clause asks for the
notice to travel with it.

**No fixture corpus, and this is deliberate.** `cargo package
-p rop-finder-core --list` emits zero fixtures, which is the observation
`ENG-08` makes. The corpus cannot be shipped: `tests/fixtures/PROVENANCE.md`
records that those 24 files are third-party binaries explicitly carved out of
this repository's licence, several of them — Microsoft's `cmd.exe`, Apple's
`ls` and `libSystem.B.dylib` — "not redistributable at all under the terms
their vendors publish". Putting 17 MB of them inside a crates.io package
would be a licence violation, not a convenience.

The consequence is measured rather than hand-waved. In the packaged crate:

```
$ cd target/package/rop-finder-core-1.0.0 && cargo test
test result: FAILED. 33 passed; 43 failed
```

Every one of the 43 fails on `fixture should exist`. **What the tarball
verifies on its own is the build** — which is what `cargo publish` checks and
what a consumer's `cargo build` does — plus the 33 tests that construct their
inputs in code. The corpus-driven suites are repository-level gates: clone,
run `python tests/fetch_fixtures.py` (it re-fetches all 24 from upstream and
verifies them against `MANIFEST.sha256`), then `cargo test --workspace`.

The remaining honest improvement is for the fixture-reading unit tests to
*skip* rather than fail when the corpus is absent. That is a change in `src/`
rather than in a manifest, and it is the one part of `ENG-08` this packaging
pass does not close.

## 6. Publish order

Strictly bottom-up: each crate must be on crates.io before anything that
depends on it, and the index needs a moment to catch up between uploads.

```
1. rop-finder-core
2. rop-finder-scan
3. rop-finder-classify
4. rop-finder-chain
5. rop-finder-cache
6. rop-finder-api
7. rop-finder            (the CLI)
8. rop-finder-mcp
```

(`rop-finder-cache` depends only on `rop-finder-scan`, and dev-depends on
`rop-finder-classify`; anywhere after 3 is fine. The rest is forced.)

## 7. Verifying without publishing

```sh
cargo publish --dry-run --allow-dirty -p rop-finder-core
cargo publish --dry-run --allow-dirty -p rop-finder-scan \
    --config .cargo/publish-dry-run.toml
```

`--allow-dirty` is there because this release work is not committed; a real
release runs from a clean, tagged tree without it.

`--config .cargo/publish-dry-run.toml` is the **pre-first-publish bootstrap**,
and every dependent crate needs it. `cargo publish --dry-run` strips the
`path` from each dependency and then verifies the tarball by building it,
which means resolving `rop-finder-core = "1.0.0"` against crates.io — where,
before the first publish, it does not exist:

```
error: failed to prepare local package for uploading
Caused by: no matching package named `rop-finder-core` found
  location searched: crates.io index
```

Cargo 1.89 offers no stable way around that: `--workspace` on `cargo publish`
is unstable, and 1.89's `cargo package --workspace` does not overlay sibling
packages either (both checked on this toolchain). The bootstrap file is a
`[patch.crates-io]` pointing the six `rop-finder-*` library names at their
local directories, so the verification build sees the graph a consumer will
see *after* step 6 has run. It is not loaded automatically — cargo only reads
`.cargo/config.toml` — and it does not change the tarball: `cargo package
--list` and the packaged `Cargo.toml` are identical with and without it. Only
where the verification build gets its dependencies differs.

After step 6, drop the `--config` and the dry run resolves for real. That is
the one check this file cannot make for you.

## 8. Result on 2026-09-04

All eight published crates, dry-run in the order of §6. Each printed:

```
Packaging <pkg> v1.0.0 …
Packaged N files, … 
Verifying <pkg> v1.0.0 …
Finished `dev` profile [unoptimized + debuginfo] target(s)
Uploading <pkg> v1.0.0 …
warning: aborting upload due to dry run
```

No errors, and no `manifest has no documentation, homepage or repository`
warning on any of them — that warning is what `ENG-08` reports as the
metadata defect, and it is gone because every crate now carries
`description`, `repository`, `readme`, `documentation`, `keywords`,
`categories` and `license`.

The only other diagnostics are `Patch … was not used in the crate graph`
lines from the bootstrap file, which are expected: a crate low in the graph
does not use the patches meant for the ones above it.
