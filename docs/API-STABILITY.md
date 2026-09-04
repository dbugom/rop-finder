# API stability

Closes `ENG-08` / `ECO-10`. This is the promise the published crates make,
and — just as important — the list of things they deliberately do *not*
promise, so that a consumer knows which of them are safe to build on and
which will move.

Every crate below repeats the crate-specific half of this document in its
own top-level rustdoc, so the answer is one `cargo doc --open` away and does
not depend on finding this file.

## The crates, and what each one is for

Every crate below has a **package name** (what you write in `Cargo.toml`)
and a **library name** (what you write in `use`). They differ: see
`docs/PUBLISHING.md` §2 for why, in short because `rf-core` and `rf-cli` on
crates.io already belong to other people.

| Package (crates.io) | `use` | Kind | What you depend on it for |
|---|---|---|---|
| `rop-finder-core` | `rf_core` | library | Loading a binary: ELF, PE, Mach-O, fat Mach-O, raw blobs. The `Image` trait, the section model, rebasing, mitigations, symbols. |
| `rop-finder-scan` | `rf_scan` | library | The gadget engine. `ScanOptions` in, `Gadget`s out, with a sink for streaming and a cancel token for stopping. |
| `rop-finder-classify` | `rf_classify` | library | What one gadget *does*: class, labels, registers set vs clobbered, stack delta, terminator, rank. |
| `rop-finder-chain` | `rf_chain` | library | Chain IR and the Linux / Windows builders, plus the `--plan-chain` feasibility report. |
| `rop-finder-cache` | `rf_cache` | library | The one authenticated, bounded scan cache both front ends share. |
| `rop-finder-api` | `rf_api` | library | The request layer both front ends share: `ScanRequest`, the option building, `scan_bytes` / `info_bytes` / `chain_bytes` and the cancellable twin, and the constraint query. |
| `rop-finder` | `rf_cli` | **binary** | The `rop-finder` executable. Install it; do not depend on it. |
| `rop-finder-mcp` | `rf_mcp` | **binary** | The `rop-finder-mcp` executable. Install it; do not depend on it. |
| `rf-bench` | `rf_bench` | not published | `publish = false`. Criterion benches only. |

`rf-cli` still exposes a library target, and it re-exports every `rf-api`
item so existing `use rf_cli::…` paths keep compiling — but it is a binary
crate, its library half carries clap types and output formatting, and
nothing outside this workspace should build against it. Until v1.0 `rf-mcp`
did exactly that, which is what `ENG-08` was about; `cargo tree -p rop-finder-mcp`
now mentions no `rf-cli` at all.

## What "pin `= "1"`" means here

These crates are versioned together and released together, so a workspace
that uses several of them should pin the same major on all of them:

```toml
[dependencies]
rop-finder-core = "1"
rop-finder-scan = "1"
rop-finder-classify = "1"
```

and then `use rf_core::…`, `use rf_scan::…`, `use rf_classify::…`: cargo
names the extern after the library target, not the package.

Mixing majors across the workspace is not supported: `rf_scan::Gadget`
appears in `rf-classify`'s and `rf-chain`'s signatures, so two majors of
`rf-scan` in one graph produces two incompatible `Gadget` types.

## Covered by semver

Breaking any of these needs a major release.

* **Item signatures.** Every `pub fn`, `pub struct`, `pub enum`, `pub trait`
  and `pub const` reachable from a crate root, unless it is listed below or
  marked `#[doc(hidden)]`.
* **Struct fields that are `pub`.** Reading them is stable. *Constructing*
  is not — see the next section.
* **Enum variant sets**, for matching: `rf_core::Arch`, `rf_core::Format`,
  `rf_core::LoadedBinary`, `rf_scan::TableKind`, `rf_classify::Class`,
  `rf_classify::Terminator`, `rf_classify::TerminatorClass`,
  `rf_chain::WordKind`, `rf_chain::ChainError`.
* **The string vocabularies both front ends share**: `Class::name`,
  `Terminator::name`, `TerminatorClass::ALL`, `LinuxTarget::NAMES`,
  `ApiRecipe::NAMES`, and `rf_api::arch_name`. `tests/capability_matrix.py`
  gates that the CLI and the MCP server accept the same 45 paired
  capabilities using exactly these spellings, so they cannot drift quietly.
* **The `rf_core::Image` trait's method set**, which is the contract every
  loader implements and the engine consumes.
* **The `rf_scan::GadgetSink` trait**, which is how a caller streams a scan
  too large to hold.
* **Error *kinds***: that `rf_api::ScanError` distinguishes `Usage` from
  `Binary` from `Chain`, and that `rf_scan::Error` distinguishes
  `Cancelled` from `Budget` from `Core`. A front end branches on these.

## Explicitly NOT covered

These change in minor and patch releases. Do not build a test, a parser or a
regex on them.

* **The CLI's human output format.** `rop-finder`'s text listing exists to
  be byte-compatible with ROPgadget, and it tracks ROPgadget. Use
  `--format json`, `--format jsonl` or `--format csv` if you are parsing.
* **The exact gadget text.** `Gadget::insns` and `Gadget::text` are whatever
  iced-x86 and the linked capstone print. capstone's disassembly text drifts
  between releases — that is why `crates/rf-scan/Cargo.toml` pins it exactly
  and `tests/parity.py` re-measures rather than asserting — so a bump of
  either decoder can change the string for the same bytes.
* **Which gadgets a given binary yields.** A decode or anchor-table fix
  changes the set. That is the fix landing, not a break; `tests/parity.py`
  records the number.
* **Which gadgets a chain picks, and therefore its byte payload.** A better
  strategy is a bug fix. What is held is that the chain *works*:
  `tests/emulate.py` runs it under Unicorn.
* **All message text.** Every `Display` string on every error type, every
  `ChainWord::comment`, every `Mitigation::evidence` sentence. They are
  diagnostics for humans and they get better.
* **Classifier outcomes for a particular gadget.** Which `Class` a gadget
  earns follows the rules in `TAXONOMY.md`; a rule fix changes outcomes.
  Cite the rule number, not the label you observed.
* **`quality_score` / `quality_score_full` numbers and `usability` tier
  boundaries.** These are a heuristic that is expected to be re-tuned
  against measured precision. Compare ranks; never compare absolute scores
  across versions, and never hardcode one.
* **The JSON documents.** `rf_api::info_json`, `plan_json` and `chain_json`
  produce documents that GAIN fields. Additive change only — nothing is
  renamed or removed without a major — but parse them permissively.
* **The on-disk cache format.** `rf_cache::CACHE_FORMAT_VERSION` and the key
  schema version are folded into both the hashed material and the file name
  precisely so that a format change MISSES rather than mismatching. A format
  change is a cold cache, never a wrong answer, and so it is not breaking.
* **Anything marked `#[doc(hidden)]`.** It is not API; it exists so the
  workspace's own crates and tests can reach it.
* **`rf-bench`**, entirely. It is `publish = false` — see
  `docs/PUBLISHING.md` §1 for the argument, crate by crate, about what is
  published and what is not.

## Additive changes that are minor, not major

Plan for these, because they will happen:

* **A new `Arch`, `Format`, `Class`, `Terminator`, `WordKind` or chain
  target.** Adding a supported architecture is the most likely single
  change this project will ever make. Match with a `_ =>` arm.
* **A new field on `ScanOptions`, `ScanRequest` or `LinuxChainOpts`.** All
  three implement `Default` for exactly this reason — construct them as
  `ScanOptions { depth: 8, ..ScanOptions::default() }`, never exhaustively,
  or a new option is a compile error for you.
* **A new field in any JSON document**, or a new mitigation in the
  `--info` report.
* **A mitigation answer moving from `Enabled::Unknown` to a decided
  `Yes`/`No`** as a reader learns to see the deciding bytes.

## Deprecation

An item that is going away is marked `#[deprecated(since = …, note = …)]`
for at least one minor release before it is removed, and the note names the
replacement. Nothing is removed in a patch release.

## MSRV

The workspace declares `rust-version` in the root `Cargo.toml` and pins the
toolchain in `rust-toolchain.toml`. The declared MSRV is derived from the
resolved graph, not aspirational:

```
cargo metadata --format-version 1 --locked
```

and take the maximum `rust_version`. Raising the MSRV is a **minor**
release, and it is stated in the changelog.

## Surfaces that are products, not APIs

Two things this project ships are contracts with *users* rather than with
*code*, and they have their own compatibility stories:

* **The CLI flag surface.** `tests/flag_conformance.py` holds it — 1,562
  cases. Flags are not removed; where rop-finder deliberately differs from
  ROPgadget, `--compat` restores the oracle's behaviour.
* **The MCP tool schemas.** `MANUAL.md`'s tool block is generated from the
  server's own `tools/list` by `cargo test -p rop-finder-mcp --test manual_schema`
  and fails if it has drifted. Tool parameters are additive; a removed
  parameter is a major release of `rf-mcp`.
