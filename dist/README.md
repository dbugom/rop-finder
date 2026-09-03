# dist/

**There are no prebuilt binaries in this repository any more.** This directory
holds this file and nothing else.

Until v0.1.1 it held four binaries — `linux-x86_64/rop-finder`,
`linux-x86_64/rop-finder-mcp`, `windows-x86_64/rop-finder.exe`,
`windows-x86_64/rop-finder-mcp.exe`, 41.4 MiB in total — committed straight
into git. They were removed (finding `ENG-09`) because a binary you cannot
verify is worse than no binary at all:

* no `SHA256SUMS`, no signature, no SBOM, and no reproducible build recipe, so
  nothing tied them to any particular commit of this source tree;
* stored with git mode `100644`, so `dist/linux-x86_64/rop-finder` was not
  executable on clone and the quick-start this file used to advertise failed
  with `Permission denied`;
* the Windows build was unstripped and embedded the panic-location paths of the
  whole dependency graph — every one of them rooted at the maintainer's home
  directory.

Removing them does not shrink the git history; the blobs stay in the objects of
any existing clone. It stops the problem growing, and it stops anyone running an
unverifiable binary from here.

Get a binary one of the two ways below instead.

## Build it yourself

```sh
cargo build --release -p rf-cli -p rf-mcp
# -> target/release/rop-finder       (CLI)
# -> target/release/rop-finder-mcp   (MCP server)
```

`rust-toolchain.toml` pins the toolchain (1.89.0 with `rustfmt` and `clippy`),
so rustup installs the right compiler on first invocation and everyone builds
with the same one. The workspace MSRV declared in `Cargo.toml` is 1.88 — the
real floor of the dependency graph, and a CI job builds on it.

The only non-Rust prerequisite is a C compiler, for the vendored Capstone
sources that the `capstone` crate builds:

| Host | Prerequisite |
|---|---|
| Linux | `cc` — `build-essential` or equivalent |
| macOS | Xcode Command Line Tools — `xcode-select --install` |
| Windows | the MSVC build tools that rustup's `x86_64-pc-windows-msvc` host already requires |

Cross-compiling to macOS from anywhere else needs the Apple SDK, which is
licensed for use on Apple hardware — build macOS binaries on a Mac, or take them
from a release (below), where CI does it on macOS runners.

To confirm what you built:

```sh
./target/release/rop-finder --version
```

## Download a release

Tagged pushes run `.github/workflows/release.yml`, which is the authority on
what a release contains and how it is produced. As specified in
`docs/REMEDIATION.md` (Phase 1), that job builds:

* `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` — statically
  linked, because an MCP host may launch the server under any glibc;
* a `lipo`-merged universal macOS binary, codesigned with `--options runtime
  --timestamp`, notarized via `xcrun notarytool submit --wait` and stapled —
  an unsigned download is quarantined by Gatekeeper and an MCP host's spawn
  then fails with no visible error;
* `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`.

Unix artifacts are packaged as `.tar.gz` so the `0755` mode survives — loose
files in a git tree do not preserve it, which is precisely the bug that made the
old `dist/linux-x86_64/rop-finder` unusable. Windows artifacts are `.zip`. Every
artifact ships with its checksum, and a per-platform smoke job downloads the
artifact it just built, asserts the binary is executable, and runs `--version`.

Verify a download against the published checksum before running it:

```sh
sha256sum -c SHA256SUMS
```

## Anything else in here

Nothing. If you find a binary under `dist/` in a working tree, it is a local
build artifact, not something this repository ships — `target/` is where builds
belong, and it is gitignored.

Full documentation: [`../README.md`](../README.md) and
[`../MANUAL.md`](../MANUAL.md). Measured performance and parity figures, with
the method used to obtain them, are in
[`../docs/measured-2026-09.md`](../docs/measured-2026-09.md).
