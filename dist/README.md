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

## Install it from crates.io

```sh
cargo install rop-finder        # -> `rop-finder`
cargo install rop-finder-mcp    # -> `rop-finder-mcp`
```

This is the shortest route, and it needs the same C toolchain the "build it
yourself" section lists. **Not available until the 1.0.0 release is actually
uploaded** — it is packaged and `cargo publish --dry-run`-verified but not
published; see `docs/PUBLISHING.md`.

## Build it yourself

```sh
cargo build --release -p rop-finder -p rop-finder-mcp
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

## Build them yourself

Three scripts, one per platform. All of them strip the binary, remap the build
machine's paths out of it, set mode 0755, emit `SHA256SUMS`, and package into an
archive so the executable bit survives a download. Output lands in
`dist/build/<platform>/`, which is gitignored -- see the note above about why
binaries do not belong in this repository.

```sh
./dist/build-linux.sh                 # static musl x86_64
./dist/build-linux.sh --arch aarch64
pwsh -File dist/build-windows.ps1     # MSVC x86_64
./dist/build-macos.sh                 # native (Apple Silicon -> arm64)
./dist/build-macos.sh --universal     # arm64 + x86_64, lipo'd
./dist/build-macos.sh --universal --sign "Developer ID Application: NAME (TEAMID)" \
                      --notarize-profile my-profile
```

### What each one needs

`rf-scan` depends on `capstone-sys`, which compiles ~44 MB of vendored C with the
`cc` crate, so **every** platform needs a working C toolchain -- not just a Rust
target.

| platform | C toolchain |
|---|---|
| Linux (musl) | `cross`, or `musl-tools`, or `zig` (the script picks whichever it finds) |
| Windows | MSVC C++ build tools (`cl.exe`) |
| macOS | Xcode Command Line Tools -- `xcode-select --install` |

### macOS notes

* **Apple Silicon** builds `aarch64-apple-darwin` natively; `--universal` adds
  `x86_64-apple-darwin` and `lipo`s the two together.
* **Unsigned binaries are quarantined by Gatekeeper**, and when that happens
  Claude Desktop's MCP spawn fails with no visible error -- it looks like the
  server is broken rather than blocked. Either pass `--sign`, or tell users to
  run `xattr -d com.apple.quarantine <binary>`.
* A bare executable cannot be stapled; the notarization ticket attaches to a
  container, which is why the script ships the `.tar.gz`.

### Verified for v1.0.0-rc1

Built and smoke-tested on 2026-09-04:

| artifact | size | check |
|---|---|---|
| `rop-finder` (linux-musl) | 11,951,344 | `statically linked, stripped`; `ldd` -> not a dynamic executable |
| `rop-finder-mcp` (linux-musl) | 14,895,696 | starts, exits 2 with no `--allow-dir` |
| `rop-finder.exe` (windows) | 12,558,336 | 42,508 gadgets on `elf-Linux-x86`, matching the oracle |
| `rop-finder-mcp.exe` (windows) | 16,522,752 | -- |

The Windows and Linux builds produce **byte-identical** gadget output: `--json`
on `elf-Linux-x64` at depth 10 is 5,992,606 bytes with SHA-256
`e982483145035d5316930f7e391ee0ce79bbdc218e0d4691a87e991995eaa4dc` from both.

Build-path leakage was measured before and after adding `--remap-path-prefix`:
`rop-finder.exe` went from **178** occurrences of the build machine's home
directory to **0**, and `rop-finder-mcp.exe` from **330** to **0**. The single
remaining `C:\Users` string in the MCP binary is not a leak -- it is the
wide-allowlist refusal table from `MCP-02`, naming roots the server declines to
serve.

macOS artifacts have **not** been produced: no macOS machine was available. The
script is written and syntax-checked but has never been executed.
