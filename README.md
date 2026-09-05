# rop-finder

A ROP/JOP/SYS gadget finder and ROP chain builder, written in Rust. It is a port of
[ROPgadget](https://github.com/JonathanSalwan/ROPgadget), and it agrees with ROPgadget on
**763,166 of 763,204 gadgets (99.995%)** across **24** fixtures — a figure enforced by a CI
gate that fails the build, not a number typed into this file.

It ships two binaries:

| Binary | What it is |
|---|---|
| `rop-finder` | the command-line tool |
| `rop-finder-mcp` | an MCP server, so an AI agent can drive the engine over stdio |

```console
$ rop-finder --binary /bin/ls --set-reg rdi --from-stack --no-clobber rsi,rdx \
             --max-side-effects 1 --terminator ret
Gadgets information
============================================================
0x0000000000401648 : pop rdi ; ret

Unique gadgets found: 1
```

That query narrowed 43,972 gadgets to one. Asking a gadget finder a *question* — rather than
grepping its output — is the thing this tool adds.

---

## What it does

**Finds gadgets.** ROP, JOP and syscall gadgets across 10 architectures: x86, x86-64, ARM,
ARM64, MIPS, PowerPC, PPC64, SPARC, RISC-V 32 and RISC-V 64. Reads ELF, PE, Mach-O, fat Mach-O
and raw blobs.

**Answers constraint queries.** `--set-reg rdi --from-stack --no-clobber rsi,rdx
--max-side-effects 1 --terminator ret` is one command, not a jq pipeline. The semantic layer
behind it — stack delta, register-transfer relations, clobber sets — is verified against a
Unicorn emulator on a 500-gadget sample with zero mismatches.

**Classifies and ranks.** `pop rdi ; ret` sorts above `retf 0xce39`, which sounds obvious and is
not: a naive quality score ties 92% of gadgets at the same value.

**Builds ROP chains that have been executed.** Every emitted chain is run under a Unicorn
harness in CI and observed to reach its goal — `execve("/bin/sh")` for Linux, or VirtualProtect
entered with four correct arguments and control transferred into shellcode whose first four
bytes survive. See [known limits](#known-limits) for what is not covered.

**Talks to agents.** `rop-finder-mcp` exposes 15 tools over stdio with a declared `outputSchema`
on every one, stable gadget ids, cursor pagination, an audit log, and a directory allowlist that
the server refuses to start without.

---

## Speed

<!-- speedup-table: current -->

Against ROPgadget 7.7, `--depth 10`, best-of-3 on both sides, Windows 11 / 24 logical CPUs.
Reproduce with `python tests/benchmark.py --runs 3 --no-ropper`.

| Fixture | ROPgadget | rop-finder | Speedup |
|---|---:|---:|---:|
| elf-Linux-x86 | 1.411 s | 0.086 s | **16.4x** |
| elf-x64-bash-v4.1.5.1 | 1.387 s | 0.096 s | **14.5x** |
| elf-ARM64-bash | 0.949 s | 0.101 s | **9.4x** |
| elf-Mips-Defcon-20-pwn100 | 5.288 s | 0.542 s | **9.7x** |
| elf-PowerPC-bash | 1.701 s | 0.232 s | **7.3x** |

Gadget counts are identical to the oracle's on all five, so these compare equal work.

Read that table with two caveats. The v0.1.1 release **retracted** an earlier ">=10x" headline
because the measured figures at the time were 5.7-6.2x on x86/x64 and 1.3-2.1x elsewhere —
**neither was met**, and PLAN.md recorded the criterion as unmet. The engine work in v0.5.0
reversed that, and the numbers above are the ones that did it. Second: much of the gain over the
v0.1.1 table is that it was taken on macOS where the *oracle* ran ~2.5x faster. Measured on one
machine against v0.4.0, the honest engine-only gain is 1.60x on x86 and 4.89x on ARM64.

[docs/COMPARISON-rp.md](docs/COMPARISON-rp.md) measures rp++ beating this tool at default
settings, which the speed table above does not tell you.

---

## Install

No published release yet — see [known limits](#known-limits). Build from source:

```bash
git clone https://github.com/dbugom/rop-finder
cd rop-finder
cargo build --release          # -> target/release/rop-finder{,-mcp}
```

You need a **C toolchain** as well as Rust: `capstone-sys` compiles about 44 MB of vendored C.

| Platform | Needs |
|---|---|
| Linux | `cross`, or `musl-tools`, or `zig` |
| Windows | MSVC C++ build tools (`cl.exe`) |
| macOS | Xcode Command Line Tools — `xcode-select --install` |

Rust floor is 1.88; `rust-toolchain.toml` pins the tested compiler to 1.89.0.

Packaging scripts produce stripped binaries with the build machine's paths removed, a
`SHA256SUMS`, and an archive that preserves the executable bit:

```bash
./dist/build-linux.sh                 # static musl
pwsh -File dist/build-windows.ps1
./dist/build-macos.sh --universal     # arm64 + x86_64
```

**Full per-OS instructions, including wiring the MCP server into Claude, are in
[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md).**

---

## Use it

```bash
# every gadget
rop-finder --binary ./target

# only ROP, deeper, ROPgadget-compatible regex filter
rop-finder --binary ./target --nojop --nosys --depth 12 --filter "j.*"

# what am I even looking at? format, base, sections, imports, mitigations
rop-finder --binary ./target --info

# where does "/bin/sh" live?
rop-finder --binary ./target --string "/bin/sh"

# stream a large scan into jq without buffering the whole array
rop-finder --binary ./target --format jsonl | jq -r 'select(.class=="stack-pivot") | .vaddr'

# build a chain, then ask why if it fails
rop-finder --binary ./target --ropchain
rop-finder --binary ./target --plan-chain --chain windows-virtualprotect
```

`--plan-chain` always succeeds. It returns machine-readable feasibility — which requirements the
binary meets, what was tried, and which parameter changes would help — instead of a prose
dead-end.

Every flag is documented in **[MANUAL.md](MANUAL.md)**, along with 9 scenario-based use cases —
kernel gadgets under `--section .text`, bad-byte-constrained chains, CET/GUARD_CF targets, and
the agent workflow.

---

## The MCP server

```bash
rop-finder-mcp --allow-dir /abs/path/to/binaries
```

`--allow-dir` is the only source of the allowlist and the server **exits 2 without it**. It fails
closed on purpose: the MCP host chooses the process's working directory, so defaulting to it
would grant access to whatever the host happened to pick.

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "rop-finder": {
      "command": "/abs/path/to/rop-finder-mcp",
      "args": ["--allow-dir", "/abs/path/to/binaries"]
    }
  }
}
```

On Windows, backslashes in that JSON **must be doubled** (`C:\\tools\\rop-finder-mcp.exe`) — a
single backslash is the most common reason the server silently fails to appear.

[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) covers Claude Code, per-OS config paths, a
hand-driven stdio handshake for debugging without any host, and a troubleshooting table.

---

## How it is verified

This project was rebuilt in response to a 137-finding independent audit. The evidence is in the
repository rather than in adjectives:

| Gate | What it proves |
|---|---|
| `tests/parity.py` | 99.995% agreement with ROPgadget 7.7 over 24 fixtures; **exits non-zero** on regression |
| `tests/emulate.py` | every emitted chain is executed under Unicorn and observed to reach its goal |
| `tests/flag_conformance.py` | 1,562 flag/fixture cases against the vendored oracle — a flag that is present but *wrong* fails like a missing one |
| `tests/capability_matrix.py` | the CLI and the MCP server answer 43 identical queries identically, so the two surfaces cannot drift |
| `tests/doc_claims.py` | every quantitative claim in the docs is re-measured; a stale number fails the build |
| `tests/mcp_workability.py` | an agent completes locate → constrain → classify → chain inside a token budget |
| `docs/gate-mutation.md` | five fixes deliberately reverted, each confirmed to turn a gate **red**, then restored |

That last one matters most: a gate nobody has watched fail is not a gate. Two of the five
reverts are invisible to the parity harness, which is exactly why they were run.

`cargo test --workspace`: **750 passing.**

---

## Known limits

Stated plainly, because the audit that produced this tool was mostly about unstated ones.

- **Nothing is published.** `cargo publish --dry-run` is clean for all eight crates; no crate has
  been uploaded to crates.io.
- **CI is green, with one gate weaker than it looks.** As of 2026-09-05, all 13 jobs pass: the
  test suite on ubuntu-22.04, macos-15 and windows-2022, parity against
  ROPgadget, flag conformance, the CLI/MCP capability matrix, MSRV, rustfmt, cargo-deny +
  cargo-audit, `cargo publish --dry-run`, doc-claims, criterion and cargo-fuzz, twice in a
  row (runs #19 and #20). The criterion gate is doing real work in that number: #19 recorded
  its baseline, #20 restored it -- the record step is conditional on a cache miss and shows
  as skipped -- so #20 was a genuine comparison against a previously banked run, not a
  benchmark measured against itself. One qualification remains, and it is not small: the
  fuzz job runs with `ASAN_OPTIONS=detect_leaks=0`, so CI performs no leak detection at all
  ([fuzz/README.md](fuzz/README.md) says why, and what it would take to restore it).
- **Getting there took six defects, none of which any local run could have found.** A corpus
  file no clone could reproduce; a cache test only ever correct on Windows; two timing
  assertions that encoded a fast workstation rather than a property; a `macos-13` runner
  GitHub had retired, which held one run open for 9h19m waiting for a machine that no longer
  exists; a truncating pointer subtraction inside iced-x86 that only panics under
  `overflow-checks`; and a bench baseline frozen against a contended runner. Four of the six
  were in the harness rather than the product -- which is the point: an unrun CI suite is a
  claim, not evidence.
- **No ARM64 or MIPS chain builder.** The scanner reads those architectures; the chain builder
  does not target them. They are absent from `--help` rather than advertised and broken.
- **`dist/build-macos.sh` has never run.** It is syntax-checked only. The release workflow
  does build a universal macOS binary and smoke-test it, so a macOS artifact now exists --
  but it is not produced by that script.
- **The universal binary's x86_64 half is never executed.** GitHub retired the macos-13
  Intel runner, and its successor is a billed larger runner, so every macOS job -- build,
  test and release smoke -- runs on arm64. The Intel slice is compiled and shipped without
  ever having been started on an Intel Mac.
- **`--badbytes 00` on 64-bit is unsatisfiable** by construction — every address below 2⁴⁸ packed
  little-endian contains a zero byte. Refusing is the correct answer.
- **rp++ is faster** at default settings and finds memory-indirect terminators this tool misses.
  See [docs/COMPARISON-rp.md](docs/COMPARISON-rp.md), which was written by measuring both.

The complete ledger — 119 findings closed, 15 partial, 3 deferred, with what remains for each —
is in [docs/REMEDIATION-OUTCOME.md](docs/REMEDIATION-OUTCOME.md).

---

## Documentation

| Document | For |
|---|---|
| [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) | installing, running and connecting to Claude, per OS |
| [MANUAL.md](MANUAL.md) | the complete flag reference and use cases |
| [docs/COMPARISON-rp.md](docs/COMPARISON-rp.md) | measured comparison against rp++ |
| [docs/API-STABILITY.md](docs/API-STABILITY.md) | what semver covers if you use the crates as libraries |
| [docs/REMEDIATION-OUTCOME.md](docs/REMEDIATION-OUTCOME.md) | the audit ledger |
| [docs/measured-2026-09.md](docs/measured-2026-09.md) | every performance and parity number, with its command |
| [TAXONOMY.md](TAXONOMY.md) | the gadget classification rules |

---

## Responsible use

rop-finder is a dual-use security tool, built for defensive research, CTFs, authorized
penetration testing and exploit-mitigation evaluation. Finding gadgets in binaries you own or are
authorized to test is standard practice. Using them against systems you are not authorized to
test is not.

The MCP server is deliberately local-only — stdio transport, directory allowlist, no network
listener. Keep it that way unless you add authentication.

---

## License and attribution

The Rust work is **BSD-2-Clause** — see [LICENSE](LICENSE). Written by Mohammad Razavi.

This is a port of **ROPgadget** by Jonathan Salwan, Alexey Vishnyakov and contributors
(BSD-3-Clause). [NOTICE](NOTICE) records that relationship and reproduces the upstream copyright.

`tests/fixtures/` holds 24 third-party binaries used as test data. They are **not** covered by
this project's license: [tests/fixtures/PROVENANCE.md](tests/fixtures/PROVENANCE.md) records the
origin and license of each one, and `tests/fetch_fixtures.py` can re-fetch them from ROPgadget's
test suite at a pinned commit if you would rather not hold copies.
