# rop-finder

A Rust rewrite of [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) —
a memory-safe ROP/JOP/SYS gadget finder with structured internals, aiming
for output parity with the original Python tool.

**Measured speed vs ROPgadget 7.7** (`--depth 10`, Windows 11 / 24 logical
CPUs, rustc 1.89.0, ROPgadget 7.7 on CPython 3.12.10 + capstone 5.0.7;
best-of-3 on both sides — full method, raw timings and the same-machine
v0.4.0 control in
[`docs/measured-2026-09.md`](docs/measured-2026-09.md)):

<!-- speedup-table: current -->

| Fixture | ROPgadget | rop-finder | Speedup |
|---|---:|---:|---:|
| elf-Linux-x86 | 1.411 s | 0.086 s | 16.4x |
| elf-x64-bash-v4.1.5.1 | 1.387 s | 0.096 s | 14.5x |
| elf-ARM64-bash | 0.949 s | 0.101 s | 9.4x |
| elf-Mips-Defcon-20-pwn100 | 5.288 s | 0.542 s | 9.7x |
| elf-PowerPC-bash | 1.701 s | 0.232 s | 7.3x |

PLAN.md's Phase-1 exit criterion asked for a tenfold speedup on x86/x64 and a
fourfold one elsewhere. At v0.1.1 **neither was met** (6.2x / 5.7x on x86/x64
and 1.3–2.1x elsewhere), the claim was retracted, and PLAN.md recorded the
criterion as NOT MET. Phase 6 re-measured against that table and **both lines
are met now, on every architecture**.

Two caveats, because a speedup is a ratio and both sides of it moved. The
v0.1.1 figures were taken on macOS/Apple Silicon with CPython 3.11, where the
oracle was roughly 2.5x faster than it is here, so `16.4x vs 6.2x` overstates
what the engine gained. The controlled number is a v0.4.0 build of this
repository measured on this machine an hour earlier: the engine itself got
**1.6x faster on x86/x64 and 4.3–5.0x faster on the capstone-backed
architectures**, and the ratio against the oracle went 10.1x → 16.4x (x86),
9.0x → 14.5x (x64), 1.9x → 9.4x (ARM64), 2.0x → 9.7x (MIPS), 1.7x → 7.3x
(PPC). The gadget set is byte-identical across that change, on all 22
scannable fixtures, in the raw pre-dedup stream as well as the final one.
Second caveat, unchanged from v0.1.1: the small fixtures (raw-x86.raw, the
RISC-V pair, pe-ARMv7) show 10-12x, but those runs are dominated by CPython's
interpreter startup rather than scan work and are not evidence for anything.

ROPgadget remains the parity oracle. Two things this repository refers to
live *outside* it: `../PLAN.md`, the original design document, and
`../ropgadget`, the oracle checkout the parity harnesses run against. Neither
is needed to install, use or build rop-finder — only the three harnesses that
compare against it (`tests/parity.py`, `tests/chain_parity.py`,
`tests/flag_conformance.py`) want the oracle, and each says so when it is
missing.

**📖 User documentation: [MANUAL.md](MANUAL.md)** — installation, concepts,
CLI reference, and 9 scenario-based use cases (ASLR workflows, ring0 kernel
gadget discovery, chain generation, MCP/AI-agent setup, …). It also carries
the [ROPgadget flag-coverage table](MANUAL.md#ropgadget-flag-coverage) and
the [list of known divergences](MANUAL.md#known-divergences) from the oracle.

## Install

```sh
cargo install rop-finder        # the CLI  -> `rop-finder`
cargo install rop-finder-mcp    # the MCP server -> `rop-finder-mcp`
```

> **Not uploaded yet.** As of this commit the 1.0.0 release is *packaged and
> verified* — `cargo publish --dry-run` succeeds for all eight published
> crates — but nothing has been sent to crates.io, so the two lines above will
> not resolve until a maintainer runs the release in
> [`docs/PUBLISHING.md`](docs/PUBLISHING.md) §6. Build from a checkout until
> then; the instructions below work today.

**Prerequisites.** Rust 1.88 or newer (the declared MSRV; `rust-toolchain.toml`
pins 1.89.0 for development) and a C toolchain — `capstone-sys` builds the
vendored C capstone that drives every non-x86 architecture. Nothing else: no
Python, no ROPgadget, no system capstone. Python is needed only to run this
repository's own gates.

From a checkout instead:

```sh
git clone <this repository> && cd rop-finder
cargo build --release -p rop-finder -p rop-finder-mcp
# -> target/release/rop-finder, target/release/rop-finder-mcp
```

There are deliberately no prebuilt binaries committed in this repository;
[`dist/README.md`](dist/README.md) explains why (`ENG-09`) and describes the
release artifacts `.github/workflows/release.yml` is configured to produce —
`SHA256SUMS` over every artifact, and macOS builds codesigned with a hardened
runtime and notarized. That workflow has never run (this checkout has no git
remote), so **no release artifact of this project exists yet**; build from
source.

### Using it as a library

The engine is split into crates a third party can build against — that is
what `ENG-08`/`ECO-10` were about, and at 1.0.0 they are packaged for
crates.io (with the caveat in the note above). **Package names carry the product prefix; the
`use` names do not**, because cargo names an extern after the library target:

| `cargo add …` | `use …` | What it gives you |
|---|---|---|
| `rop-finder-api` | `rf_api` | **Start here.** `ScanRequest` → `scan_bytes` / `info_bytes` / `chain_bytes`, the cancellable twins, the constraint query. What both front ends call. |
| `rop-finder-core` | `rf_core` | Loaders: ELF, PE, Mach-O, fat Mach-O, raw; sections, rebasing, mitigations, symbols. |
| `rop-finder-scan` | `rf_scan` | The engine: `ScanOptions`, `Gadget`, the streaming sink, the cancel token. |
| `rop-finder-classify` | `rf_classify` | What a gadget does: class, labels, sets/clobbers, stack delta, terminator, rank. |
| `rop-finder-chain` | `rf_chain` | Chain IR and the Linux/Windows builders. |
| `rop-finder-cache` | `rf_cache` | The authenticated, bounded scan cache both front ends share. |

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

What is covered by semver and what deliberately is not — the human output
format, the exact gadget text, quality scores, error strings, the on-disk
cache format — is [`docs/API-STABILITY.md`](docs/API-STABILITY.md). Which
crate is published, under which name, and in which order they go out is
[`docs/PUBLISHING.md`](docs/PUBLISHING.md). Pin the same major on every
`rop-finder-*` crate: `rf_scan::Gadget` appears in `rf_classify`'s and
`rf_chain`'s signatures, so two majors in one graph are two incompatible
types.

## Layout

Directory names keep the short `rf-` prefix; the crates.io package names do
not (`rf-core` and `rf-cli` are unrelated crates owned by other people —
`docs/PUBLISHING.md` §2).

```
crates/
  rf-core/      # rop-finder-core:     binary loaders (goblin): ELF, PE,
                # Mach-O, Universal, Raw; mitigations; symbols
  rf-scan/      # rop-finder-scan:     anchor tables, resumable region decode,
                # trie-indexed dedup, iced-x86 (x86/x64) + capstone-rs (all
                # other arches), rayon
  rf-classify/  # rop-finder-classify: semantic classification, the constraint
                # predicates, quality/usability ranking
  rf-chain/     # rop-finder-chain:    Chain IR + Linux execve/mprotect/
                # syscall/ret2libc/SROP and Windows VirtualProtect builders
  rf-cache/     # rop-finder-cache:    the one authenticated, bounded scan
                # cache, shared by both front ends
  rf-api/       # rop-finder-api:      shared request/option layer:
                # ScanRequest, the option building, scan_bytes/info_bytes/
                # chain_bytes and the cancellable twin, and the query layer
  rf-cli/       # rop-finder:          the `rop-finder` CLI (clap), output
                # formats, cache directory policy, interactive console
  rf-mcp/       # rop-finder-mcp:      the `rop-finder-mcp` MCP server
                # (rmcp SDK, stdio only)
  rf-bench/     # not published:       criterion benches + the `probe` binary
tests/
  fixtures/     # binaries copied from ROPgadget's test suite (all formats)
  parity.py     # output-parity harness against ROPgadget (run with python)
  capability_matrix.py  # the CLI and the MCP server expose the same tool
fuzz/           # cargo-fuzz targets + `rf-smoke`, the portable mutation
                # harness that runs on stable Rust everywhere
```

## Phase roadmap (PLAN.md §7)

| Phase | Deliverable | Status |
|---|---|---|
| **0. Spike** | `rf-core` + `rf-scan` MVP: x86/x64 ELF only, memchr anchors, per-start decode cache, JSON out; parity harness | done — though the decode cache it shipped was measured at a 0.8% hit rate and deleted in v0.5 (`PERF-03`) |
| **1. Engine** | All ROPgadget arches (capstone-rs), PE/Mach-O/Universal/Raw loaders, rayon parallelism, trie index | **done** — parity 99.995% over 24 fixtures; the perf exit criterion is MET as of v0.5 (>=10x on x86/x64, >=4x elsewhere — see the table above); the suffix-trie index ships as `rf_scan::trie` and is what dedup runs on. The fuzz corpus exists (`fuzz/`, seven cargo-fuzz targets plus the portable `rf-smoke` harness) and the 10K-mutation criterion has an artifact 10x its size: 100,000 mutants, 0 panics |
| 2. Features | `--section`, `--base` hardening, `--info` structured binary info | **done** |
| 3. MCP server | `rf-mcp` stdio tools | **done** |
| 4a. Chains | Chain IR, Linux execve chains (x86 int 0x80, x64 syscall) | **done** |
| 4b. Chains | Windows VirtualProtect chains (x64 register ABI + x86 stdcall), anchor/IAT/export API resolution, alignment invariant, stack pivots, shellcode staging, multi-call composition, `--cfg-aware` | **partial** — 2 of 3 PLAN exit criteria met. The emulator harness landed in v0.5 (`tests/emulate.py`): every advertised Windows chain is now generated by the real CLI and *executed*, with VirtualProtect's four arguments and the shellcode's first four bytes asserted, and `CHWIN-01/-02/-03/-07` each have a failing-before and passing-after run in [`docs/chain-regressions.md`](docs/chain-regressions.md). Still no CET-marked PE fixture, so `--cfg-aware` remains untested against a real hardened binary |
| 5. Differentiators | Semantic classification + ranking (`rf-classify`, `--classify`/`--rank`), JOP dispatcher analysis, scan cache (`--cache`, MCP `sort_by`) | **partial** — classification, ranking, dispatcher analysis and the cache ship; the chain DSL and ARM64 PAC awareness do not, and both have been dropped from the roadmap rather than left as silent debt |

## Building and checking

```sh
cargo build --release                 # CLI at target/release/rop-finder
cargo test --workspace                # the whole suite
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check advisories licenses bans sources   # supply chain
cargo audit
```

The gates that need Python live in `tests/` and are listed under
[Parity harness](#parity-harness) below; `.github/workflows/ci.yml` runs every
one of them, and each is meant to be able to go red.

`rop-finder --version` prints the tool version, the version of the capstone
core the binary is linked against, and a one-line attribution to ROPgadget
(see [NOTICE](NOTICE)). The capstone line matters when reporting a parity
diff or a decode disagreement: PLAN.md names capstone version drift as the
project's top residual risk, and the disassembler build that produced a
given output is otherwise unrecoverable from the output itself.

## Usage

```sh
rop-finder --binary tests/fixtures/elf-x64-bash-v4.1.5.1 --depth 10
rop-finder --binary /bin/ls --json --norop
rop-finder --binary ./prog --only "pop|ret" --badbytes "0a|0d" --range 0x1000-0x2000
rop-finder --binary ./prog --base 0x400000 --offset 0x1000
rop-finder --binary tests/fixtures/raw-x86.raw --rawArch=x86 --rawMode=32
rop-finder --binary tests/fixtures/elf-ARMv7-ls --thumb
rop-finder --binary ./driver.sys --section .text --base 0   # RVAs, .text only
rop-finder --binary ./prog --info                           # metadata JSON, no scan
rop-finder --binary tests/fixtures/elf-Linux-x64 --ropchain # execve("/bin/sh") chain script
rop-finder --binary ./prog.exe --ropchain --chain windows-virtualprotect --api-addr 0x7fff12340000
rop-finder --binary ./hardened.exe --cfg-aware               # endbr64-entering gadgets only
rop-finder --binary ./prog --json --classify --rank          # classified, best gadgets first
rop-finder --binary ./prog --cache                           # reuse a previous scan instantly
```

Ask by *effect* rather than by text (the v0.4 constraint layer — the full list
is in [MANUAL.md](MANUAL.md)):

```sh
rop-finder --binary ./prog --set-reg rdi --from-stack --terminator bare-ret
rop-finder --binary ./prog --set-reg rsi --no-clobber rdi --max-side-effects 1
rop-finder --binary ./prog --search "pop rdi; ret"     # ropper-style sequence
rop-finder --binary ./prog --pivot                     # stack-pivot preset
rop-finder --binary ./prog --plan-chain --chain linux-execve   # can it? if not, why not
```

Output formats: `--format human` (default, ROPgadget-compatible),
`json`, `jsonl` (streaming, in scan order), `csv`, `raw`. Parse the structured
ones — the human listing tracks ROPgadget and is not covered by semver.

Formats are detected by magic bytes (ELF, PE, Mach-O, Universal/fat Mach-O);
`--rawArch`/`--rawMode`/`--rawEndian` force the raw loader, exactly like
ROPgadget (accepted values: `x86|arm|arm64|sparc|mips|ppc|riscv`,
`32|64|arm|thumb|riscv`, `little|big`). Universal (fat Mach-O) binaries need
`--arch <slice>`: rop-finder **refuses** to do what ROPgadget does here, which
is concatenate every slice's executable regions and disassemble them all with
the first slice's decoder. The slices' virtual address ranges overlap and
every slice but the first would be decoded wrongly, so most of that output is
fabricated (`CORE-03`). The error names the slices the file actually holds. Architectures: x86, x64, ARM (incl.
Thumb via `--thumb`), ARM64, MIPS32/64, PPC32/64, SPARC(V9), RISC-V 32/64 —
with endianness from the binary.

Output format matches ROPgadget: `0x<addr> : insn ; insn ; ...` (human) or a
JSON array of `{"vaddr", "bytes", "text"}` with `--json` / `--format json`
(plus an `arch` field per gadget for Universal binaries, and a `section` field
per gadget when `--section` is used). `--classify` adds `class`, `labels`,
`regs_written`, `regs_read`, `side_effects`, `quality`, `dispatcher` and
`low_confidence` to each JSON record (see Phase 5 below).

Exit codes: `0` success, `1` usage error, `2` malformed/unsupported binary.

## Phase 2 features

### `--section <glob>` — scan only selected executable sections

Restricts the scan to the binary's *named* executable sections
(`SHF_EXECINSTR` sections for ELF, `Characteristics & IMAGE_SCN_MEM_EXECUTE`
for PE, `__TEXT` executable sections for Mach-O) instead of ROPgadget's
default `PF_X` *segment* granularity. Repeatable and comma-separated, with
`*` globbing:

```sh
rop-finder --binary ./prog --section .text
rop-finder --binary ./prog --section ".init*,.plt" --section .text
```

With `--json`, every gadget gains a `section` field naming the section that
contains it. An unknown name exits `1` and lists the available executable
sections. `--range`, `--base`, `--offset`, and `--badbytes` compose with
`--section` normally.

**Stripped-ELF caveat:** without a section table there are no names to
match; the loader falls back to synthetic `PT_LOAD#n` segment names (one per
executable segment) and prints a one-line stderr warning when `--section` is
used against such a binary.

### `--base <hex>` — load-time rebase

Rebases the image at load time, before scanning: every gadget vaddr becomes
`vaddr - original_image_base + <base>`. `--base 0` yields RVA-style
addresses. `--offset` is applied *after* the rebase, so the final printed
address is `vaddr - original_base + base + offset`. `--badbytes` is checked
against that **final** address — e.g. after `--base 0x55550000`,
`--badbytes 55` eliminates every gadget. For Universal (fat Mach-O)
binaries every slice is slid by the same delta (`base - first_slice_base`);
ROPgadget has no `--base` for Universal.

### `--info` — structured binary metadata

Dumps image metadata as JSON and exits without scanning (`--base` is
honoured, so the printed addresses match what a scan would emit):

```json
{
  "format": "pe",            // elf | pe | macho | raw | universal
  "arch": "x64",
  "endianness": "little",
  "addr_size": 8,
  "image_base": "0x4ad00000",
  "entry": "0x4ad090b4",
  "sections": [{"name": ".text", "vaddr": "0x4ad01000", "size": 160256,
                "executable": true, "writable": false}, ...],
  "imports":  [{"dll": "KERNEL32.dll", "symbol": "GetTickCount",
                "iat_vaddr": "0x4ad2b382"}, ...]   // PE only; [] otherwise
}
```

Universal binaries emit `{"format": "universal", "slices": [<per-slice macho
info>, ...]}`. Addresses are hex strings (consistent with gadget vaddrs),
sizes are numbers.

## ROP chain generation (Phases 4a/4b)

`--ropchain` builds a chain; `--chain <target>` selects the family
(default `linux-execve`):

```sh
rop-finder --binary tests/fixtures/elf-Linux-x64 --ropchain          # python script
rop-finder --binary tests/fixtures/elf-Linux-x64 --ropchain --json   # chain IR as JSON
rop-finder --binary tests/fixtures/pe-x86-cmd-v6.1.7600 --ropchain \
    --chain windows-virtualprotect --api-addr 0x7fff12340000         # stdcall chain
```

### linux-execve (Phase 4a)

A Linux `execve("/bin/sh", 0, 0)` chain — x86 via `int 0x80`, x64 via
`syscall` — ported faithfully from ROPgadget's `ropmakerx86.py` /
`ropmakerx64.py` (same gadget search order, same write-what-where
backtracking). One deliberate divergence: padding words render at
column 0, not with ROPgadget's leading tab, because the tab made the
generated script raise `IndentationError` at import (ROB-05). ELF x86/x64 only
(matching ROPgadget's `ropmaker.py` dispatch); anything else exits 1 with
a "not supported yet for the rop chain generation" usage error.
`--depth`, `--badbytes`, `--base`, `--offset` and `--section` all apply
to the underlying scan; `--badbytes` additionally rejects chain words
(data-section addresses included) whose packed bytes contain a banned
byte.

### windows-virtualprotect (Phase 4b)

> **Still marked experimental, and the CLI still says so on stderr — but the
> reason has changed.** The four layout defects this warning used to name —
> `CHWIN-01` (an inert alignment pad the preceding `ret` lands on),
> `CHWIN-02` (`lpflOldProtect` defaulting into the shellcode buffer),
> `CHWIN-03` (the IAT path using `IMAGE_IMPORT_BY_NAME` instead of the
> `FirstThunk` slot) and `CHWIN-07` — are **fixed in v0.5**, each with a
> failing-before and a passing-after run recorded in
> [`docs/chain-regressions.md`](docs/chain-regressions.md), and every
> advertised Windows chain is now generated by the real CLI and *executed*
> under Unicorn by `tests/emulate.py`, which asserts VirtualProtect's four
> arguments and the shellcode's first four bytes. What the emulator cannot
> check is still yours: that `--api-addr` is the runtime address, that `rsp`
> really is `--chain-base` mod 16 at entry, and that CFG/CET is not enforced
> on the target. That is the residual the flag warns about.

A Windows `VirtualProtect(shellcode, size, PAGE_EXECUTE_READWRITE, &old)`
chain for PE x86/x64, designed per PLAN sec. 6.2 after the mandatory
gadget-inventory spike ([tests/spike-report.md](tests/spike-report.md),
regenerate with `python tests/spike_inventory.py`):

- **x64**: registers per the Win64 ABI — `rcx`=lpAddress, `rdx`=dwSize,
  `r8`=0x40, `r9`=&old (a writable `.data` address); 32-byte shadow
  space; the word after the API transfer is the return address
  VirtualProtect's own `ret` consumes (second-stack frame → shellcode).
  Arg population prefers `pop rX` gadgets and falls back to
  `pop rax` + `mov rX, rax`; when neither exists the build fails with a
  structured error naming the register and every strategy tried — the
  spike shows this is the common case (cmd.exe x64 has NO ret-terminated
  gadget writing rdx/r8/r9).
- **x86 (stdcall)**: everything on the stack —
  `[api][ret→shellcode][lpAddress][dwSize][0x40][&old]`; VirtualProtect's
  `ret 0x10` continues into the shellcode. Needs no gadgets at all;
  `--api-addr` is required.
- **Stack-alignment invariant** (x64): the API transfer word must land at
  an even word index (chain base assumed 16-aligned at the pivot), so
  `rsp % 16 == 8` at API entry; the builder auto-inserts an alignment
  padding word and a `validate_with` hook enforces it.
- **API resolution order** (anchor-first): (a) `--api-addr <hex>`
  explicit runtime address; (b) IAT dereference when the PE imports the
  API (`pop rax ; @IAT ; mov rax, [rax] ; jmp rax`); (c) a structured
  error explaining why both failed. The spike found cmd.exe imports
  VirtualAlloc but NOT VirtualProtect — anchor-first is the primary path.
- Parameters: `--api-addr`, `--shellcode-addr` (default: writable
  `.data`), `--shellcode-size` (default 0x1000).
- **`--cfg-aware`**: models Intel CET/IBT by *reach mechanism*, which is
  what `CRIT-01` fixed in v0.2. JOP/SYS gadgets are entered through an
  indirect `jmp`/`call`, so under IBT their entry must be an
  `endbr64`/`endbr32` landing pad and the filter requires one. ROP gadgets
  are entered through a `ret`, which IBT does not check at all — the
  mitigation that constrains them is CET's *shadow stack*, a property of the
  exploit rather than of the gadget — so they are kept. The earlier
  implementation demanded a landing pad at the entry of every gadget, which
  is why it returned zero gadgets on every binary in the repository. The
  remaining honest limitation: goblin does not expose the load-config CET
  fields, so "does this image use IBT at all" is answered by scanning the
  executable regions for an actual `f3 0f 1e fa`/`fb` (`rf_scan::ibt_applicable`),
  and the CLI *warns* when you pass the flag to an image that has none rather
  than silently handing back a shorter list. A PE's `GUARD_CF` bit is
  Microsoft's software Control Flow Guard, a different mitigation, and is
  deliberately not used to decide this filter. There is still no CET-marked
  PE in the fixture corpus to test against.

The chain is first built as a target-independent IR (`rf-chain` crate):
a `RopChain` is a word list where each word is tagged `gadget` /
`immediate` / `data` / `code` / `padding`, plus a table of the referenced
gadgets with their disassembly. `RopChain::validate` checks the
build-time invariants (every gadget word exists in the scan output; every
non-gadget word is badbyte-free), and `validate_with` accepts per-target
invariant hooks (the Win64 stack-alignment rule is implemented as one).
Two renderers emit the IR: `to_python()` (exploit script) and
`to_json()`.

Unlike ROPgadget, which prints gadget dumps and step logs around the
script, `--ropchain` prints only the script (or the IR with `--json`),
and "can't find a suitable gadget" situations are structured errors
rather than best-effort output.

Parity vs `ROPgadget.py --ropchain` across the eight x86/x64 ELF fixtures
(`python tests/chain_parity.py`) is **deliberately gone as of v0.5, on the
default flag set.** Until v0.4 the harness recorded 2 byte-identical scripts
(elf-Linux-x86, elf-Linux-x86-NDH-chall) and 2 payload-identical
(elf-Linux-x64, Linux_lib64.so). It now records 0 of each, because
reproducing ROPgadget's script byte for byte means reproducing its
59-instruction `inc eax` ladder for the `execve` syscall number: on
elf-Linux-x64 the chain is **19 words where the oracle emits 76**. You cannot
keep byte parity and cut the payload 4x, and the shorter chain is the point.

What the harness gates instead: every one of the 56 (fixture, flag-set) cells
has a recorded verdict, an unrecorded change fails the build, and
`BADBYTE-LEAK` — a word rop-finder emits that contains a byte the user said it
must not — is unconditionally fatal. Whether an emitted chain actually *runs*
moved to a stronger check: `tests/emulate.py` executes it under unicorn and
asserts the syscall and its arguments. 13 cells that were error-parity at
v0.4.0 are now chains the oracle still cannot build.

Windows chains have no ROPgadget oracle; they are covered by the emulator
harness and by unit and integration tests.

## Phase 5: classification, ranking, scan cache

`rf-classify` assigns every gadget a semantic class from iced-x86
operand metadata (x86/x64, high confidence) or mnemonic heuristics
(other arches, `low_confidence: true`). The full decision rules
(R1–R13) live in [TAXONOMY.md](TAXONOMY.md).

- **Classes**: `reg-write`, `stack-pivot`, `mem-read`, `mem-write`,
  `arithmetic`, `syscall`, `dispatcher`, `other` (multi-label set plus a
  primary class from the last side-effecting instruction).
- **JOP dispatcher analysis (R8)**: a gadget ending in a
  register-indirect jump (`jmp qword ptr [reg]`), or `jmp reg` where an
  earlier instruction arithmetically steps that register (the classic
  dispatcher loop form), is labeled `dispatcher` — a documented
  heuristic, not a proof.
- **Quality score (R12)**: `max(0, 100 − 15·(side_effects−1) −
  3·(n_insns−2))`. A clean `pop rdi ; ret` scores 100; each extra
  side-effecting instruction costs 15, each extra instruction costs 3.
- **`--classify`**: adds the classification fields to `--json` records.
- **`--rank`**: sorts output by quality descending (ties by address),
  for both human and JSON output.
- **`--cache`**: caches scan results on disk, keyed by SHA-256 of the
  file plus every scan parameter (depth/modes/filters/sections/base/
  offset…). Directory: `ROP_FINDER_CACHE_DIR`, else
  `%LOCALAPPDATA%\rop-finder\cache` (Windows) or `~/.cache/rop-finder`.
  Hits and misses are reported on stderr.

**`rf-classify` is a heuristic, and as of v0.3.0 it has been measured
against a hand-labeled corpus** — `tests/classify-corpus/`, 438 records over
eight architectures, labeled by hand and hash-frozen, never regenerated from
the classifier's own output. Method, per-record justifications and the full
caveat list are in [`docs/classifier-eval.md`](docs/classifier-eval.md); the
figures are pinned as constants in `crates/rf-classify/tests/eval.rs`, so the
classifier cannot move in either direction without the numbers moving with it.

| Architecture | n | Primary-class accuracy |
|---|---:|---:|
| arm | 25 | 1.0000 |
| arm64 | 44 | 1.0000 |
| i386 | 74 | 1.0000 |
| mips | 25 | 0.8400 |
| ppc | 25 | 0.6400 |
| riscv64 | 24 | 0.8333 |
| sparc | 25 | 0.8000 |
| x86_64 | 195 | 0.9949 |
| **all** | **437** | **0.9474** |

x86-64 macro-averaged precision is 0.9959 and recall 0.9977. Read those
numbers with their caveats attached, all of which are recorded in
`docs/classifier-eval.md` §5: this was **not a blind study** (the labeler had
already read `crates/rf-classify/src/x86.rs`); the dispatcher heuristic's
precision of 1.0000 rests on a single predicted positive and its recall is
0.2000; PowerPC and MIPS carry known defects listed in §4.1; six of the
fourteen `Arch` variants have no corpus entries at all; the disassembly-text
fallback path (`low_confidence`) has zero measured accuracy because no corpus
record reaches it; and **the ranking — `quality`, `usability`, the default
`rank` order — is not evaluated here at all**, because the corpus carries no
ground truth for gadget usefulness. What replaced the old circular harness is
described in `docs/classifier-eval.md` §1: the earlier retraction of that
harness's self-agreement figure stands.

**Chain DSL: deferred.** The stretch goal from PLAN §5 (a declarative
chain-description DSL compiled to the Chain IR) is intentionally not
shipped in Phase 5 rather than half-shipped; the Chain IR and the six chain
targets (`--chain`) remain the supported interface. Future work.

## MCP server

> Installing, running and wiring the server into Claude Desktop or Claude Code is
> covered step by step, per operating system, in
> [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md).


`rop-finder-mcp` (package `rop-finder-mcp`, directory `crates/rf-mcp`)
exposes the engine to AI agent hosts over the Model Context Protocol, using
the official Rust SDK (`rmcp`). **stdio
transport only** — there is deliberately no network listener.

```sh
cargo build --release
target/release/rop-finder-mcp --allow-dir /path/to/binaries --allow-dir /path/to/rop-finder/tests/fixtures
# optional: --cache-dir <dir> --timeout-secs 60 --max-results 1000
#           --max-depth 64 --max-concurrent 2 --allow-cwd --verbose-path-errors
#           --max-gadgets 5000000 --scan-threads <n>
#           --cache-mem-mb 512 --cache-ttl-secs 86400 --cursor-ttl-secs 300
#           --audit-log <path> --audit-log-max-mb 64 --probe-threshold 20
#           --workspace-dir <dir>
```

`--allow-dir` takes **absolute** paths and is the only source of the
allowlist; with none given the server exits 2. See the security model below.

The scan orchestration (`ScanRequest` → `scan_bytes`/`info_bytes`) lives in
the `rop-finder-api` library (`rf_api`) and is shared verbatim with the CLI —
no stdout scraping. Until v1.0 it lived in `rf_cli`, a *binary* crate, which
is why the MCP server could not be published at all and had to keep its own
copy of the option mapping; `ENG-08`/`ECO-10` extracted it. See
[`docs/API-STABILITY.md`](docs/API-STABILITY.md) for what the published
crates promise.

### Tools

All fifteen tools return structured JSON (`structuredContent` + text content)
and declare an `outputSchema`; errors are `{error: {code, message, retryable,
details, suggestions}}` with the MCP `isError` flag. The table below is a
summary — [MANUAL.md](MANUAL.md) carries the generated block with every
parameter, regenerated from the server's own `tools/list` by a test so it
cannot drift.

| Tool | Purpose |
|---|---|
| `find_gadgets` | ROP gadgets only (ret-terminated); `sort_by: "quality"` ranks by the Phase 5 quality score |
| `find_jop_gadgets` | JOP gadgets only (jmp/call-terminated); also supports `sort_by` |
| `find_syscall_gadgets` | SYS gadgets only (syscall/sysenter/int/iret); also supports `sort_by` |
| `find_gadgets_by_effect` | The constraint query as one call: "set rdi from the stack, preserve rsi and rdx, at most one side effect, a clean ret" |
| `find_bytes` | A byte sequence in the mapped executable regions — the same regions `find_gadgets` walks |
| `find_string` | A string in the mapped data sections: where `/bin/sh` lives, and at what address |
| `get_gadgets` | Resolve stable gadget `id`s (the `id` field of any gadget record) back to full records, without re-running a search |
| `get_binary_info` | The `--info` payload (format/arch/sections/imports), no scan |
| `get_mitigations` | The binary's exploit mitigations, so an agent can decide whether ROP is even the right technique before it scans |
| `get_server_config` | The effective allow roots and caps (`max_depth`, `max_file_bytes`, `max_results`, `max_concurrent`, `timeout_secs`, cache state), so an agent never has to probe for them |
| `get_server_stats` | This session's counters: requests by tool, ok/denied/timeout/cancelled/error totals, cache hit/miss/eviction counts and `cache_bytes`, `inflight` |
| `search_gadgets_by_pattern` | Regex over gadget text (invalid regex → literal substring), full scan |
| `run_ropgadget_command` | Flag passthrough, restricted to the allowlist below |
| `plan_chain` | Whether this binary can host a chain for `target`, and if not, exactly which primitive is missing |
| `build_rop_chain` | ROP chains; returns chain IR + python script |

`build_rop_chain` takes `{"binary_path": ..., "target": ..., "depth"?,
"base"?, "offset"?, "badbytes"?, "cfg_aware"?, "api_addr"?,
"shellcode_addr"?, "shellcode_size"?, "timeout_secs"?}`, where `target` is one
of the same set the CLI's `--chain` accepts — `linux-execve`,
`linux-mprotect`, `linux-syscall`, `linux-ret2libc`, `linux-srop` (ELF x86/x64)
and `windows-virtualprotect` (PE x86/x64). An unknown target is a
`usage_error` that lists the valid ones. It shares the CLI's `chain_bytes` pipeline (no stdout
scraping), confined to the same directory allowlist; missing gadgets
surface as a `chain_error`, and an unknown `target` is a `usage_error`.
Chain builds bypass the gadget cache.

Example JSON-RPC exchange (newline-delimited over stdio):

```jsonc
=> {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}
=> {"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
=> {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_gadgets",
     "arguments":{"binary_path":"tests/fixtures/elf-x64-bash-v4.1.5.1","depth":6,
                  "section":".plt","max_results":10}}}
<= {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{...}"}],
     "isError":false,"structuredContent":{"gadgets":[{"vaddr":"0x...","bytes":"...",
     "text":"... ; ret","section":".plt"},...],"total_count":283,"returned":10,
     "truncated":true,"binary_sha256":"...","cache":"miss","fallback_section_names":false}}}
```

`run_ropgadget_command` takes `{"binary_path": ..., "args": ["--depth","6",
"--only","pop|ret"]}`. The flag allowlist (PLAN §6.1): `--depth --norop
--nojop --nosys --only --filter --re --range --section --base --offset
--badbytes --align --multibr --json`. `--re` (regex over gadget text) and
`--align` (address alignment) are applied as post-filters; everything else
maps onto the engine. Side-channel flags (`--dump`, `--string`, `--memstr`,
`--console`) and unknown flags are rejected with `invalid_flag`.

### Security model (PLAN §6.1)

The server is, by construction, a way to hand a local file's bytes to an
autonomous agent. Everything below describes what the code enforces as of
v0.1.1. Read the "What this does NOT protect against" list too — it is the
half that decides whether running this is safe for you.

**What the code enforces**

- **Path confinement by open-then-verify handle.** `binary_path` is
  resolved by `crates/rf-mcp/src/confine.rs`, not by canonicalizing a
  string. Phase 1 is lexical and performs zero syscalls: the path must be
  absolute, must contain no `.`/`..` component and no interior NUL, and on
  Windows must not use a `\\?\` / `\\.\` / UNC prefix or carry a `:` after
  the drive letter; the allow root is selected by component-wise match on
  path components, never by string prefix, so `/allowed` does not admit
  `/allowed-evil/x`. Phase 2 opens the file *pinned to the root*: on Unix
  each remaining component is opened with
  `openat(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)` from a directory descriptor held
  since startup, so no name is resolved twice and the descriptor is
  provably a descendant; on Windows the handle is validated after the fact
  with `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED|VOLUME_NAME_GUID)`
  against the root's own final path, plus `GetFileType == FILE_TYPE_DISK`
  and a matching volume serial. Phase 3 fstats the *handle* and requires a
  regular file (which also rejects FIFOs) within the size cap. The open
  handle — not a path — is what crosses into the blocking worker, so there
  is no window between check and read. This replaces the previous
  canonicalize-then-reopen-by-name design, against which a rename race read
  a file outside the allowlist in 323 of 400 attempts
  (`docs/AUDIT-FINDINGS.md` `MCP-01`).
- **The allowlist is `--allow-dir` and nothing else.** The server's own
  working directory is no longer seeded into the allowlist; starting with
  no `--allow-dir` exits 2 rather than silently allowing the cwd. Passing
  `--allow-cwd` opts the cwd back in explicitly (for `cargo run` and CI),
  and obviously-wide roots are refused without
  `--i-accept-a-wide-allowlist`: a filesystem or drive root, and anything
  at or above `/etc`, `/usr`, `/var`, `/System`, `/Library`, `/home`,
  `/Users`, `/root`, `/private/etc`, `/private/var`, `C:\Users`,
  `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)` or
  `C:\ProgramData` (matched component-wise, so `/etc` covers `/etc/ssl`).
  `--cache-dir` and `--audit-log` are refused if they fall inside an
  allowed root.
- **One denial code, no existence oracle.** Every rejection returns
  `path_denied` with the same message and no OS error text, whether the
  path is outside every root, absent, a directory, a symlink, or
  unreadable. The old taxonomy (`not_a_file` / `path_not_allowed` /
  `path_not_found`) distinguished exists-as-dir from exists-as-file from
  absent for *any* absolute path on the machine — a whole-filesystem
  existence oracle (`MCP-07`). `--verbose-path-errors` restores detail, and
  only for paths that already selected an allowed root. Use
  `get_server_config` to read back the effective roots and caps rather than
  probing for them.
- **Flag allowlist** for `run_ropgadget_command` (see above); no flag can
  expand file access beyond the directory allowlist.
- **Resource caps**: `max_results` defaults to 1000, hard-capped at 50000;
  per-request timeout defaults to 60 s (hard cap 300 s); `depth` above
  `--max-depth` (default 64) is *rejected* with a `usage_error` naming the
  limit and the value, not silently clamped; `--max-concurrent` (default 2)
  bounds simultaneous scans; `--max-file-bytes` (default 256 MiB) is
  enforced against the fstat of the open handle, before any read;
  `--max-gadgets` (default 5,000,000, `0` disables) is an engine budget, so a
  scan that would accept more stops with `resource_exhausted` instead of
  filling memory; `--scan-threads` (default `num_cpus - 1`) keeps the server
  off the operator's last core.
- **Bounded caches, and a timeout that actually stops the work**: a timed-out
  or cancelled request stops its scan rather than orphaning it — the engine
  observes a cancellation token, and a worker that has not stopped within 5 s
  is reported as `timeout_hard` and counted in `wedged_total` instead of being
  silently abandoned. `--cache-mem-mb` (default 512) bounds the in-memory scan
  cache by bytes with least-recently-used eviction, `--cache-ttl-secs`
  (default 86400) bounds it by age, and `--cursor-ttl-secs` (default 300)
  bounds how long a paged scan stays pinned for an outstanding cursor.
- **Audit trail**: `--audit-log <path>` records one JSON line per call —
  denials, timeouts and cancellations included — append/create, mode 0600 on
  unix, rotated at `--audit-log-max-mb`. It carries the binary label, its
  SHA-256, a parameter hash and the result counts, and never gadget text or
  file bytes. The path may not fall inside an allow root.
  `get_server_stats` exposes the live counters (requests by tool, ok/denied/
  timeout/cancelled/wedged totals, cache hits/misses/evictions, `cache_bytes`,
  `inflight`).
- **Content-hash cache**: SHA-256 of the file plus the scan parameters
  (including `base` and `cfg_aware`) keys an in-memory cache (plus
  optional `--cache-dir` on-disk spill), so repeated queries on the same
  binary are instant.
- **Sampled responses**: at most `max_results` gadgets plus `total_count`
  and `truncated`. PLAN's "top-N by quality rank" is available via
  `sort_by: "quality"` on the find tools — quality and primary class are
  computed once at scan time and ride in the cache, so quality-sorted
  queries need no rescan; without `sort_by`, the first N in
  deterministic traversal order are returned.
- **Loader errors are structured**: a malformed or unsupported binary
  returns a `binary_error` tool error rather than taking the server down.
  This is not a *proof* of no-panic, but it is no longer an untested claim
  either: `fuzz/` holds seven cargo-fuzz targets and `rf-smoke`, a
  deterministic mutation harness that runs on stable Rust everywhere, and the
  recorded run is **100,000 mutants of the 24 fixtures through
  `Binary::load`, `info_bytes` and `scan_bytes` with 0 panics and 0 hard
  failures** (`fuzz/README.md`, which also records the depth counters that
  make that number mean something). CI runs both.

**What this does NOT protect against**

- **Your own choice of root.** The confinement is exactly as narrow as the
  directories you pass to `--allow-dir`. Point it at a home directory or a
  source tree and everything in there is in scope, by design. The
  wide-root refusal is a guardrail against the obvious mistakes, not a
  policy engine.
- **Anything readable inside a root.** There is no per-file policy, no
  file-type gate beyond "regular file within the size cap", and no
  redaction. If a private key, a credential file or an unrelated document
  sits inside an allowed root, a request naming it will be served.
- **The binary's bytes reaching the agent.** That is the product, not a
  leak: gadget text, byte sequences, section layout, import names and
  chain scripts derived from the target all flow to the model and to
  whatever the host does with model context. Do not point this at a binary
  you would not paste into a chat window.
- **A worker that ignores its cancellation flag.** Since v0.2 a timed-out or
  cancelled request really does stop the scan — the engine checks a token
  inside its loops (`MCP-03`) — but the guarantee is *bounded*, not instant:
  a worker that has not stopped within 5 s is reported as `timeout_hard` and
  counted in `wedged_total` rather than being silently abandoned. Cost during
  that window is bounded by `--max-depth`, `--max-concurrent` and
  `--max-gadgets`, not by zero.
- **The agent itself.** Nothing here judges intent. An agent that has been
  prompt-injected can issue any request the operator's own roots and flag
  allowlist permit.

## Parity harness

```sh
python tests/parity.py             # uses debug binary
python tests/parity.py --release   # uses release binary + timing comparison
python tests/chain_parity.py       # --ropchain parity (ELF x86/x64 fixtures)
python tests/flag_conformance.py   # every ROPgadget flag, stdout byte for byte
python tests/capability_matrix.py  # the CLI and the MCP server must agree
python tests/doc_claims.py         # every quantitative claim in these docs
python tests/mcp_workability.py    # an MCP answer must fit an agent's context
python tests/emulate.py --all      # generated chains, executed under unicorn
python tests/emulate.py --regressions   # every recorded chain-defect verdict
```

They need ROPgadget only where they compare against it: `parity.py`,
`chain_parity.py` and `flag_conformance.py` want `ROPGADGET_PATH` /
`ROPGADGET_PYTHON` (or the conventional `../ropgadget` checkout and a
`.venv-oracle` with `capstone==5.0.7`), and `emulate.py` wants `unicorn` —
each says so if it is missing. The other four need nothing but the built
binaries.

`capability_matrix.py` is the ECO-02 gate and needs no oracle: it enumerates
the CLI's flags from clap's own `--help`, the MCP surface from the server's
own `tools/list`, maps them through a declared equivalence table in which
every asymmetry carries a written reason, and then asks both surfaces the
same questions and compares the gadget sets element by element — the current
run reports 45 paired capabilities, 45 declared asymmetries, 2 vocabularies
and 43 answers compared. It exists
because "the CLI is behind its own MCP server" was fixed once by hand and
came back: two front ends, one shared vocabulary, and `--reads-reg rax` and
`reads_reg: "rax"` still answered 2,888 and 2,147 gadgets.

Compares post-dedup `(vaddr, bytes)` gadget sets against
`python ../ropgadget/ROPgadget.py --binary <f> --depth 10 --dump` for the
full fixture corpus (ELF all arches, PE, Mach-O, Universal, raw — raw gets
`--rawArch=x86 --rawMode=32` on both sides) and prints per-file overlap
statistics, sample diffs, and per-file timings. Current status
([`docs/measured-2026-09.md`](docs/measured-2026-09.md)): **763,166 of
763,204 reference gadgets reproduced — 99.995%** across **24** fixtures, all
24 of which are bit-exact by gadget set (22 are also byte-identical in
rendered instruction text; the other two are recorded intentional
divergences). The corpus is 24 binaries, not
25: ROPgadget's own test suite has a 25th, `core` (a 300 KB ET_CORE ELF
core dump exercising a distinct loader path — no section headers, unusual
program-header layout), which was never copied into `tests/fixtures/`.
`tests/fixtures/PROVENANCE.md` records that drop along with the origin and
licence of each fixture that is present, and explains why the corpus is not
redistributable — which is also why no published crate contains it
([`docs/PUBLISHING.md`](docs/PUBLISHING.md) §5). The ET_CORE loader path is
therefore unmeasured. `python tests/fetch_fixtures.py` re-fetches all 24 from
upstream and verifies them against `MANIFEST.sha256`, so a checkout without
them can still run the parity suite.

## Semantic notes / intentional deviations

- Gadget validity follows ROPgadget's clean-decode rule (`gadgets.py:100-103`):
  bytes from candidate start to anchor end must decode linearly with the total
  decoded size equal to `end - start`. The anchor *start* need not coincide
  with an instruction boundary (e.g. `66 0f 05` decodes as a 3-byte `syscall`,
  and a gadget may "end" on an anchor byte embedded mid-instruction, like a
  `\xc3` SIB byte inside `jmp [r11+r8*8]`).
- Scan granularity matches ROPgadget exactly: every program header with the
  `PF_X` flag (not section headers), reading `p_memsz` file bytes from
  `p_offset` with Python-slice clamping semantics. rf-core still exposes the
  `SHF_EXECINSTR` section model (`exec_sections()`) for Phase-2 `--section`
  support; stripped ELFs fall back to `PT_LOAD` sections there.
- Dedup is by gadget **text**, first-occurrence-wins, in deterministic
  traversal order: region order → anchor-table order (ROP, JOP, SYS per
  region) → anchor-hit offset order → depth order — matching
  `rgutils.deleteDuplicateGadgets` + `core.py:__getGadgets`.
- Disassembly uses iced-x86 (FastFormatter) for x86/x64 and capstone-rs
  (pinned `capstone = "=0.14.0"`, capstone-sys 0.18 bundling the C capstone
  whose header says 5.0.6) for every other architecture. Because dedup is
  text-keyed, formatter differences can shift dedup *classes*, not just
  cosmetics; the x86 path normalizes the biggest capstone quirks
  (segment-override prefixes on non-memory instructions, rep/repne outside
  string ops and branch families, rep/repne kept on string ops, memory sizes
  always shown, RIP-relative operands). The 0.13 → 0.14 bump (capstone 5.0.0 → 5.0.6, moving *toward* the
  5.0.7 the oracle runs) closed the ARM/ARM64 encoding gap that used to cost
  11 gadgets on elf-ARM64-bash and 14 on elf-ARMv7-ls: both are 0 missing
  now, with no architecture regressed. The per-architecture before/after
  counts are in `crates/rf-scan/Cargo.toml` beside the pin, and in
  [`docs/measured-2026-09.md`](docs/measured-2026-09.md).
- **Two different divergence numbers, and they are not interchangeable.**
  Parity is judged on post-dedup `(vaddr, bytes)` SETS: which byte
  sequences at which addresses were found. On that measure the loss is
  0.005% overall (99.995%, `docs/measured-2026-09.md`) and the residual
  x86/x64 divergence is zero on a default scan
  (`docs/AUDIT-FINDINGS.md` `SCAN-08` confirms the historical
  0.05–0.2% range for this measure) — decoder
  disagreements (capstone accepts some invalid LOCK-prefixed instructions
  iced rejects and vice versa, e.g. `ud0` operands; iced rejects `mov cs,
  r/m16` which capstone decodes), far jumps (`ljmp`/`lcall`), and
  dedup-survivor swaps. **The divergence in gadget TEXT is 100-500x larger:
  15-29% of x86/x64 gadget texts do not match ROPgadget's byte for byte**
  (measured in `docs/AUDIT-FINDINGS.md` `SCAN-08`). The two numbers measure
  different things and conflating them is a real user-facing bug: the same
  gadget, found at the same address with the same bytes, is *rendered*
  differently by iced-x86 than by capstone. Sources: immediates always in
  hex (`add rsp, 0x8` vs `add rsp, 8`), no spaces around displacement signs
  (`[rbp-0x38]` vs `[rbp - 0x38]`), and genuinely different mnemonics —
  `popal`/`popad`, `pushal`/`pushad`, `xlatb` vs `xlat byte ptr [rbx]`,
  `retf`/`retfq`, `fucompi`/`fucomip`, `call`/`callf`, `jmp`/`jmpf`, and
  `xrelease mov` for f3-prefixed stores. Consequence: **do not reuse
  ROPgadget-era greps, `--re` patterns or `--only` lists unchanged.**
  `--only` matches the first whitespace token, so `--only "popal|ret"`,
  `--only "xlatb"` and `--only "call"` (far calls are `callf` here) all
  select differently from ROPgadget. Text-level parity is not a goal this
  release claims to meet.
- Non-x86 scan semantics replicate `gadgets.py:__gadgetsFinding`: aligned
  backward stepping in virtual-address space with byte-fallback
  (gadgets.py:73-89), the fixed-width clean-decode rule (104-107), the
  RISC-V last-instruction-size rule (109-112), and per-arch passClean
  (488-498 — branch-in-middle rejection exists only on x86). SPARC/ARM64
  SYS tables are empty, matching ROPgadget's TODO placeholders.
- Thumb mode comes only from `--thumb` (gadgets.py:331,448): a PE tagged
  ARMv7/Thumb2 is scanned in ARM mode by default, like ROPgadget.
- Gadgets carry `delay_slot: true` on MIPS/SPARC (PLAN.md §4).
- Anchor matching replicates Python `re.finditer` non-overlapping semantics
  per anchor pattern.
- MPX anchors (`f2 c3` etc.) decode as `bnd ret`/`bnd jmp`, which are not in
  ROPgadget's accepted branch list — they are scanned but always rejected,
  exactly as in ROPgadget.
- `--filter`: **fixed in v0.2 (`CLI-02`/`SCAN-01`), and it is the oracle's
  semantics now.** The value is compiled as a `|`-separated regex
  alternation, full-matched against each mnemonic — ROPgadget's
  `re.match("({})$")` — so `--filter "j.*"` removes every jump gadget and
  `--filter "op"` removes nothing, because no mnemonic *is* `op`. It used to
  be a literal `ends_with` per alternative, which silently ignored every
  regex and silently deleted `pop` for `op`; `tests/flag_conformance.py`
  exercises the flag now, which is what the old divergence survived by not
  being tested.
- `--ropchain` (Phase 4a) intentional deviations from ropmaker:
  - the write-what-where register match in
    `ropgadget/ropchain/arch/ropmakerx64.py:29` /
    `ropmakerx86.py:29` is a Python character class that was clearly meant
    to be an alternation: `[(rax)|(rbx)|…|(r15)]{3}`. Written with `[…]` it
    is not an alternation and contains no ranges — it is the literal set of
    characters `{ ( ) | r a x b c d s i 0 1 2 3 4 5 9 }`, and `;` is **not**
    in it. The actual bug is that *any* 3-character permutation of that set
    matches (`r9d`, `((r`, `rxx`), which in practice never changes the
    outcome because the following `pop <reg>` lookup discards non-registers.
    We do explicit operand parsing against fixed register lists
    (`REGS64`/`REGS32` in `crates/rf-chain/src/linux.rs`) with the same
    backtracking, and those lists **reproduce the oracle's effective set
    rather than correcting it**: x64 is the oracle's enumeration minus `r9`
    (the `{3}` quantifier cannot match a 2-character name, so ROPgadget
    never selects it either), and `r8` is absent from the oracle's
    enumeration altogether — the character `8` is not in the class, so no
    `r8` form can match. `rbp` and `rsp` are considered by neither tool.
    Net effect: a binary whose only clean-tail write-what-where primitive
    goes through `r8`, `r9` or `rbp` reports "can't find a suitable gadget"
    in both tools. Widening the register set is a deliberate parity
    divergence and is not done here.
  - `ropmakerx64.py:79` hardcodes `.data`; we fall back to the first
    writable non-executable section when no section is named `.data`
    (mirrors how ROPgadget's `getDataSections` already treats every
    non-exec section as a candidate).
  - iced-x86 renders single-digit immediates as hex (`add rax, 0x1`) where
    capstone prints decimal (`add rax, 1`); the builder matches both forms
    (the comment text in the generated script keeps our iced rendering —
    payloads are byte-identical).
  - the CLI prints only the python script (not ROPgadget's surrounding
    gadget dump and step logs), and missing gadgets are a structured
    `chain_error` instead of print-and-return.
- `--chain windows-virtualprotect` (Phase 4b) design choices (no ROPgadget
  oracle exists; per PLAN sec. 6.2):
  - **anchor-first** API resolution (`--api-addr`) precedes IAT
    dereference — the spike confirmed the IAT path is not the common case
    (cmd.exe does not import VirtualProtect).
  - the x86 IAT dereference path is not implemented; x86 requires
    `--api-addr` and the error says so.
  - `call rax`-family transfer gadgets are rejected for the IAT path
    (`call` pushes a return address that would shadow the second-stack
    frame); only `jmp rax` is used.
  - export-table lookup (PLAN sec. 6.2 #3c) is not implemented: the spike
    showed anchor-first + IAT cover the realistic cases.
  - multi-call second-stack composition landed in v0.5 (`CHWIN-08`): a
    comma-separated `--api-name` list composes several calls into one chain,
    each returning into the next through a stack-adjust gadget, with
    `--stage` writing the shellcode via write-what-where gadgets and
    `--chain-pivot` splitting the chain at the pivot. The single-call
    return-into-shellcode frame remains the default.
  - the alignment model assumes a 16-aligned chain base at the pivot —
    the standard exploit precondition; the invariant reasons about word
    index parity, not absolute addresses.

## Documentation map

| Document | What it is for |
|---|---|
| [MANUAL.md](MANUAL.md) | **The user manual.** Installation, concepts, the complete flag reference, the ROPgadget flag-coverage table, the known divergences, the generated MCP tool block, and nine worked scenarios. |
| [TAXONOMY.md](TAXONOMY.md) | The classifier's decision rules R1–R13. Cite a rule number, not a label you observed. |
| [`docs/API-STABILITY.md`](docs/API-STABILITY.md) | What the published crates promise, and — as explicitly — what they do not. |
| [`docs/PUBLISHING.md`](docs/PUBLISHING.md) | Which crate is published under which name, in which order, and what is in the tarball. |
| [`docs/measured-2026-09.md`](docs/measured-2026-09.md) | Every measurement this README quotes, with the command that produced it. |
| [`docs/classifier-eval.md`](docs/classifier-eval.md) | How the classifier was evaluated, and the caveats on the accuracy table. |
| [`docs/chain-regressions.md`](docs/chain-regressions.md) | Failing-before / passing-after runs for each chain defect fixed in v0.5. |
| [`docs/AUDIT-FINDINGS.md`](docs/AUDIT-FINDINGS.md) · [`docs/REMEDIATION.md`](docs/REMEDIATION.md) | The 137-finding audit this project was rebuilt against, and the plan that closed it. |
| [`docs/REMEDIATION-OUTCOME.md`](docs/REMEDIATION-OUTCOME.md) | **Read this before trusting the rest.** The final ledger: which of the 137 are fully closed (119), which only partly (15), which were deferred (3), what remains in each, and a section on what this evidence does *not* establish. |
| [`docs/gate-mutation.md`](docs/gate-mutation.md) | Every recorded experiment in which a gate was deliberately made to fail, including the v1.0.0 re-run of the five source reverts. |
| [`fuzz/README.md`](fuzz/README.md) | The two hostile-input harnesses and the recorded runs. |
| [`docs/MCP-DESIGN.md`](docs/MCP-DESIGN.md) | The MCP server's design review. |

Dated evidence files quote commands as they were run at the time, with the
pre-1.0 package names (`-p rf-cli`, `-p rf-mcp`); `docs/PUBLISHING.md` §2 has
the translation table.

## License and attribution

BSD-2-Clause — see [LICENSE](LICENSE). Every published crate ships a copy.

rop-finder is a **derivative work of
[ROPgadget](https://github.com/JonathanSalwan/ROPgadget)** in behaviour and in
ported algorithms: the anchor tables, the clean-decode rule, the dedup order
and the `ropmaker` chain construction are reimplementations of its logic, and
its test-suite binaries are this project's parity corpus. The copyright notice
and licence that entails are reproduced in [NOTICE](NOTICE);
`rop-finder --version` prints a one-line attribution.

`tests/fixtures/` is **not** covered by this repository's licence: those files
are third-party binaries under their own terms, several of them not
redistributable at all. See `tests/fixtures/PROVENANCE.md` before you fork,
mirror or vendor this repository — and note that no published crate contains
any of them.
