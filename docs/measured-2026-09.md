# Measured baseline — 2026-09-03, with v1.0.0 results appended 2026-09-04

Numbers measured on this tree, on one machine, so that later releases can cite a
file instead of a memory. `REMEDIATION.md` Phase 1 rewrites README/MANUAL/PLAN to
reference this document rather than restating figures inline.

Sections are dated and marked `(current)` or `[superseded]`. A superseded
section is kept because comparing it with its replacement is itself evidence
(most often, evidence that the *oracle* differs between platforms); it is not
a claim about the build you have.

## Build and test — v1.0.0, 2026-09-04 (current)

**Environment.** Windows 11 Pro 10.0.26200, 24 logical CPUs, AMD Ryzen.
`rustc 1.89.0`, `cargo 1.89.0 (c24e10642 2025-06-23)`, pinned by
`rust-toolchain.toml`. CPython 3.12.10. Oracle: ROPgadget 7.7 @ `b6e3fe31af46`
under `.venv-oracle`, **capstone 5.0.7, unicorn 2.1.2** — the same capstone
generation `rf-scan` pins via `capstone = "=0.14.0"`.

| Check | Command | Result |
|---|---|---|
| format | `cargo fmt --all -- --check` | clean, exit 0 |
| lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| tests | `cargo test --workspace --lib --bins --tests` | **729 passed, 0 failed, 4 ignored** |
| doctests | `cargo test --doc --workspace` | **21 passed, 0 failed** |
| MSRV | `cargo +1.88.0 check --workspace --all-targets --locked` | exit 0 |
| supply chain | `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok` |
| packaging | `cargo publish --dry-run` × 8 | all exit 0, no metadata warnings |

Per-package test counts (`--lib --bins --tests`): `rop-finder-core` 90,
`rop-finder-scan` 90, `rop-finder-classify` 48 (+4 ignored),
`rop-finder-chain` 91, `rop-finder-cache` 42, `rop-finder-api` 15,
`rop-finder` 118, `rop-finder-mcp` 235, `rf-bench` 0 — total 729.
Doc-tests by crate: `rf_api` 10, `rf_core` 4, `rf_classify` 3, `rf_scan` 3,
`rf_chain` 1 — total 21 (there were **zero** before v1.0.0; `ENG-08`).

The four ignored tests are review/sampling tools that assert nothing
(`corpus_diff::print_disagreements`, `effect_cost::classification_throughput`,
`effect_sample::dump_sample`, `sample_corpus::dump_candidates`), each carrying
its reason in the `#[ignore = "…"]` string.

### The eight gates — 2026-09-04 (current)

| Gate | Result |
|---|---|
| `tests/parity.py` | **PASS** — 763,166 of 763,204 = 99.9950%, `ours-only=0`, 68 divergent texts |
| `tests/doc_claims.py` | **PASS** — 12 claims, 0 failed, 0 warned; `LIVE-SPEEDUP` elf-Linux-x86 15.8x / 16.4x, elf-ARM64-bash 9.5x / 9.6x on two runs |
| `tests/chain_parity.py` | **PASS** — ERROR-PARITY 19, MISMATCH 21, OURS-REFUSED 1, REF-REFUSED 13, STRUCTURAL 2 |
| `tests/mcp_workability.py` | **PASS** — 4,972 rendered tokens vs a 10,000 budget (wire figure 10,692, advisory only) |
| `tests/flag_conformance.py` | **PASS** — 1,562 cases, 0 failures |
| `tests/capability_matrix.py` | **PASS** — 45 paired capabilities, 45 declared asymmetries, 43 answers |
| `tests/emulate.py --all` | exit 0 — RUNS 6, NO-CHAIN 2 |
| `tests/emulate.py --regressions` | exit 0 — CHWIN 8/8, CHWIN-08 5/5, CHLX-07 32/32 |

`docs/gate-mutation.md` Part 4 records the five source reverts re-run on this
tree: all five still turn a gate red, and all four touched files restored
byte-identically (`sha256sum -c`, 4 of 4 OK).

### `--cfg-aware` across the corpus — 2026-09-04

`CRIT-01`'s fix is table-aware: ROP-table gadgets survive, JOP/SYS gadgets need
an `endbr64`/`endbr32` landing pad. Measured on all 24 fixtures (the fat Mach-O
with `--arch x64`, the raw blob with its `--raw*` spec):

* **No fixture in the corpus contains an `endbr64` (`f3 0f 1e fa`) or
  `endbr32` (`f3 0f 1e fb`) byte sequence.** There is still no CET-marked
  binary here, so the JOP/SYS half of the filter is exercised only by unit
  tests.
* `--cfg-aware` returns a non-zero count on **21 of 24** fixtures — e.g.
  `elf-Linux-x64` 8,389, `pe-x64-cmd-v6.1.7601` 2,097, `elf-ARM64-bash`
  14,103, `UNIVERSAL-…-libSystem.B.dylib --arch x64` 21. The three zeros are
  `elf-ARMv7-ls`, `elf-Mips-Defcon-20-pwn100` and
  `pe-Windows-ARMv7-Thumb2LE-HelloWorld`.
* Every one of the 24 prints `CRIT-01`'s promised warning
  (`--cfg-aware: this binary contains no endbr32/endbr64 landing pads …`).

Reverting the fix (`docs/gate-mutation.md` R5) takes those counts to 0 and 0.

## Build and test — 2026-09-03 [superseded]

**Environment.** macOS (Darwin 27), Apple Silicon. rustc 1.89.0.
Oracle: ROPgadget 7.7 (`../ropgadget`) on CPython 3.11 with capstone 5.0.7.
(This section's parenthetical about the pinned `capstone = "=0.13.0"` was true
when it was written; `rf-scan` pins `=0.14.0` since v0.2.0, `ANCH-05`.)

| Check | Result |
|---|---|
| `cargo build --release` | clean, zero warnings |
| `cargo test --workspace` | 153 passed, 0 failed |
| `cargo clippy --all-targets -- -D warnings` | exit 0 |

Per-crate test counts: rf-scan 36, rf-cli 33, rf-core 33, rf-chain 28,
rf-classify 11 (+1 eval), rf-mcp 8 (+3 stdio integration). Doc-tests: 0.

## Gadget parity vs ROPgadget 7.7 — v0.2.0 (current)

This is the authoritative parity measurement for the current build. The two
older sections below are kept, marked `[superseded]`, because comparing them is
the evidence that the oracle itself differs between platforms — they are not
claims about this build.

**Environment.** Windows 11 Pro 10.0.26200, rustc 1.89.0, CPython 3.12.10.
Oracle: ROPgadget 7.7 @ `b6e3fe31af46` under `.venv-oracle`, capstone 5.0.7 —
the generation `rf-scan` pins via `capstone = "=0.14.0"`.
Post-dedup `(vaddr, bytes)` sets, `--depth 10`, full 24-fixture corpus.

**763,166 of 763,204 reference gadgets reproduced — 99.995% parity.**

| Fixture | ref | ours | matched | overlap | text divergent |
|---|---:|---:|---:|---:|---:|
| Linux_lib32.so | 59929 | 59929 | 59929 | 100.0000% | 0 |
| Linux_lib64.so | 53759 | 53759 | 53759 | 100.0000% | 0 |
| UNIVERSAL-x86-x64-libSystem.B.dylib | 366 | 366 | 366 | 100.0000% | 0 |
| elf-ARM64-bash | 17653 | 17653 | 17653 | 100.0000% | 0 |
| elf-ARMv7-ls | 3244 | 3244 | 3244 | 100.0000% | 0 |
| elf-FreeBSD-x86 | 11565 | 11565 | 11565 | 100.0000% | 0 |
| elf-Linux-RISCV_32 | 279 | 279 | 279 | 100.0000% | 68 |
| elf-Linux-RISCV_64 | 302 | 302 | 302 | 100.0000% | 0 |
| elf-Linux-x64 | 43972 | 43972 | 43972 | 100.0000% | 0 |
| elf-Linux-x86 | 42508 | 42508 | 42508 | 100.0000% | 0 |
| elf-Linux-x86-NDH-chall | 33642 | 33642 | 33642 | 100.0000% | 0 |
| elf-Mips-Defcon-20-pwn100 | 133163 | 133163 | 133163 | 100.0000% | 0 |
| elf-PPC64-bash | 45631 | 45631 | 45631 | 100.0000% | 0 |
| elf-PowerPC-bash | 86966 | 86966 | 86966 | 100.0000% | 0 |
| elf-SparcV8-bash | 7264 | 7264 | 7264 | 100.0000% | 0 |
| elf-x64-bash-v4.1.5.1 | 45377 | 45377 | 45377 | 100.0000% | 0 |
| elf-x86-bash-v4.1.5.1 | 42056 | 42056 | 42056 | 100.0000% | 0 |
| macho-ppc-openssl | 106710 | 106710 | 106710 | 100.0000% | 0 |
| macho-x64-ls | 1289 | 1289 | 1289 | 100.0000% | 0 |
| macho-x86-ls | 1272 | 1272 | 1272 | 100.0000% | 0 |
| pe-Windows-ARMv7-Thumb2LE-HelloWorld | 38 | 404 | 0 | 0.0000% | n/a |
| pe-x64-cmd-v6.1.7601 | 12509 | 12509 | 12509 | 100.0000% | 0 |
| pe-x86-cmd-v6.1.7600 | 13703 | 13703 | 13703 | 100.0000% | 0 |
| raw-x86.raw | 7 | 7 | 7 | 100.0000% | 0 |
| **total** | **763204** | **763570** | **763166** | **99.9950%** | **68** |

`UNIVERSAL-x86-x64-libSystem.B.dylib` is measured with `--compat`. Since
CORE-03 a multi-slice fat Mach-O is refused without `--arch`, so reproducing
the oracle's flat-concatenation output has to be asked for explicitly.

### Two different counts of "bit-exact", both reported

The number depends on whether gadget TEXT is part of "bit-exact", and both
figures are worth stating because they answer different questions:

* **24 of 24 fixtures are bit-exact** by *gadget set* — zero unexcused
  `ref-only` and zero unexcused `ours-only` `(vaddr, bytes)` keys. This is what
  `tests/doc_claims.py` recounts from `tests/parity-baseline/*.json`.
* **22 of 24 are bit-exact by set AND rendered text.** The two that are not are
  the two recorded intentional divergences in `tests/known-divergences.json`:
  `elf-Linux-RISCV_32` (ANCH-04, 68 of 279 texts differ — ROPgadget decodes
  every RISC-V binary as RV64 including ELFCLASS32 ones) and
  `pe-Windows-ARMv7-Thumb2LE-HelloWorld` (ANCH-06, disjoint sets — ROPgadget
  scans a Thumb-2-only image with the A32 tables).

Against the v0.1.1 baseline of 11 of 24 (macOS) / 9 of 24 (Windows), and the
Phase 2 exit criterion of >= 20 of 24.

**Gadget-text divergence on x86/x64: 0 of 361,954 matched gadgets (0.0000%).**
The criterion was < 1%, from a measured 15-29% at v0.1.1. All 68 remaining text
differences in the whole corpus are on the one RISC-V 32 fixture.

Reproduce: `python tests/parity.py` (add `--oracle-cache DIR` to use
precomputed oracle dumps instead of re-running ROPgadget).

## Gadget parity vs ROPgadget 7.7

Post-dedup `(vaddr, bytes)` sets, `--depth 10`, full 24-fixture corpus.

**763,186 of 763,718 reference gadgets reproduced — 99.93%.** [superseded]

11 of 24 fixtures are bit-exact (100.00% both directions): [superseded]
UNIVERSAL-x86-x64-libSystem, elf-Linux-RISCV_32, elf-Linux-RISCV_64,
elf-Mips-Defcon-20-pwn100, elf-PPC64-bash, elf-PowerPC-bash, elf-SparcV8-bash,
macho-ppc-openssl, macho-x64-ls, pe-Windows-ARMv7-Thumb2LE-HelloWorld, raw-x86.raw.

Divergence is confined to x86/x64 (iced-x86 vs capstone text) and ARM/ARM64
(capstone core version). Lowest: elf-ARMv7-ls 99.57%, macho-x86-ls 99.61%.

Reproduce: `python tests/parity.py --release`.

> **Superseded note (v0.2.0).** This section originally warned that the harness
> preferred `target/release/rop-finder.exe` when one existed and therefore
> failed on non-Windows hosts (`ENG-04`, `CLAIM-08`). That is fixed: the binary
> name is now chosen by platform, the oracle is resolved by repo-relative path
> with `ROPGADGET_PATH`/`ROPGADGET_PYTHON` overrides, and the harness exits
> non-zero on a regression instead of printing a percentage and returning. The
> macOS figures above are left exactly as they were measured; the Windows
> re-measurement is a **separate** section below, not a replacement for them.

## Speed vs ROPgadget 7.7 — v0.5.0 (current)

<!-- speedup-table: current -->

This is the authoritative speed measurement for the current build, and it is
the one `tests/doc_claims.py` gates. The v0.1.1 macOS table below is kept,
marked `[superseded]`, for the same reason the v0.1.1 parity numbers are kept:
deleting the number a claim was retracted against would hide the retraction.

**Environment.** Windows 11 Pro 10.0.26200, 24 logical CPUs, rustc 1.89.0,
`cargo build --release` (`lto = true`, `codegen-units = 1`). Oracle: ROPgadget
7.7 @ `b6e3fe31af46` on CPython 3.12.10 with capstone 5.0.7.
`--depth 10`, both tools' stdout discarded, quiet machine, **best-of-3 on both
sides**. Reproduce: `python tests/benchmark.py --runs 3 --no-ropper`.

| Fixture | ROPgadget | rop-finder | Speedup |
|---|---:|---:|---:|
| elf-Linux-x86 | 1.411 s | 0.086 s | **16.4x** |
| elf-x64-bash-v4.1.5.1 | 1.387 s | 0.096 s | **14.5x** |
| elf-ARM64-bash | 0.949 s | 0.101 s | **9.4x** |
| elf-Mips-Defcon-20-pwn100 | 5.288 s | 0.542 s | **9.7x** |
| elf-PowerPC-bash | 1.701 s | 0.232 s | **7.3x** |

Gadget counts are identical to the oracle's on all five (42,508 / 45,377 /
17,653 / 133,163 / 86,966), so these are like-for-like runs and not a
comparison of different amounts of work.

PLAN.md's Phase 1 exit criteria were >=10x on x86/x64 and >=4x on the
capstone-backed architectures. **Both are now met on every architecture
measured**, and PLAN.md's §3.4 and §7 dispositions are updated to say so. This
reverses the v0.1.1 retraction; the retraction was correct when it was made
and the numbers that justified it are still printed below.

### The honest caveat: this machine is not that machine

The v0.1.1 table was taken on macOS/Apple Silicon with CPython 3.11, where the
oracle ran `elf-Linux-x86` in 0.56 s. Here the same oracle takes 1.411 s. A
speedup is a ratio between two things and one of them moved, so
`16.4x vs 6.2x` is **not** a statement that the engine got 2.6x faster.

The controlled statement is the same-machine, same-oracle, same-harness
comparison of the two builds. `v0.4.0` here is this repository at commit
`8ee168b` with `crates/rf-scan/` restored from that commit and everything else
held constant:

| Fixture | v0.4.0 | v0.5.0 | engine speedup | ratio at v0.4.0 | ratio at v0.5.0 |
|---|---:|---:|---:|---:|---:|
| elf-Linux-x86 | 0.138 s | 0.086 s | 1.60x | 10.1x | 16.4x |
| elf-x64-bash-v4.1.5.1 | 0.153 s | 0.096 s | 1.60x | 9.0x | 14.5x |
| elf-ARM64-bash | 0.493 s | 0.101 s | **4.89x** | 1.9x | 9.4x |
| elf-Mips-Defcon-20-pwn100 | 2.693 s | 0.542 s | **4.97x** | 2.0x | 9.7x |
| elf-PowerPC-bash | 0.991 s | 0.232 s | **4.27x** | 1.7x | 7.3x |

Read that way the result is sharper than the headline ratios, not weaker.
Phase 6's exit criterion was *improvement on every architecture*, and every
architecture improved on both comparisons — against the v0.1.1 record and
against a v0.4.0 binary built on this machine an hour earlier. The x86/x64
gain is 1.6x because iced-x86 was already fast and the work removed there was
the decode cache; the 4.3–5.0x on the capstone architectures is `PERF-09`, the
coverage-limited resumable region decode, which is where the audit said the
non-x86 speedup would have to come from.

### Where the time went — phase measurements

`crates/rf-bench/src/bin/probe.rs`, best-of-5, `--depth 10`. The `scan` phase
is the decode phase alone, with `post_process` excluded so it cannot move
underneath the measurement.

| Measurement | v0.4.0 | v0.5.0 | ratio |
|---|---:|---:|---:|
| `probe time scan elf-x64-bash-v4.1.5.1` (parallel) | 0.0603 s | 0.0129 s | **4.67x** |
| `probe time scan elf-x64-bash-v4.1.5.1 --serial` | 0.1474 s | 0.0977 s | **1.51x** |

`PERF-03`'s exit criterion was ">=1.4x on the decode phase of elf-x64-bash
with a byte-identical gadget set". Both rows clear it, and the gadget set is
byte-identical: `probe digest` over all 22 scannable fixtures is equal between
the two builds in **both** modes — the final post-processed stream **and** the
raw pre-dedup traversal stream, which is order-sensitive and therefore also
catches a partitioning change that silently reorders dedup survivors.

The per-start decode cache itself is gone. `engine.rs` and `cs.rs` each held a
`HashMap<usize, Rc<Vec<WinInsn>>>` at v0.4.0; at v0.5.0 the only occurrences
of the phrase in either file are the two comments that explain the removal.

### Parallel scaling

`PERF-04`'s exit criterion was >=8x against single-threaded on the MIPS
fixture. This machine has 24 logical CPUs.

| Phase, `elf-Mips-Defcon-20-pwn100` | serial | parallel | scaling |
|---|---:|---:|---:|
| `scan` (the parallelised phase) | 1.2997 s | 0.1366 s | **9.51x** |
| `full` (scan + `post_process`) | 1.5898 s | 0.3242 s | 4.90x |

The `full` row is reported because it is the number a user experiences, and
the gap between the two is the honest one: `post_process` is largely serial,
so the pipeline scales at 4.9x even though the phase that was parallelised
scales at 9.5x. The criterion is stated against the scan phase and is met
there.

### Allocation, and the trie index

`PERF-10`'s exit criterion was "zero per-gadget temporary String allocations
remain in `post_process`". Discharged by counting rather than profiling: there
is no heap profiler on this host, so `cargo run --release -p rf-bench
--features alloc-count --bin probe -- alloc FIXTURE` installs a counting
`GlobalAlloc` and reads the delta across `post_process`. The feature is **off
by default** — two relaxed atomics on every allocation is exactly what must
not be in a timing run.

| Fixture | gadgets in | v0.4.0 allocs | per gadget | v0.5.0 allocs | per gadget |
|---|---:|---:|---:|---:|---:|
| elf-Mips-Defcon-20-pwn100 | 324,286 | 648,592 | 2.0001 | **165** | 0.0005 |
| elf-x64-bash-v4.1.5.1 | 71,946 | 143,910 | 2.0003 | **76** | 0.0011 |

Two allocations per gadget to none: the old path built a joined `String` key
per gadget and then cloned it into the `HashSet`. `crates/rf-scan/src/trie.rs`
(`GadgetTrie`) replaces both — `insert` walks the instruction list the gadget
already owns and returns "is this text new", which *is* the dedup predicate,
and `trie::cmp_joined` sorts on the `" ; "`-joined text without ever joining
it. The 165 and 76 that remain are the trie's own vector growth, which is
O(log n) in the gadget count and not per-gadget: they do not scale with the
input, which is what the criterion is about.

The trie also answers `ending_with(tail)` in O(|tail|) plus a subtree walk
(gadgets are stored reversed, so a tail is a prefix), which is the "all
gadgets ending in this tail" capability PLAN listed. That capability exists in
the library and is tested; there is no CLI flag or MCP argument for it yet.

## Speed vs ROPgadget 7.7 — v0.1.1 baseline (macOS) [superseded]

<!-- speedup-table: v0.1.1-superseded -->

`--depth 10`, both tools' stdout discarded, quiet machine.
rop-finder best-of-3, ROPgadget best-of-2. macOS/Apple Silicon, CPython 3.11.

| Fixture | ROPgadget | rop-finder | Speedup |
|---|---:|---:|---:|
| elf-Linux-x86 | 0.56 s | 0.09 s | **6.2x** [superseded] |
| elf-x64-bash-v4.1.5.1 | 0.57 s | 0.10 s | **5.7x** [superseded] |
| elf-ARM64-bash | 0.48 s | 0.23 s | **2.1x** [superseded] |
| elf-Mips-Defcon-20-pwn100 | 2.54 s | 1.52 s | **1.7x** [superseded] |
| elf-PowerPC-bash | 0.76 s | 0.60 s | **1.3x** [superseded] |

PLAN.md's Phase 1 exit criteria were >=10x on x86/x64 and 4-8x elsewhere.
**Neither was met by these numbers**, and Phase 1 of the remediation plan
retracted the claim on the strength of this table. Phase 6 re-measured against
it and required improvement on every architecture; the current section above
records the result. This table is kept, not edited, because the retraction it
justified is part of the record.

Small fixtures (raw-x86.raw, the RISC-V pair, pe-ARMv7) show 10-12x, but those
runs are dominated by CPython interpreter startup rather than scan work and are
not evidence for the headline claim.

## Second machine — Windows, 2026-09-03 (v0.2.0 gate baseline)

The figures above were taken on macOS/Apple Silicon with CPython 3.11. The
v0.2.0 gates (`tests/parity-baseline/`, `crates/rf-bench/baseline.json`) were
frozen on a different machine, and **both numbers are kept**: replacing one
with the other would hide the fact that the oracle is not bit-identical across
platforms, which is exactly the kind of silent substitution `ENG-04` was about.

**Environment.** Windows 11 Pro 10.0.26200, rustc 1.89.0, CPython 3.12.10.
Oracle: ROPgadget at upstream commit `b6e3fe31af46` (7.7) on CPython 3.12.10
with capstone 5.0.7. `cargo build --release -p rf-cli`.

### The oracle side

| | macOS (above) | Windows (here) | delta |
|---|---:|---:|---:|
| Fixtures the oracle handles | 24 / 24 | 24 / 24 | — |
| Reference gadgets, `--depth 10 --dump` | 763,718 | **763,204** | **−514 (−0.067%)** |
| Fixtures skipped | 0 | 0 | — |

**The 514-gadget delta is a property of the oracle, not a regression in
rop-finder.** ROPgadget is python-capstone plus a Python gadget walker, and
both halves are platform-sensitive:

* python-capstone 5.0.7 ships a *prebuilt* `libcapstone` per wheel. The macOS
  arm64 wheel and the Windows x86-64 wheel are separate builds of the C core,
  and the ARM/ARM64/x86 decoders differ at the margins in exactly the places
  the parity harness already flags (`udf #0`, some VFP `vmov`/`vmrs` forms,
  LOCK-prefixed encodings). A handful of instructions that decode on one host
  fail to decode on the other, and each failure removes the gadgets that end
  at that byte.
* The interpreter differs too (3.11 vs 3.12); ROPgadget's own `re` and byte
  handling do not change results, but the wheel selected for each interpreter
  does.

Two consequences, both deliberate:

1. `tests/parity-baseline/*.json` records the oracle's **per-fixture count and
   a sha256 over its sorted `(vaddr, bytes)` key set**. If someone runs the
   gate against a different ROPgadget commit or a different capstone build, the
   harness reports `ORACLE DRIFT` and exits non-zero rather than charging the
   difference to rop-finder. That is the mechanism that keeps the two numbers
   above from ever being quietly merged.
2. Comparing the two machines' *ratios* is meaningful; comparing their
   *absolute* gadget counts is not. `tests/doc_claims.py` therefore gates the
   percentage strictly and the absolute total with an explicit 0.5% band, and
   prints the delta either way.

### The rop-finder side, same machine, same oracle

**762,672 of 763,204 reference gadgets reproduced — 99.9303%**, with 1,202 [superseded]
gadgets found that the oracle does not have. [superseded]

| Fixture | ref | matched | ref-only | ours-only | coverage |
|---|---:|---:|---:|---:|---:|
| Linux_lib32.so | 59929 | 59844 | 85 | 144 | 99.8582% |
| Linux_lib64.so | 53759 | 53741 | 18 | 266 | 99.9665% |
| UNIVERSAL-x86-x64-libSystem.B.dylib | 366 | 366 | 0 | 3 | 100.0000% |
| elf-ARM64-bash | 17653 | 17642 | 11 | 0 | 99.9377% |
| elf-ARMv7-ls | 3244 | 3230 | 14 | 0 | 99.5684% |
| elf-FreeBSD-x86 | 11565 | 11544 | 21 | 19 | 99.8184% |
| elf-Linux-RISCV_32 | 279 | 279 | 0 | 0 | 100.0000% |
| elf-Linux-RISCV_64 | 302 | 302 | 0 | 0 | 100.0000% |
| elf-Linux-x64 | 43972 | 43939 | 33 | 206 | 99.9250% |
| elf-Linux-x86 | 42508 | 42421 | 87 | 59 | 99.7953% |
| elf-Linux-x86-NDH-chall | 33642 | 33542 | 100 | 50 | 99.7028% |
| elf-Mips-Defcon-20-pwn100 | 133163 | 133163 | 0 | 0 | 100.0000% |
| elf-PPC64-bash | 45631 | 45631 | 0 | 0 | 100.0000% |
| elf-PowerPC-bash | 86966 | 86966 | 0 | 0 | 100.0000% |
| elf-SparcV8-bash | 7264 | 7264 | 0 | 0 | 100.0000% |
| elf-x64-bash-v4.1.5.1 | 45377 | 45348 | 29 | 303 | 99.9361% |
| elf-x86-bash-v4.1.5.1 | 42056 | 41968 | 88 | 70 | 99.7908% |
| macho-ppc-openssl | 106710 | 106710 | 0 | 0 | 100.0000% |
| macho-x64-ls | 1289 | 1289 | 0 | 4 | 100.0000% |
| macho-x86-ls | 1272 | 1267 | 5 | 0 | 99.6069% |
| pe-Windows-ARMv7-Thumb2LE-HelloWorld | 38 | 38 | 0 | 0 | 100.0000% |
| pe-x64-cmd-v6.1.7601 | 12509 | 12490 | 19 | 48 | 99.8481% |
| pe-x86-cmd-v6.1.7600 | 13703 | 13681 | 22 | 30 | 99.8395% |
| raw-x86.raw | 7 | 7 | 0 | 0 | 100.0000% |
| **total** | **763204** | **762672** | **532** | **1202** | **99.9303%** |

**9 of 24 fixtures are bit-exact** (zero divergence in both directions) here, [superseded]
against 11 on macOS: elf-Linux-RISCV_32, elf-Linux-RISCV_64,
elf-Mips-Defcon-20-pwn100, elf-PPC64-bash, elf-PowerPC-bash, elf-SparcV8-bash,
macho-ppc-openssl, pe-Windows-ARMv7-Thumb2LE-HelloWorld, raw-x86.raw. The two
that drop off — `UNIVERSAL-x86-x64-libSystem.B.dylib` (3 ours-only) and
`macho-x64-ls` (4 ours-only) — reach 100% coverage of the reference in both
runs; they lose "bit-exact" status only in the ours-only direction. This is
recorded as a `warn`, not a `fail`, in `tests/doc_claims.py` (`BIT-EXACT`),
because it is a cross-platform comparison, and it is the one claim in
README/`measured-2026-09.md` that does not reproduce here.

### Gadget-text agreement

Parity is judged on `(vaddr, bytes)` sets. The harness also reports text
agreement over the matched set, which is a different and much weaker number:
**625,203 of 762,672 matched gadgets (81.98%) render identically** after
whitespace/immediate normalization. Per-fixture, x86/x64 text divergence on
this machine runs 27–42% (lowest `macho-x86-ls` 26.8%, highest
`Linux_lib64.so` 42.5%), and 0% on every capstone architecture.

> This does **not** reproduce README/MANUAL's "15–29% of x86/x64 gadget texts
> do not match" (`SCAN-08`). The harness's normalizer and `SCAN-08`'s are not
> the same function, so the two numbers are not comparable as written. Until
> one definition is settled the doc-claims gate does not assert this figure;
> the divergence-class work in the "filter semantics and formatter fidelity"
> workstream is what will settle it.

Reproduce all of the above:

```
cargo build --release -p rf-cli
python tests/parity.py                     # the gate: exit 1 on any regression
python tests/parity.py --seed-reference    # re-freeze the ORACLE reference sets
python tests/parity.py --update-floor      # ratchet the per-fixture floors up
```

### Speed on this machine

`--depth 10`, both tools' stdout discarded, best-of-2, `tests/benchmark.py`:

| Fixture | ROPgadget | rop-finder | Speedup |
|---|---:|---:|---:|
| elf-Linux-x86 | 1.392 s | 0.155 s | **9.0x** |
| elf-ARM64-bash | 0.974 s | 0.331 s | **2.9x** |

Higher than the macOS row on x86 (9.0x vs 6.2x) and on ARM64 (2.9x vs 2.1x) —
but the *oracle* is also much slower here (1.392 s vs 0.56 s on the same
fixture), so most of the difference is CPython-on-Windows process and import
cost, not rop-finder being faster. **PLAN's >=10x / >=4x criteria are still not
met on either machine**, which is what `tests/doc_claims.py` asserts.

## Criterion benchmark suite (CLAIM-02 / PERF-08)

`benches/` was an empty directory with no `criterion` dependency anywhere in
the workspace. `crates/rf-bench` is now that suite: 26 benchmarks across three
targets, driven through the stable `rf_scan::scan_binary` entry point.

* `scan_throughput` — one benchmark per decode path (x86, x64, arm64, armv7,
  ppc32, ppc64, sparc, riscv64, PE x64, Mach-O x64), reporting bytes of
  executable code scanned per second, plus a serial-vs-parallel pair on x86 and
  arm64 so the rayon utilisation ratio (`CLAIM-01`) is visible.
* `dedup` — `post_process` with and without text dedup, over the real
  undeduplicated gadget list.
* `output` — the two CLI output modes over the finished gadget set.

Baseline recorded on the Windows machine described above and committed to
`crates/rf-bench/baseline.json` (medians; `cargo bench -p rf-bench`).

> **Re-record this after the engine keystone lands.** These medians were taken
> while the `ScanOptions`/sink/cancellation reshape of `rf-scan` was still in
> progress in the same release. The suite compiles and runs against the current
> engine (`cargo bench -p rf-bench -- --test`, 26/26 Success), but the numbers
> are a snapshot of a moving target. Re-run `cargo bench -p rf-bench` and
> `python crates/rf-bench/check_regression.py --record` once the engine is
> final, and update the table below in the same commit. CI does not depend on
> this file: the regression gate compares against a baseline the runner records
> for itself, so a stale committed baseline degrades to a report, not a
> false failure.

| benchmark | median | | benchmark | median |
|---|---:|---|---|---:|
| scan/parallel/x86 | 113.854 ms | | post_process/dedup/x86 | 35.622 ms |
| scan/parallel/x64 | 105.463 ms | | post_process/dedup/x64 | 45.381 ms |
| scan/parallel/arm64 | 499.259 ms | | post_process/dedup/arm64 | 39.839 ms |
| scan/parallel/armv7 | 21.268 ms | | post_process/dedup/pe-x64 | 8.152 ms |
| scan/parallel/ppc32 | 1.179 s | | post_process/sort_only/x86 | 26.760 ms |
| scan/parallel/ppc64 | 614.402 ms | | post_process/sort_only/x64 | 27.900 ms |
| scan/parallel/sparc | 36.679 ms | | post_process/sort_only/arm64 | 26.327 ms |
| scan/parallel/riscv64 | 931.349 us | | post_process/sort_only/pe-x64 | 4.185 ms |
| scan/parallel/pe-x64 | 24.255 ms | | output/text/x86 | 13.646 ms |
| scan/parallel/macho-x64 | 2.424 ms | | output/text/arm64 | 5.708 ms |
| scan/serial/x86 | 183.864 ms | | output/text/pe-x64 | 1.495 ms |
| scan/serial/arm64 | 575.457 ms | | output/json/x86 | 87.221 ms |
| | | | output/json/arm64 | 81.573 ms |
| | | | output/json/pe-x64 | 17.103 ms |

Two things fall straight out of the table and are worth recording:

* **Parallel speedup is 1.61x on x86 (183.864 / 113.854) and 1.15x on arm64
  (575.457 / 499.259)** on a multi-core machine. That is the coarse
  (region × anchor) work-item granularity `CLAIM-01` describes, now measured by
  a committed instrument instead of asserted.
* **`--json` output costs more than the scan on arm64** (81.573 ms of
  rendering against a 499 ms scan is 16%, but against `output/text`'s 5.708 ms
  it is 14x) — the JSON path is the expensive one, and it is the path the MCP
  server uses.

The regression gate is `crates/rf-bench/check_regression.py`: >10% slower than
the baseline median is a failure. Its deliberately-red run is recorded in
`docs/gate-mutation.md` (M5).

### The committed baseline is not reproducible — measured 2026-09-04

**Read this before treating `baseline.json` as a ratchet.** On 2026-09-04, on
the same machine that recorded it, `cargo bench -p rf-bench` followed by
`python crates/rf-bench/check_regression.py` was run four times and returned
`BENCH GATE: FAIL` every time, **with a different set of "regressions" each
time**:

| run | conditions | reported regressions |
|---|---|---|
| A | this repo's `target/`, full suite | `decode/serial/arm64` 13.6%, `post_process/dedup/pe-x64` 14.3% |
| B | same, offenders re-run alone | `decode/serial/arm64` 16.1% (the other fell back to 4.7%) |
| C | fresh copy of the same source, fresh target, machine busy | `post_process/dedup/pe-x64` 43.3%, `post_process/sort_only/pe-x64` 44.1%, `scan/parallel/pe-x64` 15.8% — `decode/serial/arm64` back inside the band at 1.024x |
| D | same fresh tree, machine quiet | `post_process/dedup/pe-x64` 52.3%, `post_process/sort_only/pe-x64` 44.1% |

None of them is a real regression. The v1.0.0 source and the committed v0.5.0
source (`git archive HEAD`), each built in a **fresh** target directory and
benchmarked alternately, are indistinguishable:

| benchmark | v1.0.0 fresh target | v0.5.0 fresh target | v1.0.0 in this repo's `target/` | baseline |
|---|---|---|---|---|
| `decode/serial/arm64` | 355.16 / 353.89 ms | 354.50 / 354.02 ms | 392.34 / 393.37 ms | 339.393 ms |
| `post_process/dedup/pe-x64` | 4.575 / 4.372 ms | 4.536 / 4.439 ms | — | 4.061 ms |
| `post_process/sort_only/pe-x64` | 2.989 / 3.044 ms | 3.153 / 3.043 ms | — | 3.247 ms |

Two distinct artifacts, both identified:

* **`decode/serial/arm64`'s 13-16% gap belongs to this working copy's
  long-lived `target/` directory**, not to the source. The same source in a
  clean target measures 354 ms, the same as v0.5.0. (That directory has by
  now absorbed a debug build, a release build, an MSRV build under rustc
  1.88, eight `cargo publish` verification builds and five mutation
  rebuilds.)
* **The `pe-x64` post-process 43-52% figures are suite contamination.** Those
  two are the smallest benchmarks in the suite (3-4 ms medians) and follow
  much heavier ones. Run on their own they land at 4.4-4.6 ms and 3.0-3.2 ms
  in *both* trees.

For the record, the source cannot be responsible: `git diff` over
`crates/rf-scan/src` and `crates/rf-core/src`, comments filtered out, contains
exactly two changes in total between them — a `#![warn(missing_docs)]`
attribute and a rustfmt reflow of two enum variants that gained doc comments.
`Cargo.lock` moved no third-party dependency, and `[profile.release]` is
identical in both trees.

The baseline was **not** re-recorded to make the gate green; re-recording a
baseline to silence a gate is the failure mode this whole exercise exists to
prevent. What this measurement says is that
`check_regression.py --band 0.10` against a committed developer baseline is a
**report, not a gate** — which is exactly how `.github/workflows/ci.yml` uses
it (`|| true`, with the real gate against a baseline the runner records for
itself), and how this file should have described it. The honest fixes are to
raise the sample count on the sub-5 ms benchmarks or drop them, and to run the
suite from a clean target directory.

## Not measured here

**Superseded (v0.2.0):** this section used to open "No criterion benchmark
suite exists (`benches/` is empty)". It does now — see the criterion section
above — and `crates/rf-bench/baseline.json` is committed, so the wall-clock
figures in the macOS tables at the top of this file are no longer the only
performance evidence in the repository. The macOS tables themselves remain
wall-clock and unsampled; they are not re-derived from criterion, because that
run was on a machine that is no longer available.

Still not measured:

* **Peer tools.** No comparison against `ropper`, `rp++`, `radare2` or anything
  else was run. Earlier documentation carried a "~9-14x faster than ropper"
  figure; it has no source and has been removed rather than restated.
  `tests/benchmark.py` will benchmark `ropper` when it is importable and
  reports `n/a` when it is not; nothing in the repository asserts a number.
  `tests/doc_claims.py` fails if a ropper speedup figure reappears in any
  document (`NO-ROPPER-SPEEDUP`).
* **Peak RSS.** `PERF-05`/`ROB-02`'s memory figures (117 bytes per code byte,
  1.08 GB on the 9.3 MB fixture, 19.8 GB on the cloned-section PE) are not
  re-measured here and the criterion suite does not measure allocation.
* **The ET_CORE loader path.** Still no `core` fixture in the corpus, so the
  25th binary of ROPgadget's own suite remains unmeasured.
* **Cross-machine wall clock.** The macOS and Windows speed tables were taken
  on different hardware, OS and CPython builds and are not comparable to each
  other. Only the criterion suite, compared against a baseline recorded on the
  same machine, is a regression instrument.

## Documentation-retraction pass — 2026-09-03

Facts checked while rewriting README/MANUAL/PLAN/TAXONOMY for Phase 1
(`REMEDIATION.md`, "Retract every claim the code does not support"). Each
row is either a command actually run against this tree — Windows 11,
`cargo build -p rf-cli --release`, rustc 1.89.0 — or a source location that
was read. These are the receipts for the claims those documents now make.

| Claim now in the docs | How it was checked | Result |
|---|---|---|
| Fixture corpus is 24 binaries, not 25 | `ls tests/fixtures` | 24 binaries (plus `MANIFEST.sha256` and `PROVENANCE.md`, added in the same release). `PROVENANCE.md` records the dropped 25th, `core` (ET_CORE) |
| Default output is sorted alphabetically by gadget text, not by address | `rop-finder --binary tests/fixtures/elf-Linux-x86 --depth 4` | First gadget `0x080604ab : aaa ; …`, last `0x0807d14c : xor esi, esi ; ret 0xf01`. Alphabetical, addresses unordered. Source: `post_process` in `crates/rf-scan/src/engine.rs` (`keyed.sort_by(\|a, b\| a.0.cmp(&b.0))`, a port of `rgutils.alphaSortgadgets`) |
| `--cfg-aware` returns zero gadgets on every fixture | `for f in tests/fixtures/*; do rop-finder --binary "$f" --cfg-aware \| grep -c '^0x'; done` | 0 on all 24. Confirms `CRIT-01`; the MANUAL's `--cfg-aware` recommendation is withdrawn until v0.2 |
| `--version` prints the capstone version and the ROPgadget attribution | `rop-finder --version` | Prints `rop-finder 0.1.0`, `capstone 5.0 (bundled; …)`, `iced-x86 (decodes x86/x64)`, and the ROPgadget/BSD-3-Clause attribution. Exit 0 |
| `--help` and `--version` exit 0; `-v` is not bound | `rop-finder --help; rop-finder --version; rop-finder -v` | Exit 0, 0, 1. `-v` reports `unexpected argument` — recorded as a `partial` row in the MANUAL's flag-coverage table |
| `--chain windows-virtualprotect` prints an experimental warning | `rop-finder --binary tests/fixtures/pe-x86-cmd-v6.1.7600 --ropchain --chain windows-virtualprotect --api-addr 0x76771234` | Three `[Warning]` lines on stderr naming `CHWIN-01`, `CHWIN-02`, `CHWIN-03` and v0.5 |
| `--string`, `--opcode` are implemented | `rop-finder --binary tests/fixtures/elf-Linux-x86 --opcode c9c3` / `--string "bin"` | Both print ROPgadget-format hit lists |
| `--align` constrains but does not deepen on x86/x64 | Read `crates/rf-scan/src/engine.rs` (x86 path) vs `crates/rf-scan/src/cs.rs` (capstone path) vs `ropgadget/gadgets.py:73-89` | The oracle and `cs.rs` both step candidate starts by `ref - i*align`, reaching `(depth-1)*align` bytes back. The x86 path steps by `ref - i` and discards unaligned starts, reaching `depth-1` bytes. Counts on `elf-Linux-x86 --depth 10`: 42,480 gadgets at `--align 0`, 12,099 at `--align 4`. The oracle side could not be run here — python-capstone is not installed on this machine — so no cross-tool ratio is quoted |
| `--filter` is a literal suffix match, not an anchored regex | Read `pass_clean` in `crates/rf-scan/src/x86.rs` (`m.ends_with(s)`) vs `options.py`'s `re.match("({})$")` | Confirms `CLI-02`/`SCAN-01`; recorded as a known divergence |
| The classifier's evaluation is circular | Read `crates/rf-classify/tests/eval.rs` | `independent_labels()` re-implements the TAXONOMY.md rules over the same iced-x86 `InstructionInfoFactory` metadata `rf-classify` consumes; the three sampled fixtures (`elf-x64-bash-v4.1.5.1`, `pe-x64-cmd-v6.1.7601`, `elf-Linux-x64`) are all x86-64. The reported precision is self-agreement; it is now retracted from README and MANUAL |
| ROPgadget's write-what-where register class contains no ranges and not `;` | Read `ropgadget/ropchain/arch/ropmakerx64.py:29` and `ropmakerx86.py:29` | The class is `[(rax)\|(rbx)\|…\|(r15)]{3}` — the literal character set `{ ( ) \| r a x b c d s i 0 1 2 3 4 5 9 }`. `;` is absent, `8` is absent (so no `r8` form can match), and `{3}` cannot match the 2-character `r9`. `REGS64` in `crates/rf-chain/src/linux.rs` is that enumeration minus `r9` — the oracle's effective set, not a corrected one. README's description of this bug was wrong on both counts and has been rewritten |
| ROPgadget 7.7 has 30 flags | Read `ropgadget/args.py:75-104` | 30 `add_argument` calls; all 30 appear in the MANUAL's flag-coverage table against `pub struct Cli` in `crates/rf-cli/src/lib.rs` |
| The MCP server's post-fix shape | Read `crates/rf-mcp/src/confine.rs`, `lib.rs`, `main.rs` | `open_confined` handle API, `allow_dirs: Vec::new()` by default, `--allow-cwd` / `--i-accept-a-wide-allowlist` / `--max-depth` (64) / `--max-file-bytes` (256 MiB) / `--max-concurrent` (2) / `--verbose-path-errors`, single `path_denied` code, and a `get_server_config` tool — eight tools total, not seven. README and MANUAL now describe this shape |

No new timing or parity measurement was taken in this pass: the speed and
parity tables above are unchanged, and the retraction work only removed or
sourced claims rather than producing new figures.
