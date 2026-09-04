# Remediation outcome — the final ledger

**Date:** 2026-09-04. **Tree:** branch `remediation/v0.1.1-through-v1.0`,
working copy at v1.0.0, `git log --oneline -1` = `7291d9d` (the v0.5.0 release
commit; the v1.0.0 commit is made by the integrator, not by this pass).

This document exists so that the other five release documents can be trusted.
`docs/REMEDIATION.md` is the *plan*; `docs/AUDIT-FINDINGS.md` is the *charge
sheet*; the five release commit messages are each release's *own account of
itself*. None of those is a disinterested source. This one is written by the
pass whose only job was to check the others, and its bias — if it has one —
should be toward finding the plan wrong rather than right.

Everything below was re-measured on 2026-09-04 on the machine described in
§1. Where a number comes from a document rather than from a command run
today, the document is named. Where the evidence is thin, §6 says so in
plain words rather than leaving the reader to infer it.

**The one-line answer.** 137 findings: **119 fully closed, 15 partially
closed, 3 deferred by plan** (one of which turned out to be partly delivered
anyway). Every gate the six releases built is green today, and every one of
the five mutation experiments that is supposed to be able to turn a gate red
still does. Nothing has been published to crates.io.

---

## 1. The v1.0.0 verification, in full

**Environment.** Windows 11 Pro 10.0.26200, 24 logical CPUs. `rustc 1.89.0`,
`cargo 1.89.0 (c24e10642 2025-06-23)`, toolchain pinned by
`rust-toolchain.toml`. CPython 3.12.10 for the harnesses. Oracle: ROPgadget
7.7 @ `b6e3fe31af46` under `D:\Private\ROP-Finder\.venv-oracle`, **capstone
5.0.7, unicorn 2.1.2**. Corpus: 24 fixtures, 763,204 reference gadgets.

### 1.1 Build, lint, test

| Check | Command | Result |
|---|---|---|
| format | `cargo fmt --all -- --check` | clean, exit 0 |
| lint | `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 |
| tests | `cargo test --workspace --lib --bins --tests` | **729 passed, 0 failed, 4 ignored** |
| doctests | `cargo test --doc --workspace` | **21 passed, 0 failed** |
| MSRV | `cargo +1.88.0 check --workspace --all-targets --locked` | exit 0 |
| supply chain | `cargo deny check` | `advisories ok, bans ok, licenses ok, sources ok` |

729 is exactly the v0.5.0 count. The restructure removed 2,826 lines from
`crates/rf-cli/src` (`lib.rs` −1,770, plus `info.rs`, `pe_exports.rs` and
`query.rs` deleted outright) and stood up `crates/rf-api` at 3,206 lines,
the difference being the public API documentation that did not exist before —
without adding or losing a single test. The 21 doctests are
new: there were **zero** before this release, which is one half of what
`ENG-08` complained about.

Per package: `rop-finder-core` 90, `rop-finder-scan` 90, `rop-finder-classify`
48 (+4 ignored), `rop-finder-chain` 91, `rop-finder-cache` 42,
`rop-finder-api` 15, `rop-finder` 118, `rop-finder-mcp` 235, `rf-bench` 0.

The **four ignored tests** are not skipped assertions. They are
`corpus_diff::print_disagreements`, `effect_cost::classification_throughput`,
`effect_sample::dump_sample` and `sample_corpus::dump_candidates` — review and
sampling tools that print to stdout and assert nothing. Each carries its
reason in the `#[ignore = "…"]` string.

`#![warn(missing_docs)]` is set on all six library crates, and
`clippy --all-targets -D warnings` passes, so every public item in the
published API surface is documented. That is checked, not asserted.

### 1.2 The eight gates

All eight re-run on 2026-09-04, on the tree as it stands, after the
restructure and the rename.

| Gate | Command | Result |
|---|---|---|
| parity | `python tests/parity.py` | **PASS** — 763,166 of 763,204 = **99.9950%**, `ours-only=0`, 68 divergent texts (99.9911% text agreement) |
| doc claims | `python tests/doc_claims.py` | **PASS** — 12 claims checked, 0 failed, **0 warned**; `LIVE-SPEEDUP` measured elf-Linux-x86 15.8x / 16.4x and elf-ARM64-bash 9.5x / 9.6x on two runs |
| chain parity | `python tests/chain_parity.py` | **PASS** — ERROR-PARITY=19, MISMATCH=21, OURS-REFUSED=1, REF-REFUSED=13, STRUCTURAL=2 |
| MCP workability | `python tests/mcp_workability.py` | **PASS** — 4,972 rendered tokens against a 10,000 budget (50.3% under) |
| flag conformance | `python tests/flag_conformance.py` | **PASS** — 1,562 cases in 83 s, **0 failures**, 164 hits across 10 declared and bounded divergence classes |
| capability matrix | `python tests/capability_matrix.py` | **PASS** — 45 paired capabilities, 45 declared asymmetries, 2 vocabularies, 43 answers compared |
| chain emulation | `tests/emulate.py --all` | exit 0 — RUNS=6, NO-CHAIN=2 (both `int 0x80` absent, both expected) |
| chain regressions | `tests/emulate.py --regressions` | exit 0 — **CHWIN 8/8, CHWIN-08 5/5, CHLX-07 32/32** |

The parity figure is the load-bearing one, because the restructure claimed to
*move* code rather than change it. 763,166 of 763,204 is bit-for-bit the
v0.4.0 and v0.5.0 number. `ours-only=0` on every fixture — no fabricated
gadget anywhere in the corpus.

Two things in those runs that pass but should not be read as clean:

* `tests/parity.py` reports `STALE KNOWN-DIVERGENCES: divergence ANCH-03
  excused nothing across the whole run`. The AArch64/SPARC SYS-superset
  waiver is on the books and currently excuses zero gadgets. The gate prints
  this and **does not fail on it**, so a waiver that has stopped being needed
  can sit there indefinitely. It is inert today, not wrong.
* `tests/mcp_workability.py` prints `ADVISORY (wire): FAIL — 10,692 >= 10,000
  tokens`. The payload is still sent twice (`content[0].text` *and*
  `structuredContent`). The gate is on the rendered figure only, so this
  advisory has been red since v0.3.0 and is not gated by anything.

### 1.3 The v0.2 mutation experiments, re-run

Full transcripts in `docs/gate-mutation.md` Part 4. Five source fixes
reverted one at a time, each built, each run against the gates that are
supposed to hold it, each restored from a byte-level backup and verified with
`diff` plus `sha256sum -c` on all four touched files.

| Reverted | Gate that should go red | Verdict |
|---|---|---|
| `CORE-01` | `cargo test -p rop-finder-core` / `--test refusals` | **RED** (2/74, 1/9) — and the mutant ELF printed 42,508 fabricated gadgets at exit 0 |
| `CLI-01` | `cargo test -p rop-finder` | **RED** (2/81) — and an ARM query got a cache HIT serving seven x86 gadgets |
| `SCAN-02` | `cargo test -p rop-finder-scan --lib` + parity | **RED** both (−1 gadget on each CET-marked fixture) |
| `SCAN-03` | `cargo test -p rop-finder-scan --lib` + parity | **RED** both (−35 x86, −24 x64) |
| `CRIT-01` | `cargo test -p rop-finder-scan` | **RED** (1/71) — `--cfg-aware` went 2,097 → 0 and 8,389 → 0 |

**No gate has quietly stopped being able to go red.** The failing test names
are identical to the 2026-09-03 run; only the passing counts moved, because
the suite grew from 333 to 729.

Two results carry forward unchanged and matter for CI configuration:
`CLI-01` and `CRIT-01` are **invisible to the parity harness** — it never
passes `--cache` or `--cfg-aware`, which is now checked (`grep`) rather than
remembered. Each is held by exactly one `cargo test` suite. Dropping either
suite from CI silently un-gates a finding.

**What the mutation set does not cover.** None of the five reverts touches
the code the v1.0.0 restructure actually moved (`request_options`,
`scan_bytes`, `info_bytes`, the chain entry points, the whole query layer,
all lifted from `rf-cli` into `rf-api`). There is **no mutation experiment
aimed at the restructure itself**. The claim that the move was
behaviour-preserving rests on the eight gates and on the test count holding
at 729 — which is strong evidence, but it is evidence of a different kind
from a revert-and-observe-red experiment, and it should not be reported as
the same thing.

### 1.4 Packaging — dry runs only

Eight `cargo publish --dry-run --allow-dirty -p <pkg> --config
.cargo/publish-dry-run.toml`, in dependency order. **All eight exit 0.**

| Package | Files | Size (compressed) |
|---|---:|---:|
| `rop-finder-core` | 22 | 246.0 KiB (69.6 KiB) |
| `rop-finder-scan` | 19 | 324.2 KiB (92.9 KiB) |
| `rop-finder-classify` | 25 | 614.5 KiB (137.5 KiB) |
| `rop-finder-chain` | 10 | 318.7 KiB (81.9 KiB) |
| `rop-finder-cache` | 13 | 109.2 KiB (32.3 KiB) |
| `rop-finder-api` | 10 | 135.3 KiB (40.4 KiB) |
| `rop-finder` | 15 | 306.6 KiB (84.1 KiB) |
| `rop-finder-mcp` | 41 | 972.9 KiB (228.0 KiB) |

Across all eight runs the only warnings are the eight `aborting upload due to
dry run` lines and the expected `Patch … was not used in the crate graph`
notes from the bootstrap file. In particular **no `manifest has no
description / documentation / homepage / repository` warning appears on any
crate** — that warning is the metadata half of `ENG-08`, and it is gone.

`cargo publish --dry-run -p rf-bench` is refused: `` `rf-bench` cannot be
published. `package.publish` must be set to `true` or a non-empty list ``.
That is the intended state and CI asserts it.

### 1.5 Nothing was published

Checked four independent ways, because the prohibition on publishing is the
one instruction in this release whose violation could not be undone.

1. `git log --oneline -1` is still `7291d9d` (v0.5.0). Tags are `v0.1.1`
   through `v0.5.0`; **there is no `v1.0.0` tag**.
2. There is **no credential file**: neither `~/.cargo/credentials.toml` nor
   the legacy `~/.cargo/credentials` exists, and `CARGO_REGISTRY_TOKEN` is
   unset. `cargo publish` without `--dry-run` could not have authenticated.
3. Queried from **outside** the workspace (a scratch directory, so cargo
   cannot answer from the local packages), every one of the eight names
   returns `error: could not find <name> in registry
   https://github.com/rust-lang/crates.io-index`:
   `rop-finder`, `rop-finder-core`, `rop-finder-scan`, `rop-finder-classify`,
   `rop-finder-chain`, `rop-finder-cache`, `rop-finder-api`,
   `rop-finder-mcp`.
4. No workflow can publish one either: the only `cargo publish` invocations
   anywhere in `.github/workflows/` carry `--dry-run`, and `release.yml`'s
   job named `publish` creates a *GitHub release*, not a crates.io upload.

The rename was also verified rather than taken on trust. From outside the
workspace, `cargo info rf-core` returns a package (`rf-core`, the RuFi
framework) and `cargo info rf-cli` returns one too (RavenFabric's CLI);
`rf-scan`, `rf-classify`, `rf-chain`, `rf-cache`, `rf-mcp` and `rf-api` are
free. So the rename was **forced**, not stylistic: two of the old names
belong to other people.

---

## 2. The ledger

`docs/AUDIT-FINDINGS.md` contains 137 `### ID` sections with no duplicates.
`docs/REMEDIATION.md`'s six phases list 134 unique IDs under `*Closes:*` with
no overlaps, plus 3 in `## Deferred`. 134 + 3 = 137, and the set difference
in both directions is empty. The bookkeeping is exact; the question is what
"closed" bought.

| Landed in | Findings | of which partial |
|---|---:|---:|
| v0.1.1 | 33 | 3 |
| v0.2.0 | 47 | 2 |
| v0.3.0 | 21 | 3 |
| v0.4.0 | 9 | 2 |
| v0.5.0 | 16 | 3 |
| v1.0.0 | 8 | 2 |
| deferred | 3 | — |
| **total** | **137** | **15** |

**Closed** below means: the defect the finding describes is gone, and
something in the repository fails if it comes back. **Partial** means the
finding's central complaint is answered but a named part of its own text is
not, or the gate that holds it is weaker than the finding's exit criterion
asked for. Every partial is expanded in §3.


| Finding | Sev | Landed | Status | Title / what remains |
|---|---|---|---|---|
| `ANCH-01` | high | v0.2.0 | **partial** | ROPgadget's --align is not implemented at all in the CLI, and the x86 engine has no alignment stepping to implement it with — `--align` implemented; the byte-by-byte fallback is not |
| `ANCH-02` | high | v0.2.0 | closed | MCP server advertises --align but implements it as an address post-filter, silently under-reporting by ~53% |
| `ANCH-03` | medium | v0.2.0 | closed | ARM64 and SPARC SYS anchor tables are empty, so SYS gadget search returns nothing on AArch64 |
| `ANCH-04` | medium | v0.2.0 | closed | RISC-V 32-bit binaries are disassembled in RV64 mode, producing instruction text that does not exist on RV32 |
| `ANCH-05` | low | v0.2.0 | closed | Bundled capstone is 5.0.0 while the parity oracle uses 5.0.7, costing real gadgets on ARM and ARM64 |
| `ANCH-06` | low | v0.2.0 | closed | Windows ARMv7 PEs are detected as Thumb-only but still scanned with the A32 anchor tables unless --thumb is passed |
| `CHLX-01` | high | v0.5.0 | closed | Chain build fails on binaries where a chain is clearly constructible — no fallback strategy for any required gadget |
| `CHLX-02` | medium | v0.5.0 | closed | Syscall number built with 59 chained gadgets even when `pop rax ; ret` is already in the chain — 4x larger payload than necessary |
| `CHLX-03` | medium | v0.5.0 | closed | `--badbytes` turns chain generation into an unrecoverable hard failure with no alternative-address search |
| `CHLX-04` | medium | v0.5.0 | closed | No semantic verification of the generated chain; inherited padding gaps can emit a chain that cannot work |
| `CHLX-05` | medium | v0.5.0 | closed | `.data` fallback picks the first writable non-executable section, which on the project's own fixtures is `.tdata`/`.tbss` (TLS offsets) or `.init_array` (RELRO read-only) |
| `CHLX-06` | low | v0.1.1 | closed | README's description of the ROPgadget register regex bug is factually wrong, and the claimed "intended register set" is not what the code implements |
| `CHLX-07` | medium | v0.5.0 | **partial** | Only one Linux chain target exists — no mprotect, ret2libc, SROP, stager, or non-x86 chains — six Linux targets, all x86/x64; no ARM64/MIPS |
| `CHLX-08` | low | v0.5.0 | closed | PIE / ET_DYN binaries get link-time addresses in the chain with no warning, unlike the PE GUARD_CF path |
| `CHLX-09` | low | v0.5.0 | closed | Chain parity harness exercises only the default flag set, so the documented badbyte divergence is untested |
| `CHWIN-01` | high | v0.5.0 | closed | Stack-alignment pad is an inert data word that the preceding gadget's `ret` jumps to — chain crashes at 0x4141414141414141 instead of calling VirtualProtect |
| `CHWIN-02` | high | v0.5.0 | closed | lpflOldProtect defaults to the same address as the shellcode — VirtualProtect overwrites the first 4 bytes of the shellcode it just made RWX, then the chain returns there |
| `CHWIN-03` | high | v0.3.0 | closed | IAT "thunk" address is the IMAGE_IMPORT_BY_NAME record, not the FirstThunk slot — the IAT-dereference chain jumps to the ASCII of the function name |
| `CHWIN-04` | medium | v0.5.0 | closed | The alignment invariant is anchored to a hardcoded, unstated and usually-wrong assumption about the chain base, with no way for the user to correct it |
| `CHWIN-05` | medium | v0.5.0 | closed | PLAN §4b's emulator-harness exit criterion is unmet; no end-to-end execution test exists, and the existing tests only assert word kinds |
| `CHWIN-06` | medium | v0.5.0 | closed | The target API name is hardcoded to "VirtualProtect" with no CLI or MCP knob, making the IAT resolution path unreachable on every binary the project itself ships and analyzed |
| `CHWIN-07` | medium | v0.5.0 | closed | emit_api_call64 passes an empty already-set list to ChainBuilder::padding, so extra pops in the IAT gadgets destroy previously-populated argument registers |
| `CHWIN-08` | medium | v0.5.0 | **partial** | PLAN §6.2's hard parts are absent: no stack pivot, no multi-call composition, no export-table resolution, no x86 IAT, no shellcode staging, and no way to choose flNewProtect — all six capabilities ship; the x86 IAT path is not emulator-gated |
| `CHWIN-09` | low | v0.1.1 | closed | The advertised ring0 success-path demo (ntoskrnl.exe) is not a workable chain |
| `CLAIM-01` | high | v0.1.1 | closed | Phase 1 performance exit criterion is not met, and the README's headline speed claim is false |
| `CLAIM-02` | medium | v0.2.0 | closed | No benchmark suite exists at all — `benches/` is an empty directory and there is no criterion dependency |
| `CLAIM-03` | medium | v0.2.0 | closed | No fuzzing infrastructure exists; the Phase 1 'zero panics on 10K mutated binaries' criterion has no artifact |
| `CLAIM-04` | medium | v0.2.0 | **partial** | There is no CI of any kind, so every gate PLAN §9 defines as continuous is manual — CI exists as configuration and has never executed |
| `CLAIM-05` | medium | v0.1.1 | closed | The Phase 5 classification gate's 'independent' labeler is a re-implementation of the same rules, so the reported 1.0000 precision measures self-agreement, not accuracy |
| `CLAIM-06` | medium | v0.1.1 | **partial** | Phase 4b is marked done but two of its three exit criteria have no artifact: no emulator harness and no CET-marked PE — emulator harness landed; still no CET-marked PE fixture |
| `CLAIM-07` | medium | v1.0.0 | closed | The trie index — a Phase 1 deliverable and the basis of two PLAN features — does not exist anywhere in the codebase |
| `CLAIM-08` | medium | v0.2.0 | closed | Three of five shipped verification/benchmark harnesses are hardcoded to `rop-finder.exe`; two are unrunnable on macOS/Linux with no fallback |
| `CLAIM-09` | low | v0.1.1 | closed | ARM64 PAC awareness (PLAN §5.8, a Phase 5 roadmap item) is entirely absent while Phase 5 is marked done |
| `CLAIM-10` | low | v0.1.1 | closed | `--version` does not record the capstone version, and Cargo.lock — the other half of the same mitigation — is gitignored |
| `CLAIM-11` | low | v0.1.1 | **partial** | Parity is claimed on 'all 25 test-suite binaries' but the corpus contains 24; the ET_CORE fixture was dropped — claim corrected to 24; the ET_CORE loader path is still unmeasured |
| `CLI-01` | high | v0.2.0 | closed | --cache key omits --rawArch/--rawMode/--rawEndian: a cached scan is served for the wrong architecture |
| `CLI-02` | high | v0.2.0 | closed | --filter is a literal suffix match, not ROPgadget's anchored regex — it both under- and over-filters |
| `CLI-03` | high | v0.2.0 | closed | --all is not implemented: no way to disable duplicate removal, costing ~13x the usable gadgets in the bad-byte workflow |
| `CLI-04` | high | v0.2.0 | closed | --callPreceded is not implemented, and the engine cannot support it (no preceding-bytes capture) |
| `CLI-05` | high | v0.4.0 | closed | The entire non-gadget search surface is missing: --string, --opcode, --memstr |
| `CLI-06` | medium | v0.1.1 | closed | --help and --version exit with status 1 |
| `CLI-07` | medium | v0.2.0 | closed | A tampered --cache entry is trusted verbatim: arbitrary attacker-chosen gadget addresses and text are printed |
| `CLI-08` | medium | v0.2.0 | closed | --cache has no eviction, size cap, or TTL — unbounded disk growth in the user's home directory |
| `CLI-09` | medium | v0.4.0 | closed | --re is implemented in the MCP server but not exposed on the CLI |
| `CLI-10` | medium | v0.2.0 | closed | --align missing from the CLI; the MCP's version is a non-equivalent post-filter and parses its argument as hex |
| `CLI-11` | medium | v0.2.0 | closed | Human-readable output is not byte-for-byte compatible with ROPgadget — operand formatting, segment prefixes and ordering all differ |
| `CLI-12` | medium | v0.4.0 | closed | ROPgadget flag coverage: 14 of 26 flags unimplemented (full table) |
| `CLI-13` | low | v0.1.1 | closed | Missing --rawEndian is reported as 'Specify --rawArch' |
| `CLI-14` | low | v0.1.1 | closed | MANUAL.md presents a complete CLI reference with no statement of what ROPgadget functionality is absent |
| `CLS-01` | high | v0.3.0 | closed | The classification quality gate is circular: the "independent" labeler is a transliteration of the classifier |
| `CLS-02` | high | v0.3.0 | closed | `popfq ; ret` is classified as a stack-pivot |
| `CLS-03` | high | v0.3.0 | **partial** | The `dispatcher` label (R8) fires on 99.3% non-dispatchers and misses the COP form entirely — over-labeling fixed; precision rests on ONE predicted positive, recall 0.2857 |
| `CLS-04` | high | v0.3.0 | closed | Non-x86 heuristic path produces zero mem-read, mem-write and stack-pivot labels on MIPS, PowerPC and RISC-V |
| `CLS-05` | medium | v0.3.0 | closed | `regs_written` contains non-register junk (`{r4`, `#0x12e44`) on ARM and other non-x86 targets |
| `CLS-06` | medium | v0.3.0 | closed | The primary class — the `class` field users actually see — is never evaluated, and the labeled dataset mixes prediction with ground truth |
| `CLS-07` | medium | v0.3.0 | **partial** | The quality score is uncalibrated and degenerate: 92% of gadgets tie at 100, and `ret` scores the same as `pop rdi ; ret` — score reshaped; ranking quality is not evaluated at all |
| `CLS-08` | medium | v0.3.0 | closed | Classification is computed but not queryable: no filter by class, label, or written register in CLI or MCP |
| `CLS-09` | medium | v0.4.0 | closed | No register-transfer relations, stack delta, or clobber set — the semantic layer stops at eight coarse class names |
| `CLS-10` | medium | v0.3.0 | **partial** | Evaluation covers x86-64 only; the 32-bit path and all seven low-confidence architectures have zero measured precision — x86-32 and 4 arches measured; 6 of 14 `Arch` variants and the R13 text path are not |
| `CLS-11` | medium | v0.3.0 | closed | The "committed labeled set" is regenerated by the test itself, and the hand-verification claim has no artifact |
| `CLS-12` | low | v0.3.0 | closed | R6's arithmetic set omits division, xadd, bit-test and byte-swap while including flags-only compares |
| `CLS-13` | low | v0.3.0 | closed | `push rax ; ret` is classified `other`, and `ret 0x10` is not a stack adjustment while `add rsp, 0x10 ; ret` is |
| `CORE-01` | high | v0.2.0 | closed | Unsupported ELF e_machine silently falls back to x86 and emits thousands of fabricated gadgets |
| `CORE-02` | high | v0.2.0 | closed | Mach-O image_base is __PAGEZERO (always 0), so --base is broken and --info misreports the load address |
| `CORE-03` | medium | v0.2.0 | closed | Fat Mach-O: no way to select an architecture slice; modern x86_64+arm64 binaries yield ~70% fabricated gadgets |
| `CORE-04` | medium | v0.2.0 | closed | Section.size is clamped to file bytes instead of p_memsz/SizeOfRawData, changing --range trimming vs the oracle |
| `CORE-05` | low | v0.2.0 | closed | 64-bit fat Mach-O (FAT_MAGIC_64 / cafebabf) is detected but cannot be loaded |
| `CORE-06` | low | v0.2.0 | closed | Stripped ELF: PT_LOAD#n names are numbered from two different enumerations, and --section scans p_filesz where the default scan uses p_memsz |
| `CORE-07` | low | v0.2.0 | closed | x32-ABI ELFs (ELFCLASS32 + EM_X86_64) are decoded in a different mode than the oracle, undocumented |
| `CRIT-01` | high | v0.2.0 | closed | `--cfg-aware` returns zero gadgets on every binary in the repository, including ntoskrnl.exe where the MANUAL specifically recommends it; GUARD_CF is conflated with Intel CET/IBT and the promised scan-time warning never fires |
| `CRIT-02` | medium | v0.1.1 | closed | Both primary output modes panic (exit 101) when piped to `head`; the MANUAL misattributes this to Windows, offers a Windows-only workaround, and its own UC3 example triggers it |
| `CRIT-03` | medium | v0.3.0 | closed | The documented JSON record schema does not match what is emitted: `section` appears only with `--section`, `delay_slot` is never emitted by any interface, and the vaddr format differs |
| `CRIT-04` | low | v0.1.1 | closed | MANUAL states the default output is sorted by address; it is sorted alphabetically by gadget text, identically to ROPgadget |
| `ECO-01` | high | v0.4.0 | closed | No constraint-based / register-aware gadget search anywhere in the product |
| `ECO-02` | high | v0.4.0 | closed | No text-, regex-, opcode- or string-search: the CLI cannot search at all, and is behind its own MCP server |
| `ECO-03` | high | v0.2.0 | closed | No `--callPreceded` filter — the standard mitigation-aware gadget filter is missing |
| `ECO-04` | high | v0.5.0 | **partial** | Chain generation is two frozen recipes, not a synthesis engine — no goal-directed chains, no generic syscall, no ARM chains — synthesis and five new targets ship; no non-x86 chain |
| `ECO-05` | medium | v0.3.0 | closed | Register read/write data is empty on 8 of the 10 supported architectures (capstone driven without detail mode) |
| `ECO-06` | medium | v0.4.0 | **partial** | `--info` reports no exploit mitigations and no ELF symbols — it is not a `checksec`/`rabin2 -I` replacement — `checksec` itself was never run; ground truth is an independent parse |
| `ECO-07` | medium | DEFERRED | **deferred** | No symbolic or emulated gadget semantics — classification is purely syntactic, with no rsp delta and no verification — deferred by plan; the useful 80% landed as CLS-09 + the emulator harness |
| `ECO-08` | medium | DEFERRED | **deferred** | Single-binary only: no multi-module / libc workflow, and no libc-database or one_gadget integration — deferred by plan; unchanged |
| `ECO-09` | medium | v0.4.0 | **partial** | Output formats: no JSON-lines/CSV/raw, monolithic JSON array, and the documented "raw bytes" chain output is unreachable — all five formats ship; `jsonl` does not truly stream |
| `ECO-10` | medium | v1.0.0 | **partial** | No library/API story: crates are unpublished path-only deps, no FFI, no Python binding — the Rust library story is delivered; the C ABI and Python binding are not |
| `ECO-11` | low | DEFERRED | **deferred** | No interactive console and no RE-tool integrations (r2/rizin, Ghidra, IDA, gdb/pwndbg) — PARTLY DELIVERED ANYWAY: `--console` ships. RE-tool integrations do not, and the plan's own closing action was not performed |
| `ECO-12` | low | v0.4.0 | closed | No stack-pivot-oriented search, despite the classifier already computing the label |
| `ENG-01` | high | v0.1.1 | closed | No CI configuration of any kind exists |
| `ENG-02` | high | v0.1.1 | closed | Cargo.lock is gitignored in a binary-producing workspace, while the parity-critical x86 formatter is left unpinned |
| `ENG-03` | high | v0.1.1 | closed | No LICENSE file anywhere in the Rust tree, and no legally adequate attribution to ROPgadget |
| `ENG-04` | high | v0.2.0 | closed | Parity — the project's central claim — is measured by a script that cannot run from a clone and never fails |
| `ENG-05` | high | v0.2.0 | closed | `--cache` returns wrong results for `--rawArch`/`--rawMode` because the cache key omits them |
| `ENG-06` | medium | v0.1.1 | closed | `--version` and `--help` exit with status 1, breaking the project's own build script |
| `ENG-07` | medium | v0.1.1 | closed | Declared MSRV of 1.80 is false — the dependency graph requires rustc >= 1.88 — and is never tested |
| `ENG-08` | medium | v1.0.0 | **partial** | None of the crates can actually be published; the library story is aspirational — publishable and dry-run clean; packaged tests still fail, no CHANGELOG, `repository` is a placeholder |
| `ENG-09` | medium | v0.1.1 | closed | 41 MB of prebuilt binaries committed to git with no build recipe, no checksums, non-executable mode, and a leaked developer path |
| `ENG-10` | medium | v0.2.0 | closed | No property-based testing, fuzzing, or corpus anywhere, in a tool whose entire job is parsing hostile binaries |
| `ENG-11` | medium | v0.1.1 | closed | No dependency auditing tooling for a 141-package graph with 23 build scripts and 44 MB of vendored C |
| `ENG-12` | medium | v0.1.1 | closed | 24 fixtures are byte-identical redistributions of third-party proprietary and GPL binaries under a blanket BSD-2 declaration |
| `ENG-13` | medium | v0.1.1 | closed | The 1 GB ROP-Finder.7z is a raw snapshot of a dirty working tree, 95.6% cargo build artifacts |
| `MCP-01` | high | v0.1.1 | **partial** | TOCTOU race between confine_path() and the file read defeats path confinement entirely (arbitrary file read) — fix in place; its own rename-race harness has never executed anywhere |
| `MCP-02` | high | v0.1.1 | closed | The server process cwd is always in the allowlist and cannot be removed, so `--allow-dir` does not actually confine anything |
| `MCP-03` | high | v0.3.0 | closed | Unbounded `--depth` plus a non-cancellable worker: one request pins a CPU and consumes tens of GB after the client already got its timeout error |
| `MCP-04` | medium | v0.2.0 | closed | On-disk cache entries are trusted verbatim — no integrity check, deterministic filenames, 0644 — so results can be silently poisoned |
| `MCP-05` | medium | v0.3.0 | closed | In-memory scan cache has no size limit, eviction or TTL — memory grows monotonically for the life of the server |
| `MCP-06` | medium | v0.3.0 | closed | get_binary_info has no timeout and no cap, runs inline on the async runtime, and no tool limits input file size |
| `MCP-07` | medium | v0.1.1 | closed | Error-code taxonomy is a whole-filesystem existence oracle outside the allowlist |
| `MCP-08` | medium | v0.1.1 | closed | README and MANUAL state three security guarantees the code does not provide |
| `MCP-09` | low | v0.3.0 | closed | No audit trail for a tool the project itself classifies as dual-use |
| `PERF-01` | high | v0.1.1 | closed | Headline ">=10x faster on x86/x64" is not met: measured 6.0x |
| `PERF-02` | high | v0.1.1 | closed | Non-x86 arches reach 1.4-1.9x, not the ">=4x" Phase-1 exit criterion |
| `PERF-03` | high | v1.0.0 | closed | The "per-start decode cache" has a 0.8% hit rate and is a net slowdown on x86 |
| `PERF-04` | high | v1.0.0 | closed | Rayon partitioning at (region x anchor) granularity gives 1.2-1.9x on 16 cores |
| `PERF-05` | high | v0.2.0 | closed | No streaming or bounded-memory mode: RSS is ~117 bytes per byte of scanned code (1.08 GB on a 9.3 MB input) |
| `PERF-06` | high | v0.3.0 | closed | MCP per-request timeout cannot cancel the scan it is timing out |
| `PERF-07` | medium | v0.1.1 | closed | 55% of x86-64 wall clock is 45,651 unbuffered println! syscalls |
| `PERF-08` | medium | v0.2.0 | closed | No criterion benchmarks exist; the only benchmark harness is Windows-only and crashes here |
| `PERF-09` | medium | v1.0.0 | closed | Capstone path re-decodes a window per (hit, depth); a single resumable region decode is 2.3-3.3x cheaper |
| `PERF-10` | medium | v1.0.0 | closed | The suffix-trie index was never built; dedup allocates 3 extra strings per gadget instead |
| `PERF-11` | low | v1.0.0 | closed | Executable bytes are copied at least three times before scanning |
| `PERF-12` | low | v0.2.0 | closed | --cache grows without bound: 5.3 MB per scan configuration, no eviction and no purge |
| `ROB-01` | high | v0.1.1 | closed | Untrusted PE import DLL name is written unescaped into the generated Python exploit script (code injection) |
| `ROB-02` | high | v0.2.0 | closed | Memory-exhaustion DoS: a 382 KB malformed PE drives 19.8 GB RSS with no special flags |
| `ROB-03` | medium | v0.1.1 | closed | Panic (exit 101) on broken pipe - `rop-finder --binary x \| head` always crashes |
| `ROB-04` | medium | v0.2.0 | closed | Panic on a corrupt/poisoned scan cache file - non-ASCII in the `bytes` field slices a UTF-8 char in half |
| `ROB-05` | medium | v0.1.1 | closed | Every windows-virtualprotect chain script is invalid Python and cannot be run |
| `ROB-06` | medium | v0.2.0 | closed | Input file is read entirely into memory with no size cap - `--binary /dev/zero` allocates until the OS kills it |
| `ROB-07` | low | v0.3.0 | closed | MCP server's in-memory scan cache is never evicted |
| `ROB-08` | medium | v0.2.0 | closed | The fuzzing infrastructure the plan committed to does not exist - and neither does any CI |
| `SCAN-01` | high | v0.2.0 | closed | --filter implements neither of ROPgadget's semantics: no regex support, and suffix matching rejects gadgets ROPgadget keeps |
| `SCAN-02` | high | v0.2.0 | closed | Every `notrack jmp` / `notrack call` gadget is silently lost to a dedup collision |
| `SCAN-03` | high | v0.2.0 | closed | `repz ret` is rendered as `rep ret`, so the canonical AMD return gadget is unfindable by name |
| `SCAN-04` | medium | v0.2.0 | closed | Segment overrides on memory operands are wrongly stripped; the code comment asserts a capstone behavior that does not exist |
| `SCAN-05` | medium | v0.2.0 | closed | --align is not implemented in the engine; the MCP server's post-filter is not equivalent and loses ~half the gadgets |
| `SCAN-06` | medium | v0.2.0 | closed | Far branches (ljmp/lcall) are accepted as "jmp"/"call" that ROPgadget rejects, and mid-gadget lcall is rejected that ROPgadget accepts |
| `SCAN-07` | medium | v0.2.0 | closed | --all (disable dedup) and --callPreceded are absent from the engine, with no `prev` bytes captured |
| `SCAN-08` | medium | v0.1.1 | closed | 15-29% of x86/x64 gadget texts differ from ROPgadget's; the README quantifies divergence as "~0.05-0.2% of gadgets" |
| `SCAN-09` | low | v0.2.0 | closed | `mov cs, r/m16` gadgets are lost (iced-x86 rejects the encoding capstone accepts) |
| `SCAN-10` | low | v0.2.0 | closed | --range is applied only once; ROPgadget also re-filters the final, --offset-shifted addresses |

---

## 3. The fifteen that are not fully closed

Ordered by how much a user would care.

### `ECO-10` — the library story is Rust-only

The finding's own text names three things: unpublishable path-only crates, no
stated semver policy, and **"no C ABI surface and no Python binding, so the
enormous pwntools user base cannot call rop-finder from an exploit script"**.
The first two are delivered — eight crates dry-run clean with full metadata,
`docs/API-STABILITY.md` states what semver covers and what it deliberately
does not. The third is not delivered and was not attempted:
`grep -rn "pyo3\|cbindgen\|crate-type" crates/ --include=Cargo.toml --include=*.rs`
returns nothing, so no crate declares a `cdylib` or `staticlib` target and
there is no exported C ABI. (The single `extern "C"` in the workspace is an
*inbound* `mkfifo` declaration inside a `#[cfg(unix)]` test in
`crates/rf-mcp/src/confine.rs` — the opposite direction.)

`docs/REMEDIATION.md`'s Phase 6 workstream text quietly re-scoped `ECO-10` to
metadata plus API docs and never mentions the binding. That re-scoping is
never flagged as a reduction anywhere in the plan. **The user the finding
identifies as most affected — a Python exploit developer — is exactly the
user this release does not serve.** They still have to shell out to the CLI
and parse `--json`, which is the impact `ECO-10` describes.

### `ENG-08` — publishable, but the published crate still cannot test itself

Delivered: versioned internal deps, full metadata on all eight published
packages (no `manifest has no description/repository` warning on any dry
run), `#![warn(missing_docs)]` on all six library crates enforced by
`clippy -D warnings`, `[package.metadata.docs.rs]` on all eight, 21 doctests
where there were zero, `rf-mcp` off the binary crate, and git tags.

Not delivered, and each is named in `ENG-08`'s own text:

* **The packaged crate's test suite still cannot run.** Measured, not
  assumed: `cd target/package/rop-finder-core-1.0.0 && cargo test` gives
  `test result: FAILED. 33 passed; 43 failed`, every failure on
  `fixture should exist`. `docs/PUBLISHING.md` §5 states this and explains
  that the corpus is not redistributable, which is true — but the fix
  `ENG-08` is asking for is for those tests to *skip* rather than *fail*
  when the corpus is absent, and that is a change in `src/` nobody made.
  (There is a real argument on the other side: a test that skips when its
  data is missing is a test that goes green when CI loses the corpus. The
  right answer is probably "skip loudly outside the repository, fail inside
  it", and nobody has written it.)
* **No CHANGELOG.** `ENG-08` lists "no CHANGELOG" among the reasons there is
  no semver discipline to inherit. There still is none. The release commit
  messages are the changelog, and they are not in the tarball.
* **`repository` was `https://placeholder.invalid/rop-finder`; it is now
  `https://github.com/dbugom/rop-finder` (set 2026-09-05).** This working
  copy has no git remote (`git remote -v` is empty; `.git/config` has no
  `[remote]` section), so there is no honest URL to put there and inventing a
  `github.com` path would point crates.io and docs.rs at a repository that
  either does not exist or belongs to someone else. `.invalid` is
  RFC 2606-reserved so it cannot resolve to a stranger's property. This is
  the one item genuinely blocked on a human, it is step 1 of
  `docs/PUBLISHING.md` §4, and it does not block the dry run.
* **Nothing has been published.** The dry runs resolve sibling crates through
  `.cargo/publish-dry-run.toml`, a `[patch.crates-io]` bootstrap, because
  before the first upload `rop-finder-core = "1.0.0"` does not exist on
  crates.io and cargo 1.89 offers no stable alternative (`--workspace` on
  `cargo publish` is unstable). The check that cannot be made before
  uploading — that the requirement resolves against the real index — has not
  been made.

### `CLAIM-04` / CI — the configuration exists; it has never executed

`ENG-01` ("no CI configuration of any kind exists") is closed: there are two
workflows and eleven jobs. `CLAIM-04` is not, because its complaint was that
"every gate PLAN §9 defines as continuous is manual", and **every gate is
still manual.** There is no git remote, so neither
`.github/workflows/ci.yml` nor `.github/workflows/release.yml` has ever run,
not once, on any commit. Everything asserted about CI in the five release
commit messages is an assertion about YAML.

Concretely, this means the following have never been observed to work:
the ubuntu / macos-14 / macos-13 / windows-2022 test matrix; the MSRV job
(though see below); the parity job's oracle checkout and its
freeze-a-CI-baseline dance; the cross-environment bench baseline; the fuzz
job; and the entire release pipeline including macOS codesigning and
notarization.

One of those was closed by hand during this pass rather than left as a
claim. The MSRV job's exact command was executed locally:

```
$ msrv=$(sed -n 's/^rust-version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -1)   # -> 1.88.0
$ cargo +1.88.0 check --workspace --all-targets --locked
Finished `dev` profile [unoptimized + debuginfo] target(s) in 21.21s        # exit 0
```

So the declared MSRV of 1.88 is now a number that has been compiled against,
on this host, at this commit — which is what `ENG-07` asked for. The *job*
still has never run.

### `MCP-01` — the fix is real; its harness has never executed

`MCP-01` was an arbitrary-file-read: a TOCTOU between `confine_path()` and
the open. The fix is in place and the Windows half of the confinement
(re-checking `GetFinalPathNameByHandleW` on the opened HANDLE) is unit-tested
and passes here. But the harness that reproduces the actual attack —
`crates/rf-mcp/tests/confine_race.rs`, which swaps a name between a hardlink
and an out-of-allowlist symlink while firing 400 `find_gadgets` calls and
asserts ZERO escapes against a pre-fix baseline of 323 of 400 — begins with
`#![cfg(unix)]`. It compiles to **zero tests on this host and has never been
executed on this machine**, and since CI has never run, it has not been
executed anywhere. The 323-of-400 baseline it cites is from the audit, not
from a run in this repository.

This is the single largest gap between "a finding is closed" and "the
evidence for closing it was produced here".

### `ECO-06` — checksec was never run

The exit criterion in `docs/REMEDIATION.md` is literally *"`--info`
mitigation output matches `checksec` on every Linux fixture … field for
field"*. `checksec` is a Linux shell script and this is a Windows host, so
what was actually done (and stated openly in
`crates/rf-core/tests/mitigations.rs`'s module doc) is that the expected
table was derived independently with CPython + pyelftools 0.33 +
pefile 2024.8.26 + hand-rolled `struct` parses, with four documented
divergences from what `checksec.sh` would print. That is a good substitute
and it is genuinely independent of the code under test. It is not the
criterion as written, and the criterion as written has never been run.

### `CLS-03` and `CLS-10` — the classifier's measured accuracy is narrower than the headline

`docs/classifier-eval.md` is unusually honest about this and says so itself;
it is repeated here because a reader of the README will not get there.

* **Dispatcher precision 1.0000 is vacuous.** It rests on **one** predicted
  positive across the whole 438-gadget corpus (tp=1, fp=0). Its 95%
  Clopper-Pearson lower bound is 0.025. Recall is 0.2857 — 2 of 7
  hand-identified dispatchers. `CLS-03`'s complaint (99.3% false positives)
  is genuinely fixed; the classifier now labels almost nothing instead.
* **The text-fallback path has zero measured accuracy.** `low_confidence` was
  false for all 437 scored records, so `crates/rf-classify/src/text.rs` — the
  heuristic that runs when no capstone detail mode resolves — was never
  exercised by the evaluation. `eval.rs` asserts that count stays at zero, so
  the *absence* of measurement is itself gated, which is the right design;
  the path is still unmeasured.
* **Six of fourteen `Arch` variants have no corpus entry at all**
  (`ArmThumb`, `Mips64`, `Ppc64`, `Sparc64`, `SparcV9`, `RiscV32`). Of the
  ten "supported architectures", eight are measured.
* **Ranking is not evaluated at all.** `quality_score`, `usability` and
  `rank_key` have no ground truth in this corpus. `CLS-07` reshaped a
  degenerate score into a better one, but "better" here is a design argument,
  not a measurement.

### `CLAIM-06` / `CHWIN-08` — the Windows chain evidence has two holes

The emulator harness exists and every advertised Windows chain is executed
(`CHWIN 8/8`, `CHWIN-08 5/5` today). Two things it does not cover:

* **There is still no CET-marked PE fixture.** `--cfg-aware` has never been
  run against a real hardened binary. Measured across all 24 fixtures today,
  none contains an `endbr64` byte sequence, and every invocation prints the
  warning `--cfg-aware: this binary contains no endbr32/endbr64 landing pads,
  so Intel CET/IBT is not enforced on it and the flag constrains nothing`.
  That warning is `CRIT-01`'s promised behaviour and it fires correctly; the
  filter's behaviour on a binary that *does* have landing pads is untested
  outside synthetic unit tests.
* **The x86 IAT strategy is unit-tested but not emulator-gated** (stated in
  the v0.5.0 commit message and still true).

### `ECO-04` / `CHLX-07` — chains are x86/x64 only

Six Linux targets and one Windows target ship, all x86/x64. ARM64 and MIPS
chain targets are not shipped, deliberately, because `tests/emulate.py` has
no non-x86 half and the release rule was that a target is not advertised
until it executes. Verified today:

```
$ rop-finder --binary tests/fixtures/elf-ARM64-bash --ropchain --chain linux-execve
[Error] arch arm64 / format elf not supported yet for the rop chain generation
$ rop-finder --binary tests/fixtures/elf-Mips-Defcon-20-pwn100 --ropchain --chain linux-execve
[Error] arch mips32 / format elf not supported yet for the rop chain generation
```

The refusal is clear and the absence is not advertised anywhere as present.
`ECO-04`'s title, however, is *"no goal-directed chains, no generic syscall,
**no ARM chains**"* — two of those three are delivered and one is not.

### `ANCH-01`, `ECO-09`, `CLAIM-11` — smaller, named, bounded

* **`ANCH-01`.** `--align` is implemented in the engine (not as a post-filter),
  but the byte-by-byte alignment *fallback* is not. `flag_conformance.py`
  carries it as a declared divergence (`[ANCH-01/align-fallback] 2 hits`), so
  it is bounded and cannot grow quietly.
* **`ECO-09`.** All five formats ship and the raw chain output is reachable,
  but `--format jsonl` does not truly stream: `scan_binary_into` still buffers
  `Vec<Vec<Gadget>>`, so the first record lands after decoding and the
  bounded-RSS half of the criterion passed by 0.93%. A user who chose `jsonl`
  to get early records does not get them.
* **`CLAIM-11`.** The false "25 binaries" claim is corrected everywhere and
  the doc-claims gate holds the number at 24. The 25th fixture — ROPgadget's
  `core`, an ET_CORE dump with no section headers — was never added, so **the
  ET_CORE loader path remains completely unmeasured**. README says this
  plainly.

---

## 4. The three deferred — and one that was not really deferred

`ECO-07` (symbolic/emulated per-gadget semantics) and `ECO-08` (multi-module
/ libc workflows, libc-database, one_gadget) are deferred with written
reasons in `docs/REMEDIATION.md`. Both reasons hold up: `ECO-07`'s
practically useful part did land as `CLS-09`'s stack delta / clobber sets /
register-transfer relations plus the v0.5 emulator harness, and `ECO-08` is
genuinely additive.

`ECO-11` is a different case and the plan's own bookkeeping is wrong about
it.

* The interactive console **shipped**. `crates/rf-cli/src/console.rs` exists,
  `--console` is a documented flag, and it mirrors ROPgadget's `cmd.Cmd` REPL
  down to the `settings`/`setted` messages. It arrived through the flag-
  conformance work (`CLI-12`), not through `ECO-11`. So half of the finding
  is delivered while the plan still lists it as wholly deferred.
* The RE-tool integrations (r2/rizin, Ghidra, IDA, gdb/pwndbg) are absent, as
  planned.
* **The plan's stated closing action was not performed.**
  `docs/REMEDIATION.md` says: *"Close the finding by stating plainly in
  MANUAL.md that they are not planned, so a reader is not left guessing."*
  `grep -in "radare\|rizin\|ghidra\|pwndbg\|not planned" MANUAL.md` finds
  nothing of the sort. A reader is left guessing, which is exactly the
  outcome the deferral undertook to avoid.

---

## 5. Performance, and the one gate that is not a gate

The v0.5.0 speedup figures re-measured clean today. `tests/doc_claims.py`
(12 claims, 0 failed, **0 warned**) recomputes the documented table from
`tests/parity-baseline/*.json` and, in the `LIVE-SPEEDUP` claim, times both
tools live on this machine: `elf-Linux-x86` 15.8x and 16.4x on two separate
runs, `elf-ARM64-bash` 9.5x and 9.6x, against criteria of 10x and 4x. (It is
wall clock, so it moves; both runs clear both criteria.) That measurement is sound and the README's
table stands.

**The criterion bench gate is a different story. It failed four times today,
with a different answer each time, and none of the failures was real.**

| run | where | `check_regression.py` verdict |
|---|---|---|
| A | this repo's `target/`, after a full `cargo bench` | FAIL — `decode/serial/arm64` 13.6% slower, `post_process/dedup/pe-x64` 14.3% slower |
| B | same, the two offenders re-run in isolation | FAIL — `decode/serial/arm64` 16.1% slower; `post_process/dedup/pe-x64` back inside the band at 4.7% |
| C | a fresh copy of the same source, fresh target, full suite (machine busy) | FAIL — `post_process/dedup/pe-x64` 43.3%, `post_process/sort_only/pe-x64` 44.1%, `scan/parallel/pe-x64` 15.8%; `decode/serial/arm64` back inside the band at **1.024x** |
| D | same fresh tree, full suite, machine quiet | FAIL — `post_process/dedup/pe-x64` 52.3%, `post_process/sort_only/pe-x64` 44.1% |

Every one of those was chased to ground rather than re-recorded, and **the
source is not responsible for any of them.**

First, the source. `git diff -- crates/rf-scan/src` and
`crates/rf-core/src`, with comment lines filtered out, contain *exactly two
changes between them*: a `#![warn(missing_docs)]` attribute and a rustfmt
reflow of two enum variants whose fields gained doc comments. Not one
executable line of the scan engine or the loader changed in this release.
`git diff Cargo.lock` changes only this workspace's own package names and
versions — no third-party dependency moved, and capstone is still `=0.14.0`.
The `[profile.release]` block (`lto = true`, `codegen-units = 1`) is identical
in both trees.

Second, the A/B. The committed v0.5.0 tree (`git archive HEAD`) and the
v1.0.0 working tree were each built in a **fresh** target directory and
benchmarked alternately on this machine:

| benchmark | v1.0.0 fresh target | v0.5.0 fresh target | v1.0.0 in this repo's `target/` |
|---|---|---|---|
| `decode/serial/arm64` | 355.16 / 353.89 ms | 354.50 / 354.02 ms | 392.34 / 393.37 ms |
| `post_process/dedup/pe-x64` | 4.575 / 4.372 ms | 4.536 / 4.439 ms | — |
| `post_process/sort_only/pe-x64` | 2.989 / 3.044 ms | 3.153 / 3.043 ms | — |

v1.0.0 and v0.5.0 are indistinguishable. The two conclusions:

* **`decode/serial/arm64`'s 13-16% "regression" belongs to this working
  copy's long-lived `target/` directory**, which has by now absorbed a debug
  build, a release build, an MSRV build under rustc 1.88, eight
  `cargo publish` verification builds and five mutation rebuilds. Same source
  in a clean target: 354 ms, same as v0.5.0.
* **The `pe-x64` post-process "regressions" of 43-52% are suite
  contamination.** Those two are the smallest benchmarks in the suite (3-4 ms
  medians) and they follow much heavier ones. Run on their own they measure
  4.4-4.6 ms and 3.0-3.2 ms in *both* trees, against baselines of 4.061 and
  3.247 ms.

**v1.0.0 did not regress the engine. Nothing was traded for the
restructure.** That is the good news, and it is well supported.

The uncomfortable half is about the instrument. `check_regression.py` with
its committed developer baseline and a 10% band produced four different
failure sets in four runs on the machine that recorded the baseline, and
every one of them was an artifact. A gate that cries wolf four times out of
four is not a gate; it is a report that people will learn to skip.
`.github/workflows/ci.yml` already half-knows this — it records a fresh
per-runner baseline, gates on *that*, and runs the committed-baseline
comparison with `|| true`. But `docs/measured-2026-09.md` presents
`crates/rf-bench/baseline.json` as a ratchet, and today it is not reproducible
in the tree that recorded it.

The baseline was deliberately **not** re-recorded. Re-recording a baseline to
make a gate green is the precise failure this whole exercise exists to
prevent, and the honest fix is elsewhere: raise the sample counts on the
sub-5 ms benchmarks (or drop them), and stop presenting a
developer-machine baseline as an absolute ratchet.

`docs/measured-2026-09.md` now carries the same finding beside the baseline
table, so a reader who only opens that file is not misled.

---

## 6. What a reader should not conclude from this document

Everything in §1 is real and was run today. That is not the same as the
product being proved. Read the following as the list of places where the
evidence is thinner than the summary implies.

1. **"CI is green."** CI has never run. There is no git remote; neither
   workflow has ever executed on any commit, on any runner, once. Every
   green thing in this document was run by hand on one Windows machine.
   The ubuntu/macOS legs of the test matrix — including every `#[cfg(unix)]`
   test — have never executed anywhere.
2. **"The MCP path-confinement fix is proven."** Its harness
   (`confine_race.rs`, `MCP-01`) is `#![cfg(unix)]` and has never executed on
   this host, and CI has never run, so it has never executed at all. What is
   proven here is the Windows half plus unit tests.
3. **"The MSRV is tested."** It was compiled today, by hand, on Windows, at
   MSRV 1.88.0. The MSRV *job* has never run, and the MSRV has never been
   compiled on Linux or macOS.
4. **"`--info` matches checksec."** `checksec` was never executed. The
   comparison is against an independent re-parse of the same headers, with
   four documented divergences.
5. **"rop-finder builds ROP chains."** It builds x86 and x64 chains.
   **ARM64 and MIPS chain targets do not exist** and the tool refuses them by
   name. If your target is ARM64, this tool finds gadgets and does not build
   chains.
6. **"`--badbytes` works."** `--badbytes 00` on any 64-bit target returns
   **zero gadgets**, exit 0, with no explanation — because every address
   below 2^48 packed little-endian contains a `00` byte, so the constraint is
   unsatisfiable by construction. That matches ROPgadget (it is why parity
   holds), but a user who has not thought it through gets a silent empty
   result and no hint that the question was impossible.
7. **"The classifier is accurate."** Its *dispatcher* precision of 1.0000 is
   one true positive and nothing else; its recall there is 0.2857. Its
   text-fallback path has **zero** measured accuracy. Six of fourteen
   architectures have no evaluation corpus. Ranking is not evaluated at all.
8. **"The gadget set is byte-identical to ROPgadget."** 99.9950% of the
   oracle's gadgets are reproduced and `ours-only` is 0 everywhere, which is
   strong. 38 reference gadgets are still missing and 68 rendered texts still
   differ. The parity harness also never passes `--cache` or `--cfg-aware`,
   so two shipped features are outside its reach entirely.
9. **"The benchmarks prove the speedup held."** They do not, in either
   direction. `check_regression.py` against the committed baseline reported
   `BENCH GATE: FAIL` on all four runs made today and named a *different*
   set of regressions each time; every one turned out to be an artifact of
   the target directory or of suite ordering (§5). The gate cannot currently
   distinguish a real 10% regression from run-to-run variance on the machine
   that recorded its baseline, and the baseline was deliberately not
   re-recorded. What *is* sound is the controlled A/B in §5 — v1.0.0 and
   v0.5.0 are indistinguishable — and the README's speedup table, which comes
   from `tests/doc_claims.py`, a different and more robust measurement.
10. **"The crates are on crates.io."** They are not. Nothing has been
    uploaded (§1.5). Both `cargo install rop-finder` lines in the README
    fail today, and the README says so. The dry runs resolve internal deps
    through a `[patch.crates-io]` bootstrap, so the one thing that cannot be
    checked before the first upload — that `rop-finder-core = "1.0.0"`
    resolves against the real index — has not been checked.
11. **"A published crate ships a working test suite."** It does not:
    `cargo test` inside `target/package/rop-finder-core-1.0.0` is
    `33 passed; 43 failed`.
12. **"`dist/` binaries are verified and notarized."** `dist/` contains a
    README and nothing else. The release workflow that would codesign and
    notarize macOS artifacts has never run, so no signed or notarized
    artifact of this project has ever existed.
13. **"Every waiver in the parity gate is load-bearing."** The `ANCH-03`
    known-divergence entry currently excuses zero gadgets on every fixture.
    `tests/parity.py` prints it as STALE and passes anyway.
14. **"The MCP response fits the token budget."** The *rendered* figure does
    (4,972 of 10,000). The *wire* figure is 10,692 and has been over budget
    since v0.3.0, because the payload is sent twice. That advisory is printed
    on every run and gated by nothing.
15. **"The v1.0.0 restructure is proved behaviour-preserving by the mutation
    experiments."** It is not: none of the five reverts touches the moved
    code (§1.3). The evidence for the move is the eight gates and the test
    count, not a revert-and-observe-red experiment.
16. **"137 findings closed means the product is complete."** The audit is one
    reviewer's list from one point in time. Nothing in these six releases
    searched for defects the audit did not already name. Where a phase's
    workstream text is narrower than the finding it claims to close — `ECO-10`
    is the clearest case — the ledger inherits the narrower scope, and this
    document is the only place that says so.

### Two documentation defects found during this pass

Both were in `MANUAL.md` and are corrected in this commit; they are listed
because they had survived five releases of documentation review.

* `MANUAL.md` said `--cfg-aware` *"returns zero gadgets on every fixture
  here"* and that *"the flag has no way to tell you it did nothing useful"*.
  Both were false against the shipped build: measured across the corpus today
  it returns 2,097 on `pe-x64-cmd-v6.1.7601`, 8,389 on `elf-Linux-x64` and a
  non-zero count on 21 of 24 fixtures, and it prints an explicit warning on
  every one of them.
* `MANUAL.md` still said the `--cfg-aware` recommendation was *"withdrawn
  until that is fixed in v0.2"* — three releases after it was fixed, and two
  paragraphs from a line that says it was fixed.

`README.md` also described release artifacts that *"carry `SHA256SUMS` and
are notarized on macOS"* in the present tense, for a workflow that has never
run; corrected to say what is configured rather than what exists.

---

## 7. Is v1.0.0 defensible?

Yes, with the caveats above stated where a user will see them — which, after
this pass, they are: the README carries the not-yet-published caveat, the
`--cfg-aware` and chain-target limits are in MANUAL and in the tool's own
refusals, and `docs/classifier-eval.md`, `docs/PUBLISHING.md` and this file
carry the rest.

What would make it more defensible, in order:

1. Run CI once. Nothing else in this list matters as much. Eleven jobs and a
   release pipeline have never executed; the `#[cfg(unix)]` half of the test
   suite, including the `MCP-01` race harness, has never run anywhere.
2. Set `repository` to a real URL before the first upload.
3. Make the fixture-reading tests skip-with-a-loud-message outside the
   repository, so a published crate can run its own suite.
4. Write a CHANGELOG.
5. Either build the PyO3 wrapper `ECO-10` asks for, or amend `ECO-10`'s
   status to say plainly that its Python half was descoped.

---

## Addendum, 2026-09-04

The qualification recorded above under "what I would not ship without" item 1 has been
partly discharged: the Unix confinement suite, including MCP-01's `confine_race`
harness, was executed on Linux and passed. See [linux-verification-2026-09-04.md](linux-verification-2026-09-04.md).
Items 2 (the repository URL) and 3 (fixture tests that skip-loudly outside the repo)
stand, and the full-workspace Linux run did not complete.
