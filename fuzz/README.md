# fuzz/ — hostile-input testing for rop-finder

Closes `ROB-08`, `CLAIM-03`, `ENG-10`.

rop-finder's job is parsing binaries you do not trust, and `rf-mcp` exposes
that parser to an LLM host over stdio. Until this directory existed there was
no fuzzer, no corpus, and no CI gate: `grep -ri fuzz` over the workspace
returned one hit, a README line saying "fuzz corpus pending". PLAN.md:226
made *"zero panics on 10K mutated binaries"* a Phase 1 exit criterion and
nothing ever produced that number.

There are **two** harnesses here, and they are not redundant:

| | what it is | where it runs | what it proves |
|---|---|---|---|
| `fuzz_targets/` | seven cargo-fuzz / libFuzzer targets | nightly toolchain + a libFuzzer-capable target (Linux/macOS always; Windows with one extra step, see below) | coverage-guided search — finds inputs nobody thought of |
| `smoke/` | `rf-smoke`, a deterministic seeded mutation harness | **stable Rust, every platform, no extra tooling** | a reproducible, quotable "N mutants, zero panics" number, and a bisecting parent that survives an OOM |

The smoke harness exists because a fuzz target that a contributor cannot run
is not a gate. It is also the thing that produces the PLAN exit-criterion
artifact, because every mutant has an integer name: `rf-smoke mutant 4711`
regenerates mutant 4711 byte for byte on any machine, forever.

---

## 1. The part that runs everywhere: `rf-smoke`

```sh
# 10,000 deterministic mutants of the 24 fixtures through Binary::load,
# info_bytes and scan_bytes. Exits non-zero if anything panics.
cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- run --count 10000

# Reproduce one mutant exactly (writes it to fuzz/artifacts/smoke/).
cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- mutant 4711

# (Re)build the committed corpus from tests/fixtures.
cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- seed-corpus

# Build and measure the ROB-02 amplification witness (see section 6).
cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- amplify --format pe --clones 2000
```

`fuzz/smoke` is its own cargo workspace (a bare `[workspace]` stanza in its
manifest), so it never enters the root `cargo build --workspace` and the root
`Cargo.toml` needs no edit.

### What it does

* **Mutants are addressed by index.** `Rng::new(index)` runs the index
  through a splitmix64 finaliser into an xorshift64\* stream. No `rand`
  dependency, no clock, no entropy: index → bytes is a pure function, stable
  across platforms and rebuilds.
* **Eight mutation kinds** — header bit-flips, whole-file bit-flips,
  truncation, poison-value field pokes (0, 1, 0x7f, 0x80, `u16::MAX`,
  `u32::MAX`, `i64::MAX`, `u64::MAX`, …), block scrambles, trailing-garbage
  appends, container-magic swaps (send an ELF body to the PE loader), and
  two-fixture splices. Every mutant is derived from one of the 24 real
  binaries in `tests/fixtures/`; one in four is first cut to a 64 KiB prefix
  so the short-input paths get exercised too.
* **The exercised surface** is the whole hostile path, not just `parse`:
  `ElfBinary::parse`, `PeBinary::parse`, `MachOBinary::parse`,
  `UniversalBinary::parse` (called directly, bypassing the magic dispatch),
  `Binary::load`, four `info_bytes` variants (including a rebase to
  `u64::MAX` and a forced raw-arch load), a full `scan_bytes` when the
  mutant's executable extent is small enough to be quick, and a
  **forced-raw `scan_bytes`** that walks arbitrary bytes straight into the
  decoder for one of all 14 supported architectures. That last one is the
  point: ENG-10's complaint is that the in-tree `mutated_bytes_never_panic`
  tests stop at `Binary::parse` and nothing ever fuzzes the decode engine.
* **It reports how deep the mutants actually got** — parse-ok counts per
  format, scan counts, and total gadgets produced. A harness that reports
  "10,000 mutants, zero panics" while every mutant bounced off a four-byte
  magic check is worthless, so the numbers are printed and quotable.

### Process model, and why it is not one process

The parent runs each chunk of mutants in a **child process**. Panics are
caught inside the child with `catch_unwind` and reported without stopping the
run. Anything `catch_unwind` cannot catch — a hard abort, a stack overflow,
a fault inside capstone's C code, or the allocation cap being hit — kills
only that child; the parent then re-runs that chunk **one mutant at a time**,
names the exact index, and writes the bytes to `fuzz/artifacts/smoke/`.

That matters because of `ROB-02`: a small malformed PE with a cloned section
table drives ~19.8 GB RSS. A single-process harness would be OOM-killed with
nothing to show. So each worker installs a **counting global allocator with a
hard cap** (`--mem-cap-mb`, default 1024). Past the cap `alloc` returns null,
the process aborts with a `MEMCAP request=… live_would_be=…` line on stderr,
and the parent turns that into a named finding instead of a dead machine.

Two honest limitations of that accounting:

* capstone allocates through **C `malloc`**, not Rust's `GlobalAlloc`, so the
  12 non-x86 decoders' allocations are invisible to the cap. Use libFuzzer's
  `-rss_limit_mb` (section 2) for a true RSS bound.
* the cap is *live bytes*, not RSS, so it under-reports fragmentation.

### Tuning

| flag | default | meaning |
|---|---|---|
| `--count N` | 10000 | mutants to run |
| `--start S` | 0 | first mutant index (shard a long run) |
| `--chunk C` | 250 | mutants per child process |
| `--mem-cap-mb M` | 1024 | allocation cap per child |
| `--timeout-secs T` | 20 | base of the per-chunk hang backstop (`T + 2 s × chunk`) |

---

## 2. cargo-fuzz

### Toolchain

```sh
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
```

`--locked` is not optional: on the toolchain this repo pins
(`rust-toolchain.toml` → 1.89.0) an unlocked install fails with

```
rustc 1.89.0 is not supported by the following package:
  cargo-platform@0.3.3 requires rustc 1.91
Try re-running `cargo install` with `--locked`
```

`cargo +nightly` also overrides `rust-toolchain.toml` for the whole build,
which is what you want: libFuzzer needs `-Zsanitizer=address`.

### Build and run

```sh
cd fuzz
cargo +nightly fuzz build                     # all seven targets
cargo +nightly fuzz list                      # target names
cargo +nightly fuzz run load_elf -- -max_total_time=60
```

### Windows: it *does* work, with one extra step

The commonly repeated claim is that cargo-fuzz does not work on Windows.
With cargo-fuzz 0.13.2 and the MSVC target that is **half true**, and the
half that is true is easy to fix:

* `cargo +nightly fuzz build` **succeeds** on `x86_64-pc-windows-msvc`.
* `cargo +nightly fuzz run <target>` then fails at process start with

  ```
  error: process didn't exit successfully: `target\x86_64-pc-windows-msvc\release\load_elf.exe …`
  (exit code: 0xc0000135, STATUS_DLL_NOT_FOUND)
  ```

  because the ASan-instrumented binary needs
  `clang_rt.asan_dynamic-x86_64.dll`, which ships with MSVC and is not on
  `PATH`.

Put the MSVC host toolchain bin directory on `PATH` and it runs:

```sh
# adjust the MSVC version to your install
export PATH="/c/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64:$PATH"
cargo +nightly fuzz run load_elf -- -max_total_time=60
```

PowerShell equivalent:

```powershell
$env:PATH = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;$env:PATH"
```

If your machine has Visual Studio rather than the Build Tools, the same DLL
lives under `C:\Program Files\Microsoft Visual Studio\2022\<edition>\VC\Tools\MSVC\<ver>\bin\Hostx64\x64`.

Note: `cargo fuzz build` emits seven `binary "load_elf" should have a
kebab-case name` manifest warnings. Target names are kept snake_case because
that is what `cargo fuzz add`, every cargo-fuzz tutorial and OSS-Fuzz build
scripts expect; renaming them would break every documented command for a
cosmetic lint.

---

## 3. The targets

| target | entry point | what it is for |
|---|---|---|
| `load_elf` | `ElfBinary::parse` + `arch()` + `rebase()` + `Binary::load` | ELF loader; `arch()` is where `CORE-01` lives |
| `load_pe` | `PeBinary::parse` + accessors + `Binary::load` | PE loader; **this is the `ROB-02` target** |
| `load_macho` | `MachOBinary::parse` + `image_base()` + `rebase()` | Mach-O loader; `image_base` is `CORE-02` |
| `load_universal` | `UniversalBinary::parse` + per-slice accessors | fat header = count + N (offset,size) triples, the classic amplification shape |
| `cli_info_bytes` | `rf_api::info_bytes` ×3 (auto, rebased, forced-raw) | the whole `--info` pipeline; cheapest target, run it longest |
| `cli_scan_bytes` | `rf_api::scan_bytes` at depth 2–5 | load → view → scan → post_process |
| `cli_scan_raw` | `rf_api::scan_bytes` with a forced `--rawArch` | **the decode engine**: arbitrary bytes into iced-x86 and into capstone's C code for all 14 architectures |

### Why four loader targets rather than one with a format-selector byte

A selector byte would let one target cover all four formats, but:

1. **The corpus would stop being real binaries.** With a leading selector
   byte, `tests/fixtures/elf-Linux-x86` is no longer a valid input — every
   seed has to be rewritten, and a crasher artifact is no longer a file you
   can hand to `rop-finder --binary` or to ROPgadget to confirm the bug.
   Reproducers that only the fuzzer can read are reproducers nobody uses.
2. **Coverage feedback gets diluted.** libFuzzer's corpus is per-target; one
   target for four formats means one shared energy budget and one shared
   corpus, and the cheap-to-reach format crowds out the others.
3. **`Binary::load` dispatches on magic anyway.** A selector byte would
   *mask* mis-dispatch bugs — exactly the class `CORE-01` and `CORE-03`
   belong to. Each loader target instead calls the concrete parser directly
   *and* drives `Binary::load` when the magic survives, so both the parser
   and the dispatcher are covered without a synthetic wrapper.

### Why the option byte is the LAST byte

`cli_scan_bytes` and `cli_scan_raw` need scan options (depth, jop/sys,
`--all`, `--callPreceded`, `--cfg-aware`, raw arch). They take them from the
**final** byte of the input, for the same reason as above: a real binary
dropped into the corpus unchanged is still a valid input, and dropping its
last byte changes nothing about how it parses. A *leading* byte would shift
every real file by one and make the whole corpus useless as input to any
other tool.

### Why depth is bounded

`cli_scan_bytes` caps depth at 5 and input at 1 MiB. An unbounded `--depth`
makes almost every non-trivial input a libFuzzer timeout, and a fuzzer that
only ever reports timeouts learns nothing — it stops mutating and starts
minimising. Depth 2–5 reaches every code path in the backward walk; the
walk's *structure* does not change with depth, only its iteration count.

---

## 4. The corpus

`fuzz/corpus/<target>/` holds a **deterministic seed corpus**, committed, and
regenerating it is one command:

```sh
cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- seed-corpus
```

* fixtures at or below 96 KiB are copied whole — a seed that does not parse
  teaches the fuzzer nothing, and a truncated ELF fails `goblin` outright
  because its section-header table lives at the end of the file;
* larger fixtures are committed as a 16 KiB header prefix (`*.prefix`);
* `seed-corpus --full` copies the whole fixtures locally as `*.full` for a
  long run; `.gitignore` keeps those out of the repository.

Measured: 75 files, 1,528 KiB.

**What is not committed, and why.** libFuzzer names every input it discovers
after that input's SHA-1, and it discovers a lot of them: 60 s per target
grew `fuzz/corpus/` from 1.6 MB to 11.5 MB here (load_elf 16 → 515 files).
`.gitignore` excludes hex-named files, so the repository keeps the
reproducible seed set and not the churn — `ENG-13` is about exactly this kind
of bloat, in a repository that already carries 17 MB of fixtures. The grown
corpus belongs in the CI cache and the job artifact (section 7), and the
files that *matter* for regressions — crashers — are committed under
`fuzz/artifacts/`. If you do want to commit a discovered corpus, minimise it
first and drop the `.gitignore` line deliberately:

```sh
cargo +nightly fuzz cmin load_elf
```

The seeds are derived from `tests/fixtures/`, so they inherit
`tests/fixtures/PROVENANCE.md` and the NOTICE — see `ENG-12`. Nothing new
enters the repository that is not already there.

---

## 5. Reproducing a crasher

libFuzzer writes the failing input to `fuzz/artifacts/<target>/` and prints
its path. Both are committed, so a crash found in CI is reproducible from a
clean clone.

```sh
# re-run one artifact under the fuzzer (prints the stack trace)
cargo +nightly fuzz run load_pe fuzz/artifacts/load_pe/crash-<hash>

# shrink it first
cargo +nightly fuzz tmin load_pe fuzz/artifacts/load_pe/crash-<hash>

# or just look at it
xxd fuzz/artifacts/load_pe/crash-<hash> | head
rop-finder --binary fuzz/artifacts/load_pe/crash-<hash> --info
```

For the smoke harness the reproducer is an integer:

```sh
cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- mutant 4711
# -> fuzz/artifacts/smoke/mutant-4711-<fixture>-<kind>.bin
```

Once a crasher is fixed, keep the artifact: move it into
`fuzz/corpus/<target>/` so it becomes a permanent regression seed.

---

## 6. The two findings this directory covers for someone else

`ROB-02` and `ROB-06` belong to the bounds workstream, not to this one. The
targets and the witness generator are here anyway, so the fix has a gate that
can go red without one.

### `ROB-02` — memory amplification (owner: the bounds workstream)

`crates/rf-core/src/pe.rs` made one owned byte copy per **declared** section
header, and the scan pipeline materialises all gadgets from all regions
before dedup. A PE whose section table is 2,000 clones of `.text` is a
~54,000× amplifier. The loader half is bounded as of the `ByteBudget` change
in `rf-core` — measured before and after in section 8 — and the scan half is
what the streaming sink from the engine-keystone workstream bounds.

Run `load_pe` (or `cli_scan_bytes`) with libFuzzer's RSS and malloc limits
set to the number the Phase 2 exit criteria name, and the amplifier is
reported as an OOM with a committed reproducer:

```sh
cargo +nightly fuzz run load_pe -- -rss_limit_mb=512 -malloc_limit_mb=512 -max_total_time=300
```

`rf-smoke amplify` builds the witness directly, in a child process under the
allocation cap, so the measurement can be taken without an OOM-kill:

```sh
cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- amplify --format pe --clones 2000
cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- amplify --format elf --clones 4000
```

It appends a second PE header at EOF with `NumberOfSections = N` followed by
N clones of the first section entry and repoints `e_lfanew` (the ELF variant
clones the largest section header and repoints `e_shoff`/`e_shnum`) — the
shape AUDIT-FINDINGS describes. The witness is *generated*, not committed, so
no new opaque binary enters the tree.

### `ROB-06` — unbounded input read (owner: the bounds workstream)

**Not reachable from any target here, and that is worth stating plainly.**
`ROB-06` is `std::fs::read` in `rf-cli`'s argument handling; every entry
point in this directory takes `&[u8]` that is already in memory. No
byte-level fuzz target can reach a missing file-size cap. It needs a
CLI-level test — run the binary against a character device / a FIFO / an
oversized sparse file and assert it errors quickly — which belongs in
`crates/rf-cli/tests/`, not here. What the fuzzers *do* cover is the
downstream half: `-max_len=8388608` in a nightly run exercises the
large-input path once the bytes are in memory.

---

## 7. CI

The PR job is a smoke gate; the long runs are nightly. Both should be
**required** — `CLAIM-04`'s whole point is that PLAN §9 calls these gates
"continuous" while nothing runs them.

```yaml
# PR: fast, deterministic, no nightly needed.
fuzz-smoke:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - run: cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- run --count 10000

# PR: 60 s per libFuzzer target over the committed corpus.
fuzz-short:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - run: rustup toolchain install nightly
    - run: cargo +nightly install cargo-fuzz --locked
    - run: |
        cd fuzz
        for t in $(cargo +nightly fuzz list); do
          cargo +nightly fuzz run "$t" -- \
            -max_total_time=60 -max_len=65536 -rss_limit_mb=2048 -timeout=25
        done

# Nightly: the long run. 24 h across the targets is the Phase 2 exit criterion.
fuzz-nightly:
  runs-on: ubuntu-latest
  timeout-minutes: 1500
  steps:
    - uses: actions/checkout@v4
    - run: rustup toolchain install nightly
    - run: cargo +nightly install cargo-fuzz --locked
    - run: |
        cd fuzz
        for t in $(cargo +nightly fuzz list); do
          cargo +nightly fuzz run "$t" -- \
            -max_total_time=12000 -max_len=8388608 -rss_limit_mb=512 \
            -malloc_limit_mb=512 -timeout=60 -jobs=4
          cargo +nightly fuzz cmin "$t"
        done
    - run: cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- run --count 1000000
    - uses: actions/upload-artifact@v4
      if: always()
      with: { name: fuzz-artifacts, path: fuzz/artifacts/ }
```

`-rss_limit_mb=512` on the nightly run is deliberate: it is the number the
Phase 2 exit criteria set for the amplifying PE, so the nightly job stays red
until `ROB-02` is fixed and then guards it.

---

## 8. Measured, 2026-09-03, this machine

Windows 11, `x86_64-pc-windows-msvc`, rustc 1.89.0 (repo pin) plus
`nightly-2026-09-02` (1.100.0-nightly) for cargo-fuzz 0.13.2. Every number
below came out of the command quoted next to it. Numbers taken while other
Phase 2 workstreams were mid-edit in the same tree; re-run before quoting
them in a release note.

### `rf-smoke` — the PLAN exit-criterion artifact

```
$ ./fuzz/smoke/target/release/rf-smoke.exe run --count 10000 --chunk 250 --mem-cap-mb 1024
mutants executed : 10000
worst mutant     : index 275 used 99303246 bytes (94.7 MiB)
elf_parse_ok     : 2693      pe_parse_ok      : 760
macho_parse_ok   : 848       universal_parse_ok: 379
dispatch_load_ok : 4634      info_bytes_ok    : 4634
scan_auto_ok     : 2489      scan_raw_ok      : 9524
gadgets_produced : 10075676
panics           : 0
hard failures    : 0
slow (>3 s)      : 0
elapsed          : 69.2 s
```

and the same harness ten times longer:

```
$ ./fuzz/smoke/target/release/rf-smoke.exe run --count 100000 --chunk 500 --mem-cap-mb 1024
mutants executed : 100000
worst mutant     : index 19475 used 99305990 bytes (94.7 MiB)
dispatch_load_ok : 45851     scan_auto_ok     : 24529
scan_raw_ok      : 95238     gadgets_produced : 99220368
panics           : 0
hard failures    : 0
elapsed          : 632.2 s
```

**PLAN.md:226's "zero panics on 10K mutated binaries" now has an artifact,
and it is 10× the required size.** The depth counters are the part that makes
it worth something: 45,851 of the 100,000 mutants got past format detection
into a real loader, 24,529 completed a full container scan, 95,238 completed
a forced-raw scan, and 99,220,368 gadgets came out of the decode engine. Peak
allocation over the whole run was 94.7 MiB against a 1024 MiB cap.

### cargo-fuzz, 60 s per target

`cargo +nightly fuzz run <target> -- -max_total_time=60 -max_len=65536
-rss_limit_mb=2048 -timeout=25`, from the committed seed corpus:

| target | runs in 61 s | final `cov` | final corpus | peak RSS |
|---|---|---|---|---|
| `load_elf` | 225,231 | — | — | — |
| `load_pe` | 192,456 | — | — | — |
| `load_macho` | 201,276 | — | — | — |
| `load_universal` | 316,282 | 1,021 | 329 files / 9.1 MB | 543 MB |
| `cli_info_bytes` | 7,724 | 3,017 | 213 files / 2.2 MB | 469 MB |
| `cli_scan_bytes` | 3,880 | 7,413 | 677 files / 26 MB | 597 MB |
| `cli_scan_raw` | 7,486 | 4,387 | 848 files / 4.7 MB | 580 MB |

**Zero crashes, zero OOMs, zero timeouts across all seven.** `load_elf`
reaches `cov: 910 ft: 1123` on the seed corpus alone, before mutation starts.

Caveat worth stating: the three loader rows were measured against the live
working tree; the other four were measured against the `v0.1.1` tag, because
mid-Phase-2 the tree spent a long stretch not compiling (the engine-keystone
change had landed in `rf-scan` before its `rf-cli` consumer was updated).
Re-run all seven once the release is integrated.

Note the 469–597 MB peak RSS on the scan targets even at `-max_len=65536`:
that is `PERF-05` and the scan half of `ROB-02` showing up in the fuzzer, and
it is why the nightly job in section 7 sets `-rss_limit_mb=512`.

### `ROB-02` amplification: before and after

`rf-smoke amplify` measured against two trees — `v0.1.1` (the tagged tree,
before the bounds workstream) and the same tree with only `crates/rf-core`
replaced by the version carrying `ByteBudget`. This is `Binary::load` **only**;
the scan pipeline's own materialisation is on top of it, which is where
AUDIT-FINDINGS' 19.8 GB figure comes from.

| witness | input | `v0.1.1` peak live alloc | with `ByteBudget` |
|---|---|---|---|
| PE, 2,000 cloned section headers | 381,816 B | **541.5 MiB — 1,487× input** | 0.8 MiB — 2× |
| PE, 4,000 cloned section headers | 461,816 B | **exceeded the 1,024 MiB cap** | 1.3 MiB — 3× |
| ELF, 4,000 cloned section headers | 1,119,320 B | **exceeded the 1,024 MiB cap** | 2.6 MiB — 2× |

The cap-exceeded rows are what the harness's process model is for. The child
prints, from inside the allocator,

```
MEMCAP request=141824 live_would_be=1073753795
memory allocation of 141824 bytes failed
```

and the parent reports

```
RESULT: child exited -1073740791 (0xc0000409) — the 1024 MiB allocation cap
        was exceeded before the load completed.
```

with exit status 1, instead of the machine being OOM-killed.

### `rf-smoke`'s own tests

```
$ cargo test --release --manifest-path fuzz/smoke/Cargo.toml
running 5 tests
test tests::mutants_are_reproducible ... ok
test tests::every_fixture_is_used ... ok
test tests::a_slice_of_mutants_never_panics ... ok
test tests::mutation_is_deterministic ... ok
test tests::every_mutation_kind_is_reachable ... ok
test result: ok. 5 passed; 0 failed
```

`mutation_is_deterministic` is the load-bearing one: it pins the signature of
mutants 0..64, so a change to the RNG, the mutation order or the fixture list
cannot silently repoint every recorded reproducer index at a different input.

---

## 9. Layout

```
fuzz/
  Cargo.toml            cargo-fuzz package; own [workspace], excluded from the root
  fuzz_targets/*.rs     the seven libFuzzer targets (+ common.rs, shared knob decoding)
  corpus/<target>/      committed seeds, generated by `rf-smoke seed-corpus`
  artifacts/<target>/   committed crashers (libFuzzer writes here)
  artifacts/smoke/      committed crashers and generated witnesses from rf-smoke
  smoke/                the portable harness; own [workspace], stable Rust
  README.md             this file
```
