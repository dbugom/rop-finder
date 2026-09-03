# Gate mutation log

A gate that has never been observed to fail is not a gate. Phase 2's exit
criteria say so explicitly: *"MUTATION TEST OF THE GATE ITSELF … verified as
recorded revert-and-run experiments checked into docs/gate-mutation.md. This
tests the gate rather than the fix."*

This file records those experiments. Each entry is a real command run on a real
machine with its real output, not a description of what would happen.

**Environment for every run below.**

```
Windows 11 Pro 10.0.26200, rustc 1.89.0, CPython 3.12.10
oracle: ROPgadget @ b6e3fe31af46 (D:\Private\ROP-Finder\ropgadget\ROPgadget.py)
        run under D:\Private\ROP-Finder\.venv-oracle\Scripts\python.exe, capstone 5.0.7
corpus: 24 fixtures, 763,204 reference gadgets, zero skips
build:  cargo build --release -p rf-cli
```

Every mutation below was reverted immediately after the run; the committed
files are unmodified.

---

## Part 1 — mutations of the harnesses themselves (run)

These prove the machinery can go red at all. Before v0.2.0 none of it could:
`tests/parity.py`'s `main()` had no non-zero exit path, `benches/` was empty,
and there was no doc-claims harness (ENG-04, CLAIM-02, PERF-08).

### M1 — parity floor regression

**Mutation.** Raise one fixture's committed floor by 100 gadgets, simulating a
change that loses 100 gadgets that ROPgadget finds.

```
python -c "import json;p='tests/parity-baseline/elf-Linux-x86.json';d=json.load(open(p));d['floor']['min_matched']+=100;json.dump(d,open(p,'w'),indent=2,sort_keys=True)"
python tests/parity.py --fixture elf-Linux-x86 --top 0
```

**Result — exit 1.**

```
=== elf-Linux-x86
  |ref|=42508  |ours|=42480  matched=42421  ref-only=87  ours-only=59  (99.7953% of ref)
  text: exact=23435  normalized=26283  divergent=16138
  REGRESSION: matched 42421 < floor 42521 (-100 gadgets)
...
=== REGRESSIONS BELOW THE COMMITTED BASELINE
  elf-Linux-x86: matched 42421 < floor 42521 (-100 gadgets)

PARITY GATE: FAIL
A_EXIT=1
```

### M2 — oracle drift is not absorbed as a rop-finder result

**Mutation.** Corrupt the committed *oracle* reference digest for one fixture.
This is the case where the reference set itself moved — a different ROPgadget
commit or a different capstone. It must be reported as ORACLE-DRIFT and never
silently accepted as "our number changed".

```
python -c "import json;p='tests/parity-baseline/macho-x64-ls.json';d=json.load(open(p));d['reference']['sha256_vaddr_bytes_set']='0'*64;json.dump(d,open(p,'w'),indent=2,sort_keys=True)"
python tests/parity.py --fixture macho-x64-ls --top 0
```

**Result — exit 1**, and note that the *floor* check still passes: the two
failure modes are distinguished, not conflated.

```
=== macho-x64-ls
  |ref|=1289  |ours|=1293  matched=1289  ref-only=0  ours-only=4  (100.0% of ref)
  ok - at or above the committed floor
...
=== ORACLE DRIFT (the reference moved, not rop-finder)
  macho-x64-ls: oracle reference 1289 gadgets 0000000000000000... but this oracle produced 1289 gadgets 3a66eaa851f0961a...
  The committed reference was frozen against ROPgadget b6e3fe31af46 + capstone 5.0.7. Re-freeze with --seed-reference only after confirming the new oracle is correct.

PARITY GATE: FAIL
B_EXIT=1
```

### M3 — an intentional divergence cannot hide an accidental one

This is the specific property the Phase 2 exit criteria demand of the
known-divergence list: *"its known-divergence list explicitly names the
intentional ARM64/SPARC SYS-table divergence so that divergence cannot be used
to hide an accidental one."*

`macho-x64-ls` has exactly 4 gadgets rop-finder finds that ROPgadget does not.
Its floor was temporarily set to `max_ours_only: 0` for this experiment, and
three variants were run against a synthetic divergence list supplied through
`RF_KNOWN_DIVERGENCES` (so the real `tests/known-divergences.json` was never
touched):

| variant | list contents | result |
|---|---|---|
| (a) no list | — | `REGRESSION: ours-only 4 > floor 0 (+4 fabricated/divergent)` → **FAIL** |
| (b) all four keys named | `keys: [4 exact "0xvaddr\|hexbytes" strings]` | `known-divergence TEST-FULL: excused 4 (unused 0)` → **PASS** |
| (c) three of four named | `keys: [3 of those strings]` | `known-divergence TEST-PARTIAL: excused 3 (unused 0)` then `REGRESSION: ours-only 1 > floor 0 (+1 fabricated/divergent)` → **FAIL** |

Variant (c) is the point. The waiver is per-key (or a hard `max_count`), never
per-fixture, so adding one accidental divergence to a fixture that already has
an excused intentional one still turns the gate red. `tests/parity.py` refuses
to load an entry that supplies neither `keys` nor an integer `max_count`, and
reports any entry that excused nothing as STALE.

### M3b — the same property, re-verified on the merged v0.2.0 tree

M3 above was run when `macho-x64-ls` still had 4 `ours-only` gadgets. It has
none now — the engine and formatter workstreams took that fixture to
bit-exact — so M3's setup is no longer reproducible as written. The property
it tested was re-verified by the integrator against the fixture that *does*
carry divergent keys today, `pe-Windows-ARMv7-Thumb2LE-HelloWorld` (404
`ours-only`, ANCH-06), again through `RF_KNOWN_DIVERGENCES` so the committed
list was never touched:

| variant | list contents | result |
|---|---|---|
| (a) blanket | `direction` only — no `keys`, no `max_count`, no `match` | `known-divergences.json: entry 'TEST-BLANKET' must give either an explicit keys list or an integer max_count: a blanket per-fixture waiver is not accepted` → **refuses to run** |
| (b) 4 short | `max_count: 400` against 404 divergent keys | `excused 400 (unused 0)` then `REGRESSION: ours-only 4 > floor 0` → **FAIL** |
| (c) wrong regex | `effect: extra-gadgets`, `extra_gadgets_must_match: "^(svc\|ta)\b"` | `excused 0` then `REGRESSION: ours-only 404 > floor 0` → **FAIL** |
| (d) right regex | same entry with `match: "."` | `excused 404` → **PASS** |

(c) is the one that matters for `ANCH-03`. That waiver is bounded by a regex
over the *gadget text*, not by a count, so it can excuse an extra `svc`/`ta`
gadget and cannot excuse anything else: an accidental divergence on an
AArch64 or SPARC fixture still turns the gate red even though an intentional
one is on record for it.

### M4 — doc-claims: retracted numbers cannot drift back

**Mutation.** Copy README/MANUAL/PLAN into a scratch directory, edit three
numbers back to the pre-v0.1.1 claims, and point the harness at the copy with
`--doc-root` (so no real document is touched):

* README speedup table: `elf-Linux-x86 … 6.2x` → `12.4x`
* README corpus size: `across **24** fixtures` → `across **25** fixtures`
* MANUAL speed row: add `~11x faster than ropper`

```
python tests/doc_claims.py --no-timing --doc-root <scratch>
```

**Result — exit 1**, three separate claims red:

```
[FAIL] FIXTURE-COUNT        the fixture corpus size stated in the docs is the number of files in tests/fixtures
         expected: 24 (ls tests/fixtures, excluding MANIFEST.sha256/PROVENANCE.md)
         measured: MANUAL.md=24, PLAN.md=24, README.md=25
[FAIL] SPEEDUP-RETRACTED    every documented speedup stays below the 10x/4x criteria PLAN records as NOT MET
         measured: elf-Linux-x86=12.4x, ...
         note:     elf-Linux-x86 12.4x >= 10.0x
[FAIL] NO-ROPPER-SPEEDUP    no speedup-vs-ropper figure is asserted (the old ~9-14x had no source)
         measured: 1 occurrences
         note:     MANUAL.md: '11x faster than ropper'
```

Unmutated, the same command reports `12 claims checked, 0 failed, 1 warned`
(the warn is `BIT-EXACT`; see docs/measured-2026-09.md).

### M5 — criterion regression band

**Mutation.** Tell the committed bench baseline that `scan/parallel/x86` used
to be 20% faster than it is, i.e. simulate a 25% slowdown landing.

```
python -c "import json;p='crates/rf-bench/baseline.json';d=json.load(open(p));d['benchmarks']['scan/parallel/x86']['median_ns']*=0.80;json.dump(d,open(p,'w'),indent=2,sort_keys=True)"
python crates/rf-bench/check_regression.py --cross-environment
```

**Result — exit 1:**

```
scan/parallel/x86                 91.083 ms    113.854 ms   1.250x  REGRESSION
1 REGRESSION(S) beyond the 10% band:
  scan/parallel/x86: 25.0% slower

BENCH GATE: FAIL
```

Unmutated: `BENCH GATE: PASS`, all 26 benchmarks at `1.000x`.

### M6 — the parity gate refuses to run blind

Not a mutation so much as a property worth recording: with no oracle reachable,
`tests/parity.py` exits with the setup instructions rather than printing a
number.

```
$ ROPGADGET_PATH=/nonexistent/ROPgadget.py python tests/parity.py --fixture raw-x86.raw
# environment: win32 python=3.12.10 oracle=<not found>
# rop-finder:  D:\Private\ROP-Finder\rop-finder\target\release\rop-finder.exe
# baselines:   D:\Private\ROP-Finder\rop-finder\tests\parity-baseline
ROPgadget.py not found.
The ROPgadget parity oracle was not found.

  git clone https://github.com/JonathanSalwan/ROPgadget ropgadget   # beside this repo
  git -C ropgadget checkout b6e3fe31af46
  python -m venv .venv-oracle
  .venv-oracle/Scripts/pip install 'capstone==5.0.7'

then either place them beside this repository (../ropgadget, ../.venv-oracle),
or set ROPGADGET_PATH and ROPGADGET_PYTHON.
$ echo $?
1
```

The old harness ran the oracle with `sys.executable`. On a machine whose
default interpreter has no `capstone` the oracle subprocess fails, `run_ref`
returns `None`, every fixture lands in the SKIP list, and `main()` — which had
no non-zero exit path — still exits 0. That is a green parity gate over an
empty comparison.

---

## Part 2 — the five source reverts (RUN 2026-09-03, integration wave)

Phase 2's exit criteria name five specific fixes whose deliberate reversion
must turn CI red: `CORE-01`, `CLI-01`, `SCAN-02`, `SCAN-03`, `CRIT-01`.

When this section was first written those fixes were still being landed by the
workstreams that own `crates/rf-core`, `crates/rf-scan` and `crates/rf-cli`, so
reverting a file mid-change would have measured the wrong tree. They were run
by the integrator once all six workstreams had merged and the whole workspace
was green at **333 passing tests** (Phase 1 ended at 207).

Procedure for every row: back the file up, apply the revert, `cargo build
--release`, run the gates, restore from the backup, `diff` against the backup
to prove the restore was exact. The workspace was re-verified green after the
last restore — `cargo fmt --all -- --check`, `cargo clippy --workspace
--all-targets -- -D warnings`, `cargo test --workspace` (333 passed, 0 failed)
and `python tests/parity.py` (PASS).

**All five went red. None of them went red on every gate**, which is the useful
part of the exercise: it says which gate carries which fix.

| # | Fix reverted | Gate | Result |
|---|---|---|---|
| R1 | `CORE-01` | `cargo test -p rf-core` | **RED** — 2 failed, 54 passed |
| R1 | `CORE-01` | `cargo test -p rf-cli --test refusals` | **RED** — 1 failed, 9 passed |
| R2 | `CLI-01` | `cargo test -p rf-cli` | **RED** — 2 failed, 61 passed |
| R2 | `CLI-01` | `python tests/parity.py` | green — parity never passes `--cache` |
| R3 | `SCAN-02` | `cargo test -p rf-scan --lib` | **RED** — 1 failed, 57 passed |
| R3 | `SCAN-02` | `python tests/parity.py` | **RED** — every CET-marked fixture |
| R4 | `SCAN-03` | `cargo test -p rf-scan --lib` | **RED** — 2 failed, 56 passed |
| R4 | `SCAN-03` | `python tests/parity.py` | **RED** — every x86/x64 fixture |
| R5 | `CRIT-01` | `cargo test -p rf-scan` | **RED** — 1 failed, 57 passed |
| R5 | `CRIT-01` | `python tests/parity.py` | green — parity never passes `--cfg-aware` |

### R1 — `CORE-01`: guess `Arch::X86` for an unrecognized `e_machine`

Revert: in `crates/rf-core/src/elf.rs`, replace the `other => return
Err(Error::UnsupportedArch { machine })` arm with `_other => X86`.

```
$ cargo test -p rf-core
test elf::tests::unknown_e_machine_is_refused_naming_the_machine ... FAILED
test elf::tests::unknown_e_machine_refused_for_a_sample_of_real_unsupported_machines ... FAILED
test result: FAILED. 54 passed; 2 failed

$ cargo test -p rf-cli --test refusals
test unrecognized_e_machine_is_refused_and_prints_no_gadgets ... FAILED
test result: FAILED. 9 passed; 1 failed
```

The behavioural consequence is the finding itself. On an ELF whose
`e_machine` was set to `0x9999` (a copy of `elf-Linux-x86` with two bytes
changed):

```
reverted:  exit=0, 42,508 gadgets printed   <- all fabricated, silently
restored:  exit=2, 0 gadgets printed
           [Error] unsupported architecture: machine type 0x9999 (39321) is not
           one rop-finder can disassemble; refusing rather than emitting
           fabricated gadgets
```

### R2 — `CLI-01`: drop the raw spec from `cache_key`

Revert: in `crates/rf-cli/src/lib.rs`, pass `Option::<&str>::None` in place of
`id.raw_arch`, `id.raw_mode` and `id.raw_endian`.

```
$ cargo test -p rf-cli
test tests::cache_key_covers_every_output_affecting_parameter ... FAILED
test tests::a_cached_scan_is_never_served_across_rawarch ... FAILED
test result: FAILED. 61 passed; 2 failed
```

Behaviour, against a fresh cache directory on `tests/fixtures/raw-x86.raw`:

```
reverted:  --rawArch x86 --rawMode 32          -> [Cache] miss, stored 7 gadgets
           --rawArch arm --rawMode arm         -> [Cache] hit  (7 gadgets)   <- LIE
restored:  --rawArch arm --rawMode arm         -> [Cache] miss, stored 0 gadgets
```

The correct answer for the ARM query is 0 gadgets. Reverted, the cache serves
seven x86 gadgets to an ARM query. **`tests/parity.py` stays green through
this** — the harness never passes `--cache` — so `cargo test -p rf-cli` is the
only gate holding CLI-01.

### R3 — `SCAN-02`: stop emitting the `notrack` prefix

Revert: in `crates/rf-scan/src/x86.rs`, make `add_notrack` return without
inserting the prefix.

```
$ cargo test -p rf-scan --lib
test x86::tests::renders_capstone_spelling ... FAILED
test result: FAILED. 57 passed; 1 failed

$ python tests/parity.py --fixture macho-x86-ls
  |ref|=1272  |ours|=1271  matched=1271  ref-only=1
  REGRESSION: our own gadget count 1271 < floor 1272 (output collapsed)
  REGRESSION: matched 1271 < floor 1272 (-1 gadgets)
  REGRESSION: text-normalized matches 1269 < floor 1272
PARITY GATE: FAIL

$ python tests/parity.py --fixture pe-x64-cmd
  |ref|=12509  |ours|=12508  matched=12508  ref-only=1
  REGRESSION: matched 12508 < floor 12509 (-1 gadgets)
PARITY GATE: FAIL
```

Without the prefix a `notrack jmp` collides with the plain `jmp` in dedup and
one gadget disappears per CET-marked fixture.

### R4 — `SCAN-03`: render `f3 c3` as `rep ret` again

Revert: in `crates/rf-scan/src/x86.rs`, drop the `Mnemonic::Ret` special case
so the `rep ` prefix is stripped like any other.

```
$ cargo test -p rf-scan --lib
test engine::tests::repz_ret_is_rendered_and_findable_with_only ... FAILED
test x86::tests::renders_capstone_spelling ... FAILED
test result: FAILED. 56 passed; 2 failed

$ python tests/parity.py --fixture elf-Linux-x86
  text: exact=42300  normalized=42300  divergent=173
  REGRESSION: matched 42473 < floor 42508 (-35 gadgets)
  REGRESSION: text-normalized matches 42300 < floor 42508
PARITY GATE: FAIL

$ python tests/parity.py --fixture elf-Linux-x64
  text: exact=43682  normalized=43682  divergent=266
  REGRESSION: matched 43948 < floor 43972 (-24 gadgets)
PARITY GATE: FAIL
```

### R5 — `CRIT-01`: require an endbr landing pad on every gadget

Revert: in `crates/rf-scan/src/engine.rs`, make `survives_cet` ignore
`Gadget::table` and call `is_endbr_entry` unconditionally.

```
$ cargo test -p rf-scan
test engine::tests::cfg_aware_is_table_aware ... FAILED
test result: FAILED. 57 passed; 1 failed
```

Behaviour — this is the original CRIT-01 bug reproduced exactly:

```
                                reverted   restored
--cfg-aware pe-x64-cmd-v6.1.7601       0      2,097
--cfg-aware elf-Linux-x64              0      8,389
```

`tests/parity.py` stays green through this too: the harness never passes
`--cfg-aware`. `cargo test -p rf-scan` is the only gate holding CRIT-01, and
`docs/measured-2026-09.md` should state the counts so the doc-claims harness
holds them as well.

### What this says about the gate set

Two of the five (R2, R5) are invisible to the parity harness. Parity is a
strong gate for *decode and render* fidelity and a **non-gate** for anything
reachable only through a CLI flag the harness does not pass — the cache and
`--cfg-aware` today. Adding `--cache` and `--cfg-aware` coverage to the harness,
or keeping the `cargo test` suites as required CI jobs alongside it, is what
keeps those two findings from silently regressing.

---

## How to re-run everything here

```
cargo build --release -p rf-cli
python tests/parity.py                       # exit 0 expected
python tests/doc_claims.py --no-timing       # exit 0 expected
cargo bench -p rf-bench
python crates/rf-bench/check_regression.py   # exit 0 expected
python tests/chain_parity.py                 # exit 0 expected
```

Regenerating the parity baseline (only after deliberately accepting a new
oracle or a measured improvement):

```
# the oracle reference set - the ground truth, never taken from rop-finder output
python tests/parity.py --seed-reference

# the ratchet floors - raised to the current measurement, never lowered
python tests/parity.py --update-floor
```

On a platform other than the one the committed baseline was frozen on, freeze a
local one instead of editing the committed files — the oracle itself differs
between capstone wheels (`tests/parity-baseline/README.md`):

```
python tests/parity.py --seed-reference --baseline-dir my-baseline
python tests/parity.py --update-floor  --baseline-dir my-baseline
python tests/parity.py                 --baseline-dir my-baseline   # the gate
```
