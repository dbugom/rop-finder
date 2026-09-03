# tests/parity-baseline — the committed parity gate

One JSON file per fixture in `tests/fixtures`. `tests/parity.py` reads these
and exits non-zero when the current build falls below them. Before v0.2.0 no
golden or reference output was committed anywhere in this repository and the
parity harness had no non-zero exit path at all (`ENG-04`), which is why a
change that dropped parity to 80% would have passed every check the project
had.

## File shape

```json
{
  "fixture": "elf-Linux-x86",

  "oracle": {
    "ropgadget_commit": "b6e3fe31af46",
    "capstone": "5.0.7",
    "depth": 10,
    "extra_flags": []
  },

  "reference": {
    "count": 42508,
    "sha256_vaddr_bytes_set": "f2e31f01c702a127…"
  },

  "floor": {
    "min_matched": 42421,
    "max_ours_only": 59,
    "min_text_normalized": 26283
  },

  "recorded": { "…": "the full measurement the floor was taken from" }
}
```

### `reference` — ground truth, from the ORACLE only

The oracle's post-dedup `(vaddr, bytes)` set: its size, and a sha256 over the
sorted `0xVADDR|HEXBYTES` key list. **This is generated from ROPgadget output
and never from rop-finder output.** That is deliberate and it is the whole
reason this directory is credible: a baseline seeded from our own current
output would freeze today's bugs into the definition of correct.

If the oracle produces a different set, `tests/parity.py` reports
`ORACLE DRIFT` and exits non-zero rather than charging the difference to
rop-finder. Different ROPgadget commit, different capstone build, different
platform — all of them show up here, not as a parity regression. (The oracle
is not bit-identical across platforms; see the two reference totals recorded in
`docs/measured-2026-09.md`.)

### `floor` — a ratchet on our side

Three one-sided bounds, each measured, each able to go red on its own:

| field | meaning | a failure means |
|---|---|---|
| `min_matched` | fewest reference gadgets we may reproduce | we lost gadgets ROPgadget finds |
| `max_ours_only` | most gadgets we may report that ROPgadget does not | we started fabricating, or a formatter change split a dedup class |
| `min_text_normalized` | fewest matched gadgets whose text agrees after normalization | rendering diverged further from the oracle |

Floors only go **up**. `--update-floor` takes the maximum of old and new for
the two minimums and the minimum for the maximum; `--force-lower` is required
to move one down, so accepting a regression is a visible diff in review rather
than a number that quietly changed.

## Regenerating

```bash
# 1. Re-freeze the ORACLE reference sets. Only after deliberately accepting a
#    new ROPgadget commit or capstone build — this redefines "correct".
python tests/parity.py --seed-reference

#    …or from precomputed oracle dumps (<fixture>.json mapping
#    "0xVADDR|HEXBYTES" -> gadget text), without running ROPgadget:
python tests/parity.py --seed-reference --oracle-cache path/to/dumps

# 2. Ratchet the floors to the current measurement.
python tests/parity.py --update-floor
```

Both need the oracle. See `tests/rf_paths.py` for the one-command venv setup
(`ROPgadget b6e3fe31af46` + `capstone==5.0.7`) and the `ROPGADGET_PATH` /
`ROPGADGET_PYTHON` overrides.

## `--baseline-dir`, and why CI does not gate against this directory

python-capstone ships a **prebuilt** `libcapstone` per wheel, so ROPgadget's
own output differs slightly between platforms: the same 24 fixtures yield
763,718 reference gadgets on macOS/arm64 (CPython 3.11) and 763,204 on
Windows/x86-64 (CPython 3.12) — a 514-gadget, 0.067% delta, concentrated in the
ARM/ARM64/x86 encodings the harness already flags. Both totals are recorded in
`docs/measured-2026-09.md`; neither is "the" right one.

The files here were frozen on Windows. Gating a Linux CI runner against them
would charge a wheel difference to rop-finder, so the CI parity job freezes its
own baseline once (`--seed-reference --baseline-dir ci-parity-baseline`, then
`--update-floor`), caches it against the ROPgadget commit and capstone version,
and gates every later run against that. The committed Windows baseline is still
run on every CI build, in report-only mode, so the cross-platform delta stays
visible in the log instead of being forgotten.

A same-platform contributor gets the committed baseline as a real gate with no
flags: `python tests/parity.py`.

## Intentional divergences

`tests/known-divergences.json`, when present, excuses specific gadgets that
rop-finder deliberately reports differently from the oracle — for instance the
populated ARM64/SPARC SYS anchor tables (`ANCH-03`), where ROPgadget's own
tables are empty. Each entry must name either the **exact keys** it excuses or
an integer `max_count`; a blanket per-fixture waiver cannot be expressed, so an
intentional divergence cannot be used to hide an accidental one. Entries that
excuse nothing are reported as STALE. The gate's own red runs are recorded in
`docs/gate-mutation.md`.

## Environment these were frozen on

Windows 11 Pro 10.0.26200, CPython 3.12.10, ROPgadget `b6e3fe31af46` with
capstone 5.0.7, `cargo build --release -p rf-cli` (rustc 1.89.0).
24 fixtures, 763,204 reference gadgets, zero skips.
