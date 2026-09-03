#!/usr/bin/env python3
"""Parity gate: rop-finder against ROPgadget, with a committed baseline.

ENG-04.  The previous version of this file printed an overlap percentage and
returned.  `main()` had no non-zero exit path at all, so the project's central
claim — "99.93% of ROPgadget's gadgets" — was untested *by construction*: a
change that dropped parity to 80% passed `cargo test` and passed this script.
It also hardcoded a sibling `../ropgadget` directory, ran the oracle with
`sys.executable` (which may not have python-capstone at all) and preferred
`target/release/rop-finder.exe`, so it could not run from a clone on
macOS/Linux.

What it does now
----------------
For every fixture in ``tests/fixtures``:

1. Obtain the oracle's post-dedup ``(vaddr, bytes)`` set, either by running
   ROPgadget (``--depth 10 --dump``) or from a cached dump directory.
2. Check that set against the **committed reference** in
   ``tests/parity-baseline/<fixture>.json`` — count and sha256 over the sorted
   key set.  A mismatch means the *oracle* moved (different ROPgadget commit or
   capstone build) and is reported as ORACLE-DRIFT, never silently absorbed.
3. Run ``rop-finder --depth 10 --json`` and compare the two sets.
4. Compare the result against the committed **floor** and exit non-zero on any
   regression below it.

The reference block is generated FROM THE ORACLE, never from rop-finder
output, so it cannot bake in a rop-finder bug.  The floor block is a ratchet
recorded from a measured run; ``--update-floor`` only ever raises it (lowering
requires ``--force-lower``, which makes a regression a visible diff in review
rather than a silent number change).

Known divergences
-----------------
``tests/known-divergences.json``, when present, excuses specific intentional
divergences (e.g. the ARM64/SPARC SYS anchor tables, which ROPgadget leaves
empty — ANCH-03).  An entry must name either the exact ``keys`` it excuses or
a ``max_count``; a blanket per-fixture waiver is not expressible, so an
intentional divergence cannot be used to hide an accidental one.  Entries that
match nothing are reported as STALE.

Usage
-----
    python tests/parity.py                          # the gate (exit 1 on regression)
    python tests/parity.py --fixture elf-Linux-x86  # one fixture
    python tests/parity.py --oracle-cache DIR       # use precomputed oracle dumps
    python tests/parity.py --seed-reference --oracle-cache DIR
    python tests/parity.py --update-floor           # ratchet floors upward
    python tests/parity.py --baseline-dir DIR       # gate against a different baseline

The oracle is not bit-identical across platforms (python-capstone ships a
prebuilt libcapstone per wheel), so CI freezes its own baseline with
``--baseline-dir`` rather than gating a Linux runner against a baseline frozen
on Windows. See tests/parity-baseline/README.md.

Oracle setup: see the module docstring of tests/rf_paths.py.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

# No __pycache__ beside the harnesses: tests/ is not gitignored for it,
# and a stray cache directory in a source tree is noise, not a build product.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rf_paths  # noqa: E402

# CI consoles are not always UTF-8; never let an encoding error mask a gate result.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, OSError):  # pragma: no cover
        pass

HERE = rf_paths.HERE
REPO = rf_paths.REPO
# The committed baseline. `--baseline-dir` points the gate at a different one:
# the oracle is NOT bit-identical across platforms (python-capstone ships a
# prebuilt libcapstone per wheel, and the macOS/Windows reference totals already
# differ by 514 gadgets - see docs/measured-2026-09.md), so a CI runner freezes
# and gates against its own, exactly as the criterion job does.
BASELINE_DIR = os.path.join(HERE, "parity-baseline")
# Overridable so the gate's own behaviour can be tested against a synthetic
# list without editing the real one (see docs/gate-mutation.md).
KNOWN_DIVERGENCES = os.environ.get(
    "RF_KNOWN_DIVERGENCES", os.path.join(HERE, "known-divergences.json")
)
DEPTH = 10

REF_LINE = re.compile(r"^(0x[0-9a-f]+)\s*:\s*(.*?)\s*//\s*([0-9a-f]+)\s*$")

# Fixtures that need explicit raw-loader flags for BOTH tools (mirrors
# ropgadget/test-suite-binaries/test.sh).
EXTRA_FLAGS = {
    "raw-x86.raw": ["--rawArch=x86", "--rawMode=32"],
}

# Flags passed to rop-finder ONLY, because ROPgadget has no equivalent.
#
# The fat Mach-O is the whole reason `--compat` exists (CORE-03/CORE-05).
# ROPgadget scans a universal binary as the flat concatenation of its slices,
# so its 366 gadgets are a mix of real x86_64 gadgets and i386 bytes decoded
# with the wrong decoder at overlapping virtual addresses.  rop-finder now
# REFUSES that file without `--arch` rather than fabricating the same output.
# Measuring parity therefore requires asking for the oracle's behaviour
# explicitly: `--compat` reproduces the concatenation bug-for-bug (and warns on
# stderr while doing it).  Without this the harness cannot measure the fixture
# at all, and dropping the fixture would silently retire 366 gadgets of
# coverage.  `--arch x86_64` alone yields the 200 real gadgets of one slice,
# which is the correct answer to a different question than "do we match?".
OURS_ONLY_FLAGS = {
    "UNIVERSAL-x86-x64-libSystem.B.dylib": ["--compat"],
}


# --------------------------------------------------------------------------
# key helpers
# --------------------------------------------------------------------------
def key_str(vaddr, byts):
    return f"{vaddr:#x}|{byts}"


def parse_key(s):
    v, _, b = s.partition("|")
    return (int(v, 16), b)


def set_digest(keys):
    """sha256 over the sorted `0xvaddr|hexbytes` key set."""
    h = hashlib.sha256()
    for k in sorted(key_str(v, b) for v, b in keys):
        h.update(k.encode())
        h.update(b"\n")
    return h.hexdigest()


def norm_text(t):
    """Normalize immediate spelling / whitespace for the fuzzy text class."""
    t = re.sub(r"\s+", " ", t.strip())
    t = re.sub(r"\b0x0+([0-9a-f])", r"0x\1", t)
    t = re.sub(r"\b0x([0-9a-f])\b", r"\1", t)
    return t


# --------------------------------------------------------------------------
# running the two tools
# --------------------------------------------------------------------------
def run_ref(fixture_path, extra):
    """{(vaddr, bytes): text}, seconds — or (None, dt) if the oracle refuses."""
    t0 = time.perf_counter()
    p = subprocess.run(
        rf_paths.oracle_cmd(fixture_path, extra=extra, depth=DEPTH),
        capture_output=True,
        text=True,
    )
    dt = time.perf_counter() - t0
    if p.returncode != 0:
        return None, dt
    gadgets = {}
    for line in p.stdout.splitlines():
        m = REF_LINE.match(line)
        if m:
            gadgets[(int(m.group(1), 16), m.group(3))] = m.group(2)
    return gadgets, dt


def load_ref_cache(cache_dir, name):
    """Load a precomputed oracle dump: {"0xvaddr|hex": text}."""
    path = os.path.join(cache_dir, name + ".json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return {parse_key(k): v for k, v in raw.items()}


def run_ours(binary, fixture_path, extra, runs=1):
    """{(vaddr, bytes): text}, best-of-N seconds — or (None, None) if the
    architecture is unsupported (exit code 2)."""
    best = None
    p = None
    for _ in range(runs):
        t0 = time.perf_counter()
        p = subprocess.run(
            [binary, "--binary", fixture_path, "--depth", str(DEPTH), "--json"] + list(extra),
            capture_output=True,
            text=True,
        )
        dt = time.perf_counter() - t0
        if p.returncode == 2:
            return None, None
        if p.returncode != 0:
            sys.exit(f"rop-finder failed on {fixture_path}:\n{p.stdout}\n{p.stderr}")
        best = dt if best is None else min(best, dt)
    return {(int(g["vaddr"], 16), g["bytes"]): g["text"] for g in json.loads(p.stdout)}, best


# --------------------------------------------------------------------------
# baseline I/O
# --------------------------------------------------------------------------
def baseline_path(name, baseline_dir=None):
    return os.path.join(baseline_dir or BASELINE_DIR, name + ".json")


def load_baseline(name, baseline_dir=None):
    path = baseline_path(name, baseline_dir)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save_baseline(name, data, baseline_dir=None):
    os.makedirs(baseline_dir or BASELINE_DIR, exist_ok=True)
    with open(baseline_path(name, baseline_dir), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")


# --------------------------------------------------------------------------
# known divergences
# --------------------------------------------------------------------------
class Divergences:
    """Normalized known-divergences: key-set waivers plus text budgets.

    `waivers` is {(fixture, direction): [waiver, ...]}, where `fixture` may be
    the wildcard "*".  Each waiver carries at least one of `keys`, `max_count`
    or `match`, so it can never excuse an unbounded set.  `text_budgets` is
    {fixture: [budget, ...]} for divergences that leave the (vaddr, bytes) set
    alone and only change gadget TEXT.
    """

    def __init__(self):
        self.waivers = {}
        self.text_budgets = {}

    def __len__(self):
        return sum(len(v) for v in self.waivers.values()) + sum(
            len(v) for v in self.text_budgets.values()
        )

    def add_waiver(self, fixture, direction, waiver):
        self.waivers.setdefault((fixture, direction), []).append(waiver)

    def add_text_budget(self, fixture, budget):
        self.text_budgets.setdefault(fixture, []).append(budget)

    def for_fixture(self, fixture, direction):
        return self.waivers.get((fixture, direction), []) + self.waivers.get(
            ("*", direction), []
        )


def _die(eid, msg):
    sys.exit(f"known-divergences.json: entry {eid!r} {msg}")


def load_known_divergences():
    """Parse tests/known-divergences.json into a `Divergences`.

    Two entry shapes are accepted, because the divergence list and this
    harness were written against each other's documentation rather than
    against a shared implementation:

    * the harness-native shape -- `direction` ("ours_only"/"ref_only") plus an
      explicit `keys` list or an integer `max_count`;
    * the descriptive shape -- an `effect` of "text-only", "disjoint-set" or
      "extra-gadgets" with an `expect`/`measured` block, which is what
      tests/known-divergences.json actually ships.

    Either way the invariant is the same and is enforced here: a waiver must
    be BOUNDED, by an exact key list, a count, or a regex the excused gadget's
    text has to match.  A blanket per-fixture waiver is not expressible, so an
    intentional divergence cannot be used to hide an accidental one.
    """
    divs = Divergences()
    if not os.path.exists(KNOWN_DIVERGENCES):
        return divs
    with open(KNOWN_DIVERGENCES, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    for entry in doc.get("divergences", []):
        eid = entry.get("id", "?")
        fixture = entry.get("fixture")
        if not fixture:
            _die(eid, "has no `fixture` (use \"*\" for any)")
        if not entry.get("reason"):
            _die(eid, "has no `reason`")
        reason = entry["reason"]
        effect = entry.get("effect")

        if effect is None:
            direction = entry.get("direction")
            if direction not in ("ours_only", "ref_only"):
                _die(
                    eid,
                    f"has direction {direction!r}; expected 'ours_only' or 'ref_only' "
                    "(or an `effect`)",
                )
            has_keys = isinstance(entry.get("keys"), list)
            has_cap = isinstance(entry.get("max_count"), int)
            if not (has_keys or has_cap):
                _die(
                    eid,
                    "must give either an explicit `keys` list or an integer "
                    "`max_count`: a blanket per-fixture waiver is not accepted",
                )
            divs.add_waiver(
                fixture,
                direction,
                {
                    "id": eid,
                    "keys": entry.get("keys") if has_keys else None,
                    "max_count": entry.get("max_count") if has_cap else None,
                    "match": None,
                    "reason": reason,
                },
            )
            continue

        expect = entry.get("expect") or {}
        measured = entry.get("measured") or {}

        if effect == "text-only":
            # The (vaddr, bytes) sets must still agree EXACTLY; only the
            # rendered text may differ, and by no more than the recorded
            # budget.  Nothing is excused in the key-set dimension.
            budget = expect.get("max_text_differences")
            if not isinstance(budget, int):
                _die(eid, "effect 'text-only' needs an integer `expect.max_text_differences`")
            if not expect.get("vaddr_bytes_set_equal"):
                _die(eid, "effect 'text-only' must assert `expect.vaddr_bytes_set_equal`")
            divs.add_text_budget(
                fixture,
                {"id": eid, "max_text_differences": budget, "reason": reason},
            )
        elif effect == "disjoint-set":
            # The two tools decoded the image in different instruction sets, so
            # the sets are not comparable.  Bounded by the measured totals: a
            # NEW divergence beyond what was measured still fails.
            ours_cap = measured.get("ours_gadgets")
            ref_cap = measured.get("oracle_gadgets")
            if not isinstance(ours_cap, int) or not isinstance(ref_cap, int):
                _die(
                    eid,
                    "effect 'disjoint-set' needs integer `measured.ours_gadgets` "
                    "and `measured.oracle_gadgets` to bound the waiver",
                )
            divs.add_waiver(
                fixture,
                "ours_only",
                {"id": eid, "keys": None, "max_count": ours_cap, "match": None, "reason": reason},
            )
            divs.add_waiver(
                fixture,
                "ref_only",
                {"id": eid, "keys": None, "max_count": ref_cap, "match": None, "reason": reason},
            )
        elif effect == "extra-gadgets":
            # Our set may be a superset, but ONLY of gadgets whose text matches
            # the recorded regex -- that regex is the bound.
            pat = expect.get("extra_gadgets_must_match") or entry.get("match")
            if not pat:
                _die(
                    eid,
                    "effect 'extra-gadgets' needs `expect.extra_gadgets_must_match` "
                    "(or `match`) to bound which extras are excused",
                )
            divs.add_waiver(
                fixture,
                "ours_only",
                {
                    "id": eid,
                    "keys": None,
                    "max_count": expect.get("max_extra"),
                    "match": re.compile(pat),
                    "reason": reason,
                },
            )
        else:
            _die(
                eid,
                f"has unknown effect {effect!r}; expected 'text-only', "
                "'disjoint-set' or 'extra-gadgets'",
            )
    return divs


def excuse(divs, fixture, direction, keys, texts):
    """Split `keys` into (excused, remaining, notes).

    `texts` maps key -> rendered gadget text, so a `match`-bounded waiver can
    check that every gadget it excuses really is the kind it claims to excuse.
    """
    entries = divs.for_fixture(fixture, direction)
    if not entries:
        return set(), set(keys), []
    remaining = set(keys)
    excused = set()
    notes = []
    for entry in entries:
        eid = entry["id"]
        if entry["keys"] is not None:
            want = {parse_key(k) for k in entry["keys"]}
            hit = want & remaining
            miss = want - remaining
            remaining -= hit
            excused |= hit
            notes.append((eid, len(hit), len(miss), entry["reason"]))
            continue
        pool = remaining
        if entry["match"] is not None:
            pool = {k for k in remaining if entry["match"].search(texts.get(k, ""))}
        cap = entry["max_count"]
        take = set(sorted(pool)) if cap is None else set(sorted(pool)[:cap])
        remaining -= take
        excused |= take
        unused = "" if cap is None else max(0, cap - len(take))
        notes.append((eid, len(take), unused if unused != "" else 0, entry["reason"]))
    return excused, remaining, notes


# --------------------------------------------------------------------------
# comparison
# --------------------------------------------------------------------------
def compare(name, ref, ours, divs):
    ref_keys, our_keys = set(ref), set(ours)
    matched = ref_keys & our_keys
    ref_only_all = ref_keys - our_keys
    our_only_all = our_keys - ref_keys

    ref_ex, ref_only, ref_notes = excuse(divs, name, "ref_only", ref_only_all, ref)
    our_ex, our_only, our_notes = excuse(divs, name, "ours_only", our_only_all, ours)

    text_exact = sum(1 for k in matched if ref[k] == ours[k])
    text_norm = sum(1 for k in matched if norm_text(ref[k]) == norm_text(ours[k]))

    # `text-only` divergences (ANCH-04): the key sets must still be identical
    # and the text differences must stay inside the recorded budget.  This is
    # the half of the waiver that can still go red.
    text_budget_failures = []
    for b in divs.text_budgets.get(name, []) + divs.text_budgets.get("*", []):
        if ref_only_all or our_only_all:
            text_budget_failures.append(
                f"known-divergence {b['id']} asserts the (vaddr,bytes) sets are equal, "
                f"but ref-only={len(ref_only_all)} ours-only={len(our_only_all)}"
            )
        divergent = len(matched) - text_norm
        if divergent > b["max_text_differences"]:
            text_budget_failures.append(
                f"known-divergence {b['id']}: {divergent} text differences > "
                f"budget {b['max_text_differences']}"
            )
        ref_notes.append((b["id"], len(matched) - text_norm, 0, b["reason"]))

    return {
        "_text_budget_failures": text_budget_failures,
        "ref_total": len(ref_keys),
        "ours_total": len(our_keys),
        "matched": len(matched),
        "ref_only": len(ref_only),
        "ours_only": len(our_only),
        "ref_only_excused": len(ref_ex),
        "ours_only_excused": len(our_ex),
        "text_exact": text_exact,
        "text_normalized": text_norm,
        "text_divergent": len(matched) - text_norm,
        "coverage_pct": round(100.0 * len(matched) / len(ref_keys), 4) if ref_keys else 100.0,
        "_notes": ref_notes + our_notes,
        "_ref_only_keys": sorted(ref_only),
        "_ours_only_keys": sorted(our_only),
    }


def check_floor(res, floor):
    """List of human-readable regression strings (empty == pass)."""
    bad = []
    # `min_matched` protects the OVERLAP with the oracle, which is zero by
    # definition on a disjoint-set fixture (ANCH-06): its floor is legitimately
    # 0, and without this clause the fixture could drop to no gadgets at all
    # and still pass.  Absent in older baselines -> treated as 0.
    if res["ours_total"] < floor.get("min_ours_total", 0):
        bad.append(
            f"our own gadget count {res['ours_total']} < floor "
            f"{floor['min_ours_total']} (output collapsed)"
        )
    if res["matched"] < floor["min_matched"]:
        bad.append(
            f"matched {res['matched']} < floor {floor['min_matched']} "
            f"(-{floor['min_matched'] - res['matched']} gadgets)"
        )
    if res["ours_only"] > floor["max_ours_only"]:
        bad.append(
            f"ours-only {res['ours_only']} > floor {floor['max_ours_only']} "
            f"(+{res['ours_only'] - floor['max_ours_only']} fabricated/divergent)"
        )
    if res["text_normalized"] < floor["min_text_normalized"]:
        bad.append(
            f"text-normalized matches {res['text_normalized']} < floor "
            f"{floor['min_text_normalized']}"
        )
    return bad


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--release", action="store_true", default=True)
    ap.add_argument("--debug", dest="release", action="store_false")
    ap.add_argument("--fixture", help="only this fixture (substring match)")
    ap.add_argument("--top", type=int, default=10, help="examples printed per direction")
    ap.add_argument(
        "--oracle-cache",
        help="directory of precomputed oracle dumps (<fixture>.json: key -> text); "
        "avoids running ROPgadget",
    )
    ap.add_argument(
        "--seed-reference",
        action="store_true",
        help="(re)write the oracle `reference` block of each baseline file",
    )
    ap.add_argument(
        "--update-floor",
        action="store_true",
        help="raise floors to the measured values (never lowers)",
    )
    ap.add_argument(
        "--force-lower",
        action="store_true",
        help="with --update-floor, also allow floors to move DOWN (records a regression)",
    )
    ap.add_argument(
        "--allow-oracle-drift",
        action="store_true",
        help="report, but do not fail on, a mismatch against the committed oracle reference",
    )
    ap.add_argument(
        "--baseline-dir",
        help="use this directory instead of tests/parity-baseline (a CI runner "
        "freezes its own, because the oracle is not bit-identical across platforms)",
    )
    ap.add_argument("--runs", type=int, default=1, help="rop-finder timing runs (best-of-N)")
    args = ap.parse_args()

    names = rf_paths.fixture_names()
    if args.fixture:
        names = [n for n in names if args.fixture in n]
    if not names:
        sys.exit("no fixtures matched")

    binary = None
    if not args.seed_reference:
        binary = rf_paths.rop_finder(release=args.release)

    divs = load_known_divergences()
    print(f"# environment: {rf_paths.describe_environment()}")
    if binary:
        print(f"# rop-finder:  {binary}")
    if len(divs):
        print(f"# known divergences: {len(divs)} entries from {KNOWN_DIVERGENCES}")
    baseline_dir = args.baseline_dir or BASELINE_DIR
    print(f"# baselines:   {baseline_dir}")

    failures = []       # regressions -> exit 1
    drift = []          # oracle moved -> exit 1 unless --allow-oracle-drift
    missing = []        # no committed baseline -> exit 1
    stale_divs = []
    excused_total = {}
    wildcard_ids = {
        w["id"]
        for (fx, _d), ws in divs.waivers.items()
        if fx == "*"
        for w in ws
    }
    totals = {"ref": 0, "ours": 0, "matched": 0, "text_norm": 0, "ours_only": 0}
    seeded = 0

    for name in names:
        path = rf_paths.fixture_path(name)
        extra = EXTRA_FLAGS.get(name, [])

        ref = None
        if args.oracle_cache:
            ref = load_ref_cache(args.oracle_cache, name)
        if ref is None:
            ref, _ = run_ref(path, extra)
        if ref is None:
            print(f"\n=== {name}\n  SKIP - the oracle itself cannot handle this binary")
            continue

        live = {"count": len(ref), "sha256_vaddr_bytes_set": set_digest(ref.keys())}
        base = load_baseline(name, baseline_dir)

        if args.seed_reference:
            base = base or {
                "fixture": name,
                "oracle": {
                    "ropgadget_commit": rf_paths.ORACLE_COMMIT,
                    "capstone": rf_paths.ORACLE_CAPSTONE,
                    "depth": DEPTH,
                    "extra_flags": extra,
                },
                "floor": None,
                "recorded": None,
            }
            base["reference"] = live
            base["oracle"]["extra_flags"] = extra
            save_baseline(name, base, baseline_dir)
            seeded += 1
            print(f"=== {name}\n  seeded reference: {live['count']} gadgets  {live['sha256_vaddr_bytes_set'][:16]}...")
            continue

        if base is None:
            missing.append(name)
            print(f"\n=== {name}\n  NO BASELINE - run --seed-reference (this is a failure)")
            continue

        want = base.get("reference") or {}
        if want.get("sha256_vaddr_bytes_set") != live["sha256_vaddr_bytes_set"]:
            drift.append(
                f"{name}: oracle reference {want.get('count')} gadgets "
                f"{str(want.get('sha256_vaddr_bytes_set'))[:16]}... but this oracle produced "
                f"{live['count']} gadgets {live['sha256_vaddr_bytes_set'][:16]}..."
            )

        ours, _ = run_ours(
            binary, path, extra + OURS_ONLY_FLAGS.get(name, []), runs=args.runs
        )
        if ours is None:
            failures.append(f"{name}: rop-finder reports this architecture unsupported (exit 2)")
            print(f"\n=== {name}\n  FAIL - rop-finder exited 2 (unsupported) but a baseline exists")
            continue

        res = compare(name, ref, ours, divs)
        totals["ref"] += res["ref_total"]
        totals["ours"] += res["ours_total"]
        totals["matched"] += res["matched"]
        totals["text_norm"] += res["text_normalized"]
        totals["ours_only"] += res["ours_only"]

        floor = base.get("floor")
        print(f"\n=== {name}")
        print(
            f"  |ref|={res['ref_total']}  |ours|={res['ours_total']}  matched={res['matched']}"
            f"  ref-only={res['ref_only']}  ours-only={res['ours_only']}"
            f"  ({res['coverage_pct']}% of ref)"
        )
        print(
            f"  text: exact={res['text_exact']}  normalized={res['text_normalized']}"
            f"  divergent={res['text_divergent']}"
        )
        for eid, hit, miss, reason in res["_notes"]:
            print(f"  known-divergence {eid}: excused {hit} (unused {miss}) - {reason}")
            excused_total[eid] = excused_total.get(eid, 0) + hit
            # A wildcard entry is offered to every fixture, so "excused nothing
            # here" is normal; it is stale only if it excused nothing ANYWHERE.
            # Judged once after the loop, not 24 times inside it.
            if hit == 0 and eid not in wildcard_ids:
                stale_divs.append(f"{name}: divergence {eid} excused nothing")
        for tbf in res["_text_budget_failures"]:
            failures.append(f"{name}: {tbf}")
            print(f"  REGRESSION: {tbf}")

        for k in res["_ref_only_keys"][: args.top]:
            print(f"    ref-only  {k[0]:#x} : {ref[k]}  // {k[1]}")
        for k in res["_ours_only_keys"][: args.top]:
            print(f"    ours-only {k[0]:#x} : {ours[k]}  // {k[1]}")

        if floor is None:
            if not args.update_floor:
                missing.append(f"{name} (no floor)")
                print("  NO FLOOR - run --update-floor (this is a failure)")
        else:
            bad = check_floor(res, floor)
            for b in bad:
                failures.append(f"{name}: {b}")
                print(f"  REGRESSION: {b}")
            if not bad:
                print("  ok - at or above the committed floor")

        if args.update_floor:
            old = floor or {
                "min_matched": 0,
                "max_ours_only": 10**12,
                "min_text_normalized": 0,
                "min_ours_total": 0,
            }
            new = {
                "min_matched": res["matched"],
                "max_ours_only": res["ours_only"],
                "min_text_normalized": res["text_normalized"],
                "min_ours_total": res["ours_total"],
            }
            if not args.force_lower:
                new["min_matched"] = max(new["min_matched"], old["min_matched"])
                new["max_ours_only"] = min(new["max_ours_only"], old["max_ours_only"])
                new["min_text_normalized"] = max(
                    new["min_text_normalized"], old["min_text_normalized"]
                )
                new["min_ours_total"] = max(
                    new["min_ours_total"], old.get("min_ours_total", 0)
                )
            base["floor"] = new
            base["recorded"] = {
                k: v for k, v in res.items() if not k.startswith("_")
            }
            base["recorded"]["environment"] = rf_paths.describe_environment(brief=True)
            base["recorded"]["when"] = time.strftime("%Y-%m-%d")
            save_baseline(name, base, baseline_dir)

    if args.seed_reference:
        print(f"\nseeded {seeded} reference blocks under {baseline_dir}")
        return 0

    print("\n=== TOTAL")
    cov = 100.0 * totals["matched"] / totals["ref"] if totals["ref"] else 100.0
    print(
        f"  |ref|={totals['ref']}  |ours|={totals['ours']}  matched={totals['matched']}"
        f"  ours-only={totals['ours_only']}  coverage={cov:.4f}%"
    )
    if totals["matched"]:
        tn = 100.0 * totals["text_norm"] / totals["matched"]
        print(
            f"  gadget-text agreement on matched gadgets: {totals['text_norm']} "
            f"({tn:.4f}%), divergent {totals['matched'] - totals['text_norm']}"
        )

    for eid in sorted(wildcard_ids):
        if excused_total.get(eid, 0) == 0:
            stale_divs.append(
                f"(any fixture): divergence {eid} excused nothing across the whole run"
            )

    status = 0
    if drift:
        print("\n=== ORACLE DRIFT (the reference moved, not rop-finder)")
        for d in drift:
            print(f"  {d}")
        print(
            "  The committed reference was frozen against ROPgadget "
            f"{rf_paths.ORACLE_COMMIT} + capstone {rf_paths.ORACLE_CAPSTONE}. "
            "Re-freeze with --seed-reference only after confirming the new oracle is correct."
        )
        if not args.allow_oracle_drift:
            status = 1
    if stale_divs:
        print("\n=== STALE KNOWN-DIVERGENCES (excused nothing - delete or fix)")
        for s in stale_divs:
            print(f"  {s}")
    if missing:
        print("\n=== MISSING BASELINE")
        for m in missing:
            print(f"  {m}")
        status = 1
    if failures:
        print("\n=== REGRESSIONS BELOW THE COMMITTED BASELINE")
        for f in failures:
            print(f"  {f}")
        status = 1

    print("\nPARITY GATE: " + ("FAIL" if status else "PASS"))
    return status


if __name__ == "__main__":
    sys.exit(main())
