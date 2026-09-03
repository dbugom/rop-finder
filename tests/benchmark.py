#!/usr/bin/env python3
"""Competitor benchmark: rop-finder vs ROPgadget vs ropper.

CLAIM-08/PERF-08.  This file used to open with

    RF = os.path.join(ROOT, "target", "release", "rop-finder.exe")

with no fallback of any kind, so on macOS/Linux it died with
``OSError: [Errno 8] Exec format error`` before printing a number — and the
speed figures in README/MANUAL were reproducible only on the author's Windows
box.  It also ran the oracle with ``sys.executable``, which is only the right
interpreter if the one running this script happens to have python-capstone.
Both are resolved by :mod:`rf_paths` now.

Methodology: wall-clock best-of-N, full gadget scan, stdout to devnull.
Tool configuration notes (honest-comparison caveats):
  - rop-finder / ROPgadget: --depth 10, ROP+JOP+SYS (defaults).
  - ropper: no depth flag; scans ret/jmp/call endings with its own defaults.
Gadget counts are informational only (tool semantics differ).

`ropper` is optional: when it is not importable the row is reported as
`not installed` rather than crashing the run.

Usage:
    python tests/benchmark.py
    python tests/benchmark.py --runs 5 --json out.json
    python tests/benchmark.py --case elf-Linux-x86 --no-ropper
"""

import argparse
import json
import os
import subprocess
import sys
import time

# No __pycache__ beside the harnesses: tests/ is not gitignored for it,
# and a stray cache directory in a source tree is noise, not a build product.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rf_paths  # noqa: E402

CASES = ["elf-x64-bash-v4.1.5.1", "elf-Linux-x86", "pe-x64-cmd-v6.1.7601"]
DEPTH = 10


def bench(cmd, runs, timeout=900):
    best = None
    for _ in range(runs):
        t0 = time.perf_counter()
        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None
        except OSError as exc:
            print(f"  [skip] {cmd[0]}: {exc}", file=sys.stderr)
            return None
        dt = time.perf_counter() - t0
        best = dt if best is None else min(best, dt)
    return best


def _count_after(out, marker):
    if marker not in out:
        return -1
    tail = out.split(marker)[1].strip().split()
    return int(tail[0]) if tail and tail[0].isdigit() else -1


def count_rf(rf, fx):
    out = subprocess.run(
        [rf, "--binary", fx, "--depth", str(DEPTH)], capture_output=True, text=True
    ).stdout
    return _count_after(out, "Unique gadgets found:")


def count_ropgadget(fx):
    out = subprocess.run(
        rf_paths.oracle_cmd(fx, dump=False, depth=DEPTH), capture_output=True, text=True
    ).stdout
    return _count_after(out, "Unique gadgets found:")


def count_ropper(ropper_py, fx):
    out = subprocess.run(
        [ropper_py, "-m", "ropper", "--file", fx, "--nocolor"], capture_output=True, text=True
    ).stdout
    for line in out.splitlines():
        low = line.lower()
        if "gadgets" in low and ("found" in low or "loaded" in low):
            nums = [int(t) for t in line.replace(",", " ").split() if t.isdigit()]
            if nums:
                return nums[0]
    return -1


def find_ropper():
    """Interpreter that can `-m ropper`, or None. Never fatal."""
    candidates = [sys.executable]
    res = rf_paths.oracle(required=False)
    if res:
        candidates.insert(0, res[0])
    for interp in candidates:
        try:
            p = subprocess.run(
                [interp, "-c", "import ropper"], capture_output=True, timeout=60
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode == 0:
            return interp
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--case", action="append", help="fixture name (repeatable)")
    ap.add_argument("--no-ropper", action="store_true")
    ap.add_argument("--json", dest="json_out", help="also write results here")
    ap.add_argument("--release", action="store_true", default=True)
    ap.add_argument("--debug", dest="release", action="store_false")
    args = ap.parse_args()

    rf = rf_paths.rop_finder(release=args.release)
    ropper_py = None if args.no_ropper else find_ropper()

    print(f"# environment: {rf_paths.describe_environment()}")
    print(f"# rop-finder:  {rf}")
    print(f"# ropper:      {ropper_py or 'not installed (rows reported as n/a)'}")
    print(f"# best-of-{args.runs}, --depth {DEPTH}, stdout discarded\n")

    cases = args.case or CASES
    results = {}
    print(f"{'fixture':<26} {'tool':<12} {'best-of-N (s)':>13} {'gadgets':>9}")
    print("-" * 64)
    for case in cases:
        fx = rf_paths.fixture_path(case)
        if not os.path.exists(fx):
            print(f"{case:<26} {'MISSING FIXTURE':<12}")
            continue
        row = {}
        tools = [
            ("rop-finder", [rf, "--binary", fx, "--depth", str(DEPTH)], lambda: count_rf(rf, fx)),
            (
                "ROPgadget",
                rf_paths.oracle_cmd(fx, dump=False, depth=DEPTH),
                lambda: count_ropgadget(fx),
            ),
        ]
        if ropper_py:
            tools.append(
                (
                    "ropper",
                    [ropper_py, "-m", "ropper", "--file", fx, "--nocolor"],
                    lambda: count_ropper(ropper_py, fx),
                )
            )
        for name, cmd, counter in tools:
            t = bench(cmd, args.runs)
            try:
                n = counter()
            except Exception:  # noqa: BLE001 - a counter failure must not kill the run
                n = -1
            row[name] = {"seconds": t, "gadgets": n}
            print(f"{case:<26} {name:<12} {('%.3f' % t) if t else 'TIMEOUT':>13} {n:>9}")
        if not ropper_py:
            print(f"{case:<26} {'ropper':<12} {'n/a':>13} {'n/a':>9}")
        rfs = row.get("rop-finder", {}).get("seconds")
        for other in ("ROPgadget", "ropper"):
            os_ = row.get(other, {}).get("seconds")
            if rfs and os_:
                row[f"speedup_vs_{other}"] = round(os_ / rfs, 2)
                print(f"{'':<26} {'vs ' + other:<12} {os_ / rfs:>12.1f}x")
        results[case] = row
        print("-" * 64)

    if args.json_out:
        payload = {
            "environment": rf_paths.describe_environment(brief=True),
            "runs": args.runs,
            "depth": DEPTH,
            "results": results,
        }
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
