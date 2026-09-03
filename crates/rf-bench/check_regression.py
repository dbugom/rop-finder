#!/usr/bin/env python3
"""Criterion regression gate (CLAIM-02 / PERF-08 / CLAIM-04).

`cargo bench -p rf-bench` writes one `estimates.json` per benchmark under
`target/criterion/`. This script turns those into a gate:

    cargo bench -p rf-bench
    python crates/rf-bench/check_regression.py --record       # freeze a baseline
    python crates/rf-bench/check_regression.py                # compare, exit 1 on regression

A benchmark is a REGRESSION when its median time exceeds the committed
baseline by more than `--band` (default 10%, the number PLAN/REMEDIATION name).
An improvement of more than the band is reported as IMPROVED, not a failure —
re-record the baseline to bank it.

Wall-clock benchmarks on shared CI runners are noisy, so two guards keep this
from being a flake generator:

  * `--band` is a *ratio* against a baseline recorded on the same job, and CI
    records its own baseline on the default branch rather than trusting one
    frozen on a developer's laptop (see the committed baseline's `environment`
    field — a comparison across different environments is reported and, unless
    `--cross-environment` is passed, refuses to fail the build).
  * `--min-ns` ignores benchmarks whose baseline is below a floor (default
    50 us), where timer resolution and scheduler noise dominate.

The committed `baseline.json` is a machine-specific artifact by construction.
It is committed anyway because a number nobody can diff is a number nobody
notices moving; the `environment` field says which machine produced it.
"""

import argparse
import json
import os
import platform
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
CRITERION_DIR = os.path.join(REPO, "target", "criterion")
BASELINE = os.path.join(HERE, "baseline.json")


def environment():
    return {
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
    }


def collect(criterion_dir):
    """{full_id: {median_ns, mean_ns, std_dev_ns, throughput}} from a bench run."""
    out = {}
    for root, _dirs, files in os.walk(criterion_dir):
        if os.path.basename(root) != "new" or "estimates.json" not in files:
            continue
        est_path = os.path.join(root, "estimates.json")
        bm_path = os.path.join(root, "benchmark.json")
        if not os.path.exists(bm_path):
            continue
        with open(bm_path, "r", encoding="utf-8") as fh:
            bm = json.load(fh)
        with open(est_path, "r", encoding="utf-8") as fh:
            est = json.load(fh)
        out[bm["full_id"]] = {
            "median_ns": est["median"]["point_estimate"],
            "mean_ns": est["mean"]["point_estimate"],
            "std_dev_ns": est["std_dev"]["point_estimate"],
            "throughput": bm.get("throughput"),
        }
    return out


def load_baseline(path):
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def fmt_ns(ns):
    for unit, scale in (("s", 1e9), ("ms", 1e6), ("us", 1e3)):
        if ns >= scale:
            return f"{ns / scale:.3f} {unit}"
    return f"{ns:.1f} ns"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--record", action="store_true", help="write the baseline instead of checking")
    ap.add_argument("--baseline", default=BASELINE)
    ap.add_argument("--criterion-dir", default=CRITERION_DIR)
    ap.add_argument("--band", type=float, default=0.10, help="allowed slowdown ratio (0.10 = 10%%)")
    ap.add_argument(
        "--min-ns",
        type=float,
        default=50_000.0,
        help="ignore benchmarks whose baseline median is below this (timer noise)",
    )
    ap.add_argument(
        "--cross-environment",
        action="store_true",
        help="fail even when the baseline was recorded on a different machine",
    )
    ap.add_argument(
        "--allow-missing",
        action="store_true",
        help="do not fail when the current run lacks a benchmark the baseline has",
    )
    args = ap.parse_args()

    current = collect(args.criterion_dir)
    if not current:
        sys.exit(
            f"no criterion results under {args.criterion_dir} - run `cargo bench -p rf-bench` first"
        )

    if args.record:
        payload = {
            "band": args.band,
            "environment": environment(),
            "benchmarks": {k: current[k] for k in sorted(current)},
        }
        with open(args.baseline, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"recorded {len(current)} benchmarks to {args.baseline}")
        for k in sorted(current):
            print(f"  {k:<34} {fmt_ns(current[k]['median_ns'])}")
        return 0

    base = load_baseline(args.baseline)
    if base is None:
        sys.exit(f"no baseline at {args.baseline} - record one with --record")

    same_env = base.get("environment") == environment()
    band = args.band
    print(f"# band:        {band * 100:.0f}% slower than baseline is a regression")
    print(f"# baseline:    {args.baseline}")
    print(f"# recorded on: {base.get('environment')}")
    print(f"# running on:  {environment()}")
    if not same_env:
        print(
            "# NOTE: different environment. Ratios are reported; they "
            + ("WILL" if args.cross_environment else "will NOT")
            + " fail the build (use --cross-environment to change that)."
        )
    print()

    regressions = []
    improvements = []
    missing = []
    rows = []
    for name in sorted(base["benchmarks"]):
        b = base["benchmarks"][name]
        cur = current.get(name)
        if cur is None:
            missing.append(name)
            continue
        if b["median_ns"] < args.min_ns:
            rows.append((name, b["median_ns"], cur["median_ns"], None, "below --min-ns"))
            continue
        ratio = cur["median_ns"] / b["median_ns"]
        status = ""
        if ratio > 1.0 + band:
            status = "REGRESSION"
            regressions.append((name, ratio))
        elif ratio < 1.0 - band:
            status = "improved"
            improvements.append((name, ratio))
        rows.append((name, b["median_ns"], cur["median_ns"], ratio, status))

    new = sorted(set(current) - set(base["benchmarks"]))
    width = max((len(r[0]) for r in rows), default=10)
    print(f"{'benchmark':<{width}}  {'baseline':>12}  {'current':>12}  {'ratio':>7}  status")
    for name, b_ns, c_ns, ratio, status in rows:
        r = f"{ratio:.3f}x" if ratio is not None else "   -   "
        print(f"{name:<{width}}  {fmt_ns(b_ns):>12}  {fmt_ns(c_ns):>12}  {r:>7}  {status}")

    if new:
        print("\nnew benchmarks not in the baseline (re-record to include them):")
        for n in new:
            print(f"  {n}")
    if missing:
        print("\nbenchmarks in the baseline but missing from this run:")
        for n in missing:
            print(f"  {n}")

    status = 0
    if regressions:
        print(f"\n{len(regressions)} REGRESSION(S) beyond the {band * 100:.0f}% band:")
        for name, ratio in regressions:
            print(f"  {name}: {(ratio - 1) * 100:.1f}% slower")
        if same_env or args.cross_environment:
            status = 1
        else:
            print("  (not failing the build: baseline was recorded on a different machine)")
    if improvements:
        print(f"\n{len(improvements)} improvement(s) beyond the band - re-record to bank them:")
        for name, ratio in improvements:
            print(f"  {name}: {(1 - ratio) * 100:.1f}% faster")
    if missing and not args.allow_missing:
        status = 1

    print("\nBENCH GATE: " + ("FAIL" if status else "PASS"))
    return status


if __name__ == "__main__":
    sys.exit(main())
