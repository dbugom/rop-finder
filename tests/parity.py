#!/usr/bin/env python3
"""Parity harness: rop-finder vs ROPgadget (the reference oracle).

For every fixture in tests/fixtures:
  * run the reference:  python <ropgadget>/ROPgadget.py --binary F --depth 10 --dump
  * run rop-finder:     rop-finder --binary F --depth 10 --json
  * compare the post-dedup sets of (vaddr, bytes) and report
    |ref|, |ours|, |intersection|, ref-only, ours-only and % overlap.

A small number of diffs is expected and acceptable IF explained:
  * dedup-survivor differences (text dedup with different formatters)
  * iced-x86 vs capstone decode disagreements
  * ROPgadget scans executable PT_LOAD *segments*; rop-finder scans
    SHF_EXECINSTR *sections* (inter-section padding is not scanned)
Top 10 examples of each direction are printed for human judgement.

Usage:  python tests/parity.py [--release|--debug] [--fixture NAME] [--top N]
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)                       # rop-finder/
ROPGADGET = os.path.join(os.path.dirname(REPO), "ropgadget", "ROPgadget.py")
FIXTURES = os.path.join(HERE, "fixtures")
DEPTH = 10

REF_LINE = re.compile(r"^(0x[0-9a-f]+)\s*:\s*(.*?)\s*//\s*([0-9a-f]+)\s*$")


def find_rop_finder(release: bool) -> str:
    profile = "release" if release else "debug"
    exe = os.path.join(REPO, "target", profile, "rop-finder.exe")
    if not os.path.exists(exe):
        exe = exe[:-4]  # non-Windows
    if not os.path.exists(exe):
        sys.exit(f"rop-finder binary not found at {exe} — build it first")
    return exe


def run_ref(fixture: str):
    """Return ({(vaddr, bytes): text}, seconds)."""
    t0 = time.perf_counter()
    p = subprocess.run(
        [sys.executable, ROPGADGET, "--binary", fixture, "--depth", str(DEPTH), "--dump"],
        capture_output=True, text=True,
    )
    dt = time.perf_counter() - t0
    if p.returncode != 0:
        sys.exit(f"ROPgadget failed on {fixture}:\n{p.stdout}\n{p.stderr}")
    gadgets = {}
    for line in p.stdout.splitlines():
        m = REF_LINE.match(line)
        if m:
            gadgets[(int(m.group(1), 16), m.group(3))] = m.group(2)
    return gadgets, dt


def run_ours(binary: str, fixture: str, runs: int = 1):
    """Return ({(vaddr, bytes): text}, best-of-N seconds)."""
    gadgets = {}
    best = None
    for _ in range(runs):
        t0 = time.perf_counter()
        p = subprocess.run(
            [binary, "--binary", fixture, "--depth", str(DEPTH), "--json"],
            capture_output=True, text=True,
        )
        dt = time.perf_counter() - t0
        if p.returncode != 0:
            sys.exit(f"rop-finder failed on {fixture}:\n{p.stdout}\n{p.stderr}")
        best = dt if best is None else min(best, dt)
    for g in json.loads(p.stdout):
        gadgets[(int(g["vaddr"], 16), g["bytes"])] = g["text"]
    return gadgets, best


def compare(name, ref, ours, top):
    ref_keys, our_keys = set(ref), set(ours)
    inter = ref_keys & our_keys
    ref_only = sorted(ref_keys - our_keys)
    our_only = sorted(our_keys - ref_keys)
    cov = 100.0 * len(inter) / len(ref_keys) if ref_keys else 100.0
    prec = 100.0 * len(inter) / len(our_keys) if our_keys else 100.0
    print(f"\n=== {name}")
    print(f"  |ref|={len(ref_keys)}  |ours|={len(our_keys)}  |intersection|={len(inter)}"
          f"  ref-only={len(ref_only)}  ours-only={len(our_only)}")
    print(f"  overlap: {cov:.2f}% of ref found, {prec:.2f}% of ours match ref")
    if ref_only:
        print(f"  top {min(top, len(ref_only))} ref-only (in ROPgadget, missing in rop-finder):")
        for k in ref_only[:top]:
            print(f"    {k[0]:#x} : {ref[k]}  // {k[1]}")
    if our_only:
        print(f"  top {min(top, len(our_only))} ours-only (in rop-finder, missing in ROPgadget):")
        for k in our_only[:top]:
            print(f"    {k[0]:#x} : {ours[k]}  // {k[1]}")
    return len(ref_keys), len(our_keys), len(inter)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", action="store_true", default=False)
    ap.add_argument("--debug", dest="release", action="store_false")
    ap.add_argument("--fixture", help="only run this fixture (substring match)")
    ap.add_argument("--top", type=int, default=10)
    args = ap.parse_args()

    binary = find_rop_finder(args.release)
    names = sorted(os.listdir(FIXTURES))
    if args.fixture:
        names = [n for n in names if args.fixture in n]
    if not names:
        sys.exit("no fixtures matched")

    totals = [0, 0, 0]
    timing = {}
    for name in names:
        path = os.path.join(FIXTURES, name)
        ref, t_ref = run_ref(path)
        ours, t_ours = run_ours(binary, path, runs=3)
        timing[name] = (t_ref, t_ours)
        r, o, i = compare(name, ref, ours, args.top)
        totals[0] += r
        totals[1] += o
        totals[2] += i

    print("\n=== TOTAL")
    print(f"  |ref|={totals[0]}  |ours|={totals[1]}  |intersection|={totals[2]}"
          f"  overlap={100.0 * totals[2] / totals[0]:.2f}% of ref")

    print("\n=== TIMING (seconds; ROPgadget single run, rop-finder best of 3)")
    print(f"  {'fixture':<28} {'ROPgadget':>10} {'rop-finder':>11} {'speedup':>8}")
    for name, (t_ref, t_ours) in timing.items():
        print(f"  {name:<28} {t_ref:>10.3f} {t_ours:>11.3f} {t_ref / t_ours:>7.1f}x")


if __name__ == "__main__":
    main()
