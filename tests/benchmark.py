#!/usr/bin/env python3
"""Competitor benchmark: rop-finder vs ROPgadget vs ropper.

Methodology: wall-clock best-of-3, full gadget scan, stdout to devnull.
Tool configuration notes (honest-comparison caveats):
  - rop-finder / ROPgadget: --depth 10, ROP+JOP+SYS (defaults).
  - ropper: no depth flag; scans ret/jmp/call endings with its own defaults.
Gadget counts are informational only (tool semantics differ).
"""
import subprocess, sys, time, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RF = os.path.join(ROOT, "target", "release", "rop-finder.exe")
FIX = os.path.join(ROOT, "tests", "fixtures")

CASES = ["elf-x64-bash-v4.1.5.1", "elf-Linux-x86", "pe-x64-cmd-v6.1.7601"]

def bench(cmd, runs=3, timeout=900):
    best = None
    for _ in range(runs):
        t0 = time.perf_counter()
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return None
        dt = time.perf_counter() - t0
        best = dt if best is None else min(best, dt)
    return best

def count_rf(fx):
    out = subprocess.run([RF, "--binary", fx, "--depth", "10"],
                         capture_output=True, text=True).stdout
    return int(out.split("Unique gadgets found:")[1].strip())

def count_ropgadget(fx):
    out = subprocess.run([sys.executable, os.path.join(ROOT, "..", "ropgadget", "ROPgadget.py"),
                          "--binary", fx, "--depth", "10"], capture_output=True, text=True).stdout
    return int(out.split("Unique gadgets found:")[1].strip())

def count_ropper(fx):
    out = subprocess.run([sys.executable, "-m", "ropper", "--file", fx, "--nocolor"],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if "gadgets" in line.lower() and ("found" in line.lower() or "loaded" in line.lower()):
            nums = [int(t) for t in line.replace(",", " ").split() if t.isdigit()]
            if nums:
                return nums[0]
    return -1

print(f"{'fixture':<26} {'tool':<12} {'best-of-3 (s)':>13} {'gadgets':>9}")
print("-" * 64)
for case in CASES:
    fx = os.path.join(FIX, case)
    tools = [
        ("rop-finder", [RF, "--binary", fx, "--depth", "10"], count_rf),
        ("ROPgadget", [sys.executable, os.path.join(ROOT, "..", "ropgadget", "ROPgadget.py"),
                       "--binary", fx, "--depth", "10"], count_ropgadget),
        ("ropper", [sys.executable, "-m", "ropper", "--file", fx, "--nocolor"], count_ropper),
    ]
    results = {}
    for name, cmd, counter in tools:
        t = bench(cmd)
        try:
            n = counter(fx)
        except Exception:
            n = -1
        results[name] = t
        print(f"{case:<26} {name:<12} {('%.3f' % t) if t else 'TIMEOUT':>13} {n:>9}")
    if results.get("rop-finder") and results.get("ROPgadget"):
        print(f"{'':<26} {'speedup':<12} {results['ROPgadget']/results['rop-finder']:>12.1f}x")
    if results.get("rop-finder") and results.get("ropper"):
        print(f"{'':<26} {'vs ropper':<12} {results['ropper']/results['rop-finder']:>12.1f}x")
    print("-" * 64)
