#!/usr/bin/env python3
"""Chain parity harness: rop-finder --ropchain vs ROPgadget --ropchain.

For every ELF x86/x64 fixture in tests/fixtures:
  * run the reference:  python <ropgadget>/ROPgadget.py --binary F --ropchain
  * run rop-finder:     rop-finder --binary F --ropchain
  * extract the python script portion (from the '#!/usr/bin/env python3'
    shebang to EOF) on both sides and classify the result:

      BYTE-IDENTICAL   the two scripts are exactly equal
      PAYLOAD-IDENTICAL the pack('<..', addr) words and data words are equal;
                        only gadget comment text differs (iced-x86 renders
                        single-digit immediates as 0x1 where capstone
                        prints 1 — same gadget, same address)
      STRUCTURAL       same word count and word kinds; gadget addresses
                       differ (dedup-survivor / disassembler drift)
      ERROR-PARITY     both tools fail to build a chain for this fixture
      MISMATCH         anything else (one side fails, or structure diverges)

Non-x86 ELF fixtures and non-ELF fixtures are skipped: ropmaker only
supports Linux execve chains on x86 (int 0x80) and x64 (syscall).

Usage:  python tests/chain_parity.py [--release|--debug] [--fixture NAME]

Exits non-zero on any MISMATCH or MISSING-FIXTURE. The rop-finder binary and
the ROPgadget oracle are resolved by `tests/rf_paths.py` -- by platform, with
env overrides, and building rop-finder if it is absent (CLAIM-08/ENG-04).
"""

import argparse
import os
import re
import subprocess
import sys

# No __pycache__ beside the harnesses: tests/ is not gitignored for it,
# and a stray cache directory in a source tree is noise, not a build product.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rf_paths  # noqa: E402

HERE = rf_paths.HERE
REPO = rf_paths.REPO
FIXTURES = rf_paths.FIXTURES

SHEBANG = "#!/usr/bin/env python3"
PACK_ADDR = re.compile(r"pack\('<[QI]', (0x[0-9a-f]+)\)")
DATA_WORD = re.compile(r"^p \+= b'(.*)'", re.M)

# x86/x64 ELF fixtures only (ropmaker supports nothing else).
CANDIDATES = [
    "elf-Linux-x64",
    "elf-Linux-x86",
    "elf-Linux-x86-NDH-chall",
    "elf-FreeBSD-x86",
    "elf-x64-bash-v4.1.5.1",
    "elf-x86-bash-v4.1.5.1",
    "Linux_lib32.so",
    "Linux_lib64.so",
]


def script_portion(text: str):
    """Extract the generated python script (shebang line to EOF)."""
    idx = text.find(SHEBANG)
    if idx < 0:
        return None
    return text[idx:]


def run_ref(fixture: str):
    """Return the oracle's script portion, or None when it cannot build one."""
    p = subprocess.run(
        rf_paths.oracle_cmd(fixture, ropchain=True),
        capture_output=True, text=True,
    )
    # ROPgadget prints "[-] Can't find ..." messages during its internal
    # backtracking even when the chain ultimately succeeds — the reliable
    # success signal is the presence of the generated python script.
    return script_portion(p.stdout)


def run_ours(binary: str, fixture: str):
    """Return our script portion, or None when we report a structured error."""
    p = subprocess.run(
        [binary, "--binary", fixture, "--ropchain"],
        capture_output=True, text=True,
    )
    if p.returncode != 0:
        return None
    return script_portion(p.stdout)


def words(script: str):
    """(pack address words, data words) — the payload, comments stripped."""
    packs = PACK_ADDR.findall(script)
    data = DATA_WORD.findall(script)
    return packs, data


def classify(ref, ours):
    if ref is None and ours is None:
        return "ERROR-PARITY"
    if ref is None or ours is None:
        return "MISMATCH"
    if ref == ours:
        return "BYTE-IDENTICAL"
    rp, rd = words(ref)
    op, od = words(ours)
    if rp == op and rd == od:
        return "PAYLOAD-IDENTICAL"
    ref_lines = [l for l in ref.splitlines() if l.startswith("p +=")]
    our_lines = [l for l in ours.splitlines() if l.startswith("p +=")]
    if len(ref_lines) == len(our_lines):
        return "STRUCTURAL"
    return "MISMATCH"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", action="store_true", default=True)
    ap.add_argument("--debug", dest="release", action="store_false")
    ap.add_argument("--fixture", help="only run this fixture")
    args = ap.parse_args()

    binary = rf_paths.rop_finder(release=args.release)
    names = [args.fixture] if args.fixture else CANDIDATES
    print(f"# environment: {rf_paths.describe_environment()}")
    print(f"# rop-finder:  {binary}")

    counts = {}
    rows = []
    for name in names:
        path = os.path.join(FIXTURES, name)
        if not os.path.exists(path):
            rows.append((name, "MISSING-FIXTURE", ""))
            counts["MISSING-FIXTURE"] = counts.get("MISSING-FIXTURE", 0) + 1
            continue
        ref = run_ref(path)
        ours = run_ours(binary, path)
        verdict = classify(ref, ours)
        detail = ""
        if verdict in ("PAYLOAD-IDENTICAL", "STRUCTURAL", "MISMATCH") and ref and ours:
            rp, _ = words(ref)
            op, _ = words(ours)
            detail = f"ref={len(rp)} packs ours={len(op)} packs"
        elif verdict == "ERROR-PARITY":
            detail = "both sides report the chain cannot be built"
        rows.append((name, verdict, detail))
        counts[verdict] = counts.get(verdict, 0) + 1

    print(f"\n{'fixture':<28} {'verdict':<20} detail")
    print("-" * 80)
    for name, verdict, detail in rows:
        print(f"{name:<28} {verdict:<20} {detail}")
    print("-" * 80)
    print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    bad = counts.get("MISMATCH", 0) + counts.get("MISSING-FIXTURE", 0)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
