#!/usr/bin/env python3
"""Analyze parity diffs: categorize ref-only and ours-only gadgets.

Categories for ref-only:
  SEGMENT_ONLY  - vaddr is not inside any SHF_EXECINSTR section (ROPgadget
                  scans whole PT_LOAD X segments incl. headers/padding)
  TEXT_DEDUP    - vaddr inside exec sections; an ours gadget with the SAME
                  (normalized) text exists elsewhere -> dedup survivor differs
  DECODE        - otherwise (likely capstone vs iced-x86 decode disagreement)

Usage: python tests/analyze_diff.py <fixture>
"""
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
ROPGADGET = os.path.join(os.path.dirname(REPO), "ropgadget", "ROPgadget.py")
REF_LINE = re.compile(r"^(0x[0-9a-f]+)\s*:\s*(.*?)\s*//\s*([0-9a-f]+)\s*$")


def exec_sections(path):
    with open(path, "rb") as fh:
        data = fh.read()
    assert data[:4] == b"\x7fELF"
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    if is64:
        shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        shentsize, shnum = struct.unpack_from(endian + "HH", data, 0x3A)
        out = []
        for i in range(shnum):
            base = shoff + i * shentsize
            flags, addr, _off, size = struct.unpack_from(endian + "QQQQ", data, base + 8)
            if flags & 0x4:  # SHF_EXECINSTR
                out.append((addr, addr + size))
    else:
        shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        shentsize, shnum = struct.unpack_from(endian + "HH", data, 0x2E)
        out = []
        for i in range(shnum):
            base = shoff + i * shentsize
            flags, addr, _off, size = struct.unpack_from(endian + "IIII", data, base + 8)
            if flags & 0x4:
                out.append((addr, addr + size))
    return out


def run(cmd, is_ref):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"failed: {cmd}\n{p.stdout}{p.stderr}")
    g = {}
    if is_ref:
        for line in p.stdout.splitlines():
            m = REF_LINE.match(line)
            if m:
                g[(int(m.group(1), 16), m.group(3))] = m.group(2)
    else:
        for x in json.loads(p.stdout):
            g[(int(x["vaddr"], 16), x["bytes"])] = x["text"]
    return g


def norm(text):
    """Normalize whitespace/ptr spelling for fuzzy text comparison."""
    t = re.sub(r"\s+", "", text).replace("0x0", "0")
    t = re.sub(r"0x0*([0-9a-f])", r"\1", t)
    return t


def main():
    fixture = sys.argv[1]
    exe = os.path.join(REPO, "target", "release", "rop-finder.exe")
    ref = run([sys.executable, ROPGADGET, "--binary", fixture, "--depth", "10", "--dump"], True)
    ours = run([exe, "--binary", fixture, "--depth", "10", "--json"], False)
    secs = exec_sections(fixture)

    ref_only = sorted(set(ref) - set(ours))
    our_only = sorted(set(ours) - set(ref))

    # map normalized text -> count, for dedup-survivor detection
    our_texts = {}
    for t in ours.values():
        our_texts.setdefault(norm(t), set()).add(t)
    ref_texts = {}
    for t in ref.values():
        ref_texts.setdefault(norm(t), set()).add(t)

    cats = {"SEGMENT_ONLY": [], "TEXT_MATCH_OURS": [], "DECODE?": []}
    for k in ref_only:
        v = k[0]
        if not any(a <= v < b for a, b in secs):
            cats["SEGMENT_ONLY"].append(k)
        elif norm(ref[k]) in our_texts:
            cats["TEXT_MATCH_OURS"].append(k)
        else:
            cats["DECODE?"].append(k)

    ocats = {"TEXT_MATCH_REF": [], "DECODE?": []}
    for k in our_only:
        if norm(ours[k]) in ref_texts:
            ocats["TEXT_MATCH_REF"].append(k)
        else:
            ocats["DECODE?"].append(k)

    print(f"ref-only={len(ref_only)} ours-only={len(our_only)}")
    for c, ks in cats.items():
        print(f"  ref-only {c}: {len(ks)}")
        for k in ks[:8]:
            print(f"    {k[0]:#x} : {ref[k]} // {k[1]}")
    for c, ks in ocats.items():
        print(f"  ours-only {c}: {len(ks)}")
        for k in ks[:8]:
            print(f"    {k[0]:#x} : {ours[k]} // {k[1]}")


if __name__ == "__main__":
    main()
