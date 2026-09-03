#!/usr/bin/env python3
"""CLI-12 conformance gate: every ROPgadget flag, on every fixture.

Why this exists
---------------
v0.1.1's MANUAL published a flag-coverage table and the audit's CLI-12
finding counted the unimplemented rows.  A table is a claim, and the claim
that closed the finding was "the table now has no unimplemented rows".  That
is only half an answer: **a flag that exists but behaves differently is worse
than a missing one**, because a missing flag fails loudly at the shell while
a wrong one silently returns a different gadget set.  ``--filter`` shipped as
a literal suffix match for a whole release while the table said
"implemented"; ``--align`` filtered unaligned starts instead of stepping to
them; ``--range`` was applied once where the oracle applies it twice.  None
of those were catchable by reading the table.

So this harness does not read the table at all.  It derives the flag list
from the oracle's own ``args.py`` (all 30 ``add_argument`` calls), builds a
matrix of invocations over that list, runs both tools, and compares **stdout
byte for byte and the exit code**.  A flag that is present but semantically
wrong fails exactly as a missing one does.

Declared divergences
--------------------
rop-finder deliberately differs from ROPgadget in a handful of places, each
with a finding ID.  Every one of them is listed in ``DIVERGENCES`` below with
the reason, and a divergence that stops happening is reported as **STALE** —
so this file cannot be used to paper over an accidental difference, and a
fixed divergence cannot be left claimed forever.  Anything not on that list
is a failure.

Usage
-----
    python tests/flag_conformance.py                    # the gate
    python tests/flag_conformance.py --fixture elf-Linux-x86
    python tests/flag_conformance.py --case only        # one case (substring)
    python tests/flag_conformance.py --depth 4 -j 8     # scan depth, workers
    python tests/flag_conformance.py --list             # the matrix, no runs

Oracle setup: see the module docstring of tests/rf_paths.py.
"""

import argparse
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rf_paths  # noqa: E402

# --------------------------------------------------------------------------
# The flag list, derived from the oracle rather than from our own manual.
# --------------------------------------------------------------------------

#: `parser.add_argument("-x", "--flag", ...)` in ropgadget/args.py.
_ADD_ARG = re.compile(r'add_argument\(\s*((?:"[^"]+"\s*,\s*)*"[^"]+")')


def oracle_flags():
    """Every flag ROPgadget 7.7 accepts, in args.py declaration order.

    Read from the vendored source, so a new upstream flag shows up here as a
    new uncovered row instead of being silently missing from a hand-written
    list.
    """
    _, script, _ = rf_paths.oracle()
    args_py = os.path.join(os.path.dirname(script), "ropgadget", "args.py")
    with open(args_py, encoding="utf-8") as fh:
        src = fh.read()
    flags = []
    for m in _ADD_ARG.finditer(src):
        names = re.findall(r'"([^"]+)"', m.group(1))
        flags.append(tuple(names))
    # argparse always adds -h/--help; args.py does not declare it.
    flags.append(("-h", "--help"))
    return flags


# --------------------------------------------------------------------------
# Per-fixture facts the matrix needs.
# --------------------------------------------------------------------------

#: Fixtures that are raw blobs: the oracle refuses them without these.
RAW_ARGS = {"raw-x86.raw": ["--rawArch", "x86", "--rawMode", "32"]}

#: Fixtures whose architecture makes --thumb meaningful.
ARM_FIXTURES = {"elf-ARMv7-ls", "pe-Windows-ARMv7-Thumb2LE-HelloWorld"}


def exec_range(rf, fixture_path, prefix):
    """A --range that actually truncates: the first half of the first
    executable section, taken from rop-finder's own --info.

    Data-driven rather than a constant, because a hardcoded range is outside
    every section on most of the corpus and would silently test nothing.
    """
    p = subprocess.run(
        [rf, "--binary", fixture_path, "--info"] + prefix,
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        return None
    try:
        info = json.loads(p.stdout)
    except json.JSONDecodeError:
        return None
    if "slices" in info:
        info = info["slices"][0]
    for s in info.get("sections", []):
        if s.get("executable") and s.get("size", 0) > 16:
            lo = int(s["vaddr"], 16)
            hi = lo + s["size"] // 2
            return f"0x{lo:x}-0x{hi:x}"
    return None


# --------------------------------------------------------------------------
# The matrix.  Each case is (name, args-builder).  The builder receives the
# per-fixture facts and returns the argument list, or None to skip.
# --------------------------------------------------------------------------


def build_cases(depth):
    d = ["--depth", str(depth)]

    def fixed(*args):
        return lambda f: list(args)

    cases = [
        # --binary + the default scan.
        ("binary/default-scan", fixed(*d)),
        # A raw blob with no --rawArch: neither tool can load it, and the
        # two refuse differently (declared below).
        ("binary/no-raw-spec", lambda f: list(d) if f["raw"] else None),
        # --depth
        ("depth/2", fixed("--depth", "2")),
        ("depth/8", fixed("--depth", "8")),
        ("depth/below-minimum", fixed("--depth", "1")),
        # --norop / --nojop / --nosys
        ("norop", fixed(*d, "--norop")),
        ("nojop", fixed(*d, "--nojop")),
        ("nosys", fixed(*d, "--nosys")),
        ("norop+nosys", fixed(*d, "--norop", "--nosys")),
        # --multibr
        ("multibr", fixed(*d, "--multibr")),
        # --only / --filter
        ("only/mov-ret", fixed(*d, "--only", "mov|ret")),
        ("only/pop-ret", fixed(*d, "--only", "pop|ret")),
        ("filter/jumps", fixed(*d, "--filter", "j.*")),
        ("filter/literal-substring", fixed(*d, "--filter", "op")),
        # --range (data-driven) and --range + --offset (SCAN-10).
        ("range/exec-first-half", lambda f: d + ["--range", f["range"]] if f["range"] else None),
        (
            "range+offset",
            lambda f: d + ["--range", f["range"], "--offset", "0x1000"] if f["range"] else None,
        ),
        # --badbytes, including an a-b range.
        ("badbytes/00-0a", fixed(*d, "--badbytes", "00|0a")),
        ("badbytes/span", fixed(*d, "--badbytes", "01-1f|7f")),
        # --offset
        ("offset/0x1000", fixed(*d, "--offset", "0x1000")),
        ("offset/huge", fixed(*d, "--offset", "0xdeadbeef00000000")),
        ("offset/not-hex", fixed(*d, "--offset", "zz")),
        # --re
        ("re/pop-or-ret", fixed(*d, "--re", "pop.*|ret")),
        ("re/single", fixed(*d, "--re", "pop")),
        ("re/spaced-alternation", fixed(*d, "--re", "pop.* | ret")),
        # --align
        ("align/4", fixed(*d, "--align", "4")),
        ("align/8", fixed(*d, "--align", "8")),
        # --all / --noinstr / --dump / --silent
        ("all", fixed(*d, "--all")),
        ("noinstr", fixed(*d, "--noinstr")),
        ("dump", fixed(*d, "--dump")),
        ("silent", fixed(*d, "--silent")),
        ("all+dump", fixed(*d, "--all", "--dump")),
        # --callPreceded
        ("callPreceded", fixed(*d, "--callPreceded")),
        # cross-flag validation (args.py:108-112)
        ("conflict/noinstr+only", fixed(*d, "--noinstr", "--only", "pop")),
        ("conflict/noinstr+re", fixed(*d, "--noinstr", "--re", "pop")),
        # --thumb (ARM only; elsewhere the oracle still accepts the flag)
        # ...but not on a raw blob, whose --rawMode prefix conflicts with it
        # (args.py:114); that combination is `rawspec/thumb-conflict`.
        ("thumb", lambda f: None if f["raw"] else d + ["--thumb"]),
        # --rawArch / --rawMode / --rawEndian.  The three cross-checks in
        # args.py:114-128 run BEFORE the binary is loaded, so they exercise
        # all three flags on every fixture; the loading cases run on the raw
        # blob, where they are what makes the file readable at all.
        ("rawspec/missing-mode", fixed(*d, "--rawArch", "x86")),
        ("rawspec/missing-arch", fixed(*d, "--rawMode", "32")),
        ("rawspec/endian-without-arch", fixed(*d, "--rawEndian", "little")),
        ("rawspec/thumb-conflict", fixed(*d, "--thumb", "--rawArch", "arm", "--rawMode", "arm")),
        ("rawspec/missing-endian", fixed(*d, "--rawArch", "mips", "--rawMode", "32")),
        (
            "rawspec/load-x86-32",
            lambda f: d + ["--rawArch", "x86", "--rawMode", "32"] if f["raw"] else None,
        ),
        (
            "rawspec/load-mips-big",
            lambda f: d + ["--rawArch", "mips", "--rawMode", "32", "--rawEndian", "big"]
            if f["raw"]
            else None,
        ),
        # --mipsrop: all five modes plus the unknown-mode message
        ("mipsrop/stackfinder", fixed(*d, "--mipsrop", "stackfinder")),
        ("mipsrop/system", fixed(*d, "--mipsrop", "system")),
        ("mipsrop/tails", fixed(*d, "--mipsrop", "tails")),
        ("mipsrop/lia0", fixed(*d, "--mipsrop", "lia0")),
        ("mipsrop/registers", fixed(*d, "--mipsrop", "registers")),
        ("mipsrop/unknown-mode", fixed(*d, "--mipsrop", "nope")),
        # --string / --opcode / --memstr, alone and with --range/--offset.
        ("string/regex", fixed("--string", "m..n")),
        ("string/literal", fixed("--string", "main")),
        ("string/slash-bin-sh", fixed("--string", "/bin/sh")),
        ("string+offset", fixed("--string", "m..n", "--offset", "0x1000")),
        (
            "string+range",
            lambda f: ["--string", "m..n", "--range", f["range"]] if f["range"] else None,
        ),
        ("opcode/c9c3", fixed("--opcode", "c9c3")),
        ("opcode/ffe4", fixed("--opcode", "ffe4")),
        ("opcode+offset", fixed("--opcode", "c9c3", "--offset", "0x1000")),
        (
            "opcode+range",
            lambda f: ["--opcode", "c9c3", "--range", f["range"]] if f["range"] else None,
        ),
        ("memstr/bin-sh", fixed("--memstr", "/bin/sh")),
        ("memstr/regex-metachar", fixed("--memstr", "abc[")),
        ("memstr+offset", fixed("--memstr", "/bin/sh", "--offset", "0x1000")),
        (
            "memstr+range",
            lambda f: ["--memstr", "/bin/sh", "--range", f["range"]] if f["range"] else None,
        ),
        ("string+silent", fixed("--string", "main", "--silent")),
        # --ropchain
        ("ropchain", fixed("--ropchain")),
        # --console, driven to EOF on an empty stdin.
        ("console/eof", fixed("--console")),
        # -v / --version / -c / --checkUpdate / -h, which take no binary.
        ("version/long", fixed("--version")),
        ("version/short-v", fixed("-v")),
        ("checkUpdate", fixed("--checkUpdate")),
        ("help", fixed("--help")),
    ]
    return cases


#: Cases that must NOT be given a --binary (they are global switches).
NO_BINARY = {"version/long", "version/short-v", "checkUpdate", "help"}

#: Cases where BOTH tools must refuse the command line before doing any
#: work.  These are not byte-compared on stdout, because rop-finder writes
#: diagnostics to stderr and exits 1 while ROPgadget prints them on stdout
#: and exits -1 -- the exit-code contract CLI-06/ENG-06 fixed and the MANUAL
#: documents.  What IS compared is the message itself, oracle stdout against
#: rop-finder stderr, so a flag that is silently accepted (or refused with a
#: different reason) still fails.
USAGE_ERROR = {
    "depth/below-minimum",
    "offset/not-hex",
    "conflict/noinstr+only",
    "conflict/noinstr+re",
    "rawspec/missing-mode",
    "rawspec/missing-arch",
    "rawspec/endian-without-arch",
    "rawspec/thumb-conflict",
    "rawspec/missing-endian",
}

#: The two usage-error messages rop-finder deliberately words differently,
#: with the substring its wording must still contain.  Both name the flag,
#: which the oracle's wording does not; neither is allowed to say nothing.
MESSAGE_DIVERGENCES = {
    "depth/below-minimum": "--depth must be >= 2",
    "offset/not-hex": '--offset "zz"',
}

#: Cases that supply their own raw spec and must not also get RAW_ARGS.
NO_PREFIX = {
    "rawspec/missing-mode",
    "rawspec/missing-arch",
    "rawspec/endian-without-arch",
    "rawspec/thumb-conflict",
    "rawspec/missing-endian",
    "rawspec/load-x86-32",
    "rawspec/load-mips-big",
}

# --------------------------------------------------------------------------
# Declared divergences.
#
# Each entry names the finding it belongs to, the cases and fixtures it may
# apply to, and an `effect` predicate over the run summary that must hold.
# The predicate is what stops this list from being a waiver: "text-only"
# means the ADDRESS sets are identical, "subset" bounds how many addresses
# may be missing, and an entry that never fires is reported as STALE.
# --------------------------------------------------------------------------


def text_only(s):
    """Same gadgets, different spelling: the address sets are identical."""
    return (
        s["addr_only_oracle"] == 0
        and s["addr_only_rf"] == 0
        and s["n_oracle"] == s["n_rf"]
    )


def subset(max_missing):
    """rop-finder finds a strict subset, short by at most `max_missing`."""

    def check(s):
        return s["addr_only_rf"] == 0 and s["addr_only_oracle"] <= max_missing

    return check


def both_nonempty(s):
    return s["n_oracle"] > 0 and s["n_rf"] > 0


def always(_s):
    return True


#: Every gadget-listing case: the ones whose stdout is a gadget dump, so an
#: address-set predicate means something.
SCAN_CASES = "scan"

DIVERGENCES = [
    {
        "id": "CLAIM-10/version",
        "cases": {"version/long"},
        "fixtures": "*",
        "why": "--version must name the linked capstone build and the ROPgadget "
        "attribution; matching the oracle's four-line block byte for byte "
        "would re-open CLAIM-10. Exit 0 and both facts are required.",
        "effect": lambda s: "capstone" in s["r_head"] and "ROPgadget" in s["r_head"]
        and s["r_rc"] == 0,
    },
    {
        "id": "CLI-12/short-v",
        "cases": {"version/short-v"},
        "fixtures": "*",
        "why": "ROPgadget spells the version flag -v (args.py:75) and rop-finder "
        "bound only clap's -V, so a ROPgadget script's capability probe died "
        "with 'unexpected argument'. -v is bound now and exits 0; the text is "
        "rop-finder's own, as for --version.",
        "effect": lambda s: s["r_head"].startswith("rop-finder ") and s["r_rc"] == 0,
    },
    {
        "id": "CLI-12/checkUpdate",
        "cases": {"checkUpdate"},
        "fixtures": "*",
        "why": "Deliberately not implemented: this tool makes no network request, "
        "ever. It is the one flag the remediation plan puts explicitly out of "
        "scope, and it must be REFUSED rather than silently ignored.",
        "effect": lambda s: s["r_out_empty"] and s["r_rc"] == 1,
    },
    {
        "id": "n/a/help",
        "cases": {"help"},
        "fixtures": "*",
        "why": "A different tool's help text, listing rop-finder's own flags.",
        "effect": lambda s: "Usage:" in s["r_head"] and s["r_rc"] == 0,
    },
    {
        "id": "CLI-12/ropchain",
        "cases": {"ropchain"},
        "fixtures": "*",
        "why": "By design: rop-finder prints the exploit script alone, with no "
        "preceding gadget dump and no step log, and a missing gadget is a "
        "structured error rather than print-and-return.",
        "effect": always,
    },
    {
        "id": "MANUAL/exit-codes",
        "cases": {"binary/no-raw-spec"},
        "fixtures": "*",
        "why": "A blob no loader recognises is exit 2 on stderr here and exit 1 on "
        "stdout there; the MANUAL documents 2 as 'malformed/unreadable "
        "binary'. Only reachable on a raw fixture with no --rawArch.",
        "effect": lambda s: s["r_out_empty"] and s["r_rc"] == 2,
    },
    {
        "id": "ANCH-04",
        "cases": SCAN_CASES,
        "fixtures": {"elf-Linux-RISCV_32"},
        "why": "ROPgadget opens EVERY RISC-V binary in CS_MODE_RISCV64|RISCVC "
        "(gadgets.py:202,392,479) including ELFCLASS32 ones, so it prints "
        "RV64-only text (`c.ldsp`, `c.ld`, `addiw`) for instructions an RV32 "
        "target cannot execute. rop-finder selects RISCV32. Already recorded "
        "in tests/known-divergences.json as text-only; the address sets must "
        "still be identical, and that is what is checked here.",
        "effect": text_only,
    },
    {
        "id": "ANCH-06",
        "cases": SCAN_CASES,
        "fixtures": {"pe-Windows-ARMv7-Thumb2LE-HelloWorld"},
        "why": "IMAGE_FILE_MACHINE_ARMNT is Thumb-2 ONLY. ROPgadget scans the "
        "image with the A32 tables unless --thumb is passed, so its gadgets "
        "are A32 misinterpretations of Thumb code; rop-finder routes a "
        "Thumb-only image to the Thumb tables. Recorded in "
        "tests/known-divergences.json as a deliberately disjoint set.",
        "effect": both_nonempty,
    },
    {
        "id": "SCAN-08/x87-alias",
        "cases": {"align/4", "align/8", "all", "all+dump", "noinstr", "dump"},
        "fixtures": {"elf-Linux-x86", "elf-SparcV8-bash"},
        "min_depth": 10,
        "why": "The two remaining x86 spelling differences MANUAL.md item 1 "
        "records: `fndisi` where capstone prints `fdisi8087_nop`, and "
        "`cldemote [eax]` where capstone prints `cldemote byte ptr [eax]`. "
        "Text only - the address sets are identical, which is checked. The "
        "bytes that decode to them are not reachable below --depth 10, so "
        "this entry is only expected to fire on a --depth 10 run.",
        "effect": text_only,
    },
    {
        "id": "ANCH-01/align-fallback",
        "cases": {"align/4", "align/8"},
        "fixtures": {"elf-Linux-x64"},
        "why": "OPEN, not accepted. gadgets.py:73-89 tries the aligned step "
        "`ref - i*align` first and, when `ref` itself is not align-aligned "
        "(a `ret` at an odd address behind a 5-byte `movdqu` store), falls "
        "back to the byte-by-byte `ref - i` and keeps it if THAT start is "
        "aligned. v0.2's ANCH-01 fix implemented the aligned-stepping branch "
        "for x86/x64 and not the fallback, so rop-finder finds a strict "
        "SUBSET. Measured at --depth 10 on elf-Linux-x64: 18 of 19,603 "
        "addresses missing at --align 4 (0.09%) and 16 of 9,731 at --align 8 "
        "(0.16%); every one is a `movdqu xmmword ptr [rdi - N], xmm0 ; ret` "
        "shape. rf-scan owns the fix; the bound below is what keeps it from "
        "growing quietly in the meantime.",
        "effect": subset(20),
    },
]


def scan_case(case):
    """Is this case's stdout a gadget listing (so address predicates apply)?"""
    return case not in NO_BINARY and case not in USAGE_ERROR and not any(
        case.startswith(p) for p in ("string", "opcode", "memstr", "ropchain", "console")
    )


def divergence_for(case, fixture, summary):
    for d in DIVERGENCES:
        if d["cases"] == SCAN_CASES:
            if not scan_case(case):
                continue
        elif case not in d["cases"]:
            continue
        if d["fixtures"] != "*" and fixture not in d["fixtures"]:
            continue
        if d["effect"](summary):
            return d, None
        return d, f"declared divergence {d['id']} failed its own check"
    return None, None


# --------------------------------------------------------------------------
# Running.
# --------------------------------------------------------------------------

_ADDR = re.compile(r"^(0x[0-9a-fA-F]+)")


def addr_set(out):
    return {m.group(1) for m in (_ADDR.match(l) for l in out.splitlines()) if m}


def run(cmd, timeout=1800):
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="replace",
        stdin=subprocess.DEVNULL,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


def summarize(o_rc, o_out, r_rc, r_out, r_err):
    """A small, bounded description of one comparison.

    The full outputs are megabytes and there are 1500+ of them, so nothing
    downstream ever sees them; every predicate works off this dict.
    """
    ol, rl = o_out.splitlines(), r_out.splitlines()
    so, sr = set(ol), set(rl)
    oa, ra = addr_set(o_out), addr_set(r_out)
    return {
        "o_rc": o_rc,
        "r_rc": r_rc,
        "n_oracle": len(ol),
        "n_rf": len(rl),
        "only_oracle": len(so - sr),
        "only_rf": len(sr - so),
        "sample_oracle": sorted(so - sr)[:3],
        "sample_rf": sorted(sr - so)[:3],
        "addr_only_oracle": len(oa - ra),
        "addr_only_rf": len(ra - oa),
        "r_head": r_out[:400],
        "r_err": r_err[:400],
        "r_out_empty": r_out == "",
        "identical": o_out == r_out and o_rc == r_rc,
        "same_lines_wrong_order": so == sr and ol != rl,
    }


def one(job):
    rf, interp, script, fixture, path, case, args, prefix = job
    if case in NO_BINARY:
        o_cmd = [interp, script] + args
        r_cmd = [rf] + args
    else:
        o_cmd = [interp, script, "--binary", path] + prefix + args
        # --compat reproduces the two oracle bugs rop-finder otherwise
        # refuses to reproduce (fat Mach-O slice concatenation, and reading
        # an SHT_NOBITS section's declared file extent).  Both are opt-in
        # here precisely because a conformance run is the one context in
        # which bug-for-bug is what you want.
        r_cmd = [rf, "--binary", path] + prefix + args + ["--compat"]
    t0 = time.perf_counter()
    try:
        o_rc, o_out, _o_err = run(o_cmd)
        r_rc, r_out, r_err = run(r_cmd)
    except subprocess.TimeoutExpired:
        return (fixture, case, "TIMEOUT", {}, time.perf_counter() - t0)
    dt = time.perf_counter() - t0
    s = summarize(o_rc, o_out, r_rc, r_out, r_err)

    if case in USAGE_ERROR:
        problems = []
        if not o_out.startswith("[Error] "):
            problems.append(f"the oracle did not refuse this: {o_out.splitlines()[:1]}")
        if not s["r_out_empty"]:
            problems.append(f"rop-finder wrote {len(r_out)} bytes to stdout instead of refusing")
        if r_rc != 1:
            problems.append(f"rop-finder exit {r_rc}, expected the documented usage-error 1")
        want = MESSAGE_DIVERGENCES.get(case)
        if want is None:
            if r_err.strip() != o_out.strip():
                problems.append(f"message: oracle {o_out.strip()!r} vs rf {r_err.strip()!r}")
        elif want not in r_err:
            problems.append(f"message {r_err.strip()!r} does not contain {want!r}")
        s["problems"] = problems
        return (fixture, case, "MATCH" if not problems else "DIFF", s, dt)

    return (fixture, case, "MATCH" if s["identical"] else "DIFF", s, dt)


def describe(s):
    if s.get("problems"):
        return "\n".join(s["problems"])
    lines = []
    if s["o_rc"] != s["r_rc"]:
        lines.append(f"exit {s['o_rc']} vs {s['r_rc']}")
    if s["same_lines_wrong_order"]:
        lines.append("same lines, different order")
    elif s["only_oracle"] or s["only_rf"]:
        lines.append(
            f"{s['n_oracle']} lines vs {s['n_rf']} "
            f"(addresses: {s['addr_only_oracle']} only-oracle, {s['addr_only_rf']} only-rf)"
        )
        for x in s["sample_oracle"]:
            lines.append(f"  only-oracle: {x!r}")
        for x in s["sample_rf"]:
            lines.append(f"  only-rf    : {x!r}")
    return "\n".join(lines) or "outputs differ"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fixture", action="append", help="only these fixtures")
    ap.add_argument("--case", help="only cases whose name contains this")
    ap.add_argument("--depth", type=int, default=4, help="scan depth (default 4)")
    ap.add_argument("-j", "--jobs", type=int, default=max(1, (os.cpu_count() or 4) // 2))
    ap.add_argument("--list", action="store_true", help="print the matrix and exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    opt = ap.parse_args()

    flags = oracle_flags()
    cases = build_cases(opt.depth)
    if opt.case:
        cases = [c for c in cases if opt.case in c[0]]

    # Every declared oracle flag must be exercised by at least one case, so a
    # new upstream flag cannot slip in untested.
    covered = " ".join(name for name, _ in cases)
    case_args = " ".join(
        " ".join(b({"range": "0x0-0x1", "raw": True}) or []) for _, b in build_cases(opt.depth)
    )
    uncovered = []
    for names in flags:
        if not any(n in case_args or n.lstrip("-") in covered for n in names):
            uncovered.append("/".join(names))
    print(f"ROPgadget flags declared in args.py: {len(flags)}")
    if uncovered:
        print(f"  NOT EXERCISED by this matrix: {', '.join(uncovered)}")
    else:
        print("  every one is exercised by at least one case")

    fixtures = opt.fixture or rf_paths.fixture_names()
    if opt.list:
        for name, _ in cases:
            print(f"  {name}")
        print(f"{len(cases)} cases x {len(fixtures)} fixtures")
        return 0

    rf = rf_paths.rop_finder()
    interp, script, capstone = rf_paths.oracle()
    print(f"oracle: ROPgadget@{rf_paths.ORACLE_COMMIT} capstone={capstone}")
    print(f"binary: {rf}")
    print(f"matrix: {len(cases)} cases x {len(fixtures)} fixtures, depth {opt.depth}")

    jobs = []
    for fx in fixtures:
        path = rf_paths.fixture_path(fx)
        prefix = RAW_ARGS.get(fx, [])
        facts = {"range": exec_range(rf, path, prefix), "raw": fx in RAW_ARGS}
        for name, builder in cases:
            args = builder(facts)
            if args is None:
                continue
            p = [] if name in NO_PREFIX or name == "binary/no-raw-spec" else prefix
            jobs.append((rf, interp, script, fx, path, name, args, p))

    results = []
    t0 = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=opt.jobs) as ex:
        for i, res in enumerate(ex.map(one, jobs), 1):
            results.append(res)
            if opt.verbose or i % 200 == 0:
                print(f"  [{i}/{len(jobs)}] {res[0]} {res[1]} {res[2]}", flush=True)
    wall = time.perf_counter() - t0

    failures, hits = [], {d["id"]: 0 for d in DIVERGENCES}
    per_fixture = {}
    for fixture, case, verdict, summary, _dt in results:
        per_fixture.setdefault(fixture, [0, 0])
        if verdict == "MATCH":
            per_fixture[fixture][0] += 1
            continue
        d, why_not = (None, "timed out") if verdict == "TIMEOUT" else divergence_for(
            case, fixture, summary
        )
        if d is not None and why_not is None:
            hits[d["id"]] += 1
            per_fixture[fixture][0] += 1
            continue
        per_fixture[fixture][1] += 1
        failures.append((fixture, case, why_not or describe(summary)))

    print()
    for fx in sorted(per_fixture):
        ok, bad = per_fixture[fx]
        mark = "ok  " if bad == 0 else "FAIL"
        print(f"  {mark} {fx:40s} {ok}/{ok + bad} conformant")
    print()
    print(f"cases run     : {len(results)} in {wall:.0f}s ({opt.jobs} workers)")
    print(f"excused       : {sum(hits.values())} declared divergences")
    print(f"failures      : {len(failures)}")
    print()
    print("declared divergences:")
    stale = []
    # STALE-ness is only meaningful for a full run: a --fixture/--case filter
    # legitimately leaves entries unexercised, and a few divergences only
    # appear at a scan depth deep enough to reach the bytes involved.
    full_run = not opt.fixture and not opt.case
    for d in DIVERGENCES:
        n = hits[d["id"]]
        shallow = opt.depth < d.get("min_depth", 0)
        if n == 0:
            state = "not exercised (needs --depth %d)" % d["min_depth"] if shallow else "STALE"
            if not shallow and full_run:
                stale.append(d["id"])
        else:
            state = f"{n} hits"
        print(f"  [{d['id']:<24}] {state}")

    if failures:
        print()
        print("UNDECLARED DIVERGENCES:")
        for fx, case, detail in failures[:40]:
            print(f"  {fx} [{case}]")
            for line in str(detail).splitlines():
                print(f"    {line}")
        if len(failures) > 40:
            print(f"  ... and {len(failures) - 40} more")

    if stale:
        print()
        print("STALE declared divergences (they no longer happen - delete them):")
        for i in stale:
            print(f"  {i}")

    if failures or stale:
        return 1
    print()
    print("PASS: every ROPgadget flag behaves identically to the oracle, or "
          "diverges only in a declared and bounded way.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
