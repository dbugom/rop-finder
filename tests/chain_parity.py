#!/usr/bin/env python3
"""Chain parity harness: rop-finder --ropchain vs ROPgadget --ropchain.

For every ELF x86/x64 fixture in tests/fixtures, and for every FLAG SET in
`FLAG_SETS`:
  * run the reference:  python <ropgadget>/ROPgadget.py --binary F --ropchain
  * run rop-finder:     rop-finder --binary F --ropchain
  * extract the python script portion (from the '#!/usr/bin/env python3'
    shebang to EOF) on both sides and classify the result:

      BYTE-IDENTICAL    the two scripts are exactly equal
      PAYLOAD-IDENTICAL the pack('<..', addr) words and data words are equal;
                        only gadget comment text differs (iced-x86 renders
                        single-digit immediates as 0x1 where capstone
                        prints 1 — same gadget, same address)
      STRUCTURAL        same word count and word kinds; gadget addresses
                        differ (dedup-survivor / disassembler drift)
      ERROR-PARITY      both tools fail to build a chain for this fixture
      OURS-REFUSED      the oracle emits a chain and rop-finder refuses
      REF-REFUSED       rop-finder emits a chain and the oracle refuses
      BADBYTE-LEAK      rop-finder emitted a word containing a bad byte
      MISMATCH          same word kinds impossible to reconcile

CHLX-09 — why the flag sets exist
---------------------------------
This harness used to run one flag set (`--binary F --ropchain`) over 8
fixtures.  `--badbytes` is the flag where the two tools *deliberately*
disagree: rop-finder rejects a chain whose non-gadget words (the `.data`
address, the padding constant) contain a bad byte, where ROPgadget filters
gadget addresses only and emits the chain anyway.  That divergence was
documented in README.md and asserted nowhere, so:

  * a regression that silently started emitting badbyte-containing words
    would not have been caught — `BADBYTE_LEAK` is now checked on every
    word of every chain rop-finder emits, and it is ALWAYS fatal;
  * a regression that started refusing a case the oracle handles was
    indistinguishable from the intended behaviour — every (fixture, flag
    set) pair now has a recorded verdict in `EXPECTED`, and any change is
    reported.

Two changes are not regressions, print `IMPROVED`, and ask for the table to
be re-recorded without failing the build:

  * `OURS-REFUSED -> a real chain`, which is what CHLX-03's
    alternative-address search under `--badbytes` is meant to produce;
  * `ERROR-PARITY -> REF-REFUSED`, which is what CHLX-01's fallback planner
    is meant to produce: a fixture neither tool could chain, that we can
    chain now.

Every other change is fatal.

v0.5 — why MISMATCH is no longer fatal on its own
-------------------------------------------------
`MISMATCH` is decided by comparing `p +=` line counts, so it fires whenever
the two tools build chains of different LENGTHS.  Until v0.5 that could only
mean "we reconstructed the same recipe and got it wrong".  CHLX-02 changed
what it means: rop-finder now pops the execve syscall number instead of
building it with a 59-instruction `inc eax` ladder, so on elf-Linux-x64 the
chain is 19 words where the oracle emits 76.  Byte parity with ROPgadget's
*chain* is gone by design — you cannot both keep it and cut the payload 4x —
and there is no verdict this harness can compute that distinguishes "shorter
because better" from "different because broken".

So `MISMATCH` is governed by the recorded table like every other verdict: an
unrecorded MISMATCH, or a cell that changes into or out of one, still fails.
What did NOT move is the check that actually detects a defect in a word we
emit: `BADBYTE-LEAK` is unconditionally fatal, on every word of every chain,
and so is `MISSING-FIXTURE`.  Whether a chain rop-finder emits actually RUNS
is no longer this harness's job either — `tests/emulate.py` executes them
under unicorn, which is a stronger statement than resembling the oracle.

Non-x86 ELF fixtures and non-ELF fixtures are skipped: ropmaker only
supports Linux execve chains on x86 (int 0x80) and x64 (syscall).

Usage:  python tests/chain_parity.py [--release|--debug] [--fixture NAME]
                                     [--flags LABEL] [--record]

Exits non-zero on any BADBYTE-LEAK, MISSING-FIXTURE or unexpected verdict
change.  The rop-finder binary and the ROPgadget oracle are resolved
by `tests/rf_paths.py` -- by platform, with env overrides, and building
rop-finder if it is absent (CLAIM-08/ENG-04).
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
PACK_ADDR = re.compile(r"pack\('<([QI])', (0x[0-9a-f]+)\)")
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

#: label -> extra argv passed to BOTH tools.  `--badbytes` is the flag the
#: two tools deliberately disagree about; the rest of the flag space
#: (`--depth`, `--offset`, `--base`, `--range`, `--only`, `--section`,
#: `--multibr`) changes the gadget universe identically in both and is
#: covered by tests/parity.py at the gadget level.
FLAG_SETS = {
    "default": [],
    # The single most common real constraint, and CHLX-03's headline case.
    "badbytes-00": ["--badbytes", "00"],
    # The classic newline/CR pair.
    "badbytes-0a0d": ["--badbytes", "0a|0d"],
    # 0x0f and 0x60 are bytes of elf-Linux-x86's `.data` base (0x080f4060),
    # so they hit the DATA word rather than any gadget address: this is the
    # documented divergence in its purest form — the oracle emits a chain
    # containing the byte the user forbade, we refuse.  CHLX-03 will turn
    # these into a `.data + N` search; until then they pin the behaviour.
    "badbytes-0f": ["--badbytes", "0f"],
    "badbytes-60": ["--badbytes", "60"],
    # 0x41 is the padding constant itself (0x41414141 / 0x4141414141414141) —
    # a word kind ROPgadget never bad-byte checks at all.
    "badbytes-41": ["--badbytes", "41"],
    # Control: no gadget address and no data word in these fixtures contains
    # 0xff, so nothing should change.
    "badbytes-ff": ["--badbytes", "ff"],
}

#: The recorded verdict for every (flag set, fixture) pair.  Filled by
#: `--record`.  A verdict that differs from this table is reported; the two
#: non-fatal directions are OURS-REFUSED -> real chain (CHLX-03) and
#: ERROR-PARITY -> REF-REFUSED (CHLX-01).
#:
#: Re-recorded for v0.5 on 2026-09-04, twice, byte-identical between runs.
#: The BYTE-IDENTICAL / PAYLOAD-IDENTICAL cells this table used to hold are
#: gone: CHLX-02 cut the x64 execve chain from 76 words to 19, so no default
#: flag set can still reproduce ROPgadget's script byte for byte.  The 13
#: ERROR-PARITY -> REF-REFUSED cells are CHLX-01's fallbacks landing.
EXPECTED = {
    "default": {
        "elf-Linux-x64": "MISMATCH",
        "elf-Linux-x86": "MISMATCH",
        "elf-Linux-x86-NDH-chall": "MISMATCH",
        "elf-FreeBSD-x86": "REF-REFUSED",
        "elf-x64-bash-v4.1.5.1": "REF-REFUSED",
        "elf-x86-bash-v4.1.5.1": "ERROR-PARITY",
        "Linux_lib32.so": "ERROR-PARITY",
        "Linux_lib64.so": "MISMATCH",
    },
    "badbytes-00": {
        "elf-Linux-x64": "ERROR-PARITY",
        "elf-Linux-x86": "STRUCTURAL",
        "elf-Linux-x86-NDH-chall": "STRUCTURAL",
        "elf-FreeBSD-x86": "ERROR-PARITY",
        "elf-x64-bash-v4.1.5.1": "ERROR-PARITY",
        "elf-x86-bash-v4.1.5.1": "ERROR-PARITY",
        "Linux_lib32.so": "ERROR-PARITY",
        "Linux_lib64.so": "ERROR-PARITY",
    },
    "badbytes-0a0d": {
        "elf-Linux-x64": "MISMATCH",
        "elf-Linux-x86": "MISMATCH",
        "elf-Linux-x86-NDH-chall": "MISMATCH",
        "elf-FreeBSD-x86": "REF-REFUSED",
        "elf-x64-bash-v4.1.5.1": "REF-REFUSED",
        "elf-x86-bash-v4.1.5.1": "ERROR-PARITY",
        "Linux_lib32.so": "ERROR-PARITY",
        "Linux_lib64.so": "MISMATCH",
    },
    "badbytes-0f": {
        "elf-Linux-x64": "MISMATCH",
        "elf-Linux-x86": "OURS-REFUSED",
        "elf-Linux-x86-NDH-chall": "MISMATCH",
        "elf-FreeBSD-x86": "REF-REFUSED",
        "elf-x64-bash-v4.1.5.1": "REF-REFUSED",
        "elf-x86-bash-v4.1.5.1": "ERROR-PARITY",
        "Linux_lib32.so": "ERROR-PARITY",
        "Linux_lib64.so": "MISMATCH",
    },
    "badbytes-60": {
        "elf-Linux-x64": "ERROR-PARITY",
        "elf-Linux-x86": "MISMATCH",
        "elf-Linux-x86-NDH-chall": "MISMATCH",
        "elf-FreeBSD-x86": "REF-REFUSED",
        "elf-x64-bash-v4.1.5.1": "REF-REFUSED",
        "elf-x86-bash-v4.1.5.1": "ERROR-PARITY",
        "Linux_lib32.so": "ERROR-PARITY",
        "Linux_lib64.so": "MISMATCH",
    },
    "badbytes-41": {
        "elf-Linux-x64": "REF-REFUSED",
        "elf-Linux-x86": "MISMATCH",
        "elf-Linux-x86-NDH-chall": "MISMATCH",
        "elf-FreeBSD-x86": "REF-REFUSED",
        "elf-x64-bash-v4.1.5.1": "REF-REFUSED",
        "elf-x86-bash-v4.1.5.1": "ERROR-PARITY",
        "Linux_lib32.so": "ERROR-PARITY",
        "Linux_lib64.so": "MISMATCH",
    },
    "badbytes-ff": {
        "elf-Linux-x64": "MISMATCH",
        "elf-Linux-x86": "MISMATCH",
        "elf-Linux-x86-NDH-chall": "MISMATCH",
        "elf-FreeBSD-x86": "REF-REFUSED",
        "elf-x64-bash-v4.1.5.1": "REF-REFUSED",
        "elf-x86-bash-v4.1.5.1": "ERROR-PARITY",
        "Linux_lib32.so": "ERROR-PARITY",
        "Linux_lib64.so": "MISMATCH",
    },
}

#: Verdicts that mean "rop-finder produced a chain the oracle also produced".
CHAIN_ON_BOTH = ("BYTE-IDENTICAL", "PAYLOAD-IDENTICAL", "STRUCTURAL")
#: Always fatal, whatever the table says.  `MISMATCH` was here until v0.5;
#: see the module docstring for why it is now governed by `EXPECTED` instead.
#: These two are not, because neither can ever be a deliberate improvement:
#: BADBYTE-LEAK is a word we emitted that violates what the user asked for,
#: and MISSING-FIXTURE means the corpus shrank under the harness.
FATAL_VERDICTS = ("BADBYTE-LEAK", "MISSING-FIXTURE")


def parse_badbytes(spec):
    """`"00|0a-0d"` -> {0x00, 0x0a, 0x0b, 0x0c, 0x0d} — the CLI's own syntax."""
    out = set()
    for part in spec.split("|"):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.update(range(int(lo, 16), int(hi, 16) + 1))
        else:
            out.add(int(part, 16))
    return out


def badbytes_of(extra):
    """The bad-byte set a flag set imposes, or an empty set."""
    for i, arg in enumerate(extra):
        if arg == "--badbytes" and i + 1 < len(extra):
            return parse_badbytes(extra[i + 1])
    return set()


def leaked_badbytes(script, bad):
    """Words of `script` that contain a byte from `bad`.

    This is the invariant that must hold before and after CHLX-03: whatever
    rop-finder decides to emit under `--badbytes`, no emitted word may carry
    one.  Both word forms are checked — the `pack('<Q', 0x...)` addresses and
    the `p += b'...'` string immediates.
    """
    if not bad or not script:
        return []
    hits = []
    for size_char, value in PACK_ADDR.findall(script):
        size = 8 if size_char == "Q" else 4
        packed = int(value, 16).to_bytes(size, "little")
        found = sorted({b for b in packed if b in bad})
        if found:
            hits.append(f"{value} -> " + " ".join(f"{b:02x}" for b in found))
    for literal in DATA_WORD.findall(script):
        raw = literal.encode("latin-1", "replace").decode("unicode_escape").encode("latin-1")
        found = sorted({b for b in raw if b in bad})
        if found:
            hits.append(f"b'{literal}' -> " + " ".join(f"{b:02x}" for b in found))
    return hits


def script_portion(text: str):
    """Extract the generated python script (shebang line to EOF)."""
    idx = text.find(SHEBANG)
    if idx < 0:
        return None
    return text[idx:]


def run_ref(fixture: str, extra=()):
    """Return the oracle's script portion, or None when it cannot build one."""
    p = subprocess.run(
        rf_paths.oracle_cmd(fixture, extra=extra, ropchain=True),
        capture_output=True, text=True,
    )
    # ROPgadget prints "[-] Can't find ..." messages during its internal
    # backtracking even when the chain ultimately succeeds — the reliable
    # success signal is the presence of the generated python script.
    return script_portion(p.stdout)


def run_ours(binary: str, fixture: str, extra=()):
    """Return our script portion, or None when we report a structured error."""
    p = subprocess.run(
        [binary, "--binary", fixture, "--ropchain", *extra],
        capture_output=True, text=True,
    )
    if p.returncode != 0:
        return None
    return script_portion(p.stdout)


def words(script: str):
    """(pack address words, data words) — the payload, comments stripped."""
    packs = [v for _, v in PACK_ADDR.findall(script)]
    data = DATA_WORD.findall(script)
    return packs, data


def classify(ref, ours, bad):
    if ours is not None and bad and leaked_badbytes(ours, bad):
        return "BADBYTE-LEAK"
    if ref is None and ours is None:
        return "ERROR-PARITY"
    if ref is None:
        return "REF-REFUSED"
    if ours is None:
        return "OURS-REFUSED"
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


def judge(label, name, verdict):
    """('OK'|'IMPROVED'|'CHANGED'|'FATAL', note) against the recorded table."""
    if verdict in FATAL_VERDICTS:
        return "FATAL", ""
    want = EXPECTED.get(label, {}).get(name)
    if want is None:
        return "OK", "not recorded yet (run --record)"
    if verdict == want:
        return "OK", ""
    if want == "OURS-REFUSED" and verdict in CHAIN_ON_BOTH:
        # Exactly what CHLX-03 is meant to produce: an alternative-address
        # search that finds a badbyte-free chain where we used to abort.
        return "IMPROVED", f"was {want}; record it"
    if want == "ERROR-PARITY" and verdict == "REF-REFUSED":
        # Exactly what CHLX-01 is meant to produce: a fixture where BOTH
        # tools used to give up, and where the fallback planner now builds a
        # chain the oracle still cannot.  tests/emulate.py is what proves the
        # chain runs; this only records that it exists.
        return "IMPROVED", f"was {want}; record it"
    return "CHANGED", f"expected {want}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", action="store_true", default=True)
    ap.add_argument("--debug", dest="release", action="store_false")
    ap.add_argument("--fixture", help="only run this fixture")
    ap.add_argument("--flags", help="only run this flag set (see FLAG_SETS)")
    ap.add_argument(
        "--record",
        action="store_true",
        help="print an EXPECTED table for the observed verdicts and exit 0",
    )
    args = ap.parse_args()

    binary = rf_paths.rop_finder(release=args.release)
    names = [args.fixture] if args.fixture else CANDIDATES
    labels = [args.flags] if args.flags else list(FLAG_SETS)
    print(f"# environment: {rf_paths.describe_environment()}")
    print(f"# rop-finder:  {binary}")

    counts = {}
    rows = []
    observed = {}
    bad_runs = 0
    for label in labels:
        extra = FLAG_SETS[label]
        bad = badbytes_of(extra)
        observed[label] = {}
        for name in names:
            path = os.path.join(FIXTURES, name)
            if not os.path.exists(path):
                rows.append((label, name, "MISSING-FIXTURE", "FATAL", ""))
                counts["MISSING-FIXTURE"] = counts.get("MISSING-FIXTURE", 0) + 1
                bad_runs += 1
                continue
            ref = run_ref(path, extra)
            ours = run_ours(binary, path, extra)
            verdict = classify(ref, ours, bad)
            observed[label][name] = verdict
            status, note = judge(label, name, verdict)
            detail = note
            if verdict == "BADBYTE-LEAK":
                detail = "; ".join(leaked_badbytes(ours, bad)[:2])
            elif verdict == "OURS-REFUSED" and ref is not None and bad:
                # Say WHY the divergence is real: the oracle's own chain
                # carries the byte the user said it must not carry.
                leaks = leaked_badbytes(ref, bad)
                detail = (
                    (note + "; " if note else "")
                    + f"oracle emitted {len(leaks)} word(s) containing a bad byte"
                )
            elif not detail and verdict in ("PAYLOAD-IDENTICAL", "STRUCTURAL") and ref and ours:
                detail = f"ref={len(words(ref)[0])} packs ours={len(words(ours)[0])} packs"
            elif not detail and verdict == "ERROR-PARITY":
                detail = "both sides report the chain cannot be built"
            rows.append((label, name, verdict, status, detail))
            counts[verdict] = counts.get(verdict, 0) + 1
            if status in ("FATAL", "CHANGED"):
                bad_runs += 1

    if args.record:
        print("\nEXPECTED = {")
        for label in labels:
            print(f'    "{label}": {{')
            for name in names:
                v = observed.get(label, {}).get(name)
                if v:
                    print(f'        "{name}": "{v}",')
            print("    },")
        print("}")
        return 0

    print(f"\n{'flags':<16} {'fixture':<26} {'verdict':<18} {'vs record':<10} detail")
    print("-" * 110)
    for label, name, verdict, status, detail in rows:
        print(f"{label:<16} {name:<26} {verdict:<18} {status:<10} {detail}")
    print("-" * 110)
    print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    improved = [r for r in rows if r[3] == "IMPROVED"]
    if improved:
        print(
            "\nIMPROVED rows moved in one of the two good directions: CHLX-03 (we used to\n"
            "refuse, now we emit a badbyte-free chain) or CHLX-01 (neither tool could build\n"
            "a chain, now we can). Re-run with --record and paste the table into EXPECTED\n"
            "in the same commit as the fix."
        )
    if bad_runs:
        print(
            "\nCHAIN PARITY GATE: FAIL. A CHANGED row means the divergence moved in a\n"
            "direction that is not an improvement; BADBYTE-LEAK means a word rop-finder\n"
            "emitted contains a byte the user said it must not (always a bug, CHLX-09)."
        )
        return 1
    print("\nCHAIN PARITY GATE: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
