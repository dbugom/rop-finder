#!/usr/bin/env python3
"""Doc-claims gate: every quantitative claim in README/MANUAL/PLAN, checked.

Grafted onto the "gates that can go red" workstream.  v0.1.1 retracted a set
of unsupported numbers (the ">=10x on x86/x64" headline, the "~9-14x faster
than ropper" figure, a 25-fixture corpus that was really 24).  Nothing stopped
those numbers from being typed back in.  This harness extracts each remaining
quantitative claim from the documents, resolves it against a live measurement
or against a committed artifact, and exits non-zero when one no longer holds.

Severity
--------
``fail``  a hard gate.  Deterministic on any machine: counts, ratios computed
          from the committed parity baseline, and internal consistency between
          documents.  A failure exits 1.
``warn``  reported with its measured value but not fatal, because the value is
          machine-dependent (wall-clock speedups) or because the document it
          checks records a figure measured on a different platform.  ``--strict``
          promotes every warn to a fail.

Why wall-clock speedup is a warn: re-measuring a ratio on a shared CI runner
tests the runner, not the tool.  What IS hard-gated is the *direction* the
documents assert.  Until v0.4 that direction was a retraction — the numbers in
the table had to stay BELOW PLAN's unmet 10x/4x criteria, so editing the table
back to "12x" turned the gate red.  v0.5 met both criteria, so `SPEEDUP-MET`
now runs the other way: every figure in the table marked
`<!-- speedup-table: current -->` must REACH its threshold, and a regression
papered over by editing the table down fails without any timing run.  The
v0.1.1 figures stay in both documents, outside that marker, as the record of
the retraction.

Usage
-----
    python tests/doc_claims.py                 # the gate
    python tests/doc_claims.py --strict        # warns are failures too
    python tests/doc_claims.py --no-timing     # skip the live speedup rows
    python tests/doc_claims.py --doc-root DIR  # read the documents from DIR
    python tests/doc_claims.py --json out.json

``--doc-root`` exists so the gate's own red path can be demonstrated against a
scratch copy of the documents (see docs/gate-mutation.md) without editing the
real ones.
"""

import argparse
import glob
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

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")
    except (AttributeError, OSError):  # pragma: no cover
        pass

REPO = rf_paths.REPO
BASELINE_DIR = os.path.join(rf_paths.HERE, "parity-baseline")

# Fixtures decoded by the iced-x86 path (the "x86/x64" half of every claim).
X86_FIXTURES = {
    "Linux_lib32.so",
    "Linux_lib64.so",
    "UNIVERSAL-x86-x64-libSystem.B.dylib",
    "elf-FreeBSD-x86",
    "elf-Linux-x64",
    "elf-Linux-x86",
    "elf-Linux-x86-NDH-chall",
    "elf-x64-bash-v4.1.5.1",
    "elf-x86-bash-v4.1.5.1",
    "macho-x64-ls",
    "macho-x86-ls",
    "pe-x64-cmd-v6.1.7601",
    "pe-x86-cmd-v6.1.7600",
    "raw-x86.raw",
}

# PLAN's Phase-1 exit criteria: >=10x on the iced-x86 path, >=4x on the
# capstone-backed architectures.
#
# v0.5 INVERTED THIS CHECK, and that is the whole point of the change. Until
# v0.4 both criteria were NOT MET, so the guard was a RETRACTION guard: no
# number in the documented table was allowed to REACH its threshold, because a
# passing number would have contradicted PLAN's own disposition. Phase 6 met
# both criteria on every architecture, PLAN and README now say so, and the
# guard therefore has to run the other way: every documented figure must be AT
# OR ABOVE its threshold, so that a performance regression which someone
# "fixes" by editing the table back down fails here.
#
# The v0.1.1 figures are still in both documents and must NOT be checked
# against this — they are the record of the retraction. Which table is which
# is declared in the documents themselves with an HTML marker
# (`<!-- speedup-table: current -->`), not inferred from the numbers, so that
# a superseded table can never be silently promoted by editing a digit.
SPEEDUP_LIMITS = {"x86": 10.0, "capstone": 4.0}

#: The marker line that precedes the table under test in README.md and
#: docs/measured-2026-09.md. Everything before the next `##` heading after it
#: is the current table.
CURRENT_TABLE_MARKER = "<!-- speedup-table: current -->"


class Result:
    def __init__(self, cid, severity, source, description, ok, expected, measured, note=""):
        self.cid = cid
        self.severity = severity
        self.source = source
        self.description = description
        self.ok = ok
        self.expected = expected
        self.measured = measured
        self.note = note

    def as_dict(self):
        return {
            "id": self.cid,
            "severity": self.severity,
            "source": self.source,
            "description": self.description,
            "ok": self.ok,
            "expected": self.expected,
            "measured": self.measured,
            "note": self.note,
        }


# --------------------------------------------------------------------------
# document + baseline access
# --------------------------------------------------------------------------
class Docs:
    """The documents under test. PLAN.md lives one level above the repo."""

    def __init__(self, doc_root=None):
        root = doc_root or REPO
        self.paths = {
            "README.md": os.path.join(root, "README.md"),
            "MANUAL.md": os.path.join(root, "MANUAL.md"),
            "PLAN.md": os.path.join(root, "PLAN.md"),
            "docs/measured-2026-09.md": os.path.join(root, "docs", "measured-2026-09.md"),
        }
        if doc_root is None:
            self.paths["PLAN.md"] = os.path.join(os.path.dirname(REPO), "PLAN.md")
        self.text = {}
        for name, path in self.paths.items():
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    self.text[name] = fh.read()

    def get(self, name):
        if name not in self.text:
            sys.exit(f"document not found: {self.paths.get(name, name)}")
        return self.text[name]

    def current(self, name):
        """`get`, minus lines explicitly marked as a superseded measurement.

        docs/measured-2026-09.md deliberately keeps every earlier measurement
        rather than overwriting it — the macOS Phase-1 run and the Windows
        re-measurement both stay on the page, because comparing them is the
        evidence that the oracle differs per platform. Those preserved numbers
        are history, not claims about the current build, and a harness that
        reads them as claims forces the file to either lie or forget.

        A line is treated as history when it carries the marker `[superseded]`.
        Nothing else is filtered, so a stale number that nobody has marked is
        still a failure -- the marker has to be added deliberately, and it
        reads as an admission in review.
        """
        return "\n".join(
            ln for ln in self.get(name).splitlines() if "[superseded]" not in ln
        )

    def count(self, name, pattern, flags=0):
        return len(re.findall(pattern, self.get(name), flags))

    def has(self, name, pattern, flags=0):
        return re.search(pattern, self.get(name), flags) is not None


def load_parity_baselines():
    out = {}
    for path in sorted(glob.glob(os.path.join(BASELINE_DIR, "*.json"))):
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        out[d["fixture"]] = d
    return out


# --------------------------------------------------------------------------
# claims
# --------------------------------------------------------------------------
def claim_fixture_count(docs, base, _args):
    """README/MANUAL/PLAN all say the corpus is 24 binaries."""
    actual = len(rf_paths.fixture_names())
    stated = set()
    for doc, pat in (
        ("README.md", r"across \*\*(\d+)\*\* fixtures"),
        ("MANUAL.md", r"across (\d+) reference binaries"),
        ("PLAN.md", r"parity on all (\d+) test-suite binaries"),
    ):
        m = re.search(pat, docs.get(doc))
        if m:
            stated.add((doc, int(m.group(1))))
    bad = [f"{d}={n}" for d, n in stated if n != actual]
    return Result(
        "FIXTURE-COUNT",
        "fail",
        "README.md, MANUAL.md, PLAN.md",
        "the fixture corpus size stated in the docs is the number of files in tests/fixtures",
        not bad and len(stated) == 3,
        f"{actual} (ls tests/fixtures, excluding MANIFEST.sha256/PROVENANCE.md)",
        ", ".join(f"{d}={n}" for d, n in sorted(stated)) or "no statement found",
        "; ".join(bad),
    )


def claim_parity_percentage(docs, base, _args):
    """The 99.93% headline, recomputed from the committed parity baseline."""
    ref = sum(b["reference"]["count"] for b in base.values())
    matched = sum(b["recorded"]["matched"] for b in base.values())
    pct = 100.0 * matched / ref if ref else 0.0
    # 2 to 4 decimals: at 99.995% a two-decimal statement cannot land inside
    # the 0.005 band at all (99.99 is 0.0050 away, 100.00 is 0.0050 away), so
    # restricting the docs to two decimals would make the claim unstatable.
    # The docs are allowed to be as precise as the measurement.
    pct_re = r"(\d{2}\.\d{2,4})"
    stated = sorted(
        {
            float(m)
            for doc in ("README.md", "MANUAL.md", "docs/measured-2026-09.md")
            for m in re.findall(
                rf"{pct_re}% parity|parity[^.\n]{{0,40}}?{pct_re}%", docs.current(doc)
            )
            for m in [x for x in m if x]
        }
        | {
            float(m)
            for doc in ("README.md", "MANUAL.md", "docs/measured-2026-09.md")
            for m in re.findall(rf"reproduced\s+[-—]\s+{pct_re}%", docs.current(doc))
        }
    )
    ok = bool(stated) and all(abs(s - pct) < 0.005 for s in stated)
    return Result(
        "PARITY-PCT",
        "fail",
        "README.md, MANUAL.md, docs/measured-2026-09.md",
        "the stated parity percentage equals matched/reference over the committed baseline",
        ok,
        # 4 decimals, matching the `measured` line: at 2 decimals a stated
        # 99.995% prints as "100.00%", which reads like a different (and
        # impossible) claim than the one in the document.
        ", ".join(f"{s:.4f}%" for s in stated) or "no percentage found",
        f"{pct:.4f}% ({matched} of {ref})",
        "recomputed from tests/parity-baseline/*.json",
    )


def claim_reference_total(docs, base, _args):
    """docs/measured-2026-09.md's absolute reference-gadget total.

    Platform sensitive: the committed figure was taken on macOS with CPython
    3.11; this machine's oracle produces a slightly different set. The gate
    admits a 0.5% band and reports the exact delta.
    """
    ref = sum(b["reference"]["count"] for b in base.values())
    m = re.search(r"of ([\d,]+) reference gadgets", docs.get("docs/measured-2026-09.md"))
    stated = int(m.group(1).replace(",", "")) if m else None
    if stated is None:
        return Result(
            "REF-TOTAL", "fail", "docs/measured-2026-09.md",
            "the absolute reference-gadget total is stated", False, "a number", "none found",
        )
    delta = ref - stated
    ok = abs(delta) <= 0.005 * stated
    return Result(
        "REF-TOTAL",
        "warn",
        "docs/measured-2026-09.md",
        "the stated reference-gadget total matches this machine's oracle within 0.5%",
        ok,
        f"{stated:,}",
        f"{ref:,}",
        f"delta {delta:+,} ({100.0 * delta / stated:+.3f}%) - oracle interpreter/platform difference",
    )


def claim_bit_exact(docs, base, _args):
    """"11 of 24 fixtures are bit-exact" — recount it."""
    actual = sum(
        1
        for b in base.values()
        if b["recorded"]["ref_only"] == 0 and b["recorded"]["ours_only"] == 0
    )
    m = re.search(
        r"(\d+) of (\d+) fixtures are bit-exact", docs.current("docs/measured-2026-09.md")
    )
    stated = int(m.group(1)) if m else None
    return Result(
        "BIT-EXACT",
        "warn",
        "docs/measured-2026-09.md, README.md",
        "the count of fixtures with zero divergence in both directions",
        stated == actual,
        str(stated),
        str(actual),
        "recounted from tests/parity-baseline/*.json on this machine",
    )


def _current_speedup_rows(docs, doc):
    """(fixture, speedup) rows of the table marked `speedup-table: current`.

    Scoped to the marker so the v0.1.1 table both documents still carry — the
    record of the retraction — is not read as a claim about this build.
    """
    text = docs.get(doc)
    i = text.find(CURRENT_TABLE_MARKER)
    if i < 0:
        return None
    rest = text[i + len(CURRENT_TABLE_MARKER):]
    # Stop at the next heading of ANY level. docs/measured-2026-09.md puts the
    # v0.4.0-vs-v0.5.0 engine control under a `###` immediately after the
    # headline table, and one of its numeric columns is an ENGINE ratio
    # (1.60x), not a ratio against the oracle -- reading it as one made this
    # check demand that a 1.6x engine speedup be >= 10x.
    m = re.search(r"^#{1,6} ", rest, re.M)
    if m:
        rest = rest[: m.start()]
    return re.findall(
        r"^\|\s*([A-Za-z0-9_.\-]+)\s*\|[^|]*\|[^|]*\|\s*\**([\d.]+)x\**\s*\|",
        rest,
        re.M,
    )


def claim_speedup_table_meets_the_criteria(docs, base, _args):
    """Every documented speedup must REACH PLAN's thresholds.

    The inverse of the v0.1.1-v0.4 retraction guard, and inverted deliberately
    (see SPEEDUP_LIMITS). PLAN now records >=10x on x86/x64 and >=4x on the
    capstone arches as MET, so a table row below its threshold means either a
    performance regression or a document that has drifted from the code.
    Needs no timing run: it is a consistency check between two documents.
    """
    rows, missing = [], []
    for doc in ("README.md", "docs/measured-2026-09.md"):
        found = _current_speedup_rows(docs, doc)
        if found is None:
            missing.append(f"{doc} has no {CURRENT_TABLE_MARKER}")
        elif not found:
            missing.append(f"{doc}'s current speedup table has no rows")
        else:
            rows += found
    bad = list(missing)
    for fixture, value in rows:
        limit = SPEEDUP_LIMITS["x86" if fixture in X86_FIXTURES else "capstone"]
        if float(value) < limit:
            bad.append(f"{fixture} {value}x < {limit}x")
    return Result(
        "SPEEDUP-MET",
        "fail",
        "README.md + docs/measured-2026-09.md + PLAN.md",
        "every documented speedup reaches the 10x/4x criteria PLAN records as MET",
        not bad,
        "x86/x64 >= 10.0x, capstone arches >= 4.0x",
        ", ".join(f"{f}={v}x" for f, v in rows) or "none parsed",
        "; ".join(bad),
    )


def claim_retraction_markers(docs, base, _args):
    """The sentences that record the v0.1.1 retractions must still be there.

    v0.5 met the performance criterion, so the two speed markers changed
    TENSE, not presence. They are still checked, because the point of a
    retraction record is that it survives the good news: a reader has to be
    able to see that this project once claimed a speedup it could not
    support, and what the measurement actually was when it was withdrawn.
    """
    required = [
        ("PLAN.md", r"NOT MET", "PLAN still records what the >=10x/>=4x criterion measured when it was unmet"),
        ("README.md", r"neither was met", "README still records that the perf criterion was unmet at v0.1.1"),
        (
            "MANUAL.md",
            r"No comparison against\s*\n?\s*`ropper`",
            "MANUAL still declines to make a ropper comparison",
        ),
    ]
    missing = [f"{doc}: {why}" for doc, pat, why in required if not docs.has(doc, pat)]
    return Result(
        "RETRACTIONS-PRESENT",
        "fail",
        "README.md, MANUAL.md, PLAN.md",
        "the v0.1.1 retraction sentences are still in the documents",
        not missing,
        "3 markers present",
        f"{3 - len(missing)} present",
        "; ".join(missing),
    )


def claim_no_ropper_speedup(docs, base, _args):
    """The unsourced "~9-14x faster than ropper" figure must not come back."""
    pat = r"(?:\d+\s*[-–]\s*\d+|\d+(?:\.\d+)?)\s*[x×]\s*(?:faster\s*)?(?:than\s*)?`?ropper"
    hits = []
    for doc in ("README.md", "MANUAL.md", "PLAN.md"):
        for m in re.finditer(pat, docs.get(doc), re.I):
            hits.append(f"{doc}: {m.group(0)!r}")
    return Result(
        "NO-ROPPER-SPEEDUP",
        "fail",
        "README.md, MANUAL.md, PLAN.md",
        "no speedup-vs-ropper figure is asserted (the old ~9-14x had no source)",
        not hits,
        "0 occurrences",
        f"{len(hits)} occurrences",
        "; ".join(hits),
    )


def claim_flag_coverage(docs, base, _args):
    """MANUAL's flag table covers all 30 of ROPgadget 7.7's flags."""
    res = rf_paths.oracle(required=False)
    if res is None:
        return Result(
            "FLAG-COVERAGE", "warn", "MANUAL.md",
            "MANUAL's flag table names every ROPgadget flag",
            True, "30 flags", "skipped", "oracle not available on this machine",
        )
    args_py = os.path.join(os.path.dirname(res[1]), "ropgadget", "args.py")
    if not os.path.exists(args_py):
        args_py = os.path.join(os.path.dirname(res[1]), "args.py")
    if not os.path.exists(args_py):
        return Result(
            "FLAG-COVERAGE", "warn", "MANUAL.md",
            "MANUAL's flag table names every ROPgadget flag",
            True, "30 flags", "skipped", f"args.py not found next to {res[1]}",
        )
    with open(args_py, "r", encoding="utf-8") as fh:
        src = fh.read()
    calls = re.findall(r"add_argument\(([^)]*)", src, re.S)
    flags = []
    for call in calls:
        names = re.findall(r"[\"'](--?[A-Za-z][A-Za-z0-9-]*)[\"']", call)
        if names:
            flags.append(names[-1])  # the long form is written last in args.py
    manual = docs.get("MANUAL.md")
    table = manual.split("### ROPgadget flag coverage", 1)[-1].split("### Known divergences", 1)[0]
    missing = [f for f in flags if f"`{f}" not in table]
    stated = re.search(r"all (\d+)\s*\n?\s*flags", table)
    stated_n = int(stated.group(1)) if stated else None
    ok = not missing and len(calls) == 30 and stated_n == 30
    return Result(
        "FLAG-COVERAGE",
        "fail",
        "MANUAL.md vs ropgadget/args.py",
        "MANUAL's flag-coverage table names every flag ROPgadget 7.7 defines",
        ok,
        f"{len(calls)} add_argument calls in args.py, MANUAL says {stated_n}",
        f"{len(flags) - len(missing)} of {len(flags)} flags found in the table",
        ("missing from the table: " + ", ".join(missing)) if missing else "",
    )


def claim_mcp_tool_count(docs, base, _args):
    """"8 tools" in README/MANUAL == the number of #[tool(...)] in rf-mcp."""
    src_path = os.path.join(REPO, "crates", "rf-mcp", "src", "lib.rs")
    if not os.path.exists(src_path):
        return Result(
            "MCP-TOOL-COUNT", "warn", "README.md, MANUAL.md",
            "the advertised MCP tool count matches the source",
            True, "8", "skipped", "crates/rf-mcp/src/lib.rs not present",
        )
    with open(src_path, "r", encoding="utf-8") as fh:
        actual = len(re.findall(r"#\[tool\(", fh.read()))
    stated = set()
    m = re.search(r"exposing (\d+) tools", docs.get("MANUAL.md"))
    if m:
        stated.add(int(m.group(1)))
    m = re.search(r"\*\*The (\d+) tools", docs.get("MANUAL.md"))
    if m:
        stated.add(int(m.group(1)))
    return Result(
        "MCP-TOOL-COUNT",
        "fail",
        "MANUAL.md vs crates/rf-mcp/src/lib.rs",
        "the advertised MCP tool count equals the number of #[tool] attributes",
        stated == {actual},
        f"{actual} (#[tool( in rf-mcp/src/lib.rs)",
        ", ".join(str(s) for s in sorted(stated)) or "no count stated",
    )


def claim_use_case_count(docs, base, _args):
    """README says the MANUAL carries 9 scenario-based use cases."""
    actual = len(re.findall(r"^#+\s*UC\d+\b", docs.get("MANUAL.md"), re.M))
    m = re.search(r"(\d+) scenario-based use cases", docs.get("README.md"))
    stated = int(m.group(1)) if m else None
    return Result(
        "USE-CASE-COUNT",
        "fail",
        "README.md vs MANUAL.md",
        "the number of use-case sections README advertises exists in MANUAL",
        stated == actual,
        str(stated),
        str(actual),
    )


# Fixtures that cannot be scanned from the filename alone, and the flags that
# supply what the file does not carry.
#
# The fat Mach-O needs `--arch` because it holds two slices at overlapping
# virtual addresses: since CORE-03 rop-finder refuses to scan the concatenation
# rather than disassembling one slice with the other's decoder. Naming a slice
# is the supported way to scan it, so that is what "this format is supported"
# means for a universal binary — not that a bare invocation exits 0.
SCAN_FLAGS = {
    "raw-x86.raw": ["--rawArch=x86", "--rawMode=32"],
    "UNIVERSAL-x86-x64-libSystem.B.dylib": ["--arch", "x86_64"],
}


def claim_arch_count(docs, base, _args):
    """Every fixture the docs claim support for actually scans."""
    binary = rf_paths.rop_finder()
    unsupported = []
    for name in rf_paths.fixture_names():
        extra = SCAN_FLAGS.get(name, [])
        p = subprocess.run(
            [binary, "--binary", rf_paths.fixture_path(name), "--depth", "2"] + extra,
            capture_output=True,
            text=True,
        )
        if p.returncode != 0:
            unsupported.append(f"{name} (exit {p.returncode})")
    return Result(
        "CORPUS-SCANS",
        "fail",
        "README.md architecture/format list",
        "every fixture in the documented corpus is scanned without an error exit",
        not unsupported,
        f"{len(rf_paths.fixture_names())} fixtures scan cleanly",
        f"{len(rf_paths.fixture_names()) - len(unsupported)} scan cleanly",
        "; ".join(unsupported),
    )


def claim_live_speedup(docs, base, args):
    """Live wall-clock speedup on this machine (informational)."""
    if args.no_timing:
        return None
    binary = rf_paths.rop_finder()
    rows = []
    for name, kind in (("elf-Linux-x86", "x86"), ("elf-ARM64-bash", "capstone")):
        fx = rf_paths.fixture_path(name)

        def best(cmd):
            b = None
            for _ in range(args.timing_runs):
                t0 = time.perf_counter()
                subprocess.run(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
                )
                dt = time.perf_counter() - t0
                b = dt if b is None else min(b, dt)
            return b

        ours = best([binary, "--binary", fx, "--depth", "10"])
        ref = best(rf_paths.oracle_cmd(fx, dump=False, depth=10))
        rows.append((name, kind, ref / ours))
    # v0.5: inverted with SPEEDUP-MET. A run BELOW the criterion is now the
    # interesting event. Kept at `warn` severity rather than `fail` because
    # this is raw wall clock on whatever machine the gate runs on, and a
    # loaded CI box is not a regression; SPEEDUP-MET is the fail-severity
    # half, and it compares the two documents against each other where no
    # machine can move the answer.
    bad = [f"{n} {s:.1f}x < {SPEEDUP_LIMITS[k]}x" for n, k, s in rows if s < SPEEDUP_LIMITS[k]]
    return Result(
        "LIVE-SPEEDUP",
        "warn",
        "README.md speedup table",
        "measured speedup on THIS machine reaches PLAN's 10x/4x criteria",
        not bad,
        "x86/x64 >= 10.0x, capstone arches >= 4.0x",
        ", ".join(f"{n}={s:.1f}x" for n, _, s in rows),
        "; ".join(bad) or "wall-clock, machine dependent - a loaded host can dip below",
    )


CLAIMS = [
    claim_fixture_count,
    claim_parity_percentage,
    claim_reference_total,
    claim_bit_exact,
    claim_speedup_table_meets_the_criteria,
    claim_retraction_markers,
    claim_no_ropper_speedup,
    claim_flag_coverage,
    claim_mcp_tool_count,
    claim_use_case_count,
    claim_arch_count,
    claim_live_speedup,
]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--strict", action="store_true", help="promote every warn to a failure")
    ap.add_argument("--no-timing", action="store_true", help="skip the live speedup measurement")
    ap.add_argument("--timing-runs", type=int, default=2)
    ap.add_argument("--doc-root", help="read README/MANUAL/PLAN/docs from here instead")
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args()

    docs = Docs(args.doc_root)
    base = load_parity_baselines()
    if not base:
        sys.exit(
            f"no parity baselines under {BASELINE_DIR} - run "
            "`python tests/parity.py --seed-reference` then `--update-floor` first"
        )

    print(f"# environment: {rf_paths.describe_environment()}")
    print(f"# documents:   {args.doc_root or REPO}")
    print(f"# baselines:   {len(base)} fixtures from {BASELINE_DIR}\n")

    results = []
    for fn in CLAIMS:
        r = fn(docs, base, args)
        if r is not None:
            results.append(r)

    width = max(len(r.cid) for r in results)
    failed = 0
    warned = 0
    for r in results:
        sev = r.severity
        if not r.ok and sev == "warn" and args.strict:
            sev = "fail"
        status = "ok  " if r.ok else ("FAIL" if sev == "fail" else "warn")
        if not r.ok:
            if sev == "fail":
                failed += 1
            else:
                warned += 1
        print(f"[{status}] {r.cid:<{width}}  {r.description}")
        print(f"{'':>7}  expected: {r.expected}")
        print(f"{'':>7}  measured: {r.measured}")
        if r.note:
            print(f"{'':>7}  note:     {r.note}")
        print(f"{'':>7}  source:   {r.source}")

    print(f"\n{len(results)} claims checked, {failed} failed, {warned} warned")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(
                {
                    "environment": rf_paths.describe_environment(brief=True),
                    "strict": args.strict,
                    "claims": [r.as_dict() for r in results],
                },
                fh,
                indent=2,
                sort_keys=True,
            )
            fh.write("\n")
        print(f"wrote {args.json_out}")

    print("DOC-CLAIMS GATE: " + ("FAIL" if failed else "PASS"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
