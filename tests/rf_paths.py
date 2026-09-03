#!/usr/bin/env python3
"""Shared path/tool resolution for every harness in tests/.

Before this module, five harnesses each resolved the rop-finder binary and the
ROPgadget oracle their own way, and three of the five did it wrongly:

  * `tests/benchmark.py:13` and `tests/analyze_diff.py:78` hardcoded
    `rop-finder.exe` with no fallback, so they raised `OSError: [Errno 8] Exec
    format error` on macOS/Linux (CLAIM-08, PERF-08).
  * `tests/parity.py`, `tests/chain_parity.py` and `tests/spike_inventory.py`
    *preferred* the `.exe` and only fell back when it was absent — and this
    checkout used to ship a stale Windows PE in `target/release/`, so the
    fallback never fired and the documented parity command died on non-Windows
    hosts anyway (CLAIM-08).
  * every one of them ran the oracle with `sys.executable`, which is only
    correct if the interpreter running the harness happens to have python
    `capstone` installed (ENG-04).

Everything is resolved here instead, by platform and with environment
overrides, so a fresh clone can run every harness with one documented command.

Environment overrides
---------------------
``ROPGADGET_PATH``    absolute path to ``ROPgadget.py``.
``ROPGADGET_PYTHON``  interpreter that has python-capstone 5.0.7 installed.
``ROP_FINDER_BIN``    absolute path to a prebuilt rop-finder binary.
``RF_NO_BUILD=1``     never shell out to cargo; fail instead.

Oracle setup (the "one documented command")
-------------------------------------------
The oracle is ROPgadget 7.7 at upstream commit ``b6e3fe31af46`` with python
``capstone==5.0.7`` — the same capstone *generation* ``rf-scan`` links via
``capstone = "=0.13.0"``. From the parent directory of this repository::

    git clone https://github.com/JonathanSalwan/ROPgadget ropgadget
    git -C ropgadget checkout b6e3fe31af46
    python -m venv .venv-oracle
    .venv-oracle/bin/pip install 'capstone==5.0.7'          # Windows: .venv-oracle\\Scripts\\pip
    export ROPGADGET_PYTHON="$PWD/.venv-oracle/bin/python"  # Windows: ...\\Scripts\\python.exe

That is exactly the layout this module probes for by default, so on a machine
where those two commands have been run no environment variable is needed:
``../ropgadget/ROPgadget.py`` and ``../.venv-oracle`` are found automatically.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")

#: Files in tests/fixtures that are documentation/checksums, not binaries.
NON_FIXTURE_FILES = {"MANIFEST.sha256", "PROVENANCE.md"}

#: ROPgadget upstream commit this corpus of baselines was frozen against.
ORACLE_COMMIT = "b6e3fe31af46"
#: python-capstone version the oracle must be running.
ORACLE_CAPSTONE = "5.0.7"

_SETUP_HELP = """
The ROPgadget parity oracle was not found.

  git clone https://github.com/JonathanSalwan/ROPgadget ropgadget   # beside this repo
  git -C ropgadget checkout {commit}
  python -m venv .venv-oracle
  .venv-oracle/{bindir}/pip install 'capstone=={capstone}'

then either place them beside this repository (../ropgadget, ../.venv-oracle),
or set ROPGADGET_PATH and ROPGADGET_PYTHON.
""".strip()


def setup_help():
    return _SETUP_HELP.format(
        commit=ORACLE_COMMIT,
        capstone=ORACLE_CAPSTONE,
        bindir="Scripts" if os.name == "nt" else "bin",
    )


def exe_name(stem):
    """Platform-correct executable file name (CLAIM-08).

    This is *the* fix for the `.exe` hardcoding: the name is derived from the
    platform, never guessed and never probed-then-fallen-back-to.
    """
    return stem + ".exe" if sys.platform == "win32" else stem


def fixture_names():
    """Every real binary in tests/fixtures, sorted."""
    return sorted(
        n
        for n in os.listdir(FIXTURES)
        if n not in NON_FIXTURE_FILES and os.path.isfile(os.path.join(FIXTURES, n))
    )


def fixture_path(name):
    return os.path.join(FIXTURES, name)


def rop_finder(release=True, build=True, package="rf-cli", stem="rop-finder"):
    """Absolute path to the rop-finder binary, building it if it is absent.

    Resolution order: ``$ROP_FINDER_BIN`` -> ``target/<profile>/<name>`` ->
    ``cargo build -p <package>``. The file name is chosen by platform up front,
    so a stale `rop-finder.exe` left in a checkout can never be handed to a
    non-Windows exec().
    """
    override = os.environ.get("ROP_FINDER_BIN")
    if override:
        if not os.path.exists(override):
            sys.exit(f"ROP_FINDER_BIN={override} does not exist")
        return override

    profile = "release" if release else "debug"
    path = os.path.join(REPO, "target", profile, exe_name(stem))
    if os.path.exists(path):
        return path

    if not build or os.environ.get("RF_NO_BUILD") == "1":
        sys.exit(f"{path} not found (build it with: cargo build -p {package} --{profile})")

    cmd = ["cargo", "build", "-p", package]
    if release:
        cmd.append("--release")
    print(f"[rf_paths] {path} missing — running: {' '.join(cmd)}", file=sys.stderr)
    p = subprocess.run(cmd, cwd=REPO)
    if p.returncode != 0 or not os.path.exists(path):
        sys.exit(f"failed to build {path} ({' '.join(cmd)} exited {p.returncode})")
    return path


def _has_capstone(interpreter):
    try:
        p = subprocess.run(
            [interpreter, "-c", "import capstone;print(capstone.__version__)"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return p.stdout.strip() if p.returncode == 0 else None


def _candidate_oracle_scripts():
    env = os.environ.get("ROPGADGET_PATH")
    if env:
        yield env
        return
    parent = os.path.dirname(REPO)
    # Repo-relative, in preference order. The sibling checkout stays supported
    # because that is what existing machines have, but it is no longer the
    # *only* thing that works (ENG-04).
    for rel in (
        os.path.join(REPO, "third_party", "ropgadget", "ROPgadget.py"),
        os.path.join(REPO, "vendor", "ropgadget", "ROPgadget.py"),
        os.path.join(parent, "ropgadget", "ROPgadget.py"),
    ):
        yield rel


def _candidate_interpreters():
    env = os.environ.get("ROPGADGET_PYTHON")
    if env:
        yield env
        return
    parent = os.path.dirname(REPO)
    bindir = "Scripts" if os.name == "nt" else "bin"
    pyexe = "python.exe" if os.name == "nt" else "python"
    for venv in (
        os.path.join(REPO, ".venv-oracle"),
        os.path.join(parent, ".venv-oracle"),
        os.path.join(parent, "ropgadget", ".venv"),
    ):
        yield os.path.join(venv, bindir, pyexe)
    # Last resort: the interpreter running this harness, but only if it can
    # actually import capstone. `sys.executable` used to be used unconditionally,
    # which is why parity.py "worked" while measuring nothing (ENG-04).
    yield sys.executable


def oracle(required=True):
    """``(interpreter, ROPgadget.py, capstone_version)`` for the parity oracle.

    Returns ``None`` instead of exiting when ``required=False``.
    """
    script = None
    for cand in _candidate_oracle_scripts():
        if cand and os.path.exists(cand):
            script = cand
            break
    if script is None:
        if not required:
            return None
        sys.exit("ROPgadget.py not found.\n" + setup_help())

    for cand in _candidate_interpreters():
        if not cand or not os.path.exists(cand):
            continue
        version = _has_capstone(cand)
        if version:
            return (cand, script, version)

    if not required:
        return None
    sys.exit(
        "found "
        + script
        + " but no interpreter with python-capstone installed.\n"
        + setup_help()
    )


def oracle_cmd(binary, extra=(), dump=True, depth=10, ropchain=False):
    """Full argv for one oracle invocation."""
    interp, script, _ = oracle()
    cmd = [interp, script, "--binary", binary]
    if ropchain:
        cmd.append("--ropchain")
    else:
        cmd += ["--depth", str(depth)]
        if dump:
            cmd.append("--dump")
    return cmd + list(extra)


def describe_environment(brief=False):
    """One-line provenance string.

    ``brief=True`` omits absolute paths — use it for anything committed to git,
    so a baseline file does not carry one developer's directory layout.
    """
    res = oracle(required=False)
    if res is None:
        return f"{sys.platform} python={sys.version.split()[0]} oracle=<not found>"
    interp, script, version = res
    if brief:
        return (
            f"{sys.platform} python={sys.version.split()[0]} "
            f"ROPgadget@{ORACLE_COMMIT} capstone={version}"
        )
    return (
        f"{sys.platform} python={sys.version.split()[0]} "
        f"oracle={script} interp={interp} capstone={version}"
    )
