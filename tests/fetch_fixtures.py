#!/usr/bin/env python3
"""Fetch and verify the 24 third-party test fixtures.

The fixtures in tests/fixtures/ are byte-identical redistributions of other
people's compiled binaries — Microsoft's cmd.exe, Apple's ls and libSystem,
GPL bash and coreutils, cairo, CTF challenge binaries. They are NOT covered by
this repository's LICENSE; tests/fixtures/PROVENANCE.md records the origin and
license of each one.

The copies are kept in-tree so that CI and the parity gate never depend on
GitHub being reachable. This script exists for the other case: if you would
rather not hold the copies, delete them and re-fetch on demand. Either way,
every byte is checked against tests/fixtures/MANIFEST.sha256.

They come from ROPgadget's test-suite-binaries/ at a pinned commit — the same
commit this project's parity numbers were measured against.

Usage:
  python tests/fetch_fixtures.py                 # fetch what is missing, verify all
  python tests/fetch_fixtures.py --verify-only   # no network; what CI runs
  python tests/fetch_fixtures.py --force         # re-fetch even if present
  python tests/fetch_fixtures.py --list          # print the 24 names, one per line
  python tests/fetch_fixtures.py --from-clone ../ropgadget   # copy from a local clone

Exit status: 0 all present and correct, 1 a checksum mismatch or a missing file
that could not be fetched, 2 a usage error.
"""

import argparse
import hashlib
import os
import shutil
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")
MANIFEST = os.path.join(FIXTURES, "MANIFEST.sha256")

# Pinned upstream. Do not float this to a branch: the fixtures ARE the parity
# corpus, so a silent upstream change would silently move the parity number in
# docs/measured-2026-09.md. See tests/fixtures/PROVENANCE.md.
UPSTREAM_REPO = "https://github.com/JonathanSalwan/ROPgadget"
UPSTREAM_COMMIT = "b6e3fe31af46d7e045fef99a3ab19ccbcea5c2f6"
UPSTREAM_SUBDIR = "test-suite-binaries"
RAW_URL = "https://raw.githubusercontent.com/JonathanSalwan/ROPgadget/{commit}/{subdir}/{name}"

CHUNK = 1 << 20


def read_manifest(path):
    """Parse a sha256sum-format manifest into [(name, hexdigest), ...]."""
    entries = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            digest, _, name = line.partition(" ")
            name = name.lstrip(" *")  # sha256sum binary-mode marker
            if len(digest) != 64 or not name:
                sys.exit(f"{path}:{lineno}: malformed manifest line: {line!r}")
            entries.append((name, digest.lower()))
    if not entries:
        sys.exit(f"{path}: no entries")
    return entries


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def fetch(name, dest):
    url = RAW_URL.format(commit=UPSTREAM_COMMIT, subdir=UPSTREAM_SUBDIR, name=name)
    tmp = dest + ".part"
    with urllib.request.urlopen(url, timeout=60) as resp, open(tmp, "wb") as out:
        shutil.copyfileobj(resp, out, CHUNK)
    os.replace(tmp, dest)


def copy_from_clone(clone, name, dest):
    src = os.path.join(clone, UPSTREAM_SUBDIR, name)
    if not os.path.isfile(src):
        raise FileNotFoundError(src)
    tmp = dest + ".part"
    shutil.copyfile(src, tmp)
    os.replace(tmp, dest)


def main():
    ap = argparse.ArgumentParser(
        description="Fetch and verify tests/fixtures against MANIFEST.sha256."
    )
    ap.add_argument("--verify-only", action="store_true",
                    help="never touch the network; only check what is on disk")
    ap.add_argument("--force", action="store_true",
                    help="re-acquire every fixture even if it is already correct")
    ap.add_argument("--list", action="store_true",
                    help="print the manifest's file names and exit")
    ap.add_argument("--from-clone", metavar="DIR",
                    help="copy from a local ROPgadget clone instead of downloading; "
                         "the clone must be at the pinned commit")
    args = ap.parse_args()

    if args.verify_only and (args.force or args.from_clone):
        ap.error("--verify-only cannot be combined with --force or --from-clone")

    entries = read_manifest(MANIFEST)

    if args.list:
        for name, _ in entries:
            print(name)
        return 0

    print(f"{len(entries)} fixtures, pinned to {UPSTREAM_REPO} @ {UPSTREAM_COMMIT[:12]}")
    if not args.verify_only:
        print("These are third-party binaries under their own licenses; "
              "see tests/fixtures/PROVENANCE.md before redistributing them.")

    os.makedirs(FIXTURES, exist_ok=True)
    ok = missing = fetched = bad = 0

    for name, want in entries:
        dest = os.path.join(FIXTURES, name)
        have = os.path.isfile(dest)

        if have and not args.force and sha256(dest) == want:
            ok += 1
            continue

        if args.verify_only:
            if have:
                print(f"  MISMATCH  {name}\n            expected {want}\n"
                      f"            got      {sha256(dest)}")
                bad += 1
            else:
                print(f"  MISSING   {name}")
                missing += 1
            continue

        try:
            if args.from_clone:
                copy_from_clone(args.from_clone, name, dest)
            else:
                fetch(name, dest)
        except (OSError, urllib.error.URLError) as exc:
            print(f"  FAILED    {name}: {exc}")
            bad += 1
            continue

        got = sha256(dest)
        if got != want:
            print(f"  MISMATCH  {name} after fetch\n            expected {want}\n"
                  f"            got      {got}")
            bad += 1
            continue

        print(f"  ok        {name}")
        fetched += 1

    summary = f"{ok} already correct"
    if fetched:
        summary += f", {fetched} acquired"
    if missing:
        summary += f", {missing} missing"
    if bad:
        summary += f", {bad} BAD"
    print(summary)

    return 1 if (bad or missing) else 0


if __name__ == "__main__":
    sys.exit(main())
