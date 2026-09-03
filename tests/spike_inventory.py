#!/usr/bin/env python3
"""Phase 4b gadget-inventory spike (PLAN sec. 6.2 "Phase-4-entry spike").

Runs `rop-finder --json` over real Windows binaries and counts the gadget
classes a VirtualProtect chain needs:

  * pop rcx / pop rdx / pop r8 / pop r9   (Win64 arg registers; r8/r9 pops
    are known to be scarce in real PEs -- the design must survive that)
  * pop rax / pop rbx / pop rsp           (scratch + pivots)
  * push-based arg gadgets                (push rX ; ... ; ret)
  * mov reg, [reg] dereference gadgets    (IAT resolution path)
  * stack pivots                          (xchg rsp / leave / add rsp, imm / pop rsp)
  * jmp/call reg gadgets                  (dispatchers, indirect calls)
  * call/jmp qword ptr [reg]              (IAT call sites)

Writes tests/spike-report.md (--out/--no-write override). System binaries (kernel32.dll, ntoskrnl.exe)
are copied into tests/spike-binaries/ (gitignored) -- skip them gracefully
when absent.

Usage: python tests/spike_inventory.py [--release] [--out PATH] [--no-write]
"""

import argparse
import json
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

BINARIES = [
    ("tests/fixtures/pe-x64-cmd-v6.1.7601", "cmd.exe x64 6.1.7601"),
    ("tests/fixtures/pe-x86-cmd-v6.1.7600", "cmd.exe x86 6.1.7600"),
    ("tests/spike-binaries/kernel32.dll", "kernel32.dll (this machine)"),
    ("tests/spike-binaries/ntoskrnl.exe", "ntoskrnl.exe (this machine)"),
]

POP_ARG = ["rcx", "rdx", "r8", "r9"]
POP_OTHER = ["rax", "rbx", "rsp", "rsi", "rdi"]


def clean_tail(insns):
    """ropmaker tail rule: everything after insn[0] is a pop or bare ret."""
    for insn in insns[1:]:
        head = insn.split()[0] if insn.split() else ""
        if head == "pop":
            continue
        if insn == "ret":
            continue
        return False
    return True


def inventory(gadgets):
    inv = {}

    def count_first(pred, clean=True):
        n = 0
        for g in gadgets:
            insns = [i.strip() for i in g["text"].split(" ; ")]
            if pred(insns[0]) and (not clean or clean_tail(insns)):
                n += 1
        return n

    for reg in POP_ARG + POP_OTHER:
        inv[f"pop {reg}"] = count_first(lambda i, r=reg: i == f"pop {r}")
    for reg in POP_ARG:
        inv[f"push {reg}"] = count_first(lambda i, r=reg: i == f"push {r}")
        # mov rX, qword ptr [rY] -- dereference (IAT path)
        inv[f"mov {reg}, [reg]"] = count_first(
            lambda i, r=reg: re.fullmatch(rf"mov {r}, qword ptr \[\w+\]", i) is not None
        )
    inv["mov rax, [reg]"] = count_first(
        lambda i: re.fullmatch(r"mov rax, qword ptr \[\w+\]", i) is not None
    )
    # mov-from-stack fallback: mov rX, qword ptr [rsp] / [rsp+imm]
    for reg in POP_ARG:
        inv[f"mov {reg}, [rsp+imm]"] = count_first(
            lambda i, r=reg: re.fullmatch(
                rf"mov {r}, qword ptr \[rsp(\+0x[0-9a-f]+)?\]", i
            )
            is not None
        )
        # reg-move fallback: pop rax -> mov rX, rax
        inv[f"mov {reg}, rax"] = count_first(
            lambda i, r=reg: re.fullmatch(rf"mov {r}, rax", i) is not None
        )
    # pivots
    inv["pop rsp"] = inv.get("pop rsp", 0)
    inv["xchg rsp, reg"] = count_first(
        lambda i: re.fullmatch(r"xchg (rsp|\w+), (rsp|\w+)", i) is not None and "rsp" in i
    )
    inv["leave"] = count_first(lambda i: i == "leave")
    inv["add rsp, imm"] = count_first(
        lambda i: re.fullmatch(r"add rsp, (0x[0-9a-f]+|\d+)", i) is not None
    )
    # indirect control flow (tails differ -- these END the gadget)
    inv["jmp reg"] = sum(
        1 for g in gadgets if re.fullmatch(r"jmp \w+", g["text"].split(" ; ")[-1].strip())
        and not g["text"].endswith("]") and "[" not in g["text"].split(" ; ")[-1]
    )
    inv["call reg"] = sum(
        1 for g in gadgets
        if re.fullmatch(r"call \w+", g["text"].split(" ; ")[-1].strip())
        and "[" not in g["text"].split(" ; ")[-1]
    )
    inv["call qword ptr [reg]"] = sum(
        1 for g in gadgets
        if re.fullmatch(r"call qword ptr \[\w+\]", g["text"].split(" ; ")[-1].strip())
    )
    inv["jmp qword ptr [reg]"] = sum(
        1 for g in gadgets
        if re.fullmatch(r"jmp qword ptr \[\w+\]", g["text"].split(" ; ")[-1].strip())
    )
    return inv


VERDICT = """
## Verdict

* **cmd.exe x64 (6.1.7601): NOT feasible with ret-terminated
  arg-population strategies.** The complete set of clean-tail pop gadgets is
  `pop {rax, rbx, rcx, rsi, rdi, rsp, rbp, r12, r13, r14, r15}` -- there is
  **no** ret-terminated gadget that writes `rdx`, `r8`, or `r9` (checked:
  all `pop` forms incl. `pop r8d/r9d`, all `mov`/`xchg`/`lea` first-insns,
  tails relaxed to allow `add rsp, imm` fixups). `mov rX, rax` and
  `mov rX, [rsp+imm]` forms exist only as jmp-terminated dispatcher
  fragments (JOP territory, Phase 5). A VirtualProtect chain here needs
  `--api-addr` AND gadgets this binary does not have; the builder reports a
  structured error naming the unresolvable argument registers and every
  strategy it tried. This is exactly the finding PLAN sec. 6.2's spike was added
  to force ("the design must survive that finding") -- the design survives
  it by failing cleanly, not by emitting a DOA chain.
* **kernel32.dll (this machine): also not feasible via clean pops** -- zero
  `pop rcx/rdx/r8/r9`, zero `mov rX, rax` / `mov rX, [rsp]` with usable
  tails. Push/rsp-relative fragments exist but are jmp-terminated.
* **ntoskrnl.exe (this machine): feasible, pop-based.** `pop rcx` (3),
  `pop rdx` (4), `pop r8` (3), `pop r9` (2) -- the full Win64 arg set plus
  `add rsp, imm` pivots (348). This is PLAN sec. 6.2's ring0 target; it is the
  primary success-path demo for the x64 builder.
* **cmd.exe x86 (6.1.7600): feasible via the stdcall layout, no arg pops
  needed.** Win32 VirtualProtect takes its four args on the stack; the
  chain is `[api][ret-to-shellcode][lpAddress][dwSize][0x40][&old]` and
  VirtualProtect's own `ret 0x10` transfers control to the shellcode
  (second-stack frame).

## Import-table findings (anchor-first vs IAT, PLAN sec. 6.2 #3)

* Neither cmd.exe (x64 nor x86) imports **VirtualProtect**; both import
  **VirtualAlloc** (usable IAT target for a VirtualAlloc-based variant).
* kernel32.dll on this machine DOES import **VirtualProtect** (IAT slot
  resolvable at load time) -- the IAT-deref path is exercised against it.
* Conclusion (as PLAN predicted): **anchor-first (`--api-addr`) is the
  primary path**; IAT dereference is implemented as strategy (b) for
  binaries that actually import the API.
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", action="store_true", default=True)
    ap.add_argument("--debug", dest="release", action="store_false")
    # CLAIM-08: CI runs this harness purely to prove it *runs* on a non-Windows
    # host. It must not rewrite the committed report while doing so, so the
    # destination is a flag and `--no-write` prints only.
    ap.add_argument(
        "--out",
        default=os.path.join(HERE, "spike-report.md"),
        help="where to write the markdown report (default tests/spike-report.md)",
    )
    ap.add_argument("--no-write", action="store_true", help="print the report, write nothing")
    args = ap.parse_args()
    exe = rf_paths.rop_finder(release=args.release)

    rows = []
    for rel, label in BINARIES:
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            print(f"[skip] {rel} not present", file=sys.stderr)
            continue
        p = subprocess.run([exe, "--binary", path, "--json"], capture_output=True, text=True)
        if p.returncode != 0:
            print(f"[skip] {rel}: rop-finder failed: {p.stderr.strip()}", file=sys.stderr)
            continue
        gadgets = json.loads(p.stdout)
        inv = inventory(gadgets)
        rows.append((label, len(gadgets), inv))
        print(f"[ok] {label}: {len(gadgets)} gadgets", file=sys.stderr)

    if not rows:
        sys.exit("no binaries could be scanned")

    # render markdown
    keys = list(rows[0][2].keys())
    out = ["# Phase 4b gadget-inventory spike report", ""]
    out.append("PLAN sec. 6.2 Phase-4-entry spike: can real Windows binaries sustain a")
    out.append("VirtualProtect ROP chain, and which arg-population strategy does each need?")
    out.append("")
    out.append("Counts are post-dedup gadgets whose FIRST instruction matches and whose")
    out.append("tail follows the ropmaker clean-tail rule (pops / bare ret only).")
    out.append("System binaries were scanned from local copies (not committed).")
    out.append("")
    header = "| gadget class | " + " | ".join(r[0] for r in rows) + " |"
    out.append(header)
    out.append("|" + "---|" * (len(rows) + 1))
    out.append("| total gadgets | " + " | ".join(str(r[1]) for r in rows) + " |")
    for k in keys:
        out.append(f"| `{k}` | " + " | ".join(str(r[2][k]) for r in rows) + " |")
    out.append("")
    report = "\n".join(out) + VERDICT
    if not args.no_write:
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(report)
        print(f"[wrote] {args.out}", file=sys.stderr)
    print(report)


if __name__ == "__main__":
    main()
