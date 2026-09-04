#!/usr/bin/env python3
"""Ground truth for CLS-09's stack delta and clobber set, by EXECUTION.

Phase 4's exit criterion for the semantic workstream is:

    Stack delta and clobber set are verified against ground truth on a
    500-gadget sample with zero mismatches; every gadget where the rsp effect
    is non-constant reports None rather than a number.

Nothing in this file reads, imports, links or transliterates `rf-classify`.
It takes the gadget's *bytes*, runs them under the Unicorn CPU emulator, and
reports what the machine did. That is what makes it ground truth rather than a
second opinion from the same rules — the defect CLS-05/CLAIM-05 recorded about
the old classifier eval, which was the classifier retyped.

  input   crates/rf-classify/tests/ground-truth/x86-sample.jsonl
          (produced by `tests/effect_sample.rs`, a deterministic stride)
  output  crates/rf-classify/tests/ground-truth/x86-truth.jsonl
  check   `cargo test -p rop-finder-classify --test ground_truth`

    "D:/Private/ROP-Finder/.venv-oracle/Scripts/python.exe" \
        crates/rf-classify/tests/ground-truth/oracle_unicorn.py

HOW A CONSTANT IS TOLD FROM A NON-CONSTANT
------------------------------------------
Every gadget is executed K times with a different *uncontrolled* machine
state each time — every general-purpose register, the arithmetic flags, the
direction flag, all non-stack memory, and the absolute address of the stack
itself — while the *controlled* state, the payload bytes at each offset from
the entry stack pointer, is byte-identical in every trial.

That single design decision is what makes the file an oracle for three
different questions at once:

  * **stack delta** — the deltas agree across all K trials iff the effect is
    constant. `pop rdi ; ret` agrees (16). `xchg rsp, rax ; ret` does not,
    because rax differs per trial. `leave ; ret` does not, because rbp does.
    `pop rsp ; ret` does not, because the stack base does. In every one of
    those the expected answer is None, and it is derived here, not assumed.
  * **clobbered** — a register whose final value differs across trials got it
    from something the payload does not choose.
  * **set** — a register that ends every trial holding the *same* value it did
    not start with got that value from the payload or from a constant.
  * **untouched** — a register that ends every trial holding exactly what it
    started with.

A gadget is only reported when every trial ran to completion. Gadgets
containing instructions Unicorn cannot faithfully model in a bare CPU with no
kernel — the syscall and interrupt gates, the ring-0 instructions, and the
non-deterministic readers `rdtsc`/`rdrand`/`cpuid` — are reported as
`status: "skipped"` with a reason, and the Rust side counts them so the
skipped population is visible rather than silently absent.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

try:
    from unicorn import (
        UC_ARCH_X86,
        UC_HOOK_MEM_UNMAPPED,
        UC_MODE_32,
        UC_MODE_64,
        UC_PROT_ALL,
        Uc,
        UcError,
    )
    from unicorn import x86_const as X
except ImportError:  # pragma: no cover - reported, never silently skipped
    sys.exit(
        "unicorn is not importable from this interpreter.\n"
        "Run with D:/Private/ROP-Finder/.venv-oracle/Scripts/python.exe"
    )

HERE = Path(__file__).resolve().parent
SAMPLE = HERE / "x86-sample.jsonl"
TRUTH = HERE / "x86-truth.jsonl"
STATS = HERE / "x86-truth-stats.json"

# ---------------------------------------------------------------------------
# Layout. Everything is a fixed constant so a re-run reproduces the file byte
# for byte.
# ---------------------------------------------------------------------------

TRIALS = 6
SEED = 0x5EEDC1A9

# The "uncontrolled data" region. Every register and every payload word points
# in here, so a dereference through any of them is mapped rather than a fault.
# Its CONTENTS differ in every trial, which is the point: memory that is not
# the chain payload is uncontrolled state, and a register that ends up holding
# a byte from it must come out `clobbered`. (Filling it with `nop` instead —
# the obvious first design — made `mov eax, [rax+0x28]` look like a *constant*
# 0x90909090 and produced six false "set" verdicts. Nothing is ever executed
# out of this region: `emu_start` stops after exactly the gadget's own
# instruction count, and a gadget's control transfer is its last instruction.)
DATA = 0x2000_0000
DATA_SIZE = 0x0040_0000  # 4 MiB

# The stack. In 64-bit mode it lives ABOVE 4 GiB, because that is the only way
# to observe that `add esp, 0x120` in 64-bit code truncates rsp to 32 bits
# rather than offsetting it: with a stack below 4 GiB the truncation is
# invisible and the emulator reports a confident, wrong, constant delta.
STACK0 = {64: 0x0000_1000_0000_0000, 32: 0x3000_0000}
# Per-trial stride. The 64-bit value moves the HIGH half of the stack address
# as well as the low half: with only the low half moving, `add esp, 0x120 ;
# pop rbx ; ret` produced the same (enormous, negative) delta in every trial
# and the emulator called the truncation a constant.
STACK_STRIDE = {64: 0x0000_0100_0010_0000, 32: 0x0010_0000}
STACK_SPAN = 0x0002_0000  # mapped region per trial
STACK_MID = 0x0001_0000  # rsp sits near here inside it
# rsp is also jittered inside the page, so its low bits are not all zero:
# a page-aligned rsp makes `or eax, <mask>` after `xchg esp, eax` look
# constant when it is not.
JITTER = 0x1A8
KEEP_PER_FIXTURE = 250  # 2 fixtures x 250 = the 500-gadget sample
TIMEOUT_US = 200_000

REGS64 = [
    ("rax", X.UC_X86_REG_RAX),
    ("rbx", X.UC_X86_REG_RBX),
    ("rcx", X.UC_X86_REG_RCX),
    ("rdx", X.UC_X86_REG_RDX),
    ("rsi", X.UC_X86_REG_RSI),
    ("rdi", X.UC_X86_REG_RDI),
    ("rbp", X.UC_X86_REG_RBP),
    ("r8", X.UC_X86_REG_R8),
    ("r9", X.UC_X86_REG_R9),
    ("r10", X.UC_X86_REG_R10),
    ("r11", X.UC_X86_REG_R11),
    ("r12", X.UC_X86_REG_R12),
    ("r13", X.UC_X86_REG_R13),
    ("r14", X.UC_X86_REG_R14),
    ("r15", X.UC_X86_REG_R15),
]

REGS32 = [
    ("eax", X.UC_X86_REG_EAX),
    ("ebx", X.UC_X86_REG_EBX),
    ("ecx", X.UC_X86_REG_ECX),
    ("edx", X.UC_X86_REG_EDX),
    ("esi", X.UC_X86_REG_ESI),
    ("edi", X.UC_X86_REG_EDI),
    ("ebp", X.UC_X86_REG_EBP),
]

SP_REG = {64: X.UC_X86_REG_RSP, 32: X.UC_X86_REG_ESP}
FLAGS_REG = {64: X.UC_X86_REG_EFLAGS, 32: X.UC_X86_REG_EFLAGS}

# Instructions a bare CPU with no kernel, no TSC and no CPUID table does not
# reproduce faithfully. A gadget containing one is reported as skipped rather
# than quietly turned into a wrong expectation.
UNFAITHFUL = {
    "syscall", "sysenter", "sysexit", "sysexitq", "sysret", "sysretq",
    "int", "int1", "int3", "into", "iret", "iretd", "iretq",
    "hlt", "ud0", "ud1", "ud2",
    "cli", "sti", "clts", "invd", "wbinvd", "invlpg",
    "lgdt", "lidt", "lldt", "ltr", "lmsw", "sgdt", "sidt", "sldt", "smsw", "str",
    "rdmsr", "wrmsr", "rsm", "vmcall", "vmlaunch", "vmresume", "vmxoff",
    "in", "insb", "insw", "insd", "out", "outsb", "outsw", "outsd",
    "rdtsc", "rdtscp", "rdpmc", "rdrand", "rdseed", "cpuid", "xgetbv", "xsetbv",
    "swapgs", "monitor", "mwait", "wrfsbase", "wrgsbase", "rdfsbase", "rdgsbase",
    "retf", "retfq", "retfw", "lret", "arpl", "lar", "lsl", "verr", "verw",
    "loadall", "ud1w",
}


def lcg(state: int) -> int:
    """A 64-bit LCG. Fixed multiplier and increment, seeded from SEED, so the
    per-trial uncontrolled state is reproducible."""
    return (state * 6364136223846793005 + 1442695040888963407) & 0xFFFF_FFFF_FFFF_FFFF


def payload_word(slot: int, word: int) -> int:
    """The controlled state: the value the chain payload places in the stack
    slot `slot` words above the entry stack pointer.

    Identical in every trial — that is what makes it "controlled" — and
    distinct per slot, so a register found holding one of these values can be
    traced back to the offset it came from. Every value is a valid pointer
    into the scratch region, so a gadget that pops one and dereferences it, or
    returns through it, does not fault.
    """
    off = (slot * 0x2A31) % 0x0030_0000
    v = DATA + 0x1000 + off
    return v & (0xFFFF_FFFF if word == 4 else 0xFFFF_FFFF_FFFF_FFFF)


# Byte offset -> payload byte, over the window a gadget can plausibly reach.
# Rebuilt once per word size and reused, because it is the same in every trial
# by construction.
_PAYLOAD_INDEX: dict[int, dict[int, int]] = {}


def payload_offset_of(value: int, word: int) -> int | None:
    """Which entry-relative byte offset holds `value`, if exactly one does."""
    index = _PAYLOAD_INDEX.get(word)
    if index is None:
        lo, hi = -256, 1024
        blob = bytearray()
        first = lo // word  # floors towards -inf in Python, which is wanted
        for k in range(first, (hi // word) + 2):
            blob += payload_word(k, word).to_bytes(word, "little")
        base = first * word
        seen: dict[int, list[int]] = {}
        for off in range(lo, hi):
            i = off - base
            if i < 0 or i + word > len(blob):
                continue
            seen.setdefault(int.from_bytes(blob[i : i + word], "little"), []).append(off)
        # Only unambiguous values identify an offset.
        index = {v: offs[0] for v, offs in seen.items() if len(offs) == 1}
        _PAYLOAD_INDEX[word] = index
    return index.get(value)


def make_uc(bits: int, trial: int, vaddr: int, code: bytes):
    """A machine for one trial: identical payload, different everything else."""
    mode = UC_MODE_64 if bits == 64 else UC_MODE_32
    uc = Uc(UC_ARCH_X86, mode)
    word = bits // 8

    rnd = lcg(SEED ^ (trial * 0x9E3779B9))
    for _ in range(3):
        rnd = lcg(rnd)

    # Uncontrolled memory: 4 MiB whose contents differ per trial.
    uc.mem_map(DATA, DATA_SIZE, UC_PROT_ALL)
    chunk = bytes(((lcg(rnd ^ (i * 0x100000001B3)) >> 27) & 0xFF) for i in range(0x1000))
    uc.mem_write(DATA, chunk * (DATA_SIZE // 0x1000))

    # The code page(s).
    page = vaddr & ~0xFFF
    span = ((vaddr + len(code) - page) + 0xFFF) & ~0xFFF
    try:
        uc.mem_map(page, max(span, 0x1000), UC_PROT_ALL)
    except UcError:
        pass
    uc.mem_write(vaddr, code)

    # The stack. Its ABSOLUTE ADDRESS varies per trial, so a gadget whose
    # result depends on where the stack happens to be (`mov rax, rsp`,
    # `lea rax, [rsp+8]`, `pop rsp`, `xchg rsp, rax`) is detected as
    # uncontrolled — while the payload at each offset from rsp stays
    # byte-identical.
    stack = STACK0[bits] + trial * STACK_STRIDE[bits]
    uc.mem_map(stack, STACK_SPAN, UC_PROT_ALL)
    jitter = (trial * JITTER) & (0xFF8 if bits == 64 else 0xFFC)
    sp = stack + STACK_MID + jitter
    # The payload is written RELATIVE TO sp, so slot k is always at sp + k*word
    # no matter where the stack or the jitter put sp.
    lo = stack
    first_slot = -((sp - lo) // word)
    slots = (STACK_SPAN - (sp - lo) % word) // word
    blob = bytearray()
    for k in range(slots):
        blob += payload_word(first_slot + k, word).to_bytes(word, "little")
    uc.mem_write(sp + first_slot * word, bytes(blob))

    # Incoming register values span the WHOLE address width rather than a
    # window inside the data region. Confining them to a 4 MiB window left
    # every register's high bits — including the 32-bit sign bit — identical
    # in every trial, so `cdq` (edx <- eax >> 31) came out constant and the
    # emulator called edx "set". Any address they reach is mapped on demand by
    # the hook below, so they do not need to point anywhere in particular.
    regs = REGS64 if bits == 64 else REGS32
    initial = {}
    for nm, rid in regs:
        rnd = lcg(rnd)
        val = rnd & (0x0000_7FFF_FFFF_FFFF if bits == 64 else 0xFFFF_FFFF)
        uc.reg_write(rid, val)
        initial[nm] = val
    uc.reg_write(SP_REG[bits], sp)

    # Arithmetic flags plus the direction flag; bit 1 is reserved-and-set.
    rnd = lcg(rnd)
    uc.reg_write(FLAGS_REG[bits], 0x2 | (rnd & 0xCD5))

    # Anything the gadget reaches that we did not map is mapped on demand and
    # filled with trial-varying bytes: non-stack memory is uncontrolled state.
    filler = bytes(((lcg(rnd ^ i) >> 24) & 0xFF) for i in range(0x1000))

    def on_unmapped(uc_, access, address, size, value, data):
        base = address & ~0xFFF
        try:
            uc_.mem_map(base, 0x1000, UC_PROT_ALL)
            uc_.mem_write(base, filler)
        except UcError:
            pass
        return True

    uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)
    return uc, sp, initial


def run_trials(rec: dict):
    """Execute the gadget TRIALS times. Returns (deltas, finals, initials) or
    a failure reason."""
    bits = rec["bits"]
    vaddr = int(rec["vaddr"], 16)
    code = bytes.fromhex(rec["bytes"])
    n_insns = len(rec["text"].split(" ; "))
    regs = REGS64 if bits == 64 else REGS32

    deltas = []
    finals = []
    initials = []
    for t in range(TRIALS):
        try:
            uc, sp, initial = make_uc(bits, t, vaddr, code)
        except UcError as e:
            return None, f"setup: {e}"
        try:
            uc.emu_start(vaddr, 0, TIMEOUT_US, n_insns)
        except UcError as e:
            return None, f"emu_start: {e}"
        try:
            after = uc.reg_read(SP_REG[bits])
            final = {nm: uc.reg_read(rid) for nm, rid in regs}
        except UcError as e:
            return None, f"reg_read: {e}"
        # Signed, and wrapped into the address width.
        span = 1 << bits
        d = (after - sp) % span
        if d >= span // 2:
            d -= span
        deltas.append(d)
        finals.append(final)
        initials.append(initial)
    return (deltas, finals, initials), None


def is_transfer(mnemonic: str) -> bool:
    """Does this instruction hand control somewhere else?"""
    return (
        mnemonic.startswith("j")
        or mnemonic.startswith("loop")
        or mnemonic.startswith("ret")
        or mnemonic in {"call", "lcall", "ljmp", "xbegin", "xabort"}
    )


def ret_imm(text: str) -> int | None:
    """The immediate on a `ret imm16`, if the gadget's last instruction is one."""
    last = text.split(" ; ")[-1].strip()
    parts = last.split()
    if len(parts) == 2 and parts[0] in ("ret", "retn"):
        try:
            return int(parts[1], 0)
        except ValueError:
            return None
    return None


def classify(rec: dict):
    insns = [ins.strip() for ins in rec["text"].split(" ; ")]
    mnems = {ins.split(" ")[0].lower() for ins in insns}
    bad = sorted(mnems & UNFAITHFUL)
    if bad:
        return {"status": "skipped", "reason": f"not faithfully emulated: {','.join(bad)}"}

    # A gadget whose control leaves before its own terminator is not something
    # this method can measure. `emu_start` runs a fixed instruction COUNT, so
    # on the taken path it executes the branch target's instructions and
    # reports their stack effect as if it were the gadget's. There is no
    # principled stop point along that path, and the quantity being defined —
    # what THIS gadget does to rsp — is not well defined either, because which
    # instructions run depends on incoming flags the chain does not control.
    # rf-classify answers None for exactly this case; rather than "verify" that
    # against a number the emulator cannot vouch for, the case is excluded and
    # counted.
    if any(is_transfer(i.split(" ")[0].lower()) for i in insns[:-1]):
        return {"status": "skipped", "reason": "early transfer: control leaves before the terminator"}

    # QEMU (which Unicorn is built on) loads `ret imm16` with a SIGNED word
    # (`x86_ldsw_code` in target/i386/tcg/translate.c) and adds it to rsp. The
    # Intel SDM and the AMD APM describe the operand as a count of bytes to
    # release, and iced-x86 -- like Bochs -- zero-extends it. The two agree for
    # every imm16 below 0x8000 and disagree by exactly 0x10000 above it. This
    # oracle cannot adjudicate between a documented ISA and an emulator, so it
    # declines to state a value for the disputed range instead of recording one
    # that might be wrong. `ret imm16` below 0x8000 stays verified.
    ri = ret_imm(rec["text"])
    if ri is not None and ri >= 0x8000:
        return {
            "status": "skipped",
            "reason": "ret imm16 >= 0x8000: qemu sign-extends where the SDM zero-extends",
        }

    out, err = run_trials(rec)
    if out is None:
        return {"status": "skipped", "reason": err}
    deltas, finals, initials = out

    delta = deltas[0] if all(d == deltas[0] for d in deltas) else None

    sets, clobbers = [], []
    for nm in finals[0]:
        if all(finals[t][nm] == initials[t][nm] for t in range(TRIALS)):
            continue  # untouched
        if all(finals[t][nm] == finals[0][nm] for t in range(TRIALS)):
            sets.append(nm)
        else:
            clobbers.append(nm)

    # For every register that ended up holding a payload word, say which
    # offset from the entry stack pointer it came from. This is an independent
    # check of the register-transfer relations: it is derived from the value
    # that actually landed in the register, not from the instruction encoding.
    #
    # The search is at BYTE granularity, not word granularity: `dec esp ;
    # add esp, 0x24 ; pop ebx` really does read four bytes starting 35 bytes
    # above the entry stack pointer, and an aligned-only search would have
    # called that correct claim unverifiable.
    word = rec["bits"] // 8
    offsets = {nm: o for nm in sets if (o := payload_offset_of(finals[0][nm], word)) is not None}

    return {
        "status": "ok",
        "stack_delta": delta,
        "deltas": deltas if delta is None else None,
        "sets": sorted(sets),
        "clobbers": sorted(clobbers),
        "stack_offsets": offsets,
    }


def main() -> int:
    if not SAMPLE.exists():
        sys.exit(f"missing {SAMPLE}; run tests/effect_sample.rs first")
    records = [json.loads(line) for line in SAMPLE.read_text().splitlines() if line.strip()]

    kept_per_fixture: dict[str, int] = {}
    stats = {"ok": 0, "skipped": 0}
    reasons: dict[str, int] = {}
    out_lines = []
    for rec in records:
        fx = rec["fixture"]
        if kept_per_fixture.get(fx, 0) >= KEEP_PER_FIXTURE:
            continue
        verdict = classify(rec)
        if verdict["status"] == "skipped":
            stats["skipped"] += 1
            key = verdict["reason"].split(":")[0]
            reasons[key] = reasons.get(key, 0) + 1
            continue
        kept_per_fixture[fx] = kept_per_fixture.get(fx, 0) + 1
        stats["ok"] += 1
        row = {
            "fixture": fx,
            "bits": rec["bits"],
            "vaddr": rec["vaddr"],
            "bytes": rec["bytes"],
            "text": rec["text"],
        }
        row.update({k: v for k, v in verdict.items() if k != "deltas" or v is not None})
        out_lines.append(json.dumps(row, sort_keys=True))

    TRUTH.write_text("\n".join(out_lines) + "\n")
    STATS.write_text(
        json.dumps(
            {
                "trials_per_gadget": TRIALS,
                "candidates_read": len(records),
                "verified": stats["ok"],
                "verified_per_fixture": kept_per_fixture,
                "skipped": stats["skipped"],
                "skipped_by_reason": reasons,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print(f"verified={stats['ok']} skipped={stats['skipped']}", file=sys.stderr)
    for fx, n in sorted(kept_per_fixture.items()):
        print(f"  {fx}: {n}", file=sys.stderr)
    for k, n in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"  skipped[{k}]: {n}", file=sys.stderr)
    print(f"wrote {TRUTH}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
