#!/usr/bin/env python3
"""tests/emulate.py — the ROP chain emulator harness (CHWIN-05).

Every chain rop-finder emits used to be verified by asserting the *kinds* of
its stack words.  A chain of the right shape that jumps to 0x4141414141414141
passes such a test; so does a chain that makes its shellcode buffer RWX and
then overwrites the shellcode's first four bytes before returning into it.
Both of those are real, shipped defects (CHWIN-01, CHWIN-02).  This harness
is the answer: it maps the target's segments, lays the generated chain bytes
on a synthetic stack, stubs the target API at its resolved address, steps the
machine to a bound, and asserts the GOAL WAS REACHED WITH THE EXPECTED
ARGUMENTS.

--------------------------------------------------------------------------
PUBLIC INTERFACE  (this is the contract the chain workstreams call)
--------------------------------------------------------------------------

  from emulate import emulate_chain, generate_chain, verify_binary, Goal

  # 1. one call, end to end: generate with the real CLI, then execute it
  res = verify_binary("tests/fixtures/elf-Linux-x64")            # goal auto
  res = verify_binary(pe, goal=Goal.WIN_VIRTUALPROTECT,
                      chain_args=["--api-addr", "0x7fff12340000"])
  assert res.ok, res.reason

  # 2. or split it: build the chain yourself, hand the IR to the emulator
  spec, info = generate_chain(binary, ["--chain", "windows-virtualprotect"])
  res = emulate_chain(binary, spec, goal=Goal.WIN_VIRTUALPROTECT,
                      api_addr=0x7fff12340000)

  `emulate_chain(binary, chain, goal, **opts)` accepts `chain` as the parsed
  Chain IR dict (`rop-finder --ropchain --json`), the JSON text, an
  `EmulatedChain`, or raw little-endian bytes + `word_size=`.

  It returns an `EmulationResult` with:
      .ok        bool   — the goal was reached with the expected arguments
      .reason    str    — one line saying exactly what happened
      .observed  dict   — every measured fact (syscall number, argv, the four
                          VirtualProtect arguments, the shellcode's first four
                          bytes before and after, ret targets, faults)
      .steps     int    — instructions executed
      .checks    list   — [(name, bool, detail)] every individual assertion

CLI
  python tests/emulate.py --binary FIXTURE [--goal auto|linux-execve|
                          windows-virtualprotect] [--chain-arg ARG]...
  python tests/emulate.py --all           the Linux execve sweep: every ELF
                                          fixture, and every one that produces
                                          a chain must RUN
  python tests/emulate.py --regressions   the seeded Windows cases, each
                                          against its recorded pre/post-fix
                                          state in docs/chain-regressions.md
  python tests/emulate.py --binary F --chain-json FILE

The Windows cases are not in --all because they are pre-fix failures by
design; they belong to a table with recorded expectations, not to a
"everything must pass" sweep.  Both entry points exit 0 today.

Requires `unicorn`.  The module re-execs itself into `.venv-oracle` when the
interpreter running it has no unicorn, so `python tests/emulate.py` works from
any interpreter on a machine set up per tests/rf_paths.py.
"""

import os
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _reexec_with_unicorn():
    """Re-run this script under an interpreter that has unicorn, once.

    tests/rf_paths.py documents `.venv-oracle` beside or inside the repo as
    the harness venv; unicorn lives there next to capstone.  Without this the
    harness is only runnable by naming that interpreter explicitly, which is
    exactly the kind of undocumented local step the audit calls out.

    `subprocess.run` + propagate the exit code, deliberately NOT `os.execv`:
    on Windows execv does not replace the process, it spawns a child and
    exits the parent, which detaches the child's stdout when stdout is a
    pipe — so `python tests/emulate.py ... | tail` silently printed nothing.
    """
    if os.environ.get("RF_EMULATE_REEXEC") == "1":
        sys.exit(
            "unicorn is not installed for this interpreter and the re-exec "
            "already happened.\n"
            "Install it:  <python> -m pip install 'unicorn==2.1.4'\n"
            "or set RF_EMULATE_PYTHON to an interpreter that has it."
        )
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    bindir, pyexe = ("Scripts", "python.exe") if os.name == "nt" else ("bin", "python")
    cands = []
    if os.environ.get("RF_EMULATE_PYTHON"):
        cands.append(os.environ["RF_EMULATE_PYTHON"])
    for venv in (
        os.path.join(repo, ".venv-oracle"),
        os.path.join(os.path.dirname(repo), ".venv-oracle"),
    ):
        cands.append(os.path.join(venv, bindir, pyexe))
    for cand in cands:
        if (
            cand
            and os.path.exists(cand)
            and os.path.abspath(cand) != os.path.abspath(sys.executable)
        ):
            env = dict(os.environ, RF_EMULATE_REEXEC="1")
            p = subprocess.run(
                [cand, os.path.abspath(__file__)] + sys.argv[1:], env=env
            )
            sys.exit(p.returncode)
    sys.exit(
        "unicorn is not installed and no .venv-oracle interpreter was found.\n"
        "  python -m venv .venv-oracle\n"
        "  .venv-oracle/%s/pip install 'unicorn==2.1.4' 'capstone==5.0.7'\n"
        "or set RF_EMULATE_PYTHON." % bindir
    )


try:
    import unicorn  # noqa: F401
except ImportError:
    if __name__ == "__main__":
        _reexec_with_unicorn()
    raise

import argparse  # noqa: E402
import json  # noqa: E402
import struct  # noqa: E402
import tempfile  # noqa: E402
from dataclasses import dataclass, field  # noqa: E402

from unicorn import (  # noqa: E402
    UC_ARCH_X86,
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_HOOK_INTR,
    UC_HOOK_MEM_INVALID,
    UC_HOOK_MEM_READ,
    UC_MODE_32,
    UC_MODE_64,
    UC_PROT_ALL,
    UC_PROT_EXEC,
    UC_PROT_READ,
    UC_PROT_WRITE,
    Uc,
    UcError,
)
from unicorn.x86_const import (  # noqa: E402
    UC_X86_INS_SYSCALL,
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_EIP,
    UC_X86_REG_ESP,
    UC_X86_REG_EBP,
    UC_X86_REG_EDI,
    UC_X86_REG_ESI,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RBP,
    UC_X86_REG_RBX,
    UC_X86_REG_RAX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

import rf_paths  # noqa: E402

#: Syscall argument registers in ABI order, per width.  One table, used by
#: the syscall hook, the judge and the SROP frame reader.
SYSCALL_REGS64 = [
    ("rdi", UC_X86_REG_RDI),
    ("rsi", UC_X86_REG_RSI),
    ("rdx", UC_X86_REG_RDX),
    ("r10", UC_X86_REG_R10),
    ("r8", UC_X86_REG_R8),
    ("r9", UC_X86_REG_R9),
]
SYSCALL_REGS32 = [
    ("ebx", UC_X86_REG_EBX),
    ("ecx", UC_X86_REG_ECX),
    ("edx", UC_X86_REG_EDX),
    ("esi", UC_X86_REG_ESI),
    ("edi", UC_X86_REG_EDI),
    ("ebp", UC_X86_REG_EBP),
]
SROP_RESTORE64 = {
    "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX, "rcx": UC_X86_REG_RCX,
    "rdx": UC_X86_REG_RDX, "rsi": UC_X86_REG_RSI, "rdi": UC_X86_REG_RDI,
    "rbp": UC_X86_REG_RBP, "rsp": UC_X86_REG_RSP,
    "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9, "r10": UC_X86_REG_R10,
    "r11": UC_X86_REG_R11, "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13,
    "r14": UC_X86_REG_R14, "r15": UC_X86_REG_R15,
}

PAGE = 0x1000
PADDING64 = 0x4141414141414141
PADDING32 = 0x41414141

#: What the emulated VirtualProtect writes through lpflOldProtect.
#: PAGE_READWRITE — the previous protection of a writable data page.
OLD_PROTECT_VALUE = 0x04

#: VirtualAlloc's flAllocationType for re-committing an already-committed
#: page with a new protection — the DEP-bypass form that needs no
#: out-parameter (CHWIN-06).  Must match rf_chain::windows::MEM_COMMIT.
MEM_COMMIT = 0x1000

#: The four bytes planted at the shellcode address before the run.  The
#: CHWIN-02 assertion is that control arrives there with these INTACT.
SHELLCODE_MARKER = b"\x90\x90\x90\x90"
#: ...followed by `hlt`, so arriving there halts instead of running off.
SHELLCODE_TRAP = b"\xf4"

__NR_execve_x64 = 59
__NR_execve_x86 = 11


class Goal:
    LINUX_EXECVE = "linux-execve"
    #: CHLX-07: any syscall, judged against an EXPECTED number and argument
    #: register set the caller states.  `linux-mprotect` is this goal with
    #: __NR_mprotect and the three arguments the builder computed.
    LINUX_SYSCALL = "linux-syscall"
    #: CHLX-07: control reaches `func_addr` with the ABI's first argument
    #: pointing at the "/bin//sh" the chain wrote.
    LINUX_RET2LIBC = "linux-ret2libc"
    #: CHLX-07: `rt_sigreturn` restores a frame the harness then APPLIES,
    #: after which the restored context must itself reach execve.
    LINUX_SROP = "linux-srop"
    WIN_VIRTUALPROTECT = "windows-virtualprotect"
    AUTO = "auto"

    #: Every Linux goal, i.e. everything judged by the syscall hooks.
    LINUX = (LINUX_EXECVE, LINUX_SYSCALL, LINUX_RET2LIBC, LINUX_SROP)


__NR_mprotect_x64 = 10
__NR_mprotect_x86 = 125
__NR_rt_sigreturn_x64 = 15

#: amd64 rt_sigreturn frame: word offsets from rsp at the `syscall`.
#: Kernel `struct rt_sigframe`; pwntools' SigreturnFrame("amd64") word for
#: word.  The Rust side (linux.rs SROP64_*) MUST agree with this table --
#: it is the whole content of the SROP target, and a one-word disagreement
#: is a chain that restores garbage.
SROP64_SLOTS = {
    "r8": 5, "r9": 6, "r10": 7, "r11": 8, "r12": 9, "r13": 10, "r14": 11, "r15": 12,
    "rdi": 13, "rsi": 14, "rbp": 15, "rbx": 16, "rdx": 17, "rax": 18, "rcx": 19,
    "rsp": 20, "rip": 21, "eflags": 22, "csgsfs": 23,
}


# ---------------------------------------------------------------------------
# Image loading: just enough ELF/PE to map what the chain touches.
# ---------------------------------------------------------------------------


@dataclass
class Segment:
    vaddr: int
    memsz: int
    data: bytes
    prot: int
    name: str = ""


@dataclass
class LoadedImage:
    fmt: str  # "elf" | "pe"
    bits: int  # 32 | 64
    image_base: int
    segments: list


def _u8(b, o):
    return b[o]


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def load_elf(blob):
    """PT_LOAD segments with their real p_flags permissions.

    Real permissions, not blanket RWX: a chain that writes its "/bin//sh"
    string into a read-only or TLS-template section (CHLX-05) must fault here
    rather than silently succeed.
    """
    if blob[:4] != b"\x7fELF":
        raise ValueError("not an ELF")
    if blob[5] != 1:
        raise ValueError("big-endian ELF is out of scope for the harness")
    is64 = blob[4] == 2
    if is64:
        phoff, phentsize, phnum = _u64(blob, 32), _u16(blob, 54), _u16(blob, 56)
    else:
        phoff, phentsize, phnum = _u32(blob, 28), _u16(blob, 42), _u16(blob, 44)
    segs = []
    lowest = None
    for i in range(phnum):
        o = phoff + i * phentsize
        if o + phentsize > len(blob):
            break
        if _u32(blob, o) != 1:  # PT_LOAD
            continue
        if is64:
            flags = _u32(blob, o + 4)
            off, vaddr = _u64(blob, o + 8), _u64(blob, o + 16)
            filesz, memsz = _u64(blob, o + 32), _u64(blob, o + 40)
        else:
            off, vaddr = _u32(blob, o + 4), _u32(blob, o + 8)
            filesz, memsz = _u32(blob, o + 16), _u32(blob, o + 20)
            flags = _u32(blob, o + 24)
        prot = 0
        prot |= UC_PROT_EXEC if flags & 1 else 0
        prot |= UC_PROT_WRITE if flags & 2 else 0
        prot |= UC_PROT_READ if flags & 4 else 0
        segs.append(
            Segment(vaddr, max(memsz, filesz), blob[off : off + filesz], prot, f"PT_LOAD[{i}]")
        )
        lowest = vaddr if lowest is None else min(lowest, vaddr)
    if not segs:
        raise ValueError("ELF has no PT_LOAD segments")
    return LoadedImage("elf", 64 if is64 else 32, lowest or 0, segs)


def load_pe(blob):
    """PE sections at ImageBase + VirtualAddress, plus the header page."""
    if blob[:2] != b"MZ":
        raise ValueError("not a PE")
    nt = _u32(blob, 0x3C)
    if blob[nt : nt + 4] != b"PE\x00\x00":
        raise ValueError("bad PE signature")
    coff = nt + 4
    nsections = _u16(blob, coff + 2)
    opt_size = _u16(blob, coff + 16)
    opt = coff + 20
    magic = _u16(blob, opt)
    is64 = magic == 0x20B
    image_base = _u64(blob, opt + 24) if is64 else _u32(blob, opt + 28)
    size_of_headers = _u32(blob, opt + 60)
    sect = opt + opt_size
    segs = [
        Segment(image_base, max(size_of_headers, PAGE), blob[:size_of_headers], UC_PROT_READ, "headers")
    ]
    for i in range(nsections):
        o = sect + i * 40
        name = blob[o : o + 8].rstrip(b"\x00").decode("latin-1")
        vsize, vaddr = _u32(blob, o + 8), _u32(blob, o + 12)
        rawsize, rawptr = _u32(blob, o + 16), _u32(blob, o + 20)
        chars = _u32(blob, o + 36)
        prot = UC_PROT_READ
        prot |= UC_PROT_EXEC if chars & 0x20000000 else 0
        prot |= UC_PROT_WRITE if chars & 0x80000000 else 0
        segs.append(
            Segment(
                image_base + vaddr,
                max(vsize, rawsize, PAGE),
                blob[rawptr : rawptr + rawsize],
                prot,
                name,
            )
        )
    return LoadedImage("pe", 64 if is64 else 32, image_base, segs)


def load_image(path):
    with open(path, "rb") as fh:
        blob = fh.read()
    if blob[:4] == b"\x7fELF":
        return load_elf(blob)
    if blob[:2] == b"MZ":
        return load_pe(blob)
    raise ValueError(f"{path}: neither ELF nor PE — the harness maps those two")


# ---------------------------------------------------------------------------
# The machine
# ---------------------------------------------------------------------------


class Machine:
    """A unicorn x86/x64 machine with a page-permission model of its own.

    Unicorn's `mem_write` ignores protection, so the harness keeps its own
    page table: that is what lets it answer "would this write have faulted on
    a real loader?" — the question CHLX-05 and the lpflOldProtect write in
    CHWIN-02 both turn on.
    """

    def __init__(self, bits):
        self.bits = bits
        self.word = 8 if bits == 64 else 4
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64 if bits == 64 else UC_MODE_32)
        self.pages = {}  # page base -> prot
        self._pending = []  # (vaddr, data)
        self._alloc_next = 0x00007FF000000000 if bits == 64 else 0x30000000

    # -- mapping ---------------------------------------------------------
    def reserve(self, vaddr, size, prot, data=b""):
        first = vaddr & ~(PAGE - 1)
        last = (vaddr + max(size, 1) + PAGE - 1) & ~(PAGE - 1)
        for p in range(first, last, PAGE):
            self.pages[p] = self.pages.get(p, 0) | prot
        if data:
            self._pending.append((vaddr, bytes(data)))

    def commit(self):
        """Map maximal runs of equal-permission pages, then write contents."""
        for base, size, prot in self._runs():
            self.uc.mem_map(base, size, prot)
        for vaddr, data in self._pending:
            self.uc.mem_write(vaddr, data)
        self._pending = []

    def _runs(self):
        out = []
        for p in sorted(self.pages):
            prot = self.pages[p]
            if out and out[-1][0] + out[-1][1] == p and out[-1][2] == prot:
                out[-1] = (out[-1][0], out[-1][1] + PAGE, prot)
            else:
                out.append((p, PAGE, prot))
        return out

    def alloc(self, size, prot, name=""):
        """Reserve a fresh region that cannot collide with the image."""
        size = (size + PAGE - 1) & ~(PAGE - 1)
        while True:
            base = self._alloc_next
            self._alloc_next += size + PAGE
            if all((base + off) not in self.pages for off in range(0, size, PAGE)):
                self.reserve(base, size, prot)
                return base

    def prot_of(self, addr):
        return self.pages.get(addr & ~(PAGE - 1), 0)

    def writable(self, addr):
        return bool(self.prot_of(addr) & UC_PROT_WRITE)

    def set_prot(self, addr, size, prot):
        first = addr & ~(PAGE - 1)
        last = (addr + max(size, 1) + PAGE - 1) & ~(PAGE - 1)
        for p in range(first, last, PAGE):
            if p in self.pages:
                self.pages[p] = prot
        self.uc.mem_protect(first, last - first, prot)

    # -- registers -------------------------------------------------------
    @property
    def sp_reg(self):
        return UC_X86_REG_RSP if self.bits == 64 else UC_X86_REG_ESP

    @property
    def pc_reg(self):
        return UC_X86_REG_RIP if self.bits == 64 else UC_X86_REG_EIP

    def read_word(self, addr):
        raw = self.uc.mem_read(addr, self.word)
        return int.from_bytes(raw, "little")

    def cstring(self, addr, limit=256):
        out = bytearray()
        for i in range(limit):
            b = self.uc.mem_read(addr + i, 1)[0]
            if b == 0:
                break
            out.append(b)
        return bytes(out)


# ---------------------------------------------------------------------------
# Chain plumbing
# ---------------------------------------------------------------------------


@dataclass
class EmulatedChain:
    """The chain to execute, in the form the emulator needs."""

    word_size: int
    words: list  # list of ints
    ir: dict = field(default_factory=dict)

    @property
    def raw(self):
        return b"".join(w.to_bytes(self.word_size, "little") for w in self.words)

    @classmethod
    def from_ir(cls, ir):
        if isinstance(ir, (bytes, bytearray)):
            raise TypeError("use EmulatedChain.from_bytes for raw chain bytes")
        if isinstance(ir, str):
            ir = json.loads(ir)
        ws = int(ir["word_size"])
        return cls(ws, [int(w["value"], 16) for w in ir["words"]], ir)

    @classmethod
    def from_bytes(cls, raw, word_size):
        words = [
            int.from_bytes(raw[i : i + word_size], "little")
            for i in range(0, len(raw), word_size)
        ]
        return cls(word_size, words, {})


def _as_chain(chain, word_size=None):
    if isinstance(chain, EmulatedChain):
        return chain
    if isinstance(chain, (bytes, bytearray)):
        if not word_size:
            raise ValueError("raw chain bytes need word_size=")
        return EmulatedChain.from_bytes(bytes(chain), word_size)
    return EmulatedChain.from_ir(chain)


class ChainBuildFailed(Exception):
    """rop-finder refused to emit a chain (a structured refusal, not a crash)."""

    def __init__(self, message, stderr=""):
        super().__init__(message)
        self.stderr = stderr


def generate_chain(binary, extra_args=(), rop_finder=None):
    """Run the real CLI and return (EmulatedChain, binary_info).

    Raises ChainBuildFailed when the builder refuses — a refusal is a result,
    not a harness error (CHLX-04: "chains that are emitted must be runnable
    or not emitted").
    """
    exe = rop_finder or rf_paths.rop_finder(release=True)
    cmd = [exe, "--binary", binary, "--ropchain", "--json", *extra_args]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0 or not p.stdout.strip().startswith("{"):
        raise ChainBuildFailed(
            (p.stdout.strip() + "\n" + p.stderr.strip()).strip() or f"exit {p.returncode}",
            p.stderr,
        )
    chain = EmulatedChain.from_ir(json.loads(p.stdout))
    info = subprocess.run(
        [exe, "--binary", binary, "--info"], capture_output=True, text=True
    )
    return chain, (json.loads(info.stdout) if info.returncode == 0 else {})


@dataclass
class EmulationResult:
    ok: bool
    goal: str
    reason: str
    observed: dict = field(default_factory=dict)
    checks: list = field(default_factory=list)
    steps: int = 0
    trace: list = field(default_factory=list)

    def check(self, name, passed, detail=""):
        self.checks.append((name, bool(passed), detail))
        return bool(passed)

    def finish(self):
        failed = [c for c in self.checks if not c[1]]
        self.ok = not failed
        if failed:
            self.reason = "; ".join(f"{n}: {d}" for n, _, d in failed)
        return self

    def report(self, indent="    "):
        lines = [f"{indent}goal={self.goal} steps={self.steps} ok={self.ok}"]
        for name, passed, detail in self.checks:
            mark = "PASS" if passed else "FAIL"
            lines.append(f"{indent}  [{mark}] {name}" + (f" - {detail}" if detail else ""))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# The emulator proper
# ---------------------------------------------------------------------------


def emulate_chain(
    binary,
    chain,
    goal=Goal.AUTO,
    *,
    word_size=None,
    shellcode_addr=None,
    shellcode_size=0x1000,
    new_protect=0x40,
    api_addr=None,
    api_name="VirtualProtect",
    iat_slot=None,
    max_steps=200000,
    keep_trace=False,
    info=None,
    expect_syscall=None,
    expect_regs=None,
    func_addr=None,
    extra_apis=(),
    expect_stage=None,
    expect_calls=None,
):
    """Execute `chain` against `binary` and assert the goal was reached.

    `shellcode_addr` / `api_addr` / `iat_slot` default to what the builder
    itself defaults to (first writable section; IAT slot of `api_name` from
    `--info`), so a caller that passed no override to the CLI passes none
    here either.
    """
    chain = _as_chain(chain, word_size)
    img = load_image(binary)
    if goal == Goal.AUTO:
        goal = Goal.LINUX_EXECVE if img.fmt == "elf" else Goal.WIN_VIRTUALPROTECT

    m = Machine(img.bits)
    for seg in img.segments:
        m.reserve(seg.vaddr, seg.memsz, seg.prot, seg.data)
    if goal == Goal.LINUX_RET2LIBC and func_addr is not None:
        # The called function is not in the image (it is libc's `system`),
        # so the harness maps a one-byte stub at the address the chain was
        # told to use.  Reaching it IS the goal.
        m.reserve(func_addr & ~(PAGE - 1), PAGE, UC_PROT_READ | UC_PROT_EXEC, b"")

    # Synthetic stack.  The chain sits in the middle so a gadget that adjusts
    # rsp in either direction still lands on mapped memory.
    stack = m.alloc(0x100000, UC_PROT_READ | UC_PROT_WRITE, "stack")
    chain_base = stack + 0x40000
    # CHWIN-08 #1: a pivoted chain is TWO pieces, and the split is stated in
    # the IR's own `assumptions` rather than guessed here.  The prologue goes
    # at the overflow point; the body goes at the address the builder was
    # told to pivot to, which is where the builder computed its alignment
    # parity from.  Laying it out any other way would test a chain nobody
    # asked for.
    assumptions = (chain.ir or {}).get("assumptions") or {}
    pivot_addr = assumptions.get("pivot_addr")
    pivot_words = int(assumptions.get("pivot_words") or 0)
    if pivot_addr and pivot_words:
        pivot_addr = int(pivot_addr, 16) if isinstance(pivot_addr, str) else int(pivot_addr)
        head = chain.raw[: pivot_words * chain.word_size]
        body = chain.raw[pivot_words * chain.word_size :]
        m.reserve(chain_base, max(len(head), PAGE), UC_PROT_READ | UC_PROT_WRITE, head)
        m.reserve(
            pivot_addr - 0x1000,
            max(len(body), PAGE) + 0x2000,
            UC_PROT_READ | UC_PROT_WRITE,
        )
        m.reserve(pivot_addr, max(len(body), PAGE), UC_PROT_READ | UC_PROT_WRITE, body)
        obs_pivot = (pivot_addr, pivot_words)
    else:
        m.reserve(chain_base, max(len(chain.raw), PAGE), UC_PROT_READ | UC_PROT_WRITE, chain.raw)
        obs_pivot = None
    # A bare `ret`: the pivot.  Starting here makes the first chain word the
    # first RIP, exactly as a stack-smash into a `ret` does.
    tramp = m.alloc(PAGE, UC_PROT_READ | UC_PROT_EXEC, "trampoline")
    m.reserve(tramp, PAGE, UC_PROT_READ | UC_PROT_EXEC, b"\xc3")

    result = EmulationResult(ok=False, goal=goal, reason="")
    obs = result.observed
    if func_addr is not None:
        obs["func_addr"] = func_addr

    if obs_pivot:
        obs["pivot_addr"], obs["pivot_words"] = obs_pivot

    if goal == Goal.WIN_VIRTUALPROTECT:
        _prepare_windows(m, img, obs, binary, info, api_name, api_addr, iat_slot, shellcode_addr)
        # CHWIN-08 #2: one stub per composed call, each with its OWN recipe
        # — VirtualAlloc's third argument is not VirtualProtect's third
        # argument, so a single stub would judge the second call wrongly.
        stubs = {obs["api_entry"]: api_name}
        for addr, name in extra_apis:
            page = addr & ~(PAGE - 1)
            if page not in m.pages:
                m.reserve(page, PAGE, UC_PROT_READ | UC_PROT_EXEC)
            m.reserve(addr, PAGE, UC_PROT_READ | UC_PROT_EXEC, b"\xc3" if m.bits == 64 else b"\xc2\x10\x00")
            stubs[addr] = name
        obs["api_stubs"] = stubs

    m.commit()

    if goal == Goal.WIN_VIRTUALPROTECT:
        if expect_stage is None:
            m.uc.mem_write(obs["shellcode_addr"], SHELLCODE_MARKER + SHELLCODE_TRAP)
            obs["shellcode_first4_before"] = bytes(
                m.uc.mem_read(obs["shellcode_addr"], 4)
            ).hex()
        else:
            # CHWIN-08 #5: with --stage the CHAIN is supposed to put the
            # shellcode there.  Pre-fill with 0xCC so "the staged bytes are
            # present" is an assertion about the chain's own writes, not
            # about what the harness planted.
            m.uc.mem_write(obs["shellcode_addr"], b"\xcc" * (len(expect_stage) + 8))
            obs["expect_stage"] = expect_stage.hex()
            obs["shellcode_first4_before"] = expect_stage[:4].hex()
        if obs.get("iat_slot") is not None:
            # What the Windows loader does: patch the IAT slot with the
            # resolved address.  Without this the deref reads file bytes.
            m.uc.mem_write(
                obs["iat_slot"], obs["api_entry"].to_bytes(m.word, "little")
            )

    _install_hooks(m, result, goal, obs, keep_trace, shellcode_size, new_protect)

    m.uc.reg_write(m.sp_reg, chain_base)
    obs["chain_base"] = chain_base
    obs["chain_words"] = len(chain.words)
    try:
        m.uc.emu_start(tramp, tramp + 1, count=max_steps)
        # CHLX-07 (SROP): the sigreturn handler stopped the run so the
        # restored context can be started cleanly at its own rip.
        if obs.get("srop_resume_rip") is not None:
            m.uc.emu_start(obs.pop("srop_resume_rip"), 0, count=max_steps)
    except UcError as exc:
        obs["uc_error"] = str(exc)
        obs["pc_at_error"] = m.uc.reg_read(m.pc_reg)

    result.steps = obs.get("steps", 0)
    if goal == Goal.LINUX_EXECVE:
        _judge_linux(m, result, obs)
    elif goal == Goal.LINUX_SYSCALL:
        _judge_syscall(m, result, obs, expect_syscall, expect_regs or {})
    elif goal == Goal.LINUX_RET2LIBC:
        _judge_ret2libc(m, result, obs)
    elif goal == Goal.LINUX_SROP:
        _judge_srop(m, result, obs, expect_syscall, expect_regs or {})
    else:
        _judge_windows(m, result, obs, shellcode_size, new_protect, expect_calls)
    return result.finish()


def _prepare_windows(m, img, obs, binary, info, api_name, api_addr, iat_slot, shellcode_addr):
    """Resolve shellcode / API / IAT the way the builder and loader would."""
    # CHWIN-06: which API is being stubbed decides what its four arguments
    # MEAN.  VirtualProtect and VirtualAlloc both take four; only one of
    # them has an out-parameter.
    obs["api_name"] = api_name
    if info is None:
        exe = rf_paths.rop_finder(release=True)
        p = subprocess.run([exe, "--binary", binary, "--info"], capture_output=True, text=True)
        info = json.loads(p.stdout) if p.returncode == 0 else {}
    if shellcode_addr is None:
        # windows.rs: `.data` if writable, else the first writable section.
        secs = info.get("sections", [])
        pick = next((s for s in secs if s["name"] == ".data" and s["writable"]), None)
        pick = pick or next((s for s in secs if s["writable"]), None)
        if pick is None:
            raise ValueError("no writable section — cannot infer the shellcode address")
        shellcode_addr = int(pick["vaddr"], 16)
    obs["shellcode_addr"] = shellcode_addr

    if api_addr is None and iat_slot is None:
        imp = next(
            (i for i in info.get("imports", []) if i.get("symbol", "").lower() == api_name.lower()),
            None,
        )
        if imp is not None:
            iat_slot = int(imp["iat_vaddr"], 16)
    imp = next(
        (i for i in info.get("imports", []) if i.get("symbol", "").lower() == api_name.lower()),
        None,
    )
    if imp is not None and imp.get("hint_name_vaddr"):
        # CHWIN-03's decoy.  The hint/name record holds `00 00 "VirtualProtect\0"`
        # straight from the file; a chain that dereferences it loads ASCII.
        # The harness patches ONLY the IAT slot, so reading the wrong cell is
        # observable rather than merely wrong-looking.
        obs["hint_name_vaddr"] = int(imp["hint_name_vaddr"], 16)
    if api_addr is not None:
        obs["api_entry"] = api_addr
        obs["iat_slot"] = iat_slot
        api_page = api_addr & ~(PAGE - 1)
        if api_page not in m.pages:
            m.reserve(api_page, PAGE, UC_PROT_READ | UC_PROT_EXEC)
    else:
        # The chain resolves the API through the IAT; the harness stands the
        # API up at an address of its own and patches the slot after mapping.
        entry = m.alloc(PAGE, UC_PROT_READ | UC_PROT_EXEC, "api")
        obs["api_entry"] = entry
        obs["iat_slot"] = iat_slot
    # The stub body: x64 `ret`, x86 stdcall `ret 0x10` (four DWORD args).
    body = b"\xc3" if m.bits == 64 else b"\xc2\x10\x00"
    m.reserve(obs["api_entry"], PAGE, UC_PROT_READ | UC_PROT_EXEC, body)


def _install_hooks(m, result, goal, obs, keep_trace, shellcode_size, new_protect):
    uc = m.uc
    obs.setdefault("steps", 0)
    obs.setdefault("ret_targets", [])
    obs.setdefault("faults", [])
    stub = obs.get("api_entry")
    shellcode = obs.get("shellcode_addr")

    def on_code(uc_, address, size, _):
        obs["steps"] += 1
        if keep_trace:
            result.trace.append(address)
        # Record where each `ret` intends to go.  This is what makes
        # "the chain transferred control to 0x4141414141414141" observable
        # even though the fetch of that address is what actually faults.
        try:
            op = uc_.mem_read(address, 1)[0]
        except UcError:
            op = 0
        if op == 0xC3:
            try:
                obs["ret_targets"].append(m.read_word(uc_.reg_read(m.sp_reg)))
            except UcError:
                pass
        if goal == Goal.WIN_VIRTUALPROTECT:
            stubs = obs.get("api_stubs") or ({stub: obs.get("api_name")} if stub else {})
            if address in stubs:
                _virtualprotect_stub(m, obs, stubs[address])
            if shellcode is not None and address == shellcode and "shellcode_first4" not in obs:
                obs["reached_shellcode"] = True
                obs["shellcode_first4"] = bytes(uc_.mem_read(shellcode, 4)).hex()
                uc_.emu_stop()

    uc.hook_add(UC_HOOK_CODE, on_code)

    def on_invalid(uc_, access, address, size, value, _):
        obs["faults"].append(
            {"access": int(access), "address": address, "size": size, "value": value}
        )
        return False  # do not resolve; let the run stop

    uc.hook_add(UC_HOOK_MEM_INVALID, on_invalid)

    # CHWIN-03: which cell did the chain dereference?  The IAT slot the
    # loader patches, or the IMAGE_IMPORT_BY_NAME record that holds the
    # function's NAME?  A read hook over each answers it directly.
    for key, flag in (("iat_slot", "read_iat_slot"), ("hint_name_vaddr", "read_hint_name")):
        addr = obs.get(key)
        if addr:
            uc.hook_add(
                UC_HOOK_MEM_READ,
                (lambda f: lambda uc_, a, addr_, sz, val, _u: obs.__setitem__(f, True))(flag),
                begin=addr,
                end=addr + m.word - 1,
            )

    if goal in Goal.LINUX:
        table = SYSCALL_REGS64 if m.bits == 64 else SYSCALL_REGS32
        nr_reg = UC_X86_REG_RAX if m.bits == 64 else UC_X86_REG_EAX

        def record_syscall(uc_):
            """Record one syscall, and say whether the run should continue.

            SROP is the only goal that continues: the first syscall is
            `rt_sigreturn`, whose whole effect is to load a register set
            from the stack.  The harness performs that load — reading the
            SAME frame layout the builder emitted — and lets the restored
            context run on, so the assertion is not "the chain asked for
            sigreturn" (which proves nothing) but "the frame it laid down
            actually executes the intended syscall".
            """
            nr = uc_.reg_read(nr_reg)
            regs = {name: uc_.reg_read(rid) for name, rid in table}
            obs.setdefault("syscalls", []).append({"nr": nr, **regs})
            if (
                goal == Goal.LINUX_SROP
                and m.bits == 64
                and nr == __NR_rt_sigreturn_x64
                and not obs.get("sigreturn_applied")
            ):
                obs["sigreturn_applied"] = True
                _apply_sigreturn(m, uc_, obs)
                # Stop and RESTART at the restored rip rather than writing
                # RIP here: unicorn has already advanced past the `syscall`
                # by the time this hook runs, and a write from inside the
                # instruction hook does not redirect it (measured: the run
                # carried straight on into the image and reached an
                # unrelated syscall 2).
                uc_.emu_stop()
                return True
            obs["syscall"] = nr
            for i, (name, _rid) in enumerate(table[:3], start=1):
                obs[f"arg{i}"] = regs[name]
            obs["syscall_regs"] = regs
            uc_.emu_stop()
            return False

        if m.bits == 64:

            def on_syscall(uc_, _):
                record_syscall(uc_)

            # unicorn 2.x: the instruction id goes in `aux1`.
            uc.hook_add(UC_HOOK_INSN, on_syscall, aux1=UC_X86_INS_SYSCALL)
        else:

            def on_intr(uc_, intno, _):
                if intno != 0x80:
                    return
                record_syscall(uc_)

            uc.hook_add(UC_HOOK_INTR, on_intr)

    if goal == Goal.LINUX_RET2LIBC and obs.get("func_addr") is not None:
        target = obs["func_addr"]

        def on_call(uc_, address, size, _):
            if address != target or "reached_func" in obs:
                return
            obs["reached_func"] = True
            if m.bits == 64:
                obs["func_arg1"] = uc_.reg_read(UC_X86_REG_RDI)
            else:
                # cdecl: arg1 sits one word above the return address, which
                # `jmp`-free entry leaves at [esp].
                obs["func_arg1"] = m.read_word(uc_.reg_read(m.sp_reg) + m.word)
            uc_.emu_stop()

        uc.hook_add(UC_HOOK_CODE, on_call)


def _apply_sigreturn(m, uc_, obs):
    """Do what the kernel's rt_sigreturn does: load the frame at rsp."""
    frame_base = uc_.reg_read(UC_X86_REG_RSP)
    obs["srop_frame_at"] = frame_base
    frame = {}
    for name, slot in SROP64_SLOTS.items():
        try:
            frame[name] = m.read_word(frame_base + slot * 8)
        except UcError as exc:
            obs["srop_frame_error"] = str(exc)
            uc_.emu_stop()
            return
    obs["srop_frame"] = frame
    for name, rid in SROP_RESTORE64.items():
        uc_.reg_write(rid, frame[name])
    obs["srop_resume_rip"] = frame["rip"]


def _virtualprotect_stub(m, obs, api_name=None):
    """Behave like the API being called: VirtualProtect or VirtualAlloc.

    For VirtualProtect: change protection, then write the old one through
    `lpflOldProtect`.  That second half is the whole point.  A stub that
    only records its arguments cannot falsify CHWIN-02, because CHWIN-02 is
    not a wrong argument — it is a correct argument aimed at the wrong
    address, and the damage is done by the API's own out-parameter write.

    For VirtualAlloc (CHWIN-06): the arguments are
    `(lpAddress, dwSize, flAllocationType, flProtect)` — the protection is
    the FOURTH, there is no out-parameter to write through, and the return
    value is the base address.  Same argument count, different meaning; a
    stub that pretended otherwise would report a correct VirtualAlloc chain
    as broken and a broken one as correct.
    """
    uc = m.uc
    if api_name is None:
        api_name = obs.get("api_name")
    if m.bits == 64:
        args = [
            uc.reg_read(UC_X86_REG_RCX),
            uc.reg_read(UC_X86_REG_RDX),
            uc.reg_read(UC_X86_REG_R8),
            uc.reg_read(UC_X86_REG_R9),
        ]
    else:
        sp = uc.reg_read(UC_X86_REG_ESP)
        args = [m.read_word(sp + 4 * (i + 1)) for i in range(4)]
    obs["vp_args"] = args
    obs["vp_called"] = True
    obs.setdefault("vp_calls", []).append({"api": api_name, "args": list(args)})
    lp_address, dw_size, third, fourth = args
    alloc = str(api_name or "").lower() == "virtualalloc"
    fl_protect = fourth if alloc else third
    lp_old = None if alloc else fourth

    # 1. make the region match the protection argument (PAGE_EXECUTE_* -> RWX)
    if m.prot_of(lp_address):
        prot = (
            UC_PROT_ALL
            if fl_protect in (0x40, 0x80, 0x20, 0x10)
            else UC_PROT_READ | UC_PROT_WRITE
        )
        try:
            m.set_prot(lp_address, max(dw_size, 1), prot)
            obs["vp_protect_applied"] = True
        except UcError as exc:
            obs["vp_protect_error"] = str(exc)
    else:
        obs["vp_lpaddress_unmapped"] = True

    # 2. *lpflOldProtect = previous protection.  VirtualAlloc has no
    #    out-parameter, so there is nothing to write and nothing to alias.
    if lp_old is None:
        obs["vp_old_protect_writable"] = None
        uc.reg_write(UC_X86_REG_RAX if m.bits == 64 else UC_X86_REG_EAX, lp_address)
        return
    obs["vp_old_protect_writable"] = m.writable(lp_old)
    if m.writable(lp_old):
        uc.mem_write(lp_old, struct.pack("<I", OLD_PROTECT_VALUE))
        obs["vp_old_protect_written_at"] = lp_old
    else:
        obs["vp_old_protect_write_faulted"] = True
    uc.reg_write(UC_X86_REG_RAX if m.bits == 64 else UC_X86_REG_EAX, 1)


def _judge_linux(m, result, obs):
    want = __NR_execve_x64 if m.bits == 64 else __NR_execve_x86
    reached = "syscall" in obs
    result.check(
        "reached the execve syscall",
        reached,
        "" if reached else _no_goal_detail(obs),
    )
    if not reached:
        return
    result.check(
        "syscall number is execve",
        obs["syscall"] == want,
        f"got {obs['syscall']}, want {want}",
    )
    path = b""
    try:
        path = m.cstring(obs["arg1"])
    except UcError as exc:
        obs["path_read_error"] = str(exc)
    obs["path"] = path.decode("latin-1")
    result.check(
        "arg1 points at \"/bin//sh\"",
        path == b"/bin//sh",
        f"[{obs['arg1']:#x}] = {path!r}",
    )
    for name, key in (("argv", "arg2"), ("envp", "arg3")):
        ptr = obs[key]
        if ptr == 0:
            obs[f"{name}_first"] = None
            result.check(f"{name} is NULL or a readable NULL-terminated vector", True, "NULL")
            continue
        try:
            first = m.read_word(ptr)
            obs[f"{name}_first"] = first
            result.check(
                f"{name} is NULL or a readable NULL-terminated vector",
                True,
                f"{ptr:#x} -> {first:#x}",
            )
        except UcError as exc:
            result.check(
                f"{name} is NULL or a readable NULL-terminated vector",
                False,
                f"{ptr:#x} unreadable ({exc})",
            )


def _judge_syscall(m, result, obs, want_nr, want_regs):
    """CHLX-07: the chain entered the kernel with the stated call."""
    reached = "syscall" in obs
    result.check(
        "reached a syscall",
        reached,
        "" if reached else _no_goal_detail(obs),
    )
    if not reached:
        return
    if want_nr is not None:
        result.check(
            "syscall number is the requested one",
            obs["syscall"] == want_nr,
            f"got {obs['syscall']}, want {want_nr}",
        )
    for reg, want in sorted(want_regs.items()):
        got = obs.get("syscall_regs", {}).get(reg)
        result.check(
            f"argument register {reg} holds the requested value",
            got == want,
            f"got {got if got is None else hex(got)}, want {want:#x}",
        )


def _judge_ret2libc(m, result, obs):
    """CHLX-07: control reached the function with arg1 -> "/bin//sh"."""
    reached = obs.get("reached_func", False)
    result.check(
        "reached the called function",
        reached,
        "" if reached else _no_goal_detail(obs),
    )
    if not reached:
        return
    ptr = obs.get("func_arg1", 0)
    path = b""
    try:
        path = m.cstring(ptr)
    except UcError as exc:
        obs["path_read_error"] = str(exc)
    obs["path"] = path.decode("latin-1")
    result.check(
        'arg1 points at "/bin//sh"',
        path == b"/bin//sh",
        f"[{ptr:#x}] = {path!r}",
    )


def _judge_srop(m, result, obs, want_nr, want_regs):
    """CHLX-07: the sigreturn frame the chain laid down actually runs.

    Two assertions, and the second is the one that matters: it is easy to
    emit `pop rax ; 15 ; syscall` and call it SROP.  The frame is applied by
    the harness exactly as the kernel would, and the RESTORED context then
    has to reach the intended syscall by itself.
    """
    applied = obs.get("sigreturn_applied", False)
    result.check(
        "rt_sigreturn was invoked with a readable frame",
        applied and "srop_frame" in obs,
        obs.get("srop_frame_error", "") or ("" if applied else _no_goal_detail(obs)),
    )
    if not applied or "srop_frame" not in obs:
        return
    reached = "syscall" in obs
    result.check(
        "the restored context reached its syscall",
        reached,
        "" if reached else _no_goal_detail(obs),
    )
    if not reached:
        return
    if want_nr is not None:
        result.check(
            "the restored syscall number is the requested one",
            obs["syscall"] == want_nr,
            f"got {obs['syscall']}, want {want_nr}",
        )
    if want_nr == __NR_execve_x64:
        path = b""
        try:
            path = m.cstring(obs.get("arg1", 0))
        except UcError as exc:
            obs["path_read_error"] = str(exc)
        obs["path"] = path.decode("latin-1")
        result.check(
            'the restored rdi points at "/bin//sh"',
            path == b"/bin//sh",
            f"[{obs.get('arg1', 0):#x}] = {path!r}",
        )
    for reg, want in sorted(want_regs.items()):
        got = obs.get("syscall_regs", {}).get(reg)
        result.check(
            f"the restored {reg} holds the requested value",
            got == want,
            f"got {got if got is None else hex(got)}, want {want:#x}",
        )


def _judge_windows(m, result, obs, shellcode_size, new_protect, expect_calls=None):
    pad = PADDING64 if m.bits == 64 else PADDING32
    hit_padding = pad in obs.get("ret_targets", []) or any(
        f["address"] == pad for f in obs.get("faults", [])
    )
    # CHWIN-01: the alignment pad is an inert data word the previous `ret`
    # jumps to.  This is the check no word-kind assertion can express.
    result.check(
        "no control transfer to the padding constant",
        not hit_padding,
        f"a `ret` targeted {pad:#x}" if hit_padding else "",
    )
    if obs.get("iat_slot"):
        # CHWIN-03: the deref must load a POINTER out of the FirstThunk slot.
        # Reading the hint/name record instead loads eight bytes of ASCII and
        # `jmp rax` lands on a non-canonical address.
        read_iat = obs.get("read_iat_slot", False)
        read_name = obs.get("read_hint_name", False)
        if read_iat and not read_name:
            detail = f"read the FirstThunk slot at {obs['iat_slot']:#x}"
        elif read_name:
            detail = (
                "read the IMAGE_IMPORT_BY_NAME record at "
                f"{obs.get('hint_name_vaddr', 0):#x} (that cell holds the NAME)"
            )
        else:
            detail = f"never read the IAT slot at {obs['iat_slot']:#x}"
        result.check(
            "the IAT deref read the IAT slot, not the hint/name record",
            read_iat and not read_name,
            detail,
        )
    called = obs.get("vp_called", False)
    result.check("the API stub was entered", called, "" if called else _no_goal_detail(obs))
    if called:
        # CHWIN-06: the two recipes take the same NUMBER of arguments and
        # not the same arguments.  `None` in `want` means "no fixed value —
        # this is the out-parameter, check it points somewhere writable that
        # is not the shellcode" (CHWIN-02); VirtualAlloc has no such slot.
        if str(obs.get("api_name", "")).lower() == "virtualalloc":
            names = ("lpAddress", "dwSize", "flAllocationType", "flProtect")
            want = (obs["shellcode_addr"], shellcode_size, MEM_COMMIT, new_protect)
        else:
            names = ("lpAddress", "dwSize", "flNewProtect", "lpflOldProtect")
            want = (obs["shellcode_addr"], shellcode_size, new_protect, None)
        for i, (nm, w) in enumerate(zip(names, want)):
            got = obs["vp_args"][i]
            if w is None:
                # CHWIN-02: the out-parameter must not alias the shellcode,
                # and must point at writable memory.
                writable = obs.get("vp_old_protect_writable", False)
                result.check(
                    "lpflOldProtect points at writable memory",
                    writable,
                    f"{got:#x}" if writable else f"{got:#x} is not writable",
                )
                aliases = obs["shellcode_addr"] <= got < obs["shellcode_addr"] + 4
                result.check(
                    "lpflOldProtect does not alias the shellcode",
                    not aliases,
                    f"{got:#x} is inside the shellcode's first DWORD"
                    if aliases
                    else f"{got:#x} vs shellcode {obs['shellcode_addr']:#x}",
                )
                continue
            # CHWIN-07: an argument register clobbered by a later gadget's
            # tail pop shows up right here, as 0x4141414141414141.
            result.check(f"{nm} == {w:#x}", got == w, f"got {got:#x}")
    reached = obs.get("reached_shellcode", False)
    result.check(
        "control reached the shellcode", reached, "" if reached else _no_goal_detail(obs)
    )
    if reached:
        before = obs.get("shellcode_first4_before")
        after = obs.get("shellcode_first4")
        why = (
            ""
            if str(obs.get("api_name", "")).lower() == "virtualalloc"
            else " (VirtualProtect wrote through lpflOldProtect)"
        )
        if obs.get("expect_stage") is not None:
            # CHWIN-08 #5: the region was pre-filled with 0xCC, so matching
            # the expected first four bytes means the CHAIN wrote them.
            result.check(
                "the staged shellcode is present at the shellcode address",
                before == after,
                f"want {before}, got {after}{why}",
            )
        else:
            result.check(
                "shellcode's first 4 bytes are intact",
                before == after,
                f"{before} -> {after}{why}",
            )
    if expect_calls:
        # CHWIN-08 #2: every composed call must have been entered, in order,
        # with the recipe the builder named.
        got = [c["api"] for c in obs.get("vp_calls", [])]
        result.check(
            "every composed API call was entered, in order",
            got == list(expect_calls),
            f"entered {got}, want {list(expect_calls)}",
        )


def _no_goal_detail(obs):
    bits = []
    if obs.get("uc_error"):
        bits.append(obs["uc_error"])
    if obs.get("pc_at_error") is not None:
        bits.append(f"pc={obs['pc_at_error']:#x}")
    for f in obs.get("faults", [])[:1]:
        bits.append(f"fault at {f['address']:#x}")
    tgts = obs.get("ret_targets", [])
    if tgts:
        bits.append(f"last ret target {tgts[-1]:#x}")
    bits.append(f"{obs.get('steps', 0)} steps")
    return ", ".join(bits)


def verify_binary(binary, goal=Goal.AUTO, chain_args=(), **kw):
    """generate_chain + emulate_chain in one call — the common entry point."""
    chain, info = generate_chain(binary, chain_args)
    return emulate_chain(binary, chain, goal, info=info, **kw)


def _no_goal_detail_linux(obs):
    return _no_goal_detail(obs)


# ---------------------------------------------------------------------------
# Synthetic PE builder — the four Windows regressions need gadget sets the
# shipped fixtures do not have.  pe-x64-cmd-v6.1.7601 cannot populate rdx at
# all (measured: "cannot populate rdx: no 'pop rdx' gadget and no 'pop rax' +
# 'mov rdx, rax' fallback"), so no chain is produced and no end-to-end run is
# possible on it.  These PEs are the same trick windows.rs's own unit tests
# use — a synthetic gadget set — except they go through the real CLI.
# ---------------------------------------------------------------------------

SYNTH_IMAGE_BASE = 0x140000000
SYNTH_TEXT_RVA = 0x1000
SYNTH_RDATA_RVA = 0x2000
SYNTH_DATA_RVA = 0x3000
SYNTH_FILE_ALIGN = 0x200

#: name -> machine code.  Every gadget the Windows builder can ask for.
GADGET_BYTES = {
    "pop rcx ; ret": b"\x59\xc3",
    "pop rdx ; ret": b"\x5a\xc3",
    "pop r8 ; ret": b"\x41\x58\xc3",
    "pop r8 ; pop rbx ; ret": b"\x41\x58\x5b\xc3",
    "pop r9 ; ret": b"\x41\x59\xc3",
    "pop r9 ; pop rbx ; ret": b"\x41\x59\x5b\xc3",
    "pop rax ; ret": b"\x58\xc3",
    "pop rax ; pop rcx ; ret": b"\x58\x59\xc3",
    "mov rax, qword ptr [rax] ; ret": b"\x48\x8b\x00\xc3",
    "mov rax, qword ptr [rax] ; pop rbx ; ret": b"\x48\x8b\x00\x5b\xc3",
    "jmp rax": b"\xff\xe0",
    # CHWIN-08 #1: the stack pivot. `5c` is `pop rsp`.
    "pop rsp ; ret": b"\x5c\xc3",
    # CHWIN-08 #2: discards the four shadow-space words and returns, so a
    # non-final API call can return INTO the chain without the exploit
    # knowing the chain's runtime address.
    "pop rdi ; pop rsi ; pop rbx ; pop rbp ; ret": b"\x5f\x5e\x5b\x5d\xc3",
    # CHWIN-08 #5: the write-what-where the staging writes go through, and
    # the two pops that drive it. `pop rdi`/`pop rsi` are single bytes and
    # are also the first two slots of the stack-adjust gadget above, which
    # is why that one is listed FIRST (see the ordering note).
    "mov qword ptr [rdi], rsi ; ret": b"\x48\x89\x37\xc3",
    "pop rdi ; ret": b"\x5f\xc3",
    "pop rsi ; ret": b"\x5e\xc3",
}


def _align(n, a):
    return (n + a - 1) & ~(a - 1)


#: RVA of the first EXPORTED stub inside .text.  `write_synthetic_pe`
#: appends one `ret` per exported name AFTER the gadget bytes, so the export
#: points at real, executable code -- which is what makes CHWIN-08 #3
#: testable: the harness stubs the exported address, and only a chain that
#: actually read the export directory transfers control there.
def synthetic_export_rva(gadget_names, index=0):
    body = sum(len(GADGET_BYTES[n]) + 1 for n in gadget_names)
    return SYNTH_TEXT_RVA + body + index


def synthetic_export_addr(gadget_names, index=0):
    return SYNTH_IMAGE_BASE + synthetic_export_rva(gadget_names, index)


def write_synthetic_pe(
    path,
    gadget_names,
    imports=(("KERNEL32.dll", "VirtualProtect"),),
    exports=(),
):
    """A minimal PE32+ carrying exactly `gadget_names`, in that order.

    Order is load-bearing: `find_exact` scans the gadget list REVERSED, so a
    later (higher-address) gadget wins.  Sub-decodes of REX-prefixed pops
    alias shorter gadgets (`41 58 c3` contains `pop rax ; ret` at +1), so put
    the gadget you want selected last.

    `exports` is a tuple of names.  Each gets a one-byte `ret` stub appended
    to .text, in order, at `synthetic_export_addr(gadget_names, i)`, and an
    IMAGE_EXPORT_DIRECTORY naming it (CHWIN-08 #3).
    """
    text = bytearray()
    for name in gadget_names:
        text += GADGET_BYTES[name]
        text += b"\xcc"  # int3 separator: stops cross-gadget decoding
    export_rvas = []
    for i, _ in enumerate(exports):
        export_rvas.append(SYNTH_TEXT_RVA + len(text))
        text += b"\xc3"  # the exported "API": a bare ret the harness stubs
    text = bytes(text)

    rdata = bytearray()
    n = len(imports)
    desc_off = 0
    desc_size = (n + 1) * 20
    ilt_off = _align(desc_size, 8)
    ilt_size = (n + 1) * 8
    iat_off = ilt_off + ilt_size
    iat_size = (n + 1) * 8
    strings_off = iat_off + iat_size
    rdata.extend(b"\x00" * strings_off)

    dll_rvas, name_rvas = [], []
    for dll, sym in imports:
        dll_rvas.append(SYNTH_RDATA_RVA + len(rdata))
        rdata.extend(dll.encode() + b"\x00")
        if len(rdata) % 2:
            rdata.append(0)
        name_rvas.append(SYNTH_RDATA_RVA + len(rdata))
        rdata.extend(struct.pack("<H", 0) + sym.encode() + b"\x00")
        if len(rdata) % 2:
            rdata.append(0)

    for i, _ in enumerate(imports):
        struct.pack_into(
            "<IIIII",
            rdata,
            desc_off + i * 20,
            SYNTH_RDATA_RVA + ilt_off + i * 8,  # OriginalFirstThunk (ILT)
            0,
            0,
            dll_rvas[i],  # Name
            SYNTH_RDATA_RVA + iat_off + i * 8,  # FirstThunk (IAT)
        )
        struct.pack_into("<Q", rdata, ilt_off + i * 8, name_rvas[i])
        struct.pack_into("<Q", rdata, iat_off + i * 8, name_rvas[i])

    # IMAGE_EXPORT_DIRECTORY (CHWIN-08 #3): the 40-byte header, then the
    # three parallel arrays (functions, names, name-ordinals) the loader
    # walks, then the name strings.
    edir_off = edir_size = 0
    if exports:
        while len(rdata) % 4:
            rdata.append(0)
        edir_off = len(rdata)
        n_exp = len(exports)
        rdata.extend(b"\x00" * 40)
        funcs_off = len(rdata)
        rdata.extend(b"\x00" * (4 * n_exp))
        names_off = len(rdata)
        rdata.extend(b"\x00" * (4 * n_exp))
        ords_off = len(rdata)
        rdata.extend(b"\x00" * (2 * n_exp))
        exp_name_rvas = []
        for name in exports:
            exp_name_rvas.append(SYNTH_RDATA_RVA + len(rdata))
            rdata.extend(name.encode() + b"\x00")
        edir_size = len(rdata) - edir_off
        struct.pack_into("<I", rdata, edir_off + 0x0C, exp_name_rvas[0])  # module Name
        struct.pack_into("<I", rdata, edir_off + 0x10, 1)  # Base ordinal
        struct.pack_into("<I", rdata, edir_off + 0x14, n_exp)  # NumberOfFunctions
        struct.pack_into("<I", rdata, edir_off + 0x18, n_exp)  # NumberOfNames
        struct.pack_into("<I", rdata, edir_off + 0x1C, SYNTH_RDATA_RVA + funcs_off)
        struct.pack_into("<I", rdata, edir_off + 0x20, SYNTH_RDATA_RVA + names_off)
        struct.pack_into("<I", rdata, edir_off + 0x24, SYNTH_RDATA_RVA + ords_off)
        for i in range(n_exp):
            struct.pack_into("<I", rdata, funcs_off + 4 * i, export_rvas[i])
            struct.pack_into("<I", rdata, names_off + 4 * i, exp_name_rvas[i])
            struct.pack_into("<H", rdata, ords_off + 2 * i, i)
    rdata = bytes(rdata)

    data = b"\x00" * 0x200

    headers_size = _align(0x40 + 4 + 20 + 240 + 3 * 40, SYNTH_FILE_ALIGN)
    secs = [
        (b".text", SYNTH_TEXT_RVA, text, 0x60000020),
        (b".rdata", SYNTH_RDATA_RVA, rdata, 0x40000040),
        (b".data", SYNTH_DATA_RVA, data, 0xC0000040),
    ]
    out = bytearray(headers_size)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x40)
    struct.pack_into("<4s", out, 0x40, b"PE\x00\x00")
    coff = 0x44
    struct.pack_into("<HHIIIHH", out, coff, 0x8664, len(secs), 0, 0, 0, 240, 0x0022)
    opt = coff + 20
    struct.pack_into("<HBB", out, opt, 0x20B, 1, 0)
    struct.pack_into("<III", out, opt + 4, len(text), len(rdata) + len(data), 0)
    struct.pack_into("<II", out, opt + 16, SYNTH_TEXT_RVA, SYNTH_TEXT_RVA)
    struct.pack_into("<Q", out, opt + 24, SYNTH_IMAGE_BASE)
    struct.pack_into("<II", out, opt + 32, 0x1000, SYNTH_FILE_ALIGN)
    struct.pack_into("<HHHHHH", out, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", out, opt + 52, 0)
    struct.pack_into("<I", out, opt + 56, SYNTH_DATA_RVA + 0x1000)  # SizeOfImage
    struct.pack_into("<I", out, opt + 60, headers_size)
    struct.pack_into("<I", out, opt + 64, 0)
    struct.pack_into("<HH", out, opt + 68, 3, 0)
    struct.pack_into("<QQQQ", out, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<II", out, opt + 104, 0, 16)
    dd = opt + 112
    if exports:
        struct.pack_into(
            "<II", out, dd + 0 * 8, SYNTH_RDATA_RVA + edir_off, edir_size
        )  # EXPORT
    struct.pack_into("<II", out, dd + 1 * 8, SYNTH_RDATA_RVA + desc_off, desc_size)  # IMPORT
    struct.pack_into("<II", out, dd + 12 * 8, SYNTH_RDATA_RVA + iat_off, iat_size)  # IAT

    sect = opt + 240
    file_off = headers_size
    for i, (name, rva, blob, chars) in enumerate(secs):
        raw = _align(len(blob), SYNTH_FILE_ALIGN)
        o = sect + i * 40
        struct.pack_into("<8s", out, o, name)
        struct.pack_into("<IIII", out, o + 8, max(len(blob), 0x1000), rva, raw, file_off)
        struct.pack_into("<IIHH", out, o + 24, 0, 0, 0, 0)
        struct.pack_into("<I", out, o + 36, chars)
        out.extend(blob + b"\x00" * (raw - len(blob)))
        file_off += raw

    with open(path, "wb") as fh:
        fh.write(bytes(out))
    return path


# ---------------------------------------------------------------------------
# The seeded Windows regressions (CHWIN-01, -02, -03, -07)
# ---------------------------------------------------------------------------

STUB_API_ADDR = 0x00007FFF12340000

#: (id, title, gadget set, extra CLI args, expected verdict TODAY, the
#: assertion that decides it).  `expect` is the recorded pre-fix state from
#: docs/chain-regressions.md — PASS / FAIL / REFUSED / NO-CHAIN — and the
#: harness FAILS if a test does not match it, in EITHER direction, so "fixed"
#: and "broken again" are both caught.  When a fix lands, update `expect`
#: here and the table in docs/chain-regressions.md in the same commit.
WIN_REGRESSIONS = [
    {
        "id": "CHWIN-01",
        "title": "alignment pad is an inert word the previous `ret` jumps to",
        "gadgets": [
            "pop r8 ; ret",
            "pop rdx ; ret",
            "pop rcx ; ret",
            "pop r9 ; pop rbx ; ret",
        ],
        # `--chain-base aligned` is the parity model the PRE-FIX builder
        # hardcoded (windows.rs:28, "chain base assumed 16-aligned at the
        # pivot -- the standard exploit precondition").  Under it this
        # gadget set's odd pre-transfer word count is exactly the condition
        # that made `align_for_transfer` fire, so the case still exercises
        # the alignment slide after CHWIN-04 made the base a parameter and
        # changed the DEFAULT.  Without it this set needs no slide at all
        # and the case would pass vacuously.
        "args": [
            "--chain",
            "windows-virtualprotect",
            "--api-addr",
            hex(STUB_API_ADDR),
            "--chain-base",
            "aligned",
        ],
        "api_addr": STUB_API_ADDR,
        "key_check": "no control transfer to the padding constant",
        # Pre-fix this chain was EMITTED and the emulator watched it die:
        # "a `ret` targeted 0x4141414141414141", 10 steps, VirtualProtect
        # never entered (quoted in docs/chain-regressions.md). CHLX-04's
        # static verifier then refused it at generation time instead --
        # the stronger pre-fix state, since the user was no longer handed
        # the dead chain. FIXED: the one-word slide is now the address of a
        # bare `ret` gadget, which consumes itself, so the chain is emitted,
        # runs, and reaches intact shellcode. `refusal_must_contain` is kept
        # so a REGRESSION back to the padding word is reported as REFUSED --
        # which no longer matches the record -- rather than as something else.
        "expect": "PASS",
        "refusal_must_contain": ("static stack accounting (CHLX-04)", "Padding", "CHWIN-01"),
    },
    {
        "id": "CHWIN-02",
        "title": "lpflOldProtect aliases the shellcode; VirtualProtect "
        "overwrites the first 4 bytes of the buffer it just made RWX",
        "gadgets": [
            "pop r8 ; ret",
            "pop r9 ; ret",
            "pop rdx ; ret",
            "pop rcx ; ret",
        ],
        "args": ["--chain", "windows-virtualprotect", "--api-addr", hex(STUB_API_ADDR)],
        "api_addr": STUB_API_ADDR,
        "key_check": "shellcode's first 4 bytes are intact",
        # FIXED: &lpflOldProtect is now a distinct writable DWORD (the last
        # word of the region the call itself makes writable), so the
        # out-parameter write no longer lands on the shellcode's entry.
        "expect": "PASS",
    },
    {
        "id": "CHWIN-03",
        "title": "the IAT deref must load a POINTER, not the hint/name ASCII",
        "gadgets": [
            "pop r8 ; ret",
            "pop r9 ; ret",
            "pop rdx ; ret",
            "pop rcx ; ret",
            "pop rax ; ret",
            "mov rax, qword ptr [rax] ; pop rbx ; ret",
            "jmp rax",
        ],
        "args": ["--chain", "windows-virtualprotect"],
        "api_addr": None,
        "key_check": "the IAT deref read the IAT slot",
        "expect": "PASS",
    },
    {
        "id": "CHWIN-07",
        "title": "extra pops in the IAT gadgets destroy argument registers "
        "populated earlier",
        # `pop r8 ; ret` is deliberately absent: its REX form (41 58 c3)
        # sub-decodes to a plain `pop rax ; ret` at +1, and find_exact scans
        # the ALPHABETICALLY sorted gadget list reversed, so "pop rax ; ret"
        # would outrank "pop rax ; pop rcx ; ret" and the IAT gadget would
        # have no extra pop left to demonstrate.  The `pop rbx` tails also
        # keep the pre-transfer word count EVEN, so align_for_transfer does
        # not fire and CHWIN-01 cannot mask this case.
        "gadgets": [
            "pop r8 ; pop rbx ; ret",
            "pop r9 ; pop rbx ; ret",
            "pop rdx ; ret",
            "pop rcx ; ret",
            "mov rax, qword ptr [rax] ; ret",
            "jmp rax",
            "pop rax ; pop rcx ; ret",
        ],
        "args": ["--chain", "windows-virtualprotect"],
        "api_addr": None,
        "key_check": "lpAddress == ",
        # FIXED: emit_api_call64 now threads the populated argument
        # registers into ChainBuilder::padding, so the IAT gadget's tail
        # `pop rcx` is handed lpAddress back instead of the 0x41.. constant.
        "expect": "PASS",
    },
    {
        # Same defect as CHWIN-02, on the x86 stdcall builder
        # (`build_win32(b, opts, data.vaddr, shellcode)` passes the writable
        # section vaddr for BOTH the shellcode home and &lpflOldProtect) and
        # on a REAL shipped fixture rather than a synthetic one.  The x86
        # path needs no register gadgets at all — every argument is a stack
        # word — so pe-x86-cmd DOES produce a chain, and that makes this the
        # one end-to-end reproduction of CHWIN-02 on a binary the project
        # ships.  The x64 fixture cannot get this far (it cannot populate
        # rdx), which is why the other cases use synthetic PEs.
        "id": "CHWIN-02-x86",
        "title": "same aliasing on the x86 stdcall builder, on the shipped "
        "pe-x86-cmd fixture",
        "binary": "pe-x86-cmd-v6.1.7600",
        "args": ["--chain", "windows-virtualprotect", "--api-addr", "0x77001234"],
        "api_addr": 0x77001234,
        "key_check": "shellcode's first 4 bytes are intact",
        # FIXED with the x64 path: build_win32 is handed the scratch DWORD,
        # not the shellcode address a second time.
        "expect": "PASS",
    },
    {
        # CHWIN-04. The alignment invariant used to be anchored to a
        # hardcoded, unstated assumption ("chain base assumed 16-aligned at
        # the pivot"), which is INVERTED in the commonest delivery: an
        # overwritten saved return address sits at an address = 8 (mod 16).
        # The base is now a declared parameter, and declaring it changes the
        # layout -- this case is the same four pops as CHWIN-02 with the
        # OTHER base, so the transfer word lands at an even index instead of
        # an odd one, and the chain still runs. Pre-fix state: the flag did
        # not exist (AUDIT-FINDINGS CHWIN-04, "There is no --chain-base /
        # alignment flag in the CLI or MCP schema"), so clap rejected it and
        # no chain was produced.
        "id": "CHWIN-04",
        "title": "the chain-base parity is a declared parameter, and the "
        "chain runs under either value",
        "gadgets": [
            "pop r8 ; ret",
            "pop r9 ; ret",
            "pop rdx ; ret",
            "pop rcx ; ret",
        ],
        "args": [
            "--chain",
            "windows-virtualprotect",
            "--api-addr",
            hex(STUB_API_ADDR),
            "--chain-base",
            "aligned",
        ],
        "api_addr": STUB_API_ADDR,
        "key_check": "control reached the shellcode",
        "expect": "PASS",
    },
    {
        # CHWIN-06, the pre-fix state, reproduced rather than remembered:
        # `WinChainOpts::api_name` was set from nowhere, so the IAT path
        # could only ever resolve "VirtualProtect". This PE imports
        # VirtualAlloc -- like both cmd.exe fixtures this project ships, and
        # unlike anything the old code could target -- and without
        # `--api-name` the builder still refuses it. This row must keep
        # REFUSING: it is what fails if the name is ever re-hardcoded.
        "id": "CHWIN-06-before",
        "title": "without --api-name the IAT path can only resolve "
        "VirtualProtect, which no shipped PE imports",
        "gadgets": [
            "pop r8 ; ret",
            "pop r9 ; ret",
            "pop rdx ; ret",
            "pop rcx ; ret",
            "pop rax ; ret",
            "mov rax, qword ptr [rax] ; pop rbx ; ret",
            "jmp rax",
        ],
        "imports": (("KERNEL32.dll", "VirtualAlloc"),),
        "args": ["--chain", "windows-virtualprotect"],
        "api_addr": None,
        "api_name": "VirtualAlloc",
        "key_check": "the IAT deref read the IAT slot",
        "expect": "REFUSED",
        "refusal_must_contain": ("does not import VirtualProtect", "--api-name"),
    },
    {
        # CHWIN-06, fixed: the same PE, the same gadgets, plus the name of
        # the API it actually imports. The chain resolves through the IAT
        # and enters the stub -- the resolution path the audit found was
        # unreachable on every binary the project ships. VirtualAlloc's
        # third and fourth arguments are flAllocationType and flProtect, not
        # flNewProtect and &lpflOldProtect, so the builder uses ITS recipe
        # and the harness stubs it with the matching semantics.
        "id": "CHWIN-06",
        "title": "--api-name reaches the IAT path for the API the PE "
        "actually imports",
        "gadgets": [
            "pop r8 ; ret",
            "pop r9 ; ret",
            "pop rdx ; ret",
            "pop rcx ; ret",
            "pop rax ; ret",
            "mov rax, qword ptr [rax] ; pop rbx ; ret",
            "jmp rax",
        ],
        "imports": (("KERNEL32.dll", "VirtualAlloc"),),
        "args": ["--chain", "windows-virtualprotect", "--api-name", "VirtualAlloc"],
        "api_addr": None,
        "api_name": "VirtualAlloc",
        "key_check": "the IAT deref read the IAT slot",
        "expect": "PASS",
    },
]


# ---------------------------------------------------------------------------
# CHLX-07: the Linux chain targets, each gated on an executed assertion.
#
# THE GATING RULE (PLAN sec. Phase 5): "Every target is gated on a passing
# harness assertion before it may be advertised."  A row here is what earns
# a target its place in --help, in the MCP tool description and in the docs.
# `expect` is the RECORDED verdict, so a target that stops working fails the
# build, and a target that starts working where it could not is a visible
# change rather than a silent one.
# ---------------------------------------------------------------------------

#: A 32-bit stand-in for libc's `system`, and its 64-bit twin.  Neither is in
#: any fixture's image: the harness maps a stub page there, and reaching it
#: with arg1 -> "/bin//sh" IS the ret2libc goal.
STUB_LIBC32 = 0xF7A52390
STUB_LIBC64 = 0x7FFFF7A52390

LINUX_REGRESSIONS = [
    # --- linux-execve: the pre-existing target, still executed ------------
    {"id": "execve-x64", "fixture": "elf-Linux-x64", "goal": Goal.LINUX_EXECVE,
     "args": ["--chain", "linux-execve"], "expect": "PASS"},
    {"id": "execve-x86", "fixture": "elf-Linux-x86", "goal": Goal.LINUX_EXECVE,
     "args": ["--chain", "linux-execve"], "expect": "PASS"},
    # --- linux-mprotect (CHLX-07): the NX answer, and the staging half ----
    {"id": "mprotect-x64", "fixture": "elf-Linux-x64", "goal": Goal.LINUX_SYSCALL,
     "args": ["--chain", "linux-mprotect"], "kw": {"expect_syscall": 10},
     "expect": "PASS"},
    {"id": "mprotect-x64-bash", "fixture": "elf-x64-bash-v4.1.5.1",
     "goal": Goal.LINUX_SYSCALL, "args": ["--chain", "linux-mprotect"],
     "kw": {"expect_syscall": 10}, "expect": "PASS"},
    {"id": "mprotect-x86", "fixture": "elf-Linux-x86", "goal": Goal.LINUX_SYSCALL,
     "args": ["--chain", "linux-mprotect"], "kw": {"expect_syscall": 125},
     "expect": "PASS"},
    {"id": "mprotect-x86-freebsd", "fixture": "elf-FreeBSD-x86",
     "goal": Goal.LINUX_SYSCALL, "args": ["--chain", "linux-mprotect"],
     "kw": {"expect_syscall": 125}, "expect": "PASS"},
    # An explicit region: the builder must page-align it DOWN and round the
    # length UP, which is what mprotect requires and what a chain that
    # passed the raw address straight through would get wrong.
    {"id": "mprotect-explicit-region", "fixture": "elf-Linux-x64",
     "goal": Goal.LINUX_SYSCALL,
     "args": ["--chain", "linux-mprotect", "--shellcode-addr", "0x6bc123",
              "--shellcode-size", "0x10", "--prot", "5"],
     "kw": {"expect_syscall": 10,
            "expect_regs": {"rdi": 0x6BC000, "rsi": 0x1000, "rdx": 5}},
     "expect": "PASS"},
    # --- linux-syscall (CHLX-07): the generic builder ---------------------
    {"id": "syscall-generic-x64", "fixture": "elf-Linux-x64",
     "goal": Goal.LINUX_SYSCALL,
     "args": ["--chain", "linux-syscall", "--syscall", "39"],
     "kw": {"expect_syscall": 39}, "expect": "PASS"},
    {"id": "syscall-args-x64", "fixture": "elf-Linux-x64",
     "goal": Goal.LINUX_SYSCALL,
     "args": ["--chain", "linux-syscall", "--syscall", "60",
              "--syscall-args", "rdi=0x2a"],
     "kw": {"expect_syscall": 60, "expect_regs": {"rdi": 0x2A}},
     "expect": "PASS"},
    {"id": "syscall-generic-x86", "fixture": "elf-Linux-x86",
     "goal": Goal.LINUX_SYSCALL,
     "args": ["--chain", "linux-syscall", "--syscall", "20",
              "--syscall-args", "ebx=0x1234"],
     "kw": {"expect_syscall": 20, "expect_regs": {"ebx": 0x1234}},
     "expect": "PASS"},
    # --- linux-ret2libc (CHLX-07) -----------------------------------------
    # All four fixtures the audit named as producing NOTHING at all
    # (elf-x64-bash, elf-x86-bash, elf-FreeBSD-x86, Linux_lib32.so) are here,
    # and all four now execute.
    {"id": "ret2libc-x64", "fixture": "elf-Linux-x64", "goal": Goal.LINUX_RET2LIBC,
     "args": ["--chain", "linux-ret2libc", "--api-addr", hex(STUB_LIBC64)],
     "kw": {"func_addr": STUB_LIBC64}, "expect": "PASS"},
    {"id": "ret2libc-x64-bash", "fixture": "elf-x64-bash-v4.1.5.1",
     "goal": Goal.LINUX_RET2LIBC,
     "args": ["--chain", "linux-ret2libc", "--api-addr", hex(STUB_LIBC64)],
     "kw": {"func_addr": STUB_LIBC64}, "expect": "PASS"},
    {"id": "ret2libc-x86", "fixture": "elf-Linux-x86", "goal": Goal.LINUX_RET2LIBC,
     "args": ["--chain", "linux-ret2libc", "--api-addr", hex(STUB_LIBC32)],
     "kw": {"func_addr": STUB_LIBC32}, "expect": "PASS"},
    {"id": "ret2libc-x86-bash", "fixture": "elf-x86-bash-v4.1.5.1",
     "goal": Goal.LINUX_RET2LIBC,
     "args": ["--chain", "linux-ret2libc", "--api-addr", hex(STUB_LIBC32)],
     "kw": {"func_addr": STUB_LIBC32}, "expect": "PASS"},
    {"id": "ret2libc-freebsd-x86", "fixture": "elf-FreeBSD-x86",
     "goal": Goal.LINUX_RET2LIBC,
     "args": ["--chain", "linux-ret2libc", "--api-addr", hex(STUB_LIBC32)],
     "kw": {"func_addr": STUB_LIBC32}, "expect": "PASS"},
    {"id": "ret2libc-lib32", "fixture": "Linux_lib32.so",
     "goal": Goal.LINUX_RET2LIBC,
     "args": ["--chain", "linux-ret2libc", "--api-addr", hex(STUB_LIBC32)],
     "kw": {"func_addr": STUB_LIBC32}, "expect": "PASS"},
    # A 64-bit address on a 32-bit target must be REFUSED, not packed into a
    # word it does not fit.
    {"id": "ret2libc-x86-wide-addr-refused", "fixture": "elf-Linux-x86",
     "goal": Goal.LINUX_RET2LIBC,
     "args": ["--chain", "linux-ret2libc", "--api-addr", hex(STUB_LIBC64)],
     "kw": {"func_addr": STUB_LIBC64}, "expect": "REFUSED",
     "refusal_must_contain": ("does not fit", "4-byte word")},
    # --- linux-srop (CHLX-07) ---------------------------------------------
    # The assertion is not "the chain asked for rt_sigreturn": the harness
    # APPLIES the frame exactly as the kernel would, and the restored context
    # has to reach execve by itself.
    {"id": "srop-x64", "fixture": "elf-Linux-x64", "goal": Goal.LINUX_SROP,
     "args": ["--chain", "linux-srop"], "kw": {"expect_syscall": 59},
     "expect": "PASS"},
    {"id": "srop-x64-bash", "fixture": "elf-x64-bash-v4.1.5.1",
     "goal": Goal.LINUX_SROP, "args": ["--chain", "linux-srop"],
     "kw": {"expect_syscall": 59}, "expect": "PASS"},
    # SROP with an explicit call: no write primitive is needed at all, which
    # is the technique's actual selling point for a gadget-poor binary.
    {"id": "srop-x64-explicit-syscall", "fixture": "elf-Linux-x64",
     "goal": Goal.LINUX_SROP,
     "args": ["--chain", "linux-srop", "--syscall", "10",
              "--syscall-args", "rdi=0x6bc000,rsi=0x1000,rdx=7"],
     "kw": {"expect_syscall": 10,
            "expect_regs": {"rdi": 0x6BC000, "rsi": 0x1000, "rdx": 7}},
     "expect": "PASS"},
    # i386's sigcontext is a different structure and is NOT modelled;
    # refusing beats emitting a frame with the wrong layout.
    {"id": "srop-x86-refused", "fixture": "elf-Linux-x86", "goal": Goal.LINUX_SROP,
     "args": ["--chain", "linux-srop"], "kw": {"expect_syscall": 59},
     "expect": "REFUSED", "refusal_must_contain": ("linux-srop is x86-64 only",)},
    # --- targets that must stay refused where they cannot work ------------
    # These two x86 fixtures have no `int 0x80` at all.  They DO have a
    # `syscall`, which in 32-bit mode is not a Linux system-call entry, so
    # accepting it would emit a chain that faults.
    {"id": "mprotect-x86-bash-no-int80", "fixture": "elf-x86-bash-v4.1.5.1",
     "goal": Goal.LINUX_SYSCALL, "args": ["--chain", "linux-mprotect"],
     "kw": {"expect_syscall": 125}, "expect": "REFUSED",
     "refusal_must_contain": ("int 0x80",)},
    {"id": "mprotect-lib32-no-int80", "fixture": "Linux_lib32.so",
     "goal": Goal.LINUX_SYSCALL, "args": ["--chain", "linux-mprotect"],
     "kw": {"expect_syscall": 125}, "expect": "REFUSED",
     "refusal_must_contain": ("int 0x80",)},
    # --- coverage closure: EVERY (target, fixture) pair that emits ---------
    # The v0.5 exit criterion is "the harness executes every chain the tool
    # emits", and the rows above were chosen to demonstrate each TARGET, not
    # to cover the corpus. Sweeping the 5 advertised Linux targets across the
    # 8 chainable ELF fixtures found 29 pairs that emit a chain and 9 of them
    # with no row here — a chain a user can generate and nothing had ever
    # run. These nine close that gap. They assert nothing new about the
    # builder; they assert that no emitted chain is unexecuted.
    {"id": "mprotect-ndh", "fixture": "elf-Linux-x86-NDH-chall",
     "goal": Goal.LINUX_SYSCALL, "args": ["--chain", "linux-mprotect"],
     "kw": {"expect_syscall": 125}, "expect": "PASS"},
    {"id": "mprotect-lib64", "fixture": "Linux_lib64.so",
     "goal": Goal.LINUX_SYSCALL, "args": ["--chain", "linux-mprotect"],
     "kw": {"expect_syscall": 10}, "expect": "PASS"},
    {"id": "syscall-ndh", "fixture": "elf-Linux-x86-NDH-chall",
     "goal": Goal.LINUX_SYSCALL,
     "args": ["--chain", "linux-syscall", "--syscall", "20"],
     "kw": {"expect_syscall": 20}, "expect": "PASS"},
    {"id": "syscall-freebsd-x86", "fixture": "elf-FreeBSD-x86",
     "goal": Goal.LINUX_SYSCALL,
     "args": ["--chain", "linux-syscall", "--syscall", "20"],
     "kw": {"expect_syscall": 20}, "expect": "PASS"},
    {"id": "syscall-x64-bash", "fixture": "elf-x64-bash-v4.1.5.1",
     "goal": Goal.LINUX_SYSCALL,
     "args": ["--chain", "linux-syscall", "--syscall", "39"],
     "kw": {"expect_syscall": 39}, "expect": "PASS"},
    {"id": "syscall-lib64", "fixture": "Linux_lib64.so",
     "goal": Goal.LINUX_SYSCALL,
     "args": ["--chain", "linux-syscall", "--syscall", "39"],
     "kw": {"expect_syscall": 39}, "expect": "PASS"},
    {"id": "ret2libc-ndh", "fixture": "elf-Linux-x86-NDH-chall",
     "goal": Goal.LINUX_RET2LIBC,
     "args": ["--chain", "linux-ret2libc", "--api-addr", hex(STUB_LIBC32)],
     "kw": {"func_addr": STUB_LIBC32}, "expect": "PASS"},
    {"id": "ret2libc-lib64", "fixture": "Linux_lib64.so",
     "goal": Goal.LINUX_RET2LIBC,
     "args": ["--chain", "linux-ret2libc", "--api-addr", hex(STUB_LIBC64)],
     "kw": {"func_addr": STUB_LIBC64}, "expect": "PASS"},
    {"id": "srop-lib64", "fixture": "Linux_lib64.so", "goal": Goal.LINUX_SROP,
     "args": ["--chain", "linux-srop"], "kw": {"expect_syscall": 59},
     "expect": "PASS"},
]


def run_linux_regression(case, verbose=False):
    """Generate the case's chain with the real CLI, then execute it.

    Same verdict vocabulary as `run_win_regression`.
    """
    path = rf_paths.fixture_path(case["fixture"])
    try:
        chain, info = generate_chain(path, case["args"])
    except ChainBuildFailed as exc:
        text = " ".join(str(exc).split())
        shown = next((ln for ln in str(exc).splitlines() if "[Error]" in ln), text)
        shown = " ".join(shown.split())
        want = case.get("refusal_must_contain") or ()
        if want and all(frag in text for frag in want):
            return "REFUSED", None, shown[:200]
        return "NO-CHAIN", None, shown[:200]
    res = emulate_chain(path, chain, case["goal"], info=info, **case.get("kw", {}))
    if verbose:
        print(res.report())
    return ("PASS" if res.ok else "FAIL"), res, res.reason[:200]


def run_linux_regressions(verbose=False):
    print("# CHLX-07 Linux chain targets, each EXECUTED (the gating rule)")
    rows = []
    for case in LINUX_REGRESSIONS:
        verdict, _res, detail = run_linux_regression(case, verbose)
        rows.append((case["id"], verdict, case["expect"], verdict == case["expect"], detail))
    print("\n{:<32} {:<10} {:<10} detail".format("case", "verdict", "expected"))
    print("-" * 100)
    bad = 0
    for cid, verdict, expect, agrees, detail in rows:
        mark = "" if agrees else "  <-- CHANGED"
        if not agrees:
            bad += 1
        print("{:<32} {:<10} {:<10} {}{}".format(cid, verdict, expect, detail[:42], mark))
    print("-" * 100)
    print("summary: {} of {} match the recorded verdict".format(len(rows) - bad, len(rows)))
    return 1 if bad else 0


#: CHWIN-08's four capabilities, each EXECUTED. `--prot` (the fifth) is
#: covered by CHWIN-04/-06's cases, which already pass a non-default value.
#: Every one of these is a synthetic PE, because the shipped fixtures cannot
#: express the gadget sets: pe-x64-cmd-v6.1.7601 has no `pop rdx` at all and
#: pe-x86-cmd-v6.1.7600 has no clean-tailed `pop eax` or `mov eax, [eax]`
#: (measured -- see the plan_chain output quoted in the workstream notes).
STUB_API2_ADDR = 0x00007FFF12350000

WIN08_REGRESSIONS = [
    {
        "id": "CHWIN-08-pivot",
        "title": "stack pivot: the chain is two pieces and the body runs at --chain-pivot",
        "gadgets": [
            "pop r8 ; ret", "pop r9 ; ret", "pop rdx ; ret", "pop rcx ; ret",
            "pop rsp ; ret",
        ],
        "args": ["--chain", "windows-virtualprotect", "--api-addr", hex(STUB_API_ADDR),
                 "--chain-pivot", "0x30000000"],
        "api_addr": STUB_API_ADDR,
        "key_check": "control reached the shellcode",
        "expect": "PASS",
    },
    {
        "id": "CHWIN-08-pivot-parity",
        "title": "a pivot target that is 4 mod 16 cannot satisfy the Win64 entry "
                 "condition and is refused, not emitted",
        "gadgets": [
            "pop r8 ; ret", "pop r9 ; ret", "pop rdx ; ret", "pop rcx ; ret",
            "pop rsp ; ret",
        ],
        "args": ["--chain", "windows-virtualprotect", "--api-addr", hex(STUB_API_ADDR),
                 "--chain-pivot", "0x30000004"],
        "api_addr": STUB_API_ADDR,
        "key_check": "control reached the shellcode",
        "expect": "REFUSED",
        "refusal_must_contain": ("mod 16", "--pivot"),
    },
    {
        "id": "CHWIN-08-staging",
        "title": "shellcode staging: the chain WRITES the shellcode into the "
                 "region instead of assuming somebody else did",
        "gadgets": [
            "pop r8 ; ret", "pop r9 ; ret", "pop rdx ; ret", "pop rcx ; ret",
            "mov qword ptr [rdi], rsi ; ret", "pop rdi ; ret", "pop rsi ; ret",
        ],
        "args": ["--chain", "windows-virtualprotect", "--api-addr", hex(STUB_API_ADDR),
                 "--stage", "9090909090909090"],
        "api_addr": STUB_API_ADDR,
        "expect_stage": bytes.fromhex("9090909090909090"),
        "key_check": "the staged shellcode is present",
        "expect": "PASS",
    },
    {
        "id": "CHWIN-08-exports",
        "title": "export-table resolution: the target itself exports the API, so "
                 "the chain needs neither a leak nor an IAT dereference",
        "gadgets": [
            "pop r8 ; ret", "pop r9 ; ret", "pop rdx ; ret", "pop rcx ; ret",
        ],
        "exports": ("VirtualProtect",),
        # NO --api-addr: the builder has to read the export directory.
        "args": ["--chain", "windows-virtualprotect"],
        "api_addr": None,
        "api_addr_from_exports": 0,
        "key_check": "control reached the shellcode",
        "expect": "PASS",
    },
    {
        "id": "CHWIN-08-multicall",
        "title": "multi-call composition: VirtualAlloc then VirtualProtect, the "
                 "first returning into the chain through a stack-adjust gadget",
        "gadgets": [
            "pop rdi ; pop rsi ; pop rbx ; pop rbp ; ret",
            "pop r8 ; ret", "pop r9 ; ret", "pop rdx ; ret", "pop rcx ; ret",
        ],
        "args": ["--chain", "windows-virtualprotect",
                 "--api-name", "VirtualAlloc,VirtualProtect",
                 "--api-addr", hex(STUB_API_ADDR) + "," + hex(STUB_API2_ADDR)],
        "api_addr": STUB_API_ADDR,
        "api_name": "VirtualAlloc",
        "extra_apis": ((STUB_API2_ADDR, "VirtualProtect"),),
        "expect_calls": ("VirtualAlloc", "VirtualProtect"),
        "key_check": "every composed API call was entered",
        "expect": "PASS",
    },
]


def run_win_regression(case, workdir, verbose=False):
    """Build the case's synthetic PE, generate its chain, execute it.

    Returns (verdict, EmulationResult|None, detail):
      PASS      the case's key assertion holds
      FAIL      it does not — the chain ran and missed its goal
      REFUSED   generation refused, and the refusal names this case's defect
                (CHLX-04's static verifier: "runnable or not emitted")
      NO-CHAIN  generation refused for some other reason
    """
    if case.get("binary"):
        pe = rf_paths.fixture_path(case["binary"])
    else:
        pe = os.path.join(workdir, f"synth-{case['id']}.exe")
        # `imports` lets a case ship a PE that imports something OTHER than
        # VirtualProtect — which is what every PE this project ships does,
        # and the whole of CHWIN-06.
        kw = {"imports": case["imports"]} if case.get("imports") else {}
        if case.get("exports"):
            kw["exports"] = case["exports"]
        write_synthetic_pe(pe, case["gadgets"], **kw)
    try:
        chain, info = generate_chain(pe, case["args"])
    except ChainBuildFailed as exc:
        # A refusal is a result. CHLX-04's static verifier rejects some of
        # these chains at generation time, which is the contract working:
        # "chains that are emitted must be runnable or not emitted". Only a
        # refusal that NAMES this case's defect counts as that case's
        # pre-fix state, so a refusal for some unrelated reason still fails.
        text = " ".join(str(exc).split())
        # Show the refusal, not the CHWIN-09 experimental warning that
        # precedes it on stderr.
        shown = next(
            (ln for ln in str(exc).splitlines() if "[Error]" in ln), text
        )
        shown = " ".join(shown.split())
        want = case.get("refusal_must_contain") or ()
        if want and all(frag in text for frag in want):
            return "REFUSED", None, shown[:220]
        return "NO-CHAIN", None, shown[:220]
    api_addr = case["api_addr"]
    if case.get("api_addr_from_exports") is not None and case.get("exports"):
        # The harness must stub the address the EXPORT points at; a chain
        # that ignored the export table transfers somewhere else and the
        # stub is never entered, which is exactly the assertion.
        api_addr = synthetic_export_addr(
            case["gadgets"], case["api_addr_from_exports"]
        )
    res = emulate_chain(
        pe,
        chain,
        Goal.WIN_VIRTUALPROTECT,
        api_addr=api_addr,
        api_name=case.get("api_name", "VirtualProtect"),
        new_protect=case.get("new_protect", 0x40),
        info=info,
        extra_apis=case.get("extra_apis", ()),
        expect_stage=case.get("expect_stage"),
        expect_calls=case.get("expect_calls"),
    )
    key = [c for c in res.checks if c[0].startswith(case["key_check"])]
    if not key:
        # The key assertion never ran because an earlier one stopped the
        # chain — that is a failure of this case too, and the reason says why.
        return "FAIL", res, f"{case['key_check']!r} never evaluated: {res.reason}"
    name, passed, detail = key[0]
    return ("PASS" if passed else "FAIL"), res, detail


def run_win08_regressions(verbose=False):
    """CHWIN-08's capabilities, each executed (the gating rule)."""
    print("# CHWIN-08 Windows capabilities, each EXECUTED (the gating rule)")
    rows = []
    with tempfile.TemporaryDirectory(prefix="rf-emulate-w8-") as tmp:
        for case in WIN08_REGRESSIONS:
            verdict, _res, detail = run_win_regression(case, tmp, verbose)
            rows.append((case["id"], verdict, case["expect"],
                         verdict == case["expect"], detail))
    print("\n{:<26} {:<10} {:<10} detail".format("case", "verdict", "expected"))
    print("-" * 100)
    bad = 0
    for cid, verdict, expect, agrees, detail in rows:
        if not agrees:
            bad += 1
        mark = "" if agrees else "  <-- CHANGED"
        print("{:<26} {:<10} {:<10} {}{}".format(cid, verdict, expect, detail[:44], mark))
    print("-" * 100)
    print("summary: {} of {} match the recorded verdict".format(len(rows) - bad, len(rows)))
    return 1 if bad else 0


def run_regressions(verbose=False):
    print("# seeded Windows chain regressions (CHWIN-01/-02/-03/-04/-06/-07)")
    print("# each runs the REAL CLI over a synthetic PE, then executes the chain")
    print(f"# stub API address: {STUB_API_ADDR:#x}\n")
    rows = []
    with tempfile.TemporaryDirectory(prefix="rf-emulate-") as tmp:
        for case in WIN_REGRESSIONS:
            verdict, res, detail = run_win_regression(case, tmp, verbose)
            agrees = verdict == case["expect"]
            rows.append((case, verdict, agrees, detail, res))
            src = case.get("binary") or "synthetic PE: " + ", ".join(case["gadgets"])
            print(f"{case['id']}  {case['title']}")
            print(f"    target        : {src}")
            print(f"    key assertion : {case['key_check']}")
            print(f"    expected      : {case['expect']}   (docs/chain-regressions.md)")
            print(f"    observed      : {verdict}" + (f"   {detail}" if detail else ""))
            if res is not None and (verbose or not agrees):
                print(res.report())
            print(f"    -> {'as recorded' if agrees else 'DIVERGES FROM THE RECORD'}\n")
    bad = [r for r in rows if not r[2]]
    print("-" * 78)
    print(
        "summary: "
        + ", ".join(f"{c['id']}={v}" for c, v, _, _, _ in rows)
        + f"  ({len(rows) - len(bad)}/{len(rows)} match the recorded state)"
    )
    if bad:
        print(
            "\nA regression whose observed state differs from docs/chain-regressions.md\n"
            "is either a fix that has not been recorded, or a regression. Update the\n"
            "table in docs/chain-regressions.md in the same commit as the fix."
        )
    return 1 if bad else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

#: Fixtures the harness sweeps in --all.  Only x86/x64 ELF and PE can produce
#: a chain today; the rest are reported as NO-CHAIN, not as failures.
SWEEP = [
    "elf-Linux-x64",
    "elf-Linux-x86",
    "elf-Linux-x86-NDH-chall",
    "elf-FreeBSD-x86",
    "elf-x64-bash-v4.1.5.1",
    "elf-x86-bash-v4.1.5.1",
    "Linux_lib32.so",
    "Linux_lib64.so",
]


def run_sweep(verbose=False):
    print(f"# environment: {rf_paths.describe_environment(brief=True)}")
    print(f"# unicorn:     {unicorn.__version__}\n")
    rows = []
    for name in SWEEP:
        path = rf_paths.fixture_path(name)
        if not os.path.exists(path):
            rows.append((name, "MISSING", ""))
            continue
        try:
            chain, info = generate_chain(path)
        except ChainBuildFailed as exc:
            rows.append((name, "NO-CHAIN", str(exc).splitlines()[-1][:60]))
            continue
        res = emulate_chain(path, chain, Goal.AUTO, info=info)
        rows.append((name, "RUNS" if res.ok else "BROKEN", res.reason[:70]))
        if verbose or not res.ok:
            print(f"{name}:")
            print(res.report())
    print(f"\n{'fixture':<28} {'verdict':<10} detail")
    print("-" * 78)
    for name, verdict, detail in rows:
        print(f"{name:<28} {verdict:<10} {detail}")
    print("-" * 78)
    counts = {}
    for _, v, _ in rows:
        counts[v] = counts.get(v, 0) + 1
    print("summary: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return 1 if counts.get("BROKEN") or counts.get("MISSING") else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--binary", help="target to emulate a chain against")
    ap.add_argument(
        "--goal",
        default=Goal.AUTO,
        choices=[
            Goal.AUTO,
            Goal.LINUX_EXECVE,
            Goal.LINUX_SYSCALL,
            Goal.LINUX_RET2LIBC,
            Goal.LINUX_SROP,
            Goal.WIN_VIRTUALPROTECT,
        ],
    )
    ap.add_argument("--chain-json", help="chain IR JSON file (default: generate one)")
    ap.add_argument("--chain-arg", action="append", default=[], help="extra rop-finder arg")
    ap.add_argument("--api-addr", help="stubbed API address (hex) for the Windows goal")
    ap.add_argument("--shellcode-addr", help="shellcode address (hex)")
    ap.add_argument("--all", action="store_true", help="sweep every chainable fixture")
    ap.add_argument("--regressions", action="store_true", help="run the seeded CHWIN tests")
    ap.add_argument("--max-steps", type=int, default=200000)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.regressions:
        rc = run_regressions(args.verbose)
        print()
        rc |= run_win08_regressions(args.verbose)
        print()
        return rc | run_linux_regressions(args.verbose)
    if args.all:
        return run_sweep(args.verbose)
    if not args.binary:
        ap.error("one of --binary, --all or --regressions is required")

    kw = {"max_steps": args.max_steps}
    if args.api_addr:
        kw["api_addr"] = int(args.api_addr, 16)
    if args.shellcode_addr:
        kw["shellcode_addr"] = int(args.shellcode_addr, 16)

    if args.chain_json:
        with open(args.chain_json) as fh:
            chain = EmulatedChain.from_ir(json.load(fh))
    else:
        try:
            chain, info = generate_chain(args.binary, args.chain_arg)
            kw["info"] = info
        except ChainBuildFailed as exc:
            print(f"NO-CHAIN {args.binary}: {exc}")
            return 1
    res = emulate_chain(args.binary, chain, args.goal, **kw)
    print(f"{args.binary}: {'RUNS' if res.ok else 'BROKEN'}")
    print(res.report())
    if args.verbose:
        print("    observed:")
        for k, v in sorted(res.observed.items()):
            if k in ("ret_targets",):
                v = [hex(x) for x in v][-6:]
            elif isinstance(v, int) and k not in ("steps", "syscall", "chain_words"):
                v = hex(v)
            print(f"      {k} = {v}")
    return 0 if res.ok else 1


if __name__ == "__main__":
    sys.exit(main())
