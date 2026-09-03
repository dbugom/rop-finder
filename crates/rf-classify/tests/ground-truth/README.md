# Emulated ground truth for CLS-09

Phase 4's exit criterion for the semantic workstream:

> Stack delta and clobber set are verified against ground truth on a
> 500-gadget sample with zero mismatches; every gadget where the rsp effect is
> non-constant reports None rather than a number.

This directory is that verification. It exists because the previous
classifier evaluation was a transliteration of the classifier itself
(CLAIM-05, CLS-11), so the number it produced measured self-agreement. **No
file here reads, imports, links or restates `rf-classify`.** The expected
answers come from running the gadget's bytes on a CPU.

| file | what it is |
|---|---|
| `../effect_sample.rs` | the sampler: a deterministic stride over two fixtures, `#[ignore]`d, prints JSONL |
| `x86-sample.jsonl` | 1,200 candidate gadgets — identity only (fixture, index, vaddr, bytes, text) |
| `oracle_unicorn.py` | the oracle: executes each candidate under Unicorn and records what the machine did |
| `x86-truth.jsonl` | 500 verified gadgets with their measured stack delta, sets, clobbers and payload offsets |
| `x86-truth-stats.json` | the population accounting: what was declined, and why |
| `../ground_truth.rs` | the test: classifies each gadget and compares, in both directions |

## Reproducing it

```sh
# 1. the sample (deterministic; the stride rule is documented in effect_sample.rs)
cargo test -p rf-classify --test effect_sample -- --ignored --nocapture \
  | grep '^{' > crates/rf-classify/tests/ground-truth/x86-sample.jsonl

# 2. the ground truth (needs the `unicorn` package; ~50 s)
"D:/Private/ROP-Finder/.venv-oracle/Scripts/python.exe" \
  crates/rf-classify/tests/ground-truth/oracle_unicorn.py

# 3. the check
cargo test -p rf-classify --test ground_truth
```

Steps 1 and 2 are both byte-for-byte reproducible: the sampler strides rather
than randomises, and the oracle's per-trial machine state comes from a fixed
LCG seeded with a constant written into the file.

## The sampling rule

Two fixtures, one per x86 mode — `tests/fixtures/elf-Linux-x64` (x86-64) and
`tests/fixtures/elf-Linux-x86` (i386) — scanned at the tool's default depth of
10. From each scan's own emission order, take every `stride`-th gadget
starting at index `SEED % stride`, where `stride = floor(total / 600)` and
`SEED = 0x5eedc1a9`. That yields 600 candidates per fixture; the oracle keeps
the first 250 per fixture it can measure, for the 500 the criterion names.

## How a constant is told from a non-constant

Each gadget is executed **six times**. Every trial varies the *uncontrolled*
machine state — all general-purpose registers (over the full address width),
the arithmetic flags, the direction flag, all non-stack memory, and the
absolute address of the stack, high half and low half, plus a sub-page jitter
so `rsp`'s low bits are not always zero. Every trial holds the *controlled*
state fixed: the payload byte at each offset from the entry stack pointer is
identical in all six.

From that one arrangement three questions are answered at once:

* **stack delta** — the six deltas agree iff the effect is constant.
  `pop rdi ; ret` agrees at 16. `xchg rsp, rax ; ret` does not, because rax
  differs. `leave ; ret` does not, because rbp does. `pop rsp ; ret` does not,
  because the stack base does. Each of those *must* be `None`, and that
  requirement is derived here rather than assumed.
* **clobbered** — a register whose final value differs across trials took it
  from something the payload does not choose.
* **set** — a register that ends every trial holding the same value it did not
  start with took it from the payload or from a constant.
* **untouched** — a register that ends every trial holding what it started
  with.

A fourth check falls out of the fixed payload: each payload slot holds a
distinct marker word, so a register that ends up holding one can be traced
back to the byte offset it came from, at byte granularity. That is an
independent check of the register-transfer relations — derived from the value
that actually landed in the register, never from the instruction encoding —
and `ground_truth.rs` compares it in both directions.

Three of the oracle's design choices were forced by wrong answers it produced
first, and each is recorded at the constant it belongs to:

* filling the uncontrolled data region with `nop` made `mov eax, [rax+0x28]`
  read a *constant* `0x90909090` and produced six false "set" verdicts;
* keeping the 64-bit stack below 4 GiB made `add esp, 0x120 ; pop rbx ; ret`
  produce the same (enormous, negative) delta in every trial, so the emulator
  called a 32-bit truncation of `rsp` a constant offset;
* confining register values to a 4 MiB window left every register's high bits
  — including the 32-bit sign bit — identical in every trial, so `cdq` came
  out constant.

## What is declined, and why

`x86-truth-stats.json` records the whole population. Of 1,200 candidates, 500
were verified and 160 declined; the rest were never reached, because the
oracle stops at 250 per fixture. Every declined candidate is a limit of the
**measurement**, never a case of bending an expectation to fit the code:

| reason | count | why the measurement cannot speak |
|---|---|---|
| `early transfer` | 80 | control leaves the gadget before its own terminator. `emu_start` runs a fixed instruction count, so on the taken path it executes the branch target's instructions and would report their stack effect as this gadget's. The quantity is not well defined either — which instructions run depends on incoming flags the chain does not control — and `rf-classify` answers `None` for exactly this case. |
| `not faithfully emulated` | 59 | the gadget contains a syscall or interrupt gate, a ring-0 instruction, or a non-deterministic reader (`rdtsc`, `rdrand`, `cpuid`), which a bare CPU with no kernel does not reproduce. |
| `ret imm16 >= 0x8000` | 17 | QEMU, which Unicorn is built on, loads the immediate with `x86_ldsw_code` — a **signed** word — and adds it to rsp. The Intel SDM and the AMD APM describe the operand as a count of bytes to release, and iced-x86, like Bochs, zero-extends it. The two agree below `0x8000` and disagree by exactly `0x10000` above it. The oracle cannot adjudicate between a documented ISA and an emulator, so it declines to state a value rather than record one that might be wrong. `ret imm16` below `0x8000` stays verified, and `tests.rs` covers `ret 0x10` directly. |
| `emu_start` | 4 | the emulator refused the instruction stream outright. |

## The result

500 gadgets, 250 per fixture, **0 mismatches** — over the stack delta, the
clobber set, the set-register set, and the payload offset of every register
whose provenance the emulator could confirm. Within that sample:

* 11 gadgets have a non-constant rsp effect and report `None`;
* 63 `set` and 244 `clobber` verdicts are confirmed;
* 44 register-provenance offsets are confirmed, in both directions (the test
  fails if the classifier claims a payload offset the marker words contradict,
  as well as if it misses one).

Getting there took six defects out of the classifier that inspection had not
found: `inc`/`dec esp` treated as unprovable, a pop from an unknown `rsp`
reported as payload-controlled, no store-forwarding (so `push [rbp+2] ;
pop rbx` looked like a controlled load), `and al, 0xff` not recognised as an
identity, no known-zero-bit tracking (so `and al, 0x68 ; … ; and eax, 1` came
out clobbered), and push/pop slot widths taken from the operand instead of the
stack step.
