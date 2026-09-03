# Gadget classification taxonomy (Phase 5)

PLAN sec. 7 Phase-5 gate: a written taxonomy with concrete inclusion/
exclusion decision rules, N >= 1,000 gadgets labeled from iced-x86 operand
metadata and spot-verified by hand, per-class precision/recall, gate =
macro-averaged precision >= 0.90 on the held-out half.

> **Superseded in v0.3.0.** The circular gate described here is gone. The
> "independent" labeler in `crates/rf-classify/tests/eval.rs` was a second
> transcription of these same rules — its R6, R2 and R1 mnemonic sets were
> byte-identical to `src/x86.rs`'s (22, 7 and 12 mnemonics; the comparison is
> in `docs/classifier-eval.md` §1.1) — so its 1.0000 measured self-agreement,
> not accuracy. It has been deleted along with the two data files it wrote
> into the source tree on every run (`CLS-01`, `CLS-11`).
>
> The classifier is now measured against **438 hand-labeled gadgets** in
> `tests/classify-corpus/`, frozen by SHA-256, covering x86-64, x86-32, ARM,
> ARM64, MIPS, PowerPC, SPARC and RISC-V 64 (`CLS-10`), and the **primary
> class** — the `class` field users actually see — is the headline metric
> (`CLS-06`). Results, the labeling protocol, the confidence intervals and an
> explicit list of what is *not* measured:
> [`docs/classifier-eval.md`](docs/classifier-eval.md).

## Classes

| class | meaning |
|---|---|
| `reg-write` | writes one or more GPRs, no non-stack memory operands |
| `stack-pivot` | modifies rsp/esp (the stack pointer itself) |
| `mem-read` | reads memory through a non-stack address |
| `mem-write` | writes memory through a non-stack address |
| `arithmetic` | arithmetic/logical computation on registers |
| `syscall` | contains a syscall/sysenter/int gate |
| `dispatcher` | JOP dispatcher: register-indirect control transfer (heuristic) |
| `other` | none of the above (pure control flow, nop, flags-only) |

## Decision rules (x86/x64, iced-x86 `InstructionInfoFactory`)

Applied per gadget after decoding with iced-x86. Each rule names the
metadata it consumes; "GPR" excludes rsp/esp and the flags register.

R1. **Stack normalization.** `push`/`pop`/`enter`/`leave`/`call`/`ret`
    implicitly read or write rsp; that implicit rsp effect is excluded
    from `regs_read`/`regs_written` (it is the chain mechanism, not a
    payload effect). Stack memory operands ([rsp], [rsp+off] in push/pop)
    never trigger `mem-read`/`mem-write`.

R2. **syscall.** Any instruction whose mnemonic is `syscall`, `sysenter`,
    `sysexit`, `sysret`, or an int-family gate (`int`, `int1`, `into`)
    → label `syscall`.

R3. **mem-write.** Any non-control instruction with a memory WRITE
    operand (excluding stack operands per R1) → label `mem-write`.

R4. **mem-read.** Any non-control instruction with a memory READ
    operand (excluding stack operands per R1) → label `mem-read`.
    A read-modify-write instruction (`add qword ptr [rax], rbx`) earns
    BOTH `mem-read` and `mem-write`.

R5. **stack-pivot.** Any instruction that writes rsp/esp as an explicit
    destination (`mov rsp, rX`, `xchg rsp, rX`, `add rsp, imm`, `pop rsp`,
    `leave`, `sub rsp, imm`) → label `stack-pivot`. ANY explicit rsp/esp
    write qualifies — there is no delta exemption, so `add rsp, 8` IS a
    pivot. (The implicit decrement of `call`/`push` is R1-normalized
    away and does NOT count.)

R6. **arithmetic.** Any instruction whose mnemonic is in the arithmetic/
    logical set {add, sub, adc, sbb, inc, dec, neg, not, and, or, xor,
    shl, shr, sar, sal, rol, ror, imul, mul, lea, cmp, test} → label
    `arithmetic`. The mnemonic set is the sole criterion (`cmp`/`test`
    qualify via their flags write; `xor rax, rax` is BOTH reg-write and
    arithmetic — multi-label).

R7. **reg-write.** Any non-control instruction that writes a GPR
    (destination register operand) and has no non-stack memory operand →
    label `reg-write`. "GPR" means a general-purpose 8/16/32/64-bit
    register excluding the rsp/esp family and the flags register — writes
    of xmm/ymm/mmx or rflags alone (e.g. `popfq`, `xorps xmm0, xmm0`)
    do NOT earn `reg-write`.

R8. **dispatcher (heuristic).** The gadget's FINAL instruction is a
    register-INDIRECT jump (`jmp qword ptr [reg]`, `jmp qword ptr [reg+off]`,
    x86 dword forms; any non-RIP base register), OR the final instruction
    is `jmp reg` where an earlier instruction in the gadget arithmetically
    modifies that same register (the classic `add rX, 8 ; jmp [rX]`
    loop-step form). → label `dispatcher`.
    This is a documented heuristic, not a proof.

R9. **Multi-label.** A gadget carries the SET of labels from R2-R8
    (e.g. `mov qword ptr [rdi], rax ; ret` = {mem-write};
    `pop rax ; add rbx, rcx ; ret` = {reg-write, arithmetic}).

R10. **Primary class = class of the LAST side-effecting instruction.**
    Scan instructions in order, skip ONLY the final control-transfer
    instruction (ret/jmp/call anchor — mid-gadget control transfers in
    `--multibr` gadgets are labeled normally) and `nop`; the last
    instruction that earns any label determines the primary class.
    syscall/sysenter/int anchors are exempt from the skip (R2: the gate
    is the payload). If one instruction earns several labels,
    precedence: `mem-write` > `mem-read` > `stack-pivot` > `dispatcher`
    > `syscall` > `arithmetic` > `reg-write`.
    Gadgets with no labeled instruction → `other`.

R11. **side_effects** = number of instructions earning at least one
    label (post-R1 normalization). A clean `pop rdi ; ret` has 1.

R12. **quality** (deterministic, documented):
    `quality = max(0, 100 - 15 * (side_effects - 1) - 3 * (n_insns - 2))`
    A 2-instruction single-effect gadget scores 100; each extra
    side-effecting instruction costs 15, each extra instruction costs 3.
    Sorting by quality is descending; ties break by vaddr ascending for
    determinism.

R13. **Confidence.** x86/x64 classification decodes bytes with iced-x86
    and uses `InstructionInfoFactory` register metadata → `high`.
    Other architectures use capstone-mnemonic text heuristics (same
    rules applied to the mnemonic/operand text) → `low_confidence: true`.

## Amendments (v0.3.0)

R1-R13 above are the v0.2 spelling. Four audit findings changed them, and
`rf-classify` and `tests/classify-corpus/` both follow the amended form:

* **`CLS-02`** — R1's implicit-stack-pointer set gains the flags forms
  (`pushf*`, `popf*`). R5 needs an rsp-*targeting* write, so `popfq ; ret` is
  no longer a stack pivot.
* **`CLS-03`** — R8 is redefined. A dispatcher is a register-indirect branch
  whose target register an *earlier arithmetic instruction both read and
  wrote* (`add rdx, 8 ; jmp [rdx]`). A bare `jmp [rax]` is an ordinary JOP
  gadget, not a dispatcher; `call [reg]` now qualifies.
* **`CLS-12`** — R6's set drops `cmp` and `test` (they compute nothing into a
  register) and gains `div`, `idiv`, `xadd`, `xchg`, `bt`/`bts`/`btr`/`btc`,
  `bswap`, `shld`/`shrd`, `rcl`/`rcr`.
* **`CLS-13`** — a `push`'s stack *write* is payload and earns `mem-write`
  (stack *reads* stay R1-exempt), and a terminating `ret imm16` / `retf imm16`
  keeps its stack adjustment and earns `stack-pivot`.

## Labeling + evaluation protocol (the gate)

The v0.2 protocol is withdrawn. It sampled x86-64 only, its "ground truth" was
a second transcription of these rules rather than an independent judgement, and
it *wrote* `tests/fixtures-labeled.jsonl` and `tests/fixtures-eval.json` on
every run so the labeled set could never disagree with the code. It also
claimed hand spot-verification of 35 entries; **no artifact of that
verification ever existed** — no vaddr list, no verifier, no per-entry outcome —
and the claim is withdrawn rather than repaired.

What replaces it:

1. **A frozen, hand-labeled corpus.** `tests/classify-corpus/` — 438 gadgets
   sampled by a documented deterministic rule (every k-th gadget of a depth-10
   scan, k prime, offset 0) from eleven fixtures across eight architectures,
   plus enriched strata drawn by purely textual filters to reach the rare
   classes. Each record carries its ground-truth primary class, its label set,
   the rule ids applied, **a one-line written justification**, and who labeled
   it and when — the artifact the withdrawn claim above lacked.
2. **Read-only, hash-checked.** `crates/rf-classify/tests/eval.rs` verifies
   every corpus file's SHA-256 against `MANIFEST.sha256` before *and* after
   scoring, and asserts the two regenerated files are gone. `cargo test` writes
   nothing into the source tree.
3. **The primary class is scored**, per architecture, per class, alongside the
   label set — plus the confusion pairs, so the mistakes are visible and not
   just their count.
4. **Gate:** x86-64 primary-class macro precision >= 0.90 and dispatcher
   precision >= 0.80. Measured 2026-09-03: x86-64 macro-P **0.9959** (n=195,
   95 % CP lower bound 0.9718); whole-corpus accuracy **0.9474** (n=437).
   PowerPC is **0.6400** and SPARC **0.8000** — the corpus found twelve
   classifier defects, listed in `docs/classifier-eval.md` §4, and the honest
   caveats are in §5.

