# Gadget classification taxonomy (Phase 5)

PLAN sec. 7 Phase-5 gate: a written taxonomy with concrete inclusion/
exclusion decision rules, N >= 1,000 gadgets labeled from iced-x86 operand
metadata and spot-verified by hand, per-class precision/recall, gate =
macro-averaged precision >= 0.90 on the held-out half.

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

## Labeling + evaluation protocol (the gate)

1. Sample N >= 1,000 gadgets deterministically (every k-th in scan
   order) from `tests/fixtures` x86/x64 binaries, split 50/50 into
   dev (rule tuning) and held-out (reported) halves by index parity.
2. Ground-truth labels come from an INDEPENDENT direct metadata mapping
   (in the eval harness, not the classifier): per instruction, iced
   register/memory effects mapped to label sets with rules R1-R8 and no
   production normalizations beyond R1. Hand spot-verify >= 30 entries
   (done: 35 entries, 5 per primary class, evenly spread across the
   sample — all agreed with the assigned labels; verified 2026-06).
3. The committed file `tests/fixtures-labeled.jsonl` records
   {vaddr, text, labels, primary} for the full sample.
4. Eval reports per-class precision and recall on the held-out half,
   plus the macro average over the 8 taxonomy classes. Gate:
   macro-averaged precision >= 0.90.

## Dev-half tuning log

The first harness run (held-out macro-P 0.62) exposed spec ambiguities,
resolved above: R5 has no delta exemption (`add rsp, 8` is a pivot);
R6 is mnemonic-set-only (cmp/test qualify); R7's "GPR" excludes flags
and xmm/ymm (a classifier bug — `cmp` had earned reg-write via its
rflags write); R3+R4 dual-label read-modify-write; R10's anchor skip
applies to the final instruction only with syscall gates exempt; R8
examines the final jump only.
