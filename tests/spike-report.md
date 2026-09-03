# Phase 4b gadget-inventory spike report

PLAN sec. 6.2 Phase-4-entry spike: can real Windows binaries sustain a
VirtualProtect ROP chain, and which arg-population strategy does each need?

Counts are post-dedup gadgets whose FIRST instruction matches and whose
tail follows the ropmaker clean-tail rule (pops / bare ret only).
System binaries were scanned from local copies (not committed).

| gadget class | cmd.exe x64 6.1.7601 | cmd.exe x86 6.1.7600 | kernel32.dll (this machine) | ntoskrnl.exe (this machine) |
|---|---|---|---|---|
| total gadgets | 12538 | 13711 | 35347 | 627248 |
| `pop rcx` | 1 | 0 | 0 | 3 |
| `pop rdx` | 0 | 0 | 0 | 4 |
| `pop r8` | 0 | 0 | 0 | 3 |
| `pop r9` | 0 | 0 | 0 | 2 |
| `pop rax` | 1 | 0 | 3 | 20 |
| `pop rbx` | 1 | 0 | 2 | 6 |
| `pop rsp` | 6 | 0 | 12 | 22 |
| `pop rsi` | 14 | 0 | 32 | 80 |
| `pop rdi` | 11 | 0 | 33 | 125 |
| `push rcx` | 0 | 0 | 0 | 2 |
| `mov rcx, [reg]` | 0 | 0 | 0 | 0 |
| `push rdx` | 0 | 0 | 1 | 2 |
| `mov rdx, [reg]` | 0 | 0 | 0 | 0 |
| `push r8` | 0 | 0 | 0 | 1 |
| `mov r8, [reg]` | 0 | 0 | 0 | 0 |
| `push r9` | 0 | 0 | 0 | 0 |
| `mov r9, [reg]` | 0 | 0 | 0 | 0 |
| `mov rax, [reg]` | 0 | 0 | 2 | 6 |
| `mov rcx, [rsp+imm]` | 0 | 0 | 0 | 0 |
| `mov rcx, rax` | 0 | 0 | 0 | 0 |
| `mov rdx, [rsp+imm]` | 0 | 0 | 0 | 0 |
| `mov rdx, rax` | 0 | 0 | 0 | 0 |
| `mov r8, [rsp+imm]` | 0 | 0 | 0 | 0 |
| `mov r8, rax` | 0 | 0 | 0 | 0 |
| `mov r9, [rsp+imm]` | 0 | 0 | 0 | 0 |
| `mov r9, rax` | 0 | 0 | 0 | 0 |
| `xchg rsp, reg` | 0 | 0 | 0 | 0 |
| `leave` | 1 | 1 | 1 | 1 |
| `add rsp, imm` | 43 | 0 | 93 | 348 |
| `jmp reg` | 9767 | 8599 | 28485 | 502118 |
| `call reg` | 224 | 1448 | 136 | 7814 |
| `call qword ptr [reg]` | 1 | 0 | 10 | 264 |
| `jmp qword ptr [reg]` | 6 | 0 | 12 | 237 |

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
  `add rsp, imm` pivots (348). This is PLAN sec. 6.2's ring0 target.
  **Retracted (CHWIN-09, v0.1.1):** the gadget inventory above is accurate,
  but this is NOT a success-path demo. The only chain the builder knows how
  to construct calls VirtualProtect, a Win32 usermode API that does not
  exist in kernel address space, so the chain it emits is not a ring0
  primitive.
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
