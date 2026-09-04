# Chain regressions — the emulator record

Every row in this file is a chain that was **executed**, not inspected. The
harness is `tests/emulate.py`; it maps the target's segments into unicorn,
lays the generated chain bytes on a synthetic stack, stubs the target API at
its resolved address, single-steps to a bound and asserts the goal was
reached *with the expected arguments*.

This file exists because the previous verification of chain building was 31
assertions over `WordKind` sequences (`crates/rf-chain/src/windows.rs`). Four
independent defects survived all 31, and each one alone kills the chain. A
word-kind assertion cannot distinguish "the words are of the right type" from
"the machine gets there", which is the only claim that matters.

Closes `CHWIN-05`. Records the pre-fix state for `CHWIN-01`, `CHWIN-02`,
`CHWIN-03`, `CHWIN-07`; **section 5** records the runs that closed
`CHWIN-01`, `CHWIN-02`, `CHWIN-04`, `CHWIN-06` and `CHWIN-07`;
**section 6** the five `CHWIN-08` Windows capabilities and **section 7** the
23 `CHLX-07` Linux ones, each of which is advertised only because it appears
here; **section 8** the v0.5.0 integration re-run of all of it.

---

## Running it

```
python tests/emulate.py --binary tests/fixtures/elf-Linux-x64   # one target
python tests/emulate.py --all                                   # every fixture
python tests/emulate.py --regressions                           # the table below
```

`unicorn` is the only extra dependency. The harness re-execs itself into
`.venv-oracle` (the venv `tests/rf_paths.py` already documents) when the
interpreter running it has no unicorn, so plain `python tests/emulate.py`
works. Set `RF_EMULATE_PYTHON` to point somewhere else.

Environment these numbers were measured on:
`win32 python=3.12.10 unicorn=2.1.4 capstone=5.0.7`, release build.

---

## 1. Linux execve — the chains the tree produces today

`python tests/emulate.py --all`:

```
fixture                      verdict    detail
------------------------------------------------------------------------------
elf-Linux-x64                RUNS
elf-Linux-x86                RUNS
elf-Linux-x86-NDH-chall      RUNS
elf-FreeBSD-x86              NO-CHAIN   [Error] can't find a suitable gadget: mov dword ptr [r32], r
elf-x64-bash-v4.1.5.1        NO-CHAIN   [Error] can't find a suitable gadget: mov qword ptr [r64], r
elf-x86-bash-v4.1.5.1        NO-CHAIN   [Error] can't find a suitable gadget: mov dword ptr [r32], r
Linux_lib32.so               NO-CHAIN   [Error] can't find a suitable gadget: pop ecx
Linux_lib64.so               RUNS
------------------------------------------------------------------------------
summary: NO-CHAIN=4, RUNS=4
```

`RUNS` means the emulator reached `SYS_execve` with the right arguments, not
that a chain was printed. In full, for `elf-Linux-x64`:

```
tests/fixtures/elf-Linux-x64: RUNS
    goal=linux-execve steps=140 ok=True
      [PASS] reached the execve syscall
      [PASS] syscall number is execve - got 59, want 59
      [PASS] arg1 points at "/bin//sh" - [0x6bc080] = b'/bin//sh'
      [PASS] argv is NULL or a readable NULL-terminated vector - 0x6bc088 -> 0x0
      [PASS] envp is NULL or a readable NULL-terminated vector - 0x6bc088 -> 0x0
```

and for `elf-Linux-x86` (the `int 0x80` path, `__NR_execve` = 11):

```
tests/fixtures/elf-Linux-x86: RUNS
    goal=linux-execve steps=50 ok=True
      [PASS] reached the execve syscall
      [PASS] syscall number is execve - got 11, want 11
      [PASS] arg1 points at "/bin//sh" - [0x80f4060] = b'/bin//sh'
      [PASS] argv is NULL or a readable NULL-terminated vector - 0x80f4068 -> 0x0
      [PASS] envp is NULL or a readable NULL-terminated vector - 0x80f4068 -> 0x0
```

The four `NO-CHAIN` fixtures are the ones `CHLX-01` names — the binaries where
ropper, angrop and pwntools all succeed. When that workstream lands they must
turn `RUNS`, not merely stop erroring.

---

## 2. Windows — the four seeded regressions

> **This section is the PRE-FIX record and is kept verbatim.** The runs that
> replaced it — and the current contents of `WIN_REGRESSIONS` — are in
> [section 5](#5-the-windows-fixes-and-the-runs-that-gate-them).

`python tests/emulate.py --regressions`.

### Why these run against a synthetic PE

The shipped fixture cannot reach the builder's argument-population stage at
all. Measured on `tests/fixtures/pe-x64-cmd-v6.1.7601`:

```
[Error] can't find a suitable gadget: cannot populate rdx: no 'pop rdx' gadget
and no 'pop rax' + 'mov rdx, rax' fallback
```

No chain is emitted, so nothing can be executed, so `CHWIN-01`, `CHWIN-02` and
`CHWIN-07` cannot be reproduced end to end on it. "Cannot reproduce" is not
"already fixed". `tests/emulate.py` therefore builds a minimal PE32+ per case
(`write_synthetic_pe`) carrying exactly the gadget set that isolates that
defect, and drives the **real CLI** over it — same trick the existing
`windows.rs` unit tests use, except the chain then gets executed.

Gadget order inside those PEs is load-bearing and the code says why:
`find_exact` scans the alphabetically sorted gadget list reversed, and
REX-prefixed pops sub-decode into shorter ones (`41 58 c3` contains
`pop rax ; ret` at +1).

### The table

`expected` is what the harness asserts today. A run that does not match — in
**either** direction — fails. When a fix lands, update the `expect` field in
`WIN_REGRESSIONS` (tests/emulate.py) and the `post-fix` column here **in the
same commit**; a fix with no recorded failing-before run does not count.

| id | key assertion | pre-fix state | post-fix |
|---|---|---|---|
| `CHWIN-01` | no control transfer to the padding constant | **REFUSED** at generation (see below) | **PASS** (section 5.3) |
| `CHWIN-02` | shellcode's first 4 bytes are intact | **FAIL** — `90909090 -> 04000000 (VirtualProtect wrote through lpflOldProtect)` | **PASS** (section 5.4) |
| `CHWIN-03` | the IAT deref read the IAT slot, not the hint/name record | **PASS** — `read the FirstThunk slot at 0x140002038` | root-fixed in v0.3.0 |
| `CHWIN-07` | `lpAddress == <shellcode>` at the API call | **FAIL** — `got 0x4141414141414141` | **PASS** (section 5.5) |
| `CHWIN-02-x86` | shellcode's first 4 bytes are intact, **on the shipped `pe-x86-cmd-v6.1.7600`** | **FAIL** — `90909090 -> 04000000` | **PASS** (section 5.4) |

Summary line as it read then, exit 0 (superseded by section 5.2):

```
summary: CHWIN-01=REFUSED, CHWIN-02=FAIL, CHWIN-03=PASS, CHWIN-07=FAIL, CHWIN-02-x86=FAIL
         (5/5 match the recorded state)
```

`CHWIN-02-x86` is not a synthetic case. The x86 stdcall builder needs no
register gadgets at all — every argument is a stack word — so
`pe-x86-cmd-v6.1.7600` *does* produce a chain, and `build_win32(b, opts,
data.vaddr, shellcode)` passes the same writable-section vaddr for both the
shellcode home and `&lpflOldProtect`. So `CHWIN-02` is reproducible end to end
on a binary the project ships, and it is not an x64-only defect. Whoever fixes
`CHWIN-02` must fix `build_win32` as well as `win64_args`.

`REFUSED` deserves its own note. CHWIN-01's chain was **emitted and executed**
when this harness was first run, on the v0.4.0 tree before `CHLX-04`'s static
verifier — the other half of this same workstream — was wired into
`RopChain::validate_with`. Measured then:

```
    goal=windows-virtualprotect steps=10 ok=False
      [FAIL] no control transfer to the padding constant - a `ret` targeted 0x4141414141414141
      [FAIL] the API stub was entered - Invalid memory fetch (UC_ERR_FETCH_UNMAPPED),
             pc=0x4141414141414141, fault at 0x1414141414141,
             last ret target 0x4141414141414141, 10 steps
      [FAIL] control reached the shellcode - (same)
```

Ten instructions in, before VirtualProtect is entered, on a word the emitted
script labels `# stack alignment word (rsp % 16 == 8 at api entry)`. With the
static verifier in place the CLI no longer prints that chain at all:

```
[Error] chain word 9 (0x4141414141414141, Padding): static stack accounting
(CHLX-04): control transfers here — the preceding `ret` loads this word into
rip — but it is a Padding word, not a gadget or code address. ...
```

`REFUSED` is the stronger pre-fix state, not a weaker one: the user is no
longer handed a chain that dies. The harness only accepts it as CHWIN-01's
recorded state when the refusal text actually names the defect
(`refusal_must_contain`), so an unrelated refusal still fails the case. When
`align_for_transfer` is fixed the way the message prescribes, this row must
become **PASS** — a chain that is emitted, executed, and reaches intact
shellcode. `REFUSED` after the fix means the fix did not work.

`CHWIN-03` is the control. It is the one of the four that was already fixed,
and it passes — which is how you know the other three are failing on their own
defect and not on a broken harness.

### The runs, in full

**CHWIN-01** — the alignment pad is an inert data word the preceding gadget's
`ret` jumps to. Gadget set: `pop r8 ; ret`, `pop rdx ; ret`, `pop rcx ; ret`,
`pop r9 ; pop rbx ; ret` (the double pop makes the pre-transfer word count odd,
so `align_for_transfer` fires), `--api-addr 0x7fff12340000`. Both observed
states — the executed chain and the refusal that replaced it — are quoted in
the table note above.

**CHWIN-02** — `lpflOldProtect` defaults to the shellcode address. Gadget set:
all four `pop` forms, `--api-addr 0x7fff12340000`. The harness plants
`90 90 90 90` at the shellcode address, stubs VirtualProtect faithfully (change
protection, **then write the previous protection DWORD through lpflOldProtect**,
return TRUE), and reads the four bytes back when control arrives:

```
    goal=windows-virtualprotect steps=11 ok=False
      [PASS] no control transfer to the padding constant
      [PASS] the API stub was entered
      [PASS] lpAddress == 0x140003000 - got 0x140003000
      [PASS] dwSize == 0x1000 - got 0x1000
      [PASS] flNewProtect == 0x40 - got 0x40
      [PASS] lpflOldProtect points at writable memory - 0x140003000
      [FAIL] lpflOldProtect does not alias the shellcode - 0x140003000 is inside the shellcode's first DWORD
      [PASS] control reached the shellcode
      [FAIL] shellcode's first 4 bytes are intact - 90909090 -> 04000000 (VirtualProtect wrote through lpflOldProtect)
```

Every argument is correct. Control arrives at the shellcode. The first
instruction executed is assembled from `04 00 00 00`. This is the row the
harness exists for: **no assertion over word kinds can express it**, because
nothing about the *words* is wrong — the damage is done by the API's own
out-parameter write to an address that is correct in type and wrong in value.

**CHWIN-03** — the IAT dereference. Gadget set includes
`mov rax, qword ptr [rax] ; pop rbx ; ret` and `jmp rax`; no `--api-addr`, so
the chain must resolve through the import. The harness patches **only** the
FirstThunk slot with the stub address, exactly as the Windows loader does, and
leaves the `IMAGE_IMPORT_BY_NAME` record holding `00 00 "VirtualProtect\0"`.
A read hook on each cell answers which one the chain dereferenced:

```
      [PASS] the IAT deref read the IAT slot, not the hint/name record - read the FirstThunk slot at 0x140002038
      [PASS] the API stub was entered
```

Pre-v0.3.0 this chain read the hint/name record, loaded eight bytes of ASCII
and `jmp rax`'d to a non-canonical address.

**CHWIN-07** — extra pops in the IAT gadgets destroy argument registers
populated earlier. The gadget set gives the IAT path only
`pop rax ; pop rcx ; ret`, which is legal under `clean_tail` and common in real
PEs. `emit_api_call64` calls `b.padding(pop_rax, &[])` with a literal empty
already-set list, so the `pop rcx` gets the `0x4141…` constant instead of the
`lpAddress` value set eight words earlier:

```
    goal=windows-virtualprotect steps=18 ok=False
      [PASS] no control transfer to the padding constant
      [PASS] the IAT deref read the IAT slot, not the hint/name record
      [PASS] the API stub was entered
      [FAIL] lpAddress == 0x140003000 - got 0x4141414141414141
      [PASS] dwSize == 0x1000 - got 0x1000
      [PASS] flNewProtect == 0x40 - got 0x40
      [FAIL] control reached the shellcode - Fetch from non-executable memory (UC_ERR_FETCH_PROT), pc=0x140003000
```

Note the follow-on: because `lpAddress` was garbage, VirtualProtect never made
the shellcode executable, and the return into it faults. That is exactly the
failure mode `CHWIN-07` predicts — "VirtualProtect returns FALSE, nothing is
made executable, and the chain returns to non-executable shellcode" — observed
rather than argued.

**CHWIN-02-x86** — the same aliasing, x86 stdcall, real fixture:

```
tests/fixtures/pe-x86-cmd-v6.1.7600: BROKEN
    goal=windows-virtualprotect steps=3 ok=False
      [PASS] no control transfer to the padding constant
      [PASS] the API stub was entered
      [PASS] lpAddress == 0x4ad24000 - got 0x4ad24000
      [PASS] dwSize == 0x1000 - got 0x1000
      [PASS] flNewProtect == 0x40 - got 0x40
      [PASS] lpflOldProtect points at writable memory - 0x4ad24000
      [FAIL] lpflOldProtect does not alias the shellcode - 0x4ad24000 is inside the shellcode's first DWORD
      [PASS] control reached the shellcode
      [FAIL] shellcode's first 4 bytes are intact - 90909090 -> 04000000 (VirtualProtect wrote through lpflOldProtect)
```

Three instructions: the stdcall frame is the whole chain. The stub reads its
four arguments off the stack, applies the protection change, writes the old
protection through `lpflOldProtect`, and its `ret 0x10` lands on the shellcode
— whose entry point is now `04 00 00 00`.

The gadget set for CHWIN-07 deliberately omits `pop r8 ; ret`: its encoding
`41 58 c3` sub-decodes to a plain `pop rax ; ret`, which would outrank
`pop rax ; pop rcx ; ret` in the reversed alphabetical scan and leave the case
with no extra pop to demonstrate. The `pop rbx` tails also keep the
pre-transfer word count even so `align_for_transfer` does not fire and
`CHWIN-01` cannot mask this case.

---

## 3. The static verifier, and the cargo tests it turns red

`CHLX-04` adds `RopChain::verify_stack_accounting` and wires it into
`RopChain::validate_with`, so **generation refuses** rather than printing a
chain that cannot run. It walks the chain the way the machine will: the
pivot's `ret` loads word 0; a gadget consumes one word per `pop` and its
terminator decides what happens next; a `CodeAddr` or a non-`ret` terminator
hands control to something the chain does not describe, and everything from
there is reported as the callee's frame rather than guessed at.

`cargo test -p rf-chain` before this workstream: `35 passed; 0 failed`.
After: `35 passed; 6 failed` — six new verifier tests pass, and six existing
`windows.rs` tests fail **all on the same defect**. That is the intended
forcing function for the `CHWIN-01` workstream. `cargo test -p rf-cli`
(117 passed) and `cargo test -p rf-mcp` (234 passed) stay green, so the blast
radius is exactly these six:

```
windows::tests::win64_alignment_autopad_fires
windows::tests::win64_iat_resolution_path
windows::tests::win64_iat_word_is_the_slot_not_the_hint_name_record
windows::tests::win64_mov_fallback_chain_uses_rax_route
windows::tests::iat_dll_name_cannot_inject_python
windows::tests::every_generated_chain_script_is_flat_python
```

Each fails with:

```
InvalidWord { index: 9, value: 4702111234474983745, kind: Padding, reason:
  "static stack accounting (CHLX-04): control transfers here — the preceding
   `ret` loads this word into rip — but it is a Padding word, not a gadget or
   code address. In a ret-chain there is no filler the machine skips over: a
   stack alignment pad must be the ADDRESS OF A BARE `ret` GADGET, which
   consumes itself and advances rsp by one word (CHWIN-01)" }
```

All six are the `align_for_transfer` inert pad. They go green the moment
`CHWIN-01` is fixed the way the message prescribes — by making the pad the
address of a bare `ret` gadget, which consumes itself. **Do not** relax the
verifier to make them pass.

The verifier's own tests live in `crates/rf-chain/src/lib.rs`:
`padding_gap_is_refused_not_warned` (splice a padding word in front of a
control word — the CHWIN-01 shape — and assert a refusal),
`missing_padding_word_is_refused` (delete one and the chain runs a word out of
phase), `pops_past_the_end_are_refused`, `callee_frame_is_reported_not_guessed`,
`ret_imm_discards_its_operands` and `unmodelled_stack_effect_stops_the_walk`.

---

## 4. `--badbytes` parity (`CHLX-09`)

`tests/chain_parity.py` used to run one flag set. It now runs seven over the
same eight fixtures — 56 pairs — and adds two assertions the old harness could
not make:

* **`BADBYTE-LEAK` is always fatal.** Every `pack('<Q'…)` word and every
  `p += b'…'` literal of every chain rop-finder emits is checked against the
  bad-byte set. This holds today and must hold after `CHLX-03` replaces the
  hard failure with an alternative-address search.
* **Every (flag set, fixture) verdict is recorded** in `EXPECTED`, so a
  regression that starts refusing a case the oracle handles is no longer
  indistinguishable from the intended divergence.

Measured today: `BYTE-IDENTICAL=14, ERROR-PARITY=32, OURS-REFUSED=3,
PAYLOAD-IDENTICAL=7`, exit 0.

The three `OURS-REFUSED` rows are the documented divergence, and the harness
now says *why* it is real rather than cosmetic:

```
badbytes-0f  elf-Linux-x86    OURS-REFUSED  oracle emitted 6 word(s) containing a bad byte
badbytes-60  elf-Linux-x86    OURS-REFUSED  oracle emitted 2 word(s) containing a bad byte
badbytes-41  Linux_lib64.so   OURS-REFUSED  oracle emitted 10 word(s) containing a bad byte
```

`0x0f` and `0x60` are bytes of `elf-Linux-x86`'s `.data` base (`0x080f4060`),
so they land on the data word rather than any gadget address; `0x41` is the
padding constant itself. ROPgadget filters gadget addresses only and ships the
chain anyway.

`OURS-REFUSED -> a real chain` is the one verdict change that is not a
regression — it is what `CHLX-03` is meant to produce. That direction prints
`IMPROVED` and asks for `--record`; it does not fail the build. Every other
change does.

---

## 5. The Windows fixes, and the runs that gate them

This section is the other half of section 2. Everything above records the
**pre-fix** state; everything here is the run that replaced it. The rule the
table states is unchanged: a fix with no recorded failing-before run does not
count, and a verdict that moves in **either** direction without the record
moving with it fails the build.

Closes `CHWIN-01`, `CHWIN-02`, `CHWIN-04`, `CHWIN-06`, `CHWIN-07`.

### 5.1 The transition run — the same harness, the same table, the new code

`python tests/emulate.py --regressions`, run against the fixed builder while
`WIN_REGRESSIONS` still held the pre-fix expectations. This is the
failing-before/passing-after in one document: the `expected` line is the
pre-fix state section 2 recorded, the `observed` line is the fixed builder.

```
CHWIN-01  alignment pad is an inert word the previous `ret` jumps to
    key assertion : no control transfer to the padding constant
    expected      : REFUSED   (docs/chain-regressions.md)
    observed      : PASS
    -> DIVERGES FROM THE RECORD

CHWIN-02  lpflOldProtect aliases the shellcode; VirtualProtect overwrites the first 4 bytes ...
    key assertion : shellcode's first 4 bytes are intact
    expected      : FAIL   (docs/chain-regressions.md)
    observed      : PASS   90909090 -> 90909090
    -> DIVERGES FROM THE RECORD

CHWIN-07  extra pops in the IAT gadgets destroy argument registers populated earlier
    key assertion : lpAddress ==
    expected      : FAIL   (docs/chain-regressions.md)
    observed      : PASS   got 0x140003000
    -> DIVERGES FROM THE RECORD

CHWIN-02-x86  same aliasing on the x86 stdcall builder, on the shipped pe-x86-cmd fixture
    key assertion : shellcode's first 4 bytes are intact
    expected      : FAIL   (docs/chain-regressions.md)
    observed      : PASS   90909090 -> 90909090
    -> DIVERGES FROM THE RECORD

------------------------------------------------------------------------------
summary: CHWIN-01=PASS, CHWIN-02=PASS, CHWIN-03=PASS, CHWIN-07=PASS, CHWIN-02-x86=PASS
         (1/5 match the recorded state)
```

Exit 1, as designed: four fixes that had not yet been recorded. `CHWIN-03` is
still the control — it was already fixed in v0.3.0 and it did not move.

### 5.2 The recorded state now

`WIN_REGRESSIONS` and the table below were updated in the same change, and the
harness agrees:

```
summary: CHWIN-01=PASS, CHWIN-02=PASS, CHWIN-03=PASS, CHWIN-07=PASS,
         CHWIN-02-x86=PASS, CHWIN-04=PASS, CHWIN-06-before=REFUSED, CHWIN-06=PASS
         (8/8 match the recorded state)
```

exit 0.

| id | key assertion | pre-fix state | post-fix |
|---|---|---|---|
| `CHWIN-01` | no control transfer to the padding constant | **REFUSED** at generation (section 2) | **PASS** — emitted, executed, intact shellcode |
| `CHWIN-02` | shellcode's first 4 bytes are intact | **FAIL** — `90909090 -> 04000000` | **PASS** — `90909090 -> 90909090` |
| `CHWIN-03` | the IAT deref read the IAT slot, not the hint/name record | **PASS** (the control) | **PASS**, unchanged |
| `CHWIN-07` | `lpAddress == <shellcode>` at the API call | **FAIL** — `got 0x4141414141414141` | **PASS** — `got 0x140003000` |
| `CHWIN-02-x86` | shellcode's first 4 bytes are intact, on the shipped `pe-x86-cmd-v6.1.7600` | **FAIL** — `90909090 -> 04000000` | **PASS** — `90909090 -> 90909090` |
| `CHWIN-04` | control reached the shellcode, with `--chain-base aligned` | the flag did not exist | **PASS** |
| `CHWIN-06-before` | the IAT deref read the IAT slot | *is* the pre-fix state, kept as a live row | **REFUSED**, and must stay refused |
| `CHWIN-06` | the IAT deref read the IAT slot, `--api-name VirtualAlloc` | unreachable — the name was hardcoded | **PASS** |

### 5.3 CHWIN-01 — the alignment slide is a gadget now, not a constant

The pad is the address of a **bare `ret` gadget**, which loads itself into rip
and advances rsp by one word. That is the only one-word construction with the
right effect, because the preceding argument gadget's `ret` *jumps to* whatever
word it is handed — `clean_tail` guarantees that gadget ends in a bare `ret`,
and `ChainBuilder::padding` already emits exactly one word per tail `pop`, so
there is never a spare word for the machine to step over.

Visible in the emitted script, on `tests/spike-binaries/ntoskrnl.exe`:

```
$ rop-finder --binary tests/spike-binaries/ntoskrnl.exe --ropchain \
      --chain windows-virtualprotect --api-addr 0x7fff12340000
#!/usr/bin/env python3
# VirtualProtect chain (rop-finder); chain base: return_address
...
p += pack('<Q', 0x00000001406c1a23) # pop r9 ; ret
p += pack('<Q', 0x0000000140fc5000) # arg4 lpflOldProtect (writable scratch, NOT the shellcode)
p += pack('<Q', 0x000000014020043b) # ret
p += pack('<Q', 0x00007fff12340000) # VirtualProtect @ 0x7fff12340000 (--api-addr)
p += pack('<Q', 0x0000000140e00000) # return address: shellcode (second-stack frame)
```

`0x14020043b` is a real gadget in ntoskrnl's own `.text`, not a data word. The
line it replaced read
`p += pack('<Q', 0x4141414141414141) # stack alignment word (rsp % 16 == 8 at api entry)`.

When the binary has no bare `ret` gadget there is no legal slide, and the
builder says so instead of reaching for a constant:

```
[Error] can't find a suitable gadget: stack alignment (chain base return_address):
the transfer word must land at an odd index and needs a one-word slide, which
must be a bare `ret` GADGET that consumes itself — an inert padding word is what
the preceding gadget's `ret` would jump to (CHWIN-01). No bare `ret` gadget in
this binary
```

(Measured: both shipped cmd.exe fixtures report exactly one bare `ret` gadget
at `--depth 3`, so this refusal is a real edge case, not the common path.)

### 5.4 CHWIN-02 — the out-parameter is a distinct writable DWORD

`&lpflOldProtect` is chosen so it cannot alias the shellcode:

1. a writable section the protected region does not cover — what
   `ntoskrnl.exe` gets above (`0x140fc5000` against a shellcode at
   `0x140e00000`), and what any image with a second writable section or a
   relocated `--shellcode-addr` gets;
2. otherwise the **last word of the region the call itself makes writable**.
   It is the only address the builder can prove is writable without knowing
   section sizes (`DataSection` does not carry one): the caller has already
   asserted `[shellcode, shellcode+dwSize)` is a valid region by passing it as
   `dwSize`, and it is the furthest point in that region from the entry.

Rule 2 is what the single-writable-section fixtures take:
`pe-x86-cmd-v6.1.7600` puts the shellcode at `.data` = `0x4ad24000` and the
scratch at `0x4ad24ffc`; the x64 synthetic PEs put it at `0x140003ff8` against
a shellcode at `0x140003000`. A `--shellcode-size 0` cannot collapse the two:
the "is this section inside the region?" test guards at least one word.

The emulator, on the shipped x86 fixture — the same nine assertions section 2
ran, with the two that failed now passing:

```
tests/fixtures/pe-x86-cmd-v6.1.7600
    goal=windows-virtualprotect steps=3 ok=True
      [PASS] no control transfer to the padding constant
      [PASS] the API stub was entered
      [PASS] lpAddress == 0x4ad24000 - got 0x4ad24000
      [PASS] dwSize == 0x1000 - got 0x1000
      [PASS] flNewProtect == 0x40 - got 0x40
      [PASS] lpflOldProtect points at writable memory - 0x4ad24ffc
      [PASS] lpflOldProtect does not alias the shellcode - 0x4ad24ffc vs shellcode 0x4ad24000
      [PASS] control reached the shellcode
      [PASS] shellcode's first 4 bytes are intact - 90909090 -> 90909090
```

### 5.5 CHWIN-07 — the already-set list reaches the IAT gadgets

`emit_api_call64` now threads the populated argument registers into
`ChainBuilder::padding`, which already knew how to re-supply a live value and
had simply never been told what was live. The case's gadget set gives the IAT
path only `pop rax ; pop rcx ; ret`:

```
CHWIN-07
    goal=windows-virtualprotect steps=20 ok=True
      [PASS] no control transfer to the padding constant
      [PASS] the IAT deref read the IAT slot, not the hint/name record
      [PASS] the API stub was entered
      [PASS] lpAddress == 0x140003000 - got 0x140003000
      [PASS] dwSize == 0x1000 - got 0x1000
      [PASS] flNewProtect == 0x40 - got 0x40
      [PASS] lpflOldProtect points at writable memory - 0x140003ff8
      [PASS] lpflOldProtect does not alias the shellcode
      [PASS] control reached the shellcode
      [PASS] shellcode's first 4 bytes are intact - 90909090 -> 90909090
```

`lpAddress` was `0x4141414141414141` before. Note the follow-on the pre-fix run
predicted and showed — `control reached the shellcode` used to fault, because a
garbage `lpAddress` meant VirtualProtect never made the buffer executable — is
gone with it.

The same family, closed in the same edit: a `pop rax` in the tail of the
`pop rax` or the deref gadget would overwrite the *resolved API address*
between the dereference and the `jmp rax`. `clean_tail` permits such a gadget,
so it is now rejected by name rather than selected and hoped for
(`win64_iat_gadget_that_pops_rax_is_refused`).

### 5.6 CHWIN-04 — the chain base is a declared parameter

`--chain-base aligned|return-address` (MCP: `chain_base`), default
`return_address`. The arithmetic it parameterises: with the chain's first word
at address `S`, word `i` sits at `S + 8*i`, the `ret` into the API consumes
word `j`, so `rsp = S + 8*(j+1)` at entry and the Win64 ABI wants
`rsp % 16 == 8`.

| chain base | `S mod 16` | transfer word index | delivery |
|---|---|---|---|
| `aligned` | 0 | even | a pivot into a controlled, 16-aligned buffer |
| `return_address` (default) | 8 | odd | an overwritten saved return address — the common case |

The pre-fix builder hardcoded `S ≡ 0` and called it "the standard exploit
precondition" (`windows.rs:28`), which inverts the commonest delivery: the ABI
puts `rsp % 16 == 0` immediately before a `call`, so the pushed return address
— the first word the attacker controls — is at an address `≡ 8 (mod 16)`.
The pre-fix state of this finding is a fact about the surface, not an
emulation: there was no `--chain-base` flag and no `chain_base` MCP parameter
(AUDIT-FINDINGS CHWIN-04, "There is no `--chain-base` / alignment flag in the
CLI or MCP schema").

Same binary, same gadgets, the two bases, showing the layout actually moves:

```
$ ... --api-addr 0x7fff12340000                          $ ... --chain-base aligned
# VirtualProtect chain (rop-finder); chain base: return_address   ...; chain base: aligned
p += pack('<Q', 0x00000001406c1a23) # pop r9 ; ret        p += pack('<Q', 0x00000001406c1a23) # pop r9 ; ret
p += pack('<Q', 0x0000000140fc5000) # arg4 lpflOldPro...  p += pack('<Q', 0x0000000140fc5000) # arg4 lpflOldPro...
p += pack('<Q', 0x000000014020043b) # ret                 p += pack('<Q', 0x00007fff12340000) # VirtualProtect @ ...
p += pack('<Q', 0x00007fff12340000) # VirtualProtect @ ...
```

and under the emulator, `CHWIN-04` (aligned, no slide) runs in **11 steps**
against `CHWIN-02`'s **12** (default, one slide), both `ok=True`.

The assumption is echoed where it will be read. In the script's preamble
(`# VirtualProtect chain (rop-finder); chain base: return_address` — kept
inside `PY_COMMENT_MAX`, the 64 characters `py_comment` allows), in the IR's
`description`, and machine-readably in a new `assumptions` object that both
front ends emit — `rop-finder --ropchain --json` and the MCP's
`build_rop_chain`, spelled identically, `null` for a Linux chain, which makes
none of these assumptions:

```json
"assumptions": {
  "api_name": "VirtualProtect",
  "chain_base_mod16": 8,
  "chain_base_parity": "return_address",
  "old_protect_addr": "0x4ad24ffc",
  "shellcode_addr": "0x4ad24000"
}
```

`old_protect_addr` next to `shellcode_addr` is deliberate: CHWIN-02 was two
addresses that were silently one, so the artefact now shows both.

### 5.7 CHWIN-06 — the API name is a parameter, and so is its recipe

`WinChainOpts::api_name` existed and was written from nowhere. Verified against
the import tables of the fixtures this project ships, with the tool's own
`--info`:

```
pe-x64-cmd-v6.1.7601  KERNEL32.dll VirtualAlloc  iat 0x4ad293f8
                      KERNEL32.dll VirtualFree   iat 0x4ad29400
                      KERNEL32.dll VirtualQuery  iat 0x4ad29508
pe-x86-cmd-v6.1.7600  KERNEL32.dll VirtualAlloc  iat 0x4ad01204
                      KERNEL32.dll VirtualFree   iat 0x4ad01208
                      KERNEL32.dll VirtualQuery  iat 0x4ad0129c
```

Neither imports `VirtualProtect`. The audit's claim is confirmed: the IAT
resolution path — the only ASLR-friendly one — could not be reached on any PE
in the repository.

`CHWIN-06-before` is that state, kept as a live row rather than a memory. It
builds a PE importing `VirtualAlloc` and drives the builder **without**
`--api-name`, which is exactly what the old code did unconditionally:

```
CHWIN-06-before
    expected      : REFUSED
    observed      : REFUSED   [Error] can't find a suitable gadget: no --api-addr given
                    and the PE does not import VirtualProtect (IAT resolution unavailable);
                    supply --api-addr <runtime address>, or --api-name <an API this PE does import>
```

`CHWIN-06` is the same PE and the same gadgets with `--api-name VirtualAlloc`:

```
CHWIN-06
    goal=windows-virtualprotect steps=18 ok=True
      [PASS] no control transfer to the padding constant
      [PASS] the IAT deref read the IAT slot, not the hint/name record - read the FirstThunk slot at 0x140002038
      [PASS] the API stub was entered
      [PASS] lpAddress == 0x140003000 - got 0x140003000
      [PASS] dwSize == 0x1000 - got 0x1000
      [PASS] flAllocationType == 0x1000 - got 0x1000
      [PASS] flProtect == 0x40 - got 0x40
      [PASS] control reached the shellcode
      [PASS] shellcode's first 4 bytes are intact - 90909090 -> 90909090
```

**Same argument count is not same arguments.** The module header used to claim
"VirtualAlloc works too — same arg count", which is wrong as exploitation:
VirtualAlloc's third and fourth arguments are `flAllocationType` and
`flProtect`, so handing it VirtualProtect's `(flNewProtect, &lpflOldProtect)`
commits nothing and writes nowhere. `--api-name` therefore selects a *recipe*,
not just a symbol:

| | arg1 | arg2 | arg3 | arg4 |
|---|---|---|---|---|
| `VirtualProtect` | lpAddress | dwSize | flNewProtect | `&lpflOldProtect` |
| `VirtualAlloc` | lpAddress | dwSize | `MEM_COMMIT` (0x1000) | flProtect |

VirtualAlloc with `MEM_COMMIT` on an already-committed page is the DEP-bypass
form that changes protection with no out-parameter — which is also why
CHWIN-02 has nothing to alias there and `assumptions.old_protect_addr` is
`null`. An API name outside this set is refused rather than guessed at, on both
front ends, with the accepted set in the message. `tests/emulate.py`'s stub and
judge model both recipes for the same reason: a stub that pretended
VirtualAlloc's third argument were a protection constant would report a correct
chain as broken.

`--prot` (default `0x40`, `PAGE_EXECUTE_READWRITE`) sets `flNewProtect` /
`flProtect` for either recipe, and the constant is named in the word comment
(`arg3 flNewProtect PAGE_EXECUTE_READ` for `--prot 0x20`).

**What `--api-name` does not by itself unblock.** On the two shipped cmd.exe
fixtures the IAT path is now *addressable* but still not *reachable*, for
reasons that are other findings:

```
$ rop-finder --binary tests/fixtures/pe-x64-cmd-v6.1.7601 --ropchain       --chain windows-virtualprotect --api-name VirtualAlloc
[Error] can't find a suitable gadget: cannot populate rdx: no 'pop rdx' gadget
and no 'pop rax' + 'mov rdx, rax' fallback (see tests/spike-report.md ...)

$ rop-finder --binary tests/fixtures/pe-x86-cmd-v6.1.7600 --ropchain       --chain windows-virtualprotect --api-name VirtualAlloc
[Error] can't find a suitable gadget: x86 requires --api-addr <runtime address
of VirtualAlloc> (x86 IAT dereference not implemented)
```

The x64 fixture stops at argument population (the spike's scarcity finding —
CHLX-01's Windows analogue, and CHWIN-08's stack-pivot/synthesis work), and
the x86 builder has no IAT path at all (CHWIN-08 item 4). Neither is
`api_name` being unset, which is what CHWIN-06 is; the `CHWIN-06` /
`CHWIN-06-before` pair isolates that variable on a PE that can reach the
resolution stage.

### 5.8 The cargo tests, and the six that section 3 turned red

Section 3 recorded `cargo test -p rf-chain` at `35 passed; 6 failed`, all six
on `align_for_transfer`'s inert pad, and said they would go green the moment
CHWIN-01 was fixed the way the verifier's message prescribes. They did — with
`align_for_transfer` emitting a bare `ret` gadget, and with **no change to the
verifier**:

```
windows::tests::win64_alignment_autopad_fires                          (rewritten, green)
windows::tests::win64_iat_resolution_path                              green
windows::tests::win64_iat_word_is_the_slot_not_the_hint_name_record    green
windows::tests::win64_mov_fallback_chain_uses_rax_route                green
windows::tests::iat_dll_name_cannot_inject_python                      green
windows::tests::every_generated_chain_script_is_flat_python            green
```

`cargo test -p rf-chain --lib windows::` — **28 passed; 0 failed**, 14 of them
new in this change. (The whole-lib figure moves under you while the
Linux-chain workstream lands in the same file tree; it read `71 passed;
0 failed` when this was written.)
`cargo test -p rf-cli` **86 passed; 0 failed** in the lib plus 35 across its
three integration binaries (`cli_contract` 6, `query` 19, `refusals` 10); `cargo test -p rf-mcp` green across every one of its test
binaries, including a new `windows_chain_parameters_and_assumptions` that asserts every
one of these behaviours against the **server**, not the library.

`cargo fmt --all --check` clean, `cargo clippy -p rf-chain -p rf-cli -p rf-mcp
--all-targets -- -D warnings` clean.

`python tests/capability_matrix.py`: **PASS**, now `40 paired capabilities, 45
declared asymmetries, 2 vocabularies and 43 answers compared` — the three new
parameters are declared pairs (`--api-name`/`api_name`,
`--chain-base`/`chain_base`, `--prot`/`prot`), and both surfaces validate them
through the same function, `rf_cli::win_opts`, so their accepted value sets
cannot drift apart. `python tests/doc_claims.py`: **PASS**, 12 claims
checked, 0 failed (1 pre-existing warning, about the speedup table).

---

## 6. CHWIN-08 — the five Windows capabilities, each EXECUTED

`CHWIN-08` added capabilities rather than fixing defects, so there is no
"failing before" run to record for them: the thing being recorded is the
**gating rule**, which is that a capability is not advertised — not in
`--help`, not in the MCP tool description, not in the MANUAL — until it has
executed here. Five did.

Run: `python tests/emulate.py --regressions`, section *CHWIN-08 Windows
capabilities*. The recorded verdicts live in `WIN08_REGRESSIONS`'s `expect`
field in `tests/emulate.py` — that is what fails the build on a change, and
this table is its human-readable half.

| id | what is executed | key assertion | verdict |
|---|---|---|---|
| `CHWIN-08-pivot` | stack pivot: the chain is two pieces and the body runs at `--chain-pivot` | control reached the shellcode after the pivot | **PASS** |
| `CHWIN-08-pivot-parity` | a pivot target that is 4 mod 16 cannot satisfy the Win64 entry invariant | the builder refuses **by name** rather than emitting it | **REFUSED** |
| `CHWIN-08-staging` | `--stage`: the chain WRITES the shellcode with write-what-where gadgets | region pre-filled `0xCC`, then `want 90909090, got 90909090` | **PASS** |
| `CHWIN-08-exports` | export-table resolution: the PE exports the API, no `--api-addr` given | the harness stubs the *exported* address, so only a chain that read the export directory transfers there | **PASS** |
| `CHWIN-08-multicall` | `--api-name A,B`: VirtualAlloc then VirtualProtect, the first returning into the chain | `entered ['VirtualAlloc', 'VirtualProtect']`, in order, through a stack-adjust gadget with no absolute chain address anywhere | **PASS** |

```
summary: 5 of 5 match the recorded verdict
```

`CHWIN-08-pivot-parity` is worth reading twice. A refusal is a recorded
verdict here, not the absence of one: the alternative to refusing is emitting
a chain whose `rsp` is 4 mod 16 at the API entry, which the Win64 ABI forbids
and which would die inside the callee rather than anywhere this harness could
attribute.

**Not gated, and stated as such.** The x86 IAT dereference (`CHWIN-08` item 4)
is implemented and unit-tested but is **not** in this table. It could not be
executed on `pe-x86-cmd-v6.1.7600`: measured, that fixture has zero
clean-tailed `pop eax ; ret`, and all ten of its `mov eax, dword ptr [eax]`
gadgets end in `ret 4` or `mov dword ptr [esp], eax`, so `find_exact`'s
clean-tail rule rejects every one. Gating it needs a PE32 synthetic builder;
`write_synthetic_pe` emits PE32+ only. Nothing in `--help` or the MCP
description claims x86 IAT specifically — both say "a PE must import the API
(IAT dereference)", which is true on both widths.

---

## 7. CHLX-07 — the Linux chain targets, each EXECUTED

Same gating rule, same harness, the Linux half. Four of the six targets the
finding named shipped; the two non-x86 ones did not, and section 7.2 says why
in measurements rather than adjectives.

Run: `python tests/emulate.py --regressions`, section *CHLX-07 Linux chain
targets*. The recorded verdicts live in `LINUX_REGRESSIONS`. Every
`(target, fixture)` pair that emits a chain has a row: see the note under the
table for the sweep that established it.

### 7.1 The table

| id | fixture | what is executed | verdict |
|---|---|---|---|
| `execve-x64` | `elf-Linux-x64` | `linux-execve` | **PASS** |
| `execve-x86` | `elf-Linux-x86` | `linux-execve` | **PASS** |
| `mprotect-x64` | `elf-Linux-x64` | `linux-mprotect` | **PASS** |
| `mprotect-x64-bash` | `elf-x64-bash-v4.1.5.1` | `linux-mprotect`, syscall 10 | **PASS** |
| `mprotect-x86` | `elf-Linux-x86` | `linux-mprotect` | **PASS** |
| `mprotect-x86-freebsd` | `elf-FreeBSD-x86` | `linux-mprotect`, syscall 125 | **PASS** |
| `mprotect-explicit-region` | `elf-Linux-x64` | `--shellcode-addr 0x6bc123 --shellcode-size 0x10 --prot 5` must reach `rdi=0x6bc000, rsi=0x1000, rdx=5` — page-aligns **down**, rounds length **up** | **PASS** |
| `syscall-generic-x64` | `elf-Linux-x64` | `linux-syscall` nr 39 | **PASS** |
| `syscall-args-x64` | `elf-Linux-x64` | `linux-syscall` nr 60, `rdi=0x2a` | **PASS** |
| `syscall-generic-x86` | `elf-Linux-x86` | `linux-syscall` nr 20, `ebx=0x1234` | **PASS** |
| `ret2libc-x64` | `elf-Linux-x64` | `linux-ret2libc` | **PASS** |
| `ret2libc-x64-bash` | `elf-x64-bash-v4.1.5.1` | `linux-ret2libc` | **PASS** |
| `ret2libc-x86` | `elf-Linux-x86` | `linux-ret2libc` | **PASS** |
| `ret2libc-x86-bash` | `elf-x86-bash-v4.1.5.1` | `linux-ret2libc` | **PASS** |
| `ret2libc-freebsd-x86` | `elf-FreeBSD-x86` | `linux-ret2libc` | **PASS** |
| `ret2libc-lib32` | `Linux_lib32.so` | `linux-ret2libc` | **PASS** |
| `ret2libc-x86-wide-addr-refused` | `elf-Linux-x86` | a 64-bit `--api-addr` against a 32-bit target | **REFUSED** |
| `srop-x64` | `elf-Linux-x64` | `linux-srop` | **PASS** |
| `srop-x64-bash` | `elf-x64-bash-v4.1.5.1` | `linux-srop`, syscall 59 reached from the restored context | **PASS** |
| `srop-x64-explicit-syscall` | `elf-Linux-x64` | `linux-srop` doing mprotect from the frame with **no write primitive at all** | **PASS** |
| `srop-x86-refused` | `elf-Linux-x86` | `linux-srop` on i386 — a different `sigcontext` layout | **REFUSED** (`linux-srop is x86-64 only`) |
| `mprotect-x86-bash-no-int80` | `elf-x86-bash-v4.1.5.1` | `linux-mprotect` on a fixture with no `int 0x80` | **REFUSED** |
| `mprotect-lib32-no-int80` | `Linux_lib32.so` | `linux-mprotect` on a fixture with no `int 0x80` | **REFUSED** |
| `mprotect-ndh` | `elf-Linux-x86-NDH-chall` | `linux-mprotect`, syscall 125 | **PASS** |
| `mprotect-lib64` | `Linux_lib64.so` | `linux-mprotect`, syscall 10 | **PASS** |
| `syscall-ndh` | `elf-Linux-x86-NDH-chall` | `linux-syscall` nr 20 | **PASS** |
| `syscall-freebsd-x86` | `elf-FreeBSD-x86` | `linux-syscall` nr 20 | **PASS** |
| `syscall-x64-bash` | `elf-x64-bash-v4.1.5.1` | `linux-syscall` nr 39 | **PASS** |
| `syscall-lib64` | `Linux_lib64.so` | `linux-syscall` nr 39 | **PASS** |
| `ret2libc-ndh` | `elf-Linux-x86-NDH-chall` | `linux-ret2libc` | **PASS** |
| `ret2libc-lib64` | `Linux_lib64.so` | `linux-ret2libc` | **PASS** |
| `srop-lib64` | `Linux_lib64.so` | `linux-srop` | **PASS** |

```
summary: 32 of 32 match the recorded verdict
```

The last nine rows were added at integration, and the reason they exist is
worth stating because it is the exit criterion, not a detail. The criterion is
"the harness executes **every** chain the tool emits". The 23 rows above it
were chosen to demonstrate each *target*; nobody had swept the product. Doing
that — the 5 advertised Linux targets across the 8 chainable ELF fixtures —
found **29 pairs that emit a chain and 9 with no recorded run**: `mprotect`
and `ret2libc` and `srop` on `Linux_lib64.so`, `mprotect`/`syscall`/`ret2libc`
on `elf-Linux-x86-NDH-chall`, `syscall` on `elf-FreeBSD-x86` and
`elf-x64-bash-v4.1.5.1`. Every one of them is a chain a user could generate
today and nothing had ever executed. All nine pass; none of them assert
anything new about the builder, and that is the point — the claim being
defended is coverage, not behaviour.

The corresponding sweep on the Windows side has three PE fixtures and one
emitting pair: `pe-x86-cmd-v6.1.7600`, which is `CHWIN-02-x86` in section 5
and executes. `pe-x64-cmd-v6.1.7601` cannot populate `rdx` and emits nothing
(that is what `--plan-chain` reports as `set_rdx`), and
`pe-Windows-ARMv7-Thumb2LE-HelloWorld` has no chain builder at all.

Four of the `ret2libc` rows are the point of the whole target.
`elf-x64-bash-v4.1.5.1`, `elf-x86-bash-v4.1.5.1`, `elf-FreeBSD-x86` and
`Linux_lib32.so` are the four fixtures the audit named as producing **nothing
at all** at the v0.4.0 baseline. They produce an executing chain now.

`srop-x64` deserves a note about what is actually asserted. It is **not** "the
chain asked for `rt_sigreturn`". The harness applies the 31-word frame exactly
as the kernel does, and the *restored context* must reach
`execve("/bin//sh")` by itself. A frame with the wrong layout restores garbage
and fails here.

### 7.2 The two targets that are NOT shipped, and the measurements

ARM64 and MIPS chain targets do not appear in `LinuxTarget::NAMES`, `--help`,
the MCP description or the MANUAL. `--chain` on an ARM64/MIPS ELF still
reports the same `Unsupported` error it did at v0.4.0 — except that
`--plan-chain` now answers with a document (`target_supported: false`) instead
of failing.

* **ARM64.** No syscall-based chain is constructible on the only ARM64 fixture
  at all. Measured: `rop-finder --binary tests/fixtures/elf-ARM64-bash` piped
  through `grep -c svc` is **0**, and `--re "^ldr x0, \[sp"` and
  `--re "^ldp x0, x1"` are **0** unique gadgets each. The one real shape is a
  `func_call` chain over `ldp x19, x20, [sp, #N] … ldp x29, x30, [sp], #M ;
  ret` plus `mov x0, x19`, which needs a slot-offset stack model this crate
  does not have and an AArch64 half of `tests/emulate.py` — `Machine` is
  x86-only, `Uc(UC_ARCH_X86, …)`.
* **MIPS.** `elf-Mips-Defcon-20-pwn100` *does* support a chain — 2,557 gadgets
  matching `lw $ra, N($sp) … jr $ra ; addiu $sp, $sp, M`, 4,331 with
  `lw $s0, N($sp)`, 3,027 with `move $a0, $s0`, 996 syscall-terminated — so
  the target is real. It needs the same offset-addressed frame model, plus
  delay-slot semantics, plus a MIPS32LE `Machine` in the harness.

Shipping either without a row in section 7.1 would break the gating rule, so
neither was shipped. That is the honest reading of the `CHLX-07` exit
criterion: two of six targets are missing, and no chain is advertised that
this harness has not executed.

---

## 8. The v0.5.0 integration run

Everything above, re-run on the integrated tree on 2026-09-04, release build,
environment `win32 python=3.12.10 unicorn=2.1.2 capstone=5.0.7`. (The runs in
sections 1–7 were taken under unicorn 2.1.4; every verdict is identical under
2.1.2.)

```
python tests/emulate.py --regressions
  CHWIN-01=PASS, CHWIN-02=PASS, CHWIN-03=PASS, CHWIN-07=PASS,
  CHWIN-02-x86=PASS, CHWIN-04=PASS, CHWIN-06-before=REFUSED, CHWIN-06=PASS
                                             (8/8 match the recorded state)
  CHWIN-08: 5 of 5 match the recorded verdict
  CHLX-07:  32 of 32 match the recorded verdict
```

```
python tests/emulate.py --all      # the DEFAULT target (linux-execve), per fixture

fixture                      verdict    detail
elf-Linux-x64                RUNS
elf-Linux-x86                RUNS
elf-Linux-x86-NDH-chall      RUNS
elf-FreeBSD-x86              RUNS
elf-x64-bash-v4.1.5.1        RUNS
elf-x86-bash-v4.1.5.1        NO-CHAIN   [Error] can't find a suitable gadget: int 0x80
Linux_lib32.so               NO-CHAIN   [Error] can't find a suitable gadget: int 0x80
Linux_lib64.so               RUNS
summary: NO-CHAIN=2, RUNS=6
```

The two `NO-CHAIN` rows are a real limit of those two binaries, not a defect:
neither contains an `int 0x80`, so no `execve` syscall chain exists in either
to be found. Both build and execute under `linux-ret2libc`
(`ret2libc-x86-bash`, `ret2libc-lib32` in section 7.1), which is what the
`--plan-chain` document for those two points at.

Workspace state at this run: `cargo test --workspace` **729 passed; 0 failed;
4 ignored** (the v0.4.0 baseline was 645/0/4). `cargo fmt --all --check` and
`cargo clippy --workspace --all-targets -- -D warnings` both clean.
`tests/parity.py` **PASS** at 763,166 / 763,204 = 99.9950%, byte-for-byte the
v0.4.0 figure — the Phase 6 engine rewrite changed no gadget.
