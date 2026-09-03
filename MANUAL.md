# rop-finder — User Manual

A Rust engine for ROP/JOP/SYS gadget discovery and ROP chain generation, with an MCP server for AI-assisted exploit development. Run `rop-finder --version` for the version of the build you have; every measured figure in this manual is sourced to [`docs/measured-2026-09.md`](docs/measured-2026-09.md) or to a named finding in [`docs/AUDIT-FINDINGS.md`](docs/AUDIT-FINDINGS.md).

---

## Table of contents

1. [What rop-finder gives you](#1-what-rop-finder-gives-you)
2. [Installation](#2-installation)
3. [Core concepts in 3 minutes](#3-core-concepts-in-3-minutes)
4. [Quick start](#4-quick-start)
5. [CLI reference](#5-cli-reference)
   - [ROPgadget flag coverage](#ropgadget-flag-coverage)
   - [Known divergences](#known-divergences)
6. [Use cases](#6-use-cases)
   - [UC1 — Basic gadget hunting (Linux ELF)](#uc1--basic-gadget-hunting-linux-elf)
   - [UC2 — Exploit constraints: bad bytes and instruction filters](#uc2--exploit-constraints-bad-bytes-and-instruction-filters)
   - [UC3 — ASLR workflow: RVA addresses with `--base 0`](#uc3--aslr-workflow-rva-addresses-with---base-0)
   - [UC4 — Windows kernel (ring0) ROP: scanning only non-pageable `.text`](#uc4--windows-kernel-ring0-rop-scanning-only-non-pageable-text)
   - [UC5 — Auto-generating a Linux `execve` chain](#uc5--auto-generating-a-linux-execve-chain)
   - [UC6 — Auto-generating a Windows VirtualProtect chain](#uc6--auto-generating-a-windows-virtualprotect-chain)
   - [UC7 — AI agents via the MCP server](#uc7--ai-agents-via-the-mcp-server)
   - [UC8 — Raw blobs and firmware](#uc8--raw-blobs-and-firmware)
   - [UC9 — CET/CFG-hardened targets](#uc9--cetcfg-hardened-targets)
7. [Output formats](#7-output-formats)
8. [Semantic classification and quality ranking](#8-semantic-classification-and-quality-ranking)
9. [Performance guide](#9-performance-guide)
10. [Troubleshooting & FAQ](#10-troubleshooting--faq)
11. [Responsible use](#11-responsible-use)

---

## 1. What rop-finder gives you

rop-finder is a rewrite of [ROPgadget](https://github.com/jonathansalwan/ROPgadget) in Rust. Given any executable, it finds **gadgets** — short instruction sequences ending in `ret` (ROP), `jmp`/`call` (JOP), or syscall instructions — that exploit developers chain together to reuse a binary's own code.

| Capability | Details |
|---|---|
| **Gadget discovery** | ROP, JOP, and syscall gadgets; 99.995% parity with ROPgadget across 24 reference binaries — measured on post-dedup `(address, bytes)` sets, **not** on instruction text (see [§10, "Different output from ROPgadget?"](#10-troubleshooting--faq)) |
| **Formats** | ELF, PE (.exe/.dll), Mach-O, fat/Universal Mach-O, raw blobs |
| **Architectures** | x86, x64, ARM, Thumb, ARM64, MIPS 32/64, PowerPC 32/64, SPARC, RISC-V 32/64 |
| **Chain generation** | Linux `execve("/bin//sh")` (x86/x64), emitted as a Python exploit script or JSON IR. Windows `VirtualProtect` (x86/x64) is **experimental** and prints a warning — see [UC6](#uc6--auto-generating-a-windows-virtualprotect-chain) |
| **Address control** | `--base` rebase (RVA/ASLR workflows), `--offset` slide, `--section` filtering, `--range` trimming |
| **Intelligence** | Semantic classification (reg-write, stack-pivot, …), quality ranking, JOP dispatcher detection — classification measured against a hand-labeled corpus (x86-64 macro-P 0.9959); ranking is an unevaluated heuristic (see [§8](#8-semantic-classification-and-quality-ranking)) |
| **AI integration** | MCP server (`rop-finder-mcp`) exposing 10 tools to AI agents over stdio |
| **Speed** | ~6× faster than ROPgadget on x86/x64; 1.3–2.1× on ARM64/MIPS/PowerPC. Per-fixture timings and method: [`docs/measured-2026-09.md`](docs/measured-2026-09.md) |
| **Robustness** | Structured errors with exit codes on malformed/corrupt binaries |

Two binaries:

- **`rop-finder`** — the CLI tool.
- **`rop-finder-mcp`** — the MCP server for AI agents (see [UC7](#uc7--ai-agents-via-the-mcp-server)).

**What this manual does not claim.** It is a ROPgadget rewrite, not a
superset and not a drop-in replacement: [§5's flag-coverage
table](#ropgadget-flag-coverage) lists every ROPgadget flag with its status
here, and the [known divergences](#known-divergences) that follow it list
the places where the same flag behaves differently. No comparison against
`ropper`, `rp++` or `radare2` is made anywhere in this document, because
none has been measured.

---

## 2. Installation

### Build from source (any OS) — the supported path

```sh
# needs: rustup (https://rustup.rs) + a C compiler (MSVC / gcc / clang)
git clone <repo-url> && cd rop-finder
cargo build --release
# → target/release/rop-finder(.exe), target/release/rop-finder-mcp(.exe)
```

Copy the two binaries anywhere you like (e.g. a directory on your `PATH`).
A C compiler is required because the non-x86 disassembler is the vendored C
capstone core.

### Prebuilt binaries

Prebuilt binaries are produced by the release CI job on a tagged push
(Linux x86_64/aarch64 static musl, a universal macOS binary, Windows
x86_64/aarch64), published with checksums. They are **not** committed to the
git tree; a checkout gives you source only. See `dist/README.md`.

### Verify your install

```sh
rop-finder --version
```

`--version` prints the tool version, the version of the capstone core this
binary is linked against, and a one-line ROPgadget attribution. Quote the
whole thing when reporting a decode or parity disagreement — the capstone
build is otherwise unrecoverable from the output.

---

## 3. Core concepts in 3 minutes

**Gadget.** A short instruction sequence ending in a control-flow instruction. `pop rdi ; ret` lets you load a value into `rdi` and continue to the next gadget. Thousands of them hide inside any binary — between intended instructions, at unaligned offsets.

**ROP vs JOP vs SYS.** ROP gadgets end in `ret`, JOP gadgets end in indirect `jmp`/`call` (useful when stack protection watches returns), SYS gadgets end in `syscall`/`sysenter`/`int 0x80`. All three engines run by default; disable with `--norop/--nojop/--nosys`.

**Image base, RVA, rebase, slide.** A gadget's address depends on where the binary is loaded:
- **Image base** — the address baked into the file (PE `ImageBase`, ELF min `PT_LOAD` vaddr).
- **RVA** — address relative to the image base. Under ASLR, the base changes every run; RVAs don't.
- **`--base <addr>`** — *rebases at load time*: everything (including disassembly of address-dependent operands) is computed as if the binary loaded at `<addr>`. `--base 0` gives you RVAs.
- **`--offset <addr>`** — an *emission-time slide*: added to printed addresses only; disassembly is unaffected. Use it when you know the runtime base and want ready-to-paste addresses.

**Bad bytes.** Characters your exploit delivery can't contain (often `00 0a 0d`). `--badbytes "00|0a|0d"` rejects any gadget whose **final** address (after base+offset) contains them — because that's the address that lands in your payload.

**Depth.** `--depth N` controls how many bytes before the terminating instruction the engine looks back. Default 10 matches ROPgadget; larger = more gadgets, slower.

---

## 4. Quick start

```sh
# Find all gadgets in a binary
rop-finder --binary ./target.bin

# Just ROP gadgets (no JOP/syscall), deeper search
rop-finder --binary ./target.bin --nojop --nosys --depth 12

# Machine-readable output
rop-finder --binary ./target.bin --json --depth 5

# What is this binary? (format, arch, sections, PE imports)
rop-finder --binary ./target.bin --info
```

Typical session flow: `--info` to understand the target → gadget scan with filters → chain generation or manual chain building from `--json` output.

---

## 5. CLI reference

```
rop-finder --binary <file> [options]
```

**Engines & scan scope**

| Flag | Effect |
|---|---|
| `--depth <n>` | Search depth (default 10) |
| `--norop / --nojop / --nosys` | Disable an engine |
| `--multibr` | Allow multiple branch instructions inside gadgets |
| `--section <glob>` | Scan only named executable sections; repeatable, comma-separated, `*` glob (`--section ".text,.init*"`). **rop-finder extension** — ROPgadget has no `--section` |
| `--range <0xA-0xB>` | Restrict to an address range (applied inside `--section` if both given) |
| `--align <n>` | Constrain gadget start addresses to an `n`-byte boundary (`0` = no constraint). **Partial on x86/x64** — see [known divergences](#known-divergences) |
| `--all` | Disable duplicate-gadget removal |
| `--thumb` | ARM Thumb mode |
| `--rawArch/--rawMode/--rawEndian` | Required for raw blobs (see [UC8](#uc8--raw-blobs-and-firmware)) |

**Addressing**

| Flag | Effect |
|---|---|
| `--base <hex>` | Rebase image at load time; `0` = RVA output. Changes disassembly of address-dependent operands |
| `--offset <hex>` | Additive slide on printed addresses only (applied after `--base`) |

**Filtering**

| Flag | Effect |
|---|---|
| `--only "pop\|ret"` | Keep gadgets containing only these mnemonics |
| `--filter "leave\|enter"` | Suppress mnemonics. **Diverges from ROPgadget** — literal suffix match here, anchored regex there; see [known divergences](#known-divergences) |
| `--re "<regex>"` | Keep gadgets where every `\|`-separated pattern matches at least one instruction |
| `--badbytes "00\|0a-0d"` | Reject gadgets whose **final** address contains these bytes |
| `--callPreceded` | Keep only gadgets whose preceding bytes decode as an x86 `call` (backward-edge check) |
| `--cfg-aware` | Keep only `endbr64/endbr32`-aligned gadget entries (forward-edge CET/IBT check). **Returns zero gadgets on every fixture in this repository** — see [UC9](#uc9--cetcfg-hardened-targets) |

`--callPreceded` (backward edge: is this address a legitimate return site?)
and `--cfg-aware` (forward edge: is this address a legitimate indirect-branch
target?) are different checks. Neither substitutes for the other.

**Search modes** (these replace the gadget scan rather than filtering it)

| Flag | Effect |
|---|---|
| `--string "<regex>"` | Byte-regex search across readable/data sections |
| `--opcode <hex>` | Literal byte-sequence search across executable sections |
| `--memstr "<chars>"` | First occurrence of each character of the string, across executable then data sections |
| `--mipsrop <type>` | MIPS useful-gadget finder: `stackfinder\|system\|tails\|lia0\|registers` |
| `--console` | Interactive REPL over the search engine (`--binary` optional; preloaded when given) |

**Output**

| Flag | Effect |
|---|---|
| `--json` | JSON array of `{vaddr, bytes, text, section, ...}` |
| `--dump` | Append the gadget bytes to human output (` // hexbytes`) |
| `--noinstr` | Print bare addresses: no instruction text, no dedup, no sort. Cannot combine with `--only` or `--re` |
| `--silent` | Suppress gadget printing during analysis |
| `--classify` | Add semantic fields to JSON (class, regs_written, quality, …). **rop-finder extension** |
| `--rank` | Sort best-quality gadgets first. **rop-finder extension** |
| `--cache` | Disk-cache scan results (see [§9](#9-performance-guide)). **rop-finder extension** |
| `--info` | Print image metadata JSON and exit (no scan). **rop-finder extension** |

**Chain generation**

| Flag | Effect |
|---|---|
| `--ropchain` | Generate a chain (Python script; JSON IR with `--json`) |
| `--chain <target>` | `linux-execve` (default) or `windows-virtualprotect` (**experimental**, prints a stderr warning — see [UC6](#uc6--auto-generating-a-windows-virtualprotect-chain)) |
| `--api-addr <hex>` | Runtime address of the target API (Windows) |
| `--shellcode-addr <hex>` | Where your shellcode will live (default: writable `.data`) |
| `--shellcode-size <hex>` | `dwSize` for VirtualProtect (default `0x1000`) |

**Exit codes:** `0` success · `1` usage error (bad flags, unknown section, missing gadgets) · `2` malformed/unreadable binary.

### ROPgadget flag coverage

rop-finder is a rewrite of ROPgadget, so the question "does my ROPgadget
command line work here?" has to have an answer. This table is derived from
ROPgadget 7.7's complete argument list (`ropgadget/args.py:75-104`, all 30
flags) against `pub struct Cli` in `crates/rf-cli/src/lib.rs`. Nothing is
omitted.

| ROPgadget flag | Status here | Notes |
|---|---|---|
| `--binary <file>` | implemented | Same magic-byte format dispatch |
| `--depth <n>` | implemented | Same default 10 |
| `--norop` / `--nojop` / `--nosys` | implemented | |
| `--multibr` | implemented | |
| `--only <key>` | implemented | Same first-token matching — but see [known divergences](#known-divergences) on instruction text |
| `--filter <key>` | **partial / divergent** | Literal suffix match, not ROPgadget's anchored regex |
| `--re <re>` | implemented | Same split rule and per-instruction conjunction (`options.py:64-98`); an invalid pattern is a clean usage error here, an uncaught `re.error` there |
| `--range <start-end>` | **partial** | Applied once, at section truncation. ROPgadget also re-filters the `--offset`-shifted addresses, so `--range` combined with `--offset` diverges |
| `--badbytes <bytes>` | implemented | Includes `aa-bb` ranges; checked on the final (rebased + slid) address in both tools |
| `--offset <hexaddr>` | implemented | |
| `--callPreceded` | implemented | Same six suffix heuristics (`options.py:100-120`). ROPgadget reads the preceding bytes with the `--offset` slide mixed in (an oracle bug); rop-finder reads the true preceding bytes, so `--callPreceded --offset` diverges |
| `--align <n>` | **partial** | Full aligned backward stepping on the capstone architectures; on x86/x64 it constrains start addresses but does not extend the backward reach — see below |
| `--all` | implemented | |
| `--noinstr` | implemented | Same `--only` / `--re` conflict errors |
| `--dump` | implemented | |
| `--silent` | implemented | |
| `--thumb` | implemented | Thumb comes only from this flag, as in ROPgadget |
| `--rawArch` / `--rawMode` / `--rawEndian` | implemented | Same accepted values |
| `--opcode <hex>` | implemented | Literal byte search over executable sections (`core.py:182-200`) |
| `--string <regex>` | implemented | Byte regex over data sections (`core.py:159-180`) |
| `--memstr <chars>` | implemented | Per-character search, executable then data (`core.py:202-227`) |
| `--mipsrop <type>` | implemented | All five modes (`core.py:118-157`) |
| `--console` | implemented | Prompt, messages, empty-line repeat and EOF semantics mirror `cmd.Cmd`; `string`/`opcode`/`memstr` additionally *run* the search here, where the oracle only lists them in `settings` |
| `--ropchain` | **partial / divergent** | Linux `execve` for ELF x86/x64 only, same gadget search order and backtracking. Output is the script alone — no surrounding gadget dump or step log — and a missing gadget is a structured error, not print-and-return. `--chain windows-virtualprotect` is a rop-finder addition with no oracle |
| `-v` / `--version` | **partial** | `--version` exits 0 and prints more than the oracle does: tool version, linked capstone version, the x86 formatter, and the ROPgadget attribution. `-V` prints the one-line version only. ROPgadget's single-dash `-v` spelling is not bound and exits 1 |
| `-c` / `--checkUpdate` | **not implemented** | Deliberate: no network access from this tool, ever |

rop-finder additionally has `--section`, `--base`, `--info`, `--classify`,
`--rank`, `--cache`, `--cfg-aware`, `--chain`, `--api-addr`,
`--shellcode-addr` and `--shellcode-size`, none of which exist in ROPgadget.

### Known divergences

These are the places where the same command produces different output. Each
names its finding ID in
[`docs/AUDIT-FINDINGS.md`](docs/AUDIT-FINDINGS.md). Items 1-6 were the v0.1.1
divergences and are **fixed in v0.2.0** — they are kept here, with the measured
result, because the previous release's advice ("do not reuse ROPgadget-era
greps") is now wrong and saying so is more useful than deleting it. Items 7-13
are what still differs.

1. **Instruction text on x86/x64 now matches exactly** (`SCAN-08`, fixed in
   v0.2.0). This entry previously warned that 15-29% of x86/x64 gadget texts
   diverged and told you not to reuse ROPgadget-era greps. That is no longer
   true: on a default `--depth 10` scan the rendered text is byte-identical to
   capstone's on **all 361,954 matched x86/x64 gadgets across the corpus —
   0 differences**. `--only "popal|ret"`, `--only "xlatb"`, `--only "call"` and
   `repz ret` all select what ROPgadget selects.

   Two spellings still differ, and only under `--align` or `--all`:
   `fndisi` where capstone prints `fdisi8087_nop` (an undocumented x87 alias),
   and `cldemote [eax]` where capstone prints `cldemote byte ptr [eax]`.
   Three lines total on the whole corpus.

2. **`--filter` is a regex, matched in full** (`CLI-02`, `SCAN-01`, fixed in
   v0.2.0). `--filter "j.*"` removes every gadget containing a jump, exactly as
   ROPgadget does; `--filter "op"` matches no mnemonic and so filters nothing
   (it does **not** remove `pop`). Verified against the oracle on
   `elf-Linux-x86`: 13,762 and 42,508 gadgets respectively, set-identical.

3. **`--align` steps the candidate start** (`ANCH-01`, `SCAN-05`, fixed in
   v0.2.0). x86/x64 now steps back by `ref - i*align` like the capstone
   architectures instead of filtering unaligned starts, so `--align 4 --depth
   10` reaches the full 36 bytes behind the anchor. Verified on
   `elf-Linux-x86`: `--align 4` -> 19,240 and `--align 8` -> 9,136, both
   set-identical to the oracle.

4. **`--range` is applied twice** (`SCAN-10`, fixed in v0.2.0), once truncating
   the section on raw addresses and once over the final `--offset`-shifted
   address, matching ROPgadget.

5. **`--cfg-aware` models Intel CET/IBT correctly** (`CRIT-01`, fixed in
   v0.2.0). It used to require an `endbr32`/`endbr64` at the entry of every
   gadget, which is a contradiction — IBT does not check returns — and so it
   returned **zero gadgets on every binary**. It now keeps ROP gadgets
   unconditionally and requires an endbr entry only for JOP/SYS gadgets, which
   are the ones reached through an indirect branch. Measured:
   `pe-x64-cmd-v6.1.7601` 2,097, `pe-x86-cmd-v6.1.7600` 2,304,
   `elf-Linux-x64` 8,389, `elf-Linux-x86` 12,056. When the image contains no
   landing pads at all the flag prints a warning saying so, because then it can
   only ever remove gadgets.

6. **`mov cs, r/m16` gadgets** (`SCAN-09`, fixed in v0.2.0) are no longer
   missing.

### What still differs

7. **`movdqu` with a redundant `LOCK` prefix** — 18 gadgets under
   `--align 4` and 3 under `--all` on `elf-Linux-x64`. capstone 5.0.7 accepts
   `f0 f3 0f 7f 47 f0 c3`; rop-finder's lock whitelist rejects it. These are
   gadgets ROPgadget finds and rop-finder does not; rop-finder never invents
   the reverse. Reproduce with
   `rop-finder --binary tests/fixtures/elf-Linux-x64 --depth 10 --align 4`.

8. **RISC-V 32 gadget text** (`ANCH-04`) — deliberate. ROPgadget opens *every*
   RISC-V binary in RV64 mode, including ELFCLASS32 ones, and prints RV64-only
   text for instructions an RV32 target cannot execute. rop-finder decodes an
   ELFCLASS32 image as RV32. The `(address, bytes)` sets are identical; 68 of
   279 texts on `elf-Linux-RISCV_32` differ.

9. **Windows ARM Thumb-2 images** (`ANCH-06`) — deliberate. An
   `IMAGE_FILE_MACHINE_ARMNT` PE is Thumb-2 only. ROPgadget scans it with the
   A32 tables unless `--thumb` is passed, so its 38 gadgets are
   misinterpretations of Thumb code; rop-finder routes the image to the Thumb
   tables and returns a different, correct set of 404.

10. **AArch64 and SPARC `--sys`** (`ANCH-03`) — deliberate. ROPgadget's ARM64
    and SPARC syscall anchor tables are empty (`gadgets.py` has two `TODO`
    comments there), so `--sys` returns nothing on AArch64. rop-finder
    populates them, so its result can be a superset. Neither `bash` fixture in
    this corpus contains an inline `svc`/`ta`, so on the corpus the two agree.

11. **Unloadable input goes to stderr with exit 2** — deliberate. ROPgadget
    prints `[Error] Binary format not supported` on *stdout* and exits 1.
    rop-finder prints a more specific message on *stderr* and exits 2, which is
    the documented 0/1/2 contract and the better behaviour in a pipeline.

12. **A multi-slice fat Mach-O is refused, not guessed** (`CORE-03`) —
    deliberate. Pass `--arch <slice>` to choose one, or `--compat` to reproduce
    ROPgadget's flat concatenation bug-for-bug.

13. **Ordering is identical, not different.** Both tools sort alphabetically
    by gadget text. See [§10](#10-troubleshooting--faq).

---

## 6. Use cases

### UC1 — Basic gadget hunting (Linux ELF)

You're analyzing a 64-bit Linux binary and need a `pop rdi` gadget to set up a call:

```sh
rop-finder --binary ./server --nojop --nosys --only "pop|ret" | grep "pop rdi"
```

```
0x0000000000400532 : pop rdi ; pop rbp ; ret
0x0000000000401648 : pop rdi ; ret
```

**Tips:** `--only "pop|ret"` collapses output to pure pop gadgets. Pipe through `grep` for the register you need. Add `--rank` to see the cleanest gadgets (fewest side effects) first.

---

### UC2 — Exploit constraints: bad bytes and instruction filters

Your stack overflow goes through a `strcpy`-like function: the payload can't contain `00`, `0a`, `0d`.

```sh
rop-finder --binary ./server --base 0x7ffff7a00000 --badbytes "00|0a|0d" --filter "leave"
```

- `--base` sets the runtime load address you leaked, so bad-byte checking happens on the **real** addresses your payload will contain.
- `--filter "leave"` drops `leave ; ret` gadgets (they corrupt frame pointers in your layout).

Then verify your chosen gadgets individually:

```sh
rop-finder --binary ./server --base 0x7ffff7a00000 --badbytes "00|0a|0d" --only "pop|ret" --json | python -m json.tool | less
```

---

### UC3 — ASLR workflow: RVA addresses with `--base 0`

With ASLR, you compute runtime addresses as `leaked_base + RVA`. You want RVAs, not absolute addresses:

```sh
# RVAs for pop gadgets
rop-finder --binary libc.so.6 --base 0 --nojop --nosys --only "pop|ret" | head -5
```

```
0x000000000003e81c : pop r10 ; pop rbx ; pop rbp ; ret
0x0000000000015e3c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000018048 : pop r12 ; pop r13 ; pop r14 ; ret
```

```sh
# RVAs for syscall gadgets (SYS engine — don't pass --nosys!)
rop-finder --binary libc.so.6 --base 0 --norop --nojop | grep syscall | head
```

Every address is now an offset from the library base — no manual subtraction. Two gotchas:

- `--base 0` → addresses are RVAs; disassembly text reflects base 0 (matters for `jmp`-relative operands in JOP output).
- `--offset 0x7f…` → keeps original disassembly, only slides the printed address (wrong tool for RVA work).

---

### UC4 — Windows kernel (ring0) ROP: scanning only non-pageable `.text`

Kernel exploits must only use gadgets from **non-pageable** memory: in a Windows kernel image most sections can be paged out, `.text` can't. Instead of computing RVA ranges by hand:

```sh
rop-finder --binary ./kernel-image.exe --section .text --base 0 --json > gadgets.json
```

- `--section .text` — only the non-pageable section is scanned (glob patterns work: `--section ".text,PAGE*"`).
- `--base 0` — RVA output for the ASLR'd kernel base you recover at runtime.

**Scope of this use case: gadget discovery only.** rop-finder will enumerate and classify the gadgets in a kernel image; it will not build you a ring0 chain. The only chain target for PE binaries is `windows-virtualprotect`, and `VirtualProtect` is a Win32 usermode API that does not exist in kernel address space and cannot be called from ring0 — so `--ropchain --chain windows-virtualprotect` against a kernel image produces output that cannot run in the context you are scanning for. Earlier revisions of this manual presented a kernel image as a working chain demonstration; that is retracted (`CHWIN-09`). Ring0 chain construction is manual work from the `--json --classify` output.

Do not add `--cfg-aware` here. It keeps only gadgets entering on `endbr64`/`endbr32`, and Windows kernel images of the CFG generation carry `IMAGE_DLLCHARACTERISTICS_GUARD_CF` — software Control Flow Guard, a different mitigation — with no CET landing pads anywhere in the file. The flag silently returns zero gadgets and exit 0, which is indistinguishable from "this binary has no usable gadgets" (`CRIT-01`). The recommendation is withdrawn until that is fixed in v0.2.

---

### UC5 — Auto-generating a Linux `execve` chain

For a classic ret2libc-free execve on a vulnerable x64 ELF:

```sh
rop-finder --binary ./vuln64 --ropchain
```

```python
#!/usr/bin/env python3
from struct import pack
p = b''
p += pack('<Q', 0x0000000000401767) # pop rsi ; ret
p += pack('<Q', 0x00000000006bc080) # @ .data
p += pack('<Q', 0x0000000000402036) # pop rax ; ret
p += b'/bin//sh'
...
```

Paste your padding into `p = b''` and you have a working exploit skeleton. Notes:

- Works on ELF x86 (`int 0x80`) and x64 (`syscall`); other targets get a clean error.
- If the binary lacks a needed gadget (e.g. no `mov [r64], r64` write gadget), rop-finder says exactly what's missing — exit code 1, no silent garbage.
- `--json` returns the **Chain IR** (typed words: gadget addresses, immediates, data pointers) if you want to post-process the chain yourself.
- Rebasing composes: `--ropchain --base 0x7ffff7a00000` generates the chain with runtime addresses.

---

### UC6 — Auto-generating a Windows VirtualProtect chain

> **Experimental. The chain this produces is not known to execute.**
> `--chain windows-virtualprotect` prints a warning to stderr for this
> reason. No generated Windows chain has ever been run against a CPU or an
> emulator — the "verify the layout in an emulator harness" exit criterion
> for this feature has no artifact — and three concrete layout defects are
> recorded in [`docs/AUDIT-FINDINGS.md`](docs/AUDIT-FINDINGS.md): the
> stack-alignment pad is an inert data word that the preceding gadget's
> `ret` lands on (`CHWIN-01`), `lpflOldProtect` defaults to the shellcode
> address so `VirtualProtect` overwrites the first four bytes of the buffer
> it just made RWX (`CHWIN-02`), and the IAT path uses the
> `IMAGE_IMPORT_BY_NAME` record rather than the `FirstThunk` slot
> (`CHWIN-03`). Read the output as a layout sketch to check by hand. Fixes
> are scheduled for v0.5.

Bypassing DEP on Windows by calling `VirtualProtect` on your shellcode:

```sh
rop-finder --binary ./target.exe --ropchain --chain windows-virtualprotect \
    --api-addr 0x76771234 --shellcode-addr 0x4ad24000 --shellcode-size 0x2000
```

- `--api-addr` is the **primary** resolution path: most PEs don't import VirtualProtect, so pass the runtime address you resolved (e.g. via a leaked module base + export offset).
- If the PE *does* import the API, omit `--api-addr` and rop-finder uses an IAT-dereference gadget sequence — ASLR-safe.
- The builder enforces the **Win64 calling convention**: `rcx/rdx/r8/r9` arg population, 32-byte shadow space, 16-byte stack alignment at the call (auto-padded), and a second-stack frame so execution continues into your shellcode after the call.

**Honest expectation-setting:** real x64 userland PEs often lack `pop rdx/r8/r9` gadgets — our spike found **zero** in cmd.exe and kernel32.dll. When a chain is infeasible you get a precise error:

```
[Error] can't find a suitable gadget: cannot populate rdx: no 'pop rdx' gadget
and no 'pop rax' + 'mov rdx, rax' fallback
```

That's a property of the binary, not a tool failure: a gadget-rich target may have the full `pop` set where cmd.exe does not. Earlier revisions of this manual named a specific Windows kernel image as the success-path demonstration; that claim is retracted, because a `VirtualProtect` chain is not a ring0 primitive at all (`CHWIN-09`, and see [UC4](#uc4--windows-kernel-ring0-rop-scanning-only-non-pageable-text)). x86 targets use stdcall (arguments on the stack) and rarely hit the missing-gadget case.

---

### UC7 — AI agents via the MCP server

`rop-finder-mcp` lets an AI agent (Claude Desktop, Cursor, a custom harness) find gadgets and build chains programmatically. It speaks MCP over **stdio** — the host launches it as a child process.

**Claude Desktop config** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "rop-finder": {
      "command": "C:\\tools\\rop-finder-mcp.exe",
      "args": ["--allow-dir", "C:\\exploit-work\\binaries"]
    }
  }
}
```

`--allow-dir` takes **absolute** paths and is the only source of the
allowlist. A server started with no `--allow-dir` exits 2 rather than
falling back to its working directory — which, launched from a host like
Claude Desktop, is a directory you did not choose and cannot see.

<!-- BEGIN GENERATED: mcp-surface -->
<!-- Generated by `cargo test -p rf-mcp --test manual_schema`. Do not edit by hand: the test regenerates it from the server's own tools/list and outputSchema and fails if this block has drifted. -->

**The 10 tools:**

| Tool | Required parameters | What it does |
|---|---|---|
| `build_rop_chain` | `binary_path`, `target` | Build a ROP chain. |
| `find_gadgets` | `binary_path` | Find ROP gadgets in a binary (ret-terminated). |
| `find_jop_gadgets` | `binary_path` | Find JOP gadgets in a binary (jmp/call-terminated). |
| `find_syscall_gadgets` | `binary_path` | Find SYS gadgets in a binary (syscall/sysenter/int). |
| `get_binary_info` | `binary_path` | Get binary metadata as JSON: format, arch, endianness, addr_size, image_base, entry, sections (name/vaddr/size/executable/writable), PE imports (iat_v… |
| `get_gadgets` | `binary_path`, `ids` | Resolve stable gadget ids (the `id` field of any gadget record, e.g. |
| `get_server_config` | (none) | Report the server's effective configuration: allow_roots (the only directories binary_path may name), max_depth, max_file_bytes, max_results, max_conc… |
| `get_server_stats` | (none) | Report this session's counters: requests_total and requests_by_tool, ok/denied/timeout/cancelled/error totals, denied_consecutive and probing_suspecte… |
| `run_ropgadget_command` | `binary_path`, `args` | Run a ROPgadget-style scan with explicit flags. |
| `search_gadgets_by_pattern` | `binary_path`, `pattern` | Search gadgets by pattern: regex matched against gadget text (e.g. |

**The gadget record.** Every gadget-returning tool emits this shape, and emits it *invariantly*: a field whose value is unknown is `null`, never absent, so a parser written against one response works on every other.

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable identity: `g_` + base32 of the first 10 bytes of `blake3(binary_sha256 \|\| vaddr_le \|\| bytes)`. |
| `vaddr` | string | Zero-padded hex address, for humans. |
| `vaddr_u64` | integer | The same address as a number. |
| `bytes` | string | Gadget bytes, lowercase hex. |
| `text` | string | `insns.join(" ; ")`. |
| `insns` | array of string | The instructions, already split. |
| `delay_slot` | boolean | MIPS/SPARC: the LAST instruction is the branch's delay slot, so it executes **before** control transfers. |
| `labels` | array of string | Every class the gadget earns, not just the primary one. |
| `regs_written` | array of string | Registers the gadget writes, lowercase and sigil-free. |
| `regs_read` | array of string | Registers the gadget reads. |
| `regs_from_stack` | array of string | The subset of `regs_written` loaded off the stack — the registers a chain payload can actually control. |
| `side_effects` | integer | Instructions that earn at least one label. |
| `quality` | integer | TAXONOMY.md R12 quality score, higher is cleaner. |
| `usability` | integer | Usability tier 0..=3 — the primary key of the default `rank` order. |
| `terminator` | string | How the gadget hands control on: `ret`, `ret-imm`, `retf`, `iret`, `far`, `jmp`, `call`, `syscall`, `none`. |
| `dispatcher` | boolean | JOP/COP dispatcher heuristic. |
| `privileged` | boolean | Contains a privileged or undefined instruction, so it faults in user mode and cannot appear in a chain. |
| `low_confidence` | boolean | The classification came from disassembly text rather than decoder metadata, so treat the semantic fields as advisory. |
| `arch` | string \| null | Fat Mach-O slice this gadget came from; `null` for every other container. |
| `class` | string \| null | Primary class (`reg-write`, `stack-pivot`, `mem-read`, `mem-write`, `arithmetic`, `syscall`, `dispatcher`, `other`); `null` when the architecture has… |
| `section` | string \| null | Section containing the gadget; `null` when no `section` filter was applied (the scan then has no section table to consult). |
| `stack_delta` | integer \| null | Net change to the stack pointer. |

<!-- END GENERATED: mcp-surface -->

**What the server enforces:**

- **Path confinement on an open handle, not on a string.** A request's `binary_path` is first checked lexically with no filesystem access at all: it must be absolute, contain no `.`/`..` component and no interior NUL, and on Windows must not use a `\\?\` / `\\.\` / UNC prefix or an alternate-data-stream `:`. The allowed root is picked by comparing path *components*, not string prefixes, so `/allowed` does not admit `/allowed-evil`. The file is then opened pinned to that root — component-by-component with `openat(O_NOFOLLOW)` on Unix, and on Windows by validating the returned handle's own final path, file type and volume serial — and the open handle, not the name, is what the scan reads from. Nothing re-resolves the path afterwards, so there is no window in which a rename or a freshly created symlink can redirect the read. (The previous design canonicalized a string and reopened it by name later; a rename race against it read a file outside the allowlist in 323 of 400 attempts — `MCP-01`.)
- **One denial code.** Every rejected path returns `path_denied`, with the same message and no OS error text, whether it is outside every root, absent, a directory, or unreadable. The older three-code taxonomy let a caller distinguish "exists as a file" from "exists as a directory" from "does not exist" for *any* absolute path on the machine — a filesystem existence oracle (`MCP-07`). Call `get_server_config` to read back the effective roots and caps instead of probing for them.
- **Flag allowlist** on `run_ropgadget_command`. Flags that would turn the tool into a general file reader are rejected with `invalid_flag`.
- **Caps.** `--max-results` (default 1000, hard max 50000); `--timeout-secs` (default 60, hard max 300); `--max-depth` (default 64) — a request above it is rejected with a `usage_error` naming the limit and the value, not silently clamped; `--max-concurrent` (default 2) queues rather than multiplies concurrent scans; `--max-file-bytes` (default 268435456, i.e. 256 MiB), checked against the open handle before any read; `--max-gadgets` (default 5000000, `0` disables) is the engine budget — a scan that accepts more stops with `resource_exhausted`; `--scan-threads` (default `num_cpus - 1`) sizes the scan pool so the server never takes every core.
- **Bounded caches.** `--cache-mem-mb` (default 512) is the in-memory scan-cache budget, evicted least-recently-used; `--cache-ttl-secs` (default 86400) is an entry's lifetime; `--cursor-ttl-secs` (default 300) is how long a paged scan stays pinned so an outstanding cursor can finish walking it. Every one of these is reported by `get_server_config` and the live totals by `get_server_stats`, so an agent never has to probe for them.
- **Audit trail.** `--audit-log <path>` writes one JSON object per call — including denials, timeouts and cancellations — opened append/create, mode 0600 on unix, rotated at `--audit-log-max-mb` (default 64) keeping `.1` and `.2`. It records the binary label, its SHA-256, a hash of the parameters and the result counts; it never records gadget text or file bytes. The path must not fall inside an allow root. `--probe-threshold` (default 20, `0` disables) is how many consecutive `path_denied` results in one session before responses are delayed 250 ms and `probing_suspected` is set.
- **Workspace.** `--workspace-dir <path>` materializes each paged scan as an NDJSON file, so an agent with filesystem tools can grep a whole result instead of paging it. Must not fall inside an allow root.
- **Content-hash cache.** Repeat agent queries on the same binary are near-instant. Add `--cache-dir` for persistence; it must not point inside an allowed root.

**What the server does NOT protect against — read this before you point it at anything:**

- **Your own choice of `--allow-dir`.** Confinement is exactly as narrow as the roots you pass. Point it at a home directory or a whole source tree and everything inside is in scope, by design. The server refuses the obviously-catastrophic roots — a filesystem or drive root, and anything at or above `/etc`, `/usr`, `/var`, `/System`, `/Library`, `/home`, `/Users`, `/root`, `C:\Users`, `C:\Windows`, `C:\Program Files`, `C:\ProgramData` — unless you pass `--i-accept-a-wide-allowlist`, but that is a guardrail against slips, not a policy engine.
- **Anything readable inside a root.** There is no per-file policy and no content filtering. A key, a credential file or an unrelated document that happens to live in an allowed directory will be read and returned if a request names it.
- **The target binary's bytes reaching the model.** This is the product, not a leak: gadget text, byte sequences, section layout, import names and generated chain scripts all flow into the agent's context and wherever the host sends it. Do not point this at a binary you would not paste into a chat window.
- **A timeout stopping the work.** Until the v0.2 engine cancellation token lands, a timed-out request returns a `timeout` error to the caller while the worker runs to completion (`MCP-03`). The depth and concurrency caps bound the cost; they do not cancel it.
- **A compromised or prompt-injected agent.** Nothing here reasons about intent. An agent under someone else's influence can issue any request your roots and flag allowlist permit.

Example agent prompt once configured: *"Use rop-finder to check whether target.exe in the allowed directory has gadgets to populate rcx, rdx, r8 and r9, and classify the ones it finds."*

---

### UC8 — Raw blobs and firmware

For a raw ARM firmware dump with no headers:

```sh
rop-finder --binary firmware.bin --rawArch arm --rawMode 32 --rawEndian little --base 0x8000000
```

- All three `--raw*` flags are required for raw blobs (arch ∈ `x86|arm|arm64|sparc|mips|ppc|riscv`, mode ∈ `32|64|arm|thumb|riscv`, endian ∈ `little|big`).
- `--base` sets the address where the blob is mapped on the device, so gadget addresses match your target's memory map.

---

### UC9 — CET/CFG-hardened targets

On binaries compiled with Intel CET (IBT), indirect branches can only land on `endbr64` instructions — most historical gadgets are unusable:

```sh
rop-finder --binary ./hardened.exe --cfg-aware --json
```

Only gadgets whose entry point is an `endbr64`/`endbr32` survive.

**Two caveats you need before you rely on this.**

First, the flag has no way to tell you it did nothing useful. There is no CET-marked binary in this repository's fixture corpus, and **`--cfg-aware` returns zero gadgets on every fixture here** (`CRIT-01`). An empty result and exit 0 is what you get both when the binary genuinely has no CET-valid gadget and when the binary has no CET landing pads at all. Check for `endbr64` (`f3 0f 1e fa`) yourself before concluding anything from an empty list.

Second, the warning rop-finder prints when you scan a "hardened" PE *without* the flag keys on `IMAGE_DLLCHARACTERISTICS_GUARD_CF`, because goblin does not expose the PE load-config CET fields. GUARD_CF is Microsoft's software Control Flow Guard — a runtime bitmap check on indirect call targets — and is a different mitigation from Intel CET/IBT. A GUARD_CF binary with no `endbr64` bytes will trigger the warning and then be wiped to zero gadgets by the flag the warning suggested. Both halves are scheduled for v0.2.

---

## 7. Output formats

**Human (default):**

```
Gadgets information
============================================================
0x0000000000402036 : pop rax ; ret
...
Unique gadgets found: 3211
```

**JSON (`--json`):** an array of records —

```json
[
  {
    "vaddr": "0x402036",
    "bytes": "58c3",
    "text": "pop rax ; ret",
    "section": ".text"
  }
]
```

With `--classify`, records additionally carry `class`, `labels`, `regs_written`, `regs_read`, `side_effects`, `quality`, `dispatcher`, and (on MIPS/SPARC) `delay_slot: true` — a reminder that the instruction *after* a `jr $ra` executes too.

**Chain IR (`--ropchain --json`):** typed words (`GadgetAddr | Immediate | DataAddr | Padding | CodeAddr`) with per-word comments and source-gadget indices — every gadget address in a chain is validated against the actual scan output before emission.

---

## 8. Semantic classification and quality ranking

Gadget dumps are huge (10K–600K+). Classification tells you *what a gadget does*; ranking tells you *which are easiest to use*.

```sh
rop-finder --binary ./target --json --classify --rank --depth 5 | head -40
```

- **Classes** (full rules in [TAXONOMY.md](TAXONOMY.md)): `reg-write`, `stack-pivot`, `mem-read`, `mem-write`, `arithmetic`, `syscall`, `dispatcher`, `other`. Multi-label with a primary class by last side effect.
- **Quality score (0–100):** penalizes side effects and gadget length. `pop rdi ; ret` scores 100; `pop rdi ; add [rbx], rax ; cli ; ret` scores low.
- **`dispatcher: true`** marks JOP dispatcher-style gadgets (register-indirect jumps with register arithmetic) — the pivot points JOP chains are built around.
- On x86/x64, classification uses full instruction metadata; other architectures get best-effort heuristic labels flagged `low_confidence`.

**As of v0.3.0 these labels are measured, not merely asserted** (`CLAIM-05`, `CLS-01`/`CLS-11`). The old self-agreement harness is gone; in its place is `tests/classify-corpus/`, a hand-labeled, hash-frozen corpus of 438 gadget records across eight architectures, never regenerated from the classifier's own output. Primary-class accuracy: arm 1.0000 (n=25), arm64 1.0000 (44), i386 1.0000 (74), mips 0.8400 (25), ppc 0.6400 (25), riscv64 0.8333 (24), sparc 0.8000 (25), x86_64 0.9949 (195); whole corpus 0.9474 (437). x86-64 macro-precision 0.9959, macro-recall 0.9977. Method and every caveat are in [`docs/classifier-eval.md`](docs/classifier-eval.md), and the figures are pinned in `crates/rf-classify/tests/eval.rs` so the classifier cannot drift without the numbers drifting too.

Four caveats matter when you rely on a label. The study was **not blind** — the labeler had read `crates/rf-classify/src/x86.rs` — so read the x86-64 figure with that attached. The `dispatcher` heuristic's precision of 1.0000 comes from one predicted positive; its recall is 0.2000, so a gadget *not* marked `dispatcher` tells you very little. PowerPC and MIPS have known, enumerated defects (`docs/classifier-eval.md` §4.1). And the **ranking is not evaluated at all** — there is no ground truth for gadget usefulness in the corpus, so `quality`, `usability` and the default `rank` order remain a documented heuristic for triage, not a measured judgement.

Use `--classify` and `--rank` to triage a large dump quickly. Verify the gadget you are about to put in a chain by reading its disassembly.

---

## 9. Performance guide

| Situation | Recommendation |
|---|---|
| Repeated scans of one big binary | `--cache` — second run is near-instant. Override location with `ROP_FINDER_CACHE_DIR` |
| Only need one section | `--section .text` skips the rest of the binary |
| Huge binaries (100+ MB) | Lower `--depth` first (10 → 6 cuts candidates dramatically), then `--section` |
| Just exploring | Lower `--depth`; it is the number of backward steps tried per anchor hit, so a smaller value means fewer candidates and a shorter scan |
| Scripting | `--json` + `--cache`; or the MCP server which caches automatically |

**Reference numbers.** The only timings this project stands behind are in [`docs/measured-2026-09.md`](docs/measured-2026-09.md), which names the machine, the toolchain, the oracle build and the exact command for every figure. Summary at `--depth 10`: `elf-Linux-x86` 0.09 s vs ROPgadget's 0.56 s (6.2×); `elf-x64-bash-v4.1.5.1` 0.10 s vs 0.57 s (5.7×); `elf-ARM64-bash` 0.23 s vs 0.48 s (2.1×); `elf-Mips-Defcon-20-pwn100` 1.52 s vs 2.54 s (1.7×); `elf-PowerPC-bash` 0.60 s vs 0.76 s (1.3×).

Earlier revisions of this manual quoted a `--depth 5` speed ratio and a per-fixture gadget-count/time pair with no hardware named. Neither survived re-measurement and both have been removed rather than corrected, because no benchmark in this repository produced them — `benches/` is empty and the figures above are wall-clock from the parity harness, not statistically sampled runs. A criterion suite lands in v1.0.

The scanner parallelizes across (region × anchor) work items with rayon. That granularity is coarse — on `elf-x64-bash` the audit measured only ~1.6× CPU utilisation on a 16-core machine (`CLAIM-01`) — and is a substantial part of why the x86/x64 ratio is ~6× rather than the order of magnitude originally projected. Finer-grained parallelism is v1.0 work.

---

## 10. Troubleshooting & FAQ

**"Unknown section" / exit 1 with a section list.**
The name you passed to `--section` doesn't exist. The error message lists available executable sections — check spelling. On **stripped ELFs** there are no section names; you get `PT_LOAD#n` segment names (a stderr warning tells you), which are coarser than real sections.

**"can't find a suitable gadget …" during `--ropchain`.**
The binary genuinely lacks a required gadget class (common for `pop rdx/r8/r9` on x64 PEs). Try: a different target binary (e.g. a DLL), `--depth` higher, or manual chain construction from `--json --classify` output. The error names the exact missing piece.

**Gadget addresses look wrong under ASLR.**
You're comparing absolute addresses across runs. Use `--base 0` (RVA) for analysis and add the leaked base at exploit time — or pass the leaked base via `--base`.

**Different output from ROPgadget?**
Two answers, for two different questions.

*Which gadgets were found:* the post-dedup `(address, bytes)` sets are 99.995% identical (`docs/measured-2026-09.md`); the ~0.005% that differ are the recorded intentional divergences in `tests/known-divergences.json`.

*How each gadget is printed:* 15–29% of x86/x64 gadget **texts** differ, because the two tools use different disassembler formatters. That is 100–500× the set-level number and it is the one that will bite you, because it breaks greps, `--only` lists and `--re` patterns carried over from ROPgadget. See [known divergences](#known-divergences) for the full list.

*Ordering:* it does **not** differ. Both tools sort alphabetically by gadget text (rop-finder's `post_process` in `crates/rf-scan/src/engine.rs` is a deliberate port of ROPgadget's `alphaSortgadgets`). Earlier revisions of this manual said rop-finder sorts by address; that was wrong (`CRIT-04`). A direct `diff` of the two tools' output is meaningful and is the fastest way to spot a parity gap, modulo the text differences above. `--rank` is the one thing that changes the order: quality descending, ties by ascending address. Note the consequence of alphabetical ordering: `rop-finder … | head` gives you the alphabetically first gadgets, **not** the lowest-addressed ones.

**`--badbytes` seems to reject too much after `--base`.**
By design: bad bytes are checked on the **final** address (after rebase and offset), because that's what goes into your payload. If you rebased to an address containing a bad byte (e.g. `0x55550000` with badbyte `55`), every gadget is correctly rejected.

**Broken pipe when piping to `head`.**
`rop-finder --binary x | head` used to abort with exit 101 on *every* platform — not a Windows quirk, and the workaround this manual previously offered did not address it (`CRIT-02`, `ROB-03`; the UC3 example above is one of the commands that triggered it). Both output paths now write through a buffered, locked stdout and treat a closed reader as a clean exit 0. Piping into `head`, `more`, `less` or `python -m json.tool` is fine.

**Mach-O universal binaries.**
All slices are scanned with the first slice's architecture (matching ROPgadget). Per-slice metadata: `--info`.

---

## 11. Responsible use

rop-finder is a dual-use security tool built for **defensive research, CTFs, authorized penetration testing, and exploit-mitigation evaluation**. Finding gadgets in binaries you own or are authorized to test is standard practice; using them against systems without authorization is not. The MCP server is deliberately local-only (stdio, directory-allowlisted) — keep it that way unless you add proper authentication.

---

*Project layout, architecture, and the phase-by-phase development plan live in [README.md](README.md) and [PLAN.md](../PLAN.md). Classification rules: [TAXONOMY.md](TAXONOMY.md). Windows chain feasibility data: [tests/spike-report.md](tests/spike-report.md).*
