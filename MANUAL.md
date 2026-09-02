# rop-finder — User Manual

**Version 0.1.0** · A fast Rust engine for ROP/JOP/SOP gadget discovery and ROP chain generation, with an MCP server for AI-assisted exploit development.

---

## Table of contents

1. [What rop-finder gives you](#1-what-rop-finder-gives-you)
2. [Installation](#2-installation)
3. [Core concepts in 3 minutes](#3-core-concepts-in-3-minutes)
4. [Quick start](#4-quick-start)
5. [CLI reference](#5-cli-reference)
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
| **Gadget discovery** | ROP, JOP, and syscall gadgets; 99.93% output parity with ROPgadget across 24 reference binaries |
| **Formats** | ELF, PE (.exe/.dll), Mach-O, fat/Universal Mach-O, raw blobs |
| **Architectures** | x86, x64, ARM, Thumb, ARM64, MIPS 32/64, PowerPC 32/64, SPARC, RISC-V 32/64 |
| **Chain generation** | Linux `execve("/bin//sh")` (x86/x64) and Windows `VirtualProtect` (x86/x64), emitted as a Python exploit script, JSON IR, or raw bytes |
| **Address control** | `--base` rebase (RVA/ASLR workflows), `--offset` slide, `--section` filtering, `--range` trimming |
| **Intelligence** | Semantic classification (reg-write, stack-pivot, …), quality ranking, JOP dispatcher detection |
| **AI integration** | MCP server (`rop-finder-mcp`) exposing 7 tools to AI agents over stdio |
| **Speed** | ~5–7× faster than ROPgadget, ~9–14× faster than ropper (measured, best-of-3) |
| **Robustness** | Never panics on malformed/corrupt binaries — structured errors with exit codes |

Two binaries ship in `dist/`:

- **`rop-finder`** — the CLI tool.
- **`rop-finder-mcp`** — the MCP server for AI agents (see [UC7](#uc7--ai-agents-via-the-mcp-server)).

---

## 2. Installation

### Windows / Linux — use the prebuilt binaries

```
dist/windows-x86_64/rop-finder.exe       (Windows CLI)
dist/windows-x86_64/rop-finder-mcp.exe   (Windows MCP server)
dist/linux-x86_64/rop-finder             (Linux CLI — static musl, zero dependencies)
dist/linux-x86_64/rop-finder-mcp         (Linux MCP server)
```

Copy the two files for your OS anywhere you like (e.g. a directory on your `PATH`). The Linux binaries are statically linked against musl — they run on any x86_64 distro with no glibc requirement.

### macOS — build from source (~2 minutes)

Prebuilt macOS binaries can't be produced off Apple hardware (Apple SDK licensing). On any Mac:

```sh
xcode-select --install          # once, provides the C compiler
sh dist/macos-arm64/build-macos.sh
```

The script installs Rust if needed, builds, and places the binaries next to itself. Works on both Apple Silicon and Intel Macs.

### Build from source (any OS)

```sh
# needs: rustup (https://rustup.rs) + a C compiler (MSVC / gcc / clang)
git clone <repo-url> && cd rop-finder
cargo build --release
# → target/release/rop-finder(.exe), target/release/rop-finder-mcp(.exe)
```

Verify your install:

```sh
rop-finder --version     # rop-finder 0.1.0
```

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
| `--section <glob>` | Scan only named executable sections; repeatable, comma-separated, `*` glob (`--section ".text,.init*"`) |
| `--range <0xA-0xB>` | Restrict to an address range (applied inside `--section` if both given) |
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
| `--only "pop|ret"` | Keep gadgets containing only these mnemonics |
| `--filter "leave|enter"` | Suppress mnemonics (suffix match) |
| `--badbytes "00|0a-0d"` | Reject gadgets whose **final** address contains these bytes |
| `--cfg-aware` | Keep only `endbr64/endbr32`-aligned gadget entries (CET targets) |

**Output**

| Flag | Effect |
|---|---|
| `--json` | JSON array of `{vaddr, bytes, text, section, ...}` |
| `--classify` | Add semantic fields to JSON (class, regs_written, quality, …) |
| `--rank` | Sort best-quality gadgets first |
| `--cache` | Disk-cache scan results (see [§9](#9-performance-guide)) |
| `--info` | Print image metadata JSON and exit (no scan) |

**Chain generation**

| Flag | Effect |
|---|---|
| `--ropchain` | Generate a chain (Python script; JSON IR with `--json`) |
| `--chain <target>` | `linux-execve` (default) or `windows-virtualprotect` |
| `--api-addr <hex>` | Runtime address of the target API (Windows) |
| `--shellcode-addr <hex>` | Where your shellcode will live (default: writable `.data`) |
| `--shellcode-size <hex>` | `dwSize` for VirtualProtect (default `0x1000`) |

**Exit codes:** `0` success · `1` usage error (bad flags, unknown section, missing gadgets) · `2` malformed/unreadable binary.

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

Kernel exploits must only use gadgets from **non-pageable** memory. In `ntoskrnl.exe`, most sections can be paged out — `.text` can't. Instead of computing RVA ranges by hand:

```sh
rop-finder --binary ntoskrnl.exe --section .text --base 0 --json > gadgets.json
```

- `--section .text` — only the non-pageable section is scanned (glob patterns work: `--section ".text,PAGE*"`).
- `--base 0` — RVA output for the ASLR'd kernel base you recover at runtime.
- Bonus: ntoskrnl is CET-marked; add `--cfg-aware` to keep only `endbr64`-aligned gadget entries (rop-finder prints a warning when you scan a GUARD_CF binary without it).

Measured on the shipping ntoskrnl: ~627K gadgets total, including the `pop rcx/rdx/r8/r9` gadgets needed for Win64-call-convention chains (see `tests/spike-report.md`).

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

That's a property of the binary, not a tool failure — point the same command at ntoskrnl.exe or a gadget-rich binary and it succeeds. x86 targets use stdcall (arguments on the stack) and rarely have this problem.

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

**The 7 tools:**

| Tool | What it does |
|---|---|
| `find_gadgets` | ROP gadgets (params: depth, section, base, offset, only, range, badbytes, max_results, sort_by) |
| `find_jop_gadgets` | JOP gadgets |
| `find_syscall_gadgets` | syscall gadgets |
| `get_binary_info` | format/arch/sections/imports metadata |
| `search_gadgets_by_pattern` | regex/substring search over gadget text |
| `run_ropgadget_command` | full flag passthrough (allowlisted) |
| `build_rop_chain` | Linux execve or Windows VirtualProtect chain as JSON IR + Python script |

**Security model (important):**
- The server can only read binaries inside `--allow-dir` directories (default: its working directory). Paths are canonicalized; `..` escapes and symlink escapes are rejected.
- `run_ropgadget_command` enforces a flag allowlist — no `--string`/`--dump` (they'd leak arbitrary file contents).
- Every call is capped (`--max-results`, default 1000, hard max 50000; `--timeout-secs`, default 60).
- Results are cached by content hash — repeat agent queries on the same binary are near-instant. Add `--cache-dir` for persistence.
- `sort_by: "quality"` returns the *best* gadgets first, so agents don't drown in noise.

Example agent prompt once configured: *"Use rop-finder to check whether ntoskrnl.exe in the allowed directory has gadgets to populate rcx, rdx, r8, r9, then build a VirtualProtect chain and save the Python script."*

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

Only gadgets whose entry point is an `endbr64`/`endbr32` survive. When you scan a GUARD_CF-marked PE *without* the flag, rop-finder warns you on stderr so you don't build a chain that's dead on arrival.

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

The classifier is tested against a labeled set of 5,744 gadgets (macro-avg precision 1.0 on held-out data).

---

## 9. Performance guide

| Situation | Recommendation |
|---|---|
| Repeated scans of one big binary | `--cache` — second run is near-instant. Override location with `ROP_FINDER_CACHE_DIR` |
| Only need one section | `--section .text` skips the rest of the binary |
| Huge binaries (100+ MB) | Lower `--depth` first (10 → 6 cuts candidates dramatically), then `--section` |
| Just exploring | `--depth 5` is ~4× faster than 10 and covers most useful gadgets |
| Scripting | `--json` + `--cache`; or the MCP server which caches automatically |

Reference numbers (this project's benchmark, best-of-3): x64 bash ELF — 0.25 s for 45K gadgets; x64 cmd.exe PE — 0.07 s for 12.5K gadgets. The scanner parallelizes across sections automatically (rayon).

---

## 10. Troubleshooting & FAQ

**"Unknown section" / exit 1 with a section list.**
The name you passed to `--section` doesn't exist. The error message lists available executable sections — check spelling. On **stripped ELFs** there are no section names; you get `PT_LOAD#n` segment names (a stderr warning tells you), which are coarser than real sections.

**"can't find a suitable gadget …" during `--ropchain`.**
The binary genuinely lacks a required gadget class (common for `pop rdx/r8/r9` on x64 PEs). Try: a different target binary (e.g. a DLL), `--depth` higher, or manual chain construction from `--json --classify` output. The error names the exact missing piece.

**Gadget addresses look wrong under ASLR.**
You're comparing absolute addresses across runs. Use `--base 0` (RVA) for analysis and add the leaked base at exploit time — or pass the leaked base via `--base`.

**Different output from ROPgadget?**
~0.07% of gadgets differ due to disassembler-version drift (capstone vs iced-x86 decode disagreements); sets are 99.93% identical. Ordering also differs: rop-finder sorts by address (or quality with `--rank`).

**`--badbytes` seems to reject too much after `--base`.**
By design: bad bytes are checked on the **final** address (after rebase and offset), because that's what goes into your payload. If you rebased to an address containing a bad byte (e.g. `0x55550000` with badbyte `55`), every gadget is correctly rejected.

**Broken pipe panic when piping to `head`.**
A known Rust-on-Windows quirk when the reader closes the pipe early; the output up to that point is correct. Use `cmd /c "rop-finder … | more"` or `--json | python -m json.tool` for interactive browsing.

**Mach-O universal binaries.**
All slices are scanned with the first slice's architecture (matching ROPgadget). Per-slice metadata: `--info`.

---

## 11. Responsible use

rop-finder is a dual-use security tool built for **defensive research, CTFs, authorized penetration testing, and exploit-mitigation evaluation**. Finding gadgets in binaries you own or are authorized to test is standard practice; using them against systems without authorization is not. The MCP server is deliberately local-only (stdio, directory-allowlisted) — keep it that way unless you add proper authentication.

---

*Project layout, architecture, and the phase-by-phase development plan live in [README.md](README.md) and [PLAN.md](../PLAN.md). Classification rules: [TAXONOMY.md](TAXONOMY.md). Windows chain feasibility data: [tests/spike-report.md](tests/spike-report.md).*
