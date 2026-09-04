# rop-finder — Getting Started

This is the **operator guide**: how to get a `rop-finder` binary onto a machine, prove it runs,
drive it from a shell, wire the MCP server into an AI host, keep that wiring safe, and diagnose it
when it breaks — on Windows, Linux and macOS. It is task-shaped and deliberately opinionated: each
section tells you what to type and what you should see back.

It is **not** the flag reference. Every flag, its exact semantics, the ROPgadget compatibility
notes, the output-format schemas and the use cases UC1–UC9 live in [`MANUAL.md`](../MANUAL.md).
[`README.md`](../README.md) is the project overview — what the tool is and why it exists. Come here
to learn the shape of a working command and a working install; go to MANUAL.md for the details of
any one switch. Where the two would overlap, this guide links rather than restates.

**Every command block below was executed while writing this guide**, on Windows 11 against
`dist/build/windows-x86_64/` and under WSL2 Ubuntu against `dist/build/linux-x86_64/`, both built
from this workspace at `v1.0.0-rc1`. Output is real, trimmed with `…` where it ran long. The few
things that could **not** be executed here — all macOS behaviour, Windows Mark-of-the-Web, and
Claude Desktop end to end — are labelled *not executed here* at the point they appear and collected
in [Known limits](#10-known-limits). Nothing in this document is aspirational unless it says so.

---

## Table of contents

- [1. What you are installing](#1-what-you-are-installing)
- [2. Getting a binary](#2-getting-a-binary)
  - [A. crates.io — the intended route, not yet available](#a-cratesio--the-intended-route-not-yet-available)
  - [B. Build from source — the route that works today](#b-build-from-source--the-route-that-works-today)
  - [C. The release workflow — written, never run](#c-the-release-workflow--written-never-run)
- [3. Installing it](#3-installing-it)
  - [Windows](#windows)
  - [Linux](#linux)
  - [macOS — not executed here](#macos--not-executed-here)
- [4. Verifying what you got](#4-verifying-what-you-got)
- [5. The 60-second smoke test](#5-the-60-second-smoke-test)
- [6. Using the CLI](#6-using-the-cli)
  - [Finding gadgets](#finding-gadgets)
  - [Choosing engines](#choosing-engines)
  - [The ROPgadget-era text filters](#the-ropgadget-era-text-filters)
  - [Asking a real question instead of grepping](#asking-a-real-question-instead-of-grepping)
  - [Sequence matching with search and re](#sequence-matching-with-search-and-re)
  - [Two traps in register names](#two-traps-in-register-names)
  - [Searching for data instead of code](#searching-for-data-instead-of-code)
  - [Reconnaissance before you scan](#reconnaissance-before-you-scan)
  - [Output for humans and for scripts](#output-for-humans-and-for-scripts)
  - [Chains](#chains)
  - [Caching](#caching)
- [7. Where the operating system genuinely matters](#7-where-the-operating-system-genuinely-matters)
- [8. The MCP server](#8-the-mcp-server)
  - [What the server actually is](#what-the-server-actually-is)
  - [The allowlist is the whole security model](#the-allowlist-is-the-whole-security-model)
  - [Verify the server before you touch any host config](#verify-the-server-before-you-touch-any-host-config)
  - [Claude Desktop](#claude-desktop)
  - [Claude Code](#claude-code)
  - [What the agent can do](#what-the-agent-can-do)
  - [Operating it safely](#operating-it-safely)
- [9. Troubleshooting](#9-troubleshooting)
  - [First run](#first-run)
  - [CLI errors](#cli-errors)
  - [MCP server startup and calls](#mcp-server-startup-and-calls)
- [10. Known limits](#10-known-limits)
- [11. What this guide does not cover](#11-what-this-guide-does-not-cover)

---

## 1. What you are installing

There are two binaries and you almost certainly want both:

| Binary | What it is | How it talks |
| --- | --- | --- |
| `rop-finder` | the CLI | argv in, text/JSON/JSONL/CSV out |
| `rop-finder-mcp` | the MCP server | **stdio only** — no HTTP, no socket, no port |

Both report version `1.0.0` and are built from the same workspace: `crates/rf-cli` publishes as the
package `rop-finder`, `crates/rf-mcp` as `rop-finder-mcp`. Neither needs the other. You can install
only the CLI, or only the server.

---

## 2. Getting a binary

Three routes. Two of them do not work yet, and it is better to know that now than after ten minutes
of debugging.

| Route | State today | Needs a C toolchain? | Use it when |
| --- | --- | --- | --- |
| **A. crates.io** (`cargo install`) | **Not published.** Dry-runs pass; nothing is uploaded. | Yes | Later, once it is published. Intended default. |
| **B. Build from source** (`dist/` scripts) | Works. Both binaries used throughout this guide came from here. | Yes | Today. |
| **C. Release workflow artifacts** | `.github/workflows/release.yml` exists and **has never run**. | No | Later, once a `v*` tag is pushed to a remote. |

### A. crates.io — the intended route, not yet available

When publishing happens, this will be the whole install:

```bash
cargo install rop-finder        # -> rop-finder
cargo install rop-finder-mcp    # -> rop-finder-mcp
```

Right now both fail. Verified on Windows, 2026-09-04:

```bash
$ cd /tmp && cargo info rop-finder
    Updating crates.io index
error: could not find `rop-finder` in registry `https://github.com/rust-lang/crates.io-index`
# exit 101

$ cargo info rop-finder-mcp
    Updating crates.io index
error: could not find `rop-finder-mcp` in registry `https://github.com/rust-lang/crates.io-index`
# exit 101
```

> **Gotcha that will waste your time.** Run that check from *outside* the repo. Inside the
> workspace, `cargo info rop-finder` resolves the **local** `crates/rf-cli` path and prints a
> perfectly convincing crate record — which says nothing at all about crates.io:
>
> ```
> rop-finder #rop #gadget #ropgadget #exploit #security
> A fast, memory-safe ROP/JOP/SYS gadget finder with ROPgadget output parity, …
> version: 1.0.0 (from .\crates\rf-cli)
> ```

Note also that `cargo install` still compiles `capstone-sys` from source, so it needs the same C
toolchain as route B. It is less work, not zero work.

### B. Build from source — the route that works today

Three committed scripts, one per OS:

| Script | Produces | Notable options |
| --- | --- | --- |
| `dist/build-linux.sh` | `dist/build/linux-<arch>/` | `--arch x86_64\|aarch64` |
| `dist/build-windows.ps1` | `dist/build/windows-x86_64/` | none |
| `dist/build-macos.sh` | `dist/build/macos-<arch>/` | `--universal`, `--sign "Developer ID Application: NAME (TEAMID)"`, `--notarize-profile NAME` |

Each writes both binaries, a `SHA256SUMS`, and an archive.

**Every platform needs a C compiler.** `rf-scan` depends on `capstone-sys`, which compiles roughly
44 MB of vendored C with the `cc` crate. A Rust toolchain alone is not enough anywhere:

| OS | C toolchain | What the script does about it |
| --- | --- | --- |
| Linux | `cross` (preferred), or `<arch>-linux-musl-gcc` from `musl-tools`, or `zig` | `build-linux.sh` picks whichever it finds, in that order, and exits with `error: need one of: cross, <arch>-linux-musl-gcc, or zig` if none is present |
| Windows | MSVC C++ build tools (`cl.exe`) | `build-windows.ps1` **warns** if `cl.exe` is not on `PATH` and carries on — the failure then comes from deep inside a build script |
| macOS | Xcode Command Line Tools | `build-macos.sh` **refuses to start** unless `xcode-select -p` succeeds |

Rust floor is `rust-version = "1.88"` in `Cargo.toml`; `rust-toolchain.toml` pins the tested
compiler to `1.89.0`, which is what produced the artifacts used throughout this guide.

Both shell scripts pass `bash -n`:

```bash
$ bash -n dist/build-macos.sh && echo "build-macos.sh: syntax OK"
build-macos.sh: syntax OK
$ bash -n dist/build-linux.sh && echo "build-linux.sh: syntax OK"
build-linux.sh: syntax OK
```

That is the *only* thing verified about `dist/build-macos.sh`. It **has never been executed** — no
macOS machine was available — so no macOS artifact has ever existed. Treat its output paths as
intent, not as observed behaviour.

The scripts were also not re-run while writing this guide: re-running `dist/build-windows.ps1`
would delete and regenerate `dist/build/windows-x86_64/`, changing the checksums quoted below.

### C. The release workflow — written, never run

`.github/workflows/release.yml` triggers on `push: tags: ['v*']`. It builds six targets
(`x86_64`/`aarch64` musl Linux, universal macOS, `x86_64`/`aarch64` MSVC Windows), packages each
with `LICENSE`, `NOTICE`, `README.md` and `MANUAL.md`, writes a `.sha256` next to each archive, and
then runs a `smoke` job that re-downloads each artifact on its own OS, verifies the checksum,
asserts `test -x`, and runs `--version`. It is a good pipeline.

**It has never run.** Six tags exist locally —

```bash
$ git tag -l
v0.1.1
v0.2.0
v0.3.0
v0.4.0
v0.5.0
v1.0.0-rc1

$ git remote -v
# (no output — no remote is configured)
```

— but the repository has **no configured git remote**, so nothing has ever been pushed, GitHub
Actions has never fired, and there are no release assets to download. Do not point anyone at a
releases page yet.

One difference worth knowing for when both exist: the local `dist/build-linux.sh` tarball is
**flat**, while the CI tarball unpacks into a `rop-finder-<version>-<target>/` directory. The flat
layout is observed; the CI layout is read from the workflow (lines 119–132), not observed.

```bash
$ tar -tvzf dist/build/linux-x86_64/rop-finder-linux-x86_64-musl.tar.gz
-rwxr-xr-x root/root  11951344 2026-09-04 12:59 rop-finder
-rwxr-xr-x root/root  14895696 2026-09-04 12:59 rop-finder-mcp
```

---

## 3. Installing it

### Windows

Put the two `.exe` files somewhere on `PATH`. A per-user location that needs no admin rights:

```powershell
$d = "$env:LOCALAPPDATA\Programs\rop-finder"
New-Item -ItemType Directory -Force $d | Out-Null
Copy-Item .\dist\build\windows-x86_64\rop-finder.exe     $d -Force
Copy-Item .\dist\build\windows-x86_64\rop-finder-mcp.exe $d -Force
$env:PATH = "$d;$env:PATH"     # this session only
"which: " + (Get-Command rop-finder).Source
rop-finder --version | Select-Object -First 1
rop-finder-mcp --version
```

Verified:

```
which: C:\Users\razavi\AppData\Local\Programs\rop-finder\rop-finder.exe
rop-finder 1.0.0
rop-finder-mcp 1.0.0
```

To make it permanent, add `%LOCALAPPDATA%\Programs\rop-finder` to your user `Path` in
`System Properties -> Environment Variables`, then open a new shell.

**SmartScreen and Mark of the Web.** A binary you **downloaded** carries a `Zone.Identifier`
alternate data stream and Defender SmartScreen will interpose on first run. A binary you **built
locally** does not. Only the negative case could be checked here — nothing on this machine was
downloaded:

```powershell
PS> Get-Item "$d\rop-finder.exe" -Stream Zone.Identifier
# -> FileNotFoundException: no Zone.Identifier stream (locally built, not downloaded)
```

If the stream *is* there — which is what you will see once route C exists — strip it **after** you
have verified the checksum, not before:

```powershell
Get-Item .\rop-finder.exe -Stream Zone.Identifier   # confirm it's there
Unblock-File .\rop-finder.exe                       # remove it
```

*`Unblock-File` was not executed here — there is nothing downloaded on this machine to unblock.*

Shell-level Windows gotchas — the PowerShell call operator, redirection, and pipeline exit codes —
are in [Where the operating system genuinely matters](#7-where-the-operating-system-genuinely-matters).

### Linux

The shipped Linux binary is **static musl**. There is no glibc requirement, no `LD_LIBRARY_PATH`,
nothing to match against the host distro:

```bash
$ file dist/build/linux-x86_64/rop-finder
dist/build/linux-x86_64/rop-finder: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped

$ ldd dist/build/linux-x86_64/rop-finder
	not a dynamic executable
```

Install to `~/.local/bin` (on `PATH` for most distros) with `install -m 0755`, which sets the mode
for you:

```bash
mkdir -p ~/.local/bin
install -m 0755 dist/build/linux-x86_64/rop-finder     ~/.local/bin/
install -m 0755 dist/build/linux-x86_64/rop-finder-mcp ~/.local/bin/
command -v rop-finder && rop-finder --version | head -1 && rop-finder-mcp --version
```

Verified:

```
/home/razavi/.local/bin/rop-finder
rop-finder 1.0.0
rop-finder-mcp 1.0.0
```

**The executable bit (finding ENG-09).** `install -m 0755` is not decoration. The tarball stores
mode `0755` and `tar -xzf` restores it; a raw single-file download over HTTP does not, and neither
does a plain `cp` off a Windows filesystem. The failure looks like this — reproduced by copying the
binary and `chmod 644`:

```bash
$ ls -l /tmp/rfdl/rop-finder
-rw-r--r-- 1 razavi razavi 11951344 Sep  4 13:35 /tmp/rfdl/rop-finder
$ /tmp/rfdl/rop-finder --version
bash: /tmp/rfdl/rop-finder: Permission denied
# exit 126
$ chmod +x /tmp/rfdl/rop-finder && /tmp/rfdl/rop-finder --version | head -1
rop-finder 1.0.0
# exit 0
```

Exit 126 with `Permission denied` on a file you can plainly read is always this, never a broken
build. Prefer the tarball, whose listing above shows it preserves `0755`.

### macOS — not executed here

**No macOS machine was available for any part of this project, and no macOS artifact has ever been
built.** Everything in this subsection is derived from `dist/build-macos.sh` and `release.yml`, both
of which are written and syntax-checked but unrun. Nothing below has been observed. Verify it
yourself before you rely on it.

*Toolchain.* `build-macos.sh` refuses to start without the Xcode Command Line Tools, because
`capstone-sys` otherwise fails deep inside a build script with an unhelpful message:

```bash
xcode-select -p || xcode-select --install
```

*Architecture.* `./dist/build-macos.sh` builds natively — arm64 on Apple Silicon, x86_64 on Intel.
`./dist/build-macos.sh --universal` builds both and `lipo`s them into one binary that runs on
either. If you distribute to a mixed fleet, build universal; the CI job does.

*Gatekeeper quarantine.* A downloaded, unsigned binary gets the `com.apple.quarantine` extended
attribute and macOS will refuse to run it ("cannot be opened because the developer cannot be
verified"). After you have verified the checksum:

```bash
xattr -d com.apple.quarantine ./rop-finder ./rop-finder-mcp
```

The proper fix is signing and notarisation, which `build-macos.sh` supports via
`--sign "Developer ID Application: NAME (TEAMID)"` and `--notarize-profile NAME` (the script
requires `--sign` whenever `--notarize-profile` is given). The workflow's macOS job builds
**unsigned** when no signing secrets are configured, so assume you will need the `xattr` step until
someone wires a certificate up. Building from source locally avoids quarantine entirely, since the
file was never downloaded.

---

## 4. Verifying what you got

**`--version`.** Byte-for-byte identical on Windows and in WSL2 Ubuntu; exit 0 on both:

```
rop-finder 1.0.0
capstone 5.0 (bundled; decodes ARM, ARM64, MIPS, PPC, SPARC, RISC-V)
iced-x86 (decodes x86/x64)
A port of ROPgadget by Jonathan Salwan, Alexey Vishnyakov and contributors (BSD-3-Clause):
https://github.com/JonathanSalwan/ROPgadget
```

`rop-finder-mcp --version` prints the single line `rop-finder-mcp 1.0.0`.

Both `-v` and `-V` are bound to `--version` and both exit 0, so a ROPgadget script that opens with a
`-v` capability probe works unchanged.

**Checksums.** Each build directory carries a `SHA256SUMS` in the standard `<hash>  <filename>`
format, with bare filenames — run the check *from inside that directory*.

Linux (and macOS via `shasum`):

```bash
$ cd dist/build/linux-x86_64 && sha256sum -c SHA256SUMS
rop-finder: OK
rop-finder-mcp: OK
rop-finder-linux-x86_64-musl.tar.gz: OK
# exit 0
```

On macOS `sha256sum` is usually absent; use `shasum -a 256 -c SHA256SUMS` instead. *(Not executed —
no macOS machine.)*

Windows has no `sha256sum`. `Get-FileHash` plus a one-liner does the same job:

```powershell
Set-Location .\dist\build\windows-x86_64
Get-Content .\SHA256SUMS | ForEach-Object {
    $p = $_ -split '\s+', 2
    $got = (Get-FileHash -Algorithm SHA256 $p[1].Trim()).Hash.ToLower()
    if ($got -eq $p[0]) { "$($p[1].Trim()): OK" } else { "$($p[1].Trim()): FAILED" }
}
```

```
rop-finder.exe: OK
rop-finder-mcp.exe: OK
rop-finder-windows-x86_64.zip: OK
```

`Get-FileHash` returns uppercase hex; `sha256sum` writes lowercase. The `.ToLower()` above is why
the comparison works — omit it and every line says FAILED.

---

## 5. The 60-second smoke test

Two commands. Run them from the repo root, because both use a committed fixture.

**1. The CLI produces the right number of gadgets.** This fixture is also the ROPgadget 7.7 oracle
case, so the count is a real correctness assertion, not just "it started":

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x86 --depth 10 | tail -6
0x0807d540 : xor esi, esi ; pop ebx ; mov eax, esi ; pop esi ; pop edi ; pop ebp ; ret
0x0807d14c : xor esi, esi ; ret 0xf01
0x080c7bad : xor esi, esi ; test ebx, ebx ; jne 0x80c7bd0 ; jmp 0x80c7bf8
0x0808e088 : xor esi, esi ; xor ecx, ecx ; jmp 0x808d2c9

Unique gadgets found: 42508
```

Identical output on Windows and Linux. **42508 is the number.** Anything else means the install is
wrong, not that your machine is different. Wall clock here, three runs each: 0.13 s on Windows,
0.70 s under WSL2 (which reads the fixture across the `/mnt/d` filesystem) — the "60 seconds" is you
typing, not the tool working. (The ROPgadget 7.7 agreement is
cross-referenced from [`docs/measured-2026-09.md`](measured-2026-09.md); the oracle itself was not
re-run while writing this guide.)

**2. The MCP binary refuses to start unsafely.** This is the fastest proof that the server binary is
the real thing, and it needs no MCP client:

```bash
$ rop-finder-mcp
rop-finder-mcp: refusing to start with no --allow-dir. The MCP host chooses this process's
working directory, so defaulting to it would grant access to whatever the host happened to
pick (currently: /mnt/d/Private/ROP-Finder/rop-finder). Pass --allow-dir <dir> for each
directory of binaries you want the agent to analyse, or --allow-cwd to deliberately serve
the working directory.
# exit 2
```

Same message and same exit 2 on Windows, with the Windows cwd substituted. If you get exit 2 and
that paragraph, the server binary is installed and its allowlist enforcement is live. Why it
behaves this way, and what to do next, is [The allowlist is the whole security
model](#the-allowlist-is-the-whole-security-model). To watch it actually speak protocol before you
touch any host config, go to [Verify the server before you touch any host
config](#verify-the-server-before-you-touch-any-host-config).

---

## 6. Using the CLI

A task tour: what you actually type to get an answer out of `rop-finder`. Three shells appear below:

| Shown as | Shell | Binary invoked |
| --- | --- | --- |
| ```bash``` from repo root | Git Bash on Windows 11 | `./dist/build/windows-x86_64/rop-finder.exe` |
| ```bash``` marked *(WSL)* | `wsl.exe -d Ubuntu` | `./dist/build/linux-x86_64/rop-finder` |
| ```powershell``` | Windows PowerShell 5.1 | `dist\build\windows-x86_64\rop-finder.exe` |

Where a command reads `rop-finder`, it was run through one of those paths; the fixtures ship with
the repository, so you can reproduce every number here. Nothing in this section was run on macOS —
the CLI has no platform-specific command surface, so the commands should transcribe directly, but
treat every macOS claim as *not executed here*.

### Finding gadgets

The zero-thought invocation. `--depth` defaults to 10, all three engines are on:

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --depth 10 | tail -1

Unique gadgets found: 43972
```

**`--depth` is the single biggest lever.** Depth is the maximum number of instructions *before* the
terminator. It costs you roughly linearly in gadget count and superlinearly in the noise you have to
read. On `tests/fixtures/elf-Linux-x64`:

| `--depth` | Unique gadgets |
| --- | --- |
| 2 | 8,158 |
| 3 | 12,334 |
| 5 | 21,003 |
| 10 *(default)* | 43,972 |
| 20 | 84,772 |

Start at the default. Only raise it when a constrained query comes back empty and you have reason to
believe a longer gadget would satisfy it.

### Choosing engines

Three independent engines run by default; `--norop`, `--nojop` and `--nosys` switch them off. Same
binary, depth 10:

| Command | Unique gadgets | What you get |
| --- | --- | --- |
| *(no flags)* | 43,972 | everything |
| `--nojop --nosys` | 8,389 | ROP only — `ret`-terminated |
| `--norop --nosys` | 35,104 | JOP only — `jmp`/`call`-terminated |
| `--norop --nojop` | 823 | SYS only — `syscall`/`int 0x80`/`sysenter` |
| `--norop` | 35,854 | JOP + SYS |
| `--nojop` | 9,207 | ROP + SYS |
| `--nosys` | 43,227 | ROP + JOP |

On this binary JOP is 80% of the raw output. If you are building a classic stack-based chain,
`--nojop --nosys` cuts the listing by 5x before you have written a single filter.

### The ROPgadget-era text filters

These are string filters over the printed instruction text. They are cheap, blunt, and still useful
for a first pass. All measured on `elf-Linux-x64` at the default depth:

| Command | Result | Note |
| --- | --- | --- |
| `--only "pop\|ret"` | 596 | keep only gadgets whose every mnemonic is `pop` or `ret` |
| `--filter "leave\|enter"` | 43,386 | drop gadgets containing `leave` or `enter` |
| `--filter "j.*"` | 10,224 | drop everything with a jump — near-equivalent to `--nojop` here |
| `--align 8` | 9,715 | keep only 8-byte-aligned addresses |
| `--callPreceded` | 10,654 | only gadgets immediately preceded by a `call` |
| `--all` | 72,036 | **disable** deduplication (72,036 raw vs 43,972 unique) |
| `--section .text` | 40,184 | scope to one section |
| `--section ".plt,.init"` | 72 | comma-separated section list |
| `--range 0x401000-0x402000` | 410 | scope to an address range |

`--filter` is a full-match regex alternation against each *mnemonic*, not a substring test.
`--filter "op"` removes nothing — it does not match `pop`. That is deliberate ROPgadget
compatibility; MANUAL.md documents it.

`--callPreceded` also prints a progress line, exactly as ROPgadget does — **on stdout, with the
gadgets**, not on stderr:

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --callPreceded --silent > out.txt 2> err.txt
$ cat out.txt
Options().removeNonCallPreceded(): Filtered out 33318 gadgets.
$ cat err.txt      # empty
```

If you are parsing gadget lines out of stdout, filter that line out.

### Asking a real question instead of grepping

This is the part that makes `rop-finder` different from piping ROPgadget into `grep`. The constraint
layer filters on *what a gadget does to machine state*, computed from a semantic classification of
each gadget, not on how it happens to be spelled.

The canonical example. "Give me a gadget that loads `rdi` from my payload, does not touch `rsi` or
`rdx`, has at most one side effect, and returns":

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 \
    --set-reg rdi --from-stack \
    --no-clobber rsi,rdx \
    --max-side-effects 1 \
    --terminator ret

Gadgets information
============================================================
0x0000000000401648 : pop rdi ; ret

Unique gadgets found: 1
```

**43,972 gadgets down to exactly one.** Verified byte-for-byte on Windows and, via WSL, on the Linux
build — same address, same text, same count.

The funnel, one constraint at a time, so you can see where the leverage is:

| Constraints (cumulative) | Remaining |
| --- | --- |
| *(none — the default scan)* | 43,972 |
| `--set-reg rdi` | 318 |
| `+ --from-stack` | 89 |
| `+ --no-clobber rsi,rdx` | 79 |
| `+ --max-side-effects 1` | 37 |
| `+ --terminator ret` | **1** |

The first three rows were re-run under WSL against the Linux binary and produced 318 / 89 / 79
identically.

**What each constraint means, in one line.** Full semantics in [`MANUAL.md`](../MANUAL.md); this
table is only so you can pick the right one. Every number was measured on `elf-Linux-x64`:

| Flag | Keeps a gadget when… | Example measured |
| --- | --- | --- |
| `--set-reg <regs>` | it writes those regs with a *payload-controlled* value | `--set-reg rdi` → 318 |
| `--from-stack` | that write comes off the stack (a `pop` or `[rsp+n]` load), not a computation | `--set-reg rdi --from-stack` → 89 |
| `--writes-reg <regs>` | it writes all those regs by any means | `--writes-reg rdi,rsi` → 471 |
| `--no-clobber <regs>` | it does *not* destroy those regs | see funnel |
| `--reads-reg <regs>` | it reads all those regs (operand, address, or branch target) | `--reads-reg rdi` → 3,644 |
| `--max-stack-delta <n>` | rsp moves at most n bytes | `--set-reg rdi --from-stack --max-stack-delta 16` → 81 |
| `--max-side-effects <n>` | at most n side effects | see funnel |
| `--max-insns <n>` | at most n instructions, terminator included | `--set-reg rdi --max-insns 2` → 122 |
| `--terminator <kinds>` | it ends in one of those | 14 values, listed in the error below |
| `--class <classes>` | its *primary* class is one of these | `--class syscall --max-insns 2` → 105 |
| `--label <labels>` | it carries at least one of these labels | `--label stack-pivot` → 5,243 |
| `--pivot` | preset: exactly `--label stack-pivot` | → 5,243 (identical) |
| `--search <pattern>` | its instruction run matches a Ropper-style pattern | see below |

`--set-reg` distinguishes a *set* from a *clobber*: `xor rdi, rdi` writes `rdi` but does not take it
from your payload, so `--from-stack` rejects it. That distinction is the whole point of the layer.

A malformed `--terminator` is caught properly and exits 1 — and the error is also the complete list
of legal values:

```
[Error] invalid --terminator value "retn"; valid values are ret, jmp, call, syscall, none, any,
bare-ret, ret-imm, jmp-reg, jmp-mem, call-reg, call-mem, far, other
```

### Sequence matching with search and re

`--search` matches a **contiguous run** of instructions. `?` is any one character, `%` is any run of
characters *within one instruction*:

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --search "pop rdi; ret"

Gadgets information
============================================================
0x0000000000401648 : pop rdi ; ret

Unique gadgets found: 1
```

Same result under WSL. Note this reaches the same single gadget as the semantic query above — but
only because you already knew the answer was spelled `pop rdi ; ret`. `--search` is for when you
know the instructions; the constraint layer is for when you know the *effect*.

Do not confuse `--search` with `--re`. `--re` is ROPgadget's per-instruction regex conjunction:
every `|`-separated pattern must match *some* instruction, anywhere in the gadget, in any order.

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --re "pop r.i" | tail -1

Unique gadgets found: 134
```

134, not 1 — the extra 133 are longer gadgets with junk around the pop.

### Two traps in register names

Both of these exit **0** and print an empty listing. Neither is an error:

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --set-reg r99 | tail -1
Unique gadgets found: 0        # r99 is not a register; nothing warns you

$ rop-finder --binary tests/fixtures/elf-Linux-x64 --set-reg edi | tail -1
Unique gadgets found: 0        # sub-registers are not accepted on x64
```

Register names are **full-width architectural names**: `rdi` not `edi` on x64, `x0` not `w0` on
ARM64. Case does not matter — `--set-reg RDI` also returns 318. If a constraint query returns zero,
check the register spelling *first*.

### Searching for data instead of code

Four searches that do not scan for gadgets at all. Each replaces the gadget scan entirely.

```bash
# --string: byte regex over readable (data) sections
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --string "/proc"
Strings information
============================================================
0x000000000048e708 : /proc
0x000000000048f168 : /proc
0x0000000000491668 : /proc
…
```

It is a regex, not a literal — `--string "m..n"` finds `mbin` at `0x48f37f` and `main` at
`0x48f9e2`, `0x48fb1a`, `0x48fc46`, …

```bash
# --opcode: exact byte sequence in executable sections
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --opcode c9c3
Opcodes information
============================================================
0x0000000000400ae2 : c9c3
0x00000000004010d4 : c9c3
0x00000000004118c0 : c9c3
…
```

**What "no results" looks like, and why it is often correct.**

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x86 --string "/bin/sh"
Strings information
============================================================
# exit 0
```

Empty, exit 0. This is not a bug and not a Windows problem — the identical command under WSL against
the Linux binary is equally empty. That fixture simply contains no contiguous `/bin/sh`. `--memstr`
is the tool for exactly this case: it finds the first occurrence of **each byte** separately, so you
can assemble the string from scattered bytes:

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x86 --memstr "/bin/sh"
Memory bytes information
=======================================================
0x080487ea : '/'
0x08048b59 : 'b'
0x080494d3 : 'i'
0x08048b2e : 'n'
0x080487ea : '/'
0x080485c6 : 's'
0x080481e6 : 'h'
```

Byte-identical under WSL.

> **Git Bash trap — verified.** Run that exact `--memstr "/bin/sh"` in Git Bash and you get `'C'`,
> `':'`, `'/'`, `'P'`, `'r'`, `'o'`, `'g'`, … instead. MSYS2's argument translation rewrote the
> Unix-looking `/bin/sh` into `C:/Program Files/Git/...` before `rop-finder.exe` ever saw it. Fix:
> prefix the command with `MSYS_NO_PATHCONV=1`, which restores the correct 7-byte output above.
> PowerShell and WSL are unaffected. This bites any flag whose *value* starts with `/`.

### Reconnaissance before you scan

`--info` dumps image metadata as JSON and exits **without scanning**, so it is instant even on a
large binary, and it carries checksec-grade mitigation detection.

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --info
```
```json
{
  "addr_size": 8,
  "arch": "x64",
  "endianness": "little",
  "entry": "0x400f78",
  "format": "elf",
  "image_base": "0x400000",
  "imports": [ "…46 entries…" ],
  "sections": [ "…30 entries…" ],
  "symbol_count": 2169,
  "symbols": [ "…2169 entries…" ],
  "mitigations": { "…": "…" },
  "mitigations_order": ["nx","pie","relro","canary","fortify","rpath","runpath"]
}
```

Those arrays are why the full JSON runs to 24,498 pretty-printed lines on this fixture. `--info` is
for a parser, not for reading — pipe it to `jq` or `ConvertFrom-Json`. (The MCP server's
`get_binary_info` differs here: it makes symbols **opt-in** and returns none unless you ask.)

The mitigation set is **format-specific**, and `mitigations_order` tells you the intended reading
order for that format:

| Format | Keys reported |
| --- | --- |
| ELF | `nx`, `pie`, `relro`, `canary`, `fortify`, `rpath`, `runpath` |
| PE | `aslr`, `dep`, `high_entropy_va`, `guard_cf`, `cet_compat`, `safe_seh`, `force_integrity` |

Each entry is `{enabled, detail, evidence}` — and `evidence` states *how* it was decided, which
matters when you are about to argue with someone about a finding *(WSL, Linux binary)*:

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --info | jq '.mitigations.canary'
```
```json
{
  "detail": null,
  "enabled": false,
  "evidence": "no reference to __stack_chk_fail in any of the 2169 named symbols this image carries"
}
```

The one-line summary you will actually use most:

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --info \
  | jq -c '.mitigations | to_entries | map({(.key): .value.enabled}) | add'
```
```json
{"canary":false,"fortify":"unknown","nx":true,"pie":false,"relro":true,"rpath":false,"runpath":false}
```

The PE side is where the evidence strings earn their keep — this is `pe-x64-cmd-v6.1.7601`:

```json
{
  "cet_compat": {
    "detail": null,
    "enabled": false,
    "evidence": "no IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS (type 20) debug-directory record: the image carries no CET marking at all, so Windows will not enable a hardware shadow stack for it and return addresses on the stack are not protected. This is the field that distinguishes real backward-edge protection from GUARD_CF, which is forward-edge only."
  },
  "safe_seh": {
    "detail": "not-applicable",
    "enabled": true,
    "evidence": "COFF Machine=0x8664 is not IMAGE_FILE_MACHINE_I386: on this architecture exception handling is table-driven (the unwind data lives in a read-only directory), so there is no SEH chain on the stack to overwrite and SafeSEH does not apply"
  }
}
```

Note `safe_seh` reports `enabled: true` with `detail: "not-applicable"`. Read `detail` before you
report a mitigation as present.

**A worked recon step on a real binary.** `--info` on something that is not a fixture, to show the
shape of real use:

```powershell
PS> Copy-Item "$env:SystemRoot\System32\ws2_32.dll" "$env:TEMP\target.dll" -Force
PS> & rop-finder --binary "$env:TEMP\target.dll" --info > "$env:TEMP\info.json"   # exit 0
PS> $i = Get-Content "$env:TEMP\info.json" -Raw | ConvertFrom-Json
PS> "format: $($i.format)  arch: $($i.arch)  base: $($i.image_base)  entry: $($i.entry)"
format: pe  arch: x64  base: 0x180000000  entry: 0x180031c20
PS> $i.sections | Select-Object -First 6 | Format-Table -AutoSize
```
```
executable name      size vaddr       writable
---------- ----      ---- -----       --------
      True .text   331776 0x180001000    False
      True _wpp_sf  16384 0x180052000    False
      True fothk     4096 0x180056000    False
     False .rdata   61440 0x180057000    False
     False .data     4096 0x180066000     True
     False .pdata   16384 0x180068000    False
```

That JSON ran to 1,609 lines on this machine — it lists every section and every import — so pipe it
to `jq` or `ConvertFrom-Json` rather than reading it. The exact line count depends on your Windows
build.

If this step fails, nothing downstream will work, and the error is blunt:

```powershell
PS> & rop-finder --binary "C:\nope\missing.exe"
[Error] cannot read C:\nope\missing.exe: The system cannot find the path specified. (os error 3)
# exit 1
```

**Rebasing.** A PIE image reports `image_base: 0x0`, so every address the scanner prints is an
offset, not a runtime address. `/usr/bin/ls` is one *(WSL)*:

```bash
$ rop-finder --binary /usr/bin/ls --info | jq -r '.image_base, .format, .arch'
0x0
elf
x64

$ rop-finder --binary /usr/bin/ls --depth 10 | tail -1
Unique gadgets found: 6523

$ rop-finder --binary /usr/bin/ls --set-reg rdi --from-stack --terminator ret --max-side-effects 1
Gadgets information
============================================================

Unique gadgets found: 0
```

Zero is an answer, not a failure. Relax the constraint by one and it resolves:

```bash
$ rop-finder --binary /usr/bin/ls --set-reg rdi --from-stack --terminator ret --max-side-effects 2
Gadgets information
============================================================
0x0000000000005cb4 : pop rdi ; pop rbp ; ret

Unique gadgets found: 1
```

`0x5cb4` there is an offset. Use `--base` to rebase before you write those numbers into anything.
The semantics of `--base`, `--offset` and `--badbytes` (which applies to the *final* address, after
both) are in [`MANUAL.md`](../MANUAL.md).

### Output for humans and for scripts

`--format` picks the shape. Everything below is one query —
`--set-reg rdi --from-stack --no-clobber rsi,rdx --max-side-effects 2 --terminator bare-ret`, which
yields 3 gadgets on `elf-Linux-x64`.

| `--format` | Shape | Ordering |
| --- | --- | --- |
| `human` *(default)* | banner + `addr : text`, then the `Unique gadgets found:` total | deterministic (by instruction text) |
| `raw` | just `addr : text`, no banner, no total | deterministic (by instruction text) |
| `json` | pretty-printed array of objects | deterministic |
| `jsonl` | one object per line, **streamed during the scan** | scan order |
| `csv` | 19-column header + rows | deterministic |

```bash
$ … --format raw
0x00000000004037e6 : pop rdi ; and byte ptr [rax + 0x39], cl ; ret
0x0000000000400532 : pop rdi ; pop rbp ; ret
0x0000000000401648 : pop rdi ; ret
```

```bash
$ … --format jsonl
{"vaddr":"0x0000000000400532","bytes":"5f5dc3","text":"pop rdi ; pop rbp ; ret"}
{"vaddr":"0x0000000000401648","bytes":"5fc3","text":"pop rdi ; ret"}
{"vaddr":"0x00000000004037e6","bytes":"5f204839c3","text":"pop rdi ; and byte ptr [rax + 0x39], cl ; ret"}
```

`jsonl` is unordered **by design** — records are emitted as they are found so a consumer can start
work before the scan finishes. If you need deterministic order, use `json` or sort downstream.

`--rank` is the flag that reorders **human** output (best quality first, ties by address). The same
three-gadget query with `--rank` puts the clean one first:

```
0x0000000000401648 : pop rdi ; ret
0x0000000000400532 : pop rdi ; pop rbp ; ret
0x00000000004037e6 : pop rdi ; and byte ptr [rax + 0x39], cl ; ret
```

**`--classify` fills in the analysis columns.** By default `json` and `csv` carry only
`vaddr`/`bytes`/`text`; the 16 analysis columns of the CSV are present but **empty**. `--classify`
populates them, and has **no effect on human output**:

```bash
$ … --format json --classify --search "pop rdi; ret"
```
```json
[
  {
    "vaddr": "0x0000000000401648",
    "bytes": "5fc3",
    "text": "pop rdi ; ret",
    "class": "reg-write",
    "labels": ["reg-write"],
    "regs_written": ["rdi"],
    "regs_read": [],
    "side_effects": 1,
    "quality": 100,
    "dispatcher": false,
    "low_confidence": false,
    "sets": ["rdi"],
    "clobbers": [],
    "regs_from_stack": ["rdi"],
    "stack_delta": 16,
    "terminator": "ret",
    "terminator_class": "ret"
  }
]
```

**`--dump`, `--silent`, and the `--noinstr` trap.** `--dump` appends the raw bytes to human output:

```
0x0000000000401648 : pop rdi ; ret // 5fc3
```

`--silent` suppresses gadget printing **and the total line**; the `--callPreceded` notice still
prints. Useful when you only care about the exit code.

`--noinstr` prints bare addresses — and, per its documented behaviour, **disables dedup and sort**.
Your filters still apply, but the line count is no longer the gadget count:

```bash
$ … --format raw --noinstr | wc -l
150      # the same query that reports "Unique gadgets found: 3"
```

150 addresses, 3 unique gadgets. Do not feed `--noinstr` output into anything that assumes one line
per gadget.

**Piping to `jq`** *(WSL / Linux / macOS)*:

```bash
# every clean rdi setter with a small stack delta
$ rop-finder --binary tests/fixtures/elf-Linux-x64 \
    --set-reg rdi --from-stack --max-side-effects 1 --terminator bare-ret \
    --format json --classify \
  | jq -r '.[] | select(.stack_delta <= 16) | "\(.vaddr)  \(.text)"'
0x0000000000401648  pop rdi ; ret
```

```bash
# stream jsonl, then rank by the quality score
$ rop-finder --binary tests/fixtures/elf-Linux-x64 \
    --class reg-write --from-stack --format jsonl --classify \
  | jq -sr 'sort_by(-.quality) | .[0:5] | .[] | "\(.quality)  \(.vaddr)  \(.text)"'
100  0x0000000000400533  pop rbp ; ret
100  0x0000000000400d1e  pop r12 ; ret
100  0x0000000000401648  pop rdi ; ret
100  0x0000000000401647  pop r15 ; ret
100  0x0000000000401767  pop rsi ; ret
```

`jq` is **not** on the PATH in Git Bash on this machine. Either use WSL for jq pipelines, or use
PowerShell's `ConvertFrom-Json` as shown in [Reconnaissance before you
scan](#reconnaissance-before-you-scan).

**Piping to `head` exits 0.**

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 --depth 10 | head -5
Gadgets information
============================================================
0x0000000000465e76 : adc al, 0 ; add byte ptr [rax + 0x39], cl ; retf
0x000000000044861d : adc al, 0 ; add byte ptr [rax - 0x68], cl ; jmp 0x448207
0x00000000004330ff : adc al, 0 ; add byte ptr [rax - 0x7d], cl ; ret 0x4910
$ echo "exit=${PIPESTATUS[0]}"
exit=0
```

Confirmed 0 on both Windows and Linux. Earlier builds panicked with exit 101 when the consumer
closed the pipe early; the broken pipe is now handled. PowerShell's pipeline behaves differently —
see [Where the operating system genuinely
matters](#7-where-the-operating-system-genuinely-matters).

### Chains

`--ropchain` emits a chain, `--plan-chain` explains whether one is even possible. Target is selected
with `--chain`; the default is `linux-execve`.

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x86 --ropchain
```
```python
#!/usr/bin/env python3
# execve generated by ROPgadget

from struct import pack

# Padding goes here
p = b''

p += pack('<I', 0x08056c2c) # pop edx ; ret
p += pack('<I', 0x080f4060) # @ .data
p += pack('<I', 0x080e9563) # pop ecx ; ret
p += b'/bin'
p += pack('<I', 0x0806f702) # mov dword ptr [edx], ecx ; ret
…
```

**The complete target list.** There are exactly six. Results below are from
`tests/fixtures/elf-Linux-x64` (and `pe-x64-cmd-v6.1.7601` for the Windows target):

| `--chain` value | Applies to | Result here | Required extra flags |
| --- | --- | --- | --- |
| `linux-execve` *(default)* | ELF x86/x64 | chain emitted, exit 0 | — |
| `linux-mprotect` | ELF x86/x64 | chain emitted, exit 0 | `--prot` (defaults to 7) |
| `linux-syscall` | ELF x86/x64 | needs `--syscall`, else exit 1 | `--syscall`, `--syscall-args` |
| `linux-ret2libc` | ELF x86/x64 | needs `--api-addr`, else exit 1 | `--api-addr` |
| `linux-srop` | ELF x86/x64 | chain emitted, exit 0 | `--syscall`, `--syscall-args` |
| `windows-virtualprotect` | PE x86/x64 | experimental; failed on this PE | `--api-addr` or an IAT import |

**There is no ARM64 chain target and no MIPS chain target.** Asking for one is a clean, explicit
refusal, not a silent empty chain:

```bash
$ rop-finder --binary tests/fixtures/elf-ARM64-bash --ropchain
[Error] arch arm64 / format elf not supported yet for the rop chain generation      # exit 1

$ rop-finder --binary tests/fixtures/elf-Mips-Defcon-20-pwn100 --ropchain
[Error] arch mips32 / format elf not supported yet for the rop chain generation     # exit 1
```

Chain generation is x86/x64 only. Gadget *finding* works fine on ARM64 and MIPS; only the chain
builders are x86-family.

The two "needs a flag" targets tell you exactly which flag:

```
[Error] can't find a suitable gadget: linux-syscall needs --syscall <n> (the syscall number to invoke)
[Error] can't find a suitable gadget: linux-ret2libc needs --api-addr <runtime address of the
function to call> (e.g. libc's `system`); this builder does not resolve libc symbols
```

Supply it and you get a chain:

```bash
$ rop-finder --binary tests/fixtures/elf-Linux-x64 \
    --ropchain --chain linux-syscall --syscall 59 --syscall-args "rdi=0x404000,rsi=0,rdx=0"
```
```python
p += pack('<Q', 0x0000000000401648) # pop rdi ; ret
p += pack('<Q', 0x0000000000404000) # rdi = 0x404000
p += pack('<Q', 0x0000000000401767) # pop rsi ; ret
p += pack('<Q', 0x0000000000000000) # rsi = 0x0
p += pack('<Q', 0x0000000000447b4d) # xor eax, eax ; pop rdx ; ret
p += pack('<Q', 0x0000000000000000) # rdx = 0x0
…
```

Use `--chain-format` to change the emitted shape: `python` (default), `json` (the Chain IR), or
`raw` (the packed little-endian payload written to stdout **as bytes** — read the PowerShell
redirection warning in [section 7](#7-where-the-operating-system-genuinely-matters) before you
redirect that anywhere).

**`windows-virtualprotect` prints an experimental warning.** Every invocation of that target prints
three warnings on **stderr** before anything else:

```
[Warning] --chain windows-virtualprotect is EXPERIMENTAL: the chain it emits executes under this
project's emulator (tests/emulate.py), not on Windows.
[Warning] The four layout defects this warning used to name — CHWIN-01, CHWIN-02, CHWIN-03,
CHWIN-07 — are fixed in v0.5, each with a failing-before and a passing-after run recorded in
docs/chain-regressions.md.
[Warning] What the emulator cannot check is still yours: that --api-addr is the runtime address,
that rsp really is --chain-base mod 16 at entry, and that CFG/CET is not enforced on the target.
```

Read the third line carefully — that is the actual scope of the warning. The chain layout is
regression-tested against an emulator, not against Windows. Three things the tool cannot verify for
you remain your job: that `--api-addr` is a *runtime* address (not a file offset or an RVA), that
the stack alignment assumption in `--chain-base` matches your real overflow, and that CFG or CET is
not enforced on the target process.

On `pe-x64-cmd-v6.1.7601` the chain does not build at all (exit 1):

```
[Error] can't find a suitable gadget: cannot populate rdx: no 'pop rdx' gadget and no 'pop rax' +
'mov rdx, rax' fallback (see tests/spike-report.md — this is the common case on real PEs)
```

Identical error under WSL against the Linux binary. "This is the common case on real PEs" is not
hedging — Windows binaries genuinely tend not to carry a clean `pop rdx`.

**`--plan-chain`: why it failed, and what would help.** `--plan-chain` never fails. It always emits
JSON describing which requirements the binary meets, what was tried, and which parameter changes
were *measured* (by re-scanning) to help.

```bash
$ rop-finder --binary tests/fixtures/pe-x64-cmd-v6.1.7601 \
    --plan-chain --chain windows-virtualprotect 2>/dev/null \
  | jq -r '"feasible=\(.feasible)",
           (.requirements[] | "  [\(if .satisfied then "ok" else "MISSING" end)] \(.id): \(.description)")'
```
```
feasible=false
  [ok] write_target: a writable section for the shellcode home and, on the VirtualProtect recipe,
       a distinct &lpflOldProtect scratch DWORD (CHWIN-02)
  [ok] set_rcx: rcx must hold 0x4ad2e000 — arg1 lpAddress (shellcode)
  [MISSING] set_rdx: rdx must hold 0x1000 — arg2 dwSize
  [MISSING] set_r8: r8 must hold 0x40 — arg3 flNewProtect PAGE_EXECUTE_READWRITE
  [MISSING] set_r9: r9 must hold 0x4ad2eff8 — arg4 lpflOldProtect (writable scratch, NOT the shellcode)
  [ok] stack_align: a bare `ret` gadget for the one-word alignment slide …
  [MISSING] api_transfer: control must reach VirtualProtect — by an explicit runtime address or by
       dereferencing the PE's own import table
```

Note the `2>/dev/null`: the experimental warnings go to stderr, so `jq` gets clean JSON on stdout
without any filtering.

Each requirement also carries `strategies_tried` (what patterns were searched and how many
candidates each found) and `relaxations` (parameter changes, each with a measured
`would_help: true|false`). On this binary:

```bash
$ … --plan-chain … 2>/dev/null | jq -c '[.requirements[].relaxations[] | select(.would_help)]'
[]
```

Empty. The relaxations that were tried and measured are visible in the raw record —

```json
{"id":"set_rdx","relaxations":[{"from":"10","param":"depth","to":"20","would_help":false},
                              {"from":"false","param":"multibr","to":"true","would_help":false}]}
```

— so raising `--depth` from 10 to 20 and enabling `--multibr` were both tried and both measured as
not helping. That is a definitive "this binary will not do it", not a guess. Stop turning knobs and
find a different module.

The same tool on a binary that *will* work returns `"feasible": true`, and the ELF x64 fixture does;
its full requirement/strategy record is shown from the MCP side in [What the agent can
do](#what-the-agent-can-do), where the output is identical.

### Caching

```bash
$ rop-finder --binary <file> --depth 30 --cache
$ rop-finder --cache-purge
```

`--cache` keys on the binary's content hash plus every scan parameter, so changing `--depth`,
`--section` or any filter produces a different entry. A cached run announces itself on stdout:

```
[Cache] miss v1-0146420bfadda — stored 109878 gadgets
[Cache] hit v1-0146420bfadda (109878 gadgets)
```

`--cache-purge` needs no `--binary`:

```
Purged 1 cache entry (18252048 bytes) from C:\Users\razavi\AppData\Local\rop-finder\cache
```

Cache location and limits, quoted from `--help` (not empirically driven to eviction or expiry here):
`ROP_FINDER_CACHE_DIR`, else `%LOCALAPPDATA%\rop-finder\cache` on Windows or `~/.cache/rop-finder`
elsewhere; size cap `ROP_FINDER_CACHE_MAX_BYTES` (512 MiB default) and lifetime
`ROP_FINDER_CACHE_TTL_SECS` (14 days default).

**Measured honestly:** on the repository fixtures the cache does not pay for itself. Scanning
`elf-x64-bash-v4.1.5.1` at `--depth 30` (109,878 gadgets), three runs each, on this machine:

| | run 1 | run 2 | run 3 |
| --- | --- | --- | --- |
| uncached | 302 ms | 294 ms | 305 ms |
| warm cache hit | 346 ms | 352 ms | 345 ms |

The cached path is consistently *slower*: re-scanning beats reading back the 18 MB cache entry.
Enable `--cache` for large binaries you will re-query repeatedly, not reflexively.

---

## 7. Where the operating system genuinely matters

The gadget engine does not vary by OS. Four things around it do.

**1. Output is byte-identical across platforms.** Verified this session:

```bash
# Windows
$ ./dist/build/windows-x86_64/rop-finder.exe --binary tests/fixtures/elf-Linux-x64 --depth 10 --json > win.json
# WSL / Linux
$ ./dist/build/linux-x86_64/rop-finder      --binary tests/fixtures/elf-Linux-x64 --depth 10 --json > lin.json
```

Both files: **5,992,606 bytes**, both
`sha256 e982483145035d5316930f7e391ee0ce79bbdc218e0d4691a87e991995eaa4dc`, and `cmp` reports no
difference. You can diff a Windows analyst's `--json` output against a Linux CI run and expect a
clean result. *(Not verified on macOS — no macOS machine. The Linux side was exercised under WSL2
Ubuntu on this Windows host, not on a native Linux machine; the static-musl `file`/`ldd` result
above makes that a reasonable proxy, but it is a proxy.)*

**2. PowerShell's `>` silently breaks that byte-identity.** This is the single most likely way to
get a "corrupt" file out of an otherwise correct run:

```powershell
PS> & $B --binary $F --depth 10 --json > out.json
PS> (Get-Item out.json).Length
6212471
PS> (Get-FileHash -Algorithm SHA256 out.json).Hash
F26A1AE9880B1C624AA8D7E654011B07AE73E912E9C25589A46DCCA224F1BFFB
```

Not the 5,992,606 / `E9824831…` above. Windows PowerShell 5.1 re-encodes and CRLF-normalises
anything that flows through `>` or `Out-File`. For text JSON this is merely annoying; for
`--chain-format raw`, which writes **binary payload bytes** to stdout, it silently corrupts the
payload.

Two workarounds, both verified byte-exact (5,992,606 / `E9824831…`):

```powershell
# a. let cmd.exe do the redirection
cmd /c "`"$B`" --binary `"$F`" --depth 10 --json > `"out.json`""

# b. redirect at the process level
Start-Process -FilePath $B `
  -ArgumentList '--binary',$F,'--depth','10','--json' `
  -RedirectStandardOutput out.json -NoNewWindow -Wait
```

Git Bash `>` and WSL `>` are byte-exact with no workaround.

**3. Piping, paging, and the pipeline exit code.**

| Task | bash / WSL / macOS | PowerShell |
| --- | --- | --- |
| first 20 lines | `\| head -20` | `\| Select-Object -First 20` |
| last line (the total) | `\| tail -1` | `\| Select-Object -Last 1` |
| skip a banner | `\| tail -n +3` | `\| Select-Object -Skip 2` |
| count lines | `\| wc -l` | `\| Measure-Object -Line` |
| parse JSON | `\| jq …` | `\| ConvertFrom-Json` |
| exit code after a pipe | `${PIPESTATUS[0]}` | `$LASTEXITCODE` — but read on |

The macOS column asserts POSIX-shell equivalence with bash/WSL, which were measured; macOS itself
was not.

`$LASTEXITCODE` after a PowerShell pipeline depends on whether the pipeline *finished*:

```powershell
# pipeline consumes all output -> the real exit code survives
PS> & $B --binary $F --search "pop rdi; ret" | Out-Null ; $LASTEXITCODE
0

# Select-Object -First N stops the pipeline early -> PowerShell reports -1
PS> & $B --binary $F --depth 10 | Select-Object -First 3 | Out-Null ; $LASTEXITCODE
-1
```

That `-1` (which surfaces as 255 to anything that invoked `powershell.exe`) is PowerShell tearing
down the pipeline, **not** `rop-finder` failing. If you care about the exit code, either let the
pipeline drain or redirect to a file first.

Relatedly, do **not** redirect a native command's stderr in Windows PowerShell 5.1:
`rop-finder-mcp.exe 2>&1` wraps each stderr line in a `NativeCommandError` record and reports a
non-zero exit even when the process is fine. Let stderr go to the console, or redirect to a file
with `2> err.txt`.

**4. Paths and quoting.** Forward slashes work everywhere, including in `.exe` arguments on Windows:

```bash
$ rop-finder --binary D:/Private/ROP-Finder/rop-finder/tests/fixtures/elf-Linux-x64 --search "pop rdi; ret"
0x0000000000401648 : pop rdi ; ret
```

In PowerShell, if the path to the **executable** is quoted, PowerShell parses it as a string
expression, not a command, and the arguments become a syntax error. Reproduced:

```powershell
PS> "$d\rop-finder.exe" --version
At line:1 char:23
+ "$d\rop-finder.exe" --version
+                       ~~~~~~~
Unexpected token 'version' in expression or statement.
The '--' operator works only on variables or on properties.
```

Prefix it with the call operator `&`:

```powershell
PS> & "$d\rop-finder.exe" --version | Select-Object -First 1
rop-finder 1.0.0
```

Paths passed *as arguments* need no such ceremony — quote them normally, and a `$variable` already
holding a spaced path needs no extra quoting at all:

```powershell
PS> & $B --binary "$env:TEMP\rf space test\target bin" --search "pop rdi; ret"
Gadgets information
============================================================
0x0000000000401648 : pop rdi ; ret

Unique gadgets found: 1
```

In `cmd.exe` the rule is simpler — quote any path with a space, and there is no call operator — but
`cmd` has no equivalent of `$env:` interpolation, so use `%TEMP%` style expansion instead. *(That
`cmd.exe` remark is a general statement about the shell; everything here ran through PowerShell and
Git Bash, so there is no `cmd.exe` transcript behind it.)*

And the Git Bash `MSYS_NO_PATHCONV` trap from [Searching for data instead of
code](#searching-for-data-instead-of-code) applies to *any* flag value beginning with `/`.

---

## 8. The MCP server

`rop-finder-mcp` exposes the gadget engine to an AI agent as **15 MCP tools**. This section is the
operator path: what the server is, how to point it at the right directories, how to prove it works
*before* you touch any host config, and what to do when the host shows you nothing at all.

For the tool-by-tool parameter tables, the gadget record schema, and the threat model, see
[`MANUAL.md` UC7](../MANUAL.md#uc7--ai-agents-via-the-mcp-server) and
[`docs/MCP-DESIGN.md`](MCP-DESIGN.md). This section does not repeat them.

### What the server actually is

Read this first; it removes most of the confusion people bring to MCP.

- It speaks **JSON-RPC over stdio**. Requests arrive on stdin, responses go out on stdout, one JSON
  object per line.
- **There is no port and no network listener.** Nothing binds, nothing accepts. You cannot `curl`
  it, you cannot point a browser at it, and "which port does it run on" has no answer.
- **It is not a daemon.** You do not start it and leave it running. The MCP host (Claude Desktop,
  Claude Code) launches it as a **child process** when the host starts, talks to it over the pipe,
  and kills it on exit. If you run it by hand in a terminal it will sit there waiting on stdin —
  that is correct, not a hang.
- **stdout is the transport.** Nothing but JSON-RPC may ever be written there. All human-readable
  output — the startup banner, warnings — goes to **stderr**.

Verified. Three lines in (two requests and one notification), two responses out, every one of them
parseable, and the banner on stderr only:

```bash
$ printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"s","version":"0"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | ./dist/build/windows-x86_64/rop-finder-mcp.exe \
     --allow-dir "D:/Private/ROP-Finder/rop-finder/tests/fixtures" 2> err.txt \
 | python -c "import sys,json; ls=[l for l in sys.stdin if l.strip()]; print('stdout lines:',len(ls)); print('all parse as JSON:', all(json.loads(l) for l in ls))"
stdout lines: 2
all parse as JSON: True
```

Two, not three: `notifications/initialized` is a notification and correctly gets no reply. The
banner that did *not* appear on stdout, captured from stderr:

```
rop-finder-mcp serving on stdio; session 9d544b1d-08f0-4b12-91e2-484391193025; allowed dirs: D:\Private\ROP-Finder\rop-finder\tests\fixtures
```

That banner is your first diagnostic: it names the session id and the effective allow roots. If you
ever see it interleaved into stdout, something is wrong with your wrapper script, not with the
server.

### The allowlist is the whole security model

`--allow-dir` is the **only** source of the allowlist. There is no config file, no environment
variable, and no default. The server **refuses to start** without at least one — that is the exit-2
refusal from [the smoke test](#5-the-60-second-smoke-test).

**Why it fails closed.** The message says it, but it is worth spelling out because it drives every
other decision here: **the MCP host picks the working directory, not you.**
`claude_desktop_config.json` has no `cwd` key. If the server defaulted to its own cwd, your
allowlist would be whatever directory the host happened to launch from — a directory you did not
choose, cannot see, and which changes between host versions. So the server declines to guess.

`--allow-cwd` is the explicit opt-in for the cases where cwd *is* what you want (`cargo run`, CI).
Do not put it in a host config.

**Roots must be absolute.** A relative `--allow-dir` is accepted and resolved against the process
cwd — which is the thing you do not control. Verified:

```bash
$ cd D:/Private/ROP-Finder/rop-finder
$ ./dist/build/windows-x86_64/rop-finder-mcp.exe --allow-dir "tests/fixtures"
# stderr: … allowed dirs: D:\Private\ROP-Finder\rop-finder\tests\fixtures
```

It worked *here* because this shell's cwd was the repo root. Under a host it would resolve somewhere
else entirely, or fail. **Always pass absolute paths.**

A root that does not exist is a startup failure, not a warning (exit 2):

```
rop-finder-mcp: --allow-dir D:\nope\nothing: The system cannot find the path specified. (os error 3)
```

**Wide roots are refused.** Pointing the agent at a drive root or a home directory is refused unless
you say you meant it. Both verified, both exit 2:

```
$ rop-finder-mcp --allow-dir "C:\"
rop-finder-mcp: refusing to start: C:\ has fewer than two path components, so it covers a
filesystem root, a drive root or a whole system directory. If that really is what you want,
re-run with --i-accept-a-wide-allowlist; the agent will then be able to read every file under it.

$ rop-finder-mcp --allow-dir "C:\Users\razavi"
rop-finder-mcp: refusing to start: C:\Users\razavi is your home directory or an ancestor of it
(C:\Users\razavi). If that really is what you want, re-run with --i-accept-a-wide-allowlist; the
agent will then be able to read every file under it.
```

Same on Linux for `--allow-dir ~` (verified in WSL2, exit 2). `--i-accept-a-wide-allowlist` exists so
that the refusal is a speed bump against a slip, not a policy engine. If you find yourself reaching
for it, you almost certainly want a narrower root instead.

**Choosing roots.**

| | Root | Why |
|---|---|---|
| Good | `C:\work\ctf-2026\binaries` | One engagement, only the samples |
| Good | `/home/you/malware-samples/case-1179` | Scoped to a case |
| Good | two or three narrow roots, repeated `--allow-dir` | Verified: multiple roots are additive and all appear in the banner |
| Bad | `C:\Users\you\Desktop` | Everything you ever downloaded |
| Bad | your source tree | `.env`, `.pem`, `.git/config` are all readable files |
| Refused | `C:\`, `/`, `~`, `/etc`, `C:\Windows` | Needs `--i-accept-a-wide-allowlist` |

There is **no per-file policy**. Anything readable inside a root is in scope. Put the binaries you
want analysed in a directory that contains nothing else.

**The server's own files must live outside the roots.** The audit log, cache and workspace must not
be inside an allow root — otherwise the agent could read the server's record of what it did, or feed
the server's own output back in as a binary. All three refusals verified, all exit 2:

```
rop-finder-mcp: refusing to start: --audit-log …\tests\fixtures\audit.jsonl is inside the allow root D:\…\tests\fixtures. Put it somewhere the agent cannot read.
rop-finder-mcp: refusing to start: --cache-dir …/tests/fixtures/c is inside the allow root D:\…\tests\fixtures. Put it somewhere the agent cannot read.
rop-finder-mcp: refusing to start: --workspace-dir …/tests/fixtures/ws is inside the allow root D:\…\tests\fixtures. Put it somewhere the agent cannot read.
```

**What a denied path looks like.** Every rejection returns the same `path_denied` code with the same
message. This is deliberate — a caller must not be able to use the error to learn whether a file
exists. Six different failure kinds, one indistinguishable answer, all verified against a server
rooted at `…\tests\fixtures`:

| `binary_path` sent | Why it is refused |
|---|---|
| `C:\Windows\System32\notepad.exe` | outside every root |
| `elf-Linux-x64` | relative — must be absolute |
| `…\tests\fixtures\..\fixtures\elf-Linux-x64` | contains `..`, refused lexically even though it resolves back inside |
| `…\tests\fixtures-evil\x` | string-prefix match on a root is not a match; comparison is by path component |
| `…\tests\fixtures` (the root itself) | a directory is not a binary inside the root |
| `…\tests\fixtures\does-not-exist` | absent — **same message**, no existence oracle |

Every one produced exactly:

```json
{
  "error": {
    "code": "path_denied",
    "details": { "allow_roots": ["D:\\Private\\ROP-Finder\\rop-finder\\tests\\fixtures"] },
    "message": "binary_path is not inside an allowed directory. Allowed: [D:\\Private\\ROP-Finder\\rop-finder\\tests\\fixtures]. Call get_server_config for the effective allowlist.",
    "retryable": false,
    "suggestion": null
  }
}
```

Note the last two rows. **A file that is missing inside a root reports the same error as a path
outside every root.** That is the single most confusing thing an operator will hit;
`--verbose-path-errors` is the way out of it — see [MCP server startup and
calls](#mcp-server-startup-and-calls).

Forward slashes are accepted on Windows for both `--allow-dir` and `binary_path` (verified — a
`binary_path` of `D:/Private/…/elf-Linux-x64` was analysed successfully). The server normalises them
to backslashes in its own output.

### Verify the server before you touch any host config

This is the most useful thing in this document. An operator who can drive the server by hand never
has to guess whether a failure is the server or the host.

**The 30-second version: shell only, no dependencies.** Three JSON lines piped into the binary.
Works in Git Bash, WSL, macOS Terminal, any POSIX shell:

```bash
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"sh","version":"0"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
 | ./dist/build/windows-x86_64/rop-finder-mcp.exe \
     --allow-dir "D:/Private/ROP-Finder/rop-finder/tests/fixtures" 2>/dev/null \
 | tail -1 | grep -o '"name":"[a-z_]*"' | sed 's/"name":"//;s/"//' | sort -u
```

Real output — this is your pass condition, 15 names:

```
build_rop_chain
find_bytes
find_gadgets
find_gadgets_by_effect
find_jop_gadgets
find_string
find_syscall_gadgets
get_binary_info
get_gadgets
get_mitigations
get_server_config
get_server_stats
plan_chain
run_ropgadget_command
search_gadgets_by_pattern
```

If you see those 15 names, **the server is fine**. Every remaining problem is in the host config,
the host's approval state, or the OS refusing to spawn the binary. The same pipeline against
`dist/build/linux-x86_64/rop-finder-mcp` under WSL2 Ubuntu returned the identical 15 names.

**An empty stdin is not a failure of the server, and it is not the same as a one-shot request.**
Two cases people confuse, both verified on Windows and under WSL2:

```bash
# A. stdin closed with no request at all -> the server has nothing to initialize with
$ rop-finder-mcp --allow-dir "$PWD/tests/fixtures" < /dev/null
rop-finder-mcp serving on stdio; session 4b25284d-…; allowed dirs: …/tests/fixtures
[Error] MCP initialization failed: connection closed: initialize request
# exit 2

# B. one initialize, then EOF -> the reply IS written before the server exits
$ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}' \
  | rop-finder-mcp --allow-dir "$PWD/tests/fixtures"
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{…},"serverInfo":{"name":"rop-finder-mcp","version":"0.1.0"},"instructions":"…"}}
# exit 0
```

So a one-shot `printf | rop-finder-mcp` is a perfectly good probe. What it cannot do is hold a
*conversation* — you cannot read a reply and then decide what to send next, because stdin is already
closed. For that you need to keep the pipe open. On Linux an `exec sleep` is the crudest way:

```bash
{ printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
  exec sleep 3
} | timeout 8 ./dist/build/linux-x86_64/rop-finder-mcp --allow-dir "$PWD/tests/fixtures"
# exit 0
```

The Python probe below is the civilised version.

**The fuller version: a reusable Python probe.** It prints the handshake and the tool list, and —
unlike the shell version — keeps the pipe open so you can add `tools/call` requests. Save as
`mcp-probe.py`:

```python
import json, subprocess, sys, threading

EXE, ARGS = sys.argv[1], sys.argv[2:]
p = subprocess.Popen([EXE] + ARGS, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, text=True, encoding="utf-8", bufsize=1)
err = []
threading.Thread(target=lambda: [err.append(l) for l in p.stderr], daemon=True).start()

def send(o): p.stdin.write(json.dumps(o) + "\n"); p.stdin.flush()
def recv(): return json.loads(p.stdout.readline())

send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-03-26", "capabilities": {},
    "clientInfo": {"name": "probe", "version": "0"}}})
init = recv()["result"]
print("protocol:", init["protocolVersion"], "| server:", init["serverInfo"])
print("capabilities:", list(init["capabilities"]))
print("\ninstructions:\n", init["instructions"][:400], "...")

send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
tools = recv()["result"]["tools"]
print("\n%d tools" % len(tools))
for t in tools:
    print("  %-28s outputSchema=%s" % (t["name"], "outputSchema" in t))

p.stdin.close(); p.wait(timeout=10)
print("\nstderr:", "".join(err).strip())
print("exit:", p.returncode)
```

```bash
python mcp-probe.py ./dist/build/windows-x86_64/rop-finder-mcp.exe \
  --allow-dir "D:/Private/ROP-Finder/rop-finder/tests/fixtures"
```

Real output (instructions trimmed):

```
protocol: 2025-03-26 | server: {'name': 'rop-finder-mcp', 'version': '0.1.0'}
capabilities: ['logging', 'resources', 'tools']

instructions:
 ROP/JOP/SYS gadget search via rop-finder, plus Linux execve ROP chain generation
 (build_rop_chain, ELF x86/x64).
 binary_path MUST be an absolute path inside one of these directories:
 D:\Private\ROP-Finder\rop-finder\tests\fixtures. Anything else — including a path
 that merely starts with one of those strings, a relative path, or one containing
 ".." — is refused with a single `path_denied` code that deliberately reveals
 nothing about the target, so probing for files is pointless. Call
 get_server_config for the machine-readable allowlist and caps. ...

15 tools
  build_rop_chain              outputSchema=True
  …
  search_gadgets_by_pattern    outputSchema=True

stderr: rop-finder-mcp serving on stdio; session a125afe3-… ; allowed dirs: D:\Private\ROP-Finder\rop-finder\tests\fixtures
exit: 0
```

Two things worth noticing:

- **The `instructions` string names the effective allow roots.** A well-behaved agent reads it
  during the handshake and never has to guess a path. If your agent is guessing, check that the host
  is actually surfacing `instructions`.
- **`serverInfo.version` reports `0.1.0` while `--version` reports `rop-finder-mcp 1.0.0`.**
  Observed on both the Windows and Linux `v1.0.0-rc1` builds. It is a cosmetic mismatch in the
  handshake payload, not a sign that you are running an old binary — confirm the build with
  `--version`.

### Claude Desktop

**Where the config file lives:**

| OS | Path |
|---|---|
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

The Windows path was confirmed to exist on this machine
(`C:\Users\razavi\AppData\Roaming\Claude\claude_desktop_config.json`, 5,097 bytes). It was
deliberately **not read** — it is the user's config and may contain other servers — and **not
modified**, and Claude Desktop was **never launched or restarted**. So every `mcpServers` block
below is configuration that was **not executed end to end**. The server side of each one (the exact
`command` and `args`) *is* verified: those are the arguments this guide drove by hand throughout.

If the file does not exist, create it. If it does, merge your entry into the existing `mcpServers`
object — do not overwrite the file.

**Minimal — Windows.** **Doubled backslashes.** This is the single most common mistake. JSON treats
`\` as an escape character, so a Windows path needs `\\` at every separator. A single backslash
makes the file invalid JSON and Claude Desktop will silently show you no tools at all.

```json
{
  "mcpServers": {
    "rop-finder": {
      "command": "C:\\tools\\rop-finder\\rop-finder-mcp.exe",
      "args": [
        "--allow-dir",
        "C:\\work\\binaries"
      ]
    }
  }
}
```

Forward slashes also work and sidestep the escaping problem entirely — verified for the server's own
path handling (`--allow-dir "D:/…"` and a `binary_path` of `D:/…` both succeeded):

```json
{
  "mcpServers": {
    "rop-finder": {
      "command": "C:/tools/rop-finder/rop-finder-mcp.exe",
      "args": ["--allow-dir", "C:/work/binaries"]
    }
  }
}
```

**Minimal — macOS.** *Not executed here — no macOS machine was available, and no macOS binary has
ever been built.* Build from source first; see [section 2](#2-getting-a-binary).

```json
{
  "mcpServers": {
    "rop-finder": {
      "command": "/usr/local/bin/rop-finder-mcp",
      "args": ["--allow-dir", "/Users/you/work/binaries"]
    }
  }
}
```

**Minimal — Linux.** The server-side arguments here are verified (the Linux binary was driven
through a full handshake under WSL2 Ubuntu); the Claude Desktop wiring itself was not executed, and
Claude Desktop is not installed in WSL2, so the config path above is unverified for Linux.

```json
{
  "mcpServers": {
    "rop-finder": {
      "command": "/usr/local/bin/rop-finder-mcp",
      "args": ["--allow-dir", "/home/you/work/binaries"]
    }
  }
}
```

**Production — Windows.** Narrow roots, an audit trail outside them, a bounded cache, and caps
tightened below the defaults. Every flag below is real and was exercised by hand; see
[`MANUAL.md` UC7](../MANUAL.md#uc7--ai-agents-via-the-mcp-server) for what each one does.

```json
{
  "mcpServers": {
    "rop-finder": {
      "command": "C:\\tools\\rop-finder\\rop-finder-mcp.exe",
      "args": [
        "--allow-dir", "C:\\work\\case-1179\\binaries",
        "--allow-dir", "C:\\work\\case-1179\\libs",
        "--audit-log", "C:\\work\\case-1179\\audit\\rop-finder.jsonl",
        "--audit-log-max-mb", "32",
        "--cache-dir", "C:\\work\\case-1179\\cache",
        "--scan-threads", "4",
        "--max-concurrent", "1",
        "--max-results", "200",
        "--timeout-secs", "120",
        "--max-file-bytes", "134217728"
      ]
    }
  }
}
```

Note that `audit`, `cache` and the allow roots are **siblings**, not nested. If you put the audit log
under `C:\work\case-1179\binaries` the server exits 2 at startup and Claude Desktop shows you
nothing.

**Production — Linux / macOS.** Same shape. The macOS half is *not executed here*.

```json
{
  "mcpServers": {
    "rop-finder": {
      "command": "/usr/local/bin/rop-finder-mcp",
      "args": [
        "--allow-dir", "/srv/case-1179/binaries",
        "--audit-log", "/var/log/rop-finder/audit.jsonl",
        "--audit-log-max-mb", "32",
        "--cache-dir", "/var/cache/rop-finder",
        "--scan-threads", "4",
        "--max-concurrent", "1",
        "--max-results", "200",
        "--timeout-secs", "120"
      ]
    }
  }
}
```

**After editing.** Fully quit and relaunch Claude Desktop. Closing the window is not enough on
Windows or macOS — the process stays resident and keeps the old child. Before you relaunch, run the
JSON through a parser; an invalid file is the most common cause of "no tools appeared":

```bash
python -m json.tool "$APPDATA/Claude/claude_desktop_config.json" > /dev/null && echo "valid JSON"
```

```powershell
Get-Content "$env:APPDATA\Claude\claude_desktop_config.json" -Raw | ConvertFrom-Json | Out-Null
"valid JSON"
```

### Claude Code

Verified against the `claude` CLI **v2.1.207** installed on this machine.

**`claude mcp add`.** Everything after `--` is passed to the server as its own arguments. Without
the separator, `--allow-dir` is parsed as a flag to `claude`.

```bash
claude mcp add rop-finder --scope project -- \
  "D:\Private\ROP-Finder\rop-finder\dist\build\windows-x86_64\rop-finder-mcp.exe" \
  --allow-dir "D:\Private\ROP-Finder\rop-finder\tests\fixtures"
```

Real output:

```
Added stdio MCP server rop-finder with command: D:\Private\ROP-Finder\rop-finder\dist\build\windows-x86_64\rop-finder-mcp.exe --allow-dir D:\Private\ROP-Finder\rop-finder\tests\fixtures to project config
```

Scopes, from the verified `claude mcp add --help`:

| Scope | Flag | Where it is written |
|---|---|---|
| `local` | *(default)* | Your own user config, keyed to the current project |
| `project` | `-s project` | `.mcp.json` in the project root — shared with the team |
| `user` | `-s user` | Your user config, every project |

Only `--scope project` was actually executed here, in a throwaway scratch directory whose generated
`.mcp.json` was deleted afterwards; `local` and `user` write outside that directory and were not
run. Transport defaults to stdio, which is what this server needs; `-t/--transport` does not apply
here since the server has no HTTP mode.

**`.mcp.json` (project scope).** `claude mcp add --scope project` generated this file verbatim — it
is not a hand-written example:

```json
{
  "mcpServers": {
    "rop-finder": {
      "type": "stdio",
      "command": "D:\\Private\\ROP-Finder\\rop-finder\\dist\\build\\windows-x86_64\\rop-finder-mcp.exe",
      "args": [
        "--allow-dir",
        "D:\\Private\\ROP-Finder\\rop-finder\\tests\\fixtures"
      ],
      "env": {}
    }
  }
}
```

You can commit that to a repo. Note the same doubled-backslash rule applies.

**Project-scoped servers need approval before they run.** This trips people up and looks exactly
like a broken config. Immediately after the `add` above:

```bash
$ claude mcp list
Checking MCP server health…

rop-finder: D:\…\rop-finder-mcp.exe --allow-dir D:\…\tests\fixtures - ⏸ Pending approval (run `claude` to approve)
```

The server is correct and would start fine — Claude Code simply will not launch a server defined in
a checked-in `.mcp.json` until you approve it interactively. Run `claude` once in that directory and
accept. `claude mcp list` is the fastest way to tell "not approved" apart from "not working".

### What the agent can do

15 tools, all declaring an `outputSchema`, so the host can validate responses. Grouped by what you
would actually ask for:

| Purpose | Tools |
|---|---|
| **Recon — is ROP even the right idea?** | `get_binary_info`, `get_mitigations` |
| **Discovery — find gadgets** | `find_gadgets`, `find_jop_gadgets`, `find_syscall_gadgets`, `search_gadgets_by_pattern`, `run_ropgadget_command` |
| **Constraint search — find *the* gadget** | `find_gadgets_by_effect`, `get_gadgets` |
| **Data, not code** | `find_string`, `find_bytes` |
| **Chains** | `plan_chain`, `build_rop_chain` |
| **Server introspection** | `get_server_config`, `get_server_stats` |

The one to reach for is `find_gadgets_by_effect`. It takes the whole constraint set in a single call
and returns an `explanation` with every hit, so the agent does not fetch thousands of gadgets and
filter them in its context window.

**A worked flow.** Four real calls against `tests/fixtures/elf-Linux-x64`, in the order an agent
should make them. Requests are verbatim; responses are trimmed where marked.

**1. `get_server_config` — learn the roots and caps instead of probing for them.**

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_server_config","arguments":{}}}
```

```json
{
  "allow_roots": ["D:\\Private\\ROP-Finder\\rop-finder\\tests\\fixtures"],
  "audit_log": false,
  "cache": false,
  "cache_mem_max_bytes": 536870912,
  "cache_ttl_secs": 86400,
  "cursor_ttl_secs": 300,
  "error_codes": ["path_denied","usage_error","unsupported_binary","resource_exhausted",
                  "timeout","cancelled","cursor_expired","not_found","internal"],
  "hard_max_results": 50000,
  "max_concurrent": 2,
  "max_depth": 64,
  "max_file_bytes": 268435456,
  "max_gadgets": 5000000,
  "max_imports": 4096,
  "max_results": 1000,
  "max_sections": 4096,
  "orders": ["rank","address","quality","text"],
  "probe_threshold": 20,
  "scan_threads": 23,
  "timeout_secs": 60,
  "version": "1.0.0",
  "workspace_dir": null
}
```

**2. `get_binary_info` — what am I looking at?** (`imports`, `sections`, `symbols` elided)

```json
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_binary_info","arguments":{"binary_path":"D:\\Private\\ROP-Finder\\rop-finder\\tests\\fixtures\\elf-Linux-x64"}}}
```

```json
{
  "format": "elf", "arch": "x64", "addr_size": 8, "endianness": "little",
  "image_base": "0x400000", "entry": "0x400f78", "symbol_count": 2169,
  "binary_sha256": "6d440623405fadb76b0d01bf95d16b345189e15b5e34572eb947963fa9718649",
  "imports": "<46 items>", "sections": "<30 items>",
  "warnings": [{"code":"symbols_truncated",
                "message":"symbols truncated to 0 of 2169 entries",
                "detail":"symbols are opt-in: pass max_symbols (up to 4096) to include them. …"}]
}
```

`get_mitigations` on the same file returns `nx` enabled, `pie` **disabled**
(`e_type=ET_EXEC: the image declares a fixed load address`), `relro` partial, `canary` absent — each
with its evidence string, and each as a named record in a list rather than the CLI's keyed object. A
fixed-address non-PIE binary is exactly the shape where a static ROP chain is worth building, which
is what makes step 3 worth doing.

**3. `find_gadgets_by_effect` — the whole constraint in one call.**

```json
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"find_gadgets_by_effect","arguments":{
  "binary_path":"D:\\Private\\ROP-Finder\\rop-finder\\tests\\fixtures\\elf-Linux-x64",
  "set_reg":"rdi","from_stack":true,"no_clobber":["rsi","rdx"],
  "max_side_effects":1,"terminator":"ret","max_results":3}}}
```

Out of 863,316 bytes of binary, exactly one gadget survives:

```json
{
  "total_count": 1, "returned": 1, "offset": 0, "truncated": false,
  "order": "rank", "cache": "miss", "binary_label": "elf-Linux-x64",
  "gadgets": [{
    "id": "g_akwajkx3loccv6it",
    "vaddr": "0x0000000000401648", "vaddr_u64": 4200008,
    "text": "pop rdi ; ret", "insns": ["pop rdi","ret"], "bytes": "5fc3",
    "class": "reg-write", "terminator": "ret",
    "regs_written": ["rdi"], "regs_from_stack": ["rdi"], "regs_read": [],
    "stack_delta": 16, "side_effects": 1, "quality": 100, "usability": 3,
    "explanation": {
      "sets": ["rdi"], "clobbers": [], "reads": [], "stack_delta": 16,
      "terminator": "ret",
      "why": "sets rdi from stack[+0]; clobbers nothing; stack delta +16; ends in ret"
    }
  }]
}
```

This is the same single gadget the CLI returns for the equivalent
`--set-reg rdi --from-stack --no-clobber rsi,rdx --max-side-effects 1 --terminator ret` query in
[Asking a real question](#asking-a-real-question-instead-of-grepping). The MCP surface and the CLI
are the same engine; if they ever disagree, that is a bug worth reporting.

The `id` (`g_akwajkx3loccv6it`) is stable — the agent can hand it back to `get_gadgets` later
instead of re-scanning.

**4. `plan_chain` — is a full chain feasible, and if not, why not?**

```json
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"plan_chain","arguments":{
  "binary_path":"D:\\Private\\ROP-Finder\\rop-finder\\tests\\fixtures\\elf-Linux-x64",
  "target":"linux-execve"}}}
```

```json
{
  "feasible": true, "arch": "x64", "format": "elf", "error": null, "word_count": 19,
  "assumptions": { "needs_leak": false, "write_target": ".data @ 0x6bc080" },
  "requirements": [
    { "id": "write_target", "satisfied": true,
      "description": "a writable, non-TLS, post-RELRO section with room for 16 bytes of path + NULL (CHLX-05)",
      "strategies_tried": [{"pattern":"section: writable && !tls && !relro","candidates":4}] },
    { "id": "write_primitive", "satisfied": true,
      "strategies_tried": [
        {"pattern":"mov qword ptr [r64], r64","candidates":92},
        {"pattern":"mov qword ptr [r64], r64 over {rax, rbx, …}","candidates":32}] },
    { "id": "set_rdi", "satisfied": true,
      "description": "rdi must hold 0x6bc080 (@ .data)",
      "strategies_tried": [{"pattern":"pop rdi","candidates":2},
                           {"pattern":"mov rdi, <reg>","candidates":0}] },
    { "id": "set_rsi", "satisfied": true, "…": "pop rsi: 8 candidates" },
    { "id": "set_rdx", "satisfied": true, "…": "pop rdx: 6 candidates" },
    { "id": "set_rax", "satisfied": true,
      "description": "rax must hold 0x3b (rax = 59 (__NR_execve))",
      "strategies_tried": [{"pattern":"pop rax","candidates":2},
                           {"pattern":"mov rax, <reg>","candidates":54},
                           {"pattern":"inc rax","candidates":1}] },
    { "id": "syscall_trap", "satisfied": true,
      "strategies_tried": [{"pattern":"syscall","candidates":1}] }
  ],
  "satisfied_requirements": [
    { "id": "write_target",    "vaddr": "0x6bc080", "gadget_id": null, "text": ".data @ 0x6bc080" },
    { "id": "write_primitive", "vaddr": "0x435d7c", "gadget_id": "g_4x57p7ub4hgh2zbp",
      "text": "nop dword ptr [rax] ; mov qword ptr [rdi], rcx ; repz ret" },
    { "id": "set_rdi",         "vaddr": "0x401648", "gadget_id": "g_akwajkx3loccv6it",
      "text": "pop rdi ; ret" },
    { "id": "syscall_trap",    "vaddr": "0x401560", "gadget_id": "g_qwovmu4p6j63wnaf",
      "text": "syscall" }
  ]
}
```

`plan_chain` always succeeds — on an infeasible binary it returns `"feasible": false` with the
unsatisfied requirement and what was tried, which is far more useful to an agent than a failure.
Only call `build_rop_chain` once `plan_chain` says yes.

**Paging and the workspace.** Gadget-returning tools page. `find_gadgets` with no `depth` runs the
ROP engine at depth 10 — 8,389 gadgets on this fixture, matching the CLI's `--nojop --nosys` — and
with `max_results: 2` returned:

```json
{
  "returned": 2, "total_count": 8389, "offset": 0, "truncated": true, "order": "rank",
  "next_cursor": "eyJ2IjoxLCJjYWNoZV9rZXkiOiJ2MS02ZDQ0MDYyMzQwNWZhZGI3…",
  "resource_uri": "ropfinder://scan/v1-6d440623…/gadgets.ndjson",
  "workspace_file": "…\\ws2\\v1-6d440623…-10e92bb6….ndjson",
  "warnings": [{"code":"truncated","field":"gadgets",
                "message":"gadgets truncated to 2 of 8389 entries","returned":2,"total":8389}]
}
```

If you start the server with `--workspace-dir`, each paged scan is also materialised on disk as
NDJSON plus a JSON Schema sidecar (verified — a 6.1 MB `.ndjson` and an 8 KB `.schema.json`
appeared). An agent that also has filesystem tools can then `grep` the whole result instead of
walking hundreds of pages. The workspace directory must be outside every allow root.

### Operating it safely

**The audit log.** `--audit-log <path>` writes one JSON object per call — successes, denials and
all. Verified content, one denied call, one successful scan, one no-argument tool:

```jsonl
{"binary":"C:\\Windows\\System32\\notepad.exe","binary_sha256":null,"bytes_read":0,"cache":null,"code":"path_denied","duration_ms":0,"params_hash":"b45009c2ebe9d71bd051341ad08b736462c55848cd1bcee9523bb81a73637d62","probing_suspected":false,"req_id":"2","returned":null,"session":"38b85be1-6831-4ade-9fb8-a9d5808bcf85","tool":"get_binary_info","total_count":null,"ts":"2026-09-04T09:33:17.435Z","verdict":"denied"}
{"binary":"elf-Linux-x64","binary_sha256":"6d440623405fadb76b0d01bf95d16b345189e15b5e34572eb947963fa9718649","bytes_read":863316,"cache":"miss","code":null,"duration_ms":47,"params_hash":"0dfa779d180babbebf88209803d38b8e4ae93ac59ba738a10f61258b0c5d0838","probing_suspected":false,"req_id":"3","returned":2,"session":"38b85be1-6831-4ade-9fb8-a9d5808bcf85","tool":"find_gadgets","total_count":8389,"ts":"2026-09-04T09:33:17.485Z","verdict":"ok"}
{"binary":null,"binary_sha256":null,"bytes_read":0,"cache":null,"code":null,"duration_ms":0,"params_hash":"","probing_suspected":false,"req_id":"4","returned":null,"session":"38b85be1-6831-4ade-9fb8-a9d5808bcf85","tool":"get_server_stats","total_count":null,"ts":"2026-09-04T09:33:17.490Z","verdict":"ok"}
```

What a line contains: the tool, the verdict, the error code if any, the binary label and its
SHA-256, bytes read, duration, result counts, a session id, and a **hash** of the parameters. What
it never contains: **gadget text, instruction bytes, or any content from the file**. You can hand
this log to someone who is not cleared to see the binaries.

Two details worth knowing:

- On a **denial** the `binary` field is the full path the caller asked for; on **success** it is
  only the basename. So the log does record what an agent tried to reach outside your roots — which
  is the point.
- `params_hash` is empty for tools that take no arguments (`get_server_stats`).

Rotation is at `--audit-log-max-mb` (default 64), keeping `.1` and `.2`. Mode 0600 on Unix.

**`get_server_stats` and probe detection.** `--probe-threshold` (default 20, `0` disables) counts
**consecutive** `path_denied` results in one session. Past the threshold, responses are delayed
250 ms and `probing_suspected` is set. This is the signal that an agent — a prompt-injected one, or
just a confused one — is walking your filesystem.

Verified with `--probe-threshold 3` and four denied paths:

```json
{
  "requests_total": 5, "ok_total": 0, "denied_total": 4,
  "denied_consecutive": 4, "denied_consecutive_max": 4,
  "probing_suspected": true, "inflight": 0,
  "requests_by_tool": { "get_binary_info": 4, "get_server_stats": 1 },
  "timeout_total": 0, "cancelled_total": 0, "error_total": 0, "wedged_total": 0,
  "bytes_read_total": 0,
  "cache": { "entries": 0, "hits": 0, "misses": 0, "cache_bytes": 0, "evictions": 0 }
}
```

and on stderr:

```
2026-09-04T09:33:28.986274Z  WARN rf_mcp::logging: consecutive path_denied results suggest an agent is enumerating the filesystem code="path_probing" detail="{\"denied_consecutive\":3,\"requested\":\"C:\\\\probe\\\\2\",\"threshold\":3}"
```

Note `denied_consecutive` **resets on a successful call** while `denied_consecutive_max` and
`denied_total` do not — check the totals, not just the current run.

**The caps, and what they do when hit.** All verified by hand except the last row.

| Cap | Behaviour when exceeded | Real error |
|---|---|---|
| `--max-depth` (64) | **Rejected, never silently clamped** | `usage_error`: `depth 200 exceeds the server's max_depth of 64; re-send with depth <= 64`, `details: {got: 200, limit: "max_depth", limit_value: 64}` |
| `--max-file-bytes` (256 MiB) | Checked before any read | `resource_exhausted`: `binary is 863316 bytes; the --max-file-bytes cap is 100000` |
| `--max-gadgets` (5,000,000) | Scan stops | `resource_exhausted`: `the scan exceeded the server's gadget budget after 1000 gadgets (limit 1000); lower depth, or narrow the scan with section/range` |
| `--max-concurrent` (2) | Queues, does not multiply | **not triggered here** — the driver issued requests serially, so two scans were never in flight |
| `--timeout-secs` (60, range 1–300) | Returns `timeout` to the caller | **not reproduced here** — see below |

The `--max-depth` behaviour is deliberate and worth internalising: a clamp would let an agent believe
it had searched to depth 200 when it had not. A rejection forces it to re-ask.

**On the timeout:** it could not be triggered against the bundled fixtures. Even the worst case
tried — `elf-x64-bash-v4.1.5.1` at `--depth 64` with `--multibr`, 351,785 gadgets — completes in
**1.12 s** wall clock (three runs: 1120, 1120, 1118 ms), so a `--timeout-secs 1` server returned
success rather than a timeout. The
`timeout` code is real and is listed in `get_server_config.error_codes`, but this document has not
observed it. Note also the caveat in
[`MANUAL.md` UC7](../MANUAL.md#uc7--ai-agents-via-the-mcp-server): a timed-out request returns an
error to the caller while the worker runs to completion (`MCP-03`) — the depth and concurrency caps
bound the cost, they do not cancel it.

**The things it does not protect you from.** Covered fully in
[`MANUAL.md` UC7](../MANUAL.md#uc7--ai-agents-via-the-mcp-server); the two an operator must hold in
mind while choosing roots:

- **Confinement is exactly as narrow as your `--allow-dir` list.** There is no per-file policy
  inside a root.
- **The binary's contents reach the model.** Gadget text, byte sequences, section layout, import
  names and generated chain scripts flow into the agent's context and wherever the host sends it. Do
  not point this at a binary you would not paste into a chat window.

---

## 9. Troubleshooting

### First run

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Permission denied`, exit 126 (Linux/macOS) | exec bit lost by a raw file download or a copy off a Windows filesystem | `chmod +x`, or use the tarball, which preserves 0755 |
| `cannot be opened because the developer cannot be verified` (macOS) | `com.apple.quarantine` on an unsigned download | verify the checksum, then `xattr -d com.apple.quarantine <file>` — *not executed here* |
| SmartScreen prompt (Windows) | Mark of the Web on a downloaded exe | verify the checksum, then `Unblock-File <file>` — *not executed here* |
| `The '--' operator works only on variables` (PowerShell) | quoted exe path parsed as a string | prefix with the call operator: `& "C:\path with space\rop-finder.exe" --version` |
| `error: could not find 'rop-finder' in registry` | crates.io publish has not happened | build from source, [route B](#b-build-from-source--the-route-that-works-today) |
| Build dies inside a `capstone-sys` build script | no C toolchain | Linux: `cross`/`musl-tools`/`zig`. Windows: MSVC build tools. macOS: `xcode-select --install`. *(No such build failure was observed here — the toolchain requirement is read from the scripts and from `capstone-sys`.)* |
| Every checksum line says FAILED on Windows | `Get-FileHash` returns uppercase hex | lowercase before comparing (`.Hash.ToLower()`) |
| `Unique gadgets found:` is not 42508 on the smoke fixture | wrong binary, wrong fixture, or a bad build | re-verify `SHA256SUMS` and re-check the `--depth 10` argument |

### CLI errors

Every message below was produced this session.

| What you did | What you get | Exit |
| --- | --- | --- |
| no `--binary` | `[Error] Need a binary filename (--binary/--console or --help)` | 1 |
| file missing, directory exists | `[Error] cannot read <path>: The system cannot find the file specified. (os error 2)` (Windows) / `No such file or directory (os error 2)` (Linux) | 1 |
| the directory itself is missing | `[Error] cannot read <path>: The system cannot find the path specified. (os error 3)` (Windows) | 1 |
| passed a directory | `[Error] cannot read <path>: a directory; rop-finder reads whole files into memory and refuses inputs with no fixed length` | 1 |
| bad `--terminator` | `[Error] invalid --terminator value "retn"; valid values are ret, jmp, …` | 1 |
| `--max-gadgets` too low | `[Error] scan budget exhausted after 1000 gadgets (limit 1000); raise --max-gadgets/--max-memory, lower --depth, or narrow the scan with --section` | **2** |
| ARM64/MIPS + `--ropchain` | `[Error] arch arm64 / format elf not supported yet for the rop chain generation` | 1 |
| `--chain linux-syscall` without `--syscall` | `[Error] can't find a suitable gadget: linux-syscall needs --syscall <n> …` | 1 |
| **bad register name** (`--set-reg r99`) | `Unique gadgets found: 0` — *no warning at all* | **0** |
| **sub-register** (`--set-reg edi` on x64) | `Unique gadgets found: 0` — *no warning at all* | **0** |
| `--badbytes` rejecting everything | `Unique gadgets found: 0` | **0** |

The last three are the ones that waste your afternoon. When a query returns zero:

1. Drop constraints one at a time until it returns something — the funnel table in [Asking a real
   question](#asking-a-real-question-instead-of-grepping) shows what that looks like.
2. Check register spelling: full-width architectural names only (`rdi`, not `edi` or `di`).
3. Remember `--badbytes` filters the **final address after `--base` and `--offset`**. On x64 a low
   address like `0x0000000000401648` still has zero bytes in its high half, so `--badbytes "00"`
   rejects it and reports 0 — verified. That is expected behaviour, not a bug. *(The zero result was
   measured; the byte-rejection mechanism was not instrumented.)*
4. Only then raise `--depth`.

### MCP server startup and calls

| Symptom | Cause | Fix |
| --- | --- | --- |
| Server exits **2** immediately; host shows nothing | No `--allow-dir` | Add at least one absolute `--allow-dir`. Run the binary by hand — it prints the reason to stderr, which the host swallows. |
| Exits 2: *"has fewer than two path components"* / *"is your home directory"* | Root too wide | Use a narrower root. Only add `--i-accept-a-wide-allowlist` if you truly meant it. |
| Exits 2: *"is inside the allow root … Put it somewhere the agent cannot read"* | `--audit-log`, `--cache-dir` or `--workspace-dir` is nested under an allow root | Move it to a sibling directory. |
| Exits 2: *"The system cannot find the path specified. (os error 3)"* | An `--allow-dir` does not exist | Create it, or fix the typo. Check backslash escaping in JSON. |
| `path_denied` on a file the operator can plainly see | (a) path is relative; (b) contains `..`; (c) is outside every root; (d) **exists nowhere** — all four return the identical message | Send an **absolute**, `..`-free path. Call `get_server_config` for the real roots. Then restart with `--verbose-path-errors` to tell them apart. |
| `path_denied` and you still cannot tell why | The single-code design is deliberate — it prevents a filesystem existence oracle | Restart with `--verbose-path-errors`. A file inside a root then reports `"does-not-exist" is inside allow root D:\… but could not be opened: cannot open` with `details.verbose_reason: "cannot open"`; a path outside keeps the generic message. Turn it back off afterwards. |
| `path_denied` on a path that *looks* inside the root | Root matching is by **path component**, not string prefix — `…\fixtures-evil\x` is not inside `…\fixtures`. Per [MANUAL.md UC7](../MANUAL.md#uc7--ai-agents-via-the-mcp-server), a symlink leaving the root is also refused, since the file is opened pinned to the root (`openat(O_NOFOLLOW)` on Unix, handle validation on Windows) — *that symlink behaviour is attributed to MANUAL.md, not measured here* | Resolve symlinks yourself and pass a real path inside the root, or add the symlink target's directory as its own `--allow-dir`. |
| `unsupported_binary: binary format not recognized; use RawBinary with an explicit arch` | The path is fine — the file just is not a binary this build parses (verified on a `.md` file inside a root) | Check you named the right file. For headerless blobs use the raw-binary path with an explicit arch (see MANUAL.md UC8). |
| `usage_error: depth N exceeds the server's max_depth of 64` | Depth caps **reject**, they never clamp | Re-send with `depth <= 64`, or raise `--max-depth` on the server. |
| `resource_exhausted` naming `max_file_bytes` or `max_gadgets` | Hit a server budget | Raise the cap, or narrow the scan (`section`, `range`, lower `depth`). |
| `MCP initialization failed: connection closed: initialize request`, exit 2 | stdin reached EOF before any `initialize` arrived — e.g. `< /dev/null`, or a launcher that never writes. A one-shot `printf | rop-finder-mcp` does **not** cause this; verified exit 0 | Send an `initialize`. Under a host, this means the host never spoke to the process. |
| A tool call hangs or times out | A very large binary at high depth; only 2 scans run at once by default | Lower `depth`, narrow with `section`/`range`, raise `--timeout-secs` (max 300). Check `get_server_stats` for `inflight` and `busy_total`. |
| **Claude Desktop shows no tools at all, no error** | Invalid config JSON — nearly always single backslashes in a Windows path | Validate the file (`python -m json.tool "$APPDATA/Claude/claude_desktop_config.json"`). Use `\\` everywhere, or forward slashes. |
| Claude Desktop shows no tools, JSON is valid | Wrong config path, or the app was not fully restarted | Confirm the path for your OS from the table in [Claude Desktop](#claude-desktop). Quit the app completely — closing the window is not enough — then relaunch. |
| Claude Desktop shows no tools, JSON valid, path right | The server is exiting 2 before the handshake | Run the exact `command` + `args` from the config in a terminal. The stderr message tells you which refusal it is. |
| Claude Code: server listed as **⏸ Pending approval** | Project-scoped `.mcp.json` servers require interactive approval | Run `claude` in that directory and approve it. Verified — this looks identical to a broken server in `claude mcp list`. |
| Claude Code: `--allow-dir` treated as an argument to `claude` | Missing `--` separator | `claude mcp add rop-finder -- <exe> --allow-dir <dir>` |
| **macOS: the host spawns nothing and shows no error at all** | Gatekeeper/quarantine silently kills a downloaded, unsigned binary. **Not reproducible here: no macOS machine, and no macOS binary has ever been built.** | *(unverified, standard macOS remediation)* Run the binary once in Terminal to see the real refusal, then `xattr -d com.apple.quarantine /usr/local/bin/rop-finder-mcp`, or approve it in System Settings → Privacy & Security. Building from source locally avoids quarantine entirely. |
| Garbled protocol errors; host reports malformed JSON | Something is writing to **stdout** — a wrapper shell script, a profile that echoes, a `set -x` | Never print to stdout in a launcher. Verified: the server itself writes only JSON-RPC to stdout. Invoke the binary directly rather than through a wrapper. |
| Works by hand, fails under the host | Relative `--allow-dir`, or a relative `command` | Both resolve against a cwd **the host chose**. Make every path absolute. |
| `serverInfo.version` says `0.1.0` but you built 1.0.0 | Cosmetic mismatch in the handshake payload, observed on both `v1.0.0-rc1` builds | Confirm the real build with `rop-finder-mcp --version`. Not a stale binary. |

**The one diagnostic that settles it.** When a host misbehaves, do not debug the host. Run the
[shell handshake](#verify-the-server-before-you-touch-any-host-config) with the **exact** `command`
and `args` from your config.

- **15 tool names printed** → the server is fine. The problem is the host: config JSON, config path,
  approval state, or the OS refusing the spawn.
- **A refusal message on stderr and exit 2** → the problem is your flags, and the message names it.

---

## 10. Known limits

Stated plainly, because every one of these is a place where this document stops being evidence and
starts being intent.

- **macOS is entirely unexecuted.** No macOS machine exists in this environment. `dist/build-macos.sh`
  is written and passes `bash -n`, but has **never run**, so **no macOS artifact has ever been
  built**. Not executed: `xcode-select -p` / `--install`, the build script in any form (native,
  `--universal`, `--sign`, `--notarize-profile`), `lipo`, `shasum -a 256 -c`,
  `xattr -d com.apple.quarantine`, and the Gatekeeper "developer cannot be verified" dialog. The
  macOS Claude Desktop config path and every macOS troubleshooting row are unverified.
- **Nothing is published to crates.io.** `cargo publish --dry-run` is clean, but no upload has
  happened. `cargo install rop-finder` and `cargo install rop-finder-mcp` both fail today; only the
  *failure* has been verified (exit 101), never a successful install.
- **The GitHub release workflow has never run.** Six tags exist locally (`v0.1.1` … `v1.0.0-rc1`)
  but the repository has **no configured git remote**, so nothing has been pushed and Actions has
  never fired. No release artifact has been downloaded, checksummed or unpacked; the CI tarball
  layout (`rop-finder-<version>-<target>/`) is read from `release.yml`, not observed.
- **There is no ARM64 chain target and no MIPS chain target.** Chain generation is x86/x64 only.
  Gadget *finding* works on ARM64 and MIPS; asking for a chain is an explicit exit-1 refusal.
- **No aarch64 artifact of any kind exists here.** Only x86_64 was built;
  `dist/build-linux.sh --arch aarch64` was not run.
- **The `dist/` build scripts were not re-run this session.** Re-running `dist/build-windows.ps1`
  would regenerate `dist/build/windows-x86_64/` and change the checksums quoted here. Toolchain
  selection in `build-linux.sh` and the `cl.exe` warning in `build-windows.ps1` are read from the
  scripts, not observed, and **no `capstone-sys` build failure from a missing C toolchain was
  reproduced on any platform**.
- **Windows Mark of the Web is only verified negatively.** Nothing was downloaded on this machine,
  so no file carried a `Zone.Identifier` stream. `Unblock-File` was not executed.
- **No real MCP host was driven.** Claude Desktop is installed but was never launched, restarted, or
  configured; its config file was located but deliberately not read or modified. Claude Code was
  used only for `claude mcp add --scope project` in a throwaway directory (and `claude mcp list`);
  `--scope local` and `--scope user` write outside that directory and were not run. Every MCP proof
  here is a hand-driven stdio handshake.
- **Linux was exercised under WSL2 Ubuntu**, not on a native Linux machine. The static-musl
  `file`/`ldd` result makes that a reasonable proxy, but it is a proxy.
- **`cmd.exe` has no transcript behind it.** Everything ran through PowerShell 5.1 and Git Bash.
- **`--console` (the interactive REPL) was not exercised** — it is interactive and this session was
  not.
- **The MCP `timeout` path was never triggered**, and `--max-concurrent` queueing was never
  observed, because the driver issued requests serially and no bundled fixture is slow enough.
- **Cache eviction and expiry were not driven.** `ROP_FINDER_CACHE_MAX_BYTES` (512 MiB) and
  `ROP_FINDER_CACHE_TTL_SECS` (14 days) are quoted from `--help`.
- **The ROPgadget 7.7 agreement on 42508 was not re-run here.** It is cross-referenced to
  [`docs/measured-2026-09.md`](measured-2026-09.md).
- **`--badbytes` mechanism not instrumented.** The zero result on `--badbytes "00"` was measured; the
  explanation that the packed 64-bit address contains zero bytes is reasoning, not instrumentation.
- **Symlink escape from an allow root was not tested.** The `openat(O_NOFOLLOW)` / handle-validation
  claim is attributed to [`MANUAL.md` UC7](../MANUAL.md#uc7--ai-agents-via-the-mcp-server).

---

## 11. What this guide does not cover

| Document | What it holds |
| --- | --- |
| [`MANUAL.md`](../MANUAL.md) | **The flag reference.** Every flag and its exact semantics, ROPgadget compatibility and known divergences, output-format schemas, semantic classification and quality ranking, the performance guide, and use cases UC1–UC9 (UC7 is the MCP tool reference, UC8 raw blobs and firmware, UC9 CET/CFG-hardened targets). Flags this guide deliberately skips — `--thumb`, `--rawArch`/`--rawMode`/`--rawEndian`, `--mipsrop`, `--multibr`, `--compat`, `--arch` for fat Mach-O slice selection, `--max-memory`, `--max-file-size`, `--cfg-aware`, `--console` — are documented there. |
| [`README.md`](../README.md) | The project overview: what rop-finder is, why it exists, what it is not. |
| [`docs/API-STABILITY.md`](API-STABILITY.md) | What is covered by the stability promise and what may change between versions. |
| [`docs/MCP-DESIGN.md`](MCP-DESIGN.md) | The MCP tool schemas, gadget record shape, and the threat model behind the allowlist. |
| [`docs/measured-2026-09.md`](measured-2026-09.md) | Measured performance figures and the ROPgadget parity numbers. |
| [`dist/README.md`](../dist/README.md) | Why no binaries are committed to git (finding ENG-09), and the two supported ways to get one. |
| [`docs/chain-regressions.md`](chain-regressions.md) | The failing-before / passing-after runs behind the `windows-virtualprotect` warning. |
