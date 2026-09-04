# rop-finder and rp++ — a technical comparison

Document date: 4 September 2026.
Written in ASD-STE-100 Simplified Technical English.

---

## 1. Purpose

This document compares two ROP gadget finders:

- rop-finder v1.0.0-rc1, the tool in this repository;
- rp++ v2.1.5, by Axel Souchet, MIT licence, at https://github.com/0vercl0k/rp.

A gadget is a short instruction sequence that ends in a branch. An attacker
chains gadgets together to make a program do new work.

The document gives the technical facts about the two tools. It shows where each
tool is better than the other one. It also shows the defects that this
comparison found in each tool. Section 8 gives the limits of the comparison.

This document comes from the rop-finder project. It is therefore not neutral.
Read section 8 before you make a decision from it.

---

## 2. What each tool is

### 2.1 rp++

The rp++ README describes the tool as a fast gadget finder in C++ (D). The
tool reads PE, ELF and Mach-O files on x86, x64, ARM and ARM64 (D). It does
that job well.

rp++ finds gadgets and prints them as text. It has 16 command-line options. It
has one output format. It has no ROP chain builder, no semantic query, no
classes, no JSON output and no cache (S). The README makes no claim to any of
these functions. Do not count them as defects in rp++.

rp++ is 13 years old. It has 170 commits, 2184 stars and 10 releases. Axel
Souchet released v2.1.5 on 14 September 2025 (M).

### 2.2 rop-finder

rop-finder is a port of ROPgadget to Rust with a larger scope. It finds
gadgets. It also does the following work (M):

- a semantic query on the effect of a gadget;
- a class and a quality rank for each gadget;
- a ROP chain builder for x86 and x64;
- a mitigation report for ELF, PE and Mach-O;
- five output formats;
- an MCP server with 15 tools for an agent.

It has 71 command-line options (M).

A larger scope is not automatically better. More code gives more surface for
defects. This comparison found six defects in rop-finder and five in rp++.
Section 6.6 gives the most serious one, and it is on the rop-finder side.

---

## 3. Method

### 3.1 The machine

- Host: Windows 11 Pro 26200, 24 logical CPUs.
- Linux measurements: WSL2 Ubuntu on the same host.
- Windows measurements: `dist\build\windows-x86_64\rop-finder.exe`.
- Test corpus: the 24 fixtures in `tests\fixtures`.
- Third tool for the parity check: ROPgadget 7.7.

Three agents ran the measurements between 3 and 4 September 2026. The agents
copied both binaries and all fixtures to an ext4 file system for the Linux
timings. No timing crosses the 9p file system of WSL2.

### 3.2 The labels

Each fact in this document carries a label:

- (M) means that an agent measured the fact on this machine.
- (S) means that an agent read the fact in the source code.
- (D) means that the fact is a claim in the documentation of the tool.

### 3.3 The rp++ binary

CAUTION: The rp++ binary in this comparison is not the official release build.
An agent compiled it from source in WSL2 with the zig C and C++ shims. The
agent used `-O2`. The official `src/CMakeLists.txt` sets
`CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE` and links the Linux build with
`-static` (S). This build has neither option. The official binary is therefore
plausibly faster than this one. Read each rp++ time in this document as an
upper limit on the time of the official build.

The binary reports `version 2.1.5 x64 ... for Linux (Release)` (M).

### 3.4 The two depth flags are different units

This point comes first, because it controls every speed number.

- rp++ `-r N` counts instructions. The tool returns gadgets of 1 to N+1
  instructions (M, S).
- rop-finder `--depth D` counts bytes of look-back. This is the ROPgadget
  unit, which rop-finder keeps for parity (M).

On x86 and x64, `rp++ -r K` is equal to
`rop-finder --depth (15*K) --max-insns (K+1)`. The number 15 is the largest
instruction size on x86 in rp++ (S). An agent verified the mapping against the
instruction-count histograms of both tools (M).

A comparison of `rp++ -r 5` against `rop-finder --depth 10` is therefore not a
comparison of equal work. Section 6.1 gives the matched-budget numbers.

---

## 4. Capability table

| Capability | rop-finder | rp++ |
|---|---|---|
| Architectures with a decoder (M) | 11 | 4 |
| Container formats (M) | 5 | 4 |
| Big-endian targets (M) | Yes | No |
| Fixtures of 24 with a gadget list (M) | 24 | 16 |
| Fixtures of 24 that need no flag (M) | 22 | 15 |
| Command-line options (M) | 71 | 16 |
| Output formats (M) | 5 | 1 |
| JSON or CSV output (M) | Yes | No |
| Semantic constraint query (M) | Yes | No |
| Gadget classes (M) | 8 | 0 |
| Quality rank (M) | Yes | No |
| ROP chain builder (M) | Yes | No |
| Chain feasibility report (M) | Yes | No |
| MCP server for an agent (M) | Yes | No |
| Pointer search by integer or hex (M) | No | Yes |
| Occurrence count per gadget (M) | No | Yes |
| Duplicate removal without a flag (M) | Yes | No |
| Limit on the instruction count (M) | No | Yes |
| Limit on the look-back bytes (M) | Yes | No |
| Filter to drop JOP or syscall gadgets (M) | Yes | No |
| Bad-byte filter on the address (M) | Yes | Yes |
| Rebase flag (M) | Yes | Yes |
| Binary header report (M) | Yes | Yes |
| Mitigation report (M) | Yes | No |
| Cache (M) | Yes | No |
| Non-zero exit code on a failure (M) | Yes | No |
| Test suite in the repository (M) | Yes | No |
| Stripped Linux binary, bytes (M) | 11951344 | 2721352 |

---

## 5. The technical advantages of rop-finder

### 5.1 More architectures and more container formats

rop-finder reads 11 architectures. rp++ reads 4.

**Evidence (M).** rop-finder decoded x86, x64, ARM, ARM Thumb, ARM64, MIPS32,
PPC32, PPC64, SPARC, RISC-V 32 and RISC-V 64 in the corpus. It read 22 of the
24 fixtures with no flag. The fat Mach-O file needs `--arch`, and the raw file
needs `--rawArch`.

rp++ stopped with an error on 8 fixtures (M). The errors are these:

- RISC-V 32, RISC-V 64, MIPS, PowerPC, PPC64 and SPARC give
  "Cannot determine the CPU type";
- the big-endian Mach-O file for PowerPC gives "Cannot determine the
  executable format used";
- the fat Mach-O file gives "I don't handle OSX Universal binaries".

On the MIPS fixture rp++ stops after 2 ms with 0 gadgets. rop-finder returns
133163 gadgets (M). rop-finder also reads three big-endian fixtures. rp++ has
no big-endian path (S).

**Cost and limit.** rp++ never claimed these architectures. The rp++ CPU
enumeration has exactly four members, and the vendored Capstone build compiles
only the ARM and AArch64 back ends (S). Wide architecture coverage also costs
rop-finder binary size (section 6.4). Both tools stop on the fat Mach-O file
without a flag.

### 5.2 Semantic constraint query

rop-finder selects a gadget by its effect on the registers. rp++ has no
equivalent, and it makes no such claim.

**Evidence (M).** On `elf-Linux-x64`, five orthogonal constraints reduce 43972
gadgets to 1:

| Query | Gadgets |
|---|---|
| No constraint | 43972 |
| `--set-reg rdi` | 318 |
| plus `--from-stack` | 89 |
| plus `--no-clobber rsi,rdx` | 79 |
| plus `--max-side-effects 1` | 37 |
| plus `--terminator ret` | 1 |

The last query returns `0x0000000000401648 : pop rdi ; ret`.

`--set-reg` is not a text match. The 318 hits include `mov rdi, ...` forms.
`--from-stack` separates a value from the payload from a computed value.

**Cost and limit.** The agents verified the classifier only against the tool
itself. No agent proved that the register model is correct for every
instruction. The query layer also costs code and binary size. rp++ answers the
same question with a text filter from a shell pipe, which is often enough.

### 5.3 Gadget classes and quality rank

rop-finder gives each gadget a class and a quality number. rp++ sorts the
output by the disassembly text and does no more (S).

**Evidence (M).** The eight primary classes partition the corpus of
`elf-Linux-x64` exactly. The sum is 43972, which is the total:

| Class | Gadgets |
|---|---|
| mem-write | 11605 |
| other | 9184 |
| arithmetic | 7990 |
| reg-write | 6699 |
| stack-pivot | 4597 |
| mem-read | 3515 |
| syscall | 382 |
| dispatcher | 0 |

With `--rank`, the first eight `reg-write` records all show `quality: 100`.
Without `--rank`, the same first eight show 54, 54, 77, 77, 77, 77, 46 and 59
(M).

**Cost and limit.** The quality number is a project convention. No agent
compared it against a second tool or against an expert judgement. The class
`other` holds 9184 gadgets, which is 21 percent of the corpus.

### 5.4 The ROP chain builder and the feasibility report

rop-finder writes a Python ROP chain for six targets. rp++ has no chain
builder and makes no such claim (S).

**Evidence (M).** The six targets are `linux-execve`, `linux-mprotect`,
`linux-syscall`, `linux-ret2libc`, `linux-srop` and
`windows-virtualprotect`. Six ELF fixtures gave a chain. The tool wrote a
24-line chain for `elf-Linux-x64` and a 64-line chain for `elf-FreeBSD-x86`.

`--plan-chain` always exits 0 and always writes JSON (M). On
`elf-x86-bash-v4.1.5.1` it returned 7 requirements. It marked `syscall_trap`
as unsatisfied with 0 candidates. It then reported that a depth increase from
10 to 20 and the `--multibr` flag both give `would_help: false`. The tool
establishes those two booleans by a new scan (M).

**Cost and limit.** This is the weakest area of rop-finder, and the limits are
large:

- The chain builder covers ELF and PE on x86 and x64 only. ARM, ARM64, MIPS
  and PPC each stop with a clear error message (M).
- `windows-virtualprotect` fails on both PE fixtures in the corpus (M).
- `linux-ret2libc` needs `--api-addr` and gives nothing without it (M).
- `linux-srop` refuses x86 and covers x86-64 only (M).
- Two fixtures give no chain at all (M).

The tool prints its own warning that the Windows chain runs under the project
emulator at `tests/emulate.py` and not on Windows. That warning is a claim in
the output of the tool. No agent executed a chain against a real target.

### 5.5 Machine-readable output

rop-finder writes five output formats. rp++ writes one.

**Evidence (M).** On `elf-Linux-x64` the formats give these results:

- `human`: 43976 lines, with a banner and a trailer;
- `json`: a pretty array, 219862 lines;
- `jsonl`: 43972 lines, one object per line, written during the scan;
- `csv`: a header row with 19 columns, plus 43972 rows;
- `raw`: 43972 lines with no banner.

The `jsonl` format streams. The first record is the `ret` at the lowest
address, not the first record in alphabetical order (M).

rp++ has one text format (M, S). A search of `src/rp/` for `json`, `csv` and
`xml` returns nothing (M). rp++ also writes its banner lines to stdout between
the results. A consumer program must therefore select the lines that start
with `0x` (M).

**Cost and limit.** The rp++ text format is stable and simple. A shell pipe
reads it well. The extra formats in rop-finder cost code and test surface.

### 5.6 The MCP server and its confinement model

rop-finder ships an MCP server with a directory allowlist. rp++ has no agent
interface and makes no such claim (S).

**Evidence (M).** The server refuses to start with no `--allow-dir`. It
explains that the MCP host chooses the working directory of the process. It
then offers `--allow-cwd` for a deliberate choice.

With an allowlist, the server reports 15 tools over protocol 2024-11-05 (M).
`get_server_config` returns the whole enforced envelope (M):

- `max_concurrent` 2;
- `timeout_secs` 60;
- `max_depth` 64;
- `max_results` 1000;
- `hard_max_results` 50000;
- `max_file_bytes` 268435456;
- `max_gadgets` 5000000;
- `cursor_ttl_secs` 300;
- a closed list of 9 error codes.

An agent tested the confinement. A call to `get_binary_info` on
`C:/Windows/System32/notepad.exe` with an allowlist of the fixtures directory
returned a structured error, not a scan (M):

```
{"code":"path_denied","message":"binary_path is not inside an allowed directory...","retryable":false}
```

The server enforces the allowlist. It does not only document it.

**Cost and limit.** The MCP binary is 16522752 bytes, which is larger than the
CLI (M). The parameter types are inconsistent: `set_reg` takes a string and
`no_clobber` takes an array (M). An agent drove raw JSON-RPC over stdio, not a
real MCP host. Only 3 of the 15 tools ran. Pagination, cursors, cancellation
and timeouts remain untested.

### 5.7 Output agreement with ROPgadget 7.7

rop-finder gives the same gadget list as ROPgadget 7.7 on 20 of 22 fixtures,
and the CI configuration holds that agreement as a gate.

**Evidence (M).** An agent sorted and compared the full listings of both tools.
Five benchmark binaries gave zero different lines:

| Fixture | rop-finder | ROPgadget 7.7 | Times faster | Gadgets |
|---|---|---|---|---|
| elf-Linux-x86 | 131 ms | 1381 ms | 10.5 | 42508 |
| elf-x64-bash-v4.1.5.1 | 159 ms | 1425 ms | 9.0 | 45377 |
| elf-ARM64-bash | 183 ms | 1055 ms | 5.8 | 17653 |
| elf-Mips-Defcon-20-pwn100 | 633 ms | 5318 ms | 8.4 | 133163 |
| elf-PowerPC-bash | 283 ms | 1716 ms | 6.1 | 86966 |

Over 22 fixtures, rop-finder took 3270 ms and ROPgadget took 24701 ms (M). Two
listings differ:

- `elf-Linux-RISCV_32`: the same 279 addresses, but 68 gadgets differ in text.
  The two tools decode the same halfword in a different XLEN mode.
- `pe-Windows-ARMv7-Thumb2LE-HelloWorld`: 404 against 38. rop-finder reads the
  PE machine type and selects Thumb without a flag. ROPgadget needs `--thumb`,
  and with that flag the two listings are identical (M).

The CI configuration at `.github/workflows/ci.yml` has 11 jobs (S). One job is
`parity`. It checks out a pinned ROPgadget oracle, makes a virtual environment
with capstone 5.0.7 and runs `tests/parity.py` as a gate (S). Other jobs run
`chain_parity.py`, `doc_claims.py`, `capability_matrix.py`,
`flag_conformance.py`, a benchmark band and 7 fuzz targets (S).

rp++ has no test suite. A search for a test file outside the vendored trees
returns nothing (M). The rp++ CI has three jobs, and each one builds the tool
and uploads an artefact (S). Five compiler and platform pairs build on each
push, which is wide portability coverage. It is not a correctness gate.

**Cost and limit.** No agent ran the rop-finder CI in this session. The gate is
read in the configuration file, not observed here. Parity with ROPgadget also
carries the limits of ROPgadget. Section 6.6 shows one such limit.

### 5.8 Correct rejection of invalid and unusable encodings

rop-finder rejects three groups of terminators that rp++ accepts. Two groups
are invalid encodings, and one group is unusable.

**Evidence (M).** An agent compared the one-instruction gadget sets of both
tools on `elf-Linux-x64`. rp++ returned 570 gadgets that rop-finder does not
return. Three groups of them are wrong:

| Group | Count on x64 | Fact |
|---|---|---|
| LOCK-prefixed branch | 59 | `f0 c3` is LOCK RET; the CPU raises #UD |
| Direct call to address 0 | 42 | `e8 rel32` with a computed target of 0 |
| `iretq` and `iretw` | 57 | rp++ excludes `iretd` but not these forms |

An example of the first group is
`0x430118: add eax, 0x17448D48 ; lock ret ; \x05\x48\x8d\x44\x17\xf0\xc3` (M).
An example of the second group is
`0x400318: call 0x00000000 ; \xe8\xe3\xfc\xbf\xff` (M).

The second group is a defect in the terminator test of rp++. The test is
`CallType && AddrValue == 0`, which means "an indirect call" (S). A direct call
with a computed target of 0 passes the same test. The x86 fixture gives 49 of
these.

rop-finder also finds a class of terminator that rp++ excludes by design. rp++
accepts an indirect branch only when `AddrValue == 0`, and BeaEngine computes
`AddrValue` for a RIP-relative operand (S). A synthetic reproducer confirms the
gap: rop-finder finds `jmp qword ptr [rip - 0x1d000005]` at offset 0xa, and
rp++ finds only the overlapping `jmp rdx` at 0xe (M). On x86-64 this form is
the PLT and GOT dispatch instruction.

**Cost and limit.** No agent executed any of these encodings on real hardware.
The #UD result comes from the instruction set manual, not from a test. The
RIP-relative gap gives only 1 gadget in each x64 fixture, although the class is
systematic.

### 5.9 Resource limits and exit codes

rop-finder stops with a budget message and a non-zero exit code. rp++ exits 0
after a failure.

**Evidence (M).** With `--max-gadgets 100`, rop-finder prints:

```
[Error] scan budget exhausted after 100 gadgets (limit 100); raise --max-gadgets/--max-memory,
lower --depth, or narrow the scan with --section
```

This is a budget report, not a short list. The tool also gives a full
explanation before it refuses the fat Mach-O file, and `--compat` reproduces
the ROPgadget behaviour with a warning (M).

rp++ returns exit code 0 after an unsupported architecture, and 0 after a
missing file (M). `main()` catches the exception, prints it and returns 0 (S).
Only a CLI11 argument error gives a non-zero code. A missing `-f` gives 106
(M). A wrapper script cannot detect an rp++ failure from the exit code.

**Cost and limit.** The rop-finder message is long. A user who wants the first
100 gadgets must add `--max-results` in the MCP path or pipe the output through
`head`. The exit-code defect in rp++ is small for interactive work.

### 5.10 The mitigation report

rop-finder reports the mitigations of the target file with evidence. rp++
prints a header dump and makes no mitigation claim.

**Evidence (M).** `--info` writes JSON and does no scan. It reports 7
mitigations for ELF, 8 for PE and 5 for Mach-O. Each entry carries an evidence
string that names the exact header field. Two examples:

- `nx`: "PT_GNU_STACK p_flags=0x6 (RW): the kernel maps the stack
  non-executable";
- `pie`: "e_type=ET_EXEC: the image declares a fixed load address".

The `fortify` entry returns a third state, `"enabled": "unknown"`, on a static
binary. The reason is that a static link leaves no relocation behind (M).

The report also gives 2169 symbols for `elf-Linux-x64` and 229 imports for the
x64 PE fixture, with the GOT and PLT addresses (M).

**Cost and limit.** No agent checked a single verdict against `checksec`,
`readelf` or `dumpbin`. The evidence strings read well, and several name what
`checksec.sh` prints. They remain unverified. rp++ `-i 1` to `-i 3` gives a
compact header view for a human reader, which is a different and valid job.

### 5.11 The cache

rop-finder has a cache. The measured gain is small.

**Evidence (M).** On the 6 MB MIPS fixture, with `ROP_FINDER_CACHE_DIR` set to
a scratch directory:

- a cold run with `--cache` takes 1315 ms, which is slower than a scan with no
  cache;
- a warm run takes 478 ms, against 559 ms with no cache.

The gain is about 15 percent on a warm run. The cache is not the reason for the
speed of the tool. The scanner is.

**Cost and limit.** The cold run pays a write cost of about 750 ms. No agent
tested the cache key against a modified file, so no agent verified the
integrity model. Do not use the cache as an argument in favour of rop-finder.

---

## 6. The technical advantages of rp++

### 6.1 Speed at a matched instruction budget

rp++ is 15 to 72 times faster than rop-finder at the same instruction budget.

**Evidence (M).** `rp++ -r 5 --unique` against
`rop-finder --depth 75 --max-insns 6`, best of 3 runs, on WSL2:

| Fixture | rp++ | rp++ gadgets | rop-finder | rop-finder gadgets | Times faster |
|---|---|---|---|---|---|
| elf-Linux-x86 | 0.481 s | 22890 | 9.033 s | 76115 | 18.8 |
| elf-Linux-x64 | 0.469 s | 19897 | 7.939 s | 88826 | 16.9 |
| Linux_lib32.so | 0.770 s | 37590 | 12.091 s | 101662 | 15.7 |
| elf-ARM64-bash | 0.100 s | 3611 | 7.238 s | 7071 | 72.0 |
| pe-x64-cmd | 0.084 s | 2578 | 1.687 s | 21087 | 20.0 |
| macho-x64-ls | 0.006 s | 194 | 0.142 s | 2469 | 24.0 |

rop-finder returns 3 to 4.5 times more gadgets. Most of that difference comes
from the wider terminator set, not from a deeper search (M).

The cause is a design difference. rp++ stops the backward walk after N
preceding instructions (S). rop-finder has no instruction limit on the scan.
`--max-insns` is a filter after the scan, and it costs extra time. On
`elf-Linux-x64` at `--depth 75`, the scan takes 6.338 s and gives 188384
gadgets. With `--max-insns 6` the same scan takes 7.937 s and gives 88826
gadgets (M).

**Cost and limit.** The two tools do different work in this test, because the
terminator sets differ. The rp++ binary in the test has no LTO, so the official
build is plausibly faster again. This is a real design advantage for rp++, and
it points at a missing feature in rop-finder.

### 6.2 Memory

rp++ uses 21 times less memory than rop-finder at a matched budget.

**Evidence (M).** On `Linux_lib64.so`:

| Tool and setting | Maximum resident memory |
|---|---|
| `rp++ -r 5 --unique` | 31104 KB |
| `rop-finder --depth 75 --max-insns 6` | 654380 KB |
| `rop-finder --depth 10` (default) | 39996 KB |

Both tools hold the whole result set in memory and then print it (S).

**Cost and limit.** At its own default depth, rop-finder uses 39996 KB, which
is close to rp++. The 21-times gap appears only at the matched budget, where
rop-finder explores 75 bytes of look-back. An earlier measurement on a 43 MB
library gave 609 MB for rp++ and 669 MB for rop-finder, which is a small
difference (M).

### 6.3 Speed at the default settings on WSL2

At the default settings on WSL2, rp++ is faster than rop-finder on every
fixture that both tools read.

**Evidence (M).** Best of 3 runs, in milliseconds:

| Fixture | rp++ `-r 5 --unique` | rop-finder default | rop-finder with 1 thread |
|---|---|---|---|
| elf-Linux-x64 | 460 | 597 | 179 |
| elf-Linux-x86 | 476 | 677 | — |
| Linux_lib64.so | 694 | 799 | 224 |
| elf-ARM64-bash | 99 | 1871 | 355 |
| elf-ARMv7-ls | 11 | 115 | — |
| pe-x64-cmd | 84 | 185 | — |
| macho-x64-ls | 7 | 19 | — |

The margin is 1.15 to 2.7 times on x86, x64, PE and Mach-O. It is 10 to 19
times on ARM and ARM64. rp++ also returns fewer gadgets at these settings, so
the two tools do not do equal work.

This test found a defect in rop-finder. On WSL2, each added thread makes the
scan slower:

| Fixture | 1 thread | 2 | 4 | 8 | 16 | 24 |
|---|---|---|---|---|---|---|
| elf-Linux-x64 | 179 | 240 | 345 | 495 | 628 | 623 |
| Linux_lib64.so | 224 | 310 | 428 | 624 | 798 | 801 |
| elf-Mips-Defcon-20 | 2316 | 3953 | 8300 | 14131 | 16808 | 12773 |

On `Linux_lib64.so`, rop-finder uses 1.47 s of user time and 16.43 s of system
time. rp++ uses 0.72 s of user time and 0.03 s of system time (M).

**Cost and limit.** The thread defect is specific to WSL2. The same rop-finder
code on native Windows scales in the normal way. On Windows, `elf-Linux-x64`
takes 265 ms with 1 thread and 172 ms with 8 threads (M). Do not describe this
as a general threading defect. With one thread on WSL2, rop-finder is 2.6 times
faster than rp++ on `elf-Linux-x64` and 3.1 times faster on `Linux_lib64.so`
(M). rp++ keeps its ARM64 and MIPS advantage in all cases.

### 6.4 A smaller binary and a faster start

The rp++ binary is 4.4 times smaller than the rop-finder binary, and it starts
about 2.4 times faster.

**Evidence (M).** Both binaries stripped, on Linux:

| Item | rp++ | rop-finder |
|---|---|---|
| Size | 2721352 B | 11951344 B |
| 20 runs of `--help` | 27 ms | 38 ms |
| Load cost above the spawn floor | ~0.4 ms | ~0.95 ms |

The spawn floor on the same machine is 19 ms for 20 runs of `/bin/true`.

An earlier measurement reported a 9-times start difference. The later warm-cache
measurement gives 2.4 times. Use the 2.4 figure. The 9-times figure looks like
a cold-cache result (M).

The official rp++ release assets are smaller again. The Linux clang build is
1682246 B and the macOS build is 568342 B (M, from the GitHub API).

**Cost and limit.** The size difference matters for a container image or a
constrained host. The start difference matters only for a shell loop with
thousands of calls. For a single scan of 130 ms to 600 ms, 0.5 ms is noise.

### 6.5 A simpler build

rp++ builds with no fetched dependency. This is a real advantage.

**Evidence (S, M).** rp++ vendors BeaEngine, Capstone 4.0.2, fmt 11.1.3 and
CLI11 2.1.2 as source in the tree. The repository has no `.gitmodules` file
(M). The build needs a C++20 compiler, cmake and ninja. The build script is one
line. The `src/CMakeLists.txt` file is 50 lines (S).

An agent compiled the tool with no cmake at all. The agent wrote the compile
line by hand for about 20 C++ files and the vendored C. It worked on the first
try, with no patch (M).

rop-finder needs a Rust toolchain and a fetch from crates.io. That is more
steps and a network dependency.

**Cost and limit.** The vendored trees carry a licence consequence. rp++ itself
is MIT. The vendored BeaEngine tree contains a GPLv3 `COPYING.txt` and an LGPL
`COPYING.LESSER.txt` (M). A distributed rp++ binary therefore carries an
(L)GPL component. This is a fact about redistribution, not a defect.

### 6.6 Terminators that branch through memory

rp++ finds a whole family of indirect branch terminators that rop-finder never
prints. This is the most serious result in this comparison, and it is against
rop-finder.

**Evidence (M).** An agent compared the one-instruction gadget sets of both
tools:

| Fixture | rp++ | rop-finder | Agree | rp++ only | rop-finder only |
|---|---|---|---|---|---|
| elf-Linux-x64 | 8444 | 7889 | 7874 | 570 | 15 |
| elf-Linux-x86 | 8562 | 8271 | 8181 | 381 | 90 |
| pe-x64-cmd | 1650 | 1650 | 1645 | 5 | 5 |
| macho-x86-ls | 164 | 83 | 83 | 81 | 0 |
| macho-x64-ls | 94 | 101 | 93 | 1 | 8 |

Of the 570 gadgets on x64, 429 are indirect branches through memory. All of
them use SIB indexing or an absolute disp32 address. Three examples (M):

```
0x401381  jmp  qword [rbx+rax*4+0x38]
0x401718  call qword [0x006BBEC0+rbx*8]
0x402c88  jmp  qword [rax+rcx*2-0x77]
```

On `elf-Linux-x86` the same gap costs 317 gadgets, and those gadgets are the
PLT (M):

```
0x80481e0  jmp [0x080F400C]
0x80481f0  jmp [0x080F4010]
0x8048200  jmp [0x080F4014]
```

A PLT stub is one of the most useful JOP gadgets in a binary. On
`macho-x86-ls`, this family is 81 of 164 terminators, which is 49 percent.

An agent also found a second gap. rop-finder skips a terminator that starts
inside an earlier terminator. The reproducer is a 13-byte blob with a
`jmp [rdx-0x6f000005]` at offset 0 and a `call [rax-0x51000007]` at offset 4.
rp++ finds both. rop-finder finds only the one at offset 0. With the two
instructions separated by NOPs, both tools find both (M).

**Cost and limit.** The agent did not read the rop-finder source to find the
cause. The agent also did not run ROPgadget on the same test. rop-finder holds
byte parity with ROPgadget on 20 of 22 fixtures. rop-finder therefore
plausibly inherits the gap from the upstream tool. That is an explanation, not
an excuse. Both gaps remain open defects in rop-finder.

A third defect appears in the same test. The 15 rop-finder-only gadgets on
`elf-Linux-x64` include 12 far calls with the bytes `ff 5b c3`. `FF /3` is
CALL FAR m16:32. rop-finder gives them the class `call-mem` and prints them
without the word "far". They need a valid segment selector, so they are
unusable. rp++ excludes them correctly (M).

### 6.7 Pointer search

rp++ finds a byte string or an integer inside the executable sections.
rop-finder has no equal option for an integer.

**Evidence (M).** `--search-hexa` prints a line for each match, in the form
`0x100003bf3: UH\x89\xe5`. `--search-int e5894855` matches the bytes
`55 48 89 e5`.

Both searches read the executable sections only, through
`get_executables_section` (S).

**Cost and limit.** `--search-int` parses its argument as hex and always uses
4 bytes. An agent passed `--search-int 100`, and the tool matched the byte
pattern `\x00\x01\x00\x00`, which is 0x100 (M, S). A user who wants decimal
100 gets a different result with no warning. Since v2.1.5, both searches also
run a full ROP scan of 5 instructions first. The reason is that the tool sets
`--rop` to 5 when the user gives no depth (M, S).

rop-finder has `--opcode` for a byte sequence and `--string` for a text
pattern in the data sections (M). It has no integer search.

### 6.8 Occurrence counts

rp++ prints the number of addresses that share a gadget. rop-finder does not
print this number in the default output.

**Evidence (M).** With `--unique`, each line ends with a suffix such as
`(1 found)`. The count helps a user to select a stable gadget.

**Cost and limit.** rp++ removes duplicates only with `--unique`. Without the
flag, the tool prints every occurrence. An agent measured 28 duplicated
disassembly strings on `macho-x64-ls -r 2` (M). rop-finder removes duplicates
by default and offers `--all` for the full list.

### 6.9 The ELF program headers

rp++ reads the ELF program headers, not the section headers. A stripped ELF
file with no section table still gives gadgets.

**Evidence (S).** `elf_struct.hpp:435` iterates the program headers and keeps
each header with the PF_X flag. It then dumps the range
`[p_offset, p_offset+p_filesz)`. The whole executable segment is therefore in
scope, and that includes the PLT and any read-only data inside the segment.

**Cost and limit.** No agent checked which headers rop-finder reads. This is an
rp++ fact, not a proven difference between the two tools.

### 6.10 Maturity

rp++ is a mature tool with a known author and a long record.

**Evidence (M).** The repository has 170 commits and a first commit in 2012. It
has 2184 stars and 4 open issues. It is not archived. Axel Souchet released
v2.1.5 on 14 September 2025.

The 2025 commits are real fixes. They correct the order of the bad-byte filter
against the uniqueness step, the WinDbg form of `--va` and the static release
binaries (M). The project also merges pull requests from outside contributors.

rop-finder is at v1.0.0-rc1 and has no release record.

**Cost and limit.** Maturity does not remove defects. This comparison found
five in rp++:

- the terminator test admits a direct call to address 0;
- the tool accepts LOCK-prefixed invalid encodings;
- the tool excludes RIP-relative indirect branches;
- `--va` has no effect on a Mach-O file, because the offset cancels itself in
  `macho_struct.hpp:300`;
- `--bad-bytes` reads the low 4 bytes of the address only, so it is unsound
  above bit 31. With `--va 0xaa00000000`, the filter `\xaa` removed 0 gadgets
  and the filter `\x00` removed 161 (M).

`--max-thread` is also close to inert. The thread pool takes one whole section
per task, and a normal ELF file has one executable segment (M, S).

---

## 7. Where each tool is the correct choice

| Task | Correct tool | Reason |
|---|---|---|
| Find gadgets in a MIPS, PPC, SPARC or RISC-V file | rop-finder | rp++ stops with "Cannot determine the CPU type" (M) |
| Find gadgets in a big-endian file | rop-finder | rp++ has no big-endian path (S) |
| Find every gadget of 6 instructions or fewer, fast | rp++ | 15 to 72 times faster at a matched budget (M) |
| Find a PLT stub or another branch through memory | rp++ | rop-finder omits 429 such gadgets on one x64 fixture (M) |
| Find one gadget that sets a register from the stack and clobbers nothing | rop-finder | Five constraints reduce 43972 gadgets to 1 (M) |
| Give a gadget list to a program or an agent | rop-finder | JSON, JSONL, CSV and an MCP server with an allowlist (M) |
| Run a scan on a small container image or a constrained host | rp++ | 2.7 MB against 12.0 MB, and no fetched dependency (M, S) |
| Write a first ROP chain for a Linux x86 or x64 ELF file | rop-finder | Six chain targets, and a feasibility report on a failure (M) |
| Find a pointer to an integer value inside an executable section | rp++ | `--search-int` and `--search-hexa` (M) |

---

## 8. The limits of this comparison

### 8.1 This document is not neutral

This document comes from the rop-finder project. The authors of rop-finder
selected the corpus, the flags and the measurements. Read section 6 first if
you want the case against rop-finder.

### 8.2 The rp++ binary is not the official build

The agents compiled rp++ from source with `-O2`, with no LTO and with no
`-static` link. The official build sets both options (S). Every rp++ time in
this document is an upper limit on the time of the official build. The stripped
size of 2721352 B may also differ from the shipped size. No agent downloaded a
release binary.

### 8.3 The agents did not measure these items

Platform and build:

- rp++ on Windows and on macOS. Every rp++ measurement ran on WSL2 Ubuntu x64.
- The colour path for the Windows console and the MSVC build of rp++ (read in
  source only).
- The `-i 2` and `-i 3` levels, the `--raw arm` and `--raw arm64` modes, and
  the FreeBSD and OpenBSD paths of rp++.
- The exact BeaEngine version inside rp++.

Correctness:

- The gadget output of rp++ against the ROPgadget 7.7 oracle. No agent ran a
  set difference between those two tools.
- Whether ROPgadget also omits the 429 and 317 branches through memory.
  rop-finder possibly inherits the gap from the upstream tool. It possibly
  introduces the gap itself.
- The agreement of the two tools on gadgets of more than one instruction. Every
  set comparison in section 6.6 uses one-instruction gadgets only.
- The correct XLEN mode for the RISC-V 32 fixture. The two tools differ, and no
  agent read the instruction set manual.
- Whether the extra `lock sbb` gadget at depth 40 is a valid decoding or a
  decoder artefact.
- The correctness of any emitted ROP chain against a real target. No agent
  executed a chain.
- The correctness of any mitigation verdict against `checksec`, `readelf` or
  `dumpbin`.
- The gadget sets of rp++ on ARM, Thumb and ARM64. The agents timed those
  fixtures but ran no set comparison.

Behaviour and internals:

- The cause of the missing branches through memory in rop-finder. The agents
  measured the gap but did not read the scanner source.
- The reason that rop-finder prints `ff 5d c3` and not `ff 5d 11`. The
  behaviour is repeatable and depends on the displacement byte. No agent
  explained it.
- The cause of the WSL2 thread collapse in rop-finder. No agent ran a profile
  or an strace.
- The behaviour of both tools on a packed file, a malformed file or a file
  larger than 6 MB.
- The pagination, the cursors, the cancellation and the timeouts of the MCP
  server. Only 3 of the 15 tools ran.
- The behaviour of the MCP server under a real agent host. An agent drove raw
  JSON-RPC over stdio.
- The integrity model of the rop-finder cache. No agent tested a cache key
  against a modified file.
- An audit log. This document contains no measurement of an audit log in
  either tool, so it makes no claim about one.
- The rop-finder CI gate. The agents read `.github/workflows/ci.yml` and did
  not run the workflow in this session.

### 8.4 Two numbers changed between measurements

Two earlier numbers were wrong, and this document uses the later values:

- The start-time difference is 2.4 times, not 9 times. The 9-times value came
  from a cold cache.
- The CPU-time comparison on a 43 MB library compared `rp++ -r 5` against
  `rop-finder --depth 6`. Those two settings are different units, so that
  comparison is void. Section 3.4 gives the correct mapping.

### 8.5 Do not compare against a claim that rp++ never made

rp++ describes itself as a fast gadget finder for four architectures and three
container formats. It meets that description. It has no chain builder, no
semantic query, no class model, no machine-readable format, no cache and no
agent interface. It also reads no other architecture. Each absence is a scope
decision. It is not a defect in rp++.
