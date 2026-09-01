# rop-finder

A Rust rewrite of [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) —
a fast, memory-safe ROP/JOP/SYS gadget finder with structured internals,
aiming for output parity with the original Python tool while being an order
of magnitude faster on x86/x64.

The full design rationale lives in [`../PLAN.md`](../PLAN.md). ROPgadget
remains the parity oracle; its source is cloned at `../ropgadget`.

## Layout

```
crates/
  rf-core/      # binary loaders (goblin): ELF, PE, Mach-O, Universal, Raw
  rf-scan/      # anchor tables, per-start decode cache, filters, dedup,
                # iced-x86 (x86/x64) + capstone-rs (all other arches), rayon
  rf-classify/  # (Phase 5) semantic classification of gadgets
  rf-chain/     # (Phase 4) ROP chain builders
  rf-cli/       # `rop-finder` command line tool (clap) + shared scan
                # orchestration library (ScanRequest → scan_bytes/info_bytes)
  rf-mcp/       # `rop-finder-mcp` MCP server (rmcp SDK, stdio only)
tests/
  fixtures/     # binaries copied from ROPgadget's test suite (all formats)
  parity.py     # output-parity harness against ROPgadget (run with python)
```

## Phase roadmap (PLAN.md §7)

| Phase | Deliverable | Status |
|---|---|---|
| **0. Spike** | `rf-core` + `rf-scan` MVP: x86/x64 ELF only, memchr anchors, per-start decode cache, JSON out; parity harness | done |
| **1. Engine** | All ROPgadget arches (capstone-rs), PE/Mach-O/Universal/Raw loaders, rayon parallelism | **done** (trie index, fuzz corpus pending) |
| 2. Features | `--section`, `--base` hardening, `--info` structured binary info | **done** |
| 3. MCP server | `rf-mcp` stdio tools | **done** |
| 4a/4b. Chains | Chain IR, Linux execve chains, Windows VirtualProtect chains | planned |
| 5. Differentiators | Semantic classification + ranking, chain DSL, dispatcher analysis | planned |

## Building

```sh
cargo build            # debug
cargo build --release  # optimized CLI at target/release/rop-finder
cargo test             # unit tests (rf-core, rf-scan, rf-cli)
cargo clippy -- -D warnings
```

## Usage

```sh
rop-finder --binary tests/fixtures/elf-x64-bash-v4.1.5.1 --depth 10
rop-finder --binary /bin/ls --json --norop
rop-finder --binary ./prog --only "pop|ret" --badbytes "0a|0d" --range 0x1000-0x2000
rop-finder --binary ./prog --base 0x400000 --offset 0x1000
rop-finder --binary tests/fixtures/raw-x86.raw --rawArch=x86 --rawMode=32
rop-finder --binary tests/fixtures/elf-ARMv7-ls --thumb
rop-finder --binary ./ntoskrnl.exe --section .text --base 0   # ring0: RVAs, .text only
rop-finder --binary ./prog --info                           # metadata JSON, no scan
```

Formats are detected by magic bytes (ELF, PE, Mach-O, Universal/fat Mach-O);
`--rawArch`/`--rawMode`/`--rawEndian` force the raw loader, exactly like
ROPgadget (accepted values: `x86|arm|arm64|sparc|mips|ppc|riscv`,
`32|64|arm|thumb|riscv`, `little|big`). Universal binaries are scanned as
ROPgadget does: all slices' executable regions concatenated, disassembled
with the first slice's architecture. Architectures: x86, x64, ARM (incl.
Thumb via `--thumb`), ARM64, MIPS32/64, PPC32/64, SPARC(V9), RISC-V 32/64 —
with endianness from the binary.

Output format matches ROPgadget: `0x<addr> : insn ; insn ; ...` (human) or a
JSON array of `{"vaddr", "bytes", "text"}` with `--json` (plus an `arch`
field per gadget for Universal binaries, and a `section` field per gadget
when `--section` is used).

Exit codes: `0` success, `1` usage error, `2` malformed/unsupported binary.

## Phase 2 features

### `--section <glob>` — scan only selected executable sections

Restricts the scan to the binary's *named* executable sections
(`SHF_EXECINSTR` sections for ELF, `Characteristics & IMAGE_SCN_MEM_EXECUTE`
for PE, `__TEXT` executable sections for Mach-O) instead of ROPgadget's
default `PF_X` *segment* granularity. Repeatable and comma-separated, with
`*` globbing:

```sh
rop-finder --binary ./prog --section .text
rop-finder --binary ./prog --section ".init*,.plt" --section .text
```

With `--json`, every gadget gains a `section` field naming the section that
contains it. An unknown name exits `1` and lists the available executable
sections. `--range`, `--base`, `--offset`, and `--badbytes` compose with
`--section` normally.

**Stripped-ELF caveat:** without a section table there are no names to
match; the loader falls back to synthetic `PT_LOAD#n` segment names (one per
executable segment) and prints a one-line stderr warning when `--section` is
used against such a binary.

### `--base <hex>` — load-time rebase

Rebases the image at load time, before scanning: every gadget vaddr becomes
`vaddr - original_image_base + <base>`. `--base 0` yields RVA-style
addresses. `--offset` is applied *after* the rebase, so the final printed
address is `vaddr - original_base + base + offset`. `--badbytes` is checked
against that **final** address — e.g. after `--base 0x55550000`,
`--badbytes 55` eliminates every gadget. For Universal (fat Mach-O)
binaries every slice is slid by the same delta (`base - first_slice_base`);
ROPgadget has no `--base` for Universal.

### `--info` — structured binary metadata

Dumps image metadata as JSON and exits without scanning (`--base` is
honoured, so the printed addresses match what a scan would emit):

```json
{
  "format": "pe",            // elf | pe | macho | raw | universal
  "arch": "x64",
  "endianness": "little",
  "addr_size": 8,
  "image_base": "0x4ad00000",
  "entry": "0x4ad090b4",
  "sections": [{"name": ".text", "vaddr": "0x4ad01000", "size": 160256,
                "executable": true, "writable": false}, ...],
  "imports":  [{"dll": "KERNEL32.dll", "symbol": "GetTickCount",
                "iat_vaddr": "0x4ad2b382"}, ...]   // PE only; [] otherwise
}
```

Universal binaries emit `{"format": "universal", "slices": [<per-slice macho
info>, ...]}`. Addresses are hex strings (consistent with gadget vaddrs),
sizes are numbers.

## MCP server

`rop-finder-mcp` (crate `rf-mcp`) exposes the engine to AI agent hosts over
the Model Context Protocol, using the official Rust SDK (`rmcp`). **stdio
transport only** — there is deliberately no network listener.

```sh
cargo build --release
target/release/rop-finder-mcp --allow-dir /path/to/binaries --allow-dir tests/fixtures
# optional: --cache-dir <dir> --timeout-secs 60 --max-results 1000
```

The scan orchestration (`ScanRequest` → `scan_bytes`/`info_bytes`) lives in
the `rf-cli` library and is shared verbatim with the CLI — no stdout
scraping.

### Tools

All six tools return structured JSON (`structuredContent` + text content);
errors are `{error: {code, message}}` with the MCP `isError` flag.

| Tool | Purpose |
|---|---|
| `find_gadgets` | ROP gadgets only (ret-terminated) |
| `find_jop_gadgets` | JOP gadgets only (jmp/call-terminated) |
| `find_syscall_gadgets` | SYS gadgets only (syscall/sysenter/int/iret) |
| `get_binary_info` | The `--info` payload (format/arch/sections/imports), no scan |
| `search_gadgets_by_pattern` | Regex over gadget text (invalid regex → literal substring), full scan |
| `run_ropgadget_command` | Flag passthrough, restricted to the allowlist below |

Example JSON-RPC exchange (newline-delimited over stdio):

```jsonc
=> {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}
=> {"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
=> {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"find_gadgets",
     "arguments":{"binary_path":"tests/fixtures/elf-x64-bash-v4.1.5.1","depth":6,
                  "section":".plt","max_results":10}}}
<= {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"{...}"}],
     "isError":false,"structuredContent":{"gadgets":[{"vaddr":"0x...","bytes":"...",
     "text":"... ; ret","section":".plt"},...],"total_count":283,"returned":10,
     "truncated":true,"binary_sha256":"...","cache":"miss","fallback_section_names":false}}}
```

`run_ropgadget_command` takes `{"binary_path": ..., "args": ["--depth","6",
"--only","pop|ret"]}`. The flag allowlist (PLAN §6.1): `--depth --norop
--nojop --nosys --only --filter --re --range --section --base --offset
--badbytes --align --multibr --json`. `--re` (regex over gadget text) and
`--align` (address alignment) are applied as post-filters; everything else
maps onto the engine. Side-channel flags (`--dump`, `--string`, `--memstr`,
`--console`) and unknown flags are rejected with `invalid_flag`.

### Security model (PLAN §6.1, hardened after review)

The server would otherwise be a local arbitrary-file-read primitive, so:

- **Path confinement**: `binary_path` must canonicalize (symlinks and `..`
  resolved) into the allowlist — the server process working directory plus
  every `--allow-dir`. Anything else → `path_not_allowed`.
- **Flag allowlist** for `run_ropgadget_command` (see above); no flag can
  expand file access beyond the directory allowlist.
- **Resource caps**: `max_results` defaults to 1000, hard-capped at 50000;
  per-request timeout defaults to 60 s (hard cap 300 s). Scans run on
  blocking worker threads; a timed-out request returns a `timeout` error
  while the orphaned worker finishes in the background.
- **Content-hash cache**: SHA-256 of the file plus the scan parameters keys
  an in-memory cache (plus optional `--cache-dir` on-disk spill), so
  repeated queries on the same binary are instant.
- **Sampled responses**: at most `max_results` gadgets plus `total_count`
  and `truncated`. PLAN calls for "top-N by quality rank"; ranking lands in
  Phase 5, so v1 returns the first N in deterministic traversal order.
- **No panics**: malformed binaries return a `binary_error` tool error.

## Parity harness

```sh
python tests/parity.py            # uses debug binary
python tests/parity.py --release  # uses release binary + timing comparison
```

Compares post-dedup `(vaddr, bytes)` gadget sets against
`python ../ropgadget/ROPgadget.py --binary <f> --depth 10 --dump` for the
full fixture corpus (ELF all arches, PE, Mach-O, Universal, raw — raw gets
`--rawArch=x86 --rawMode=32` on both sides) and prints per-file overlap
statistics, sample diffs, and per-file timings. Current status: 99.93% of
ROPgadget's gadgets reproduced across ~764 K reference gadgets; 100% on
MIPS/PPC/SPARC/RISC-V/Universal/raw/Mach-O-PPC/x64.

## Semantic notes / intentional deviations

- Gadget validity follows ROPgadget's clean-decode rule (`gadgets.py:100-103`):
  bytes from candidate start to anchor end must decode linearly with the total
  decoded size equal to `end - start`. The anchor *start* need not coincide
  with an instruction boundary (e.g. `66 0f 05` decodes as a 3-byte `syscall`,
  and a gadget may "end" on an anchor byte embedded mid-instruction, like a
  `\xc3` SIB byte inside `jmp [r11+r8*8]`).
- Scan granularity matches ROPgadget exactly: every program header with the
  `PF_X` flag (not section headers), reading `p_memsz` file bytes from
  `p_offset` with Python-slice clamping semantics. rf-core still exposes the
  `SHF_EXECINSTR` section model (`exec_sections()`) for Phase-2 `--section`
  support; stripped ELFs fall back to `PT_LOAD` sections there.
- Dedup is by gadget **text**, first-occurrence-wins, in deterministic
  traversal order: region order → anchor-table order (ROP, JOP, SYS per
  region) → anchor-hit offset order → depth order — matching
  `rgutils.deleteDuplicateGadgets` + `core.py:__getGadgets`.
- Disassembly uses iced-x86 (FastFormatter) for x86/x64 and capstone-rs
  (pinned `capstone = "=0.13.0"`, capstone-sys 0.17 bundling the C capstone
  5.0.x "next" core) for every other architecture. Because dedup is
  text-keyed, formatter differences can shift dedup *classes*, not just
  cosmetics; the x86 path normalizes the biggest capstone quirks
  (segment-override prefixes on non-memory instructions, rep/repne outside
  string ops and branch families, rep/repne kept on string ops, memory sizes
  always shown, RIP-relative operands). Residual parity noise (~0.05–0.2% of
  gadgets on x86/x64): capstone accepts some invalid LOCK-prefixed
  instructions iced rejects (and vice versa, e.g. `ud0` operands), far
  jumps (`ljmp`/`lcall`), and dedup-survivor swaps from any remaining text
  difference. On ARM/ARM64 the capstone "next" core rejects a few encodings
  python-capstone 5.0.7 accepts (`udf #0`, some `vmov`/`vmrs` VFP forms) —
  11 gadgets on elf-ARM64-bash, 14 on elf-ARMv7-ls. Parity is judged on
  post-dedup `(vaddr, bytes)` sets.
- Non-x86 scan semantics replicate `gadgets.py:__gadgetsFinding`: aligned
  backward stepping in virtual-address space with byte-fallback
  (gadgets.py:73-89), the fixed-width clean-decode rule (104-107), the
  RISC-V last-instruction-size rule (109-112), and per-arch passClean
  (488-498 — branch-in-middle rejection exists only on x86). SPARC/ARM64
  SYS tables are empty, matching ROPgadget's TODO placeholders.
- Thumb mode comes only from `--thumb` (gadgets.py:331,448): a PE tagged
  ARMv7/Thumb2 is scanned in ARM mode by default, like ROPgadget.
- Gadgets carry `delay_slot: true` on MIPS/SPARC (PLAN.md §4).
- Anchor matching replicates Python `re.finditer` non-overlapping semantics
  per anchor pattern.
- MPX anchors (`f2 c3` etc.) decode as `bnd ret`/`bnd jmp`, which are not in
  ROPgadget's accepted branch list — they are scanned but always rejected,
  exactly as in ROPgadget.
- `--filter`: ROPgadget anchors the regex with `re.match("(…)$")`, i.e.
  effectively full-mnemonic equality; Phase 0 uses suffix matching on `|`
  parts (close enough for the flag's purpose; not used by the parity harness).
