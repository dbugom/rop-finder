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
  rf-core/      # binary loaders (goblin), section model, rebasing
  rf-scan/      # anchor tables, per-start decode cache, filters, dedup
  rf-classify/  # (Phase 5) semantic classification of gadgets
  rf-chain/     # (Phase 4) ROP chain builders
  rf-cli/       # `rop-finder` command line tool (clap)
  rf-mcp/       # (Phase 3) MCP server
tests/
  fixtures/     # ELF binaries copied from ROPgadget's test suite
  parity.py     # output-parity harness against ROPgadget (run with python)
```

## Phase roadmap (PLAN.md §7)

| Phase | Deliverable | Status |
|---|---|---|
| **0. Spike** | `rf-core` + `rf-scan` MVP: x86/x64 ELF only, memchr anchors, per-start decode cache, JSON out; parity harness | **this phase** |
| 1. Engine | All ROPgadget arches (capstone-rs), PE/Mach-O/Universal/Raw loaders, trie index, fuzz corpus | planned |
| 2. Features | `--section`, `--base`/`--offset` parity polish, structured binary info | planned |
| 3. MCP server | `rf-mcp` stdio tools | planned |
| 4a/4b. Chains | Chain IR, Linux execve chains, Windows VirtualProtect chains | planned |
| 5. Differentiators | Semantic classification + ranking, chain DSL, dispatcher analysis | planned |

## Building

```sh
cargo build            # debug
cargo build --release  # optimized CLI at target/release/rop-finder
cargo test             # unit tests (rf-core, rf-scan)
cargo clippy -- -D warnings
```

## Usage

```sh
rop-finder --binary tests/fixtures/elf-x64-bash-v4.1.5.1 --depth 10
rop-finder --binary /bin/ls --json --norop
rop-finder --binary ./prog --only "pop|ret" --badbytes "0a|0d" --range 0x1000-0x2000
rop-finder --binary ./prog --base 0x400000 --offset 0x1000
```

Output format matches ROPgadget: `0x<addr> : insn ; insn ; ...` (human) or a
JSON array of `{"vaddr", "bytes", "text"}` with `--json`.

Exit codes: `0` success, `1` usage error, `2` malformed/unsupported binary.

## Parity harness

```sh
python tests/parity.py            # uses debug binary
python tests/parity.py --release  # uses release binary + timing comparison
```

Compares post-dedup `(vaddr, bytes)` gadget sets against
`python ../ropgadget/ROPgadget.py --binary <f> --depth 10 --dump` for every
fixture and prints per-file overlap statistics, sample diffs, and a speedup
measurement on `elf-x64-bash-v4.1.5.1`.

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
- Disassembly uses iced-x86 (FastFormatter) instead of capstone. Because
  dedup is text-keyed, formatter differences can shift dedup *classes*, not
  just cosmetics; `rf-scan` therefore normalizes the biggest capstone quirks
  (segment-override prefixes on non-memory instructions, rep/repne outside
  string ops and branch families, rep/repne kept on string ops, memory sizes
  always shown, RIP-relative operands). Residual parity noise (~0.05–0.2% of
  gadgets): capstone accepts some invalid LOCK-prefixed instructions iced
  rejects (and vice versa, e.g. `ud0` operands), 64-bit segment-override
  handling, and dedup-survivor swaps from any remaining text difference.
  Parity is judged on post-dedup `(vaddr, bytes)` sets.
- Anchor matching replicates Python `re.finditer` non-overlapping semantics
  per anchor pattern.
- MPX anchors (`f2 c3` etc.) decode as `bnd ret`/`bnd jmp`, which are not in
  ROPgadget's accepted branch list — they are scanned but always rejected,
  exactly as in ROPgadget.
- `--filter`: ROPgadget anchors the regex with `re.match("(…)$")`, i.e.
  effectively full-mnemonic equality; Phase 0 uses suffix matching on `|`
  parts (close enough for the flag's purpose; not used by the parity harness).
