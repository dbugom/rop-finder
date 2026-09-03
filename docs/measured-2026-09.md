# Measured baseline — 2026-09-03

Numbers measured on this tree, on one machine, so that later releases can cite a
file instead of a memory. `REMEDIATION.md` Phase 1 rewrites README/MANUAL/PLAN to
reference this document rather than restating figures inline.

**Environment.** macOS (Darwin 27), Apple Silicon. rustc 1.89.0.
Oracle: ROPgadget 7.7 (`../ropgadget`) on CPython 3.11 with capstone 5.0.7 —
the same capstone generation `rf-scan` pins via `capstone = "=0.13.0"`.

## Build and test

| Check | Result |
|---|---|
| `cargo build --release` | clean, zero warnings |
| `cargo test --workspace` | 153 passed, 0 failed |
| `cargo clippy --all-targets -- -D warnings` | exit 0 |

Per-crate test counts: rf-scan 36, rf-cli 33, rf-core 33, rf-chain 28,
rf-classify 11 (+1 eval), rf-mcp 8 (+3 stdio integration). Doc-tests: 0.

## Gadget parity vs ROPgadget 7.7

Post-dedup `(vaddr, bytes)` sets, `--depth 10`, full 24-fixture corpus.

**763,186 of 763,718 reference gadgets reproduced — 99.93%.**

11 of 24 fixtures are bit-exact (100.00% both directions):
UNIVERSAL-x86-x64-libSystem, elf-Linux-RISCV_32, elf-Linux-RISCV_64,
elf-Mips-Defcon-20-pwn100, elf-PPC64-bash, elf-PowerPC-bash, elf-SparcV8-bash,
macho-ppc-openssl, macho-x64-ls, pe-Windows-ARMv7-Thumb2LE-HelloWorld, raw-x86.raw.

Divergence is confined to x86/x64 (iced-x86 vs capstone text) and ARM/ARM64
(capstone core version). Lowest: elf-ARMv7-ls 99.57%, macho-x86-ls 99.61%.

Reproduce: `python tests/parity.py --release`.
Note that as of this baseline the harness prefers `target/release/rop-finder.exe`
when one exists, which makes it fail on non-Windows hosts — see `ENG-04`.

## Speed vs ROPgadget 7.7

`--depth 10`, both tools' stdout discarded, quiet machine.
rop-finder best-of-3, ROPgadget best-of-2.

| Fixture | ROPgadget | rop-finder | Speedup |
|---|---:|---:|---:|
| elf-Linux-x86 | 0.56 s | 0.09 s | **6.2x** |
| elf-x64-bash-v4.1.5.1 | 0.57 s | 0.10 s | **5.7x** |
| elf-ARM64-bash | 0.48 s | 0.23 s | **2.1x** |
| elf-Mips-Defcon-20-pwn100 | 2.54 s | 1.52 s | **1.7x** |
| elf-PowerPC-bash | 0.76 s | 0.60 s | **1.3x** |

PLAN.md's Phase 1 exit criteria were >=10x on x86/x64 and 4-8x elsewhere.
**Neither is met.** Phase 1 of the remediation plan retracts the claim; Phase 6
re-measures against this table and requires improvement on every architecture.

Small fixtures (raw-x86.raw, the RISC-V pair, pe-ARMv7) show 10-12x, but those
runs are dominated by CPython interpreter startup rather than scan work and are
not evidence for the headline claim.

## Not measured here

No criterion benchmark suite exists (`benches/` is empty), so these figures are
wall-clock from the parity harness and shell timing, not statistically sampled.
Phase 6 replaces this section with generated output.

No comparison against `ropper`, `rp++`, `radare2` or any other peer tool was
run. Earlier documentation carried a "~9-14x faster than ropper" figure; it has
no source and has been removed rather than restated.

## Documentation-retraction pass — 2026-09-03

Facts checked while rewriting README/MANUAL/PLAN/TAXONOMY for Phase 1
(`REMEDIATION.md`, "Retract every claim the code does not support"). Each
row is either a command actually run against this tree — Windows 11,
`cargo build -p rf-cli --release`, rustc 1.89.0 — or a source location that
was read. These are the receipts for the claims those documents now make.

| Claim now in the docs | How it was checked | Result |
|---|---|---|
| Fixture corpus is 24 binaries, not 25 | `ls tests/fixtures` | 24 binaries (plus `MANIFEST.sha256` and `PROVENANCE.md`, added in the same release). `PROVENANCE.md` records the dropped 25th, `core` (ET_CORE) |
| Default output is sorted alphabetically by gadget text, not by address | `rop-finder --binary tests/fixtures/elf-Linux-x86 --depth 4` | First gadget `0x080604ab : aaa ; …`, last `0x0807d14c : xor esi, esi ; ret 0xf01`. Alphabetical, addresses unordered. Source: `post_process` in `crates/rf-scan/src/engine.rs` (`keyed.sort_by(\|a, b\| a.0.cmp(&b.0))`, a port of `rgutils.alphaSortgadgets`) |
| `--cfg-aware` returns zero gadgets on every fixture | `for f in tests/fixtures/*; do rop-finder --binary "$f" --cfg-aware \| grep -c '^0x'; done` | 0 on all 24. Confirms `CRIT-01`; the MANUAL's `--cfg-aware` recommendation is withdrawn until v0.2 |
| `--version` prints the capstone version and the ROPgadget attribution | `rop-finder --version` | Prints `rop-finder 0.1.0`, `capstone 5.0 (bundled; …)`, `iced-x86 (decodes x86/x64)`, and the ROPgadget/BSD-3-Clause attribution. Exit 0 |
| `--help` and `--version` exit 0; `-v` is not bound | `rop-finder --help; rop-finder --version; rop-finder -v` | Exit 0, 0, 1. `-v` reports `unexpected argument` — recorded as a `partial` row in the MANUAL's flag-coverage table |
| `--chain windows-virtualprotect` prints an experimental warning | `rop-finder --binary tests/fixtures/pe-x86-cmd-v6.1.7600 --ropchain --chain windows-virtualprotect --api-addr 0x76771234` | Three `[Warning]` lines on stderr naming `CHWIN-01`, `CHWIN-02`, `CHWIN-03` and v0.5 |
| `--string`, `--opcode` are implemented | `rop-finder --binary tests/fixtures/elf-Linux-x86 --opcode c9c3` / `--string "bin"` | Both print ROPgadget-format hit lists |
| `--align` constrains but does not deepen on x86/x64 | Read `crates/rf-scan/src/engine.rs` (x86 path) vs `crates/rf-scan/src/cs.rs` (capstone path) vs `ropgadget/gadgets.py:73-89` | The oracle and `cs.rs` both step candidate starts by `ref - i*align`, reaching `(depth-1)*align` bytes back. The x86 path steps by `ref - i` and discards unaligned starts, reaching `depth-1` bytes. Counts on `elf-Linux-x86 --depth 10`: 42,480 gadgets at `--align 0`, 12,099 at `--align 4`. The oracle side could not be run here — python-capstone is not installed on this machine — so no cross-tool ratio is quoted |
| `--filter` is a literal suffix match, not an anchored regex | Read `pass_clean` in `crates/rf-scan/src/x86.rs` (`m.ends_with(s)`) vs `options.py`'s `re.match("({})$")` | Confirms `CLI-02`/`SCAN-01`; recorded as a known divergence |
| The classifier's evaluation is circular | Read `crates/rf-classify/tests/eval.rs` | `independent_labels()` re-implements the TAXONOMY.md rules over the same iced-x86 `InstructionInfoFactory` metadata `rf-classify` consumes; the three sampled fixtures (`elf-x64-bash-v4.1.5.1`, `pe-x64-cmd-v6.1.7601`, `elf-Linux-x64`) are all x86-64. The reported precision is self-agreement; it is now retracted from README and MANUAL |
| ROPgadget's write-what-where register class contains no ranges and not `;` | Read `ropgadget/ropchain/arch/ropmakerx64.py:29` and `ropmakerx86.py:29` | The class is `[(rax)\|(rbx)\|…\|(r15)]{3}` — the literal character set `{ ( ) \| r a x b c d s i 0 1 2 3 4 5 9 }`. `;` is absent, `8` is absent (so no `r8` form can match), and `{3}` cannot match the 2-character `r9`. `REGS64` in `crates/rf-chain/src/linux.rs` is that enumeration minus `r9` — the oracle's effective set, not a corrected one. README's description of this bug was wrong on both counts and has been rewritten |
| ROPgadget 7.7 has 30 flags | Read `ropgadget/args.py:75-104` | 30 `add_argument` calls; all 30 appear in the MANUAL's flag-coverage table against `pub struct Cli` in `crates/rf-cli/src/lib.rs` |
| The MCP server's post-fix shape | Read `crates/rf-mcp/src/confine.rs`, `lib.rs`, `main.rs` | `open_confined` handle API, `allow_dirs: Vec::new()` by default, `--allow-cwd` / `--i-accept-a-wide-allowlist` / `--max-depth` (64) / `--max-file-bytes` (256 MiB) / `--max-concurrent` (2) / `--verbose-path-errors`, single `path_denied` code, and a `get_server_config` tool — eight tools total, not seven. README and MANUAL now describe this shape |

No new timing or parity measurement was taken in this pass: the speed and
parity tables above are unchanged, and the retraction work only removed or
sourced claims rather than producing new figures.
