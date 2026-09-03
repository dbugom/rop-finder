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
