# rop-finder-chain

ROP chain construction for [rop-finder](https://docs.rs/rop-finder): a
target-independent Chain IR, the Linux `execve` builders (x86 `int 0x80`,
x64 `syscall`), the Windows `VirtualProtect` builders (x64 register ABI and
x86 stdcall), and the `--plan-chain` feasibility report.

```toml
[dependencies]
rop-finder-chain = "1"
```

```rust
use rf_chain::{build_linux_execve, ChainError, RopChain, WordKind};
```

**The package is `rop-finder-chain`; the library it provides is `rf_chain`.**

## What is in it

* `RopChain` — a word list where every `ChainWord` is tagged `gadget`,
  `immediate`, `data`, `code` or `padding`, plus the table of referenced
  gadgets with their disassembly. Two renderers: `to_python()` and
  `to_json()`.
* `RopChain::validate` / `validate_with` — the build-time invariants (every
  gadget word exists in the scan output; every non-gadget word is
  badbyte-free), plus per-target hooks such as the Win64 stack-alignment
  rule.
* `build_linux_execve` / `build_windows_virtualprotect`, and `plan_linux` /
  `plan_windows`, which report *why* a chain is not buildable — the missing
  primitive, by name — instead of returning nothing.
* `ChainError` — a structured failure naming the register and every strategy
  tried.

Chains are executed, not just shaped: `tests/emulate.py` runs the generated
Linux and Windows chains under Unicorn and asserts the syscall and its
arguments.

## Stability

Covered: item signatures and the `WordKind` and `ChainError` variant sets.

**Not covered: which gadgets a chain picks, and therefore its byte payload.**
A better strategy is a bug fix. What is held is that the chain *works*.
Comment text on words is diagnostic and changes freely.

## Building and testing

MSRV 1.88. The emulation and parity gates live in the repository, not in the
published `.crate` — see `docs/PUBLISHING.md`.

BSD-2-Clause. See `LICENSE`.
