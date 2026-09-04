# rop-finder-classify

What one gadget *does*: semantic class, labels, registers set versus
clobbered, stack delta, transfers, terminator, and the quality/usability
ranking used by [rop-finder](https://docs.rs/rop-finder)'s `--classify`,
`--rank` and constraint queries.

```toml
[dependencies]
rop-finder-classify = "1"
```

```rust
use rf_classify::{classify, Class, Classification, Terminator};
```

**The package is `rop-finder-classify`; the library it provides is
`rf_classify`.**

## What is in it

* `Class` — `reg-write`, `stack-pivot`, `mem-read`, `mem-write`,
  `arithmetic`, `syscall`, `dispatcher`, `other`, as a primary class plus a
  multi-label set.
* Register effects — `sets`, `clobbers`, `reads`, `transfers` and the
  closed-form `stack_delta`, from iced-x86 operand metadata on x86/x64 and
  from mnemonic heuristics elsewhere (`low_confidence: true`).
* `Terminator` / `TerminatorClass` — how the gadget leaves.
* The ranking heuristic behind `--rank`.

The decision rules (R1–R13) are written out in `TAXONOMY.md`, and the
measured accuracy against a hand-labeled 438-record corpus, with its caveats,
is in `docs/classifier-eval.md`. **This is a heuristic with published error
rates, not a proof.**

## Stability

Covered: item signatures, the `Class` / `Terminator` / `TerminatorClass`
variant sets, and the string vocabulary (`Class::name`, `Terminator::name`,
`TerminatorClass::ALL`) that both front ends share.

Not covered: which class a particular gadget earns (cite the rule number from
`TAXONOMY.md`, not the label you observed), and the absolute `quality_score`
/ `usability` numbers, which are re-tuned against measured precision. Compare
ranks, never scores.

## Building and testing

MSRV 1.88. Corpus-driven tests need the repository's fixtures and labeled
corpus, which the published `.crate` does not contain — see
`docs/PUBLISHING.md`.

BSD-2-Clause. See `LICENSE`.
