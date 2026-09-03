# Classifier evaluation — provenance, protocol, results

*Written for Phase 3 (v0.3.0), closing `CLS-01`, `CLS-06`, `CLS-10`, `CLS-11`.*
*Measured 2026-09-03 against the tree at that date. Every figure here is
asserted by `crates/rf-classify/tests/eval.rs`, so this document cannot go
stale without the test failing.*

---

## 1. What was wrong, demonstrated

### 1.1 The "independent" labeler was the classifier retyped (CLS-01)

`crates/rf-classify/tests/eval.rs:32-34` (at tag `v0.2.0`) said:

> a fresh implementation of the TAXONOMY.md decision rules ... No rf-classify
> code is reused

I extracted the mnemonic sets from both files programmatically and compared
them. Command and result:

```
$ git show v0.2.0:crates/rf-classify/src/x86.rs   > x86_v020.rs
$ git show v0.2.0:crates/rf-classify/tests/eval.rs > eval_v020.rs
$ python compare.py            # regex-extract every Mnemonic:: in each rule block
```

| rule set | implementation | "independent" labeler | identical? |
|---|---|---|---|
| R6 arithmetic (`is_arithmetic` vs the inline `matches!`) | 22 mnemonics | 22 mnemonics | **yes**, symmetric difference empty |
| R2 syscall (`is_syscall` vs `is_sys`) | 7 mnemonics | 7 mnemonics | **yes** |
| R1 implicit stack pointer (`has_implicit_sp` vs `implicit_sp`) | 12 mnemonics | 12 mnemonics | **yes** |
| R8 dispatcher arithmetic set (`dispatcher_heuristic` vs `dispatcher_check`) | the same 22 | the same 22 (+`Mnemonic::Jmp`, which is the mnemonic test, not a set member) | **yes** |

The R6 set both files agree on, verbatim: `Adc Add And Cmp Dec Imul Inc Lea Mul
Neg Not Or Rol Ror Sal Sar Sbb Shl Shr Sub Test Xor`.

`dispatcher_check` and `dispatcher_heuristic` share 49 identifiers; the only
identifiers unique to the implementation are `is_arithmetic`, `access_writes`
and the loop variable name — i.e. the labeler is the same function with the
arithmetic list inlined instead of called.

An agreement between those two programs measures transcription fidelity. It is
not evidence about accuracy, and the 1.0000 it produced should never have been
published as one.

### 1.2 The ground truth was an output of the test (CLS-11)

`classification_gate` ended with `std::fs::write(repo_root().join("tests/fixtures-labeled.jsonl"), …)`
and the same for `tests/fixtures-eval.json`. The "committed labeled set" was
therefore rewritten to match whatever the rules currently produced.

Both files were still tracked and **dirty** in the working tree at the start of
this workstream — `git status --porcelain` showed
`M tests/fixtures-eval.json` and `M tests/fixtures-labeled.jsonl`, a 740-line
diff, because Wave 3A had changed the classifier and someone had run the suite.
The regenerated `tests/fixtures-eval.json` recorded
`"macro_precision": 0.8299, "passed": false` — i.e. the gate was red, and the
only thing it was detecting was that the classifier had been corrected while
its copy in the labeler had not.

Both files are **deleted**. `eval.rs::the_old_generated_artifacts_are_gone`
fails if either comes back.

### 1.3 The field users see was never scored (CLS-06)

The old metrics loop compared label *sets* only. R10's primary-class selection —
the anchor skip, the syscall exemption, the last-side-effect rule and the 7-way
precedence order — was never measured, even though `class` is the field the CLI
prints and the MCP server returns. Worse, `eval.rs:364` wrote
`"primary": c.primary.name()` — the classifier's own prediction — into
`fixtures-labeled.jsonl` next to a ground-truth `labels` field, with nothing
marking which was which.

**The primary class is now the headline metric**, and `truth_primary` is a
hand-assigned field that no code produced.

### 1.4 Only x86-64 was ever sampled (CLS-10)

The plan was three x86-64 fixtures and the labeler hard-coded
`Decoder::with_ip(64, …)`. `classify_x86(g, 32)` and every non-x86 architecture
had **zero** measured accuracy. The corpus now covers eight architectures.

---

## 2. The corpus

**438 hand-labeled gadgets**, frozen in `tests/classify-corpus/` and verified by
SHA-256 before and after every scoring run. Sampling rule, per-stratum table,
record format and the full labeling protocol are in
[`tests/classify-corpus/README.md`](../tests/classify-corpus/README.md).

Summary: eleven **uniform** strata (every k-th gadget of a depth-10 scan, k the
smallest prime at or above `total/target`, offset 0) across eleven fixtures and
eight architectures, plus seven **enriched** strata drawn by purely textual
filters (last instruction is an indirect branch; text contains `syscall` /
`int 0x80` / `rsp`; at least six instructions) that reach the rare classes and
the rules most likely to be wrong.

Labels were assigned per gadget from **TAXONOMY.md R1–R13 as amended by
`docs/AUDIT-FINDINGS.md` CLS-02, CLS-03, CLS-12 and CLS-13** — the specification,
not the implementation — with a one-line written justification per record.
`rf_classify` was never run to produce a label.

Ground-truth distribution:

| arch | n | reg-write | stack-pivot | mem-read | mem-write | arithmetic | syscall | other |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| x86_64 | 196 | 34 | 23 | 11 | 62 | 32 | 5 | 29 |
| i386 | 74 | 10 | 5 | 3 | 16 | 17 | 10 | 13 |
| arm64 | 44 | 24 | 1 | 1 | 3 | 15 | 0 | 0 |
| arm | 25 | 10 | 0 | 1 | 0 | 2 | 11 | 1 |
| mips | 25 | 3 | 0 | 3 | 0 | 19 | 0 | 0 |
| ppc | 25 | 14 | 2 | 1 | 3 | 5 | 0 | 0 |
| sparc | 25 | 10 | 4 | 3 | 3 | 3 | 0 | 2 |
| riscv64 | 24 | 6 | 1 | 5 | 5 | 1 | 0 | 6 |

One record (`linuxx64.jsonl:0x424583`, `cmpxchg dword ptr [rax], esi`) is marked
`uncertain` and excluded from every metric; eleven more are marked
`labels_uncertain` and excluded from the label-set metric only. **437 records
are scored for the primary class.**

---

## 3. Results

Reproduce with:

```
cargo test -p rf-classify --test eval -- classification_gate --nocapture
```

### 3.1 Primary class, per architecture

`P` and `R` are precision and recall for that class *within that
architecture*. A dash means the class was never predicted and never true.

| arch | class | tp | fp | fn | P | R |
|---|---|--:|--:|--:|--:|--:|
| **x86_64** | reg-write | 34 | 1 | 0 | 0.9714 | 1.0000 |
| | stack-pivot | 23 | 0 | 0 | 1.0000 | 1.0000 |
| | mem-read | 11 | 0 | 0 | 1.0000 | 1.0000 |
| | mem-write | 60 | 0 | 1 | 1.0000 | 0.9836 |
| | arithmetic | 32 | 0 | 0 | 1.0000 | 1.0000 |
| | syscall | 5 | 0 | 0 | 1.0000 | 1.0000 |
| | other | 29 | 0 | 0 | 1.0000 | 1.0000 |
| | **TOTAL n=195** | | | | **macro-P 0.9959** | **macro-R 0.9977** |
| **i386** | reg-write | 10 | 0 | 0 | 1.0000 | 1.0000 |
| | stack-pivot | 5 | 0 | 0 | 1.0000 | 1.0000 |
| | mem-read | 3 | 0 | 0 | 1.0000 | 1.0000 |
| | mem-write | 16 | 0 | 0 | 1.0000 | 1.0000 |
| | arithmetic | 17 | 0 | 0 | 1.0000 | 1.0000 |
| | syscall | 10 | 0 | 0 | 1.0000 | 1.0000 |
| | other | 13 | 0 | 0 | 1.0000 | 1.0000 |
| | **TOTAL n=74** | | | | **macro-P 1.0000** | **macro-R 1.0000** |
| **arm64** | reg-write | 24 | 0 | 0 | 1.0000 | 1.0000 |
| | stack-pivot | 1 | 0 | 0 | 1.0000 | 1.0000 |
| | mem-read | 1 | 0 | 0 | 1.0000 | 1.0000 |
| | mem-write | 3 | 0 | 0 | 1.0000 | 1.0000 |
| | arithmetic | 15 | 0 | 0 | 1.0000 | 1.0000 |
| | **TOTAL n=44** | | | | **macro-P 1.0000** | **macro-R 1.0000** |
| **arm** | reg-write | 10 | 0 | 0 | 1.0000 | 1.0000 |
| | mem-read | 1 | 0 | 0 | 1.0000 | 1.0000 |
| | arithmetic | 2 | 0 | 0 | 1.0000 | 1.0000 |
| | syscall | 11 | 0 | 0 | 1.0000 | 1.0000 |
| | other | 1 | 0 | 0 | 1.0000 | 1.0000 |
| | **TOTAL n=25** | | | | **macro-P 1.0000** | **macro-R 1.0000** |
| **riscv64** | reg-write | 6 | 1 | 0 | 0.8571 | 1.0000 |
| | stack-pivot | 1 | 0 | 0 | 1.0000 | 1.0000 |
| | mem-read | 5 | 1 | 0 | 0.8333 | 1.0000 |
| | mem-write | 1 | 0 | 4 | 1.0000 | 0.2000 |
| | arithmetic | 1 | 0 | 0 | 1.0000 | 1.0000 |
| | other | 6 | 2 | 0 | 0.7500 | 1.0000 |
| | **TOTAL n=24** | | | | **macro-P 0.9067** | **macro-R 0.8667** |
| **mips** | reg-write | 3 | 4 | 0 | 0.4286 | 1.0000 |
| | mem-read | 3 | 0 | 0 | 1.0000 | 1.0000 |
| | arithmetic | 15 | 0 | 4 | 1.0000 | 0.7895 |
| | **TOTAL n=25** | | | | **macro-P 0.8095** | **macro-R 0.9298** |
| **sparc** | reg-write | 10 | 2 | 0 | 0.8333 | 1.0000 |
| | stack-pivot | 0 | 0 | 4 | – | 0.0000 |
| | mem-read | 3 | 1 | 0 | 0.7500 | 1.0000 |
| | mem-write | 3 | 1 | 0 | 0.7500 | 1.0000 |
| | arithmetic | 2 | 0 | 1 | 1.0000 | 0.6667 |
| | other | 2 | 1 | 0 | 0.6667 | 1.0000 |
| | **TOTAL n=25** | | | | **macro-P 0.8000** | **macro-R 0.7778** |
| **ppc** | reg-write | 14 | 9 | 0 | 0.6087 | 1.0000 |
| | stack-pivot | 1 | 0 | 1 | 1.0000 | 0.5000 |
| | mem-read | 0 | 0 | 1 | – | 0.0000 |
| | mem-write | 0 | 0 | 3 | – | 0.0000 |
| | arithmetic | 1 | 0 | 4 | 1.0000 | 0.2000 |
| | **TOTAL n=25** | | | | **macro-P 0.8696** | **macro-R 0.3400** |

**Whole corpus, n=437: accuracy 0.9474, macro-P 0.9615, macro-R 0.9488.**

Accuracy with 95 % Clopper-Pearson lower bounds — the honest form of every
number above, because most of these strata are small:

| arch | correct / n | accuracy | 95 % lower bound |
|---|---|--:|--:|
| x86_64 | 194 / 195 | 0.9949 | **0.9718** |
| i386 | 74 / 74 | 1.0000 | **0.9514** |
| arm64 | 44 / 44 | 1.0000 | **0.9196** |
| arm | 25 / 25 | 1.0000 | **0.8628** |
| riscv64 | 20 / 24 | 0.8333 | **0.6262** |
| mips | 21 / 25 | 0.8400 | **0.6392** |
| sparc | 20 / 25 | 0.8000 | **0.5930** |
| ppc | 16 / 25 | 0.6400 | **0.4252** |
| whole corpus | 414 / 437 | 0.9474 | **0.9221** |

### 3.2 Label set (multi-label, whole corpus)

Eleven entries with a contested label are excluded.

| class | tp | fp | fn | precision | recall |
|---|--:|--:|--:|--:|--:|
| reg-write | 258 | 13 | 0 | 0.9520 | 1.0000 |
| stack-pivot | 46 | 0 | 4 | 1.0000 | 0.9200 |
| mem-read | 179 | 1 | 1 | 0.9944 | 0.9944 |
| mem-write | 163 | 0 | 5 | 1.0000 | 0.9702 |
| arithmetic | 244 | 0 | 17 | 1.0000 | 0.9349 |
| syscall | 25 | 0 | 0 | 1.0000 | 1.0000 |
| dispatcher | 2 | 0 | 5 | 1.0000 | 0.2857 |

### 3.3 Phase 3 exit criteria

| criterion | measured | verdict |
|---|---|---|
| x86-64 class precision >= 0.90 | macro-P **0.9959** (n=195) | **met** |
| the reported x86-64 figure is no longer 1.0000 | **0.9959** | **met** |
| dispatcher precision >= 0.80 | **1.0000** | **met on the letter, vacuous in substance — see below** |

**The dispatcher gate is not a real result.** Precision 1.0000 rests on
**one** predicted positive across the whole 438-gadget corpus (tp=1, fp=0). Its
95 % Clopper-Pearson lower bound is **0.025**. The classifier is not
over-labeling dispatchers any more — which was CLS-03's complaint, and that
much is genuinely fixed — but it now labels almost nothing: recall is
**0.2857** (2 of 7 hand-identified dispatchers). `eval.rs` asserts the number
*and* the predicted-positive count, so if a future change makes the claim
stronger or weaker the test says so.

---

## 4. Every disagreement, and who is wrong

`cargo test -p rf-classify --test corpus_diff -- --ignored --nocapture` prints
all of them with the hand justification beside the prediction. 23 primary-class
and 42 label-set disagreements, all reviewed. **No corpus label was changed to
make a number come out.** Grouped by cause:

### 4.1 Real classifier defects found by this corpus

1. **PowerPC's link register is in the GPR set** (`generic.rs:128`,
   `Family::Ppc => numbered('r', 32) || matches!(n, "lr" | "ctr")`), and the
   terminating `bl` is not exempted, so **the anchor itself earns
   `reg-write`**. `stw r0, 0x24(r1) ; stw r29, 0x14(r1) ; bl 0x100c00c0`
   reports `regs_written: ["lr"]` and class `reg-write` instead of `mem-write`.
   This alone accounts for **7 of the 9 PowerPC primary-class errors** and for
   PowerPC's reg-write precision of 0.6087. `mtlr r0` has the same effect.
2. **MIPS reports a register the instruction only reads.** For
   `addi $zero, $at, 0x2020` — destination `$zero`, hardwired to zero —
   `classify` returns `regs_written: ["at"]` and labels the gadget
   `reg-write`. `$at` is a source operand. (`Family::Mips::is_zero_reg`
   handles `"zero"`, so the fault is upstream of that filter, in how the
   destination operand is picked.) Eight MIPS entries are affected; four change
   the primary class.
3. **MIPS conditional branches are treated as register writes.** In
   `… ; j 0x8808080 ; bgtzl $t9, 0x8dc684`, the delay-slot conditional branch
   earns `reg-write` and becomes the primary class. Capstone does not fill
   instruction groups for MIPS, so `d.groups.control()` is false and the
   branch falls into the "derive the destination from the operand list" path.
   This is `CLS-04`'s "fires on conditional branches" surviving into the
   metadata path.
4. **The R8 dispatcher rule never fires on AArch64 jump tables.**
   `add x1, x3, w1, sxth #2 ; br x1` is the canonical dispatcher shape; the
   rule requires the earlier arithmetic instruction to both read and write the
   branch-target register, but the read is spelled `w1` and the write `x1`,
   and the W/X aliasing is not normalised. Four ARM64 dispatchers missed.
5. **The R8 dispatcher rule never fires on SPARC at all.** `dispatcher()`
   gates on `d.groups.jump || d.groups.call`; capstone reports **no** groups
   for SPARC (the code says so at `generic.rs:terminator_of`), so
   `sll %g1, 2, %g1 ; ld [%l6+%g1], %g1 ; jmp %g1` is not labeled.
6. **RISC-V compressed stores are not stores.** `c.sd s1, 0x28(a2) ; c.j 0x6a`
   classifies as **`other` with an empty label set** — the gadget writes eight
   bytes of attacker-controlled memory. `c.sdsp` and `c.fsdsp` likewise. Four
   of RISC-V's five `mem-write` gadgets are missed; this is the mnemonic-list
   half of `CLS-04` still open for the compressed ISA.
7. **RISC-V compressed arithmetic is not arithmetic.** `c.addi`, `c.add`,
   `c.srai`, `c.addi16sp` are absent from the R6 set, so
   `c.addi t2, 0x1d ; c.add a1, a5 ; c.srai a1, 1 ; …` earns `reg-write` only.
8. **PowerPC `stbx` is not a store.**
   `… ; li r9, 0x6d ; stbx r9, r3, r8 ; b …` gets no `mem-write` label at all.
9. **ARM condition-code suffixes defeat the R6 mnemonic set.** `andhs`,
   `eorhs`, `rsbvs`, `rsbvc`, `rsbshs`, `subpl`, `muleq`, `andeq`, `movtmi`
   earn no `arithmetic`. Nine ARM entries; none changes a primary class here
   only because those gadgets end in `svc`, but on ARM code that ends in
   `bx lr` it would.
10. **SPARC `restore` is not recognised as a stack-pointer change.**
    `ba 0xafce0 ; restore` classifies as `other`; `restore` is SPARC's
    `leave`, which R5 names explicitly. Four SPARC stack-pivots missed — SPARC's
    `stack-pivot` recall is **0.0000**.
11. **SPARC `rett %i7+8` is read as a memory operand.**
    `or %i1, %g3, %i1 ; rett %i7+8 ; …` gets a spurious `mem-read` that becomes
    the primary class.
12. **x86-64: `loop`/`loopne` earn `reg-write`.** R7 labels only *non-control*
    instructions; `loopne` is a conditional branch. In
    `clc ; hlt ; add byte ptr [rax], al ; loopne … ; cld ; call qword ptr [rax]`
    this flips the class from `mem-write` to `reg-write`. **This is the single
    x86-64 primary-class error in the corpus**, and it is why the x86-64 figure
    is 0.9959 rather than 1.0000.

### 4.2 Disagreements that are taxonomy-mapping choices, not defects

Nineteen records carry resolution `D-ADR` (address-formation instructions
`adrp`/`adr`/`auipc` earn `arithmetic`, by analogy with `lea`, which R6 lists
explicitly). On sixteen of them an ordinary `add`/`addi` supplies the
`arithmetic` label anyway, so the mapping makes no difference. **Three**
disagreements — `arm64:0x4980d8`, `arm64:0x4919a8`, `riscv64:0x10590` — turn
*solely* on it. None changes a primary class. A reader who rejects `D-ADR`
should read the label-set `arithmetic` recall as 244/258 = **0.9457** instead
of 244/261 = 0.9349.

The `D-SUBREG` cases (does writing `al` "advance" `rax` for R8?) are marked
`labels_uncertain` and excluded rather than being scored either way.

---

## 5. What this does **not** measure

* **Blindness.** The labeler is a language model that had already read
  `crates/rf-classify/src/x86.rs` — extracting its mnemonic sets is the CLS-01
  evidence in §1.1. This is not a blind study. What is checkable is narrower:
  no label was produced by running `rf_classify`, every label carries a written
  reason, the files are hash-frozen, and the x86 labels were cross-decoded with
  a different decoder (§ `tests/classify-corpus/README.md`). Read the x86-64
  number with that caveat attached.
* **Sample size.** 24–44 gadgets per non-x86 architecture. The lower bounds in
  §3.1 are wide and are the number to quote, not the point estimate. `ppc`'s
  true accuracy could be anywhere from 0.43 upward.
* **Population.** Uniform strata come from **one fixture per architecture**
  at depth 10. Nothing here says how the classifier behaves on other
  compilers, other libc versions, or other depths. Nine of the twenty-five ARM
  entries and eleven of the twenty-five MIPS entries are misdecoded string data
  rather than compiled code, because that is what a real scan of those binaries
  is full of — which is representative of the tool's output, but not of
  hand-written gadget chains.
* **`Arch::ArmThumb`, `Mips64`, `Ppc64`, `Sparc64`, `SparcV9`, `RiscV32`.**
  Six of the fourteen `Arch` variants have **no corpus entry at all**. Of the
  ten "supported architectures", eight are measured.
* **Mach-O and raw containers.** Every fixture sampled is ELF or PE.
* **The text fallback path (R13).** `low_confidence` was false for all 437
  scored records — every one resolved to a capstone detail mode. The
  disassembly-text heuristic in `crates/rf-classify/src/text.rs` therefore has
  **zero** measured accuracy. `eval.rs` asserts the count stays at zero, so if
  a detail mode stops resolving the test reports it rather than silently
  measuring a different code path.
* **Ranking.** `quality_score`, `usability` and `rank_key` are not evaluated
  here at all. There is no ground truth for "is this gadget more useful than
  that one" in this corpus, and inventing one by hand would be a preference
  survey, not a measurement.
* **`regs_written` / `regs_read` contents.** Only the classes are scored. The
  register lists are quoted in §4 as evidence for specific defects but are not
  measured as a field. (`CLS-05`'s garbage tokens do not appear anywhere in the
  corpus's predictions, but that is an observation, not a metric.)
* **Whether the taxonomy is the right taxonomy.** This measures conformance to
  TAXONOMY.md as amended. It says nothing about whether those seven classes are
  the ones an exploit developer wants.

---

## 6. Reproducing

```
# the gate and the tables above
cargo test -p rf-classify --test eval -- classification_gate --nocapture

# every individual disagreement, with the hand justification
cargo test -p rf-classify --test corpus_diff -- --ignored --nocapture

# re-draw a sampling stratum (writes nothing; prints JSONL to stdout)
RF_SAMPLE_FIXTURE=elf-x64-bash-v4.1.5.1 RF_SAMPLE_STRIDE=757 \
  cargo test -p rf-classify --test sample_corpus -- --ignored --nocapture
```

`cargo test -p rf-classify` writes nothing into the source tree; the corpus is
opened read-only and its SHA-256s are checked before and after the run.
