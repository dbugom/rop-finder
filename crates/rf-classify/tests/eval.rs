//! Classifier evaluation against a **hand-labeled, frozen** corpus
//! (CLS-01, CLS-06, CLS-10, CLS-11).
//!
//! What replaced what, and why:
//!
//! * The previous harness contained a "fresh implementation of the TAXONOMY.md
//!   decision rules ... No rf-classify code is reused". It was the same rule
//!   table retyped: the R6 arithmetic set (22 mnemonics), the R2 syscall set
//!   (7) and the R1 implicit-stack-pointer set (12) were byte-identical
//!   between `src/x86.rs` and the labeler, and `dispatcher_check` was
//!   `dispatcher_heuristic` with the arithmetic list inlined. It measured
//!   self-agreement. It is **deleted**, and nothing here decodes an
//!   instruction (CLS-01).
//! * That harness also WROTE `tests/fixtures-labeled.jsonl` and
//!   `tests/fixtures-eval.json` on every run, so the "committed labeled set"
//!   was an output regenerated to match the current rules. This file opens
//!   every path read-only, checks each corpus file's SHA-256 against
//!   `tests/classify-corpus/MANIFEST.sha256` **before and after** scoring, and
//!   asserts the corpus directory's bytes are unchanged when the test
//!   finishes (CLS-11).
//! * The old metrics loop compared label SETS only, and wrote the classifier's
//!   own `primary` prediction into the "labeled sample" beside the ground
//!   truth. Here `truth_primary` is a hand-assigned field that no code
//!   produced, and the **primary class is the headline metric** (CLS-06).
//! * The old sampling plan was three x86-64 fixtures. The corpus covers
//!   x86-64, x86-32 (i386) and six of the seven previously unmeasured
//!   architectures — ARM, ARM64, MIPS, PowerPC, SPARC and RISC-V 64
//!   (CLS-10).
//!
//! The labeling protocol, the per-entry justifications and the list of things
//! this does NOT measure are in `docs/classifier-eval.md` and
//! `tests/classify-corpus/README.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use rf_core::Arch;
use rf_scan::{Gadget, TableKind};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Recorded results. These are the figures quoted in docs/classifier-eval.md
// and in the workstream report; the test fails if the code moves away from
// them in either direction, so the document cannot silently go stale.
// ---------------------------------------------------------------------------

/// Corpus size, and the number of entries excluded as `uncertain`.
const CORPUS_RECORDS: usize = 438;
const CORPUS_UNCERTAIN: usize = 1;

/// Phase 3 exit criterion (docs/REMEDIATION.md): x86-64 primary-class
/// macro-averaged precision >= 0.90, and it must no longer be 1.0000.
const X64_GATE: f64 = 0.90;

/// Recorded x86-64 primary-class macro precision, to 4 dp. A change in either
/// direction is a deliberate act and must move this constant and the document.
const X64_MACRO_P: f64 = 0.9959;
const X64_MACRO_R: f64 = 0.9977;

/// Recorded whole-corpus primary-class accuracy, to 4 dp.
const OVERALL_ACC: f64 = 0.9474;

/// Phase 3 exit criterion: dispatcher precision >= 0.80, measured on the
/// indirect-branch stratum. Recorded value, and the size it rests on — the
/// number is 1.0000 on ONE predicted positive, which is not a strong result
/// and is reported as such in docs/classifier-eval.md.
const DISPATCHER_GATE: f64 = 0.80;
const DISPATCHER_P: f64 = 1.0;
const DISPATCHER_PREDICTED_POSITIVES: usize = 1;

/// Recorded per-architecture primary-class accuracy, to 4 dp. This is the
/// table published in docs/classifier-eval.md; the test fails if any cell
/// moves, so the document and the code cannot disagree.
const PER_ARCH_ACCURACY: &[(&str, usize, f64)] = &[
    ("arm", 25, 1.0),
    ("arm64", 44, 1.0),
    ("i386", 74, 1.0),
    ("mips", 25, 0.84),
    ("ppc", 25, 0.64),
    ("riscv64", 24, 0.8333),
    ("sparc", 25, 0.80),
    ("x86_64", 195, 0.9949),
];

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4). Hand-rolled so this test needs no new dependency in
// rf-classify's Cargo.toml; checked against `certutil -hashfile` /
// `sha256sum` when the manifest was written.
// ---------------------------------------------------------------------------

mod sha256 {
    use std::fmt::Write as _;

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    pub fn hex(data: &[u8]) -> String {
        let mut h: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut msg = data.to_vec();
        let bitlen = (data.len() as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bitlen.to_be_bytes());

        let mut w = [0u32; 64];
        for chunk in msg.chunks_exact(64) {
            for (i, word) in w.iter_mut().enumerate().take(16) {
                let b = &chunk[i * 4..i * 4 + 4];
                *word = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let (mut a, mut b, mut c, mut d) = (h[0], h[1], h[2], h[3]);
            let (mut e, mut f, mut g, mut hh) = (h[4], h[5], h[6], h[7]);
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
                *slot = slot.wrapping_add(v);
            }
        }
        let mut s = String::with_capacity(64);
        for v in h {
            let _ = write!(s, "{v:08x}");
        }
        s
    }

    #[test]
    fn sha256_known_answers() {
        assert_eq!(
            hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 64-byte input: exercises the extra padding block.
        assert_eq!(
            hex(&[b'a'; 64]),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
    }
}

// ---------------------------------------------------------------------------
// The frozen corpus.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Record {
    fixture: String,
    arch: String,
    vaddr: String,
    bytes: String,
    text: String,
    delay_slot: bool,
    truth_primary: String,
    truth_labels: Vec<String>,
    /// Excluded from BOTH metrics: the ground truth itself is contested.
    uncertain: bool,
    /// Excluded from the label-set metric only: one label is contested, the
    /// primary class is not.
    labels_uncertain: bool,
    #[allow(dead_code)]
    why: String,
    stratum: String,
}

impl Record {
    fn vaddr_u64(&self) -> u64 {
        u64::from_str_radix(self.vaddr.trim_start_matches("0x"), 16)
            .unwrap_or_else(|e| panic!("{}: bad vaddr {}: {e}", self.fixture, self.vaddr))
    }

    fn bytes_vec(&self) -> Vec<u8> {
        let b = self.bytes.as_bytes();
        assert!(b.len() % 2 == 0, "{}: odd byte string", self.vaddr);
        (0..b.len() / 2)
            .map(|i| u8::from_str_radix(&self.bytes[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// Rebuild the scanner record the classifier is asked to classify. The
    /// scanner joins instruction text with `" ; "` (`Gadget::text`), so the
    /// split is exact. `table` is not read by `rf_classify` (it selects the
    /// anchor family, not the semantics) and is set to the ROP table.
    fn gadget(&self) -> Gadget {
        Gadget {
            vaddr: self.vaddr_u64(),
            bytes: self.bytes_vec(),
            insns: self.text.split(" ; ").map(str::to_string).collect(),
            delay_slot: self.delay_slot,
            prev: None,
            table: TableKind::Rop,
        }
    }

    fn arch(&self) -> Arch {
        Arch::from_slice_name(&self.arch).unwrap_or_else(|| panic!("unknown arch {:?}", self.arch))
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn corpus_dir() -> PathBuf {
    repo_root().join("tests/classify-corpus")
}

/// `(file name, recorded sha256)` in manifest order.
fn manifest() -> Vec<(String, String)> {
    let path = corpus_dir().join("MANIFEST.sha256");
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let (sha, name) = l
                .split_once("  ")
                .unwrap_or_else(|| panic!("bad manifest line {l:?}"));
            (name.trim().to_string(), sha.trim().to_string())
        })
        .collect()
}

/// Hash every corpus file named in the manifest. Returns `(name, sha)` pairs.
fn hash_corpus() -> Vec<(String, String)> {
    manifest()
        .into_iter()
        .map(|(name, _)| {
            let p = corpus_dir().join(&name);
            let sha = sha256::hex(
                &std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display())),
            );
            (name, sha)
        })
        .collect()
}

fn verify_manifest(when: &str) {
    let expected = manifest();
    let actual = hash_corpus();
    assert_eq!(
        expected.len(),
        actual.len(),
        "{when}: manifest lists {} files, hashed {}",
        expected.len(),
        actual.len()
    );
    for ((name, want), (_, got)) in expected.iter().zip(actual.iter()) {
        assert_eq!(
            want, got,
            "{when}: tests/classify-corpus/{name} does not match MANIFEST.sha256.\n\
             The corpus is HAND-LABELED ground truth and is never regenerated by a test.\n\
             If you changed it deliberately, update MANIFEST.sha256 in the same commit and \
             say why in docs/classifier-eval.md."
        );
    }
    // Nothing in the directory may be an unlisted .jsonl: a stray file would
    // silently be excluded from the measurement.
    let listed: BTreeSet<String> = expected.iter().map(|(n, _)| n.clone()).collect();
    for entry in std::fs::read_dir(corpus_dir()).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".jsonl") {
            assert!(
                listed.contains(&name),
                "{when}: tests/classify-corpus/{name} is not in MANIFEST.sha256"
            );
        }
    }
}

fn load_corpus() -> Vec<Record> {
    let mut all = Vec::new();
    for (name, _) in manifest() {
        let p = corpus_dir().join(&name);
        let text = std::fs::read_to_string(&p).unwrap();
        for (i, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let r: Record =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("{name}:{}: {e}", i + 1));
            all.push(r);
        }
    }
    all
}

// ---------------------------------------------------------------------------
// Metrics.
// ---------------------------------------------------------------------------

const CLASSES: [&str; 8] = [
    "reg-write",
    "stack-pivot",
    "mem-read",
    "mem-write",
    "arithmetic",
    "syscall",
    "dispatcher",
    "other",
];

#[derive(Default, Clone, Copy)]
struct Cell {
    tp: usize,
    fp: usize,
    fn_: usize,
}

impl Cell {
    fn precision(&self) -> Option<f64> {
        (self.tp + self.fp > 0).then(|| self.tp as f64 / (self.tp + self.fp) as f64)
    }
    fn recall(&self) -> Option<f64> {
        (self.tp + self.fn_ > 0).then(|| self.tp as f64 / (self.tp + self.fn_) as f64)
    }
}

/// Confusion for one architecture: per-class cells plus the raw confusion
/// pairs, so the report can show what the mistakes actually were.
#[derive(Default)]
struct Conf {
    cells: BTreeMap<&'static str, Cell>,
    pairs: BTreeMap<(String, String), usize>,
    n: usize,
    correct: usize,
}

impl Conf {
    fn add(&mut self, truth: &str, pred: &str) {
        self.n += 1;
        if truth == pred {
            self.correct += 1;
        } else {
            *self
                .pairs
                .entry((truth.to_string(), pred.to_string()))
                .or_default() += 1;
        }
        for c in CLASSES {
            let cell = self.cells.entry(c).or_default();
            match (truth == c, pred == c) {
                (true, true) => cell.tp += 1,
                (false, true) => cell.fp += 1,
                (true, false) => cell.fn_ += 1,
                (false, false) => {}
            }
        }
    }

    /// Macro average over the classes that are PRESENT in this architecture's
    /// ground truth or predictions — averaging in a 1.0 for a class that
    /// never occurs is how the old harness inflated its number.
    fn macro_precision(&self) -> f64 {
        let vals: Vec<f64> = CLASSES
            .iter()
            .filter_map(|c| self.cells.get(c).and_then(|x| x.precision()))
            .collect();
        vals.iter().sum::<f64>() / vals.len().max(1) as f64
    }

    fn macro_recall(&self) -> f64 {
        let vals: Vec<f64> = CLASSES
            .iter()
            .filter_map(|c| self.cells.get(c).and_then(|x| x.recall()))
            .collect();
        vals.iter().sum::<f64>() / vals.len().max(1) as f64
    }
}

fn round4(x: f64) -> f64 {
    (x * 10000.0).round() / 10000.0
}

fn fmt_opt(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{x:8.4}"),
        None => "       -".to_string(),
    }
}

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

#[test]
fn classification_gate() {
    verify_manifest("before");
    let corpus = load_corpus();
    assert_eq!(
        corpus.len(),
        CORPUS_RECORDS,
        "corpus size changed; update CORPUS_RECORDS and docs/classifier-eval.md"
    );
    assert_eq!(
        corpus.iter().filter(|r| r.uncertain).count(),
        CORPUS_UNCERTAIN
    );

    let mut per_arch: BTreeMap<String, Conf> = BTreeMap::new();
    let mut overall = Conf::default();
    // Label-set (multi-label) confusion, whole corpus.
    let mut labelset: BTreeMap<&'static str, Cell> = BTreeMap::new();
    // Dispatcher precision is reported separately: it is measured over the
    // indirect-branch stratum, which contains every gadget shape that can
    // possibly earn the label, so precision estimated there is unbiased even
    // though the stratum is enriched.
    let mut dispatcher = Cell::default();
    let mut low_confidence = 0usize;
    let mut report = String::new();

    for r in &corpus {
        if r.uncertain {
            continue;
        }
        let g = r.gadget();
        let c = rf_classify::classify(&g, r.arch());
        if c.low_confidence {
            low_confidence += 1;
        }
        let pred = c.primary.name();
        per_arch
            .entry(r.arch.clone())
            .or_default()
            .add(&r.truth_primary, pred);
        overall.add(&r.truth_primary, pred);

        if !r.labels_uncertain {
            let truth: BTreeSet<&str> = r.truth_labels.iter().map(String::as_str).collect();
            let predicted: BTreeSet<&str> = c.labels.iter().map(|l| l.name()).collect();
            for cl in CLASSES {
                if cl == "other" {
                    continue;
                }
                let cell = labelset.entry(cl).or_default();
                match (truth.contains(cl), predicted.contains(cl)) {
                    (true, true) => cell.tp += 1,
                    (false, true) => cell.fp += 1,
                    (true, false) => cell.fn_ += 1,
                    (false, false) => {}
                }
            }
            if r.stratum == "indirect-branch" {
                match (
                    truth.contains("dispatcher"),
                    predicted.contains("dispatcher"),
                ) {
                    (true, true) => dispatcher.tp += 1,
                    (false, true) => dispatcher.fp += 1,
                    (true, false) => dispatcher.fn_ += 1,
                    (false, false) => {}
                }
            }
        }
    }

    // ---- primary class, per architecture ------------------------------
    writeln!(
        report,
        "\nPRIMARY CLASS (the `class` field users see) - hand-labeled corpus, \
         {} records ({} excluded as uncertain)",
        corpus.len(),
        CORPUS_UNCERTAIN
    )
    .unwrap();
    writeln!(
        report,
        "{:<9} {:<12} {:>4} {:>4} {:>4} {:>9} {:>9}",
        "arch", "class", "tp", "fp", "fn", "precision", "recall"
    )
    .unwrap();
    for (arch, conf) in &per_arch {
        for c in CLASSES {
            let Some(cell) = conf.cells.get(c) else {
                continue;
            };
            if cell.tp + cell.fp + cell.fn_ == 0 {
                continue;
            }
            writeln!(
                report,
                "{:<9} {:<12} {:>4} {:>4} {:>4} {} {}",
                arch,
                c,
                cell.tp,
                cell.fp,
                cell.fn_,
                fmt_opt(cell.precision()),
                fmt_opt(cell.recall())
            )
            .unwrap();
        }
        writeln!(
            report,
            "{:<9} {:<12} n={:<3}  accuracy={:.4}  macro-P={:.4}  macro-R={:.4}",
            arch,
            "TOTAL",
            conf.n,
            conf.correct as f64 / conf.n as f64,
            conf.macro_precision(),
            conf.macro_recall()
        )
        .unwrap();
        if !conf.pairs.is_empty() {
            let mut worst: Vec<_> = conf.pairs.iter().collect();
            worst.sort_by(|a, b| b.1.cmp(a.1));
            let shown: Vec<String> = worst
                .iter()
                .take(4)
                .map(|((t, p), n)| format!("{t}->{p} x{n}"))
                .collect();
            writeln!(
                report,
                "{:<9} {:<12} {}",
                arch,
                "confusions",
                shown.join(", ")
            )
            .unwrap();
        }
        writeln!(report).unwrap();
    }
    writeln!(
        report,
        "ALL       TOTAL        n={:<3}  accuracy={:.4}  macro-P={:.4}  macro-R={:.4}",
        overall.n,
        overall.correct as f64 / overall.n as f64,
        overall.macro_precision(),
        overall.macro_recall()
    )
    .unwrap();

    // ---- label set ----------------------------------------------------
    writeln!(
        report,
        "\nLABEL SET (multi-label, whole corpus, {} entries with a contested label excluded)",
        corpus.iter().filter(|r| r.labels_uncertain).count()
    )
    .unwrap();
    for c in CLASSES {
        if c == "other" {
            continue;
        }
        let cell = labelset.get(c).copied().unwrap_or_default();
        writeln!(
            report,
            "{:<12} {:>4} {:>4} {:>4} {} {}",
            c,
            cell.tp,
            cell.fp,
            cell.fn_,
            fmt_opt(cell.precision()),
            fmt_opt(cell.recall())
        )
        .unwrap();
    }
    writeln!(
        report,
        "\nDISPATCHER (indirect-branch stratum only): tp={} fp={} fn={} precision={} recall={}",
        dispatcher.tp,
        dispatcher.fp,
        dispatcher.fn_,
        fmt_opt(dispatcher.precision()),
        fmt_opt(dispatcher.recall())
    )
    .unwrap();
    writeln!(
        report,
        "\nDECODE PATH: {low_confidence} of {} scored records fell back to the disassembly-TEXT \
         heuristic (`low_confidence`)",
        overall.n
    )
    .unwrap();
    eprintln!("{report}");

    // ---- gates --------------------------------------------------------
    let x64 = per_arch
        .get("x86_64")
        .expect("corpus must contain x86_64 records");
    let x64_p = x64.macro_precision();
    let x64_r = x64.macro_recall();
    let acc = overall.correct as f64 / overall.n as f64;

    assert!(
        x64_p >= X64_GATE,
        "GATE FAILED: x86-64 primary-class macro precision {x64_p:.4} < {X64_GATE:.2}\n{report}"
    );
    assert!(
        x64_p < 1.0,
        "x86-64 macro precision is exactly 1.0000 again - a corpus that cannot \
         disagree with the classifier is the CLS-01 defect returning"
    );
    assert_eq!(
        round4(x64_p),
        X64_MACRO_P,
        "x86-64 macro precision moved; update X64_MACRO_P and docs/classifier-eval.md\n{report}"
    );
    assert_eq!(
        round4(x64_r),
        X64_MACRO_R,
        "x86-64 macro recall moved\n{report}"
    );
    assert_eq!(
        round4(acc),
        OVERALL_ACC,
        "whole-corpus accuracy moved; update OVERALL_ACC and docs/classifier-eval.md\n{report}"
    );

    for (arch, n, want) in PER_ARCH_ACCURACY {
        let conf = per_arch
            .get(*arch)
            .unwrap_or_else(|| panic!("corpus lost every {arch} record\n{report}"));
        assert_eq!(conf.n, *n, "{arch}: scored record count moved\n{report}");
        assert_eq!(
            round4(conf.correct as f64 / conf.n as f64),
            *want,
            "{arch}: primary-class accuracy moved; update PER_ARCH_ACCURACY and \
             docs/classifier-eval.md\n{report}"
        );
    }

    // Dispatcher (R8) precision, the second Phase 3 exit criterion.
    let disp_p = dispatcher.precision().unwrap_or(0.0);
    assert!(
        disp_p >= DISPATCHER_GATE,
        "GATE FAILED: dispatcher precision {disp_p:.4} < {DISPATCHER_GATE:.2}\n{report}"
    );
    assert_eq!(
        round4(disp_p),
        DISPATCHER_P,
        "dispatcher precision moved\n{report}"
    );
    assert_eq!(
        dispatcher.tp + dispatcher.fp,
        DISPATCHER_PREDICTED_POSITIVES,
        "the dispatcher precision above rests on this many predicted positives; if it \
         changed, the strength of the claim in docs/classifier-eval.md changed too\n{report}"
    );

    // The disassembly-TEXT fallback (R13) is a last resort; if a corpus entry
    // starts reaching it, a capstone detail mode stopped resolving and the
    // measurement above no longer describes the path users get.
    assert_eq!(
        low_confidence, 0,
        "{low_confidence} corpus records fell back to the text heuristic; every one of them \
         used the capstone detail path when this was recorded\n{report}"
    );

    verify_manifest("after");
}

/// CLS-11's second half: `cargo test` must not write into the source tree.
/// The corpus is opened read-only and hashed before and after the gate above;
/// this test additionally asserts that the two files the OLD harness used to
/// regenerate are gone, so a stale copy cannot be mistaken for ground truth.
#[test]
fn the_old_generated_artifacts_are_gone() {
    for stale in ["tests/fixtures-labeled.jsonl", "tests/fixtures-eval.json"] {
        let p = repo_root().join(stale);
        assert!(
            !p.exists(),
            "{stale} still exists. It was WRITTEN by the classification gate on every run \
             (CLS-11), so it could never disagree with the code. The ground truth now lives \
             in tests/classify-corpus/, hand-labeled and hash-frozen."
        );
    }
}

/// The corpus is only meaningful if its entries are gadgets the scanner really
/// produces. Re-scan each fixture the corpus draws from and require every
/// record's `(vaddr, bytes, text)` triple to be present.
///
/// This is the check that stops the corpus drifting into fiction if the
/// scanner changes. It scans eleven fixtures, so it is the slow test in this
/// crate.
#[test]
fn every_corpus_entry_is_real_scanner_output() {
    verify_manifest("before");
    let corpus = load_corpus();
    let mut by_fixture: BTreeMap<&str, Vec<&Record>> = BTreeMap::new();
    for r in &corpus {
        by_fixture.entry(&r.fixture).or_default().push(r);
    }
    for (fixture, records) in by_fixture {
        let path = repo_root().join("tests/fixtures").join(fixture);
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {fixture}: {e}"));
        let loaded =
            rf_core::Binary::load(&data).unwrap_or_else(|e| panic!("parse {fixture}: {e}"));
        let opts = rf_scan::ScanOptions {
            depth: 10,
            ..Default::default()
        };
        let gadgets = match &loaded {
            rf_core::LoadedBinary::Elf(b) => rf_scan::scan_binary(b, &opts).unwrap(),
            rf_core::LoadedBinary::Pe(b) => rf_scan::scan_binary(b, &opts).unwrap(),
            rf_core::LoadedBinary::MachO(b) => rf_scan::scan_binary(b, &opts).unwrap(),
            other => panic!("{fixture}: unsupported container {other:?}"),
        };
        let index: BTreeSet<(u64, String, String)> = gadgets
            .iter()
            .map(|g| (g.vaddr, g.bytes_hex(), g.text()))
            .collect();
        for r in records {
            let key = (r.vaddr_u64(), r.bytes.clone(), r.text.clone());
            assert!(
                index.contains(&key),
                "{fixture} {} is in the corpus but not in a depth-10 scan any more:\n  {}",
                r.vaddr,
                r.text
            );
        }
    }
}

/// Every corpus record must be internally consistent: a non-`other` primary
/// has to be one of the gadget's own labels, `other` means no label except
/// possibly `dispatcher`, and every entry must carry a justification.
#[test]
fn corpus_records_are_well_formed() {
    let corpus = load_corpus();
    for r in &corpus {
        let labels: BTreeSet<&str> = r.truth_labels.iter().map(String::as_str).collect();
        for l in &labels {
            assert!(CLASSES.contains(l), "{}: unknown label {l}", r.vaddr);
        }
        assert!(
            CLASSES.contains(&r.truth_primary.as_str()),
            "{}: unknown primary {}",
            r.vaddr,
            r.truth_primary
        );
        if r.truth_primary == "other" {
            assert!(
                labels.is_empty() || labels == BTreeSet::from(["dispatcher"]),
                "{}: primary `other` with labels {:?}",
                r.vaddr,
                r.truth_labels
            );
        } else {
            assert!(
                labels.contains(r.truth_primary.as_str()),
                "{}: primary {} is not in the label set {:?}",
                r.vaddr,
                r.truth_primary,
                r.truth_labels
            );
        }
        // Every entry must carry a written reason. The bar is deliberately
        // low — "a single direct jmp" is a complete justification for
        // `other` — but it rules out an empty or placeholder field, which is
        // what TAXONOMY.md's withdrawn "35 hand-verified entries" claim
        // amounted to.
        assert!(
            r.why.len() >= 15 && r.why.split_whitespace().count() >= 3,
            "{}: justification too short to be a real one: {:?}",
            r.vaddr,
            r.why
        );
        assert!(!r.bytes.is_empty(), "{}: empty bytes", r.vaddr);
        assert!(!r.text.is_empty(), "{}: empty text", r.vaddr);
    }
    // CLS-10: the corpus must keep covering more than x86-64.
    let arches: BTreeSet<&str> = corpus.iter().map(|r| r.arch.as_str()).collect();
    for want in [
        "x86_64", "i386", "arm", "arm64", "mips", "ppc", "sparc", "riscv64",
    ] {
        assert!(arches.contains(want), "corpus lost coverage of {want}");
    }
}
