//! ECO-01 / ECO-12 / ECO-09 / ECO-06 at the process level.
//!
//! The centrepiece is [`exit_criterion_pop_rdi_no_rsi_rdx`], Phase 4's gate.
//! It deliberately does **not** read `regs_written` back out of the JSON: the
//! field under test cannot also be the evidence that the test passed. Every
//! returned gadget's written-register set is re-derived here, from the
//! gadget's own disassembly text, by [`regs_written_from_text`] — a small,
//! separate x86-64 model that shares no code with rf-classify. If the
//! classifier ever decides that `pop rsi` does not write rsi, this test
//! notices.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_rop-finder");

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

/// Run rop-finder, requiring exit 0, and return stdout.
fn rf(args: &[&str]) -> String {
    let o = Command::new(EXE).args(args).output().expect("spawn");
    assert_eq!(
        o.status.code(),
        Some(0),
        "rop-finder {args:?} exited {:?}\nstderr: {}",
        o.status.code(),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn rf_fail(args: &[&str]) -> (i32, String) {
    let o = Command::new(EXE).args(args).output().expect("spawn");
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn json_gadgets(args: &[&str]) -> Vec<serde_json::Value> {
    serde_json::from_str(&rf(args)).expect("--format json emits a JSON array")
}

// ---------------------------------------------------------------------------
// An independent model of "which registers does this x86-64 text write?".
//
// This exists so the exit criterion is checked against the gadget's
// disassembly rather than against the classifier's own answer. It is
// deliberately written from the Intel manual's operand rules rather than
// derived from crates/rf-classify: two implementations that agree are
// evidence, one implementation quoted back at itself is not.
// ---------------------------------------------------------------------------

/// Full-width name for any 8/16/32/64-bit spelling of a general register.
fn full_width(reg: &str) -> Option<&'static str> {
    const FAMILIES: &[(&str, &[&str])] = &[
        ("rax", &["rax", "eax", "ax", "al", "ah"]),
        ("rbx", &["rbx", "ebx", "bx", "bl", "bh"]),
        ("rcx", &["rcx", "ecx", "cx", "cl", "ch"]),
        ("rdx", &["rdx", "edx", "dx", "dl", "dh"]),
        ("rsi", &["rsi", "esi", "si", "sil"]),
        ("rdi", &["rdi", "edi", "di", "dil"]),
        ("rbp", &["rbp", "ebp", "bp", "bpl"]),
        ("rsp", &["rsp", "esp", "sp", "spl"]),
        ("r8", &["r8", "r8d", "r8w", "r8b"]),
        ("r9", &["r9", "r9d", "r9w", "r9b"]),
        ("r10", &["r10", "r10d", "r10w", "r10b"]),
        ("r11", &["r11", "r11d", "r11w", "r11b"]),
        ("r12", &["r12", "r12d", "r12w", "r12b"]),
        ("r13", &["r13", "r13d", "r13w", "r13b"]),
        ("r14", &["r14", "r14d", "r14w", "r14b"]),
        ("r15", &["r15", "r15d", "r15w", "r15b"]),
    ];
    FAMILIES
        .iter()
        .find(|(_, names)| names.contains(&reg))
        .map(|(full, _)| *full)
}

/// Split an operand list on top-level commas (a `[rax + rbx*4]` memory
/// operand has none, but `mov rax, qword ptr [rbx + 8]` does).
fn operands(rest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut cur = String::new();
    for c in rest.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c);
            }
            ']' => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur = String::new();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// A bare register operand, if that is what this operand is. A memory
/// reference (`[rdi]`, `qword ptr [rdi + 8]`) is NOT a register write — the
/// register is a pointer being read.
fn bare_register(op: &str) -> Option<&'static str> {
    if op.contains('[') {
        return None;
    }
    full_width(op.trim())
}

/// Registers written by one instruction's text.
fn writes_of(insn: &str) -> BTreeSet<&'static str> {
    let mut out = BTreeSet::new();
    let insn = insn.trim();
    let (mnemonic, rest) = match insn.split_once(' ') {
        Some((m, r)) => (m, r),
        None => (insn, ""),
    };
    // `rep`/`lock`/`repz`... prefixes: recurse on the rest.
    if matches!(
        mnemonic,
        "rep" | "repe" | "repz" | "repne" | "repnz" | "lock" | "bnd"
    ) {
        out.extend(writes_of(rest));
        // A `rep` prefix also decrements rcx.
        if mnemonic.starts_with("rep") {
            out.insert("rcx");
        }
        return out;
    }
    let ops = operands(rest);

    // Implicit-destination forms first: these write registers that do not
    // appear in the operand text at all, which is exactly the class a
    // text-matching test would otherwise miss.
    match mnemonic {
        "mul" | "imul" if ops.len() == 1 => {
            out.insert("rax");
            out.insert("rdx");
        }
        "div" | "idiv" => {
            out.insert("rax");
            out.insert("rdx");
        }
        "cdq" | "cqo" | "cwd" => {
            out.insert("rdx");
        }
        "cbw" | "cwde" | "cdqe" => {
            out.insert("rax");
        }
        "syscall" => {
            out.insert("rcx");
            out.insert("r11");
        }
        "leave" => {
            out.insert("rsp");
            out.insert("rbp");
        }
        "cpuid" => {
            for r in ["rax", "rbx", "rcx", "rdx"] {
                out.insert(r);
            }
        }
        "rdtsc" | "rdtscp" => {
            out.insert("rax");
            out.insert("rdx");
        }
        _ => {}
    }
    if mnemonic.starts_with("movs")
        || mnemonic.starts_with("stos")
        || mnemonic.starts_with("lods")
        || mnemonic.starts_with("scas")
        || mnemonic.starts_with("cmps")
    {
        // The string forms without operands are the implicit ones;
        // `movsx`/`movsxd`/`movzx` are handled as ordinary two-operand
        // instructions below.
        if ops.is_empty() {
            out.insert("rsi");
            out.insert("rdi");
            if mnemonic.starts_with("lods") {
                out.insert("rax");
            }
        }
    }
    // Anything that touches the stack moves rsp.
    if matches!(
        mnemonic,
        "push" | "pop" | "call" | "ret" | "retf" | "pusha" | "popa"
    ) || mnemonic.starts_with("ret")
    {
        out.insert("rsp");
    }

    // Explicit destinations.
    const WRITES_FIRST: &[&str] = &[
        "mov", "movabs", "movzx", "movsx", "movsxd", "lea", "add", "sub", "and", "or", "xor",
        "adc", "sbb", "shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr", "neg", "not", "inc",
        "dec", "bswap", "bsf", "bsr", "lzcnt", "tzcnt", "popcnt", "xadd", "btc", "btr", "bts",
        "shld", "shrd", "andn", "blsi", "blsr", "bextr", "adcx", "adox", "crc32", "imul",
    ];
    let writes_first = WRITES_FIRST.contains(&mnemonic)
        || mnemonic.starts_with("cmov")
        || mnemonic.starts_with("set");
    if writes_first {
        if let Some(op) = ops.first().and_then(|o| bare_register(o)) {
            out.insert(op);
        }
    }
    if mnemonic == "pop" {
        if let Some(op) = ops.first().and_then(|o| bare_register(o)) {
            out.insert(op);
        }
    }
    // xchg and xadd write both operands.
    if matches!(mnemonic, "xchg" | "xadd" | "cmpxchg") {
        for o in &ops {
            if let Some(r) = bare_register(o) {
                out.insert(r);
            }
        }
        if mnemonic == "cmpxchg" {
            out.insert("rax");
        }
    }
    out
}

/// Every register a gadget's text writes, full-width, derived here and not
/// read back from the classifier.
fn regs_written_from_text(text: &str) -> BTreeSet<&'static str> {
    text.split(" ; ").flat_map(writes_of).collect()
}

#[test]
fn the_independent_model_finds_the_writes_it_is_relied_on_for() {
    // If this test is wrong, the exit criterion below proves nothing — so
    // the model is pinned first, on shapes whose answer is not debatable.
    let w = |t: &str| regs_written_from_text(t);
    assert!(w("pop rdi ; ret").contains("rdi"));
    assert!(w("pop rsi ; ret").contains("rsi"));
    assert!(w("mov rdx, rax ; ret").contains("rdx"));
    assert!(w("xor esi, esi ; ret").contains("rsi"));
    assert!(w("xchg rax, rsi ; ret").contains("rsi"));
    assert!(w("inc dl ; ret").contains("rdx"));
    // Implicit destinations, which a naive "does the text mention rdx" test
    // would miss entirely.
    assert!(w("div rcx ; ret").contains("rdx"));
    assert!(w("cdq ; ret").contains("rdx"));
    assert!(w("rep movsb ; ret").contains("rsi"));
    // ...and the reads that must NOT count as writes.
    assert!(!w("mov rax, rsi ; ret").contains("rsi"));
    assert!(!w("mov qword ptr [rsi], rax ; ret").contains("rsi"));
    assert!(!w("cmp rdx, rax ; ret").contains("rdx"));
    assert!(!w("push rdx ; ret").contains("rdx"));
}

/// **Phase 4's exit criterion.**
///
/// `rop-finder --binary elf-Linux-x64 --set-reg rdi --from-stack
///  --no-clobber rsi,rdx --max-side-effects 1 --terminator ret` must return
/// the `pop rdi ; ret` gadget and no gadget that writes rsi or rdx.
#[test]
fn exit_criterion_pop_rdi_no_rsi_rdx() {
    let bin = fixture("elf-Linux-x64");
    assert!(bin.is_file(), "fixture missing: {}", bin.display());
    let bin = bin.to_string_lossy().into_owned();
    let query = [
        "--binary",
        &bin,
        "--set-reg",
        "rdi",
        "--from-stack",
        "--no-clobber",
        "rsi,rdx",
        "--max-side-effects",
        "1",
        "--terminator",
        "ret",
    ];
    let mut args = query.to_vec();
    args.push("--format");
    args.push("json");
    let gadgets = json_gadgets(&args);

    assert!(!gadgets.is_empty(), "the query returned nothing");
    // The plan names 0x401648 for `pop rdi ; ret`; this asserts it against
    // the fixture rather than trusting the plan.
    let texts: Vec<&str> = gadgets
        .iter()
        .map(|g| g["text"].as_str().unwrap())
        .collect();
    let pop_rdi = gadgets
        .iter()
        .find(|g| g["text"] == "pop rdi ; ret")
        .unwrap_or_else(|| panic!("`pop rdi ; ret` not returned; got {texts:?}"));
    assert_eq!(
        pop_rdi["vaddr"], "0x0000000000401648",
        "the plan's address for `pop rdi ; ret` does not match the fixture"
    );

    // The real gate: NO returned gadget may write rsi or rdx, judged from
    // each gadget's own text.
    for g in &gadgets {
        let text = g["text"].as_str().expect("every record has text");
        let written = regs_written_from_text(text);
        for forbidden in ["rsi", "rdx"] {
            assert!(
                !written.contains(forbidden),
                "--no-clobber rsi,rdx returned {text:?}, which writes {forbidden} \
                 (re-derived from the text: {written:?})"
            );
        }
        // ...and every returned gadget must actually write rdi, which is
        // what --set-reg asked for.
        assert!(
            regs_written_from_text(text).contains("rdi"),
            "--set-reg rdi returned {text:?}, which does not write rdi"
        );
    }
}

/// The negative control for the test above.
///
/// A filter that returned nothing, or a written-register model that could
/// not see an rsi write, would both make the exit criterion pass vacuously.
/// Dropping `--no-clobber` must therefore bring back gadgets that the same
/// model says DO write rsi or rdx.
#[test]
fn without_no_clobber_the_forbidden_gadgets_come_back() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    let gadgets = json_gadgets(&[
        "--binary",
        &bin,
        "--set-reg",
        "rdi",
        "--terminator",
        "ret",
        "--format",
        "json",
    ]);
    let offenders: Vec<&str> = gadgets
        .iter()
        .map(|g| g["text"].as_str().unwrap())
        .filter(|t| {
            let w = regs_written_from_text(t);
            w.contains("rsi") || w.contains("rdx")
        })
        .collect();
    assert!(
        !offenders.is_empty(),
        "the unconstrained query returned nothing that writes rsi/rdx, so \
         --no-clobber's effect in the exit criterion is untested"
    );
}

/// `--from-stack` is strictly stronger than `--set-reg`: a gadget that
/// computes a register's value rather than popping it must be dropped.
#[test]
fn from_stack_is_stronger_than_set_reg() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    let set_only = json_gadgets(&["--binary", &bin, "--set-reg", "rdi", "--format", "json"]);
    let from_stack = json_gadgets(&[
        "--binary",
        &bin,
        "--set-reg",
        "rdi",
        "--from-stack",
        "--format",
        "json",
    ]);
    assert!(
        from_stack.len() < set_only.len(),
        "--from-stack narrowed nothing ({} vs {})",
        from_stack.len(),
        set_only.len()
    );
    let popped: Vec<&str> = from_stack
        .iter()
        .map(|g| g["text"].as_str().unwrap())
        .collect();
    // Everything --from-stack keeps must contain a `pop rdi` or an
    // rsp-relative load into rdi; a `xor rdi, rdi` or `mov rdi, rax` must not
    // survive.
    for t in &popped {
        assert!(
            t.contains("pop rdi") || t.contains("[rsp") || t.contains("[esp"),
            "--from-stack kept {t:?}, which does not take rdi off the stack"
        );
    }
}

/// ECO-12: `--pivot` is the preset over the label, not a second rule.
#[test]
fn pivot_is_exactly_the_stack_pivot_label() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    let a = json_gadgets(&[
        "--binary", &bin, "--pivot", "--depth", "4", "--format", "json",
    ]);
    let b = json_gadgets(&[
        "--binary",
        &bin,
        "--label",
        "stack-pivot",
        "--depth",
        "4",
        "--format",
        "json",
    ]);
    assert!(!a.is_empty(), "--pivot found no stack pivots");
    assert_eq!(
        a, b,
        "--pivot and --label stack-pivot must be the same query"
    );
}

/// ECO-01's ropper-style sequence matcher.
#[test]
fn search_matches_an_instruction_sequence_not_a_regex() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    let hits = json_gadgets(&[
        "--binary",
        &bin,
        "--search",
        "pop rdi; ret",
        "--format",
        "json",
    ]);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0]["text"], "pop rdi ; ret");

    // A wildcard widens it, and every hit really contains the sequence.
    let wide = json_gadgets(&[
        "--binary",
        &bin,
        "--search",
        "pop r?i; ret",
        "--format",
        "json",
    ]);
    assert!(
        wide.len() > hits.len(),
        "the ? wildcard matched nothing extra"
    );
    for g in &wide {
        let t = g["text"].as_str().unwrap();
        assert!(t.ends_with("; ret"), "{t}");
    }

    // `--search` is not `--re`: the pattern is a sequence, so an instruction
    // between the two pieces breaks the match.
    let text_of = |g: &serde_json::Value| g["text"].as_str().unwrap().to_string();
    assert!(
        !wide
            .iter()
            .map(text_of)
            .any(|t| t == "pop rdi ; pop rsi ; ret"),
        "--search matched a non-contiguous sequence"
    );
}

/// CLS-09: an unknown stack delta is not zero.
#[test]
fn max_stack_delta_rejects_an_unknown_delta() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    let bounded = json_gadgets(&[
        "--binary",
        &bin,
        "--max-stack-delta",
        "8",
        "--depth",
        "4",
        "--classify",
        "--format",
        "json",
    ]);
    assert!(!bounded.is_empty());
    for g in &bounded {
        let d = g["stack_delta"]
            .as_i64()
            .unwrap_or_else(|| panic!("a gadget passed --max-stack-delta with a null delta: {g}"));
        assert!(d <= 8, "{g}");
    }
}

/// The `--terminator` vocabulary is validated, and the message names it.
#[test]
fn bad_flag_values_name_their_vocabulary() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    for (args, want) in [
        (vec!["--terminator", "returns"], "syscall"),
        (vec!["--format", "yaml"], "jsonl"),
        (vec!["--chain-format", "c"], "python"),
        (vec!["--class", "pivot"], "stack-pivot"),
    ] {
        let mut a = vec!["--binary", &bin];
        a.extend(args.iter().copied());
        let (code, err) = rf_fail(&a);
        assert_eq!(code, 1, "{args:?} -> {err}");
        assert!(err.contains(want), "{args:?} -> {err}");
    }
    // --json and --format must not silently pick a winner.
    let (code, err) = rf_fail(&["--binary", &bin, "--json", "--format", "csv"]);
    assert_eq!(code, 1);
    assert!(err.contains("conflict"), "{err}");
}

// ---------------------------------------------------------------------------
// ECO-09: output formats.
// ---------------------------------------------------------------------------

/// The streaming path must produce the same *records* as the buffered one.
/// Only the order may differ.
#[test]
fn jsonl_is_the_same_record_set_as_json() {
    let bin = fixture("elf-Linux-x86");
    let bin = bin.to_string_lossy().into_owned();
    for extra in [
        vec![],
        vec!["--badbytes", "00|0a"],
        vec!["--only", "pop|ret"],
        vec!["--all"],
        vec!["--classify"],
        vec!["--re", "pop.*|ret"],
    ] {
        let mut a = vec!["--binary", &bin, "--depth", "3", "--format", "json"];
        a.extend(extra.iter().copied());
        let json: Vec<serde_json::Value> = serde_json::from_str(&rf(&a)).unwrap();

        let mut b = vec!["--binary", &bin, "--depth", "3", "--format", "jsonl"];
        b.extend(extra.iter().copied());
        let jsonl: Vec<serde_json::Value> = rf(&b)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("each line is one JSON object"))
            .collect();

        // A MULTIset, not a set: `--all` disables dedup, and one gadget can
        // legitimately be produced by more than one anchor table, so an
        // identical record may appear twice. Collapsing that to a set would
        // let the streaming path drop a duplicate unnoticed.
        let key = |v: &serde_json::Value| serde_json::to_string(v).unwrap();
        let mut sa: Vec<String> = json.iter().map(key).collect();
        let mut sb: Vec<String> = jsonl.iter().map(key).collect();
        sa.sort();
        sb.sort();
        assert_eq!(sa.len(), sb.len(), "record count differs with {extra:?}");
        assert_eq!(sa, sb, "jsonl diverged from json with {extra:?}");
    }
}

/// jsonl really is in scan order, not the alphabetical order of the other
/// formats — the documented, deliberate difference.
#[test]
fn jsonl_is_in_scan_order_and_json_is_alphabetical() {
    let bin = fixture("elf-Linux-x86");
    let bin = bin.to_string_lossy().into_owned();
    let json: Vec<serde_json::Value> =
        serde_json::from_str(&rf(&["--binary", &bin, "--depth", "3", "--format", "json"])).unwrap();
    let texts: Vec<&str> = json.iter().map(|g| g["text"].as_str().unwrap()).collect();
    let mut sorted = texts.clone();
    sorted.sort_unstable();
    assert_eq!(texts, sorted, "--format json must stay alphabetical");

    let jsonl = rf(&["--binary", &bin, "--depth", "3", "--format", "jsonl"]);
    let ltexts: Vec<String> = jsonl
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["text"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    let mut lsorted = ltexts.clone();
    lsorted.sort();
    assert_ne!(
        ltexts, lsorted,
        "--format jsonl came out alphabetical, so it is not streaming"
    );
}

#[test]
fn csv_has_a_fixed_header_and_one_row_per_gadget() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    let csv = rf(&["--binary", &bin, "--depth", "3", "--format", "csv"]);
    let mut lines = csv.lines();
    let header = lines.next().expect("a header row");
    assert!(header.starts_with("vaddr,bytes,text,"), "{header}");
    let rows: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
    let json = json_gadgets(&["--binary", &bin, "--depth", "3", "--format", "json"]);
    assert_eq!(rows.len(), json.len());
    // A gadget text with a comma must be quoted, not split across columns.
    assert!(
        rows.iter().any(|r| r.contains("\",")),
        "no row quoted a comma-bearing gadget text"
    );
}

/// ECO-09 names "no address-only mode" as one of the gaps. It is
/// `--format raw --noinstr`, composed from two orthogonal flags.
#[test]
fn raw_is_undecorated_and_composes_into_address_only() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    let raw = rf(&["--binary", &bin, "--depth", "3", "--format", "raw"]);
    assert!(!raw.contains("Gadgets information"), "raw printed a header");
    assert!(
        !raw.contains("Unique gadgets found"),
        "raw printed a footer"
    );
    assert!(raw.lines().all(|l| l.starts_with("0x")));

    let addrs = rf(&[
        "--binary",
        &bin,
        "--depth",
        "3",
        "--format",
        "raw",
        "--noinstr",
    ]);
    for line in addrs.lines() {
        assert!(
            !line.contains(" : "),
            "--format raw --noinstr is address-only, got {line:?}"
        );
        assert!(line.starts_with("0x"));
    }
}

/// ECO-09 part two: MANUAL.md has advertised raw-bytes chain output since
/// v0.1 and `RopChain::to_bytes` was reachable from no interface.
#[test]
fn chain_format_raw_emits_the_packed_payload() {
    let bin = fixture("elf-Linux-x86");
    let bin = bin.to_string_lossy().into_owned();
    let ir: serde_json::Value = serde_json::from_str(&rf(&[
        "--binary",
        &bin,
        "--ropchain",
        "--chain-format",
        "json",
    ]))
    .expect("the JSON chain IR");
    let words = ir["words"].as_array().expect("the IR has a word list");
    assert!(!words.is_empty());

    let o = Command::new(EXE)
        .args(["--binary", &bin, "--ropchain", "--chain-format", "raw"])
        .output()
        .expect("spawn");
    assert_eq!(o.status.code(), Some(0));
    let bytes = o.stdout;
    // 32-bit target: one 4-byte little-endian word per IR entry.
    assert_eq!(
        bytes.len(),
        words.len() * 4,
        "raw payload is {} bytes for {} words",
        bytes.len(),
        words.len()
    );
    let first = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64;
    let want = words[0]["value"]
        .as_u64()
        .or_else(|| {
            words[0]["value"]
                .as_str()
                .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        })
        .expect("a word value");
    assert_eq!(
        first, want,
        "the first packed word is not the IR's first word"
    );
}

// ---------------------------------------------------------------------------
// ECO-06: --info as a checksec replacement.
// ---------------------------------------------------------------------------

#[test]
fn info_reports_mitigations_with_evidence_on_every_format() {
    for (name, keys) in [
        (
            "elf-Linux-x64",
            &["nx", "pie", "relro", "canary", "fortify"][..],
        ),
        (
            "pe-x64-cmd-v6.1.7601",
            &["aslr", "dep", "guard_cf", "cet_compat"][..],
        ),
        ("macho-x64-ls", &["pie", "nx_stack", "code_signature"][..]),
    ] {
        let bin = fixture(name);
        assert!(bin.is_file(), "fixture missing: {}", bin.display());
        let info: serde_json::Value =
            serde_json::from_str(&rf(&["--binary", &bin.to_string_lossy(), "--info"]))
                .expect("--info emits JSON");
        let m = &info["mitigations"];
        for k in keys {
            let v = &m[*k];
            assert!(!v.is_null(), "{name}: no {k} mitigation reported");
            assert!(
                v["enabled"].is_boolean() || v["enabled"] == "unknown",
                "{name}/{k}: enabled is {} (want a bool or \"unknown\")",
                v["enabled"]
            );
            let evidence = v["evidence"].as_str().unwrap_or("");
            assert!(!evidence.is_empty(), "{name}/{k}: no evidence");
            // ECO-06's whole point: an "unknown" that does not say why is
            // no better than a wrong boolean.
            if v["enabled"] == "unknown" {
                assert!(
                    evidence.len() > 20,
                    "{name}/{k}: unknown with a one-word reason {evidence:?}"
                );
            }
        }
    }
}

/// A raw blob has no headers, so the mitigation set is empty *by design* and
/// must say so rather than looking like a binary with everything switched
/// off.
#[test]
fn info_on_a_raw_blob_says_why_it_has_no_mitigations() {
    let bin = fixture("raw-x86.raw");
    let info: serde_json::Value = serde_json::from_str(&rf(&[
        "--binary",
        &bin.to_string_lossy(),
        "--rawArch",
        "x86",
        "--rawMode",
        "32",
        "--info",
    ]))
    .expect("--info emits JSON");
    assert_eq!(info["mitigations"], serde_json::json!({}));
    let note = info["mitigations_note"].as_str().expect("a stated reason");
    assert!(!note.is_empty(), "empty note");
}

/// ECO-06: ELF `imports` was hardcoded `[]`, so ret2plt needed a second
/// tool. It is now the SHN_UNDEF symbol set with GOT/PLT where provable.
#[test]
fn info_enumerates_elf_symbols_and_imports() {
    let bin = fixture("elf-ARM64-bash");
    let info: serde_json::Value =
        serde_json::from_str(&rf(&["--binary", &bin.to_string_lossy(), "--info"])).unwrap();
    let imports = info["imports"].as_array().expect("an imports array");
    assert!(!imports.is_empty(), "a dynamic ELF has undefined symbols");
    assert!(imports.iter().all(|i| i["symbol"].is_string()));
    let symbols = info["symbols"].as_array().expect("a symbols array");
    assert!(symbols.len() >= imports.len());
    assert!(symbols.iter().any(|s| s["table"] == "dynsym"));
    assert_eq!(
        info["symbol_count"].as_u64().unwrap() as usize,
        symbols.len()
    );
    // --base 0 must slide symbol addresses exactly as it slides sections.
    let rebased: serde_json::Value = serde_json::from_str(&rf(&[
        "--binary",
        &bin.to_string_lossy(),
        "--base",
        "0",
        "--info",
    ]))
    .unwrap();
    let base = u64::from_str_radix(
        info["image_base"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let named = |v: &serde_json::Value, n: &str| -> Option<u64> {
        v["symbols"].as_array()?.iter().find_map(|s| {
            (s["name"] == n)
                .then(|| s["addr"].as_str())
                .flatten()
                .and_then(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok())
        })
    };
    let name = symbols
        .iter()
        .find(|s| s["addr"].is_string() && s["name"].is_string())
        .and_then(|s| s["name"].as_str())
        .expect("some symbol has an address");
    let before = named(&info, name).unwrap();
    let after = named(&rebased, name).unwrap();
    assert_eq!(
        after,
        before - base,
        "symbol {name} did not rebase with --base 0"
    );
}

/// PERF-05's budget must mean the same thing in every format. The streaming
/// path cannot un-write the records it already emitted, but the exit code
/// and the sentence a script reads must not depend on `--format`.
#[test]
fn a_budget_hit_reads_the_same_in_every_format() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    let mut seen = Vec::new();
    for fmt in ["json", "jsonl", "human", "csv", "raw"] {
        let o = Command::new(EXE)
            .args(["--binary", &bin, "--format", fmt, "--max-gadgets", "5"])
            .output()
            .expect("spawn");
        assert_eq!(
            o.status.code(),
            Some(2),
            "--format {fmt} exited {:?} on an exhausted budget",
            o.status.code()
        );
        let err = String::from_utf8_lossy(&o.stderr).into_owned();
        assert!(err.contains("--max-gadgets"), "--format {fmt}: {err}");
        seen.push(err);
    }
    assert!(
        seen.windows(2).all(|w| w[0] == w[1]),
        "the budget message differs between formats: {seen:?}"
    );
}

/// CLI-05 / ECO-02: a search hit names the section it is in and that
/// section's permissions, so "is this string writable?" needs no second
/// tool. The human output stays byte-identical to ROPgadget's (that is what
/// tests/flag_conformance.py checks); only the structured formats gain the
/// fields.
#[test]
fn search_hits_carry_their_section_and_permissions() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    let hits: Vec<serde_json::Value> = serde_json::from_str(&rf(&[
        "--binary", &bin, "--string", "main", "--format", "json",
    ]))
    .expect("a JSON array");
    assert!(!hits.is_empty());
    for h in &hits {
        assert!(h["vaddr"].as_str().is_some_and(|v| v.starts_with("0x")));
        assert!(h["section"].is_string(), "no section on {h}");
        assert_eq!(h["length"], 4, "length is the pattern length");
        assert!(h["match"].is_string());
        assert!(h["writable"].is_boolean());
        // --string searches DATA sections, so nothing it finds is executable.
        assert_eq!(h["executable"], false, "{h}");
    }

    // --opcode searches EXECUTABLE sections, and says so.
    let ops: Vec<serde_json::Value> = serde_json::from_str(&rf(&[
        "--binary", &bin, "--opcode", "c9c3", "--format", "json",
    ]))
    .expect("a JSON array");
    assert!(!ops.is_empty());
    for h in &ops {
        assert_eq!(h["executable"], true, "{h}");
        assert_eq!(h["length"], 2, "length is the byte count");
    }

    // csv is the same records with a fixed column order.
    let csv = rf(&["--binary", &bin, "--opcode", "c9c3", "--format", "csv"]);
    let mut lines = csv.lines();
    assert_eq!(
        lines.next(),
        Some("vaddr,section,length,opcode,writable,executable")
    );
    assert_eq!(lines.filter(|l| !l.is_empty()).count(), ops.len());
}

/// The v0.4 `--classify` record must carry the fields the constraint flags
/// filter on, so a query can be checked by reading its own output rather
/// than by trusting the filter.
#[test]
fn classify_exposes_the_fields_the_constraints_filter_on() {
    let bin = fixture("elf-Linux-x64");
    let bin = bin.to_string_lossy().into_owned();
    let g = json_gadgets(&[
        "--binary",
        &bin,
        "--search",
        "pop rdi; ret",
        "--classify",
        "--format",
        "json",
    ]);
    assert_eq!(g.len(), 1);
    let r = &g[0];
    assert_eq!(r["sets"], serde_json::json!(["rdi"]));
    assert_eq!(r["clobbers"], serde_json::json!([]));
    assert_eq!(r["regs_from_stack"], serde_json::json!(["rdi"]));
    // The terminating `ret` pops 8 bytes of its own on x86-64.
    assert_eq!(r["stack_delta"], 16);
    assert_eq!(r["terminator"], "ret");
    assert_eq!(r["terminator_class"], "ret");
    // ...and without --classify none of it is emitted.
    let plain = rf(&[
        "--binary",
        &bin,
        "--search",
        "pop rdi; ret",
        "--format",
        "json",
    ]);
    assert!(!plain.contains("stack_delta"), "{plain}");
    assert!(!plain.contains("clobbers"), "{plain}");
}
