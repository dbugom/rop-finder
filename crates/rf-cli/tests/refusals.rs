//! Process-level tests for the v0.2.0 refusals — the cases where
//! rop-finder now declines to answer rather than answering wrongly.
//!
//! Each of these is a *process* contract (exit code + which stream the
//! diagnostic lands on + that stdout carries no gadget listing), so none of
//! them can be checked from a unit test:
//!
//!   * CORE-01 — an ELF whose `e_machine` rop-finder cannot disassemble
//!     used to fall back to x86 (`unwrap_or(Arch::X86)`) and print a
//!     complete, confident, entirely fabricated listing.
//!   * CORE-03/CORE-05 — a fat Mach-O with more than one usable slice used
//!     to be scanned as the concatenation of every slice's executable
//!     regions with the FIRST slice's decoder, so most of the output was an
//!     x86 misreading of another architecture at addresses interleaved with
//!     the genuine ones.
//!   * ROB-06 — the input file was `std::fs::read` with no cap and no
//!     stat, so a character device or FIFO allocated until the OS killed
//!     the process.
//!   * CLI-11 — `--noinstr` printed the disassembly the oracle suppresses.

use std::path::PathBuf;
use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_rop-finder");

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let o = Command::new(EXE).args(args).output().expect("spawn");
    Run {
        code: o.status.code(),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// Write `bytes` to a uniquely named file under the target dir and return
/// its path. `tempfile` is a dev-dependency of rf-cli's own tests only in
/// some configurations, so this stays dependency-free.
fn scratch_file(tag: &str, bytes: &[u8]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/rf-cli-test-scratch");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let p = dir.join(format!("{tag}-{}", std::process::id()));
    std::fs::write(&p, bytes).expect("write scratch");
    p
}

// ---------------------------------------------------------------------------
// CORE-01
// ---------------------------------------------------------------------------

/// An ELF declaring a machine type rop-finder cannot disassemble must exit
/// non-zero, name the machine, and print ZERO gadgets.
///
/// Before v0.2.0 this printed 42,508 gadgets for `e_machine = 0x9999` on
/// this very fixture, decoded as x86, with exit 0. ROPgadget refuses the
/// same file (`[Error] ELF.getArch() - Architecture not supported`, exit 1).
#[test]
fn unrecognized_e_machine_is_refused_and_prints_no_gadgets() {
    let mut bytes = std::fs::read(fixture("elf-Linux-x86")).expect("fixture");
    // e_machine is a 2-byte LE field at offset 18 in both ELF classes.
    bytes[18] = 0x99;
    bytes[19] = 0x99;
    let path = scratch_file("elf-e-machine-9999", &bytes);

    let r = run(&["--binary", path.to_str().unwrap(), "--depth", "10"]);
    assert_ne!(r.code, Some(0), "must not succeed\nstderr: {}", r.stderr);
    assert!(
        !r.stdout.contains("Gadgets information") && r.stdout.trim().is_empty(),
        "must print ZERO gadgets, got:\n{}",
        r.stdout
    );
    assert!(
        r.stderr.contains("0x9999"),
        "the diagnostic must name the machine type: {}",
        r.stderr
    );
    // ...and it must survive --json too: a caller parsing JSON must not get
    // a fabricated array either.
    let j = run(&["--binary", path.to_str().unwrap(), "--json"]);
    assert_ne!(j.code, Some(0));
    assert!(j.stdout.trim().is_empty(), "{}", j.stdout);
}

// ---------------------------------------------------------------------------
// CORE-03 / CORE-05
// ---------------------------------------------------------------------------

fn unique_count(stdout: &str) -> usize {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("Unique gadgets found: "))
        .and_then(|n| n.trim().parse().ok())
        .expect("no 'Unique gadgets found' line")
}

/// A multi-slice fat Mach-O with no `--arch` is refused, and the message
/// lists the slices on offer.
#[test]
fn fat_macho_without_arch_is_refused_not_guessed() {
    let bin = fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
    let r = run(&["--binary", bin.to_str().unwrap(), "--depth", "10"]);
    assert_eq!(r.code, Some(1), "stderr: {}", r.stderr);
    assert!(r.stdout.trim().is_empty(), "{}", r.stdout);
    assert!(r.stderr.contains("--arch"), "{}", r.stderr);
    assert!(r.stderr.contains("x86_64"), "{}", r.stderr);
    assert!(r.stderr.contains("i386"), "{}", r.stderr);
}

/// `--arch` selects exactly one slice, and the two slices are different
/// scans. Neither is the concatenation.
#[test]
fn fat_macho_arch_selects_one_slice() {
    let bin = fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
    let bin = bin.to_str().unwrap();
    let x64 = run(&["--binary", bin, "--depth", "10", "--arch", "x86_64"]);
    let x86 = run(&["--binary", bin, "--depth", "10", "--arch", "i386"]);
    assert_eq!(x64.code, Some(0), "{}", x64.stderr);
    assert_eq!(x86.code, Some(0), "{}", x86.stderr);
    let (c64, c86) = (unique_count(&x64.stdout), unique_count(&x86.stdout));
    assert!(c64 > 0 && c86 > 0, "{c64} {c86}");
    assert_ne!(c64, c86, "the two slices must not produce the same scan");

    // An alias resolves to the same slice.
    let alias = run(&["--binary", bin, "--depth", "10", "--arch", "amd64"]);
    assert_eq!(alias.stdout, x64.stdout);

    // A slice the container does not hold is a usage error naming what it
    // does hold.
    let missing = run(&["--binary", bin, "--arch", "arm64"]);
    assert_eq!(missing.code, Some(1));
    assert!(
        missing.stderr.contains("no arm64 slice") && missing.stderr.contains("x86_64"),
        "{}",
        missing.stderr
    );

    // An unknown name is rejected before the binary is even consulted.
    let bogus = run(&["--binary", bin, "--arch", "vax"]);
    assert_eq!(bogus.code, Some(1));
    assert!(bogus.stderr.contains("unknown --arch"), "{}", bogus.stderr);
}

/// `--compat` restores ROPgadget's bug-for-bug concatenation and says so on
/// stderr, so the escape hatch can never be mistaken for a clean scan.
#[test]
fn fat_macho_compat_restores_the_concatenation_with_a_warning() {
    let bin = fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
    let bin = bin.to_str().unwrap();
    let compat = run(&["--binary", bin, "--depth", "10", "--compat"]);
    assert_eq!(compat.code, Some(0), "{}", compat.stderr);
    let concat = unique_count(&compat.stdout);
    let x64 = unique_count(&run(&["--binary", bin, "--depth", "10", "--arch", "x86_64"]).stdout);
    assert!(
        concat > x64,
        "the concatenation must be strictly larger than one slice ({concat} vs {x64})"
    );
    assert!(
        compat.stderr.contains("FABRICATED"),
        "--compat must warn that the extra gadgets are not real: {}",
        compat.stderr
    );
}

/// `--info` is the way OUT of the refusal, so it must not refuse, and it
/// must name the slices in the spelling `--arch` accepts.
///
/// Before this, `--info` reported a fat binary's slices under rop-finder's
/// internal architecture names ("x64", "x86") while `--arch` speaks Mach-O
/// slice names ("x86_64", "i386"), so the tool told the user a choice was
/// required and not what to type.
#[test]
fn info_names_the_slices_arch_accepts() {
    let bin = fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
    let r = run(&["--binary", bin.to_str().unwrap(), "--info"]);
    assert_eq!(r.code, Some(0), "--info must not refuse: {}", r.stderr);
    let v: serde_json::Value = serde_json::from_str(&r.stdout).expect("--info must be JSON");
    assert_eq!(v["format"], "universal");
    assert_eq!(v["arch_selection_required"], serde_json::Value::Bool(true));
    let names: Vec<&str> = v["slices"]
        .as_array()
        .expect("slices")
        .iter()
        .map(|s| s["slice"].as_str().expect("slice name"))
        .collect();
    assert_eq!(names, vec!["x86_64", "i386"]);
    // Every name --info prints must actually work as --arch.
    for n in names {
        let s = run(&[
            "--binary",
            bin.to_str().unwrap(),
            "--depth",
            "4",
            "--arch",
            n,
        ]);
        assert_eq!(s.code, Some(0), "--arch {n} must be accepted: {}", s.stderr);
    }
}

/// `--arch` on a single-architecture image is accepted when it agrees and
/// refused when it does not, rather than silently selecting nothing.
#[test]
fn arch_on_a_single_architecture_image_must_agree() {
    let bin = fixture("elf-Linux-x86");
    let bin = bin.to_str().unwrap();
    let ok = run(&["--binary", bin, "--depth", "10", "--arch", "i386"]);
    assert_eq!(ok.code, Some(0), "{}", ok.stderr);
    let plain = run(&["--binary", bin, "--depth", "10"]);
    assert_eq!(ok.stdout, plain.stdout);

    let wrong = run(&["--binary", bin, "--depth", "10", "--arch", "arm64"]);
    assert_eq!(wrong.code, Some(1));
    assert!(wrong.stderr.contains("does not match"), "{}", wrong.stderr);
}

// ---------------------------------------------------------------------------
// ROB-06
// ---------------------------------------------------------------------------

/// A non-regular file is refused from its metadata, before a byte is read.
/// A directory is the one non-regular input every platform in CI has.
#[test]
fn non_regular_input_is_refused() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let r = run(&["--binary", dir.to_str().unwrap()]);
    assert_eq!(r.code, Some(1), "stderr: {}", r.stderr);
    assert!(r.stdout.trim().is_empty());
    assert!(
        r.stderr.contains("cannot read") && r.stderr.contains("directory"),
        "{}",
        r.stderr
    );
}

/// A regular file over `--max-file-size` is refused from its metadata, and
/// the message says how to allow it. The default cap is 512 MiB, so the
/// fixtures are unaffected.
#[test]
fn oversized_input_is_refused_before_it_is_read() {
    let bin = fixture("elf-Linux-x86");
    let bin = bin.to_str().unwrap();
    let len = std::fs::metadata(bin).unwrap().len();

    let refused = run(&["--binary", bin, "--max-file-size", "1024"]);
    assert_eq!(refused.code, Some(1), "{}", refused.stderr);
    assert!(refused.stdout.trim().is_empty());
    assert!(
        refused.stderr.contains(&len.to_string()) && refused.stderr.contains("max-file-size"),
        "{}",
        refused.stderr
    );

    // Exactly at the limit is allowed; the boundary is `>`, not `>=`.
    let allowed = run(&[
        "--binary",
        bin,
        "--depth",
        "10",
        "--max-file-size",
        &len.to_string(),
    ]);
    assert_eq!(allowed.code, Some(0), "{}", allowed.stderr);

    // Suffixes are DECIMAL scaled, never hex: `--max-file-size 1M` must be
    // 1 MiB, not 0x1M.
    let one_meg = run(&["--binary", bin, "--depth", "10", "--max-file-size", "1M"]);
    assert_eq!(one_meg.code, Some(0), "{}", one_meg.stderr);
    let sub_meg = run(&["--binary", bin, "--max-file-size", "700K"]);
    assert_eq!(sub_meg.code, Some(1), "700K < 773246 bytes must refuse");
}

// ---------------------------------------------------------------------------
// PERF-05
// ---------------------------------------------------------------------------

/// `--max-gadgets` stops the scan and says so, instead of silently
/// truncating a listing the user would read as complete.
#[test]
fn max_gadgets_stops_the_scan_visibly() {
    let bin = fixture("elf-Linux-x86");
    let bin = bin.to_str().unwrap();
    let r = run(&["--binary", bin, "--depth", "10", "--max-gadgets", "100"]);
    assert_eq!(r.code, Some(2), "{}", r.stderr);
    assert!(r.stderr.contains("budget"), "{}", r.stderr);
    assert!(
        !r.stdout.contains("Unique gadgets found"),
        "a budgeted-out run must not print a listing that looks complete"
    );

    // A budget larger than the answer changes nothing at all.
    let bounded = run(&["--binary", bin, "--depth", "10", "--max-memory", "2G"]);
    let plain = run(&["--binary", bin, "--depth", "10"]);
    assert_eq!(bounded.code, Some(0), "{}", bounded.stderr);
    assert_eq!(
        bounded.stdout, plain.stdout,
        "the bounded sink must be byte-identical while the budget is not hit"
    );
}

// ---------------------------------------------------------------------------
// CLI-11
// ---------------------------------------------------------------------------

/// `--noinstr` prints bare addresses (`core.py:110-111`: the oracle never
/// records `g["gadget"]` for a --noinstr scan, so `insts` is empty).
///
/// Before this, every one of the 68,386 --noinstr lines on elf-Linux-x86
/// carried a ` : <disassembly>` ROPgadget does not print.
#[test]
fn noinstr_prints_bare_addresses() {
    let bin = fixture("elf-Linux-x86");
    let bin = bin.to_str().unwrap();
    let r = run(&["--binary", bin, "--depth", "10", "--noinstr"]);
    assert_eq!(r.code, Some(0), "{}", r.stderr);
    let body: Vec<&str> = r
        .stdout
        .lines()
        .filter(|l| l.starts_with("0x"))
        .take(200)
        .collect();
    assert!(!body.is_empty());
    for l in &body {
        assert!(!l.contains(" : "), "--noinstr line carries text: {l}");
    }

    // ...and --noinstr --dump is `0xADDR // hexbytes`, still no text.
    let d = run(&["--binary", bin, "--depth", "10", "--noinstr", "--dump"]);
    for l in d.stdout.lines().filter(|l| l.starts_with("0x")).take(200) {
        assert!(!l.contains(" : "), "{l}");
        assert!(l.contains(" // "), "{l}");
    }

    // The normal path is unaffected.
    let n = run(&["--binary", bin, "--depth", "10"]);
    assert!(n
        .stdout
        .lines()
        .filter(|l| l.starts_with("0x"))
        .all(|l| l.contains(" : ")));
}
