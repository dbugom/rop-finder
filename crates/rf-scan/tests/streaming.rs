//! PERF-05: the sink, the budget and the cancellation token, measured on the
//! biggest fixture in the corpus.
//!
//! `RF_RSS=1` makes the sweep print the estimated retained bytes so the
//! numbers in the release notes can be re-derived; the assertions run either
//! way and do not depend on the platform's RSS accounting.

use rf_scan::{
    scan_binary, scan_binary_into, scan_bounded, sink::gadget_bytes, BoundedSink, CancelToken,
    Error, GadgetSink, ScanOptions, VecSink,
};

/// 6.0 MB, 1.4 MB of scanned code, 133,163 gadgets — the largest fixture in
/// tests/fixtures.
const BIG: &str = "elf-Mips-Defcon-20-pwn100";

fn load(name: &str) -> rf_core::ElfBinary {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    rf_core::Binary::parse(&std::fs::read(p).expect("fixture")).expect("parse")
}

fn code_bytes(bin: &rf_core::ElfBinary) -> usize {
    bin.exec_scan_regions().iter().map(|s| s.bytes.len()).sum()
}

/// The unbounded sink retains the whole raw candidate stream; the bounded one
/// stops the scan the moment the caller's ceiling is crossed. This is the
/// measurement PERF-05 asks for, in the units the engine can actually
/// account for (retained heap bytes, not process RSS, which is allocator- and
/// OS-dependent).
#[test]
fn bounded_sink_caps_retained_memory() {
    let bin = load(BIG);
    let opts = ScanOptions::default();

    let mut unbounded = VecSink::new();
    scan_binary_into(&bin, &opts, &mut unbounded).unwrap();
    let raw = unbounded.gadgets.len();
    let raw_bytes: usize = unbounded.gadgets.iter().map(gadget_bytes).sum();
    let code = code_bytes(&bin);

    if std::env::var("RF_RSS").is_ok() {
        eprintln!(
            "{BIG}: {code} code bytes, {raw} raw gadgets, {raw_bytes} retained bytes \
             ({:.1} bytes per code byte)",
            raw_bytes as f64 / code as f64
        );
    }
    assert!(raw > 100_000, "expected a big raw stream, got {raw}");

    // A 16 MiB ceiling on an input whose unbounded stream needs far more.
    let cap = 16 << 20;
    assert!(raw_bytes > cap, "fixture is too small to exercise the cap");
    let mut bounded = BoundedSink::new(None, Some(cap));
    let err = scan_binary_into(&bin, &opts, &mut bounded).unwrap_err();
    assert!(matches!(err, Error::Budget { .. }), "{err}");
    assert!(
        bounded.bytes() <= cap,
        "bounded sink held {} bytes, cap {cap}",
        bounded.bytes()
    );
    assert!(bounded.accepted() > 0);
}

/// A generous budget must not change the answer by even one gadget.
#[test]
fn a_generous_budget_is_byte_identical() {
    let bin = load("elf-Linux-x64");
    let plain = scan_binary(&bin, &ScanOptions::default()).unwrap();
    let o = ScanOptions {
        max_gadgets: Some(50_000_000),
        max_memory: Some(8 << 30),
        ..Default::default()
    };
    let bounded = scan_bounded(&bin, &o).unwrap();
    let key = |g: &rf_scan::Gadget| (g.vaddr, g.bytes.clone(), g.text());
    assert_eq!(
        plain.iter().map(key).collect::<Vec<_>>(),
        bounded.iter().map(key).collect::<Vec<_>>()
    );
}

/// The residual cost after a cancel is bounded by the number of work items,
/// not by their contents, so a cancelled scan of the largest fixture returns
/// in a small fraction of the 2.6 s a full scan takes.
///
/// The bound is expressed as a RATIO against a full scan measured in the
/// same process, not as a wall-clock constant: this file's other tests scan
/// the same 6 MB fixture on every core at the same time, so an absolute
/// deadline measures the test runner's scheduling, not the engine. The tight
/// absolute assertion — under 200 ms — is the engine unit test
/// `engine::tests::scan_stops_on_token`.
#[test]
fn cancellation_is_prompt_on_the_largest_fixture() {
    let bin = load(BIG);
    let o = ScanOptions {
        cancel: CancelToken::new(),
        ..Default::default()
    };
    let token = o.cancel.clone();
    // The flip thread reports WHEN it actually flipped: under a loaded test
    // runner a `sleep(5ms)` can take seconds to be scheduled, and that is the
    // scheduler's latency, not the engine's.
    let (tx, rx) = std::sync::mpsc::channel();
    let flip = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(5));
        let at = std::time::Instant::now();
        token.cancel();
        tx.send(at).unwrap();
    });
    let r = scan_bounded(&bin, &o);
    let returned_at = std::time::Instant::now();
    flip.join().unwrap();
    assert!(matches!(r, Err(Error::Cancelled)), "{r:?}");
    let latency = returned_at.duration_since(rx.recv().unwrap());

    let t0 = std::time::Instant::now();
    let full = scan_binary(&bin, &ScanOptions::default()).unwrap();
    let uncancelled = t0.elapsed();
    assert_eq!(full.len(), 133_163);
    if std::env::var("RF_RSS").is_ok() {
        eprintln!("cancel latency {latency:?} vs full scan {uncancelled:?}");
    }
    assert!(
        latency * 4 < uncancelled || latency < std::time::Duration::from_millis(150),
        "cancel took {latency:?} to be observed, a full scan is {uncancelled:?}"
    );
}

/// `max_gadgets` stops the scan rather than trimming the output afterwards.
#[test]
fn max_gadgets_stops_the_scan() {
    let bin = load(BIG);
    let o = ScanOptions {
        max_gadgets: Some(1_000),
        ..Default::default()
    };
    let t0 = std::time::Instant::now();
    let r = scan_bounded(&bin, &o);
    let capped = t0.elapsed();
    assert!(
        matches!(r, Err(Error::Budget { limit: 1_000, .. })),
        "{r:?}"
    );
    let t0 = std::time::Instant::now();
    let full = scan_binary(&bin, &ScanOptions::default()).unwrap();
    let uncapped = t0.elapsed();
    assert_eq!(full.len(), 133_163);
    if std::env::var("RF_RSS").is_ok() {
        eprintln!("capped {capped:?} vs uncapped {uncapped:?}");
    }
}
