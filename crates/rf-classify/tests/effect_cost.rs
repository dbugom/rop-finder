//! What CLS-09's semantic layer costs, measured rather than asserted.
//!
//! `#[ignore]`d, prints to stdout, writes nothing:
//!
//! ```text
//! cargo test -p rf-classify --release --test effect_cost -- --ignored --nocapture
//! ```
//!
//! Two things make the cost small enough to pay unconditionally:
//!
//! * the analysis runs inside the classifier's existing decode loop and reads
//!   the same `InstructionInfo` that `effect_of` already asks the factory for,
//!   so it adds no decode and no second `factory.info()` call;
//! * `Vec::new()` does not allocate, so a gadget with no transfers, no sets
//!   and no clobbers — which is most of them — costs three null pointers.
//!
//! And classification is not on the scan path at all: `rf_scan` never calls
//! it, so a scan that is not classified pays nothing whatsoever. The figure
//! this prints is the marginal cost per *classified* gadget.

use std::path::{Path, PathBuf};
use std::time::Instant;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn scan(name: &str, depth: usize) -> (rf_core::Arch, Vec<rf_scan::Gadget>) {
    let path = repo_root().join("tests/fixtures").join(name);
    let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let opts = rf_scan::ScanOptions {
        depth,
        ..Default::default()
    };
    match rf_core::Binary::load(&data).unwrap() {
        rf_core::LoadedBinary::Elf(b) => (
            rf_core::Image::arch(&b),
            rf_scan::scan_binary(&b, &opts).unwrap(),
        ),
        other => panic!("{name}: unsupported container {other:?}"),
    }
}

#[test]
#[ignore = "measurement: prints timings, asserts nothing about wall time"]
fn classification_throughput() {
    for name in ["elf-x64-bash-v4.1.5.1", "elf-Linux-x64", "elf-Linux-x86"] {
        let t_scan = Instant::now();
        let (arch, gadgets) = scan(name, 10);
        let scan_time = t_scan.elapsed();
        let c = rf_classify::Classifier::new(arch);
        // Warm the thread-local decoder state.
        for g in gadgets.iter().take(1000) {
            std::hint::black_box(c.classify(g));
        }
        let t0 = Instant::now();
        let mut with_delta = 0usize;
        let mut with_transfers = 0usize;
        for g in &gadgets {
            let cl = c.classify(g);
            if cl.stack_delta.is_some() {
                with_delta += 1;
            }
            if !cl.transfers.is_empty() {
                with_transfers += 1;
            }
            std::hint::black_box(&cl);
        }
        let dt = t0.elapsed();
        println!(
            "{name}: scan {:?}; classify {} gadgets in {:?} ({:.0} ns/gadget, {:.1}% of the \
             scan); stack_delta on {} ({:.1}%), transfers on {} ({:.1}%)",
            scan_time,
            gadgets.len(),
            dt,
            dt.as_nanos() as f64 / gadgets.len() as f64,
            100.0 * dt.as_secs_f64() / scan_time.as_secs_f64(),
            with_delta,
            100.0 * with_delta as f64 / gadgets.len() as f64,
            with_transfers,
            100.0 * with_transfers as f64 / gadgets.len() as f64,
        );
    }
}
