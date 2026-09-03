//! Per-architecture scan throughput (CLAIM-02 / PERF-08).
//!
//! One benchmark per decode path, driven through the stable
//! `rf_scan::scan_binary(&view, &opts)` entry point at the oracle's default
//! flags (`--depth 10`, ROP+JOP+SYS). Throughput is reported in bytes of
//! executable code scanned per second, so the numbers are comparable across
//! architectures and across machines with different fixture sets.
//!
//! Serial (`parallel = false`) is benched alongside parallel on the two x86
//! fixtures: `CLAIM-01` measured only ~1.6x CPU utilisation on a 16-core
//! machine, and a criterion suite that only ever runs the parallel path cannot
//! see that ratio change.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use rf_bench::{load, Loaded, SCAN_CASES};
use rf_scan::{scan_binary, ScanOptions};

fn opts(parallel: bool) -> ScanOptions {
    ScanOptions {
        depth: 10,
        parallel,
        ..ScanOptions::default()
    }
}

fn bench_one(c: &mut Criterion, group_name: &str, parallel: bool, ids: Option<&[&str]>) {
    let mut group = c.benchmark_group(group_name);
    // A single scan of the larger fixtures is ~100 ms; criterion's default 100
    // samples would put this suite in the tens of minutes. Ten samples over
    // three seconds is enough to keep the confidence interval tight enough for
    // a 10% regression band.
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));

    for case in SCAN_CASES {
        if let Some(ids) = ids {
            if !ids.contains(&case.id) {
                continue;
            }
        }
        let loaded: Loaded = load(case.fixture);
        let image = loaded.image();
        let code = loaded.code_bytes();
        group.throughput(Throughput::Bytes(code));
        group.bench_with_input(BenchmarkId::from_parameter(case.id), &code, |b, _| {
            let o = opts(parallel);
            b.iter(|| {
                let g = scan_binary(black_box(image), black_box(&o)).expect("scan");
                black_box(g.len())
            });
        });
    }
    group.finish();
}

fn scan_parallel(c: &mut Criterion) {
    bench_one(c, "scan/parallel", true, None);
}

fn scan_serial(c: &mut Criterion) {
    bench_one(c, "scan/serial", false, Some(&["x86", "arm64"]));
}

criterion_group!(benches, scan_parallel, scan_serial);
criterion_main!(benches);
