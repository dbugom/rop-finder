//! The decode phase on its own, and its parallel scaling (PERF-03/04/09).
//!
//! `scan_throughput` benches `scan_binary`, which is decode **plus**
//! dedup/filter/sort. That is the right end-to-end number and the wrong one
//! for this phase: v0.5's engine work made the decode 2-3x cheaper while
//! `post_process` stayed roughly where it was, and in an end-to-end mean the
//! second hides the first. This target drives `scan_binary_into` with a
//! `VecSink`, so the number moves only when the scan moves.
//!
//! The serial rows are not decoration either. PERF-04's exit criterion is a
//! *ratio* — parallel against single-threaded on the MIPS fixture — so both
//! halves have to be recorded per commit or the ratio cannot be checked
//! after the fact.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use rf_bench::{load, Loaded};
use rf_scan::{scan_binary_into, ScanOptions, VecSink};

/// One fixture per decode path that Phase 6 changed, plus the MIPS fixture
/// the scaling criterion names. `elf-Mips-Defcon-20-pwn100` is deliberately
/// included here even though `scan_throughput` skips it: it is the fixture
/// the >= 8x scaling gate is written against.
const CASES: &[(&str, &str)] = &[
    ("x64", "elf-x64-bash-v4.1.5.1"),
    ("x86", "elf-Linux-x86"),
    ("arm64", "elf-ARM64-bash"),
    ("ppc32", "elf-PowerPC-bash"),
    ("mips", "elf-Mips-Defcon-20-pwn100"),
    ("sparc", "elf-SparcV8-bash"),
];

fn opts(parallel: bool) -> ScanOptions {
    ScanOptions {
        depth: 10,
        parallel,
        ..ScanOptions::default()
    }
}

fn bench(c: &mut Criterion, group_name: &str, parallel: bool) {
    let mut group = c.benchmark_group(group_name);
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(3));
    for (id, fixture) in CASES {
        let loaded: Loaded = load(fixture);
        let image = loaded.image();
        group.throughput(Throughput::Bytes(loaded.code_bytes()));
        group.bench_function(BenchmarkId::from_parameter(id), |b| {
            let o = opts(parallel);
            b.iter(|| {
                let mut sink = VecSink::new();
                scan_binary_into(black_box(image), black_box(&o), &mut sink).expect("scan");
                black_box(sink.into_inner().len())
            });
        });
    }
    group.finish();
}

fn decode_parallel(c: &mut Criterion) {
    bench(c, "decode/parallel", true);
}

fn decode_serial(c: &mut Criterion) {
    bench(c, "decode/serial", false);
}

criterion_group!(benches, decode_parallel, decode_serial);
criterion_main!(benches);
