//! Post-processing: text dedup, filters and the alphabetical sort.
//!
//! `post_process` is the second half of every scan and the part `--all`
//! switches off (SCAN-07/CLI-03), so it gets its own baseline: a change that
//! makes dedup cheaper but scanning slower — or the reverse — is invisible in
//! an end-to-end number and obvious here.
//!
//! The input is produced once with `all = true` (dedup skipped), so each
//! iteration sees the same undeduplicated gadget list the real pipeline hands
//! to `post_process`.

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use rf_bench::load;
use rf_scan::{post_process, scan_binary, Gadget, ScanOptions};

const CASES: &[(&str, &str)] = &[
    ("x86", "elf-Linux-x86"),
    ("x64", "elf-Linux-x64"),
    ("arm64", "elf-ARM64-bash"),
    ("pe-x64", "pe-x64-cmd-v6.1.7601"),
];

fn raw_gadgets(fixture: &str) -> (Vec<Gadget>, usize) {
    let loaded = load(fixture);
    let image = loaded.image();
    let o = ScanOptions {
        depth: 10,
        all: true, // skip dedup: we want post_process's real input
        ..ScanOptions::default()
    };
    let g = scan_binary(image, &o).expect("scan");
    (g, image.addr_size())
}

fn dedup(c: &mut Criterion) {
    let mut group = c.benchmark_group("post_process/dedup");
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(3));

    for (id, fixture) in CASES {
        let (gadgets, addr_size) = raw_gadgets(fixture);
        group.throughput(Throughput::Elements(gadgets.len() as u64));
        let o = ScanOptions::default();
        group.bench_with_input(BenchmarkId::from_parameter(id), &gadgets, |b, g| {
            b.iter_batched(
                || g.clone(),
                |input| {
                    black_box(
                        post_process(input, black_box(&o), addr_size)
                            .expect("post_process")
                            .len(),
                    )
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn sort_only(c: &mut Criterion) {
    // `--all` keeps the alphabetical sort but drops the HashSet pass; the delta
    // between this and the group above is the cost of dedup itself.
    let mut group = c.benchmark_group("post_process/sort_only");
    group.sample_size(20);
    group.measurement_time(std::time::Duration::from_secs(3));

    for (id, fixture) in CASES {
        let (gadgets, addr_size) = raw_gadgets(fixture);
        group.throughput(Throughput::Elements(gadgets.len() as u64));
        let o = ScanOptions {
            all: true,
            ..ScanOptions::default()
        };
        group.bench_with_input(BenchmarkId::from_parameter(id), &gadgets, |b, g| {
            b.iter_batched(
                || g.clone(),
                |input| {
                    black_box(
                        post_process(input, black_box(&o), addr_size)
                            .expect("post_process")
                            .len(),
                    )
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, dedup, sort_only);
criterion_main!(benches);
