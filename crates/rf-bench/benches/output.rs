//! Output rendering: ROPgadget-format text lines and the `--json` payload.
//!
//! The CLI's two output modes are the last thing between a finished scan and
//! the user, and both are pure string work over the whole gadget list
//! (`Gadget::text()` joins per-instruction strings; `bytes_hex()` formats two
//! characters per byte). On the larger fixtures that is tens of thousands of
//! allocations, which is exactly the kind of cost an end-to-end wall-clock
//! number hides inside "the scan".

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::fmt::Write as _;
use std::hint::black_box;

use rf_bench::load;
use rf_scan::{scan_binary, Gadget, ScanOptions};

const CASES: &[(&str, &str)] = &[
    ("x86", "elf-Linux-x86"),
    ("arm64", "elf-ARM64-bash"),
    ("pe-x64", "pe-x64-cmd-v6.1.7601"),
];

fn gadgets(fixture: &str) -> Vec<Gadget> {
    let loaded = load(fixture);
    let o = ScanOptions {
        depth: 10,
        ..ScanOptions::default()
    };
    scan_binary(loaded.image(), &o).expect("scan")
}

/// The human-readable mode: `0xVADDR : text`, one line per gadget.
fn render_text(gs: &[Gadget]) -> String {
    let mut out = String::with_capacity(gs.len() * 64);
    for g in gs {
        let _ = writeln!(out, "{:#010x} : {}", g.vaddr, g.text());
    }
    out
}

/// The `--json` mode: the same three fields rf-cli emits per gadget.
fn render_json(gs: &[Gadget]) -> String {
    let arr: Vec<serde_json::Value> = gs
        .iter()
        .map(|g| {
            serde_json::json!({
                "vaddr": format!("{:#010x}", g.vaddr),
                "bytes": g.bytes_hex(),
                "text": g.text(),
            })
        })
        .collect();
    serde_json::to_string(&arr).expect("serialize")
}

fn output(c: &mut Criterion) {
    for (mode, f) in [
        ("output/text", render_text as fn(&[Gadget]) -> String),
        ("output/json", render_json as fn(&[Gadget]) -> String),
    ] {
        let mut group = c.benchmark_group(mode);
        group.sample_size(20);
        group.measurement_time(std::time::Duration::from_secs(3));
        for (id, fixture) in CASES {
            let gs = gadgets(fixture);
            group.throughput(Throughput::Elements(gs.len() as u64));
            group.bench_with_input(BenchmarkId::from_parameter(id), &gs, |b, gs| {
                b.iter(|| black_box(f(black_box(gs)).len()));
            });
        }
        group.finish();
    }
}

criterion_group!(benches, output);
criterion_main!(benches);
