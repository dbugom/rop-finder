//! `probe` — the engine's own before/after instrument (Phase 6, PERF-03/04/09/10).
//!
//! Criterion gives a committed baseline with confidence intervals; it is the
//! wrong tool for "is this change byte-identical?" and for "what does this
//! phase cost with `RAYON_NUM_THREADS` pinned?". This binary answers exactly
//! those two questions and nothing else:
//!
//! * `digest` — a 128-bit fingerprint of the gadget stream, either the FINAL
//!   post-processed output or the RAW pre-dedup traversal stream (`--raw`).
//!   An optimization that changes either number is a behaviour change, and
//!   the raw digest is order-sensitive, so it also catches a partitioning
//!   change that silently reorders the dedup survivors.
//! * `time` — best-of-N wall clock for one pipeline PHASE (`scan`, `post`,
//!   `full`), so the decode phase can be measured without the dedup/sort
//!   phase moving underneath it.
//! * `alloc` — allocation counts around `post_process`, available when the
//!   crate is built with `--features alloc-count` (PERF-10 exit criterion).
//!
//! Usage:
//!   cargo run --release -p rf-bench --bin probe -- digest [--raw] [--depth N] [--serial] [FIXTURE..]
//!   cargo run --release -p rf-bench --bin probe -- time scan|post|full FIXTURE [--runs N] [--serial]
//!   cargo run --release -p rf-bench --features alloc-count --bin probe -- alloc FIXTURE

use std::time::Instant;

use rf_bench::{fixtures_dir, load, Loaded};
use rf_scan::{post_process, scan_binary_into, CancelToken, Gadget, ScanOptions, VecSink};

// ---------------------------------------------------------------------------
// allocation counting (PERF-10 exit criterion)
// ---------------------------------------------------------------------------
#[cfg(feature = "alloc-count")]
mod counting {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub static ALLOCS: AtomicUsize = AtomicUsize::new(0);
    pub static BYTES: AtomicUsize = AtomicUsize::new(0);

    /// Counts every allocation that reaches the global allocator. There is no
    /// heap profiler on this host (no valgrind/massif; dhat wants a profiler
    /// this target does not have), so the exit criterion "zero per-gadget
    /// temporary String allocations in post_process" is discharged by
    /// counting instead of profiling: run `post_process` over N gadgets and
    /// read the delta.
    pub struct Counting;

    // SAFETY: every method forwards verbatim to the System allocator and only
    // adds two relaxed counter updates; no pointer is created, freed or
    // reinterpreted here.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(l.size(), Ordering::Relaxed);
            System.alloc(l)
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            System.dealloc(p, l)
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(new, Ordering::Relaxed);
            System.realloc(p, l, new)
        }
    }
}

#[cfg(feature = "alloc-count")]
#[global_allocator]
static A: counting::Counting = counting::Counting;

// ---------------------------------------------------------------------------
// digest
// ---------------------------------------------------------------------------
/// 128-bit FNV-1a (two independent 64-bit lanes with different constants).
/// Not a cryptographic hash and not meant to be: it exists to answer "did the
/// gadget stream change at all", where an accidental collision between two
/// builds of the same program is not a realistic failure mode.
#[derive(Clone, Copy)]
struct Fnv128 {
    a: u64,
    b: u64,
}

impl Fnv128 {
    fn new() -> Self {
        Fnv128 {
            a: 0xcbf2_9ce4_8422_2325,
            b: 0x9e37_79b9_7f4a_7c15,
        }
    }
    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.a = (self.a ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3);
            self.b = (self.b ^ byte as u64).wrapping_mul(0x0000_0100_0000_01b3);
            self.b = self.b.rotate_left(7);
        }
    }
    fn finish(&self) -> String {
        format!("{:016x}{:016x}", self.a, self.b)
    }
}

fn digest_gadgets(gadgets: &[Gadget]) -> String {
    let mut h = Fnv128::new();
    for g in gadgets {
        h.write(&g.vaddr.to_le_bytes());
        h.write(&g.bytes);
        h.write(b"|");
        for (i, ins) in g.insns.iter().enumerate() {
            if i > 0 {
                h.write(b" ; ");
            }
            h.write(ins.as_bytes());
        }
        h.write(b"\n");
    }
    h.finish()
}

// ---------------------------------------------------------------------------
// pipeline phases
// ---------------------------------------------------------------------------
fn opts(depth: usize, parallel: bool) -> ScanOptions {
    ScanOptions {
        depth,
        parallel,
        cancel: CancelToken::never(),
        ..ScanOptions::default()
    }
}

/// Raw traversal-order stream: the SCAN phase only, no dedup/filter/sort.
fn raw_scan(loaded: &Loaded, o: &ScanOptions) -> Vec<Gadget> {
    let mut sink = VecSink::new();
    scan_binary_into(loaded.image(), o, &mut sink).expect("scan");
    sink.into_inner()
}

/// The v0.4.0 `post_process` dedup+sort, kept verbatim as the control for
/// PERF-10.
///
/// The engine's own history is not runnable side by side with the current
/// build, so the thing being replaced is reimplemented here instead: a
/// joined `String` per gadget as the key, a `clone` of it into the
/// `HashSet`, and a sort over `(String, Gadget)` pairs. Only the two steps
/// PERF-10 changed are reproduced; the post-dedup filters between them are
/// untouched by this work and are no-ops at default options.
fn post_legacy(all: Vec<Gadget>) -> Vec<Gadget> {
    use std::collections::HashSet;
    let mut keyed: Vec<(String, Gadget)> = all.into_iter().map(|g| (g.text(), g)).collect();
    let mut seen: HashSet<String> = HashSet::new();
    keyed.retain(|(text, _)| seen.insert(text.clone()));
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.into_iter().map(|(_, g)| g).collect()
}

fn all_fixtures() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .expect("fixtures dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "MANIFEST.sha256" && n != "PROVENANCE.md")
        .collect();
    names.sort();
    names
}

/// Fixtures the sweep skips rather than panicking on: a fat Mach-O has no
/// single `Image`, and a headerless blob needs an explicit `--rawArch` that
/// only the CLI supplies. Both are covered by `tests/parity.py`.
fn skipped(name: &str) -> bool {
    name.starts_with("UNIVERSAL-") || name.ends_with(".raw")
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| argv.iter().any(|a| a == name);
    let value = |name: &str, default: usize| -> usize {
        argv.iter()
            .position(|a| a == name)
            .and_then(|i| argv.get(i + 1))
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let positional: Vec<String> = {
        let mut out = Vec::new();
        let mut skip = false;
        for (i, a) in argv.iter().enumerate() {
            if skip {
                skip = false;
                continue;
            }
            if a == "--depth" || a == "--runs" {
                skip = true;
                continue;
            }
            if a.starts_with("--") || i == 0 {
                continue; // a flag, or the subcommand itself
            }
            out.push(a.clone());
        }
        out
    };

    let depth = value("--depth", 10);
    let runs = value("--runs", 3);
    let parallel = !flag("--serial");
    let teardown = flag("--teardown");
    let o = opts(depth, parallel);

    match argv.first().map(|s| s.as_str()) {
        Some("digest") => {
            let names: Vec<String> = if positional.is_empty() {
                all_fixtures()
            } else {
                positional.clone()
            };
            let raw = flag("--raw");
            println!(
                "# depth={depth} parallel={parallel} mode={}",
                if raw { "raw" } else { "final" }
            );
            for name in names {
                if skipped(&name) {
                    continue;
                }
                let loaded = load(&name);
                let gadgets = if raw {
                    raw_scan(&loaded, &o)
                } else {
                    let addr = loaded.image().addr_size();
                    post_process(raw_scan(&loaded, &o), &o, addr).expect("post_process")
                };
                println!("{name}\t{}\t{}", gadgets.len(), digest_gadgets(&gadgets));
            }
        }
        Some("hits") => {
            // PERF-04 diagnostics: the anchor-hit distribution is the work
            // distribution, and `find_matches` is the one phase that runs
            // before any partitioning can help.
            use rf_scan::anchors;
            let name = positional.first().expect("hits FIXTURE");
            let loaded = load(name);
            let image = loaded.image();
            let arch = image.arch();
            let endian = image.endianness();
            let mut total = 0usize;
            let mut worst = (0usize, String::new());
            let mut elapsed = 0f64;
            for sec in image.exec_scan_regions() {
                for kind in [
                    rf_scan::TableKind::Rop,
                    rf_scan::TableKind::Jop,
                    rf_scan::TableKind::Sys,
                ] {
                    for a in anchors::table(kind, arch, endian, false) {
                        let t0 = Instant::now();
                        let h = anchors::find_matches(&sec.bytes, &a);
                        elapsed += t0.elapsed().as_secs_f64();
                        total += h.len();
                        if h.len() > worst.0 {
                            worst = (h.len(), a.name.to_string());
                        }
                    }
                }
            }
            println!(
                "{name}\thits={total}\tbiggest_anchor={}({})\tshare={:.1}%\tfind_matches={elapsed:.4}s",
                worst.1,
                worst.0,
                100.0 * worst.0 as f64 / total.max(1) as f64
            );
        }
        Some("time") => {
            let phase = positional
                .first()
                .map(|s| s.as_str())
                .expect("time PHASE FIXTURE");
            let name = positional.get(1).expect("time PHASE FIXTURE");
            let loaded = load(name);
            let addr = loaded.image().addr_size();
            let mut best = f64::MAX;
            let mut count = 0usize;
            // `post` times only post_process, so its input is produced once.
            let pre = if phase == "post" || phase == "post-legacy" {
                let mut a = o.clone();
                a.all = true;
                Some(raw_scan(&loaded, &a))
            } else {
                None
            };
            for _ in 0..runs {
                // The result vector is bound, not dropped, before the clock
                // is read: freeing 324k gadgets (three heap blocks each) is
                // ~120 ms of serial allocator work on this host, and folding
                // that into every phase would flatten the parallel-scaling
                // ratio the release is judged on. Teardown is real but it is
                // not the scan.
                // The `post` phase's input is cloned OUTSIDE the clock:
                // copying 324k gadgets and their strings costs several times
                // what post_process does, and timing it would report the
                // allocator rather than the dedup.
                let input = pre.clone();
                let t0 = Instant::now();
                let held = match phase {
                    "scan" => raw_scan(&loaded, &o),
                    "post" => post_process(input.expect("prepared"), &o, addr).expect("post"),
                    "post-legacy" => post_legacy(input.expect("prepared")),
                    "full" => post_process(raw_scan(&loaded, &o), &o, addr).expect("post"),
                    other => panic!("unknown phase {other}"),
                };
                count = held.len();
                if teardown {
                    // `--teardown` keeps the result vector's destruction
                    // inside the clock, which is the convention the v0.4.0
                    // baseline in this workstream was first measured with.
                    drop(held);
                    best = best.min(t0.elapsed().as_secs_f64());
                } else {
                    best = best.min(t0.elapsed().as_secs_f64());
                    drop(held);
                }
            }
            let threads = std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".into());
            println!(
                "{name}\tphase={phase}\tparallel={parallel}\tthreads={threads}\tdepth={depth}\tbest_of_{runs}={best:.4}s\tgadgets={count}"
            );
        }
        #[cfg(feature = "alloc-count")]
        Some("alloc") => {
            use std::sync::atomic::Ordering;
            let name = positional.first().expect("alloc FIXTURE");
            let loaded = load(name);
            let addr = loaded.image().addr_size();
            let mut a = o.clone();
            a.all = true;
            let input = raw_scan(&loaded, &a);
            let n = input.len();
            let control = input.clone();
            let a0 = counting::ALLOCS.load(Ordering::Relaxed);
            let b0 = counting::BYTES.load(Ordering::Relaxed);
            let out = post_process(input, &o, addr).expect("post");
            let a1 = counting::ALLOCS.load(Ordering::Relaxed);
            let b1 = counting::BYTES.load(Ordering::Relaxed);
            // The v0.4.0 dedup+sort over the same input, for the ratio.
            let l0 = counting::ALLOCS.load(Ordering::Relaxed);
            let legacy = post_legacy(control);
            let l1 = counting::ALLOCS.load(Ordering::Relaxed);
            assert_eq!(out.len(), legacy.len(), "the control must dedup the same");
            println!(
                "{name}\tin={n}\tout={}\tallocs={}\t/gadget={:.4}\tbytes={}\t| v0.4.0 allocs={}\t/gadget={:.4}",
                out.len(),
                a1 - a0,
                (a1 - a0) as f64 / n as f64,
                b1 - b0,
                l1 - l0,
                (l1 - l0) as f64 / n as f64,
            );
        }
        other => {
            eprintln!("unknown subcommand {other:?}; see the module docs");
            std::process::exit(2);
        }
    }
}
