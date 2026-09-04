//! The two invariants Phase 6's engine work rests on (PERF-03, PERF-04).
//!
//! Both changes are meant to be *behaviour-preserving*, so neither has an
//! observable output to assert on directly. What they do have is a stated
//! reason they are safe, and these tests pin those reasons:
//!
//!  * PERF-03 deleted the per-start decode cache AND stopped decoding the
//!    full `depth*align + MAX_ANCHOR_SIZE` window, decoding only as far as
//!    the candidate's `end`. That is sound only because a decode is
//!    left-to-right and stops at the first byte it cannot consume, so the
//!    boundaries at or before `end` do not depend on what follows. If a
//!    future decoder change ever made a window's early boundaries depend on
//!    later bytes, every gadget on that architecture would silently move.
//!  * PERF-04 cut the work list into hit slices whose count depends on
//!    `rayon::current_num_threads()`. The dedup survivor — and therefore the
//!    emitted (vaddr, bytes) set — depends on traversal order, so a partition
//!    that reorders is a parity regression, not a scheduling detail.

use rayon::ThreadPoolBuilder;
use rf_core::Binary;
use rf_scan::{cs, scan_binary, x86, ScanOptions};

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read(p).expect("fixture")
}

/// PERF-03, x86 half: truncating the window at `end` yields exactly the
/// prefix of the long window that ends at or before `end`.
#[test]
fn x86_decode_window_is_a_prefix_of_any_longer_window() {
    let bytes = fixture("elf-Linux-x86");
    let bin = Binary::parse(&bytes).expect("parse");
    let sec = &bin.exec_scan_regions()[0];
    let code = &sec.bytes;
    let vaddr = sec.vaddr;
    // Every 37th offset over the first 256 KB: dense enough to cover both
    // real code and the data that follows it, cheap enough for a unit test.
    let mut checked = 0usize;
    for start in (0..code.len().min(256 * 1024)).step_by(37) {
        let long = x86::decode_window(code, start, vaddr, 32, start + 64);
        for end in [start + 1, start + 4, start + 11, start + 30] {
            if end > code.len() {
                continue;
            }
            let short = x86::decode_window(code, start, vaddr, 32, end);
            let want: Vec<usize> = long.iter().map(|w| w.end).filter(|&e| e <= end).collect();
            let got: Vec<usize> = short.iter().map(|w| w.end).collect();
            assert_eq!(got, want, "start={start} end={end}");
            checked += 1;
        }
    }
    assert!(checked > 10_000, "only {checked} windows compared");
}

/// PERF-03, capstone half: same lemma, on a variable-width mode (Thumb),
/// which is the one where it could plausibly fail.
#[test]
fn capstone_decode_window_is_a_prefix_of_any_longer_window() {
    let bytes = fixture("elf-ARMv7-ls");
    let bin = Binary::parse(&bytes).expect("parse");
    let sec = &bin.exec_scan_regions()[0];
    let code = &sec.bytes;
    let vaddr = sec.vaddr;
    for thumb in [false, true] {
        let spec = cs::spec(rf_core::Arch::Arm, rf_core::Endianness::Little, thumb).expect("spec");
        let cs = cs::open(&spec).expect("open");
        for start in (0..code.len()).step_by(13) {
            let long = cs::decode_window(&cs, code, start, vaddr, start + 48);
            for end in [start + 2, start + 4, start + 12, start + 24] {
                if end > code.len() {
                    continue;
                }
                let short = cs::decode_window(&cs, code, start, vaddr, end);
                let want: Vec<usize> = long.iter().map(|w| w.end).filter(|&e| e <= end).collect();
                let got: Vec<usize> = short.iter().map(|w| w.end).collect();
                assert_eq!(got, want, "thumb={thumb} start={start} end={end}");
            }
        }
    }
}

/// PERF-04: the number of work items is derived from the rayon pool size, so
/// running the same scan in pools of different widths partitions it
/// differently. Every partition must produce the identical listing — same
/// gadgets, same addresses, same order — because the text-dedup survivor is
/// chosen by traversal order.
#[test]
fn partition_width_does_not_change_the_listing() {
    let opts = ScanOptions {
        depth: 10,
        ..ScanOptions::default()
    };
    for name in [
        "elf-Linux-x86",             // iced-x86 path, 74 anchors
        "elf-ARM64-bash",            // capstone fixed-width path + region index
        "elf-Mips-Defcon-20-pwn100", // one anchor holds 92% of the hits
        "elf-Linux-RISCV_64",        // capstone variable-width path (no index)
    ] {
        let bytes = fixture(name);
        let bin = Binary::parse(&bytes).expect("parse");
        let mut serial = opts.clone();
        serial.parallel = false;
        let want = scan_binary(&bin, &serial).expect("serial scan");
        let want: Vec<(u64, Vec<u8>, String)> = want
            .iter()
            .map(|g| (g.vaddr, g.bytes.clone(), g.text()))
            .collect();

        for threads in [1usize, 2, 3, 7, 16] {
            let pool = ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .expect("pool");
            let got = pool.install(|| scan_binary(&bin, &opts).expect("parallel scan"));
            let got: Vec<(u64, Vec<u8>, String)> = got
                .iter()
                .map(|g| (g.vaddr, g.bytes.clone(), g.text()))
                .collect();
            assert_eq!(
                got.len(),
                want.len(),
                "{name} at {threads} threads: gadget count moved"
            );
            assert!(
                got == want,
                "{name} at {threads} threads: the listing differs from the serial scan"
            );
        }
    }
}
