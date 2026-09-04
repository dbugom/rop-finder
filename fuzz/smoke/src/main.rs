//! `rf-smoke` — the portable half of rop-finder's hostile-input testing.
//!
//! Why this exists
//! ---------------
//! ROB-08 / CLAIM-03 / ENG-10 ask for cargo-fuzz coverage of the loaders and
//! the scan pipeline. cargo-fuzz needs a nightly toolchain and libFuzzer;
//! this repository pins stable 1.89.0, and on `x86_64-pc-windows-msvc` the
//! instrumented binary additionally needs the MSVC ASan runtime DLL on PATH
//! or it dies at process start with STATUS_DLL_NOT_FOUND (see
//! fuzz/README.md §2). `fuzz/fuzz_targets/` therefore cannot be the only
//! artifact: on a machine where it will not run, PLAN's "zero panics on 10K
//! mutated binaries" exit criterion would still be an assertion with nothing
//! behind it.
//!
//! This binary is that something. It is a deterministic, seeded mutation
//! harness that runs on stable Rust on every platform, mutates the 24
//! fixtures in `tests/fixtures/` and asserts that `Binary::load`,
//! `info_bytes` and `scan_bytes` never panic. Every mutant is addressed by a
//! single integer, so `rf-smoke mutant <index>` reproduces byte for byte on
//! any machine.
//!
//! Process model
//! -------------
//! The parent splits the run into chunks and executes each chunk in a child
//! process. A panic is *caught* inside the child and reported without
//! stopping the run; anything a `catch_unwind` cannot catch — a hard abort,
//! a stack overflow, a C-side fault in capstone, or the allocation cap being
//! hit — kills only that child, and the parent then re-runs that chunk one
//! mutant at a time to name the exact input. That is deliberate: ROB-02's
//! section-clone amplification turns a small malformed PE into tens of
//! gigabytes of RSS, and a single-process harness would be OOM-killed with
//! nothing to show for it.
//!
//! Usage
//! -----
//! ```text
//! cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- run --count 10000
//! cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- mutant 4711
//! cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- amplify --format pe --clones 2000
//! cargo run --release --manifest-path fuzz/smoke/Cargo.toml -- seed-corpus
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rf_api::{RawSpec, ScanRequest};
use rf_core::{Arch, Binary, ElfBinary, Endianness, MachOBinary, PeBinary, UniversalBinary};

// ---------------------------------------------------------------------------
// Allocation cap: turn "the machine dies" into "this mutant is a finding".
// ---------------------------------------------------------------------------

struct Capped;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static CAP: AtomicUsize = AtomicUsize::new(usize::MAX);
static TRIPPED: AtomicBool = AtomicBool::new(false);

/// SAFETY: `alloc`/`dealloc` forward to `System` unchanged; the only added
/// behaviour is refusing an allocation that would take live bytes past the
/// cap, which is a legal `GlobalAlloc` response (null = allocation failed).
/// `realloc` and `alloc_zeroed` are deliberately NOT overridden so the
/// default implementations route through this `alloc`/`dealloc` pair and the
/// accounting stays exact.
unsafe impl GlobalAlloc for Capped {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let now = LIVE.fetch_add(size, Ordering::Relaxed) + size;
        if now > CAP.load(Ordering::Relaxed) {
            LIVE.fetch_sub(size, Ordering::Relaxed);
            report_cap(size, now);
            return std::ptr::null_mut();
        }
        PEAK.fetch_max(now, Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static ALLOCATOR: Capped = Capped;

/// Report a cap hit without allocating (we are inside the allocator).
fn report_cap(request: usize, would_be: usize) {
    if TRIPPED.swap(true, Ordering::SeqCst) {
        return;
    }
    let mut buf = [0u8; 160];
    let mut n = 0;
    let mut put = |bytes: &[u8], n: &mut usize| {
        for &b in bytes {
            if *n < buf.len() {
                buf[*n] = b;
                *n += 1;
            }
        }
    };
    put(b"MEMCAP request=", &mut n);
    let mut tmp = [0u8; 20];
    put(fmt_usize(request, &mut tmp), &mut n);
    put(b" live_would_be=", &mut n);
    let mut tmp2 = [0u8; 20];
    put(fmt_usize(would_be, &mut tmp2), &mut n);
    put(b"\n", &mut n);
    let _ = std::io::stderr().write_all(&buf[..n]);
}

fn fmt_usize(mut v: usize, buf: &mut [u8; 20]) -> &[u8] {
    if v == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut i = buf.len();
    while v > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let len = buf.len() - i;
    buf.copy_within(i.., 0);
    &buf[..len]
}

// ---------------------------------------------------------------------------
// Deterministic RNG: xorshift64* seeded through splitmix64. No `rand` crate,
// so a mutant index means the same bytes on every platform and every build.
// ---------------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(index: u64) -> Self {
        // splitmix64 finalizer, so adjacent indices are not correlated and
        // the state is never 0 (which would make xorshift degenerate).
        let mut z = index.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        Rng(if z == 0 { 0x2545_F491_4F6C_DD1D } else { z })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi.saturating_sub(lo).saturating_add(1))
    }
}

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// The 24 real binaries from `tests/fixtures/`, in sorted order. Hardcoded
/// rather than read from the directory so that mutant N is the same mutant
/// on every machine even if the directory gains a file.
const FIXTURES: [&str; 24] = [
    "Linux_lib32.so",
    "Linux_lib64.so",
    "UNIVERSAL-x86-x64-libSystem.B.dylib",
    "elf-ARM64-bash",
    "elf-ARMv7-ls",
    "elf-FreeBSD-x86",
    "elf-Linux-RISCV_32",
    "elf-Linux-RISCV_64",
    "elf-Linux-x64",
    "elf-Linux-x86",
    "elf-Linux-x86-NDH-chall",
    "elf-Mips-Defcon-20-pwn100",
    "elf-PPC64-bash",
    "elf-PowerPC-bash",
    "elf-SparcV8-bash",
    "elf-x64-bash-v4.1.5.1",
    "elf-x86-bash-v4.1.5.1",
    "macho-ppc-openssl",
    "macho-x64-ls",
    "macho-x86-ls",
    "pe-Windows-ARMv7-Thumb2LE-HelloWorld",
    "pe-x64-cmd-v6.1.7601",
    "pe-x86-cmd-v6.1.7600",
    "raw-x86.raw",
];

fn repo_root() -> PathBuf {
    // fuzz/smoke -> fuzz -> repo root
    let raw = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    match raw.canonicalize() {
        // Windows canonicalisation yields a `\\?\` verbatim path, which is
        // valid but unreadable in a report. Strip it for display; both forms
        // open the same files.
        Ok(c) => {
            let s = c.to_string_lossy().into_owned();
            PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s).to_string())
        }
        Err(_) => raw,
    }
}

fn fixture_dir() -> PathBuf {
    repo_root().join("tests/fixtures")
}

struct Fixtures {
    cache: HashMap<&'static str, Vec<u8>>,
}

impl Fixtures {
    fn new() -> Self {
        Fixtures {
            cache: HashMap::new(),
        }
    }

    fn get(&mut self, name: &'static str) -> &[u8] {
        self.cache.entry(name).or_insert_with(|| {
            let p = fixture_dir().join(name);
            std::fs::read(&p).unwrap_or_else(|e| {
                eprintln!("[fatal] cannot read fixture {}: {e}", p.display());
                std::process::exit(3);
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

/// Mutants whose index is a multiple of this are cut down to a header-sized
/// prefix before mutation, so the small-input paths get exercised too.
const PREFIX_EVERY: u64 = 4;
const PREFIX_LEN: usize = 64 * 1024;

/// Poison values written by the field-poke mutation. These are the constants
/// that break length/count/offset fields: zero, one, the signed and unsigned
/// boundaries, and a recognisable filler.
const POISON: [u64; 12] = [
    0,
    1,
    0x7f,
    0x80,
    0xff,
    0x7fff,
    0xffff,
    0x7fff_ffff,
    0xffff_ffff,
    0x4141_4141,
    0x7fff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];

/// Container magics, so a mutation can route an ELF's body into the PE or
/// Mach-O loader and vice versa.
const MAGICS: [[u8; 4]; 8] = [
    [0x7f, b'E', b'L', b'F'],
    [b'M', b'Z', 0x90, 0x00],
    [0xca, 0xfe, 0xba, 0xbe],
    [0xca, 0xfe, 0xba, 0xbf],
    [0xce, 0xfa, 0xed, 0xfe],
    [0xcf, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xce],
    [0xfe, 0xed, 0xfa, 0xcf],
];

/// The mutation kinds, in the order the `kind` selector picks them.
const KIND_NAMES: [&str; 8] = [
    "header-bitflip",
    "whole-file-bitflip",
    "truncate",
    "field-poke",
    "block-scramble",
    "append",
    "magic-swap",
    "splice",
];

struct Mutant {
    fixture: &'static str,
    kind: &'static str,
    bytes: Vec<u8>,
}

fn mutant(index: u64, fx: &mut Fixtures) -> Mutant {
    let mut rng = Rng::new(index);
    let fixture = FIXTURES[(index as usize) % FIXTURES.len()];
    let mut bytes = fx.get(fixture).to_vec();

    if index % PREFIX_EVERY == 0 && bytes.len() > PREFIX_LEN {
        bytes.truncate(PREFIX_LEN);
    }
    if bytes.is_empty() {
        bytes.push(0);
    }

    let kind = rng.below(KIND_NAMES.len());
    match kind {
        // 0: bit flips confined to the header region — the highest-yield
        // mutation for a parser, and the one the existing in-tree
        // `mutated_bytes_never_panic` tests do (256 flips, one fixture).
        0 => {
            let window = bytes.len().min(1024);
            for _ in 0..rng.range(1, 8) {
                let off = rng.below(window);
                bytes[off] ^= 1u8 << rng.below(8);
            }
        }
        // 1: bit flips anywhere, including inside code the decoder will run.
        1 => {
            for _ in 0..rng.range(1, 16) {
                let off = rng.below(bytes.len());
                bytes[off] ^= 1u8 << rng.below(8);
            }
        }
        // 2: truncation, biased towards short files.
        2 => {
            let len = bytes.len();
            let new_len = match rng.below(4) {
                0 => rng.below(len.min(256) + 1),
                1 => len / 2,
                2 => len.saturating_sub(rng.range(1, 64)),
                _ => rng.below(len),
            };
            bytes.truncate(new_len.max(1));
        }
        // 3: poison values into header fields at 1/2/4/8-byte widths.
        3 => {
            let window = bytes.len().min(4096);
            for _ in 0..rng.range(1, 6) {
                let width = 1usize << rng.below(4); // 1, 2, 4, 8
                if window <= width {
                    break;
                }
                let off = rng.below(window - width);
                let v = POISON[rng.below(POISON.len())];
                for (i, b) in v.to_le_bytes().iter().take(width).enumerate() {
                    bytes[off + i] = *b;
                }
            }
        }
        // 4: overwrite a run with noise.
        4 => {
            let run = rng.range(1, 256).min(bytes.len());
            let off = rng.below(bytes.len() - run + 1);
            for i in 0..run {
                bytes[off + i] = rng.byte();
            }
        }
        // 5: append trailing garbage (offsets that used to be past EOF now
        // resolve, which is how "clamped to file length" logic gets caught).
        5 => {
            for _ in 0..rng.range(1, 256) {
                bytes.push(rng.byte());
            }
        }
        // 6: swap the container magic, sending this body to a different
        // loader than the one that produced it.
        6 => {
            let m = MAGICS[rng.below(MAGICS.len())];
            for (i, b) in m.iter().enumerate() {
                if i < bytes.len() {
                    bytes[i] = *b;
                }
            }
        }
        // 7: splice two different fixtures together.
        _ => {
            let other_name = FIXTURES[rng.below(FIXTURES.len())];
            let cut = rng.below(bytes.len());
            let other = fx.get(other_name);
            let take = other.len().min(PREFIX_LEN);
            bytes.truncate(cut);
            bytes.extend_from_slice(&other[..take]);
        }
    }

    if bytes.is_empty() {
        bytes.push(0);
    }
    Mutant {
        fixture,
        kind: KIND_NAMES[kind],
        bytes,
    }
}

// ---------------------------------------------------------------------------
// The exercised surface
// ---------------------------------------------------------------------------

/// Bound on the executable bytes a mutant may present before we skip the
/// full scan. This is a TIME bound; the memory bound is the allocator cap.
const SCAN_EXEC_CAP: u64 = 256 * 1024;
/// Every Nth mutant is allowed a much bigger scan, so full-size real
/// binaries still get through the decode engine sometimes.
const BIG_SCAN_EVERY: u64 = 25;
const SCAN_EXEC_CAP_BIG: u64 = 8 * 1024 * 1024;
/// Bytes handed to the forced-raw scan (hostile bytes straight into
/// iced-x86 / capstone with no container in the way).
const RAW_SCAN_CAP: usize = 64 * 1024;
/// Bounded depth. Unbounded depth is why a naive fuzz target only ever
/// reports timeouts.
const DEPTH: usize = 3;

const ARCHES: [Arch; 14] = [
    Arch::X86,
    Arch::X64,
    Arch::Arm,
    Arch::ArmThumb,
    Arch::Arm64,
    Arch::Mips32,
    Arch::Mips64,
    Arch::Ppc32,
    Arch::Ppc64,
    Arch::Sparc,
    Arch::Sparc64,
    Arch::SparcV9,
    Arch::RiscV32,
    Arch::RiscV64,
];

fn raw_spec(index: u64) -> RawSpec {
    let arch = ARCHES[(index as usize) % ARCHES.len()];
    let endian = if index % 3 == 0 {
        Endianness::Big
    } else {
        Endianness::Little
    };
    (arch, endian, index % 5 == 0)
}

fn request() -> ScanRequest {
    ScanRequest {
        depth: DEPTH,
        ..ScanRequest::default()
    }
}

/// Coverage counters. A harness that reports "10,000 mutants, zero panics"
/// while every mutant bounced off a 4-byte magic check is worthless, so the
/// run reports how deep the inputs actually got.
mod stat {
    use std::sync::atomic::AtomicU64;
    pub static ELF_OK: AtomicU64 = AtomicU64::new(0);
    pub static PE_OK: AtomicU64 = AtomicU64::new(0);
    pub static MACHO_OK: AtomicU64 = AtomicU64::new(0);
    pub static UNIV_OK: AtomicU64 = AtomicU64::new(0);
    pub static LOAD_OK: AtomicU64 = AtomicU64::new(0);
    pub static INFO_OK: AtomicU64 = AtomicU64::new(0);
    pub static SCAN_AUTO: AtomicU64 = AtomicU64::new(0);
    pub static SCAN_RAW: AtomicU64 = AtomicU64::new(0);
    pub static GADGETS: AtomicU64 = AtomicU64::new(0);

    pub const NAMES: [&str; 9] = [
        "elf_parse_ok",
        "pe_parse_ok",
        "macho_parse_ok",
        "universal_parse_ok",
        "dispatch_load_ok",
        "info_bytes_ok",
        "scan_auto_ok",
        "scan_raw_ok",
        "gadgets_produced",
    ];

    pub fn all() -> [&'static AtomicU64; 9] {
        [
            &ELF_OK, &PE_OK, &MACHO_OK, &UNIV_OK, &LOAD_OK, &INFO_OK, &SCAN_AUTO, &SCAN_RAW,
            &GADGETS,
        ]
    }
}

fn bump(c: &std::sync::atomic::AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

/// Everything a hostile byte string is allowed to reach. Any panic here is
/// the finding this harness exists to produce.
fn exercise(index: u64, m: &[u8]) {
    // ---- loaders, direct (bypasses the magic dispatch) ----------------
    if ElfBinary::parse(m).is_ok() {
        bump(&stat::ELF_OK, 1);
    }
    if PeBinary::parse(m).is_ok() {
        bump(&stat::PE_OK, 1);
    }
    if MachOBinary::parse(m).is_ok() {
        bump(&stat::MACHO_OK, 1);
    }
    if UniversalBinary::parse(m).is_ok() {
        bump(&stat::UNIV_OK, 1);
    }
    // ---- loader dispatch ---------------------------------------------
    if Binary::load(m).is_ok() {
        bump(&stat::LOAD_OK, 1);
    }

    // ---- --info -------------------------------------------------------
    if rf_api::info_bytes(m, None, None).is_ok() {
        bump(&stat::INFO_OK, 1);
    }
    let _ = rf_api::info_bytes(m, None, Some(0));
    let _ = rf_api::info_bytes(m, None, Some(u64::MAX));
    let _ = rf_api::info_bytes(m, Some(raw_spec(index)), Some(0x4000_0000));

    // ---- full scan, when the exec extent is small enough to be quick --
    let cap = if index % BIG_SCAN_EVERY == 0 {
        SCAN_EXEC_CAP_BIG
    } else {
        SCAN_EXEC_CAP
    };
    if let Ok(target) = rf_api::load_target(m, None) {
        let view = rf_api::build_view(&target);
        let exec: u64 = view.regions.iter().map(|r| r.bytes.len() as u64).sum();
        if exec <= cap {
            if let Ok(out) = rf_api::scan_bytes(m, None, &request()) {
                bump(&stat::SCAN_AUTO, 1);
                bump(&stat::GADGETS, out.result.gadgets.len() as u64);
            }
        }
    }

    // ---- forced-raw scan: the decode engine on arbitrary bytes --------
    let head = &m[..m.len().min(RAW_SCAN_CAP)];
    if let Ok(out) = rf_api::scan_bytes(head, Some(raw_spec(index)), &request()) {
        bump(&stat::SCAN_RAW, 1);
        bump(&stat::GADGETS, out.result.gadgets.len() as u64);
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

static PANIC_MSG: Mutex<Option<String>> = Mutex::new(None);

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let mut slot = PANIC_MSG.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(info.to_string());
        }
    }));
}

fn escape(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' => '|',
            '\r' => ' ',
            '\t' => ' ',
            c => c,
        })
        .collect()
}

fn run_worker(start: u64, count: u64, cap_bytes: usize) -> i32 {
    CAP.store(cap_bytes, Ordering::Relaxed);
    install_panic_hook();
    let mut fx = Fixtures::new();
    let t0 = Instant::now();
    let mut worst = (0u64, 0usize);
    let mut panics = 0u64;

    for index in start..start + count {
        let m = mutant(index, &mut fx);
        let baseline = LIVE.load(Ordering::Relaxed);
        PEAK.store(baseline, Ordering::Relaxed);
        let started = Instant::now();

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            exercise(index, &m.bytes);
        }));

        let used = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
        if used > worst.1 {
            worst = (index, used);
        }
        let ms = started.elapsed().as_millis();
        if ms > 3000 {
            println!("SLOW {index} {} {} {ms}", m.fixture, m.kind);
        }
        if outcome.is_err() {
            panics += 1;
            let msg = PANIC_MSG
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .unwrap_or_else(|| "<no message captured>".to_string());
            println!(
                "PANIC {index} {} {} len={} {}",
                m.fixture,
                m.kind,
                m.bytes.len(),
                escape(&msg)
            );
            let _ = save_artifact(index, &m);
        }
        let _ = std::io::stdout().flush();
    }

    let mut done = format!(
        "DONE start={start} count={count} panics={panics} worst_index={} worst_bytes={} elapsed_ms={}",
        worst.0,
        worst.1,
        t0.elapsed().as_millis()
    );
    for (name, counter) in stat::NAMES.iter().zip(stat::all()) {
        done.push_str(&format!(" {name}={}", counter.load(Ordering::Relaxed)));
    }
    println!("{done}");
    if panics == 0 {
        0
    } else {
        1
    }
}

fn artifact_dir() -> PathBuf {
    repo_root().join("fuzz/artifacts/smoke")
}

fn save_artifact(index: u64, m: &Mutant) -> std::io::Result<PathBuf> {
    let dir = artifact_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("mutant-{index}-{}-{}.bin", m.fixture, m.kind));
    std::fs::write(&path, &m.bytes)?;
    Ok(path)
}

// ---------------------------------------------------------------------------
// Parent
// ---------------------------------------------------------------------------

struct Failure {
    index: u64,
    fixture: String,
    kind: String,
    detail: String,
}

#[allow(clippy::too_many_lines)]
fn run_parent(count: u64, chunk: u64, cap_mb: usize, timeout: Duration, start: u64) -> i32 {
    let exe = std::env::current_exe().expect("current_exe");
    let cap_bytes = cap_mb * 1024 * 1024;
    let mut executed = 0u64;
    let mut panics: Vec<Failure> = Vec::new();
    let mut hard: Vec<Failure> = Vec::new();
    let mut slow: Vec<String> = Vec::new();
    let mut worst = (0u64, 0usize);
    let mut totals = [0u64; stat::NAMES.len()];
    let t0 = Instant::now();

    let mut at = start;
    while at < start + count {
        let n = chunk.min(start + count - at);
        let res = spawn_worker(&exe, at, n, cap_bytes, chunk_timeout(timeout, n));
        match res {
            WorkerOutcome::Completed { stdout, .. } => {
                for line in stdout.lines() {
                    if let Some(rest) = line.strip_prefix("PANIC ") {
                        panics.push(parse_failure(rest));
                    } else if let Some(rest) = line.strip_prefix("SLOW ") {
                        slow.push(rest.to_string());
                    } else if let Some(rest) = line.strip_prefix("DONE ") {
                        if let Some(w) = parse_worst(rest) {
                            if w.1 > worst.1 {
                                worst = w;
                            }
                        }
                        for (i, name) in stat::NAMES.iter().enumerate() {
                            for tok in rest.split_whitespace() {
                                if let Some(v) = tok.strip_prefix(&format!("{name}=")) {
                                    totals[i] += v.parse::<u64>().unwrap_or(0);
                                }
                            }
                        }
                    }
                }
                executed += n;
            }
            WorkerOutcome::Died { status, stderr } => {
                eprintln!(
                    "[chunk {at}..{}] worker died ({status}); bisecting one mutant at a time",
                    at + n
                );
                if !stderr.trim().is_empty() {
                    eprintln!("[chunk stderr] {}", escape(stderr.trim()));
                }
                let mut fx = Fixtures::new();
                for index in at..at + n {
                    let single = spawn_worker(&exe, index, 1, cap_bytes, chunk_timeout(timeout, 1));
                    executed += 1;
                    match single {
                        WorkerOutcome::Completed { stdout, .. } => {
                            for line in stdout.lines() {
                                if let Some(rest) = line.strip_prefix("PANIC ") {
                                    panics.push(parse_failure(rest));
                                }
                            }
                        }
                        WorkerOutcome::Died { status, stderr } => {
                            let m = mutant(index, &mut fx);
                            let saved = save_artifact(index, &m)
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|e| format!("<save failed: {e}>"));
                            hard.push(Failure {
                                index,
                                fixture: m.fixture.to_string(),
                                kind: m.kind.to_string(),
                                detail: format!(
                                    "child terminated: {status}; len={}; stderr={}; artifact={saved}",
                                    m.bytes.len(),
                                    escape(stderr.trim())
                                ),
                            });
                        }
                    }
                }
            }
        }
        at += n;
    }

    println!();
    println!("================ rf-smoke summary ================");
    println!("mutants executed : {executed}");
    println!("fixtures         : {}", FIXTURES.len());
    println!("mutation kinds   : {}", KIND_NAMES.len());
    println!("scan depth       : {DEPTH}");
    println!("alloc cap        : {cap_mb} MiB per worker process");
    println!(
        "worst mutant     : index {} used {} bytes ({:.1} MiB)",
        worst.0,
        worst.1,
        worst.1 as f64 / (1024.0 * 1024.0)
    );
    println!("-- depth reached (how far the mutants actually got) --");
    for (name, total) in stat::NAMES.iter().zip(totals.iter()) {
        println!("{name:<20}: {total}");
    }
    println!("-- results --");
    println!("panics           : {}", panics.len());
    println!("hard failures    : {}", hard.len());
    println!("slow (>3 s)      : {}", slow.len());
    println!("elapsed          : {:.1} s", t0.elapsed().as_secs_f64());
    for f in &panics {
        println!(
            "  PANIC  index={} fixture={} kind={} :: {}",
            f.index, f.fixture, f.kind, f.detail
        );
    }
    for f in &hard {
        println!(
            "  HARD   index={} fixture={} kind={} :: {}",
            f.index, f.fixture, f.kind, f.detail
        );
    }
    for s in &slow {
        println!("  SLOW   {s}");
    }
    println!("=================================================");

    if panics.is_empty() && hard.is_empty() {
        0
    } else {
        1
    }
}

fn parse_failure(rest: &str) -> Failure {
    let mut it = rest.splitn(4, ' ');
    let index = it.next().unwrap_or("0").parse().unwrap_or(0);
    let fixture = it.next().unwrap_or("?").to_string();
    let kind = it.next().unwrap_or("?").to_string();
    let detail = it.next().unwrap_or("").to_string();
    Failure {
        index,
        fixture,
        kind,
        detail,
    }
}

fn parse_worst(rest: &str) -> Option<(u64, usize)> {
    let mut index = None;
    let mut bytes = None;
    for tok in rest.split_whitespace() {
        if let Some(v) = tok.strip_prefix("worst_index=") {
            index = v.parse().ok();
        } else if let Some(v) = tok.strip_prefix("worst_bytes=") {
            bytes = v.parse().ok();
        }
    }
    Some((index?, bytes?))
}

/// Wall-clock budget for a chunk: a fixed base (process start-up, the first
/// fixture read) plus a per-mutant allowance. This is a hang backstop, not a
/// performance gate — per-mutant slowness is reported as `SLOW` lines.
fn chunk_timeout(base: Duration, n: u64) -> Duration {
    base + Duration::from_secs(2) * u32::try_from(n).unwrap_or(u32::MAX)
}

enum WorkerOutcome {
    Completed { stdout: String },
    Died { status: String, stderr: String },
}

fn spawn_worker(
    exe: &Path,
    start: u64,
    count: u64,
    cap_bytes: usize,
    timeout: Duration,
) -> WorkerOutcome {
    let mut child = match Command::new(exe)
        .arg("worker")
        .arg(start.to_string())
        .arg(count.to_string())
        .arg(cap_bytes.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return WorkerOutcome::Died {
                status: format!("spawn failed: {e}"),
                stderr: String::new(),
            }
        }
    };

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let out = child.wait_with_output().ok();
                    return WorkerOutcome::Died {
                        status: format!("timeout after {:?}", timeout),
                        stderr: out
                            .map(|o| String::from_utf8_lossy(&o.stderr).into_owned())
                            .unwrap_or_default(),
                    };
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                return WorkerOutcome::Died {
                    status: format!("wait failed: {e}"),
                    stderr: String::new(),
                }
            }
        }
    }

    let out = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            return WorkerOutcome::Died {
                status: format!("wait_with_output failed: {e}"),
                stderr: String::new(),
            }
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    // Exit code 1 is "a panic was caught and reported" — the worker still
    // completed and its stdout is authoritative. Anything else is a hard
    // failure the worker could not describe itself.
    match out.status.code() {
        Some(0) | Some(1) => WorkerOutcome::Completed { stdout },
        other => WorkerOutcome::Died {
            status: match other {
                Some(c) => format!("exit code {c} (0x{:08x})", c as u32),
                None => "terminated by signal".to_string(),
            },
            stderr,
        },
    }
}

// ---------------------------------------------------------------------------
// `mutant` — reproduce one input by index
// ---------------------------------------------------------------------------

fn show_mutant(index: u64) -> i32 {
    let mut fx = Fixtures::new();
    let m = mutant(index, &mut fx);
    let path = save_artifact(index, &m);
    println!("index   : {index}");
    println!("fixture : {}", m.fixture);
    println!("kind    : {}", m.kind);
    println!("len     : {}", m.bytes.len());
    match path {
        Ok(p) => println!("written : {}", p.display()),
        Err(e) => println!("written : <failed: {e}>"),
    }
    print!("head    : ");
    for b in m.bytes.iter().take(64) {
        print!("{b:02x}");
    }
    println!();
    0
}

// ---------------------------------------------------------------------------
// `amplify` — build the ROB-02 witness and measure it
// ---------------------------------------------------------------------------

/// Build a PE whose section table is `clones` copies of the first section
/// header, by appending a fresh PE header at EOF and repointing `e_lfanew`.
/// This is the shape AUDIT-FINDINGS ROB-02 describes; it is generated rather
/// than committed so no new opaque binary enters the repository.
fn amplify_pe(base: &[u8], clones: u16) -> Option<Vec<u8>> {
    let mut out = base.to_vec();
    let e_lfanew = u32::from_le_bytes(out.get(0x3c..0x40)?.try_into().ok()?) as usize;
    let coff = e_lfanew + 4;
    let size_opt = u16::from_le_bytes(out.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    let nsec = u16::from_le_bytes(out.get(coff + 2..coff + 4)?.try_into().ok()?) as usize;
    let sec_tab = coff + 20 + size_opt;
    if nsec == 0 || out.len() < sec_tab + 40 {
        return None;
    }
    let header = out.get(e_lfanew..sec_tab)?.to_vec();
    let first_sec = out.get(sec_tab..sec_tab + 40)?.to_vec();

    // Align the new header to 8 bytes at EOF.
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let new_lfanew = out.len();
    out.extend_from_slice(&header);
    // Patch NumberOfSections in the copy we just appended.
    let new_coff = new_lfanew + 4;
    out[new_coff + 2..new_coff + 4].copy_from_slice(&clones.to_le_bytes());
    // Drop the symbol table and every data directory in the appended copy.
    // Their RVAs point into the ORIGINAL header's mapping, and goblin rejects
    // the whole file with "Cannot map base reloc rva ... into offset" before
    // it ever reaches the section loop — so without this the witness parses
    // as an error and measures nothing.
    out[new_coff + 8..new_coff + 16].copy_from_slice(&[0u8; 8]);
    let new_opt = new_coff + 20;
    let opt_magic = u16::from_le_bytes(out.get(new_opt..new_opt + 2)?.try_into().ok()?);
    // PE32 puts NumberOfRvaAndSizes at optional-header offset 92 (28 standard
    // + 68 windows-specific fields); PE32+ at 108 (24 + 84).
    let nrva_off = if opt_magic == 0x20b { 108 } else { 92 };
    if size_opt > nrva_off + 4 {
        out[new_opt + nrva_off..new_opt + nrva_off + 4].copy_from_slice(&0u32.to_le_bytes());
        for b in out
            .iter_mut()
            .skip(new_opt + nrva_off + 4)
            .take(size_opt - nrva_off - 4)
        {
            *b = 0;
        }
    }
    for _ in 0..clones {
        out.extend_from_slice(&first_sec);
    }
    out[0x3c..0x40].copy_from_slice(&(new_lfanew as u32).to_le_bytes());
    Some(out)
}

/// The ELF analogue: append `clones` copies of the first section header and
/// repoint `e_shoff` / `e_shnum`. 64-bit little-endian only (the fixture we
/// use is `elf-Linux-x64`).
fn amplify_elf(base: &[u8], clones: u16) -> Option<Vec<u8>> {
    let mut out = base.to_vec();
    if out.len() < 64 || out[4] != 2 || out[5] != 1 {
        return None;
    }
    let e_shoff = u64::from_le_bytes(out.get(0x28..0x30)?.try_into().ok()?) as usize;
    let e_shentsize = u16::from_le_bytes(out.get(0x3a..0x3c)?.try_into().ok()?) as usize;
    let e_shnum = u16::from_le_bytes(out.get(0x3c..0x3e)?.try_into().ok()?) as usize;
    if e_shentsize == 0 || e_shnum < 2 || out.len() < e_shoff + e_shentsize * e_shnum {
        return None;
    }
    // Clone the biggest existing section header (most bytes copied per entry).
    let mut best = (0usize, 0u64);
    for i in 0..e_shnum {
        let at = e_shoff + i * e_shentsize;
        let size = u64::from_le_bytes(out.get(at + 0x20..at + 0x28)?.try_into().ok()?);
        if size > best.1 {
            best = (at, size);
        }
    }
    let entry = out.get(best.0..best.0 + e_shentsize)?.to_vec();
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let new_shoff = out.len();
    // Entry 0 must stay SHT_NULL: `e_shstrndx` is cleared below and goblin
    // then reads section header 0 as the shdr string table. If that is a
    // clone of a code section the whole file is rejected with
    // "bad input invalid utf8" before any section content is materialised,
    // and the witness measures nothing.
    out.extend_from_slice(&vec![0u8; e_shentsize]);
    for _ in 1..clones {
        out.extend_from_slice(&entry);
    }
    out[0x28..0x30].copy_from_slice(&(new_shoff as u64).to_le_bytes());
    out[0x3c..0x3e].copy_from_slice(&clones.to_le_bytes());
    out[0x3e..0x40].copy_from_slice(&0u16.to_le_bytes());
    Some(out)
}

fn run_amplify(format: &str, clones: u16, cap_mb: usize, child: bool) -> i32 {
    if !child {
        // Run the measurement in a child so that blowing the cap is
        // observable instead of fatal.
        let exe = std::env::current_exe().expect("current_exe");
        let out = Command::new(exe)
            .arg("amplify-child")
            .arg(format)
            .arg(clones.to_string())
            .arg(cap_mb.to_string())
            .output();
        return match out {
            Ok(o) => {
                print!("{}", String::from_utf8_lossy(&o.stdout));
                let err = String::from_utf8_lossy(&o.stderr);
                if !err.trim().is_empty() {
                    println!("child stderr: {}", escape(err.trim()));
                }
                match o.status.code() {
                    Some(0) => 0,
                    Some(c) => {
                        println!(
                            "RESULT: child exited {c} (0x{:08x}) — the {cap_mb} MiB allocation cap \
                             was exceeded before the load completed.",
                            c as u32
                        );
                        1
                    }
                    None => {
                        println!("RESULT: child terminated by signal.");
                        1
                    }
                }
            }
            Err(e) => {
                println!("failed to spawn child: {e}");
                2
            }
        };
    }

    CAP.store(cap_mb * 1024 * 1024, Ordering::Relaxed);
    let mut fx = Fixtures::new();
    let (name, built) = match format {
        "pe" => (
            "pe-x86-cmd-v6.1.7600",
            amplify_pe(fx.get("pe-x86-cmd-v6.1.7600"), clones),
        ),
        "elf" => (
            "elf-Linux-x64",
            amplify_elf(fx.get("elf-Linux-x64"), clones),
        ),
        other => {
            println!("unknown format {other}; expected pe or elf");
            return 2;
        }
    };
    let Some(bytes) = built else {
        println!("could not build the {format} witness from {name}");
        return 2;
    };
    let dir = artifact_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("amplify-{format}-{clones}.bin"));
    let _ = std::fs::write(&path, &bytes);
    println!("witness      : {}", path.display());
    println!("input bytes  : {}", bytes.len());
    println!("clones       : {clones}");

    let baseline = LIVE.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let t0 = Instant::now();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match Binary::load(&bytes) {
            Ok(b) => {
                // Keep the loaded image alive across the measurement, and
                // report how many regions the amplification produced.
                let regions = match &b {
                    rf_core::LoadedBinary::Pe(p) => p.exec_scan_regions().len(),
                    rf_core::LoadedBinary::Elf(e) => e.exec_scan_regions().len(),
                    _ => 0,
                };
                let named = match &b {
                    rf_core::LoadedBinary::Pe(p) => p.exec_sections().len(),
                    rf_core::LoadedBinary::Elf(e) => e.sections().len(),
                    _ => 0,
                };
                format!("Ok (scan_regions={regions} sections={named})")
            }
            Err(e) => format!("Err({e})"),
        }
    }));
    let used = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    match &outcome {
        Ok(s) => println!("load result  : {s}"),
        Err(_) => println!("load result  : PANIC"),
    }
    println!("load panic   : {}", outcome.is_err());
    println!(
        "peak alloc   : {used} bytes ({:.1} MiB)",
        used as f64 / 1048576.0
    );
    println!(
        "amplification: {:.0}x input",
        used as f64 / bytes.len().max(1) as f64
    );
    println!("elapsed_ms   : {}", t0.elapsed().as_millis());
    0
}

// ---------------------------------------------------------------------------
// `seed-corpus` — populate fuzz/corpus/<target>/ from tests/fixtures
// ---------------------------------------------------------------------------

/// Bytes kept from each large fixture when seeding the committed corpus.
/// Small fixtures are copied whole. See fuzz/README.md, "The corpus".
const SEED_PREFIX: usize = 16 * 1024;
/// Fixtures at or below this size are copied in full.
const SEED_WHOLE_MAX: usize = 96 * 1024;

fn seed_corpus(full: bool) -> i32 {
    let targets: [(&str, &[&str]); 7] = [
        ("load_elf", &["elf-", "Linux_lib"]),
        ("load_pe", &["pe-"]),
        ("load_macho", &["macho-"]),
        ("load_universal", &["UNIVERSAL-"]),
        ("cli_info_bytes", &[""]),
        ("cli_scan_bytes", &[""]),
        ("cli_scan_raw", &["raw-", "elf-Linux-RISCV", "pe-Windows"]),
    ];
    let mut fx = Fixtures::new();
    let root = repo_root().join("fuzz/corpus");
    let mut written = 0usize;
    let mut bytes_written = 0usize;
    for (target, prefixes) in targets {
        let dir = root.join(target);
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("cannot create {}: {e}", dir.display());
            return 2;
        }
        for name in FIXTURES {
            if !prefixes.iter().any(|p| name.starts_with(p)) {
                continue;
            }
            let data = fx.get(name);
            // Small fixtures go in whole (a seed that does not parse teaches
            // the fuzzer nothing). Large ones are committed as a 16 KiB
            // header prefix and can be expanded locally with `--full`, which
            // names them `.full` so .gitignore keeps them out of the repo.
            let (keep, suffix) = if data.len() <= SEED_WHOLE_MAX {
                (data.len(), "")
            } else if full {
                (data.len(), ".full")
            } else {
                (SEED_PREFIX, ".prefix")
            };
            let out = dir.join(format!("{name}{suffix}"));
            if let Err(e) = std::fs::write(&out, &data[..keep]) {
                eprintln!("cannot write {}: {e}", out.display());
                return 2;
            }
            written += 1;
            bytes_written += keep;
        }
    }
    println!(
        "seeded {written} corpus files ({} KiB) under {}",
        bytes_written / 1024,
        root.display()
    );
    println!("(pass --full to copy whole fixtures for a long local run; those are gitignored)");
    0
}

// ---------------------------------------------------------------------------

fn usage() -> i32 {
    eprintln!(
        "rf-smoke — deterministic hostile-input smoke harness

  rf-smoke run [--count N] [--start S] [--chunk C] [--mem-cap-mb M] [--timeout-secs T]
  rf-smoke mutant <index>
  rf-smoke amplify [--format pe|elf] [--clones N] [--mem-cap-mb M]
  rf-smoke seed-corpus [--full]
  rf-smoke worker <start> <count> <cap-bytes>     (internal)
"
    );
    2
}

fn arg_val(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("run");
    let code = match cmd {
        "worker" => {
            let start = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            let count = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
            let cap = args
                .get(3)
                .and_then(|s| s.parse().ok())
                .unwrap_or(usize::MAX);
            run_worker(start, count, cap)
        }
        "mutant" => match args.get(1).and_then(|s| s.parse().ok()) {
            Some(i) => show_mutant(i),
            None => usage(),
        },
        "amplify" => run_amplify(
            &arg_val(&args, "--format").unwrap_or_else(|| "pe".to_string()),
            arg_val(&args, "--clones")
                .and_then(|s| s.parse().ok())
                .unwrap_or(2000),
            arg_val(&args, "--mem-cap-mb")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1024),
            false,
        ),
        "amplify-child" => run_amplify(
            args.get(1).map(String::as_str).unwrap_or("pe"),
            args.get(2).and_then(|s| s.parse().ok()).unwrap_or(2000),
            args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1024),
            true,
        ),
        "seed-corpus" => seed_corpus(args.iter().any(|a| a == "--full")),
        "run" | "--count" | "--start" | "--chunk" | "--mem-cap-mb" | "--timeout-secs" => {
            let count = arg_val(&args, "--count")
                .and_then(|s| s.parse().ok())
                .unwrap_or(10_000);
            let start = arg_val(&args, "--start")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let chunk = arg_val(&args, "--chunk")
                .and_then(|s| s.parse().ok())
                .unwrap_or(250);
            let cap_mb = arg_val(&args, "--mem-cap-mb")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1024);
            let secs: u64 = arg_val(&args, "--timeout-secs")
                .and_then(|s| s.parse().ok())
                .unwrap_or(20);
            run_parent(count, chunk, cap_mb, Duration::from_secs(secs), start)
        }
        _ => usage(),
    };
    std::process::exit(code);
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// FNV-1a, so the determinism test needs no hashing dependency.
    fn fnv(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in bytes {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }

    /// The whole artifact rests on "mutant N is the same bytes everywhere".
    /// Lock it: if a refactor changes the RNG, the mutation order, or the
    /// fixture list, every recorded reproducer index silently starts naming a
    /// different input, and this test is what stops that landing quietly.
    #[test]
    fn mutation_is_deterministic() {
        let mut fx = Fixtures::new();
        let mut sig = 0u64;
        for index in 0..64u64 {
            let m = mutant(index, &mut fx);
            sig ^= fnv(&m.bytes)
                .rotate_left((index % 61) as u32)
                .wrapping_add(index);
        }
        assert_eq!(
            sig, MUTATION_SIGNATURE,
            "mutant generation changed: every recorded reproducer index now names \
             a different input. If the change is intended, update MUTATION_SIGNATURE \
             and say so in the commit message."
        );
    }

    /// Same mutant index, twice, must be byte-identical.
    #[test]
    fn mutants_are_reproducible() {
        let mut a = Fixtures::new();
        let mut b = Fixtures::new();
        for index in [0u64, 1, 7, 23, 24, 4711] {
            let x = mutant(index, &mut a);
            let y = mutant(index, &mut b);
            assert_eq!(x.bytes, y.bytes, "mutant {index} is not reproducible");
            assert_eq!(x.fixture, y.fixture);
            assert_eq!(x.kind, y.kind);
        }
    }

    /// Every mutation kind must actually be reachable, or the harness is
    /// quietly testing fewer shapes than it claims.
    #[test]
    fn every_mutation_kind_is_reachable() {
        let mut fx = Fixtures::new();
        let mut seen = std::collections::HashSet::new();
        for index in 0..512u64 {
            seen.insert(mutant(index, &mut fx).kind);
        }
        for kind in KIND_NAMES {
            assert!(seen.contains(kind), "mutation kind {kind} never generated");
        }
    }

    /// Every fixture must be reachable too.
    #[test]
    fn every_fixture_is_used() {
        let mut fx = Fixtures::new();
        let mut seen = std::collections::HashSet::new();
        for index in 0..FIXTURES.len() as u64 {
            seen.insert(mutant(index, &mut fx).fixture);
        }
        assert_eq!(seen.len(), FIXTURES.len());
    }

    /// A fast in-process slice of the real run, so `cargo test` is a gate on
    /// its own. The full 10,000-mutant run is the binary — see fuzz/README.md.
    #[test]
    fn a_slice_of_mutants_never_panics() {
        let mut fx = Fixtures::new();
        for index in 0..FIXTURES.len() as u64 {
            let m = mutant(index, &mut fx);
            exercise(index, &m.bytes);
        }
    }
}

/// Signature of mutants 0..64, asserted by `mutation_is_deterministic`.
#[cfg(test)]
const MUTATION_SIGNATURE: u64 = 0x6375_c395_12fc_206d;
