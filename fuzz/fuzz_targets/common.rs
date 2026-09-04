//! Shared knob decoding for the CLI-level fuzz targets.
//!
//! Design note (see fuzz/README.md, "Why the option byte is the LAST byte"):
//! the scan options are taken from the FINAL byte of the input, not the
//! first. That keeps every corpus file a valid standalone binary — you can
//! drop `tests/fixtures/elf-Linux-x86` into `corpus/cli_scan_bytes/`
//! unchanged, and `cargo fuzz run cli_scan_bytes <crasher>` reproduces on a
//! file you can also feed to `rop-finder --binary` and to ROPgadget. A
//! leading selector byte would shift every real binary by one byte and make
//! the whole corpus unusable as input to anything else.

#![allow(dead_code)]

use rf_api::{RawSpec, ScanRequest};
use rf_core::{Arch, Endianness};

/// Hard cap on the bytes handed to the scan pipeline.
///
/// This is a *time* bound, not a memory bound: it keeps a single libFuzzer
/// execution short enough that the fuzzer makes progress. It deliberately
/// does NOT bound memory — ROB-02's section-clone amplification turns a
/// 382 KB input into ~19.8 GB RSS, and we WANT that reported, which is why
/// the README pins `-rss_limit_mb=512 -malloc_limit_mb=512`.
pub const MAX_INPUT: usize = 1 << 20;

/// Depth is bounded to 2..=5. An unbounded `--depth` makes every non-trivial
/// input a libFuzzer timeout, and a fuzzer that only ever reports timeouts
/// learns nothing.
pub const MAX_DEPTH: usize = 5;

/// Split `data` into (binary bytes, option byte). Returns `None` for inputs
/// too short to carry both.
pub fn split_opts(data: &[u8]) -> Option<(&[u8], u8)> {
    if data.len() < 2 || data.len() > MAX_INPUT {
        return None;
    }
    let (body, tail) = data.split_at(data.len() - 1);
    Some((body, tail[0]))
}

/// Decode the option byte into a bounded [`ScanRequest`].
pub fn request_from(opt: u8) -> ScanRequest {
    ScanRequest {
        depth: 2 + usize::from(opt & 0x03),
        rop: true,
        jop: opt & 0x04 == 0,
        sys: opt & 0x08 == 0,
        multibr: opt & 0x10 != 0,
        all: opt & 0x20 != 0,
        call_preceded: opt & 0x40 != 0,
        cfg_aware: opt & 0x80 != 0,
        ..ScanRequest::default()
    }
}

/// Every architecture the raw loader accepts, so the option byte can steer
/// the capstone back end as well as the iced-x86 one. ENG-10's core
/// complaint is that nothing fuzzes the decode engine; this is the list that
/// fixes it.
pub const ARCHES: [Arch; 14] = [
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

/// Pick a raw-loader spec from the option byte's high nibble.
pub fn raw_spec_from(opt: u8) -> RawSpec {
    let arch = ARCHES[usize::from(opt >> 4) % ARCHES.len()];
    let endian = if opt & 0x08 == 0 {
        Endianness::Little
    } else {
        Endianness::Big
    };
    (arch, endian, opt & 0x04 != 0)
}
