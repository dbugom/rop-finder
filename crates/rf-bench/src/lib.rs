//! Shared fixture plumbing for the criterion benches (CLAIM-02 / PERF-08).
//!
//! `benches/` used to be an empty directory: PLAN.md made "criterion bench
//! recorded against the clean baseline" a Phase 0 exit criterion, and no
//! `criterion` dependency existed anywhere in the workspace, so every
//! performance number in README/MANUAL/dist was unreproducible and no
//! mechanism could catch a regression. This crate is that instrument.
//!
//! Benches drive the STABLE entry point [`rf_scan::scan_binary`] over
//! [`rf_core::Image`], so they keep compiling while the engine's internals are
//! reshaped.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use rf_core::{Binary, Image, LoadedBinary, RawBinary};

/// Absolute path to `tests/fixtures`, resolved from this crate's manifest so
/// it works regardless of the directory `cargo bench` is invoked from.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
}

pub fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// A loaded fixture, owned so a bench can borrow an `&dyn Image` from it.
pub enum Loaded {
    Real(LoadedBinary),
    Raw(RawBinary),
}

impl Loaded {
    pub fn image(&self) -> &dyn Image {
        match self {
            Loaded::Real(LoadedBinary::Elf(b)) => b,
            Loaded::Real(LoadedBinary::Pe(b)) => b,
            Loaded::Real(LoadedBinary::MachO(b)) => b,
            Loaded::Real(LoadedBinary::Universal(_)) => {
                unreachable!("universal fixtures are not benched: no Image impl")
            }
            Loaded::Real(LoadedBinary::Raw(b)) => b,
            Loaded::Raw(b) => b,
        }
    }

    /// Total executable bytes actually walked — the denominator for a
    /// throughput number that means something across architectures.
    pub fn code_bytes(&self) -> u64 {
        self.image()
            .exec_scan_regions()
            .iter()
            .map(|s| s.bytes.len() as u64)
            .sum()
    }
}

pub fn load(name: &str) -> Loaded {
    let bytes = fixture_bytes(name);
    Loaded::Real(Binary::load(&bytes).unwrap_or_else(|e| panic!("load {name}: {e}")))
}

/// One benched fixture: the name criterion reports it under, and the file.
pub struct Case {
    pub id: &'static str,
    pub fixture: &'static str,
}

/// Per-architecture coverage. One fixture per decode path, chosen small enough
/// that a full criterion run finishes in minutes rather than hours: the point
/// is a stable ratio against a committed baseline, not a leaderboard.
///
/// `elf-Mips-Defcon-20-pwn100` is deliberately absent — it is the slowest
/// fixture in the corpus by an order of magnitude (5.6 s in the oracle) and
/// would dominate the wall-clock cost of the whole suite; MIPS throughput is
/// covered by the parity harness's timing column instead.
pub const SCAN_CASES: &[Case] = &[
    Case {
        id: "x86",
        fixture: "elf-Linux-x86",
    },
    Case {
        id: "x64",
        fixture: "elf-Linux-x64",
    },
    Case {
        id: "arm64",
        fixture: "elf-ARM64-bash",
    },
    Case {
        id: "armv7",
        fixture: "elf-ARMv7-ls",
    },
    Case {
        id: "ppc32",
        fixture: "elf-PowerPC-bash",
    },
    Case {
        id: "ppc64",
        fixture: "elf-PPC64-bash",
    },
    Case {
        id: "sparc",
        fixture: "elf-SparcV8-bash",
    },
    Case {
        id: "riscv64",
        fixture: "elf-Linux-RISCV_64",
    },
    Case {
        id: "pe-x64",
        fixture: "pe-x64-cmd-v6.1.7601",
    },
    Case {
        id: "macho-x64",
        fixture: "macho-x64-ls",
    },
];
