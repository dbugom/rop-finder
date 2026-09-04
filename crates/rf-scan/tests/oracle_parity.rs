//! Parity measurement against the ROPgadget reference dumps.
//!
//! The heavy sweep is opt-in through environment variables so that a plain
//! `cargo test -p rop-finder-scan` stays fast and needs no oracle checkout:
//!
//!   * `RF_DUMP_DIR=<dir>` — write `<fixture>.tsv` (`key<TAB>text`, key =
//!     `0x{vaddr:0width$x}|{hex bytes}`, exactly the key the oracle harness
//!     builds from `ROPgadget --dump` output) for every fixture.
//!   * `RF_ONE=<fixture>` — restrict the sweep to one fixture.
//!
//! The always-on tests in this file are the absolute oracle-matched counts
//! from the Phase 2 exit criteria on `tests/fixtures/elf-Linux-x86`. They are
//! driven through the ENGINE directly (`scan_binary` / `scan_binary_with`)
//! because rf-cli does not yet expose `--align`, `--filter` as a regex, or
//! `--callPreceded`; wiring those flags is the next wave's work.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use rf_scan::{scan_binary, Gadget, ScanOptions};

use rf_core::{Arch, Endianness, Image, LoadedBinary, RawBinary, Section};

/// An owned, format-agnostic [`Image`] so the harness can scan every fixture
/// (including fat Mach-O, whose slices are merged the way rf-cli merges them)
/// without depending on rf-cli.
pub struct HarnessImage {
    arch: Arch,
    endian: Endianness,
    base: u64,
    regions: Vec<Section>,
}

impl Image for HarnessImage {
    fn arch(&self) -> Arch {
        self.arch
    }
    fn endianness(&self) -> Endianness {
        self.endian
    }
    fn image_base(&self) -> u64 {
        self.base
    }
    fn entry(&self) -> u64 {
        0
    }
    fn exec_sections(&self) -> Vec<&Section> {
        self.regions.iter().collect()
    }
    fn exec_scan_regions(&self) -> &[Section] {
        &self.regions
    }
    fn rebase(&mut self, _new_base: u64) {}
}

pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

/// Fixtures the oracle harness dumps (everything but the two metadata files).
pub fn fixture_names() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(fixtures_dir())
        .expect("fixtures dir")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "MANIFEST.sha256" && n != "PROVENANCE.md")
        .collect();
    v.sort();
    v
}

pub fn load(name: &str) -> HarnessImage {
    let bytes = std::fs::read(fixtures_dir().join(name)).expect("fixture");
    // The oracle passes --rawArch=x86 --rawMode=32 for the raw blob.
    if name == "raw-x86.raw" {
        let raw = RawBinary::new(&bytes, Arch::X86, Endianness::Little);
        return HarnessImage {
            arch: raw.arch(),
            endian: raw.endianness(),
            base: raw.image_base(),
            regions: raw.exec_scan_regions().to_vec(),
        };
    }
    let loaded = rf_core::Binary::load(&bytes).expect("load");
    match loaded {
        LoadedBinary::Universal(u) => {
            let first = &u.slices()[0];
            HarnessImage {
                arch: first.arch(),
                endian: first.endianness(),
                base: first.image_base(),
                regions: u.all_exec_scan_regions().into_iter().cloned().collect(),
            }
        }
        other => {
            let img: &dyn Image = match &other {
                LoadedBinary::Elf(b) => b,
                LoadedBinary::Pe(b) => b,
                LoadedBinary::MachO(b) => b,
                LoadedBinary::Raw(b) => b,
                LoadedBinary::Universal(_) => unreachable!(),
            };
            HarnessImage {
                arch: img.arch(),
                endian: img.endianness(),
                base: img.image_base(),
                regions: img.exec_scan_regions().to_vec(),
            }
        }
    }
}

/// `0x{vaddr:0{2*addr_size}x}|{hex}` — the oracle harness's key.
pub fn key(g: &Gadget, addr_size: usize) -> String {
    let w = addr_size * 2;
    format!("0x{:0w$x}|{}", g.vaddr, g.bytes_hex(), w = w)
}

pub fn keyed(gadgets: &[Gadget], addr_size: usize) -> HashMap<String, String> {
    gadgets
        .iter()
        .map(|g| (key(g, addr_size), g.text()))
        .collect()
}

/// Opt-in sweep: dump every fixture's (vaddr, bytes) → text map to
/// `$RF_DUMP_DIR/<fixture>.tsv`. No-op (and no cost) when unset.
#[test]
fn dump_all_fixtures() {
    let Ok(dir) = std::env::var("RF_DUMP_DIR") else {
        return;
    };
    std::fs::create_dir_all(&dir).expect("dump dir");
    let only = std::env::var("RF_ONE").ok();
    for name in fixture_names() {
        if let Some(o) = &only {
            if o != &name {
                continue;
            }
        }
        let img = load(&name);
        let t0 = std::time::Instant::now();
        let g = scan_binary(&img, &ScanOptions::default()).expect("scan");
        let dt = t0.elapsed();
        let addr_size = img.addr_size();
        let mut f = std::io::BufWriter::new(
            std::fs::File::create(Path::new(&dir).join(format!("{name}.tsv"))).expect("create"),
        );
        for g in &g {
            writeln!(f, "{}\t{}", key(g, addr_size), g.text()).expect("write");
        }
        f.flush().expect("flush");
        eprintln!(
            "DUMP {name}: {} gadgets in {:.2}s",
            g.len(),
            dt.as_secs_f64()
        );
    }
}
