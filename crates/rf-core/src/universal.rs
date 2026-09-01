//! Universal (fat Mach-O) loading via goblin.
//!
//! Mirrors ROPgadget's `loaders/universal.py`: each fat-arch entry is carved
//! out and parsed as its own Mach-O (universal.py:66-75), and scanning
//! happens per-slice (universal.py:77-81 — `getExecSections` concatenates
//! every slice's exec sections). rop-finder keeps the slices separate so the
//! scanner can pick one architecture explicitly.
//!
//! Conscious deviations:
//! - ROPgadget only accepts little-endian slice magics (universal.py:71);
//!   goblin parses big-endian slices too, and we accept them.
//! - Unusable entries (non-Mach-O archives, corrupt slices) are skipped and
//!   counted, mirroring universal.py:74 which prints an error and continues;
//!   a fat binary with zero usable slices is an error.
//! - goblin 0.10 does not support the 64-bit fat magic `cafebabf`; such
//!   files are detected as Universal by [`crate::Binary::detect`] but fail
//!   here with a structured error.

use crate::macho::MachOBinary;
use crate::{Arch, Error};

/// A fat Mach-O ("Universal") container: one [`MachOBinary`] per
/// architecture slice.
#[derive(Debug)]
pub struct UniversalBinary {
    slices: Vec<MachOBinary>,
    /// Fat-arch entries that were skipped (archive or unparseable).
    skipped: usize,
}

impl UniversalBinary {
    /// Parse a fat Mach-O container, returning a structured error on
    /// malformed input.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let multi = goblin::mach::MultiArch::new(bytes)?;
        let arches = multi.arches()?;

        let mut slices = Vec::with_capacity(arches.len());
        let mut skipped = 0usize;
        for fat_arch in &arches {
            // FatArch::slice is bounds-checked (returns empty on overflow).
            let slice = fat_arch.slice(bytes);
            match goblin::mach::MachO::parse(slice, 0) {
                Ok(macho) => match MachOBinary::from_goblin(&macho, slice) {
                    Ok(bin) => slices.push(bin),
                    // e.g. a slice with an unsupported cputype.
                    Err(_) => skipped += 1,
                },
                Err(_) => skipped += 1,
            }
        }

        if slices.is_empty() {
            return Err(Error::Malformed(format!(
                "universal binary has {} entries but no usable Mach-O slice",
                arches.len()
            )));
        }

        Ok(UniversalBinary { slices, skipped })
    }

    /// All usable slices, in fat-arch order.
    pub fn slices(&self) -> &[MachOBinary] {
        &self.slices
    }

    /// Number of fat-arch entries skipped because they were not parseable
    /// Mach-O slices (universal.py:74).
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// Architectures of all usable slices, in fat-arch order.
    pub fn arches(&self) -> Vec<Arch> {
        self.slices.iter().map(|s| s.arch()).collect()
    }

    /// Get the slice for `arch`, if present.
    pub fn get(&self, arch: Arch) -> Option<&MachOBinary> {
        self.slices.iter().find(|s| s.arch() == arch)
    }

    /// ROPgadget parity: concatenated executable scan regions of every
    /// slice (universal.py:77-81). The scanner normally picks one slice via
    /// [`get`](Self::get); this exists for parity debugging.
    pub fn all_exec_scan_regions(&self) -> Vec<&crate::Section> {
        self.slices
            .iter()
            .flat_map(|s| s.exec_scan_regions().iter())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixture_path(name)).expect("fixture should exist")
    }

    #[test]
    fn parses_real_universal() {
        let bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let bin = UniversalBinary::parse(&bytes).expect("should parse");
        assert_eq!(bin.skipped(), 0);
        // Slices come in fat-arch (file) order; this fixture lists x86_64
        // first. Assert membership, not order.
        let arches = bin.arches();
        assert_eq!(arches.len(), 2);
        assert!(arches.contains(&Arch::X86));
        assert!(arches.contains(&Arch::X64));

        let x86 = bin.get(Arch::X86).expect("x86 slice");
        assert!(!x86.is_64());
        assert!(!x86.exec_scan_regions().is_empty());
        let x64 = bin.get(Arch::X64).expect("x64 slice");
        assert!(x64.is_64());
        assert!(!x64.exec_scan_regions().is_empty());
        assert!(bin.get(Arch::Arm64).is_none());

        // universal.py:77-81 — concatenated exec regions over all slices.
        let all = bin.all_exec_scan_regions();
        assert_eq!(
            all.len(),
            x86.exec_scan_regions().len() + x64.exec_scan_regions().len()
        );
    }

    #[test]
    fn truncations_never_panic() {
        let bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        for n in 0..=512usize.min(bytes.len()) {
            let _ = UniversalBinary::parse(&bytes[..n]);
        }
        // ~200 coarse truncation lengths over the whole file.
        let step = (bytes.len() / 200).max(1);
        for n in (512..bytes.len()).step_by(step) {
            let _ = UniversalBinary::parse(&bytes[..n]);
        }
    }

    #[test]
    fn mutated_bytes_never_panic() {
        let bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        // Bit-flip mutations across the fat header and arch table.
        for i in 0..256usize.min(bytes.len()) {
            let mut m = bytes.clone();
            m[i] ^= 0xff;
            let _ = UniversalBinary::parse(&m);
        }
        // Pseudo-random single-byte flips across the rest of the file.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..200 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let idx = (state >> 33) as usize % bytes.len();
            let mut m = bytes.clone();
            m[idx] ^= (state >> 11) as u8 | 1;
            let _ = UniversalBinary::parse(&m);
        }
    }

    #[test]
    fn garbage_returns_err_not_panic() {
        assert!(UniversalBinary::parse(b"").is_err());
        assert!(UniversalBinary::parse(b"\xca\xfe\xba\xbe").is_err());
        assert!(UniversalBinary::parse(&[0u8; 64]).is_err());
        // Valid fat magic, absurd nfat_arch.
        let mut g = vec![0u8; 64];
        g[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        g[4..8].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        let _ = UniversalBinary::parse(&g); // must not panic
    }
}
