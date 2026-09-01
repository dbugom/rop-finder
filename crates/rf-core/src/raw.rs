//! Raw (flat blob) loading.
//!
//! Mirrors ROPgadget's `loaders/raw.py`: the whole blob is a single
//! executable section named "raw" at vaddr 0 (raw.py:32-33); arch, mode and
//! endianness are supplied by the caller (`--rawArch`/`--rawMode`/
//! `--rawEndian`), never detected.

use crate::{Arch, Endianness, Section};

/// A flat blob treated as one executable region (ROPgadget `--rawArch`).
#[derive(Debug)]
pub struct RawBinary {
    arch: Arch,
    endianness: Endianness,
    /// Load address assigned by [`rebase`](Image::rebase); 0 by default
    /// (raw.py:33, `vaddr: 0x0`).
    base: u64,
    section: Section,
}

impl RawBinary {
    /// Wrap `bytes` as a raw image for `arch`/`endianness`.
    pub fn new(bytes: &[u8], arch: Arch, endianness: Endianness) -> Self {
        RawBinary {
            arch,
            endianness,
            base: 0,
            section: Section {
                name: "raw".to_string(),
                vaddr: 0,
                offset: 0,
                size: bytes.len() as u64,
                bytes: bytes.to_vec(),
                executable: true,
                writable: false,
            },
        }
    }

    /// The single synthetic "raw" section (raw.py:32-33).
    pub fn section(&self) -> &Section {
        &self.section
    }

    /// Raw blobs load at 0 unless rebased (raw.py:33, `vaddr: 0x0`).
    pub fn image_base(&self) -> u64 {
        self.base
    }

    /// Entry point 0 (raw.py:29-30).
    pub fn entry(&self) -> u64 {
        0
    }
}

impl crate::Image for RawBinary {
    fn arch(&self) -> Arch {
        self.arch
    }

    fn endianness(&self) -> Endianness {
        self.endianness
    }

    fn image_base(&self) -> u64 {
        self.base
    }

    fn entry(&self) -> u64 {
        0
    }

    fn exec_sections(&self) -> Vec<&Section> {
        vec![&self.section]
    }

    fn exec_scan_regions(&self) -> &[Section] {
        std::slice::from_ref(&self.section)
    }

    /// Rebase shifts the single section's vaddr and the image base; entry
    /// stays 0 (raw.py:29-30 — a raw blob has no entry point).
    fn rebase(&mut self, new_base: u64) {
        self.base = new_base;
        self.section.vaddr = new_base;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Image;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    #[test]
    fn wraps_blob_as_single_raw_section() {
        let bytes = std::fs::read(fixture_path("raw-x86.raw")).expect("fixture");
        let bin = RawBinary::new(&bytes, Arch::X86, Endianness::Little);
        assert_eq!(bin.arch(), Arch::X86);
        assert_eq!(bin.endianness(), Endianness::Little);
        assert_eq!(bin.image_base(), 0);
        assert_eq!(bin.entry(), 0);
        let sec = bin.section();
        assert_eq!(sec.name, "raw");
        assert_eq!(sec.vaddr, 0);
        assert_eq!(sec.offset, 0);
        assert_eq!(sec.size, bytes.len() as u64);
        assert_eq!(sec.bytes, bytes);
        assert!(sec.executable);
        assert_eq!(bin.exec_scan_regions().len(), 1);
        assert_eq!(bin.exec_sections().len(), 1);
    }

    #[test]
    fn empty_blob_is_fine() {
        let bin = RawBinary::new(b"", Arch::Arm64, Endianness::Big);
        assert_eq!(bin.section().size, 0);
        assert!(bin.section().bytes.is_empty());
    }

    #[test]
    fn rebase_moves_section_vaddr_and_base() {
        let mut bin = RawBinary::new(b"\x90\x90\xc3", Arch::X64, Endianness::Little);
        bin.rebase(0x1000);
        assert_eq!(bin.section().vaddr, 0x1000);
        assert_eq!(bin.image_base(), 0x1000);
        assert_eq!(bin.entry(), 0);
    }
}
