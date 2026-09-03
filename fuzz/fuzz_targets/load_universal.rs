//! Universal (fat Mach-O) loader target — `rf_core::UniversalBinary::parse`.
//!
//! The fat header is a count plus N (offset, size) triples read straight out
//! of the file, which is the classic amplification/overflow shape; and
//! CORE-03/CORE-05 (slice selection, FAT_MAGIC_64) both live here.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rf_core::{Binary, Image, UniversalBinary};

fuzz_target!(|data: &[u8]| {
    if let Ok(u) = UniversalBinary::parse(data) {
        let _ = u.skipped();
        let _ = u.arches();
        let _ = u.all_exec_scan_regions().len();
        for arch in u.arches() {
            if let Some(s) = u.get(arch) {
                let _ = Image::endianness(s);
                let _ = s.image_base();
                let _ = s.exec_scan_regions().len();
            }
        }
    }
    if data.starts_with(&[0xca, 0xfe, 0xba, 0xbe]) || data.starts_with(&[0xca, 0xfe, 0xba, 0xbf]) {
        let _ = Binary::load(data);
    }
});
