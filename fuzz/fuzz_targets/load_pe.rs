//! PE loader target — `rf_core::PeBinary::parse` / `rf_core::Binary::load`.
//!
//! This is the target that catches ROB-02 (382 KB malformed PE -> 19.8 GB
//! RSS): pe.rs makes one owned byte copy per DECLARED section header, so a
//! cloned section table amplifies the input by ~54,000x. Run this target
//! with `-rss_limit_mb=512 -malloc_limit_mb=512` and libFuzzer reports the
//! amplifying input as an OOM with the reproducer written to artifacts/.
//! See fuzz/README.md, "Targets that are meant to go red today".
#![no_main]

use libfuzzer_sys::fuzz_target;
use rf_core::{Binary, Image, PeBinary};

fuzz_target!(|data: &[u8]| {
    if let Ok(pe) = PeBinary::parse(data) {
        let _ = Image::arch(&pe);
        let _ = Image::endianness(&pe);
        let _ = pe.exec_scan_regions().len();
        let _ = pe.exec_sections().len();
        let mut pe = pe;
        pe.rebase(0);
    }
    if data.starts_with(b"MZ") {
        let _ = Binary::load(data);
    }
});
