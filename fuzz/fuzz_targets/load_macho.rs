//! Mach-O loader target — `rf_core::MachOBinary::parse` / `Binary::load`.
//!
//! Also drives `image_base()`, which is CORE-02's home (min vmaddr over all
//! LC_SEGMENTs is always __PAGEZERO), and `rebase`, which is arithmetic on
//! attacker-controlled vmaddrs.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rf_core::{Binary, Image, MachOBinary};

const MAGICS: [[u8; 4]; 4] = [
    [0xce, 0xfa, 0xed, 0xfe],
    [0xcf, 0xfa, 0xed, 0xfe],
    [0xfe, 0xed, 0xfa, 0xce],
    [0xfe, 0xed, 0xfa, 0xcf],
];

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = MachOBinary::parse(data) {
        let _ = Image::arch(&m);
        let _ = Image::endianness(&m);
        let _ = m.image_base();
        let _ = m.exec_scan_regions().len();
        let _ = m.exec_sections().len();
        let mut m = m;
        m.rebase(0);
    }
    if data.len() >= 4 && MAGICS.iter().any(|mg| data.starts_with(mg)) {
        let _ = Binary::load(data);
    }
});
