//! ELF loader target — `rf_core::ElfBinary::parse` / `rf_core::Binary::load`.
//!
//! Closes the ELF half of ROB-08. `ElfBinary::parse` is called directly so
//! the fuzzer does not spend its budget rediscovering the 4-byte magic;
//! `Binary::load` is additionally driven whenever the magic survives, which
//! is what exercises the dispatcher's routing (binary.rs:68).
#![no_main]

use libfuzzer_sys::fuzz_target;
use rf_core::{Binary, ElfBinary, Image};

fuzz_target!(|data: &[u8]| {
    if let Ok(elf) = ElfBinary::parse(data) {
        // Reach past `parse` into the accessors the CLI actually calls: a
        // panic in arch mapping or rebasing is just as fatal as one in the
        // parser, and `arch()` is where CORE-01 lives.
        let _ = elf.arch();
        let _ = Image::endianness(&elf);
        let _ = elf.exec_scan_regions().len();
        let _ = elf.exec_sections().len();
        let mut elf = elf;
        elf.rebase(0);
        elf.rebase(u64::MAX);
    }
    if data.starts_with(b"\x7fELF") {
        let _ = Binary::load(data);
    }
});
