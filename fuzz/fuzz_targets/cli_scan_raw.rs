//! `rf_cli::scan_bytes` through the RAW loader, one architecture per option
//! byte — the decode-engine target.
//!
//! `cli_scan_bytes` can only reach a decoder if the input still parses as a
//! container, so in practice it fuzzes x86/x64 (the fixtures that survive
//! mutation) and little else. Forcing the raw loader hands arbitrary bytes
//! straight to the anchor tables and the disassembler for all 14 supported
//! architectures, including the 12 that go through capstone's C code — the
//! "unsafe FFI into a large C disassembler being fed attacker-controlled
//! bytes" that ENG-11 flags and that nothing else in the tree exercises.
#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((body, opt)) = common::split_opts(data) else {
        return;
    };
    let req = common::request_from(opt);
    let _ = rf_cli::scan_bytes(body, Some(common::raw_spec_from(opt)), &req);
});
