//! `rf_api::scan_bytes` target at BOUNDED depth — the whole pipeline.
//!
//! options -> load -> view -> rf_scan::scan_binary -> post_process. This is
//! the target that finally puts the decode engine (iced-x86 for x86/x64,
//! capstone for everything else) behind a fuzzer, which is the specific gap
//! ENG-10 and CLAIM-03 name: today's `mutated_bytes_never_panic` tests stop
//! at `Binary::parse`.
//!
//! Depth is capped at 5 (common::MAX_DEPTH) and input at 1 MiB. An
//! unbounded depth makes every input a libFuzzer timeout and the fuzzer
//! learns nothing; a bounded depth still reaches every code path in the
//! backward walk, because the walk's structure does not change with depth.
#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((body, opt)) = common::split_opts(data) else {
        return;
    };
    let req = common::request_from(opt);
    let _ = rf_api::scan_bytes(body, None, &req);
});
