//! `rf_cli::info_bytes` target — the `--info` pipeline over hostile bytes.
//!
//! `info_bytes` = load_target + info_json, so this covers format dispatch,
//! every loader, the arch/endianness mapping, the image-base derivation
//! (CORE-02) and the JSON serialisation of attacker-controlled section
//! names in one execution. It is cheap (no decode), so it is the target to
//! run first and longest.
#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((body, opt)) = common::split_opts(data) else {
        return;
    };

    // Auto-detected format, no rebase.
    let _ = rf_cli::info_bytes(body, None, None);
    // Auto-detected format, rebased: exercises the wrapping arithmetic in
    // every loader's `rebase` against attacker-controlled vmaddrs.
    let base = if opt & 1 == 0 { 0 } else { u64::MAX };
    let _ = rf_cli::info_bytes(body, None, Some(base));
    // Raw loader: --rawArch wins over magic detection (binary.py:32-49), so
    // this arm reaches the raw path with arbitrary bytes.
    let _ = rf_cli::info_bytes(body, Some(common::raw_spec_from(opt)), Some(base));
});
