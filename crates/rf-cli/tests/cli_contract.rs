//! Process-level exit-code contract (MANUAL: "0 success, 1 usage error,
//! 2 malformed binary").
//!
//! These four commands are exactly the ones the audit found broken, and
//! they cannot be checked from a unit test: the defects are in what the
//! *process* returns to a shell, an installer script or a CI step.
//!
//!   * CLI-06 / ENG-06 — `--help` and `--version` exited 1, so the
//!     project's own `set -e` build script failed at its last line.
//!   * ROB-03 / CRIT-02 — `--binary x | head` panicked and exited 101 on
//!     every platform, both in human and in `--json` mode.
//!   * CLAIM-10 — `--version` recorded neither the linked capstone nor
//!     the ROPgadget attribution.
//!   * CHWIN-09 — `--chain windows-virtualprotect` printed a chain that
//!     does not execute, with nothing said about it.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const EXE: &str = env!("CARGO_BIN_EXE_rop-finder");

/// A repo fixture; `crates/rf-cli/` → `tests/fixtures/`.
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn help_exits_zero() {
    for flag in ["--help", "-h"] {
        let o = Command::new(EXE).arg(flag).output().expect("spawn");
        assert_eq!(o.status.code(), Some(0), "{flag} must exit 0");
        assert!(
            String::from_utf8_lossy(&o.stdout).contains("Usage:"),
            "{flag} must print usage on stdout"
        );
    }
}

#[test]
fn version_exits_zero_and_records_capstone_and_ropgadget() {
    let o = Command::new(EXE).arg("--version").output().expect("spawn");
    assert_eq!(o.status.code(), Some(0), "--version must exit 0");
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(text.starts_with("rop-finder "), "{text}");
    // CLAIM-10: the disassembler build a parity report has to cite.
    assert!(
        text.contains(&format!("capstone {}", rf_scan::capstone_version())),
        "{text}"
    );
    // ENG-03/CLAIM-10: the attribution the port owes its original.
    assert!(text.contains("ROPgadget"), "{text}");
}

#[test]
fn unknown_flag_still_exits_one() {
    let o = Command::new(EXE)
        .arg("--no-such-flag")
        .output()
        .expect("spawn");
    assert_eq!(o.status.code(), Some(1), "a usage error is exit 1");
}

/// ROB-03 / CRIT-02, both output modes. The reader takes a few bytes and
/// then closes; the child, still writing megabytes, must notice the closed
/// pipe and stop cleanly instead of panicking (exit 101).
///
/// Not `cfg(unix)`: the defect is not a Windows quirk (that claim is
/// CRIT-02's third count), and Windows reports the same condition as
/// ERROR_BROKEN_PIPE/ERROR_NO_DATA, which `std` maps to
/// `ErrorKind::BrokenPipe`.
#[test]
fn broken_pipe_exits_zero_in_both_output_modes() {
    let bin = fixture("elf-Linux-x64");
    assert!(bin.is_file(), "fixture missing: {}", bin.display());
    for extra in [&[][..], &["--json"][..]] {
        let mut child = Command::new(EXE)
            .arg("--binary")
            .arg(&bin)
            .args(extra)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn");
        let mut pipe = child.stdout.take().expect("piped stdout");
        // Read less than one buffer: the child is left blocked on a full
        // pipe with ~2.9 MB still to write when the reader goes away.
        let mut head = [0u8; 64];
        pipe.read_exact(&mut head).expect("child produced output");
        drop(pipe);
        let status = child.wait().expect("wait");
        assert_eq!(
            status.code(),
            Some(0),
            "a closed reader is a clean exit, not a panic (args: {extra:?})"
        );
    }
}

/// CHWIN-09: the experimental gate is loud, is on stderr (so a redirected
/// script stays clean), and comes out even when the build then fails.
#[test]
fn windows_chain_warns_on_stderr() {
    let bin = fixture("pe-x64-cmd-v6.1.7601");
    assert!(bin.is_file(), "fixture missing: {}", bin.display());
    let o = Command::new(EXE)
        .arg("--binary")
        .arg(&bin)
        .arg("--ropchain")
        .arg("--chain")
        .arg("windows-virtualprotect")
        .output()
        .expect("spawn");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("EXPERIMENTAL"), "{err}");
    assert!(err.contains("CHWIN-01"), "{err}");
    assert!(err.contains("v0.5"), "{err}");
    assert!(
        !String::from_utf8_lossy(&o.stdout).contains("EXPERIMENTAL"),
        "the warning must not pollute the generated script"
    );
}

/// The Linux target — the default — is not experimental and must stay
/// silent, so the warning keeps meaning something.
#[test]
fn linux_chain_is_not_warned_about() {
    let bin = fixture("elf-Linux-x64");
    assert!(bin.is_file(), "fixture missing: {}", bin.display());
    let o = Command::new(EXE)
        .arg("--binary")
        .arg(&bin)
        .arg("--ropchain")
        .output()
        .expect("spawn");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!err.contains("EXPERIMENTAL"), "{err}");
}
