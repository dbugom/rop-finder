//! The one output sink every print path writes through.
//!
//! Two defects share a cause and therefore a fix (REMEDIATION Phase 1):
//!
//!   * PERF-07 — the gadget listing used a per-gadget `println!` to a fresh
//!     unlocked `Stdout`, so a reference scan spent 45,651 write(2) calls
//!     (55% of x86-64 wall clock) printing what it had already found.
//!   * ROB-03 / CRIT-02 — `println!` *panics* when the reader closes the
//!     pipe, so `rop-finder --binary x | head` exited 101 with a Rust
//!     backtrace hint. This is not a Windows quirk: it happens on every
//!     platform, because the Rust runtime sets SIGPIPE to SIG_IGN and the
//!     resulting EPIPE surfaces as a panic inside `std::io::stdio`.
//!
//! [`Out`] fixes both: one 64 KiB [`BufWriter`] over a lock held for the
//! whole process, and a *recorded* first error instead of a panic. The
//! broken pipe is not repaired by restoring the default SIGPIPE
//! disposition — that is Unix-only and this project's CI matrix includes
//! Windows — it is handled where it is observed, as an ordinary I/O error
//! that [`exit_code_for`] maps to a clean exit 0.

use std::io::{self, BufWriter, ErrorKind, StdoutLock, Write};

/// 64 KiB: the gadget listing is the only large writer and its lines are
/// ~40-70 bytes, so this is ~1000 lines per syscall.
const BUF_CAPACITY: usize = 64 * 1024;

/// A [`Write`] that remembers the first error it saw and stops issuing
/// syscalls afterwards.
///
/// Every print path in this crate takes `&mut dyn Write` and discards the
/// per-write `Result` (there is nothing useful a formatting loop can do
/// with it). That is only sound because the error is not lost: it is kept
/// here and surfaced once by [`Out::finish`], which the process entry
/// point turns into an exit code.
pub struct Out<W: Write> {
    inner: W,
    first_err: Option<ErrorKind>,
}

/// Buffered, locked stdout — the concrete [`Out`] the binary runs on.
pub type StdOut = Out<BufWriter<StdoutLock<'static>>>;

impl StdOut {
    /// Lock stdout for the lifetime of the process and buffer it.
    ///
    /// The lock is reentrant, so a stray `println!` elsewhere would not
    /// deadlock — but it would appear out of order, ahead of whatever is
    /// still sitting in this buffer. That is why the CLI has no `println!`
    /// on any output path any more.
    pub fn stdout() -> Self {
        Out::new(BufWriter::with_capacity(BUF_CAPACITY, io::stdout().lock()))
    }
}

impl<W: Write> Out<W> {
    pub fn new(inner: W) -> Self {
        Out {
            inner,
            first_err: None,
        }
    }

    /// Flush and report the first error seen, whether it happened during a
    /// write or during this flush. Call exactly once, at the end of the
    /// run; the returned error belongs to [`exit_code_for`].
    pub fn finish(&mut self) -> io::Result<()> {
        if self.first_err.is_none() {
            if let Err(e) = self.inner.flush() {
                self.first_err = Some(e.kind());
            }
        }
        match self.first_err {
            None => Ok(()),
            Some(kind) => Err(io::Error::new(
                kind,
                "stdout closed before all output was written",
            )),
        }
    }
}

impl<W: Write> Write for Out<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Once the reader is gone every further write would fail the same
        // way; pretending they succeed keeps a 45,000-line listing from
        // turning into 45,000 failing syscalls on the way out.
        if self.first_err.is_some() {
            return Ok(buf.len());
        }
        match self.inner.write(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                self.first_err = Some(e.kind());
                Err(e)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.first_err.is_some() {
            return Ok(());
        }
        match self.inner.flush() {
            Ok(()) => Ok(()),
            Err(e) => {
                self.first_err = Some(e.kind());
                Err(e)
            }
        }
    }
}

/// Exit code for an error that escaped the output path.
///
/// A closed reader (`| head`, `| grep -m1`, `less` + `q`) is a normal end
/// of output, not a failure — every other Unix text tool exits 0 there —
/// so [`ErrorKind::BrokenPipe`] maps to 0. Windows reports the same
/// condition as ERROR_BROKEN_PIPE/ERROR_NO_DATA, which `std` also maps to
/// `BrokenPipe`, so this needs no `cfg`. Anything else (a full disk, an
/// unwritable redirect) is a real failure and keeps exit 1.
pub fn exit_code_for(e: &io::Error) -> Result<i32, String> {
    if e.kind() == ErrorKind::BrokenPipe {
        Ok(0)
    } else {
        Err(format!("cannot write output: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that fails every call with `kind`, counting attempts.
    struct Failing {
        kind: ErrorKind,
        attempts: usize,
    }

    impl Write for Failing {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            self.attempts += 1;
            Err(io::Error::new(self.kind, "test"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(self.kind, "test"))
        }
    }

    #[test]
    fn broken_pipe_is_recorded_once_and_exits_zero() {
        let mut out = Out::new(Failing {
            kind: ErrorKind::BrokenPipe,
            attempts: 0,
        });
        // A print loop ignores the per-write Result, exactly as the gadget
        // listing does.
        for _ in 0..100 {
            let _ = writeln!(out, "0x0000000000401000 : ret");
        }
        let err = out
            .finish()
            .expect_err("the broken pipe must survive to finish()");
        assert_eq!(err.kind(), ErrorKind::BrokenPipe);
        // ROB-03: a closed reader is a clean exit, not a panic and not 101.
        assert_eq!(exit_code_for(&err), Ok(0));
        // PERF-07's sibling: no syscall storm after the pipe is gone.
        assert_eq!(out.inner.attempts, 1);
    }

    #[test]
    fn other_io_errors_stay_failures() {
        let mut out = Out::new(Failing {
            kind: ErrorKind::PermissionDenied,
            attempts: 0,
        });
        let _ = writeln!(out, "x");
        let err = out.finish().expect_err("the write error must be reported");
        assert!(exit_code_for(&err).is_err());
    }

    #[test]
    fn clean_writer_flushes_and_reports_success() {
        let mut out = Out::new(Vec::new());
        let _ = writeln!(out, "hello");
        out.finish().expect("no error on a healthy writer");
        assert_eq!(out.inner, b"hello\n");
    }

    #[test]
    fn a_late_flush_failure_is_reported() {
        let mut out = Out::new(Failing {
            kind: ErrorKind::BrokenPipe,
            attempts: 0,
        });
        // Nothing written: the error can only come from the final flush.
        let err = out.finish().expect_err("flush failure must be reported");
        assert_eq!(exit_code_for(&err), Ok(0));
    }
}
