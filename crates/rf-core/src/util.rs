//! Internal helpers shared by the format loaders.

use std::collections::HashSet;

use crate::Error;

/// Decode a fixed-size C string field (e.g. PE's 8-byte section name,
/// Mach-O's 16-byte `sectname`). These fields are NOT guaranteed to be
/// NUL-terminated: when they fill the whole field there is no terminator,
/// so we cut at the first NUL *if present* and decode lossily.
pub(crate) fn cstr_lossy(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Bounded, de-overlapping materializer for one *view* of a binary's byte
/// ranges (ROB-02).
///
/// The loaders make one owned copy per declared section/segment header.
/// Nothing in the file format stops a header table from declaring the SAME
/// file range thousands of times: a 382 KB PE with a 2000-entry section
/// table all pointing at `.text` used to materialise 2000 copies of it
/// (measured 19.8 GB RSS, a ~54,000x amplification), and the ELF variant
/// with 4000 cloned section headers was worse.
///
/// Two bounds, both derived from the file itself so a well-formed binary is
/// never affected:
///
/// 1. **De-overlap.** A `(file_offset, declared_size)` pair that has already
///    been materialised in this view yields an EMPTY byte buffer the second
///    time. The header keeps its metadata (name, vaddr, size, flags) so
///    `--info` still reports the file faithfully; only the redundant *copy*
///    of identical bytes is dropped. In a well-formed binary distinct
///    sections never share a raw-data range, and where they do the bytes are
///    by definition identical, so dedup collapses the resulting gadgets
///    anyway.
/// 2. **Total budget.** The materialised bytes of one view may not exceed
///    [`ByteBudget::for_file`]'s allowance (4x the file length, floor 64 KiB).
///    In a valid container the raw ranges are disjoint, so their sum is at
///    most the file length; 4x is generous headroom for legitimately
///    overlapping mappings. Exceeding it is a structured `Malformed` error,
///    never an allocation.
pub(crate) struct ByteBudget {
    remaining: usize,
    total: usize,
    seen: HashSet<(u64, u64)>,
}

impl ByteBudget {
    /// Budget for one view of a `file_len`-byte file: 4x the file length,
    /// with a 64 KiB floor so tiny hand-built binaries are never refused.
    pub(crate) fn for_file(file_len: usize) -> Self {
        let total = file_len.saturating_mul(4).max(64 * 1024);
        ByteBudget {
            remaining: total,
            total,
            seen: HashSet::new(),
        }
    }

    /// Materialise `bytes[offset .. offset+size]`, clamped to the file.
    ///
    /// Returns an empty buffer for a range already taken in this view, and
    /// `Err(Error::Malformed)` when the view's total would exceed the
    /// budget. Never allocates more than the remaining budget.
    pub(crate) fn take(
        &mut self,
        bytes: &[u8],
        offset: u64,
        size: u64,
        what: &str,
    ) -> Result<Vec<u8>, Error> {
        if size == 0 {
            return Ok(Vec::new());
        }
        if !self.seen.insert((offset, size)) {
            return Ok(Vec::new());
        }
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start >= bytes.len() {
            return Ok(Vec::new());
        }
        let want = usize::try_from(size).unwrap_or(usize::MAX);
        let end = start.saturating_add(want).min(bytes.len());
        let len = end - start;
        if len > self.remaining {
            return Err(Error::Malformed(format!(
                "{what} declare more than {} bytes of content in a {}-byte file \
                 (refusing to materialise {len} more); the header table is malformed",
                self.total,
                bytes.len(),
            )));
        }
        self.remaining -= len;
        Ok(bytes[start..end].to_vec())
    }
}
