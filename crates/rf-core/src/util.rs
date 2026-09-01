//! Internal helpers shared by the format loaders.

/// Clamp a file range to what the file actually contains. Never panics,
/// never reads out of bounds; truncated sections yield truncated bytes.
pub(crate) fn slice_clamped(bytes: &[u8], offset: u64, size: u64) -> Vec<u8> {
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    if start >= bytes.len() {
        return Vec::new();
    }
    let end = start.saturating_add(size).min(bytes.len());
    bytes[start..end].to_vec()
}

/// Decode a fixed-size C string field (e.g. PE's 8-byte section name,
/// Mach-O's 16-byte `sectname`). These fields are NOT guaranteed to be
/// NUL-terminated: when they fill the whole field there is no terminator,
/// so we cut at the first NUL *if present* and decode lossily.
pub(crate) fn cstr_lossy(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}
