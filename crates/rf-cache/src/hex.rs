//! Checked hex encode/decode.
//!
//! ROB-04. The panic this replaces was `&c.bytes[i..i + 2]` — a **byte
//! range slice of a `&str`** — which existed twice, once in
//! `rf_cli::cache_load` and once in `rf_mcp::gadget_from_cached`. A cache
//! entry whose `bytes` field held `"€€"` (3-byte UTF-8 characters) made
//! `i + 2` land inside a character and the process aborted with
//! `byte index 2 is not a char boundary; it is inside '€'`. Every decode
//! here runs over `as_bytes()`, so no index can ever be interior to a
//! character, and the alphabet is checked explicitly rather than being
//! delegated to `from_str_radix` (which accepts `+`/`-` signs and
//! Unicode digits).

/// Longest gadget byte string a cache entry may carry. A gadget is at most
/// `depth` instructions of at most 15 bytes each; 4 KiB is far above any
/// real value and still bounds an adversarial entry.
pub const MAX_GADGET_BYTES: usize = 4096;

/// ASCII hex digit -> value. `None` for everything else, including the
/// signs and non-ASCII digits `u8::from_str_radix` would accept.
const fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Lowercase hex, no separators.
#[must_use]
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // 0..=15 with radix 16 is always `Some`; the `if let` exists so the
        // function needs no indexing and no `unwrap`.
        if let Some(c) = char::from_digit(u32::from(b >> 4), 16) {
            s.push(c);
        }
        if let Some(c) = char::from_digit(u32::from(b & 0x0f), 16) {
            s.push(c);
        }
    }
    s
}

/// Decode `s` as hex. `None` unless the length is even, every byte is an
/// ASCII hex digit, and the result is at most `max_bytes` long.
#[must_use]
pub fn decode_hex(s: &str, max_bytes: usize) -> Option<Vec<u8>> {
    let raw = s.as_bytes();
    if raw.len() % 2 != 0 || raw.len() / 2 > max_bytes {
        return None;
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.chunks_exact(2) {
        let [hi, lo] = pair else { return None };
        out.push((hexval(*hi)? << 4) | hexval(*lo)?);
    }
    Some(out)
}

/// True when `s` is a well-formed hex byte string of at most `max_bytes`
/// bytes — the validation half of [`decode_hex`] with no allocation.
#[must_use]
pub fn is_hex_bytes(s: &str, max_bytes: usize) -> bool {
    let raw = s.as_bytes();
    raw.len() % 2 == 0 && raw.len() / 2 <= max_bytes && raw.iter().all(|b| hexval(*b).is_some())
}

/// Parse an address written in hex, with or without a `0x`/`0X` prefix.
/// `None` on an empty string, on more than 16 digits (would overflow), or
/// on any non-hex byte — so `vaddr: "not-hex"` is a clean miss.
#[must_use]
pub fn parse_hex_u64(s: &str) -> Option<u64> {
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let raw = body.as_bytes();
    if raw.is_empty() || raw.len() > 16 {
        return None;
    }
    let mut v: u64 = 0;
    for b in raw {
        v = (v << 4) | u64::from(hexval(*b)?);
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let b = vec![0x00, 0x0f, 0xf0, 0xff, 0x5c];
        assert_eq!(encode_hex(&b), "000ff0ff5c");
        assert_eq!(decode_hex("000ff0ff5c", 16).unwrap(), b);
        assert_eq!(decode_hex("", 16).unwrap(), Vec::<u8>::new());
    }

    /// ROB-04, the exact input that panicked. Three-byte characters make
    /// every odd byte index interior to a character.
    #[test]
    fn non_ascii_is_none_not_panic() {
        assert_eq!(decode_hex("€€", MAX_GADGET_BYTES), None);
        assert_eq!(decode_hex("c3€", MAX_GADGET_BYTES), None);
        assert_eq!(parse_hex_u64("€"), None);
    }

    #[test]
    fn rejects_odd_length_bad_alphabet_and_overlong() {
        assert_eq!(decode_hex("abc", 16), None);
        assert_eq!(decode_hex("zz", 16), None);
        assert_eq!(decode_hex("+1", 16), None);
        // `u8::from_str_radix("＋", 16)` is an error too, but the point is
        // that we never reach it: the byte alphabet is checked first.
        assert_eq!(decode_hex("00112233", 3), None);
        assert!(decode_hex("00112233", 4).is_some());
    }

    #[test]
    fn hex_u64() {
        assert_eq!(parse_hex_u64("0x401000"), Some(0x0040_1000));
        assert_eq!(parse_hex_u64("401000"), Some(0x0040_1000));
        assert_eq!(parse_hex_u64("ffffffffffffffff"), Some(u64::MAX));
        assert_eq!(parse_hex_u64("1ffffffffffffffff"), None);
        assert_eq!(parse_hex_u64("not-hex"), None);
        assert_eq!(parse_hex_u64(""), None);
        assert_eq!(parse_hex_u64("0x"), None);
        assert_eq!(parse_hex_u64("-1"), None);
    }

    #[test]
    fn is_hex_bytes_agrees_with_decode() {
        for s in ["", "00", "aabb", "abc", "zz", "€€", "AABB"] {
            assert_eq!(
                is_hex_bytes(s, MAX_GADGET_BYTES),
                decode_hex(s, MAX_GADGET_BYTES).is_some(),
                "{s:?}"
            );
        }
    }
}
