//! HMAC-SHA256 (RFC 2104) over the `sha2` crate the workspace already
//! depends on.
//!
//! CLI-07/MCP-04. A cache entry is authenticated with a tag over
//! `key || 0x00 || body`, so neither the body nor the key it was stored
//! under can be changed without detection, and an entry cannot be moved
//! from one key to another. Thirty lines of RFC 2104 is cheaper than a new
//! dependency in a graph `cargo deny` has to keep auditing, and it is
//! pinned to the published test vectors below.

use sha2::{Digest, Sha256};

/// Tag length in bytes.
pub const MAC_LEN: usize = 32;
/// SHA-256 block size, the pad width RFC 2104 specifies.
const BLOCK: usize = 64;

/// HMAC-SHA256 of `msg` under `key`.
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; MAC_LEN] {
    // K0: the key, hashed first if it is longer than a block, then zero
    // padded to a full block. Written as zip-copies so this module needs no
    // indexing at all (`#![deny(clippy::indexing_slicing)]`).
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        for (dst, src) in k0.iter_mut().zip(digest.iter()) {
            *dst = *src;
        }
    } else {
        for (dst, src) in k0.iter_mut().zip(key.iter()) {
            *dst = *src;
        }
    }

    let ipad: Vec<u8> = k0.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k0.iter().map(|b| b ^ 0x5c).collect();

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner);
    let outer = outer.finalize();

    let mut out = [0u8; MAC_LEN];
    for (dst, src) in out.iter_mut().zip(outer.iter()) {
        *dst = *src;
    }
    out
}

/// Length-independent, data-independent-time comparison. A cache tag check
/// is not a remote timing oracle, but a byte-at-a-time `==` on a security
/// tag is the kind of thing that gets copied somewhere it matters.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// SHA-256 as lowercase hex. Both front ends hash the input file with it,
/// so it lives here with the rest of the key machinery.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    crate::hex::encode_hex(&h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex::encode_hex;

    /// RFC 4231 §4.2, §4.3 and §4.6 (the >block-size key case, which is the
    /// only branch in `hmac_sha256` that is not exercised by the others).
    /// Cross-checked against CPython's `hmac.new(..., hashlib.sha256)`.
    #[test]
    fn rfc4231_vectors() {
        assert_eq!(
            encode_hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            encode_hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            encode_hex(&hmac_sha256(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn tag_depends_on_key_and_message() {
        let a = hmac_sha256(b"k1", b"body");
        assert_ne!(a, hmac_sha256(b"k2", b"body"));
        assert_ne!(a, hmac_sha256(b"k1", b"bodz"));
        assert_eq!(a, hmac_sha256(b"k1", b"body"));
    }

    #[test]
    fn ct_eq_basics() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn sha256_hex_known_value() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
