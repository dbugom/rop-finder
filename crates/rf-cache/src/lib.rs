//! rf-cache — the *one* scan cache shared by `rop-finder` (rf-cli) and
//! `rop-finder-mcp` (rf-mcp).
//!
//! This crate exists because the duplication *was* the bug. Two copies of
//! the cache meant two copies of the hex decoder, and the ROB-04
//! char-boundary panic lived in both of them; it meant two key builders,
//! and only one of them ever learned about `--align`. Everything that
//! decides whether a cached result may be believed now lives here:
//!
//! * **[`make_key`]** — a versioned key. Every output-affecting parameter
//!   goes in (CLI-01/ENG-05: the old rf-cli key omitted `--rawArch`,
//!   `--rawMode` and `--rawEndian`, so `--cache` served an x86 scan for an
//!   ARM query), and the schema version is in both the hashed material and
//!   the file name, so the *next* key change misses instead of
//!   mismatching.
//! * **[`DiskCache`]** — HMAC-SHA256 over `key || 0x00 || body` with a
//!   per-directory random key, 0600 entries in a 0700 directory,
//!   `create_new` + rename for atomicity, and a byte-weighted LRU with a
//!   TTL (CLI-07/MCP-04, CLI-08/PERF-12).
//! * **[`MemCache`]** — the in-memory half: a byte-weighted LRU with a
//!   TTL, weighted by [`CachedScan::heap_bytes`] and evicted on insert
//!   (MCP-05/ROB-07). The unbounded `HashMap` it replaces walked the MCP
//!   server's RSS from 5 MB to 84 MB over twelve scans of one 900 KB
//!   binary and pinned 2.57 GB from a single depth-40 request.
//! * **[`CachedScan::validate`]** — run on every deserialize, so a
//!   corrupt or hostile entry is a miss with a counter rather than a
//!   panic or a lie (ROB-04).
//!
//! A cache that cannot prove an entry is its own does not fall back to
//! trusting it: [`DiskCache::open`] fails, and the caller runs uncached.
//!
//! # Semver policy
//!
//! Covered by semver from 1.0: the signatures of [`make_key`],
//! [`DiskCache`]'s and [`MemCache`]'s methods, and the fields of
//! [`CacheLimits`], [`CacheStats`] and [`MemStats`].
//!
//! **Not** covered: the on-disk format. [`CACHE_FORMAT_VERSION`] and the
//! key schema version are in both the hashed material and the file name
//! precisely so that changing them MISSES rather than mismatching — a
//! format change is a cold cache, never a wrong answer, and so it is not a
//! breaking change. The text of an [`OpenError`] is not covered either.
//! Pin `rf-cache = "1"`.
//!
//! See `docs/API-STABILITY.md` in the repository for the workspace-wide
//! statement.

#![deny(clippy::indexing_slicing, clippy::string_slice)]
// ENG-08: every public item carries documentation.
#![warn(missing_docs)]

mod hex;
mod mac;
mod mem;
mod record;
mod store;

pub use hex::{decode_hex, encode_hex, is_hex_bytes, parse_hex_u64, MAX_GADGET_BYTES};
pub use mac::{ct_eq, hmac_sha256, sha256_hex, MAC_LEN};
pub use mem::{now_unix, MemCache, MemLimits, MemStats, DEFAULT_MEM_MAX_BYTES, DEFAULT_MEM_TTL};
pub use record::{
    CachedGadget, CachedScan, CACHE_FORMAT_VERSION, GADGET_OVERHEAD_BYTES, KNOWN_CLASSES,
    MAX_GADGETS_PER_ENTRY, MAX_INSNS_PER_GADGET, MAX_LABEL_BYTES, MAX_PREV_BYTES, MAX_TEXT_BYTES,
    SCAN_OVERHEAD_BYTES,
};
pub use store::{
    CacheLimits, CacheStats, DiskCache, OpenError, DEFAULT_MAX_ENTRY_BYTES,
    DEFAULT_MAX_TOTAL_BYTES, DEFAULT_TTL, KEY_FILE,
};

/// Key schema version.
///
/// It is hashed *into* the parameter digest and prefixed onto the file
/// name. Both matter: the prefix means a v1 entry is never even opened by
/// a v2 lookup, and the hashed copy means two schemas can never
/// accidentally agree on a digest. When a future release adds another
/// output-affecting flag, bumping this is the whole migration — old
/// entries miss, get rescanned, and age out under the TTL.
pub const KEY_SCHEMA_VERSION: u32 = 1;

/// Build a cache key from the input file's SHA-256 (hex) and a rendering
/// of every parameter that can change the output.
///
/// `params` is the caller's business — it is the front end that knows
/// which flags it has — but it must be *complete*. CLI-01/ENG-05 was
/// exactly an incomplete `params`.
#[must_use]
pub fn make_key(file_sha256_hex: &str, params: &str) -> String {
    let material = format!("rf-cache/key/v{KEY_SCHEMA_VERSION}\u{1f}{params}");
    let param_hash = sha256_hex(material.as_bytes());
    // "--" separator: ':' is not a legal Windows file name character.
    format!("v{KEY_SCHEMA_VERSION}-{file_sha256_hex}--{param_hash}")
}

/// First 16 characters of a key, for log lines. Char-safe by construction
/// (`str::get`, not a byte-range slice) — the same discipline that ROB-04
/// was a failure of.
#[must_use]
pub fn key_prefix(key: &str) -> &str {
    match key.char_indices().nth(16) {
        Some((i, _)) => key.get(..i).unwrap_or(key),
        None => key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_deterministic_and_parameter_sensitive() {
        let f = sha256_hex(b"binary");
        let a = make_key(&f, "depth=10|align=1");
        assert_eq!(a, make_key(&f, "depth=10|align=1"));
        assert_ne!(a, make_key(&f, "depth=10|align=4"));
        assert_ne!(a, make_key(&sha256_hex(b"other"), "depth=10|align=1"));
    }

    #[test]
    fn key_carries_the_schema_version_in_the_name() {
        let k = make_key(&sha256_hex(b"binary"), "p");
        assert!(k.starts_with(&format!("v{KEY_SCHEMA_VERSION}-")), "{k}");
        // Windows file names cannot contain ':'.
        assert!(!k.contains(':'));
        // A key is a legal file-name stem.
        assert!(k
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn key_prefix_never_splits_a_character() {
        assert_eq!(key_prefix("0123456789abcdefXYZ"), "0123456789abcdef");
        assert_eq!(key_prefix("short"), "short");
        assert_eq!(key_prefix(""), "");
        // Not a key we would ever build, but the helper must still not
        // panic on one.
        assert_eq!(key_prefix("€€€"), "€€€");
    }
}
