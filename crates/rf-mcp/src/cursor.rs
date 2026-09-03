//! MCP-DESIGN fix #8 part B — pagination.
//!
//! Without it, "40,872 gadgets, here are the first 1,000" is the whole
//! answer an agent can ever get out of the MIPS fixture. The cursor is
//! base64url of `{v, cache_key, order, offset, params_hash}`: it names the
//! exact result set (`cache_key` folds in the file's SHA-256 and every scan
//! parameter), the order the set was put in, and how far through it the
//! caller is.
//!
//! It is verified rather than trusted. `params_hash` is a hash of the
//! request that produced it, minus the three parameters that do not change
//! *which* gadgets are in the set (`cursor`, `max_results`, `timeout_secs`),
//! so an agent that pages a depth-4 query with a depth-6 cursor gets
//! `cursor_expired` and a suggestion that clears it, instead of a page from
//! the wrong set silently spliced into the middle of its results.
//!
//! The cursor is opaque to the client and carries nothing secret: every
//! field in it is something the client sent or was told. It is not signed —
//! forging one buys the forger a page of a scan they could have asked for
//! directly.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::schema::ErrorCode;
use crate::ToolError;

/// Cursor payload version. A bump makes every outstanding cursor expire
/// rather than be misread.
pub const CURSOR_VERSION: u32 = 1;

/// The decoded cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub v: u32,
    /// The cached scan this cursor walks.
    pub cache_key: String,
    /// The order the set was put in (`Order::as_str`).
    pub order: String,
    /// Index of the next gadget to return.
    pub offset: u64,
    /// Fingerprint of the query that produced the set.
    pub params_hash: String,
}

/// The one error a bad cursor produces, with the patch that fixes it.
///
/// `retryable` is true and the suggestion clears the cursor, because
/// re-sending the same call with `cursor: null` always works: it starts the
/// walk again from the top.
fn expired(why: &str, details: serde_json::Value) -> ToolError {
    ToolError::with_details(
        ErrorCode::CursorExpired,
        format!(
            "the cursor does not describe this query ({why}); \
             re-send with cursor: null to start again"
        ),
        details,
    )
    .retryable(true)
    .with_suggestion(json!({"arguments_patch": {"cursor": null}}))
}

impl Cursor {
    #[must_use]
    pub fn encode(&self) -> String {
        // Serialization of five scalars cannot fail.
        let json = serde_json::to_vec(self).unwrap_or_default();
        URL_SAFE_NO_PAD.encode(json)
    }

    /// Decode and validate against the request that presented it.
    pub fn decode(
        raw: &str,
        cache_key: &str,
        order: &str,
        params_hash: &str,
    ) -> Result<Cursor, ToolError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(raw.trim())
            .map_err(|_| expired("it is not valid base64url", json!({"reason": "malformed"})))?;
        let c: Cursor = serde_json::from_slice(&bytes)
            .map_err(|_| expired("it is not a cursor", json!({"reason": "malformed"})))?;
        if c.v != CURSOR_VERSION {
            return Err(expired(
                "it was issued by a different version of this server",
                json!({"reason": "version", "got": c.v, "want": CURSOR_VERSION}),
            ));
        }
        if c.cache_key != cache_key {
            return Err(expired(
                "it belongs to a different binary or a different scan",
                json!({"reason": "cache_key"}),
            ));
        }
        if c.order != order {
            return Err(expired(
                "the order changed since it was issued",
                json!({"reason": "order", "got": c.order, "want": order}),
            ));
        }
        if c.params_hash != params_hash {
            return Err(expired(
                "the query parameters changed since it was issued",
                json!({"reason": "params_hash"}),
            ));
        }
        Ok(c)
    }

    /// The cursor for the page after `offset + returned`, or `None` when
    /// the walk is done.
    #[must_use]
    pub fn next(
        cache_key: &str,
        order: &str,
        params_hash: &str,
        offset: u64,
        returned: u64,
        total: u64,
    ) -> Option<String> {
        let next = offset.saturating_add(returned);
        (next < total).then(|| {
            Cursor {
                v: CURSOR_VERSION,
                cache_key: cache_key.to_string(),
                order: order.to_string(),
                offset: next,
                params_hash: params_hash.to_string(),
            }
            .encode()
        })
    }
}

/// Fingerprint of the parameters that decide WHICH gadgets are in the set.
///
/// `cursor`, `max_results` and `timeout_secs` are removed: an agent may
/// legitimately change its page size or its patience halfway through a walk,
/// and neither changes the set or its order. Everything else — the path, the
/// depth, the section, the semantic filters — is in, which is what makes a
/// depth-4 cursor fail against a depth-6 query.
#[must_use]
pub fn params_fingerprint<T: Serialize>(q: &T) -> String {
    let mut v = serde_json::to_value(q).unwrap_or(serde_json::Value::Null);
    if let Some(o) = v.as_object_mut() {
        for drop in ["cursor", "max_results", "timeout_secs"] {
            o.remove(drop);
        }
    }
    rf_cache::sha256_hex(v.to_string().as_bytes())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;

    fn cur(offset: u64) -> Cursor {
        Cursor {
            v: CURSOR_VERSION,
            cache_key: "k".into(),
            order: "rank".into(),
            offset,
            params_hash: "p".into(),
        }
    }

    #[test]
    fn round_trips_and_is_url_safe() {
        let c = cur(100);
        let s = c.encode();
        assert!(
            s.chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'),
            "{s}"
        );
        assert_eq!(Cursor::decode(&s, "k", "rank", "p").unwrap(), c);
    }

    #[test]
    fn a_cursor_from_another_query_is_rejected_with_a_patch() {
        let s = cur(100).encode();
        for (key, order, hash, reason) in [
            ("other", "rank", "p", "cache_key"),
            ("k", "address", "p", "order"),
            ("k", "rank", "other", "params_hash"),
        ] {
            let e = Cursor::decode(&s, key, order, hash).unwrap_err();
            assert_eq!(e.code, ErrorCode::CursorExpired, "{reason}");
            assert!(e.retryable, "{reason}");
            let sug = e.suggestion.as_ref().expect(reason);
            assert!(sug["arguments_patch"]["cursor"].is_null(), "{sug}");
            assert_eq!(e.details.as_ref().unwrap()["reason"], reason);
        }
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for bad in ["", "!!!!", "aaaa", "eyJ2Ijo5OTl9"] {
            let e = Cursor::decode(bad, "k", "rank", "p").unwrap_err();
            assert_eq!(e.code, ErrorCode::CursorExpired, "{bad}");
        }
    }

    #[test]
    fn next_stops_at_the_end() {
        assert!(Cursor::next("k", "rank", "p", 0, 100, 250).is_some());
        assert!(Cursor::next("k", "rank", "p", 200, 50, 250).is_none());
        assert!(Cursor::next("k", "rank", "p", 0, 0, 0).is_none());
        let s = Cursor::next("k", "rank", "p", 100, 100, 250).unwrap();
        assert_eq!(Cursor::decode(&s, "k", "rank", "p").unwrap().offset, 200);
    }

    /// The three parameters that do not change the set are excluded, and
    /// everything else is included.
    #[test]
    fn the_fingerprint_ignores_only_paging_parameters() {
        let base = json!({"binary_path": "/a", "depth": 4, "max_results": 100,
                          "timeout_secs": 60, "cursor": null});
        let a = params_fingerprint(&base);
        let paged = json!({"binary_path": "/a", "depth": 4, "max_results": 7,
                           "timeout_secs": 300, "cursor": "abc"});
        assert_eq!(a, params_fingerprint(&paged));
        let deeper = json!({"binary_path": "/a", "depth": 6, "max_results": 100,
                            "timeout_secs": 60, "cursor": null});
        assert_ne!(a, params_fingerprint(&deeper));
        let other_file = json!({"binary_path": "/b", "depth": 4, "max_results": 100,
                                "timeout_secs": 60, "cursor": null});
        assert_ne!(a, params_fingerprint(&other_file));
    }
}
