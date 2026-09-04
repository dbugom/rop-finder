//! On-disk cache behaviour: integrity, the malformed-entry matrix,
//! bounds, and concurrent writers.
//!
//! Every test here fails against the pre-v0.2 cache, which read a
//! deterministically-named 0644 JSON file, trusted it verbatim, and
//! sliced its `bytes` field by byte range.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rf_cache::{
    hmac_sha256, make_key, sha256_hex, CacheLimits, CachedGadget, CachedScan, DiskCache, KEY_FILE,
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "rf-cache-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scan_with(gadgets: Vec<CachedGadget>) -> CachedScan {
    CachedScan {
        gadgets,
        ..CachedScan::default()
    }
}

fn one_gadget() -> CachedScan {
    scan_with(vec![CachedGadget {
        vaddr: "0x401000".to_string(),
        bytes: "5fc3".to_string(),
        text: "pop rdi ; ret".to_string(),
        ..CachedGadget::default()
    }])
}

fn entry_path(dir: &Path, key: &str) -> PathBuf {
    dir.join(format!("{key}.rfc"))
}

/// Write a body under `key` with a *valid* tag, so the test exercises
/// [`CachedScan::validate`] rather than the integrity check.
fn write_authenticated(dir: &Path, key: &str, body: &[u8]) {
    let mac_key = std::fs::read(dir.join(KEY_FILE)).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(key.as_bytes());
    msg.push(0);
    msg.extend_from_slice(body);
    let mut framed = Vec::new();
    framed.extend_from_slice(b"RFCACHE\x02");
    framed.extend_from_slice(&hmac_sha256(&mac_key, &msg));
    framed.extend_from_slice(body);
    std::fs::write(entry_path(dir, key), framed).unwrap();
}

#[test]
fn round_trip_hit_and_cold_miss() {
    let t = TempDir::new("roundtrip");
    let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();
    let key = make_key(&sha256_hex(b"binary"), "depth=10");
    assert!(c.load(&key).is_none(), "cold cache misses");
    c.store(&key, &one_gadget()).unwrap();
    let hit = c.load(&key).expect("warm cache hits");
    assert_eq!(hit.gadgets.len(), 1);
    assert_eq!(hit.gadgets.first().unwrap().text, "pop rdi ; ret");
    let s = c.stats();
    assert_eq!((s.hits, s.misses, s.tampered, s.malformed), (1, 1, 0, 0));
}

/// CLI-07/MCP-04. Flipping one byte of an entry must produce a miss, a
/// warning and a tamper counter — never a served result, never a panic.
#[test]
fn one_flipped_byte_is_a_miss_with_a_tamper_counter() {
    let t = TempDir::new("tamper");
    let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();
    let key = make_key(&sha256_hex(b"binary"), "depth=10");
    c.store(&key, &one_gadget()).unwrap();

    let path = entry_path(t.path(), &key);
    let mut raw = std::fs::read(&path).unwrap();
    let last = raw.len() - 4;
    raw[last] ^= 0x01;
    std::fs::write(&path, &raw).unwrap();

    assert!(c.load(&key).is_none(), "a tampered entry is never served");
    assert_eq!(c.stats().tampered, 1);
    assert_eq!(c.stats().hits, 0);
}

/// The reproduction from the audit: an attacker writes a whole entry of
/// their own at the deterministic file name. Before v0.2 the fabricated
/// `pop rdi ; ret @ 0xdeadbeefcafe0000` was printed alongside the genuine
/// `binary_sha256`.
#[test]
fn a_fabricated_entry_is_never_served() {
    let t = TempDir::new("fabricated");
    let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();
    let key = make_key(&sha256_hex(b"binary"), "depth=10");
    c.store(&key, &one_gadget()).unwrap();

    let fake = scan_with(vec![CachedGadget {
        vaddr: "0xdeadbeefcafe0000".to_string(),
        bytes: "5fc3".to_string(),
        text: "pop rdi ; ret".to_string(),
        ..CachedGadget::default()
    }]);
    // Plain JSON at the entry path, exactly what the old cache accepted.
    std::fs::write(
        entry_path(t.path(), &key),
        serde_json::to_vec(&fake).unwrap(),
    )
    .unwrap();

    assert!(c.load(&key).is_none());
    assert_eq!(c.stats().tampered, 1);
}

/// An entry cannot be moved from one scan configuration to another: the
/// key is inside the authenticated message.
#[test]
fn an_entry_cannot_be_relabelled_onto_another_key() {
    let t = TempDir::new("relabel");
    let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();
    let k1 = make_key(&sha256_hex(b"binary"), "rawArch=x86");
    let k2 = make_key(&sha256_hex(b"binary"), "rawArch=arm");
    c.store(&k1, &one_gadget()).unwrap();
    std::fs::copy(entry_path(t.path(), &k1), entry_path(t.path(), &k2)).unwrap();
    assert!(c.load(&k2).is_none(), "a relabelled entry is not served");
    assert_eq!(c.stats().tampered, 1);
    assert!(c.load(&k1).is_some(), "the original still verifies");
}

/// A cache directory whose key file has been replaced can no longer
/// authenticate its own old entries — they miss, they are not trusted.
#[test]
fn entries_do_not_survive_a_new_key_file() {
    let t = TempDir::new("newkey");
    let key = make_key(&sha256_hex(b"binary"), "depth=10");
    {
        let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();
        c.store(&key, &one_gadget()).unwrap();
        assert!(c.load(&key).is_some());
    }
    std::fs::remove_file(t.path().join(KEY_FILE)).unwrap();
    let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();
    assert!(c.load(&key).is_none());
    assert_eq!(c.stats().tampered, 1);
}

/// ROB-04, end to end. Every one of these is an authenticated entry — the
/// integrity check passes — so each case is decided by
/// `CachedScan::validate`. The old code panicked on the first one with
/// `byte index 2 is not a char boundary; it is inside '€'`; a panic here
/// fails the test, which is the assertion.
#[test]
fn malformed_entry_matrix_is_a_clean_miss() {
    let t = TempDir::new("malformed");
    let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();

    let cases: Vec<(&str, String)> = vec![
        (
            "non-ASCII bytes field",
            r#"{"version":2,"gadgets":[{"vaddr":"0x401000","bytes":"€€","text":"x"}]}"#.to_string(),
        ),
        (
            "odd-length hex",
            r#"{"version":2,"gadgets":[{"vaddr":"0x401000","bytes":"5fc","text":"x"}]}"#
                .to_string(),
        ),
        (
            "non-hex alphabet",
            r#"{"version":2,"gadgets":[{"vaddr":"0x401000","bytes":"zz","text":"x"}]}"#.to_string(),
        ),
        (
            "1 MB text field",
            format!(
                r#"{{"version":2,"gadgets":[{{"vaddr":"0x401000","bytes":"5fc3","text":"{}"}}]}}"#,
                "a".repeat(1024 * 1024)
            ),
        ),
        (
            "vaddr not-hex",
            r#"{"version":2,"gadgets":[{"vaddr":"not-hex","bytes":"5fc3","text":"x"}]}"#
                .to_string(),
        ),
        (
            "quality 99999",
            r#"{"version":2,"gadgets":[{"vaddr":"0x401000","bytes":"5fc3","text":"x","quality":99999}]}"#
                .to_string(),
        ),
        (
            "class ../../etc",
            r#"{"version":2,"gadgets":[{"vaddr":"0x401000","bytes":"5fc3","text":"x","class":"../../etc"}]}"#
                .to_string(),
        ),
        (
            "control characters in text",
            "{\"version\":2,\"gadgets\":[{\"vaddr\":\"0x401000\",\"bytes\":\"5fc3\",\"text\":\"a\\u001b[2Jb\"}]}"
                .to_string(),
        ),
        (
            "not JSON at all",
            "\u{feff}not json".to_string(),
        ),
        (
            "wrong record version",
            r#"{"version":9999,"gadgets":[]}"#.to_string(),
        ),
    ];

    for (n, (what, body)) in cases.iter().enumerate() {
        let key = make_key(&sha256_hex(b"binary"), &format!("case={n}"));
        write_authenticated(t.path(), &key, body.as_bytes());
        assert!(c.load(&key).is_none(), "{what} must be a miss");
    }
    let s = c.stats();
    assert_eq!(s.hits, 0);
    assert_eq!(s.malformed, cases.len() as u64);
    assert_eq!(s.tampered, 0, "these are authentic, just unusable");
}

#[test]
fn a_truncated_file_is_a_miss() {
    let t = TempDir::new("truncated");
    let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();
    let key = make_key(&sha256_hex(b"binary"), "depth=10");
    c.store(&key, &one_gadget()).unwrap();
    let path = entry_path(t.path(), &key);
    let raw = std::fs::read(&path).unwrap();
    for keep in [0, 1, 8, 20, 39, raw.len() - 1] {
        std::fs::write(&path, raw.get(..keep).unwrap()).unwrap();
        assert!(c.load(&key).is_none(), "truncated to {keep} bytes");
    }
    assert_eq!(c.stats().hits, 0);
}

/// A pre-v0.2 `.json` entry is not even looked at.
#[test]
fn legacy_json_entries_are_ignored() {
    let t = TempDir::new("legacy");
    let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();
    let key = make_key(&sha256_hex(b"binary"), "depth=10");
    std::fs::write(
        t.path().join(format!("{key}.json")),
        serde_json::to_vec(&one_gadget()).unwrap(),
    )
    .unwrap();
    assert!(c.load(&key).is_none());
    assert_eq!(c.stats().tampered, 0, "an ignored file is not a tamper");
}

/// CLI-08/PERF-12: a TTL, and a byte-weighted LRU that evicts
/// oldest-used-first until the directory is inside its budget.
#[test]
fn ttl_expires_entries() {
    let t = TempDir::new("ttl");
    let limits = CacheLimits {
        ttl: Duration::from_secs(60),
        ..CacheLimits::default()
    };
    let c = DiskCache::open(t.path(), limits).unwrap();
    let key = make_key(&sha256_hex(b"binary"), "depth=10");
    c.store(&key, &one_gadget()).unwrap();
    assert!(c.load(&key).is_some(), "fresh entries are served");
    // Backdate rather than sleep: the entry's age is the thing under test,
    // and a test that waits out a real TTL is either slow or flaky.
    let f = std::fs::File::options()
        .write(true)
        .open(entry_path(t.path(), &key))
        .unwrap();
    f.set_modified(std::time::SystemTime::now() - Duration::from_secs(3600))
        .unwrap();
    drop(f);
    assert!(c.load(&key).is_none(), "an expired entry is not served");
    assert_eq!(c.stats().expired, 1);
    assert!(!entry_path(t.path(), &key).exists(), "and it is removed");
}

#[test]
fn lru_evicts_until_the_budget_is_met() {
    let t = TempDir::new("lru");
    // One entry of this scan is comfortably over 400 bytes, so a 1 KiB
    // budget holds two of them and evicts on the third.
    let big = scan_with(
        (0..12)
            .map(|i| CachedGadget {
                vaddr: format!("{:x}", 0x40_1000 + i),
                bytes: "5fc3".to_string(),
                text: "pop rdi ; ret".to_string(),
                ..CachedGadget::default()
            })
            .collect(),
    );
    let limits = CacheLimits {
        max_total_bytes: 1024,
        ..CacheLimits::default()
    };
    let c = DiskCache::open(t.path(), limits).unwrap();
    let keys: Vec<String> = (0..6)
        .map(|i| make_key(&sha256_hex(b"binary"), &format!("n={i}")))
        .collect();
    for k in &keys {
        c.store(k, &big).unwrap();
        // Distinct mtimes so "oldest first" is well defined.
        std::thread::sleep(Duration::from_millis(15));
    }
    assert!(
        c.size_on_disk().unwrap() <= 1024,
        "cache is {} bytes, over its 1024 byte budget",
        c.size_on_disk().unwrap()
    );
    assert!(c.stats().evicted > 0, "something must have been evicted");
    // The newest entry survived; the oldest did not.
    assert!(c.load(keys.last().unwrap()).is_some());
    assert!(c.load(keys.first().unwrap()).is_none());
}

#[test]
fn purge_empties_the_cache_but_keeps_the_key() {
    let t = TempDir::new("purge");
    let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();
    for i in 0..5 {
        c.store(
            &make_key(&sha256_hex(b"binary"), &format!("n={i}")),
            &one_gadget(),
        )
        .unwrap();
    }
    assert!(c.size_on_disk().unwrap() > 0);
    let (files, bytes) = c.purge().unwrap();
    assert_eq!(files, 5);
    assert!(bytes > 0);
    assert_eq!(c.size_on_disk().unwrap(), 0);
    assert!(t.path().join(KEY_FILE).exists());
}

/// If the key file is not trustworthy the cache is *disabled*, not
/// downgraded to unauthenticated reads.
#[test]
fn a_wrong_length_key_file_disables_the_cache() {
    let t = TempDir::new("badkey");
    let path = t.path().join(KEY_FILE);
    std::fs::write(&path, b"short").unwrap();
    // `std::fs::write` creates the file 0644, and `DiskCache::open` checks the
    // mode BEFORE the length, so on Unix this test used to receive the
    // permission refusal and assert against the wrong message. It passed on
    // Windows only because there is no mode check there — the first CI run
    // caught it on ubuntu-22.04 and macos-14. Narrow the file to 0600 so this
    // test exercises the length path it is named for; the mode path has its
    // own test immediately below.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let err = DiskCache::open(t.path(), CacheLimits::default()).unwrap_err();
    assert!(err.to_string().contains("expected 32"), "{err}");
}

#[cfg(unix)]
#[test]
fn a_group_readable_key_file_disables_the_cache() {
    use std::os::unix::fs::PermissionsExt;
    let t = TempDir::new("modekey");
    let path = t.path().join(KEY_FILE);
    std::fs::write(&path, [0u8; 32]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = DiskCache::open(t.path(), CacheLimits::default()).unwrap_err();
    assert!(err.to_string().contains("owner"), "{err}");
}

#[cfg(unix)]
#[test]
fn a_fresh_cache_directory_and_key_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let t = TempDir::new("modes");
    let dir = t.path().join("nested");
    let c = DiskCache::open(&dir, CacheLimits::default()).unwrap();
    c.store(&make_key(&sha256_hex(b"b"), "p"), &one_gadget())
        .unwrap();
    let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(dir.clone()), 0o700);
    assert_eq!(mode(dir.join(KEY_FILE)), 0o600);
    let entry = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().and_then(|s| s.to_str()) == Some("rfc"))
        .unwrap();
    assert_eq!(mode(entry), 0o600);
}

/// Eight writers hammering one key while a reader loops. The reader must
/// never see a half-written body: every load either misses (before the
/// first rename) or returns a fully valid entry. A single torn read shows
/// up as a `tampered` or `malformed` count.
#[test]
fn concurrent_writers_never_expose_a_torn_entry() {
    let t = TempDir::new("concurrent");
    let c = Arc::new(DiskCache::open(t.path(), CacheLimits::default()).unwrap());
    let key = Arc::new(make_key(&sha256_hex(b"binary"), "depth=10"));
    // A body big enough that a non-atomic write would be split across
    // several filesystem operations.
    let payload = scan_with(
        (0..4000)
            .map(|i| CachedGadget {
                vaddr: format!("{:x}", 0x40_0000 + i),
                bytes: "5fc3".to_string(),
                text: "pop rdi ; ret".to_string(),
                ..CachedGadget::default()
            })
            .collect(),
    );

    let stop = Arc::new(AtomicBool::new(false));
    let writers: Vec<_> = (0..8)
        .map(|_| {
            let (c, key, payload) = (c.clone(), key.clone(), payload.clone());
            std::thread::spawn(move || {
                for _ in 0..25 {
                    c.store(&key, &payload).unwrap();
                }
            })
        })
        .collect();

    let reader = {
        let (c, key, stop) = (c.clone(), key.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut hits = 0u64;
            while !stop.load(Ordering::Relaxed) {
                if let Some(scan) = c.load(&key) {
                    assert_eq!(scan.gadgets.len(), 4000, "short read");
                    hits += 1;
                }
            }
            hits
        })
    };

    for w in writers {
        w.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    let hits = reader.join().unwrap();

    let s = c.stats();
    assert_eq!(s.tampered, 0, "a torn or partial entry was observed");
    assert_eq!(s.malformed, 0, "a partial body reached the parser");
    assert!(hits > 0, "the reader never saw the entry at all");
    assert_eq!(s.store_errors, 0);
}

/// A key that is not a plain file-name stem never reaches the filesystem.
#[test]
fn a_path_like_key_is_refused() {
    let t = TempDir::new("keyname");
    let c = DiskCache::open(t.path(), CacheLimits::default()).unwrap();
    for bad in ["../escape", "a/b", "..", ".hidden", "", "a\\b"] {
        assert!(c.load(bad).is_none(), "{bad:?}");
        assert!(c.store(bad, &one_gadget()).is_err(), "{bad:?}");
    }
}

/// An entry that cannot fit inside the budget is refused rather than
/// written and then evicted on the same call.
#[test]
fn an_entry_larger_than_the_budget_is_not_written() {
    let t = TempDir::new("toobig");
    let limits = CacheLimits {
        max_total_bytes: 256,
        ..CacheLimits::default()
    };
    let c = DiskCache::open(t.path(), limits).unwrap();
    let big = scan_with(
        (0..64)
            .map(|i| CachedGadget {
                vaddr: format!("{:x}", 0x40_1000 + i),
                bytes: "5fc3".to_string(),
                text: "pop rdi ; ret".to_string(),
                ..CachedGadget::default()
            })
            .collect(),
    );
    let key = make_key(&sha256_hex(b"binary"), "depth=10");
    let err = c.store(&key, &big).unwrap_err();
    assert!(err.contains("cap for one entry"), "{err}");
    assert_eq!(c.size_on_disk().unwrap(), 0);
    assert_eq!(c.stats().store_errors, 1);
    assert_eq!(
        c.stats().evicted,
        0,
        "nothing was written, so nothing was evicted"
    );
}
