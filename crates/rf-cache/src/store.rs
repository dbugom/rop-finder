//! The on-disk cache itself: authenticated entries, restrictive
//! permissions, atomic writes, and a byte-weighted LRU with a TTL.
//!
//! Findings closed here: CLI-07/MCP-04 (entries were trusted verbatim,
//! deterministically named and mode 0644 — a fabricated
//! `pop rdi ; ret @ 0xdeadbeefcafe0000` was served through the live MCP
//! server alongside the genuine `binary_sha256`), CLI-08/PERF-12 (the CLI
//! cache grew 5.3 MB per scan configuration in the user's home, for ever,
//! with no eviction and no way to purge it).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use crate::mac::{ct_eq, hmac_sha256, MAC_LEN};
use crate::record::CachedScan;

/// File extension for entries. Deliberately *not* `.json`: the pre-v0.2
/// cache wrote unauthenticated `.json` files, and those must be ignored
/// rather than parsed.
const ENTRY_EXT: &str = "rfc";
/// Entry frame: `MAGIC || tag[32] || body`.
const MAGIC: &[u8; 8] = b"RFCACHE\x02";
/// Name of the entry-authentication key inside the cache directory.
pub const KEY_FILE: &str = ".cachekey";
/// Length of that key.
const KEY_LEN: usize = 32;

/// Default total on-disk budget for cache entries.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
/// Default entry lifetime.
pub const DEFAULT_TTL: Duration = Duration::from_secs(14 * 24 * 60 * 60);
/// Default per-entry cap. Enforced by `stat` *before* the file is read, so
/// an oversized entry never costs the memory it claims.
pub const DEFAULT_MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// CLI-08/PERF-12 budget.
#[derive(Debug, Clone, Copy)]
pub struct CacheLimits {
    /// Total on-disk budget; the LRU evicts to stay under it.
    pub max_total_bytes: u64,
    /// How long an entry stays usable.
    pub ttl: Duration,
    /// Largest single entry that will be stored at all.
    pub max_entry_bytes: u64,
}

impl Default for CacheLimits {
    fn default() -> Self {
        CacheLimits {
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            ttl: DEFAULT_TTL,
            max_entry_bytes: DEFAULT_MAX_ENTRY_BYTES,
        }
    }
}

impl CacheLimits {
    /// Defaults, overridable by `ROP_FINDER_CACHE_MAX_BYTES` and
    /// `ROP_FINDER_CACHE_TTL_SECS`. Environment rather than flags because
    /// both front ends need them and neither has a settings file; a bad
    /// value is ignored rather than being a startup error.
    #[must_use]
    pub fn from_env() -> Self {
        let mut l = CacheLimits::default();
        if let Some(v) = std::env::var("ROP_FINDER_CACHE_MAX_BYTES")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            l.max_total_bytes = v;
        }
        if let Some(v) = std::env::var("ROP_FINDER_CACHE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            l.ttl = Duration::from_secs(v);
        }
        l
    }
}

/// Counters. `tampered` is the one that matters: it is non-zero only when
/// a file in the cache directory carried a body the cache did not write.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Lookups served from disk.
    pub hits: u64,
    /// Lookups that found nothing usable.
    pub misses: u64,
    /// Entries whose HMAC tag did not verify, or whose frame was not one
    /// this program writes (wrong magic, truncated).
    pub tampered: u64,
    /// Entries that authenticated but did not [`CachedScan::validate`].
    pub malformed: u64,
    /// Entries dropped because they were older than the TTL.
    pub expired: u64,
    /// Entries written.
    pub stored: u64,
    /// Writes that failed (a full or read-only directory).
    pub store_errors: u64,
    /// Entries dropped to stay under `max_total_bytes`.
    pub evicted: u64,
    /// Bytes reclaimed by those evictions.
    pub evicted_bytes: u64,
}

/// Why the on-disk cache is not available. The caller warns and continues
/// **without** a cache: an unauthenticated read is never the fallback.
#[derive(Debug, Clone)]
pub struct OpenError(String);

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OpenError {}

/// An opened, authenticated cache directory.
#[derive(Debug)]
pub struct DiskCache {
    dir: PathBuf,
    mac_key: [u8; KEY_LEN],
    limits: CacheLimits,
    stats: Mutex<CacheStats>,
    /// Monotonic suffix so two threads in one process never pick the same
    /// temp name.
    seq: AtomicU64,
}

impl DiskCache {
    /// Open (creating if necessary) the cache directory at `dir`.
    ///
    /// Fails — meaning *disable the cache*, not *fall back to
    /// unauthenticated reads* — when the directory belongs to another
    /// user, when it cannot be made private, or when the key file is
    /// absent-and-uncreatable, the wrong length, or readable by anyone
    /// but the owner.
    pub fn open(dir: impl Into<PathBuf>, limits: CacheLimits) -> Result<Self, OpenError> {
        let dir = dir.into();
        create_private_dir(&dir)?;
        check_dir_owner(&dir)?;
        let mac_key = load_or_create_key(&dir)?;
        Ok(DiskCache {
            dir,
            mac_key,
            limits,
            stats: Mutex::new(CacheStats::default()),
            seq: AtomicU64::new(0),
        })
    }

    /// The directory this cache lives in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The budget this cache was opened with.
    #[must_use]
    pub fn limits(&self) -> CacheLimits {
        self.limits
    }

    /// Snapshot of the counters.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        *self.lock()
    }

    /// Poisoned-mutex policy for every cache lock: take the inner value.
    /// The counters are plain integers, so a panic elsewhere cannot have
    /// left them in a state that makes the *next* scan wrong, and
    /// `.lock().unwrap()` would turn one unrelated panic into a permanent
    /// failure of the whole cache.
    fn lock(&self) -> std::sync::MutexGuard<'_, CacheStats> {
        self.stats.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn bump(&self, f: impl FnOnce(&mut CacheStats)) {
        f(&mut self.lock());
    }

    fn entry_path(&self, key: &str) -> Option<PathBuf> {
        // A key reaches the filesystem, so it is checked as a name and not
        // trusted to be one: no separators, no `..`, no drive letters.
        if key.is_empty()
            || key.len() > 256
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            || key.starts_with('.')
            || key.contains("..")
        {
            return None;
        }
        Some(self.dir.join(format!("{key}.{ENTRY_EXT}")))
    }

    /// Load and authenticate the entry for `key`.
    ///
    /// Every failure path — absent, expired, oversized, truncated, wrong
    /// magic, bad tag, or a body that does not validate — returns `None`.
    /// A tag mismatch also warns on stderr and bumps
    /// [`CacheStats::tampered`].
    #[must_use]
    pub fn load(&self, key: &str) -> Option<CachedScan> {
        let raw = self.load_body(key)?;
        match serde_json::from_slice::<CachedScan>(&raw) {
            Ok(scan) => match scan.validate() {
                Ok(()) => {
                    self.bump(|s| s.hits += 1);
                    Some(scan)
                }
                Err(why) => {
                    self.reject(key, &format!("entry did not validate: {why}"), true);
                    None
                }
            },
            Err(e) => {
                self.reject(key, &format!("entry is not valid JSON: {e}"), true);
                None
            }
        }
    }

    /// Store `scan` under `key`, atomically and authenticated.
    pub fn store(&self, key: &str, scan: &CachedScan) -> Result<(), String> {
        let body = serde_json::to_vec(scan).map_err(|e| format!("serialize: {e}"))?;
        self.store_body(key, &body)
    }

    /// Delete every entry. Returns `(files, bytes)` removed. The key file
    /// survives, so a purge does not invalidate anything an operator has
    /// backed up out of band — it just empties the cache.
    pub fn purge(&self) -> Result<(u64, u64), String> {
        let mut files = 0;
        let mut bytes = 0;
        for (path, _, len) in self.entries()? {
            if fs::remove_file(&path).is_ok() {
                files += 1;
                bytes += len;
            }
        }
        self.bump(|s| {
            s.evicted += files;
            s.evicted_bytes += bytes;
        });
        Ok((files, bytes))
    }

    /// Total bytes currently held by entries.
    pub fn size_on_disk(&self) -> Result<u64, String> {
        Ok(self.entries()?.iter().map(|(_, _, len)| *len).sum())
    }

    // -- internals ---------------------------------------------------

    fn load_body(&self, key: &str) -> Option<Vec<u8>> {
        let path = self.entry_path(key)?;
        let Ok(meta) = fs::metadata(&path) else {
            self.bump(|s| s.misses += 1);
            return None;
        };
        if meta.len() > self.limits.max_entry_bytes.saturating_add(64) {
            // Refused by `stat`, before a byte is read.
            self.reject(key, "entry is larger than the per-entry cap", true);
            return None;
        }
        if age(&meta).is_some_and(|a| a > self.limits.ttl) {
            let _ = fs::remove_file(&path);
            self.bump(|s| {
                s.expired += 1;
                s.misses += 1;
            });
            return None;
        }
        let Ok(raw) = fs::read(&path) else {
            self.bump(|s| s.misses += 1);
            return None;
        };
        let (Some(magic), Some(tag), Some(body)) = (
            raw.get(..MAGIC.len()),
            raw.get(MAGIC.len()..MAGIC.len() + MAC_LEN),
            raw.get(MAGIC.len() + MAC_LEN..),
        ) else {
            // Truncated file: shorter than the frame header.
            self.reject(key, "entry is truncated", false);
            return None;
        };
        if magic != MAGIC.as_slice() {
            self.reject(key, "entry has the wrong frame magic", false);
            return None;
        }
        if !ct_eq(tag, &self.tag(key, body)) {
            self.reject(key, "entry failed its integrity check", false);
            return None;
        }
        // LRU recency: the cache has no atime it can rely on (noatime,
        // relatime, Windows defaults), so a hit republishes mtime and
        // eviction is oldest-mtime-first. Best effort — a read-only
        // directory still serves hits, it just evicts in the wrong order.
        if let Ok(f) = File::options().write(true).open(&path) {
            let _ = f.set_modified(SystemTime::now());
        }
        Some(body.to_vec())
    }

    fn store_body(&self, key: &str, body: &[u8]) -> Result<(), String> {
        let Some(path) = self.entry_path(key) else {
            self.bump(|s| s.store_errors += 1);
            return Err(format!("refusing to use {key:?} as a cache file name"));
        };
        // An entry larger than the whole budget would be written and then
        // immediately evicted by `enforce_budget`, which is pure I/O for
        // nothing and reads as "stored" in the log. Refuse it up front.
        let cap = self.limits.max_entry_bytes.min(self.limits.max_total_bytes);
        if body.len() as u64 > cap {
            self.bump(|s| s.store_errors += 1);
            return Err(format!(
                "result is {} bytes, over the {cap} byte cap for one entry; not cached",
                body.len(),
            ));
        }
        let mut framed = Vec::with_capacity(MAGIC.len() + MAC_LEN + body.len());
        framed.extend_from_slice(MAGIC);
        framed.extend_from_slice(&self.tag(key, body));
        framed.extend_from_slice(body);

        self.persist_atomically(&path, &framed).map_err(|e| {
            self.bump(|s| s.store_errors += 1);
            format!("{e}")
        })?;
        self.bump(|s| s.stored += 1);
        // Eviction runs after the write, so the entry just stored counts
        // against the budget like any other.
        if let Err(e) = self.enforce_budget() {
            return Err(format!("stored, but eviction failed: {e}"));
        }
        Ok(())
    }

    /// The authenticated message is `key || 0x00 || body`. The NUL keeps
    /// the two fields unambiguous, and binding the key means an entry
    /// cannot be renamed onto a different scan configuration.
    fn tag(&self, key: &str, body: &[u8]) -> [u8; MAC_LEN] {
        let mut msg = Vec::with_capacity(key.len() + 1 + body.len());
        msg.extend_from_slice(key.as_bytes());
        msg.push(0);
        msg.extend_from_slice(body);
        hmac_sha256(&self.mac_key, &msg)
    }

    /// Write to a fresh private file and rename over the entry, so a
    /// concurrent reader sees either the whole old entry or the whole new
    /// one — never a half-written body, and never a body with a tag from a
    /// different write.
    fn persist_atomically(&self, path: &Path, framed: &[u8]) -> std::io::Result<()> {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let tmp = self
            .dir
            .join(format!(".tmp-{}-{n}-{nanos:x}", std::process::id()));
        {
            let mut f = private_create_new(&tmp)?;
            f.write_all(framed)?;
            f.sync_all()?;
        }
        // Windows can transiently refuse the replace while another handle
        // is closing; std's rename replaces an existing destination on
        // both platforms, so this is the whole atomicity story.
        let mut last = None;
        for _ in 0..32 {
            match fs::rename(&tmp, path) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last = Some(e);
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
        let _ = fs::remove_file(&tmp);
        Err(last.unwrap_or_else(|| std::io::Error::other("rename failed")))
    }

    /// `(path, mtime, len)` for every entry.
    fn entries(&self) -> Result<Vec<(PathBuf, SystemTime, u64)>, String> {
        let rd = match fs::read_dir(&self.dir) {
            Ok(rd) => rd,
            Err(e) => return Err(format!("{}: {e}", self.dir.display())),
        };
        let mut out = Vec::new();
        for e in rd.flatten() {
            let path = e.path();
            if path.extension().and_then(|s| s.to_str()) != Some(ENTRY_EXT) {
                continue;
            }
            if let Ok(meta) = e.metadata() {
                let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                out.push((path, mtime, meta.len()));
            }
        }
        Ok(out)
    }

    /// CLI-08/PERF-12: drop expired entries, then evict oldest-first until
    /// the directory is inside the byte budget.
    fn enforce_budget(&self) -> Result<(), String> {
        let mut entries = self.entries()?;
        let now = SystemTime::now();
        let mut evicted = 0u64;
        let mut evicted_bytes = 0u64;
        entries.retain(|(path, mtime, len)| {
            let expired = now
                .duration_since(*mtime)
                .is_ok_and(|a| a > self.limits.ttl);
            if expired && fs::remove_file(path).is_ok() {
                evicted += 1;
                evicted_bytes += *len;
                return false;
            }
            true
        });
        let mut total: u64 = entries.iter().map(|(_, _, len)| *len).sum();
        if total > self.limits.max_total_bytes {
            // Byte-weighted LRU: least recently *used*, because a hit
            // republishes mtime.
            entries.sort_by_key(|(_, mtime, _)| *mtime);
            for (path, _, len) in &entries {
                if total <= self.limits.max_total_bytes {
                    break;
                }
                if fs::remove_file(path).is_ok() {
                    total = total.saturating_sub(*len);
                    evicted += 1;
                    evicted_bytes += *len;
                }
            }
        }
        if evicted > 0 {
            self.bump(|s| {
                s.evicted += evicted;
                s.evicted_bytes += evicted_bytes;
            });
        }
        Ok(())
    }

    /// One place for "this entry is not usable": counter, warning, miss.
    /// Never an error, and never a served result.
    fn reject(&self, key: &str, why: &str, authenticated: bool) {
        self.bump(|s| {
            s.misses += 1;
            if authenticated {
                s.malformed += 1;
            } else {
                s.tampered += 1;
            }
        });
        eprintln!(
            "[Cache] warning: {} for {} — ignoring it and rescanning",
            why,
            crate::key_prefix(key)
        );
    }
}

fn age(meta: &fs::Metadata) -> Option<Duration> {
    SystemTime::now().duration_since(meta.modified().ok()?).ok()
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<(), OpenError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| OpenError(format!("cannot create {}: {e}", dir.display())))?;
    }
    let meta =
        fs::metadata(dir).map_err(|e| OpenError(format!("cannot stat {}: {e}", dir.display())))?;
    if !meta.is_dir() {
        return Err(OpenError(format!("{} is not a directory", dir.display())));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            OpenError(format!(
                "{} is group/world accessible and cannot be tightened: {e}",
                dir.display()
            ))
        })?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<(), OpenError> {
    // Windows: a directory created under %LOCALAPPDATA% inherits that
    // profile's DACL, which grants the owning user and denies other
    // non-administrative users. There is no portable chmod, and building a
    // DACL by hand needs the Win32 security APIs; this is the documented
    // best-effort half of CLI-07. The HMAC is what actually keeps a
    // poisoned entry out of the output, and it is platform-independent.
    fs::create_dir_all(dir).map_err(|e| OpenError(format!("cannot create {}: {e}", dir.display())))
}

#[cfg(unix)]
fn check_dir_owner(dir: &Path) -> Result<(), OpenError> {
    use std::os::unix::fs::MetadataExt;
    let meta =
        fs::metadata(dir).map_err(|e| OpenError(format!("cannot stat {}: {e}", dir.display())))?;
    let me = rustix::process::getuid().as_raw();
    if meta.uid() != me {
        return Err(OpenError(format!(
            "{} is owned by uid {}, not by uid {me}",
            dir.display(),
            meta.uid()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_dir_owner(_dir: &Path) -> Result<(), OpenError> {
    Ok(())
}

#[cfg(unix)]
fn private_create_new(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn private_create_new(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Read the entry-authentication key, creating it on first use.
///
/// The three refusals — absent-and-uncreatable, wrong length, and
/// group/world readable — all disable the cache. That is the point: with
/// no trustworthy key there is no way to tell a genuine entry from a
/// planted one, and serving unauthenticated entries "just this once" is
/// exactly the CLI-07 bug.
fn load_or_create_key(dir: &Path) -> Result<[u8; KEY_LEN], OpenError> {
    let path = dir.join(KEY_FILE);
    match private_create_new(&path) {
        Ok(mut f) => {
            let mut key = [0u8; KEY_LEN];
            getrandom::fill(&mut key)
                .map_err(|e| OpenError(format!("no OS randomness for the cache key: {e}")))?;
            f.write_all(&key)
                .and_then(|()| f.sync_all())
                .map_err(|e| OpenError(format!("cannot write {}: {e}", path.display())))?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_key(&path),
        Err(e) => Err(OpenError(format!("cannot create {}: {e}", path.display()))),
    }
}

fn read_key(path: &Path) -> Result<[u8; KEY_LEN], OpenError> {
    let meta = fs::metadata(path)
        .map_err(|e| OpenError(format!("cannot stat {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(OpenError(format!(
                "{} is mode {:o}; it must be readable only by its owner",
                path.display(),
                mode & 0o777
            )));
        }
    }
    if meta.len() != KEY_LEN as u64 {
        return Err(OpenError(format!(
            "{} is {} bytes; expected {KEY_LEN}",
            path.display(),
            meta.len()
        )));
    }
    let raw =
        fs::read(path).map_err(|e| OpenError(format!("cannot read {}: {e}", path.display())))?;
    let mut key = [0u8; KEY_LEN];
    if raw.len() != KEY_LEN {
        return Err(OpenError(format!(
            "{} is {} bytes; expected {KEY_LEN}",
            path.display(),
            raw.len()
        )));
    }
    for (dst, src) in key.iter_mut().zip(raw.iter()) {
        *dst = *src;
    }
    Ok(key)
}
