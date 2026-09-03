//! Path confinement for the MCP server (MCP-01 / MCP-07).
//!
//! The old `confine_path` canonicalized a *string* and handed back a
//! `PathBuf`; the file was re-opened by name later, on another thread,
//! inside a `spawn_blocking` closure. Nothing pinned the inode, so any
//! process able to create a name inside an allowed directory could swap it
//! between the check and the read (measured: 323 of 400 requests read a
//! file outside the allowlist — docs/AUDIT-FINDINGS.md MCP-01).
//!
//! This module replaces it with an open-then-verify API. [`open_confined`]
//! returns a [`ConfinedFile`] holding an open handle; the caller reads from
//! the handle and the path is never resolved a second time.
//!
//! Three phases, in this order:
//!
//! 1. **Lexical, zero syscalls.** The input must be absolute, must contain
//!    no `.`/`..` component and no interior NUL, and on Windows must not use
//!    a `\\?\` / `\\.\` / UNC prefix nor carry a `:` after the drive letter
//!    (alternate data streams). The allow root is selected by *component-wise*
//!    match on [`std::path::Component`], never by string prefix, so the root
//!    `/allowed` does not admit `/allowed-evil/x`. A path outside every root
//!    is rejected here, with no filesystem access at all — that is what stops
//!    the error taxonomy from being a whole-filesystem existence oracle
//!    (MCP-07).
//! 2. **Open, pinned to the root.** On Unix each remaining component is
//!    opened with `openat(O_RDONLY|O_NOFOLLOW|O_CLOEXEC)` from the directory
//!    descriptor pinned at startup, so no name is ever resolved twice and the
//!    resulting descriptor is provably a descendant of the root. On Windows
//!    there is no `openat`, so the file is opened once and then the *handle*
//!    is validated: `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED |
//!    VOLUME_NAME_GUID)` must still be under the root's own final path,
//!    `GetFileType` must be `FILE_TYPE_DISK`, and the volume serial must
//!    match the root's.
//! 3. **fstat the handle** (`File::metadata`, not `stat` on a name): a
//!    regular file — which also rejects FIFOs, on which `std::fs::read` would
//!    block forever — of at most `max_bytes`.
//!
//! Every failure in phases 2 and 3 maps to the same `path_denied` code and
//! the same message as a phase-1 rejection, with no OS error text, unless
//! the operator started the server with `--verbose-path-errors`; verbose
//! detail is only ever produced for a path that already selected a root.

use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde_json::json;

use crate::schema::ErrorCode;
use crate::ToolError;

/// Root identity as recorded at startup: `(dev, ino)` on Unix,
/// `(volume serial, file index)` on Windows. Used to reject duplicate
/// `--allow-dir` entries that name the same directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RootId(pub u64, pub u64);

/// A directory the agent may read binaries from, pinned open for the
/// lifetime of the process so the root itself cannot be renamed or
/// replaced underneath us.
#[derive(Debug)]
pub struct AllowRoot {
    /// Canonical path used to build the path actually opened (Windows) —
    /// may be in `\\?\` verbatim form.
    #[cfg_attr(unix, allow(dead_code))]
    canon: PathBuf,
    /// De-verbatimized canonical path, used for lexical matching and for
    /// anything the operator or the agent is shown.
    display: PathBuf,
    /// Pinned directory handle. On Unix this is the dirfd every `openat`
    /// walk starts from.
    #[cfg_attr(windows, allow(dead_code))]
    dir: std::fs::File,
    id: RootId,
    /// Windows: `GetFinalPathNameByHandleW(VOLUME_NAME_GUID)` of `dir`,
    /// taken once at startup and compared against every opened handle.
    #[cfg(windows)]
    final_path: PathBuf,
}

impl AllowRoot {
    /// Canonicalize `path`, open it, and pin the handle. The directory is
    /// held open for the lifetime of the returned value.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let canon = path.canonicalize()?;
        if !canon.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "not a directory",
            ));
        }
        let dir = open_dir(&canon)?;
        let id = identity_of(&dir)?;
        let display = dedevirtualize(&canon);
        #[cfg(windows)]
        let final_path = final_path_of(&dir)?;
        Ok(AllowRoot {
            canon,
            display,
            dir,
            id,
            #[cfg(windows)]
            final_path,
        })
    }

    /// Startup identity of the pinned directory.
    pub fn id(&self) -> RootId {
        self.id
    }

    /// Operator-facing canonical path (no `\\?\` prefix).
    pub fn display_path(&self) -> &Path {
        &self.display
    }
}

/// An open, confined file. The handle — not a name — is what crosses into
/// the blocking worker.
#[derive(Debug)]
pub struct ConfinedFile {
    pub file: std::fs::File,
    pub len: u64,
    /// Root-relative label, for logs and error text. Never re-opened.
    pub label: String,
}

impl ConfinedFile {
    /// Read the whole file from the pinned handle, refusing anything that
    /// grew past `max_bytes` between the fstat and the read.
    pub fn read_all(mut self, max_bytes: u64) -> Result<Vec<u8>, ToolError> {
        let mut buf = Vec::with_capacity(self.len.min(max_bytes) as usize);
        (&mut self.file)
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|_| denied_read())?;
        if buf.len() as u64 > max_bytes {
            return Err(ToolError::with_details(
                ErrorCode::ResourceExhausted,
                format!("binary exceeds the {max_bytes}-byte --max-file-bytes cap"),
                json!({"limit": "max_file_bytes", "limit_value": max_bytes}),
            )
            .with_kind("file_too_large"));
        }
        Ok(buf)
    }
}

/// The one and only rejection an out-of-allowlist path ever produces.
///
/// It carries no information about the target: not whether it exists, not
/// whether it is a file or a directory, not an errno.
pub fn path_denied(roots: &[AllowRoot]) -> ToolError {
    let list: Vec<String> = roots
        .iter()
        .map(|r| r.display_path().display().to_string())
        .collect();
    ToolError::with_details(
        ErrorCode::PathDenied,
        format!(
            "binary_path is not inside an allowed directory. Allowed: [{}]. \
             Call get_server_config for the effective allowlist.",
            list.join(", ")
        ),
        json!({ "allow_roots": list }),
    )
}

fn denied_read() -> ToolError {
    ToolError::new(
        ErrorCode::UnsupportedBinary,
        "cannot read the confined binary",
    )
    .with_kind("io_error")
}

/// Open a file confined to `roots` and return its handle.
///
/// See the module documentation for the three phases. Failures never
/// distinguish absent / directory / unreadable / not-a-regular-file.
pub fn open_confined(
    roots: &[AllowRoot],
    input: &str,
    max_bytes: u64,
) -> Result<ConfinedFile, ToolError> {
    open_confined_with(roots, input, max_bytes, false)
}

/// [`open_confined`] with the `--verbose-path-errors` escape hatch. Verbose
/// detail is only ever emitted for an input that already selected a root,
/// so it can never describe a path outside the allowlist.
pub fn open_confined_with(
    roots: &[AllowRoot],
    input: &str,
    max_bytes: u64,
    verbose: bool,
) -> Result<ConfinedFile, ToolError> {
    // PHASE 1 — lexical. No syscalls.
    let (root, rest) = select_root(roots, input).ok_or_else(|| path_denied(roots))?;
    let label = rest
        .iter()
        .map(|c| c.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/");

    let vlabel = label.clone();
    let detail = |what: &str| -> ToolError {
        if verbose {
            ToolError::with_details(
                ErrorCode::PathDenied,
                format!(
                    "{vlabel:?} is inside allow root {} but could not be opened: {what}",
                    root.display_path().display()
                ),
                json!({"allow_roots": [root.display_path().display().to_string()],
                       "verbose_reason": what}),
            )
        } else {
            path_denied(roots)
        }
    };

    // PHASE 2 — open, pinned to the root.
    let file = open_within(root, &rest).map_err(|e| detail(&e))?;

    // PHASE 3 — fstat the HANDLE, never a name.
    let md = file.metadata().map_err(|_| detail("fstat failed"))?;
    if !md.is_file() {
        return Err(detail("not a regular file"));
    }
    let len = md.len();
    if len > max_bytes {
        return Err(ToolError::with_details(
            ErrorCode::ResourceExhausted,
            format!("binary is {len} bytes; the --max-file-bytes cap is {max_bytes}"),
            json!({"limit": "max_file_bytes", "limit_value": max_bytes, "got": len}),
        )
        .with_kind("file_too_large"));
    }
    Ok(ConfinedFile { file, len, label })
}

// ---------------------------------------------------------------------------
// Phase 1 — lexical
// ---------------------------------------------------------------------------

/// Component-wise root selection. Returns the matched root and the
/// remaining components. Performs no filesystem access whatsoever.
fn select_root<'a>(
    roots: &'a [AllowRoot],
    input: &str,
) -> Option<(&'a AllowRoot, Vec<std::ffi::OsString>)> {
    if input.contains('\0') {
        return None;
    }
    // `Path::components` silently normalizes away interior "." segments, so
    // the raw string is checked as well; "." and ".." are both refused
    // outright rather than resolved.
    let seps: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    if input.split(seps).any(|seg| seg == "." || seg == "..") {
        return None;
    }
    let p = Path::new(input);
    if !p.is_absolute() {
        return None;
    }
    let mut parts: Vec<Component<'_>> = Vec::new();
    for c in p.components() {
        match c {
            Component::CurDir | Component::ParentDir => return None,
            Component::Prefix(prefix) => {
                if !prefix_is_plain(&prefix) {
                    return None;
                }
                parts.push(c);
            }
            Component::RootDir => parts.push(c),
            Component::Normal(name) => {
                // Windows: a ':' after the drive letter is an alternate
                // data stream (`x.bin:secret`) or a device qualifier.
                if cfg!(windows) && name.to_string_lossy().contains(':') {
                    return None;
                }
                parts.push(c);
            }
        }
    }
    for root in roots {
        let rootc: Vec<Component<'_>> = root.display.components().collect();
        if rootc.is_empty() || parts.len() <= rootc.len() {
            continue;
        }
        if rootc
            .iter()
            .zip(parts.iter())
            .all(|(a, b)| components_eq(a, b))
        {
            let rest = parts[rootc.len()..]
                .iter()
                .map(|c| c.as_os_str().to_os_string())
                .collect();
            return Some((root, rest));
        }
    }
    None
}

/// `true` for an ordinary drive-letter prefix; `false` for verbatim
/// (`\\?\`), device (`\\.\`) and UNC prefixes.
#[cfg(windows)]
fn prefix_is_plain(p: &std::path::PrefixComponent<'_>) -> bool {
    matches!(p.kind(), std::path::Prefix::Disk(_))
}

#[cfg(not(windows))]
fn prefix_is_plain(_p: &std::path::PrefixComponent<'_>) -> bool {
    // Unix paths have no prefix component; if one somehow appears, refuse.
    false
}

/// Root *selection* is case-insensitive on the platforms whose default
/// filesystem is (NTFS, APFS). It is only ever used to choose a root — the
/// components handed to `openat` are the caller's own bytes.
fn components_eq(a: &Component<'_>, b: &Component<'_>) -> bool {
    if cfg!(any(windows, target_os = "macos")) {
        let (x, y) = (a.as_os_str(), b.as_os_str());
        x.len() == y.len()
            && x.to_string_lossy()
                .eq_ignore_ascii_case(&y.to_string_lossy())
    } else {
        a == b
    }
}

/// Strip a Windows `\\?\` verbatim prefix so canonical roots compare
/// against the ordinary absolute paths an agent sends.
fn dedevirtualize(p: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let s = p.as_os_str().to_string_lossy().into_owned();
        if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
    }
    p.to_path_buf()
}

// ---------------------------------------------------------------------------
// Phase 2 — Unix: openat walk from the pinned dirfd
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn open_dir(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(unix)]
fn identity_of(f: &std::fs::File) -> std::io::Result<RootId> {
    use std::os::unix::fs::MetadataExt;
    let md = f.metadata()?;
    Ok(RootId(md.dev(), md.ino()))
}

/// Walk `rest` from the root's pinned descriptor, one `openat` per
/// component with `O_NOFOLLOW`. Because no name is resolved twice and
/// `..` was rejected lexically, the descriptor returned is provably a
/// descendant of the pinned root: there is no window in which a rename or
/// a freshly-created symlink can redirect it.
#[cfg(unix)]
fn open_within(root: &AllowRoot, rest: &[std::ffi::OsString]) -> Result<std::fs::File, String> {
    use rustix::fs::{openat, Mode, OFlags};
    use std::os::fd::{AsFd, OwnedFd};

    let Some((last, dirs)) = rest.split_last() else {
        return Err("path names the allow root itself".to_string());
    };
    let mut cur: Option<OwnedFd> = None;
    for comp in dirs {
        let fd = openat(
            cur.as_ref().map_or_else(|| root.dir.as_fd(), AsFd::as_fd),
            comp.as_os_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "cannot descend".to_string())?;
        cur = Some(fd);
    }
    // NONBLOCK on the final hop so a FIFO planted inside an allowed root
    // cannot wedge the worker in `open(2)`; phase 3 then rejects it for not
    // being a regular file. It is a no-op for regular files.
    let fd = openat(
        cur.as_ref().map_or_else(|| root.dir.as_fd(), AsFd::as_fd),
        last.as_os_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| "cannot open".to_string())?;
    Ok(std::fs::File::from(fd))
}

// ---------------------------------------------------------------------------
// Phase 2 — Windows: open once, then validate the HANDLE
// ---------------------------------------------------------------------------

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION;

#[cfg(windows)]
fn open_dir(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// Windows identity comes from `GetFileInformationByHandle` on the open
/// handle, not from `Metadata` (whose `volume_serial_number`/`file_index`
/// accessors are still unstable) and never from a path.
#[cfg(windows)]
fn identity_of(f: &std::fs::File) -> std::io::Result<RootId> {
    let info = file_info(f)?;
    Ok(RootId(
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

/// `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_GUID)` —
/// the true object path of an *open handle*, after every reparse point.
#[cfg(windows)]
fn final_path_of(f: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_GUID,
    };

    let h = f.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_GUID;
    // SAFETY: `h` is a live handle owned by `f`; the first call passes a
    // null buffer of length 0, which the API documents as "return the
    // required length".
    let need = unsafe { GetFinalPathNameByHandleW(h, std::ptr::null_mut(), 0, flags) };
    if need == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = vec![0u16; need as usize + 1];
    // SAFETY: `buf` has `need + 1` u16 slots, which is at least what the
    // probing call above asked for.
    let got = unsafe { GetFinalPathNameByHandleW(h, buf.as_mut_ptr(), need + 1, flags) };
    if got == 0 || got > need + 1 {
        return Err(std::io::Error::last_os_error());
    }
    buf.truncate(got as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf)))
}

#[cfg(windows)]
fn file_info(f: &std::fs::File) -> std::io::Result<BY_HANDLE_FILE_INFORMATION> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle;

    let h = f.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    // SAFETY: `h` is a live handle owned by `f` and `info` is a correctly
    // sized, writable out-parameter. `BY_HANDLE_FILE_INFORMATION` is a
    // plain-old-data struct, so an all-zero value is valid.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(h, &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(info)
}

/// Windows has no `openat`, so confinement is proved on the *handle*
/// rather than on the name: the file is opened once from the root's own
/// canonical path, and the resulting handle must still resolve — via
/// `GetFinalPathNameByHandleW` — to an object underneath the root's
/// startup final path, on the same volume, of type `FILE_TYPE_DISK`.
/// Because both the name and the identity come from the open handle,
/// nothing can be swapped after the check.
#[cfg(windows)]
fn open_within(root: &AllowRoot, rest: &[std::ffi::OsString]) -> Result<std::fs::File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileType, FILE_FLAG_BACKUP_SEMANTICS, FILE_TYPE_DISK,
    };

    if rest.is_empty() {
        return Err("path names the allow root itself".to_string());
    }
    let mut target = root.canon.clone();
    for c in rest {
        target.push(c);
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(&target)
        .map_err(|_| "cannot open".to_string())?;

    let h = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    // SAFETY: `h` is a live handle owned by `file`.
    if unsafe { GetFileType(h) } != FILE_TYPE_DISK {
        return Err("not a disk file (pipe, console or device)".to_string());
    }
    let info = file_info(&file).map_err(|_| "cannot stat handle".to_string())?;
    if u64::from(info.dwVolumeSerialNumber) != root.id.0 {
        return Err("file is on a different volume than the allow root".to_string());
    }
    let final_path = final_path_of(&file).map_err(|_| "cannot resolve handle".to_string())?;
    if !under_final_path(&root.final_path, &final_path) {
        return Err("handle resolves outside the allow root".to_string());
    }
    Ok(file)
}

/// Component-wise, case-insensitive containment of two
/// `GetFinalPathNameByHandleW` results.
#[cfg(windows)]
fn under_final_path(root: &Path, target: &Path) -> bool {
    let rc: Vec<Component<'_>> = root.components().collect();
    let tc: Vec<Component<'_>> = target.components().collect();
    !rc.is_empty()
        && tc.len() > rc.len()
        && rc.iter().zip(tc.iter()).all(|(a, b)| components_eq(a, b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique temp dir per test, cleaned up on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let raw = std::env::temp_dir().join(format!(
                "rf-mcp-confine-{}-{}-{}",
                tag,
                std::process::id(),
                n
            ));
            let _ = std::fs::remove_dir_all(&raw);
            std::fs::create_dir_all(&raw).unwrap();
            TempDir(raw.canonicalize().unwrap())
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

    const CAP: u64 = 1 << 20;

    /// Ordinary (non-verbatim) absolute path an agent would actually send.
    fn plain(p: &Path) -> String {
        dedevirtualize(p).display().to_string()
    }

    #[test]
    fn accepts_a_file_inside_the_root() {
        let t = TempDir::new("ok");
        let root = t.path().join("allowed");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.bin"), b"MZ").unwrap();
        let roots = vec![AllowRoot::open(&root).unwrap()];
        let cf = open_confined(&roots, &plain(&root.join("a.bin")), CAP).unwrap();
        assert_eq!(cf.len, 2);
        assert_eq!(cf.label, "a.bin");
        assert_eq!(cf.read_all(CAP).unwrap(), b"MZ");
    }

    #[test]
    fn nested_components_resolve() {
        let t = TempDir::new("nested");
        let root = t.path().join("allowed");
        std::fs::create_dir_all(root.join("sub/deeper")).unwrap();
        std::fs::write(root.join("sub/deeper/b.bin"), b"ELF").unwrap();
        let roots = vec![AllowRoot::open(&root).unwrap()];
        let cf = open_confined(&roots, &plain(&root.join("sub/deeper/b.bin")), CAP).unwrap();
        assert_eq!(cf.read_all(CAP).unwrap(), b"ELF");
    }

    /// MCP-01 regression: the root `/allowed` must not admit
    /// `/allowed-evil/x`. A string `starts_with` would let this through.
    #[test]
    fn root_prefix_is_component_wise() {
        let t = TempDir::new("prefix");
        let root = t.path().join("allowed");
        let evil = t.path().join("allowed-evil");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&evil).unwrap();
        std::fs::write(evil.join("x.bin"), b"secret").unwrap();
        let roots = vec![AllowRoot::open(&root).unwrap()];
        let err = open_confined(&roots, &plain(&evil.join("x.bin")), CAP).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathDenied);
    }

    /// MCP-07 regression: absent / directory / existing-file outside the
    /// allowlist must be indistinguishable, and must cost no syscall.
    #[test]
    fn outside_paths_are_one_indistinguishable_code() {
        let t = TempDir::new("oracle");
        let root = t.path().join("allowed");
        let outside = t.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(outside.join("adir")).unwrap();
        std::fs::write(outside.join("afile"), b"x").unwrap();
        let roots = vec![AllowRoot::open(&root).unwrap()];

        let bodies: Vec<String> = ["afile", "adir", "absent"]
            .iter()
            .map(|n| {
                let e = open_confined(&roots, &plain(&outside.join(n)), CAP).unwrap_err();
                e.to_json().to_string()
            })
            .collect();
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[1], bodies[2]);
        for b in &bodies {
            assert!(!b.contains("No such file"), "{b}");
            assert!(!b.contains("os error"), "{b}");
            assert!(!b.contains("canonicalize"), "{b}");
            assert!(!b.contains("is not a regular file"), "{b}");
        }
    }

    #[test]
    fn relative_dotdot_and_nul_are_rejected_lexically() {
        let t = TempDir::new("lex");
        let root = t.path().join("allowed");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.bin"), b"MZ").unwrap();
        let roots = vec![AllowRoot::open(&root).unwrap()];
        let base = plain(&root);

        for bad in [
            "a.bin".to_string(),
            format!("{base}/../allowed/a.bin"),
            format!("{base}/./a.bin"),
            format!("{base}/a\0.bin"),
        ] {
            let err = open_confined(&roots, &bad, CAP).unwrap_err();
            assert_eq!(err.code, ErrorCode::PathDenied, "{bad:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_verbatim_device_and_ads_prefixes_are_rejected() {
        let t = TempDir::new("winlex");
        let root = t.path().join("allowed");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("a.bin"), b"MZ").unwrap();
        let roots = vec![AllowRoot::open(&root).unwrap()];
        let base = plain(&root);

        for bad in [
            // verbatim: bypasses Win32 path normalization
            format!(r"\\?\{base}\a.bin"),
            // device namespace
            r"\\.\PIPE\somepipe".to_string(),
            // UNC
            r"\\server\share\a.bin".to_string(),
            // alternate data stream after the drive letter
            format!(r"{base}\a.bin:secret"),
        ] {
            let err = open_confined(&roots, &bad, CAP).unwrap_err();
            assert_eq!(err.code, ErrorCode::PathDenied, "{bad:?}");
        }
    }

    #[test]
    fn a_directory_inside_the_root_is_not_a_file() {
        let t = TempDir::new("dir");
        let root = t.path().join("allowed");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        let roots = vec![AllowRoot::open(&root).unwrap()];
        let err = open_confined(&roots, &plain(&root.join("sub")), CAP).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathDenied);
        assert!(!err.message.contains("regular file"), "{err:?}");
    }

    #[test]
    fn oversize_files_are_rejected_by_fstat_before_any_read() {
        let t = TempDir::new("cap");
        let root = t.path().join("allowed");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("big.bin"), vec![0u8; 4096]).unwrap();
        let roots = vec![AllowRoot::open(&root).unwrap()];
        let err = open_confined(&roots, &plain(&root.join("big.bin")), 1024).unwrap_err();
        assert_eq!(err.kind, "file_too_large");
    }

    /// Verbose detail is scoped to paths that already selected a root: a
    /// path outside the allowlist gets the same body verbose or not.
    #[test]
    fn verbose_errors_never_apply_outside_a_root() {
        let t = TempDir::new("verbose");
        let root = t.path().join("allowed");
        let outside = t.path().join("outside");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("f"), b"x").unwrap();
        let roots = vec![AllowRoot::open(&root).unwrap()];

        let quiet = open_confined(&roots, &plain(&outside.join("f")), CAP)
            .unwrap_err()
            .to_json()
            .to_string();
        let loud = open_confined_with(&roots, &plain(&outside.join("f")), CAP, true)
            .unwrap_err()
            .to_json()
            .to_string();
        assert_eq!(quiet, loud);

        // Inside the root, verbose does add detail.
        let loud_inside = open_confined_with(&roots, &plain(&root.join("absent")), CAP, true)
            .unwrap_err()
            .to_json()
            .to_string();
        assert!(loud_inside.contains("verbose_reason"), "{loud_inside}");
    }

    /// A symlink inside the root pointing outside it must not be followed.
    /// On Unix `O_NOFOLLOW` rejects it outright; on Windows the handle's
    /// final path resolves outside the root and is rejected there.
    #[test]
    fn symlink_escape_is_refused() {
        let t = TempDir::new("symlink");
        let root = t.path().join("allowed");
        let secret = t.path().join("secret");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&secret).unwrap();
        let target = secret.join("s.bin");
        std::fs::write(&target, b"TOPSECRET").unwrap();
        let link = root.join("link.bin");
        #[cfg(windows)]
        let made = std::os::windows::fs::symlink_file(&target, &link);
        #[cfg(unix)]
        let made = std::os::unix::fs::symlink(&target, &link);
        let Ok(()) = made else {
            eprintln!("symlink creation unavailable; skipping");
            return;
        };
        let roots = vec![AllowRoot::open(&root).unwrap()];
        let err = open_confined(&roots, &plain(&link), CAP).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathDenied);
    }

    #[test]
    fn root_identity_is_stable_and_distinguishes_roots() {
        let t = TempDir::new("ident");
        let a = t.path().join("a");
        let b = t.path().join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let ra = AllowRoot::open(&a).unwrap();
        let rb = AllowRoot::open(&b).unwrap();
        assert_eq!(ra.id(), AllowRoot::open(&a).unwrap().id());
        assert_ne!(ra.id(), rb.id());
    }

    /// A FIFO inside an allowed root must be refused by the fstat phase.
    /// `std::fs::read` on one blocks forever, which is why this check is
    /// not optional.
    #[cfg(unix)]
    #[test]
    fn fifo_inside_the_root_is_rejected_not_hung_on() {
        use std::os::unix::fs::FileTypeExt;
        let t = TempDir::new("fifo");
        let root = t.path().join("allowed");
        std::fs::create_dir_all(&root).unwrap();
        let fifo = root.join("f.bin");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: `c` is a valid NUL-terminated path.
        if unsafe { libc_mkfifo(c.as_ptr(), 0o600) } != 0 {
            eprintln!("mkfifo unavailable; skipping");
            return;
        }
        assert!(std::fs::symlink_metadata(&fifo)
            .unwrap()
            .file_type()
            .is_fifo());
        let roots = vec![AllowRoot::open(&root).unwrap()];
        // The final `openat` sets O_NONBLOCK precisely so this returns
        // instead of blocking in open(2) waiting for a writer.
        let err = open_confined(&roots, &plain(&fifo), CAP).unwrap_err();
        assert_eq!(err.code, ErrorCode::PathDenied);
    }

    #[cfg(unix)]
    extern "C" {
        #[link_name = "mkfifo"]
        fn libc_mkfifo(path: *const std::os::raw::c_char, mode: u32) -> std::os::raw::c_int;
    }
}
