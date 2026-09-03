# MCP server: hardening and capability design

The implementation spec for Phase 1 (security) and Phase 3 (workable) of
[REMEDIATION.md](../REMEDIATION.md). Written after driving the shipped
`target/release/rop-finder-mcp` over stdio, not from reading the code.

## Current state

The server RUNS and every one of its 7 tools answers correctly-shaped JSON-RPC over stdio on the first try — handshake, tools/list, tools/call all work, and gadget results are real. That is the good news, and it is genuinely a working prototype. It is NOT a server you can hand to an agent host today, for four independent reasons, all of which I reproduced live rather than inferring from code:

(1) PATH CONFINEMENT IS NOT REAL. `confine_path` (crates/rf-mcp/src/lib.rs:112-133) canonicalizes and returns a PathBuf; the file is re-opened BY PATH later, inside the `spawn_blocking` closure (lib.rs:593 -> :599). I ran a swap loop against the live server: 323 of 400 requests (81%) returned a scan of a file OUTSIDE the allowlist. The `spawn_blocking` dispatch does not narrow the race, it widens it into a reliable primitive. Separately, `ServerConfig::default()` seeds the allowlist with the process cwd and `--allow-dir` only appends (lib.rs:78-83, main.rs:41-54), so I read an out-of-allowlist file with zero racing simply by launching the server with cwd set to its parent — which is exactly what an MCP host does, because `claude_desktop_config.json` has no cwd key. The startup banner even prints the fixtures dir twice when cwd == allow-dir, which is the bug announcing itself.

(2) NOTHING CAN STOP A RUNAWAY SCAN. `depth` is unclamped. `tokio::time::timeout` around `spawn_blocking` (lib.rs:705) abandons the await, never the closure, and the closure has no cancellation point. I sent `depth: 18446744073709551615, timeout_secs: 2`; the client got a tidy `{"error":{"code":"timeout"}}` at 2.00 s and the process then held 398-400% CPU for as long as I watched. With `depth: 100000` the process reached 54.8 GB RSS 13 seconds after the client had already given up. `notifications/cancelled` is accepted and ignored — the work continues. There is no concurrency limit and no file-size cap.

(3) THE CACHE IS AN UNAUTHENTICATED CHANNEL AND A MEMORY LEAK. With `--cache-dir` I overwrote one 0644, deterministically-named entry and the server returned my fabricated gadget `pop rdi ; ret @ 0xdeadbeefcafe0000` alongside the REAL `binary_sha256` — authentic-looking to both the agent and a human reviewer. A malformed entry panics: I got `thread 'tokio-rt-worker' panicked at crates/rf-mcp/src/lib.rs:277:45: byte index 2 is not a char boundary` from a non-ASCII `bytes` field (the `&c.bytes[i..i+2]` slice in `gadget_from_cached`). The in-memory cache is insert-only: 12 depth-varying scans of one 900 KB binary took the process from 5 MB to 84 MB, and one depth-40 scan pinned 2.57 GB permanently.

(4) IT HANDS AGENTS WRONG DATA AND UNUSABLE SLICES. `get_binary_info` on the shipped pe-x64-cmd fixture reports `iat_vaddr: 0x4ad2af40` for msvcrt!memset. I parsed the PE by hand: 0x4ad2af40 is the IMAGE_IMPORT_BY_NAME record; the real IAT slot is 0x4ad29000. Every reported import address is wrong, and the spacing (10, 10, 10, 20 bytes — 2-byte hint plus name length) proves it. `delay_slot` is computed in rf-scan and dropped at every output boundary — MIPS gadgets come back without it. No tool declares an `outputSchema`, and the record shape varies (`section` only appears with `section`, `arch` only for universal binaries). And the sampling is worthless: `find_gadgets` at max_results=3 on elf-Linux-x64 returned `adc al, 0x89 ; retf 0xc281`, `adc al, 0xe9 ; retf 0xfffe`, `adc al, ch ; ret 0xfabd` out of 2789 — the alphabetical head, with no cursor to get past it. `sort_by: "quality"` does not save you: its top 8 were `ret`, `add esp, 0x8 ; ret`, `retf 0x2bbc`, `ret 0x2bbc`, `retf 0xce39`, ... all tied at quality 100, with `pop rdi ; ret` nowhere near the top.

What breaks first, in order: an operator follows MANUAL.md:329-340 verbatim and gets an allowlist of whatever cwd the host chose (not a race — just the default); then the first agent that guesses a large depth wedges the machine; then, if `--cache-dir` is on shared storage, results silently become attacker-controlled.

Underneath all of that is a usefulness problem the security work does not touch: rf-classify computes `regs_written`, `regs_read`, `labels`, `class`, `side_effects` per gadget, and the MCP surface exposes none of them as a filter. An agent cannot ask "give me a gadget that loads rdi from the stack without touching rsi/rdx" — the single most common real ROP question. It must pull thousands of gadgets into context and filter them itself, which is precisely the failure mode an MCP server exists to prevent.

## What was observed live

```
All observations below are from driving target/release/rop-finder-mcp over stdio with newline-delimited JSON-RPC (initialize -> notifications/initialized -> tools/list -> tools/call), Python driver at <scratch>

HANDSHAKE / SURFACE. initialize returns protocolVersion 2025-03-26, serverInfo {name: "rop-finder-mcp", version: "0.1.0"}, capabilities {tools:{}} only — no resources, no logging, no completions. 7 tools, all with `inputSchema`, NONE with `outputSchema`. Confirmed MCP-06: get_binary_info's properties are exactly ['base','binary_path'] — no timeout_secs, no max_results, while every other tool carries timeout_secs. Responses carry both `content[0].text` (stringified JSON) and `structuredContent`; errors set isError:true with `{"error":{"code":..,"message":..}}`.

TOCTOU (MCP-01), reproduced. Allowlist = one temp dir containing a hardlink `target.bin` -> a real ELF. A swapper thread alternated `rename(hardlink, target.bin)` and `rename(symlink->outside/secret.bin, target.bin)`. 400 sequential find_gadgets calls: 323 returned binary_sha256 761b2e78... (outside/secret.bin, OUTSIDE the allowlist), 76 returned the decoy 6d440623..., 1 path_not_found, ZERO path_not_allowed. 81% success rate. Server launched with cwd=/ so cwd could not mask the result.

CWD ALLOWLIST (MCP-02), reproduced with no race at all. Launched with `--allow-dir <fixtures>` and cwd=<scratch>. `get_binary_info` on `<scratch>/outside/secret.bin` returned `format=elf arch=x86 entry=0x8048d78`. The manual's promise ("can only read binaries inside --allow-dir") is false by construction.

EXISTENCE ORACLE (MCP-07), reproduced. Allowlist = fixtures only. ~/.ssh -> not_a_file (it exists, as a directory). ~/.ssh/id_rsa -> path_not_allowed (it exists, as a file). ~/.ssh/known_hosts -> path_not_allowed. /etc/passwd -> path_not_allowed. /etc/shadow -> path_not_found (with the raw errno string echoed). ~/.aws/credentials -> path_not_found. ~/Library/Application Support -> not_a_file. Three codes, three facts, any absolute path on the machine, one legitimate-looking tool call each.

CANCELLATION (MCP-03 / PERF-06), reproduced twice. (a) depth=u64::MAX, timeout_secs=2 on elf-x64-bash: reply `{"error":{"code":"timeout","message":"scan exceeded the 2 s timeout"}}` at t=2.00 s; the process then sat at 395-400% CPU at +5, +10, +15, +20, +25, +30 s after the reply, and answered a fresh get_binary_info in 0.00 s the whole time (so it looks healthy while burning 4 cores). (b) depth=100000, timeout_secs=300, then `notifications/cancelled {requestId:7}` sent at t=1.0 s: no response ever arrived, and at t=13 s the process was at 54873 MB RSS / 398.8% CPU. rmcp 3.2.0's cancellation notification is plumbed to nothing.

CONCURRENCY + CACHE MEMORY (MCP-05). 32 in-flight find_gadgets at depth 40 on elf-x64-bash: all 32 replies in 0.9 s, then RSS 2570 MB held flat for 40 s with 0% CPU — i.e. retained cache, not work. Separately, 12 sequential scans at depths 2..13 of the same 900 KB binary walked RSS 5 -> 20 -> 22 -> 27 -> 30 -> 36 -> 39 -> 46 -> 52 -> 59 -> 67 -> 71 -> 84 MB, monotonic, never released. `max_results:1` on every one of those calls — the response cap does not bound retention.

CACHE POISONING + PANIC (MCP-04 / CLI-07). Cache file created mode 0644, name `<sha256(file)>--<sha256(params)>.json`, fully predictable. Overwriting it with one fabricated gadget produced: `{"cache":"hit","gadgets":[{"bytes":"deadbeef","class":"reg-write","quality":100,"text":"pop rdi ; ret","vaddr":"0xdeadbeefcafe0000"}],"binary_sha256":"6d440623405fadb76b0d01bf95d16b345189e15b5e34572eb947963fa9718649"}` — attacker gadget, real file hash. Then `{"bytes":"€€"}` with sort_by=quality panicked the worker at lib.rs:277:45 ("byte index 2 is not a char boundary; it is inside '€'"). The panic is caught by spawn_blocking and surfaces as `{"code":"internal","message":"scan worker failed: task 26 panicked..."}`; the process survives, but a panic is not an error contract and the mutex `.unwrap()`s make it a latent wedge.

WRONG IMPORT ADDRESSES. MCP get_binary_info on tests/fixtures/pe-x64-cmd-v6.1.7601 reports msvcrt.dll memset iat_vaddr=0x4ad2af40, memcpy=0x4ad2af4a, memcmp=0x4ad2af54, _setjmp=0x4ad2af5e, ?terminate@@YAXXZ=0x4ad2af68 — spacings of 10,10,10,20 = 2-byte hint + strlen+1. I parsed the PE directly: image_base 0x4ad00000, msvcrt descriptor has ILT_rva 0x2a7f8 and IAT_rva 0x29000, so the true IAT slots are 0x4ad29000, 0x4ad29008, 0x4ad29010, 0x4ad29018, and 0x4ad2af40 is the IMAGE_IMPORT_BY_NAME record for "memset". Root cause: pe.rs:119 uses goblin's `imp.rva`. In goblin 0.10.7 src/pe/import.rs:531-537, `Import::offset = import_address_table_rva + i*T::size_of()` (the IAT slot) while `Import::rva` comes from `HintNameTableRVA`. The one-token fix is `imp.offset`, and the existing test (pe.rs:288, `thunk_vaddr == image_base + thunk_rva`) is tautological and would not notice.

MISSING delay_slot / VARIABLE SHAPE. MIPS fixture: find_gadgets total_count=0, find_jop_gadgets total_count=40872, find_syscall_gadgets total_count=270 — and not one returned record carries `delay_slot`, despite rf_scan::Gadget computing it (engine.rs:139-142) and MIPS being a delay-slot ISA. `section` appears only when `section` is passed; `arch` only for the universal fixture. 40872 JOP gadgets, max 50000 returnable in one blob, no cursor.

CHAIN TOOLS. build_rop_chain linux-execve on elf-Linux-x64 works: 76 words, valid Python. windows-virtualprotect on the shipped PE fixture returns `chain_error: "cannot populate rdx: no 'pop rdx' gadget and no 'pop rax' + 'mov rdx, rax' fallback"` — honest, but a prose string with nothing an agent can act on. linux-execve on elf-ARM64-bash: `usage_error: arch arm64 / format elf not supported yet`.

PACKAGING. dist/linux-x86_64/{rop-finder,rop-finder-mcp} are mode 0666 (rw-rw-rw-) — not executable. dist/macos-arm64 contains only build-macos.sh, dist/macos-x86_64 is empty. Only the Windows .exe files are 0777. No LICENSE file and no .github/ anywhere in the Rust tree (the only LICENSE in the repo is ropgadget/LICENSE_BSD.txt, for the Python oracle this is a derivative of).
```

## Minimum bar for "workable"

Every line below is a claim someone can falsify with a test, and every one of them is false today.

A engineer can hand this MCP server to an agent host when ALL of the following are true. Each line is a claim someone can falsify with a test, and every one of them is false today.

CONFINEMENT (it does not leak)
1. Every file read goes through a HANDLE obtained by an O_NOFOLLOW walk from a pinned root dirfd (Unix) or validated with GetFinalPathNameByHandleW + volume/index on the open handle (Windows). `std::fs::read(&path)` appears nowhere in rf-mcp. The 400-iteration rename-race test yields 0 leaks (today: 323).
2. The allowlist is exactly the --allow-dir set. With zero --allow-dir the server refuses to start. The process cwd is never implicitly allowed. Launching with cwd=<parent> and --allow-dir=<elsewhere> denies <parent>/x (today it reads it).
3. Any path outside every root returns one code, one message, with no filesystem access and no errno text. A file, a directory and an absent path outside the allowlist are indistinguishable in the response.
4. Roots are refused by default when they are /, $HOME, an ancestor of $HOME, or a system directory.

RESOURCE CONTROL (it does not wedge the machine)
5. A timed-out or cancelled request STOPS the work. CPU returns to idle within 3 s of the error reaching the client, measured, not asserted. Today it holds ~400% indefinitely.
6. notifications/cancelled produces a `cancelled` response within 3 s. Today it produces nothing, ever.
7. depth above --max-depth (default 64) is rejected with a structured usage_error naming the limit — not clamped, not accepted. depth=100000 does not reach 54 GB RSS.
8. Concurrency is bounded by a semaphore whose permits are released only after the worker has actually stopped; file size, gadget count and result count are all bounded; get_binary_info is subject to the same caps as everything else.
9. Steady-state RSS is bounded by --cache-mem-mb across an arbitrary parameter sweep. Forty scans at forty depths stay under the configured bound (today: monotonic growth to 84 MB on a 900 KB file, 2.57 GB at depth 40).

INTEGRITY (it does not lie)
10. Every on-disk cache entry is MAC-verified against a 0600 server key; a tampered entry is a miss plus a counter plus an audit line, never a result. Writes are tempfile+rename. The dir is 0700 and entries 0600.
11. No input — malformed cache entry, hostile binary, any tool argument — produces a panic. The full malformed-cache matrix (non-ASCII bytes, odd length, huge strings, bad vaddr) returns clean errors and leaves no "panicked" in stderr.
12. get_binary_info reports true IAT slot addresses: msvcrt!memset on the shipped cmd.exe fixture is 0x4ad29000, and every DLL's slots are 8-byte aligned and 8 apart. delay_slot is emitted and is true for MIPS/SPARC.
13. Every tool declares an outputSchema; every response validates against it across all 24 fixtures; the record shape is invariant (no conditionally-omitted fields); the error-code set is a closed, documented enum.
14. README.md and MANUAL.md describe only guarantees that a test enforces. Every security sentence in the docs maps to a named test.

USEFULNESS (an agent can do real work)
15. An agent can express "set rdi from the stack, preserve rsi and rdx, at most one side effect, clean ret" in ONE call and get a small correct answer — not 1000 alphabetically-ordered records beginning with `adc al, 0x89 ; retf 0xc281`.
16. The default ordering puts usable gadgets first: `pop rdi ; ret` ranks above `retf 0xce39`. Every result set is walkable with a cursor.
17. Gadgets carry stable ids that survive across calls and cache evictions, and can be resolved back with get_gadgets.
18. A chain that cannot be built returns a structured requirements/relaxations object, not a sentence.

OPERABILITY (someone can actually run it)
19. A signed, notarized, executable binary exists for macOS arm64 + x86_64, Linux x86_64 (static), and Windows x86_64 — packaged so the executable bit survives (today Linux ships 0666 and macOS ships nothing).
20. CI runs fmt, clippy -D warnings, tests, cargo-deny, fuzz targets and the parity harness on all four platforms; a release smoke job drives a full MCP session against the packaged artifact on each.
21. A LICENSE and a NOTICE crediting ROPgadget exist.
22. An audit log records tool, binary, verdict and duration for every call, including denials, and get_server_stats exposes denied/timeout/cancelled/wedged counters. Diagnostics never touch stdout, and a test proves stdout is pure JSON-RPC.

Rough shape: items 1-14 and 19-22 are the "do not ship without this" set and are roughly 3-4 hours of focused work; items 15-18 are what make the server worth having and are another 3-4 hours, most of it in rf-classify (stack_delta, the ARM register-parsing fix, a non-degenerate rank) rather than in rf-mcp itself.

---

## Fixes

### 1. [confinement] confine_path canonicalizes a string and hands back a PathBuf; the file is re-opened by path later, on a different thread, inside the spawn_blocking closure. Nothing pins the inode. I measured an 81% (323/400) arbitrary-file-read success rate against the live server with a trivial rename loop. The MANUAL claims symlink escapes are rejected; only symlinks that exist at check time are.

*Effort:* days · *Closes:* `MCP-01`, `MCP-08`
*Files:* `crates/rf-mcp/src/confine.rs`, `crates/rf-mcp/src/lib.rs`, `crates/rf-mcp/src/main.rs`, `crates/rf-mcp/Cargo.toml`

**Design**

Replace confine_path entirely with an open-then-verify API that returns a HANDLE and never touches the path again.

New module crates/rf-mcp/src/confine.rs:

  pub struct AllowRoot { canon: PathBuf, dir: std::fs::File /*pinned dirfd*/, dev: u64, ino: u64 }
  pub struct ConfinedFile { pub file: std::fs::File, pub len: u64, pub label: String /* root-relative, for logs */ }
  pub fn open_confined(roots: &[AllowRoot], input: &str, max_bytes: u64) -> Result<ConfinedFile, ToolError>

Startup (main.rs): for each --allow-dir, canonicalize once, then OPEN the directory and keep the File for the process lifetime (Unix: File::open; Windows: CreateFileW with FILE_FLAG_BACKUP_SEMANTICS). Record dev/ino (Unix, std::os::unix::fs::MetadataExt::dev()/ino()) or volume serial + file index (Windows, GetFileInformationByHandle -> dwVolumeSerialNumber, nFileIndexHigh/Low). The root itself can then no longer be renamed or replaced under us.

Per request, three phases, in this order:

PHASE 1 - lexical, no syscalls. Require an absolute path; reject any component equal to "." or ".."; reject interior NUL; on Windows reject \\?\, \\.\, UNC prefixes, and any ':' after the drive letter (alternate data streams). Select the root by COMPONENT-WISE prefix match on std::path::Component, never by string starts_with — this is what makes /allowed-evil not match root /allowed, which today's `canon.starts_with(d)` also happens to get right only because Path::starts_with is already component-wise; keep it component-wise explicitly and add the regression test. On case-insensitive filesystems (APFS default, NTFS) compare components with eq_ignore_ascii_case for root SELECTION only. If no root matches, return path_denied without any filesystem access at all.

PHASE 2 - Unix: walk the remainder from the pinned root dirfd with rustix (rustix = "1", features = ["fs"]). For each intermediate component: rustix::fs::openat(dirfd, comp, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty()). For the last component: same without DIRECTORY. O_NOFOLLOW on every hop plus the ban on ".." means the resulting fd is PROVABLY a descendant of the pinned root — there is no window in which anything can be swapped, because no name is ever resolved twice. (nix::fcntl::openat is an equivalent alternative; rustix is preferred, it is already in the tree via tempfile/is-terminal.)

PHASE 2 - Windows: no openat. Open the final path once with CreateFileW(GENERIC_READ, FILE_SHARE_READ|WRITE|DELETE, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS), then validate the HANDLE, not the path: GetFinalPathNameByHandleW(h, FILE_NAME_NORMALIZED | VOLUME_NAME_GUID) gives the true object path after every reparse point; compare it component-wise (case-insensitively) against the root's own GetFinalPathNameByHandleW taken at startup from the pinned root handle. Also require GetFileType(h) == FILE_TYPE_DISK (rejects \\.\pipe\, console, mailslots), and GetFileInformationByHandle -> require dwVolumeSerialNumber equal to the root's. Because both the name and the identity come from the open handle, there is no TOCTOU. Crate: windows-sys with features Win32_Foundation, Win32_Storage_FileSystem.

PHASE 3 - fstat the HANDLE (File::metadata(), which is fstat(2)/GetFileInformationByHandle, not stat on a path): require a regular file (Unix: st_mode & S_IFMT == S_IFREG — this also rejects FIFOs, which would otherwise hang std::fs::read forever), require len <= max_bytes, and require st_dev == root.dev unless --allow-crossdev (catches a mount planted inside an allowed tree).

READ FROM THE HANDLE: let mut buf = Vec::with_capacity(len as usize); (&mut cf.file).take(max_bytes + 1).read_to_end(&mut buf)?; then assert buf.len() as u64 <= max_bytes. Delete every std::fs::read(&path) in lib.rs — the three sites are :599 (run_scan), :757 (run_chain), :913 (get_binary_info). ConfinedFile is Send, so it moves into the spawn_blocking closure and the handle, not a name, crosses the thread boundary.

The only string that survives is `label` (root-relative, for the audit log and error text); it is never re-opened.

**Test that proves it** (and would have caught the original bug)

crates/rf-mcp/tests/confine_race.rs, an integration test that IS the harness I ran. Spawn the real server with --allow-dir <tmp>/allowed and cwd=/. A background thread loops { link(decoy, t); rename(t, allowed/target.bin); symlink(outside/secret.bin, t); rename(t, allowed/target.bin) }. Fire 400 find_gadgets at allowed/target.bin and assert that binary_sha256 is NEVER the secret's hash and that the outcome is only ever {decoy hash, path_denied}. Today this fails at 323/400. Add unit tests: root /allowed does not admit /allowed-evil/x; a FIFO inside an allowed root is rejected (not hung on); on Unix a symlink INSIDE the root pointing to another file inside the root is rejected under O_NOFOLLOW (documented behaviour, not a bug); and on macOS that /tmp/<root>/x resolves when the root was given as /tmp but canonicalizes to /private/tmp.

### 2. [confinement] ServerConfig::default() seeds allow_dirs with the process cwd and main.rs only pushes --allow-dir onto it, so the allowlist can never be narrower than wherever the host launched the process. claude_desktop_config.json has no cwd key, so the operator cannot control it. I read an out-of-allowlist file with no race at all just by choosing cwd. MANUAL.md:355 and README.md:340 both assert the opposite.

*Effort:* hours · *Closes:* `MCP-02`, `MCP-08`
*Files:* `crates/rf-mcp/src/main.rs`, `crates/rf-mcp/src/lib.rs`, `MANUAL.md`, `README.md`

**Design**

Make --allow-dir the ONLY source of roots, and make the empty case a hard failure.

1. Delete the cwd seed. ServerConfig::default() gets `allow_dirs: Vec::new()`. main.rs builds the roots strictly from --allow-dir.
2. If zero --allow-dir were given: print to stderr and exit 2 —
   "rop-finder-mcp: refusing to start with no --allow-dir. The MCP host chooses this process's working directory, so defaulting to it would grant access to whatever the host happened to pick (currently: <cwd>). Pass --allow-dir <dir> for each directory of binaries you want the agent to analyse, or --allow-cwd to deliberately serve the working directory."
   Failing closed is correct here: a silently-wide allowlist is exactly the reported bug, and an MCP host surfaces a startup failure to the operator immediately.
3. Add --allow-cwd as an explicit opt-in for the old behaviour (useful for `cargo run` and CI), and keep the existing tests working by passing it.
4. Refuse dangerous roots unless --i-accept-a-wide-allowlist: any root that is "/", a filesystem root on Windows (C:\), $HOME itself, an ancestor of $HOME, /Users, /home, /etc, /usr, /var, /System, /Library, C:\Users, C:\Windows, C:\Program Files, or any path with fewer than 2 components. Exit 2 with the offending root named.
5. Reject --cache-dir, --audit-log and --workspace-dir that fall INSIDE any allow root (a cache file inside a scannable root muddles the trust boundary).
6. Publish the effective allowlist so the agent never needs to probe for it: include it in the `instructions` string returned by initialize, and add a `get_server_config` tool returning {allow_roots: [...], max_depth, max_file_bytes, max_results, max_concurrent, cache: bool, version}. An agent that can read the roots has no reason to guess paths, which removes most of the pressure on the error taxonomy.
7. Rewrite MANUAL.md:355-357 and README.md:336-346 to state exactly what holds after these fixes, and add a "what this does NOT protect against" paragraph (the operator's own choice of root; anything readable inside a root; the fact that the binary's own bytes reach the agent).

**Test that proves it** (and would have caught the original bug)

crates/rf-mcp/tests/mcp_stdio.rs: `allowlist_is_exactly_allow_dir` — spawn the server with --allow-dir <fixtures> and cwd set to a temp dir containing probe.bin; assert get_binary_info on <tmp>/probe.bin returns path_denied. This is the test the existing `mcp_rejects_traversal_and_disallowed_flags` only appears to be: it passes today purely because the harness's cwd (crates/rf-mcp) happens not to contain the probe file. Second test: spawning with no --allow-dir exits 2 and prints "refusing to start". Third: --allow-dir / exits 2 without --i-accept-a-wide-allowlist.

### 3. [confinement] confine_path checks containment LAST: canonicalize failure -> path_not_found (with the raw errno echoed), directory -> not_a_file, existing file outside the allowlist -> path_not_allowed. Those three codes distinguish exists-as-file / exists-as-dir / absent for any absolute path on the machine. I confirmed live that the server disclosed that ~/.ssh exists as a directory, ~/.ssh/id_rsa exists as a file, and ~/.aws/credentials does not exist.

*Effort:* hours · *Closes:* `MCP-07`
*Files:* `crates/rf-mcp/src/confine.rs`, `crates/rf-mcp/src/lib.rs`

**Design**

Containment first, one code, no OS strings.

In open_confined, phase 1 (lexical root selection) runs BEFORE any syscall. A path outside every root returns:
  {"code":"path_denied","message":"binary_path is not inside an allowed directory. Allowed: [/x/y, /z]","details":{"allow_roots":[...]}}
with zero filesystem access, so the response carries no information about the target path at all.

Inside a root, every failure of phase 2/3 ALSO maps to path_denied by default, with a single fixed message and no errno text — ENOENT, EISDIR, ELOOP, EACCES, EPERM, ENOTDIR and "not a regular file" are indistinguishable. A `--verbose-path-errors` flag (off by default) restores the distinction inside allowed roots only, for operators debugging their own setup; it must never apply outside a root.

Delete the `format!("cannot canonicalize {input:?}: {e}")` interpolation at lib.rs:114 — echoing the OS error string is what turns the code into a precise oracle.

Add a rate limit and a counter on denials: a `denied_total` counter (exported by get_server_stats and written to the audit log), and after N consecutive path_denied results from one session (default 20) the server starts returning path_denied with a 250 ms delay and logs `"probing_suspected": true`. That is the signal that reveals a prompt-injected agent walking the filesystem, and it costs almost nothing.

Pair this with get_server_config (previous fix): once the agent is TOLD the roots, a legitimate agent never generates a denial, so denials become a clean signal.

**Test that proves it** (and would have caught the original bug)

crates/rf-mcp/tests/mcp_stdio.rs: `error_taxonomy_is_not_an_existence_oracle` — build a temp tree with an existing file, an existing directory and an absent path, all OUTSIDE the allowlist; call get_binary_info on each and assert all three responses are byte-identical apart from the echoed input path (same code, same message, same details). Assert no response body contains "No such file", "os error", "canonicalize", or "is not a regular file". Today the three differ and one leaks errno 2.

### 4. [resource-control] tokio::time::timeout wraps spawn_blocking, so it abandons the await and never the work. The scan loop has no cancellation point. I measured 398-400% CPU held indefinitely after the client received its timeout error, and 54.8 GB RSS 13 s after a depth-100000 request that the client had already cancelled via notifications/cancelled — which the server accepts and ignores.

*Effort:* days · *Closes:* `MCP-03`, `PERF-06`, `MCP-06`
*Files:* `crates/rf-scan/src/cancel.rs`, `crates/rf-scan/src/engine.rs`, `crates/rf-scan/src/cs.rs`, `crates/rf-cli/src/lib.rs`, `crates/rf-mcp/src/lib.rs`, `crates/rf-mcp/src/main.rs`

**Design**

Cooperative cancellation threaded from the MCP request down into the rf-scan hot loops, plus a JOIN (not an abandon) at the timeout.

A. rf-scan gets a token. New crates/rf-scan/src/cancel.rs:
   #[derive(Clone, Default)] pub struct CancelToken(Arc<AtomicBool>);
   impl CancelToken { pub fn new() -> Self; pub fn never() -> Self; pub fn cancel(&self) { self.0.store(true, Ordering::Relaxed) } pub fn is_cancelled(&self) -> bool { self.0.load(Ordering::Relaxed) } }
   Add `Cancelled` and `Budget { produced: usize, limit: usize }` to rf_scan::Error.

B. Exact check points (all in the existing loops, no restructuring):
   - engine.rs:212 `scan_work(regions, tables, opts, f)` gains `cancel: &CancelToken`. Its `run` closure (engine.rs:225-230) starts with `if cancel.is_cancelled() { return Vec::new(); }`. Rayon's `par_iter().map(run).collect()` at engine.rs:233 has no early exit, but once the flag is set every remaining work item becomes an O(1) no-op, so the residual cost after cancellation is bounded by the number of (region x anchor) items, not by their contents.
   - engine.rs:359 `for ref_pos in anchors::find_matches(code, anchor)` in x86_scan_anchor: `.enumerate()`, and `if n & 0x3FF == 0 && cancel.is_cancelled() { cache.clear(); return; }`.
   - engine.rs:365 `for i in 0..opts.depth` — THIS is the loop that ran away at depth=100000 and produced the 54 GB. `if i & 0xFF == 0 && cancel.is_cancelled() { return; }` plus the budget check below. The stride keeps the relaxed atomic load off the innermost path.
   - cs.rs:282 (`for ref_pos in ...`) and cs.rs:288 (`for i in 0..opts.depth`) in scan_anchor: identical treatment, since MIPS/ARM/PPC go through this path.
   - engine.rs:242 post_process: check once on entry and once before the sort; return `Err(Error::Cancelled)`.
   - Memory budget in the same place: `out.len()` is checked against `opts.max_gadgets` in both anchor scanners; exceeding it sets the token and records Error::Budget. This is what actually bounds RSS, since cancellation alone does not bound a scan that is legitimately huge.

C. Public API: `pub fn scan_binary_cancellable<B: Image + ?Sized>(bin: &B, opts: &ScanOptions, cancel: &CancelToken) -> Result<Vec<Gadget>, Error>`; the existing `scan_binary` delegates with `CancelToken::never()`, so the 153 existing tests and the CLI are untouched. Mirror in rf-cli: `scan_bytes_cancellable(bytes, raw, req, &CancelToken)` next to scan_bytes (lib.rs:853), and the same for chain_bytes (lib.rs:974) and info_bytes.

D. rf-mcp: one helper replaces the three ad-hoc timeout blocks (lib.rs:705, :775, and the inline get_binary_info at :901).

   async fn run_guarded<T: Send + 'static>(&self, ctx: &RequestContext<RoleServer>, timeout: Duration,
                                           f: impl FnOnce(CancelToken) -> Result<T, ToolError> + Send + 'static)
       -> Result<T, ToolError>
   {
       let _permit = self.inflight.clone().acquire_owned().await.map_err(...)?;   // tokio::sync::Semaphore
       let token = CancelToken::new();
       // bridge the MCP cancellation notification, which today does nothing:
       let (t, ct) = (token.clone(), ctx.ct.clone());
       let bridge = tokio::spawn(async move { ct.cancelled().await; t.cancel(); });
       let t = token.clone();
       let mut handle = tokio::task::spawn_blocking(move || f(t));
       let out = tokio::select! {
           r = &mut handle => r.map_err(join_to_tool)?,
           _ = tokio::time::sleep(timeout) => {
               token.cancel();
               // JOIN, do not abandon: the permit must not be released until the work stops.
               match tokio::time::timeout(Duration::from_secs(5), handle).await {
                   Ok(_) => Err(ToolError::timeout(timeout)),
                   Err(_) => { self.stats.wedged.fetch_add(1, Relaxed); Err(ToolError::timeout_hard(timeout)) }
               }
           }
       };
       bridge.abort();
       out
   }

   Awaiting the join after cancelling is the load-bearing detail: it is what makes the semaphore a real concurrency bound rather than a bound on outstanding awaits. `_permit` is dropped only after the worker has actually stopped.

E. Caps, all enforced before any work starts:
   - depth: HARD_MAX_DEPTH = 64 (configurable via --max-depth). A larger value is REJECTED with usage_error carrying {limit_value: 64, got: N} — not silently clamped, because an agent that silently gets depth 64 when it asked for 100000 will draw wrong conclusions. Applies to GadgetQuery.depth, SearchQuery.depth, ChainQuery.depth and the --depth parse at lib.rs:472.
   - --max-file-bytes, default 256 MiB, enforced by fstat on the confined HANDLE before read (see the confinement fix).
   - --max-gadgets, default 5_000_000, enforced in the engine (B above).
   - --max-concurrent, default 2, as the Semaphore permit count. Also build an explicit rayon pool with rayon::ThreadPoolBuilder::new().num_threads(cfg.scan_threads).build() (--scan-threads, default max(1, num_cpus-1)) and run every scan inside pool.install(...), so the server never consumes every core on the developer's machine.
   - get_binary_info moves onto run_guarded and gains timeout_secs and the file cap — it is the one tool with neither today.

**Test that proves it** (and would have caught the original bug)

Three tests, each of which fails today.
1. crates/rf-mcp/tests/cancellation.rs `timeout_actually_stops_the_work`: spawn the real server, send find_gadgets on elf-x64-bash with depth=64 timeout_secs=2, receive the timeout error, then sample the server's CPU via /proc/<pid>/stat (Linux) or `ps -o %cpu` (macOS) at +3 s and +8 s and assert utime delta < 0.2 s over the interval and RSS growth < 50 MB. Today this measures ~400% CPU forever.
2. `cancellation_notification_is_honoured`: send find_gadgets with depth=64 and a large timeout, then notifications/cancelled with the matching requestId; assert a response arrives within 3 s with code "cancelled", and that CPU returns to idle. Today no response ever arrives.
3. `depth_over_max_is_rejected_not_clamped`: depth=100000 -> usage_error with details.limit="max_depth", details.got=100000, and RSS unchanged. Plus a rf-scan unit test `scan_stops_on_token`: set the token from another thread mid-scan of the bash fixture and assert scan_binary_cancellable returns Err(Cancelled) in under 200 ms.

### 5. [cache] On-disk cache entries are read, deserialized and served verbatim: no integrity check, deterministic 0644 filenames derived only from public inputs, no atomic write, no eviction, no TTL, and a malformed entry panics the worker. I served an attacker-chosen gadget at 0xdeadbeefcafe0000 alongside the genuine binary_sha256, and panicked the server at lib.rs:277 with a non-ASCII bytes field. The in-memory map is insert-only and reached 2.57 GB from one request.

*Effort:* days · *Closes:* `MCP-04`, `MCP-05`, `CLI-07`, `CLI-08`, `PERF-12`
*Files:* `crates/rf-mcp/src/cache.rs`, `crates/rf-mcp/src/lib.rs`, `crates/rf-mcp/src/main.rs`, `crates/rf-cli/src/lib.rs`

**Design**

Four separable pieces; do them together because they all touch Cache::get/put (lib.rs:164-219).

A. INTEGRITY. On-disk format becomes two lines: line 1 = 64 hex chars of MAC, line 2 = the JSON body. MAC = HMAC-SHA256(server_key, key_string || 0x00 || body_bytes), using the `hmac` crate over the sha2 already in the tree. server_key is 32 bytes from getrandom, created on first use at <cache_dir>/.cachekey with OpenOptions::new().write(true).create_new(true).mode(0o600) (Unix) / a DACL restricted to the current user (Windows). If .cachekey is absent, unreadable, the wrong length, or group/world-readable: disable the on-disk cache entirely and log a warning — never fall back to unauthenticated reads. A MAC mismatch on read: treat as a miss, delete the file, increment stats.cache_tamper, and write an audit-log line. Note the threat model this addresses is another local process or a prompt-injected agent with a write tool, not the operator; that is exactly the reported threat.
   Also harden the directory: after create_dir_all, set_permissions(0o700); refuse to use a pre-existing cache dir whose mode is group/world-writable or whose uid != the current uid (std::os::unix::fs::MetadataExt), unless --cache-insecure-ok.

B. ATOMIC WRITES. Replace `std::fs::write(path, text)` (lib.rs:214) with tempfile::NamedTempFile::new_in(dir) -> write MAC line + body -> set mode 0600 -> .persist(final_path). persist() is rename(2), atomic within the directory, so a reader never sees a half-written entry and a crash never leaves one.

C. NO PANICS ON MALFORMED DATA. The panic site is gadget_from_cached at lib.rs:272-283, specifically `&c.bytes[i..i+2]` — a &str byte-range slice that panics on a non-char-boundary. Replace with a slice over as_bytes():
     fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
         let b = s.as_bytes();
         if b.len() % 2 != 0 || b.len() > 4096 || !b.iter().all(u8::is_ascii_hexdigit) { return None; }
         b.chunks_exact(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect()
     }
   Then add CachedScan::validate(&self) -> Result<(), &'static str>, called on EVERY deserialize (disk or otherwise) before the entry is usable: vaddr parses as hex u64 after stripping "0x"; bytes passes hex_to_bytes; text <= 64 KiB with no control characters; quality in 0..=100; class in the known Class name set; gadget count <= max_gadgets. Any violation rejects the whole file. Add #![deny(clippy::indexing_slicing, clippy::string_slice)] to crates/rf-mcp/src/lib.rs so the class of bug cannot come back. Replace every `self.mem.lock().unwrap()` with `.unwrap_or_else(PoisonError::into_inner)` so a panic anywhere can never permanently wedge the cache.

D. BOUNDS AND EVICTION. Replace `Mutex<HashMap<String, Arc<CachedScan>>>` with a byte-weighted LRU: keep `lru::LruCache<String, Arc<CachedScan>>` plus a running `total_bytes` and a per-entry cost from `CachedScan::heap_bytes()` (sum of vaddr/bytes/text/arch/section/class string lengths + 48 bytes per gadget). On insert, pop_lru() until total_bytes <= --cache-mem-mb (default 512 MiB). Store `created_unix` per entry and treat an entry older than --cache-ttl-secs (default 86400) as a miss. On disk: after each put, at most once per 60 s (guarded by a Mutex<Instant>), read_dir, sort by mtime, unlink oldest until the directory is under --cache-disk-mb (default 2048). Expose cache_entries / cache_bytes / cache_hit_ratio / evictions via get_server_stats.
   Do the same for the CLI's ~/.cache cache, which has the identical unbounded-growth and trusted-verbatim problems (CLI-07, CLI-08, PERF-12) — share the module rather than writing it twice.

**Test that proves it** (and would have caught the original bug)

crates/rf-mcp/tests/cache_integrity.rs, a direct port of the poison run I did.
1. `tampered_entry_is_rejected`: run a scan with --cache-dir, then rewrite the single cache file with a fabricated gadget at 0xdeadbeefcafe0000 keeping the filename; re-run and assert cache=="miss", the fabricated vaddr does not appear, and stats.cache_tamper == 1. Today it is served as cache=="hit".
2. `malformed_entry_never_panics`: parameterise over bytes fields "\u{20ac}\u{20ac}" (the exact input that panicked at lib.rs:277:45), "zz", "abc", a 1 MB string, vaddr "not-hex", quality 99999, class "../../etc", and a truncated file; each must produce a clean cache miss and a normal 200-shaped response, and the server's stderr must contain no "panicked".
3. `cache_is_bounded`: 40 scans at 40 depths with --cache-mem-mb 64; assert RSS stays under 250 MB and cache_bytes stays under 64 MiB. Today the equivalent sequence walks monotonically to 84 MB on a 900 KB file and 2.57 GB at depth 40.
4. `writes_are_atomic`: concurrently put the same key from 8 threads while a reader loops; the reader must never observe a parse failure.

### 6. [correctness] get_binary_info reports the IMAGE_IMPORT_BY_NAME RVA as iat_vaddr. On the shipped pe-x64-cmd fixture the tool says msvcrt!memset lives at 0x4ad2af40; the real IAT slot is 0x4ad29000. Every import address handed to an agent (and to the Windows IAT-dereference chain builder) is wrong, and the only test of the field is tautological.

*Effort:* hours · *Closes:* `CHWIN-03`, `CORE-02`
*Files:* `crates/rf-core/src/pe.rs`, `crates/rf-cli/src/lib.rs`, `crates/rf-mcp/src/lib.rs`, `crates/rf-chain/src/windows.rs`

**Design**

One-line root fix plus a schema correction that makes the mistake impossible to repeat.

crates/rf-core/src/pe.rs:119. goblin 0.10.7 src/pe/import.rs:531-537 computes `offset = import_address_table_rva + i * T::size_of()` (the FirstThunk/IAT slot the loader patches) and takes `rva` from the SyntheticImportLookupTableEntry::HintNameTableRVA. The code uses `imp.rva`. Change to:

    iat_slot_rva: imp.offset as u64,
    hint_name_rva: imp.rva as u64,

Rename PeImport::thunk_rva -> iat_slot_rva and thunk_vaddr -> iat_slot_vaddr, and ADD hint_name_rva/hint_name_vaddr rather than dropping the old value (it is genuinely useful for locating the import name string). Update the doc comment at pe.rs:41, which currently describes the field correctly and the code implements something else.

Downstream: rf-cli info_json (lib.rs ~616) emits `"iat_vaddr"` from the corrected field; add `"hint_name_vaddr"`. crates/rf-chain/src/windows.rs:281 consumes the corrected value, which is what makes the `pop rax ; <addr> ; mov rax, [rax] ; jmp rax` sequence load a function pointer instead of eight bytes of ASCII name.

While in the same output path, fix delay_slot (CRIT-03): rf_scan::Gadget::delay_slot is computed at engine.rs:139-142 and discarded at every emission point. Add `delay_slot: bool` to rf-mcp's CachedGadget (lib.rs:137-158) and to the CLI's JSON record, populated from g.delay_slot. Without it an agent reading a MIPS or SPARC gadget has no way to know the last instruction in the text executes BEFORE the branch — which changes what the gadget does.

**Test that proves it** (and would have caught the original bug)

Replace the tautological pe.rs:288 assertion (`thunk_vaddr == image_base + thunk_rva`) with semantic assertions against the shipped fixture: on tests/fixtures/pe-x64-cmd-v6.1.7601, msvcrt.dll!memset must have iat_slot_vaddr == 0x4ad29000 and hint_name_vaddr == 0x4ad2af40; and, as a structural invariant that generalises to every PE, assert that for each DLL the iat_slot_vaddrs are strictly increasing, exactly 8 bytes apart (4 on x86), and 8-byte aligned. The current wrong values (0x4ad2af40, 0x4ad2af4a, 0x4ad2af54 — 10 bytes apart, unaligned) fail the alignment assertion instantly, on any PE, with no hardcoded constants. For delay_slot: a stdio test asserting every gadget from elf-Mips-Defcon-20-pwn100 carries delay_slot:true and every gadget from elf-Linux-x64 carries delay_slot:false — today the field is absent from both.

### 7. [schema] No tool declares an outputSchema, and the emitted record shape is not fixed: `section` appears only when the section parameter was passed, `arch` only for universal binaries, `delay_slot` never. MANUAL/README document a JSON record that does not match what is emitted. An agent cannot write a stable parser against this.

*Effort:* days · *Closes:* `CRIT-03`, `MCP-08`
*Files:* `crates/rf-mcp/src/schema.rs`, `crates/rf-mcp/src/lib.rs`, `crates/rf-mcp/tests/expected_tools_schema.json`, `MANUAL.md`

**Design**

Make the contract explicit, fixed-shape, and machine-checked.

1. Define the response types as real Rust types deriving serde::Serialize + schemars::JsonSchema, and attach them via rmcp's output-schema support so every entry in tools/list carries `outputSchema`:
     struct GadgetRecord { id: String, vaddr: String, vaddr_u64: u64, bytes: String, text: String,
                           insns: Vec<String>, arch: Option<String>, section: Option<String>,
                           delay_slot: bool, class: Option<String>, labels: Vec<String>,
                           regs_written: Vec<String>, regs_read: Vec<String>, side_effects: u32,
                           stack_delta: Option<i64>, quality: i32, low_confidence: bool }
     struct ScanResponse { gadgets: Vec<GadgetRecord>, total_count: usize, returned: usize,
                           truncated: bool, next_cursor: Option<String>, order: String,
                           binary_sha256: String, binary_label: String, cache: String,
                           fallback_section_names: bool, warnings: Vec<Warning> }
     struct ToolErrorBody { code: ErrorCode /* a #[serde(rename_all="snake_case")] enum */,
                           message: String, retryable: bool, details: Value,
                           suggestion: Option<Suggestion> }
2. REMOVE every #[serde(skip_serializing_if = ...)] from the gadget record (lib.rs:137-158). Fields are always present, null when unknown. Variable-shape JSON is the thing an agent handles worst.
3. Add `vaddr_u64` alongside the zero-padded `vaddr` string. The string form ("0x0000000000445f50") is for humans; agents doing arithmetic should not have to parse it, and the zero-padding width silently changes between 32- and 64-bit targets.
4. Add a `warnings: []` array carrying non-fatal facts the agent must know: {code:"low_confidence_classification", detail:"non-x86 heuristics"}, {code:"fallback_section_names"}, {code:"universal_slice_selected", detail:"x64"}, {code:"truncated"}. Today `fallback_section_names` is a bare bool with no explanation.
5. Close the ErrorCode enum and document it: path_denied, usage_error, unsupported_binary, resource_exhausted, timeout, cancelled, cursor_expired, not_found, internal. Collapse today's path_not_found/not_a_file/path_not_allowed into path_denied (see the oracle fix) and rename the two spellings currently in use (`usage` at lib.rs:588 and `usage_error` elsewhere) to one.
6. Rewrite the MANUAL/README JSON-record sections from the generated schema rather than by hand, and generate them in a test so they cannot drift.

**Test that proves it** (and would have caught the original bug)

Extend the existing tests/expected_tools_schema.json snapshot to cover outputSchema for all tools (it would have caught get_binary_info's missing timeout_secs too — the snapshot exists but only records inputSchema). Then add crates/rf-mcp/tests/schema_conformance.rs: for each of the 24 fixtures x {find_gadgets, find_jop_gadgets, find_syscall_gadgets, search_gadgets_by_pattern, get_binary_info, build_rop_chain, run_ropgadget_command}, drive the real server over stdio and validate every structuredContent against the tool's own declared outputSchema with the `jsonschema` crate. Assert additionalProperties:false so an added field is a test failure, and assert that the same field set is present for elf-Linux-x64 (no section), elf-Linux-x64 with section=.text, elf-Mips (delay_slot true), and the UNIVERSAL fixture (arch set) — the four shapes that differ today.

### 8. [usability] There is no pagination and no stable identity. find_gadgets at max_results=3 on elf-Linux-x64 returns the alphabetical head — `adc al, 0x89 ; retf 0xc281` and friends — out of 2789, and the MIPS JOP set is 40872 gadgets with no way to walk it. sort_by:"quality" does not help: its top 8 were ret, add esp 0x8 ; ret, retf 0x2bbc, ret 0x2bbc, retf 0xce39... all tied at 100. There is also no way to refer to a gadget across calls.

*Effort:* days · *Closes:* `MCP-05`, `CLS-07`, `CLS-08`, `ECO-01`
*Files:* `crates/rf-mcp/src/lib.rs`, `crates/rf-mcp/src/schema.rs`, `crates/rf-classify/src/lib.rs`

**Design**

Three changes: a real default order, a cursor, and stable ids.

A. DEFAULT ORDER. Change the default `order` from "traversal" (which is alphabetical-by-text after post_process) to "rank". Rank key, descending:
     (usability_tier, quality, -(n_insns as i32), -(side_effects as i32), vaddr asc)
   where usability_tier is a new rf-classify function `pub fn usability(c: &Classification, g: &Gadget) -> u8` returning 0..=3:
     3 = terminator is a bare `ret`/`jr $ra`/`bx lr` AND at least one register is loaded from the stack (a `pop`-family instruction) AND side_effects <= 2;
     2 = bare terminator, any useful class;
     1 = terminator is `ret imm16` / `retf` / `retf imm16` / `iret` / a far transfer, or the class is `other`;
     0 = contains a privileged/undefined instruction (int3, ud2, hlt, in/out, cli/sti, lgdt...) or the gadget is pure control flow.
   That single tier is what moves `pop rdi ; ret` above `retf 0xce39` — the R12 quality score alone cannot, because it gives 100 to every <=2-instruction single-side-effect gadget, which is 92% of them. Also expose `order: "address" | "rank" | "quality" | "text"` and echo the applied order in the response, so the agent knows what it got. Reject unknown values (already done) but list the valid set in the error.

B. CURSOR. Add `cursor: Option<String>` to GadgetQuery/SearchQuery/RawCommandQuery and `next_cursor: Option<String>` to the response. The cursor is base64url of a small struct {v:1, cache_key, order, offset, params_hash}. On presentation, verify params_hash matches the current request's parameters (so an agent cannot accidentally page one query with another's cursor) and that the cache entry still exists; if it does not, return `cursor_expired` with `{"retryable":true,"suggestion":{"arguments_patch":{"cursor":null}}}`. Pin cursored entries: mark the LRU entry as recently-used on each page and refuse to evict entries with an outstanding cursor younger than --cursor-ttl-secs (default 300). Pagination is what turns "40872 gadgets, here are the first 1000 alphabetically" into something an agent can actually consume.

C. STABLE IDS. `id = "g_" + base32_nopad(blake3(binary_sha256_bytes || vaddr.to_le_bytes() || bytes)[..10])` — stable across calls, across processes, across cache evictions, and independent of scan parameters. Return it on every GadgetRecord. Add a tool `get_gadgets(binary_path, ids: [String])` that resolves ids from the cache or by rescanning at the recorded depth. This is what lets an agent say "build a chain using g_ab12... and g_cd34..." and lets build_rop_chain report which gadgets it selected in a form the agent can look up rather than re-parse from text.

**Test that proves it** (and would have caught the original bug)

crates/rf-mcp/tests/paging.rs `cursor_walks_the_whole_set_exactly_once`: on elf-Linux-x64 depth 4, page with max_results=100 until next_cursor is null; assert the concatenated ids are exactly the id set from one max_results=50000 call, in the same order, with no duplicates and no gaps (2789 gadgets, 28 pages). Assert a cursor from a depth-4 query rejected against a depth-6 query with cursor_expired. crates/rf-classify: `rank_puts_useful_gadgets_first` — on elf-Linux-x64, assert `pop rdi ; ret` and `pop rsi ; ret` appear in the top 20 by rank and that no `retf`/`ret imm16` gadget does. Today `pop rdi ; ret` is not in the top 8 and three `retf`/`ret imm` gadgets are.

### 9. [usability] rf-classify computes regs_written, regs_read, labels, class, side_effects and dispatcher for every gadget, and none of it is filterable in the MCP surface — the tools expose only depth/section/base/offset/only/range/badbytes/max_results/sort_by. An agent cannot ask the tool's most common real question and must instead pull thousands of gadgets into context.

*Effort:* 1 hour · *Closes:* `CLS-08`, `ECO-01`, `CLS-09`, `CLS-05`, `ECO-07`
*Files:* `crates/rf-classify/src/lib.rs`, `crates/rf-classify/src/x86.rs`, `crates/rf-mcp/src/lib.rs`, `crates/rf-cli/src/lib.rs`

**Design**

Add the semantic fields to the cached record, then add a constraint-search tool over them.

1. Extend CachedGadget (lib.rs:137-158) with labels: Vec<String>, regs_written: Vec<String>, regs_read: Vec<String>, side_effects: u32, low_confidence: bool, stack_delta: Option<i64>, terminator: String. The classification already happens once at scan time (lib.rs:634) and is thrown away except for quality/class; keeping it costs nothing extra at scan time and removes the on-demand reclassification path in sort_by_quality (which is where the char-boundary panic lives).
2. Add `stack_delta` to rf-classify (this is new work, ECO-07/CLS-09): for x86/x64 via iced-x86, sum pop-family width + `ret imm16` immediate + `add/sub rsp, imm` + `leave`; None when a non-constant rsp effect is present. This is the field that decides whether a gadget can appear mid-chain at all, and no consumer can compute it from the text.
3. Fix CLS-05 first or the filter returns garbage: crates/rf-classify/src/lib.rs:218-224 takes the first comma-separated operand token verbatim, so ARM `pop {r4, r5, pc}` yields the register name "{r4" and `bhi #0x12e44` yields "#0x12e44". Strip `{`/`}`/`!`/`^`, reject tokens starting with `#` or `[`, expand `{r4-r7}` ranges, and add the conditional-branch mnemonics (b<cond>, cbz/cbnz, tbz/tbnz) to the control blocklist at lib.rs:192-215.
4. New tool `find_gadgets_by_effect` with parameters: binary_path, sets_regs: [String], from_stack: bool (require the write to come from a pop/load, not an arbitrary computation), preserves_regs: [String] (reject gadgets writing any of these), require_classes/forbid_classes: [Class], max_side_effects: u32, max_insns: u32, terminator: "ret"|"jmp"|"call"|"syscall"|"any", max_stack_delta: i64, plus the existing depth/section/range/badbytes/align/max_results/cursor. It is a pure predicate over the cached set, so it needs no new scan machinery. Each returned gadget carries an explanation object: {"sets":["rdi"],"reads":["rsp"],"clobbers":["rax"],"stack_delta":16,"why":"pop rdi loads rdi from the stack; ret is a clean terminator"}.
5. Surface the same filters on the CLI (--class, --label, --writes-reg, --preserves-reg, --max-side-effects) so the two interfaces stop diverging; the MCP already has --re and --align that the CLI lacks (CLI-09, CLI-10), which is the same divergence in the other direction.

**Test that proves it** (and would have caught the original bug)

crates/rf-mcp/tests/effect_search.rs, one test per real question: on elf-Linux-x64, find_gadgets_by_effect{sets_regs:["rdi"], from_stack:true, preserves_regs:["rsi","rdx"], max_side_effects:1, terminator:"ret"} must return exactly the gadget at 0x401648 (`pop rdi ; ret`, confirmed present by my search_gadgets_by_pattern run) and must NOT return any gadget whose regs_written intersects {rsi,rdx}. Cross-check every returned gadget by re-deriving its regs_written independently from the text. For CLS-05: assert that on elf-ARMv7-ls and elf-ARM64-bash, no regs_written token starts with '{', '#' or '[' and every token matches ^(r[0-9]+|x[0-9]+|w[0-9]+|sp|lr|pc|fp|ip|sl|sb)$ — today `{r4` and `#0x12e44` appear.

### 10. [usability] Chain failures are prose. windows-virtualprotect on the shipped PE fixture returns `chain_error: "cannot populate rdx: no 'pop rdx' gadget and no 'pop rax' + 'mov rdx, rax' fallback (see tests/spike-report.md ...)"`. An agent cannot act on that. Related: the target API is hardcoded to VirtualProtect with no parameter, so the IAT path is unreachable on the very fixtures the project ships; the chain generator emits a Python script with an unescaped PE-supplied DLL name interpolated after a `#`.

*Effort:* hours · *Closes:* `ECO-04`, `CHWIN-06`, `CHWIN-04`, `ROB-01`
*Files:* `crates/rf-chain/src/lib.rs`, `crates/rf-chain/src/windows.rs`, `crates/rf-mcp/src/lib.rs`, `crates/rf-cli/src/lib.rs`

**Design**

A. STRUCTURED FEASIBILITY. Split build_rop_chain into `plan_chain` (analysis, always succeeds) and `build_rop_chain` (emission). plan_chain returns:
     {"target":"windows-virtualprotect","feasible":false,
      "requirements":[{"id":"set_rdx","description":"load flNewProtect into rdx","satisfied":false,
                       "strategies_tried":[{"pattern":"pop rdx ; ret","candidates":0},
                                           {"pattern":"pop rax ; ret + mov rdx, rax ; ret","candidates":0}],
                       "relaxations":[{"param":"depth","from":10,"to":24,"would_help":"unknown"},
                                      {"param":"multibr","to":true},
                                      {"param":"modules","hint":"add a loaded DLL via open_workspace"}]}],
      "satisfied_requirements":[{"id":"set_rcx","gadget_id":"g_ab12...","vaddr":"0x..."}]}
   `relaxations` is the point: it turns a dead end into a next action. build_rop_chain returns the same `requirements` array on failure so an agent gets one response shape either way.
B. Plumb `api_name` (WinChainOpts::api_name at windows.rs:52,67 exists and is never set from anywhere — grep matches only windows.rs) into both the CLI and the MCP ChainQuery, defaulting to VirtualProtect. Without it the IAT path cannot target VirtualAlloc, which is what the shipped cmd.exe fixtures actually import.
C. Plumb `chain_base_parity: "aligned"|"return_address"` (default return_address, the saved-return-address case, which is the common one and the opposite of the hardcoded assumption at windows.rs:25-29), echo the assumption in the JSON and in the emitted script's preamble, and validate against it.
D. Sanitise the generated Python. rf-chain/src/lib.rs:227,233 interpolate a PE-supplied DLL name straight after `#`. Replace with a `fn py_comment(s: &str) -> String` that strips everything outside [ -~], truncates to 64 chars, and refuses newlines; better, emit comments only from a fixed vocabulary and put untrusted strings in the JSON IR (where they are data) rather than in executable output. Add `#![forbid]`-style review note: any untrusted string reaching to_python must go through py_comment.

**Test that proves it** (and would have caught the original bug)

crates/rf-mcp/tests/chain_plan.rs: plan_chain{target:"windows-virtualprotect"} on pe-x64-cmd-v6.1.7601 must return feasible:false with a requirements entry id=="set_rdx", satisfied:false, at least one non-empty `relaxations` entry, and a non-empty satisfied_requirements list — today the same input yields one prose string. plan_chain{target:"linux-execve"} on elf-Linux-x64 must return feasible:true and its gadget_ids must resolve via get_gadgets. For ROB-01: a fuzz/unit test that builds a PE whose import DLL name contains "\nimport os\n" and asserts to_python() output contains no line beginning with `import` other than the fixed header, and that ast.parse of the output has exactly the expected top-level statements.

### 11. [observability] The only output the server ever produces is one startup line on stderr, which MCP hosts discard. Nothing records which binaries were scanned, which chains were built, or which paths were refused — and the refusal count is precisely the signal that would reveal the filesystem probing I demonstrated. For a tool the project itself classifies as dual-use, this is the cheapest missing control.

*Effort:* hours · *Closes:* `MCP-09`, `MCP-07`
*Files:* `crates/rf-mcp/src/audit.rs`, `crates/rf-mcp/src/lib.rs`, `crates/rf-mcp/src/main.rs`, `crates/rf-mcp/Cargo.toml`

**Design**

Structured logging plus a stats tool. Nothing here may touch stdout — stdout is the JSON-RPC transport and a stray println! corrupts the session.

1. Adopt `tracing` + `tracing-subscriber` with a stderr layer (level from RUST_LOG, default warn) and an optional JSONL file layer.
2. `--audit-log <path>`: opened once with O_APPEND|O_CREAT, mode 0600, one JSON object per line:
   {"ts":"2026-09-03T10:11:12.345Z","session":"<uuid>","req_id":42,"tool":"find_gadgets",
    "binary":"<root-relative label>","binary_sha256":"...","params_hash":"...",
    "verdict":"ok|denied|timeout|cancelled|error","code":null,"duration_ms":37,
    "total_count":2789,"returned":1000,"cache":"miss","bytes_read":901234}
   Denials log the REQUESTED path (that is the whole point) but never file contents or gadget text. Rotate at --audit-log-max-mb (default 64) by renaming to .1/.2.
3. Counters, atomics on the server struct, exposed by a `get_server_stats` tool and logged on shutdown: requests_total by tool, denied_total, denied_consecutive, timeout_total, cancelled_total, wedged_total (workers that did not stop within 5 s of cancellation — a direct health signal for the cancellation fix), cache_hit/miss/tamper/evictions, cache_bytes, inflight, bytes_read_total, peak_rss.
4. Startup warnings, to stderr AND the audit log: allowlist wider than expected, cache dir with loose permissions, on-disk cache running without an integrity key, --i-accept-a-wide-allowlist in effect.
5. Declare the MCP `logging` capability and forward warn/error events as notifications/message so the host surfaces them to the operator, who otherwise never sees stderr.

**Test that proves it** (and would have caught the original bug)

crates/rf-mcp/tests/audit.rs: run a session of one allowed scan, one denied path, one timeout; assert the audit file has exactly 3 lines, each valid JSON with the required keys, that the denied line carries verdict:"denied" and the requested path, that NO line contains any gadget text or file bytes, and that the file mode is 0600. Separately, a `stdout_is_pure_jsonrpc` test that runs a full session including an error and a panic-inducing cache entry, and asserts every stdout line parses as a JSON-RPC message with jsonrpc=="2.0" — the cheapest possible guard against a future println! breaking the transport.

### 12. [resource-control] get_binary_info is the one tool with neither timeout_secs nor max_results, and the only one that does its blocking work (whole-file std::fs::read + goblin parse) directly in the async handler rather than on a worker, so it occupies a tokio runtime thread. No tool bounds input file size. README/MANUAL claim every call is capped.

*Effort:* hours · *Closes:* `MCP-06`, `MCP-03`
*Files:* `crates/rf-mcp/src/lib.rs`, `fuzz/fuzz_targets/load.rs`, `README.md`, `MANUAL.md`

**Design**

Move get_binary_info (lib.rs:901-919) onto the shared run_guarded helper: it takes a ConfinedFile, reads through the handle under --max-file-bytes, runs goblin on a blocking worker under the same semaphore and timeout as everything else. Add timeout_secs to InfoQuery (lib.rs:341-347) and a max_sections/max_imports cap (default 4096 each) so a hostile PE with a million import entries cannot produce a gigabyte of JSON — cap and set warnings:[{code:"imports_truncated"}].

While there: goblin parsing of attacker-supplied binaries is the largest untrusted-input surface in the process, and there is currently no fuzzing anywhere in the tree. Add cargo-fuzz targets for rf_core::Binary::load, rf_cli::info_bytes and rf_cli::scan_bytes (bounded depth), seeded from tests/fixtures, and run them in CI for 60 s per target on every PR plus a nightly long run.

Also correct the docs: README.md:340-346 and MANUAL.md:355-357 must state the actual caps (max_results, timeout, max_depth, max_file_bytes, max_gadgets, max_concurrent) and say plainly that a timed-out request now stops the work rather than orphaning it.

**Test that proves it** (and would have caught the original bug)

Extend the tests/expected_tools_schema.json snapshot to require timeout_secs on EVERY tool including get_binary_info — this snapshot already exists and recorded the omission without failing, which is the interesting part. Add `oversized_file_is_refused`: create a sparse 512 MiB file in the allowlist, call get_binary_info with --max-file-bytes 268435456, assert resource_exhausted with details.limit=="max_file_bytes" and that the server's RSS grew by under 20 MB. Add `info_does_not_block_the_runtime`: issue 4 concurrent get_binary_info on the largest fixture and assert a tools/list issued alongside them answers in under 100 ms.

### 13. [correctness] The MCP advertises --align in the run_ropgadget_command allowlist and implements it as an address post-filter over already-found gadgets, which is not what ROPgadget's --align does (it changes which start offsets are considered during the scan) and silently under-reports by roughly half. The CLI does not expose --align at all, and the MCP parses its argument as hex where ROPgadget takes decimal.

*Effort:* days · *Closes:* `ANCH-02`, `CLI-10`, `ANCH-01`
*Files:* `crates/rf-scan/src/engine.rs`, `crates/rf-mcp/src/lib.rs`, `crates/rf-cli/src/lib.rs`

**Design**

Implement alignment in the engine and make the two front ends agree.

1. Add `align: Option<u64>` to rf_scan::ScanOptions. In engine.rs x86_scan_anchor, the candidate-start loop at :365 currently steps `start = ref_pos - i` for i in 0..depth. Under alignment, mirror the cs.rs:282-310 structure that already exists for non-x86: step by `i * align` and skip starts where `(sec_vaddr + start) % align != 0`. The non-x86 path already does this correctly, so this is porting a known-good loop into the x86 scanner, not new design.
2. Delete the post-filter at rf-mcp lib.rs:672-681 and pass align through to ScanOptions.
3. Parse align as DECIMAL first, hex only with an explicit 0x prefix (ROPgadget takes an int). Today rf-mcp tries parse_hex first, so `--align 16` is read as 0x16 == 22 — a silently wrong answer, not an error.
4. Expose --align on the CLI, and add --re there too (CLI-09): the CLI is currently behind its own MCP server on both flags.
5. Because align changes the scan, it must join the cache param_hash (lib.rs:602-621) — it is a post-filter today so it is not in the key, and adding it to ScanOptions without adding it to the key would serve an unaligned cached result for an aligned query.

**Test that proves it** (and would have caught the original bug)

Extend tests/parity.py to a parametrised align case: for each x86/x64 fixture and align in {2,4,8,16}, compare the (vaddr, bytes) set against `ROPgadget --align N` from the vendored oracle at ../ropgadget, run under the capstone-5.0.7 venv. Assert exact set equality; the post-filter currently loses roughly half. Add a unit test asserting `--align 16` yields alignment 16, not 22.

### 14. [packaging] dist/linux-x86_64/{rop-finder,rop-finder-mcp} are mode 0666 — not executable, so the MCP host's spawn fails outright. dist/macos-arm64 contains only a build script and dist/macos-x86_64 is empty, so there is no macOS build at all despite this being a macOS-developed project. There is no LICENSE in the Rust tree and no CI.

*Effort:* days · *Closes:* `ENG-01`, `MCP-08`
*Files:* `LICENSE`, `NOTICE`, `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `dist/README.md`, `MANUAL.md`

**Design**

A. LICENSE + NOTICE at rop-finder/. This is a port of ROPgadget (BSD-3, ropgadget/LICENSE_BSD.txt in this repo); ship a LICENSE for the Rust work and a NOTICE that credits ROPgadget/Jonathan Salwan and states the port relationship. Add license/repository/description to every crate's Cargo.toml — they are currently path-only deps with no metadata, so nothing is publishable.
B. .github/workflows/ci.yml: matrix over ubuntu-22.04, macos-14 (arm64), macos-13 (x86_64), windows-2022 x stable. Steps: cargo fmt --check; cargo clippy --workspace --all-targets -- -D warnings; cargo test --workspace; cargo deny check (advisories, licenses, bans); the fuzz targets for 60 s each; and on Linux the parity harness against the vendored oracle. There is no CI at all today, so every one of these is new.
C. .github/workflows/release.yml, triggered on tag. Targets: x86_64-unknown-linux-musl and aarch64-unknown-linux-musl (static — an MCP host may launch the binary under any glibc), aarch64-apple-darwin + x86_64-apple-darwin combined with `lipo -create` into one universal binary, x86_64-pc-windows-msvc and aarch64-pc-windows-msvc. Package as .tar.gz on Unix (tar preserves mode 0755 — loose files in a git tree do not, which is exactly the 0666 bug) and .zip on Windows. Publish SHA256SUMS plus a minisign/cosign signature.
D. macOS signing is mandatory, not optional: an unsigned downloaded binary is quarantined by Gatekeeper and Claude Desktop's spawn fails with no visible error. `codesign --sign "Developer ID Application: <org>" --options runtime --timestamp` on both binaries, then `xcrun notarytool submit --wait` on the zip and `xcrun stapler staple`. Document `xattr -d com.apple.quarantine /usr/local/bin/rop-finder-mcp` as the unsigned-build fallback.
E. Document the exact host config, with the flags this design requires. macOS ~/Library/Application Support/Claude/claude_desktop_config.json, Linux ~/.config/Claude/claude_desktop_config.json:
   {"mcpServers":{"rop-finder":{
     "command":"/usr/local/bin/rop-finder-mcp",
     "args":["--allow-dir","/Users/me/exploit-work/binaries",
             "--cache-dir","/Users/me/.cache/rop-finder",
             "--audit-log","/Users/me/.local/state/rop-finder/audit.jsonl",
             "--max-depth","32","--max-concurrent","2",
             "--max-file-bytes","268435456","--timeout-secs","60"],
     "env":{"RUST_LOG":"rf_mcp=info"}}}}
   Windows %APPDATA%\Claude\claude_desktop_config.json with "command":"C:\\Program Files\\rop-finder\\rop-finder-mcp.exe" and doubled backslashes in every path. Claude Code: `claude mcp add rop-finder -- /usr/local/bin/rop-finder-mcp --allow-dir /path/to/binaries`.
   State explicitly in MANUAL.md that there is NO cwd key in this config format — that is precisely why the cwd default had to be removed, and an operator reading the current manual has no way to know their allowlist is wider than the one flag they passed.

**Test that proves it** (and would have caught the original bug)

A release smoke job that, on each of the four runners, downloads its own freshly built artifact, extracts it, asserts the binary is executable (`test -x`, or mode & 0o111 != 0), runs `rop-finder-mcp --version`, then drives a full MCP session over stdio — initialize, notifications/initialized, tools/list (assert 9 tools with outputSchema), find_gadgets against a bundled fixture — and asserts the gadget count matches the CI-recorded value. That job fails today at `test -x` on Linux and at "file does not exist" on macOS.

---

## New capabilities

Safety is the floor. These are what make the server useful to an agent.

### `find_gadgets_by_effect (constraint/register-aware search)`



**Why.** This is the single biggest gap, and it is a gap in DATA THE TOOL ALREADY HAS. An agent's real question is "give me a gadget that loads rdi from the stack and does not clobber rsi or rdx". Today it must call find_gadgets, receive 1000 alphabetically-ordered records starting at `adc al, 0x89 ; retf 0xc281`, and filter them in its own context window — which is the exact failure mode an MCP server exists to eliminate. ropper (--search, --semantic), angrop (rop.set_regs(rdi=X)) and pwntools (rop.find_gadget([...])) all have this; rop-finder has it computed and unreachable.

**Design.** Filter predicate over the semantic fields already produced by rf_classify::classify at scan time (rf-mcp lib.rs:634) once they are persisted into CachedGadget. Parameters: sets_regs, preserves_regs, reads_regs, from_stack (require the write to originate in a pop/load rather than an arithmetic result), require_classes/forbid_classes over the eight Class values, max_side_effects, max_insns, max_stack_delta, terminator, call_preceded, plus the standard depth/section/range/badbytes/align/max_results/cursor. Each result carries an explanation object {sets, reads, clobbers, stack_delta, terminator, why} so the agent can justify its choice without re-deriving semantics from text. Prerequisites, in order: persist labels/regs_written/regs_read/side_effects into the cache record; add stack_delta to rf-classify (iced-x86 for x86/x64; None elsewhere rather than a wrong number); fix CLS-05 so regs_written stops containing `{r4` and `#0x12e44` on ARM; and expose low_confidence in every response so an agent knows the non-x86 answers are heuristic. Mirror the same flags on the CLI.

### `plan_chain — machine-readable feasibility with relaxations`



**Why.** When an agent asks "can you build me a chain that does X" and the answer is no, it currently gets a sentence: "cannot populate rdx: no 'pop rdx' gadget and no 'pop rax' + 'mov rdx, rax' fallback". That is a dead end. An agent needs to know WHICH requirement failed, what was tried, what is already satisfied, and what change might succeed — otherwise it either gives up or retries the identical call.

**Design.** plan_chain(binary_path, target, depth, api_name, chain_base_parity, badbytes, modules) -> {feasible, requirements[], satisfied_requirements[], assumptions{}}. Each requirement carries id, description, satisfied, strategies_tried[{pattern, candidates}], and relaxations[{param, from, to, would_help}]. Relaxations are computed, not guessed: re-run the per-requirement gadget query at depth*2 and with multibr, and report whether candidates appear. `assumptions` states the things the builder silently assumes today — chain base alignment (windows.rs:25-29 assumes a 16-byte-aligned base; the saved-return-address case, which is the common one, is the opposite), which writable section will hold the string, and whether an info leak is required. build_rop_chain returns the same shape on failure, so the agent handles one contract. Also plumb api_name (WinChainOpts::api_name exists at windows.rs:52 and is set from nowhere) so the IAT path can target VirtualAlloc — the API the shipped cmd.exe fixtures actually import.

### `get_mitigations (checksec-equivalent)`

*Effort:* days

**Why.** Before an agent decides ROP is even the right technique, it must know whether the target has NX, PIE, RELRO, a stack canary, CFG/CET, or a shadow stack. get_binary_info returns format/arch/sections/imports and nothing about mitigations, so the agent either guesses or asks the human to run checksec. Everything needed is already in headers goblin parses, so this is close to free — and it changes the agent's whole plan, which few other additions do.

**Design.** New tool over the loaded image, no scan. ELF: NX from PT_GNU_STACK flags, PIE from ET_DYN plus a DT_DEBUG/interpreter check, RELRO from PT_GNU_RELRO plus DT_BIND_NOW/DF_BIND_NOW, canary from a __stack_chk_fail import, FORTIFY from *_chk imports, and a symbol/dynsym listing (also missing today, ECO-06). PE: DllCharacteristics for DYNAMICBASE / NXCOMPAT / GUARD_CF / HIGH_ENTROPY_VA, and the load-config directory for CETCOMPAT and the GuardFlags — this also fixes CRIT-01, where --cfg-aware conflates GUARD_CF with Intel CET/IBT and its promised warning never fires. Mach-O: PIE from MH_PIE, hardened runtime and code-signature presence. Return {mitigation: {enabled: bool|"unknown", evidence: "..."}} — "unknown" with a reason is far more useful to an agent than a confident wrong boolean.

### `find_string / find_bytes within the confined binary`

*Effort:* days

**Why.** Every real chain needs to locate "/bin/sh", a "cmd.exe" literal, or a specific byte pattern in the target. ROPgadget's --string/--memstr are blanket-rejected by the flag allowlist because they were treated as a file-read leak — but the agent can already obtain the file's executable bytes through find_gadgets, so the ban costs a core capability and buys nothing. It just needs to be scoped so it stays a binary-analysis primitive rather than a file-dump primitive.

**Design.** find_string(binary_path, pattern, sections?, mode: "literal"|"regex"|"hex") searching only within MAPPED sections of the loaded image (never raw file offsets, never bytes outside a section), returning {vaddr, section, length, printable_preview (<=64 chars, non-printables escaped), writable, executable}. find_bytes takes a hex pattern with `??` wildcards for the same regions. Cap matches at max_results with a cursor. Deliberately still absent: any tool that returns arbitrary file offsets or a raw dump — that is the line the flag allowlist was drawn to protect, and this design keeps it while restoring the capability. Also add --callPreceded (ECO-03/CLI-04): it needs the engine to capture up to 7 preceding bytes per gadget, since rf_scan::Gadget carries only {vaddr, bytes, insns, delay_slot}. On a hardened target that filter is the difference between 2768 candidate gadgets and the 414 that are legal return sites.

### `Results as MCP resources + a workspace directory`

*Effort:* days

**Why.** The MIPS fixture alone has 40,872 JOP gadgets. No agent can hold that in context, and paging 1000 at a time through 41 calls is nearly as bad. Agents are much better served by being handed a file they can grep with their own tools than by being streamed records they must summarise.

**Design.** Declare the MCP `resources` capability. Any scan whose total_count exceeds `returned` also returns resource_uri: "ropfinder://scan/<cache_key>/gadgets.ndjson", served by resources/read with range support, one GadgetRecord per line. With --workspace-dir <path> (which must lie outside every allow root), the same NDJSON is materialised as a real file and its path returned, so an agent with filesystem tools can grep/sort/join it directly. Include a matching .schema.json. Files are keyed by cache_key, garbage-collected on the same LRU schedule as the cache, and never written into an allowed root.

### `Progress notifications and honoured cancellation`

*Effort:* days

**Why.** A scan of a large binary at depth 24 takes tens of seconds. Today the client blocks silently and then, if the timeout wins, gets an error — while the work continues to burn four cores. I proved notifications/cancelled is accepted and ignored. An agent that can see progress and can stop a scan it no longer needs is a fundamentally different tool from one that can only wait and hope.

**Design.** Honour the `_meta.progressToken` on tools/call: the scan worker publishes {progress, total, message: "region 3/7, 12480 gadgets"} through a bounded channel that the async side drains into notifications/progress at most every 250 ms (rmcp's Peer::notify_progress). Sourced from the same counters as the cancellation checks in engine.rs:359/365 and cs.rs:282/288, so it costs one relaxed atomic store per 1024 anchor hits. Wire ctx.ct (rmcp's RequestContext CancellationToken, which is already fed by notifications/cancelled) to the rf-scan CancelToken so a cancelled request returns {"code":"cancelled"} within one check interval and releases its semaphore permit. Optionally return partial results on cancellation with warnings:[{code:"partial"}] — often exactly what the agent wanted.

### `open_workspace — multi-module analysis`



**Why.** Real exploitation is never single-binary: you chain the target plus libc plus a loaded DLL, each at its own base. rop-finder is single-binary everywhere (ECO-08), so an agent working a realistic target must call the tool once per module, track bases by hand, and merge the results itself — and build_rop_chain can only ever see one module, which is why the Windows chain fails on the shipped fixtures for want of a `pop rdx` that certainly exists in kernel32.

**Design.** open_workspace(modules: [{binary_path, base?, name?}]) -> {workspace_id, modules:[{name, sha256, arch, base, mitigations}]} with a validation pass rejecting mixed architectures. Every gadget-returning tool accepts `workspace` in place of `binary_path`, scans each module with its own base, and tags each record with `module`. Gadget ids already include the per-module binary_sha256, so they stay unique and stable across a workspace. plan_chain then draws requirements from the union and reports which module satisfies each — turning "cannot populate rdx" into "rdx satisfied by kernel32.dll+0x1a2b3". Workspaces are in-memory, TTL'd, capped by --max-workspaces and by total module bytes.
