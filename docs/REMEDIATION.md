# Remediation plan

Closes all 137 findings from the September 2026 independent audit, in six tagged releases.

> **Six tagged releases — legal and honest in one day, trustworthy results by One day, a genuinely workable MCP server , and 1.0  — with the scan engine reshaped exactly once so no release rewrites the same loop twice.**

The finding IDs used throughout (`CORE-01`, `MCP-03`, …) are defined in
[docs/AUDIT-FINDINGS.md](docs/AUDIT-FINDINGS.md). The measured baseline this plan cites is in
[docs/measured-2026-09.md](docs/measured-2026-09.md). The implementation spec for the MCP
work in Phases 1 and 3 is in [docs/MCP-DESIGN.md](docs/MCP-DESIGN.md).

## Coverage

| | Count |
|---|---|
| Findings in the ledger | 137 |
| Assigned to a phase | 134 |
| Deferred with justification | 3 |
| Missing / duplicated / invented | 0 / 0 / 0 |

Verified mechanically against the ledger, not by inspection.



## How the phases are bounded

Phase boundaries sit where the tree can be tagged, published and announced with a README that is true on the day it ships. Three gates set them, and one graft cuts across them.

GATE 1 — LEGAL. There is no LICENSE anywhere in the Rust tree while Cargo.toml declares BSD-2, and 24 fixtures are byte-identical Microsoft/Apple/GPL binaries. Nothing can be published — not a crate, not a GitHub release, not a signed binary — until ENG-03/ENG-12 close. That alone forces a small v0.1.1 ahead of all engineering.

GATE 2 — TRUTH. Every release must retract or substantiate its own claims. A retraction is a complete fix for an unsubstantiated-claim finding and costs hours, so v0.1.1 retracts aggressively: the >=10x headline (measured 5.7-6.2x), the 1.0000 classifier precision (self-agreement), the "~0.05-0.2% divergence" (measured 15-29% of gadget texts), the three MCP security guarantees, the ntoskrnl ring0 demo, the ARM64-PAC roadmap item. A false README is this project's single most damaging defect and it is fixable in hour one. Where a feature is broken and cannot be fixed yet, the release DELETES or warning-gates the surface rather than shipping a lying one: --align comes out of the MCP tool schema, --chain windows-virtualprotect gets an experimental gate, the --cfg-aware recommendation comes out of the MANUAL. A missing capability is safer than a capability that under-reports by 53%.

GATE 3 — CONSUMER. A release ships only when its consumer can use it. The MCP server is third, not first, because an agent cannot verify anything it is told: hardening rf-mcp on top of a loader that silently fabricates gadgets from unrecognized e_machine values (CORE-01) and reports a Mach-O base of 0 (CORE-02) would make the product more trusted while it is still wrong. But the two findings that can INJURE the operator rather than merely mislead them — attacker-controlled Python from an analyzed PE reaching the interpreter (ROB-01), and the MCP arbitrary-read plus existence oracle (MCP-01/02/07) — are pulled into v0.1.1, because "critical first" beats thematic tidiness.

THE GRAFT. The losing dependency-ordered plan proved, and I re-verified in source, that rf_scan::Gadget carries only {vaddr, bytes, insns, delay_slot} — no preceding bytes, no table provenance — and ScanOptions carries only {depth, rop, jop, sys, multibr, only, range, badbytes, filter, offset, thumb, cfg_aware, parallel} — no all, no align, no call_preceded, no cancellation. Roughly thirty findings are edits to those two declarations, to post_process, and to one loop (x86_scan_anchor plus its capstone twin). Spread across releases, that loop gets rewritten four times and parity re-litigated four times. So the engine SHAPE change lands exactly once, in v0.2, even where the features it enables only light up in v0.3 (cancellation), v0.4 (constraint search) and v1.0 (streaming perf). That is the one place this plan overrides pure release logic, and it is why v0.2 is the fattest release.

## Before the first commit

There is no phase zero, but three things must be true before the first commit of v0.1.1 and they are hours of work, not a phase: (1) `cargo build --release && cargo test --workspace` currently passes with 153 tests and zero warnings — capture that as the baseline, because v0.1.1 changes exit codes and the CI job must be written against known-good behaviour; (2) record the current measured numbers in a file (`docs/measured-2026-09.md`): gadget parity 99.93% (763,186/763,718), 11/24 fixtures bit-exact, x86/x64 5.7-6.2x, ARM64 2.1x, MIPS 1.7x, PPC 1.3x, all at --depth 10 — the v0.1.1 retraction workstream edits README/MANUAL/PLAN to cite that file, so it must exist first; (3) confirm the ROPgadget 7.7 oracle at `../ropgadget` and the capstone-5.0.7 venv still run, since every parity criterion in v0.2 onward depends on them.

## Release summary

| Phase | Release | Findings | Effort |
|---|---|---|---|
| 1 | **v0.1.1** — Honest, legal, and not dangerous | 33 | 1-Hour |
| 2 | **v0.2.0** — Results you can trust, and the engine reshaped once | 47 | 1-hour |
| 3 | **v0.3.0** — The workable MCP server: bounded, cancellable, ranked, auditable | 21 | 1-hour |
| 4 | **v0.4.0** — Ask a real question | 9 | 1-hour |
| 5 | **v0.5.0** — Chains that actually run | 16 | 1-hour |
| 6 | **v1.0.0** — Fast enough to say so, and published | 8 | 1-hour |
| — | *deferred* | 3 | — |

## Where the MCP work sits

Full implementation spec: [docs/MCP-DESIGN.md](docs/MCP-DESIGN.md).

The MCP work is deliberately split across three releases by what each half depends on, and it is a first-class deliverable in every one — not a wrapper bolted on at the end.

v0.1.1  — SECURITY, which depends on nothing. This closes the live arbitrary-file-read: confine_path (rf-mcp/src/lib.rs:112-133) is deleted and replaced by an open-then-verify `open_confined` returning a HANDLE (O_NOFOLLOW openat walk from a pinned root dirfd on Unix; CreateFileW plus GetFinalPathNameByHandleW/volume-serial validation on Windows), with all three `std::fs::read(&path)` sites at :599/:757/:913 removed so a handle, not a name, crosses into spawn_blocking — the measured 323-of-400 leak rate goes to zero. The cwd is dropped from the default allowlist and `--allow-dir` becomes mandatory and meaningful, with wide roots refused. The three-code error taxonomy that acts as a whole-filesystem existence oracle collapses to one `path_denied` returned before any syscall. Interim caps (hard --max-depth, concurrency semaphore) bound the runaway even though MCP-03 does not close until v0.3. The false security guarantees in README/MANUAL are rewritten in the same commit as the code that makes them true.

v0.3.0  — CAPABILITY, which is the release the user asked for, scoped to exactly four properties: BOUNDED (uniform file-size, depth, result and concurrency caps; get_binary_info moved off the async runtime onto the shared guard), CANCELLABLE (a `run_guarded` helper that sets the v0.2 CancelToken and then JOINS the worker rather than abandoning it, so timeouts and `notifications/cancelled` actually stop the 398%-CPU runaway), RANKED (the non-obvious dependency: the server returns first-N in traversal order and `sort_by: quality` is useless because 92% of gadgets tie at 100, so all thirteen classifier findings are IN this release — the classifier work is the ranking work), and AUDITABLE (JSONL audit log of every call including denials, plus a refusal counter that is the specific signal revealing a prompt-injected agent probing the filesystem). Alongside those: outputSchema on every tool with an invariant record shape and delay_slot finally emitted, cursor pagination and stable blake3 gadget ids, class/label/register filters, NDJSON results as MCP resources, and the corrected IAT slot addresses. `--align` was REMOVED from the MCP tool schema in v0.3's predecessor work rather than left under-reporting by 53%, and returns in v0.4 once the engine implements it. The release is judged by one criterion above all: an agent completes a full locate → constrain → classify → chain loop in under 10,000 tokens of tool output.

v0.4.0  — the constraint search (`find_gadgets_by_effect`), string/opcode/byte search and checksec-grade mitigations land on the MCP and the CLI simultaneously, enforced by a capability-matrix CI test that fails on any divergence between the two surfaces — so 'the CLI is behind its own MCP server' becomes structurally impossible rather than fixed once. v0.5 adds `plan_chain`, which returns machine-readable feasibility with computed relaxations instead of today's prose dead-end.

---

## Phase 1 — v0.1.1 — Honest, legal, and not dangerous

**Effort:** 1-hour · **Findings closed:** 33

**Goal.** The tree can legally be published for the first time, no sentence in README/MANUAL/PLAN is false, CI exists, and the two ways this tool can actively injure the person running it — arbitrary file read through the MCP server, and attacker-controlled Python in generated chain scripts — are closed.

**Why here.** This is a hard gate, not a preference. With no LICENSE/NOTICE and 24 non-redistributable third-party binaries in git, there is no legal artifact to release at all, so every later release's 'ship it' is blocked behind ENG-03/ENG-12. Everything else here is hours-to-days of work with disproportionate payoff. Retraction closes eighteen unsubstantiated-claim findings completely, and a false README is the defect that costs this project the most per hour it stands — the two rival plans left the >=10x lie standing for 2 hours  respectively. The three security fixes (MCP-01/02/07, ROB-01) are each localized to one file and do not depend on any engine work, so deferring them buys nothing and leaves a live arbitrary-read primitive open. Capability is deliberately unchanged: nothing in this release makes the tool find more gadgets. Note on scope discipline: MCP-03 (non-cancellable worker) is NOT closed here — real cancellation needs the engine token that lands in v0.2 — but this release ships the interim mitigation (a hard --max-depth clamp and a concurrency semaphore at the request boundary), so the 54.8 GB / 400%-CPU runaway is bounded from 1 hour even though the finding closes in v0.3.

### Workstreams

#### Legal clearance, repo hygiene, and supply-chain pinning *(days)*

Add rop-finder/LICENSE (BSD-2 for the Rust work) and rop-finder/NOTICE reproducing ROPgadget's copyright (Jonathan Salwan, Alexey Vishnyakov, ropgadget/AUTHORS) and stating the port relationship; embed a one-line attribution in `--version` output (rf-cli/src/lib.rs). ENG-12: do NOT rewrite git history — that invalidates every clone and makes the parity gate depend on GitHub availability. Instead add tests/fixtures/PROVENANCE.md carving each of the 24 binaries out of the blanket BSD-2 declaration with its true origin and license, add tests/fixtures/MANIFEST.sha256, and add tests/fetch_fixtures.py that can re-fetch from ROPgadget's test-suite-binaries at a pinned commit for anyone who prefers not to hold the copies; the in-tree copies stay so CI never needs the network. ENG-09: delete dist/ (41 MB, mode 0666 on Linux so the binaries are not even executable, macos-x86_64 empty, leaked developer path) and replace with dist/README.md documenting `cargo build --release` plus the CI release job. ENG-13: delete ../../ROP-Finder.7z (1 GB, 95.6% cargo build artifacts). ENG-02: remove Cargo.lock from .gitignore:2, commit it, and pin the parity-critical x86 formatter exactly in the workspace Cargo.toml as `iced-x86 = "=1.21.0"` (an exact requirement — `=1.21.x` is not valid cargo syntax), matching the existing `=0.13.0` capstone pin. ENG-07: correct Cargo.toml:16 rust-version from the false 1.80 to the real floor (>=1.88, forced by the goblin/rmcp graph), add rust-toolchain.toml, and add a `cargo +$MSRV check` CI job so the number is enforced rather than restated.

*Closes:* `ENG-03`, `ENG-12`, `ENG-09`, `ENG-13`, `ENG-02`, `ENG-07`

#### CI that exists at all *(days)*

ENG-01: add .github/workflows/ci.yml — `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and the MSRV check, on a matrix of ubuntu-22.04, macos-14 (arm64), macos-13 (x86_64) and windows-2022. The Windows-specific code paths (the %LOCALAPPDATA% cache, the \\?\ verbatim handling at rf-mcp/src/lib.rs:1086, the whole VirtualProtect chain builder) have never once been executed by an automated build. ENG-11: add a `cargo deny check advisories licenses bans sources` job over the 141-package graph with 23 build scripts and 44 MB of vendored C, plus `cargo audit`. Add .github/workflows/release.yml triggered on tag, producing checksummed artifacts for x86_64/aarch64-unknown-linux-musl (static — an MCP host may launch under any glibc), a lipo'd universal macOS binary, and x86_64/aarch64-pc-windows-msvc, packaged as .tar.gz on Unix so the 0755 mode survives (loose files in a git tree do not preserve it, which is exactly the ENG-09 bug) and .zip on Windows. macOS artifacts are codesigned with `--options runtime --timestamp` and notarized with `xcrun notarytool submit --wait` then stapled; an unsigned downloaded binary is quarantined by Gatekeeper and Claude Desktop's spawn fails with no visible error.

*Closes:* `ENG-01`, `ENG-11`

#### Stop crashing: one BufWriter change closes four findings *(days)*

PERF-07 + ROB-03 + CRIT-02 are the same defect at rf-cli/src/lib.rs:1326-1333 (print_human) and :1382-1388 (print_json): a per-gadget `println!` that both costs 45,651 unbuffered syscalls (55% of x86-64 wall clock) and panics at exit 101 on EPIPE. Replace both with a single locked `BufWriter<Stdout>` and handle `ErrorKind::BrokenPipe` as a clean exit 0. Do NOT fix this by installing the default SIGPIPE disposition: that is Unix-only, this project's CI matrix includes Windows, and CRIT-02's own finding is that MANUAL.md:469-471 wrongly calls this a Windows quirk while its UC3 example triggers it on every platform — so correct that MANUAL text in the same commit. CLI-06/ENG-06: rf-cli/src/lib.rs:1514-1522 maps every clap error, including `ErrorKind::DisplayHelp` and `DisplayVersion`, to `ExitCode::from(1)`; match on the kind and return 0 for DisplayHelp/DisplayVersion/DisplayHelpOnMissingArgumentOrSubcommand. This is a CI prerequisite: the project's own build and harness scripts cannot invoke the binary correctly until it is fixed. CLI-13: rf-cli/src/lib.rs:280-282 prints 'Specify --rawArch' when --rawEndian is the missing flag; report the flag that is actually absent. ROB-05: rf-chain/src/lib.rs:227 emits a leading tab for `WordKind::Padding`, which makes EVERY generated windows-virtualprotect script an IndentationError — remove the tab, and delete the two tests at lib.rs:400,409 that assert the tab as intended.

*Closes:* `CLI-06`, `ENG-06`, `CLI-13`, `ROB-03`, `CRIT-02`, `PERF-07`, `ROB-05`

#### Close the two live security holes, and bound the MCP runaway on the way past 

MCP-01 (measured: 323 of 400 requests read a file outside the allowlist against the live server): delete confine_path (rf-mcp/src/lib.rs:112-133) and replace with a new crates/rf-mcp/src/confine.rs exposing `open_confined(roots, input, max_bytes) -> ConfinedFile` that returns a HANDLE and never touches the path again. At startup, open each --allow-dir and keep the dirfd for the process lifetime, recording dev/ino (Unix) or volume-serial + file-index (Windows). Per request: (a) lexical phase with no syscalls — require absolute, reject any `.`/`..` component and interior NUL, on Windows reject \\?\, \\.\, UNC and any ':' after the drive letter; select the root by component-wise match; (b) Unix — walk the remainder from the pinned dirfd with `rustix::fs::openat(..., O_RDONLY|O_NOFOLLOW|O_CLOEXEC)` per component, which makes the resulting fd provably a descendant because no name is resolved twice; Windows — CreateFileW once, then validate the HANDLE with GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED|VOLUME_NAME_GUID) against the root's own final path, require GetFileType == FILE_TYPE_DISK and a matching volume serial; (c) fstat the handle — require a regular file (this also rejects FIFOs, which would hang std::fs::read forever) and len <= max_bytes. Then delete all three `std::fs::read(&path)` sites at rf-mcp/src/lib.rs:599, :757, :913 and read from the handle instead; ConfinedFile is Send so the handle, not a name, crosses into spawn_blocking. MCP-02: ServerConfig::default() (lib.rs:78-83) seeds allow_dirs with the process cwd and main.rs:41-54 only appends, so --allow-dir can never narrow anything — and claude_desktop_config.json has no cwd key, so the operator cannot control it. Set `allow_dirs: Vec::new()`, make --allow-dir the only source, exit 2 with an explanatory message when none is given, add an explicit --allow-cwd opt-in for `cargo run`/CI, and refuse `/`, a Windows drive root, $HOME, an ancestor of $HOME, /etc, /usr, /var, /System, /Library, C:\Users, C:\Windows unless --i-accept-a-wide-allowlist. Also reject a --cache-dir or --audit-log that falls inside an allow root. MCP-07: confine_path checks containment LAST (canonicalize -> is_file -> allowlist), so `not_a_file` / `path_not_allowed` / `path_not_found` distinguish exists-as-dir / exists-as-file / absent for any absolute path on the machine — confirmed live against ~/.ssh, ~/.ssh/id_rsa, /etc/passwd, /etc/shadow, ~/.aws/credentials. In the new design the lexical phase returns a single `path_denied` with no syscall at all, and every failure inside a root also maps to `path_denied` by default with no errno text (delete the `format!("cannot canonicalize {input:?}: {e}")` interpolation at lib.rs:114); a --verbose-path-errors flag restores detail inside allowed roots only. Add a `get_server_config` tool returning the effective roots and caps so a legitimate agent never needs to guess a path. ROB-01: rf-chain/src/lib.rs:227,233 interpolate the PE import DLL name (tainted at rf-core/src/pe.rs:117, carried through windows.rs:282) straight into the generated Python after a `#`. Add `fn py_comment(&str) -> String` stripping everything outside [ -~], truncating to 64 chars, refusing newlines, and route every binary-sourced string through it. INTERIM MITIGATION (does not close MCP-03, which needs the v0.2 engine token): clamp `depth` at the request boundary (rf-mcp/src/lib.rs:472) to a hard --max-depth default 64, REJECTING larger values with a structured usage_error rather than silently clamping, and add a `tokio::sync::Semaphore` with --max-concurrent default 2. That bounds the measured 54.8 GB / 398% CPU runaway from 1 hour.

*Closes:* `MCP-01`, `MCP-02`, `MCP-07`, `ROB-01`

#### Retract every claim the code does not support *(days)*

This is a real fix, not a cop-out: for an unsubstantiated-claim finding, making the sentence true by deleting it closes the finding as completely as building the feature would, and it costs hours. CLAIM-01/PERF-01/PERF-02: replace README.md:5-6 and :38's '>=10x faster' headline with the measured table from docs/measured-2026-09.md (x86/x64 5.7-6.2x, ARM64 2.1x, MIPS 1.7x, PPC 1.3x, --depth 10, stated hardware), and mark PLAN.md:226's Phase-1 perf exit criterion explicitly NOT MET. SCAN-08: README.md:392-409 quantifies divergence as '~0.05-0.2% of gadgets'; the measured figure is 15-29% of gadget TEXTS against 99.93% address-set parity — state both numbers and the distinction. CLAIM-05: delete the 1.0000 classifier-precision claim and label rf-classify 'heuristic, not independently evaluated', noting that crates/rf-classify/tests/eval.rs:32-34,125-285 is a transliteration of the classifier itself so the number is self-agreement. (The circular harness is REPLACED in v0.3 under CLS-01/CLS-11; here we only stop asserting its output.) MCP-08: rewrite README.md:336-346 and MANUAL.md:355-357 to describe what confine_path now actually does after this release's fixes, and add an explicit 'what this does NOT protect against' paragraph — the operator's own choice of root, anything readable inside a root, and the fact that the analyzed binary's bytes reach the agent. CLAIM-06: mark PLAN Phase 4b 'partial' — there is no emulator harness and no CET-marked PE fixture; those land in v0.5 and v0.2 respectively. CLAIM-09: remove the ARM64-PAC roadmap item from README.md:43 rather than leaving Phase 5 marked done with §5.8 entirely absent. CLAIM-10: emit the linked capstone version and the Cargo.lock hash from `--version`. CLAIM-11: correct 'all 25 test-suite binaries' to the real 24 and record in PROVENANCE.md that the ET_CORE fixture was dropped. CHWIN-09: delete the ntoskrnl.exe ring0 success-path demo at MANUAL.md:263-267 — it is not a workable chain — and, in the same edit, gate `--chain windows-virtualprotect` behind a loud stderr warning ('experimental: known not to execute correctly; see CHWIN-01/02/03 — fixed in v0.5'). CHLX-06: README.md:425-428's description of the ROPgadget register-regex bug is factually wrong and the claimed 'intended register set' is not what rf-chain/src/linux.rs:47-51 implements; correct both. CRIT-04: MANUAL.md:464 says the default output is sorted by address; engine.rs:273 sorts alphabetically by gadget text (identically to ROPgadget) — correct the manual, not the code. CLI-14: add to MANUAL.md a full ROPgadget flag-coverage table naming all 14 unimplemented flags explicitly, plus a 'known divergences' section. Also pull the --cfg-aware recommendation from MANUAL.md:267 until CRIT-01's code fix lands in v0.2 — the flag returns zero gadgets on every binary in the repository including the one the manual recommends it for.

*Closes:* `CLAIM-01`, `PERF-01`, `PERF-02`, `CLAIM-05`, `CLAIM-06`, `CLAIM-09`, `CLAIM-10`, `CLAIM-11`, `SCAN-08`, `MCP-08`, `CHLX-06`, `CHWIN-09`, `CRIT-04`, `CLI-14`

### Exit criteria

These are the gates. Each one is meant to be able to go red.

- `git ls-files rop-finder | grep -ix 'rop-finder/\(LICENSE\|NOTICE\)'` returns both files; tests/fixtures/PROVENANCE.md names an origin and license for all 24 fixtures; `git ls-files` shows no path under dist/ and no ROP-Finder.7z; Cargo.lock is tracked and `iced-x86` is pinned with an exact `=` requirement that `cargo metadata` resolves to a single version.
- `rop-finder --binary <any fixture> | head -5` exits 0 on ubuntu-22.04, macos-14 and windows-2022 in BOTH human and --json modes; `rop-finder --help` and `--version` exit 0 and --version prints the capstone version plus the ROPgadget attribution. Today all four of those commands exit non-zero (101 and 1 respectively) and the project's own build script is broken by it.
- The MCP server started with no --allow-dir exits 2. Started with `--allow-dir /tmp/ok` and cwd=/tmp/elsewhere, `get_binary_info` on /tmp/elsewhere/probe.bin returns path_denied — the existing test `mcp_rejects_traversal_and_disallowed_flags` passes today only because the harness's cwd happens not to contain the probe file, so it must be rewritten to set cwd deliberately.
- The rename-race harness (400 sequential find_gadgets against a path being swapped between a decoy hardlink and a symlink to a file outside the allowlist, server launched with cwd=/) yields ZERO reads of the outside file. The measured baseline today is 323/400.
- For four probe paths outside the allowlist — an existing file, an existing directory, an absent path, and an unreadable path — the four responses are byte-identical apart from the echoed input, and none contains the strings 'No such file', 'os error', 'canonicalize' or 'is not a regular file'. Today they return three distinct codes and one echoes errno 2.
- A PE fixture whose import DLL name contains `\nimport os\nos.system('id')` produces a chain script where `python3 -m py_compile` succeeds, `ast.parse` shows no top-level statement beyond the fixed header, and the injected text appears only inside a comment. Today the string is interpolated raw after a `#`.
- Every generated windows-virtualprotect script passes `python3 -m py_compile` (today every one is an IndentationError from the WordKind::Padding tab), and running the tool with `--chain windows-virtualprotect` prints the experimental warning to stderr.
- An MCP request with depth=100000 is REJECTED with a usage_error naming limit=max_depth and got=100000, and the server's RSS is unchanged; concurrent requests above --max-concurrent queue rather than multiply. Today depth is unbounded and the same request reaches 54.8 GB RSS.
- `grep -rn -e '10x' -e '1\.0000' -e 'ntoskrnl' -e '0\.05-0\.2%' -e 'all 25 test-suite' README.md MANUAL.md TAXONOMY.md ../PLAN.md` returns nothing, and every remaining numeric claim in those files either cites docs/measured-2026-09.md or is reproduced by a command printed in the same document.
- CI is green on ubuntu-22.04, macos-14, macos-13 and windows-2022 for fmt/clippy -D warnings/test/MSRV/cargo-deny; a tagged push produces checksummed artifacts, and on each platform a smoke job downloads its own artifact, asserts the binary is executable (`test -x` / mode & 0o111), and runs `--version`. The Linux artifact fails `test -x` today (mode 0666) and there is no macOS artifact at all.

<details><summary>All findings closed in this phase</summary>

| ID | Sev | Kind | Title |
|---|---|---|---|
| `CHLX-06` | low | unsubstantiated-claim | README's description of the ROPgadget register regex bug is factually wrong, and the claimed "intended register set" is not what the code implements |
| `CHWIN-09` | low | unsubstantiated-claim | The advertised ring0 success-path demo (ntoskrnl.exe) is not a workable chain |
| `CLAIM-01` | high | unsubstantiated-claim | Phase 1 performance exit criterion is not met, and the README's headline speed claim is false |
| `CLAIM-05` | medium | unsubstantiated-claim | The Phase 5 classification gate's 'independent' labeler is a re-implementation of the same rules, so the reported 1.0000 precision measures self-agreement, not accuracy |
| `CLAIM-06` | medium | unsubstantiated-claim | Phase 4b is marked done but two of its three exit criteria have no artifact: no emulator harness and no CET-marked PE |
| `CLAIM-09` | low | missing-feature | ARM64 PAC awareness (PLAN §5.8, a Phase 5 roadmap item) is entirely absent while Phase 5 is marked done |
| `CLAIM-10` | low | unsubstantiated-claim | `--version` does not record the capstone version, and Cargo.lock — the other half of the same mitigation — is gitignored |
| `CLAIM-11` | low | unsubstantiated-claim | Parity is claimed on 'all 25 test-suite binaries' but the corpus contains 24; the ET_CORE fixture was dropped |
| `CLI-06` | medium | correctness-bug | --help and --version exit with status 1 |
| `CLI-13` | low | correctness-bug | Missing --rawEndian is reported as 'Specify --rawArch' |
| `CLI-14` | low | unsubstantiated-claim | MANUAL.md presents a complete CLI reference with no statement of what ROPgadget functionality is absent |
| `CRIT-02` | medium | unsubstantiated-claim | Both primary output modes panic (exit 101) when piped to `head`; the MANUAL misattributes this to Windows, offers a Windows-only workaround, and its own UC3 example triggers it |
| `CRIT-04` | low | unsubstantiated-claim | MANUAL states the default output is sorted by address; it is sorted alphabetically by gadget text, identically to ROPgadget |
| `ENG-01` | high | missing-engineering | No CI configuration of any kind exists |
| `ENG-02` | high | missing-engineering | Cargo.lock is gitignored in a binary-producing workspace, while the parity-critical x86 formatter is left unpinned |
| `ENG-03` | high | missing-engineering | No LICENSE file anywhere in the Rust tree, and no legally adequate attribution to ROPgadget |
| `ENG-06` | medium | parity-divergence | `--version` and `--help` exit with status 1, breaking the project's own build script |
| `ENG-07` | medium | unsubstantiated-claim | Declared MSRV of 1.80 is false — the dependency graph requires rustc >= 1.88 — and is never tested |
| `ENG-09` | medium | missing-engineering | 41 MB of prebuilt binaries committed to git with no build recipe, no checksums, non-executable mode, and a leaked developer path |
| `ENG-11` | medium | missing-engineering | No dependency auditing tooling for a 141-package graph with 23 build scripts and 44 MB of vendored C |
| `ENG-12` | medium | missing-engineering | 24 fixtures are byte-identical redistributions of third-party proprietary and GPL binaries under a blanket BSD-2 declaration |
| `ENG-13` | medium | missing-engineering | The 1 GB ROP-Finder.7z is a raw snapshot of a dirty working tree, 95.6% cargo build artifacts |
| `MCP-01` | high | security | TOCTOU race between confine_path() and the file read defeats path confinement entirely (arbitrary file read) |
| `MCP-02` | high | security | The server process cwd is always in the allowlist and cannot be removed, so `--allow-dir` does not actually confine anything |
| `MCP-07` | medium | security | Error-code taxonomy is a whole-filesystem existence oracle outside the allowlist |
| `MCP-08` | medium | unsubstantiated-claim | README and MANUAL state three security guarantees the code does not provide |
| `PERF-01` | high | unsubstantiated-claim | Headline ">=10x faster on x86/x64" is not met: measured 6.0x |
| `PERF-02` | high | unsubstantiated-claim | Non-x86 arches reach 1.4-1.9x, not the ">=4x" Phase-1 exit criterion |
| `PERF-07` | medium | missing-engineering | 55% of x86-64 wall clock is 45,651 unbuffered println! syscalls |
| `ROB-01` | high | security | Untrusted PE import DLL name is written unescaped into the generated Python exploit script (code injection) |
| `ROB-03` | medium | correctness-bug | Panic (exit 101) on broken pipe - `rop-finder --binary x | head` always crashes |
| `ROB-05` | medium | correctness-bug | Every windows-virtualprotect chain script is invalid Python and cannot be run |
| `SCAN-08` | medium | unsubstantiated-claim | 15-29% of x86/x64 gadget texts differ from ROPgadget's; the README quantifies divergence as "~0.05-0.2% of gadgets" |

</details>

---

## Phase 2 — v0.2.0 — Results you can trust, and the engine reshaped once

**Effort:** 1-hour · **Findings closed:** 47

**Goal.** Every address rop-finder prints is really in the target on every format it claims to support; the 99.93% parity figure is enforced by a CI gate that can go red instead of asserted in a README; and the scan engine's shape (preceding bytes, table provenance, optional dedup, alignment stepping, a sink, a cancellation token) is changed exactly once so no later release rewrites the hot loop.

**Why here.** This is the release that earns the project its reason to exist, and it must precede the MCP release: an agent consuming rf-mcp cannot verify anything it is told, and CORE-01 alone means an unsupported e_machine ELF silently decodes as x86 and yields thousands of fabricated gadgets where ROPgadget refuses the file outright. Two ordering details inside the release are load-bearing. First, ANCH-05 (bundled capstone 5.0.0 -> 5.0.7, matching the oracle) and the v0.1.1 Cargo.lock/iced-x86 pin must both land BEFORE the parity baseline is frozen — both change gadget output, and a baseline taken first bakes the wrong oracle delta into every gate that follows. Second, the engine keystone: I verified in source that Gadget has no prev and no table field, ScanOptions has no all/align/call_preceded, post_process dedups unconditionally, scan_binary returns a materialized Vec, and the anchor loop has no cancellation point. --callPreceded, --all, --align, a correct --cfg-aware, bounded memory, MCP cancellation and the v1.0 perf work are all edits to those same declarations and that one loop. Landing them as one change costs one parity re-litigation instead of four. The features that the shape unlocks but that need a query layer (constraint search) still wait for v0.4; what lands here is the shape plus the four flags that are pure engine semantics.

### Workstreams

#### Toolchain first: bump capstone before any baseline is frozen *(hours)*

ANCH-05: the bundled capstone is 5.0.0 (Cargo.lock:133, capstone-sys 0.17.0) while the parity oracle runs 5.0.7, which costs real gadgets on ARM and ARM64. Bump to 5.0.7, re-run the full fixture sweep, and record the per-architecture gadget delta in docs/measured-2026-09.md. This is the FIRST commit of the release: everything downstream in this plan is measured against a baseline, and freezing that baseline against a stale capstone would calibrate every later gate to the wrong oracle. It pairs with v0.1.1's Cargo.lock commit and exact iced-x86 pin, which do the same job for the x86 formatter.

*Closes:* `ANCH-05`

#### Loader truth: refuse rather than fabricate 

CORE-01: rf-core/src/elf.rs:221 uses `unwrap_or(Arch::X86)` for an unrecognized e_machine, producing a complete confident fabricated gadget listing. Make `Image::arch` fallible, return `Error::UnsupportedArch` naming the machine type, and surface it at rf-cli/src/lib.rs:378. CORE-02: rf-core/src/macho.rs:143 takes min vmaddr over all LC_SEGMENT commands, which is __PAGEZERO and therefore always 0 — derive image_base from the first non-__PAGEZERO segment with a nonzero vmaddr, so `--base` and `--info` stop reporting 0x0. CORE-03/CORE-05: add `--arch <slice>` selection for fat Mach-O (rf-cli/src/lib.rs:412) and REFUSE rather than guess when a multi-slice file arrives without it (today a modern x86_64+arm64 binary yields ~70% fabricated gadgets); add FAT_MAGIC_64 / cafebabf support at rf-core/src/universal.rs:35. CORE-04: use p_memsz / SizeOfRawData for Section.size at elf.rs:104 (bytes still clamped to file content) so --range trimming matches the oracle. CORE-06: unify the two PT_LOAD#n enumerations at elf.rs:282 and make --section scan the same extent the default scan does (p_filesz vs p_memsz today). CORE-07: detect ELFCLASS32 + EM_X86_64 (x32 ABI) at elf.rs:193 and either match the oracle's decode mode or warn explicitly; document whichever is chosen. ANCH-06: rf-core/src/pe.rs:75 detects Thumb-only ARMv7 PEs and still scans them with A32 tables unless --thumb is passed — route them to the Thumb anchor tables automatically. ANCH-04: rf-scan/src/cs.rs:85 opens 32-bit RISC-V in RV64 mode, producing instruction text that does not exist on RV32 — select the RV32 capstone mode for ELFCLASS32 RISC-V. ANCH-03: populate the empty ARM64 and SPARC SYS anchor tables at rf-scan/src/anchors.rs:312 and :381 so SYS search stops returning nothing on AArch64. NOTE: those tables are empty because ROPgadget's own tables are empty there, so populating them is an INTENTIONAL divergence from the oracle — record it in the parity harness's known-divergence list rather than letting it fail the gate, and state it in MANUAL.md's divergences section.

*Closes:* `CORE-01`, `CORE-02`, `CORE-03`, `CORE-04`, `CORE-05`, `CORE-06`, `CORE-07`, `ANCH-06`, `ANCH-04`, `ANCH-03`

#### The engine keystone: one shape change, ten findings 

This is the grafted workstream and it must land as ONE change, not ten tickets. (a) rf-scan/src/engine.rs:100-113 — add `prev: Vec<u8>` (bytes preceding the gadget start, capped at 7, captured during the backward walk) and `table: TableKind` (Rop/Jop/Sys) to `Gadget`. (b) engine.rs:36-78 — add `all: bool`, `align: Option<u64>`, `call_preceded: bool`, `filter_re: Option<Regex>` and `cancel: CancelToken` to `ScanOptions`; add crates/rf-scan/src/cancel.rs with `CancelToken(Arc<AtomicBool>)`, `Error::Cancelled` and `Error::Budget`. (c) engine.rs:206-247 — convert `scan_binary` from returning a materialized `Vec<Gadget>` to driving a sink trait, with a Vec collector and a bounded streaming collector as the two implementations, and make post_process's dedup conditional on `!opts.all`. Update the three consumers (rf-cli, rf-mcp, rf-chain) to the sink API in the same change. (d) Cancellation and budget check points, all inside existing loops: `run` closure at engine.rs:225-230 returns empty when cancelled (so residual cost after cancellation is bounded by the number of work items, not their contents); `for ref_pos in anchors::find_matches(...)` at engine.rs:359 checks every 1024 iterations; `for i in 0..opts.depth` at engine.rs:365 checks every 256 and also tests `out.len()` against a new `opts.max_gadgets`; identical treatment at cs.rs:282 and cs.rs:288 for the capstone architectures; post_process checks on entry and before the sort. Keep the old `scan_binary` as a delegate with `CancelToken::never()` so the 153 existing tests and the CLI are untouched. WHAT THIS UNLOCKS, closed here: SCAN-07/CLI-03 (`--all` disables dedup — worth ~13x the usable gadgets in the bad-byte workflow, 649 pop/ret gadgets today against ROPgadget's 8,461); CLI-04/ECO-03 (`--callPreceded`, which needs `prev` and is impossible without it); ANCH-01/SCAN-05/CLI-10 (`--align` as real scan-time stepping in x86_scan_anchor at engine.rs:369 AND cs.rs:277 — the candidate-start loop must stride by align and skip misaligned starts, mirroring the structure cs.rs:282-310 already has); ANCH-02 (delete the MCP address post-filter at rf-mcp/src/lib.rs:677-683, which under-reports by ~53% and parses `--align 16` as hex 0x16 = 22, and point the MCP tool at the real engine option — parse decimal first, hex only with an explicit 0x); CRIT-01 (`--cfg-aware` at engine.rs:269-289 returns zero gadgets on every binary in the repository including the ntoskrnl.exe the MANUAL recommends, because it tests every gadget's first four bytes with no idea which table produced it — with `table: TableKind` it can apply endbr-entry filtering to indirect-branch targets and model shadow-stack semantics for ROP separately, stop conflating PE GUARD_CF with Intel CET/IBT, and actually fire the promised scan-time warning); PERF-05 (the streaming sink plus `--max-memory` and `--max-gadgets`, taking RSS on the 9.3 MB fixture off its current ~117 bytes per code byte / 1.08 GB). Because align changes what is scanned, it MUST also join the cache param hash (see the cache workstream) or an unaligned cached result will be served for an aligned query.

*Closes:* `SCAN-07`, `CLI-03`, `CLI-04`, `ECO-03`, `ANCH-01`, `ANCH-02`, `SCAN-05`, `CLI-10`, `PERF-05`, `CRIT-01`

#### Filter semantics and formatter fidelity

SCAN-01/CLI-02: rf-scan/src/x86.rs:317-319 and the identical code at cs.rs:248-251 implement --filter as a literal `ends_with` suffix match, which is neither of ROPgadget's semantics — it ignores regexes (`--filter "j.*"` returns the complete unfiltered 15,609 gadgets instead of 3,967) and deletes 612 gadgets ROPgadget keeps for `--filter "op"`. Move `regex` to a workspace dependency and implement ROPgadget's anchored `({})$` regex over the full mnemonic. SCAN-02: capstone_normalize at x86.rs:201-208 strips the `notrack` prefix, so every `notrack jmp`/`notrack call` collides in dedup with an ordinary jmp and is lost — precisely on the CET binaries where it is the highest-value JOP primitive. Give them distinct dedup keys. SCAN-03: format_gadget at x86.rs:159-183 renders `f3 c3` as `rep ret`; render it as `repz ret` so the canonical AMD return gadget is findable via --only and by name, and narrow the over-broad branchy exclusion at :221-247 that also creates spurious `rep jmp` dedup classes. SCAN-04: x86.rs:209-220 and default_segment at :253-267 strip segment overrides from memory operands; stop, and delete the comment asserting a capstone behaviour that does not exist. SCAN-06: align far-branch (ljmp/lcall) accept/reject with the oracle at x86.rs:95-96 and 101-109 — today far branches are accepted as jmp/call that ROPgadget rejects, and mid-gadget lcall is rejected that ROPgadget accepts. SCAN-09: decode_window at x86.rs:116-154 stops at `Code::INVALID` for the `mov cs, r/m16` encoding that iced-x86 rejects and capstone accepts; recover it. SCAN-10: re-apply --range to the final --offset-shifted addresses in post_process (engine.rs:242-276), as the oracle does at apply_range/:292-321. CLI-11: reconcile operand formatting, segment prefixes and ordering at rf-cli/src/lib.rs:1326-1333 with ROPgadget's, adding a `--compat` mode if a divergence is deliberate. This whole workstream is the 15-29% text divergence, and the parity harness built below is its work queue.

*Closes:* `SCAN-01`, `CLI-02`, `SCAN-02`, `SCAN-03`, `SCAN-04`, `SCAN-06`, `SCAN-09`, `SCAN-10`, `CLI-11`

#### The cache cannot lie: one module rewrite, seven findings 

CLI-01/ENG-05 are literally the same bug: cache_key at rf-cli/src/lib.rs:1428-1462 omits --rawArch/--rawMode/--rawEndian, so a cached scan is served for the wrong architecture. Add every output-affecting flag to the key INCLUDING the new `align` and `all`, plus a key-schema VERSION byte so that when the key format changes again old entries MISS rather than mismatch. CLI-07/MCP-04: entries are trusted verbatim, deterministically named, mode 0644 — I reproduced serving a fabricated `pop rdi ; ret @ 0xdeadbeefcafe0000` alongside the genuine binary_sha256 through the MCP server. Add an HMAC-SHA256 tag over `key || 0x00 || body`, keyed by 32 random bytes at `<cache_dir>/.cachekey` created `create_new` mode 0600; a mismatch is a MISS plus a stderr warning plus a counter, never an error and never a served result; if the key file is absent, wrong-length or group/world-readable, disable the on-disk cache entirely rather than falling back to unauthenticated reads. Create the cache dir 0700 and entries 0600, refuse a pre-existing dir owned by another uid, and write with `NamedTempFile::new_in(dir).persist(path)` so a reader never sees a half-written entry. ROB-04: the panic is `&c.bytes[i..i+2]` — a &str byte-range slice — at rf-cli/src/lib.rs:1483 and identically rf-mcp/src/lib.rs:277; I reproduced `byte index 2 is not a char boundary; it is inside '€'`. Replace with a checked hex decoder over `as_bytes()` that validates even length, an ASCII-hexdigit-only alphabet and a length cap, and add a `CachedScan::validate()` called on every deserialize (vaddr parses as hex u64, text <= 64 KiB with no control characters, quality in 0..=100, class in the known set). Add `#![deny(clippy::indexing_slicing, clippy::string_slice)]` to both crates so this bug class cannot return, and replace every `.lock().unwrap()` with `.unwrap_or_else(PoisonError::into_inner)`. CLI-08/PERF-12: the CLI cache grows 5.3 MB per scan configuration in the user's home forever — add a byte-weighted LRU with a size cap, a TTL, and a `--cache-purge` subcommand. Share one cache module between rf-cli and rf-mcp: the align post-filter and the char-boundary panic each existed twice precisely because this code is duplicated.

*Closes:* `CLI-01`, `ENG-05`, `CLI-07`, `ROB-04`, `CLI-08`, `PERF-12`, `MCP-04`

#### Hostile input: bounds, then fuzzing to prove them 

ROB-02: rf-core/src/pe.rs:85 makes one owned byte copy per DECLARED section header, so a 382 KB PE with ~2000 cloned section headers drives 19.8 GB RSS — a 54,000x amplification. Validate SizeOfRawData/p_filesz against the actual file length before reserving, de-overlap duplicate section entries, and cap total scanned region bytes; the streaming sink from the keystone workstream bounds the second half of the amplification (all gadgets from all regions materialized before dedup). ROB-06: the `std::fs::read` in rf-cli has no cap, so `--binary /dev/zero` allocates until the OS kills it — stat first, refuse non-regular files, and add `--max-file-size` (default 512 MB). ROB-08/CLAIM-03/ENG-10: create fuzz/ with cargo-fuzz targets for `rf_core::Binary::load` on ELF, PE, Mach-O and Universal, plus `rf_cli::info_bytes` and `rf_cli::scan_bytes` at bounded depth, seeded from tests/fixtures. Run 60 s per target in PR CI and a long run nightly. This is the artifact PLAN's 'zero panics on 10K mutated binaries' criterion was asserted without.

*Closes:* `ROB-02`, `ROB-06`, `ROB-08`, `CLAIM-03`, `ENG-10`

#### Gates that can go red 

ENG-04: tests/parity.py:37 hardcodes a sibling oracle directory, cannot run from a clone, and `main()` has no non-zero exit path at all — the project's central claim is untested by construction. Rewrite it to resolve the oracle by repo-relative path (or a pinned submodule) with a documented one-command venv setup at capstone 5.0.7, build the binary if absent, record a committed per-fixture baseline of (vaddr, bytes) sets and text-diff classes, and exit non-zero on any regression below that baseline. CLAIM-08: tests/benchmark.py:13 and tests/analyze_diff.py:78 hardcode `rop-finder.exe` and are unrunnable on macOS/Linux — resolve the binary name by platform. CLAIM-04: wire parity.py, chain_parity.py, the fuzz targets and the benchmark regression band in as REQUIRED CI jobs so PLAN §9's 'continuous' gates are continuous. CLAIM-02/PERF-08: benches/ is an empty directory with no criterion dependency; add criterion benches covering per-architecture scan throughput, dedup and output, commit a baseline JSON, and fail CI on a >10% regression — this is the instrument v1.0 is judged by, and building it now is what lets v1.0's performance claims be resolved by measurement instead of rhetoric. Add the doc-claims test here too (grafted): a CI test that extracts every quantitative claim from README/MANUAL/PLAN (speedup, parity percentage, fixture count, flag coverage) and asserts it against live measurement, so the v0.1.1 retractions cannot silently drift back.

*Closes:* `ENG-04`, `CLAIM-04`, `CLAIM-08`, `CLAIM-02`, `PERF-08`

### Exit criteria

These are the gates. Each one is meant to be able to go red.

- ABSOLUTE oracle-matched counts, not a ratchet. On elf-Linux-x86 at the oracle's default flags: `--filter "j.*"` returns exactly 3,967 gadgets; `--filter "op"` returns the same SET ROPgadget returns; `--align 4` returns 8,547 and `--align 8` returns 4,392; `--all` yields 8,461 pop/ret candidates under a null-byte constraint (today 649); `--callPreceded` narrows 15,587 to 3,966. Each is an exact number from the oracle — 'no worse than today' would let half this release's scanner work pass, which is why it is not the criterion.
- Bit-exact fixtures rise from 11/24 to at least 20/24, and gadget-TEXT divergence against ROPgadget on x86/x64 drops below 1% of gadgets (measured 15-29% today). README states the measured number and the doc-claims CI test asserts it.
- MUTATION TEST OF THE GATE ITSELF: deliberately reverting any one of CORE-01, CLI-01, SCAN-02, SCAN-03 and CRIT-01 turns CI red, verified as five recorded revert-and-run experiments checked into docs/gate-mutation.md. This tests the gate rather than the fix; today's suite has 153 tests and would notice none of those five.
- tests/parity.py runs from a fresh clone with one documented command, exits non-zero when a fixture's gadget set regresses past its recorded tolerance, and its known-divergence list explicitly names the intentional ARM64/SPARC SYS-table divergence so that divergence cannot be used to hide an accidental one.
- An ELF with e_machine=0x9999 exits non-zero naming the machine type and prints ZERO gadgets. `--info` on a Mach-O x86_64 executable reports image_base 0x100000000, and `--base 0` shifts every printed address by that amount. A fat Mach-O without `--arch` is refused, not guessed.
- `--cfg-aware` on ntoskrnl.exe returns a non-zero, hand-verified gadget count (today: 0 on every binary in the repository, with exit 0 and no warning); on a binary where the flag is inapplicable it prints the promised warning instead of a silent zero. A CET-marked PE fixture is added to the corpus and to CI.
- `repz ret` appears verbatim in output and is findable with `--only`; notrack-prefixed indirect branches appear on the CET fixture with a count matching the oracle; SYS search on the AArch64 fixture returns a non-empty result.
- A scan cached under `--rawArch x86` is a cache MISS under `--rawArch arm`, and both uncached runs are reproduced byte for byte. Flipping one byte of a cache file on disk produces a miss plus a stderr warning and a tamper counter, never a served result and never a panic. The full malformed-entry matrix (non-ASCII bytes, odd-length hex, 1 MB text, vaddr 'not-hex', quality 99999, truncated file) produces clean misses with no 'panicked' anywhere in stderr — today the '€€' case panics at rf-cli/src/lib.rs:1483 and rf-mcp/src/lib.rs:277.
- 24 hours of cargo-fuzz across all six loader targets: zero panics, zero OOMs, zero timeouts. The 382 KB cloned-section PE peaks under 512 MB RSS (today 19.8 GB); `--binary /dev/zero` errors within one second. Crashers and corpus are committed.
- Peak RSS on the 9.3 MB fixture drops from 1.08 GB to under 200 MB in streaming mode with a byte-identical gadget set, and `--max-memory` bounds a 100 MB input to a completed run with complete output.
- `cargo bench` reports per-architecture throughput against a committed baseline and a deliberate 20% slowdown fails CI; the doc-claims test fails if any number in README/MANUAL/PLAN is edited to something measurement does not support.

<details><summary>All findings closed in this phase</summary>

| ID | Sev | Kind | Title |
|---|---|---|---|
| `ANCH-01` | high | missing-feature | ROPgadget's --align is not implemented at all in the CLI, and the x86 engine has no alignment stepping to implement it with |
| `ANCH-02` | high | parity-divergence | MCP server advertises --align but implements it as an address post-filter, silently under-reporting by ~53% |
| `ANCH-03` | medium | missing-feature | ARM64 and SPARC SYS anchor tables are empty, so SYS gadget search returns nothing on AArch64 |
| `ANCH-04` | medium | design-limitation | RISC-V 32-bit binaries are disassembled in RV64 mode, producing instruction text that does not exist on RV32 |
| `ANCH-05` | low | parity-divergence | Bundled capstone is 5.0.0 while the parity oracle uses 5.0.7, costing real gadgets on ARM and ARM64 |
| `ANCH-06` | low | missing-feature | Windows ARMv7 PEs are detected as Thumb-only but still scanned with the A32 anchor tables unless --thumb is passed |
| `CLAIM-02` | medium | missing-engineering | No benchmark suite exists at all — `benches/` is an empty directory and there is no criterion dependency |
| `CLAIM-03` | medium | missing-engineering | No fuzzing infrastructure exists; the Phase 1 'zero panics on 10K mutated binaries' criterion has no artifact |
| `CLAIM-04` | medium | missing-engineering | There is no CI of any kind, so every gate PLAN §9 defines as continuous is manual |
| `CLAIM-08` | medium | missing-engineering | Three of five shipped verification/benchmark harnesses are hardcoded to `rop-finder.exe`; two are unrunnable on macOS/Linux with no fallback |
| `CLI-01` | high | correctness-bug | --cache key omits --rawArch/--rawMode/--rawEndian: a cached scan is served for the wrong architecture |
| `CLI-02` | high | parity-divergence | --filter is a literal suffix match, not ROPgadget's anchored regex — it both under- and over-filters |
| `CLI-03` | high | missing-feature | --all is not implemented: no way to disable duplicate removal, costing ~13x the usable gadgets in the bad-byte workflow |
| `CLI-04` | high | missing-feature | --callPreceded is not implemented, and the engine cannot support it (no preceding-bytes capture) |
| `CLI-07` | medium | security | A tampered --cache entry is trusted verbatim: arbitrary attacker-chosen gadget addresses and text are printed |
| `CLI-08` | medium | missing-engineering | --cache has no eviction, size cap, or TTL — unbounded disk growth in the user's home directory |
| `CLI-10` | medium | missing-feature | --align missing from the CLI; the MCP's version is a non-equivalent post-filter and parses its argument as hex |
| `CLI-11` | medium | parity-divergence | Human-readable output is not byte-for-byte compatible with ROPgadget — operand formatting, segment prefixes and ordering all differ |
| `CORE-01` | high | correctness-bug | Unsupported ELF e_machine silently falls back to x86 and emits thousands of fabricated gadgets |
| `CORE-02` | high | correctness-bug | Mach-O image_base is __PAGEZERO (always 0), so --base is broken and --info misreports the load address |
| `CORE-03` | medium | missing-feature | Fat Mach-O: no way to select an architecture slice; modern x86_64+arm64 binaries yield ~70% fabricated gadgets |
| `CORE-04` | medium | parity-divergence | Section.size is clamped to file bytes instead of p_memsz/SizeOfRawData, changing --range trimming vs the oracle |
| `CORE-05` | low | missing-feature | 64-bit fat Mach-O (FAT_MAGIC_64 / cafebabf) is detected but cannot be loaded |
| `CORE-06` | low | design-limitation | Stripped ELF: PT_LOAD#n names are numbered from two different enumerations, and --section scans p_filesz where the default scan uses p_memsz |
| `CORE-07` | low | parity-divergence | x32-ABI ELFs (ELFCLASS32 + EM_X86_64) are decoded in a different mode than the oracle, undocumented |
| `CRIT-01` | high | unsubstantiated-claim | `--cfg-aware` returns zero gadgets on every binary in the repository, including ntoskrnl.exe where the MANUAL specifically recommends it; GUARD_CF is conflated with Intel CET/IBT and the promised scan-time warning never fires |
| `ECO-03` | high | missing-feature | No `--callPreceded` filter — the standard mitigation-aware gadget filter is missing |
| `ENG-04` | high | missing-engineering | Parity — the project's central claim — is measured by a script that cannot run from a clone and never fails |
| `ENG-05` | high | correctness-bug | `--cache` returns wrong results for `--rawArch`/`--rawMode` because the cache key omits them |
| `ENG-10` | medium | missing-engineering | No property-based testing, fuzzing, or corpus anywhere, in a tool whose entire job is parsing hostile binaries |
| `MCP-04` | medium | security | On-disk cache entries are trusted verbatim — no integrity check, deterministic filenames, 0644 — so results can be silently poisoned |
| `PERF-05` | high | missing-feature | No streaming or bounded-memory mode: RSS is ~117 bytes per byte of scanned code (1.08 GB on a 9.3 MB input) |
| `PERF-08` | medium | missing-engineering | No criterion benchmarks exist; the only benchmark harness is Windows-only and crashes here |
| `PERF-12` | low | missing-engineering | --cache grows without bound: 5.3 MB per scan configuration, no eviction and no purge |
| `ROB-02` | high | design-limitation | Memory-exhaustion DoS: a 382 KB malformed PE drives 19.8 GB RSS with no special flags |
| `ROB-04` | medium | correctness-bug | Panic on a corrupt/poisoned scan cache file - non-ASCII in the `bytes` field slices a UTF-8 char in half |
| `ROB-06` | medium | design-limitation | Input file is read entirely into memory with no size cap - `--binary /dev/zero` allocates until the OS kills it |
| `ROB-08` | medium | missing-engineering | The fuzzing infrastructure the plan committed to does not exist - and neither does any CI |
| `SCAN-01` | high | parity-divergence | --filter implements neither of ROPgadget's semantics: no regex support, and suffix matching rejects gadgets ROPgadget keeps |
| `SCAN-02` | high | correctness-bug | Every `notrack jmp` / `notrack call` gadget is silently lost to a dedup collision |
| `SCAN-03` | high | parity-divergence | `repz ret` is rendered as `rep ret`, so the canonical AMD return gadget is unfindable by name |
| `SCAN-04` | medium | correctness-bug | Segment overrides on memory operands are wrongly stripped; the code comment asserts a capstone behavior that does not exist |
| `SCAN-05` | medium | missing-feature | --align is not implemented in the engine; the MCP server's post-filter is not equivalent and loses ~half the gadgets |
| `SCAN-06` | medium | parity-divergence | Far branches (ljmp/lcall) are accepted as "jmp"/"call" that ROPgadget rejects, and mid-gadget lcall is rejected that ROPgadget accepts |
| `SCAN-07` | medium | missing-feature | --all (disable dedup) and --callPreceded are absent from the engine, with no `prev` bytes captured |
| `SCAN-09` | low | parity-divergence | `mov cs, r/m16` gadgets are lost (iced-x86 rejects the encoding capstone accepts) |
| `SCAN-10` | low | parity-divergence | --range is applied only once; ROPgadget also re-filters the final, --offset-shifted addresses |

</details>

---

## Phase 3 — v0.3.0 — The workable MCP server: bounded, cancellable, ranked, auditable

**Effort:** 1-hour · **Findings closed:** 21

**Goal.** An operator can hand this MCP server to an agent host: no call can pin a core or outlive its own timeout, results come back RANKED and paginated so a twenty-gadget answer beats a thousand-gadget dump, every response validates against a declared outputSchema, and every call including every refusal is in an audit log.

**Why here.** This is the release the user asked for by name, and it sits third because 'workable' has a prerequisite chain: safe (v0.1.1), correct (v0.2), then useful. 'Workable' is scoped here to exactly four properties and no more, because those four are what separate a demo from something you leave running. The non-obvious dependency is ranking: the server currently returns the first N gadgets in traversal order (which post_process has already sorted alphabetically), so `find_gadgets` with max_results=3 on elf-Linux-x64 returns `adc al, 0x89 ; retf 0xc281` out of 2789; and `sort_by: "quality"` does not save it, because CLS-07's finding is that 92% of gadgets tie at quality 100 and its top 8 are `ret`, `add esp, 0x8 ; ret`, `retf 0x2bbc`... with `pop rdi ; ret` nowhere near. So the classifier work IS the ranking work, not a side quest, and that is why all thirteen CLS findings live in the MCP release. The other half is cancellation: `tokio::time::timeout` around `spawn_blocking` (rf-mcp/src/lib.rs:705) abandons the await and never the closure, so a client that has already received a tidy timeout error leaves the server at 398-400% CPU indefinitely — measured. That fix is only possible now because v0.2 threaded the CancelToken through the scan loops. v0.1.1's depth clamp and semaphore have bounded the blast radius in the meantime.

### Workstreams

#### Cancellation that actually cancels, and uniform caps 

MCP-03/PERF-06: replace the three ad-hoc timeout blocks (rf-mcp/src/lib.rs:705, :775, and the inline get_binary_info at :901) with one `run_guarded` helper: acquire a `tokio::sync::Semaphore` permit; create a `CancelToken` (the v0.2 type); bridge rmcp's `RequestContext::ct` to it in a spawned task so `notifications/cancelled` — which the server accepts and ignores today — actually stops the work; `tokio::select!` between the spawn_blocking join handle and a sleep; on timeout, set the token and then JOIN the handle rather than abandoning it, so the permit is released only after the worker has really stopped (this is the load-bearing detail: awaiting the join is what makes the semaphore a bound on concurrent WORK rather than on outstanding awaits); if the join does not complete in 5 s, increment a `wedged` counter and return a distinct hard-timeout error. Also run every scan inside an explicit `rayon::ThreadPool` sized by `--scan-threads` (default num_cpus-1) so the server cannot consume every core. MCP-06: get_binary_info at lib.rs:901-919 is the one tool with neither a timeout nor a cap and it does its whole-file read plus goblin parse INLINE on the async runtime — move it onto run_guarded, add `timeout_secs` to InfoQuery (lib.rs:341-347), and cap max_sections/max_imports at 4096 each with a `warnings: [{code: "imports_truncated"}]` entry so a hostile PE with a million imports cannot produce a gigabyte of JSON. The file-size cap is enforced by fstat on the confined HANDLE from v0.1.1's open_confined, before any read.

*Closes:* `MCP-03`, `PERF-06`, `MCP-06`

#### Bounded caches on the server side *(days)*

MCP-05/ROB-07: `Cache { mem: Mutex<HashMap<String, Arc<CachedScan>>> }` at rf-mcp/src/lib.rs:164-219 has only get and put — no capacity, no TTL, no eviction. Measured: twelve depth-varying scans of one 900 KB binary walk RSS from 5 MB to 84 MB monotonically with `max_results: 1` on every call (so the response cap does not bound retention), and one depth-40 scan pins 2.57 GB permanently. Replace with a byte-weighted LRU carrying `--cache-mem-mb` (default 512), a per-entry `heap_bytes()` cost, `created_unix`, and a `--cache-ttl-secs` (default 86400); evict on insert until under budget. The on-disk half shares the v0.2 integrity-tagged cache module, so the HMAC, 0600/0700 permissions, atomic persist and disk size cap come for free.

*Closes:* `MCP-05`, `ROB-07`

#### The classifier is the ranking function — fix it before ranking on it 

ECO-05 is the root cause of three findings and one line: `cs::open` at rf-scan/src/cs.rs:102-108 constructs Capstone without `set_detail(true)`, so regs_read/regs_written are empty on 8 of 10 architectures and `classify()` falls through to `classify_heuristic`, which string-splits mnemonics. Enable detail mode and carry per-instruction regs_access, groups and memory-operand metadata through the scan records. CLS-04: with real metadata, replace the `operands.contains('[')` memory test at rf-classify/src/lib.rs:126-154 with per-architecture operand handling covering `off(reg)` syntax and the real load/store mnemonics (lwz/stw, ld/sd/c.ld, ldp/stp) so R3/R4/R5 fire on MIPS, PowerPC and RISC-V, where today the taxonomy collapses to one class with 0 mem-read, 0 mem-write and 0 stack-pivot across an entire binary. CLS-05: lib.rs:218-224 takes the first comma-separated operand token verbatim, yielding register names `{r4` and `#0x12e44` — strip `{`/`}`/`!`/`^`, expand `{r4-r7}` ranges, reject tokens starting with `#` or `[`, and add the conditional-branch mnemonics (b<cond>, cbz/cbnz, tbz/tbnz) to the control blocklist at lib.rs:192-215. CLS-02: `popfq ; ret` is labeled stack-pivot because R4/R5 (x86.rs:56-72, :170-174) treat any implicit-sp instruction as a pivot — add Popfq/Popfd/Popf/Pushfq/Pushfd to has_implicit_sp and require an rsp-TARGETING write. CLS-03: R8 at x86.rs:212-244 fires on 865 gadgets of which 6 qualify (99.3% false positive) and misses the COP form entirely — redefine it around a register-relative indirect branch with a self-advancing index register, and stop excluding the 1,224 `call [reg]` endings. CLS-12: widen R6's arithmetic set (x86.rs:13-39) to division, xadd, bit-test and byte-swap, and drop flags-only compares. CLS-13: classify `push rax ; ret` rather than `other`, and treat `ret 0x10` as a stack adjustment consistently with `add rsp, 0x10 ; ret` (x86.rs:149-160, :264-273). CLS-07: the quality score at lib.rs:83-88 gives 100 to every <=2-instruction single-side-effect gadget, which is 92% of them — replace it with a rank key `(usability_tier, quality, -n_insns, -side_effects, vaddr)` where a new `rf_classify::usability()` returns 3 for a bare `ret`/`jr $ra`/`bx lr` terminator WITH a stack-sourced register load and <=2 side effects, 2 for a bare terminator, 1 for `ret imm16`/`retf`/`iret`/far transfer or class `other`, and 0 for privileged/undefined instructions or pure control flow. That single tier is what moves `pop rdi ; ret` above `retf 0xce39`; the R12 quality score alone provably cannot.

*Closes:* `ECO-05`, `CLS-02`, `CLS-03`, `CLS-04`, `CLS-05`, `CLS-07`, `CLS-12`, `CLS-13`

#### Break the circular evaluation before trusting any of it 

CLS-01/CLS-11: crates/rf-classify/tests/eval.rs:32-34,125-285 contains an 'independent' labeler that is a transliteration of the classifier's own rules, and the 'committed labeled set' at :473,485-489 is REGENERATED by the test that consumes it — so the reported 1.0000 precision is self-agreement and the hand-verification claim has no artifact. Delete the transliterated labeler. Commit a hand-labeled JSONL corpus with a written provenance note (who labeled, when, against what reference), loaded read-only by the test, with a test that FAILS if the corpus file's hash changes during a run. CLS-06: eval.rs:355-371 scores only the label set; score the primary `class` field, which is what users and agents actually see and what is currently never measured at all. CLS-10: eval.rs:126,343-347 covers x86-64 only — stratify the corpus across x86-32 and at least three of the seven previously-unmeasured architectures. Publish real per-class precision and recall. (v0.1.1 already deleted the 1.0000 claim from the docs; this is where the number is replaced by a true one.)

*Closes:* `CLS-01`, `CLS-06`, `CLS-10`, `CLS-11`

#### An agent-usable surface: schema, rank, cursor, stable ids, semantic filters 

CLS-08: extend rf-mcp's CachedGadget (lib.rs:137-158) with labels, regs_written, regs_read, side_effects, low_confidence and terminator — the classification already runs once at scan time (lib.rs:634) and is thrown away except for quality/class, so keeping it is free and it also removes the on-demand reclassification path where the char-boundary panic lived. Add class/label/writes_reg filters to every gadget-returning MCP tool and the matching `--class`/`--label`/`--writes-reg` flags to the CLI. CRIT-03: define the response types as real Rust structs deriving `schemars::JsonSchema` and attach them so every entry in tools/list carries an `outputSchema` (today NONE do); REMOVE every `#[serde(skip_serializing_if)]` from the gadget record so the shape is invariant — `section` currently appears only with the section parameter, `arch` only for universal binaries; EMIT `delay_slot`, which rf_scan computes at engine.rs:139-142 and which every output boundary silently drops, so MIPS gadgets reach the agent with no indication that the last instruction executes before the branch; add `vaddr_u64` alongside the zero-padded string; close the ErrorCode set into a documented enum and collapse the two spellings (`usage` at lib.rs:588 vs `usage_error` elsewhere). Regenerate MANUAL.md:398-415's schema section FROM the generated schema in a test so it cannot drift. Then make the results usable: default `order` becomes `rank` (the usability_tier key above) with `address`/`quality`/`text` also selectable and the applied order echoed in the response; add `cursor`/`next_cursor` (base64url of {v, cache_key, order, offset, params_hash}, rejecting a cursor whose params_hash does not match with a retryable `cursor_expired`, and pinning cursored cache entries against eviction) so the MIPS fixture's 40,872 JOP gadgets are walkable; add stable `id = "g_" + base32(blake3(binary_sha256 || vaddr_le || bytes)[..10])` plus a `get_gadgets(binary_path, ids)` tool, so an agent can say 'build a chain from g_ab12, g_cd34' and so build_rop_chain can name the gadgets it selected. Also add MCP resources: any scan whose total_count exceeds `returned` also returns `ropfinder://scan/<cache_key>/gadgets.ndjson`, and with `--workspace-dir` (which must lie outside every allow root) the same NDJSON is materialized as a real file an agent can grep with its own tools. CHWIN-03: `get_binary_info` on the shipped pe-x64-cmd fixture reports msvcrt!memset at iat_vaddr 0x4ad2af40; hand-parsing the PE shows that is the IMAGE_IMPORT_BY_NAME record and the real IAT slot is 0x4ad29000 (image_base 0x4ad00000, IAT_rva 0x29000) — the 10/10/10/20-byte spacings are hint+name lengths, not pointer slots. Root cause: rf-core/src/pe.rs:119-120 uses goblin's `imp.rva` (HintNameTableRVA) where `imp.offset` (import_address_table_rva + i*size_of) is the FirstThunk slot. Change to `imp.offset`, rename thunk_rva/thunk_vaddr to iat_slot_rva/iat_slot_vaddr, ADD hint_name_rva/hint_name_vaddr (genuinely useful for locating the name string), and update the doc comment at pe.rs:41 which already describes the correct behaviour the code does not implement. Every import address handed to an agent is wrong today; the chain that consumes it is fixed in v0.5.

*Closes:* `CLS-08`, `CRIT-03`, `CHWIN-03`

#### Audit trail for a dual-use tool *(days)*

MCP-09: the server's only output today is one startup line on stderr, which MCP hosts discard. Adopt `tracing` with a stderr layer (never stdout — stdout is the JSON-RPC transport and one stray println! corrupts the session) plus `--audit-log <path>` opened O_APPEND|O_CREAT mode 0600, one JSON object per line: ts, session uuid, req_id, tool, root-relative binary label, binary_sha256, params_hash, verdict (ok/denied/timeout/cancelled/error), code, duration_ms, total_count, returned, cache hit/miss, bytes_read. Denials log the REQUESTED path — that is the whole point — but no file contents and no gadget text. Rotate at --audit-log-max-mb. Add a `get_server_stats` tool exposing requests_total by tool, denied_total, denied_consecutive, timeout_total, cancelled_total, wedged_total, cache hit/miss/tamper/evictions, cache_bytes, inflight. After N consecutive path_denied results in one session (default 20), delay responses by 250 ms and log `probing_suspected: true` — a rising refusal count is the specific signal that reveals a prompt-injected agent walking the filesystem, and combined with v0.1.1's `get_server_config` (which TELLS the agent the roots) a legitimate agent generates no denials at all, so the signal is clean. Declare the MCP `logging` capability and forward warn/error as notifications/message so the operator, who never sees stderr, sees them.

*Closes:* `MCP-09`

### Exit criteria

These are the gates. Each one is meant to be able to go red.

- A find_gadgets request that times out leaves NO work running: CPU utime delta measured at +3 s and +8 s after the client receives the error is under 0.2 s and RSS growth is under 50 MB, asserted by a test that samples /proc/<pid>/stat or `ps -o %cpu`. The measured baseline today is 398-400% CPU held indefinitely after a clean 2.00 s timeout reply.
- `notifications/cancelled` produces a `cancelled` response within 3 s and releases the semaphore permit. Today the notification is accepted and NOTHING happens — the depth-100000 request I sent never produced a response and was at 54,873 MB RSS thirteen seconds later.
- get_binary_info accepts timeout_secs, refuses a file over --max-file-bytes with resource_exhausted, and does not block the runtime: four concurrent get_binary_info calls on the largest fixture still let a tools/list answer in under 100 ms. The existing tests/expected_tools_schema.json snapshot already RECORDED that get_binary_info's properties are only ['base','binary_path'] and did not fail — extend it to require timeout_secs on every tool so the omission becomes an error.
- Both caches are bounded: 1,000 distinct scans with --cache-mem-mb 64 keep steady-state RSS flat and cache_bytes under 64 MiB. Today twelve scans of one 900 KB binary walk 5 MB -> 84 MB monotonically with max_results:1, and one depth-40 scan retains 2.57 GB.
- Every tool declares an outputSchema; a conformance test drives the real server over stdio for all 24 fixtures x all tools and validates each structuredContent against that tool's own schema with additionalProperties:false, asserting the SAME field set for elf-Linux-x64, elf-Linux-x64 with section=.text, elf-Mips (delay_slot true) and the universal fixture (arch set) — the four shapes that differ today, one of which never emits delay_slot at all.
- `popfq ; ret` is not stack-pivot; a bare `jmp [rax]` is not dispatcher and the COP form is; MIPS, PowerPC, RISC-V and ARM64 fixtures each report non-zero counts in at least four distinct classes (today they report 0 mem-read, 0 mem-write, 0 stack-pivot); and a register-name validator over every fixture's regs_written passes `^(r[0-9]+|x[0-9]+|w[0-9]+|e?[a-z]{2}|sp|lr|pc|fp|ip|sl|sb)$` with zero tokens beginning `{`, `#` or `[` — today `{r4` and `#0x12e44` appear on ARM.
- Classifier precision and recall are reported for the primary `class` field against a hand-labeled corpus the classifier did not generate, per architecture, covering x86-64, x86-32 and at least three non-x86 architectures, with x86-64 class precision >= 0.90 and dispatcher precision >= 0.80. The reported x86-64 figure is no longer 1.0000. A test asserts the corpus file's hash is unchanged after the run, which the current test cannot do because it regenerates the corpus it grades against.
- No quality/rank bucket holds more than 25% of gadgets on elf-x64-bash (today 92% tie at 100), `pop rdi ; ret` and `pop rsi ; ret` appear in the top 20 by default order, and no `retf`/`ret imm16` gadget does. Today the top 8 by sort_by=quality are ret, add esp 0x8 ; ret, retf 0x2bbc, ret 0x2bbc, retf 0xce39...
- A cursor walks elf-Linux-x64 at depth 4 with max_results=100 across 28 pages, and the concatenated ids equal exactly the id set from one max_results=50000 call, in the same order, with no duplicates or gaps; a cursor from a depth-4 query is rejected against a depth-6 query.
- THE WORKABILITY TEST: a scripted agent completes a full loop — locate '/bin/sh', find a gadget that sets rdi without clobbering rsi or rdx, classify it, generate a chain — using FEWER THAN 10,000 tokens of tool output in total. This is the criterion that operationalizes the word 'workable'; today the same task requires pulling thousands of alphabetically-ordered gadgets into context.
- msvcrt!memset on pe-x64-cmd-v6.1.7601 reports iat_slot_vaddr 0x4ad29000 and hint_name_vaddr 0x4ad2af40; and as a structural invariant that generalizes to any PE, every DLL's iat_slot_vaddrs are strictly increasing, 8-byte aligned and exactly 8 apart (4 on x86). The current wrong values (0x4ad2af40, 0x4ad2af4a, 0x4ad2af54 — 10 apart, unaligned) fail the alignment assertion on any input. The existing test at pe.rs:288 asserts `thunk_vaddr == image_base + thunk_rva`, which is tautological and passes either way.
- Every tool call, including every denial and timeout, produces exactly one audit line with the resolved path and verdict, mode 0600, containing no gadget text or file bytes; and a `stdout_is_pure_jsonrpc` test runs a full session including an error and a tampered cache entry and asserts every stdout line parses as JSON-RPC 2.0.
- An end-to-end MCP smoke test runs in CI on Linux, macOS and Windows against the PACKAGED release artifact, not a cargo-built binary.

<details><summary>All findings closed in this phase</summary>

| ID | Sev | Kind | Title |
|---|---|---|---|
| `CHWIN-03` | high | correctness-bug | IAT "thunk" address is the IMAGE_IMPORT_BY_NAME record, not the FirstThunk slot — the IAT-dereference chain jumps to the ASCII of the function name |
| `CLS-01` | high | unsubstantiated-claim | The classification quality gate is circular: the "independent" labeler is a transliteration of the classifier |
| `CLS-02` | high | correctness-bug | `popfq ; ret` is classified as a stack-pivot |
| `CLS-03` | high | design-limitation | The `dispatcher` label (R8) fires on 99.3% non-dispatchers and misses the COP form entirely |
| `CLS-04` | high | correctness-bug | Non-x86 heuristic path produces zero mem-read, mem-write and stack-pivot labels on MIPS, PowerPC and RISC-V |
| `CLS-05` | medium | correctness-bug | `regs_written` contains non-register junk (`{r4`, `#0x12e44`) on ARM and other non-x86 targets |
| `CLS-06` | medium | missing-engineering | The primary class — the `class` field users actually see — is never evaluated, and the labeled dataset mixes prediction with ground truth |
| `CLS-07` | medium | design-limitation | The quality score is uncalibrated and degenerate: 92% of gadgets tie at 100, and `ret` scores the same as `pop rdi ; ret` |
| `CLS-08` | medium | missing-feature | Classification is computed but not queryable: no filter by class, label, or written register in CLI or MCP |
| `CLS-10` | medium | missing-engineering | Evaluation covers x86-64 only; the 32-bit path and all seven low-confidence architectures have zero measured precision |
| `CLS-11` | medium | unsubstantiated-claim | The "committed labeled set" is regenerated by the test itself, and the hand-verification claim has no artifact |
| `CLS-12` | low | design-limitation | R6's arithmetic set omits division, xadd, bit-test and byte-swap while including flags-only compares |
| `CLS-13` | low | design-limitation | `push rax ; ret` is classified `other`, and `ret 0x10` is not a stack adjustment while `add rsp, 0x10 ; ret` is |
| `CRIT-03` | medium | missing-feature | The documented JSON record schema does not match what is emitted: `section` appears only with `--section`, `delay_slot` is never emitted by any interface, and the vaddr format differs |
| `ECO-05` | medium | design-limitation | Register read/write data is empty on 8 of the 10 supported architectures (capstone driven without detail mode) |
| `MCP-03` | high | security | Unbounded `--depth` plus a non-cancellable worker: one request pins a CPU and consumes tens of GB after the client already got its timeout error |
| `MCP-05` | medium | design-limitation | In-memory scan cache has no size limit, eviction or TTL — memory grows monotonically for the life of the server |
| `MCP-06` | medium | parity-divergence | get_binary_info has no timeout and no cap, runs inline on the async runtime, and no tool limits input file size |
| `MCP-09` | low | missing-engineering | No audit trail for a tool the project itself classifies as dual-use |
| `PERF-06` | high | correctness-bug | MCP per-request timeout cannot cancel the scan it is timing out |
| `ROB-07` | low | design-limitation | MCP server's in-memory scan cache is never evicted |

</details>

---

## Phase 4 — v0.4.0 — Ask a real question

**Effort:** 1-hour · **Findings closed:** 9

**Goal.** A practitioner can express the question they actually have — 'a gadget that loads rdi from the stack and clobbers neither rsi nor rdx' — in one command, search for strings, opcodes and memory, and get machine-readable output; and the CLI is no longer behind its own MCP server.

**Why here.** Everything here is a consumer of the v0.2 engine shape and the v0.3 semantic layer, so it cannot come earlier: a constraint search built on a classifier that emits `{r4` as a register name on eight architectures returns confidently wrong answers, and `--string`/`--opcode`/`--memstr` reuse v0.2's region iterator and regex primitive. It comes before chains (v0.5) because goal-directed chain synthesis is a search over exactly this query layer. It is one release rather than two because the surface must land on the CLI and the MCP simultaneously — shipping a filter an agent can use but a human cannot repeats the exact defect ECO-02 names, and the reverse defect already exists (the MCP has `--re` and `--align`, the CLI has neither). This release is small in finding count and large in work: the four heavy flags (--all, --align, --callPreceded, --re) already landed with the v0.2 keystone, so what remains is genuinely new capability rather than plumbing.

### Workstreams

#### Constraint and semantic search, on both surfaces at once 


CLS-09: extend `Classification` (rf-classify/src/lib.rs:60-81) with the three things a constraint search needs and no consumer can derive from the text — register-transfer relations (src -> dst per gadget), a computed stack delta (for x86/x64 via iced-x86: sum pop-family widths + `ret imm16` immediate + `add/sub rsp, imm` + `leave`, and None rather than a wrong number where a non-constant rsp effect exists), and an explicit clobber set. ECO-01: build the query layer over those fields — `--set-reg rdi`, `--from-stack` (require the write to originate in a pop/load, not an arbitrary computation), `--no-clobber rsi,rdx`, `--reads-reg`, `--max-stack-delta N`, `--max-side-effects N`, `--max-insns N`, `--terminator ret|jmp|call|syscall`, plus a ropper-style wildcard sequence matcher (`--search 'pop rdi; ret'`). ECO-12: `--pivot` as a preset over the stack-pivot label the classifier already computes (rf-classify/src/x86.rs:169) and which v0.3 made correct. Expose the identical parameters as an MCP `find_gadgets_by_effect` tool, with each result carrying an explanation object {sets, reads, clobbers, stack_delta, terminator, why} so an agent can justify a choice without re-deriving semantics from gadget text. Add the grafted capability-matrix test: a CI test that enumerates the CLI flag surface and the MCP tool-parameter surface and FAILS on divergence, so 'the CLI is behind its own MCP server' becomes structurally impossible rather than fixed once.

*Closes:* `ECO-01`, `CLS-09`, `ECO-12`

#### Non-gadget search 

CLI-05/ECO-02: implement `--string` (ROPgadget's regex semantics), `--opcode` (hex byte sequence, with `??` wildcards) and `--memstr`, searching only within MAPPED sections of the loaded image — never raw file offsets, never bytes outside a section — and honoring --range and --offset as the oracle does. Return {vaddr, section, length, escaped preview, writable, executable}. Expose the same as MCP `find_string`/`find_bytes` tools: the flag allowlist currently blanket-rejects these as a file-read leak, but an agent can already obtain the file's executable bytes through find_gadgets, so the ban costs a core capability and buys nothing; scoping the search to mapped sections keeps the line the allowlist was drawn to protect. CLI-09: expose `--re` on the CLI, which exists only in rf-mcp today so the same query is not portable between an agent and its human teammate.

*Closes:* `CLI-05`, `ECO-02`, `CLI-09`

#### Close the ROPgadget flag gap and prove it 

CLI-12: work the 26-flag table published in v0.1.1's MANUAL down to zero unimplemented rows other than those explicitly marked out of scope (`--console` and the RE-tool flags). Add a conformance test that walks the full flag matrix against the vendored oracle on every fixture, so a flag that is present but semantically wrong fails the same way a missing one does.

*Closes:* `CLI-12`

#### --info becomes a real checksec, and output formats an agent can stream 

ECO-06: extend `--info` (rf-cli/src/lib.rs:595) into a checksec/rabin2 -I replacement plus a new MCP `get_mitigations` tool — ELF: NX from PT_GNU_STACK, PIE from ET_DYN plus interpreter/DT_DEBUG, RELRO from PT_GNU_RELRO plus DT_BIND_NOW/DF_BIND_NOW, canary from a __stack_chk_fail import, FORTIFY from *_chk imports, plus symbol/dynsym listing; PE: DllCharacteristics for DYNAMICBASE/NXCOMPAT/GUARD_CF/HIGH_ENTROPY_VA and the load-config directory for CETCOMPAT and GuardFlags (this is also what makes v0.2's CRIT-01 warning able to distinguish GUARD_CF from Intel CET honestly); Mach-O: MH_PIE, hardened runtime, code-signature presence. Report `{mitigation: {enabled: bool|"unknown", evidence: "..."}}` — 'unknown' with a reason is far more useful to an agent than a confident wrong boolean. Before an agent decides ROP is even the right technique it must know this, and today it must ask a human to run checksec. ECO-09: add `--format {human,json,jsonl,csv,raw}`, streaming JSON-lines through v0.2's sink rather than materializing a monolithic array, and make the raw-bytes chain output documented at rf-chain/src/lib.rs:248 actually reachable.

*Closes:* `ECO-06`, `ECO-09`

### Exit criteria

These are the gates. Each one is meant to be able to go red.

- `rop-finder --binary elf-Linux-x64 --set-reg rdi --from-stack --no-clobber rsi,rdx --max-side-effects 1 --terminator ret` returns exactly the gadget at 0x401648 (`pop rdi ; ret`) and returns NO gadget whose regs_written intersects {rsi, rdx}; every returned gadget's regs_written is independently re-derived from its text by the test rather than read back from the field under test.
- The same query issued through the MCP `find_gadgets_by_effect` tool returns the identical id set, and the capability-matrix CI test enumerates both surfaces and fails if a flag exists on one and not the other. Today `--re` and `--align` exist only on the MCP side and `--string`/`--opcode`/`--memstr` on neither.
- Stack delta and clobber set are verified against ground truth on a 500-gadget sample with zero mismatches; every gadget where the rsp effect is non-constant reports None rather than a number.
- `--string`, `--opcode` and `--memstr` produce byte-identical output to ROPgadget on all 24 fixtures, including under `--range` and `--offset`.
- The MANUAL's ROPgadget flag-coverage table has zero 'not implemented' rows other than `--console` and the RE-tool flags, and the 26-flag conformance test passes against the vendored oracle on every fixture — a flag that exists but diverges fails identically to one that is missing.
- `--info` mitigation output matches `checksec` on every Linux fixture and the PE header/load-config flags on every Windows fixture, field for field, with any 'unknown' carrying a stated reason.
- `--format jsonl` emits its first record before the scan completes and peak RSS is strictly lower than `--format json` on the 9.3 MB fixture; the raw-bytes chain output is reachable from the CLI.

<details><summary>All findings closed in this phase</summary>

| ID | Sev | Kind | Title |
|---|---|---|---|
| `CLI-05` | high | missing-feature | The entire non-gadget search surface is missing: --string, --opcode, --memstr |
| `CLI-09` | medium | missing-feature | --re is implemented in the MCP server but not exposed on the CLI |
| `CLI-12` | medium | missing-feature | ROPgadget flag coverage: 14 of 26 flags unimplemented (full table) |
| `CLS-09` | medium | missing-feature | No register-transfer relations, stack delta, or clobber set — the semantic layer stops at eight coarse class names |
| `ECO-01` | high | missing-feature | No constraint-based / register-aware gadget search anywhere in the product |
| `ECO-02` | high | missing-feature | No text-, regex-, opcode- or string-search: the CLI cannot search at all, and is behind its own MCP server |
| `ECO-06` | medium | missing-feature | `--info` reports no exploit mitigations and no ELF symbols — it is not a `checksec`/`rabin2 -I` replacement |
| `ECO-09` | medium | missing-feature | Output formats: no JSON-lines/CSV/raw, monolithic JSON array, and the documented "raw bytes" chain output is unreachable |
| `ECO-12` | low | missing-feature | No stack-pivot-oriented search, despite the classifier already computing the label |

</details>

---

## Phase 5 — v0.5.0 — Chains that actually run

**Effort:** 1-hour · **Findings closed:** 16

**Goal.** For the first time, every chain this tool emits has been EXECUTED under an emulator in CI and observed to do what the tool claims — execve('/bin/sh') for Linux targets, VirtualProtect called with four correct arguments and control transferred into intact shellcode for Windows — and generation refuses rather than printing a chain that cannot work.

**Why here.** The ordering INSIDE this release is the whole point, and it is the one place both losing plans got it right or wrong in an instructive way. The Windows builder has four independent defects that each alone make the chain crash: an inert 0x4141... alignment word that the preceding gadget's `ret` jumps to (CHWIN-01), lpflOldProtect defaulting to the shellcode address so VirtualProtect overwrites the first 4 bytes of the buffer it just made RWX before the chain returns there (CHWIN-02), an IAT 'thunk' that is the ASCII function name (CHWIN-03, root-fixed in v0.3), and an empty already-set list so IAT-gadget pops destroy populated argument registers (CHWIN-07). All four survived a 31-assertion test suite because those tests only assert WORD KINDS. Fixing them before the emulator exists produces four more unverified rewrites — which is exactly what the risk-first rival proposed while conceding in its own next phase that the emulator 'is the only thing that would have caught' them. So the harness is workstream one and it is a real build, not a checkbox. This release is fifth because v0.1.1 already warning-gated the Windows chain as experimental, which buys the time to do it properly; and because synthesis depends on v0.4's constraint query layer and v0.3's clobber/transfer data to pick gadgets at all.

### Workstreams

#### Build the emulator harness FIRST — nothing else in this release starts until it runs 

CHWIN-05: PLAN §4b's emulator-harness exit criterion was marked done with no artifact; the only chain tests are rf-chain/src/windows.rs:381-697, which assert word kinds. Build a unicorn-engine harness (Rust, or tests/emulate.py) that maps the target's segments, lays the generated chain bytes on a synthetic stack, stubs VirtualProtect/execve at their resolved addresses, single-steps to a bound, and ASSERTS the goal was reached with the expected arguments. Wire it into CI over every fixture that can produce a chain, and seed it with the four Windows bugs as pre-fix/post-fix regression tests — each must FAIL on the current code and PASS after, recorded as such. CHLX-04: add a static semantic verifier in rf-chain/src/lib.rs:129-188 that checks stack-word accounting end to end (every emitted word is consumed by a pop or a ret; no inherited padding gaps) and REFUSES to emit a chain that fails either the static check or the emulator — 'chains that are emitted must be runnable or not emitted'. CHLX-09: extend tests/chain_parity.py:73-80 past the default flag set to cover `--badbytes`, where the divergence is documented but untested.

*Closes:* `CHWIN-05`, `CHLX-04`, `CHLX-09`

#### Windows chain correctness, each fix proven by the harness 

CHWIN-01: align_for_transfer at rf-chain/src/windows.rs:226-236 inserts an inert `WordKind::Padding` data word for stack alignment, which the preceding gadget's `ret` consumes as a RETURN ADDRESS — the chain crashes at 0x4141414141414141 instead of calling VirtualProtect. Achieve alignment by choosing a real `ret` gadget address, or by gadget selection, never by inserting a word the ret will jump into. CHWIN-02: windows.rs:99-100, :304, :110 default lpflOldProtect to the shellcode address, so VirtualProtect writes the old protection DWORD over the first 4 bytes of the shellcode it just made RWX and then the chain returns there — allocate a distinct writable DWORD scratch address. CHWIN-07: windows.rs:283,286 pass an EMPTY already-set list to `ChainBuilder::padding`, so extra pops in the IAT gadgets destroy argument registers populated earlier — pass the real set. CHWIN-04: the alignment invariant at windows.rs:25-29 and :130-155 is anchored to a hardcoded, unstated assumption about the chain base that is usually wrong (it assumes a 16-byte-aligned base; the saved-return-address case, which is the common one, is the opposite) — make it an explicit `--chain-base` / `chain_base_parity: aligned|return_address` parameter defaulting to return_address, echo the assumption in the JSON and in the emitted script's preamble, and validate against it. CHWIN-06: `WinChainOpts::api_name` exists at windows.rs:52,67 and is set from NOWHERE (a grep for it matches only that file), hardcoding VirtualProtect and making the IAT resolution path unreachable on every binary the project ships — plumb `--api-name` through the CLI (lib.rs:112-118) and the MCP ChainQuery (lib.rs:371-380), so it can target VirtualAlloc, which is what the shipped cmd.exe fixtures actually import. Every one of these is gated on a harness assertion, not on inspection.

*Closes:* `CHWIN-01`, `CHWIN-02`, `CHWIN-04`, `CHWIN-06`, `CHWIN-07`

#### Linux chain correctness and resilience 

CHLX-05: the `.data` fallback at rf-chain/src/linux.rs:72-77 picks the first writable non-executable section, which on this project's OWN fixtures is `.tdata`/`.tbss` (TLS offsets, not absolute addresses) or `.init_array` (read-only under RELRO) — require a genuinely writable, non-TLS, post-RELRO section and error clearly when none exists. CHLX-01: linux.rs:338-362 fails outright when any one of five literal gadgets is absent, which is why chain generation fails on elf-x64-bash, elf-x86-bash, elf-FreeBSD-x86 and Linux_lib32.so — binaries where ropper, angrop and pwntools all succeed. Add per-requirement fallback strategies (register-transfer chains such as `pop rax ; mov rdx, rax`, ret2csu, SROP) driven by v0.4's constraint query layer. CHLX-02: linux.rs:406-412 builds the syscall number with 59 chained gadgets even when `pop rax ; ret` is already in the chain — use it, cutting payload size ~4x. CHLX-03: linux.rs:114 (chain.validate) and lib.rs:169-181 make `--badbytes` an unrecoverable hard failure; trigger an alternative-address and alternative-gadget search instead. CHLX-08: rf-cli/src/lib.rs:1041-1050 warns on PE GUARD_CF but says nothing when a PIE/ET_DYN target gets link-time addresses baked into the chain — add the symmetric warning.

*Closes:* `CHLX-01`, `CHLX-02`, `CHLX-03`, `CHLX-05`, `CHLX-08`

#### From two frozen recipes to goal-directed synthesis, and structured failure 
ECO-04: replace the two hardcoded recipes with a synthesizer over v0.4's constraint layer — a goal is a set of register/memory postconditions, the search backtracks over candidate gadget sequences using v0.3's clobber and transfer data, and every candidate is validated against the emulator before emission. Add `plan_chain` alongside `build_rop_chain` on both surfaces: it always succeeds and returns machine-readable feasibility — {feasible, requirements:[{id, description, satisfied, strategies_tried:[{pattern, candidates}], relaxations:[{param, from, to, would_help}]}], satisfied_requirements:[{id, gadget_id, vaddr}], assumptions:{chain_base_parity, write_target, needs_leak}}. `relaxations` is computed, not guessed: re-run each unsatisfied requirement's query at depth*2 and with multibr and report whether candidates appear. Today the same input returns the prose string `cannot populate rdx: no 'pop rdx' gadget and no 'pop rax' + 'mov rdx, rax' fallback`, which an agent can neither act on nor learn from; build_rop_chain returns the same shape on failure so there is one contract. CHLX-07: add mprotect, ret2libc, SROP and staged-shellcode targets plus a generic `--syscall <n>`, and one ARM64 and one MIPS chain target. CHWIN-08: add stack pivoting, multi-call composition, export-table resolution, x86 IAT support, shellcode staging and a user-selectable flNewProtect (`--prot`) at windows.rs:294-379. Every target is gated on a passing harness assertion before it may be advertised.

*Closes:* `ECO-04`, `CHLX-07`, `CHWIN-08`

### Exit criteria

These are the gates. Each one is meant to be able to go red.

- The emulator harness runs in CI and, for every fixture that produces a chain, EXECUTES it and observes the intended effect: SYS_execve with the correct argv for Linux targets; VirtualProtect entered with correct lpAddress/dwSize/flNewProtect/lpflOldProtect and control transferred into shellcode whose first 4 bytes are INTACT for Windows targets. That last clause is the direct falsification of CHWIN-02 and cannot be satisfied by any test that only inspects word kinds, which is all the current 31 assertions at windows.rs:381-697 do.
- Each of CHWIN-01, CHWIN-02, CHWIN-03 and CHWIN-07 has a named regression test that FAILS on the pre-fix commit and PASSES after, with both runs recorded in docs/chain-regressions.md. A fix without a failing-before run does not count.
- `--ropchain` produces an emulator-validated chain on all four x86/x64 ELF fixtures that fail today (elf-x64-bash, elf-x86-bash, elf-FreeBSD-x86, Linux_lib32.so) and on at least one ARM64 and one MIPS fixture.
- `--ropchain --badbytes 00` produces a working alternative chain rather than a hard failure on at least three fixtures where it currently aborts; chain_parity.py covers the --badbytes flag set and gates CI.
- The execve chain on elf-Linux-x64 is at least 4x smaller in words than today's 59-gadget syscall-number construction, and no larger than 1.25x the pwntools-generated equivalent in gadget count.
- The static verifier REJECTS a hand-corrupted chain with a padding gap, and generation refuses to print any chain that fails either the static verifier or the emulator — verified by a test that corrupts a known-good chain and asserts a refusal, not a warning.
- At least four Linux targets (execve, mprotect, ret2libc, SROP) and three Windows capabilities (stack pivot, multi-call composition, export-table resolution) each pass a harness assertion on a fixture. `--api-name VirtualAlloc` reaches the IAT path on the shipped cmd.exe fixture, which is unreachable today.
- `plan_chain` on pe-x64-cmd-v6.1.7601 for windows-virtualprotect returns feasible:false with a requirements entry id=set_rdx, a non-empty strategies_tried, at least one computed relaxation, and a non-empty satisfied_requirements list whose gadget_ids resolve through get_gadgets. Today the same input returns one prose sentence.
- No chain-related statement anywhere in README/MANUAL is unbacked by a passing harness test or explicitly marked not implemented; the doc-claims CI test from v0.2 enforces it.

<details><summary>All findings closed in this phase</summary>

| ID | Sev | Kind | Title |
|---|---|---|---|
| `CHLX-01` | high | missing-feature | Chain build fails on binaries where a chain is clearly constructible — no fallback strategy for any required gadget |
| `CHLX-02` | medium | design-limitation | Syscall number built with 59 chained gadgets even when `pop rax ; ret` is already in the chain — 4x larger payload than necessary |
| `CHLX-03` | medium | design-limitation | `--badbytes` turns chain generation into an unrecoverable hard failure with no alternative-address search |
| `CHLX-04` | medium | missing-engineering | No semantic verification of the generated chain; inherited padding gaps can emit a chain that cannot work |
| `CHLX-05` | medium | correctness-bug | `.data` fallback picks the first writable non-executable section, which on the project's own fixtures is `.tdata`/`.tbss` (TLS offsets) or `.init_array` (RELRO read-only) |
| `CHLX-07` | medium | missing-feature | Only one Linux chain target exists — no mprotect, ret2libc, SROP, stager, or non-x86 chains |
| `CHLX-08` | low | missing-engineering | PIE / ET_DYN binaries get link-time addresses in the chain with no warning, unlike the PE GUARD_CF path |
| `CHLX-09` | low | missing-engineering | Chain parity harness exercises only the default flag set, so the documented badbyte divergence is untested |
| `CHWIN-01` | high | correctness-bug | Stack-alignment pad is an inert data word that the preceding gadget's `ret` jumps to — chain crashes at 0x4141414141414141 instead of calling VirtualProtect |
| `CHWIN-02` | high | correctness-bug | lpflOldProtect defaults to the same address as the shellcode — VirtualProtect overwrites the first 4 bytes of the shellcode it just made RWX, then the chain returns there |
| `CHWIN-04` | medium | design-limitation | The alignment invariant is anchored to a hardcoded, unstated and usually-wrong assumption about the chain base, with no way for the user to correct it |
| `CHWIN-05` | medium | missing-engineering | PLAN §4b's emulator-harness exit criterion is unmet; no end-to-end execution test exists, and the existing tests only assert word kinds |
| `CHWIN-06` | medium | missing-feature | The target API name is hardcoded to "VirtualProtect" with no CLI or MCP knob, making the IAT resolution path unreachable on every binary the project itself ships and analyzed |
| `CHWIN-07` | medium | correctness-bug | emit_api_call64 passes an empty already-set list to ChainBuilder::padding, so extra pops in the IAT gadgets destroy previously-populated argument registers |
| `CHWIN-08` | medium | missing-feature | PLAN §6.2's hard parts are absent: no stack pivot, no multi-call composition, no export-table resolution, no x86 IAT, no shellcode staging, and no way to choose flNewProtect |
| `ECO-04` | high | missing-feature | Chain generation is two frozen recipes, not a synthesis engine — no goal-directed chains, no generic syscall, no ARM chains |

</details>

---

## Phase 6 — v1.0.0 — Fast enough to say so, and published

**Effort:** multi-hours · **Findings closed:** 8

**Goal.** The performance numbers in the README are generated by the v0.2 criterion suite rather than typed, every architecture improves on the recorded baseline, and rf-core/rf-scan/rf-classify/rf-chain are on crates.io with documented public APIs someone else can build on.

**Why here.** Performance is last because the honest move was already made in 1 hour: the README now states the measured 5.7-6.2x rather than claiming >=10x, so nothing here is broken or dishonest — the number is simply smaller than PLAN wanted, and the remaining work is optimization with a real gate behind it. Optimizing earlier would have been actively wrong twice over: before v0.2's parity gate, a speed/correctness trade would have nothing to catch it; and before the v0.2 engine keystone and v0.4's query surface, it would have tuned a loop that was about to change shape. The four wins are known, measured and specific, and three of them are rewrites of the very loop v0.2 reshaped — which is exactly why they wait until that shape is final rather than fighting it. Publishing is genuinely last: you cannot put a 1.0 API on crates.io while the loader can fabricate gadgets, the MCP can read arbitrary files, or the chains cannot run, and all three of those are only settled by v0.5.

### Workstreams

#### Delete what does not pay, then parallelize what does 

PERF-03: remove the per-start decode cache at rf-scan/src/engine.rs:347 and its capstone twin at cs.rs:274 — measured 171,648 decode invocations against 1,452 hits on elf-x64-bash (0.8% hit rate), a NET SLOWDOWN on x86, the dominant cost centre on capstone architectures, and hundreds of MB of retained memory. Deleting it alone makes the decode phase 1.47x faster. The project is architecturally named after this cache; delete it anyway. PERF-04: re-partition rayon at engine.rs:206-233 from (region x anchor) work items to overlapping byte ranges with overlap = depth*align — the current granularity gives 1.2-1.9x on 16 cores because on MIPS one anchor holds 92% of the hits. PERF-09: replace the per-(hit, depth) window re-decode at cs.rs:296 with a single resumable region decode, measured 2.3-3.3x cheaper; this is where the non-x86 speedup has to come from. PERF-11: eliminate the three redundant copies of executable bytes between loader and scanner at engine.rs:151.

*Closes:* `PERF-03`, `PERF-04`, `PERF-09`, `PERF-11`

#### Build the trie index PLAN promised and use it for dedup 

PERF-10/CLAIM-07: the suffix-trie index was a Phase 1 PLAN deliverable and the stated basis of two PLAN features, and it does not exist anywhere in the codebase — dedup at engine.rs:239 allocates three extra strings per gadget instead. Build it, use it for dedup, and either eliminate the per-gadget temporary allocations or hash the joined text without materializing it; then either mark the two dependent PLAN features as delivered or delete them from the roadmap. This lands after PERF-03/04/09 because dedup's cost profile changes once the decode phase stops dominating.

*Closes:* `PERF-10`, `CLAIM-07`

#### Publish 

ENG-08/ECO-10: give rf-core, rf-scan, rf-classify and rf-chain the metadata crates.io requires (description, repository, license, keywords, categories) and replace path-only workspace deps with versioned ones — none of the crates can currently be published at all. Break rf-mcp's dependency on the rf-cli BINARY crate by extracting the shared request/option layer into a library crate: that duplication is the concrete reason the align post-filter and the cache char-boundary panic each existed in two places. Define and document the public API surface for rf-core (loaders), rf-scan (ScanOptions, Gadget, the sink) and rf-classify (Classification, the query predicates), with doc comments, doctests and a stated semver policy; cut 1.0.0 across the workspace and publish rop-finder and rop-finder-mcp as installable binaries.

*Closes:* `ENG-08`, `ECO-10`

### Exit criteria

These are the gates. Each one is meant to be able to go red.

- `cargo bench` runs in CI, results are recorded per commit, and the performance table in README.md is GENERATED from that data rather than typed — the v0.2 doc-claims test fails if the two disagree. This is not an OR: 'edit the docs' is not an acceptable way to satisfy this phase, because the docs were already made honest in v0.1.1 and the only remaining question is whether the engineering moved the number.
- Measured speedup versus ROPgadget 7.7 at --depth 10 improves on the recorded v0.1.1 baseline on EVERY architecture (from 5.7-6.2x x86/x64, 2.1x ARM64, 1.7x MIPS, 1.3x PPC), with the achieved figure published whatever it is; PLAN's >=10x criterion is either met or formally retired in PLAN.md with a written reason. A phase that lands no engine change fails this criterion.
- A 16-core machine shows >= 8x scaling versus single-threaded on the MIPS fixture (today 1.2-1.9x, because one anchor holds 92% of the hits).
- The per-start decode cache is gone from both engine.rs and cs.rs, and the decode phase on elf-x64-bash is at least 1.4x faster with a byte-identical gadget set.
- The suffix-trie index exists as a module, dedup uses it, and a heap-profile run shows zero per-gadget temporary String allocations in post_process.
- Every exit criterion from v0.1.1 through v0.5 still holds after every change in this phase — parity absolute counts, classifier precision, chain emulation, fuzz, cache integrity, MCP cancellation timing — and CI is green throughout. The mutation experiments from v0.2 are re-run and still turn CI red.
- `cargo publish --dry-run` succeeds for all six crates; rf-mcp no longer depends on a binary crate; rf-core and rf-scan have documented public APIs with passing doctests; a third party can `cargo install rop-finder` and follow the README end to end without reading the source.

<details><summary>All findings closed in this phase</summary>

| ID | Sev | Kind | Title |
|---|---|---|---|
| `CLAIM-07` | medium | missing-feature | The trie index — a Phase 1 deliverable and the basis of two PLAN features — does not exist anywhere in the codebase |
| `ECO-10` | medium | missing-engineering | No library/API story: crates are unpublished path-only deps, no FFI, no Python binding |
| `ENG-08` | medium | missing-engineering | None of the crates can actually be published; the library story is aspirational |
| `PERF-03` | high | design-limitation | The "per-start decode cache" has a 0.8% hit rate and is a net slowdown on x86 |
| `PERF-04` | high | design-limitation | Rayon partitioning at (region x anchor) granularity gives 1.2-1.9x on 16 cores |
| `PERF-09` | medium | missing-engineering | Capstone path re-decodes a window per (hit, depth); a single resumable region decode is 2.3-3.3x cheaper |
| `PERF-10` | medium | missing-feature | The suffix-trie index was never built; dedup allocates 3 extra strings per gadget instead |
| `PERF-11` | low | missing-engineering | Executable bytes are copied at least three times before scanning |

</details>

---

## Deferred

Three of 137, deferred deliberately rather than padded into a phase.

### `ECO-07` — No symbolic or emulated gadget semantics — classification is purely syntactic, with no rsp delta and no verification

Full symbolic or emulated per-gadget semantics is a research-scale subsystem — an IR, a symbolic executor and a solver integration, comparable in size to the rest of this plan — and it is not what a gadget finder's users need first. The practically useful 80% of it is pulled forward and CLOSED elsewhere rather than quietly dropped: stack delta, clobber sets and register-transfer relations land in v0.4 under CLS-09, and concrete-execution validation lands in v0.5's emulator harness under CHWIN-05/CHLX-04, which is where it matters most because that is what stops a broken chain from being printed. What stays deferred is per-gadget symbolic summaries. I would rather ship a syntactic semantic layer with measured precision than a half-built symbolic one whose failures look like answers. Revisit as its own project once v0.4's query layer has real users saying which queries it cannot express. One rival plan claimed this finding closed inside a one-hour workstream that actually delivers only a closed-form stack delta; that is coverage bought by under-scoping, and it is exactly the pattern this audit was run to catch.

### `ECO-08` — Single-binary only: no multi-module / libc workflow, and no libc-database or one_gadget integration

Multi-module / libc workflows plus libc-database and one_gadget integration require a new addressing model — per-module bases, relocation, leak-driven rebasing — that touches rf-core, rf-scan, rf-chain and both front ends, and the database halves are network- and corpus-dependent in a way that cannot be gated in CI without vendoring a corpus that would dwarf the repository. It is additive: no user is misled by its absence, and everyone who needs it today already has pwntools open. The reconnaissance half that users reach for most often is delivered in v0.4 by ECO-06's checksec-grade --info, and v1.0's published library API is the enabler that makes a module-aware workspace (an `open_workspace` MCP tool over per-module bases) a bounded follow-on rather than a rewrite. Explicitly out of scope for this plan rather than padded into v0.5, where it would be the item that slips.

### `ECO-11` — No interactive console and no RE-tool integrations (r2/rizin, Ghidra, IDA, gdb/pwndbg)

An interactive console plus r2/rizin, Ghidra, IDA and gdb/pwndbg integrations are four to six separate integration projects, each with its own host plugin API, release cadence and test rig, and every one of them would need a third-party tool installed in CI to be testable at all. They add no capability the CLI and MCP will not already have after v0.4. The MCP server delivered in v0.3 is the strategically better integration surface for this product and covers the agent-driven case that motivates most of these; JSON-lines output (v0.4, ECO-09) and the published rf-core/rf-scan API (v1.0, ECO-10) turn the rest into things other people can build rather than things this project must carry and maintain. Close the finding by stating plainly in MANUAL.md that they are not planned, so a reader is not left guessing.

## Trade-off this ordering makes

Ordering by shippability means capability lags safety and truth by two releases: the MCP server the user asked for by name lands third, around 1 hour, not first. An MCP-first plan could harden rf-mcp in a fortnight — but it would ship an agent-facing server on a loader that silently fabricates thousands of gadgets from unrecognized ELF machine types (CORE-01), reports 0 as the Mach-O image base (CORE-02), loses every notrack and repz-ret gadget to dedup collisions (SCAN-02/03), serves cached results for the wrong architecture (CLI-01), and reports the ASCII of a function name as its IAT slot (CHWIN-03). An agent cannot detect any of that, so hardening first would make the product more TRUSTED while it is still wrong, which is a worse outcome than the current state. That is the deliberate cost, and v0.1.1's interim depth clamp and concurrency semaphore are the hedge against it.

The second cost is that v0.2 is a 47-finding, 1-2 hour release with no tag in the middle — the largest single stretch in the plan and its main abandonment risk. I accepted that specifically to graft the losing dependency-ordered plan's best insight: Gadget has no prev and no table field, ScanOptions has no all/align/call_preceded/cancellation, post_process dedups unconditionally, and scan_binary returns a materialized Vec (all verified in source), so roughly thirty findings are edits to those declarations and one loop. Landing that shape once costs one long release; landing it release-by-release would cost four rewrites of x86_scan_anchor and four parity re-litigations. If v0.2 must be split for morale or schedule, split it at the loader/formatter boundary and tag a v0.2.0-rc — do NOT split the keystone workstream itself, which is the one change that genuinely cannot be landed in pieces without leaving the sink API half-migrated.

The third cost is that chain generation, arguably the project's most interesting differentiator, spends four releases warning-gated as experimental. That is deliberate: CHWIN-01/02/03/07 each independently break the chain, all four survived a 31-assertion test suite that only checked word kinds, and fixing them before the emulator harness exists would just produce a fifth undetected variant. The fourth is that the performance gap a user is most likely to notice is closed by retraction in 1 hour one and by engineering only in month seven — but a slow correct answer harms nobody, while a false speed headline harms trust every day it stands.
