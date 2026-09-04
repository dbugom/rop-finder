//! rop-finder — ROPgadget-compatible CLI library.
//!
//! Phase 1: ELF, PE, Mach-O, Universal/fat Mach-O, and raw blobs; all
//! supported architectures. Format dispatch mirrors ROPgadget's
//! `binary.py`: `--rawArch` forces the raw loader regardless of magic
//! bytes; otherwise magic-byte dispatch via `rf_core::Binary::load`.
//! Universal (fat Mach-O) binaries follow ROPgadget's `universal.py`:
//! every slice's executable regions are concatenated and scanned with the
//! FIRST slice's arch/mode/endianness (universal.py:92-108 returns
//! "whatever is in the first binary").
//!
//! Phase 2 (PLAN.md §6.3/§6.4):
//!   * `--section <glob>` — restrict the scan to named executable sections
//!     (repeatable, comma-separated, `*` globbing).
//!   * `--base <hex>` — rebase the image at load time (rf-core `rebase`).
//!   * `--info` — dump image metadata as JSON without scanning.
//!
//! Phase 3 (PLAN.md §6.1): the scan orchestration (`ScanRequest` →
//! [`scan_bytes`] / [`info_bytes`]) is library API so the `rf-mcp` MCP
//! server reuses it without shelling out to the CLI. Since v1.0 that
//! orchestration lives in the `rf-api` LIBRARY crate and is re-exported
//! here unchanged (ENG-08/ECO-10): `rf-mcp` depends on `rf-api`, never on
//! this binary crate. What is left in this file is the CLI itself — the
//! clap surface, the output formats, the scan cache's key and directory,
//! and `main_entry`.
//!
//! Exit codes: 0 success, 1 usage error, 2 malformed/unsupported binary.

use std::process::ExitCode;

mod console;
mod format;
mod out;
mod search;

use clap::Parser;
use rf_core::{Arch, Endianness, Image};
use rf_scan::{Gadget, ScanOptions};

/// The shared request layer, re-exported so that `rf_cli::ScanRequest` and
/// `rf_api::ScanRequest` stay one type and every existing `use rf_cli::…`
/// keeps compiling. The definitions live in `rf-api`.
pub use rf_api::*;

/// `--version` body (CLAIM-10). clap prints `"rop-finder "` in front of
/// it, so the first line completes the usual `name version` line and the
/// rest is the provenance a bug report needs.
///
/// The capstone version is the one the process is actually linked against,
/// asked of the library at runtime — PLAN.md:262 names capstone drift the
/// project's #1 residual parity risk, and a version reprinted from a
/// Cargo.toml pin would not detect the drift it is supposed to record.
///
/// No Cargo.lock hash is printed. Computing one honestly needs a build
/// script hashing a file that does not exist in a packaged crate or in a
/// `cargo install` build, and a hash that is silently absent or wrong is
/// worse than no hash; the lockfile is committed instead (ENG-02).
///
/// Returned as `&'static str` (built once in a `OnceLock`) because clap's
/// `long_version` only accepts a borrowed string unless the `string`
/// feature is enabled workspace-wide.
fn long_version() -> &'static str {
    static LONG_VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    LONG_VERSION.get_or_init(|| {
        format!(
            "{ver}\n\
             Written by {authors}.\n\
             \n\
             capstone {cs} (bundled; decodes ARM, ARM64, MIPS, PPC, SPARC, RISC-V)\n\
             iced-x86 (decodes x86/x64)\n\
             \n\
             A port of ROPgadget by Jonathan Salwan, Alexey Vishnyakov and \
             contributors (BSD-3-Clause):\n\
             https://github.com/JonathanSalwan/ROPgadget",
            ver = env!("CARGO_PKG_VERSION"),
            // From `authors` in the workspace manifest, so the binary and the
            // crates.io metadata cannot disagree. Cargo joins multiple authors
            // with ':'. This credits the author of the Rust work; it does NOT
            // replace the ROPgadget line below, which credits the upstream
            // project this is a port of and is required by its licence (ENG-03).
            authors = env!("CARGO_PKG_AUTHORS").replace(':', ", "),
            cs = rf_scan::capstone_version(),
        )
    })
}

#[derive(Parser, Debug)]
#[command(
    name = "rop-finder",
    version,
    long_version = long_version(),
    disable_version_flag = true,
    about = "Fast Rust ROP/JOP/SYS gadget finder (ROPgadget rewrite)"
)]
pub struct Cli {
    /// Display the version, the linked capstone build and the ROPgadget
    /// attribution, and exit 0
    ///
    /// CLI-12: ROPgadget spells this `-v`/`--version` (args.py:75) and
    /// rop-finder bound only clap's automatic `-V`, so every ROPgadget
    /// script that starts with a `-v` capability probe died on
    /// "unexpected argument '-v' found". Both shorts are bound here; the
    /// text deliberately still differs from the oracle's four-line block,
    /// because CLAIM-10 requires the linked capstone version to be in it.
    #[arg(
        short = 'v',
        short_alias = 'V',
        long = "version",
        action = clap::ArgAction::Version
    )]
    pub version: Option<bool>,

    /// Specify a binary filename to analyze (optional with --console)
    #[arg(long)]
    pub binary: Option<String>,

    /// Depth for search engine (default 10)
    #[arg(long, default_value_t = 10)]
    pub depth: usize,

    /// Disable ROP search engine
    #[arg(long)]
    pub norop: bool,

    /// Disable JOP search engine
    #[arg(long)]
    pub nojop: bool,

    /// Disable SYS search engine
    #[arg(long)]
    pub nosys: bool,

    /// Enable multiple branch gadgets
    #[arg(long)]
    pub multibr: bool,

    /// Only show specific instructions (e.g. "pop|ret|mov")
    #[arg(long)]
    pub only: Option<String>,

    /// Suppress gadgets containing a matching mnemonic. A `|`-separated
    /// regex alternation, FULL-matched against each mnemonic as ROPgadget
    /// does (e.g. "leave|enter", "j.*"). Not a suffix match: "op" matches
    /// no mnemonic and so filters nothing, it does not remove `pop`
    #[arg(long)]
    pub filter: Option<String>,

    /// Search between two addresses (0x...-0x...)
    #[arg(long)]
    pub range: Option<String>,

    /// Rejects specific bytes in the gadget's FINAL address, after --base
    /// rebase and --offset (e.g. "0a|0d" or "00-1f")
    #[arg(long)]
    pub badbytes: Option<String>,

    /// Specify an offset ADDED to gadget addresses after any --base rebase
    /// (hex)
    #[arg(long)]
    pub offset: Option<String>,

    /// Rebase the binary to this image base at load time, before scanning
    /// and before --offset is applied (hex). Use 0 for RVA-style addresses
    #[arg(long)]
    pub base: Option<String>,

    /// Dump image metadata (format/arch/sections/imports) as JSON and exit
    /// without scanning
    #[arg(long)]
    pub info: bool,

    /// Generate a ROP chain; default output is the Python exploit script,
    /// with --json the JSON Chain IR. Target selection via --chain
    #[arg(long)]
    pub ropchain: bool,

    /// Machine-readable feasibility report for the --chain target instead
    /// of a chain: which requirements this binary meets, which it does not,
    /// what was tried, and which parameter changes would help (measured, by
    /// re-scanning). Always succeeds; always JSON (ECO-04)
    #[arg(long)]
    pub plan_chain: bool,

    /// Chain target for --ropchain / --plan-chain: linux-execve (default),
    /// linux-mprotect, linux-syscall, linux-ret2libc, linux-srop (ELF
    /// x86/x64) or windows-virtualprotect (PE x86/x64)
    #[arg(long, default_value = "linux-execve")]
    pub chain: String,

    /// Syscall number for --chain linux-syscall, and the syscall the
    /// linux-srop frame invokes (decimal, or hex with 0x)
    #[arg(long, value_name = "<n>")]
    pub syscall: Option<String>,

    /// Argument registers for --chain linux-syscall / linux-srop, e.g.
    /// "rdi=0x404000,rsi=0x1000,rdx=7" (hex values)
    #[arg(long, value_name = "<reg=val,...>")]
    pub syscall_args: Option<String>,

    /// Pivot the stack pointer to this address before the chain body runs
    /// (hex). The emitted chain is then in two pieces: the leading
    /// `pivot_words` go at the overflow point, the rest go here (CHWIN-08).
    /// Spelled `--chain-pivot` because `--pivot` is the v0.4 gadget-query
    /// preset (ECO-12) and taking that name would silently change what an
    /// existing command means
    #[arg(long = "chain-pivot", value_name = "<addr>")]
    pub chain_pivot: Option<String>,

    /// Shellcode bytes (hex, e.g. "9090cc") for windows-virtualprotect to
    /// WRITE into the region at --shellcode-addr with write-what-where
    /// gadgets, instead of assuming it is already there (CHWIN-08)
    #[arg(long, value_name = "<hex>")]
    pub stage: Option<String>,

    /// Runtime address of the target API for windows-virtualprotect (hex),
    /// or the function linux-ret2libc calls. Primary resolution path;
    /// without it a PE must import the API (IAT dereference). A
    /// comma-separated list supplies one address per --api-name
    #[arg(long)]
    pub api_addr: Option<String>,

    /// API windows-virtualprotect targets: VirtualProtect (default) or
    /// VirtualAlloc. Selects the IAT import to resolve AND the argument
    /// recipe — the two do not take the same four arguments (CHWIN-06).
    /// A comma-separated list composes several calls into one chain, each
    /// returning into the next through a stack-adjust gadget (CHWIN-08)
    #[arg(long)]
    pub api_name: Option<String>,

    /// What the windows-virtualprotect x64 alignment invariant may assume
    /// about the chain's first word: return-address (default, the chain
    /// overwrites a saved return address, so its base is 8 mod 16) or
    /// aligned (the base is 16-byte aligned)
    #[arg(long)]
    pub chain_base: Option<String>,

    /// Protection constant (hex). For windows-virtualprotect it is
    /// flNewProtect / flProtect and defaults to 0x40 =
    /// PAGE_EXECUTE_READWRITE; for linux-mprotect it is mprotect's `prot`
    /// and defaults to 7 = PROT_READ|PROT_WRITE|PROT_EXEC. The default
    /// follows the target because the two constant spaces are unrelated
    #[arg(long)]
    pub prot: Option<String>,

    /// Runtime address the shellcode will occupy for windows-virtualprotect
    /// (hex; default: the binary's writable .data section)
    #[arg(long)]
    pub shellcode_addr: Option<String>,

    /// dwSize argument for windows-virtualprotect (hex; default 0x1000)
    #[arg(long)]
    pub shellcode_size: Option<String>,

    /// CFG/CET-aware scan: keep only gadgets whose entry is an
    /// endbr64/endbr32 instruction (x86/x64)
    #[arg(long)]
    pub cfg_aware: bool,

    /// Scan only the named executable section(s); repeatable and
    /// comma-separated, `*` globbing allowed (e.g. --section .text or
    /// --section ".init*,.plt")
    #[arg(long = "section", value_delimiter = ',')]
    pub section: Vec<String>,

    /// Use the thumb mode for the search engine (ARM only)
    #[arg(long)]
    pub thumb: bool,

    /// Specify an arch for a raw file: x86|arm|arm64|sparc|mips|ppc|riscv
    #[arg(long = "rawArch", value_name = "<arch>")]
    pub raw_arch: Option<String>,

    /// Specify a mode for a raw file: 32|64|arm|thumb|riscv
    #[arg(long = "rawMode", value_name = "<mode>")]
    pub raw_mode: Option<String>,

    /// Specify an endianness for a raw file: little|big
    #[arg(long = "rawEndian", value_name = "<endian>")]
    pub raw_endian: Option<String>,

    /// Emit a JSON array of {vaddr, bytes, text} instead of human output
    #[arg(long)]
    pub json: bool,

    /// Semantic classification (Phase 5): --json gadget records gain
    /// class/labels/regs_written/regs_read/side_effects/quality fields.
    /// Rules live in TAXONOMY.md; no effect without --json
    #[arg(long)]
    pub classify: bool,

    /// Rank gadgets by quality score (best first, ties by address);
    /// applies to both human and JSON output
    #[arg(long)]
    pub rank: bool,

    /// Keep only gadgets whose primary class is one of these
    /// (comma-separated): reg-write, stack-pivot, mem-read, mem-write,
    /// arithmetic, syscall, dispatcher, other. Implies --classify's
    /// analysis; add --classify to see the fields in --json output
    /// (CLS-08 — the MCP server has the same filter)
    #[arg(long = "class", value_name = "<class[,class...]>")]
    pub class: Option<String>,

    /// Keep only gadgets carrying at least one of these labels (same
    /// vocabulary as --class; a gadget can earn several)
    #[arg(long = "label", value_name = "<label[,label...]>")]
    pub label: Option<String>,

    /// Keep only gadgets that write ALL of these registers
    /// (comma-separated, e.g. rdi or rdi,rsi). Names are matched
    /// lowercase and without a $/% sigil
    #[arg(long = "writes-reg", value_name = "<reg[,reg...]>")]
    pub writes_reg: Option<String>,

    // -- ECO-01 / ECO-12: the constraint query layer (v0.4) ---------------
    // Every flag below is one `find_gadgets_by_effect` parameter of the
    // same name in snake_case. See crates/rf-cli/src/query.rs.
    /// Keep only gadgets that WRITE these registers with a value the chain
    /// payload decides (rf_classify `sets`, full-width architectural names:
    /// rdi not edi on x64, x0 not w0 on ARM64)
    #[arg(long = "set-reg", value_name = "<reg[,reg...]>")]
    pub set_reg: Option<String>,

    /// Require the write to ORIGINATE in a pop or a stack-pointer-relative
    /// load rather than an arbitrary computation ("xor rdi, rdi" sets rdi
    /// but does not take it from the stack). Narrows --set-reg, or
    /// --writes-reg, or — with neither — means "some register comes off
    /// the payload"
    #[arg(long = "from-stack")]
    pub from_stack: bool,

    /// Reject gadgets that CLOBBER any of these registers (comma-separated).
    /// Clobber is the rf_classify partition, not regs_written: a register
    /// written with a payload-controlled value is a `set`, not a clobber
    #[arg(long = "no-clobber", value_name = "<reg[,reg...]>")]
    pub no_clobber: Option<String>,

    /// Keep only gadgets that READ ALL of these registers (comma-separated) — as an operand, an
    /// address component, a transfer dependency or the terminator's target
    #[arg(long = "reads-reg", value_name = "<reg[,reg...]>")]
    pub reads_reg: Option<String>,

    /// Keep only gadgets whose stack pointer moves at most N bytes
    /// (terminator included). A gadget whose rsp effect is not provably
    /// constant reports "unknown" and is REJECTED, never treated as 0
    #[arg(
        long = "max-stack-delta",
        value_name = "<n>",
        allow_negative_numbers = true
    )]
    pub max_stack_delta: Option<i64>,

    /// Keep only gadgets with at most N side effects (TAXONOMY.md R11)
    #[arg(long = "max-side-effects", value_name = "<n>")]
    pub max_side_effects: Option<usize>,

    /// Keep only gadgets with at most N instructions (the terminator counts)
    #[arg(long = "max-insns", value_name = "<n>")]
    pub max_insns: Option<usize>,

    /// Keep only gadgets with this terminator; comma-separated, any-of.
    /// Coarse: ret|jmp|call|syscall|none|any. Fine (CLS-09): bare-ret|
    /// ret-imm|jmp-reg|jmp-mem|call-reg|call-mem|far|other. Coarse "ret"
    /// includes ret imm16/retf/iret; "bare-ret" is the plain near return
    /// only; "any" is no constraint. Same 13 values as the MCP
    /// `terminator` parameter
    #[arg(long = "terminator", value_name = "<kind[,kind...]>")]
    pub terminator: Option<String>,

    /// Ropper-style gadget-sequence search, e.g. "pop rdi; ret". Matches a
    /// CONTIGUOUS run of instructions; `?` is any one character and `%` any
    /// run of characters within one instruction. Not --re, which is
    /// ROPgadget's per-instruction regex conjunction
    #[arg(long = "search", value_name = "<pattern>")]
    pub search: Option<String>,

    /// Stack-pivot preset (ECO-12): exactly --label stack-pivot
    #[arg(long)]
    pub pivot: bool,

    // -- ECO-09: output formats ------------------------------------------
    /// Output format: human (default), json, jsonl, csv, raw. `jsonl`
    /// STREAMS — records are written during the scan, in scan order rather
    /// than the alphabetical order of the other formats. `raw` is the
    /// undecorated listing; with --noinstr it is the address-only mode
    #[arg(long = "format", value_name = "<fmt>")]
    pub format: Option<String>,

    /// --ropchain output: python (default), json, or raw (the packed
    /// little-endian chain payload, written to stdout as BYTES)
    #[arg(long = "chain-format", value_name = "<fmt>")]
    pub chain_format: Option<String>,

    /// Cache scan results on disk, keyed by the binary's content hash plus
    /// all scan parameters. Cache directory: ROP_FINDER_CACHE_DIR, else
    /// %LOCALAPPDATA%/rop-finder/cache (Windows) or ~/.cache/rop-finder
    #[arg(long)]
    pub cache: bool,

    /// Delete every entry in the scan cache directory and exit. Needs no
    /// --binary. Size cap and lifetime are ROP_FINDER_CACHE_MAX_BYTES
    /// (default 512 MiB) and ROP_FINDER_CACHE_TTL_SECS (default 14 days)
    #[arg(long)]
    pub cache_purge: bool,

    /// Search a string (byte regex, e.g. "m..n") in readable (data)
    /// sections instead of gadget scanning
    #[arg(long)]
    pub string: Option<String>,

    /// Search an opcode byte sequence (hex, e.g. c9c3) in executable
    /// sections instead of gadget scanning
    #[arg(long)]
    pub opcode: Option<String>,

    /// Search the first occurrence of each byte of the string across all
    /// readable sections instead of gadget scanning
    #[arg(long)]
    pub memstr: Option<String>,

    /// Regular expression over gadget instructions; every |-separated
    /// pattern must match at least one instruction (options.py:64-98)
    #[arg(long)]
    pub re: Option<String>,

    /// Only show gadgets immediately preceded by a call instruction
    /// (x86/x64; options.py:100-120 heuristic)
    #[arg(long = "callPreceded")]
    pub call_preceded: bool,

    /// Disable the gadget instruction printing: bare addresses, no dedup,
    /// no sort
    #[arg(long)]
    pub noinstr: bool,

    /// Append the gadget bytes to human output (" // hexbytes")
    #[arg(long)]
    pub dump: bool,

    /// Suppress gadget printing during analysis (the callPreceded filter
    /// line still prints, as in ROPgadget)
    #[arg(long)]
    pub silent: bool,

    /// Align gadget addresses (overrides anchor stepping alignment, in
    /// bytes; 0 = no alignment constraint)
    #[arg(long)]
    pub align: Option<usize>,

    /// MIPS useful-gadget finder: stackfinder|system|tails|lia0|registers
    #[arg(long)]
    pub mipsrop: Option<String>,

    /// Disable duplicate-gadget removal
    #[arg(long)]
    pub all: bool,

    /// Interactive console (REPL) for the search engine; with --binary the
    /// binary is preloaded
    #[arg(long)]
    pub console: bool,

    /// Architecture slice to scan in a fat (Universal) Mach-O, e.g.
    /// x86_64, arm64, i386. REQUIRED for a multi-slice file: without it
    /// rop-finder refuses rather than concatenating slices whose virtual
    /// address ranges overlap (CORE-03)
    #[arg(long, value_name = "<slice>")]
    pub arch: Option<String>,

    /// Refuse input files larger than this many bytes; accepts a K/M/G
    /// suffix. Non-regular files (devices, FIFOs, directories) are always
    /// refused (ROB-06)
    #[arg(long = "max-file-size", value_name = "<bytes>", default_value = "512M")]
    pub max_file_size: String,

    /// Stop the scan once this many gadgets have been accepted, and report
    /// the budget instead of a truncated listing (PERF-05)
    #[arg(long = "max-gadgets", value_name = "<n>")]
    pub max_gadgets: Option<usize>,

    /// Stop the scan once the retained gadgets are estimated to exceed this
    /// many heap bytes; accepts a K/M/G suffix (PERF-05)
    #[arg(long = "max-memory", value_name = "<bytes>")]
    pub max_memory: Option<String>,

    /// Bug-for-bug ROPgadget compatibility where rop-finder deliberately
    /// differs (CLI-11). Exactly two things. (1) A fat (Universal) Mach-O
    /// with no --arch is scanned as ROPgadget scans it — every slice's
    /// executable regions concatenated and disassembled with the FIRST
    /// slice's decoder — instead of being refused; the output is then
    /// knowingly part-fabricated and a warning says so. (2) --string and
    /// --memstr read a section's DECLARED file extent (elf.py:332) rather
    /// than the bytes it really owns, which resurrects the oracle's
    /// SHT_NOBITS phantom hits. It does NOT change gadget text or layout
    #[arg(long)]
    pub compat: bool,
}

/// ROPgadget's raw-loader argument validation (args.py:114-128) and the
/// raw.py arch/mode/endian mapping, resolved to the rf-core contract.
/// Returns (arch, endianness, thumb) when a raw load was requested.
fn parse_raw_spec(cli: &Cli) -> Result<Option<(Arch, Endianness, bool)>, String> {
    if cli.thumb && cli.raw_mode.is_some() && cli.raw_mode.as_deref() != Some("thumb") {
        return Err("--rawMode is conflicting with --thumb".to_string());
    }
    if cli.raw_arch.is_none() && cli.raw_mode.is_some() {
        return Err("Specify --rawArch".to_string());
    }
    if cli.raw_arch.is_none() && cli.raw_endian.is_some() {
        return Err("Specify --rawArch".to_string());
    }
    let Some(arch_s) = cli.raw_arch.as_deref() else {
        return Ok(None);
    };
    // args.py:123 — --thumb implies rawMode=thumb.
    let mode_s = if cli.thumb {
        Some("thumb")
    } else {
        cli.raw_mode.as_deref()
    };
    let Some(mode_s) = mode_s else {
        return Err("Specify --rawMode".to_string());
    };
    if !["32", "64", "arm", "thumb", "riscv"].contains(&mode_s) {
        return Err(format!(
            "invalid --rawMode {mode_s:?} (32|64|arm|thumb|riscv)"
        ));
    }
    // args.py:128 — the flag that is missing here is --rawEndian, not
    // --rawArch (which the `let Some(arch_s)` above has already proved
    // present). CLI-13: this message was a copy-paste of the two guards
    // above and named the wrong flag.
    if cli.raw_endian.is_none() && arch_s != "x86" {
        return Err("Specify --rawEndian".to_string());
    }
    let endian = match cli.raw_endian.as_deref() {
        None | Some("little") => Endianness::Little,
        Some("big") => Endianness::Big,
        Some(e) => return Err(format!("invalid --rawEndian {e:?} (little|big)")),
    };
    // raw.py:71-72 — x86 is always little-endian.
    let endian = if arch_s == "x86" {
        Endianness::Little
    } else {
        endian
    };
    // raw.py mode/endian interplay with gadgets.py's per-arch mode
    // overrides: arm64 always lands in CS_MODE_ARM, sparc in mode 0, riscv
    // in RV64|RISCVC regardless of the requested 32/64 (gadgets.py:178,
    // 191, 202), so those accept any listed mode.
    let (arch, thumb) = match (arch_s, mode_s) {
        ("x86", "32") => (Arch::X86, false),
        ("x86", "64") => (Arch::X64, false),
        ("arm", "thumb") => (Arch::ArmThumb, true),
        ("arm", _) => (Arch::Arm, false),
        ("arm64", _) => (Arch::Arm64, false),
        ("sparc", _) => (Arch::Sparc, false),
        ("mips", "32") => (Arch::Mips32, false),
        ("mips", "64") => (Arch::Mips64, false),
        ("ppc", "32") => (Arch::Ppc32, false),
        ("ppc", "64") => (Arch::Ppc64, false),
        ("riscv", _) => (Arch::RiscV64, false),
        (a, m) => {
            return Err(format!(
                "unsupported --rawArch {a:?} / --rawMode {m:?} combination"
            ))
        }
    };
    Ok(Some((arch, endian, thumb)))
}

/// options.py:22-33 — the post-scan gadget filters in oracle order: --re
/// first, then --callPreceded. The "Filtered out" line prints even under
/// --silent because Options runs inside __getGadgets, before the looking
/// function's silent check.
///
/// `json` redirects that line to STDERR. ROPgadget has no --json, so there is
/// no oracle behaviour to copy here, and a progress line on stdout ahead of
/// the array makes `--json` unparseable — `--callPreceded --json` emitted
/// `Options().removeNonCallPreceded(): ...` followed by the JSON and every
/// consumer (the parity harness included) failed to decode it. Human output
/// is byte-for-byte unchanged, so the --compat diff against the oracle is
/// unaffected.
fn apply_post_filters(
    gadgets: &mut Vec<Gadget>,
    re: &Option<String>,
    call_preceded: bool,
    arch: Arch,
    json: bool,
    out: &mut dyn std::io::Write,
) -> Result<(), String> {
    if let Some(re) = re {
        search::apply_re_filter(gadgets, re)?;
    }
    if call_preceded {
        let line = if matches!(arch, Arch::X86 | Arch::X64) {
            let before = gadgets.len();
            gadgets.retain(|g| g.prev.as_deref().is_some_and(search::is_call_preceded));
            format!(
                "Options().removeNonCallPreceded(): Filtered out {} gadgets.",
                before - gadgets.len()
            )
        } else {
            "Options().removeNonCallPreceded(): Unsupported architecture.".to_string()
        };
        if json {
            eprintln!("{line}");
        } else {
            let _ = writeln!(out, "{line}");
        }
    }
    Ok(())
}

/// Every byte of stdout goes through `out` — one buffered, locked writer
/// owned by [`main_entry`] (PERF-07), which also decides what a write
/// failure means for the exit code (ROB-03). There is deliberately no
/// `println!` left on any path reachable from here: it would take the
/// stdout lock again and interleave ahead of what is still buffered.
fn run(cli: Cli, out: &mut dyn std::io::Write) -> Result<i32, String> {
    // Error precedence mirrors the pre-refactor CLI exactly: depth → file
    // read → raw spec → option parsing → binary load → (--info | --base →
    // --section → scan).
    if cli.depth < 2 {
        return Err("--depth must be >= 2".to_string());
    }
    // args.py:108-112 cross-flag validation.
    if cli.noinstr && cli.only.is_some() {
        return Err("--noinstr and --only=<key> can't be used together".to_string());
    }
    if cli.noinstr && cli.re.is_some() {
        return Err("--noinstr and --re=<re> can't be used together".to_string());
    }
    // --cache-purge is maintenance, not analysis: it runs before the
    // "a binary is required" gate so `rop-finder --cache-purge` works on
    // its own (CLI-08/PERF-12).
    if cli.cache_purge {
        return Ok(run_cache_purge(out));
    }
    // args.py:142-143: a binary is required unless the console is requested.
    if cli.binary.is_none() && !cli.console {
        return Err("Need a binary filename (--binary/--console or --help)".to_string());
    }

    // ECO-09. Parsed here, before any work, so `--format yaml` costs a
    // message rather than a scan.
    let (out_format, chain_format) = resolve_formats(&cli)?;
    // ECO-01: one predicate, built once, applied by both the streaming and
    // the buffered path.
    let q = query::Query::parse(&query::QuerySpec {
        class: cli.class.as_deref(),
        label: cli.label.as_deref(),
        writes_reg: cli.writes_reg.as_deref(),
        set_reg: cli.set_reg.as_deref(),
        from_stack: cli.from_stack,
        no_clobber: cli.no_clobber.as_deref(),
        reads_reg: cli.reads_reg.as_deref(),
        max_stack_delta: cli.max_stack_delta,
        max_side_effects: cli.max_side_effects,
        max_insns: cli.max_insns,
        terminator: cli.terminator.as_deref(),
        search: cli.search.as_deref(),
        pivot: cli.pivot,
    })?;

    // --console: interactive REPL (binary optional, preloaded when given).
    if cli.console {
        return console::run_console(&cli, out);
    }

    let binary = cli.binary.as_deref().unwrap();
    // ROB-06: stat before allocating. `--binary /dev/zero` now errors in
    // milliseconds instead of consuming the machine.
    let max_file_size = parse_size(&cli.max_file_size, "--max-file-size")?;
    let bytes = read_input_file(binary, max_file_size)?;
    let raw = parse_raw_spec(&cli)?;

    let max_memory = cli
        .max_memory
        .as_deref()
        .map(|m| parse_size(m, "--max-memory"))
        .transpose()?
        .map(|m| m as usize);

    let req = ScanRequest {
        depth: cli.depth,
        rop: !cli.norop,
        jop: !cli.nojop,
        sys: !cli.nosys,
        multibr: cli.multibr,
        only: cli.only.clone(),
        filter: cli.filter.clone(),
        range: cli.range.clone(),
        badbytes: cli.badbytes.clone(),
        offset: cli.offset.clone(),
        base: cli.base.clone(),
        section: cli.section.clone(),
        thumb: cli.thumb,
        cfg_aware: cli.cfg_aware,
        align: cli.align,
        call_preceded: cli.call_preceded,
        all: cli.all,
        noinstr: cli.noinstr,
        arch: cli.arch.clone(),
        max_gadgets: cli.max_gadgets,
        max_memory,
        compat: cli.compat,
    };
    let opts = match request_options(&req, raw) {
        Ok(o) => o,
        Err(ScanError::Usage(e)) => return Err(e),
        Err(ScanError::Binary(e) | ScanError::Chain(e)) => return Err(e), // unreachable
    };
    let target = match load_target(&bytes, raw) {
        Ok(t) => t,
        Err(ScanError::Binary(e)) => {
            eprintln!("[Error] {e}");
            return Ok(2);
        }
        Err(ScanError::Usage(e) | ScanError::Chain(e)) => return Err(e), // unreachable
    };

    // --info: metadata only, no scanning. --base is honoured.
    if cli.info {
        let new_base = cli
            .base
            .as_deref()
            .map(|b| parse_hex(b, "--base"))
            .transpose()?;
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&info_json(&target, new_base)).unwrap()
        );
        return Ok(0);
    }

    // --ropchain: chain generation (--chain selects the target). Unlike
    // ROPgadget, which dumps the gadget list and step logs first, we print
    // only the exploit script (or the JSON Chain IR with --json).
    if cli.ropchain || cli.plan_chain {
        // CHWIN-09: warn before doing the work, not after printing a
        // chain that looks authoritative.
        if let Some(warning) = chain_experimental_warning(&cli.chain) {
            eprint!("{warning}");
        }
        let spec = ChainSpec {
            target: cli.chain.clone(),
            api_addr: cli.api_addr.clone(),
            api_name: cli.api_name.clone(),
            shellcode_addr: cli.shellcode_addr.clone(),
            shellcode_size: cli.shellcode_size.clone(),
            chain_base: cli.chain_base.clone(),
            prot: cli.prot.clone(),
            syscall: cli.syscall.clone(),
            syscall_args: cli.syscall_args.clone(),
            pivot: cli.chain_pivot.clone(),
            stage: cli.stage.clone(),
        };
        // ECO-04: `--plan-chain` ALWAYS succeeds. Infeasibility is a
        // result, and it is the same document `--ropchain --json` prints
        // when it has to refuse, so an agent parses one shape either way.
        if cli.plan_chain {
            let outcome = match plan_chain_bytes(&bytes, raw, &req, &spec) {
                Ok(o) => o,
                Err(ScanError::Usage(e)) | Err(ScanError::Chain(e)) => return Err(e),
                Err(ScanError::Binary(e)) => {
                    eprintln!("[Error] {e}");
                    return Ok(2);
                }
            };
            let _ = writeln!(out, "{}", plan_json(&outcome));
            return Ok(0);
        }
        let outcome = match chain_bytes(&bytes, raw, &req, &spec) {
            Ok(o) => o,
            Err(ScanError::Usage(e)) | Err(ScanError::Chain(e)) => {
                // ECO-04: on the JSON surface a refusal is a DOCUMENT, not
                // a sentence. `--ropchain --json` that cannot build prints
                // the same ChainPlan `--plan-chain` prints (feasible:false,
                // with the requirement that failed), and still exits
                // non-zero. The human/python surface is untouched.
                if chain_format == format::ChainFormat::Json {
                    if let Ok(o) = plan_chain_bytes(&bytes, raw, &req, &spec) {
                        let _ = writeln!(out, "{}", plan_json(&o));
                    }
                }
                return Err(e);
            }
            Err(ScanError::Binary(e)) => {
                eprintln!("[Error] {e}");
                return Ok(2);
            }
        };
        if outcome.outcome.fallback_names {
            eprintln!(
                "[Warning] binary has no section names (stripped ELF?);                  executable segments are named PT_LOAD#n"
            );
        }
        match chain_format {
            format::ChainFormat::Json => {
                let _ = writeln!(out, "{}", chain_json(&outcome));
            }
            // ECO-09 part 2: MANUAL.md has advertised "raw bytes" chain
            // output since v0.1 and `RopChain::to_bytes` was called only
            // from unit tests. These are real bytes, not a hex dump —
            // redirect them into a file or a harness's stdin.
            format::ChainFormat::Raw => {
                let _ = out.write_all(&outcome.chain.to_bytes());
            }
            format::ChainFormat::Python => {
                let _ = write!(out, "{}", outcome.chain.to_python());
            }
        }
        return Ok(0);
    }

    let orig_base = target_base(&target);
    let base = cli
        .base
        .as_deref()
        .map(|b| parse_hex(b, "--base"))
        .transpose()?;
    let prepared = match prepare_view(&target, base, &cli.section, cli.arch.as_deref(), cli.compat)
    {
        Ok(v) => v,
        Err(ScanError::Usage(e)) => return Err(e),
        Err(ScanError::Binary(e) | ScanError::Chain(e)) => return Err(e), // unreachable
    };
    let view = prepared.view;
    if prepared.fallback_names {
        eprintln!(
            "[Warning] binary has no section names (stripped ELF?); \
             executable segments are named PT_LOAD#n"
        );
    }
    for w in scan_warnings(&target, &view, cli.cfg_aware, cli.compat) {
        eprintln!("{w}");
    }
    let universal_arch = view.universal.then_some(view.arch());

    // core.py:248-261 dispatch order: console → string → opcode → memstr
    // → mipsrop → gadget scan. Search modes ignore --section (the oracle
    // has no --section); --base/--offset/--range apply.
    if cli.string.is_some() || cli.opcode.is_some() || cli.memstr.is_some() {
        if cli.silent {
            return Ok(0); // core.py:163-164 etc.: search modes print nothing
        }
        let delta = view.base.wrapping_sub(orig_base);
        let width8 = search::search_width8(&target, view.arch());
        // --compat: search the raw file extent a section DECLARES rather
        // than the content it really owns, reproducing the oracle's
        // SHT_NOBITS read (see search::compat_bytes).
        let compat_file = cli.compat.then_some(bytes.as_slice());
        if let Some(s) = &cli.string {
            let hits =
                search::find_string(&target, delta, opts.offset, opts.range, s, compat_file)?;
            if out_format.is_structured() {
                let v = search::search_json_string(&hits, width8);
                print_hit_records(&v, search::STRING_COLUMNS, out_format, out);
            } else {
                search::print_string_hits(&hits, width8, out);
            }
        } else if let Some(op) = &cli.opcode {
            let hits = search::find_opcode(&target, delta, opts.offset, opts.range, op)?;
            if out_format.is_structured() {
                let v = search::search_json_opcode(&hits, op, width8);
                print_hit_records(&v, search::OPCODE_COLUMNS, out_format, out);
            } else {
                search::print_opcode_hits(&hits, op, width8, out);
            }
        } else if let Some(m) = &cli.memstr {
            let hits = search::find_memstr(&target, delta, opts.offset, opts.range, m, compat_file);
            if out_format.is_structured() {
                let v = search::search_json_memstr(&hits, width8);
                print_hit_records(&v, search::MEMSTR_COLUMNS, out_format, out);
            } else {
                search::print_memstr_hits(&hits, width8, out);
            }
        }
        return Ok(0);
    }

    let do_scan = |view: &RegionView, opts: &ScanOptions| -> Result<Vec<Gadget>, i32> {
        match run_scan_engine(view, opts) {
            Ok(g) => Ok(g),
            Err(e) => {
                // Scan-time Unsupported errors (e.g. capstone mode) and
                // exhausted --max-gadgets/--max-memory budgets are
                // binary-level failures, like ROPgadget's loader errors.
                eprintln!("[Error] {e}");
                Err(2)
            }
        }
    };
    // Opened once, before the closure, so a cache that cannot be trusted
    // reports itself exactly once per run.
    let cache = if cli.cache {
        let opened = open_cache();
        if opened.is_none() && cache_dir().is_none() {
            eprintln!("[Cache] no cache directory (set ROP_FINDER_CACHE_DIR); scanning");
        }
        opened
    } else {
        None
    };
    // Gadget acquisition, shared by the --mipsrop and normal paths.
    let acquire = || -> Result<Vec<Gadget>, i32> {
        let Some(cache) = &cache else {
            return do_scan(&view, &opts);
        };
        let key = cache_key(&bytes, &opts, &CacheIdentity::of(&cli, base));
        // `load` authenticates and validates; a tampered or corrupt entry
        // is a warning plus a miss, never a served result (CLI-07, ROB-04).
        if let Some(g) = cache
            .load(&key)
            .as_ref()
            .and_then(rf_cache::CachedScan::to_scan_gadgets)
        {
            eprintln!(
                "[Cache] hit {} ({} gadgets)",
                rf_cache::key_prefix(&key),
                g.len()
            );
            return Ok(g);
        }
        let g = do_scan(&view, &opts)?;
        match cache.store(&key, &rf_cache::CachedScan::from_scan_gadgets(&g)) {
            Ok(()) => eprintln!(
                "[Cache] miss {} — stored {} gadgets",
                rf_cache::key_prefix(&key),
                g.len()
            ),
            Err(e) => eprintln!(
                "[Cache] miss {} — store failed: {e}",
                rf_cache::key_prefix(&key)
            ),
        }
        Ok(g)
    };

    // --mipsrop (core.py:118-157): silent check first, then the mode
    // check, then the header — all BEFORE the gadget scan.
    if let Some(mode) = &cli.mipsrop {
        if cli.silent {
            return Ok(0);
        }
        let Some(regexes) = search::compile_mips_regexes(mode) else {
            let _ = writeln!(out, "Unrecognized option {mode}");
            let _ = writeln!(
                out,
                "Accepted options stackfinder|system|tails|lia0|registers"
            );
            return Ok(1); // analyze() -> False -> exit 1
        };
        let _ = writeln!(out, "MIPS ROP ({mode})");
        let _ = writeln!(out, "{}", search::RULE60);
        let mut gadgets = match acquire() {
            Ok(g) => g,
            Err(c) => return Ok(c),
        };
        apply_post_filters(
            &mut gadgets,
            &cli.re,
            cli.call_preceded,
            view.arch(),
            out_format != format::OutFormat::Human,
            out,
        )?;
        search::print_mips_gadgets(
            &gadgets,
            &regexes,
            cli.dump,
            search::search_width8(&target, view.arch()),
            out,
        );
        return Ok(0);
    }

    // ECO-09: the streaming path. Chosen BEFORE `acquire()`, because the
    // whole point is that no `Vec<Gadget>` is ever built.
    if format::can_stream(out_format, cli.rank, cli.cache, false) && !cli.silent {
        let re = cli
            .re
            .as_deref()
            .map(search::ReFilter::compile)
            .transpose()?;
        // apply_post_filters() only applies --callPreceded on x86/x64 and
        // prints "Unsupported architecture." otherwise; the same rule here.
        let cp_supported = matches!(view.arch(), Arch::X86 | Arch::X64);
        let classifier =
            (cli.classify || !q.is_empty()).then(|| rf_classify::Classifier::new(view.arch()));
        let mut sink = format::JsonlSink::new(
            out,
            &opts,
            view.addr_size(),
            format::RecordCtx {
                addr_size: view.addr_size(),
                offset: opts.offset,
                universal_arch,
                selected_sections: prepared.selected_sections.as_deref(),
                classify: cli.classify,
            },
            format::GadgetFilters {
                re: re.as_ref(),
                call_preceded: cli.call_preceded && cp_supported,
                query: &q,
                classify: classifier.as_ref(),
            },
        );
        if let Err(e) = rf_scan::scan_binary_into(&view, &opts, &mut sink) {
            // Records already written cannot be unwritten, so a budget hit
            // leaves a partial stream on stdout plus this line on stderr and
            // exit 2 - the same exit code the buffered path uses, which is
            // what a script actually checks.
            eprintln!("[Error] {}", scan_error_message(e));
            return Ok(2);
        }
        // The oracle prints this line before the listing; a streamed
        // listing has no "before", and it is a count over the whole run.
        // It goes to stderr so the JSONL stream stays parseable, which is
        // where the --json path already sent it.
        if cli.call_preceded {
            if cp_supported {
                eprintln!(
                    "Options().removeNonCallPreceded(): Filtered out {} gadgets.",
                    sink.call_preceded_dropped()
                );
            } else {
                eprintln!("Options().removeNonCallPreceded(): Unsupported architecture.");
            }
        }
        return Ok(0);
    }

    let mut gadgets = match acquire() {
        Ok(g) => g,
        Err(c) => return Ok(c),
    };
    // options.py:22-33 — --re then --callPreceded, after the scan.
    apply_post_filters(
        &mut gadgets,
        &cli.re,
        cli.call_preceded,
        view.arch(),
        out_format != format::OutFormat::Human,
        out,
    )?;
    let mut classes: Option<Vec<rf_classify::Classification>> = None;
    // CLS-08 + ECO-01/ECO-12: the classification is computed for every
    // gadget and was only ever *printed* before v0.3. The `--class` /
    // `--label` / `--writes-reg` filters made it queryable; the v0.4
    // constraint flags ask the question a practitioner actually has. Same
    // predicate, same names, as the MCP `find_gadgets_by_effect` tool.
    if cli.classify || cli.rank || !q.is_empty() {
        let (g, c) = classify_gadgets(gadgets, view.arch(), cli.rank);
        gadgets = g;
        classes = Some(c);
    }
    if let Some(cs) = classes.as_mut() {
        if !q.is_empty() {
            let keep: Vec<bool> = gadgets
                .iter()
                .zip(cs.iter())
                .map(|(g, c)| {
                    let text = g.text();
                    q.matches(c, &text.split(" ; ").collect::<Vec<_>>())
                })
                .collect();
            let mut it = keep.iter();
            gadgets.retain(|_| *it.next().unwrap_or(&true));
            let mut it = keep.iter();
            cs.retain(|_| *it.next().unwrap_or(&true));
        }
    }
    let result = ScanResult {
        gadgets,
        addr_size: view.addr_size(),
        universal_arch,
        selected_sections: prepared.selected_sections,
    };

    // core.py:103-104 — --silent suppresses all gadget output (the
    // callPreceded filter line above still printed, as in the oracle).
    if cli.silent {
        return Ok(0);
    }
    // --rank alone reorders but does not add classification fields.
    let classes = classes.as_deref().filter(|_| cli.classify);
    print_result(&result, opts.offset, classes, out_format, &cli, out);
    Ok(0)
}

/// ECO-09: resolve `--format` / `--chain-format`, reconciling them with the
/// older `--json` boolean.
///
/// `--json` predates both and cannot be removed — it is in the manual, in
/// the MCP allowlist and in every existing script — so it stays as the
/// spelling of `--format json` (and, under `--ropchain`, of
/// `--chain-format json`). Asking for two different things at once is a
/// usage error rather than a silent precedence rule, because a script that
/// says `--json --format csv` has a bug either way and a quiet winner would
/// hide it.
fn resolve_formats(cli: &Cli) -> Result<(format::OutFormat, format::ChainFormat), String> {
    let out = match cli.format.as_deref() {
        Some(f) => {
            let f = format::OutFormat::parse(f).ok_or_else(|| {
                format!(
                    "invalid --format {f:?}; valid values are {}",
                    format::OutFormat::ALL.join(", ")
                )
            })?;
            if cli.json && f != format::OutFormat::Json {
                return Err(format!(
                    "--json and --format {} conflict; --json means --format json",
                    f.name()
                ));
            }
            f
        }
        None if cli.json => format::OutFormat::Json,
        None => format::OutFormat::Human,
    };
    let chain = match cli.chain_format.as_deref() {
        Some(f) => {
            let f = format::ChainFormat::parse(f).ok_or_else(|| {
                format!(
                    "invalid --chain-format {f:?}; valid values are {}",
                    format::ChainFormat::ALL.join(", ")
                )
            })?;
            if cli.json && f != format::ChainFormat::Json {
                return Err(
                    "--json and --chain-format conflict; --json means --chain-format json"
                        .to_string(),
                );
            }
            f
        }
        None if cli.json => format::ChainFormat::Json,
        None => format::ChainFormat::Python,
    };
    Ok((out, chain))
}

/// Render a search-mode hit list (`--string` / `--opcode` / `--memstr`) in
/// one of the structured formats. `cols` fixes the CSV column order.
fn print_hit_records(
    hits: &serde_json::Value,
    cols: &[&str],
    fmt: format::OutFormat,
    out: &mut dyn std::io::Write,
) {
    let empty = Vec::new();
    let rows = hits.as_array().unwrap_or(&empty);
    match fmt {
        format::OutFormat::Jsonl => {
            for r in rows {
                let _ = writeln!(out, "{r}");
            }
        }
        format::OutFormat::Csv => {
            let _ = writeln!(out, "{}", cols.join(","));
            for r in rows {
                let cells: Vec<String> = cols
                    .iter()
                    .map(|c| match &r[*c] {
                        serde_json::Value::Null => String::new(),
                        serde_json::Value::String(s) => s.clone(),
                        v => v.to_string(),
                    })
                    .collect();
                let _ = writeln!(out, "{}", format::csv_join(&cells));
            }
        }
        // Serialization of this simple structure cannot fail.
        _ => {
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(hits).unwrap());
        }
    }
}

/// The buffered gadget listing, in whichever `--format` was asked for.
fn print_result(
    res: &ScanResult,
    offset: u64,
    classes: Option<&[rf_classify::Classification]>,
    fmt: format::OutFormat,
    cli: &Cli,
    out: &mut dyn std::io::Write,
) {
    let ctx = format::RecordCtx {
        addr_size: res.addr_size,
        offset,
        universal_arch: res.universal_arch,
        selected_sections: res.selected_sections.as_deref(),
        classify: cli.classify,
    };
    let rec = |i: usize| format::record(&res.gadgets[i], classes.map(|cs| &cs[i]), &ctx);
    match fmt {
        format::OutFormat::Human => print_human(res, cli.noinstr, cli.dump, out),
        format::OutFormat::Json => {
            let all: Vec<_> = (0..res.gadgets.len()).map(rec).collect();
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&all).unwrap());
        }
        // The same records the streaming path emits; reached only when
        // `--rank`/`--cache` forced the buffered path.
        format::OutFormat::Jsonl => {
            for i in 0..res.gadgets.len() {
                if let Ok(line) = serde_json::to_string(&rec(i)) {
                    let _ = writeln!(out, "{line}");
                }
            }
        }
        format::OutFormat::Csv => {
            let _ = writeln!(out, "{}", format::CSV_HEADER);
            for i in 0..res.gadgets.len() {
                let _ = writeln!(out, "{}", format::csv_row(&rec(i)));
            }
        }
        format::OutFormat::Raw => {
            for g in &res.gadgets {
                let _ = writeln!(
                    out,
                    "{}",
                    format::raw_line(g, res.addr_size, cli.noinstr, cli.dump)
                );
            }
        }
    }
}

/// Phase 5: classify every gadget and, when `rank` is set, sort by
/// quality descending with vaddr-ascending tie-break (TAXONOMY.md R12).
fn classify_gadgets(
    gadgets: Vec<Gadget>,
    arch: Arch,
    rank: bool,
) -> (Vec<Gadget>, Vec<rf_classify::Classification>) {
    let mut pairs: Vec<(Gadget, rf_classify::Classification)> = gadgets
        .into_iter()
        .map(|g| {
            let c = rf_classify::classify(&g, arch);
            (g, c)
        })
        .collect();
    if rank {
        pairs.sort_by(|(ga, ca), (gb, cb)| {
            cb.quality.cmp(&ca.quality).then(ga.vaddr.cmp(&gb.vaddr))
        });
    }
    pairs.into_iter().unzip()
}

/// core.py:99-116 `__lookingForGadgets`. With --noinstr the gadget dicts
/// carry no text, so the line is the bare address (core.py:110-111);
/// --dump appends " // hexbytes" (core.py:112).
///
/// CLI-11: `noinstr` used to be ignored here on the theory that a
/// --noinstr scan produced gadgets with empty `insns`. It does not — the
/// v0.2.0 engine keeps the disassembly and lets --noinstr mean only "skip
/// dedup and skip the alphabetical sort" (`core.py:87,94`), because
/// `--filter`/`--badbytes` still have to look at the instructions. The
/// oracle drops the text at PRINT time (`gadgets.py:117` never stores
/// `g["gadget"]`, and `core.py:110-111` then formats an empty `insts`), so
/// the suppression belongs here. Without this, every --noinstr line
/// carried a ` : <text>` the oracle does not print: 68,386 of 68,390 lines
/// differed on elf-Linux-x86.
fn print_human(res: &ScanResult, noinstr: bool, dump: bool, out: &mut dyn std::io::Write) {
    let _ = writeln!(out, "Gadgets information");
    let _ = writeln!(out, "{}", search::RULE60);
    for g in &res.gadgets {
        let text = if noinstr { String::new() } else { g.text() };
        let insts = if text.is_empty() {
            String::new()
        } else {
            format!(" : {text}")
        };
        let bytes_str = if dump {
            format!(" // {}", g.bytes_hex())
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "{}{}{}",
            fmt_addr(g.vaddr, res.addr_size),
            insts,
            bytes_str
        );
    }
    let _ = writeln!(out, "\nUnique gadgets found: {}", res.gadgets.len());
}

/// The `--format json` record list. Kept as a named function because the
/// crate's tests assert on the *typed* record rather than on parsed JSON.
#[cfg(test)]
fn to_json(res: &ScanResult, offset: u64) -> Vec<format::GadgetRecord<'_>> {
    to_json_classified(res, offset, None)
}

#[cfg(test)]
fn to_json_classified<'a>(
    res: &'a ScanResult,
    offset: u64,
    classes: Option<&'a [rf_classify::Classification]>,
) -> Vec<format::GadgetRecord<'a>> {
    let ctx = format::RecordCtx {
        addr_size: res.addr_size,
        offset,
        universal_arch: res.universal_arch,
        selected_sections: res.selected_sections.as_deref(),
        classify: classes.is_some(),
    };
    (0..res.gadgets.len())
        .map(|i| format::record(&res.gadgets[i], classes.map(|cs| &cs[i]), &ctx))
        .collect()
}

// ---------------------------------------------------------------------------
// Scan cache (--cache, --cache-purge).
//
// The cache itself — the key schema, the HMAC that authenticates an entry,
// the permissions, the atomic write and the LRU — lives in `rf_cache` and
// is shared byte for byte with the MCP server. That sharing IS the fix:
// the ROB-04 char-boundary panic and the ANCH-02 align post-filter each
// existed twice because there were two copies of this code. What stays
// here is only what the CLI knows and the library cannot: where the cache
// directory is, and which flags of *this* front end change the output.
// ---------------------------------------------------------------------------

/// Cache directory: ROP_FINDER_CACHE_DIR wins, else the platform default
/// (%LOCALAPPDATA%/rop-finder/cache on Windows, ~/.cache/rop-finder
/// elsewhere). None when no base directory can be determined.
fn cache_dir() -> Option<std::path::PathBuf> {
    if let Ok(d) = std::env::var("ROP_FINDER_CACHE_DIR") {
        if !d.is_empty() {
            return Some(std::path::PathBuf::from(d));
        }
    }
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(|p| std::path::PathBuf::from(p).join("rop-finder").join("cache"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(|p| {
            std::path::PathBuf::from(p)
                .join(".cache")
                .join("rop-finder")
        })
    }
}

/// Everything that changes what a scan produces and is *not* already in
/// [`ScanOptions`].
///
/// CLI-01/ENG-05 was exactly a missing member of this list: the key
/// omitted `--rawArch`/`--rawMode`/`--rawEndian`, so a cached scan was
/// served for the wrong architecture. Reproduced on
/// `tests/fixtures/raw-x86.raw`: `--rawArch x86 --rawMode 32 --cache`
/// stored 2 gadgets, and `--rawArch arm --rawMode arm --rawEndian little
/// --cache` was then served those same 2 x86 gadgets, when the true
/// answer for the ARM query is 0.
struct CacheIdentity<'a> {
    /// `--section` globs, as written.
    sections: &'a [String],
    /// `--base`, already parsed.
    base: Option<u64>,
    /// `--rawArch`/`--rawMode`/`--rawEndian`: which loader runs, and how
    /// the bytes are decoded. The CLI-01/ENG-05 omission.
    raw_arch: Option<&'a str>,
    raw_mode: Option<&'a str>,
    raw_endian: Option<&'a str>,
    /// `--arch`: which slice of a fat Mach-O is scanned (CORE-03).
    arch: Option<&'a str>,
    /// `--compat`: decides whether a multi-slice container is scanned as a
    /// concatenation or refused.
    compat: bool,
}

impl<'a> CacheIdentity<'a> {
    fn of(cli: &'a Cli, base: Option<u64>) -> Self {
        CacheIdentity {
            sections: &cli.section,
            base,
            raw_arch: cli.raw_arch.as_deref(),
            raw_mode: cli.raw_mode.as_deref(),
            raw_endian: cli.raw_endian.as_deref(),
            arch: cli.arch.as_deref(),
            compat: cli.compat,
        }
    }
}

/// Cache key: the binary's content hash plus **every** parameter that can
/// change the output.
///
/// `parallel` is the one deliberate omission — rayon scheduling cannot
/// change the result — and `cancel` is not a parameter. Everything else
/// goes in: the engine options wave 2A added (`align`, `all`, `noinstr`,
/// `call_preceded`, `filter_re`), the loader identity above, and the
/// `--max-gadgets`/`--max-memory` budgets, which *truncate* a result and
/// so must never let a bounded scan be served for an unbounded query.
/// [`rf_cache::make_key`] folds in the key-schema version, so the next
/// time this list grows the old entries miss instead of mismatching.
fn cache_key(bytes: &[u8], opts: &ScanOptions, id: &CacheIdentity<'_>) -> String {
    let params = format!(
        "depth={}|rop={}|jop={}|sys={}|multibr={}|only={:?}|filter={:?}|\
         filter_re={:?}|range={:?}|badbytes={:?}|offset={}|thumb={}|cfg_aware={}|\
         align={:?}|call_preceded={}|all={}|noinstr={}|max_gadgets={:?}|\
         max_memory={:?}|sections={:?}|base={:?}|raw_arch={:?}|raw_mode={:?}|\
         raw_endian={:?}|arch={:?}|compat={}",
        opts.depth,
        opts.rop,
        opts.jop,
        opts.sys,
        opts.multibr,
        opts.only,
        opts.filter,
        opts.filter_re.as_ref().map(regex::Regex::as_str),
        opts.range,
        opts.badbytes,
        opts.offset,
        opts.thumb,
        opts.cfg_aware,
        opts.align,
        opts.call_preceded,
        opts.all,
        opts.noinstr,
        opts.max_gadgets,
        opts.max_memory,
        id.sections,
        id.base,
        id.raw_arch,
        id.raw_mode,
        id.raw_endian,
        id.arch,
        id.compat,
    );
    rf_cache::make_key(&rf_cache::sha256_hex(bytes), &params)
}

/// ROB-04. This was `&s[i..i + 2]` — a byte-range slice of a `&str` —
/// and it is reachable from `--opcode`, not only from the cache:
/// `rop-finder --binary <elf> --opcode "€€"` aborted the process with
/// `byte index 2 is not a char boundary; it is inside '€'`. The shared
/// decoder works over `as_bytes()` and checks the alphabet itself.
///
/// `usize::MAX` because `--opcode` has never had a length limit and this
/// change is about the panic, not about adding one; the *record* fields
/// that an attacker controls are capped in `rf_cache` instead.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    rf_cache::decode_hex(s, usize::MAX)
}

/// Open the on-disk cache, or say on stderr why there is none.
///
/// CLI-07/MCP-04: when the directory or its key file cannot be trusted,
/// the cache is *disabled*. It never degrades to unauthenticated reads —
/// that fallback is the finding.
fn open_cache() -> Option<rf_cache::DiskCache> {
    let dir = cache_dir()?;
    match rf_cache::DiskCache::open(&dir, rf_cache::CacheLimits::from_env()) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("[Cache] disabled: {e}");
            None
        }
    }
}

/// `--cache-purge` (CLI-08/PERF-12): empty the cache directory and exit.
/// Before this the only way to reclaim the 5.3 MB per scan configuration
/// the cache accumulated in `~/.cache/rop-finder` was `rm -rf`, and the
/// user had to know the path.
fn run_cache_purge(out: &mut dyn std::io::Write) -> i32 {
    let Some(dir) = cache_dir() else {
        eprintln!("[Cache] no cache directory (set ROP_FINDER_CACHE_DIR); nothing to purge");
        return 0;
    };
    let cache = match rf_cache::DiskCache::open(&dir, rf_cache::CacheLimits::from_env()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "[Error] cannot open the cache directory {}: {e}",
                dir.display()
            );
            return 2;
        }
    };
    match cache.purge() {
        Ok((files, bytes)) => {
            let _ = writeln!(
                out,
                "Purged {files} cache {} ({bytes} bytes) from {}",
                if files == 1 { "entry" } else { "entries" },
                dir.display()
            );
            0
        }
        Err(e) => {
            eprintln!("[Error] cache purge failed: {e}");
            2
        }
    }
}

/// CHWIN-09. The Windows VirtualProtect builder emits a chain that does
/// not execute (CHWIN-01/02/03); until v0.5 fixes it, saying so out loud —
/// on stderr, so a piped `--ropchain > exploit.py` still gets a clean
/// script and the human still gets the warning — is the honest gate.
/// Returns the warning for a target that has one, `None` otherwise.
fn chain_experimental_warning(target: &str) -> Option<&'static str> {
    (target == "windows-virtualprotect").then_some(
        "[Warning] --chain windows-virtualprotect is EXPERIMENTAL: the chain it emits \
         executes under this project's emulator (tests/emulate.py), not on Windows.\n\
         [Warning] The four layout defects this warning used to name — CHWIN-01, \
         CHWIN-02, CHWIN-03, CHWIN-07 — are fixed in v0.5, each with a failing-before \
         and a passing-after run recorded in docs/chain-regressions.md.\n\
         [Warning] What the emulator cannot check is still yours: that --api-addr is \
         the runtime address, that rsp really is --chain-base mod 16 at entry, and that \
         CFG/CET is not enforced on the target.\n",
    )
}

/// clap signals `--help` and `--version` as an `Err` whose `exit_code()`
/// is 0: they are successful terminations, not usage errors. CLI-06 /
/// ENG-06 — the old blanket `ExitCode::from(1)` broke the project's own
/// build script (`set -e` + a final `rop-finder --version`), Homebrew and
/// dpkg post-install smoke tests, and every CI step that checks a tool is
/// runnable. ROPgadget exits 0 for both.
fn clap_exit_code(kind: clap::error::ErrorKind) -> u8 {
    use clap::error::ErrorKind as K;
    match kind {
        K::DisplayHelp | K::DisplayVersion | K::DisplayHelpOnMissingArgumentOrSubcommand => 0,
        // MANUAL's documented contract: 1 is the usage error (clap's own 2
        // is deliberately not adopted).
        _ => 1,
    }
}

pub fn main_entry() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let code = clap_exit_code(e.kind());
            // clap writes help/version to stdout and errors to stderr.
            let _ = e.print();
            return ExitCode::from(code);
        }
    };
    // One buffered, locked stdout for the whole run (PERF-07), whose first
    // I/O error decides the exit code instead of panicking (ROB-03).
    let mut out = out::StdOut::stdout();
    let code = match run(cli, &mut out) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("[Error] {msg}");
            1
        }
    };
    match out.finish() {
        Ok(()) => ExitCode::from(code as u8),
        // A run that already failed keeps its own exit code; a run that
        // succeeded into a closed pipe ends at 0, like every other text
        // tool, rather than at 101 with a panic message.
        Err(e) => match out::exit_code_for(&e) {
            Ok(pipe_code) => ExitCode::from(if code == 0 { pipe_code } else { code } as u8),
            Err(msg) => {
                eprintln!("[Error] {msg}");
                ExitCode::from(1)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Loader types the moved-out library layer no longer needs at the crate
    // root, but the CLI's own tests still construct directly.
    use rf_core::{Binary, LoadedBinary, RawBinary, Section};

    fn cli_with(
        thumb: bool,
        raw_arch: Option<&str>,
        raw_mode: Option<&str>,
        raw_endian: Option<&str>,
    ) -> Cli {
        Cli {
            binary: Some("x".into()),
            depth: 10,
            norop: false,
            nojop: false,
            nosys: false,
            multibr: false,
            // v0.4 (ECO-01/ECO-09): the constraint query and output
            // formats. All absent = the v0.3 behaviour, unchanged.
            version: None,
            set_reg: None,
            from_stack: false,
            no_clobber: None,
            reads_reg: None,
            max_stack_delta: None,
            max_side_effects: None,
            max_insns: None,
            terminator: None,
            search: None,
            pivot: false,
            format: None,
            chain_format: None,
            // CLS-08's three semantic filters; None = unfiltered.
            class: None,
            label: None,
            writes_reg: None,
            only: None,
            filter: None,
            range: None,
            badbytes: None,
            offset: None,
            base: None,
            info: false,
            ropchain: false,
            plan_chain: false,
            syscall: None,
            syscall_args: None,
            chain_pivot: None,
            stage: None,
            chain: "linux-execve".into(),
            api_addr: None,
            api_name: None,
            shellcode_addr: None,
            shellcode_size: None,
            chain_base: None,
            prot: None,
            cfg_aware: false,
            section: Vec::new(),
            thumb,
            raw_arch: raw_arch.map(Into::into),
            raw_mode: raw_mode.map(Into::into),
            raw_endian: raw_endian.map(Into::into),
            json: false,
            classify: false,
            rank: false,
            cache: false,
            cache_purge: false,
            string: None,
            opcode: None,
            memstr: None,
            re: None,
            call_preceded: false,
            noinstr: false,
            dump: false,
            silent: false,
            align: None,
            mipsrop: None,
            all: false,
            console: false,
            arch: None,
            max_file_size: "512M".to_string(),
            max_gadgets: None,
            max_memory: None,
            compat: false,
        }
    }

    fn fixture_bytes(name: &str) -> Vec<u8> {
        std::fs::read(format!(
            "{}/../../tests/fixtures/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn load_target(bytes: &[u8]) -> Target {
        match Binary::load(bytes).unwrap() {
            LoadedBinary::Elf(b) => Target::Elf(b),
            LoadedBinary::Pe(b) => Target::Pe(b),
            LoadedBinary::MachO(b) => Target::MachO(b),
            LoadedBinary::Raw(b) => Target::Raw(b),
            LoadedBinary::Universal(u) => Target::Universal(u),
        }
    }

    fn default_opts() -> ScanOptions {
        ScanOptions {
            depth: 10,
            rop: true,
            jop: true,
            sys: true,
            multibr: false,
            only: None,
            range: None,
            badbytes: Vec::new(),
            filter: Vec::new(),
            offset: 0,
            thumb: false,
            cfg_aware: false,
            align: None,
            call_preceded: false,
            all: false,
            noinstr: false,
            parallel: true,
            ..ScanOptions::default()
        }
    }

    /// Scan `fixture` with the given view mutations; returns (view, gadgets).
    fn scan_fixture(
        fixture: &str,
        base: Option<u64>,
        sections: &[&str],
        configure: impl Fn(&mut ScanOptions),
    ) -> (RegionView, Vec<Gadget>) {
        let bytes = fixture_bytes(fixture);
        let target = load_target(&bytes);
        let mut view = build_view(&target);
        if let Some(b) = base {
            view.rebase(b);
        }
        if !sections.is_empty() {
            let pats: Vec<String> = sections.iter().map(|s| s.to_string()).collect();
            let (secs, _) = select_sections(&view.named_exec, &pats).unwrap();
            view.regions = secs;
        }
        let mut opts = default_opts();
        configure(&mut opts);
        let gadgets = rf_scan::scan_binary(&view, &opts).unwrap();
        (view, gadgets)
    }

    fn make_section(name: &str, vaddr: u64, size: u64) -> Section {
        Section {
            name: name.to_string(),
            vaddr,
            offset: 0,
            size,
            bytes: vec![0u8; size as usize],
            executable: true,
            writable: false,
            allocated: true,
        }
    }

    /// vaddr of the dedup-stable bare "ret" gadget (traversal order is
    /// base-invariant, so the survivor is the same gadget across rebases).
    fn bare_ret_vaddr(gadgets: &[Gadget]) -> Option<u64> {
        gadgets.iter().find(|g| g.text() == "ret").map(|g| g.vaddr)
    }

    fn scan_result_for(fixture: &str, depth: usize) -> (RegionView, ScanResult) {
        let (view, gadgets) = scan_fixture(fixture, None, &[], |o| o.depth = depth);
        let res = ScanResult {
            gadgets,
            addr_size: view.addr_size(),
            universal_arch: None,
            selected_sections: None,
        };
        (view, res)
    }

    /// Unique temp directory per test (parallel cargo test safe); removed
    /// on drop.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "rf-cli-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cache_roundtrip_and_key_sensitivity() {
        let (view, res) = scan_result_for("elf-Linux-x64", 4);
        let bytes = fixture_bytes("elf-Linux-x64");
        let mut opts = default_opts();
        opts.depth = 4;
        let dir = TempDir::new("cache");
        let cache = rf_cache::DiskCache::open(&dir.0, rf_cache::CacheLimits::default()).unwrap();

        let plain_cli = cli_with(false, None, None, None);
        let id = CacheIdentity::of(&plain_cli, None);
        let key = cache_key(&bytes, &opts, &id);
        assert!(cache.load(&key).is_none(), "cold cache misses");
        cache
            .store(&key, &rf_cache::CachedScan::from_scan_gadgets(&res.gadgets))
            .unwrap();
        let loaded = cache
            .load(&key)
            .and_then(|s| s.to_scan_gadgets())
            .expect("warm cache hits");
        assert_eq!(loaded.len(), res.gadgets.len());
        for (a, b) in loaded.iter().zip(res.gadgets.iter()) {
            assert_eq!(a.vaddr, b.vaddr);
            assert_eq!(a.bytes, b.bytes);
            assert_eq!(a.insns, b.insns);
            assert_eq!(a.delay_slot, b.delay_slot);
            assert_eq!(a.prev, b.prev);
        }

        // Same inputs → same key (determinism).
        assert_eq!(key, cache_key(&bytes, &opts, &id));
        // ':' would be an invalid Windows file name; keys must avoid it.
        assert!(!key.contains(':'));
        drop(view);
    }

    /// CLI-01/ENG-05 and the wave-2A engine options: every parameter that
    /// can change the output has to move the key. Each `assert_ne!` below
    /// that names a raw-loader flag, an align/all/noinstr/callPreceded
    /// flag or a budget fails against the pre-v0.2 key, which hashed
    /// eighteen fields and none of these.
    #[test]
    fn cache_key_covers_every_output_affecting_parameter() {
        let bytes = fixture_bytes("elf-Linux-x64");
        let base_cli = cli_with(false, None, None, None);
        let opts = default_opts();
        let key = cache_key(&bytes, &opts, &CacheIdentity::of(&base_cli, None));

        // ScanOptions half.
        let with = |mutate: &dyn Fn(&mut ScanOptions), what: &str| {
            let mut o = default_opts();
            mutate(&mut o);
            assert_ne!(
                key,
                cache_key(&bytes, &o, &CacheIdentity::of(&base_cli, None)),
                "{what} must be part of the cache key"
            );
        };
        with(&|o| o.depth = 11, "--depth");
        with(&|o| o.rop = !o.rop, "--norop");
        with(&|o| o.jop = !o.jop, "--nojop");
        with(&|o| o.sys = !o.sys, "--nosys");
        with(&|o| o.multibr = true, "--multibr");
        with(&|o| o.only = Some(vec!["pop".into()]), "--only");
        with(&|o| o.filter = vec!["pop".into()], "--filter");
        with(&|o| o.range = Some((0x1000, 0x2000)), "--range");
        with(&|o| o.badbytes = vec![0x0a], "--badbytes");
        with(&|o| o.offset = 0x10, "--offset");
        with(&|o| o.thumb = true, "--thumb");
        with(&|o| o.cfg_aware = true, "--cfg-aware");
        with(&|o| o.align = Some(4), "--align");
        with(&|o| o.call_preceded = true, "--callPreceded");
        with(&|o| o.all = true, "--all");
        with(&|o| o.noinstr = true, "--noinstr");
        with(&|o| o.max_gadgets = Some(10), "--max-gadgets");
        with(&|o| o.max_memory = Some(1 << 20), "--max-memory");
        with(
            &|o| o.filter_re = Some(regex::Regex::new("pop").unwrap()),
            "a compiled --filter regex",
        );
        // `parallel` is the deliberate exception: it cannot change output.
        let mut par = default_opts();
        par.parallel = !par.parallel;
        assert_eq!(
            key,
            cache_key(&bytes, &par, &CacheIdentity::of(&base_cli, None)),
            "--parallel is output-identical and must NOT split the cache"
        );

        // CacheIdentity half.
        let sections = vec![".text".to_string()];
        let raw_x86 = cli_with(false, Some("x86"), Some("32"), None);
        let raw_arm = cli_with(false, Some("arm"), Some("arm"), Some("little"));
        let ids: Vec<(CacheIdentity<'_>, &str)> = vec![
            (
                CacheIdentity {
                    sections: &sections,
                    ..CacheIdentity::of(&base_cli, None)
                },
                "--section",
            ),
            (CacheIdentity::of(&base_cli, Some(0x40_0000)), "--base"),
            (CacheIdentity::of(&raw_x86, None), "--rawArch/--rawMode"),
            (CacheIdentity::of(&raw_arm, None), "--rawEndian"),
            (
                CacheIdentity {
                    arch: Some("arm64"),
                    ..CacheIdentity::of(&base_cli, None)
                },
                "--arch",
            ),
            (
                CacheIdentity {
                    compat: true,
                    ..CacheIdentity::of(&base_cli, None)
                },
                "--compat",
            ),
        ];
        for (id, what) in &ids {
            assert_ne!(
                key,
                cache_key(&bytes, &opts, id),
                "{what} must be part of the cache key"
            );
        }
        // ...and the raw specs differ from EACH OTHER, not just from "none".
        let x86 = cache_key(&bytes, &opts, &CacheIdentity::of(&raw_x86, None));
        let arm = cache_key(&bytes, &opts, &CacheIdentity::of(&raw_arm, None));
        assert_ne!(x86, arm, "--rawArch x86 and arm are different scans");

        // File content, obviously.
        assert_ne!(
            key,
            cache_key(
                b"not the same binary",
                &opts,
                &CacheIdentity::of(&base_cli, None)
            )
        );
    }

    /// Serializes the tests that set `ROP_FINDER_CACHE_DIR`, which is
    /// process-global.
    static CACHE_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn run_to_string(cli: Cli) -> String {
        let mut out: Vec<u8> = Vec::new();
        let code = run(cli, &mut out).expect("no usage error");
        assert_eq!(code, 0, "scan exited {code}");
        String::from_utf8(out).unwrap()
    }

    /// CLI-01/ENG-05, end to end through `run`.
    ///
    /// Against the pre-v0.2 key this fails on the first assertion: the ARM
    /// query is served the x86 entry and prints
    /// `0x00000010 : xor eax, eax ; ret`, two gadgets, where the truth for
    /// ARM is zero.
    #[test]
    fn a_cached_scan_is_never_served_across_rawarch() {
        let _guard = CACHE_ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new("rawarch");
        std::env::set_var("ROP_FINDER_CACHE_DIR", &dir.0);

        let raw = format!(
            "{}/../../tests/fixtures/raw-x86.raw",
            env!("CARGO_MANIFEST_DIR")
        );
        let mk = |arch: &str, mode: &str, endian: Option<&str>, cache: bool| Cli {
            binary: Some(raw.clone()),
            depth: 4,
            cache,
            ..cli_with(false, Some(arch), Some(mode), endian)
        };

        let x86_first = run_to_string(mk("x86", "32", None, true));
        let arm_cached = run_to_string(mk("arm", "arm", Some("little"), true));
        let arm_uncached = run_to_string(mk("arm", "arm", Some("little"), false));
        let x86_uncached = run_to_string(mk("x86", "32", None, false));
        let x86_hit = run_to_string(mk("x86", "32", None, true));

        assert_ne!(
            x86_first, arm_cached,
            "the ARM query was served the x86 cache entry"
        );
        assert_eq!(
            arm_cached, arm_uncached,
            "the ARM query must reproduce the uncached ARM run byte for byte"
        );
        assert_eq!(
            x86_hit, x86_uncached,
            "the x86 cache hit must reproduce the uncached x86 run byte for byte"
        );
        assert_eq!(x86_first, x86_hit);
        // One entry per architecture, not one shared between them.
        let entries = std::fs::read_dir(&dir.0)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rfc"))
            .count();
        assert_eq!(entries, 2, "each --rawArch needs its own entry");

        std::env::remove_var("ROP_FINDER_CACHE_DIR");
    }

    /// CLI-07 through the CLI: a fabricated entry at the deterministic
    /// file name is not printed. Before v0.2 this run printed
    /// `0xdeadbeefcafe0000 : pop rdi ; ret`.
    #[test]
    fn a_poisoned_cache_entry_is_not_printed() {
        let _guard = CACHE_ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new("poison");
        std::env::set_var("ROP_FINDER_CACHE_DIR", &dir.0);

        let cli = || Cli {
            binary: Some(format!(
                "{}/../../tests/fixtures/elf-Linux-x86",
                env!("CARGO_MANIFEST_DIR")
            )),
            depth: 3,
            cache: true,
            ..cli_with(false, None, None, None)
        };
        let genuine = run_to_string(cli());
        assert!(!genuine.contains("0xdeadbeefcafe0000"));

        // Overwrite every entry with the attacker's version, in the shape
        // the old cache accepted and in the shape the new one writes.
        let entry = std::fs::read_dir(&dir.0)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().and_then(|s| s.to_str()) == Some("rfc"))
            .expect("the miss stored an entry");
        let fabricated = br#"{"version":2,"gadgets":[{"vaddr":"0xdeadbeefcafe0000","bytes":"5fc3","text":"pop rdi ; ret","insns":["pop rdi","ret"]}]}"#;
        std::fs::write(&entry, fabricated).unwrap();
        let after_plain = run_to_string(cli());
        // ...and with the frame header, so only the tag is wrong.
        let mut framed = Vec::from(b"RFCACHE\x02".as_slice());
        framed.extend_from_slice(&[0u8; 32]);
        framed.extend_from_slice(fabricated);
        std::fs::write(&entry, &framed).unwrap();
        let after_framed = run_to_string(cli());

        for (what, out) in [("bare JSON", &after_plain), ("bad tag", &after_framed)] {
            assert!(
                !out.contains("0xdeadbeefcafe0000"),
                "{what}: a poisoned entry reached the output"
            );
            assert_eq!(out, &genuine, "{what}: the rescan reproduces the truth");
        }

        std::env::remove_var("ROP_FINDER_CACHE_DIR");
    }

    /// CLS-08 on the CLI: the classification the tool already computes is
    /// now queryable, with the same three filters the MCP server exposes.
    ///
    /// Without the flags this is the finding itself — `--classify` prints
    /// class, labels and regs_written for 16,707 gadgets and there is no
    /// way to ask for the 2,027 that are stack pivots.
    #[test]
    fn class_label_and_writes_reg_filter_the_gadget_list() {
        let base = || Cli {
            binary: Some(format!(
                "{}/../../tests/fixtures/elf-Linux-x64",
                env!("CARGO_MANIFEST_DIR")
            )),
            depth: 4,
            json: true,
            classify: true,
            ..cli_with(false, None, None, None)
        };
        let parse = |s: &str| -> Vec<serde_json::Value> { serde_json::from_str(s).unwrap() };

        let all = parse(&run_to_string(base()));
        assert!(
            all.len() > 1000,
            "{} gadgets is too few to prove anything",
            all.len()
        );

        // --class keeps only that primary class, and narrows.
        let pivots = parse(&run_to_string(Cli {
            class: Some("stack-pivot".into()),
            ..base()
        }));
        assert!(!pivots.is_empty() && pivots.len() < all.len());
        for g in &pivots {
            assert_eq!(g["class"], "stack-pivot", "{g}");
        }

        // --label is any-of over the full label set, so it is a superset
        // of the same name used as --class.
        let labelled = parse(&run_to_string(Cli {
            label: Some("stack-pivot".into()),
            ..base()
        }));
        assert!(labelled.len() >= pivots.len());
        for g in &labelled {
            assert!(
                g["labels"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|l| l == "stack-pivot"),
                "{g}"
            );
        }

        // --writes-reg is all-of, and sigil/case insensitive.
        for spelling in ["rdi", "$RDI"] {
            let writes = parse(&run_to_string(Cli {
                writes_reg: Some(spelling.into()),
                ..base()
            }));
            assert!(!writes.is_empty(), "{spelling}");
            for g in &writes {
                assert!(
                    g["regs_written"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|r| r == "rdi"),
                    "{spelling}: {g}"
                );
            }
        }
        let both = parse(&run_to_string(Cli {
            writes_reg: Some("rdi,rsi".into()),
            ..base()
        }));
        for g in &both {
            let w = g["regs_written"].as_array().unwrap();
            assert!(
                w.iter().any(|r| r == "rdi") && w.iter().any(|r| r == "rsi"),
                "{g}"
            );
        }

        // The filters compose, and an unknown value names the valid set
        // instead of leaving the user to guess.
        let combined = parse(&run_to_string(Cli {
            class: Some("reg-write".into()),
            writes_reg: Some("rdi".into()),
            ..base()
        }));
        for g in &combined {
            assert_eq!(g["class"], "reg-write", "{g}");
            assert!(g["regs_written"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "rdi"));
        }
        let err = run(
            Cli {
                class: Some("stack_pivot".into()),
                ..base()
            },
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(err.contains("--class"), "{err}");
        assert!(err.contains("stack-pivot"), "{err}");
    }

    /// The predicate itself, against classifications the classifier really
    /// produced rather than ones this test invented.
    #[test]
    fn the_semantic_predicate_matches_what_it_claims() {
        let g = |bytes: Vec<u8>, insns: &[&str]| Gadget {
            vaddr: 0x1000,
            bytes,
            insns: insns.iter().map(|s| (*s).to_string()).collect(),
            delay_slot: false,
            prev: None,
            table: rf_scan::TableKind::Rop,
        };
        let pop_rdi = rf_classify::classify(&g(vec![0x5f, 0xc3], &["pop rdi", "ret"]), Arch::X64);
        let bare_ret = rf_classify::classify(&g(vec![0xc3], &["ret"]), Arch::X64);

        let q = |spec: query::QuerySpec<'_>| query::Query::parse(&spec).unwrap();
        let pop_rdi_insns = ["pop rdi", "ret"];
        let ret_insns = ["ret"];

        let empty = q(query::QuerySpec::default());
        assert!(empty.is_empty());
        assert!(empty.matches(&pop_rdi, &pop_rdi_insns));
        assert!(empty.matches(&bare_ret, &ret_insns));

        let f = q(query::QuerySpec {
            writes_reg: Some("%RDI"),
            ..Default::default()
        });
        assert!(f.matches(&pop_rdi, &pop_rdi_insns));
        assert!(!f.matches(&bare_ret, &ret_insns));

        let f = q(query::QuerySpec {
            writes_reg: Some("rdi,rsi"),
            ..Default::default()
        });
        assert!(!f.matches(&pop_rdi, &pop_rdi_insns), "all-of, not any-of");

        assert!(query::Query::parse(&query::QuerySpec {
            class: Some("nope"),
            ..Default::default()
        })
        .is_err());
        assert!(query::Query::parse(&query::QuerySpec {
            label: Some("stack_pivot"),
            ..Default::default()
        })
        .is_err());
    }

    /// ROB-04 on the `--opcode` path, which is the same decoder and was
    /// the same panic: `--opcode "€€"` aborted with
    /// `byte index 2 is not a char boundary; it is inside '€'`.
    #[test]
    fn hex_decode_never_panics_on_non_ascii() {
        assert_eq!(hex_decode("€€"), None);
        assert_eq!(hex_decode("c3€"), None);
        assert_eq!(hex_decode("zz"), None);
        assert_eq!(hex_decode("c3"), Some(vec![0xc3]));
        let err = run(
            Cli {
                binary: Some(format!(
                    "{}/../../tests/fixtures/elf-Linux-x86",
                    env!("CARGO_MANIFEST_DIR")
                )),
                opcode: Some("€€".to_string()),
                ..cli_with(false, None, None, None)
            },
            &mut Vec::new(),
        );
        assert!(
            err.unwrap_err().contains("invalid --opcode"),
            "a bad --opcode is a usage error, not a panic"
        );
    }

    /// CLI-08/PERF-12.
    #[test]
    fn cache_purge_empties_the_directory() {
        let _guard = CACHE_ENV
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = TempDir::new("purge");
        std::env::set_var("ROP_FINDER_CACHE_DIR", &dir.0);

        let scan = Cli {
            binary: Some(format!(
                "{}/../../tests/fixtures/elf-Linux-x86",
                env!("CARGO_MANIFEST_DIR")
            )),
            depth: 3,
            cache: true,
            ..cli_with(false, None, None, None)
        };
        run_to_string(scan);
        let count = |dir: &std::path::Path| {
            std::fs::read_dir(dir)
                .unwrap()
                .flatten()
                .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rfc"))
                .count()
        };
        assert_eq!(count(&dir.0), 1);

        let report = run_to_string(Cli {
            cache_purge: true,
            binary: None,
            ..cli_with(false, None, None, None)
        });
        assert!(report.starts_with("Purged 1 cache entry ("), "{report}");
        assert_eq!(count(&dir.0), 0);

        std::env::remove_var("ROP_FINDER_CACHE_DIR");
    }

    #[test]
    fn classify_adds_json_fields() {
        let (view, res) = scan_result_for("elf-Linux-x64", 5);
        let (gadgets, classes) = classify_gadgets(res.gadgets, view.arch(), false);
        let res = ScanResult { gadgets, ..res };
        let json = to_json_classified(&res, 0, Some(&classes));
        let pop_rax = json
            .iter()
            .find(|j| j.text == "pop rax ; ret")
            .expect("fixture has pop rax ; ret");
        assert_eq!(pop_rax.class, Some("reg-write"));
        assert_eq!(pop_rax.labels.as_deref(), Some(&["reg-write"][..]));
        assert_eq!(pop_rax.regs_written.unwrap(), &["rax".to_string()]);
        assert_eq!(pop_rax.side_effects, Some(1));
        assert_eq!(pop_rax.quality, Some(100));
        assert_eq!(pop_rax.dispatcher, Some(false));
        assert_eq!(pop_rax.low_confidence, Some(false));
        // Without --classify the fields are absent from the JSON text.
        let plain = serde_json::to_string(&to_json(&res, 0)[0]).unwrap();
        assert!(!plain.contains("\"class\""));
        assert!(!plain.contains("\"quality\""));
    }

    #[test]
    fn rank_sorts_by_quality_desc_then_vaddr() {
        let (view, res) = scan_result_for("elf-Linux-x64", 5);
        let (gadgets, classes) = classify_gadgets(res.gadgets, view.arch(), true);
        assert_eq!(gadgets.len(), classes.len());
        for (gw, cw) in gadgets.windows(2).zip(classes.windows(2)) {
            let (ga, gb, ca, cb) = (&gw[0], &gw[1], &cw[0], &cw[1]);
            assert!(
                ca.quality > cb.quality || (ca.quality == cb.quality && ga.vaddr < gb.vaddr),
                "ordering violated: q{} @ {:#x} before q{} @ {:#x}",
                ca.quality,
                ga.vaddr,
                cb.quality,
                gb.vaddr
            );
        }
        // The cleanest gadgets score 100 and lead the output.
        assert_eq!(classes[0].quality, 100);
        assert!(gadgets[0].text().ends_with(" ; ret") || gadgets[0].text() == "ret");
    }

    /// CLI-06 / ENG-06: clap's help and version terminations are
    /// successes. Driven through the real parser so a clap upgrade that
    /// renamed a kind would fail here.
    #[test]
    fn help_and_version_exit_zero() {
        for args in [
            vec!["rop-finder", "--help"],
            vec!["rop-finder", "-h"],
            vec!["rop-finder", "--version"],
            vec!["rop-finder", "-V"],
        ] {
            let e = Cli::try_parse_from(&args).expect_err("clap reports these as Err");
            assert_eq!(e.exit_code(), 0, "{args:?} is a successful termination");
            assert_eq!(clap_exit_code(e.kind()), 0, "{args:?} must exit 0");
        }
        // ...and a real usage error still exits 1 (MANUAL's contract).
        let e = Cli::try_parse_from(["rop-finder", "--no-such-flag"]).unwrap_err();
        assert_eq!(clap_exit_code(e.kind()), 1);
        assert_eq!(
            clap_exit_code(clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand),
            0
        );
    }

    /// CLAIM-10: `--version` records the disassembler build and the
    /// attribution the port owes ROPgadget.
    #[test]
    fn long_version_names_capstone_and_ropgadget() {
        let v = long_version();
        assert!(v.starts_with(env!("CARGO_PKG_VERSION")), "{v}");
        assert!(
            v.contains(&format!("capstone {}", rf_scan::capstone_version())),
            "{v}"
        );
        assert!(v.contains("ROPgadget"), "{v}");
        assert!(v.contains("Jonathan Salwan"), "{v}");
        // The version is the linked library's, not a placeholder.
        assert!(v.contains("capstone 5.0"), "{v}");
        // The author of the Rust work is named, and is taken from the
        // manifest rather than typed here — a literal would drift, which is
        // exactly how the MCP server came to report version 0.1.0 for a
        // 1.0.0 build.
        assert!(v.contains("Written by "), "{v}");
        for author in env!("CARGO_PKG_AUTHORS").split(':') {
            assert!(v.contains(author), "author {author:?} missing from:\n{v}");
        }
        // Crediting the port's author must never displace the upstream
        // attribution the licence requires (ENG-03). Both, always.
        assert!(
            v.find("Written by ") < v.find("A port of ROPgadget"),
            "the author line must precede, not replace, the upstream credit:\n{v}"
        );
    }

    /// CHWIN-09: the experimental gate fires for the Windows chain and
    /// only for it.
    #[test]
    fn windows_chain_target_is_gated_by_a_warning() {
        let w = chain_experimental_warning("windows-virtualprotect")
            .expect("windows-virtualprotect must warn");
        assert!(w.contains("EXPERIMENTAL"), "{w}");
        assert!(w.contains("CHWIN-01"), "{w}");
        assert!(w.contains("CHWIN-02"), "{w}");
        assert!(w.contains("CHWIN-03"), "{w}");
        assert!(w.contains("CHWIN-07"), "{w}");
        assert!(w.contains("v0.5"), "{w}");
        // v0.5: the warning still fires, but it may no longer say the chain
        // cannot run. CHWIN-01/-02/-03/-07 are fixed and every one of them
        // has a recorded run under tests/emulate.py, so this sentence would
        // now be a false statement about the tool's own output. It is
        // asserted absent so it cannot be reinstated by a copy-paste.
        assert!(
            !w.contains("known NOT to execute"),
            "the pre-v0.5 retraction text is back: {w}"
        );
        assert!(w.contains("docs/chain-regressions.md"), "{w}");
        assert!(w.ends_with('\n'), "{w:?}");
        assert!(chain_experimental_warning("linux-execve").is_none());
    }

    #[test]
    fn badbytes_parsing() {
        assert_eq!(parse_badbytes("0a|0d").unwrap(), vec![0x0a, 0x0d]);
        // Ranges are inclusive (ropgadget/options.py:134, range(low, high+1)).
        assert_eq!(parse_badbytes("00-03|ff").unwrap(), vec![0, 1, 2, 3, 0xff]);
        assert_eq!(parse_badbytes("0a|").unwrap(), vec![0x0a]); // trailing | ok
        assert!(parse_badbytes("0x100").is_err());
        assert!(parse_badbytes("zz").is_err());
    }

    #[test]
    fn range_parsing() {
        assert_eq!(parse_range("0x0-0x0").unwrap(), None);
        assert_eq!(
            parse_range("0x1000-0x2000").unwrap(),
            Some((0x1000, 0x2000))
        );
        assert!(parse_range("0x2000-0x1000").is_err());
        assert!(parse_range("nonsense").is_err());
    }

    #[test]
    fn hex_parsing() {
        assert_eq!(parse_hex("0x41414141", "x").unwrap(), 0x41414141);
        assert_eq!(parse_hex("ff", "x").unwrap(), 0xff);
        assert!(parse_hex("0xz", "x").is_err());
    }

    #[test]
    fn raw_spec_validation_mirrors_args_py() {
        // no raw flags at all → no raw load
        assert!(parse_raw_spec(&cli_with(false, None, None, None))
            .unwrap()
            .is_none());
        // rawMode/rawEndian without rawArch
        assert!(parse_raw_spec(&cli_with(false, None, Some("32"), None)).is_err());
        assert!(parse_raw_spec(&cli_with(false, None, None, Some("big"))).is_err());
        // rawArch without mode
        assert!(parse_raw_spec(&cli_with(false, Some("x86"), None, None)).is_err());
        // rawArch non-x86 without endian. CLI-13: the message must name
        // the flag that is missing (--rawEndian), not the one already
        // given; args.py:128 says "Specify --rawEndian".
        assert_eq!(
            parse_raw_spec(&cli_with(false, Some("arm"), Some("arm"), None)).unwrap_err(),
            "Specify --rawEndian"
        );
        // ...while a genuinely missing --rawArch still says --rawArch
        // (args.py:117-121).
        assert_eq!(
            parse_raw_spec(&cli_with(false, None, None, Some("big"))).unwrap_err(),
            "Specify --rawArch"
        );
        // thumb conflicting with rawMode
        assert!(parse_raw_spec(&cli_with(true, Some("arm"), Some("arm"), Some("little"))).is_err());
        // unknown mode / arch+mode combo
        assert!(parse_raw_spec(&cli_with(false, Some("x86"), Some("v99"), None)).is_err());
        assert!(
            parse_raw_spec(&cli_with(false, Some("mips"), Some("thumb"), Some("big"))).is_err()
        );
        assert!(parse_raw_spec(&cli_with(false, Some("s390"), Some("64"), Some("big"))).is_err());
    }

    #[test]
    fn raw_spec_mapping() {
        let (a, e, t) = parse_raw_spec(&cli_with(false, Some("x86"), Some("32"), None))
            .unwrap()
            .unwrap();
        assert_eq!((a, e, t), (Arch::X86, Endianness::Little, false));
        // x86 forces little-endian even if big requested (raw.py:71-72)
        let (_, e, _) = parse_raw_spec(&cli_with(false, Some("x86"), Some("64"), Some("big")))
            .unwrap()
            .unwrap();
        assert_eq!(e, Endianness::Little);
        let (a, _, t) =
            parse_raw_spec(&cli_with(false, Some("arm"), Some("thumb"), Some("little")))
                .unwrap()
                .unwrap();
        assert_eq!((a, t), (Arch::ArmThumb, true));
        // --thumb implies rawMode=thumb (args.py:123)
        let (a, _, t) = parse_raw_spec(&cli_with(true, Some("arm"), None, Some("big")))
            .unwrap()
            .unwrap();
        assert_eq!((a, t), (Arch::ArmThumb, true));
        let (a, e, _) = parse_raw_spec(&cli_with(false, Some("mips"), Some("64"), Some("big")))
            .unwrap()
            .unwrap();
        assert_eq!((a, e), (Arch::Mips64, Endianness::Big));
        let (a, _, _) = parse_raw_spec(&cli_with(
            false,
            Some("riscv"),
            Some("riscv"),
            Some("little"),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(a, Arch::RiscV64);
    }

    // ---- Phase 2: --section selection (PLAN.md §6.3) ----

    #[test]
    fn select_sections_glob_and_fallback_flag() {
        let secs = vec![
            make_section(".init", 0x1000, 0x10),
            make_section(".plt", 0x1010, 0x20),
            make_section(".text", 0x2000, 0x100),
        ];
        // exact match
        let (m, fb) = select_sections(&secs, &[".text".to_string()]).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, ".text");
        assert!(!fb);
        // glob match
        let (m, _) = select_sections(&secs, &[".p*".to_string()]).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].name, ".plt");
        // multiple patterns
        let (m, _) = select_sections(&secs, &[".init".to_string(), ".plt".to_string()]).unwrap();
        assert_eq!(m.len(), 2);
        // zero matches → error listing available names
        let err = select_sections(&secs, &[".nope".to_string()]).unwrap_err();
        assert!(err.contains(".text"), "error lists available: {err}");
        assert!(err.contains(".plt"), "error lists available: {err}");
        // stripped-ELF fallback names detected
        let stripped = vec![
            make_section("PT_LOAD#0", 0x1000, 0x10),
            make_section("PT_LOAD#1", 0x2000, 0x20),
        ];
        let (m, fb) = select_sections(&stripped, &["PT_LOAD#*".to_string()]).unwrap();
        assert_eq!(m.len(), 2);
        assert!(fb);
        // invalid glob
        assert!(select_sections(&secs, &["[".to_string()]).is_err());
    }

    #[test]
    fn section_filter_pe_matches_default_scan() {
        // PE exec scan regions == exec sections, so --section .text must
        // reproduce the default scan exactly, with every vaddr inside .text.
        let (_, all) = scan_fixture("pe-x64-cmd-v6.1.7601", None, &[], |_| {});
        let (view, filtered) = scan_fixture("pe-x64-cmd-v6.1.7601", None, &[".text"], |_| {});
        assert!(!filtered.is_empty());
        assert_eq!(all.len(), filtered.len());
        let text = &view.named_exec.iter().find(|s| s.name == ".text").unwrap();
        for g in &filtered {
            assert!(
                g.vaddr >= text.vaddr && g.vaddr < text.vaddr + text.size,
                "gadget {:#x} outside .text",
                g.vaddr
            );
        }
    }

    #[test]
    fn section_filter_elf_multi_and_glob() {
        // ELF: exec sections (.init/.plt/.text/.fini) are a subset of the
        // PT_LOAD scan regions, so filtering narrows coverage (intended,
        // PLAN §6.3).
        let (view, plt) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[".p*"], |_| {});
        assert!(!plt.is_empty());
        let plt_sec = view.named_exec.iter().find(|s| s.name == ".plt").unwrap();
        for g in &plt {
            assert!(
                g.vaddr >= plt_sec.vaddr && g.vaddr < plt_sec.vaddr + plt_sec.size,
                "gadget {:#x} outside .plt",
                g.vaddr
            );
        }
        // comma-style multi selection (clap splits commas; here two pats)
        let (_, multi) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[".init", ".plt"], |_| {});
        let init_sec = view.named_exec.iter().find(|s| s.name == ".init").unwrap();
        assert!(multi.len() > plt.len(), ".init adds gadgets");
        for g in &multi {
            let in_plt = g.vaddr >= plt_sec.vaddr && g.vaddr < plt_sec.vaddr + plt_sec.size;
            let in_init = g.vaddr >= init_sec.vaddr && g.vaddr < init_sec.vaddr + init_sec.size;
            assert!(
                in_plt || in_init,
                "gadget {:#x} outside .init/.plt",
                g.vaddr
            );
        }
        // filtered scan finds strictly fewer gadgets than the default
        let (_, all) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[], |_| {});
        assert!(multi.len() < all.len());
    }

    #[test]
    fn section_unknown_name_is_usage_error() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let target = load_target(&bytes);
        let view = build_view(&target);
        let err = select_sections(&view.named_exec, &[".nonexistent".to_string()]).unwrap_err();
        assert!(err.contains(".text"), "lists available sections: {err}");
    }

    #[test]
    fn stripped_elf_falls_back_to_segment_names() {
        // Zero e_shoff (0x28, 8 bytes) and e_shnum (0x3c, 2 bytes) of an
        // ELF64 fixture copy — the loader must fall back to PT_LOAD#n names.
        let mut bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        assert_eq!(&bytes[0..4], b"\x7fELF");
        assert_eq!(bytes[4], 2, "fixture must be ELF64");
        bytes[0x28..0x30].fill(0);
        bytes[0x3c..0x3e].fill(0);
        let target = load_target(&bytes);
        let view = build_view(&target);
        assert!(!view.named_exec.is_empty());
        assert!(view
            .named_exec
            .iter()
            .all(|s| s.name.starts_with("PT_LOAD#")));
        let (matched, fallback) =
            select_sections(&view.named_exec, &["PT_LOAD#*".to_string()]).unwrap();
        assert!(fallback, "warning flag set for fallback names");
        assert_eq!(matched.len(), view.named_exec.len());
    }

    #[test]
    fn range_composes_with_section() {
        // --range applies to whatever regions the view exposes (here: the
        // selected .text section only).
        let (view, _) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[".text"], |_| {});
        let text = view.named_exec.iter().find(|s| s.name == ".text").unwrap();
        let mid = text.vaddr + text.size / 2;
        let (_, gadgets) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[".text"], |o| {
            o.range = Some((text.vaddr, mid));
        });
        assert!(!gadgets.is_empty());
        for g in &gadgets {
            assert!(g.vaddr >= text.vaddr && g.vaddr < mid);
        }
    }

    #[test]
    fn json_gadgets_carry_section_name() {
        let (view, gadgets) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[".plt"], |_| {});
        let res = ScanResult {
            gadgets,
            addr_size: view.addr_size(),
            universal_arch: None,
            selected_sections: Some(
                view.regions
                    .iter()
                    .map(|s| (s.name.clone(), s.vaddr, s.size))
                    .collect(),
            ),
        };
        let json = to_json(&res, 0);
        assert!(!json.is_empty());
        for g in &json {
            assert_eq!(g.section.as_deref(), Some(".plt"));
        }
        // offset is subtracted before the section lookup: with an offset
        // of 0x10 the lookup keys shift 16 bytes down, so gadgets at the
        // very start of .plt (if any) fall out; with a huge offset every
        // key lands below the section and the section is None.
        let huge = to_json(&res, 0x8000_0000);
        assert!(huge.iter().all(|g| g.section.is_none()));
    }

    // ---- Phase 2: --base hardening (PLAN.md §6.4) ----

    #[test]
    fn base_zero_pe_gives_rvas() {
        let bytes = fixture_bytes("pe-x64-cmd-v6.1.7601");
        let target = load_target(&bytes);
        let orig_base = build_view(&target).base;
        let (_, default) = scan_fixture("pe-x64-cmd-v6.1.7601", None, &[], |_| {});
        let (_, rebased) = scan_fixture("pe-x64-cmd-v6.1.7601", Some(0), &[], |_| {});
        let ret_default = bare_ret_vaddr(&default).expect("bare ret in default scan");
        let ret_base0 = bare_ret_vaddr(&rebased).expect("bare ret in base-0 scan");
        assert_eq!(ret_base0, ret_default - orig_base);
        // PLAN §6.4 review point: rebasing changes address-dependent
        // operand text, so the text SETS differ even though the traversal
        // is identical.
        let texts_default: std::collections::BTreeSet<_> =
            default.iter().map(|g| g.text()).collect();
        let texts_base0: std::collections::BTreeSet<_> = rebased.iter().map(|g| g.text()).collect();
        assert_ne!(texts_default, texts_base0);
    }

    #[test]
    fn base_shift_pie_elf() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let target = load_target(&bytes);
        let orig_base = build_view(&target).base;
        let (_, default) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[], |_| {});
        let (_, rebased) = scan_fixture("elf-x64-bash-v4.1.5.1", Some(0x55550000), &[], |_| {});
        let ret_default = bare_ret_vaddr(&default).expect("bare ret in default scan");
        let ret_shifted = bare_ret_vaddr(&rebased).expect("bare ret in rebased scan");
        assert_eq!(ret_shifted, ret_default - orig_base + 0x55550000);
    }

    #[test]
    fn badbytes_check_final_rebased_address() {
        // After --base 0x55550000 every gadget address contains byte 0x55,
        // so --badbytes 55 eliminates everything.
        let (_, filtered) = scan_fixture("elf-x64-bash-v4.1.5.1", Some(0x55550000), &[], |o| {
            o.badbytes = vec![0x55];
        });
        assert!(filtered.is_empty(), "badbytes apply after rebase");
        // Same rebase without badbytes finds gadgets.
        let (_, plain) = scan_fixture("elf-x64-bash-v4.1.5.1", Some(0x55550000), &[], |_| {});
        assert!(!plain.is_empty());
        // At the default base (0x400000-ish) 0x55 bytes are rare → gadgets
        // survive.
        let (_, default) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[], |o| {
            o.badbytes = vec![0x55];
        });
        assert!(!default.is_empty());
    }

    #[test]
    fn base_and_offset_compose() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let target = load_target(&bytes);
        let orig_base = build_view(&target).base;
        let (_, default) = scan_fixture("elf-x64-bash-v4.1.5.1", None, &[], |_| {});
        let ret_default = bare_ret_vaddr(&default).unwrap();
        // offset applies AFTER rebase: vaddr == default - orig + B + O
        let (_, composed) = scan_fixture("elf-x64-bash-v4.1.5.1", Some(0x70000000), &[], |o| {
            o.offset = 0x1000;
        });
        let ret_composed = bare_ret_vaddr(&composed).unwrap();
        assert_eq!(ret_composed, ret_default - orig_base + 0x70000000 + 0x1000);
        // Same for PE.
        let bytes = fixture_bytes("pe-x64-cmd-v6.1.7601");
        let target = load_target(&bytes);
        let orig_base = build_view(&target).base;
        let (_, default) = scan_fixture("pe-x64-cmd-v6.1.7601", None, &[], |_| {});
        let ret_default = bare_ret_vaddr(&default).unwrap();
        let (_, composed) = scan_fixture("pe-x64-cmd-v6.1.7601", Some(0x80000000), &[], |o| {
            o.offset = 0x2000;
        });
        let ret_composed = bare_ret_vaddr(&composed).unwrap();
        assert_eq!(ret_composed, ret_default - orig_base + 0x80000000 + 0x2000);
    }

    // ---- Phase 2: --info (PLAN.md §6.4) ----

    #[test]
    fn info_pe_shape() {
        let bytes = fixture_bytes("pe-x64-cmd-v6.1.7601");
        let target = load_target(&bytes);
        let Target::Pe(ref pe) = target else {
            panic!("expected PE")
        };
        let expect_base = hexs(pe.image_base());
        let info = info_json(&target, None);
        assert_eq!(info["format"], "pe");
        assert_eq!(info["arch"], "x64");
        assert_eq!(info["endianness"], "little");
        assert_eq!(info["addr_size"], 8);
        assert_eq!(info["image_base"], serde_json::json!(expect_base));
        let sections = info["sections"].as_array().unwrap();
        let text = sections
            .iter()
            .find(|s| s["name"] == ".text")
            .expect(".text section");
        assert_eq!(text["executable"], true);
        assert_eq!(text["writable"], false);
        let imports = info["imports"].as_array().unwrap();
        assert!(!imports.is_empty());
        assert!(imports.iter().any(|i| i["dll"]
            .as_str()
            .unwrap()
            .to_uppercase()
            .contains("KERNEL32")));
        assert!(imports[0]["symbol"].is_string());
        assert!(imports[0]["iat_vaddr"].as_str().unwrap().starts_with("0x"));

        // CHWIN-03: `iat_vaddr` is the IAT slot the loader patches, NOT the
        // IMAGE_IMPORT_BY_NAME record. Measured out of this fixture by hand:
        // image_base 0x4ad00000, IAT directory RVA 0x29000, so
        // msvcrt.dll!memset sits at slot 0x4ad29000 with its hint/name
        // record at 0x4ad2af40 (which is what --info used to print).
        let memset = imports
            .iter()
            .find(|i| {
                i["dll"]
                    .as_str()
                    .unwrap()
                    .eq_ignore_ascii_case("msvcrt.dll")
                    && i["symbol"] == "memset"
            })
            .expect("msvcrt.dll!memset");
        assert_eq!(memset["iat_vaddr"], "0x4ad29000");
        assert_eq!(memset["hint_name_vaddr"], "0x4ad2af40");
        for i in imports {
            assert_ne!(
                i["iat_vaddr"], i["hint_name_vaddr"],
                "{i} — the IAT slot must not be the hint/name record"
            );
        }
    }

    /// CHWIN-03: `--base` slides both import addresses by the same delta.
    #[test]
    fn info_pe_imports_honour_base() {
        let bytes = fixture_bytes("pe-x64-cmd-v6.1.7601");
        let target = load_target(&bytes);
        let info = info_json(&target, Some(0));
        let memset = info["imports"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| {
                i["dll"]
                    .as_str()
                    .unwrap()
                    .eq_ignore_ascii_case("msvcrt.dll")
                    && i["symbol"] == "memset"
            })
            .expect("msvcrt.dll!memset")
            .clone();
        // rebased to 0 ⇒ the printed addresses are the RVAs.
        assert_eq!(memset["iat_vaddr"], "0x29000");
        assert_eq!(memset["hint_name_vaddr"], "0x2af40");
    }

    #[test]
    fn info_elf_shape() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let target = load_target(&bytes);
        let info = info_json(&target, None);
        assert_eq!(info["format"], "elf");
        assert_eq!(info["arch"], "x64");
        let sections = info["sections"].as_array().unwrap();
        assert!(sections.iter().any(|s| s["name"] == ".text"));
        assert!(info["entry"].as_str().unwrap().starts_with("0x"));

        // ECO-06: `imports` was hardcoded `[]` for every ELF, so there was
        // no ret2plt/ret2libc symbol resolution anywhere in the tool. It is
        // now the SHN_UNDEF subset of the symbol tables.
        let imports = info["imports"].as_array().unwrap();
        assert!(!imports.is_empty(), "a dynamic ELF has undefined symbols");
        let strcpy = imports
            .iter()
            .find(|i| i["symbol"] == "strcpy")
            .expect("bash imports strcpy");
        assert_eq!(strcpy["binding"], "GLOBAL");
        // A DT_JMPREL relocation, not a guess.
        assert!(
            strcpy["got"].as_str().is_some_and(|g| g.starts_with("0x")),
            "{strcpy}"
        );
        let symbols = info["symbols"].as_array().unwrap();
        assert_eq!(
            info["symbol_count"].as_u64().unwrap() as usize,
            symbols.len()
        );
        assert!(symbols.len() >= imports.len());

        // ECO-06: the mitigation report, with `unknown` as a first-class
        // answer that states its reason.
        let m = &info["mitigations"];
        for key in ["nx", "pie", "relro", "canary", "fortify"] {
            let v = &m[key];
            assert!(!v.is_null(), "missing mitigation {key}");
            assert!(
                v["enabled"].is_boolean() || v["enabled"] == "unknown",
                "{key}: enabled must be a bool or the string \"unknown\", got {}",
                v["enabled"]
            );
            assert!(
                v["evidence"].as_str().is_some_and(|e| !e.is_empty()),
                "{key} has no evidence"
            );
        }
        // The declaration order is carried beside the (alphabetical) map.
        assert_eq!(
            info["mitigations_order"],
            serde_json::json!(["nx", "pie", "relro", "canary", "fortify", "rpath", "runpath"])
        );
    }

    #[test]
    fn info_honours_base() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let target = load_target(&bytes);
        let Target::Elf(ref elf) = target else {
            panic!("expected ELF")
        };
        let orig_base = elf.image_base();
        let orig_entry = elf.entry();
        let info = info_json(&target, Some(0x55550000));
        assert_eq!(info["image_base"], "0x55550000");
        assert_eq!(
            info["entry"],
            serde_json::json!(hexs(orig_entry - orig_base + 0x55550000))
        );
    }

    #[test]
    fn info_universal_and_raw() {
        let bytes = fixture_bytes("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let target = load_target(&bytes);
        let Target::Universal(ref u) = target else {
            panic!("expected Universal")
        };
        let n_slices = u.slices().len();
        let info = info_json(&target, None);
        assert_eq!(info["format"], "universal");
        let slices = info["slices"].as_array().unwrap();
        assert_eq!(slices.len(), n_slices);
        assert!(slices.iter().all(|s| s["format"] == "macho"));

        let raw = RawBinary::new(&fixture_bytes("raw-x86.raw"), Arch::X86, Endianness::Little);
        let info = info_json(&Target::Raw(raw), None);
        assert_eq!(info["format"], "raw");
        assert_eq!(info["arch"], "x86");
        assert_eq!(info["image_base"], "0x0");
    }

    // -- --ropchain (Phase 4a) ------------------------------------------------

    fn chain_fixture(fixture: &str) -> ChainOutcome {
        match chain_bytes(
            &fixture_bytes(fixture),
            None,
            &ScanRequest::default(),
            &ChainSpec::linux(),
        ) {
            Ok(o) => o,
            Err(e) => panic!("chain build failed for {fixture}: {e}"),
        }
    }

    /// vaddr universe for `RopChain::validate`: the scan's gadget vaddrs.
    fn scan_universe(out: &ChainOutcome) -> std::collections::HashSet<u64> {
        out.outcome
            .result
            .gadgets
            .iter()
            .map(|g| g.vaddr.wrapping_add(out.outcome.opts.offset))
            .collect()
    }

    // -- ECO-04 / CHLX-07 / CHLX-08 -------------------------------------------

    #[test]
    fn syscall_number_is_decimal_unless_it_says_0x() {
        assert_eq!(parse_syscall_nr("59").unwrap(), 59);
        assert_eq!(parse_syscall_nr(" 10 ").unwrap(), 10);
        // ANCH-02's rule, for the same reason: a syscall number is written
        // in decimal everywhere from the kernel table to strace.
        assert_eq!(parse_syscall_nr("0x3b").unwrap(), 59);
        assert!(parse_syscall_nr("zz").is_err());
    }

    #[test]
    fn syscall_args_parse_into_register_value_pairs() {
        let got = parse_syscall_args("rdi=0x1000,rsi=8, RDX =7").unwrap();
        assert_eq!(
            got,
            vec![
                ("rdi".to_string(), 0x1000),
                ("rsi".to_string(), 8),
                ("rdx".to_string(), 7),
            ]
        );
        assert!(parse_syscall_args("rdi")
            .unwrap_err()
            .contains("<reg>=<value>"));
        assert!(parse_syscall_args("=1")
            .unwrap_err()
            .contains("empty register"));
        assert!(parse_syscall_args("").unwrap().is_empty());
    }

    #[test]
    fn stage_bytes_parse_as_hex() {
        assert_eq!(
            parse_hex_bytes("9090cc", "--stage").unwrap(),
            vec![0x90, 0x90, 0xcc]
        );
        assert_eq!(
            parse_hex_bytes("0x90 90", "--stage").unwrap(),
            vec![0x90, 0x90]
        );
        assert!(parse_hex_bytes("909", "--stage")
            .unwrap_err()
            .contains("odd number"));
        assert!(parse_hex_bytes("", "--stage")
            .unwrap_err()
            .contains("no bytes"));
    }

    /// CHWIN-08 #2: `--api-name A,B` composes two calls; `--api-addr` then
    /// needs one address per call or none.
    #[test]
    fn api_name_list_composes_calls_and_pairs_with_api_addr() {
        let spec = ChainSpec {
            target: "windows-virtualprotect".into(),
            api_name: Some("VirtualAlloc,virtualprotect".into()),
            api_addr: Some("0x1000,0x2000".into()),
            ..ChainSpec::default()
        };
        let o = win_opts(&spec).unwrap();
        assert_eq!(o.api_name, "VirtualAlloc");
        assert_eq!(o.api_addr, Some(0x1000));
        // canonical casing, so the IAT lookup and the description agree
        assert_eq!(
            o.extra_calls,
            vec![("VirtualProtect".to_string(), Some(0x2000))]
        );

        let mismatched = ChainSpec {
            api_addr: Some("0x1000".into()),
            ..spec.clone()
        };
        let err = win_opts(&mismatched).unwrap_err().to_string();
        assert!(err.contains("one runtime address per call"), "{err}");

        let unknown = ChainSpec {
            api_name: Some("VirtualAlloc,LoadLibraryA".into()),
            api_addr: None,
            ..spec
        };
        let err = win_opts(&unknown).unwrap_err().to_string();
        assert!(err.contains("LoadLibraryA"), "{err}");
    }

    /// ECO-04: `--plan-chain` always succeeds and names the requirement
    /// that failed. This is the exit criterion's fixture.
    #[test]
    fn plan_chain_on_pe_x64_cmd_reports_set_rdx_with_computed_relaxations() {
        let bytes = fixture_bytes("pe-x64-cmd-v6.1.7601");
        let spec = ChainSpec {
            target: "windows-virtualprotect".into(),
            ..ChainSpec::default()
        };
        let out = plan_chain_bytes(&bytes, None, &ScanRequest::default(), &spec).unwrap();
        let plan = &out.plan;
        assert!(!plan.feasible);
        let rdx = plan.requirement("set_rdx").expect("set_rdx");
        assert!(!rdx.satisfied);
        assert!(
            !rdx.strategies_tried.is_empty(),
            "strategies_tried must not be empty"
        );
        // Computed, not guessed: each relaxation is a real re-scan.
        assert!(
            !rdx.relaxations.is_empty(),
            "at least one computed relaxation"
        );
        assert!(rdx.relaxations.iter().any(|r| r.param == "depth"));
        assert!(rdx.relaxations.iter().any(|r| r.param == "multibr"));
        // ...and the requirements this binary DOES meet are listed, with a
        // vaddr that is a real gadget of the scan.
        assert!(!plan.satisfied_requirements.is_empty());
        let rcx = plan
            .satisfied_requirements
            .iter()
            .find(|s| s.id == "set_rcx")
            .expect("set_rcx is satisfied on cmd.exe");
        assert!(
            out.gadget_bytes(rcx.vaddr).is_some(),
            "the vaddr resolves in the scan"
        );
    }

    /// ECO-04: `--plan-chain` on a target it cannot even dispatch is still
    /// a document, not an error.
    #[test]
    fn plan_chain_never_fails_for_a_feasible_target() {
        let bytes = fixture_bytes("elf-Linux-x64");
        for target in ["linux-execve", "linux-mprotect", "linux-srop"] {
            let spec = ChainSpec {
                target: target.to_string(),
                ..ChainSpec::default()
            };
            let out = plan_chain_bytes(&bytes, None, &ScanRequest::default(), &spec).unwrap();
            assert!(out.plan.feasible, "{target}: {:?}", out.plan.error);
            assert!(
                out.plan.requirements.iter().all(|r| r.satisfied),
                "{target}"
            );
            // A feasible plan does no relaxation re-scans at all.
            assert!(out
                .plan
                .requirements
                .iter()
                .all(|r| r.relaxations.is_empty()));
        }
    }

    /// ECO-04: `--plan-chain` is a DOCUMENT even when the target is not
    /// dispatchable at all. `--ropchain --json` prints the same document
    /// when it has to refuse, which is the one-contract rule.
    #[test]
    fn plan_chain_reports_an_undispatchable_target_as_a_requirement() {
        let bytes = fixture_bytes("pe-x64-cmd-v6.1.7601");
        let spec = ChainSpec::linux();
        let out = plan_chain_bytes(&bytes, None, &ScanRequest::default(), &spec).unwrap();
        assert!(!out.plan.feasible);
        assert_eq!(
            out.plan
                .requirements
                .iter()
                .map(|r| r.id.as_str())
                .collect::<Vec<_>>(),
            vec!["target_supported"]
        );
        assert!(out.plan.error.unwrap().contains("not supported yet"));
        // ...and a target name that does not exist at all IS a usage error,
        // because there is then nothing to plan for.
        let spec = ChainSpec {
            target: "linux-nonsense".into(),
            ..ChainSpec::default()
        };
        let err = match plan_chain_bytes(&bytes, None, &ScanRequest::default(), &spec) {
            Ok(_) => panic!("an unknown target name must be a usage error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("unknown chain target"), "{err}");
    }

    /// CHLX-07: every advertised chain target is dispatchable on both
    /// surfaces, and an unknown one names the accepted set.
    #[test]
    fn chain_targets_are_the_advertised_set() {
        assert_eq!(
            chain_targets(),
            vec![
                "linux-execve",
                "linux-mprotect",
                "linux-syscall",
                "linux-ret2libc",
                "linux-srop",
                "windows-virtualprotect",
            ]
        );
        let bytes = fixture_bytes("elf-Linux-x64");
        let spec = ChainSpec {
            target: "linux-nonsense".into(),
            ..ChainSpec::default()
        };
        let m = match chain_bytes(&bytes, None, &ScanRequest::default(), &spec) {
            Ok(_) => panic!("an unknown target must not build"),
            Err(e) => e.to_string(),
        };
        assert!(m.contains("linux-srop"), "{m}");
        assert!(m.contains("windows-virtualprotect"), "{m}");
    }

    /// CHLX-08: the symmetric warning to the PE GUARD_CF one. It fires for
    /// an ET_DYN target with no `--offset`, and not otherwise.
    #[test]
    fn chlx08_pie_targets_are_warned_about() {
        assert!(rf_chain::linux::pie_chain_warning(true, 0, 0)
            .unwrap()
            .contains("--offset"));
        assert!(rf_chain::linux::pie_chain_warning(true, 0, 0x7ffff7a00000).is_none());
        assert!(rf_chain::linux::pie_chain_warning(false, 0x400000, 0).is_none());
        // ...and rf-core agrees the shipped shared object IS ET_DYN, which
        // is what the CLI branches on.
        let bytes = fixture_bytes("Linux_lib64.so");
        let Target::Elf(b) = load_target(&bytes) else {
            panic!("not an ELF");
        };
        assert_eq!(
            b.mitigations().enabled(rf_core::mitigations::PIE),
            rf_core::mitigations::Enabled::Yes
        );
        let bytes = fixture_bytes("elf-Linux-x64");
        let Target::Elf(b) = load_target(&bytes) else {
            panic!("not an ELF");
        };
        assert_ne!(
            b.mitigations().enabled(rf_core::mitigations::PIE),
            rf_core::mitigations::Enabled::Yes
        );
    }

    #[test]
    fn chain_builds_on_linux_x64() {
        let out = chain_fixture("elf-Linux-x64");
        let chain = &out.chain;
        assert_eq!(chain.arch, "x64");
        assert_eq!(chain.word_size, 8);
        chain.validate(&scan_universe(&out), &[]).unwrap();
        // Renderers: python script has the ropmaker header; every word
        // except string immediates renders as a pack line (padding, like
        // every other word, renders at column 0 — ROB-05); JSON exposes the
        // full IR.
        let py = chain.to_python();
        assert!(py.starts_with("#!/usr/bin/env python3\n# execve generated by ROPgadget\n"));
        assert!(py.contains("p += b'/bin//sh'"));
        assert_eq!(
            py.matches("p += pack('<Q',").count(),
            chain
                .words
                .iter()
                .filter(|w| w.kind != rf_chain::WordKind::Immediate)
                .count()
        );
        let json = chain.to_json();
        assert_eq!(json["arch"], "x64");
        assert_eq!(json["words"].as_array().unwrap().len(), chain.words.len());
    }

    #[test]
    fn chain_builds_on_linux_x86() {
        let out = chain_fixture("elf-Linux-x86");
        let chain = &out.chain;
        assert_eq!(chain.arch, "x86");
        assert_eq!(chain.word_size, 4);
        chain.validate(&scan_universe(&out), &[]).unwrap();
        assert!(chain.to_python().contains("pack('<I',"));
    }

    #[test]
    fn chain_gadget_addrs_come_from_scan() {
        // Property test: every GadgetAddr word references a vaddr the scan
        // actually produced, and the chain's gadget table agrees.
        let out = chain_fixture("elf-Linux-x64");
        let universe = scan_universe(&out);
        for w in &out.chain.words {
            if w.kind == rf_chain::WordKind::GadgetAddr {
                let g = &out.chain.gadgets[w.source_gadget.unwrap()];
                assert_eq!(g.vaddr, w.value);
                assert!(
                    universe.contains(&w.value),
                    "chain gadget {:#x} not in scan output",
                    w.value
                );
            }
        }
        // The execve chain must end in a syscall gadget.
        let last = out.chain.gadgets.last().unwrap();
        assert!(last.text.contains("syscall"));
    }

    #[test]
    fn chain_rejects_unsupported_targets() {
        // PE x64 → Usage error ("not supported"), mirroring ropmaker.py's
        // dispatch which only knows ELF x86/x64.
        let err = match chain_bytes(
            &fixture_bytes("pe-x64-cmd-v6.1.7601"),
            None,
            &ScanRequest::default(),
            &ChainSpec::linux(),
        ) {
            Err(e) => e,
            Ok(_) => panic!("PE chain build unexpectedly succeeded"),
        };
        match err {
            ScanError::Usage(m) => assert!(m.contains("not supported"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
        // ELF but wrong arch (ARM64) → same structured refusal.
        let err = match chain_bytes(
            &fixture_bytes("elf-ARM64-bash"),
            None,
            &ScanRequest::default(),
            &ChainSpec::linux(),
        ) {
            Err(e) => e,
            Ok(_) => panic!("ARM64 chain build unexpectedly succeeded"),
        };
        assert!(matches!(err, ScanError::Usage(_)));
    }

    #[test]
    fn chain_missing_gadgets_is_structured_error() {
        // A gadget the recipe needs and the scan does not hold is a
        // ScanError::Chain naming it — ROPgadget prints "Can't find ..."
        // and gives up.
        //
        // The scan is pinned to `depth: 2` deliberately. This used to run
        // at the default depth against elf-x64-bash, but CHLX-01's
        // fallback strategies now build a chain there, and pinning a
        // *shortage* test to a fixture that has since grown a route makes
        // the assertion about the fixture rather than about the error
        // shape. A two-instruction gadget budget is a shortage no
        // fallback can search its way out of; the assertion below is on
        // the shape and on the message naming a gadget, not on which one.
        let req = ScanRequest {
            depth: 2,
            ..ScanRequest::default()
        };
        let err = match chain_bytes(
            &fixture_bytes("elf-x64-bash-v4.1.5.1"),
            None,
            &req,
            &ChainSpec::linux(),
        ) {
            Err(e) => e,
            Ok(_) => panic!("bash chain build at depth 2 unexpectedly succeeded"),
        };
        match err {
            ScanError::Chain(m) => {
                assert!(m.contains("can't find a suitable gadget"), "{m}");
                assert!(m.len() > "can't find a suitable gadget: ".len(), "{m}");
            }
            other => panic!("expected Chain, got {other:?}"),
        }
    }

    #[test]
    fn chain_honours_badbytes() {
        // elf-Linux-x64's image base is 0x400000; banning 0x40 must make
        // the build fail (every gadget address contains it), proving the
        // badbytes constraint reaches the chain builder.
        let req = ScanRequest {
            badbytes: Some("40".into()),
            ..ScanRequest::default()
        };
        let res = chain_bytes(
            &fixture_bytes("elf-Linux-x64"),
            None,
            &req,
            &ChainSpec::linux(),
        );
        assert!(matches!(res, Err(ScanError::Chain(_))));
    }

    // -- --chain windows-virtualprotect (Phase 4b) ---------------------------

    fn win_spec() -> ChainSpec {
        ChainSpec {
            target: "windows-virtualprotect".into(),
            api_addr: Some("0x7fff12340000".into()),
            ..ChainSpec::default()
        }
    }

    #[test]
    fn chain_windows_x86_stdcall_full_chain() {
        // pe-x86-cmd: stdcall needs no gadgets — the chain is
        // [api][ret→shellcode][4 args] and VirtualProtect's ret 0x10
        // continues into the shellcode (second-stack frame).
        let out = chain_bytes(
            &fixture_bytes("pe-x86-cmd-v6.1.7600"),
            None,
            &ScanRequest::default(),
            &win_spec(),
        )
        .unwrap();
        let chain = &out.chain;
        assert_eq!(chain.arch, "x86");
        assert_eq!(chain.word_size, 4);
        let values: Vec<u64> = chain.words.iter().map(|w| w.value).collect();
        assert_eq!(values.len(), 6);
        assert_eq!(values[0], 0x7fff12340000, "api addr (--api-addr)");
        assert_eq!(
            values[1], values[2],
            "return-to and lpAddress both = shellcode"
        );
        assert_eq!(values[3], 0x1000, "default dwSize");
        assert_eq!(values[4], 0x40, "PAGE_EXECUTE_READWRITE");
        // shellcode defaults to the PE's writable .data
        assert!(chain.description.contains("VirtualProtect"));
        chain
            .validate(&std::collections::HashSet::new(), &[])
            .unwrap();
        // python renderer: 6 pack('<I') words
        assert_eq!(chain.to_python().matches("pack('<I',").count(), 6);
    }

    /// CHWIN-02, on a binary the project ships. `build_win32` used to pass
    /// the writable section's vaddr for BOTH the shellcode home and
    /// `&lpflOldProtect`, so VirtualProtect wrote the previous-protection
    /// DWORD over the first four bytes of the buffer it had just made RWX,
    /// and the `ret 0x10` then landed on it. The emulator saw
    /// `90909090 -> 04000000` (docs/chain-regressions.md, CHWIN-02-x86).
    #[test]
    fn chain_windows_x86_out_parameter_does_not_alias_the_shellcode() {
        let out = chain_bytes(
            &fixture_bytes("pe-x86-cmd-v6.1.7600"),
            None,
            &ScanRequest::default(),
            &win_spec(),
        )
        .unwrap();
        let values: Vec<u64> = out.chain.words.iter().map(|w| w.value).collect();
        let shellcode = values[2];
        let old = values[5];
        assert_eq!(shellcode, 0x4ad24000, "the .data vaddr --info reports");
        assert_ne!(old, shellcode, "CHWIN-02: the out-parameter aliases arg1");
        assert!(
            old < shellcode || old >= shellcode + 4,
            "{old:#x} lands in the shellcode's first DWORD"
        );
        let a = out.assumptions.as_ref().unwrap();
        assert_eq!(a.shellcode_addr, shellcode);
        assert_eq!(a.old_protect_addr, Some(old));
        assert!(out.chain.words[5].comment.contains("NOT the shellcode"));
    }

    /// CHWIN-06 on the shipped fixture: cmd.exe imports VirtualAlloc, not
    /// VirtualProtect (measured with `--info`: VirtualAlloc, VirtualFree,
    /// VirtualQuery). `--api-name` selects both the symbol and the argument
    /// recipe, so arg3 becomes MEM_COMMIT and arg4 the protection.
    #[test]
    fn chain_windows_api_name_selects_the_recipe() {
        let out = chain_bytes(
            &fixture_bytes("pe-x86-cmd-v6.1.7600"),
            None,
            &ScanRequest::default(),
            &ChainSpec {
                api_name: Some("virtualalloc".into()), // case-insensitive
                ..win_spec()
            },
        )
        .unwrap();
        let values: Vec<u64> = out.chain.words.iter().map(|w| w.value).collect();
        assert_eq!(values[4], rf_chain::windows::MEM_COMMIT, "flAllocationType");
        assert_eq!(values[5], 0x40, "flProtect");
        assert!(out.chain.description.contains("VirtualAlloc"));
        assert!(out.chain.description.contains("MEM_COMMIT"));
        // No out-parameter, so nothing for CHWIN-02 to alias.
        assert_eq!(out.assumptions.as_ref().unwrap().old_protect_addr, None);
        assert_eq!(out.assumptions.as_ref().unwrap().api_name, "VirtualAlloc");
    }

    /// CHWIN-04: `--chain-base` changes the layout the invariant enforces,
    /// and `--prot` reaches flNewProtect. Both are usage-validated.
    #[test]
    fn chain_base_and_prot_flags_are_parsed_and_validated() {
        let spec = ChainSpec {
            chain_base: Some("aligned".into()),
            prot: Some("0x20".into()),
            ..win_spec()
        };
        let o = win_opts(&spec).unwrap();
        assert_eq!(o.chain_base, rf_chain::windows::ChainBaseParity::Aligned);
        assert_eq!(o.new_protect, 0x20);
        // Defaults, when the flags are absent.
        let d = win_opts(&win_spec()).unwrap();
        assert_eq!(
            d.chain_base,
            rf_chain::windows::ChainBaseParity::ReturnAddress
        );
        assert_eq!(d.new_protect, 0x40);
        assert_eq!(d.api_name, "VirtualProtect");
        // The MCP passes snake_case; both surfaces accept both spellings.
        for v in ["return-address", "return_address"] {
            let o = win_opts(&ChainSpec {
                chain_base: Some(v.into()),
                ..win_spec()
            })
            .unwrap();
            assert_eq!(
                o.chain_base,
                rf_chain::windows::ChainBaseParity::ReturnAddress
            );
        }
        // Bad values are usage errors that name the accepted set.
        let err = win_opts(&ChainSpec {
            chain_base: Some("stack".into()),
            ..win_spec()
        })
        .unwrap_err();
        assert!(
            matches!(&err, ScanError::Usage(m) if m.contains("aligned")),
            "{err:?}"
        );
        let err = win_opts(&ChainSpec {
            api_name: Some("VirtualProtectEx".into()),
            ..win_spec()
        })
        .unwrap_err();
        assert!(
            matches!(&err, ScanError::Usage(m) if m.contains("VirtualProtect, VirtualAlloc")),
            "{err:?}"
        );
        assert!(win_opts(&ChainSpec {
            prot: Some("zz".into()),
            ..win_spec()
        })
        .is_err());
    }

    /// CHWIN-04's disclosure half on the CLI: `--ropchain --json` carries
    /// the assumption the layout was built on, next to the layout.
    #[test]
    fn chain_json_carries_the_windows_assumptions() {
        let out = chain_bytes(
            &fixture_bytes("pe-x86-cmd-v6.1.7600"),
            None,
            &ScanRequest::default(),
            &win_spec(),
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&chain_json(&out)).unwrap();
        let a = &v["assumptions"];
        assert_eq!(a["chain_base_parity"], "return_address");
        assert_eq!(a["chain_base_mod16"], 8);
        assert_eq!(a["api_name"], "VirtualProtect");
        assert_eq!(a["shellcode_addr"], "0x4ad24000");
        assert_ne!(a["old_protect_addr"], a["shellcode_addr"]);
        // The IR itself is untouched: same words, same order.
        assert_eq!(v["words"].as_array().unwrap().len(), out.chain.words.len());
        // A Linux chain makes none of these assumptions and says nothing.
        let lin = chain_bytes(
            &fixture_bytes("elf-Linux-x64"),
            None,
            &ScanRequest::default(),
            &ChainSpec::linux(),
        )
        .unwrap();
        assert!(lin.assumptions.is_none());
        let lv: serde_json::Value = serde_json::from_str(&chain_json(&lin)).unwrap();
        assert_eq!(lv["assumptions"], serde_json::Value::Null);
    }

    #[test]
    fn chain_windows_x64_cmd_reports_spike_scarcity() {
        // The spike finding: pe-x64-cmd has NO ret-terminated gadget that
        // writes rdx/r8/r9. The builder must fail with a structured error
        // naming the unpopulatable register and the strategies tried.
        let err = chain_bytes(
            &fixture_bytes("pe-x64-cmd-v6.1.7601"),
            None,
            &ScanRequest::default(),
            &win_spec(),
        )
        .err()
        .expect("x64 cmd cannot sustain a VirtualProtect chain (spike report)");
        match err {
            ScanError::Chain(m) => {
                assert!(m.contains("cannot populate rdx"), "{m}");
                assert!(m.contains("pop rdx"), "{m}");
                assert!(m.contains("mov rdx, rax"), "{m}");
            }
            other => panic!("expected Chain, got {other:?}"),
        }
    }

    #[test]
    fn chain_windows_x64_ntoskrnl_full_chain() {
        // ring0 target from PLAN sec. 6.2 #5; the spike binary is
        // gitignored, so skip gracefully when absent.
        let path = format!(
            "{}/../../tests/spike-binaries/ntoskrnl.exe",
            env!("CARGO_MANIFEST_DIR")
        );
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: tests/spike-binaries/ntoskrnl.exe not present");
            return;
        };
        let out = chain_bytes(&bytes, None, &ScanRequest::default(), &win_spec()).unwrap();
        let chain = &out.chain;
        assert_eq!(chain.arch, "x64");
        assert_eq!(chain.word_size, 8);

        // Structure: 4×(pop gadget + arg word), transfer at an ODD index
        // under the DEFAULT chain base (`return_address`, CHWIN-04), then
        // return-to-shellcode + 4 shadow words.
        let call_idx = chain
            .words
            .iter()
            .position(|w| w.comment.contains("--api-addr"))
            .unwrap();
        assert_eq!(call_idx % 2, 1, "alignment invariant (return_address base)");
        assert_eq!(chain.words.len(), call_idx + 1 + 1 + 4);
        assert_eq!(chain.words[call_idx].value, 0x7fff12340000);
        assert_eq!(
            chain.words[call_idx + 1].value,
            chain.words[1].value,
            "return address = shellcode (arg1)"
        );
        assert!(chain.words[call_idx + 2..]
            .iter()
            .all(|w| w.kind == rf_chain::WordKind::Padding));

        // CHWIN-01, on a real 20 MB PE: whatever word the API transfer is
        // reached through, it is never an inert data word — the preceding
        // gadget's `ret` loads it into rip.
        let before = &chain.words[call_idx - 1];
        assert!(
            matches!(
                before.kind,
                rf_chain::WordKind::GadgetAddr | rf_chain::WordKind::Padding
            ),
            "{before:?}"
        );
        if before.kind == rf_chain::WordKind::GadgetAddr {
            let g = &chain.gadgets[before.source_gadget.unwrap()];
            assert_eq!(g.text, "ret", "the alignment slide must consume itself");
        }
        chain.verify_stack_accounting().unwrap();

        // CHWIN-02: &lpflOldProtect is arg4 (word 7) and must not alias the
        // shellcode, which is arg1 (word 1).
        let assumptions = out.assumptions.as_ref().expect("windows assumptions");
        assert_eq!(assumptions.chain_base_parity, "return_address");
        assert_eq!(assumptions.shellcode_addr, chain.words[1].value);
        let old = assumptions
            .old_protect_addr
            .expect("VirtualProtect out-param");
        assert_eq!(chain.words[7].value, old);
        assert!(
            old < chain.words[1].value || old >= chain.words[1].value + 4,
            "{old:#x} aliases the shellcode at {:#x}",
            chain.words[1].value
        );

        // Property: every gadget word references a real scan gadget.
        let universe: std::collections::HashSet<u64> = out
            .outcome
            .result
            .gadgets
            .iter()
            .map(|g| g.vaddr.wrapping_add(out.outcome.opts.offset))
            .collect();
        for w in &chain.words {
            if w.kind == rf_chain::WordKind::GadgetAddr {
                assert!(universe.contains(&w.value), "{:#x} not in scan", w.value);
            }
        }
        chain.validate(&universe, &[]).unwrap();
    }

    #[test]
    fn chain_windows_rejects_wrong_format_and_unknown_target() {
        // windows-virtualprotect on an ELF → structured "not supported".
        let err = chain_bytes(
            &fixture_bytes("elf-Linux-x64"),
            None,
            &ScanRequest::default(),
            &win_spec(),
        )
        .err()
        .unwrap();
        match err {
            ScanError::Usage(m) => assert!(m.contains("not supported"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
        // unknown --chain value → usage error naming valid targets.
        let err = chain_bytes(
            &fixture_bytes("elf-Linux-x64"),
            None,
            &ScanRequest::default(),
            &ChainSpec {
                target: "plan9-forkbomb".into(),
                ..ChainSpec::default()
            },
        )
        .err()
        .unwrap();
        match err {
            ScanError::Usage(m) => assert!(m.contains("linux-execve"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // ROB-06 - input bounds
    // -----------------------------------------------------------------

    #[test]
    fn parse_size_is_decimal_with_binary_suffixes() {
        assert_eq!(parse_size("512", "x").unwrap(), 512);
        // The whole point: 16 means SIXTEEN. parse_hex would say 22.
        assert_eq!(parse_size("16", "x").unwrap(), 16);
        assert_eq!(parse_size("1K", "x").unwrap(), 1024);
        assert_eq!(parse_size("1k", "x").unwrap(), 1024);
        assert_eq!(parse_size("512M", "x").unwrap(), DEFAULT_MAX_FILE_SIZE);
        assert_eq!(parse_size("2G", "x").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size(" 4M ", "x").unwrap(), 4 * 1024 * 1024);
        for bad in ["", "0x10", "abc", "-1", "1T", "99999999999999999999G"] {
            assert!(parse_size(bad, "--max-file-size").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn check_input_metadata_refuses_non_regular_and_oversized() {
        let dir = format!("{}/../../tests/fixtures", env!("CARGO_MANIFEST_DIR"));
        let meta = std::fs::metadata(&dir).unwrap();
        let err = check_input_metadata(&dir, &meta, DEFAULT_MAX_FILE_SIZE).unwrap_err();
        assert!(err.contains("directory"), "{err}");

        let f = format!("{dir}/elf-Linux-x86");
        let meta = std::fs::metadata(&f).unwrap();
        let len = meta.len();
        // At the limit: allowed. One byte under: refused, naming both
        // numbers so the user can raise the cap without guessing.
        assert!(check_input_metadata(&f, &meta, len).is_ok());
        let err = check_input_metadata(&f, &meta, len - 1).unwrap_err();
        assert!(err.contains(&len.to_string()), "{err}");
        assert!(err.contains(&(len - 1).to_string()), "{err}");
    }

    #[test]
    fn read_input_file_honours_the_cap() {
        let f = format!(
            "{}/../../tests/fixtures/elf-Linux-x86",
            env!("CARGO_MANIFEST_DIR")
        );
        assert!(read_input_file(&f, 1024).is_err());
        let got = read_input_file(&f, DEFAULT_MAX_FILE_SIZE).unwrap();
        assert_eq!(got.len() as u64, std::fs::metadata(&f).unwrap().len());
    }

    // -----------------------------------------------------------------
    // CORE-01 / CORE-03 / CORE-05 - refuse rather than fabricate
    // -----------------------------------------------------------------

    /// CORE-01: the loader refuses, so no caller can hold an image whose
    /// architecture was guessed. The same bytes used to produce a full
    /// x86 listing.
    #[test]
    fn unrecognized_e_machine_is_a_load_error_not_an_x86_guess() {
        let mut bytes = fixture_bytes("elf-Linux-x86");
        bytes[18] = 0x99;
        bytes[19] = 0x99;
        let err = scan_bytes(&bytes, None, &ScanRequest::default())
            .err()
            .expect("must refuse");
        match err {
            ScanError::Binary(m) => {
                assert!(m.contains("0x9999"), "must name the machine type: {m}");
            }
            other => panic!("expected Binary, got {other:?}"),
        }
        // ...and --info refuses too, rather than reporting arch "x86".
        assert!(info_bytes(&bytes, None, None).is_err());
    }

    /// CORE-03: `resolve_arch` is the refusal gate, and it is the only
    /// place the decision is made (scan, chain and console all route
    /// through `prepare_view`).
    #[test]
    fn fat_macho_needs_an_explicit_arch() {
        let bytes = fixture_bytes("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let target = load_target(&bytes);
        assert!(matches!(target, Target::Universal(_)));

        let err = resolve_arch(&target, None, false).unwrap_err();
        match err {
            ScanError::Usage(m) => {
                assert!(m.contains("--arch"), "{m}");
                assert!(m.contains("x86_64") && m.contains("i386"), "{m}");
            }
            other => panic!("expected Usage, got {other:?}"),
        }
        // --compat opts back into ROPgadget's concatenation.
        assert_eq!(resolve_arch(&target, None, true).unwrap(), None);
        // Explicit selection, including aliases and case folding.
        assert_eq!(
            resolve_arch(&target, Some("x86_64"), false).unwrap(),
            Some(Arch::X64)
        );
        assert_eq!(
            resolve_arch(&target, Some("AMD64"), false).unwrap(),
            Some(Arch::X64)
        );
        assert_eq!(
            resolve_arch(&target, Some("i386"), false).unwrap(),
            Some(Arch::X86)
        );
        assert!(resolve_arch(&target, Some("arm64"), false).is_err());
        assert!(resolve_arch(&target, Some("nonesuch"), false).is_err());
    }

    /// The selected slice really is scanned alone: each slice's gadget set
    /// is a strict subset of the concatenation, and the two differ.
    #[test]
    fn fat_macho_slice_selection_scans_one_slice() {
        let bytes = fixture_bytes("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let req = |arch: Option<&str>, compat: bool| ScanRequest {
            arch: arch.map(str::to_string),
            compat,
            ..ScanRequest::default()
        };
        let keys = |r: &ScanOutcome| -> std::collections::HashSet<(u64, Vec<u8>)> {
            r.result
                .gadgets
                .iter()
                .map(|g| (g.vaddr, g.bytes.clone()))
                .collect()
        };
        let x64 = scan_bytes(&bytes, None, &req(Some("x86_64"), false)).unwrap();
        let x86 = scan_bytes(&bytes, None, &req(Some("i386"), false)).unwrap();
        let cat = scan_bytes(&bytes, None, &req(None, true)).unwrap();
        let (k64, k86, kc) = (keys(&x64), keys(&x86), keys(&cat));
        assert!(!k64.is_empty() && !k86.is_empty());
        assert_ne!(k64, k86);
        assert!(kc.len() > k64.len());

        // This is CORE-03. The concatenation decodes EVERY slice with the
        // FIRST slice's decoder (universal.py:92-108, "just return
        // whatever is in the first binary"), so the x86_64 slice - first
        // in this container - survives intact while the i386 slice is read
        // as x86-64. On THIS fixture the two ISAs share most short
        // encodings, so the damage is mild and measurable rather than
        // catastrophic: 20 of 185 real i386 gadgets are dropped and one
        // concatenation entry belongs to neither real slice. (The audit's
        // 41%-fabricated figure is for an arm64+x86_64 Apple-silicon
        // binary, where the two decoders share nothing; no such fixture is
        // in the corpus.) Both directions of the damage are asserted, so
        // this fails if the concatenation ever silently becomes the union
        // of two honest scans.
        assert!(
            k64.is_subset(&kc),
            "the first slice decodes correctly in the concatenation"
        );
        let lost: Vec<_> = k86.difference(&kc).collect();
        assert!(
            !lost.is_empty(),
            "the concatenation must LOSE real second-slice gadgets"
        );
        let real = &k64 | &k86;
        let fabricated: Vec<_> = kc.difference(&real).collect();
        assert!(
            !fabricated.is_empty(),
            "the concatenation must contain gadgets belonging to NEITHER real slice"
        );
    }

    /// `--arch` on a single-architecture image is accepted only when it
    /// agrees with the image.
    #[test]
    fn arch_on_a_single_architecture_image_must_agree() {
        let target = load_target(&fixture_bytes("elf-Linux-x86"));
        assert_eq!(
            resolve_arch(&target, Some("i386"), false).unwrap(),
            Some(Arch::X86)
        );
        assert_eq!(resolve_arch(&target, None, false).unwrap(), None);
        let err = resolve_arch(&target, Some("arm64"), false).unwrap_err();
        match err {
            ScanError::Usage(m) => assert!(m.contains("does not match"), "{m}"),
            other => panic!("expected Usage, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // CRIT-01 / CORE-07 - say it out loud
    // -----------------------------------------------------------------

    /// `--cfg-aware` on a binary with no landing pads warns instead of
    /// letting the user read an unconstrained result as a constrained one.
    #[test]
    fn cfg_aware_warns_when_ibt_is_not_in_play() {
        let bytes = fixture_bytes("pe-x64-cmd-v6.1.7601");
        let target = load_target(&bytes);
        let view = build_view(&target);
        let quiet = scan_warnings(&target, &view, false, false);
        assert!(quiet.is_empty(), "{quiet:?}");
        let loud = scan_warnings(&target, &view, true, false);
        assert_eq!(loud.len(), 1, "{loud:?}");
        assert!(loud[0].contains("endbr"), "{}", loud[0]);
        assert!(loud[0].contains("GUARD_CF"), "{}", loud[0]);
    }

    /// CLI-11/`--compat`: the fat-Mach-O escape hatch is never silent.
    #[test]
    fn compat_fat_macho_scan_is_announced() {
        let bytes = fixture_bytes("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let target = load_target(&bytes);
        let view = build_view(&target);
        assert!(scan_warnings(&target, &view, false, false).is_empty());
        let w = scan_warnings(&target, &view, false, true);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("FABRICATED"), "{}", w[0]);
    }

    // -----------------------------------------------------------------
    // PERF-05
    // -----------------------------------------------------------------

    /// A budget that is not hit changes nothing; a budget that is hit
    /// reports itself rather than truncating silently.
    #[test]
    fn max_gadgets_bounds_the_scan_without_changing_an_unbounded_one() {
        let bytes = fixture_bytes("macho-x64-ls");
        let keys = |o: &ScanOutcome| -> Vec<(u64, Vec<u8>)> {
            o.result
                .gadgets
                .iter()
                .map(|g| (g.vaddr, g.bytes.clone()))
                .collect()
        };
        let plain = scan_bytes(&bytes, None, &ScanRequest::default()).unwrap();
        let n = plain.result.gadgets.len();
        assert!(n > 10);

        let generous = scan_bytes(
            &bytes,
            None,
            &ScanRequest {
                max_gadgets: Some(n * 100),
                ..ScanRequest::default()
            },
        )
        .unwrap();
        assert_eq!(keys(&generous), keys(&plain));

        let err = scan_bytes(
            &bytes,
            None,
            &ScanRequest {
                max_gadgets: Some(5),
                ..ScanRequest::default()
            },
        )
        .err()
        .expect("budget must trip");
        match err {
            ScanError::Binary(m) => assert!(m.contains("budget"), "{m}"),
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // CLI-11 - the print path
    // -----------------------------------------------------------------

    /// core.py:110-111: a --noinstr line is the bare address (plus
    /// " // bytes" under --dump). The engine still carries the text -
    /// --filter and --badbytes need it - so the suppression is the CLI's.
    #[test]
    fn print_human_suppresses_text_under_noinstr() {
        let res = ScanResult {
            gadgets: vec![Gadget {
                vaddr: 0x0804_8000,
                bytes: vec![0x5f, 0xc3],
                insns: vec!["pop edi".into(), "ret".into()],
                delay_slot: false,
                prev: None,
                table: rf_scan::TableKind::Rop,
            }],
            addr_size: 4,
            universal_arch: None,
            selected_sections: None,
        };
        let render = |noinstr, dump| {
            let mut buf: Vec<u8> = Vec::new();
            print_human(&res, noinstr, dump, &mut buf);
            String::from_utf8(buf).unwrap()
        };
        assert!(render(false, false).contains("0x08048000 : pop edi ; ret\n"));
        assert!(render(true, false).contains("0x08048000\n"));
        assert!(!render(true, false).contains("pop edi"));
        assert!(render(true, true).contains("0x08048000 // 5fc3\n"));
        assert!(!render(true, true).contains("pop edi"));
        assert!(render(false, true).contains("0x08048000 : pop edi ; ret // 5fc3\n"));
    }
}
