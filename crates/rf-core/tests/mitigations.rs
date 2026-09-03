//! ECO-06 exit criterion: the mitigation report must match `checksec` on
//! every Linux fixture and the PE header / load-config flags on every
//! Windows fixture, FIELD FOR FIELD, with any "unknown" carrying a reason.
//!
//! # Where the expected values come from
//!
//! `checksec` is a Linux shell script and this workspace is developed on
//! Windows, so the ground truth was derived here from the raw headers with a
//! **separate tool from the code under test** — CPython 3.12 plus
//! `pyelftools` 0.33, `pefile` 2024.8.26, and hand-rolled `struct` parses for
//! the Mach-O header, the fat header, the Mach-O code-signature SuperBlob and
//! (as a cross-check on `pefile`) the PE optional header. Nothing in this
//! table was read out of rf-core.
//!
//! Every ELF verdict below is the value `checksec.sh` computes from
//! `readelf -h/-l/-d/-s`, with four deliberate, documented exceptions where
//! this crate answers `unknown` instead of guessing. They are marked
//! `DIVERGES FROM checksec.sh` inline, and the reason is asserted to be
//! present in the evidence string, so the divergence cannot become silent.
//!
//! Two derived fields were additionally verified against actual instruction
//! bytes rather than against another parser:
//!
//! * `elf-x64-bash-v4.1.5.1` `printf` PLT `0x41e470` disassembles to
//!   `ff 25 b2 ad 2b 00` = `jmp [rip+0x2badb2]` = `jmp [0x6d9228]`, which is
//!   that symbol's `DT_JMPREL` `r_offset`.
//! * `elf-ARM64-bash` `puts` PLT `0x41c930` is
//!   `adrp x16, 0x4d6000 ; ldr x17, [x16, #0x388]`, i.e. `0x4d6388`, which is
//!   that symbol's `r_offset`.

use rf_core::mitigations as mit;
use rf_core::{Binary, ElfBinary, Enabled, LoadedBinary, Mitigations, RawBinary};

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("fixture {}: {e}", p.display()))
}

/// `Some(true)` / `Some(false)` / `None` = "unknown".
type Tri = Option<bool>;
const Y: Tri = Some(true);
const N: Tri = Some(false);
const U: Tri = None;

#[track_caller]
fn check(m: &Mitigations, key: &str, want: Tri, want_detail: Option<&str>, ctx: &str) {
    let got = m
        .get(key)
        .unwrap_or_else(|| panic!("{ctx}: no `{key}` in report {:?}", m.names()));
    assert_eq!(
        got.enabled.as_bool(),
        want,
        "{ctx}: {key} — expected {want:?}, got {} ({})",
        got.enabled,
        got.evidence
    );
    assert_eq!(
        got.detail.as_deref(),
        want_detail,
        "{ctx}: {key} detail ({})",
        got.evidence
    );
    assert!(
        !got.evidence.trim().is_empty(),
        "{ctx}: {key} has no evidence"
    );
    if got.enabled == Enabled::Unknown {
        // The whole contract: an "unknown" must say why.
        assert!(
            got.evidence.len() > 40,
            "{ctx}: {key} is unknown with no stated reason: {:?}",
            got.evidence
        );
    }
}

fn elf(name: &str) -> ElfBinary {
    match Binary::load(&fixture(name)) {
        Ok(LoadedBinary::Elf(e)) => e,
        other => panic!("{name}: expected ELF, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// ELF — one row per fixture, field for field against the independent parse.
// ---------------------------------------------------------------------------

/// name, nx, (pie, detail), (relro, detail), canary, fortify, rpath, runpath
type ElfRow = (
    &'static str,
    Tri,
    (Tri, Option<&'static str>),
    (Tri, Option<&'static str>),
    Tri,
    Tri,
    Tri,
    Tri,
);

const EXEC: Option<&str> = Some("fixed-address-executable");
const PIEX: Option<&str> = Some("pie-executable");
const DSO: Option<&str> = Some("shared-object");
const PARTIAL: Option<&str> = Some("partial");
const NORELRO: Option<&str> = Some("none");

/// Ground truth for all 16 ELF fixtures. One row per fixture, kept as a
/// readable grid rather than let rustfmt explode it.
#[rustfmt::skip]
const ELF_TABLE: &[ElfRow] = &[
    // ET_DYN, no PT_INTERP / DT_DEBUG / DF_1_PIE -> a shared library.
    // checksec.sh prints "DSO"; we say pie=true with detail shared-object.
    ("Linux_lib32.so", Y, (Y, DSO), (Y, PARTIAL), N, Y, N, N),
    ("Linux_lib64.so", Y, (Y, DSO), (Y, PARTIAL), N, Y, N, N),
    // No PT_GNU_STACK at all -> nx unknown. DIVERGES FROM checksec.sh,
    // which prints "NX enabled" purely because no GNU_STACK line says RWE.
    ("elf-ARM64-bash", U, (N, EXEC), (Y, PARTIAL), N, Y, N, N),
    ("elf-ARMv7-ls", Y, (N, EXEC), (N, NORELRO), Y, Y, N, N),
    // Static FreeBSD binary: no PT_GNU_STACK (nx unknown), __stack_chk_fail
    // DEFINED in .symtab, and not one __*_chk symbol anywhere.
    ("elf-FreeBSD-x86", U, (N, EXEC), (N, NORELRO), Y, N, N, N),
    ("elf-Linux-RISCV_32", Y, (N, EXEC), (Y, PARTIAL), N, N, N, N),
    ("elf-Linux-RISCV_64", U, (N, EXEC), (Y, PARTIAL), Y, N, N, N),
    // Static glibc binaries. PT_GNU_RELRO but no PT_DYNAMIC, so full vs
    // partial cannot be decided from bind-now; checksec.sh also says Partial.
    // fortify is unknown: __vfprintf_chk & co are DEFINED (they came in with
    // libc.a), which does not say the program's own calls were fortified.
    // DIVERGES FROM checksec.sh's libc-list heuristic.
    ("elf-Linux-x64", Y, (N, EXEC), (Y, PARTIAL), N, U, N, N),
    ("elf-Linux-x86", Y, (N, EXEC), (Y, PARTIAL), N, U, N, N),
    ("elf-Linux-x86-NDH-chall", Y, (N, EXEC), (N, NORELRO), N, U, N, N),
    // Zero symbols of any kind: canary is unanswerable, not "not found".
    // DIVERGES FROM checksec.sh, which prints "No canary found".
    ("elf-Mips-Defcon-20-pwn100", U, (N, EXEC), (N, NORELRO), U, N, N, N),
    // ET_DYN carrying DT_FLAGS_1 & DF_1_PIE (0x8000000): a PIE executable,
    // NOT a shared library — the distinction ET_DYN alone cannot make.
    ("elf-PPC64-bash", Y, (Y, PIEX), (Y, PARTIAL), Y, Y, N, N),
    ("elf-PowerPC-bash", Y, (N, EXEC), (Y, PARTIAL), Y, Y, N, N),
    ("elf-SparcV8-bash", Y, (N, EXEC), (Y, PARTIAL), Y, Y, N, N),
    ("elf-x64-bash-v4.1.5.1", Y, (N, EXEC), (N, NORELRO), N, N, N, N),
    ("elf-x86-bash-v4.1.5.1", Y, (N, EXEC), (N, NORELRO), N, N, N, N),
];

#[test]
fn elf_mitigations_match_the_independent_header_parse() {
    for &(name, nx, pie, relro, canary, fortify, rpath, runpath) in ELF_TABLE {
        let b = elf(name);
        let m = b.mitigations();
        assert_eq!(
            m.names(),
            vec![
                mit::NX,
                mit::PIE,
                mit::RELRO,
                mit::CANARY,
                mit::FORTIFY,
                mit::RPATH,
                mit::RUNPATH
            ],
            "{name}: report keys"
        );
        check(m, mit::NX, nx, None, name);
        check(m, mit::PIE, pie.0, pie.1, name);
        check(m, mit::RELRO, relro.0, relro.1, name);
        check(m, mit::CANARY, canary, None, name);
        check(m, mit::RPATH, rpath, None, name);
        check(m, mit::RUNPATH, runpath, None, name);
        // fortify carries the __*_chk list as its detail when there is one.
        let f = m.get(mit::FORTIFY).unwrap();
        assert_eq!(
            f.enabled.as_bool(),
            fortify,
            "{name}: fortify ({})",
            f.evidence
        );
        assert_eq!(
            f.detail.is_some(),
            fortify != Some(false),
            "{name}: fortify detail should list the __*_chk symbols unless there are none"
        );
    }
}

/// Each `unknown` verdict must name the missing evidence.
#[test]
fn every_unknown_states_its_reason() {
    let cases: &[(&str, &str, &str)] = &[
        ("elf-ARM64-bash", mit::NX, "no PT_GNU_STACK"),
        ("elf-Linux-RISCV_64", mit::NX, "READ_IMPLIES_EXEC"),
        (
            "elf-Mips-Defcon-20-pwn100",
            mit::CANARY,
            "neither a .dynsym nor a .symtab",
        ),
        ("elf-Linux-x64", mit::FORTIFY, "statically linked"),
        ("elf-Linux-x86-NDH-chall", mit::FORTIFY, "_FORTIFY_SOURCE"),
    ];
    for (name, key, needle) in cases {
        let b = elf(name);
        let m = b.mitigations().get(key).unwrap();
        assert_eq!(m.enabled, Enabled::Unknown, "{name}/{key}");
        assert!(
            m.evidence.contains(needle),
            "{name}/{key}: evidence does not mention {needle:?}: {}",
            m.evidence
        );
    }
}

/// The PIE reader must not confuse a shared library with a PIE executable —
/// both are `ET_DYN`, and this is the distinction the finding calls out.
#[test]
fn et_dyn_pie_executable_is_distinguished_from_a_shared_library() {
    let pie = elf("elf-PPC64-bash");
    let m = pie.mitigations().get(mit::PIE).unwrap();
    assert_eq!(m.detail.as_deref(), Some("pie-executable"));
    assert!(m.evidence.contains("DF_1_PIE"), "{}", m.evidence);

    let dso = elf("Linux_lib64.so");
    let m = dso.mitigations().get(mit::PIE).unwrap();
    assert_eq!(m.detail.as_deref(), Some("shared-object"));
    assert!(
        m.evidence.contains("no DF_1_PIE")
            && m.evidence.contains("no PT_INTERP")
            && m.evidence.contains("no DT_DEBUG"),
        "{}",
        m.evidence
    );
}

// ---------------------------------------------------------------------------
// ELF symbols, GOT and PLT
// ---------------------------------------------------------------------------

/// Named-symbol and import counts, from the independent `pyelftools` walk of
/// `.dynsym` + `.symtab` (named entries only, `SHN_UNDEF` = import).
const SYMBOL_COUNTS: &[(&str, usize, usize)] = &[
    ("Linux_lib32.so", 725, 324),
    ("Linux_lib64.so", 813, 401),
    ("elf-ARM64-bash", 2181, 205),
    ("elf-ARMv7-ls", 133, 115),
    ("elf-FreeBSD-x86", 1806, 4),
    ("elf-Linux-RISCV_32", 60, 18),
    ("elf-Linux-RISCV_64", 46, 12),
    ("elf-Linux-x64", 2169, 46),
    ("elf-Linux-x86", 2180, 46),
    ("elf-Linux-x86-NDH-chall", 2028, 43),
    ("elf-Mips-Defcon-20-pwn100", 0, 0),
    ("elf-PPC64-bash", 391, 380),
    ("elf-PowerPC-bash", 2178, 205),
    ("elf-SparcV8-bash", 2103, 198),
    ("elf-x64-bash-v4.1.5.1", 2117, 192),
    ("elf-x86-bash-v4.1.5.1", 2118, 192),
];

#[test]
fn elf_symbol_tables_are_no_longer_empty() {
    for &(name, symbols, imports) in SYMBOL_COUNTS {
        let b = elf(name);
        assert_eq!(b.symbols().len(), symbols, "{name}: named symbols");
        assert_eq!(b.imports().len(), imports, "{name}: imports");
        assert_eq!(
            b.symbols().iter().filter(|s| s.is_import).count(),
            imports,
            "{name}: imports() must agree with the is_import flag"
        );
        assert!(
            b.symbols().iter().all(|s| !s.name.is_empty()),
            "{name}: unnamed symbols must be dropped"
        );
    }
}

/// name, symbol, got, plt — every value from the independent relocation walk.
const GOT_PLT: &[(&str, &str, u64, Option<u64>)] = &[
    // x86 / x86-64: PLT derived from `.plt` size == (n + 1) * 16.
    ("elf-x64-bash-v4.1.5.1", "printf", 0x6d9228, Some(0x41e470)),
    ("elf-x64-bash-v4.1.5.1", "puts", 0x6d92c8, Some(0x41e5b0)),
    ("elf-x64-bash-v4.1.5.1", "execve", 0x6d9580, Some(0x41eb20)),
    (
        "elf-x86-bash-v4.1.5.1",
        "printf",
        0x810a674,
        Some(0x8061c1c),
    ),
    ("elf-x86-bash-v4.1.5.1", "puts", 0x810a71c, Some(0x8061ebc)),
    ("Linux_lib64.so", "puts", 0x3161f8, Some(0x143d0)),
    ("Linux_lib32.so", "puts", 0x1153fc, Some(0xbb60)),
    // ARM / AArch64 / SPARC / RISC-V: PLT from the psABI `st_value`, accepted
    // only because it lands inside `.plt`.
    ("elf-ARM64-bash", "puts", 0x4d6388, Some(0x41c930)),
    ("elf-ARM64-bash", "execve", 0x4d6448, Some(0x41cab0)),
    ("elf-Linux-RISCV_64", "system", 0x12010, Some(0x10540)),
    ("elf-SparcV8-bash", "execve", 0xec65c, Some(0xec65c)),
    // PowerPC leaves `st_value` 0 for imports and its `.plt` holds data, so
    // there is a GOT slot and deliberately no PLT address.
    ("elf-PowerPC-bash", "execve", 0x100f41bc, None),
    ("elf-PPC64-bash", "execve", 0x130678, None),
];

#[test]
fn plt_and_got_addresses_match_the_relocation_table() {
    for &(name, sym, got, plt) in GOT_PLT {
        let b = elf(name);
        let s = b
            .symbol(sym)
            .unwrap_or_else(|| panic!("{name}: no symbol {sym}"));
        assert!(s.is_import, "{name}/{sym}: expected an import");
        assert_eq!(s.got, Some(got), "{name}/{sym}: GOT slot");
        assert_eq!(s.plt, plt, "{name}/{sym}: PLT stub");
    }
}

/// A static binary has no dynamic relocations, so it gets no GOT/PLT — and
/// its `.plt` (IRELATIVE stubs only) must not be mistaken for a symbol PLT.
#[test]
fn a_static_binary_reports_no_plt_or_got() {
    for name in ["elf-Linux-x64", "elf-Linux-x86", "elf-FreeBSD-x86"] {
        let b = elf(name);
        assert!(
            b.symbols()
                .iter()
                .all(|s| s.got.is_none() && s.plt.is_none()),
            "{name}: a static binary has no PLT relocations to read"
        );
    }
}

#[test]
fn rebasing_moves_symbol_got_and_plt_with_the_sections() {
    let mut b = elf("elf-x64-bash-v4.1.5.1");
    let base = b.image_base();
    let before = b.symbol("printf").unwrap().clone();
    b.rebase(0);
    let after = b.symbol("printf").unwrap();
    assert_eq!(after.got, Some(before.got.unwrap() - base));
    assert_eq!(after.plt, Some(before.plt.unwrap() - base));
    assert_eq!(after.addr, 0, "an import with st_value 0 stays 0");

    // ARM64 keeps the PLT stub in st_value, so `addr` must move too.
    let mut a = elf("elf-ARM64-bash");
    let base = a.image_base();
    let before = a.symbol("puts").unwrap().clone();
    a.rebase(0);
    let after = a.symbol("puts").unwrap();
    assert_eq!(after.addr, before.addr - base);
    assert_eq!(after.plt, Some(before.plt.unwrap() - base));
}

// ---------------------------------------------------------------------------
// PE — DllCharacteristics + load config, from `pefile` and a hand-rolled
// optional-header parse that agreed with it byte for byte.
// ---------------------------------------------------------------------------

/// name, DllCharacteristics, aslr, dep, high_entropy_va, guard_cf,
/// cet_compat, (safe_seh, detail), force_integrity
type PeRow = (
    &'static str,
    u16,
    Tri,
    Tri,
    Tri,
    Tri,
    Tri,
    (Tri, Option<&'static str>),
    Tri,
);

const NA: Option<&str> = Some("not-applicable");

#[rustfmt::skip]
const PE_TABLE: &[PeRow] = &[
    // 0x8100 = TERMINAL_SERVER_AWARE | NX_COMPAT. No DYNAMIC_BASE: this
    // Windows 7 32-bit cmd.exe is NOT ASLR-enabled. Load config is 0x48
    // bytes: SEHandlerTable = 0x4ad1bbd8 with SEHandlerCount = 1, and the
    // struct stops short of GuardFlags.
    ("pe-x86-cmd-v6.1.7600", 0x8100, N, Y, N, N, N, (Y, None), N),
    // 0x8140 = TERMINAL_SERVER_AWARE | NX_COMPAT | DYNAMIC_BASE. PE32+ but
    // HIGH_ENTROPY_VA (0x20) is clear. No load-config directory at all.
    ("pe-x64-cmd-v6.1.7601", 0x8140, Y, Y, N, N, N, (Y, NA), N),
    // ARMNT: SEH is table-driven, so SafeSEH is not applicable.
    ("pe-Windows-ARMv7-Thumb2LE-HelloWorld", 0x8140, Y, Y, N, N, N, (Y, NA), N),
];

#[test]
fn pe_mitigations_match_the_independent_header_parse() {
    for &(name, dc, aslr, dep, hev, cfg, cet, seh, fi) in PE_TABLE {
        let b = match Binary::load(&fixture(name)) {
            Ok(LoadedBinary::Pe(p)) => p,
            other => panic!("{name}: expected PE, got {other:?}"),
        };
        assert_eq!(b.dll_characteristics(), dc, "{name}: DllCharacteristics");
        let m = b.mitigations();
        assert_eq!(
            m.names(),
            vec![
                mit::ASLR,
                mit::DEP,
                mit::HIGH_ENTROPY_VA,
                mit::GUARD_CF,
                mit::CET_COMPAT,
                mit::SAFE_SEH,
                mit::FORCE_INTEGRITY
            ],
            "{name}: report keys"
        );
        check(m, mit::ASLR, aslr, None, name);
        check(m, mit::DEP, dep, None, name);
        check(m, mit::HIGH_ENTROPY_VA, hev, None, name);
        check(m, mit::GUARD_CF, cfg, None, name);
        check(m, mit::CET_COMPAT, cet, None, name);
        check(m, mit::SAFE_SEH, seh.0, seh.1, name);
        check(m, mit::FORCE_INTEGRITY, fi, None, name);
        // The legacy accessor and the new report must never disagree.
        assert_eq!(
            b.guard_cf(),
            m.enabled(mit::GUARD_CF).is_yes(),
            "{name}: guard_cf()"
        );
    }
}

/// CRIT-01: the CFG bit and the CET marking are different fields in
/// different directories, and every fixture here has neither.
#[test]
fn pe_cet_is_reported_separately_from_guard_cf() {
    for row in PE_TABLE {
        let name = row.0;
        let b = match Binary::load(&fixture(name)) {
            Ok(LoadedBinary::Pe(p)) => p,
            _ => unreachable!(),
        };
        let cet = b.mitigations().get(mit::CET_COMPAT).unwrap();
        assert_eq!(cet.enabled, Enabled::No);
        assert!(
            cet.evidence.contains("EX_DLLCHARACTERISTICS") && cet.evidence.contains("shadow stack"),
            "{name}: {}",
            cet.evidence
        );
    }
}

/// The x86 fixture is the one with a load-config directory; it must be read,
/// and its truncation past `SEHandlerCount` must be reported as such.
#[test]
fn pe_load_config_is_read_and_its_limits_stated() {
    let b = match Binary::load(&fixture("pe-x86-cmd-v6.1.7600")) {
        Ok(LoadedBinary::Pe(p)) => p,
        _ => unreachable!(),
    };
    let seh = b.mitigations().get(mit::SAFE_SEH).unwrap();
    assert!(
        seh.evidence.contains("SEHandlerTable=0x4ad1bbd8")
            && seh.evidence.contains("SEHandlerCount=1"),
        "{}",
        seh.evidence
    );
    let cfg = b.mitigations().get(mit::GUARD_CF).unwrap();
    assert!(
        cfg.evidence.contains("0x48") && cfg.evidence.contains("stops short of GuardFlags"),
        "{}",
        cfg.evidence
    );
    // The x64 fixture has no load-config directory at all, and says so.
    let b = match Binary::load(&fixture("pe-x64-cmd-v6.1.7601")) {
        Ok(LoadedBinary::Pe(p)) => p,
        _ => unreachable!(),
    };
    assert!(b
        .mitigations()
        .get(mit::GUARD_CF)
        .unwrap()
        .evidence
        .contains("no load-config directory"));
}

// ---------------------------------------------------------------------------
// Mach-O — header flags and the code-signature SuperBlob.
// ---------------------------------------------------------------------------

/// name, header flags, pie(+detail), nx_stack, nx_heap, code_signature,
/// hardened_runtime
type MachRow = (
    &'static str,
    u32,
    (Tri, Option<&'static str>),
    Tri,
    Tri,
    Tri,
    Tri,
);

const MACHO_TABLE: &[MachRow] = &[
    // MH_EXECUTE, flags 0x1200085 = MH_PIE | MH_NO_HEAP_EXECUTION | …,
    // LC_CODE_SIGNATURE present, CodeDirectory v0x20100 flags 0x0.
    ("macho-x86-ls", 0x0120_0085, (Y, PIEX), Y, Y, Y, N),
    ("macho-x64-ls", 0x0020_0085, (Y, PIEX), Y, Y, Y, N),
    // 32-bit PowerPC MH_EXECUTE, flags 0x85: no MH_PIE, no
    // MH_NO_HEAP_EXECUTION, and no LC_CODE_SIGNATURE at all — so hardened
    // runtime is unknown, not false.
    ("macho-ppc-openssl", 0x85, (N, EXEC), Y, N, N, U),
];

#[test]
fn macho_mitigations_match_the_independent_header_parse() {
    for &(name, flags, pie, nx_stack, nx_heap, cs, hardened) in MACHO_TABLE {
        let b = match Binary::load(&fixture(name)) {
            Ok(LoadedBinary::MachO(m)) => m,
            other => panic!("{name}: expected Mach-O, got {other:?}"),
        };
        let m = b.mitigations();
        assert_eq!(
            m.names(),
            vec![
                mit::PIE,
                mit::NX_STACK,
                mit::NX_HEAP,
                mit::CODE_SIGNATURE,
                mit::HARDENED_RUNTIME
            ],
            "{name}: report keys"
        );
        // The evidence quotes the flags word, so a wrong read cannot pass.
        assert!(
            m.get(mit::PIE)
                .unwrap()
                .evidence
                .contains(&format!("flags={flags:#x}")),
            "{name}: {}",
            m.get(mit::PIE).unwrap().evidence
        );
        check(m, mit::PIE, pie.0, pie.1, name);
        check(m, mit::NX_STACK, nx_stack, None, name);
        check(m, mit::NX_HEAP, nx_heap, None, name);
        check(m, mit::CODE_SIGNATURE, cs, None, name);
        check(m, mit::HARDENED_RUNTIME, hardened, None, name);
    }
}

/// A fat binary reports per slice. Both `libSystem` slices are `MH_DYLIB`
/// with flags 0x85 — no `MH_PIE` — yet both are position independent, and
/// only the 32-bit one can answer the heap question from a flag.
#[test]
fn universal_slices_report_independently() {
    let u = match Binary::load(&fixture("UNIVERSAL-x86-x64-libSystem.B.dylib")) {
        Ok(LoadedBinary::Universal(u)) => u,
        other => panic!("expected Universal, got {other:?}"),
    };
    assert_eq!(u.slices().len(), 2);
    for (i, s) in u.slices().iter().enumerate() {
        let ctx = format!("slice{i} {}", s.arch().slice_name());
        let m = s.mitigations();
        check(m, mit::PIE, Y, DSO, &ctx);
        check(m, mit::NX_STACK, Y, None, &ctx);
        check(m, mit::CODE_SIGNATURE, Y, None, &ctx);
        check(m, mit::HARDENED_RUNTIME, N, None, &ctx);
    }
    // slice 0 is x86_64, slice 1 is i386 (fat header order).
    check(u.slices()[0].mitigations(), mit::NX_HEAP, Y, None, "slice0");
    check(u.slices()[1].mitigations(), mit::NX_HEAP, N, None, "slice1");
    assert!(u.slices()[1]
        .mitigations()
        .get(mit::NX_HEAP)
        .unwrap()
        .evidence
        .contains("MH_NO_HEAP_EXECUTION"));
}

// ---------------------------------------------------------------------------
// Raw
// ---------------------------------------------------------------------------

#[test]
fn a_raw_blob_reports_nothing_and_says_why() {
    let b = RawBinary::new(
        &fixture("raw-x86.raw"),
        rf_core::Arch::X86,
        rf_core::Endianness::Little,
    );
    let m = b.mitigations();
    assert!(m.is_empty());
    let note = m.note().expect("an empty report must carry a reason");
    assert!(note.contains("no container headers"), "{note}");
    // A missing key reads as unknown, never as "mitigation off".
    assert_eq!(m.enabled(mit::NX), Enabled::Unknown);
}

// ---------------------------------------------------------------------------
// Invariants that hold for every fixture, whatever its format.
// ---------------------------------------------------------------------------

#[test]
fn every_report_on_every_fixture_is_non_empty_and_fully_evidenced() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut seen = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let loaded = match Binary::load(&bytes) {
            Ok(l) => l,
            Err(_) => continue,
        };
        let reports: Vec<&Mitigations> = match loaded {
            LoadedBinary::Elf(ref e) => vec![e.mitigations()],
            LoadedBinary::Pe(ref p) => vec![p.mitigations()],
            LoadedBinary::MachO(ref m) => vec![m.mitigations()],
            LoadedBinary::Universal(ref u) => u.slices().iter().map(|s| s.mitigations()).collect(),
            LoadedBinary::Raw(_) => continue,
        };
        for m in reports {
            seen += 1;
            assert!(!m.is_empty(), "{name}: empty report");
            assert!(
                m.note().is_none(),
                "{name}: a populated report needs no note"
            );
            for (k, v) in m.iter() {
                assert!(
                    v.evidence.len() > 20,
                    "{name}/{k}: evidence is too thin to act on: {:?}",
                    v.evidence
                );
                assert!(
                    v.detail.as_deref() != Some(""),
                    "{name}/{k}: empty detail should be None"
                );
            }
        }
    }
    // 16 ELF + 3 PE + 3 Mach-O + 2 fat slices.
    assert_eq!(seen, 24, "fixture coverage");
}
