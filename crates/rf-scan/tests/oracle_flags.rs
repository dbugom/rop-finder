//! The Phase 2 exit criteria that are ABSOLUTE oracle-matched counts, driven
//! through the ENGINE rather than the CLI.
//!
//! `--align`, the regex `--filter` and `--callPreceded` are engine options in
//! v0.2.0 but are not wired to CLI flags yet (rf-cli is a later wave), so
//! these run `rf_scan::scan_binary` directly and say so.
//!
//! EVERY number below was produced by running the live oracle on this
//! machine, not copied from the plan:
//!
//! ```text
//! $ .venv-oracle/Scripts/python.exe ropgadget/ROPgadget.py \
//!       --binary tests/fixtures/elf-Linux-x86 [FLAGS]
//! (no flags)                             Unique gadgets found: 42508
//! --filter "j.*"                         Unique gadgets found: 13762
//! --filter "op"                          Unique gadgets found: 42508
//! --align 4                              Unique gadgets found: 19240
//! --align 8                              Unique gadgets found:  9136
//! --callPreceded                         Unique gadgets found:  9892
//! --all                                  Unique gadgets found: 68386
//! --only "pop|ret"                       Unique gadgets found:   665
//! --only "pop|ret" --badbytes 00         Unique gadgets found:   663
//! --all --only "pop|ret" --badbytes 00   Unique gadgets found:  8830
//! ```
//!
//! docs/REMEDIATION.md's exit criteria quote 3,967 / 8,547 / 4,392 / 8,461
//! and "narrows 15,587 to 3,966" for the same runs. Those do not reproduce
//! against the pinned oracle (ROPgadget 7.7 @ b6e3fe31af46, python capstone
//! 5.0.7): its unfiltered baseline here is 42,508, not 15,587. The pinned
//! commit's `__gadgetsFinding` is not stock upstream — it has an x86-specific
//! clean-decode branch (`total_size != (end - start)`) that accepts many more
//! candidates than the `total_size != expected_size` rule the other
//! architectures use — which is the most likely source of the ~2.7x gap. The
//! oracle wins: these tests assert what the oracle actually returns.

use std::collections::HashSet;

use rf_core::{Arch, Endianness, Image, Section};
use rf_scan::{scan_binary, Gadget, ScanOptions};

fn fixture(name: &str) -> Vec<u8> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name);
    std::fs::read(p).expect("fixture")
}

fn elf_linux_x86() -> rf_core::ElfBinary {
    rf_core::Binary::parse(&fixture("elf-Linux-x86")).expect("parse")
}

fn count(opts: &ScanOptions) -> usize {
    scan_binary(&elf_linux_x86(), opts).expect("scan").len()
}

fn keys(gadgets: &[Gadget]) -> HashSet<(u64, Vec<u8>)> {
    gadgets.iter().map(|g| (g.vaddr, g.bytes.clone())).collect()
}

/// Baseline: the unfiltered scan the other numbers are relative to.
#[test]
fn baseline_matches_the_oracle() {
    assert_eq!(count(&ScanOptions::default()), 42_508);
}

/// SCAN-01/CLI-02. `--filter "j.*"` is ROPgadget's `(db|int3|j.*)$` matched
/// with `re.match`, i.e. a FULL match against each mnemonic: every gadget
/// containing a `j*` instruction is REJECTED. The old suffix matcher ignored
/// regexes completely and returned the unfiltered 42,508.
#[test]
fn filter_regex_j_star() {
    let o = ScanOptions {
        filter: vec!["j.*".to_string()],
        ..Default::default()
    };
    assert_eq!(count(&o), 13_762);
}

/// SCAN-01/CLI-02. `--filter "op"` matches no x86 mnemonic at all (`pop` is
/// not a full match for `op`), so the oracle returns the SAME SET as an
/// unfiltered run. The old `ends_with` matcher deleted every `pop` gadget.
#[test]
fn filter_op_is_the_unfiltered_set() {
    let o = ScanOptions {
        filter: vec!["op".to_string()],
        ..Default::default()
    };
    let bin = elf_linux_x86();
    let filtered = scan_binary(&bin, &o).unwrap();
    let plain = scan_binary(&bin, &ScanOptions::default()).unwrap();
    assert_eq!(filtered.len(), 42_508);
    assert_eq!(keys(&filtered), keys(&plain), "--filter op must be a no-op");
}

/// ANCH-01/SCAN-05/CLI-10. `--align` is scan-time STEPPING
/// (gadgets.py:73-89), not a filter on byte-stepped starts.
#[test]
fn align_matches_the_oracle() {
    let mut o = ScanOptions {
        align: Some(4),
        ..Default::default()
    };
    assert_eq!(count(&o), 19_240);
    o.align = Some(8);
    assert_eq!(count(&o), 9_136);
    // Every surviving address really is aligned.
    let g = scan_binary(&elf_linux_x86(), &o).unwrap();
    assert!(g.iter().all(|x| x.vaddr % 8 == 0));
    // `--align 0` is falsy in the oracle: identical to no --align.
    o.align = Some(0);
    assert_eq!(count(&o), 42_508);
}

/// SCAN-07/CLI-03. `--all` disables duplicate removal.
#[test]
fn all_disables_dedup() {
    let o = ScanOptions {
        all: true,
        ..Default::default()
    };
    assert_eq!(count(&o), 68_386);
}

/// SCAN-07/CLI-03 in the workflow the finding is actually about: pop/ret
/// gadgets whose address contains no NUL byte. Dedup throws away every
/// duplicate-text gadget BEFORE `--badbytes` runs, so the null-free copy of a
/// gadget is lost with the address that happens to contain a zero;
/// `--all` recovers 663 -> 8,830, a 13.3x difference.
#[test]
fn all_recovers_the_bad_byte_workflow() {
    let mut o = ScanOptions {
        only: Some(vec!["pop".to_string(), "ret".to_string()]),
        badbytes: vec![0x00],
        ..Default::default()
    };
    assert_eq!(count(&o), 663);
    o.all = true;
    assert_eq!(count(&o), 8_830);
}

/// CLI-04/ECO-03. The engine's half is capturing `prev`; the predicate is
/// ROPgadget's six anchored byte patterns (options.py:100-112), which
/// [`rf_scan::is_call_preceded`] implements — including the Python
/// `$`-matches-before-a-trailing-newline quirk that is worth exactly 3
/// gadgets here.
#[test]
fn call_preceded_matches_the_oracle() {
    let o = ScanOptions {
        call_preceded: true,
        ..Default::default()
    };
    let g = scan_binary(&elf_linux_x86(), &o).unwrap();
    assert_eq!(g.len(), 42_508, "capturing prev must not change the set");
    assert!(g.iter().all(|x| x.prev.is_some()));
    // PREV_BYTES = 9 (gadgets.py:57), capped at the start of the section.
    assert!(g.iter().all(|x| x.prev.as_ref().unwrap().len() <= 9));
    assert!(g.iter().any(|x| x.prev.as_ref().unwrap().len() == 9));
    let kept = g
        .iter()
        .filter(|x| rf_scan::is_call_preceded(x.prev.as_deref().unwrap()))
        .count();
    assert_eq!(kept, 9_892, "--callPreceded narrows 42,508 to 9,892");
}

/// SCAN-10: `--range` is applied a second time to the final addresses.
#[test]
fn range_is_applied_to_final_addresses() {
    let o = ScanOptions {
        range: Some((0x0804_8000, 0x0805_0000)),
        ..Default::default()
    };
    let g = scan_binary(&elf_linux_x86(), &o).unwrap();
    assert!(!g.is_empty());
    assert!(g
        .iter()
        .all(|x| (0x0804_8000..=0x0805_0000).contains(&x.vaddr)));
}

/// ANCH-03: SYS search on AArch64 and SPARC used to return nothing at all
/// because ROPgadget's tables are empty there. `elf-ARM64-bash` is
/// dynamically linked and contains no inline `svc`, so this asserts the
/// table itself on a synthetic image — the same route `scan_binary` takes.
struct Buf {
    arch: Arch,
    endian: Endianness,
    regions: Vec<Section>,
}
impl Image for Buf {
    fn arch(&self) -> Arch {
        self.arch
    }
    fn endianness(&self) -> Endianness {
        self.endian
    }
    fn image_base(&self) -> u64 {
        0
    }
    fn entry(&self) -> u64 {
        0
    }
    fn exec_sections(&self) -> Vec<&Section> {
        self.regions.iter().collect()
    }
    fn exec_scan_regions(&self) -> &[Section] {
        &self.regions
    }
    fn rebase(&mut self, _n: u64) {}
}

fn buf(arch: Arch, endian: Endianness, bytes: Vec<u8>) -> Buf {
    Buf {
        arch,
        endian,
        regions: vec![Section {
            name: ".text".into(),
            vaddr: 0x1000,
            offset: 0,
            size: bytes.len() as u64,
            bytes,
            executable: true,
            writable: false,
            allocated: true,
        }],
    }
}

#[test]
fn sys_search_is_not_empty_on_aarch64_and_sparc() {
    let o = ScanOptions {
        rop: false,
        jop: false,
        parallel: false,
        ..Default::default()
    };

    // mov x0, x1 ; svc #0   |   svc #0x1234
    let mut code = vec![0xe0, 0x03, 0x01, 0xaa, 0x01, 0x00, 0x00, 0xd4];
    code.extend_from_slice(&[0x81, 0x46, 0x02, 0xd4]);
    let g = scan_binary(&buf(Arch::Arm64, Endianness::Little, code), &o).unwrap();
    let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
    assert!(texts.iter().any(|t| t == "svc #0"), "{texts:?}");
    assert!(
        texts.iter().any(|t| t == "mov x0, x1 ; svc #0"),
        "{texts:?}"
    );
    assert!(texts.iter().any(|t| t.contains("#0x1234")), "{texts:?}");

    // ta 0x10 ; nop (big-endian SPARC V8) — the Linux syscall gate.
    let code = vec![0x91, 0xd0, 0x20, 0x10, 0x01, 0x00, 0x00, 0x00];
    let g = scan_binary(&buf(Arch::Sparc, Endianness::Big, code), &o).unwrap();
    let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
    assert!(texts.iter().any(|t| t.starts_with("ta ")), "{texts:?}");
}

/// ANCH-06 (rf-scan half): a Thumb-only image is routed to the Thumb anchor
/// tables even without `--thumb`.
#[test]
fn thumb_only_image_uses_thumb_tables() {
    // pop {pc} ; bx lr ; svc #0 — Thumb-2 encodings.
    let code = vec![0x00, 0xbd, 0x70, 0x47, 0x00, 0xdf];
    let o = ScanOptions {
        parallel: false,
        ..Default::default()
    };
    let g = scan_binary(&buf(Arch::ArmThumb, Endianness::Little, code.clone()), &o).unwrap();
    let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
    assert!(texts.iter().any(|t| t == "pop {pc}"), "{texts:?}");
    // ...while a dual-mode ARM ELF still needs --thumb (gadgets.py:331, 448).
    let g = scan_binary(&buf(Arch::Arm, Endianness::Little, code), &o).unwrap();
    assert!(
        g.iter().all(|x| x.text() != "pop {pc}"),
        "{:?}",
        g.iter().map(|x| x.text()).collect::<Vec<_>>()
    );
}
