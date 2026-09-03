//! ELF mitigation and symbol readers (ECO-06).
//!
//! Split out of `elf.rs` so the header-reading rules live in one auditable
//! place. Everything here is a pure function of the parsed headers; nothing
//! disassembles, probes or guesses.
//!
//! The expected values for every fixture were derived independently with
//! `pyelftools` (a different implementation from goblin) and are pinned in
//! `crates/rf-core/tests/mitigations.rs`, so a regression in this file fails
//! a test rather than quietly changing what the tool tells an agent.

use goblin::elf::dynamic::{
    DF_1_NOW, DF_1_PIE, DF_BIND_NOW, DT_BIND_NOW, DT_DEBUG, DT_FLAGS, DT_FLAGS_1, DT_RPATH,
    DT_RUNPATH,
};
use goblin::elf::header::{et_to_str, ET_DYN, ET_EXEC};
use goblin::elf::program_header::{PF_R, PF_W, PF_X, PT_GNU_RELRO, PT_GNU_STACK};

use crate::mitigations::{Enabled, Mitigation, Mitigations};
use crate::symbols::{Symbol, SymbolTable};
use crate::{Arch, Section};

/// `SHN_UNDEF` — the section index of a symbol this image does not define.
const SHN_UNDEF: usize = 0;

/// What `collect` produces: the report plus the symbol tables.
pub(crate) struct ElfInfo {
    pub(crate) mitigations: Mitigations,
    pub(crate) symbols: Vec<Symbol>,
}

/// Render `p_flags` the way `readelf -l` does.
fn perm_str(flags: u32) -> String {
    let mut s = String::with_capacity(3);
    s.push(if flags & PF_R != 0 { 'R' } else { ' ' });
    s.push(if flags & PF_W != 0 { 'W' } else { ' ' });
    s.push(if flags & PF_X != 0 { 'E' } else { ' ' });
    s.trim().to_string()
}

/// Join at most `max` names for an evidence string, deterministically.
fn sample(names: &[String], max: usize) -> String {
    let shown: Vec<&str> = names.iter().take(max).map(String::as_str).collect();
    if names.len() > max {
        format!("{}, … ({} total)", shown.join(", "), names.len())
    } else {
        shown.join(", ")
    }
}

/// Read every mitigation and every symbol out of an already-parsed ELF.
pub(crate) fn collect(elf: &goblin::elf::Elf, sections: &[Section], arch: Arch) -> ElfInfo {
    let symbols = collect_symbols(elf, sections, arch);
    let mitigations = collect_mitigations(elf, &symbols);
    ElfInfo {
        mitigations,
        symbols,
    }
}

// ---------------------------------------------------------------------------
// Symbols
// ---------------------------------------------------------------------------

fn collect_symbols(elf: &goblin::elf::Elf, sections: &[Section], arch: Arch) -> Vec<Symbol> {
    // `DT_JMPREL` — the PLT relocations. Every entry names a `.dynsym` index
    // in `r_sym` and the GOT cell the dynamic linker patches in `r_offset`.
    // Entries with `r_sym == 0` (`R_*_IRELATIVE`) name no symbol.
    //
    // The map is keyed by dynsym index and holds `(slot position, r_offset)`.
    // The position is the relocation's index in `DT_JMPREL` INCLUDING the
    // `r_sym == 0` entries, which still occupy a PLT slot — dropping them
    // would shift every later stub address.
    let mut n_plt_slots = 0usize;
    let mut plt_slot: std::collections::HashMap<usize, (usize, u64)> =
        std::collections::HashMap::new();
    for (i, r) in elf.pltrelocs.iter().enumerate() {
        n_plt_slots = i + 1;
        if r.r_sym != 0 {
            plt_slot.entry(r.r_sym).or_insert((i, r.r_offset));
        }
    }
    let plt_base = plt_stub_base(sections, arch, n_plt_slots);
    let plt_range = sections
        .iter()
        .find(|s| s.name == ".plt")
        .map(|s| (s.vaddr, s.vaddr.saturating_add(s.size)));

    let mut out = Vec::with_capacity(elf.dynsyms.len() + elf.syms.len());
    push_table(
        &mut out,
        &elf.dynsyms,
        &elf.dynstrtab,
        SymbolTable::Dynamic,
        &plt_slot,
        plt_base,
        plt_range,
    );
    push_table(
        &mut out,
        &elf.syms,
        &elf.strtab,
        SymbolTable::Static,
        &std::collections::HashMap::new(),
        None,
        plt_range,
    );
    out
}

/// Where the PLT stub for relocation `idx` lives, and how wide a stub is.
///
/// Returned as `Some((base, stride, skip_plt0))` only when the layout is
/// known *exactly*. A wrong PLT address produces a chain that jumps into the
/// middle of a stub, so this refuses rather than approximates:
///
/// * only x86 and x86-64, whose PLT entry is a fixed 16 bytes. Every other
///   architecture in this tool (ARM, ARM64, MIPS, PowerPC, SPARC, RISC-V)
///   has a variable or differently-sized stub, and several put the callable
///   stub somewhere other than `.plt` entirely — SPARC's is 12 bytes,
///   PowerPC32's `.plt` holds data, not code.
/// * the size check is the proof: a classic `.plt` is exactly
///   `(n + 1) * 16` bytes (one `PLT0` push/jmp header plus one stub per
///   relocation). A `-z now` + IBT link instead emits `.plt.sec` at exactly
///   `n * 16` bytes with no header, and *that* is the callable stub. If
///   neither size matches to the byte, no PLT address is reported.
///
/// Verified against the fixture bytes: for `elf-x64-bash-v4.1.5.1` the
/// derived stub for `printf` (relocation 4) is `0x41e470`, whose first
/// instruction is `ff 25 b2 ad 2b 00` = `jmp qword [rip+0x2badb2]` =
/// `jmp [0x6d9228]`, and `0x6d9228` is exactly that relocation's `r_offset`.
fn plt_stub_base(sections: &[Section], arch: Arch, n_relocs: usize) -> Option<(u64, u64, bool)> {
    if n_relocs == 0 || !arch.is_x86_family() {
        return None;
    }
    const STRIDE: u64 = 16;
    let n = n_relocs as u64;
    let find = |name: &str| sections.iter().find(|s| s.name == name);
    // Modern `-z now` layout: `.plt.sec` holds the callable stubs, one per
    // relocation, with no PLT0 header.
    if let Some(sec) = find(".plt.sec") {
        if sec.size == n * STRIDE {
            return Some((sec.vaddr, STRIDE, false));
        }
    }
    if let Some(plt) = find(".plt") {
        if plt.size == (n + 1) * STRIDE {
            return Some((plt.vaddr, STRIDE, true));
        }
    }
    None
}

fn push_table(
    out: &mut Vec<Symbol>,
    table: &goblin::elf::Symtab<'_>,
    strtab: &goblin::strtab::Strtab<'_>,
    which: SymbolTable,
    plt_slot: &std::collections::HashMap<usize, (usize, u64)>,
    plt_base: Option<(u64, u64, bool)>,
    plt_range: Option<(u64, u64)>,
) {
    for (idx, sym) in table.iter().enumerate() {
        let name = strtab.get_at(sym.st_name).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        let is_import = sym.st_shndx == SHN_UNDEF;
        let mut got = None;
        let mut plt = None;
        if let Some(&(pos, r_offset)) = plt_slot.get(&idx) {
            got = Some(r_offset);
            plt = plt_base
                .map(|(base, stride, skip0)| base + (pos as u64 + u64::from(skip0)) * stride);
        }
        // The second, ABI-given source of a PLT address, used only where the
        // x86 derivation above produced nothing. The ARM, AArch64, SPARC and
        // RISC-V psABIs let an `SHN_UNDEF` symbol carry the address of its
        // PLT stub in `st_value` (x86 and PowerPC leave it 0). Accepting it
        // blind would be a guess, so it is taken only when the value lands
        // inside `.plt` — a containment proof against the section table.
        // Measured on the fixtures: this recovers 201 of 205 stubs on
        // elf-ARM64-bash, 110 of 115 on elf-ARMv7-ls, 196 of 198 on
        // elf-SparcV8-bash and 12 of 12 on elf-Linux-RISCV_64, while
        // correctly rejecting both nonzero-`st_value` imports of
        // elf-PowerPC-bash, which point outside `.plt`.
        if plt.is_none() && is_import && sym.st_value != 0 {
            if let Some((lo, hi)) = plt_range {
                if sym.st_value >= lo && sym.st_value < hi {
                    plt = Some(sym.st_value);
                }
            }
        }
        out.push(Symbol {
            name: name.to_string(),
            addr: sym.st_value,
            size: sym.st_size,
            sym_type: sym.st_type(),
            binding: sym.st_bind(),
            is_import,
            table: which,
            got,
            plt,
        });
    }
}

// ---------------------------------------------------------------------------
// Mitigations
// ---------------------------------------------------------------------------

/// The dynamic-section facts the mitigation readers need, gathered once.
struct DynFacts {
    present: bool,
    debug: bool,
    bind_now: bool,
    flags: u64,
    flags_1: u64,
    rpath: Option<String>,
    runpath: Option<String>,
}

fn dyn_facts(elf: &goblin::elf::Elf) -> DynFacts {
    let mut f = DynFacts {
        present: elf.dynamic.is_some(),
        debug: false,
        bind_now: false,
        flags: 0,
        flags_1: 0,
        rpath: None,
        runpath: None,
    };
    let Some(dynamic) = elf.dynamic.as_ref() else {
        return f;
    };
    for d in &dynamic.dyns {
        match d.d_tag {
            DT_DEBUG => f.debug = true,
            DT_BIND_NOW => f.bind_now = true,
            DT_FLAGS => f.flags = d.d_val,
            DT_FLAGS_1 => f.flags_1 = d.d_val,
            DT_RPATH => {
                f.rpath = elf
                    .dynstrtab
                    .get_at(d.d_val as usize)
                    .map(str::to_string)
                    .or_else(|| Some(String::new()))
            }
            DT_RUNPATH => {
                f.runpath = elf
                    .dynstrtab
                    .get_at(d.d_val as usize)
                    .map(str::to_string)
                    .or_else(|| Some(String::new()))
            }
            _ => {}
        }
    }
    f
}

fn collect_mitigations(elf: &goblin::elf::Elf, symbols: &[Symbol]) -> Mitigations {
    let d = dyn_facts(elf);
    let mut m = Mitigations::default();
    m.push(crate::mitigations::NX, nx(elf));
    m.push(crate::mitigations::PIE, pie(elf, &d));
    m.push(crate::mitigations::RELRO, relro(elf, &d));
    m.push(crate::mitigations::CANARY, canary(symbols));
    m.push(crate::mitigations::FORTIFY, fortify(&d, symbols));
    m.push(
        crate::mitigations::RPATH,
        path_tag("DT_RPATH", &d.rpath, &d),
    );
    m.push(
        crate::mitigations::RUNPATH,
        path_tag("DT_RUNPATH", &d.runpath, &d),
    );
    m
}

fn nx(elf: &goblin::elf::Elf) -> Mitigation {
    match elf
        .program_headers
        .iter()
        .find(|p| p.p_type == PT_GNU_STACK)
    {
        Some(ph) => {
            let exec = ph.p_flags & PF_X != 0;
            Mitigation::new(
                Enabled::from(!exec),
                format!(
                    "PT_GNU_STACK p_flags={:#x} ({}): the kernel maps the stack {}executable",
                    ph.p_flags,
                    perm_str(ph.p_flags),
                    if exec { "" } else { "non-" }
                ),
            )
        }
        None => Mitigation::new(
            Enabled::Unknown,
            "no PT_GNU_STACK program header: the file does not state its stack permission, so \
             the kernel's ABI default applies (historically executable on Linux, via \
             READ_IMPLIES_EXEC). checksec.sh reports 'NX enabled' here because it only greps \
             for a GNU_STACK line carrying RWE, which is a guess.",
        ),
    }
}

fn pie(elf: &goblin::elf::Elf, d: &DynFacts) -> Mitigation {
    let et = elf.header.e_type;
    if et == ET_EXEC {
        return Mitigation::new(
            Enabled::No,
            "e_type=ET_EXEC: the image declares a fixed load address, so every address in it \
             is absolute and ASLR does not move the module",
        )
        .with_detail("fixed-address-executable");
    }
    if et != ET_DYN {
        return Mitigation::new(
            Enabled::Unknown,
            format!(
                "e_type={}: neither ET_EXEC nor ET_DYN, so position independence is not a \
                 property of this file",
                et_to_str(et)
            ),
        );
    }
    // ET_DYN alone does NOT distinguish a PIE executable from a shared
    // library — both are ET_DYN. Three markers separate them, strongest
    // first. All three are set by the *link editor* for executables only.
    if d.flags_1 & DF_1_PIE != 0 {
        return Mitigation::new(
            Enabled::Yes,
            format!(
                "e_type=ET_DYN with DT_FLAGS_1={:#x} & DF_1_PIE ({DF_1_PIE:#x}): the link \
                 editor marked this ET_DYN explicitly as a position-independent executable, \
                 not a shared library",
                d.flags_1
            ),
        )
        .with_detail("pie-executable");
    }
    if let Some(interp) = elf.interpreter {
        return Mitigation::new(
            Enabled::Yes,
            format!(
                "e_type=ET_DYN with PT_INTERP '{interp}': ET_DYN alone cannot tell a PIE \
                 executable from a shared library, but only an executable names a program \
                 interpreter, so this is a PIE executable"
            ),
        )
        .with_detail("pie-executable");
    }
    if d.debug {
        return Mitigation::new(
            Enabled::Yes,
            "e_type=ET_DYN with a DT_DEBUG entry: the link editor emits DT_DEBUG only for \
             dynamic executables (it is where the loader stores its r_debug pointer) and never \
             for a shared object, so this ET_DYN is a PIE executable",
        )
        .with_detail("pie-executable");
    }
    Mitigation::new(
        Enabled::Yes,
        "e_type=ET_DYN with no DF_1_PIE, no PT_INTERP and no DT_DEBUG: a shared library. It is \
         still loaded at an arbitrary base, so its addresses are offsets and must be added to a \
         leaked module base. checksec.sh prints 'DSO' for this shape.",
    )
    .with_detail("shared-object")
}

fn relro(elf: &goblin::elf::Elf, d: &DynFacts) -> Mitigation {
    if !elf.program_headers.iter().any(|p| p.p_type == PT_GNU_RELRO) {
        return Mitigation::new(
            Enabled::No,
            "no PT_GNU_RELRO program header: nothing is re-mapped read-only after relocation, \
             so the GOT and .init_array stay writable for the life of the process",
        )
        .with_detail("none");
    }
    let mut why = Vec::new();
    if d.bind_now {
        why.push("DT_BIND_NOW".to_string());
    }
    if d.flags & DF_BIND_NOW != 0 {
        why.push(format!("DT_FLAGS={:#x} & DF_BIND_NOW", d.flags));
    }
    if d.flags_1 & DF_1_NOW != 0 {
        why.push(format!("DT_FLAGS_1={:#x} & DF_1_NOW", d.flags_1));
    }
    if !why.is_empty() {
        return Mitigation::new(
            Enabled::Yes,
            format!(
                "PT_GNU_RELRO present and {}: the loader resolves every PLT entry up front and \
                 then maps the whole GOT read-only",
                why.join(" and ")
            ),
        )
        .with_detail("full");
    }
    if !d.present {
        return Mitigation::new(
            Enabled::Yes,
            "PT_GNU_RELRO present, but the image has no PT_DYNAMIC segment: there is no \
             DT_BIND_NOW to read and no lazy PLT to protect, so full vs partial cannot be \
             decided from bind-now. checksec.sh reports 'Partial RELRO' for this shape.",
        )
        .with_detail("partial");
    }
    Mitigation::new(
        Enabled::Yes,
        "PT_GNU_RELRO present but no DT_BIND_NOW, no DT_FLAGS & DF_BIND_NOW and no DT_FLAGS_1 & \
         DF_1_NOW: binding is lazy, so .got.plt stays writable and remains a valid overwrite \
         target",
    )
    .with_detail("partial")
}

fn canary(symbols: &[Symbol]) -> Mitigation {
    if symbols.is_empty() {
        return Mitigation::new(
            Enabled::Unknown,
            "the image has neither a .dynsym nor a .symtab with named entries: there is no \
             symbol table in which to look __stack_chk_fail up. checksec.sh prints 'No canary \
             found' here, which is indistinguishable from a genuinely unprotected binary.",
        );
    }
    if let Some(s) = symbols
        .iter()
        .find(|s| s.is_import && s.name == "__stack_chk_fail")
    {
        return Mitigation::new(
            Enabled::Yes,
            format!(
                "the image imports __stack_chk_fail (undefined in .{}): the compiler emitted \
                 stack-protector epilogues",
                s.table.as_str()
            ),
        );
    }
    if let Some(s) = symbols.iter().find(|s| {
        !s.is_import
            && (s.name == "__stack_chk_fail"
                || s.name == "__stack_chk_fail_local"
                || s.name == "__stack_chk_guard")
    }) {
        return Mitigation::new(
            Enabled::Yes,
            format!(
                "'{}' is defined in .{}: a static link only pulls that object out of libc when \
                 something references it, so the stack protector is in use",
                s.name,
                s.table.as_str()
            ),
        );
    }
    Mitigation::new(
        Enabled::No,
        format!(
            "no reference to __stack_chk_fail in any of the {} named symbols this image carries",
            symbols.len()
        ),
    )
}

fn fortify(d: &DynFacts, symbols: &[Symbol]) -> Mitigation {
    let imported: Vec<String> = collect_chk(symbols, true);
    if !imported.is_empty() {
        return Mitigation::new(
            Enabled::Yes,
            format!(
                "the image imports {} fortified libc entry point(s): {}",
                imported.len(),
                sample(&imported, 6)
            ),
        )
        .with_detail(imported.join(","));
    }
    if d.present {
        let n_dyn = symbols
            .iter()
            .filter(|s| s.table == SymbolTable::Dynamic)
            .count();
        if n_dyn == 0 {
            return Mitigation::new(
                Enabled::Unknown,
                "the image is dynamically linked but carries no named .dynsym entries, so its \
                 imports cannot be examined for __*_chk entry points",
            );
        }
        return Mitigation::new(
            Enabled::No,
            format!("none of the {n_dyn} dynamic symbols is a __*_chk fortified libc entry point"),
        );
    }
    let defined: Vec<String> = collect_chk(symbols, false);
    if defined.is_empty() {
        return Mitigation::new(
            Enabled::No,
            "statically linked, and no __*_chk symbol is present at all",
        );
    }
    Mitigation::new(
        Enabled::Unknown,
        format!(
            "statically linked: {} __*_chk symbol(s) ({}) are DEFINED here, which proves only \
             that the libc linked in provides fortified variants — a fortified call site leaves \
             no relocation behind in a static link, so the file cannot say whether this \
             program's own code was compiled with -D_FORTIFY_SOURCE",
            defined.len(),
            sample(&defined, 6)
        ),
    )
    .with_detail(defined.join(","))
}

/// `__*_chk` names, deduplicated and sorted so evidence strings are stable.
fn collect_chk(symbols: &[Symbol], imports_only: bool) -> Vec<String> {
    let mut v: Vec<String> = symbols
        .iter()
        .filter(|s| s.is_import == imports_only && s.name.ends_with("_chk"))
        .map(|s| s.name.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

fn path_tag(tag: &str, value: &Option<String>, d: &DynFacts) -> Mitigation {
    match value {
        Some(v) => Mitigation::new(Enabled::Yes, format!("{tag} = '{v}'")).with_detail(v.clone()),
        None if d.present => Mitigation::new(Enabled::No, format!("no {tag} dynamic entry")),
        None => Mitigation::new(
            Enabled::No,
            format!("the image has no PT_DYNAMIC segment, so it can carry no {tag}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perm_str_matches_readelf_spelling() {
        assert_eq!(perm_str(PF_R | PF_W), "RW");
        assert_eq!(perm_str(PF_R | PF_W | PF_X), "RWE");
        assert_eq!(perm_str(PF_R), "R");
    }

    #[test]
    fn sample_is_bounded_and_states_the_total() {
        let v: Vec<String> = (0..10).map(|i| format!("s{i}")).collect();
        assert_eq!(sample(&v, 3), "s0, s1, s2, … (10 total)");
        assert_eq!(sample(&v[..2], 3), "s0, s1");
        assert_eq!(sample(&[], 3), "");
    }

    #[test]
    fn plt_base_refuses_every_shape_it_cannot_prove() {
        let sec = |name: &str, vaddr: u64, size: u64| Section {
            name: name.to_string(),
            vaddr,
            offset: 0,
            size,
            bytes: Vec::new(),
            executable: true,
            writable: false,
            allocated: true,
        };
        // Classic layout: (n + 1) * 16, PLT0 skipped.
        let s = vec![sec(".plt", 0x1000, (3 + 1) * 16)];
        assert_eq!(plt_stub_base(&s, Arch::X64, 3), Some((0x1000, 16, true)));
        // Size that does not match to the byte: refuse.
        let s = vec![sec(".plt", 0x1000, 0xc0)];
        assert_eq!(plt_stub_base(&s, Arch::X64, 0), None);
        assert_eq!(plt_stub_base(&s, Arch::X64, 3), None);
        // `-z now` + IBT layout: `.plt.sec`, n * 16, no PLT0.
        let s = vec![
            sec(".plt", 0x1000, (3 + 1) * 16),
            sec(".plt.sec", 0x2000, 3 * 16),
        ];
        assert_eq!(plt_stub_base(&s, Arch::X86, 3), Some((0x2000, 16, false)));
        // Non-x86: the stub width is not 16 bytes, so refuse.
        let s = vec![sec(".plt", 0x1000, (3 + 1) * 16)];
        assert_eq!(plt_stub_base(&s, Arch::Arm64, 3), None);
        assert_eq!(plt_stub_base(&s, Arch::Ppc32, 3), None);
        // No .plt at all (stripped section headers).
        assert_eq!(plt_stub_base(&[], Arch::X64, 3), None);
    }
}
