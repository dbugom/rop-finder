//! Symbol enumeration (ECO-06).
//!
//! ELF `imports` used to be hardcoded empty, so there was no dynsym / PLT /
//! GOT enumeration and therefore no ret2plt or ret2libc symbol resolution —
//! the thing `elf.plt['system']` and `elf.got` make a one-liner in pwntools.
//! [`ElfBinary::symbols`](crate::ElfBinary::symbols) now returns the real
//! tables, and every imported function carries the GOT slot the dynamic
//! linker patches.
//!
//! Addresses here live in the same address space as
//! [`Section::vaddr`](crate::Section) and are shifted by `rebase`, so
//! `--base 0` yields RVAs for symbols exactly as it does for sections.

/// Which table a symbol came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolTable {
    /// ELF `.dynsym` — the table the dynamic linker uses. This is the one
    /// that survives `strip`, and the only one a stripped binary has.
    Dynamic,
    /// ELF `.symtab` — the full static table, removed by `strip`.
    Static,
}

impl SymbolTable {
    /// `"dynsym"` / `"symtab"`, matching what `readelf -s` calls them.
    pub fn as_str(self) -> &'static str {
        match self {
            SymbolTable::Dynamic => "dynsym",
            SymbolTable::Static => "symtab",
        }
    }
}

// ELF `STT_*` symbol types (`elf.h`).
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;
const STT_COMMON: u8 = 5;
const STT_TLS: u8 = 6;
const STT_GNU_IFUNC: u8 = 10;

// ELF `STB_*` bindings.
const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

/// One symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Symbol name. Never empty — unnamed entries (including the mandatory
    /// index-0 entry) are dropped.
    pub name: String,
    /// `st_value`, rebased with the image.
    ///
    /// `0` for an import on x86, x86-64 and PowerPC. On ARM, AArch64, SPARC
    /// and RISC-V the psABI lets an `SHN_UNDEF` symbol carry the address of
    /// its PLT stub here instead, which is why this is not assumed to be
    /// zero for imports — and why [`plt`](Self::plt) mirrors it when the
    /// value provably lands inside `.plt`.
    pub addr: u64,
    /// `st_size`.
    pub size: u64,
    /// ELF `STT_*` type: 0 NOTYPE, 1 OBJECT, 2 FUNC, 3 SECTION, 4 FILE,
    /// 5 COMMON, 6 TLS, 10 GNU_IFUNC.
    pub sym_type: u8,
    /// ELF `STB_*` binding: 0 LOCAL, 1 GLOBAL, 2 WEAK.
    pub binding: u8,
    /// `SHN_UNDEF` with a name — a reference this image expects some other
    /// object to define. This is the `imports` list.
    pub is_import: bool,
    /// Which table it came from.
    pub table: SymbolTable,
    /// Address of the GOT slot the dynamic linker writes for this symbol,
    /// taken from the `r_offset` of the `DT_JMPREL` relocation that names
    /// it. `None` when the symbol has no PLT relocation. Exact — it is a
    /// relocation field, not a guess.
    pub got: Option<u64>,
    /// Address of the PLT stub that jumps through [`got`](Self::got).
    ///
    /// `None` unless it can be derived *exactly*; see
    /// [`ElfBinary::symbols`](crate::ElfBinary::symbols) for the conditions.
    /// A wrong PLT address silently produces a chain that jumps into the
    /// middle of a stub, so this field guesses at nothing.
    pub plt: Option<u64>,
}

impl Symbol {
    /// `STT_FUNC` or `STT_GNU_IFUNC`.
    pub fn is_function(&self) -> bool {
        self.sym_type == STT_FUNC || self.sym_type == STT_GNU_IFUNC
    }

    /// `readelf -s`-style type name (`FUNC`, `OBJECT`, …).
    pub fn type_name(&self) -> &'static str {
        match self.sym_type {
            STT_NOTYPE => "NOTYPE",
            STT_OBJECT => "OBJECT",
            STT_FUNC => "FUNC",
            STT_SECTION => "SECTION",
            STT_FILE => "FILE",
            STT_COMMON => "COMMON",
            STT_TLS => "TLS",
            STT_GNU_IFUNC => "IFUNC",
            _ => "OTHER",
        }
    }

    /// `readelf -s`-style binding name (`GLOBAL`, `WEAK`, …).
    pub fn binding_name(&self) -> &'static str {
        match self.binding {
            STB_LOCAL => "LOCAL",
            STB_GLOBAL => "GLOBAL",
            STB_WEAK => "WEAK",
            _ => "OTHER",
        }
    }

    /// Shift every address this symbol carries by `delta`.
    ///
    /// An import whose `st_value` is 0 keeps it — that is "no address", not
    /// "address zero", and moving it would invent one. An import with a
    /// nonzero `st_value` (the ARM/SPARC/RISC-V PLT-stub convention) does
    /// move: that address is in this image.
    pub(crate) fn rebase(&mut self, delta: u64) {
        if !self.is_import || self.addr != 0 {
            self.addr = self.addr.wrapping_add(delta);
        }
        if let Some(g) = self.got.as_mut() {
            *g = g.wrapping_add(delta);
        }
        if let Some(p) = self.plt.as_mut() {
            *p = p.wrapping_add(delta);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sym(is_import: bool, addr: u64) -> Symbol {
        Symbol {
            name: "system".into(),
            addr,
            size: 0,
            sym_type: STT_FUNC,
            binding: STB_GLOBAL,
            is_import,
            table: SymbolTable::Dynamic,
            got: Some(0x601018),
            plt: Some(0x400560),
        }
    }

    #[test]
    fn rebase_moves_got_and_plt_but_never_a_zero_import_value() {
        let mut s = sym(true, 0);
        s.rebase(0x1000);
        assert_eq!(s.addr, 0, "st_value 0 means 'no address', not 'address 0'");
        assert_eq!(s.got, Some(0x602018));
        assert_eq!(s.plt, Some(0x401560));

        let mut d = sym(false, 0x400500);
        d.rebase(0x1000);
        assert_eq!(d.addr, 0x401500);

        // ARM/SPARC/RISC-V put the PLT stub in an import's st_value; that
        // address is in this image, so it moves.
        let mut arm = sym(true, 0x41c930);
        arm.rebase(0x1000);
        assert_eq!(arm.addr, 0x41d930);
    }

    #[test]
    fn type_and_binding_names_match_readelf() {
        let mut s = sym(false, 0x10);
        assert_eq!(s.type_name(), "FUNC");
        assert_eq!(s.binding_name(), "GLOBAL");
        assert!(s.is_function());
        s.sym_type = STT_GNU_IFUNC;
        assert_eq!(s.type_name(), "IFUNC");
        assert!(s.is_function());
        s.sym_type = STT_OBJECT;
        assert!(!s.is_function());
        assert_eq!(s.type_name(), "OBJECT");
        s.binding = STB_WEAK;
        assert_eq!(s.binding_name(), "WEAK");
        assert_eq!(SymbolTable::Dynamic.as_str(), "dynsym");
        assert_eq!(SymbolTable::Static.as_str(), "symtab");
    }
}
