//! x86/x64 instruction decoding (iced-x86) and the `passCleanX86` port.
//!
//! ROPgadget uses capstone; we use iced-x86. The two decoders disagree on a
//! handful of byte sequences, which is a documented parity-noise source.
//!
//! Performance design: window decodes record a compact, string-free
//! [`WinInsn`] per instruction (no formatter, no allocations). Capstone-style
//! mnemonic strings are computed lazily only for branch-relevant
//! instructions, and full instruction *text* is formatted (FastFormatter)
//! only for accepted candidates — never for the ~5× larger window-instruction
//! population.

use iced_x86::{Code, Decoder, DecoderOptions, FastFormatter, FlowControl, Mnemonic, Register};

/// Accepted last-instruction mnemonics (ROPgadget's `br` list,
/// gadgets.py:44). Membership of the *last* instruction decides validity;
/// membership of any *middle* instruction rejects (unless --multibr).
pub const BRANCH_MNEMONICS: [&str; 15] = [
    "ret",
    "repz ret",
    "retf",
    "int",
    "sysenter",
    "jmp",
    "notrack jmp",
    "call",
    "notrack call",
    "syscall",
    "iret",
    "iretd",
    "iretq",
    "sysret",
    "sysretq",
];

/// Compact per-instruction record inside a decode window. String-free.
#[derive(Debug, Clone, Copy)]
pub struct WinInsn {
    /// Offset (in the scanned buffer) one past this instruction's last byte.
    pub end: usize,
    pub flow: FlowControl,
    pub code: Code,
    pub mnem: Mnemonic,
    pub seg_prefix: Register,
    pub repne: bool,
    pub repe: bool,
}

/// One decoded instruction with text (used by the property tests).
#[derive(Debug, Clone)]
pub struct InsnRec {
    pub end: usize,
    pub mnem: String,
    pub text: String,
}

/// Build the gadget-text formatter. Reuse ONE formatter across candidates
/// (construction is not free). Configured to match capstone's Intel syntax
/// as closely as iced-x86 gets (see README "Semantic notes").
pub fn make_formatter() -> FastFormatter {
    let mut fmt = FastFormatter::new();
    let o = fmt.options_mut();
    o.set_space_after_operand_separator(true);
    // capstone renders RIP-relative operands as "[rip + 0x...]" (keeps gadget
    // text vaddr-dependent — important for text dedup) and always prints
    // memory operand sizes ("nop word ptr [rax]").
    o.set_rip_relative_addresses(true);
    o.set_always_show_memory_size(true);
    o.set_use_hex_prefix(true);
    o.set_uppercase_hex(false);
    fmt
}

/// Capstone-style mnemonic for a window instruction.
///
/// iced-x86's own mnemonic names match capstone's for the ret/int/syscall
/// families, so we only special-case prefix-sensitive branch names:
///  - `f2`-prefixed ret/jmp/call render as "bnd ..." (capstone MPX spelling)
///  - `f3 c3` renders as "repz ret"
///  - `3e`-prefixed indirect jmp/call render as "notrack ..."
pub fn cs_mnemonic(rec: &WinInsn) -> String {
    // Mnemonic implements Debug (not Display); Debug spelling is PascalCase.
    let base = || format!("{:?}", rec.mnem).to_lowercase();
    match rec.flow {
        FlowControl::Return => {
            let base = base();
            if rec.repne {
                format!("bnd {base}")
            } else if rec.repe && base == "ret" {
                "repz ret".to_string()
            } else {
                base
            }
        }
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => branch_name("jmp", rec),
        FlowControl::Call | FlowControl::IndirectCall => branch_name("call", rec),
        _ => base(),
    }
}

fn branch_name(kind: &str, rec: &WinInsn) -> String {
    if rec.repne {
        format!("bnd {kind}")
    } else if rec.seg_prefix == Register::DS {
        format!("notrack {kind}")
    } else {
        kind.to_string()
    }
}

/// Decode a window starting at `start`, recording every instruction boundary
/// until the first undecodable instruction or `max_end` (whichever first).
///
/// iced-x86 yields `Code::INVALID`/`Code::DeclareByte` for undecodable bytes;
/// we stop there, mirroring capstone failing the clean-decode check.
pub fn decode_window(
    code: &[u8],
    start: usize,
    vaddr: u64,
    bits: u32,
    max_end: usize,
) -> Vec<WinInsn> {
    let limit = max_end.min(code.len());
    if start >= limit {
        return Vec::new();
    }
    let slice = &code[start..limit];
    let ip = vaddr.wrapping_add(start as u64);
    let mut decoder = Decoder::with_ip(bits, slice, ip, DecoderOptions::NONE);
    let mut out = Vec::new();
    let mut off = start;
    let mut instr = iced_x86::Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if matches!(instr.code(), Code::INVALID | Code::DeclareByte) {
            break;
        }
        let len = instr.len();
        if len == 0 {
            break;
        }
        off += len;
        out.push(WinInsn {
            end: off,
            flow: instr.flow_control(),
            code: instr.code(),
            mnem: instr.mnemonic(),
            seg_prefix: instr.segment_prefix(),
            repne: instr.has_repne_prefix(),
            repe: instr.has_repe_prefix(),
        });
    }
    out
}

/// Format the instruction texts of an accepted gadget (bytes `start..end`,
/// known to decode cleanly). This re-decodes the short gadget byte range —
/// deliberately, so window decodes never touch the formatter.
pub fn format_gadget(
    code: &[u8],
    start: usize,
    end: usize,
    vaddr: u64,
    bits: u32,
    fmt: &mut FastFormatter,
) -> Vec<String> {
    let slice = &code[start..end];
    let ip = vaddr.wrapping_add(start as u64);
    let mut decoder = Decoder::with_ip(bits, slice, ip, DecoderOptions::NONE);
    let mut out = Vec::new();
    let mut instr = iced_x86::Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if matches!(instr.code(), Code::INVALID | Code::DeclareByte) {
            break;
        }
        let mut text = String::new();
        fmt.format(&instr, &mut text);
        capstone_normalize(&instr, &mut text);
        out.push(text);
    }
    out
}

/// Align FastFormatter output with capstone quirks (both directions of this
/// affect text-keyed dedup, not just cosmetics):
///  - capstone drops segment-override prefixes on instructions WITHOUT a
///    memory operand (`3e c3` → "ret", not "ds ret"); FastFormatter prints
///    them. In 64-bit mode these prefixes are architectural no-ops anyway.
///  - capstone drops rep/repne prefixes except on string ops (`rep movs`)
///    and the ret/jmp/call families (`repz ret`, `bnd jmp`); FastFormatter
///    prints them everywhere (`f2 4e b0 d6` → "repne mov al, 0xd6" vs
///    capstone "mov al, 0xd6").
fn capstone_normalize(instr: &iced_x86::Instruction, text: &mut String) {
    let mnem = format!("{:?}", instr.mnemonic()).to_lowercase();
    // iced's Mnemonic is size-suffixed (Stosb/Stosd/...), capstone's is too.
    let stringop = ["movs", "cmps", "stos", "lods", "scas"].iter().any(|p| mnem.starts_with(p))
        || ["insb", "insw", "insd", "outsb", "outsw", "outsd"].contains(&mnem.as_str());
    let has_mem = (0..instr.op_count()).any(|i| instr.op_kind(i) == iced_x86::OpKind::Memory);
    if !has_mem {
        for p in ["ss ", "ds ", "es ", "cs ", "fs ", "gs "] {
            if text.starts_with(p) {
                text.drain(..p.len());
                break;
            }
        }
    } else if instr.segment_prefix() != Register::None
        && instr.segment_prefix() == default_segment(instr, &mnem)
    {
        // capstone omits a segment override equal to the operand's default
        // segment (`26 ab` → "stosd dword ptr [rdi], eax", but `26 00 00` →
        // "add byte ptr es:[rax], al").
        let seg = format!("{:?}", instr.segment_prefix()).to_lowercase();
        let pat = format!("{seg}:[");
        if let Some(idx) = text.find(&pat) {
            text.replace_range(idx..idx + seg.len() + 1, "");
        }
    }
    let branchy = matches!(
        instr.flow_control(),
        FlowControl::Return
            | FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Call
            | FlowControl::IndirectCall
    );
    if stringop {
        // capstone keeps rep/repne on string ops; FastFormatter drops them.
        if instr.has_repne_prefix() && !text.starts_with("repne ") {
            text.insert_str(0, "repne ");
        } else if instr.has_repe_prefix()
            && !text.starts_with("rep ")
            && !text.starts_with("repne ")
        {
            text.insert_str(0, "rep ");
        }
    } else if !branchy {
        for p in ["repne ", "rep "] {
            if text.starts_with(p) {
                text.drain(..p.len());
                break;
            }
        }
    }
}

/// Architectural default segment for the (first) memory operand: SS for
/// rsp/rbp-based addressing, ES for the destination of one-address string
/// ops, DS otherwise (approximation — covers the cases capstone applies).
fn default_segment(instr: &iced_x86::Instruction, mnem: &str) -> Register {
    if ["stosb", "stosw", "stosd", "stosq", "scasb", "scasw", "scasd", "scasq", "insb", "insw", "insd"]
        .contains(&mnem)
    {
        Register::ES
    } else {
        match instr.memory_base() {
            Register::RSP | Register::ESP | Register::RBP | Register::EBP => Register::SS,
            _ => Register::DS,
        }
    }
}

/// Port of ROPgadget's `passCleanX86` + the mnemonic filter
/// (gadgets.py:43-53 and 488-498). Returns true if the gadget is REJECTED.
///
/// `filter_suffixes`: user-supplied `--filter` alternation parts; Phase 0
/// uses simple suffix matching (ROPgadget anchors a regex at both ends via
/// `re.match("(…)$")`, i.e. full-mnemonic equality — see README).
///
/// Mnemonic strings are computed lazily: instructions with
/// `FlowControl::Next` can never be in the branch list and (capstone-side)
/// no sequential-flow x86 mnemonic contains the substring "ret", so their
/// names are only materialized when a user `--filter` is active.
pub fn pass_clean(decodes: &[WinInsn], multibr: bool, filter_suffixes: &[String]) -> bool {
    if decodes.is_empty() {
        return true;
    }
    let br = &BRANCH_MNEMONICS[..];
    let last = cs_mnemonic(&decodes[decodes.len() - 1]);
    if !br.contains(&last.as_str()) {
        return true;
    }
    let middle = &decodes[..decodes.len() - 1];
    let middle_mnem = |d: &WinInsn| -> Option<String> {
        if d.flow == FlowControl::Next && filter_suffixes.is_empty() {
            None // cannot be in br, cannot contain "ret"
        } else {
            Some(cs_mnemonic(d))
        }
    };
    if !multibr
        && middle
            .iter()
            .any(|d| d.flow != FlowControl::Next && br.contains(&cs_mnemonic(d).as_str()))
    {
        return true;
    }
    if middle.iter().any(|d| {
        d.flow != FlowControl::Next && cs_mnemonic(d).contains("ret")
    }) {
        return true;
    }
    // Built-in mnemonic filter ("db|int3", full equality — see above) plus
    // user --filter suffixes.
    for d in decodes {
        if let Some(m) = middle_mnem(d) {
            if m == "db" || m == "int3" {
                return true;
            }
            if filter_suffixes.iter().any(|s| !s.is_empty() && m.ends_with(s.as_str())) {
                return true;
            }
        }
    }
    false
}
