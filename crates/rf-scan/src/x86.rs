//! x86/x64 instruction decoding (iced-x86) and the `passCleanX86` port.
//!
//! ROPgadget uses capstone; we use iced-x86. Gadget *text* is the dedup key
//! and the user-visible output, so this module renders iced output in
//! capstone's exact Intel spelling — every rule below was derived by running
//! the parity oracle's capstone 5.0.7 on the byte sequence in the comment
//! (see `docs/measured-2026-09.md`).
//!
//! Performance design: window decodes record a compact, string-free
//! [`WinInsn`] per instruction (no formatter, no allocations). Capstone-style
//! mnemonic strings are computed lazily only for branch-relevant
//! instructions, and full instruction *text* is formatted only for accepted
//! candidates — never for the ~5× larger window-instruction population.

use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Formatter, FormatterOperandOptions,
    FormatterOptionsProvider, Instruction, IntelFormatter, MemorySizeOptions, Mnemonic,
    NumberFormattingOptions, OpKind, Register,
};
use regex::Regex;

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

/// Decoder flags used for BOTH the window decode and the gadget formatter —
/// they must agree or an accepted candidate would re-decode differently.
///
/// SCAN-09: `NO_INVALID_CHECK` disables iced's "this encoding is
/// architecturally useless" rejections, which capstone does not make. It
/// recovers `mov cs, r/m16` (`8e /1`) and `lock`-prefixed instructions with a
/// register destination (`f0 0a 0e` → `lock or cl, byte ptr [esi]`), both of
/// which the oracle decodes and we previously dropped mid-gadget.
pub const DECODER_OPTIONS: u32 = DecoderOptions::NO_INVALID_CHECK;

/// Compact per-instruction record inside a decode window. String-free.
#[derive(Debug, Clone, Copy)]
pub struct WinInsn {
    /// Offset (in the scanned buffer) one past this instruction's last byte.
    pub end: usize,
    /// iced-x86's flow-control class (call, ret, branch, ...).
    pub flow: FlowControl,
    /// iced-x86's exact instruction code.
    pub code: Code,
    /// iced-x86's mnemonic id.
    pub mnem: Mnemonic,
    /// The instruction's segment override, or [`Register::None`].
    pub seg_prefix: Register,
    /// `f2` prefix present.
    pub repne: bool,
    /// `f3` prefix present.
    pub repe: bool,
}

/// One decoded instruction with text (used by the property tests).
#[derive(Debug, Clone)]
pub struct InsnRec {
    /// Offset one past this instruction's last byte.
    pub end: usize,
    /// The lowercase mnemonic on its own.
    pub mnem: String,
    /// The full formatted instruction text.
    pub text: String,
}

/// Per-operand override for capstone's immediate signedness, which follows
/// LLVM's per-instruction operand class rather than any single global rule.
/// Every case below was checked against the oracle's capstone 5.0.7:
///
/// | bytes            | capstone            | why                         |
/// |------------------|---------------------|-----------------------------|
/// | `83 c0 ff`       | `add eax, -1`       | sign-extended imm8, arith   |
/// | `83 c8 ff`       | `or eax, 0xffffffff`| sign-extended imm8, LOGICAL |
/// | `81 c0 ffffffff` | `add eax, 0xffffffff`| plain imm32                |
/// | `48 c7 c0 ...`   | `mov rax, 0xffff…`  | sign-extended imm32, MOV    |
/// | `48 05 ...`      | `add rax, -1`       | sign-extended imm32, arith  |
/// | `cd 80`          | `int 0x80`          | plain imm8                  |
/// | `c8 fd ff ff`    | `enter -3, -1`      | ENTER is signed both ways   |
/// | `f6 c0 84`       | `test al, 0x84`     | `f6 /0` unsigned            |
/// | `f6 48 89 df`    | `test …, -0x21`     | `f6 /1` alias is signed     |
#[derive(Debug, Default)]
struct CapstoneImmediateSigns;

/// Sign-extended immediate operand kinds.
fn is_sign_extended(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

fn is_immediate(k: OpKind) -> bool {
    is_sign_extended(k)
        || matches!(
            k,
            OpKind::Immediate8
                | OpKind::Immediate8_2nd
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
        )
}

fn capstone_prints_signed(instr: &Instruction, kind: OpKind) -> bool {
    // ENTER, the `f6 /1`-style TEST aliases and the REX.W far return print
    // their PLAIN immediates signed.
    if matches!(
        instr.code(),
        Code::Enterw_imm16_imm8
            | Code::Enterd_imm16_imm8
            | Code::Enterq_imm16_imm8
            | Code::Test_rm8_imm8_F6r1
            | Code::Xabort_imm8
            | Code::Retfq_imm16
    ) {
        return true;
    }
    if !is_sign_extended(kind) {
        return false;
    }
    // Sign-extended immediates print signed EXCEPT on the logical ops and
    // MOV, whose LLVM operand class is unsigned.
    !matches!(
        instr.mnemonic(),
        Mnemonic::Or | Mnemonic::And | Mnemonic::Xor | Mnemonic::Mov
    )
}

impl FormatterOptionsProvider for CapstoneImmediateSigns {
    fn operand_options(
        &mut self,
        instruction: &Instruction,
        _operand: u32,
        instruction_operand: Option<u32>,
        _options: &mut FormatterOperandOptions,
        number_options: &mut NumberFormattingOptions<'_>,
    ) {
        if let Some(i) = instruction_operand {
            let kind = instruction.op_kind(i);
            if is_immediate(kind) {
                number_options.signed_number = capstone_prints_signed(instruction, kind);
            }
        }
    }
}

/// The gadget-text formatter. Reuse ONE across candidates (construction is
/// not free).
pub struct GadgetFormatter {
    inner: IntelFormatter,
}

/// Build the gadget-text formatter, configured to reproduce capstone 5.0.x
/// Intel syntax: `[eax + 0x10]` spacing, `0x`-prefixed lowercase hex with
/// decimal for values in -9..=9, no `short`/leading-zero branch decoration,
/// explicit memory operand sizes and RIP-relative operands.
pub fn make_formatter() -> GadgetFormatter {
    let mut inner = IntelFormatter::with_options(None, Some(Box::new(CapstoneImmediateSigns)));
    let o = inner.options_mut();
    o.set_space_after_operand_separator(true);
    o.set_space_between_memory_add_operators(true);
    o.set_space_between_memory_mul_operators(false);
    o.set_rip_relative_addresses(true);
    o.set_memory_size_options(MemorySizeOptions::Always);
    o.set_uppercase_hex(false);
    o.set_hex_prefix("0x");
    o.set_hex_suffix("");
    o.set_add_leading_zero_to_hex_numbers(false);
    o.set_small_hex_numbers_in_decimal(true);
    o.set_branch_leading_zeros(false);
    o.set_show_branch_size(false);
    o.set_signed_immediate_operands(false);
    o.set_signed_memory_displacements(true);
    o.set_leading_zeros(false);
    o.set_show_zero_displacements(false);
    GadgetFormatter { inner }
}

impl GadgetFormatter {
    /// `raw` is the instruction's own bytes — needed for the handful of
    /// spellings that depend on the ENCODING rather than the decoded
    /// operands (the `riz` index register, which exists only to make an
    /// otherwise-redundant SIB byte round-trip).
    fn format(&mut self, instr: &Instruction, bits: u32, raw: &[u8], out: &mut String) {
        out.clear();
        self.inner.format(instr, out);
        capstone_normalize(instr, bits, raw, out);
    }
}

/// Capstone-style mnemonic for a window instruction.
///
/// iced-x86's own mnemonic names match capstone's for the ret/int/syscall
/// families, so we only special-case the prefix-sensitive branch names and
/// the far-branch forms:
///  - `f2`-prefixed ret/retf/jmp/call render as "bnd ..." (capstone MPX)
///  - `f3 c3` renders as "repz ret" (but `f3 cb` is plain "retf")
///  - `3e`-prefixed jmp/call render as "notrack ..." (near AND indirect)
///  - `ea`/`9a` and REX.W `ff /5`, `ff /3` render as "ljmp"/"lcall", which
///    are NOT in ROPgadget's branch list (SCAN-06): the oracle rejects them
///    as a gadget's last instruction and accepts them in the middle.
pub fn cs_mnemonic(rec: &WinInsn) -> String {
    if let Some(far) = far_branch_mnemonic(rec.code) {
        return far.to_string();
    }
    // Mnemonic implements Debug (not Display); Debug spelling is PascalCase.
    let base = || format!("{:?}", rec.mnem).to_lowercase();
    match rec.flow {
        FlowControl::Return => {
            let base = match rec.code {
                Code::Retfq | Code::Retfq_imm16 => "retfq".to_string(),
                _ => base(),
            };
            // `f2` is MPX `bnd` on ret/retf but not on the interrupt
            // returns: `f2 cf` is plain `iretd` to capstone.
            if rec.repne && !base.starts_with("iret") {
                format!("bnd {base}")
            } else if rec.repe && base == "ret" {
                "repz ret".to_string()
            } else {
                base
            }
        }
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => branch_name("jmp", rec),
        FlowControl::Call | FlowControl::IndirectCall => branch_name("call", rec),
        // capstone spells an `f2`-prefixed conditional branch "bnd jne".
        FlowControl::ConditionalBranch if rec.repne => format!("bnd {}", base()),
        _ => match rec.code {
            Code::Pushad => "pushal".to_string(),
            Code::Popad => "popal".to_string(),
            Code::Xlat_m8 => "xlatb".to_string(),
            Code::Nopw => "nop".to_string(),
            _ => base(),
        },
    }
}

/// `ljmp`/`lcall` for the far-branch encodings capstone names that way:
/// the direct `ptr16:16`/`ptr16:32` forms and the REX.W `m16:64` forms.
/// The plain `m16:16`/`m16:32` memory forms are still "jmp"/"call" to
/// capstone (`ff 2a` → `jmp ptr [edx]`), so they are absent here.
fn far_branch_mnemonic(code: Code) -> Option<&'static str> {
    match code {
        Code::Jmp_ptr1616 | Code::Jmp_ptr1632 | Code::Jmp_m1664 => Some("ljmp"),
        Code::Call_ptr1616 | Code::Call_ptr1632 | Code::Call_m1664 => Some("lcall"),
        _ => None,
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

/// Where an instruction's opcode starts, plus the encoding facts capstone's
/// spelling depends on. Returns `None` if the bytes run out.
struct Prefixes {
    /// Index of the first opcode byte in `raw`.
    opcode: usize,
    /// A `0x67` address-size override was present.
    addr_size: bool,
    /// The LAST segment-override prefix — capstone reports that one, iced
    /// reports the last ARCHITECTURALLY MEANINGFUL one, and in 64-bit mode
    /// `cs`/`ds`/`es`/`ss` are not meaningful (`64 2e 00 00` is
    /// `add byte ptr cs:[rax], al` to capstone, `fs:` to iced).
    seg: Register,
}

fn scan_prefixes(raw: &[u8], bits: u32) -> Option<Prefixes> {
    let mut i = 0usize;
    let mut seg = Register::None;
    let mut addr_size = false;
    loop {
        let b = *raw.get(i)?;
        if b == 0x67 {
            addr_size = true;
        }
        match b {
            0x26 => seg = Register::ES,
            0x2e => seg = Register::CS,
            0x36 => seg = Register::SS,
            0x3e => seg = Register::DS,
            0x64 => seg = Register::FS,
            0x65 => seg = Register::GS,
            0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 => {}
            0x40..=0x4f if bits == 64 => {}
            _ => break,
        }
        i += 1;
    }
    Some(Prefixes {
        opcode: i,
        addr_size,
        seg,
    })
}

/// The 148 `d8..df` + ModRM >= 0xc0 encodings LLVM (and therefore capstone)
/// has no table entry for, as a bitmask of `rm` per (opcode, reg) — iced
/// decodes them all as undocumented aliases. Generated by sweeping the
/// oracle's capstone 5.0.7 over the whole 8x64 space.
const X87_ALIAS_REJECT: [[u8; 8]; 8] = [
    [0, 0, 0, 0, 0, 0, 0, 0],                // d8
    [0, 0, 0xfe, 0, 0xcc, 0x80, 0, 0],       // d9
    [0, 0, 0, 0, 0xff, 0xfd, 0xff, 0xff],    // da
    [0, 0, 0, 0, 0xe0, 0, 0, 0xff],          // db
    [0, 0, 0xff, 0xff, 0, 0, 0, 0],          // dc
    [0, 0xff, 0, 0, 0, 0, 0xff, 0xff],       // dd
    [0, 0, 0xff, 0xfd, 0, 0, 0, 0],          // de
    [0, 0xff, 0xff, 0xff, 0xfe, 0, 0, 0xff], // df
];

fn is_rejected_x87_alias(raw: &[u8], pre: &Prefixes) -> bool {
    let Some(&op) = raw.get(pre.opcode) else {
        return false;
    };
    if !(0xd8..=0xdf).contains(&op) {
        return false;
    }
    let Some(&modrm) = raw.get(pre.opcode + 1) else {
        return false;
    };
    if modrm < 0xc0 {
        return false; // memory form, all of which capstone decodes
    }
    let reg = ((modrm >> 3) & 7) as usize;
    let rm = modrm & 7;
    X87_ALIAS_REJECT[(op - 0xd8) as usize][reg] & (1 << rm) != 0
}

/// Encodings iced accepts (with [`DECODER_OPTIONS`]) that capstone refuses.
/// Both the window decode and the formatter must apply this identically, or
/// an accepted candidate would re-decode into different text.
///
///  * a `lock` prefix is legal only on a lockable opcode that also has a
///    memory operand — capstone takes `f0 0b 0e` (`lock or ecx, [esi]`) and
///    refuses `f0 eb 22`, `f0 31 c0`, `f0 48 89 bd ...`. Without this,
///    `NO_INVALID_CHECK` invents `lock jmp` / `lock mov` gadgets.
///  * `63 /r` without REX.W (`movsxd r32, r/m32`) is not in capstone's
///    tables at all.
pub fn capstone_rejects(instr: &Instruction, bits: u32, raw: &[u8]) -> bool {
    if matches!(instr.code(), Code::Movsxd_r16_rm16 | Code::Movsxd_r32_rm32) {
        return true;
    }
    if let Some(pre) = scan_prefixes(raw, bits) {
        if is_rejected_x87_alias(raw, &pre) {
            return true;
        }
        // VEX/EVEX/XOP: `NO_INVALID_CHECK` also switches off the "vvvv must
        // be 1111 when the instruction has no NDS operand" rule, inventing
        // `vmovaps`/`vmovdqu`/`vmovntps` forms capstone refuses. Re-decode
        // the (rare) vector-encoded instruction with the checks ON.
        if matches!(raw.get(pre.opcode), Some(0xc4 | 0xc5 | 0x62 | 0x8f)) {
            let probe = Decoder::new(bits, raw, DecoderOptions::NONE).decode();
            if probe.code() == Code::INVALID || probe.len() != instr.len() {
                return true;
            }
        }
    }
    // `f3 66 90` is not `pause` to capstone, it is nothing at all.
    if instr.code() == Code::Pause && instr.len() != 2 {
        return true;
    }
    // `f0` TOGETHER WITH `f2`/`f3` makes capstone drop all three prefixes and
    // decode the instruction plainly (`f0 f2 8a 57 bf` ->
    // `mov dl, byte ptr [edi - 0x41]`), so it is never a rejection.
    if instr.has_lock_prefix() && !instr.has_repne_prefix() && !instr.has_repe_prefix() {
        let lockable = matches!(
            instr.mnemonic(),
            Mnemonic::Add
                | Mnemonic::Adc
                | Mnemonic::And
                | Mnemonic::Btc
                | Mnemonic::Btr
                | Mnemonic::Bts
                | Mnemonic::Cmpxchg
                | Mnemonic::Cmpxchg8b
                | Mnemonic::Cmpxchg16b
                | Mnemonic::Dec
                | Mnemonic::Inc
                | Mnemonic::Neg
                | Mnemonic::Not
                | Mnemonic::Or
                | Mnemonic::Sbb
                | Mnemonic::Sub
                | Mnemonic::Xor
                | Mnemonic::Xadd
                | Mnemonic::Xchg
                // `f0 0f 1f 00` -> `lock nop dword ptr [eax]`, which LLVM's
                // table allows and the Intel manual does not.
                | Mnemonic::Nop
        );
        let has_mem = (0..instr.op_count()).any(|i| is_memory_kind(instr.op_kind(i)));
        if !lockable || !has_mem {
            return true;
        }
    }
    false
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
    let mut decoder = Decoder::with_ip(bits, slice, ip, DECODER_OPTIONS);
    let mut out = Vec::new();
    let mut off = start;
    let mut pos = 0usize;
    let mut instr = iced_x86::Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if matches!(instr.code(), Code::INVALID | Code::DeclareByte) {
            break;
        }
        let raw = &slice[pos..(pos + instr.len()).min(slice.len())];
        if capstone_rejects(&instr, bits, raw) {
            break;
        }
        let len = capstone_len(&instr);
        if len == 0 {
            break;
        }
        if len != instr.len() {
            pos += len;
            if pos > slice.len() || decoder.set_position(pos).is_err() {
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
                break;
            }
            decoder.set_ip(ip.wrapping_add(pos as u64));
        } else {
            pos += len;
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
    fmt: &mut GadgetFormatter,
) -> Vec<String> {
    let slice = &code[start..end];
    let ip = vaddr.wrapping_add(start as u64);
    let mut decoder = Decoder::with_ip(bits, slice, ip, DECODER_OPTIONS);
    let mut out = Vec::new();
    let mut instr = iced_x86::Instruction::default();
    let mut text = String::new();
    let mut pos = 0usize;
    while decoder.can_decode() {
        decoder.decode_out(&mut instr);
        if matches!(instr.code(), Code::INVALID | Code::DeclareByte) {
            break;
        }
        let full = &slice[pos..(pos + instr.len()).min(slice.len())];
        if capstone_rejects(&instr, bits, full) {
            break;
        }
        let len = capstone_len(&instr);
        if len == 0 {
            break;
        }
        let raw = &slice[pos..(pos + len).min(slice.len())];
        fmt.format(&instr, bits, raw, &mut text);
        out.push(text.clone());
        pos += len;
        if pos > slice.len() || decoder.set_position(pos).is_err() {
            break;
        }
        decoder.set_ip(ip.wrapping_add(pos as u64));
    }
    out
}

/// Instruction length as capstone sees it. `0f ff` / `0f b9` are two-byte
/// `ud0` / `ud1` there (no ModRM); iced consumes a ModRM byte for the
/// documented `ud0 r32, r/m32` form, which would slide every following
/// instruction boundary by one.
pub fn capstone_len(instr: &Instruction) -> usize {
    if matches!(
        instr.code(),
        Code::Ud0_r16_rm16
            | Code::Ud0_r32_rm32
            | Code::Ud0_r64_rm64
            | Code::Ud1_r16_rm16
            | Code::Ud1_r32_rm32
            | Code::Ud1_r64_rm64
    ) {
        return 2;
    }
    instr.len()
}

// ---------------------------------------------------------------------------
// capstone spelling
// ---------------------------------------------------------------------------

/// capstone's number rendering: decimal in -9..=9, `0x`-prefixed lowercase
/// hex otherwise (`printImm`, HEX_THRESHOLD = 9).
fn cs_num(v: u64) -> String {
    if v <= 9 {
        format!("{v}")
    } else {
        format!("0x{v:x}")
    }
}

fn seg_name(r: Register) -> Option<&'static str> {
    Some(match r {
        Register::ES => "es",
        Register::CS => "cs",
        Register::SS => "ss",
        Register::DS => "ds",
        Register::FS => "fs",
        Register::GS => "gs",
        _ => return None,
    })
}

fn is_es_string_dest(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::MemoryESDI | OpKind::MemoryESEDI | OpKind::MemoryESRDI
    )
}

fn is_memory_kind(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Memory
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI
    )
}

/// Rewrite iced's Intel text into capstone's, in place.
fn capstone_normalize(instr: &Instruction, bits: u32, raw: &[u8], text: &mut String) {
    // Whole-text forms first: capstone renders these nothing like iced.
    match instr.code() {
        Code::Xlat_m8 => {
            *text = "xlatb".to_string();
            return;
        }
        // `66 90` / `48 90` are a plain "nop" to capstone; iced renders the
        // underlying `xchg ax, ax` / `xchg rax, rax`.
        Code::Nopw | Code::Nopd | Code::Nopq => {
            if instr.op_count() == 0 {
                *text = "nop".to_string();
                return;
            }
        }
        Code::Jmp_ptr1616 | Code::Jmp_ptr1632 => {
            *text = format!(
                "ljmp {}:{}",
                cs_num(instr.far_branch_selector() as u64),
                cs_num(far_branch_offset(instr))
            );
            return;
        }
        Code::Call_ptr1616 | Code::Call_ptr1632 => {
            *text = format!(
                "lcall {}, {}",
                cs_num(instr.far_branch_selector() as u64),
                cs_num(far_branch_offset(instr))
            );
            return;
        }
        _ => {}
    }

    match instr.code() {
        Code::Ud0_r16_rm16 | Code::Ud0_r32_rm32 | Code::Ud0_r64_rm64 => {
            *text = "ud0".to_string();
            return;
        }
        Code::Ud1_r16_rm16 | Code::Ud1_r32_rm32 | Code::Ud1_r64_rm64 => {
            *text = "ud1".to_string();
            return;
        }
        _ => {}
    }
    if let Some(t) = x87_register_form(instr) {
        *text = t;
        return;
    }
    if text.starts_with("prefetch_exclusive") {
        text.replace_range(.."prefetch_exclusive".len(), "prefetch");
    }
    strip_iced_only_prefixes(instr, text);
    rewrite_mnemonic(instr, bits, text);
    fix_operand_size_branch_target(instr, bits, raw, text);
    fix_far_memory_operand(instr, text);
    fix_segment_overrides(instr, bits, raw, text);
    add_implicit_string_operand(instr, text);
    fix_x87_implicit_st0(instr, text);
    fix_implicit_operand_count(instr, text);
    fix_sib_artefacts(instr, bits, raw, text);
    add_notrack(instr, text);
}

/// Operand lists where capstone prints more (or fewer) operands than iced:
///
///  * `imul r, r/m, imm` — capstone always prints all three
///    (`imul edi, edi, 0xe889ffff`), iced elides the repeated destination.
///  * the shift-by-one MEMORY forms — capstone drops the implicit `1`
///    (`d0 10` -> `rcl byte ptr [eax]`) but keeps it on registers
///    (`d1 d0` -> `rcl eax, 1`).
///  * `mov Sreg, r/m16` with a register source — capstone widens the name to
///    the 32-bit register (`8e cf` -> `mov cs, edi`).
///  * `sidt`/`sgdt`/`lidt`/`lgdt` print a bare `[mem]` with no size at all.
fn fix_implicit_operand_count(instr: &Instruction, text: &mut String) {
    if matches!(
        instr.code(),
        Code::Imul_r16_rm16_imm16
            | Code::Imul_r16_rm16_imm8
            | Code::Imul_r32_rm32_imm32
            | Code::Imul_r32_rm32_imm8
            | Code::Imul_r64_rm64_imm32
            | Code::Imul_r64_rm64_imm8
    ) && instr.op_count() == 3
        && instr.op_kind(0) == OpKind::Register
        && instr.op_kind(1) == OpKind::Register
        && instr.op_register(0) == instr.op_register(1)
    {
        if let Some(p) = text.find(", ") {
            let reg = format!("{:?}", instr.op_register(1)).to_lowercase();
            text.insert_str(p, &format!(", {reg}"));
        }
        return;
    }
    if matches!(
        instr.code(),
        Code::Rcl_rm8_1 | Code::Rcl_rm16_1 | Code::Rcl_rm32_1 | Code::Rcl_rm64_1
    ) && (0..instr.op_count()).any(|i| is_memory_kind(instr.op_kind(i)))
        && text.ends_with(", 1")
    {
        let n = text.len() - ", 1".len();
        text.truncate(n);
        return;
    }
    if matches!(
        instr.code(),
        Code::Mov_Sreg_rm16 | Code::Mov_Sreg_r32m16 | Code::Mov_Sreg_r64m16
    ) && instr.op_kind(1) == OpKind::Register
    {
        if let Some(p) = text.rfind(", ") {
            let wide = widen_register(instr.op_register(1));
            text.replace_range(p + 2.., &wide);
        }
        return;
    }
    if matches!(
        instr.mnemonic(),
        Mnemonic::Sidt | Mnemonic::Sgdt | Mnemonic::Lidt | Mnemonic::Lgdt
    ) {
        // capstone prints a bare `sgdt fs:[rax]` — no size AND no `ptr`.
        if let Some(p) = text.find(" ptr ") {
            if let Some(w) = text[..p].rfind(' ') {
                text.replace_range(w + 1..p + " ptr ".len(), "");
            }
        }
        return;
    }
    // ...and conversely, capstone prints a size where iced has none.
    let size = match instr.mnemonic() {
        Mnemonic::Fnsave | Mnemonic::Frstor => "dword ptr ",
        Mnemonic::Invlpg => "byte ptr ",
        _ => return,
    };
    if let Some(p) = text.find('[') {
        if !text[..p].ends_with("ptr ") && !text[..p].contains(':') {
            text.insert_str(p, size);
        }
    }
}

/// 16-bit register -> its 32-bit counterpart, for `mov Sreg, r32`.
fn widen_register(r: Register) -> String {
    let n = format!("{r:?}").to_lowercase();
    match n.as_str() {
        "ax" => "eax",
        "cx" => "ecx",
        "dx" => "edx",
        "bx" => "ebx",
        "sp" => "esp",
        "bp" => "ebp",
        "si" => "esi",
        "di" => "edi",
        "r8w" => "r8d",
        "r9w" => "r9d",
        "r10w" => "r10d",
        "r11w" => "r11d",
        "r12w" => "r12d",
        "r13w" => "r13d",
        "r14w" => "r14d",
        "r15w" => "r15d",
        _ => return n,
    }
    .to_string()
}

/// Encoding-level memory-operand artefacts.
///
///  * `*1` — iced writes the scale on a base-less index (`[ecx*1 + 0x10]`),
///    capstone never does (`[ecx + 0x10]`).
///  * `riz` — in 64-bit mode LLVM (and therefore capstone) materialises the
///    "no index" SIB field as the pseudo-register `riz` so the redundant SIB
///    byte survives a re-assemble: `8b 44 27 04` is `[rdi + riz + 4]` and
///    `00 4c 63 d1` is `[rbx + riz*2 - 0x2f]`. It is suppressed when the base
///    is (R)SP/R12, where the SIB byte is mandatory anyway, and in 32-bit
///    mode, where capstone prints nothing. iced has no API for "was there a
///    SIB byte", so this reads the ModRM/SIB out of the encoding.
fn fix_sib_artefacts(instr: &Instruction, bits: u32, raw: &[u8], text: &mut String) {
    while let Some(p) = text.find("*1") {
        text.replace_range(p..p + 2, "");
    }
    if bits != 64 {
        return;
    }
    let Some((scale, has_base)) = riz_index(instr, bits, raw) else {
        return;
    };
    let Some(open) = text.find('[') else { return };
    let Some(close) = text[open..].find(']').map(|i| i + open) else {
        return;
    };
    let inner = text[open + 1..close].to_string();
    let riz = if scale == 1 {
        "riz".to_string()
    } else {
        format!("riz*{scale}")
    };
    let new = if has_base {
        // `rdi + 4` -> `rdi + riz + 4`; `rbx - 0x2f` -> `rbx + riz*2 - 0x2f`
        match inner.find(' ') {
            Some(sp) => format!("{} + {riz} {}", &inner[..sp], &inner[sp + 1..]),
            None => format!("{inner} + {riz}"),
        }
    } else {
        // No base: capstone treats the disp32 as a signed displacement
        // (`[riz*2 - 0x51780000]`), iced as an absolute address.
        let d = instr.memory_displacement64() as i32;
        match d {
            0 => riz.clone(),
            d if d > 0 => format!("{riz} + {}", cs_num(d as u64)),
            d => format!("{riz} - {}", cs_num(d.unsigned_abs() as u64)),
        }
    };
    text.replace_range(open + 1..close, &new);
}

/// Returns `(scale, has_base)` when the encoding carries a SIB byte whose
/// index field is "none" and capstone would therefore print `riz`.
fn riz_index(instr: &Instruction, bits: u32, raw: &[u8]) -> Option<(u32, bool)> {
    if !(0..instr.op_count()).any(|i| instr.op_kind(i) == OpKind::Memory) {
        return None;
    }
    let mut i = 0usize;
    let mut pre_rex = 0u8;
    loop {
        let b = *raw.get(i)?;
        match b {
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 => {
                pre_rex = 0;
                i += 1;
            }
            0x40..=0x4f if bits == 64 => {
                pre_rex = b;
                i += 1;
            }
            _ => break,
        }
    }
    let mut op = *raw.get(i)?;
    // VEX: the ModRM/SIB pair sits after the 1- or 2-byte VEX payload and
    // the opcode, and REX.X lives (inverted) in bit 6 of the 3-byte form.
    if matches!(op, 0xc4 | 0xc5) {
        let (payload, x) = if op == 0xc4 {
            (2usize, 1 - ((*raw.get(i + 1)? >> 6) & 1))
        } else {
            (1usize, 0)
        };
        let modrm = *raw.get(i + payload + 2)?;
        let sib = *raw.get(i + payload + 3)?;
        return sib_riz(modrm, sib, x);
    }
    if matches!(op, 0x62 | 0x8f) {
        return None; // EVEX / XOP
    }
    i += 1;
    if op == 0x0f {
        op = *raw.get(i)?;
        i += 1;
        if op == 0x38 || op == 0x3a {
            i += 1;
        }
    } else if matches!(op, 0xa0..=0xaf | 0x6c..=0x6f | 0xd7) {
        // moffs / string / xlat: memory operand without a ModRM byte.
        return None;
    }
    let modrm = *raw.get(i)?;
    let sib = *raw.get(i + 1).unwrap_or(&0);
    sib_riz(modrm, sib, (pre_rex >> 1) & 1)
}

/// The riz decision for one (ModRM, SIB, REX.X) triple.
fn sib_riz(modrm: u8, sib: u8, rex_x: u8) -> Option<(u32, bool)> {
    if modrm >> 6 == 3 || modrm & 7 != 4 {
        return None; // no SIB byte
    }
    let scale = 1u32 << (sib >> 6);
    let index = (sib >> 3) & 7;
    if index != 4 || rex_x != 0 {
        return None; // a real index register
    }
    let base = sib & 7;
    if base == 4 && scale == 1 {
        // (R)SP / R12 with scale 1: the SIB byte is mandatory anyway, so
        // LLVM has no reason to materialise the index (`8b 44 24 04` ->
        // `[rsp + 4]`, but `8b 44 64 fd` -> `[rsp + riz*2 - 3]`).
        return None;
    }
    if modrm >> 6 == 0 && base == 5 {
        // disp32 with no base: capstone prints `[riz*N]` only for N > 1.
        return if scale == 1 {
            None
        } else {
            Some((scale, false))
        };
    }
    Some((scale, true))
}

fn far_branch_offset(instr: &Instruction) -> u64 {
    if instr.op_kind(0) == OpKind::FarBranch16 {
        instr.far_branch16() as u64
    } else {
        instr.far_branch32() as u64
    }
}

fn starts_with_word(text: &str, word: &str) -> bool {
    text.len() > word.len() && text.starts_with(word) && text.as_bytes()[word.len()] == b' '
}

/// Prefixes iced prints and capstone does not: the operand-size `data16`
/// pseudo-prefix, the HLE `xacquire`/`xrelease` hints, and `rep`/`repne` on
/// anything that is not a string operation. `f3 c3` is the one exception
/// capstone keeps, spelled `repz ret` (SCAN-03) — and `rep`-prefixed
/// branches must lose the prefix or they form a spurious dedup class of
/// their own (`rep jmp` beside the identical `jmp`).
fn strip_iced_only_prefixes(instr: &Instruction, text: &mut String) {
    // `f0` + `f2`/`f3`: capstone drops lock and the HLE hint both.
    if instr.has_lock_prefix() && (instr.has_repne_prefix() || instr.has_repe_prefix()) {
        for p in ["xacquire ", "xrelease ", "lock "] {
            if text.starts_with(p) {
                text.drain(..p.len());
            }
        }
    }
    // capstone keeps the HLE hint only where HLE is architecturally valid:
    // `xchg` and the lock-prefixed read-modify-write forms.
    if !matches!(instr.mnemonic(), Mnemonic::Xchg) && !instr.has_lock_prefix() {
        for p in ["xrelease ", "xacquire "] {
            if text.starts_with(p) {
                text.drain(..p.len());
            }
        }
    }
    for p in [
        "data16 ",
        "data32 ",
        "data64 ",
        "addr16 ",
        "addr32 ",
        "addr64 ",
        "hint-not-taken ",
        "hint-taken ",
    ] {
        if text.starts_with(p) {
            text.drain(..p.len());
        }
    }
    if is_string_op(instr.code()) {
        return;
    }
    if text.starts_with("rep ") {
        if instr.mnemonic() == Mnemonic::Ret && text == "rep ret" {
            *text = "repz ret".to_string();
        } else {
            text.drain(.."rep ".len());
        }
    } else if text.starts_with("repe ") {
        text.drain(.."repe ".len());
    } else if text.starts_with("repne ") {
        text.drain(.."repne ".len());
    }
    // `f2` is "bnd" to capstone on EVERY branch — ret, retf, jmp, call and
    // jcc (`f2 cb` → `bnd retf`, `f2 75 ef` → `bnd jne`). iced spells only
    // some of them that way.
    if instr.has_repne_prefix()
        && is_branchy(instr)
        && !matches!(
            instr.mnemonic(),
            Mnemonic::Iret | Mnemonic::Iretd | Mnemonic::Iretq
        )
        && !matches!(
            instr.mnemonic(),
            Mnemonic::Loop
                | Mnemonic::Loope
                | Mnemonic::Loopne
                | Mnemonic::Jrcxz
                | Mnemonic::Jecxz
                | Mnemonic::Jcxz
        )
        && !text.starts_with("bnd ")
    {
        text.insert_str(0, "bnd ");
    }
}

fn is_branchy(instr: &Instruction) -> bool {
    matches!(
        instr.flow_control(),
        FlowControl::Return
            | FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::ConditionalBranch
            | FlowControl::Call
            | FlowControl::IndirectCall
    )
}

fn is_string_op(code: Code) -> bool {
    matches!(
        code,
        Code::Movsb_m8_m8
            | Code::Movsw_m16_m16
            | Code::Movsd_m32_m32
            | Code::Movsq_m64_m64
            | Code::Cmpsb_m8_m8
            | Code::Cmpsw_m16_m16
            | Code::Cmpsd_m32_m32
            | Code::Cmpsq_m64_m64
            | Code::Stosb_m8_AL
            | Code::Stosw_m16_AX
            | Code::Stosd_m32_EAX
            | Code::Stosq_m64_RAX
            | Code::Lodsb_AL_m8
            | Code::Lodsw_AX_m16
            | Code::Lodsd_EAX_m32
            | Code::Lodsq_RAX_m64
            | Code::Scasb_AL_m8
            | Code::Scasw_AX_m16
            | Code::Scasd_EAX_m32
            | Code::Scasq_RAX_m64
            | Code::Insb_m8_DX
            | Code::Insw_m16_DX
            | Code::Insd_m32_DX
            | Code::Outsb_DX_m8
            | Code::Outsw_DX_m16
            | Code::Outsd_DX_m32
    )
}

/// Mnemonic spellings where capstone and iced simply disagree.
fn rewrite_mnemonic(instr: &Instruction, bits: u32, text: &mut String) {
    let replace_head = |text: &mut String, from: &str, to: &str| {
        if let Some(p) = text.find(from) {
            text.replace_range(p..p + from.len(), to);
        }
    };
    match instr.code() {
        // `/6` of the shift group is an undocumented alias of `/4`; capstone
        // spells it `sal`, iced folds it into `shl`.
        Code::Sal_rm8_1
        | Code::Sal_rm8_CL
        | Code::Sal_rm8_imm8
        | Code::Sal_rm16_1
        | Code::Sal_rm16_CL
        | Code::Sal_rm16_imm8
        | Code::Sal_rm32_1
        | Code::Sal_rm32_CL
        | Code::Sal_rm32_imm8
        | Code::Sal_rm64_1
        | Code::Sal_rm64_CL
        | Code::Sal_rm64_imm8 => replace_head(text, "shl", "sal"),
        Code::Wait => replace_head(text, "fwait", "wait"),
        // REX.W far return: capstone names it `retfq` (and prints its imm16
        // signed: `4e ca c1 8b` -> `retfq -0x743f`).
        Code::Retfq | Code::Retfq_imm16 => replace_head(text, "ret far", "retfq"),
        Code::Pushad => replace_head(text, "pushad", "pushal"),
        Code::Popad => replace_head(text, "popad", "popal"),
        Code::Pushaw => replace_head(text, "pusha", "pushaw"),
        Code::Popaw => replace_head(text, "popa", "popaw"),
        // `ret far` / `bnd ret far` → `retf` / `bnd retf`.
        Code::Retfw | Code::Retfd | Code::Retfw_imm16 | Code::Retfd_imm16 => {
            replace_head(text, "ret far", "retf")
        }
        // In 64-bit mode capstone names the absolute-address MOV forms
        // `movabs`; in 32-bit they are plain `mov`.
        Code::Mov_r64_imm64
        | Code::Mov_AL_moffs8
        | Code::Mov_AX_moffs16
        | Code::Mov_EAX_moffs32
        | Code::Mov_RAX_moffs64
        | Code::Mov_moffs8_AL
        | Code::Mov_moffs16_AX
        | Code::Mov_moffs32_EAX
        | Code::Mov_moffs64_RAX => {
            if bits == 64 {
                replace_head(text, "mov ", "movabs ")
            }
        }
        // `lss ecx, fword ptr [eax]` → capstone `lss ecx, ptr [eax]`.
        _ if matches!(
            instr.mnemonic(),
            Mnemonic::Lss | Mnemonic::Lds | Mnemonic::Les | Mnemonic::Lfs | Mnemonic::Lgs
        ) =>
        {
            drop_memory_size_word(text)
        }
        _ => {}
    }
}

/// Remove the `<size>` in `<size> ptr [` (capstone prints a bare `ptr` when
/// the operand size is a far pointer).
fn drop_memory_size_word(text: &mut String) {
    let Some(p) = text.find(" ptr ") else { return };
    let head = &text[..p];
    let Some(start) = head.rfind([' ', ',']) else {
        return;
    };
    text.replace_range(start + 1..p + 1, "");
}

/// `ff /5` and `ff /3`: iced prints `jmp far fword ptr [edx]`, capstone
/// prints `jmp ptr [edx]`; with REX.W capstone switches the mnemonic to
/// `ljmp [rdx]` instead (SCAN-06).
fn fix_far_memory_operand(instr: &Instruction, text: &mut String) {
    let far = match instr.code() {
        Code::Jmp_m1616 | Code::Jmp_m1632 => "jmp",
        Code::Call_m1616 | Code::Call_m1632 => "call",
        Code::Jmp_m1664 => "ljmp",
        Code::Call_m1664 => "lcall",
        _ => return,
    };
    let Some(p) = text.find(" far ") else { return };
    let rest = &text[p + " far ".len()..];
    let Some(q) = rest.find(" ptr ") else { return };
    let tail = rest[q + " ptr ".len()..].to_string();
    let head = text[..p].replace("jmp", far).replace("call", far);
    *text = if far.starts_with('l') {
        format!("{head} {tail}")
    } else {
        format!("{head} ptr {tail}")
    };
}

/// capstone prints a memory operand's segment whenever the encoding carries
/// a segment-override prefix (even a redundant one: `3e 8b 00` →
/// `mov eax, dword ptr ds:[eax]`, `2e 8b 45 f8` in 64-bit mode →
/// `cs:[rbp - 8]`), and always prints `es:` on a 16/32-bit string
/// destination. iced omits both whenever the segment is the operand's
/// architectural default. (SCAN-04 — the previous code did the opposite,
/// STRIPPING default-segment overrides, which collided `ss:`-prefixed
/// gadgets with their unprefixed twins in text dedup and lost them.)
fn fix_segment_overrides(instr: &Instruction, bits: u32, raw: &[u8], text: &mut String) {
    let prefix = scan_prefixes(raw, bits).map_or(Register::None, |p| p.seg);
    let kinds: Vec<OpKind> = (0..instr.op_count())
        .map(|i| instr.op_kind(i))
        .filter(|k| is_memory_kind(*k))
        .collect();
    if kinds.is_empty() {
        return;
    }
    // Walk the '[' occurrences left to right; the k-th belongs to the k-th
    // memory operand (Intel syntax prints operands in order).
    let mut k = 0usize;
    let mut pos = 0usize;
    while let Some(rel) = text[pos..].find('[') {
        let at = pos + rel;
        let Some(kind) = kinds.get(k).copied() else {
            break;
        };
        k += 1;
        pos = at + 1;
        let want = if is_es_string_dest(kind) {
            if bits == 64 {
                None
            } else {
                Some("es")
            }
        } else {
            seg_name(prefix)
        };
        let has_seg = at >= 3 && text.as_bytes()[at - 1] == b':';
        let Some(want) = want else {
            // 64-bit ES string destination: capstone prints no segment even
            // when another prefix is present (`64 6d` -> `insd …[rdi], dx`).
            if has_seg {
                text.replace_range(at - 3..at, "");
                pos -= 3;
            }
            continue;
        };
        if has_seg {
            // iced picked the architecturally meaningful prefix, capstone
            // the LAST one written (`64 2e 00 00` -> `cs:`, not `fs:`).
            if &text[at - 3..at - 1] != want {
                text.replace_range(at - 3..at - 1, want);
            }
            continue;
        }
        text.insert_str(at, &format!("{want}:"));
        pos += want.len() + 1;
    }
}

/// capstone prints the implicit accumulator operand of `stos`/`lods`/`scas`
/// (`stosd dword ptr es:[edi], eax`); iced prints only the memory operand.
fn add_implicit_string_operand(instr: &Instruction, text: &mut String) {
    let (acc, append) = match instr.code() {
        Code::Stosb_m8_AL => ("al", true),
        Code::Stosw_m16_AX => ("ax", true),
        Code::Stosd_m32_EAX => ("eax", true),
        Code::Stosq_m64_RAX => ("rax", true),
        Code::Lodsb_AL_m8 | Code::Scasb_AL_m8 => ("al", false),
        Code::Lodsw_AX_m16 | Code::Scasw_AX_m16 => ("ax", false),
        Code::Lodsd_EAX_m32 | Code::Scasd_EAX_m32 => ("eax", false),
        Code::Lodsq_RAX_m64 | Code::Scasq_RAX_m64 => ("rax", false),
        _ => return,
    };
    if append {
        text.push_str(", ");
        text.push_str(acc);
        return;
    }
    let mnem = format!("{:?}", instr.mnemonic()).to_lowercase();
    let pat = format!("{mnem} ");
    if let Some(p) = text.find(&pat) {
        text.insert_str(p + pat.len(), &format!("{acc}, "));
    }
}

/// The documented one-ST-operand x87 forms. capstone prints exactly the
/// explicit `st(i)` for these (`dd da` -> `fstp st(2)`, `d9 c0` ->
/// `fld st(0)`), while iced also renders the implicit `st`. The
/// UNDOCUMENTED aliases (`d9 d9` -> `fstpnce st(1), st(0)`) keep both, so
/// they fall through to the "spell st(0) out" branch.
fn x87_drops_implicit_st0(code: Code) -> bool {
    matches!(
        code,
        Code::Fld_sti
            | Code::Fst_sti
            | Code::Fstp_sti
            | Code::Fxch_st0_sti
            | Code::Ffree_sti
            | Code::Ffreep_sti
    )
}

fn x87_single_register_form(instr: &Instruction) -> Option<String> {
    let r0 = st_name(instr.op_register(0))?;
    let mnem = format!("{:?}", instr.mnemonic()).to_lowercase();
    if !mnem.starts_with('f') {
        return None;
    }
    Some(if x87_drops_implicit_st0(instr.code()) {
        format!("{mnem} {r0}")
    } else if instr.code() == Code::Fld_sti || format!("{:?}", instr.code()).contains("_st0_") {
        format!("{mnem} st(0), {r0}")
    } else {
        format!("{mnem} {r0}, st(0)")
    })
}

fn st_name(r: Register) -> Option<&'static str> {
    Some(match r {
        Register::ST0 => "st(0)",
        Register::ST1 => "st(1)",
        Register::ST2 => "st(2)",
        Register::ST3 => "st(3)",
        Register::ST4 => "st(4)",
        Register::ST5 => "st(5)",
        Register::ST6 => "st(6)",
        Register::ST7 => "st(7)",
        _ => return None,
    })
}

/// The two-register x87 forms, where capstone and iced disagree about which
/// implicit `st(0)` to print and (for `fcomip`/`fucomip`) about the mnemonic
/// itself. Verified against the oracle's capstone 5.0.7:
///
/// | bytes  | capstone              | iced                  |
/// |--------|-----------------------|-----------------------|
/// | `d8 d1`| `fcom st(1)`          | `fcom st, st(1)`      |
/// | `dc e1`| `fsubr st(1), st(0)`  | `fsubr st(1), st`     |
/// | `de c2`| `faddp st(2)`         | `faddp`               |
/// | `df ee`| `fucompi st(6)`       | `fucomip st, st(6)`   |
/// | `da c1`| `fcmovb st(0), st(1)` | `fcmovb st, st(1)`    |
fn x87_register_form(instr: &Instruction) -> Option<String> {
    if instr.op_count() == 1 {
        return x87_single_register_form(instr);
    }
    if instr.op_count() != 2 {
        return None;
    }
    let r0 = st_name(instr.op_register(0))?;
    let r1 = st_name(instr.op_register(1))?;
    let mnem = format!("{:?}", instr.mnemonic()).to_lowercase();
    if !mnem.starts_with('f') {
        return None;
    }
    // `fcmov*` is the one family that spells both operands out.
    if mnem.starts_with("fcmov") {
        return Some(format!("{mnem} {r0}, {r1}"));
    }
    // `dc e8` is `fsub st(0), st(0)` — both operands ARE st(0), so which
    // group it belongs to has to come from the encoding, not the operands.
    let code = format!("{:?}", instr.code());
    if code.contains("_sti_st0") {
        // `dc` group keeps both; the `de` pop group prints only st(i).
        return Some(if mnem.ends_with('p') {
            format!("{mnem} {r0}")
        } else {
            format!("{mnem} {r0}, st(0)")
        });
    }
    if code.contains("_st0_sti") {
        // `d8`/`db`/`df` group: st(0) is the implicit accumulator, dropped.
        let mnem = match instr.mnemonic() {
            Mnemonic::Fcomip => "fcompi".to_string(),
            Mnemonic::Fucomip => "fucompi".to_string(),
            _ => mnem,
        };
        return Some(format!("{mnem} {r1}"));
    }
    None
}

/// capstone omits the implicit `st(0)` operand of the memory x87 forms
/// (`fadd dword ptr [eax]`), iced prints it (`fadd st, dword ptr [eax]`).
fn fix_x87_implicit_st0(instr: &Instruction, text: &mut String) {
    let mnem = format!("{:?}", instr.mnemonic()).to_lowercase();
    if !mnem.starts_with('f') || !(0..instr.op_count()).any(|i| is_memory_kind(instr.op_kind(i))) {
        return;
    }
    let pat = format!("{mnem} st, ");
    if text.starts_with(&pat) {
        text.replace_range(mnem.len() + 1..mnem.len() + 1 + "st, ".len(), "");
    }
    if text.ends_with(", st") {
        let n = text.len() - ", st".len();
        text.truncate(n);
    }
    // capstone calls the 80-bit x87 FLOAT memory operand `xword` (iced:
    // `tbyte`) but keeps `tbyte` for the 80-bit BCD `fbld`/`fbstp`.
    if !matches!(instr.mnemonic(), Mnemonic::Fbld | Mnemonic::Fbstp) {
        if let Some(q) = text.find("tbyte ptr ") {
            text.replace_range(q..q + "tbyte".len(), "xword");
        }
    }
}

/// A `66`-prefixed near branch in 32/64-bit mode has a 16-bit operand size,
/// so the architectural target wraps at 64 KiB; iced applies that wrap,
/// capstone does not (`66 eb 0c` at 0x0808b5cc is `jmp 0x808b5db` there and
/// `jmp 0xb5db` in iced). Matching capstone also collapses a dedup class:
/// the wrapped text made those gadgets look distinct from their unwrapped
/// twins, so they survived a dedup the oracle performs.
fn fix_operand_size_branch_target(instr: &Instruction, bits: u32, raw: &[u8], text: &mut String) {
    if bits == 16 || instr.op_count() == 0 {
        return;
    }
    let next = instr.next_ip();
    let target = match instr.op_kind(0) {
        OpKind::NearBranch16 => {
            let rel = (instr.near_branch16() as i64 - (next & 0xffff) as i64) as i16 as i64;
            let full = next.wrapping_add(rel as u64);
            if bits == 32 {
                full & 0xffff_ffff
            } else {
                full
            }
        }
        // Mirror image: in 32-bit mode a `0x67` address-size override makes
        // LLVM compute the branch target with a 16-bit instruction pointer,
        // keeping the high half of the current IP (`67 e9 ff ff c7 04` at
        // 0x804d285 is `jmp 0x804d28a`, not `jmp 0xcccd28a`). iced follows
        // the Intel spec instead and does not truncate.
        OpKind::NearBranch32
            if bits == 32 && scan_prefixes(raw, bits).is_some_and(|p| p.addr_size) =>
        {
            (next & 0xffff_0000) | (instr.near_branch32() as u64 & 0xffff)
        }
        _ => return,
    };
    if let Some(p) = text.rfind(' ') {
        text.replace_range(p + 1.., &cs_num(target));
    }
}

/// capstone spells a `3e`-prefixed jmp/call `notrack ...` for EVERY form,
/// including the direct relative ones (`3e e9 rel32` →
/// `notrack jmp 0x1006`); iced only does it for the indirect forms.
fn add_notrack(instr: &Instruction, text: &mut String) {
    if instr.segment_prefix() != Register::DS || text.starts_with("notrack ") {
        return;
    }
    if !matches!(
        instr.flow_control(),
        FlowControl::UnconditionalBranch
            | FlowControl::IndirectBranch
            | FlowControl::Call
            | FlowControl::IndirectCall
    ) {
        return;
    }
    if !starts_with_word(text, "jmp") && !starts_with_word(text, "call") {
        return;
    }
    text.insert_str(0, "notrack ");
}

// ---------------------------------------------------------------------------
// passCleanX86
// ---------------------------------------------------------------------------

/// Port of ROPgadget's `passCleanX86` + the mnemonic filter
/// (gadgets.py:43-53 and 488-498). Returns true if the gadget is REJECTED.
///
/// `filter`: the compiled `({user})$` regex (SCAN-01/CLI-02). ROPgadget
/// builds ONE regex per scan out of the architecture's built-in list and the
/// user's `--filter` string and matches it with `re.match`, i.e. a FULL match
/// against each instruction's mnemonic — not a suffix test. The x86 built-in
/// half (`db|int3`) is checked here without materializing a string: iced
/// never yields capstone's SKIPDATA `db`, and `int3` is a single [`Mnemonic`].
///
/// Mnemonic strings are computed lazily: instructions with
/// `FlowControl::Next` can never be in the branch list and (capstone-side)
/// no sequential-flow x86 mnemonic contains the substring "ret", so their
/// names are only materialized when a user `--filter` is active.
pub fn pass_clean(decodes: &[WinInsn], multibr: bool, filter: Option<&Regex>) -> bool {
    if decodes.is_empty() {
        return true;
    }
    let br = &BRANCH_MNEMONICS[..];
    let last = cs_mnemonic(&decodes[decodes.len() - 1]);
    if !br.contains(&last.as_str()) {
        return true;
    }
    let middle = &decodes[..decodes.len() - 1];
    if !multibr
        && middle
            .iter()
            .any(|d| d.flow != FlowControl::Next && br.contains(&cs_mnemonic(d).as_str()))
    {
        return true;
    }
    if middle
        .iter()
        .any(|d| d.flow != FlowControl::Next && cs_mnemonic(d).contains("ret"))
    {
        return true;
    }
    // Built-in filter `db|int3` (gadgets.py:31-32), full-mnemonic equality.
    if decodes.iter().any(|d| d.mnem == Mnemonic::Int3) {
        return true;
    }
    if let Some(re) = filter {
        if decodes.iter().any(|d| re.is_match(&cs_mnemonic(d))) {
            return true;
        }
    }
    false
}

/// Compile ROPgadget's mnemonic filter: `re.match("({})$".format(src))` is a
/// full match of the alternation, so the Rust equivalent is `^(?:src)$`
/// (gadgets.py:31-40).
pub fn compile_filter(src: &str) -> Result<Regex, regex::Error> {
    Regex::new(&format!("^(?:{src})$"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt_one(bits: u32, hex: &str) -> Vec<String> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        let mut f = make_formatter();
        format_gadget(&bytes, 0, bytes.len(), 0x1000, bits, &mut f)
    }

    /// Every expectation here is capstone 5.0.7's exact output for those
    /// bytes, captured from the parity oracle's interpreter.
    #[test]
    fn renders_capstone_spelling() {
        let cases32: &[(&str, &str)] = &[
            ("f3c3", "repz ret"), // SCAN-03
            ("f364cb", "retf"),   // rep dropped, `ret far` renamed
            ("f2c3", "bnd ret"),
            ("f2cb", "bnd retf"),
            ("f2ca0700", "bnd retf 7"),
            ("f275ef", "bnd jne 0xff2"),
            ("f2ff20", "bnd jmp dword ptr [eax]"),
            ("66c3", "ret"),         // data16 dropped
            ("f3ebd6", "jmp 0xfd9"), // SCAN-03 spurious `rep jmp` class
            ("f3e922efffff", "jmp 0xffffff28"),
            ("f375ef", "jne 0xff2"),
            ("f389bdb0feffff", "mov dword ptr [ebp - 0x150], edi"),
            ("3ec3", "ret"),
            ("3eebd6", "notrack jmp 0xfd9"),
            ("3eff10", "notrack call dword ptr ds:[eax]"),
            ("3ee800000000", "notrack call 0x1006"),
            ("d7", "xlatb"),
            ("60", "pushal"),
            ("61", "popal"),
            ("6690", "nop"),
            ("368b55dc", "mov edx, dword ptr ss:[ebp - 0x24]"), // SCAN-04
            ("3e8b00", "mov eax, dword ptr ds:[eax]"),          // SCAN-04
            ("6c", "insb byte ptr es:[edi], dx"),               // SCAN-04
            ("26ab", "stosd dword ptr es:[edi], eax"),
            ("ab", "stosd dword ptr es:[edi], eax"),
            ("ad", "lodsd eax, dword ptr [esi]"),
            ("af", "scasd eax, dword ptr es:[edi]"),
            ("a4", "movsb byte ptr es:[edi], byte ptr [esi]"),
            ("64ac", "lodsb al, byte ptr fs:[esi]"),
            ("8b442404", "mov eax, dword ptr [esp + 4]"),
            ("83c008", "add eax, 8"),
            ("83c0f8", "add eax, -8"),
            ("81c0ffffffff", "add eax, 0xffffffff"),
            ("cd80", "int 0x80"),
            ("b0d6", "mov al, 0xd6"),
            ("c20700", "ret 7"),
            ("8d5240", "lea edx, [edx + 0x40]"),
            ("ea010000000200", "ljmp 2:1"),                 // SCAN-06
            ("ea112233445566", "ljmp 0x6655:0x44332211"),   // SCAN-06
            ("9a112233445566", "lcall 0x6655, 0x44332211"), // SCAN-06
            ("ff2a", "jmp ptr [edx]"),                      // SCAN-06
            ("ff1a", "call ptr [edx]"),
            ("0fb208", "lss ecx, ptr [eax]"),
            ("8e0a", "mov cs, word ptr [edx]"),       // SCAN-09
            ("f00a0e", "lock or cl, byte ptr [esi]"), // SCAN-09
            ("d800", "fadd dword ptr [eax]"),
            ("8b048d00000000", "mov eax, dword ptr [ecx*4]"),
            ("8b440804", "mov eax, dword ptr [eax + ecx + 4]"),
            ("8b04c8", "mov eax, dword ptr [eax + ecx*8]"),
            ("6af8", "push -8"),
            ("64a100000000", "mov eax, dword ptr fs:[0]"),
        ];
        for (hex, want) in cases32 {
            assert_eq!(fmt_one(32, hex).join(" ; "), *want, "32-bit {hex}");
        }
        let cases64: &[(&str, &str)] = &[
            ("f3c3", "repz ret"),
            ("3effe0", "notrack jmp rax"),
            ("488b442408", "mov rax, qword ptr [rsp + 8]"),
            ("488d0d11000000", "lea rcx, [rip + 0x11]"),
            ("2e8b45f8", "mov eax, dword ptr cs:[rbp - 8]"),
            ("48ff2a", "ljmp [rdx]"),
            ("48ff1a", "lcall [rdx]"),
            ("aa", "stosb byte ptr [rdi], al"),
            ("48ab", "stosq qword ptr [rdi], rax"),
            ("48b8ffffffffffffffff", "movabs rax, 0xffffffffffffffff"),
            ("4805ffffffff", "add rax, -1"),
            ("64488b042528000000", "mov rax, qword ptr fs:[0x28]"),
        ];
        for (hex, want) in cases64 {
            assert_eq!(fmt_one(64, hex).join(" ; "), *want, "64-bit {hex}");
        }
    }

    /// SCAN-01: `--filter op` is ROPgadget's `(op)$` full match, which no
    /// x86 mnemonic satisfies — it must NOT behave like `ends_with("op")`
    /// and delete every `pop`.
    #[test]
    fn filter_is_a_full_match_not_a_suffix() {
        let re = compile_filter("op").unwrap();
        assert!(!re.is_match("pop"));
        assert!(re.is_match("op"));
        let re = compile_filter("j.*").unwrap();
        assert!(re.is_match("jmp"));
        assert!(re.is_match("jne"));
        assert!(!re.is_match("pop"));
        assert!(!re.is_match("ajmp"));
    }

    /// SCAN-06: `ljmp`/`lcall` are not in ROPgadget's branch list, so a far
    /// branch may not terminate a gadget but may sit in the middle of one.
    #[test]
    fn far_branches_are_not_branch_terminators() {
        let win = decode_window(&[0xea, 1, 0, 0, 0, 2, 0], 0, 0x1000, 32, 7);
        assert_eq!(win.len(), 1);
        assert_eq!(cs_mnemonic(&win[0]), "ljmp");
        assert!(!BRANCH_MNEMONICS.contains(&"ljmp"));
    }
}
