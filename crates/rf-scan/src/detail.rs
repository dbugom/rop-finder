//! Per-instruction semantic metadata from capstone **detail mode** (ECO-05).
//!
//! The scanning path ([`crate::cs`]) drives capstone as a pure text
//! formatter: [`crate::cs::open`] used to call `Capstone::new_raw` and never
//! `set_detail(true)`, so `regs_read`/`regs_written` were empty on the eight
//! architectures that decode through capstone and `rf_classify::classify`
//! fell back to splitting mnemonic strings.
//!
//! Detail mode is capstone's expensive path — it fills `cs_detail` for every
//! decoded instruction, and the scanner decodes one window per *candidate*,
//! of which only a small fraction are ever emitted. So detail is **not**
//! enabled during scanning. It is decoded on demand, from
//! [`Gadget::bytes`](crate::Gadget::bytes), by the consumer that actually
//! wants semantics — exactly as the x86/x64 classifier already re-decodes
//! `g.bytes` with iced-x86. That keeps the cost proportional to the number of
//! gadgets *classified* rather than the number of candidates *considered*,
//! and it means a scan that is not classified pays nothing at all.
//!
//! ## Mode resolution
//!
//! [`crate::Gadget`] records the architecture only through the image
//! it came from; it does not record endianness or ARM/Thumb mode. Rather than
//! widen every call signature, [`Detailer::resolve`] opens every capstone mode
//! that is plausible for an [`Arch`] and keeps the one that **reproduces the
//! gadget's own text byte-for-byte**. Every decode is then re-verified against
//! the recorded text ([`Detailer::decode_checked`]), so metadata is only ever
//! attached to a decode that agrees with what the scanner printed — a wrong
//! mode degrades to "no metadata", never to wrong metadata.

use capstone::arch::ArchOperand;
use capstone::{Capstone, InsnGroupId, InsnGroupType, RegId};

use rf_core::{Arch, Endianness, Error};

use crate::cs::{self, CsSpec};
use crate::Gadget;

/// The architecture-independent capstone instruction groups (`CS_GRP_*` 1-7),
/// as a flat record. Architecture-specific groups are not carried: the
/// classifier only needs "is this a transfer of control" and "is this
/// privileged", and those seven ids mean the same thing on every arch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InsnGroups {
    /// `CS_GRP_JUMP`.
    pub jump: bool,
    /// `CS_GRP_CALL`.
    pub call: bool,
    /// `CS_GRP_RET`.
    pub ret: bool,
    /// `CS_GRP_INT` — a software interrupt / trap.
    pub int: bool,
    /// `CS_GRP_IRET` — an interrupt return.
    pub iret: bool,
    /// `CS_GRP_PRIVILEGE`.
    pub privileged: bool,
    /// `CS_GRP_BRANCH_RELATIVE` — a PC-relative branch.
    pub branch_relative: bool,
}

impl InsnGroups {
    /// Any transfer of control (jump, call, return or interrupt return).
    pub fn control(&self) -> bool {
        self.jump || self.call || self.ret || self.iret
    }

    fn from_ids(ids: &[InsnGroupId]) -> Self {
        let mut g = InsnGroups::default();
        for id in ids {
            match u32::from(id.0) {
                InsnGroupType::CS_GRP_JUMP => g.jump = true,
                InsnGroupType::CS_GRP_CALL => g.call = true,
                InsnGroupType::CS_GRP_RET => g.ret = true,
                InsnGroupType::CS_GRP_INT => g.int = true,
                InsnGroupType::CS_GRP_IRET => g.iret = true,
                InsnGroupType::CS_GRP_PRIVILEGE => g.privileged = true,
                InsnGroupType::CS_GRP_BRANCH_RELATIVE => g.branch_relative = true,
                _ => {}
            }
        }
        g
    }
}

/// A memory operand's shape: `disp(base)` on MIPS/PPC/RISC-V,
/// `[base, index]` on ARM/ARM64, `[base + index]` on SPARC. Register names
/// are normalized by [`normalize_reg`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemRef {
    /// Base register, normalized to lowercase.
    pub base: Option<String>,
    /// Index register, normalized to lowercase.
    pub index: Option<String>,
    /// Signed displacement, in bytes.
    pub disp: i64,
}

/// One decoded operand, architecture-independent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// A register, normalized to lowercase.
    Reg(String),
    /// An immediate.
    Imm(i64),
    /// A memory reference.
    Mem(MemRef),
    /// Anything else capstone models per-architecture (condition fields,
    /// coprocessor operands, register lists already expanded into `Reg`).
    Other,
}

/// An operand plus capstone's per-operand access flags **where the
/// architecture reports them**. capstone 5.0 fills `cs_ac_type` for ARM and
/// ARM64 only; `access` is `None` everywhere else and the consumer has to
/// decide from the mnemonic (which is what [`crate::detail`]'s callers do).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperandInfo {
    /// The operand itself.
    pub op: Operand,
    /// Read/write flags, where the architecture reports them.
    pub access: Option<Access>,
}

/// Read/write flags for one operand.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Access {
    /// The instruction reads this operand.
    pub read: bool,
    /// The instruction writes this operand.
    pub write: bool,
}

/// Everything detail mode yields for a single instruction.
///
/// Index `i` of a [`Detailer::decode_checked`] result corresponds to index
/// `i` of [`Gadget::insns`](crate::Gadget::insns) — that correspondence is
/// what `decode_checked` verifies before returning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsnDetail {
    /// Lowercase mnemonic (`"lw"`, `"addiu"`, `"c.ld"`).
    pub mnemonic: String,
    /// Registers capstone reports as read. Only ARM, ARM64 (and x86, which
    /// does not use this path) implement `cs_regs_access`, so on MIPS, PPC,
    /// SPARC and RISC-V this holds the *implicit* reads only — usually
    /// nothing. Derive the explicit ones from [`InsnDetail::operands`].
    pub regs_read: Vec<String>,
    /// Registers capstone reports as written. Same caveat as
    /// [`InsnDetail::regs_read`].
    pub regs_written: Vec<String>,
    /// The decoded operands, in operand order.
    pub operands: Vec<OperandInfo>,
    /// The architecture-independent capstone groups.
    pub groups: InsnGroups,
}

impl InsnDetail {
    /// The instruction's memory operands, in operand order.
    pub fn mem_refs(&self) -> impl Iterator<Item = &MemRef> {
        self.operands.iter().filter_map(|o| match &o.op {
            Operand::Mem(m) => Some(m),
            _ => None,
        })
    }

    /// Register operands, in operand order.
    pub fn reg_operands(&self) -> impl Iterator<Item = &str> {
        self.operands.iter().filter_map(|o| match &o.op {
            Operand::Reg(r) => Some(r.as_str()),
            _ => None,
        })
    }
}

/// Strip a disassembly sigil and lowercase: `"$sp"` -> `"sp"`,
/// `"%o0"` -> `"o0"`, `"R4"` -> `"r4"`.
///
/// capstone prints MIPS registers with `$` and SPARC registers with `%`;
/// carrying the sigil into `regs_written` makes the field un-matchable
/// against a user-supplied register name and un-checkable against any
/// register-name grammar (CLS-05).
pub fn normalize_reg(name: &str) -> String {
    name.trim_start_matches(['$', '%']).to_ascii_lowercase()
}

/// A capstone handle with detail mode on, pinned to one resolved
/// (arch, endianness, mode) triple.
///
/// capstone-rs `Capstone` is `!Send`/`!Sync`, so a `Detailer` is single
/// threaded; construct one per worker thread.
pub struct Detailer {
    cs: Capstone,
    spec: CsSpec,
    arch: Arch,
}

impl std::fmt::Debug for Detailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detailer")
            .field("arch", &self.arch)
            .field("mode", &self.spec.mode)
            .field("endian", &self.spec.endian)
            .finish()
    }
}

impl Detailer {
    /// Open a detail-mode handle for an explicitly known configuration.
    /// Open a capstone handle in detail mode for `(arch, endian, thumb)`.
    ///
    /// Fails with [`crate::Error::Core`] when no capstone configuration
    /// covers the combination.
    pub fn new(arch: Arch, endian: Endianness, thumb: bool) -> Result<Self, Error> {
        let spec = cs::spec(arch, endian, thumb)?;
        let cs = cs::open_detail(&spec, true)?;
        Ok(Detailer { cs, spec, arch })
    }

    /// The architecture this detailer was opened for.
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// Every capstone configuration that could have produced a gadget for
    /// `arch`, most likely first. ARM images may have been scanned in either
    /// ARM or Thumb mode and either endianness; MIPS/PPC/SPARC differ only in
    /// endianness; RISC-V is little-endian only.
    fn candidates(arch: Arch) -> Vec<(Endianness, bool)> {
        use Endianness::{Big, Little};
        match arch {
            Arch::Arm | Arch::ArmThumb => {
                vec![(Little, false), (Little, true), (Big, false), (Big, true)]
            }
            Arch::Arm64 => vec![(Little, false), (Big, false)],
            Arch::Mips32 | Arch::Mips64 => vec![(Big, false), (Little, false)],
            Arch::Ppc32 | Arch::Ppc64 => vec![(Big, false), (Little, false)],
            Arch::Sparc | Arch::Sparc64 | Arch::SparcV9 => vec![(Big, false)],
            Arch::RiscV32 | Arch::RiscV64 => vec![(Little, false)],
            Arch::X86 | Arch::X64 => Vec::new(),
        }
    }

    /// Open a detail handle for every capstone configuration that could have
    /// produced gadgets for `arch` (at most four; none for x86/x64).
    ///
    /// A caller that classifies many gadgets opens these once and asks each
    /// gadget which one reproduces its text, instead of re-resolving per
    /// gadget: `cs_open` is not free, and `Capstone` is `!Send`, so the
    /// natural home for the set is a per-thread cache.
    pub fn all_candidates(arch: Arch) -> Vec<Detailer> {
        Self::candidates(arch)
            .into_iter()
            .filter_map(|(e, t)| Detailer::new(arch, e, t).ok())
            .collect()
    }

    /// Open the detail handle whose decode reproduces `sample`'s recorded
    /// text exactly. Returns `None` for x86/x64 (they use iced-x86) and when
    /// no candidate mode reproduces the text — the caller then keeps whatever
    /// text-only path it had.
    pub fn resolve(arch: Arch, sample: &Gadget) -> Option<Detailer> {
        for (endian, thumb) in Self::candidates(arch) {
            let Ok(d) = Detailer::new(arch, endian, thumb) else {
                continue;
            };
            if d.decode_checked(sample).is_some() {
                return Some(d);
            }
        }
        None
    }

    /// Decode `bytes` at `vaddr` with detail on, unconditionally.
    pub fn decode(&self, bytes: &[u8], vaddr: u64) -> Vec<InsnDetail> {
        self.decode_inner(bytes, vaddr, None).unwrap_or_default()
    }

    /// Shared body of [`Detailer::decode`] and [`Detailer::decode_checked`].
    ///
    /// When `expect` is given, each instruction's text is compared against the
    /// corresponding entry as it is decoded and the whole decode is abandoned
    /// on the first mismatch. Doing the check inside the single `disasm_all`
    /// pass is what keeps mode verification from doubling the cost of
    /// classification: the alternative — format the gadget, compare, then
    /// decode again — disassembles every gadget twice.
    fn decode_inner(
        &self,
        bytes: &[u8],
        vaddr: u64,
        expect: Option<&[String]>,
    ) -> Option<Vec<InsnDetail>> {
        let insns = self.cs.disasm_all(bytes, vaddr).ok()?;
        if let Some(e) = expect {
            if insns.len() != e.len() {
                return None;
            }
        }
        let mut out = Vec::with_capacity(insns.len());
        for (i, insn) in insns.iter().enumerate() {
            if let Some(e) = expect {
                if cs::insn_text(insn) != e[i] {
                    return None;
                }
            }
            let mnemonic = insn.mnemonic().unwrap_or("").to_ascii_lowercase();
            let Ok(det) = self.cs.insn_detail(insn) else {
                out.push(InsnDetail {
                    mnemonic,
                    regs_read: Vec::new(),
                    regs_written: Vec::new(),
                    operands: Vec::new(),
                    groups: InsnGroups::default(),
                });
                continue;
            };
            let groups = InsnGroups::from_ids(det.groups());
            let regs_read = self.reg_names(det.regs_read());
            let regs_written = self.reg_names(det.regs_write());
            let operands = det
                .arch_detail()
                .operands()
                .into_iter()
                .map(|o| self.operand(o))
                .collect();
            out.push(InsnDetail {
                mnemonic,
                regs_read,
                regs_written,
                operands,
                groups,
            });
        }
        Some(out)
    }

    /// Decode `g.bytes` and return the detail records only when the decode
    /// reproduces `g.insns` exactly (same instruction count, same text).
    ///
    /// This is the guard that lets [`Detailer::resolve`] pick a mode by
    /// experiment: a mismatched endianness or ARM/Thumb setting cannot
    /// silently supply metadata for a different instruction stream.
    pub fn decode_checked(&self, g: &Gadget) -> Option<Vec<InsnDetail>> {
        if g.bytes.is_empty() {
            return None;
        }
        self.decode_inner(&g.bytes, g.vaddr, Some(&g.insns))
    }

    fn reg_names(&self, ids: &[RegId]) -> Vec<String> {
        ids.iter()
            .filter(|r| r.0 != 0)
            .filter_map(|r| self.cs.reg_name(*r))
            .map(|n| normalize_reg(&n))
            .collect()
    }

    fn reg(&self, id: RegId) -> Option<String> {
        if id.0 == 0 {
            return None;
        }
        self.cs.reg_name(id).map(|n| normalize_reg(&n))
    }

    fn operand(&self, o: ArchOperand) -> OperandInfo {
        use capstone::arch::arm::{ArmOperand, ArmOperandType};
        use capstone::arch::arm64::{Arm64Operand, Arm64OperandType};
        use capstone::arch::mips::MipsOperand;
        use capstone::arch::ppc::PpcOperand;
        use capstone::arch::riscv::RiscVOperand;
        use capstone::arch::sparc::SparcOperand;

        let access = |a: Option<capstone::AccessType>| {
            a.map(|a| Access {
                read: a.is_readable(),
                write: a.is_writable(),
            })
        };

        match o {
            ArchOperand::ArmOperand(ArmOperand {
                op_type,
                access: ac,
                ..
            }) => {
                let op = match op_type {
                    ArmOperandType::Reg(r) => {
                        self.reg(r).map(Operand::Reg).unwrap_or(Operand::Other)
                    }
                    ArmOperandType::Imm(i) => Operand::Imm(i as i64),
                    ArmOperandType::Mem(m) => Operand::Mem(MemRef {
                        base: self.reg(m.base()),
                        index: self.reg(m.index()),
                        disp: m.disp() as i64,
                    }),
                    _ => Operand::Other,
                };
                OperandInfo {
                    op,
                    access: access(ac),
                }
            }
            ArchOperand::Arm64Operand(Arm64Operand {
                op_type,
                access: ac,
                ..
            }) => {
                let op = match op_type {
                    Arm64OperandType::Reg(r) => {
                        self.reg(r).map(Operand::Reg).unwrap_or(Operand::Other)
                    }
                    Arm64OperandType::Imm(i) => Operand::Imm(i),
                    Arm64OperandType::Mem(m) => Operand::Mem(MemRef {
                        base: self.reg(m.base()),
                        index: self.reg(m.index()),
                        disp: m.disp() as i64,
                    }),
                    _ => Operand::Other,
                };
                OperandInfo {
                    op,
                    access: access(ac),
                }
            }
            ArchOperand::MipsOperand(m) => OperandInfo {
                op: match m {
                    MipsOperand::Reg(r) => self.reg(r).map(Operand::Reg).unwrap_or(Operand::Other),
                    MipsOperand::Imm(i) => Operand::Imm(i),
                    MipsOperand::Mem(m) => Operand::Mem(MemRef {
                        base: self.reg(m.base()),
                        index: None,
                        disp: m.disp(),
                    }),
                    MipsOperand::Invalid => Operand::Other,
                },
                access: None,
            },
            ArchOperand::PpcOperand(p) => OperandInfo {
                op: match p {
                    PpcOperand::Reg(r) => self.reg(r).map(Operand::Reg).unwrap_or(Operand::Other),
                    PpcOperand::Imm(i) => Operand::Imm(i),
                    PpcOperand::Mem(m) => Operand::Mem(MemRef {
                        base: self.reg(m.base()),
                        index: None,
                        disp: m.disp() as i64,
                    }),
                    _ => Operand::Other,
                },
                access: None,
            },
            ArchOperand::RiscVOperand(r) => OperandInfo {
                op: match r {
                    RiscVOperand::Reg(r) => self.reg(r).map(Operand::Reg).unwrap_or(Operand::Other),
                    RiscVOperand::Imm(i) => Operand::Imm(i),
                    RiscVOperand::Mem(m) => Operand::Mem(MemRef {
                        base: self.reg(m.base()),
                        index: None,
                        disp: m.disp(),
                    }),
                    RiscVOperand::Invalid => Operand::Other,
                },
                access: None,
            },
            ArchOperand::SparcOperand(s) => OperandInfo {
                op: match s {
                    SparcOperand::Reg(r) => self.reg(r).map(Operand::Reg).unwrap_or(Operand::Other),
                    SparcOperand::Imm(i) => Operand::Imm(i),
                    SparcOperand::Mem(m) => Operand::Mem(MemRef {
                        base: self.reg(m.base()),
                        index: self.reg(m.index()),
                        disp: m.disp() as i64,
                    }),
                    SparcOperand::Invalid => Operand::Other,
                },
                access: None,
            },
            _ => OperandInfo {
                op: Operand::Other,
                access: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TableKind;

    fn gadget(bytes: &[u8], vaddr: u64, text: &str) -> Gadget {
        Gadget {
            vaddr,
            bytes: bytes.to_vec(),
            insns: text.split(" ; ").map(str::to_string).collect(),
            delay_slot: false,
            prev: None,
            table: TableKind::Rop,
        }
    }

    #[test]
    fn arm64_detail_has_registers_and_groups() {
        // e0 03 01 aa = mov x0, x1 ; c0 03 5f d6 = ret
        let g = gadget(
            &[0xe0, 0x03, 0x01, 0xaa, 0xc0, 0x03, 0x5f, 0xd6],
            0x4000,
            "mov x0, x1 ; ret",
        );
        let d = Detailer::resolve(Arch::Arm64, &g).expect("arm64 detailer");
        let det = d.decode_checked(&g).expect("text reproduced");
        assert_eq!(det.len(), 2);
        assert_eq!(det[0].mnemonic, "mov");
        assert!(det[0].regs_written.contains(&"x0".to_string()), "{det:?}");
        assert!(det[0].regs_read.contains(&"x1".to_string()), "{det:?}");
        assert!(det[1].groups.ret, "ret must carry CS_GRP_RET: {det:?}");
    }

    #[test]
    fn mips_be_memory_operand_is_off_reg_not_brackets() {
        // 8f a2 00 10 = lw $v0, 0x10($sp) ; 03 e0 00 08 = jr $ra ; nop
        let g = gadget(
            &[
                0x8f, 0xa2, 0x00, 0x10, 0x03, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
            ],
            0x400000,
            "lw $v0, 0x10($sp) ; jr $ra ; nop",
        );
        let d = Detailer::resolve(Arch::Mips32, &g).expect("mips detailer");
        let det = d.decode_checked(&g).expect("text reproduced");
        let m = det[0].mem_refs().next().expect("lw has a memory operand");
        assert_eq!(m.base.as_deref(), Some("sp"), "sigil must be stripped");
        assert_eq!(m.disp, 0x10);
        assert!(det[1].groups.jump, "jr is a jump: {:?}", det[1]);
    }

    #[test]
    fn wrong_mode_is_rejected_rather_than_believed() {
        // MIPS big-endian bytes decoded little-endian must not be accepted.
        let g = gadget(
            &[0x03, 0xe0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00],
            0x400000,
            "jr $ra ; nop",
        );
        let le = Detailer::new(Arch::Mips32, Endianness::Little, false).unwrap();
        assert!(le.decode_checked(&g).is_none());
        let be = Detailer::new(Arch::Mips32, Endianness::Big, false).unwrap();
        assert!(be.decode_checked(&g).is_some());
        // resolve() picks the working one.
        assert!(Detailer::resolve(Arch::Mips32, &g).is_some());
    }

    #[test]
    fn x86_has_no_capstone_detailer() {
        let g = gadget(&[0x5f, 0xc3], 0x401000, "pop rdi ; ret");
        assert!(Detailer::resolve(Arch::X64, &g).is_none());
        assert!(Detailer::resolve(Arch::X86, &g).is_none());
    }

    /// ECO-05's load-bearing invariant: turning `CS_OPT_DETAIL` on must not
    /// change a single character of capstone's disassembly text, because that
    /// text is what `tests/parity.py` compares against the oracle. Scanned
    /// with detail off, re-decoded with detail on, every gadget must come
    /// back identical — on every capstone-driven fixture.
    #[test]
    fn detail_mode_does_not_change_text() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
        let fixtures = [
            "elf-ARM64-bash",
            "elf-ARMv7-ls",
            "elf-Mips-Defcon-20-pwn100",
            "elf-PowerPC-bash",
            "elf-PPC64-bash",
            "elf-SparcV8-bash",
            "elf-Linux-RISCV_32",
            "elf-Linux-RISCV_64",
        ];
        for name in fixtures {
            let data = std::fs::read(root.join(name)).unwrap();
            let rf_core::LoadedBinary::Elf(b) = rf_core::Binary::load(&data).unwrap() else {
                panic!("{name}: expected ELF");
            };
            let arch = rf_core::Image::arch(&b);
            let opts = crate::ScanOptions {
                depth: 3,
                ..Default::default()
            };
            let gadgets = crate::scan_binary(&b, &opts).unwrap();
            assert!(!gadgets.is_empty(), "{name}: no gadgets");
            let cands = Detailer::all_candidates(arch);
            assert!(
                !cands.is_empty(),
                "{name}: no detail candidates for {arch:?}"
            );
            let mut checked = 0usize;
            for g in gadgets.iter().take(4000) {
                let ok = cands.iter().any(|d| d.decode_checked(g).is_some());
                assert!(
                    ok,
                    "{name}: detail-mode decode did not reproduce {:#x} {:?}",
                    g.vaddr,
                    g.text()
                );
                checked += 1;
            }
            assert!(checked > 0);
        }
    }

    #[test]
    fn arm_thumb_and_arm_modes_are_distinguished() {
        // ARM (A32): 1e ff 2f e1 = bx lr
        let a32 = gadget(&[0x1e, 0xff, 0x2f, 0xe1], 0x1000, "bx lr");
        let d = Detailer::resolve(Arch::Arm, &a32).expect("a32 detailer");
        assert!(d.decode_checked(&a32).is_some());
        // Thumb: 70 47 = bx lr
        let t = gadget(&[0x70, 0x47], 0x2000, "bx lr");
        let d = Detailer::resolve(Arch::ArmThumb, &t).expect("thumb detailer");
        assert!(d.decode_checked(&t).is_some());
    }
}
