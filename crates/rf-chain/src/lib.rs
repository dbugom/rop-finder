//! rf-chain — ROP chain builders (Phase 4a, PLAN.md §6.2).
//!
//! **Chain IR first** (the review-driven design): builders produce a
//! structured [`RopChain`] — a `Vec<ChainWord>` where every word knows its
//! kind, its comment, and which gadget it came from — and renderers turn
//! the IR into ROPgadget-compatible Python exploit text, JSON, or raw
//! little-endian bytes. ROPgadget's stdout-text design is why nothing can
//! consume its chains programmatically; the IR is the fix.
//!
//! Invariants are checked at build/validation time and reported as
//! structured [`ChainError`]s, never panics:
//!   * every `GadgetAddr` word's value is the vaddr of an actually-reported
//!     gadget (checked against the scan's vaddr universe);
//!   * every non-gadget word (`Immediate` / `DataAddr` / `Padding`) must be
//!     badbyte-free when bad bytes are configured — bad bytes are a
//!     property of the final packed word (PLAN.md §6.4);
//!   * per-target invariant hooks ([`ChainInvariant`]) are the Phase 4b
//!     extension point — the Win64 16-byte stack-alignment invariant lands
//!     there; Linux execve needs no extra invariants.

use rf_core::Arch;
use serde::Serialize;
use std::collections::HashSet;

pub mod linux;

pub use linux::{build_linux_execve, DataSection};

/// What a chain word is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WordKind {
    /// Address of a gadget in the scanned binary.
    GadgetAddr,
    /// Immediate constant (e.g. the packed "/bin//sh" bytes).
    Immediate,
    /// Address of a data-section location (e.g. `@ .data`).
    DataAddr,
    /// Filler consumed by a `pop` in a gadget's tail.
    Padding,
}

fn hex_u64<S: serde::Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{v:x}"))
}

/// One machine word of the chain (8 bytes on x64, 4 on x86).
#[derive(Debug, Clone, Serialize)]
pub struct ChainWord {
    #[serde(serialize_with = "hex_u64")]
    pub value: u64,
    pub kind: WordKind,
    pub comment: String,
    /// Index into [`RopChain::gadgets`] for `GadgetAddr` words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_gadget: Option<usize>,
}

/// A gadget referenced by the chain.
#[derive(Debug, Clone, Serialize)]
pub struct GadgetRef {
    #[serde(serialize_with = "hex_u64")]
    pub vaddr: u64,
    pub text: String,
}

/// A generated ROP chain in target-independent form.
#[derive(Debug, Clone, Serialize)]
pub struct RopChain {
    /// e.g. "x86" / "x64".
    pub arch: String,
    /// Human-readable summary of what the chain does.
    pub description: String,
    /// Bytes per word (4 or 8).
    pub word_size: usize,
    pub words: Vec<ChainWord>,
    /// Distinct gadgets referenced by `GadgetAddr` words, in order of
    /// first reference; `ChainWord::source_gadget` indexes this list.
    pub gadgets: Vec<GadgetRef>,
}

/// Structured chain-building failure. Builders never panic and never emit
/// partial garbage: any missing gadget or violated invariant is an `Err`.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// Mirrors ropmaker.py:23-40 dispatch: only ELF x86/x64 are supported.
    #[error("arch {arch} / format {format} not supported yet for the rop chain generation")]
    Unsupported { arch: String, format: String },
    /// A required gadget is absent from the scan output.
    #[error("can't find a suitable gadget: {0}")]
    MissingGadget(String),
    /// No `.data` (and no fallback writable section) for the string write.
    #[error("can't find a writable section")]
    NoWritableSection,
    /// An IR invariant was violated (see [`RopChain::validate`]).
    #[error("chain word {index} (0x{value:016x}, {kind:?}): {reason}")]
    InvalidWord {
        index: usize,
        value: u64,
        kind: WordKind,
        reason: String,
    },
}

/// Per-target invariant hook (Phase 4b extension point). Receives the full
/// chain; returns `Err` to reject it. Example for Phase 4b (Win64):
/// "rsp must be 16-byte aligned at the VirtualProtect call site".
pub type ChainInvariant<'a> = &'a dyn Fn(&RopChain) -> Result<(), ChainError>;

impl RopChain {
    /// Check the build-time invariants:
    ///   * every `GadgetAddr` word points at a real reported gadget
    ///     (`universe` = the scan's vaddr set) and its `source_gadget`
    ///     index agrees;
    ///   * every non-gadget word is badbyte-free (packed at `word_size`).
    pub fn validate(&self, universe: &HashSet<u64>, badbytes: &[u8]) -> Result<(), ChainError> {
        self.validate_with(universe, badbytes, &[])
    }

    /// [`validate`](Self::validate) plus per-target invariant hooks.
    pub fn validate_with(
        &self,
        universe: &HashSet<u64>,
        badbytes: &[u8],
        hooks: &[ChainInvariant],
    ) -> Result<(), ChainError> {
        for (i, w) in self.words.iter().enumerate() {
            let invalid = |reason: String| ChainError::InvalidWord {
                index: i,
                value: w.value,
                kind: w.kind,
                reason,
            };
            match w.kind {
                WordKind::GadgetAddr => {
                    let idx = w
                        .source_gadget
                        .ok_or_else(|| invalid("gadget word without source_gadget".to_string()))?;
                    let g = self
                        .gadgets
                        .get(idx)
                        .ok_or_else(|| invalid(format!("source_gadget {idx} out of range")))?;
                    if g.vaddr != w.value {
                        return Err(invalid(format!(
                            "value {:#x} != gadgets[{idx}].vaddr {:#x}",
                            w.value, g.vaddr
                        )));
                    }
                    if !universe.contains(&w.value) {
                        return Err(invalid(format!(
                            "vaddr {:#x} is not in the scan output",
                            w.value
                        )));
                    }
                }
                WordKind::Immediate | WordKind::DataAddr | WordKind::Padding => {
                    if !badbytes.is_empty() {
                        let packed = &w.value.to_le_bytes()[..self.word_size];
                        if let Some(b) = packed.iter().find(|b| badbytes.contains(b)) {
                            return Err(invalid(format!(
                                "packed word contains bad byte 0x{b:02x}"
                            )));
                        }
                    }
                }
            }
        }
        for hook in hooks {
            hook(self)?;
        }
        Ok(())
    }

    /// The scan's vaddr universe, for [`validate`](Self::validate).
    pub fn universe_from(gadgets: &[rf_scan::Gadget]) -> HashSet<u64> {
        gadgets.iter().map(|g| g.vaddr).collect()
    }

    fn pack_char(&self) -> (char, usize) {
        match self.word_size {
            4 => ('I', 8),
            _ => ('Q', 16),
        }
    }

    /// ROPgadget-compatible Python exploit script (ropmakerx64.py output
    /// structure: the `from struct import pack` header, `p = b''`, and
    /// `p += pack('<Q', 0x...) # ...` lines; padding lines are
    /// tab-indented; string immediates render as `p += b'...'`).
    pub fn to_python(&self) -> String {
        let (c, w) = self.pack_char();
        let mask = if self.word_size >= 8 {
            u64::MAX
        } else {
            (1u64 << (self.word_size * 8)) - 1
        };
        let mut out = String::from(
            "#!/usr/bin/env python3\n# execve generated by ROPgadget\n\nfrom struct import pack\n\n# Padding goes here\np = b''\n\n",
        );
        for word in &self.words {
            let value = word.value & mask;
            match word.kind {
                WordKind::Immediate => {
                    let bytes = &value.to_le_bytes()[..self.word_size];
                    out.push_str(&format!("p += b'{}'\n", py_bytes_escape(bytes)));
                }
                WordKind::Padding => {
                    out.push_str(&format!(
                        "\tp += pack('<{c}', 0x{:0w$x}) # {}\n",
                        value, word.comment
                    ));
                }
                WordKind::GadgetAddr | WordKind::DataAddr => {
                    out.push_str(&format!(
                        "p += pack('<{c}', 0x{:0w$x}) # {}\n",
                        value, word.comment
                    ));
                }
            }
        }
        out
    }

    /// JSON form of the IR.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap()
    }

    /// Raw little-endian bytes of the chain (what `p` contains at runtime).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.words.len() * self.word_size);
        for w in &self.words {
            out.extend_from_slice(&w.value.to_le_bytes()[..self.word_size]);
        }
        out
    }
}

/// Render bytes as a Python `b'...'` literal body (ROPgadget only ever
/// emits printable ASCII here, but escape defensively).
fn py_bytes_escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'\'' => out.push_str("\\'"),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

/// Arch display name used in the IR (`"x86"` / `"x64"` / ...).
pub fn arch_name(arch: Arch) -> String {
    match arch {
        Arch::X86 => "x86",
        Arch::X64 => "x64",
        Arch::Arm => "arm",
        Arch::ArmThumb => "arm-thumb",
        Arch::Arm64 => "arm64",
        Arch::Mips32 => "mips32",
        Arch::Mips64 => "mips64",
        Arch::Ppc32 => "ppc32",
        Arch::Ppc64 => "ppc64",
        Arch::Sparc => "sparc",
        Arch::Sparc64 => "sparc64",
        Arch::SparcV9 => "sparcv9",
        Arch::RiscV32 => "riscv32",
        Arch::RiscV64 => "riscv64",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain_fixture() -> RopChain {
        RopChain {
            arch: "x64".to_string(),
            description: "test".to_string(),
            word_size: 8,
            gadgets: vec![GadgetRef {
                vaddr: 0x401000,
                text: "pop rdi ; ret".to_string(),
            }],
            words: vec![
                ChainWord {
                    value: 0x401000,
                    kind: WordKind::GadgetAddr,
                    comment: "pop rdi ; ret".to_string(),
                    source_gadget: Some(0),
                },
                ChainWord {
                    value: 0x6bc080,
                    kind: WordKind::DataAddr,
                    comment: "@ .data".to_string(),
                    source_gadget: None,
                },
                ChainWord {
                    value: 0x4141414141414141,
                    kind: WordKind::Padding,
                    comment: "padding".to_string(),
                    source_gadget: None,
                },
            ],
        }
    }

    #[test]
    fn validate_accepts_wellformed() {
        let c = chain_fixture();
        let universe: HashSet<u64> = [0x401000].into_iter().collect();
        c.validate(&universe, &[]).unwrap();
    }

    #[test]
    fn validate_rejects_unknown_gadget_addr() {
        let mut c = chain_fixture();
        c.words[0].value = 0xdead0000;
        let universe: HashSet<u64> = [0x401000].into_iter().collect();
        let err = c.validate(&universe, &[]).unwrap_err();
        assert!(matches!(err, ChainError::InvalidWord { index: 0, .. }));
    }

    #[test]
    fn validate_rejects_source_mismatch_and_missing_index() {
        let universe: HashSet<u64> = [0x401000, 0x401002].into_iter().collect();
        let mut c = chain_fixture();
        c.words[0].value = 0x401002; // in universe but != gadgets[0].vaddr
        assert!(c.validate(&universe, &[]).is_err());
        let mut c = chain_fixture();
        c.words[0].source_gadget = None;
        assert!(c.validate(&universe, &[]).is_err());
        let mut c = chain_fixture();
        c.words[0].source_gadget = Some(7);
        assert!(c.validate(&universe, &[]).is_err());
    }

    #[test]
    fn validate_rejects_badbyte_immediates_and_data_addrs() {
        let c = chain_fixture();
        let universe: HashSet<u64> = [0x401000].into_iter().collect();
        // 0x6bc080 packs to 80 c0 6b 00 ... — byte 00 is bad
        let err = c.validate(&universe, &[0x00]).unwrap_err();
        assert!(matches!(err, ChainError::InvalidWord { index: 1, .. }));
        // 0x41 in the padding constant
        let err = c.validate(&universe, &[0x41]).unwrap_err();
        assert!(matches!(err, ChainError::InvalidWord { index: 2, .. }));
        // gadget words are not re-checked (they passed scan-time badbytes)
        c.validate(&universe, &[0x10]).unwrap();
    }

    #[test]
    fn invariant_hooks_run() {
        let c = chain_fixture();
        let universe: HashSet<u64> = [0x401000].into_iter().collect();
        let reject: ChainInvariant = &|_| {
            Err(ChainError::InvalidWord {
                index: 0,
                value: 0,
                kind: WordKind::GadgetAddr,
                reason: "hook says no".to_string(),
            })
        };
        let err = c.validate_with(&universe, &[], &[reject]).unwrap_err();
        assert!(err.to_string().contains("hook says no"));
    }

    #[test]
    fn python_renderer_matches_ropmaker_format() {
        let c = chain_fixture();
        let py = c.to_python();
        assert!(py.starts_with(
            "#!/usr/bin/env python3\n# execve generated by ROPgadget\n\nfrom struct import pack\n\n# Padding goes here\np = b''\n\n"
        ));
        assert!(py.contains("p += pack('<Q', 0x0000000000401000) # pop rdi ; ret\n"));
        assert!(py.contains("p += pack('<Q', 0x00000000006bc080) # @ .data\n"));
        // padding lines are tab-indented
        assert!(py.contains("\tp += pack('<Q', 0x4141414141414141) # padding\n"));
    }

    #[test]
    fn x86_pack_format() {
        let mut c = chain_fixture();
        c.word_size = 4;
        let py = c.to_python();
        assert!(py.contains("pack('<I', 0x00401000)"));
        assert!(py.contains("\tp += pack('<I', 0x41414141) # padding\n"));
        // raw bytes are 4-byte LE words
        let raw = c.to_bytes();
        assert_eq!(raw.len(), 12);
        assert_eq!(&raw[0..4], &0x401000u32.to_le_bytes());
    }

    #[test]
    fn immediate_renders_as_python_bytes() {
        let mut c = chain_fixture();
        c.words.push(ChainWord {
            value: u64::from_le_bytes(*b"/bin//sh"),
            kind: WordKind::Immediate,
            comment: String::new(),
            source_gadget: None,
        });
        let py = c.to_python();
        assert!(py.contains("p += b'/bin//sh'\n"));
        let raw = c.to_bytes();
        assert_eq!(&raw[24..32], b"/bin//sh");
    }

    #[test]
    fn json_renderer_roundtrips() {
        let c = chain_fixture();
        let v = c.to_json();
        assert_eq!(v["arch"], "x64");
        assert_eq!(v["word_size"], 8);
        assert_eq!(v["words"][0]["value"], "0x401000");
        assert_eq!(v["words"][0]["kind"], "gadget_addr");
        assert_eq!(v["gadgets"][0]["text"], "pop rdi ; ret");
    }
}
