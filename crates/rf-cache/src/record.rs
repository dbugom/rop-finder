//! The one on-disk cache record, shared by rf-cli and rf-mcp.
//!
//! Before this crate existed there were two of these — `rf_cli::CacheFile`
//! and `rf_mcp::CachedScan` — with two reconstruction functions, and the
//! ROB-04 char-boundary panic lived in *both* of them. One record, one
//! reconstruction, one [`CachedScan::validate`].

use serde::{Deserialize, Serialize};

use crate::hex::{decode_hex, encode_hex, is_hex_bytes, parse_hex_u64, MAX_GADGET_BYTES};

/// Payload schema version. Bumped whenever the record shape changes; a
/// mismatch is a miss, never a mis-parse. (The *key* carries its own
/// schema version — see [`crate::make_key`] — so an old entry is not even
/// looked up under a new key format.)
pub const CACHE_FORMAT_VERSION: u32 = 2;

/// Largest gadget text a cache entry may carry.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
/// Largest number of gadgets in one entry. The entry byte cap
/// ([`crate::CacheLimits::max_entry_bytes`]) is the primary bound — it is
/// enforced by `stat` before a byte is read — and this is the backstop for
/// an entry that is small on disk but expands.
pub const MAX_GADGETS_PER_ENTRY: usize = 10_000_000;
/// Largest number of instructions in one gadget (`--depth` is bounded well
/// below this).
pub const MAX_INSNS_PER_GADGET: usize = 4096;
/// Largest `prev` context, in bytes: `gadgets.py` captures at most 9.
pub const MAX_PREV_BYTES: usize = 16;
/// Cap on the small free-text fields (`arch`, `section`, `class`).
pub const MAX_LABEL_BYTES: usize = 256;

/// The classifier's `Class::name()` values. `class: "../../etc"` in an
/// entry is not a path — nothing joins it to anything — but an unknown
/// class is still evidence the entry did not come from this program, so it
/// is refused. `known_classes_match_rf_classify` keeps the list honest.
pub const KNOWN_CLASSES: &[&str] = &[
    "reg-write",
    "stack-pivot",
    "mem-read",
    "mem-write",
    "arithmetic",
    "syscall",
    "dispatcher",
    "other",
];

fn is_false(b: &bool) -> bool {
    !*b
}

/// One cached gadget.
///
/// The serialized shape is the union of what both front ends need, and
/// every field either front end does not use is skipped when empty — so
/// rf-mcp's response objects are byte-identical to what they were before
/// this crate existed (`vaddr`, `bytes`, `text`, and the optional `arch`,
/// `section`, `quality`, `class`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedGadget {
    /// Address in hex, with or without a `0x` prefix. rf-mcp stores the
    /// zero-padded display form; rf-cli stores bare hex.
    pub vaddr: String,
    /// Gadget bytes as lowercase hex.
    pub bytes: String,
    /// `insns.join(" ; ")` — what rf-mcp returns to the agent. Empty (and
    /// then omitted) in an rf-cli entry, which carries `insns` instead:
    /// storing both would put every instruction in the file twice, and
    /// CLI-08 is a finding about how much disk this cache uses.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// Phase 5 quality score (TAXONOMY.md R12), computed once at scan time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<i32>,
    /// Phase 5 primary class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// Instruction list. Present when the producer had it (rf-cli), so the
    /// reconstruction does not have to re-split `text`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insns: Option<Vec<String>>,
    /// MIPS/SPARC delay slot flag.
    #[serde(default, skip_serializing_if = "is_false")]
    pub delay_slot: bool,
    /// Hex of the section bytes preceding the gadget — `--callPreceded`
    /// scans only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
}

impl Default for CachedGadget {
    fn default() -> Self {
        CachedGadget {
            vaddr: "0".to_string(),
            bytes: String::new(),
            text: String::new(),
            arch: None,
            section: None,
            quality: None,
            class: None,
            insns: None,
            delay_slot: false,
            prev: None,
        }
    }
}

impl CachedGadget {
    /// The rf-cli flavour: everything the scanner produced, nothing the
    /// classifier adds.
    #[must_use]
    pub fn from_scan_gadget(g: &rf_scan::Gadget) -> Self {
        CachedGadget {
            vaddr: format!("{:x}", g.vaddr),
            bytes: g.bytes_hex(),
            insns: Some(g.insns.clone()),
            delay_slot: g.delay_slot,
            prev: g.prev.as_ref().map(|p| encode_hex(p)),
            ..CachedGadget::default()
        }
    }

    /// Rebuild an [`rf_scan::Gadget`]. `None` for any record that does not
    /// validate — the caller treats that as a cache miss.
    ///
    /// The producing anchor table is not recorded, and `Rop` is the
    /// conservative reconstruction: `--cfg-aware` keeps ROP gadgets
    /// unconditionally, so a wrong guess can never *narrow* a cached
    /// result. (Plumbing the real table through the record is what
    /// `--cfg-aware` on cached results would need; it is not free, because
    /// it changes the stored shape for a flag that currently reads it.)
    #[must_use]
    pub fn to_scan_gadget(&self) -> Option<rf_scan::Gadget> {
        Some(rf_scan::Gadget {
            vaddr: parse_hex_u64(&self.vaddr)?,
            bytes: decode_hex(&self.bytes, MAX_GADGET_BYTES)?,
            insns: match &self.insns {
                Some(i) => i.clone(),
                // rf-mcp records carry the joined text and no list.
                None if self.text.is_empty() => return None,
                None => self.text.split(" ; ").map(str::to_string).collect(),
            },
            delay_slot: self.delay_slot,
            prev: match &self.prev {
                Some(p) => Some(decode_hex(p, MAX_PREV_BYTES)?),
                None => None,
            },
            table: rf_scan::TableKind::Rop,
        })
    }

    fn validate(&self) -> Result<(), String> {
        if parse_hex_u64(&self.vaddr).is_none() {
            return Err(format!(
                "vaddr {:?} is not a hex address",
                trunc(&self.vaddr)
            ));
        }
        if !is_hex_bytes(&self.bytes, MAX_GADGET_BYTES) {
            return Err(format!("bytes {:?} is not hex", trunc(&self.bytes)));
        }
        check_text("text", &self.text, MAX_TEXT_BYTES)?;
        if self.insns.is_none() && self.text.is_empty() {
            return Err("gadget has neither an instruction list nor text".to_string());
        }
        if let Some(insns) = &self.insns {
            if insns.len() > MAX_INSNS_PER_GADGET {
                return Err(format!("{} instructions in one gadget", insns.len()));
            }
            for i in insns {
                check_text("insn", i, MAX_TEXT_BYTES)?;
            }
        }
        if let Some(p) = &self.prev {
            if !is_hex_bytes(p, MAX_PREV_BYTES) {
                return Err(format!("prev {:?} is not hex", trunc(p)));
            }
        }
        if let Some(a) = &self.arch {
            check_text("arch", a, MAX_LABEL_BYTES)?;
        }
        if let Some(s) = &self.section {
            check_text("section", s, MAX_LABEL_BYTES)?;
        }
        if let Some(q) = self.quality {
            if !(0..=100).contains(&q) {
                return Err(format!("quality {q} outside 0..=100"));
            }
        }
        if let Some(c) = &self.class {
            if !KNOWN_CLASSES.contains(&c.as_str()) {
                return Err(format!("unknown class {:?}", trunc(c)));
            }
        }
        Ok(())
    }
}

/// One cached scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScan {
    /// [`CACHE_FORMAT_VERSION`]. Absent (0) in anything not written by this
    /// crate, which fails [`CachedScan::validate`].
    #[serde(default)]
    pub version: u32,
    pub gadgets: Vec<CachedGadget>,
    /// rf-mcp's `fallback_section_names` flag.
    #[serde(default)]
    pub fallback_names: bool,
}

impl Default for CachedScan {
    fn default() -> Self {
        CachedScan {
            version: CACHE_FORMAT_VERSION,
            gadgets: Vec::new(),
            fallback_names: false,
        }
    }
}

impl CachedScan {
    #[must_use]
    pub fn from_scan_gadgets(gadgets: &[rf_scan::Gadget]) -> Self {
        CachedScan {
            gadgets: gadgets.iter().map(CachedGadget::from_scan_gadget).collect(),
            ..CachedScan::default()
        }
    }

    /// Rebuild the scanner's gadget list. `None` if any record is
    /// unusable, so a partly-corrupt entry is a miss rather than a
    /// silently short result.
    #[must_use]
    pub fn to_scan_gadgets(&self) -> Option<Vec<rf_scan::Gadget>> {
        self.gadgets
            .iter()
            .map(CachedGadget::to_scan_gadget)
            .collect()
    }

    /// ROB-04. Called on **every** deserialize, before any field is used.
    /// Anything that fails is a clean miss plus a counter, never a panic
    /// and never a served result.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != CACHE_FORMAT_VERSION {
            return Err(format!(
                "record version {} (expected {CACHE_FORMAT_VERSION})",
                self.version
            ));
        }
        if self.gadgets.len() > MAX_GADGETS_PER_ENTRY {
            return Err(format!("{} gadgets in one entry", self.gadgets.len()));
        }
        for (n, g) in self.gadgets.iter().enumerate() {
            g.validate().map_err(|e| format!("gadget {n}: {e}"))?;
        }
        Ok(())
    }
}

/// Reject control characters (including the NUL, newline and ANSI escapes
/// that would let a poisoned entry rewrite a terminal) and cap the length.
fn check_text(what: &str, s: &str, max: usize) -> Result<(), String> {
    if s.len() > max {
        return Err(format!("{what} is {} bytes (max {max})", s.len()));
    }
    if let Some(c) = s.chars().find(|c| c.is_control()) {
        return Err(format!("{what} contains control character {:?}", c as u32));
    }
    Ok(())
}

/// Keep a diagnostic bounded: an attacker-supplied field must not be able
/// to print a megabyte to the operator's terminal.
fn trunc(s: &str) -> String {
    let mut out: String = s.chars().take(32).collect();
    if out.len() < s.len() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    // Panicking on a bad index is the *desired* behaviour in a test; the
    // crate-level deny exists to keep it out of the library.
    #![allow(clippy::indexing_slicing)]

    use super::*;

    fn ok_gadget() -> CachedGadget {
        CachedGadget {
            vaddr: "0x401000".to_string(),
            bytes: "5fc3".to_string(),
            text: "pop rdi ; ret".to_string(),
            ..CachedGadget::default()
        }
    }

    fn scan_of(g: CachedGadget) -> CachedScan {
        CachedScan {
            gadgets: vec![g],
            ..CachedScan::default()
        }
    }

    #[test]
    fn valid_record_round_trips() {
        let s = scan_of(ok_gadget());
        s.validate().unwrap();
        let g = s.to_scan_gadgets().unwrap();
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].vaddr, 0x0040_1000);
        assert_eq!(g[0].bytes, vec![0x5f, 0xc3]);
        assert_eq!(g[0].insns, vec!["pop rdi", "ret"]);
    }

    /// ROB-04, at the record level: the exact `bytes` value that panicked.
    #[test]
    fn non_ascii_bytes_field_is_a_miss() {
        let bad = CachedGadget {
            bytes: "€€".to_string(),
            ..ok_gadget()
        };
        assert!(bad.to_scan_gadget().is_none());
        assert!(scan_of(bad).validate().is_err());
    }

    #[test]
    fn malformed_matrix() {
        let cases: Vec<(&str, CachedGadget)> = vec![
            (
                "odd-length hex",
                CachedGadget {
                    bytes: "5fc".to_string(),
                    ..ok_gadget()
                },
            ),
            (
                "non-hex alphabet",
                CachedGadget {
                    bytes: "zz".to_string(),
                    ..ok_gadget()
                },
            ),
            (
                "1 MB text",
                CachedGadget {
                    text: "a".repeat(1024 * 1024),
                    ..ok_gadget()
                },
            ),
            (
                "vaddr not-hex",
                CachedGadget {
                    vaddr: "not-hex".to_string(),
                    ..ok_gadget()
                },
            ),
            (
                "quality 99999",
                CachedGadget {
                    quality: Some(99999),
                    ..ok_gadget()
                },
            ),
            (
                "class ../../etc",
                CachedGadget {
                    class: Some("../../etc".to_string()),
                    ..ok_gadget()
                },
            ),
            (
                "control characters in text",
                CachedGadget {
                    text: "pop rdi\u{1b}[2J ; ret".to_string(),
                    ..ok_gadget()
                },
            ),
            (
                "prev not hex",
                CachedGadget {
                    prev: Some("qq".to_string()),
                    ..ok_gadget()
                },
            ),
        ];
        for (what, g) in cases {
            assert!(scan_of(g).validate().is_err(), "{what} must not validate");
        }
    }

    #[test]
    fn version_must_match() {
        let mut s = scan_of(ok_gadget());
        s.version = 0;
        assert!(s.validate().is_err());
        s.version = CACHE_FORMAT_VERSION + 1;
        assert!(s.validate().is_err());
    }

    /// rf-mcp's response objects are these records. Adding rf-cli's fields
    /// to the shared struct must not add keys to the MCP wire shape.
    #[test]
    fn mcp_shape_unchanged_when_cli_fields_are_empty() {
        let g = CachedGadget {
            arch: Some("x86_64".to_string()),
            section: Some(".text".to_string()),
            quality: Some(70),
            class: Some("reg-write".to_string()),
            ..ok_gadget()
        };
        let v = serde_json::to_value(&g).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["arch", "bytes", "class", "quality", "section", "text", "vaddr"]
        );
    }

    /// An rf-cli record carries `insns` and no `text`; an rf-mcp record
    /// carries `text` and no `insns`. Both reconstruct; a record with
    /// neither is refused rather than producing a one-instruction gadget
    /// whose instruction is the empty string.
    #[test]
    fn either_insns_or_text_reconstructs_and_neither_does_not() {
        let cli = CachedGadget::from_scan_gadget(&rf_scan::Gadget {
            vaddr: 0x0040_1000,
            bytes: vec![0x5f, 0xc3],
            insns: vec!["pop rdi".to_string(), "ret".to_string()],
            delay_slot: false,
            prev: Some(vec![0xe8]),
            table: rf_scan::TableKind::Rop,
        });
        assert_eq!(cli.text, "", "text is not stored twice");
        let json = serde_json::to_string(&cli).unwrap();
        assert!(!json.contains("\"text\""), "{json}");
        let back = cli.to_scan_gadget().unwrap();
        assert_eq!(back.vaddr, 0x0040_1000);
        assert_eq!(back.insns, ["pop rdi", "ret"]);
        assert_eq!(back.prev, Some(vec![0xe8]));
        scan_of(cli).validate().unwrap();

        let mcp = ok_gadget();
        assert_eq!(mcp.to_scan_gadget().unwrap().insns, ["pop rdi", "ret"]);

        let neither = CachedGadget {
            text: String::new(),
            ..ok_gadget()
        };
        assert!(neither.to_scan_gadget().is_none());
        assert!(scan_of(neither).validate().is_err());
    }

    #[test]
    fn known_classes_match_rf_classify() {
        use rf_classify::Class;
        let live = [
            Class::RegWrite,
            Class::StackPivot,
            Class::MemRead,
            Class::MemWrite,
            Class::Arithmetic,
            Class::Syscall,
            Class::Dispatcher,
            Class::Other,
        ];
        let mut live: Vec<&str> = live.iter().map(|c| c.name()).collect();
        live.sort_unstable();
        let mut known: Vec<&str> = KNOWN_CLASSES.to_vec();
        known.sort_unstable();
        assert_eq!(live, known, "KNOWN_CLASSES has drifted from rf_classify");
    }
}
