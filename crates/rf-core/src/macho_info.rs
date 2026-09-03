//! Mach-O mitigation reader (ECO-06).
//!
//! Three answers matter for deciding whether ROP is the right technique:
//! `MH_PIE`, whether the image is signed at all, and whether that signature
//! opted into the hardened runtime. The first two are header reads. The
//! third is not: `CS_RUNTIME` lives in the CodeDirectory blob *inside* the
//! `LC_CODE_SIGNATURE` payload, which goblin hands over as raw bytes, so
//! this module walks the `CSMAGIC_EMBEDDED_SIGNATURE` SuperBlob itself. All
//! code-signing structures are big-endian regardless of the slice's byte
//! order.
//!
//! An unsigned image gets `hardened_runtime = unknown`, never `false`:
//! hardened runtime is a property of a signature, so with no signature there
//! is nothing to read, and saying "false" would imply the file was checked
//! and found lacking.

use goblin::mach::load_command::CommandVariant;

use crate::mitigations::{self, Enabled, Mitigation, Mitigations};

// Mach-O header flags (`loader.h`).
const MH_ALLOW_STACK_EXECUTION: u32 = 0x0000_0800;
const MH_PIE: u32 = 0x0020_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;

// Mach-O filetypes.
const MH_EXECUTE: u32 = 2;
const MH_DYLIB: u32 = 6;
const MH_DYLINKER: u32 = 7;
const MH_BUNDLE: u32 = 8;

// Code-signing magics and flags (`cs_blobs.h`).
const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CS_ADHOC: u32 = 0x0000_0002;
const CS_RUNTIME: u32 = 0x0001_0000;
const CS_LINKER_SIGNED: u32 = 0x0002_0000;

/// Mitigation-relevant Mach-O facts, captured at parse time.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MachOFacts {
    pub(crate) flags: u32,
    pub(crate) filetype: u32,
    pub(crate) is_64: bool,
    /// An `LC_CODE_SIGNATURE` load command exists.
    pub(crate) code_signature: bool,
    /// CodeDirectory `flags`, when the SuperBlob could be walked.
    pub(crate) cd_flags: Option<u32>,
}

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = b.get(off..end)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Walk the embedded-signature SuperBlob and return the CodeDirectory flags.
///
/// Returns `None` for a signature this cannot decode (a detached or
/// unexpected magic, a truncated blob) rather than guessing zero — zero is
/// the encoding of "signed, no special flags", which is a different answer
/// from "could not tell".
fn code_directory_flags(sig: &[u8]) -> Option<u32> {
    if be_u32(sig, 0)? != CSMAGIC_EMBEDDED_SIGNATURE {
        return None;
    }
    let count = be_u32(sig, 8)? as usize;
    // A SuperBlob index is 8 bytes per entry after the 12-byte header.
    for i in 0..count.min(64) {
        let entry = 12 + i * 8;
        let blob_off = be_u32(sig, entry + 4)? as usize;
        if be_u32(sig, blob_off)? == CSMAGIC_CODEDIRECTORY {
            // CodeDirectory: magic(0) length(4) version(8) flags(12).
            return be_u32(sig, blob_off + 12);
        }
    }
    None
}

/// Read the facts out of a parsed Mach-O plus its slice-local bytes
/// (`bytes[0]` is the Mach-O header, which is what code-signature offsets
/// are relative to).
pub(crate) fn facts(macho: &goblin::mach::MachO<'_>, bytes: &[u8]) -> MachOFacts {
    let mut f = MachOFacts {
        flags: macho.header.flags,
        filetype: macho.header.filetype,
        is_64: macho.is_64,
        ..MachOFacts::default()
    };
    for lc in &macho.load_commands {
        if let CommandVariant::CodeSignature(c) = lc.command {
            f.code_signature = true;
            let start = c.dataoff as usize;
            let end = start.saturating_add(c.datasize as usize).min(bytes.len());
            if start < end {
                f.cd_flags = code_directory_flags(&bytes[start..end]);
            }
        }
    }
    f
}

fn filetype_name(ft: u32) -> &'static str {
    match ft {
        1 => "MH_OBJECT",
        MH_EXECUTE => "MH_EXECUTE",
        MH_DYLIB => "MH_DYLIB",
        MH_DYLINKER => "MH_DYLINKER",
        MH_BUNDLE => "MH_BUNDLE",
        _ => "other",
    }
}

pub(crate) fn report(f: &MachOFacts) -> Mitigations {
    let mut m = Mitigations::default();
    let flags = f.flags;

    // --- PIE ----------------------------------------------------------------
    let shared = matches!(f.filetype, MH_DYLIB | MH_BUNDLE | MH_DYLINKER);
    m.push(
        mitigations::PIE,
        if flags & MH_PIE != 0 {
            Mitigation::new(
                Enabled::Yes,
                format!(
                    "Mach-O header flags={flags:#x} & MH_PIE ({MH_PIE:#x}): dyld slides this \
                     image, so its addresses are offsets from a leaked base"
                ),
            )
            .with_detail("pie-executable")
        } else if shared {
            Mitigation::new(
                Enabled::Yes,
                format!(
                    "Mach-O filetype {} with flags={flags:#x}: MH_PIE ({MH_PIE:#x}) is only \
                     meaningful for MH_EXECUTE, and a dylib/bundle is always loaded at a \
                     dyld-chosen base, so its addresses are offsets regardless",
                    filetype_name(f.filetype)
                ),
            )
            .with_detail("shared-object")
        } else {
            Mitigation::new(
                Enabled::No,
                format!(
                    "Mach-O filetype {} with flags={flags:#x} and no MH_PIE ({MH_PIE:#x}): the \
                     image is mapped at its declared __TEXT vmaddr",
                    filetype_name(f.filetype)
                ),
            )
            .with_detail("fixed-address-executable")
        },
    );

    // --- stack ---------------------------------------------------------------
    let allow_stack_exec = flags & MH_ALLOW_STACK_EXECUTION != 0;
    m.push(
        mitigations::NX_STACK,
        Mitigation::new(
            Enabled::from(!allow_stack_exec),
            format!(
                "Mach-O header flags={flags:#x} {} MH_ALLOW_STACK_EXECUTION \
                 ({MH_ALLOW_STACK_EXECUTION:#x})",
                if allow_stack_exec { "&" } else { "without" }
            ),
        ),
    );

    // --- heap ----------------------------------------------------------------
    m.push(
        mitigations::NX_HEAP,
        if f.is_64 {
            Mitigation::new(
                Enabled::Yes,
                format!(
                    "64-bit Mach-O: data pages are non-executable by default on x86-64 and \
                     arm64, and MH_NO_HEAP_EXECUTION ({MH_NO_HEAP_EXECUTION:#x}) is a 32-bit-only \
                     opt-in, so it carries no information here"
                ),
            )
        } else {
            let on = flags & MH_NO_HEAP_EXECUTION != 0;
            Mitigation::new(
                Enabled::from(on),
                format!(
                    "32-bit Mach-O with flags={flags:#x} {} MH_NO_HEAP_EXECUTION \
                     ({MH_NO_HEAP_EXECUTION:#x})",
                    if on { "&" } else { "without" }
                ),
            )
        },
    );

    // --- code signature -------------------------------------------------------
    m.push(
        mitigations::CODE_SIGNATURE,
        if f.code_signature {
            let mut mit = Mitigation::new(
                Enabled::Yes,
                match f.cd_flags {
                    Some(cd) => format!(
                        "an LC_CODE_SIGNATURE load command is present and its CodeDirectory \
                         flags are {cd:#x}"
                    ),
                    None => "an LC_CODE_SIGNATURE load command is present, but its payload is \
                             not a CSMAGIC_EMBEDDED_SIGNATURE SuperBlob this reader can walk"
                        .to_string(),
                },
            );
            if let Some(cd) = f.cd_flags {
                let mut tags = Vec::new();
                if cd & CS_ADHOC != 0 {
                    tags.push("adhoc");
                }
                if cd & CS_LINKER_SIGNED != 0 {
                    tags.push("linker-signed");
                }
                if !tags.is_empty() {
                    mit = mit.with_detail(tags.join(","));
                }
            }
            mit
        } else {
            Mitigation::new(
                Enabled::No,
                "no LC_CODE_SIGNATURE load command: the image is unsigned",
            )
        },
    );

    // --- hardened runtime ------------------------------------------------------
    m.push(
        mitigations::HARDENED_RUNTIME,
        match (f.code_signature, f.cd_flags) {
            (_, Some(cd)) => Mitigation::new(
                Enabled::from(cd & CS_RUNTIME != 0),
                format!(
                    "CodeDirectory flags={cd:#x} {} CS_RUNTIME ({CS_RUNTIME:#x})",
                    if cd & CS_RUNTIME != 0 { "&" } else { "without" }
                ),
            ),
            (true, None) => Mitigation::new(
                Enabled::Unknown,
                "the image has an LC_CODE_SIGNATURE, but its CodeDirectory could not be located \
                 inside the signature payload, and CS_RUNTIME lives only there",
            ),
            (false, None) => Mitigation::new(
                Enabled::Unknown,
                "the image is unsigned (no LC_CODE_SIGNATURE): hardened runtime is a code-signing \
                 flag (CS_RUNTIME in the CodeDirectory), so there is nothing to read. This is not \
                 the same as it being off in a signed binary.",
            ),
        },
    );
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dylib_without_mh_pie_is_still_position_independent() {
        let f = MachOFacts {
            flags: 0x85,
            filetype: MH_DYLIB,
            is_64: true,
            ..MachOFacts::default()
        };
        let r = report(&f);
        assert_eq!(r.enabled(mitigations::PIE), Enabled::Yes);
        assert_eq!(
            r.get(mitigations::PIE).unwrap().detail.as_deref(),
            Some("shared-object")
        );
        // An MH_EXECUTE with the same flags is genuinely not PIE.
        let f = MachOFacts {
            filetype: MH_EXECUTE,
            ..f
        };
        let r = report(&f);
        assert_eq!(r.enabled(mitigations::PIE), Enabled::No);
        assert_eq!(
            r.get(mitigations::PIE).unwrap().detail.as_deref(),
            Some("fixed-address-executable")
        );
    }

    #[test]
    fn unsigned_image_reports_hardened_runtime_unknown_not_false() {
        let f = MachOFacts {
            flags: 0x85,
            filetype: MH_EXECUTE,
            is_64: false,
            code_signature: false,
            cd_flags: None,
        };
        let r = report(&f);
        assert_eq!(r.enabled(mitigations::CODE_SIGNATURE), Enabled::No);
        assert_eq!(r.enabled(mitigations::HARDENED_RUNTIME), Enabled::Unknown);
        assert!(r
            .get(mitigations::HARDENED_RUNTIME)
            .unwrap()
            .evidence
            .contains("unsigned"));
    }

    #[test]
    fn cs_runtime_decides_hardened_runtime_when_a_signature_is_readable() {
        let base = MachOFacts {
            flags: 0x200085,
            filetype: MH_EXECUTE,
            is_64: true,
            code_signature: true,
            cd_flags: Some(0),
        };
        assert_eq!(
            report(&base).enabled(mitigations::HARDENED_RUNTIME),
            Enabled::No
        );
        let f = MachOFacts {
            cd_flags: Some(CS_RUNTIME | CS_ADHOC),
            ..base
        };
        let r = report(&f);
        assert_eq!(r.enabled(mitigations::HARDENED_RUNTIME), Enabled::Yes);
        assert_eq!(
            r.get(mitigations::CODE_SIGNATURE)
                .unwrap()
                .detail
                .as_deref(),
            Some("adhoc")
        );
    }

    #[test]
    fn nx_heap_is_only_a_flag_question_on_32_bit() {
        let f32 = MachOFacts {
            flags: MH_NO_HEAP_EXECUTION,
            filetype: MH_EXECUTE,
            is_64: false,
            ..MachOFacts::default()
        };
        assert_eq!(report(&f32).enabled(mitigations::NX_HEAP), Enabled::Yes);
        let f32b = MachOFacts { flags: 0, ..f32 };
        assert_eq!(report(&f32b).enabled(mitigations::NX_HEAP), Enabled::No);
        let f64 = MachOFacts {
            is_64: true,
            ..f32b
        };
        let r = report(&f64);
        assert_eq!(r.enabled(mitigations::NX_HEAP), Enabled::Yes);
        assert!(r
            .get(mitigations::NX_HEAP)
            .unwrap()
            .evidence
            .contains("32-bit-only opt-in"));
    }

    #[test]
    fn superblob_walker_refuses_what_it_cannot_decode() {
        assert_eq!(code_directory_flags(&[]), None);
        assert_eq!(code_directory_flags(&[0, 0, 0, 0, 0, 0, 0, 0]), None);
        // A well-formed SuperBlob with one CodeDirectory carrying CS_RUNTIME.
        let mut sig = Vec::new();
        sig.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        sig.extend_from_slice(&0u32.to_be_bytes()); // length
        sig.extend_from_slice(&1u32.to_be_bytes()); // count
        sig.extend_from_slice(&0u32.to_be_bytes()); // blob type
        sig.extend_from_slice(&20u32.to_be_bytes()); // blob offset
        sig.extend_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        sig.extend_from_slice(&0u32.to_be_bytes()); // length
        sig.extend_from_slice(&0x0002_0400u32.to_be_bytes()); // version
        sig.extend_from_slice(&CS_RUNTIME.to_be_bytes()); // flags
        assert_eq!(code_directory_flags(&sig), Some(CS_RUNTIME));
        // Truncated: no flags to read.
        assert_eq!(code_directory_flags(&sig[..30]), None);
    }
}
