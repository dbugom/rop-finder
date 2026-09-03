//! PE mitigation reader (ECO-06).
//!
//! Two sources, and the difference between them is the whole point:
//!
//! * the optional header's `DllCharacteristics` word — ASLR, DEP, high-entropy
//!   ASLR, Control Flow Guard, Force Integrity. Already parsed and stored;
//!   before this only bit `0x4000` was ever read.
//! * the **load-config directory** and the **`EX_DLLCHARACTERISTICS` debug
//!   directory entry**, which goblin does not decode into flags for us.
//!   `SEHandlerTable` lives in the first; CET shadow-stack compatibility
//!   lives in the second.
//!
//! CRIT-01 depended on this: the tool warned about "CFG" from
//! `DllCharacteristics & 0x4000` and had no way to say whether the target
//! also had hardware shadow stacks. `GUARD_CF` is Microsoft's *software*
//! forward-edge check on indirect calls; it does nothing to a `ret`. Intel
//! CET's shadow stack is what actually breaks ROP, and an image opts into it
//! with `IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT` in a debug-directory record
//! that has nothing to do with `DllCharacteristics`. The two are now separate
//! keys with separate evidence.

use crate::mitigations::{self, Enabled, Mitigation, Mitigations};

// IMAGE_DLLCHARACTERISTICS_* (winnt.h).
const HIGH_ENTROPY_VA: u16 = 0x0020;
const DYNAMIC_BASE: u16 = 0x0040;
const FORCE_INTEGRITY: u16 = 0x0080;
const NX_COMPAT: u16 = 0x0100;
const NO_SEH: u16 = 0x0400;
const GUARD_CF: u16 = 0x4000;

// IMAGE_DLLCHARACTERISTICS_EX_* (the debug-directory record, type 20).
const EX_CET_COMPAT: u32 = 0x0001;
const EX_CET_COMPAT_STRICT_MODE: u32 = 0x0002;

const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;

/// The raw fields the PE mitigation readers need, captured at parse time so
/// [`PeBinary`](crate::PeBinary) stays self-contained (no borrowed bytes).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PeFacts {
    /// Optional-header `DllCharacteristics`.
    pub(crate) dll_characteristics: u16,
    /// COFF `Machine`.
    pub(crate) machine: u16,
    /// PE32+ image?
    pub(crate) is_64: bool,
    /// A base relocation directory exists, so the loader *can* move the image.
    pub(crate) has_relocs: bool,
    /// Load-config directory found and its self-declared `Size` field.
    pub(crate) load_config_size: Option<u32>,
    /// Load-config `GuardFlags`, when the struct is long enough to hold it.
    pub(crate) guard_flags: Option<u32>,
    /// Load-config `SEHandlerTable` / `SEHandlerCount`, when present.
    pub(crate) seh_table: Option<(u64, u64)>,
    /// `IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS` payload, when the record
    /// exists at all.
    pub(crate) ex_dll_characteristics: Option<u32>,
}

/// Offset of `GuardFlags` inside `IMAGE_LOAD_CONFIG_DIRECTORY{32,64}`.
const GUARD_FLAGS_OFF32: usize = 0x58;
const GUARD_FLAGS_OFF64: usize = 0x88;
/// Offset of `SEHandlerTable` (PE32 only — PE32+ has no SafeSEH).
const SEH_TABLE_OFF32: usize = 0x40;

/// Translate an RVA to a file offset using the section table, clamped to the
/// bytes the file actually holds.
fn rva_to_offset(pe: &goblin::pe::PE<'_>, rva: u32) -> Option<usize> {
    for s in &pe.sections {
        let start = s.virtual_address;
        // `VirtualSize` of 0 means "use SizeOfRawData" (old linkers).
        let vsize = if s.virtual_size == 0 {
            s.size_of_raw_data
        } else {
            s.virtual_size
        };
        if rva >= start && (rva - start) < vsize {
            let delta = rva - start;
            if delta >= s.size_of_raw_data {
                return None; // inside the section, but not backed by the file
            }
            return (s.pointer_to_raw_data as usize).checked_add(delta as usize);
        }
    }
    None
}

fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let s = b.get(off..end)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    let end = off.checked_add(8)?;
    let s = b.get(off..end)?;
    Some(u64::from_le_bytes(s.try_into().ok()?))
}

/// Read every mitigation-relevant field out of a parsed PE plus its bytes.
pub(crate) fn facts(pe: &goblin::pe::PE<'_>, bytes: &[u8]) -> PeFacts {
    let mut f = PeFacts {
        machine: pe.header.coff_header.machine,
        is_64: pe.is_64,
        ..PeFacts::default()
    };
    let Some(opt) = pe.header.optional_header else {
        return f;
    };
    f.dll_characteristics = opt.windows_fields.dll_characteristics;
    f.has_relocs = opt
        .data_directories
        .get_base_relocation_table()
        .is_some_and(|d| d.virtual_address != 0 && d.size != 0);

    // --- load config -------------------------------------------------------
    //
    // The directory's `Size` and the struct's own `Size` field disagree in
    // real Microsoft binaries (Windows 7 `cmd.exe` declares 64 in the
    // directory and 0x48 in the struct). Windows gates field presence on the
    // struct's own `Size`, so this does too, and bounds the read by what the
    // containing section actually holds.
    if let Some(dir) = opt.data_directories.get_load_config_table() {
        if dir.virtual_address != 0 {
            if let Some(off) = rva_to_offset(pe, dir.virtual_address) {
                if let Some(size) = read_u32(bytes, off) {
                    f.load_config_size = Some(size);
                    let end = off.saturating_add(size as usize).min(bytes.len());
                    let lc = &bytes[off.min(end)..end];
                    let gf_off = if f.is_64 {
                        GUARD_FLAGS_OFF64
                    } else {
                        GUARD_FLAGS_OFF32
                    };
                    f.guard_flags = read_u32(lc, gf_off);
                    if !f.is_64 {
                        if let Some(pair) = read_u64(lc, SEH_TABLE_OFF32) {
                            let table = pair & 0xffff_ffff;
                            let count = pair >> 32;
                            f.seh_table = Some((table, count));
                        }
                    }
                }
            }
        }
    }

    // --- EX_DLLCHARACTERISTICS (debug directory type 20) -------------------
    f.ex_dll_characteristics = pe
        .debug_data
        .as_ref()
        .and_then(|d| d.ex_dll_characteristics_info.as_ref())
        .map(|e| e.characteristics_ex);
    f
}

/// Decode `GuardFlags` into the named bits, in ascending bit order.
fn guard_flag_names(flags: u32) -> Vec<&'static str> {
    const NAMES: &[(u32, &str)] = &[
        (0x0000_0100, "CF_INSTRUMENTED"),
        (0x0000_0200, "CFW_INSTRUMENTED"),
        (0x0000_0400, "CF_FUNCTION_TABLE_PRESENT"),
        (0x0000_0800, "SECURITY_COOKIE_UNUSED"),
        (0x0000_1000, "PROTECT_DELAYLOAD_IAT"),
        (0x0000_2000, "DELAYLOAD_IAT_IN_ITS_OWN_SECTION"),
        (0x0000_4000, "CF_EXPORT_SUPPRESSION_INFO_PRESENT"),
        (0x0000_8000, "CF_ENABLE_EXPORT_SUPPRESSION"),
        (0x0001_0000, "CF_LONGJUMP_TABLE_PRESENT"),
        (0x0002_0000, "RF_INSTRUMENTED"),
        (0x0004_0000, "RF_ENABLE"),
        (0x0008_0000, "RF_STRICT"),
        (0x0010_0000, "RETPOLINE_PRESENT"),
        (0x0040_0000, "EH_CONTINUATION_TABLE_PRESENT"),
        (0x0080_0000, "XFG_ENABLED"),
    ];
    NAMES
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, n)| *n)
        .collect()
}

/// Build the report.
pub(crate) fn report(f: &PeFacts) -> Mitigations {
    let dc = f.dll_characteristics;
    let bit = |b: u16| dc & b != 0;
    let mut m = Mitigations::default();

    // --- ASLR --------------------------------------------------------------
    m.push(
        mitigations::ASLR,
        if !bit(DYNAMIC_BASE) {
            Mitigation::new(
                Enabled::No,
                format!(
                    "DllCharacteristics={dc:#06x} without IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE \
                     ({DYNAMIC_BASE:#06x}): the loader maps this module at its declared ImageBase, \
                     so every address in it is fixed"
                ),
            )
        } else if !f.has_relocs {
            Mitigation::new(
                Enabled::No,
                format!(
                    "DllCharacteristics={dc:#06x} sets DYNAMIC_BASE but the image has no base \
                     relocation directory, so the loader cannot move it and maps it at its \
                     declared ImageBase anyway"
                ),
            )
        } else {
            Mitigation::new(
                Enabled::Yes,
                format!(
                    "DllCharacteristics={dc:#06x} & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE \
                     ({DYNAMIC_BASE:#06x}), and a base relocation directory is present"
                ),
            )
        },
    );

    // --- DEP ---------------------------------------------------------------
    m.push(
        mitigations::DEP,
        Mitigation::new(
            Enabled::from(bit(NX_COMPAT)),
            format!(
                "DllCharacteristics={dc:#06x} {} IMAGE_DLLCHARACTERISTICS_NX_COMPAT \
                 ({NX_COMPAT:#06x})",
                if bit(NX_COMPAT) { "&" } else { "without" }
            ),
        ),
    );

    // --- high-entropy ASLR --------------------------------------------------
    m.push(
        mitigations::HIGH_ENTROPY_VA,
        if !f.is_64 {
            Mitigation::new(
                Enabled::No,
                format!(
                    "PE32 image: IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA ({HIGH_ENTROPY_VA:#06x}) \
                     is only honoured for PE32+ images, so a 32-bit module gets at most the \
                     low-entropy 8-bit randomisation"
                ),
            )
        } else {
            Mitigation::new(
                Enabled::from(bit(HIGH_ENTROPY_VA)),
                format!(
                    "DllCharacteristics={dc:#06x} {} IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA \
                     ({HIGH_ENTROPY_VA:#06x}) on a PE32+ image",
                    if bit(HIGH_ENTROPY_VA) { "&" } else { "without" }
                ),
            )
        },
    );

    // --- Control Flow Guard -------------------------------------------------
    let guard_note = match (f.guard_flags, f.load_config_size) {
        (Some(g), _) => format!("load-config GuardFlags={g:#010x}"),
        (None, Some(sz)) => format!(
            "the load-config directory is only {sz:#x} bytes, which stops short of GuardFlags at \
             offset {:#x}",
            if f.is_64 {
                GUARD_FLAGS_OFF64
            } else {
                GUARD_FLAGS_OFF32
            }
        ),
        (None, None) => "the image has no load-config directory".to_string(),
    };
    m.push(
        mitigations::GUARD_CF,
        if bit(GUARD_CF) {
            let mut mit = Mitigation::new(
                Enabled::Yes,
                format!(
                    "DllCharacteristics={dc:#06x} & IMAGE_DLLCHARACTERISTICS_GUARD_CF \
                     ({GUARD_CF:#06x}); {guard_note}. CFG checks INDIRECT CALL targets only — it \
                     does not validate a `ret`, so it does not stop a classic ROP chain."
                ),
            );
            if let Some(g) = f.guard_flags {
                mit = mit.with_detail(format!("{:#010x} {}", g, guard_flag_names(g).join("|")));
            }
            mit
        } else {
            Mitigation::new(
                Enabled::No,
                format!(
                    "DllCharacteristics={dc:#06x} without IMAGE_DLLCHARACTERISTICS_GUARD_CF \
                     ({GUARD_CF:#06x}); {guard_note}"
                ),
            )
        },
    );

    // --- CET ----------------------------------------------------------------
    m.push(
        mitigations::CET_COMPAT,
        match f.ex_dll_characteristics {
            Some(ex) => {
                let on = ex & EX_CET_COMPAT != 0;
                let mut mit = Mitigation::new(
                    Enabled::from(on),
                    format!(
                        "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS record present with \
                         CharacteristicsEx={ex:#010x}, {} \
                         IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT ({EX_CET_COMPAT:#x})",
                        if on {
                            "which sets"
                        } else {
                            "which does not set"
                        }
                    ),
                );
                if on && ex & EX_CET_COMPAT_STRICT_MODE != 0 {
                    mit = mit.with_detail("strict-mode");
                }
                mit
            }
            None => Mitigation::new(
                Enabled::No,
                "no IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS (type 20) debug-directory record: the \
                 image carries no CET marking at all, so Windows will not enable a hardware \
                 shadow stack for it and return addresses on the stack are not protected. This \
                 is the field that distinguishes real backward-edge protection from GUARD_CF, \
                 which is forward-edge only.",
            ),
        },
    );

    // --- SafeSEH -------------------------------------------------------------
    m.push(mitigations::SAFE_SEH, safe_seh(f, bit(NO_SEH)));

    // --- Force Integrity ------------------------------------------------------
    m.push(
        mitigations::FORCE_INTEGRITY,
        Mitigation::new(
            Enabled::from(bit(FORCE_INTEGRITY)),
            format!(
                "DllCharacteristics={dc:#06x} {} IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY \
                 ({FORCE_INTEGRITY:#06x})",
                if bit(FORCE_INTEGRITY) { "&" } else { "without" }
            ),
        ),
    );
    m
}

fn safe_seh(f: &PeFacts, no_seh: bool) -> Mitigation {
    if f.machine != IMAGE_FILE_MACHINE_I386 {
        return Mitigation::new(
            Enabled::Yes,
            format!(
                "COFF Machine={:#06x} is not IMAGE_FILE_MACHINE_I386: on this architecture \
                 exception handling is table-driven (the unwind data lives in a read-only \
                 directory), so there is no SEH chain on the stack to overwrite and SafeSEH does \
                 not apply",
                f.machine
            ),
        )
        .with_detail("not-applicable");
    }
    if no_seh {
        return Mitigation::new(
            Enabled::Yes,
            format!(
                "DllCharacteristics={:#06x} & IMAGE_DLLCHARACTERISTICS_NO_SEH ({NO_SEH:#06x}): \
                 the image declares that it uses no structured exception handlers",
                f.dll_characteristics
            ),
        )
        .with_detail("no-seh");
    }
    match f.seh_table {
        Some((table, count)) if table != 0 && count != 0 => Mitigation::new(
            Enabled::Yes,
            format!(
                "load-config SEHandlerTable={table:#x} with SEHandlerCount={count}: the image \
                 ships a table of permitted exception handlers, so an overwritten SEH record \
                 cannot point at arbitrary code"
            ),
        ),
        Some(_) => Mitigation::new(
            Enabled::No,
            "the load-config directory is present but SEHandlerTable is empty: any address may \
             be used as an exception handler",
        ),
        None => match f.load_config_size {
            Some(sz) => Mitigation::new(
                Enabled::No,
                format!(
                    "the load-config directory is only {sz:#x} bytes, which stops short of \
                     SEHandlerTable at offset {SEH_TABLE_OFF32:#x}: the image ships no \
                     safe-handler table"
                ),
            ),
            None => Mitigation::new(
                Enabled::No,
                "the image has no load-config directory, so it ships no safe-handler table",
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts_with(dc: u16) -> PeFacts {
        PeFacts {
            dll_characteristics: dc,
            machine: IMAGE_FILE_MACHINE_I386,
            is_64: false,
            has_relocs: true,
            ..PeFacts::default()
        }
    }

    #[test]
    fn dynamic_base_without_relocations_is_not_aslr() {
        let mut f = facts_with(DYNAMIC_BASE);
        assert_eq!(report(&f).enabled(mitigations::ASLR), Enabled::Yes);
        f.has_relocs = false;
        let r = report(&f);
        assert_eq!(r.enabled(mitigations::ASLR), Enabled::No);
        assert!(r
            .get(mitigations::ASLR)
            .unwrap()
            .evidence
            .contains("no base relocation directory"));
    }

    #[test]
    fn guard_cf_and_cet_are_separate_answers() {
        // CRIT-01: an image may advertise CFG and have no CET marking at all.
        let mut f = facts_with(GUARD_CF);
        f.guard_flags = Some(0x0001_0500);
        let r = report(&f);
        assert_eq!(r.enabled(mitigations::GUARD_CF), Enabled::Yes);
        assert_eq!(r.enabled(mitigations::CET_COMPAT), Enabled::No);
        assert_eq!(
            r.get(mitigations::GUARD_CF).unwrap().detail.as_deref(),
            Some("0x00010500 CF_INSTRUMENTED|CF_FUNCTION_TABLE_PRESENT|CF_LONGJUMP_TABLE_PRESENT")
        );
        f.ex_dll_characteristics = Some(EX_CET_COMPAT | EX_CET_COMPAT_STRICT_MODE);
        let r = report(&f);
        assert_eq!(r.enabled(mitigations::CET_COMPAT), Enabled::Yes);
        assert_eq!(
            r.get(mitigations::CET_COMPAT).unwrap().detail.as_deref(),
            Some("strict-mode")
        );
    }

    #[test]
    fn high_entropy_va_is_false_for_pe32_and_says_why() {
        let f = facts_with(HIGH_ENTROPY_VA);
        let r = report(&f);
        assert_eq!(r.enabled(mitigations::HIGH_ENTROPY_VA), Enabled::No);
        assert!(r
            .get(mitigations::HIGH_ENTROPY_VA)
            .unwrap()
            .evidence
            .contains("only honoured for PE32+"));
    }

    #[test]
    fn safe_seh_reads_the_load_config_table() {
        let mut f = facts_with(0);
        assert_eq!(report(&f).enabled(mitigations::SAFE_SEH), Enabled::No);
        f.load_config_size = Some(0x48);
        f.seh_table = Some((0x4ad1_bbd8, 1));
        let r = report(&f);
        assert_eq!(r.enabled(mitigations::SAFE_SEH), Enabled::Yes);
        assert!(r
            .get(mitigations::SAFE_SEH)
            .unwrap()
            .evidence
            .contains("SEHandlerCount=1"));
        // Non-i386: not applicable, and it says so rather than claiming a win.
        f.machine = 0x8664;
        let r = report(&f);
        assert_eq!(
            r.get(mitigations::SAFE_SEH).unwrap().detail.as_deref(),
            Some("not-applicable")
        );
    }

    #[test]
    fn guard_flag_names_decode_in_bit_order() {
        assert_eq!(guard_flag_names(0), Vec::<&str>::new());
        assert_eq!(
            guard_flag_names(0x0000_0100 | 0x0080_0000),
            vec!["CF_INSTRUMENTED", "XFG_ENABLED"]
        );
    }
}
