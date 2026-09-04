//! `CHWIN-08` #3 — the PE export directory.
//!
//! PLAN.md:192 lists three ways a Windows chain can reach its API: an
//! explicit runtime address, an IAT dereference, and the target's own
//! export table. The third one was never built, and it is the only one that
//! needs neither an information leak nor three gadgets — when the target IS
//! the module that exports the API (a DLL, a driver), the address is simply
//! in the file.
//!
//! `rf-core`'s PE loader parses imports and not exports, and `rf-core` is
//! not this workstream's to change, so the directory is read here, from the
//! bytes `chain_bytes` already holds. That keeps the parser small and, more
//! usefully, keeps it *total*: every field is bounds-checked against the
//! file length and against the section table, nothing is trusted, and a
//! malformed or hostile directory yields an empty list rather than a panic
//! or a fabricated address. A chain that resolved a fabricated address
//! would be worse than no chain.

use rf_chain::PeExport;

/// Bound on how many exports are read. A hostile PE can declare
/// `NumberOfNames = 0xffffffff`; the chain builder needs one match, and a
/// directory larger than this is not a real module's.
const MAX_EXPORTS: usize = 65536;

fn u16le(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn u32le(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

/// One section's file/RVA mapping, as the section table declares it.
struct Map {
    va: u32,
    vsize: u32,
    ptr: u32,
    rawsize: u32,
}

/// File offset of `rva`, or `None` when no section covers it.
fn to_offset(maps: &[Map], rva: u32) -> Option<usize> {
    for m in maps {
        // A section's virtual extent can exceed its raw extent (.bss-like
        // tails); an RVA in that tail has no file bytes and must not be
        // read as if it did.
        let extent = m.vsize.max(m.rawsize);
        if rva >= m.va && rva < m.va.saturating_add(extent) {
            let delta = rva - m.va;
            if delta >= m.rawsize {
                return None;
            }
            return Some(m.ptr as usize + delta as usize);
        }
    }
    None
}

fn cstring(bytes: &[u8], off: usize, limit: usize) -> Option<String> {
    let end = bytes
        .get(off..)?
        .iter()
        .position(|&c| c == 0)
        .map(|n| off + n)?;
    if end - off > limit {
        return None;
    }
    let raw = bytes.get(off..end)?;
    // Export names are ASCII by specification; anything else is either a
    // corrupt directory or an attempt to smuggle bytes into a comment.
    if !raw.iter().all(|c| c.is_ascii_graphic()) {
        return None;
    }
    Some(String::from_utf8_lossy(raw).into_owned())
}

/// Read `bytes`' export directory, rebased onto `image_base`.
///
/// Returns an empty list for anything that is not a PE with a populated
/// export directory — including every executable, which is the common case.
/// Only named exports are returned: an ordinal-only export cannot be
/// matched against `--api-name`, so reporting it would only be noise.
pub fn parse_pe_exports(bytes: &[u8], image_base: u64) -> Vec<PeExport> {
    let out = Vec::new();
    if bytes.get(0..2) != Some(b"MZ") {
        return out;
    }
    let Some(pe_off) = u32le(bytes, 0x3C).map(|v| v as usize) else {
        return out;
    };
    if bytes.get(pe_off..pe_off + 4) != Some(b"PE\0\0") {
        return out;
    }
    let coff = pe_off + 4;
    let Some(nsecs) = u16le(bytes, coff + 2).map(|v| v as usize) else {
        return out;
    };
    let Some(opt_size) = u16le(bytes, coff + 16).map(|v| v as usize) else {
        return out;
    };
    let opt = coff + 20;
    let Some(magic) = u16le(bytes, opt) else {
        return out;
    };
    // The data directory sits after the optional header's fixed part, whose
    // length differs between PE32 (0x60) and PE32+ (0x70).
    let dd = match magic {
        0x10B => opt + 0x60,
        0x20B => opt + 0x70,
        _ => return out,
    };
    let Some(export_rva) = u32le(bytes, dd) else {
        return out;
    };
    let Some(export_size) = u32le(bytes, dd + 4) else {
        return out;
    };
    if export_rva == 0 || export_size == 0 {
        return out;
    }

    let sect = opt + opt_size;
    let mut maps = Vec::with_capacity(nsecs);
    for i in 0..nsecs.min(96) {
        let o = sect + i * 40;
        let (Some(vsize), Some(va), Some(rawsize), Some(ptr)) = (
            u32le(bytes, o + 8),
            u32le(bytes, o + 12),
            u32le(bytes, o + 16),
            u32le(bytes, o + 20),
        ) else {
            return out;
        };
        // A section whose raw extent runs off the end of the file is a
        // malformed header, not a section.
        if (ptr as usize).saturating_add(rawsize as usize) > bytes.len() {
            continue;
        }
        maps.push(Map {
            va,
            vsize,
            ptr,
            rawsize,
        });
    }

    let Some(dir) = to_offset(&maps, export_rva) else {
        return out;
    };
    // IMAGE_EXPORT_DIRECTORY: ..., NumberOfNames at +0x18, AddressOfFunctions
    // at +0x1c, AddressOfNames at +0x20, AddressOfNameOrdinals at +0x24.
    let (Some(n_names), Some(funcs_rva), Some(names_rva), Some(ords_rva)) = (
        u32le(bytes, dir + 0x18),
        u32le(bytes, dir + 0x1C),
        u32le(bytes, dir + 0x20),
        u32le(bytes, dir + 0x24),
    ) else {
        return out;
    };
    let (Some(funcs), Some(names), Some(ords)) = (
        to_offset(&maps, funcs_rva),
        to_offset(&maps, names_rva),
        to_offset(&maps, ords_rva),
    ) else {
        return out;
    };

    let mut exports = Vec::new();
    for i in 0..(n_names as usize).min(MAX_EXPORTS) {
        let Some(name_rva) = u32le(bytes, names + i * 4) else {
            break;
        };
        let Some(ord) = u16le(bytes, ords + i * 2) else {
            break;
        };
        let Some(func_rva) = u32le(bytes, funcs + ord as usize * 4) else {
            continue;
        };
        if func_rva == 0 {
            continue;
        }
        // A "forwarder" export's address points INSIDE the export directory
        // and names another module ("NTDLL.RtlDeleteCriticalSection")
        // instead of being code. Calling it would transfer control into an
        // ASCII string.
        if func_rva >= export_rva && func_rva < export_rva.saturating_add(export_size) {
            continue;
        }
        let Some(name_off) = to_offset(&maps, name_rva) else {
            continue;
        };
        let Some(name) = cstring(bytes, name_off, 512) else {
            continue;
        };
        exports.push(PeExport {
            name,
            vaddr: image_base.wrapping_add(func_rva as u64),
        });
    }
    exports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_pe_has_no_exports() {
        assert!(parse_pe_exports(b"", 0).is_empty());
        assert!(parse_pe_exports(b"\x7fELF............", 0).is_empty());
        assert!(parse_pe_exports(b"MZ", 0).is_empty());
    }

    /// The shipped PE fixtures are executables: they import, they do not
    /// export. The parser must say so rather than inventing entries.
    #[test]
    fn the_shipped_executables_export_nothing() {
        for name in ["pe-x64-cmd-v6.1.7601", "pe-x86-cmd-v6.1.7600"] {
            let bytes = std::fs::read(format!(
                "{}/../../tests/fixtures/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            assert!(
                parse_pe_exports(&bytes, 0x140000000).is_empty(),
                "{name} reported exports"
            );
        }
    }

    /// A truncated file must not panic and must not fabricate an address —
    /// every prefix of a real PE is a hostile input the parser may meet.
    #[test]
    fn every_truncation_of_a_pe_is_survivable() {
        let bytes = std::fs::read(format!(
            "{}/../../tests/fixtures/pe-x64-cmd-v6.1.7601",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        for n in (0..4096).step_by(7) {
            let _ = parse_pe_exports(&bytes[..n.min(bytes.len())], 0);
        }
    }
}
