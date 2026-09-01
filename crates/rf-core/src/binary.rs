//! Format detection and loader dispatch, mirroring ROPgadget's `binary.py`.
//!
//! Magic-byte dispatch (binary.py:39-47): `\x7fELF` → ELF, `MZ` → PE,
//! `cafebabe` (and `cafebabf`) → Universal, the four Mach-O magics → Mach-O.
//! Anything else is `RawUnknown` — a raw blob cannot be auto-loaded because
//! it needs an explicit arch/mode/endianness (binary.py:32-38), so
//! [`Binary::load`] rejects it; construct [`RawBinary`] directly instead.

use crate::{ElfBinary, Error, MachOBinary, PeBinary, RawBinary, UniversalBinary};

/// Detected container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Elf,
    Pe,
    MachO,
    /// Fat ("Universal") Mach-O container.
    Universal,
    /// No known magic: only loadable as a raw blob with an explicit arch.
    RawUnknown,
}

/// A loaded binary of any supported format.
#[derive(Debug)]
pub enum LoadedBinary {
    Elf(ElfBinary),
    Pe(PeBinary),
    MachO(MachOBinary),
    Universal(UniversalBinary),
    Raw(RawBinary),
}

/// Entry point mirroring ROPgadget's loader dispatch (binary.py).
pub struct Binary;

impl Binary {
    /// Parse an ELF binary, returning a structured error on malformed input.
    pub fn parse(bytes: &[u8]) -> Result<ElfBinary, Error> {
        ElfBinary::parse(bytes)
    }

    /// Detect the container format from magic bytes (binary.py:39-47).
    pub fn detect(bytes: &[u8]) -> Format {
        if bytes.len() >= 4 {
            match &bytes[..4] {
                b"\x7fELF" => return Format::Elf,
                // FAT_MAGIC / FAT_MAGIC_64 (binary.py:43; cafebabf added).
                [0xca, 0xfe, 0xba, 0xbe] | [0xca, 0xfe, 0xba, 0xbf] => {
                    return Format::Universal
                }
                // Mach-O magics, little- and big-endian, 32- and 64-bit
                // (binary.py:45-46).
                [0xce, 0xfa, 0xed, 0xfe]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xce]
                | [0xfe, 0xed, 0xfa, 0xcf] => return Format::MachO,
                _ => {}
            }
        }
        // binary.py:41 — checked after the 4-byte magics, like ROPgadget.
        if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
            return Format::Pe;
        }
        Format::RawUnknown
    }

    /// Detect the format and load the binary. `RawUnknown` input is an
    /// error here (binary.py:48-49) — raw blobs need an explicit arch, use
    /// [`RawBinary::new`] directly.
    pub fn load(bytes: &[u8]) -> Result<LoadedBinary, Error> {
        match Self::detect(bytes) {
            Format::Elf => Ok(LoadedBinary::Elf(ElfBinary::parse(bytes)?)),
            Format::Pe => Ok(LoadedBinary::Pe(PeBinary::parse(bytes)?)),
            Format::MachO => Ok(LoadedBinary::MachO(MachOBinary::parse(bytes)?)),
            Format::Universal => Ok(LoadedBinary::Universal(UniversalBinary::parse(bytes)?)),
            Format::RawUnknown => Err(Error::Unsupported(
                "binary format not recognized; use RawBinary with an explicit arch".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures")
            .join(name)
    }

    fn load_fixture(name: &str) -> Vec<u8> {
        std::fs::read(fixture_path(name)).expect("fixture should exist")
    }

    #[test]
    fn detects_magics() {
        assert_eq!(Binary::detect(b"\x7fELF\x02\x01"), Format::Elf);
        assert_eq!(Binary::detect(b"MZ\x90\x00"), Format::Pe);
        assert_eq!(Binary::detect(&[0xca, 0xfe, 0xba, 0xbe]), Format::Universal);
        assert_eq!(Binary::detect(&[0xca, 0xfe, 0xba, 0xbf]), Format::Universal);
        assert_eq!(Binary::detect(&[0xce, 0xfa, 0xed, 0xfe]), Format::MachO);
        assert_eq!(Binary::detect(&[0xcf, 0xfa, 0xed, 0xfe]), Format::MachO);
        assert_eq!(Binary::detect(&[0xfe, 0xed, 0xfa, 0xce]), Format::MachO);
        assert_eq!(Binary::detect(&[0xfe, 0xed, 0xfa, 0xcf]), Format::MachO);
        assert_eq!(Binary::detect(b""), Format::RawUnknown);
        assert_eq!(Binary::detect(b"\x90\x90\xc3"), Format::RawUnknown);
        assert_eq!(Binary::detect(b"M"), Format::RawUnknown);
        assert_eq!(Binary::detect(b"\x7f"), Format::RawUnknown);
    }

    #[test]
    fn loads_every_fixture_format() {
        let cases: &[(&str, Format)] = &[
            ("elf-x64-bash-v4.1.5.1", Format::Elf),
            ("pe-x86-cmd-v6.1.7600", Format::Pe),
            ("pe-x64-cmd-v6.1.7601", Format::Pe),
            ("pe-Windows-ARMv7-Thumb2LE-HelloWorld", Format::Pe),
            ("macho-x86-ls", Format::MachO),
            ("macho-x64-ls", Format::MachO),
            ("macho-ppc-openssl", Format::MachO),
            ("UNIVERSAL-x86-x64-libSystem.B.dylib", Format::Universal),
            ("raw-x86.raw", Format::RawUnknown),
        ];
        for (name, fmt) in cases {
            let bytes = load_fixture(name);
            assert_eq!(Binary::detect(&bytes), *fmt, "detect({name})");
            match fmt {
                Format::RawUnknown => {
                    assert!(Binary::load(&bytes).is_err(), "load({name})");
                }
                Format::Elf => assert!(
                    matches!(Binary::load(&bytes), Ok(LoadedBinary::Elf(_))),
                    "load({name})"
                ),
                Format::Pe => assert!(
                    matches!(Binary::load(&bytes), Ok(LoadedBinary::Pe(_))),
                    "load({name})"
                ),
                Format::MachO => assert!(
                    matches!(Binary::load(&bytes), Ok(LoadedBinary::MachO(_))),
                    "load({name})"
                ),
                Format::Universal => assert!(
                    matches!(Binary::load(&bytes), Ok(LoadedBinary::Universal(_))),
                    "load({name})"
                ),
            }
        }
    }

    #[test]
    fn load_never_panics_on_garbage() {
        assert!(Binary::load(b"").is_err());
        assert!(Binary::load(&[0u8; 256]).is_err());
        // Valid magics, garbage bodies.
        let magics: [&[u8]; 5] = [
            b"\x7fELF",
            b"MZ",
            &[0xca, 0xfe, 0xba, 0xbe],
            &[0xce, 0xfa, 0xed, 0xfe],
            &[0xfe, 0xed, 0xfa, 0xcf],
        ];
        for magic in magics {
            let mut g = vec![0u8; 512];
            g[..magic.len()].copy_from_slice(magic);
            let _ = Binary::load(&g); // must not panic
        }
    }
}
