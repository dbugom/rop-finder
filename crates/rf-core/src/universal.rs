//! Universal (fat Mach-O) loading via goblin, plus 64-bit fat support.
//!
//! Mirrors ROPgadget's `loaders/universal.py`: each fat-arch entry is carved
//! out and parsed as its own Mach-O (universal.py:66-75), and scanning
//! happens per-slice (universal.py:77-81 — `getExecSections` concatenates
//! every slice's exec sections). rop-finder keeps the slices separate so the
//! scanner can pick one architecture explicitly.
//!
//! Conscious deviations:
//! - ROPgadget only accepts little-endian slice magics (universal.py:71);
//!   goblin parses big-endian slices too, and we accept them.
//! - Unusable entries (non-Mach-O archives, corrupt slices) are skipped and
//!   counted, mirroring universal.py:74 which prints an error and continues;
//!   a fat binary with zero usable slices is an error.
//! - ROPgadget concatenates every slice and disassembles the lot with the
//!   first slice's architecture. On a modern x86_64+arm64 binary that makes
//!   roughly 70% of the printed gadgets fabricated, so rop-finder exposes
//!   [`UniversalBinary::select`] instead and the CLI refuses a multi-slice
//!   file that arrives without an explicit `--arch` (CORE-03).
//!   [`UniversalBinary::all_exec_scan_regions`] keeps the old behaviour for
//!   parity debugging.

use crate::macho::MachOBinary;
use crate::{Arch, Endianness, Error};

/// `FAT_MAGIC` — 32-bit fat header, big-endian on disk.
const FAT_MAGIC: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe];
/// `FAT_MAGIC_64` — 64-bit fat header (`cafebabf`), big-endian on disk.
const FAT_MAGIC_64: [u8; 4] = [0xca, 0xfe, 0xba, 0xbf];
/// `struct fat_arch_64`: cputype, cpusubtype, offset, size, align, reserved.
const FAT_ARCH_64_SIZE: usize = 4 + 4 + 8 + 8 + 4 + 4;
/// A fat header cannot plausibly declare more entries than this; the field
/// is a u32, so without a bound a corrupt header asks for a 4-billion-entry
/// allocation.
const MAX_FAT_ARCHES: u32 = 4096;

/// What a fat container holds, per usable slice. This is the metadata the
/// CLI needs to implement `--arch` (list the choices, name the one it
/// picked, and say what it refused to guess between).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SliceInfo {
    /// Architecture of the slice.
    pub arch: Arch,
    /// Byte order of the slice.
    pub endianness: Endianness,
    /// 64-bit Mach-O?
    pub is_64: bool,
    /// Mach-O `cputype` of the slice.
    pub cpu_type: u32,
    /// Offset of the slice inside the fat container.
    pub offset: u64,
    /// Declared length of the slice inside the fat container.
    pub size: u64,
}

impl SliceInfo {
    /// The name `--arch` accepts for this slice (`x86_64`, `arm64`, ...).
    pub fn name(&self) -> &'static str {
        self.arch.slice_name()
    }
}

/// A fat Mach-O ("Universal") container: one [`MachOBinary`] per
/// architecture slice.
#[derive(Debug)]
pub struct UniversalBinary {
    slices: Vec<MachOBinary>,
    infos: Vec<SliceInfo>,
    /// Fat-arch entries that were skipped (archive or unparseable).
    skipped: usize,
    /// 64-bit fat container (`cafebabf`) rather than `cafebabe`.
    fat64: bool,
}

impl UniversalBinary {
    /// Parse a fat Mach-O container, returning a structured error on
    /// malformed input.
    ///
    /// Dispatch is on the magic, not on goblin's guess: `cafebabe` goes to
    /// `goblin::mach::MultiArch`, `cafebabf` to the 64-bit reader below
    /// (CORE-05). That split matters twice — goblin 0.10 has no `fat_arch_64`
    /// support at all, and it does not *reject* `cafebabf` either: it read a
    /// 32-bit arch table as a 64-bit one, which turned a fat32 file with a
    /// single corrupted magic byte into 69 confidently-printed gadgets where
    /// the oracle printed "[Error] Binary format not supported".
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let magic = bytes.get(..4).ok_or_else(|| {
            Error::Malformed("universal binary is shorter than its 4-byte magic".to_string())
        })?;
        match magic {
            m if m == FAT_MAGIC => Self::parse_fat32(bytes),
            m if m == FAT_MAGIC_64 => Self::parse_fat64(bytes),
            other => Err(Error::Malformed(format!(
                "not a fat Mach-O container: magic {other:02x?}"
            ))),
        }
    }

    fn parse_fat32(bytes: &[u8]) -> Result<Self, Error> {
        let multi = goblin::mach::MultiArch::new(bytes)?;
        let arches = multi.arches()?;
        let entries: Vec<(u64, u64)> = arches
            .iter()
            .map(|a| (u64::from(a.offset), u64::from(a.size)))
            .collect();
        let slices: Vec<&[u8]> = arches.iter().map(|a| a.slice(bytes)).collect();
        Self::from_slices(&slices, &entries, arches.len(), false)
    }

    /// `struct fat_header` + `struct fat_arch_64[]`, both big-endian
    /// (`mach-o/fat.h`). goblin 0.10 cannot read this layout.
    fn parse_fat64(bytes: &[u8]) -> Result<Self, Error> {
        let nfat = bytes
            .get(4..8)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| Error::Malformed("fat64 header is truncated".to_string()))?;
        if nfat == 0 {
            return Err(Error::Malformed(
                "fat64 binary declares zero architecture slices".to_string(),
            ));
        }
        if nfat > MAX_FAT_ARCHES {
            return Err(Error::Malformed(format!(
                "fat64 binary declares {nfat} architecture slices (limit {MAX_FAT_ARCHES})"
            )));
        }
        let table_end = 8usize.saturating_add(FAT_ARCH_64_SIZE.saturating_mul(nfat as usize));
        if table_end > bytes.len() {
            return Err(Error::Malformed(format!(
                "fat64 arch table needs {table_end} bytes in a {}-byte file",
                bytes.len()
            )));
        }

        let mut entries = Vec::with_capacity(nfat as usize);
        let mut slices = Vec::with_capacity(nfat as usize);
        for i in 0..nfat as usize {
            let base = 8 + i * FAT_ARCH_64_SIZE;
            let e = &bytes[base..base + FAT_ARCH_64_SIZE];
            let offset = u64::from_be_bytes(e[8..16].try_into().unwrap_or([0; 8]));
            let size = u64::from_be_bytes(e[16..24].try_into().unwrap_or([0; 8]));
            entries.push((offset, size));
            // Bounds-checked like goblin's `FatArch::slice`: an out-of-range
            // entry yields an empty slice, which then fails to parse and is
            // counted as skipped rather than aborting the whole file.
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            let len = usize::try_from(size).unwrap_or(usize::MAX);
            let slice = match start.checked_add(len) {
                Some(end) if start <= bytes.len() && end <= bytes.len() => &bytes[start..end],
                _ => &[][..],
            };
            slices.push(slice);
        }
        Self::from_slices(&slices, &entries, nfat as usize, true)
    }

    fn from_slices(
        raw: &[&[u8]],
        entries: &[(u64, u64)],
        declared: usize,
        fat64: bool,
    ) -> Result<Self, Error> {
        let mut slices = Vec::with_capacity(raw.len());
        let mut infos = Vec::with_capacity(raw.len());
        let mut skipped = 0usize;
        for (slice, (offset, size)) in raw.iter().zip(entries.iter()) {
            match goblin::mach::MachO::parse(slice, 0) {
                Ok(macho) => match MachOBinary::from_goblin(&macho, slice) {
                    Ok(bin) => {
                        infos.push(SliceInfo {
                            arch: bin.arch(),
                            endianness: bin.endianness(),
                            is_64: bin.is_64(),
                            cpu_type: bin.cpu_type(),
                            offset: *offset,
                            size: *size,
                        });
                        slices.push(bin);
                    }
                    // e.g. a slice with an unsupported cputype.
                    Err(_) => skipped += 1,
                },
                Err(_) => skipped += 1,
            }
        }

        if slices.is_empty() {
            return Err(Error::Malformed(format!(
                "universal binary has {declared} entries but no usable Mach-O slice"
            )));
        }

        Ok(UniversalBinary {
            slices,
            infos,
            skipped,
            fat64,
        })
    }

    /// All usable slices, in fat-arch order.
    pub fn slices(&self) -> &[MachOBinary] {
        &self.slices
    }

    /// Per-slice metadata in fat-arch order — architecture, byte order,
    /// container offset and length. This is what a `--arch` implementation
    /// needs to list the available choices (CORE-03).
    pub fn slice_infos(&self) -> &[SliceInfo] {
        &self.infos
    }

    /// Number of fat-arch entries skipped because they were not parseable
    /// Mach-O slices (universal.py:74).
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// True for a 64-bit fat container (`FAT_MAGIC_64` / `cafebabf`).
    pub fn is_fat64(&self) -> bool {
        self.fat64
    }

    /// Architectures of all usable slices, in fat-arch order.
    pub fn arches(&self) -> Vec<Arch> {
        self.slices.iter().map(|s| s.arch()).collect()
    }

    /// Get the slice for `arch`, if present.
    pub fn get(&self, arch: Arch) -> Option<&MachOBinary> {
        self.slices.iter().find(|s| s.arch() == arch)
    }

    /// CORE-03 — does this container need an explicit architecture choice?
    ///
    /// True whenever more than one usable slice is present. The CLI is
    /// expected to REFUSE such a file when no `--arch` was given rather than
    /// scanning the concatenation: the slices' virtual address ranges
    /// overlap, so real and fabricated gadgets come out interleaved at
    /// indistinguishable addresses and the user cannot tell them apart.
    /// A single-slice container needs no choice and can be scanned directly.
    pub fn needs_arch_selection(&self) -> bool {
        self.slices.len() > 1
    }

    /// Select one architecture slice, or explain what is on offer.
    ///
    /// This is the API `--arch` drives. Unlike [`get`](Self::get) it returns
    /// a structured error naming every available slice, so the CLI can print
    /// a usable message instead of a bare `None`.
    pub fn select(&self, arch: Arch) -> Result<&MachOBinary, Error> {
        match self.slices.iter().position(|s| s.arch() == arch) {
            Some(i) => Ok(&self.slices[i]),
            None => Err(Error::Unsupported(self.no_such_slice(arch))),
        }
    }

    /// [`select`](Self::select) for callers that need to
    /// [`rebase`](crate::Image::rebase) the chosen slice.
    pub fn select_mut(&mut self, arch: Arch) -> Result<&mut MachOBinary, Error> {
        match self.slices.iter().position(|s| s.arch() == arch) {
            Some(i) => Ok(&mut self.slices[i]),
            None => Err(Error::Unsupported(self.no_such_slice(arch))),
        }
    }

    /// Take ownership of one architecture slice, dropping the others.
    pub fn into_slice(mut self, arch: Arch) -> Result<MachOBinary, Error> {
        match self.slices.iter().position(|s| s.arch() == arch) {
            Some(i) => Ok(self.slices.swap_remove(i)),
            None => Err(Error::Unsupported(self.no_such_slice(arch))),
        }
    }

    fn no_such_slice(&self, arch: Arch) -> String {
        let available = self
            .slices
            .iter()
            .map(|s| s.arch().slice_name())
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "universal binary has no {} slice; available: {available}",
            arch.slice_name()
        )
    }

    /// ROPgadget parity: concatenated executable scan regions of every
    /// slice (universal.py:77-81). The scanner should pick one slice via
    /// [`select`](Self::select); this exists for parity debugging.
    pub fn all_exec_scan_regions(&self) -> Vec<&crate::Section> {
        self.slices
            .iter()
            .flat_map(|s| s.exec_scan_regions().iter())
            .collect()
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

    /// Rebuild a `cafebabe` fat file as a `cafebabf` one: same slices, a
    /// 64-bit arch table. This is what `lipo -fat64` produces and what
    /// goblin 0.10 cannot read.
    fn to_fat64(bytes: &[u8]) -> Vec<u8> {
        let nfat = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        let mut entries = Vec::new();
        for i in 0..nfat {
            let e = &bytes[8 + i * 20..8 + (i + 1) * 20];
            entries.push((
                i32::from_be_bytes(e[0..4].try_into().unwrap()),
                i32::from_be_bytes(e[4..8].try_into().unwrap()),
                u32::from_be_bytes(e[8..12].try_into().unwrap()) as u64,
                u32::from_be_bytes(e[12..16].try_into().unwrap()) as u64,
                u32::from_be_bytes(e[16..20].try_into().unwrap()),
            ));
        }
        // New table is wider, so the slices move; keep them page-aligned.
        let table_end = 8 + nfat * FAT_ARCH_64_SIZE;
        let mut out = Vec::new();
        out.extend_from_slice(&FAT_MAGIC_64);
        out.extend_from_slice(&(nfat as u32).to_be_bytes());
        let mut cursor = table_end.next_multiple_of(0x1000);
        let mut placed = Vec::new();
        for (ct, cs, off, size, align) in &entries {
            out.extend_from_slice(&ct.to_be_bytes());
            out.extend_from_slice(&cs.to_be_bytes());
            out.extend_from_slice(&(cursor as u64).to_be_bytes());
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(&align.to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes()); // reserved
            placed.push((cursor, *off as usize, *size as usize));
            cursor = (cursor + *size as usize).next_multiple_of(0x1000);
        }
        out.resize(cursor, 0);
        for (dst, src, len) in placed {
            out[dst..dst + len].copy_from_slice(&bytes[src..src + len]);
        }
        out
    }

    #[test]
    fn parses_real_universal() {
        let bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let bin = UniversalBinary::parse(&bytes).expect("should parse");
        assert_eq!(bin.skipped(), 0);
        assert!(!bin.is_fat64());
        // Slices come in fat-arch (file) order; this fixture lists x86_64
        // first. Assert membership, not order.
        let arches = bin.arches();
        assert_eq!(arches.len(), 2);
        assert!(arches.contains(&Arch::X86));
        assert!(arches.contains(&Arch::X64));

        let x86 = bin.get(Arch::X86).expect("x86 slice");
        assert!(!x86.is_64());
        assert!(!x86.exec_scan_regions().is_empty());
        let x64 = bin.get(Arch::X64).expect("x64 slice");
        assert!(x64.is_64());
        assert!(!x64.exec_scan_regions().is_empty());
        assert!(bin.get(Arch::Arm64).is_none());

        // universal.py:77-81 — concatenated exec regions over all slices.
        let all = bin.all_exec_scan_regions();
        assert_eq!(
            all.len(),
            x86.exec_scan_regions().len() + x64.exec_scan_regions().len()
        );
    }

    // ---- CORE-03 ---------------------------------------------------------

    #[test]
    fn slice_infos_describe_every_usable_slice() {
        let bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let bin = UniversalBinary::parse(&bytes).unwrap();
        let infos = bin.slice_infos();
        assert_eq!(infos.len(), bin.slices().len());
        let names: Vec<&str> = infos.iter().map(|i| i.name()).collect();
        assert!(names.contains(&"i386"), "{names:?}");
        assert!(names.contains(&"x86_64"), "{names:?}");
        for i in infos {
            // Offsets/sizes are the fat-arch table's, and they must be a
            // real range inside the file.
            assert!(i.offset > 0);
            assert!(i.offset + i.size <= bytes.len() as u64);
            assert_eq!(i.endianness, Endianness::Little);
        }
        // The fat-arch table really says x86_64 at 0x1000 and i386 at 0x8000.
        let mut spans: Vec<(u64, u64)> = infos.iter().map(|i| (i.offset, i.size)).collect();
        spans.sort_unstable();
        assert_eq!(spans, vec![(0x1000, 0x68f0), (0x8000, 0x66d0)]);
    }

    #[test]
    fn select_picks_one_slice_and_names_the_alternatives() {
        let bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let bin = UniversalBinary::parse(&bytes).unwrap();
        assert!(bin.needs_arch_selection(), "two slices need a choice");

        let x64 = bin.select(Arch::X64).expect("x86_64 slice");
        assert_eq!(x64.arch(), Arch::X64);
        assert!(x64.is_64());
        // Selecting one slice scans strictly less than the concatenation —
        // the point of the flag.
        assert!(x64.exec_scan_regions().len() < bin.all_exec_scan_regions().len());

        let err = bin.select(Arch::Arm64).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("arm64"), "{msg}");
        assert!(msg.contains("x86_64") && msg.contains("i386"), "{msg}");
    }

    #[test]
    fn select_mut_and_into_slice_hand_over_a_rebasable_image() {
        let bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        let mut bin = UniversalBinary::parse(&bytes).unwrap();
        {
            let s = bin.select_mut(Arch::X86).unwrap();
            let v0 = s.exec_scan_regions()[0].vaddr;
            s.rebase(0x4000);
            assert_eq!(s.exec_scan_regions()[0].vaddr, v0 + 0x4000);
        }
        let owned = bin.into_slice(Arch::X64).unwrap();
        assert_eq!(owned.arch(), Arch::X64);
    }

    #[test]
    fn arch_slice_names_round_trip() {
        for a in [
            Arch::X86,
            Arch::X64,
            Arch::Arm,
            Arch::ArmThumb,
            Arch::Arm64,
            Arch::Mips32,
            Arch::Mips64,
            Arch::Ppc32,
            Arch::Ppc64,
            Arch::Sparc,
            Arch::Sparc64,
            Arch::SparcV9,
            Arch::RiscV32,
            Arch::RiscV64,
        ] {
            assert_eq!(Arch::from_slice_name(a.slice_name()), Some(a), "{a:?}");
        }
        assert_eq!(Arch::from_slice_name("ARM64e"), Some(Arch::Arm64));
        assert_eq!(Arch::from_slice_name("aarch64"), Some(Arch::Arm64));
        assert_eq!(Arch::from_slice_name(" x86_64 "), Some(Arch::X64));
        assert_eq!(Arch::from_slice_name("nonesuch"), None);
    }

    // ---- CORE-05 ---------------------------------------------------------

    #[test]
    fn fat64_container_loads() {
        let bytes = to_fat64(&load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib"));
        assert_eq!(&bytes[..4], &FAT_MAGIC_64);
        assert_eq!(crate::Binary::detect(&bytes), crate::Format::Universal);
        let bin = UniversalBinary::parse(&bytes).expect("fat64 must load");
        assert!(bin.is_fat64());
        assert_eq!(bin.skipped(), 0);
        let arches = bin.arches();
        assert_eq!(arches.len(), 2, "{arches:?}");
        assert!(arches.contains(&Arch::X86));
        assert!(arches.contains(&Arch::X64));
        assert!(!bin
            .select(Arch::X64)
            .unwrap()
            .exec_scan_regions()
            .is_empty());
        // And through the format dispatcher, which detects `cafebabf`.
        assert!(matches!(
            crate::Binary::load(&bytes),
            Ok(crate::LoadedBinary::Universal(_))
        ));
    }

    #[test]
    fn fat32_file_with_a_corrupted_magic_byte_is_refused() {
        // CORE-05's related risk: goblin does not reject `cafebabf`, it read
        // the 32-bit arch table as a 64-bit one and rop-finder printed 69
        // gadgets where the oracle printed "Binary format not supported".
        // Dispatching on the magic makes the garbage table fail instead.
        let mut bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        bytes[3] = 0xbf;
        let err = UniversalBinary::parse(&bytes).expect_err("must be refused");
        assert!(matches!(err, Error::Malformed(_)), "{err:?}");
    }

    #[test]
    fn fat64_garbage_is_refused_not_allocated() {
        // Absurd nfat_arch in a 64-bit fat header.
        let mut g = vec![0u8; 64];
        g[0..4].copy_from_slice(&FAT_MAGIC_64);
        g[4..8].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        assert!(UniversalBinary::parse(&g).is_err());
        // Zero slices.
        g[4..8].copy_from_slice(&0u32.to_be_bytes());
        assert!(UniversalBinary::parse(&g).is_err());
        // A plausible count whose table does not fit.
        g[4..8].copy_from_slice(&8u32.to_be_bytes());
        assert!(UniversalBinary::parse(&g).is_err());
        // Entries that point outside the file.
        let mut g = vec![0u8; 8 + FAT_ARCH_64_SIZE];
        g[0..4].copy_from_slice(&FAT_MAGIC_64);
        g[4..8].copy_from_slice(&1u32.to_be_bytes());
        g[16..24].copy_from_slice(&u64::MAX.to_be_bytes()); // offset
        g[24..32].copy_from_slice(&u64::MAX.to_be_bytes()); // size
        assert!(UniversalBinary::parse(&g).is_err());
    }

    // ---- pre-existing coverage ------------------------------------------

    #[test]
    fn truncations_never_panic() {
        let bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        for n in 0..=512usize.min(bytes.len()) {
            let _ = UniversalBinary::parse(&bytes[..n]);
        }
        // ~200 coarse truncation lengths over the whole file.
        let step = (bytes.len() / 200).max(1);
        for n in (512..bytes.len()).step_by(step) {
            let _ = UniversalBinary::parse(&bytes[..n]);
        }
        // Same sweep over the fat64 rewrite.
        let fat64 = to_fat64(&bytes);
        for n in 0..=512usize.min(fat64.len()) {
            let _ = UniversalBinary::parse(&fat64[..n]);
        }
        let step = (fat64.len() / 200).max(1);
        for n in (512..fat64.len()).step_by(step) {
            let _ = UniversalBinary::parse(&fat64[..n]);
        }
    }

    #[test]
    fn mutated_bytes_never_panic() {
        let bytes = load_fixture("UNIVERSAL-x86-x64-libSystem.B.dylib");
        // Bit-flip mutations across the fat header and arch table.
        for i in 0..256usize.min(bytes.len()) {
            let mut m = bytes.clone();
            m[i] ^= 0xff;
            let _ = UniversalBinary::parse(&m);
        }
        // Pseudo-random single-byte flips across the rest of the file.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..200 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let idx = (state >> 33) as usize % bytes.len();
            let mut m = bytes.clone();
            m[idx] ^= (state >> 11) as u8 | 1;
            let _ = UniversalBinary::parse(&m);
        }
        // And over the fat64 header/arch table.
        let fat64 = to_fat64(&bytes);
        for i in 0..256usize.min(fat64.len()) {
            let mut m = fat64.clone();
            m[i] ^= 0xff;
            let _ = UniversalBinary::parse(&m);
        }
    }

    #[test]
    fn garbage_returns_err_not_panic() {
        assert!(UniversalBinary::parse(b"").is_err());
        assert!(UniversalBinary::parse(b"\xca\xfe\xba\xbe").is_err());
        assert!(UniversalBinary::parse(&[0u8; 64]).is_err());
        // Valid fat magic, absurd nfat_arch.
        let mut g = vec![0u8; 64];
        g[0..4].copy_from_slice(&FAT_MAGIC);
        g[4..8].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        let _ = UniversalBinary::parse(&g); // must not panic
    }
}
