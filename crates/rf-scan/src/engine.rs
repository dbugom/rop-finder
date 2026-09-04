//! The scanning engine: anchor scan → per-candidate decode → clean-decode
//! validity → passClean → dedup → filters.
//!
//! Traversal order (deterministic, matching ROPgadget's pipeline):
//! **section order → table order (ROP, JOP, SYS within each section) →
//! anchor-table order → anchor-hit offset order → depth order**
//! (`i = 0..depth`, i.e. shortest gadget first).
//!
//! Output dedup is by gadget **text**, first-occurrence-wins in that order
//! (ropgadget/rgutils.py:9-18) — through [`crate::trie::GadgetTrie`], which
//! decides it without materialising the text. Because our formatter is
//! iced-x86 rather than capstone, text — and therefore dedup survivor
//! identity in rare ties — can differ cosmetically; parity is judged on
//! (vaddr, bytes) sets.
//!
//! Parallelism (v0.5.0, PERF-04): each anchor's hit list is found once per
//! region and CUT into equal slices, and a work item is one such slice —
//! i.e. an overlapping byte range of the region, sized by where the work
//! actually is rather than by address. The previous unit was a whole
//! `(region × anchor)` pair, which on the MIPS fixture put 92% of the work
//! in one item and capped scaling at 1.09x. Items are enumerated in exactly
//! the traversal order above and rayon's indexed `map_init` preserves it, so
//! the merged output — and therefore the text-dedup survivor — is identical
//! to the serial run regardless of thread scheduling.
//! `ScanOptions::parallel = false` selects the serial path (tests).
//!
//! There is no per-start decode cache: PERF-03 measured a 0.8% hit rate and
//! a net slowdown, and deleted it. On the fixed-width capstone
//! architectures its place is taken by [`crate::cs::RegionIndex`], which
//! decodes each region once (over the slots any candidate can reach) and
//! answers the whole candidate test — clean decode AND `passClean` — with
//! one array lookup.
//!
//! Output shape (v0.2.0): the scan drives a [`GadgetSink`] rather than
//! returning a materialized `Vec`, and polls a [`CancelToken`] inside the
//! loops it already runs. [`scan_binary`] stays as the unbounded,
//! uncancellable delegate so existing callers are untouched.

use std::borrow::Cow;

use rayon::prelude::*;
use regex::Regex;

use rf_core::{Arch, Image};

use crate::anchors::{self, Anchor, TableKind};
use crate::cancel::{CancelToken, Error};
use crate::cs;
use crate::sink::{BoundedSink, GadgetSink, VecSink};
use crate::trie::{self, GadgetTrie};
use crate::x86::{self, GadgetFormatter, WinInsn};

/// Poll the cancel token every this many anchor hits (`gadgets.py:70`'s
/// `for ref in allRefRet`).
pub(crate) const CANCEL_CHECK_HITS: usize = 1024;
/// Poll the cancel token every this many candidate starts (the depth loop).
pub(crate) const CANCEL_CHECK_CANDIDATES: usize = 256;

/// Scanner configuration.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// ROPgadget --depth: candidate starts are `anchor_pos - i` for
    /// `i in 0..depth` (shortest gadget first).
    pub depth: usize,
    pub rop: bool,
    pub jop: bool,
    pub sys: bool,
    /// ROPgadget --multibr: allow branch instructions in the middle of a
    /// gadget (ret-family still always rejected in the middle).
    pub multibr: bool,
    /// ROPgadget --only: keep gadgets whose every instruction mnemonic
    /// (first whitespace-separated token) is in this set.
    pub only: Option<Vec<String>>,
    /// ROPgadget --range: sections are truncated to `[start, end)` before
    /// scanning (`core.py:_sectionInRange`) AND the final, --offset-shifted
    /// addresses are re-filtered inclusively (`options.py:__rangeOption`,
    /// SCAN-10).
    pub range: Option<(u64, u64)>,
    /// ROPgadget --badbytes: reject gadgets whose packed little-endian
    /// address (4 bytes for ELF32, 8 for ELF64, after --offset) contains any
    /// of these bytes.
    pub badbytes: Vec<u8>,
    /// ROPgadget --filter, as the alternation parts the CLI split on `|`.
    /// Joined back with `|` and compiled into ROPgadget's anchored
    /// `({...})$` regex — a FULL match against each instruction's mnemonic
    /// (SCAN-01/CLI-02). Ignored when [`ScanOptions::filter_re`] is set.
    pub filter: Vec<String>,
    /// ROPgadget --filter as an already-compiled regex. Its source is
    /// re-wrapped as `^(?:src)$` and OR-ed with the architecture's built-in
    /// filter, exactly as `gadgets.py:31-40` concatenates them.
    pub filter_re: Option<Regex>,
    /// ROPgadget --offset: additive slide applied at emission; disassembly
    /// is unaffected.
    pub offset: u64,
    /// ROPgadget --thumb: disassemble ARM binaries in Thumb mode.
    /// A Thumb-only image (`Arch::ArmThumb`, e.g. a Windows ARMv7 PE) is
    /// routed to the Thumb tables automatically (ANCH-06); for a dual-mode
    /// ARM ELF this flag is the only source of Thumb mode, because
    /// ROPgadget scans those in ARM mode unless --thumb is given
    /// (gadgets.py:331, 448).
    pub thumb: bool,
    /// Phase 4b `--cfg-aware` (CRIT-01): keep only the gadgets that survive
    /// Intel CET. Table-aware: JOP/SYS gadgets are reached through an
    /// indirect branch and therefore need an `endbr32`/`endbr64` landing pad
    /// at their entry; ROP gadgets are reached through a `ret`, which IBT
    /// does not constrain at all, so they are kept. x86/x64 only — see
    /// [`ibt_applicable`] for the "this binary has no landing pads" warning
    /// the CLI is supposed to print.
    pub cfg_aware: bool,
    /// ROPgadget --align: override every anchor's backward-stepping
    /// alignment (gadgets.py:66-67). This is real scan-time STEPPING, not a
    /// post-filter: an aligned anchor hit steps back by `align` bytes per
    /// depth level (ANCH-01/SCAN-05/CLI-10). `Some(0)`/`None` both mean "use
    /// the anchor table's own align" — the oracle's `if self.__options.align`
    /// is falsy for 0.
    pub align: Option<usize>,
    /// ROPgadget --callPreceded: capture up to 9 section bytes preceding
    /// each gadget start into [`Gadget::prev`] (gadgets.py:57,120-124).
    /// The filter itself runs at the CLI boundary (options.py:100-120).
    pub call_preceded: bool,
    /// ROPgadget --all: skip duplicate-gadget removal
    /// (core.py:87-88); alphabetical sort still applies.
    pub all: bool,
    /// ROPgadget --noinstr: skip BOTH dedup and the alphabetical sort
    /// (core.py:87-95); the CLI prints bare addresses.
    pub noinstr: bool,
    /// Scan (region × anchor) work items with rayon. Output is identical
    /// either way; serial exists for tests and debugging.
    pub parallel: bool,
    /// Cooperative cancellation. Only the cancellable entry points
    /// ([`scan_binary_into`], [`scan_bounded`]) observe it.
    pub cancel: CancelToken,
    /// Stop with [`Error::Budget`] after this many accepted gadgets
    /// (PERF-05). `None` = unbounded.
    pub max_gadgets: Option<usize>,
    /// Stop with [`Error::Budget`] once the retained gadgets are estimated
    /// to exceed this many heap bytes (PERF-05). `None` = unbounded.
    pub max_memory: Option<usize>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            depth: 10,
            rop: true,
            jop: true,
            sys: true,
            multibr: false,
            only: None,
            range: None,
            badbytes: Vec::new(),
            filter: Vec::new(),
            filter_re: None,
            offset: 0,
            thumb: false,
            cfg_aware: false,
            align: None,
            call_preceded: false,
            all: false,
            noinstr: false,
            parallel: true,
            cancel: CancelToken::never(),
            max_gadgets: None,
            max_memory: None,
        }
    }
}

impl ScanOptions {
    /// The user half of ROPgadget's mnemonic filter, as regex source.
    pub(crate) fn filter_source(&self) -> Option<String> {
        if let Some(re) = &self.filter_re {
            return Some(re.as_str().to_string());
        }
        let parts: Vec<&str> = self.filter.iter().map(|s| s.as_str()).collect();
        if parts.is_empty() {
            None
        } else {
            Some(parts.join("|"))
        }
    }

    /// ROPgadget's compiled `({user})$` matcher, or `None` when no user
    /// filter was given. The architecture's built-in list is applied
    /// separately by each decode path (`db|int3` for x86, `brk|smc|hvc` for
    /// ARM64) so the common no-filter case allocates no strings.
    pub(crate) fn compiled_filter(&self) -> Result<Option<Regex>, Error> {
        match self.filter_source() {
            None => Ok(None),
            Some(src) => x86::compile_filter(&src).map(Some).map_err(|e| {
                Error::Core(rf_core::Error::Unsupported(format!(
                    "--filter is not a valid regex: {e}"
                )))
            }),
        }
    }

    /// `gadgets.py:66-67`: a non-zero `--align` replaces the anchor's own
    /// `gad_align`; 0 and None leave it alone.
    pub(crate) fn effective_align(&self, anchor: &Anchor) -> usize {
        match self.align {
            Some(a) if a > 0 => a,
            _ => anchor.align(),
        }
    }
}

/// One gadget. Text is produced once at the output boundary.
#[derive(Debug, Clone)]
pub struct Gadget {
    pub vaddr: u64,
    pub bytes: Vec<u8>,
    /// Full formatted text per instruction (mnemonic + operands).
    pub insns: Vec<String>,
    /// True on delay-slot ISAs (MIPS, SPARC — PLAN.md §4): the instruction
    /// after the control transfer still executes before the jump takes
    /// effect, so classification/chains must not treat the text as the full
    /// executed path. (ROPgadget includes the delay slot in the gadget text
    /// for MIPS — anchor size 8 — but not for SPARC — anchor size 4.)
    pub delay_slot: bool,
    /// Up to 9 section bytes preceding the gadget start — captured only
    /// when `ScanOptions::call_preceded` is set (gadgets.py:120-124,
    /// PREV_BYTES=9). Note the oracle reads these with the --offset slide
    /// mixed in (a latent oracle bug with --offset --callPreceded); we
    /// always read the true preceding bytes.
    pub prev: Option<Vec<u8>>,
    /// Which anchor table produced this gadget. Recorded because how a
    /// gadget is *reached* decides which mitigation applies to it: an
    /// indirect branch into a JOP/SYS gadget is checked by Intel IBT, a
    /// `ret` into a ROP gadget is not (CRIT-01).
    pub table: TableKind,
}

impl Gadget {
    /// ROPgadget-style " ; "-joined text (`gadgets.py:118-119`).
    pub fn text(&self) -> String {
        self.insns.join(" ; ")
    }

    pub fn bytes_hex(&self) -> String {
        let mut s = String::with_capacity(self.bytes.len() * 2);
        for b in &self.bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// Everything the per-anchor routines need that is derived once per scan.
pub(crate) struct ScanCtx<'a> {
    pub(crate) opts: &'a ScanOptions,
    pub(crate) filter: Option<Regex>,
    /// Per-work-item gadget cap derived from `max_gadgets` (PERF-05): a
    /// work item never produces more than the whole scan may keep.
    pub(crate) item_cap: Option<usize>,
    /// Per-work-item BYTE cap derived from `max_memory`. Work items run
    /// concurrently and each holds its own vector until the merge, so
    /// bounding the sink alone does not bound the peak: a single item that
    /// alone exceeds the whole budget has already blown it, and stopping
    /// there is what keeps the parallel path's high-water mark down.
    pub(crate) item_byte_cap: Option<usize>,
}

/// Scan a loaded binary of any supported architecture. Dispatch: x86/x64 →
/// iced-x86 path; every other [`Arch`] → the capstone path.
///
/// Works over the format-agnostic [`Image`] contract so ELF, PE, Mach-O and
/// raw images all share this entry point. Returns gadgets deduplicated by
/// text and sorted alphabetically (ROPgadget's `alphaSortgadgets`).
///
/// This is the unbounded, uncancellable delegate: it drives a [`VecSink`]
/// with [`CancelToken::never`], so no existing caller changes behaviour.
pub fn scan_binary<B: Image + ?Sized>(
    bin: &B,
    opts: &ScanOptions,
) -> Result<Vec<Gadget>, rf_core::Error> {
    let mut opts = opts.clone();
    opts.cancel = CancelToken::never();
    opts.max_gadgets = None;
    opts.max_memory = None;
    let mut sink = VecSink::new();
    scan_binary_into(bin, &opts, &mut sink)?;
    Ok(post_process(sink.into_inner(), &opts, bin.addr_size())?)
}

/// Cancellable, budgeted scan: drives `sink` with the RAW traversal-order
/// gadget stream (before dedup/filters/sort — run [`post_process`] on the
/// collected result to finish the pipeline).
pub fn scan_binary_into<B: Image + ?Sized, S: GadgetSink>(
    bin: &B,
    opts: &ScanOptions,
    sink: &mut S,
) -> Result<(), Error> {
    let arch = bin.arch();
    let endian = bin.endianness();
    // PLAN.md §4: delay-slot ISAs.
    let delay_slot = matches!(
        arch,
        Arch::Mips32 | Arch::Mips64 | Arch::Sparc | Arch::Sparc64 | Arch::SparcV9
    );

    // Scan ROPgadget-compatible regions (executable program headers for ELF),
    // range-truncated up front (core.py:_sectionInRange).
    //
    // PERF-11: with no `--range` the region BORROWS the loader's bytes. The
    // previous `sec.bytes.clone()` was the third copy of every executable
    // byte in the process (whole-file buffer → `Section::bytes` → this), and
    // on the 100 MB targets MANUAL.md recommends it was ~100 MB of memcpy
    // before a single gadget was found. `--range` still owns, because it
    // truncates.
    let mut regions: Vec<Region<'_>> = Vec::new();
    for sec in bin.exec_scan_regions() {
        match opts.range {
            None => regions.push(Region {
                code: Cow::Borrowed(&sec.bytes),
                vaddr: sec.vaddr,
            }),
            Some(_) => {
                if let Some((bytes, vaddr)) = apply_range(sec, opts.range) {
                    regions.push(Region {
                        code: Cow::Owned(bytes),
                        vaddr,
                    });
                }
            }
        }
    }

    let ctx = ScanCtx {
        opts,
        filter: opts.compiled_filter()?,
        item_cap: opts.max_gadgets,
        item_byte_cap: opts.max_memory,
    };

    // ANCH-06: a Thumb-only image has no A32 code to find, so route it to
    // the Thumb tables whether or not --thumb was passed. rf-core decides
    // Thumb-only-ness (PE `IMAGE_FILE_MACHINE_ARMNT` → `Arch::ArmThumb`).
    let thumb = opts.thumb || arch == Arch::ArmThumb;

    let chunks = if arch.is_x86_family() {
        let bits = if arch == Arch::X64 { 64 } else { 32 };
        let tables = x86_tables(bits, opts);
        let lists = find_hits(&regions, &tables, &ctx);
        let items = plan_items(&lists, &ctx);
        run_items(
            &regions,
            &items,
            &ctx,
            x86::make_formatter,
            |fmt, region, item, out| {
                x86_scan_hits(
                    &region.code,
                    region.vaddr,
                    bits,
                    &ctx,
                    item.anchor,
                    item.kind,
                    item.hits,
                    fmt,
                    out,
                );
            },
        )
    } else {
        let spec = cs::spec(arch, endian, thumb)?;
        // Validate the capstone mode once up front so a bad combination is a
        // clean error rather than empty per-thread results.
        let _probe = cs::open(&spec)?;
        let tables: Vec<(TableKind, Vec<Anchor>)> = [
            opts.rop.then(|| {
                (
                    TableKind::Rop,
                    anchors::table(TableKind::Rop, arch, endian, thumb),
                )
            }),
            opts.jop.then(|| {
                (
                    TableKind::Jop,
                    anchors::table(TableKind::Jop, arch, endian, thumb),
                )
            }),
            opts.sys.then(|| {
                (
                    TableKind::Sys,
                    anchors::table(TableKind::Sys, arch, endian, thumb),
                )
            }),
        ]
        .into_iter()
        .flatten()
        .collect();
        let lists = find_hits(&regions, &tables, &ctx);
        let items = plan_items(&lists, &ctx);
        // PERF-09: one resumable decode of each region, shared by every
        // anchor and every candidate in it. Fixed-width ISAs only, and only
        // when the region is probed densely enough to pay for it —
        // `cs::build_indexes` decides both.
        let indexes: Vec<Option<cs::RegionIndex>> =
            cs::build_indexes(&spec, &regions, &lists, &ctx, max_span(&lists, &ctx));
        run_items(
            &regions,
            &items,
            &ctx,
            || cs::open(&spec).ok(),
            |handle, region, item, out| {
                // capstone-rs Capstone is !Send/!Sync: one handle per rayon
                // worker (already validated above; a failure yields nothing).
                if let Some(handle) = handle.as_ref() {
                    cs::scan_hits(
                        handle,
                        &spec,
                        &region.code,
                        region.vaddr,
                        item.anchor,
                        item.kind,
                        item.hits,
                        indexes[item.region].as_ref(),
                        &ctx,
                        delay_slot,
                        out,
                    );
                }
            },
        )
    };

    opts.cancel.check()?;
    // The whole raw stream is already materialised in the per-item vectors,
    // so the sink can size itself once instead of regrowing 324k times.
    sink.reserve(chunks.iter().map(Vec::len).sum());
    for chunk in chunks {
        for g in chunk {
            sink.accept(g)?;
        }
    }
    Ok(())
}

/// Convenience wrapper: cancellable + bounded scan through a
/// [`BoundedSink`], finished by [`post_process`].
pub fn scan_bounded<B: Image + ?Sized>(bin: &B, opts: &ScanOptions) -> Result<Vec<Gadget>, Error> {
    let mut sink = BoundedSink::new(opts.max_gadgets, opts.max_memory);
    scan_binary_into(bin, opts, &mut sink)?;
    post_process(sink.into_inner(), opts, bin.addr_size())
}

/// Enabled x86 anchor tables in ROP/JOP/SYS order, tagged with the table
/// that produced them.
fn x86_tables(bits: u32, opts: &ScanOptions) -> Vec<(TableKind, Vec<Anchor>)> {
    [
        opts.rop.then(|| (TableKind::Rop, anchors::rop_anchors())),
        opts.jop
            .then(|| (TableKind::Jop, anchors::jop_anchors(bits == 64))),
        opts.sys.then(|| (TableKind::Sys, anchors::sys_anchors())),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// One executable buffer to scan — borrowed from the loader unless `--range`
/// truncated it (PERF-11).
pub(crate) struct Region<'a> {
    pub(crate) code: Cow<'a, [u8]>,
    pub(crate) vaddr: u64,
}

/// Every hit of one anchor in one region, in ascending offset order.
pub(crate) struct AnchorHits<'a> {
    pub(crate) region: usize,
    pub(crate) anchor: &'a Anchor,
    pub(crate) kind: TableKind,
    pub(crate) hits: Vec<usize>,
}

/// One unit of scan work: a contiguous SLICE of one anchor's hit list in one
/// region.
///
/// PERF-04 — the previous unit was a whole `(region × anchor)` pair, and a
/// region was never split. For an ELF there is effectively one executable
/// region, so the parallel width was the anchor-table size and the balance
/// was the hit distribution across anchors, which is extremely skewed: on
/// `elf-Mips-Defcon-20-pwn100` one anchor (`j addr`) holds 92% of the hits,
/// pinning the ceiling at 1.09x however many cores are present. Measured
/// end-to-end scaling was 1.2-1.9x.
///
/// The hit list is now computed once per (region, anchor) and cut into equal
/// slices, so the unit of work is an overlapping byte range of the region —
/// the range those hits span, plus `depth*align` bytes of lead-in and the
/// anchor's trailing bytes, read straight out of the shared region buffer
/// rather than copied into a window. Cutting the hit list rather than the
/// address space is what makes the pieces EQUAL: the hits are the work, and
/// they are not uniformly distributed over the bytes.
///
/// Two invariants make this safe:
///  * `anchors::find_matches` has Python `re.finditer` semantics — after a
///    match it resumes at `match_end` — so the hit set is a property of the
///    WHOLE region and cannot be reconstructed by scanning a sub-range in
///    isolation. Computing it once and slicing the result keeps it exact;
///    cutting the bytes would silently change it.
///  * Items are enumerated region → table → anchor → hit-slice and each item
///    preserves (hit, depth) order internally, so concatenating item outputs
///    in index order reproduces the single-threaded traversal order exactly.
///    That is what keeps the text-dedup survivor — and therefore the emitted
///    (vaddr, bytes) set — independent of thread scheduling.
pub(crate) struct WorkItem<'a> {
    /// Index into the region list; the region is shared, never copied.
    pub(crate) region: usize,
    pub(crate) anchor: &'a Anchor,
    pub(crate) kind: TableKind,
    /// A slice of this (region, anchor)'s hit list.
    pub(crate) hits: &'a [usize],
}

/// Aim for this many work items per worker thread. Oversubscribing lets
/// rayon smooth over the residual cost differences between anchors (a `ret`
/// hit and a `jmp rel32` hit do not cost the same) without paying a per-item
/// setup cost big enough to show in the profile.
const ITEMS_PER_THREAD: usize = 8;

/// Never cut a hit list finer than this: below it the per-item overhead — a
/// `Vec` allocation, and on the capstone path the branch that checks for a
/// per-worker handle — starts to dominate the work inside the item.
const MIN_HITS_PER_ITEM: usize = 64;

/// Below this many surviving gadgets the alphabetical sort stays serial:
/// rayon's split and join cost more than the sort does.
const PARALLEL_SORT_MIN: usize = 8192;

/// Smallest byte range the parallel anchor search will hand to one worker.
/// Below this the merge pass and the task overhead cost more than the memchr
/// sweep they split.
const HIT_SCAN_MIN_CHUNK: usize = 32 * 1024;

/// Find every anchor hit, in traversal order (region → table → anchor).
///
/// memchr over a 1.4 MB region for 100k hits is not free and is perfectly
/// parallel, so this runs across (region × anchor) pairs under rayon before
/// any decoding starts.
fn find_hits<'a>(
    regions: &[Region<'_>],
    tables: &'a [(TableKind, Vec<Anchor>)],
    ctx: &ScanCtx<'_>,
) -> Vec<AnchorHits<'a>> {
    let keys: Vec<(usize, TableKind, &'a Anchor)> = (0..regions.len())
        .flat_map(|r| {
            tables
                .iter()
                .flat_map(move |(k, t)| t.iter().map(move |a| (r, *k, a)))
        })
        .collect();
    if !ctx.opts.parallel || keys.len() < 2 {
        return keys
            .iter()
            .map(|&(region, kind, anchor)| AnchorHits {
                region,
                anchor,
                kind,
                hits: if ctx.opts.cancel.is_cancelled() {
                    Vec::new()
                } else {
                    anchors::find_matches(&regions[region].code, anchor)
                },
            })
            .collect();
    }

    // Parallelising over anchors alone leaves the same skew that PERF-04 is
    // about: on the MIPS fixture one anchor holds 92% of the hits, so the
    // whole search is as slow as that one memchr sweep. Split each key's
    // region into byte ranges as well, then rebuild `re.finditer`'s stateful
    // leftmost-greedy selection over the concatenated positions.
    let cancelled = ctx.opts.cancel.is_cancelled();
    let chunk = |len: usize| -> usize {
        let want = rayon::current_num_threads().max(1) * 4;
        len.div_ceil(want.max(1)).max(HIT_SCAN_MIN_CHUNK)
    };
    let mut subkeys: Vec<(usize, usize, usize)> = Vec::new(); // (key, lo, hi)
    for (ki, &(region, _, _)) in keys.iter().enumerate() {
        let len = regions[region].code.len();
        if cancelled || len == 0 {
            continue;
        }
        let step = chunk(len);
        let mut lo = 0usize;
        while lo < len {
            subkeys.push((ki, lo, (lo + step).min(len)));
            lo += step;
        }
    }
    let parts: Vec<Vec<usize>> = subkeys
        .par_iter()
        .map(|&(ki, lo, hi)| {
            if ctx.opts.cancel.is_cancelled() {
                return Vec::new();
            }
            let (region, _, anchor) = keys[ki];
            anchors::find_matches_in(&regions[region].code, anchor, lo, hi)
        })
        .collect();

    let mut per_key: Vec<Vec<usize>> = vec![Vec::new(); keys.len()];
    for (&(ki, _, _), part) in subkeys.iter().zip(parts) {
        per_key[ki].extend(part);
    }
    keys.iter()
        .zip(per_key)
        .map(|(&(region, kind, anchor), all)| AnchorHits {
            region,
            anchor,
            kind,
            hits: anchors::merge_finditer(&all, anchor),
        })
        .collect()
}

/// Cut the hit lists into balanced work items, preserving traversal order.
fn plan_items<'a>(lists: &'a [AnchorHits<'a>], ctx: &ScanCtx<'_>) -> Vec<WorkItem<'a>> {
    let total: usize = lists.iter().map(|l| l.hits.len()).sum();
    let threads = if ctx.opts.parallel {
        rayon::current_num_threads().max(1)
    } else {
        1
    };
    let per_item = total
        .div_ceil((threads * ITEMS_PER_THREAD).max(1))
        .max(MIN_HITS_PER_ITEM);
    let mut items = Vec::new();
    for l in lists {
        for hits in l.hits.chunks(per_item) {
            items.push(WorkItem {
                region: l.region,
                anchor: l.anchor,
                kind: l.kind,
                hits,
            });
        }
    }
    items
}

/// The longest byte span any candidate of any anchor can cover:
/// `(depth-1)*align + anchor size`. This is the lead-in the overlapping byte
/// ranges read, and the cap on the run lengths [`cs::RegionIndex`] stores.
fn max_span(lists: &[AnchorHits<'_>], ctx: &ScanCtx<'_>) -> usize {
    lists
        .iter()
        .map(|l| {
            ctx.opts.depth.saturating_sub(1) * ctx.opts.effective_align(l.anchor).max(1)
                + l.anchor.size()
        })
        .max()
        .unwrap_or(0)
}

/// Run the work list, serially or under rayon, returning the per-item
/// outputs in item order.
///
/// `init` builds whatever per-worker state the decode path needs (an
/// iced-x86 formatter; a capstone handle, which is `!Send`) once per rayon
/// worker rather than once per item. Rayon's `map_init` over an indexed
/// parallel iterator preserves item order, so the merged stream is identical
/// to the serial traversal (PLAN.md §3.3 invariant).
///
/// The closure short-circuits to an empty vector once the token is set, so
/// the residual cost of a cancelled scan is one relaxed atomic load per
/// remaining work item rather than the contents of those items.
fn run_items<'a, T, I, F>(
    regions: &[Region<'_>],
    items: &[WorkItem<'a>],
    ctx: &ScanCtx<'_>,
    init: I,
    f: F,
) -> Vec<Vec<Gadget>>
where
    I: Fn() -> T + Sync + Send,
    F: Fn(&mut T, &Region<'_>, &WorkItem<'a>, &mut Vec<Gadget>) + Sync + Send,
{
    let run = |state: &mut T, item: &WorkItem<'a>| {
        let mut out = Vec::new();
        if ctx.opts.cancel.is_cancelled() {
            return out;
        }
        f(state, &regions[item.region], item, &mut out);
        out
    };
    if ctx.opts.parallel && items.len() > 1 {
        items.par_iter().map_init(init, run).collect()
    } else {
        let mut state = init();
        items.iter().map(|i| run(&mut state, i)).collect()
    }
}

/// Dedup (text, first-wins) → --only → --range → --badbytes → --cfg-aware →
/// alphabetical sort, matching `core.py:87-95` + `options.py:22-33`.
/// Split out of `scan_binary` so it can be unit-tested on synthetic gadgets.
pub fn post_process(
    mut all: Vec<Gadget>,
    opts: &ScanOptions,
    addr_size: usize,
) -> Result<Vec<Gadget>, Error> {
    opts.cancel.check()?;

    // PERF-10 / CLAIM-07. This used to open with
    //     let mut keyed: Vec<(String, Gadget)> = all.drain(..)
    //         .map(|g| (g.text(), g)).collect();
    // and then `seen.insert(text.clone())` — a joined `String` per gadget for
    // the key, a clone of it for the set, and the set's own copy: three heap
    // strings per gadget beyond the per-instruction ones, 15.9 ms of a
    // 110.4 ms serial run, and a large share of the 117 B/code-byte
    // footprint. Nothing is materialised now: [`GadgetTrie`] decides dedup
    // by walking the instruction list it already has, and [`cmp_joined`]
    // sorts on the joined text without ever joining it.
    if !opts.all && !opts.noinstr {
        // Dedup by text, first-occurrence-wins in traversal order
        // (rgutils.deleteDuplicateGadgets). --all and --noinstr both skip it
        // (core.py:87-88).
        let mut keep = Vec::with_capacity(all.len());
        {
            let mut trie = GadgetTrie::with_capacity(all.len());
            for (i, g) in all.iter().enumerate() {
                keep.push(trie.insert(&g.insns, i));
            }
        }
        let mut verdict = keep.into_iter();
        all.retain(|_| verdict.next().unwrap_or(true));
    }

    // Post-dedup filters (ropgadget/options.py), in the oracle's order.
    if let Some(only) = &opts.only {
        all.retain(|g| {
            g.insns
                .iter()
                .all(|ins| only.iter().any(|o| o == first_token(ins)))
        });
    }
    // SCAN-10: --range is applied a SECOND time, to the final --offset-
    // shifted addresses, inclusively at both ends (options.py:__rangeOption).
    // "0x0-0x0" means "no range" there, so (0, 0) is a no-op.
    if let Some((lo, hi)) = opts.range {
        if !(lo == 0 && hi == 0) {
            all.retain(|g| lo <= g.vaddr && g.vaddr <= hi);
        }
    }
    if !opts.badbytes.is_empty() {
        all.retain(|g| {
            let packed = g.vaddr.to_le_bytes();
            !opts
                .badbytes
                .iter()
                .any(|b| packed[..addr_size].contains(b))
        });
    }
    if opts.cfg_aware {
        all.retain(survives_cet);
    }

    opts.cancel.check()?;
    // Alphabetical sort by gadget text (rgutils.alphaSortgadgets) —
    // skipped with --noinstr (core.py:94-95).
    //
    // The permutation is sorted, not the gadgets: a `Gadget` is ~80 bytes of
    // move per comparison swap against 8 for an index, and `sort_by` on the
    // indices is still the stable sort the oracle's order depends on when
    // --all leaves equal keys in the list.
    if !opts.noinstr {
        let mut order: Vec<(u128, u32)> = all
            .iter()
            .enumerate()
            .map(|(i, g)| (trie::prefix_key(&g.insns), i as u32))
            .collect();
        let by_text = |a: &(u128, u32), b: &(u128, u32)| {
            a.0.cmp(&b.0)
                .then_with(|| trie::cmp_joined(&all[a.1 as usize].insns, &all[b.1 as usize].insns))
        };
        // rayon's `par_sort_by` is a stable merge sort, so it produces the
        // same permutation as `sort_by` on equal keys — which matters,
        // because with `--all` the dedup pass is skipped and equal keys are
        // ordered by the traversal the whole pipeline depends on. Once the
        // decode phase stopped dominating, this sort became the largest
        // single item left on the MIPS fixture.
        if opts.parallel && order.len() >= PARALLEL_SORT_MIN {
            order.par_sort_by(by_text);
        } else {
            order.sort_by(by_text);
        }
        let mut slots: Vec<Option<Gadget>> = all.into_iter().map(Some).collect();
        all = order
            .into_iter()
            .map(|(_, i)| slots[i as usize].take().expect("each index appears once"))
            .collect();
    }
    Ok(all)
}

fn first_token(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or("")
}

/// `--cfg-aware` (CRIT-01), table-aware.
///
/// The previous implementation required an `endbr32`/`endbr64` at the entry
/// of EVERY gadget, which is a contradiction: a ROP gadget is entered by a
/// `ret`, and Intel IBT does not check returns at all — no compiler emits a
/// landing pad after one. That is why the flag returned zero gadgets on
/// every binary in the repository. With [`Gadget::table`] recorded the two
/// reach mechanisms are modelled separately:
///
///  * JOP/SYS gadgets are reached through an indirect `jmp`/`call`. Under
///    IBT the only legal targets are `endbr32`/`endbr64`, so the entry must
///    be one.
///  * ROP gadgets are reached through a `ret`. IBT is silent about them; the
///    mitigation that constrains them is the CET *shadow stack*, which no
///    gadget's bytes can satisfy or violate — it is a property of the
///    exploit, not of the gadget. They are therefore kept, and the caller is
///    responsible for saying whether shadow stack is enabled.
///
/// Note what this deliberately does NOT do: a PE's `GUARD_CF` bit means
/// Windows Control Flow Guard, a *forward-edge software* check with its own
/// valid-target bitmap. It is not Intel CET and it does not imply landing
/// pads, so it must not be used to decide this filter.
fn survives_cet(g: &Gadget) -> bool {
    match g.table {
        TableKind::Rop => true,
        TableKind::Jop | TableKind::Sys => is_endbr_entry(g),
    }
}

/// The gadget's first bytes are `endbr64` (f3 0f 1e fa) or `endbr32`
/// (f3 0f 1e fb).
fn is_endbr_entry(g: &Gadget) -> bool {
    g.bytes.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]) || g.bytes.starts_with(&[0xf3, 0x0f, 0x1e, 0xfb])
}

/// Does `--cfg-aware` mean anything for this binary? True when the image is
/// x86/x64 AND at least one IBT landing pad (`endbr32`/`endbr64`) appears in
/// an executable region. When this is false the flag can only ever remove
/// gadgets, and the caller is expected to warn instead of silently
/// returning a shorter list (CRIT-01's "promised scan-time warning").
pub fn ibt_applicable<B: Image + ?Sized>(bin: &B) -> bool {
    if !bin.arch().is_x86_family() {
        return false;
    }
    bin.exec_scan_regions().iter().any(|s| {
        s.bytes
            .windows(4)
            .any(|w| w == [0xf3, 0x0f, 0x1e, 0xfa] || w == [0xf3, 0x0f, 0x1e, 0xfb])
    })
}

/// ROPgadget `core.py:_sectionInRange`: truncate the section to the range
/// before scanning. Returns (bytes, new_vaddr).
fn apply_range(sec: &rf_core::Section, range: Option<(u64, u64)>) -> Option<(Vec<u8>, u64)> {
    let (range_start, range_end) = range?;
    let mut vaddr = sec.vaddr;
    let mut offset = sec.offset;
    let mut size = sec.size;
    let sec_end = sec.vaddr.wrapping_add(sec.size);

    if range_end < sec.vaddr || range_start > sec_end {
        return None;
    }
    if range_start > vaddr {
        let diff = range_start - vaddr;
        vaddr += diff;
        offset += diff;
        size -= diff;
    }
    if range_end < sec_end {
        size -= sec_end - range_end;
    }
    if size == 0 {
        return None;
    }
    let byte_start = usize::try_from(offset - sec.offset).ok()?;
    let byte_end = byte_start.saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
    let byte_end = byte_end.min(sec.bytes.len());
    if byte_start >= byte_end {
        return None;
    }
    Some((sec.bytes[byte_start..byte_end].to_vec(), vaddr))
}

/// Scan one executable buffer (x86/x64, serial). Gadgets are appended in
/// traversal order. This is the serial per-section entry point used by
/// tests; `scan_binary` drives the same per-anchor routine over its work
/// list (in parallel when `ScanOptions::parallel` is set).
pub fn scan_section(
    code: &[u8],
    sec_vaddr: u64,
    bits: u32,
    opts: &ScanOptions,
    out: &mut Vec<Gadget>,
) {
    let ctx = ScanCtx {
        opts,
        filter: opts.compiled_filter().unwrap_or(None),
        item_cap: opts.max_gadgets,
        item_byte_cap: opts.max_memory,
    };
    let mut fmt = x86::make_formatter();
    for (kind, table) in x86_tables(bits, opts) {
        for anchor in &table {
            let hits = anchors::find_matches(code, anchor);
            x86_scan_hits(
                code, sec_vaddr, bits, &ctx, anchor, kind, &hits, &mut fmt, out,
            );
        }
    }
}

/// Scan one x86 anchor over one buffer.
///
/// PERF-03 — there is deliberately no per-start decode cache here any more.
/// The one that used to live at this line keyed `HashMap<usize, Rc<Vec<
/// WinInsn>>>` on the candidate start, and because every candidate start is
/// `anchor_pos - i*align` and anchor hits are far apart relative to `depth`,
/// the starts were almost all distinct: 171,648 distinct starts against
/// 173,100 lookups on `elf-x64-bash-v4.1.5.1`, a 0.8% hit rate. The map and
/// `Rc` bookkeeping cost strictly more than the decode they avoided, and the
/// retained windows were the project's largest single memory consumer. The
/// window is now decoded per candidate and, more importantly, only as far as
/// `end` instead of `start + depth*align + MAX_ANCHOR_SIZE`: the candidate
/// test only ever reads the boundary that lands exactly on `end` and the
/// prefix before it, and iced-x86 stops at the first instruction that does
/// not fit, so truncating the window at `end` is provably the same decision
/// on the same bytes — while decoding on average half as many.
///
/// Alignment (ANCH-01/SCAN-05/CLI-10): the candidate-start loop STEPS by
/// `align` — `ref - i*align` when that lands on an aligned virtual address,
/// with ROPgadget's byte-by-byte fallback otherwise (gadgets.py:73-89). At
/// the x86 tables' own `gad_align == 1` this is exactly `ref - i`, so the
/// default scan is byte-identical to before; with `--align 4` it reaches
/// `depth * 4` bytes back instead of filtering `depth` byte-steps down to
/// the two or three that happen to be aligned.
#[allow(clippy::too_many_arguments)]
fn x86_scan_hits(
    code: &[u8],
    sec_vaddr: u64,
    bits: u32,
    ctx: &ScanCtx<'_>,
    anchor: &Anchor,
    kind: TableKind,
    hit_list: &[usize],
    fmt: &mut GadgetFormatter,
    out: &mut Vec<Gadget>,
) {
    let opts = ctx.opts;
    let align = opts.effective_align(anchor);
    let mut hits = 0usize;
    let mut candidates = 0usize;
    let mut item_bytes = 0usize;

    for &ref_pos in hit_list {
        hits += 1;
        if hits % CANCEL_CHECK_HITS == 0 && opts.cancel.is_cancelled() {
            return;
        }
        let end = ref_pos + anchor.size();
        if end > code.len() {
            continue;
        }
        for i in 0..opts.depth {
            candidates += 1;
            if candidates % CANCEL_CHECK_CANDIDATES == 0 {
                if opts.cancel.is_cancelled() {
                    return;
                }
                if let Some(cap) = ctx.item_cap {
                    if out.len() >= cap {
                        return;
                    }
                }
            }
            let Some(start) = step_back(ref_pos, i, align, sec_vaddr, code.len()) else {
                continue;
            };
            let insns = x86::decode_window(code, start, sec_vaddr, bits, end);
            if let Some(g) =
                try_candidate(code, sec_vaddr, bits, start, end, &insns, ctx, kind, fmt)
            {
                if let Some(cap) = ctx.item_byte_cap {
                    item_bytes += crate::sink::gadget_bytes(&g);
                    if item_bytes > cap {
                        out.push(g);
                        return;
                    }
                }
                out.push(g);
            }
        }
    }
}

/// ROPgadget's backward stepping (`gadgets.py:73-89`), shared by both decode
/// paths: try the aligned step `ref - i*align` first and fall back to the
/// byte step `ref - i`, in both cases requiring the candidate start to be
/// `align`-aligned in VIRTUAL address space. Returns `None` when the
/// candidate is out of bounds or misaligned in both forms.
pub(crate) fn step_back(
    ref_pos: usize,
    i: usize,
    align: usize,
    sec_vaddr: u64,
    code_len: usize,
) -> Option<usize> {
    let stepped = i.checked_mul(align)?;
    if align != 0 && ref_pos >= stepped {
        let s = ref_pos - stepped;
        if s < code_len && sec_vaddr.wrapping_add(s as u64) % align as u64 == 0 {
            return Some(s);
        }
    }
    // Byte-by-byte fallback (gadgets.py:82-89).
    if ref_pos < i {
        return None;
    }
    let s = ref_pos - i;
    if s >= code_len {
        return None;
    }
    if align != 0 && sec_vaddr.wrapping_add(s as u64) % align as u64 != 0 {
        return None;
    }
    Some(s)
}

/// A candidate is valid iff the bytes `start..end` decode cleanly
/// (total decoded size == end - start, gadgets.py:100-103 — equivalently:
/// `end` coincides with an instruction boundary of the decode from `start`)
/// and `passCleanX86` accepts it. Instruction text is formatted only here,
/// for accepted candidates.
#[allow(clippy::too_many_arguments)]
fn try_candidate(
    code: &[u8],
    sec_vaddr: u64,
    bits: u32,
    start: usize,
    end: usize,
    window: &[WinInsn],
    ctx: &ScanCtx<'_>,
    kind: TableKind,
    fmt: &mut GadgetFormatter,
) -> Option<Gadget> {
    // Instruction ends are strictly increasing; find the prefix ending at
    // exactly `end`.
    let n = window.partition_point(|r| r.end < end);
    if n >= window.len() || window[n].end != end {
        return None;
    }
    let decodes = &window[..=n];
    if x86::pass_clean(decodes, ctx.opts.multibr, ctx.filter.as_ref()) {
        return None;
    }
    Some(Gadget {
        vaddr: ctx
            .opts
            .offset
            .wrapping_add(sec_vaddr)
            .wrapping_add(start as u64),
        bytes: code[start..end].to_vec(),
        insns: x86::format_gadget(code, start, end, sec_vaddr, bits, fmt),
        delay_slot: false, // x86/x64 have no delay slots
        prev: ctx
            .opts
            .call_preceded
            .then(|| code[start.saturating_sub(PREV_BYTES)..start].to_vec()),
        table: kind,
    })
}

/// `gadgets.py:57` — `PREV_BYTES = 9`.
pub const PREV_BYTES: usize = 9;

/// ROPgadget's `--callPreceded` predicate over [`Gadget::prev`]
/// (options.py:100-112). The engine captures the bytes; this is the test the
/// CLI applies to them, kept here so the two halves cannot drift apart.
///
/// The oracle expresses it as six byte regexes anchored with `$`:
/// `\xe8` + 4 or 8 bytes, or `\xff` + 1, 2, 4 or 8 bytes, at the END of the
/// preceding-byte window — i.e. "the bytes immediately before the gadget are
/// a near or indirect `call`".
///
/// The `trailing newline` arm is not decoration. Python's `$` also matches
/// immediately BEFORE a final `\n`, and `prev` is raw machine code, so a
/// window whose last byte happens to be `0x0a` gets a second chance to match
/// one byte earlier. On tests/fixtures/elf-Linux-x86 that is the difference
/// between 9,889 and the oracle's 9,892 gadgets, so reproducing the quirk is
/// required for parity even though it is plainly an oracle bug.
pub fn is_call_preceded(prev: &[u8]) -> bool {
    fn matches_at(prev: &[u8], end: usize) -> bool {
        let at = |back: usize| -> Option<u8> { end.checked_sub(back).map(|i| prev[i]) };
        at(5) == Some(0xe8)
            || at(9) == Some(0xe8)
            || at(2) == Some(0xff)
            || at(3) == Some(0xff)
            || at(5) == Some(0xff)
            || at(9) == Some(0xff)
    }
    if matches_at(prev, prev.len()) {
        return true;
    }
    prev.last() == Some(&b'\n') && matches_at(prev, prev.len() - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> ScanOptions {
        ScanOptions::default()
    }

    fn scan(code: &[u8], vaddr: u64, bits: u32, o: &ScanOptions) -> Vec<Gadget> {
        let mut out = Vec::new();
        scan_section(code, vaddr, bits, o, &mut out);
        out
    }

    #[test]
    fn decodes_simple_function() {
        // push ebp ; mov ebp, esp ; ret
        let g = scan(b"\x55\x89\xe5\xc3", 0x1000, 32, &opts());
        let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
        assert!(texts.contains(&"ret".to_string()), "{texts:?}");
        assert!(
            texts.contains(&"mov ebp, esp ; ret".to_string()),
            "{texts:?}"
        );
        assert!(
            texts.contains(&"push ebp ; mov ebp, esp ; ret".to_string()),
            "{texts:?}"
        );
        // vaddr of the full prologue gadget
        let full = g
            .iter()
            .find(|x| x.text() == "push ebp ; mov ebp, esp ; ret")
            .unwrap();
        assert_eq!(full.vaddr, 0x1000);
        assert_eq!(full.bytes, b"\x55\x89\xe5\xc3");
        assert_eq!(full.table, TableKind::Rop);
    }

    #[test]
    fn anchor_start_need_not_be_a_boundary() {
        // 66 0f 05 decodes as one 3-byte syscall; the SYS anchor sits at
        // offset 1, mid-instruction. ROPgadget accepts this (clean-decode
        // rule only constrains the gadget END).
        let g = scan(b"\x66\x0f\x05", 0x2000, 64, &opts());
        assert!(
            g.iter().any(|x| x.text() == "syscall" && x.vaddr == 0x2000),
            "{:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn depth_limits_gadget_length() {
        // 9 nops + ret: with depth 2 only "nop ; ret" and "ret" appear.
        let mut code = vec![0x90u8; 9];
        code.push(0xc3);
        let mut o = opts();
        o.depth = 2;
        let g = scan(&code, 0x1000, 32, &o);
        let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
        assert!(texts.contains(&"ret".to_string()));
        assert!(texts.contains(&"nop ; ret".to_string()));
        assert!(!texts.contains(&"nop ; nop ; ret".to_string()));
    }

    #[test]
    fn multibr_controls_middle_branches() {
        // call rel32 ; ret  (plus a lone ret)
        let code = b"\xe8\x00\x00\x00\x00\xc3";
        let g = scan(code, 0x1000, 32, &opts());
        assert!(
            !g.iter().any(|x| x.text().contains("call")),
            "middle call must be rejected without --multibr: {:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
        let mut o = opts();
        o.multibr = true;
        let g = scan(code, 0x1000, 32, &o);
        assert!(
            g.iter()
                .any(|x| x.text().starts_with("call") && x.text().ends_with("ret")),
            "--multibr must keep it: {:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn bnd_ret_is_rejected_like_ropgadget() {
        // f2 c3 = "bnd ret" which is NOT in ROPgadget's branch list, so the
        // MPX anchor produces no gadget ending at those bytes.
        let g = scan(b"\xf2\xc3", 0x1000, 64, &opts());
        assert!(
            g.iter().all(|x| !x.bytes.ends_with(b"\xf2\xc3")),
            "{:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
    }

    /// SCAN-02: `notrack jmp` / `notrack call` used to be normalized down to
    /// a bare `jmp` / `call`, so on a CET binary every `3e`-prefixed indirect
    /// branch — the highest-value JOP primitive there — collided in text
    /// dedup with an ordinary indirect branch and was DELETED. They must
    /// carry distinct dedup keys and both survive.
    #[test]
    fn notrack_branches_survive_dedup() {
        // jmp rax ; notrack jmp rax ; call rax ; notrack call rax
        let code = b"\xff\xe0\x3e\xff\xe0\xff\xd0\x3e\xff\xd0";
        let mut o = opts();
        o.rop = false;
        let g = post_process(scan(code, 0x1000, 64, &o), &o, 8).unwrap();
        let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
        for want in ["jmp rax", "notrack jmp rax", "call rax", "notrack call rax"] {
            assert!(
                texts.iter().any(|t| t == want),
                "{want:?} lost to a dedup collision: {texts:?}"
            );
        }
    }

    /// SCAN-03: `f3 c3` is `repz ret`, the canonical AMD return gadget —
    /// rendering it `rep ret` made it unfindable by name. ROPgadget's
    /// `--only` splits each instruction on the first space
    /// (options.py:__onlyOption), so the token to search for is `repz`.
    #[test]
    fn repz_ret_is_rendered_and_findable_with_only() {
        let g = scan(b"\x90\xf3\xc3", 0x1000, 64, &opts());
        let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
        assert!(texts.iter().any(|t| t == "repz ret"), "{texts:?}");
        let mut o = opts();
        o.only = Some(vec!["repz".to_string()]);
        let out = post_process(scan(b"\x90\xf3\xc3", 0x1000, 64, &o), &o, 8).unwrap();
        assert_eq!(
            out.iter().map(|x| x.text()).collect::<Vec<_>>(),
            vec!["repz ret".to_string()]
        );
    }

    #[test]
    fn int3_is_filtered() {
        // int3 ; ret — middle int3 rejected by the built-in db|int3 filter
        let g = scan(b"\xcc\xc3", 0x1000, 32, &opts());
        let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
        assert!(!texts.iter().any(|t| t.contains("int3")), "{texts:?}");
        assert!(texts.contains(&"ret".to_string()));
    }

    #[test]
    fn bad_decode_rejects_candidate() {
        // `ff ff` is group-5 `/7`, which neither capstone nor iced decodes;
        // no candidate may span it, so only the bare `ret` at +2 survives.
        let g = scan(b"\xff\xff\xc3", 0x1000, 64, &opts());
        assert!(
            g.iter().all(|x| x.vaddr == 0x1002),
            "{:?}",
            g.iter().map(|x| (x.vaddr, x.text())).collect::<Vec<_>>()
        );
        // `0f ff` IS decodable — capstone renders it as a two-byte `ud0`
        // with no ModRM. iced consumes three bytes for the documented
        // `ud0 r32, r/m32`, which would slide every following instruction
        // boundary and lose the gadgets the oracle finds here.
        let g = scan(b"\x0f\xff\xc3", 0x1000, 64, &opts());
        assert!(
            g.iter()
                .any(|x| x.text() == "ud0 ; ret" && x.vaddr == 0x1000),
            "{:?}",
            g.iter().map(|x| (x.vaddr, x.text())).collect::<Vec<_>>()
        );
    }

    #[test]
    fn offset_slides_vaddr_not_text() {
        let mut o = opts();
        o.offset = 0x10_0000;
        let g = scan(b"\x58\xc3", 0x1000, 32, &o);
        let pop = g.iter().find(|x| x.text() == "pop eax ; ret").unwrap();
        assert_eq!(pop.vaddr, 0x10_1000);
        let plain = scan(b"\x58\xc3", 0x1000, 32, &opts());
        let pop0 = plain.iter().find(|x| x.text() == "pop eax ; ret").unwrap();
        assert_eq!(pop0.vaddr, 0x1000);
        assert_eq!(pop.text(), pop0.text());
    }

    #[test]
    fn jop_and_sys_anchors_work() {
        // jmp rax ; (padding) ; int 0x80
        let mut o = opts();
        o.rop = false;
        let g = scan(b"\xff\xe0\x90\xcd\x80", 0x4000, 64, &o);
        let texts: Vec<String> = g.iter().map(|x| x.text()).collect();
        assert!(texts.contains(&"jmp rax".to_string()), "{texts:?}");
        assert!(texts.contains(&"int 0x80".to_string()), "{texts:?}");
        // with norop, no "ret"-ending gadgets appear
        assert!(texts.iter().all(|t| !t.ends_with("ret")), "{texts:?}");
        // table provenance is recorded
        let jmp = g.iter().find(|x| x.text() == "jmp rax").unwrap();
        assert_eq!(jmp.table, TableKind::Jop);
        let int = g.iter().find(|x| x.text() == "int 0x80").unwrap();
        assert_eq!(int.table, TableKind::Sys);
    }

    #[test]
    fn only_filter_keeps_whitelisted_mnemonics() {
        let mut o = opts();
        o.only = Some(vec!["pop".to_string(), "ret".to_string()]);
        // pop eax ; ret  |  mov eax, ebx ; ret
        let g = scan(b"\x58\xc3\x89\xd8\xc3", 0x1000, 32, &o);
        assert!(!g.is_empty());
        let out = post_process(g, &o, 4).unwrap();
        let texts: Vec<String> = out.iter().map(|x| x.text()).collect();
        assert!(texts.contains(&"pop eax ; ret".to_string()), "{texts:?}");
        // "mov eax, ebx" is not whitelisted
        assert!(!texts.iter().any(|t| t.contains("mov")), "{texts:?}");
    }

    // -- SCAN-01/CLI-02: --filter is ROPgadget's anchored full-mnemonic regex

    #[test]
    fn filter_rejects_by_full_mnemonic_match_not_suffix() {
        // pop eax ; ret
        let code = b"\x58\xc3";
        let mut o = opts();
        o.filter = vec!["op".to_string()];
        let g = scan(code, 0x1000, 32, &o);
        assert!(
            g.iter().any(|x| x.text() == "pop eax ; ret"),
            "--filter op must NOT delete `pop` (it is not a full match): {:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
        // ...while a regex that DOES fully match `pop` removes it.
        o.filter = vec!["p.p".to_string()];
        let g = scan(code, 0x1000, 32, &o);
        assert!(
            !g.iter().any(|x| x.text().contains("pop")),
            "{:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn filter_regex_matches_branch_mnemonics() {
        // jmp eax  (JOP anchor) — `--filter "j.*"` must remove it.
        let mut o = opts();
        o.filter = vec!["j.*".to_string()];
        let g = scan(b"\xff\xe0", 0x1000, 32, &o);
        assert!(
            g.is_empty(),
            "{:?}",
            g.iter().map(|x| x.text()).collect::<Vec<_>>()
        );
        let g = scan(b"\xff\xe0", 0x1000, 32, &opts());
        assert!(!g.is_empty());
    }

    // -- ANCH-01/SCAN-05/CLI-10: --align is scan-time stepping

    #[test]
    fn align_steps_the_candidate_start_rather_than_filtering_it() {
        // 16 nops then `ret` at offset 16 (vaddr 0x1010, 4-aligned).
        let mut code = vec![0x90u8; 16];
        code.push(0xc3);
        let mut o = opts();
        o.align = Some(4);
        let g = scan(&code, 0x1000, 32, &o);
        // Every gadget start must be 4-aligned...
        assert!(g.iter().all(|x| x.vaddr % 4 == 0), "{:?}", g.len());
        // ...and stepping (not filtering) reaches depth*4 = 36 bytes back,
        // so the 9-nop gadget starting at 0x1004 exists. A post-filter over
        // byte steps could only reach 0x1008.
        assert!(
            g.iter().any(|x| x.vaddr == 0x1004),
            "aligned stepping must reach ref-3*align: {:?}",
            g.iter()
                .map(|x| (format!("{:#x}", x.vaddr), x.text()))
                .collect::<Vec<_>>()
        );
        // align 0 is falsy in the oracle: same as no --align at all.
        let mut o0 = opts();
        o0.align = Some(0);
        let a = scan(&code, 0x1000, 32, &o0);
        let b = scan(&code, 0x1000, 32, &opts());
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn default_scan_is_unchanged_by_the_stepping_rewrite() {
        // x86 anchors have gad_align == 1, where stepping degenerates to
        // `ref - i` — the pre-v0.2.0 behaviour.
        for i in 0..10 {
            assert_eq!(step_back(100, i, 1, 0x1000, 200), Some(100 - i));
        }
    }

    // -- SCAN-07/CLI-03: --all disables dedup

    #[test]
    fn all_disables_dedup() {
        // Two identical `ret` gadgets at different addresses.
        let all = vec![
            gadget(0x1000, b"\xc3", &["ret"]),
            gadget(0x2000, b"\xc3", &["ret"]),
        ];
        assert_eq!(post_process(all.clone(), &opts(), 4).unwrap().len(), 1);
        let mut o = opts();
        o.all = true;
        assert_eq!(post_process(all, &o, 4).unwrap().len(), 2);
    }

    // -- CLI-04/ECO-03: --callPreceded needs `prev`

    #[test]
    fn call_preceded_captures_nine_preceding_bytes() {
        // e8 <rel32> then 3 nops then ret: PREV_BYTES = 9 (gadgets.py:57).
        let mut code = vec![0xe8, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90];
        code.push(0xc3);
        let mut o = opts();
        o.call_preceded = true;
        let g = scan(&code, 0x1000, 32, &o);
        let ret = g.iter().find(|x| x.text() == "ret").unwrap();
        assert_eq!(ret.vaddr, 0x1008);
        assert_eq!(ret.prev.as_deref(), Some(&code[..8][..]));
        assert_eq!(PREV_BYTES, 9);
        // A gadget more than 9 bytes into the section sees exactly 9.
        let mut code2 = vec![0x90u8; 20];
        code2.push(0xc3);
        let g = scan(&code2, 0x1000, 32, &o);
        let ret = g.iter().find(|x| x.text() == "ret").unwrap();
        assert_eq!(ret.prev.as_ref().unwrap().len(), 9);
        // off by default
        let g = scan(&code2, 0x1000, 32, &opts());
        assert!(g.iter().all(|x| x.prev.is_none()));
    }

    fn gadget(vaddr: u64, bytes: &[u8], insns: &[&str]) -> Gadget {
        Gadget {
            vaddr,
            bytes: bytes.to_vec(),
            insns: insns.iter().map(|s| s.to_string()).collect(),
            delay_slot: false,
            prev: None,
            table: TableKind::Rop,
        }
    }

    fn gadget_of(vaddr: u64, bytes: &[u8], insns: &[&str], table: TableKind) -> Gadget {
        let mut g = gadget(vaddr, bytes, insns);
        g.table = table;
        g
    }

    #[test]
    fn dedup_keeps_first_occurrence_in_traversal_order() {
        // Same text at two vaddrs: the first in traversal order survives.
        let all = vec![
            gadget(0x2000, b"\x89\xc0\xc3", &["mov eax, eax", "ret"]),
            gadget(0x1000, b"\x8b\xc0\xc3", &["mov eax, eax", "ret"]),
            gadget(0x3000, b"\xc3", &["ret"]),
        ];
        let out = post_process(all, &opts(), 4).unwrap();
        assert_eq!(out.len(), 2);
        let m = out
            .iter()
            .find(|g| g.text() == "mov eax, eax ; ret")
            .unwrap();
        assert_eq!(m.vaddr, 0x2000, "first occurrence must win");
        assert_eq!(m.bytes, b"\x89\xc0\xc3");
        // sorted alphabetically: "mov..." < "ret"
        assert_eq!(out[0].text(), "mov eax, eax ; ret");
        assert_eq!(out[1].text(), "ret");
    }

    #[test]
    fn badbytes_rejects_packed_le_address() {
        // Distinct texts so both survive dedup (dedup runs before badbytes,
        // exactly like ROPgadget's Options pass).
        let all = vec![
            gadget(0x100a, b"\xc3", &["ret"]),
            gadget(0x100b, b"\xcb", &["retf"]),
        ];
        let mut o = opts();
        o.badbytes = vec![0x0a];
        let out = post_process(all.clone(), &o, 4).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].vaddr, 0x100b);
        // 64-bit packing checks all 8 LE bytes; 0x10 rejects both.
        o.badbytes = vec![0x10];
        assert!(post_process(all, &o, 8).unwrap().is_empty());
    }

    /// SCAN-10: `--range` is re-applied to the final (offset-shifted)
    /// addresses, inclusively, exactly as `options.py:__rangeOption` does.
    #[test]
    fn range_is_reapplied_to_final_addresses() {
        let all = vec![
            gadget(0x1000, b"\xc3", &["ret"]),
            gadget(0x2000, b"\xcb", &["retf"]),
            gadget(0x3000, b"\x90\xc3", &["nop", "ret"]),
        ];
        let mut o = opts();
        o.range = Some((0x2000, 0x3000));
        let out = post_process(all.clone(), &o, 4).unwrap();
        let addrs: Vec<u64> = out.iter().map(|g| g.vaddr).collect();
        assert_eq!(addrs.len(), 2, "{addrs:?}");
        assert!(
            addrs.contains(&0x2000) && addrs.contains(&0x3000),
            "{addrs:?}"
        );
        // "0x0-0x0" is the oracle's "no range" sentinel.
        o.range = Some((0, 0));
        assert_eq!(post_process(all, &o, 4).unwrap().len(), 3);
    }

    /// CRIT-01: the flag used to return zero on every binary because it
    /// demanded an endbr entry on ROP gadgets, which are reached by `ret`
    /// and never have one.
    #[test]
    fn cfg_aware_is_table_aware() {
        let all = vec![
            gadget_of(
                0x1000,
                b"\xf3\x0f\x1e\xfa\xff\xe0",
                &["endbr64", "jmp rax"],
                TableKind::Jop,
            ),
            gadget_of(0x1010, b"\xff\xe0", &["jmp rax"], TableKind::Jop),
            gadget_of(0x1020, b"\x59\xc3", &["pop rcx", "ret"], TableKind::Rop),
            gadget_of(
                0x1030,
                b"\xf3\x0f\x1e\xfa\x0f\x05",
                &["endbr64", "syscall"],
                TableKind::Sys,
            ),
            gadget_of(0x1040, b"\x0f\x05", &["syscall"], TableKind::Sys),
        ];
        let mut o = opts();
        o.cfg_aware = true;
        let out = post_process(all.clone(), &o, 8).unwrap();
        let texts: Vec<String> = out.iter().map(|g| g.text()).collect();
        assert_eq!(out.len(), 3, "{texts:?}");
        // The endbr-preceded indirect targets survive...
        assert!(
            texts.contains(&"endbr64 ; jmp rax".to_string()),
            "{texts:?}"
        );
        assert!(
            texts.contains(&"endbr64 ; syscall".to_string()),
            "{texts:?}"
        );
        // ...the bare indirect targets do not...
        assert!(!texts.contains(&"jmp rax".to_string()), "{texts:?}");
        assert!(!texts.contains(&"syscall".to_string()), "{texts:?}");
        // ...and the ROP gadget is kept: IBT does not check returns.
        assert!(texts.contains(&"pop rcx ; ret".to_string()), "{texts:?}");
        // off by default
        assert_eq!(post_process(all, &opts(), 8).unwrap().len(), 5);
    }

    #[test]
    fn range_truncates_sections() {
        let sec = rf_core::Section {
            name: ".text".into(),
            vaddr: 0x1000,
            offset: 0x200,
            size: 8,
            bytes: vec![1, 2, 3, 4, 5, 6, 7, 8],
            executable: true,
            writable: false,
            allocated: true,
        };
        let (bytes, vaddr) = apply_range(&sec, Some((0x1002, 0x1006))).unwrap();
        assert_eq!(vaddr, 0x1002);
        assert_eq!(bytes, vec![3, 4, 5, 6]);
        assert!(apply_range(&sec, Some((0x2000, 0x3000))).is_none());
        assert!(apply_range(&sec, Some((0x0, 0x0))).is_none());
    }

    fn fixture_bytes(name: &str) -> Vec<u8> {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/");
        std::fs::read(format!("{path}{name}")).unwrap()
    }

    #[test]
    fn scans_real_fixture() {
        let bytes = fixture_bytes("elf-Linux-x64");
        let bin = rf_core::Binary::parse(&bytes).unwrap();
        let g = scan_binary(&bin, &opts()).unwrap();
        assert!(
            g.len() > 1000,
            "expected thousands of gadgets, got {}",
            g.len()
        );
        assert!(g.iter().any(|x| x.text() == "ret"));
        // every gadget vaddr lies inside some scanned exec region
        let exec = bin.exec_scan_regions();
        for x in &g {
            assert!(
                exec.iter()
                    .any(|s| s.vaddr <= x.vaddr && x.vaddr < s.vaddr + s.size),
                "gadget {:#x} outside exec sections",
                x.vaddr
            );
        }
        // property test (PLAN §4): every gadget's bytes re-disassemble to
        // exactly its instruction list
        let mut fmt = crate::x86::make_formatter();
        for x in g.iter().step_by(97) {
            let retexts =
                crate::x86::format_gadget(&x.bytes, 0, x.bytes.len(), x.vaddr, 64, &mut fmt);
            assert_eq!(
                retexts, x.insns,
                "gadget {:#x} bytes do not re-decode",
                x.vaddr
            );
        }
    }

    /// Parallel and serial scans must produce byte-identical output
    /// (deterministic text-dedup survivor) on real fixtures — x64 (iced-x86
    /// path) and ARM64 (capstone path).
    #[test]
    fn parallel_matches_serial_on_real_fixtures() {
        for fixture in ["elf-Linux-x64", "elf-ARM64-bash"] {
            let bytes = fixture_bytes(fixture);
            let bin = rf_core::Binary::parse(&bytes).unwrap();
            let mut serial_opts = opts();
            serial_opts.parallel = false;
            let serial = scan_binary(&bin, &serial_opts).unwrap();
            let parallel = scan_binary(&bin, &opts()).unwrap();
            assert!(!serial.is_empty(), "{fixture}: no gadgets");
            let key = |g: &Gadget| (g.vaddr, g.bytes.clone(), g.text());
            let s: Vec<_> = serial.iter().map(key).collect();
            let p: Vec<_> = parallel.iter().map(key).collect();
            assert_eq!(s, p, "{fixture}: parallel output differs from serial");
        }
    }

    /// Multi-arch smoke test: the capstone path scans real non-x86 fixtures
    /// and finds gadgets of the expected anchor families.
    #[test]
    fn scans_non_x86_real_fixtures() {
        let cases: &[(&str, &str)] = &[
            ("elf-ARM64-bash", "ret"),
            ("elf-ARMv7-ls", "bx"),
            ("elf-Mips-Defcon-20-pwn100", "jr"),
            ("elf-PowerPC-bash", "blr"),
            ("elf-SparcV8-bash", "retl"),
        ];
        for (name, want_mnem) in cases {
            let bytes = fixture_bytes(name);
            let bin = rf_core::Binary::parse(&bytes).unwrap();
            let mut o = opts();
            o.parallel = false; // keep test output deterministic to debug
            let g = scan_binary(&bin, &o).unwrap();
            assert!(
                g.iter().any(|x| x.text().contains(want_mnem)),
                "{name}: no gadget containing {want_mnem:?} in {} gadgets",
                g.len()
            );
            // Every gadget vaddr lies inside a scanned exec region.
            let exec = bin.exec_scan_regions();
            for x in &g {
                assert!(
                    exec.iter()
                        .any(|s| s.vaddr <= x.vaddr && x.vaddr < s.vaddr + s.size),
                    "{name}: gadget {:#x} outside exec regions",
                    x.vaddr
                );
            }
        }
    }

    /// RISC-V fixtures exercise the compressed-instruction size rule on real
    /// code; also validates the RV32 (ELFCLASS32) capstone mode override.
    #[test]
    fn scans_riscv_real_fixtures() {
        for name in ["elf-Linux-RISCV_32", "elf-Linux-RISCV_64"] {
            let bytes = fixture_bytes(name);
            let bin = rf_core::Binary::parse(&bytes).unwrap();
            let mut o = opts();
            o.parallel = false;
            let g = scan_binary(&bin, &o).unwrap();
            assert!(!g.is_empty(), "{name}: no gadgets found");
        }
    }

    // -- cancellation and budget (PERF-05)

    /// The cancellable entry point must abandon the scan when the token is set
    /// from another thread mid-scan.
    ///
    /// The property is asserted STRUCTURALLY, not on a stopwatch, in two parts:
    ///
    ///  * `scan_binary_into` ITSELF returns `Err(Cancelled)` — not merely the
    ///    chained `post_process`, which would also "catch" a token the scan
    ///    had ignored entirely;
    ///  * the cancelled run collected strictly FEWER raw gadgets than the same
    ///    scan run to completion on this machine, right now. So the token
    ///    really did abandon work, rather than being reported after the whole
    ///    scan had already happened. The comparison run is what makes this
    ///    load-independent; no absolute gadget count is hardcoded.
    ///
    /// Verified to be a real gate by disabling all seven cancellation
    /// observation sites on the scan path, which turns the first assertion
    /// red. Disabling only the three in-loop `is_cancelled()` checks does not:
    /// the per-section `cancel.check()?` calls then abandon the remaining
    /// sections, which is still early exit and still correct behaviour.
    ///
    /// It previously required the return to land within 200 ms of the flag
    /// being set. That was a flake generator: `cargo test` runs the crate's
    /// test binaries concurrently, and on a saturated machine the observing
    /// thread is descheduled for longer than the window — measured here at
    /// 366 ms on an engine that had in fact stopped immediately, while the
    /// same test passes in 0.02 s when run alone. The clock now only guards
    /// against a genuine hang.
    #[test]
    fn scan_stops_on_token() {
        let bytes = fixture_bytes("elf-x64-bash-v4.1.5.1");
        let bin = rf_core::Binary::parse(&bytes).unwrap();
        let mut o = opts();
        o.cancel = CancelToken::new();
        let token = o.cancel.clone();
        let started = std::time::Instant::now();
        let flip = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            token.cancel();
        });
        let mut sink = VecSink::new();
        let scanned = scan_binary_into(&bin, &o, &mut sink);
        let elapsed = started.elapsed();
        let scan_was_cancelled = scanned == Err(Error::Cancelled);
        let collected = sink.into_inner();
        let stopped_early = collected.len();
        let chained = match scanned {
            Err(e) => Err(e),
            Ok(()) => post_process(collected, &o, 8).map(|_| ()),
        };
        flip.join().unwrap();

        // The same scan run to completion, on this machine, right now.
        let mut full_sink = VecSink::new();
        scan_binary_into(&bin, &opts(), &mut full_sink).expect("uncancelled scan");
        let full = full_sink.into_inner().len();

        assert!(
            scan_was_cancelled,
            "scan_binary_into must itself return Cancelled, not leave it to post_process"
        );
        assert_eq!(chained, Err(Error::Cancelled), "expected a cancelled scan");
        assert!(
            stopped_early < full,
            "the scan ran to completion anyway: collected {stopped_early} of {full} raw              gadgets, so cancellation did not actually abandon any work"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "the scan did not return at all ({elapsed:?}); this is a hang, not a latency check"
        );
    }

    #[test]
    fn budget_stops_the_scan() {
        let bytes = fixture_bytes("elf-Linux-x64");
        let bin = rf_core::Binary::parse(&bytes).unwrap();
        let mut o = opts();
        o.max_gadgets = Some(50);
        let r = scan_bounded(&bin, &o);
        assert!(
            matches!(r, Err(Error::Budget { limit: 50, .. })),
            "{:?}",
            r.map(|g| g.len())
        );
        // ...and the unbounded delegate is unaffected.
        assert!(scan_binary(&bin, &o).unwrap().len() > 50);
    }

    #[test]
    fn bounded_sink_matches_unbounded_when_the_budget_is_generous() {
        let bytes = fixture_bytes("elf-Linux-x86");
        let bin = rf_core::Binary::parse(&bytes).unwrap();
        let plain = scan_binary(&bin, &opts()).unwrap();
        let mut o = opts();
        o.max_gadgets = Some(10_000_000);
        o.max_memory = Some(4 << 30);
        let bounded = scan_bounded(&bin, &o).unwrap();
        let key = |g: &Gadget| (g.vaddr, g.bytes.clone(), g.text());
        assert_eq!(
            plain.iter().map(key).collect::<Vec<_>>(),
            bounded.iter().map(key).collect::<Vec<_>>()
        );
    }

    /// CRIT-01's warning half: the flag is meaningless on a binary with no
    /// IBT landing pads, and the caller needs to be able to say so.
    #[test]
    fn ibt_applicability_is_reported() {
        let bytes = fixture_bytes("elf-Linux-x86");
        let bin = rf_core::Binary::parse(&bytes).unwrap();
        // A 2013-era 32-bit binary predates CET entirely.
        assert!(!ibt_applicable(&bin));
        let bytes = fixture_bytes("elf-ARM64-bash");
        let bin = rf_core::Binary::parse(&bytes).unwrap();
        assert!(!ibt_applicable(&bin), "non-x86 is never IBT-applicable");
    }
}
