//! CRIT-03 — the response contract, as real Rust types.
//!
//! Before this module the MCP server's responses were `serde_json::json!`
//! literals. Three consequences, all of them things an agent handles badly:
//!
//! * **No `outputSchema`.** Not one tool in `tools/list` declared one, so a
//!   client had no machine-readable description of what came back.
//! * **A variable shape.** `section` was serialized only when the `section`
//!   parameter had been passed and `arch` only for a fat Mach-O, because the
//!   shared cache record skips those fields when empty. A parser written
//!   against one response broke on the next.
//! * **Dropped facts.** `rf_scan` computes `delay_slot` — on MIPS and SPARC
//!   the last instruction of a gadget executes *before* the branch, which
//!   changes what the gadget does — and every output boundary threw it away.
//!
//! Everything here is `Serialize + Deserialize + JsonSchema` with
//! `#[serde(deny_unknown_fields)]`, which is what makes schemars emit
//! `additionalProperties: false`, which in turn is what lets
//! `tests/schema_conformance.rs` fail on an *added* field as well as a
//! missing one. Optional fields are `Option<T>` and are **always present**,
//! `null` when unknown: there is not one `skip_serializing_if` in this file,
//! and there must never be one.

use std::sync::Arc;

use rmcp::model::JsonObject;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// The closed set of error codes the server can return (CRIT-03 item 5).
///
/// It was open before: `usage` was returned from one place and `usage_error`
/// from every other, `invalid_flag` / `binary_error` / `chain_error` /
/// `file_too_large` / `busy` / `timeout_hard` were each invented at their
/// call site, and nothing enumerated them. An agent cannot branch on a set
/// it cannot enumerate.
///
/// The finer-grained reason survives in two places that are *not* the wire
/// contract: [`ToolError::kind`](crate::ToolError::kind), which is what the
/// audit log records, and `details`, which carries the breached limit. So
/// collapsing `file_too_large` into `resource_exhausted` loses no
/// information an operator had — `details.limit` still says
/// `"max_file_bytes"` and the audit line still says `file_too_large`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// `binary_path` is not inside an allow root, or could not be opened as
    /// a regular file there. Deliberately indistinguishable from "absent"
    /// (MCP-07).
    PathDenied,
    /// The request is malformed: a bad value, an unknown enum member, a
    /// depth above `max_depth`, a flag outside the allowlist.
    UsageError,
    /// The file is not a binary this tool can analyse, or the analysis of it
    /// failed.
    UnsupportedBinary,
    /// A bound was hit: `max_file_bytes`, the engine's `max_gadgets` budget,
    /// or every concurrent scan slot. `details.limit` names which.
    ResourceExhausted,
    /// The request exceeded `timeout_secs` and the work was stopped.
    Timeout,
    /// The client sent `notifications/cancelled` and the work stopped.
    Cancelled,
    /// The cursor does not describe this query, or the scan it paged has
    /// been evicted. Always `retryable`, with a suggestion that clears it.
    CursorExpired,
    /// The thing asked for is not in this binary: a chain needs a gadget it
    /// does not have, an id does not resolve.
    NotFound,
    /// A bug in the server.
    Internal,
}

impl ErrorCode {
    /// The wire spelling, which is also the serialized form.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::PathDenied => "path_denied",
            ErrorCode::UsageError => "usage_error",
            ErrorCode::UnsupportedBinary => "unsupported_binary",
            ErrorCode::ResourceExhausted => "resource_exhausted",
            ErrorCode::Timeout => "timeout",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::CursorExpired => "cursor_expired",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Internal => "internal",
        }
    }

    /// Every code, for the documentation generator and the tests.
    #[must_use]
    pub fn all() -> &'static [ErrorCode] {
        &[
            ErrorCode::PathDenied,
            ErrorCode::UsageError,
            ErrorCode::UnsupportedBinary,
            ErrorCode::ResourceExhausted,
            ErrorCode::Timeout,
            ErrorCode::Cancelled,
            ErrorCode::CursorExpired,
            ErrorCode::NotFound,
            ErrorCode::Internal,
        ]
    }

    /// Whether re-sending the *same* request could plausibly succeed.
    ///
    /// `timeout` and a busy server are transient. A denied path, a bad
    /// parameter or a binary this tool cannot read are not: retrying is
    /// wasted work and, for `path_denied`, is exactly the probing behaviour
    /// MCP-09 counts. `resource_exhausted` is the ambiguous one — it is
    /// `false` here and set to `true` explicitly by the one site (the
    /// concurrency bound) where waiting helps.
    #[must_use]
    pub fn default_retryable(self) -> bool {
        matches!(self, ErrorCode::Timeout | ErrorCode::CursorExpired)
    }
}

// ---------------------------------------------------------------------------
// Warnings
// ---------------------------------------------------------------------------

/// A non-fatal fact the agent has to know to read the result correctly
/// (CRIT-03 item 4).
///
/// `fallback_section_names` used to be a bare boolean with no explanation,
/// and truncation was announced nowhere at all. Every entry has a stable
/// `code` to branch on and a `message` to show a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Warning {
    /// Stable machine-readable tag: `low_confidence_classification`,
    /// `fallback_section_names`, `universal_slice_selected`, `truncated`,
    /// `sections_truncated`, `imports_truncated`, `ids_not_found`,
    /// `unmapped_info_fields`.
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Free-form detail (the slice name, the architecture, …).
    pub detail: Option<String>,
    /// The response field the warning is about, when it is about one.
    pub field: Option<String>,
    /// Entries returned in that field.
    pub returned: Option<u64>,
    /// Entries that exist.
    pub total: Option<u64>,
}

impl Warning {
    #[must_use]
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Warning {
            code: code.to_string(),
            message: message.into(),
            detail: None,
            field: None,
            returned: None,
            total: None,
        }
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    #[must_use]
    pub fn truncation(code: &str, field: &str, returned: usize, total: usize) -> Self {
        Warning {
            code: code.to_string(),
            message: format!("{field} truncated to {returned} of {total} entries"),
            detail: None,
            field: Some(field.to_string()),
            returned: Some(returned as u64),
            total: Some(total as u64),
        }
    }
}

// ---------------------------------------------------------------------------
// Gadget records
// ---------------------------------------------------------------------------

/// One gadget, in the shape every gadget-returning tool emits.
///
/// Invariant: the field set does not depend on the request. A gadget from a
/// scan with no `section` parameter carries `"section": null`, not a missing
/// key; an x86-64 ELF carries `"arch": null` and `"delay_slot": false`, not
/// nothing at all. `tests/schema_conformance.rs` asserts the four shapes
/// that used to differ — plain, `section=.text`, MIPS, and the fat Mach-O —
/// have identical key sets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GadgetRecord {
    /// Stable identity: `g_` + base32 of the first 10 bytes of
    /// `blake3(binary_sha256 || vaddr_le || bytes)`. Independent of every
    /// scan parameter, so the same gadget has the same id across calls,
    /// processes and cache evictions. Pass a list of these to
    /// `get_gadgets`.
    pub id: String,
    /// Zero-padded hex address, for humans. The padding width is 8 on a
    /// 32-bit target and 16 on a 64-bit one, which is why `vaddr_u64`
    /// exists.
    pub vaddr: String,
    /// The same address as a number. Agents doing arithmetic should use
    /// this and never parse `vaddr`.
    pub vaddr_u64: u64,
    /// Gadget bytes, lowercase hex.
    pub bytes: String,
    /// `insns.join(" ; ")`.
    pub text: String,
    /// The instructions, already split.
    pub insns: Vec<String>,
    /// Fat Mach-O slice this gadget came from; `null` for every other
    /// container.
    pub arch: Option<String>,
    /// Section containing the gadget; `null` when no `section` filter was
    /// applied (the scan then has no section table to consult).
    pub section: Option<String>,
    /// MIPS/SPARC: the LAST instruction is the branch's delay slot, so it
    /// executes **before** control transfers. `rf_scan` has always computed
    /// this and every output boundary dropped it.
    pub delay_slot: bool,
    /// Primary class (`reg-write`, `stack-pivot`, `mem-read`, `mem-write`,
    /// `arithmetic`, `syscall`, `dispatcher`, `other`); `null` when the
    /// architecture has no classifier.
    pub class: Option<String>,
    /// Every class the gadget earns, not just the primary one.
    pub labels: Vec<String>,
    /// Registers the gadget writes, lowercase and sigil-free.
    pub regs_written: Vec<String>,
    /// Registers the gadget reads.
    pub regs_read: Vec<String>,
    /// The subset of `regs_written` loaded off the stack — the registers a
    /// chain payload can actually control.
    pub regs_from_stack: Vec<String>,
    /// Instructions that earn at least one label.
    pub side_effects: u32,
    /// Net change to the stack pointer. **Always `null` in v0.3**: the
    /// computation is ECO-07/CLS-09 and lands in v0.4. The field is here
    /// now so the record shape does not change when it does.
    pub stack_delta: Option<i64>,
    /// TAXONOMY.md R12 quality score, higher is cleaner.
    pub quality: i32,
    /// Usability tier 0..=3 — the primary key of the default `rank` order.
    /// 3 = bare return plus a stack-loaded register; 2 = bare return;
    /// 1 = needs a dispatcher or a stack fix-up, or nothing was identified;
    /// 0 = privileged, or pure control flow.
    pub usability: u8,
    /// How the gadget hands control on: `ret`, `ret-imm`, `retf`, `iret`,
    /// `far`, `jmp`, `call`, `syscall`, `none`.
    pub terminator: String,
    /// JOP/COP dispatcher heuristic.
    pub dispatcher: bool,
    /// Contains a privileged or undefined instruction, so it faults in user
    /// mode and cannot appear in a chain.
    pub privileged: bool,
    /// The classification came from disassembly text rather than decoder
    /// metadata, so treat the semantic fields as advisory.
    pub low_confidence: bool,
}

impl GadgetRecord {
    /// Assemble the wire record from the cached gadget and its semantics.
    ///
    /// The two halves are index-aligned by construction: `sems[i]` is
    /// derived from `scan.gadgets[i]` in
    /// [`crate::semantics::classify_scan`]. Everything the classifier
    /// computed rides along, which is CLS-08's whole point — it used to be
    /// discarded except for `quality` and `class`.
    #[must_use]
    pub fn build(g: &rf_cache::CachedGadget, s: &crate::semantics::Semantics) -> GadgetRecord {
        GadgetRecord {
            id: s.id.clone(),
            vaddr: g.vaddr.clone(),
            vaddr_u64: s.vaddr,
            bytes: g.bytes.clone(),
            text: g.text.clone(),
            insns: s.insns.clone(),
            arch: g.arch.clone(),
            section: g.section.clone(),
            delay_slot: s.delay_slot,
            class: s.primary().map(str::to_string),
            labels: s.labels().iter().map(|l| (*l).to_string()).collect(),
            regs_written: s.regs_written().to_vec(),
            regs_read: s.regs_read().to_vec(),
            regs_from_stack: s.regs_from_stack().to_vec(),
            side_effects: s.side_effects(),
            // ECO-07/CLS-09, v0.4. The field exists now so the record's
            // shape does not change when the computation lands.
            stack_delta: None,
            quality: s.quality(),
            usability: s.rank.usability,
            terminator: s.terminator().to_string(),
            dispatcher: s.dispatcher(),
            privileged: s.privileged(),
            low_confidence: s.low_confidence(),
        }
    }
}

/// The response of every gadget-returning tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanResponse {
    pub gadgets: Vec<GadgetRecord>,
    /// Gadgets matching the query, before paging.
    pub total_count: u64,
    /// Gadgets in this page.
    pub returned: u64,
    /// Index of this page's first gadget within the ordered result.
    pub offset: u64,
    /// `total_count > offset + returned`.
    pub truncated: bool,
    /// Opaque token for the next page; `null` on the last one. Send it back
    /// as `cursor` with the SAME query parameters.
    pub next_cursor: Option<String>,
    /// The order actually applied: `rank`, `address`, `quality`, `text` or
    /// `ids`. Echoed because the default changed to `rank` and an agent
    /// must not have to assume.
    pub order: String,
    /// SHA-256 of the analysed file.
    pub binary_sha256: String,
    /// The binary's path relative to its allow root — what the audit log
    /// records, and never the caller's spelling of the path.
    pub binary_label: String,
    /// `hit` when the gadget set came from a cache (in memory, pinned for
    /// a cursor, or authenticated from disk), `miss` when it was scanned.
    pub cache: String,
    /// Key of the cached scan; the second path component of `resource_uri`.
    pub cache_key: String,
    /// The binary has no section names and synthetic `PT_LOAD#n` names were
    /// matched instead. Also reported in `warnings`.
    pub fallback_section_names: bool,
    /// Non-fatal facts. Always present; `[]` when there are none.
    pub warnings: Vec<Warning>,
    /// `ropfinder://scan/<cache_key>/gadgets.ndjson` — the WHOLE ordered
    /// result, one `GadgetRecord` per line, readable with `resources/read`.
    /// Present only when the result was paged.
    pub resource_uri: Option<String>,
    /// The same NDJSON as a real file, when the server was started with
    /// `--workspace-dir`. An agent with filesystem tools should grep this
    /// instead of paging.
    pub workspace_file: Option<String>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A patch an agent can apply to its own arguments to make the call work.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Suggestion {
    /// Merge these into the arguments and retry. A `null` value means
    /// "remove this argument".
    pub arguments_patch: Value,
}

/// The body of a failed tool call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolErrorBody {
    pub code: ErrorCode,
    pub message: String,
    /// Whether re-sending the same request could succeed.
    pub retryable: bool,
    /// Machine-readable specifics — the breached limit, the allow roots.
    /// Always an object; `{}` when there are none. Never carries an OS
    /// error string for a path outside the allowlist.
    pub details: Value,
    pub suggestion: Option<Suggestion>,
}

/// What `structuredContent` holds when `isError` is true.
///
/// This is deliberately NOT a tool's declared `outputSchema`: per the MCP
/// specification an `outputSchema` describes a *successful* result. The
/// shape is fixed all the same, and `tests/schema_conformance.rs` validates
/// every error body against [`error_output_schema`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    pub error: ToolErrorBody,
}

// ---------------------------------------------------------------------------
// get_binary_info
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SectionRecord {
    pub name: String,
    pub vaddr: String,
    pub size: u64,
    pub executable: bool,
    pub writable: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImportRecord {
    pub dll: String,
    pub symbol: String,
    /// CHWIN-03: the IAT slot the loader patches. Dereference this.
    pub iat_vaddr: String,
    /// The `IMAGE_IMPORT_BY_NAME` record holding the name string.
    pub hint_name_vaddr: String,
}

/// One slice of a fat (Universal) Mach-O.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SliceRecord {
    pub format: String,
    pub arch: Option<String>,
    pub endianness: Option<String>,
    pub addr_size: Option<u32>,
    pub image_base: Option<String>,
    pub entry: Option<String>,
    pub sections: Vec<SectionRecord>,
    pub imports: Vec<ImportRecord>,
    /// The name `--arch` / the `arch` parameter accepts for this slice.
    pub slice: Option<String>,
    pub slice_offset: Option<String>,
    pub slice_size: Option<u64>,
}

/// `get_binary_info`. Fixed shape across every container format: an ELF
/// carries `"slices": []`, a fat Mach-O carries `"sections": []`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InfoResponse {
    /// `elf`, `pe`, `macho`, `raw` or `universal`.
    pub format: String,
    pub arch: Option<String>,
    pub endianness: Option<String>,
    pub addr_size: Option<u32>,
    pub image_base: Option<String>,
    pub entry: Option<String>,
    pub sections: Vec<SectionRecord>,
    pub imports: Vec<ImportRecord>,
    /// Fat Mach-O only.
    pub fat64: Option<bool>,
    /// Fat Mach-O only: the scan tools refuse this binary without `arch`.
    pub arch_selection_required: Option<bool>,
    pub slices: Vec<SliceRecord>,
    pub binary_sha256: String,
    pub warnings: Vec<Warning>,
}

/// Pull a known key out of an object, so whatever is LEFT is by definition
/// a field this crate does not model.
fn take(o: &mut serde_json::Map<String, Value>, key: &str) -> Option<Value> {
    o.remove(key)
}

fn as_str(v: Option<Value>) -> Option<String> {
    v.and_then(|v| v.as_str().map(str::to_string))
}

fn as_u64(v: Option<Value>) -> Option<u64> {
    v.and_then(|v| v.as_u64())
}

fn as_bool(v: Option<Value>) -> Option<bool> {
    v.and_then(|v| v.as_bool())
}

fn as_array(v: Option<Value>) -> Vec<Value> {
    match v {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    }
}

impl SectionRecord {
    fn from_value(v: Value) -> Option<SectionRecord> {
        let mut o = match v {
            Value::Object(o) => o,
            _ => return None,
        };
        Some(SectionRecord {
            name: as_str(take(&mut o, "name")).unwrap_or_default(),
            vaddr: as_str(take(&mut o, "vaddr")).unwrap_or_default(),
            size: as_u64(take(&mut o, "size")).unwrap_or(0),
            executable: as_bool(take(&mut o, "executable")).unwrap_or(false),
            writable: as_bool(take(&mut o, "writable")).unwrap_or(false),
        })
    }
}

impl ImportRecord {
    fn from_value(v: Value) -> Option<ImportRecord> {
        let mut o = match v {
            Value::Object(o) => o,
            _ => return None,
        };
        Some(ImportRecord {
            dll: as_str(take(&mut o, "dll")).unwrap_or_default(),
            symbol: as_str(take(&mut o, "symbol")).unwrap_or_default(),
            iat_vaddr: as_str(take(&mut o, "iat_vaddr")).unwrap_or_default(),
            hint_name_vaddr: as_str(take(&mut o, "hint_name_vaddr")).unwrap_or_default(),
        })
    }
}

impl SliceRecord {
    fn from_value(v: Value) -> Option<SliceRecord> {
        let mut o = match v {
            Value::Object(o) => o,
            _ => return None,
        };
        Some(SliceRecord {
            format: as_str(take(&mut o, "format")).unwrap_or_default(),
            arch: as_str(take(&mut o, "arch")),
            endianness: as_str(take(&mut o, "endianness")),
            addr_size: as_u64(take(&mut o, "addr_size")).map(|n| n as u32),
            image_base: as_str(take(&mut o, "image_base")),
            entry: as_str(take(&mut o, "entry")),
            sections: as_array(take(&mut o, "sections"))
                .into_iter()
                .filter_map(SectionRecord::from_value)
                .collect(),
            imports: as_array(take(&mut o, "imports"))
                .into_iter()
                .filter_map(ImportRecord::from_value)
                .collect(),
            slice: as_str(take(&mut o, "slice")),
            slice_offset: as_str(take(&mut o, "slice_offset")),
            slice_size: as_u64(take(&mut o, "slice_size")),
        })
    }
}

impl InfoResponse {
    /// Map `rf_cli::info_bytes`' free-form payload onto the fixed shape.
    ///
    /// Anything the payload carries that is not modelled here is reported
    /// as an `unmapped_info_fields` warning rather than silently dropped,
    /// and `tests/schema_conformance.rs` asserts that warning never fires
    /// on any of the 24 fixtures. That is what makes the contract unable to
    /// drift when rf-cli grows a field: the response degrades visibly in
    /// production and fails loudly in CI, instead of quietly losing data.
    #[must_use]
    pub fn from_value(v: Value, binary_sha256: String, mut warnings: Vec<Warning>) -> InfoResponse {
        let mut o = match v {
            Value::Object(o) => o,
            other => {
                warnings.push(
                    Warning::new(
                        "unmapped_info_fields",
                        "the binary description was not an object",
                    )
                    .with_detail(other.to_string()),
                );
                serde_json::Map::new()
            }
        };
        let out = InfoResponse {
            format: as_str(take(&mut o, "format")).unwrap_or_default(),
            arch: as_str(take(&mut o, "arch")),
            endianness: as_str(take(&mut o, "endianness")),
            addr_size: as_u64(take(&mut o, "addr_size")).map(|n| n as u32),
            image_base: as_str(take(&mut o, "image_base")),
            entry: as_str(take(&mut o, "entry")),
            sections: as_array(take(&mut o, "sections"))
                .into_iter()
                .filter_map(SectionRecord::from_value)
                .collect(),
            imports: as_array(take(&mut o, "imports"))
                .into_iter()
                .filter_map(ImportRecord::from_value)
                .collect(),
            fat64: as_bool(take(&mut o, "fat64")),
            arch_selection_required: as_bool(take(&mut o, "arch_selection_required")),
            slices: as_array(take(&mut o, "slices"))
                .into_iter()
                .filter_map(SliceRecord::from_value)
                .collect(),
            binary_sha256,
            warnings: Vec::new(),
        };
        if !o.is_empty() {
            let names: Vec<&str> = o.keys().map(String::as_str).collect();
            warnings.push(
                Warning::new(
                    "unmapped_info_fields",
                    "this build of the server does not model every field the binary parser \
                     produced; they are omitted from this response",
                )
                .with_detail(names.join(",")),
            );
        }
        InfoResponse { warnings, ..out }
    }
}

// ---------------------------------------------------------------------------
// build_rop_chain
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChainWordRecord {
    /// Hex, so a 64-bit word survives a JSON parser with 53-bit numbers.
    pub value: String,
    /// `gadget_addr`, `immediate`, `data_addr`, `code_addr` or `padding`.
    pub kind: String,
    pub comment: String,
    /// Index into `chain.gadgets` for a `gadget_addr` word; `null`
    /// otherwise. It used to be omitted rather than null.
    pub source_gadget: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChainGadgetRef {
    pub vaddr: String,
    pub vaddr_u64: u64,
    pub text: String,
    /// The same stable id `find_gadgets` returns, so an agent can look the
    /// gadget up with `get_gadgets`. `null` when the chain's scan no longer
    /// holds the gadget's bytes.
    pub id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChainIr {
    pub arch: String,
    pub description: String,
    pub script_comment: String,
    pub word_size: u64,
    pub words: Vec<ChainWordRecord>,
    pub gadgets: Vec<ChainGadgetRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChainResponse {
    pub chain: ChainIr,
    /// The equivalent python exploit script.
    pub python: String,
    pub arch: String,
    pub description: String,
    pub word_count: u64,
    pub binary_sha256: String,
    pub binary_label: String,
    pub warnings: Vec<Warning>,
}

// ---------------------------------------------------------------------------
// get_server_config / get_server_stats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigResponse {
    /// The only directories `binary_path` may name.
    pub allow_roots: Vec<String>,
    pub max_depth: u64,
    pub max_file_bytes: u64,
    pub max_results: u64,
    pub hard_max_results: u64,
    pub max_concurrent: u64,
    pub scan_threads: u64,
    pub max_gadgets: Option<u64>,
    pub max_sections: u64,
    pub max_imports: u64,
    pub timeout_secs: u64,
    pub cache: bool,
    pub cache_mem_max_bytes: u64,
    pub cache_ttl_secs: u64,
    pub cursor_ttl_secs: u64,
    pub workspace_dir: Option<String>,
    pub audit_log: bool,
    pub probe_threshold: u64,
    /// Every value `order` accepts.
    pub orders: Vec<String>,
    /// Every code an error can carry.
    pub error_codes: Vec<String>,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatsResponse {
    pub requests_total: u64,
    pub requests_by_tool: std::collections::BTreeMap<String, u64>,
    pub ok_total: u64,
    pub denied_total: u64,
    pub denied_consecutive: u64,
    pub denied_consecutive_max: u64,
    pub timeout_total: u64,
    pub cancelled_total: u64,
    pub wedged_total: u64,
    pub busy_total: u64,
    pub error_total: u64,
    pub bytes_read_total: u64,
    pub inflight: u64,
    pub probing_suspected: bool,
    /// The cache counters, as `crate::cache::Cache::stats_json` renders
    /// them. Left as a free-form object so the cache's own counters can
    /// grow without a schema change.
    pub cache: Value,
}

// ---------------------------------------------------------------------------
// Declared schemas
// ---------------------------------------------------------------------------

/// `outputSchema` for every gadget-returning tool.
#[must_use]
pub fn scan_output_schema() -> Arc<JsonObject> {
    rmcp::handler::server::common::schema_for_output::<ScanResponse>()
}

#[must_use]
pub fn info_output_schema() -> Arc<JsonObject> {
    rmcp::handler::server::common::schema_for_output::<InfoResponse>()
}

#[must_use]
pub fn chain_output_schema() -> Arc<JsonObject> {
    rmcp::handler::server::common::schema_for_output::<ChainResponse>()
}

#[must_use]
pub fn config_output_schema() -> Arc<JsonObject> {
    rmcp::handler::server::common::schema_for_output::<ConfigResponse>()
}

#[must_use]
pub fn stats_output_schema() -> Arc<JsonObject> {
    rmcp::handler::server::common::schema_for_output::<StatsResponse>()
}

/// The shape of `structuredContent` when `isError` is true. Not declared in
/// `tools/list` (an `outputSchema` describes success), but fixed and tested.
#[must_use]
pub fn error_output_schema() -> Arc<JsonObject> {
    rmcp::handler::server::common::schema_for_output::<ErrorResponse>()
}

// ---------------------------------------------------------------------------
// Stable gadget identity (MCP-DESIGN fix #8 part C)
// ---------------------------------------------------------------------------

/// RFC 4648 base32 alphabet, lowercased. 10 bytes is 80 bits, which is
/// exactly 16 symbols, so no padding is ever needed.
const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Lowercase base32, no padding. Only ever called with 10 bytes.
fn base32_nopad(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1f) as usize;
            // `B32` is 32 bytes and `idx` is masked to 0..=31, so this
            // cannot fail; `get` keeps the crate-level indexing deny happy.
            out.push(char::from(*B32.get(idx).unwrap_or(&b'a')));
        }
    }
    if bits > 0 {
        let idx = ((acc << (5 - bits)) & 0x1f) as usize;
        out.push(char::from(*B32.get(idx).unwrap_or(&b'a')));
    }
    out
}

/// Bytes of the stable id that go into the hash.
///
/// `binary_sha256` is the raw 32 bytes when the hex parses and the hex
/// bytes otherwise — a caller cannot reach the second case, and falling
/// back rather than panicking keeps the property that no input crashes the
/// server.
#[must_use]
pub fn gadget_id(binary_sha256_hex: &str, vaddr: u64, bytes: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    match rf_cache::decode_hex(binary_sha256_hex, 64) {
        Some(raw) => h.update(&raw),
        None => h.update(binary_sha256_hex.as_bytes()),
    };
    h.update(&vaddr.to_le_bytes());
    h.update(bytes);
    let digest = h.finalize();
    let mut first10 = [0u8; 10];
    let full = digest.as_bytes();
    for (i, slot) in first10.iter_mut().enumerate() {
        *slot = *full.get(i).unwrap_or(&0);
    }
    format!("g_{}", base32_nopad(&first10))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;

    /// 10 bytes is exactly 16 base32 symbols, so an id is always
    /// `g_` + 16 characters and never carries padding.
    #[test]
    fn ids_are_stable_and_fixed_width() {
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let a = gadget_id(sha, 0x401648, &[0x5f, 0xc3]);
        assert_eq!(a.len(), 18, "{a}");
        assert!(a.starts_with("g_"), "{a}");
        assert!(!a.contains('='), "{a}");
        // Deterministic across calls.
        assert_eq!(a, gadget_id(sha, 0x401648, &[0x5f, 0xc3]));
        // Every input participates.
        assert_ne!(a, gadget_id(sha, 0x401649, &[0x5f, 0xc3]));
        assert_ne!(a, gadget_id(sha, 0x401648, &[0x5e, 0xc3]));
        let other = "0000000000000000000000000000000000000000000000000000000000000000";
        assert_ne!(a, gadget_id(other, 0x401648, &[0x5f, 0xc3]));
        // The alphabet is the lowercase RFC 4648 one.
        assert!(
            a.chars().skip(2).all(|c| B32.contains(&(c as u8))),
            "unexpected symbol in {a}"
        );
    }

    /// The whole point of the module: no response field may be skipped when
    /// empty, or the shape varies with the request again.
    #[test]
    fn every_response_field_is_always_present() {
        let rec = GadgetRecord {
            id: "g_x".into(),
            vaddr: "0x1".into(),
            vaddr_u64: 1,
            bytes: "c3".into(),
            text: "ret".into(),
            insns: vec!["ret".into()],
            arch: None,
            section: None,
            delay_slot: false,
            class: None,
            labels: Vec::new(),
            regs_written: Vec::new(),
            regs_read: Vec::new(),
            regs_from_stack: Vec::new(),
            side_effects: 0,
            stack_delta: None,
            quality: 0,
            usability: 0,
            terminator: "ret".into(),
            dispatcher: false,
            privileged: false,
            low_confidence: false,
        };
        let v = serde_json::to_value(&rec).unwrap();
        let obj = v.as_object().unwrap();
        for key in [
            "id",
            "vaddr",
            "vaddr_u64",
            "bytes",
            "text",
            "insns",
            "arch",
            "section",
            "delay_slot",
            "class",
            "labels",
            "regs_written",
            "regs_read",
            "regs_from_stack",
            "side_effects",
            "stack_delta",
            "quality",
            "usability",
            "terminator",
            "dispatcher",
            "privileged",
            "low_confidence",
        ] {
            assert!(obj.contains_key(key), "missing {key} in {v}");
        }
        assert_eq!(obj.len(), 22, "unexpected field count: {v}");
        assert!(obj["arch"].is_null());
        assert!(obj["section"].is_null());
    }

    /// `deny_unknown_fields` is what makes schemars emit
    /// `additionalProperties: false`, which is what makes the conformance
    /// test able to fail on an ADDED field.
    #[test]
    fn declared_schemas_forbid_extra_fields() {
        for (name, schema) in [
            ("scan", scan_output_schema()),
            ("info", info_output_schema()),
            ("chain", chain_output_schema()),
            ("config", config_output_schema()),
            ("stats", stats_output_schema()),
            ("error", error_output_schema()),
        ] {
            let v = serde_json::to_value(schema.as_ref()).unwrap();
            assert_eq!(
                v.get("additionalProperties"),
                Some(&Value::Bool(false)),
                "{name} schema does not forbid extra fields: {v}"
            );
            assert_eq!(v["type"], "object", "{name}");
        }
    }

    /// The error taxonomy is closed and every spelling is unique.
    #[test]
    fn error_codes_are_a_closed_unique_set() {
        let names: Vec<&str> = ErrorCode::all().iter().map(|c| c.as_str()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "duplicate spelling in {names:?}");
        assert_eq!(names.len(), 9, "{names:?}");
        // The two spellings CRIT-03 names as collapsed must not come back.
        assert!(!names.contains(&"usage"));
        assert!(!names.contains(&"invalid_flag"));
        assert!(!names.contains(&"file_too_large"));
        // Serialization agrees with `as_str`.
        for c in ErrorCode::all() {
            assert_eq!(
                serde_json::to_value(c).unwrap(),
                Value::String(c.as_str().into())
            );
        }
    }
}
