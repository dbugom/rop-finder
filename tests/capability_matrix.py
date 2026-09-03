#!/usr/bin/env python3
"""ECO-02 gate: the CLI and the MCP server must expose the same tool.

Why this exists
---------------
The audit finding ECO-02 is "the CLI is behind its own MCP server".  It was
closed once, in v0.3, by adding the missing filters by hand.  That is not a
fix — it is a snapshot.  Phase 4 proved the point: two agents implemented the
*same* query surface on the two front ends in the same week, agreed a shared
vocabulary in advance, and still shipped:

  * ``--reads-reg rax`` and ``reads_reg: "rax"`` returning **2888 vs 2147**
    gadgets for the same question on ``elf-Linux-x64`` at depth 4, because one
    side counted the terminator's target register (``jmp rax`` reads rax) and
    the other did not;
  * ``--terminator bare-ret`` answering on the CLI and being a ``usage_error``
    on MCP, while ``terminator: "any"`` answered on MCP and was a usage error
    on the CLI.

Neither is catchable by reading either surface's documentation, and neither
would fail a test that only exercises one side.  The second one is the mild
case: a value that is a hard error somewhere is at least loud.  The first is
the dangerous shape — *same flag name, same parameter name, silently different
answer* — which is exactly the failure ECO-02 names.

So this harness does not check that a list of flags exists.  It:

  1. **Enumerates the CLI surface** from ``rop-finder --help``.  clap generates
     that text from the ``Cli`` derive, so parsing it is reflection over the
     clap command, not a hand-maintained list: a flag added to ``Cli`` shows up
     here on the next run whether or not anybody remembers this file.
  2. **Enumerates the MCP surface** by driving ``tools/list`` over stdio and
     reading the declared ``inputSchema`` of every tool.  Same property: a new
     ``#[tool]`` or a new parameter appears by itself.
  3. Maps the two through the **declared equivalence table** below, and fails
     on any capability present on one surface and absent from the other.  An
     asymmetry is allowed only by being *written down with a reason* in
     ``CLI_ONLY`` / ``MCP_ONLY`` — and a declaration that has stopped being
     true (the capability arrived on the other side, or left entirely) fails as
     STALE, so the table cannot rot into a permission slip.
  4. Compares the **accepted value vocabulary** of every enumerated shared
     option, by probing both surfaces with each candidate value.  Same name,
     different accepted values is a divergence.
  5. Compares the **answers**.  For each shared constraint, the same question
     is asked of both surfaces on a real fixture and the two gadget sets are
     compared element by element.  This is the half that catches ``reads_reg``.

Usage
-----
    python tests/capability_matrix.py                 # the gate
    python tests/capability_matrix.py --list          # print both surfaces
    python tests/capability_matrix.py --skip-behaviour   # names only (fast)
    python tests/capability_matrix.py --depth 6       # scan depth for step 5

Requires the two release binaries; ``rf_paths`` builds them if absent (set
``RF_NO_BUILD=1`` to forbid that).  It does NOT need the ROPgadget oracle.
"""

import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rf_paths  # noqa: E402

FIXTURE = "elf-Linux-x64"

# ==========================================================================
# THE EQUIVALENCE TABLE.  Data, not code.
#
# Three sections, and every capability on either surface must appear in
# exactly one of them:
#
#   PAIRS      the capability exists on both surfaces.  `cli` is the long
#              flag without its leading dashes; `mcp` is the parameter name,
#              or "tool:<name>" when the MCP spells the capability as a whole
#              tool rather than a parameter.
#   CLI_ONLY   deliberately absent from MCP, with the reason.
#   MCP_ONLY   deliberately absent from the CLI, with the reason.
#
# The default naming rule is mechanical: kebab-case flag <-> snake_case
# parameter (`--max-stack-delta` <-> `max_stack_delta`).  A pair whose two
# spellings do not transliterate must say why in `spelling`, so a rename is a
# decision somebody made rather than a typo nobody noticed.
# ==========================================================================

PAIRS = [
    # ---- the shared v0.4 constraint vocabulary (ECO-01 / ECO-12) ----------
    {"cli": "set-reg", "mcp": "set_reg"},
    {"cli": "from-stack", "mcp": "from_stack"},
    {"cli": "no-clobber", "mcp": "no_clobber"},
    {"cli": "reads-reg", "mcp": "reads_reg"},
    {"cli": "max-stack-delta", "mcp": "max_stack_delta"},
    {"cli": "max-side-effects", "mcp": "max_side_effects"},
    {"cli": "max-insns", "mcp": "max_insns"},
    {"cli": "terminator", "mcp": "terminator"},
    {"cli": "search", "mcp": "search"},
    {"cli": "pivot", "mcp": "pivot"},
    # ---- v0.3 semantic filters, unchanged --------------------------------
    {"cli": "class", "mcp": "class"},
    {"cli": "label", "mcp": "label"},
    {"cli": "writes-reg", "mcp": "writes_reg"},
    # ---- scan shaping ----------------------------------------------------
    {
        "cli": "binary",
        "mcp": "binary_path",
        "spelling": "the MCP name says it is a PATH, and a confined one: it is "
        "resolved against --allow-dir. Renaming either side now would break "
        "every existing caller for no gain.",
    },
    {"cli": "depth", "mcp": "depth"},
    {"cli": "section", "mcp": "section"},
    {"cli": "base", "mcp": "base"},
    {"cli": "offset", "mcp": "offset"},
    {"cli": "range", "mcp": "range"},
    {"cli": "badbytes", "mcp": "badbytes"},
    {"cli": "only", "mcp": "only"},
    {"cli": "arch", "mcp": "arch"},
    {"cli": "cfg-aware", "mcp": "cfg_aware"},
    {
        "cli": "re",
        "mcp": "pattern",
        "spelling": "ROPgadget spells this `--re`, which is meaningless as a "
        "JSON key; the MCP tool is search_gadgets_by_pattern and its parameter "
        "is `pattern`. Same ROPgadget per-instruction-conjunction semantics.",
    },
    {
        "cli": "rank",
        "mcp": "order",
        "spelling": "a boolean flag on the CLI, an enum on MCP (`order: rank` "
        "vs `order: address`), because MCP defaults to ranked and the CLI "
        "defaults to address order.",
    },
    # ---- non-gadget search (CLI-05 / ECO-02) -----------------------------
    {"cli": "string", "mcp": "string"},
    {"cli": "opcode", "mcp": "opcode"},
    {"cli": "memstr", "mcp": "memstr"},
    # ---- whole-tool equivalences ----------------------------------------
    {
        "cli": "info",
        "mcp": "tool:get_binary_info",
        "spelling": "a mode flag on the CLI, a tool on MCP.",
    },
    {
        "cli": "ropchain",
        "mcp": "tool:build_rop_chain",
        "spelling": "a mode flag on the CLI, a tool on MCP.",
    },
    {"cli": "chain", "mcp": "target", "spelling": "the chain target selector."},
    {"cli": "api-addr", "mcp": "api_addr"},
    {"cli": "shellcode-addr", "mcp": "shellcode_addr"},
    {"cli": "shellcode-size", "mcp": "shellcode_size"},
    {
        "cli": "nojop",
        "mcp": "tool:find_jop_gadgets",
        "spelling": "the CLI turns engines off with --norop/--nojop/--nosys; "
        "MCP names the family it wants as a tool. Both reach the same three "
        "anchor tables.",
    },
    {"cli": "nosys", "mcp": "tool:find_syscall_gadgets", "spelling": "see --nojop."},
    {"cli": "norop", "mcp": "tool:find_gadgets", "spelling": "see --nojop."},
]

CLI_ONLY = {
    # --- terminal/interactive presentation, meaningless over JSON-RPC -----
    "help": "clap's own flag. tools/list is the MCP equivalent and needs no parameter.",
    "version": "CLI-12. The server reports its version in `initialize` and in "
    "get_server_config; a version parameter would be nonsense.",
    "console": "an interactive REPL on a TTY. An MCP session IS the REPL, and a "
    "stdio server cannot host a second one on the same pipe.",
    "silent": "suppresses gadget PRINTING during a terminal scan. The MCP never "
    "prints; max_results/cursor are how a caller asks for less.",
    "noinstr": "ROPgadget's bare-address listing mode. A structured record always "
    "carries its text; an agent that wants only addresses reads the vaddr field.",
    "dump": "appends hex bytes to the human listing. Every MCP gadget record "
    "already carries `bytes`, unconditionally.",
    "format": "ECO-09 selects between human/json/jsonl/csv/raw TEXT renderings. "
    "The MCP transport is JSON-RPC; the NDJSON equivalent is the "
    "ropfinder://scan/<key>/gadgets.ndjson resource, not a parameter.",
    "chain-format": "same reason as --format, for the chain: python script vs JSON "
    "IR vs raw bytes. build_rop_chain returns the JSON IR and the script text "
    "together, so the choice does not arise.",
    "json": "the v0.2 spelling of --format json. See --format.",
    "classify": "controls whether the CLI's JSON records carry the semantic fields. "
    "MCP records ALWAYS carry them (and, since ECO-01, an `explanation`), so "
    "there is nothing to turn on.",
    # --- process-level and host-level concerns ---------------------------
    "cache": "an on-disk scan cache the user opts into per invocation. The server "
    "caches by policy, sized with --cache-mem-mb, and reports hits in "
    "get_server_stats; a per-request toggle would let a caller evict another "
    "caller's work.",
    "cache-purge": "deletes the on-disk cache and exits. Destructive, host-level, "
    "and deliberately not reachable from a tool call.",
    "max-file-size": "a per-invocation limit the user sets. On the server it is "
    "--max-file-bytes, an operator policy a tool call must not be able to raise.",
    "max-gadgets": "a per-invocation budget. The server's equivalents are "
    "max_results plus the operator's --max-gadgets, for the same reason.",
    "max-memory": "as --max-gadgets: an operator policy, not a request parameter.",
    "compat": "CLI-11's bug-for-bug ROPgadget compatibility, which knowingly "
    "produces part-fabricated output (concatenated fat-Mach-O slices) and reads "
    "a section's declared file extent rather than the bytes it owns. Refused on "
    "the MCP surface on purpose: the confinement argument in find.rs rests on "
    "never reading outside a materialised section.",
    # --- raw-blob and ISA decoding hints ---------------------------------
    "rawArch": "raw-blob decoding hints. The MCP takes a file inside an allow-root "
    "and identifies it from its own headers; a raw blob has none, so the server "
    "reports the unsupported format rather than being told what to pretend.",
    "rawMode": "a raw-blob decoding hint, as --rawArch: the MCP identifies a file from its own headers rather than being told what to pretend it is.",
    "rawEndian": "a raw-blob decoding hint, as --rawArch and --rawMode.",
    "thumb": "as --rawArch: an ARM decoding hint. rop-finder routes a Thumb-only "
    "image to the Thumb tables from the header (see the ANCH-06 divergence), so "
    "the hint is only needed to override that deliberately.",
    # --- ROPgadget-compatibility surface ---------------------------------
    "filter": "ROPgadget's mnemonic-suppression alternation. Reachable over MCP "
    "through run_ropgadget_command's `args`, which is the tool that exists for "
    "exactly this: ROPgadget flags with no first-class MCP twin.",
    "align": "as --filter: reachable via run_ropgadget_command args.",
    "all": "as --filter (disables dedup): reachable via run_ropgadget_command args.",
    "multibr": "as --filter: reachable via run_ropgadget_command args.",
    "callPreceded": "as --filter: reachable via run_ropgadget_command args.",
    "mipsrop": "as --filter: reachable via run_ropgadget_command args.",
}

MCP_ONLY = {
    # --- transport-level shaping the CLI does not need --------------------
    "max_results": "a stdio response goes into a model's context window, so every "
    "list is capped and paged. A terminal scrolls, and the CLI's equivalent "
    "budget knob is --max-gadgets.",
    "cursor": "the paging continuation for max_results. A pipe does not page.",
    "timeout_secs": "a per-request deadline, so one tool call cannot hold the "
    "session. The CLI's process is the user's to interrupt.",
    "ids": "get_gadgets round-trips the stable ids find_gadgets handed out, which "
    "is how an agent refers to a gadget across calls. A shell has no such "
    "handle; the address is the handle.",
    "sort_by": "orders the returned page (quality/address/length). The CLI's "
    "--rank is the boolean form; see that pair.",
    "max_sections": "MCP-06 output caps on get_binary_info's arrays. --info writes "
    "to a terminal and prints everything.",
    "max_imports": "an MCP-06 output cap on get_binary_info's imports array, as max_sections. --info writes to a terminal and prints them all.",
    "max_symbols": "as max_sections, and additionally the DEFAULT is 0 because a "
    "symbol table is unbounded by the file's structure; --info prints them all.",
    # --- semantics that exist only because the caller is a model ---------
    "preserves_regs": "the v0.3 spelling, kept for compatibility with callers "
    "written against it. It is `regs_written`-based and therefore NOT the same "
    "predicate as --no-clobber/no_clobber, which is the CLS-09 clobber "
    "partition; both are offered on MCP so an existing caller's meaning does "
    "not change under it. New callers, and the CLI, use no_clobber.",
    "args": "run_ropgadget_command's allow-listed raw ROPgadget argv. It is the "
    "escape hatch that makes the CLI-only ROPgadget flags reachable; on the CLI "
    "the argv IS the interface.",
}

#: MCP tool names that are the twin of a CLI *mode*, declared in PAIRS above
#: as "tool:<name>", plus the tools that are deliberately server-only.
MCP_ONLY_TOOLS = {
    "get_server_config": "reports the server's own policy (allow roots, caps, "
    "timeouts). There is no server in a CLI invocation; the flags ARE the config.",
    "get_server_stats": "per-session counters for an operator watching a running "
    "server. A CLI process exits.",
    "get_gadgets": "resolves the stable ids from a previous call. See the `ids` "
    "parameter.",
    "find_gadgets_by_effect": "a named preset over the same predicate find_gadgets "
    "applies, which additionally REFUSES an unconstrained call rather than "
    "returning the whole scan. On the CLI the constraint flags compose directly "
    "onto the default scan, so the preset has nothing to add.",
    "find_string": "the tool form of --string/--memstr; both spellings are in "
    "PAIRS, and `memstr` selects between them.",
    "find_bytes": "the tool form of --opcode; the parameter is in PAIRS.",
    "get_mitigations": "ECO-06. The CLI reports the same rf-core report inside "
    "--info's JSON rather than as a separate mode.",
    "search_gadgets_by_pattern": "the tool form of --re; the parameter is in PAIRS.",
    "run_ropgadget_command": "the raw-argv escape hatch. See `args`.",
}

# ==========================================================================
# Enumerated value vocabularies that must be IDENTICAL on both surfaces.
#
# A shared name with a different accepted value set is the quiet half of
# ECO-02: an agent that learns a spelling from one surface gets a usage error
# (or worse, a different answer) on the other.  Candidates are probed against
# both, so this list may safely be a superset of what either accepts.
# ==========================================================================

VOCABULARIES = [
    {
        "cli": "terminator",
        "mcp": "terminator",
        "candidates": [
            "ret", "jmp", "call", "syscall", "none", "any",
            "bare-ret", "ret-imm", "jmp-reg", "jmp-mem",
            "call-reg", "call-mem", "far", "other",
            # normalisation and any-of composition, which must not be a
            # usage error on one surface and a working query on the other
            "RET", "ret ", "", "ret,jmp", "ret|jmp", "any,ret",
            # negative controls: both surfaces must reject these
            "returns", "ret-", "jmp reg",
        ],
    },
    {
        "cli": "class",
        "mcp": "class",
        "candidates": [
            "reg-write", "stack-pivot", "mem-read", "mem-write",
            "arithmetic", "syscall", "dispatcher", "other",
            "regwrite", "pivot",
        ],
    },
]

# ==========================================================================
# Queries asked of BOTH surfaces, whose answers must be equal as sets.
#
# `cli` is extra argv; `mcp` is extra find_gadgets_by_effect arguments.  The
# binary, depth and output shaping are supplied by the runner.
#
# A row may carry a fourth element, `NONVACUOUS`, meaning "and the answer must
# not be empty".  Two empty sets are equal and prove nothing, which matters
# here: `--set-reg rdi,rsi` agreed with `set_reg: "rdi,rsi"` at 0 == 0 on the
# depth the harness used, while one surface was requiring both registers and
# the other was looking for a register literally named "rdi,rsi".  Every
# multi-valued probe is marked, and DEPTH is chosen so they are all answerable.
# ==========================================================================

NONVACUOUS = "nonvacuous"

QUERIES = [
    ("set-reg", ["--set-reg", "rdi"], {"set_reg": "rdi"}),
    ("set-reg+from-stack", ["--set-reg", "rdi", "--from-stack"],
     {"set_reg": "rdi", "from_stack": True}),
    ("no-clobber", ["--set-reg", "rdi", "--no-clobber", "rsi,rdx"],
     {"set_reg": "rdi", "no_clobber": ["rsi", "rdx"]}),
    ("reads-reg", ["--reads-reg", "rax"], {"reads_reg": "rax"}),
    ("reads-reg (sub-register)", ["--reads-reg", "rcx"], {"reads_reg": "rcx"}),
    ("max-stack-delta 8", ["--max-stack-delta", "8"], {"max_stack_delta": 8}),
    ("max-stack-delta 0", ["--max-stack-delta", "0"], {"max_stack_delta": 0}),
    ("max-side-effects 0", ["--max-side-effects", "0"], {"max_side_effects": 0}),
    ("max-insns 2", ["--max-insns", "2"], {"max_insns": 2}),
    ("search literal", ["--search", "pop rdi; ret"], {"search": "pop rdi; ret"}),
    ("search % wildcard", ["--search", "pop %; ret"], {"search": "pop %; ret"}),
    ("search ? wildcard", ["--search", "p?p rdi; ret"], {"search": "p?p rdi; ret"}),
    ("pivot", ["--pivot"], {"pivot": True}),
    ("class", ["--class", "reg-write"], {"class": "reg-write"}),
    ("label", ["--label", "stack-pivot"], {"label": "stack-pivot"}),
    ("writes-reg", ["--writes-reg", "rdi"], {"writes_reg": "rdi"}),
    ("from-stack alone", ["--from-stack"], {"from_stack": True}),
    # Multi-valued forms. Every list-valued flag is asked a TWO-register
    # question, because a flag that is a list on one surface and a single
    # opaque string on the other agrees on every one-value probe and then
    # answers 0 against 45. That is exactly what `--set-reg rdi,rsi` and
    # `--reads-reg rax,rcx` did before this row existed.
    ("set-reg two (ALL)", ["--set-reg", "rdi,rsi"], {"set_reg": "rdi,rsi"}, NONVACUOUS),
    ("set-reg two + from-stack", ["--set-reg", "rdi,rsi", "--from-stack"],
     {"set_reg": "rdi,rsi", "from_stack": True}),
    ("set-reg two, one absent", ["--set-reg", "rdi,r15"], {"set_reg": "rdi,r15"},
     NONVACUOUS),
    ("reads-reg two (ALL)", ["--reads-reg", "rax,rcx"], {"reads_reg": "rax,rcx"}, NONVACUOUS),
    ("writes-reg two (ALL)", ["--writes-reg", "rdi,rsi"], {"writes_reg": "rdi,rsi"}, NONVACUOUS),
    ("no-clobber two", ["--no-clobber", "rsi,rdx"], {"no_clobber": ["rsi,rdx"]}, NONVACUOUS),
    ("no-clobber piped", ["--no-clobber", "rsi|rdx"], {"no_clobber": ["rsi|rdx"]}, NONVACUOUS),
    ("class two (any-of)", ["--class", "reg-write,mem-write"],
     {"class": "reg-write,mem-write"}, NONVACUOUS),
    ("label two (any-of)", ["--label", "stack-pivot,syscall"],
     {"label": "stack-pivot,syscall"}, NONVACUOUS),
    ("terminator two (any-of)", ["--terminator", "ret,jmp"], {"terminator": "ret,jmp"}, NONVACUOUS),
    # Register-name normalisation: sigil and case must mean the same thing.
    ("set-reg sigil", ["--set-reg", "$RDI"], {"set_reg": "$RDI"}, NONVACUOUS),
    ("set-reg uppercase", ["--set-reg", "RDI"], {"set_reg": "RDI"}, NONVACUOUS),
    # The Phase 4 exit-criterion query itself.
    ("EXIT CRITERION",
     ["--set-reg", "rdi", "--from-stack", "--no-clobber", "rsi,rdx",
      "--max-side-effects", "1", "--terminator", "ret"],
     {"set_reg": "rdi", "from_stack": True, "no_clobber": ["rsi", "rdx"],
      "max_side_effects": 1, "terminator": "ret"}),
]
# Every terminator value, coarse and fine, asked of both surfaces.
for _t in ["ret", "jmp", "call", "syscall", "none", "bare-ret", "ret-imm",
           "jmp-reg", "jmp-mem", "call-reg", "call-mem", "far", "other"]:
    QUERIES.append((f"terminator {_t}", ["--terminator", _t], {"terminator": _t}))


# --------------------------------------------------------------------------
# Surface enumeration
# --------------------------------------------------------------------------

#: A long option as clap renders it: two spaces, optional short, then --name.
_LONG_FLAG = re.compile(r"^\s{2,}(?:-\w,\s+)?--([A-Za-z][A-Za-z0-9-]*)")


def cli_surface(exe):
    """Every long flag ``rop-finder`` accepts, from its clap-generated help.

    clap renders the help from the ``Cli`` derive, so this is reflection over
    the command rather than a list somebody maintains: a field added to
    ``Cli`` appears here on the next run.
    """
    p = subprocess.run([exe, "--help"], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"{exe} --help exited {p.returncode}: {p.stderr[:400]}")
    flags = []
    for line in p.stdout.splitlines():
        m = _LONG_FLAG.match(line)
        if m:
            flags.append(m.group(1))
    if len(flags) < 20:
        sys.exit(f"only parsed {len(flags)} flags from --help; the format changed")
    return sorted(set(flags))


class Mcp:
    """The smallest possible MCP client: JSON-RPC over stdio."""

    def __init__(self, exe, allow_dir, cwd):
        self.proc = subprocess.Popen(
            [exe, "--allow-dir", allow_dir],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, cwd=cwd, text=True,
            encoding="utf-8", bufsize=1,
        )
        self._id = 0
        self._send({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": {"name": "capability-matrix", "version": "0"}}})
        self._recv()
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized",
                    "params": {}})

    def _send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _recv(self):
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("rop-finder-mcp closed stdout")
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "id" in obj:
                return obj

    def request(self, method, params):
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": method,
                    "params": params})
        r = self._recv()
        if "error" in r:
            raise RuntimeError(f"{method} failed: {r['error']}")
        return r["result"]

    def call(self, name, args):
        return self.request("tools/call", {"name": name, "arguments": args})

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.terminate()
            self.proc.wait(timeout=10)
        except Exception:
            pass


def mcp_surface(mcp):
    """``(tool names, parameter names)`` from the server's own tools/list."""
    tools = mcp.request("tools/list", {})["tools"]
    names = sorted(t["name"] for t in tools)
    params = set()
    for t in tools:
        params.update((t.get("inputSchema") or {}).get("properties", {}).keys())
    return names, sorted(params)


# --------------------------------------------------------------------------
# The checks
# --------------------------------------------------------------------------

def kebab_to_snake(flag):
    return flag.replace("-", "_")


def check_table_shape(fails):
    """The table itself must be well formed before it can judge anything."""
    seen = {}
    for row in PAIRS:
        if row["cli"] in seen:
            fails.append(f"TABLE: --{row['cli']} appears twice in PAIRS")
        seen[row["cli"]] = row
        if row["cli"] in CLI_ONLY:
            fails.append(f"TABLE: --{row['cli']} is in both PAIRS and CLI_ONLY")
        if row["mcp"] in MCP_ONLY:
            fails.append(f"TABLE: {row['mcp']} is in both PAIRS and MCP_ONLY")
        # The mechanical naming rule, unless the row declares otherwise.
        if not row["mcp"].startswith("tool:"):
            if kebab_to_snake(row["cli"]) != row["mcp"] and "spelling" not in row:
                fails.append(
                    f"TABLE: --{row['cli']} <-> {row['mcp']} does not transliterate "
                    "and declares no `spelling` reason"
                )
    for name, reason in list(CLI_ONLY.items()) + list(MCP_ONLY.items()) \
            + list(MCP_ONLY_TOOLS.items()):
        if not reason or len(reason) < 20:
            fails.append(f"TABLE: {name!r} is declared asymmetric with no real reason")


def check_names(cli_flags, mcp_tools, mcp_params, fails, verbose):
    paired_cli = {r["cli"] for r in PAIRS}
    paired_mcp = {r["mcp"] for r in PAIRS if not r["mcp"].startswith("tool:")}
    paired_tools = {r["mcp"][5:] for r in PAIRS if r["mcp"].startswith("tool:")}

    # 1. Every CLI flag is accounted for.
    for f in cli_flags:
        if f in paired_cli or f in CLI_ONLY:
            continue
        fails.append(
            f"CLI-ONLY, UNDECLARED: --{f} exists on the CLI and has no MCP twin "
            "and no declared reason. Add it to PAIRS (implement it on MCP) or to "
            "CLI_ONLY with a reason."
        )

    # 2. Every MCP parameter is accounted for.
    for p in mcp_params:
        if p in paired_mcp or p in MCP_ONLY:
            continue
        fails.append(
            f"MCP-ONLY, UNDECLARED: the parameter {p!r} exists on the MCP surface "
            "and has no CLI twin and no declared reason. Add it to PAIRS "
            "(implement it on the CLI) or to MCP_ONLY with a reason."
        )

    # 3. Every MCP tool is accounted for.
    for t in mcp_tools:
        if t in paired_tools or t in MCP_ONLY_TOOLS:
            continue
        fails.append(
            f"MCP-ONLY TOOL, UNDECLARED: {t} has no declared CLI equivalent."
        )

    # 4. No stale rows: a declared pair whose either half has vanished, or a
    #    declared asymmetry that stopped being asymmetric.
    for row in PAIRS:
        if row["cli"] not in cli_flags:
            fails.append(
                f"STALE PAIR: --{row['cli']} is in the table but not in --help. "
                "The CLI lost a capability its MCP twin still has."
            )
        if row["mcp"].startswith("tool:"):
            if row["mcp"][5:] not in mcp_tools:
                fails.append(f"STALE PAIR: MCP tool {row['mcp'][5:]} no longer exists")
        elif row["mcp"] not in mcp_params:
            fails.append(
                f"STALE PAIR: MCP parameter {row['mcp']!r} no longer exists. "
                "The MCP lost a capability the CLI still has."
            )
    for f in CLI_ONLY:
        if f not in cli_flags:
            fails.append(f"STALE CLI_ONLY: --{f} no longer exists; delete the row")
        if kebab_to_snake(f) in mcp_params:
            fails.append(
                f"STALE CLI_ONLY: --{f} is declared CLI-only but {kebab_to_snake(f)!r} "
                "is now an MCP parameter. Move it to PAIRS."
            )
    for p in MCP_ONLY:
        if p not in mcp_params:
            fails.append(f"STALE MCP_ONLY: {p!r} no longer exists; delete the row")
    for t in MCP_ONLY_TOOLS:
        if t not in mcp_tools:
            fails.append(f"STALE MCP_ONLY_TOOLS: {t} no longer exists; delete the row")

    if verbose:
        print(f"  {len(cli_flags)} CLI flags, {len(mcp_params)} MCP parameters, "
              f"{len(mcp_tools)} MCP tools")
        print(f"  {len(PAIRS)} paired, {len(CLI_ONLY)} declared CLI-only, "
              f"{len(MCP_ONLY)} declared MCP-only parameters, "
              f"{len(MCP_ONLY_TOOLS)} declared MCP-only tools")


def check_vocabularies(cli, mcp, binary, fails):
    """Same option name, same accepted values."""
    for vocab in VOCABULARIES:
        cli_ok, mcp_ok = set(), set()
        for value in vocab["candidates"]:
            p = subprocess.run(
                [cli, "--binary", binary, "--depth", "2", "--silent",
                 f"--{vocab['cli']}", value],
                capture_output=True, text=True,
            )
            if p.returncode == 0:
                cli_ok.add(value)
            r = mcp.call("find_gadgets", {
                "binary_path": binary, "depth": 2, "max_results": 1,
                vocab["mcp"]: value})
            if not r.get("isError"):
                mcp_ok.add(value)
        only_cli = sorted(cli_ok - mcp_ok)
        only_mcp = sorted(mcp_ok - cli_ok)
        if only_cli or only_mcp:
            fails.append(
                f"VOCABULARY: --{vocab['cli']} / {vocab['mcp']} accept different "
                f"values. CLI-only: {only_cli}. MCP-only: {only_mcp}. Same name, "
                "different vocabulary is the quiet half of ECO-02."
            )
        print(f"  {vocab['cli']:12} both accept {len(cli_ok & mcp_ok)}, "
              f"both reject {len(set(vocab['candidates']) - cli_ok - mcp_ok)}"
              + (f"  DIVERGENT cli={only_cli} mcp={only_mcp}"
                 if (only_cli or only_mcp) else ""))


def cli_answer(cli, binary, depth, extra):
    p = subprocess.run(
        [cli, "--binary", binary, "--depth", str(depth), "--format", "json"] + extra,
        capture_output=True, text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"CLI exited {p.returncode}: {p.stderr.strip()[:300]}")
    return {(g["vaddr"], g["text"]) for g in json.loads(p.stdout)}


def mcp_answer(mcp, binary, depth, extra, cap):
    args = {"binary_path": binary, "depth": depth, "max_results": cap}
    args.update(extra)
    r = mcp.call("find_gadgets_by_effect", args)
    if r.get("isError"):
        raise RuntimeError("MCP error: " + r["content"][0]["text"][:300])
    body = r["structuredContent"]
    if body.get("next_cursor"):
        raise RuntimeError(
            f"answer did not fit in one page (total {body.get('total_count')} > "
            f"{cap}); raise the cap rather than comparing a prefix"
        )
    return {(g["vaddr"], g["text"]) for g in body["gadgets"]}


def check_behaviour(cli, mcp, binary, depth, cap, fails):
    """Same question, same answer -- compared gadget by gadget."""
    for row in QUERIES:
        name, cargs, margs = row[0], row[1], row[2]
        nonvacuous = len(row) > 3 and row[3] == NONVACUOUS
        try:
            a = cli_answer(cli, binary, depth, cargs)
            b = mcp_answer(mcp, binary, depth, margs, cap)
        except RuntimeError as e:
            fails.append(f"BEHAVIOUR {name}: {e}")
            print(f"  {name:28} ERROR {e}")
            continue
        if a == b:
            if nonvacuous and not a:
                fails.append(
                    f"VACUOUS {name}: both surfaces returned nothing, so this row "
                    "compares two empty sets and proves nothing. Raise --depth or "
                    "pick a question this fixture can answer."
                )
                print(f"  {name:28} VACUOUS (both empty)")
            else:
                print(f"  {name:28} agree, n={len(a)}")
            continue
        examples = sorted(a - b)[:3] + sorted(b - a)[:3]
        fails.append(
            f"BEHAVIOUR {name}: the two surfaces answer the same question "
            f"differently. CLI {len(a)} gadgets, MCP {len(b)}; "
            f"{len(a - b)} CLI-only, {len(b - a)} MCP-only. e.g. {examples}"
        )
        print(f"  {name:28} DIVERGENT cli={len(a)} mcp={len(b)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--depth", type=int, default=8,
                    help="scan depth for the behavioural comparison (default 8; "
                         "elf-Linux-x64 first answers `--set-reg rdi,rsi` at 7, "
                         "and a NONVACUOUS row that comes back empty FAILS)")
    ap.add_argument("--max-results", type=int, default=50000,
                    help="MCP page size; a query that overflows it FAILS rather "
                         "than being compared as a prefix")
    ap.add_argument("--fixture", default=FIXTURE)
    ap.add_argument("--skip-behaviour", action="store_true",
                    help="names and vocabularies only")
    ap.add_argument("--list", action="store_true",
                    help="print both surfaces and exit 0")
    args = ap.parse_args()

    cli = rf_paths.rop_finder(package="rf-cli", stem="rop-finder")
    srv = rf_paths.rop_finder(package="rf-mcp", stem="rop-finder-mcp")
    binary = rf_paths.fixture_path(args.fixture)
    if not os.path.exists(binary):
        sys.exit(f"missing fixture {binary} (run tests/fetch_fixtures.py)")

    print(f"# cli:    {cli}")
    print(f"# server: {srv}")
    print(f"# fixture: {args.fixture} at depth {args.depth}\n")

    mcp = Mcp(srv, rf_paths.FIXTURES, rf_paths.REPO)
    try:
        cli_flags = cli_surface(cli)
        mcp_tools, mcp_params = mcp_surface(mcp)

        if args.list:
            print("CLI flags:", " ".join("--" + f for f in cli_flags))
            print("\nMCP tools:", " ".join(mcp_tools))
            print("\nMCP parameters:", " ".join(mcp_params))
            return 0

        fails = []
        print("== table shape")
        check_table_shape(fails)
        print("== name coverage")
        check_names(cli_flags, mcp_tools, mcp_params, fails, verbose=True)
        print("== value vocabularies")
        check_vocabularies(cli, mcp, binary, fails)
        if args.skip_behaviour:
            print("== behaviour: SKIPPED (--skip-behaviour)")
        else:
            print("== behaviour (same question, both surfaces)")
            check_behaviour(cli, mcp, binary, args.depth, args.max_results, fails)
    finally:
        mcp.close()

    print()
    if fails:
        for f in fails:
            print("FAIL: " + f)
        print(f"\nCAPABILITY MATRIX: FAIL ({len(fails)} divergences)")
        return 1
    print(f"{len(PAIRS)} paired capabilities, "
          f"{len(CLI_ONLY) + len(MCP_ONLY) + len(MCP_ONLY_TOOLS)} declared "
          f"asymmetries, {len(VOCABULARIES)} vocabularies and "
          f"{0 if args.skip_behaviour else len(QUERIES)} answers compared.")
    print("CAPABILITY MATRIX: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
