#!/usr/bin/env python3
"""Workability gate: can an agent finish a real task inside a token budget?

Phase 3's headline exit criterion is not "the server responds" — v0.2 already
did that — it is that a *scripted agent* can complete an end-to-end exploitation
question over the MCP surface and still have context left to think with.  This
driver is that criterion, made falsifiable.

The loop, on ``tests/fixtures/elf-Linux-x64``
--------------------------------------------
1. **Locate ``/bin/sh``.**  This fixture contains no ``/bin/sh`` string (checked
   here, not assumed), so — exactly as ROPgadget's own ``--ropchain`` does — the
   string has to be *written* at run time into a writable, non-executable data
   page.  "Locating ``/bin/sh``" therefore means resolving the address the
   argument will live at.  The agent gets it from ``get_binary_info`` by picking
   the writable non-executable section, and step 4 proves the answer was right
   by checking the generated chain's ``data_addr`` words land inside it.
2. **Find a gadget that sets ``rdi`` without clobbering ``rsi`` or ``rdx``.**
   One ``find_gadgets`` call with the semantic filters
   ``writes_reg=rdi`` + ``preserves_regs=rsi,rdx``, in the default ``rank``
   order.  The agent does not read gadget text and grep it; it asks the
   question it actually has.
3. **Classify it.**  The chosen gadget's stable ``id`` is round-tripped through
   ``get_gadgets`` — which is the test that ids are usable as handles at all —
   and the returned record must carry the semantic fields (class, labels,
   ``regs_written``, ``regs_from_stack``, terminator, usability, quality).
4. **Generate a chain.**  ``build_rop_chain`` with ``target: linux-execve``,
   and the result must be internally consistent with steps 1-3.

The budget
----------
FEWER THAN 10,000 TOKENS of tool output, total, for the whole loop.  There is no
tokenizer here on purpose: a gate that depends on a model's vocabulary is not
reproducible.  The estimate is **characters / 4**, the standard rule of thumb,
and the character counts are printed so anyone can re-derive the number under a
different assumption.

Two character counts are reported, because "tool output" has two defensible
readings and they differ by a factor of two:

``rendered`` only ``content[*].text`` — what an MCP host actually puts in the
            model's context window, and therefore what the criterion is really
            about, since the criterion is about an agent's remaining room to
            think.  **THE GATE IS ON THIS NUMBER.**
``wire``    every byte of every ``result`` object the server sends back.  rmcp
            emits the *same payload twice* — once as ``content[0].text`` and
            once as the ``structuredContent`` mirror — plus the JSON escaping
            of the first, so this is ~2.1x ``rendered``.  It is reported on
            every run, and the run prints a separate verdict for it, because
            the doubling is a real property of the transport that a future
            change could make matter.  It is not the gate because no host
            charges the model for both copies, so gating on it would measure
            rmcp's redundancy rather than this tool's verbosity.

Neither number is allowed to be silent: the run prints both verdicts, so a
reader cannot mistake a pass on one for a pass on the other.

Usage
-----
    python tests/mcp_workability.py              # the gate (exit 1 over budget)
    python tests/mcp_workability.py -v           # dump every request/response
    python tests/mcp_workability.py --budget N   # a different token budget

``ROP_FINDER_BIN`` is honoured for the *CLI* by rf_paths; this harness resolves
``rop-finder-mcp`` the same way and builds it if it is absent.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rf_paths  # noqa: E402

#: The Phase 3 exit criterion.
DEFAULT_BUDGET_TOKENS = 10_000
#: Characters per token. A rule of thumb, stated so the number can be redone.
CHARS_PER_TOKEN = 4

FIXTURE = "elf-Linux-x64"


class Mcp:
    """The smallest possible MCP client: newline-delimited JSON-RPC on stdio."""

    def __init__(self, exe, allow_dir, cwd, verbose=False):
        self.verbose = verbose
        self.proc = subprocess.Popen(
            [exe, "--allow-dir", allow_dir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=cwd,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        self._id = 0
        #: (label, wire_chars, rendered_chars) for every tools/call.
        self.usage = []
        self._send(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "workability", "version": "0"},
                },
            }
        )
        self._recv()
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def _send(self, obj):
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _recv(self):
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("rop-finder-mcp closed stdout")
        return json.loads(line)

    def call(self, label, name, arguments):
        """One tools/call. Returns structuredContent; records its size."""
        self._id += 1
        want = self._id
        self._send(
            {
                "jsonrpc": "2.0",
                "id": want,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        while True:
            msg = self._recv()
            if msg.get("id") == want:
                break
        result = msg["result"]
        rendered = "".join(c.get("text", "") for c in result.get("content", []))
        wire = len(json.dumps(result, separators=(",", ":")))
        self.usage.append((label, wire, len(rendered)))
        if self.verbose:
            print(f"\n--> {name} {json.dumps(arguments)}")
            print(f"<-- {json.dumps(result, indent=1)[:4000]}")
        body = result.get("structuredContent")
        if result.get("isError"):
            raise AssertionError(f"{label}: tool reported an error: {json.dumps(body)}")
        if body is None:
            raise AssertionError(f"{label}: no structuredContent in {json.dumps(result)[:400]}")
        return body

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def check(cond, msg):
    if not cond:
        raise AssertionError(msg)


def run_loop(mcp, binary):
    """The four steps. Returns a dict of what each one established."""
    found = {}

    # -- 1. locate the address /bin/sh will live at ---------------------------
    info = mcp.call("1. get_binary_info", "get_binary_info", {"binary_path": binary})
    check(info["format"] == "elf", f"expected an ELF, got {info['format']}")
    data = [
        s
        for s in info["sections"]
        if s.get("writable") and not s.get("executable") and s["name"] == ".data"
    ]
    check(len(data) == 1, f"expected exactly one writable .data section, got {len(data)}")
    argv_addr = int(data[0]["vaddr"], 16)
    found["argv_addr"] = argv_addr
    found["argv_section"] = data[0]
    print(f"  1. /bin/sh will live at {data[0]['name']} = {hex(argv_addr)} "
          f"(writable, not executable, size {data[0]['size']})")

    # -- 2. a gadget that sets rdi and preserves rsi/rdx ----------------------
    hits = mcp.call(
        "2. find_gadgets",
        "find_gadgets",
        {
            "binary_path": binary,
            "depth": 4,
            "writes_reg": "rdi",
            "preserves_regs": "rsi,rdx",
            "max_results": 5,
        },
    )
    check(hits["order"] == "rank", f"default order should be rank, got {hits['order']}")
    check(hits["gadgets"], "no gadget writes rdi while preserving rsi and rdx")
    best = hits["gadgets"][0]
    for reg in ("rsi", "rdx"):
        check(reg not in best["regs_written"], f"{best['text']} clobbers {reg}")
    check("rdi" in best["regs_written"], f"{best['text']} does not write rdi")
    found["gadget"] = best
    found["candidates"] = hits["total_count"]
    print(f"  2. {hits['total_count']} candidates; rank #1 is "
          f"{best['vaddr']}  {best['text']!r}  (id {best['id']})")

    # -- 3. classify it, by id --------------------------------------------------
    back = mcp.call(
        "3. get_gadgets",
        "get_gadgets",
        {"binary_path": binary, "depth": 4, "ids": [best["id"]]},
    )
    check(len(back["gadgets"]) == 1, f"id round-trip returned {len(back['gadgets'])} records")
    rec = back["gadgets"][0]
    check(rec["id"] == best["id"], "get_gadgets returned a different id")
    check(rec["text"] == best["text"], "get_gadgets returned a different gadget")
    for field in ("class", "labels", "regs_written", "regs_from_stack",
                  "terminator", "usability", "quality", "side_effects"):
        check(field in rec, f"the gadget record has no {field}")
    check(rec["class"] is not None, "the gadget is unclassified")
    found["record"] = rec
    print(f"  3. classified: class={rec['class']} labels={rec['labels']} "
          f"regs_from_stack={rec['regs_from_stack']} terminator={rec['terminator']} "
          f"usability={rec['usability']} quality={rec['quality']}")

    # -- 4. build the chain ----------------------------------------------------
    chain = mcp.call(
        "4. build_rop_chain",
        "build_rop_chain",
        {"binary_path": binary, "target": "linux-execve"},
    )
    ir = chain["chain"]
    check(ir["words"], "the chain has no words")
    check(chain["python"], "the chain has no script")
    # The step-1 answer has to be the address the chain actually uses.
    #
    # `data_addr` is the IR's "rendered as a pack() word" kind, and since
    # CHLX-02 it carries two different sorts of value: section locations,
    # whose comment names the section (`@ .data`, `@ .data + 8`), and plain
    # numeric stack arguments — the NULL argv terminator, the execve syscall
    # number — whose comment does not.  Only the first sort is an address, so
    # only the first sort can be inside a section.  Asserting the invariant
    # over the second sort is what made this harness demand that 0x3b live in
    # .data.  See crates/rf-chain/src/lib.rs's `WordKind::DataAddr` doc, which
    # has said "and on Windows also numeric stack arguments" since v0.1.
    sec = found["argv_section"]
    lo = argv_addr
    hi = argv_addr + int(sec["size"], 16) if isinstance(sec["size"], str) else argv_addr + sec["size"]
    data_words = [
        int(w["value"], 16)
        for w in ir["words"]
        if w["kind"] == "data_addr" and w.get("comment", "").startswith("@ ")
    ]
    check(data_words, "the chain writes no data address")
    check(
        all(lo <= a < hi for a in data_words),
        f"chain data addresses {[hex(a) for a in data_words]} are outside "
        f"{sec['name']} [{hex(lo)}, {hex(hi)})",
    )
    # The gadget class found in step 2 has to be one the chain relies on.
    texts = {g["text"] for g in ir["gadgets"]}
    check(
        any(t.startswith("pop rdi") for t in texts),
        f"the chain sets rdi some other way: {sorted(texts)}",
    )
    found["chain"] = chain
    print(f"  4. chain: {chain['word_count']} words, {len(ir['gadgets'])} distinct gadgets, "
          f"{len(chain['python'])}-char script; /bin/sh written to "
          f"{[hex(a) for a in sorted(set(data_words))]}")
    return found


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--budget", type=int, default=DEFAULT_BUDGET_TOKENS,
                    help=f"token budget for the whole loop (default {DEFAULT_BUDGET_TOKENS})")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="dump every request and response")
    args = ap.parse_args()

    exe = rf_paths.rop_finder(package="rf-mcp", stem="rop-finder-mcp")
    fixtures = rf_paths.FIXTURES
    binary = os.path.join(fixtures, FIXTURE)
    if not os.path.exists(binary):
        sys.exit(f"missing fixture {binary} (run tests/fetch_fixtures.py)")

    # The premise of step 1: this binary really has no /bin/sh string, so the
    # chain has to write one. Asserted, not assumed.
    with open(binary, "rb") as fh:
        blob = fh.read()
    if b"/bin/sh" in blob or b"/bin//sh" in blob:
        sys.exit(f"{FIXTURE} now contains a /bin/sh string; step 1's premise is stale")

    # A working directory the server is NOT allowed to read from, so the run
    # also demonstrates that the allowlist is the only way in.
    cwd = tempfile.mkdtemp(prefix="rf-workability-")
    print(f"# server: {exe}")
    print(f"# allow-dir: {fixtures}")
    print(f"# target: {FIXTURE} ({len(blob)} bytes, no /bin/sh string)\n")

    mcp = Mcp(exe, fixtures, cwd, verbose=args.verbose)
    try:
        run_loop(mcp, binary)
    finally:
        usage = list(mcp.usage)
        mcp.close()
        shutil.rmtree(cwd, ignore_errors=True)

    wire = sum(u[1] for u in usage)
    rendered = sum(u[2] for u in usage)
    print(f"\n{'step':<22}{'rendered':>10}{'wire':>10}{'~tok rendered':>15}{'~tok wire':>11}")
    for label, w, r in usage:
        print(f"{label:<22}{r:>10}{w:>10}"
              f"{r // CHARS_PER_TOKEN:>15}{w // CHARS_PER_TOKEN:>11}")
    print(f"{'TOTAL':<22}{rendered:>10}{wire:>10}"
          f"{rendered // CHARS_PER_TOKEN:>15}{wire // CHARS_PER_TOKEN:>11}")

    wire_tokens = wire / CHARS_PER_TOKEN
    rendered_tokens = rendered / CHARS_PER_TOKEN
    print(
        f"\nmethod: characters / {CHARS_PER_TOKEN}"
        f"\n  rendered = content[*].text only         = {rendered} chars"
        f" = {rendered_tokens:.0f} tokens"
        f"\n  wire     = whole result, both copies    = {wire} chars"
        f" = {wire_tokens:.0f} tokens"
        f"\n  budget   = {args.budget} tokens"
    )

    ok = rendered_tokens < args.budget
    verdict = "PASS" if ok else "FAIL"
    cmp_r = "<" if ok else ">="
    print(f"\nGATE      (rendered): {verdict} -- {rendered_tokens:.0f} {cmp_r} "
          f"{args.budget} tokens"
          f"{f', {100.0 * (1 - rendered_tokens / args.budget):.1f}% under budget' if ok else ''}")
    wire_ok = wire_tokens < args.budget
    print(f"ADVISORY  (wire)    : {'PASS' if wire_ok else 'FAIL'} -- "
          f"{wire_tokens:.0f} {'<' if wire_ok else '>='} {args.budget} tokens"
          + ("" if wire_ok else
             "  <-- the payload is sent TWICE (content[0].text + structuredContent);"
             " not gated, see the module docstring"))

    print(f"\nWORKABILITY GATE: {verdict}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
