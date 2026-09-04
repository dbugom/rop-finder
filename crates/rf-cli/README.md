# rop-finder

A fast, memory-safe ROP/JOP/SYS gadget finder: a Rust rewrite of
[ROPgadget](https://github.com/JonathanSalwan/ROPgadget) that aims at output
parity with it, plus semantic classification, constraint queries and chain
generation.

```sh
cargo install rop-finder
rop-finder --binary /bin/ls --depth 10
```

`cargo install` builds one executable, `rop-finder`. A C toolchain is
required: `rop-finder-scan` builds the vendored C capstone that drives every
non-x86 architecture.

```sh
rop-finder --binary ./prog --only "pop|ret" --badbytes "0a|0d"
rop-finder --binary ./prog --classify --rank --format json
rop-finder --binary ./prog --set-reg rdi --terminator ret   # constraint query
rop-finder --binary ./prog --info                          # metadata, no scan
rop-finder --binary ./elf --ropchain                       # execve("/bin/sh")
```

* **Parity, measured:** 763,166 of 763,204 reference gadgets reproduced
  (99.995%) across 24 fixtures spanning every supported format and
  architecture. The harness and the recorded divergences ship with the
  repository.
* **Formats:** ELF, PE, Mach-O, fat Mach-O, raw. **Architectures:** x86,
  x64, ARM (incl. Thumb), ARM64, MIPS32/64, PPC32/64, SPARC(V9), RISC-V
  32/64.
* **Output:** ROPgadget-compatible text, or `--format json|jsonl|csv`. Parse
  the structured forms; the text listing tracks ROPgadget and is not covered
  by semver.

Full documentation — installation, concepts, the whole flag reference, the
ROPgadget flag-coverage table, the known divergences and nine worked
scenarios — is in the repository's `MANUAL.md`. The MCP server for agent
hosts is the separate `rop-finder-mcp` package.

## Library use

**Do not depend on this crate as a library.** It exposes one (its `[lib]`
target is `rf_cli`) so the MCP server and the tests can call what the binary
calls, but it carries clap types and output formatting, and
`docs/API-STABILITY.md` excludes it from every promise.

The supported programmatic surface is `rop-finder-api` (`rf_api`), with
`rop-finder-core`, `rop-finder-scan`, `rop-finder-classify` and
`rop-finder-chain` underneath it.

## Notes

* MSRV 1.88.
* The package is `rop-finder`; the executable is `rop-finder`; the internal
  library target is `rf_cli`.
* BSD-2-Clause (`LICENSE`). rop-finder is a derivative work of ROPgadget in
  behaviour and in ported algorithms — see `NOTICE` in the repository for the
  attribution it owes.
