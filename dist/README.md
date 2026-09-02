# rop-finder — prebuilt binaries

ROP/JOP/syscall gadget finder + ROP chain builder + MCP server.
Rust rewrite of ROPgadget: 99.93% gadget parity, ~2–20× faster.

## Layout

| Folder | Contents | Status |
|---|---|---|
| `windows-x86_64/` | `rop-finder.exe`, `rop-finder-mcp.exe` | ✅ built & tested on Windows 11 |
| `linux-x86_64/` | `rop-finder`, `rop-finder-mcp` | ✅ built & tested (static musl — runs on any x86_64 Linux, no glibc dependency) |
| `macos-arm64/` | `build-macos.sh` | ⚠️ run the script on any Mac (Intel or Apple Silicon) — see below |

## Why no prebuilt macOS binary?

macOS binaries cannot be cross-compiled without the Apple SDK (Xcode), which
is license-restricted to Apple hardware. Run `build-macos.sh` on any Mac —
it installs Rust if needed, builds, and drops the binaries next to itself
(~2 minutes).

## Quick start

```sh
# Find gadgets
rop-finder --binary /path/to/binary --depth 10

# JSON output, only .text, RVA addresses (ASLR workflow)
rop-finder --binary ntoskrnl.exe --section .text --base 0 --json

# Build a ROP chain
rop-finder --binary ./vuln-binary --ropchain                              # Linux execve
rop-finder --binary ./pe.exe --ropchain --chain windows-virtualprotect \
    --api-addr 0x7fff12340000                                             # Windows

# MCP server for AI agents (stdio)
rop-finder-mcp --allow-dir /path/to/binaries
```

Full docs: `../README.md`
