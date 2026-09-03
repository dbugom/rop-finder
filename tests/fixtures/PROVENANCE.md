# tests/fixtures — provenance and licensing

**These 24 files are NOT covered by this repository's LICENSE.** The workspace
declares `license = "BSD-2-Clause"`; this directory is explicitly carved out of
that declaration. Each file below is a byte-identical redistribution of a
third-party compiled binary, and is governed by whatever license or agreement
its own rights holder applies. Several of them — Microsoft's `cmd.exe`, Apple's
`ls` and `libSystem.B.dylib` — are **not redistributable at all** under the
terms their vendors publish.

If you fork, mirror, vendor or repackage this repository, you inherit that
exposure. `tests/fetch_fixtures.py` exists so you do not have to: it re-fetches
all 24 from upstream on demand and verifies them against `MANIFEST.sha256`, so
you can delete the copies and still run the parity suite.

## Where they came from

All 24 are SHA-256-identical to the files in `test-suite-binaries/` of

> ROPgadget — https://github.com/JonathanSalwan/ROPgadget
> pinned commit `b6e3fe31af46d7e045fef99a3ab19ccbcea5c2f6` (ROPgadget v7.7)

They are used as this project's output-parity corpus (see
`docs/measured-2026-09.md`). ROPgadget redistributes them under its own
repository-wide `LICENSE_BSD.txt` with no per-file notice — that is the upstream
condition this file corrects for our copies. The ROPgadget copyright notice and
license text are reproduced in the repository's `NOTICE`.

**The upstream corpus is 25 files, not 24.** `test-suite-binaries/core`
(SHA-256 `f868ce6d349aa491cb18caec19da78f07419601fd0516a6025ab734475af53b3`,
300 KB, an `ET_CORE` i386 core dump of `elf-Linux-x86-NDH-chall` that records
the invoking user's uid/gid and command line) is deliberately **not** copied
here. Any statement that this project achieves parity on "all 25 test-suite
binaries" is wrong; the corpus is 24 and the `ET_CORE` loader path is untested.

## How the identifications below were made

Every claim in the per-file sections is read out of the file itself and is
reproducible: ELF/PE/Mach-O headers, the ELF `.comment` and `SYMTAB` sections
(`STT_FILE` entries name the original source files), the `@(#)` version
identifiers GNU tools embed, PE `VS_VERSION_INFO` resources, and Mach-O load
commands. Where a fact is *not* recoverable from the bytes — who built a given
binary, from which distribution package — this file says so rather than
guessing.

Checksums for all 24 are in `MANIFEST.sha256` (`sha256sum -c MANIFEST.sha256`).

## Summary

| File | What it actually is | Rights holder | License / terms | Redistributable? |
|---|---|---|---|---|
| `Linux_lib32.so` | cairo 1.12.14, `libcairo.so.2`, i386 | cairo project | LGPL-2.1-or-later **or** MPL-1.1 (dual) | yes, with source offer |
| `Linux_lib64.so` | cairo 1.12.14, `libcairo.so.2`, x86-64 | cairo project | LGPL-2.1-or-later **or** MPL-1.1 (dual) | yes, with source offer |
| `UNIVERSAL-x86-x64-libSystem.B.dylib` | Apple `libSystem.B.dylib`, `Libsystem-1197.1.1`, fat i386+x86-64 | Apple Inc. | macOS Software License Agreement | **no** |
| `elf-ARM64-bash` | GNU bash 4.2.45(1), aarch64 | Free Software Foundation | GPL-3.0-or-later | yes, with source offer |
| `elf-ARMv7-ls` | GNU coreutils 8.21 `ls`, ARM EABI5 | Free Software Foundation | GPL-3.0-or-later | yes, with source offer |
| `elf-FreeBSD-x86` | ROPgadget test program (`main_freebsd.c`), static, FreeBSD 8.2 libc | ROPgadget authors + FreeBSD Project | ROPgadget `LICENSE_BSD.txt` + BSD-2-Clause (FreeBSD base) | yes |
| `elf-Linux-RISCV_32` | ROPgadget test program (`hello.cpp`), rv32gc, GCC 9.2.0 | ROPgadget authors | ROPgadget `LICENSE_BSD.txt` (+ glibc CRT, LGPL-2.1-or-later) | yes |
| `elf-Linux-RISCV_64` | ROPgadget test program (`ch91.c`), rv64gc | ROPgadget authors | ROPgadget `LICENSE_BSD.txt` (+ glibc CRT, LGPL-2.1-or-later) | yes |
| `elf-Linux-x64` | ROPgadget test program (`main_linux.c`), static glibc, x86-64 | ROPgadget authors + FSF (glibc) | ROPgadget `LICENSE_BSD.txt` + LGPL-2.1-or-later | yes, with source offer |
| `elf-Linux-x86` | ROPgadget test program (`main_linux.c`), static glibc, i386 | ROPgadget authors + FSF (glibc) | ROPgadget `LICENSE_BSD.txt` + LGPL-2.1-or-later | yes, with source offer |
| `elf-Linux-x86-NDH-chall` | Nuit du Hack CTF challenge (`ndh_rop.c`), static glibc, i386 | challenge author (unidentified) | **unknown** | unclear |
| `elf-Mips-Defcon-20-pwn100` | DEF CON 20 CTF `pwn100` challenge, static MIPS-I | challenge author (unidentified) | **unknown** | unclear |
| `elf-PPC64-bash` | GNU bash 5.1.16(1), ppc64 ELFv2 | Free Software Foundation | GPL-3.0-or-later | yes, with source offer |
| `elf-PowerPC-bash` | GNU bash 4.2.45(1), 32-bit big-endian PowerPC | Free Software Foundation | GPL-3.0-or-later | yes, with source offer |
| `elf-SparcV8-bash` | GNU bash 4.1.5(1), SPARC32PLUS | Free Software Foundation | GPL-3.0-or-later | yes, with source offer |
| `elf-x64-bash-v4.1.5.1` | GNU bash 4.1.5(1), x86-64 | Free Software Foundation | GPL-3.0-or-later | yes, with source offer |
| `elf-x86-bash-v4.1.5.1` | GNU bash 4.1.5(1), i386 | Free Software Foundation | GPL-3.0-or-later | yes, with source offer |
| `macho-ppc-openssl` | OpenSSL 1.0.1h `openssl` CLI, Mach-O ppc7400 | OpenSSL Project / Eric Young | OpenSSL License **and** SSLeay License (dual, both apply) | yes, with notices |
| `macho-x64-ls` | Apple macOS `/bin/ls`, x86-64, Apple-code-signed | Apple Inc. | macOS Software License Agreement | **no** |
| `macho-x86-ls` | Apple macOS `/bin/ls`, i386, Apple-code-signed | Apple Inc. | macOS Software License Agreement | **no** |
| `pe-Windows-ARMv7-Thumb2LE-HelloWorld` | Visual Studio "Win32Project1" hello-world, ARMv7 Thumb-2 | contributor (unidentified) + Microsoft (CRT) | ROPgadget `LICENSE_BSD.txt`; CRT under Visual Studio redist terms | probably |
| `pe-x64-cmd-v6.1.7601` | Microsoft Windows Command Processor 6.1.7601.17514, x86-64 | Microsoft Corporation | Windows 7 EULA | **no** |
| `pe-x86-cmd-v6.1.7600` | Microsoft Windows Command Processor 6.1.7600.16385, i386 | Microsoft Corporation | Windows 7 EULA | **no** |
| `raw-x86.raw` | 19 bytes of headerless x86 machine code | ROPgadget authors | ROPgadget `LICENSE_BSD.txt` | yes |

"Redistributable?" is a summary for triage, not legal advice. Get your own
counsel before mirroring this directory.

---

## Per-file detail

### Not redistributable — vendor operating-system binaries

#### `pe-x64-cmd-v6.1.7601`, `pe-x86-cmd-v6.1.7600`

Microsoft Windows `cmd.exe`. The PE `VS_VERSION_INFO` resource reads
`CompanyName: Microsoft Corporation`, `FileDescription: Windows Command
Processor`, `InternalName: Cmd.Exe`, `LegalCopyright: (c) Microsoft
Corporation. All rights reserved.`, and:

| File | FileVersion | Build tag | Machine |
|---|---|---|---|
| `pe-x64-cmd-v6.1.7601` | `6.1.7601.17514` | `win7sp1_rtm.101119-1850` | PE32+ x86-64 |
| `pe-x86-cmd-v6.1.7600` | `6.1.7600.16385` | `win7_rtm.090713-1255` | PE32 i386 |

These are Windows 7 RTM and Windows 7 SP1 system files. The Windows EULA
licenses the operating system to a licensed device; it does not grant a right to
extract and redistribute system binaries. **Do not mirror these.** Anyone with a
Windows 7 licence can supply their own copy at
`C:\Windows\System32\cmd.exe` — compare with `MANIFEST.sha256` to confirm you
have the same build.

#### `macho-x64-ls`, `macho-x86-ls`

Apple's macOS `/bin/ls`. Both carry `com.apple.ls` as the code-signing
identifier and an Apple code-signature chain (`Apple Root CA` → `Apple
Certification Authority` → `Apple Code Signing Certification Authority`), and
link `/usr/lib/libSystem.B.dylib`. `macho-x64-ls` is x86-64 PIE;
`macho-x86-ls` is i386 PIE with `NO_HEAP_EXECUTION`.

The *source* for Apple's `ls` ships in the `file_cmds` project under APSL-2.0,
but these files are the compiled, Apple-signed binaries distributed as part of
macOS, and the macOS Software License Agreement governs them. **Not
redistributable.**

#### `UNIVERSAL-x86-x64-libSystem.B.dylib`

Apple's `libSystem.B.dylib`, a Mach-O universal (fat) binary containing x86-64
and i386 slices. Embedded identifier: `@(#)PROGRAM:System.B
PROJECT:Libsystem-1197.1.1`. It re-exports the `/usr/lib/system/libsystem_*`
family (`libsystem_c`, `libsystem_kernel`, `libsystem_asl`, …). Apple-signed;
governed by the macOS Software License Agreement. **Not redistributable.**

This file is also the only fat/universal fixture, so it is the sole coverage for
the `universal` loader path.

### GPL — redistributable, but with a source offer attached

#### `elf-x86-bash-v4.1.5.1`, `elf-x64-bash-v4.1.5.1`, `elf-SparcV8-bash`

GNU bash. All three embed `@(#)Bash version 4.1.5(1) release GNU` and the
runtime banner `License GPLv3+: GNU GPL version 3 or later
<http://gnu.org/licenses/gpl.html>`; `elf-x64-bash-v4.1.5.1` carries
`Copyright (C) 2009 Free Software Foundation, Inc.`. Architectures: i386,
x86-64, and SPARC32PLUS (V8+ Required, big-endian). Dynamically linked against
glibc.

#### `elf-ARM64-bash`, `elf-PowerPC-bash`

GNU bash 4.2.45(1) (`@(#)Bash version 4.2.45(1) release GNU`), `Copyright (C)
2011 Free Software Foundation, Inc.`, GPLv3+. aarch64 and 32-bit big-endian
PowerPC respectively.

#### `elf-PPC64-bash`

GNU bash 5.1.16(1) (`@(#)Bash version 5.1.16(1) release GNU`), `Copyright (C)
2020 Free Software Foundation, Inc.`, GPLv3+. 64-bit PowerPC, OpenPOWER ELF V2
ABI, PIE.

#### `elf-ARMv7-ls`

GNU coreutils `ls`, version string `8.21`, with the coreutils help footer
(`bug-coreutils@gnu.org`, `http://www.gnu.org/software/coreutils/`). ARM EABI5,
dynamically linked. GPL-3.0-or-later.

**GPL obligation.** Distributing these binaries carries a corresponding-source
obligation (GPLv3 §6). Neither this project nor ROPgadget ships that source or a
written offer, and the exact upstream package each was built from is not
recorded in the binary. This is the strongest practical argument for deleting
the in-tree copies and using `tests/fetch_fixtures.py` instead. Matching source
is available from the GNU project: <https://ftp.gnu.org/gnu/bash/> and
<https://ftp.gnu.org/gnu/coreutils/>.

### LGPL / dual-licensed libraries

#### `Linux_lib32.so`, `Linux_lib64.so`

Not "Linux libraries" in any generic sense despite the names: both are builds of
**cairo**, `SONAME = libcairo.so.2`, embedded version string `1.12.14`. They
export the full `cairo_*` / `_cairo_*` surface (`cairo_version`,
`cairo_version_string`, `_cairo_surface_release_source_image`, the PS/script
surface backends) and link `libpixman-1.so.0`, `libfontconfig.so.1`,
`libfreetype.so.6`, `libXrender.so.1`, `libEGL.so.1`, plus `libpng15.so.15`
(32-bit) / `libpng16.so.16` (64-bit). Both are stripped. i386 and x86-64.

cairo is dual-licensed: LGPL-2.1-or-later **or** MPL-1.1, at the recipient's
option (<https://www.cairographics.org>). Redistribution of the compiled library
is permitted under either, with the usual notice and relinking/source
obligations. The distributor who built these is not recorded in the files.

#### `macho-ppc-openssl`

The OpenSSL `openssl` command-line tool, Mach-O `ppc_7400` executable. It links
`/usr/local/Cellar/openssl/1.0.1h/lib/libssl.1.0.0.dylib` and
`.../libcrypto.1.0.0.dylib` — a Homebrew-installed **OpenSSL 1.0.1h** — and
contains OpenSSL's own strings (`OpenSSL> `, `OPENSSL_CONF`, `OPENSSL_FIPS`,
`openssl:Error: '%s' is an invalid command.`).

OpenSSL 1.0.x predates the project's 2018 move to Apache-2.0: it is governed by
the dual **OpenSSL License and original SSLeay License**, both of which apply
simultaneously and both of which carry advertising/acknowledgement clauses
(Eric Young, Tim Hudson). This is the only PowerPC Mach-O fixture, so it is the
sole coverage for that loader path.

### ROPgadget's own test programs, and CTF challenge binaries

#### `elf-Linux-x86`, `elf-Linux-x64`, `elf-FreeBSD-x86`

The same tiny purpose-built test program, compiled three ways. The `STT_FILE`
symbols name the original source: `main_linux.c` for the two Linux builds and
`main_freebsd.c` for the FreeBSD one. Each is statically linked, so the file is
overwhelmingly libc by volume:

* `elf-Linux-x86` / `elf-Linux-x64` — `.comment` reads
  `GCC: (Gentoo 4.7.3-r1 p1.4, pie-0.5.5) 4.7.3`; static **glibc**
  (LGPL-2.1-or-later, with some GPL-licensed components in a static link) for
  GNU/Linux 2.6.16+.
* `elf-FreeBSD-x86` — `.comment` reads `GCC: (GNU) 4.2.1 20070719 [FreeBSD]`
  with `$FreeBSD: src/lib/csu/i386-elf/crt1_s.S,v ... 2011/01/22 $`; static
  **FreeBSD 8.2 base libc**, which is BSD-2-Clause.

The program itself is ROPgadget test material, covered by ROPgadget's
`LICENSE_BSD.txt`. The static libc payload carries its own terms — for the glibc
builds, an LGPL relinking/source obligation.

#### `elf-Linux-RISCV_32`, `elf-Linux-RISCV_64`

Small purpose-built RISC-V test programs, added upstream when RISC-V support
landed (ROPgadget's `AUTHORS` credits `0xMirasio` with "RISC-V 64 and
Compressed"). Both are unstripped and retain DWARF.

* `elf-Linux-RISCV_32` — source `hello.cpp`; `GCC: (GNU) 9.2.0`, `GNU AS 2.32`,
  `-march=rv32gc -mabi=ilp32d -mtune=rocket`; glibc 2.29.
* `elf-Linux-RISCV_64` — source `ch91.c`; imports `system`, `read`, `puts`,
  `fflush` from glibc 2.27 — i.e. a deliberate ROP target.

Covered by ROPgadget's `LICENSE_BSD.txt`; the linked glibc CRT is
LGPL-2.1-or-later.

#### `elf-Linux-x86-NDH-chall`

A CTF challenge binary: `STT_FILE` names the source `ndh_rop.c`, and the
upstream filename expands "NDH" to the **Nuit du Hack** CTF — that expansion is
inference from the two names, not something the bytes state. Statically linked
i386 glibc, for GNU/Linux 2.6.27.

The challenge author is not identified in the binary and no license accompanies
it upstream. **Its redistribution terms are unknown.** Treat it the way you
would any CTF artifact of unclear provenance.

#### `elf-Mips-Defcon-20-pwn100`

A statically linked big-endian MIPS-I executable, stripped, whose `.rodata` is a
corpus of quotation strings used by the challenge. The attribution to the
`pwn100` challenge of the **DEF CON 20 CTF (2012)** comes from the upstream
filename; nothing inside the binary states it. As with the NDH binary: no
author, no license, **terms unknown**.

#### `pe-Windows-ARMv7-Thumb2LE-HelloWorld`

A Visual Studio hello-world for Windows on ARM. The PE debug directory retains
the builder's PDB path,
`D:\Downloads\tmp\Win32Project1\ARM\Release\Win32Project1.pdb`, and the program
prints `Hiya, I'm a PE ARM!`. PE32, ARMv7 Thumb-2 little-endian, subsystem
version 6.02, 6 sections, `asInvoker` manifest, linked against the Microsoft C
runtime (`__getmainargs`).

Contributed to ROPgadget's test suite and covered by its `LICENSE_BSD.txt`; the
statically linked Microsoft CRT fragments are subject to the Visual Studio
redistribution terms. This is the only ARM PE fixture.

#### `raw-x86.raw`

19 bytes with no container format:

```
31 c9 89 48 04 89 08 89 48 08 0b 4c 24 08 89 01 31 c0 c3
```

It exists to exercise the `--rawArch` / `--rawMode` headerless path. Part of
ROPgadget's test suite, covered by its `LICENSE_BSD.txt`; at this length there
is nothing meaningfully copyrightable in it.

---

## If you would rather not hold these copies

```sh
# from the repo root — removes the 24 binaries and nothing else
python tests/fetch_fixtures.py --list | xargs -I{} rm -f tests/fixtures/{}

# ...and put them back, verified, whenever you need to run the parity suite
python tests/fetch_fixtures.py
```

`tests/fetch_fixtures.py --verify-only` checks what is already on disk without
touching the network, and is the check CI runs. The in-tree copies are kept by
default precisely so that CI and the parity gate never depend on GitHub being
reachable.
