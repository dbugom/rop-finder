#!/usr/bin/env bash
# Build static-musl Linux binaries. Static because an MCP host may launch this
# under any glibc, or none.
#
#   ./dist/build-linux.sh              # x86_64
#   ./dist/build-linux.sh --arch aarch64
#
# Output: dist/build/linux-<arch>/{rop-finder,rop-finder-mcp,SHA256SUMS,*.tar.gz}
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$REPO"

ARCH=x86_64
while [ $# -gt 0 ]; do
  case "$1" in
    --arch) ARCH="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
TARGET="${ARCH}-unknown-linux-musl"

# rf-scan depends on capstone-sys, which compiles ~44 MB of vendored C. A musl
# *C* toolchain is required, not just a Rust musl std. Three ways, in order of
# preference; the script picks whichever is present.
if command -v cross >/dev/null 2>&1; then
  echo "==> using cross (carries a musl C toolchain in its image)"
  BUILD=(cross build --release --locked --target "$TARGET" -p rop-finder -p rop-finder-mcp)
elif command -v "${ARCH}-linux-musl-gcc" >/dev/null 2>&1; then
  echo "==> using ${ARCH}-linux-musl-gcc"
  export "CC_${TARGET//-/_}=${ARCH}-linux-musl-gcc"
  export "CARGO_TARGET_$(echo "$TARGET" | tr 'a-z-' 'A-Z_')_LINKER=${ARCH}-linux-musl-gcc"
  BUILD=(cargo build --release --locked --target "$TARGET" -p rop-finder -p rop-finder-mcp)
elif command -v zig >/dev/null 2>&1 || [ -x "$HOME/zig/zig" ]; then
  # Fallback used to produce the shipped v1.0.0-rc1 Linux artifacts on a host
  # with no C compiler and no root. zig is a self-contained toolchain.
  ZIG="$(command -v zig || echo "$HOME/zig/zig")"
  echo "==> using zig cc at $ZIG"
  mkdir -p "$REPO/dist/.zigshim"
  cat > "$REPO/dist/.zigshim/zcc" <<EOF
#!/bin/sh
# rustc and cc-rs emit --target=<arch>-unknown-linux-{gnu,musl}; zig rejects
# that spelling with UnknownOperatingSystem. Rewrite to zig triple form.
n=\$#; i=0
while [ \$i -lt \$n ]; do
  a=\$1; shift
  case "\$a" in
    --target=*-unknown-linux-gnu)  a="--target=\$(echo "\$a" | sed 's|--target=\(.*\)-unknown-linux-gnu|\1-linux-gnu|')" ;;
    --target=*-unknown-linux-musl) a="--target=\$(echo "\$a" | sed 's|--target=\(.*\)-unknown-linux-musl|\1-linux-musl|')" ;;
  esac
  set -- "\$@" "\$a"; i=\$((i+1))
done
exec "$ZIG" cc "\$@"
EOF
  chmod +x "$REPO/dist/.zigshim/zcc"
  Z="$REPO/dist/.zigshim/zcc"
  export CC="$Z" CXX="$Z"
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$Z"   # host build scripts
  export "CARGO_TARGET_$(echo "$TARGET" | tr 'a-z-' 'A-Z_')_LINKER=$Z"
  # zig ships its own musl CRT and so does rustc's self-contained/ dir; both
  # define _init/_fini. Defer to zig, then force static back on explicitly --
  # link-self-contained=no otherwise silently yields a glibc-DYNAMIC binary.
  export "CARGO_TARGET_$(echo "$TARGET" | tr 'a-z-' 'A-Z_')_RUSTFLAGS=-C link-self-contained=no -C target-feature=+crt-static -C link-arg=-static -C link-arg=--target=${ARCH}-linux-musl --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${REPO}=/src"
  BUILD=(cargo build --release --locked --target "$TARGET" -p rop-finder -p rop-finder-mcp)
else
  echo "error: need one of: cross, ${ARCH}-linux-musl-gcc, or zig" >&2
  echo "       cargo install cross   |   apt install musl-tools   |   https://ziglang.org/download/" >&2
  exit 1
fi

rustup target list --installed | grep -qx "$TARGET" || rustup target add "$TARGET"
echo "==> ${BUILD[*]}"; "${BUILD[@]}"

OUT="$REPO/dist/build/linux-$ARCH"; rm -rf "$OUT"; mkdir -p "$OUT"
cd "target/$TARGET/release"
chmod 0755 rop-finder rop-finder-mcp
cp rop-finder rop-finder-mcp "$OUT/"
cd "$OUT"

# A static binary is the whole point -- fail loudly if it is not one.
if command -v file >/dev/null 2>&1; then
  file rop-finder | grep -q "statically linked" \
    || { echo "error: rop-finder is NOT statically linked:"; file rop-finder; exit 1; }
fi
echo "==> verified statically linked"

sha256sum rop-finder rop-finder-mcp > SHA256SUMS
tar -czf "rop-finder-linux-$ARCH-musl.tar.gz" --owner=0 --group=0 --mode=0755 rop-finder rop-finder-mcp
sha256sum "rop-finder-linux-$ARCH-musl.tar.gz" >> SHA256SUMS

echo "==> smoke test"; ./rop-finder --version | head -1
echo; ls -l; cat SHA256SUMS
