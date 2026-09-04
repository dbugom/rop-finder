#!/usr/bin/env bash
# Build rop-finder and rop-finder-mcp for macOS.
#
#   ./dist/build-macos.sh                 # native (Apple Silicon -> arm64)
#   ./dist/build-macos.sh --universal     # arm64 + x86_64 lipo'd into one binary
#   ./dist/build-macos.sh --sign "Developer ID Application: NAME (TEAMID)"
#   ./dist/build-macos.sh --universal --sign "..." --notarize-profile my-profile
#
# Output: dist/build/macos-<arch>/{rop-finder,rop-finder-mcp} + SHA256SUMS
#         and a .tar.gz, because a plain download loses the executable bit and
#         that is exactly how the pre-v0.1.1 dist/ binaries shipped unrunnable
#         (finding ENG-09).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

UNIVERSAL=0; SIGN_ID=""; NOTARY_PROFILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --universal)        UNIVERSAL=1; shift ;;
    --sign)             SIGN_ID="${2:?--sign needs a Developer ID}"; shift 2 ;;
    --notarize-profile) NOTARY_PROFILE="${2:?--notarize-profile needs a name}"; shift 2 ;;
    -h|--help)          sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- preflight
[ "$(uname -s)" = "Darwin" ] || { echo "error: this script must run on macOS" >&2; exit 1; }

# rf-scan depends on capstone-sys, which compiles ~44 MB of vendored C with the
# `cc` crate. That needs a working C toolchain -- on macOS that means the Xcode
# Command Line Tools. Without them the build fails deep inside a build script
# with an unhelpful message, so check up front.
if ! xcode-select -p >/dev/null 2>&1; then
  echo "error: Xcode Command Line Tools are required (capstone-sys builds vendored C)." >&2
  echo "       run:  xcode-select --install" >&2
  exit 1
fi
command -v cargo >/dev/null || { echo "error: cargo not found. https://rustup.rs" >&2; exit 1; }

# The workspace pins a toolchain in rust-toolchain.toml; rustup honours it
# automatically. MSRV is 1.88 (ENG-07) and CI enforces it.
echo "==> $(cargo --version)"
echo "==> $(rustc --version)"

HOST_ARCH="$(uname -m)"   # arm64 on Apple Silicon, x86_64 on Intel
if [ "$UNIVERSAL" = "1" ]; then
  TARGETS=(aarch64-apple-darwin x86_64-apple-darwin); OUT_ARCH=universal
elif [ "$HOST_ARCH" = "arm64" ]; then
  TARGETS=(aarch64-apple-darwin); OUT_ARCH=arm64
else
  TARGETS=(x86_64-apple-darwin); OUT_ARCH=x86_64
fi

for t in "${TARGETS[@]}"; do
  rustup target list --installed | grep -qx "$t" || { echo "==> rustup target add $t"; rustup target add "$t"; }
done

# ---------------------------------------------------------------- build
# Strip the build machine out of the binary. `strip = "symbols"` in
# [profile.release] drops the symbol table, but panic locations come from the
# file!() macro and are baked in as &'static str -- only --remap-path-prefix
# removes those, and it cannot be expressed in a profile. ENG-09 again: the old
# Windows binary embedded the maintainer's home directory 178 times.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${REPO}=/src"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || echo 0)}"

BINS=(rop-finder rop-finder-mcp)
for t in "${TARGETS[@]}"; do
  echo "==> cargo build --release --locked --target $t"
  cargo build --release --locked --target "$t" -p rop-finder -p rop-finder-mcp
done

OUT="$REPO/dist/build/macos-$OUT_ARCH"
rm -rf "$OUT"; mkdir -p "$OUT"

for b in "${BINS[@]}"; do
  if [ "$UNIVERSAL" = "1" ]; then
    lipo -create -output "$OUT/$b" \
      "target/aarch64-apple-darwin/release/$b" \
      "target/x86_64-apple-darwin/release/$b"
    lipo -info "$OUT/$b"
  else
    cp "target/${TARGETS[0]}/release/$b" "$OUT/$b"
  fi
  chmod 0755 "$OUT/$b"
done

# ---------------------------------------------------------------- sign
# An unsigned binary downloaded from the internet is quarantined by Gatekeeper,
# and Claude Desktop's MCP spawn then fails with no visible error -- the failure
# mode looks like "the server is broken", not "the binary is quarantined".
if [ -n "$SIGN_ID" ]; then
  for b in "${BINS[@]}"; do
    echo "==> codesign $b"
    codesign --force --options runtime --timestamp --sign "$SIGN_ID" "$OUT/$b"
    codesign --verify --strict --verbose=2 "$OUT/$b"
  done
else
  echo "==> NOT code signed. For distribution: --sign \"Developer ID Application: NAME (TEAMID)\"" >&2
  echo "    A user who downloads this will need:  xattr -d com.apple.quarantine <binary>" >&2
fi

# ---------------------------------------------------------------- package
cd "$OUT"
shasum -a 256 "${BINS[@]}" > SHA256SUMS
TARBALL="rop-finder-macos-$OUT_ARCH.tar.gz"
tar -czf "$TARBALL" "${BINS[@]}" SHA256SUMS
shasum -a 256 "$TARBALL" >> SHA256SUMS

# ---------------------------------------------------------------- notarize
if [ -n "$NOTARY_PROFILE" ]; then
  [ -n "$SIGN_ID" ] || { echo "error: --notarize-profile requires --sign" >&2; exit 2; }
  echo "==> notarytool submit --wait (profile: $NOTARY_PROFILE)"
  xcrun notarytool submit "$TARBALL" --keychain-profile "$NOTARY_PROFILE" --wait
  # A bare executable cannot be stapled -- the ticket attaches to a container.
  # Gatekeeper falls back to an online check for loose binaries, which is why
  # notarization still matters even without a staple.
  echo "==> notarized. (Bare executables cannot be stapled; ship the .tar.gz.)"
fi

# ---------------------------------------------------------------- verify
echo
echo "==> smoke test"
./rop-finder --version
./rop-finder --binary "$REPO/tests/fixtures/elf-Linux-x86" --depth 4 | head -3
printf '%s\n' '--- verify the shipped binary leaks no build path (ENG-09) ---'
for b in "${BINS[@]}"; do
  n=$(LC_ALL=C grep -ac -e "$HOME" -e "$(basename "$HOME")" "$b" || true)
  printf '    %-16s build-path hits: %s\n' "$b" "${n:-0}"
done
echo
echo "==> artifacts in $OUT"
ls -l
cat SHA256SUMS
