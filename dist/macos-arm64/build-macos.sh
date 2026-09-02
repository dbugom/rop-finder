#!/bin/sh
# Build rop-finder natively on macOS (Intel x86_64 or Apple Silicon arm64).
#
# Why a script instead of a prebuilt binary: macOS binaries cannot be
# cross-compiled from Windows/Linux without the Apple SDK (Xcode), which is
# license-restricted to Apple hardware. Building natively on any Mac takes
# ~2 minutes with this script.
#
# Prerequisites: Xcode Command Line Tools (xcode-select --install) — provides
# the C compiler needed by the bundled capstone library.
set -e

if ! command -v cargo >/dev/null 2>&1; then
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    . "$HOME/.cargo/env"
fi

# Resolve the repo root (this script lives in dist/macos-*/)
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
cd "$REPO_ROOT"

echo "Building rop-finder + rop-finder-mcp (release)..."
cargo build --release -p rf-cli -p rf-mcp

mkdir -p "$SCRIPT_DIR"
cp target/release/rop-finder target/release/rop-finder-mcp "$SCRIPT_DIR/"
echo "Done. Binaries placed in: $SCRIPT_DIR"
"$SCRIPT_DIR/rop-finder" --version
