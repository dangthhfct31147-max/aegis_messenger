#!/bin/bash
# Aegis Messenger — Build Script for Windows (via cross-compilation or natively)
# Run from repository root: ./scripts/build-windows.sh
#
# For cross-compilation from Linux, you need:
#   rustup target add x86_64-pc-windows-gnu
#   cargo install cross  # or use xbuild
#
# For native build, run this script on a Windows machine with:
#   - Rust (https://rustup.rs)
#   - Node.js (https://nodejs.org)
#   - Visual Studio Build Tools with MSVC

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

echo "=== Aegis Messenger — Windows Build ==="
echo

# Check dependencies
command -v cargo >/dev/null 2>&1 || { echo "Rust/Cargo is required."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Node.js/npm is required."; exit 1; }

# Install Tauri CLI if not present
if ! command -v tauri >/dev/null 2>&1; then
    echo "[1/4] Installing Tauri CLI..."
    npm install -g @tauri-apps/cli@2
fi

# Install frontend dependencies
echo "[2/4] Installing frontend dependencies..."
cd desktop
npm install
npm run build

# Build Tauri app (produces .msi and .exe)
echo "[3/4] Building Tauri application..."
cd ..
npm run tauri build -- --bundles msi,nsis

echo "[4/4] Build complete."
echo
echo "Output:"
ls -lh desktop/src-tauri/target/release/bundle/msi/*.msi 2>/dev/null || true
ls -lh desktop/src-tauri/target/release/bundle/nsis/*.exe 2>/dev/null || true
ls -lh desktop/src-tauri/target/release/aegis-desktop.exe 2>/dev/null || true
