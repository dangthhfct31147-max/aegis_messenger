#!/bin/bash
# Aegis Messenger — Build Script for macOS (Intel & Apple Silicon)
# Run from repository root: ./scripts/build-macos.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

echo "=== Aegis Messenger — macOS Build ==="
echo

# Check dependencies
command -v cargo >/dev/null 2>&1 || { echo "Rust/Cargo is required."; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Node.js/npm is required."; exit 1; }

# Install Tauri CLI if not present
if ! command -v tauri >/dev/null 2>&1; then
    echo "[1/5] Installing Tauri CLI..."
    npm install -g @tauri-apps/cli@2
fi

# Check macOS-specific dependencies
if [[ "$(uname)" != "Darwin" ]]; then
    echo "This script must be run on macOS."
    exit 1
fi

# Install frontend dependencies
echo "[2/5] Installing frontend dependencies..."
cd desktop
npm install
npm run build

# Build Tauri app (produces .app bundle and optionally .dmg)
echo "[3/5] Building Tauri application..."
cd ..
npm run tauri build -- --bundles app,dmg

echo "[4/4] Build complete."
echo
echo "Output:"
ls -lh desktop/src-tauri/target/release/bundle/dmg/*.dmg 2>/dev/null || true
find desktop/src-tauri/target/release/bundle -name "*.app" -type d 2>/dev/null || true
