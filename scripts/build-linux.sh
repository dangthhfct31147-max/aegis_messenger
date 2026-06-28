#!/bin/bash
# Aegis Messenger — Build Script for Linux (x86_64 / aarch64)
# Run from repository root: ./scripts/build-linux.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

echo "=== Aegis Messenger — Linux Build ==="
echo

# Check dependencies
command -v cargo >/dev/null 2>&1 || { echo "Rust/Cargo is required. Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "Node.js/npm is required."; exit 1; }

# Install Tauri CLI if not present
if ! command -v tauri >/dev/null 2>&1; then
    echo "[1/5] Installing Tauri CLI..."
    npm install -g @tauri-apps/cli@2
fi

# Install Linux build dependencies
echo "[2/5] Checking Linux build dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq libgtk-3-dev libwebkit2gtk-4.1-dev \
    libayatana-appindicator3-dev librsvg2-dev patchelf \
    pkg-config libssl-dev > /dev/null

# Install frontend dependencies
echo "[3/5] Installing frontend dependencies..."
cd desktop
npm install
npm run build

# Build Tauri app
echo "[4/5] Building Tauri application..."
cd ..
npm run tauri build -- --bundles deb,appimage

echo "[5/5] Build complete."
echo
echo "Output:"
ls -lh desktop/src-tauri/target/release/bundle/deb/*.deb 2>/dev/null || true
ls -lh desktop/src-tauri/target/release/bundle/appimage/*.AppImage 2>/dev/null || true
ls -lh desktop/src-tauri/target/release/aegis-desktop 2>/dev/null || true
