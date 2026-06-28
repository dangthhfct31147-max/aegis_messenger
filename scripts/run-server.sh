#!/bin/bash
# Aegis Messenger — Relay Server Startup Script
# Place on your Raspberry Pi and run with: ./scripts/run-server.sh
#
# For systemd service, copy the unit file:
#   sudo cp scripts/aegis-server.service /etc/systemd/system/
#   sudo systemctl enable aegis-server
#   sudo systemctl start aegis-server

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
cd "$REPO_DIR"

AEGIS_BIND="${AEGIS_BIND:-0.0.0.0:8080}"
AEGIS_MODE="${AEGIS_MODE:-strict}"  # strict | ephemeral

echo "=== Aegis Messenger Relay Server ==="
echo "Bind: $AEGIS_BIND"
echo "Mode: $AEGIS_MODE"
echo

# Check if running on a Raspberry Pi
if grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
    echo "Detected: Raspberry Pi ($(cat /proc/device-tree/model))"
    echo
fi

# Check if binary exists, build if needed
if [ ! -f target/release/aegis-server ]; then
    echo "Building server..."
    cargo build --release -p aegis-server
fi

echo "Starting relay server..."
export RUST_LOG="${RUST_LOG:-info}"
exec ./target/release/aegis-server
