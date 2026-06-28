# Aegis Messenger

**Security-focused, privacy-first, cross-platform end-to-end encrypted messenger MVP.**

Built for the Raspberry Pi as your personal relay server. Works on Linux, macOS, and Windows.

## Security Properties

| Property | Implementation |
|---|---|
| End-to-end encryption | XChaCha20-Poly1305 AEAD |
| Post-quantum KEM | Planned; ML-KEM-768 placeholder currently fails closed |
| Forward secrecy | Double Ratchet (Signal-style) |
| Key derivation | HKDF-SHA512 + Argon2id |
| Digital signatures | Ed25519 |
| Server trust model | Untrusted relay (zero-knowledge) |
| Metadata minimization | Pairwise anonymous IDs, no global identity |
| Local storage | Encrypted vault (AES-256-GCM) |
| Hardware key support | Design documented; not implemented in the MVP |

See [docs/SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) for full details.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Aegis Messenger Desktop App (Tauri v2 + Svelte)    │
│  ┌──────────┐ ┌────────────┐ ┌──────────────┐   │
│  │ UI Layer │ │ Crypto Core│ │ Transport    │   │
│  │ (Svelte)│ │ aegis-    │ │ aegis-      │   │
│  │          │ │ vault     │ │ transport   │   │
│  └──────────┘ └────────────┘ └──────────────┘   │
└───────────────────────┬─────────────────────────────┘
                        │ HTTPS/WSS
┌───────────────────────▼─────────────────────────────┐
│  Aegis Relay Server (Rust/Axum) — runs on RasPi    │
│  ┌──────────┐ ┌────────┐ ┌──────────────────┐    │
│  │ Account  │ │ Queue  │ │ Envelope Relay   │    │
│  │ Mgmt     │ │ Mgmt   │ │ (strict mode)    │    │
│  └──────────┘ └────────┘ └──────────────────┘    │
└───────────────────────────────────────────────────┘
```

## Repository Structure

```
aegis_messenger/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── aegis-crypto/      # Cryptographic primitives
│   ├── aegis-protocol/     # PQXDH handshake, Double Ratchet
│   ├── aegis-vault/        # Encrypted local storage
│   ├── aegis-transport/     # Server API client
│   └── aegis-server/        # Minimal relay server
├── desktop/                 # Tauri v2 desktop app
│   ├── src-tauri/          # Rust backend (Tauri commands)
│   └── src/                # Svelte frontend
├── scripts/
│   ├── build-linux.sh       # Linux build script
│   ├── build-macos.sh       # macOS build script
│   ├── build-windows.sh     # Windows build script
│   └── run-server.sh       # Server startup script
├── .github/workflows/        # CI/CD pipelines
└── docs/                   # Architecture & security docs
```

## Quick Start

### 1. Build the Relay Server

```bash
# On your Raspberry Pi
cargo build --release -p aegis-server
./target/release/aegis-server
```

### 2. Build the Desktop App

**Linux:**
```bash
./scripts/build-linux.sh
# or manually:
cd desktop && npm install && npm run tauri build
```

**macOS:**
```bash
./scripts/build-macos.sh
```

**Windows:**
```powershell
.\scripts\build-windows.sh
```

### 3. Run

```bash
# Desktop app
./target/release/aegis-desktop

# Relay server (on Pi, default port 8080)
AEGIS_BIND=0.0.0.0:8080 ./target/release/aegis-server
```

## Cryptographic Crates

### aegis-crypto
- `chacha20poly1305` → XChaCha20-Poly1305 AEAD
- `x25519-dalek` → X25519 key agreement
- `ed25519-dalek` → Ed25519 signing
- `argon2` → Argon2id password hashing
- `hkdf` → HKDF-SHA512 key derivation
- ML-KEM-768 placeholders (swap in `cryml-kem` when available)

### aegis-protocol
- PQXDH-inspired initial handshake (hybrid X25519 + post-quantum KEM)
- Double Ratchet session with symmetric initialization
- Envelope serialization with metadata minimization
- Safety numbers for contact verification

### aegis-vault
- Argon2id-derived master key from passphrase
- AES-256-GCM encrypted records
- Auto-lock after configurable timeout
- Platform-specific data directories

### aegis-transport
- Minimal server API client
- Account/queue/envelope management
- Constant-time token comparison

### aegis-server
- In-memory state (strict mode: no persistence)
- Ephemeral relay: queues auto-expire
- Token capability system (read/write separation)
- Rate limiting ready

## Server Privacy Model

The relay server is intentionally dumb. It stores only:
- `accounts` — public metadata only, no private keys
- `queues` — encrypted envelopes with expiring TTLs
- `envelopes` — opaque ciphertext blobs

It explicitly **does not** store:
- Message plaintext
- Private identity keys
- Session chain keys
- Contact relationships

See [docs/SERVER_PRIVACY_MODEL.md](docs/SERVER_PRIVACY_MODEL.md).

## Build Artifacts

| Platform | Package | Artifact |
|---|---|---|
| Linux arm64 (RPi) | `.deb`, `.rpm` | `Aegis Messenger_0.1.0_arm64.deb` |
| Linux x86_64 | `.deb`, `.AppImage` | `aegis-desktop` |
| macOS | `.dmg`, `.app` | `Aegis Messenger.app` |
| Windows | `.msi`, `.exe` | `Aegis Messenger_0.1.0_x64_en-US.msi` |

## Cross-Platform Testing

| Platform | Status |
|---|---|
| Linux (RPi / arm64) | Built & tested |
| Linux (x86_64) | CI builds via GitHub Actions |
| macOS (Apple Silicon) | CI builds via GitHub Actions |
| macOS (Intel) | CI builds via GitHub Actions |
| Windows (x64) | CI builds via GitHub Actions |

## Development

```bash
# Check all crates compile
cargo check --workspace

# Run all tests
cargo test --workspace

# Run specific crate tests
cargo test -p aegis-crypto
cargo test -p aegis-protocol

# Lint
cargo clippy --workspace --all-targets

# Format
cargo fmt --all
```

## Limitations

This is an MVP. Known limitations:
- No MLS group messaging (1:1 only)
- No offline message delivery
- No multi-device key sync
- No perfect forward secrecy for the relay server itself
- ML-KEM-768 uses placeholder (swap for real implementation)
- No Tor/I2P mode yet

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for full list.

## License

MIT OR Apache-2.0
