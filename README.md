# Aegis Messenger

**Security-focused, privacy-first, cross-platform end-to-end encrypted messenger MVP.**

Built for the Raspberry Pi as your personal relay server. Works on Linux, macOS, and Windows.

## Security Properties

| Property | Status | Implementation |
|---|---|
| End-to-end message encryption | Partial | Desktop invite/import/send/poll flow encrypts paired 1:1 messages before relay upload |
| Post-quantum KEM | Partial | ML-KEM-768 is integrated behind a provider trait; downgrade handling and external review are required before production claims |
| Forward secrecy | Partial | Double Ratchet session state has per-message keys, replay rejection, and skipped-key handling |
| Key derivation | Implemented | HKDF-SHA512 + Argon2id |
| Digital signatures | Implemented | Ed25519 |
| Server trust model | Implemented for relay contents | Relay accepts only public key material and ciphertext envelopes |
| Metadata minimization | Partial | Hashed queue IDs and TTL envelopes; traffic correlation remains out of scope for MVP |
| Local storage | Implemented for vault records | Encrypted local vault; full chat history schema still pending |
| Hardware key support | Partial | Desktop can record hardware-unlock enrollment intent; FIDO2 PRF unlock is not implemented yet |

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
- `ml-kem` → ML-KEM-768 behind the `KemProvider` abstraction

### aegis-protocol
- PQXDH-inspired initial handshake (hybrid X25519 + ML-KEM-768 when recipient publishes a PQ prekey)
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
- Optional proxy routing for Tor SOCKS or I2P HTTP proxy mode
- Constant-time token comparison

### aegis-server
- In-memory strict mode plus TTL persistent JSON store when `AEGIS_RELAY_STORE_PATH` is set
- Ephemeral relay: queues/envelopes auto-expire
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
- Group UI/API uses per-recipient E2EE fanout; no MLS ratchet tree yet
- Offline delivery requires `ttl_persistent` relay mode and `AEGIS_RELAY_STORE_PATH`
- No multi-device key sync
- No perfect forward secrecy for the relay server itself
- ML-KEM-768 is integrated but still requires production review and downgrade UX
- Tor/I2P proxy routing is available, but traffic-correlation protection is not complete

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for full list.

## License

MIT OR Apache-2.0
