# Aegis Messenger — Security Architecture

**Version:** 0.1.0-draft  
**Last Updated:** 2026-06-25

---

## 1. Overview

Aegis Messenger is built around a single principle: **treat the server as fully untrusted**. The server is a relay — nothing more. It routes encrypted envelopes without any ability to decrypt, store meaningfully, or correlate their contents to individuals.

The architecture is divided into three layers:

```
┌─────────────────────────────────────────────────────┐
│  UI Layer (Svelte + Tauri v2)                      │
│  - Contact list, chat view, settings               │
│  - Communicates with Crypto Core via Tauri IPC     │
├─────────────────────────────────────────────────────┤
│  Crypto Core (Rust — aegis-crypto, aegis-vault)   │
│  - All encryption/decryption                        │
│  - Local vault management                           │
│  - Key derivation, session ratchet state            │
│  - Protocol message construction                    │
├─────────────────────────────────────────────────────┤
│  Transport Layer (aegis-transport)                 │
│  - TLS / Tor / onion transport abstraction          │
│  - Server API client                                │
│  - Queue polling and envelope relay                  │
└─────────────────────────────────────────────────────┘
```

---

## 2. Crate Architecture

```
aegis_messenger/           # Cargo workspace root
├── aegis-crypto/          # Cryptographic primitives (pure Rust)
├── aegis-protocol/        # Protocol types, message formats, session state
├── aegis-vault/           # Local encrypted vault
├── aegis-transport/       # Server API client, transport abstraction
├── aegis-server/          # Minimal relay server (Axum)
└── desktop/               # Tauri v2 + Svelte UI app
```

### 2.1 `aegis-crypto`

Provides all cryptographic operations. No protocol logic lives here.

- **Key Derivation:** Argon2id (vault KDF), HKDF (session KDF)
- **AEAD:** XChaCha20-Poly1305 for all message/file encryption
- **Key Agreement:** X25519 (classical ECDH)
- **Post-Quantum KEM:** ML-KEM-768 via `kyber` crate (when stable)
- **Signatures:** Ed25519 (classical), ML-DSA (post-quantum, experimental)
- **Hashing:** SHA-512 (for HKDF input, token hashing), BLAKE3 (for local DB)
- **Randomness:** `getrandom` + OS CSPRNG

All operations follow `ring`/`x25519-dalek`/`chacha20poly1305`/`argon2`/`kyber`/`dalek` crate conventions. All secret buffers use `zeroize` for memory cleanup.

### 2.2 `aegis-protocol`

Defines protocol types and state machines.

- **Envelope format:** versioned header + ciphertext + AEAD tag
- **Prekey bundle:** Identity key + signed prekey + one-time prekeys
- **Session state:** Double Ratchet state for each contact
- **Handshake:** PQXDH-inspired hybrid key agreement
- **Group state:** MLS-like client-side group management
- **Contact card:** Encrypted invite format with QR code encoding

### 2.3 `aegis-vault`

Manages the local encrypted vault on disk.

- **Vault format:** Single encrypted file (or SQLite with record-level encryption)
- **Unlock:** Argon2id(passphrase) + optional hardware key PRF → HKDF → vault master key
- **Contents:** Identity private key, device private key, session states, contact list, group states, settings
- **Locking:** Auto-lock on inactivity (configurable timeout), on sleep, on screen lock, on panic hotkey
- **Memory:** Secrets held in RAM cleared on lock via `zeroize`

### 2.4 `aegis-transport`

Implements the server API client and transport abstraction.

- **Server API:** Queue creation, capability token exchange, envelope upload/download, device registration
- **Transport:** TLS by default; Tor/onion as optional layer
- **Polling:** Efficient long-poll / WebSocket for envelope delivery
- **Padding:** Message sizes padded to standard buckets before transmission

### 2.5 `aegis-server`

Minimal relay server. See `SERVER_PRIVACY_MODEL.md` for full details.

---

## 3. Key Hierarchy

```
User Passphrase
      │
      ▼
Argon2id(passphrase, salt, m=2^21, t=3, p=4)  [vault KDF]
      │
      ├──► [hardware key PRF output — if enabled]
      │
      ▼ (HKDF)
Vault Master Key (256-bit)
      │
      ├──► Identity Key Wrapping Key
      ├──► Device Key Wrapping Key
      ├──► Session State Encryption Key
      ├──► Contact List Encryption Key
      └──► Settings Encryption Key
```

**Identity Key Pair:** Ed25519 (signing) + X25519 (key agreement) — long-term, never leaves vault unencrypted.

**Device Key Pair:** Per-device X25519 + Ed25519 — derived from identity key and signed by it.

**Session Keys:** Derived via Double Ratchet. Each message uses a fresh key. Old keys deleted after use.

**Prekey Bundles:** Public parts stored on server. Private parts encrypted in local vault.

---

## 4. Trust Model

### 4.1 Client Trust Boundaries

```
User
  └── Passphrase (or + Hardware Key)
        └── Vault Master Key
              ├── Identity Key (trusted)
              └── Session Keys (per-contact, ephemeral)
                    └── Message Keys (per-message, ephemeral)
```

The user's passphrase and hardware key are the root of all trust. Everything else is derived from them.

### 4.2 Server Trust Boundaries

The server is trusted to:
- Relay encrypted envelopes without modification
- Delete envelopes after TTL or delivery
- Not log sensitive metadata
- Not correlate queue IDs with user identities beyond the account_id_hash
- Maintain a transparency log of key events

The server is NOT trusted to:
- See message content
- See contact lists or conversation names
- Know who is talking to whom beyond traffic volume
- Store identity private keys or session keys
- Add devices without the user's existing trusted device

---

## 5. App Isolation Architecture

### 5.1 Process Separation

```
┌─────────────────┐     IPC (Tauri invoke)     ┌──────────────────┐
│  UI Process     │ ◄────────────────────────► │  Crypto Process  │
│  (Svelte/JS)    │                            │  (Rust core)     │
└─────────────────┘                            └──────────────────┘
        │                                              │
        │                                              │
        ▼                                              ▼
┌─────────────────┐                            ┌──────────────────┐
│  OS Window Mgr  │                            │  Vault File      │
│  (standard)     │                            │  (encrypted)     │
└─────────────────┘                            └──────────────────┘
```

In MVP, the UI and crypto core share a process via Tauri commands. Future versions (Phase 7) will split into separate processes with IPC.

### 5.2 Platform-Specific Isolation

**macOS:**
- App Sandbox (entitlements: network client, no filesystem except app data)
- Hardened Runtime
- Notarization (production)
- XPC separation for crypto core (Phase 7)

**Windows:**
- MSIX packaging (production)
- AppContainer for crypto core (Phase 7)
- No admin rights required

**Linux:**
- Flatpak with portals for file access
- bubblewrap sandbox for attachment viewer (no network, read-only input)
- No `filesystem=host` or `filesystem=home` in Flatpak manifest

---

## 6. Crypto Agility

All protocol messages include versioned headers:

```
Envelope {
    protocol_version: u16,   // 0x0001 for current
    cipher_suite_id: u16,     // 0x0001 = X25519 + ML-KEM-768 + XChaCha20-Poly1305
    key_version: u32,         // incremented on key rotation
    sender_ephemeral: [u8; 32],
    ciphertext: [u8],
    aad: [u8; 32],            // auth binding
}
```

New cipher suites can be introduced by bumping `cipher_suite_id`. Clients negotiate the highest mutually supported suite.

---

## 7. Privacy Architecture

### 7.1 Metadata Minimization

| Metadata | How Minimized |
|---|---|
| Sender identity | Server never receives sender account in envelope request |
| Receiver identity | Queue ID is hashed server-side; server stores hash only |
| Message content | Never on server |
| Conversation existence | No conversations table on server |
| Contact graph | No contacts table on server |
| Message timing | Timestamp buckets (1-hour precision) instead of exact time |
| Message size | Padded to 256-byte buckets |

### 7.2 Transport Privacy

- **TLS:** Standard transport encryption (server certificate verification)
- **Tor:** `.onion` service endpoint for extreme network privacy
- **Cover Traffic:** Optional, in extreme privacy mode
- **Queue Rotation:** Queue IDs rotated periodically to break long-term linkability

---

## 8. Revision History

| Version | Date | Changes |
|---|---|---|
| 0.1.0-draft | 2026-06-25 | Initial draft |
