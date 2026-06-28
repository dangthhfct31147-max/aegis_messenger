# Aegis Messenger — Cryptographic Design

**Version:** 0.1.0-draft  
**Last Updated:** 2026-06-25

---

## 1. Design Principles

1. **No custom crypto.** All primitives come from audited, widely-reviewed libraries.
2. **Crypto agility.** Every cryptographic object carries a `cipher_suite_id` and version field.
3. **Defense in depth.** Hybrid classical + post-quantum for key agreement.
4. **Forward secrecy.** Old keys are deleted. Compromise does not expose past messages.
5. **Post-compromise recovery.** New key agreements reset the ratchet after compromise.
6. **Memory safety.** All secret buffers use `zeroize` for explicit cleanup.

---

## 2. Cryptographic Libraries

| Primitive | Library | Version | Audit |
|---|---|---|---|
| XChaCha20-Poly1305 | `chacha20poly1305` | latest | `rust-crypto` / audit |
| X25519 ECDH | `x25519-dalek` | 2.x | formal review |
| Ed25519 Signatures | `ed25519-dalek` | 2.x | formal review |
| Argon2id KDF | `argon2` | latest | RFC 9106 |
| HKDF | `hkdf` | latest | RFC 5869 |
| ML-KEM-768 KEM | `ml-kem` | 0.2.x | RustCrypto implementation of FIPS 203; wrapped by `KemProvider` |
| SHA-512 | `sha2` | latest | FIPS 180-4 |
| BLAKE3 | `blake3` | latest | external audit |
| Randomness | `getrandom` | latest | OS CSPRNG |

> **Note on ML-KEM-768 / ML-DSA:** ML-KEM-768 is accessed through an internal provider abstraction so the backend can be replaced if the ecosystem or audit status changes. We do NOT implement post-quantum algorithms from scratch.

---

## 3. Cryptographic Identities

### 3.1 Identity Key Pair

```
Type:        Ed25519 (signing) + X25519 (key agreement) — separate key pairs
Generation:  client-side, in vault
Lifetime:    Long-term (until user explicitly rotates)
Storage:     Encrypted in local vault
On Server:   ONLY the public X25519 part (in device registration)
Purpose:     Sign device keys, sign prekeys, sign contact invites
```

### 3.2 Device Key Pair

```
Type:        X25519 (key agreement) + Ed25519 (signing)
Generation:  client-side, signed by identity key
Lifetime:    Per device (user can have multiple devices)
Storage:     Encrypted in local vault
On Server:   Public parts only (device_public_id_key, signed_prekey_public)
Purpose:     Per-device key agreement for multi-device support
```

### 3.3 Prekey Bundle

A prekey bundle allows asynchronous key agreement (sender and recipient do not need to be online simultaneously).

```
PrekeyBundle {
    identity_key:           [u8; 32]   // X25519 public
    signed_prekey:          [u8; 32]   // X25519 public, signed by identity key
    signed_prekey_signature:[u8; 64]   // Ed25519 signature
    one_time_prekey:        [u8; 32]?  // X25519 public, used once then deleted
    // Post-quantum (if available):
    pq_signed_prekey:       [u8; 1184]? // ML-KEM-768 encapsulated key
    pq_one_time_prekey:     [u8; 1184]? // ML-KEM-768 encapsulated key
    key_version:            u32
    cipher_suite_id:        u16
}
```

### 3.4 Queue Capability Tokens

```
queue_id:    [u8; 32]  // 256-bit random, generated client-side
read_token:  [u8; 32]  // 256-bit random, client-side
write_token: [u8; 32] // 256-bit random, client-side
```

Server stores only SHA-512 hashes of these values.

---

## 4. Key Derivation

### 4.1 Vault Unlock (Argon2id + HKDF)

```
Inputs:
  passphrase:         user-provided string
  salt:              16 random bytes, stored in vault header
  hardware_key_prf:  optional output from FIDO2 hmac-secret (32 bytes)

KDF:
  argon2id_output = Argon2id(
    password:    passphrase,
    salt:        salt,
    m:           2097152 (2^21) KiB,
    t:           3,
    p:           4,
    dklen:       32
  )

  // Combine argon2id output with hardware key if present
  if hardware_key_prf is present:
    master_input = HKDF-SHA512(ikm=argon2id_output || hardware_key_prf, salt="aegis-vault", info="master-key")
  else:
    master_input = argon2id_output

  vault_master_key = master_input[0:32]

  // Derive sub-keys
  identity_wrapped = HKDF-SHA512(vault_master_key, info="identity-wrapping", salt=salt)
  session_wrapped  = HKDF-SHA512(vault_master_key, info="session-wrapping",  salt=salt)
  contact_wrapped  = HKDF-SHA512(vault_master_key, info="contact-wrapping",  salt=salt)
  settings_wrapped = HKDF-SHA512(vault_master_key, info="settings-wrapping", salt=salt)
```

### 4.2 Session Key Derivation (HKDF)

```
message_key = HKDF-SHA512(
  ikm:  chain_key,
  salt: "aegis-message-key",
  info: ratchet_counter || message_number
)

chain_key = HKDF-SHA512(
  ikm:  previous_chain_key,
  salt: "aegis-chain-key",
  info: ratchet_counter
)
```

---

## 5. Handshake Protocol (PQXDH-Inspired)

### 5.1 Initial Key Agreement (First Contact)

```
PARTICIPANTS: Alice (initiator) and Bob (recipient)
BEFORE:       Alice has Bob's signed prekey bundle from server

1. Alice generates ephemeral key pair: (E_A, e_A) using X25519
2. Alice generates ephemeral key pair: (EK_A, ek_A) using ML-KEM-768

3. Alice computes shared secrets:
   DH1 = X25519(e_A, Bob.identity_key)          // classical
   DH2 = X25519(E_A, Bob.signed_prekey)          // classical
   DH3 = X25519(e_A, Bob.signed_prekey)          // classical
   KEM = ML-KEM-768.Encaps(Bob.pq_signed_prekey) // post-quantum

   // DH1 + DH2 + DH3 are concatenated for 96 bytes (X25519 scalar multiplication = 32 bytes)
   combined_classical = DH1 || DH2 || DH3        // 96 bytes
   shared_secret = SHA-512(combined_classical || KEM.shared_secret)

4. Alice derives root key:
   root_key = HKDF-SHA512(
     ikm:  shared_secret,
     salt: "aegis-pxdh",
     info: Alice.identity_key || Bob.identity_key
   )

5. Alice creates initial message using root_key as chain key for Double Ratchet.
   She consumes one of Bob's one-time prekeys (if provided).

6. Alice sends Bob: (E_A public, EK_A encapsulated, initial encrypted message)
```

### 5.2 Ratchet Reset (Post-Compromise Recovery)

When a new prekey bundle is fetched (e.g., after key change notification), a new PQXDH handshake is performed to re-establish forward secrecy.

---

## 6. Message Encryption (Double Ratchet)

### 6.1 Symmetric Ratchet

Each message uses a fresh message key derived from the chain key. The chain key advances after each message.

```
message_key_i = HKDF-SHA512(chain_key, info="message-key", salt=message_number_i)
chain_key_i   = HKDF-SHA512(chain_key, info="chain-key",   salt=message_number_i)
```

### 6.2 DH Ratchet (Symmetric Ratchet Reset)

Periodically, a new DH key pair is generated and exchanged to advance the root key:

```
new_dh_keypair = X25519KeyPair::generate()
new_shared     = X25519(our_private, their_new_public)
root_key, chain_key = HKDF-SHA512-Cat(
  ikm:  new_shared,
  salt: root_key,
  info: "aegis-dh-ratchet"
)
```

### 6.3 AEAD Encryption

```
ciphertext = XChaCha20-Poly1305::seal(
  plaintext:  message || padding,
  nonce:      random_96bit_nonce,
  key:        message_key_i[0:32],
  aad:        envelope_header  // authenticated, not encrypted
)
```

### 6.4 Out-of-Order Message Handling

Message keys for future messages are pre-computed and stored (up to a lookahead window, e.g., 100 messages). If a message arrives out of order, its key is retrieved from the pre-computed store.

---

## 7. Envelope Format

```
Envelope {
    protocol_version:  u16,      // 0x0001
    cipher_suite_id:   u16,      // 0x0001
    key_version:       u32,
    sender_ephemeral:  [u8; 32], // ephemeral public key for this session
    message_number:    u64,      // per-sender monotonically increasing
    previous_chain:    u64,      // chain counter for out-of-order detection
    ciphertext:        Vec<u8>,  // AEAD ciphertext
    nonce:             [u8; 12], // XChaCha20-Poly1305 nonce
}
```

**AAD (Authenticated Associated Data):** The first 4 fields above are used as AAD so that an attacker cannot strip the header and replay an old envelope with a new header.

---

## 8. Group Messaging (MLS / OpenMLS Staged)

Current desktop group messaging delivery is still per-recipient fanout over existing 1:1 contact secrets. The protocol crate now exposes an MLS/OpenMLS-facing facade (`AegisMlsGroup`, `MlsKeyPackage`, `MlsWelcome`, `MlsCommit`, `MlsApplicationMessage`, and `MlsEpochState`) so the desktop/server contracts can move to RFC 9420 semantics without exposing OpenMLS internals across the app.

The production claim gate remains blocked until OpenMLS-backed group state is wired end-to-end and tested for add/remove/update commits, epoch mismatch rejection, removed-member decrypt failure, and interop.

### 8.1 Group Model

- Group state is stored CLIENT-SIDE only.
- Server sees ONLY encrypted blobs.
- Group membership changes (add/remove member) trigger a secret tree re-key.
- Every group message is encrypted with a group secret derived from the group ratchet tree.

### 8.2 Group Key Derivation

```
group_secret = TreeKDF(root_of_tree)
message_key  = HKDF-SHA512(group_secret, info="group-msg", salt=message_counter)
```

### 8.3 Group Management (Client-Side)

```
GroupOperation = Add | Remove | Update | Commit
1. Client performs operation locally on group state tree
2. Client computes new group secret
3. Client encrypts group_secret for each remaining member using their session chain
4. Client sends: (operation, encrypted_group_secret_blobs[], sender_key_package)
```

Server stores: `group_queue_id_hash`, `encrypted_blob`, `padded_size_bucket` — nothing else.

---

## 9. Post-Quantum Readiness

### 9.1 Hybrid Key Agreement

The shared secret is computed as:

```
classical_secret  = SHA-512(X25519(e_A, id_B) || X25519(E_A, sp_B) || X25519(e_A, sp_B))
pq_secret         = ML-KEM-768.Encaps(pq_sp_B).shared_secret
shared_secret     = SHA-512(classical_secret || pq_secret)
```

If ML-KEM-768 is unavailable on a platform, production paths must call the fail-closed downgrade policy and reject the handshake. Explicit lab/demo downgrade can still be allowed by policy, but it must not silently produce a production-grade post-quantum claim.

### 9.2 Post-Quantum Signatures (Experimental)

Ed25519 is the primary signature scheme. ML-DSA (via `ml-dsa` crate) is added as an experimental secondary signature for future-proofing. Protocol can negotiate signature scheme via `key_version`.

### 9.3 Crypto Agility

```
CipherSuiteRegistry:
  0x0001: X25519 + ML-KEM-768 + XChaCha20-Poly1305 + Ed25519 + SHA-512
  0x0002: (future) X-WireGuard + ML-KEM-1024 + AES-256-GCM + ML-DSA + SHA3-512
```

All implementations must handle unknown `cipher_suite_id` gracefully (fail closed, do not negotiate down silently).

---

## 10. Local Vault Encryption

All vault contents are encrypted using the vault master key and XChaCha20-Poly1305.

```
VaultRecord {
    record_type:  u16,        // identifies the record (identity, session, contact, etc.)
    record_id:    [u8; 16],   // unique per record
    nonce:        [u8; 12],
    ciphertext:   Vec<u8>,
    tag:          [u8; 16],
    version:      u32,        // for future key rotation
}
```

All records are independently encrypted. Compromising one record does not trivially lead to compromising others (key separation per record type via HKDF).

---

## 11. Security Considerations

| Concern | Mitigation |
|---|---|
| Argon2id too fast on high-end GPU | Calibrate `m` parameter to ≥ 1s on target hardware; warn users |
| Weak passphrase | Strength meter; enforce minimum entropy |
| Passphrase reuse | Never send passphrase anywhere; local-only |
| Key compromise on device theft | Hardware key factor; auto-lock |
| Forward secrecy break | Old keys deleted immediately; ratchet reset available |
| Quantum break of X25519 | ML-KEM-768 hybrid absorbs quantum advantage |
| Random number generator weakness | OS CSPRNG via `getrandom`; seed from `std::hint::black_box` mixing |
| Side-channel in constant-time ops | Use `subtle::ConstantTimeEq` for all secret comparisons |
| Memory not zeroed on panic | `zeroize::Zeroizing` wrapper; `Drop` impl for all secret types |

---

## 12. What We Do NOT Use

| Algorithm | Reason |
|---|---|
| RSA | Not post-quantum; larger key sizes |
| ECDH P-256/P-384 | Not post-quantum |
| AES-CBC | Not authenticated; replaced by XChaCha20-Poly1305 |
| HMAC-SHA256 | Replaced by Poly1305 (faster in software) |
| PBKDF2 | Replaced by Argon2id (memory-hard) |
| MD5 / SHA-1 | Collision attacks; used only where cryptographically irrelevant |
| Custom AEAD construction | Replaced by XChaCha20-Poly1305 (standard, audited) |
| Custom KDF | Replaced by HKDF (RFC 5869) |
| Custom key agreement | Replaced by X25519 + ML-KEM-768 |

---

## 13. Revision History

| Version | Date | Changes |
|---|---|---|
| 0.1.0-draft | 2026-06-25 | Initial draft |
