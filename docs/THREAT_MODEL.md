# Aegis Messenger — Threat Model

**Version:** 0.1.0-draft  
**Classification:** Draft — Internal  
**Last Updated:** 2026-06-25

---

## 1. Scope

This document covers Aegis Messenger, an ultra-secure end-to-end encrypted messenger for macOS, Windows, and Linux. The threat model covers:

- The Aegis desktop client application
- The Aegis relay server
- All cryptographic protocols used between clients and server
- Local vault storage on client devices

---

## 2. Assets to Protect

### 2.1 Confidentiality Assets

| Asset | Description | CIA Priority |
|---|---|---|
| Message plaintext | Content of all 1:1 and group messages | Confidentiality ★★★ |
| File plaintext | Content of any sent/received files | Confidentiality ★★★ |
| Identity private key | Long-term Ed25519/X25519 identity key | Confidentiality ★★★ |
| Device private key | Per-device X25519/Ed25519 key | Confidentiality ★★★ |
| Session / ratchet state | Double Ratchet chain keys and message keys | Confidentiality ★★★ |
| Group secrets | MLS-style group encryption keys and leaf keys | Confidentiality ★★★ |
| Vault master key | Derived key protecting all local data | Confidentiality ★★★ |
| Contact graph | Who talks to whom, relationship existence | Confidentiality ★★ |
| Queue tokens | Read/write capability tokens for routing | Confidentiality ★★ |
| Queue IDs | Routing identifiers | Confidentiality ★ |
| Server-side envelope ciphertext | Encrypted blobs on server | Confidentiality ★ (server should not know plaintext) |

### 2.2 Integrity Assets

| Asset | Description | CIA Priority |
|---|---|---|
| Public key binding | Identity key ↔ device key chain of trust | Integrity ★★★ |
| Prekey bundle | Signed prekey and one-time prekeys | Integrity ★★★ |
| Safety numbers | Contact verification codes | Integrity ★★★ |
| Safety numbers are used to verify that the channel is not compromised. | |
| Group membership | Who belongs to which group | Integrity ★★ |
| Server transparency log | Append-only key event log | Integrity ★★ |

### 2.3 Availability Assets

| Asset | Description | CIA Priority |
|---|---|---|
| Message delivery | Messages reach intended recipients | Availability ★★ |
| Queue availability | Server accepts envelopes reliably | Availability ★★ |
| Vault accessibility | User can always unlock their own vault | Availability ★★ |

---

## 3. Adversaries

### 3.1 Adversary: Malicious Server Operator

**Capability:** Controls all server software, database, logs, and network infrastructure.

**Attack Vector:** Reads server database, modifies API responses, injects messages, deletes messages, correlates metadata, deanonymizes users.

**Defenses:**
- Server never receives plaintext. All envelopes are encrypted client-side.
- Server stores only hashed queue IDs and capability tokens.
- No plaintext metadata: no sender_id, receiver_id, conversation_id, group names, or profile names.
- Strict relay mode: server keeps envelopes in RAM only, no persistence.
- Ephemeral offline mode: TTL deletion of encrypted envelopes.

**Residual Risk:** Server operator can correlate connection metadata (IP addresses, connection timing). This is partially mitigated by Tor support.

### 3.2 Adversary: Passive Network Observer

**Capability:** Observes network traffic between clients and server (ISP, network operator, country-level adversary).

**Attack Vector:** Traffic analysis, timing attacks, volume correlation, identifying communication patterns.

**Defenses:**
- All traffic is TLS-encrypted.
- Message sizes are padded to buckets.
- Optional Tor transport layer.
- No direct P2P connections; all traffic routed through relay.
- Queue ID rotation.
- Cover traffic in extreme mode.

**Residual Risk:** Traffic analysis may correlate volume patterns with known message send/receive events. Latency-based traffic analysis is a known limitation.

### 3.3 Adversary: Compromised Relay Server

**Capability:** The server binary and runtime are fully compromised by an attacker.

**Attack Vector:** Same as malicious server operator, plus potential injection of malformed envelopes.

**Defenses:**
- Envelopes are authenticated with AEAD (XChaCha20-Poly1305). Tampering is detectable.
- Server cannot forge valid ciphertexts without the per-conversation keys (which server never holds).
- Strict relay mode limits persistence even on server compromise.

### 3.4 Adversary: Database Leak

**Capability:** An attacker exfiltrates the entire server database (via SQL injection, backup leak, insider threat, physical media theft).

**Attack Vector:** Exfiltrates all stored data, attempts to decrypt envelopes, extracts metadata.

**Defenses:**
- Server database contains only: encrypted envelopes (AEAD ciphertext), hashed queue IDs, hashed capability tokens, public key material, and timestamps in bucket form.
- No plaintext messages, no conversation names, no contact graph.
- Ephemeral TTL ensures data self-deletes.
- Private keys are never on the server.
- Envelope decryption requires per-conversation keys that the server never has.

**Residual Risk:** Hashed identifiers can be subjected to rainbow table / brute force if token entropy is low. Use high-entropy (256-bit) random tokens.

### 3.5 Adversary: Stolen Laptop

**Capability:** Physical access to an unlocked or locked laptop. May attempt to read local storage.

**Attack Vector:** Boots from USB, removes disk, reads local database, extracts vault.

**Defenses:**
- Vault is encrypted with Argon2id-derived key.
- Optional hardware key factor (FIDO2 PRF).
- OS keychain binding as additional factor.
- Auto-lock on sleep/screen lock.
- Memory zeroization of secret material where possible.

**Residual Risk:** If attacker knows the passphrase and has the hardware key, vault is readable. A cold-boot attack on RAM may recover keys if machine is not power-cycled — beyond scope of software-only defense.

### 3.6 Adversary: Attacker Who Steals Local App Database

**Capability:** Can read the app's local SQLite / vault files.

**Attack Vector:** Extracts encrypted vault, attempts offline passphrase brute force.

**Defenses:**
- Argon2id with high iteration count and memory cost.
- Hardware key factor prevents brute force without physical hardware key.
- Distinguish between real vault and decoy vault.
- Vault does not contain obvious markers of a decoy vault.

**Residual Risk:** Passphrase brute force is the primary attack. Use high entropy passphrase; Argon2id parameters should be calibrated to make brute force computationally expensive (≥ 3 seconds on target hardware).

### 3.7 Adversary: Malware Running Outside the App Sandbox

**Capability:** Arbitrary code runs on the same OS as Aegis, outside the app's trust boundary.

**Attack Vector:** Keyboard log, screen capture, process memory dump, API hooking.

**Defenses:**
- App isolation strategies per platform (macOS sandbox, Windows AppContainer, Linux Flatpak portals).
- No global keyboard hooks; standard OS input APIs only.
- Warning to users about the limits of software security when the OS is compromised.
- Hardware key does not prevent RAM capture from OS-level malware.

**Residual Risk:** When OS is fully compromised, no software can protect visible plaintext. Hardware-based screen capture prevention is not in scope.

### 3.8 Adversary: Malware Running in the Same OS Account

**Capability:** Runs as the same user, can read Aegis process memory and files.

**Attack Vector:** Reads Aegis vault unlock keys from memory, intercepts decrypted messages from the UI rendering process.

**Defenses:**
- Same as 3.7. Additionally: security-critical crypto code in separate Rust process from UI.
- Memory zeroization after secret use.
- Decoy vault provides plausible deniability.

**Residual Risk:** Same as 3.7. This is an inherent software limitation.

### 3.9 Adversary: Coercive Attacker

**Capability:** Physically coerces user to unlock the app, reveals the existence of Aegis.

**Attack Vector:** User is forced to provide passphrase and/or hardware key.

**Defenses:**
- Duress PIN opens decoy vault with convincing but fake content.
- Real vault is indistinguishable from decoy vault without knowing the real passphrase.
- Clear documentation that duress mode is not cryptographically perfect.
- Panic lock hotkey can immediately lock the app.

**Residual Risk:** Advanced forensic analysis (timing of unlock events, memory patterns, storage access patterns) may detect the presence of a decoy vs real vault. Users must understand this limitation.

### 3.10 Adversary: Malicious Attachment

**Capability:** Sends a file designed to exploit a vulnerability in the receiving application's parsing library.

**Attack Vector:** Buffer overflow, XXE, deserialization attack, etc. via a crafted file.

**Defenses:**
- Never auto-open attachments.
- Never render active content (macros, scripts, remote HTML).
- Attachments opened in isolated sandboxed viewer process.
- For PDFs/docs, prefer external sandboxed viewer.
- No inline preview for risky formats in MVP.
- Images decoded using hardened libraries in isolated process.

### 3.11 Adversary: Future Quantum Adversary

**Capability:** Has a cryptographically relevant quantum computer (CRQC) and stored all intercepted ciphertext.

**Attack Vector:** Grovers algorithm / Shor's algorithm to break asymmetric and symmetric encryption.

**Defenses:**
- Hybrid classical + post-quantum key agreement: X25519 + ML-KEM-768.
- Post-quantum signatures: Ed25519 + ML-DSA (when stable libraries available).
- Do not rely on RSA or ECC alone for key agreement.
- When quantum-resistant hashes are standardized, use them for HKDF and hashing.
- Crypto agility: versioned protocol so algorithms can be updated.

**Residual Risk:** Symmetric encryption (AES-256, ChaCha20) is resistant to Grover's algorithm with 256-bit keys. Asymmetric encryption is the primary quantum risk, addressed by post-quantum hybrid schemes.

---

## 4. Non-Goals and Honest Limits

1. **OS fully compromised:** If malware has kernel-level or equivalent access, no software-only design can protect plaintext visible on screen or in memory. Aegis does not attempt to defend against this threat.

2. **Hardware key limitations:** Hardware keys protect vault unlock and login, but they do not prevent screen capture, RAM scraping, or keylogging by OS-level malware.

3. **Metadata privacy limits:** Traffic analysis, timing correlation, and volume correlation can reveal communication patterns. Perfect metadata privacy requires latency-hiding mechanisms (mixnets, cover traffic) that have significant usability and performance trade-offs. Aegis reduces metadata exposure but does not eliminate it.

4. **Deniability:** Aegis does not provide deniable messaging (like Signal's Sealed Sender in some modes). Sender identity is cryptographically bound to each message for the recipient.

5. **Server IP exposure:** The server always sees the IP address of connecting clients. Tor mode helps, but the first hop (client → entry guard) still passes through the ISP.

6. **Social graph completely hidden:** While the server does not store the contact graph, a global passive observer with traffic correlation capabilities could potentially infer relationships over time.

---

## 5. Security Properties Summary

| Property | Achieved? | Mechanism |
|---|---|---|
| End-to-end encryption | Yes | XChaCha20-Poly1305, Double Ratchet |
| Forward secrecy | Yes | Ratchet advances delete old keys |
| Post-compromise recovery | Yes | New key agreement on ratchet reset |
| Post-quantum key agreement | Yes (hybrid) | X25519 + ML-KEM-768 |
| Server cannot read messages | Yes | Client-side encryption before send |
| Server cannot see social graph | Yes | No plaintext contact/conversation storage |
| Server cannot see metadata | Partial | Queue ID hashing, TTL deletion |
| Local vault encryption | Yes | Argon2id + AEAD |
| Hardware key protection | Yes (optional) | FIDO2 PRF |
| Duress plausible deniability | Yes (optional) | Decoy vault |
| No custom crypto | Yes | Audited library primitives only |
| Crypto agility | Yes | Versioned protocol headers |

---

## 6. Revision History

| Version | Date | Changes |
|---|---|---|
| 0.1.0-draft | 2026-06-25 | Initial draft |
