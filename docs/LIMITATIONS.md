# Aegis Messenger — Limitations

**Version:** 0.1.0-draft  
**Last Updated:** 2026-06-25

This document honestly describes what Aegis Messenger does NOT protect against, what is intentionally out of scope, and known trade-offs. Users and reviewers should read this carefully.

---

## 1. Fundamental Limitations

### 1.1 Compromised Operating System

If an attacker has root/kernel-level access to the device's operating system, no software-only design can protect:

- Plaintext messages visible on screen
- Keystrokes entered via standard OS input APIs
- Memory contents of the Aegis process
- Clipboard contents
- Files stored in the app's data directory

**What Aegis does:** Uses OS-level sandboxing (macOS sandbox, Windows AppContainer, Linux Flatpak) to limit damage from other apps. But this does not protect against a privileged attacker on the same machine.

**What Aegis cannot do:** Prevent a kernel-level keylogger from capturing the passphrase, or screen capture software from recording the UI while a message is displayed.

### 1.2 Hardware Key Limitations

Hardware keys protect:
- Vault unlock (prevents offline passphrase brute force)
- Server login (prevents credential theft)

Hardware keys do NOT protect:
- Messages visible on screen after unlock
- RAM scraping while the vault is unlocked
- Screen recording / screenshot by OS-level malware
- Keylogging at the OS level
- Clipboard contents

### 1.3 Metadata Privacy

Aegis significantly reduces metadata exposure but cannot achieve mathematical perfect metadata privacy without:

- **Mixnet:** Routing messages through multiple relays with cover traffic
- **Cover traffic:** Sending fake messages to hide real traffic patterns
- **Artificial latency:** Adding random delays to break timing correlation
- **Constant-rate padding:** Sending at a fixed rate regardless of user activity

These trade-offs (usability, bandwidth, battery) are not acceptable for the MVP. Aegis provides:
- Hashed queue IDs (server cannot see raw routing address)
- TTL deletion of envelopes
- Padded message sizes
- No plaintext conversation or contact storage on server

But a global passive observer can still:
- See that a specific IP address is connecting to the Aegis relay
- See connection timing patterns
- Correlate traffic volume with message send/receive events
- Infer that two users are communicating (over time, through traffic correlation)

### 1.4 Traffic Correlation

Even with Tor, the first hop (client → entry guard) passes through the user's ISP, which can observe that the user is connecting to a Tor entry node. The last hop (exit node → Aegis relay) can observe traffic to the relay. A sufficiently powerful adversary (country-level) can correlate entry and exit traffic.

### 1.5 Forward Secrecy Scope

Forward secrecy protects past messages if a key is compromised **in the future**. It does NOT protect past messages if:

- The key was already compromised before the messages were sent
- The device was cloned or key material was exfiltrated before the messages were encrypted
- A court order compels the user to disclose the passphrase (duress PIN helps with deniability but is not cryptographically perfect)

---

## 2. Known Technical Limitations

### 2.1 Argon2id Calibration

Argon2id parameters (`m`, `t`, `p`) must be calibrated to the target device. High-end desktop with 32 GB RAM: `m=2^21` (2 GiB) may take 3+ seconds. Low-end mobile with 2 GB RAM: `m=2^21` may cause OOM.

**Mitigation:** Aegis will ship with adaptive calibration that adjusts `m` to target ~1 second unlock time, with a minimum floor that prevents OOM. Users can configure manual parameters.

### 2.2 ML-KEM-768 Library Maturity

The RustCrypto `ml-kem` crate is integrated behind the Aegis `KemProvider` abstraction. NIST standardized ML-KEM in 2024, and the Rust ecosystem is still maturing.

**Mitigation:** Aegis can swap the provider without protocol-wide rewrites. Desktop contact import validates that an invite contains an encapsulatable ML-KEM-768 prekey and fails closed if it does not. Production builds still require external review, stable test vectors, and downgrade UX for non-desktop protocol paths.

### 2.3 FIDO2 hmac-secret Extension Availability

Not all browsers and hardware keys support the FIDO2 hmac-secret extension (CTAP2.1). Chrome on desktop supports it; Safari on iOS/macOS has partial support; Firefox support depends on OS-level implementation.

**Mitigation:** Hardware key vault protection is optional. Users without hmac-secret support can use passphrase-only vault protection, hardware key server login, or wait for platform support to improve.

### 2.4 Multi-Device Key Distribution

The relay has device registration/prekey foundations, but the desktop client does not yet implement encrypted device-link approval or private state transfer between a user's devices.

**Limitation:** Aegis should not sync private keys through the relay in plaintext or via server escrow. A future device-link flow must transfer device state encrypted end-to-end from an approved existing device. Users who lose all enrolled devices and all recovery phrases are permanently locked out, by design.

### 2.5 Group Messaging Scope

Desktop MVP group messaging uses per-recipient E2EE fanout over each member's 1:1 contact secret. The sender uploads one encrypted envelope per member.

**Limitation:** This is not RFC 9420 MLS. It does not provide MLS tree-based group forward secrecy, efficient membership changes, or cryptographic group state commits. Large groups and advanced group admin controls remain out of scope until an audited MLS implementation is integrated.

### 2.6 Offline Message Delivery Modes

TTL persistent relay mode is now the default and stores only encrypted envelopes plus hashed capability metadata in a local JSON store. Strict ephemeral mode remains available with `AEGIS_RELAY_MODE=strict_ephemeral`.

**Limitation:** Strict ephemeral mode can still drop offline messages after process restart or TTL cleanup. TTL persistence improves availability, but it is not durable database replication and still depends on the relay host's local storage.

---

## 3. Out of Scope for MVP

The following features are planned for post-MVP releases and are explicitly out of scope for the initial release:

| Feature | Reason |
|---|---|
| Mobile apps (iOS/Android) | Desktop-first; mobile requires separate security review |
| Voice/video calls | Complex attack surface; separate protocol needed |
| Server-side search | Would require plaintext indexing — incompatible with security model |
| Message reactions / emoji | Non-critical feature; adds metadata |
| Public channels | Not aligned with private messenger model |
| Bots / integrations | Security attack surface; deferred |
| Read receipts (server-visible) | Metadata; privacy degradation |
| Typing indicators (server-visible) | Metadata; privacy degradation |
| "Last seen" / online status | Metadata; privacy degradation |
| MLS group ratchet tree | Current desktop group messaging is per-recipient fanout, not RFC 9420 MLS |
| Contact transfer between devices | Requires secure offline transfer protocol |
| Key escrow / account recovery server | Single point of failure; against design principle |
| Mixnet transport | Significant trade-offs; future version |

### 3.1 Desktop MVP Feature Boundaries

The desktop app now has an invite/import/send/poll flow for 1:1 encrypted messages. The contact secret is derived client-side from X25519 identity keys exchanged through the invite. This is useful for local demos and paired-device workflows, but it is not a full PQXDH responder implementation yet.

Hardware unlock enrollment currently records local intent and display metadata. It does not yet use FIDO2 hmac-secret/PRF to derive or unwrap the vault key.

Group messaging currently sends one encrypted envelope per member using the member's 1:1 session. This keeps the relay blind to plaintext, but it does not provide MLS tree-based group forward secrecy or efficient membership changes.

Tor/I2P mode configures the transport HTTP client to use a proxy. It does not add cover traffic, padding beyond existing envelope buckets, mixnet routing, or global traffic-correlation resistance.

Envelope payloads are padded before relay upload, and the relay exposes a cover-traffic endpoint for padded dummy traffic. These reduce simple size and activity signals, but they do not provide mixnet-level anonymity or global passive adversary resistance.

---

## 4. What Aegis Does NOT Claim to Be

- **Not a replacement for Signal.** Aegis prioritizes metadata minimization and post-quantum readiness differently. Signal has more mature group messaging.
- **Not a replacement for Signal's sealed sender.** Aegis does not implement sender hiding in the MVP.
- **Not a "private" messenger in the sense of hiding from the user's own OS.** Aegis runs as a standard desktop application, not a hidden process.
- **Not resistant to a coercive attacker with full physical access and the user's cooperation.** Duress PIN provides plausible deniability, not cryptographic deniability.
- **Not audited by a third party (yet).** The cryptographic design is reviewed internally against this document. External audit is planned before production release.
- **Not providing legal guarantees.** This is security software. Use it as one layer of your personal security posture, not as the only layer.

---

## 5. Security Warnings to Display to Users

The following warnings should be shown to users at appropriate points:

1. **On vault creation:** "Your recovery phrase is the ONLY way to recover your vault if you lose your hardware keys and passphrase. Write it down. Store it offline. Do NOT take a screenshot. Aegis never stores your recovery phrase."

2. **On hardware key enrollment:** "Enroll at least one backup hardware key. If you lose your only hardware key and do not have a recovery phrase, your vault is permanently inaccessible."

3. **On duress PIN setup:** "The duress PIN opens a decoy vault. The decoy vault should look convincing. Do not put obviously fake data in it. Advanced forensic analysis may still detect the presence of a decoy vault. Aegis cannot guarantee perfect plausible deniability."

4. **On Tor mode:** "Using Tor hides your IP address from the Aegis relay server, but your ISP can see you're using Tor. The Tor network itself may observe traffic to/from the Aegis relay. For maximum privacy, use Tor in a country with strong privacy laws."

5. **On key change:** "A contact's security key has changed. This could mean they reinstalled the app, got a new device, or an attacker intercepted your connection. Verify the new safety number in person if possible."

---

## 6. Revision History

| Version | Date | Changes |
|---|---|---|
| 0.1.0-draft | 2026-06-25 | Initial draft |
