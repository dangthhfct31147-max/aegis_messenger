# Aegis Messenger — Hardware Key Design

**Version:** 0.1.0-draft  
**Last Updated:** 2026-06-25

---

## 1. Overview

Hardware security keys (FIDO2/WebAuthn) are a core security feature of Aegis Messenger, not a gimmick. They provide protection against:

- Offline passphrase brute force (attacker steals laptop database)
- Unauthorized vault unlock on a device the attacker has physical access to
- Coercive unlock (combined with duress PIN)

Hardware keys do NOT protect against:
- Screen capture while the vault is unlocked
- RAM scraping by OS-level malware
- Keyboard logging
- A fully compromised operating system

---

## 2. Supported Hardware Keys

| Standard | Use Case | Examples |
|---|---|---|
| FIDO2 / WebAuthn | Login + vault unlock (PRF extension) | YubiKey 5 Series, Google Titan, Solo v2 |
| FIDO2 / CTAP2 | hmac-secret extension for vault PRF | YubiKey 5 Series, Feitian ePass |
| U2F (backwards compat) | Login only | Older YubiKeys |

Requirements for vault unlock PRF:
- FIDO2 with `hmac-secret` extension (CTAP2.1+)
- Platform must support `navigator.credentials.get({..., publicKey: {..., extensions: {hmnSecret: true} }})`

---

## 3. Vault Unlock with Hardware Key

### 3.1 Registration Flow

```
1. User inserts hardware key and clicks "Add Hardware Key" in settings
2. App generates registration challenge: 32 random bytes (challenge_nonce)
3. App calls navigator.credentials.create({
     publicKey: {
       rp:   { name: "Aegis Messenger", id: "aegis-messenger" },
       user: { id: <user's vault_salt>, name: "aegis-vault", displayName: "Aegis" },
       pubKeyCredParams: [{ alg: -8, type: "public-key" }],  // EdDSA
       attestation: "none",
       authenticatorSelection: { userVerification: "required" },
       extensions: { hmacSecret: true }
     }
   })
4. Hardware key generates key pair, signs attestation
5. App stores credential ID and public key (encrypted in vault) for future PRF calls
6. User names the key ("Primary", "Backup") and sets priority order
```

### 3.2 Vault Unlock Flow

```
1. App prompts for passphrase (required)
2. App prompts for hardware key touch (required for hw-key-protected vaults)

   // In Phase 5, hardware key must be present to unlock a hw-protected vault.
   // This is intentional: no hw key = no vault access.

3. App computes Argon2id(passphrase, salt) → 32-byte intermediate
4. App calls navigator.credentials.get({
     publicKey: {
       challenge: Argon2id_output,   // challenge bound to passphrase
       allowCredentials: [{ id: credential_id, type: "public-key" }],
       userVerification: true,
       extensions: { hmacSecret: true }
     }
   })
5. Hardware key computes hmac_secret = HMAC-SHA256(auth_key, Argon2id_output)
   — The auth_key is unique per credential, bound to the device and user ID
   — The challenge (Argon2id output) ensures hw key output is bound to this passphrase
6. App receives hmac_secret (32 bytes)
7. App derives:
   vault_master_key = HKDF-SHA512(
     ikm: Argon2id_output || hmac_secret,
     salt: "aegis-hw-vault",
     info: vault_salt
   )
8. If vault_master_key decrypts the vault header → unlock SUCCESS
   If not → unlock FAIL (wrong passphrase OR wrong hardware key)
```

### 3.3 Security Properties

- **Passphrase alone is insufficient.** Even with the passphrase, attacker cannot unlock without the hardware key.
- **Hardware key alone is insufficient.** Without the correct passphrase, the hmac-secret challenge will produce a different output, and the derived vault key will be wrong.
- **No passphrase stored on server.** The challenge is derived from the local Argon2id output, not from any server-stored value.
- **Replay attack prevented.** Each unlock uses a fresh Argon2id output as the WebAuthn challenge.

---

## 4. Multi-Key Support

### 4.1 Primary + Backup Key

Aegis requires at least one backup hardware key to be enrolled. This prevents permanent lockout if the primary key is lost.

```
Registration:
1. User enrolls primary key (step 3.1)
2. User enrolls backup key (step 3.1)
3. App requires BOTH keys to be verified during enrollment to confirm:
   - Both keys produce correct PRF for the same vault_salt
   - App stores credential IDs for both keys
```

### 4.2 Recovery Phrase

A 24-word BIP-39 mnemonic is generated during vault creation. This serves as an offline backup when hardware keys are unavailable.

```
Recovery phrase = 24 words from wordlist[2048]
Entropy:        256 bits (security equivalent to 24-word phrase)
Stored:         User-written on paper; NEVER in digital storage

Recovery flow:
1. User enters 24-word recovery phrase
2. App derives: recovery_seed = BIP39_derive(mnemonic)
3. App derives: recovery_master = HKDF-SHA512(recovery_seed, info="aegis-recovery")
4. App attempts vault unlock with recovery_master as hmac_secret stand-in
5. If successful: vault unlocks; user is prompted to enroll new hardware key
6. If failed: recovery phrase is wrong OR vault is corrupted
```

### 4.3 Hardware Key Replacement

```
1. User must have access to an existing enrolled device (primary or backup key)
   OR a recovery phrase
2. App generates new credential for the new hardware key
3. App re-encrypts vault wrapping keys with new hardware key factor
4. Old credential is marked as revoked in vault
5. Local security event is logged: "Hardware key replaced: OLD_NAME -> NEW_NAME"
```

---

## 5. Hardware Key Removal Detection

Platform-specific detection of hardware key removal:

### 5.1 macOS

- Monitor `IOPSNotificationCreate` for USB HID device change events
- Check for presence of known credential IDs via `CTKPolicyRegistry`
- If hardware key is removed while vault is unlocked → trigger panic lock

### 5.2 Windows

- Monitor `WM_DEVICECHANGE` for USB device removal
- Enumerate `SCardListReaders` (Smart Card / FIDO2 CCID)
- If hardware key is removed while vault is unlocked → trigger panic lock

### 5.3 Linux

- Monitor `udev` events for USB device removal (`libudev`)
- Enumerate FIDO2 devices via `libfido2` (`fido_dev_info()`)
- If hardware key is removed while vault is unlocked → trigger panic lock

### 5.4 Implementation Note

> **MVP Limitation:** Hardware key removal detection requires OS-level USB monitoring, which needs elevated permissions or specific platform APIs on some systems. This is planned for Phase 5 refinement. In MVP, auto-lock on vault close and on system sleep/screen lock provides the primary protection.

---

## 6. FIDO2 Login (Server)

For server authentication (account creation and device registration):

```
1. Client requests login challenge from server:
   GET /v1/auth/challenge
   Response: { challenge: b64_random_32_bytes, expires_at: timestamp }
2. Client calls navigator.credentials.get({
     publicKey: {
       challenge: server_challenge,
       allowCredentials: [{ id: stored_credential_id, type: "public-key" }],
       userVerification: true
     }
   })
3. Hardware key signs: authenticatorData || signature
4. Client sends to server:
   POST /v1/auth/verify
   { credential_id: b64, authenticator_data: b64, signature: b64, client_data_json: b64 }
5. Server verifies signature against stored public key
6. Server returns: { session_token: b64 } (short-lived, used for subsequent API calls)
```

**Server stores:** credential ID + public key (associated with account_id). No private keys ever touch the server.

---

## 7. Security Properties

| Property | Description |
|---|---|
| Two-factor | Both passphrase AND hardware key required for vault unlock |
| No server-stored secrets | Server stores only public credential data |
| No replay | Each unlock uses fresh challenge |
| No offline crack | Hardware key PRF cannot be extracted from credential ID |
| Multi-key | Support for primary + backup key |
| Recovery | 24-word recovery phrase for emergency access |
| Hardware key removal | Auto-lock on USB removal (Phase 5) |
| Duress mode | Duress PIN bypasses hardware key requirement for decoy vault |

---

## 8. Limitations

1. **Platform support:** Not all browsers/platforms support FIDO2 hmac-secret extension. Check availability before enabling.
2. **Cross-device:** Hardware keys enrolled on one device cannot be used to unlock vault on another device without migration.
3. **Backup key must be enrolled on same device:** For MVP, primary and backup keys must be enrolled on the same device. Cross-device key enrollment is planned for Phase 5.
4. **OS-level malware:** Hardware keys do not protect against OS-level malware that hooks into the UI after unlock.
5. **YubiKey OTPs:** FIDO2 is used, not YubiKey OTP mode. OTP mode is not used in Aegis.

---

## 9. Revision History

| Version | Date | Changes |
|---|---|---|
| 0.1.0-draft | 2026-06-25 | Initial draft |
