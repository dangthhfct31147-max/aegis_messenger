# Aegis Messenger — Server Privacy Model

**Version:** 0.1.0-draft  
**Last Updated:** 2026-06-25

---

## 1. Design Principle

The Aegis relay server is a **dumb pipe** for encrypted envelopes. It knows nothing about:

- Who sends messages
- Who receives messages
- What the messages say
- Who contacts whom
- Group names or members
- User profile names or avatars

The server has no business logic, no conversation state, and no message content.

---

## 2. Server Database Schema

The server MUST only contain these tables. No other tables are permitted.

### 2.1 `accounts`

```
accounts
  account_id_random    BYTEA(32)    PRIMARY KEY  -- 256-bit random, server-generated
  created_at_bucket   TIMESTAMPTZ              -- 1-hour bucket, no exact time
  public_metadata     JSONB       DEFAULT '{}'  -- optional: display_name_hash, avatar_hash
                                                   -- no phone, no email, no username
```

**Notes:**
- No email, phone, or username. Account creation requires no identifying information.
- `public_metadata` is optional and only for features the user explicitly enables.
- Server MUST NOT require or store any PII.

### 2.2 `devices`

```
devices
  device_id_random    BYTEA(32)    PRIMARY KEY  -- 256-bit random
  account_id_random   BYTEA(32)    NOT NULL     -- FK to accounts
  device_public_id_key BYTEA(32)               -- X25519 public key (32 bytes)
  signed_prekey_public BYTEA(32)                -- signed prekey public
  pq_prekey_public     BYTEA(32)   DEFAULT NULL -- ML-KEM-768 encapsulated key (if available)
  signature            BYTEA(64)    NOT NULL     -- Ed25519 signature over prekeys
  key_version         INT          NOT NULL     -- monotonically increasing
  created_at_bucket   TIMESTAMPTZ              -- 1-hour bucket
  revoked_at          TIMESTAMPTZ  DEFAULT NULL -- NULL = active
```

**Notes:**
- One-time prekeys are stored as separate rows (one row per prekey, deleted after use).
- Private keys are NEVER on the server.
- Device revocation sets `revoked_at`; the row is NOT deleted immediately.

### 2.3 `queues`

```
queues
  queue_id_hash       BYTEA(32)    PRIMARY KEY  -- SHA-512 of random queue_id
  read_cap_hash       BYTEA(32)    NOT NULL     -- SHA-512 of read token
  write_cap_hash      BYTEA(32)    NOT NULL     -- SHA-512 of write token
  account_id_random   BYTEA(32)   NOT NULL     -- FK to accounts
  created_at_bucket   TIMESTAMPTZ              -- 1-hour bucket
  expires_at          TIMESTAMPTZ  NOT NULL     -- auto-cleanup
  rate_limit_bucket   INT          DEFAULT 0    -- for rate limiting
```

**Notes:**
- Server stores SHA-512 hashes of all tokens, never raw tokens.
- Raw tokens are returned to clients once on creation and never stored in plaintext.
- Queue IDs are 256-bit random values, not sequential or guessable.
- `expires_at` enables automatic cleanup via a background job.

### 2.4 `envelopes`

```
envelopes
  envelope_id_random  BYTEA(32)    PRIMARY KEY
  queue_id_hash       BYTEA(32)    NOT NULL     -- index for fast polling
  ciphertext_blob     BYTEA        NOT NULL     -- AEAD ciphertext (variable size)
  padded_size_bucket  INT          NOT NULL     -- 256-byte size bucket
  created_at_bucket   TIMESTAMPTZ              -- 1-hour bucket, not exact
  expires_at          TIMESTAMPTZ  NOT NULL     -- TTL expiry
  delivery_state      TEXT          DEFAULT 'pending'  -- pending / delivered / expired
```

**CRITICAL:**
- NO `sender_id` column.
- NO `receiver_id` column.
- NO `conversation_id` column.
- NO `message_body` or `plaintext` column.
- `padded_size_bucket` is the only size information — actual size is not stored.
- Envelopes are deleted after `expires_at` or immediately after delivery acknowledgment.

### 2.5 `one_time_prekeys`

```
one_time_prekeys
  id                  SERIAL       PRIMARY KEY
  account_id_random   BYTEA(32)   NOT NULL
  device_id_random    BYTEA(32)   NOT NULL
  prekey_id           INT          NOT NULL
  prekey_public       BYTEA(32)   NOT NULL     -- X25519 public
  pq_prekey_public    BYTEA(32)   DEFAULT NULL -- ML-KEM-768 public
  created_at_bucket   TIMESTAMPTZ              -- 1-hour bucket
  used_at             TIMESTAMPTZ  DEFAULT NULL -- NULL = available
```

**Notes:**
- Row is deleted immediately after use (not soft-deleted).
- Each prekey is single-use.

### 2.6 `transparency_log`

```
transparency_log
  id                  SERIAL       PRIMARY KEY
  event_hash         BYTEA(32)    NOT NULL     -- BLAKE3 of event data
  prev_hash          BYTEA(32)    NOT NULL     -- hash of previous event
  event_data         BYTEA        NOT NULL     -- device_add, device_revoked, etc.
  signature          BYTEA(64)    NOT NULL     -- Ed25519 over event_data
  timestamp_bucket   TIMESTAMPTZ              -- 1-hour bucket
```

**Notes:**
- Append-only. No deletes or updates.
- Used for key transparency: clients can detect unexpected device additions.

### 2.7 `device_key_packages`

```
device_key_packages
  device_id_random        BYTEA(32) PRIMARY KEY
  account_id_random       BYTEA(32) NOT NULL
  mls_key_package         BYTEA     NOT NULL  -- public OpenMLS key package material
  device_list_signature   BYTEA(64) NOT NULL
  key_version             INT       NOT NULL
  created_at_bucket       TIMESTAMPTZ
```

### 2.8 `device_link_bundles`

```
device_link_bundles
  bundle_id_random        BYTEA(32) PRIMARY KEY
  account_id_random       BYTEA(32) NOT NULL
  target_device_id_random BYTEA(32) NOT NULL
  encrypted_payload       BYTEA     NOT NULL  -- E2E encrypted private-state transfer bundle
  created_at_bucket       TIMESTAMPTZ
  expires_at              TIMESTAMPTZ NOT NULL
```

Private keys, contact plaintext, message plaintext, and decrypted device state remain forbidden on the relay.

---

## 3. What the Server MUST NOT Have

The following are strictly forbidden in any server database or log:

- `conversations` table
- `conversation_members` table
- `friendships` or `contacts` table
- `messages` table with `sender_id` or `receiver_id`
- Plaintext message body
- Plaintext file metadata (filename, MIME type)
- Plaintext group names
- Plaintext profile names
- Plaintext avatars
- Raw queue IDs or tokens
- User IP addresses (logged)
- Exact request timestamps
- Request body contents
- Sender or receiver account ID in envelope storage
- Any correlation between envelopes and user accounts beyond `queue_id_hash`

---

## 4. Relay Modes

### 4.1 Strict Relay Mode (Default — Highest Security)

```
1. Client A uploads encrypted envelope to server.
2. Server stores envelope in RAM only (never to disk).
3. Server immediately relays to Client B's long-poll / WebSocket connection.
4. If Client B is offline: server drops the envelope (no storage).
5. Client A keeps pending message locally and retries when Client B is online.
```

**Privacy:** Maximum. Server holds zero persisted data about messages.

**Availability tradeoff:** Messages are lost if recipient is offline. Sender must retry.

### 4.2 Ephemeral Offline Mode (Optional)

```
1. Client A uploads encrypted envelope to server.
2. Server stores envelope in DB with TTL (default: 24 hours).
3. Client B polls / connects and receives envelope.
4. Server deletes envelope after delivery OR TTL expiry.
5. Server never sees plaintext.
```

**Privacy:** Strong, but server stores ciphertext. TTL limits exposure window.

**Availability tradeoff:** Recipients can receive messages sent while offline (up to TTL).

---

## 5. Capability Token System

Every queue has three tokens:

| Token | Purpose | Stored on Server |
|---|---|---|
| `queue_id` | Routing address for sender | Hashed only (`queue_id_hash`) |
| `read_token` | Recipient uses to poll/download | Hashed only (`read_cap_hash`) |
| `write_token` | Sender uses to upload | Hashed only (`write_cap_hash`) |

Raw tokens are returned to the user once during queue creation. The user must store them securely (e.g., in their vault, in their contact invite link).

**Invite Link Format (URL-safe, base64url):**

```
aegis://invite/
  ?v=1                              -- protocol version
  &q=<queue_id_base64url>           -- queue ID
  &r=<read_token_base64url>         -- read capability
  &w=<write_token_base64url>        -- write capability
  &pk=<signed_prekey_bundle_b64>   -- signed prekey bundle
  &sig=<signature_b64>             -- signature over invite
  &exp=<unix_timestamp>            -- invite expiration
```

---

## 6. Server API Endpoints

All endpoints require TLS. No endpoint returns raw tokens — only hashes are stored.

### Registration (Account)

```
POST /v1/accounts
Body: { public_metadata?: {...} }
Response: { account_id: b64, created_at: bucket_ts }
```

### Device Registration

```
POST /v1/accounts/{account_id}/devices
Headers: Authorization: Bearer {account_token}
Body: {
  device_public_id_key: b64,
  signed_prekey_public: b64,
  pq_prekey_public?: b64,
  signature: b64
}
Response: { device_id: b64, key_version: int }
```

### Queue Creation

```
POST /v1/queues
Headers: Authorization: Bearer {account_token}
Response: {
  queue_id: b64_raw,
  read_token: b64_raw,
  write_token: b64_raw,
  expires_at: timestamp
}
```

### Envelope Upload (Strict Mode — RAM Only)

```
POST /v1/relay/{queue_id_hash}
Headers: Authorization: Bearer {write_token_hash}
Body: { ciphertext_blob: b64, padded_size_bucket: int }
Response: 202 Accepted (no body stored)
```

### Envelope Upload (Ephemeral Mode)

```
POST /v1/envelopes
Headers: Authorization: Bearer {write_token_hash}
Body: {
  queue_id_hash: b64,
  ciphertext_blob: b64,
  padded_size_bucket: int,
  ttl_seconds: int?
}
Response: { envelope_id: b64, expires_at: timestamp }
```

### Envelope Poll (Recipient)

```
GET /v1/envelopes?queue={queue_id_hash}&since={envelope_id?}
Headers: Authorization: Bearer {read_token_hash}
Response: { envelopes: [{ envelope_id, ciphertext_blob, created_at_bucket }] }
```

### Envelope Delivery Acknowledgment

```
DELETE /v1/envelopes/{envelope_id}
Headers: Authorization: Bearer {read_token_hash}
Response: 204 No Content
```

### Prekey Bundle Fetch

```
GET /v1/prekeys/{device_id}
Response: {
  signed_prekey_public: b64,
  pq_prekey_public?: b64,
  signature: b64
}
```

### Device Key Package Publish/Fetch

```
POST /v1/device-key-packages
Body: {
  account_id: b64,
  device_id: b64,
  mls_key_package: b64,
  device_list_signature: b64,
  key_version: int
}

GET /v1/device-key-packages/{device_id}
Response: { account_id, device_id, mls_key_package, device_list_signature, key_version, created_at_bucket }
```

### Transparency Log

```
POST /v1/transparency-log
Body: { account_id, device_id, event_type, event_hash, prev_hash, signature }

GET /v1/transparency-log?account_id={account_id}
Response: { events: [...] }
```

### Encrypted Device-Link Bundle

```
POST /v1/device-link-bundles
Body: { account_id, target_device_id, encrypted_payload, ttl_seconds? }

GET /v1/device-link-bundles/{bundle_id}
Response: { bundle_id, account_id, target_device_id, encrypted_payload, expires_at, created_at_bucket }
```

### Dummy Traffic

Dummy traffic MUST use `POST /v1/envelopes` with ciphertext-shaped padded blobs and `dummy=true`. The old `/v1/cover` endpoint is deprecated because a separate endpoint makes dummy traffic distinguishable from real envelope traffic.

### One-Time Prekey Upload

```
POST /v1/prekeys
Headers: Authorization: Bearer {account_token}
Body: {
  device_id: b64,
  prekeys: [{ prekey_id: int, prekey_public: b64, pq_prekey_public?: b64 }]
}
Response: 201 Created
```

---

## 7. Logging Policy

Server logs MUST NOT contain:

- User IP addresses (use `[REDACTED]` or omit)
- Raw queue IDs or tokens
- Request bodies (message content)
- `account_id` in plaintext
- `device_id` in plaintext
- Exact timestamps (use 1-hour buckets)
- `envelope_id` in plaintext (use `[REDACTED]`)
- Message sizes (only padded bucket sizes)

Server logs MAY contain (in aggregate, anonymized):

- Total envelope count per hour
- Average queue lifetime
- Error type counts
- Total active accounts (not individual)
- Total encrypted data volume (no per-user breakdown)

**Example safe log line:**
```
[2026-06-25T14:00:00Z] "POST /v1/envelopes" 202 45ms -- ip=[REDACTED] bytes=[bucket_2k_4k]
```

---

## 8. Deletion Policy

| Data | Deletion Trigger | Method |
|---|---|---|
| Envelope | After delivery acknowledgment OR TTL expiry | Hard delete |
| One-time prekey | After first use | Hard delete |
| Queue | After `expires_at` | Hard delete |
| Device | After revocation + grace period | Hard delete |
| Account | After user-initiated deletion | Hard delete |
| Transparency log | Never (append-only) | N/A |

---

## 9. Rate Limiting

- Per `write_cap_hash`: 100 uploads per minute
- Per `read_cap_hash`: 100 polls per minute
- Per `account_id`: 10 device registrations per day
- Per IP: 1000 requests per minute (general)

---

## 10. Security Review Checklist

Before adding any new server feature:

- [ ] Does this require storing any plaintext message content?
- [ ] Does this create a correlation between queue_id and account_id that can be inferred by the server?
- [ ] Does this require logging the sender or receiver of any message?
- [ ] Does this create a `conversations` or `contacts` table?
- [ ] Does this expose any user's IP address to any other user?
- [ ] Does this log raw queue IDs or tokens?
- [ ] Does this require email or phone verification?

If any answer is "yes", the feature MUST be redesigned or deferred.

---

## 11. Revision History

| Version | Date | Changes |
|---|---|---|
| 0.1.0-draft | 2026-06-25 | Initial draft |
