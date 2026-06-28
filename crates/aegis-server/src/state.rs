//! In-memory state for the relay server
//!
//! In production, replace with PostgreSQL. The structures here mirror
//! the production schema so the swap is straightforward.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory envelope storage
#[derive(Debug, Clone)]
pub struct Envelope {
    pub id: [u8; 32],
    pub queue_id_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub padded_size_bucket: i32,
    pub created_at_bucket: String,
    pub expires_at: DateTime<Utc>,
    pub delivery_state: String,
}

/// In-memory queue storage
#[derive(Debug, Clone)]
pub struct Queue {
    pub id_hash: [u8; 32],
    pub read_cap_hash: [u8; 32],
    pub write_cap_hash: [u8; 32],
    pub account_id: [u8; 32],
    pub created_at_bucket: String,
    pub expires_at: DateTime<Utc>,
}

/// In-memory device registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: [u8; 32],
    pub account_id: [u8; 32],
    pub public_id_key: Vec<u8>,
    pub signed_prekey_public: Vec<u8>,
    pub pq_prekey_public: Option<Vec<u8>>,
    pub signature: Vec<u8>,
    pub key_version: i32,
    pub created_at_bucket: String,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// In-memory account
#[derive(Debug, Clone)]
pub struct Account {
    pub account_id: [u8; 32],
    pub created_at_bucket: String,
    pub public_metadata: serde_json::Value,
}

/// Shared server state
pub struct ServerState {
    pub accounts: RwLock<HashMap<[u8; 32], Account>>,
    pub devices: RwLock<HashMap<[u8; 32], Device>>,
    pub queues: RwLock<HashMap<[u8; 32], Queue>>,
    pub envelopes: RwLock<HashMap<[u8; 32], Envelope>>,
    /// envelopes indexed by queue_id_hash → list of envelope IDs
    pub queue_envelopes: RwLock<HashMap<[u8; 32], Vec<[u8; 32]>>>,
    pub relay_mode: RelayMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    /// Server keeps envelopes in RAM only. No persistence. Offline delivery impossible.
    Strict,
    /// Server stores encrypted envelopes with TTL.
    Ephemeral { ttl_seconds: i64 },
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            accounts: RwLock::new(HashMap::new()),
            devices: RwLock::new(HashMap::new()),
            queues: RwLock::new(HashMap::new()),
            envelopes: RwLock::new(HashMap::new()),
            queue_envelopes: RwLock::new(HashMap::new()),
            relay_mode: RelayMode::Strict,
        }
    }
}

impl ServerState {
    pub fn new(relay_mode: RelayMode) -> Self {
        Self {
            relay_mode,
            ..Default::default()
        }
    }
}
