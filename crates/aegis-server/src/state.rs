//! In-memory state for the relay server
//!
//! In production, replace with PostgreSQL. The structures here mirror
//! the production schema so the swap is straightforward.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

/// In-memory envelope storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub id: [u8; 32],
    pub queue_id_hash: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub padded_size_bucket: i32,
    pub created_at_bucket: String,
    pub expires_at: DateTime<Utc>,
    pub delivery_state: String,
    #[serde(default)]
    pub is_dummy: bool,
}

/// In-memory queue storage
#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKeyPackage {
    pub account_id: [u8; 32],
    pub device_id: [u8; 32],
    pub mls_key_package: Vec<u8>,
    pub device_list_signature: Vec<u8>,
    pub key_version: i32,
    pub created_at_bucket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyLogEvent {
    pub event_id: [u8; 32],
    pub account_id: [u8; 32],
    pub device_id: [u8; 32],
    pub event_type: String,
    pub event_hash: Vec<u8>,
    pub prev_hash: Vec<u8>,
    pub signature: Vec<u8>,
    pub created_at_bucket: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceLinkBundle {
    pub bundle_id: [u8; 32],
    pub account_id: [u8; 32],
    pub target_device_id: [u8; 32],
    pub encrypted_payload: Vec<u8>,
    pub created_at_bucket: String,
    pub expires_at: DateTime<Utc>,
}

/// In-memory account
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub device_key_packages: RwLock<HashMap<[u8; 32], DeviceKeyPackage>>,
    pub transparency_log: RwLock<Vec<TransparencyLogEvent>>,
    pub device_link_bundles: RwLock<HashMap<[u8; 32], DeviceLinkBundle>>,
    pub relay_mode: RelayMode,
    pub persistence_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedRelayState {
    pub accounts: Vec<Account>,
    pub devices: Vec<Device>,
    pub queues: Vec<Queue>,
    pub envelopes: Vec<Envelope>,
    pub queue_envelopes: Vec<([u8; 32], Vec<[u8; 32]>)>,
    pub device_key_packages: Vec<DeviceKeyPackage>,
    pub transparency_log: Vec<TransparencyLogEvent>,
    pub device_link_bundles: Vec<DeviceLinkBundle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayMode {
    /// Server keeps envelopes in RAM only. Offline delivery is best-effort.
    StrictEphemeral,
    /// Server may persist encrypted envelopes until TTL expiry.
    TtlPersistent { ttl_seconds: i64 },
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            accounts: RwLock::new(HashMap::new()),
            devices: RwLock::new(HashMap::new()),
            queues: RwLock::new(HashMap::new()),
            envelopes: RwLock::new(HashMap::new()),
            queue_envelopes: RwLock::new(HashMap::new()),
            device_key_packages: RwLock::new(HashMap::new()),
            transparency_log: RwLock::new(Vec::new()),
            device_link_bundles: RwLock::new(HashMap::new()),
            relay_mode: RelayMode::StrictEphemeral,
            persistence_path: None,
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

    pub fn new_with_persistence(relay_mode: RelayMode, persistence_path: PathBuf) -> Self {
        let persisted = std::fs::read(&persistence_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<PersistedRelayState>(&bytes).ok())
            .unwrap_or_default();
        Self {
            accounts: RwLock::new(
                persisted
                    .accounts
                    .into_iter()
                    .map(|account| (account.account_id, account))
                    .collect(),
            ),
            devices: RwLock::new(
                persisted
                    .devices
                    .into_iter()
                    .map(|device| (device.device_id, device))
                    .collect(),
            ),
            queues: RwLock::new(
                persisted
                    .queues
                    .into_iter()
                    .map(|queue| (queue.id_hash, queue))
                    .collect(),
            ),
            envelopes: RwLock::new(
                persisted
                    .envelopes
                    .into_iter()
                    .map(|envelope| (envelope.id, envelope))
                    .collect(),
            ),
            queue_envelopes: RwLock::new(persisted.queue_envelopes.into_iter().collect()),
            device_key_packages: RwLock::new(
                persisted
                    .device_key_packages
                    .into_iter()
                    .map(|package| (package.device_id, package))
                    .collect(),
            ),
            transparency_log: RwLock::new(persisted.transparency_log),
            device_link_bundles: RwLock::new(
                persisted
                    .device_link_bundles
                    .into_iter()
                    .map(|bundle| (bundle.bundle_id, bundle))
                    .collect(),
            ),
            relay_mode,
            persistence_path: Some(persistence_path),
        }
    }

    pub fn save_to_disk(&self) -> Result<(), String> {
        let Some(path) = &self.persistence_path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let persisted = PersistedRelayState {
            accounts: self
                .accounts
                .read()
                .map_err(|e| e.to_string())?
                .values()
                .cloned()
                .collect(),
            devices: self
                .devices
                .read()
                .map_err(|e| e.to_string())?
                .values()
                .cloned()
                .collect(),
            queues: self
                .queues
                .read()
                .map_err(|e| e.to_string())?
                .values()
                .cloned()
                .collect(),
            envelopes: self
                .envelopes
                .read()
                .map_err(|e| e.to_string())?
                .values()
                .cloned()
                .collect(),
            queue_envelopes: self
                .queue_envelopes
                .read()
                .map_err(|e| e.to_string())?
                .iter()
                .map(|(queue_id_hash, envelopes)| (*queue_id_hash, envelopes.clone()))
                .collect(),
            device_key_packages: self
                .device_key_packages
                .read()
                .map_err(|e| e.to_string())?
                .values()
                .cloned()
                .collect(),
            transparency_log: self
                .transparency_log
                .read()
                .map_err(|e| e.to_string())?
                .clone(),
            device_link_bundles: self
                .device_link_bundles
                .read()
                .map_err(|e| e.to_string())?
                .values()
                .cloned()
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&persisted).map_err(|e| e.to_string())?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }
}
