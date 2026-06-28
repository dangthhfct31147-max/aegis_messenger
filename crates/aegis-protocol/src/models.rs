//! Public protocol models shared by clients and services.

use aegis_crypto::CipherSuite;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceRegistration {
    pub account_id: Option<String>,
    pub device_id: Option<String>,
    pub public_id_key: String,
    pub signed_prekey_public: String,
    pub pq_prekey_public: Option<String>,
    pub signature: String,
    pub key_version: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RegisteredDevice {
    pub account_id: String,
    pub device_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OneTimePrekey {
    pub id: u32,
    pub public_key: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrekeyBundle {
    pub account_id: String,
    pub device_id: String,
    pub public_id_key: String,
    pub signed_prekey_public: String,
    pub pq_prekey_public: Option<String>,
    pub signature: String,
    pub key_version: u32,
    pub cipher_suite: CipherSuite,
    pub one_time_prekey: Option<OneTimePrekey>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedFileChunk {
    pub chunk_id: u32,
    pub hash: String,
    pub nonce: String,
    pub size: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedFileManifest {
    pub file_id: String,
    pub encrypted_name: String,
    pub encrypted_mime: String,
    pub size: u64,
    pub chunks: Vec<EncryptedFileChunk>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SafetyNumber {
    pub version: u16,
    pub digits: String,
    pub local_identity_fingerprint: String,
    pub remote_identity_fingerprint: String,
}
