//! Contact management

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use aegis_crypto::CipherSuite;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub contact_id: Uuid,
    pub display_name: Option<String>,
    pub identity_public: [u8; 32],
    pub queue_id: Vec<u8>,
    pub read_token: Vec<u8>,
    pub write_token: Vec<u8>,
    pub signed_prekey: [u8; 32],
    pub identity_key: [u8; 32],
    pub remaining_prekeys: u32,
    pub key_version: u32,
    pub cipher_suite: CipherSuite,
    pub safety_number_verified: Option<u64>,
    pub created_at: i64,
    pub last_active: Option<i64>,
}

impl Contact {
    pub fn new(
        queue_id: Vec<u8>,
        read_token: Vec<u8>,
        write_token: Vec<u8>,
        identity_public: [u8; 32],
        signed_prekey: [u8; 32],
        cipher_suite: CipherSuite,
    ) -> Self {
        Self {
            contact_id: Uuid::new_v4(),
            display_name: None,
            identity_public,
            queue_id,
            read_token,
            write_token,
            signed_prekey,
            identity_key: identity_public,
            remaining_prekeys: 100,
            key_version: 1,
            cipher_suite,
            safety_number_verified: None,
            created_at: chrono::Utc::now().timestamp(),
            last_active: None,
        }
    }
}

pub fn compute_safety_number(our_identity: &[u8; 32], their_identity: &[u8; 32]) -> u64 {
    use sha2::{Sha512, Digest};
    let mut hasher = Sha512::new();
    let (a, b) = if our_identity < their_identity { (our_identity, their_identity) } else { (their_identity, our_identity) };
    hasher.update(a);
    hasher.update(b);
    let hash = hasher.finalize();
    u64::from_be_bytes(hash[..8].try_into().unwrap())
}
