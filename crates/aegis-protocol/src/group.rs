//! Group messaging (MLS-inspired, client-side group state)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub group_id: [u8; 32],
    pub name: Option<String>,
    pub created_at: i64,
    pub members: Vec<GroupMember>,
    pub our_role: GroupRole,
    pub group_secret_encrypted: Vec<u8>,
    pub key_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub identity_public: [u8; 32],
    pub display_name: Option<String>,
    pub role: GroupRole,
    pub joined_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupRole {
    Member,
    Admin,
}

impl Group {
    pub fn new(members: Vec<GroupMember>, our_role: GroupRole) -> Self {
        Self {
            group_id: aegis_crypto::random::random_32bytes(),
            name: None,
            created_at: chrono::Utc::now().timestamp(),
            members,
            our_role,
            group_secret_encrypted: Vec::new(),
            key_version: 1,
        }
    }
}
