//! Bridge between the Aegis Vault and the Tauri desktop application.

use std::path::PathBuf;

use aegis_crypto::{
    aead,
    kem::{KemProvider, MlKem768Provider},
    signatures::sign_prekey_bundle,
    Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, SymmetricKey, X25519PrivateKey,
    X25519PublicKey,
};
use base64::Engine;
use sha2::{Digest, Sha512};

use crate::{ChatMessage, ContactInfo, DeviceInfo, GroupInfo};

const PROFILE_RECORD_ID: &str = "local-profile";
const CONTACTS_RECORD_ID: &str = "contacts";
const MESSAGES_RECORD_ID: &str = "messages";
const GROUPS_RECORD_ID: &str = "groups";
const DEVICES_RECORD_ID: &str = "devices";
const MLS_GROUPS_RECORD_ID: &str = "mls-groups";
const SETTINGS_RECORD_ID: &str = "settings";
const TRAFFIC_PROFILE_RECORD_ID: &str = "traffic-profile";

pub struct AppVault {
    vault: aegis_vault::AegisVault,
    is_unlocked: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LocalProfile {
    pub display_name: String,
    pub account_id: Option<String>,
    pub device_id: Option<String>,
    pub queue_id: String,
    pub read_token: String,
    pub write_token: String,
    pub identity_private: X25519PrivateKey,
    pub identity_public: X25519PublicKey,
    pub signing_private: Ed25519PrivateKey,
    pub signing_public: Ed25519PublicKey,
    pub signed_prekey_private: X25519PrivateKey,
    pub signed_prekey_public: X25519PublicKey,
    pub signed_prekey_signature: Ed25519Signature,
    pub pq_prekey_public: Vec<u8>,
    pub pq_prekey_private: Vec<u8>,
    pub key_version: u32,
    pub hardware_unlock_enabled: bool,
    pub hardware_unlock_label: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContactRecord {
    pub id: String,
    pub display_name: String,
    pub queue_id: String,
    pub write_token: String,
    pub device_id: Option<String>,
    pub remote_identity_public: X25519PublicKey,
    pub remote_signing_public: Ed25519PublicKey,
    pub signed_prekey_public: X25519PublicKey,
    pub pq_prekey_public: Option<Vec<u8>>,
    pub shared_secret: SymmetricKey,
    pub safety_number: String,
    pub verified_at: Option<i64>,
    #[serde(default)]
    pub pq_verified: bool,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MessageRecord {
    pub id: String,
    pub contact_id: String,
    pub direction: MessageDirection,
    pub plaintext: String,
    pub created_at: i64,
    pub envelope_id: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum MessageDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupRecord {
    pub id: String,
    pub name: String,
    pub member_contact_ids: Vec<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceState {
    pub device_id: String,
    pub display_name: String,
    pub key_version: u32,
    pub revoked: bool,
    pub linked_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceSyncBundle {
    pub version: u16,
    pub source_device_id: String,
    pub target_device_id: String,
    pub contacts: Vec<ContactRecord>,
    pub groups: Vec<GroupRecord>,
    pub mls_groups: Vec<MlsGroupState>,
    pub created_at: i64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MlsGroupState {
    pub group_id: String,
    pub name: String,
    pub epoch: u64,
    pub member_contact_ids: Vec<String>,
    pub backend: String,
    pub serialized_group_state: String,
    pub created_at: i64,
}

#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct MlsKeyPackageStore {
    pub packages: Vec<aegis_protocol::mls::MlsKeyPackage>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransportSettings {
    pub proxy_mode: ProxyMode,
    pub proxy_url: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    Direct,
    Tor,
    I2p,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContactInvite {
    pub version: u16,
    pub display_name: String,
    pub queue_id: String,
    pub write_token: String,
    pub device_id: Option<String>,
    pub identity_public: String,
    pub signing_public: String,
    pub signed_prekey_public: String,
    pub signed_prekey_signature: String,
    pub pq_prekey_public: String,
    pub key_version: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct WireMessage {
    id: String,
    sender_identity_public: String,
    ciphertext: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PaddedWireMessage {
    payload: WireMessage,
    padding: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct ContactList {
    contacts: Vec<ContactRecord>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct MessageList {
    messages: Vec<MessageRecord>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct GroupList {
    groups: Vec<GroupRecord>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct DeviceList {
    devices: Vec<DeviceState>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct MlsGroupList {
    groups: Vec<MlsGroupState>,
}

impl Default for AppVault {
    fn default() -> Self {
        Self::new()
    }
}

impl AppVault {
    pub fn new() -> Self {
        let _vault_path = Self::vault_path();
        let vault = aegis_vault::AegisVault::open().unwrap_or_else(|_| {
            aegis_vault::AegisVault::open_with_config(aegis_vault::VaultConfig::default())
                .expect("failed to initialize vault")
        });
        Self {
            vault,
            is_unlocked: false,
        }
    }

    fn vault_path() -> PathBuf {
        let proj_dirs = directories::ProjectDirs::from("com", "aegis", "messenger")
            .expect("failed to get project directories");
        let data_dir = proj_dirs.data_dir();
        std::fs::create_dir_all(data_dir).ok();
        data_dir.join("vault.aegis")
    }

    pub fn status(&self) -> crate::VaultStatus {
        crate::VaultStatus {
            is_locked: !self.is_unlocked,
            auto_lock_seconds: 300,
            records_count: if self.is_unlocked {
                self.count_records().unwrap_or(0)
            } else {
                0
            },
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.vault.is_initialized()
    }

    pub fn create(&mut self, passphrase: &str) -> Result<(), aegis_vault::VaultError> {
        self.vault.create(passphrase)?;
        self.is_unlocked = true;
        Ok(())
    }

    pub fn unlock(&mut self, passphrase: &str) -> Result<(), aegis_vault::VaultError> {
        self.vault.unlock(passphrase)?;
        self.is_unlocked = true;
        Ok(())
    }

    pub fn lock(&mut self) {
        let _ = self.vault.lock();
        self.is_unlocked = false;
    }

    pub fn list_contacts(&self) -> Result<Vec<ContactInfo>, aegis_vault::VaultError> {
        if !self.is_unlocked {
            return Err(aegis_vault::VaultError::Locked);
        }
        Ok(self
            .load_contacts()?
            .contacts
            .into_iter()
            .map(|contact| ContactInfo {
                id: contact.id,
                display_name: contact.display_name,
                safety_number: contact.safety_number,
                pq_status: pq_status(contact.pq_verified),
                added_at: chrono::DateTime::from_timestamp(contact.created_at, 0)
                    .unwrap_or_else(chrono::Utc::now)
                    .to_rfc3339(),
            })
            .collect())
    }

    pub fn get_identity_display(&self) -> Result<serde_json::Value, aegis_vault::VaultError> {
        if !self.is_unlocked {
            return Err(aegis_vault::VaultError::Locked);
        }
        let profile = self.load_profile_optional()?;
        Ok(match profile {
            Some(profile) => serde_json::json!({
                "identity_public_key": profile.identity_public.to_base64(),
                "fingerprint": fingerprint(profile.identity_public.as_bytes()),
                "queue_id": profile.queue_id,
                "device_id": profile.device_id,
                "hardware_unlock_enabled": profile.hardware_unlock_enabled,
            }),
            None => serde_json::json!({
                "identity_public_key": "not-created",
                "fingerprint": "not-created",
            }),
        })
    }

    pub fn ensure_profile(
        &self,
        display_name: &str,
        queue_id: String,
        read_token: String,
        write_token: String,
    ) -> Result<LocalProfile, aegis_vault::VaultError> {
        if !self.is_unlocked {
            return Err(aegis_vault::VaultError::Locked);
        }
        if let Some(profile) = self.load_profile_optional()? {
            return Ok(profile);
        }

        let (identity_private, identity_public) = X25519PrivateKey::generate();
        let (signing_private, signing_public) = Ed25519PrivateKey::generate();
        let (signed_prekey_private, signed_prekey_public) = X25519PrivateKey::generate();
        let signed_prekey_signature =
            sign_prekey_bundle(&signing_private, signed_prekey_public.as_bytes(), None, 1)
                .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        let pq_keys = MlKem768Provider
            .generate_keypair()
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        let profile = LocalProfile {
            display_name: display_name.to_string(),
            account_id: None,
            device_id: None,
            queue_id,
            read_token,
            write_token,
            identity_private,
            identity_public,
            signing_private,
            signing_public,
            signed_prekey_private,
            signed_prekey_public,
            signed_prekey_signature,
            pq_prekey_public: pq_keys.public_key,
            pq_prekey_private: pq_keys.private_key,
            key_version: 1,
            hardware_unlock_enabled: false,
            hardware_unlock_label: None,
        };
        self.save_json(
            aegis_vault::vault::RecordType::IdentityKey,
            PROFILE_RECORD_ID,
            &profile,
        )?;
        Ok(profile)
    }

    pub fn save_profile(&self, profile: &LocalProfile) -> Result<(), aegis_vault::VaultError> {
        self.save_json(
            aegis_vault::vault::RecordType::IdentityKey,
            PROFILE_RECORD_ID,
            profile,
        )
    }

    pub fn export_invite(&self) -> Result<ContactInvite, aegis_vault::VaultError> {
        let profile = self.require_profile()?;
        Ok(ContactInvite {
            version: 1,
            display_name: profile.display_name,
            queue_id: profile.queue_id,
            write_token: profile.write_token,
            device_id: profile.device_id,
            identity_public: profile.identity_public.to_base64(),
            signing_public: profile.signing_public.to_base64(),
            signed_prekey_public: profile.signed_prekey_public.to_base64(),
            signed_prekey_signature: profile.signed_prekey_signature.to_base64(),
            pq_prekey_public: base64_url_encode(&profile.pq_prekey_public),
            key_version: profile.key_version,
        })
    }

    pub fn import_contact(
        &self,
        invite_json: &str,
        display_name: Option<String>,
    ) -> Result<ContactInfo, aegis_vault::VaultError> {
        let profile = self.require_profile()?;
        let invite: ContactInvite = serde_json::from_str(invite_json)
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        let remote_identity_public = X25519PublicKey::from_base64(&invite.identity_public)
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        let remote_signing_public = Ed25519PublicKey::from_base64(&invite.signing_public)
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        let signed_prekey_public = X25519PublicKey::from_base64(&invite.signed_prekey_public)
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        let pq_prekey_public = base64_url_decode(&invite.pq_prekey_public)
            .map_err(|_| aegis_vault::VaultError::Record("invalid ML-KEM prekey".into()))?;
        MlKem768Provider
            .encapsulate(&pq_prekey_public)
            .map_err(|e| aegis_vault::VaultError::Record(format!("invalid ML-KEM prekey: {e}")))?;
        let shared_secret =
            derive_contact_secret(&profile.identity_private, &remote_identity_public)
                .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        let safety_number = safety_number(
            profile.identity_public.as_bytes(),
            remote_identity_public.as_bytes(),
        );
        let contact = ContactRecord {
            id: uuid::Uuid::new_v4().to_string(),
            display_name: display_name.unwrap_or(invite.display_name),
            queue_id: invite.queue_id,
            write_token: invite.write_token,
            device_id: invite.device_id,
            remote_identity_public,
            remote_signing_public,
            signed_prekey_public,
            pq_prekey_public: Some(pq_prekey_public),
            shared_secret,
            safety_number: safety_number.clone(),
            verified_at: None,
            pq_verified: true,
            created_at: chrono::Utc::now().timestamp(),
        };
        let mut contacts = self.load_contacts()?;
        contacts.contacts.push(contact.clone());
        self.save_contacts(&contacts)?;
        Ok(ContactInfo {
            id: contact.id,
            display_name: contact.display_name,
            safety_number,
            pq_status: pq_status(contact.pq_verified),
            added_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    pub fn list_messages(
        &self,
        contact_id: &str,
    ) -> Result<Vec<ChatMessage>, aegis_vault::VaultError> {
        let messages = self.load_messages()?;
        Ok(messages
            .messages
            .into_iter()
            .filter(|message| message.contact_id == contact_id)
            .map(to_chat_message)
            .collect())
    }

    pub fn encrypt_outbound_message(
        &self,
        contact_id: &str,
        plaintext: &str,
    ) -> Result<(ContactRecord, Vec<u8>, MessageRecord), aegis_vault::VaultError> {
        let profile = self.require_profile()?;
        let contact = self.require_contact(contact_id)?;
        let id = uuid::Uuid::new_v4().to_string();
        let ciphertext = aead::encrypt(
            &contact.shared_secret,
            plaintext.as_bytes(),
            contact.id.as_bytes(),
        )
        .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        let wire = WireMessage {
            id: id.clone(),
            sender_identity_public: profile.identity_public.to_base64(),
            ciphertext: base64_url_encode(&ciphertext),
        };
        let wire_bytes = encode_padded_wire(wire)?;
        let message = MessageRecord {
            id,
            contact_id: contact.id.clone(),
            direction: MessageDirection::Outbound,
            plaintext: plaintext.to_string(),
            created_at: chrono::Utc::now().timestamp(),
            envelope_id: None,
        };
        Ok((contact, wire_bytes, message))
    }

    pub fn save_message(
        &self,
        message: MessageRecord,
    ) -> Result<ChatMessage, aegis_vault::VaultError> {
        let mut messages = self.load_messages()?;
        messages.messages.push(message.clone());
        self.save_messages(&messages)?;
        Ok(to_chat_message(message))
    }

    pub fn decrypt_inbound_wire(
        &self,
        wire_bytes: &[u8],
        envelope_id: Option<String>,
    ) -> Result<Option<ChatMessage>, aegis_vault::VaultError> {
        let wire = decode_padded_wire(wire_bytes)?;
        let ciphertext = base64_url_decode(&wire.ciphertext)
            .map_err(|_| aegis_vault::VaultError::Record("invalid wire ciphertext".into()))?;
        let contacts = self.load_contacts()?;
        for contact in contacts.contacts {
            if contact.remote_identity_public.to_base64() != wire.sender_identity_public {
                continue;
            }
            let plaintext =
                match aead::decrypt(&contact.shared_secret, &ciphertext, contact.id.as_bytes()) {
                    Ok(value) => value,
                    Err(_) => continue,
                };
            let text = String::from_utf8(plaintext)
                .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
            let message = MessageRecord {
                id: wire.id,
                contact_id: contact.id,
                direction: MessageDirection::Inbound,
                plaintext: text,
                created_at: chrono::Utc::now().timestamp(),
                envelope_id,
            };
            return self.save_message(message).map(Some);
        }
        Ok(None)
    }

    pub fn queue_credentials(&self) -> Result<(String, String, String), aegis_vault::VaultError> {
        let profile = self.require_profile()?;
        Ok((profile.queue_id, profile.read_token, profile.write_token))
    }

    pub fn account_id(&self) -> Result<Option<String>, aegis_vault::VaultError> {
        Ok(self.require_profile()?.account_id)
    }

    pub fn verify_contact(&self, contact_id: &str) -> Result<ContactInfo, aegis_vault::VaultError> {
        let mut contacts = self.load_contacts()?;
        let contact = contacts
            .contacts
            .iter_mut()
            .find(|contact| contact.id == contact_id)
            .ok_or_else(|| aegis_vault::VaultError::Record("contact not found".into()))?;
        contact.verified_at = Some(chrono::Utc::now().timestamp());
        let info = ContactInfo {
            id: contact.id.clone(),
            display_name: contact.display_name.clone(),
            safety_number: contact.safety_number.clone(),
            pq_status: pq_status(contact.pq_verified),
            added_at: chrono::Utc::now().to_rfc3339(),
        };
        self.save_contacts(&contacts)?;
        Ok(info)
    }

    pub fn set_proxy(
        &self,
        mode: ProxyMode,
        proxy_url: Option<String>,
    ) -> Result<TransportSettings, aegis_vault::VaultError> {
        let settings = TransportSettings {
            proxy_mode: mode,
            proxy_url,
        };
        self.save_json(
            aegis_vault::vault::RecordType::Settings,
            SETTINGS_RECORD_ID,
            &settings,
        )?;
        Ok(settings)
    }

    pub fn load_transport_settings(&self) -> Result<TransportSettings, aegis_vault::VaultError> {
        self.load_json(aegis_vault::vault::RecordType::Settings, SETTINGS_RECORD_ID)
            .or({
                Ok::<TransportSettings, aegis_vault::VaultError>(TransportSettings {
                    proxy_mode: ProxyMode::Direct,
                    proxy_url: None,
                })
            })
    }

    pub fn enable_hardware_unlock(
        &self,
        label: String,
    ) -> Result<DeviceInfo, aegis_vault::VaultError> {
        let mut profile = self.require_profile()?;
        profile.hardware_unlock_enabled = true;
        profile.hardware_unlock_label = Some(label.clone());
        self.save_profile(&profile)?;
        Ok(DeviceInfo {
            device_id: profile.device_id.unwrap_or_else(|| "local".into()),
            display_name: label,
            revoked: false,
        })
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceInfo>, aegis_vault::VaultError> {
        let profile = self.require_profile()?;
        let mut devices = self.load_devices()?.devices;
        if !devices.iter().any(|device| {
            profile
                .device_id
                .as_ref()
                .map(|id| id == &device.device_id)
                .unwrap_or(false)
        }) {
            devices.push(DeviceState {
                device_id: profile.device_id.unwrap_or_else(|| "local".into()),
                display_name: profile.display_name,
                key_version: profile.key_version,
                revoked: false,
                linked_at: chrono::Utc::now().timestamp(),
            });
        }
        Ok(devices
            .into_iter()
            .map(|device| DeviceInfo {
                device_id: device.device_id,
                display_name: device.display_name,
                revoked: device.revoked,
            })
            .collect())
    }

    pub fn create_device_sync_bundle(
        &self,
        target_device_id: String,
        link_secret: &str,
    ) -> Result<String, aegis_vault::VaultError> {
        let profile = self.require_profile()?;
        let source_device_id = profile.device_id.unwrap_or_else(|| "local".into());
        let bundle = DeviceSyncBundle {
            version: 1,
            source_device_id: source_device_id.clone(),
            target_device_id: target_device_id.clone(),
            contacts: self.load_contacts()?.contacts,
            groups: self.load_groups()?.groups,
            mls_groups: self.load_mls_groups()?.groups,
            created_at: chrono::Utc::now().timestamp(),
        };
        let bytes = serde_json::to_vec(&bundle)
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        let link_key = derive_device_link_key(link_secret, &target_device_id);
        let encrypted = aead::encrypt(&link_key, &bytes, target_device_id.as_bytes())
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        Ok(base64_url_encode(&encrypted))
    }

    pub fn import_device_sync_bundle(
        &self,
        encrypted_payload: &str,
        link_secret: &str,
    ) -> Result<Vec<DeviceInfo>, aegis_vault::VaultError> {
        let bytes = base64_url_decode(encrypted_payload)
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        let profile = self.require_profile()?;
        let target_device_id = profile.device_id.unwrap_or_else(|| "local".into());
        let link_key = derive_device_link_key(link_secret, &target_device_id);
        let plaintext =
            aead::decrypt(&link_key, &bytes, target_device_id.as_bytes()).map_err(|_| {
                aegis_vault::VaultError::Record("invalid device-link secret or payload".into())
            })?;
        let bundle: DeviceSyncBundle = serde_json::from_slice(&plaintext)
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;

        self.save_contacts(&ContactList {
            contacts: bundle.contacts,
        })?;
        self.save_groups(&GroupList {
            groups: bundle.groups,
        })?;
        self.save_mls_groups(&MlsGroupList {
            groups: bundle.mls_groups,
        })?;

        let mut devices = self.load_devices()?;
        if !devices
            .devices
            .iter()
            .any(|device| device.device_id == bundle.source_device_id)
        {
            devices.devices.push(DeviceState {
                device_id: bundle.source_device_id,
                display_name: "Linked device".into(),
                key_version: 1,
                revoked: false,
                linked_at: chrono::Utc::now().timestamp(),
            });
        }
        self.save_devices(&devices)?;
        self.list_devices()
    }

    pub fn revoke_device(
        &self,
        device_id: String,
    ) -> Result<Vec<DeviceInfo>, aegis_vault::VaultError> {
        let mut devices = self.load_devices()?;
        for device in &mut devices.devices {
            if device.device_id == device_id {
                device.revoked = true;
            }
        }
        self.save_devices(&devices)?;
        self.list_devices()
    }

    pub fn set_traffic_profile(
        &self,
        profile: aegis_protocol::mls::TrafficProfile,
    ) -> Result<aegis_protocol::mls::TrafficProfile, aegis_vault::VaultError> {
        self.save_json(
            aegis_vault::vault::RecordType::Settings,
            TRAFFIC_PROFILE_RECORD_ID,
            &profile,
        )?;
        Ok(profile)
    }

    pub fn create_group(
        &self,
        name: String,
        member_contact_ids: Vec<String>,
    ) -> Result<GroupInfo, aegis_vault::VaultError> {
        let contacts = self.load_contacts()?;
        for member_id in &member_contact_ids {
            if !contacts
                .contacts
                .iter()
                .any(|contact| &contact.id == member_id)
            {
                return Err(aegis_vault::VaultError::Record(format!(
                    "unknown group member: {member_id}"
                )));
            }
        }
        let group = GroupRecord {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            member_contact_ids,
            created_at: chrono::Utc::now().timestamp(),
        };
        let mls_group = MlsGroupState {
            group_id: group.id.clone(),
            name: group.name.clone(),
            epoch: 0,
            member_contact_ids: group.member_contact_ids.clone(),
            backend: aegis_protocol::mls::MLS_BACKEND.into(),
            serialized_group_state: base64_url_encode(&[]),
            created_at: group.created_at,
        };
        let mut groups = self.load_groups()?;
        groups.groups.push(group.clone());
        self.save_groups(&groups)?;
        let mut mls_groups = self.load_mls_groups()?;
        mls_groups.groups.push(mls_group);
        self.save_mls_groups(&mls_groups)?;
        Ok(to_group_info(group))
    }

    pub fn list_groups(&self) -> Result<Vec<GroupInfo>, aegis_vault::VaultError> {
        Ok(self
            .load_groups()?
            .groups
            .into_iter()
            .map(to_group_info)
            .collect())
    }

    pub fn group_member_contacts(
        &self,
        group_id: &str,
    ) -> Result<Vec<ContactRecord>, aegis_vault::VaultError> {
        let group = self
            .load_groups()?
            .groups
            .into_iter()
            .find(|group| group.id == group_id)
            .ok_or_else(|| aegis_vault::VaultError::Record("group not found".into()))?;
        let contacts = self.load_contacts()?;
        Ok(group
            .member_contact_ids
            .into_iter()
            .filter_map(|member_id| {
                contacts
                    .contacts
                    .iter()
                    .find(|contact| contact.id == member_id)
                    .cloned()
            })
            .collect())
    }

    fn count_records(&self) -> Result<usize, aegis_vault::VaultError> {
        Ok(self.load_contacts()?.contacts.len() + self.load_messages()?.messages.len())
    }

    fn require_profile(&self) -> Result<LocalProfile, aegis_vault::VaultError> {
        self.load_profile_optional()?
            .ok_or_else(|| aegis_vault::VaultError::Record("profile not created".into()))
    }

    fn load_profile_optional(&self) -> Result<Option<LocalProfile>, aegis_vault::VaultError> {
        match self.load_json(
            aegis_vault::vault::RecordType::IdentityKey,
            PROFILE_RECORD_ID,
        ) {
            Ok(profile) => Ok(Some(profile)),
            Err(aegis_vault::VaultError::Record(_)) => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn require_contact(&self, contact_id: &str) -> Result<ContactRecord, aegis_vault::VaultError> {
        self.load_contacts()?
            .contacts
            .into_iter()
            .find(|contact| contact.id == contact_id)
            .ok_or_else(|| aegis_vault::VaultError::Record("contact not found".into()))
    }

    fn load_contacts(&self) -> Result<ContactList, aegis_vault::VaultError> {
        self.load_json(aegis_vault::vault::RecordType::Contact, CONTACTS_RECORD_ID)
            .or_else(|_| Ok(ContactList::default()))
    }

    fn save_contacts(&self, contacts: &ContactList) -> Result<(), aegis_vault::VaultError> {
        self.save_json(
            aegis_vault::vault::RecordType::Contact,
            CONTACTS_RECORD_ID,
            contacts,
        )
    }

    fn load_messages(&self) -> Result<MessageList, aegis_vault::VaultError> {
        self.load_json(aegis_vault::vault::RecordType::Session, MESSAGES_RECORD_ID)
            .or_else(|_| Ok(MessageList::default()))
    }

    fn save_messages(&self, messages: &MessageList) -> Result<(), aegis_vault::VaultError> {
        self.save_json(
            aegis_vault::vault::RecordType::Session,
            MESSAGES_RECORD_ID,
            messages,
        )
    }

    fn load_groups(&self) -> Result<GroupList, aegis_vault::VaultError> {
        self.load_json(aegis_vault::vault::RecordType::Group, GROUPS_RECORD_ID)
            .or_else(|_| Ok(GroupList::default()))
    }

    fn save_groups(&self, groups: &GroupList) -> Result<(), aegis_vault::VaultError> {
        self.save_json(
            aegis_vault::vault::RecordType::Group,
            GROUPS_RECORD_ID,
            groups,
        )
    }

    fn load_devices(&self) -> Result<DeviceList, aegis_vault::VaultError> {
        self.load_json(aegis_vault::vault::RecordType::Settings, DEVICES_RECORD_ID)
            .or_else(|_| Ok(DeviceList::default()))
    }

    fn save_devices(&self, devices: &DeviceList) -> Result<(), aegis_vault::VaultError> {
        self.save_json(
            aegis_vault::vault::RecordType::Settings,
            DEVICES_RECORD_ID,
            devices,
        )
    }

    fn load_mls_groups(&self) -> Result<MlsGroupList, aegis_vault::VaultError> {
        self.load_json(aegis_vault::vault::RecordType::Group, MLS_GROUPS_RECORD_ID)
            .or_else(|_| Ok(MlsGroupList::default()))
    }

    fn save_mls_groups(&self, groups: &MlsGroupList) -> Result<(), aegis_vault::VaultError> {
        self.save_json(
            aegis_vault::vault::RecordType::Group,
            MLS_GROUPS_RECORD_ID,
            groups,
        )
    }

    fn load_json<T: serde::de::DeserializeOwned>(
        &self,
        record_type: aegis_vault::vault::RecordType,
        record_id: &str,
    ) -> Result<T, aegis_vault::VaultError> {
        let record = self.vault.get(record_type, record_id)?;
        serde_json::from_slice(&record.ciphertext)
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))
    }

    fn save_json<T: serde::Serialize>(
        &self,
        record_type: aegis_vault::vault::RecordType,
        record_id: &str,
        value: &T,
    ) -> Result<(), aegis_vault::VaultError> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?;
        self.vault.put(aegis_vault::vault::VaultRecord::new(
            record_type,
            record_id,
            bytes,
        ))
    }
}

fn derive_contact_secret(
    private: &X25519PrivateKey,
    public: &X25519PublicKey,
) -> Result<SymmetricKey, aegis_crypto::CryptoError> {
    let raw = private.diffie_hellman(public)?;
    let mut hasher = Sha512::new();
    hasher.update(b"aegis-desktop-e2ee-paired-session-v1");
    hasher.update(raw.as_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    Ok(SymmetricKey(key))
}

fn derive_device_link_key(link_secret: &str, target_device_id: &str) -> SymmetricKey {
    let mut hasher = Sha512::new();
    hasher.update(b"aegis-device-link-v1");
    hasher.update(link_secret.as_bytes());
    hasher.update(target_device_id.as_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    SymmetricKey(key)
}

fn encode_padded_wire(wire: WireMessage) -> Result<Vec<u8>, aegis_vault::VaultError> {
    let payload_len = serde_json::to_vec(&wire)
        .map_err(|e| aegis_vault::VaultError::Record(e.to_string()))?
        .len();
    let target = if payload_len <= 1024 {
        1024
    } else if payload_len <= 4096 {
        4096
    } else {
        payload_len.next_power_of_two().min(65_536)
    };
    let padding_len = target.saturating_sub(payload_len).min(16_384);
    let padded = PaddedWireMessage {
        payload: wire,
        padding: base64_url_encode(&aegis_crypto::random::random_vec(padding_len)),
    };
    serde_json::to_vec(&padded).map_err(|e| aegis_vault::VaultError::Record(e.to_string()))
}

fn decode_padded_wire(wire_bytes: &[u8]) -> Result<WireMessage, aegis_vault::VaultError> {
    if let Ok(padded) = serde_json::from_slice::<PaddedWireMessage>(wire_bytes) {
        return Ok(padded.payload);
    }
    serde_json::from_slice(wire_bytes).map_err(|e| aegis_vault::VaultError::Record(e.to_string()))
}

fn to_chat_message(message: MessageRecord) -> ChatMessage {
    ChatMessage {
        id: message.id,
        contact_id: message.contact_id,
        direction: match message.direction {
            MessageDirection::Inbound => "inbound".into(),
            MessageDirection::Outbound => "outbound".into(),
        },
        text: message.plaintext,
        created_at: chrono::DateTime::from_timestamp(message.created_at, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339(),
        envelope_id: message.envelope_id,
    }
}

fn to_group_info(group: GroupRecord) -> GroupInfo {
    GroupInfo {
        id: group.id,
        name: group.name,
        member_count: group.member_contact_ids.len(),
        created_at: chrono::DateTime::from_timestamp(group.created_at, 0)
            .unwrap_or_else(chrono::Utc::now)
            .to_rfc3339(),
    }
}

fn safety_number(a: &[u8; 32], b: &[u8; 32]) -> String {
    let n = aegis_protocol::contact::compute_safety_number(a, b);
    format!(
        "{:05} {:05} {:05} {:05}",
        n % 100000,
        (n / 100000) % 100000,
        (n / 10_000_000_000) % 100000,
        (n / 1_000_000_000_000_000) % 100000
    )
}

fn pq_status(verified: bool) -> String {
    if verified {
        "ml-kem-768-verified".into()
    } else {
        "missing-or-unverified".into()
    }
}

fn fingerprint(data: &[u8; 32]) -> String {
    let digest = Sha512::digest(data);
    base64_url_encode(&digest[..12])
}

fn base64_url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(data: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(data)
}
