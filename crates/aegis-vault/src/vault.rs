//! Encrypted vault implementation

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;
use serde::{Deserialize, Serialize};
use aegis_crypto::{SymmetricKey, Argon2Params, aead::AeadCipher, kdf::{derive_argon2, hkdf_to_key}};

use crate::error::VaultError;

const VAULT_MAGIC: [u8; 4] = [0xA6, 0xE7, 0x11, 0x5];
const VAULT_FORMAT_VERSION: u16 = 1;
const DEFAULT_AUTO_LOCK_SECS: u64 = 300;
const INACTIVITY_TIMEOUT_SECS: u64 = 60;

fn vault_path() -> Result<PathBuf, VaultError> {
    let base = directories::ProjectDirs::from("com", "aegis", "messenger")
        .ok_or_else(|| VaultError::Io("cannot determine data directory".into()))?;
    let dir = base.data_dir();
    fs::create_dir_all(dir).map_err(|e| VaultError::Io(e.to_string()))?;
    Ok(dir.join("vault.db"))
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultHeader {
    magic: [u8; 4],
    version: u16,
    salt: [u8; 16],
    argon2_t: u32,
    argon2_p: u32,
    hw_key_id: Option<String>,
    created_at: i64,
}

impl VaultHeader {
    fn new(salt: [u8; 16], argon2_t: u32, argon2_p: u32, hw_key_id: Option<String>) -> Self {
        Self {
            magic: VAULT_MAGIC,
            version: VAULT_FORMAT_VERSION,
            salt,
            argon2_t,
            argon2_p,
            hw_key_id,
            created_at: chrono::Utc::now().timestamp(),
        }
    }
    fn validate(&self) -> Result<(), VaultError> {
        if self.magic != VAULT_MAGIC { return Err(VaultError::CorruptedHeader); }
        if self.version > VAULT_FORMAT_VERSION { return Err(VaultError::CorruptedHeader); }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        serde_json::to_vec(self).map_err(|e| VaultError::Io(e.to_string()))
    }
    fn from_bytes(data: &[u8]) -> Result<Self, VaultError> {
        serde_json::from_slice(data).map_err(|_| VaultError::CorruptedHeader)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRecord {
    pub record_type: RecordType,
    pub record_id: String,
    pub version: u32,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum RecordType {
    IdentityKey = 0x0001,
    DeviceKey = 0x0002,
    Session = 0x0003,
    Contact = 0x0004,
    Group = 0x0005,
    Prekey = 0x0006,
    Settings = 0x0007,
    DecoyVault = 0x00FF,
}

impl VaultRecord {
    pub fn new(record_type: RecordType, record_id: &str, ciphertext: Vec<u8>) -> Self {
        Self { record_type, record_id: record_id.to_string(), version: 1, ciphertext }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultRecords { records: Vec<VaultRecord> }

impl Default for VaultRecords {
    fn default() -> Self { Self { records: Vec::new() } }
}

struct UnlockedVault {
    master_key: [u8; 32],
    records: VaultRecords,
    last_activity: Instant,
    auto_lock_secs: u64,
}

impl Drop for UnlockedVault {
    fn drop(&mut self) {
        for b in &mut self.master_key { *b = 0; }
    }
}

impl UnlockedVault {
    fn new(master_key: [u8; 32], records: VaultRecords, auto_lock_secs: u64) -> Self {
        Self { master_key, records, last_activity: Instant::now(), auto_lock_secs }
    }
    fn key(&self) -> SymmetricKey { SymmetricKey(self.master_key) }
    fn mark_activity(&mut self) { self.last_activity = Instant::now(); }
    fn check_lock(&self) -> Result<(), VaultError> {
        let elapsed = self.last_activity.elapsed().as_secs();
        if elapsed > self.auto_lock_secs || elapsed > INACTIVITY_TIMEOUT_SECS {
            return Err(VaultError::Locked);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub argon2_params: Argon2Params,
    pub auto_lock_secs: u64,
    pub hw_key_required: bool,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self { argon2_params: Argon2Params::default(), auto_lock_secs: DEFAULT_AUTO_LOCK_SECS, hw_key_required: false }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStatus { Unlocked, Locked, NotCreated }

enum VaultState { Locked, Unlocked(UnlockedVault) }

pub struct AegisVault {
    path: PathBuf,
    state: Mutex<VaultState>,
    config: VaultConfig,
}

impl AegisVault {
    pub fn open() -> Result<Self, VaultError> { Self::open_with_config(VaultConfig::default()) }

    pub fn open_with_config(config: VaultConfig) -> Result<Self, VaultError> {
        let path = vault_path()?;
        Ok(Self { path, state: Mutex::new(VaultState::Locked), config })
    }

    pub fn exists(&self) -> bool { self.path.exists() }

    pub fn is_initialized(&self) -> bool { self.path.exists() }

    pub fn status(&self) -> VaultStatus {
        match &*self.state.lock().unwrap() {
            VaultState::Unlocked(_) => VaultStatus::Unlocked,
            VaultState::Locked => {
                if self.exists() { VaultStatus::Locked } else { VaultStatus::NotCreated }
            }
        }
    }

    pub fn create(&self, passphrase: &str) -> Result<(), VaultError> {
        if self.exists() { return Err(VaultError::AlreadyExists); }
        let salt = aegis_crypto::random::random_16bytes();
        let params = Argon2Params { m: 65536, t: 3, p: 4, dklen: 32 };
        let argon2_key = derive_argon2(passphrase.as_bytes(), &salt, params)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        let master_key = hkdf_to_key(argon2_key.as_bytes(), &salt, b"aegis-vault-master")
            .map_err(|e| VaultError::Io(e.to_string()))?;
        let mut master_key_array = [0u8; 32];
        master_key_array.copy_from_slice(master_key.as_bytes());
        let records = VaultRecords::default();
        let records_json = serde_json::to_vec(&records).map_err(|e| VaultError::Io(e.to_string()))?;
        let mut file = File::create(&self.path).map_err(|e| VaultError::Io(e.to_string()))?;
        let header = VaultHeader::new(salt, params.t, params.p, None);
        let header_bytes = header.to_bytes()?;
        file.write_all(&header_bytes).map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(b"\n").map_err(|e| VaultError::Io(e.to_string()))?;
        let cipher = AeadCipher::new(&master_key);
        let ciphertext = cipher.seal(&records_json, &header_bytes)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(&ciphertext).map_err(|e| VaultError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn unlock(&self, passphrase: &str) -> Result<(), VaultError> {
        let mut file = File::open(&self.path).map_err(|_| VaultError::NotFound)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| VaultError::Io(e.to_string()))?;
        let newline_pos = buf.iter().position(|&b| b == b'\n')
            .ok_or(VaultError::CorruptedHeader)?;
        let header_bytes = buf[..newline_pos].to_vec();
        let ciphertext = &buf[newline_pos + 1..];
        let header = VaultHeader::from_bytes(&header_bytes)?;
        header.validate()?;
        let params = Argon2Params { m: 65536, t: header.argon2_t, p: header.argon2_p, dklen: 32 };
        let argon2_key = derive_argon2(passphrase.as_bytes(), &header.salt, params)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        let master_key = hkdf_to_key(argon2_key.as_bytes(), &header.salt, b"aegis-vault-master")
            .map_err(|e| VaultError::Io(e.to_string()))?;
        let cipher = AeadCipher::new(&master_key);
        let plaintext = cipher.open(ciphertext, &header_bytes)
            .map_err(|_| VaultError::WrongPassphrase)?;
        let records: VaultRecords = serde_json::from_slice(&plaintext)
            .map_err(|_| VaultError::CorruptedHeader)?;
        let mut master_key_array = [0u8; 32];
        master_key_array.copy_from_slice(master_key.as_bytes());
        let unlocked = UnlockedVault::new(master_key_array, records, self.config.auto_lock_secs);
        *self.state.lock().unwrap() = VaultState::Unlocked(unlocked);
        Ok(())
    }

    pub fn lock(&self) -> Result<(), VaultError> {
        *self.state.lock().unwrap() = VaultState::Locked;
        Ok(())
    }

    pub fn put(&self, record: VaultRecord) -> Result<(), VaultError> {
        let mut state = self.state.lock().unwrap();
        let unlocked = match &mut *state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked),
        };
        unlocked.mark_activity();
        unlocked.check_lock()?;
        if let Some(existing) = unlocked.records.records.iter_mut()
            .find(|r| r.record_type == record.record_type && r.record_id == record.record_id)
        {
            *existing = record;
        } else {
            unlocked.records.records.push(record);
        }
        self.save_records()
    }

    pub fn get(&self, record_type: RecordType, record_id: &str) -> Result<VaultRecord, VaultError> {
        let mut state = self.state.lock().unwrap();
        let unlocked = match &mut *state {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked),
        };
        unlocked.mark_activity();
        unlocked.check_lock()?;
        unlocked.records.records.iter()
            .find(|r| r.record_type == record_type && r.record_id == record_id)
            .cloned()
            .ok_or_else(|| VaultError::Record(format!("not found")))
    }

    fn save_records(&self) -> Result<(), VaultError> {
        let state_guard = self.state.lock().unwrap();
        let unlocked = match &*state_guard {
            VaultState::Unlocked(u) => u,
            VaultState::Locked => return Err(VaultError::Locked),
        };
        let records_json = serde_json::to_vec(&unlocked.records)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        let mut file = std::fs::OpenOptions::new().write(true).truncate(true).open(&self.path)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        let mut header_buf = Vec::new();
        file.read_to_end(&mut header_buf).map_err(|e| VaultError::Io(e.to_string()))?;
        drop(file);
        let newline_pos = header_buf.iter().position(|&b| b == b'\n')
            .ok_or(VaultError::CorruptedHeader)?;
        let header_bytes = header_buf[..newline_pos].to_vec();
        let cipher = AeadCipher::new(&unlocked.key());
        let ciphertext = cipher.seal(&records_json, &header_bytes)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        let mut file = std::fs::OpenOptions::new().write(true).truncate(true).open(&self.path)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(&header_bytes).map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(b"\n").map_err(|e| VaultError::Io(e.to_string()))?;
        file.write_all(&ciphertext).map_err(|e| VaultError::Io(e.to_string()))?;
        Ok(())
    }
}
