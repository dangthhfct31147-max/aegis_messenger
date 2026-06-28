//! Bridge between the Aegis Vault and the Tauri desktop application.

use std::path::PathBuf;

use crate::ContactInfo;

pub struct AppVault {
    vault: aegis_vault::AegisVault,
    is_unlocked: bool,
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
            records_count: 0,
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
        Ok(Vec::new())
    }

    pub fn get_identity_display(&self) -> Result<serde_json::Value, aegis_vault::VaultError> {
        if !self.is_unlocked {
            return Err(aegis_vault::VaultError::Locked);
        }
        Ok(serde_json::json!({
            "identity_public_key": "pending",
            "fingerprint": "pending",
        }))
    }
}
