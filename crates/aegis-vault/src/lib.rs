//! Aegis Messenger — Local Encrypted Vault

pub mod error;
pub mod vault;

pub use error::VaultError;
pub use vault::{AegisVault, VaultConfig, VaultStatus};
