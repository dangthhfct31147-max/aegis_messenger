//! Aegis Messenger — Local Encrypted Vault

pub mod vault;
pub mod error;

pub use vault::{AegisVault, VaultConfig, VaultStatus};
pub use error::VaultError;
