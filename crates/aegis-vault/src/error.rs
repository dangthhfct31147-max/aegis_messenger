//! Error types for aegis-vault

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum VaultError {
    #[error("vault: not found — not yet created")]
    NotFound,

    #[error("vault: already exists")]
    AlreadyExists,

    #[error("vault: corrupted header")]
    CorruptedHeader,

    #[error("vault: unlock failed")]
    UnlockFailed,

    #[error("vault: wrong passphrase")]
    WrongPassphrase,

    #[error("vault: locked")]
    Locked,

    #[error("vault: hardware key required")]
    HardwareKeyRequired,

    #[error("vault: hardware key not enrolled")]
    HardwareKeyNotEnrolled,

    #[error("vault: I/O error: {0}")]
    Io(String),

    #[error("vault: record error: {0}")]
    Record(String),
}
