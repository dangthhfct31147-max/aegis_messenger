//! Error types for aegis-protocol

use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum ProtocolError {
    #[error("serialization: {0}")]
    Serialization(String),

    #[error("session: {0}")]
    Session(String),

    #[error("handshake: {0}")]
    Handshake(String),

    #[error("envelope: {0}")]
    Envelope(String),

    #[error("contact: {0}")]
    Contact(String),

    #[error("ratchet: key not found for message {0}")]
    RatchetKeyNotFound(u64),

    #[error("ratchet: message number too far ahead")]
    RatchetLookaheadExceeded,

    #[error("envelope: invalid protocol version {0}")]
    InvalidProtocolVersion(u16),

    #[error("envelope: unknown cipher suite {0}")]
    UnknownCipherSuite(u16),

    #[error("handshake: missing prekey bundle")]
    MissingPrekeyBundle,

    #[error("handshake: signature verification failed")]
    SignatureVerificationFailed,

    #[error("handshake: session already exists")]
    SessionAlreadyExists,

    #[error("session: message key already used")]
    MessageKeyReused,
}

impl From<aegis_crypto::CryptoError> for ProtocolError {
    fn from(e: aegis_crypto::CryptoError) -> Self {
        ProtocolError::Session(e.to_string())
    }
}
