//! Error types for aegis-crypto

use thiserror::Error;

/// All errors produced by aegis-crypto operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("AEAD: encryption failed")]
    AeadEncryptFailed,

    #[error("AEAD: decryption failed — authentication error")]
    AeadDecryptFailed,

    #[error("AEAD: key length mismatch (expected {expected}, got {actual})")]
    AeadKeyLength { expected: usize, actual: usize },

    #[error("AEAD: nonce length mismatch (expected {expected}, got {actual})")]
    AeadNonceLength { expected: usize, actual: usize },

    #[error("KDF: invalid output length ({len})")]
    KdfInvalidOutputLength { len: usize },

    #[error("KDF: invalid salt length")]
    KdfInvalidSalt,

    #[error("Argon2: key derivation failed ({0})")]
    Argon2Failed(String),

    #[error("X25519: invalid public key (not on curve)")]
    X25519InvalidPublicKey,

    #[error("X25519: shared secret derivation failed")]
    X25519SharedSecretFailed,

    #[error("Ed25519: invalid signature")]
    Ed25519InvalidSignature,

    #[error("Ed25519: invalid public key")]
    Ed25519InvalidPublicKey,

    #[error("signature: verification failed")]
    SignatureVerificationFailed,

    #[error("signature: signing failed")]
    SigningFailed,

    #[error("random: not enough entropy")]
    InsufficientEntropy,

    #[error("base64: decoding failed")]
    Base64DecodeFailed,

    #[error("serialization: encoding failed")]
    EncodingFailed,

    #[error("serialization: decoding failed")]
    DecodingFailed,

    #[error("key agreement: quantum component unavailable")]
    QuantumKEMUnavailable,

    #[error("key agreement: invalid KEM public key")]
    InvalidKemPublicKey,

    #[error("key agreement: invalid KEM private key")]
    InvalidKemPrivateKey,

    #[error("key agreement: invalid KEM ciphertext")]
    InvalidKemCiphertext,

    #[error("key agreement: KEM operation failed")]
    KemOperationFailed,

    #[error("key agreement: hybrid key mismatch")]
    HybridKeyMismatch,

    #[error("unknown cipher suite: {0}")]
    UnknownCipherSuite(u16),

    #[error("protocol version mismatch: {0}")]
    ProtocolVersionMismatch(u16),
}
