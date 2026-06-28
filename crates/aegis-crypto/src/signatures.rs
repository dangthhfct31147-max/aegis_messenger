//! Digital Signature operations

use crate::{CryptoError, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};

/// Sign a message with an Ed25519 private key
pub fn sign(message: &[u8], private_key: &Ed25519PrivateKey) -> Result<Ed25519Signature, CryptoError> {
    private_key.sign(message)
}

/// Verify a signature with an Ed25519 public key
pub fn verify(
    message: &[u8],
    signature: &Ed25519Signature,
    public_key: &Ed25519PublicKey,
) -> Result<(), CryptoError> {
    use ed25519_dalek::VerifyingKey;
    use ed25519_dalek::Signature as DalekSignature;
    let vk = VerifyingKey::from_bytes(&public_key.0)
        .map_err(|_| CryptoError::Ed25519InvalidPublicKey)?;
    let dalek_sig = DalekSignature::from_bytes(&signature.0);
    vk.verify_strict(message, &dalek_sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

/// Sign a prekey bundle with the identity key
pub fn sign_prekey_bundle(
    identity_private: &Ed25519PrivateKey,
    signed_prekey: &[u8],
    one_time_prekey: Option<&[u8]>,
    key_version: u32,
) -> Result<Ed25519Signature, CryptoError> {
    use sha2::{Sha512, Digest};

    let mut data = Vec::with_capacity(32 + 32 + 4);
    data.extend_from_slice(signed_prekey);
    if let Some(otpk) = one_time_prekey {
        data.extend_from_slice(otpk);
    }
    data.extend_from_slice(&key_version.to_be_bytes());

    let mut hasher = Sha512::new();
    hasher.update(&data);
    let to_sign = hasher.finalize();

    identity_private.sign(&to_sign)
}

/// Verify a prekey bundle signature
pub fn verify_prekey_bundle_signature(
    signed_prekey: &[u8],
    one_time_prekey: Option<&[u8]>,
    key_version: u32,
    signature: &Ed25519Signature,
    identity_public: &Ed25519PublicKey,
) -> Result<(), CryptoError> {
    use sha2::{Sha512, Digest};

    let mut data = Vec::with_capacity(32 + 32 + 4);
    data.extend_from_slice(signed_prekey);
    if let Some(otpk) = one_time_prekey {
        data.extend_from_slice(otpk);
    }
    data.extend_from_slice(&key_version.to_be_bytes());

    let mut hasher = Sha512::new();
    hasher.update(&data);
    let to_verify = hasher.finalize();

    verify(&to_verify, signature, identity_public)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let (private, public) = Ed25519PrivateKey::generate();
        let message = b"Aegis Messenger: Verify this message";
        let signature = sign(message, &private).unwrap();
        verify(message, &signature, &public).unwrap();
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (alice_private, _) = Ed25519PrivateKey::generate();
        let (_, bob_public) = Ed25519PrivateKey::generate();
        let signature = sign(b"Test", &alice_private).unwrap();
        let result = verify(b"Test", &signature, &bob_public);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let (private, public) = Ed25519PrivateKey::generate();
        let signature = sign(b"Original", &private).unwrap();
        let result = verify(b"Tampered", &signature, &public);
        assert!(result.is_err());
    }
}
