//! AEAD operations using XChaCha20Poly1305

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::XChaCha20Poly1305;

use crate::{CryptoError, SymmetricKey};

/// XChaCha20-Poly1305 AEAD
pub struct AeadCipher {
    cipher: XChaCha20Poly1305,
}

impl AeadCipher {
    pub fn new(key: &SymmetricKey) -> Self {
        let key_array = GenericArray::from_slice(key.as_bytes());
        let cipher = XChaCha20Poly1305::new(key_array);
        Self { cipher }
    }

    /// Encrypt plaintext with AAD. Returns nonce (24 bytes) || ciphertext.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce_bytes: [u8; 24] = crate::random::random_vec(24)
            .try_into()
            .expect("random_vec always returns correct length");
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = self.cipher
            .encrypt(nonce, chacha20poly1305::aead::Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::AeadEncryptFailed)?;

        let mut result = Vec::with_capacity(24 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt ciphertext with AAD. Input: nonce (24 bytes) || ciphertext.
    pub fn open(&self, ciphertext_with_nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_with_nonce.len() < 24 {
            return Err(CryptoError::AeadDecryptFailed);
        }
        let nonce = GenericArray::from_slice(&ciphertext_with_nonce[..24]);
        let ciphertext = &ciphertext_with_nonce[24..];

        self.cipher
            .decrypt(nonce, chacha20poly1305::aead::Payload { msg: ciphertext, aad })
            .map_err(|_| CryptoError::AeadDecryptFailed)
    }
}

pub fn encrypt(key: &SymmetricKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    AeadCipher::new(key).seal(plaintext, aad)
}

pub fn decrypt(key: &SymmetricKey, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
    AeadCipher::new(key).open(ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_round_trip() {
        let key = SymmetricKey::generate();
        let plaintext = b"Hello, Aegis Messenger!";
        let aad = b"test-envelope";

        let ciphertext = AeadCipher::new(&key).seal(plaintext, aad).unwrap();
        let decrypted = AeadCipher::new(&key).open(&ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aead_wrong_aad_fails() {
        let key = SymmetricKey::generate();
        let ciphertext = AeadCipher::new(&key).seal(b"Secret", b"correct-aad").unwrap();
        assert!(AeadCipher::new(&key).open(&ciphertext, b"wrong-aad").is_err());
    }

    #[test]
    fn test_aead_wrong_key_fails() {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();
        let ciphertext = AeadCipher::new(&key1).seal(b"Secret", b"aad").unwrap();
        assert!(AeadCipher::new(&key2).open(&ciphertext, b"aad").is_err());
    }

    #[test]
    fn test_aead_tampered_fails() {
        let key = SymmetricKey::generate();
        let mut ciphertext = AeadCipher::new(&key).seal(b"Secret", b"aad").unwrap();
        ciphertext[30] ^= 0x42;
        assert!(AeadCipher::new(&key).open(&ciphertext, b"aad").is_err());
    }
}
