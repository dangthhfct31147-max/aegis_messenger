//! Key Derivation Functions

use hkdf::Hkdf;
use sha2::Sha512;

use crate::{Argon2Key, Argon2Params, CryptoError, SymmetricKey};

/// Derive a key from a passphrase using Argon2id.
pub fn derive_argon2(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<Argon2Key, CryptoError> {
    use argon2::{Argon2, Params as Argon2LibParams};

    let argon2_params = Argon2LibParams::new(params.m, params.t, params.p, Some(params.dklen))
        .map_err(|e| CryptoError::Argon2Failed(e.to_string()))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2_params,
    );

    let mut output = vec![0u8; params.dklen];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CryptoError::Argon2Failed(e.to_string()))?;

    Ok(Argon2Key(output))
}

/// HKDF-SHA512 → derive a SymmetricKey (32 bytes)
pub fn hkdf_to_key(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<SymmetricKey, CryptoError> {
    let mut key_bytes = [0u8; 32];
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    hk.expand(info, &mut key_bytes)
        .map_err(|_| CryptoError::KdfInvalidOutputLength { len: 32 })?;
    Ok(SymmetricKey(key_bytes))
}

/// HKDF with two outputs (root_key, chain_key)
pub fn hkdf_cat(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
) -> Result<(SymmetricKey, SymmetricKey), CryptoError> {
    let hk = Hkdf::<Sha512>::new(Some(salt), ikm);
    let mut okm = [0u8; 64];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KdfInvalidOutputLength { len: 64 })?;

    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    k1.copy_from_slice(&okm[..32]);
    k2.copy_from_slice(&okm[32..]);

    Ok((SymmetricKey(k1), SymmetricKey(k2)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_roundtrip() {
        let ikm = crate::random::random_32bytes();
        let key = hkdf_to_key(&ikm, b"salt", b"info").unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn test_hkdf_cat() {
        let ikm = crate::random::random_32bytes();
        let (k1, k2) = hkdf_cat(&ikm, b"salt", b"info").unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
        assert_eq!(k1.as_bytes().len(), 32);
        assert_eq!(k2.as_bytes().len(), 32);
    }
}
