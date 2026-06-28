//! Key Encapsulation Mechanisms

use crate::{CryptoError, SymmetricKey, X25519PublicKey, X25519PrivateKey};
use sha2::{Sha512, Digest};

#[derive(Debug)]
pub struct HybridKeyOutput {
    pub shared_secret: SymmetricKey,
    pub classical_ephemeral_public: X25519PublicKey,
    pub pq_ciphertext: Option<Vec<u8>>,
}

pub fn encapsulate_mlkem(_pq_public_key: &[u8]) -> Result<(Vec<u8>, SymmetricKey), CryptoError> {
    Err(CryptoError::QuantumKEMUnavailable)
}

pub fn pqxdh_handshake(
    our_ephemeral_private: &X25519PrivateKey,
    our_identity_private: &X25519PrivateKey,
    their_identity_public: &X25519PublicKey,
    their_signed_prekey: &X25519PublicKey,
    their_pq_public_key: Option<&[u8]>,
) -> Result<HybridKeyOutput, CryptoError> {
    use x25519_dalek::{StaticSecret, PublicKey};

    let dh1 = {
        let s = StaticSecret::from(our_identity_private.0);
        let p = PublicKey::from(their_identity_public.0);
        s.diffie_hellman(&p)
    };
    let dh2 = {
        let s = StaticSecret::from(our_ephemeral_private.0);
        let p = PublicKey::from(their_signed_prekey.0);
        s.diffie_hellman(&p)
    };
    let dh3 = {
        let s = StaticSecret::from(our_identity_private.0);
        let p = PublicKey::from(their_signed_prekey.0);
        s.diffie_hellman(&p)
    };

    let mut classical_secret = [0u8; 96];
    classical_secret[..32].copy_from_slice(dh1.as_bytes());
    classical_secret[32..64].copy_from_slice(dh2.as_bytes());
    classical_secret[64..].copy_from_slice(dh3.as_bytes());

    let mut hasher = Sha512::new();
    hasher.update(&classical_secret);
    let hash_out = hasher.finalize();

    let mut final_shared = [0u8; 32];
    final_shared.copy_from_slice(&hash_out[..32]);

    // Compute ephemeral public key
    let (eph_sk, _eph_pk) = X25519PrivateKey::generate();
    let ephemeral_public = eph_sk.0;

    if let Some(pq_pk) = their_pq_public_key {
        let (pq_ct, pq_ss) = encapsulate_mlkem(pq_pk)?;
        let mut h = Sha512::new();
        h.update(&hash_out);
        h.update(pq_ss.as_bytes());
        let combined: [u8; 64] = h.finalize().into();
        final_shared.copy_from_slice(&combined[..32]);

        return Ok(HybridKeyOutput {
            shared_secret: SymmetricKey(final_shared),
            classical_ephemeral_public: X25519PublicKey(ephemeral_public),
            pq_ciphertext: Some(pq_ct),
        });
    }

    Ok(HybridKeyOutput {
        shared_secret: SymmetricKey(final_shared),
        classical_ephemeral_public: X25519PublicKey(ephemeral_public),
        pq_ciphertext: None,
    })
}

pub fn x25519_shared_secret(
    our_private: &X25519PrivateKey,
    their_public: &X25519PublicKey,
) -> Result<SymmetricKey, CryptoError> {
    our_private.diffie_hellman(their_public)
}

/// Perform X25519 DH and return raw shared bytes
pub fn x25519_dh(
    our_private: &X25519PrivateKey,
    their_public: &X25519PublicKey,
) -> [u8; 32] {
    let shared = x25519_shared_secret(our_private, their_public).unwrap();
    *shared.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_dh() {
        let (alice_private, alice_public) = X25519PrivateKey::generate();
        let (bob_private, bob_public) = X25519PrivateKey::generate();

        let shared_alice = x25519_shared_secret(&alice_private, &bob_public).unwrap();
        let shared_bob = x25519_shared_secret(&bob_private, &alice_public).unwrap();

        assert_eq!(shared_alice.as_bytes(), shared_bob.as_bytes());
    }
}
