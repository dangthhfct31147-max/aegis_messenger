//! Key Encapsulation Mechanisms

use crate::{CryptoError, SymmetricKey, X25519PrivateKey, X25519PublicKey};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Encoded, EncodedSizeUser, KemCore, MlKem768,
};
use sha2::{Digest, Sha512};

pub const ML_KEM_768_ALGORITHM_ID: u16 = 0x0101;

#[derive(Debug)]
pub struct HybridKeyOutput {
    pub shared_secret: SymmetricKey,
    pub classical_ephemeral_public: X25519PublicKey,
    pub pq_ciphertext: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqKemKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqKemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: SymmetricKey,
}

pub trait KemProvider {
    fn algorithm_id(&self) -> u16;
    fn generate_keypair(&self) -> Result<PqKemKeyPair, CryptoError>;
    fn encapsulate(&self, public_key: &[u8]) -> Result<PqKemEncapsulation, CryptoError>;
    fn decapsulate(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<SymmetricKey, CryptoError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MlKem768Provider;

type MlKem768PublicKey = <MlKem768 as KemCore>::EncapsulationKey;
type MlKem768PrivateKey = <MlKem768 as KemCore>::DecapsulationKey;
type MlKem768Ciphertext = ml_kem::Ciphertext<MlKem768>;

fn decode_mlkem_public_key(public_key: &[u8]) -> Result<MlKem768PublicKey, CryptoError> {
    let encoded: Encoded<MlKem768PublicKey> = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKemPublicKey)?;
    Ok(MlKem768PublicKey::from_bytes(&encoded))
}

fn decode_mlkem_private_key(private_key: &[u8]) -> Result<MlKem768PrivateKey, CryptoError> {
    let encoded: Encoded<MlKem768PrivateKey> = private_key
        .try_into()
        .map_err(|_| CryptoError::InvalidKemPrivateKey)?;
    Ok(MlKem768PrivateKey::from_bytes(&encoded))
}

fn decode_mlkem_ciphertext(ciphertext: &[u8]) -> Result<MlKem768Ciphertext, CryptoError> {
    ciphertext
        .try_into()
        .map_err(|_| CryptoError::InvalidKemCiphertext)
}

impl KemProvider for MlKem768Provider {
    fn algorithm_id(&self) -> u16 {
        ML_KEM_768_ALGORITHM_ID
    }

    fn generate_keypair(&self) -> Result<PqKemKeyPair, CryptoError> {
        let mut rng = crate::random::system_rng();
        let (private, public) = MlKem768::generate(&mut rng);
        Ok(PqKemKeyPair {
            public_key: public.as_bytes().to_vec(),
            private_key: private.as_bytes().to_vec(),
        })
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<PqKemEncapsulation, CryptoError> {
        let public = decode_mlkem_public_key(public_key)?;
        let mut rng = crate::random::system_rng();
        let (ciphertext, shared) = public
            .encapsulate(&mut rng)
            .map_err(|_| CryptoError::KemOperationFailed)?;
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(shared.as_slice());
        Ok(PqKemEncapsulation {
            ciphertext: ciphertext.to_vec(),
            shared_secret: SymmetricKey(shared_secret),
        })
    }

    fn decapsulate(
        &self,
        private_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<SymmetricKey, CryptoError> {
        let private = decode_mlkem_private_key(private_key)?;
        let ciphertext = decode_mlkem_ciphertext(ciphertext)?;
        let shared = private
            .decapsulate(&ciphertext)
            .map_err(|_| CryptoError::KemOperationFailed)?;
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(shared.as_slice());
        Ok(SymmetricKey(shared_secret))
    }
}

pub fn encapsulate_mlkem(_pq_public_key: &[u8]) -> Result<(Vec<u8>, SymmetricKey), CryptoError> {
    let output = MlKem768Provider.encapsulate(_pq_public_key)?;
    Ok((output.ciphertext, output.shared_secret))
}

pub fn pqxdh_handshake(
    our_ephemeral_private: &X25519PrivateKey,
    our_identity_private: &X25519PrivateKey,
    their_identity_public: &X25519PublicKey,
    their_signed_prekey: &X25519PublicKey,
    their_one_time_prekey: Option<&X25519PublicKey>,
    their_pq_public_key: Option<&[u8]>,
) -> Result<HybridKeyOutput, CryptoError> {
    use x25519_dalek::{PublicKey, StaticSecret};

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
    let dh4 = their_one_time_prekey.map(|one_time_prekey| {
        let s = StaticSecret::from(our_ephemeral_private.0);
        let p = PublicKey::from(one_time_prekey.0);
        s.diffie_hellman(&p)
    });

    let mut classical_secret = Vec::with_capacity(if dh4.is_some() { 128 } else { 96 });
    classical_secret.extend_from_slice(dh1.as_bytes());
    classical_secret.extend_from_slice(dh2.as_bytes());
    classical_secret.extend_from_slice(dh3.as_bytes());
    if let Some(dh4) = dh4.as_ref() {
        classical_secret.extend_from_slice(dh4.as_bytes());
    }

    let mut hasher = Sha512::new();
    hasher.update(&classical_secret);
    let hash_out = hasher.finalize();

    let mut final_shared = [0u8; 32];
    final_shared.copy_from_slice(&hash_out[..32]);

    let ephemeral_secret = StaticSecret::from(our_ephemeral_private.0);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret);
    let mut ephemeral_public = [0u8; 32];
    ephemeral_public.copy_from_slice(ephemeral_public_key.as_bytes());

    if let Some(pq_pk) = their_pq_public_key {
        let (pq_ct, pq_ss) = encapsulate_mlkem(pq_pk)?;
        let mut h = Sha512::new();
        h.update(hash_out);
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
pub fn x25519_dh(our_private: &X25519PrivateKey, their_public: &X25519PublicKey) -> [u8; 32] {
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

    #[test]
    fn test_pqxdh_returns_the_supplied_ephemeral_public_key() {
        let (our_identity_private, _) = X25519PrivateKey::generate();
        let (our_ephemeral_private, our_ephemeral_public) = X25519PrivateKey::generate();
        let (_, their_identity_public) = X25519PrivateKey::generate();
        let (_, their_signed_prekey) = X25519PrivateKey::generate();

        let output = pqxdh_handshake(
            &our_ephemeral_private,
            &our_identity_private,
            &their_identity_public,
            &their_signed_prekey,
            None,
            None,
        )
        .unwrap();

        assert_eq!(output.classical_ephemeral_public, our_ephemeral_public);
    }

    #[test]
    fn test_mlkem768_provider_round_trip() {
        let provider = MlKem768Provider;
        let keys = provider.generate_keypair().unwrap();
        let sent = provider.encapsulate(&keys.public_key).unwrap();
        let received = provider
            .decapsulate(&keys.private_key, &sent.ciphertext)
            .unwrap();

        assert_eq!(sent.shared_secret.as_bytes(), received.as_bytes());
        assert_eq!(provider.algorithm_id(), ML_KEM_768_ALGORITHM_ID);
    }

    #[test]
    fn test_mlkem768_provider_rejects_bad_public_key() {
        let provider = MlKem768Provider;
        let err = provider.encapsulate(b"not-a-valid-key").unwrap_err();
        assert_eq!(err, CryptoError::InvalidKemPublicKey);
    }
}
