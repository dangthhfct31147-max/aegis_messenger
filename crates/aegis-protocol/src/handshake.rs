//! PQXDH-inspired initial handshake

use aegis_crypto::{
    kem::pqxdh_handshake,
    signatures::{sign_prekey_bundle, verify_prekey_bundle_signature},
    CipherSuite, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, X25519PrivateKey,
    X25519PublicKey,
};
use base64::Engine;

use crate::error::ProtocolError;

pub struct HandshakeResult {
    pub session_ephemeral_private: X25519PrivateKey,
    pub session_ephemeral_public: X25519PublicKey,
    pub handshake_ciphertext: Vec<u8>,
    pub shared_secret: [u8; 32],
}

pub fn initiate_pqxdh(
    our_identity_private: &X25519PrivateKey,
    their_prekey_bundle: &PrekeyBundlePayload,
    use_one_time_prekey: bool,
) -> Result<HandshakeResult, ProtocolError> {
    let (session_ephemeral_private, _session_ephemeral_public) = X25519PrivateKey::generate();

    let one_time_prekey = if use_one_time_prekey {
        their_prekey_bundle.one_time_prekey.as_ref()
    } else {
        None
    };

    verify_prekey_bundle_signature(
        their_prekey_bundle.signed_prekey.as_bytes(),
        one_time_prekey.map(|k| k.as_bytes() as &[u8]),
        their_prekey_bundle.key_version,
        &their_prekey_bundle.signed_prekey_signature,
        &their_prekey_bundle.identity_signing_key,
    )
    .map_err(|_| ProtocolError::SignatureVerificationFailed)?;

    let pq_output = pqxdh_handshake(
        &session_ephemeral_private,
        our_identity_private,
        &their_prekey_bundle.identity_key,
        &their_prekey_bundle.signed_prekey,
        one_time_prekey,
        their_prekey_bundle.pq_prekey_public.as_deref(),
    )
    .map_err(|e| ProtocolError::Handshake(e.to_string()))?;

    Ok(HandshakeResult {
        session_ephemeral_private,
        session_ephemeral_public: pq_output.classical_ephemeral_public,
        handshake_ciphertext: pq_output.pq_ciphertext.unwrap_or_default(),
        shared_secret: *pq_output.shared_secret.as_bytes(),
    })
}

#[derive(Debug, Clone)]
pub struct PrekeyBundlePayload {
    pub identity_signing_key: Ed25519PublicKey,
    pub identity_key: X25519PublicKey,
    pub signed_prekey: X25519PublicKey,
    pub signed_prekey_signature: Ed25519Signature,
    pub one_time_prekey: Option<X25519PublicKey>,
    pub pq_prekey_public: Option<Vec<u8>>,
    pub cipher_suite: CipherSuite,
    pub key_version: u32,
}

impl PrekeyBundlePayload {
    pub fn from_json(json: &str) -> Result<Self, ProtocolError> {
        #[derive(serde::Deserialize)]
        struct Raw {
            identity_signing_key: String,
            identity_key: String,
            signed_prekey: String,
            signed_prekey_signature: String,
            one_time_prekey: Option<String>,
            pq_prekey_public: Option<String>,
            cipher_suite: u16,
            key_version: u32,
        }

        let raw: Raw =
            serde_json::from_str(json).map_err(|e| ProtocolError::Handshake(e.to_string()))?;

        let identity_signing_key = Ed25519PublicKey::from_base64(&raw.identity_signing_key)
            .map_err(|e| ProtocolError::Handshake(format!("identity_signing_key: {}", e)))?;
        let identity_key = X25519PublicKey::from_base64(&raw.identity_key)
            .map_err(|e| ProtocolError::Handshake(format!("identity_key: {}", e)))?;
        let signed_prekey = X25519PublicKey::from_base64(&raw.signed_prekey)
            .map_err(|e| ProtocolError::Handshake(format!("signed_prekey: {}", e)))?;
        let signed_prekey_signature =
            Ed25519Signature::from_base64(&raw.signed_prekey_signature)
                .map_err(|e| ProtocolError::Handshake(format!("signature: {}", e)))?;
        let one_time_prekey = if let Some(ref otpk) = raw.one_time_prekey {
            Some(
                X25519PublicKey::from_base64(otpk)
                    .map_err(|e| ProtocolError::Handshake(format!("otpk: {}", e)))?,
            )
        } else {
            None
        };
        let pq_prekey_public = if let Some(ref pq) = raw.pq_prekey_public {
            Some(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(pq)
                    .map_err(|_| {
                        ProtocolError::Handshake("pq_prekey_public: invalid base64".into())
                    })?,
            )
        } else {
            None
        };

        let cipher_suite = match raw.cipher_suite {
            0x0001 => CipherSuite::Aegis1,
            v => {
                return Err(ProtocolError::Handshake(format!(
                    "unknown cipher suite: {}",
                    v
                )))
            }
        };

        Ok(Self {
            identity_signing_key,
            identity_key,
            signed_prekey,
            signed_prekey_signature,
            one_time_prekey,
            pq_prekey_public,
            cipher_suite,
            key_version: raw.key_version,
        })
    }
}

pub fn generate_prekey_bundle(
    _identity_private: &Ed25519PrivateKey,
    _identity_public: &Ed25519PublicKey,
    _identity_x25519_private: &X25519PrivateKey,
    _cipher_suite: CipherSuite,
) -> Result<(SignedPrekeyPair, Vec<PrekeyPair>), ProtocolError> {
    let (sp_private, sp_public) = X25519PrivateKey::generate();
    let signature = sign_prekey_bundle(_identity_private, sp_public.as_bytes(), None, 1)
        .map_err(|e| ProtocolError::Handshake(e.to_string()))?;

    let signed_prekey = SignedPrekeyPair {
        public: *sp_public.as_bytes(),
        signature,
        version: 1,
    };

    let mut otpk_pairs = Vec::new();
    for i in 0..100 {
        let (_, pk_public) = X25519PrivateKey::generate();
        otpk_pairs.push(PrekeyPair {
            id: i,
            public: *pk_public.as_bytes(),
        });
    }

    let _ = sp_private;
    Ok((signed_prekey, otpk_pairs))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedPrekeyPair {
    pub public: [u8; 32],
    pub signature: Ed25519Signature,
    pub version: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrekeyPair {
    pub id: u32,
    pub public: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_prekey_bundle_signs_signed_prekey() {
        let (identity_private, identity_public) = Ed25519PrivateKey::generate();
        let (identity_x25519_private, _) = X25519PrivateKey::generate();

        let (signed_prekey, _) = generate_prekey_bundle(
            &identity_private,
            &identity_public,
            &identity_x25519_private,
            CipherSuite::Aegis1,
        )
        .unwrap();

        verify_prekey_bundle_signature(
            &signed_prekey.public,
            None,
            signed_prekey.version,
            &signed_prekey.signature,
            &identity_public,
        )
        .unwrap();
        assert_ne!(signed_prekey.signature.0, [0u8; 64]);
    }

    #[test]
    fn test_initiate_pqxdh_rejects_invalid_prekey_signature() {
        let (our_identity_private, _) = X25519PrivateKey::generate();
        let (_, identity_signing_key) = Ed25519PrivateKey::generate();
        let (_, their_identity_key) = X25519PrivateKey::generate();
        let (_, their_signed_prekey) = X25519PrivateKey::generate();

        let bundle = PrekeyBundlePayload {
            identity_signing_key,
            identity_key: their_identity_key,
            signed_prekey: their_signed_prekey,
            signed_prekey_signature: Ed25519Signature([0u8; 64]),
            one_time_prekey: None,
            pq_prekey_public: None,
            cipher_suite: CipherSuite::Aegis1,
            key_version: 1,
        };

        let result = initiate_pqxdh(&our_identity_private, &bundle, false);
        assert!(matches!(
            result,
            Err(ProtocolError::SignatureVerificationFailed)
        ));
    }
}
