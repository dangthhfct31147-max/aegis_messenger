//! PQXDH-inspired initial handshake

use aegis_crypto::{
    X25519PrivateKey, X25519PublicKey, Ed25519PrivateKey, Ed25519PublicKey,
    Ed25519Signature, CipherSuite,
    kem::pqxdh_handshake,
};

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
    let _use_otpk = use_one_time_prekey;

    let otpk = their_prekey_bundle.one_time_prekey.as_ref()
        .map(|k| k.as_bytes() as &[u8]);

    let pq_output = pqxdh_handshake(
        &session_ephemeral_private,
        our_identity_private,
        &their_prekey_bundle.identity_key,
        &their_prekey_bundle.signed_prekey,
        otpk,
    ).map_err(|e| ProtocolError::Handshake(e.to_string()))?;

    Ok(HandshakeResult {
        session_ephemeral_private,
        session_ephemeral_public: pq_output.classical_ephemeral_public,
        handshake_ciphertext: pq_output.pq_ciphertext.unwrap_or_default(),
        shared_secret: *pq_output.shared_secret.as_bytes(),
    })
}

#[derive(Debug, Clone)]
pub struct PrekeyBundlePayload {
    pub identity_key: X25519PublicKey,
    pub signed_prekey: X25519PublicKey,
    pub signed_prekey_signature: Ed25519Signature,
    pub one_time_prekey: Option<X25519PublicKey>,
    pub cipher_suite: CipherSuite,
    pub key_version: u32,
}

impl PrekeyBundlePayload {
    pub fn from_json(json: &str) -> Result<Self, ProtocolError> {
        #[derive(serde::Deserialize)]
        struct Raw {
            identity_key: String,
            signed_prekey: String,
            signed_prekey_signature: String,
            one_time_prekey: Option<String>,
            cipher_suite: u16,
            key_version: u32,
        }

        let raw: Raw = serde_json::from_str(json)
            .map_err(|e| ProtocolError::Handshake(e.to_string()))?;

        let identity_key = X25519PublicKey::from_base64(&raw.identity_key)
            .map_err(|e| ProtocolError::Handshake(format!("identity_key: {}", e)))?;
        let signed_prekey = X25519PublicKey::from_base64(&raw.signed_prekey)
            .map_err(|e| ProtocolError::Handshake(format!("signed_prekey: {}", e)))?;
        let signed_prekey_signature = Ed25519Signature::from_base64(&raw.signed_prekey_signature)
            .map_err(|e| ProtocolError::Handshake(format!("signature: {}", e)))?;
        let one_time_prekey = if let Some(ref otpk) = raw.one_time_prekey {
            Some(X25519PublicKey::from_base64(otpk)
                .map_err(|e| ProtocolError::Handshake(format!("otpk: {}", e)))?)
        } else { None };

        let cipher_suite = match raw.cipher_suite {
            0x0001 => CipherSuite::Aegis1,
            v => return Err(ProtocolError::Handshake(format!("unknown cipher suite: {}", v))),
        };

        Ok(Self {
            identity_key,
            signed_prekey,
            signed_prekey_signature,
            one_time_prekey,
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
    let signature_bytes = [0u8; 64];

    let signed_prekey = SignedPrekeyPair {
        public: *sp_public.as_bytes(),
        signature: Ed25519Signature(signature_bytes),
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
