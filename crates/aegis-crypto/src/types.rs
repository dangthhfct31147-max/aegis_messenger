//! Core cryptographic types

use crate::Zeroize;

/// 256-bit symmetric key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymmetricKey(pub [u8; 32]);

impl SymmetricKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        crate::random::fill_random(&mut bytes);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for SymmetricKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// X25519 public key (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519PublicKey(pub [u8; 32]);

impl X25519PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn from_base64(input: &str) -> Result<Self, crate::CryptoError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| crate::CryptoError::Base64DecodeFailed)?;
        if bytes.len() != 32 {
            return Err(crate::CryptoError::DecodingFailed);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for X25519PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// X25519 private key (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X25519PrivateKey(pub [u8; 32]);

impl X25519PrivateKey {
    pub fn generate() -> (Self, X25519PublicKey) {
        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = StaticSecret::random_from_rng(crate::random::system_rng());
        let public = PublicKey::from(&secret);
        let mut sk = [0u8; 32];
        sk.copy_from_slice(secret.as_bytes());
        let mut pk = [0u8; 32];
        pk.copy_from_slice(public.as_bytes());
        (Self(sk), X25519PublicKey(pk))
    }
    pub fn diffie_hellman(
        &self,
        peer_public: &X25519PublicKey,
    ) -> Result<SymmetricKey, crate::CryptoError> {
        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = StaticSecret::from(self.0);
        let peer = PublicKey::from(peer_public.0);
        let shared = secret.diffie_hellman(&peer);
        let mut key = [0u8; 32];
        key.copy_from_slice(shared.as_bytes());
        Ok(SymmetricKey(key))
    }
}

impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Ed25519 public key (32 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey(pub [u8; 32]);

impl Ed25519PublicKey {
    pub fn from_base64(input: &str) -> Result<Self, crate::CryptoError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| crate::CryptoError::Base64DecodeFailed)?;
        if bytes.len() != 32 {
            return Err(crate::CryptoError::DecodingFailed);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }
    pub fn verify(
        &self,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), crate::CryptoError> {
        use ed25519_dalek::{Signature as DalekSig, Verifier, VerifyingKey};
        let vk = VerifyingKey::from_bytes(&self.0)
            .map_err(|_| crate::CryptoError::Ed25519InvalidPublicKey)?;
        let sig = DalekSig::from_bytes(&signature.0);
        vk.verify(message, &sig)
            .map_err(|_| crate::CryptoError::SignatureVerificationFailed)
    }
}

/// Ed25519 private key (64 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519PrivateKey(pub [u8; 64]);

impl Ed25519PrivateKey {
    pub fn generate() -> (Self, Ed25519PublicKey) {
        use ed25519_dalek::SigningKey;
        let signing = SigningKey::generate(&mut crate::random::system_rng());
        let verifying = signing.verifying_key();
        let mut sk = [0u8; 64];
        sk[..32].copy_from_slice(signing.as_bytes());
        sk[32..].copy_from_slice(verifying.as_bytes());
        let mut pk = [0u8; 32];
        pk.copy_from_slice(verifying.as_bytes());
        (Self(sk), Ed25519PublicKey(pk))
    }
    pub fn sign(&self, message: &[u8]) -> Result<Ed25519Signature, crate::CryptoError> {
        use ed25519_dalek::{Signer, SigningKey};
        let sk: [u8; 32] = self.0[..32].try_into().unwrap();
        let signing = SigningKey::from_bytes(&sk);
        let sig = signing.sign(message);
        Ok(Ed25519Signature(sig.to_bytes()))
    }
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Ed25519 signature (64 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Ed25519Signature {
    pub fn from_base64(input: &str) -> Result<Self, crate::CryptoError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| crate::CryptoError::Base64DecodeFailed)?;
        if bytes.len() != 64 {
            return Err(crate::CryptoError::DecodingFailed);
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&bytes);
        Ok(Self(sig))
    }
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub dklen: usize,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m: 2u32.pow(21),
            t: 3,
            p: 4,
            dklen: 32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2Key(pub Vec<u8>);

impl Argon2Key {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl AsRef<[u8]> for Argon2Key {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Argon2Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct PrekeyBundle {
    pub identity_key: X25519PublicKey,
    pub signed_prekey: X25519PublicKey,
    pub signed_prekey_signature: Ed25519Signature,
    pub one_time_prekey: Option<X25519PublicKey>,
    pub cipher_suite: CipherSuite,
    pub key_version: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    #[default]
    Aegis1 = 0x0001,
}

pub const PROTOCOL_VERSION: u16 = 0x0001;

// ============ serde support ============

impl serde::Serialize for SymmetricKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0);
        serde::Serialize::serialize(&b64, s)
    }
}

impl<'de> serde::Deserialize<'de> for SymmetricKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use base64::Engine;
        let b64 = String::deserialize(d)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&b64)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("invalid length"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
}

impl serde::Serialize for X25519PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_base64().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for X25519PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::from_base64(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for X25519PrivateKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(self.0)
            .serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for X25519PrivateKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use base64::Engine;
        let b64 = String::deserialize(d)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&b64)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("invalid length"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
}

impl serde::Serialize for Ed25519PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_base64().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::from_base64(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Ed25519PrivateKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(self.0)
            .serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519PrivateKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use base64::Engine;
        let b64 = String::deserialize(d)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&b64)
            .map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("invalid length"));
        }
        let mut key = [0u8; 64];
        key.copy_from_slice(&bytes);
        Ok(Self(key))
    }
}

impl serde::Serialize for Ed25519Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_base64().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::from_base64(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for CipherSuite {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (*self as u16).serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for CipherSuite {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = u16::deserialize(d)?;
        match v {
            0x0001 => Ok(CipherSuite::Aegis1),
            _ => Err(serde::de::Error::custom("unknown cipher suite")),
        }
    }
}

impl serde::Serialize for Argon2Params {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = s.serialize_struct("Argon2Params", 4)?;
        s.serialize_field("m", &self.m)?;
        s.serialize_field("t", &self.t)?;
        s.serialize_field("p", &self.p)?;
        s.serialize_field("dklen", &self.dklen)?;
        s.end()
    }
}

impl<'de> serde::Deserialize<'de> for Argon2Params {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Raw {
            m: u32,
            t: u32,
            p: u32,
            dklen: usize,
        }
        let raw = Raw::deserialize(d)?;
        Ok(Self {
            m: raw.m,
            t: raw.t,
            p: raw.p,
            dklen: raw.dklen,
        })
    }
}

impl serde::Serialize for Argon2Key {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(&self.0)
            .serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for Argon2Key {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use base64::Engine;
        let b64 = String::deserialize(d)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&b64)
            .map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}
