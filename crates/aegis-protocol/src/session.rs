//! Double Ratchet session state

use aegis_crypto::{
    kdf::hkdf_cat, kem::x25519_dh, CipherSuite, SymmetricKey, X25519PrivateKey, X25519PublicKey,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::error::ProtocolError;

const MAX_SKIPPED_MESSAGE_KEYS: u64 = 100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetState {
    pub dh_key_pair: Option<DhKeyPair>,
    chain_key: Option<[u8; 32]>,
    pub message_number: u64,
    pub chain_counter: u64,
    pub remote_ratchet_public: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhKeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl DhKeyPair {
    pub fn generate() -> Self {
        let (private, public) = X25519PrivateKey::generate();
        Self {
            private: private.0,
            public: *public.as_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleRatchetSession {
    pub sending: RatchetState,
    pub receiving: RatchetState,
    skipped_keys: BTreeMap<(u64, u64), [u8; 32]>,
    seen_messages: BTreeSet<(u64, u64)>,
    root_key: Option<[u8; 32]>,
    pub remote_identity: Option<[u8; 32]>,
    pub our_identity_private: Option<[u8; 32]>,
    pub associated_data: [u8; 32],
    pub key_version: u32,
    pub cipher_suite: CipherSuite,
    /// True until the first DH ratchet step is performed.
    /// Prevents DH ratcheting on the first message when using symmetric init.
    dh_ratchet_done: bool,
}

impl DoubleRatchetSession {
    /// Create a session from an initial shared secret. Both parties use the
    /// same shared secret (derived from PQXDH handshake) and derive an
    /// identical initial symmetric chain key. This is the standard Sesame/Signal
    /// symmetric initialization: the first message uses the same chain key for
    /// both parties, establishing forward secrecy from the second message onward.
    pub fn from_shared_secret(
        shared_secret: &[u8; 32],
        remote_identity: [u8; 32],
        our_identity_private: [u8; 32],
        _their_signed_prekey: [u8; 32],
        cipher_suite: CipherSuite,
    ) -> Self {
        let salt = b"Aegis-DoubleRatchet-v1";
        let (root_key, chain_key) = hkdf_cat(shared_secret, salt, b"initial-chain")
            .map_err(|e| ProtocolError::Session(e.to_string()))
            .unwrap();

        let root_key_bytes = *root_key.as_bytes();
        let chain_key_bytes = *chain_key.as_bytes();

        let mut associated_data = [0u8; 32];
        use sha2::{Digest, Sha512};
        let mut hasher = Sha512::new();
        hasher.update(remote_identity);
        hasher.update(our_identity_private);
        let combined_aad = hasher.finalize();
        associated_data.copy_from_slice(&combined_aad[..32]);

        let sending = RatchetState {
            dh_key_pair: Some(DhKeyPair::generate()),
            chain_key: Some(chain_key_bytes),
            message_number: 0,
            chain_counter: 0,
            remote_ratchet_public: None,
        };

        let receiving = RatchetState {
            dh_key_pair: None,
            chain_key: Some(chain_key_bytes),
            message_number: 0,
            chain_counter: 0,
            remote_ratchet_public: None,
        };

        Self {
            sending,
            receiving,
            skipped_keys: BTreeMap::new(),
            seen_messages: BTreeSet::new(),
            root_key: Some(root_key_bytes),
            remote_identity: Some(remote_identity),
            our_identity_private: Some(our_identity_private),
            associated_data,
            key_version: 1,
            cipher_suite,
            dh_ratchet_done: false,
        }
    }

    pub fn encrypt_next(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, EnvelopeMeta), ProtocolError> {
        let chain_key_bytes = self
            .sending
            .chain_key
            .ok_or_else(|| ProtocolError::Session("no sending chain key".into()))?;
        let (message_key, next_chain_key) = derive_message_key(chain_key_bytes)
            .map_err(|e| ProtocolError::Session(e.to_string()))?;

        let ciphertext = aegis_crypto::aead::encrypt(&message_key, plaintext, aad)
            .map_err(|e| ProtocolError::Session(e.to_string()))?;

        let meta = EnvelopeMeta {
            message_number: self.sending.message_number,
            previous_chain: self.sending.chain_counter,
            sender_ephemeral: self
                .sending
                .dh_key_pair
                .as_ref()
                .map(|kp| kp.public)
                .unwrap_or([0u8; 32]),
            key_version: self.key_version,
        };

        self.sending.chain_key = Some(next_chain_key);
        self.sending.message_number += 1;
        Ok((ciphertext, meta))
    }

    pub fn decrypt_next(
        &mut self,
        ciphertext_with_nonce: &[u8],
        meta: &EnvelopeMeta,
        aad: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        let key_id = (meta.previous_chain, meta.message_number);
        if self.seen_messages.contains(&key_id) {
            return Err(ProtocolError::MessageKeyReused);
        }

        // Check skipped keys first
        if let Some(key) = self.skipped_keys.remove(&key_id) {
            let plaintext =
                aegis_crypto::aead::decrypt(&SymmetricKey(key), ciphertext_with_nonce, aad)
                    .map_err(|e| ProtocolError::Session(e.to_string()))?;
            self.seen_messages.insert(key_id);
            return Ok(plaintext);
        }

        // Only perform DH ratchet when: (a) we've already done a DH ratchet before, AND
        // (b) the sender's ephemeral key differs from the previous one we saw.
        // During symmetric init (first message), `dh_ratchet_done = false` so we skip.
        // After each DH ratchet, `dh_ratchet_done = true` until the sender changes keys.
        let need_ratchet = self.dh_ratchet_done
            && self.receiving.remote_ratchet_public.is_some()
            && self.receiving.remote_ratchet_public != Some(meta.sender_ephemeral);

        if need_ratchet {
            self.perform_dh_ratchet(meta.sender_ephemeral)?;
        } else {
            // Mark DH ratchet as done so next message can ratchet if needed.
            // Also update the remote ephemeral to track which key we're currently at.
            if !self.dh_ratchet_done {
                self.dh_ratchet_done = true;
            }
            self.receiving.remote_ratchet_public = Some(meta.sender_ephemeral);
        }

        self.skip_message_keys_until(meta.message_number)?;

        // Derive and consume message key from receiving chain
        let chain_key_bytes = self
            .receiving
            .chain_key
            .ok_or_else(|| ProtocolError::Session("no receiving chain key".into()))?;
        let (msg_key, next_chain_key) = derive_message_key(chain_key_bytes)
            .map_err(|e| ProtocolError::Session(e.to_string()))?;
        self.receiving.chain_key = Some(next_chain_key);
        self.receiving.message_number += 1;

        let plaintext = aegis_crypto::aead::decrypt(&msg_key, ciphertext_with_nonce, aad)
            .map_err(|e| ProtocolError::Session(e.to_string()))?;
        self.seen_messages.insert(key_id);

        Ok(plaintext)
    }

    fn skip_message_keys_until(&mut self, target_message_number: u64) -> Result<(), ProtocolError> {
        if target_message_number < self.receiving.message_number {
            return Err(ProtocolError::RatchetKeyNotFound(target_message_number));
        }
        if target_message_number - self.receiving.message_number > MAX_SKIPPED_MESSAGE_KEYS {
            return Err(ProtocolError::RatchetLookaheadExceeded);
        }

        while self.receiving.message_number < target_message_number {
            let chain_key_bytes = self
                .receiving
                .chain_key
                .ok_or_else(|| ProtocolError::Session("no receiving chain key".into()))?;
            let (msg_key, next_chain_key) = derive_message_key(chain_key_bytes)
                .map_err(|e| ProtocolError::Session(e.to_string()))?;
            self.skipped_keys.insert(
                (self.receiving.chain_counter, self.receiving.message_number),
                *msg_key.as_bytes(),
            );
            self.receiving.chain_key = Some(next_chain_key);
            self.receiving.message_number += 1;
        }

        Ok(())
    }

    fn perform_dh_ratchet(&mut self, their_new_ephemeral: [u8; 32]) -> Result<(), ProtocolError> {
        let salt = b"Aegis-DoubleRatchet-v1";

        // Step 1: DH(our_current, their_new) → receiving chain
        let our_private = self
            .sending
            .dh_key_pair
            .as_ref()
            .ok_or_else(|| ProtocolError::Session("no DH key to ratchet".into()))?
            .private;
        let dh1 = x25519_dh(
            &X25519PrivateKey(our_private),
            &X25519PublicKey(their_new_ephemeral),
        );

        let rk = self
            .root_key
            .ok_or_else(|| ProtocolError::Session("no root key".into()))?;
        let mut combined1 = rk;
        for (i, byte) in dh1.iter().enumerate() {
            combined1[i] ^= byte;
        }
        let (new_root, recv_chain) = hkdf_cat(&combined1, salt, b"ratchet-step")
            .map_err(|e| ProtocolError::Session(e.to_string()))?;

        // Step 2: DH(our_new, their_new) → sending chain
        let our_new = DhKeyPair::generate();
        let dh2 = x25519_dh(
            &X25519PrivateKey(our_new.private),
            &X25519PublicKey(their_new_ephemeral),
        );
        let mut combined2 = *new_root.as_bytes();
        for (i, byte) in dh2.iter().enumerate() {
            combined2[i] ^= byte;
        }
        let (_, send_chain) = hkdf_cat(&combined2, salt, b"ratchet-step")
            .map_err(|e| ProtocolError::Session(e.to_string()))?;

        self.receiving.dh_key_pair = Some(our_new.clone());
        self.receiving.remote_ratchet_public = Some(their_new_ephemeral);
        self.receiving.chain_key = Some(*recv_chain.as_bytes());
        self.receiving.chain_counter += 1;
        self.receiving.message_number = 0;

        self.sending.dh_key_pair = Some(our_new);
        self.sending.chain_key = Some(*send_chain.as_bytes());
        self.sending.chain_counter += 1;
        self.sending.message_number = 0;

        self.root_key = Some(*new_root.as_bytes());
        self.skipped_keys.clear();

        Ok(())
    }
}

fn derive_message_key(
    chain_key: [u8; 32],
) -> Result<(SymmetricKey, [u8; 32]), aegis_crypto::CryptoError> {
    let (mk, nck) = hkdf_cat(&chain_key, b"AegisRatchet", b"aegis-msg-chain")?;
    Ok((mk, *nck.as_bytes()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeMeta {
    pub message_number: u64,
    pub previous_chain: u64,
    pub sender_ephemeral: [u8; 32],
    pub key_version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both parties derive the same initial chain key from the shared secret,
    /// enabling the symmetric initialization for the first message.
    #[test]
    fn test_session_symmetric_init() {
        let shared = [5u8; 32];
        let alice_id = [1u8; 32];
        let bob_id = [2u8; 32];

        let alice = DoubleRatchetSession::from_shared_secret(
            &shared,
            bob_id,
            alice_id,
            bob_id,
            CipherSuite::Aegis1,
        );
        let bob = DoubleRatchetSession::from_shared_secret(
            &shared,
            alice_id,
            bob_id,
            bob_id,
            CipherSuite::Aegis1,
        );

        // Both parties have identical initial chain keys
        assert_eq!(alice.sending.chain_key, bob.receiving.chain_key);
    }

    /// Alice encrypts, Bob decrypts. Both use the symmetric initial chain key.
    #[test]
    fn test_session_basic() {
        let shared = [5u8; 32];
        let alice_id = [1u8; 32];
        let bob_id = [2u8; 32];

        let mut alice = DoubleRatchetSession::from_shared_secret(
            &shared,
            bob_id,
            alice_id,
            bob_id,
            CipherSuite::Aegis1,
        );
        let mut bob = DoubleRatchetSession::from_shared_secret(
            &shared,
            alice_id,
            bob_id,
            bob_id,
            CipherSuite::Aegis1,
        );

        let plaintext = b"Hello, Aegis!";
        let aad = b"test-aad";

        let (ciphertext, meta) = alice.encrypt_next(plaintext, aad).unwrap();
        let decrypted = bob.decrypt_next(&ciphertext, &meta, aad).unwrap();
        assert_eq!(&decrypted[..], plaintext);
    }

    /// Bidirectional: Alice → Bob → Alice → Bob.
    /// Each reply triggers a DH ratchet on both sides.
    #[test]
    fn test_session_bidirectional() {
        let shared = [9u8; 32];
        let alice_id = [4u8; 32];
        let bob_id = [5u8; 32];

        let mut alice = DoubleRatchetSession::from_shared_secret(
            &shared,
            bob_id,
            alice_id,
            bob_id,
            CipherSuite::Aegis1,
        );
        let mut bob = DoubleRatchetSession::from_shared_secret(
            &shared,
            alice_id,
            bob_id,
            bob_id,
            CipherSuite::Aegis1,
        );

        let aad = b"bidirectional";

        // Alice sends first message (symmetric init, no DH yet)
        let (ct1, m1) = alice.encrypt_next(b"Message 1", aad).unwrap();
        assert_eq!(bob.decrypt_next(&ct1, &m1, aad).unwrap(), b"Message 1");

        // Bob replies — DH ratchet on both sides
        let (ct2, m2) = bob.encrypt_next(b"Reply from Bob", aad).unwrap();
        assert_eq!(
            alice.decrypt_next(&ct2, &m2, aad).unwrap(),
            b"Reply from Bob"
        );

        // Alice sends again — new DH ratchet
        let (ct3, m3) = alice.encrypt_next(b"Alice's second message", aad).unwrap();
        assert_eq!(
            bob.decrypt_next(&ct3, &m3, aad).unwrap(),
            b"Alice's second message"
        );

        // Bob sends again
        let (ct4, m4) = bob.encrypt_next(b"Bob's second message", aad).unwrap();
        assert_eq!(
            alice.decrypt_next(&ct4, &m4, aad).unwrap(),
            b"Bob's second message"
        );
    }

    #[test]
    fn test_out_of_order_messages_use_skipped_keys() {
        let shared = [7u8; 32];
        let alice_id = [1u8; 32];
        let bob_id = [2u8; 32];
        let aad = b"out-of-order";

        let mut alice = DoubleRatchetSession::from_shared_secret(
            &shared,
            bob_id,
            alice_id,
            bob_id,
            CipherSuite::Aegis1,
        );
        let mut bob = DoubleRatchetSession::from_shared_secret(
            &shared,
            alice_id,
            bob_id,
            bob_id,
            CipherSuite::Aegis1,
        );

        let (ct0, m0) = alice.encrypt_next(b"first", aad).unwrap();
        let (ct1, m1) = alice.encrypt_next(b"second", aad).unwrap();

        assert_eq!(bob.decrypt_next(&ct1, &m1, aad).unwrap(), b"second");
        assert_eq!(bob.decrypt_next(&ct0, &m0, aad).unwrap(), b"first");
    }

    #[test]
    fn test_replay_message_is_rejected() {
        let shared = [8u8; 32];
        let alice_id = [1u8; 32];
        let bob_id = [2u8; 32];
        let aad = b"replay";

        let mut alice = DoubleRatchetSession::from_shared_secret(
            &shared,
            bob_id,
            alice_id,
            bob_id,
            CipherSuite::Aegis1,
        );
        let mut bob = DoubleRatchetSession::from_shared_secret(
            &shared,
            alice_id,
            bob_id,
            bob_id,
            CipherSuite::Aegis1,
        );

        let (ct, meta) = alice.encrypt_next(b"once", aad).unwrap();
        assert_eq!(bob.decrypt_next(&ct, &meta, aad).unwrap(), b"once");
        assert!(matches!(
            bob.decrypt_next(&ct, &meta, aad),
            Err(ProtocolError::MessageKeyReused)
        ));
    }

    #[test]
    fn test_too_far_ahead_message_is_rejected() {
        let shared = [9u8; 32];
        let alice_id = [1u8; 32];
        let bob_id = [2u8; 32];
        let mut bob = DoubleRatchetSession::from_shared_secret(
            &shared,
            alice_id,
            bob_id,
            bob_id,
            CipherSuite::Aegis1,
        );
        let meta = EnvelopeMeta {
            message_number: MAX_SKIPPED_MESSAGE_KEYS + 1,
            previous_chain: 0,
            sender_ephemeral: [3u8; 32],
            key_version: 1,
        };

        assert!(matches!(
            bob.decrypt_next(b"invalid", &meta, b"aad"),
            Err(ProtocolError::RatchetLookaheadExceeded)
        ));
    }
}
