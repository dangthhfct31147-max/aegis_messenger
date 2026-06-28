//! Server-side cryptographic utilities
//!
//! Server-side crypto is minimal — only:
//! - Token hashing (SHA-512, never store raw tokens)
//! - Queue ID hashing
//! - Constant-time comparison for capability token verification
//!
//! All message encryption/decryption happens CLIENT-SIDE. Server never holds keys.

use sha2::{Digest, Sha512};

/// Hash a token (queue ID, capability token) using SHA-512.
/// Server NEVER stores raw tokens — only hashes.
pub fn hash_token(token: &[u8]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(token);
    let result = hasher.finalize();
    result[..32].try_into().unwrap()
}

/// Constant-time comparison to prevent timing attacks on token verification
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    subtle::ConstantTimeEq::ct_eq(a, b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token_deterministic() {
        let token = b"my-secret-token";
        let h1 = hash_token(token);
        let h2 = hash_token(token);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_token_different() {
        let h1 = hash_token(b"token1");
        let h2 = hash_token(b"token2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }
}
