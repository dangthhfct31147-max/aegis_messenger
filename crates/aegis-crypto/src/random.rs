//! Cryptographically secure random number generation

use rand::rngs::OsRng;

/// Alias for the system's CSPRNG
pub type SystemRng = OsRng;

/// Get the system CSPRNG (auto-seeded, backed by OS)
pub fn system_rng() -> OsRng {
    OsRng
}

/// Fill a byte slice with cryptographically secure random bytes
pub fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("CSPRNG failure — system entropy pool exhausted");
}

/// Generate a random byte vector of given length
pub fn random_vec(len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len];
    fill_random(&mut v);
    v
}

/// Generate a random 32-byte (256-bit) array
pub fn random_32bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes);
    bytes
}

/// Generate a random 16-byte (128-bit) array (e.g., for nonces)
pub fn random_16bytes() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    bytes
}

/// Generate a random 12-byte (96-bit) array (XChaCha20-Poly1305 nonce)
pub fn random_12bytes() -> [u8; 12] {
    let mut bytes = [0u8; 12];
    fill_random(&mut bytes);
    bytes
}
