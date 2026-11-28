//! Authenticated encryption primitive for a future single-file application store.
//!
//! This module only encodes bytes; it does not manage files, locking, storage
//! transactions, or integrate with the active vault. Callers must not persist
//! plaintext. The format is LinSCP-specific, not an OfflineOTP container.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::PlatformError;

const MAGIC: &[u8; 8] = b"LSCPDAT1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;
const TAG_LEN: usize = 16;
/// Maximum unencrypted payload size. Check before allocation and KDF work.
pub const MAX_PLAINTEXT: usize = 16 * 1024 * 1024;

fn error(message: &str) -> PlatformError {
    PlatformError::SecretVault(message.to_string())
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
    if password.is_empty() || password.len() > 4096 {
        return Err(error("Invalid application vault password"));
    }
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|_| error("Invalid application vault KDF"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|_| error("Could not derive application vault key"))?;
    Ok(key)
}

/// Encrypt a payload with a fresh salt and nonce. The entire header is authenticated.
pub fn seal(plaintext: &[u8], password: &str) -> Result<Vec<u8>, PlatformError> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err(error("Application vault exceeds size limit"));
    }
    let mut header = [0u8; HEADER_LEN];
    header[..MAGIC.len()].copy_from_slice(MAGIC);
    rand::thread_rng().fill_bytes(&mut header[MAGIC.len()..]);
    let key = derive_key(password, &header[MAGIC.len()..MAGIC.len() + SALT_LEN])?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| error("Invalid application vault key"))?;
    let nonce = Nonce::from_slice(&header[HEADER_LEN - NONCE_LEN..]);
    let ciphertext = cipher.encrypt(nonce, Payload { msg: plaintext, aad: &header })
        .map_err(|_| error("Could not encrypt application vault"))?;
    let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Open an authenticated envelope. Corrupt or unsupported data is never treated as empty.
pub fn open(bytes: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
    if bytes.len() < HEADER_LEN + TAG_LEN || bytes.len() > HEADER_LEN + MAX_PLAINTEXT + TAG_LEN || !bytes.starts_with(MAGIC) {
        return Err(error("Invalid application vault format or size"));
    }
    let header = &bytes[..HEADER_LEN];
    let key = derive_key(password, &header[MAGIC.len()..MAGIC.len() + SALT_LEN])?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| error("Invalid application vault key"))?;
    let nonce = Nonce::from_slice(&header[HEADER_LEN - NONCE_LEN..]);
    let plaintext = cipher.decrypt(nonce, Payload { msg: &bytes[HEADER_LEN..], aad: header })
        .map_err(|_| error("Incorrect application vault password or damaged vault"))?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_randomizes_and_rejects_wrong_password_or_damage() {
        let message = b"private application data";
        let first = seal(message, "a strong test password").unwrap();
        let second = seal(message, "a strong test password").unwrap();
        assert_ne!(first, second);
        assert_eq!(&*open(&first, "a strong test password").unwrap(), message);
        assert!(open(&first, "wrong password").is_err());
        for index in [0, 8, HEADER_LEN - 1, HEADER_LEN, first.len() - 1] {
            let mut damaged = first.clone();
            damaged[index] ^= 1;
            assert!(open(&damaged, "a strong test password").is_err());
        }
        assert!(open(&first[..HEADER_LEN], "a strong test password").is_err());
    }

    #[test]
    fn rejects_empty_password_and_oversized_data() {
        assert!(seal(b"", "").is_err());
        assert!(seal(&vec![0; MAX_PLAINTEXT + 1], "test").is_err());
        assert!(open(&vec![0; HEADER_LEN + MAX_PLAINTEXT + TAG_LEN + 1], "test").is_err());
    }
}
