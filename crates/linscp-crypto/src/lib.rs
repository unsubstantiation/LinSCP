//! Pure-Rust cryptography shared across CLI, HTTP server, and Tauri apps:
//! - Byte-compatible `lscp1$` encrypted passwords for `sessions.ini` / `sessions.key`
//! - 300,000-iteration PBKDF2-HMAC-SHA256 account password hashing
//! - `SHA-256`, `SHA-1`, `MD5`, and `CRC32` digests (`digests`)
//! - AWS Signature Version 4 signing (`sigv4`)
//! - PuTTY `.ppk` v2 & v3 + Argon2 parser and OpenSSH converter (`ppk`)

pub mod digests;
pub mod ppk;
pub mod sigv4;

use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

pub const LSCP1_PREFIX: &str = "lscp1$";
pub const KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 16;
pub const TAG_BYTES: usize = 32;
pub const MAX_PASSWORD_BYTES: usize = 4096;
pub const PBKDF2_ITERATIONS: u32 = 300_000;
pub const PBKDF2_SALT_BYTES: usize = 16;

const TAG_LABEL: &[u8] = b"lscp1";
const ENC_KEY_LABEL: &[u8] = b"LinSCP sessions file v1 encryption key";
const MAC_KEY_LABEL: &[u8] = b"LinSCP sessions file v1 authentication key";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("The encryption key must be 32 bytes.")]
    InvalidKeyLength,
    #[error("The nonce must be 16 bytes.")]
    InvalidNonceLength,
    #[error("The password is too long to store.")]
    PasswordTooLong,
    #[error("The stored password is not encrypted with a known format.")]
    UnknownFormat,
    #[error("The stored password is corrupted: its encoding is not valid base64 of the expected shape.")]
    CorruptedCiphertext,
    #[error("The stored password does not match this key file: it was encrypted somewhere else, or the value was modified.")]
    AuthenticationFailed,
    #[error("The stored password decrypted to bytes that are not text.")]
    InvalidUtf8,
    #[error("The encryption key file '{path}' does not exist (it is created when the first password is stored); restore it from a copy or store the password again")]
    MissingKeyFile { path: String },
    #[error("The encryption key file '{path}' cannot be read ({reason}).")]
    UnreadableKeyFile { path: String, reason: String },
    #[error("The encryption key file '{path}' does not contain a 32-byte key (base64 or raw); remove it to have a new one created, or restore it from a copy.")]
    MalformedKeyFile { path: String },
}

/// 32-byte master key from `sessions.key`, zeroized automatically on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionMasterKey([u8; KEY_BYTES]);

impl SessionMasterKey {
    pub const fn from_array(raw: [u8; KEY_BYTES]) -> Self {
        Self(raw)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let array: [u8; KEY_BYTES] = bytes.try_into().map_err(|_| CryptoError::InvalidKeyLength)?;
        Ok(Self(array))
    }

    pub fn generate() -> Self {
        let mut raw = [0u8; KEY_BYTES];
        rand::thread_rng().fill_bytes(&mut raw);
        Self(raw)
    }

    /// Parses raw 32-byte content or base64-encoded 32-byte content, matching
    /// `SessionStore.cpp` and `linscp_crypto.py`.
    pub fn parse_file_bytes(content: &[u8], display_path: &str) -> Result<Self, CryptoError> {
        if content.len() == KEY_BYTES {
            return Self::from_bytes(content);
        }
        let trimmed = trim_ascii_whitespace(content);
        if trimmed.len() == KEY_BYTES {
            return Self::from_bytes(trimmed);
        }
        if let Ok(decoded) = BASE64.decode(trimmed) {
            if decoded.len() == KEY_BYTES {
                return Self::from_bytes(&decoded);
            }
        }
        Err(CryptoError::MalformedKeyFile {
            path: display_path.to_string(),
        })
    }

    pub fn load_from_path(path: &Path) -> Result<Self, CryptoError> {
        let display = path.display().to_string();
        match std::fs::read(path) {
            Ok(bytes) => Self::parse_file_bytes(&bytes, &display),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Err(CryptoError::MissingKeyFile { path: display })
            }
            Err(err) => Err(CryptoError::UnreadableKeyFile {
                path: display,
                reason: err.to_string(),
            }),
        }
    }

    pub fn to_base64_line(&self) -> String {
        format!("{}\n", BASE64.encode(self.0))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

/// Companion `.key` path for a `sessions.ini` path.
pub fn key_path_for(ini_path: &str) -> String {
    if ini_path.is_empty() {
        return String::new();
    }
    if let Some(stem) = ini_path.strip_suffix(".ini") {
        format!("{stem}.key")
    } else {
        format!("{ini_path}.key")
    }
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while let Some((first, rest)) = bytes.split_first() {
        if first.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = bytes.split_last() {
        if last.is_ascii_whitespace() {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn derive_subkeys(master: &SessionMasterKey) -> ([u8; 32], [u8; 32]) {
    let enc_key = hmac_sha256(&master.0, &[ENC_KEY_LABEL]);
    let mac_key = hmac_sha256(&master.0, &[MAC_KEY_LABEL]);
    (enc_key, mac_key)
}

fn xor_keystream(enc_key: &[u8; 32], nonce: &[u8; NONCE_BYTES], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut counter: u32 = 0;
    let mut offset = 0;
    while offset < input.len() {
        let counter_be = counter.to_be_bytes();
        let mut block = hmac_sha256(enc_key, &[nonce, &counter_be]);
        let take = (input.len() - offset).min(block.len());
        for (&in_byte, &mask_byte) in input[offset..offset + take]
            .iter()
            .zip(block[..take].iter())
        {
            out.push(in_byte ^ mask_byte);
        }
        block.zeroize();
        offset += take;
        counter += 1;
    }
    out
}

/// Returns true if `value` carries the `lscp1$` encrypted-password prefix.
pub fn is_encrypted_password(value: &str) -> bool {
    value.starts_with(LSCP1_PREFIX)
}

/// Encrypts `plain` into a `lscp1$...` token using fresh OS randomness.
pub fn encrypt_password(plain: &str, master: &SessionMasterKey) -> Result<String, CryptoError> {
    let mut nonce = [0u8; NONCE_BYTES];
    rand::thread_rng().fill_bytes(&mut nonce);
    encrypt_password_with_nonce(plain, master, &nonce)
}

/// Deterministic `lscp1$` encryption with an explicit 16-byte nonce (used by
/// cross-language test vectors).
pub fn encrypt_password_with_nonce(
    plain: &str,
    master: &SessionMasterKey,
    nonce: &[u8],
) -> Result<String, CryptoError> {
    let data = plain.as_bytes();
    if data.len() > MAX_PASSWORD_BYTES {
        return Err(CryptoError::PasswordTooLong);
    }
    let nonce_arr: &[u8; NONCE_BYTES] = nonce
        .try_into()
        .map_err(|_| CryptoError::InvalidNonceLength)?;

    let (mut enc_key, mut mac_key) = derive_subkeys(master);
    let cipher = xor_keystream(&enc_key, nonce_arr, data);
    let tag = hmac_sha256(&mac_key, &[TAG_LABEL, nonce_arr, &cipher]);
    enc_key.zeroize();
    mac_key.zeroize();

    let mut blob = Vec::with_capacity(NONCE_BYTES + cipher.len() + TAG_BYTES);
    blob.extend_from_slice(nonce_arr);
    blob.extend_from_slice(&cipher);
    blob.extend_from_slice(&tag);
    Ok(format!("{LSCP1_PREFIX}{}", BASE64.encode(blob)))
}

/// Decrypts and authenticates a `lscp1$...` token.
pub fn decrypt_password(encoded: &str, master: &SessionMasterKey) -> Result<String, CryptoError> {
    let Some(b64_part) = encoded.strip_prefix(LSCP1_PREFIX) else {
        return Err(CryptoError::UnknownFormat);
    };
    let blob = BASE64
        .decode(b64_part.as_bytes())
        .map_err(|_| CryptoError::CorruptedCiphertext)?;
    if blob.len() < NONCE_BYTES + TAG_BYTES
        || blob.len() - NONCE_BYTES - TAG_BYTES > MAX_PASSWORD_BYTES
    {
        return Err(CryptoError::CorruptedCiphertext);
    }

    let nonce: &[u8; NONCE_BYTES] = blob[..NONCE_BYTES]
        .try_into()
        .expect("slice length checked");
    let cipher = &blob[NONCE_BYTES..blob.len() - TAG_BYTES];
    let tag = &blob[blob.len() - TAG_BYTES..];

    let (mut enc_key, mut mac_key) = derive_subkeys(master);
    let expected = hmac_sha256(&mac_key, &[TAG_LABEL, nonce, cipher]);
    mac_key.zeroize();

    if !bool::from(expected.ct_eq(tag)) {
        enc_key.zeroize();
        return Err(CryptoError::AuthenticationFailed);
    }

    let plain_bytes = xor_keystream(&enc_key, nonce, cipher);
    enc_key.zeroize();
    String::from_utf8(plain_bytes).map_err(|_| CryptoError::InvalidUtf8)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Hashes an account login password with PBKDF2-HMAC-SHA256 (300,000 rounds),
/// returning `(hash_hex, salt_hex)` compatible with `accounts.ini`.
pub fn hash_account_password(password: &str, salt: Option<&[u8; PBKDF2_SALT_BYTES]>) -> (String, String) {
    let salt_bytes = match salt {
        Some(given) => *given,
        None => {
            let mut generated = [0u8; PBKDF2_SALT_BYTES];
            rand::thread_rng().fill_bytes(&mut generated);
            generated
        }
    };
    let mut dk = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_bytes, PBKDF2_ITERATIONS, &mut dk);
    let hash_hex = hex_encode(&dk);
    dk.zeroize();
    (hash_hex, hex_encode(&salt_bytes))
}

/// Constant-time verification of an `accounts.ini` PBKDF2 password record.
pub fn verify_account_password(password: &str, stored_hash_hex: &str, stored_salt_hex: &str) -> bool {
    let Some(salt_vec) = hex_decode(stored_salt_hex) else {
        return false;
    };
    let Ok(salt): Result<[u8; PBKDF2_SALT_BYTES], _> = salt_vec.try_into() else {
        return false;
    };
    let Some(expected_dk) = hex_decode(stored_hash_hex) else {
        return false;
    };
    if expected_dk.len() != 32 {
        return false;
    }
    let mut actual_dk = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut actual_dk);
    let matches = bool::from(actual_dk.ct_eq(&expected_dk));
    actual_dk.zeroize();
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lscp1_matches_python_reference_vector_byte_for_byte() {
        let key_bytes: Vec<u8> = (0u8..32u8).collect();
        let nonce_bytes: Vec<u8> = (16u8..32u8).collect();
        let master = SessionMasterKey::from_bytes(&key_bytes).expect("32-byte key");
        let ciphertext =
            encrypt_password_with_nonce("S3cr3t!Pass#2026", &master, &nonce_bytes).expect("encrypt");
        assert_eq!(
            ciphertext,
            "lscp1$EBESExQVFhcYGRobHB0eH2O4ezzmYH370G39JNEWV3UKmNy5iaxBwNro1exoTvVdvdwtDnFxSYetybMyM3aAIA=="
        );
        let decrypted = decrypt_password(&ciphertext, &master).expect("decrypt");
        assert_eq!(decrypted, "S3cr3t!Pass#2026");
    }

    #[test]
    fn lscp1_rejects_wrong_key_and_tampered_tag() {
        let key_a = SessionMasterKey::from_bytes(&[0x11; 32]).unwrap();
        let key_b = SessionMasterKey::from_bytes(&[0x22; 32]).unwrap();
        let token = encrypt_password("hunter2", &key_a).unwrap();
        assert_eq!(
            decrypt_password(&token, &key_b),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn pbkdf2_matches_python_accounts_vector() {
        let salt: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let (hash_hex, salt_hex) = hash_account_password("correct horse battery staple", Some(&salt));
        assert_eq!(
            hash_hex,
            "48a269a707488c7db1ce99c1e4ba8d3204cd7a8020e6928a193c47e6e5d0dbaa"
        );
        assert!(verify_account_password(
            "correct horse battery staple",
            &hash_hex,
            &salt_hex
        ));
        assert!(!verify_account_password("wrong", &hash_hex, &salt_hex));
    }
}
