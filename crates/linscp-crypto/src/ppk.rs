//! Pure-Rust PuTTY `.ppk` v2 & v3 parser, Argon2 / SHA-1 decryptor, integrity
//! verifier, `authorized_keys` public-line exporter, and OpenSSH private-key
//! converter (`openssh-key-v1`), matching `source/linux/PpkKey.cpp`.

use std::path::Path;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use rand::RngCore;
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::digests::hex_decode;

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;

const MAX_KEY_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 1024 * 1024;
const PPK_HEADER_PREFIX: &str = "PuTTY-User-Key-File-";
const PPK_MAC_LABEL: &[u8] = b"putty-private-key-file-mac-key";
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
const BCRYPT_ROUNDS: u32 = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PpkError {
    #[error("{0}")]
    InvalidFormat(String),
    #[error("PPK Argon2 parameters are outside safe limits")]
    UnsafeArgon2Parameters,
    #[error("PPK integrity check failed (incorrect passphrase or damaged key file)")]
    IntegrityCheckFailed,
    #[error("PPK private key components are invalid or inconsistent")]
    InvalidKeyComponents,
    #[error("Unsupported PPK key algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("Output file already exists; refusing to overwrite it")]
    OutputAlreadyExists,
    #[error("Cannot read or write key file: {0}")]
    Io(String),
}

#[derive(Debug, Clone)]
pub struct ParsedPpk {
    pub version: u8,
    pub algorithm: String,
    pub encryption: String,
    pub comment: String,
    pub argon_type: String,
    pub memory_kib: u32,
    pub passes: u32,
    pub parallelism: u32,
    pub salt: Vec<u8>,
    pub public_blob: Vec<u8>,
    private_blob: Zeroizing<Vec<u8>>,
    pub mac: Vec<u8>,
}

/// Checks whether `content` begins with a `PuTTY-User-Key-File-` header.
pub fn is_ppk_bytes(content: &[u8]) -> bool {
    content.starts_with(PPK_HEADER_PREFIX.as_bytes())
}

/// Checks whether `path` starts with a `PuTTY-User-Key-File-` header.
pub fn is_ppk_file(path: &Path) -> bool {
    std::fs::read(path)
        .map(|b| is_ppk_bytes(&b))
        .unwrap_or(false)
}

fn parse_header_line(line: &str) -> Result<(&str, &str), PpkError> {
    if line.len() > MAX_FIELD_BYTES {
        return Err(PpkError::InvalidFormat("PPK header line too long".to_string()));
    }
    let Some((name, rest)) = line.split_once(':') else {
        return Err(PpkError::InvalidFormat("Malformed PPK header line".to_string()));
    };
    let val = rest.strip_prefix(' ').unwrap_or(rest);
    Ok((name, val))
}

fn decode_strict_base64_lines<'a, I>(lines: &mut I, count: usize) -> Result<Vec<u8>, PpkError>
where
    I: Iterator<Item = &'a str>,
{
    if count == 0 || count > MAX_FIELD_BYTES {
        return Err(PpkError::InvalidFormat("Invalid PPK base64 line count".to_string()));
    }
    let mut joined = String::new();
    for _ in 0..count {
        let Some(line) = lines.next() else {
            return Err(PpkError::InvalidFormat("Truncated PPK base64 block".to_string()));
        };
        if line.len() > MAX_FIELD_BYTES || joined.len() + line.len() > MAX_FIELD_BYTES {
            return Err(PpkError::InvalidFormat("PPK field exceeds maximum size".to_string()));
        }
        joined.push_str(line);
    }
    if joined.is_empty() || (joined.len() & 3) != 0 {
        return Err(PpkError::InvalidFormat("Invalid PPK base64 length".to_string()));
    }
    BASE64
        .decode(joined.as_bytes())
        .map_err(|_| PpkError::InvalidFormat("Invalid PPK base64 encoding".to_string()))
}

pub fn parse_ppk_str(text: &str) -> Result<ParsedPpk, PpkError> {
    if text.is_empty() || text.len() > MAX_KEY_FILE_BYTES {
        return Err(PpkError::InvalidFormat(
            "PPK key file is empty or too large".to_string(),
        ));
    }
    let mut lines = text.lines().map(|l| l.strip_suffix('\r').unwrap_or(l));
    let first = lines
        .next()
        .ok_or_else(|| PpkError::InvalidFormat("Invalid PPK header".to_string()))?;
    let Some(after_prefix) = first.strip_prefix(PPK_HEADER_PREFIX) else {
        return Err(PpkError::InvalidFormat("Not a PPK key file".to_string()));
    };
    let Some((ver_str, alg_rest)) = after_prefix.split_once(':') else {
        return Err(PpkError::InvalidFormat("Invalid PPK header".to_string()));
    };
    let version: u8 = ver_str
        .parse()
        .map_err(|_| PpkError::InvalidFormat("Invalid PPK version".to_string()))?;
    if version != 2 && version != 3 {
        return Err(PpkError::InvalidFormat(
            "Only PPK v2 and v3 key files are supported".to_string(),
        ));
    }
    let algorithm = alg_rest.strip_prefix(' ').unwrap_or(alg_rest).to_string();

    let (enc_name, enc_val) = parse_header_line(
        lines
            .next()
            .ok_or_else(|| PpkError::InvalidFormat("Missing Encryption header".to_string()))?,
    )?;
    if enc_name != "Encryption" || (enc_val != "none" && enc_val != "aes256-cbc") {
        return Err(PpkError::InvalidFormat(
            "Invalid or unsupported PPK encryption header".to_string(),
        ));
    }
    let encryption = enc_val.to_string();

    let (comment_name, comment_val) = parse_header_line(
        lines
            .next()
            .ok_or_else(|| PpkError::InvalidFormat("Missing Comment header".to_string()))?,
    )?;
    if comment_name != "Comment" {
        return Err(PpkError::InvalidFormat("Invalid PPK comment header".to_string()));
    }
    let comment = comment_val.to_string();

    let (pub_name, pub_count_str) = parse_header_line(
        lines
            .next()
            .ok_or_else(|| PpkError::InvalidFormat("Missing Public-Lines header".to_string()))?,
    )?;
    if pub_name != "Public-Lines" {
        return Err(PpkError::InvalidFormat("Invalid PPK public key section".to_string()));
    }
    let pub_lines: usize = pub_count_str
        .parse()
        .map_err(|_| PpkError::InvalidFormat("Invalid Public-Lines count".to_string()))?;
    let public_blob = decode_strict_base64_lines(&mut lines, pub_lines)?;

    let mut argon_type = String::new();
    let mut memory_kib = 0u32;
    let mut passes = 0u32;
    let mut parallelism = 0u32;
    let mut salt = Vec::new();

    if version == 3 {
        let (kdf_name, kdf_val) = parse_header_line(lines.next().ok_or_else(|| {
            PpkError::InvalidFormat("Missing PPK v3 Key-Derivation header".to_string())
        })?)?;
        if kdf_name != "Key-Derivation" {
            return Err(PpkError::InvalidFormat(
                "Invalid PPK v3 key derivation header".to_string(),
            ));
        }
        argon_type = kdf_val.to_string();
        if encryption == "aes256-cbc" {
            if !matches!(argon_type.as_str(), "Argon2d" | "Argon2i" | "Argon2id") {
                return Err(PpkError::InvalidFormat(
                    "Unsupported PPK v3 key derivation algorithm".to_string(),
                ));
            }
            let (m_name, m_val) = parse_header_line(lines.next().ok_or_else(|| {
                PpkError::InvalidFormat("Missing Argon2-Memory header".to_string())
            })?)?;
            if m_name != "Argon2-Memory" {
                return Err(PpkError::InvalidFormat("Missing Argon2-Memory header".to_string()));
            }
            memory_kib = m_val
                .parse()
                .map_err(|_| PpkError::InvalidFormat("Invalid Argon2-Memory value".to_string()))?;

            let (p_name, p_val) = parse_header_line(lines.next().ok_or_else(|| {
                PpkError::InvalidFormat("Missing Argon2-Passes header".to_string())
            })?)?;
            if p_name != "Argon2-Passes" {
                return Err(PpkError::InvalidFormat("Missing Argon2-Passes header".to_string()));
            }
            passes = p_val
                .parse()
                .map_err(|_| PpkError::InvalidFormat("Invalid Argon2-Passes value".to_string()))?;

            let (par_name, par_val) = parse_header_line(lines.next().ok_or_else(|| {
                PpkError::InvalidFormat("Missing Argon2-Parallelism header".to_string())
            })?)?;
            if par_name != "Argon2-Parallelism" {
                return Err(PpkError::InvalidFormat(
                    "Missing Argon2-Parallelism header".to_string(),
                ));
            }
            parallelism = par_val.parse().map_err(|_| {
                PpkError::InvalidFormat("Invalid Argon2-Parallelism value".to_string())
            })?;

            let (s_name, s_val) = parse_header_line(lines.next().ok_or_else(|| {
                PpkError::InvalidFormat("Missing Argon2-Salt header".to_string())
            })?)?;
            if s_name != "Argon2-Salt" {
                return Err(PpkError::InvalidFormat("Missing Argon2-Salt header".to_string()));
            }
            salt = hex_decode(s_val)
                .filter(|s| !s.is_empty() && s.len() <= 1024)
                .ok_or_else(|| PpkError::InvalidFormat("Invalid PPK Argon2 salt".to_string()))?;

            // Bound Argon2 work factors BEFORE allocating memory.
            if !(8..=256 * 1024).contains(&memory_kib)
                || !(1..=100).contains(&passes)
                || !(1..=64).contains(&parallelism)
            {
                return Err(PpkError::UnsafeArgon2Parameters);
            }
        } else if argon_type != "none" {
            return Err(PpkError::InvalidFormat(
                "Unencrypted PPK v3 key has unexpected derivation parameters".to_string(),
            ));
        }
    }

    let (priv_name, priv_count_str) = parse_header_line(
        lines
            .next()
            .ok_or_else(|| PpkError::InvalidFormat("Missing Private-Lines header".to_string()))?,
    )?;
    if priv_name != "Private-Lines" {
        return Err(PpkError::InvalidFormat("Invalid PPK private key section".to_string()));
    }
    let priv_lines: usize = priv_count_str
        .parse()
        .map_err(|_| PpkError::InvalidFormat("Invalid Private-Lines count".to_string()))?;
    let private_blob = Zeroizing::new(decode_strict_base64_lines(&mut lines, priv_lines)?);

    let (mac_name, mac_hex) = parse_header_line(
        lines
            .next()
            .ok_or_else(|| PpkError::InvalidFormat("Missing Private-MAC header".to_string()))?,
    )?;
    if mac_name != "Private-MAC" {
        return Err(PpkError::InvalidFormat("Invalid PPK private MAC header".to_string()));
    }
    let expected_mac_len = if version == 2 { 20 } else { 32 };
    let mac = hex_decode(mac_hex)
        .filter(|m| m.len() == expected_mac_len)
        .ok_or_else(|| PpkError::InvalidFormat("Invalid PPK private MAC".to_string()))?;

    for trailing in lines {
        if !trailing.is_empty() {
            return Err(PpkError::InvalidFormat(
                "Unexpected data after PPK MAC".to_string(),
            ));
        }
    }
    if algorithm.is_empty() || public_blob.is_empty() || private_blob.is_empty() {
        return Err(PpkError::InvalidFormat("Incomplete PPK key data".to_string()));
    }

    Ok(ParsedPpk {
        version,
        algorithm,
        encryption,
        comment,
        argon_type,
        memory_kib,
        passes,
        parallelism,
        salt,
        public_blob,
        private_blob,
        mac,
    })
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_ssh_bytes(out: &mut Vec<u8>, data: &[u8]) {
    put_u32(out, data.len() as u32);
    out.extend_from_slice(data);
}

fn get_ssh_bytes<'a>(input: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    if *pos + 4 > input.len() {
        return None;
    }
    let len = u32::from_be_bytes(input[*pos..*pos + 4].try_into().ok()?) as usize;
    *pos += 4;
    if len > MAX_FIELD_BYTES || *pos + len > input.len() {
        return None;
    }
    let slice = &input[*pos..*pos + len];
    *pos += len;
    Some(slice)
}

fn get_non_negative_mpint<'a>(input: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let raw = get_ssh_bytes(input, pos)?;
    if raw.is_empty() || (raw[0] & 0x80) != 0 {
        return None;
    }
    let mut start = 0;
    while start + 1 < raw.len() && raw[start] == 0 {
        start += 1;
    }
    Some(&raw[start..])
}

fn put_mpint_positive(out: &mut Vec<u8>, magnitude_be: &[u8]) {
    let mut trimmed = magnitude_be;
    while trimmed.len() > 1 && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }
    if trimmed.is_empty() || (trimmed == [0]) {
        put_u32(out, 0);
        return;
    }
    if (trimmed[0] & 0x80) != 0 {
        put_u32(out, (trimmed.len() + 1) as u32);
        out.push(0);
        out.extend_from_slice(trimmed);
    } else {
        put_ssh_bytes(out, trimmed);
    }
}

fn aes256_cbc_decrypt_nopad(
    key: &[u8; 32],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PpkError> {
    if ciphertext.is_empty() || (ciphertext.len() & 15) != 0 {
        return Err(PpkError::InvalidFormat(
            "Invalid AES-encrypted PPK private key length".to_string(),
        ));
    }
    let cipher = Aes256::new_from_slice(key).expect("32-byte AES key");
    let mut out = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
    let mut prev = *iv;
    for chunk in ciphertext.chunks_exact(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        for (&dec_byte, &prev_byte) in block.iter().zip(prev.iter()) {
            out.push(dec_byte ^ prev_byte);
        }
        prev.copy_from_slice(chunk);
        block.zeroize();
    }
    prev.zeroize();
    Ok(out)
}

fn aes256_ctr_apply(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
    let cipher = Aes256::new_from_slice(key).expect("32-byte AES key");
    let mut counter = u128::from_be_bytes(*iv);
    for chunk in data.chunks_mut(16) {
        let mut block = GenericArray::from(counter.to_be_bytes());
        cipher.encrypt_block(&mut block);
        for (dst, &ks) in chunk.iter_mut().zip(block.iter()) {
            *dst ^= ks;
        }
        block.zeroize();
        counter = counter.wrapping_add(1);
    }
}

pub fn decrypt_and_verify_ppk(
    ppk: &ParsedPpk,
    passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>, PpkError> {
    let mut key_material = Zeroizing::new(vec![0u8; 80]);
    let plain = if ppk.encryption == "none" {
        ppk.private_blob.clone()
    } else if ppk.version == 2 {
        let mut derived = Zeroizing::new(Vec::with_capacity(40));
        for counter in 0u32..2u32 {
            let mut hasher = Sha1::new();
            hasher.update(counter.to_be_bytes());
            hasher.update(passphrase.as_bytes());
            let digest: [u8; 20] = hasher.finalize().into();
            derived.extend_from_slice(&digest);
        }
        let aes_key: &[u8; 32] = derived[..32].try_into().expect("32 bytes");
        let zero_iv = [0u8; 16];
        aes256_cbc_decrypt_nopad(aes_key, &zero_iv, &ppk.private_blob)?
    } else {
        let alg = match ppk.argon_type.as_str() {
            "Argon2d" => Algorithm::Argon2d,
            "Argon2i" => Algorithm::Argon2i,
            "Argon2id" => Algorithm::Argon2id,
            other => {
                return Err(PpkError::InvalidFormat(format!(
                    "Unsupported Argon2 variant: {other}"
                )));
            }
        };
        let params = Params::new(ppk.memory_kib, ppk.passes, ppk.parallelism, Some(80))
            .map_err(|_| PpkError::UnsafeArgon2Parameters)?;
        Argon2::new(alg, Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), &ppk.salt, &mut key_material)
            .map_err(|_| PpkError::InvalidFormat("PPK v3 Argon2 derivation failed".to_string()))?;
        let aes_key: &[u8; 32] = key_material[..32].try_into().expect("32 bytes");
        let iv: &[u8; 16] = key_material[32..48].try_into().expect("16 bytes");
        aes256_cbc_decrypt_nopad(aes_key, iv, &ppk.private_blob)?
    };

    let mut mac_data = Zeroizing::new(Vec::new());
    put_ssh_bytes(&mut mac_data, ppk.algorithm.as_bytes());
    put_ssh_bytes(&mut mac_data, ppk.encryption.as_bytes());
    put_ssh_bytes(&mut mac_data, ppk.comment.as_bytes());
    put_ssh_bytes(&mut mac_data, &ppk.public_blob);
    put_ssh_bytes(&mut mac_data, &plain);

    let mac_ok = if ppk.version == 2 {
        let mac_key: Zeroizing<Vec<u8>> = if ppk.encryption == "aes256-cbc" {
            let mut h = Sha1::new();
            h.update(PPK_MAC_LABEL);
            h.update(passphrase.as_bytes());
            let d: [u8; 20] = h.finalize().into();
            Zeroizing::new(d.to_vec())
        } else {
            Zeroizing::new(PPK_MAC_LABEL.to_vec())
        };
        let mut mac = HmacSha1::new_from_slice(&mac_key).expect("HMAC key");
        mac.update(&mac_data);
        let actual: [u8; 20] = mac.finalize().into_bytes().into();
        bool::from(actual.ct_eq(ppk.mac.as_slice()))
    } else {
        let mac_key: &[u8] = if ppk.encryption == "aes256-cbc" {
            &key_material[48..80]
        } else {
            PPK_MAC_LABEL
        };
        let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC key");
        mac.update(&mac_data);
        let actual: [u8; 32] = mac.finalize().into_bytes().into();
        bool::from(actual.ct_eq(ppk.mac.as_slice()))
    };

    if !mac_ok {
        return Err(PpkError::IntegrityCheckFailed);
    }
    Ok(plain)
}

fn private_tail_ok(ppk: &ParsedPpk, consumed: usize, total: usize) -> bool {
    if consumed == total {
        return true;
    }
    ppk.encryption == "aes256-cbc" && consumed < total && (total - consumed) <= 15
}

fn clean_comment(comment: &str) -> String {
    comment
        .chars()
        .map(|c| if matches!(c, '\n' | '\r' | '\0') { ' ' } else { c })
        .collect()
}

fn left_pad_scalar(be_bytes: &[u8], target_len: usize) -> Option<Zeroizing<Vec<u8>>> {
    if be_bytes.len() > target_len {
        return None;
    }
    let mut padded = Zeroizing::new(vec![0u8; target_len]);
    let start = target_len - be_bytes.len();
    padded[start..].copy_from_slice(be_bytes);
    Some(padded)
}

/// Validates mathematical consistency of `ppk` + decrypted `plain` and builds
/// the inner keypair payload of an `openssh-key-v1` private section.
fn build_validated_openssh_keypair_payload(
    ppk: &ParsedPpk,
    plain: &[u8],
) -> Result<Zeroizing<Vec<u8>>, PpkError> {
    let mut pub_pos = 0usize;
    let alg_bytes = get_ssh_bytes(&ppk.public_blob, &mut pub_pos)
        .ok_or(PpkError::InvalidKeyComponents)?;
    if alg_bytes != ppk.algorithm.as_bytes() {
        return Err(PpkError::InvalidKeyComponents);
    }

    let mut priv_pos = 0usize;
    let mut payload = Zeroizing::new(Vec::new());
    let cleaned_comment = clean_comment(&ppk.comment);

    match ppk.algorithm.as_str() {
        "ssh-ed25519" => {
            let pub_key = get_ssh_bytes(&ppk.public_blob, &mut pub_pos)
                .ok_or(PpkError::InvalidKeyComponents)?;
            if pub_pos != ppk.public_blob.len() || pub_key.len() != 32 {
                return Err(PpkError::InvalidKeyComponents);
            }
            let raw_secret =
                get_ssh_bytes(plain, &mut priv_pos).ok_or(PpkError::InvalidKeyComponents)?;
            if !private_tail_ok(ppk, priv_pos, plain.len()) {
                return Err(PpkError::InvalidKeyComponents);
            }
            let seed_slice: &[u8] = if raw_secret.len() == 33 && raw_secret[0] == 0 {
                &raw_secret[1..]
            } else if raw_secret.len() == 64 && bool::from(raw_secret[32..].ct_eq(pub_key)) {
                &raw_secret[..32]
            } else if raw_secret.len() == 32 {
                raw_secret
            } else {
                return Err(PpkError::InvalidKeyComponents);
            };
            let seed_arr: &[u8; 32] = seed_slice.try_into().expect("32-byte Ed25519 seed");
            let signing = Ed25519SigningKey::from_bytes(seed_arr);
            let derived_pub = signing.verifying_key().to_bytes();
            if !bool::from(derived_pub.ct_eq(pub_key)) {
                return Err(PpkError::InvalidKeyComponents);
            }

            let mut seed_and_pub = Zeroizing::new(Vec::with_capacity(64));
            seed_and_pub.extend_from_slice(seed_arr);
            seed_and_pub.extend_from_slice(pub_key);

            put_ssh_bytes(&mut payload, b"ssh-ed25519");
            put_ssh_bytes(&mut payload, pub_key);
            put_ssh_bytes(&mut payload, &seed_and_pub);
            put_ssh_bytes(&mut payload, cleaned_comment.as_bytes());
        }
        "ssh-rsa" => {
            let e_bytes = get_non_negative_mpint(&ppk.public_blob, &mut pub_pos)
                .ok_or(PpkError::InvalidKeyComponents)?;
            let n_bytes = get_non_negative_mpint(&ppk.public_blob, &mut pub_pos)
                .ok_or(PpkError::InvalidKeyComponents)?;
            if pub_pos != ppk.public_blob.len() {
                return Err(PpkError::InvalidKeyComponents);
            }
            let d_bytes =
                get_non_negative_mpint(plain, &mut priv_pos).ok_or(PpkError::InvalidKeyComponents)?;
            let p_bytes =
                get_non_negative_mpint(plain, &mut priv_pos).ok_or(PpkError::InvalidKeyComponents)?;
            let q_bytes =
                get_non_negative_mpint(plain, &mut priv_pos).ok_or(PpkError::InvalidKeyComponents)?;
            let iqmp_bytes =
                get_non_negative_mpint(plain, &mut priv_pos).ok_or(PpkError::InvalidKeyComponents)?;
            if !private_tail_ok(ppk, priv_pos, plain.len()) {
                return Err(PpkError::InvalidKeyComponents);
            }

            let e = BigUint::from_bytes_be(e_bytes);
            let n = BigUint::from_bytes_be(n_bytes);
            let d = BigUint::from_bytes_be(d_bytes);
            let p = BigUint::from_bytes_be(p_bytes);
            let q = BigUint::from_bytes_be(q_bytes);
            let iqmp = BigUint::from_bytes_be(iqmp_bytes);
            let one = BigUint::from(1u32);
            let two = BigUint::from(2u32);
            if e <= one
                || p <= two
                || q <= two
                || (&p * &q) != n
                || ((&iqmp * &q) % &p) != one
                || two.modpow(&e, &n).modpow(&d, &n) != two
            {
                return Err(PpkError::InvalidKeyComponents);
            }

            put_ssh_bytes(&mut payload, b"ssh-rsa");
            put_mpint_positive(&mut payload, n_bytes);
            put_mpint_positive(&mut payload, e_bytes);
            put_mpint_positive(&mut payload, d_bytes);
            put_mpint_positive(&mut payload, iqmp_bytes);
            put_mpint_positive(&mut payload, p_bytes);
            put_mpint_positive(&mut payload, q_bytes);
            put_ssh_bytes(&mut payload, cleaned_comment.as_bytes());
        }
        "ssh-dss" => {
            let p_bytes = get_non_negative_mpint(&ppk.public_blob, &mut pub_pos)
                .ok_or(PpkError::InvalidKeyComponents)?;
            let q_bytes = get_non_negative_mpint(&ppk.public_blob, &mut pub_pos)
                .ok_or(PpkError::InvalidKeyComponents)?;
            let g_bytes = get_non_negative_mpint(&ppk.public_blob, &mut pub_pos)
                .ok_or(PpkError::InvalidKeyComponents)?;
            let y_bytes = get_non_negative_mpint(&ppk.public_blob, &mut pub_pos)
                .ok_or(PpkError::InvalidKeyComponents)?;
            if pub_pos != ppk.public_blob.len() {
                return Err(PpkError::InvalidKeyComponents);
            }
            let x_bytes =
                get_non_negative_mpint(plain, &mut priv_pos).ok_or(PpkError::InvalidKeyComponents)?;
            if !private_tail_ok(ppk, priv_pos, plain.len()) {
                return Err(PpkError::InvalidKeyComponents);
            }

            let p = BigUint::from_bytes_be(p_bytes);
            let q = BigUint::from_bytes_be(q_bytes);
            let g = BigUint::from_bytes_be(g_bytes);
            let y = BigUint::from_bytes_be(y_bytes);
            let x = BigUint::from_bytes_be(x_bytes);
            let one = BigUint::from(1u32);
            let zero = BigUint::from(0u32);
            if q <= one || x == zero || x >= q || ((&p - &one) % &q) != zero || g.modpow(&x, &p) != y
            {
                return Err(PpkError::InvalidKeyComponents);
            }

            put_ssh_bytes(&mut payload, b"ssh-dss");
            put_mpint_positive(&mut payload, p_bytes);
            put_mpint_positive(&mut payload, q_bytes);
            put_mpint_positive(&mut payload, g_bytes);
            put_mpint_positive(&mut payload, y_bytes);
            put_mpint_positive(&mut payload, x_bytes);
            put_ssh_bytes(&mut payload, cleaned_comment.as_bytes());
        }
        alg if alg.starts_with("ecdsa-sha2-") => {
            let curve_bytes = get_ssh_bytes(&ppk.public_blob, &mut pub_pos)
                .ok_or(PpkError::InvalidKeyComponents)?;
            let point_bytes = get_ssh_bytes(&ppk.public_blob, &mut pub_pos)
                .ok_or(PpkError::InvalidKeyComponents)?;
            if pub_pos != ppk.public_blob.len() {
                return Err(PpkError::InvalidKeyComponents);
            }
            let curve = std::str::from_utf8(curve_bytes)
                .map_err(|_| PpkError::InvalidKeyComponents)?;
            if alg != format!("ecdsa-sha2-{curve}") {
                return Err(PpkError::InvalidKeyComponents);
            }
            let scalar_be =
                get_non_negative_mpint(plain, &mut priv_pos).ok_or(PpkError::InvalidKeyComponents)?;
            if !private_tail_ok(ppk, priv_pos, plain.len()) {
                return Err(PpkError::InvalidKeyComponents);
            }

            let valid = match curve {
                "nistp256" => left_pad_scalar(scalar_be, 32)
                    .and_then(|s| p256::SecretKey::from_slice(&s).ok())
                    .zip(p256::PublicKey::from_sec1_bytes(point_bytes).ok())
                    .map(|(sk, pk)| sk.public_key() == pk)
                    .unwrap_or(false),
                "nistp384" => left_pad_scalar(scalar_be, 48)
                    .and_then(|s| p384::SecretKey::from_slice(&s).ok())
                    .zip(p384::PublicKey::from_sec1_bytes(point_bytes).ok())
                    .map(|(sk, pk)| sk.public_key() == pk)
                    .unwrap_or(false),
                "nistp521" => left_pad_scalar(scalar_be, 66)
                    .and_then(|s| p521::SecretKey::from_slice(&s).ok())
                    .zip(p521::PublicKey::from_sec1_bytes(point_bytes).ok())
                    .map(|(sk, pk)| sk.public_key() == pk)
                    .unwrap_or(false),
                _ => return Err(PpkError::UnsupportedAlgorithm(ppk.algorithm.clone())),
            };
            if !valid {
                return Err(PpkError::InvalidKeyComponents);
            }

            put_ssh_bytes(&mut payload, alg.as_bytes());
            put_ssh_bytes(&mut payload, curve_bytes);
            put_ssh_bytes(&mut payload, point_bytes);
            put_mpint_positive(&mut payload, scalar_be);
            put_ssh_bytes(&mut payload, cleaned_comment.as_bytes());
        }
        other => return Err(PpkError::UnsupportedAlgorithm(other.to_string())),
    }

    Ok(payload)
}

/// Exports the verified OpenSSH `authorized_keys` public line from `.ppk` text.
pub fn ppk_authorized_keys_line(ppk_text: &str, passphrase: &str) -> Result<String, PpkError> {
    let ppk = parse_ppk_str(ppk_text)?;
    let plain = decrypt_and_verify_ppk(&ppk, passphrase)?;
    let _ = build_validated_openssh_keypair_payload(&ppk, &plain)?;

    let mut line = format!("{} {}", ppk.algorithm, BASE64.encode(&ppk.public_blob));
    let comment = clean_comment(&ppk.comment);
    if !comment.is_empty() {
        line.push(' ');
        line.push_str(&comment);
    }
    Ok(line)
}

/// Converts `.ppk` text into an OpenSSH `-----BEGIN OPENSSH PRIVATE KEY-----`
/// PEM string. When `output_passphrase` is `Some(non_empty)`, encrypts the
/// private section with `aes256-ctr` + `bcrypt` KDF.
pub fn ppk_to_openssh_pem(
    ppk_text: &str,
    input_passphrase: &str,
    output_passphrase: Option<&str>,
) -> Result<Zeroizing<String>, PpkError> {
    let ppk = parse_ppk_str(ppk_text)?;
    let plain = decrypt_and_verify_ppk(&ppk, input_passphrase)?;
    let inner_payload = build_validated_openssh_keypair_payload(&ppk, &plain)?;

    let encrypt_pw = output_passphrase.filter(|s| !s.is_empty());
    let block_size = if encrypt_pw.is_some() { 16usize } else { 8usize };

    let mut rng = rand::thread_rng();
    let check_int = rng.next_u32();
    let mut priv_section = Zeroizing::new(Vec::with_capacity(inner_payload.len() + 24));
    put_u32(&mut priv_section, check_int);
    put_u32(&mut priv_section, check_int);
    priv_section.extend_from_slice(&inner_payload);

    let pad_needed = (block_size - (priv_section.len() % block_size)) % block_size;
    for pad_byte in 1..=pad_needed {
        priv_section.push(pad_byte as u8);
    }

    let (cipher_name, kdf_name, kdf_opts) = if let Some(pw) = encrypt_pw {
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let mut key_iv = Zeroizing::new([0u8; 48]);
        bcrypt_pbkdf::bcrypt_pbkdf(pw.as_bytes(), &salt, BCRYPT_ROUNDS, &mut *key_iv)
            .map_err(|_| PpkError::InvalidFormat("OpenSSH bcrypt-pbkdf failed".to_string()))?;
        let aes_key: &[u8; 32] = key_iv[..32].try_into().expect("32-byte key");
        let iv: &[u8; 16] = key_iv[32..48].try_into().expect("16-byte iv");
        aes256_ctr_apply(aes_key, iv, &mut priv_section);

        let mut opts = Vec::with_capacity(24);
        put_ssh_bytes(&mut opts, &salt);
        put_u32(&mut opts, BCRYPT_ROUNDS);
        ("aes256-ctr", "bcrypt", opts)
    } else {
        ("none", "none", Vec::new())
    };

    let mut wire = Zeroizing::new(Vec::new());
    wire.extend_from_slice(OPENSSH_MAGIC);
    put_ssh_bytes(&mut wire, cipher_name.as_bytes());
    put_ssh_bytes(&mut wire, kdf_name.as_bytes());
    put_ssh_bytes(&mut wire, &kdf_opts);
    put_u32(&mut wire, 1);
    put_ssh_bytes(&mut wire, &ppk.public_blob);
    put_ssh_bytes(&mut wire, &priv_section);

    let encoded = Zeroizing::new(BASE64.encode(&wire));
    let mut pem = Zeroizing::new(String::with_capacity(encoded.len() + 96));
    pem.push_str("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).expect("ASCII base64"));
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digests::hex_encode;

    const ED25519_V3_NONE: &str = "\
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: ed25519-v3
Public-Lines: 1
AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk
Key-Derivation: none
Private-Lines: 1
AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g
Private-MAC: 811d91c584905245d2ff3387fce282ae4b35c5af0e43257969d458b07031b4ff
";

    const ED25519_V2_ENCRYPTED: &str = "\
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: aes256-cbc
Comment: ed25519-v2
Public-Lines: 1
AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk
Private-Lines: 1
Y9f+qSB5FZfq2THk/c3+YDp7WUUEInGl7poCWM0H3hZSKKSrhvXEZOFcav7qc/bk
Private-MAC: 1459a716b2ebdea871aa101e3a6fe0801798df2f
";

    #[test]
    fn ppk_v3_unencrypted_and_v2_encrypted_vectors_verify_and_export() {
        let auth_v3 = ppk_authorized_keys_line(ED25519_V3_NONE, "").expect("v3 authorized_keys");
        assert_eq!(
            auth_v3,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk ed25519-v3"
        );

        assert_eq!(
            ppk_authorized_keys_line(ED25519_V2_ENCRYPTED, "wrong-pass"),
            Err(PpkError::IntegrityCheckFailed)
        );
        let pem_v2 =
            ppk_to_openssh_pem(ED25519_V2_ENCRYPTED, "secret-ppk", Some("secret-ppk")).expect("v2 pem");
        assert!(pem_v2.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
        assert!(pem_v2.ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
    }

    #[test]
    fn ppk_v3_argon2id_encrypted_round_trip_and_unsafe_memory_guard() {
        let base_ppk = parse_ppk_str(ED25519_V3_NONE).unwrap();
        let salt = [0x42u8; 16];
        let mut km = [0u8; 80];
        let params = Params::new(64, 2, 1, Some(80)).unwrap();
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"argon-pass", &salt, &mut km)
            .unwrap();

        let mut padded_plain = base_ppk.private_blob.to_vec();
        while (padded_plain.len() & 15) != 0 {
            padded_plain.push(0);
        }
        // Encrypt single CBC blocks with key=km[..32], iv=km[32..48]
        let cipher = Aes256::new_from_slice(&km[..32]).unwrap();
        let mut prev: [u8; 16] = km[32..48].try_into().unwrap();
        let mut enc_priv = Vec::new();
        for chunk in padded_plain.chunks_exact(16) {
            let mut xored = [0u8; 16];
            for ((dst, &p), &iv_b) in xored.iter_mut().zip(chunk.iter()).zip(prev.iter()) {
                *dst = p ^ iv_b;
            }
            let mut blk = GenericArray::from(xored);
            cipher.encrypt_block(&mut blk);
            prev.copy_from_slice(&blk);
            enc_priv.extend_from_slice(&blk);
        }

        let mut mac_data = Vec::new();
        put_ssh_bytes(&mut mac_data, b"ssh-ed25519");
        put_ssh_bytes(&mut mac_data, b"aes256-cbc");
        put_ssh_bytes(&mut mac_data, b"argon-v3");
        put_ssh_bytes(&mut mac_data, &base_ppk.public_blob);
        put_ssh_bytes(&mut mac_data, &padded_plain);
        let mut mac = HmacSha256::new_from_slice(&km[48..80]).unwrap();
        mac.update(&mac_data);
        let mac_hex = hex_encode(&mac.finalize().into_bytes());

        let v3_enc = format!(
            "PuTTY-User-Key-File-3: ssh-ed25519\n\
             Encryption: aes256-cbc\n\
             Comment: argon-v3\n\
             Public-Lines: 1\n\
             {}\n\
             Key-Derivation: Argon2id\n\
             Argon2-Memory: 64\n\
             Argon2-Passes: 2\n\
             Argon2-Parallelism: 1\n\
             Argon2-Salt: {}\n\
             Private-Lines: 1\n\
             {}\n\
             Private-MAC: {}\n",
            BASE64.encode(&base_ppk.public_blob),
            hex_encode(&salt),
            BASE64.encode(&enc_priv),
            mac_hex
        );

        let pem = ppk_to_openssh_pem(&v3_enc, "argon-pass", None).expect("decrypt Argon2id PPK");
        assert!(pem.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert_eq!(
            ppk_to_openssh_pem(&v3_enc, "bad", None),
            Err(PpkError::IntegrityCheckFailed)
        );

        // Excessive Argon2-Memory header (> 256 MiB) rejected before allocation
        let unsafe_ppk = v3_enc.replace("Argon2-Memory: 64", "Argon2-Memory: 4194304");
        assert_eq!(
            parse_ppk_str(&unsafe_ppk).unwrap_err(),
            PpkError::UnsafeArgon2Parameters
        );
    }
}
