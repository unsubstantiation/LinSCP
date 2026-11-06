//! Password-encrypted credential interchange designed for a future OfflineOTP importer.
//!
//! LinSCP uses a versioned Argon2id/AES-256-GCM envelope around a compact JSON
//! array of `SSH_KEY` and `PASSWORD` entries. The entry payloads retain the
//! OfflineOTP key and `PWD1` login conventions; OfflineOTP will add support for
//! this stronger envelope on its side. LinSCP-specific fields are ordinary
//! additional login columns.

use std::collections::BTreeMap;
use std::fmt;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use data_encoding::BASE32;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const FILE_LIMIT: usize = 16 * 1024 * 1024;
const ENTRY_LIMIT: usize = 2_000;
const KEY_TEXT_LIMIT: usize = 32 * 1024;
const PASSWORD_MATERIAL_LIMIT: usize = 4 * 1024 * 1024;
const PASSWORD_FIELD_LIMIT: usize = 64 * 1024;
const PASSWORD_COLUMN_LIMIT: usize = 64;
const FILE_MAGIC: &[u8; 8] = b"LSCPVLT2";
const ARGON2_MEMORY_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_LANES: u32 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const GCM_TAG_BYTES: usize = 16;
const PWD1_MAGIC: [u8; 4] = *b"PWD1";

/// A credential item represented using the OfflineOTP entry payload conventions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialEntry {
    /// A login record, encoded as an OfflineOTP `PASSWORD` entry.
    Login(LoginRecord),
    /// A public/private key pair with optional SSH connection details.
    SshKey(SshKeyRecord),
}

/// URL/login fields plus arbitrary `linscp_*` columns preserved by OfflineOTP.
#[derive(Clone, PartialEq, Eq)]
pub struct LoginRecord {
    pub label: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub metadata: BTreeMap<String, String>,
}

/// OfflineOTP SSH key payload. Each key can be absent, but not both.
#[derive(Clone, PartialEq, Eq)]
pub struct SshKeyRecord {
    pub label: String,
    pub public_key: String,
    pub private_key: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// SSH account password (not a private-key passphrase).
    pub password: String,
}

impl fmt::Debug for LoginRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginRecord")
            .field("label", &self.label)
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("metadata_columns", &self.metadata.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl fmt::Debug for SshKeyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SshKeyRecord")
            .field("label", &self.label)
            .field("public_key", &"<redacted>")
            .field("private_key", &"<redacted>")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Result of opening a vault. Non-credential OfflineOTP entries are ignored and counted,
/// allowing a user's broader OTP vault to be imported without losing unrelated entries there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedCredentialVault {
    pub entries: Vec<CredentialEntry>,
    pub ignored_entries: usize,
}

#[derive(Serialize, Deserialize)]
struct BackupEntry {
    secret: String,
    issuer: String,
    label: String,
    digits: u8,
    #[serde(rename = "type")]
    kind: String,
    algorithm: String,
    thumbnail: String,
    last_used: u64,
    used_frequency: u64,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_password: Option<String>,
}

impl BackupEntry {
    fn new(kind: &str, label: String, secret: &[u8]) -> Self {
        Self {
            secret: BASE32.encode(secret),
            issuer: String::new(),
            label,
            digits: 6,
            kind: kind.to_string(),
            algorithm: "SHA1".to_string(),
            thumbnail: String::new(),
            last_used: 0,
            used_frequency: 0,
            tags: Vec::new(),
            ssh_host: None,
            ssh_port: None,
            ssh_username: None,
            ssh_password: None,
        }
    }
}

/// Encrypts credential entries in LinSCP's versioned Argon2id vault format.
pub fn seal(entries: &[CredentialEntry], password: &str) -> Result<Vec<u8>, String> {
    if password.is_empty() || password.encode_utf16().count() > 1_024 {
        return Err("Backup password must contain 1 to 1024 characters.".to_string());
    }
    if entries.is_empty() {
        return Err("There are no credentials to export.".to_string());
    }
    if entries.len() > ENTRY_LIMIT {
        return Err(format!("The vault exceeds OfflineOTP's {ENTRY_LIMIT}-entry limit."));
    }

    let mut encoded_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        encoded_entries.push(encode_entry(entry)?);
    }
    let mut plaintext = Zeroizing::new(
        serde_json::to_vec(&encoded_entries).map_err(|e| format!("Cannot encode vault: {e}"))?,
    );
    if plaintext.len() > FILE_LIMIT {
        plaintext.zeroize();
        return Err("The credential vault exceeds OfflineOTP's 16 MiB backup limit.".to_string());
    }

    let mut rng = rand::thread_rng();
    let mut salt = [0u8; SALT_BYTES];
    let mut nonce = [0u8; NONCE_BYTES];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let key = derive_backup_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| "Cannot initialize AES-GCM.".to_string())?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload { msg: plaintext.as_slice(), aad: FILE_MAGIC },
        )
        .map_err(|_| "Cannot encrypt the credential vault.".to_string())?;

    let total = FILE_MAGIC.len()
        .checked_add(SALT_BYTES + NONCE_BYTES)
        .and_then(|n| n.checked_add(ciphertext.len()))
        .ok_or_else(|| "Encrypted vault size overflow.".to_string())?;
    if total > FILE_LIMIT {
        return Err("The encrypted vault exceeds OfflineOTP's 16 MiB backup limit.".to_string());
    }
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a LinSCP Argon2id credential vault and extracts credential entries.
/// Known OTP/note/email entries are ignored; malformed credential entries reject the whole import.
pub fn open(bytes: &[u8], password: &str) -> Result<ImportedCredentialVault, String> {
    const HEADER_LEN: usize = FILE_MAGIC.len() + SALT_BYTES + NONCE_BYTES;
    if bytes.len() < HEADER_LEN + GCM_TAG_BYTES {
        return Err("The LinSCP credential vault is truncated.".to_string());
    }
    if bytes.len() > FILE_LIMIT {
        return Err("The LinSCP credential vault exceeds 16 MiB.".to_string());
    }
    if !bytes.starts_with(FILE_MAGIC) {
        return Err("Unsupported LinSCP credential-vault format or version.".to_string());
    }
    if password.is_empty() || password.encode_utf16().count() > 1_024 {
        return Err("Backup password must contain 1 to 1024 characters.".to_string());
    }
    let salt_start = FILE_MAGIC.len();
    let nonce_start = salt_start + SALT_BYTES;
    let ciphertext_start = nonce_start + NONCE_BYTES;
    let salt = &bytes[salt_start..nonce_start];
    let nonce = &bytes[nonce_start..ciphertext_start];
    let key = derive_backup_key(password, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| "Cannot initialize AES-GCM.".to_string())?;
    let mut plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                aes_gcm::aead::Payload { msg: &bytes[ciphertext_start..], aad: FILE_MAGIC },
            )
            .map_err(|_| "Incorrect backup password or damaged LinSCP credential vault.".to_string())?,
    );
    validate_json_depth(&plaintext)?;
    let value: serde_json::Value = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Invalid credential-vault JSON: {e}"))?;
    plaintext.zeroize();
    let rows = value
        .as_array()
        .ok_or_else(|| "Credential vault must contain a JSON array.".to_string())?;
    if rows.is_empty() || rows.len() > ENTRY_LIMIT {
        return Err(format!("Credential vault must contain 1 to {ENTRY_LIMIT} entries."));
    }

    let mut entries = Vec::new();
    let mut ignored_entries = 0;
    for (index, row) in rows.iter().enumerate() {
        let Some(kind) = row.get("type").and_then(serde_json::Value::as_str) else {
            ignored_entries += 1;
            continue;
        };
        match kind {
            "SSH_KEY" => entries.push(decode_ssh_entry(row, index)?),
            "PASSWORD" => entries.push(decode_login_entry(row, index)?),
            // OfflineOTP carries OTPs, notes, archives, email entries, etc. They are not LinSCP
            // credentials and should remain in the OfflineOTP vault rather than be imported here.
            "TOTP" | "HOTP" | "MOTP" | "STEAM" | "NOTE" | "PASSWORD_ARCHIVE" | "EMAIL" => {
                ignored_entries += 1;
            }
            _ => ignored_entries += 1,
        }
    }
    if entries.is_empty() {
        return Err("The credential vault contains no SSH keys or login entries.".to_string());
    }
    Ok(ImportedCredentialVault { entries, ignored_entries })
}

fn derive_backup_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_LANES, Some(32))
        .map_err(|_| "Invalid Argon2id parameters.".to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|_| "Cannot derive the credential-vault encryption key.".to_string())?;
    Ok(key)
}

fn encode_entry(entry: &CredentialEntry) -> Result<BackupEntry, String> {
    match entry {
        CredentialEntry::SshKey(key) => {
            validate_label(&key.label)?;
            let secret = encode_ssh_key_material(&key.public_key, &key.private_key)?;
            let mut row = BackupEntry::new("SSH_KEY", key.label.clone(), &secret);
            if !key.host.is_empty() {
                validate_ssh_text(&key.host, 255, "SSH host", true)?;
                row.ssh_host = Some(key.host.clone());
            }
            if key.port != 0 {
                row.ssh_port = Some(key.port);
            }
            if !key.username.is_empty() {
                validate_ssh_text(&key.username, 128, "SSH username", true)?;
                row.ssh_username = Some(key.username.clone());
            }
            if !key.password.is_empty() {
                validate_ssh_text(&key.password, 256, "SSH password", false)?;
                row.ssh_password = Some(key.password.clone());
            }
            Ok(row)
        }
        CredentialEntry::Login(login) => {
            validate_label(&login.label)?;
            validate_password_text(&login.url, "URL")?;
            validate_password_text(&login.username, "Username")?;
            validate_password_text(&login.password, "Password")?;
            let mut fields = vec![
                ("url".to_string(), login.url.clone()),
                ("username".to_string(), login.username.clone()),
                ("password".to_string(), login.password.clone()),
            ];
            for (key, value) in &login.metadata {
                let key = key.trim();
                if !key.starts_with("linscp_") {
                    return Err("LinSCP credential metadata columns must start with linscp_.".to_string());
                }
                validate_password_text(key, "Metadata column")?;
                validate_password_text(value, "Metadata value")?;
                fields.push((key.to_string(), value.clone()));
            }
            let material = encode_password_material(&fields)?;
            Ok(BackupEntry::new("PASSWORD", login.label.clone(), &material))
        }
    }
}

fn decode_ssh_entry(row: &serde_json::Value, index: usize) -> Result<CredentialEntry, String> {
    let label = required_text(row, "label", index)?;
    validate_label(&label).map_err(|e| format!("Entry {}: {e}", index + 1))?;
    let secret = decode_secret(row, index, KEY_TEXT_LIMIT * 2 + 8)?;
    let (public_key, private_key) = decode_ssh_key_material(&secret)
        .map_err(|e| format!("Entry {} SSH key material: {e}", index + 1))?;
    let host = optional_text(row, "ssh_host", index)?.unwrap_or_default();
    let username = optional_text(row, "ssh_username", index)?.unwrap_or_default();
    let password = optional_text(row, "ssh_password", index)?.unwrap_or_default();
    let port = optional_u16(row, "ssh_port", index)?.unwrap_or(0);
    if !host.is_empty() {
        validate_ssh_text(&host, 255, "SSH host", true).map_err(|e| format!("Entry {}: {e}", index + 1))?;
    }
    if !username.is_empty() {
        validate_ssh_text(&username, 128, "SSH username", true).map_err(|e| format!("Entry {}: {e}", index + 1))?;
    }
    if !password.is_empty() {
        validate_ssh_text(&password, 256, "SSH password", false).map_err(|e| format!("Entry {}: {e}", index + 1))?;
    }
    Ok(CredentialEntry::SshKey(SshKeyRecord {
        label,
        public_key,
        private_key,
        host,
        port,
        username,
        password,
    }))
}

fn decode_login_entry(row: &serde_json::Value, index: usize) -> Result<CredentialEntry, String> {
    let label = required_text(row, "label", index)?;
    validate_label(&label).map_err(|e| format!("Entry {}: {e}", index + 1))?;
    let secret = decode_secret(row, index, PASSWORD_MATERIAL_LIMIT)?;
    let fields = decode_password_material(&secret)
        .map_err(|e| format!("Entry {} login data: {e}", index + 1))?;
    let mut values = BTreeMap::new();
    for (name, value) in fields {
        validate_password_text(&name, "Login field name")
            .map_err(|error| format!("Entry {}: {error}", index + 1))?;
        validate_password_text(&value, "Login field value")
            .map_err(|error| format!("Entry {}: {error}", index + 1))?;
        let normalized = name.trim().to_ascii_lowercase();
        if values.insert(normalized, value).is_some() {
            return Err(format!("Entry {} has duplicate login field names.", index + 1));
        }
    }
    let url = values.remove("url").ok_or_else(|| format!("Entry {} has no URL field.", index + 1))?;
    let username = values.remove("username").ok_or_else(|| format!("Entry {} has no username field.", index + 1))?;
    let password = values.remove("password").ok_or_else(|| format!("Entry {} has no password field.", index + 1))?;
    let metadata = values
        .into_iter()
        .filter(|(key, _)| key.starts_with("linscp_"))
        .collect();
    Ok(CredentialEntry::Login(LoginRecord { label, url, username, password, metadata }))
}

fn required_text(row: &serde_json::Value, field: &str, index: usize) -> Result<String, String> {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("Entry {} is missing text field '{field}'.", index + 1))
}

fn optional_text(row: &serde_json::Value, field: &str, index: usize) -> Result<Option<String>, String> {
    match row.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(format!("Entry {} has invalid '{field}'.", index + 1)),
    }
}

fn optional_u16(row: &serde_json::Value, field: &str, index: usize) -> Result<Option<u16>, String> {
    match row.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n > 0)
            .map(Some)
            .ok_or_else(|| format!("Entry {} has invalid '{field}'.", index + 1)),
    }
}

fn decode_secret(row: &serde_json::Value, index: usize, max_decoded: usize) -> Result<Vec<u8>, String> {
    let encoded = required_text(row, "secret", index)?;
    if encoded.len() > max_decoded.saturating_mul(2) {
        return Err(format!("Entry {} secret exceeds its size limit.", index + 1));
    }
    let normalized = encoded.trim().to_ascii_uppercase();
    let bytes = BASE32
        .decode(normalized.as_bytes())
        .map_err(|_| format!("Entry {} has invalid Base32 secret material.", index + 1))?;
    if bytes.len() > max_decoded || BASE32.encode(&bytes) != normalized {
        return Err(format!("Entry {} has non-canonical or oversized Base32 secret material.", index + 1));
    }
    Ok(bytes)
}

fn encode_ssh_key_material(public_key: &str, private_key: &str) -> Result<Vec<u8>, String> {
    if public_key.trim().is_empty() && private_key.trim().is_empty() {
        return Err("An SSH entry needs a public key, a private key, or both.".to_string());
    }
    validate_key_text(public_key, "Public key")?;
    validate_key_text(private_key, "Private key")?;
    let public = bounded_utf8(public_key, KEY_TEXT_LIMIT, "Public key")?;
    let private = bounded_utf8(private_key, KEY_TEXT_LIMIT, "Private key")?;
    let mut result = Vec::with_capacity(8 + public.len() + private.len());
    result.extend_from_slice(&(public.len() as u32).to_be_bytes());
    result.extend_from_slice(&public);
    result.extend_from_slice(&(private.len() as u32).to_be_bytes());
    result.extend_from_slice(&private);
    Ok(result)
}

fn decode_ssh_key_material(bytes: &[u8]) -> Result<(String, String), String> {
    if bytes.len() < 8 || bytes.len() > 2 * KEY_TEXT_LIMIT + 8 {
        return Err("invalid or oversized SSH key material".to_string());
    }
    let mut cursor = 0usize;
    let public = read_ssh_key_field(bytes, &mut cursor)?;
    let private = read_ssh_key_field(bytes, &mut cursor)?;
    validate_key_text(&public, "Public key")?;
    validate_key_text(&private, "Private key")?;
    if cursor != bytes.len() || (public.trim().is_empty() && private.trim().is_empty()) {
        return Err("trailing bytes or empty SSH key".to_string());
    }
    Ok((public, private))
}

fn read_ssh_key_field(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
    if bytes.len().saturating_sub(*cursor) < 4 {
        return Err("truncated SSH key field length".to_string());
    }
    let length = u32::from_be_bytes(bytes[*cursor..*cursor + 4].try_into().unwrap()) as usize;
    *cursor += 4;
    if length > KEY_TEXT_LIMIT || length > bytes.len().saturating_sub(*cursor) {
        return Err("invalid SSH key field length".to_string());
    }
    let value = std::str::from_utf8(&bytes[*cursor..*cursor + length])
        .map_err(|_| "SSH key is not valid UTF-8".to_string())?
        .to_string();
    *cursor += length;
    Ok(value)
}

fn encode_password_material(fields: &[(String, String)]) -> Result<Vec<u8>, String> {
    if fields.len() < 3 || fields.len() > PASSWORD_COLUMN_LIMIT {
        return Err("Invalid login metadata column count.".to_string());
    }
    let mut names = std::collections::HashSet::new();
    let mut result = Vec::new();
    result.extend_from_slice(&PWD1_MAGIC);
    result.extend_from_slice(&(fields.len() as u32).to_be_bytes());
    for (name, value) in fields {
        let normalized = name.trim().to_ascii_lowercase();
        if normalized.is_empty() || !names.insert(normalized) {
            return Err("Login field names must be non-empty and unique.".to_string());
        }
        let key = bounded_utf8(name, PASSWORD_FIELD_LIMIT, "Login field name")?;
        let value = bounded_utf8(value, PASSWORD_FIELD_LIMIT, "Login field value")?;
        result.extend_from_slice(&(key.len() as u32).to_be_bytes());
        result.extend_from_slice(&key);
        result.extend_from_slice(&(value.len() as u32).to_be_bytes());
        result.extend_from_slice(&value);
        if result.len() > PASSWORD_MATERIAL_LIMIT {
            return Err("Login entry exceeds OfflineOTP's 4 MiB limit.".to_string());
        }
    }
    Ok(result)
}

fn decode_password_material(bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    if bytes.len() < 8 || bytes.len() > PASSWORD_MATERIAL_LIMIT || bytes[..4] != PWD1_MAGIC[..] {
        return Err("invalid or oversized PWD1 payload".to_string());
    }
    let mut cursor = 4usize;
    let count = read_u32(bytes, &mut cursor)? as usize;
    if !(3..=PASSWORD_COLUMN_LIMIT).contains(&count) {
        return Err("invalid login field count".to_string());
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let name = read_text_field(bytes, &mut cursor)?;
        let value = read_text_field(bytes, &mut cursor)?;
        if name.trim().is_empty() || name.len() > PASSWORD_FIELD_LIMIT || value.len() > PASSWORD_FIELD_LIMIT {
            return Err("invalid login field size".to_string());
        }
        out.push((name, value));
    }
    if cursor != bytes.len() {
        return Err("trailing login payload data".to_string());
    }
    let names: std::collections::HashSet<_> = out.iter().map(|(n, _)| n.trim().to_ascii_lowercase()).collect();
    if names.len() != out.len() || !names.contains("url") || !names.contains("username") || !names.contains("password") {
        return Err("login payload needs unique url, username, and password fields".to_string());
    }
    Ok(out)
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, String> {
    if bytes.len().saturating_sub(*cursor) < 4 {
        return Err("truncated field length".to_string());
    }
    let value = u32::from_be_bytes(bytes[*cursor..*cursor + 4].try_into().unwrap());
    *cursor += 4;
    Ok(value)
}

fn read_text_field(bytes: &[u8], cursor: &mut usize) -> Result<String, String> {
    let length = read_u32(bytes, cursor)? as usize;
    if length > PASSWORD_FIELD_LIMIT || length > bytes.len().saturating_sub(*cursor) {
        return Err("invalid field length".to_string());
    }
    let text = std::str::from_utf8(&bytes[*cursor..*cursor + length])
        .map_err(|_| "login field is not valid UTF-8".to_string())?
        .to_string();
    *cursor += length;
    Ok(text)
}

fn validate_json_depth(bytes: &[u8]) -> Result<(), String> {
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => quoted = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > 32 {
                    return Err("OfflineOTP JSON nesting exceeds 32 levels.".to_string());
                }
            }
            b']' | b'}' => {
                depth = depth.checked_sub(1).ok_or_else(|| "Invalid OfflineOTP JSON nesting.".to_string())?;
            }
            _ => {}
        }
    }
    if quoted || depth != 0 {
        return Err("Invalid OfflineOTP JSON nesting.".to_string());
    }
    Ok(())
}

fn validate_key_text(value: &str, label: &str) -> Result<(), String> {
    if value.chars().any(|character| {
        character.is_control() && !matches!(character, '\n' | '\r' | '\t')
    }) {
        return Err(format!("{label} contains unsupported control characters."));
    }
    Ok(())
}

fn bounded_utf8(value: &str, max: usize, label: &str) -> Result<Vec<u8>, String> {
    if value.len() > max {
        return Err(format!("{label} exceeds {max} bytes."));
    }
    Ok(value.as_bytes().to_vec())
}

fn validate_label(label: &str) -> Result<(), String> {
    if label.trim().is_empty() || label.chars().count() > 1024 {
        return Err("Credential label must contain 1 to 1024 characters.".to_string());
    }
    Ok(())
}

fn validate_password_text(value: &str, label: &str) -> Result<(), String> {
    if value.len() > PASSWORD_FIELD_LIMIT || value.chars().any(char::is_control) {
        return Err(format!("{label} exceeds OfflineOTP's text limits."));
    }
    Ok(())
}

fn validate_ssh_text(value: &str, max: usize, label: &str, token: bool) -> Result<(), String> {
    if value.len() > max
        || value.chars().any(|c| c.is_control() || (token && c.is_whitespace()))
    {
        return Err(format!("{label} is outside OfflineOTP's supported limits."));
    }
    Ok(())
}

/// Timestamped filename used by OfflineOTP, in UTC and with ASCII digits.
pub fn timestamped_filename(unix_seconds: u64) -> String {
    let days = (unix_seconds / 86_400) as i64;
    let seconds = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("otp_accounts_{year:04}-{month:02}-{day:02}_{hour:02}-{minute:02}-{second:02}.json.aes")
}

// Gregorian civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<CredentialEntry> {
        vec![
            CredentialEntry::SshKey(SshKeyRecord {
                label: "Production SSH".into(),
                public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest deploy@example".into(),
                private_key: "-----BEGIN OPENSSH PRIVATE KEY-----\nexample\n-----END OPENSSH PRIVATE KEY-----\n".into(),
                host: "sftp.example.test".into(),
                port: 2222,
                username: "deploy".into(),
                password: "account-secret".into(),
            }),
            CredentialEntry::Login(LoginRecord {
                label: "WebDAV staging".into(),
                url: "webdavs://dav.example.test:8443/releases".into(),
                username: "build".into(),
                password: " p a s s ".into(),
                metadata: BTreeMap::from([
                    ("linscp_session".into(), "staging/releases".into()),
                    ("linscp_protocol".into(), "webdavs".into()),
                ]),
            }),
        ]
    }

    #[test]
    fn credential_debug_output_redacts_passwords_and_key_material() {
        let debug = format!("{:?}", fixture());
        assert!(!debug.contains("account-secret"));
        assert!(!debug.contains(" p a s s "));
        assert!(!debug.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn round_trips_argon2id_vault_and_timestamped_filename() {
        let entries = fixture();
        let sealed = seal(&entries, "correct horse battery staple").unwrap();
        let restored = open(&sealed, "correct horse battery staple").unwrap();
        assert_eq!(restored.entries, entries);
        assert_eq!(restored.ignored_entries, 0);
        assert_eq!(timestamped_filename(0), "otp_accounts_1970-01-01_00-00-00.json.aes");
        assert_eq!(timestamped_filename(1_796_150_400), "otp_accounts_2026-12-01_18-40-00.json.aes");
    }

    #[test]
    fn rejects_wrong_password_tampering_and_unknown_format_versions() {
        let sealed = seal(&fixture(), "secret").unwrap();
        assert!(open(&sealed, "wrong").is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&tampered, "secret").is_err());
        assert!(open(&sealed[..20], "secret").is_err());
        let mut unknown_version = sealed;
        unknown_version[FILE_MAGIC.len() - 1] ^= 1;
        assert!(open(&unknown_version, "secret").unwrap_err().contains("format or version"));
    }

    #[test]
    fn consumes_only_credential_types_and_rejects_malformed_credential_material() {
        // Build an encrypted mixed document directly; non-credential entries should be ignored.
        let mut entries = fixture();
        entries.push(CredentialEntry::Login(LoginRecord {
            label: "Other password".into(),
            url: "https://example.test".into(),
            username: "u".into(),
            password: "p".into(),
            metadata: BTreeMap::new(),
        }));
        let doc = serde_json::to_vec(&entries.iter().map(encode_entry).collect::<Result<Vec<_>,_>>().unwrap()).unwrap();
        let opaque = serde_json::json!([{"type":"TOTP"}]);
        let mut parsed: serde_json::Value = serde_json::from_slice(&doc).unwrap();
        parsed.as_array_mut().unwrap().push(opaque[0].clone());
        let mut plaintext = serde_json::to_vec(&parsed).unwrap();
        let mut rng = rand::thread_rng();
        let mut salt = [0; SALT_BYTES];
        let mut nonce = [0; NONCE_BYTES];
        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);
        let key = derive_backup_key("secret", &salt).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&*key).unwrap();
        let encrypted = cipher.encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload { msg: plaintext.as_slice(), aad: FILE_MAGIC },
        ).unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(FILE_MAGIC);
        framed.extend_from_slice(&salt);
        framed.extend_from_slice(&nonce);
        framed.extend_from_slice(&encrypted);
        plaintext.zeroize();
        let result = open(&framed, "secret").unwrap();
        assert_eq!(result.entries.len(), 3);
        assert_eq!(result.ignored_entries, 1);

        let mut bad_row: serde_json::Value = serde_json::from_slice(&doc).unwrap();
        bad_row[0]["secret"] = serde_json::json!("not base32!");
        let mut plain = serde_json::to_vec(&bad_row).unwrap();
        rng.fill_bytes(&mut nonce);
        let encrypted = cipher.encrypt(
            Nonce::from_slice(&nonce),
            aes_gcm::aead::Payload { msg: plain.as_slice(), aad: FILE_MAGIC },
        ).unwrap();
        framed.truncate(0);
        framed.extend_from_slice(FILE_MAGIC);
        framed.extend_from_slice(&salt);
        framed.extend_from_slice(&nonce);
        framed.extend_from_slice(&encrypted);
        plain.zeroize();
        assert!(open(&framed, "secret").unwrap_err().contains("Base32"));
    }

    #[test]
    fn encodes_offlineotp_compatible_key_and_password_material() {
        let rows = fixture().iter().map(encode_entry).collect::<Result<Vec<_>, _>>().unwrap();
        let key_secret = BASE32.decode(rows[0].secret.as_bytes()).unwrap();
        assert_eq!(decode_ssh_key_material(&key_secret).unwrap().0, fixture_public());
        let password_secret = BASE32.decode(rows[1].secret.as_bytes()).unwrap();
        let fields = decode_password_material(&password_secret).unwrap();
        assert_eq!(fields[0], ("url".into(), "webdavs://dav.example.test:8443/releases".into()));
        assert_eq!(fields[3], ("linscp_protocol".into(), "webdavs".into()));
    }

    fn fixture_public() -> String {
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest deploy@example".into()
    }
}
