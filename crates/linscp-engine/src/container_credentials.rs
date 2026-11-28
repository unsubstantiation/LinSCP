//! Experimental session and key records inside an encrypted container.
//!
//! This is not wired into CommanderService. Do not use this provisional schema
//! as the application's active vault until all readers, key materialization,
//! backup/restore, and lock/unlock paths use the same transaction boundary.
use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use linscp_crypto::SessionMasterKey;
use linscp_platform::container_file::{ContainerFile, UnlockedContainer};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{session_store::SessionStore, vault_keys};

const MAX_KEYS: usize = 2000;
const MAX_KEY_BYTES: usize = 1024 * 1024;
const MAX_METADATA_BYTES: usize = 32 * 1024;
const MAX_TLS_BYTES: usize = 384 * 1024;
const PUBLIC_KEY_FIELDS: &[&str] = &["linscp_public_key_file", "linscp_tunnel_public_key_file"];
const TLS_FIELDS: &[&str] = &["ca_certificate_file", "tls_certificate_file", "certificate", "tls_certificate_key_file"];

/// A private key and its public metadata. The key bytes are base64 inside the
/// already encrypted container; they must never be saved as plaintext files.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRecord {
    id: String,
    private_b64: String,
    label: String,
    public_key: String,
}

impl Drop for KeyRecord {
    fn drop(&mut self) { self.private_b64.zeroize(); }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsRecord {
    id: String,
    data_b64: String,
}

impl Drop for TlsRecord {
    fn drop(&mut self) { self.data_b64.zeroize(); }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyRecord {
    id: String,
    public_key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    session_key_b64: String,
    sessions_ini: String,
    keys: Vec<KeyRecord>,
    #[serde(default)]
    tls: Vec<TlsRecord>,
    #[serde(default)]
    public_keys: Vec<PublicKeyRecord>,
}

impl Drop for Document {
    fn drop(&mut self) {
        self.session_key_b64.zeroize();
        self.sessions_ini.zeroize();
    }
}

impl Document {
    fn fresh() -> Self {
        let mut key = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *key);
        Self { version: 1, session_key_b64: BASE64.encode(&*key), sessions_ini: String::new(), keys: Vec::new(), tls: Vec::new(), public_keys: Vec::new() }
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        let document: Self = serde_json::from_slice(bytes).map_err(|e| format!("Invalid credential container: {e}"))?;
        document.validate()?;
        Ok(document)
    }

    fn encoded(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        self.validate()?;
        Ok(Zeroizing::new(serde_json::to_vec(self).map_err(|e| e.to_string())?))
    }

    fn master_bytes(&self) -> Result<Zeroizing<[u8; 32]>, String> {
        let raw = Zeroizing::new(BASE64.decode(&self.session_key_b64).map_err(|_| "Invalid session key encoding")?);
        let mut key = Zeroizing::new([0u8; 32]);
        if raw.len() != key.len() { return Err("Invalid session key length".into()); }
        key.copy_from_slice(&raw);
        Ok(key)
    }

    fn session_key(&self) -> Result<SessionMasterKey, String> {
        let raw = self.master_bytes()?;
        Ok(SessionMasterKey::from_array(*raw))
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != 1 { return Err("Unsupported credential container version".into()); }
        let key = self.session_key()?;
        let sessions = SessionStore::parse_ini(&self.sessions_ini, Some(&key))?;
        if sessions.sites().iter().any(|site| site.summary().has_unreadable_secret || site.setting_error.is_some()) {
            return Err("Credential container contains unreadable session data".into());
        }
        if self.keys.len() > MAX_KEYS { return Err("Too many container keys".into()); }
        let mut ids = BTreeSet::new();
        for record in &self.keys {
            if !vault_keys::valid_id(&record.id) || !ids.insert(record.id.to_ascii_lowercase()) {
                return Err("Invalid or duplicate container key ID".into());
            }
            if record.label.len() > 512 || record.public_key.len() > MAX_METADATA_BYTES {
                return Err("Container key metadata exceeds size limit".into());
            }
            // Reject oversized encoded values before decoding.
            if record.private_b64.len() > (MAX_KEY_BYTES + 2) / 3 * 4 {
                return Err("Container key exceeds size limit".into());
            }
            let private = Zeroizing::new(BASE64.decode(&record.private_b64).map_err(|_| "Invalid container key encoding")?);
            if private.is_empty() || private.len() > MAX_KEY_BYTES { return Err("Invalid container key size".into()); }
        }
        if self.tls.len() > MAX_KEYS || self.public_keys.len() > MAX_KEYS { return Err("Too many container materials".into()); }
        let mut tls_ids = BTreeSet::new();
        for record in &self.tls {
            if !vault_keys::valid_id(&record.id) || !tls_ids.insert(record.id.to_ascii_lowercase()) {
                return Err("Invalid or duplicate TLS ID".into());
            }
            if record.data_b64.len() > (MAX_TLS_BYTES + 2) / 3 * 4 { return Err("TLS material exceeds size limit".into()); }
            let data = Zeroizing::new(BASE64.decode(&record.data_b64).map_err(|_| "Invalid TLS encoding")?);
            if data.is_empty() || data.len() > MAX_TLS_BYTES { return Err("Invalid TLS material size".into()); }
        }
        let mut public_ids: BTreeSet<String> = self.keys.iter().filter(|key| !key.public_key.is_empty()).map(|key| key.id.to_ascii_lowercase()).collect();
        for record in &self.public_keys {
            if !vault_keys::valid_id(&record.id) || ids.contains(&record.id.to_ascii_lowercase()) || !public_ids.insert(record.id.to_ascii_lowercase()) {
                return Err("Invalid or duplicate public key ID".into());
            }
            if record.public_key.is_empty() || record.public_key.len() > MAX_METADATA_BYTES { return Err("Invalid public key size".into()); }
        }
        for site in sessions.sites() {
            for value in [site.private_key.as_deref(), site.tunnel.keyfile.as_deref()].into_iter().flatten() {
                if let Some(id) = value.strip_prefix("vaultkey://") {
                    if !vault_keys::valid_id(id) || !ids.contains(&id.to_ascii_lowercase()) {
                        return Err(format!("Session '{}' references a missing container SSH key", site.name));
                    }
                }
            }
            for field in PUBLIC_KEY_FIELDS {
                if let Some(id) = site.extra_fields.get(*field).and_then(|v| v.strip_prefix("vaultpub://")) {
                    if !vault_keys::valid_id(id) || !public_ids.contains(&id.to_ascii_lowercase()) {
                        return Err(format!("Session '{}' references a missing container public key", site.name));
                    }
                }
            }
            for field in TLS_FIELDS {
                if let Some(id) = site.extra_fields.get(*field).and_then(|v| v.strip_prefix("vaulttls://")) {
                    if !vault_keys::valid_id(id) || !tls_ids.contains(&id.to_ascii_lowercase()) {
                        return Err(format!("Session '{}' references missing container TLS material", site.name));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Input for an atomic session/key import; key material is borrowed, not logged.
pub struct NewSshKey<'a> {
    pub id: &'a str,
    pub private: &'a [u8],
    pub label: &'a str,
    pub public_key: &'a str,
}

/// TLS material is held encrypted in the container and borrowed during import.
pub struct NewTlsMaterial<'a> {
    pub id: &'a str,
    pub data: &'a [u8],
}

/// Public-only key material (not accompanied by an SSH private key).
pub struct NewPublicKey<'a> {
    pub id: &'a str,
    pub public_key: &'a str,
}

/// Public metadata returned by a key listing; private bytes are excluded.
#[derive(Debug, PartialEq, Eq)]
pub struct SshKeyInfo {
    pub id: String,
    pub label: String,
    pub public_key: String,
}

/// Storage operations hold the platform lock for their whole transaction.
/// This API does not retain the password or key after a call.
pub struct CredentialContainer {
    file: ContainerFile,
}

impl CredentialContainer {
    pub fn acquire(path: &std::path::Path) -> Result<Self, String> {
        Ok(Self { file: ContainerFile::try_acquire(path).map_err(|e| e.to_string())? })
    }

    pub fn create(&self, password: &str) -> Result<(), String> {
        let document = Document::fresh();
        let bytes = Zeroizing::new(serde_json::to_vec(&document).map_err(|e| e.to_string())?);
        self.file.create(password, &bytes).map_err(|e| e.to_string())
    }

    fn read(&self, password: &str) -> Result<Document, String> {
        let bytes = self.file.open(password).map_err(|e| e.to_string())?;
        Document::decode(&bytes)
    }

    fn write(&self, password: &str, document: &Document) -> Result<(), String> {
        let bytes = document.encoded()?;
        self.file.save(password, &bytes).map_err(|e| e.to_string())
    }

    /// Validate both encryption and document before retaining an unlocked session.
    pub fn unlock(self, password: &str) -> Result<UnlockedCredentialContainer, String> {
        let (file, plaintext) = self.file.unlock(password).map_err(|e| e.to_string())?;
        Document::decode(&plaintext)?;
        Ok(UnlockedCredentialContainer { file })
    }

    pub fn load_sessions(&self, password: &str) -> Result<SessionStore, String> {
        let document = self.read(password)?;
        SessionStore::parse_ini(&document.sessions_ini, Some(&document.session_key()?))
    }

    pub fn save_sessions(&self, password: &str, sessions: &SessionStore) -> Result<(), String> {
        let mut document = self.read(password)?;
        let updated = sessions.serialize_ini(Some(&document.session_key()?))?;
        document.sessions_ini.zeroize();
        document.sessions_ini = updated;
        self.write(password, &document)
    }

    /// Commit session changes and imported keys as one encrypted replacement.
    /// Conflicts or dangling references abort before any new bytes are published.
    pub fn save_sessions_with_keys(&self, password: &str, sessions: &SessionStore, keys: &[NewSshKey<'_>]) -> Result<(), String> {
        let mut document = self.read(password)?;
        for key in keys {
            if !vault_keys::valid_id(key.id) || document.keys.iter().any(|existing| existing.id.eq_ignore_ascii_case(key.id)) {
                return Err("Invalid or duplicate container key ID".into());
            }
            if key.private.is_empty() || key.private.len() > MAX_KEY_BYTES {
                return Err("Invalid container key size".into());
            }
            document.keys.push(KeyRecord { id: key.id.to_ascii_lowercase(), private_b64: BASE64.encode(key.private), label: key.label.to_owned(), public_key: key.public_key.to_owned() });
        }
        let updated = sessions.serialize_ini(Some(&document.session_key()?))?;
        document.sessions_ini.zeroize();
        document.sessions_ini = updated;
        self.write(password, &document)
    }

    /// Store a new SSH private key under an explicitly supplied, unique ID.
    /// Existing records are never silently overwritten.
    pub fn add_ssh_key(&self, password: &str, id: &str, private: &[u8], label: &str, public_key: &str) -> Result<(), String> {
        let mut document = self.read(password)?;
        if !vault_keys::valid_id(id) || document.keys.iter().any(|key| key.id.eq_ignore_ascii_case(id)) {
            return Err("Invalid or duplicate container key ID".into());
        }
        if private.is_empty() || private.len() > MAX_KEY_BYTES { return Err("Invalid container key size".into()); }
        document.keys.push(KeyRecord { id: id.to_ascii_lowercase(), private_b64: BASE64.encode(private), label: label.to_owned(), public_key: public_key.to_owned() });
        self.write(password, &document)
    }

    /// List key metadata without returning private bytes.
    pub fn list_ssh_keys(&self, password: &str) -> Result<Vec<SshKeyInfo>, String> {
        let document = self.read(password)?;
        Ok(document.keys.iter().map(|key| SshKeyInfo {
            id: key.id.clone(), label: key.label.clone(), public_key: key.public_key.clone(),
        }).collect())
    }

    /// Refuse deletion while any saved session or tunnel references the key.
    pub fn remove_ssh_key(&self, password: &str, id: &str) -> Result<(), String> {
        let mut document = self.read(password)?;
        let index = document.keys.iter().position(|key| key.id.eq_ignore_ascii_case(id)).ok_or("Container key not found")?;
        document.keys.remove(index);
        // Validation before publication rejects now-dangling session references.
        self.write(password, &document)
    }

    pub fn read_ssh_key(&self, password: &str, id: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let document = self.read(password)?;
        let record = document.keys.iter().find(|key| key.id.eq_ignore_ascii_case(id)).ok_or("Container key not found")?;
        Ok(Zeroizing::new(BASE64.decode(&record.private_b64).map_err(|_| "Invalid container key encoding")?))
    }
}

/// Unlocked credential session; dropping it zeroizes the container encryption
/// key and releases its process lock. No password is retained in this object.
pub struct UnlockedCredentialContainer {
    file: UnlockedContainer,
}

impl UnlockedCredentialContainer {
    fn read(&self) -> Result<Document, String> {
        let bytes = self.file.open().map_err(|e| e.to_string())?;
        Document::decode(&bytes)
    }

    fn write(&mut self, document: &Document) -> Result<(), String> {
        let bytes = document.encoded()?;
        self.file.save(&bytes).map_err(|e| e.to_string())
    }

    pub fn load_sessions(&self) -> Result<SessionStore, String> {
        let document = self.read()?;
        SessionStore::parse_ini(&document.sessions_ini, Some(&document.session_key()?))
    }

    /// All session and key modifications are committed in a single replacement.
    pub fn save_sessions_with_keys(&mut self, sessions: &SessionStore, keys: &[NewSshKey<'_>]) -> Result<(), String> {
        self.save_sessions_with_materials(sessions, keys, &[], &[])
    }

    /// Atomically commit sessions, private SSH keys, public-only keys and TLS
    /// material. Any conflict or dangling reference aborts the whole update.
    pub fn save_sessions_with_materials(&mut self, sessions: &SessionStore, keys: &[NewSshKey<'_>], tls: &[NewTlsMaterial<'_>], public_keys: &[NewPublicKey<'_>]) -> Result<(), String> {
        let mut document = self.read()?;
        if keys.len() > MAX_KEYS.saturating_sub(document.keys.len()) || tls.len() > MAX_KEYS.saturating_sub(document.tls.len()) || public_keys.len() > MAX_KEYS.saturating_sub(document.public_keys.len()) {
            return Err("Too many container materials".into());
        }
        for key in keys {
            if !vault_keys::valid_id(key.id) || document.public_keys.iter().any(|existing| existing.id.eq_ignore_ascii_case(key.id)) || document.keys.iter().any(|existing| existing.id.eq_ignore_ascii_case(key.id)) {
                return Err("Invalid or duplicate container key ID".into());
            }
            if key.private.is_empty() || key.private.len() > MAX_KEY_BYTES {
                return Err("Invalid container key size".into());
            }
            document.keys.push(KeyRecord { id: key.id.to_ascii_lowercase(), private_b64: BASE64.encode(key.private), label: key.label.to_owned(), public_key: key.public_key.to_owned() });
        }
        for blob in tls {
            if !vault_keys::valid_id(blob.id) || document.tls.iter().any(|existing| existing.id.eq_ignore_ascii_case(blob.id)) {
                return Err("Invalid or duplicate container TLS ID".into());
            }
            if blob.data.is_empty() || blob.data.len() > MAX_TLS_BYTES { return Err("Invalid TLS material size".into()); }
            document.tls.push(TlsRecord { id: blob.id.to_ascii_lowercase(), data_b64: BASE64.encode(blob.data) });
        }
        for public in public_keys {
            if !vault_keys::valid_id(public.id) || document.keys.iter().any(|existing| existing.id.eq_ignore_ascii_case(public.id)) || document.public_keys.iter().any(|existing| existing.id.eq_ignore_ascii_case(public.id)) {
                return Err("Invalid or duplicate container public key ID".into());
            }
            if public.public_key.is_empty() || public.public_key.len() > MAX_METADATA_BYTES { return Err("Invalid public key size".into()); }
            document.public_keys.push(PublicKeyRecord { id: public.id.to_ascii_lowercase(), public_key: public.public_key.to_owned() });
        }
        let updated = sessions.serialize_ini(Some(&document.session_key()?))?;
        document.sessions_ini.zeroize();
        document.sessions_ini = updated;
        self.write(&document)
    }

    pub fn list_ssh_keys(&self) -> Result<Vec<SshKeyInfo>, String> {
        let document = self.read()?;
        Ok(document.keys.iter().map(|key| SshKeyInfo {
            id: key.id.clone(), label: key.label.clone(), public_key: key.public_key.clone(),
        }).collect())
    }

    pub fn read_ssh_key(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let document = self.read()?;
        let record = document.keys.iter().find(|key| key.id.eq_ignore_ascii_case(id)).ok_or("Container key not found")?;
        Ok(Zeroizing::new(BASE64.decode(&record.private_b64).map_err(|_| "Invalid container key encoding")?))
    }

    pub fn read_tls_material(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let document = self.read()?;
        let record = document.tls.iter().find(|record| record.id.eq_ignore_ascii_case(id)).ok_or("Container TLS material not found")?;
        Ok(Zeroizing::new(BASE64.decode(&record.data_b64).map_err(|_| "Invalid TLS encoding")?))
    }

    pub fn read_public_key(&self, id: &str) -> Result<String, String> {
        let document = self.read()?;
        if let Some(key) = document.keys.iter().find(|key| key.id.eq_ignore_ascii_case(id) && !key.public_key.is_empty()) {
            return Ok(key.public_key.clone());
        }
        document.public_keys.iter().find(|key| key.id.eq_ignore_ascii_case(id))
            .map(|key| key.public_key.clone()).ok_or_else(|| "Container public key not found".into())
    }

    /// Delete only when validation confirms no saved session references it.
    pub fn remove_tls_material(&mut self, id: &str) -> Result<(), String> {
        let mut document = self.read()?;
        let index = document.tls.iter().position(|record| record.id.eq_ignore_ascii_case(id)).ok_or("Container TLS material not found")?;
        document.tls.remove(index);
        self.write(&document)
    }

    pub fn remove_public_key(&mut self, id: &str) -> Result<(), String> {
        let mut document = self.read()?;
        let index = document.public_keys.iter().position(|record| record.id.eq_ignore_ascii_case(id)).ok_or("Container public-only key not found")?;
        document.public_keys.remove(index);
        self.write(&document)
    }

    pub fn remove_ssh_key(&mut self, id: &str) -> Result<(), String> {
        let mut document = self.read()?;
        let index = document.keys.iter().position(|key| key.id.eq_ignore_ascii_case(id)).ok_or("Container key not found")?;
        document.keys.remove(index);
        self.write(&document)
    }

    /// Erase the unlocked key while retaining the process lock.
    pub fn lock(self) -> CredentialContainer {
        CredentialContainer { file: self.file.lock() }
    }
}

/// Experimental bridge for existing SessionStore callers. This only routes
/// session INI; key management, other protected files, backup and the service
/// lifecycle are not switched to it yet. Never mix it with the live service
/// until all those paths use the same container transaction boundary.
pub struct ContainerSessionVault {
    root: std::path::PathBuf,
    unlocked: std::sync::Mutex<Option<UnlockedCredentialContainer>>,
}

impl ContainerSessionVault {
    pub fn new(root: &std::path::Path, unlocked: UnlockedCredentialContainer) -> Result<Self, String> {
        let root = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
        Ok(Self { root, unlocked: std::sync::Mutex::new(Some(unlocked)) })
    }

    /// Atomically update sessions and newly imported key materials under the
    /// same mutex used by the SessionStore adapter.
    pub fn save_sessions_with_materials(&self, sessions: &SessionStore, keys: &[NewSshKey<'_>], tls: &[NewTlsMaterial<'_>], public_keys: &[NewPublicKey<'_>]) -> Result<(), String> {
        let mut guard = self.unlocked.lock().map_err(|_| "Container session is unavailable")?;
        let session = guard.as_mut().ok_or("Vault is locked")?;
        session.save_sessions_with_materials(sessions, keys, tls, public_keys)
    }

    pub fn read_ssh_key(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let guard = self.unlocked.lock().map_err(|_| "Container session is unavailable")?;
        guard.as_ref().ok_or("Vault is locked")?.read_ssh_key(id)
    }

    pub fn read_tls_material(&self, id: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let guard = self.unlocked.lock().map_err(|_| "Container session is unavailable")?;
        guard.as_ref().ok_or("Vault is locked")?.read_tls_material(id)
    }

    pub fn read_public_key(&self, id: &str) -> Result<String, String> {
        let guard = self.unlocked.lock().map_err(|_| "Container session is unavailable")?;
        guard.as_ref().ok_or("Vault is locked")?.read_public_key(id)
    }

    /// Drop the derived encryption key and release the file lock.
    pub fn lock(&self) -> Result<(), String> {
        let mut guard = self.unlocked.lock().map_err(|_| "Container session is unavailable")?;
        *guard = None;
        Ok(())
    }

    fn check_root(&self, root: &std::path::Path) -> Result<(), linscp_platform::PlatformError> {
        let actual = std::fs::canonicalize(root)?;
        if actual != self.root {
            return Err(linscp_platform::PlatformError::SecretVault("Container session belongs to a different configuration root".into()));
        }
        Ok(())
    }

    fn error(message: impl ToString) -> linscp_platform::PlatformError {
        linscp_platform::PlatformError::SecretVault(message.to_string())
    }
}

impl linscp_platform::SecretVault for ContainerSessionVault {
    fn protects_session_store(&self) -> bool { true }

    fn load_master_key(&self, config_dir: &std::path::Path) -> Result<Option<Zeroizing<[u8; 32]>>, linscp_platform::PlatformError> {
        self.check_root(config_dir)?;
        let guard = self.unlocked.lock().map_err(|_| Self::error("Container session is unavailable"))?;
        let session = guard.as_ref().ok_or_else(|| Self::error("Vault is locked"))?;
        let document = session.read().map_err(Self::error)?;
        Ok(Some(document.master_bytes().map_err(Self::error)?))
    }

    fn load_or_create_master_key(&self, config_dir: &std::path::Path) -> Result<Zeroizing<[u8; 32]>, linscp_platform::PlatformError> {
        self.load_master_key(config_dir)?.ok_or_else(|| Self::error("Vault is locked"))
    }

    fn read_session_ini(&self, config_dir: &std::path::Path) -> Result<linscp_platform::SessionIniRead, linscp_platform::PlatformError> {
        self.check_root(config_dir)?;
        let guard = self.unlocked.lock().map_err(|_| Self::error("Container session is unavailable"))?;
        let session = guard.as_ref().ok_or_else(|| Self::error("Vault is locked"))?;
        let document = session.read().map_err(Self::error)?;
        Ok(linscp_platform::SessionIniRead::Plaintext(Zeroizing::new(document.sessions_ini.clone())))
    }

    fn write_session_ini(&self, config_dir: &std::path::Path, text: &str) -> Result<bool, linscp_platform::PlatformError> {
        self.check_root(config_dir)?;
        let mut guard = self.unlocked.lock().map_err(|_| Self::error("Container session is unavailable"))?;
        let session = guard.as_mut().ok_or_else(|| Self::error("Vault is locked"))?;
        let mut document = session.read().map_err(Self::error)?;
        document.sessions_ini.zeroize();
        document.sessions_ini.push_str(text);
        session.write(&document).map_err(Self::error)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_store::StoredSite;
    use linscp_types::ProtocolScheme;

    #[test]
    fn atomic_import_covers_tls_and_public_only_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let vault = CredentialContainer::acquire(&path).unwrap();
        vault.create("test password").unwrap();
        let mut unlocked = vault.unlock("test password").ok().unwrap();
        let tls_id = "11111111111111111111111111111111";
        let pub_id = "22222222222222222222222222222222";
        let mut sessions = SessionStore::new();
        let mut site = StoredSite::new("secure", ProtocolScheme::Sftp, "example.test");
        site.extra_fields.insert("tls_certificate_key_file".into(), format!("vaulttls://{tls_id}"));
        site.extra_fields.insert("linscp_public_key_file".into(), format!("vaultpub://{pub_id}"));
        sessions.upsert(site);
        let before = std::fs::read(&path).unwrap();
        assert!(unlocked.save_sessions_with_materials(&sessions, &[], &[], &[]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let tls = NewTlsMaterial { id: tls_id, data: b"private TLS material" };
        let public = NewPublicKey { id: pub_id, public_key: "ssh-ed25519 public" };
        unlocked.save_sessions_with_materials(&sessions, &[], &[tls], &[public]).unwrap();
        assert_eq!(unlocked.read_tls_material(tls_id).unwrap().as_slice(), b"private TLS material");
        assert_eq!(unlocked.read_public_key(pub_id).unwrap(), "ssh-ed25519 public");
        let committed = std::fs::read(&path).unwrap();
        assert!(unlocked.remove_tls_material(tls_id).is_err());
        assert!(unlocked.remove_public_key(pub_id).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), committed);
        assert!(!committed.windows(b"private TLS material".len()).any(|part| part == b"private TLS material"));
        unlocked.save_sessions_with_materials(&SessionStore::new(), &[], &[], &[]).unwrap();
        unlocked.remove_tls_material(tls_id).unwrap();
        unlocked.remove_public_key(pub_id).unwrap();
    }

    #[test]
    fn existing_session_store_api_uses_container_without_legacy_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let vault = CredentialContainer::acquire(&path).unwrap();
        vault.create("test password").unwrap();
        let unlocked = vault.unlock("test password").ok().unwrap();
        let bridge = ContainerSessionVault::new(dir.path(), unlocked).unwrap();
        let mut sessions = SessionStore::load_from_dir(dir.path(), &bridge).unwrap();
        let mut site = StoredSite::new("sample", ProtocolScheme::Sftp, "example.test");
        site.password = Some("secret".into());
        sessions.upsert(site);
        sessions.save_to_dir(dir.path(), &bridge).unwrap();
        let id = "33333333333333333333333333333333";
        let key = NewSshKey { id, private: b"private", label: "key", public_key: "public" };
        bridge.save_sessions_with_materials(&sessions, &[key], &[], &[]).unwrap();
        assert_eq!(bridge.read_ssh_key(id).unwrap().as_slice(), b"private");
        assert_eq!(bridge.read_public_key(id).unwrap(), "public");
        SessionStore::protect_existing(dir.path(), &bridge).unwrap();
        assert_eq!(SessionStore::load_from_dir(dir.path(), &bridge).unwrap().find("sample").unwrap().password.as_deref(), Some("secret"));
        assert!(!dir.path().join("sessions.ini").exists());
        assert!(!dir.path().join("sessions.key").exists());
        let other = tempfile::tempdir().unwrap();
        assert!(SessionStore::load_from_dir(other.path(), &bridge).is_err());
        bridge.lock().unwrap();
        assert!(bridge.read_ssh_key(id).is_err());
        assert!(SessionStore::load_from_dir(dir.path(), &bridge).is_err());
        assert!(sessions.save_to_dir(dir.path(), &bridge).is_err());
        assert!(!dir.path().join("sessions.ini").exists());
        let reopened = CredentialContainer::acquire(&path).unwrap().unlock("test password").ok().unwrap();
        assert_eq!(reopened.load_sessions().unwrap().find("sample").unwrap().password.as_deref(), Some("secret"));
    }

    #[test]
    fn unlocked_session_keeps_lock_and_commits_without_password() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let vault = CredentialContainer::acquire(&path).unwrap();
        vault.create("test password").unwrap();
        let mut unlocked = vault.unlock("test password").ok().unwrap();
        assert!(CredentialContainer::acquire(&path).is_err());
        let id = "0123456789abcdef0123456789abcdef";
        let mut sessions = SessionStore::new();
        let mut site = StoredSite::new("sample", ProtocolScheme::Sftp, "example.test");
        site.private_key = Some(format!("vaultkey://{id}"));
        site.password = Some("secret".into());
        sessions.upsert(site);
        let key = NewSshKey { id, private: b"private", label: "key", public_key: "public" };
        unlocked.save_sessions_with_keys(&sessions, &[key]).unwrap();
        assert_eq!(unlocked.load_sessions().unwrap().find("sample").unwrap().password.as_deref(), Some("secret"));
        assert_eq!(unlocked.read_ssh_key(id).unwrap().as_slice(), b"private");
        assert!(unlocked.remove_ssh_key(id).is_err());
        let locked = unlocked.lock();
        assert!(CredentialContainer::acquire(&path).is_err());
        drop(locked);
        assert!(CredentialContainer::acquire(&path).unwrap().unlock("wrong password").is_err());
        let reopened = CredentialContainer::acquire(&path).unwrap().unlock("test password").ok().unwrap();
        assert_eq!(reopened.list_ssh_keys().unwrap().len(), 1);
    }

    #[test]
    fn transaction_import_and_key_deletion_are_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let vault = CredentialContainer::acquire(&path).unwrap();
        let password = "test password";
        vault.create(password).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let mut sessions = SessionStore::new();
        let mut site = StoredSite::new("sample", ProtocolScheme::Sftp, "example.test");
        site.private_key = Some(format!("vaultkey://{id}"));
        sessions.upsert(site);
        let original = std::fs::read(&path).unwrap();
        assert!(vault.save_sessions(password, &sessions).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let key = NewSshKey { id, private: b"private-key", label: "key", public_key: "public" };
        vault.save_sessions_with_keys(password, &sessions, &[key]).unwrap();
        let before = std::fs::read(&path).unwrap();
        assert_eq!(vault.list_ssh_keys(password).unwrap()[0].id, id);
        assert!(vault.remove_ssh_key(password, id).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        let dupe = NewSshKey { id, private: b"different", label: "", public_key: "" };
        assert!(vault.save_sessions_with_keys(password, &SessionStore::new(), &[dupe]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        vault.save_sessions(password, &SessionStore::new()).unwrap();
        vault.remove_ssh_key(password, id).unwrap();
        assert!(vault.read_ssh_key(password, id).is_err());
    }

    #[test]
    fn unreadable_session_secrets_are_rejected() {
        let mut document = Document::fresh();
        let mut sessions = SessionStore::new();
        let mut site = StoredSite::new("sample", ProtocolScheme::Sftp, "example.test");
        site.password = Some("secret".into());
        sessions.upsert(site);
        document.sessions_ini = sessions.serialize_ini(Some(&document.session_key().unwrap())).unwrap();
        let other = Document::fresh();
        document.session_key_b64 = other.session_key_b64.clone();
        assert!(document.validate().is_err());
    }

    #[test]
    fn sessions_and_ssh_keys_round_trip_in_one_encrypted_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let vault = CredentialContainer::acquire(&path).unwrap();
        vault.create("test password").unwrap();
        let mut sessions = SessionStore::new();
        let mut site = StoredSite::new("sample", ProtocolScheme::Sftp, "example.test");
        site.password = Some("secret-password".into());
        sessions.upsert(site);
        vault.save_sessions("test password", &sessions).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        vault.add_ssh_key("test password", id, b"private-key-material", "test", "public").unwrap();
        assert!(vault.add_ssh_key("test password", id, b"other", "", "").is_err());
        assert!(vault.load_sessions("wrong password").is_err());
        let disk = std::fs::read(&path).unwrap();
        assert!(!disk.windows(b"secret-password".len()).any(|part| part == b"secret-password"));
        assert!(!disk.windows(b"private-key-material".len()).any(|part| part == b"private-key-material"));
        drop(vault);
        let reopened = CredentialContainer::acquire(&path).unwrap();
        assert_eq!(reopened.load_sessions("test password").unwrap().find("sample").unwrap().password.as_deref(), Some("secret-password"));
        assert_eq!(reopened.read_ssh_key("test password", id).unwrap().as_slice(), b"private-key-material");
    }
}
