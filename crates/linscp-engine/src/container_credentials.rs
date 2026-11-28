//! Experimental session and key records inside an encrypted container.
//!
//! This is not wired into CommanderService. Do not use this provisional schema
//! as the application's active vault until all readers, key materialization,
//! backup/restore, and lock/unlock paths use the same transaction boundary.
use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use linscp_crypto::SessionMasterKey;
use linscp_platform::container_file::ContainerFile;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{session_store::SessionStore, vault_keys};

const MAX_KEYS: usize = 2000;
const MAX_KEY_BYTES: usize = 1024 * 1024;
const MAX_METADATA_BYTES: usize = 32 * 1024;

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
struct Document {
    version: u32,
    session_key_b64: String,
    sessions_ini: String,
    keys: Vec<KeyRecord>,
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
        Self { version: 1, session_key_b64: BASE64.encode(&*key), sessions_ini: String::new(), keys: Vec::new() }
    }

    fn session_key(&self) -> Result<SessionMasterKey, String> {
        let raw = Zeroizing::new(BASE64.decode(&self.session_key_b64).map_err(|_| "Invalid session key encoding")?);
        SessionMasterKey::from_bytes(&raw).map_err(|_| "Invalid session key length".into())
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
        for site in sessions.sites() {
            for value in [site.private_key.as_deref(), site.tunnel.keyfile.as_deref()].into_iter().flatten() {
                if let Some(id) = value.strip_prefix("vaultkey://") {
                    if !vault_keys::valid_id(id) || !ids.contains(&id.to_ascii_lowercase()) {
                        return Err(format!("Session '{}' references a missing container SSH key", site.name));
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
        let document: Document = serde_json::from_slice(&bytes).map_err(|e| format!("Invalid credential container: {e}"))?;
        document.validate()?;
        Ok(document)
    }

    fn write(&self, password: &str, document: &Document) -> Result<(), String> {
        document.validate()?;
        let bytes = Zeroizing::new(serde_json::to_vec(document).map_err(|e| e.to_string())?);
        self.file.save(password, &bytes).map_err(|e| e.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_store::StoredSite;
    use linscp_types::ProtocolScheme;

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
