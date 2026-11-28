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
        SessionStore::parse_ini(&self.sessions_ini, Some(&key))?;
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
        Ok(())
    }
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
