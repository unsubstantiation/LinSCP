//! Durable restore intentions contain only saved-site identity, never credentials.
use std::collections::BTreeMap;
use std::path::Path;
use linscp_engine::session_store::StoredSite;
use serde::{Deserialize, Serialize};
use linscp_platform::SecretVault;
const HEADER: &[u8] = b"LSCP-RECONNECT-VAULT-1\n";
const CONTEXT: &[u8] = b"LinSCP reconnect state v1\n";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub protocol: String,
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alt_host: String,
    #[serde(default, skip_serializing_if = "is_zero_port")]
    pub alt_port: u16,
    pub username: String,
}

fn is_zero_port(port: &u16) -> bool {
    *port == 0
}

impl Identity {
    pub fn of(site: &StoredSite) -> Self {
        let port = if site.port == 0 { site.protocol.default_port() } else { site.port };
        let alt_host = site
            .extra_fields
            .get("alt_hostname")
            .filter(|host| !host.is_empty())
            .cloned()
            .unwrap_or_default();
        let alt_port = if alt_host.is_empty() {
            0
        } else {
            crate::tabs::effective_site_alt_port(site)
        };
        Self {
            protocol: site.protocol.as_str().to_string(),
            host: site.host.clone(),
            port,
            alt_host,
            alt_port,
            username: site.username.clone(),
        }
    }
}

pub fn enabled(site: &StoredSite) -> bool {
    site.extra_fields.get("auto_reconnect").is_some_and(|value| value == "1")
}

pub fn interval(site: &StoredSite) -> u64 {
    site.extra_fields.get("auto_reconnect_seconds").and_then(|value| value.parse().ok())
        .filter(|seconds| (1..=3600).contains(seconds)).unwrap_or(30)
}

pub type Intentions = BTreeMap<String, Identity>;
pub fn load(root: &Path, vault: &dyn SecretVault) -> Result<Intentions, String> {
    let path = root.join("auto-reconnect.json");
    match vault.read_protected_file(&path, "auto-reconnect").map_err(|e| e.to_string())? {
        linscp_platform::ProtectedFileRead::Unhandled => {},
        linscp_platform::ProtectedFileRead::Missing => return Ok(BTreeMap::new()),
        linscp_platform::ProtectedFileRead::Plaintext(bytes) => {
            return serde_json::from_slice(&bytes).map_err(|e| format!("Cannot read auto-reconnect state: {e}"));
        }
    }
    match std::fs::read(path) {
        Ok(bytes) => {
            if let Some(encrypted) = bytes.strip_prefix(HEADER) {
                let plain = vault.open_session_store(encrypted).map_err(|e| e.to_string())?;
                let json = plain.strip_prefix(CONTEXT).ok_or_else(|| "Invalid reconnect state context".to_string())?;
                serde_json::from_slice(json).map_err(|e| format!("Cannot read auto-reconnect state: {e}"))
            } else {
                if vault.protects_session_store() && vault.load_master_key(root).map_err(|e| e.to_string())?.is_none() {
                    return Err("Unlock the local vault to read reconnect state".into());
                }
                serde_json::from_slice(&bytes).map_err(|e| format!("Cannot read auto-reconnect state: {e}"))
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(format!("Cannot read auto-reconnect state: {e}")),
    }
}
pub fn save(root: &Path, vault: &dyn SecretVault, intentions: &Intentions) -> Result<(), String> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(intentions).map_err(|e| e.to_string())?);
    let path = root.join("auto-reconnect.json");
    if vault.write_protected_file(&path, "auto-reconnect", &bytes).map_err(|e| e.to_string())? { return Ok(()); }
    let mut payload = zeroize::Zeroizing::new(CONTEXT.to_vec());
    payload.extend_from_slice(&bytes);
    let encrypted = vault.seal_session_store(&payload).map_err(|e| e.to_string())?;
    let mut output = HEADER.to_vec();
    output.extend_from_slice(&encrypted);
    linscp_platform::write_private_file_atomic(&root.join("auto-reconnect.json"), &output)
        .map_err(|e| format!("Cannot save auto-reconnect state: {e}"))
}
pub fn protect_existing(root: &Path, vault: &dyn SecretVault) -> Result<(), String> {
    let path = root.join("auto-reconnect.json");
    match vault.read_protected_file(&path, "auto-reconnect").map_err(|e| e.to_string())? {
        linscp_platform::ProtectedFileRead::Unhandled => {},
        linscp_platform::ProtectedFileRead::Missing => return Ok(()),
        linscp_platform::ProtectedFileRead::Plaintext(bytes) => {
            serde_json::from_slice::<Intentions>(&bytes).map_err(|e| format!("Cannot read auto-reconnect state: {e}"))?;
            return Ok(());
        }
    }
    match std::fs::read(&path) {
        Ok(bytes) if !bytes.starts_with(HEADER) => {
            let intentions = load(root, vault)?;
            save(root, vault, &intentions)
        },
        Ok(_) => { load(root, vault)?; Ok(()) },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Cannot read auto-reconnect state: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn container_backend_persists_reconnect_state_without_a_sidecar() {
        use linscp_engine::container_credentials::{ContainerSessionVault, CredentialContainer};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.dat");
        let vault = CredentialContainer::acquire(&path).unwrap();
        vault.create("test password").unwrap();
        let unlocked = vault.unlock("test password").ok().unwrap();
        let bridge = ContainerSessionVault::new(dir.path(), unlocked).unwrap();
        assert!(load(dir.path(), &bridge).unwrap().is_empty());
        let mut site = StoredSite::new("saved", linscp_types::ProtocolScheme::Sftp, "private.example");
        site.username = "alice".into();
        let mut expected = Intentions::new();
        expected.insert("saved".into(), Identity::of(&site));
        save(dir.path(), &bridge, &expected).unwrap();
        protect_existing(dir.path(), &bridge).unwrap();
        assert_eq!(load(dir.path(), &bridge).unwrap(), expected);
        assert!(!dir.path().join("auto-reconnect.json").exists());
        let disk = std::fs::read(&path).unwrap();
        assert!(!disk.windows(b"private.example".len()).any(|part| part == b"private.example"));
        let wrong_root = tempfile::tempdir().unwrap();
        assert!(load(wrong_root.path(), &bridge).is_err());
        bridge.lock().unwrap();
        assert!(load(dir.path(), &bridge).is_err());
        assert!(save(dir.path(), &bridge, &expected).is_err());
        assert!(!dir.path().join("auto-reconnect.json").exists());
        let unlocked = CredentialContainer::acquire(&path).unwrap().unlock("test password").ok().unwrap();
        let bridge = ContainerSessionVault::new(dir.path(), unlocked).unwrap();
        assert_eq!(load(dir.path(), &bridge).unwrap(), expected);
        // A corrupted record is not silently interpreted as an empty state.
        bridge.write_protected_file(&dir.path().join("auto-reconnect.json"), "auto-reconnect", b"not-json").unwrap();
        assert!(load(dir.path(), &bridge).is_err());
        assert!(protect_existing(dir.path(), &bridge).is_err());
    }

    #[test]
    fn defaults_and_invalid_values_are_safe() {
        let mut site = StoredSite::new("site", linscp_types::ProtocolScheme::Sftp, "host");
        assert!(!enabled(&site));
        assert_eq!(interval(&site), 30);
        site.extra_fields.insert("auto_reconnect_seconds".into(), "0".into());
        assert_eq!(interval(&site), 30);
        site.extra_fields.insert("auto_reconnect_seconds".into(), "12".into());
        site.extra_fields.insert("auto_reconnect".into(), "1".into());
        assert!(enabled(&site));
        assert_eq!(interval(&site), 12);
    }
}
