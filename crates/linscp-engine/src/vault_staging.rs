//! Stage SSH keys in memory for atomic session/container updates.
use std::path::{Path, PathBuf};
use rand::RngCore;
use crate::session_store::StoredSite;
use crate::vault_keys::valid_id as valid_vault_key_id;
const LOCAL_VAULT_KEY_PREFIX: &str = "vaultkey://";
const OFFLINEOTP_SSH_SUFFIX: &str = " [LinSCP SSH key]";
const OFFLINEOTP_TUNNEL_SUFFIX: &str = " [LinSCP jump-host key]";

fn derive_public_ssh_key_optional(raw_key_text: &str) -> Option<String> {
    let trimmed = raw_key_text.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with("PuTTY-User-Key-File-") {
        return linscp_crypto::ppk::ppk_authorized_keys_line(trimmed, "").ok();
    }
    if trimmed.starts_with("-----BEGIN ") {
        return linscp_proto::ssh::extract_openssh_public_key_line(trimmed, None).ok();
    }
    None
}

fn sanitize_vault_key_label(raw: &str) -> String {
    let without_suffix = raw
        .strip_suffix(OFFLINEOTP_SSH_SUFFIX)
        .or_else(|| raw.strip_suffix(OFFLINEOTP_TUNNEL_SUFFIX))
        .unwrap_or(raw);
    without_suffix
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(128)
        .collect::<String>()
}

fn derive_vault_key_label(explicit_label: &str, public_key: &str, id: &str) -> String {
    let explicit = sanitize_vault_key_label(explicit_label);
    if !explicit.is_empty() {
        return explicit;
    }
    if !public_key.is_empty() {
        let mut fields = public_key.split_whitespace();
        if let Some(algorithm) = fields.next() {
            let _blob = fields.next();
            let comment = sanitize_vault_key_label(&fields.collect::<Vec<_>>().join(" "));
            if !comment.is_empty() {
                return comment;
            }
            let alg_clean = sanitize_vault_key_label(algorithm);
            if !alg_clean.is_empty() {
                return alg_clean;
            }
        }
    }
    format!("SSH key {}", &id[..id.len().min(8)])
}
fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&lhs, &rhs) in left.iter().zip(right.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}
fn read_bounded_key(path: &Path, limit: u64) -> Result<String, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("Cannot read SSH key '{}': {error}", path.display()))?;
    if metadata.len() > limit {
        return Err(format!("SSH key '{}' exceeds OfflineOTP's 32 KiB per-key limit.", path.display()));
    }
    use std::io::Read as _;
    let file = std::fs::File::open(path)
        .map_err(|error| format!("Cannot read SSH key '{}': {error}", path.display()))?;
    let mut bytes = Vec::with_capacity((limit + 1) as usize);
    file.take(limit + 1).read_to_end(&mut bytes)
        .map_err(|error| format!("Cannot read SSH key '{}': {error}", path.display()))?;
    if bytes.len() as u64 > limit {
        return Err(format!("SSH key '{}' exceeds OfflineOTP's 32 KiB per-key limit.", path.display()));
    }
    String::from_utf8(bytes).map_err(|_| format!("SSH key '{}' is not UTF-8 text.", path.display()))
}

fn read_bounded_key_optional(path: &Path, limit: u64) -> Result<String, String> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() <= limit => read_bounded_key(path, limit)
            .map_err(|error| error.replace("SSH key", "SSH public key")),
        Ok(_) => Err(format!("SSH key '{}' exceeds OfflineOTP's 32 KiB per-key limit.", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(format!("Cannot read SSH public key '{}': {error}", path.display())),
    }
}

pub struct StagedSessionKey {
    pub id: String,
    pub private: zeroize::Zeroizing<Vec<u8>>,
    pub label: String,
    pub public: String,
}

impl StagedSessionKey {
    pub fn as_import(&self) -> linscp_platform::VaultMaterialImport<'_> {
        linscp_platform::VaultMaterialImport::Ssh { id: &self.id, private: &self.private, label: &self.label, public_key: &self.public }
    }
}

// Stage plaintext in zeroizing memory; the backend validates all existing
// references and commits the new keys and session store in one replacement.
pub fn stage_session_ssh_keys(site: &mut StoredSite, staged: &mut Vec<StagedSessionKey>) -> Result<(), String> {
    site.extra_fields.retain(|key, _| {
        let key = key.to_ascii_lowercase();
        !key.contains("keyfile") && !key.ends_with("private_key_file")
    });
    for reference in [&mut site.private_key, &mut site.tunnel.keyfile] {
        let Some(path) = reference.as_deref() else { continue };
        if let Some(id) = path.strip_prefix(LOCAL_VAULT_KEY_PREFIX) {
            if !valid_vault_key_id(id) { return Err("Saved encrypted SSH key reference is invalid.".into()); }
            continue;
        }
        let source = PathBuf::from(linscp_platform::terminal::expand_tilde(path));
        if source.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("pub")) { continue; }
        let metadata = std::fs::metadata(&source).map_err(|e| format!("Cannot read private SSH key '{}': {e}", source.display()))?;
        if !metadata.is_file() || metadata.len() > 1024 * 1024 { return Err(format!("Private SSH key '{}' is not a regular file under 1 MiB.", source.display())); }
        use std::io::Read as _;
        let file = std::fs::File::open(&source).map_err(|e| format!("Cannot read private SSH key '{}': {e}", source.display()))?;
        let mut private = zeroize::Zeroizing::new(Vec::new());
        file.take(1024 * 1024 + 1).read_to_end(&mut private).map_err(|e| e.to_string())?;
        if private.is_empty() || private.len() > 1024 * 1024 { return Err("Invalid private SSH key size.".into()); }
        if let Some(existing) = staged.iter().find(|key| constant_time_bytes_eq(&key.private, &private)) {
            *reference = Some(format!("{LOCAL_VAULT_KEY_PREFIX}{}", existing.id));
            continue;
        }
        let mut public_path = source.as_os_str().to_os_string();
        public_path.push(".pub");
        let mut public = read_bounded_key_optional(&PathBuf::from(public_path), 32 * 1024)?;
        if public.is_empty() {
            if let Ok(text) = std::str::from_utf8(&private) { public = derive_public_ssh_key_optional(text).unwrap_or_default(); }
        }
        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);
        let id = random.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let name = source.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let label = derive_vault_key_label(name, &public, &id);
        *reference = Some(format!("{LOCAL_VAULT_KEY_PREFIX}{id}"));
        staged.push(StagedSessionKey { id, private, label, public });
    }
    Ok(())
}


/// TLS certificate and private-key files are copied into the same transaction
/// as their referring session. No plaintext staging files are created.
pub struct StagedTlsMaterial {
    id: String,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl StagedTlsMaterial {
    pub fn as_import(&self) -> linscp_platform::VaultMaterialImport<'_> {
        linscp_platform::VaultMaterialImport::Tls { id: &self.id, data: &self.bytes }
    }
}

pub fn stage_session_tls_material(site: &mut StoredSite, staged: &mut Vec<StagedTlsMaterial>) -> Result<(), String> {
    const LIMIT: u64 = 384 * 1024;
    for field in ["ca_certificate_file", "tls_certificate_file", "certificate", "tls_certificate_key_file"] {
        let Some(value) = site.extra_fields.get_mut(field) else { continue };
        if value.is_empty() { continue; }
        if let Some(id) = value.strip_prefix("vaulttls://") {
            if !valid_vault_key_id(id) { return Err(format!("Invalid saved TLS reference in '{field}'")); }
            continue;
        }
        let path = PathBuf::from(linscp_platform::terminal::expand_tilde(value));
        let metadata = std::fs::metadata(&path).map_err(|e| format!("Cannot read TLS material '{}': {e}", path.display()))?;
        if !metadata.is_file() || metadata.len() > LIMIT { return Err(format!("TLS material '{}' is not a regular file under 384 KiB", path.display())); }
        use std::io::Read as _;
        let file = std::fs::File::open(&path).map_err(|e| format!("Cannot read TLS material '{}': {e}", path.display()))?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        file.take(LIMIT + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        if bytes.is_empty() || bytes.len() as u64 > LIMIT { return Err("Invalid TLS material size".into()); }
        if let Some(existing) = staged.iter().find(|entry| constant_time_bytes_eq(&entry.bytes, &bytes)) {
            *value = format!("vaulttls://{}", existing.id);
            continue;
        }
        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);
        let id = random.iter().map(|b| format!("{b:02x}")).collect::<String>();
        *value = format!("vaulttls://{id}");
        staged.push(StagedTlsMaterial { id, bytes });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container_credentials::{ContainerSessionVault, CredentialContainer};
    use crate::session_store::SessionStore;
    use linscp_types::ProtocolScheme;

    #[test]
    fn tls_material_is_committed_atomically_with_session() {
        let root = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        let pem = source.path().join("client.pem");
        std::fs::write(&pem, b"private certificate material").unwrap();
        let path = root.path().join("app.dat");
        let file = CredentialContainer::acquire(&path).unwrap();
        file.create("test password").unwrap();
        let vault = ContainerSessionVault::new(root.path(), file.unlock("test password").ok().unwrap()).unwrap();
        let mut site = StoredSite::new("tls", ProtocolScheme::Ftps, "example.test");
        site.extra_fields.insert("tls_certificate_file".into(), pem.to_string_lossy().into_owned());
        site.extra_fields.insert("tls_certificate_key_file".into(), pem.to_string_lossy().into_owned());
        let mut staged = Vec::new();
        stage_session_tls_material(&mut site, &mut staged).unwrap();
        assert_eq!(staged.len(), 1);
        let reference = site.extra_fields["tls_certificate_key_file"].clone();
        let id = reference.strip_prefix("vaulttls://").unwrap();
        let mut store = SessionStore::new();
        store.upsert(site);
        store.save_with_materials(root.path(), &vault, &[staged[0].as_import()]).unwrap();
        assert_eq!(vault.read_tls_material(id).unwrap().as_slice(), b"private certificate material");
        assert_eq!(SessionStore::load_from_dir(root.path(), &vault).unwrap().find("tls").unwrap().extra_fields["tls_certificate_file"], reference);
        assert!(!root.path().join("keys").exists());
        let before = std::fs::read(&path).unwrap();
        let mut invalid = StoredSite::new("bad", ProtocolScheme::Ftps, "example.test");
        invalid.extra_fields.insert("tls_certificate_key_file".into(), source.path().join("missing").to_string_lossy().into_owned());
        assert!(stage_session_tls_material(&mut invalid, &mut Vec::new()).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
