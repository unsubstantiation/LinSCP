//! Materialize managed SSH/TLS material only for the duration of a connection.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use linscp_platform::{SecretVault, write_exclusive_private_file};
use rand::RngCore;
use crate::vault_keys::valid_id as valid_vault_key_id;

const LOCAL_VAULT_KEY_PREFIX: &str = "vaultkey://";
const LOCAL_VAULT_TLS_PREFIX: &str = "vaulttls://";
const TLS_VAULT_BLOB_LIMIT: u64 = 384 * 1024;

fn read_public_optional(path: &Path) -> Result<String, String> {
    let Some(bytes) = crate::vault_keys::read_file(path, 32 * 1024)? else { return Ok(String::new()); };
    String::from_utf8(bytes).map_err(|_| "Saved SSH public key is not UTF-8".into())
}

pub struct TemporaryVaultKeys(Vec<PathBuf>);

impl Drop for TemporaryVaultKeys {
    fn drop(&mut self) {
        for path in &self.0 { let _ = std::fs::remove_file(path); }
    }
}

pub fn materialize_vault_key_paths(
    spec: &mut crate::url_and_raw::ParsedSiteSpec,
    config_root: &Path,
    vault: &dyn SecretVault,
) -> Result<TemporaryVaultKeys, String> {
    let mut temporary = TemporaryVaultKeys(Vec::new());
    materialize_one_vault_key(&mut spec.session.keyfile, config_root, vault, &mut temporary.0)?;
    if let Some(tunnel) = spec.session.tunnel.as_mut() {
        materialize_one_vault_key(&mut tunnel.keyfile, config_root, vault, &mut temporary.0)?;
    }
    for field in ["ca_certificate_file", "tls_certificate_file", "certificate", "tls_certificate_key_file"] {
        materialize_one_vault_tls_blob(field, &mut spec.raw_fields, config_root, vault, &mut temporary.0)?;
    }
    Ok(temporary)
}

fn materialize_one_vault_tls_blob(
    field: &str,
    raw_fields: &mut BTreeMap<String, String>,
    config_root: &Path,
    vault: &dyn SecretVault,
    created: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let Some(reference) = raw_fields.get(field).cloned() else { return Ok(()); };
    let Some(id) = reference.strip_prefix(LOCAL_VAULT_TLS_PREFIX) else { return Ok(()); };
    if !valid_vault_key_id(id) {
        return Err(format!("Saved vault TLS reference in '{field}' is invalid."));
    }
    let plaintext = match vault.read_vault_material(config_root, linscp_platform::VaultMaterialKind::Tls, id).map_err(|e| e.to_string())? {
        linscp_platform::VaultMaterialRead::Plaintext(bytes) => bytes,
        linscp_platform::VaultMaterialRead::Missing => return Err("Saved TLS material is no longer in the vault.".into()),
        linscp_platform::VaultMaterialRead::Unhandled => {
            let encrypted_path = config_root.join("keys").join(format!("{id}.tls.vault"));
            let metadata = std::fs::metadata(&encrypted_path)
                .map_err(|error| format!("Cannot read saved TLS material: {error}"))?;
            if metadata.len() > TLS_VAULT_BLOB_LIMIT + 64 {
                return Err("Encrypted TLS material file is unexpectedly large.".to_string());
            }
            let encrypted = std::fs::read(&encrypted_path)
                .map_err(|error| format!("Cannot read saved TLS material: {error}"))?;
            vault.open_session_store(&encrypted).map_err(|error| error.to_string())?
        }
    };
    if plaintext.is_empty() || plaintext.len() as u64 > TLS_VAULT_BLOB_LIMIT {
        return Err("Invalid saved TLS material size.".into());
    }
    let temp_dir = config_root.join("tmp").join("unlocked-keys").join(std::process::id().to_string());
    linscp_platform::create_private_dir(&temp_dir).map_err(|error| error.to_string())?;
    for _ in 0..8 {
        let mut random = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut random);
        let suffix = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let path = temp_dir.join(format!("{id}-{suffix}.pem"));
        match write_exclusive_private_file(&path, &plaintext) {
            Ok(()) => {
                created.push(path.clone());
                raw_fields.insert(field.to_string(), path.to_string_lossy().into_owned());
                return Ok(());
            }
            Err(linscp_platform::PlatformError::AlreadyExists(_)) => continue,
            Err(error) => {
                let _ = std::fs::remove_file(&path);
                return Err(error.to_string());
            }
        }
    }
    Err("Cannot materialize temporary TLS certificate file.".to_string())
}

fn materialize_one_vault_key(
    keyfile: &mut Option<String>,
    config_root: &Path,
    vault: &dyn SecretVault,
    created: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let Some(reference) = keyfile.as_deref() else { return Ok(()); };
    let Some(id) = reference.strip_prefix(LOCAL_VAULT_KEY_PREFIX) else { return Ok(()); };
    if !valid_vault_key_id(id) {
        return Err("Saved encrypted SSH key reference is invalid.".to_string());
    }
    let plaintext = match vault.read_vault_material(config_root, linscp_platform::VaultMaterialKind::SshPrivate, id).map_err(|e| e.to_string())? {
        linscp_platform::VaultMaterialRead::Plaintext(bytes) => bytes,
        linscp_platform::VaultMaterialRead::Missing => return Err("Saved encrypted SSH key is no longer in the vault.".into()),
        linscp_platform::VaultMaterialRead::Unhandled => {
            let encrypted_path = config_root.join("keys").join(format!("{id}.key.vault"));
            let metadata = std::fs::metadata(&encrypted_path)
                .map_err(|error| format!("Cannot read encrypted SSH key: {error}"))?;
            if metadata.len() > 1024 * 1024 {
                return Err("Encrypted SSH key file is unexpectedly large.".to_string());
            }
            let encrypted = std::fs::read(&encrypted_path)
                .map_err(|error| format!("Cannot read encrypted SSH key: {error}"))?;
            vault.open_session_store(&encrypted).map_err(|error| error.to_string())?
        }
    };
    if plaintext.is_empty() || plaintext.len() > 1024 * 1024 { return Err("Invalid saved SSH key size.".into()); }
    let public = match vault.read_vault_material(config_root, linscp_platform::VaultMaterialKind::SshPublic, id).map_err(|e| e.to_string())? {
        linscp_platform::VaultMaterialRead::Plaintext(bytes) => {
            if bytes.len() > 32 * 1024 { return Err("Saved SSH public key is unexpectedly large.".into()); }
            std::str::from_utf8(&bytes).map_err(|_| "Saved SSH public key is not UTF-8")?.to_owned()
        }
        linscp_platform::VaultMaterialRead::Missing => String::new(),
        linscp_platform::VaultMaterialRead::Unhandled => {
            let source = config_root.join("keys").join(format!("{id}.pub"));
            read_public_optional(&source)?
        }
    };
    let temp_dir = config_root.join("tmp").join("unlocked-keys").join(std::process::id().to_string());
    linscp_platform::create_private_dir(&temp_dir).map_err(|error| error.to_string())?;
    for _ in 0..8 {
        let mut random = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut random);
        let suffix = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let path = temp_dir.join(format!("{id}-{suffix}.key"));
        match write_exclusive_private_file(&path, &plaintext) {
            Ok(()) => created.push(path.clone()),
            Err(linscp_platform::PlatformError::AlreadyExists(_)) => continue,
            Err(error) => {
                let _ = std::fs::remove_file(&path);
                return Err(error.to_string());
            }
        }
        if !public.is_empty() {
            let public_path = PathBuf::from(format!("{}.pub", path.display()));
            match write_exclusive_private_file(&public_path, public.as_bytes()) {
                Ok(()) => created.push(public_path),
                Err(linscp_platform::PlatformError::AlreadyExists(_)) => {
                    let _ = std::fs::remove_file(&path);
                    created.retain(|created_path| created_path != &path);
                    continue;
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&public_path);
                    let _ = std::fs::remove_file(&path);
                    created.retain(|created_path| created_path != &path);
                    return Err(error.to_string());
                }
            }
        }
        *keyfile = Some(path.to_string_lossy().into_owned());
        return Ok(());
    }
    Err("Cannot create a temporary SSH key file.".to_string())
}

