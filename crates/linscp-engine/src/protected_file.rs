//! Authenticated, domain-separated local-vault files. Legacy plaintext is read
//! only while unlocked; callers validate it before requesting migration.
use std::path::Path;
use linscp_platform::{write_private_file_atomic, SecretVault};
use zeroize::Zeroizing;

const HEADER: &[u8] = b"LSCP-PROTECTED-FILE-1\n";

pub fn read(path: &Path, domain: &str, vault: &dyn SecretVault) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    match vault.read_protected_file(path, domain).map_err(|e| e.to_string())? {
        linscp_platform::ProtectedFileRead::Unhandled => {},
        linscp_platform::ProtectedFileRead::Missing => return Ok(None),
        linscp_platform::ProtectedFileRead::Plaintext(value) => return Ok(Some(value)),
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Cannot read {}: {e}", path.display())),
    };
    if let Some(ciphertext) = bytes.strip_prefix(HEADER) {
        let plaintext = vault.open_session_store(ciphertext).map_err(|e| e.to_string())?;
        let context = format!("LinSCP protected file: {domain}\n");
        let value = plaintext.strip_prefix(context.as_bytes()).ok_or_else(|| format!("Invalid protected {domain} file"))?;
        Ok(Some(Zeroizing::new(value.to_vec())))
    } else {
        if vault.protects_session_store() && vault.load_master_key(path.parent().unwrap_or(Path::new("."))).map_err(|e| e.to_string())?.is_none() {
            return Err("Unlock the local vault to access protected data".into());
        }
        Ok(Some(bytes))
    }
}

pub fn write(path: &Path, domain: &str, vault: &dyn SecretVault, value: &[u8]) -> Result<(), String> {
    if !vault.protects_session_store() { return Err("A password vault is required to write protected data".into()); }
    if vault.write_protected_file(path, domain, value).map_err(|e| e.to_string())? { return Ok(()); }
    let mut payload = Zeroizing::new(format!("LinSCP protected file: {domain}\n").into_bytes());
    payload.extend_from_slice(value);
    let sealed = vault.seal_session_store(&payload).map_err(|e| e.to_string())?;
    let mut bytes = HEADER.to_vec();
    bytes.extend_from_slice(&sealed);
    write_private_file_atomic(path, &bytes).map_err(|e| e.to_string())
}

pub fn migrate(path: &Path, domain: &str, vault: &dyn SecretVault, validate: impl FnOnce(&[u8]) -> Result<(), String>) -> Result<(), String> {
    match vault.read_protected_file(path, domain).map_err(|e| e.to_string())? {
        linscp_platform::ProtectedFileRead::Unhandled => {},
        linscp_platform::ProtectedFileRead::Missing => return Ok(()),
        linscp_platform::ProtectedFileRead::Plaintext(value) => return validate(&value),
    }
    let Some(value) = read(path, domain, vault)? else { return Ok(()); };
    validate(&value)?;
    let original = Zeroizing::new(std::fs::read(path).map_err(|e| e.to_string())?);
    if !original.starts_with(HEADER) { write(path, domain, vault, &value)?; }
    Ok(())
}
