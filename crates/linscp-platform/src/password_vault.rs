//! Password-protected wrapping for LinSCP's local master key.
//!
//! The password is used only to unwrap the random data-encryption key. The
//! password itself is never retained; the unwrapped key exists in memory only
//! while the vault is unlocked.

use std::path::Path;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::android::KeystoreBridge;
use crate::{write_private_file_atomic, PlatformError, SecretVault};

const WRAP_MAGIC: &[u8; 8] = b"LSCPVLT1";
const KEYSTORE_MAGIC: &[u8; 8] = b"LSCPKST1";
const BLOB_MAGIC: &[u8; 8] = b"LSCPBLB1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MASTER_KEY_LEN: usize = 32;
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_ITERATIONS: u32 = 3;

#[derive(Default)]
pub struct PasswordSecretVault {
    master_key: Mutex<Option<Zeroizing<[u8; MASTER_KEY_LEN]>>>,
    keystore: Mutex<Option<Arc<dyn KeystoreBridge>>>,
}

impl PasswordSecretVault {
    pub fn new() -> Self { Self::default() }

    pub fn with_keystore(keystore: Arc<dyn KeystoreBridge>) -> Self {
        Self {
            master_key: Mutex::new(None),
            keystore: Mutex::new(Some(keystore)),
        }
    }

    pub fn set_keystore(&self, keystore: Arc<dyn KeystoreBridge>) {
        if let Ok(mut guard) = self.keystore.lock() {
            *guard = Some(keystore);
        }
    }

    pub fn has_keystore(&self) -> bool {
        self.keystore.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// `setup_required`, `locked`, or `unlocked`.
    pub fn status(&self, config_dir: &Path) -> Result<&'static str, PlatformError> {
        if self.master_key.lock().map_err(lock_error)?.is_some() { return Ok("unlocked"); }
        match std::fs::read(config_dir.join("sessions.key")) {
            Ok(bytes) if bytes.starts_with(WRAP_MAGIC) || bytes.starts_with(KEYSTORE_MAGIC) => Ok("locked"),
            Ok(_) => Ok("setup_required"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok("setup_required"),
            Err(err) => Err(PlatformError::Io(err)),
        }
    }

    /// Set the password on first use (migrating any legacy master key), or
    /// unlock an existing password-wrapped (or Android Keystore + password) master key.
    pub fn unlock_or_setup(&self, config_dir: &Path, password: &str, legacy_vault: &dyn SecretVault) -> Result<(), PlatformError> {
        validate_password(password)?;
        let keystore = self.keystore.lock().map_err(lock_error)?.clone();
        let key_path = config_dir.join("sessions.key");
        let existing = match std::fs::read(&key_path) {
            Ok(bytes) => Some(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(PlatformError::Io(err)),
        };
        let mut needs_save = false;
        let master = match existing.as_deref() {
            Some(bytes) if bytes.starts_with(KEYSTORE_MAGIC) => {
                let ks = keystore.as_deref().ok_or_else(|| {
                    vault_error("Vault key is bound to Android Keystore, which is unavailable on this host")
                })?;
                let inner = ks.unwrap_key(&bytes[KEYSTORE_MAGIC.len()..])?;
                if !inner.starts_with(WRAP_MAGIC) {
                    return Err(vault_error("Corrupted Android Keystore vault envelope"));
                }
                unwrap_master_key(&inner, password)?
            }
            Some(bytes) if bytes.starts_with(WRAP_MAGIC) => {
                let unwrapped = unwrap_master_key(bytes, password)?;
                if keystore.is_some() {
                    needs_save = true;
                }
                unwrapped
            }
            Some(_) => {
                needs_save = true;
                legacy_vault.load_master_key(config_dir)?.ok_or_else(|| vault_error("Legacy master key is missing"))?
            }
            None => {
                needs_save = true;
                let mut generated = Zeroizing::new([0u8; MASTER_KEY_LEN]);
                rand::thread_rng().fill_bytes(&mut *generated);
                generated
            }
        };
        if needs_save {
            let wrapped = wrap_master_key(&master, password)?;
            let persisted = if let Some(ks) = keystore.as_deref() {
                let hw = ks.wrap_key(&wrapped)?;
                let mut out = Vec::with_capacity(KEYSTORE_MAGIC.len() + hw.len());
                out.extend_from_slice(KEYSTORE_MAGIC);
                out.extend_from_slice(&hw);
                out
            } else {
                wrapped
            };
            write_private_file_atomic(&key_path, &persisted)?;
        }
        *self.master_key.lock().map_err(lock_error)? = Some(master);
        Ok(())
    }

    pub fn lock(&self) -> Result<(), PlatformError> {
        *self.master_key.lock().map_err(lock_error)? = None;
        Ok(())
    }

    pub fn seal_local_blob(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
        let master = self.master_key_copy()?;
        seal_blob_with_master_key(plaintext, &master)
    }

    pub fn open_local_blob(&self, encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        let master = self.master_key_copy()?;
        open_blob_with_master_key(encrypted, &master)
    }

    fn master_key_copy(&self) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, PlatformError> {
        self.master_key.lock().map_err(lock_error)?.as_ref()
            .map(|key| Zeroizing::new(**key))
            .ok_or_else(|| vault_error("Vault is locked"))
    }
}

impl SecretVault for PasswordSecretVault {
    fn protects_session_store(&self) -> bool { true }

    fn seal_session_store(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
        self.seal_local_blob(plaintext)
    }

    fn open_session_store(&self, encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        self.open_local_blob(encrypted)
    }

    fn load_master_key(&self, _config_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, PlatformError> {
        let guard = self.master_key.lock().map_err(lock_error)?;
        Ok(guard.as_ref().map(|key| Zeroizing::new(**key)))
    }

    fn load_or_create_master_key(&self, _config_dir: &Path) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        self.master_key_copy()
    }
}

impl crate::ServiceSecretVault for PasswordSecretVault {
    fn status(&self, config_dir: &Path) -> Result<&'static str, PlatformError> {
        PasswordSecretVault::status(self, config_dir)
    }
    fn unlock_or_setup(&self, config_dir: &Path, password: &str, legacy: &dyn SecretVault) -> Result<(), PlatformError> {
        PasswordSecretVault::unlock_or_setup(self, config_dir, password, legacy)
    }
    fn lock(&self) -> Result<(), PlatformError> {
        PasswordSecretVault::lock(self)
    }
}

/// Encrypt a local-vault blob with an already unlocked master key.
pub fn seal_blob_with_master_key(plaintext: &[u8], master: &[u8; 32]) -> Result<Vec<u8>, PlatformError> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(master).map_err(|_| vault_error("Invalid local vault key"))?;
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: BLOB_MAGIC })
        .map_err(|_| vault_error("Could not encrypt local vault data"))?;
    let mut output = Vec::with_capacity(BLOB_MAGIC.len() + nonce.len() + ciphertext.len());
    output.extend_from_slice(BLOB_MAGIC);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Open a local-vault blob using the source key contained inside an already
/// authenticated portable backup. The plaintext must never be written to disk.
pub fn open_blob_with_master_key(encrypted: &[u8], master: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
    if encrypted.len() < BLOB_MAGIC.len() + NONCE_LEN + 16 || !encrypted.starts_with(BLOB_MAGIC) {
        return Err(vault_error("Invalid encrypted local vault data"));
    }
    let nonce_start = BLOB_MAGIC.len();
    let ciphertext_start = nonce_start + NONCE_LEN;
    let cipher = Aes256Gcm::new_from_slice(master).map_err(|_| vault_error("Invalid local vault key"))?;
    let plaintext = cipher.decrypt(Nonce::from_slice(&encrypted[nonce_start..ciphertext_start]),
        Payload { msg: &encrypted[ciphertext_start..], aad: BLOB_MAGIC })
        .map_err(|_| vault_error("Could not decrypt local vault data"))?;
    Ok(Zeroizing::new(plaintext))
}

fn validate_password(password: &str) -> Result<(), PlatformError> {
    let length = password.encode_utf16().count();
    if !(6..=1024).contains(&length) { return Err(vault_error("Vault password must be 6 to 1024 UTF-16 units")); }
    Ok(())
}

fn derive_wrapping_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
    let params = Params::new(ARGON_MEMORY_KIB, ARGON_ITERATIONS, 1, Some(32)).map_err(|_| vault_error("Invalid password KDF parameters"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password.as_bytes(), salt, &mut *key).map_err(|_| vault_error("Could not derive vault key"))?;
    Ok(key)
}

fn wrap_master_key(master: &[u8; MASTER_KEY_LEN], password: &str) -> Result<Vec<u8>, PlatformError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let wrapping_key = derive_wrapping_key(password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key[..]).map_err(|_| vault_error("Invalid vault wrapping key"))?;
    let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: master, aad: WRAP_MAGIC })
        .map_err(|_| vault_error("Could not protect vault master key"))?;
    let mut output = Vec::with_capacity(WRAP_MAGIC.len() + SALT_LEN + NONCE_LEN + encrypted.len());
    output.extend_from_slice(WRAP_MAGIC);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

fn unwrap_master_key(bytes: &[u8], password: &str) -> Result<Zeroizing<[u8; MASTER_KEY_LEN]>, PlatformError> {
    let header_len = WRAP_MAGIC.len() + SALT_LEN + NONCE_LEN;
    if bytes.len() < header_len + MASTER_KEY_LEN + 16 { return Err(vault_error("Corrupted password-protected vault key")); }
    let salt_start = WRAP_MAGIC.len();
    let nonce_start = salt_start + SALT_LEN;
    let ciphertext_start = nonce_start + NONCE_LEN;
    let wrapping_key = derive_wrapping_key(password, &bytes[salt_start..nonce_start])?;
    let cipher = Aes256Gcm::new_from_slice(&wrapping_key[..]).map_err(|_| vault_error("Invalid vault wrapping key"))?;
    let plaintext = Zeroizing::new(cipher.decrypt(Nonce::from_slice(&bytes[nonce_start..ciphertext_start]),
        Payload { msg: &bytes[ciphertext_start..], aad: WRAP_MAGIC })
        .map_err(|_| vault_error("Incorrect vault password or damaged vault"))?);
    if plaintext.len() != MASTER_KEY_LEN { return Err(vault_error("Invalid unwrapped vault key length")); }
    let mut master = Zeroizing::new([0u8; MASTER_KEY_LEN]);
    master.copy_from_slice(&plaintext);
    Ok(master)
}

fn lock_error<T>(_error: std::sync::PoisonError<T>) -> PlatformError { vault_error("Local vault state is unavailable") }
fn vault_error(message: &str) -> PlatformError { PlatformError::SecretVault(message.to_string()) }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NativeSecretVault;

    #[test]
    fn password_vault_setup_unlock_and_lock_round_trip() {
        let dir = std::env::temp_dir().join(format!("linscp-password-vault-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = NativeSecretVault::new();
        let vault = PasswordSecretVault::new();
        assert_eq!(vault.status(&dir).unwrap(), "setup_required");
        vault.unlock_or_setup(&dir, "correct horse battery staple", &legacy).unwrap();
        assert_eq!(vault.status(&dir).unwrap(), "unlocked");
        let plaintext = b"private key material";
        let encrypted = vault.seal_local_blob(plaintext).unwrap();
        assert!(!encrypted.windows(plaintext.len()).any(|window| window == &plaintext[..]));
        let opened = vault.open_local_blob(&encrypted).unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());
        vault.lock().unwrap();
        assert_eq!(vault.status(&dir).unwrap(), "locked");
        assert!(vault.unlock_or_setup(&dir, "wrong password here", &legacy).is_err());
        vault.unlock_or_setup(&dir, "correct horse battery staple", &legacy).unwrap();
        let opened = vault.open_local_blob(&encrypted).unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());
        vault.lock().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retired_hardware_key_prefixes_are_rejected() {
        // The DPAPI/Keystore wrappers were never wired; their `dpapi1$` and
        // `aks1$` prefixes were removed from the decoder, so a sessions.key
        // carrying one must fail closed instead of loading a wrong key.
        let dir = std::env::temp_dir().join(format!(
            "linscp-retired-prefix-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = NativeSecretVault::new();
        for prefix in ["dpapi1$", "aks1$"] {
            std::fs::write(dir.join("sessions.key"), format!("{prefix}AAAA\n")).unwrap();
            let err = legacy.load_master_key(&dir).unwrap_err();
            assert!(
                matches!(err, PlatformError::SecretVault(ref message) if message.contains("base64")),
                "{prefix} must fail closed, got {err:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn android_keystore_bridge_wraps_and_upgrades_master_key_envelope() {
        struct MockKeystore {
            secret: [u8; 32],
        }
        impl KeystoreBridge for MockKeystore {
            fn wrap_key(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
                let mut nonce = [0u8; NONCE_LEN];
                rand::thread_rng().fill_bytes(&mut nonce);
                let cipher = Aes256Gcm::new_from_slice(&self.secret).unwrap();
                let ct = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: KEYSTORE_MAGIC }).unwrap();
                let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
                out.extend_from_slice(&nonce);
                out.extend_from_slice(&ct);
                Ok(out)
            }
            fn unwrap_key(&self, wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
                if wrapped.len() < NONCE_LEN + 16 {
                    return Err(vault_error("Invalid keystore ciphertext"));
                }
                let cipher = Aes256Gcm::new_from_slice(&self.secret).unwrap();
                let pt = cipher
                    .decrypt(Nonce::from_slice(&wrapped[..NONCE_LEN]), Payload { msg: &wrapped[NONCE_LEN..], aad: KEYSTORE_MAGIC })
                    .map_err(|_| vault_error("Keystore unwrap failed"))?;
                Ok(Zeroizing::new(pt))
            }
        }

        let dir = std::env::temp_dir().join(format!("linscp-keystore-vault-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = NativeSecretVault::new();
        let plain_vault = PasswordSecretVault::new();
        plain_vault.unlock_or_setup(&dir, "correct horse battery staple", &legacy).unwrap();
        let sealed = plain_vault.seal_local_blob(b"site-secret").unwrap();
        plain_vault.lock().unwrap();
        assert!(std::fs::read(dir.join("sessions.key")).unwrap().starts_with(WRAP_MAGIC));

        let ks = Arc::new(MockKeystore { secret: [0x5a; 32] });
        let hw_vault = PasswordSecretVault::with_keystore(ks.clone());
        assert_eq!(hw_vault.status(&dir).unwrap(), "locked");
        hw_vault.unlock_or_setup(&dir, "correct horse battery staple", &legacy).unwrap();
        let disk = std::fs::read(dir.join("sessions.key")).unwrap();
        assert!(disk.starts_with(KEYSTORE_MAGIC));
        assert_eq!(hw_vault.open_local_blob(&sealed).unwrap().as_slice(), b"site-secret");
        hw_vault.lock().unwrap();

        // Without the device Keystore key, an offline copy fails closed even with the right password.
        let offline = PasswordSecretVault::new();
        assert!(offline.unlock_or_setup(&dir, "correct horse battery staple", &legacy).is_err());

        // With the device Keystore key, unlocking succeeds and wrong passwords still fail.
        let reopened = PasswordSecretVault::with_keystore(ks);
        assert!(reopened.unlock_or_setup(&dir, "wrong password!", &legacy).is_err());
        reopened.unlock_or_setup(&dir, "correct horse battery staple", &legacy).unwrap();
        assert_eq!(reopened.open_local_blob(&sealed).unwrap().as_slice(), b"site-secret");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
