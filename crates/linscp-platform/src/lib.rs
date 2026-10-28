//! OS-isolated local filesystem, configuration directory, secret-vault, and
//! directory-watcher abstractions (`linux`, `windows`, and `android`).
//!
//! No crate outside `linscp-platform` and `linscp-tauri` may depend directly
//! on Win32, POSIX, or Android platform APIs.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use filetime::{set_file_mtime, FileTime};
use linscp_types::{FileEntry, LocalRootEntry};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

pub mod gssapi_sys;
pub mod gui_os;
pub mod terminal;
pub mod watcher;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
use linux as sys;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
use windows as sys;

#[cfg(target_os = "android")]
pub mod android;
#[cfg(target_os = "android")]
use android as sys;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
mod fallback_unix {
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use linscp_types::LocalRootEntry;

    use crate::PlatformError;

    pub fn default_config_dir() -> PathBuf {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(".config")
            .join("linscp")
    }

    pub fn list_roots() -> Vec<LocalRootEntry> {
        vec![LocalRootEntry {
            path: "/".to_string(),
            label: "/".to_string(),
            kind: "posix".to_string(),
            read_only: false,
        }]
    }

    pub fn format_permissions(_meta: &std::fs::Metadata) -> String {
        String::new()
    }

    pub fn set_mode(_path: &Path, _mode: u32) -> Result<(), PlatformError> {
        Ok(())
    }

    pub fn ensure_private_dir(dir: &Path) -> Result<(), PlatformError> {
        std::fs::create_dir_all(dir)?;
        Ok(())
    }

    pub fn open_private_temp_file(path: &Path) -> Result<File, PlatformError> {
        Ok(OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?)
    }

    pub fn create_exclusive_private_file(path: &Path, content: &[u8]) -> Result<(), PlatformError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    PlatformError::AlreadyExists(path.display().to_string())
                } else {
                    PlatformError::Io(err)
                }
            })?;
        file.write_all(content)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn atomic_replace(temp_path: &Path, target_path: &Path) -> Result<(), PlatformError> {
        std::fs::rename(temp_path, target_path)?;
        Ok(())
    }

    pub async fn connect_ssh_agent() -> Result<Option<Box<dyn crate::AsyncStream>>, PlatformError> {
        Ok(None)
    }
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
use fallback_unix as sys;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

const MASTER_KEY_LEN: usize = 32;
const DPAPI_KEY_PREFIX: &str = "dpapi1$";
#[cfg(target_os = "android")]
const ANDROID_KEYSTORE_PREFIX: &str = "aks1$";

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("Filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Target file already exists: {0}")]
    AlreadyExists(String),
    #[error("Unsupported local URI or path: {0}")]
    UnsupportedUri(String),
    #[error("Secret vault error: {0}")]
    SecretVault(String),
    #[error("Directory watcher error: {0}")]
    Watch(String),
}

/// Bidirectional async byte stream (e.g. Unix `SSH_AUTH_SOCK`, Windows
/// `\\.\pipe\openssh-ssh-agent`, or an in-memory duplex channel) usable by
/// platform-neutral protocol crates without exposing OS socket types.
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Connects to the host OS SSH agent if one is reachable (`SSH_AUTH_SOCK` on
/// Linux, `\\.\pipe\openssh-ssh-agent` on Windows, `None` on Android).
pub async fn connect_system_ssh_agent() -> Result<Option<Box<dyn AsyncStream>>, PlatformError> {
    sys::connect_ssh_agent().await
}

/// Platform-neutral local filesystem contract consumed by the transfer engine,
/// synchronizer, CLI, and Commander UI.
pub trait LocalFs: Send + Sync {
    fn list_roots(&self) -> Result<Vec<LocalRootEntry>, PlatformError>;
    fn list_dir(&self, path: &str) -> Result<Vec<FileEntry>, PlatformError>;
    fn stat(&self, path: &str) -> Result<FileEntry, PlatformError>;
    fn mkdir_all(&self, path: &str) -> Result<(), PlatformError>;
    fn remove_file(&self, path: &str) -> Result<(), PlatformError>;
    fn remove_dir_all(&self, path: &str) -> Result<(), PlatformError>;
    fn rename(&self, from: &str, to: &str) -> Result<(), PlatformError>;
    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, PlatformError>;
    fn write_bytes_atomic(&self, path: &str, data: &[u8]) -> Result<(), PlatformError>;
    fn set_mtime(&self, path: &str, mtime: i64) -> Result<(), PlatformError>;
    fn set_permissions_mode(&self, path: &str, mode: u32) -> Result<(), PlatformError>;
}

/// Platform-neutral `sessions.key` master-key vault (`0600` private file on
/// Linux, optional DPAPI wrapping on Windows, optional Keystore wrapping on Android).
pub trait SecretVault: Send + Sync {
    fn load_master_key(&self, config_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, PlatformError>;
    fn load_or_create_master_key(&self, config_dir: &Path) -> Result<Zeroizing<[u8; 32]>, PlatformError>;
}

#[derive(Default)]
pub struct NativeLocalFs {
    #[cfg(target_os = "android")]
    saf: Option<std::sync::Arc<dyn android::SafBridge>>,
}

impl NativeLocalFs {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(target_os = "android")]
    pub fn with_saf(saf: std::sync::Arc<dyn android::SafBridge>) -> Self {
        Self { saf: Some(saf) }
    }
}

fn resolve_os_path(path: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        windows::to_extended_length_path(Path::new(path))
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from(path)
    }
}

fn entry_from_symlink_meta(
    name: String,
    full_path: &Path,
    meta: &std::fs::Metadata,
) -> FileEntry {
    let file_type = meta.file_type();
    let is_symlink = file_type.is_symlink();
    let (is_dir, broken_link) = if is_symlink {
        match std::fs::metadata(full_path) {
            Ok(target_meta) => (target_meta.is_dir(), false),
            Err(_) => (false, true),
        }
    } else {
        (file_type.is_dir(), false)
    };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    FileEntry {
        name,
        size: if is_dir { 0 } else { meta.len() },
        is_dir,
        is_symlink,
        broken_link,
        date: gui_os::format_listing_date(mtime),
        mtime,
        permissions: sys::format_permissions(meta),
        owner: None,
        group: None,
    }
}

impl LocalFs for NativeLocalFs {
    fn list_roots(&self) -> Result<Vec<LocalRootEntry>, PlatformError> {
        #[cfg(target_os = "android")]
        {
            sys::list_roots(self.saf.as_deref())
        }
        #[cfg(not(target_os = "android"))]
        {
            Ok(sys::list_roots())
        }
    }

    fn list_dir(&self, path: &str) -> Result<Vec<FileEntry>, PlatformError> {
        if path.starts_with("content://") {
            #[cfg(target_os = "android")]
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.list_tree(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }

        let resolved = resolve_os_path(path);
        let mut entries = Vec::new();
        for item in std::fs::read_dir(&resolved)? {
            let item = item?;
            let item_path = item.path();
            let meta = std::fs::symlink_metadata(&item_path)?;
            let name = item.file_name().to_string_lossy().into_owned();
            entries.push(entry_from_symlink_meta(name, &item_path, &meta));
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<FileEntry, PlatformError> {
        if path.starts_with("content://") {
            #[cfg(target_os = "android")]
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.stat_uri(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        let resolved = resolve_os_path(path);
        let meta = std::fs::symlink_metadata(&resolved)?;
        let name = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        Ok(entry_from_symlink_meta(name, &resolved, &meta))
    }

    fn mkdir_all(&self, path: &str) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        std::fs::create_dir_all(resolve_os_path(path))?;
        Ok(())
    }

    fn remove_file(&self, path: &str) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            #[cfg(target_os = "android")]
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.delete_uri(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        std::fs::remove_file(resolve_os_path(path))?;
        Ok(())
    }

    fn remove_dir_all(&self, path: &str) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            #[cfg(target_os = "android")]
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.delete_uri(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        std::fs::remove_dir_all(resolve_os_path(path))?;
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), PlatformError> {
        if from.starts_with("content://") || to.starts_with("content://") {
            return Err(PlatformError::UnsupportedUri(from.to_string()));
        }
        sys::atomic_replace(Path::new(from), Path::new(to))
    }

    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, PlatformError> {
        if path.starts_with("content://") {
            #[cfg(target_os = "android")]
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.read_uri_bytes(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        Ok(std::fs::read(resolve_os_path(path))?)
    }

    fn write_bytes_atomic(&self, path: &str, data: &[u8]) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        let target = Path::new(path);
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(resolve_os_path(&parent.to_string_lossy()))?;
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(
            ".{}.tmp.{}.{}",
            target
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default(),
            std::process::id(),
            seq
        );
        let temp_path = parent.join(temp_name);
        {
            let mut f = std::fs::File::create(resolve_os_path(&temp_path.to_string_lossy()))?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        if let Err(err) = sys::atomic_replace(&temp_path, target) {
            let _ = std::fs::remove_file(resolve_os_path(&temp_path.to_string_lossy()));
            return Err(err);
        }
        Ok(())
    }

    fn set_mtime(&self, path: &str, mtime: i64) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        set_file_mtime(resolve_os_path(path), FileTime::from_unix_time(mtime, 0))?;
        Ok(())
    }

    fn set_permissions_mode(&self, path: &str, mode: u32) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        sys::set_mode(Path::new(path), mode)
    }
}

/// Default per-user configuration directory (`~/.config/linscp` on Linux,
/// `%APPDATA%\LinSCP` on Windows, app-private `config` on Android).
pub fn default_config_dir() -> PathBuf {
    if let Some(override_dir) = std::env::var_os("LINSCP_CONFIG_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(override_dir);
    }
    sys::default_config_dir()
}

/// Alias used by `CommanderService` for the active per-user config directory.
pub fn config_dir() -> PathBuf {
    default_config_dir()
}

/// Atomically writes sensitive configuration files (`sessions.ini`,
/// `sessions.key`, `sshhostkeys`) with owner-only permissions.
pub fn write_private_file_atomic(target: &Path, content: &[u8]) -> Result<(), PlatformError> {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    sys::ensure_private_dir(parent)?;

    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "linscp".to_string());
    let temp_path = parent.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));

    {
        let mut file = sys::open_private_temp_file(&temp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }

    if let Err(err) = sys::atomic_replace(&temp_path, target) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(err);
    }
    Ok(())
}

/// Creates `path` (and missing parent directories) with owner-only (`0700` on Unix) permissions.
pub fn create_private_dir(path: &Path) -> Result<(), PlatformError> {
    sys::ensure_private_dir(path)
}

/// Creates a brand-new owner-only file (`O_CREAT | O_EXCL`, `0600` on Unix),
/// refusing to overwrite an existing file (used by `ConvertPpkToOpenSsh`).
pub fn write_exclusive_private_file(target: &Path, content: &[u8]) -> Result<(), PlatformError> {
    sys::create_exclusive_private_file(target, content)
}

#[derive(Default)]
pub struct NativeSecretVault {
    #[cfg(target_os = "windows")]
    wrap_new_keys_with_dpapi: bool,
    #[cfg(target_os = "android")]
    keystore: Option<std::sync::Arc<dyn android::KeystoreBridge>>,
}

impl NativeSecretVault {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(target_os = "windows")]
    pub fn with_windows_dpapi() -> Self {
        Self {
            wrap_new_keys_with_dpapi: true,
        }
    }

    #[cfg(target_os = "android")]
    pub fn with_android_keystore(keystore: std::sync::Arc<dyn android::KeystoreBridge>) -> Self {
        Self {
            keystore: Some(keystore),
        }
    }
}

fn decode_stored_master_key(
    raw_bytes: &[u8],
    #[cfg(target_os = "android")] keystore: Option<&dyn android::KeystoreBridge>,
) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
    if raw_bytes.len() == MASTER_KEY_LEN {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(raw_bytes);
        return Ok(out);
    }
    let text = std::str::from_utf8(raw_bytes)
        .map_err(|_| PlatformError::SecretVault("Invalid master key encoding".to_string()))?
        .trim();

    if let Some(dpapi_b64) = text.strip_prefix(DPAPI_KEY_PREFIX) {
        #[cfg(target_os = "windows")]
        {
            let blob = BASE64
                .decode(dpapi_b64.as_bytes())
                .map_err(|_| PlatformError::SecretVault("Corrupted DPAPI master key".to_string()))?;
            let unwrapped = windows::dpapi_unprotect(&blob)?;
            if unwrapped.len() != MASTER_KEY_LEN {
                return Err(PlatformError::SecretVault(
                    "Invalid DPAPI master key length".to_string(),
                ));
            }
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(&unwrapped);
            return Ok(out);
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = dpapi_b64;
            return Err(PlatformError::SecretVault(
                "DPAPI-protected sessions.key can only be unlocked on Windows".to_string(),
            ));
        }
    }

    #[cfg(target_os = "android")]
    if let Some(aks_b64) = text.strip_prefix(ANDROID_KEYSTORE_PREFIX) {
        let Some(bridge) = keystore else {
            return Err(PlatformError::SecretVault(
                "Android Keystore bridge is required to unlock sessions.key".to_string(),
            ));
        };
        let blob = BASE64
            .decode(aks_b64.as_bytes())
            .map_err(|_| PlatformError::SecretVault("Corrupted Keystore master key".to_string()))?;
        return bridge.unwrap_master_key(&blob);
    }

    let decoded = Zeroizing::new(
        BASE64
            .decode(text.as_bytes())
            .map_err(|_| PlatformError::SecretVault("Invalid base64 master key".to_string()))?,
    );
    if decoded.len() != MASTER_KEY_LEN {
        return Err(PlatformError::SecretVault(
            "Invalid sessions.key length".to_string(),
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&decoded);
    Ok(out)
}

impl SecretVault for NativeSecretVault {
    fn load_master_key(
        &self,
        config_dir: &Path,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, PlatformError> {
        let key_path = config_dir.join("sessions.key");
        let raw = match std::fs::read(&key_path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(PlatformError::Io(err)),
        };
        #[cfg(target_os = "android")]
        let key = decode_stored_master_key(&raw, self.keystore.as_deref())?;
        #[cfg(not(target_os = "android"))]
        let key = decode_stored_master_key(&raw)?;
        Ok(Some(key))
    }

    fn load_or_create_master_key(
        &self,
        config_dir: &Path,
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        if let Some(existing) = self.load_master_key(config_dir)? {
            return Ok(existing);
        }
        let mut generated = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *generated);
        let key_path = config_dir.join("sessions.key");

        #[cfg(target_os = "windows")]
        if self.wrap_new_keys_with_dpapi {
            let wrapped = windows::dpapi_protect(&*generated)?;
            let encoded = format!("{DPAPI_KEY_PREFIX}{}\n", BASE64.encode(wrapped));
            write_private_file_atomic(&key_path, encoded.as_bytes())?;
            return Ok(generated);
        }

        #[cfg(target_os = "android")]
        if let Some(bridge) = self.keystore.as_deref() {
            let wrapped = bridge.wrap_master_key(&generated)?;
            let encoded = format!("{ANDROID_KEYSTORE_PREFIX}{}\n", BASE64.encode(wrapped));
            write_private_file_atomic(&key_path, encoded.as_bytes())?;
            return Ok(generated);
        }

        let encoded = format!("{}\n", BASE64.encode(*generated));
        write_private_file_atomic(&key_path, encoded.as_bytes())?;
        Ok(generated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_private_write_and_local_fs_operations_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "linscp-platform-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let fs = NativeLocalFs::new();
        fs.mkdir_all(&dir.to_string_lossy()).unwrap();

        let target = dir.join("sessions.ini");
        write_private_file_atomic(&target, b"[demo]\nhost=example.com\n").expect("write v1");
        write_private_file_atomic(&target, b"[demo]\nhost=updated.example.com\n")
            .expect("replace v2");

        let body = fs.read_bytes(&target.to_string_lossy()).expect("read back");
        assert_eq!(body, b"[demo]\nhost=updated.example.com\n");

        fs.set_mtime(&target.to_string_lossy(), 1_700_000_000)
            .expect("set mtime");
        let st = fs.stat(&target.to_string_lossy()).expect("stat");
        assert_eq!(st.mtime, 1_700_000_000);

        // Exclusive private write refuses to overwrite an existing file
        let excl_err = write_exclusive_private_file(&target, b"clobber").unwrap_err();
        assert!(matches!(excl_err, PlatformError::AlreadyExists(_)));

        // SecretVault round-trip
        let vault = NativeSecretVault::new();
        let k1 = vault.load_or_create_master_key(&dir).expect("create master key");
        let k2 = vault.load_master_key(&dir).expect("load master key").unwrap();
        assert_eq!(*k1, *k2);

        fs.remove_dir_all(&dir.to_string_lossy()).unwrap();
    }
}
