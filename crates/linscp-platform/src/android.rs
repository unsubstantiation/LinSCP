//! Android-specific app-private filesystem paths, Storage Access Framework
//! (`content://`) bridge contract, and Android Keystore secret-wrapping bridge.

use std::fs::{File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use linscp_types::{FileEntry, LocalRootEntry};
use zeroize::Zeroizing;

use crate::PlatformError;

/// Bridge implemented by the Tauri Android plugin to enumerate and operate on
/// user-granted Storage Access Framework (`content://`) document trees without
/// leaking JNI types into shared Rust crates.
pub trait SafBridge: Send + Sync {
    fn granted_trees(&self) -> Result<Vec<LocalRootEntry>, PlatformError>;
    fn list_tree(&self, tree_uri: &str) -> Result<Vec<FileEntry>, PlatformError>;
    fn stat_uri(&self, uri: &str) -> Result<FileEntry, PlatformError>;
    fn read_uri_bytes(&self, uri: &str) -> Result<Vec<u8>, PlatformError>;
    fn write_uri_bytes(&self, parent_uri: &str, name: &str, data: &[u8]) -> Result<String, PlatformError>;
    fn mkdir_uri(&self, parent_uri: &str, name: &str) -> Result<String, PlatformError>;
    fn delete_uri(&self, uri: &str) -> Result<(), PlatformError>;
    fn rename_uri(&self, uri: &str, new_name: &str) -> Result<String, PlatformError>;
}

/// Optional Android Keystore hardware-backed AES-256-GCM wrapper supplied by
/// the Tauri Android plugin when running inside the Android app runtime.
pub trait KeystoreBridge: Send + Sync {
    fn wrap_master_key(&self, raw_key: &[u8; 32]) -> Result<Vec<u8>, PlatformError>;
    fn unwrap_master_key(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, PlatformError>;
}

pub fn default_config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("LINSCP_ANDROID_FILES_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir).join("config");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join(".config").join("linscp");
    }
    std::env::temp_dir().join("linscp")
}

pub fn list_roots(saf: Option<&dyn SafBridge>) -> Result<Vec<LocalRootEntry>, PlatformError> {
    let app_root = std::env::var_os("LINSCP_ANDROID_FILES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("linscp-files"));
    let mut roots = vec![LocalRootEntry {
        path: app_root.to_string_lossy().into_owned(),
        label: "App Storage".to_string(),
        kind: "app_private".to_string(),
        read_only: false,
    }];
    if let Some(bridge) = saf {
        roots.extend(bridge.granted_trees()?);
    }
    Ok(roots)
}

pub fn format_permissions(meta: &std::fs::Metadata) -> String {
    format!("{:04o}", meta.mode() & 0o7777)
}

pub fn set_mode(path: &Path, mode: u32) -> Result<(), PlatformError> {
    std::fs::set_permissions(path, Permissions::from_mode(mode & 0o7777))?;
    Ok(())
}

pub fn ensure_private_dir(dir: &Path) -> Result<(), PlatformError> {
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, Permissions::from_mode(0o700))?;
    Ok(())
}

pub fn open_private_temp_file(path: &Path) -> Result<File, PlatformError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    Ok(file)
}

pub fn create_exclusive_private_file(path: &Path, content: &[u8]) -> Result<(), PlatformError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                PlatformError::AlreadyExists(path.display().to_string())
            } else {
                PlatformError::Io(err)
            }
        })?;
    if let Err(err) = file.write_all(content).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(path);
        return Err(PlatformError::Io(err));
    }
    Ok(())
}

pub fn atomic_replace(temp_path: &Path, target_path: &Path) -> Result<(), PlatformError> {
    std::fs::rename(temp_path, target_path)?;
    Ok(())
}
