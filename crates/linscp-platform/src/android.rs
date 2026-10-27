//! Android platform implementation (app-private directories, Storage Access
//! Framework `content://` URI routing, and foreground transfer lifecycle hooks).

use std::path::PathBuf;
use std::sync::{OnceLock, RwLock};

use linscp_types::{FileEntry, LocalRootEntry};

use crate::PlatformError;

/// Bridge registered at runtime by the Tauri Android Kotlin plugin to resolve
/// Storage Access Framework (`content://`) document trees via `ContentResolver`.
pub trait SafBridge: Send + Sync {
    fn persisted_roots(&self) -> Vec<LocalRootEntry>;
    fn list_tree(&self, tree_uri: &str) -> Result<Vec<FileEntry>, PlatformError>;
}

static SAF_BRIDGE: OnceLock<RwLock<Option<Box<dyn SafBridge>>>> = OnceLock::new();

fn bridge_slot() -> &'static RwLock<Option<Box<dyn SafBridge>>> {
    SAF_BRIDGE.get_or_init(|| RwLock::new(None))
}

pub fn register_saf_bridge(bridge: Box<dyn SafBridge>) {
    if let Ok(mut guard) = bridge_slot().write() {
        *guard = Some(bridge);
    }
}

pub fn is_saf_uri(path: &str) -> bool {
    path.starts_with("content://")
}

pub fn default_config_dir() -> PathBuf {
    if let Some(files_dir) = std::env::var_os("LINSCP_ANDROID_FILES_DIR") {
        if !files_dir.is_empty() {
            return PathBuf::from(files_dir).join("LinSCP");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".config").join("LinSCP");
        }
    }
    std::env::temp_dir().join("LinSCP")
}

pub fn list_roots() -> Vec<LocalRootEntry> {
    let mut roots = Vec::new();
    let app_dir = default_config_dir();
    roots.push(LocalRootEntry {
        path: app_dir.to_string_lossy().into_owned(),
        label: "App Storage".to_string(),
        kind: "app_private".to_string(),
        read_only: false,
    });
    if let Ok(guard) = bridge_slot().read() {
        if let Some(bridge) = guard.as_ref() {
            roots.extend(bridge.persisted_roots());
        }
    }
    roots
}

pub fn list_saf_dir(uri: &str) -> Result<Vec<FileEntry>, PlatformError> {
    if let Ok(guard) = bridge_slot().read() {
        if let Some(bridge) = guard.as_ref() {
            return bridge.list_tree(uri);
        }
    }
    Err(PlatformError::UnsupportedSafUri(uri.to_string()))
}
