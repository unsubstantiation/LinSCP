//! Android-specific app-private filesystem paths, Storage Access Framework
//! (`content://`) bridge contract, Share Sheet staging, ForegroundService
//! lifecycle, and Android Keystore secret-wrapping bridge.

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

/// Bridge for staging incoming Android Share Sheet intents (`ACTION_SEND` /
/// `ACTION_SEND_MULTIPLE`). The Kotlin plugin resolves incoming
/// `content://` or `file://` URIs, copies bytes into the app-private staging
/// directory, and registers a `shell-manifests/{id}.json` identical to the
/// Linux `--shell-upload` flow so the Commander UI can prompt
/// “Upload N file(s) to current session?”.
pub trait ShareBridge: Send + Sync {
    /// Returns the list of staged absolute file paths created from the most
    /// recent `ACTION_SEND` intent. The Rust side then calls
    /// `record_shell_upload_manifest` to create the pending manifest.
    fn staged_share_paths(&self) -> Result<Vec<PathBuf>, PlatformError>;
    /// Explicitly stage the given URIs (content:// or file://) into
    /// `app_files/share-staging/{id}/` and return the staged paths.
    fn stage_uris(&self, uris: &[String]) -> Result<Vec<PathBuf>, PlatformError>;
}

/// Bridge for the Android `ForegroundService` that keeps the process alive
/// while transfers or `keepuptodate` watches are active. The Kotlin
/// implementation acquires a `PARTIAL_WAKE_LOCK` + `WIFI_MODE_FULL_HIGH_PERF`
/// `WifiLock`, posts a `dataSync`/`connectedDevice` notification, and
/// exposes a Cancel action that sends a Tauri event to abort the queue.
pub trait ForegroundServiceBridge: Send + Sync {
    /// Promotes the app process to foreground with an ongoing notification.
    /// `title` is shown in the notification, `ongoing_transfers` seeds the
    /// initial progress text.
    fn start(&self, title: &str, ongoing_transfers: usize) -> Result<(), PlatformError>;
    /// Updates the foreground notification with current byte progress.
    fn update_progress(&self, bytes_done: u64, bytes_total: u64) -> Result<(), PlatformError>;
    /// Demotes the service and releases WakeLock/WifiLock when all transfers
    /// and `keepuptodate` watchers have finished.
    fn stop(&self) -> Result<(), PlatformError>;
    /// Returns true if the foreground service is currently running.
    fn is_running(&self) -> bool;
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

pub fn app_files_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("LINSCP_ANDROID_FILES_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(dir);
    }
    std::env::temp_dir().join("linscp-files")
}

pub fn list_roots(saf: Option<&dyn SafBridge>) -> Result<Vec<LocalRootEntry>, PlatformError> {
    let app_root = app_files_dir();
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
    let existed = dir.exists();
    std::fs::create_dir_all(dir)?;
    if let Err(err) = std::fs::set_permissions(dir, Permissions::from_mode(0o700)) {
        if !existed || err.kind() != std::io::ErrorKind::PermissionDenied {
            return Err(PlatformError::Io(err));
        }
    }
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

/// Stage incoming Share Sheet URIs via the provided `SafBridge` into an
/// app-private directory and return the staged file paths. Each URI is read
/// through `SafBridge::read_uri_bytes` (for `content://`) or directly via
/// `std::fs` (for `file://`/absolute paths) and written atomically with
/// `0600` permissions into `app_files/share-staging/<id>/`.
pub fn stage_share_uris_via_saf(
    saf: &dyn SafBridge,
    uris: &[String],
    staging_root: &Path,
) -> Result<Vec<PathBuf>, PlatformError> {
    if uris.is_empty() {
        return Err(PlatformError::SecretVault(
            "No files shared via Android Share Sheet.".to_string(),
        ));
    }
    ensure_private_dir(staging_root)?;
    // Create a unique subdir per staging operation to avoid collisions.
    let id = {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut h);
        std::process::id().hash(&mut h);
        std::thread::current().id().hash(&mut h);
        format!("{:016x}", h.finish())
    };
    let staging_dir = staging_root.join(&id);
    ensure_private_dir(&staging_dir)?;

    let mut staged = Vec::with_capacity(uris.len());
    for raw_uri in uris {
        let uri = raw_uri.trim();
        if uri.is_empty() {
            continue;
        }
        let (bytes, suggested_name) = if uri.starts_with("content://") {
            let entry = saf.stat_uri(uri).unwrap_or(FileEntry {
                name: "shared-file".to_string(),
                size: 0,
                is_dir: false,
                is_symlink: false,
                broken_link: false,
                date: String::new(),
                mtime: 0,
                permissions: String::new(),
                owner: None,
                group: None,
            });
            let data = saf.read_uri_bytes(uri)?;
            (data, entry.name)
        } else {
            // file:// or absolute path – strip scheme if present.
            let path_str = if let Some(stripped) = uri.strip_prefix("file://") {
                stripped.to_string()
            } else {
                uri.to_string()
            };
            let data = std::fs::read(&path_str).map_err(PlatformError::Io)?;
            let name = Path::new(&path_str)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "shared-file".to_string());
            (data, name)
        };
        // Sanitize filename – reject path separators and dot segments.
        let safe_name = sanitize_staged_filename(&suggested_name);
        let target = staging_dir.join(&safe_name);
        // Avoid overwriting if duplicate name – append suffix.
        let final_target = if target.exists() {
            let stem = Path::new(&safe_name)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".to_string());
            let ext = Path::new(&safe_name)
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_default();
            let mut idx = 1u32;
            loop {
                let candidate = staging_dir.join(format!("{stem}-{idx}{ext}"));
                if !candidate.exists() {
                    break candidate;
                }
                idx += 1;
            }
        } else {
            target
        };
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&final_target)?;
        out.write_all(&bytes)?;
        out.sync_all()?;
        staged.push(final_target);
    }

    if staged.is_empty() {
        return Err(PlatformError::SecretVault(
            "No valid files to stage from Share Sheet.".to_string(),
        ));
    }
    Ok(staged)
}

fn sanitize_staged_filename(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return "shared-file".to_string();
    }
    let mut out = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch == '/' || ch == '\\' || ch == '\0' {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        "shared-file".to_string()
    } else {
        out
    }
}

pub async fn connect_ssh_agent() -> Result<Option<Box<dyn crate::AsyncStream>>, PlatformError> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct MockSaf {
        trees: Vec<LocalRootEntry>,
        files: Mutex<std::collections::HashMap<String, (FileEntry, Vec<u8>)>>,
    }

    impl SafBridge for MockSaf {
        fn granted_trees(&self) -> Result<Vec<LocalRootEntry>, PlatformError> {
            Ok(self.trees.clone())
        }
        fn list_tree(&self, _tree_uri: &str) -> Result<Vec<FileEntry>, PlatformError> {
            Ok(vec![])
        }
        fn stat_uri(&self, uri: &str) -> Result<FileEntry, PlatformError> {
            self.files
                .lock()
                .unwrap()
                .get(uri)
                .map(|(e, _)| e.clone())
                .ok_or_else(|| PlatformError::UnsupportedUri(uri.to_string()))
        }
        fn read_uri_bytes(&self, uri: &str) -> Result<Vec<u8>, PlatformError> {
            self.files
                .lock()
                .unwrap()
                .get(uri)
                .map(|(_, b)| b.clone())
                .ok_or_else(|| PlatformError::UnsupportedUri(uri.to_string()))
        }
        fn write_uri_bytes(&self, _parent_uri: &str, _name: &str, _data: &[u8]) -> Result<String, PlatformError> {
            Ok("content://mock/new".to_string())
        }
        fn mkdir_uri(&self, _parent_uri: &str, _name: &str) -> Result<String, PlatformError> {
            Ok("content://mock/dir".to_string())
        }
        fn delete_uri(&self, _uri: &str) -> Result<(), PlatformError> {
            Ok(())
        }
        fn rename_uri(&self, _uri: &str, _new_name: &str) -> Result<String, PlatformError> {
            Ok("content://mock/renamed".to_string())
        }
    }

    struct MockFg {
        running: Mutex<bool>,
    }

    impl ForegroundServiceBridge for MockFg {
        fn start(&self, _title: &str, _ongoing: usize) -> Result<(), PlatformError> {
            *self.running.lock().unwrap() = true;
            Ok(())
        }
        fn update_progress(&self, _done: u64, _total: u64) -> Result<(), PlatformError> {
            Ok(())
        }
        fn stop(&self) -> Result<(), PlatformError> {
            *self.running.lock().unwrap() = false;
            Ok(())
        }
        fn is_running(&self) -> bool {
            *self.running.lock().unwrap()
        }
    }

    #[test]
    fn saf_and_share_and_foreground_bridges_work() {
        let saf = MockSaf {
            trees: vec![LocalRootEntry {
                path: "content://com.android.externalstorage.documents/tree/primary%3ADownload".to_string(),
                label: "Downloads (SAF)".to_string(),
                kind: "saf_tree".to_string(),
                read_only: false,
            }],
            files: Mutex::new({
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "content://mock/tree/doc1".to_string(),
                    (
                        FileEntry {
                            name: "hello.txt".to_string(),
                            size: 5,
                            is_dir: false,
                            is_symlink: false,
                            broken_link: false,
                            date: String::new(),
                            mtime: 0,
                            permissions: String::new(),
                            owner: None,
                            group: None,
                        },
                        b"hello".to_vec(),
                    ),
                );
                m
            }),
        };
        let roots = list_roots(Some(&saf)).unwrap();
        assert_eq!(roots.len(), 2);
        assert!(roots.iter().any(|r| r.kind == "saf_tree"));

        let staging_root = std::env::temp_dir().join(format!("linscp-android-test-{}", std::process::id()));
        let staged = stage_share_uris_via_saf(&saf, &["content://mock/tree/doc1".to_string()], &staging_root).unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(std::fs::read(&staged[0]).unwrap(), b"hello");
        let _ = std::fs::remove_dir_all(&staging_root);

        let fg = MockFg { running: Mutex::new(false) };
        assert!(!fg.is_running());
        fg.start("Transferring 1 file", 1).unwrap();
        assert!(fg.is_running());
        fg.update_progress(512, 1024).unwrap();
        fg.stop().unwrap();
        assert!(!fg.is_running());
    }

    #[test]
    fn keystore_roundtrip_via_mock() {
        struct MockKs;
        impl KeystoreBridge for MockKs {
            fn wrap_master_key(&self, raw: &[u8; 32]) -> Result<Vec<u8>, PlatformError> {
                Ok(raw.to_vec())
            }
            fn unwrap_master_key(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
                if wrapped.len() != 32 {
                    return Err(PlatformError::SecretVault("bad len".to_string()));
                }
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(wrapped);
                Ok(out)
            }
        }
        let ks = Arc::new(MockKs);
        let mut key = [7u8; 32];
        let wrapped = ks.wrap_master_key(&key).unwrap();
        let unwrapped = ks.unwrap_master_key(&wrapped).unwrap();
        assert_eq!(&*unwrapped, &key);
    }
}
