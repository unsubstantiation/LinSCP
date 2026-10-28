//! Android-specific Tauri plugin wiring.
//!
//! This module bridges the Kotlin Android layer (`gen/android/app/src/main/java/io/linscp/commander/*`)
//! with the pure-Rust platform abstractions in `linscp-platform::android`.
//! On non-Android hosts (Linux/Windows CI) the same types compile as no-op
//! stubs so `cargo test --workspace` remains green everywhere.

#[cfg(target_os = "android")]
mod imp {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use linscp_platform::android::{
        app_files_dir, stage_share_uris_via_saf, ForegroundServiceBridge, KeystoreBridge,
        SafBridge, ShareBridge,
    };
    use linscp_platform::PlatformError;
    use linscp_types::{FileEntry, LocalRootEntry};
    use zeroize::Zeroizing;

    #[derive(Default)]
    pub struct AndroidState {
        saf: Mutex<Option<Arc<dyn SafBridge>>>,
        share: Mutex<Option<Arc<dyn ShareBridge>>>,
        fg: Mutex<Option<Arc<dyn ForegroundServiceBridge>>>,
        keystore: Mutex<Option<Arc<dyn KeystoreBridge>>>,
    }

    impl AndroidState {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn set_saf(&self, bridge: Arc<dyn SafBridge>) {
            *self.saf.lock().unwrap() = Some(bridge);
        }
        pub fn set_share(&self, bridge: Arc<dyn ShareBridge>) {
            *self.share.lock().unwrap() = Some(bridge);
        }
        pub fn set_foreground_service(&self, bridge: Arc<dyn ForegroundServiceBridge>) {
            *self.fg.lock().unwrap() = Some(bridge);
        }
        pub fn set_keystore(&self, bridge: Arc<dyn KeystoreBridge>) {
            *self.keystore.lock().unwrap() = Some(bridge);
        }
        pub fn granted_trees(&self) -> Result<Vec<LocalRootEntry>, PlatformError> {
            let guard = self.saf.lock().unwrap();
            if let Some(bridge) = guard.as_deref() {
                bridge.granted_trees()
            } else {
                Ok(Vec::new())
            }
        }
        pub fn list_tree(&self, tree_uri: &str) -> Result<Vec<FileEntry>, PlatformError> {
            let guard = self.saf.lock().unwrap();
            if let Some(bridge) = guard.as_deref() {
                bridge.list_tree(tree_uri)
            } else {
                Err(PlatformError::UnsupportedUri(tree_uri.to_string()))
            }
        }
        pub fn stage_share_uris(&self, uris: &[String]) -> Result<Vec<PathBuf>, PlatformError> {
            if let Some(bridge) = self.share.lock().unwrap().as_deref() {
                return bridge.stage_uris(uris);
            }
            let saf_guard = self.saf.lock().unwrap();
            let saf = saf_guard
                .as_deref()
                .ok_or_else(|| PlatformError::UnsupportedUri("No SAF bridge registered".to_string()))?;
            let staging_root = app_files_dir().join("share-staging");
            stage_share_uris_via_saf(saf, uris, &staging_root)
        }
        pub fn foreground_start(&self, title: &str, ongoing: usize) -> Result<(), PlatformError> {
            if let Some(bridge) = self.fg.lock().unwrap().as_deref() {
                bridge.start(title, ongoing)
            } else {
                Ok(())
            }
        }
        pub fn foreground_update(&self, done: u64, total: u64) -> Result<(), PlatformError> {
            if let Some(bridge) = self.fg.lock().unwrap().as_deref() {
                bridge.update_progress(done, total)
            } else {
                Ok(())
            }
        }
        pub fn foreground_stop(&self) -> Result<(), PlatformError> {
            if let Some(bridge) = self.fg.lock().unwrap().as_deref() {
                bridge.stop()
            } else {
                Ok(())
            }
        }
        pub fn is_foreground_running(&self) -> bool {
            self.fg
                .lock()
                .unwrap()
                .as_deref()
                .map(|b| b.is_running())
                .unwrap_or(false)
        }
        pub fn wrap_key(&self, raw: &[u8; 32]) -> Result<Vec<u8>, PlatformError> {
            if let Some(bridge) = self.keystore.lock().unwrap().as_deref() {
                bridge.wrap_master_key(raw)
            } else {
                Err(PlatformError::SecretVault(
                    "Android Keystore bridge not registered".to_string(),
                ))
            }
        }
        pub fn unwrap_key(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
            if let Some(bridge) = self.keystore.lock().unwrap().as_deref() {
                bridge.unwrap_master_key(wrapped)
            } else {
                Err(PlatformError::SecretVault(
                    "Android Keystore bridge not registered".to_string(),
                ))
            }
        }
    }
}

#[cfg(not(target_os = "android"))]
mod imp {
    use std::path::PathBuf;

    use linscp_platform::PlatformError;
    use linscp_types::{FileEntry, LocalRootEntry};
    use zeroize::Zeroizing;

    #[derive(Default)]
    pub struct AndroidState;

    impl AndroidState {
        pub fn new() -> Self {
            Self
        }
        pub fn granted_trees(&self) -> Result<Vec<LocalRootEntry>, PlatformError> {
            Ok(Vec::new())
        }
        pub fn list_tree(&self, _tree_uri: &str) -> Result<Vec<FileEntry>, PlatformError> {
            Err(PlatformError::UnsupportedUri("SAF only on Android".to_string()))
        }
        pub fn stage_share_uris(&self, uris: &[String]) -> Result<Vec<PathBuf>, PlatformError> {
            if uris.is_empty() {
                return Err(PlatformError::SecretVault("No files shared".to_string()));
            }
            // On desktop CI, simulate staging by creating temp files
            let root = std::env::temp_dir().join(format!("linscp-share-stub-{}", std::process::id()));
            std::fs::create_dir_all(&root).map_err(PlatformError::Io)?;
            let mut out = Vec::new();
            for (idx, uri) in uris.iter().enumerate() {
                let name = uri
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("shared-file")
                    .replace(['/', '\\', '\0'], "_");
                let path = root.join(format!("{idx}-{name}"));
                std::fs::write(&path, b"stub").map_err(PlatformError::Io)?;
                out.push(path);
            }
            Ok(out)
        }
        pub fn foreground_start(&self, _title: &str, _ongoing: usize) -> Result<(), PlatformError> {
            Ok(())
        }
        pub fn foreground_update(&self, _done: u64, _total: u64) -> Result<(), PlatformError> {
            Ok(())
        }
        pub fn foreground_stop(&self) -> Result<(), PlatformError> {
            Ok(())
        }
        pub fn is_foreground_running(&self) -> bool {
            false
        }
        pub fn wrap_key(&self, _raw: &[u8; 32]) -> Result<Vec<u8>, PlatformError> {
            Err(PlatformError::SecretVault(
                "Android Keystore only on Android".to_string(),
            ))
        }
        pub fn unwrap_key(&self, _wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
            Err(PlatformError::SecretVault(
                "Android Keystore only on Android".to_string(),
            ))
        }
    }
}

pub use imp::AndroidState;

/// Validates that a SAF tree URI looks like `content://...`
pub fn validate_saf_tree_uri(uri: &str) -> Result<(), String> {
    if !uri.starts_with("content://") {
        return Err("SAF tree URI must start with content://".to_string());
    }
    if uri.len() < 14 || uri.contains("..") || uri.contains('\0') {
        return Err("Invalid SAF tree URI.".to_string());
    }
    Ok(())
}

/// Persists a newly granted SAF tree URI by returning a `LocalRootEntry`.
pub fn register_saf_tree(state: &AndroidState, uri: &str) -> Result<linscp_types::LocalRootEntry, String> {
    validate_saf_tree_uri(uri).map_err(|e| e.to_string())?;
    match state.list_tree(uri) {
        Ok(_) | Err(linscp_platform::PlatformError::UnsupportedUri(_)) => {},
        Err(e) => return Err(e.to_string()),
    }
    let label = uri
        .rsplit(&['/', ':'][..])
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| urlencoding_decode(s))
        .unwrap_or_else(|| "SAF Folder".to_string());
    Ok(linscp_types::LocalRootEntry {
        path: uri.to_string(),
        label: format!("{} (SAF)", label),
        kind: "saf_tree".to_string(),
        read_only: false,
    })
}

fn urlencoding_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '%' {
            let hi = chars.next().unwrap_or('0');
            let lo = chars.next().unwrap_or('0');
            let hex = format!("{hi}{lo}");
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                out.push(byte as char);
            } else {
                out.push('%');
                out.push(hi);
                out.push(lo);
            }
        } else {
            out.push(ch);
        }
    }
    if let Some(idx) = out.rfind(':') {
        out[idx + 1..].to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_state_share_staging_fallback() {
        let state = AndroidState::new();
        let uri = "content://com.android.externalstorage.documents/tree/primary%3ADownload";
        let entry = register_saf_tree(&state, uri).unwrap();
        assert_eq!(entry.kind, "saf_tree");
        assert!(entry.path.starts_with("content://"));
        assert!(entry.label.contains("Download"));
        assert!(validate_saf_tree_uri(uri).is_ok());
        assert!(validate_saf_tree_uri("file:///tmp").is_err());
    }

    #[test]
    fn foreground_noop_when_no_bridge() {
        let state = AndroidState::new();
        assert!(!state.is_foreground_running());
        assert!(state.foreground_start("x", 1).is_ok());
        assert!(state.foreground_update(1, 2).is_ok());
        assert!(state.foreground_stop().is_ok());
    }

    #[cfg(target_os = "android")]
    #[test]
    fn android_bridge_mock() {
        use linscp_platform::android::{SafBridge, KeystoreBridge};
        use linscp_platform::PlatformError;
        use linscp_types::{FileEntry, LocalRootEntry};
        use std::sync::{Arc, Mutex};
        use zeroize::Zeroizing;

        struct MockSaf;
        impl SafBridge for MockSaf {
            fn granted_trees(&self) -> Result<Vec<LocalRootEntry>, PlatformError> {
                Ok(vec![])
            }
            fn list_tree(&self, _tree_uri: &str) -> Result<Vec<FileEntry>, PlatformError> {
                Ok(vec![FileEntry {
                    name: "file.txt".to_string(),
                    size: 3,
                    is_dir: false,
                    is_symlink: false,
                    broken_link: false,
                    date: String::new(),
                    mtime: 0,
                    permissions: String::new(),
                    owner: None,
                    group: None,
                }])
            }
            fn stat_uri(&self, _uri: &str) -> Result<FileEntry, PlatformError> {
                Err(PlatformError::UnsupportedUri("".to_string()))
            }
            fn read_uri_bytes(&self, _uri: &str) -> Result<Vec<u8>, PlatformError> {
                Ok(b"data".to_vec())
            }
            fn write_uri_bytes(&self, _p: &str, _n: &str, _d: &[u8]) -> Result<String, PlatformError> {
                Ok("content://mock".to_string())
            }
            fn mkdir_uri(&self, _p: &str, _n: &str) -> Result<String, PlatformError> {
                Ok("content://mock".to_string())
            }
            fn delete_uri(&self, _uri: &str) -> Result<(), PlatformError> {
                Ok(())
            }
            fn rename_uri(&self, _uri: &str, _n: &str) -> Result<String, PlatformError> {
                Ok("content://mock".to_string())
            }
        }

        let state = AndroidState::new();
        // On Android, SAF bridge can be set
        state.set_saf(Arc::new(MockSaf));
        let uri = "content://com.android.externalstorage.documents/tree/primary%3ADocuments";
        let entry = register_saf_tree(&state, uri).unwrap();
        assert_eq!(entry.kind, "saf_tree");
    }
}
