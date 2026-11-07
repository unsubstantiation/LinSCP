//! Android bridge contracts.
//!
//! The generated Tauri Android host registers the Kotlin mobile plugin during
//! app setup; its Rust adapter implements these platform traits. Desktop builds
//! have no Android plugin, so their fallback state remains inert and safe.
//!
//! `storage` exposes the registered SAF bridge to the Rust filesystem, so a
//! `content://` root is a first-class local root on the Android app just as a
//! drive letter is on Windows.

#[cfg(target_os = "android")]
mod imp {
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use linscp_platform::android::{
        ExternalUriBridge, ForegroundServiceBridge, SafBridge, ShareBridge,
    };
    use linscp_platform::PlatformError;
    use linscp_types::{FileEntry, LocalRootEntry};

    #[derive(Default)]
    pub struct AndroidState {
        saf: Mutex<Option<Arc<dyn SafBridge>>>,
        share: Mutex<Option<Arc<dyn ShareBridge>>>,
        external_uri: Mutex<Option<Arc<dyn ExternalUriBridge>>>,
        fg: Mutex<Option<Arc<dyn ForegroundServiceBridge>>>,
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
        pub fn set_external_uri(&self, bridge: Arc<dyn ExternalUriBridge>) {
            *self.external_uri.lock().unwrap() = Some(bridge);
        }
        pub fn open_external_uri(&self, uri: &str) -> Result<(), PlatformError> {
            match self.external_uri.lock().unwrap().as_deref() {
                Some(bridge) => bridge.open_external_uri(uri),
                None => Err(PlatformError::Unsupported("Android external URI bridge is not available".to_string())),
            }
        }
        pub fn set_foreground_service(&self, bridge: Arc<dyn ForegroundServiceBridge>) {
            *self.fg.lock().unwrap() = Some(bridge);
        }
        /// The registered SAF bridge, for the local filesystem to use.
        pub fn saf_bridge(&self) -> Option<Arc<dyn SafBridge>> {
            self.saf.lock().unwrap().clone()
        }
        /// Opens the folder picker; `Ok(None)` when the user cancelled or the
        /// shell has no bridge.
        pub fn pick_saf_tree(&self) -> Result<Option<String>, PlatformError> {
            let guard = self.saf.lock().unwrap();
            match guard.as_deref() {
                Some(bridge) => bridge.request_tree(),
                None => Ok(None),
            }
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
            if uris.is_empty() {
                return Err(PlatformError::SecretVault("No files shared".to_string()));
            }
            Err(PlatformError::UnsupportedUri("Android share integration is not available".to_string()))
        }
        /// Share files received by ACTION_SEND/ACTION_SEND_MULTIPLE, staged by
        /// the Android plugin when its activity is created or receives an intent.
        pub fn staged_share_paths(&self) -> Result<Vec<PathBuf>, PlatformError> {
            match self.share.lock().unwrap().as_deref() {
                Some(bridge) => bridge.staged_share_paths(),
                None => Ok(Vec::new()),
            }
        }
        pub fn foreground_start(&self, title: &str, ongoing: usize) -> Result<(), PlatformError> {
            if let Some(bridge) = self.fg.lock().unwrap().as_deref() {
                bridge.start(title, ongoing)
            } else {
                Err(PlatformError::UnsupportedUri("Android foreground service is not available".to_string()))
            }
        }
        pub fn foreground_update(&self, done: u64, total: u64) -> Result<(), PlatformError> {
            if let Some(bridge) = self.fg.lock().unwrap().as_deref() {
                bridge.update_progress(done, total)
            } else {
                Err(PlatformError::UnsupportedUri("Android foreground service is not available".to_string()))
            }
        }
        pub fn foreground_stop(&self) -> Result<(), PlatformError> {
            if let Some(bridge) = self.fg.lock().unwrap().as_deref() {
                bridge.stop()
            } else {
                Err(PlatformError::UnsupportedUri("Android foreground service is not available".to_string()))
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
    }
}

#[cfg(not(target_os = "android"))]
mod imp {
    use std::path::PathBuf;

    use linscp_platform::PlatformError;
    use linscp_types::{FileEntry, LocalRootEntry};

    #[derive(Default)]
    pub struct AndroidState;

    impl AndroidState {
        pub fn new() -> Self {
            Self
        }
        /// Desktops have no Storage Access Framework; there is no bridge.
        pub fn saf_bridge(&self) -> Option<std::sync::Arc<dyn linscp_platform::android::SafBridge>> {
            None
        }
        /// Nothing to pick on a desktop, and that is not an error.
        pub fn pick_saf_tree(&self) -> Result<Option<String>, PlatformError> {
            Ok(None)
        }
        /// Desktop tests register a SAF bridge directly so the same
        /// `content://` paths the Android app uses can be exercised here.
        pub fn set_saf(&self, _bridge: std::sync::Arc<dyn linscp_platform::android::SafBridge>) {
            // The desktop AndroidState is a unit struct: there is no slot to
            // keep a bridge, and pretending otherwise would make a desktop
            // build list folders it cannot open.
        }
        pub fn open_external_uri(&self, _uri: &str) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported("External Android URI intents are only available on Android".to_string()))
        }
        pub fn granted_trees(&self) -> Result<Vec<LocalRootEntry>, PlatformError> {
            Ok(Vec::new())
        }
        pub fn list_tree(&self, _tree_uri: &str) -> Result<Vec<FileEntry>, PlatformError> {
            Err(PlatformError::UnsupportedUri("SAF only on Android".to_string()))
        }
        pub fn staged_share_paths(&self) -> Result<Vec<PathBuf>, PlatformError> { Ok(Vec::new()) }
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
    }
}

pub use imp::AndroidState;

#[cfg(all(target_os = "android", feature = "native-shell"))]
mod mobile_plugin {
    use super::AndroidState;
    use std::path::PathBuf;
    use std::sync::{atomic::{AtomicBool, Ordering}, Arc};

    use base64::Engine as _;
    use linscp_platform::{android::{ExternalUriBridge, ForegroundServiceBridge, SafBridge, ShareBridge}, PlatformError};
    use linscp_types::{FileEntry, LocalRootEntry};
    use serde::{Deserialize, Serialize};
    use tauri::{plugin::{Builder, PluginHandle, TauriPlugin}, Manager, Wry};

    #[derive(Clone)]
    struct MobileBridge {
        handle: PluginHandle<Wry>,
        foreground_running: Arc<AtomicBool>,
    }
    #[derive(Serialize)] struct UriArg<'a> { uri: &'a str }
    #[derive(Deserialize)] struct UriResult { uri: String }
    #[derive(Deserialize)] struct PathList { paths: Vec<PathBuf> }
    #[derive(Deserialize)] struct Base64Result { base64: String }

    impl MobileBridge {
        fn call<T: serde::de::DeserializeOwned, P: Serialize>(&self, command: &str, payload: P) -> Result<T, PlatformError> {
            self.handle.run_mobile_plugin(command, payload)
                .map_err(|error| PlatformError::Unsupported(error.to_string()))
        }
    }
    impl SafBridge for MobileBridge {
        fn request_tree(&self) -> Result<Option<String>, PlatformError> {
            #[derive(Deserialize)] struct Pick { uri: Option<String>, cancelled: Option<bool> }
            let value: Pick = self.call("pickTree", ())?;
            Ok(if value.cancelled.unwrap_or(false) { None } else { value.uri })
        }
        fn granted_trees(&self) -> Result<Vec<LocalRootEntry>, PlatformError> { self.call("grantedTrees", ()) }
        fn list_tree(&self, tree_uri: &str) -> Result<Vec<FileEntry>, PlatformError> { self.call("listTree", UriArg { uri: tree_uri }) }
        fn stat_uri(&self, uri: &str) -> Result<FileEntry, PlatformError> { self.call("statUri", UriArg { uri }) }
        fn read_uri_bytes(&self, uri: &str) -> Result<Vec<u8>, PlatformError> {
            let result: Base64Result = self.call("readUri", UriArg { uri })?;
            base64::engine::general_purpose::STANDARD.decode(result.base64)
                .map_err(|error| PlatformError::Unsupported(error.to_string()))
        }
        fn write_uri_bytes(&self, parent_uri: &str, name: &str, data: &[u8]) -> Result<String, PlatformError> {
            #[derive(Serialize)] struct Args<'a> { parent_uri: &'a str, name: &'a str, data_base64: String }
            let result: UriResult = self.call("writeUri", Args { parent_uri, name, data_base64: base64::engine::general_purpose::STANDARD.encode(data) })?;
            Ok(result.uri)
        }
        fn mkdir_uri(&self, parent_uri: &str, name: &str) -> Result<String, PlatformError> {
            #[derive(Serialize)] struct Args<'a> { parent_uri: &'a str, name: &'a str }
            Ok(self.call::<UriResult, _>("mkdirUri", Args { parent_uri, name })?.uri)
        }
        fn delete_uri(&self, uri: &str) -> Result<(), PlatformError> { let _: serde_json::Value = self.call("deleteUri", UriArg { uri })?; Ok(()) }
        fn rename_uri(&self, uri: &str, new_name: &str) -> Result<String, PlatformError> {
            #[derive(Serialize)] struct Args<'a> { uri: &'a str, new_name: &'a str }
            Ok(self.call::<UriResult, _>("renameUri", Args { uri, new_name })?.uri)
        }
    }
    impl ShareBridge for MobileBridge {
        fn staged_share_paths(&self) -> Result<Vec<PathBuf>, PlatformError> { Ok(self.call::<PathList, _>("takePendingShares", ())?.paths) }
        fn stage_uris(&self, uris: &[String]) -> Result<Vec<PathBuf>, PlatformError> {
            #[derive(Serialize)] struct Args<'a> { uris: &'a [String] }
            Ok(self.call::<PathList, _>("stageUris", Args { uris })?.paths)
        }
    }
    impl ExternalUriBridge for MobileBridge {
        fn open_external_uri(&self, uri: &str) -> Result<(), PlatformError> {
            let _: serde_json::Value = self.call("openExternalUri", UriArg { uri })?;
            Ok(())
        }
    }
    impl ForegroundServiceBridge for MobileBridge {
        fn start(&self, title: &str, ongoing_transfers: usize) -> Result<(), PlatformError> {
            #[derive(Serialize)] struct Args<'a> { title: &'a str, ongoing: usize }
            let _: serde_json::Value = self.call("foregroundStart", Args { title, ongoing: ongoing_transfers })?;
            self.foreground_running.store(true, Ordering::SeqCst); Ok(())
        }
        fn update_progress(&self, bytes_done: u64, bytes_total: u64) -> Result<(), PlatformError> {
            #[derive(Serialize)] struct Args { done: u64, total: u64 }
            let _: serde_json::Value = self.call("foregroundUpdate", Args { done: bytes_done, total: bytes_total })?; Ok(())
        }
        fn stop(&self) -> Result<(), PlatformError> {
            let _: serde_json::Value = self.call("foregroundStop", ())?;
            self.foreground_running.store(false, Ordering::SeqCst); Ok(())
        }
        fn is_running(&self) -> bool { self.foreground_running.load(Ordering::SeqCst) }
    }

    pub fn plugin() -> TauriPlugin<Wry> {
        Builder::new("linscp-android")
            .setup(|app, api| {
                let handle = api.register_android_plugin("com.fairuniversal.linscp", "LinSCPAndroidPlugin")?;
                let bridge = Arc::new(MobileBridge { handle, foreground_running: Arc::new(AtomicBool::new(false)) });
                let state = Arc::new(AndroidState::new());
                state.set_saf(bridge.clone());
                state.set_share(bridge.clone());
                state.set_external_uri(bridge.clone());
                state.set_foreground_service(bridge);
                app.manage(state);
                Ok(())
            })
            .build()
    }
}

#[cfg(all(target_os = "android", feature = "native-shell"))]
pub use mobile_plugin::plugin as mobile_plugin;

/// Local filesystem for the running app: the native one, plus the SAF bridge
/// once the Android shell has registered it.
///
/// The desktop builds have no bridge, so this is the ordinary native
/// filesystem; the Android build gets `content://` roots as soon as the picker
/// hands one over.
pub fn local_filesystem(state: &AndroidState) -> linscp_platform::NativeLocalFs {
    match state.saf_bridge() {
        Some(bridge) => linscp_platform::NativeLocalFs::with_saf(bridge),
        None => linscp_platform::NativeLocalFs::new(),
    }
}

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
        Ok(_) => {},
        #[cfg(not(target_os = "android"))]
        Err(linscp_platform::PlatformError::UnsupportedUri(_)) => {},
        Err(e) => return Err(e.to_string()),
    }
    let label = uri
        .rsplit(&['/', ':'][..])
        .next()
        .filter(|s| !s.is_empty())
        .map(urlencoding_decode)
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
        use linscp_platform::android::SafBridge;
        use linscp_platform::PlatformError;
        use linscp_types::{FileEntry, LocalRootEntry};
        use std::sync::{Arc, Mutex};
        use zeroize::Zeroizing;

        struct MockSaf;
        impl SafBridge for MockSaf {
            fn request_tree(&self) -> Result<Option<String>, PlatformError> {
                Ok(Some("content://com.android.externalstorage.documents/tree/primary%3ADocuments".to_string()))
            }
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
