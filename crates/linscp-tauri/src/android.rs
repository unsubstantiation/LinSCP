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
        ClipboardBridge, ExternalUriBridge, ForegroundServiceBridge, KeystoreBridge, SafBridge,
        ShareBridge,
    };
    use linscp_platform::PlatformError;
    use linscp_types::{FileEntry, LocalRootEntry};

    #[derive(Default)]
    pub struct AndroidState {
        saf: Mutex<Option<Arc<dyn SafBridge>>>,
        share: Mutex<Option<Arc<dyn ShareBridge>>>,
        external_uri: Mutex<Option<Arc<dyn ExternalUriBridge>>>,
        fg: Mutex<Option<Arc<dyn ForegroundServiceBridge>>>,
        keystore: Mutex<Option<Arc<dyn KeystoreBridge>>>,
        clipboard: Mutex<Option<Arc<dyn ClipboardBridge>>>,
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
        pub fn set_keystore(&self, bridge: Arc<dyn KeystoreBridge>) {
            *self.keystore.lock().unwrap() = Some(bridge);
        }
        pub fn keystore_bridge(&self) -> Option<Arc<dyn KeystoreBridge>> {
            self.keystore.lock().unwrap().clone()
        }
        pub fn set_clipboard(&self, bridge: Arc<dyn ClipboardBridge>) {
            *self.clipboard.lock().unwrap() = Some(bridge);
        }
        pub fn read_clipboard_text(&self) -> Result<String, PlatformError> {
            match self.clipboard.lock().unwrap().as_deref() {
                Some(bridge) => bridge.read_text(),
                None => Err(PlatformError::Unsupported("Android clipboard bridge is not available".to_string())),
            }
        }
        pub fn write_clipboard_text(&self, text: &str) -> Result<(), PlatformError> {
            match self.clipboard.lock().unwrap().as_deref() {
                Some(bridge) => bridge.write_text(text),
                None => Err(PlatformError::Unsupported("Android clipboard bridge is not available".to_string())),
            }
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
        pub fn export_bridge(&self) -> Result<Arc<dyn ShareBridge>, PlatformError> {
            self.share.lock().unwrap().clone().ok_or_else(|| PlatformError::Unsupported("Android share integration is not available".to_string()))
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

    impl SafBridge for AndroidState {
        fn request_tree(&self) -> Result<Option<String>, PlatformError> {
            match self.saf_bridge() {
                Some(b) => b.request_tree(),
                None => Ok(None),
            }
        }
        fn granted_trees(&self) -> Result<Vec<LocalRootEntry>, PlatformError> {
            match self.saf_bridge() {
                Some(b) => b.granted_trees(),
                None => Ok(Vec::new()),
            }
        }
        fn list_tree(&self, tree_uri: &str) -> Result<Vec<FileEntry>, PlatformError> {
            self.saf_bridge()
                .ok_or_else(|| PlatformError::UnsupportedUri(tree_uri.to_string()))?
                .list_tree(tree_uri)
        }
        fn stat_uri(&self, uri: &str) -> Result<FileEntry, PlatformError> {
            self.saf_bridge()
                .ok_or_else(|| PlatformError::UnsupportedUri(uri.to_string()))?
                .stat_uri(uri)
        }
        fn read_uri_bytes(&self, uri: &str) -> Result<Vec<u8>, PlatformError> {
            self.saf_bridge()
                .ok_or_else(|| PlatformError::UnsupportedUri(uri.to_string()))?
                .read_uri_bytes(uri)
        }
        fn write_uri_bytes(
            &self,
            parent_uri: &str,
            name: &str,
            data: &[u8],
        ) -> Result<String, PlatformError> {
            self.saf_bridge()
                .ok_or_else(|| PlatformError::UnsupportedUri(parent_uri.to_string()))?
                .write_uri_bytes(parent_uri, name, data)
        }
        fn mkdir_uri(&self, parent_uri: &str, name: &str) -> Result<String, PlatformError> {
            self.saf_bridge()
                .ok_or_else(|| PlatformError::UnsupportedUri(parent_uri.to_string()))?
                .mkdir_uri(parent_uri, name)
        }
        fn delete_uri(&self, uri: &str) -> Result<(), PlatformError> {
            self.saf_bridge()
                .ok_or_else(|| PlatformError::UnsupportedUri(uri.to_string()))?
                .delete_uri(uri)
        }
        fn rename_uri(&self, uri: &str, new_name: &str) -> Result<String, PlatformError> {
            self.saf_bridge()
                .ok_or_else(|| PlatformError::UnsupportedUri(uri.to_string()))?
                .rename_uri(uri, new_name)
        }
        fn read_uri_chunk(
            &self,
            uri: &str,
            offset: u64,
            length: usize,
        ) -> Result<Vec<u8>, PlatformError> {
            self.saf_bridge()
                .ok_or_else(|| PlatformError::UnsupportedUri(uri.to_string()))?
                .read_uri_chunk(uri, offset, length)
        }
        fn begin_write_uri(&self, parent_uri: &str, name: &str) -> Result<String, PlatformError> {
            self.saf_bridge()
                .ok_or_else(|| PlatformError::UnsupportedUri(parent_uri.to_string()))?
                .begin_write_uri(parent_uri, name)
        }
        fn append_uri_chunk(&self, uri: &str, data: &[u8]) -> Result<(), PlatformError> {
            self.saf_bridge()
                .ok_or_else(|| PlatformError::UnsupportedUri(uri.to_string()))?
                .append_uri_chunk(uri, data)
        }
        fn supports_chunked_write(&self) -> bool {
            self.saf_bridge()
                .map(|b| b.supports_chunked_write())
                .unwrap_or(false)
        }
    }

    impl KeystoreBridge for AndroidState {
        fn wrap_key(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
            self.keystore_bridge()
                .ok_or_else(|| {
                    PlatformError::SecretVault(
                        "Android Keystore bridge is not available".to_string(),
                    )
                })?
                .wrap_key(plaintext)
        }
        fn unwrap_key(&self, wrapped: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, PlatformError> {
            self.keystore_bridge()
                .ok_or_else(|| {
                    PlatformError::SecretVault(
                        "Android Keystore bridge is not available".to_string(),
                    )
                })?
                .unwrap_key(wrapped)
        }
    }

    static SHARED_ANDROID_STATE: std::sync::OnceLock<Arc<AndroidState>> =
        std::sync::OnceLock::new();

    impl AndroidState {
        /// Returns the process-wide `AndroidState` so Activity recreation updates
        /// live plugin handles in place without invalidating `CommanderService`.
        pub fn shared() -> Arc<Self> {
            SHARED_ANDROID_STATE
                .get_or_init(|| Arc::new(Self::new()))
                .clone()
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
        pub fn keystore_bridge(&self) -> Option<std::sync::Arc<dyn linscp_platform::android::KeystoreBridge>> {
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
        pub fn read_clipboard_text(&self) -> Result<String, PlatformError> {
            Err(PlatformError::Unsupported("Android clipboard is only available on Android".to_string()))
        }
        pub fn write_clipboard_text(&self, _text: &str) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported("Android clipboard is only available on Android".to_string()))
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
    use linscp_platform::{android::{ClipboardBridge, ExternalUriBridge, ForegroundServiceBridge, KeystoreBridge, SafBridge, ShareBridge}, PlatformError};
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
            let mut out = Vec::new();
            let mut offset = 0u64;
            loop {
                let chunk = self.read_uri_chunk(uri, offset, linscp_platform::android::SAF_CHUNK_BYTES)?;
                if chunk.is_empty() {
                    break;
                }
                let len = chunk.len();
                out.extend_from_slice(&chunk);
                offset = offset.saturating_add(len as u64);
                if len < linscp_platform::android::SAF_CHUNK_BYTES {
                    break;
                }
            }
            Ok(out)
        }
        fn write_uri_bytes(&self, parent_uri: &str, name: &str, data: &[u8]) -> Result<String, PlatformError> {
            if data.len() <= linscp_platform::android::SAF_CHUNK_BYTES {
                #[derive(Serialize)] struct Args<'a> { parent_uri: &'a str, name: &'a str, data_base64: String }
                let result: UriResult = self.call("writeUri", Args { parent_uri, name, data_base64: base64::engine::general_purpose::STANDARD.encode(data) })?;
                return Ok(result.uri);
            }
            let target_uri = self.begin_write_uri(parent_uri, name)?;
            for chunk in data.chunks(linscp_platform::android::SAF_CHUNK_BYTES) {
                self.append_uri_chunk(&target_uri, chunk)?;
            }
            Ok(target_uri)
        }
        fn read_uri_chunk(&self, uri: &str, offset: u64, length: usize) -> Result<Vec<u8>, PlatformError> {
            #[derive(Serialize)] struct Args<'a> { uri: &'a str, offset: u64, length: usize }
            let result: Base64Result = self.call("readUriChunk", Args { uri, offset, length })?;
            if result.base64.is_empty() {
                return Ok(Vec::new());
            }
            base64::engine::general_purpose::STANDARD.decode(result.base64)
                .map_err(|error| PlatformError::Unsupported(error.to_string()))
        }
        fn begin_write_uri(&self, parent_uri: &str, name: &str) -> Result<String, PlatformError> {
            #[derive(Serialize)] struct Args<'a> { parent_uri: &'a str, name: &'a str }
            Ok(self.call::<UriResult, _>("beginWriteUri", Args { parent_uri, name })?.uri)
        }
        fn append_uri_chunk(&self, uri: &str, data: &[u8]) -> Result<(), PlatformError> {
            #[derive(Serialize)] struct Args<'a> { uri: &'a str, data_base64: String }
            let _: serde_json::Value = self.call("appendUriChunk", Args {
                uri,
                data_base64: base64::engine::general_purpose::STANDARD.encode(data),
            })?;
            Ok(())
        }
        fn supports_chunked_write(&self) -> bool {
            true
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
        fn prepare_export(&self) -> Result<PathBuf, PlatformError> {
            #[derive(Deserialize)] struct Batch { path: PathBuf }
            Ok(self.call::<Batch, _>("prepareExport", ())?.path)
        }
        fn stage_local_export(&self, batch: &std::path::Path, directory: &str, names: &[String]) -> Result<(), PlatformError> {
            #[derive(Serialize)] struct Args<'a> { batch: &'a std::path::Path, directory: &'a str, names: &'a [String] }
            let _: serde_json::Value = self.call("stageLocalExport", Args { batch, directory, names })?;
            Ok(())
        }
        fn open_export(&self, batch: &std::path::Path, names: &[String]) -> Result<(), PlatformError> {
            #[derive(Serialize)] struct Args<'a> { batch: &'a std::path::Path, names: &'a [String] }
            let _: serde_json::Value = self.call("openExport", Args { batch, names })?;
            Ok(())
        }
        fn discard_export(&self, batch: &std::path::Path) -> Result<(), PlatformError> {
            #[derive(Serialize)] struct Args<'a> { batch: &'a std::path::Path }
            let _: serde_json::Value = self.call("discardExport", Args { batch })?;
            Ok(())
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
    impl KeystoreBridge for MobileBridge {
        fn wrap_key(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
            #[derive(Serialize)] struct Args { data_base64: String }
            let result: Base64Result = self.call("keystoreWrap", Args {
                data_base64: base64::engine::general_purpose::STANDARD.encode(plaintext),
            })?;
            base64::engine::general_purpose::STANDARD.decode(result.base64)
                .map_err(|e| PlatformError::SecretVault(format!("Invalid Android Keystore wrap encoding: {e}")))
        }
        fn unwrap_key(&self, wrapped: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, PlatformError> {
            #[derive(Serialize)] struct Args { data_base64: String }
            let result: Base64Result = self.call("keystoreUnwrap", Args {
                data_base64: base64::engine::general_purpose::STANDARD.encode(wrapped),
            })?;
            let decoded = base64::engine::general_purpose::STANDARD.decode(&result.base64)
                .map_err(|e| PlatformError::SecretVault(format!("Invalid Android Keystore unwrap encoding: {e}")))?;
            Ok(zeroize::Zeroizing::new(decoded))
        }
    }
    impl ClipboardBridge for MobileBridge {
        fn read_text(&self) -> Result<String, PlatformError> {
            #[derive(Deserialize)] struct Reply { text: Option<String> }
            Ok(self.call::<Reply, _>("readClipboard", ())?.text.unwrap_or_default())
        }
        fn write_text(&self, text: &str) -> Result<(), PlatformError> {
            #[derive(Serialize)] struct Args<'a> { text: &'a str }
            let _: serde_json::Value = self.call("writeClipboard", Args { text })?;
            Ok(())
        }
    }

    pub fn plugin() -> TauriPlugin<Wry> {
        Builder::new("linscp-android")
            .setup(|app, api| {
                let handle = api.register_android_plugin("com.fairuniversal.linscp", "LinSCPAndroidPlugin")?;
                let bridge = Arc::new(MobileBridge { handle, foreground_running: Arc::new(AtomicBool::new(false)) });
                let state = AndroidState::shared();
                state.set_saf(bridge.clone());
                state.set_share(bridge.clone());
                state.set_external_uri(bridge.clone());
                state.set_foreground_service(bridge.clone());
                state.set_clipboard(bridge.clone());
                state.set_keystore(bridge);
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

/// Validates that a SAF tree URI looks like `content://<authority>/tree/<id>...`
/// without dot-segment traversal.
pub fn validate_saf_tree_uri(uri: &str) -> Result<(), String> {
    if !uri.starts_with("content://") {
        return Err("SAF tree URI must start with content://".to_string());
    }
    linscp_platform::parse_saf_document_uri(uri).map_err(|_| "Invalid SAF tree URI.".to_string())?;
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
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "SAF Folder".to_string());
    Ok(linscp_types::LocalRootEntry {
        path: uri.to_string(),
        label: format!("{} (SAF)", label),
        kind: "saf_tree".to_string(),
        read_only: false,
    })
}

fn urlencoding_decode(s: &str) -> String {
    let raw = s.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%' && index + 2 < raw.len() {
            if let (Some(hi), Some(lo)) = (
                (raw[index + 1] as char).to_digit(16),
                (raw[index + 2] as char).to_digit(16),
            ) {
                bytes.push(((hi << 4) | lo) as u8);
                index += 3;
                continue;
            }
        }
        bytes.push(raw[index]);
        index += 1;
    }
    let decoded = String::from_utf8_lossy(&bytes);
    decoded
        .rsplit(['/', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(decoded.as_ref())
        .to_string()
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

        // Non-ASCII UTF-8 SAF folder names must decode cleanly instead of Latin-1 mojibake.
        let utf8_uri = "content://com.android.externalstorage.documents/tree/primary%3ADownload%2F%E6%97%A5%E6%9C%AC%E8%AA%9E";
        let utf8_entry = register_saf_tree(&state, utf8_uri).unwrap();
        assert_eq!(utf8_entry.label, "日本語 (SAF)");

        // Consecutive dots in folder names are legal, while dot-segment traversal is rejected.
        assert!(validate_saf_tree_uri(
            "content://com.android.externalstorage.documents/tree/primary%3A2025..2026"
        )
        .is_ok());
        assert!(validate_saf_tree_uri(
            "content://com.android.externalstorage.documents/tree/primary%3A..%2Fsecret"
        )
        .is_err());
        assert!(validate_saf_tree_uri("content://com.android.contacts/contacts/1").is_err());
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
