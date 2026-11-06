//! Tauri v2 desktop & mobile host adapter (`linscp-tauri`).
//!
//! Exposes `CommanderService::dispatch` directly over Tauri's in-process IPC
//! (`invoke("linscp_invoke", ...)`), eliminating localhost TCP sockets and
//! bearer tokens when running as a native Linux, Windows, or Android app.
//!
//! Android runs the same service in app-private storage. The Storage Access
//! Framework, share sheet, foreground service and Keystore bridges are traits
//! in `linscp-platform`; the generated Kotlin project registers them, and every
//! operation they would serve fails closed until it does. Granted SAF trees are
//! ordinary local roots and its documents go through the same `LocalFs` calls
//! as files under `/` or `C:\`, so the same page code drives both apps.

use linscp_service::CommanderService;
use linscp_types::{ApiEnvelope, ApiReply};

pub mod android;

#[derive(Clone, Default)]
pub struct TauriBridge {
    service: CommanderService,
    android: std::sync::Arc<android::AndroidState>,
}

impl TauriBridge {
    pub fn new(service: CommanderService) -> Self {
        Self {
            service,
            android: std::sync::Arc::new(android::AndroidState::new()),
        }
    }

    pub fn with_android_state(service: CommanderService, android: std::sync::Arc<android::AndroidState>) -> Self {
        Self { service, android }
    }

    /// Direct IPC entrypoint invoked by `TauriTransport` in `ui/src/transport/tauri.ts`.
    pub fn invoke(&self, envelope: ApiEnvelope) -> ApiReply {
        self.service.dispatch(envelope)
    }

    pub async fn invoke_async(&self, envelope: ApiEnvelope) -> ApiReply {
        self.service.dispatch_async(envelope).await
    }

    pub fn android_state(&self) -> &std::sync::Arc<android::AndroidState> {
        &self.android
    }
}

#[cfg(feature = "native-shell")]
pub mod commands {
    use linscp_types::{ApiEnvelope, ApiReply};
    use serde_json::json;

    use super::TauriBridge;

    #[tauri::command]
    pub async fn linscp_invoke(
        state: tauri::State<'_, TauriBridge>,
        envelope: ApiEnvelope,
    ) -> Result<ApiReply, String> {
        Ok(state.invoke_async(envelope).await)
    }

    #[tauri::command]
    pub async fn linscp_request_saf_tree(
        state: tauri::State<'_, TauriBridge>,
        uri: String,
    ) -> Result<serde_json::Value, String> {
        let entry = super::android::register_saf_tree(&state.android_state(), &uri)
            .map_err(|e| e.to_string())?;
        Ok(json!({ "success": true, "root": entry }))
    }

    /// Opens Android's document picker and returns the granted tree URI.
    ///
    /// The shell cannot open the picker from Rust without an activity result
    /// callback, so the Kotlin plugin installs a launcher and answers here. A
    /// cancelled picker is a normal `{ "cancelled": true }`, not an error, so
    /// the page can leave the root switcher where it was.
    #[tauri::command]
    pub async fn linscp_pick_saf_tree(
        state: tauri::State<'_, TauriBridge>,
    ) -> Result<serde_json::Value, String> {
        match state.android_state().pick_saf_tree() {
            Ok(Some(uri)) => {
                let root = super::android::register_saf_tree(&state.android_state(), &uri)
                    .map_err(|e| e.to_string())?;
                Ok(json!({ "success": true, "uri": uri, "root": root }))
            }
            Ok(None) => Ok(json!({ "success": true, "cancelled": true })),
            Err(error) => Ok(json!({ "success": false, "error": error.to_string() })),
        }
    }

    #[tauri::command]
    pub async fn linscp_handle_share_intent(
        state: tauri::State<'_, TauriBridge>,
        uris: Vec<String>,
    ) -> Result<serde_json::Value, String> {
        let staged = state
            .android_state()
            .stage_share_uris(&uris)
            .map_err(|e| e.to_string())?;
        // Record pending manifest identical to desktop --shell-upload flow.
        let cfg_dir = linscp_platform::config_dir();
        let staged_buf: Vec<std::path::PathBuf> = staged;
        let manifest = linscp_service::ops::record_shell_upload_manifest(&cfg_dir, &staged_buf)
            .map_err(|e| e.to_string())?;
        Ok(json!({ "success": true, "staged": staged_buf, "manifest": manifest }))
    }

    #[tauri::command]
    pub async fn linscp_foreground_start(
        state: tauri::State<'_, TauriBridge>,
        title: String,
        ongoing: usize,
    ) -> Result<serde_json::Value, String> {
        state
            .android_state()
            .foreground_start(&title, ongoing)
            .map_err(|e| e.to_string())?;
        Ok(json!({ "success": true, "running": true }))
    }

    #[tauri::command]
    pub async fn linscp_foreground_update(
        state: tauri::State<'_, TauriBridge>,
        done: u64,
        total: u64,
    ) -> Result<serde_json::Value, String> {
        state
            .android_state()
            .foreground_update(done, total)
            .map_err(|e| e.to_string())?;
        Ok(json!({ "success": true }))
    }

    #[tauri::command]
    pub async fn linscp_foreground_stop(
        state: tauri::State<'_, TauriBridge>,
    ) -> Result<serde_json::Value, String> {
        state.android_state().foreground_stop().map_err(|e| e.to_string())?;
        Ok(json!({ "success": true, "running": false }))
    }
}

#[cfg(feature = "native-shell")]
pub fn build_native_app() -> tauri::Builder<tauri::Wry> {
    let builder = tauri::Builder::default();
    #[cfg(not(target_os = "android"))]
    let builder = builder.manage(TauriBridge::default());
    #[cfg(target_os = "android")]
    let builder = builder.setup(|app| {
        use tauri::Manager;
        let files = app.path().app_data_dir()?;
        let cache = app.path().app_cache_dir()?;
        std::fs::create_dir_all(&files)?;
        std::fs::create_dir_all(&cache)?;
        // Android's default /data/local/tmp is not writable to app processes.
        // Set paths before constructing the service or starting any transfers.
        std::env::set_var("LINSCP_ANDROID_FILES_DIR", &files);
        std::env::set_var("TMPDIR", &cache);
        // Build the service before the page can reach it, and let its local
        // filesystem see the SAF bridge registered by the Kotlin plugin. A
        // granted tree then behaves like any other local root: listing,
        // creating, writing, renaming and deleting go through `LocalFs`.
        let state = std::sync::Arc::new(android::AndroidState::new());
        let filesystem = android::local_filesystem(&state);
        let service = CommanderService::new(
            linscp_platform::default_config_dir(),
            std::sync::Arc::new(filesystem),
        );
        app.manage(TauriBridge::with_android_state(service, state));
        Ok(())
    });
    // A window with `dragDropEnabled` consumes the drop before the page sees it,
    // so the page's HTML5 handler never runs in the native window. The paths the
    // operating system produced are handed to the page instead, and the page
    // queues them through the same endpoint a browser's byte drop uses: one
    // queue, one conflict answer, one overwrite rule in all three apps.
    #[cfg(not(target_os = "android"))]
    let builder = builder.on_window_event(|window, event| {
        use tauri::{Emitter, WindowEvent};
        if let WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) = event {
            // The side is the pane the page last focused; the shell cannot
            // know which pane is under the cursor, and the page can.
            let payload = serde_json::json!({
                "paths": paths.iter().map(|path| path.to_string_lossy()).collect::<Vec<_>>(),
            });
            let _ = window.emit("native:file-drop", payload);
        }
    });
    builder.invoke_handler(tauri::generate_handler![
            commands::linscp_invoke,
            commands::linscp_request_saf_tree,
            commands::linscp_pick_saf_tree,
            commands::linscp_handle_share_intent,
            commands::linscp_foreground_start,
            commands::linscp_foreground_update,
            commands::linscp_foreground_stop
        ])
}

#[cfg(feature = "native-shell")]
pub fn run_native_app(context: tauri::Context<tauri::Wry>) {
    build_native_app()
        .run(context)
        .expect("failed to run LinSCP Tauri shell");
}

#[cfg(all(feature = "native-shell", target_os = "android"))]
#[tauri::mobile_entry_point]
pub fn run() {
    run_native_app(tauri::generate_context!());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A SAF tree that lives in memory, so the desktop test can drive the same
    /// `content://` listing and write paths the Android app uses.
    #[derive(Default)]
    struct MemorySaf {
        written: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl linscp_platform::android::SafBridge for MemorySaf {
        fn request_tree(&self) -> Result<Option<String>, linscp_platform::PlatformError> {
            Ok(Some("content://com.example/tree/primary%3ADocuments".to_string()))
        }
        fn granted_trees(
            &self,
        ) -> Result<Vec<linscp_types::LocalRootEntry>, linscp_platform::PlatformError> {
            Ok(vec![linscp_types::LocalRootEntry {
                path: "content://com.example/tree/primary%3ADocuments".to_string(),
                label: "Documents (SAF)".to_string(),
                kind: "saf_tree".to_string(),
                read_only: false,
            }])
        }
        fn list_tree(
            &self,
            _tree_uri: &str,
        ) -> Result<Vec<linscp_types::FileEntry>, linscp_platform::PlatformError> {
            Ok(self
                .written
                .lock()
                .unwrap()
                .iter()
                .map(|(uri, bytes)| linscp_types::FileEntry {
                    name: uri.rsplit('/').next().unwrap_or_default().to_string(),
                    size: bytes.len() as u64,
                    is_dir: false,
                    is_symlink: false,
                    broken_link: false,
                    date: String::new(),
                    mtime: 0,
                    permissions: String::new(),
                    owner: None,
                    group: None,
                })
                .collect())
        }
        fn stat_uri(
            &self,
            uri: &str,
        ) -> Result<linscp_types::FileEntry, linscp_platform::PlatformError> {
            self.list_tree(uri)?
                .into_iter()
                .find(|entry| uri.ends_with(&entry.name))
                .ok_or_else(|| linscp_platform::PlatformError::UnsupportedUri(uri.to_string()))
        }
        fn read_uri_bytes(
            &self,
            uri: &str,
        ) -> Result<Vec<u8>, linscp_platform::PlatformError> {
            self.written
                .lock()
                .unwrap()
                .iter()
                .find(|(name, _)| name == uri)
                .map(|(_, bytes)| bytes.clone())
                .ok_or_else(|| linscp_platform::PlatformError::UnsupportedUri(uri.to_string()))
        }
        fn write_uri_bytes(
            &self,
            parent_uri: &str,
            name: &str,
            data: &[u8],
        ) -> Result<String, linscp_platform::PlatformError> {
            if name.contains('/') {
                return Err(linscp_platform::PlatformError::UnsupportedUri(
                    name.to_string(),
                ));
            }
            let uri = format!("{parent_uri}/document/{name}");
            self.written.lock().unwrap().push((uri.clone(), data.to_vec()));
            Ok(uri)
        }
        fn mkdir_uri(
            &self,
            parent_uri: &str,
            name: &str,
        ) -> Result<String, linscp_platform::PlatformError> {
            Ok(format!("{parent_uri}/document/{name}"))
        }
        fn delete_uri(&self, uri: &str) -> Result<(), linscp_platform::PlatformError> {
            self.written.lock().unwrap().retain(|(name, _)| name != uri);
            Ok(())
        }
        fn rename_uri(
            &self,
            uri: &str,
            new_name: &str,
        ) -> Result<String, linscp_platform::PlatformError> {
            let mut written = self.written.lock().unwrap();
            let Some((name, _)) = written.iter_mut().find(|(name, _)| name == uri) else {
                return Err(linscp_platform::PlatformError::UnsupportedUri(uri.to_string()));
            };
            let parent = name.rsplit_once('/').map(|(parent, _)| parent).unwrap_or_default();
            *name = format!("{parent}/document/{new_name}");
            Ok(name.clone())
        }
    }

    #[test]
    fn tauri_bridge_routes_status_without_network_socket() {
        let bridge = TauriBridge::default();
        let reply = bridge.invoke(ApiEnvelope {
            method: "GET".to_string(),
            path: "/api/status".to_string(),
            body: json!({}),
        });
        assert_eq!(reply.status, 200);
        assert!(reply.payload.get("local_roots").is_some());
    }

    #[test]
    fn granted_tree_is_a_local_root_and_serves_the_same_listing_api() {
        let config = std::env::temp_dir().join(format!(
            "linscp-tauri-saf-{}",
            std::process::id()
        ));
        let filesystem = linscp_platform::NativeLocalFs::with_saf(std::sync::Arc::new(MemorySaf::default()));
        let bridge = TauriBridge::new(CommanderService::new(
            config,
            std::sync::Arc::new(filesystem),
        ));
        let tree = "content://com.example/tree/primary%3ADocuments";

        let roots = bridge.invoke(ApiEnvelope {
            method: "GET".to_string(),
            path: "/api/local/roots".to_string(),
            body: json!({}),
        });
        assert_eq!(roots.status, 200);
        assert!(
            roots.payload["roots"]
                .as_array()
                .unwrap()
                .iter()
                .any(|root| root["path"] == json!(tree) && root["kind"] == json!("saf_tree")),
            "a granted tree has to be listed in the same root switcher: {}",
            roots.payload
        );

        let listing = bridge.invoke(ApiEnvelope {
            method: "GET".to_string(),
            path: format!("/api/local/list?path={}", tree.replace('%', "%25")),
            body: json!({}),
        });
        assert_eq!(listing.status, 200, "{}", listing.payload);
        assert_eq!(listing.payload["path"], json!(tree));
    }

    #[test]
    fn tauri_bridge_android_share_and_foreground_noop_on_desktop() {
        let bridge = TauriBridge::default();
        // Register SAF tree validates URI without needing Kotlin.
        let res = android::register_saf_tree(
            &bridge.android,
            "content://com.android.externalstorage.documents/tree/primary%3ADocuments",
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap().kind, "saf_tree");
        // Foreground no-ops on desktop
        assert!(bridge.android.foreground_start("test", 1).is_ok());
        assert!(bridge.android.foreground_update(100, 200).is_ok());
        assert!(bridge.android.foreground_stop().is_ok());
    }
}
