//! Tauri v2 desktop & mobile host adapter (`linscp-tauri`).
//!
//! Exposes `CommanderService::dispatch` directly over Tauri's in-process IPC
//! (`invoke("linscp_invoke", ...)`), eliminating localhost TCP sockets and
//! bearer tokens when running as a native Linux, Windows, or Android app.
//!
//! Android runs the same service in app-private storage. SAF, sharing,
//! Keystore and background-transfer bridges are not yet connected.

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

#[cfg(all(feature = "native-shell", target_os = "android"))]
struct AndroidStorage(tauri::plugin::PluginHandle<tauri::Wry>);

#[cfg(feature = "native-shell")]
pub mod commands {
    use linscp_types::{ApiEnvelope, ApiReply};
    use serde_json::json;

    use super::TauriBridge;

    #[tauri::command]
    pub async fn linscp_android_import(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
        #[cfg(target_os = "android")]
        {
            use tauri::Manager;
            let handle = app.state::<super::AndroidStorage>().0.clone();
            handle.run_mobile_plugin_async("importFiles", json!({})).await.map_err(|e| e.to_string())
        }
        #[cfg(not(target_os = "android"))]
        { let _ = app; Err("Android document picker is unavailable on this platform".into()) }
    }

    #[tauri::command]
    pub async fn linscp_android_export(app: tauri::AppHandle, path: String) -> Result<serde_json::Value, String> {
        #[cfg(target_os = "android")]
        {
            use tauri::Manager;
            let handle = app.state::<super::AndroidStorage>().0.clone();
            handle.run_mobile_plugin_async("exportFile", json!({"path": path})).await.map_err(|e| e.to_string())
        }
        #[cfg(not(target_os = "android"))]
        { let _ = (app, path); Err("Android document picker is unavailable on this platform".into()) }
    }

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
    let builder = builder.plugin(tauri::plugin::Builder::<tauri::Wry, ()>::new("linscp-storage")
        .setup(|app, api| {
            use tauri::Manager;
            let handle = api.register_android_plugin("io.linscp.commander", "StoragePlugin")?;
            app.manage(AndroidStorage(handle));
            Ok(())
        }).build());
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
        app.manage(TauriBridge::default());
        Ok(())
    });
    builder.invoke_handler(tauri::generate_handler![
            commands::linscp_invoke,
            commands::linscp_android_import,
            commands::linscp_android_export,
            commands::linscp_request_saf_tree,
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
