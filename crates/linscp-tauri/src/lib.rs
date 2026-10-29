//! Tauri v2 desktop & mobile host adapter (`linscp-tauri`).
//!
//! Exposes `CommanderService::dispatch` directly over Tauri's in-process IPC
//! (`invoke("linscp_invoke", ...)`), eliminating localhost TCP sockets and
//! bearer tokens when running as a native Linux, Windows, or Android app.
//!
//! The `android` submodule wires the Kotlin Android layer
//! (`gen/android/app/src/main/java/io/linscp/commander/*`) to the
//! pure-Rust platform bridges (`SafBridge`, `ShareBridge`,
//! `ForegroundServiceBridge`, `KeystoreBridge`) defined in `linscp-platform`.

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
        // Android SAF roots are surfaced through the normal /api/local/roots
        // dispatch; no special-casing needed here because CommanderService reads
        // from NativeLocalFs which already consults the SAF bridge when
        // running on Android. This method remains the single IPC chokepoint.
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
    tauri::Builder::default()
        .manage(TauriBridge::default())
        .invoke_handler(tauri::generate_handler![
            commands::linscp_invoke,
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
