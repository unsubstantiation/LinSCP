//! Tauri v2 desktop & mobile host adapter (`linscp-tauri`).
//!
//! Exposes `CommanderService::dispatch` directly over Tauri's in-process IPC
//! (`invoke("linscp_invoke", ...)`), eliminating localhost TCP sockets and
//! bearer tokens when running as a native Linux, Windows, or Android app.

use linscp_service::CommanderService;
use linscp_types::{ApiEnvelope, ApiReply};

#[derive(Clone, Default)]
pub struct TauriBridge {
    service: CommanderService,
}

impl TauriBridge {
    pub fn new(service: CommanderService) -> Self {
        Self { service }
    }

    /// Direct IPC entrypoint invoked by `TauriTransport` in `ui/src/transport/tauri.ts`.
    pub fn invoke(&self, envelope: ApiEnvelope) -> ApiReply {
        self.service.dispatch(envelope)
    }
}

#[cfg(feature = "native-shell")]
pub mod commands {
    use linscp_types::{ApiEnvelope, ApiReply};

    use super::TauriBridge;

    #[tauri::command]
    pub async fn linscp_invoke(
        state: tauri::State<'_, TauriBridge>,
        envelope: ApiEnvelope,
    ) -> Result<ApiReply, String> {
        Ok(state.invoke(envelope))
    }
}

#[cfg(feature = "native-shell")]
pub fn build_native_app() -> tauri::Builder<tauri::Wry> {
    tauri::Builder::default()
        .manage(TauriBridge::default())
        .invoke_handler(tauri::generate_handler![commands::linscp_invoke])
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
}
