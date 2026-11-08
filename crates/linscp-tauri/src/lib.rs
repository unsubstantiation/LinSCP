//! Tauri v2 desktop & mobile host adapter (`linscp-tauri`).
//!
//! Exposes `CommanderService::dispatch` directly over Tauri's in-process IPC
//! (`invoke("linscp_invoke", ...)`), eliminating localhost TCP sockets and
//! bearer tokens when running as a native Linux, Windows, or Android app.
//!
//! Android runs the same service in app-private storage. The Storage Access
//! Framework, share sheet, and foreground service bridges are traits
//! in `linscp-platform`; the generated Kotlin project registers them, and every
//! operation they would serve fails closed until it does. Granted SAF trees are
//! ordinary local roots and its documents go through the same `LocalFs` calls
//! as files under `/` or `C:\`, so the same page code drives both apps.

use linscp_service::CommanderService;
use linscp_types::{ApiEnvelope, ApiReply};

pub mod android;

#[derive(Clone)]
pub struct TauriBridge {
    service: CommanderService,
    android: std::sync::Arc<android::AndroidState>,
}

impl Default for TauriBridge {
    /// The bridge always belongs to one of the two apps this crate builds: the
    /// desktop window, which can show a viewer it starts, or the Android app, which
    /// cannot. There is no third, unknown host at runtime — a bare
    /// `CommanderService::default()` keeps viewer spawning off, and only the two
    /// constructors below decide to turn it on.
    fn default() -> Self {
        #[cfg(not(target_os = "android"))]
        {
            Self::for_desktop_window(CommanderService::default())
        }
        #[cfg(target_os = "android")]
        {
            Self::new(CommanderService::default()).for_no_viewer()
        }
    }
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

    /// Bridge for a *windowed* host: the desktop app. A remote-desktop viewer
    /// started here appears on the machine the user is looking at, which is what
    /// the HTTP host cannot promise and what the old code never allowed (A1).
    #[cfg(not(target_os = "android"))]
    pub fn for_desktop_window(service: CommanderService) -> Self {
        Self {
            service: service.with_desktop_spawn(true),
            android: std::sync::Arc::new(android::AndroidState::new()),
        }
    }

    /// Bridge for the Android app: no viewer binary exists, so the page answers
    /// with an intent and the service must never try to spawn one.
    pub fn for_android_app(service: CommanderService, android: std::sync::Arc<android::AndroidState>) -> Self {
        Self::with_android_state(service, android).for_no_viewer()
    }

    /// Marks this bridge as not being able to show a viewer it starts. Used for the
    /// Android app, whose answers all come from the page's `rdp://` intent branch.
    pub fn for_no_viewer(self) -> Self {
        Self {
            service: self.service.with_desktop_spawn(false),
            android: self.android,
        }
    }

    /// Direct IPC entrypoint invoked by `TauriTransport` in `ui/src/transport/tauri.ts`.
    pub fn invoke(&self, envelope: ApiEnvelope) -> ApiReply {
        self.stage_incoming_android_shares(&envelope);
        self.service.dispatch(envelope)
    }

    fn stage_incoming_android_shares(&self, envelope: &ApiEnvelope) {
        if envelope.method.eq_ignore_ascii_case("GET")
            && envelope.path.split('?').next() == Some("/api/shell/pending")
        {
            if let Ok(paths) = self.android_state().staged_share_paths() {
                if !paths.is_empty() {
                    let _ = linscp_service::ops::record_shell_upload_manifest(
                        &linscp_platform::config_dir(), &paths,
                    );
                }
            }
        }
    }

    pub async fn invoke_async(&self, envelope: ApiEnvelope) -> ApiReply {
        self.stage_incoming_android_shares(&envelope);
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

    /// Opens one terminal in its own OS window.
    ///
    /// A terminal used to be a modal inside the main window, so a person
    /// watching a build had it either in front of the file panes or behind
    /// them. A window can be alt-tabbed to on its own, moved to a second
    /// screen, and kept beside the editor while the file panes stay where they
    /// were; that is the whole reason it is a window and not a modal.
    ///
    /// The new window is labelled `terminal-<id>`, which is what tells the page
    /// inside it which terminal it is showing. Reopening the same terminal
    /// focuses the window that already exists rather than stacking a second one
    /// on the same shell - two windows on one terminal is not a bug, but two
    /// windows nobody asked for is.
    #[cfg(not(target_os = "android"))]
    #[tauri::command]
    pub async fn linscp_open_terminal_window(
        app: tauri::AppHandle,
        terminal: String,
        title: String,
        cols: u32,
        rows: u32,
    ) -> Result<serde_json::Value, String> {
        use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

        // The label is built from an id the backend chose (`term-N`), but it is
        // still an identifier handed in from the page, so it is reduced to the
        // characters a window label may contain instead of trusted.
        let safe: String = terminal
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if safe.is_empty() {
            return Err("A terminal window needs a terminal.".into());
        }
        let label = format!("terminal-{safe}");
        if let Some(existing) = app.get_webview_window(&label) {
            let _ = existing.unminimize();
            existing.set_focus().map_err(|e| e.to_string())?;
            return Ok(json!({ "label": label, "existing": true }));
        }

        let title = if title.trim().is_empty() { "Terminal".to_string() } else { title };
        // Each terminal gets its own document, which is what makes the window a
        // terminal instead of a second copy of the commander. The page reads
        // the terminal from the window's own label, so a window cannot end up
        // showing a shell another window is already drawing.
        let builder = WebviewWindowBuilder::new(&app, &label, WebviewUrl::App("index.html".into()))
            .title(title)
            // Sized for the grid the shell already has, so opening a window does
            // not immediately resize the remote PTY and reflow the program the
            // person is watching. The page measures its real font and corrects
            // this on the first frame.
            .inner_size((cols.max(20) as f64 * 9.0 + 32.0).clamp(420.0, 1920.0),
                        (rows.max(5) as f64 * 18.0 + 64.0).clamp(200.0, 1200.0))
            .min_inner_size(280.0, 120.0)
            // A terminal is a text surface, and a dropped file has nowhere to
            // go in it. Left enabled, the webview would swallow the drop before
            // the page could see it, so a person dragging a file onto a
            // terminal would watch nothing happen.
            .disable_drag_drop_handler()
            .build()
            .map_err(|e| e.to_string())?;
        if let Some(icon) = app.default_window_icon() {
            let _ = builder.set_icon(icon.clone());
        }

        Ok(json!({ "label": label, "existing": false }))
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

    /// Opens an external URI through Android's activity resolver. The Kotlin
    /// plugin allowlists HTTP(S) and supported remote-desktop viewer schemes.
    #[tauri::command]
    pub async fn linscp_open_external_uri(
        state: tauri::State<'_, TauriBridge>,
        uri: String,
    ) -> Result<serde_json::Value, String> {
        state.android_state().open_external_uri(&uri).map_err(|e| e.to_string())?;
        Ok(json!({ "opened": true }))
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
    #[cfg(target_os = "android")]
    let builder = builder.plugin(android::mobile_plugin());
    // The desktop window can show what it launches; the Android app cannot. The
    // bridge's `Default` already knows which of the two this build is, so a future
    // host cannot forget to say it (A1 was exactly that kind of omission).
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
        // The mobile plugin registers SAF/share/foreground bridges before this
        // setup hook; the exact same state must back both service and commands.
        let state = app.state::<std::sync::Arc<android::AndroidState>>().inner().clone();
        let filesystem = android::local_filesystem(&state);
        let service = CommanderService::new(
            linscp_platform::default_config_dir(),
            std::sync::Arc::new(filesystem),
        );
        app.manage(TauriBridge::for_android_app(service, state));
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
            #[cfg(not(target_os = "android"))]
            commands::linscp_open_terminal_window,
            commands::linscp_request_saf_tree,
            commands::linscp_pick_saf_tree,
            commands::linscp_handle_share_intent,
            commands::linscp_open_external_uri,
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

    /// A1 regression: the desktop window's bridge must be built with viewer spawning
    /// allowed, otherwise every remote-desktop launch writes a ticket file instead of
    /// starting `mstsc.exe`. The default has to agree with the app that ships.
    #[cfg(not(target_os = "android"))]
    #[test]
    fn desktop_window_bridge_may_spawn_a_viewer() {
        for bridge in [
            TauriBridge::for_desktop_window(CommanderService::default()),
            TauriBridge::default(),
        ] {
            assert!(
                bridge.service.desktop_spawn_allowed(),
                "the desktop window has to be allowed to start a viewer it can show"
            );
        }
        assert!(
            !CommanderService::default().desktop_spawn_allowed(),
            "a service that was never told where it runs must not spawn viewers"
        );
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
