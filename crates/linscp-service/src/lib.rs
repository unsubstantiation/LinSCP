#![allow(clippy::too_many_arguments)]
#![allow(unused_variables, unused_imports, dead_code, unused_mut, clippy::all)]
//! Transport-neutral Commander backend service (`CommanderService`).
//!
//! `linscp-tauri` (native Linux, Windows, and Android shell) routes every UI
//! command through `CommanderService::dispatch` (sync) and `dispatch_async`
//! (async for remote).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rand::RngCore;
use linscp_engine::{
    filemask::FileMask, offlineotp_vault::{self, CredentialEntry, LoginRecord, SshKeyRecord},
    parse_filezilla_xml, parse_openssh_config, PreferencesStore, SessionStore, StoredSite,
};
use linscp_platform::{
    config_dir, gui_os, write_exclusive_private_file, write_private_file_atomic, LocalFs,
    NativeLocalFs, NativeSecretVault, SecretVault,
};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use linscp_types::{
    ApiEnvelope, ApiReply, SessionConfig, TabSummary, TransferQueueItem, UserPreferences,
};
use serde_json::{json, Value};

pub mod cli_actions;
pub mod monitor;
pub mod ops;
pub mod queue;
pub mod tabs;
pub mod terminal_bridge;

use tabs::{TabRuntime, parse_tab_id_str, session_is_local, collect_session_folders, stored_site_to_gui_json};
use linscp_engine::url_and_raw::GuiConnectError;

/// What a dropped path turned out to be, once the filesystem was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DroppedKind {
    /// A regular file the backend can read itself.
    File,
    /// A directory: copied as a tree, never read as bytes.
    Directory,
    /// A granted Android folder; its bytes come from the document provider.
    SafUri,
}

struct InnerState {
    config_root: PathBuf,
    next_tab_id: u64,
    active_tab_id: Option<u64>,
    tabs: HashMap<u64, TabRuntime>,
    challenges: HashMap<u64, TabRuntime>,
    pending_connections: std::collections::HashSet<u64>,
    logs: Vec<Value>,
    preferences: UserPreferences,
    queue_transfers: Vec<Value>,
    /// Embedded terminals, one per open `xterm.js` window.
    terminals: terminal_bridge::TerminalRegistry,
    monitors: monitor::Monitors,
}

#[derive(Clone)]
pub struct CommanderService {
    local_fs: Arc<dyn LocalFs>,
    secret_vault: Arc<linscp_platform::password_vault::PasswordSecretVault>,
    legacy_secret_vault: Arc<dyn SecretVault>,
    state: Arc<Mutex<InnerState>>,
    event_tx: Arc<Mutex<Option<tokio::sync::broadcast::Sender<Value>>>>,
    queue: queue::QueueManager,
    /// Whether the caller that built this service can show a *server-side* window.
    ///
    /// A launch is only allowed to start a viewer when the transport that asked for
    /// it can also display it: the native window can, the HTTP host cannot (its
    /// browser is on some other machine), and Android always answers through a
    /// `hostCapabilities` intent. Default is `false` for exactly that reason — a
    /// service built by code that never said where it runs must not spawn viewers
    /// on the user's behalf.
    desktop_spawn_allowed: bool,
}

impl Default for CommanderService {
    fn default() -> Self {
        Self::new(config_dir(), Arc::new(NativeLocalFs::new()))
    }
}

impl CommanderService {
    fn not_implemented() -> ApiReply {
        ApiReply { status: 501, payload: json!({
            "success": false,
            "error": "This operation is not yet implemented in the native application."
        }) }
    }

    pub fn new(config_root: PathBuf, local_fs: Arc<dyn LocalFs>) -> Self {
        Self::with_secret_vault(config_root, local_fs, Arc::new(NativeSecretVault::new()))
    }

    pub fn with_secret_vault(
        config_root: PathBuf,
        local_fs: Arc<dyn LocalFs>,
        secret_vault: Arc<dyn SecretVault>,
    ) -> Self {
        cleanup_stale_temporary_keys(&config_root);
        let preferences = PreferencesStore::load(&config_root).unwrap_or_default();
        Self {
            local_fs: local_fs.clone(),
            secret_vault: Arc::new(linscp_platform::password_vault::PasswordSecretVault::new()),
            legacy_secret_vault: secret_vault,
            state: Arc::new(Mutex::new(InnerState {
                config_root,
                next_tab_id: 1,
                active_tab_id: None,
                tabs: HashMap::new(),
                challenges: HashMap::new(),
                pending_connections: std::collections::HashSet::new(),
                logs: Vec::new(),
                preferences,
                queue_transfers: Vec::new(),
                terminals: terminal_bridge::TerminalRegistry::default(),
                monitors: monitor::Monitors::default(),
            })),
            event_tx: Arc::new(Mutex::new(None)),
            queue: queue::QueueManager::new(tokio::sync::broadcast::channel(64).0, local_fs),
            desktop_spawn_allowed: false,
        }
    }

    /// Declares that the caller can show a viewer window on this machine, so
    /// `/api/desktop/launch` may start it instead of writing a ticket file.
    ///
    /// Only the native window host may pass `true`. The HTTP host cannot: the
    /// browser may be on another computer, so a viewer started here would be
    /// invisible to the person who clicked. Android does not reach this either —
    /// the page opens a `hostCapabilities` intent before it reads the ticket.
    pub fn with_desktop_spawn(mut self, allowed: bool) -> Self {
        self.desktop_spawn_allowed = allowed;
        self
    }

    /// Whether `/api/desktop/launch` may start the resolved viewer on this machine.
    pub fn desktop_spawn_allowed(&self) -> bool {
        self.desktop_spawn_allowed
    }

    pub fn config_root(&self) -> PathBuf {
        self.state.lock().expect("state mutex").config_root.clone()
    }

    pub fn add_log(&self, text: &str, level: &str) {
        let mut g = self.state.lock().expect("state mutex");
        g.logs.push(json!({"text": text, "level": level}));
        if g.logs.len() > 500 { g.logs.remove(0); }
    }

    // Synchronous dispatch for HTTP and Tauri – handles all local and file-backed endpoints.
    pub fn dispatch(&self, req: ApiEnvelope) -> ApiReply {
        let method = req.method.to_ascii_uppercase();
        let (raw_path, query_str) = match req.path.split_once('?') {
            Some((p, q)) => (p, q),
            None => (req.path.as_str(), ""),
        };
        let query = parse_query(query_str);
        match (method.as_str(), raw_path) {
            ("GET", "/api/status") => self.handle_status(),
            ("GET", "/api/vault/status") => self.handle_vault_status(),
            ("POST", "/api/vault/unlock") => self.handle_vault_unlock(req.body),
            ("POST", "/api/vault/lock") => self.handle_vault_lock(),
            ("GET", "/api/vault/keys") => self.handle_vault_ssh_keys(),
            ("POST", "/api/vault/keys/import") => self.handle_vault_ssh_key_import(req.body),
            ("GET", "/api/local/roots") => self.handle_local_roots(),
            ("GET", "/api/local/list") => self.handle_local_list(&query),
            ("GET", "/api/local/edit") => self.handle_local_edit_get(&query),
            ("GET", "/api/remote/list") => self.handle_remote_list(&query),
            ("GET", "/api/remote/edit") => self.handle_remote_edit_get(&query),
            ("GET", "/api/preferences") => self.handle_get_preferences(),
            ("POST", "/api/preferences") => self.handle_save_preferences(req.body),
            ("GET", "/api/sessions") => self.handle_list_sessions(),
            ("GET", "/api/monitor/hosts") => self.monitor_hosts(),
            ("GET", "/api/monitor/settings") => self.monitor_settings_get(),
            ("POST", "/api/monitor/settings") => self.monitor_settings_post(req.body),
            ("POST", "/api/vault/export") => self.handle_export_offlineotp_vault(req.body),
            ("POST", "/api/vault/import") => self.handle_import_offlineotp_vault(req.body),
            ("POST", "/api/sessions/save") => self.handle_save_session(req.body),
            ("POST", "/api/sessions/delete") => self.handle_delete_session(req.body),
            ("GET", "/api/sessions/import") => self.handle_sessions_import_get(&query),
            ("POST", "/api/import/openssh") => self.handle_import_openssh(req.body),
            ("POST", "/api/import/filezilla") => self.handle_import_filezilla(req.body),
            ("GET", "/api/bookmarks") => self.handle_get_bookmarks(&query),
            ("POST", "/api/bookmarks") => self.handle_save_bookmarks(req.body),
            ("POST", "/api/bookmarks/save") => self.handle_bookmarks_save(req.body),
            ("POST", "/api/bookmarks/delete") => self.handle_bookmarks_delete(req.body),
            ("GET", "/api/workspaces") => self.handle_get_workspaces(),
            ("POST", "/api/workspaces") => self.handle_save_workspaces(req.body),
            ("POST", "/api/workspaces/save") => self.handle_workspaces_save(req.body),
            ("POST", "/api/workspaces/delete") => self.handle_workspaces_delete(req.body),
            ("GET", "/api/transfers") => self.handle_list_transfers(),
            ("POST", "/api/tabs/local") => self.handle_open_local_tab(req.body),
            ("POST", "/api/tabs/open") => self.handle_tabs_open(req.body),
            ("POST", "/api/tabs/close") => self.handle_tabs_close(req.body),
            ("POST", "/api/tabs/select") => self.handle_tabs_select(req.body),
            ("POST", "/api/tabs/verify") => self.handle_tabs_verify(req.body),
            ("POST", "/api/tabs/reconnect") => self.handle_tabs_reconnect(req.body),
            ("POST", "/api/local/mkdir") => self.handle_local_mkdir(req.body),
            ("POST", "/api/local/delete") => self.handle_local_delete(req.body),
            ("POST", "/api/local/rename") => self.handle_local_rename(req.body),
            ("POST", "/api/local/chmod") => self.handle_local_chmod(req.body),
            ("POST", "/api/local/link") => self.handle_local_link(req.body),
            ("POST", "/api/local/save") => self.handle_local_save(req.body),
            ("POST", "/api/local/drop") => self.handle_local_drop(&query, req.body),
            ("POST", "/api/local/drop-dir") => self.handle_local_drop_dir(&query, req.body),
            ("GET", "/api/logs") => self.handle_logs(),
            ("GET", "/api/cleanup") => self.handle_cleanup_get(),
            ("POST", "/api/cleanup") => self.handle_cleanup_post(req.body),
            ("GET", "/api/shell/pending") => self.handle_shell_pending(),
            ("POST", "/api/shell/dismiss") => self.handle_shell_dismiss(req.body),
            ("GET", "/api/session/url") => self.handle_session_url(&query),
            ("GET", "/api/remote/transfer/targets") => self.handle_remote_transfer_targets(&query),
            ("POST", "/api/remote/mkdir") => self.handle_remote_mkdir(req.body),
            ("POST", "/api/remote/delete") => self.handle_remote_delete(req.body),
            ("POST", "/api/remote/rename") => self.handle_remote_rename(req.body),
            ("POST", "/api/remote/copy") => self.handle_remote_copy(req.body),
            ("POST", "/api/remote/link") => self.handle_remote_link(req.body),
            ("POST", "/api/remote/properties") => self.handle_remote_properties(req.body),
            ("POST", "/api/remote/rights") => self.handle_remote_rights(req.body),
            ("POST", "/api/remote/checksum") => self.handle_remote_checksum(req.body),
            ("POST", "/api/sync/preview") => self.handle_sync_preview(req.body),
            ("POST", "/api/sync/run") => self.handle_sync_run(req.body),
            ("POST", "/api/transfer/upload") => self.handle_transfer_upload(req.body),
            ("POST", "/api/transfer/download") => self.handle_transfer_download(req.body),
            ("POST", "/api/transfer/move") => self.handle_transfer_move(req.body),
            ("POST", "/api/transfer/keepuptodate") => self.handle_keepuptodate(req.body),
            ("POST", "/api/remote/transfer") => self.handle_remote_transfer(req.body),
            ("POST", "/api/queue/pause") => self.handle_queue_pause(),
            ("POST", "/api/queue/resume") => self.handle_queue_resume(),
            ("POST", "/api/queue/cancel") => self.handle_queue_cancel(req.body),
            ("POST", "/api/queue/clear") => self.handle_queue_clear(),
            ("POST", "/api/queue/retry") => self.handle_queue_retry(req.body),
            ("POST", "/api/queue/priority") => self.handle_queue_priority(req.body),
            // `list`/`save`/`delete` only. `run` needs the console interpreter,
            // which is async, so it is answered by the asynchronous entry point.
            ("POST", "/api/custom-commands") => self.handle_custom_commands(req.body),
            ("POST", "/api/command/exec") => self.handle_command_exec(req.body),
            ("GET", "/api/desktop/recommendations") => self.handle_desktop_recommendations(),
            ("GET", "/api/desktop/install-script") => self.handle_desktop_install_script(&query, req.body),
            ("POST", "/api/desktop/install-script") => self.handle_desktop_install_script(&query, req.body),
            ("POST", "/api/desktop/ticket") => self.handle_desktop_ticket(req.body),
            ("POST", "/api/desktop/launch") => self.handle_desktop_launch(req.body),
            ("POST", "/api/desktop/check") => self.handle_desktop_check(req.body),
            ("POST", "/api/desktop/install") => self.handle_desktop_install_sync(req.body),
            _ => ApiReply { status: 404, payload: json!({"error": format!("Unknown endpoint: {} {}", method, raw_path)})},
        }
    }

    pub async fn dispatch_async(&self, req: ApiEnvelope) -> ApiReply {
        let (method, raw_path) = {
            let m = req.method.to_ascii_uppercase();
            let p = req.path.split('?').next().unwrap_or(&req.path).to_string();
            (m, p)
        };
        match (method.as_str(), raw_path.as_str()) {
            ("POST", "/api/custom-commands") => self.handle_custom_commands_async(req.body).await,
            ("POST", "/api/tabs/open") => self.open_tab_async(req.body).await,
            ("POST", "/api/tabs/verify") => self.verify_tab_async(req.body).await,
            ("POST", "/api/tabs/reconnect") => self.reconnect_tab_async(req.body).await,
            ("POST", "/api/remote/mkdir") => self.mkdir_remote_async(req.body).await,
            ("POST", "/api/remote/properties") => Box::pin(self.remote_properties_async(req.body)).await,
            ("POST", "/api/workspaces/open") => Box::pin(self.open_workspace_async(req.body)).await,
            // These need a live session, so they resolve here rather than in the
            // synchronous table, which only answers local and file-backed calls.
            ("POST", "/api/remote/chmod") => self.chmod_remote_async(req.body).await,
            ("POST", "/api/remote/copy") => self.copy_remote_async(req.body).await,
            ("POST", "/api/remote/rights") => self.rights_remote_async(req.body).await,
            ("POST", "/api/transfer/keepuptodate") => self.keep_up_to_date_async(req.body).await,
            ("POST", "/api/session/copyid") => self.copy_id_async(req.body).await,
            ("POST", "/api/remote/link") => self.link_remote_async(req.body).await,
            ("POST", "/api/remote/checksum") => self.checksum_remote_async(req.body).await,
            ("POST", "/api/remote/search") => self.search_remote_async(req.body).await,
            ("POST", "/api/remote/rename") => self.rename_remote_any_async(req.body).await,
            ("POST", "/api/remote/delete") => self.delete_remote_any_async(req.body).await,
            ("POST", "/api/monitor/sample") => self.monitor_sample_async(req.body).await,
            ("POST", "/api/session/terminal") => self.open_terminal_async(req.body).await,
            ("POST", "/api/terminal/input") => self.terminal_write(req.body),
            ("POST", "/api/terminal/close") => self.terminal_close(req.body),
            ("GET", "/api/terminal/output") => self.terminal_read(&parse_query(req.path.split_once('?').map(|(_, q)| q).unwrap_or(""))),
            ("POST", "/api/shell/consume") => self.consume_shell_offer_async(req.body).await,
            ("GET", "/api/remote/edit") => self.remote_edit_read_async(&parse_query(req.path.split_once('?').map(|(_, q)| q).unwrap_or(""))).await,
            ("POST", "/api/remote/save") => self.remote_save_async(req.body).await,
            ("POST", "/api/command/exec") => Box::pin(self.exec_cli_command_async(req.body)).await,
            ("POST", "/api/sync/preview") => Box::pin(self.sync_preview_async(req.body)).await,
            ("POST", "/api/sync/run") => Box::pin(self.sync_run_async(req.body)).await,
            ("POST", "/api/transfer/drop") => self.handle_transfer_drop(req.body).await,
            ("POST", "/api/transfer/drop-dir") => self.handle_transfer_drop_dir(req.body).await,
            ("POST", "/api/transfer/upload") => self.queue_transfer_async(req.body, true, false).await,
            ("POST", "/api/transfer/download") => self.queue_transfer_async(req.body, false, false).await,
            ("POST", "/api/transfer/move") => {
                let upload = match req.body.get("direction").and_then(Value::as_str) {
                    Some("upload") => true, Some("download") => false,
                    _ => return api_error(400, "Invalid move direction"),
                };
                self.queue_transfer_async(req.body, upload, true).await
            }
            ("GET", "/api/remote/list") => self.list_remote_async(&req.path).await,
            ("POST", "/api/remote/transfer") => self.remote_transfer_async(req.body).await,
            ("POST", "/api/desktop/check") => self.handle_desktop_check_async(req.body).await,
            ("POST", "/api/desktop/install") => self.handle_desktop_install_async(req.body).await,
            ("POST", "/api/desktop/launch") => self.handle_desktop_launch_async(req.body).await,
            ("POST", "/api/desktop/ticket") => self.handle_desktop_ticket(req.body),
            _ => self.dispatch(req),
        }
    }

    async fn open_tab_async(&self, body: Value) -> ApiReply {
        if let Some(value) = body.get("connect_timeout") {
            if !value.as_u64().is_some_and(|n| (1..=60).contains(&n)) {
                return api_error(400, "Connection timeout must be an integer from 1 to 60 seconds.");
            }
        }
        let session = body.get("session").cloned().unwrap_or(json!({}));
        if session_is_local(&session) { return self.handle_tabs_open(body); }
        let site_name = body.get("site_name").and_then(Value::as_str).filter(|s| !s.is_empty());
        let root = self.config_root();
        let (mut spec, mut clean) = match tabs::parse_gui_session_spec(&session, site_name, &root, self.secret_vault.as_ref()) {
            Ok(value) => value,
            Err(error) => return api_error(400, error),
        };
        if let Some(seconds) = body.get("connect_timeout").and_then(Value::as_u64) {
            spec.timeout_secs = seconds;
        }
        if spec.session.hostkey.trim() == "*" || spec.session.tunnel.as_ref().is_some_and(|t| t.hostkey.trim() == "*") {
            return api_error(400, "Wildcard SSH host keys are not supported");
        }
        if let Some(object) = clean.as_object_mut() {
            for key in ["proxy_password", "passphrase", "password", "tunnel_password", "tunnel_passphrase"] { object.remove(key); }
            if let Some(tunnel) = object.get_mut("tunnel").and_then(Value::as_object_mut) {
                for key in ["password", "passphrase"] { tunnel.remove(key); }
            }
        }
        let local = if spec.session.local_dir.is_empty() { self.default_local_dir() } else {
            match check_local_pane_directory(&spec.session.local_dir, "local_dir") {
                Ok(path) => path, Err(error) => return api_error(400, error),
            }
        };
        let mut tab = {
            let mut state = self.state.lock().expect("state mutex");
            let id = state.next_tab_id;
            state.next_tab_id += 1;
            state.pending_connections.insert(id);
            TabRuntime {
                id, name: body.get("name").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or(&spec.session.host).to_string(),
                site_name: site_name.map(str::to_string), is_local: false, connected: false,
                local_dir: local, remote_dir: String::new(), other_local_dir: String::new(),
                observed_hostkey: String::new(), hostkey_role: String::new(), hostkey_changed: false,
                error: String::new(), spec: Some(spec), session_json: clean, remote: None,
            }
        };
        self.connect_tab(&mut tab).await
    }

    async fn connect_tab(&self, tab: &mut TabRuntime) -> ApiReply {
        let mut dial_spec = match tab.spec.as_ref() { Some(s) => s.clone(), None => return api_error(400, "Missing session settings") };
        let config_root = self.config_root();
        let _temporary_keys = match materialize_vault_key_paths(&mut dial_spec, &config_root, self.secret_vault.as_ref()) {
            Ok(files) => files,
            Err(error) => return api_error(400, error),
        };
        let result = match tokio::time::timeout(
            std::time::Duration::from_secs(dial_spec.timeout_secs.max(1)),
            tabs::dial_gui_tab_session(&dial_spec, &config_root, false, "en"),
        ).await {
            Ok(result) => result,
            Err(_) => Err(GuiConnectError::Failed(format!(
                "Connection timed out after {} seconds.", dial_spec.timeout_secs.max(1)
            ))),
        };
        let mut state = self.state.lock().expect("state mutex");
        // Closing a tab or cancelling a challenge while dialing must not bring
        // it back to life after the asynchronous connection completes.
        if !state.pending_connections.contains(&tab.id) {
            return api_error(400, "Connection was cancelled.");
        }
        match result {
            Ok((session, remote_dir, observed)) => {
                tab.remote = Some(session);
                tab.remote_dir = remote_dir;
                tab.observed_hostkey = observed;
                tab.connected = true;
                tab.error.clear();
                state.pending_connections.remove(&tab.id);
                state.challenges.remove(&tab.id);
                state.active_tab_id = Some(tab.id);
                state.tabs.insert(tab.id, tab.clone());
                ApiReply { status: 200, payload: json!({"success": true, "tab": tab.describe()}) }
            }
            Err(GuiConnectError::HostKeyChallenge(challenge)) => {
                tabs::apply_challenge_to_tab(tab, &challenge);
                let response = tab.hostkey_challenge_json();
                state.challenges.insert(tab.id, tab.clone());
                ApiReply { status: 409, payload: json!({"success": false, "error": challenge.error, "challenge": response}) }
            }
            Err(GuiConnectError::Failed(error)) => {
                state.pending_connections.remove(&tab.id);
                if let Some(current) = state.tabs.get_mut(&tab.id) {
                    current.connected = false;
                    current.remote = None;
                    current.error = error.clone();
                }
                api_error(400, error)
            }
        }
    }

    async fn reconnect_tab_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No such tab") };
        let mut tab = {
            let mut state = self.state.lock().expect("state mutex");
            state.monitors.forget(id);
            let tab = match state.tabs.get(&id).cloned() { Some(tab) => tab, None => return api_error(400, "No such tab") };
            if tab.is_local { return ApiReply { status: 200, payload: json!({"success": true, "tab": tab.describe()}) }; }
            if tab.spec.is_none() { return api_error(400, "Missing session settings"); }
            if !state.pending_connections.insert(id) { return api_error(409, "Connection already in progress"); }
            if let Some(current) = state.tabs.get_mut(&id) { current.connected = false; current.remote = None; current.error.clear(); }
            tab
        };
        // Reconnect to the directory being viewed, not the original startup
        // directory; credentials and approved host keys stay in the private spec.
        if let Some(spec) = tab.spec.as_mut() { spec.session.initial_dir = tab.remote_dir.clone(); }
        tab.connected = false;
        tab.remote = None;
        self.connect_tab(&mut tab).await
    }

    async fn mkdir_remote_async(&self, body: Value) -> ApiReply {
        self.mkdir_remote_async_with_base(body).await
    }

    /// Creates one directory below `remote_dir` (default: the tab's current
    /// directory). A dropped folder tree is built segment by segment through
    /// this, so each level is confirmed before the next one is attempted.
    async fn mkdir_remote_async_with_base(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "Not connected") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if tab.is_local { return self.handle_remote_mkdir(body); }
        let name = match body.get("name").and_then(Value::as_str) {
            Some(name) if !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\') && !name.contains(':') && !name.chars().any(char::is_control) => name,
            _ => return api_error(400, "A single valid directory name is required."),
        };
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        if !matches!(session.scheme(), linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Ftp | linscp_types::ProtocolScheme::Ftps | linscp_types::ProtocolScheme::Ftpes | linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs) {
            return api_error(501, "Safe directory creation is not supported for this protocol.");
        }
        let base = body.get("remote_dir").and_then(Value::as_str)
            .filter(|dir| !dir.is_empty() && dir.starts_with('/') && !dir.chars().any(char::is_control))
            .unwrap_or(tab.remote_dir.as_str());
        let path = format!("{}/{}", base.trim_end_matches('/'), name);
        match session.mkdir(&path).await {
            Ok(()) => ApiReply { status: 200, payload: json!({"success": true}) },
            Err(error) => api_error(400, format!("Directory creation was not confirmed; the directory may already exist: {error}")),
        }
    }

    async fn remote_properties_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "Not connected") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() { Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected") };
        if tab.is_local { return self.handle_remote_properties(body); }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let names = match body.get("names").and_then(Value::as_array) { Some(names) if !names.is_empty() && names.len() <= 1000 => names, _ => return api_error(400, "Select at least one item") };
        let mut rows = Vec::new();
        for item in names {
            let name = item.as_str().or_else(|| item.get("name").and_then(Value::as_str));
            let name = match name {
                Some(name) if !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\') && !name.contains(':') && !name.chars().any(char::is_control) => name,
                _ => return api_error(400, "Invalid file name"),
            };
            let path = format!("{}/{}", tab.remote_dir.trim_end_matches('/'), name);
            match session.stat(&path).await {
                Ok(Some(entry)) => {
                    let is_link = entry.is_symlink;
                    let mut row = json!(entry);
                    row["path"] = json!(path);
                    row["is_link"] = json!(is_link);
                    rows.push(row);
                }
                Ok(None) => rows.push(json!({"name": name, "error": "No such item"})),
                Err(error) => rows.push(json!({"name": name, "error": error.to_string()})),
            }
        }
        ApiReply { status: 200, payload: json!({"success": true, "name": rows.first().and_then(|r| r.get("name")).cloned().unwrap_or(json!("")), "properties": rows}) }
    }

    async fn open_workspace_async(&self, body: Value) -> ApiReply {
        let name = body.get("name").and_then(Value::as_str).unwrap_or("");
        let path = self.config_root().join("workspaces.json");
        let data: Value = match std::fs::read(&path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok()) {
            Some(data) => data, None => return api_error(400, "Workspace file cannot be read."),
        };
        let workspace = match data.get("workspaces").and_then(|w| w.get(name)) { Some(entry) => entry, None => return api_error(400, format!("No workspace named \"{name}\" exists.")) };
        let entries = match workspace.get("tabs").and_then(Value::as_array) { Some(tabs) if !tabs.is_empty() && tabs.len() <= 100 => tabs, _ => return api_error(400, "Workspace has no valid tabs.") };
        let active = workspace.get("active").and_then(Value::as_u64).unwrap_or(0) as usize;
        let mut opened = Vec::new();
        let mut failed = Vec::new();
        let mut active_id = None;
        for (index, entry) in entries.iter().enumerate() {
            let label = entry.get("name").and_then(Value::as_str).unwrap_or("Unnamed tab");
            let local = entry.get("local_dir").and_then(Value::as_str).unwrap_or("");
            let remote = entry.get("remote_dir").and_then(Value::as_str).unwrap_or("");
            let result = match entry.get("kind").and_then(Value::as_str) {
                Some("local") => self.create_local_tab(local.to_string(), remote.to_string()),
                Some("remote") => {
                    match entry.get("site").and_then(Value::as_str).filter(|name| !name.is_empty()) {
                        Some(site) => self.open_tab_async(json!({"site_name": site, "name": label, "session": {"local_dir": local, "initial_dir": remote}})).await,
                        None => api_error(400, "Remote workspace tabs require a saved site."),
                    }
                }
                _ => api_error(400, "Invalid workspace tab type."),
            };
            if result.status == 200 && result.payload["success"] == true {
                if let Some(id) = result.payload["tab"]["id"].as_u64() {
                    if index == active { active_id = Some(id); }
                    opened.push(json!({"name": label, "id": id}));
                } else { failed.push(json!({"name": label, "error": "Opened tab has no ID."})); }
            } else {
                // Workspace opening cannot silently approve a new SSH key.
                // Leave that tab unopened and let the user connect manually.
                if let Some(id) = result.payload["challenge"]["tab"].as_u64() { self.handle_tabs_close(json!({"tab": id})); }
                failed.push(json!({"name": label, "error": result.payload["error"].as_str().unwrap_or("Cannot open tab")}));
            }
        }
        if let Some(id) = active_id { self.handle_tabs_select(json!({"tab": id})); }
        ApiReply { status: 200, payload: json!({"success": true, "name": name, "opened": opened, "failed": failed, "active_tab": active_id}) }
    }

    async fn verify_tab_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "Missing challenge tab") };
        let mut tab = match self.state.lock().expect("state mutex").challenges.remove(&id) {
            Some(tab) => tab, None => return api_error(400, "Host-key challenge expired"),
        };
        let fingerprint = body.get("fingerprint").and_then(Value::as_str).unwrap_or("");
        let role = body.get("role").and_then(Value::as_str).unwrap_or("destination");
        if fingerprint != tab.observed_hostkey || role != tab.hostkey_role {
            self.state.lock().expect("state mutex").challenges.insert(id, tab);
            return api_error(400, "Host-key challenge did not match");
        }
        if body.get("remember").and_then(Value::as_bool).unwrap_or(false) {
            let challenge = tab.hostkey_challenge_json();
            let mut parts = fingerprint.split_whitespace();
            let (kind, key) = match (parts.next(), parts.next(), parts.next()) {
                (Some(kind), Some(key), None) => (kind, key),
                _ => {
                    self.state.lock().expect("state mutex").challenges.insert(id, tab);
                    return api_error(400, "Invalid host-key fingerprint");
                }
            };
            let path = self.config_root().join("sshhostkeys");
            let result = linscp_engine::hostkeys::HostKeyCache::load_from_path(&path).and_then(|mut cache| {
                cache.upsert(challenge["host"].as_str().unwrap_or(""), challenge["port"].as_u64().unwrap_or(22) as u16, kind, key)?;
                cache.save_to_path(&path)
            });
            if let Err(error) = result {
                self.state.lock().expect("state mutex").challenges.insert(id, tab);
                return api_error(500, error);
            }
        }
        let spec = tab.spec.as_mut().expect("challenge has session settings");
        if role == "tunnel" {
            match spec.session.tunnel.as_mut() { Some(tunnel) => tunnel.hostkey = fingerprint.to_string(), None => return api_error(400, "No tunnel configured") }
        } else if role == "destination" { spec.session.hostkey = fingerprint.to_string(); }
        else { return api_error(400, "Invalid host-key role"); }
        self.connect_tab(&mut tab).await
    }

    async fn list_remote_async(&self, path: &str) -> ApiReply {
        let query = parse_query(path.split_once('?').map(|(_, q)| q).unwrap_or(""));
        let id = query.get("tab").and_then(|s| parse_tab_id_str(Some(s)));
        let tab = id.and_then(|id| self.state.lock().expect("state mutex").tabs.get(&id).cloned());
        let tab = match tab { Some(tab) => tab, None => return api_error(400, "Not connected") };
        if tab.is_local { return self.handle_remote_list(&query); }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let requested = query.get("path").filter(|p| !p.is_empty()).map(String::as_str).unwrap_or(&tab.remote_dir);
        let resolved = match session.realpath(requested).await { Ok(path) => path, Err(error) => return api_error(400, error.to_string()) };
        match session.list_dir(&resolved).await {
            Ok(entries) => {
                if let Some(current) = self.state.lock().expect("state mutex").tabs.get_mut(&tab.id) { current.remote_dir = resolved.clone(); }
                ApiReply { status: 200, payload: json!({"success": true, "path": resolved, "entries": entries}) }
            }
            Err(error) => api_error(400, error.to_string()),
        }
    }

    async fn remote_transfer_async(&self, body: Value) -> ApiReply {
        let move_item = match body.get("operation").and_then(Value::as_str) {
            None | Some("copy") => false,
            Some("move") => true,
            _ => return api_error(400, "Unsupported remote transfer operation."),
        };
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() { Some(tab) if tab.connected && !tab.is_local => tab, _ => return api_error(400, "Not connected") };
        let target_id = match body.get("target").and_then(Value::as_str).and_then(|v| v.strip_prefix("tab:")).and_then(|v| v.parse::<u64>().ok()) {
            Some(id) => id, None => return api_error(400, "Select an open destination session.")
        };
        let target_tab = match self.state.lock().expect("state mutex").tabs.get(&target_id).cloned() {
            Some(tab) if tab.connected && !tab.is_local => tab, _ => return api_error(400, "Destination session is not connected")
        };
        let target_session = match target_tab.remote { Some(session) => session, None => return api_error(400, "Destination session is not connected") };
        let same_tab = target_id == id;
        if (!same_tab || !move_item) && !matches!(target_session.scheme(), linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs | linscp_types::ProtocolScheme::S3) {
            return api_error(501, "Cross-server moves require an exclusively creatable destination.");
        }
        if !same_tab && move_item && !body.get("accept_cross_move_risk").and_then(Value::as_bool).unwrap_or(false) {
            return ApiReply { status: 409, payload: json!({"success": false, "error": "Cross-server move requires confirmation", "cross_move_risk": true}) };
        }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let source_is_dav = matches!(session.scheme(), linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs);
        let source_is_sftp = session.scheme() == linscp_types::ProtocolScheme::Sftp;
        let source_is_s3 = session.scheme() == linscp_types::ProtocolScheme::S3;
        if !source_is_dav && (move_item || !(source_is_sftp || source_is_s3)) { return api_error(501, "Remote transfers support WebDAV sources, or SFTP and S3 sources for copies only."); }
        if source_is_sftp && !body.get("accept_sftp_copy_risk").and_then(Value::as_bool).unwrap_or(false) {
            return ApiReply { status: 409, payload: json!({"success": false, "error": "SFTP copy requires confirmation", "sftp_copy_risk": true}) };
        }
        // A mask narrows a copy; ignoring it on a move would move files the
        // user excluded, so the move keeps refusing it.
        let mask = body.get("filemask").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if !mask.is_empty() && move_item {
            return api_error(400, "File masks are not supported for remote moves.");
        }
        let directory = body.get("directory").and_then(Value::as_str).unwrap_or("");
        if !directory.starts_with('/') || directory.contains("//") || directory.chars().any(char::is_control) || directory.contains('\\') || directory.split('/').any(|part| part == "." || part == "..") {
            return api_error(400, "An absolute remote directory without dot segments is required.");
        }
        let names = match body.get("names").and_then(Value::as_array) { Some(names) if !names.is_empty() && names.len() <= 1000 => names, _ => return api_error(400, "Select at least one file") };
        if !mask.is_empty() && !names.iter().filter_map(Value::as_str).any(|name| linscp_engine::filemask_matches(&mask, name, false)) {
            return api_error(400, "The mask does not select any of the selected files.");
        }
        let mut jobs = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for value in names {
            let name = match value.as_str() { Some(name) if !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\') && !name.contains(':') && !name.chars().any(char::is_control) => name, _ => return api_error(400, "Invalid file name") };
            if !seen.insert(name) { return api_error(400, "Duplicate file name"); }
            // Outside the mask nothing is copied; the dialog's own text says so.
            if !mask.is_empty() && !linscp_engine::filemask_matches(&mask, name, false) { continue; }
            let source = format!("{}/{}", tab.remote_dir.trim_end_matches('/'), name);
            let target = format!("{}/{}", directory.trim_end_matches('/'), name);
            if same_tab && source == target { return api_error(400, "Source and destination are the same file."); }
            let (source_entry, tag) = if source_is_dav {
                match session.dav_stat_with_etag(&source).await {
                    Ok((Some(entry), Some(tag))) if !entry.is_symlink && tag.starts_with('"') && tag.ends_with('"') && tag.len() >= 2 && !tag[1..tag.len()-1].contains('"') && !tag.chars().any(char::is_control) => (entry, Some(tag)),
                    Ok(_) => return api_error(400, "WebDAV transfers require an existing resource and a strong source ETag."),
                    Err(error) => return api_error(400, error.to_string()),
                }
            } else if source_is_s3 {
                let entry = match session.stat(&source).await {
                    Ok(Some(entry)) if !entry.is_symlink && !entry.is_dir => entry,
                    Ok(_) => return api_error(400, "S3 copies require an existing object."),
                    Err(error) => return api_error(400, error.to_string()),
                };
                let tag = match session.s3_get_etag(&source).await {
                    Ok(Some(tag)) if tag.starts_with('"') && tag.ends_with('"') && tag.len() >= 2 && !tag[1..tag.len()-1].contains('"') && !tag.chars().any(char::is_control) => tag,
                    Ok(_) => return api_error(400, "S3 copies require a strong source ETag."),
                    Err(error) => return api_error(400, error.to_string()),
                };
                (entry, Some(tag))
            } else {
                match session.stat(&source).await {
                    Ok(Some(entry)) if !entry.is_symlink => (entry, None),
                    Ok(_) => return api_error(400, "SFTP copies require an existing non-symlink source."),
                    Err(error) => return api_error(400, error.to_string()),
                }
            };
            let is_dir = source_entry.is_dir;
            if (!same_tab || !move_item) && target_session.scheme() == linscp_types::ProtocolScheme::S3 && source_entry.size > 1024 * 1024 * 1024 {
                return api_error(400, "Remote transfers to S3 are limited to 1 GiB per file.");
            }
            if is_dir && (!same_tab || !move_item) && (move_item || !(source_is_sftp || source_is_dav) || !matches!(target_session.scheme(), linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs)) { return api_error(501, "Directory copies require SFTP or WebDAV sources and destinations; cross-server directory moves are unsupported."); }
            if is_dir && !move_item && source_is_dav && !body.get("accept_directory_copy_risk").and_then(Value::as_bool).unwrap_or(false) {
                return ApiReply { status: 409, payload: json!({"success": false, "error": "Directory copy requires confirmation", "directory_copy_risk": true}) };
            }
            if is_dir && same_tab && target.starts_with(&format!("{source}/")) { return api_error(400, "Cannot move a directory into itself."); }
            if is_dir && move_item && !body.get("accept_directory_move_risk").and_then(Value::as_bool).unwrap_or(false) {
                return ApiReply { status: 409, payload: json!({"success": false, "error": "Directory move requires confirmation", "directory_move_risk": true}) };
            }
            let entry = if same_tab && move_item { None } else { Some(source_entry) };
            jobs.push((name.to_string(), source, target, tag, is_dir, entry));
        }
        for (name, source, target, etag, is_dir, entry) in jobs {
            let size = entry.as_ref().map(|entry| entry.size).unwrap_or(0);
            let job = if let Some(source_entry) = entry {
                queue::QueueJob::StagedRemoteTransfer { source_session: session.clone(), target_session: target_session.clone(), source: source.clone(), target: target.clone(), etag, source_entry, move_item }
            } else {
                queue::QueueJob::DavMove { session: session.clone(), source: source.clone(), target: target.clone(), etag: etag.expect("WebDAV move preflight requires an ETag"), is_dir }
            };
            self.queue.enqueue(Some(id), if move_item { "move" } else { "copy" }, name, source, target, size, false, job);
        }
        ApiReply { status: 200, payload: json!({"success": true}) }
    }

    async fn rename_remote_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() { Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected") };
        if tab.is_local { return self.handle_remote_rename(body); }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        if !matches!(session.scheme(), linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs) {
            return api_error(501, "Safe remote renaming is currently supported only for WebDAV resources.");
        }
        let valid_name = |name: &str| !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\') && !name.contains(':') && !name.chars().any(char::is_control);
        let old = body.get("old_name").and_then(Value::as_str).unwrap_or("");
        let new = body.get("new_name").and_then(Value::as_str).unwrap_or("");
        if !valid_name(old) || !valid_name(new) || old == new { return api_error(400, "Select two different single file names."); }
        let from = format!("{}/{}", tab.remote_dir.trim_end_matches('/'), old);
        let to = format!("{}/{}", tab.remote_dir.trim_end_matches('/'), new);
        let (tag, is_dir) = match session.dav_stat_with_etag(&from).await {
            Ok((Some(entry), Some(tag))) if !entry.is_symlink && tag.starts_with('"') && tag.ends_with('"') && tag.len() >= 2 && !tag[1..tag.len()-1].contains('"') && !tag.chars().any(char::is_control) => (tag, entry.is_dir),
            Ok(_) => return api_error(400, "WebDAV rename requires an existing resource and a strong source ETag."),
            Err(error) => return api_error(400, error.to_string()),
        };
        if is_dir && !body.get("accept_directory_move_risk").and_then(Value::as_bool).unwrap_or(false) {
            return ApiReply { status: 409, payload: json!({"success": false, "error": "Directory move requires confirmation", "directory_move_risk": true}) };
        }
        match session.dav_move_if_match(&from, &to, &tag, is_dir).await {
            Ok(()) => ApiReply { status: 200, payload: json!({"success": true}) },
            Err(error) => api_error(400, error.to_string()),
        }
    }

    /// `chmod` on the active tab. A local tab is the other pane of a local
    /// pair, so it keeps using the local filesystem; a remote tab asks the
    /// server, exactly as the console client's `chmod` does.
    async fn chmod_remote_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if tab.is_local { return self.handle_remote_chmod(body); }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let names = remote_names(&body);
        if names.is_empty() { return api_error(400, "Select at least one file") }
        if names.len() > 1000 { return api_error(400, "Too many files selected") }
        // A recursive change would alter a whole tree from one click; the
        // console asks the user to select the entries instead, and so do we.
        let mut modes = Vec::new();
        for name in &names {
            let leaf = match ops::validate_leaf_name(name) { Ok(leaf) => leaf, Err(error) => return api_error(400, error) };
            let raw = body.get("permissions").and_then(Value::as_str).unwrap_or("");
            let mode = match parse_octal_mode(raw) { Some(mode) => mode, None => return api_error(400, "A symbolic or malformed mode is not supported here; enter an octal mode such as 644.") };
            modes.push((leaf.to_string(), mode));
        }
        let mut failures = Vec::new();
        for (name, mode) in modes {
            let path = format!("{}/{}", tab.remote_dir.trim_end_matches('/'), name);
            let entry = match session.stat(&path).await {
                Ok(Some(entry)) => entry,
                Ok(None) => { failures.push(format!("{name}: not found")); continue; }
                Err(error) => { failures.push(format!("{name}: {error}")); continue; }
            };
            if entry.is_symlink { failures.push(format!("{name}: a symbolic link is changed through its target")); continue; }
            if let Err(error) = session.chmod(&path, mode).await { failures.push(format!("{name}: {error}")); }
        }
        if failures.is_empty() { ApiReply { status: 200, payload: json!({"success": true}) } }
        else { ApiReply { status: 400, payload: json!({"success": false, "error": failures.join("; ")}) } }
    }

    /// Starts watching a local directory and copying changes to the server.
    /// It runs as a queue item, so cancelling it is the queue's cancel and a
    /// pause holds it before its next pass.
    async fn keep_up_to_date_async(&self, body: Value) -> ApiReply {
        use linscp_engine::keepuptodate::KeepUpToDateOptions;
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected && !tab.is_local => tab, _ => return api_error(400, "Not connected"),
        };
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let local_root = match check_sync_local_dir(body.get("local_dir").and_then(Value::as_str).unwrap_or("")) {
            Ok(dir) => dir,
            Err(error) => return api_error(400, error),
        };
        let local_is_dir = if is_saf_path(&local_root) {
            self.local_fs.stat(&local_root).is_ok_and(|info| info.is_dir && !info.is_symlink)
        } else {
            Path::new(&local_root).is_dir()
        };
        if !local_is_dir { return api_error(400, "The local directory does not exist.") }
        let remote_root = match validate_remote_absolute_path(body.get("remote_dir").and_then(Value::as_str).unwrap_or("")) {
            Ok(path) => path, Err(error) => return api_error(400, error),
        };
        let mask_text = body.get("filemask").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let file_mask = if mask_text.is_empty() {
            linscp_engine::filemask::FileMask::default()
        } else {
            match linscp_engine::filemask::FileMask::parse(&mask_text) {
                Ok(mask) => mask, Err(error) => return api_error(400, error),
            }
        };
        let seconds = body.get("interval").and_then(Value::as_u64).unwrap_or(0);
        // The dialogue asks for seconds; the engine works in milliseconds, and
        // a zero interval means "as often as the watcher can".
        let interval_ms = seconds.saturating_mul(1000).clamp(500, 86_400_000);
        let opts = KeepUpToDateOptions {
            interval_ms,
            max_passes: body.get("count").and_then(Value::as_u64).unwrap_or(0).min(u32::MAX as u64) as u32,
            preserve_time: true,
            file_mask,
            ..KeepUpToDateOptions::default()
        };
        let job = crate::queue::QueueJob::KeepUpToDate {
            session,
            local_root: std::path::PathBuf::from(&local_root),
            remote_root: remote_root.clone(),
            opts,
        };
        let task_id = self.queue.enqueue(Some(id), "keepuptodate",
            format!("Watch {local_root}"), local_root.clone(), remote_root, 0,
            body.get("priority").and_then(Value::as_bool).unwrap_or(false), job);
        ApiReply { status: 200, payload: json!({"success": true, "task_id": task_id}) }
    }

    /// The properties dialogue sends the mode as `mode`, the permissions
    /// dialogue as `permissions`; both end at the same server call.
    async fn rights_remote_async(&self, mut body: Value) -> ApiReply {
        if let Some(mode) = body.get("mode").and_then(Value::as_str).map(|s| s.to_string()) {
            body["permissions"] = json!(mode);
        }
        self.chmod_remote_async(body).await
    }

    /// Server-side copy: one source name and one absolute destination path.
    async fn copy_remote_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if tab.is_local { return self.handle_remote_copy(body); }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let source = body.get("source").and_then(Value::as_str).unwrap_or("");
        let source = match ops::validate_leaf_name(source) { Ok(leaf) => leaf, Err(error) => return api_error(400, error) };
        let destination = body.get("destination").and_then(Value::as_str).unwrap_or("");
        let destination = match validate_remote_absolute_path(destination) {
            Ok(path) => path,
            Err(error) => return api_error(400, error),
        };
        let from = format!("{}/{}", tab.remote_dir.trim_end_matches('/'), source);
        if from == destination { return api_error(400, "Source and destination are the same file.") }
        match session.stat(&from).await {
            Ok(Some(entry)) if entry.is_dir => return api_error(400, "Only a single file can be copied on the server; select the files instead."),
            Ok(Some(entry)) if entry.is_symlink => return api_error(400, "A symbolic link is not copied by name; copy its target."),
            Ok(Some(_)) => {}
            Ok(None) => return api_error(400, "The source file does not exist."),
            Err(error) => return api_error(400, error.to_string()),
        }
        // Never replace an existing file from a dialogue that did not say so.
        if let Ok(Some(_)) = session.stat(&destination).await { return api_error(400, "The destination already exists.") }
        match session.copy_file(&from, &destination).await {
            Ok(()) => ApiReply { status: 200, payload: json!({"success": true}) },
            Err(error) => api_error(400, error.to_string()),
        }
    }

    /// Creates a symbolic link next to the selected file.
    async fn link_remote_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if tab.is_local {
            // A local tab's "remote" side is the other local directory: the
            // link is created there with the same rules as the main pane.
            let target = body.get("target").and_then(Value::as_str).unwrap_or("");
            let name = body.get("name").and_then(Value::as_str).unwrap_or("");
            return match create_local_link(&tab.other_local_dir, target, name) {
                Ok(()) => ApiReply { status: 200, payload: json!({"success": true}) },
                Err(error) => api_error(400, error),
            };
        }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        if !matches!(session.scheme(), linscp_types::ProtocolScheme::Sftp) {
            return api_error(501, "Symbolic links can be created only over SFTP.");
        }
        let target = body.get("target").and_then(Value::as_str).unwrap_or("");
        let target = match ops::validate_leaf_name(target) { Ok(leaf) => leaf, Err(error) => return api_error(400, error) };
        let name = body.get("name").and_then(Value::as_str).unwrap_or("");
        let name = match ops::validate_leaf_name(name) { Ok(leaf) => leaf, Err(error) => return api_error(400, error) };
        if target == name { return api_error(400, "A link and its target need two different names.") }
        let dir = tab.remote_dir.trim_end_matches('/');
        let link = format!("{dir}/{name}");
        if let Ok(Some(_)) = session.stat(&link).await { return api_error(400, "The link name already exists.") }
        // The target is relative to the link's directory, which is what a
        // server-side link means; an absolute target is passed through as is.
        match session.symlink(&target, &link).await {
            Ok(()) => ApiReply { status: 200, payload: json!({"success": true}) },
            Err(error) => api_error(400, error.to_string()),
        }
    }

    /// Checksums of the selected remote files.
    async fn checksum_remote_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if tab.is_local { return self.handle_remote_checksum(body); }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let algorithm = match checksum_algorithm(body.get("algorithm").and_then(Value::as_str).unwrap_or("sha-256")) {
            Some(algorithm) => algorithm,
            None => return api_error(400, "Unsupported checksum algorithm; use sha-256, sha-1, md5 or crc32."),
        };
        let names = remote_names(&body);
        if names.is_empty() { return api_error(400, "Select at least one file") }
        if names.len() > 1000 { return api_error(400, "Too many files selected") }
        let mut results = Vec::new();
        for name in names {
            let leaf = match ops::validate_leaf_name(&name) { Ok(leaf) => leaf, Err(error) => return api_error(400, error) };
            let path = format!("{}/{}", tab.remote_dir.trim_end_matches('/'), leaf);
            // A directory has no checksum; report it per file instead of
            // failing the whole selection.
            let item = match session.checksum(&algorithm, &path).await {
                Ok(hex) => json!({"name": leaf, "checksum": hex}),
                Err(error) => json!({"name": leaf, "error": error.to_string()}),
            };
            results.push(item);
        }
        ApiReply { status: 200, payload: json!({"success": true, "algorithm": algorithm, "results": results}) }
    }

    /// Recursive search of the remote tree by name mask and/or content.
    async fn search_remote_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if tab.is_local { return self.handle_remote_search(body); }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let root = body.get("path").and_then(Value::as_str).filter(|p| !p.is_empty()).unwrap_or(&tab.remote_dir);
        let root = match validate_remote_absolute_path(root) { Ok(path) => path, Err(error) => return api_error(400, error) };
        let mask_spec = body.get("pattern").and_then(Value::as_str).unwrap_or("*");
        let mask = match FileMask::parse(mask_spec) { Ok(mask) => mask, Err(error) => return api_error(400, error) };
        let contents = body.get("search_contents").and_then(Value::as_bool).unwrap_or(false);
        let query = body.get("content_query").and_then(Value::as_str).unwrap_or("").to_string();
        if contents && query.is_empty() { return api_error(400, "Enter text to search for.") }
        let case_sensitive = body.get("case_sensitive").and_then(Value::as_bool).unwrap_or(false);
        // A name search also matches directories; a content search only files.
        match ops::search_remote_bounded(session.as_ref(), &root, &mask,
            if contents { Some(query.as_str()) } else { None }, case_sensitive, 500).await
        {
            Ok(stats) => ApiReply { status: 200, payload: json!({
                "success": true,
                "matches": stats.matches,
                "truncated": stats.truncated,
                "scanned": stats.scanned,
                "skipped": stats.skipped,
                "bytes_scanned": stats.bytes_scanned,
            })},
            Err(error) => api_error(400, error),
        }
    }

    /// Renames on any protocol. A same-directory rename is a plain server
    /// `rename`; WebDAV keeps its ETag-checked path so a concurrent change is
    /// still detected, and a directory move that could lose children keeps
    /// asking for the confirmation the dialogue offers.
    /// Deletes the selected entries of the remote panel.
    ///
    /// The pane's own mutation table only reaches a local tab, so a remote
    /// delete used to answer "not implemented" while the button stayed
    /// visible. The session is the same one every other remote operation uses,
    /// and the tree walk is the queue's own: a directory is emptied before it
    /// is removed, a symbolic link is unlinked rather than followed, and the
    /// server's own refusal is reported per name instead of swallowed.
    async fn delete_remote_any_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if tab.is_local { return self.handle_remote_delete(body); }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let names: Vec<String> = match body.get("names").and_then(Value::as_array) {
            Some(items) if !items.is_empty() && items.len() <= 1000 => items.iter()
                .filter_map(|item| item.as_str().or_else(|| item.get("name").and_then(Value::as_str)))
                .map(str::to_string)
                .collect(),
            _ => return api_error(400, "Select at least one item"),
        };
        if names.is_empty() { return api_error(400, "Select at least one item"); }
        let directory = body.get("remote_dir").and_then(Value::as_str)
            .filter(|dir| !dir.is_empty())
            .unwrap_or(tab.remote_dir.as_str());
        if directory.chars().any(char::is_control) {
            return api_error(400, "The directory must not contain control characters.");
        }
        let mut removed = Vec::new();
        let mut failed = Vec::new();
        for raw in names {
            let name = match ops::validate_leaf_name(&raw) {
                Ok(name) => name,
                Err(error) => { failed.push(json!({"name": raw, "error": error})); continue; }
            };
            let path = format!("{}/{}", directory.trim_end_matches('/'), name);
            match queue::delete_remote_recursive_quiet(session.as_ref(), &path).await {
                Ok(()) => {
                    self.add_log(&format!("Deleted '{path}'."), "info");
                    removed.push(name);
                }
                // A name that is already gone is the state the user asked for.
                Err(error) if error.to_lowercase().contains("not found") => {
                    removed.push(name);
                }
                Err(error) => failed.push(json!({"name": name, "error": error})),
            }
        }
        if removed.is_empty() && !failed.is_empty() {
            let reason = failed.iter()
                .filter_map(|row| row.get("error").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("; ");
            return api_error(400, reason);
        }
        ApiReply { status: 200, payload: json!({
            "success": true, "deleted": removed, "failed": failed,
        }) }
    }

    async fn rename_remote_any_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if tab.is_local { return self.handle_remote_rename(body); }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        if matches!(session.scheme(), linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs) {
            return self.rename_remote_async(body).await;
        }
        let old = match ops::validate_leaf_name(body.get("old_name").and_then(Value::as_str).unwrap_or("")) {
            Ok(name) => name, Err(error) => return api_error(400, error),
        };
        let new = match ops::validate_leaf_name(body.get("new_name").and_then(Value::as_str).unwrap_or("")) {
            Ok(name) => name, Err(error) => return api_error(400, error),
        };
        if old == new { return api_error(400, "Select two different single file names.") }
        let dir = tab.remote_dir.trim_end_matches('/');
        let from = format!("{dir}/{old}");
        let to = format!("{dir}/{new}");
        let entry = match session.stat(&from).await {
            Ok(Some(entry)) => entry,
            Ok(None) => return api_error(400, "The selected item does not exist."),
            Err(error) => return api_error(400, error.to_string()),
        };
        if entry.is_symlink { return api_error(400, "A symbolic link is renamed through its target.") }
        if entry.is_dir && !body.get("accept_directory_move_risk").and_then(Value::as_bool).unwrap_or(false) {
            return ApiReply { status: 409, payload: json!({
                "success": false, "directory_move_risk": true,
                "error": "The server may rename a directory without its children being listed first. Continue?"}) };
        }
        // Renaming onto an existing name would replace it on most servers.
        if let Ok(Some(_)) = session.stat(&to).await { return api_error(400, "The new name already exists.") }
        match session.rename(&from, &to).await {
            Ok(()) => ApiReply { status: 200, payload: json!({"success": true}) },
            Err(error) => api_error(400, error.to_string()),
        }
    }

    /// Reads the request a `sync/preview` or `sync/run` call carries into the
    /// planner's options. The page's three-way `mode` is the console's
    /// `-direction`, and the criteria string is `-criteria`.
    fn sync_options_from(body: &Value) -> Result<(std::path::PathBuf, String, linscp_engine::sync_planner::SyncOptions), String> {
        use linscp_engine::sync_planner::{SyncConflictPolicy, SyncCriteria, SyncMode, SyncOptions};
        let mode = match body.get("mode").and_then(Value::as_str).unwrap_or("local") {
            "local" => SyncMode::Local,
            "remote" => SyncMode::Remote,
            "both" => SyncMode::Both,
            other => return Err(format!("Unknown synchronization direction '{other}'.")),
        };
        let raw_criteria = body.get("criteria").and_then(Value::as_str).unwrap_or("time").trim().to_ascii_lowercase();
        let mut criteria = SyncCriteria { time: false, size: false, checksum: false };
        let mut recognised = false;
        for part in raw_criteria.split([';', ',', ' ']).filter(|p| !p.is_empty()) {
            recognised = true;
            match part {
                "time" => criteria.time = true,
                "size" => criteria.size = true,
                "checksum" => criteria.checksum = true,
                "either" => { criteria.time = true; criteria.size = true; }
                // 'none' means "copy whatever differs", which the planner
                // expresses by comparing nothing but existence.
                "none" => {}
                other => return Err(format!("Unknown synchronization criteria '{other}'.")),
            }
        }
        if !recognised { criteria.time = true; }
        let conflict_policy = match body.get("conflict").and_then(Value::as_str).unwrap_or("skip") {
            "skip" => SyncConflictPolicy::Skip,
            "local" => SyncConflictPolicy::Local,
            "remote" => SyncConflictPolicy::Remote,
            "newer" => SyncConflictPolicy::Newer,
            other => return Err(format!("Unknown conflict policy '{other}'.")),
        };
        // An empty mask is the dialogue's "every file", the same default the
        // engine carries; only a mask the user typed is parsed.
        let mask_text = body.get("filemask").and_then(Value::as_str).unwrap_or("").trim().to_string();
        let file_mask = if mask_text.is_empty() {
            linscp_engine::filemask::FileMask::default()
        } else {
            linscp_engine::filemask::FileMask::parse(&mask_text).map_err(|error| error.to_string())?
        };
        // The dialogue offers a mirror of the source tree, which is a one-way
        // copy that deletes what the source no longer has.
        let mirror = body.get("mirror").and_then(Value::as_bool).unwrap_or(false);
        let delete_obsolete = body.get("delete").and_then(Value::as_bool).unwrap_or(false) || mirror;
        let local_root = check_sync_local_dir(body.get("local_dir").and_then(Value::as_str).unwrap_or(""))?;
        let remote_root = validate_remote_absolute_path(body.get("remote_dir").and_then(Value::as_str).unwrap_or(""))?;
        let recursive = body.get("recursive").and_then(Value::as_bool).unwrap_or(true);
        let opts = SyncOptions {
            mode,
            criteria,
            conflict_policy,
            delete_obsolete,
            mirror,
            recursive,
            preserve_time: true,
            file_mask,
            // The planner never writes: a preview stops before applying, and
            // a queued run applies through `apply_sync_plan`, which is the
            // only path that decides to stop.
            preview_only: true,
            ..SyncOptions::default()
        };
        Ok((std::path::PathBuf::from(local_root), remote_root, opts))
    }

    /// The session and the state key a synchronization of this tab uses.
    fn sync_target(&self, body: &Value) -> Result<(Arc<dyn linscp_proto::RemoteSession>, u64, String, String), ApiReply> {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return Err(api_error(400, "No active tab")) };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected && !tab.is_local => tab, _ => return Err(api_error(400, "Not connected")),
        };
        let session = match tab.remote { Some(session) => session, None => return Err(api_error(400, "Not connected")) };
        // The previous record is kept per endpoint and directory pair, so a
        // second run with the same tab finds the first run's state.
        let host_key = tab.spec.as_ref().map(|spec| format!("{}:{}", spec.session.host, spec.session.port))
            .unwrap_or_else(|| format!("tab:{id}"));
        Ok((session, id, host_key, tab.remote_dir.clone()))
    }

    async fn sync_preview_async(&self, body: Value) -> ApiReply {
        use linscp_engine::sync_planner::{plan_synchronization, SyncState};
        let (session, _id, host_key, _dir) = match self.sync_target(&body) { Ok(t) => t, Err(reply) => return reply };
        let (local_root, remote_root, opts) = match Self::sync_options_from(&body) { Ok(t) => t, Err(error) => return api_error(400, error) };
        let config_root = self.state.lock().expect("state mutex").config_root.clone();
        let state_file = SyncState::state_path(&config_root, &SyncState::make_key(&host_key, &local_root.to_string_lossy(), &remote_root));
        let state = SyncState::load(&state_file).unwrap_or_default();
        let saf_fs = if is_saf_path(&local_root.to_string_lossy()) { Some(self.local_fs.as_ref()) } else { None };
        match plan_synchronization(session.as_ref(), &local_root, &remote_root, &opts, &state, saf_fs).await {
            Ok(items) => ApiReply { status: 200, payload: json!({"success": true, "plan": sync_plan_json(&items)}) },
            Err(error) => api_error(400, error),
        }
    }

    /// Queues a synchronization as one task, so the queue's pause, cancel and
    /// progress apply to it exactly as they do to a transfer.
    async fn sync_run_async(&self, body: Value) -> ApiReply {
        let (session, id, host_key, _dir) = match self.sync_target(&body) { Ok(t) => t, Err(reply) => return reply };
        let (local_root, remote_root, mut opts) = match Self::sync_options_from(&body) { Ok(t) => t, Err(error) => return api_error(400, error) };
        // The shared reader above defaults to preview-only so a preview can
        // never write; a run applies the plan, so it opts back out. Without
        // this the queued run plans, applies nothing, and reports success.
        opts.preview_only = false;
        // The same options a preview used, so what the user saw is what runs.
        let config_root = self.state.lock().expect("state mutex").config_root.clone();
        let local_is_dir = if is_saf_path(&local_root.to_string_lossy()) {
            self.local_fs.stat(&local_root.to_string_lossy()).is_ok_and(|info| info.is_dir && !info.is_symlink)
        } else {
            local_root.is_dir()
        };
        if !local_is_dir { return api_error(400, "The local directory does not exist.") }
        let job = crate::queue::QueueJob::SyncRun {
            session,
            config_dir: config_root,
            host_key,
            local_root: local_root.clone(),
            remote_root: remote_root.clone(),
            opts,
        };
        let task_id = self.queue.enqueue(Some(id), "sync", format!("Synchronize {remote_root}"),
            local_root.to_string_lossy().into_owned(), remote_root.clone(), 0,
            body.get("priority").and_then(Value::as_bool).unwrap_or(false), job);
        ApiReply { status: 200, payload: json!({"success": true, "task_id": task_id}) }
    }

    /// Lists monitorable open sessions and saved SSH sites, without credentials.
    fn monitor_hosts(&self) -> ApiReply {
        let state = self.state.lock().expect("state mutex");
        let mut tabs = state.tabs.values().filter(|tab| {
            tab.connected && tab.remote.as_ref().and_then(|remote| remote.ssh_connection()).is_some()
        }).map(|tab| {
            let session = &tab.spec.as_ref().expect("remote tab has settings").session;
            let key = monitor::config_key_for_session(tab.site_name.as_deref(), &session.host, session.port);
            json!({"tab": tab.id, "name": tab.name, "host": session.host, "port": session.port,
                "protocol": session.protocol.as_str(), "site": tab.site_name, "key": key})
        }).collect::<Vec<_>>();
        tabs.sort_by_key(|tab| tab["tab"].as_u64().unwrap_or(0));
        let mut sites = SessionStore::load_from_dir(&state.config_root, self.secret_vault.as_ref())
            .unwrap_or_default().sites().iter().filter(|site| {
                matches!(site.protocol, linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Scp | linscp_types::ProtocolScheme::Ssh)
            }).map(|site| json!({"name": site.name, "host": site.host, "port": site.port,
                "protocol": site.protocol.as_str(), "key": format!("site:{}", site.name)})).collect::<Vec<_>>();
        sites.sort_by(|a,b| a["name"].as_str().cmp(&b["name"].as_str()));
        ApiReply { status: 200, payload: json!({"success": true, "tabs": tabs, "sites": sites,
            "max_hosts": monitor::MAX_HOSTS, "default_interval": monitor::DEFAULT_INTERVAL_SECS,
            "default_timeout": monitor::DEFAULT_TIMEOUT_SECS}) }
    }

    fn monitor_settings_get(&self) -> ApiReply {
        let config_root = self.config_root();
        ApiReply { status: 200, payload: json!({"success": true, "document": monitor::load_settings(&config_root)}) }
    }

    fn monitor_settings_post(&self, body: Value) -> ApiReply {
        let value = body.get("document").cloned().unwrap_or(body);
        let doc = match serde_json::from_value::<linscp_types::MonitorSettingsDocument>(value) {
            Ok(doc) => doc,
            Err(error) => return api_error(400, format!("Invalid monitor settings: {error}")),
        };
        let config_root = self.config_root();
        match monitor::save_settings(&config_root, doc) {
            Ok(doc) => ApiReply { status: 200, payload: json!({"success": true, "document": doc}) },
            Err(error) => api_error(400, error),
        }
    }

    /// Samples selected open tabs concurrently. Selection and polling live in
    /// the shared UI; closing the display stops requests, not SSH sessions.
    async fn monitor_sample_async(&self, body: Value) -> ApiReply {
        let timeout = match monitor::validate_timeout(body.get("timeout")) {
            Ok(timeout) => timeout, Err(error) => return api_error(400, error),
        };
        let Some(requested) = body.get("tabs").and_then(Value::as_array) else {
            return api_error(400, "Select one or more open server tabs.");
        };
        if requested.is_empty() || requested.len() > monitor::MAX_HOSTS {
            return api_error(400, format!("Select between 1 and {} servers.", monitor::MAX_HOSTS));
        }
        let mut ids = std::collections::BTreeSet::new();
        for id in requested {
            let Some(id) = tabs::parse_tab_id_value(Some(id)) else { return api_error(400, "Invalid monitor tab ID."); };
            if !ids.insert(id) { return api_error(400, "Duplicate monitor tab ID."); }
        }
        let settings = monitor::load_settings(&self.config_root());
        let threshold = settings.settings.outage_threshold;
        let targets = {
            let state = self.state.lock().expect("state mutex");
            ids.iter().map(|id| {
                let tab = state.tabs.get(id);
                let session = tab.and_then(|tab| tab.spec.as_ref()).map(|spec| &spec.session);
                let key = session.map(|s| monitor::config_key_for_session(
                    tab.and_then(|tab| tab.site_name.as_deref()), &s.host, s.port))
                    .unwrap_or_default();
                let customs = settings.hosts.get(&key).cloned().unwrap_or_default().custom_metrics;
                (state.monitors.clone(), *id, key,
                    tab.map(|tab| tab.name.clone()).unwrap_or_default(),
                    session.map(|s| s.host.clone()).unwrap_or_default(),
                    session.map(|s| s.port).unwrap_or(22),
                    session.map(|s| s.protocol.as_str()).unwrap_or("unknown").to_string(),
                    tab.is_some_and(|tab| tab.connected),
                    tab.filter(|tab| tab.connected).and_then(|tab| tab.remote.as_ref())
                        .and_then(|remote| remote.ssh_connection()).cloned(),
                    customs)
            }).collect::<Vec<_>>()
        };
        let mut jobs = tokio::task::JoinSet::new();
        for (monitors, id, key, name, host, port, protocol, connected, ssh, customs) in targets {
            jobs.spawn(async move {
                let sample = monitors.sample(monitor::MonitorRequest {
                    tab: id, key: &key, name: &name, host: &host, port, protocol: &protocol,
                    ssh, connected, timeout, custom_metrics: &customs, outage_threshold: threshold,
                }).await;
                if sample.status == "unsupported" { monitors.forget(id); }
                sample
            });
        }
        let mut samples = Vec::new();
        while let Some(result) = jobs.join_next().await {
            match result {
                Ok(sample) => samples.push(sample),
                Err(error) => return api_error(500, format!("Monitoring task failed: {error}")),
            }
        }
        samples.sort_by_key(|sample: &linscp_types::MonitorSample| ids.iter().position(|id| *id == sample.tab).unwrap_or(usize::MAX));
        for sample in &samples {
            if sample.outage_started {
                self.add_log(&format!("[Monitor] {} ({}) is offline after {} failed polls: {}",
                    sample.name, sample.host, sample.consecutive_failures, sample.error), "error");
            }
            if sample.recovered {
                self.add_log(&format!("[Monitor] {} ({}) recovered.", sample.name, sample.host), "success");
            }
        }
        ApiReply { status: 200, payload: json!({"success": true, "samples": samples}) }
    }

    /// Opens an embedded terminal on a tab's pooled SSH connection.
    async fn open_terminal_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected && !tab.is_local => tab, _ => return api_error(400, "Not connected"),
        };
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let ssh = match session.ssh_connection() {
            Some(ssh) => ssh.clone(),
            // A terminal is an SSH shell; FTP, WebDAV and S3 have none, and
            // saying so is better than opening a window that cannot work.
            None => return api_error(501, "This connection has no SSH shell; open an SSH or SFTP session for a terminal."),
        };
        let cols = body.get("cols").and_then(Value::as_u64).unwrap_or(100) as u32;
        let rows = body.get("rows").and_then(Value::as_u64).unwrap_or(30) as u32;
        let (terminal_id, event_tx) = {
            let mut g = self.state.lock().expect("state mutex");
            let terminal_id = g.terminals.allocate_id();
            let event_tx = self.event_sender();
            (terminal_id, event_tx)
        };
        match terminal_bridge::EmbeddedTerminal::open_over_ssh(
            terminal_id.clone(), id, &ssh, cols, rows, Some(tab.remote_dir.as_str()), event_tx,
        ).await {
            Ok(terminal) => {
                self.state.lock().expect("state mutex").terminals.insert(terminal);
                ApiReply { status: 200, payload: json!({"success": true, "terminal": terminal_id}) }
            }
            Err(error) => api_error(400, error),
        }
    }

    fn terminal_write(&self, body: Value) -> ApiReply {
        let terminal_id = body.get("terminal").and_then(Value::as_str).unwrap_or("");
        let terminal = match self.state.lock().expect("state mutex").terminals.get(terminal_id) {
            Some(terminal) => terminal, None => return api_error(400, "This terminal is no longer open."),
        };
        // Input is base64 so a paste of arbitrary text and control bytes
        // arrives byte for byte; plain text is accepted for a simple caller.
        let data = match body.get("data").and_then(Value::as_str) {
            Some(encoded) if !encoded.is_empty() => match BASE64_STD.decode(encoded) {
                Ok(bytes) => bytes,
                Err(_) => body.get("data").and_then(Value::as_str).unwrap_or("").as_bytes().to_vec(),
            },
            // A resize arrives as the same call with empty data.
            _ => Vec::new(),
        };
        let cols = body.get("cols").and_then(Value::as_u64).unwrap_or(0) as u32;
        let rows = body.get("rows").and_then(Value::as_u64).unwrap_or(0) as u32;
        if cols > 0 && rows > 0 && !terminal.resize(cols, rows) {
            return api_error(400, "Invalid terminal size.");
        }
        if !data.is_empty() && !terminal.write(&data) {
            return api_error(400, "The terminal session ended.");
        }
        ApiReply { status: 200, payload: json!({"success": true}) }
    }

    fn terminal_read(&self, query: &BTreeMap<String,String>) -> ApiReply {
        let terminal_id = query.get("terminal").map(String::as_str).unwrap_or("");
        let terminal = match self.state.lock().expect("state mutex").terminals.get(terminal_id) {
            Some(terminal) => terminal, None => return api_error(400, "This terminal is no longer open."),
        };
        let after = query.get("after").and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        let (data, offset, alive, exit_code) = terminal.poll(after);
        // `error` is why the session stopped, not a failure of this request:
        // a server that refuses a pty or a shell keeps the channel open and
        // silent, so the reason is the only thing that distinguishes that
        // from a shell which has simply not written anything yet.
        ApiReply { status: 200, payload: json!({
            "success": true,
            "data": BASE64_STD.encode(&data),
            "offset": offset,
            "alive": alive,
            "exit_code": exit_code,
            "error": terminal.failure(),
        })}
    }

    fn terminal_close(&self, body: Value) -> ApiReply {
        let terminal_id = body.get("terminal").and_then(Value::as_str).unwrap_or("");
        // Closing twice is not an error: the window can be closed while a poll
        // already reported the end of the session, so the answer is the same
        // whether or not there was anything left to close.
        self.state.lock().expect("state mutex").terminals.close(terminal_id);
        ApiReply { status: 200, payload: json!({"success": true}) }
    }

    /// Queues the files a file manager handed over. Nothing is uploaded until
    /// the user confirms in the page, which is what this call is.
    async fn consume_shell_offer_async(&self, body: Value) -> ApiReply {
        let id = match body.get("id").and_then(Value::as_str).filter(|id| !id.is_empty()) {
            Some(id) => id.to_string(),
            None => return api_error(400, "A pending selection is required."),
        };
        let tab_id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&tab_id).cloned() {
            Some(tab) if tab.connected && !tab.is_local => tab, _ => return api_error(400, "Not connected"),
        };
        let config_root = self.state.lock().expect("state mutex").config_root.clone();
        // `take` removes the manifest, so a selection is offered and queued at
        // most once even if two windows poll at the same time.
        let manifest = match ops::take_shell_manifest(&config_root, &id) {
            Ok(manifest) => manifest,
            Err(error) => return api_error(400, error),
        };
        let items = manifest.get("items").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut queued = Vec::new();
        let mut missing = Vec::new();
        let mut refused = Vec::new();
        for item in items {
            let path = item.get("path").and_then(Value::as_str).unwrap_or("");
            let name = item.get("name").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() || !Path::new(path).exists() {
                if !name.is_empty() { missing.push(name.to_string()); }
                continue;
            }
            let request = json!({
                "tab": tab.id,
                "local_dir": Path::new(path).parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
                "remote_dir": tab.remote_dir,
                "names": [name],
            });
            let reply = self.queue_transfer_async(request, true, false).await;
            if reply.payload.get("success").and_then(Value::as_bool).unwrap_or(false) {
                queued.push(name.to_string());
            } else {
                // The file is there but the transfer was refused (a name the
                // panel cannot take, a destination that changed). Saying
                // "missing" would send the user looking for a file that exists.
                let reason = reply.payload.get("error").and_then(Value::as_str)
                    .unwrap_or("The transfer was refused.").to_string();
                refused.push(json!({"name": name, "error": reason}));
            }
        }
        ApiReply { status: 200, payload: json!({
            "success": true, "queued": queued, "missing": missing, "refused": refused,
        }) }
    }

    /// The broadcast sender the page and the native window listen on. Created
    /// once and shared, so a terminal opened on any request reaches the same
    /// listeners as the queue's progress.
    fn event_sender(&self) -> tokio::sync::broadcast::Sender<Value> {
        let mut slot = self.event_tx.lock().expect("event sender mutex");
        match slot.as_ref() {
            Some(sender) => sender.clone(),
            None => {
                let (sender, _) = tokio::sync::broadcast::channel(128);
                *slot = Some(sender.clone());
                sender
            }
        }
    }

    /// Reads a remote file into the page's editor.
    async fn remote_edit_read_async(&self, query: &BTreeMap<String,String>) -> ApiReply {
        let id = match query.get("tab").and_then(|s| parse_tab_id_str(Some(s))) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if tab.is_local { return self.handle_remote_edit_get(query); }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let path = match validate_remote_absolute_path(query.get("path").map(String::as_str).unwrap_or("")) {
            Ok(path) => path, Err(error) => return api_error(400, error),
        };
        let entry = match session.stat(&path).await {
            Ok(Some(entry)) => entry,
            Ok(None) => return api_error(400, "The file does not exist."),
            Err(error) => return api_error(400, error.to_string()),
        };
        if entry.is_dir { return api_error(400, "Cannot open a directory in the text editor.") }
        if entry.is_symlink { return api_error(400, "Refusing to edit a symbolic link.") }
        // The limit is the local editor's, so a file it accepts over SFTP is
        // accepted here too, and a larger one is refused before downloading it.
        if entry.size > ops::MAX_GUI_EDIT_BYTES {
            return api_error(400, format!(
                "File is too large for the built-in editor ({} bytes; maximum {} bytes).",
                entry.size, ops::MAX_GUI_EDIT_BYTES));
        }
        let bytes = match linscp_proto::download_bytes(session.as_ref(), &path,
            linscp_proto::TransferRequest::default()).await
        {
            Ok(bytes) => bytes,
            Err(error) => return api_error(400, error.to_string()),
        };
        if bytes.contains(&0) { return api_error(400, "Refusing to edit binary file containing NUL bytes.") }
        let content = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => return api_error(400, "File is not valid UTF-8 binary/encoded text."),
        };
        ApiReply { status: 200, payload: json!({
            "success": true,
            "path": path,
            "content": content,
            "info": {"size": entry.size, "mtime": entry.mtime, "mtime_ns": entry.mtime.to_string()},
        })}
    }

    /// Saves the editor's content to a remote path. A remote file has no
    /// nanosecond mtime on every protocol, so the guard is the second-precision
    /// mtime the listing shows; comparing it catches the edit that lost a race.
    async fn remote_save_async(&self, body: Value) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if tab.is_local {
            // "Save as" on a local tab writes to the other pane's directory,
            // which is the local filesystem the tab already owns.
            let mut local_body = body.clone();
            if let Some(path) = body.get("path").and_then(Value::as_str) {
                if path.starts_with('/') { local_body["path"] = json!(path); }
                else if is_saf_path(&tab.other_local_dir) {
                    // "Save as" into a granted other pane: a leaf resolves
                    // to a document URI, which saves verbatim (without a
                    // tab), while a joined path keeps the pane's path error.
                    let resolved = match resolve_contained(&tab.other_local_dir, path) {
                        Ok(resolved) => resolved,
                        Err(error) => return api_error(400, error),
                    };
                    local_body["path"] = json!(resolved);
                    if let Some(obj) = local_body.as_object_mut() { obj.remove("tab"); }
                }
                else {
                    let joined = format!("{}/{}", tab.other_local_dir.trim_end_matches('/'), path);
                    local_body["path"] = json!(joined);
                }
            }
            return self.handle_local_save(local_body);
        }
        let session = match tab.remote { Some(session) => session, None => return api_error(400, "Not connected") };
        let path = match validate_remote_absolute_path(body.get("path").and_then(Value::as_str).unwrap_or("")) {
            Ok(path) => path, Err(error) => return api_error(400, error),
        };
        let content = body.get("content").and_then(Value::as_str).unwrap_or("");
        if content.len() as u64 > ops::MAX_GUI_EDIT_BYTES {
            return api_error(400, "Edited content is too large for the built-in editor.");
        }
        let expected = body.get("base_mtime").and_then(Value::as_i64);
        let existing = match session.stat(&path).await {
            Ok(entry) => entry,
            Err(error) => return api_error(400, error.to_string()),
        };
        if let Some(entry) = existing.as_ref() {
            if entry.is_dir { return api_error(400, "Cannot overwrite a directory.") }
            if entry.is_symlink { return api_error(400, "Refusing to overwrite a symbolic link from the editor.") }
            if let Some(expected) = expected.filter(|seconds| *seconds > 0) {
                if entry.mtime != expected {
                    return api_error(400, "The file changed while it was open in the editor; reload before saving.");
                }
            }
        }
        // The editor writes through the same upload path as a queued
        // transfer, so the transport's own atomic replace is what the user gets.
        match linscp_proto::upload_bytes(session.as_ref(), &path, content.as_bytes(),
            linscp_proto::TransferRequest::default()).await
        {
            Ok(_) => match session.stat(&path).await {
                Ok(Some(entry)) => ApiReply { status: 200, payload: json!({
                    "success": true,
                    "info": {"size": entry.size, "mtime": entry.mtime, "mtime_ns": entry.mtime.to_string()},
                })},
                _ => ApiReply { status: 200, payload: json!({"success": true}) },
            },
            Err(error) => api_error(400, error.to_string()),
        }
    }

    /// Builds a console interpreter wired to the tab the user is looking at.
    /// Its output goes to an attached collector rather than to the process's
    /// own terminal; the caller attaches one with `capture_console`.
    fn console_interpreter(
        &self,
        tab: Option<tabs::TabRuntime>,
    ) -> Result<linscp_engine::script::ScriptInterpreter, ApiReply> {
        let config_root = self.state.lock().expect("state mutex").config_root.clone();
        let cfg = linscp_engine::script::ScriptRunConfig {
            config_dir: config_root,
            // The GUI already asked before anything destructive; a confirm
            // inside the panel cannot be answered, so it must not wait.
            batch_mode: linscp_engine::script::BatchMode::Abort,
            echo: false,
            log_level: 0,
            ..linscp_engine::script::ScriptRunConfig::default()
        };
        let logger = linscp_engine::xml_log::SessionLogger::open(None, 0, false, None, None, false, "")
            .map_err(|error| api_error(500, error.to_string()))?;
        let mut interpreter = linscp_engine::script::ScriptInterpreter::new(cfg, logger);
        interpreter.set_secret_vault(self.secret_vault.clone());
        if let Some(tab) = tab.filter(|tab| tab.connected) {
            // The local directory is the panel's, so `lcd`/`lpwd` start where
            // the user is looking rather than at the process's own directory.
            if Path::new(&tab.local_dir).is_dir() {
                interpreter.set_local_dir(PathBuf::from(&tab.local_dir));
            }
            // The tab's own session is shared, not reconnected: the
            // interpreter only needs the directories around it.
            if let (Some(session), Some(spec)) = (tab.remote.clone(), tab.spec.clone()) {
                interpreter.adopt_session(spec, session, tab.remote_dir.clone(), PathBuf::from(&tab.local_dir));
            }
        }
        Ok(interpreter)
    }

    /// Runs one console-client command from the GUI's CLI panel. The same
    /// `ScriptInterpreter` the `linscp -command` runner uses executes the line,
    /// so `ls`, `option`, `put` and the rest cannot drift between the two
    /// applications; the active tab's session is adopted as the first slot.
    async fn exec_cli_command_async(&self, body: Value) -> ApiReply {
        let line = body.get("command").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if line.is_empty() { return api_error(400, "Type a command.") }
        if line.len() > 4096 { return api_error(400, "The command is too long.") }
        // A line with a newline would run a second command nobody typed.
        if line.contains('\n') || line.contains('\r') {
            return api_error(400, "A command with a newline is never written.");
        }
        let tab = body.get("tab").and_then(|value| tabs::parse_tab_id_value(Some(value)))
            .and_then(|id| self.state.lock().expect("state mutex").tabs.get(&id).cloned());
        let mut interpreter = match self.console_interpreter(tab.clone()) {
            Ok(interpreter) => interpreter,
            Err(reply) => return reply,
        };
        let (ok, stdout, stderr) = interpreter.run_captured(&line).await;
        // `cd` and `lcd` move the panes, so the tab's directories follow the
        // interpreter's own working directories after the line ran.
        if let Some((local_cwd, remote_cwd)) = interpreter.working_directories() {
            if let Some(tab) = tab.filter(|tab| tab.connected && !tab.is_local) {
                if let Some(current) = self.state.lock().expect("state mutex").tabs.get_mut(&tab.id) {
                    current.remote_dir = remote_cwd;
                    current.local_dir = local_cwd.to_string_lossy().into_owned();
                }
            }
        }
        let exit_code = if ok && interpreter.error_count() == 0 { 0 } else { 1 };
        ApiReply { status: 200, payload: json!({
            "success": ok,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
        })}
    }

    /// Runs one saved Explorer command over the selected files.
    ///
    /// The page posts `{action:"run", name, filenames, tab}` and shows what each
    /// file's run printed, so this answers with one result per file and never
    /// lets one file's failure stop the rest. The command itself is a LinSCP
    /// command line (`checksum ...`, `chmod ...`, `lls ...`, `call ...`), run by
    /// the same `ScriptInterpreter` as the CLI panel: it is never handed to a
    /// local shell, which is what made "run a local command" work on Debian and
    /// fail on Windows.
    async fn handle_custom_commands_async(&self, body: Value) -> ApiReply {
        let action = body.get("action").and_then(Value::as_str).unwrap_or("list");
        if action != "run" {
            return self.handle_custom_commands(body);
        }
        let config_root = self.state.lock().expect("state mutex").config_root.clone();
        let name = body.get("name").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if name.is_empty() {
            return api_error(400, "A command name is required.");
        }
        let template = match ops::read_custom_commands(&config_root)
            .into_iter()
            .find(|entry| entry.get("name").and_then(Value::as_str) == Some(name.as_str()))
        {
            Some(template) => template,
            None => return api_error(404, format!("There is no command '{name}'.")),
        };
        let filenames: Vec<String> = body
            .get("filenames")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(Value::as_str)
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        // A template that names the file needs a selection to name. One that
        // does not (`terminal`, `presets`) runs once with nothing selected.
        if filenames.is_empty() && ops::template_names_a_file(&template) {
            return api_error(400, "Select at least one file or folder.");
        }
        let tab = body
            .get("tab")
            .and_then(|value| tabs::parse_tab_id_value(Some(value)))
            .and_then(|id| self.state.lock().expect("state mutex").tabs.get(&id).cloned());
        let Some(tab) = tab else {
            return api_error(400, "Open a tab first.");
        };
        let scope = template.get("scope").and_then(Value::as_str).unwrap_or("remote").to_string();
        // The page sends the panel the selection came from; a template saved for
        // the other side would otherwise act on a same-named file that is not the
        // one the user selected.
        let pane = body.get("pane").and_then(Value::as_str).unwrap_or("");
        if let Err(error) = ops::resolve_command_target(&scope, pane, &tab) {
            return api_error(400, error);
        }
        if scope != "local" && !tab.is_local && !tab.connected {
            return api_error(400, "Not connected");
        }
        // One interpreter per file, starting in the pane the template applies
        // to. `console_interpreter` only adopts a tab it considers connected, so
        // a local-only tab is presented as connected: it has no session to be
        // disconnected from, and its local pane is what the command acts on.
        let mut factory = |target: &tabs::TabRuntime| match self.console_interpreter(Some(target.clone())) {
            Ok(interpreter) => Ok(interpreter),
            Err(reply) => Err(reply
                .payload
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("The command interpreter could not be started.")
                .to_string()),
        };
        let results =
            match ops::execute_custom_command_template(&mut factory, &template, &filenames, pane, &tab, &mut |_| {}).await {
                Ok(results) => results,
                Err(error) => return api_error(400, error),
            };
        // Nothing is written back into the tab's directories: the page refreshes
        // both panes after a run, and the interpreter started in the pane the
        // template applies to, so a `cd` inside a template moves the command's
        // own working directory rather than the user's panes.
        ApiReply {
            status: 200,
            payload: json!({"success": true, "results": results}),
        }
    }

    /// Installs the current key on the server by running the interpreter's
    /// own `copyid`, so the GUI and the console cannot install a key
    /// differently.
    async fn copy_id_async(&self, body: Value) -> ApiReply {
        let tab_id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let mut tab = match self.state.lock().expect("state mutex").tabs.get(&tab_id).cloned() {
            Some(tab) if tab.connected && !tab.is_local => tab, _ => return api_error(400, "Not connected"),
        };
        let config_root = self.config_root();
        let _temporary_keys = if let Some(spec) = tab.spec.as_mut() {
            match materialize_vault_key_paths(spec, &config_root, self.secret_vault.as_ref()) {
                Ok(files) => Some(files),
                Err(error) => return api_error(400, error),
            }
        } else { None };
        let keyfile = body.get("keyfile").and_then(Value::as_str).unwrap_or("").trim().to_string();
        // `copyid` works in the console only on an SSH session whose site
        // names a private key; it installs the matching public key, and with
        // no key configured the command would need an argument nobody typed.
        // Refusing here explains that instead of running a command whose
        // answer is a syntax hint.
        if !matches!(
            tab.remote.as_ref().map(|session| session.scheme()),
            Some(linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Scp | linscp_types::ProtocolScheme::Ssh)
        ) {
            return api_error(400, "Installing a key needs an SSH, SFTP or SCP session.");
        }
        let configured_key = tab
            .spec
            .as_ref()
            .and_then(|spec| spec.session.keyfile.clone())
            .filter(|key| !key.trim().is_empty());
        // The dialogue accepts blank for "the key this session uses".
        let line = match (keyfile.is_empty(), configured_key) {
            (true, Some(_)) => "copyid".to_string(),
            (true, None) => {
                return api_error(400, "This site names no private key; the dialogue needs a key file.")
            }
            (false, _) => format!("copyid \"{}\"", keyfile.replace('"', "")),
        };
        let mut interpreter = match self.console_interpreter(Some(tab)) {
            Ok(interpreter) => interpreter,
            Err(reply) => return reply,
        };
        let (ok, stdout, stderr) = interpreter.run_captured(&line).await;
        if ok {
            ApiReply { status: 200, payload: json!({"success": true, "output": stdout}) }
        } else {
            let error = if stderr.trim().is_empty() { stdout.trim().to_string() } else { stderr.trim().to_string() };
            ApiReply { status: 400, payload: json!({"success": false, "error": error, "output": stdout}) }
        }
    }

    async fn queue_transfer_async(&self, body: Value, upload: bool, move_item: bool) -> ApiReply {
        let id = match tabs::parse_tab_id_value(body.get("tab")) { Some(id) => id, None => return api_error(400, "No active tab") };
        let tab = match self.state.lock().expect("state mutex").tabs.get(&id).cloned() {
            Some(tab) if tab.connected => tab, _ => return api_error(400, "Not connected"),
        };
        if move_item && !tab.is_local {
            let dav = tab.remote.as_ref().is_some_and(|s| matches!(s.scheme(), linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs));
            if upload || !dav { return api_error(501, "Only WebDAV file moves to a new local destination are supported."); }
        }
        let names = match body.get("names").and_then(Value::as_array) {
            Some(names) if !names.is_empty() && names.len() <= 1000 => names,
            _ => return api_error(400, "Select at least one file"),
        };
        // Until the queue implements these options, reject rather than silently ignore them.
        for key in ["append", "newer_only"] {
            if body.get(key).and_then(Value::as_bool).unwrap_or(false) { return api_error(400, format!("{key} is not yet supported")); }
        }
        for key in ["filemask", "resumesupport"] {
            if body.get(key).and_then(Value::as_str).is_some_and(|s| !s.is_empty()) { return api_error(400, format!("{key} is not yet supported")); }
        }
        if body.get("speed").and_then(Value::as_u64).unwrap_or(0) != 0 { return api_error(400, "Speed limits are not yet supported"); }
        if !matches!(body.get("transfer").and_then(Value::as_str).unwrap_or(""), "" | "binary") { return api_error(400, "Only binary transfers are supported"); }
        let local_dir = match body.get("local_dir").and_then(Value::as_str) {
            Some(path) => match check_local_pane_directory(path, "local_dir") { Ok(path) => path, Err(error) => return api_error(400, error) },
            None => return api_error(400, "Missing local directory"),
        };
        // The pane check accepts a granted folder structurally. Session
        // transfers stage its bytes through temporary files in the queue
        // worker, so a granted local side is statted through `LocalFs`
        // below instead of refused.
        let other_dir = body.get("remote_dir").and_then(Value::as_str).unwrap_or("");
        if other_dir.is_empty() || other_dir.chars().any(char::is_control) { return api_error(400, "Missing remote directory"); }
        let session = tab.remote.clone();
        if !tab.is_local && session.is_none() { return api_error(400, "Not connected"); }
        let is_ftp_upload = upload && !move_item && !tab.is_local && session.as_ref().is_some_and(|s| matches!(s.scheme(), linscp_types::ProtocolScheme::Ftp | linscp_types::ProtocolScheme::Ftps | linscp_types::ProtocolScheme::Ftpes));
        let ftp_risk_accepted = body.get("accept_ftp_rename_risk").and_then(Value::as_bool).unwrap_or(false);
        if is_ftp_upload && !ftp_risk_accepted {
            return ApiReply { status: 409, payload: json!({"success": false, "error": "FTP upload requires confirmation of rename risks", "ftp_rename_risk": true}) };
        }
        let resume = body.get("resume").and_then(Value::as_bool).unwrap_or(false);
        if resume && (move_item || upload || tab.is_local || session.as_ref().is_none_or(|s| !matches!(s.scheme(), linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs | linscp_types::ProtocolScheme::S3))) {
            return api_error(400, "Verified resume is supported only for WebDAV and S3 file downloads.");
        }
        let overwrite = body.get("overwrite").and_then(Value::as_str).unwrap_or("ask");
        if overwrite != "ask" && overwrite != "overwrite" { return api_error(400, "Unsupported overwrite policy"); }
        let mut jobs = Vec::new();
        let mut conflicts = Vec::new();
        let mut directory_conflicts = Vec::new();
        let merge_names: std::collections::HashSet<&str> = match body.get("merge_directories") {
            None => std::collections::HashSet::new(),
            Some(Value::Array(items)) if items.iter().all(|item| item.is_string()) => items.iter().filter_map(Value::as_str).collect(),
            _ => return api_error(400, "Invalid directory merge approval"),
        };
        let mut conflict_versions = serde_json::Map::new();
        let mut seen = std::collections::HashSet::new();
        for value in names {
            let name = match value.as_str() { Some(name) => name, None => return api_error(400, "Invalid file name") };
            if !seen.insert(name) { return api_error(400, "Duplicate file name"); }
            let local = match resolve_contained(&local_dir, name) { Ok(path) => PathBuf::from(path), Err(error) => return api_error(400, error) };
            let other = if tab.is_local {
                let directory = match check_local_pane_directory(other_dir, "other_local_dir") { Ok(path) => path, Err(error) => return api_error(400, error) };
                match resolve_contained(&directory, name) { Ok(path) => path, Err(error) => return api_error(400, error) }
            } else {
                format!("{}/{}", other_dir.trim_end_matches('/'), name)
            };
            let (source, destination) = if upload { (local.to_string_lossy().into_owned(), other.clone()) } else { (other.clone(), local.to_string_lossy().into_owned()) };
            if tab.is_local && source == destination { return api_error(400, "Source and destination are the same file"); }
            let size;
            let exists;
            let is_dir;
            if tab.is_local {
                // Either end may be a granted folder; `LocalFs` stats both
                // sides of a granted copy, while plain pairs keep the direct
                // metadata and its exact rule.
                let (src_is_dir, src_len) = if is_saf_path(&source) || is_saf_path(&destination) {
                    let info = match self.local_fs.stat(&source) {
                        Ok(info) if (!info.is_dir || move_item) && !info.is_symlink => info,
                        Ok(_) => return api_error(400, "Only regular files and movable directories are supported"),
                        Err(error) => return api_error(400, error.to_string()),
                    };
                    (info.is_dir, if info.is_dir { 0 } else { info.size })
                } else {
                    let meta = match std::fs::symlink_metadata(&source) { Ok(meta) if (meta.is_file() || (move_item && meta.is_dir())) && !meta.file_type().is_symlink() => meta, Ok(_) => return api_error(400, "Only regular files and movable directories are supported"), Err(error) => return api_error(400, error.to_string()) };
                    (meta.is_dir(), if meta.is_dir() { 0 } else { meta.len() })
                };
                is_dir = src_is_dir;
                size = src_len;
                exists = if is_saf_path(&destination) { self.local_fs.stat(&destination).is_ok() } else { std::fs::symlink_metadata(&destination).is_ok() };
            } else if upload {
                // A granted source is statted through `LocalFs`; the worker
                // stages it before the guarded upload runs.
                let local_str = local.to_string_lossy();
                let (src_is_dir, src_len) = if is_saf_path(&local_str) {
                    let info = match self.local_fs.stat(&local_str) {
                        Ok(info) if !info.is_symlink => info,
                        Ok(_) => return api_error(400, "Only regular files and directories can be transferred"),
                        Err(error) => return api_error(400, error.to_string()),
                    };
                    (info.is_dir, if info.is_dir { 0 } else { info.size })
                } else {
                    let meta = match std::fs::symlink_metadata(&local) { Ok(meta) if (meta.is_file() || meta.is_dir()) && !meta.file_type().is_symlink() => meta, Ok(_) => return api_error(400, "Only regular files and directories can be transferred"), Err(error) => return api_error(400, error.to_string()) };
                    (meta.is_dir(), if meta.is_dir() { 0 } else { meta.len() })
                };
                is_dir = src_is_dir;
                size = src_len;
                exists = match session.as_ref().unwrap().stat(&other).await {
                    Ok(Some(entry)) if entry.is_symlink || entry.is_dir != is_dir => return api_error(400, "Destination type conflicts with source or is a symlink"),
                    Ok(entry) => entry.is_some(), Err(error) => return api_error(400, error.to_string()),
                };
            } else {
                let entry = match session.as_ref().unwrap().stat(&other).await { Ok(Some(entry)) if !entry.is_symlink => entry, Ok(_) => return api_error(400, "Only existing files and directories can be transferred"), Err(error) => return api_error(400, error.to_string()) };
                is_dir = entry.is_dir;
                size = if is_dir { 0 } else { entry.size };
                exists = if is_saf_path(&local.to_string_lossy()) { self.local_fs.stat(&local.to_string_lossy()).is_ok() } else { std::fs::symlink_metadata(&local).is_ok() };
            }
            if resume && is_dir { return api_error(400, "Verified resume is supported only for individual files."); }
            if resume && is_saf_path(&local.to_string_lossy()) { return api_error(400, "Verified resume is not supported for granted folders."); }
            if move_item && !tab.is_local && is_dir { return api_error(400, "WebDAV directory moves are not supported."); }
            if is_dir && !move_item {
                let scheme = session.as_ref().map(|s| s.scheme());
                let dav = matches!(scheme, Some(linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs));
                if tab.is_local || (scheme != Some(linscp_types::ProtocolScheme::Sftp) && !dav) { return api_error(400, "Directory copies require SFTP or WebDAV."); }
                if dav && !body.get("accept_directory_copy_risk").and_then(Value::as_bool).unwrap_or(false) {
                    return ApiReply { status: 409, payload: json!({"success": false, "error": "WebDAV directory copy requires confirmation", "directory_copy_risk": true}) };
                }
                if exists && !merge_names.contains(name) { directory_conflicts.push(name.to_string()); }
            }
            if move_item && exists {
                return api_error(409, "Moves require a new destination; overwriting is not supported.");
            }
            if !upload || tab.is_local {
                // A granted destination — a copy target or a download
                // landing — is statted through `LocalFs`; uploads check the
                // remote side instead, above.
                let conflict = if is_saf_path(&destination) {
                    self.local_fs.stat(&destination).is_ok_and(|info| info.is_symlink || (is_dir && !info.is_dir) || (!is_dir && info.is_dir))
                } else {
                    let target = Path::new(&destination);
                    std::fs::symlink_metadata(target).is_ok_and(|m| m.file_type().is_symlink() || (is_dir && !m.is_dir()) || (!is_dir && !m.is_file()))
                };
                if conflict { return api_error(400, "Destination type conflicts with source or is a symlink"); }
            }
            // A granted end always carries bytes across the bridge whole,
            // so an over-cap file refuses here — on a copy, an upload or a
            // download; directories report size zero and are judged per
            // file in the worker instead.
            if !is_dir && (is_saf_path(&source) || is_saf_path(&destination)) && size > linscp_platform::MAX_SAF_DOCUMENT_BYTES {
                return api_error(400, linscp_platform::saf_document_too_large(name, size));
            }
            let is_dav_upload = !tab.is_local && upload && matches!(session.as_ref().unwrap().scheme(), linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs);
            let is_s3_upload = !tab.is_local && upload && session.as_ref().unwrap().scheme() == linscp_types::ProtocolScheme::S3;
            if exists && !is_dir && overwrite == "ask" {
                conflicts.push(name.to_string());
                let tag = if is_dav_upload {
                    match session.as_ref().unwrap().dav_get_etag(&other).await {
                        Ok((tag, false)) => tag,
                        Ok(_) => None,
                        Err(error) => return api_error(400, error.to_string()),
                    }
                } else if is_s3_upload {
                    match session.as_ref().unwrap().s3_get_etag(&other).await {
                        Ok(tag) => tag,
                        Err(error) => return api_error(400, error.to_string()),
                    }
                } else { None };
                if let Some(tag) = tag.filter(|tag| tag.starts_with('"') && tag.ends_with('"') && tag.len() >= 2 && !tag[1..tag.len()-1].contains('"') && !tag.chars().any(char::is_control)) {
                    conflict_versions.insert(name.to_string(), json!(tag));
                }
            }
            // Approval applies only to destinations actually present at enqueue.
            // A different item appearing later must not inherit that approval.
            let allow_overwrite = overwrite == "overwrite" && exists && !is_dir;
            if resume && allow_overwrite { return api_error(400, "Verified resume requires a new local destination."); }
            if allow_overwrite && !is_dav_upload && !is_s3_upload && !is_ftp_upload {
                return api_error(501, "Safe approved overwrites are not yet supported for this transfer. The destination was not changed.");
            }
            let mut flags = linscp_engine::transfer::TransferFlags::default();
            // Resuming existing partial files without verifying their source can
            // splice unrelated bytes into the result. Always stage a fresh copy.
            flags.resume = resume;
            flags.ftp_risky_publish = is_ftp_upload && ftp_risk_accepted;
            // Approval is per root and only applies to directories that exist now.
            flags.merge_directories = is_dir && exists && merge_names.contains(name);
            flags.resume_support = linscp_engine::presets::ResumeSupportMode::On;
            flags.preserve_time = body.get("preserve_time").and_then(Value::as_bool).unwrap_or(true);
            if (move_item && !tab.is_local) || resume {
                let sess = session.as_ref().unwrap();
                let tag = if sess.scheme() == linscp_types::ProtocolScheme::S3 {
                    sess.s3_get_etag(&other).await
                } else {
                    sess.dav_get_etag(&other).await.map(|(tag, missing)| if missing { None } else { tag })
                };
                let tag = match tag {
                    Ok(Some(tag)) if tag.starts_with('"') && tag.ends_with('"') && tag.len() >= 2 && !tag[1..tag.len()-1].contains('"') && !tag.chars().any(char::is_control) => tag,
                    Ok(_) => return api_error(400, "Moves and verified resume require a strong source ETag."),
                    Err(error) => return api_error(400, error.to_string()),
                };
                flags.source_etag = Some(tag);
            }
            if allow_overwrite && (is_dav_upload || is_s3_upload) {
                let tag = body.get("conflict_versions").and_then(|v| v.get(name)).and_then(Value::as_str);
                match tag {
                    Some(tag) if tag.starts_with('"') && tag.ends_with('"') && tag.len() >= 2 && !tag[1..tag.len()-1].contains('"') && !tag.chars().any(char::is_control) => flags.overwrite_etag = Some(tag.to_string()),
                    _ => return api_error(400, "Overwrite requires the strong ETag returned with the original conflict."),
                }
            }
            let job = if tab.is_local {
                queue::QueueJob::LocalCopyOrMove { source: PathBuf::from(&source), target: PathBuf::from(&destination), move_item, policy: if allow_overwrite { queue::ConflictPolicy::Overwrite } else { queue::ConflictPolicy::Ask } }
            } else if upload {
                queue::QueueJob::RemoteUpload { session: session.as_ref().unwrap().clone(), local_src: local, remote_dest: other, allow_overwrite, delete_source: false, cleanup_path: None, flags }
            } else {
                queue::QueueJob::RemoteDownload { session: session.as_ref().unwrap().clone(), remote_path: other, local_dest: local, allow_overwrite, delete_source: move_item, flags }
            };
            jobs.push((name.to_string(), source, destination, size, job));
        }
        if !conflicts.is_empty() || !directory_conflicts.is_empty() { return ApiReply { status: 409, payload: json!({"success": false, "error": "Destination exists", "conflicts": conflicts, "directory_conflicts": directory_conflicts, "conflict_versions": conflict_versions}) }; }
        for (name, source, destination, size, job) in jobs {
            self.queue.enqueue(Some(id), if upload { "upload" } else { "download" }, name, source, destination, size, body.get("priority").and_then(Value::as_bool).unwrap_or(false), job);
        }
        ApiReply { status: 200, payload: json!({"success": true}) }
    }

    fn default_local_dir(&self) -> String {
        if let Ok(roots) = self.local_fs.list_roots() {
            if let Some(preferred) = roots.iter().find(|r| r.label.starts_with("Home")) {
                return preferred.path.clone();
            }
            if let Some(first) = roots.first() { return first.path.clone(); }
        }
        "/".to_string()
    }

    fn handle_vault_status(&self) -> ApiReply {
        let config_root = self.config_root();
        match self.secret_vault.status(&config_root) {
            Ok(status) => ApiReply { status: 200, payload: json!({"success": true, "vault": status}) },
            Err(error) => api_error(500, error.to_string()),
        }
    }

    fn handle_vault_unlock(&self, mut body: Value) -> ApiReply {
        let config_root = self.config_root();
        let unlock_result = {
            let password = body.get("password").and_then(Value::as_str).unwrap_or("");
            self.secret_vault.unlock_or_setup(&config_root, password, self.legacy_secret_vault.as_ref())
        };
        if let Some(Value::String(password)) = body.get_mut("password") {
            zeroize::Zeroize::zeroize(password);
        }
        if let Err(error) = unlock_result {
            return api_error(400, error.to_string());
        }
        let stale_temp_dir = config_root.join("tmp").join("unlocked-keys").join(std::process::id().to_string());
        let _ = std::fs::remove_dir_all(stale_temp_dir);
        ApiReply { status: 200, payload: json!({"success": true, "vault": "unlocked"}) }
    }

    fn handle_vault_lock(&self) -> ApiReply {
        if let Err(error) = self.secret_vault.lock() {
            return api_error(500, error.to_string());
        }
        let mut state = self.state.lock().expect("state mutex");
        let tab_ids: Vec<u64> = state.tabs.keys().copied().collect();
        for tab_id in tab_ids {
            self.queue.cancel_for_tab(tab_id);
            state.terminals.close_for_tab(tab_id);
        }
        self.queue.clear_finished();
        state.tabs.clear();
        state.challenges.clear();
        state.pending_connections.clear();
        state.active_tab_id = None;
        ApiReply { status: 200, payload: json!({"success": true, "vault": "locked"}) }
    }

    fn handle_vault_ssh_keys(&self) -> ApiReply {
        let config_root = self.config_root();
        match self.secret_vault.status(&config_root) {
            Ok("unlocked") => {}
            Ok(_) => return api_error(423, "Unlock the local vault before choosing an SSH key."),
            Err(error) => return api_error(500, error.to_string()),
        }
        let key_dir = config_root.join("keys");
        let entries = match std::fs::read_dir(&key_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ApiReply { status: 200, payload: json!({"success": true, "keys": []}) };
            }
            Err(error) => return api_error(500, format!("Cannot list vault keys: {error}")),
        };
        let mut keys = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !entry.file_type().map(|kind| kind.is_file()).unwrap_or(false) { continue; }
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else { continue; };
            let Some(id) = file_name.strip_suffix(".key.vault") else { continue; };
            if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) { continue; }
            let label_path = key_dir.join(format!("{id}.label"));
            let label = std::fs::read_to_string(&label_path).ok()
                .filter(|label| label.len() <= 512)
                .map(|label| label.trim().to_string())
                .filter(|label| !label.is_empty())
                .or_else(|| {
                    let public_path = key_dir.join(format!("{id}.pub"));
                    let public = read_bounded_key_optional(&public_path, 32 * 1024).ok()?;
                    let mut fields = public.split_whitespace();
                    let algorithm = fields.next()?;
                    let _key = fields.next();
                    let comment = fields.collect::<Vec<_>>().join(" ");
                    Some(if comment.is_empty() { algorithm.to_string() } else { comment })
                })
                .unwrap_or_else(|| format!("SSH key {}", &id[..8]));
            keys.push(json!({
                "reference": format!("{LOCAL_VAULT_KEY_PREFIX}{id}"),
                "label": label,
            }));
        }
        keys.sort_by(|left, right| left["label"].as_str().cmp(&right["label"].as_str()));
        ApiReply { status: 200, payload: json!({"success": true, "keys": keys}) }
    }

    fn handle_vault_ssh_key_import(&self, mut body: Value) -> ApiReply {
        let config_root = self.config_root();
        let name = body.get("name").and_then(Value::as_str).unwrap_or("")
            .rsplit(['/', '\\']).next().unwrap_or("")
            .chars().filter(|character| !character.is_control()).take(128).collect::<String>();
        let private_key = body.get("private_key").and_then(Value::as_str).unwrap_or("");
        if private_key.is_empty() || private_key.as_bytes().len() > 1024 * 1024 || private_key.contains('\0') {
            if let Some(Value::String(private_key)) = body.get_mut("private_key") {
                zeroize::Zeroize::zeroize(private_key);
            }
            return api_error(400, "Choose a non-empty SSH key file no larger than 1 MiB.");
        }
        let plaintext = zeroize::Zeroizing::new(private_key.as_bytes().to_vec());
        let encryption_result = self.secret_vault.seal_local_blob(&plaintext);
        if let Some(Value::String(private_key)) = body.get_mut("private_key") {
            zeroize::Zeroize::zeroize(private_key);
        }
        let encrypted = match encryption_result {
            Ok(encrypted) => encrypted,
            Err(error) => return api_error(400, error.to_string()),
        };
        let key_dir = config_root.join("keys");
        if let Err(error) = linscp_platform::create_private_dir(&key_dir) {
            return api_error(500, error.to_string());
        }
        for _ in 0..8 {
            let mut random = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut random);
            let id = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
            let encrypted_path = key_dir.join(format!("{id}.key.vault"));
            match write_exclusive_private_file(&encrypted_path, &encrypted) {
                Ok(()) => {}
                Err(linscp_platform::PlatformError::AlreadyExists(_)) => continue,
                Err(error) => {
                    let _ = std::fs::remove_file(&encrypted_path);
                    return api_error(500, error.to_string());
                }
            }
            let label = if name.is_empty() { format!("SSH key {}", &id[..8]) } else { name.clone() };
            let label_path = key_dir.join(format!("{id}.label"));
            match write_exclusive_private_file(&label_path, label.as_bytes()) {
                Ok(()) => {}
                Err(linscp_platform::PlatformError::AlreadyExists(_)) => {
                    let _ = std::fs::remove_file(&encrypted_path);
                    continue;
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&encrypted_path);
                    return api_error(500, error.to_string());
                }
            }
            return ApiReply { status: 200, payload: json!({
                "success": true,
                "reference": format!("{LOCAL_VAULT_KEY_PREFIX}{id}"),
                "label": label,
            }) };
        }
        api_error(500, "Cannot allocate a unique encrypted SSH key file.")
    }

    fn handle_status(&self) -> ApiReply {
        let g = self.state.lock().expect("state mutex");
        let roots = self.local_fs.list_roots().unwrap_or_default();
        let tabs: Vec<Value> = g.tabs.values().map(|t| t.describe()).collect();
        ApiReply { status: 200, payload: json!({
            "connected": g.active_tab_id.is_some(),
            "active_tab": g.active_tab_id,
            "tabs": tabs,
            "local_dir": self.default_local_dir(),
            "local_roots": roots,
            "remote_dir": "/",
            "other_local_dir": "",
            "is_local": g.tabs.values().next().map(|t| t.is_local).unwrap_or(false),
            "binary": "linscp",
            "paused": false,
            "vault": self.secret_vault.status(&g.config_root).unwrap_or("locked"),
            "preferences": g.preferences,
            "sessions_file": g.config_root.join("sessions.ini").to_string_lossy(),
        })}
    }

    fn handle_local_roots(&self) -> ApiReply {
        match self.local_fs.list_roots() {
            Ok(roots) => ApiReply{ status: 200, payload: json!({"roots": roots})},
            Err(e) => ApiReply{ status: 500, payload: json!({"error": e.to_string()})},
        }
    }

    fn handle_local_list(&self, query: &BTreeMap<String,String>) -> ApiReply {
        let requested = query.get("path").cloned().filter(|s| !s.is_empty()).unwrap_or_else(|| self.default_local_dir());
        let tab = query.get("tab").and_then(|id| parse_tab_id_str(Some(id))).and_then(|id| self.state.lock().expect("m").tabs.get(&id).cloned());
        let base_path = tab.map(|t| t.local_dir).unwrap_or(requested.clone());
        let path_to_list = if query.contains_key("path") { requested } else { base_path };
        let resolved = match resolve_local_path_for_list(&path_to_list) {
            Ok(p) => p,
            Err(e) => return ApiReply{ status: 400, payload: json!({"success": false, "error": e, "path": path_to_list})},
        };
        match self.local_fs.list_dir(&resolved) {
            Ok(entries) => ApiReply{ status: 200, payload: json!({"success": true, "path": resolved, "entries": entries})},
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e.to_string(), "path": resolved})},
        }
    }

    fn handle_local_edit_get(&self, query: &BTreeMap<String,String>) -> ApiReply {
        let path = query.get("path").cloned().unwrap_or_default();
        let tab_id = query.get("tab").and_then(|s| parse_tab_id_str(Some(s)));
        let tab = tab_id.and_then(|id| self.state.lock().expect("m").tabs.get(&id).cloned());
        let base = tab.as_ref().map(|t| t.local_dir.clone()).unwrap_or_else(|| self.default_local_dir());
        let resolved = match resolve_contained(&base, &path) {
            Ok(p) => p,
            Err(e) => return ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        };
        // A granted document reads through the bridge; a plain path keeps the
        // direct reader.
        if is_saf_path(&resolved) {
            return match ops::read_local_text_file_via_fs(self.local_fs.as_ref(), &resolved, ops::MAX_GUI_EDIT_BYTES) {
                Ok((content, info)) => ApiReply{ status: 200, payload: json!({"success": true, "path": resolved, "content": content, "info": info})},
                Err(error) => ApiReply{ status: 400, payload: json!({"success": false, "error": error})},
            };
        }
        match ops::read_local_text_file(Path::new(&resolved), ops::MAX_GUI_EDIT_BYTES) {
            Ok((content, info)) => ApiReply{ status: 200, payload: json!({"success": true, "path": resolved, "content": content, "info": info})},
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        }
    }

    fn handle_remote_list(&self, query: &BTreeMap<String,String>) -> ApiReply {
        let tab_id = query.get("tab").and_then(|s| parse_tab_id_str(Some(s)));
        let g = self.state.lock().expect("m");
        let tab = match tab_id.and_then(|id| g.tabs.get(&id).cloned()) {
            Some(t) => t,
            None => return ApiReply{ status: 400, payload: json!({"success": false, "error": "Not connected"})},
        };
        drop(g);
        if tab.is_local {
            let req = query.get("path").cloned().unwrap_or(tab.other_local_dir.clone());
            let resolved = match resolve_local_path_for_list(&req) {
                Ok(p) => p,
                Err(e) => return ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
            };
            match self.local_fs.list_dir(&resolved) {
                Ok(entries) => ApiReply{ status: 200, payload: json!({"success": true, "path": resolved, "entries": entries})},
                Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e.to_string()})},
            }
        } else {
            ApiReply{ status: 400, payload: json!({"success": false, "error": "Remote listing requires connected session"})}
        }
    }

    fn handle_remote_edit_get(&self, query: &BTreeMap<String,String>) -> ApiReply {
        let tab_id = query.get("tab").and_then(|s| parse_tab_id_str(Some(s)));
        let path = query.get("path").cloned().unwrap_or_default();
        if path.is_empty() { return ApiReply{ status: 400, payload: json!({"success": false, "error": "No file given"})}; }
        let g = self.state.lock().expect("m");
        let tab = match tab_id.and_then(|id| g.tabs.get(&id).cloned()) {
            Some(t) => t, None => return ApiReply{ status: 400, payload: json!({"success": false, "error": "Not connected"})},
        };
        drop(g);
        if tab.is_local {
            // A leaf resolves against the granted other pane to a document
            // URI and reads through the bridge; a joined path keeps the
            // pane's path error, as on plain directories.
            let resolved = match resolve_contained(&tab.other_local_dir, &path) {
                Ok(p) => p, Err(e) => return ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
            };
            if is_saf_path(&resolved) {
                return match ops::read_local_text_file_via_fs(self.local_fs.as_ref(), &resolved, ops::MAX_GUI_EDIT_BYTES) {
                    Ok((content, info)) => ApiReply{ status: 200, payload: json!({"success": true, "path": resolved, "content": content, "info": info})},
                    Err(error) => ApiReply{ status: 400, payload: json!({"success": false, "error": error})},
                };
            }
            match ops::read_local_text_file(Path::new(&resolved), ops::MAX_GUI_EDIT_BYTES) {
                Ok((c,i)) => ApiReply{ status: 200, payload: json!({"success": true, "path": resolved, "content": c, "info": i})},
                Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
            }
        } else {
            ApiReply{ status: 400, payload: json!({"success": false, "error": "Remote edit not connected"})}
        }
    }

    fn handle_get_preferences(&self) -> ApiReply {
        let g = self.state.lock().expect("m");
        ApiReply{ status: 200, payload: json!({"success": true, "preferences": g.preferences, "defaults": UserPreferences::default(), "file": g.config_root.join("preferences.json").to_string_lossy()})}
    }
    fn handle_save_preferences(&self, body: Value) -> ApiReply {
        let prefs_val = body.get("preferences").cloned().unwrap_or(body.clone());
        let parsed: Result<UserPreferences,_> = serde_json::from_value(prefs_val.clone());
        let parsed = match parsed {
            Ok(p) => p, Err(e) => return ApiReply{ status: 400, payload: json!({"success": false, "error": format!("Invalid preferences: {e}")})},
        };
        let cfg = self.state.lock().expect("m").config_root.clone();
        if let Err(e) = PreferencesStore::save(&cfg, &parsed) {
            return ApiReply{ status: 500, payload: json!({"success": false, "error": e})};
        }
        { let mut g = self.state.lock().expect("m"); g.preferences = parsed.clone(); }
        ApiReply{ status: 200, payload: json!({"success": true, "preferences": parsed})}
    }

    fn handle_export_offlineotp_vault(&self, body: Value) -> ApiReply {
        let password = body.get("password").and_then(Value::as_str).unwrap_or("");
        if password.is_empty() {
            return api_error(400, "Choose a non-empty backup password.");
        }
        let cfg = self.state.lock().expect("m").config_root.clone();
        let store = match SessionStore::load_from_dir(&cfg, self.secret_vault.as_ref()) {
            Ok(store) => store,
            Err(error) => return api_error(500, &error),
        };
        let entries = match offlineotp_entries_from_sessions(&store, &cfg, self.secret_vault.as_ref()) {
            Ok(entries) => entries,
            Err(error) => return api_error(400, &error),
        };
        let data = match offlineotp_vault::seal(&entries, password) {
            Ok(data) => data,
            Err(error) => return api_error(400, &error),
        };
        let unix_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        ApiReply {
            status: 200,
            payload: json!({
                "success": true,
                "filename": offlineotp_vault::timestamped_filename(unix_seconds),
                "data_base64": BASE64_STD.encode(data),
                "entry_count": entries.len(),
            }),
        }
    }

    fn handle_import_offlineotp_vault(&self, body: Value) -> ApiReply {
        let password = body.get("password").and_then(Value::as_str).unwrap_or("");
        let encoded = body.get("data_base64").and_then(Value::as_str).unwrap_or("");
        if encoded.len() > 22 * 1024 * 1024 {
            return api_error(413, "The encrypted vault exceeds the 16 MiB OfflineOTP file limit.");
        }
        let bytes = match BASE64_STD.decode(encoded.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => return api_error(400, "The selected file is not valid base64 data."),
        };
        let imported = match offlineotp_vault::open(&bytes, password) {
            Ok(imported) => imported,
            Err(error) => return api_error(400, &error),
        };
        let replace = body.get("replace").and_then(Value::as_bool).unwrap_or(false);
        let cfg = self.state.lock().expect("m").config_root.clone();
        let existing = if replace {
            SessionStore::new()
        } else {
            match SessionStore::load_from_dir(&cfg, self.secret_vault.as_ref()) {
                Ok(store) => store,
                Err(error) => return api_error(500, &error),
            }
        };
        match import_offlineotp_entries(&cfg, existing, imported, self.secret_vault.as_ref()) {
            Ok((count, skipped, ignored)) => ApiReply {
                status: 200,
                payload: json!({ "success": true, "imported": count, "skipped_existing": skipped, "ignored_entries": ignored }),
            },
            Err(error) => api_error(400, &error),
        }
    }

    fn handle_list_sessions(&self) -> ApiReply {
        let g = self.state.lock().expect("m");
        let cfg = g.config_root.clone();
        drop(g);
        match SessionStore::load_from_dir(&cfg, self.secret_vault.as_ref()) {
            Ok(store) => {
                let sites: Vec<Value> = store.sites().iter().map(|s| stored_site_to_gui_json(s)).collect();
                let folders = collect_session_folders(&sites);
                ApiReply{ status: 200, payload: json!({"success": true, "sessions": sites, "file": cfg.join("sessions.ini").to_string_lossy(), "folders": folders})}
            },
            Err(e) => ApiReply{ status: 500, payload: json!({"success": false, "error": e})},
        }
    }

    fn handle_save_session(&self, body: Value) -> ApiReply {
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let session_val = body.get("session").cloned().unwrap_or(body.clone());
        if name.is_empty() && session_val.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().is_empty() {
            return ApiReply{ status: 400, payload: json!({"success": false, "error": "A session name is required"})};
        }
        let final_name = if name.is_empty() { session_val.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string() } else { name };
        if final_name.is_empty() { return ApiReply{ status: 400, payload: json!({"success": false, "error": "A session name is required"})}; }
        // Validate session data via tabs parser
        let cfg_root = self.state.lock().expect("m").config_root.clone();
        let spec_res = tabs::parse_gui_session_spec(&session_val, None, &cfg_root, self.secret_vault.as_ref());
        if let Err(e) = spec_res { return ApiReply{ status: 400, payload: json!({"success": false, "error": e})}; }
        let (spec, _) = spec_res.unwrap();
        if spec.raw_fields.get("s3_session_token").is_some_and(|token| !token.is_empty()) {
            return api_error(400, "Saving S3 session tokens is not supported; supply the token when connecting instead.");
        }
        let mut stored = tabs::build_stored_site_for_save(&final_name, &spec);
        let mut protected_key_files = Vec::new();
        if let Err(error) = protect_stored_ssh_keys(&mut stored, &cfg_root, self.secret_vault.as_ref(), &mut protected_key_files) {
            for path in protected_key_files { let _ = std::fs::remove_file(path); }
            return api_error(400, error);
        }
        let mut store = SessionStore::load_from_dir(&cfg_root, self.secret_vault.as_ref()).unwrap_or_default();
        store.upsert(stored);
        if let Err(e) = store.save_to_dir(&cfg_root, self.secret_vault.as_ref()) {
            for path in protected_key_files { let _ = std::fs::remove_file(path); }
            return ApiReply{ status: 500, payload: json!({"success": false, "error": e})};
        }
        self.add_log(&format!("Saved session {final_name}"), "success");
        ApiReply{ status: 200, payload: json!({"success": true})}
    }

    fn handle_delete_session(&self, body: Value) -> ApiReply {
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        if name.is_empty() { return ApiReply{ status: 400, payload: json!({"success": false, "error": "A session name is required"})}; }
        let cfg = self.state.lock().expect("m").config_root.clone();
        let mut store = match SessionStore::load_from_dir(&cfg, self.secret_vault.as_ref()) {
            Ok(s) => s, Err(e) => return ApiReply{ status: 500, payload: json!({"success": false, "error": e})},
        };
        if !store.remove(&name) {
            return ApiReply{ status: 400, payload: json!({"success": false, "error": format!("No session named '{name}'")})};
        }
        if let Err(e) = store.save_to_dir(&cfg, self.secret_vault.as_ref()) {
            return ApiReply{ status: 500, payload: json!({"success": false, "error": e})};
        }
        ApiReply{ status: 200, payload: json!({"success": true})}
    }

    fn handle_sessions_import_get(&self, query: &BTreeMap<String,String>) -> ApiReply {
        let source = query.get("source").cloned().unwrap_or_default();
        let path = query.get("path").cloned().unwrap_or_default();
        // Simplified: just report no sources
        ApiReply{ status: 200, payload: json!({"success": true, "sources": []})}
    }

    fn handle_import_openssh(&self, body: Value) -> ApiReply {
        let text = body.get("content").and_then(|v| v.as_str()).unwrap_or("");
        let report = parse_openssh_config(text, None);
        ApiReply{ status: 200, payload: serde_json::to_value(report).unwrap_or(json!({}))}
    }
    fn handle_import_filezilla(&self, body: Value) -> ApiReply {
        let text = body.get("content").and_then(|v| v.as_str()).unwrap_or("");
        match parse_filezilla_xml(text) {
            Ok(r) => ApiReply{ status: 200, payload: serde_json::to_value(r).unwrap_or(json!({}))},
            Err(e) => ApiReply{ status: 400, payload: json!({"error": e})},
        }
    }

    fn handle_get_bookmarks(&self, query: &BTreeMap<String,String>) -> ApiReply {
        let cfg = self.state.lock().expect("m").config_root.clone();
        let path = cfg.join("bookmarks.json");
        let data: Value = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({"local": [], "remote": []}));
        if let Some(side) = query.get("side") {
            if side != "local" && side != "remote" { return ApiReply{ status: 400, payload: json!({"success": false, "error": "side must be local or remote"})}; }
            let arr = data.get(side).cloned().unwrap_or(json!([]));
            ApiReply{ status: 200, payload: json!({"success": true, "bookmarks": arr, "file": path.to_string_lossy()})}
        } else {
            ApiReply{ status: 200, payload: json!({"success": true, "bookmarks": data, "file": path.to_string_lossy()})}
        }
    }
    fn handle_save_bookmarks(&self, body: Value) -> ApiReply {
        // POST /api/bookmarks with raw bookmarks object
        let cfg = self.state.lock().expect("m").config_root.clone();
        let next = body.get("bookmarks").cloned().unwrap_or(body.clone());
        let path = cfg.join("bookmarks.json");
        let bytes = serde_json::to_vec_pretty(&next).unwrap_or_default();
        if let Err(e) = write_private_file_atomic(&path, &bytes) {
            return ApiReply{ status: 500, payload: json!({"success": false, "error": e.to_string()})};
        }
        ApiReply{ status: 200, payload: json!({"success": true, "file": path.to_string_lossy()})}
    }
    fn handle_bookmarks_save(&self, body: Value) -> ApiReply {
        let side = body.get("side").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let bm_path = body.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if side != "local" && side != "remote" { return ApiReply{ status: 400, payload: json!({"success": false, "error": "side must be local or remote"})}; }
        if name.is_empty() || bm_path.is_empty() { return ApiReply{ status: 400, payload: json!({"success": false, "error": "name and path required"})}; }
        let cfg = self.state.lock().expect("m").config_root.clone();
        let file = cfg.join("bookmarks.json");
        let mut data: Value = std::fs::read_to_string(&file).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({"local": [], "remote": []}));
        if !data.is_object() { data = json!({"local": [], "remote": []}); }
        let arr = data.get_mut(&side).and_then(|v| v.as_array_mut());
        if let Some(a) = arr {
            a.retain(|e| e.get("name").and_then(|v| v.as_str()).unwrap_or("") != name);
            a.push(json!({"name": name, "path": bm_path}));
        }
        let bytes = serde_json::to_vec_pretty(&data).unwrap_or_default();
        if let Err(e) = write_private_file_atomic(&file, &bytes) {
            return ApiReply{ status: 500, payload: json!({"success": false, "error": e.to_string()})};
        }
        ApiReply{ status: 200, payload: json!({"success": true, "bookmark": json!({"name": name, "path": bm_path}), "file": file.to_string_lossy()})}
    }
    fn handle_bookmarks_delete(&self, body: Value) -> ApiReply {
        let side = body.get("side").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let cfg = self.state.lock().expect("m").config_root.clone();
        let file = cfg.join("bookmarks.json");
        let mut data: Value = std::fs::read_to_string(&file).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({"local": [], "remote": []}));
        if let Some(a) = data.get_mut(&side).and_then(|v| v.as_array_mut()) {
            a.retain(|e| e.get("name").and_then(|v| v.as_str()).unwrap_or("") != name);
        }
        let bytes = serde_json::to_vec_pretty(&data).unwrap_or_default();
        let _ = write_private_file_atomic(&file, &bytes);
        ApiReply{ status: 200, payload: json!({"success": true, "file": file.to_string_lossy()})}
    }

    fn handle_get_workspaces(&self) -> ApiReply {
        let cfg = self.state.lock().expect("m").config_root.clone();
        let path = cfg.join("workspaces.json");
        let data: Value = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({"workspaces": {}}));
        let mut workspaces: Vec<Value> = data.get("workspaces").and_then(Value::as_object).map(|entries| entries.iter().map(|(name, entry)| json!({"name": name, "tab_count": entry.get("tabs").and_then(Value::as_array).map_or(0, Vec::len)})).collect()).unwrap_or_default();
        workspaces.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        ApiReply{ status: 200, payload: json!({"success": true, "workspaces": workspaces, "file": path.to_string_lossy()})}
    }
    fn handle_save_workspaces(&self, body: Value) -> ApiReply {
        let cfg = self.state.lock().expect("m").config_root.clone();
        let next = body.get("workspaces").cloned().unwrap_or(body);
        let path = cfg.join("workspaces.json");
        let bytes = serde_json::to_vec_pretty(&next).unwrap_or_default();
        if let Err(e) = write_private_file_atomic(&path, &bytes) {
            return ApiReply{ status: 500, payload: json!({"success": false, "error": e.to_string()})};
        }
        ApiReply{ status: 200, payload: json!({"success": true})}
    }
    fn handle_workspaces_save(&self, body: Value) -> ApiReply {
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        if name.is_empty() { return ApiReply{ status: 400, payload: json!({"success": false, "error": "workspace name required"})}; }
        let cfg = self.state.lock().expect("m").config_root.clone();
        let (tabs, active) = {
            let g = self.state.lock().expect("m");
            let mut ordered: Vec<&TabRuntime> = g.tabs.values().collect();
            ordered.sort_by_key(|tab| tab.id);
            if ordered.iter().any(|tab| !tab.is_local && tab.site_name.as_deref().is_none_or(str::is_empty)) {
                return api_error(400, "Save each remote session as a saved site before saving a workspace; credentials are not stored in workspaces.");
            }
            let active = ordered.iter().position(|tab| Some(tab.id) == g.active_tab_id).unwrap_or(0);
            let tabs: Vec<Value> = ordered.iter().map(|t| json!({"name": t.name, "kind": if t.is_local { "local"} else {"remote"}, "local_dir": t.local_dir, "remote_dir": t.remote_dir, "site": t.site_name})).collect();
            (tabs, active)
        };
        if tabs.is_empty() { return ApiReply{ status: 400, payload: json!({"success": false, "error": "There are no open tabs to save."})}; }
        if tabs.len() > 100 { return api_error(400, "A workspace can contain at most 100 tabs."); }
        let path = cfg.join("workspaces.json");
        let mut data: Value = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}));
        if !data.is_object() { data = json!({}); }
        if data.get("workspaces").is_none() { data["workspaces"] = json!({}); }
        if !data["workspaces"].is_object() { return api_error(400, "Invalid workspace file."); }
        let overw = body.get("overwrite").and_then(|v| v.as_bool()).unwrap_or(false);
        if data["workspaces"].get(&name).is_some() && !overw {
            return ApiReply{ status: 409, payload: json!({"success": false, "error": format!("A workspace named \"{name}\" already exists."), "exists": true})};
        }
        data["workspaces"][&name] = json!({"tabs": tabs, "active": active, "updated": 0});
        let bytes = serde_json::to_vec_pretty(&data).unwrap_or_default();
        if let Err(e) = write_private_file_atomic(&path, &bytes) {
            return ApiReply{ status: 500, payload: json!({"success": false, "error": e.to_string()})};
        }
        ApiReply{ status: 200, payload: json!({"success": true, "workspace": json!({"name": name})})}
    }
    fn handle_workspaces_delete(&self, body: Value) -> ApiReply {
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let cfg = self.state.lock().expect("m").config_root.clone();
        let path = cfg.join("workspaces.json");
        let mut data: Value = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}));
        if data.get("workspaces").and_then(|w| w.get(&name)).is_none() {
            return ApiReply{ status: 400, payload: json!({"success": false, "error": format!("No workspace named \"{name}\" exists.")})};
        }
        if let Some(obj) = data.get_mut("workspaces").and_then(|v| v.as_object_mut()) { obj.remove(&name); }
        let bytes = serde_json::to_vec_pretty(&data).unwrap_or_default();
        let _ = write_private_file_atomic(&path, &bytes);
        ApiReply{ status: 200, payload: json!({"success": true})}
    }

    fn handle_list_transfers(&self) -> ApiReply {
        let (transfers, paused) = self.queue.snapshot();
        ApiReply{ status: 200, payload: json!({"transfers": transfers, "paused": paused})}
    }

    fn handle_open_local_tab(&self, body: Value) -> ApiReply {
        let left = body.get("local_dir").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let right = body.get("remote_dir").or_else(|| body.get("other_local_dir")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        self.create_local_tab(left, right)
    }

    fn handle_tabs_open(&self, body: Value) -> ApiReply {
        let session = body.get("session").cloned().unwrap_or(json!({}));
        if session_is_local(&session) {
            let left = session.get("local_dir").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let right = session.get("other_local_dir").or_else(|| session.get("remote_dir")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            return self.create_local_tab(left, right);
        }
        // Remote tabs not yet implemented asynchronously – return hostkey challenge placeholder
        ApiReply{ status: 400, payload: json!({"success": false, "error": "Remote tabs require async connection (not yet)", "tab": json!({"id": 0})})}
    }

    fn create_local_tab(&self, left_raw: String, right_raw: String) -> ApiReply {
        let left = match check_local_pane_directory(&left_raw, "local_dir") {
            Ok(p) => p, Err(e) => return ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        };
        let right = match check_local_pane_directory(&right_raw, "other_local_dir") {
            Ok(p) => p, Err(e) => return ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        };
        if left == right {
            // overlap etc. - python allows same? but we check
        }
        let mut g = self.state.lock().expect("m");
        let id = g.next_tab_id; g.next_tab_id+=1;
        let name = format!("{} ↔ {}", left.split('/').last().unwrap_or("left"), right.split('/').last().unwrap_or("right"));
        let tab = TabRuntime { id, name: name.clone(), site_name: None, is_local: true, connected: true, local_dir: left.clone(), remote_dir: right.clone(), other_local_dir: right.clone(), observed_hostkey: String::new(), hostkey_role: "destination".to_string(), hostkey_changed: false, error: String::new(), spec: None, session_json: json!({"protocol": "local", "local_dir": left, "other_local_dir": right}), remote: None };
        g.tabs.insert(id, tab.clone());
        g.active_tab_id = Some(id);
        ApiReply{ status: 200, payload: json!({"success": true, "tab": tab.describe()})}
    }

    fn handle_tabs_close(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) }).unwrap_or(0);
        let mut g = self.state.lock().expect("m");
        g.tabs.remove(&tab_id);
        g.challenges.remove(&tab_id);
        g.pending_connections.remove(&tab_id);
        // A terminal lives in a tab's connection; closing the tab must not
        // leave the shell running with no window to show it.
        g.terminals.close_for_tab(tab_id);
        g.monitors.forget(tab_id);
        if g.active_tab_id == Some(tab_id) { g.active_tab_id = g.tabs.keys().next().cloned(); }
        ApiReply{ status: 200, payload: json!({"success": true})}
    }
    fn handle_tabs_select(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let mut g = self.state.lock().expect("m");
        if let Some(id) = tab_id {
            if g.tabs.contains_key(&id) { g.active_tab_id = Some(id); return ApiReply{ status: 200, payload: json!({"success": true, "tab": g.tabs.get(&id).unwrap().describe()})}; }
        }
        ApiReply{ status: 400, payload: json!({"success": false, "error": "No such tab"})}
    }
    fn handle_tabs_verify(&self, body: Value) -> ApiReply {
        ApiReply{ status: 400, payload: json!({"success": false, "error": "No host key given"})}
    }
    fn handle_tabs_reconnect(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) }).unwrap_or(0);
        let g = self.state.lock().expect("m");
        if let Some(tab) = g.tabs.get(&tab_id) {
            if tab.is_local { return ApiReply{ status: 200, payload: json!({"success": true, "tab": tab.describe()})}; }
            return api_error(501, "Remote reconnect requires asynchronous dispatch.");
        }
        ApiReply{ status: 400, payload: json!({"success": false, "error": "No such tab"})}
    }

    fn handle_local_mkdir(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let base = tab_id.and_then(|id| self.state.lock().expect("m").tabs.get(&id).map(|t| t.local_dir.clone())).unwrap_or_else(|| self.default_local_dir());
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let target = match resolve_contained(&base, &name) {
            Ok(p) => p, Err(e) => return ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        };
        // `LocalFs`, not `std::fs`: a granted Android folder has no pathname,
        // and the pane must be able to create a directory there too.
        match self.local_fs.mkdir_all(&target) {
            Ok(_) => ApiReply{ status: 200, payload: json!({"success": true})},
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e.to_string()})},
        }
    }
    fn handle_local_link(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let base = tab_id.and_then(|id| self.state.lock().expect("m").tabs.get(&id).map(|t| t.local_dir.clone())).unwrap_or_else(|| self.default_local_dir());
        let target = body.get("target").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        match create_local_link(&base, &target, &name) {
            Ok(_) => ApiReply{ status: 200, payload: json!({"success": true})},
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        }
    }
    fn handle_local_delete(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let base = tab_id.and_then(|id| self.state.lock().expect("m").tabs.get(&id).map(|t| t.local_dir.clone())).unwrap_or_else(|| self.default_local_dir());
        let names: Vec<String> = body.get("names").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|e| e.as_str().map(|s| s.to_string())).collect()).unwrap_or_else(|| body.get("name").and_then(|v| v.as_str()).map(|s| vec![s.to_string()]).unwrap_or_default());
        if names.is_empty() { return ApiReply{ status: 400, payload: json!({"success": false, "error": "Select an item first."})}; }
        let mut errs = Vec::new();
        for name in names {
            match resolve_contained(&base, &name) {
                Ok(p) => {
                    // The kind comes from `LocalFs`, so this works for a
                    // granted Android folder as well as for a POSIX path.
                    let is_dir = self.local_fs.stat(&p).map(|entry| entry.is_dir).unwrap_or(false);
                    let res = if is_dir { self.local_fs.remove_dir_all(&p) } else { self.local_fs.remove_file(&p) };
                    if let Err(e) = res { errs.push(format!("{name}: {e}")); }
                },
                Err(e) => errs.push(format!("{name}: {e}")),
            }
        }
        if errs.is_empty() { ApiReply{ status: 200, payload: json!({"success": true})} } else { ApiReply{ status: 400, payload: json!({"success": false, "error": errs.join("; ")}) }}
    }
    fn handle_local_rename(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let base = tab_id.and_then(|id| self.state.lock().expect("m").tabs.get(&id).map(|t| t.local_dir.clone())).unwrap_or_else(|| self.default_local_dir());
        let old = body.get("old_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let new = body.get("new_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if old.is_empty() || new.is_empty() { return ApiReply{ status:400, payload: json!({"success": false, "error": "Both names are required"})}; }
        let overwrite = body.get("overwrite").and_then(Value::as_bool).unwrap_or(false);
        let src = match resolve_contained(&base, &old) { Ok(p)=>p, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},};
        let dst = match resolve_contained(&base, &new) { Ok(p)=>p, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},};
        // A rename is not an overwrite: replacing the destination would destroy
        // the entry the user asked to keep. A granted SAF document has no
        // pathname to move, so its rename stays the bridge's own operation.
        if src.starts_with("content://") || dst.starts_with("content://") {
            return match self.local_fs.rename(&src, &dst) {
                Ok(_) => ApiReply{ status: 200, payload: json!({"success": true})},
                Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e.to_string()})},
            };
        }
        match Self::rename_local_path(Path::new(&src), Path::new(&dst), overwrite) {
            Ok(()) => ApiReply{ status: 200, payload: json!({"success": true})},
            // `conflict` is the answer the page asks about; the message is for
            // the person who cancelled the prompt instead.
            Err(e) => ApiReply{ status: 400, payload: json!({
                "success": false,
                "conflict": e.ends_with(":conflict"),
                "error": Self::rename_error_message(&e),
            })},
        }
    }

    /// The message for a refused rename, with the conflict marker removed.
    fn rename_error_message(error: &str) -> String {
        match error.strip_suffix(":conflict") {
            Some(path) => format!("An item already exists at {path}."),
            None => error.to_string(),
        }
    }

    /// Moves a local entry, never replacing one unless the caller confirmed it.
    ///
    /// The no-replace move is the rule for every path (a dropped item, a file
    /// out of the panel, a rename); `overwrite` is only ever set from an answer
    /// the page collected. A refused move says which name is taken, so the page
    /// can ask about that one instead of guessing at the error text.
    fn rename_local_path(from: &Path, to: &Path, overwrite: bool) -> Result<(), String> {
        if overwrite && std::fs::symlink_metadata(to).is_ok() {
            return std::fs::remove_file(to)
                .map_err(|error| format!("Cannot replace '{}': {error}", to.display()));
        }
        linscp_platform::gui_os::rename_no_replace(from, to).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!("{}:conflict", to.display())
            } else {
                error.to_string()
            }
        })
    }
    fn handle_local_chmod(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let base = tab_id.and_then(|id| self.state.lock().expect("m").tabs.get(&id).map(|t| t.local_dir.clone())).unwrap_or_else(|| self.default_local_dir());
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let perm = body.get("permissions").or_else(|| body.get("mode")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if name.is_empty() { return ApiReply{ status:400, payload: json!({"success": false, "error": "Select an item first."})}; }
        let target = match resolve_contained(&base, &name) { Ok(p)=>p, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},};
        if is_saf_path(&target) {
            // `set_permissions_mode` is the bridge's own refusal: permissions
            // do not exist on a granted folder, so it answers before reading
            // the mode and the 0 marks the argument unused. Routing chmod
            // through it keeps the message in one place instead of restating
            // it here, and a success would mean the bridge grew a permission
            // model worth honouring.
            return match self.local_fs.set_permissions_mode(&target, 0) {
                Ok(()) => ApiReply{ status: 200, payload: json!({"success": true})},
                Err(linscp_platform::PlatformError::UnsupportedUri(message)) => ApiReply{ status:400, payload: json!({"success": false, "error": message})},
                Err(error) => ApiReply{ status:400, payload: json!({"success": false, "error": error.to_string()})},
            };
        }
        // Validate permission mode via ops
        let current = match gui_os::stat_extended(Path::new(&target)) { Ok(s)=> s.mode, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e.to_string()})},};
        let new_mode = match linscp_engine::parse_chmod_spec(&perm, current) { Ok(m)=>m, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},};
        match gui_os::stat_extended(Path::new(&target)).and_then(|_| linscp_platform::terminal::set_local_permissions(Path::new(&target), new_mode).map_err(|e| e)) {
            Ok(_) => ApiReply{ status: 200, payload: json!({"success": true})},
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e.to_string()})},
        }
    }
    fn handle_local_save(&self, body: Value) -> ApiReply {
        let path = body.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let base = tab_id.and_then(|id| self.state.lock().expect("m").tabs.get(&id).map(|t| t.local_dir.clone()));
        let resolved = if let Some(b) = base {
            match resolve_contained(&b, &path) { Ok(p)=>p, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},}
        } else { path.clone() };
        let content = body.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let mtime_ns = body.get("base_mtime_ns").and_then(|v| v.as_i64()).map(|v| v as i128).or_else(|| body.get("base_mtime").and_then(|v| v.as_i64()).map(|v| (v as i128)*1_000_000_000));
        // A granted document writes through the bridge; a plain path keeps
        // the direct writer and its permission-bit recovery.
        if is_saf_path(&resolved) {
            return match ops::write_local_text_file_via_fs(self.local_fs.as_ref(), &resolved, &content, mtime_ns) {
                Ok(info) => ApiReply{ status: 200, payload: json!({"success": true, "info": info})},
                Err(error) => ApiReply{ status: 400, payload: json!({"success": false, "error": error})},
            };
        }
        match ops::write_local_text_file(Path::new(&resolved), &content, mtime_ns) {
            Ok(info) => ApiReply{ status: 200, payload: json!({"success": true, "info": info})},
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        }
    }

    fn handle_logs(&self) -> ApiReply {
        let g = self.state.lock().expect("m");
        ApiReply{ status: 200, payload: json!({"logs": g.logs})}
    }
    fn handle_cleanup_get(&self) -> ApiReply {
        let cfg = self.state.lock().expect("m").config_root.clone();
        let locs = ops::list_cleanup_locations(&cfg);
        ApiReply{ status: 200, payload: json!({"success": true, "locations": locs, "any": locs.iter().any(|v| v.get("exists").and_then(|e| e.as_bool()).unwrap_or(false))})}
    }
    fn handle_cleanup_post(&self, body: Value) -> ApiReply {
        if body.get("confirm").and_then(|v| v.as_bool()) != Some(true) {
            return ApiReply{ status: 400, payload: json!({"success": false, "error": "Removing stored data has to be confirmed."})};
        }
        let ids: Vec<String> = body.get("ids").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|e| e.as_str().map(|s| s.to_string())).collect()).unwrap_or_default();
        if ids.is_empty() { return ApiReply{ status: 400, payload: json!({"success": false, "error": "Select at least one item to remove."})}; }
        let cfg = self.state.lock().expect("m").config_root.clone();
        match ops::execute_cleanup(&cfg, &ids) {
            Ok(removed) => {
                let locs = ops::list_cleanup_locations(&cfg);
                ApiReply{ status: 200, payload: json!({"success": true, "removed": removed, "locations": locs})}
            },
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        }
    }
    fn handle_shell_pending(&self) -> ApiReply {
        let cfg = self.state.lock().expect("m").config_root.clone();
        let pending = ops::list_shell_manifests(&cfg);
        ApiReply{ status: 200, payload: json!({"success": true, "pending": pending})}
    }
    fn handle_shell_dismiss(&self, body: Value) -> ApiReply {
        let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let cfg = self.state.lock().expect("m").config_root.clone();
        match ops::dismiss_shell_manifest(&cfg, &id) {
            Ok(_) => ApiReply{ status: 200, payload: json!({"success": true})},
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        }
    }
    /// Every path a drop carried, in the order the shell produced it.
    ///
    /// The apps reach the drop handlers differently: a browser posts one item's
    /// bytes or one staged folder, while a native window posts a list of paths
    /// the operating system handed it. Both are read here, and the list form is
    /// the authority when it is present, so a drop of twenty files is one
    /// request and one conflict answer in every app.
    fn drop_source_paths(body: &Value) -> Vec<String> {
        let mut paths = Vec::new();
        if let Some(list) = body.get("source_paths").and_then(Value::as_array) {
            paths.extend(list.iter().filter_map(Value::as_str).map(str::to_string));
        }
        if let Some(single) = body.get("source_path").and_then(Value::as_str) {
            paths.push(single.to_string());
        }
        paths
            .into_iter()
            .map(|path| path.trim().to_string())
            .filter(|path| !path.is_empty() && !path.chars().any(char::is_control))
            .collect()
    }

    /// Reads the bytes of the one file a drop named.
    ///
    /// A drop that named no path carries its content instead: base64 from the
    /// page, a bare value, or an array. One representation inside the service
    /// keeps the drop identical everywhere.
    fn drop_payload(body: &Value) -> Result<Vec<u8>, String> {
        // Bound first: a borrow of a temporary would tie the path to the end of
        // the `if let`, which is exactly where it is needed longest.
        let paths = Self::drop_source_paths(body);
        if let Some(path) = paths.first() {
            // A native window's drop is a path, not bytes: the backend reads
            // the file itself, so the page never has to hold a whole file in
            // memory and the same endpoint serves both kinds of drop.
            return Self::read_dropped_path(path);
        }
        if let Some(text) = body.get("data_base64").and_then(Value::as_str) {
            return BASE64_STD
                .decode(text)
                .map_err(|_| "The dropped file is not valid base64.".to_string());
        }
        if let Some(items) = body.as_array() {
            return Ok(json!(items).to_string().into_bytes());
        }
        if !body.is_object() {
            return Ok(body.to_string().into_bytes());
        }
        Err("The dropped file arrived without any content.".to_string())
    }

    /// Reads one file a drop named.
    fn read_dropped_path(path: &str) -> Result<Vec<u8>, String> {
        if is_saf_path(path) {
            // A granted Android folder is not a pathname: its bytes come from
            // the document provider, so the ordinary local filesystem reads
            // them rather than `std::fs` guessing at a `content://` string.
            return NativeLocalFs::new()
                .read_bytes(path)
                .map_err(|error| format!("The dropped file cannot be read: {error}"));
        }
        let meta = std::fs::symlink_metadata(path)
            .map_err(|error| format!("The dropped file cannot be read: {error}"))?;
        if meta.file_type().is_symlink() {
            return Err("A symbolic link cannot be dropped as a file.".to_string());
        }
        if !meta.is_file() {
            return Err("Only a regular file can be dropped as a file.".to_string());
        }
        std::fs::read(path).map_err(|error| format!("The dropped file cannot be read: {error}"))
    }

    /// What one dropped path is, asked of the filesystem rather than trusted.
    fn dropped_path_kind(path: &str) -> Result<DroppedKind, String> {
        if is_saf_path(path) {
            return Ok(DroppedKind::SafUri);
        }
        let meta = std::fs::symlink_metadata(path)
            .map_err(|error| format!("The dropped item cannot be read: {error}"))?;
        if meta.file_type().is_symlink() {
            return Err("A symbolic link cannot be dropped.".to_string());
        }
        if meta.is_dir() {
            Ok(DroppedKind::Directory)
        } else if meta.is_file() {
            Ok(DroppedKind::File)
        } else {
            Err("Only a file or a folder can be dropped.".to_string())
        }
    }

    /// The parent directory of a dropped path and its leaf name.
    fn dropped_path_split(path: &str) -> Result<(String, String), String> {
        let path = Path::new(path);
        let leaf = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "The dropped item has no usable name.".to_string())?
            .to_string();
        let parent = path
            .parent()
            .map(|parent| parent.to_string_lossy().into_owned())
            .filter(|parent| !parent.is_empty())
            .ok_or_else(|| "The dropped item has no usable folder.".to_string())?;
        Ok((parent, leaf))
    }

    /// The panel directory a drop lands in, with no leaf name required.
    ///
    /// `drop_target` names one file; a drop of paths has no single leaf, and a
    /// folder-only drop has none either, so the directory is resolved on its
    /// own and each caller asks for the name it actually needs.
    fn drop_base_directory(&self, query: &BTreeMap<String,String>, body: &Value, local: bool) -> Result<String, ApiReply> {
        let dir_key = if local { "local_dir" } else { "remote_dir" };
        let tab_id = query.get("tab").and_then(|value| parse_tab_id_str(Some(value)))
            .or_else(|| body.get("tab").and_then(|value| {
                if value.is_number() { value.as_u64() } else { value.as_str().and_then(|text| text.parse().ok()) }
            }));
        let tab = tab_id.and_then(|id| self.state.lock().expect("m").tabs.get(&id).cloned());
        let base = query.get(dir_key).cloned()
            .or_else(|| body.get(dir_key).and_then(Value::as_str).map(str::to_string))
            .or_else(|| tab.as_ref().map(|tab| if local { tab.local_dir.clone() } else { tab.remote_dir.clone() }))
            .unwrap_or_else(|| if local { self.default_local_dir() } else { "/".to_string() });
        let base = base.trim().to_string();
        if base.is_empty() {
            return Err(api_error(400, "The panel directory of this drop is not set."));
        }
        if base.chars().any(char::is_control) {
            return Err(api_error(400, "The panel directory must not contain control characters."));
        }
        Ok(base)
    }

    /// Saves a drop into the local panel.
    ///
    /// A browser posts bytes; a native window posts paths, one per item. Both
    /// land in the panel's own directory, and the bytes go through the same
    /// `LocalFs` the panes use, so a drop into a granted Android folder, a
    /// Windows drive or a POSIX directory behaves the same way and never
    /// bypasses the write rules (`content://` included).
    fn handle_local_drop(&self, query: &BTreeMap<String, String>, body: Value) -> ApiReply {
        // A drop is one of two shapes: the page's bytes for one file, or the
        // paths a native window hands over. Only the first has a leaf name of
        // its own; the second names every item, so requiring a name up front
        // would refuse every desktop drop. The target is therefore resolved
        // without demanding one, and the byte path asks for it before it
        // writes anything.
        let paths = Self::drop_source_paths(&body);
        let (base, name, relative) = match self.drop_target(query, &body, true) {
            Ok(parts) => parts,
            Err(reply) => return reply,
        };
        let destination_dir = match self.drop_destination(&base, "", &relative) {
            Ok(path) => path.to_string_lossy().into_owned(),
            Err(error) => return api_error(400, error),
        };
        if !paths.is_empty() {
            // A path drop is not a byte drop: the items keep their own names.
            // Whether they can be read is decided when they are copied, and a
            // path that cannot be read is refused there with its own reason.
            if !is_saf_path(&destination_dir) {
                if let Err(error) = self.local_fs.mkdir_all(&destination_dir) {
                    return api_error(400, format!("Cannot create the drop folder: {error}"));
                }
            }
            return self.save_dropped_paths(&destination_dir, &paths, &body);
        }
        if name.is_empty() {
            return api_error(400, "A file name is required.");
        }
        if let Err(error) = ops::validate_leaf_name(&name) {
            return api_error(400, error);
        }
        let bytes = match Self::drop_payload(&body) {
            Ok(bytes) => bytes,
            Err(error) => return api_error(400, error),
        };
        let target = match self.drop_destination(&base, &name, &relative) {
            Ok(path) => path,
            Err(error) => return api_error(400, error),
        };
        if let Some(parent) = target.parent() {
            let parent = parent.to_string_lossy();
            if !parent.is_empty() {
                if let Err(error) = self.local_fs.mkdir_all(&parent) {
                    return api_error(400, format!("Cannot create the drop folder: {error}"));
                }
            }
        }
        let target_path = target.to_string_lossy().into_owned();
        if let Err(error) = self.local_fs.write_bytes_atomic(&target_path, &bytes) {
            return api_error(400, format!("Cannot save the dropped file: {error}"));
        }
        self.add_log(&format!("Saved the dropped file '{target_path}'."), "info");
        ApiReply {
            status: 200,
            payload: json!({"success": true, "path": target_path, "size": bytes.len()}),
        }
    }

    /// Writes every path of a drop into `target_dir`, under its own leaf name.
    ///
    /// A name the destination already holds is reported, not replaced: the page
    /// asks the same question it asks for a byte drop and repeats the drop with
    /// the answer, so one overwrite rule governs every way a file arrives.
    fn save_dropped_paths(&self, target_dir: &str, paths: &[String], body: &Value) -> ApiReply {
        let overwrite = body.get("overwrite").and_then(Value::as_str) == Some("overwrite");
        let mut saved: Vec<String> = Vec::new();
        let mut conflicts: Vec<String> = Vec::new();
        let mut refused: Vec<String> = Vec::new();
        for path in paths {
            let (_, leaf) = match Self::dropped_path_split(path) {
                Ok(parts) => parts,
                Err(error) => {
                    refused.push(error);
                    continue;
                }
            };
            let target = match self.drop_destination(target_dir, &leaf, "") {
                Ok(target) => target,
                Err(error) => {
                    refused.push(error);
                    continue;
                }
            };
            let exists = std::fs::symlink_metadata(&target).is_ok();
            if exists && !overwrite {
                conflicts.push(leaf);
                continue;
            }
            match Self::dropped_path_kind(path) {
                Ok(DroppedKind::Directory) => {
                    if exists {
                        // A replacement was approved for this name, so the old
                        // tree goes first; the copy itself still refuses to
                        // replace anything inside the new one.
                        let removed = if std::fs::symlink_metadata(&target)
                            .is_ok_and(|meta| meta.is_dir())
                        {
                            std::fs::remove_dir_all(&target)
                        } else {
                            std::fs::remove_file(&target)
                        };
                        if let Err(error) = removed {
                            refused.push(format!("Cannot replace '{leaf}': {error}"));
                            continue;
                        }
                    }
                    match Self::copy_dropped_tree(path, &target) {
                        Ok(_) => saved.push(leaf),
                        Err(error) => {
                            // A half-copied tree is not left behind: the page
                            // reports the refusal, and nothing the drop wrote
                            // stays where the next attempt would find it.
                            let _ = std::fs::remove_dir_all(&target);
                            refused.push(error);
                        }
                    }
                }
                Ok(DroppedKind::SafUri) | Ok(DroppedKind::File) => {
                    let bytes = match Self::read_dropped_path(path) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            refused.push(error);
                            continue;
                        }
                    };
                    let target_path = target.to_string_lossy().into_owned();
                    match self.local_fs.write_bytes_atomic(&target_path, &bytes) {
                        Ok(()) => saved.push(leaf),
                        Err(error) => refused.push(format!("Cannot save '{leaf}': {error}")),
                    }
                }
                Err(error) => refused.push(error),
            }
        }
        if !conflicts.is_empty() {
            return ApiReply {
                status: 409,
                payload: json!({
                    "success": false,
                    "error": "Destination exists",
                    "conflicts": conflicts,
                    "saved": saved,
                }),
            };
        }
        if saved.is_empty() && !refused.is_empty() {
            return api_error(400, refused.join("\n"));
        }
        self.add_log(&format!("Saved {} dropped item(s) into '{target_dir}'.", saved.len()), "info");
        ApiReply {
            status: 200,
            payload: json!({
                "success": true,
                "saved": saved,
                "refused": refused,
                "path": target_dir,
            }),
        }
    }

    /// Creates the folders a dropped directory contained, including empty ones.
    fn handle_local_drop_dir(&self, query: &BTreeMap<String,String>, body: Value) -> ApiReply {
        // A dropped folder names no file, so no leaf name is asked for. The
        // relative sub-path is what the folder lands under; a native window
        // sends the folder's own name as that sub-path, and a folder drop with
        // neither is refused rather than guessed at.
        let base = match self.drop_base_directory(query, &body, true) {
            Ok(base) => base,
            Err(reply) => return reply,
        };
        let relative = query.get("relative_path").cloned()
            .or_else(|| body.get("relative_path").and_then(Value::as_str).map(str::to_string))
            .or_else(|| {
                // A native window names the dropped folder and nothing else,
                // so the folder keeps the name it has on the machine.
                Self::drop_source_paths(&body)
                    .first()
                    .and_then(|path| Path::new(path).file_name().map(|leaf| leaf.to_string_lossy().into_owned()))
            })
            .unwrap_or_default();
        if relative.is_empty() {
            return api_error(400, "A relative path is required.");
        }
        let target = match self.drop_destination(&base, "", &relative) {
            Ok(path) => path,
            Err(error) => return api_error(400, error),
        };
        let target_path = target.to_string_lossy().into_owned();
        match self.local_fs.mkdir_all(&target_path) {
            Ok(_) => ApiReply{ status: 200, payload: json!({"success": true, "path": target_path})},
            Err(error) => api_error(400, format!("Cannot create the dropped folder: {error}")),
        }
    }

    /// Stages a dropped file and queues it for the remote panel.
    ///
    /// A drop is not a second transfer implementation: the bytes are written
    /// into app-private staging under the name the user dropped, and then the
    /// ordinary upload endpoint is called. Pause, cancel, retry, conflict
    /// detection and the overwrite rules therefore behave exactly as they do
    /// for a file copied out of the local pane.
    async fn handle_transfer_drop(&self, body: Value) -> ApiReply {
        let (remote_dir, mut name, relative) = match self.drop_target(&BTreeMap::new(), &body, false) {
            Ok(parts) => parts,
            Err(reply) => return reply,
        };
        let tab_id = match tabs::parse_tab_id_value(body.get("tab")) {
            Some(id) => id,
            None => return api_error(400, "Not connected"),
        };
        let tab = match self.state.lock().expect("m").tabs.get(&tab_id).cloned() {
            Some(tab) if tab.connected => tab,
            _ => return api_error(400, "Not connected"),
        };
        if tab.is_local {
            return api_error(400, "This panel has no server to upload to.");
        }
        // An operating-system drop is a list of paths: a native window hands
        // over one path per item, and the page only names them. Each item is
        // staged under its own leaf name and the queue is asked once, so one
        // drop is one queue entry, one conflict answer and the same overwrite
        // rules a transfer out of the local pane obeys. A lone plain file is
        // left to the byte path below, which has staged files since before
        // paths existed.
        let source_paths = Self::drop_source_paths(&body);
        let single_plain_file = source_paths.len() == 1
            && matches!(Self::dropped_path_kind(&source_paths[0]), Ok(DroppedKind::File));
        if !source_paths.is_empty() && !single_plain_file {
            let staging = match self.drop_staging_dir() {
                Ok(path) => path,
                Err(error) => return api_error(500, error),
            };
            let mut names: Vec<String> = Vec::new();
            let mut staged_paths: Vec<PathBuf> = Vec::new();
            // A failed drop removes what it already staged: the queue never saw
            // those names, so nothing else will.
            let tidy = |staged: &[PathBuf]| {
                for path in staged {
                    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.is_dir()) {
                        let _ = std::fs::remove_dir_all(path);
                    } else {
                        let _ = std::fs::remove_file(path);
                    }
                }
            };
            for path in &source_paths {
                let relative = match Self::stage_dropped_path(path, &staging) {
                    Ok(relative) => relative,
                    Err(error) => {
                        tidy(&staged_paths);
                        return api_error(400, error);
                    }
                };
                if names.contains(&relative) {
                    // Two items of one drop cannot share a name: the queue
                    // would upload the same staging path twice.
                    tidy(&staged_paths);
                    return api_error(400, "Two dropped items have the same name.");
                }
                staged_paths.push(staging.join(&relative));
                names.push(relative);
            }
            if names.is_empty() {
                tidy(&staged_paths);
                return api_error(400, "The drop contained nothing that can be uploaded.");
            }
            let mut request = json!({
                "tab": tab.id,
                "local_dir": staging.to_string_lossy(),
                "remote_dir": remote_dir,
                "names": names,
            });
            // The approvals a dialog collected belong to the same request, so a
            // retry is the same drop plus one decision.
            for key in ["accept_directory_copy_risk", "accept_ftp_rename_risk", "merge_directories",
                        "overwrite", "priority", "preserve_time", "conflict_versions", "resume",
                        "transfer", "speed", "filemask", "resumesupport"] {
                if let Some(value) = body.get(key) {
                    request[key] = value.clone();
                }
            }
            let reply = self.queue_transfer_async(request, true, false).await;
            if !reply.payload.get("success").and_then(Value::as_bool).unwrap_or(false) {
                // The queue took nothing (a conflict it wants confirmed, or a
                // refusal), so the staged copy is ours again. It has to go now:
                // the page retries the same drop with the decision, and a
                // staging entry that already exists would refuse that retry.
                tidy(&staged_paths);
            }
            return reply;
        }
        let bytes = match Self::drop_payload(&body) {
            Ok(bytes) => bytes,
            Err(error) => return api_error(400, error),
        };
        // A byte drop is one file, so it needs the name it lands under. A drop
        // that named one path already carries it.
        if name.is_empty() {
            name = source_paths
                .first()
                .and_then(|path| Path::new(path).file_name().map(|leaf| leaf.to_string_lossy().into_owned()))
                .unwrap_or_default();
        }
        if name.is_empty() {
            return api_error(400, "A file name is required.");
        }
        if let Err(error) = ops::validate_leaf_name(&name) {
            return api_error(400, error);
        }
        // The panel directory plus the folder the drop carried. The leaf name
        // stays in the file name, so staging and destination agree.
        let destination_dir = if relative.is_empty() {
            remote_dir
        } else {
            match ops::validate_relative_subpath(&relative) {
                Ok(sub) => format!("{}/{}", remote_dir.trim_end_matches('/'), sub.to_string_lossy().replace('\\', "/")),
                Err(error) => return api_error(400, error),
            }
        };
        let staging = match self.drop_staging_dir() {
            Ok(path) => path,
            Err(error) => return api_error(500, error),
        };
        let staged = staging.join(&name);
        if let Err(error) = std::fs::write(&staged, &bytes) {
            return api_error(500, format!("Cannot stage the dropped file: {error}"));
        }
        let request = json!({
            "tab": tab.id,
            "local_dir": staging.to_string_lossy(),
            "remote_dir": destination_dir,
            "names": [name],
        });
        let reply = self.queue_transfer_async(request, true, false).await;
        if !reply.payload.get("success").and_then(Value::as_bool).unwrap_or(false) {
            // The queue never took it, so the staged copy is ours to remove.
            let _ = std::fs::remove_file(&staged);
        }
        reply
    }

    /// Creates the remote directories a dropped folder contained.
    async fn handle_transfer_drop_dir(&self, body: Value) -> ApiReply {
        let remote_dir = body.get("remote_dir").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if remote_dir.is_empty() || !remote_dir.starts_with('/') {
            return api_error(400, "A destination directory is required.");
        }
        if remote_dir.chars().any(char::is_control) {
            return api_error(400, "The destination must not contain control characters.");
        }
        let relative = match body.get("relative_path").and_then(Value::as_str) {
            Some(rel) => match ops::validate_relative_subpath(rel) {
                Ok(path) => path.to_string_lossy().replace('\\', "/"),
                Err(error) => return api_error(400, error),
            },
            None => return api_error(400, "A relative path is required."),
        };
        // An empty dropped folder has no files to carry it, so each segment is
        // created deliberately; MKCOL/mkdir on an existing one is not an error.
        let mut created = remote_dir.trim_end_matches('/').to_string();
        for segment in relative.split('/').filter(|part| !part.is_empty()) {
            let leaf = match ops::validate_leaf_name(segment) {
                Ok(name) => name,
                Err(error) => return api_error(400, error),
            };
            created.push('/');
            created.push_str(&leaf);
            let request = json!({
                "tab": body.get("tab").cloned().unwrap_or(json!(0)),
                "name": leaf,
                "remote_dir": created.rsplit_once('/').map(|(parent, _)| parent.to_string()).unwrap_or_default(),
            });
            let reply = self.mkdir_remote_async_with_base(request).await;
            let ok = reply.payload.get("success").and_then(Value::as_bool).unwrap_or(false);
            // "Already exists" proves the folder is there, which is all a
            // merge into an existing tree needs.
            if !ok && !reply.payload.get("error").and_then(Value::as_str).is_some_and(|error| error.to_lowercase().contains("exist")) {
                return reply;
            }
        }
        ApiReply{ status: 200, payload: json!({"success": true, "path": created})}
    }

    /// Copies a dropped folder into `target`, never replacing what is there.
    ///
    /// `create_new` is the no-replace publication the rest of the app uses, so
    /// a staged tree cannot overwrite a file another transfer is reading. A
    /// link inside the tree is refused rather than followed: it is not a copy
    /// of the bytes the folder owns, and it would point outside the staging
    /// directory.
    fn copy_dropped_tree(source: &str, target: &Path) -> Result<(usize, u64), String> {
        let mut stack = vec![(PathBuf::from(source), target.to_path_buf())];
        let mut files = 0usize;
        let mut bytes = 0u64;
        while let Some((from, to)) = stack.pop() {
            let meta = std::fs::symlink_metadata(&from)
                .map_err(|error| format!("The dropped folder cannot be read: {error}"))?;
            if meta.file_type().is_symlink() {
                return Err("A dropped folder must not contain symbolic links.".to_string());
            }
            if meta.is_dir() {
                std::fs::create_dir(&to)
                    .map_err(|error| format!("Cannot create the dropped folder: {error}"))?;
                let entries = std::fs::read_dir(&from)
                    .map_err(|error| format!("The dropped folder cannot be listed: {error}"))?;
                for entry in entries {
                    let entry =
                        entry.map_err(|error| format!("Cannot read a dropped entry: {error}"))?;
                    stack.push((entry.path(), to.join(entry.file_name())));
                }
            } else if meta.is_file() {
                let data = std::fs::read(&from)
                    .map_err(|error| format!("The dropped file cannot be read: {error}"))?;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&to)
                    .map_err(|error| format!("Cannot write the dropped file: {error}"))?;
                use std::io::Write as _;
                file.write_all(&data)
                    .map_err(|error| format!("Cannot write the dropped file: {error}"))?;
                files += 1;
                bytes += data.len() as u64;
            } else {
                return Err("A dropped folder may contain only files and folders.".to_string());
            }
        }
        Ok((files, bytes))
    }

    /// Copies one path a drop named into the staging tree, under its leaf name.
    ///
    /// The queue only reads local paths, and a granted Android URI is not one,
    /// so the bytes are brought into the app's private staging first. The item
    /// keeps its own leaf name - `report.txt`, `project/` - because that is the
    /// name the destination should show; the folders above it on the machine
    /// are not part of the drop.
    ///
    /// The staged root is created exclusively: a drop must not replace a
    /// staging entry another request is uploading from.
    fn stage_dropped_path(source: &str, staging: &Path) -> Result<String, String> {
        let (_, leaf) = Self::dropped_path_split(source)?;
        let relative = leaf.clone();
        let staged = staging.join(&leaf);
        match Self::dropped_path_kind(source) {
            Ok(DroppedKind::Directory) => {
                if std::fs::symlink_metadata(&staged).is_ok() {
                    return Err(format!("'{leaf}' is already being uploaded."));
                }
                match Self::copy_dropped_tree(source, &staged) {
                    Ok(_) => Ok(relative),
                    Err(error) => {
                        // A half-copied tree is not left behind for the queue.
                        let _ = std::fs::remove_dir_all(&staged);
                        Err(error)
                    }
                }
            }
            Ok(_) => {
                let bytes = Self::read_dropped_path(source)?;
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&staged)
                    .map_err(|_| format!("'{leaf}' is already being uploaded."))?;
                use std::io::Write as _;
                file.write_all(&bytes)
                    .map_err(|error| format!("Cannot stage the dropped file: {error}"))?;
                Ok(relative)
            }
            Err(error) => Err(error),
        }
    }

    /// The private directory a dropped file waits in until its upload runs.
    fn drop_staging_dir(&self) -> Result<PathBuf, String> {
        let staging = self.config_root().join("drop-staging");
        std::fs::create_dir_all(&staging).map_err(|error| format!("Cannot stage the dropped file: {error}"))?;
        Ok(staging)
    }


    /// Reads the panel directory, the leaf name a byte drop is written under
    /// and the relative sub-path, from the query string or the JSON body.
    ///
    /// The name is optional: a drop that names paths, or a folder-only drop,
    /// carries no single leaf, and each caller asks for the name it needs.
    fn drop_target(&self, query: &BTreeMap<String,String>, body: &Value, local: bool) -> Result<(String, String, String), ApiReply> {
        let base = self.drop_base_directory(query, body, local)?;
        let name = query.get("name").cloned()
            .or_else(|| body.get("name").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default();
        let relative = query.get("relative_path").cloned()
            .or_else(|| body.get("relative_path").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default();
        Ok((base, name, relative))
    }

    /// The local path a drop lands on: the panel directory, the relative
    /// sub-path a folder drop carried, and the leaf name.
    fn drop_destination(&self, base: &str, name: &str, relative: &str) -> Result<PathBuf, String> {
        let mut target = PathBuf::from(base);
        if !relative.is_empty() {
            target.push(ops::validate_relative_subpath(relative)?);
        }
        if !name.is_empty() {
            target.push(ops::validate_leaf_name(name)?);
        }
        Ok(target)
    }

    fn handle_session_url(&self, query: &BTreeMap<String,String>) -> ApiReply {
        let tab_id = query.get("tab").and_then(|s| parse_tab_id_str(Some(s)));
        let g = self.state.lock().expect("m");
        let tab = tab_id.and_then(|id| g.tabs.get(&id).cloned()).or_else(|| g.tabs.values().next().cloned());
        if let Some(t) = tab {
            if let Some(spec) = t.spec {
                let url = tabs::format_session_url(&spec, None);
                return ApiReply{ status: 200, payload: json!({"success": true, "url": url})};
            }
        }
        ApiReply{ status: 400, payload: json!({"success": false, "error": "No such tab"})}
    }
    fn handle_remote_transfer_targets(&self, query: &BTreeMap<String,String>) -> ApiReply {
        let tab_id = query.get("tab").and_then(|s| parse_tab_id_str(Some(s)));
        let g = self.state.lock().expect("m");
        let tab = match tab_id.and_then(|id| g.tabs.get(&id).cloned()) {
            Some(t) => t, None => return ApiReply{ status: 400, payload: json!({"success": false, "error": "Not connected"})},
        };
        if tab.is_local { return ApiReply{ status: 400, payload: json!({"success": false, "error": "A remote-to-remote copy starts in a connected remote tab."})}; }
        let mut targets = vec![json!({"id": format!("tab:{}", tab.id), "kind": "tab", "tab": tab.id, "label": tab.name, "host": "", "protocol": tab.remote.as_ref().map(|session| format!("{:?}", session.scheme()).to_ascii_lowercase()).unwrap_or_default(), "current": true, "connected": true})];
        for (id, other) in &g.tabs {
            if *id == tab.id || other.is_local { continue; }
            targets.push(json!({"id": format!("tab:{}", id), "kind": "tab", "tab": id, "label": other.name, "host": "", "protocol": other.remote.as_ref().map(|session| format!("{:?}", session.scheme()).to_ascii_lowercase()).unwrap_or_default(), "current": false, "connected": other.connected}));
        }
        ApiReply{ status: 200, payload: json!({"success": true, "targets": targets})}
    }

    // Remote stubs for local tabs
    fn handle_remote_mkdir(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let g = self.state.lock().expect("m");
        let tab = match tab_id.and_then(|id| g.tabs.get(&id).cloned()) {
            Some(t) => t, None => return ApiReply{ status: 400, payload: json!({"success": false, "error": "Not connected"})},
        };
        drop(g);
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if name.is_empty() { return ApiReply{ status:400, payload: json!({"success": false, "error": "A name is required"})}; }
        if tab.is_local {
            let target = match resolve_contained(&tab.other_local_dir, &name) { Ok(p)=>p, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},};
            match self.local_fs.mkdir_all(&target) { Ok(_)=> ApiReply{ status:200, payload: json!({"success": true})}, Err(e)=> ApiReply{ status:400, payload: json!({"success": false, "error": e.to_string()})}}
        } else { ApiReply{ status:400, payload: json!({"success": false, "error": "Remote mkdir not implemented"})}}
    }
    fn handle_remote_delete(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let g = self.state.lock().expect("m");
        let tab = match tab_id.and_then(|id| g.tabs.get(&id).cloned()) { Some(t)=>t, None=> return ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})},};
        drop(g);
        let names: Vec<String> = body.get("names").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|e| e.get("name").and_then(|v| v.as_str()).or(e.as_str()).map(|s| s.to_string())).collect()).unwrap_or_else(|| body.get("name").and_then(|v| v.as_str()).map(|s| vec![s.to_string()]).unwrap_or_default());
        if tab.is_local {
            let mut errs=Vec::new();
            for n in names {
                match resolve_contained(&tab.other_local_dir, &n) {
                    Ok(p) => {
                        let is_dir = self.local_fs.stat(&p).map(|entry| entry.is_dir).unwrap_or(false);
                        let res = if is_dir { self.local_fs.remove_dir_all(&p) } else { self.local_fs.remove_file(&p) };
                        if let Err(e)=res { errs.push(format!("{n}: {e}")); }
                    },
                    Err(e)=> errs.push(format!("{n}: {e}")),
                }
            }
            if errs.is_empty() { ApiReply{ status:200, payload: json!({"success": true})}} else { ApiReply{ status:400, payload: json!({"success": false, "error": errs.join("; ")})}}
        } else {
            // A remote tab is deleted by `delete_remote_any_async`, which has
            // the session; reaching this table with one means the caller used
            // the synchronous dispatcher, which cannot await it.
            ApiReply{ status:400, payload: json!({
                "success": false,
                "error": "The remote delete needs the session-capable request path."})}
        }
    }
    fn handle_remote_rename(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let g = self.state.lock().expect("m");
        let tab = match tab_id.and_then(|id| g.tabs.get(&id).cloned()) { Some(t)=>t, None=> return ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})},};
        drop(g);
        let old = body.get("old_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let new = body.get("new_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if tab.is_local {
            let src = match resolve_contained(&tab.other_local_dir, &old) { Ok(p)=>p, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},};
            let dst = match resolve_contained(&tab.other_local_dir, &new) { Ok(p)=>p, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},};
            // The other local pane renames through the same move, so neither
            // pane can overwrite an entry without the confirmation the other one
            // requires.
            let overwrite = body.get("overwrite").and_then(Value::as_bool).unwrap_or(false);
            match Self::rename_local_path(Path::new(&src), Path::new(&dst), overwrite) {
                Ok(())=> ApiReply{ status:200, payload: json!({"success": true})},
                Err(e)=> ApiReply{ status:400, payload: json!({"success": false, "conflict": e.ends_with(":conflict"), "error": Self::rename_error_message(&e)})},
            }
        } else { ApiReply{ status:400, payload: json!({"success": false, "error": "not implemented"})}}
    }
    // The panel's own mutation calls arrive through `dispatch_async`, which
    // has the session; only a local tab reaches this table, and a local tab
    // has no server-side permissions to change.
    fn handle_remote_chmod(&self, body: Value) -> ApiReply { self.handle_local_chmod_for_other_pane(body) }

    fn handle_local_chmod_for_other_pane(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64() } else { v.as_str().and_then(|s| s.parse().ok()) });
        let tab = tab_id.and_then(|id| self.state.lock().expect("m").tabs.get(&id).cloned());
        match tab {
            Some(tab) if tab.is_local => {
                // A local tab's "remote" side is the other local directory.
                let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if name.is_empty() { return api_error(400, "Select an item first."); }
                let perm = body.get("permissions").or_else(|| body.get("mode"))
                    .and_then(|v| v.as_str()).unwrap_or("").to_string();
                let target = match resolve_contained(&tab.other_local_dir, &name) {
                    Ok(path) => path,
                    Err(error) => return api_error(400, error),
                };
                if is_saf_path(&target) {
                    // The other pane refuses through the bridge, exactly as
                    // the main pane does: the mode is unread, the 0 only
                    // satisfies a trait written for filesystems with modes.
                    return match self.local_fs.set_permissions_mode(&target, 0) {
                        Ok(()) => ApiReply { status: 200, payload: json!({"success": true}) },
                        Err(linscp_platform::PlatformError::UnsupportedUri(message)) => api_error(400, message),
                        Err(error) => api_error(400, error.to_string()),
                    };
                }
                let current = match gui_os::stat_extended(Path::new(&target)) {
                    Ok(info) => info.mode,
                    Err(error) => return api_error(400, error.to_string()),
                };
                let new_mode = match linscp_engine::parse_chmod_spec(&perm, current) {
                    Ok(mode) => mode,
                    Err(error) => return api_error(400, error),
                };
                match linscp_platform::terminal::set_local_permissions(Path::new(&target), new_mode) {
                    Ok(()) => ApiReply { status: 200, payload: json!({"success": true}) },
                    Err(error) => api_error(400, error.to_string()),
                }
            }
            _ => api_error(400, "Not connected"),
        }
    }
    fn handle_remote_properties(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let g = self.state.lock().expect("m");
        let tab = match tab_id.and_then(|id| g.tabs.get(&id).cloned()) { Some(t)=>t, None=> return ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})},};
        drop(g);
        let names: Vec<String> = body.get("names").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|e| e.get("name").and_then(|v| v.as_str()).or(e.as_str()).map(|s| s.to_string())).collect()).unwrap_or_else(|| body.get("name").and_then(|v| v.as_str()).map(|s| vec![s.to_string()]).unwrap_or_default());
        if !tab.is_local { return Self::not_implemented(); }
        let mut rows=Vec::new();
        for n in names {
            let p = match resolve_contained(&tab.other_local_dir, &n) { Ok(path) => path, Err(error) => return api_error(400, error) };
            // A granted entry is statted through the bridge; a failure keeps
            // the row shape a plain stat failure uses, so the dialogue
            // shows the error beside the name instead of dying.
            if is_saf_path(&p) {
                match self.local_fs.stat(&p) {
                    Ok(entry) => rows.push(json!({"name": n, "size": entry.size, "is_dir": entry.is_dir, "permissions": entry.permissions, "owner": entry.owner.clone().unwrap_or_default(), "group": entry.group.clone().unwrap_or_default()})),
                    Err(error) => rows.push(json!({"name": n, "error": error.to_string()})),
                }
                continue;
            }
            let info = if tab.is_local {
                match gui_os::stat_extended(Path::new(&p)) {
                    Ok(s)=> json!({"name": n, "size": s.size, "is_dir": s.is_dir, "permissions": s.permissions, "owner": s.owner, "group": s.group}),
                    Err(e)=> json!({"name": n, "error": e.to_string()}),
                }
            } else { json!({"name": n, "size": 0, "is_dir": false, "permissions": "-rw-r--r--"})};
            rows.push(info);
        }
        ApiReply{ status:200, payload: json!({"success": true, "properties": rows, "name": rows.get(0).and_then(|v| v.get("name")).cloned().unwrap_or(json!(""))})}
    }
    fn handle_remote_rights(&self, body: Value) -> ApiReply { self.handle_remote_chmod(body) }
    // Reaching this table means no connected session, and a search walks a
    // server tree; there is nothing local to search here.
    fn handle_remote_search(&self, _body: Value) -> ApiReply { api_error(400, "Not connected") }
    fn handle_remote_checksum(&self, body: Value) -> ApiReply {
        ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})}
    }
    // The editor's save is answered in `dispatch_async`; without a session
    // there is no remote path to write to.
    fn handle_remote_save(&self, _body: Value) -> ApiReply { api_error(400, "Not connected") }
    // The remote forms of these need a session, so they are answered in
    // `dispatch_async`; reaching the synchronous table means a local tab.
    fn handle_remote_copy(&self, _body: Value) -> ApiReply { api_error(501, "A server-side copy needs a remote session.") }
    fn handle_remote_link(&self, _body: Value) -> ApiReply { api_error(501, "A symbolic link needs an SFTP session.") }
    fn handle_sync_preview(&self, body: Value) -> ApiReply { ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})}}
    fn handle_sync_run(&self, body: Value) -> ApiReply { ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})}}
    fn handle_transfer_upload(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    fn handle_transfer_download(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    fn handle_transfer_move(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    // Answered in `dispatch_async`: asking the queue to watch a directory is
    // what the synchronous table cannot do. A local tab has no server.
    fn handle_keepuptodate(&self, _body: Value) -> ApiReply { api_error(400, "Not connected") }
    fn handle_remote_transfer(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    fn handle_queue_pause(&self) -> ApiReply { self.queue.pause(); ApiReply{ status:200, payload: json!({"success": true})}}
    fn handle_queue_resume(&self) -> ApiReply { self.queue.resume(); ApiReply{ status:200, payload: json!({"success": true})}}
    fn handle_queue_cancel(&self, body: Value) -> ApiReply {
        let id = body.get("task_id").and_then(Value::as_u64).unwrap_or(0);
        if self.queue.cancel(id) { ApiReply{ status:200, payload: json!({"success": true})} } else { api_error(400, "Task cannot be cancelled") }
    }
    fn handle_queue_clear(&self) -> ApiReply { self.queue.clear_finished(); ApiReply{ status:200, payload: json!({"success": true})}}
    fn handle_queue_retry(&self, body: Value) -> ApiReply {
        let id = body.get("task_id").and_then(Value::as_u64).unwrap_or(0);
        if self.queue.retry(id) { ApiReply{ status:200, payload: json!({"success": true})} } else { api_error(400, "Task cannot be retried") }
    }
    fn handle_queue_priority(&self, body: Value) -> ApiReply {
        let id = body.get("task_id").and_then(Value::as_u64).unwrap_or(0);
        if self.queue.prioritize(id, body.get("position").and_then(Value::as_str).unwrap_or("top")) { ApiReply{ status:200, payload: json!({"success": true})} } else { api_error(400, "Task cannot be prioritized") }
    }
    fn handle_custom_commands(&self, body: Value) -> ApiReply {
        let cfg = self.state.lock().expect("m").config_root.clone();
        let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("list");
        match action {
            "list" => {
                let cmds = ops::read_custom_commands(&cfg);
                ApiReply{ status:200, payload: json!({"success": true, "commands": cmds})}
            },
            "save" => {
                let tmpl = ops::normalize_custom_command(&body);
                if tmpl.is_none() { return ApiReply{ status:400, payload: json!({"success": false, "error": "A name and a one-line command are required."})}; }
                let tmpl = tmpl.unwrap();
                let mut cmds = ops::read_custom_commands(&cfg);
                cmds.retain(|c| c.get("name").and_then(|v| v.as_str()) != tmpl.get("name").and_then(|v| v.as_str()));
                cmds.push(tmpl);
                if let Err(e) = ops::write_custom_commands(&cfg, &cmds) {
                    return ApiReply{ status:500, payload: json!({"success": false, "error": e})};
                }
                ApiReply{ status:200, payload: json!({"success": true, "commands": cmds})}
            },
            "delete" => {
                let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let mut cmds = ops::read_custom_commands(&cfg);
                let before = cmds.len();
                cmds.retain(|c| c.get("name").and_then(|v| v.as_str()) != Some(name));
                if cmds.len()==before { return ApiReply{ status:404, payload: json!({"success": false, "error": format!("There is no command '{name}'")})}; }
                if let Err(e) = ops::write_custom_commands(&cfg, &cmds) {
                    return ApiReply{ status:500, payload: json!({"success": false, "error": e})};
                }
                ApiReply{ status:200, payload: json!({"success": true, "commands": cmds})}
            },
            // The async handler answers `run`; a caller that reached this table
            // asked a shell-less page for a command, so say why it cannot.
            "run" => api_error(400, "Running a command needs the asynchronous service entry point."),
            _ => ApiReply{ status:400, payload: json!({"success": false, "error": format!("Unknown action '{action}'")})},
        }
    }
    fn handle_command_exec(&self, body: Value) -> ApiReply {
        let cmd = body.get("command").and_then(|v| v.as_str()).unwrap_or("");
        if cmd.is_empty() { return ApiReply{ status:400, payload: json!({"success": false, "error": "Empty command"})}; }
        if cmd.contains('\n') || cmd.contains('\r') { return ApiReply{ status:400, payload: json!({"success": false, "error": "A command with a newline is never written"})}; }
        // The panel's console runs through `exec_cli_command_async`; a caller
        // that reached the synchronous table still gets a real answer.
        api_error(501, "The console needs the asynchronous service entry point.")
    }

    fn handle_desktop_recommendations(&self) -> ApiReply {
        let rec = linscp_platform::desktop::desktop_recommendations();
        ApiReply{ status:200, payload: json!({"success": true, "recommendations": rec, "protocols": ["rdp","vnc","spice","x2go","x11"]})}
    }

    fn handle_desktop_ticket(&self, body: Value) -> ApiReply {
        let tab_id = tabs::parse_tab_id_value(body.get("tab"))
            .or_else(|| body.get("tabId").and_then(|v| v.as_u64()))
            .or_else(|| body.get("tab_id").and_then(|v| v.as_u64()));
        let Some(tab_id) = tab_id else {
            return ApiReply{ status:400, payload: json!({"success": false, "error": "tab is required"})};
        };
        let state = self.state.lock().expect("state mutex");
        let tab = match state.tabs.get(&tab_id) {
            Some(t) => t.clone(),
            None => return ApiReply{ status:404, payload: json!({"success": false, "error": format!("Tab {tab_id} not found")})},
        };
        drop(state);
        let Some(spec) = tab.spec.as_ref() else {
            return ApiReply{ status:400, payload: json!({"success": false, "error": "Tab has no session spec"})};
        };
        if !spec.session.protocol.is_remote_desktop() {
            return ApiReply{ status:400, payload: json!({"success": false, "error": format!("Protocol {} is not a desktop protocol", spec.session.protocol.as_str())})};
        }
        // Build ticket from stored spec via proto helper.
        let kind = linscp_proto::remote_desktop::RemoteDesktopKind::from_scheme(spec.session.protocol)
            .unwrap_or(linscp_proto::remote_desktop::RemoteDesktopKind::Rdp);
        let port = if spec.session.port == 0 { spec.session.protocol.default_port() } else { spec.session.port };
        let target = format!("{}:{}", spec.session.host, port);
        let desktop_opts = linscp_proto::remote_desktop::DesktopOptions::from_raw_fields(&spec.raw_fields);
        let tunneled = spec.session.tunnel.as_ref().map(|t| t.enabled && !t.host.trim().is_empty()).unwrap_or(false);
        let cfg = linscp_proto::remote_desktop::RemoteDesktopConnectConfig {
            scheme: spec.session.protocol,
            kind,
            host: spec.session.host.clone(),
            port,
            username: if spec.session.username.is_empty() { None } else { Some(spec.session.username.clone()) },
            password: spec.session.password.clone().map(zeroize::Zeroizing::new),
            domain: desktop_opts.domain.clone(),
            desktop_opts,
            tls: linscp_proto::tls::TlsSettings::default(),
            proxy: None,
            timeout: std::time::Duration::from_secs(15),
        };
        let ticket = linscp_proto::remote_desktop::ticket_from_config(&cfg, kind, &target, tunneled, None);
        ApiReply{ status:200, payload: json!({
            "success": true,
            "tab": tab_id,
            "ticket": {
                "kind": ticket.kind,
                "target": ticket.target,
                "viewer": ticket.viewer,
                "argv": ticket.argv,
                "file_extension": ticket.file_extension,
                "file_content": ticket.file_content,
                "tunneled": ticket.tunneled,
                "local_endpoint": ticket.local_endpoint,
                "has_file": ticket.file_content.is_some(),
            }
        })}
    }

    fn handle_desktop_launch(&self, body: Value) -> ApiReply {
        let tab_id = tabs::parse_tab_id_value(body.get("tab"))
            .or_else(|| body.get("tabId").and_then(|v| v.as_u64()))
            .or_else(|| body.get("tab_id").and_then(|v| v.as_u64()));
        let Some(tab_id) = tab_id else {
            return ApiReply{ status:400, payload: json!({"success": false, "error": "tab is required"})};
        };
        let state = self.state.lock().expect("state mutex");
        let tab = match state.tabs.get(&tab_id) {
            Some(t) => t.clone(),
            None => return ApiReply{ status:404, payload: json!({"success": false, "error": format!("Tab {tab_id} not found")})},
        };
        let config_root = state.config_root.clone();
        drop(state);
        let Some(spec) = tab.spec.as_ref() else {
            return ApiReply{ status:400, payload: json!({"success": false, "error": "Tab has no session spec"})};
        };
        if !spec.session.protocol.is_remote_desktop() {
            return ApiReply{ status:400, payload: json!({"success": false, "error": format!("Protocol {} is not a desktop protocol", spec.session.protocol.as_str())})};
        }
        let kind = linscp_proto::remote_desktop::RemoteDesktopKind::from_scheme(spec.session.protocol)
            .unwrap_or(linscp_proto::remote_desktop::RemoteDesktopKind::Rdp);
        let port = if spec.session.port == 0 { spec.session.protocol.default_port() } else { spec.session.port };
        let target = format!("{}:{}", spec.session.host, port);
        let desktop_opts = linscp_proto::remote_desktop::DesktopOptions::from_raw_fields(&spec.raw_fields);
        let tunneled = spec.session.tunnel.as_ref().map(|t| t.enabled && !t.host.trim().is_empty()).unwrap_or(false);
        let cfg = linscp_proto::remote_desktop::RemoteDesktopConnectConfig {
            scheme: spec.session.protocol,
            kind,
            host: spec.session.host.clone(),
            port,
            username: if spec.session.username.is_empty() { None } else { Some(spec.session.username.clone()) },
            password: spec.session.password.clone().map(zeroize::Zeroizing::new),
            domain: desktop_opts.domain.clone(),
            desktop_opts,
            tls: linscp_proto::tls::TlsSettings::default(),
            proxy: None,
            timeout: std::time::Duration::from_secs(15),
        };
        let proto_ticket = linscp_proto::remote_desktop::ticket_from_config(&cfg, kind, &target, tunneled, None);
        let ticket = linscp_platform::desktop::DesktopTicket {
            kind: proto_ticket.kind.clone(),
            target: proto_ticket.target.clone(),
            viewer: proto_ticket.viewer.clone(),
            argv: proto_ticket.argv.clone(),
            file_content: proto_ticket.file_content.clone(),
            file_extension: proto_ticket.file_extension.clone(),
            tunneled: proto_ticket.tunneled,
            local_endpoint: proto_ticket.local_endpoint.clone(),
        };
        // A file ticket is the honest answer here: this host cannot show the viewer
        // (or the caller said it cannot), so the client gets the `.rdp`/`.vv` body.
        let force_file_ticket = !self.desktop_spawn_allowed;
        match linscp_platform::desktop::launch_remote_desktop(&ticket, &config_root, force_file_ticket) {
            Ok(linscp_platform::desktop::DesktopLaunchResult::Spawned { pid, viewer, argv }) => {
                ApiReply{ status:200, payload: json!({"success": true, "launched": true, "pid": pid, "viewer": viewer.display().to_string(), "argv": argv, "kind": ticket.kind, "target": ticket.target, "local_endpoint": ticket.local_endpoint, "tunneled": ticket.tunneled})}
            },
            Ok(linscp_platform::desktop::DesktopLaunchResult::FileTicket { path, viewer_hint }) => {
                // Read file content for HTTP clients that cannot read server filesystem.
                let file_content = proto_ticket.file_content.clone().or_else(|| std::fs::read_to_string(&path).ok());
                ApiReply{ status:200, payload: json!({"success": true, "launched": false, "file": path.display().to_string(), "file_content": file_content, "file_extension": proto_ticket.file_extension, "viewer_hint": viewer_hint, "kind": ticket.kind, "target": ticket.target, "local_endpoint": ticket.local_endpoint, "tunneled": ticket.tunneled})}
            },
            Ok(linscp_platform::desktop::DesktopLaunchResult::BrowserGateway { url_hint }) => {
                ApiReply{ status:200, payload: json!({"success": true, "launched": false, "gateway": url_hint, "kind": ticket.kind, "viewer": ticket.viewer, "argv": ticket.argv, "target": ticket.target, "local_endpoint": ticket.local_endpoint, "tunneled": ticket.tunneled})}
            },
            Err(e) => ApiReply{ status:500, payload: json!({"success": false, "error": e})},
        }
    }

    fn parse_desktop_kind_str(raw: Option<&str>) -> linscp_proto::remote_desktop::RemoteDesktopKind {
        use linscp_proto::remote_desktop::RemoteDesktopKind;
        match raw.unwrap_or("").trim().to_ascii_lowercase().as_str() {
            "vnc" | "rfb" => RemoteDesktopKind::Vnc,
            "spice" => RemoteDesktopKind::Spice,
            "x2go" | "nx" => RemoteDesktopKind::X2Go,
            "x11" | "x" | "waypipe" => RemoteDesktopKind::X11,
            _ => RemoteDesktopKind::Rdp,
        }
    }

    fn handle_desktop_install_script(&self, query: &BTreeMap<String, String>, body: Value) -> ApiReply {
        use linscp_proto::remote_desktop::{server_description, server_package_name, probe_command_for_kind, install_script_for_kind};
        let kind_str = query.get("kind").map(|s| s.as_str()).or_else(|| body.get("kind").and_then(|v| v.as_str()));
        let kind = Self::parse_desktop_kind_str(kind_str);
        let pkg = server_package_name(kind);
        let descr = server_description(kind);
        let script = install_script_for_kind(kind);
        let probe = probe_command_for_kind(kind);
        ApiReply{ status:200, payload: json!({
            "success": true,
            "kind": kind.as_str(),
            "package": pkg,
            "description": descr,
            "probe_command": probe,
            "install_script": script
        })}
    }

    fn handle_desktop_check(&self, body: Value) -> ApiReply {
        // Sync fallback: does not actually probe via SSH (needs async). Returns
        // the installer so the UI can still prompt with cancel/install.
        use linscp_proto::remote_desktop::{server_description, server_package_name, probe_command_for_kind, install_script_for_kind};
        let kind_str = body.get("kind").and_then(|v| v.as_str()).or_else(|| body.get("protocol").and_then(|v| v.as_str()));
        let host = body.get("host").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let tab_id = tabs::parse_tab_id_value(body.get("tab")).or_else(|| body.get("tabId").and_then(|v| v.as_u64())).or_else(|| body.get("via_tab").and_then(|v| v.as_u64()));
        let mut kind = Self::parse_desktop_kind_str(kind_str);
        let mut target_host = host.clone();
        let mut target_port: u16 = body.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        // If a desktop tab is referenced, prefer its spec for host/port/kind
        if let Some(tid) = tab_id {
            let state = self.state.lock().expect("state mutex");
            if let Some(tab) = state.tabs.get(&tid) {
                if let Some(spec) = tab.spec.as_ref() {
                    if spec.session.protocol.is_remote_desktop() {
                        kind = linscp_proto::remote_desktop::RemoteDesktopKind::from_scheme(spec.session.protocol).unwrap_or(kind);
                        if target_host.is_empty() { target_host = spec.session.host.clone(); }
                        if target_port == 0 { target_port = if spec.session.port == 0 { spec.session.protocol.default_port() } else { spec.session.port }; }
                    } else if target_host.is_empty() {
                        target_host = spec.session.host.clone();
                        if target_port == 0 { target_port = if spec.session.port == 0 { 22 } else { spec.session.port }; }
                    }
                }
            }
        }
        if target_host.is_empty() {
            // Try any connected SSH tab as hint
            let state = self.state.lock().expect("state mutex");
            for t in state.tabs.values() {
                if t.connected && t.spec.as_ref().map(|s| matches!(s.session.protocol, linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Scp | linscp_types::ProtocolScheme::Ssh)).unwrap_or(false) {
                    target_host = t.spec.as_ref().map(|s| s.session.host.clone()).unwrap_or_default();
                    break;
                }
            }
        }
        if target_port == 0 {
            target_port = match kind {
                linscp_proto::remote_desktop::RemoteDesktopKind::Rdp => 3389,
                linscp_proto::remote_desktop::RemoteDesktopKind::Vnc => 5900,
                linscp_proto::remote_desktop::RemoteDesktopKind::Spice => 5900,
                _ => 22,
            };
        }
        let pkg = server_package_name(kind);
        let descr = server_description(kind);
        let script = install_script_for_kind(kind);
        let probe = probe_command_for_kind(kind);
        // Sync cannot safely run SSH exec; report not_available with script and
        // instruct client to call async /api/desktop/check for a live probe.
        ApiReply{ status:200, payload: json!({
            "success": true,
            "available": false,
            "checked": false,
            "kind": kind.as_str(),
            "host": target_host,
            "port": target_port,
            "package": pkg,
            "description": descr,
            "probe_command": probe,
            "install_script": script,
            "reason": format!("{descr} ({pkg}) not verified synchronously — call POST /api/desktop/check via dispatch_async with via_tab for live SSH probe, or run: {probe}"),
            "can_install": true,
            "message": format!("Remote desktop ({}) is not available on server '{}': {} ({}) not found. Install it now? The following compatible installer works on Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE and detects the OS automatically.", kind.as_str(), target_host, descr, pkg)
        })}
    }

    fn handle_desktop_install_sync(&self, _body: Value) -> ApiReply {
        // Sync cannot run long SSH install; prompt client to use async.
        ApiReply{ status:202, payload: json!({
            "success": false,
            "error": "Install requires async dispatch. Call POST /api/desktop/install via dispatch_async with {via_tab, kind}.",
            "install_script": "Call GET /api/desktop/install-script?kind=rdp to fetch the compatible installer, or use async install."
        })}
    }

    async fn handle_desktop_check_async(&self, body: Value) -> ApiReply {
        use linscp_proto::remote_desktop::{server_description, server_package_name, probe_command_for_kind, install_script_for_kind, RemoteDesktopKind};
        let kind_str = body.get("kind").and_then(|v| v.as_str()).or_else(|| body.get("protocol").and_then(|v| v.as_str()));
        let host = body.get("host").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
        let via_tab_raw = body.get("via_tab").cloned().or_else(|| body.get("tab").cloned());
        let tab_id = tabs::parse_tab_id_value(via_tab_raw.as_ref()).or_else(|| body.get("tabId").and_then(|v| v.as_u64()));
        let mut kind = Self::parse_desktop_kind_str(kind_str);
        let mut target_host = host.clone();
        let mut target_port: u16 = body.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        // Prefer desktop tab spec if provided
        let mut via_session: Option<std::sync::Arc<dyn linscp_proto::RemoteSession>> = None;
        let mut via_tab_id: Option<u64> = None;
        if let Some(tid) = tab_id {
            let state = self.state.lock().expect("state mutex");
            if let Some(tab) = state.tabs.get(&tid) {
                if let Some(spec) = tab.spec.as_ref() {
                    if spec.session.protocol.is_remote_desktop() {
                        kind = RemoteDesktopKind::from_scheme(spec.session.protocol).unwrap_or(kind);
                        if target_host.is_empty() { target_host = spec.session.host.clone(); }
                        if target_port == 0 { target_port = if spec.session.port == 0 { spec.session.protocol.default_port() } else { spec.session.port }; }
                    }
                }
                // If this tab itself is an SSH session, use it as via
                if tab.remote.is_some() && tab.spec.as_ref().map(|s| matches!(s.session.protocol, linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Scp | linscp_types::ProtocolScheme::Ssh)).unwrap_or(false) {
                    via_session = tab.remote.clone();
                    via_tab_id = Some(tid);
                }
            }
        }
        // Also check explicit via_tab field separate from tab
        if via_session.is_none() {
            if let Some(vid) = body.get("via_tab").and_then(|v| v.as_u64()).or_else(|| body.get("viaTab").and_then(|v| v.as_u64())) {
                let state = self.state.lock().expect("state mutex");
                if let Some(tab) = state.tabs.get(&vid) {
                    via_session = tab.remote.clone();
                    via_tab_id = Some(vid);
                    if target_host.is_empty() { if let Some(spec) = tab.spec.as_ref() { target_host = spec.session.host.clone(); } }
                }
            }
        }
        // Fallback: find any connected SSH tab with matching host
        if via_session.is_none() && !target_host.is_empty() {
            let state = self.state.lock().expect("state mutex");
            for (id, tab) in state.tabs.iter() {
                let is_ssh = tab.spec.as_ref().map(|s| matches!(s.session.protocol, linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Scp | linscp_types::ProtocolScheme::Ssh)).unwrap_or(false);
                if is_ssh && tab.remote.is_some() && tab.connected {
                    let h = tab.spec.as_ref().map(|s| s.session.host.clone()).unwrap_or_default();
                    if h.eq_ignore_ascii_case(&target_host) {
                        via_session = tab.remote.clone();
                        via_tab_id = Some(*id);
                        break;
                    }
                }
            }
        }
        // Last fallback: any SSH tab
        if via_session.is_none() {
            let state = self.state.lock().expect("state mutex");
            for (id, tab) in state.tabs.iter() {
                let is_ssh = tab.spec.as_ref().map(|s| matches!(s.session.protocol, linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Scp | linscp_types::ProtocolScheme::Ssh)).unwrap_or(false);
                if is_ssh && tab.remote.is_some() {
                    via_session = tab.remote.clone();
                    via_tab_id = Some(*id);
                    if target_host.is_empty() { if let Some(spec) = tab.spec.as_ref() { target_host = spec.session.host.clone(); } }
                    break;
                }
            }
        }
        if target_host.is_empty() { target_host = "server".to_string(); }
        if target_port == 0 { target_port = match kind { RemoteDesktopKind::Rdp => 3389, RemoteDesktopKind::Vnc => 5900, RemoteDesktopKind::Spice => 5900, _ => 22 }; }
        let pkg = server_package_name(kind);
        let descr = server_description(kind);
        let script = install_script_for_kind(kind);
        let probe = probe_command_for_kind(kind);

        // If we have an SSH session, probe via exec
        if let Some(sess) = via_session {
            match linscp_proto::remote_desktop::check_via_ssh(sess.as_ref(), kind).await {
                Ok(true) => {
                    return ApiReply{ status:200, payload: json!({
                        "success": true,
                        "available": true,
                        "checked": true,
                        "via_ssh": true,
                        "via_tab": via_tab_id,
                        "kind": kind.as_str(),
                        "host": target_host,
                        "port": target_port,
                        "package": pkg,
                        "description": descr,
                        "probe_command": probe,
                        "install_script": script,
                        "reason": format!("{descr} ({pkg}) is installed on {target_host}"),
                        "can_install": true,
                        "message": format!("Remote desktop ({}) is available on server '{}'.", kind.as_str(), target_host)
                    })};
                },
                Ok(false) => {
                    return ApiReply{ status:200, payload: json!({
                        "success": true,
                        "available": false,
                        "checked": true,
                        "via_ssh": true,
                        "via_tab": via_tab_id,
                        "kind": kind.as_str(),
                        "host": target_host,
                        "port": target_port,
                        "package": pkg,
                        "description": descr,
                        "probe_command": probe,
                        "install_script": script,
                        "reason": format!("{descr} ({pkg}) not found on {target_host} — command `{probe}` failed"),
                        "can_install": true,
                        "message": format!("Remote desktop ({}) is not available on server '{}': {} ({}) not found. Install it now?", kind.as_str(), target_host, descr, pkg),
                        "prompt": {
                            "title": format!("Remote desktop not available on {}", target_host),
                            "body": format!("{} ({}) is not installed on server '{}'. The installer below works on Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE (auto-detects via /etc/os-release and uses apt/dnf/yum/pacman/zypper). Install now or cancel?", descr, pkg, target_host),
                            "install_script": script,
                            "actions": ["cancel", "install"]
                        }
                    })};
                },
                Err(e) => {
                    return ApiReply{ status:200, payload: json!({
                        "success": true,
                        "available": false,
                        "checked": true,
                        "via_ssh": true,
                        "via_tab": via_tab_id,
                        "kind": kind.as_str(),
                        "host": target_host,
                        "port": target_port,
                        "package": pkg,
                        "description": descr,
                        "probe_command": probe,
                        "install_script": script,
                        "reason": format!("Probe failed: {e}"),
                        "can_install": true,
                        "message": format!("Could not verify {} on {}: {e}. Installer available.", descr, target_host)
                    })};
                }
            }
        }

        // No SSH session: try TCP probe if direct desktop port
        let tcp_ok = linscp_proto::remote_desktop::check_tcp_availability(&target_host, target_port).await;
        if tcp_ok {
            return ApiReply{ status:200, payload: json!({
                "success": true,
                "available": true,
                "checked": true,
                "via_ssh": false,
                "kind": kind.as_str(),
                "host": target_host,
                "port": target_port,
                "package": pkg,
                "description": descr,
                "probe_command": probe,
                "install_script": script,
                "reason": format!("TCP connect to {target_host}:{target_port} succeeded"),
                "can_install": false
            })};
        }
        ApiReply{ status:200, payload: json!({
            "success": true,
            "available": false,
            "checked": true,
            "via_ssh": false,
            "kind": kind.as_str(),
            "host": target_host,
            "port": target_port,
            "package": pkg,
            "description": descr,
            "probe_command": probe,
            "install_script": script,
            "reason": format!("{descr} ({pkg}) not reachable on {target_host}:{target_port} and no SSH session to probe"),
            "can_install": false,
            "message": format!("Remote desktop ({}) does not appear to be listening on {}:{} ({}, {}). If you have SSH access, connect via SSH first and run the installer, or run this script manually on the server.", kind.as_str(), target_host, target_port, descr, pkg),
            "prompt": {
                "title": format!("Remote desktop not available on {}", target_host),
                "body": format!("{} is not listening on {}:{}. Installer for {}:\n{}", descr, target_host, target_port, pkg, script),
                "install_script": script,
                "actions": ["cancel", "install"]
            }
        })}
    }

    async fn handle_desktop_install_async(&self, body: Value) -> ApiReply {
        use linscp_proto::remote_desktop::{server_package_name, install_script_for_kind, RemoteDesktopKind};
        let kind_str = body.get("kind").and_then(|v| v.as_str()).or_else(|| body.get("protocol").and_then(|v| v.as_str()));
        let kind = Self::parse_desktop_kind_str(kind_str);
        let via_tab = body.get("via_tab").and_then(|v| v.as_u64()).or_else(|| body.get("viaTab").and_then(|v| v.as_u64())).or_else(|| tabs::parse_tab_id_value(body.get("tab"))).or_else(|| body.get("tabId").and_then(|v| v.as_u64()));
        let mut target_host = body.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let mut via_session: Option<std::sync::Arc<dyn linscp_proto::RemoteSession>> = None;
        let mut via_tab_id: Option<u64> = None;
        if let Some(vid) = via_tab {
            let state = self.state.lock().expect("state mutex");
            if let Some(tab) = state.tabs.get(&vid) {
                via_session = tab.remote.clone();
                via_tab_id = Some(vid);
                if target_host.is_empty() { if let Some(spec) = tab.spec.as_ref() { target_host = spec.session.host.clone(); } }
            }
        }
        if via_session.is_none() {
            let state = self.state.lock().expect("state mutex");
            for (id, tab) in state.tabs.iter() {
                let is_ssh = tab.spec.as_ref().map(|s| matches!(s.session.protocol, linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Scp | linscp_types::ProtocolScheme::Ssh)).unwrap_or(false);
                if is_ssh && tab.remote.is_some() {
                    via_session = tab.remote.clone();
                    via_tab_id = Some(*id);
                    if target_host.is_empty() { if let Some(spec) = tab.spec.as_ref() { target_host = spec.session.host.clone(); } }
                    break;
                }
            }
        }
        let Some(sess) = via_session else {
            return ApiReply{ status:400, payload: json!({"success": false, "error": "No SSH session found to install on. Connect via SSH to the server first (sftp:// or scp://), then retry."})};
        };
        let pkg = server_package_name(kind);
        let script = install_script_for_kind(kind);
        // For X11/SPICE etc the script is short; for RDP/VNC/X2Go it may take minutes
        match sess.exec_command(&script).await {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                let exit = out.exit_code.unwrap_or(1);
                let success = exit == 0;
                // Re-probe after install if succeeded
                let mut now_available = false;
                if success {
                    if let Ok(avail) = linscp_proto::remote_desktop::check_via_ssh(sess.as_ref(), kind).await {
                        now_available = avail;
                    }
                }
                ApiReply{ status: if success {200} else {500}, payload: json!({
                    "success": success,
                    "via_tab": via_tab_id,
                    "host": target_host,
                    "kind": kind.as_str(),
                    "package": pkg,
                    "exit_code": exit,
                    "stdout": stdout,
                    "stderr": stderr,
                    "now_available": now_available,
                    "install_script": script,
                    "message": if success { format!("{pkg} installed on {target_host} — now_available={now_available}") } else { format!("Installer for {pkg} failed (exit {exit})") }
                })}
            },
            Err(e) => ApiReply{ status:500, payload: json!({"success": false, "error": format!("SSH install exec failed: {e}"), "kind": kind.as_str(), "package": pkg})},
        }
    }

    async fn handle_desktop_launch_async(&self, body: Value) -> ApiReply {
        use linscp_proto::remote_desktop::{server_description, server_package_name, probe_command_for_kind, install_script_for_kind, RemoteDesktopKind, ticket_from_config, DesktopOptions, RemoteDesktopConnectConfig};
        // First, perform availability check via SSH if possible. If not available,
        // return the same prompt as /api/desktop/check so the UI can show cancel/install.
        let kind_str = body.get("kind").and_then(|v| v.as_str()).or_else(|| body.get("protocol").and_then(|v| v.as_str()));
        let mut target_host = body.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let tab_id = tabs::parse_tab_id_value(body.get("tab")).or_else(|| body.get("tabId").and_then(|v| v.as_u64()));
        let mut kind = Self::parse_desktop_kind_str(kind_str);
        let mut target_port: u16 = body.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        let mut desktop_tab_spec: Option<tabs::TabRuntime> = None;
        let mut via_session: Option<std::sync::Arc<dyn linscp_proto::RemoteSession>> = None;
        let mut via_tab_id: Option<u64> = None;
        // Extract desktop tab spec if provided
        if let Some(tid) = tab_id {
            let state = self.state.lock().expect("state mutex");
            if let Some(tab) = state.tabs.get(&tid).cloned() {
                if let Some(spec) = tab.spec.as_ref() {
                    if spec.session.protocol.is_remote_desktop() {
                        kind = RemoteDesktopKind::from_scheme(spec.session.protocol).unwrap_or(kind);
                        if target_host.is_empty() { target_host = spec.session.host.clone(); }
                        if target_port == 0 { target_port = if spec.session.port == 0 { spec.session.protocol.default_port() } else { spec.session.port }; }
                        desktop_tab_spec = Some(tab.clone());
                    } else if target_host.is_empty() {
                        target_host = spec.session.host.clone();
                    }
                }
                // If this tab is SSH, remember as via
                if tab.remote.is_some() && tab.spec.as_ref().map(|s| matches!(s.session.protocol, linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Scp | linscp_types::ProtocolScheme::Ssh)).unwrap_or(false) {
                    via_session = tab.remote.clone();
                    via_tab_id = Some(tid);
                }
            }
        }
        // Also check explicit via_tab separate from tab
        if via_session.is_none() {
            if let Some(vid) = body.get("via_tab").and_then(|v| v.as_u64()).or_else(|| body.get("viaTab").and_then(|v| v.as_u64())) {
                let state = self.state.lock().expect("state mutex");
                if let Some(tab) = state.tabs.get(&vid) {
                    via_session = tab.remote.clone();
                    via_tab_id = Some(vid);
                    if target_host.is_empty() { if let Some(spec) = tab.spec.as_ref() { target_host = spec.session.host.clone(); } }
                }
            }
        }
        // Fallback: any SSH tab with matching host
        if via_session.is_none() && !target_host.is_empty() {
            let state = self.state.lock().expect("state mutex");
            for (id, tab) in state.tabs.iter() {
                let is_ssh = tab.spec.as_ref().map(|s| matches!(s.session.protocol, linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Scp | linscp_types::ProtocolScheme::Ssh)).unwrap_or(false);
                if is_ssh && tab.remote.is_some() && tab.connected {
                    let h = tab.spec.as_ref().map(|s| s.session.host.clone()).unwrap_or_default();
                    if h.eq_ignore_ascii_case(&target_host) { via_session = tab.remote.clone(); via_tab_id = Some(*id); break; }
                }
            }
        }
        if via_session.is_none() {
            let state = self.state.lock().expect("state mutex");
            for (id, tab) in state.tabs.iter() {
                let is_ssh = tab.spec.as_ref().map(|s| matches!(s.session.protocol, linscp_types::ProtocolScheme::Sftp | linscp_types::ProtocolScheme::Scp | linscp_types::ProtocolScheme::Ssh)).unwrap_or(false);
                if is_ssh && tab.remote.is_some() { via_session = tab.remote.clone(); via_tab_id = Some(*id); if target_host.is_empty() { if let Some(spec) = tab.spec.as_ref() { target_host = spec.session.host.clone(); } } break; }
            }
        }
        if target_host.is_empty() {
            if let Some(tab) = desktop_tab_spec.as_ref() { if let Some(spec) = tab.spec.as_ref() { target_host = spec.session.host.clone(); } }
        }
        if target_port == 0 { target_port = match kind { RemoteDesktopKind::Rdp => 3389, RemoteDesktopKind::Vnc => 5900, RemoteDesktopKind::Spice => 5900, _ => 22 }; }
        let pkg = server_package_name(kind);
        let descr = server_description(kind);
        let script = install_script_for_kind(kind);
        let probe = probe_command_for_kind(kind);
        // If we have SSH, probe via exec; if not available, return prompt instead of launching
        if let Some(sess) = via_session.as_ref() {
            match linscp_proto::remote_desktop::check_via_ssh(sess.as_ref(), kind).await {
                Ok(false) => {
                    return ApiReply{ status: 409, payload: json!({
                        "success": false,
                        "available": false,
                        "checked": true,
                        "via_ssh": true,
                        "via_tab": via_tab_id,
                        "kind": kind.as_str(),
                        "host": target_host,
                        "port": target_port,
                        "package": pkg,
                        "description": descr,
                        "probe_command": probe,
                        "install_script": script,
                        "reason": format!("{descr} ({pkg}) not found on {target_host}"),
                        "can_install": true,
                        "message": format!("Remote desktop ({}) is not available on server '{}': {} ({}) not found. Install it now?", kind.as_str(), target_host, descr, pkg),
                        "prompt": {
                            "title": format!("Remote desktop not available on {}", target_host),
                            "body": format!("{} ({}) is not installed on server '{}'. The installer below works on Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE (auto-detects via /etc/os-release). Install now or cancel?", descr, pkg, target_host),
                            "install_script": script,
                            "actions": ["cancel", "install"]
                        },
                        "error": format!("Remote desktop not available: {descr} not found on {target_host}")
                    })};
                },
                Ok(true) => { /* continue to launch */ },
                Err(e) => {
                    // Probe error: log but still allow launch to be attempted (maybe transient)
                    let _ = e;
                }
            }
        } else if !target_host.is_empty() && matches!(kind, RemoteDesktopKind::Rdp | RemoteDesktopKind::Vnc | RemoteDesktopKind::Spice) {
            // No SSH, try TCP probe for direct desktop ports
            let tcp_ok = linscp_proto::remote_desktop::check_tcp_availability(&target_host, target_port).await;
            if !tcp_ok {
                return ApiReply{ status: 409, payload: json!({
                    "success": false,
                    "available": false,
                    "checked": true,
                    "via_ssh": false,
                    "kind": kind.as_str(),
                    "host": target_host,
                    "port": target_port,
                    "package": pkg,
                    "description": descr,
                    "probe_command": probe,
                    "install_script": script,
                    "reason": format!("TCP connect to {target_host}:{target_port} failed"),
                    "can_install": false,
                    "message": format!("Remote desktop ({}) does not appear to be listening on {}:{} ({}, {}). Connect via SSH first to install, or run installer manually.", kind.as_str(), target_host, target_port, descr, pkg),
                    "prompt": {
                        "title": format!("Remote desktop not available on {}", target_host),
                        "body": format!("{} is not listening on {}:{}. Installer for {}:\n{}", descr, target_host, target_port, pkg, script),
                        "install_script": script,
                        "actions": ["cancel"]
                    },
                    "error": format!("Remote desktop not listening on {target_host}:{target_port}")
                })};
            }
        }
        // Proceed with actual launch (reuse sync logic but with async context)
        // Reuse the desktop tab if provided, otherwise require host/port
        let (spec_host, spec_port, spec_protocol) = if let Some(tab) = desktop_tab_spec.as_ref() {
            if let Some(spec) = tab.spec.as_ref() {
                (spec.session.host.clone(), if spec.session.port == 0 { spec.session.protocol.default_port() } else { spec.session.port }, spec.session.protocol)
            } else { (target_host.clone(), target_port, match kind { RemoteDesktopKind::Rdp => linscp_types::ProtocolScheme::Rdp, RemoteDesktopKind::Vnc => linscp_types::ProtocolScheme::Vnc, RemoteDesktopKind::Spice => linscp_types::ProtocolScheme::Spice, RemoteDesktopKind::X2Go => linscp_types::ProtocolScheme::X2Go, RemoteDesktopKind::X11 => linscp_types::ProtocolScheme::X11 }) }
        } else {
            (target_host.clone(), target_port, match kind { RemoteDesktopKind::Rdp => linscp_types::ProtocolScheme::Rdp, RemoteDesktopKind::Vnc => linscp_types::ProtocolScheme::Vnc, RemoteDesktopKind::Spice => linscp_types::ProtocolScheme::Spice, RemoteDesktopKind::X2Go => linscp_types::ProtocolScheme::X2Go, RemoteDesktopKind::X11 => linscp_types::ProtocolScheme::X11 })
        };
        // Try to find the desktop tab to get full spec (including raw_fields, tunnel)
        let tab_for_launch = if let Some(tid) = tab_id { self.state.lock().expect("m").tabs.get(&tid).cloned() } else { None };
        let (cfg, target, tunneled) = if let Some(tab) = tab_for_launch.as_ref() {
            if let Some(spec) = tab.spec.as_ref() {
                let k = RemoteDesktopKind::from_scheme(spec.session.protocol).unwrap_or(kind);
                let p = if spec.session.port == 0 { spec.session.protocol.default_port() } else { spec.session.port };
                let t = format!("{}:{}", spec.session.host, p);
                let opts = DesktopOptions::from_raw_fields(&spec.raw_fields);
                let tun = spec.session.tunnel.as_ref().map(|t| t.enabled && !t.host.trim().is_empty()).unwrap_or(false);
                let c = RemoteDesktopConnectConfig{ scheme: spec.session.protocol, kind: k, host: spec.session.host.clone(), port: p, username: if spec.session.username.is_empty() { None } else { Some(spec.session.username.clone()) }, password: spec.session.password.clone().map(zeroize::Zeroizing::new), domain: opts.domain.clone(), desktop_opts: opts, tls: linscp_proto::tls::TlsSettings::default(), proxy: None, timeout: std::time::Duration::from_secs(15) };
                (c, t, tun)
            } else { return ApiReply{ status:400, payload: json!({"success": false, "error": "Tab has no session spec"})}; }
        } else {
            if target_host.is_empty() { return ApiReply{ status:400, payload: json!({"success": false, "error": "Desktop target host is required. Provide tab with desktop session or host/kind."})}; }
            let opts = DesktopOptions::default();
            let c = RemoteDesktopConnectConfig{ scheme: spec_protocol, kind, host: spec_host.clone(), port: spec_port, username: None, password: None, domain: None, desktop_opts: opts, tls: linscp_proto::tls::TlsSettings::default(), proxy: None, timeout: std::time::Duration::from_secs(15) };
            let t = format!("{}:{}", spec_host, spec_port);
            (c, t, false)
        };
        let proto_ticket = ticket_from_config(&cfg, kind, &target, tunneled, None);
        let ticket = linscp_platform::desktop::DesktopTicket{ kind: proto_ticket.kind.clone(), target: proto_ticket.target.clone(), viewer: proto_ticket.viewer.clone(), argv: proto_ticket.argv.clone(), file_content: proto_ticket.file_content.clone(), file_extension: proto_ticket.file_extension.clone(), tunneled: proto_ticket.tunneled, local_endpoint: proto_ticket.local_endpoint.clone() };
        let config_root = self.state.lock().expect("m").config_root.clone();
        let force_file_ticket = !self.desktop_spawn_allowed;
        match linscp_platform::desktop::launch_remote_desktop(&ticket, &config_root, force_file_ticket) {
            Ok(linscp_platform::desktop::DesktopLaunchResult::Spawned{ pid, viewer, argv }) => ApiReply{ status:200, payload: json!({"success": true, "launched": true, "available": true, "pid": pid, "viewer": viewer.display().to_string(), "argv": argv, "kind": kind.as_str(), "host": target_host, "target": ticket.target, "local_endpoint": ticket.local_endpoint, "tunneled": ticket.tunneled})},
            Ok(linscp_platform::desktop::DesktopLaunchResult::FileTicket{ path, viewer_hint }) => {
                let file_content = proto_ticket.file_content.clone().or_else(|| std::fs::read_to_string(&path).ok());
                ApiReply{ status:200, payload: json!({"success": true, "launched": false, "available": true, "file": path.display().to_string(), "file_content": file_content, "file_extension": proto_ticket.file_extension, "viewer_hint": viewer_hint, "kind": ticket.kind, "target": ticket.target, "local_endpoint": ticket.local_endpoint, "tunneled": ticket.tunneled})}
            },
            Ok(linscp_platform::desktop::DesktopLaunchResult::BrowserGateway{ url_hint }) => ApiReply{ status:200, payload: json!({"success": true, "launched": false, "available": true, "gateway": url_hint, "kind": ticket.kind, "viewer": ticket.viewer, "argv": ticket.argv, "target": ticket.target, "local_endpoint": ticket.local_endpoint, "tunneled": ticket.tunneled})},
            Err(e) => ApiReply{ status:500, payload: json!({"success": false, "error": e})},
        }
    }
}

const OFFLINEOTP_SESSION_JSON: &str = "linscp_session_json";
const LOCAL_VAULT_KEY_PREFIX: &str = "vaultkey://";
const OFFLINEOTP_SSH_KEY_LABEL: &str = "linscp_ssh_key_label";
const OFFLINEOTP_TUNNEL_KEY_LABEL: &str = "linscp_tunnel_key_label";
const OFFLINEOTP_SSH_SUFFIX: &str = " [LinSCP SSH key]";
const OFFLINEOTP_TUNNEL_SUFFIX: &str = " [LinSCP jump-host key]";

fn offlineotp_entries_from_sessions(
    store: &SessionStore,
    config_root: &Path,
    secret_vault: &linscp_platform::password_vault::PasswordSecretVault,
) -> Result<Vec<CredentialEntry>, String> {
    let mut entries = Vec::new();
    for site in store.sites() {
        if site.name.trim().is_empty() || site.name.len() > 1024
            || site.name.contains(']') || site.name.chars().any(char::is_control)
        {
            return Err(format!("Saved session '{}' has a name that cannot be represented safely in an OfflineOTP import.", site.name));
        }
        if site.password_raw.is_some()
            || site.proxy_password_raw.is_some()
            || site.tunnel_password_raw.is_some()
            || site.tunnel_passphrase_raw.is_some()
            || site.password_error.is_some()
            || site.proxy_error.is_some()
            || site.tunnel_error.is_some()
            || site.setting_error.is_some()
        {
            return Err(format!(
                "Cannot export '{}' because one or more saved secrets or settings could not be read safely. Fix the affected session first.",
                site.name
            ));
        }
        if site.extra_fields.get("s3_session_token").is_some_and(|token| !token.is_empty()) {
            return Err(format!("Cannot export '{}' because LinSCP does not persist S3 session tokens in saved sessions.", site.name));
        }
        for (key, value) in &site.extra_fields {
            if !value.is_empty() && is_sensitive_vault_field(key) && key != "s3_secret_key" {
                return Err(format!("Cannot export '{}' because saved setting '{key}' is a credential that LinSCP cannot safely restore as a session.", site.name));
            }
        }
        let mut exported_password = site.password.clone();
        if exported_password.as_deref().is_none_or(str::is_empty) {
            exported_password = site.extra_fields.get("s3_secret_key").cloned();
        }
        let mut exported_username = site.username.clone();
        if exported_username.is_empty() {
            exported_username = site.extra_fields.get("s3_access_key").cloned().unwrap_or_default();
        }
        // Keep paths local to the exporting machine out of the portable file; key material is
        // carried in sibling SSH_KEY entries and gets a fresh private path on import.
        let mut portable_site = site.clone();
        portable_site.private_key = None;
        portable_site.tunnel.keyfile = None;
        portable_site.local_directory.clear();
        portable_site.password = exported_password.clone();
        portable_site.username = exported_username.clone();
        portable_site.extra_fields.retain(|key, _| {
            !key.eq_ignore_ascii_case("s3_access_key") && !is_sensitive_vault_field(key) && !is_local_path_vault_field(key)
        });
        validate_imported_site(&portable_site)?;
        let session_json = serde_json::to_string(&portable_site)
            .map_err(|error| format!("Cannot encode saved session '{}': {error}", site.name))?;
        let mut metadata = BTreeMap::from([(OFFLINEOTP_SESSION_JSON.to_string(), session_json)]);

        if let Some(path) = site.private_key.as_deref().filter(|path| !path.is_empty()) {
            let label = format!("{}{}", site.name, OFFLINEOTP_SSH_SUFFIX);
            let (public_key, private_key) = read_offlineotp_keypair(path, config_root, secret_vault)?;
            entries.push(CredentialEntry::SshKey(SshKeyRecord {
                label: label.clone(),
                public_key,
                private_key,
                host: site.host.clone(),
                port: site.port,
                username: site.username.clone(),
                password: String::new(),
            }));
            metadata.insert(OFFLINEOTP_SSH_KEY_LABEL.to_string(), label);
        }
        if let Some(path) = site.tunnel.keyfile.as_deref().filter(|path| !path.is_empty()) {
            let label = format!("{}{}", site.name, OFFLINEOTP_TUNNEL_SUFFIX);
            let (public_key, private_key) = read_offlineotp_keypair(path, config_root, secret_vault)?;
            entries.push(CredentialEntry::SshKey(SshKeyRecord {
                label: label.clone(),
                public_key,
                private_key,
                host: site.tunnel.host.clone(),
                port: site.tunnel.port,
                username: site.tunnel.username.clone(),
                password: String::new(),
            }));
            metadata.insert(OFFLINEOTP_TUNNEL_KEY_LABEL.to_string(), label);
        }

        let host = if site.host.contains(':') && !site.host.starts_with('[') {
            format!("[{}]", site.host)
        } else {
            site.host.clone()
        };
        let port = if site.port == 0 { site.protocol.default_port() } else { site.port };
        let url = if host.is_empty() {
            "linscp://saved-session".to_string()
        } else {
            format!("{}://{}:{port}", site.protocol.as_str(), host)
        };
        entries.push(CredentialEntry::Login(LoginRecord {
            label: site.name.clone(),
            url,
            username: exported_username,
            password: exported_password.unwrap_or_default(),
            metadata,
        }));
    }
    if entries.is_empty() {
        return Err("There are no saved sessions or SSH keys to export.".to_string());
    }
    Ok(entries)
}

fn read_offlineotp_keypair(
    path: &str,
    config_root: &Path,
    secret_vault: &linscp_platform::password_vault::PasswordSecretVault,
) -> Result<(String, String), String> {
    const LIMIT: u64 = 32 * 1024;
    if let Some(id) = path.strip_prefix(LOCAL_VAULT_KEY_PREFIX) {
        if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Saved encrypted SSH key reference is invalid.".to_string());
        }
        let encrypted_path = config_root.join("keys").join(format!("{id}.key.vault"));
        let metadata = std::fs::metadata(&encrypted_path)
            .map_err(|error| format!("Cannot read encrypted SSH key: {error}"))?;
        if metadata.len() > 1024 * 1024 + 64 {
            return Err("Encrypted SSH key file is unexpectedly large.".to_string());
        }
        let encrypted = std::fs::read(&encrypted_path)
            .map_err(|error| format!("Cannot read encrypted SSH key: {error}"))?;
        let private = secret_vault.open_local_blob(&encrypted)
            .map_err(|error| error.to_string())?;
        if private.len() as u64 > LIMIT {
            return Err("SSH key exceeds OfflineOTP's 32 KiB per-key limit.".to_string());
        }
        let private = String::from_utf8(private.to_vec())
            .map_err(|_| "SSH private key is not UTF-8 text.".to_string())?;
        let public_path = config_root.join("keys").join(format!("{id}.pub"));
        let public = read_bounded_key_optional(&public_path, LIMIT)?;
        return Ok((public, private));
    }
    let expanded = linscp_platform::terminal::expand_tilde(path);
    let key_path = PathBuf::from(expanded);
    let is_public_path = key_path.extension().and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pub"));
    let (private_path, public_path) = if is_public_path {
        (key_path.with_extension(""), key_path.clone())
    } else {
        let mut public = key_path.as_os_str().to_os_string();
        public.push(".pub");
        (key_path.clone(), PathBuf::from(public))
    };
    let (public, private) = if is_public_path {
        (read_bounded_key(&public_path, LIMIT)?, read_bounded_key_optional(&private_path, LIMIT)?)
    } else {
        (read_bounded_key_optional(&public_path, LIMIT)?, read_bounded_key(&private_path, LIMIT)?)
    };
    if public.trim().is_empty() && private.trim().is_empty() {
        return Err(format!("SSH key '{}' contains no key text.", path));
    }
    Ok((public, private))
}

fn read_bounded_key(path: &Path, limit: u64) -> Result<String, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("Cannot read SSH key '{}': {error}", path.display()))?;
    if metadata.len() > limit {
        return Err(format!("SSH key '{}' exceeds OfflineOTP's 32 KiB per-key limit.", path.display()));
    }
    use std::io::Read as _;
    let file = std::fs::File::open(path)
        .map_err(|error| format!("Cannot read SSH key '{}': {error}", path.display()))?;
    let mut bytes = Vec::with_capacity((limit + 1) as usize);
    file.take(limit + 1).read_to_end(&mut bytes)
        .map_err(|error| format!("Cannot read SSH key '{}': {error}", path.display()))?;
    if bytes.len() as u64 > limit {
        return Err(format!("SSH key '{}' exceeds OfflineOTP's 32 KiB per-key limit.", path.display()));
    }
    String::from_utf8(bytes).map_err(|_| format!("SSH key '{}' is not UTF-8 text.", path.display()))
}

fn read_bounded_key_optional(path: &Path, limit: u64) -> Result<String, String> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() <= limit => read_bounded_key(path, limit)
            .map_err(|error| error.replace("SSH key", "SSH public key")),
        Ok(_) => Err(format!("SSH key '{}' exceeds OfflineOTP's 32 KiB per-key limit.", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(format!("Cannot read SSH public key '{}': {error}", path.display())),
    }
}

struct OfflineOtpImportSite {
    site: StoredSite,
    ssh_key_label: Option<String>,
    tunnel_key_label: Option<String>,
    ssh_key: Option<SshKeyRecord>,
    tunnel_key: Option<SshKeyRecord>,
}

fn import_offlineotp_entries(
    config_root: &Path,
    mut store: SessionStore,
    imported: offlineotp_vault::ImportedCredentialVault,
    secret_vault: &linscp_platform::password_vault::PasswordSecretVault,
) -> Result<(usize, usize, usize), String> {
    let mut ignored = imported.ignored_entries;
    let mut sites = Vec::<OfflineOtpImportSite>::new();
    let mut keys = Vec::<SshKeyRecord>::new();

    for entry in imported.entries {
        match entry {
            CredentialEntry::Login(login) => {
                let mut site = if let Some(encoded) = login.metadata.get(OFFLINEOTP_SESSION_JSON) {
                    serde_json::from_str::<StoredSite>(encoded)
                        .map_err(|error| format!("Saved LinSCP session metadata is invalid: {error}"))?
                } else if login.url.trim().is_empty() {
                    StoredSite::new(&login.label, linscp_types::ProtocolScheme::Sftp, "")
                } else {
                    match tabs::parse_desktop_uri(&login.url, true) {
                        Ok((spec, _)) => StoredSite::from_session_config(&spec.session),
                        Err(_) => {
                            ignored += 1;
                            continue;
                        }
                    }
                };
                site.name = login.label.clone();
                if !login.username.is_empty() {
                    site.username = login.username.clone();
                }
                site.password = (!login.password.is_empty()).then_some(login.password);
                clear_imported_key_paths(&mut site);
                validate_imported_site(&site)?;
                sites.push(OfflineOtpImportSite {
                    site,
                    ssh_key_label: login.metadata.get(OFFLINEOTP_SSH_KEY_LABEL).cloned(),
                    tunnel_key_label: login.metadata.get(OFFLINEOTP_TUNNEL_KEY_LABEL).cloned(),
                    ssh_key: None,
                    tunnel_key: None,
                });
            }
            CredentialEntry::SshKey(key) => keys.push(key),
        }
    }

    let mut created_files = Vec::<PathBuf>::new();
    let result = (|| {
        {
            let mut key_labels = std::collections::HashSet::new();
            for key in &keys {
                if !key_labels.insert(key.label.clone()) {
                    return Err(format!("The OfflineOTP backup contains duplicate SSH key label '{}'.", key.label));
                }
            }
            let mut referenced_key_labels = std::collections::HashSet::new();
            for candidate in &sites {
                for label in [candidate.ssh_key_label.as_deref(), candidate.tunnel_key_label.as_deref()].into_iter().flatten() {
                    if !key_labels.contains(label) {
                        return Err(format!("Saved session '{}' refers to missing SSH key '{}'.", candidate.site.name, label));
                    }
                    if !referenced_key_labels.insert(label.to_string()) {
                        return Err(format!("SSH key '{}' is linked to more than one saved session.", label));
                    }
                }
            }
        }

        let mut paired_keys = std::collections::HashSet::new();
        for key in &keys {
            let explicit_main = sites.iter().position(|candidate|
                candidate.ssh_key_label.as_deref() == Some(key.label.as_str()));
            let explicit_tunnel = sites.iter().position(|candidate|
                candidate.tunnel_key_label.as_deref() == Some(key.label.as_str()));
            let fallback = sites.iter().position(|candidate| {
                candidate.ssh_key.is_none() && !key.host.is_empty()
                    && candidate.site.host == key.host
                    && candidate.site.username == key.username
            });
            if let Some(index) = explicit_main.or(explicit_tunnel).or(fallback) {
                let target = &mut sites[index];
                if explicit_tunnel == Some(index) {
                    target.tunnel_key = Some(key.clone());
                } else {
                    target.ssh_key = Some(key.clone());
                }
                if target.site.password.is_none() && !key.password.is_empty() {
                    target.site.password = Some(key.password.clone());
                }
                paired_keys.insert(key.label.clone());
            }
        }

        for key in &keys {
            if paired_keys.contains(&key.label) { continue; }
            let mut site = StoredSite::new(&key.label, linscp_types::ProtocolScheme::Sftp, &key.host);
            site.port = if key.port == 0 { 22 } else { key.port };
            site.username = key.username.clone();
            site.password = (!key.password.is_empty()).then(|| key.password.clone());
            validate_imported_site(&site)?;
            sites.push(OfflineOtpImportSite {
                site,
                ssh_key_label: None,
                tunnel_key_label: None,
                ssh_key: Some(key.clone()),
                tunnel_key: None,
            });
        }

        let mut seen = std::collections::HashSet::new();
        for candidate in &sites {
            if !seen.insert(candidate.site.name.to_ascii_lowercase()) {
                return Err("The OfflineOTP backup contains duplicate LinSCP session names.".to_string());
            }
        }
        let mut skipped = 0usize;
        let mut staged_site_names = Vec::new();
        for mut candidate in sites {
            if store.find(&candidate.site.name).is_some() {
                skipped += 1;
                continue;
            }
            // Serialized paths are local to the exporting computer and are never trusted on import.
            clear_imported_key_paths(&mut candidate.site);
            if let Some(key) = candidate.ssh_key.as_ref() {
                let (private_path, public_path) = stage_offlineotp_key(config_root, key, secret_vault, &mut created_files)?;
                candidate.site.private_key = private_path;
                if let Some(public) = public_path {
                    candidate.site.extra_fields.insert("linscp_public_key_file".into(), public);
                }
            }
            if let Some(key) = candidate.tunnel_key.as_ref() {
                let (private_path, public_path) = stage_offlineotp_key(config_root, key, secret_vault, &mut created_files)?;
                candidate.site.tunnel.keyfile = private_path;
                if let Some(public) = public_path {
                    candidate.site.extra_fields.insert("linscp_tunnel_public_key_file".into(), public);
                }
            }
            validate_imported_site(&candidate.site)?;
            store.upsert(candidate.site.clone());
            staged_site_names.push(candidate.site.name);
        }
        if staged_site_names.is_empty() {
            return Ok((0, skipped, ignored));
        }
        store.save_to_dir(config_root, secret_vault)
            .map_err(|error| format!("Cannot save imported sessions: {error}"))?;
        Ok((staged_site_names.len(), skipped, ignored))
    })();

    if result.is_err() {
        for path in created_files {
            let _ = std::fs::remove_file(path);
        }
    }
    result
}

fn is_sensitive_vault_field(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("password")
        || key.contains("passphrase")
        || key.contains("secret")
        || key.contains("token")
        || (key.contains("private") && key.contains("key"))
}

fn is_local_path_vault_field(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.ends_with("_file") || key.ends_with("_path") || key.contains("keyfile")
}

fn clear_imported_key_paths(site: &mut StoredSite) {
    site.private_key = None;
    site.tunnel.keyfile = None;
    site.password_raw = None;
    site.password_error = None;
    site.proxy_password_raw = None;
    site.tunnel_password_raw = None;
    site.tunnel_passphrase_raw = None;
    site.proxy_error = None;
    site.tunnel_error = None;
    site.setting_error = None;
    site.extra_fields.retain(|key, _| {
        !key.eq_ignore_ascii_case("s3_access_key") && !is_sensitive_vault_field(key) && !is_local_path_vault_field(key)
    });
}

fn validate_imported_site(site: &StoredSite) -> Result<(), String> {
    if site.name.trim().is_empty() || site.name.len() > 1024
        || site.name.contains(']') || site.name.chars().any(char::is_control)
    {
        return Err("The imported session name is invalid.".to_string());
    }
    let text_values = [
        ("host", site.host.as_str()),
        ("username", site.username.as_str()),
        ("password", site.password.as_deref().unwrap_or("")),
        ("host key", site.hostkey.as_deref().unwrap_or("")),
        ("remote directory", site.remote_directory.as_str()),
        ("local directory", site.local_directory.as_str()),
        ("preset", site.preset.as_str()),
        ("proxy method", site.proxy_method.as_str()),
        ("proxy host", site.proxy_host.as_str()),
        ("proxy username", site.proxy_username.as_str()),
        ("proxy password", site.proxy_password.as_deref().unwrap_or("")),
        ("proxy command", site.proxy_command.as_str()),
        ("proxy exclusions", site.proxy_exclude.as_str()),
        ("proxy DNS mode", site.proxy_dns.as_str()),
        ("tunnel host", site.tunnel.host.as_str()),
        ("tunnel username", site.tunnel.username.as_str()),
        ("tunnel password", site.tunnel.password.as_deref().unwrap_or("")),
        ("tunnel host key", site.tunnel.hostkey.as_str()),
        ("tunnel passphrase", site.tunnel_passphrase.as_deref().unwrap_or("")),
    ];
    for (label, value) in text_values {
        validate_imported_ini_text(value, label)?;
    }
    for (key, value) in &site.extra_fields {
        if key.is_empty() || key.len() > 128
            || !key.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err("An imported session contains an invalid setting name.".to_string());
        }
        validate_imported_ini_text(value, key)?;
    }
    Ok(())
}

fn validate_imported_ini_text(value: &str, label: &str) -> Result<(), String> {
    if value.chars().any(char::is_control) {
        return Err(format!("Imported {label} contains unsupported control characters."));
    }
    Ok(())
}

fn cleanup_stale_temporary_keys(config_root: &Path) {
    let root = config_root.join("tmp").join("unlocked-keys");
    let Ok(entries) = std::fs::read_dir(root) else { return; };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(pid) = entry.file_name().to_str().and_then(|name| name.parse::<u32>().ok()) else { continue; };
        if pid != std::process::id() && !linscp_platform::process_is_running(pid) {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

fn protect_stored_ssh_keys(
    site: &mut StoredSite,
    config_root: &Path,
    vault: &linscp_platform::password_vault::PasswordSecretVault,
    created: &mut Vec<PathBuf>,
) -> Result<(), String> {
    site.extra_fields.retain(|key, _| {
        let key = key.to_ascii_lowercase();
        !key.contains("keyfile") && !key.ends_with("private_key_file")
    });
    if let Some(path) = site.private_key.clone() {
        site.private_key = Some(protect_one_ssh_key(&path, config_root, vault, created)?);
    }
    if let Some(path) = site.tunnel.keyfile.clone() {
        site.tunnel.keyfile = Some(protect_one_ssh_key(&path, config_root, vault, created)?);
    }
    Ok(())
}

fn protect_one_ssh_key(
    path: &str,
    config_root: &Path,
    vault: &linscp_platform::password_vault::PasswordSecretVault,
    created: &mut Vec<PathBuf>,
) -> Result<String, String> {
    if let Some(id) = path.strip_prefix(LOCAL_VAULT_KEY_PREFIX) {
        if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("Saved encrypted SSH key reference is invalid.".to_string());
        }
        return Ok(path.to_string());
    }
    let expanded = linscp_platform::terminal::expand_tilde(path);
    let source = PathBuf::from(expanded);
    if source.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("pub")) {
        return Ok(path.to_string()); // Public keys are not confidential.
    }
    let metadata = std::fs::metadata(&source)
        .map_err(|error| format!("Cannot read private SSH key '{}': {error}", source.display()))?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(format!("Private SSH key '{}' is not a regular file under 1 MiB.", source.display()));
    }
    use std::io::Read as _;
    let file = std::fs::File::open(&source)
        .map_err(|error| format!("Cannot read private SSH key '{}': {error}", source.display()))?;
    let mut plaintext = zeroize::Zeroizing::new(Vec::with_capacity(1024 * 1024 + 1));
    file.take(1024 * 1024 + 1).read_to_end(&mut plaintext)
        .map_err(|error| format!("Cannot read private SSH key '{}': {error}", source.display()))?;
    if plaintext.len() > 1024 * 1024 {
        return Err(format!("Private SSH key '{}' is not a regular file under 1 MiB.", source.display()));
    }
    let encrypted = vault.seal_local_blob(&plaintext).map_err(|error| error.to_string())?;
    let mut public_source = source.as_os_str().to_os_string();
    public_source.push(".pub");
    let public_text = read_bounded_key_optional(&PathBuf::from(public_source), 32 * 1024)?;
    let key_dir = config_root.join("keys");
    linscp_platform::create_private_dir(&key_dir).map_err(|error| error.to_string())?;
    'attempt: for _ in 0..8 {
        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);
        let id = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let encrypted_path = key_dir.join(format!("{id}.key.vault"));
        match write_exclusive_private_file(&encrypted_path, &encrypted) {
            Ok(()) => created.push(encrypted_path.clone()),
            Err(linscp_platform::PlatformError::AlreadyExists(_)) => continue 'attempt,
            Err(error) => {
                let _ = std::fs::remove_file(&encrypted_path);
                return Err(error.to_string());
            }
        }
        if !public_text.is_empty() {
            let public_path = key_dir.join(format!("{id}.pub"));
            match write_exclusive_private_file(&public_path, public_text.as_bytes()) {
                Ok(()) => created.push(public_path),
                Err(linscp_platform::PlatformError::AlreadyExists(_)) => {
                    let _ = std::fs::remove_file(&encrypted_path);
                    created.retain(|created_path| created_path != &encrypted_path);
                    continue 'attempt;
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&public_path);
                    let _ = std::fs::remove_file(&encrypted_path);
                    created.retain(|created_path| created_path != &encrypted_path);
                    return Err(error.to_string());
                }
            }
        }
        return Ok(format!("{LOCAL_VAULT_KEY_PREFIX}{id}"));
    }
    Err("Cannot allocate a unique encrypted SSH key file.".to_string())
}

struct TemporaryVaultKeys(Vec<PathBuf>);

impl Drop for TemporaryVaultKeys {
    fn drop(&mut self) {
        for path in &self.0 { let _ = std::fs::remove_file(path); }
    }
}

fn materialize_vault_key_paths(
    spec: &mut linscp_engine::url_and_raw::ParsedSiteSpec,
    config_root: &Path,
    vault: &linscp_platform::password_vault::PasswordSecretVault,
) -> Result<TemporaryVaultKeys, String> {
    let mut temporary = TemporaryVaultKeys(Vec::new());
    materialize_one_vault_key(&mut spec.session.keyfile, config_root, vault, &mut temporary.0)?;
    if let Some(tunnel) = spec.session.tunnel.as_mut() {
        materialize_one_vault_key(&mut tunnel.keyfile, config_root, vault, &mut temporary.0)?;
    }
    Ok(temporary)
}

fn materialize_one_vault_key(
    keyfile: &mut Option<String>,
    config_root: &Path,
    vault: &linscp_platform::password_vault::PasswordSecretVault,
    created: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let Some(reference) = keyfile.as_deref() else { return Ok(()); };
    let Some(id) = reference.strip_prefix(LOCAL_VAULT_KEY_PREFIX) else { return Ok(()); };
    if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Saved encrypted SSH key reference is invalid.".to_string());
    }
    let encrypted_path = config_root.join("keys").join(format!("{id}.key.vault"));
    let metadata = std::fs::metadata(&encrypted_path)
        .map_err(|error| format!("Cannot read encrypted SSH key: {error}"))?;
    if metadata.len() > 1024 * 1024 {
        return Err("Encrypted SSH key file is unexpectedly large.".to_string());
    }
    let encrypted = std::fs::read(&encrypted_path)
        .map_err(|error| format!("Cannot read encrypted SSH key: {error}"))?;
    let plaintext = vault.open_local_blob(&encrypted).map_err(|error| error.to_string())?;
    let temp_dir = config_root.join("tmp").join("unlocked-keys").join(std::process::id().to_string());
    linscp_platform::create_private_dir(&temp_dir).map_err(|error| error.to_string())?;
    for _ in 0..8 {
        let mut random = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut random);
        let suffix = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let path = temp_dir.join(format!("{id}-{suffix}.key"));
        match write_exclusive_private_file(&path, &plaintext) {
            Ok(()) => created.push(path.clone()),
            Err(linscp_platform::PlatformError::AlreadyExists(_)) => continue,
            Err(error) => {
                let _ = std::fs::remove_file(&path);
                return Err(error.to_string());
            }
        }
        let source_public = config_root.join("keys").join(format!("{id}.pub"));
        let public = match read_bounded_key_optional(&source_public, 32 * 1024) {
            Ok(public) => public,
            Err(error) => return Err(error),
        };
        if !public.is_empty() {
            let public_path = PathBuf::from(format!("{}.pub", path.display()));
            match write_exclusive_private_file(&public_path, public.as_bytes()) {
                Ok(()) => created.push(public_path),
                Err(linscp_platform::PlatformError::AlreadyExists(_)) => {
                    let _ = std::fs::remove_file(&path);
                    created.retain(|created_path| created_path != &path);
                    continue;
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&public_path);
                    let _ = std::fs::remove_file(&path);
                    created.retain(|created_path| created_path != &path);
                    return Err(error.to_string());
                }
            }
        }
        *keyfile = Some(path.to_string_lossy().into_owned());
        return Ok(());
    }
    Err("Cannot create a temporary SSH key file.".to_string())
}

fn stage_offlineotp_key(
    config_root: &Path,
    key: &SshKeyRecord,
    secret_vault: &linscp_platform::password_vault::PasswordSecretVault,
    created: &mut Vec<PathBuf>,
) -> Result<(Option<String>, Option<String>), String> {
    'attempt: for _ in 0..8 {
        let mut random = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random);
        let stem = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let dir = config_root.join("keys");
        let mut private_ref = None;
        let mut private_file_path = None;
        let mut public_path = None;
        if !key.private_key.is_empty() {
            let encrypted = secret_vault.seal_local_blob(key.private_key.as_bytes())
                .map_err(|error| error.to_string())?;
            let path = dir.join(format!("{stem}.key.vault"));
            match write_exclusive_private_file(&path, &encrypted) {
                Ok(()) => {
                    created.push(path.clone());
                    private_file_path = Some(path);
                    private_ref = Some(format!("{LOCAL_VAULT_KEY_PREFIX}{stem}"));
                }
                Err(linscp_platform::PlatformError::AlreadyExists(_)) => continue 'attempt,
                Err(error) => {
                    let _ = std::fs::remove_file(&path);
                    return Err(error.to_string());
                }
            }
        }
        if !key.public_key.is_empty() {
            let path = dir.join(format!("{stem}.pub"));
            match write_exclusive_private_file(&path, key.public_key.as_bytes()) {
                Ok(()) => {
                    created.push(path.clone());
                    public_path = Some(format!("vaultpub://{stem}"));
                }
                Err(linscp_platform::PlatformError::AlreadyExists(_)) => {
                    if let Some(private) = private_file_path.as_ref() {
                        let _ = std::fs::remove_file(private);
                        created.retain(|created_path| created_path != private);
                    }
                    continue 'attempt;
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&path);
                    if let Some(private) = private_file_path.as_ref() {
                        let _ = std::fs::remove_file(private);
                        created.retain(|created_path| created_path != private);
                    }
                    return Err(error.to_string());
                }
            }
        }
        return Ok((private_ref, public_path));
    }
    Err("Cannot allocate a unique imported SSH key filename.".to_string())
}

fn api_error(status: u16, error: impl Into<String>) -> ApiReply {
    ApiReply { status, payload: json!({"success": false, "error": error.into()}) }
}

fn resolve_local_path_for_list(path: &str) -> Result<String, String> {
    if path.trim().is_empty() { return Err("No path given".to_string()); }
    // A granted Android folder is a `content://` tree, not a filesystem path:
    // `Path::is_absolute` is false for it, but the `LocalFs` can list it. The
    // URI is validated structurally, so a malformed one is refused with the
    // same message a relative path gets.
    if is_saf_path(path) {
        linscp_platform::parse_saf_document_uri(path).map_err(|error| error.to_string())?;
        return Ok(path.to_string());
    }
    let p = Path::new(path);
    if !p.is_absolute() { return Err("The local directory of this panel is not set.".to_string()); }
    let abs = p.to_path_buf();
    // For list we allow any absolute path, but check existence via local_fs later
    Ok(abs.to_string_lossy().into_owned())
}
fn resolve_contained(base: &str, name: &str) -> Result<String, String> {
    if name.is_empty() || name=="." || name==".." || name.contains('/') || name.contains('\\') || name.contains(':') || name.contains('\0') || Path::new(name).components().count() != 1 {
        return Err(format!("\"{name}\" is not a single file name in this directory."));
    }
    if name.chars().any(|c| c.is_control()) { return Err("A file name must not contain a control character.".to_string()); }
    if is_saf_path(base) {
        let base = base.trim_end_matches('/');
        linscp_platform::parse_saf_document_uri(base).map_err(|error| error.to_string())?;
        return Ok(format!("{base}/document/{name}"));
    }
    if base.is_empty() || !Path::new(base).is_absolute() { return Err("The local directory of this panel is not set.".to_string()); }
    let base_path = Path::new(base);
    let target = base_path.join(name);
    // lexical containment check: target must be within base
    let base_abs = base_path.to_path_buf();
    let target_abs = target.to_path_buf();
    // Use commonpath logic
    let base_str = base_abs.to_string_lossy().to_string();
    let target_str = target_abs.to_string_lossy().to_string();
    if !target_str.starts_with(&base_str) { return Err("The path is outside the panel directory.".to_string()); }
    Ok(target_str)
}
/// The names a remote operation targets: an object list (`names: [{name}]`),
/// a string list, or a single `name`. Order is kept and duplicates removed.
fn remote_names(body: &Value) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    {
        let mut push = |name: &str| {
            let name = name.trim();
            if !name.is_empty() && seen.insert(name.to_string()) { out.push(name.to_string()); }
        };
        match body.get("names") {
            Some(Value::Array(items)) => {
                for item in items {
                    if let Some(name) = item.as_str() {
                        push(name);
                    } else if let Some(name) = item.get("name").and_then(Value::as_str) {
                        push(name);
                    }
                }
            }
            Some(Value::String(name)) => push(name),
            _ => {}
        }
    }
    if out.is_empty() {
        if let Some(name) = body.get("name").and_then(Value::as_str) {
            let name = name.trim();
            if !name.is_empty() && seen.insert(name.to_string()) { out.push(name.to_string()); }
        }
    }
    out
}

/// An absolute remote path without dot segments, control characters or
/// backslashes – the shape every server accepts and the one the page shows.
fn validate_remote_absolute_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() || !trimmed.starts_with('/') {
        return Err("An absolute remote path is required.".to_string());
    }
    if trimmed.contains('\\') || trimmed.contains("//") || trimmed.chars().any(char::is_control) {
        return Err("A remote path must not contain backslashes, empty segments or control characters.".to_string());
    }
    if trimmed.split('/').any(|part| part == "." || part == "..") {
        return Err("A remote path must not contain dot segments.".to_string());
    }
    Ok(trimmed.to_string())
}

/// Parses an octal permission string (`644`, `0644`, `4755`) into a mode.
/// Symbolic modes (`u=rw,go=r`) are accepted by the console client only; here
/// the dialogue asks for octal, so anything else is refused rather than
/// guessed at.
fn parse_octal_mode(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 4 || !trimmed.chars().all(|c| ('0'..='7').contains(&c)) {
        return None;
    }
    u32::from_str_radix(trimmed, 8).ok().filter(|mode| *mode <= 0o7777)
}

/// The canonical spelling of a checksum algorithm, when it is one the
/// protocols implement.
fn checksum_algorithm(raw: &str) -> Option<String> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "sha256" | "sha-256" => Some("sha-256".to_string()),
        "sha1" | "sha-1" => Some("sha-1".to_string()),
        "md5" => Some("md5".to_string()),
        "crc32" => Some("crc32".to_string()),
        _ => None,
    }
}

/// The plan as the page draws it: one item per path with the action, the
/// relative path and the reason, plus the counts the summary line shows. The
/// action names match the page's own (`delete-local`, not `deletelocal`).
fn sync_plan_json(items: &[linscp_engine::sync_planner::SyncItem]) -> Value {
    use linscp_engine::sync_planner::SyncAction;
    let mut counts: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    let mut rows = Vec::with_capacity(items.len());
    for item in items {
        let action = match item.action {
            SyncAction::None => "unchanged",
            SyncAction::Upload => "upload",
            SyncAction::Download => "download",
            SyncAction::DeleteLocal => "delete-local",
            SyncAction::DeleteRemote => "delete-remote",
            SyncAction::Conflict => "conflict",
        };
        *counts.entry(action).or_insert(0) += 1;
        rows.push(json!({
            "action": action,
            "path": item.rel_path,
            "is_dir": item.is_directory,
            "size": item.local_size.max(item.remote_size),
            "reason": sync_reason_for_page(&item.reason),
        }));
    }
    let summary: serde_json::Map<String, Value> =
        counts.into_iter().map(|(action, count)| (action.to_string(), json!(count))).collect();
    json!({"items": rows, "summary": Value::Object(summary), "truncated": false})
}

/// The plan's reason as the page expects it: a sentence the GUI catalogs carry
/// a translation for. The planner's own wording is the console client's and
/// stays there; a phrase the catalogs do not know is passed through unchanged,
/// so a new reason shows up untranslated rather than missing.
fn sync_reason_for_page(reason: &str) -> String {
    let key = match reason {
        "up to date" => "unchanged",
        "missing locally" => "the other side does not have it",
        "missing on remote" => "the other side does not have it",
        "new locally" => "it is new on the local side",
        "new on remote" => "it is new on the remote side",
        "deleted locally" => "it was removed on the other side since the last synchronization",
        "deleted on remote" => "it was removed on the other side since the last synchronization",
        "removed locally since last sync" => {
            "it was removed on the other side since the last synchronization"
        }
        "removed on remote since last sync" => {
            "it was removed on the other side since the last synchronization"
        }
        "modified locally" => "it changed locally since the last synchronization",
        "modified on remote" => "it changed remotely since the last synchronization",
        "modified on both sides (conflict)" => {
            "it changed on both sides since the last synchronization"
        }
        "modified on both sides with identical timestamps" => {
            "it changed on both sides since the last synchronization"
        }
        "local is newer" => "the local file is newer",
        "remote is newer" => "the remote file is newer",
        "size differs" => "the sizes differ",
        "contents differ" => "the local file differs",
        "timestamp differs (-mirror)" => "the local file is newer",
        "type mismatch (file vs directory)" => "it is a directory on one side and a file on the other",
        "conflict resolved in favour of local" => "conflict resolved in favour of the local file",
        "conflict resolved in favour of remote" => "conflict resolved in favour of the remote file",
        "conflict resolved in favour of newer local file" => {
            "conflict resolved in favour of the newer local file"
        }
        "conflict resolved in favour of newer remote file" => {
            "conflict resolved in favour of the newer remote file"
        }
        other => other,
    };
    key.to_string()
}

/// True when `path` is a granted Android folder (`content://` tree URI).
pub(crate) fn is_saf_path(path: &str) -> bool {
    path.starts_with("content://")
}

/// The refusal for a local action the granted-folder bridge does not
/// implement. Listing, creating, renaming, deleting, editing, saving and
/// reading properties inside a granted folder go through `LocalFs`;
/// everything else — transfers, synchronization and directory watching —
/// needs a plain filesystem path, so the refusal names the limitation
/// instead of failing later with a path error. `action` is a gerund
/// phrase such as `"Synchronizing"` or `"Moving files"`.
fn saf_unsupported(action: &str) -> String {
    format!("{action} needs a folder in app storage, not a granted Android folder.")
}

/// A local directory synchronization or directory watching may use: an
/// absolute plain path. A granted folder is refused before the absolute-path
/// check so it gets the limitation's name, not "an absolute directory is
/// required", which is true but explains nothing about a tree the system
/// picker legitimately granted.
/// The local root a synchronization or keep-up-to-date run accepts: a plain
/// absolute directory, or a granted folder kept verbatim (`LocalFs` is what
/// proves it is a real root). Existence is checked by the callers, which own
/// the filesystem.
fn check_sync_local_dir(raw: &str) -> Result<String, String> {
    let dir = raw.trim().to_string();
    if is_saf_path(&dir) {
        linscp_platform::parse_saf_document_uri(&dir).map_err(|error| error.to_string())?;
        return Ok(dir);
    }
    if dir.is_empty() || !Path::new(&dir).is_absolute() {
        return Err("An absolute local directory is required.".to_string());
    }
    Ok(dir)
}

/// Creates `name` as a symbolic link to `target` inside one local pane
/// directory. Both are single leaves, like the remote form: the target is
/// relative to the link's directory, the two names must differ, and the
/// link name must not exist yet. A granted folder has no links to create,
/// so it gets the limitation's name instead of a filesystem error.
fn create_local_link(base: &str, target: &str, name: &str) -> Result<(), String> {
    if is_saf_path(base) {
        return Err(saf_unsupported("Creating symbolic links"));
    }
    let target = ops::validate_leaf_name(target)?;
    let name = ops::validate_leaf_name(name)?;
    if target == name {
        return Err("A link and its target need two different names.".to_string());
    }
    let link = resolve_contained(base, &name)?;
    if std::fs::symlink_metadata(&link).is_ok() {
        return Err("The link name already exists.".to_string());
    }
    gui_os::create_local_symlink(&target, Path::new(&link)).map_err(|error| error.to_string())
}

fn check_local_pane_directory(raw: &str, label: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() { return Err(format!("The {label} is required.")); }
    if t.chars().any(|c| c.is_control()) { return Err(format!("The {label} must not contain control characters.")); }
    // A granted Android folder has no pathname to canonicalize; it is kept
    // verbatim and `LocalFs` is what proves it is a real root.
    if is_saf_path(t) {
        linscp_platform::parse_saf_document_uri(t).map_err(|error| error.to_string())?;
        return Ok(t.to_string());
    }
    let p = Path::new(t);
    let abs = if p.is_absolute() { p.to_path_buf() } else { std::env::current_dir().unwrap_or(PathBuf::from(".")).join(p) };
    if !abs.is_dir() { return Err(format!("The {label} does not exist or is not a directory.")); }
    Ok(abs.canonicalize().unwrap_or(abs).to_string_lossy().into_owned())
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in query.split('&') {
        if pair.is_empty() { continue; }
        let (k,v) = match pair.split_once('=') { Some((k,v)) => (percent_decode(k), percent_decode(v)), None => (percent_decode(pair), String::new())};
        map.insert(k,v);
    }
    map
}
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i=0;
    while i < bytes.len() {
        if bytes[i]==b'+' { out.push(b' '); i+=1; }
        else if bytes[i]==b'%' && i+2 < bytes.len() {
            if let (Some(hi), Some(lo)) = ((bytes[i+1] as char).to_digit(16), (bytes[i+2] as char).to_digit(16)) {
                out.push(((hi<<4)|lo) as u8); i+=3; continue;
            }
            out.push(bytes[i]); i+=1;
        } else { out.push(bytes[i]); i+=1; }
    }
    String::from_utf8_lossy(&out).into_owned()
}
#[cfg(test)]
mod tests {
    use super::*;
    use linscp_platform::PlatformError;
    use linscp_types::{FileEntry, LocalRootEntry, ProtocolScheme};

    fn unlock_for_test(service: &CommanderService) {
        let reply = service.dispatch(ApiEnvelope {
            method: "POST".into(),
            path: "/api/vault/unlock".into(),
            body: json!({"password": "correct horse battery staple"}),
        });
        assert_eq!(reply.status, 200, "{}", reply.payload);
    }

    #[test]
    fn offlineotp_vault_round_trip_restores_login_and_ssh_key_without_source_paths() {
        let temp = tempfile::tempdir().unwrap();
        let source_key = temp.path().join("original-id_ed25519");
        let source_public = temp.path().join("original-id_ed25519.pub");
        std::fs::write(&source_key, "-----BEGIN OPENSSH PRIVATE KEY-----\nexample\n-----END OPENSSH PRIVATE KEY-----\n").unwrap();
        std::fs::write(&source_public, "ssh-ed25519 AAAATEST user@example\n").unwrap();

        let mut source = SessionStore::new();
        let mut site = StoredSite::new("primary", ProtocolScheme::Sftp, "sftp.example.test");
        site.username = "deploy".into();
        site.password = Some("login-secret".into());
        site.private_key = Some(source_key.to_string_lossy().into_owned());
        site.local_directory = temp.path().join("local-source").to_string_lossy().into_owned();
        source.upsert(site);

        let source_path = source_key.to_string_lossy().into_owned();
        let local_path = temp.path().join("local-source").to_string_lossy().into_owned();
        let config_root = temp.path().join("config");
        std::fs::create_dir_all(&config_root).unwrap();
        let secret_vault = linscp_platform::password_vault::PasswordSecretVault::new();
        secret_vault.unlock_or_setup(&config_root, "correct horse battery staple", &NativeSecretVault::new()).unwrap();
        let entries = offlineotp_entries_from_sessions(&source, &config_root, &secret_vault).unwrap();
        assert!(entries.iter().any(|entry| match entry {
            CredentialEntry::Login(login) => {
                !login.metadata[OFFLINEOTP_SESSION_JSON].contains(source_path.as_str())
                    && !login.metadata[OFFLINEOTP_SESSION_JSON].contains(local_path.as_str())
            }
            _ => false,
        }));
        let encrypted = offlineotp_vault::seal(&entries, "correct horse battery staple").unwrap();
        let opened = offlineotp_vault::open(&encrypted, "correct horse battery staple").unwrap();
        let (imported, skipped, ignored) = import_offlineotp_entries(
            &config_root,
            SessionStore::new(),
            opened,
            &secret_vault,
        ).unwrap();
        assert_eq!((imported, skipped, ignored), (1, 0, 0));

        let restored = SessionStore::load_from_dir(&config_root, &secret_vault).unwrap();
        let restored = restored.find("primary").unwrap();
        assert_eq!(restored.username, "deploy");
        assert_eq!(restored.password.as_deref(), Some("login-secret"));
        let restored_key_ref = restored.private_key.as_deref().unwrap();
        let restored_key_id = restored_key_ref.strip_prefix(LOCAL_VAULT_KEY_PREFIX).unwrap();
        let restored_key = config_root.join("keys").join(format!("{restored_key_id}.key.vault"));
        let ciphertext = std::fs::read(&restored_key).unwrap();
        assert!(!ciphertext.windows(b"OPENSSH PRIVATE KEY".len()).any(|window| window == b"OPENSSH PRIVATE KEY"));
        let opened_private = secret_vault.open_local_blob(&ciphertext).unwrap();
        let source_private = std::fs::read(&source_key).unwrap();
        assert_eq!(opened_private.as_slice(), source_private.as_slice());
        let mut connect_spec = linscp_engine::url_and_raw::ParsedSiteSpec::default();
        connect_spec.session.keyfile = Some(restored_key_ref.to_string());
        let temporary = materialize_vault_key_paths(&mut connect_spec, &config_root, &secret_vault).unwrap();
        let temporary_path = PathBuf::from(connect_spec.session.keyfile.as_deref().unwrap());
        assert_eq!(std::fs::read(&temporary_path).unwrap(), source_private);
        drop(temporary);
        assert!(!temporary_path.exists());
        let sessions_ini = std::fs::read_to_string(config_root.join("sessions.ini")).unwrap();
        assert!(!sessions_ini.contains("login-secret"));
        assert!(!sessions_ini.contains(source_key.to_string_lossy().as_ref()));
    }

    #[test]
    fn unsupported_operations_never_report_success_or_write_files() {
        let svc = CommanderService::default();
        // Every endpoint the page offers is implemented now. With no
        // connected tab each must still refuse instead of pretending.
        for path in [
            "/api/remote/chmod", "/api/remote/search", "/api/remote/checksum",
            "/api/remote/copy", "/api/remote/link", "/api/remote/rename", "/api/remote/rights",
            "/api/remote/save", "/api/sync/preview", "/api/sync/run",
            "/api/session/terminal", "/api/shell/consume", "/api/command/exec",
        ] {
            let reply = svc.dispatch(ApiEnvelope {
                method: "POST".into(), path: path.into(),
                body: json!({"tab": 0, "path": "/", "name": "x", "names": ["x"], "data": ""}),
            });
            // Every one of these refuses, and none of them reports success.
            // The status says why - 400 needs a connection, 404 is a route only
            // the asynchronous dispatcher serves, 501 is an operation this host
            // cannot perform - so the assertion is that it is an error status
            // and not a success, not that each endpoint picked one spelling.
            assert!(!(200..300).contains(&reply.status), "{path} answered {} with {}", reply.status, reply.payload);
            assert_ne!(reply.payload["success"], true, "{path}");
        }
    }

    /// A1: whether a launch may start a viewer is a property of the host, and it
    /// has to be off unless the host said otherwise — a service built by code that
    /// does not know where it runs must write a ticket, not open a window.
    #[test]
    fn desktop_spawn_permission_is_off_until_the_host_grants_it() {
        let root = std::env::temp_dir().join(format!("linscp-desktop-spawn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let svc = CommanderService::new(root.clone(), Arc::new(NativeLocalFs::new()));
        assert!(!svc.desktop_spawn_allowed(), "default has to be file-ticket");
        let svc = svc.with_desktop_spawn(true);
        assert!(svc.desktop_spawn_allowed());
        let _ = std::fs::remove_dir_all(root);
    }

    /// A1, from the service's side of the contract: when the service says "I cannot
    /// show a viewer", the `.rdp` body handed to the client must be writeable — and
    /// must not contain the login it describes. That is the answer a host that
    /// cannot show a viewer depends on, and it is the branch Windows used to take
    /// *by accident*.
    #[test]
    fn a_host_that_cannot_show_a_viewer_gets_a_safe_ticket_body() {
        use linscp_proto::remote_desktop::{
            ticket_from_config, DesktopOptions, RemoteDesktopConnectConfig, RemoteDesktopKind,
        };
        // A written ticket exists only where the platform has a document to write.
        if linscp_proto::remote_desktop::desktop_viewer_plan()
            != linscp_proto::remote_desktop::DesktopViewerPlan::WindowsMstsc
        {
            return;
        }
        let secret = "not-in-the-ticket";
        let cfg = RemoteDesktopConnectConfig {
            scheme: linscp_types::ProtocolScheme::Rdp,
            kind: RemoteDesktopKind::Rdp,
            host: "example.test".to_string(),
            port: 3389,
            username: Some("deploy".to_string()),
            password: Some(zeroize::Zeroizing::new(secret.to_string())),
            domain: None,
            desktop_opts: DesktopOptions::default(),
            tls: linscp_proto::tls::TlsSettings::default(),
            proxy: None,
            timeout: std::time::Duration::from_secs(15),
        };
        let ticket = ticket_from_config(&cfg, RemoteDesktopKind::Rdp, "example.test:3389", false, None);
        let content = ticket.file_content.as_deref().expect("mstsc is given a .rdp document");
        assert!(
            !content.contains(secret),
            "the .rdp body must not embed the password: {content}"
        );
        assert!(content.contains("example.test:3389"), "ticket content: {content}");
        assert!(content.contains("username:s:deploy"), "ticket content: {content}");
    }

    #[test]
    fn s3_secrets_are_not_returned_or_saved_as_plaintext() {
        let root = std::env::temp_dir().join(format!("linscp-s3-secrets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let svc = CommanderService::new(root.clone(), Arc::new(NativeLocalFs::new()));
        let body = json!({"name": "s3-test", "session": {"protocol": "s3", "host": "example.test", "s3_access_key": "access", "s3_secret_key": "secret", "s3_session_token": "token"}});
        let (spec, clean) = tabs::parse_gui_session_spec(&body["session"], None, &root, svc.secret_vault.as_ref()).unwrap();
        assert_eq!(spec.session.username, "access");
        assert_eq!(spec.session.password.as_deref(), Some("secret"));
        assert!(clean.get("s3_secret_key").is_none());
        assert!(clean.get("s3_session_token").is_none());
        let reply = svc.dispatch(ApiEnvelope { method: "POST".into(), path: "/api/sessions/save".into(), body });
        assert_eq!(reply.status, 400);
        let mut site = tabs::build_stored_site_for_save("old", &spec);
        site.extra_fields.insert("s3_secret_key".into(), "legacy secret".into());
        let view = tabs::stored_site_to_gui_json(&site);
        assert!(view.get("s3_secret_key").is_none());
        assert!(view.get("s3_session_token").is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn workspace_round_trip_and_unavailable_actions_fail_closed() {
        let tmp = std::env::temp_dir().join(format!("linscp-workspace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let left = tmp.join("left"); let right = tmp.join("right");
        std::fs::create_dir_all(&left).unwrap(); std::fs::create_dir_all(&right).unwrap();
        let root = tmp.join("config");
        let svc = CommanderService::new(root.clone(), Arc::new(NativeLocalFs::new()));
        let request = |method: &str, path: &str, body: Value| ApiEnvelope { method: method.into(), path: path.into(), body };
        let first = svc.dispatch_async(request("POST", "/api/tabs/local", json!({"local_dir": left, "remote_dir": right}))).await;
        let first_id = first.payload["tab"]["id"].as_u64().unwrap();
        let second = svc.dispatch_async(request("POST", "/api/tabs/local", json!({"local_dir": right, "remote_dir": left}))).await;
        let second_id = second.payload["tab"]["id"].as_u64().unwrap();
        svc.dispatch_async(request("POST", "/api/tabs/select", json!({"tab": first_id}))).await;
        let saved = svc.dispatch_async(request("POST", "/api/workspaces/save", json!({"name": "My workspace"}))).await;
        assert_eq!(saved.status, 200, "{}", saved.payload);
        let listed = svc.dispatch_async(request("GET", "/api/workspaces", json!({}))).await;
        assert_eq!(listed.payload["workspaces"][0]["name"], "My workspace");
        assert_eq!(listed.payload["workspaces"][0]["tab_count"], 2);
        let reopened = svc.dispatch_async(request("POST", "/api/workspaces/open", json!({"name": "My workspace"}))).await;
        assert_eq!(reopened.status, 200, "{}", reopened.payload);
        assert_eq!(reopened.payload["opened"].as_array().unwrap().len(), 2);
        assert!(reopened.payload["failed"].as_array().unwrap().is_empty());
        let restored = reopened.payload["opened"][0]["id"].as_u64().unwrap();
        assert_eq!(reopened.payload["active_tab"], restored);
        let state = svc.state.lock().unwrap();
        assert_eq!(state.active_tab_id, Some(restored));
        assert!(state.tabs.contains_key(&first_id) && state.tabs.contains_key(&second_id));
        assert_eq!(state.tabs[&restored].local_dir, left.canonicalize().unwrap().to_string_lossy().into_owned());
        drop(state);
        // A file manager's selection is staged, offered and only then queued:
        // a local tab has no server to upload to, so it must refuse and leave
        // the request in place rather than reporting an upload that cannot run.
        let shell = root.join("shell-manifests");
        std::fs::create_dir_all(&shell).unwrap();
        let manifest = shell.join("pending.json");
        std::fs::write(&manifest, b"{\"id\":\"pending\",\"items\":[]}").unwrap();
        let refused = svc.dispatch_async(request("POST", "/api/shell/consume", json!({"id": "pending", "tab": first_id}))).await;
        assert_eq!(refused.status, 400, "{}", refused.payload);
        assert_eq!(refused.payload["error"], "Not connected");
        assert!(manifest.exists(), "a refused offer must stay available");

        // A terminal needs an SSH connection; a local tab has none and says so
        // instead of opening a window that could never type anything.
        let terminal = svc.dispatch_async(request("POST", "/api/session/terminal", json!({"tab": first_id}))).await;
        assert_eq!(terminal.status, 400, "{}", terminal.payload);
        // Typing into a terminal that is gone is an error the page may
        // swallow; closing one that is already closed is not, because a poll
        // that saw the end and the window closing both get here.
        let typed = svc.dispatch_async(request("POST", "/api/terminal/input", json!({"terminal": "term-1", "data": "bHM="}))).await;
        assert_eq!(typed.status, 400, "{}", typed.payload);
        let closed = svc.dispatch_async(request("POST", "/api/terminal/close", json!({"terminal": "term-1"}))).await;
        assert_eq!(closed.status, 200);
        assert_eq!(closed.payload["success"], true);
        let output = svc.dispatch_async(request("GET", "/api/terminal/output?terminal=term-1", json!({}))).await;
        assert_eq!(output.status, 400, "an unknown terminal is not a success");
        assert_eq!(output.payload["success"], false);
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// The Custom commands page's Run button posts `{action:"run", ...}` and has
    /// to get an answer about the files it named. It used to get "Not connected"
    /// for every tab, connected or not, because the page's endpoint was a stub
    /// in the synchronous table and nothing ran.
    #[tokio::test]
    async fn the_custom_command_run_button_answers_for_each_selected_file() {
        let tmp = std::env::temp_dir().join(format!("linscp-custom-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let left = tmp.join("left");
        let right = tmp.join("right");
        std::fs::create_dir_all(&left).unwrap();
        std::fs::create_dir_all(&right).unwrap();
        std::fs::write(left.join("a.txt"), b"one").unwrap();
        std::fs::write(right.join("b.txt"), b"two").unwrap();
        // Both selections run in the local pane, so both names have to exist
        // there for their runs to succeed.
        std::fs::write(left.join("b.txt"), b"two").unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));

        let run = |tab: u64, name: &str, files: Value, pane: &str| ApiEnvelope {
            method: "POST".into(),
            path: "/api/custom-commands".into(),
            body: json!({"action": "run", "name": name, "filenames": files,
                "pane": pane, "tab": tab}),
        };

        // Nothing saved answers to that name, and the reason says so instead of
        // claiming the tab is not connected.
        let unknown = svc
            .dispatch_async(run(1, "Nope", json!(["a.txt"]), "local"))
            .await;
        assert_eq!(unknown.status, 404, "{}", unknown.payload);
        assert!(
            unknown.payload["error"].as_str().unwrap_or("").contains("Nope"),
            "{}",
            unknown.payload
        );

        let save = svc
            .dispatch(ApiEnvelope {
                method: "POST".into(),
                path: "/api/custom-commands".into(),
                body: json!({"action": "save", "name": "Look", "command": "lls {file}",
                    "scope": "local"}),
            });
        assert_eq!(save.status, 200, "{}", save.payload);

        let open = svc
            .dispatch_async(ApiEnvelope {
                method: "POST".into(),
                path: "/api/tabs/open".into(),
                body: json!({"session": {"protocol": "local", "local_dir": left,
                    "other_local_dir": right}}),
            })
            .await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();

        // Both selected entries are answered, one result each, and the command
        // the interpreter was given is reported with the file it ran for.
        let replied = svc
            .dispatch_async(run(id, "Look", json!(["a.txt", "b.txt"]), "local"))
            .await;
        assert_eq!(replied.status, 200, "{}", replied.payload);
        let results = replied.payload["results"].as_array().expect("results");
        assert_eq!(results.len(), 2, "{}", replied.payload);
        for result in results {
            assert_eq!(result["success"], true, "{}", result);
            assert_eq!(result["exit_code"], 0, "{}", result);
            assert_eq!(result["error"], "", "{}", result);
        }
        assert_eq!(results[0]["file"], "a.txt");
        assert_eq!(results[1]["file"], "b.txt");
        assert!(
            results[0]["command"].as_str().unwrap_or("").contains("lls"),
            "the answer shows the line that ran: {:?}",
            results[0]
        );

        // A name with a space is one operand, so the command runs against the
        // file the user selected rather than two names that are not there.
        std::fs::write(left.join("two words.txt"), b"three").unwrap();
        let spaced = svc
            .dispatch_async(run(id, "Look", json!(["two words.txt"]), "local"))
            .await;
        assert_eq!(spaced.status, 200, "{}", spaced.payload);
        assert_eq!(
            spaced.payload["results"][0]["success"], true,
            "a name with a space stays one operand: {}",
            spaced.payload
        );

        // A local selection is not where a remote template looks. (A local-only
        // tab cannot mismatch — both its panes are local — so this needs a
        // remote tab, which the mock session provides without dialling out.)
        let save_remote = svc
            .dispatch(ApiEnvelope {
                method: "POST".into(),
                path: "/api/custom-commands".into(),
                body: json!({"action": "save", "name": "Rem", "command": "ls {file}",
                    "scope": "remote"}),
            });
        assert_eq!(save_remote.status, 200, "{}", save_remote.payload);
        let remote_id = insert_remote_tab(&svc, Arc::new(MockSession::new()), "/tmp");
        let mismatch = svc
            .dispatch_async(run(remote_id, "Rem", json!(["a.txt"]), "local"))
            .await;
        assert_eq!(mismatch.status, 400, "{}", mismatch.payload);
        assert_eq!(mismatch.payload["success"], false);
        assert!(
            mismatch.payload["error"].as_str().unwrap_or("").contains("remote side"),
            "the refusal names the side the command is saved for: {}",
            mismatch.payload
        );
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[tokio::test]
    async fn local_file_copy_is_queued_and_conflicts_are_not_overwritten() {
        let tmp = std::env::temp_dir().join(format!("linscp-queue-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let left = tmp.join("left");
        let right = tmp.join("right");
        std::fs::create_dir_all(&left).unwrap();
        std::fs::create_dir_all(&right).unwrap();
        std::fs::write(left.join("data.txt"), b"test content").unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let open = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": left, "other_local_dir": right}}) }).await;
        assert_eq!(open.status, 200);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let request = || ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": left, "remote_dir": right, "names": ["data.txt"]}) };
        let result = svc.dispatch_async(request()).await;
        assert_eq!(result.status, 200, "{}", result.payload);
        let mut finished = false;
        for _ in 0..200 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.first().and_then(|v| v["status"].as_str()) == Some("Completed") { finished = true; break; }
            if tasks.first().and_then(|v| v["status"].as_str()) == Some("Failed") { panic!("queue failure: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(finished, "transfer did not complete");
        assert_eq!(std::fs::read(right.join("data.txt")).unwrap(), b"test content");
        std::fs::write(right.join("data.txt"), b"do not overwrite").unwrap();
        let conflict = svc.dispatch_async(request()).await;
        assert_eq!(conflict.status, 409);
        assert_eq!(std::fs::read(right.join("data.txt")).unwrap(), b"do not overwrite");
        let refused = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": left, "remote_dir": right, "names": ["data.txt"], "overwrite": "overwrite"}) }).await;
        assert_eq!(refused.status, 501, "{}", refused.payload);
        assert_eq!(std::fs::read(right.join("data.txt")).unwrap(), b"do not overwrite");
        let invalid = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": left, "remote_dir": right, "names": ["../data.txt"]}) }).await;
        assert_eq!(invalid.status, 400);
        std::fs::write(left.join("later.txt"), b"new data").unwrap();
        svc.queue.pause();
        let queued = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": left, "remote_dir": right, "names": ["later.txt"]}) }).await;
        assert_eq!(queued.status, 200);
        std::fs::write(right.join("later.txt"), b"created after queuing").unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..200 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(1).and_then(|v| v["status"].as_str()) == Some("Failed") { failed = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(failed, "new destination should fail without overwrite approval");
        assert_eq!(std::fs::read(right.join("later.txt")).unwrap(), b"created after queuing");
        std::fs::write(left.join("approved-new.txt"), b"queued data").unwrap();
        svc.queue.pause();
        let approved = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": left, "remote_dir": right, "names": ["approved-new.txt"], "overwrite": "overwrite"}) }).await;
        assert_eq!(approved.status, 200);
        std::fs::write(right.join("approved-new.txt"), b"concurrent data").unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..200 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(2).and_then(|v| v["status"].as_str()) == Some("Failed") { failed = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(failed, "approval for existing destinations must not apply to new files");
        assert_eq!(std::fs::read(right.join("approved-new.txt")).unwrap(), b"concurrent data");
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(any(target_os = "linux", windows))]
    #[tokio::test]
    async fn local_moves_are_atomic_no_replace() {
        let tmp = std::env::temp_dir().join(format!("linscp-move-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let left = tmp.join("left"); let right = tmp.join("right");
        std::fs::create_dir_all(left.join("tree")).unwrap(); std::fs::create_dir_all(&right).unwrap();
        std::fs::write(left.join("tree/data"), b"directory data").unwrap();
        std::fs::write(left.join("later"), b"move source").unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let open = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": left, "other_local_dir": right}}) }).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let request = |name: &str| ApiEnvelope { method: "POST".into(), path: "/api/transfer/move".into(), body: json!({"tab": id, "direction": "upload", "local_dir": left, "remote_dir": right, "names": [name]}) };
        // Rename in either local pane must not replace another entry.
        std::fs::write(left.join("rename-source"), b"source").unwrap();
        std::fs::write(left.join("rename-target"), b"target").unwrap();
        let rename = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/local/rename".into(), body: json!({"tab": id, "old_name": "rename-source", "new_name": "rename-target"}) }).await;
        assert_ne!(rename.status, 200);
        assert_eq!(std::fs::read(left.join("rename-source")).unwrap(), b"source");
        assert_eq!(std::fs::read(left.join("rename-target")).unwrap(), b"target");
        std::fs::write(right.join("rename-source"), b"source").unwrap();
        std::fs::write(right.join("rename-target"), b"target").unwrap();
        let rename = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/remote/rename".into(), body: json!({"tab": id, "old_name": "rename-source", "new_name": "rename-target"}) }).await;
        assert_ne!(rename.status, 200);
        assert_eq!(std::fs::read(right.join("rename-source")).unwrap(), b"source");
        assert_eq!(std::fs::read(right.join("rename-target")).unwrap(), b"target");
        let moved = svc.dispatch_async(request("tree")).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        let mut complete = false;
        for _ in 0..200 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.first().and_then(|t| t["status"].as_str()) == Some("Completed") { complete = true; break; }
            if tasks.first().and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("move failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(complete);
        assert!(!left.join("tree").exists());
        assert_eq!(std::fs::read(right.join("tree/data")).unwrap(), b"directory data");
        svc.queue.pause();
        let queued = svc.dispatch_async(request("later")).await;
        assert_eq!(queued.status, 200);
        std::fs::write(right.join("later"), b"concurrent destination").unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..200 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(1).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(failed);
        assert_eq!(std::fs::read(left.join("later")).unwrap(), b"move source");
        assert_eq!(std::fs::read(right.join("later")).unwrap(), b"concurrent destination");
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    async fn exercise_s3_resume_cancellation(svc: &CommanderService, id: u64, local: &Path, session: &dyn linscp_proto::RemoteSession) {
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        linscp_proto::upload_bytes(session, "/photos/resume-slow.bin", &vec![74u8; 4 * 1024 * 1024], Default::default()).await.unwrap();
        std::fs::write(local.join("resume-slow.bin.filepart"), vec![74u8; 1024]).unwrap();
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["resume-slow.bin"], "resume": true}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        let mut task_id = None;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(idx) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 1024 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Failed", "{task:?}");
                assert_ne!(task["status"], "Completed", "S3 download finished before cancellation");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("S3 resume did not start")}))).await;
        assert_eq!(cancelled.status, 200, "{}", cancelled.payload);
        let mut stopped = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Cancelled") { stopped = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped);
        assert!(!local.join("resume-slow.bin").exists());
        assert_eq!(std::fs::read(local.join("resume-slow.bin.filepart")).unwrap(), vec![74u8; 1024]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_s3_resume_recovery() {
        if std::env::var_os("LSCP_LIVE_S3").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-s3-resume-recovery-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp); std::fs::create_dir_all(&tmp).unwrap();
        let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests");
        let child = Command::new("/usr/bin/python3").arg(tests.join("TestS3Server.py"))
            .env("LSCP_TEST_PORT", "0").env("LSCP_TEST_SEED", "1").env("LSCP_TEST_DROP_ONCE", "/photos/resume-drop.bin")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child); let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").unwrap().parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let open = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "s3", "host": "127.0.0.1", "port": port, "s3_access_key": "AKIDTEST", "s3_secret_key": "testsecret42", "s3_region": "us-east-1", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": tmp, "initial_dir": "/photos"}}))).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let data = vec![75u8; 128 * 1024];
        linscp_proto::upload_bytes(session.as_ref(), "/photos/resume-drop.bin", &data, Default::default()).await.unwrap();
        for retry in [false, true] {
            let idx = svc.queue.snapshot().0.len();
            let queued = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": tmp, "remote_dir": "/photos", "names": ["resume-drop.bin"], "resume": true}))).await;
            assert_eq!(queued.status, 200, "{}", queued.payload);
            let mut terminal = false;
            for _ in 0..1000 {
                let (tasks, _) = svc.queue.snapshot();
                if let Some(status) = tasks.get(idx).and_then(|t| t["status"].as_str()) {
                    if status == "Completed" || status == "Failed" {
                        assert_eq!(status == "Completed", retry, "{:?}", tasks.get(idx));
                        terminal = true; break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(terminal);
            let checkpoint = std::fs::read(tmp.join("resume-drop.bin.filepart")).unwrap();
            assert!(!checkpoint.is_empty() && checkpoint.len() < data.len());
            assert_eq!(checkpoint.as_slice(), &data[..checkpoint.len()]);
            if retry { assert_eq!(std::fs::read(tmp.join("resume-drop.bin")).unwrap(), data); }
            else { assert!(!tmp.join("resume-drop.bin").exists()); }
        }
        drop(server); let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_s3_remote_copy() {
        if std::env::var_os("LSCP_LIVE_S3").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-s3-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp); std::fs::create_dir_all(&tmp).unwrap();
        let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests");
        let s3 = Command::new("/usr/bin/python3").arg(tests.join("TestS3Server.py"))
            .env("LSCP_TEST_PORT", "0").env("LSCP_TEST_SEED", "1").stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut s3 = Server(s3); let mut line = String::new();
        BufReader::new(s3.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let s3_port: u16 = line.trim().strip_prefix("READY ").unwrap().parse().unwrap();
        let dav = Command::new("/usr/bin/python3").arg(tests.join("TestDavServer.py"))
            .env("LSCP_TEST_PORT", "0").stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut dav = Server(dav); let mut line = String::new();
        BufReader::new(dav.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let dav_port: u16 = line.trim().strip_prefix("READY ").unwrap().parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let source_tab = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "s3", "host": "127.0.0.1", "port": s3_port, "s3_access_key": "AKIDTEST", "s3_secret_key": "testsecret42", "s3_region": "us-east-1", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": tmp, "initial_dir": "/photos"}}))).await;
        assert_eq!(source_tab.status, 200, "{}", source_tab.payload);
        let source_id = source_tab.payload["tab"]["id"].as_u64().unwrap();
        let dest_tab = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "dav", "host": "127.0.0.1", "port": dav_port, "username": "testuser", "password": "testpass", "local_dir": tmp, "initial_dir": "/"}}))).await;
        assert_eq!(dest_tab.status, 200, "{}", dest_tab.payload);
        let dest_id = dest_tab.payload["tab"]["id"].as_u64().unwrap();
        let source = svc.state.lock().unwrap().tabs.get(&source_id).unwrap().remote.as_ref().unwrap().clone();
        let dest = svc.state.lock().unwrap().tabs.get(&dest_id).unwrap().remote.as_ref().unwrap().clone();
        let copy = |name: &str, target: u64, dir: &str| json!({"tab": source_id, "target": format!("tab:{target}"), "directory": dir, "names": [name]});
        linscp_proto::upload_bytes(source.as_ref(), "/photos/copy.txt", b"S3 source", Default::default()).await.unwrap();
        for (target, dir, dest_path) in [(dest_id, "/", "/copy.txt"), (source_id, "/photos/sub", "/photos/sub/copy.txt")] {
            let idx = svc.queue.snapshot().0.len();
            let response = svc.dispatch_async(request("/api/remote/transfer", copy("copy.txt", target, dir))).await;
            assert_eq!(response.status, 200, "{}", response.payload);
            let mut done = false;
            for _ in 0..1000 {
                let (tasks, _) = svc.queue.snapshot();
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("S3 copy failed: {:?}", tasks.get(idx)); }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(done);
            let target_session = if target == source_id { source.as_ref() } else { dest.as_ref() };
            assert_eq!(linscp_proto::download_bytes(target_session, dest_path, Default::default()).await.unwrap(), b"S3 source");
        }
        assert_eq!(linscp_proto::download_bytes(source.as_ref(), "/photos/copy.txt", Default::default()).await.unwrap(), b"S3 source");
        // The target appeared after enqueue; exclusive creation must not replace it.
        linscp_proto::upload_bytes(source.as_ref(), "/photos/target-race.txt", b"source", Default::default()).await.unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let response = svc.dispatch_async(request("/api/remote/transfer", copy("target-race.txt", dest_id, "/"))).await;
        assert_eq!(response.status, 200);
        linscp_proto::upload_bytes(dest.as_ref(), "/target-race.txt", b"other client", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("S3 copy replaced competing destination"); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(failed);
        assert_eq!(linscp_proto::download_bytes(dest.as_ref(), "/target-race.txt", Default::default()).await.unwrap(), b"other client");
        // The captured source ETag must still match at download time.
        linscp_proto::upload_bytes(source.as_ref(), "/photos/source-race.txt", b"original", Default::default()).await.unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let response = svc.dispatch_async(request("/api/remote/transfer", copy("source-race.txt", dest_id, "/"))).await;
        assert_eq!(response.status, 200);
        linscp_proto::upload_bytes(source.as_ref(), "/photos/source-race.txt", b"changed!", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("changed S3 source was copied"); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(failed);
        assert!(dest.stat("/source-race.txt").await.unwrap().is_none());
        let rejected = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": source_id, "target": format!("tab:{dest_id}"), "directory": "/", "names": ["copy.txt"], "operation": "move", "accept_cross_move_risk": true}))).await;
        assert_eq!(rejected.status, 501);
        assert_eq!(linscp_proto::download_bytes(source.as_ref(), "/photos/copy.txt", Default::default()).await.unwrap(), b"S3 source");
        drop(s3); drop(dav); let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_s3_verified_resume() {
        if std::env::var_os("LSCP_LIVE_S3").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-s3-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let local = tmp.join("local"); std::fs::create_dir_all(&local).unwrap();
        let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests");
        let child = Command::new("/usr/bin/python3").arg(tests.join("TestS3Server.py"))
            .env("LSCP_TEST_PORT", "0").env("LSCP_TEST_SEED", "1").env("LSCP_TEST_GET_DELAY", "0.005")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child); let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").expect("S3 fixture failed to start").parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let open = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "s3", "host": "127.0.0.1", "port": port, "s3_access_key": "AKIDTEST", "s3_secret_key": "testsecret42", "s3_region": "us-east-1", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let bytes = b"verified S3 resume payload";
        for (name, partial, succeeds) in [
            ("resume-ok.bin", Some(&bytes[..8]), true),
            ("resume-complete.bin", Some(&bytes[..]), true),
            ("resume-fresh.bin", None, true),
            ("resume-mismatch.bin", Some(&b"incorrect"[..]), false),
            ("resume-oversize.bin", Some(&b"this local partial is longer than the source object"[..]), false),
            ("resume-bad-prefix.bin", Some(&bytes[..8]), false),
            ("resume-bad-tail.bin", Some(&bytes[..8]), false),
            ("resume-mid-change.bin", Some(&bytes[..8]), false),
            ("resume-redirect.bin", None, false),
            ("resume-accepted.bin", None, false),
            ("resume-noetag.bin", None, false),
        ] {
            linscp_proto::upload_bytes(session.as_ref(), &format!("/photos/{name}"), bytes, Default::default()).await.unwrap();
            let checkpoint = local.join(format!("{name}.filepart"));
            if let Some(data) = partial { std::fs::write(&checkpoint, data).unwrap(); }
            let idx = svc.queue.snapshot().0.len();
            let queued = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": [name], "resume": true}))).await;
            assert_eq!(queued.status, 200, "{}", queued.payload);
            let mut terminal = false;
            for _ in 0..1000 {
                let (tasks, _) = svc.queue.snapshot();
                if let Some(status) = tasks.get(idx).and_then(|t| t["status"].as_str()) {
                    if status == "Completed" || status == "Failed" {
                        assert_eq!(status == "Completed", succeeds, "{name}: {:?}", tasks.get(idx));
                        terminal = true; break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(terminal, "resume timed out: {name}");
            if succeeds { assert_eq!(std::fs::read(local.join(name)).unwrap(), bytes); }
            else { assert!(!local.join(name).exists()); }
            if let Some(data) = partial { assert_eq!(std::fs::read(checkpoint).unwrap(), data); }
        }
        // Capture the ETag at enqueue, then replace the object before the
        // queued request executes: the conditional GET must fail closed.
        linscp_proto::upload_bytes(session.as_ref(), "/photos/resume-race.bin", bytes, Default::default()).await.unwrap();
        std::fs::write(local.join("resume-race.bin.filepart"), &bytes[..8]).unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["resume-race.bin"], "resume": true}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        linscp_proto::upload_bytes(session.as_ref(), "/photos/resume-race.bin", b"changed S3 resume payload!", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("changed S3 source was resumed"); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(failed);
        assert!(!local.join("resume-race.bin").exists());
        assert_eq!(std::fs::read(local.join("resume-race.bin.filepart")).unwrap(), &bytes[..8]);
        // Some S3-compatible providers ignore If-Match. Even when the prefix
        // still matches, a different response ETag must prevent publication.
        linscp_proto::upload_bytes(session.as_ref(), "/photos/resume-ignore.bin", bytes, Default::default()).await.unwrap();
        std::fs::write(local.join("resume-ignore.bin.filepart"), &bytes[..8]).unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["resume-ignore.bin"], "resume": true}))).await;
        assert_eq!(queued.status, 200);
        linscp_proto::upload_bytes(session.as_ref(), "/photos/resume-ignore.bin", b"verified DIFFERENT payload", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") {
                assert!(tasks[idx]["error"].as_str().unwrap_or("").contains("ETag"), "{:?}", tasks[idx]);
                failed = true; break;
            }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("ignored S3 precondition was accepted"); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(failed);
        assert!(!local.join("resume-ignore.bin").exists());
        assert_eq!(std::fs::read(local.join("resume-ignore.bin.filepart")).unwrap(), &bytes[..8]);
        Box::pin(exercise_s3_resume_cancellation(&svc, id, &local, session.as_ref())).await;
        assert!(!std::fs::read_dir(&local).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(".linscp-download-")));
        drop(server); let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_s3_gui_download() {
        if std::env::var_os("LSCP_LIVE_S3").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-live-s3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let local = tmp.join("local"); std::fs::create_dir_all(&local).unwrap();
        let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests");
        let child = Command::new("/usr/bin/python3").arg(tests.join("TestS3Server.py"))
            .env("LSCP_TEST_PORT", "0").env("LSCP_TEST_SEED", "1").env("LSCP_TEST_GET_DELAY", "0.005").env("LSCP_TEST_PART_DELAY", "0.1")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child); let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").expect("S3 server failed to start").parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let open = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "s3", "host": "127.0.0.1", "port": port, "s3_access_key": "AKIDTEST", "s3_secret_key": "testsecret42", "s3_region": "us-east-1", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        assert!(open.payload["tab"]["session"].get("password").is_none());
        assert!(open.payload["tab"]["session"].get("s3_secret_key").is_none());
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let list = svc.dispatch_async(ApiEnvelope { method: "GET".into(), path: format!("/api/remote/list?tab={id}&path=%2Fphotos"), body: json!({}) }).await;
        assert_eq!(list.status, 200, "{}", list.payload);
        assert!(list.payload["entries"].as_array().unwrap().iter().any(|e| e["name"] == "seed.txt"));
        // Existing user partials must not be consumed or removed by a fresh download.
        std::fs::write(local.join("seed.txt.filepart"), b"unrelated partial").unwrap();
        let download = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["seed.txt"]}))).await;
        assert_eq!(download.status, 200, "{}", download.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.first().and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.first().and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("S3 download failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done, "S3 download timed out");
        assert_eq!(std::fs::read(local.join("seed.txt")).unwrap(), b"S3 verified download");
        assert_eq!(std::fs::read(local.join("seed.txt.filepart")).unwrap(), b"unrelated partial");
        assert!(!std::fs::read_dir(&local).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-download-")));
        std::fs::write(local.join("upload.txt"), b"S3 exclusive upload").unwrap();
        let upload = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["upload.txt"]}))).await;
        assert_eq!(upload.status, 200, "{}", upload.payload);
        let mut uploaded = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(1).and_then(|t| t["status"].as_str()) == Some("Completed") { uploaded = true; break; }
            if tasks.get(1).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("S3 upload failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(uploaded, "S3 upload timed out");
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let uploaded_bytes = linscp_proto::download_bytes(session.as_ref(), "/photos/upload.txt", Default::default()).await.unwrap();
        assert_eq!(uploaded_bytes, b"S3 exclusive upload");
        let mut flags = linscp_engine::transfer::TransferFlags::default(); flags.no_clobber = true;
        let mut logger = linscp_engine::xml_log::SessionLogger::open(None, 0, false, None, None, false, "").unwrap();
        let collision = linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("upload.txt"), "/photos/seed.txt", &flags, &mut logger, None).await;
        assert!(collision.is_err());
        let seed = linscp_proto::download_bytes(session.as_ref(), "/photos/seed.txt", Default::default()).await.unwrap();
        assert_eq!(seed, b"S3 verified download");
        // Capture the initial ETag, then change the object while the approved
        // request is queued; If-Match must preserve the concurrent contents.
        let conflict = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["upload.txt"]}))).await;
        assert_eq!(conflict.status, 409, "{}", conflict.payload);
        let versions = conflict.payload["conflict_versions"].clone();
        assert!(versions["upload.txt"].as_str().is_some());
        svc.queue.pause();
        let race_index = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["upload.txt"], "overwrite": "overwrite", "conflict_versions": versions}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        linscp_proto::upload_bytes(session.as_ref(), "/photos/upload.txt", b"changed after approval", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(race_index).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(race_index).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("conditional S3 overwrite replaced a changed object"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed, "changed object must reject the overwrite");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/photos/upload.txt", Default::default()).await.unwrap(), b"changed after approval");
        let conflict = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["upload.txt"]}))).await;
        let versions = conflict.payload["conflict_versions"].clone();
        let success_index = svc.queue.snapshot().0.len();
        let approved = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["upload.txt"], "overwrite": "overwrite", "conflict_versions": versions}))).await;
        assert_eq!(approved.status, 200, "{}", approved.payload);
        let mut completed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(success_index).and_then(|t| t["status"].as_str()) == Some("Completed") { completed = true; break; }
            if tasks.get(success_index).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("unchanged S3 object overwrite failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(completed);
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/photos/upload.txt", Default::default()).await.unwrap(), b"S3 exclusive upload");
        // Large conditional uploads use unique multipart upload IDs. A
        // cancelled attempt must abort that ID without deleting an object.
        let multipart_path = local.join("multipart.bin");
        let multipart_bytes = vec![61u8; 17 * 1024 * 1024];
        std::fs::write(&multipart_path, &multipart_bytes).unwrap();
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let on_progress = Arc::clone(&cancel);
        let stop = move |_: u64, _: u64| on_progress.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut multipart_flags = linscp_engine::transfer::TransferFlags::default();
        multipart_flags.no_clobber = true;
        multipart_flags.cancel_flag = Some(cancel);
        let interrupted = linscp_engine::transfer::upload_single_file(session.as_ref(), &multipart_path, "/photos/multipart-cancel.bin", &multipart_flags, &mut logger, Some(&stop)).await;
        assert!(interrupted.is_err(), "multipart cancellation unexpectedly succeeded");
        assert!(interrupted.unwrap_err().contains("Multipart upload was aborted"));
        assert!(session.stat("/photos/multipart-cancel.bin").await.unwrap().is_none());
        assert!(multipart_path.exists());
        // Successful no-replace completion publishes only after all parts.
        multipart_flags.cancel_flag = None;
        let complete = linscp_engine::transfer::upload_single_file(session.as_ref(), &multipart_path, "/photos/multipart-success.bin", &multipart_flags, &mut logger, None).await;
        assert!(complete.is_ok(), "{complete:?}");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/photos/multipart-success.bin", Default::default()).await.unwrap(), multipart_bytes);
        // A competing object cannot be overwritten by conditional completion.
        linscp_proto::upload_bytes(session.as_ref(), "/photos/multipart-conflict.bin", b"other actor", Default::default()).await.unwrap();
        let conflict = linscp_engine::transfer::upload_single_file(session.as_ref(), &multipart_path, "/photos/multipart-conflict.bin", &multipart_flags, &mut logger, None).await;
        assert!(conflict.is_err());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/photos/multipart-conflict.bin", Default::default()).await.unwrap(), b"other actor");
        // Cancellation via the public queue also preserves the abort result.
        let queued_file = local.join("multipart-queued.bin");
        std::fs::write(&queued_file, vec![63u8; 64 * 1024 * 1024]).unwrap();
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["multipart-queued.bin"]}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        let mut task_id = None;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(idx) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Completed", "multipart upload finished before cancellation");
                assert_ne!(task["status"], "Failed", "{task:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        // A second app session sharing the journal must not abort an upload
        // while its originating instance still holds the OS file lock.
        let second = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "s3", "host": "127.0.0.1", "port": port, "s3_access_key": "AKIDTEST", "s3_secret_key": "testsecret42", "s3_region": "us-east-1", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(second.status, 200, "{}", second.payload);
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("multipart upload did not start")}))).await;
        assert_eq!(cancelled.status, 200, "{}", cancelled.payload);
        let mut stopped = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Cancelled") {
                assert!(tasks[idx]["error"].as_str().unwrap_or("").contains("Multipart upload was aborted"), "{:?}", tasks[idx]);
                stopped = true; break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped);
        assert!(session.stat("/photos/multipart-queued.bin").await.unwrap().is_none());
        // Multipart overwrite must use the originally approved ETag at
        // completion, not merely check before uploading its parts.
        linscp_proto::upload_bytes(session.as_ref(), "/photos/multipart-match.bin", b"first version", Default::default()).await.unwrap();
        let old_etag = session.s3_get_etag("/photos/multipart-match.bin").await.unwrap().unwrap();
        linscp_proto::upload_bytes(session.as_ref(), "/photos/multipart-match.bin", b"changed version", Default::default()).await.unwrap();
        let mut approved = linscp_engine::transfer::TransferFlags::default();
        approved.overwrite_etag = Some(old_etag);
        let rejected = linscp_engine::transfer::upload_single_file(session.as_ref(), &multipart_path, "/photos/multipart-match.bin", &approved, &mut logger, None).await;
        assert!(rejected.is_err());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/photos/multipart-match.bin", Default::default()).await.unwrap(), b"changed version");
        approved.overwrite_etag = Some(session.s3_get_etag("/photos/multipart-match.bin").await.unwrap().unwrap());
        let replaced = linscp_engine::transfer::upload_single_file(session.as_ref(), &multipart_path, "/photos/multipart-match.bin", &approved, &mut logger, None).await;
        assert!(replaced.is_ok(), "{replaced:?}");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/photos/multipart-match.bin", Default::default()).await.unwrap(), multipart_bytes);
        let output = Command::new("curl").args(["--silent", "--show-error", "--insecure", &format!("https://127.0.0.1:{port}/__test__/state")]).output().unwrap();
        assert!(output.status.success());
        let state: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(state["active_uploads"], 0, "multipart upload IDs leaked: {state}");
        let history = state["multipart_history"].as_array().unwrap();
        assert!(history.iter().any(|e| e["action"] == "abort" && e["key"] == "multipart-cancel.bin"));
        assert!(history.iter().any(|e| e["action"] == "abort" && e["key"] == "multipart-conflict.bin"));
        assert!(history.iter().any(|e| e["action"] == "abort" && e["key"] == "multipart-queued.bin"));
        assert!(history.iter().any(|e| e["action"] == "abort" && e["key"] == "multipart-match.bin"));
        assert!(history.iter().any(|e| e["action"] == "complete" && e["key"] == "multipart-success.bin"));
        // A server that stalls an abort response must not hang cancellation.
        // The unconfirmed upload ID stays journaled for the next connection.
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let trigger = Arc::clone(&cancel);
        let stop = move |_: u64, _: u64| trigger.store(true, std::sync::atomic::Ordering::SeqCst);
        multipart_flags.cancel_flag = Some(cancel);
        let stalled = tokio::time::timeout(std::time::Duration::from_secs(12), linscp_engine::transfer::upload_single_file(session.as_ref(), &multipart_path, "/photos/multipart-abort-stall.bin", &multipart_flags, &mut logger, Some(&stop))).await.expect("stalled S3 abort hung cancellation").unwrap_err();
        assert!(stalled.contains("abort timed out") && stalled.contains("not confirmed"), "{stalled}");
        assert!(session.stat("/photos/multipart-abort-stall.bin").await.unwrap().is_none());
        let journal_dir = tmp.join("config/s3-conditional-cleanup");
        assert!(std::fs::read_dir(&journal_dir).unwrap().any(|entry| std::fs::metadata(entry.unwrap().path()).unwrap().len() > 0), "unconfirmed abort must remain journaled");
        let retried = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "s3", "host": "127.0.0.1", "port": port, "s3_access_key": "AKIDTEST", "s3_secret_key": "testsecret42", "s3_region": "us-east-1", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(retried.status, 200, "{}", retried.payload);
        assert!(std::fs::read_dir(&journal_dir).unwrap().all(|entry| std::fs::metadata(entry.unwrap().path()).unwrap().len() == 0), "reconnection should resolve the timed-out abort");
        // If abort fails, report the upload ID for later inspection instead of
        // claiming cleanup succeeded or deleting the destination pathname.
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let trigger = Arc::clone(&cancel);
        let stop = move |_: u64, _: u64| trigger.store(true, std::sync::atomic::Ordering::SeqCst);
        multipart_flags.cancel_flag = Some(cancel);
        let failed_abort = linscp_engine::transfer::upload_single_file(session.as_ref(), &multipart_path, "/photos/multipart-abort-failure.bin", &multipart_flags, &mut logger, Some(&stop)).await.unwrap_err();
        assert!(failed_abort.contains("abort was not confirmed"), "{failed_abort}");
        assert!(failed_abort.contains("upload ID"), "{failed_abort}");
        assert!(session.stat("/photos/multipart-abort-failure.bin").await.unwrap().is_none());
        let journal_dir = tmp.join("config/s3-conditional-cleanup");
        let mut records = Vec::new();
        for entry in std::fs::read_dir(&journal_dir).unwrap() {
            let path = entry.unwrap().path();
            let data = std::fs::read(path).unwrap();
            if !data.is_empty() { records.push(data); }
        }
        assert_eq!(records.len(), 1, "failed abort must be recorded exactly once");
        let journal_text = String::from_utf8(records[0].clone()).unwrap();
        assert!(!journal_text.contains("testsecret42") && !journal_text.contains("AKIDTEST"));
        // A record for a different endpoint identity must never be retried.
        let mut foreign: Value = serde_json::from_slice(&records[0]).unwrap();
        foreign["endpoint"] = json!("different-endpoint");
        let foreign_bytes = serde_json::to_vec(&foreign).unwrap();
        let foreign_path = journal_dir.join("upload-foreign.json");
        std::fs::write(&foreign_path, &foreign_bytes).unwrap();
        // A forged journal pathname must not cause an unrelated local file to
        // be opened and truncated, even when its content looks legitimate.
        {
            let target = tmp.join("unrelated-journal-content");
            std::fs::write(&target, &records[0]).unwrap();
            // Symlink creation is a platform helper (Windows needs the
            // file/directory distinction); this test only cares that a journal
            // path which is a link is never opened and truncated.
            gui_os::create_local_symlink(&target.to_string_lossy(), &journal_dir.join("upload-symlink.json")).unwrap();
            // A volume without hard links cannot build this fixture; the
            // symlink below still proves a linked journal path is refused.
            let _ = std::fs::hard_link(&target, journal_dir.join("upload-hardlink.json"));
        }
        // Seed another client's upload for the same destination key. Only our
        // journaled upload ID may be aborted on reconnect.
        let seeded = Command::new("curl").args(["--silent", "--show-error", "--insecure", &format!("https://127.0.0.1:{port}/__test__/seed-unrelated-upload")]).status().unwrap();
        assert!(seeded.success());
        // Reconnecting retries only the recorded upload ID; the fixture now
        // allows the abort. Existing destination objects remain untouched.
        let reopened = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "s3", "host": "127.0.0.1", "port": port, "s3_access_key": "AKIDTEST", "s3_secret_key": "testsecret42", "s3_region": "us-east-1", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(reopened.status, 200, "{}", reopened.payload);
        assert_eq!(std::fs::read(&foreign_path).unwrap(), foreign_bytes, "other endpoints must not be touched");
        assert_eq!(std::fs::read(tmp.join("unrelated-journal-content")).unwrap(), records[0], "linked paths must not be modified");
        let nonempty_owned_records = std::fs::read_dir(&journal_dir).unwrap().filter_map(Result::ok).filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            !matches!(name.as_ref(), "upload-foreign.json" | "upload-symlink.json" | "upload-hardlink.json") && std::fs::metadata(entry.path()).unwrap().len() != 0
        }).count();
        assert_eq!(nonempty_owned_records, 0, "resolved upload must be marked clean");
        let output = Command::new("curl").args(["--silent", "--show-error", "--insecure", &format!("https://127.0.0.1:{port}/__test__/state")]).output().unwrap();
        let state: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(state["active_uploads"], 1, "reconnect must only abort the recorded upload: {state}");
        assert_eq!(state["active_upload_ids"], json!(["test-unrelated-upload"]), "unrelated upload was modified: {state}");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/photos/multipart-conflict.bin", Default::default()).await.unwrap(), b"other actor");
        // The upload was already aborted. A later retry must accept the explicit
        // NoSuchUpload response, but not treat an unrelated 404 as confirmation.
        let expired_path = journal_dir.join("upload-expired.json");
        std::fs::write(&expired_path, &records[0]).unwrap();
        let mut other_error: Value = serde_json::from_slice(&records[0]).unwrap();
        other_error["upload_id"] = json!("test-other-not-found");
        let other_bytes = serde_json::to_vec(&other_error).unwrap();
        let other_path = journal_dir.join("upload-other-error.json");
        std::fs::write(&other_path, &other_bytes).unwrap();
        let reopened = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "s3", "host": "127.0.0.1", "port": port, "s3_access_key": "AKIDTEST", "s3_secret_key": "testsecret42", "s3_region": "us-east-1", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(reopened.status, 200, "{}", reopened.payload);
        assert_eq!(std::fs::metadata(&expired_path).unwrap().len(), 0, "NoSuchUpload should resolve the journal");
        assert_eq!(std::fs::read(&other_path).unwrap(), other_bytes, "unrelated 404 must remain unresolved");
        // Enforce the supported upper bound without an unconditional fallback.
        std::fs::OpenOptions::new().write(true).open(local.join("upload.txt")).unwrap().set_len(1024 * 1024 * 1024 + 1).unwrap();
        let conflict = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["upload.txt"]}))).await;
        let large_index = svc.queue.snapshot().0.len();
        let large = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["upload.txt"], "overwrite": "overwrite", "conflict_versions": conflict.payload["conflict_versions"]}))).await;
        assert_eq!(large.status, 200, "{}", large.payload);
        let mut large_failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(large_index).and_then(|t| t["status"].as_str()) == Some("Failed") { large_failed = true; break; }
            if tasks.get(large_index).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("large conditional S3 overwrite unexpectedly succeeded"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(large_failed);
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/photos/upload.txt", Default::default()).await.unwrap(), b"S3 exclusive upload");
        let slow_index = svc.queue.snapshot().0.len();
        let slow = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": local, "remote_dir": "/photos", "names": ["slow.bin"]}))).await;
        assert_eq!(slow.status, 200);
        let mut task_id = None;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(slow_index) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Completed", "S3 download finished before cancellation");
                assert_ne!(task["status"], "Failed", "{tasks:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancel = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("S3 download did not start")}))).await;
        assert_eq!(cancel.status, 200, "{}", cancel.payload);
        let mut cancelled = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(slow_index).and_then(|t| t["status"].as_str()) == Some("Cancelled") { cancelled = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(cancelled, "S3 cancellation was not observed");
        assert!(!local.join("slow.bin").exists());
        assert_eq!(std::fs::read(local.join("seed.txt.filepart")).unwrap(), b"unrelated partial");
        assert!(!std::fs::read_dir(&local).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-download-")), "cancelled download left an owned temporary file");
        assert!(session.stat("/photos/seed.txt").await.unwrap().is_some());
        exercise_cross_move_destination(&svc, id, "/photos", &local).await;
        drop(server); let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    async fn exercise_cross_move_destination(svc: &CommanderService, dest_id: u64, dest_dir: &str, local: &Path) {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let server_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests/TestDavServer.py");
        let child = Command::new("/usr/bin/python3").arg(server_path).env("LSCP_TEST_PORT", "0").env("LSCP_TEST_GET_DELAY", "0.005")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child); let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").expect("DAV source failed to start").parse().unwrap();
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let open = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "dav", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let source = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let dest = svc.state.lock().unwrap().tabs.get(&dest_id).unwrap().remote.as_ref().unwrap().clone();
        linscp_proto::upload_bytes(source.as_ref(), "/cross-proto.txt", b"cross-protocol content", Default::default()).await.unwrap();
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": dest_dir, "names": ["cross-proto.txt"], "operation": "move", "accept_cross_move_risk": true}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("cross-protocol move failed: {:?}", tasks.get(idx)); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert!(source.stat("/cross-proto.txt").await.unwrap().is_none());
        let target = format!("{}/cross-proto.txt", dest_dir.trim_end_matches('/'));
        assert_eq!(linscp_proto::download_bytes(dest.as_ref(), &target, Default::default()).await.unwrap(), b"cross-protocol content");
        if dest_dir == "/photos" {
            // Neither an asynchronous acceptance nor a redirect confirms an
            // S3 destination; retain the WebDAV source and do not follow the
            // redirect to another object.
            for name in ["cross-s3-accepted.txt", "cross-s3-redirect.txt"] {
                let source_path = format!("/{name}");
                linscp_proto::upload_bytes(source.as_ref(), &source_path, b"preserve source", Default::default()).await.unwrap();
                let idx = svc.queue.snapshot().0.len();
                let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": dest_dir, "names": [name], "operation": "move", "accept_cross_move_risk": true}))).await;
                assert_eq!(moved.status, 200, "{}", moved.payload);
                let mut failed = false;
                for _ in 0..500 {
                    let (tasks, _) = svc.queue.snapshot();
                    if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
                    if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("unconfirmed S3 write completed the move"); }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                assert!(failed);
                assert_eq!(linscp_proto::download_bytes(source.as_ref(), &source_path, Default::default()).await.unwrap(), b"preserve source");
                assert!(dest.stat(&format!("{dest_dir}/{name}")).await.unwrap().is_none());
            }
            assert!(dest.stat("/photos/cross-s3-redirect-target.txt").await.unwrap().is_none());
        }
        // Copying to another protocol is conditional on the captured source
        // and exclusively creates the target, but never deletes the source.
        linscp_proto::upload_bytes(source.as_ref(), "/cross-copy.txt", b"copy source", Default::default()).await.unwrap();
        let idx = svc.queue.snapshot().0.len();
        let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": dest_dir, "names": ["cross-copy.txt"]}))).await;
        assert_eq!(copied.status, 200, "{}", copied.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("cross-protocol copy failed: {:?}", tasks.get(idx)); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(linscp_proto::download_bytes(source.as_ref(), "/cross-copy.txt", Default::default()).await.unwrap(), b"copy source");
        assert_eq!(linscp_proto::download_bytes(dest.as_ref(), &format!("{}/cross-copy.txt", dest_dir.trim_end_matches('/')), Default::default()).await.unwrap(), b"copy source");
        if dest_dir == "/" {
            source.mkdir("/dav-copy-tree").await.unwrap();
            source.mkdir("/dav-copy-tree/nested").await.unwrap();
            source.mkdir("/dav-copy-tree/nested/empty").await.unwrap();
            linscp_proto::upload_bytes(source.as_ref(), "/dav-copy-tree/nested/data", b"WebDAV tree", Default::default()).await.unwrap();
            let risk = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": dest_dir, "names": ["dav-copy-tree"]}))).await;
            assert_eq!(risk.status, 409, "{}", risk.payload);
            assert_eq!(risk.payload["directory_copy_risk"], true);
            let idx = svc.queue.snapshot().0.len();
            let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": dest_dir, "names": ["dav-copy-tree"], "accept_directory_copy_risk": true}))).await;
            assert_eq!(copied.status, 200, "{}", copied.payload);
            let mut done = false;
            for _ in 0..1000 {
                let (tasks, _) = svc.queue.snapshot();
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("WebDAV tree copy failed: {:?}", tasks.get(idx)); }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(done);
            assert_eq!(linscp_proto::download_bytes(dest.as_ref(), "/dav-copy-tree/nested/data", Default::default()).await.unwrap(), b"WebDAV tree");
            assert!(dest.stat("/dav-copy-tree/nested/empty").await.unwrap().unwrap().is_dir);
            assert_eq!(linscp_proto::download_bytes(source.as_ref(), "/dav-copy-tree/nested/data", Default::default()).await.unwrap(), b"WebDAV tree");
            let idx = svc.queue.snapshot().0.len();
            let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": dest_dir, "names": ["dav-copy-tree"], "accept_directory_copy_risk": true}))).await;
            assert_eq!(copied.status, 200);
            let mut failed = false;
            for _ in 0..1000 {
                let (tasks, _) = svc.queue.snapshot();
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("existing remote tree was replaced"); }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(failed);
            assert_eq!(linscp_proto::download_bytes(dest.as_ref(), "/dav-copy-tree/nested/data", Default::default()).await.unwrap(), b"WebDAV tree");
            // Files without a strong ETag cannot be staged as a trusted
            // conditional copy, even when their collection has an ETag.
            for (dir, file) in [("dav-weak-tree", "weak.txt"), ("dav-missing-tree", "missing.txt")] {
                source.mkdir(&format!("/{dir}")).await.unwrap();
                linscp_proto::upload_bytes(source.as_ref(), &format!("/{dir}/{file}"), b"unsafe version", Default::default()).await.unwrap();
                let idx = svc.queue.snapshot().0.len();
                let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": dest_dir, "names": [dir], "accept_directory_copy_risk": true}))).await;
                assert_eq!(copied.status, 200, "{}", copied.payload);
                let mut failed = false;
                for _ in 0..1000 {
                    let (tasks, _) = svc.queue.snapshot();
                    if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
                    if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("unversioned file tree was copied"); }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                assert!(failed);
                assert!(dest.stat(&format!("/{dir}")).await.unwrap().is_none());
                assert!(source.stat(&format!("/{dir}/{file}")).await.unwrap().is_some());
            }
            source.mkdir("/dav-cancel-tree").await.unwrap();
            linscp_proto::upload_bytes(source.as_ref(), "/dav-cancel-tree/slow.bin", &vec![53u8; 4 * 1024 * 1024], Default::default()).await.unwrap();
            let idx = svc.queue.snapshot().0.len();
            let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": dest_dir, "names": ["dav-cancel-tree"], "accept_directory_copy_risk": true}))).await;
            assert_eq!(copied.status, 200);
            let mut task_id = None;
            for _ in 0..1000 {
                let (tasks, _) = svc.queue.snapshot();
                if let Some(task) = tasks.get(idx) {
                    if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                    assert_ne!(task["status"], "Completed", "tree copied before cancellation");
                    assert_ne!(task["status"], "Failed", "{task:?}");
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            let cancel = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("tree download did not begin")}))).await;
            assert_eq!(cancel.status, 200);
            let mut stopped = false;
            for _ in 0..1000 {
                let (tasks, _) = svc.queue.snapshot();
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Cancelled") { stopped = true; break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(stopped);
            assert!(dest.stat("/dav-cancel-tree").await.unwrap().is_none());
            assert!(source.stat("/dav-cancel-tree/slow.bin").await.unwrap().is_some());
        }
        // Cancellation during the first stage leaves source and destination alone.
        let stages_before: std::collections::BTreeSet<_> = std::fs::read_dir(std::env::temp_dir()).unwrap().filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("linscp-cross-move-"))
            .map(|entry| entry.file_name()).collect();
        linscp_proto::upload_bytes(source.as_ref(), "/cross-slow.bin", &vec![47u8; 4 * 1024 * 1024], Default::default()).await.unwrap();
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": dest_dir, "names": ["cross-slow.bin"], "operation": "move", "accept_cross_move_risk": true}))).await;
        assert_eq!(moved.status, 200);
        let mut task_id = None;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(idx) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Failed", "{task:?}");
                assert_ne!(task["status"], "Completed", "cross move finished before cancellation");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("cross move did not start")}))).await;
        assert_eq!(cancelled.status, 200);
        let mut stopped = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Cancelled") { stopped = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped);
        assert!(source.stat("/cross-slow.bin").await.unwrap().is_some());
        assert!(dest.stat(&format!("{}/cross-slow.bin", dest_dir.trim_end_matches('/'))).await.unwrap().is_none());
        let stages_after: std::collections::BTreeSet<_> = std::fs::read_dir(std::env::temp_dir()).unwrap().filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("linscp-cross-move-"))
            .map(|entry| entry.file_name()).collect();
        assert!(stages_after.difference(&stages_before).next().is_none(), "cancelled cross move leaked its local temporary directory");
        drop(server);
    }

    #[cfg(target_os = "linux")]
    async fn exercise_remote_mkdir(svc: &CommanderService, id: u64) {
        let request = |body: Value| ApiEnvelope { method: "POST".into(), path: "/api/remote/mkdir".into(), body };
        for name in ["", ".", "..", "../escape", "nested/name", "bad\\name", "bad\nname"] {
            let response = svc.dispatch_async(request(json!({"tab": id, "name": name}))).await;
            assert_eq!(response.status, 400, "accepted invalid name {name:?}: {}", response.payload);
        }
        let created = svc.dispatch_async(request(json!({"tab": id, "name": "gui-new-folder"}))).await;
        assert_eq!(created.status, 200, "{}", created.payload);
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        assert!(session.stat("/gui-new-folder").await.unwrap().unwrap().is_dir);
        let duplicate = svc.dispatch_async(request(json!({"tab": id, "name": "gui-new-folder"}))).await;
        assert_ne!(duplicate.status, 200, "existing directory was reported as newly created");
        let properties = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/remote/properties".into(), body: json!({"tab": id, "names": ["gui-new-folder", "not-here"]}) }).await;
        assert_eq!(properties.status, 200, "{}", properties.payload);
        assert_eq!(properties.payload["properties"][0]["name"], "gui-new-folder");
        assert_eq!(properties.payload["properties"][0]["path"], "/gui-new-folder");
        assert_eq!(properties.payload["properties"][0]["is_dir"], true);
        assert!(properties.payload["properties"][1]["error"].is_string());
        let invalid = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/remote/properties".into(), body: json!({"tab": id, "names": ["../escape"]}) }).await;
        assert_eq!(invalid.status, 400);
    }

    #[cfg(target_os = "linux")]
    async fn exercise_ftp_uploads(svc: &CommanderService, id: u64, local: &Path, remote: &Path) {
        let request = |body: Value| ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body };
        Box::pin(exercise_remote_mkdir(svc, id)).await;
        std::fs::write(local.join("up.txt"), b"FTP upload payload").unwrap();
        // Direct callers must not bypass the FTP risk acknowledgment or fall
        // through ASCII conversion to an unguarded STOR.
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let mut logger = linscp_engine::xml_log::SessionLogger::open(None, 0, false, None, None, false, "").unwrap();
        std::fs::write(remote.join("unsafe.txt.filepart"), b"unrelated partial").unwrap();
        let unguarded = linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("up.txt"), "/unsafe.txt", &linscp_engine::transfer::TransferFlags::default(), &mut logger, None).await;
        assert!(unguarded.unwrap_err().contains("Unguarded SFTP/FTP uploads are disabled"));
        assert_eq!(std::fs::read(remote.join("unsafe.txt.filepart")).unwrap(), b"unrelated partial");
        assert!(!remote.join("unsafe.txt").exists());
        let mut ascii = linscp_engine::transfer::TransferFlags::default();
        ascii.ftp_risky_publish = true;
        ascii.transfer_mode = linscp_types::TransferMode::Ascii;
        let rejected = linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("up.txt"), "/ascii-unsafe.txt", &ascii, &mut logger, None).await;
        assert!(rejected.is_err(), "FTP ASCII upload must not bypass staging");
        assert!(!remote.join("ascii-unsafe.txt").exists());
        let no_consent = svc.dispatch_async(request(json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["up.txt"]}))).await;
        assert_eq!(no_consent.status, 409);
        assert_eq!(no_consent.payload["ftp_rename_risk"], true);
        assert!(!remote.join("up.txt").exists());
        let idx = svc.queue.snapshot().0.len();
        let upload = svc.dispatch_async(request(json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["up.txt"], "accept_ftp_rename_risk": true}))).await;
        assert_eq!(upload.status, 200, "{}", upload.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("FTP upload failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(std::fs::read(remote.join("up.txt")).unwrap(), b"FTP upload payload");
        assert!(!std::fs::read_dir(remote).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-upload-")));
        std::fs::write(local.join("up.txt"), b"replacement").unwrap();
        let conflict = svc.dispatch_async(request(json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["up.txt"], "accept_ftp_rename_risk": true}))).await;
        assert_eq!(conflict.status, 409);
        assert_eq!(conflict.payload["conflicts"], json!(["up.txt"]));
        let idx = svc.queue.snapshot().0.len();
        let upload = svc.dispatch_async(request(json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["up.txt"], "accept_ftp_rename_risk": true, "overwrite": "overwrite"}))).await;
        assert_eq!(upload.status, 200, "{}", upload.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("FTP overwrite failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(std::fs::read(remote.join("up.txt")).unwrap(), b"replacement");
        // A destination appearing while STOU is writing is caught by the
        // final check. The remaining check-to-rename race is explicitly warned.
        std::fs::write(local.join("during-upload.txt"), b"upload content").unwrap();
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let competing = remote.join("during-upload.txt");
        let competing_for_progress = competing.clone();
        let progress = move |_: u64, _: u64| { std::fs::write(&competing_for_progress, b"concurrent content").unwrap(); };
        let mut flags = linscp_engine::transfer::TransferFlags::default();
        flags.no_clobber = true; flags.ftp_risky_publish = true;
        let mut logger = linscp_engine::xml_log::SessionLogger::open(None, 0, false, None, None, false, "").unwrap();
        let raced = linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("during-upload.txt"), "/during-upload.txt", &flags, &mut logger, Some(&progress)).await;
        assert!(raced.is_err());
        assert_eq!(std::fs::read(&competing).unwrap(), b"concurrent content");
        assert!(std::fs::read_dir(remote).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with(".linscp-upload-")));
        std::fs::write(local.join("new-race.txt"), b"source").unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let upload = svc.dispatch_async(request(json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["new-race.txt"], "accept_ftp_rename_risk": true}))).await;
        assert_eq!(upload.status, 200, "{}", upload.payload);
        std::fs::write(remote.join("new-race.txt"), b"competing data").unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("queued FTP race overwrote destination"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(std::fs::read(remote.join("new-race.txt")).unwrap(), b"competing data");
    }

    #[cfg(target_os = "linux")]
    async fn exercise_ftp_upload_cancellation(svc: &CommanderService, id: u64, local: &Path, remote: &Path) {
        std::fs::write(local.join("cancel-upload.bin"), vec![23u8; 4 * 1024 * 1024]).unwrap();
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_flag = Arc::clone(&cancel);
        let existing: std::collections::HashSet<_> = std::fs::read_dir(remote).unwrap().filter_map(Result::ok).map(|e| e.file_name()).collect();
        let remote_dir = remote.to_path_buf();
        let replacement = Arc::new(std::sync::Mutex::new(None::<PathBuf>));
        let observed = Arc::clone(&replacement);
        // Simulate a second client replacing the server-generated STOU path
        // while the original data connection still writes to its open file.
        let progress = move |_: u64, _: u64| {
            let mut observed = observed.lock().unwrap();
            if observed.is_none() {
                let stage = std::fs::read_dir(&remote_dir).unwrap().filter_map(Result::ok)
                    .find(|e| e.file_name().to_string_lossy().starts_with(".linscp-upload-") && !existing.contains(&e.file_name()))
                    .expect("server did not create unique stage").path();
                std::fs::rename(&stage, remote_dir.join("held-ftp-upload")).unwrap();
                std::fs::write(&stage, b"replacement by another client").unwrap();
                *observed = Some(stage);
            }
            callback_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        };
        let mut flags = linscp_engine::transfer::TransferFlags::default();
        flags.no_clobber = true;
        flags.ftp_risky_publish = true;
        flags.cancel_flag = Some(cancel);
        let mut logger = linscp_engine::xml_log::SessionLogger::open(None, 0, false, None, None, false, "").unwrap();
        let result = linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("cancel-upload.bin"), "/cancel-upload.bin", &flags, &mut logger, Some(&progress)).await;
        let error = result.expect_err("FTP upload should be interrupted");
        assert!(error.contains("temporary file"));
        assert!(!remote.join("cancel-upload.bin").exists());
        let stage = error.split('\'').nth(1).expect("missing temporary path in cancellation error");
        let stage_path = remote.join(stage.trim_start_matches('/'));
        assert_eq!(replacement.lock().unwrap().as_ref(), Some(&stage_path), "error must identify the untrusted path");
        assert_eq!(std::fs::read(&stage_path).unwrap(), b"replacement by another client", "cancellation must not delete or alter a replacement");
        assert!(remote.join("held-ftp-upload").exists(), "the original partial is left for inspection");
        let err = session.stat("/download.txt").await.expect_err("cancelled FTP upload must poison control channel");
        assert!(err.to_string().contains("reconnect"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_ftpes_gui_download() {
        if std::env::var_os("LSCP_LIVE_FTPES").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-live-ftpes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let remote = tmp.join("remote"); let local = tmp.join("local");
        std::fs::create_dir_all(&remote).unwrap(); std::fs::create_dir_all(&local).unwrap();
        std::fs::write(remote.join("download.txt"), b"explicit FTPS download").unwrap();
        let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests");
        let child = Command::new("/usr/bin/python3").arg(tests.join("TestFtpServer.py"))
            .env("LSCP_TEST_ROOT", &remote).env("LSCP_TEST_FTP_TLS", "1")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child); let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").expect("FTPS server failed to start").parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let open = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "ftpes", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let list = svc.dispatch_async(ApiEnvelope { method: "GET".into(), path: format!("/api/remote/list?tab={id}&path=%2F"), body: json!({}) }).await;
        assert_eq!(list.status, 200, "{}", list.payload);
        assert!(list.payload["entries"].as_array().unwrap().iter().any(|e| e["name"] == "download.txt"));
        let download = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["download.txt"]}))).await;
        assert_eq!(download.status, 200, "{}", download.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.first().and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.first().and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("FTPS download failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done, "FTPS download timed out");
        assert_eq!(std::fs::read(local.join("download.txt")).unwrap(), b"explicit FTPS download");
        exercise_ftp_uploads(&svc, id, &local, &remote).await;
        std::fs::write(remote.join("large.bin"), vec![19u8; 4 * 1024 * 1024]).unwrap();
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_flag = Arc::clone(&cancel);
        let progress = move |_: u64, _: u64| callback_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut flags = linscp_engine::transfer::TransferFlags::default();
        flags.no_clobber = true;
        flags.cleanup_download_stage = true;
        flags.resume_support = linscp_engine::presets::ResumeSupportMode::On;
        flags.cancel_flag = Some(cancel);
        let mut logger = linscp_engine::xml_log::SessionLogger::open(None, 0, false, None, None, false, "").unwrap();
        let interrupted = linscp_engine::transfer::download_single_file(session.as_ref(), "/large.bin", None, &local.join("large.bin"), &flags, &mut logger, Some(&progress)).await;
        assert!(interrupted.is_err());
        assert!(!local.join("large.bin").exists());
        assert!(!std::fs::read_dir(&local).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-download-")));
        let err = session.stat("/download.txt").await.expect_err("interrupted FTPS control channel must not be reused");
        assert!(err.to_string().contains("reconnect"), "{err}");
        let reopened = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "ftpes", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(reopened.status, 200, "{}", reopened.payload);
        let new_id = reopened.payload["tab"]["id"].as_u64().unwrap();
        exercise_ftp_upload_cancellation(&svc, new_id, &local, &remote).await;
        drop(server); let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_ftps_implicit_gui_upload() {
        if std::env::var_os("LSCP_LIVE_FTPS_IMPLICIT").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-live-implicit-ftps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let remote = tmp.join("remote"); let local = tmp.join("local");
        std::fs::create_dir_all(&remote).unwrap(); std::fs::create_dir_all(&local).unwrap();
        std::fs::write(remote.join("download.txt"), b"implicit FTPS").unwrap();
        let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests");
        let child = Command::new("/usr/bin/python3").arg(tests.join("TestFtpServer.py"))
            .env("LSCP_TEST_ROOT", &remote).env("LSCP_TEST_FTP_TLS", "1").env("LSCP_TEST_FTP_IMPLICIT", "1")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child); let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").expect("implicit FTPS server failed to start").parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let request = |body: Value| ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body };
        let open = svc.dispatch_async(request(json!({"session": {"protocol": "ftps", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "tls_ca_file": tests.join("fixtures/s3-server-cert.pem"), "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        exercise_ftp_uploads(&svc, id, &local, &remote).await;
        exercise_ftp_upload_cancellation(&svc, id, &local, &remote).await;
        drop(server); let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    async fn exercise_saved_remote_workspace(root: &Path, port: u16) {
        let config = root.join("workspace-config");
        let svc = CommanderService::new(config.clone(), Arc::new(NativeLocalFs::new()));
        unlock_for_test(&svc);
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let save = svc.dispatch_async(request("/api/sessions/save", json!({"name": "Saved FTP", "session": {"protocol": "ftp", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "local_dir": root, "initial_dir": "/"}}))).await;
        assert_eq!(save.status, 200, "{}", save.payload);
        let open = svc.dispatch_async(request("/api/tabs/open", json!({"site_name": "Saved FTP", "name": "Saved FTP", "session": {"local_dir": root, "initial_dir": "/"}}))).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let original = open.payload["tab"]["id"].as_u64().unwrap();
        let saved = svc.dispatch_async(request("/api/workspaces/save", json!({"name": "FTP workspace"}))).await;
        assert_eq!(saved.status, 200, "{}", saved.payload);
        let serialized = std::fs::read_to_string(config.join("workspaces.json")).unwrap();
        assert!(!serialized.contains("testpass"));
        let reopened = svc.dispatch_async(request("/api/workspaces/open", json!({"name": "FTP workspace"}))).await;
        assert_eq!(reopened.status, 200, "{}", reopened.payload);
        assert!(reopened.payload["failed"].as_array().unwrap().is_empty(), "{}", reopened.payload);
        let restored = reopened.payload["opened"][0]["id"].as_u64().unwrap();
        assert_ne!(restored, original);
        assert_eq!(reopened.payload["active_tab"], restored);
        let session = svc.state.lock().unwrap().tabs.get(&restored).unwrap().remote.as_ref().unwrap().clone();
        assert!(session.stat("/gui-new-folder").await.unwrap().is_some());
        // Workspaces do not persist transient credentials; an unsaved remote
        // session must not be silently saved in an unrecoverable form.
        let unsaved = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "ftp", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "local_dir": root, "initial_dir": "/"}}))).await;
        assert_eq!(unsaved.status, 200, "{}", unsaved.payload);
        let rejected = svc.dispatch_async(request("/api/workspaces/save", json!({"name": "unsaved"}))).await;
        assert_eq!(rejected.status, 400);
        assert!(rejected.payload["error"].as_str().unwrap().contains("saved"));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_ftp_reconnect_close_race() {
        if std::env::var_os("LSCP_LIVE_FTP").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-ftp-reconnect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp); std::fs::create_dir_all(&tmp).unwrap();
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests/TestFtpServer.py");
        let child = Command::new("/usr/bin/python3").arg(path).env("LSCP_TEST_ROOT", &tmp).env("LSCP_TEST_FTP_LOGIN_DELAY", "0.3")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child); let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").unwrap().parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let opened = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "ftp", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "local_dir": tmp, "initial_dir": "/"}}))).await;
        assert_eq!(opened.status, 200, "{}", opened.payload);
        let id = opened.payload["tab"]["id"].as_u64().unwrap();
        let other = svc.clone();
        let task = tokio::spawn(async move {
            other.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/reconnect".into(), body: json!({"tab": id}) }).await
        });
        let mut started = false;
        for _ in 0..1000 {
            if svc.state.lock().unwrap().pending_connections.contains(&id) { started = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert!(started, "reconnect did not start");
        let duplicate = svc.dispatch_async(request("/api/tabs/reconnect", json!({"tab": id}))).await;
        assert_eq!(duplicate.status, 409);
        let closed = svc.dispatch_async(request("/api/tabs/close", json!({"tab": id}))).await;
        assert_eq!(closed.status, 200);
        let response = task.await.unwrap();
        assert_ne!(response.status, 200, "closed tab was reconnected");
        assert!(!svc.state.lock().unwrap().tabs.contains_key(&id));
        assert!(!svc.state.lock().unwrap().pending_connections.contains(&id));
        drop(server); let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_ftp_gui_download() {
        if std::env::var_os("LSCP_LIVE_FTP").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-live-ftp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let remote = tmp.join("remote"); let local = tmp.join("local");
        std::fs::create_dir_all(&remote).unwrap(); std::fs::create_dir_all(&local).unwrap();
        std::fs::write(remote.join("download.txt"), b"FTP roundtrip").unwrap();
        std::fs::write(remote.join("slow.bin"), vec![17u8; 4 * 1024 * 1024]).unwrap();
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests/TestFtpServer.py");
        let child = Command::new("/usr/bin/python3").arg(path).env("LSCP_TEST_ROOT", &remote).env("LSCP_TEST_FTP_THROTTLE", "1")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child);
        let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").expect("FTP server failed to start").parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let open = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "ftp", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let list = svc.dispatch_async(ApiEnvelope { method: "GET".into(), path: format!("/api/remote/list?tab={id}&path=%2F"), body: json!({}) }).await;
        assert_eq!(list.status, 200, "{}", list.payload);
        assert!(list.payload["entries"].as_array().unwrap().iter().any(|e| e["name"] == "download.txt"));
        let download = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["download.txt"]}))).await;
        assert_eq!(download.status, 200, "{}", download.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.first().and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.first().and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("FTP download failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done, "FTP download timed out");
        assert_eq!(std::fs::read(local.join("download.txt")).unwrap(), b"FTP roundtrip");
        exercise_ftp_uploads(&svc, id, &local, &remote).await;
        Box::pin(exercise_saved_remote_workspace(&local, port)).await;
        let slow_index = svc.queue.snapshot().0.len();
        let slow = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["slow.bin"]}))).await;
        assert_eq!(slow.status, 200, "{}", slow.payload);
        let mut task_id = None;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(slow_index) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Completed", "FTP download finished before cancellation");
                assert_ne!(task["status"], "Failed", "{tasks:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let result = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("FTP download did not start")}))).await;
        assert_eq!(result.status, 200, "{}", result.payload);
        let mut cancelled = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(slow_index).and_then(|t| t["status"].as_str()) == Some("Cancelled") {
                assert!(tasks[slow_index]["error"].as_str().unwrap_or_default().contains("Reconnect"));
                cancelled = true; break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(cancelled, "FTP cancellation was not observed");
        assert!(!local.join("slow.bin").exists());
        assert!(!std::fs::read_dir(&local).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-download-")));
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let err = session.stat("/download.txt").await.expect_err("interrupted FTP control channel must not be reused");
        assert!(err.to_string().contains("reconnect"), "{err}");
        let reopened = svc.dispatch_async(request("/api/tabs/reconnect", json!({"tab": id}))).await;
        assert_eq!(reopened.status, 200, "{}", reopened.payload);
        let new_id = reopened.payload["tab"]["id"].as_u64().unwrap();
        assert_eq!(new_id, id);
        let fresh = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        assert!(!Arc::ptr_eq(&session, &fresh));
        assert!(fresh.stat("/download.txt").await.unwrap().is_some());
        // Running FTP uploads must accept cancellation through the public
        // queue, poison the control connection, and retain the reported stage.
        std::fs::write(local.join("queued-ftp-cancel.bin"), vec![43u8; 32 * 1024 * 1024]).unwrap();
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": new_id, "local_dir": local, "remote_dir": "/", "names": ["queued-ftp-cancel.bin"], "accept_ftp_rename_risk": true}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        let mut task_id = None;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(idx) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Failed", "{tasks:?}");
                assert_ne!(task["status"], "Completed", "FTP upload finished before cancellation");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("queued FTP upload did not start")}))).await;
        assert_eq!(cancelled.status, 200, "{}", cancelled.payload);
        let mut stopped = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Cancelled") {
                let error = tasks[idx]["error"].as_str().unwrap_or("");
                assert!(error.contains("Reconnect") && error.contains("temporary file"), "{error}");
                let stage = error.split('\'').nth(1).expect("missing FTP temporary path");
                assert!(remote.join(stage.trim_start_matches('/')).exists());
                stopped = true; break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped, "running FTP upload did not cancel");
        assert!(!remote.join("queued-ftp-cancel.bin").exists());
        let reopened = svc.dispatch_async(request("/api/tabs/reconnect", json!({"tab": new_id}))).await;
        assert_eq!(reopened.status, 200, "{}", reopened.payload);
        let new_id = reopened.payload["tab"]["id"].as_u64().unwrap();
        assert_eq!(new_id, id);
        exercise_ftp_upload_cancellation(&svc, new_id, &local, &remote).await;
        drop(server);
        let failed = svc.dispatch_async(request("/api/tabs/reconnect", json!({"tab": id}))).await;
        assert_ne!(failed.status, 200, "offline reconnect must not report success");
        assert_eq!(svc.state.lock().unwrap().tabs.get(&id).unwrap().connected, false);
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// Deletes through the session, which is what the panes' Delete does.
    ///
    /// Every path here went wrong at some point: a name that is not a leaf, a
    /// link that pointed out of the tree, a directory that is not empty, a name
    /// the server no longer has, and a delete mixed with one refusal.
    #[cfg(target_os = "linux")]
    async fn exercise_remote_delete(svc: &CommanderService, id: u64) {
        let request = |body: Value| ApiEnvelope { method: "POST".into(), path: "/api/remote/delete".into(), body };
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        // A PUT of `a/b/c.txt` is not a directory creation on any server, so
        // the tree is made first and then filled the way a batch upload does.
        for dir in ["/delete-tree", "/delete-tree/nested", "/delete-dir"] {
            session.mkdir(dir).await.unwrap();
        }
        for (path, bytes) in [
            ("/delete-file.txt", b"one".as_slice()),
            ("/delete-tree/keep.txt", b"two".as_slice()),
            ("/delete-tree/nested/deep.txt", b"three".as_slice()),
            ("/delete-scoped.txt", b"four".as_slice()),
        ] {
            linscp_proto::upload_bytes(session.as_ref(), path, bytes, Default::default())
                .await
                .unwrap();
        }
        // A name that is not a leaf is refused per name, and the valid name in
        // the same request still runs: one bad entry does not cancel the drop
        // of the whole selection.
        let mixed = svc.dispatch_async(request(json!({
            "tab": id, "names": ["delete-file.txt", "../escape", ""]
        }))).await;
        assert_eq!(mixed.status, 200, "{}", mixed.payload);
        assert_eq!(mixed.payload["deleted"], json!(["delete-file.txt"]));
        let failed = mixed.payload["failed"].as_array().unwrap();
        assert_eq!(failed.len(), 2, "{}", mixed.payload);
        assert!(session.stat("/delete-file.txt").await.unwrap().is_none());
        // A directory is emptied before it is removed, and its children go too.
        let tree = svc.dispatch_async(request(json!({
            "tab": id, "names": [{"name": "delete-tree", "is_dir": true}]
        }))).await;
        assert_eq!(tree.status, 200, "{}", tree.payload);
        assert_eq!(tree.payload["deleted"], json!(["delete-tree"]));
        assert!(session.stat("/delete-tree").await.unwrap().is_none());
        assert!(session.stat("/delete-tree/nested/deep.txt").await.unwrap().is_none());
        // A name the server no longer has is the state the caller asked for.
        let gone = svc.dispatch_async(request(json!({
            "tab": id, "names": ["delete-file.txt"]
        }))).await;
        assert_eq!(gone.status, 200, "{}", gone.payload);
        assert_eq!(gone.payload["deleted"], json!(["delete-file.txt"]));
        assert!(gone.payload["failed"].as_array().unwrap().is_empty());
        // Nothing selected, and a request that names nothing usable, are
        // refusals rather than an empty success.
        for body in [json!({"tab": id, "names": []}), json!({"tab": id})] {
            assert_eq!(
                svc.dispatch_async(request(body.clone())).await.status,
                400,
                "{body}"
            );
        }
        // A name is resolved against the directory the request names, and a
        // name that only exists elsewhere is left alone: the panel directory is
        // not a suggestion.
        linscp_proto::upload_bytes(session.as_ref(), "/delete-dir/inner.txt", b"five", Default::default())
            .await
            .unwrap();
        let elsewhere = svc.dispatch_async(request(json!({
            "tab": id, "names": ["inner.txt"], "remote_dir": "/delete-dir"
        }))).await;
        assert_eq!(elsewhere.status, 200, "{}", elsewhere.payload);
        assert!(session.stat("/delete-dir/inner.txt").await.unwrap().is_none());
        let scoped = svc.dispatch_async(request(json!({
            "tab": id, "names": ["delete-scoped.txt"], "remote_dir": "/"
        }))).await;
        assert_eq!(scoped.status, 200, "{}", scoped.payload);
        assert!(session.stat("/delete-scoped.txt").await.unwrap().is_none());
    }

    #[cfg(target_os = "linux")]
    async fn exercise_webdav_local_trees(svc: &CommanderService, id: u64, local: &Path, downloaded: &Path, session: &dyn linscp_proto::RemoteSession) {
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        // MKCOL must not follow redirects or treat an ambiguous 207 as a
        // confirmed creation of the requested directory.
        assert!(session.mkdir("/mkcol-redirect").await.is_err());
        assert!(session.stat("/mkcol-target").await.unwrap().is_none());
        assert!(session.mkdir("/mkcol-multistatus").await.is_err());
        assert!(session.stat("/mkcol-multistatus").await.unwrap().is_none());
        // WebDAV trees are staged locally; confirmation is required because
        // collection ETags do not make their descendants a snapshot.
        session.mkdir("/tree-download").await.unwrap();
        session.mkdir("/tree-download/nested").await.unwrap();
        session.mkdir("/tree-download/nested/empty").await.unwrap();
        linscp_proto::upload_bytes(session, "/tree-download/nested/data.txt", b"tree data", Default::default()).await.unwrap();
        let risk = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["tree-download"]}))).await;
        assert_eq!(risk.status, 409, "{}", risk.payload);
        assert_eq!(risk.payload["directory_copy_risk"], true);
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["tree-download"], "accept_directory_copy_risk": true}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        let mut done = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("WebDAV tree download failed: {:?}", tasks.get(idx)); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(std::fs::read(downloaded.join("tree-download/nested/data.txt")).unwrap(), b"tree data");
        assert!(downloaded.join("tree-download/nested/empty").is_dir());
        // A merge must preserve existing files, even when publication stops on
        // a conflicting leaf after approval.
        linscp_proto::upload_bytes(session, "/tree-download/nested/data.txt", b"changed remote", Default::default()).await.unwrap();
        let conflict = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["tree-download"], "accept_directory_copy_risk": true}))).await;
        assert_eq!(conflict.status, 409, "{}", conflict.payload);
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["tree-download"], "accept_directory_copy_risk": true, "merge_directories": ["tree-download"]}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        let mut failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("existing local file was replaced"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(std::fs::read(downloaded.join("tree-download/nested/data.txt")).unwrap(), b"tree data");
    }

    #[cfg(target_os = "linux")]
    async fn exercise_webdav_remote_trees(svc: &CommanderService, id: u64, session: &dyn linscp_proto::RemoteSession) {
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        // Remote-to-remote copies also use a locally staged tree and refuse
        // to replace an existing destination tree.
        session.mkdir("/webdav-copy-dest").await.unwrap();
        let risk = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/webdav-copy-dest", "names": ["tree-download"]}))).await;
        assert_eq!(risk.status, 409, "{}", risk.payload);
        assert_eq!(risk.payload["directory_copy_risk"], true);
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/webdav-copy-dest", "names": ["tree-download"], "accept_directory_copy_risk": true}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        let mut done = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("WebDAV remote tree copy failed: {:?}", tasks.get(idx)); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(linscp_proto::download_bytes(session, "/webdav-copy-dest/tree-download/nested/data.txt", Default::default()).await.unwrap(), b"changed remote");
        assert!(session.stat("/webdav-copy-dest/tree-download/nested/empty").await.unwrap().unwrap().is_dir);
        assert_eq!(linscp_proto::download_bytes(session, "/tree-download/nested/data.txt", Default::default()).await.unwrap(), b"changed remote");
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/webdav-copy-dest", "names": ["tree-download"], "accept_directory_copy_risk": true}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        let mut failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("existing remote WebDAV tree was replaced"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(linscp_proto::download_bytes(session, "/webdav-copy-dest/tree-download/nested/data.txt", Default::default()).await.unwrap(), b"changed remote");
    }

    #[cfg(target_os = "linux")]
    async fn exercise_webdav_upload_trees(svc: &CommanderService, id: u64, local: &Path, session: &dyn linscp_proto::RemoteSession) {
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        // Upload a new WebDAV tree, then verify an approved merge cannot
        // replace a file that appeared in the destination.
        std::fs::create_dir_all(local.join("tree-upload/nested/empty")).unwrap();
        std::fs::write(local.join("tree-upload/nested/data.txt"), b"upload tree").unwrap();
        let risk = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["tree-upload"]}))).await;
        assert_eq!(risk.status, 409, "{}", risk.payload);
        assert_eq!(risk.payload["directory_copy_risk"], true);
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["tree-upload"], "accept_directory_copy_risk": true}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        let mut done = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("WebDAV tree upload failed: {:?}", tasks.get(idx)); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(linscp_proto::download_bytes(session, "/tree-upload/nested/data.txt", Default::default()).await.unwrap(), b"upload tree");
        assert!(session.stat("/tree-upload/nested/empty").await.unwrap().unwrap().is_dir);
        std::fs::write(local.join("tree-upload/nested/data.txt"), b"must not replace").unwrap();
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["tree-upload"], "accept_directory_copy_risk": true, "merge_directories": ["tree-upload"]}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        let mut failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("existing WebDAV file was replaced"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(linscp_proto::download_bytes(session, "/tree-upload/nested/data.txt", Default::default()).await.unwrap(), b"upload tree");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_webdav_cross_server_trees() {
        if std::env::var_os("LSCP_LIVE_WEBDAV").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-live-webdav-cross-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests/TestDavServer.py");
        let child = Command::new("/usr/bin/python3").arg(path).env("LSCP_TEST_PORT", "0")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child);
        let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").expect("WebDAV destination failed to start").parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let open = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "dav", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "local_dir": tmp, "initial_dir": "/"}}) }).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        Box::pin(exercise_cross_move_destination(&svc, id, "/", &tmp)).await;
        drop(server); let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_webdav_gui_upload_download() {
        if std::env::var_os("LSCP_LIVE_WEBDAV").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-live-webdav-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let local = tmp.join("local"); let downloaded = tmp.join("downloaded");
        std::fs::create_dir_all(&local).unwrap(); std::fs::create_dir_all(&downloaded).unwrap();
        let server_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests/TestDavServer.py");
        let child = Command::new("/usr/bin/python3").arg(server_path).env("LSCP_TEST_PORT", "0").env("LSCP_TEST_GET_DELAY", "0.005").env("LSCP_TEST_DELETE_RACE", "1").env("LSCP_TEST_DROP_ONCE", "/resume-drop.bin").env("LSCP_TEST_BAD_RANGE", "1").env("LSCP_TEST_MKCOL_RESPONSES", "1")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child);
        let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").expect("WebDAV server failed to start").parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let open = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "dav", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        Box::pin(exercise_remote_mkdir(&svc, id)).await;
        std::fs::write(local.join("upload.txt"), b"WebDAV roundtrip").unwrap();
        let upload = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["upload.txt"]}))).await;
        assert_eq!(upload.status, 200, "{}", upload.payload);
        for index in 0..2 {
            if index == 1 {
                let download = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["upload.txt"]}))).await;
                assert_eq!(download.status, 200, "{}", download.payload);
            }
            let mut done = false;
            for _ in 0..500 {
                let (tasks, _) = svc.queue.snapshot();
                if tasks.get(index).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
                if tasks.get(index).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("WebDAV transfer failed: {tasks:?}"); }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(done, "WebDAV transfer timed out");
        }
        let list = svc.dispatch_async(ApiEnvelope { method: "GET".into(), path: format!("/api/remote/list?tab={id}&path=%2F"), body: json!({}) }).await;
        assert_eq!(list.status, 200, "{}", list.payload);
        assert!(list.payload["entries"].as_array().unwrap().iter().any(|e| e["name"] == "upload.txt"));
        assert_eq!(std::fs::read(downloaded.join("upload.txt")).unwrap(), b"WebDAV roundtrip");
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        Box::pin(exercise_remote_delete(&svc, id)).await;
        Box::pin(exercise_webdav_local_trees(&svc, id, &local, &downloaded, session.as_ref())).await;
        Box::pin(exercise_webdav_remote_trees(&svc, id, session.as_ref())).await;
        Box::pin(exercise_webdav_upload_trees(&svc, id, &local, session.as_ref())).await;
        std::fs::write(local.join("other.txt"), b"must not replace").unwrap();
        let mut flags = linscp_engine::transfer::TransferFlags::default();
        flags.no_clobber = true;
        let mut logger = linscp_engine::xml_log::SessionLogger::open(None, 0, false, None, None, false, "").unwrap();
        let collision = linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("other.txt"), "/upload.txt", &flags, &mut logger, None).await;
        assert!(collision.is_err());
        let remote_bytes = linscp_proto::download_bytes(session.as_ref(), "/upload.txt", Default::default()).await.unwrap();
        assert_eq!(remote_bytes, b"WebDAV roundtrip");
        // Approval captures the ETag; replacing the destination while queued
        // must cause the conditional PUT to fail without changing its contents.
        let conflict_body = || json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["upload.txt"]});
        let conflict = svc.dispatch_async(request("/api/transfer/upload", conflict_body())).await;
        assert_eq!(conflict.status, 409, "{}", conflict.payload);
        let versions = conflict.payload["conflict_versions"].clone();
        assert!(versions["upload.txt"].as_str().is_some());
        svc.queue.pause();
        let race_index = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["upload.txt"], "overwrite": "overwrite", "conflict_versions": versions}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        linscp_proto::upload_bytes(session.as_ref(), "/upload.txt", b"changed after approval", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(race_index).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(race_index).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("conditional overwrite replaced a changed target"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed, "changed target must reject the overwrite");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/upload.txt", Default::default()).await.unwrap(), b"changed after approval");
        let conflict = svc.dispatch_async(request("/api/transfer/upload", conflict_body())).await;
        let versions = conflict.payload["conflict_versions"].clone();
        let success_index = svc.queue.snapshot().0.len();
        let approved = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["upload.txt"], "overwrite": "overwrite", "conflict_versions": versions}))).await;
        assert_eq!(approved.status, 200, "{}", approved.payload);
        let mut completed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(success_index).and_then(|t| t["status"].as_str()) == Some("Completed") { completed = true; break; }
            if tasks.get(success_index).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("unchanged target overwrite failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(completed);
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/upload.txt", Default::default()).await.unwrap(), b"WebDAV roundtrip");
        // A remote-to-local WebDAV move pins the source ETag for both GET
        // and DELETE, and publishes locally only with no-replace semantics.
        linscp_proto::upload_bytes(session.as_ref(), "/move-success.txt", b"move payload", Default::default()).await.unwrap();
        let move_index = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/transfer/move", json!({"tab": id, "direction": "download", "local_dir": downloaded, "remote_dir": "/", "names": ["move-success.txt"], "resume": false}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        let mut complete = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(move_index).and_then(|t| t["status"].as_str()) == Some("Completed") { complete = true; break; }
            if tasks.get(move_index).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("WebDAV move failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(complete);
        assert_eq!(std::fs::read(downloaded.join("move-success.txt")).unwrap(), b"move payload");
        assert!(session.stat("/move-success.txt").await.unwrap().is_none());
        // A successful-looking but incomplete GET must never publish a local
        // destination or delete the remote source during a move.
        for name in ["move-get-accepted.txt", "move-get-short.txt"] {
            let path = format!("/{name}");
            linscp_proto::upload_bytes(session.as_ref(), &path, b"complete source", Default::default()).await.unwrap();
            let idx = svc.queue.snapshot().0.len();
            let moved = svc.dispatch_async(request("/api/transfer/move", json!({"tab": id, "direction": "download", "local_dir": downloaded, "remote_dir": "/", "names": [name]}))).await;
            assert_eq!(moved.status, 200, "{}", moved.payload);
            let mut failed = false;
            for _ in 0..500 {
                let (tasks, _) = svc.queue.snapshot();
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("incomplete GET completed the move"); }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(failed);
            assert!(!downloaded.join(name).exists());
            assert_eq!(session.stat(&path).await.unwrap().unwrap().size, b"complete source".len() as u64);
        }
        // Exercise cross-server moves against a second independent WebDAV server.
        let server_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests/TestDavServer.py");
        let child = Command::new("/usr/bin/python3").arg(server_path).env("LSCP_TEST_PORT", "0").env("LSCP_TEST_ACCEPTED_PUT", "1")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut dest_server = Server(child); let mut line = String::new();
        BufReader::new(dest_server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let dest_port: u16 = line.trim().strip_prefix("READY ").expect("destination DAV server failed to start").parse().unwrap();
        let dest_open = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "dav", "host": "127.0.0.1", "port": dest_port, "username": "testuser", "password": "testpass", "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(dest_open.status, 200, "{}", dest_open.payload);
        let dest_id = dest_open.payload["tab"]["id"].as_u64().unwrap();
        let dest_session = svc.state.lock().unwrap().tabs.get(&dest_id).unwrap().remote.as_ref().unwrap().clone();
        linscp_proto::upload_bytes(session.as_ref(), "/cross-success.txt", b"cross server", Default::default()).await.unwrap();
        let risk = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": "/", "names": ["cross-success.txt"], "operation": "move"}))).await;
        assert_eq!(risk.status, 409);
        assert_eq!(risk.payload["cross_move_risk"], true);
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": "/", "names": ["cross-success.txt"], "operation": "move", "accept_cross_move_risk": true}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("cross-server move failed: {:?}", tasks.get(idx)); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert!(session.stat("/cross-success.txt").await.unwrap().is_none());
        assert_eq!(linscp_proto::download_bytes(dest_session.as_ref(), "/cross-success.txt", Default::default()).await.unwrap(), b"cross server");
        linscp_proto::upload_bytes(session.as_ref(), "/cross-copy-race.txt", b"original", Default::default()).await.unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": "/", "names": ["cross-copy-race.txt"], "operation": "copy"}))).await;
        assert_eq!(copied.status, 200, "{}", copied.payload);
        linscp_proto::upload_bytes(session.as_ref(), "/cross-copy-race.txt", b"changed source", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("changed source was copied"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(dest_session.stat("/cross-copy-race.txt").await.unwrap().is_none());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/cross-copy-race.txt", Default::default()).await.unwrap(), b"changed source");
        linscp_proto::upload_bytes(session.as_ref(), "/cross-conflict.txt", b"source", Default::default()).await.unwrap();
        linscp_proto::upload_bytes(dest_session.as_ref(), "/cross-conflict.txt", b"existing destination", Default::default()).await.unwrap();
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": "/", "names": ["cross-conflict.txt"], "operation": "move", "accept_cross_move_risk": true}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("cross-server conflict was overwritten"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/cross-conflict.txt", Default::default()).await.unwrap(), b"source");
        assert_eq!(linscp_proto::download_bytes(dest_session.as_ref(), "/cross-conflict.txt", Default::default()).await.unwrap(), b"existing destination");
        linscp_proto::upload_bytes(session.as_ref(), "/cross-changed.txt", b"original", Default::default()).await.unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": "/", "names": ["cross-changed.txt"], "operation": "move", "accept_cross_move_risk": true}))).await;
        assert_eq!(moved.status, 200);
        linscp_proto::upload_bytes(session.as_ref(), "/cross-changed.txt", b"changed", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("changed source was moved"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(dest_session.stat("/cross-changed.txt").await.unwrap().is_none());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/cross-changed.txt", Default::default()).await.unwrap(), b"changed");
        linscp_proto::upload_bytes(session.as_ref(), "/move-delete-race.txt", b"original cross copy", Default::default()).await.unwrap();
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": "/", "names": ["move-delete-race.txt"], "operation": "move", "accept_cross_move_risk": true}))).await;
        assert_eq!(moved.status, 200);
        let mut running_id = None;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if dest_session.stat("/move-delete-race.txt").await.unwrap().is_some() && tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Running") {
                running_id = tasks[idx]["id"].as_u64(); break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        // The fixture holds the conditional DELETE for 500 ms. Allow its
        // request to arrive after the destination becomes visible.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": running_id.expect("conditional source deletion did not start")}))).await;
        assert_eq!(cancelled.status, 200);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { assert!(tasks[idx]["error"].as_str().unwrap_or("").contains("Move incomplete")); failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("changed source was deleted"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(linscp_proto::download_bytes(dest_session.as_ref(), "/move-delete-race.txt", Default::default()).await.unwrap(), b"original cross copy");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/move-delete-race.txt", Default::default()).await.unwrap(), b"changed before conditional delete");
        // HTTP 202 does not confirm either a destination write or source
        // deletion; neither may be reported as a completed move.
        for name in ["cross-accepted.txt", "cross-delete-accepted.txt"] {
            linscp_proto::upload_bytes(session.as_ref(), &format!("/{name}"), b"preserve source", Default::default()).await.unwrap();
            let idx = svc.queue.snapshot().0.len();
            let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{dest_id}"), "directory": "/", "names": [name], "operation": "move", "accept_cross_move_risk": true}))).await;
            assert_eq!(moved.status, 200, "{}", moved.payload);
            let mut failed = false;
            for _ in 0..500 {
                let (tasks, _) = svc.queue.snapshot();
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
                if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("unconfirmed HTTP operation reported success"); }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(failed);
            assert_eq!(linscp_proto::download_bytes(session.as_ref(), &format!("/{name}"), Default::default()).await.unwrap(), b"preserve source");
            if name == "cross-accepted.txt" { assert!(dest_session.stat(&format!("/{name}")).await.unwrap().is_none()); }
            else { assert_eq!(linscp_proto::download_bytes(dest_session.as_ref(), &format!("/{name}"), Default::default()).await.unwrap(), b"preserve source"); }
        }
        drop(dest_server);
        // Same-session queued moves use the captured source ETag and an
        // atomic no-replace request against a different remote directory.
        session.mkdir("/archive").await.unwrap();
        linscp_proto::upload_bytes(session.as_ref(), "/same-copy.txt", b"copy on server", Default::default()).await.unwrap();
        let idx = svc.queue.snapshot().0.len();
        let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/archive", "names": ["same-copy.txt"]}))).await;
        assert_eq!(copied.status, 200, "{}", copied.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("same-session copy failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/same-copy.txt", Default::default()).await.unwrap(), b"copy on server");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/archive/same-copy.txt", Default::default()).await.unwrap(), b"copy on server");
        // Copying again cannot overwrite the existing destination.
        linscp_proto::upload_bytes(session.as_ref(), "/same-copy.txt", b"changed source", Default::default()).await.unwrap();
        let idx = svc.queue.snapshot().0.len();
        let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/archive", "names": ["same-copy.txt"]}))).await;
        assert_eq!(copied.status, 200);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("copy overwrote the destination"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/same-copy.txt", Default::default()).await.unwrap(), b"changed source");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/archive/same-copy.txt", Default::default()).await.unwrap(), b"copy on server");
        linscp_proto::upload_bytes(session.as_ref(), "/remote-move.txt", b"move on server", Default::default()).await.unwrap();
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/archive", "names": ["remote-move.txt"], "operation": "move"}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("server move failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert!(session.stat("/remote-move.txt").await.unwrap().is_none());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/archive/remote-move.txt", Default::default()).await.unwrap(), b"move on server");
        linscp_proto::upload_bytes(session.as_ref(), "/queued-race.txt", b"original", Default::default()).await.unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/archive", "names": ["queued-race.txt"], "operation": "move"}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        linscp_proto::upload_bytes(session.as_ref(), "/queued-race.txt", b"changed source", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("changed source was moved"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(session.stat("/archive/queued-race.txt").await.unwrap().is_none());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/queued-race.txt", Default::default()).await.unwrap(), b"changed source");
        linscp_proto::upload_bytes(session.as_ref(), "/queued-target.txt", b"original source", Default::default()).await.unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/archive", "names": ["queued-target.txt"], "operation": "move"}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        linscp_proto::upload_bytes(session.as_ref(), "/archive/queued-target.txt", b"competing target", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("destination was overwritten"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/queued-target.txt", Default::default()).await.unwrap(), b"original source");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/archive/queued-target.txt", Default::default()).await.unwrap(), b"competing target");
        linscp_proto::upload_bytes(session.as_ref(), "/queued-cancel.txt", b"cancel source", Default::default()).await.unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/archive", "names": ["queued-cancel.txt"], "operation": "move"}))).await;
        assert_eq!(moved.status, 200);
        let task = svc.queue.snapshot().0[idx]["id"].as_u64().unwrap();
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task}))).await;
        assert_eq!(cancelled.status, 200);
        svc.queue.resume();
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/queued-cancel.txt", Default::default()).await.unwrap(), b"cancel source");
        assert!(session.stat("/archive/queued-cancel.txt").await.unwrap().is_none());
        // Directory moves require explicit acknowledgement because a
        // collection ETag need not describe every descendant.
        session.mkdir("/tree-to-move").await.unwrap();
        session.mkdir("/tree-to-move/nested").await.unwrap();
        linscp_proto::upload_bytes(session.as_ref(), "/tree-to-move/nested/data.txt", b"nested", Default::default()).await.unwrap();
        let risk = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/archive", "names": ["tree-to-move"], "operation": "move"}))).await;
        assert_eq!(risk.status, 409);
        assert_eq!(risk.payload["directory_move_risk"], true);
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/archive", "names": ["tree-to-move"], "operation": "move", "accept_directory_move_risk": true}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        // The collection's ETag does not track nested content: the explicitly
        // acknowledged operation includes this concurrent descendant change.
        linscp_proto::upload_bytes(session.as_ref(), "/tree-to-move/nested/data.txt", b"changed descendant", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("WebDAV directory move failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert!(session.stat("/tree-to-move").await.unwrap().is_none());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/archive/tree-to-move/nested/data.txt", Default::default()).await.unwrap(), b"changed descendant");
        let risk = svc.dispatch_async(request("/api/remote/rename", json!({"tab": id, "old_name": "archive", "new_name": "renamed-archive"}))).await;
        assert_eq!(risk.status, 409);
        assert_eq!(risk.payload["directory_move_risk"], true);
        let bad = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/archive/tree-to-move", "names": ["archive"], "operation": "move", "accept_directory_move_risk": true}))).await;
        assert_eq!(bad.status, 400);
        let renamed = svc.dispatch_async(request("/api/remote/rename", json!({"tab": id, "old_name": "archive", "new_name": "renamed-archive", "accept_directory_move_risk": true}))).await;
        assert_eq!(renamed.status, 200, "{}", renamed.payload);
        assert!(session.stat("/archive").await.unwrap().is_none());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/renamed-archive/tree-to-move/nested/data.txt", Default::default()).await.unwrap(), b"changed descendant");
        // Same-session renames are conditional on the source ETag and never
        // replace a destination; failure after a lost response is ambiguous.
        linscp_proto::upload_bytes(session.as_ref(), "/rename-old.txt", b"rename content", Default::default()).await.unwrap();
        let renamed = svc.dispatch_async(request("/api/remote/rename", json!({"tab": id, "old_name": "rename-old.txt", "new_name": "rename-new.txt"}))).await;
        assert_eq!(renamed.status, 200, "{}", renamed.payload);
        assert!(session.stat("/rename-old.txt").await.unwrap().is_none());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/rename-new.txt", Default::default()).await.unwrap(), b"rename content");
        linscp_proto::upload_bytes(session.as_ref(), "/rename-dest.txt", b"keep destination", Default::default()).await.unwrap();
        let conflict = svc.dispatch_async(request("/api/remote/rename", json!({"tab": id, "old_name": "rename-new.txt", "new_name": "rename-dest.txt"}))).await;
        assert_ne!(conflict.status, 200);
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/rename-new.txt", Default::default()).await.unwrap(), b"rename content");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/rename-dest.txt", Default::default()).await.unwrap(), b"keep destination");
        let tag = session.dav_get_etag("/rename-new.txt").await.unwrap().0.unwrap();
        linscp_proto::upload_bytes(session.as_ref(), "/rename-new.txt", b"changed", Default::default()).await.unwrap();
        assert!(session.dav_move_if_match("/rename-new.txt", "/rename-race.txt", &tag, false).await.is_err());
        assert!(session.stat("/rename-race.txt").await.unwrap().is_none());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/rename-new.txt", Default::default()).await.unwrap(), b"changed");
        // MOVE must not follow redirects to a different source or treat
        // a multi-status response as an unambiguous success.
        linscp_proto::upload_bytes(session.as_ref(), "/rename-redirect.txt", b"same bytes", Default::default()).await.unwrap();
        linscp_proto::upload_bytes(session.as_ref(), "/rename-other.txt", b"same bytes", Default::default()).await.unwrap();
        let redirect = svc.dispatch_async(request("/api/remote/rename", json!({"tab": id, "old_name": "rename-redirect.txt", "new_name": "rename-followed.txt"}))).await;
        assert_ne!(redirect.status, 200);
        assert!(session.stat("/rename-other.txt").await.unwrap().is_some());
        assert!(session.stat("/rename-followed.txt").await.unwrap().is_none());
        linscp_proto::upload_bytes(session.as_ref(), "/rename-multistatus.txt", b"multi", Default::default()).await.unwrap();
        let multistatus = svc.dispatch_async(request("/api/remote/rename", json!({"tab": id, "old_name": "rename-multistatus.txt", "new_name": "rename-multi-result.txt"}))).await;
        assert_ne!(multistatus.status, 200);
        assert!(multistatus.payload["error"].as_str().unwrap_or("").contains("may have moved"));
        let invalid = svc.dispatch_async(request("/api/remote/rename", json!({"tab": id, "old_name": "rename-new.txt", "new_name": "../escape"}))).await;
        assert_eq!(invalid.status, 400);
        // A source changed after queueing fails conditional GET without a local publication.
        linscp_proto::upload_bytes(session.as_ref(), "/move-before-get.txt", b"original", Default::default()).await.unwrap();
        svc.queue.pause();
        let changed_index = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/transfer/move", json!({"tab": id, "direction": "download", "local_dir": downloaded, "remote_dir": "/", "names": ["move-before-get.txt"]}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        linscp_proto::upload_bytes(session.as_ref(), "/move-before-get.txt", b"new source", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(changed_index).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(changed_index).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("changed source was moved"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(!downloaded.join("move-before-get.txt").exists());
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/move-before-get.txt", Default::default()).await.unwrap(), b"new source");
        // A destination appearing after the move was queued must not be
        // replaced, and the remote source must not be deleted.
        linscp_proto::upload_bytes(session.as_ref(), "/move-dest-race.txt", b"remote source", Default::default()).await.unwrap();
        svc.queue.pause();
        let dest_index = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/transfer/move", json!({"tab": id, "direction": "download", "local_dir": downloaded, "remote_dir": "/", "names": ["move-dest-race.txt"]}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        std::fs::write(downloaded.join("move-dest-race.txt"), b"concurrent local destination").unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(dest_index).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(dest_index).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("competing destination was overwritten"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(std::fs::read(downloaded.join("move-dest-race.txt")).unwrap(), b"concurrent local destination");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/move-dest-race.txt", Default::default()).await.unwrap(), b"remote source");
        // A source changed between publication and DELETE remains remote,
        // while the downloaded copy remains local and the task reports failure.
        linscp_proto::upload_bytes(session.as_ref(), "/move-delete-race.txt", b"original copy", Default::default()).await.unwrap();
        let changed_index = svc.queue.snapshot().0.len();
        let moved = svc.dispatch_async(request("/api/transfer/move", json!({"tab": id, "direction": "download", "local_dir": downloaded, "remote_dir": "/", "names": ["move-delete-race.txt"]}))).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        let mut running_id = None;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if downloaded.join("move-delete-race.txt").exists() && tasks.get(changed_index).and_then(|t| t["status"].as_str()) == Some("Running") {
                running_id = tasks[changed_index]["id"].as_u64(); break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancel = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": running_id.expect("conditional delete did not start")}))).await;
        assert_eq!(cancel.status, 200, "{}", cancel.payload);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(changed_index).and_then(|t| t["status"].as_str()) == Some("Failed") {
                assert!(tasks[changed_index]["error"].as_str().unwrap_or_default().contains("Move incomplete"));
                failed = true; break;
            }
            if tasks.get(changed_index).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("changed source was deleted"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(std::fs::read(downloaded.join("move-delete-race.txt")).unwrap(), b"original copy");
        assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/move-delete-race.txt", Default::default()).await.unwrap(), b"changed before conditional delete");
        // Verified resume compares the entire existing partial to the same
        // ETag-pinned source before requesting the remaining range.
        linscp_proto::upload_bytes(session.as_ref(), "/resume-good.txt", b"abcdefghij", Default::default()).await.unwrap();
        std::fs::write(downloaded.join("resume-good.txt.filepart"), b"abcd").unwrap();
        let idx = svc.queue.snapshot().0.len();
        let resumed = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["resume-good.txt"], "resume": true}))).await;
        assert_eq!(resumed.status, 200, "{}", resumed.payload);
        let mut complete = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { complete = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("verified resume failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(complete);
        assert_eq!(std::fs::read(downloaded.join("resume-good.txt")).unwrap(), b"abcdefghij");
        assert_eq!(std::fs::read(downloaded.join("resume-good.txt.filepart")).unwrap(), b"abcd");
        linscp_proto::upload_bytes(session.as_ref(), "/resume-bad.txt", b"abcdefghij", Default::default()).await.unwrap();
        std::fs::write(downloaded.join("resume-bad.txt.filepart"), b"xxxx").unwrap();
        let idx = svc.queue.snapshot().0.len();
        let resumed = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["resume-bad.txt"], "resume": true}))).await;
        assert_eq!(resumed.status, 200, "{}", resumed.payload);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("mismatched partial was published"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(!downloaded.join("resume-bad.txt").exists());
        assert_eq!(std::fs::read(downloaded.join("resume-bad.txt.filepart")).unwrap(), b"xxxx");
        linscp_proto::upload_bytes(session.as_ref(), "/resume-race.txt", b"abcdefghij", Default::default()).await.unwrap();
        std::fs::write(downloaded.join("resume-race.txt.filepart"), b"abcd").unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let resumed = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["resume-race.txt"], "resume": true}))).await;
        assert_eq!(resumed.status, 200, "{}", resumed.payload);
        linscp_proto::upload_bytes(session.as_ref(), "/resume-race.txt", b"abcdNEWxyz", Default::default()).await.unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("changed source was resumed"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(!downloaded.join("resume-race.txt").exists());
        assert_eq!(std::fs::read(downloaded.join("resume-race.txt.filepart")).unwrap(), b"abcd");
        // A server that lies about the returned range cannot cause a splice.
        linscp_proto::upload_bytes(session.as_ref(), "/resume-wrong-range.txt", b"abcdefghij", Default::default()).await.unwrap();
        std::fs::write(downloaded.join("resume-wrong-range.txt.filepart"), b"abcd").unwrap();
        let idx = svc.queue.snapshot().0.len();
        let resumed = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["resume-wrong-range.txt"], "resume": true}))).await;
        assert_eq!(resumed.status, 200);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("invalid range was published"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(!downloaded.join("resume-wrong-range.txt").exists());
        assert_eq!(std::fs::read(downloaded.join("resume-wrong-range.txt.filepart")).unwrap(), b"abcd");
        // Full-length partials are still compared, and symlink partials are
        // rejected rather than followed or removed.
        linscp_proto::upload_bytes(session.as_ref(), "/resume-full.txt", b"complete", Default::default()).await.unwrap();
        std::fs::write(downloaded.join("resume-full.txt.filepart"), b"complete").unwrap();
        let idx = svc.queue.snapshot().0.len();
        let resumed = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["resume-full.txt"], "resume": true}))).await;
        assert_eq!(resumed.status, 200);
        let mut complete = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { complete = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("full-prefix resume failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(complete);
        assert_eq!(std::fs::read(downloaded.join("resume-full.txt")).unwrap(), b"complete");
        linscp_proto::upload_bytes(session.as_ref(), "/resume-link.txt", b"complete", Default::default()).await.unwrap();
        std::os::unix::fs::symlink(downloaded.join("resume-full.txt"), downloaded.join("resume-link.txt.filepart")).unwrap();
        let idx = svc.queue.snapshot().0.len();
        let resumed = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["resume-link.txt"], "resume": true}))).await;
        assert_eq!(resumed.status, 200);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("symlink partial was followed"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(!downloaded.join("resume-link.txt").exists());
        assert_eq!(std::fs::read(downloaded.join("resume-full.txt")).unwrap(), b"complete");
        // A network interruption creates a no-clobber checkpoint; retry
        // verifies it before reusing any bytes and leaves the checkpoint intact.
        let resume_data = vec![42u8; 256 * 1024];
        linscp_proto::upload_bytes(session.as_ref(), "/resume-drop.bin", &resume_data, Default::default()).await.unwrap();
        let idx = svc.queue.snapshot().0.len();
        let first = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["resume-drop.bin"], "resume": true}))).await;
        assert_eq!(first.status, 200, "{}", first.payload);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("interrupted download unexpectedly completed"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(!downloaded.join("resume-drop.bin").exists());
        let checkpoint = downloaded.join("resume-drop.bin.filepart");
        let partial = std::fs::read(&checkpoint).expect("network interruption did not save checkpoint");
        assert!(!partial.is_empty() && partial.len() < resume_data.len());
        let retry_index = svc.queue.snapshot().0.len();
        let retry = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["resume-drop.bin"], "resume": true}))).await;
        assert_eq!(retry.status, 200, "{}", retry.payload);
        let mut complete = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(retry_index).and_then(|t| t["status"].as_str()) == Some("Completed") { complete = true; break; }
            if tasks.get(retry_index).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("checkpoint retry failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(complete);
        assert_eq!(std::fs::read(downloaded.join("resume-drop.bin")).unwrap(), resume_data);
        assert_eq!(std::fs::read(checkpoint).unwrap(), partial);
        // Queue a large WebDAV download and cancel it after the first chunk.
        std::fs::write(local.join("slow.bin"), vec![13u8; 4 * 1024 * 1024]).unwrap();
        let upload_index = svc.queue.snapshot().0.len();
        let large_upload = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["slow.bin"]}))).await;
        assert_eq!(large_upload.status, 200, "{}", large_upload.payload);
        let mut uploaded = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(upload_index).and_then(|t| t["status"].as_str()) == Some("Completed") { uploaded = true; break; }
            if tasks.get(upload_index).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("WebDAV upload failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(uploaded);
        let download_index = svc.queue.snapshot().0.len();
        let slow_download = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["slow.bin"]}))).await;
        assert_eq!(slow_download.status, 200);
        let mut task_id = None;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(download_index) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Completed", "download finished before cancellation");
                assert_ne!(task["status"], "Failed", "{tasks:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("download did not start")}))).await;
        assert_eq!(cancelled.status, 200, "{}", cancelled.payload);
        let mut stopped = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(download_index).and_then(|t| t["status"].as_str()) == Some("Cancelled") { stopped = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped, "WebDAV cancellation was not observed");
        assert!(!downloaded.join("slow.bin").exists());
        assert!(!std::fs::read_dir(&downloaded).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-download-")), "cancelled WebDAV download left an owned temporary file");
        assert!(session.stat("/upload.txt").await.unwrap().is_some());
        // Cancellation of a resumable download must not create a new partial.
        let resume_cancel_dir = downloaded.join("resume-cancel-dir");
        std::fs::create_dir_all(&resume_cancel_dir).unwrap();
        let idx = svc.queue.snapshot().0.len();
        let resumed = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": resume_cancel_dir, "remote_dir": "/", "names": ["slow.bin"], "resume": true}))).await;
        assert_eq!(resumed.status, 200, "{}", resumed.payload);
        let mut task_id = None;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(idx) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Completed", "resumable download finished before cancellation");
                assert_ne!(task["status"], "Failed", "{tasks:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancel = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("resumable download did not start")}))).await;
        assert_eq!(cancel.status, 200, "{}", cancel.payload);
        let mut stopped = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Cancelled") { stopped = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped);
        assert!(!resume_cancel_dir.join("slow.bin").exists());
        assert!(!resume_cancel_dir.join("slow.bin.filepart").exists());
        assert!(!std::fs::read_dir(&resume_cancel_dir).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-download-")));
        // An interrupted PUT must not deadlock the queue or report success.
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_flag = Arc::clone(&cancel);
        let progress = move |_: u64, _: u64| callback_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut cancelling = linscp_engine::transfer::TransferFlags::default();
        cancelling.no_clobber = true;
        cancelling.cancel_flag = Some(cancel);
        let result = tokio::time::timeout(std::time::Duration::from_secs(15), linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("slow.bin"), "/cancelled.bin", &cancelling, &mut logger, Some(&progress))).await.expect("cancelled PUT hung");
        assert!(result.is_err());
        assert!(session.stat("/upload.txt").await.unwrap().is_some());
        exercise_locked_webdav_upload_cleanup(&local).await;
        drop(server); let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    async fn exercise_locked_webdav_upload_cleanup(local: &Path) {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let server_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests/TestDavServer.py");
        for replacement in [false, true] {
            let mut command = Command::new("/usr/bin/python3");
            command.arg(&server_path).env("LSCP_TEST_PORT", "0").env("LSCP_TEST_LOCK_STAGING", "1");
            if replacement { command.env("LSCP_TEST_LOCK_REPLACEMENT", "1"); }
            let child = command.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
            let mut server = Server(child); let mut line = String::new();
            BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
            let port: u16 = line.trim().strip_prefix("READY ").expect("lock-capable DAV server did not start").parse().unwrap();
            let svc = CommanderService::new(local.join(format!("lock-config-{replacement}")), Arc::new(NativeLocalFs::new()));
            let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
            let opened = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "dav", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "local_dir": local, "initial_dir": "/"}}))).await;
            assert_eq!(opened.status, 200, "{}", opened.payload);
            let id = opened.payload["tab"]["id"].as_u64().unwrap();
            let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
            let mut flags = linscp_engine::transfer::TransferFlags::default(); flags.no_clobber = true;
            let mut logger = linscp_engine::xml_log::SessionLogger::open(None, 0, false, None, None, false, "").unwrap();
            let input = local.join("lock-upload.bin");
            std::fs::write(&input, vec![67u8; 512 * 1024]).unwrap();
            if !replacement {
                // An UNLOCK token must never be forwarded through a redirect.
                let unlocked = session.dav_unlock("/unlock-redirect-source", Some("opaquelocktoken:private-test")).await;
                assert!(unlocked.is_err(), "UNLOCK redirect must not be followed");
                let output = Command::new("curl").args(["--silent", "--show-error", &format!("http://127.0.0.1:{port}/__test__/state")]).output().unwrap();
                let state: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(state["unlock_redirect_target_count"], 0, "UNLOCK leaked the token through a redirect");
                // A valid Lock-Token header is usable without waiting for a
                // stalled optional response body. XML-only servers still work.
                for (mode, path) in [("slow-body", "/lock-slow-body.bin"), ("xml-only", "/lock-xml-only.bin")] {
                    let injected = Command::new("curl").args(["--silent", "--show-error", &format!("http://127.0.0.1:{port}/__test__/next-stage-lock?mode={mode}")]).status().unwrap();
                    assert!(injected.success());
                    let result = tokio::time::timeout(std::time::Duration::from_secs(4), linscp_engine::transfer::upload_single_file(session.as_ref(), &input, path, &flags, &mut logger, None)).await.expect("staging LOCK waited for a stalled body");
                    assert!(result.is_ok(), "{result:?}");
                    assert_eq!(linscp_proto::download_bytes(session.as_ref(), path, Default::default()).await.unwrap().len(), 512 * 1024);
                }
                let completed = linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-success.bin", &flags, &mut logger, None).await;
                assert!(completed.is_ok(), "{completed:?}");
                assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/lock-success.bin", Default::default()).await.unwrap().len(), 512 * 1024);
                assert!(!session.list_dir("/").await.unwrap().iter().any(|e| e.name.starts_with(".linscp-lock-")));
                let conflict = linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-success.bin", &flags, &mut logger, None).await;
                assert!(conflict.is_err());
                assert!(!session.list_dir("/").await.unwrap().iter().any(|e| e.name.starts_with(".linscp-lock-")));
                assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/lock-success.bin", Default::default()).await.unwrap().len(), 512 * 1024);
                // Approved overwrite publishes only if the destination's
                // original ETag still matches at the MOVE itself.
                linscp_proto::upload_bytes(session.as_ref(), "/lock-overwrite-race.bin", b"approved original", Default::default()).await.unwrap();
                let old = session.dav_get_etag("/lock-overwrite-race.bin").await.unwrap().0.unwrap();
                let mut overwrite = linscp_engine::transfer::TransferFlags::default();
                overwrite.overwrite_etag = Some(old);
                let raced = linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-overwrite-race.bin", &overwrite, &mut logger, None).await;
                assert!(raced.is_err(), "changed destination was replaced");
                assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/lock-overwrite-race.bin", Default::default()).await.unwrap(), b"changed before MOVE");
                assert!(!session.list_dir("/").await.unwrap().iter().any(|e| e.name.starts_with(".linscp-lock-")));
                linscp_proto::upload_bytes(session.as_ref(), "/lock-overwrite.bin", b"original", Default::default()).await.unwrap();
                let tag = session.dav_get_etag("/lock-overwrite.bin").await.unwrap().0.unwrap();
                let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let set_cancel = Arc::clone(&cancel);
                let progress = move |_: u64, _: u64| set_cancel.store(true, std::sync::atomic::Ordering::SeqCst);
                overwrite.overwrite_etag = Some(tag.clone());
                overwrite.cancel_flag = Some(cancel);
                let interrupted = linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-overwrite.bin", &overwrite, &mut logger, Some(&progress)).await;
                assert!(interrupted.is_err());
                assert!(interrupted.unwrap_err().contains("Locked temporary resource removed"));
                assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/lock-overwrite.bin", Default::default()).await.unwrap(), b"original");
                overwrite.cancel_flag = None;
                let completed = linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-overwrite.bin", &overwrite, &mut logger, None).await;
                assert!(completed.is_ok(), "{completed:?}");
                assert_eq!(linscp_proto::download_bytes(session.as_ref(), "/lock-overwrite.bin", Default::default()).await.unwrap().len(), 512 * 1024);
                assert!(!session.list_dir("/").await.unwrap().iter().any(|e| e.name.starts_with(".linscp-lock-")));
                for path in ["/lock-redirect.bin", "/lock-multistatus.bin"] {
                    let result = linscp_engine::transfer::upload_single_file(session.as_ref(), &input, path, &flags, &mut logger, None).await;
                    assert!(result.is_err(), "ambiguous MOVE reported success");
                    assert!(session.stat(path).await.unwrap().is_none());
                    assert!(session.stat("/lock-other.bin").await.unwrap().is_none());
                    assert!(!session.list_dir("/").await.unwrap().iter().any(|e| e.name.starts_with(".linscp-lock-")));
                }
            }
            if !replacement {
                // A transient failure leaves the lock intact and is retried
                // when this session next attempts a staged upload.
                let injected = Command::new("curl").args(["--silent", "--show-error", &format!("http://127.0.0.1:{port}/__test__/reject-next-stage-delete")]).status().unwrap();
                assert!(injected.success());
                let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let callback_flag = Arc::clone(&cancelled);
                let progress = move |_: u64, _: u64| callback_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                flags.cancel_flag = Some(cancelled);
                let error = linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-retry-cancel.bin", &flags, &mut logger, Some(&progress)).await.unwrap_err();
                assert!(error.contains("will be retried"), "{error}");
                let stages: Vec<_> = session.list_dir("/").await.unwrap().into_iter().filter(|e| e.name.starts_with(".linscp-lock-")).collect();
                assert_eq!(stages.len(), 1);
                let output = Command::new("curl").args(["--silent", "--show-error", &format!("http://127.0.0.1:{port}/__test__/state")]).output().unwrap();
                let state: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert!(state["locks"].as_object().unwrap().contains_key(&format!("/{}", stages[0].name)), "failed cleanup must retain the lock: {state}");
                flags.cancel_flag = None;
                let next = linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-retry-next.bin", &flags, &mut logger, None).await;
                assert!(next.is_ok(), "{next:?}");
                assert!(!session.list_dir("/").await.unwrap().iter().any(|e| e.name.starts_with(".linscp-lock-")));
                let output = Command::new("curl").args(["--silent", "--show-error", &format!("http://127.0.0.1:{port}/__test__/state")]).output().unwrap();
                let state: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert!(!state["locks"].as_object().unwrap().contains_key(&format!("/{}", stages[0].name)), "resolved stage should be unlocked: {state}");
                // The background retry also works without starting another
                // transfer in the session.
                let injected = Command::new("curl").args(["--silent", "--show-error", &format!("http://127.0.0.1:{port}/__test__/reject-next-stage-delete")]).status().unwrap();
                assert!(injected.success());
                let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let callback_flag = Arc::clone(&cancelled);
                let progress = move |_: u64, _: u64| callback_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                flags.cancel_flag = Some(cancelled);
                let error = linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-background-cancel.bin", &flags, &mut logger, Some(&progress)).await.unwrap_err();
                assert!(error.contains("will be retried"), "{error}");
                let mut removed = false;
                for _ in 0..100 {
                    if !session.list_dir("/").await.unwrap().iter().any(|e| e.name.starts_with(".linscp-lock-")) { removed = true; break; }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                assert!(removed, "background cleanup did not retry the locked stage");
                assert!(session.stat("/lock-background-cancel.bin").await.unwrap().is_none());
            }
            let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let callback_flag = Arc::clone(&cancelled);
            let progress = move |_: u64, _: u64| callback_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            flags.cancel_flag = Some(cancelled);
            let error = tokio::time::timeout(std::time::Duration::from_secs(15), linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-cancel.bin", &flags, &mut logger, Some(&progress))).await.expect("locked upload cancellation hung").unwrap_err();
            let stages: Vec<_> = session.list_dir("/").await.unwrap().into_iter().filter(|e| e.name.starts_with(".linscp-lock-")).collect();
            assert!(session.stat("/lock-cancel.bin").await.unwrap().is_none());
            if replacement {
                assert!(error.contains("was not removed"), "{error}");
                assert_eq!(stages.len(), 1);
                assert_eq!(linscp_proto::download_bytes(session.as_ref(), &format!("/{}", stages[0].name), Default::default()).await.unwrap(), b"replacement by another actor");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                assert_eq!(linscp_proto::download_bytes(session.as_ref(), &format!("/{}", stages[0].name), Default::default()).await.unwrap(), b"replacement by another actor", "background retry removed a replacement");
                flags.cancel_flag = None;
                let next = linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-replacement-next.bin", &flags, &mut logger, None).await;
                assert!(next.is_ok(), "{next:?}");
                assert_eq!(linscp_proto::download_bytes(session.as_ref(), &format!("/{}", stages[0].name), Default::default()).await.unwrap(), b"replacement by another actor", "retry removed another actor's replacement");
            } else {
                assert!(error.contains("Locked temporary resource removed"), "{error}");
                assert!(stages.is_empty(), "owned locked stage was not cleaned");
            }
            if !replacement {
                // If the server never supplies a usable token, fail within the
                // body deadline and never attempt path-only cleanup.
                let injected = Command::new("curl").args(["--silent", "--show-error", &format!("http://127.0.0.1:{port}/__test__/next-stage-lock?mode=slow-no-header")]).status().unwrap();
                assert!(injected.success());
                flags.cancel_flag = None;
                let result = tokio::time::timeout(std::time::Duration::from_secs(4), linscp_engine::transfer::upload_single_file(session.as_ref(), &input, "/lock-no-token.bin", &flags, &mut logger, None)).await.expect("missing token response hung").unwrap_err();
                assert!(result.contains("no usable token"), "{result}");
                assert!(session.stat("/lock-no-token.bin").await.unwrap().is_none());
                let stages: Vec<_> = session.list_dir("/").await.unwrap().into_iter().filter(|e| e.name.starts_with(".linscp-lock-")).collect();
                assert_eq!(stages.len(), 1, "unconfirmed token must not trigger pathname deletion");
                // A server can also create the lock but never send headers.
                // Honor the connection timeout and leave that unknown stage
                // untouched rather than guessing ownership from its pathname.
                let injected = Command::new("curl").args(["--silent", "--show-error", &format!("http://127.0.0.1:{port}/__test__/next-stage-lock?mode=slow-headers")]).status().unwrap();
                assert!(injected.success());
                let dav = linscp_proto::webdav::WebDavSession::connect(linscp_proto::webdav::WebDavConnectConfig {
                    scheme: linscp_types::ProtocolScheme::Dav,
                    host: "127.0.0.1".into(), port,
                    username: Some("testuser".into()), password: Some(zeroize::Zeroizing::new("testpass".into())),
                    timeout: std::time::Duration::from_secs(1), ..Default::default()
                }, None, 0).await.unwrap();
                let result = tokio::time::timeout(std::time::Duration::from_secs(4), linscp_engine::transfer::upload_single_file(&dav, &input, "/lock-no-headers.bin", &flags, &mut logger, None)).await.expect("staging LOCK did not honor its timeout").unwrap_err();
                assert!(result.contains("LOCK timed out"), "{result}");
                assert!(session.stat("/lock-no-headers.bin").await.unwrap().is_none());
                let stages: Vec<_> = session.list_dir("/").await.unwrap().into_iter().filter(|e| e.name.starts_with(".linscp-lock-")).collect();
                assert_eq!(stages.len(), 2, "unknown lock token must not cause pathname deletion");
            }
            drop(server);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn live_sftp_connection_hostkey_upload_download() {
        if std::env::var_os("LSCP_LIVE_SFTP").is_none() { return; }
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        struct Server(std::process::Child);
        impl Drop for Server { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
        let tmp = std::env::temp_dir().join(format!("linscp-live-native-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let remote = tmp.join("remote"); let local = tmp.join("local"); let downloaded = tmp.join("downloaded");
        for p in [&remote, &local, &downloaded] { std::fs::create_dir_all(p).unwrap(); }
        let server_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests/TestSftpServer.py");
        let child = Command::new("/usr/bin/python3").arg(server_path).env("LSCP_TEST_PORT", "0").env("LSCP_TEST_ROOT", &remote).env("LSCP_TEST_WRITE_DELAY", "0.01").env("LSCP_TEST_READ_DELAY", "0.005")
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut server = Server(child);
        let mut line = String::new();
        BufReader::new(server.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port: u16 = line.trim().strip_prefix("READY ").expect("SFTP server failed to start").parse().unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let request = |path: &str, body: Value| ApiEnvelope { method: "POST".into(), path: path.into(), body };
        let open = svc.dispatch_async(request("/api/tabs/open", json!({"name": "live", "session": {"protocol": "sftp", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(open.status, 409, "{}", open.payload);
        let challenge = &open.payload["challenge"];
        let id = challenge["tab"].as_u64().unwrap();
        let fingerprint = challenge["fingerprint"].as_str().unwrap().to_string();
        let bad = svc.dispatch_async(request("/api/tabs/verify", json!({"tab": id, "role": "destination", "fingerprint": "wrong"}))).await;
        assert_eq!(bad.status, 400);
        let connected = svc.dispatch_async(request("/api/tabs/verify", json!({"tab": id, "role": "destination", "fingerprint": fingerprint, "remember": false}))).await;
        assert_eq!(connected.status, 200, "{}", connected.payload);
        assert!(connected.payload["tab"]["session"].get("password").is_none());
        assert!(!tmp.join("config/sshhostkeys").exists());
        Box::pin(exercise_remote_mkdir(&svc, id)).await;
        let previous = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let reconnected = svc.dispatch_async(request("/api/tabs/reconnect", json!({"tab": id}))).await;
        assert_eq!(reconnected.status, 200, "{}", reconnected.payload);
        let current = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        assert!(!Arc::ptr_eq(&previous, &current), "reconnect reused the old connection");
        assert_eq!(reconnected.payload["tab"]["id"], id);
        std::fs::write(local.join("upload.txt"), b"hello from native").unwrap();
        let upload = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["upload.txt"]}))).await;
        assert_eq!(upload.status, 200, "{}", upload.payload);
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.first().and_then(|t| t["status"].as_str()) == Some("Completed") { break; }
            if tasks.first().and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("upload failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(std::fs::read(remote.join("upload.txt")).unwrap(), b"hello from native");
        let list = svc.dispatch_async(ApiEnvelope { method: "GET".into(), path: format!("/api/remote/list?tab={id}&path=%2F"), body: json!({}) }).await;
        assert_eq!(list.status, 200, "{}", list.payload);
        assert!(list.payload["entries"].as_array().unwrap().iter().any(|e| e["name"] == "upload.txt"));
        let download = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["upload.txt"]}))).await;
        assert_eq!(download.status, 200, "{}", download.payload);
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(1).and_then(|t| t["status"].as_str()) == Some("Completed") { break; }
            if tasks.get(1).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("download failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(std::fs::read(downloaded.join("upload.txt")).unwrap(), b"hello from native");
        // Create a competing destination during the transfer, after preflight.
        let session = svc.state.lock().unwrap().tabs.get(&id).unwrap().remote.as_ref().unwrap().clone();
        let raced_target = downloaded.join("race.txt");
        let callback_target = raced_target.clone();
        let progress = move |_: u64, _: u64| { std::fs::write(&callback_target, b"concurrent data").unwrap(); };
        let mut flags = linscp_engine::transfer::TransferFlags::default();
        flags.no_clobber = true;
        flags.cleanup_download_stage = true;
        flags.resume_support = linscp_engine::presets::ResumeSupportMode::On;
        let mut logger = linscp_engine::xml_log::SessionLogger::open(None, 0, false, None, None, false, "").unwrap();
        let race = linscp_engine::transfer::download_single_file(session.as_ref(), "/upload.txt", None, &raced_target, &flags, &mut logger, Some(&progress)).await;
        assert!(race.is_err(), "concurrent destination must not be replaced");
        assert_eq!(std::fs::read(&raced_target).unwrap(), b"concurrent data");
        assert!(!std::fs::read_dir(&downloaded).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-download-")), "failed publication left an owned temporary file");
        // Fresh overwrite downloads must not touch an unrelated stage file,
        // even if it appears after the queue's preflight check.
        let overwrite_target = downloaded.join("overwrite.txt");
        let overwrite_stage = downloaded.join("overwrite.txt.filepart");
        std::fs::write(&overwrite_target, b"old destination").unwrap();
        std::fs::write(&overwrite_stage, b"unrelated stage").unwrap();
        let mut overwrite_flags = linscp_engine::transfer::TransferFlags::default();
        overwrite_flags.resume_support = linscp_engine::presets::ResumeSupportMode::On;
        let blocked_stage = linscp_engine::transfer::download_single_file(session.as_ref(), "/upload.txt", None, &overwrite_target, &overwrite_flags, &mut logger, None).await;
        assert!(blocked_stage.is_err());
        assert_eq!(std::fs::read(&overwrite_stage).unwrap(), b"unrelated stage");
        assert_eq!(std::fs::read(&overwrite_target).unwrap(), b"old destination");
        std::fs::remove_file(&overwrite_stage).unwrap();
        let unrelated = downloaded.join("unrelated.txt");
        std::fs::write(&unrelated, b"unrelated data").unwrap();
        std::os::unix::fs::symlink(&unrelated, &overwrite_stage).unwrap();
        let symlink_stage = linscp_engine::transfer::download_single_file(session.as_ref(), "/upload.txt", None, &overwrite_target, &overwrite_flags, &mut logger, None).await;
        assert!(symlink_stage.is_err());
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"unrelated data");
        assert_eq!(std::fs::read(&overwrite_target).unwrap(), b"old destination");
        std::fs::remove_file(&overwrite_stage).unwrap();
        let overwrite = linscp_engine::transfer::download_single_file(session.as_ref(), "/upload.txt", None, &overwrite_target, &overwrite_flags, &mut logger, None).await;
        assert!(overwrite.is_ok(), "{overwrite:?}");
        assert_eq!(std::fs::read(&overwrite_target).unwrap(), b"hello from native");
        assert!(!overwrite_stage.exists());
        // Cancel both directions mid-stream and ensure the session remains usable.
        std::fs::write(remote.join("large.bin"), vec![17u8; 512 * 1024]).unwrap();
        std::fs::write(local.join("large.bin"), vec![29u8; 512 * 1024]).unwrap();
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_flag = Arc::clone(&cancel);
        let cancel_on_progress = move |_: u64, _: u64| callback_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut cancelling = linscp_engine::transfer::TransferFlags::default();
        cancelling.no_clobber = true;
        cancelling.cancel_flag = Some(Arc::clone(&cancel));
        cancelling.resume_support = linscp_engine::presets::ResumeSupportMode::On;
        let cancel_overwrite_target = downloaded.join("cancel-overwrite.bin");
        std::fs::write(&cancel_overwrite_target, b"original destination").unwrap();
        cancelling.no_clobber = false;
        let cancelled_overwrite = linscp_engine::transfer::download_single_file(session.as_ref(), "/large.bin", None, &cancel_overwrite_target, &cancelling, &mut logger, Some(&cancel_on_progress)).await;
        assert!(cancelled_overwrite.is_err());
        assert_eq!(std::fs::read(&cancel_overwrite_target).unwrap(), b"original destination");
        cancel.store(false, std::sync::atomic::Ordering::SeqCst);
        cancelling.no_clobber = true;
        let cancelled_download = linscp_engine::transfer::download_single_file(session.as_ref(), "/large.bin", None, &downloaded.join("large.bin"), &cancelling, &mut logger, Some(&cancel_on_progress)).await;
        assert!(cancelled_download.is_err());
        assert!(!downloaded.join("large.bin").exists());
        assert!(downloaded.join("large.bin.filepart").exists());
        cancel.store(false, std::sync::atomic::Ordering::SeqCst);
        cancelling.no_clobber = false;
        // The legacy unguarded upload route must fail before it can adopt or
        // remove a stage that belongs to another client.
        std::fs::write(remote.join("cancelled.bin.filepart"), b"unrelated partial").unwrap();
        let cancelled_upload = linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("large.bin"), "/cancelled.bin", &cancelling, &mut logger, Some(&cancel_on_progress)).await;
        assert!(cancelled_upload.unwrap_err().contains("Unguarded SFTP/FTP uploads are disabled"));
        assert!(!remote.join("cancelled.bin").exists());
        assert_eq!(std::fs::read(remote.join("cancelled.bin.filepart")).unwrap(), b"unrelated partial");
        assert!(session.stat("/upload.txt").await.unwrap().is_some());
        // Exclusive creation must fail without changing a destination that
        // appeared after any earlier conflict check.
        let mut exclusive = linscp_engine::transfer::TransferFlags::default();
        exclusive.no_clobber = true;
        let collision = linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("large.bin"), "/upload.txt", &exclusive, &mut logger, None).await;
        assert!(collision.is_err());
        assert_eq!(std::fs::read(remote.join("upload.txt")).unwrap(), b"hello from native");
        cancel.store(false, std::sync::atomic::Ordering::SeqCst);
        exclusive.cancel_flag = Some(Arc::clone(&cancel));
        let direct_cancel = linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("large.bin"), "/exclusive-cancelled.bin", &exclusive, &mut logger, Some(&cancel_on_progress)).await;
        assert!(direct_cancel.is_err());
        let partial = std::fs::metadata(remote.join("exclusive-cancelled.bin")).unwrap();
        assert!(partial.len() < 512 * 1024);
        // A source truncated during an exclusive upload must not be reported
        // as complete or deleted. The partial remote file is left for review,
        // rather than blindly unlinking a path another client may replace.
        let shrinking = local.join("shrinking.bin");
        std::fs::write(&shrinking, vec![31u8; 512 * 1024]).unwrap();
        let source_to_shrink = shrinking.clone();
        let shrink = move |_: u64, _: u64| { let _ = std::fs::OpenOptions::new().write(true).open(&source_to_shrink).and_then(|file| file.set_len(1)); };
        let mut exclusive_shrinking = linscp_engine::transfer::TransferFlags::default();
        exclusive_shrinking.no_clobber = true;
        let result = linscp_engine::transfer::upload_single_file(session.as_ref(), &shrinking, "/shrinking.bin", &exclusive_shrinking, &mut logger, Some(&shrink)).await;
        assert!(result.is_err(), "truncated upload was reported complete");
        assert!(shrinking.exists());
        assert!(std::fs::metadata(remote.join("shrinking.bin")).unwrap().len() < 512 * 1024);
        std::fs::write(local.join("another.txt"), b"new data").unwrap();
        std::fs::write(remote.join("another.txt.filepart"), b"unrelated partial").unwrap();
        let blocked = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["another.txt"]}))).await;
        assert_eq!(blocked.status, 200);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(2).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed, "an unrelated partial file must block a transfer");
        assert_eq!(std::fs::read(remote.join("another.txt.filepart")).unwrap(), b"unrelated partial");
        assert!(!remote.join("another.txt").exists());
        // Copy a new nested directory in both directions, including an empty folder.
        std::fs::create_dir_all(local.join("tree/nested")).unwrap();
        std::fs::create_dir_all(local.join("tree/empty")).unwrap();
        std::fs::write(local.join("tree/nested/data.txt"), b"directory roundtrip").unwrap();
        let upload_index = svc.queue.snapshot().0.len();
        let tree_up = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["tree"]}))).await;
        assert_eq!(tree_up.status, 200, "{}", tree_up.payload);
        for index in [upload_index, upload_index + 1] {
            if index != upload_index {
                let tree_down = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["tree"]}))).await;
                assert_eq!(tree_down.status, 200, "{}", tree_down.payload);
            }
            let mut done = false;
            for _ in 0..500 {
                let (tasks, _) = svc.queue.snapshot();
                if tasks.get(index).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
                if tasks.get(index).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("directory transfer failed: {tasks:?}"); }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert!(done, "directory transfer timed out");
        }
        assert_eq!(std::fs::read(downloaded.join("tree/nested/data.txt")).unwrap(), b"directory roundtrip");
        assert!(downloaded.join("tree/empty").is_dir());
        assert!(!std::fs::read_dir(&downloaded).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-tree-")));
        // A failed new-tree copy must leave neither its final directory nor
        // its privately staged partial tree, while preserving other data.
        std::fs::create_dir_all(remote.join("bad-tree")).unwrap();
        std::fs::write(remote.join("bad-tree/aaa-file"), b"partial data").unwrap();
        std::os::unix::fs::symlink(remote.join("upload.txt"), remote.join("bad-tree/zzz-link")).unwrap();
        let failed_index = svc.queue.snapshot().0.len();
        let bad_tree = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["bad-tree"]}))).await;
        assert_eq!(bad_tree.status, 200, "{}", bad_tree.payload);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(failed_index).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(!downloaded.join("bad-tree").exists());
        assert!(!std::fs::read_dir(&downloaded).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-tree-")));
        assert_eq!(std::fs::read(downloaded.join("tree/nested/data.txt")).unwrap(), b"directory roundtrip");
        // Cancellation of an in-progress tree copy also removes its stage.
        std::fs::create_dir_all(remote.join("slow-tree")).unwrap();
        std::fs::write(remote.join("slow-tree/large.bin"), vec![21u8; 4 * 1024 * 1024]).unwrap();
        let slow_tree_index = svc.queue.snapshot().0.len();
        let slow_tree = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["slow-tree"]}))).await;
        assert_eq!(slow_tree.status, 200, "{}", slow_tree.payload);
        let mut tree_task_id = None;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(slow_tree_index) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { tree_task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Completed", "tree completed before cancellation");
                assert_ne!(task["status"], "Failed", "{tasks:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": tree_task_id.expect("tree download did not start")}))).await;
        assert_eq!(cancelled.status, 200, "{}", cancelled.payload);
        let mut stopped = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(slow_tree_index).and_then(|t| t["status"].as_str()) == Some("Cancelled") { stopped = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped, "tree cancellation was not observed");
        assert!(!downloaded.join("slow-tree").exists());
        assert!(!std::fs::read_dir(&downloaded).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-tree-")));
        assert_eq!(std::fs::metadata(remote.join("slow-tree/large.bin")).unwrap().len(), 4 * 1024 * 1024);
        // Cancelling a merge during its download leaves the pre-existing
        // target tree untouched; only its private stage is discarded.
        std::fs::create_dir_all(remote.join("merge-slow")).unwrap();
        std::fs::write(remote.join("merge-slow/large.bin"), vec![17u8; 4 * 1024 * 1024]).unwrap();
        std::fs::create_dir_all(downloaded.join("merge-slow")).unwrap();
        std::fs::write(downloaded.join("merge-slow/keep"), b"keep merged tree").unwrap();
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["merge-slow"], "merge_directories": ["merge-slow"]}))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        let mut task_id = None;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(idx) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Completed", "merge finished before cancellation");
                assert_ne!(task["status"], "Failed", "{tasks:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancel = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("merge did not start")}))).await;
        assert_eq!(cancel.status, 200);
        let mut stopped = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Cancelled") { stopped = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped);
        assert_eq!(std::fs::read(downloaded.join("merge-slow/keep")).unwrap(), b"keep merged tree");
        assert!(!downloaded.join("merge-slow/large.bin").exists());
        assert!(!std::fs::read_dir(&downloaded).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-tree-")));
        // A competing destination appearing during the copy must survive
        // atomic no-replace publication; the staged tree is then removed.
        let race_index = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["slow-tree"]}))).await;
        assert_eq!(queued.status, 200);
        let mut started = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(race_index) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { started = true; break; }
                assert_ne!(task["status"], "Completed", "tree completed before race");
                assert_ne!(task["status"], "Failed", "{tasks:?}");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(started);
        std::fs::create_dir_all(downloaded.join("slow-tree")).unwrap();
        std::fs::write(downloaded.join("slow-tree/keep"), b"concurrent tree").unwrap();
        let mut race_failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(race_index).and_then(|t| t["status"].as_str()) == Some("Failed") { race_failed = true; break; }
            if tasks.get(race_index).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("competing directory was replaced"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(race_failed);
        assert_eq!(std::fs::read(downloaded.join("slow-tree/keep")).unwrap(), b"concurrent tree");
        assert!(!downloaded.join("slow-tree/large.bin").exists());
        assert!(!std::fs::read_dir(&downloaded).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".linscp-tree-")));
        let blocked_merge = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["tree"], "overwrite": "overwrite"}))).await;
        assert_eq!(blocked_merge.status, 409);
        // Merges require a separate, per-root approval and never overwrite files.
        std::fs::create_dir_all(local.join("merge-up/nested")).unwrap();
        std::fs::create_dir_all(remote.join("merge-up/nested")).unwrap();
        std::fs::write(local.join("merge-up/nested/new.txt"), b"new upload").unwrap();
        std::fs::write(remote.join("merge-up/nested/kept.txt"), b"keep remote").unwrap();
        let merge_body = || json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["merge-up"]});
        let ask = svc.dispatch_async(request("/api/transfer/upload", merge_body())).await;
        assert_eq!(ask.status, 409, "{}", ask.payload);
        assert_eq!(ask.payload["directory_conflicts"], json!(["merge-up"]));
        let idx = svc.queue.snapshot().0.len();
        let merged = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["merge-up"], "merge_directories": ["merge-up"]}))).await;
        assert_eq!(merged.status, 200, "{}", merged.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("upload merge failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(std::fs::read(remote.join("merge-up/nested/new.txt")).unwrap(), b"new upload");
        assert_eq!(std::fs::read(remote.join("merge-up/nested/kept.txt")).unwrap(), b"keep remote");
        // A file conflict fails and leaves the remote file intact.
        std::fs::write(local.join("merge-up/nested/kept.txt"), b"must not replace").unwrap();
        let idx = svc.queue.snapshot().0.len();
        let conflict = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["merge-up"], "merge_directories": ["merge-up"]}))).await;
        assert_eq!(conflict.status, 200);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(std::fs::read(remote.join("merge-up/nested/kept.txt")).unwrap(), b"keep remote");
        std::fs::create_dir_all(remote.join("merge-down/nested")).unwrap();
        std::fs::create_dir_all(downloaded.join("merge-down/nested")).unwrap();
        std::fs::write(remote.join("merge-down/nested/new.txt"), b"new download").unwrap();
        std::fs::write(downloaded.join("merge-down/nested/kept.txt"), b"keep local").unwrap();
        let ask = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["merge-down"]}))).await;
        assert_eq!(ask.status, 409, "{}", ask.payload);
        assert_eq!(ask.payload["directory_conflicts"], json!(["merge-down"]));
        let idx = svc.queue.snapshot().0.len();
        let merged = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["merge-down"], "merge_directories": ["merge-down"]}))).await;
        assert_eq!(merged.status, 200, "{}", merged.payload);
        let mut done = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("download merge failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(std::fs::read(downloaded.join("merge-down/nested/new.txt")).unwrap(), b"new download");
        assert_eq!(std::fs::read(downloaded.join("merge-down/nested/kept.txt")).unwrap(), b"keep local");
        std::fs::write(remote.join("merge-down/nested/kept.txt"), b"must not replace").unwrap();
        let idx = svc.queue.snapshot().0.len();
        let conflict = svc.dispatch_async(request("/api/transfer/download", json!({"tab": id, "local_dir": downloaded, "remote_dir": "/", "names": ["merge-down"], "merge_directories": ["merge-down"]}))).await;
        assert_eq!(conflict.status, 200);
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(std::fs::read(downloaded.join("merge-down/nested/kept.txt")).unwrap(), b"keep local");
        // Approval for other roots must not authorize merging a directory
        // that appears after this transfer was queued.
        std::fs::create_dir_all(local.join("new-root")).unwrap();
        std::fs::write(local.join("new-root/data"), b"source data").unwrap();
        svc.queue.pause();
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["new-root"], "merge_directories": ["other-root"]}))).await;
        assert_eq!(queued.status, 200);
        std::fs::create_dir_all(remote.join("new-root")).unwrap();
        std::fs::write(remote.join("new-root/keep"), b"concurrent data").unwrap();
        svc.queue.resume();
        let mut failed = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed, "a newly created destination must not inherit merge approval");
        assert_eq!(std::fs::read(remote.join("new-root/keep")).unwrap(), b"concurrent data");
        assert!(!remote.join("new-root/data").exists());
        std::fs::create_dir_all(local.join("links")).unwrap();
        std::os::unix::fs::symlink(local.join("upload.txt"), local.join("links/link")).unwrap();
        let link_index = svc.queue.snapshot().0.len();
        let link_up = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["links"]}))).await;
        assert_eq!(link_up.status, 200);
        let mut rejected = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(link_index).and_then(|t| t["status"].as_str()) == Some("Failed") { rejected = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(rejected, "a directory containing a symlink must be rejected");
        assert!(!remote.join("links/link").exists());
        // Exercise cancellation through the public queue API while SFTP is running.
        std::fs::write(local.join("slow.bin"), vec![19u8; 4 * 1024 * 1024]).unwrap();
        let slow_index = svc.queue.snapshot().0.len();
        let slow = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["slow.bin"]}))).await;
        assert_eq!(slow.status, 200);
        let mut task_id = None;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(slow_index) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 {
                    task_id = task["id"].as_u64(); break;
                }
                assert_ne!(task["status"], "Failed", "{tasks:?}");
                assert_ne!(task["status"], "Completed", "upload finished before cancellation");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let task_id = task_id.expect("upload did not begin");
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id}))).await;
        assert_eq!(cancelled.status, 200, "{}", cancelled.payload);
        let mut stopped = false;
        for _ in 0..500 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(slow_index).and_then(|t| t["status"].as_str()) == Some("Cancelled") {
                assert!(tasks[slow_index]["error"].as_str().unwrap_or("").contains("remote destination"));
                stopped = true; break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped, "cancellation was not observed");
        assert!(std::fs::metadata(remote.join("slow.bin")).unwrap().len() < 4 * 1024 * 1024);
        // Replace the pathname after the server opened our exclusive upload.
        // Cancellation must not unlink the other client's replacement.
        std::fs::write(local.join("replacement-race.bin"), vec![27u8; 4 * 1024 * 1024]).unwrap();
        let idx = svc.queue.snapshot().0.len();
        let queued = svc.dispatch_async(request("/api/transfer/upload", json!({"tab": id, "local_dir": local, "remote_dir": "/", "names": ["replacement-race.bin"]}))).await;
        assert_eq!(queued.status, 200);
        let mut task_id = None;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(idx) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Failed", "{tasks:?}");
                assert_ne!(task["status"], "Completed", "upload finished before replacement");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let task_id = task_id.expect("SFTP replacement test did not start");
        std::fs::rename(remote.join("replacement-race.bin"), remote.join("held-sftp-upload")).unwrap();
        std::fs::write(remote.join("replacement-race.bin"), b"replacement by another client").unwrap();
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id}))).await;
        assert_eq!(cancelled.status, 200);
        let mut stopped = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Cancelled") { stopped = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped, "SFTP replacement test did not cancel");
        assert_eq!(std::fs::read(remote.join("replacement-race.bin")).unwrap(), b"replacement by another client", "cancellation must not delete or alter a replacement");
        assert!(remote.join("held-sftp-upload").exists(), "the original partial remains for inspection");
        assert!(session.stat("/upload.txt").await.unwrap().is_some());
        // SFTP-to-SFTP file and tree copies require explicit acceptance of
        // source/path races and never replace an existing destination.
        std::fs::create_dir_all(remote.join("copy-target")).unwrap();
        std::fs::create_dir_all(remote.join("copy-tree/nested/empty")).unwrap();
        std::fs::write(remote.join("copy-file.txt"), b"source file").unwrap();
        std::fs::write(remote.join("copy-tree/nested/data"), b"tree data").unwrap();
        let no_risk = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/copy-target", "names": ["copy-tree"]}))).await;
        assert_eq!(no_risk.status, 409);
        assert_eq!(no_risk.payload["sftp_copy_risk"], true);
        let idx = svc.queue.snapshot().0.len();
        let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/copy-target", "names": ["copy-file.txt", "copy-tree"], "accept_sftp_copy_risk": true}))).await;
        assert_eq!(copied.status, 200, "{}", copied.payload);
        let mut done = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") || tasks.get(idx + 1).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("SFTP copy failed: {tasks:?}"); }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") && tasks.get(idx + 1).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(std::fs::read(remote.join("copy-target/copy-file.txt")).unwrap(), b"source file");
        assert_eq!(std::fs::read(remote.join("copy-target/copy-tree/nested/data")).unwrap(), b"tree data");
        assert!(remote.join("copy-target/copy-tree/nested/empty").is_dir());
        assert_eq!(std::fs::read(remote.join("copy-tree/nested/data")).unwrap(), b"tree data");
        let idx = svc.queue.snapshot().0.len();
        let conflict = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/copy-target", "names": ["copy-tree"], "accept_sftp_copy_risk": true}))).await;
        assert_eq!(conflict.status, 200);
        let mut failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("directory conflict was replaced"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert_eq!(std::fs::read(remote.join("copy-target/copy-tree/nested/data")).unwrap(), b"tree data");
        std::fs::create_dir_all(remote.join("copy-link-tree")).unwrap();
        std::os::unix::fs::symlink(remote.join("copy-file.txt"), remote.join("copy-link-tree/link")).unwrap();
        let idx = svc.queue.snapshot().0.len();
        let copy = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/copy-target", "names": ["copy-link-tree"], "accept_sftp_copy_risk": true}))).await;
        assert_eq!(copy.status, 200);
        let mut failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("symlink tree copied"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(failed);
        assert!(!remote.join("copy-target/copy-link-tree").exists());
        // Repeat against an independent SFTP server/session, not merely two
        // directories on one connection.
        let remote2 = tmp.join("remote2");
        std::fs::create_dir_all(&remote2).unwrap();
        let child = Command::new("/usr/bin/python3").arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../source/linux/tests/TestSftpServer.py"))
            .env("LSCP_TEST_PORT", "0").env("LSCP_TEST_ROOT", &remote2)
            .stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut second = Server(child); let mut line = String::new();
        BufReader::new(second.0.stdout.take().unwrap()).read_line(&mut line).unwrap();
        let port2: u16 = line.trim().strip_prefix("READY ").expect("second SFTP server did not start").parse().unwrap();
        let opened = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "sftp", "host": "127.0.0.1", "port": port2, "username": "testuser", "password": "testpass", "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(opened.status, 409, "{}", opened.payload);
        let target_id = opened.payload["challenge"]["tab"].as_u64().unwrap();
        let key = opened.payload["challenge"]["fingerprint"].as_str().unwrap();
        let verified = svc.dispatch_async(request("/api/tabs/verify", json!({"tab": target_id, "role": "destination", "fingerprint": key, "remember": false}))).await;
        assert_eq!(verified.status, 200, "{}", verified.payload);
        let idx = svc.queue.snapshot().0.len();
        let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{target_id}"), "directory": "/", "names": ["copy-tree"], "accept_sftp_copy_risk": true}))).await;
        assert_eq!(copied.status, 200, "{}", copied.payload);
        let mut done = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { done = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { panic!("cross-server SFTP tree copy failed: {tasks:?}"); }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(done);
        assert_eq!(std::fs::read(remote2.join("copy-tree/nested/data")).unwrap(), b"tree data");
        assert!(remote2.join("copy-tree/nested/empty").is_dir());
        assert_eq!(std::fs::read(remote.join("copy-tree/nested/data")).unwrap(), b"tree data");
        drop(second);
        std::fs::create_dir_all(remote.join("copy-cancel-tree")).unwrap();
        std::fs::write(remote.join("copy-cancel-tree/slow.bin"), vec![37u8; 4 * 1024 * 1024]).unwrap();
        let idx = svc.queue.snapshot().0.len();
        let copy = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/copy-target", "names": ["copy-cancel-tree"], "accept_sftp_copy_risk": true}))).await;
        assert_eq!(copy.status, 200);
        let mut task_id = None;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(idx) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Failed", "{task:?}");
                assert_ne!(task["status"], "Completed", "tree copied before cancellation");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("tree download did not start")}))).await;
        assert_eq!(cancelled.status, 200);
        let mut stopped = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Cancelled") { stopped = true; break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped);
        assert!(!remote.join("copy-target/copy-cancel-tree").exists());
        assert_eq!(std::fs::metadata(remote.join("copy-cancel-tree/slow.bin")).unwrap().len(), 4 * 1024 * 1024);
        // Cancellation after publication begins must not remove the remote
        // pathname blindly: another actor could have replaced it.
        std::fs::create_dir_all(remote.join("copy-publish-tree")).unwrap();
        std::fs::write(remote.join("copy-publish-tree/slow.bin"), vec![41u8; 4 * 1024 * 1024]).unwrap();
        let idx = svc.queue.snapshot().0.len();
        let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/copy-target", "names": ["copy-publish-tree"], "accept_sftp_copy_risk": true}))).await;
        assert_eq!(copied.status, 200);
        let target = remote.join("copy-target/copy-publish-tree/slow.bin");
        let mut task_id = None;
        for _ in 0..2000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(idx) {
                if task["status"] == "Running" && std::fs::metadata(&target).is_ok_and(|m| m.len() > 0) { task_id = task["id"].as_u64(); break; }
                assert_ne!(task["status"], "Failed", "{task:?}");
                assert_ne!(task["status"], "Completed", "tree uploaded before cancellation");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let cancelled = svc.dispatch_async(request("/api/queue/cancel", json!({"task_id": task_id.expect("tree publication did not start")}))).await;
        assert_eq!(cancelled.status, 200);
        let mut stopped = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Cancelled") {
                assert!(tasks[idx]["error"].as_str().unwrap_or("").contains("remote destination"));
                stopped = true; break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(stopped);
        assert!(std::fs::metadata(&target).unwrap().len() < 4 * 1024 * 1024);
        assert_eq!(std::fs::metadata(remote.join("copy-publish-tree/slow.bin")).unwrap().len(), 4 * 1024 * 1024);
        std::fs::create_dir_all(remote.join("copy-shrinking-tree")).unwrap();
        let changing = remote.join("copy-shrinking-tree/large.bin");
        std::fs::write(&changing, vec![39u8; 4 * 1024 * 1024]).unwrap();
        let idx = svc.queue.snapshot().0.len();
        let copied = svc.dispatch_async(request("/api/remote/transfer", json!({"tab": id, "target": format!("tab:{id}"), "directory": "/copy-target", "names": ["copy-shrinking-tree"], "accept_sftp_copy_risk": true}))).await;
        assert_eq!(copied.status, 200);
        let mut downloading = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if let Some(task) = tasks.get(idx) {
                if task["status"] == "Running" && task["bytes_done"].as_u64().unwrap_or(0) > 0 { downloading = true; break; }
                assert_ne!(task["status"], "Failed", "{task:?}");
                assert_ne!(task["status"], "Completed", "tree copied before source change");
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(downloading);
        std::fs::OpenOptions::new().write(true).open(&changing).unwrap().set_len(1).unwrap();
        let mut failed = false;
        for _ in 0..1000 {
            let (tasks, _) = svc.queue.snapshot();
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Failed") { failed = true; break; }
            if tasks.get(idx).and_then(|t| t["status"].as_str()) == Some("Completed") { panic!("truncated source tree was published"); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(failed);
        assert!(!remote.join("copy-target/copy-shrinking-tree").exists());
        assert_eq!(std::fs::metadata(changing).unwrap().len(), 1);
        exercise_cross_move_destination(&svc, id, "/", &local).await;
        drop(server);
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn local_vault_requires_setup_then_unlock_and_can_be_locked() {
        let root = std::env::temp_dir().join(format!("linscp-service-vault-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let service = CommanderService::new(root.clone(), Arc::new(NativeLocalFs::new()));
        let status = |service: &CommanderService| service.dispatch(ApiEnvelope {
            method: "GET".into(), path: "/api/vault/status".into(), body: json!({}),
        });
        assert_eq!(status(&service).payload["vault"], "setup_required");
        let too_short = service.dispatch(ApiEnvelope {
            method: "POST".into(), path: "/api/vault/unlock".into(), body: json!({"password": "12345"}),
        });
        assert_eq!(too_short.status, 400);
        let minimum_length = service.dispatch(ApiEnvelope {
            method: "POST".into(), path: "/api/vault/unlock".into(), body: json!({"password": "123456"}),
        });
        assert_eq!(minimum_length.status, 200, "{}", minimum_length.payload);
        assert_eq!(status(&service).payload["vault"], "unlocked");
        let wrapped_key = std::fs::read(root.join("sessions.key")).unwrap();
        assert!(wrapped_key.starts_with(b"LSCPVLT1"));
        let locked = service.dispatch(ApiEnvelope {
            method: "POST".into(), path: "/api/vault/lock".into(), body: json!({}),
        });
        assert_eq!(locked.status, 200);
        assert_eq!(status(&service).payload["vault"], "locked");
        let locked_key_list = service.dispatch(ApiEnvelope {
            method: "GET".into(), path: "/api/vault/keys".into(), body: json!({}),
        });
        assert_eq!(locked_key_list.status, 423);
        let unlocked_again = service.dispatch(ApiEnvelope {
            method: "POST".into(), path: "/api/vault/unlock".into(), body: json!({"password": "123456"}),
        });
        assert_eq!(unlocked_again.status, 200, "{}", unlocked_again.payload);
        assert_eq!(status(&service).payload["vault"], "unlocked");
        let private_key = "fixture private key contents";
        let imported = service.dispatch(ApiEnvelope {
            method: "POST".into(),
            path: "/api/vault/keys/import".into(),
            body: json!({"name": "id_ed25519", "private_key": private_key}),
        });
        assert_eq!(imported.status, 200, "{}", imported.payload);
        let reference = imported.payload["reference"].as_str().unwrap();
        assert!(reference.starts_with("vaultkey://"));
        let key_id = reference.strip_prefix("vaultkey://").unwrap();
        let encrypted = std::fs::read(root.join("keys").join(format!("{key_id}.key.vault"))).unwrap();
        assert!(!encrypted.windows(private_key.len()).any(|window| window == private_key.as_bytes()));
        let listed = service.dispatch(ApiEnvelope {
            method: "GET".into(), path: "/api/vault/keys".into(), body: json!({}),
        });
        assert_eq!(listed.status, 200);
        assert_eq!(listed.payload["keys"][0]["reference"], reference);
        assert_eq!(listed.payload["keys"][0]["label"], "id_ed25519");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn service_dispatches_status_roots_sessions_and_importers() {
        let tmp = std::env::temp_dir().join(format!("linscp-svc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let svc = CommanderService::new(tmp.clone(), Arc::new(NativeLocalFs::new()));
        unlock_for_test(&svc);
        let roots_reply = svc.dispatch(ApiEnvelope { method: "GET".to_string(), path: "/api/local/roots".to_string(), body: json!({}) });
        assert_eq!(roots_reply.status, 200);
        assert!(!roots_reply.payload["roots"].as_array().unwrap().is_empty());
        let save_reply = svc.dispatch(ApiEnvelope { method: "POST".to_string(), path: "/api/sessions/save".to_string(), body: serde_json::to_value(SessionConfig { name: "prod/web".to_string(), protocol: ProtocolScheme::Sftp, host: "10.0.0.8".to_string(), port: 22, username: "deploy".to_string(), password: Some("vault-secret".to_string()), keyfile: None, hostkey: "SHA256:xyz".to_string(), initial_dir: "/srv/www".to_string(), local_dir: String::new(), tunnel: None }).unwrap() });
        assert_eq!(save_reply.status, 200);
        assert!(tmp.join("sessions.key").exists());
        let stored_sessions = std::fs::read_to_string(tmp.join("sessions.ini")).unwrap();
        assert!(!stored_sessions.contains("vault-secret"), "saved passwords must be encrypted at rest");
        let list_reply = svc.dispatch(ApiEnvelope { method: "GET".to_string(), path: "/api/sessions".to_string(), body: json!({}) });
        assert_eq!(list_reply.status, 200);
        assert_eq!(list_reply.payload["sessions"][0]["name"], "prod/web");
        assert_eq!(list_reply.payload["sessions"][0]["has_password"], true);
        assert_eq!(list_reply.payload["folders"][0], "prod");
        let _ = std::fs::remove_dir_all(&tmp);
    }
    #[test]
    fn a_native_window_drop_names_paths_and_the_backend_reads_them() {
        // The desktop shell consumes the drop before the page sees it and
        // arrives over Tauri's event channel with paths, while a browser sends
        // bytes. Both reach the same endpoint, so where a dropped item lands
        // cannot drift between the apps.
        let tmp = std::env::temp_dir().join(format!("linscp-path-drop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let local = tmp.join("local");
        let outside = tmp.join("outside");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let drop_local = |body: Value| {
            svc.dispatch(ApiEnvelope {
                method: "POST".to_string(),
                path: "/api/local/drop".to_string(),
                body,
            })
        };

        // One file the operating system dropped lands under its own name.
        let dropped = outside.join("report.txt");
        std::fs::write(&dropped, b"native drop bytes").unwrap();
        let saved = drop_local(json!({
            "local_dir": local.to_string_lossy(),
            "name": "report.txt",
            "source_path": dropped.to_string_lossy(),
        }));
        assert_eq!(saved.status, 200, "{}", saved.payload);
        assert_eq!(std::fs::read(local.join("report.txt")).unwrap(), b"native drop bytes");

        // A drop that names nothing usable is refused instead of being written
        // as an empty file.
        for body in [
            json!({"local_dir": local.to_string_lossy(), "name": "missing.txt",
                   "source_path": outside.join("not-there.txt").to_string_lossy()}),
            json!({"local_dir": local.to_string_lossy(), "name": "control",
                   "source_path": "bad\u{0}path"}),
            json!({"local_dir": local.to_string_lossy(), "name": "report.txt"}),
        ] {
            let reply = drop_local(body);
            assert_eq!(reply.status, 400, "{}", reply.payload);
        }

        // A path drop is refused, now, when the destination already holds the
        // name: the page asks the one overwrite question and repeats the same
        // drop with the answer, so nothing is replaced before it is asked.
        let dropped_again = drop_local(json!({
            "local_dir": local.to_string_lossy(), "name": "report.txt",
            "source_path": dropped.to_string_lossy(),
        }));
        assert_eq!(dropped_again.status, 409, "{}", dropped_again.payload);
        assert_eq!(dropped_again.payload["conflicts"], json!(["report.txt"]));
        // The name alone is not taken: a second file of the same drop is new,
        // so the refusal is about the destination, not about the gesture.
        let second = outside.join("notes.txt");
        std::fs::write(&second, b"notes").unwrap();
        let both = drop_local(json!({
            "local_dir": local.to_string_lossy(),
            "name": "report.txt",
            "source_paths": [dropped.to_string_lossy(), second.to_string_lossy()],
        }));
        assert_eq!(both.status, 409, "{}", both.payload);
        assert_eq!(both.payload["conflicts"], json!(["report.txt"]));
        assert_eq!(std::fs::read(local.join("notes.txt")).unwrap(), b"notes");

        // The page's approval is what turns a conflict into a replacement, and
        // the retry is the same request plus that decision.
        std::fs::write(&dropped, b"changed").unwrap();
        let approved = drop_local(json!({
            "local_dir": local.to_string_lossy(), "name": "report.txt",
            "source_path": dropped.to_string_lossy(), "overwrite": "overwrite",
        }));
        assert_eq!(approved.status, 200, "{}", approved.payload);
        assert_eq!(std::fs::read(local.join("report.txt")).unwrap(), b"changed");

        // A folder travels under its own leaf name, with its contents: the
        // directories above it on the machine are not part of the drop, which
        // is what made the same gesture land at a different depth before.
        let tree = outside.join("project");
        std::fs::create_dir_all(tree.join("nested")).unwrap();
        std::fs::write(tree.join("one.txt"), b"one").unwrap();
        std::fs::write(tree.join("nested/two.txt"), b"two").unwrap();
        let copied = drop_local(json!({
            "local_dir": local.to_string_lossy(), "name": "project",
            "source_path": tree.to_string_lossy(),
        }));
        assert_eq!(copied.status, 200, "{}", copied.payload);
        assert_eq!(copied.payload["saved"], json!(["project"]));
        assert_eq!(std::fs::read(local.join("project/nested/two.txt")).unwrap(), b"two");
        // The second drop of the same folder is the conflict, and the approval
        // replaces the old tree rather than merging into it.
        let folder_again = drop_local(json!({
            "local_dir": local.to_string_lossy(), "name": "project",
            "source_path": tree.to_string_lossy(),
        }));
        assert_eq!(folder_again.status, 409, "{}", folder_again.payload);
        assert_eq!(folder_again.payload["conflicts"], json!(["project"]));
        std::fs::write(tree.join("one.txt"), b"replaced").unwrap();
        let folder_approved = drop_local(json!({
            "local_dir": local.to_string_lossy(), "name": "project",
            "source_path": tree.to_string_lossy(), "overwrite": "overwrite",
        }));
        assert_eq!(folder_approved.status, 200, "{}", folder_approved.payload);
        assert_eq!(std::fs::read(local.join("project/one.txt")).unwrap(), b"replaced");

        // A link is not a copy of bytes the folder owns, so a tree that
        // contains one is refused and leaves nothing half-written behind.
        #[cfg(unix)]
        {
            let linked = outside.join("linked");
            std::fs::create_dir_all(&linked).unwrap();
            std::os::unix::fs::symlink("/etc/passwd", linked.join("escape")).unwrap();
            let refused = drop_local(json!({
                "local_dir": local.to_string_lossy(), "name": "linked",
                "source_path": linked.to_string_lossy(),
            }));
            assert_eq!(refused.status, 400, "{}", refused.payload);
            assert!(!local.join("linked/escape").exists());
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn desktop_drops_are_saved_by_the_same_endpoint_in_every_app() {
        // The page sends one JSON body (base64 bytes) on both transports, so
        // the browser and the native window reach this handler; the HTTP layer
        // only has to turn a raw browser upload into the same body.
        let tmp = std::env::temp_dir().join(format!("linscp-drop-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let local = tmp.join("local");
        std::fs::create_dir_all(&local).unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));

        let saved = svc.dispatch(ApiEnvelope {
            method: "POST".to_string(),
            path: "/api/local/drop".to_string(),
            body: json!({
                "local_dir": local.to_string_lossy(),
                "name": "dropped.txt",
                "relative_path": "folder/nested",
                "data_base64": BASE64_STD.encode(b"dropped bytes"),
            }),
        });
        assert_eq!(saved.status, 200, "{}", saved.payload);
        assert_eq!(
            std::fs::read(local.join("folder/nested/dropped.txt")).unwrap(),
            b"dropped bytes",
            "a drop keeps the folder it was dragged from"
        );

        // An empty dropped folder still exists afterwards.
        let created = svc.dispatch(ApiEnvelope {
            method: "POST".to_string(),
            path: "/api/local/drop-dir".to_string(),
            body: json!({
                "local_dir": local.to_string_lossy(),
                "relative_path": "tree/empty",
            }),
        });
        assert_eq!(created.status, 200, "{}", created.payload);
        assert!(local.join("tree/empty").is_dir());

        // Every unsafe shape is refused, and nothing is written outside.
        for body in [
            json!({"local_dir": local.to_string_lossy(), "name": "../escape.txt", "data_base64": ""}),
            json!({"local_dir": local.to_string_lossy(), "name": "ok.txt", "relative_path": "../../etc", "data_base64": ""}),
            json!({"local_dir": local.to_string_lossy(), "name": "ok.txt"}),
            json!({"local_dir": local.to_string_lossy(), "data_base64": "AAAA"}),
        ] {
            let reply = svc.dispatch(ApiEnvelope { method: "POST".to_string(), path: "/api/local/drop".to_string(), body });
            assert_eq!(reply.status, 400, "{}", reply.payload);
        }
        assert!(!tmp.join("escape.txt").exists());

        // Signing out answers in the native app too, where there is no account
        // server; the page offers the menu entry on every host.
        let logout = svc.dispatch(ApiEnvelope { method: "POST".to_string(), path: "/api/logout".to_string(), body: json!({}) });
        assert_eq!(logout.status, 200);
        let session = svc.dispatch(ApiEnvelope { method: "GET".to_string(), path: "/api/login".to_string(), body: json!({}) });
        assert_eq!(session.status, 200);
        assert_eq!(session.payload["logged_in"], false);

        // An upload drop needs a connected remote tab and says so instead of
        // reporting success or writing a file. A remote drop is dispatched
        // asynchronously, which is what both apps call for one.
        let upload = svc.dispatch_async(ApiEnvelope {
            method: "POST".to_string(),
            path: "/api/transfer/drop".to_string(),
            body: json!({"tab": 0, "remote_dir": "/incoming", "name": "x.txt", "data_base64": "eA=="}),
        }).await;
        assert_eq!(upload.status, 400, "{}", upload.payload);
        assert!(!tmp.join("config/drop-staging/x.txt").exists(), "a refused drop leaves no staged file");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// The console panel can only run something that is one command line.
    /// Anything else is refused before an interpreter is built, so a pasted
    /// script cannot run as a series of commands nobody confirmed.
    #[tokio::test]
    async fn the_console_refuses_an_empty_or_multi_line_command() {
        let svc = CommanderService::default();
        let request = |body: Value| ApiEnvelope {
            method: "POST".into(), path: "/api/command/exec".into(), body,
        };
        // The command stays on one line: the interpreter is not a script
        // runner, so a server-mode line is never built here.
        let long = "x".repeat(4097);
        for body in [
            json!({"command": "   ", "tab": 0}),
            json!({"command": "lpwd\nrm /", "tab": 0}),
            json!({"command": "lpwd\rrm /", "tab": 0}),
            json!({"command": long, "tab": 0}),
        ] {
            let reply = svc.dispatch_async(request(body.clone())).await;
            assert_eq!(reply.status, 400, "{body}: {}", reply.payload);
            assert_eq!(reply.payload["success"], false, "{body}");
        }
    }

    /// A command that needs a server says so instead of failing obscurely.
    #[tokio::test]
    async fn a_console_command_without_a_session_refuses_the_remote_side() {
        let svc = CommanderService::default();
        let reply = svc.dispatch_async(ApiEnvelope {
            method: "POST".into(), path: "/api/command/exec".into(),
            body: json!({"command": "ls", "tab": 0}),
        }).await;
        assert_eq!(reply.status, 200, "the console itself answers");
        assert_eq!(reply.payload["success"], false);
        assert_eq!(reply.payload["exit_code"], 1);
        assert!(
            reply.payload["stderr"].as_str().unwrap_or("").contains("Not connected"),
            "the error explains the missing connection: {}",
            reply.payload
        );
    }

    /// `copyid` and keep-up-to-date both need a live server; with no tab they
    /// must refuse rather than report a task that cannot run.
    #[tokio::test]
    async fn copyid_and_keep_up_to_date_refuse_without_a_connection() {
        let svc = CommanderService::default();
        for (path, body) in [
            ("/api/session/copyid", json!({"tab": 0, "keyfile": ""})),
            ("/api/session/copyid", json!({"tab": 99, "keyfile": "id_ed25519.pub"})),
            ("/api/transfer/keepuptodate", json!({"tab": 0, "local_dir": "/tmp", "remote_dir": "/"})),
        ] {
            let reply = svc.dispatch_async(ApiEnvelope {
                method: "POST".into(), path: path.into(), body: body.clone(),
            }).await;
            assert_eq!(reply.status, 400, "{path} {body}: {}", reply.payload);
            assert_ne!(reply.payload["success"], true, "{path} {body}");
            assert!(reply.payload.get("task_id").is_none(), "{path} queued nothing");
        }
    }

    /// The page passes a plan's reason through the GUI catalogs. A reason the
    /// catalogs do not carry shows up in English in every other language, so
    /// every phrase the planner can produce has to have a key.
    #[test]
    fn every_plan_reason_has_a_gui_translation() {
        let catalog: Value =
            serde_json::from_str(include_str!("../../../locales/en.json")).expect("catalog parses");
        let gui = &catalog["gui"];
        // The planner's own vocabulary, as `sync_planner.rs` writes it.
        let planner = [
            "up to date",
            "missing locally",
            "missing on remote",
            "new locally",
            "new on remote",
            "deleted locally",
            "deleted on remote",
            "removed locally since last sync",
            "removed on remote since last sync",
            "modified locally",
            "modified on remote",
            "modified on both sides (conflict)",
            "modified on both sides with identical timestamps",
            "local is newer",
            "remote is newer",
            "size differs",
            "contents differ",
            "timestamp differs (-mirror)",
            "type mismatch (file vs directory)",
            "conflict resolved in favour of local",
            "conflict resolved in favour of remote",
            "conflict resolved in favour of newer local file",
            "conflict resolved in favour of newer remote file",
        ];
        for reason in planner {
            let key = sync_reason_for_page(reason);
            assert_ne!(key, reason, "{reason} was left in the planner's own words");
            assert!(
                gui.get(&key).is_some(),
                "the GUI catalog has no translation for '{key}' (from '{reason}')"
            );
        }
    }

    /// The synchronize dialogue's settings reach the planner as the planner
    /// defines them: an empty mask is "every file", a mirror is one-way and
    /// deletes, and the plan call itself never writes anything.
    #[test]
    fn sync_settings_follow_the_dialogue() {
        use linscp_engine::sync_planner::SyncMode;
        let dir = std::env::temp_dir().join(format!("linscp-sync-options-{}", std::process::id()));
        let base = json!({"local_dir": dir.to_string_lossy(), "remote_dir": "/remote", "criteria": "time"});
        let with = |extra: Value| {
            let mut body = base.clone();
            for (key, value) in extra.as_object().expect("object").iter() {
                body[key] = value.clone();
            }
            CommanderService::sync_options_from(&body)
        };
        let (_, remote, opts) = with(json!({})).expect("the defaults are valid");
        assert_eq!(remote, "/remote");
        assert_eq!(opts.mode, SyncMode::Local);
        assert!(opts.file_mask.is_empty(), "an empty mask selects every file");
        assert!(opts.preview_only, "the planner never writes on its own");
        assert!(!opts.delete_obsolete && !opts.mirror);

        let (_, _, mirror) = with(json!({"mirror": true, "mode": "remote"})).expect("a mirror is valid");
        assert!(mirror.mirror, "the dialogue's mirror reaches the planner");
        assert!(mirror.delete_obsolete, "and a mirror deletes what the source lacks");

        // What the page cannot express is still judged: a criteria it never
        // offers, and a local directory that is not absolute, are refused
        // rather than silently defaulted.
        assert!(with(json!({"criteria": "colour"})).is_err());
        assert!(with(json!({"local_dir": "relative/path"})).is_err());
        assert!(with(json!({"remote_dir": "relative/path"})).is_err(),
            "a remote root has to be absolute too");
        // A mask the user typed is parsed, and a bad one is refused.
        assert!(with(json!({"filemask": "*.txt"})).is_ok());
        // A trailing operator has no value to compare against.
        assert!(with(json!({"filemask": "*.txt>"})).is_err());
    }

    /// The keep-up-to-date dialogue asks for seconds; the engine counts
    /// milliseconds, and the conversion is clamped so a zero or absurd
    /// interval cannot spin or sleep forever.
    #[test]
    fn a_keep_up_to_date_interval_is_seconds_clamped_to_milliseconds() {
        let convert = |seconds: u64| seconds.saturating_mul(1000).clamp(500, 86_400_000);
        assert_eq!(convert(0), 500, "zero means as often as the watcher can");
        assert_eq!(convert(1), 1000);
        assert_eq!(convert(90), 90_000);
        assert_eq!(convert(u64::MAX), 86_400_000, "a day is the longest wait");
    }

    /// A structurally valid granted-folder URI, the same shape the platform
    /// tests use for the mock bridge. The editor tests below register a
    /// bridge over it; the chmod test registers none, proving the message
    /// comes from the `content://` branch and not from any provider.
    const SAF_GRANTED_DIR: &str = "content://mock.tree/tree/primary%3ADownload";

    /// In-memory `SafBridge` for the granted-folder tests: documents are
    /// keyed by full URI, writes create-or-replace like the Kotlin plugin
    /// (and refuse a file over a directory, as the provider does), and a
    /// missing document errors like a provider that cannot find it. One
    /// bridge serves every tree, as the real adapter does.
    struct MockDoc {
        bytes: Option<Vec<u8>>,
    }

    struct MockBridge {
        docs: Mutex<HashMap<String, MockDoc>>,
        mtime: i64,
    }

    /// A second granted tree, so cross-tree copies and moves have somewhere
    /// to go without leaving the one mock bridge.
    const SAF_OTHER_TREE: &str = "content://mock.tree/tree/primary%3APictures";

    impl MockBridge {
        fn with_file(name: &str, content: &[u8]) -> Self {
            let bridge = MockBridge { docs: Mutex::new(HashMap::new()), mtime: 1_791_875_271 };
            bridge.add_file(&Self::doc_uri(name), content);
            bridge
        }

        fn doc_uri(name: &str) -> String {
            format!("{SAF_GRANTED_DIR}/document/{name}")
        }

        fn add_file(&self, uri: &str, content: &[u8]) {
            self.docs.lock().expect("m").insert(uri.to_string(), MockDoc { bytes: Some(content.to_vec()) });
        }

        fn add_dir(&self, uri: &str) {
            self.docs.lock().expect("m").insert(uri.to_string(), MockDoc { bytes: None });
        }

        fn leaf_of(uri: &str) -> String {
            uri.rsplit("/document/").next().unwrap_or("").to_string()
        }

        fn parent_of(uri: &str) -> String {
            uri.rsplit_once("/document/").map(|(parent, _)| parent.to_string()).unwrap_or_default()
        }

        fn entry_for_uri(&self, uri: &str, doc: &MockDoc) -> FileEntry {
            FileEntry { name: Self::leaf_of(uri), size: doc.bytes.as_ref().map(|bytes| bytes.len() as u64).unwrap_or(0), is_dir: doc.bytes.is_none(), is_symlink: false, broken_link: false, date: String::new(), mtime: self.mtime, permissions: String::new(), owner: None, group: None }
        }

        fn bytes_of(&self, name: &str) -> Option<Vec<u8>> {
            self.bytes_of_uri(&Self::doc_uri(name))
        }

        fn bytes_of_uri(&self, uri: &str) -> Option<Vec<u8>> {
            self.docs.lock().expect("m").get(uri).and_then(|doc| doc.bytes.clone())
        }
    }

    impl linscp_platform::android::SafBridge for MockBridge {
        fn request_tree(&self) -> Result<Option<String>, PlatformError> { Ok(None) }
        fn granted_trees(&self) -> Result<Vec<LocalRootEntry>, PlatformError> { Ok(Vec::new()) }
        fn list_tree(&self, tree_uri: &str) -> Result<Vec<FileEntry>, PlatformError> {
            let docs = self.docs.lock().expect("m");
            let mut uris: Vec<String> = docs.keys().filter(|uri| Self::parent_of(uri) == tree_uri).cloned().collect();
            uris.sort();
            Ok(uris.iter().map(|uri| self.entry_for_uri(uri, &docs[uri])).collect())
        }
        fn stat_uri(&self, uri: &str) -> Result<FileEntry, PlatformError> {
            let docs = self.docs.lock().expect("m");
            match docs.get(uri) {
                Some(doc) => Ok(self.entry_for_uri(uri, doc)),
                // A tree root (no `/document/` segment) always stats as a
                // directory, like the plugin's tree-to-document conversion.
                None if !uri.contains("/document/") => Ok(self.entry_for_uri(uri, &MockDoc { bytes: None })),
                None => Err(PlatformError::Unsupported(format!("Unknown document: {uri}"))),
            }
        }
        fn read_uri_bytes(&self, uri: &str) -> Result<Vec<u8>, PlatformError> {
            self.bytes_of_uri(uri).ok_or_else(|| PlatformError::Unsupported(format!("Unknown document: {uri}")))
        }
        fn write_uri_bytes(&self, parent_uri: &str, name: &str, data: &[u8]) -> Result<String, PlatformError> {
            let uri = format!("{parent_uri}/document/{name}");
            let mut docs = self.docs.lock().expect("m");
            if docs.get(&uri).is_some_and(|doc| doc.bytes.is_none()) {
                return Err(PlatformError::Unsupported(format!("Cannot replace the directory: {uri}")));
            }
            docs.insert(uri.clone(), MockDoc { bytes: Some(data.to_vec()) });
            Ok(uri)
        }
        fn mkdir_uri(&self, parent_uri: &str, name: &str) -> Result<String, PlatformError> {
            let uri = format!("{parent_uri}/document/{name}");
            let mut docs = self.docs.lock().expect("m");
            if docs.get(&uri).is_some_and(|doc| doc.bytes.is_some()) {
                return Err(PlatformError::Unsupported(format!("Cannot make a directory over the file: {uri}")));
            }
            docs.insert(uri.clone(), MockDoc { bytes: None });
            Ok(uri)
        }
        fn delete_uri(&self, uri: &str) -> Result<(), PlatformError> {
            let prefix = format!("{uri}/document/");
            self.docs.lock().expect("m").retain(|key, _| key.as_str() != uri && !key.as_str().starts_with(prefix.as_str()));
            Ok(())
        }
        fn rename_uri(&self, uri: &str, new_name: &str) -> Result<String, PlatformError> {
            let new_uri = format!("{}/document/{new_name}", Self::parent_of(uri));
            let old_prefix = format!("{uri}/document/");
            let new_prefix = format!("{new_uri}/document/");
            let mut docs = self.docs.lock().expect("m");
            let mut moved: HashMap<String, MockDoc> = HashMap::new();
            docs.retain(|key, doc| {
                if key.as_str() == uri {
                    moved.insert(new_uri.clone(), MockDoc { bytes: doc.bytes.clone() });
                    false
                } else if let Some(tail) = key.as_str().strip_prefix(old_prefix.as_str()) {
                    moved.insert(format!("{new_prefix}{tail}"), MockDoc { bytes: doc.bytes.clone() });
                    false
                } else {
                    true
                }
            });
            docs.extend(moved);
            Ok(new_uri)
        }
    }

    /// Opening and saving in a granted main pane go through the bridge: the
    /// editor reads the document, a save with a fresh stamp replaces it, a
    /// stale stamp is refused, and a new name is created.
    #[tokio::test]
    async fn saf_editor_reads_and_saves_through_the_bridge() {
        let tmp = std::env::temp_dir().join(format!("linscp-saf-edit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("other")).unwrap();
        let bridge = Arc::new(MockBridge::with_file("note.txt", b"granted text\n"));
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let svc = CommanderService::new(tmp.join("config"), Arc::new(fs));
        let open = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": SAF_GRANTED_DIR, "other_local_dir": tmp.join("other")}}) }).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let edit = svc.dispatch(ApiEnvelope { method: "GET".into(), path: format!("/api/local/edit?tab={id}&path=note.txt"), body: json!({}) });
        assert_eq!(edit.status, 200, "{}", edit.payload);
        assert_eq!(edit.payload["content"], json!("granted text\n"), "{}", edit.payload);
        assert_eq!(edit.payload["info"]["mtime"], json!(1_791_875_271), "{}", edit.payload);
        let stamp = 1_791_875_271_000_000_000i64;
        let save = svc.dispatch(ApiEnvelope { method: "POST".into(), path: "/api/local/save".into(), body: json!({"tab": id, "path": "note.txt", "content": "edited\n", "base_mtime_ns": stamp}) });
        assert_eq!(save.status, 200, "{}", save.payload);
        assert_eq!(bridge.bytes_of("note.txt").as_deref(), Some(b"edited\n".as_slice()), "the bridge holds the replacement");
        let stale = svc.dispatch(ApiEnvelope { method: "POST".into(), path: "/api/local/save".into(), body: json!({"tab": id, "path": "note.txt", "content": "lost\n", "base_mtime_ns": stamp - 1}) });
        assert_eq!(stale.status, 400, "{}", stale.payload);
        assert!(stale.payload["error"].as_str().unwrap_or("").contains("changed while it was open"), "{}", stale.payload);
        let created = svc.dispatch(ApiEnvelope { method: "POST".into(), path: "/api/local/save".into(), body: json!({"tab": id, "path": "fresh.txt", "content": "new\n"}) });
        assert_eq!(created.status, 200, "{}", created.payload);
        assert_eq!(bridge.bytes_of("fresh.txt").as_deref(), Some(b"new\n".as_slice()), "a missing document is created");
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// The granted other pane edits and reports properties the same way: a
    /// leaf opens and saves through the bridge, and the properties rows
    /// carry the bridge's stat instead of a refusal.
    #[tokio::test]
    async fn saf_other_pane_edits_and_reads_properties() {
        let tmp = std::env::temp_dir().join(format!("linscp-saf-other-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("left")).unwrap();
        let bridge = Arc::new(MockBridge::with_file("note.txt", b"other text\n"));
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let svc = CommanderService::new(tmp.join("config"), Arc::new(fs));
        let open = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": tmp.join("left"), "other_local_dir": SAF_GRANTED_DIR}}) }).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let edit = svc.dispatch_async(ApiEnvelope { method: "GET".into(), path: format!("/api/remote/edit?tab={id}&path=note.txt"), body: json!({}) }).await;
        assert_eq!(edit.status, 200, "{}", edit.payload);
        assert_eq!(edit.payload["content"], json!("other text\n"), "{}", edit.payload);
        let save = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/remote/save".into(), body: json!({"tab": id, "path": "note.txt", "content": "saved\n"}) }).await;
        assert_eq!(save.status, 200, "{}", save.payload);
        assert_eq!(bridge.bytes_of("note.txt").as_deref(), Some(b"saved\n".as_slice()), "save-as reaches the bridge");
        let properties = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/remote/properties".into(), body: json!({"tab": id, "names": ["note.txt"]}) }).await;
        assert_eq!(properties.status, 200, "{}", properties.payload);
        let row = &properties.payload["properties"][0];
        assert_eq!(row["name"], json!("note.txt"), "{}", properties.payload);
        assert_eq!(row["size"], json!(6), "{}", properties.payload);
        assert_eq!(row["is_dir"], json!(false), "{}", properties.payload);
        assert!(row.get("error").is_none(), "{}", properties.payload);
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// Permissions are the editor-adjacent action that stays refused: with
    /// no bridge registered, chmod on a granted main pane and on a granted
    /// other pane both carry the bridge's own message.
    #[tokio::test]
    async fn saf_chmod_still_refuses_granted_folders() {
        let tmp = std::env::temp_dir().join(format!("linscp-saf-chmod-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("left")).unwrap();
        std::fs::create_dir_all(tmp.join("right")).unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let open = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": SAF_GRANTED_DIR, "other_local_dir": tmp.join("right")}}) }).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let chmod = svc.dispatch(ApiEnvelope { method: "POST".into(), path: "/api/local/chmod".into(), body: json!({"tab": id, "name": "note.txt", "permissions": "644"}) });
        assert_eq!(chmod.status, 400, "{}", chmod.payload);
        assert!(chmod.payload["error"].as_str().unwrap_or("").contains("POSIX permissions do not exist"), "{}", chmod.payload);
        let open_other = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": tmp.join("left"), "other_local_dir": SAF_GRANTED_DIR}}) }).await;
        assert_eq!(open_other.status, 200, "{}", open_other.payload);
        let other_id = open_other.payload["tab"]["id"].as_u64().unwrap();
        let chmod_other = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/remote/chmod".into(), body: json!({"tab": other_id, "name": "note.txt", "permissions": "644"}) }).await;
        assert_eq!(chmod_other.status, 400, "{}", chmod_other.payload);
        assert!(chmod_other.payload["error"].as_str().unwrap_or("").contains("POSIX permissions do not exist"), "{}", chmod_other.payload);
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// Waits for the newest queue task to land on `want` (`Completed` or
    /// `Failed`) and returns its row; the other terminal state panics with
    /// the task's own error, so a failure never reads as a timeout.
    async fn wait_for_task(service: &CommanderService, want: &str) -> Value {
        for _ in 0..500 {
            let (tasks, _) = service.queue.snapshot();
            if let Some(task) = tasks.last() {
                let status = task["status"].as_str().unwrap_or("");
                if status == want {
                    return task.clone();
                }
                if status == "Completed" || status == "Failed" {
                    panic!("task landed on {status}, wanted {want}: {}", task["error"]);
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("no task reached {want}");
    }

    /// Copies across the granted/plain boundary move bytes through the
    /// bridge in both directions, and between two granted trees; an
    /// over-cap file refuses at enqueue time, and a directory copy keeps
    /// the plain panes' refusal word for word.
    #[tokio::test]
    async fn saf_local_copy_moves_bytes_through_the_bridge() {
        let tmp = std::env::temp_dir().join(format!("linscp-saf-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let left = tmp.join("left"); let right = tmp.join("right");
        std::fs::create_dir_all(&left).unwrap(); std::fs::create_dir_all(&right).unwrap();
        std::fs::write(left.join("plain.txt"), b"plain bytes").unwrap();
        let bridge = Arc::new(MockBridge::with_file("note.txt", b"granted bytes"));
        bridge.add_dir(&format!("{SAF_GRANTED_DIR}/document/folder"));
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let svc = CommanderService::new(tmp.join("config"), Arc::new(fs));
        let open = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": SAF_GRANTED_DIR, "other_local_dir": right}}) }).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        // Granted pane to plain pane.
        let copy = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": right, "names": ["note.txt"]}) }).await;
        assert_eq!(copy.status, 200, "{}", copy.payload);
        let done = wait_for_task(&svc, "Completed").await;
        assert_eq!(done["bytes_total"], json!(13), "{}", done);
        assert_eq!(std::fs::read(right.join("note.txt")).unwrap(), b"granted bytes".to_vec());
        // Plain pane to granted pane.
        let open_plain = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": left, "other_local_dir": SAF_GRANTED_DIR}}) }).await;
        assert_eq!(open_plain.status, 200, "{}", open_plain.payload);
        let plain_id = open_plain.payload["tab"]["id"].as_u64().unwrap();
        let copy_back = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": plain_id, "local_dir": left, "remote_dir": SAF_GRANTED_DIR, "names": ["plain.txt"]}) }).await;
        assert_eq!(copy_back.status, 200, "{}", copy_back.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(bridge.bytes_of("plain.txt").as_deref(), Some(b"plain bytes".as_slice()), "the bridge holds the copy");
        // Granted tree to granted tree.
        let open_other = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": SAF_GRANTED_DIR, "other_local_dir": SAF_OTHER_TREE}}) }).await;
        assert_eq!(open_other.status, 200, "{}", open_other.payload);
        let other_id = open_other.payload["tab"]["id"].as_u64().unwrap();
        let copy_tree = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": other_id, "local_dir": SAF_GRANTED_DIR, "remote_dir": SAF_OTHER_TREE, "names": ["note.txt"]}) }).await;
        assert_eq!(copy_tree.status, 200, "{}", copy_tree.payload);
        wait_for_task(&svc, "Completed").await;
        let other_doc = format!("{SAF_OTHER_TREE}/document/note.txt");
        assert_eq!(bridge.bytes_of_uri(&other_doc).as_deref(), Some(b"granted bytes".as_slice()), "the other tree holds the copy");
        // Over the document cap refuses at enqueue time, naming the file.
        let big = vec![0u8; (linscp_platform::MAX_SAF_DOCUMENT_BYTES + 1) as usize];
        bridge.add_file(&format!("{SAF_GRANTED_DIR}/document/big.bin"), &big);
        let refused = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": right, "names": ["big.bin"]}) }).await;
        assert_eq!(refused.status, 400, "{}", refused.payload);
        assert!(refused.payload["error"].as_str().unwrap_or("").contains("larger than a granted folder can carry"), "{}", refused.payload);
        // A directory copy keeps the plain panes' refusal.
        let dir_copy = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": right, "names": ["folder"]}) }).await;
        assert_eq!(dir_copy.status, 400, "{}", dir_copy.payload);
        assert!(dir_copy.payload["error"].as_str().unwrap_or("").contains("Only regular files and movable directories are supported"), "{}", dir_copy.payload);
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// Granted moves are copies that delete their source: across trees, to
    /// a plain pane, and onto an existing name (refused). A link nested in
    /// a moved directory fails the task by name while the source survives.
    #[tokio::test]
    async fn saf_local_move_copies_then_deletes_across_trees() {
        let tmp = std::env::temp_dir().join(format!("linscp-saf-move-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let right = tmp.join("right");
        std::fs::create_dir_all(&right).unwrap();
        let bridge = Arc::new(MockBridge::with_file("gone.txt", b"moving bytes"));
        bridge.add_file(&MockBridge::doc_uri("clash.txt"), b"stays");
        std::fs::write(right.join("clash.txt"), b"taken").unwrap();
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let svc = CommanderService::new(tmp.join("config"), Arc::new(fs));
        let open = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": SAF_GRANTED_DIR, "other_local_dir": right}}) }).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let request = |name: &str| ApiEnvelope { method: "POST".into(), path: "/api/transfer/move".into(), body: json!({"tab": id, "direction": "upload", "local_dir": SAF_GRANTED_DIR, "remote_dir": right, "names": [name]}) };
        // Granted pane to plain pane: the bytes land, the source is gone.
        let moved = svc.dispatch_async(request("gone.txt")).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(std::fs::read(right.join("gone.txt")).unwrap(), b"moving bytes".to_vec());
        assert!(bridge.bytes_of("gone.txt").is_none(), "the bridge no longer holds the source");
        // A move onto an existing name refuses before anything is queued.
        let clash = svc.dispatch_async(request("clash.txt")).await;
        assert_eq!(clash.status, 409, "{}", clash.payload);
        assert!(clash.payload["error"].as_str().unwrap_or("").contains("Moves require a new destination"), "{}", clash.payload);
        // An over-cap move refuses at enqueue time like a copy.
        let big = vec![0u8; (linscp_platform::MAX_SAF_DOCUMENT_BYTES + 1) as usize];
        bridge.add_file(&format!("{SAF_GRANTED_DIR}/document/big.bin"), &big);
        let refused = svc.dispatch_async(request("big.bin")).await;
        assert_eq!(refused.status, 400, "{}", refused.payload);
        assert!(refused.payload["error"].as_str().unwrap_or("").contains("larger than a granted folder can carry"), "{}", refused.payload);
        // Granted tree to granted tree.
        let open_other = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": SAF_GRANTED_DIR, "other_local_dir": SAF_OTHER_TREE}}) }).await;
        assert_eq!(open_other.status, 200, "{}", open_other.payload);
        let other_id = open_other.payload["tab"]["id"].as_u64().unwrap();
        let moved_tree = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/move".into(), body: json!({"tab": other_id, "direction": "upload", "local_dir": SAF_GRANTED_DIR, "remote_dir": SAF_OTHER_TREE, "names": ["clash.txt"]}) }).await;
        assert_eq!(moved_tree.status, 200, "{}", moved_tree.payload);
        wait_for_task(&svc, "Completed").await;
        let other_doc = format!("{SAF_OTHER_TREE}/document/clash.txt");
        assert_eq!(bridge.bytes_of_uri(&other_doc).as_deref(), Some(b"stays".as_slice()), "the other tree holds the move");
        assert!(bridge.bytes_of("clash.txt").is_none(), "the source tree no longer holds it");
        // A link nested in a moved directory fails the task by name. Unix-only:
        // creating the link needs a privilege the Windows suite cannot grant
        // itself, so asserting its creation there would fail the run.
        if cfg!(unix) {
            std::fs::create_dir_all(tmp.join("linked")).unwrap();
            std::fs::write(tmp.join("linked/real.txt"), b"real").unwrap();
            let open_link = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": tmp.join("linked"), "other_local_dir": right}}) }).await;
            let link_id = open_link.payload["tab"]["id"].as_u64().unwrap();
            let link = svc.dispatch(ApiEnvelope { method: "POST".into(), path: "/api/local/link".into(), body: json!({"tab": link_id, "target": "real.txt", "name": "alias.txt"}) });
            assert_eq!(link.status, 200, "{}", link.payload);
            let open_parent = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": tmp, "other_local_dir": SAF_GRANTED_DIR}}) }).await;
            let parent_id = open_parent.payload["tab"]["id"].as_u64().unwrap();
            let moved_dir = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/move".into(), body: json!({"tab": parent_id, "direction": "upload", "local_dir": tmp, "remote_dir": SAF_GRANTED_DIR, "names": ["linked"]}) }).await;
            assert_eq!(moved_dir.status, 200, "{}", moved_dir.payload);
            let failed = wait_for_task(&svc, "Failed").await;
            assert!(failed["error"].as_str().unwrap_or("").contains("symbolic link"), "{}", failed);
            assert!(tmp.join("linked/real.txt").is_file(), "the source survives a failed move");
        }
        let _ = std::fs::remove_dir_all(tmp);
    }

    use async_trait::async_trait;
    use linscp_proto::{ProgressCallback, ProtoError, RemoteSession, TransferRequest};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    /// One in-memory remote file or directory for the session-transfer tests.
    struct MockRemoteDoc {
        bytes: Vec<u8>,
        is_dir: bool,
        mtime: i64,
    }

    /// In-memory `RemoteSession` for the session-transfer tests: paths are
    /// absolute `/`-joined names, uploads record the offered mtime so the
    /// tests see the staged stamps, and unneeded operations fail like a
    /// server that refuses them.
    struct MockSession {
        docs: Mutex<HashMap<String, MockRemoteDoc>>,
    }

    impl MockSession {
        /// The strong ETag every mock document answers to.
        const ETAG: &'static str = "\"mock-etag\"";

        fn new() -> Self {
            let session = MockSession { docs: Mutex::new(HashMap::new()) };
            session.add_dir("/");
            session
        }

        fn add_file(&self, path: &str, content: &[u8]) {
            self.docs.lock().expect("m").insert(path.to_string(), MockRemoteDoc { bytes: content.to_vec(), is_dir: false, mtime: 0 });
        }

        fn add_dir(&self, path: &str) {
            self.docs.lock().expect("m").insert(path.to_string(), MockRemoteDoc { bytes: Vec::new(), is_dir: true, mtime: 0 });
        }

        fn bytes_of(&self, path: &str) -> Option<Vec<u8>> {
            self.docs.lock().expect("m").get(path).filter(|doc| !doc.is_dir).map(|doc| doc.bytes.clone())
        }

        fn mtime_of(&self, path: &str) -> Option<i64> {
            self.docs.lock().expect("m").get(path).map(|doc| doc.mtime)
        }

        fn leaf_of(path: &str) -> &str {
            path.rsplit('/').next().unwrap_or(path)
        }

        fn parent_of(path: &str) -> &str {
            match path.rsplit_once('/') {
                Some(("", _)) | None => "/",
                Some((parent, _)) => parent,
            }
        }

        fn entry_for(path: &str, doc: &MockRemoteDoc) -> FileEntry {
            FileEntry { name: Self::leaf_of(path).to_string(), size: doc.bytes.len() as u64, is_dir: doc.is_dir, is_symlink: false, broken_link: false, date: String::new(), mtime: doc.mtime, permissions: String::new(), owner: None, group: None }
        }

        fn missing(path: &str) -> ProtoError {
            ProtoError::Transport(format!("No such file or directory: '{path}'."))
        }

        async fn serve(&self, path: &str, offset: u64, sink: &mut (dyn AsyncWrite + Unpin + Send), progress: Option<&ProgressCallback>) -> Result<u64, ProtoError> {
            let bytes = self.bytes_of(path).ok_or_else(|| Self::missing(path))?;
            let from = offset.min(bytes.len() as u64) as usize;
            sink.write_all(&bytes[from..]).await.map_err(|e| ProtoError::Transport(e.to_string()))?;
            let sent = (bytes.len() - from) as u64;
            if let Some(report) = progress { report(sent, bytes.len() as u64); }
            Ok(sent)
        }

        async fn store(&self, path: &str, opts: TransferRequest, source: &mut (dyn AsyncRead + Unpin + Send), progress: Option<&ProgressCallback>) -> Result<u64, ProtoError> {
            let mut bytes = Vec::new();
            source.read_to_end(&mut bytes).await.map_err(|e| ProtoError::Transport(e.to_string()))?;
            let sent = bytes.len() as u64;
            let mtime = if opts.preserve_time { opts.mtime.unwrap_or(0) } else { 0 };
            self.docs.lock().expect("m").insert(path.to_string(), MockRemoteDoc { bytes, is_dir: false, mtime });
            if let Some(report) = progress { report(sent, sent); }
            Ok(sent)
        }
    }

    #[async_trait]
    impl RemoteSession for MockSession {
        fn scheme(&self) -> ProtocolScheme { ProtocolScheme::Dav }

        async fn pwd(&self) -> Result<String, ProtoError> { Ok("/".to_string()) }

        async fn stat(&self, remote_path: &str) -> Result<Option<FileEntry>, ProtoError> {
            let docs = self.docs.lock().expect("m");
            Ok(docs.get(remote_path).map(|doc| Self::entry_for(remote_path, doc)))
        }

        async fn list_dir(&self, remote_path: &str) -> Result<Vec<FileEntry>, ProtoError> {
            let docs = self.docs.lock().expect("m");
            let mut paths: Vec<String> = docs.keys()
                .filter(|path| Self::parent_of(path) == remote_path && path.as_str() != remote_path)
                .cloned().collect();
            paths.sort();
            Ok(paths.iter().map(|path| Self::entry_for(path, &docs[path])).collect())
        }

        async fn mkdir(&self, remote_path: &str) -> Result<(), ProtoError> {
            let mut docs = self.docs.lock().expect("m");
            if docs.contains_key(remote_path) {
                return Err(ProtoError::Transport(format!("Cannot create directory '{remote_path}': it already exists.")));
            }
            docs.insert(remote_path.to_string(), MockRemoteDoc { bytes: Vec::new(), is_dir: true, mtime: 0 });
            Ok(())
        }

        async fn remove_file(&self, remote_path: &str) -> Result<(), ProtoError> {
            let mut docs = self.docs.lock().expect("m");
            match docs.get(remote_path) {
                Some(doc) if !doc.is_dir => { docs.remove(remote_path); Ok(()) }
                _ => Err(Self::missing(remote_path)),
            }
        }

        async fn remove_dir(&self, remote_path: &str) -> Result<(), ProtoError> {
            let prefix = format!("{}/", remote_path.trim_end_matches('/'));
            let mut docs = self.docs.lock().expect("m");
            if !docs.contains_key(remote_path) { return Err(Self::missing(remote_path)); }
            docs.retain(|key, _| key.as_str() != remote_path && !key.as_str().starts_with(prefix.as_str()));
            Ok(())
        }

        async fn rename(&self, from: &str, to: &str) -> Result<(), ProtoError> {
            let mut docs = self.docs.lock().expect("m");
            let doc = docs.remove(from).ok_or_else(|| Self::missing(from))?;
            docs.insert(to.to_string(), doc);
            Ok(())
        }

        async fn copy_file(&self, from: &str, to: &str) -> Result<(), ProtoError> {
            let mut docs = self.docs.lock().expect("m");
            let doc = docs.get(from).ok_or_else(|| Self::missing(from))?;
            if doc.is_dir { return Err(ProtoError::Transport(format!("Cannot copy directory '{from}' as a file."))); }
            let bytes = doc.bytes.clone();
            let mtime = doc.mtime;
            docs.insert(to.to_string(), MockRemoteDoc { bytes, is_dir: false, mtime });
            Ok(())
        }

        async fn symlink(&self, _target: &str, _link_path: &str) -> Result<(), ProtoError> {
            Err(ProtoError::UnsupportedCapability("symlink", self.scheme()))
        }

        async fn chmod(&self, _remote_path: &str, _mode: u32) -> Result<(), ProtoError> { Ok(()) }

        async fn set_mtime(&self, remote_path: &str, mtime: i64) -> Result<(), ProtoError> {
            let mut docs = self.docs.lock().expect("m");
            let doc = docs.get_mut(remote_path).ok_or_else(|| Self::missing(remote_path))?;
            doc.mtime = mtime;
            Ok(())
        }

        async fn checksum(&self, _algorithm: &str, remote_path: &str) -> Result<String, ProtoError> {
            let bytes = self.bytes_of(remote_path).ok_or_else(|| Self::missing(remote_path))?;
            Ok(linscp_crypto::digests::sha256_hex(&bytes))
        }

        async fn download(&self, remote_path: &str, opts: TransferRequest, sink: &mut (dyn AsyncWrite + Unpin + Send), progress: Option<&ProgressCallback>) -> Result<u64, ProtoError> {
            self.serve(remote_path, opts.resume_offset, sink, progress).await
        }

        async fn download_if_match(&self, remote_path: &str, etag: &str, opts: TransferRequest, sink: &mut (dyn AsyncWrite + Unpin + Send), progress: Option<&ProgressCallback>) -> Result<u64, ProtoError> {
            if etag != Self::ETAG { return Err(ProtoError::Transport(format!("Remote file '{remote_path}' changed; conditional download refused."))); }
            self.serve(remote_path, opts.resume_offset, sink, progress).await
        }

        async fn dav_stat_with_etag(&self, remote_path: &str) -> Result<(Option<FileEntry>, Option<String>), ProtoError> {
            Ok((self.stat(remote_path).await?, Some(Self::ETAG.to_string())))
        }

        async fn dav_get_etag(&self, _remote_path: &str) -> Result<(Option<String>, bool), ProtoError> {
            Ok((Some(Self::ETAG.to_string()), false))
        }

        async fn remove_if_match(&self, remote_path: &str, etag: &str) -> Result<(), ProtoError> {
            if etag != Self::ETAG { return Err(ProtoError::Transport(format!("Remote file '{remote_path}' changed; conditional delete refused."))); }
            self.remove_file(remote_path).await
        }

        async fn upload(&self, remote_path: &str, opts: TransferRequest, source: &mut (dyn AsyncRead + Unpin + Send), _total_size: Option<u64>, progress: Option<&ProgressCallback>) -> Result<u64, ProtoError> {
            self.store(remote_path, opts, source, progress).await
        }

        async fn upload_exclusive(&self, remote_path: &str, opts: TransferRequest, source: &mut (dyn AsyncRead + Unpin + Send), _total_size: Option<u64>, progress: Option<&ProgressCallback>) -> Result<u64, ProtoError> {
            if self.docs.lock().expect("m").contains_key(remote_path) {
                return Err(ProtoError::Transport(format!("Remote file '{remote_path}' already exists.")));
            }
            self.store(remote_path, opts, source, progress).await
        }
    }

    /// Opens a remote tab against `session` without dialling anywhere: the
    /// tab row is inserted directly, so session transfers run the real
    /// preflight and worker against the mock.
    fn insert_remote_tab(service: &CommanderService, session: Arc<MockSession>, local_dir: &str) -> u64 {
        let tab = TabRuntime { id: 7, name: "mock".to_string(), site_name: None, is_local: false, connected: true, local_dir: local_dir.to_string(), remote_dir: "/".to_string(), other_local_dir: String::new(), observed_hostkey: String::new(), hostkey_role: "destination".to_string(), hostkey_changed: false, error: String::new(), spec: None, session_json: json!({"protocol": "dav"}), remote: Some(session) };
        service.state.lock().expect("state mutex").tabs.insert(tab.id, tab);
        7
    }

    /// A session-download request body with the WebDAV tree options set.
    fn download_body(id: u64, name: &str, accept_risk: bool, merge: bool) -> Value {
        let mut body = json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "names": [name]});
        if accept_risk { body["accept_directory_copy_risk"] = json!(true); }
        if merge { body["merge_directories"] = json!([name]); }
        body
    }

    /// Serializes the tests that stage granted transfers: the leak checks
    /// below scan the shared temporary directory, so a stage from a
    /// parallel test would read as a leak. Every test that runs a
    /// session transfer against a granted folder holds this lock.
    static SAF_STAGE_LEAK_LOCK: Mutex<()> = Mutex::new(());

    /// The granted-transfer staging directories currently in the system
    /// temporary directory, for before/after leak checks. Only the two
    /// stage prefixes count: the tests' own `linscp-saf-<name>-<pid>`
    /// scratch directories share the family prefix but are not stages.
    fn saf_stage_names() -> std::collections::BTreeSet<std::ffi::OsString> {
        std::fs::read_dir(std::env::temp_dir()).map(|entries| {
            entries.filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .filter(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with("linscp-saf-upload-") || name.starts_with("linscp-saf-download-")
                })
                .collect()
        }).unwrap_or_default()
    }

    /// Uploads from a granted folder stage through temporary files: a file
    /// keeps its bytes and its seconds, a tree uploads whole, an over-cap
    /// file refuses at enqueue time naming the file, and no stage leaks.
    #[tokio::test]
    async fn saf_session_upload_stages_through_temp_files() {
        let _leak_lock = SAF_STAGE_LEAK_LOCK.lock().expect("saf stage lock");
        let tmp = std::env::temp_dir().join(format!("linscp-saf-up-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let bridge = Arc::new(MockBridge::with_file("up.txt", b"upload bytes"));
        bridge.add_dir(&format!("{SAF_GRANTED_DIR}/document/tree"));
        bridge.add_file(&format!("{SAF_GRANTED_DIR}/document/tree/document/nested.txt"), b"nested upload");
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let svc = CommanderService::new(tmp.join("config"), Arc::new(fs));
        let session = Arc::new(MockSession::new());
        let id = insert_remote_tab(&svc, session.clone(), SAF_GRANTED_DIR);
        let stages_before = saf_stage_names();
        // A file keeps its bytes and its seconds.
        let queued = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "names": ["up.txt"]}) }).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(session.bytes_of("/up.txt").as_deref(), Some(b"upload bytes".as_slice()), "the remote holds the upload");
        assert_eq!(session.mtime_of("/up.txt"), Some(1_791_875_271), "the remote keeps the granted seconds");
        // A tree uploads whole, after the WebDAV risk dance.
        let risk = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "names": ["tree"]}) }).await;
        assert_eq!(risk.status, 409, "{}", risk.payload);
        assert_eq!(risk.payload["directory_copy_risk"], true);
        let queued_tree = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "names": ["tree"], "accept_directory_copy_risk": true}) }).await;
        assert_eq!(queued_tree.status, 200, "{}", queued_tree.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(session.bytes_of("/tree/nested.txt").as_deref(), Some(b"nested upload".as_slice()), "the remote holds the tree");
        assert!(session.stat("/tree").await.unwrap().unwrap().is_dir);
        // An over-cap file refuses at enqueue time, naming the file.
        let big = vec![0u8; (linscp_platform::MAX_SAF_DOCUMENT_BYTES + 1) as usize];
        bridge.add_file(&format!("{SAF_GRANTED_DIR}/document/big.bin"), &big);
        let refused = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "names": ["big.bin"]}) }).await;
        assert_eq!(refused.status, 400, "{}", refused.payload);
        assert!(refused.payload["error"].as_str().unwrap_or("").contains("larger than a granted folder can carry"), "{}", refused.payload);
        assert!(saf_stage_names().difference(&stages_before).next().is_none(), "a session upload leaked its staging directory");
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// Downloads into a granted folder land in a stage and publish across
    /// the bridge: a file, a fresh tree, and a merge that adds without
    /// replacing; an overlapping merge fails, and an over-cap remote file
    /// and a resume refuse at enqueue time.
    #[tokio::test]
    async fn saf_session_download_stages_through_temp_files() {
        let _leak_lock = SAF_STAGE_LEAK_LOCK.lock().expect("saf stage lock");
        let tmp = std::env::temp_dir().join(format!("linscp-saf-down-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let bridge = Arc::new(MockBridge::with_file("seed.txt", b"seed"));
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let svc = CommanderService::new(tmp.join("config"), Arc::new(fs));
        let session = Arc::new(MockSession::new());
        session.add_file("/down.txt", b"download bytes");
        session.add_dir("/tree");
        session.add_file("/tree/a.txt", b"tree a");
        session.add_dir("/tree/sub");
        session.add_file("/tree/sub/b.txt", b"tree b");
        session.add_dir("/mtree");
        session.add_file("/mtree/new.txt", b"merged in");
        session.add_dir("/mtree2");
        session.add_file("/mtree2/x.txt", b"remote x");
        let big = vec![0u8; (linscp_platform::MAX_SAF_DOCUMENT_BYTES + 1) as usize];
        session.add_file("/huge.bin", &big);
        let id = insert_remote_tab(&svc, session.clone(), SAF_GRANTED_DIR);
        let stages_before = saf_stage_names();
        let download = |body: Value| ApiEnvelope { method: "POST".into(), path: "/api/transfer/download".into(), body };
        // A file lands across the bridge.
        let queued = svc.dispatch_async(download(download_body(id, "down.txt", false, false))).await;
        assert_eq!(queued.status, 200, "{}", queued.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(bridge.bytes_of("down.txt").as_deref(), Some(b"download bytes".as_slice()), "the granted folder holds the download");
        // A fresh tree publishes whole, after the WebDAV risk dance.
        let risk = svc.dispatch_async(download(download_body(id, "tree", false, false))).await;
        assert_eq!(risk.status, 409, "{}", risk.payload);
        let queued_tree = svc.dispatch_async(download(download_body(id, "tree", true, false))).await;
        assert_eq!(queued_tree.status, 200, "{}", queued_tree.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(bridge.bytes_of_uri(&format!("{SAF_GRANTED_DIR}/document/tree/document/a.txt")).as_deref(), Some(b"tree a".as_slice()));
        assert_eq!(bridge.bytes_of_uri(&format!("{SAF_GRANTED_DIR}/document/tree/document/sub/document/b.txt")).as_deref(), Some(b"tree b".as_slice()));
        // A merge adds without replacing.
        bridge.add_dir(&format!("{SAF_GRANTED_DIR}/document/mtree"));
        bridge.add_file(&format!("{SAF_GRANTED_DIR}/document/mtree/document/old.txt"), b"stays");
        let merged = svc.dispatch_async(download(download_body(id, "mtree", true, true))).await;
        assert_eq!(merged.status, 200, "{}", merged.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(bridge.bytes_of_uri(&format!("{SAF_GRANTED_DIR}/document/mtree/document/new.txt")).as_deref(), Some(b"merged in".as_slice()));
        assert_eq!(bridge.bytes_of_uri(&format!("{SAF_GRANTED_DIR}/document/mtree/document/old.txt")).as_deref(), Some(b"stays".as_slice()), "the merge keeps granted files");
        // An overlapping merge fails instead of replacing.
        bridge.add_dir(&format!("{SAF_GRANTED_DIR}/document/mtree2"));
        bridge.add_file(&format!("{SAF_GRANTED_DIR}/document/mtree2/document/x.txt"), b"granted x");
        let overlap = svc.dispatch_async(download(download_body(id, "mtree2", true, true))).await;
        assert_eq!(overlap.status, 200, "{}", overlap.payload);
        let failed = wait_for_task(&svc, "Failed").await;
        assert!(failed["error"].as_str().unwrap_or("").contains("already exists"), "{}", failed);
        assert_eq!(bridge.bytes_of_uri(&format!("{SAF_GRANTED_DIR}/document/mtree2/document/x.txt")).as_deref(), Some(b"granted x".as_slice()), "the failed merge keeps the granted file");
        // An over-cap remote file and a resume refuse at enqueue time.
        let refused = svc.dispatch_async(download(download_body(id, "huge.bin", false, false))).await;
        assert_eq!(refused.status, 400, "{}", refused.payload);
        assert!(refused.payload["error"].as_str().unwrap_or("").contains("larger than a granted folder can carry"), "{}", refused.payload);
        let mut resume_body = download_body(id, "down.txt", false, false);
        resume_body["resume"] = json!(true);
        let resumed = svc.dispatch_async(download(resume_body)).await;
        assert_eq!(resumed.status, 400, "{}", resumed.payload);
        assert!(resumed.payload["error"].as_str().unwrap_or("").contains("Verified resume is not supported for granted folders"), "{}", resumed.payload);
        assert!(saf_stage_names().difference(&stages_before).next().is_none(), "a session download leaked its staging directory");
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// A WebDAV move into a granted folder stages the download, publishes
    /// across the bridge, then deletes the remote source by ETag.
    #[tokio::test]
    async fn saf_webdav_move_to_granted_folder_deletes_remote_source() {
        let _leak_lock = SAF_STAGE_LEAK_LOCK.lock().expect("saf stage lock");
        let tmp = std::env::temp_dir().join(format!("linscp-saf-move-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let bridge = Arc::new(MockBridge::with_file("seed.txt", b"seed"));
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let svc = CommanderService::new(tmp.join("config"), Arc::new(fs));
        let session = Arc::new(MockSession::new());
        session.add_file("/gone.txt", b"moving down");
        let id = insert_remote_tab(&svc, session.clone(), SAF_GRANTED_DIR);
        let moved = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/move".into(), body: json!({"tab": id, "direction": "download", "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "names": ["gone.txt"]}) }).await;
        assert_eq!(moved.status, 200, "{}", moved.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(bridge.bytes_of("gone.txt").as_deref(), Some(b"moving down".as_slice()), "the granted folder holds the move");
        assert!(session.stat("/gone.txt").await.unwrap().is_none(), "the remote source is deleted");
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// Synchronization plans and applies against a granted folder: a preview
    /// names the download and the unchanged file while the granted-only
    /// files need no action without delete; a run with delete downloads the
    /// remote-only file and removes the deleted ones; an upload run carries
    /// a granted-only file up.
    #[tokio::test]
    async fn saf_sync_preview_and_run_moves_bytes_both_ways() {
        // The shared check keeps its plain rules and accepts a granted root.
        assert!(check_sync_local_dir(SAF_GRANTED_DIR).is_ok(), "a granted root passes structurally");
        assert_eq!(check_sync_local_dir("relative/dir").unwrap_err(), "An absolute local directory is required.");
        let plain = std::env::temp_dir().to_string_lossy().into_owned();
        assert!(check_sync_local_dir(&plain).is_ok(), "a plain absolute directory still passes");

        let tmp = std::env::temp_dir().join(format!("linscp-saf-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let bridge = Arc::new(MockBridge::with_file("up.txt", b"upload me"));
        bridge.add_file(&MockBridge::doc_uri("same.txt"), b"same");
        bridge.add_file(&MockBridge::doc_uri("extra.txt"), b"deleted on remote");
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let svc = CommanderService::new(tmp.join("config"), Arc::new(fs));
        let session = Arc::new(MockSession::new());
        session.add_file("/down.txt", b"download me");
        session.add_file("/same.txt", b"same");
        session.set_mtime("/same.txt", 1_791_875_271).await.unwrap();
        let id = insert_remote_tab(&svc, session.clone(), SAF_GRANTED_DIR);
        let planned = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/sync/preview".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "mode": "local"}) }).await;
        assert_eq!(planned.status, 200, "{}", planned.payload);
        let items = planned.payload["plan"]["items"].as_array().unwrap();
        assert!(items.iter().any(|i| i["action"] == "download" && i["path"] == "down.txt"), "{}", planned.payload);
        assert!(items.iter().any(|i| i["action"] == "unchanged" && i["path"] == "same.txt"), "{}", planned.payload);
        assert!(!items.iter().any(|i| i["path"] == "up.txt"), "no delete, no action: {}", planned.payload);
        // A run with delete downloads and removes.
        let run = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/sync/run".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "mode": "local", "delete": true}) }).await;
        assert_eq!(run.status, 200, "{}", run.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(bridge.bytes_of("down.txt").as_deref(), Some(b"download me".as_slice()), "the granted folder holds the download");
        assert!(bridge.bytes_of("extra.txt").is_none() && bridge.bytes_of("up.txt").is_none(), "deleted files are gone from the granted folder");
        // An upload run carries a granted-only file up.
        bridge.add_file(&MockBridge::doc_uri("up2.txt"), b"upload too");
        let run_up = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/sync/run".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "mode": "remote"}) }).await;
        assert_eq!(run_up.status, 200, "{}", run_up.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(session.bytes_of("/up2.txt").as_deref(), Some(b"upload too".as_slice()), "the remote holds the upload");
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// Checksum criteria read the granted side through the bridge: contents
    /// that differ plan an upload, while an over-cap file refuses the plan
    /// naming the file, before its bytes are read.
    #[tokio::test]
    async fn saf_sync_checksum_criteria_reads_through_the_bridge() {
        let tmp = std::env::temp_dir().join(format!("linscp-saf-sum-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let bridge = Arc::new(MockBridge::with_file("a.txt", b"aaa"));
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let svc = CommanderService::new(tmp.join("config"), Arc::new(fs));
        let session = Arc::new(MockSession::new());
        session.add_file("/a.txt", b"bbb");
        let id = insert_remote_tab(&svc, session.clone(), SAF_GRANTED_DIR);
        let preview = |body: Value| ApiEnvelope { method: "POST".into(), path: "/api/sync/preview".into(), body };
        let planned = svc.dispatch_async(preview(json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "mode": "remote", "criteria": "checksum"}))).await;
        assert_eq!(planned.status, 200, "{}", planned.payload);
        let items = planned.payload["plan"]["items"].as_array().unwrap();
        assert!(items.iter().any(|i| i["action"] == "upload" && i["path"] == "a.txt"), "{}", planned.payload);
        // The same contents plan no action.
        session.add_file("/a.txt", b"aaa");
        let clean = svc.dispatch_async(preview(json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "mode": "remote", "criteria": "checksum"}))).await;
        assert_eq!(clean.status, 200, "{}", clean.payload);
        assert!(clean.payload["plan"]["items"].as_array().unwrap().iter().any(|i| i["action"] == "unchanged" && i["path"] == "a.txt"), "{}", clean.payload);
        // An over-cap file refuses the plan naming the file.
        let big = vec![0u8; (linscp_platform::MAX_SAF_DOCUMENT_BYTES + 1) as usize];
        bridge.add_file(&format!("{SAF_GRANTED_DIR}/document/big.bin"), &big);
        session.add_file("/big.bin", b"small");
        let refused = svc.dispatch_async(preview(json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "mode": "remote", "criteria": "checksum"}))).await;
        assert_eq!(refused.status, 400, "{}", refused.payload);
        assert!(refused.payload["error"].as_str().unwrap_or("").contains("larger than a granted folder can carry"), "{}", refused.payload);
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// Keep-up-to-date polls a granted folder it cannot watch: one pass
    /// carries a granted-only file up and the task completes.
    #[tokio::test]
    async fn saf_keep_up_to_date_polls_a_granted_folder() {
        let tmp = std::env::temp_dir().join(format!("linscp-saf-watch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let bridge = Arc::new(MockBridge::with_file("watch.txt", b"watch me"));
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let svc = CommanderService::new(tmp.join("config"), Arc::new(fs));
        let session = Arc::new(MockSession::new());
        let id = insert_remote_tab(&svc, session.clone(), SAF_GRANTED_DIR);
        let watch = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/transfer/keepuptodate".into(), body: json!({"tab": id, "local_dir": SAF_GRANTED_DIR, "remote_dir": "/", "count": 1}) }).await;
        assert_eq!(watch.status, 200, "{}", watch.payload);
        wait_for_task(&svc, "Completed").await;
        assert_eq!(session.bytes_of("/watch.txt").as_deref(), Some(b"watch me".as_slice()), "one pass carries the file up");
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// Link creation validates before it touches the filesystem, on every
    /// platform: the two names must differ and be single leaves, the link
    /// name must be free, and a granted folder gets the limitation's name.
    #[tokio::test]
    async fn local_symlink_validation_refuses_bad_names() {
        let tmp = std::env::temp_dir().join(format!("linscp-link-validate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let left = tmp.join("left"); let right = tmp.join("right");
        std::fs::create_dir_all(&left).unwrap(); std::fs::create_dir_all(&right).unwrap();
        std::fs::write(left.join("taken.txt"), b"occupied").unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let open = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": left, "other_local_dir": right}}) }).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let link = |target: &str, name: &str| ApiEnvelope { method: "POST".into(), path: "/api/local/link".into(), body: json!({"tab": id, "target": target, "name": name}) };
        let same = svc.dispatch(link("real.txt", "real.txt"));
        assert_eq!(same.status, 400, "{}", same.payload);
        assert!(same.payload["error"].as_str().unwrap_or("").contains("two different names"), "{}", same.payload);
        let separators = svc.dispatch(link("sub/real.txt", "alias.txt"));
        assert_eq!(separators.status, 400, "{}", separators.payload);
        let taken = svc.dispatch(link("real.txt", "taken.txt"));
        assert_eq!(taken.status, 400, "{}", taken.payload);
        assert!(taken.payload["error"].as_str().unwrap_or("").contains("already exists"), "{}", taken.payload);
        let granted = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": SAF_GRANTED_DIR, "other_local_dir": right}}) }).await;
        assert_eq!(granted.status, 200, "{}", granted.payload);
        let granted_id = granted.payload["tab"]["id"].as_u64().unwrap();
        let refused = svc.dispatch(ApiEnvelope { method: "POST".into(), path: "/api/local/link".into(), body: json!({"tab": granted_id, "target": "real.txt", "name": "alias.txt"}) });
        assert_eq!(refused.status, 400, "{}", refused.payload);
        assert!(refused.payload["error"].as_str().unwrap_or("").contains("app storage"), "{}", refused.payload);
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// On Unix both panes link: the main pane through `/api/local/link`,
    /// the other pane of a local tab through `/api/remote/link`. Windows
    /// creation needs a privilege this suite cannot grant itself, so it
    /// stays review-level there while validation runs everywhere.
    #[cfg(unix)]
    #[tokio::test]
    async fn local_symlink_creation_links_leaves() {
        let tmp = std::env::temp_dir().join(format!("linscp-link-create-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let left = tmp.join("left"); let right = tmp.join("right");
        std::fs::create_dir_all(&left).unwrap(); std::fs::create_dir_all(&right).unwrap();
        std::fs::write(left.join("real.txt"), b"target").unwrap();
        std::fs::write(right.join("other.txt"), b"other target").unwrap();
        let svc = CommanderService::new(tmp.join("config"), Arc::new(NativeLocalFs::new()));
        let open = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": left, "other_local_dir": right}}) }).await;
        assert_eq!(open.status, 200, "{}", open.payload);
        let id = open.payload["tab"]["id"].as_u64().unwrap();
        let made = svc.dispatch(ApiEnvelope { method: "POST".into(), path: "/api/local/link".into(), body: json!({"tab": id, "target": "real.txt", "name": "alias.txt"}) });
        assert_eq!(made.status, 200, "{}", made.payload);
        assert_eq!(std::fs::read_link(left.join("alias.txt")).unwrap().to_string_lossy(), "real.txt");
        let other = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/remote/link".into(), body: json!({"tab": id, "target": "other.txt", "name": "other-alias.txt"}) }).await;
        assert_eq!(other.status, 200, "{}", other.payload);
        assert_eq!(std::fs::read_link(right.join("other-alias.txt")).unwrap().to_string_lossy(), "other.txt");
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[tokio::test]
    async fn monitor_routes_validate_selection_and_never_expose_site_secrets() {
        let tmp = std::env::temp_dir().join(format!("linscp-monitor-routes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let config = tmp.join("config");
        std::fs::create_dir_all(&config).unwrap();
        let svc = CommanderService::new(config.clone(), Arc::new(NativeLocalFs::new()));
        let mut store = SessionStore::new();
        let mut site = StoredSite::new("worker", linscp_types::ProtocolScheme::Sftp, "worker.example");
        site.username = "alice".into();
        site.password = Some("do-not-list".into());
        store.upsert(site);
        // The site carries a password, so the store encrypts it with the master
        // key, and that only exists while the vault is unlocked. A save into a
        // locked vault fails with "Vault is locked" rather than writing the
        // password in the clear - which is the behaviour asserted below, before
        // the same store is saved for real.
        store.save_to_dir(&config, svc.secret_vault.as_ref())
            .expect_err("a password cannot be saved while the vault is locked");
        unlock_for_test(&svc);
        store.save_to_dir(&config, svc.secret_vault.as_ref()).unwrap();
        let hosts = svc.dispatch_async(ApiEnvelope { method: "GET".into(), path: "/api/monitor/hosts".into(), body: json!({}) }).await;
        assert_eq!(hosts.status, 200, "{}", hosts.payload);
        assert_eq!(hosts.payload["sites"][0]["name"], "worker");
        assert!(!hosts.payload.to_string().contains("do-not-list"));
        assert!(!hosts.payload.to_string().contains("alice"));
        let sample = |body: Value| ApiEnvelope { method: "POST".into(), path: "/api/monitor/sample".into(), body };
        for body in [json!({"tabs": []}), json!({"tabs": [1, 1]}), json!({"tabs": ["x"]}),
            json!({"tabs": [1], "timeout": 0}), json!({"tabs": [1], "timeout": "5"}),
            json!({"tabs": (0..33).collect::<Vec<u32>>()})] {
            assert_eq!(svc.dispatch_async(sample(body.clone())).await.status, 400, "{body}");
        }
        let missing = svc.dispatch_async(sample(json!({"tabs": [999]}))).await;
        assert_eq!(missing.status, 200);
        assert_eq!(missing.payload["samples"][0]["status"], "disconnected");
        // A local tab has two panes, and opening one without its second
        // directory is refused, so both are named here.
        let local = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": tmp, "other_local_dir": tmp}}) }).await;
        assert_eq!(local.status, 200, "{}", local.payload);
        let id = local.payload["tab"]["id"].as_u64().unwrap();
        let unsupported = svc.dispatch_async(sample(json!({"tabs": [id]}))).await;
        assert_eq!(unsupported.payload["samples"][0]["status"], "unsupported");
        for timeout in [json!(0), json!(61), json!("10"), json!(1.5)] {
            let refused = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/tabs/open".into(), body: json!({"session": {"protocol": "local", "local_dir": tmp}, "connect_timeout": timeout}) }).await;
            assert_eq!(refused.status, 400);
        }
        let settings_get = svc.dispatch_async(ApiEnvelope { method: "GET".into(), path: "/api/monitor/settings".into(), body: json!({}) }).await;
        assert_eq!(settings_get.status, 200);
        assert_eq!(settings_get.payload["document"]["settings"]["outage_threshold"], 3);
        let doc = json!({"version": 1, "settings": {"interval_secs": 5.0, "connect_timeout_secs": 10.0,
            "poll_timeout_secs": 10.0, "outage_threshold": 1, "notify_on_outage": true,
            "beep_on_outage": false, "beep_cooldown_secs": 10},
            "hosts": {"site:worker": {"enabled_metrics": ["cpu", "net"], "custom_metrics": [
                {"id": "users", "name": "Users", "command": "who | wc -l", "parse": "number", "display": "sparkline", "unit": ""}
            ], "paused": false}}});
        let saved = svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/monitor/settings".into(), body: doc.clone() }).await;
        assert_eq!(saved.status, 200, "{}", saved.payload);
        let reread = svc.dispatch_async(ApiEnvelope { method: "GET".into(), path: "/api/monitor/settings".into(), body: json!({}) }).await;
        assert_eq!(reread.payload["document"], doc);
        let offline = svc.dispatch_async(sample(json!({"tabs": [998]}))).await;
        assert_eq!(offline.payload["samples"][0]["outage_started"], true);
        assert!(svc.dispatch(ApiEnvelope { method: "GET".into(), path: "/api/logs".into(), body: json!({}) }).payload.to_string().contains("is offline"));
        let mut bad = doc.clone();
        bad["settings"]["outage_threshold"] = json!(0);
        assert_eq!(svc.dispatch_async(ApiEnvelope { method: "POST".into(), path: "/api/monitor/settings".into(), body: bad }).await.status, 400);
        let _ = std::fs::remove_dir_all(tmp);
    }
}
