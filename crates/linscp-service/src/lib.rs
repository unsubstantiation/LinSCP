#![allow(clippy::too_many_arguments)]
#![allow(unused_variables, unused_imports, dead_code, unused_mut, clippy::all)]
//! Transport-neutral Commander backend service (`CommanderService`).
//!
//! Both `linscp-http` (axum browser server) and `linscp-tauri` (native Linux,
//! Windows, and Android shell) route every UI command through
//! `CommanderService::dispatch` (sync) and `dispatch_async` (async for remote).

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use linscp_engine::{
    parse_filezilla_xml, parse_openssh_config, PreferencesStore, SessionStore, StoredSite,
};
use linscp_platform::{
    config_dir, gui_os, write_private_file_atomic, LocalFs, NativeLocalFs, NativeSecretVault,
    SecretVault,
};
use linscp_types::{
    ApiEnvelope, ApiReply, SessionConfig, TabSummary, TransferQueueItem, UserPreferences,
};
use serde_json::{json, Value};

pub mod ops;
pub mod queue;
pub mod tabs;
pub mod terminal_bridge;

use tabs::{TabRuntime, parse_tab_id_str, session_is_local, collect_session_folders, stored_site_to_gui_json};
use linscp_engine::url_and_raw::GuiConnectError;

struct InnerState {
    config_root: PathBuf,
    next_tab_id: u64,
    active_tab_id: Option<u64>,
    tabs: HashMap<u64, TabRuntime>,
    challenges: HashMap<u64, TabRuntime>,
    logs: Vec<Value>,
    preferences: UserPreferences,
    queue_transfers: Vec<Value>,
}

#[derive(Clone)]
pub struct CommanderService {
    local_fs: Arc<dyn LocalFs>,
    secret_vault: Arc<dyn SecretVault>,
    state: Arc<Mutex<InnerState>>,
    event_tx: Arc<Mutex<Option<tokio::sync::broadcast::Sender<Value>>>>,
    queue: queue::QueueManager,
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
        let preferences = PreferencesStore::load(&config_root).unwrap_or_default();
        Self {
            local_fs,
            secret_vault,
            state: Arc::new(Mutex::new(InnerState {
                config_root,
                next_tab_id: 1,
                active_tab_id: None,
                tabs: HashMap::new(),
                challenges: HashMap::new(),
                logs: Vec::new(),
                preferences,
                queue_transfers: Vec::new(),
            })),
            event_tx: Arc::new(Mutex::new(None)),
            queue: queue::QueueManager::new(tokio::sync::broadcast::channel(64).0),
        }
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
            ("GET", "/api/local/roots") => self.handle_local_roots(),
            ("GET", "/api/local/list") => self.handle_local_list(&query),
            ("GET", "/api/local/edit") => self.handle_local_edit_get(&query),
            ("GET", "/api/remote/list") => self.handle_remote_list(&query),
            ("GET", "/api/remote/edit") => self.handle_remote_edit_get(&query),
            ("GET", "/api/preferences") => self.handle_get_preferences(),
            ("POST", "/api/preferences") => self.handle_save_preferences(req.body),
            ("GET", "/api/sessions") => self.handle_list_sessions(),
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
            ("POST", "/api/workspaces/open") => self.handle_workspaces_open(req.body),
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
            ("POST", "/api/local/save") => self.handle_local_save(req.body),
            ("GET", "/api/logs") => self.handle_logs(),
            ("GET", "/api/cleanup") => self.handle_cleanup_get(),
            ("POST", "/api/cleanup") => self.handle_cleanup_post(req.body),
            ("GET", "/api/shell/pending") => self.handle_shell_pending(),
            ("POST", "/api/shell/consume") => self.handle_shell_consume(req.body),
            ("POST", "/api/shell/dismiss") => self.handle_shell_dismiss(req.body),
            ("GET", "/api/session/url") => self.handle_session_url(&query),
            ("GET", "/api/remote/transfer/targets") => self.handle_remote_transfer_targets(&query),
            ("POST", "/api/remote/mkdir") => self.handle_remote_mkdir(req.body),
            ("POST", "/api/remote/delete") => self.handle_remote_delete(req.body),
            ("POST", "/api/remote/rename") => self.handle_remote_rename(req.body),
            ("POST", "/api/remote/chmod") => self.handle_remote_chmod(req.body),
            ("POST", "/api/remote/properties") => self.handle_remote_properties(req.body),
            ("POST", "/api/remote/rights") => self.handle_remote_rights(req.body),
            ("POST", "/api/remote/search") => self.handle_remote_search(req.body),
            ("POST", "/api/remote/checksum") => self.handle_remote_checksum(req.body),
            ("POST", "/api/remote/save") => self.handle_remote_save(req.body),
            ("POST", "/api/remote/copy") => self.handle_remote_copy(req.body),
            ("POST", "/api/remote/link") => self.handle_remote_link(req.body),
            ("POST", "/api/sync/preview") => self.handle_sync_preview(req.body),
            ("POST", "/api/sync/run") => self.handle_sync_run(req.body),
            ("POST", "/api/transfer/upload") => self.handle_transfer_upload(req.body),
            ("POST", "/api/transfer/download") => self.handle_transfer_download(req.body),
            ("POST", "/api/transfer/move") => self.handle_transfer_move(req.body),
            ("POST", "/api/transfer/keepuptodate") => self.handle_keepuptodate(req.body),
            ("POST", "/api/remote/transfer") => self.handle_remote_transfer(req.body),
            ("POST", "/api/session/copyid") => self.handle_copyid(req.body),
            ("POST", "/api/session/terminal") => self.handle_session_terminal(req.body),
            ("POST", "/api/terminal/input") => self.handle_terminal_input(req.body),
            ("POST", "/api/terminal/close") => self.handle_terminal_close(req.body),
            ("GET", "/api/terminal/output") => self.handle_terminal_output(&query),
            ("POST", "/api/queue/pause") => self.handle_queue_pause(),
            ("POST", "/api/queue/resume") => self.handle_queue_resume(),
            ("POST", "/api/queue/cancel") => self.handle_queue_cancel(req.body),
            ("POST", "/api/queue/clear") => self.handle_queue_clear(),
            ("POST", "/api/queue/retry") => self.handle_queue_retry(req.body),
            ("POST", "/api/queue/priority") => self.handle_queue_priority(req.body),
            ("GET", "/api/accounts") => self.handle_accounts(),
            ("POST", "/api/login") => ApiReply{ status: 400, payload: json!({"success": false, "error": "Accounts not enabled"})},
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
            ("POST", "/api/tabs/open") => self.open_tab_async(req.body).await,
            ("POST", "/api/tabs/verify") => self.verify_tab_async(req.body).await,
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
            ("POST", "/api/remote/rename") => self.rename_remote_async(req.body).await,
            ("POST", "/api/remote/transfer") => self.remote_transfer_async(req.body).await,
            ("POST", "/api/desktop/check") => self.handle_desktop_check_async(req.body).await,
            ("POST", "/api/desktop/install") => self.handle_desktop_install_async(req.body).await,
            ("POST", "/api/desktop/launch") => self.handle_desktop_launch_async(req.body).await,
            ("POST", "/api/desktop/ticket") => self.handle_desktop_ticket(req.body),
            _ => self.dispatch(req),
        }
    }

    async fn open_tab_async(&self, body: Value) -> ApiReply {
        let session = body.get("session").cloned().unwrap_or(json!({}));
        if session_is_local(&session) { return self.handle_tabs_open(body); }
        let site_name = body.get("site_name").and_then(Value::as_str).filter(|s| !s.is_empty());
        let root = self.config_root();
        let (spec, mut clean) = match tabs::parse_gui_session_spec(&session, site_name, &root, self.secret_vault.as_ref()) {
            Ok(value) => value,
            Err(error) => return api_error(400, error),
        };
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
        let spec = match tab.spec.as_ref() { Some(s) => s, None => return api_error(400, "Missing session settings") };
        match tabs::dial_gui_tab_session(spec, &self.config_root(), false, "en").await {
            Ok((session, remote_dir, observed)) => {
                tab.remote = Some(session);
                tab.remote_dir = remote_dir;
                tab.observed_hostkey = observed;
                tab.connected = true;
                tab.error.clear();
                let mut state = self.state.lock().expect("state mutex");
                state.challenges.remove(&tab.id);
                state.active_tab_id = Some(tab.id);
                state.tabs.insert(tab.id, tab.clone());
                ApiReply { status: 200, payload: json!({"success": true, "tab": tab.describe()}) }
            }
            Err(GuiConnectError::HostKeyChallenge(challenge)) => {
                tabs::apply_challenge_to_tab(tab, &challenge);
                let response = tab.hostkey_challenge_json();
                self.state.lock().expect("state mutex").challenges.insert(tab.id, tab.clone());
                ApiReply { status: 409, payload: json!({"success": false, "error": challenge.error, "challenge": response}) }
            }
            Err(GuiConnectError::Failed(error)) => api_error(400, error),
        }
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
                _ => return api_error(400, "Invalid host-key fingerprint"),
            };
            let path = self.config_root().join("sshhostkeys");
            let result = linscp_engine::hostkeys::HostKeyCache::load_from_path(&path).and_then(|mut cache| {
                cache.upsert(challenge["host"].as_str().unwrap_or(""), challenge["port"].as_u64().unwrap_or(22) as u16, kind, key)?;
                cache.save_to_path(&path)
            });
            if let Err(error) = result { return api_error(500, error); }
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
        if !source_is_dav && (move_item || !source_is_sftp) { return api_error(501, "Remote transfers support WebDAV sources, or SFTP sources for copies only."); }
        if source_is_sftp && !body.get("accept_sftp_copy_risk").and_then(Value::as_bool).unwrap_or(false) {
            return ApiReply { status: 409, payload: json!({"success": false, "error": "SFTP copy requires confirmation", "sftp_copy_risk": true}) };
        }
        if body.get("filemask").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) { return api_error(400, "File masks are not supported for remote moves."); }
        let directory = body.get("directory").and_then(Value::as_str).unwrap_or("");
        if !directory.starts_with('/') || directory.contains("//") || directory.chars().any(char::is_control) || directory.contains('\\') || directory.split('/').any(|part| part == "." || part == "..") {
            return api_error(400, "An absolute remote directory without dot segments is required.");
        }
        let names = match body.get("names").and_then(Value::as_array) { Some(names) if !names.is_empty() && names.len() <= 1000 => names, _ => return api_error(400, "Select at least one file") };
        let mut jobs = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for value in names {
            let name = match value.as_str() { Some(name) if !name.is_empty() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\') && !name.contains(':') && !name.chars().any(char::is_control) => name, _ => return api_error(400, "Invalid file name") };
            if !seen.insert(name) { return api_error(400, "Duplicate file name"); }
            let source = format!("{}/{}", tab.remote_dir.trim_end_matches('/'), name);
            let target = format!("{}/{}", directory.trim_end_matches('/'), name);
            if same_tab && source == target { return api_error(400, "Source and destination are the same file."); }
            let (source_entry, tag) = if source_is_dav {
                match session.dav_stat_with_etag(&source).await {
                    Ok((Some(entry), Some(tag))) if !entry.is_symlink && tag.starts_with('"') && tag.ends_with('"') && tag.len() >= 2 && !tag[1..tag.len()-1].contains('"') && !tag.chars().any(char::is_control) => (entry, Some(tag)),
                    Ok(_) => return api_error(400, "WebDAV transfers require an existing resource and a strong source ETag."),
                    Err(error) => return api_error(400, error.to_string()),
                }
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
            if is_dir && (!same_tab || !move_item) && (move_item || !(source_is_sftp || source_is_dav) || target_session.scheme() != linscp_types::ProtocolScheme::Sftp) { return api_error(501, "Directory copies require an SFTP or WebDAV source and an SFTP destination; cross-server directory moves are unsupported."); }
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
        if resume && (move_item || upload || tab.is_local || session.as_ref().is_none_or(|s| !matches!(s.scheme(), linscp_types::ProtocolScheme::Dav | linscp_types::ProtocolScheme::Davs | linscp_types::ProtocolScheme::Webdav | linscp_types::ProtocolScheme::Webdavs))) {
            return api_error(400, "Verified resume is supported only for WebDAV file downloads.");
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
                let meta = match std::fs::symlink_metadata(&source) { Ok(meta) if (meta.is_file() || (move_item && meta.is_dir())) && !meta.file_type().is_symlink() => meta, Ok(_) => return api_error(400, "Only regular files and movable directories are supported"), Err(error) => return api_error(400, error.to_string()) };
                size = if meta.is_dir() { 0 } else { meta.len() };
                is_dir = meta.is_dir();
                exists = std::fs::symlink_metadata(&destination).is_ok();
            } else if upload {
                let meta = match std::fs::symlink_metadata(&local) { Ok(meta) if (meta.is_file() || meta.is_dir()) && !meta.file_type().is_symlink() => meta, Ok(_) => return api_error(400, "Only regular files and directories can be transferred"), Err(error) => return api_error(400, error.to_string()) };
                is_dir = meta.is_dir();
                size = if is_dir { 0 } else { meta.len() };
                exists = match session.as_ref().unwrap().stat(&other).await {
                    Ok(Some(entry)) if entry.is_symlink || entry.is_dir != is_dir => return api_error(400, "Destination type conflicts with source or is a symlink"),
                    Ok(entry) => entry.is_some(), Err(error) => return api_error(400, error.to_string()),
                };
            } else {
                let entry = match session.as_ref().unwrap().stat(&other).await { Ok(Some(entry)) if !entry.is_symlink => entry, Ok(_) => return api_error(400, "Only existing files and directories can be transferred"), Err(error) => return api_error(400, error.to_string()) };
                is_dir = entry.is_dir;
                size = if is_dir { 0 } else { entry.size };
                exists = std::fs::symlink_metadata(&local).is_ok();
            }
            if resume && is_dir { return api_error(400, "Verified resume is supported only for individual files."); }
            if move_item && !tab.is_local && is_dir { return api_error(400, "WebDAV directory moves are not supported."); }
            if is_dir && !move_item {
                if tab.is_local || session.as_ref().is_none_or(|s| s.scheme() != linscp_types::ProtocolScheme::Sftp) { return api_error(400, "Directory transfers are supported only for SFTP"); }
                if exists && !merge_names.contains(name) { directory_conflicts.push(name.to_string()); }
            }
            if move_item && exists {
                return api_error(409, "Moves require a new destination; overwriting is not supported.");
            }
            if !upload || tab.is_local {
                let target = Path::new(&destination);
                if std::fs::symlink_metadata(target).is_ok_and(|m| m.file_type().is_symlink() || (is_dir && !m.is_dir()) || (!is_dir && !m.is_file())) { return api_error(400, "Destination type conflicts with source or is a symlink"); }
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
                let tag = match session.as_ref().unwrap().dav_get_etag(&other).await {
                    Ok((Some(tag), false)) if tag.starts_with('"') && tag.ends_with('"') && tag.len() >= 2 && !tag[1..tag.len()-1].contains('"') && !tag.chars().any(char::is_control) => tag,
                    Ok(_) => return api_error(400, "WebDAV moves and verified resume require a strong source ETag."),
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
            let resolved = match resolve_contained(&tab.other_local_dir, &path) {
                Ok(p) => p, Err(e) => return ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
            };
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
        let stored = tabs::build_stored_site_for_save(&final_name, &spec);
        let mut store = SessionStore::load_from_dir(&cfg_root, self.secret_vault.as_ref()).unwrap_or_default();
        store.upsert(stored);
        if let Err(e) = store.save_to_dir(&cfg_root, self.secret_vault.as_ref()) {
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
        ApiReply{ status: 200, payload: json!({"success": true, "workspaces": data.get("workspaces").cloned().unwrap_or(json!([])), "file": path.to_string_lossy()})}
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
        let tabs: Vec<Value> = {
            let g = self.state.lock().expect("m");
            g.tabs.values().map(|t| json!({"name": t.name, "kind": if t.is_local { "local"} else {"remote"}, "local_dir": t.local_dir, "remote_dir": t.remote_dir, "site": t.site_name})).collect()
        };
        if tabs.is_empty() { return ApiReply{ status: 400, payload: json!({"success": false, "error": "There are no open tabs to save."})}; }
        let path = cfg.join("workspaces.json");
        let mut data: Value = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}));
        if !data.is_object() { data = json!({}); }
        if data.get("workspaces").is_none() { data["workspaces"] = json!({}); }
        let overw = body.get("overwrite").and_then(|v| v.as_bool()).unwrap_or(false);
        if data["workspaces"].get(&name).is_some() && !overw {
            return ApiReply{ status: 409, payload: json!({"success": false, "error": format!("A workspace named \"{name}\" already exists."), "exists": true})};
        }
        data["workspaces"][&name] = json!({"tabs": tabs, "active": 0, "updated": 0});
        let bytes = serde_json::to_vec_pretty(&data).unwrap_or_default();
        if let Err(e) = write_private_file_atomic(&path, &bytes) {
            return ApiReply{ status: 500, payload: json!({"success": false, "error": e.to_string()})};
        }
        ApiReply{ status: 200, payload: json!({"success": true, "workspace": json!({"name": name})})}
    }
    fn handle_workspaces_open(&self, body: Value) -> ApiReply {
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let cfg = self.state.lock().expect("m").config_root.clone();
        let path = cfg.join("workspaces.json");
        let data: Value = std::fs::read_to_string(&path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}));
        let entry = data.get("workspaces").and_then(|w| w.get(&name));
        if entry.is_none() { return ApiReply{ status: 400, payload: json!({"success": false, "error": format!("No workspace named \"{name}\" exists.")})}; }
        ApiReply{ status: 200, payload: json!({"success": true, "name": name})}
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
            return ApiReply{ status: 200, payload: json!({"success": true, "tab": tab.describe()})};
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
        match std::fs::create_dir_all(&target) {
            Ok(_) => ApiReply{ status: 200, payload: json!({"success": true})},
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e.to_string()})},
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
                    let path = Path::new(&p);
                    let res = if path.is_dir() && !path.is_symlink() { std::fs::remove_dir_all(path) } else { std::fs::remove_file(path) };
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
        let src = match resolve_contained(&base, &old) { Ok(p)=>p, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},};
        let dst = match resolve_contained(&base, &new) { Ok(p)=>p, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},};
        match gui_os::rename_no_replace(Path::new(&src), Path::new(&dst)) {
            Ok(_) => ApiReply{ status: 200, payload: json!({"success": true})},
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e.to_string()})},
        }
    }
    fn handle_local_chmod(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let base = tab_id.and_then(|id| self.state.lock().expect("m").tabs.get(&id).map(|t| t.local_dir.clone())).unwrap_or_else(|| self.default_local_dir());
        let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let perm = body.get("permissions").or_else(|| body.get("mode")).and_then(|v| v.as_str()).unwrap_or("").to_string();
        if name.is_empty() { return ApiReply{ status:400, payload: json!({"success": false, "error": "Select an item first."})}; }
        let target = match resolve_contained(&base, &name) { Ok(p)=>p, Err(e)=> return ApiReply{ status:400, payload: json!({"success": false, "error": e})},};
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
    fn handle_shell_consume(&self, body: Value) -> ApiReply {
        let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let cfg = self.state.lock().expect("m").config_root.clone();
        let manifest = match ops::take_shell_manifest(&cfg, &id) {
            Ok(v) => v, Err(e) => return ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        };
        // Validate tab
        let g = self.state.lock().expect("m");
        let tab = tab_id.and_then(|id| g.tabs.get(&id).cloned());
        if tab.is_none() || tab.as_ref().map(|t| t.is_local).unwrap_or(true) {
            return ApiReply{ status: 400, payload: json!({"success": false, "error": "Files from a file manager can only be sent to a session tab."})};
        }
        drop(g);
        ApiReply{ status: 200, payload: json!({"success": true, "queued": manifest.get("items").cloned().unwrap_or(json!([])), "manifest": manifest})}
    }
    fn handle_shell_dismiss(&self, body: Value) -> ApiReply {
        let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let cfg = self.state.lock().expect("m").config_root.clone();
        match ops::dismiss_shell_manifest(&cfg, &id) {
            Ok(_) => ApiReply{ status: 200, payload: json!({"success": true})},
            Err(e) => ApiReply{ status: 400, payload: json!({"success": false, "error": e})},
        }
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
            match std::fs::create_dir_all(&target) { Ok(_)=> ApiReply{ status:200, payload: json!({"success": true})}, Err(e)=> ApiReply{ status:400, payload: json!({"success": false, "error": e.to_string()})}}
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
                        let path=Path::new(&p);
                        let res = if path.is_dir() && !path.is_symlink() { std::fs::remove_dir_all(path) } else { std::fs::remove_file(path) };
                        if let Err(e)=res { errs.push(format!("{n}: {e}")); }
                    },
                    Err(e)=> errs.push(format!("{n}: {e}")),
                }
            }
            if errs.is_empty() { ApiReply{ status:200, payload: json!({"success": true})}} else { ApiReply{ status:400, payload: json!({"success": false, "error": errs.join("; ")})}}
        } else { ApiReply{ status:400, payload: json!({"success": false, "error": "Remote delete not implemented"})}}
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
            match gui_os::rename_no_replace(Path::new(&src), Path::new(&dst)) { Ok(_)=> ApiReply{ status:200, payload: json!({"success": true})}, Err(e)=> ApiReply{ status:400, payload: json!({"success": false, "error": e.to_string()})}}
        } else { ApiReply{ status:400, payload: json!({"success": false, "error": "not implemented"})}}
    }
    fn handle_remote_chmod(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    fn handle_remote_properties(&self, body: Value) -> ApiReply {
        let tab_id = body.get("tab").and_then(|v| if v.is_number() { v.as_u64()} else { v.as_str().and_then(|s| s.parse().ok()) });
        let g = self.state.lock().expect("m");
        let tab = match tab_id.and_then(|id| g.tabs.get(&id).cloned()) { Some(t)=>t, None=> return ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})},};
        drop(g);
        let names: Vec<String> = body.get("names").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|e| e.get("name").and_then(|v| v.as_str()).or(e.as_str()).map(|s| s.to_string())).collect()).unwrap_or_else(|| body.get("name").and_then(|v| v.as_str()).map(|s| vec![s.to_string()]).unwrap_or_default());
        let mut rows=Vec::new();
        for n in names {
            let p = if tab.is_local { resolve_contained(&tab.other_local_dir, &n).unwrap_or(n.clone()) } else { format!("{}/{}", tab.remote_dir, n) };
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
    fn handle_remote_search(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    fn handle_remote_checksum(&self, body: Value) -> ApiReply {
        ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})}
    }
    fn handle_remote_save(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    fn handle_remote_copy(&self, body: Value) -> ApiReply { ApiReply{ status:400, payload: json!({"success": false, "error": "not implemented"})}}
    fn handle_remote_link(&self, body: Value) -> ApiReply { ApiReply{ status:400, payload: json!({"success": false, "error": "not implemented"})}}
    fn handle_sync_preview(&self, body: Value) -> ApiReply { ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})}}
    fn handle_sync_run(&self, body: Value) -> ApiReply { ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})}}
    fn handle_transfer_upload(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    fn handle_transfer_download(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    fn handle_transfer_move(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    fn handle_keepuptodate(&self, body: Value) -> ApiReply { ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})}}
    fn handle_remote_transfer(&self, _body: Value) -> ApiReply { Self::not_implemented() }
    fn handle_copyid(&self, body: Value) -> ApiReply { ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})}}
    fn handle_session_terminal(&self, body: Value) -> ApiReply { ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})}}
    fn handle_terminal_input(&self, body: Value) -> ApiReply { ApiReply{ status:200, payload: json!({"success": true})}}
    fn handle_terminal_close(&self, body: Value) -> ApiReply { ApiReply{ status:200, payload: json!({"success": true})}}
    fn handle_terminal_output(&self, query: &BTreeMap<String,String>) -> ApiReply {
        ApiReply{ status:200, payload: json!({"success": true, "data": "", "offset": 0, "alive": false, "exit_code": 0})}
    }
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
    fn handle_accounts(&self) -> ApiReply { ApiReply{ status:200, payload: json!({"accounts_enabled": false})}}
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
            "run" => ApiReply{ status:400, payload: json!({"success": false, "error": "Not connected"})},
            _ => ApiReply{ status:400, payload: json!({"success": false, "error": format!("Unknown action '{action}'")})},
        }
    }
    fn handle_command_exec(&self, body: Value) -> ApiReply {
        let cmd = body.get("command").and_then(|v| v.as_str()).unwrap_or("");
        if cmd.is_empty() { return ApiReply{ status:400, payload: json!({"success": false, "error": "Empty command"})}; }
        if cmd.contains('\n') || cmd.contains('\r') { return ApiReply{ status:400, payload: json!({"success": false, "error": "A command with a newline is never written"})}; }
        Self::not_implemented()
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
        match linscp_platform::desktop::launch_remote_desktop(&ticket, &config_root, false) {
            Ok(linscp_platform::desktop::DesktopLaunchResult::Spawned { pid, viewer, argv }) => {
                ApiReply{ status:200, payload: json!({"success": true, "launched": true, "pid": pid, "viewer": viewer.display().to_string(), "argv": argv})}
            },
            Ok(linscp_platform::desktop::DesktopLaunchResult::FileTicket { path, viewer_hint }) => {
                // Read file content for HTTP clients that cannot read server filesystem.
                let file_content = proto_ticket.file_content.clone().or_else(|| std::fs::read_to_string(&path).ok());
                ApiReply{ status:200, payload: json!({"success": true, "launched": false, "file": path.display().to_string(), "file_content": file_content, "file_extension": proto_ticket.file_extension, "viewer_hint": viewer_hint, "kind": ticket.kind})}
            },
            Ok(linscp_platform::desktop::DesktopLaunchResult::BrowserGateway { url_hint }) => {
                ApiReply{ status:200, payload: json!({"success": true, "launched": false, "gateway": url_hint, "kind": ticket.kind, "viewer": ticket.viewer, "argv": ticket.argv})}
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
        if target_port == 0 { target_port = kind.default_viewer(false).len() as u16; target_port = match kind { linscp_proto::remote_desktop::RemoteDesktopKind::Rdp => 3389, linscp_proto::remote_desktop::RemoteDesktopKind::Vnc => 5900, linscp_proto::remote_desktop::RemoteDesktopKind::Spice => 5900, _ => 22 }; }
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
        match linscp_platform::desktop::launch_remote_desktop(&ticket, &config_root, false) {
            Ok(linscp_platform::desktop::DesktopLaunchResult::Spawned{ pid, viewer, argv }) => ApiReply{ status:200, payload: json!({"success": true, "launched": true, "available": true, "pid": pid, "viewer": viewer.display().to_string(), "argv": argv, "kind": kind.as_str(), "host": target_host})},
            Ok(linscp_platform::desktop::DesktopLaunchResult::FileTicket{ path, viewer_hint }) => {
                let file_content = proto_ticket.file_content.clone().or_else(|| std::fs::read_to_string(&path).ok());
                ApiReply{ status:200, payload: json!({"success": true, "launched": false, "available": true, "file": path.display().to_string(), "file_content": file_content, "file_extension": proto_ticket.file_extension, "viewer_hint": viewer_hint, "kind": ticket.kind})}
            },
            Ok(linscp_platform::desktop::DesktopLaunchResult::BrowserGateway{ url_hint }) => ApiReply{ status:200, payload: json!({"success": true, "launched": false, "available": true, "gateway": url_hint, "kind": ticket.kind, "viewer": ticket.viewer, "argv": ticket.argv})},
            Err(e) => ApiReply{ status:500, payload: json!({"success": false, "error": e})},
        }
    }
}

fn api_error(status: u16, error: impl Into<String>) -> ApiReply {
    ApiReply { status, payload: json!({"success": false, "error": error.into()}) }
}

fn resolve_local_path_for_list(path: &str) -> Result<String, String> {
    if path.trim().is_empty() { return Err("No path given".to_string()); }
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
fn check_local_pane_directory(raw: &str, label: &str) -> Result<String, String> {
    let t = raw.trim();
    if t.is_empty() { return Err(format!("The {label} is required.")); }
    if t.chars().any(|c| c.is_control()) { return Err(format!("The {label} must not contain control characters.")); }
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
    use linscp_types::ProtocolScheme;
    #[test]
    fn unsupported_operations_never_report_success_or_write_files() {
        let svc = CommanderService::default();
        for path in [
            "/api/transfer/upload", "/api/transfer/download", "/api/transfer/move",
            "/api/remote/transfer", "/api/remote/save", "/api/remote/chmod",
            "/api/remote/rights", "/api/remote/search", "/api/command/exec",
        ] {
            let reply = svc.dispatch(ApiEnvelope {
                method: "POST".into(), path: path.into(),
                body: json!({"command": "test", "path": "nonexistent-test-file"}),
            });
            assert_eq!(reply.status, 501, "{path}");
            assert_eq!(reply.payload["success"], false, "{path}");
        }
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
        std::fs::write(&queued_file, vec![63u8; 25 * 1024 * 1024]).unwrap();
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
    async fn exercise_ftp_uploads(svc: &CommanderService, id: u64, local: &Path, remote: &Path) {
        let request = |body: Value| ApiEnvelope { method: "POST".into(), path: "/api/transfer/upload".into(), body };
        std::fs::write(local.join("up.txt"), b"FTP upload payload").unwrap();
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
        let progress = move |_: u64, _: u64| callback_flag.store(true, std::sync::atomic::Ordering::SeqCst);
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
        assert!(remote.join(stage.trim_start_matches('/')).exists(), "reported temporary file must exist");
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
        let reopened = svc.dispatch_async(request("/api/tabs/open", json!({"session": {"protocol": "ftp", "host": "127.0.0.1", "port": port, "username": "testuser", "password": "testpass", "local_dir": local, "initial_dir": "/"}}))).await;
        assert_eq!(reopened.status, 200, "{}", reopened.payload);
        let new_id = reopened.payload["tab"]["id"].as_u64().unwrap();
        exercise_ftp_upload_cancellation(&svc, new_id, &local, &remote).await;
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
        let child = Command::new("/usr/bin/python3").arg(server_path).env("LSCP_TEST_PORT", "0").env("LSCP_TEST_GET_DELAY", "0.005").env("LSCP_TEST_DELETE_RACE", "1").env("LSCP_TEST_DROP_ONCE", "/resume-drop.bin").env("LSCP_TEST_BAD_RANGE", "1")
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
            } else {
                assert!(error.contains("Locked temporary resource removed"), "{error}");
                assert!(stages.is_empty(), "owned locked stage was not cleaned");
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
        let cancelled_upload = linscp_engine::transfer::upload_single_file(session.as_ref(), &local.join("large.bin"), "/cancelled.bin", &cancelling, &mut logger, Some(&cancel_on_progress)).await;
        assert!(cancelled_upload.is_err());
        assert!(!remote.join("cancelled.bin").exists());
        assert!(remote.join("cancelled.bin.filepart").exists());
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
    fn service_dispatches_status_roots_sessions_and_importers() {
        let tmp = std::env::temp_dir().join(format!("linscp-svc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let svc = CommanderService::new(tmp.clone(), Arc::new(NativeLocalFs::new()));
        let roots_reply = svc.dispatch(ApiEnvelope { method: "GET".to_string(), path: "/api/local/roots".to_string(), body: json!({}) });
        assert_eq!(roots_reply.status, 200);
        assert!(!roots_reply.payload["roots"].as_array().unwrap().is_empty());
        let save_reply = svc.dispatch(ApiEnvelope { method: "POST".to_string(), path: "/api/sessions/save".to_string(), body: serde_json::to_value(SessionConfig { name: "prod/web".to_string(), protocol: ProtocolScheme::Sftp, host: "10.0.0.8".to_string(), port: 22, username: "deploy".to_string(), password: Some("vault-secret".to_string()), keyfile: None, hostkey: "SHA256:xyz".to_string(), initial_dir: "/srv/www".to_string(), local_dir: String::new(), tunnel: None }).unwrap() });
        assert_eq!(save_reply.status, 200);
        assert!(tmp.join("sessions.key").exists());
        let list_reply = svc.dispatch(ApiEnvelope { method: "GET".to_string(), path: "/api/sessions".to_string(), body: json!({}) });
        assert_eq!(list_reply.status, 200);
        assert_eq!(list_reply.payload["sessions"][0]["name"], "prod/web");
        assert_eq!(list_reply.payload["sessions"][0]["has_password"], true);
        assert_eq!(list_reply.payload["folders"][0], "prod");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
