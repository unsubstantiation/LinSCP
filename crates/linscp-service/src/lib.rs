//! Transport-neutral Commander backend service (`CommanderService`).
//!
//! Both `linscp-http` (axum browser server) and `linscp-tauri` (native Linux,
//! Windows, and Android shell) route every UI command through
//! `CommanderService::dispatch`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use linscp_engine::{
    parse_filezilla_xml, parse_openssh_config, PreferencesStore, SessionStore, StoredSite,
};
use linscp_platform::{
    config_dir, write_private_file_atomic, LocalFs, NativeLocalFs, NativeSecretVault, SecretVault,
};
use linscp_types::{
    ApiEnvelope, ApiReply, SessionConfig, TabSummary, TransferQueueItem, UserPreferences,
};
use serde_json::{json, Value};

struct InnerState {
    config_root: PathBuf,
    next_tab_id: u64,
    active_tab_id: Option<u64>,
    tabs: Vec<TabSummary>,
    transfers: Vec<TransferQueueItem>,
    preferences: UserPreferences,
    bookmarks: Value,
    workspaces: Value,
}

#[derive(Clone)]
pub struct CommanderService {
    local_fs: Arc<dyn LocalFs>,
    secret_vault: Arc<dyn SecretVault>,
    state: Arc<Mutex<InnerState>>,
}

impl Default for CommanderService {
    fn default() -> Self {
        Self::new(config_dir(), Arc::new(NativeLocalFs::new()))
    }
}

impl CommanderService {
    pub fn new(config_root: PathBuf, local_fs: Arc<dyn LocalFs>) -> Self {
        Self::with_secret_vault(config_root, local_fs, Arc::new(NativeSecretVault::new()))
    }

    pub fn with_secret_vault(
        config_root: PathBuf,
        local_fs: Arc<dyn LocalFs>,
        secret_vault: Arc<dyn SecretVault>,
    ) -> Self {
        let preferences = PreferencesStore::load(&config_root).unwrap_or_default();
        let bookmarks = load_json_value(&config_root.join("bookmarks.json"), json!({}));
        let workspaces = load_json_value(&config_root.join("workspaces.json"), json!({}));
        Self {
            local_fs,
            secret_vault,
            state: Arc::new(Mutex::new(InnerState {
                config_root,
                next_tab_id: 1,
                active_tab_id: None,
                tabs: Vec::new(),
                transfers: Vec::new(),
                preferences,
                bookmarks,
                workspaces,
            })),
        }
    }

    /// Dispatches an API call regardless of whether it arrived over HTTP
    /// (`linscp-http`) or Tauri IPC (`linscp-tauri`).
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
            ("GET", "/api/preferences") => self.handle_get_preferences(),
            ("POST", "/api/preferences") => self.handle_save_preferences(req.body),
            ("GET", "/api/sessions") => self.handle_list_sessions(),
            ("POST", "/api/sessions/save") => self.handle_save_session(req.body),
            ("POST", "/api/sessions/delete") => self.handle_delete_session(req.body),
            ("POST", "/api/import/openssh") => self.handle_import_openssh(req.body),
            ("POST", "/api/import/filezilla") => self.handle_import_filezilla(req.body),
            ("GET", "/api/bookmarks") => self.handle_get_bookmarks(),
            ("POST", "/api/bookmarks") => self.handle_save_bookmarks(req.body),
            ("GET", "/api/workspaces") => self.handle_get_workspaces(),
            ("POST", "/api/workspaces") => self.handle_save_workspaces(req.body),
            ("GET", "/api/transfers") => self.handle_list_transfers(),
            ("POST", "/api/tabs/local") => self.handle_open_local_tab(req.body),
            _ => ApiReply {
                status: 404,
                payload: json!({ "error": format!("Unknown endpoint: {} {}", method, raw_path) }),
            },
        }
    }

    fn default_local_dir(&self) -> String {
        if let Ok(roots) = self.local_fs.list_roots() {
            if let Some(preferred) = roots.iter().find(|r| r.label.starts_with("Home")) {
                return preferred.path.clone();
            }
            if let Some(first) = roots.first() {
                return first.path.clone();
            }
        }
        "/".to_string()
    }

    fn handle_status(&self) -> ApiReply {
        let guard = self.state.lock().expect("state mutex");
        let roots = self.local_fs.list_roots().unwrap_or_default();
        ApiReply {
            status: 200,
            payload: json!({
                "connected": guard.active_tab_id.is_some(),
                "active_tab": guard.active_tab_id,
                "tabs": guard.tabs,
                "local_dir": self.default_local_dir(),
                "local_roots": roots,
                "preferences": guard.preferences,
            }),
        }
    }

    fn handle_local_roots(&self) -> ApiReply {
        match self.local_fs.list_roots() {
            Ok(roots) => ApiReply {
                status: 200,
                payload: json!({ "roots": roots }),
            },
            Err(err) => ApiReply {
                status: 500,
                payload: json!({ "error": err.to_string() }),
            },
        }
    }

    fn handle_local_list(&self, query: &BTreeMap<String, String>) -> ApiReply {
        let requested = query
            .get("path")
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.default_local_dir());
        match self.local_fs.list_dir(&requested) {
            Ok(entries) => ApiReply {
                status: 200,
                payload: json!({
                    "path": requested,
                    "entries": entries,
                }),
            },
            Err(err) => ApiReply {
                status: 400,
                payload: json!({ "error": err.to_string(), "path": requested }),
            },
        }
    }

    fn handle_get_preferences(&self) -> ApiReply {
        let guard = self.state.lock().expect("state mutex");
        ApiReply {
            status: 200,
            payload: serde_json::to_value(&guard.preferences).unwrap_or_else(|_| json!({})),
        }
    }

    fn handle_save_preferences(&self, body: Value) -> ApiReply {
        let parsed: UserPreferences = match serde_json::from_value(body) {
            Ok(prefs) => prefs,
            Err(err) => {
                return ApiReply {
                    status: 400,
                    payload: json!({ "error": format!("Invalid preferences: {err}") }),
                };
            }
        };
        let mut guard = self.state.lock().expect("state mutex");
        if let Err(err) = PreferencesStore::save(&guard.config_root, &parsed) {
            return ApiReply {
                status: 500,
                payload: json!({ "error": err }),
            };
        }
        guard.preferences = parsed;
        ApiReply {
            status: 200,
            payload: serde_json::to_value(&guard.preferences).unwrap_or_else(|_| json!({})),
        }
    }

    fn handle_list_sessions(&self) -> ApiReply {
        let guard = self.state.lock().expect("state mutex");
        match SessionStore::load_from_dir(&guard.config_root, self.secret_vault.as_ref()) {
            Ok(store) => {
                let summaries: Vec<_> = store.sites().iter().map(StoredSite::summary).collect();
                ApiReply {
                    status: 200,
                    payload: json!({
                        "sessions": summaries,
                        "folders": store.folders(),
                    }),
                }
            }
            Err(err) => ApiReply {
                status: 500,
                payload: json!({ "error": err }),
            },
        }
    }

    fn handle_save_session(&self, body: Value) -> ApiReply {
        let cfg: SessionConfig = match serde_json::from_value(body) {
            Ok(s) => s,
            Err(err) => {
                return ApiReply {
                    status: 400,
                    payload: json!({ "error": format!("Invalid session payload: {err}") }),
                };
            }
        };
        if cfg.name.trim().is_empty() {
            return ApiReply {
                status: 400,
                payload: json!({ "error": "Session name is required" }),
            };
        }
        let guard = self.state.lock().expect("state mutex");
        let mut store =
            match SessionStore::load_from_dir(&guard.config_root, self.secret_vault.as_ref()) {
                Ok(s) => s,
                Err(err) => {
                    return ApiReply {
                        status: 500,
                        payload: json!({ "error": err }),
                    };
                }
            };
        let site = StoredSite::from_session_config(&cfg);
        let summary = site.summary();
        store.upsert(site);
        if let Err(err) = store.save_to_dir(&guard.config_root, self.secret_vault.as_ref()) {
            return ApiReply {
                status: 500,
                payload: json!({ "error": err }),
            };
        }
        ApiReply {
            status: 200,
            payload: json!({ "ok": true, "session": summary }),
        }
    }

    fn handle_delete_session(&self, body: Value) -> ApiReply {
        let name = body
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim();
        if name.is_empty() {
            return ApiReply {
                status: 400,
                payload: json!({ "error": "Session name is required" }),
            };
        }
        let guard = self.state.lock().expect("state mutex");
        let mut store =
            match SessionStore::load_from_dir(&guard.config_root, self.secret_vault.as_ref()) {
                Ok(s) => s,
                Err(err) => {
                    return ApiReply {
                        status: 500,
                        payload: json!({ "error": err }),
                    };
                }
            };
        let removed = store.remove(name);
        if removed {
            if let Err(err) = store.save_to_dir(&guard.config_root, self.secret_vault.as_ref()) {
                return ApiReply {
                    status: 500,
                    payload: json!({ "error": err }),
                };
            }
        }
        ApiReply {
            status: 200,
            payload: json!({ "ok": true, "removed": removed }),
        }
    }

    fn handle_import_openssh(&self, body: Value) -> ApiReply {
        let text = body.get("content").and_then(Value::as_str).unwrap_or("");
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let report = parse_openssh_config(text, home.as_deref());
        ApiReply {
            status: 200,
            payload: serde_json::to_value(report).unwrap_or_else(|_| json!({})),
        }
    }

    fn handle_import_filezilla(&self, body: Value) -> ApiReply {
        let text = body.get("content").and_then(Value::as_str).unwrap_or("");
        match parse_filezilla_xml(text) {
            Ok(report) => ApiReply {
                status: 200,
                payload: serde_json::to_value(report).unwrap_or_else(|_| json!({})),
            },
            Err(err) => ApiReply {
                status: 400,
                payload: json!({ "error": err }),
            },
        }
    }

    fn handle_get_bookmarks(&self) -> ApiReply {
        let guard = self.state.lock().expect("state mutex");
        ApiReply {
            status: 200,
            payload: json!({ "bookmarks": guard.bookmarks }),
        }
    }

    fn handle_save_bookmarks(&self, body: Value) -> ApiReply {
        let mut guard = self.state.lock().expect("state mutex");
        let next = body.get("bookmarks").cloned().unwrap_or(body);
        let target = guard.config_root.join("bookmarks.json");
        let bytes = serde_json::to_vec_pretty(&next).unwrap_or_default();
        if let Err(err) = write_private_file_atomic(&target, &bytes) {
            return ApiReply {
                status: 500,
                payload: json!({ "error": err.to_string() }),
            };
        }
        guard.bookmarks = next.clone();
        ApiReply {
            status: 200,
            payload: json!({ "bookmarks": next }),
        }
    }

    fn handle_get_workspaces(&self) -> ApiReply {
        let guard = self.state.lock().expect("state mutex");
        ApiReply {
            status: 200,
            payload: json!({ "workspaces": guard.workspaces }),
        }
    }

    fn handle_save_workspaces(&self, body: Value) -> ApiReply {
        let mut guard = self.state.lock().expect("state mutex");
        let next = body.get("workspaces").cloned().unwrap_or(body);
        let target = guard.config_root.join("workspaces.json");
        let bytes = serde_json::to_vec_pretty(&next).unwrap_or_default();
        if let Err(err) = write_private_file_atomic(&target, &bytes) {
            return ApiReply {
                status: 500,
                payload: json!({ "error": err.to_string() }),
            };
        }
        guard.workspaces = next.clone();
        ApiReply {
            status: 200,
            payload: json!({ "workspaces": next }),
        }
    }

    fn handle_list_transfers(&self) -> ApiReply {
        let guard = self.state.lock().expect("state mutex");
        ApiReply {
            status: 200,
            payload: json!({ "transfers": guard.transfers }),
        }
    }

    fn handle_open_local_tab(&self, body: Value) -> ApiReply {
        let default_dir = self.default_local_dir();
        let left = body
            .get("local_dir")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(&default_dir)
            .to_string();
        let right = body
            .get("remote_dir")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(&default_dir)
            .to_string();
        let mut guard = self.state.lock().expect("state mutex");
        let id = guard.next_tab_id;
        guard.next_tab_id += 1;
        let summary = TabSummary {
            id,
            name: "local".to_string(),
            connected: true,
            local_dir: left,
            remote_dir: right,
            session: None,
            observed_hostkey: String::new(),
            error: String::new(),
        };
        guard.tabs.push(summary.clone());
        guard.active_tab_id = Some(id);
        ApiReply {
            status: 200,
            payload: json!({ "tab": summary, "active_tab": id }),
        }
    }
}

fn load_json_value(path: &Path, fallback: Value) -> Value {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or(fallback)
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        };
        map.insert(k, v);
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use linscp_types::ProtocolScheme;

    #[test]
    fn service_dispatches_status_roots_sessions_and_importers() {
        let tmp = std::env::temp_dir().join(format!("linscp-svc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let svc = CommanderService::new(tmp.clone(), Arc::new(NativeLocalFs::new()));

        let roots_reply = svc.dispatch(ApiEnvelope {
            method: "GET".to_string(),
            path: "/api/local/roots".to_string(),
            body: json!({}),
        });
        assert_eq!(roots_reply.status, 200);
        assert!(!roots_reply.payload["roots"].as_array().unwrap().is_empty());

        let save_reply = svc.dispatch(ApiEnvelope {
            method: "POST".to_string(),
            path: "/api/sessions/save".to_string(),
            body: serde_json::to_value(SessionConfig {
                name: "prod/web".to_string(),
                protocol: ProtocolScheme::Sftp,
                host: "10.0.0.8".to_string(),
                port: 22,
                username: "deploy".to_string(),
                password: Some("vault-secret".to_string()),
                keyfile: None,
                hostkey: "SHA256:xyz".to_string(),
                initial_dir: "/srv/www".to_string(),
                local_dir: String::new(),
                tunnel: None,
            })
            .unwrap(),
        });
        assert_eq!(save_reply.status, 200);
        assert!(tmp.join("sessions.key").exists());

        let list_reply = svc.dispatch(ApiEnvelope {
            method: "GET".to_string(),
            path: "/api/sessions".to_string(),
            body: json!({}),
        });
        assert_eq!(list_reply.status, 200);
        assert_eq!(list_reply.payload["sessions"][0]["name"], "prod/web");
        assert_eq!(list_reply.payload["sessions"][0]["has_password"], true);
        assert_eq!(list_reply.payload["folders"][0], "prod");

        let ssh_import = svc.dispatch(ApiEnvelope {
            method: "POST".to_string(),
            path: "/api/import/openssh".to_string(),
            body: json!({ "content": "Host bastion\n  HostName 192.0.2.10\n  User ops\n" }),
        });
        assert_eq!(ssh_import.status, 200);
        assert_eq!(ssh_import.payload["imported"][0]["name"], "bastion");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
