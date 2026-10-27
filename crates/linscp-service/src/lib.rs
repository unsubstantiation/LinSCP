//! Transport-neutral Commander backend service (`CommanderService`).
//!
//! Both `linscp-http` (axum browser server) and `linscp-tauri` (native Linux,
//! Windows, and Android shell) route every UI command through
//! `CommanderService::dispatch`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use linscp_engine::{parse_ini_sections, serialize_ini_sections};
use linscp_platform::{config_dir, write_private_file_atomic, LocalFs, NativeLocalFs};
use linscp_types::{
    ApiEnvelope, ApiReply, TabSummary, TransferQueueItem, UserPreferences,
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
    state: Arc<Mutex<InnerState>>,
}

impl Default for CommanderService {
    fn default() -> Self {
        Self::new(config_dir(), Arc::new(NativeLocalFs::new()))
    }
}

impl CommanderService {
    pub fn new(config_root: PathBuf, local_fs: Arc<dyn LocalFs>) -> Self {
        let preferences = load_json_or_default(&config_root.join("preferences.json"));
        let bookmarks = load_json_value(&config_root.join("bookmarks.json"), json!({}));
        let workspaces = load_json_value(&config_root.join("workspaces.json"), json!({}));
        Self {
            local_fs,
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
        let target = guard.config_root.join("preferences.json");
        let serialized = serde_json::to_vec_pretty(&parsed).unwrap_or_default();
        if let Err(err) = write_private_file_atomic(&target, &serialized) {
            return ApiReply {
                status: 500,
                payload: json!({ "error": err.to_string() }),
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
        let ini_path = guard.config_root.join("sessions.ini");
        let content = std::fs::read_to_string(&ini_path).unwrap_or_default();
        let parsed = parse_ini_sections(&content);
        let sessions: Vec<Value> = parsed
            .into_iter()
            .map(|(name, fields)| {
                json!({
                    "name": name,
                    "protocol": fields.get("protocol").cloned().unwrap_or_else(|| "sftp".to_string()),
                    "host": fields.get("host").cloned().unwrap_or_default(),
                    "port": fields.get("port").and_then(|p| p.parse::<u16>().ok()).unwrap_or(22),
                    "username": fields.get("username").cloned().unwrap_or_default(),
                    "has_password": fields.get("password").map(|p| !p.is_empty()).unwrap_or(false),
                })
            })
            .collect();
        let _ = serialize_ini_sections;
        ApiReply {
            status: 200,
            payload: json!({ "sessions": sessions }),
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

fn load_json_or_default<T>(path: &PathBuf) -> T
where
    T: serde::de::DeserializeOwned + Default,
{
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

fn load_json_value(path: &PathBuf, fallback: Value) -> Value {
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

    #[test]
    fn service_dispatches_status_roots_and_local_tab() {
        let tmp = std::env::temp_dir().join(format!("linscp-svc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let svc = CommanderService::new(tmp.clone(), Arc::new(NativeLocalFs::new()));

        let roots_reply = svc.dispatch(ApiEnvelope {
            method: "GET".to_string(),
            path: "/api/local/roots".to_string(),
            body: json!({}),
        });
        assert_eq!(roots_reply.status, 200);
        assert!(roots_reply.payload["roots"].as_array().unwrap().len() >= 1);

        let open_reply = svc.dispatch(ApiEnvelope {
            method: "POST".to_string(),
            path: "/api/tabs/local".to_string(),
            body: json!({}),
        });
        assert_eq!(open_reply.status, 200);
        assert_eq!(open_reply.payload["tab"]["name"], "local");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
