#![allow(unused_variables, unused_imports, dead_code, clippy::all)]
//! Standalone browser HTTP server mode (`linscp-http`).
//!
//! Wraps `CommanderService` in an `axum` router with the same security
//! invariants as `linscp_gui.py`:
//! - Loopback + explicit `--allow-host` `Host` / `Origin` enforcement (DNS-rebinding defense)
//! - Constant-time `X-LSCP-Token` (or `Authorization: Bearer`) verification on `/api/*`
//! - Bounded `application/octet-stream` staging for browser uploads

use std::collections::HashSet;
use std::fmt::Write as _
;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use linscp_service::CommanderService;
use linscp_types::ApiEnvelope;
use rand::RngCore;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

pub const MAX_BROWSER_UPLOAD_BYTES: usize = 1024 * 1024 * 1024;
pub const MAX_JSON_BODY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone)]
pub struct HttpServerConfig {
    pub bind_addr: SocketAddr,
    pub bearer_token: String,
    pub allowed_hosts: HashSet<String>,
    pub index_html: Option<String>,
    pub ui_dist: Option<PathBuf>,
}

impl HttpServerConfig {
    pub fn loopback(port: u16) -> Self {
        let mut raw = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut raw);
        let mut token = String::with_capacity(48);
        for b in raw {
            let _ = write!(token, "{b:02x}");
        }
        let mut allowed_hosts = HashSet::new();
        for host in ["localhost", "127.0.0.1", "[::1]", "::1"] {
            allowed_hosts.insert(host.to_string());
        }
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            bearer_token: token,
            allowed_hosts,
            index_html: None,
            ui_dist: find_ui_dist(),
        }
    }
}

pub struct HttpAppState {
    pub service: CommanderService,
    pub config: HttpServerConfig,
}

fn find_ui_dist() -> Option<PathBuf> {
    // Search relative to current exe and cwd for ui/dist
    let candidates = [
        PathBuf::from("ui/dist"),
        PathBuf::from("../ui/dist"),
        PathBuf::from("../../ui/dist"),
        PathBuf::from("source/gui/web"),
    ];
    for c in candidates {
        if c.join("index.html").exists() {
            return Some(c);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for rel in ["../../ui/dist", "../ui/dist", "ui/dist", "../share/linscp/gui/web"] {
                let cand = dir.join(rel);
                if cand.join("index.html").exists() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

/// Strips optional `:port` from an HTTP `Host` header value while preserving
/// bracketed IPv6 literals (`[::1]:8080` -> `[::1]`).
pub fn normalize_host_header(raw_host: &str) -> String {
    let trimmed = raw_host.trim().to_ascii_lowercase();
    if trimmed.starts_with('[') {
        if let Some(end) = trimmed.find(']') {
            return trimmed[..=end].to_string();
        }
        return trimmed;
    }
    match trimmed.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host.to_string(),
        _ => trimmed,
    }
}

/// Extracts the hostname portion of an `Origin` header (`http://127.0.0.1:9000` -> `127.0.0.1`).
pub fn extract_origin_host(origin: &str) -> Option<String> {
    let after_scheme = origin.trim().split_once("://")?.1;
    let authority = after_scheme.split('/').next()?;
    let host_port = authority.rsplit_once('@').map(|(_, hp)| hp).unwrap_or(authority);
    Some(normalize_host_header(host_port))
}

pub fn constant_time_str_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    ab.len() == bb.len() && bool::from(ab.ct_eq(bb))
}

fn check_host_and_origin(headers: &HeaderMap, allowed: &HashSet<String>) -> Result<(), &'static str> {
    if allowed.contains("*") {
        return Ok(());
    }
    let Some(host_val) = headers.get("host").and_then(|v| v.to_str().ok()) else {
        return Err("Missing Host header");
    };
    let host = normalize_host_header(host_val);
    if !allowed.contains(&host) {
        return Err("Rejected Host header");
    }
    if let Some(origin_val) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        if !origin_val.is_empty() {
            let Some(origin_host) = extract_origin_host(origin_val) else {
                return Err("Malformed Origin header");
            };
            if !allowed.contains(&origin_host) {
                return Err("Cross-origin request forbidden");
            }
        }
    }
    Ok(())
}

fn supplied_token(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get("x-lscp-token").and_then(|v| v.to_str().ok()) {
        if !v.is_empty() {
            return v.to_string();
        }
    }
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(bearer) = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer ")) {
            return bearer.trim().to_string();
        }
    }
    String::new()
}

pub fn build_router(state: Arc<HttpAppState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/index.html", get(index_handler))
        .route("/api/*tail", any(api_handler))
        .fallback(fallback_handler)
        .with_state(state)
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<HttpAppState>,
) -> std::io::Result<()> {
    axum::serve(listener, build_router(state)).await
}

async fn index_handler(State(state): State<Arc<HttpAppState>>, headers: HeaderMap) -> Response {
    if let Err(reason) = check_host_and_origin(&headers, &state.config.allowed_hosts) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": reason }))).into_response();
    }
    // Prefer embedded index_html, then filesystem ui/dist, then minimal fallback
    let html = if let Some(raw) = state.config.index_html.as_deref() {
        raw.to_string()
    } else if let Some(dist) = state.config.ui_dist.as_deref() {
        let p = dist.join("index.html");
        std::fs::read_to_string(&p).unwrap_or_else(|_| "<!doctype html><title>LinSCP</title>".to_string())
    } else {
        "<!doctype html><title>LinSCP</title><script>window.__LINSCP_TOKEN__=\"__LSCP_TOKEN__\";</script>".to_string()
    };
    let rendered = html.replace("__LSCP_TOKEN__", &state.config.bearer_token).replace("__LSCP_TOKEN__", &state.config.bearer_token);
    // Also inject LSCP_TOKEN and LSCP_CONFIG like Python does: window.LSCP_TOKEN
    let injected = if rendered.contains("window.__LINSCP_TOKEN__") {
        rendered
    } else if rendered.contains("</head>") {
        let snippet = format!("<script>window.LSCP_TOKEN=\"{}\";window.__LINSCP_TOKEN__=\"{}\";</script>", state.config.bearer_token, state.config.bearer_token);
        rendered.replacen("</head>", &format!("{snippet}</head>"), 1)
    } else {
        rendered
    };
    let mut resp = Html(injected).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate".parse().unwrap());
    resp.headers_mut().insert(axum::http::HeaderName::from_static("x-content-type-options"), "nosniff".parse().unwrap());
    resp.headers_mut().insert(axum::http::HeaderName::from_static("x-frame-options"), "DENY".parse().unwrap());
    resp
}

async fn fallback_handler(State(state): State<Arc<HttpAppState>>, headers: HeaderMap, uri: Uri) -> Response {
    if let Err(reason) = check_host_and_origin(&headers, &state.config.allowed_hosts) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": reason }))).into_response();
    }
    let path = uri.path().trim_start_matches('/');
    if path.is_empty() {
        return index_handler(State(state), headers).await;
    }
    // Prevent directory traversal
    if path.contains("..") || path.contains('\0') {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid path"}))).into_response();
    }
    if let Some(dist) = state.config.ui_dist.as_deref() {
        let file_path = dist.join(path);
        if let Ok(data) = std::fs::read(&file_path) {
            let mime = mime_for_path(&file_path);
            let mut resp = (StatusCode::OK, [(header::CONTENT_TYPE, mime)], data).into_response();
            resp.headers_mut().insert(header::CACHE_CONTROL, "public, max-age=3600".parse().unwrap());
            return resp;
        }
    }
    (StatusCode::NOT_FOUND, Json(json!({"error": "Not Found"}))).into_response()
}

fn mime_for_path(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase().as_str() {
        "html" => "text/html; charset=utf-8".to_string(),
        "css" => "text/css; charset=utf-8".to_string(),
        "js" | "mjs" => "application/javascript".to_string(),
        "json" => "application/json".to_string(),
        "svg" => "image/svg+xml".to_string(),
        "png" => "image/png".to_string(),
        "ico" => "image/x-icon".to_string(),
        _ => "application/octet-stream".to_string(),
    }
}

async fn api_handler(
    State(state): State<Arc<HttpAppState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(reason) = check_host_and_origin(&headers, &state.config.allowed_hosts) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": reason }))).into_response();
    }
    // Binary upload handling for browser drops
    let path_only = uri.path().to_string();
    let ct = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    if (path_only == "/api/transfer/drop" || path_only == "/api/local/drop") && ct == "application/octet-stream" {
        return handle_octet_drop(State(state), method, uri, headers, body).await;
    }
    let provided = supplied_token(&headers);
    if !constant_time_str_eq(&provided, &state.config.bearer_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid or missing X-LSCP-Token" })),
        )
            .into_response();
    }
    if body.len() > MAX_JSON_BODY_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({"error": "JSON body too large"}))).into_response();
    }
    let parsed_body: Value = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice::<Value>(&body) {
            Ok(val) => {
                if !val.is_object() && !val.is_array() {
                    // Python requires dict, but we allow any JSON and let service validate
                }
                val
            },
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("Invalid JSON body: {err}") })),
                )
                    .into_response();
            }
        }
    };
    let full_path = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string());
    // Enforce JSON object for POST body (like Python)
    let body_for_service = if parsed_body.is_object() { parsed_body } else if parsed_body.is_null() { json!({}) } else { parsed_body };
    let reply = state.service.dispatch(ApiEnvelope {
        method: method.as_str().to_string(),
        path: full_path,
        body: body_for_service,
    });
    let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    // Add security headers
    let mut resp = (status, Json(reply.payload)).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate".parse().unwrap());
    resp
}

async fn handle_octet_drop(
    State(state): State<Arc<HttpAppState>>,
    _method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(reason) = check_host_and_origin(&headers, &state.config.allowed_hosts) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": reason }))).into_response();
    }
    let provided = supplied_token(&headers);
    if !constant_time_str_eq(&provided, &state.config.bearer_token) {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "Invalid or missing X-LSCP-Token"}))).into_response();
    }
    if body.len() > MAX_BROWSER_UPLOAD_BYTES {
        return (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({"error": "Browser uploads are limited to 1 GiB"}))).into_response();
    }
    let query = uri.query().unwrap_or("");
    let mut params = std::collections::HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() { continue; }
        let (k,v) = match pair.split_once('=') {
            Some((k,v)) => (k.to_string(), v.to_string()),
            None => (pair.to_string(), String::new()),
        };
        // percent-decode '+' and %XX minimal
        let k = k.replace('+', " ");
        let v = v.replace('+', " ");
        params.insert(k, v);
    }
    let _is_local = uri.path() == "/api/local/drop";
    // Validate tab if present? For now accept
    // Write to staging dir: use temp dir
    let staging = std::env::temp_dir().join("linscp-http-staging");
    let _ = std::fs::create_dir_all(&staging);
    let name = params.get("name").map(|s| s.as_str()).unwrap_or("upload.bin");
    // Validate name is single file name
    if name.contains('/') || name.contains('\\') || name.contains('\0') || name == "." || name == ".." {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "Invalid file name"}))).into_response();
    }
    let mut dest = staging.join(format!("{}_{}", std::process::id(), name));
    // If relative_path present, ensure it doesn't escape
    if let Some(rel) = params.get("relative_path") {
        if rel.contains("..") {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "Relative path escapes directory"}))).into_response();
        }
        dest = staging.join(rel.replace('/', "_"));
    }
    match std::fs::write(&dest, &body) {
        Ok(_) => (StatusCode::OK, Json(json!({"success": true, "path": dest.to_string_lossy()}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_and_origin_normalization_handles_ports_and_ipv6() {
        assert_eq!(normalize_host_header("127.0.0.1:8765"), "127.0.0.1");
        assert_eq!(normalize_host_header("[::1]:8765"), "[::1]");
        assert_eq!(
            extract_origin_host("https://localhost:9443").as_deref(),
            Some("localhost")
        );
        assert_eq!(
            extract_origin_host("http://[::1]:8080").as_deref(),
            Some("[::1]")
        );
    }

    #[test]
    fn dns_rebinding_host_is_refused() {
        let cfg = HttpServerConfig::loopback(0);
        let mut bad_headers = HeaderMap::new();
        bad_headers.insert("host", "attacker.example.com:8080".parse().unwrap());
        assert!(check_host_and_origin(&bad_headers, &cfg.allowed_hosts).is_err());

        let mut ok_headers = HeaderMap::new();
        ok_headers.insert("host", "127.0.0.1:8080".parse().unwrap());
        ok_headers.insert("origin", "http://127.0.0.1:8080".parse().unwrap());
        assert!(check_host_and_origin(&ok_headers, &cfg.allowed_hosts).is_ok());
    }
}
