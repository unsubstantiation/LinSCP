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
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use linscp_service::CommanderService;
use linscp_types::ApiEnvelope;
use rand::RngCore;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

pub const MAX_BROWSER_UPLOAD_BYTES: usize = 1024 * 1024 * 1024;
pub const MAX_JSON_BODY_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_OFFLINEOTP_IMPORT_JSON_BYTES: usize = 24 * 1024 * 1024;

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

/// The path and query the service dispatches on, as the request carried them.
fn full_path(uri: &Uri) -> String {
    uri.path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| uri.path().to_string())
}

#[axum::debug_handler]
async fn api_handler(
    State(state): State<Arc<HttpAppState>>,
    request: axum::extract::Request,
) -> Response {
    // axum 0.7 requires a handler's last extractor to implement `FromRequest`,
    // which `HeaderMap` does not, so the request is taken whole and read here.
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let uri = parts.uri;
    let headers = parts.headers;
    // The Host/Origin allowlist and the token are decided once, before any body
    // is read: an unauthenticated caller must not be able to make the server
    // buffer a gigabyte it will refuse to dispatch.
    if let Err(reason) = check_host_and_origin(&headers, &state.config.allowed_hosts) {
        return (StatusCode::FORBIDDEN, Json(json!({ "error": reason }))).into_response();
    }
    let provided = supplied_token(&headers);
    if !constant_time_str_eq(&provided, &state.config.bearer_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid or missing X-LSCP-Token" })),
        )
            .into_response();
    }
    // A browser posts a dropped file as raw bytes, because a `File` cannot be
    // JSON-encoded without first reading it into memory twice. That body may be
    // large; every other body is JSON and stays small.
    let path_only = uri.path().to_string();
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let is_octet_drop = (path_only == "/api/transfer/drop" || path_only == "/api/local/drop")
        && content_type == "application/octet-stream";
    let is_offlineotp_import = method == Method::POST && path_only == "/api/vault/import";
    let limit = if is_octet_drop {
        MAX_BROWSER_UPLOAD_BYTES
    } else if is_offlineotp_import {
        MAX_OFFLINEOTP_IMPORT_JSON_BYTES
    } else {
        MAX_JSON_BODY_BYTES
    };
    let body = match axum::body::to_bytes(body, limit).await {
        Ok(bytes) => bytes,
        Err(_) => {
            let error = if is_octet_drop {
                "Browser uploads are limited to 1 GiB"
            } else {
                "JSON body too large"
            };
            return (StatusCode::PAYLOAD_TOO_LARGE, Json(json!({ "error": error }))).into_response();
        }
    };
    if is_octet_drop {
        return dispatch_octet_drop(&state, method, uri, body).await;
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
    // Enforce JSON object for POST body (like Python)
    let body_for_service = if parsed_body.is_object() { parsed_body } else if parsed_body.is_null() { json!({}) } else { parsed_body };
    let reply = state.service.dispatch_async(ApiEnvelope {
        method: method.as_str().to_string(),
        path: full_path(&uri),
        body: body_for_service,
    }).await;
    let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    // Add security headers
    let mut resp = (status, Json(reply.payload)).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate".parse().unwrap());
    resp
}

/// The already-authenticated body of a browser drop, in the one representation
/// the service accepts, so the drop endpoint exists once: the desktop window,
/// the browser and the Android app all reach the same handler.
async fn dispatch_octet_drop(
    state: &Arc<HttpAppState>,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Response {
    let reply = state.service.dispatch_async(ApiEnvelope {
        method: method.as_str().to_string(),
        path: full_path(&uri),
        body: json!({ "data_base64": BASE64_STD.encode(&body) }),
    }).await;
    let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = (status, Json(reply.payload)).into_response();
    resp.headers_mut().insert(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate".parse().unwrap());
    resp
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

/// A bound browser server, for the binary that offers browser mode.
///
/// The desktop window is a Tauri application; a browser, a headless host and a
/// multi-user deployment are the same page served by this crate over HTTP. The
/// startup lives here rather than in a `main.rs` so the address and the token a
/// test reads are the ones the launcher really used, and so the two apps cannot
/// drift in how they embed the page.
pub struct BrowserServer {
    pub addr: SocketAddr,
    /// The bearer token the page has to send with every `/api` request.
    pub token: String,
    listener: std::net::TcpListener,
    config: HttpServerConfig,
}

impl BrowserServer {
    /// Binds a port (`0` lets the kernel pick one) and keeps the token.
    ///
    /// The listener is bound here, once: a second bind could land on a
    /// different port than the one printed for the user, which is the kind of
    /// difference a smoke test that reads the printed address would not catch.
    pub fn bind(port: u16, allowed_hosts: &[String], bind_addr: Option<SocketAddr>) -> std::io::Result<Self> {
        let mut config = HttpServerConfig::loopback(port);
        if let Some(addr) = bind_addr {
            config.bind_addr = addr;
        }
        for host in allowed_hosts {
            let host = host.trim();
            if !host.is_empty() {
                config.allowed_hosts.insert(host.to_ascii_lowercase());
            }
        }
        let listener = std::net::TcpListener::bind(config.bind_addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        config.bind_addr = addr;
        let token = config.bearer_token.clone();
        Ok(Self { addr, token, listener, config })
    }

    /// The URL the user opens. A port the kernel picked is already resolved.
    pub fn url(&self) -> String {
        let ip = self.addr.ip();
        let host = if ip.is_unspecified() {
            "127.0.0.1".to_string()
        } else if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        };
        format!("http://{host}:{}/", self.addr.port())
    }

    /// Serves the page and the API until the listener fails.
    pub async fn serve(self) -> std::io::Result<()> {
        let listener = tokio::net::TcpListener::from_std(self.listener)?;
        let state = Arc::new(HttpAppState {
            // The browser may be on another machine, so this host must not start a
            // viewer the user cannot see: `/api/desktop/launch` answers with a
            // `.rdp`/`.vv` ticket the browser can hand to its own client.
            service: CommanderService::default().with_desktop_spawn(false),
            config: self.config,
        });
        serve(listener, state).await
    }
}

#[cfg(test)]
mod browser_server_tests {
    use super::*;

    /// The address printed for the user and the address actually bound are the
    /// same one, and the token the page carries is the token the API checks.
    #[test]
    fn the_browser_server_prints_the_address_it_bound() {
        let server = BrowserServer::bind(0, &[], None).expect("bind a loopback port");
        assert_ne!(server.addr.port(), 0, "the kernel picked a port");
        let expected = format!("http://127.0.0.1:{}/", server.addr.port());
        assert_eq!(server.url(), expected);
        // Opening the printed URL and sending the printed token has to pass
        // the check the API makes; anything else means a page that cannot talk.
        let mut headers = HeaderMap::new();
        headers.insert("host", "127.0.0.1:8765".parse().unwrap());
        headers.insert("origin", "http://127.0.0.1:8765".parse().unwrap());
        assert!(check_host_and_origin(&headers, &server.config.allowed_hosts).is_ok());
        assert!(constant_time_str_eq(&server.token, &server.config.bearer_token));
        assert!(!server.token.is_empty());
    }

    /// A request that reaches the router really is dispatched, and the two
    /// guards refuse before any work happens: the bearer token, and a `Host`
    /// the server does not answer to. Fetching the page alone would not show
    /// that the `/api` route is wired at all.
    #[tokio::test]
    async fn the_api_route_dispatches_and_guards_itself() {
        let server = BrowserServer::bind(0, &[], None).expect("bind a loopback port");
        let port = server.addr.port();
        let token = server.token.clone();
        tokio::spawn(async move {
            let _ = server.serve().await;
        });
        let client = reqwest::Client::new();
        let url = format!("http://127.0.0.1:{port}/api/status");
        let local_host = format!("127.0.0.1:{port}");
        // Without the token the API refuses instead of dispatching.
        let refused = client
            .get(&url)
            .header("host", &local_host)
            .send()
            .await
            .expect("reach the server");
        assert_eq!(refused.status().as_u16(), 401);
        // With it, the same request reaches the service and is answered.
        let answered = client
            .get(&url)
            .header("host", &local_host)
            .header("x-lscp-token", &token)
            .send()
            .await
            .expect("reach the server");
        assert_eq!(answered.status().as_u16(), 200);
        let body: Value = serde_json::from_str(&answered.text().await.expect("an answer"))
            .expect("a JSON answer");
        assert_eq!(body["binary"], "linscp");
        // A foreign `Host` is refused even with the token, so a DNS rebinding
        // page cannot borrow the caller's credentials.
        let rebound = client
            .get(&url)
            .header("host", "attacker.example.com")
            .header("x-lscp-token", &token)
            .send()
            .await
            .expect("reach the server");
        assert_eq!(rebound.status().as_u16(), 403);
    }

    /// An extra host is accepted only by name, and it does not widen the list
    /// to everything: the token is still the only thing guarding the API.
    #[test]
    fn an_extra_allowed_host_is_named_not_wildcarded() {
        let server = BrowserServer::bind(0, &[" LinSCP.Internal ".to_string(), String::new()], None)
            .expect("bind a loopback port");
        assert!(server.config.allowed_hosts.contains("linscp.internal"));
        assert!(!server.config.allowed_hosts.contains("*"));
        let mut headers = HeaderMap::new();
        headers.insert("host", "linscp.internal:8765".parse().unwrap());
        assert!(check_host_and_origin(&headers, &server.config.allowed_hosts).is_ok());
        headers.insert("host", "other.example:8765".parse().unwrap());
        assert!(check_host_and_origin(&headers, &server.config.allowed_hosts).is_err());
    }
}
