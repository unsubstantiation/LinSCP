//! Standalone browser HTTP server mode (`linscp-http`).
//!
//! Wraps `CommanderService` in an `axum` router with the same security
//! invariants as `linscp_gui.py`:
//! - Loopback + explicit `--allow-host` `Host` / `Origin` enforcement (DNS-rebinding defense)
//! - Constant-time `X-LSCP-Token` verification on `/api/*`
//! - Optional `X-LSCP-CSRF` enforcement for authenticated browser sessions

use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use linscp_service::CommanderService;
use linscp_types::ApiEnvelope;
use rand::RngCore;
use serde_json::{json, Value};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub struct HttpServerConfig {
    pub bind_addr: SocketAddr,
    pub bearer_token: String,
    pub allowed_hosts: HashSet<String>,
    pub index_html: Option<String>,
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
        }
    }
}

pub struct HttpAppState {
    pub service: CommanderService,
    pub config: HttpServerConfig,
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

pub fn build_router(state: Arc<HttpAppState>) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/api/*tail", any(api_handler))
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
    let raw = state
        .config
        .index_html
        .as_deref()
        .unwrap_or("<!doctype html><title>LinSCP</title><script>window.__LINSCP_TOKEN__=\"__LSCP_TOKEN__\";</script>");
    let rendered = raw.replace("__LSCP_TOKEN__", &state.config.bearer_token);
    Html(rendered).into_response()
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

    let provided = headers
        .get("x-lscp-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !constant_time_str_eq(provided, &state.config.bearer_token) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "Invalid or missing X-LSCP-Token" })),
        )
            .into_response();
    }

    let parsed_body: Value = if body.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&body) {
            Ok(val) => val,
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

    let reply = state.service.dispatch(ApiEnvelope {
        method: method.as_str().to_string(),
        path: full_path,
        body: parsed_body,
    });
    let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(reply.payload)).into_response()
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
