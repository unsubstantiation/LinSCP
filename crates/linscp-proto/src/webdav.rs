//! Pure-Rust WebDAV / HTTP(S) client (`WebDavSession` implementing
//! `RemoteSession`) built on `reqwest`, custom `rustls::ClientConfig` (`tls.rs`),
//! and XXE-safe `roxmltree` multistatus/property parsing, porting all WebDAV
//! operations and extensions (`LOCK`/`UNLOCK`, `PROPPATCH`/`PROPFIND`, RFC 4918
//! `If` ETag/lock-token preconditions) from `ProtocolClient.{h,cpp}`.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_core::Stream;
use linscp_crypto::digests::{DigestAlgorithm, DigestHasher};
use linscp_types::{FileEntry, ProtocolScheme};
use reqwest::{Body, Client, Method, Proxy};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use zeroize::Zeroizing;

use crate::listing::{format_utc_timestamp, utc_ymdhms_to_unix};
use crate::proxy::{ProxyConfig, ProxyKind};
use crate::sftp::HasherAsyncSink;
use crate::ssh::SshConnectConfig;
use crate::tls::{build_rustls_client_config, TlsSettings};
use crate::tunnel::{Socks5JumpRelay, SshJumpTunnel};
use crate::{ProgressCallback, ProtoError, RateLimiter, RemoteSession, TransferRequest};

pub const DAV_PROPERTY_NAMESPACE: &str = "urn:linscp:properties";
pub const DAV_PROPERTY_PREFIX: &str = "L";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DavEtagPrecondition {
    pub if_match: Option<String>,
    pub if_none_match: Option<String>,
}

/// Normalizes an ETag for RFC 4918 `If` condition lists (`"tag"`, `W/"tag"`, or `*`),
/// matching `DavEntityTag` in `ProtocolClient.cpp`.
pub fn dav_entity_tag(value: &str) -> String {
    let (weak, rest) = if let Some(stripped) = value.strip_prefix("W/") {
        ("W/", stripped)
    } else {
        ("", value)
    };
    if rest == "*" {
        return "*".to_string();
    }
    if rest.len() >= 2 && rest.starts_with('"') && rest.ends_with('"') {
        format!("{weak}{rest}")
    } else {
        format!("{weak}\"{rest}\"")
    }
}

/// Builds the RFC 4918 §10.4 no-tag `If` header (`(<token> ["etag"] Not ["etag"])`)
/// for a remote path, or returns `None` when neither lock nor ETag precondition
/// is active.
pub fn dav_if_header(
    lock_token: Option<&str>,
    precondition: Option<&DavEtagPrecondition>,
) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(tok) = lock_token.filter(|t| !t.is_empty()) {
        parts.push(format!("<{tok}>"));
    }
    if let Some(pre) = precondition {
        if let Some(im) = pre.if_match.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!("[{}]", dav_entity_tag(im)));
        }
        if let Some(inm) = pre.if_none_match.as_deref().filter(|s| !s.is_empty()) {
            parts.push(format!("Not [{}]", dav_entity_tag(inm)));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(format!("({})", parts.join(" ")))
    }
}

/// Validates a custom WebDAV dead-property XML local name (`[A-Za-z_][A-Za-z0-9_.-]*`).
pub fn dav_valid_property_name(name: &str) -> Result<(), ProtoError> {
    if name.is_empty() {
        return Err(ProtoError::Transport(
            "The property name is empty.".to_string(),
        ));
    }
    let mut chars = name.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(ProtoError::Transport(format!(
            "The property name '{name}' has to start with a letter or '_'."
        )));
    }
    for ch in chars {
        if !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')) {
            return Err(ProtoError::Transport(format!(
                "The property name '{name}' may only hold letters, digits, '_', '-' and '.'."
            )));
        }
    }
    Ok(())
}

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

pub fn dav_property_propfind_body(name: &str) -> Result<String, ProtoError> {
    dav_valid_property_name(name)?;
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <D:propfind xmlns:D=\"DAV:\" xmlns:{DAV_PROPERTY_PREFIX}=\"{DAV_PROPERTY_NAMESPACE}\">\
         <D:prop><{DAV_PROPERTY_PREFIX}:{name}/></D:prop></D:propfind>"
    ))
}

pub fn dav_property_update_body(name: &str, value: &str) -> Result<String, ProtoError> {
    dav_valid_property_name(name)?;
    let escaped = xml_escape(value);
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <D:propertyupdate xmlns:D=\"DAV:\" xmlns:{DAV_PROPERTY_PREFIX}=\"{DAV_PROPERTY_NAMESPACE}\">\
         <D:set><D:prop><{DAV_PROPERTY_PREFIX}:{name}>{escaped}</{DAV_PROPERTY_PREFIX}:{name}></D:prop></D:set>\
         </D:propertyupdate>"
    ))
}

pub(crate) fn reject_xxe_declarations(xml: &str) -> Result<(), ProtoError> {
    let upper = xml.to_ascii_uppercase();
    if upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY") {
        return Err(ProtoError::Transport(
            "Refusing XML response containing DOCTYPE or ENTITY declarations.".to_string(),
        ));
    }
    Ok(())
}

/// Extracts the lock token from a WebDAV `LOCK` response XML document (or plain
/// token body), matching `DavLockTokenFromXml` in `ProtocolClient.cpp`.
pub fn dav_lock_token_from_xml(xml: &str) -> Result<String, ProtoError> {
    reject_xxe_declarations(xml)?;
    let trimmed = xml.trim();
    if !trimmed.is_empty() && !trimmed.contains('<') {
        return Ok(trimmed.to_string());
    }
    let doc = roxmltree::Document::parse(trimmed)
        .map_err(|e| ProtoError::Transport(format!("Malformed WebDAV LOCK XML: {e}")))?;
    for node in doc.descendants() {
        if node.is_element() && node.tag_name().name().eq_ignore_ascii_case("locktoken") {
            for child in node.descendants() {
                if child.is_element() && child.tag_name().name().eq_ignore_ascii_case("href") {
                    if let Some(txt) = child.text().map(str::trim).filter(|s| !s.is_empty()) {
                        return Ok(txt.to_string());
                    }
                }
            }
            if let Some(txt) = node.text().map(str::trim).filter(|s| !s.is_empty()) {
                return Ok(txt.to_string());
            }
        }
    }
    Err(ProtoError::Transport(
        "WebDAV LOCK reply did not carry a locktoken.".to_string(),
    ))
}

/// Extracts a custom dead property's value from a `PROPFIND` multistatus XML
/// document. Returns `Ok(None)` when the property is inside a non-200 `propstat`
/// (e.g. `404 Not Found`), or `Ok(Some(value))` when present.
pub fn dav_property_value_from_xml(xml: &str, name: &str) -> Result<Option<String>, ProtoError> {
    dav_valid_property_name(name)?;
    reject_xxe_declarations(xml)?;
    let doc = roxmltree::Document::parse(xml)
        .map_err(|e| ProtoError::Transport(format!("Malformed WebDAV PROPFIND XML: {e}")))?;

    let mut saw_propstat = false;
    for propstat in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("propstat"))
    {
        saw_propstat = true;
        let status_ok = propstat
            .children()
            .find(|c| c.is_element() && c.tag_name().name().eq_ignore_ascii_case("status"))
            .and_then(|s| s.text())
            .map(|t| t.contains(" 200"))
            .unwrap_or(true);
        if !status_ok {
            continue;
        }
        for elem in propstat.descendants().filter(|n| n.is_element()) {
            if elem.tag_name().name() == name {
                return Ok(Some(elem.text().unwrap_or("").to_string()));
            }
        }
    }

    if saw_propstat {
        return Ok(None);
    }
    for elem in doc.descendants().filter(|n| n.is_element()) {
        if elem.tag_name().name() == name {
            return Ok(Some(elem.text().unwrap_or("").to_string()));
        }
    }
    Ok(None)
}

pub(crate) fn build_reqwest_proxy(proxy: &ProxyConfig) -> Result<Option<Proxy>, ProtoError> {
    let url = match proxy.kind {
        ProxyKind::None => return Ok(None),
        ProxyKind::Socks5 => {
            let scheme = if proxy.remote_dns {
                "socks5h"
            } else {
                "socks5"
            };
            format!("{scheme}://{}:{}", proxy.host, proxy.port)
        }
        ProxyKind::Socks4 => {
            let scheme = if proxy.remote_dns {
                "socks4a"
            } else {
                "socks4"
            };
            format!("{scheme}://{}:{}", proxy.host, proxy.port)
        }
        ProxyKind::HttpConnect => format!("http://{}:{}", proxy.host, proxy.port),
        ProxyKind::Telnet => {
            return Err(ProtoError::Transport(
                "This protocol connects through curl, which cannot run a telnet proxy; use SOCKS4, SOCKS5 or HTTP, or a protocol this build serves with its own transport.".to_string(),
            ));
        }
        ProxyKind::LocalCommand => {
            return Err(ProtoError::Transport(
                "This protocol connects through curl, which cannot run a local command proxy; use SOCKS4, SOCKS5 or HTTP, or a protocol this build serves with its own transport.".to_string(),
            ));
        }
    };
    let mut p = Proxy::all(&url)
        .map_err(|e| ProtoError::Transport(format!("Invalid proxy URL '{url}': {e}")))?;
    if let Some(user) = proxy.username.as_deref().filter(|u| !u.is_empty()) {
        p = p.basic_auth(user, proxy.password.as_deref().unwrap_or(""));
    }
    Ok(Some(p))
}

pub(crate) struct ChannelBodyStream {
    pub rx: mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl Stream for ChannelBodyStream {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

fn percent_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    out.push('/');
    for (idx, seg) in path.trim_start_matches('/').split('/').enumerate() {
        if idx > 0 {
            out.push('/');
        }
        for &b in seg.as_bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((h << 4) | l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn parse_http_date(text: &str) -> Option<i64> {
    let s = text.trim();
    // Try RFC 3339 / ISO 8601 first (`2026-03-15T12:30:45Z`)
    if let Some((date_p, time_p)) = s.split_once('T') {
        let mut dp = date_p.split('-');
        let y: i32 = dp.next()?.parse().ok()?;
        let m: u32 = dp.next()?.parse().ok()?;
        let d: u32 = dp.next()?.parse().ok()?;
        let clock = time_p
            .trim_end_matches('Z')
            .split(['+', '-', '.'])
            .next()?;
        let mut tp = clock.split(':');
        let hh: u32 = tp.next()?.parse().ok()?;
        let mm: u32 = tp.next()?.parse().ok()?;
        let ss: u32 = tp.next()?.parse().ok()?;
        return utc_ymdhms_to_unix(y, m, d, hh, mm, ss);
    }

    // RFC 1123 (`Sun, 06 Nov 1994 08:49:37 GMT`)
    let after_comma = s.split_once(',').map(|(_, r)| r.trim()).unwrap_or(s);
    let toks: Vec<&str> = after_comma.split_whitespace().collect();
    if toks.len() >= 4 {
        let day: u32 = toks[0].parse().ok()?;
        let month = match toks[1].to_ascii_uppercase().as_str() {
            "JAN" => 1,
            "FEB" => 2,
            "MAR" => 3,
            "APR" => 4,
            "MAY" => 5,
            "JUN" => 6,
            "JUL" => 7,
            "AUG" => 8,
            "SEP" => 9,
            "OCT" => 10,
            "NOV" => 11,
            "DEC" => 12,
            _ => return None,
        };
        let year: i32 = toks[2].parse().ok()?;
        let mut tp = toks[3].split(':');
        let hh: u32 = tp.next()?.parse().ok()?;
        let mm: u32 = tp.next()?.parse().ok()?;
        let ss: u32 = tp.next()?.parse().ok()?;
        return utc_ymdhms_to_unix(year, month, day, hh, mm, ss);
    }
    None
}

#[derive(Clone)]
pub struct WebDavConnectConfig {
    pub scheme: ProtocolScheme,
    pub host: String,
    pub port: u16,
    pub base_path: String,
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
    pub tls: TlsSettings,
    pub proxy: Option<ProxyConfig>,
    pub timeout: Duration,
}

impl Default for WebDavConnectConfig {
    fn default() -> Self {
        Self {
            scheme: ProtocolScheme::Webdavs,
            host: String::new(),
            port: 443,
            base_path: "/".to_string(),
            username: None,
            password: None,
            tls: TlsSettings::default(),
            proxy: None,
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Default)]
struct DavConditionState {
    locks: HashMap<String, String>,
    etags: HashMap<String, DavEtagPrecondition>,
}

pub struct WebDavSession {
    cfg: WebDavConnectConfig,
    client: Client,
    state: Mutex<DavConditionState>,
    jump_tunnel: Option<Arc<SshJumpTunnel>>,
    socks_relay: Mutex<Option<Socks5JumpRelay>>,
}

impl WebDavSession {
    pub async fn connect(
        mut cfg: WebDavConnectConfig,
        tunnel_cfg: Option<&SshConnectConfig>,
        tunnel_local_port: u16,
    ) -> Result<Self, ProtoError> {
        let mut jump_tunnel = None;
        let mut socks_relay = None;

        if let Some(tcfg) = tunnel_cfg {
            let jump = Arc::new(SshJumpTunnel::connect(tcfg.clone()).await?);
            let relay = jump.start_socks5_relay(tunnel_local_port).await?;
            cfg.proxy = Some(ProxyConfig::socks5_loopback(relay.local_port()));
            jump_tunnel = Some(jump);
            socks_relay = Some(relay);
        }

        let tls_cfg = build_rustls_client_config(&cfg.tls)?;
        let mut builder = Client::builder()
            .use_preconfigured_tls(tls_cfg)
            .connect_timeout(cfg.timeout);

        if let Some(proxy_cfg) = cfg.proxy.as_ref() {
            if let Some(proxy) = build_reqwest_proxy(proxy_cfg)? {
                builder = builder.proxy(proxy);
            } else {
                builder = builder.no_proxy();
            }
        } else {
            builder = builder.no_proxy();
        }

        let client = builder
            .build()
            .map_err(|e| ProtoError::Transport(format!("Failed to build WebDAV client: {e}")))?;

        Ok(Self {
            cfg,
            client,
            state: Mutex::new(DavConditionState::default()),
            jump_tunnel,
            socks_relay: Mutex::new(socks_relay),
        })
    }

    fn http_scheme(&self) -> &'static str {
        match self.cfg.scheme {
            ProtocolScheme::Davs | ProtocolScheme::Webdav | ProtocolScheme::Webdavs => "https",
            _ => "http",
        }
    }

    fn resolve_remote_path(&self, remote_path: &str) -> String {
        let base = self.cfg.base_path.trim_end_matches('/');
        let rel = if remote_path.is_empty() || remote_path == "." {
            ""
        } else {
            remote_path
        };
        if rel.starts_with('/') {
            if !base.is_empty() && (rel == base || rel.starts_with(&format!("{base}/"))) {
                rel.to_string()
            } else {
                format!("{base}{rel}")
            }
        } else if base.is_empty() {
            format!("/{rel}")
        } else {
            format!("{base}/{rel}")
        }
    }

    fn url_for(&self, remote_path: &str, trailing_slash: bool) -> String {
        let full_path = self.resolve_remote_path(remote_path);
        let mut encoded = percent_encode_path(&full_path);
        if trailing_slash && !encoded.ends_with('/') {
            encoded.push('/');
        }
        let host = if self.cfg.host.contains(':') && !self.cfg.host.starts_with('[') {
            format!("[{}]", self.cfg.host)
        } else {
            self.cfg.host.clone()
        };
        format!("{}://{}:{}{}", self.http_scheme(), host, self.cfg.port, encoded)
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(user) = self.cfg.username.as_deref().filter(|u| !u.is_empty()) {
            let pass = self.cfg.password.as_deref().map(String::as_str);
            req.basic_auth(user, pass)
        } else {
            req
        }
    }

    async fn has_etag_precondition(&self, remote_path: &str) -> bool {
        let key = self.resolve_remote_path(remote_path);
        let guard = self.state.lock().await;
        guard.etags.contains_key(&key)
    }

    async fn if_header_for(&self, remote_path: &str) -> Option<String> {
        let key = self.resolve_remote_path(remote_path);
        let guard = self.state.lock().await;
        dav_if_header(
            guard.locks.get(&key).map(String::as_str),
            guard.etags.get(&key),
        )
    }

    pub async fn set_etag_precondition(
        &self,
        remote_path: &str,
        precondition: Option<DavEtagPrecondition>,
    ) {
        let key = self.resolve_remote_path(remote_path);
        let mut guard = self.state.lock().await;
        match precondition {
            Some(p) => {
                guard.etags.insert(key, p);
            }
            None => {
                guard.etags.remove(&key);
            }
        }
    }

    /// Acquires an exclusive write `LOCK` on `remote_path`, stores the token in
    /// the session's active lock map, and returns it.
    pub async fn lock(&self, remote_path: &str, timeout_secs: u32) -> Result<String, ProtoError> {
        let method = Method::from_bytes(b"LOCK")
            .map_err(|e| ProtoError::Transport(format!("Invalid LOCK method: {e}")))?;
        let timeout_hdr = if timeout_secs > 0 {
            format!("Second-{timeout_secs}")
        } else {
            "Infinite, Second-3600".to_string()
        };
        let body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
            <D:lockinfo xmlns:D=\"DAV:\">\
            <D:lockscope><D:exclusive/></D:lockscope>\
            <D:locktype><D:write/></D:locktype>\
            </D:lockinfo>";

        let mut req = self
            .apply_auth(self.client.request(method, self.url_for(remote_path, false)))
            .header("Depth", "0")
            .header("Timeout", timeout_hdr)
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(body);
        if let Some(if_hdr) = self.if_header_for(remote_path).await {
            req = req.header("If", if_hdr);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV LOCK failed: {e}")))?;
        let status = resp.status();
        let header_tok = resp
            .headers()
            .get("Lock-Token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().trim_start_matches('<').trim_end_matches('>').to_string());
        let text = resp
            .text()
            .await
            .map_err(|e| ProtoError::Transport(format!("Reading LOCK body failed: {e}")))?;
        if !status.is_success() {
            return Err(ProtoError::Transport(format!(
                "WebDAV LOCK '{remote_path}' failed with HTTP {status}: {}",
                text.trim()
            )));
        }
        let token = match dav_lock_token_from_xml(&text) {
            Ok(t) => t,
            Err(_) if header_tok.is_some() => header_tok.unwrap(),
            Err(e) => return Err(e),
        };
        let key = self.resolve_remote_path(remote_path);
        self.state.lock().await.locks.insert(key, token.clone());
        Ok(token)
    }

    /// Releases a WebDAV `UNLOCK` token and clears any stored lock for `remote_path`.
    pub async fn unlock(&self, remote_path: &str, token: Option<&str>) -> Result<(), ProtoError> {
        let key = self.resolve_remote_path(remote_path);
        let resolved_tok = match token {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => self
                .state
                .lock()
                .await
                .locks
                .get(&key)
                .cloned()
                .ok_or_else(|| {
                    ProtoError::Transport(format!("No WebDAV lock token held for '{remote_path}'."))
                })?,
        };
        let method = Method::from_bytes(b"UNLOCK")
            .map_err(|e| ProtoError::Transport(format!("Invalid UNLOCK method: {e}")))?;
        let formatted_tok = if resolved_tok.starts_with('<') {
            resolved_tok
        } else {
            format!("<{resolved_tok}>")
        };
        let resp = self
            .apply_auth(self.client.request(method, self.url_for(remote_path, false)))
            .header("Lock-Token", formatted_tok)
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV UNLOCK failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(ProtoError::Transport(format!(
                "WebDAV UNLOCK '{remote_path}' failed with HTTP {}.",
                resp.status()
            )));
        }
        self.state.lock().await.locks.remove(&key);
        Ok(())
    }

    /// Queries the current `DAV:getetag` of `remote_path` via `PROPFIND` `Depth: 0`.
    pub async fn get_etag(&self, remote_path: &str) -> Result<Option<String>, ProtoError> {
        let (_, etag_opt) = self.propfind_single(remote_path).await?;
        Ok(etag_opt)
    }

    /// Queries `(etag, path_missing)` for `etag <file> -get`.
    pub async fn get_etag_with_existence(
        &self,
        remote_path: &str,
    ) -> Result<(Option<String>, bool), ProtoError> {
        let (entry_opt, etag_opt) = self.propfind_single(remote_path).await?;
        Ok((etag_opt, entry_opt.is_none()))
    }

    /// Verifies that the WebDAV endpoint is reachable and credentials are accepted.
    pub async fn check_endpoint(&self, initial_dir: &str) -> Result<(), ProtoError> {
        let method = Method::from_bytes(b"PROPFIND")
            .map_err(|e| ProtoError::Transport(format!("Invalid PROPFIND method: {e}")))?;
        let target = if initial_dir.is_empty() {
            "/"
        } else {
            initial_dir
        };
        let body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
            <D:propfind xmlns:D=\"DAV:\"><D:prop><D:resourcetype/></D:prop></D:propfind>";
        let resp = self
            .apply_auth(self.client.request(method, self.url_for(target, false)))
            .header("Depth", "0")
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(body)
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV endpoint probe failed: {e}")))?;
        let code = resp.status().as_u16();
        if code == 401 {
            return Err(ProtoError::Transport(
                "Authentication failed: WebDAV server rejected credentials (HTTP 401).".to_string(),
            ));
        }
        if code == 405 {
            return Err(ProtoError::Transport(
                "The server does not support WebDAV: PROPFIND is not allowed.".to_string(),
            ));
        }
        Ok(())
    }

    /// Sets a custom dead property in `urn:linscp:properties` via `PROPPATCH`.
    pub async fn set_property(
        &self,
        remote_path: &str,
        name: &str,
        value: &str,
    ) -> Result<(), ProtoError> {
        let body = dav_property_update_body(name, value)?;
        let method = Method::from_bytes(b"PROPPATCH")
            .map_err(|e| ProtoError::Transport(format!("Invalid PROPPATCH method: {e}")))?;
        let mut req = self
            .apply_auth(self.client.request(method, self.url_for(remote_path, false)))
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(body);
        if let Some(if_hdr) = self.if_header_for(remote_path).await {
            req = req.header("If", if_hdr);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV PROPPATCH failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(ProtoError::Transport(format!(
                "WebDAV PROPPATCH '{remote_path}' failed with HTTP {}.",
                resp.status()
            )));
        }
        Ok(())
    }

    /// Reads a custom dead property in `urn:linscp:properties` via `PROPFIND`.
    pub async fn get_property(
        &self,
        remote_path: &str,
        name: &str,
    ) -> Result<Option<String>, ProtoError> {
        let body = dav_property_propfind_body(name)?;
        let method = Method::from_bytes(b"PROPFIND")
            .map_err(|e| ProtoError::Transport(format!("Invalid PROPFIND method: {e}")))?;
        let resp = self
            .apply_auth(self.client.request(method, self.url_for(remote_path, false)))
            .header("Depth", "0")
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(body)
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV PROPFIND failed: {e}")))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(ProtoError::Transport(format!(
                "WebDAV PROPFIND '{remote_path}' failed with HTTP {}.",
                resp.status()
            )));
        }
        let xml = resp
            .text()
            .await
            .map_err(|e| ProtoError::Transport(format!("Reading PROPFIND body failed: {e}")))?;
        dav_property_value_from_xml(&xml, name)
    }

    async fn propfind_raw(
        &self,
        remote_path: &str,
        depth: &str,
    ) -> Result<Option<String>, ProtoError> {
        let method = Method::from_bytes(b"PROPFIND")
            .map_err(|e| ProtoError::Transport(format!("Invalid PROPFIND method: {e}")))?;
        let body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
            <D:propfind xmlns:D=\"DAV:\"><D:prop>\
            <D:resourcetype/><D:getcontentlength/><D:getlastmodified/><D:getetag/>\
            </D:prop></D:propfind>";
        let resp = self
            .apply_auth(
                self.client
                    .request(method, self.url_for(remote_path, depth == "1")),
            )
            .header("Depth", depth)
            .header("Content-Type", "application/xml; charset=utf-8")
            .body(body)
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV PROPFIND failed: {e}")))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(ProtoError::Transport(format!(
                "WebDAV PROPFIND '{remote_path}' failed with HTTP {}.",
                resp.status()
            )));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| ProtoError::Transport(format!("Reading PROPFIND XML failed: {e}")))?;
        Ok(Some(text))
    }

    async fn propfind_single(
        &self,
        remote_path: &str,
    ) -> Result<(Option<FileEntry>, Option<String>), ProtoError> {
        let Some(xml) = self.propfind_raw(remote_path, "0").await? else {
            return Ok((None, None));
        };
        let mut items = parse_propfind_multistatus(&xml)?;
        let Some(first) = items.pop() else {
            return Ok((None, None));
        };
        let leaf = remote_path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("/");
        let mut entry = first.entry;
        entry.name = leaf.to_string();
        Ok((Some(entry), first.etag))
    }
}

struct DavParsedResponse {
    href_path: String,
    entry: FileEntry,
    etag: Option<String>,
}

fn strip_url_to_path(href: &str) -> String {
    let without_scheme = if let Some((_, rest)) = href.split_once("://") {
        match rest.find('/') {
            Some(pos) => &rest[pos..],
            None => "/",
        }
    } else {
        href
    };
    percent_decode(without_scheme.split('?').next().unwrap_or(without_scheme))
}

fn parse_propfind_multistatus(xml: &str) -> Result<Vec<DavParsedResponse>, ProtoError> {
    reject_xxe_declarations(xml)?;
    let doc = roxmltree::Document::parse(xml)
        .map_err(|e| ProtoError::Transport(format!("Malformed WebDAV multistatus XML: {e}")))?;
    let mut results = Vec::new();

    for resp_node in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("response"))
    {
        let href = resp_node
            .children()
            .find(|c| c.is_element() && c.tag_name().name().eq_ignore_ascii_case("href"))
            .and_then(|c| c.text())
            .unwrap_or("")
            .trim();
        let href_path = strip_url_to_path(href);

        let mut is_dir = href.ends_with('/');
        let mut size = 0u64;
        let mut mtime = 0i64;
        let mut has_time = false;
        let mut etag = None;

        for propstat in resp_node
            .children()
            .filter(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("propstat"))
        {
            let status_ok = propstat
                .children()
                .find(|c| c.is_element() && c.tag_name().name().eq_ignore_ascii_case("status"))
                .and_then(|s| s.text())
                .map(|t| t.contains(" 200"))
                .unwrap_or(true);
            if !status_ok {
                continue;
            }
            for elem in propstat.descendants().filter(|n| n.is_element()) {
                match elem.tag_name().name().to_ascii_lowercase().as_str() {
                    "collection" => is_dir = true,
                    "getcontentlength" => {
                        if let Some(txt) = elem.text() {
                            if let Ok(v) = txt.trim().parse::<u64>() {
                                size = v;
                            }
                        }
                    }
                    "getlastmodified" => {
                        if let Some(txt) = elem.text() {
                            if let Some(ts) = parse_http_date(txt) {
                                mtime = ts;
                                has_time = true;
                            }
                        }
                    }
                    "getetag" => {
                        if let Some(txt) = elem.text().map(str::trim).filter(|s| !s.is_empty()) {
                            etag = Some(txt.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        let clean = href_path.trim_end_matches('/');
        let leaf = clean
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("/")
            .to_string();

        results.push(DavParsedResponse {
            href_path,
            entry: FileEntry {
                name: leaf,
                size: if is_dir { 0 } else { size },
                is_dir,
                is_symlink: false,
                broken_link: false,
                date: if has_time {
                    format_utc_timestamp(mtime)
                } else {
                    String::new()
                },
                mtime: if has_time { mtime } else { 0 },
                permissions: if is_dir {
                    "drwxr-xr-x".to_string()
                } else {
                    "-rw-r--r--".to_string()
                },
                owner: None,
                group: None,
            },
            etag,
        });
    }
    Ok(results)
}

#[async_trait]
impl RemoteSession for WebDavSession {
    fn scheme(&self) -> ProtocolScheme {
        self.cfg.scheme
    }

    async fn pwd(&self) -> Result<String, ProtoError> {
        let base = self.cfg.base_path.trim();
        if base.is_empty() {
            Ok("/".to_string())
        } else {
            Ok(base.to_string())
        }
    }

    async fn stat(&self, remote_path: &str) -> Result<Option<FileEntry>, ProtoError> {
        let (entry_opt, _) = self.propfind_single(remote_path).await?;
        Ok(entry_opt)
    }

    async fn list_dir(&self, remote_path: &str) -> Result<Vec<FileEntry>, ProtoError> {
        let Some(xml) = self.propfind_raw(remote_path, "1").await? else {
            return Err(ProtoError::Transport(format!(
                "WebDAV directory '{remote_path}' does not exist."
            )));
        };
        let requested = self.resolve_remote_path(remote_path);
        let norm_req = requested.trim_end_matches('/');
        let parsed = parse_propfind_multistatus(&xml)?;
        let mut entries = Vec::new();
        for item in parsed {
            let item_norm = item.href_path.trim_end_matches('/');
            if item_norm == norm_req || item.entry.name == "." || item.entry.name == ".." {
                continue;
            }
            entries.push(item.entry);
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    async fn mkdir(&self, remote_path: &str) -> Result<(), ProtoError> {
        let method = Method::from_bytes(b"MKCOL")
            .map_err(|e| ProtoError::Transport(format!("Invalid MKCOL method: {e}")))?;
        let mut req = self.apply_auth(self.client.request(method, self.url_for(remote_path, true)));
        if let Some(if_hdr) = self.if_header_for(remote_path).await {
            req = req.header("If", if_hdr);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV MKCOL failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(ProtoError::Transport(format!(
                "WebDAV MKCOL '{remote_path}' failed with HTTP {}.",
                resp.status()
            )));
        }
        Ok(())
    }

    async fn remove_file(&self, remote_path: &str) -> Result<(), ProtoError> {
        let mut req = self.apply_auth(self.client.delete(self.url_for(remote_path, false)));
        let has_etag = self.has_etag_precondition(remote_path).await;
        if let Some(if_hdr) = self.if_header_for(remote_path).await {
            req = req.header("If", if_hdr);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV DELETE failed: {e}")))?;
        if !resp.status().is_success() {
            if resp.status().as_u16() == 412 && has_etag {
                return Err(ProtoError::Transport(format!(
                    "WebDAV DELETE '{remote_path}' failed with HTTP {} (ETag precondition not satisfied).",
                    resp.status()
                )));
            }
            return Err(ProtoError::Transport(format!(
                "WebDAV DELETE '{remote_path}' failed with HTTP {}.",
                resp.status()
            )));
        }
        Ok(())
    }

    async fn remove_dir(&self, remote_path: &str) -> Result<(), ProtoError> {
        let mut req = self.apply_auth(self.client.delete(self.url_for(remote_path, true)));
        let has_etag = self.has_etag_precondition(remote_path).await;
        if let Some(if_hdr) = self.if_header_for(remote_path).await {
            req = req.header("If", if_hdr);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV DELETE collection failed: {e}")))?;
        if !resp.status().is_success() {
            if resp.status().as_u16() == 412 && has_etag {
                return Err(ProtoError::Transport(format!(
                    "WebDAV DELETE '{remote_path}' failed with HTTP {} (ETag precondition not satisfied).",
                    resp.status()
                )));
            }
            return Err(ProtoError::Transport(format!(
                "WebDAV DELETE '{remote_path}' failed with HTTP {}.",
                resp.status()
            )));
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        let method = Method::from_bytes(b"MOVE")
            .map_err(|e| ProtoError::Transport(format!("Invalid MOVE method: {e}")))?;
        let dest_url = self.url_for(to, false);
        let mut req = self
            .apply_auth(self.client.request(method, self.url_for(from, false)))
            .header("Destination", dest_url)
            .header("Overwrite", "T");
        let has_etag = self.has_etag_precondition(from).await;
        if let Some(if_hdr) = self.if_header_for(from).await {
            req = req.header("If", if_hdr);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV MOVE failed: {e}")))?;
        if !resp.status().is_success() {
            if resp.status().as_u16() == 412 && has_etag {
                return Err(ProtoError::Transport(format!(
                    "WebDAV MOVE '{from}' -> '{to}' failed with HTTP {} (ETag precondition not satisfied).",
                    resp.status()
                )));
            }
            return Err(ProtoError::Transport(format!(
                "WebDAV MOVE '{from}' -> '{to}' failed with HTTP {}.",
                resp.status()
            )));
        }
        Ok(())
    }

    async fn copy_file(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        let method = Method::from_bytes(b"COPY")
            .map_err(|e| ProtoError::Transport(format!("Invalid COPY method: {e}")))?;
        let dest_url = self.url_for(to, false);
        let mut req = self
            .apply_auth(self.client.request(method, self.url_for(from, false)))
            .header("Destination", dest_url)
            .header("Overwrite", "T");
        if let Some(if_hdr) = self.if_header_for(to).await {
            req = req.header("If", if_hdr);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV COPY failed: {e}")))?;
        if !resp.status().is_success() {
            if matches!(resp.status().as_u16(), 405 | 501) {
                return Err(ProtoError::UnsupportedCapability("COPY", self.cfg.scheme));
            }
            return Err(ProtoError::Transport(format!(
                "WebDAV COPY '{from}' -> '{to}' failed with HTTP {}.",
                resp.status()
            )));
        }
        Ok(())
    }

    async fn symlink(&self, _target: &str, _link_path: &str) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("symlink", self.cfg.scheme))
    }

    async fn chmod(&self, _remote_path: &str, _mode: u32) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("chmod", self.cfg.scheme))
    }

    async fn set_mtime(&self, _remote_path: &str, _mtime: i64) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("set_mtime", self.cfg.scheme))
    }

    async fn checksum(&self, algorithm: &str, remote_path: &str) -> Result<String, ProtoError> {
        let alg = DigestAlgorithm::parse(algorithm).ok_or_else(|| {
            ProtoError::Transport(format!("Unsupported checksum algorithm '{algorithm}'."))
        })?;
        let mut hasher = DigestHasher::new(alg);
        let mut sink = HasherAsyncSink {
            hasher: &mut hasher,
        };
        self.download(remote_path, TransferRequest::default(), &mut sink, None)
            .await?;
        Ok(hasher.finalize_hex())
    }

    async fn download(
        &self,
        remote_path: &str,
        opts: TransferRequest,
        sink: &mut (dyn AsyncWrite + Unpin + Send),
        progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        let mut req = self.apply_auth(self.client.get(self.url_for(remote_path, false)));
        if opts.resume_offset > 0 {
            req = req.header("Range", format!("bytes={}-", opts.resume_offset));
        }
        let mut resp = req
            .send()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV GET failed: {e}")))?;
        if opts.resume_offset > 0 && resp.status().as_u16() != 206 {
            return Err(ProtoError::Transport(format!(
                "WebDAV server did not honor byte-range resume (HTTP {}).",
                resp.status()
            )));
        }
        if !resp.status().is_success() {
            return Err(ProtoError::Transport(format!(
                "WebDAV GET '{remote_path}' failed with HTTP {}.",
                resp.status()
            )));
        }

        let content_len = resp.content_length().unwrap_or(0);
        let total = opts.resume_offset + content_len;
        let mut transferred = 0u64;
        let mut limiter = RateLimiter::new(opts.speed_kbytes_per_sec);

        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| ProtoError::Transport(format!("WebDAV download stream error: {e}")))?
        {
            sink.write_all(&chunk)
                .await
                .map_err(|e| ProtoError::Transport(format!("Writing download sink failed: {e}")))?;
            transferred += chunk.len() as u64;
            if let Some(cb) = progress {
                cb(opts.resume_offset + transferred, total);
            }
            if opts.speed_kbytes_per_sec > 0 {
                sink.flush()
                    .await
                    .map_err(|e| ProtoError::Transport(format!("Flushing download sink failed: {e}")))?;
            }
            limiter.consume(chunk.len()).await;
        }
        sink.flush()
            .await
            .map_err(|e| ProtoError::Transport(format!("Flushing download sink failed: {e}")))?;
        Ok(transferred)
    }

    async fn upload(
        &self,
        remote_path: &str,
        opts: TransferRequest,
        source: &mut (dyn AsyncRead + Unpin + Send),
        total_size: Option<u64>,
        progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        if opts.resume_offset > 0 || opts.append {
            return Err(ProtoError::Transport(
                "WebDAV PUT does not support unguarded byte-offset resume or append.".to_string(),
            ));
        }

        let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(4);
        let mut req = self.apply_auth(self.client.put(self.url_for(remote_path, false)));
        if let Some(sz) = total_size {
            req = req.header("Content-Length", sz.to_string());
        }
        let has_etag = self.has_etag_precondition(remote_path).await;
        if let Some(if_hdr) = self.if_header_for(remote_path).await {
            req = req.header("If", if_hdr);
        }
        req = req.body(Body::wrap_stream(ChannelBodyStream { rx }));

        let send_fut = req.send();
        let pump_fut = async {
            let mut buf = vec![0u8; 32 * 1024];
            let mut sent = 0u64;
            let mut limiter = RateLimiter::new(opts.speed_kbytes_per_sec);
            let reported_total = total_size.unwrap_or(0);
            loop {
                let n = source.read(&mut buf).await.map_err(|e| {
                    ProtoError::Transport(format!("Reading upload source failed: {e}"))
                })?;
                if n == 0 {
                    break;
                }
                let bytes = Bytes::copy_from_slice(&buf[..n]);
                if tx.send(Ok(bytes)).await.is_err() {
                    break;
                }
                sent += n as u64;
                if let Some(cb) = progress {
                    cb(sent, reported_total);
                }
                limiter.consume(n).await;
            }
            drop(tx);
            Ok::<u64, ProtoError>(sent)
        };

        let (pump_res, resp_res) = tokio::join!(pump_fut, send_fut);
        let transferred = pump_res?;
        let resp = resp_res
            .map_err(|e| ProtoError::Transport(format!("WebDAV PUT '{remote_path}' failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            if status.as_u16() == 412 && has_etag {
                return Err(ProtoError::Transport(format!(
                    "WebDAV PUT '{remote_path}' failed with HTTP {status} (ETag precondition not satisfied): {}",
                    detail.trim()
                )));
            }
            return Err(ProtoError::Transport(format!(
                "WebDAV PUT '{remote_path}' failed with HTTP {status}: {}",
                detail.trim()
            )));
        }
        Ok(transferred)
    }

    async fn probe_endpoint(&self, initial_dir: &str) -> Result<(), ProtoError> {
        self.check_endpoint(initial_dir).await
    }

    async fn dav_lock(&self, remote_path: &str, timeout_secs: u32) -> Result<String, ProtoError> {
        self.lock(remote_path, timeout_secs).await
    }

    async fn dav_unlock(&self, remote_path: &str, token: Option<&str>) -> Result<(), ProtoError> {
        self.unlock(remote_path, token).await
    }

    async fn dav_get_etag(&self, remote_path: &str) -> Result<(Option<String>, bool), ProtoError> {
        self.get_etag_with_existence(remote_path).await
    }

    async fn dav_set_etag_precondition(
        &self,
        remote_path: &str,
        precondition: Option<DavEtagPrecondition>,
    ) -> Result<(), ProtoError> {
        self.set_etag_precondition(remote_path, precondition).await;
        Ok(())
    }

    async fn dav_set_property(
        &self,
        remote_path: &str,
        name: &str,
        value: &str,
    ) -> Result<(), ProtoError> {
        self.set_property(remote_path, name, value).await
    }

    async fn dav_get_property(
        &self,
        remote_path: &str,
        name: &str,
    ) -> Result<Option<String>, ProtoError> {
        self.get_property(remote_path, name).await
    }

    async fn close(&self) -> Result<(), ProtoError> {
        if let Some(relay) = self.socks_relay.lock().await.take() {
            relay.stop().await;
        }
        if let Some(jump) = &self.jump_tunnel {
            let _ = jump.close().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dav_if_header_and_xml_helpers_match_rfc4918() {
        assert_eq!(dav_entity_tag("v1"), "\"v1\"");
        assert_eq!(dav_entity_tag("W/v1"), "W/\"v1\"");
        assert_eq!(
            dav_if_header(
                Some("opaquelocktoken:abc-123"),
                Some(&DavEtagPrecondition {
                    if_match: Some("v1".to_string()),
                    if_none_match: None,
                }),
            )
            .unwrap(),
            "(<opaquelocktoken:abc-123> [\"v1\"])"
        );
        assert_eq!(
            dav_if_header(
                None,
                Some(&DavEtagPrecondition {
                    if_match: None,
                    if_none_match: Some("\"v2\"".to_string()),
                }),
            )
            .unwrap(),
            "(Not [\"v2\"])"
        );

        let lock_xml = "<?xml version=\"1.0\"?><D:prop xmlns:D=\"DAV:\"><D:lockdiscovery>\
            <D:activelock><D:locktoken><D:href>urn:uuid:1111-2222</D:href></D:locktoken>\
            </D:activelock></D:lockdiscovery></D:prop>";
        assert_eq!(dav_lock_token_from_xml(lock_xml).unwrap(), "urn:uuid:1111-2222");

        let prop_xml = "<?xml version=\"1.0\"?><D:multistatus xmlns:D=\"DAV:\" \
            xmlns:L=\"urn:linscp:properties\"><D:response><D:propstat>\
            <D:prop><L:release_tag>2026.10</L:release_tag></D:prop>\
            <D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>";
        assert_eq!(
            dav_property_value_from_xml(prop_xml, "release_tag").unwrap(),
            Some("2026.10".to_string())
        );

        assert!(dav_valid_property_name("9bad").is_err());
        assert!(dav_lock_token_from_xml("<!DOCTYPE foo><x/>").is_err());
    }
}
