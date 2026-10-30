//! Pure-Rust Amazon S3 / S3-compatible object storage client (`S3Session`
//! implementing `RemoteSession`) built on `reqwest` + `tls.rs` +
//! `linscp_crypto::sigv4` + XXE-safe `roxmltree`, porting `S3Client.{h,cpp}`:
//! - Bucket (`ListAllMyBuckets`) and prefix (`ListObjectsV2`) directory listings
//! - `HEAD` stat, zero-byte `key/` folder markers, `CopyObject` / `UploadPartCopy`
//! - Resumable Multipart Upload (`CreateMultipartUpload`, `UploadPart` skipping
//!   verified completed parts on retry, `CompleteMultipartUpload`, and automatic
//!   `AbortMultipartUpload` on non-resumable error)
//! - Byte-range `GET` resume and full S3 Object Versioning (`ListObjectVersions`,
//!   `?versionId=` stat, download, and delete)

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use linscp_crypto::digests::{compute_digest_hex, DigestAlgorithm, DigestHasher};
use linscp_crypto::sigv4::{region_from_s3_host, sign_s3_request, S3SignParams};
use linscp_types::{FileEntry, ProtocolScheme};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::listing::format_utc_timestamp;
use crate::proxy::ProxyConfig;
use crate::sftp::HasherAsyncSink;
use crate::ssh::SshConnectConfig;
use crate::tls::{build_rustls_client_config, TlsSettings};
use crate::tunnel::{Socks5JumpRelay, SshJumpTunnel};
use crate::webdav::{build_reqwest_proxy, parse_http_date, reject_xxe_declarations};
use crate::{ProgressCallback, ProtoError, RateLimiter, RemoteSession, TransferRequest};

pub const DEFAULT_MULTIPART_THRESHOLD: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MIN_PART_SIZE: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3ObjectVersion {
    pub key: String,
    pub version_id: String,
    pub is_latest: bool,
    pub is_delete_marker: bool,
    pub size: u64,
    pub mtime: i64,
}

/// Resumable checkpoint for an in-flight S3 multipart upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultipartCheckpoint {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub total_size: u64,
    pub part_size: u64,
    /// `part_number (1..=10000) -> ETag`
    pub completed_parts: BTreeMap<u32, String>,
}

/// Thread-safe store of active multipart checkpoints (in-memory and optionally
/// mirrored to a private JSON sidecar file so interrupted uploads resume cleanly).
#[derive(Default)]
pub struct MultipartResumeStore {
    entries: Mutex<HashMap<String, MultipartCheckpoint>>,
    sidecar_path: Option<PathBuf>,
}

impl MultipartResumeStore {
    pub fn new_in_memory() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn with_sidecar_file(path: PathBuf) -> Arc<Self> {
        let initial = std::fs::read_to_string(&path)
            .ok()
            .and_then(|txt| serde_json::from_str::<HashMap<String, MultipartCheckpoint>>(&txt).ok())
            .unwrap_or_default();
        Arc::new(Self {
            entries: Mutex::new(initial),
            sidecar_path: Some(path),
        })
    }

    async fn get(&self, target_id: &str) -> Option<MultipartCheckpoint> {
        self.entries.lock().await.get(target_id).cloned()
    }

    async fn upsert(&self, target_id: String, cp: MultipartCheckpoint) {
        let mut guard = self.entries.lock().await;
        guard.insert(target_id, cp);
        if let Some(path) = &self.sidecar_path {
            if let Ok(json) = serde_json::to_vec_pretty(&*guard) {
                let _ = linscp_platform::write_private_file_atomic(path, &json);
            }
        }
    }

    async fn remove(&self, target_id: &str) {
        let mut guard = self.entries.lock().await;
        guard.remove(target_id);
        if let Some(path) = &self.sidecar_path {
            if let Ok(json) = serde_json::to_vec_pretty(&*guard) {
                let _ = linscp_platform::write_private_file_atomic(path, &json);
            }
        }
    }
}

#[derive(Clone)]
pub struct S3ConnectConfig {
    pub use_https: bool,
    pub host: String,
    pub port: u16,
    pub region: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
    /// Default bucket if `remote_path` does not begin with `/<bucket>/`.
    pub default_bucket: Option<String>,
    /// Use path-style `https://host:port/bucket/key` URLs (default `true` for
    /// custom endpoints/IPs, `false` for `*.amazonaws.com` virtual-hosted when desired).
    pub path_style: bool,
    pub multipart_threshold: u64,
    pub min_part_size: u64,
    /// When `false`, leaves unfinished multipart checkpoints intact on error so
    /// the caller can retry and resume from the last completed part.
    pub abort_multipart_on_error: bool,
    pub resume_store: Arc<MultipartResumeStore>,
    pub extra_signed_headers: BTreeMap<String, String>,
    /// Headers signed and sent exclusively on object write operations (`PUT`, `CreateMultipartUpload`, `CopyObject`).
    pub object_write_headers: BTreeMap<String, String>,
    pub tls: TlsSettings,
    pub proxy: Option<ProxyConfig>,
    pub timeout: Duration,
}

impl Default for S3ConnectConfig {
    fn default() -> Self {
        Self {
            use_https: true,
            host: "s3.us-east-1.amazonaws.com".to_string(),
            port: 443,
            region: None,
            access_key_id: String::new(),
            secret_access_key: Zeroizing::new(String::new()),
            session_token: None,
            default_bucket: None,
            path_style: true,
            multipart_threshold: DEFAULT_MULTIPART_THRESHOLD,
            min_part_size: DEFAULT_MIN_PART_SIZE,
            abort_multipart_on_error: true,
            resume_store: MultipartResumeStore::new_in_memory(),
            extra_signed_headers: BTreeMap::new(),
            object_write_headers: BTreeMap::new(),
            tls: TlsSettings::default(),
            proxy: None,
            timeout: Duration::from_secs(30),
        }
    }
}

fn s3_uri_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    out.push('/');
    for (i, seg) in path.trim_start_matches('/').split('/').enumerate() {
        if i > 0 {
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

fn s3_query_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
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

fn parse_s3_error_xml(status: reqwest::StatusCode, body: &str) -> ProtoError {
    if reject_xxe_declarations(body).is_ok() {
        if let Ok(doc) = roxmltree::Document::parse(body) {
            let mut code = None;
            let mut msg = None;
            for node in doc.descendants().filter(|n| n.is_element()) {
                match node.tag_name().name() {
                    "Code" if code.is_none() => code = node.text().map(str::trim),
                    "Message" if msg.is_none() => msg = node.text().map(str::trim),
                    _ => {}
                }
            }
            if code.is_some() || msg.is_some() {
                return ProtoError::Transport(format!(
                    "S3 HTTP {status} ({}): {}",
                    code.unwrap_or("Error"),
                    msg.unwrap_or("request failed")
                ));
            }
        }
    }
    let trimmed = body.trim();
    if trimmed.is_empty() {
        ProtoError::Transport(format!("S3 request failed with HTTP {status}."))
    } else {
        ProtoError::Transport(format!("S3 HTTP {status}: {trimmed}"))
    }
}

pub struct S3Session {
    cfg: S3ConnectConfig,
    region: String,
    client: Client,
    jump_tunnel: Option<Arc<SshJumpTunnel>>,
    socks_relay: Mutex<Option<Socks5JumpRelay>>,
}

impl S3Session {
    pub async fn connect(
        mut cfg: S3ConnectConfig,
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

        if cfg.access_key_id.trim().is_empty() || cfg.secret_access_key.is_empty() {
            return Err(ProtoError::Transport(
                "S3 access key id and secret access key are required.".to_string(),
            ));
        }

        let region = cfg
            .region
            .clone()
            .filter(|r| !r.trim().is_empty())
            .or_else(|| region_from_s3_host(&cfg.host))
            .unwrap_or_else(|| "us-east-1".to_string());

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
            .map_err(|e| ProtoError::Transport(format!("Failed to build S3 HTTP client: {e}")))?;

        Ok(Self {
            cfg,
            region,
            client,
            jump_tunnel,
            socks_relay: Mutex::new(socks_relay),
        })
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    /// Splits a remote path into `(Option<bucket>, key)`.
    /// `/` maps to `(None, "")` (or `(Some(default_bucket), "")` when `default_bucket` is set).
    fn split_bucket_and_key(&self, remote_path: &str) -> Result<(Option<String>, String), ProtoError> {
        let trimmed = remote_path.trim();
        let rel = trimmed.trim_start_matches('/');
        if rel.is_empty() || trimmed == "." {
            return Ok((self.cfg.default_bucket.clone(), String::new()));
        }
        if let Some(def_bkt) = self.cfg.default_bucket.as_ref() {
            if let Some(after) = rel.strip_prefix(&format!("{def_bkt}/")) {
                return Ok((Some(def_bkt.clone()), after.to_string()));
            }
            if rel == def_bkt {
                return Ok((Some(def_bkt.clone()), String::new()));
            }
            return Ok((Some(def_bkt.clone()), rel.to_string()));
        }
        match rel.split_once('/') {
            Some((bkt, rest)) => Ok((Some(bkt.to_string()), rest.to_string())),
            None => Ok((Some(rel.to_string()), String::new())),
        }
    }

    fn endpoint_for(&self, bucket: Option<&str>, key: &str) -> (String, String, String) {
        let scheme = if self.cfg.use_https { "https" } else { "http" };
        let default_port = if self.cfg.use_https { 443 } else { 80 };
        let raw_host = match (bucket, self.cfg.path_style) {
            (Some(bkt), false) => format!("{bkt}.{}", self.cfg.host),
            _ => self.cfg.host.clone(),
        };
        let authority_host = if raw_host.contains(':') && !raw_host.starts_with('[') {
            format!("[{raw_host}]")
        } else {
            raw_host
        };
        let host_header = if self.cfg.port == default_port {
            authority_host.clone()
        } else {
            format!("{authority_host}:{}", self.cfg.port)
        };

        let raw_path = match (bucket, self.cfg.path_style) {
            (None, _) => "/".to_string(),
            (Some(bkt), true) => {
                if key.is_empty() {
                    format!("/{bkt}")
                } else {
                    format!("/{bkt}/{key}")
                }
            }
            (Some(_), false) => {
                if key.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{key}")
                }
            }
        };
        let canonical_uri = s3_uri_encode_path(&raw_path);
        let base_url = format!("{scheme}://{}:{}{canonical_uri}", authority_host, self.cfg.port);
        (host_header, canonical_uri, base_url)
    }

    async fn send_signed(
        &self,
        method: Method,
        bucket: Option<&str>,
        key: &str,
        query_params: &[(String, String)],
        extra_headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<reqwest::Response, ProtoError> {
        let (host_header, canonical_uri, base_url) = self.endpoint_for(bucket, key);
        let qs = query_params
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    s3_query_encode(k)
                } else {
                    format!("{}={}", s3_query_encode(k), s3_query_encode(v))
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        let url = if qs.is_empty() {
            base_url
        } else {
            format!("{base_url}?{qs}")
        };

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let payload_sha256 = compute_digest_hex(DigestAlgorithm::Sha256, &body);

        let mut custom_headers: Vec<(String, String)> = Vec::new();
        if let Some(tok) = self.cfg.session_token.as_deref().filter(|t| !t.is_empty()) {
            custom_headers.push(("x-amz-security-token".to_string(), tok.as_str().to_string()));
        }
        for (hk, hv) in &self.cfg.extra_signed_headers {
            custom_headers.push((hk.clone(), hv.clone()));
        }
        for (hk, hv) in extra_headers {
            custom_headers.push((hk.clone(), hv.clone()));
        }

        let sig = sign_s3_request(&S3SignParams {
            method: method.as_str(),
            uri: &canonical_uri,
            query: &qs,
            host: &host_header,
            extra_headers: &custom_headers,
            payload_hash: &payload_sha256,
            epoch_seconds: now_secs,
            region: &self.region,
            access_key: &self.cfg.access_key_id,
            secret_access_key: self.cfg.secret_access_key.as_str(),
        });

        let mut req = self.client.request(method, url);
        for (hk, hv) in &sig.headers {
            req = req.header(hk, hv);
        }
        req = req.header("Authorization", sig.authorization);
        if !body.is_empty() {
            req = req.body(body);
        }

        req.send()
            .await
            .map_err(|e| ProtoError::Transport(format!("S3 HTTP request failed: {e}")))
    }

    async fn list_buckets(&self) -> Result<Vec<FileEntry>, ProtoError> {
        let resp = self
            .send_signed(Method::GET, None, "", &[], &[], Vec::new())
            .await?;
        let status = resp.status();
        let xml = resp
            .text()
            .await
            .map_err(|e| ProtoError::Transport(format!("Reading S3 bucket list failed: {e}")))?;
        if !status.is_success() {
            return Err(parse_s3_error_xml(status, &xml));
        }
        reject_xxe_declarations(&xml)?;
        let doc = roxmltree::Document::parse(&xml)
            .map_err(|e| ProtoError::Transport(format!("Malformed S3 bucket XML: {e}")))?;

        let mut entries = Vec::new();
        for bnode in doc
            .descendants()
            .filter(|n| n.is_element() && n.tag_name().name() == "Bucket")
        {
            let mut name = None;
            let mut mtime = 0i64;
            for child in bnode.children().filter(|c| c.is_element()) {
                match child.tag_name().name() {
                    "Name" => name = child.text().map(str::trim),
                    "CreationDate" => {
                        if let Some(ts) = child.text().and_then(parse_http_date) {
                            mtime = ts;
                        }
                    }
                    _ => {}
                }
            }
            if let Some(bname) = name.filter(|s| !s.is_empty()) {
                entries.push(FileEntry {
                    name: bname.to_string(),
                    size: 0,
                    is_dir: true,
                    is_symlink: false,
                    broken_link: false,
                    date: format_utc_timestamp(mtime),
                    mtime,
                    permissions: "drwxr-xr-x".to_string(),
                    owner: None,
                    group: None,
                });
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    /// Lists object versions and delete markers under `remote_path` via
    /// `GET /bucket?versions&prefix=...`.
    pub async fn list_versions(&self, remote_path: &str) -> Result<Vec<S3ObjectVersion>, ProtoError> {
        let (Some(bucket), prefix_raw) = self.split_bucket_and_key(remote_path)? else {
            return Err(ProtoError::Transport(
                "S3 version listing requires a bucket name.".to_string(),
            ));
        };
        let exact_match = !remote_path.ends_with('/') && !prefix_raw.is_empty();
        let mut versions = Vec::new();
        let mut key_marker: Option<String> = None;
        let mut ver_marker: Option<String> = None;
        let mut seen_markers: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();

        loop {
            let mut qp = vec![
                ("versions".to_string(), String::new()),
                ("prefix".to_string(), prefix_raw.clone()),
            ];
            if let Some(km) = &key_marker {
                qp.push(("key-marker".to_string(), km.clone()));
            }
            if let Some(vm) = &ver_marker {
                qp.push(("version-id-marker".to_string(), vm.clone()));
            }
            let resp = self
                .send_signed(Method::GET, Some(&bucket), "", &qp, &[], Vec::new())
                .await?;
            let status = resp.status();
            let xml = resp.text().await.map_err(|e| {
                ProtoError::Transport(format!("Reading S3 ListObjectVersions XML failed: {e}"))
            })?;
            if !status.is_success() {
                return Err(parse_s3_error_xml(status, &xml));
            }
            reject_xxe_declarations(&xml)?;
            let doc = roxmltree::Document::parse(&xml)
                .map_err(|e| ProtoError::Transport(format!("Malformed S3 versions XML: {e}")))?;

            for node in doc.descendants().filter(|n| n.is_element()) {
                let tag = node.tag_name().name();
                if tag != "Version" && tag != "DeleteMarker" {
                    continue;
                }
                let mut key = String::new();
                let mut version_id = String::new();
                let mut is_latest = false;
                let mut size = 0u64;
                let mut mtime = 0i64;
                for c in node.children().filter(|c| c.is_element()) {
                    match c.tag_name().name() {
                        "Key" => key = c.text().unwrap_or("").to_string(),
                        "VersionId" => version_id = c.text().unwrap_or("").to_string(),
                        "IsLatest" => {
                            is_latest = c
                                .text()
                                .map(|t| t.trim().eq_ignore_ascii_case("true"))
                                .unwrap_or(false)
                        }
                        "Size" => {
                            size = c
                                .text()
                                .and_then(|t| t.trim().parse().ok())
                                .unwrap_or(0)
                        }
                        "LastModified" => {
                            mtime = c.text().and_then(parse_http_date).unwrap_or(0);
                        }
                        _ => {}
                    }
                }
                if exact_match && key != prefix_raw {
                    continue;
                }
                versions.push(S3ObjectVersion {
                    key,
                    version_id,
                    is_latest,
                    is_delete_marker: tag == "DeleteMarker",
                    size,
                    mtime,
                });
            }

            let is_truncated = doc
                .descendants()
                .find(|n| n.is_element() && n.tag_name().name() == "IsTruncated")
                .and_then(|n| n.text())
                .map(|t| t.trim().eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !is_truncated {
                break;
            }
            let next_km = doc
                .descendants()
                .find(|n| n.is_element() && n.tag_name().name() == "NextKeyMarker")
                .and_then(|n| n.text())
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ProtoError::Transport(
                        "Truncated S3 ListObjectVersions response has no next key marker."
                            .to_string(),
                    )
                })?;
            let next_vm = doc
                .descendants()
                .find(|n| n.is_element() && n.tag_name().name() == "NextVersionIdMarker")
                .and_then(|n| n.text())
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ProtoError::Transport(
                        "Truncated S3 ListObjectVersions response has no next version ID marker."
                            .to_string(),
                    )
                })?;
            if !seen_markers.insert((next_km.clone(), next_vm.clone())) {
                return Err(ProtoError::Transport(
                    "Truncated S3 ListObjectVersions response repeated its pagination marker."
                        .to_string(),
                ));
            }
            key_marker = Some(next_km);
            ver_marker = Some(next_vm);
        }
        Ok(versions)
    }

    pub async fn stat_version(
        &self,
        remote_path: &str,
        version_id: &str,
    ) -> Result<Option<FileEntry>, ProtoError> {
        let (Some(bucket), key) = self.split_bucket_and_key(remote_path)? else {
            return Ok(None);
        };
        let qp = if version_id.is_empty() {
            Vec::new()
        } else {
            vec![("versionId".to_string(), version_id.to_string())]
        };
        let resp = self
            .send_signed(Method::HEAD, Some(&bucket), &key, &qp, &[], Vec::new())
            .await?;
        let is_delete_marker = resp
            .headers()
            .get("x-amz-delete-marker")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.eq_ignore_ascii_case("true"));
        if resp.status().as_u16() == 404 && (version_id.is_empty() || !is_delete_marker) {
            return Ok(None);
        }
        if !version_id.is_empty() && (is_delete_marker || resp.status().as_u16() == 405) {
            return Err(ProtoError::Transport(format!(
                "S3 version '{version_id}' of '{remote_path}' is a delete marker and cannot be downloaded."
            )));
        }
        if !resp.status().is_success() {
            return Err(ProtoError::Transport(format!(
                "S3 HEAD '{remote_path}' failed with HTTP {}.",
                resp.status()
            )));
        }
        let size = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let mtime = resp
            .headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_http_date)
            .unwrap_or(0);
        let is_dir = key.ends_with('/');
        let leaf = key
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(&bucket)
            .to_string();
        Ok(Some(FileEntry {
            name: leaf,
            size: if is_dir { 0 } else { size },
            is_dir,
            is_symlink: false,
            broken_link: false,
            date: format_utc_timestamp(mtime),
            mtime,
            permissions: if is_dir {
                "drwxr-xr-x".to_string()
            } else {
                "-rw-r--r--".to_string()
            },
            owner: None,
            group: None,
        }))
    }

    pub async fn remove_version(
        &self,
        remote_path: &str,
        version_id: &str,
    ) -> Result<(), ProtoError> {
        let (Some(bucket), key) = self.split_bucket_and_key(remote_path)? else {
            return Err(ProtoError::Transport(
                "S3 object deletion requires a bucket and key.".to_string(),
            ));
        };
        let qp = if version_id.is_empty() {
            Vec::new()
        } else {
            vec![("versionId".to_string(), version_id.to_string())]
        };
        let resp = self
            .send_signed(Method::DELETE, Some(&bucket), &key, &qp, &[], Vec::new())
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(parse_s3_error_xml(status, &body));
        }
        Ok(())
    }

    async fn abort_multipart(&self, bucket: &str, key: &str, upload_id: &str) {
        let qp = vec![("uploadId".to_string(), upload_id.to_string())];
        let _ = self
            .send_signed(Method::DELETE, Some(bucket), key, &qp, &[], Vec::new())
            .await;
    }

    async fn upload_multipart(
        &self,
        bucket: &str,
        key: &str,
        opts: &TransferRequest,
        source: &mut (dyn AsyncRead + Unpin + Send),
        total_size: Option<u64>,
        progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        let min_part = self.cfg.min_part_size.max(5 * 1024);
        let part_size = match total_size {
            Some(sz) if sz > min_part * 9_999 => sz.div_ceil(9_999),
            _ => min_part,
        };

        let store_id = format!("{bucket}/{key}");
        let mut checkpoint = match self.cfg.resume_store.get(&store_id).await {
            Some(existing)
                if total_size.is_none_or(|sz| existing.total_size == sz)
                    && existing.part_size == part_size =>
            {
                existing
            }
            Some(stale) => {
                self.abort_multipart(bucket, key, &stale.upload_id).await;
                self.cfg.resume_store.remove(&store_id).await;
                self.initiate_multipart(bucket, key, total_size.unwrap_or(0), part_size)
                    .await?
            }
            None => {
                self.initiate_multipart(bucket, key, total_size.unwrap_or(0), part_size)
                    .await?
            }
        };
        self.cfg
            .resume_store
            .upsert(store_id.clone(), checkpoint.clone())
            .await;

        let mut part_number = 1u32;
        let mut transferred = 0u64;
        let mut limiter = RateLimiter::new(opts.speed_kbytes_per_sec);
        let reported_total = total_size.unwrap_or(0);

        let upload_res: Result<(), ProtoError> = async {
            loop {
                let mut part_buf = Vec::with_capacity(part_size as usize);
                while (part_buf.len() as u64) < part_size {
                    let remain = (part_size as usize) - part_buf.len();
                    let mut tmp = vec![0u8; remain.min(64 * 1024)];
                    let n = source.read(&mut tmp).await.map_err(|e| {
                        ProtoError::Transport(format!("Reading S3 upload source failed: {e}"))
                    })?;
                    if n == 0 {
                        break;
                    }
                    part_buf.extend_from_slice(&tmp[..n]);
                }
                if part_buf.is_empty() && part_number > 1 {
                    break;
                }

                let chunk_len = part_buf.len();
                if checkpoint.completed_parts.contains_key(&part_number) {
                    // Already verified & uploaded on an earlier attempt!
                    transferred += chunk_len as u64;
                    if let Some(cb) = progress {
                        cb(transferred, reported_total);
                    }
                } else {
                    let qp = vec![
                        ("partNumber".to_string(), part_number.to_string()),
                        ("uploadId".to_string(), checkpoint.upload_id.clone()),
                    ];
                    let resp = self
                        .send_signed(Method::PUT, Some(bucket), key, &qp, &[], part_buf)
                        .await?;
                    let status = resp.status();
                    let etag = resp
                        .headers()
                        .get("etag")
                        .and_then(|v| v.to_str().ok())
                        .map(str::trim)
                        .unwrap_or("")
                        .to_string();
                    let body_txt = resp.text().await.unwrap_or_default();
                    if !status.is_success() || body_txt.contains("<Error>") {
                        return Err(parse_s3_error_xml(status, &body_txt));
                    }
                    if etag.is_empty() {
                        return Err(ProtoError::Transport(format!(
                            "S3 UploadPart {part_number} returned no ETag header."
                        )));
                    }
                    checkpoint.completed_parts.insert(part_number, etag);
                    self.cfg
                        .resume_store
                        .upsert(store_id.clone(), checkpoint.clone())
                        .await;

                    transferred += chunk_len as u64;
                    if let Some(cb) = progress {
                        cb(transferred, reported_total);
                    }
                    limiter.consume(chunk_len).await;
                }

                if (chunk_len as u64) < part_size {
                    break;
                }
                part_number += 1;
            }
            Ok(())
        }
        .await;

        if let Err(err) = upload_res {
            if self.cfg.abort_multipart_on_error {
                self.abort_multipart(bucket, key, &checkpoint.upload_id).await;
                self.cfg.resume_store.remove(&store_id).await;
            }
            return Err(err);
        }

        let mut complete_xml = String::from("<CompleteMultipartUpload>");
        for (pnum, etag) in &checkpoint.completed_parts {
            complete_xml.push_str(&format!(
                "<Part><PartNumber>{pnum}</PartNumber><ETag>{}</ETag></Part>",
                xml_escape(etag)
            ));
        }
        complete_xml.push_str("</CompleteMultipartUpload>");

        let qp = vec![("uploadId".to_string(), checkpoint.upload_id.clone())];
        let headers = vec![("content-type".to_string(), "application/xml".to_string())];
        let resp = self
            .send_signed(
                Method::POST,
                Some(bucket),
                key,
                &qp,
                &headers,
                complete_xml.into_bytes(),
            )
            .await?;
        let status = resp.status();
        let xml = resp.text().await.unwrap_or_default();
        if !status.is_success() || xml.contains("<Error>") {
            self.abort_multipart(bucket, key, &checkpoint.upload_id).await;
            self.cfg.resume_store.remove(&store_id).await;
            return Err(parse_s3_error_xml(status, &xml));
        }
        self.cfg.resume_store.remove(&store_id).await;
        Ok(transferred)
    }

    fn write_headers_vec(&self) -> Vec<(String, String)> {
        self.cfg
            .object_write_headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub async fn check_endpoint(&self) -> Result<(), ProtoError> {
        let resp = self
            .send_signed(Method::GET, None, "", &[], &[], Vec::new())
            .await?;
        let status = resp.status();
        let xml = resp.text().await.unwrap_or_default();
        if status.as_u16() == 403 {
            if reject_xxe_declarations(&xml).is_ok() {
                if let Ok(doc) = roxmltree::Document::parse(&xml) {
                    if let Some(code) = doc
                        .descendants()
                        .find(|n| n.is_element() && n.tag_name().name() == "Code")
                        .and_then(|n| n.text())
                        .map(str::trim)
                    {
                        if matches!(
                            code,
                            "SignatureDoesNotMatch"
                                | "InvalidAccessKeyId"
                                | "ExpiredToken"
                                | "InvalidToken"
                        ) {
                            return Err(parse_s3_error_xml(status, &xml));
                        }
                    }
                }
            }
            return Ok(());
        }
        if status.is_server_error() {
            return Err(parse_s3_error_xml(status, &xml));
        }
        Ok(())
    }

    async fn initiate_multipart(
        &self,
        bucket: &str,
        key: &str,
        total_size: u64,
        part_size: u64,
    ) -> Result<MultipartCheckpoint, ProtoError> {
        let qp = vec![("uploads".to_string(), String::new())];
        let write_hdrs = self.write_headers_vec();
        let resp = self
            .send_signed(Method::POST, Some(bucket), key, &qp, &write_hdrs, Vec::new())
            .await?;
        let status = resp.status();
        let xml = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(parse_s3_error_xml(status, &xml));
        }
        reject_xxe_declarations(&xml)?;
        let doc = roxmltree::Document::parse(&xml)
            .map_err(|e| ProtoError::Transport(format!("Malformed CreateMultipartUpload XML: {e}")))?;
        let upload_id = doc
            .descendants()
            .find(|n| n.is_element() && n.tag_name().name() == "UploadId")
            .and_then(|n| n.text())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ProtoError::Transport("CreateMultipartUpload XML missing UploadId.".to_string())
            })?
            .to_string();

        Ok(MultipartCheckpoint {
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id,
            total_size,
            part_size,
            completed_parts: BTreeMap::new(),
        })
    }
}

#[async_trait]
impl RemoteSession for S3Session {
    fn scheme(&self) -> ProtocolScheme {
        ProtocolScheme::S3
    }

    async fn pwd(&self) -> Result<String, ProtoError> {
        match &self.cfg.default_bucket {
            Some(b) => Ok(format!("/{b}")),
            None => Ok("/".to_string()),
        }
    }

    async fn stat(&self, remote_path: &str) -> Result<Option<FileEntry>, ProtoError> {
        let (Some(bucket), key) = self.split_bucket_and_key(remote_path)? else {
            return Ok(Some(FileEntry {
                name: "/".to_string(),
                size: 0,
                is_dir: true,
                is_symlink: false,
                broken_link: false,
                date: String::new(),
                mtime: 0,
                permissions: "drwxr-xr-x".to_string(),
                owner: None,
                group: None,
            }));
        };
        if key.is_empty() {
            return Ok(Some(FileEntry {
                name: bucket,
                size: 0,
                is_dir: true,
                is_symlink: false,
                broken_link: false,
                date: String::new(),
                mtime: 0,
                permissions: "drwxr-xr-x".to_string(),
                owner: None,
                group: None,
            }));
        }
        if let Some(found) = self.stat_version(remote_path, "").await? {
            return Ok(Some(found));
        }
        // Check virtual folder prefix (`key/`)
        let prefix = format!("{}/", key.trim_end_matches('/'));
        let qp = vec![
            ("list-type".to_string(), "2".to_string()),
            ("max-keys".to_string(), "1".to_string()),
            ("prefix".to_string(), prefix),
        ];
        let resp = self
            .send_signed(Method::GET, Some(&bucket), "", &qp, &[], Vec::new())
            .await?;
        if resp.status().is_success() {
            let xml = resp.text().await.unwrap_or_default();
            if reject_xxe_declarations(&xml).is_ok() {
                if let Ok(doc) = roxmltree::Document::parse(&xml) {
                    let has_item = doc.descendants().any(|n| {
                        n.is_element()
                            && matches!(n.tag_name().name(), "Contents" | "CommonPrefixes")
                    });
                    if has_item {
                        let leaf = key.trim_end_matches('/').rsplit('/').next().unwrap_or(&key);
                        return Ok(Some(FileEntry {
                            name: leaf.to_string(),
                            size: 0,
                            is_dir: true,
                            is_symlink: false,
                            broken_link: false,
                            date: String::new(),
                            mtime: 0,
                            permissions: "drwxr-xr-x".to_string(),
                            owner: None,
                            group: None,
                        }));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn list_dir(&self, remote_path: &str) -> Result<Vec<FileEntry>, ProtoError> {
        let (Some(bucket), raw_key) = self.split_bucket_and_key(remote_path)? else {
            return self.list_buckets().await;
        };
        let prefix = if raw_key.is_empty() {
            String::new()
        } else {
            format!("{}/", raw_key.trim_end_matches('/'))
        };

        let mut by_name: BTreeMap<String, FileEntry> = BTreeMap::new();
        let mut continuation_token: Option<String> = None;

        loop {
            let mut qp = vec![
                ("delimiter".to_string(), "/".to_string()),
                ("list-type".to_string(), "2".to_string()),
                ("prefix".to_string(), prefix.clone()),
            ];
            if let Some(tok) = &continuation_token {
                qp.push(("continuation-token".to_string(), tok.clone()));
            }
            let resp = self
                .send_signed(Method::GET, Some(&bucket), "", &qp, &[], Vec::new())
                .await?;
            let status = resp.status();
            let xml = resp.text().await.map_err(|e| {
                ProtoError::Transport(format!("Reading S3 ListObjectsV2 XML failed: {e}"))
            })?;
            if !status.is_success() {
                return Err(parse_s3_error_xml(status, &xml));
            }
            reject_xxe_declarations(&xml)?;
            let doc = roxmltree::Document::parse(&xml)
                .map_err(|e| ProtoError::Transport(format!("Malformed S3 ListObjectsV2 XML: {e}")))?;

            for cp in doc
                .descendants()
                .filter(|n| n.is_element() && n.tag_name().name() == "CommonPrefixes")
            {
                if let Some(pstr) = cp
                    .children()
                    .find(|c| c.is_element() && c.tag_name().name() == "Prefix")
                    .and_then(|c| c.text())
                {
                    let rel = pstr.strip_prefix(&prefix).unwrap_or(pstr);
                    let dname = rel.trim_end_matches('/');
                    if !dname.is_empty() && !dname.contains('/') {
                        by_name.insert(
                            dname.to_string(),
                            FileEntry {
                                name: dname.to_string(),
                                size: 0,
                                is_dir: true,
                                is_symlink: false,
                                broken_link: false,
                                date: String::new(),
                                mtime: 0,
                                permissions: "drwxr-xr-x".to_string(),
                                owner: None,
                                group: None,
                            },
                        );
                    }
                }
            }

            for item in doc
                .descendants()
                .filter(|n| n.is_element() && n.tag_name().name() == "Contents")
            {
                let mut key = "";
                let mut size = 0u64;
                let mut mtime = 0i64;
                for c in item.children().filter(|c| c.is_element()) {
                    match c.tag_name().name() {
                        "Key" => key = c.text().unwrap_or(""),
                        "Size" => {
                            size = c
                                .text()
                                .and_then(|t| t.trim().parse().ok())
                                .unwrap_or(0)
                        }
                        "LastModified" => {
                            mtime = c.text().and_then(parse_http_date).unwrap_or(0);
                        }
                        _ => {}
                    }
                }
                if key == prefix {
                    continue;
                }
                let rel = key.strip_prefix(&prefix).unwrap_or(key);
                let is_marker = rel.ends_with('/');
                let clean = rel.trim_end_matches('/');
                if clean.is_empty() || clean.contains('/') {
                    continue;
                }
                by_name.entry(clean.to_string()).or_insert(FileEntry {
                    name: clean.to_string(),
                    size: if is_marker { 0 } else { size },
                    is_dir: is_marker,
                    is_symlink: false,
                    broken_link: false,
                    date: format_utc_timestamp(mtime),
                    mtime,
                    permissions: if is_marker {
                        "drwxr-xr-x".to_string()
                    } else {
                        "-rw-r--r--".to_string()
                    },
                    owner: None,
                    group: None,
                });
            }

            let is_truncated = doc
                .descendants()
                .find(|n| n.is_element() && n.tag_name().name() == "IsTruncated")
                .and_then(|n| n.text())
                .map(|t| t.trim().eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            if !is_truncated {
                break;
            }
            let next_tok = doc
                .descendants()
                .find(|n| n.is_element() && n.tag_name().name() == "NextContinuationToken")
                .and_then(|n| n.text())
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    ProtoError::Transport(
                        "Truncated S3 ListObjectsV2 response has no continuation token."
                            .to_string(),
                    )
                })?;
            if continuation_token.as_deref() == Some(next_tok.as_str()) {
                return Err(ProtoError::Transport(
                    "Truncated S3 ListObjectsV2 response repeated a continuation token."
                        .to_string(),
                ));
            }
            continuation_token = Some(next_tok);
        }
        Ok(by_name.into_values().collect())
    }

    async fn mkdir(&self, remote_path: &str) -> Result<(), ProtoError> {
        let (Some(bucket), raw_key) = self.split_bucket_and_key(remote_path)? else {
            return Err(ProtoError::Transport(
                "S3 mkdir requires a bucket name.".to_string(),
            ));
        };
        if raw_key.is_empty() {
            // Check whether bucket already exists via HEAD /bucket
            let head = self
                .send_signed(Method::HEAD, Some(&bucket), "", &[], &[], Vec::new())
                .await?;
            if head.status().is_success() {
                return Err(ProtoError::Transport(format!(
                    "Cannot create the directory '/{bucket}': that name already exists."
                )));
            }
            // CreateBucket (`PUT /bucket`)
            let resp = self
                .send_signed(Method::PUT, Some(&bucket), "", &[], &[], Vec::new())
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(parse_s3_error_xml(status, &body));
            }
            return Ok(());
        }
        if self.stat(remote_path).await?.is_some() {
            return Err(ProtoError::Transport(format!(
                "Cannot create the directory '{remote_path}': that name already exists."
            )));
        }
        let marker = format!("{}/", raw_key.trim_end_matches('/'));
        let resp = self
            .send_signed(Method::PUT, Some(&bucket), &marker, &[], &[], Vec::new())
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(parse_s3_error_xml(status, &body));
        }
        Ok(())
    }

    async fn remove_file(&self, remote_path: &str) -> Result<(), ProtoError> {
        self.remove_version(remote_path, "").await
    }

    async fn remove_dir(&self, remote_path: &str) -> Result<(), ProtoError> {
        let (Some(bucket), raw_key) = self.split_bucket_and_key(remote_path)? else {
            return Err(ProtoError::Transport(
                "Cannot remove S3 root.".to_string(),
            ));
        };
        if raw_key.is_empty() {
            return Err(ProtoError::Transport(
                "The bucket itself cannot be removed with rmdir; use 'rm -r' on its contents (or the S3 console).".to_string(),
            ));
        }
        let children = self.list_dir(remote_path).await?;
        if !children.is_empty() {
            return Err(ProtoError::Transport(format!(
                "S3 directory '{remote_path}' is not empty."
            )));
        }
        let key = format!("{}/", raw_key.trim_end_matches('/'));
        let resp = self
            .send_signed(Method::DELETE, Some(&bucket), &key, &[], &[], Vec::new())
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(parse_s3_error_xml(status, &body));
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        self.copy_file(from, to).await?;
        self.remove_file(from).await
    }

    async fn copy_file(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        let (Some(src_bucket), src_key) = self.split_bucket_and_key(from)? else {
            return Err(ProtoError::Transport(
                "S3 copy source requires bucket and key.".to_string(),
            ));
        };
        let (Some(dst_bucket), dst_key) = self.split_bucket_and_key(to)? else {
            return Err(ProtoError::Transport(
                "S3 copy destination requires bucket and key.".to_string(),
            ));
        };
        let copy_source = s3_uri_encode_path(&format!("/{src_bucket}/{src_key}"));

        // Objects exceeding `multipart_threshold` (except `.filepart` stage renames)
        // copy via Multipart `UploadPartCopy` (`x-amz-copy-source-range`).
        if !from.ends_with(".filepart") {
            if let Ok(Some(src_info)) = self.stat_version(from, "").await {
                if src_info.size > self.cfg.multipart_threshold {
                    let min_part = self.cfg.min_part_size.max(5 * 1024);
                    let part_size = if src_info.size > min_part * 9_999 {
                        src_info.size.div_ceil(9_999)
                    } else {
                        min_part
                    };
                    let cp = self
                        .initiate_multipart(&dst_bucket, &dst_key, src_info.size, part_size)
                        .await?;
                    let mut parts_etags: Vec<(u32, String)> = Vec::new();
                    let mut offset = 0u64;
                    let mut part_num = 1u32;
                    let copy_res: Result<(), ProtoError> = async {
                        while offset < src_info.size {
                            let end = (offset + part_size).min(src_info.size) - 1;
                            let qp = vec![
                                ("partNumber".to_string(), part_num.to_string()),
                                ("uploadId".to_string(), cp.upload_id.clone()),
                            ];
                            let hdrs = vec![
                                ("x-amz-copy-source".to_string(), copy_source.clone()),
                                (
                                    "x-amz-copy-source-range".to_string(),
                                    format!("bytes={offset}-{end}"),
                                ),
                            ];
                            let resp = self
                                .send_signed(
                                    Method::PUT,
                                    Some(&dst_bucket),
                                    &dst_key,
                                    &qp,
                                    &hdrs,
                                    Vec::new(),
                                )
                                .await?;
                            let st = resp.status();
                            let xml = resp.text().await.unwrap_or_default();
                            if !st.is_success() || xml.contains("<Error>") {
                                return Err(parse_s3_error_xml(st, &xml));
                            }
                            reject_xxe_declarations(&xml)?;
                            let doc = roxmltree::Document::parse(&xml).map_err(|e| {
                                ProtoError::Transport(format!("Malformed UploadPartCopy XML: {e}"))
                            })?;
                            let etag = doc
                                .descendants()
                                .find(|n| n.is_element() && n.tag_name().name() == "ETag")
                                .and_then(|n| n.text())
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .ok_or_else(|| {
                                    ProtoError::Transport(
                                        "UploadPartCopy XML missing ETag.".to_string(),
                                    )
                                })?
                                .to_string();
                            parts_etags.push((part_num, etag));
                            offset = end + 1;
                            part_num += 1;
                        }
                        Ok(())
                    }
                    .await;
                    if let Err(err) = copy_res {
                        self.abort_multipart(&dst_bucket, &dst_key, &cp.upload_id)
                            .await;
                        return Err(err);
                    }
                    let mut complete_xml = String::from("<CompleteMultipartUpload>");
                    for (pn, etag) in &parts_etags {
                        complete_xml.push_str(&format!(
                            "<Part><PartNumber>{pn}</PartNumber><ETag>{}</ETag></Part>",
                            xml_escape(etag)
                        ));
                    }
                    complete_xml.push_str("</CompleteMultipartUpload>");
                    let qp = vec![("uploadId".to_string(), cp.upload_id.clone())];
                    let hdrs = vec![("content-type".to_string(), "application/xml".to_string())];
                    let resp = self
                        .send_signed(
                            Method::POST,
                            Some(&dst_bucket),
                            &dst_key,
                            &qp,
                            &hdrs,
                            complete_xml.into_bytes(),
                        )
                        .await?;
                    let st = resp.status();
                    let xml = resp.text().await.unwrap_or_default();
                    if !st.is_success() || xml.contains("<Error>") {
                        self.abort_multipart(&dst_bucket, &dst_key, &cp.upload_id)
                            .await;
                        return Err(parse_s3_error_xml(st, &xml));
                    }
                    return Ok(());
                }
            }
        }

        let mut headers = self.write_headers_vec();
        headers.push(("x-amz-copy-source".to_string(), copy_source));
        let resp = self
            .send_signed(
                Method::PUT,
                Some(&dst_bucket),
                &dst_key,
                &[],
                &headers,
                Vec::new(),
            )
            .await?;
        let status = resp.status();
        let xml = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(parse_s3_error_xml(status, &xml));
        }
        if xml.contains("<Error>") {
            return Err(parse_s3_error_xml(status, &xml));
        }
        Ok(())
    }

    async fn symlink(&self, _target: &str, _link_path: &str) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("symlink", ProtocolScheme::S3))
    }

    async fn chmod(&self, _remote_path: &str, _mode: u32) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("chmod", ProtocolScheme::S3))
    }

    async fn set_mtime(&self, _remote_path: &str, _mtime: i64) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("set_mtime", ProtocolScheme::S3))
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
        let (Some(bucket), key) = self.split_bucket_and_key(remote_path)? else {
            return Err(ProtoError::Transport(
                "S3 download requires a bucket and object key.".to_string(),
            ));
        };
        let mut qp = Vec::new();
        if let Some(vid) = opts.version_id.as_deref().filter(|v| !v.is_empty()) {
            qp.push(("versionId".to_string(), vid.to_string()));
        }
        let mut headers = Vec::new();
        if opts.resume_offset > 0 {
            headers.push(("range".to_string(), format!("bytes={}-", opts.resume_offset)));
        }

        let mut resp = self
            .send_signed(Method::GET, Some(&bucket), &key, &qp, &headers, Vec::new())
            .await?;
        let status = resp.status();
        let is_delete_marker = resp
            .headers()
            .get("x-amz-delete-marker")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.eq_ignore_ascii_case("true"));
        if is_delete_marker || status.as_u16() == 405 {
            return Err(ProtoError::Transport(format!(
                "S3 object '{remote_path}' is a delete marker and cannot be downloaded."
            )));
        }
        if opts.resume_offset > 0 && status.as_u16() != 206 {
            let body = resp.text().await.unwrap_or_default();
            return Err(parse_s3_error_xml(status, &body));
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(parse_s3_error_xml(status, &body));
        }

        let content_len = resp.content_length().unwrap_or(0);
        let total = opts.resume_offset + content_len;
        let mut transferred = 0u64;
        let mut limiter = RateLimiter::new(opts.speed_kbytes_per_sec);

        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| ProtoError::Transport(format!("S3 download stream error: {e}")))?
        {
            sink.write_all(&chunk)
                .await
                .map_err(|e| ProtoError::Transport(format!("S3 sink write failed: {e}")))?;
            transferred += chunk.len() as u64;
            if let Some(cb) = progress {
                cb(opts.resume_offset + transferred, total);
            }
            if opts.speed_kbytes_per_sec > 0 {
                sink.flush()
                    .await
                    .map_err(|e| ProtoError::Transport(format!("S3 sink flush failed: {e}")))?;
            }
            limiter.consume(chunk.len()).await;
        }
        sink.flush()
            .await
            .map_err(|e| ProtoError::Transport(format!("S3 sink flush failed: {e}")))?;
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
        if opts.append {
            return Err(ProtoError::Transport(
                "S3 objects are immutable and do not support append.".to_string(),
            ));
        }
        let (Some(bucket), key) = self.split_bucket_and_key(remote_path)? else {
            return Err(ProtoError::Transport(
                "S3 upload requires a bucket and object key.".to_string(),
            ));
        };
        if key.is_empty() {
            return Err(ProtoError::Transport(
                "S3 upload object key must not be empty.".to_string(),
            ));
        }

        let use_multipart = match total_size {
            Some(sz) => sz > self.cfg.multipart_threshold,
            None => true,
        };
        if use_multipart {
            return self
                .upload_multipart(&bucket, &key, &opts, source, total_size, progress)
                .await;
        }

        let mut payload = Vec::with_capacity(total_size.unwrap_or(0) as usize);
        source
            .read_to_end(&mut payload)
            .await
            .map_err(|e| ProtoError::Transport(format!("Reading S3 upload source failed: {e}")))?;
        let total = payload.len() as u64;
        let write_hdrs = self.write_headers_vec();
        let resp = self
            .send_signed(Method::PUT, Some(&bucket), &key, &[], &write_hdrs, payload)
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(parse_s3_error_xml(status, &body));
        }
        if let Some(cb) = progress {
            cb(total, total);
        }
        Ok(total)
    }

    async fn upload_exclusive(
        &self,
        remote_path: &str,
        opts: TransferRequest,
        source: &mut (dyn AsyncRead + Unpin + Send),
        total_size: Option<u64>,
        progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        // Single PUT with If-None-Match is atomic. Multipart conditional
        // completion is not implemented here; fail closed rather than overwrite.
        const MAX_EXCLUSIVE_BYTES: u64 = 16 * 1024 * 1024;
        let Some(expected) = total_size else { return Err(ProtoError::UnsupportedCapability("exclusive upload without known size", self.scheme())); };
        if opts.append || opts.resume_offset != 0 || expected > MAX_EXCLUSIVE_BYTES {
            return Err(ProtoError::UnsupportedCapability("exclusive multipart, resume or append", self.scheme()));
        }
        let (Some(bucket), key) = self.split_bucket_and_key(remote_path)? else {
            return Err(ProtoError::Transport("S3 upload requires a bucket and object key.".to_string()));
        };
        if key.is_empty() { return Err(ProtoError::Transport("S3 object key must not be empty.".to_string())); }
        let mut payload = Vec::with_capacity(expected as usize);
        source.take(expected + 1).read_to_end(&mut payload).await
            .map_err(|e| ProtoError::Transport(format!("Reading S3 upload source failed: {e}")))?;
        if payload.len() as u64 != expected {
            return Err(ProtoError::Transport("S3 upload source size changed during transfer.".to_string()));
        }
        let mut headers = self.write_headers_vec();
        headers.push(("if-none-match".to_string(), "*".to_string()));
        let response = self.send_signed(Method::PUT, Some(&bucket), &key, &[], &headers, payload).await?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(parse_s3_error_xml(status, &body));
        }
        if let Some(callback) = progress { callback(expected, expected); }
        Ok(expected)
    }

    async fn probe_endpoint(&self, _initial_dir: &str) -> Result<(), ProtoError> {
        self.check_endpoint().await
    }

    async fn s3_list_versions(&self, remote_path: &str) -> Result<Vec<S3ObjectVersion>, ProtoError> {
        self.list_versions(remote_path).await
    }

    async fn s3_stat_version(
        &self,
        remote_path: &str,
        version_id: &str,
    ) -> Result<Option<FileEntry>, ProtoError> {
        self.stat_version(remote_path, version_id).await
    }

    async fn s3_remove_version(
        &self,
        remote_path: &str,
        version_id: &str,
    ) -> Result<(), ProtoError> {
        self.remove_version(remote_path, version_id).await
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
