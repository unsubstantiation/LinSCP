//! Pure-Rust async protocol engines and fail-closed host-key / TLS verification
//! shared across Linux, Windows, and Android:
//! - `ssh`, `sftp`, `tunnel`, `proxy`, `gssapi`: SSH-2, SFTP v3 (`copy-data` &
//!   `check-file-name`), jump-host `direct-tcpip` & SOCKS5h relay, and proxy dialer
//! - `scp`: native `scp -f`/`scp -t` wire transfer and POSIX shell engine
//! - `tls`, `webdav`, `s3`: custom `rustls` SPKI SHA-256 `PinnedPublicKey`
//!   verifier, WebDAV (`PROPFIND`/`MKCOL`/`LOCK`/`UNLOCK`/`PROPPATCH`), and
//!   AWS SigV4 S3 (resumable multipart upload + object versioning)
//! - `listing`, `ftp`: hardened `MLSD`/`MLST` + Unix/DOS/VMS `LIST` parser and
//!   async FTP / Explicit FTPS (`ftpes://`) / Implicit FTPS (`ftps://`) engine

use std::time::{Duration, Instant};

use async_trait::async_trait;
use linscp_types::{FileEntry, HostKeyChallenge, ProtocolScheme, SessionConfig};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

pub mod ftp;
pub mod gssapi;
pub mod listing;
pub mod proxy;
pub mod remote_desktop;
pub mod s3;
pub mod scp;
pub mod sftp;
pub mod ssh;
pub mod tls;
pub mod tunnel;
pub mod webdav;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("SSH host key policy rejects wildcard or unverified trust '{0}'")]
    WeakHostKeyPolicy(String),
    #[error("Host key verification required for {role} {host}:{port} ({state})")]
    HostKeyChallengeRequired {
        role: String,
        state: String,
        host: String,
        port: u16,
        fingerprint: String,
    },
    #[error("Operation '{0}' is not supported by protocol {1:?}")]
    UnsupportedCapability(&'static str, ProtocolScheme),
    #[error("{0}")]
    Transport(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolCapabilities {
    pub pty_shell: bool,
    pub remote_exec: bool,
    pub symlinks: bool,
    pub posix_permissions: bool,
    pub server_checksum: bool,
    pub object_versioning: bool,
    pub remote_desktop: bool,
}

pub const fn capabilities_for(scheme: ProtocolScheme) -> ProtocolCapabilities {
    match scheme {
        ProtocolScheme::Sftp | ProtocolScheme::Ssh => ProtocolCapabilities {
            pty_shell: true,
            remote_exec: true,
            symlinks: true,
            posix_permissions: true,
            server_checksum: true,
            object_versioning: false,
            remote_desktop: false,
        },
        ProtocolScheme::Scp => ProtocolCapabilities {
            pty_shell: true,
            remote_exec: true,
            symlinks: true,
            posix_permissions: true,
            server_checksum: true,
            object_versioning: false,
            remote_desktop: false,
        },
        ProtocolScheme::Ftp | ProtocolScheme::Ftps | ProtocolScheme::Ftpes => ProtocolCapabilities {
            pty_shell: false,
            remote_exec: false,
            symlinks: false,
            posix_permissions: true,
            server_checksum: true,
            object_versioning: false,
            remote_desktop: false,
        },
        ProtocolScheme::Dav
        | ProtocolScheme::Davs
        | ProtocolScheme::Webdav
        | ProtocolScheme::Webdavs => ProtocolCapabilities {
            pty_shell: false,
            remote_exec: false,
            symlinks: false,
            posix_permissions: false,
            server_checksum: false,
            object_versioning: false,
            remote_desktop: false,
        },
        ProtocolScheme::S3 => ProtocolCapabilities {
            pty_shell: false,
            remote_exec: false,
            symlinks: false,
            posix_permissions: false,
            server_checksum: true,
            object_versioning: true,
            remote_desktop: false,
        },
        ProtocolScheme::Local => ProtocolCapabilities {
            pty_shell: false,
            remote_exec: false,
            symlinks: true,
            posix_permissions: true,
            server_checksum: true,
            object_versioning: false,
            remote_desktop: false,
        },
        ProtocolScheme::Rdp
        | ProtocolScheme::Vnc
        | ProtocolScheme::Spice
        | ProtocolScheme::X2Go
        | ProtocolScheme::X11 => ProtocolCapabilities {
            pty_shell: false,
            remote_exec: false,
            symlinks: false,
            posix_permissions: false,
            server_checksum: false,
            object_versioning: false,
            remote_desktop: true,
        },
    }
}

fn matches_ssh_pin(
    pin_spec: &str,
    observed_key_type: &str,
    observed_sha256: &str,
    observed_md5: &str,
) -> bool {
    for candidate in pin_spec.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let tokens: Vec<&str> = candidate.split_whitespace().collect();
        let fp_tok = match tokens.as_slice() {
            [single] => *single,
            [alg, fp] => {
                if !observed_key_type.is_empty() && !alg.eq_ignore_ascii_case(observed_key_type) {
                    continue;
                }
                *fp
            }
            [alg, _bits, fp, ..] => {
                if !observed_key_type.is_empty() && !alg.eq_ignore_ascii_case(observed_key_type) {
                    continue;
                }
                *fp
            }
            [] => continue,
        };

        if fp_tok == observed_sha256 {
            return true;
        }
        if let Some(rest) = fp_tok
            .strip_prefix("SHA256:")
            .or_else(|| fp_tok.strip_prefix("sha256:"))
        {
            if observed_sha256
                .strip_prefix("SHA256:")
                .is_some_and(|obs| obs == rest.trim_end_matches('='))
            {
                return true;
            }
        }
        if !observed_md5.is_empty() {
            let norm_md5 = fp_tok
                .strip_prefix("MD5:")
                .or_else(|| fp_tok.strip_prefix("md5:"))
                .unwrap_or(fp_tok);
            if observed_md5
                .strip_prefix("MD5:")
                .is_some_and(|obs| obs.eq_ignore_ascii_case(norm_md5))
            {
                return true;
            }
        }
    }
    false
}

/// Evaluates an observed server host-key fingerprint against a pinned policy
/// (`-hostkey` or `known_hosts` entry). Wildcard `"*"` and `"acceptnew"` are
/// unconditionally rejected so connections always fail closed.
pub fn evaluate_host_key(
    tab_id: u64,
    role: &str,
    host: &str,
    port: u16,
    pinned: Option<&str>,
    known_hosts_match: Option<&str>,
    observed_fingerprint: &str,
) -> Result<(), Result<HostKeyChallenge, ProtoError>> {
    evaluate_host_key_extended(
        tab_id,
        role,
        host,
        port,
        pinned,
        known_hosts_match,
        "",
        observed_fingerprint,
        "",
    )
}

/// Extended SSH host-key evaluator supporting SHA-256, legacy MD5, and
/// `<algorithm> [bits] <fingerprint>` pins while preserving fail-closed rules.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_host_key_extended(
    tab_id: u64,
    role: &str,
    host: &str,
    port: u16,
    pinned: Option<&str>,
    known_hosts_match: Option<&str>,
    observed_key_type: &str,
    observed_sha256: &str,
    observed_md5: &str,
) -> Result<(), Result<HostKeyChallenge, ProtoError>> {
    if let Some(pin) = pinned.map(str::trim).filter(|s| !s.is_empty()) {
        let lower = pin.to_ascii_lowercase();
        if lower == "*" || lower == "acceptnew" || lower == "any" || lower == "none" {
            return Err(Err(ProtoError::WeakHostKeyPolicy(pin.to_string())));
        }
        if matches_ssh_pin(pin, observed_key_type, observed_sha256, observed_md5) {
            return Ok(());
        }
        return Err(Ok(HostKeyChallenge {
            tab_id,
            role: role.to_string(),
            state: "changed".to_string(),
            host: host.to_string(),
            port,
            fingerprint: observed_sha256.to_string(),
        }));
    }

    match known_hosts_match {
        Some(existing)
            if matches_ssh_pin(existing, observed_key_type, observed_sha256, observed_md5) =>
        {
            Ok(())
        }
        Some(_) => Err(Ok(HostKeyChallenge {
            tab_id,
            role: role.to_string(),
            state: "changed".to_string(),
            host: host.to_string(),
            port,
            fingerprint: observed_sha256.to_string(),
        })),
        None => Err(Ok(HostKeyChallenge {
            tab_id,
            role: role.to_string(),
            state: "unknown".to_string(),
            host: host.to_string(),
            port,
            fingerprint: observed_sha256.to_string(),
        })),
    }
}

/// Byte-transfer parameters shared across SFTP, SCP, FTP/FTPS, WebDAV, and S3.
#[derive(Debug, Clone, Default)]
pub struct TransferRequest {
    pub resume_offset: u64,
    pub append: bool,
    pub preserve_time: bool,
    pub mtime: Option<i64>,
    pub permissions: Option<u32>,
    /// Optional transfer speed cap in KiB/s (`0` = unlimited).
    pub speed_kbytes_per_sec: u32,
    /// Optional S3 object version identifier for versioned downloads.
    pub version_id: Option<String>,
}

pub type ProgressCallback = dyn Fn(u64, u64) + Send + Sync;

/// Shared async token-schedule rate limiter enforcing `-speed=<KiB/s>`.
pub struct RateLimiter {
    limit_kbytes_per_sec: u32,
    bytes_transferred: u64,
    started_at: Option<Instant>,
}

impl RateLimiter {
    pub const fn new(limit_kbytes_per_sec: u32) -> Self {
        Self {
            limit_kbytes_per_sec,
            bytes_transferred: 0,
            started_at: None,
        }
    }

    pub async fn consume(&mut self, bytes: usize) {
        if self.limit_kbytes_per_sec == 0 || bytes == 0 {
            return;
        }
        self.bytes_transferred += bytes as u64;
        let now = Instant::now();
        let Some(start) = self.started_at else {
            self.started_at = Some(now);
            return;
        };
        let target_ms =
            (self.bytes_transferred * 1000) / (u64::from(self.limit_kbytes_per_sec) * 1024);
        let elapsed_ms = now.duration_since(start).as_millis() as u64;
        if target_ms > elapsed_ms {
            tokio::time::sleep(Duration::from_millis(target_ms - elapsed_ms)).await;
        }
    }
}

/// Async remote filesystem & transfer session implemented by each pure-Rust
/// protocol engine (`sftp`, `scp`, `ftp`/`ftps`/`ftpes`, `webdav`, and `s3`).
#[async_trait]
pub trait RemoteSession: Send + Sync {
    fn scheme(&self) -> ProtocolScheme;
    async fn pwd(&self) -> Result<String, ProtoError>;
    async fn stat(&self, remote_path: &str) -> Result<Option<FileEntry>, ProtoError>;
    async fn list_dir(&self, remote_path: &str) -> Result<Vec<FileEntry>, ProtoError>;
    async fn mkdir(&self, remote_path: &str) -> Result<(), ProtoError>;
    async fn remove_file(&self, remote_path: &str) -> Result<(), ProtoError>;
    async fn remove_dir(&self, remote_path: &str) -> Result<(), ProtoError>;
    async fn rename(&self, from: &str, to: &str) -> Result<(), ProtoError>;
    async fn copy_file(&self, from: &str, to: &str) -> Result<(), ProtoError>;
    async fn symlink(&self, target: &str, link_path: &str) -> Result<(), ProtoError>;
    async fn chmod(&self, remote_path: &str, mode: u32) -> Result<(), ProtoError>;
    async fn set_mtime(&self, remote_path: &str, mtime: i64) -> Result<(), ProtoError>;
    async fn checksum(&self, algorithm: &str, remote_path: &str) -> Result<String, ProtoError>;
    async fn download(
        &self,
        remote_path: &str,
        opts: TransferRequest,
        sink: &mut (dyn AsyncWrite + Unpin + Send),
        progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError>;
    /// Read only the representation matching the supplied strong ETag.
    async fn download_if_match(
        &self, _remote_path: &str, _etag: &str, _opts: TransferRequest,
        _sink: &mut (dyn AsyncWrite + Unpin + Send), _progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        Err(ProtoError::UnsupportedCapability("conditional download", self.scheme()))
    }
    /// Compare a local prefix against an ETag-pinned remote representation.
    async fn verify_prefix_if_match(
        &self, _remote_path: &str, _etag: &str, _prefix_len: u64, _total_len: u64,
        _prefix: &mut (dyn AsyncRead + Unpin + Send),
    ) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("verified resume", self.scheme()))
    }
    /// Move a WebDAV file only if its source ETag matches and the target is absent.
    async fn dav_move_if_match(&self, _from: &str, _to: &str, _etag: &str, _is_dir: bool) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("conditional no-replace move", self.scheme()))
    }
    /// Remove only the representation matching the supplied strong ETag.
    async fn remove_if_match(&self, _remote_path: &str, _etag: &str) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("conditional delete", self.scheme()))
    }
    async fn upload(
        &self,
        remote_path: &str,
        opts: TransferRequest,
        source: &mut (dyn AsyncRead + Unpin + Send),
        total_size: Option<u64>,
        progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError>;
    /// FTP STOU uploads to a server-created unique temporary name.
    async fn upload_ftp_unique(
        &self, _directory: &str, _opts: TransferRequest,
        _source: &mut (dyn AsyncRead + Unpin + Send), _total_size: Option<u64>,
        _progress: Option<&ProgressCallback>,
    ) -> Result<(u64, String), ProtoError> {
        Err(ProtoError::UnsupportedCapability("FTP unique upload", self.scheme()))
    }
    /// Create a new destination atomically, failing if any entry already exists.
    /// Implementations must not silently fall back to an overwriting upload.
    async fn upload_exclusive(
        &self,
        _remote_path: &str,
        _opts: TransferRequest,
        _source: &mut (dyn AsyncRead + Unpin + Send),
        _total_size: Option<u64>,
        _progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        Err(ProtoError::UnsupportedCapability("exclusive upload", self.scheme()))
    }
    /// Replace only if the server atomically matches the supplied strong ETag.
    async fn upload_if_match(
        &self, _remote_path: &str, _etag: &str, _opts: TransferRequest,
        _source: &mut (dyn AsyncRead + Unpin + Send), _total_size: Option<u64>,
        _progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        Err(ProtoError::UnsupportedCapability("conditional overwrite", self.scheme()))
    }
    async fn probe_endpoint(&self, _initial_dir: &str) -> Result<(), ProtoError> {
        Ok(())
    }
    async fn realpath(&self, remote_path: &str) -> Result<String, ProtoError> {
        Ok(remote_path.to_string())
    }
    async fn readlink(&self, _link_path: &str) -> Result<String, ProtoError> {
        Err(ProtoError::UnsupportedCapability("readlink", self.scheme()))
    }
    async fn exec_command(&self, _command: &str) -> Result<ssh::ExecOutput, ProtoError> {
        Err(ProtoError::UnsupportedCapability("exec", self.scheme()))
    }
    async fn checksum_server_only(
        &self,
        _algorithm: &str,
        _remote_path: &str,
    ) -> Result<Option<String>, ProtoError> {
        Ok(None)
    }
    async fn dav_lock(&self, _remote_path: &str, _timeout_secs: u32) -> Result<String, ProtoError> {
        Err(ProtoError::UnsupportedCapability("dav_lock", self.scheme()))
    }
    async fn dav_unlock(&self, _remote_path: &str, _token: Option<&str>) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("dav_unlock", self.scheme()))
    }
    /// Return the current S3 object's ETag, or None if it does not exist.
    async fn s3_get_etag(&self, _remote_path: &str) -> Result<Option<String>, ProtoError> {
        Err(ProtoError::UnsupportedCapability("s3_etag", self.scheme()))
    }
    async fn dav_get_etag(&self, _remote_path: &str) -> Result<(Option<String>, bool), ProtoError> {
        Err(ProtoError::UnsupportedCapability("dav_etag", self.scheme()))
    }
    async fn dav_set_etag_precondition(
        &self,
        _remote_path: &str,
        _precondition: Option<webdav::DavEtagPrecondition>,
    ) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("dav_etag", self.scheme()))
    }
    async fn dav_set_property(
        &self,
        _remote_path: &str,
        _name: &str,
        _value: &str,
    ) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability(
            "dav_property",
            self.scheme(),
        ))
    }
    async fn dav_get_property(
        &self,
        _remote_path: &str,
        _name: &str,
    ) -> Result<Option<String>, ProtoError> {
        Err(ProtoError::UnsupportedCapability(
            "dav_property",
            self.scheme(),
        ))
    }
    async fn s3_list_versions(
        &self,
        _remote_path: &str,
    ) -> Result<Vec<s3::S3ObjectVersion>, ProtoError> {
        Err(ProtoError::UnsupportedCapability(
            "s3_versions",
            self.scheme(),
        ))
    }
    async fn s3_stat_version(
        &self,
        _remote_path: &str,
        _version_id: &str,
    ) -> Result<Option<FileEntry>, ProtoError> {
        Err(ProtoError::UnsupportedCapability(
            "s3_versions",
            self.scheme(),
        ))
    }
    async fn s3_remove_version(
        &self,
        _remote_path: &str,
        _version_id: &str,
    ) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability(
            "s3_versions",
            self.scheme(),
        ))
    }
    async fn close(&self) -> Result<(), ProtoError> {
        Ok(())
    }
    fn ssh_connection(&self) -> Option<&std::sync::Arc<ssh::SshConnection>> {
        None
    }
    fn observed_host_key(&self) -> Option<&str> {
        None
    }
}

/// Convenience helper downloading an entire remote file into memory.
pub async fn download_bytes(
    session: &dyn RemoteSession,
    remote_path: &str,
    opts: TransferRequest,
) -> Result<Vec<u8>, ProtoError> {
    let mut out = Vec::new();
    session.download(remote_path, opts, &mut out, None).await?;
    Ok(out)
}

/// Convenience helper uploading an in-memory byte slice to `remote_path`.
pub async fn upload_bytes(
    session: &dyn RemoteSession,
    remote_path: &str,
    data: &[u8],
    opts: TransferRequest,
) -> Result<u64, ProtoError> {
    let mut cursor = std::io::Cursor::new(data);
    session
        .upload(
            remote_path,
            opts,
            &mut cursor,
            Some(data.len() as u64),
            None,
        )
        .await
}

/// Connects any supported remote `SessionConfig` (including optional SSH jump
/// host tunneling across SFTP, SCP, FTP/FTPS, WebDAV, and S3).
pub async fn connect_session(
    tab_id: u64,
    session: &SessionConfig,
    known_dest_hostkey: Option<String>,
    known_tunnel_hostkey: Option<String>,
    tls: tls::TlsSettings,
    proxy: Option<proxy::ProxyConfig>,
) -> Result<Box<dyn RemoteSession>, ProtoError> {
    let port = if session.port == 0 {
        session.protocol.default_port()
    } else {
        session.port
    };

    let (tunnel_ssh_cfg, tunnel_local_port) = match session.tunnel.as_ref().filter(|t| t.enabled) {
        Some(t) => {
            let tport = if t.port == 0 { 22 } else { t.port };
            (
                Some(ssh::SshConnectConfig {
                    tab_id,
                    role: "tunnel".to_string(),
                    host: t.host.clone(),
                    port: tport,
                    username: t.username.clone(),
                    password: t.password.clone().map(Zeroizing::new),
                    private_key_path: t.keyfile.clone(),
                    pinned_host_key: if t.hostkey.is_empty() {
                        None
                    } else {
                        Some(t.hostkey.clone())
                    },
                    known_host_key: known_tunnel_hostkey,
                    try_agent: t.keyfile.is_none() && t.password.is_none(),
                    proxy: proxy.clone(),
                    ..Default::default()
                }),
                t.local_port,
            )
        }
        None => (None, 0),
    };

    match session.protocol {
        ProtocolScheme::Sftp => {
            let dest_cfg = ssh::SshConnectConfig {
                tab_id,
                role: "destination".to_string(),
                host: session.host.clone(),
                port,
                username: session.username.clone(),
                password: session.password.clone().map(Zeroizing::new),
                private_key_path: session.keyfile.clone(),
                pinned_host_key: if session.hostkey.is_empty() {
                    None
                } else {
                    Some(session.hostkey.clone())
                },
                known_host_key: known_dest_hostkey,
                try_agent: session.keyfile.is_none() && session.password.is_none(),
                proxy,
                ..Default::default()
            };
            let sftp = sftp::SftpClientSession::connect(
                session.protocol,
                &dest_cfg,
                tunnel_ssh_cfg.as_ref(),
                tunnel_local_port,
            )
            .await?;
            Ok(Box::new(sftp))
        }
        ProtocolScheme::Scp | ProtocolScheme::Ssh => {
            let dest_cfg = ssh::SshConnectConfig {
                tab_id,
                role: "destination".to_string(),
                host: session.host.clone(),
                port,
                username: session.username.clone(),
                password: session.password.clone().map(Zeroizing::new),
                private_key_path: session.keyfile.clone(),
                pinned_host_key: if session.hostkey.is_empty() {
                    None
                } else {
                    Some(session.hostkey.clone())
                },
                known_host_key: known_dest_hostkey,
                try_agent: session.keyfile.is_none() && session.password.is_none(),
                proxy,
                ..Default::default()
            };
            let scp = scp::ScpSession::connect(
                &dest_cfg,
                tunnel_ssh_cfg.as_ref(),
                tunnel_local_port,
            )
            .await?;
            Ok(Box::new(scp))
        }
        ProtocolScheme::Ftp | ProtocolScheme::Ftps | ProtocolScheme::Ftpes => {
            let ftp_cfg = ftp::FtpConnectConfig {
                scheme: session.protocol,
                host: session.host.clone(),
                port,
                username: if session.username.is_empty() {
                    "anonymous".to_string()
                } else {
                    session.username.clone()
                },
                password: session.password.clone().map(Zeroizing::new),
                tls,
                proxy,
                ..Default::default()
            };
            let client =
                ftp::FtpSession::connect(ftp_cfg, tunnel_ssh_cfg.as_ref(), tunnel_local_port)
                    .await?;
            Ok(Box::new(client))
        }
        ProtocolScheme::Dav
        | ProtocolScheme::Davs
        | ProtocolScheme::Webdav
        | ProtocolScheme::Webdavs => {
            let dav_cfg = webdav::WebDavConnectConfig {
                scheme: session.protocol,
                host: session.host.clone(),
                port,
                base_path: if session.initial_dir.is_empty() {
                    "/".to_string()
                } else {
                    session.initial_dir.clone()
                },
                username: if session.username.is_empty() {
                    None
                } else {
                    Some(session.username.clone())
                },
                password: session.password.clone().map(Zeroizing::new),
                tls,
                proxy,
                ..Default::default()
            };
            let client =
                webdav::WebDavSession::connect(dav_cfg, tunnel_ssh_cfg.as_ref(), tunnel_local_port)
                    .await?;
            Ok(Box::new(client))
        }
        ProtocolScheme::S3 => {
            let s3_cfg = s3::S3ConnectConfig {
                use_https: true,
                host: session.host.clone(),
                port,
                access_key_id: session.username.clone(),
                secret_access_key: Zeroizing::new(session.password.clone().unwrap_or_default()),
                default_bucket: session
                    .initial_dir
                    .trim_matches('/')
                    .split('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                tls,
                proxy,
                ..Default::default()
            };
            let client =
                s3::S3Session::connect(s3_cfg, tunnel_ssh_cfg.as_ref(), tunnel_local_port).await?;
            Ok(Box::new(client))
        }
        ProtocolScheme::Local => Err(ProtoError::UnsupportedCapability(
            "network_session",
            ProtocolScheme::Local,
        )),
        ProtocolScheme::Rdp
        | ProtocolScheme::Vnc
        | ProtocolScheme::Spice
        | ProtocolScheme::X2Go
        | ProtocolScheme::X11 => {
            let kind = remote_desktop::RemoteDesktopKind::from_scheme(session.protocol)
                .unwrap_or(remote_desktop::RemoteDesktopKind::Rdp);
            let cfg = remote_desktop::RemoteDesktopConnectConfig {
                scheme: session.protocol,
                kind,
                host: session.host.clone(),
                port,
                username: if session.username.is_empty() { None } else { Some(session.username.clone()) },
                password: session.password.clone().map(Zeroizing::new),
                domain: None,
                desktop_opts: remote_desktop::DesktopOptions::default(),
                tls: tls.clone(),
                proxy: proxy.clone(),
                timeout: Duration::from_secs(15),
            };
            let sess = remote_desktop::RemoteDesktopSession::connect(
                cfg,
                tunnel_ssh_cfg.as_ref(),
                tunnel_local_port,
            )
            .await?;
            Ok(Box::new(sess))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_policy_rejects_wildcard_and_acceptnew() {
        for forbidden in ["*", "acceptnew", "AcceptNew", "none"] {
            let outcome = evaluate_host_key(
                1,
                "destination",
                "example.com",
                22,
                Some(forbidden),
                None,
                "SHA256:abc",
            );
            assert_eq!(
                outcome,
                Err(Err(ProtoError::WeakHostKeyPolicy(forbidden.to_string())))
            );
        }
    }

    #[test]
    fn host_key_policy_distinguishes_tunnel_and_destination_challenges_and_md5() {
        let tunnel = evaluate_host_key(
            7,
            "tunnel",
            "bastion.example.com",
            2222,
            None,
            None,
            "SHA256:bastionKey",
        )
        .expect_err("untrusted bastion must challenge")
        .expect("challenge payload");
        assert_eq!(tunnel.role, "tunnel");
        assert_eq!(tunnel.state, "unknown");
        assert_eq!(tunnel.port, 2222);

        let mismatched = evaluate_host_key(
            7,
            "destination",
            "app.internal",
            22,
            Some("SHA256:old"),
            None,
            "SHA256:new",
        )
        .expect_err("changed host key must challenge")
        .expect("challenge payload");
        assert_eq!(mismatched.role, "destination");
        assert_eq!(mismatched.state, "changed");

        assert!(evaluate_host_key_extended(
            1,
            "destination",
            "legacy.internal",
            22,
            Some("ssh-ed25519 255 aa:bb:cc:dd"),
            None,
            "ssh-ed25519",
            "SHA256:modern",
            "MD5:AA:BB:CC:DD",
        )
        .is_ok());
    }
}
