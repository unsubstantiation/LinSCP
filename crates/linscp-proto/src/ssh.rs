//! Pure-Rust SSH-2 client transport built on `russh` (`ring` crypto provider):
//! - Fail-closed SHA-256 and MD5 host-key verification (`destination` & `tunnel`)
//! - Password, public-key (OpenSSH PEM, PKCS#8, and PuTTY `.ppk` v2/v3 via
//!   `linscp-crypto`), SSH Agent (`AgentClient` over platform/duplex streams),
//!   keyboard-interactive, and optional `gssapi-with-mic` authentication
//! - Exec channels, SFTP subsystem channels, and `direct-tcpip` jump channels

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD as BASE64_STD, STANDARD_NO_PAD as BASE64_NO_PAD};
use base64::Engine as _;
use linscp_platform::AsyncStream;
use md5::Md5;
use russh::client::{self, AuthResult, Handle, KeyboardInteractiveAuthResponse};
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::ssh_encoding::Encode;
use russh::keys::{decode_secret_key, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate};
pub use russh::ChannelMsg;
use russh::{Channel, ChannelStream, Disconnect, MethodKind};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::gssapi::{ensure_gssapi_available, GssapiTokenProvider};
use crate::proxy::{connect_stream_maybe_proxied, ProxyConfig};
use crate::{evaluate_host_key_extended, ProtoError};

const DEFAULT_SSH_TIMEOUT_SECS: u64 = 20;

/// Produces an async stream connected to an SSH agent (e.g. OS `SSH_AUTH_SOCK`
/// / Windows named pipe via `SystemSshAgentConnector`, or an in-memory duplex
/// stream in integration tests).
#[async_trait]
pub trait SshAgentConnector: Send + Sync {
    async fn connect(&self) -> Result<Option<Box<dyn AsyncStream>>, ProtoError>;
}

/// Default OS SSH agent connector delegating to `linscp_platform::connect_system_ssh_agent`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemSshAgentConnector;

#[async_trait]
impl SshAgentConnector for SystemSshAgentConnector {
    async fn connect(&self) -> Result<Option<Box<dyn AsyncStream>>, ProtoError> {
        linscp_platform::connect_system_ssh_agent()
            .await
            .map_err(|e| ProtoError::Transport(format!("SSH agent connection failed: {e}")))
    }
}

/// Interactive responder for RFC 4256 `keyboard-interactive` prompts.
#[async_trait]
pub trait KeyboardInteractiveResponder: Send + Sync {
    async fn respond(
        &self,
        name: &str,
        instructions: &str,
        prompts: &[(String, bool)],
    ) -> Result<Vec<String>, ProtoError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedServerHostKey {
    pub role: String,
    pub host: String,
    pub port: u16,
    pub key_type: String,
    pub sha256_fingerprint: String,
    pub md5_fingerprint: String,
    pub pubkey_base64: String,
}

pub type HostKeyDecisionCallback =
    Arc<dyn Fn(&ObservedServerHostKey) -> Result<(), ProtoError> + Send + Sync>;
pub type SshEventLogger = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Clone)]
pub struct SshConnectConfig {
    pub tab_id: u64,
    /// `"destination"` or `"tunnel"`.
    pub role: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<Zeroizing<String>>,
    /// Raw PEM / OpenSSH / `.ppk` key text (takes precedence over `private_key_path`).
    pub private_key_pem: Option<Zeroizing<String>>,
    /// Filesystem path to an OpenSSH / PEM / `.ppk` private key file.
    pub private_key_path: Option<String>,
    pub key_passphrase: Option<Zeroizing<String>>,
    /// Explicit `-hostkey` pin (`SHA256:...`, `MD5:...`, or `<alg> [bits] <fp>`).
    pub pinned_host_key: Option<String>,
    /// Existing cached `sshhostkeys` fingerprint for `(host, port, key_type)`.
    pub known_host_key: Option<String>,
    /// Explicit CLI `-hostkey=*` override (never cached, keeps `evaluate_host_key` fail-closed).
    pub danger_accept_any_host_key: bool,
    /// Optional custom host-key verifier invoked during `check_server_key` before userauth.
    pub host_key_decision: Option<HostKeyDecisionCallback>,
    pub try_agent: bool,
    pub agent_connector: Option<Arc<dyn SshAgentConnector>>,
    pub keyboard_interactive: Option<Arc<dyn KeyboardInteractiveResponder>>,
    /// Attempt `gssapi-with-mic` opportunistically when the server advertises it (`AuthGSSAPI=1`).
    pub try_gssapi: bool,
    pub request_gssapi: bool,
    pub request_gssapi_kex: bool,
    pub gssapi_provider: Option<Arc<tokio::sync::Mutex<Box<dyn GssapiTokenProvider>>>>,
    pub event_logger: Option<SshEventLogger>,
    pub proxy: Option<ProxyConfig>,
    pub connect_timeout: Duration,
}

impl Default for SshConnectConfig {
    fn default() -> Self {
        Self {
            tab_id: 0,
            role: "destination".to_string(),
            host: String::new(),
            port: 22,
            username: String::new(),
            password: None,
            private_key_pem: None,
            private_key_path: None,
            key_passphrase: None,
            pinned_host_key: None,
            known_host_key: None,
            danger_accept_any_host_key: false,
            host_key_decision: None,
            try_agent: false,
            agent_connector: None,
            keyboard_interactive: None,
            try_gssapi: false,
            request_gssapi: false,
            request_gssapi_kex: false,
            gssapi_provider: None,
            event_logger: None,
            proxy: None,
            connect_timeout: Duration::from_secs(DEFAULT_SSH_TIMEOUT_SECS),
        }
    }
}

/// Computes `(key_type, sha256_fingerprint, md5_fingerprint, pubkey_base64)` from
/// the RFC 4253 SSH wire encoding of `public_key`.
pub fn compute_ssh_key_details(
    public_key: &PublicKey,
) -> Result<(String, String, String, String), ProtoError> {
    let mut wire_blob = Vec::new();
    public_key
        .key_data()
        .encode(&mut wire_blob)
        .map_err(|e| ProtoError::Transport(format!("Failed to encode SSH server key: {e}")))?;

    let sha256_b64 = BASE64_NO_PAD.encode(Sha256::digest(&wire_blob));
    let sha256_fp = format!("SHA256:{sha256_b64}");

    let md5_bytes = Md5::digest(&wire_blob);
    let md5_hex = md5_bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let md5_fp = format!("MD5:{md5_hex}");
    let pubkey_b64 = BASE64_STD.encode(&wire_blob);

    Ok((
        public_key.algorithm().as_str().to_string(),
        sha256_fp,
        md5_fp,
        pubkey_b64,
    ))
}

/// Computes `(key_type, sha256_fingerprint, md5_fingerprint)` directly from the
/// RFC 4253 SSH wire encoding of `public_key`.
pub fn compute_ssh_fingerprints(
    public_key: &PublicKey,
) -> Result<(String, String, String), ProtoError> {
    let (alg, sha256_fp, md5_fp, _) = compute_ssh_key_details(public_key)?;
    Ok((alg, sha256_fp, md5_fp))
}

/// Decodes an SSH private key from OpenSSH PEM, PKCS#8 PEM, or PuTTY `.ppk`
/// v2/v3 text (converting `.ppk` through `linscp_crypto::ppk`).
pub fn load_private_key_text(
    raw_key_text: &str,
    passphrase: Option<&str>,
) -> Result<PrivateKey, ProtoError> {
    let trimmed = raw_key_text.trim_start_matches('\u{feff}');
    if trimmed.trim_start().starts_with("PuTTY-User-Key-File-") {
        let openssh_pem =
            linscp_crypto::ppk::ppk_to_openssh_pem(trimmed, passphrase.unwrap_or(""), None)
                .map_err(|e| ProtoError::Transport(format!("Failed to load PPK private key: {e}")))?;
        return decode_secret_key(openssh_pem.as_str(), None)
            .map_err(|e| ProtoError::Transport(format!("Failed to decode converted PPK key: {e}")));
    }

    decode_secret_key(trimmed, passphrase)
        .map_err(|e| ProtoError::Transport(format!("Failed to decode SSH private key: {e}")))
}

/// Extracts an OpenSSH `authorized_keys` public-key line from an OpenSSH PEM,
/// PKCS#8 PEM, or PuTTY `.ppk` v2/v3 private key.
pub fn extract_openssh_public_key_line(
    raw_key_text: &str,
    passphrase: Option<&str>,
) -> Result<String, ProtoError> {
    let priv_key = load_private_key_text(raw_key_text, passphrase)?;
    priv_key
        .public_key()
        .to_openssh()
        .map_err(|e| ProtoError::Transport(format!("Failed to format OpenSSH public key: {e}")))
}

type ObservedSshFingerprint = Arc<Mutex<Option<(String, String)>>>;

struct SshClientHandler {
    tab_id: u64,
    role: String,
    host: String,
    port: u16,
    pinned_host_key: Option<String>,
    known_host_key: Option<String>,
    danger_accept_any_host_key: bool,
    host_key_decision: Option<HostKeyDecisionCallback>,
    rejection: Arc<Mutex<Option<ProtoError>>>,
    observed_fingerprint: ObservedSshFingerprint,
}

impl client::Handler for SshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let pubkey = server_public_key.public_key();
        let (key_type, sha256_fp, md5_fp, pubkey_b64) = match compute_ssh_key_details(&pubkey) {
            Ok(v) => v,
            Err(err) => {
                if let Ok(mut guard) = self.rejection.lock() {
                    *guard = Some(err);
                }
                return Ok(false);
            }
        };

        if let Ok(mut obs) = self.observed_fingerprint.lock() {
            *obs = Some((key_type.clone(), sha256_fp.clone()));
        }

        if let Some(ref cb) = self.host_key_decision {
            let info = ObservedServerHostKey {
                role: self.role.clone(),
                host: self.host.clone(),
                port: self.port,
                key_type,
                sha256_fingerprint: sha256_fp,
                md5_fingerprint: md5_fp,
                pubkey_base64: pubkey_b64,
            };
            match cb(&info) {
                Ok(()) => return Ok(true),
                Err(err) => {
                    if let Ok(mut guard) = self.rejection.lock() {
                        *guard = Some(err);
                    }
                    return Ok(false);
                }
            }
        }

        if self.danger_accept_any_host_key {
            return Ok(true);
        }

        match evaluate_host_key_extended(
            self.tab_id,
            &self.role,
            &self.host,
            self.port,
            self.pinned_host_key.as_deref(),
            self.known_host_key.as_deref(),
            &key_type,
            &sha256_fp,
            &md5_fp,
        ) {
            Ok(()) => Ok(true),
            Err(Ok(challenge)) => {
                if let Ok(mut guard) = self.rejection.lock() {
                    *guard = Some(ProtoError::HostKeyChallengeRequired {
                        role: challenge.role,
                        state: challenge.state,
                        host: challenge.host,
                        port: challenge.port,
                        fingerprint: challenge.fingerprint,
                    });
                }
                Ok(false)
            }
            Err(Err(policy_err)) => {
                if let Ok(mut guard) = self.rejection.lock() {
                    *guard = Some(policy_err);
                }
                Ok(false)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    pub exit_code: Option<u32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Authenticated pure-Rust SSH-2 session handle.
pub struct SshConnection {
    handle: tokio::sync::Mutex<Handle<SshClientHandler>>,
    observed_key_type: String,
    observed_fingerprint: String,
    timeout: Duration,
}

impl SshConnection {
    /// Connects over TCP (or configured client proxy) and authenticates.
    pub async fn connect(cfg: &SshConnectConfig) -> Result<Self, ProtoError> {
        if cfg.request_gssapi || cfg.request_gssapi_kex {
            ensure_gssapi_available(cfg.request_gssapi_kex)?;
        }
        let stream = connect_stream_maybe_proxied(
            &cfg.host,
            cfg.port,
            cfg.proxy.as_ref(),
            cfg.connect_timeout,
        )
        .await?;
        Self::connect_over_stream(cfg, stream).await
    }

    /// Runs the SSH handshake, fail-closed host-key verification, and user
    /// authentication over any pre-established async byte stream (e.g. a
    /// jump-host `direct-tcpip` channel stream!).
    pub async fn connect_over_stream<S>(
        cfg: &SshConnectConfig,
        stream: S,
    ) -> Result<Self, ProtoError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        if cfg.request_gssapi || cfg.request_gssapi_kex {
            ensure_gssapi_available(cfg.request_gssapi_kex)?;
        }
        if cfg.username.trim().is_empty() {
            return Err(ProtoError::Transport(
                "SSH username must not be empty.".to_string(),
            ));
        }
        // Fail closed immediately on weak host-key pins unless custom callback / explicit override
        if !cfg.danger_accept_any_host_key && cfg.host_key_decision.is_none() {
            if let Some(pin) = cfg.pinned_host_key.as_deref().map(str::trim) {
                let lower = pin.to_ascii_lowercase();
                if lower == "*" || lower == "acceptnew" || lower == "any" || lower == "none" {
                    return Err(ProtoError::WeakHostKeyPolicy(pin.to_string()));
                }
            }
        }

        let russh_cfg = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(120)),
            keepalive_interval: Some(Duration::from_secs(30)),
            ..Default::default()
        });

        let rejection: Arc<Mutex<Option<ProtoError>>> = Arc::new(Mutex::new(None));
        let observed: ObservedSshFingerprint = Arc::new(Mutex::new(None));

        let handler = SshClientHandler {
            tab_id: cfg.tab_id,
            role: cfg.role.clone(),
            host: cfg.host.clone(),
            port: cfg.port,
            pinned_host_key: cfg.pinned_host_key.clone(),
            known_host_key: cfg.known_host_key.clone(),
            danger_accept_any_host_key: cfg.danger_accept_any_host_key,
            host_key_decision: cfg.host_key_decision.clone(),
            rejection: Arc::clone(&rejection),
            observed_fingerprint: Arc::clone(&observed),
        };

        let mut handle = match client::connect_stream(russh_cfg, stream, handler).await {
            Ok(h) => h,
            Err(err) => {
                if let Ok(mut guard) = rejection.lock() {
                    if let Some(proto_err) = guard.take() {
                        return Err(proto_err);
                    }
                }
                return Err(ProtoError::Transport(format!(
                    "SSH handshake with {}:{} failed: {err}",
                    cfg.host, cfg.port
                )));
            }
        };

        Self::authenticate(&mut handle, cfg).await?;

        let (observed_key_type, observed_fingerprint) = observed
            .lock()
            .ok()
            .and_then(|mut g| g.take())
            .unwrap_or_default();

        Ok(Self {
            handle: tokio::sync::Mutex::new(handle),
            observed_key_type,
            observed_fingerprint,
            timeout: cfg.connect_timeout.max(Duration::from_secs(1)),
        })
    }

    async fn authenticate(
        handle: &mut Handle<SshClientHandler>,
        cfg: &SshConnectConfig,
    ) -> Result<(), ProtoError> {
        let mut last_error: Option<String> = None;

        // 0. Probe `none` userauth to discover advertised server methods (and allow `none` auth).
        let server_offers_gssapi = match handle.authenticate_none(&cfg.username).await {
            Ok(AuthResult::Success) => return Ok(()),
            Ok(AuthResult::Failure {
                remaining_methods, ..
            }) => remaining_methods.contains(&MethodKind::GssapiWithMic),
            Err(_) => false,
        };

        // 1. Optional GSSAPI (`gssapi-with-mic`) when explicitly requested or advertised with `try_gssapi`
        let attempt_gssapi = cfg.request_gssapi || (cfg.try_gssapi && server_offers_gssapi);
        if attempt_gssapi {
            #[cfg(feature = "gssapi")]
            {
                if let Some(provider_arc) = cfg.gssapi_provider.as_ref() {
                    if let Some(ref logger) = cfg.event_logger {
                        logger("Attempting GSSAPI authentication");
                    }
                    let mut guard = provider_arc.lock().await;
                    let oids = guard.mechanism_oids();
                    let mut adapter = crate::gssapi::russh_bridge::ProviderAdapter {
                        provider: guard.as_mut(),
                    };
                    match handle
                        .authenticate_gssapi_with_mic(&cfg.username, oids, &mut adapter)
                        .await
                    {
                        Ok(res) if res.success() => {
                            if let Some(ref logger) = cfg.event_logger {
                                logger("Authenticated with GSSAPI");
                            }
                            return Ok(());
                        }
                        Ok(_) => {
                            last_error =
                                Some("GSSAPI authentication rejected by server.".to_string());
                        }
                        Err(e) => {
                            last_error = Some(format!("GSSAPI authentication failed: {e}"));
                        }
                    }
                } else if cfg.request_gssapi {
                    return Err(ProtoError::Transport(
                        "GSSAPI authentication requested, but no GssapiTokenProvider was configured."
                            .to_string(),
                    ));
                } else if let Some(ref logger) = cfg.event_logger {
                    logger("The server offers GSSAPI, but this build's libssh cannot use it");
                }
            }
            #[cfg(not(feature = "gssapi"))]
            {
                if let Some(ref logger) = cfg.event_logger {
                    logger("The server offers GSSAPI, but this build's libssh cannot use it");
                }
            }
        }

        // 2. Explicit private key (PEM / OpenSSH / PPK)
        let key_material = if let Some(pem) = cfg.private_key_pem.as_deref() {
            Some(pem.as_str().to_string())
        } else if let Some(path) = cfg.private_key_path.as_deref().filter(|p| !p.is_empty()) {
            let text = tokio::fs::read_to_string(path).await.map_err(|e| {
                ProtoError::Transport(format!("Failed to read SSH private key '{path}': {e}"))
            })?;
            Some(text)
        } else {
            None
        };

        if let Some(raw_key) = key_material {
            let key_pair = load_private_key_text(
                &raw_key,
                cfg.key_passphrase.as_deref().map(String::as_str),
            )?;
            let rsa_hash = handle
                .best_supported_rsa_hash()
                .await
                .map_err(|e| ProtoError::Transport(format!("RSA hash negotiation failed: {e}")))?
                .flatten();
            let auth_res = handle
                .authenticate_publickey(
                    &cfg.username,
                    PrivateKeyWithHashAlg::new(Arc::new(key_pair), rsa_hash),
                )
                .await
                .map_err(|e| ProtoError::Transport(format!("Public-key auth error: {e}")))?;
            if auth_res.success() {
                return Ok(());
            }
            last_error = Some("Server rejected private key authentication.".to_string());
        }

        // 3. SSH Agent (`AgentClient` over platform or custom stream)
        if cfg.try_agent || cfg.agent_connector.is_some() {
            let connector: Arc<dyn SshAgentConnector> = cfg
                .agent_connector
                .clone()
                .unwrap_or_else(|| Arc::new(SystemSshAgentConnector));
            if let Some(agent_stream) = connector.connect().await? {
                let mut agent = AgentClient::connect(agent_stream);
                if let Ok(identities) = agent.request_identities().await {
                    let rsa_hash = handle
                        .best_supported_rsa_hash()
                        .await
                        .ok()
                        .flatten()
                        .flatten();
                    for identity in identities {
                        let accepted = match identity {
                            AgentIdentity::PublicKey { key, .. } => handle
                                .authenticate_publickey_with(
                                    &cfg.username,
                                    key,
                                    rsa_hash,
                                    &mut agent,
                                )
                                .await
                                .map(|r| r.success())
                                .unwrap_or(false),
                            AgentIdentity::Certificate { certificate, .. } => handle
                                .authenticate_certificate_with(
                                    &cfg.username,
                                    certificate,
                                    rsa_hash,
                                    &mut agent,
                                )
                                .await
                                .map(|r| r.success())
                                .unwrap_or(false),
                        };
                        if accepted {
                            return Ok(());
                        }
                    }
                    last_error = Some("SSH agent keys were rejected by server.".to_string());
                }
            }
        }

        // 4. Password authentication
        if let Some(password) = cfg.password.as_deref() {
            let auth_res = handle
                .authenticate_password(&cfg.username, password.as_str())
                .await
                .map_err(|e| ProtoError::Transport(format!("Password auth error: {e}")))?;
            if auth_res.success() {
                return Ok(());
            }
            last_error = Some("Server rejected password authentication.".to_string());
        }

        // 5. Keyboard-interactive authentication (responder or password fallback)
        if cfg.keyboard_interactive.is_some() || cfg.password.is_some() {
            if let Ok(mut step) = handle
                .authenticate_keyboard_interactive_start(&cfg.username, None::<String>)
                .await
            {
                for _round in 0..8 {
                    match step {
                        KeyboardInteractiveAuthResponse::Success => return Ok(()),
                        KeyboardInteractiveAuthResponse::Failure { .. } => {
                            last_error = Some(
                                "Server rejected keyboard-interactive authentication.".to_string(),
                            );
                            break;
                        }
                        KeyboardInteractiveAuthResponse::InfoRequest {
                            name,
                            instructions,
                            prompts,
                        } => {
                            let answers = if let Some(responder) = &cfg.keyboard_interactive {
                                let pairs: Vec<(String, bool)> = prompts
                                    .into_iter()
                                    .map(|p| (p.prompt, p.echo))
                                    .collect();
                                responder.respond(&name, &instructions, &pairs).await?
                            } else if prompts.is_empty() {
                                Vec::new()
                            } else if let Some(pw) = cfg.password.as_deref() {
                                vec![pw.as_str().to_string(); prompts.len()]
                            } else {
                                break;
                            };
                            step = handle
                                .authenticate_keyboard_interactive_respond(answers)
                                .await
                                .map_err(|e| {
                                    ProtoError::Transport(format!(
                                        "Keyboard-interactive response error: {e}"
                                    ))
                                })?;
                        }
                    }
                }
            }
        }

        Err(ProtoError::Transport(last_error.unwrap_or_else(|| {
            format!(
                "Authentication failed for {}@{}:{}.",
                cfg.username, cfg.host, cfg.port
            )
        })))
    }

    pub fn observed_key_type(&self) -> &str {
        &self.observed_key_type
    }

    pub fn observed_fingerprint(&self) -> &str {
        &self.observed_fingerprint
    }

    /// Opens a fresh SSH session channel.
    pub async fn open_session_channel(&self) -> Result<Channel<client::Msg>, ProtoError> {
        let guard = self.handle.lock().await;
        tokio::time::timeout(self.timeout, guard.channel_open_session())
            .await
            .map_err(|_| ProtoError::Transport("Timed out opening SSH session channel.".to_string()))?
            .map_err(|e| ProtoError::Transport(format!("Failed to open SSH session channel: {e}")))
    }

    /// Opens an SFTP subsystem channel and returns its bidirectional byte stream.
    pub async fn open_sftp_stream(&self) -> Result<ChannelStream<client::Msg>, ProtoError> {
        let channel = self.open_session_channel().await?;
        tokio::time::timeout(self.timeout, channel.request_subsystem(true, "sftp"))
            .await
            .map_err(|_| ProtoError::Transport("Timed out starting SFTP subsystem.".to_string()))?
            .map_err(|e| ProtoError::Transport(format!("Failed to start SFTP subsystem: {e}")))?;
        Ok(channel.into_stream())
    }

    /// Opens a `direct-tcpip` forwarded stream to `dest_host:dest_port` through
    /// this SSH connection (used by `SshJumpTunnel` and the SOCKS5 jump relay).
    pub async fn open_direct_tcpip_stream(
        &self,
        dest_host: &str,
        dest_port: u16,
    ) -> Result<ChannelStream<client::Msg>, ProtoError> {
        let guard = self.handle.lock().await;
        let channel = tokio::time::timeout(
            self.timeout,
            guard.channel_open_direct_tcpip(dest_host, u32::from(dest_port), "127.0.0.1", 0),
        )
        .await
        .map_err(|_| {
            ProtoError::Transport(format!(
                "SSH tunnel forwarding to {dest_host}:{dest_port} failed: timed out."
            ))
        })?
        .map_err(|e| {
            ProtoError::Transport(format!(
                "SSH tunnel forwarding to {dest_host}:{dest_port} failed: {e}"
            ))
        })?;
        Ok(channel.into_stream())
    }

    /// Executes a non-interactive remote command on an `exec` channel and
    /// collects stdout, stderr, and exit status.
    pub async fn exec_command(&self, command: &str) -> Result<ExecOutput, ProtoError> {
        let mut channel = self.open_session_channel().await?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| ProtoError::Transport(format!("SSH exec '{command}' failed: {e}")))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                ChannelMsg::ExtendedData { .. } => {}
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = Some(exit_status);
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(ExecOutput {
            exit_code,
            stdout,
            stderr,
        })
    }

    pub async fn open_pty_shell(
        &self,
        term: &str,
        cols: u32,
        rows: u32,
    ) -> Result<Channel<client::Msg>, ProtoError> {
        let channel = self.open_session_channel().await?;
        let eff_cols = if cols > 0 { cols } else { 80 };
        let eff_rows = if rows > 0 { rows } else { 24 };
        channel
            .request_pty(true, term, eff_cols, eff_rows, 0, 0, &[])
            .await
            .map_err(|e| ProtoError::Transport(format!("SSH PTY request failed: {e}")))?;
        channel
            .request_shell(true)
            .await
            .map_err(|e| ProtoError::Transport(format!("SSH shell request failed: {e}")))?;
        Ok(channel)
    }

    pub async fn disconnect(&self) -> Result<(), ProtoError> {
        let guard = self.handle.lock().await;
        if guard.is_closed() {
            return Ok(());
        }
        let res = guard
            .disconnect(Disconnect::ByApplication, "", "en")
            .await
            .map_err(|e| ProtoError::Transport(format!("SSH disconnect error: {e}")));
        for _ in 0..40 {
            if guard.is_closed() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519_V2_ENCRYPTED_PPK: &str = "\
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: aes256-cbc
Comment: ed25519-v2
Public-Lines: 1
AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk
Private-Lines: 1
Y9f+qSB5FZfq2THk/c3+YDp7WUUEInGl7poCWM0H3hZSKKSrhvXEZOFcav7qc/bk
Private-MAC: 1459a716b2ebdea871aa101e3a6fe0801798df2f
";

    #[test]
    fn load_private_key_text_decodes_encrypted_ppk_and_computes_fingerprints() {
        assert!(load_private_key_text(ED25519_V2_ENCRYPTED_PPK, Some("wrong")).is_err());
        let key =
            load_private_key_text(ED25519_V2_ENCRYPTED_PPK, Some("secret-ppk")).expect("load PPK");
        let (alg, sha256_fp, md5_fp) =
            compute_ssh_fingerprints(key.public_key()).expect("fingerprints");
        assert_eq!(alg, "ssh-ed25519");
        assert!(sha256_fp.starts_with("SHA256:"));
        assert!(md5_fp.starts_with("MD5:"));
    }
}
