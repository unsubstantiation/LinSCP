//! Pure-Rust async FTP (`ftp://`), Explicit FTPS (`ftpes://`: `AUTH TLS` +
//! `PBSZ 0` + `PROT P`), and Implicit FTPS (`ftps://`: TLS from connect +
//! `PBSZ 0` + `PROT P`) client (`FtpSession` implementing `RemoteSession`),
//! porting `FtpClient.{h,cpp}` with hardened `EPSV`/`PASV` parsing,
//! `FtpForcePasvIp`, active `PORT`/`EPRT` mode, `MLSD`/`MLST` + Unix/DOS/VMS
//! `LIST` fallback, custom `rustls` SPKI pinning on BOTH control and data
//! channels, and SOCKS5 jump-host tunneling.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use linscp_crypto::digests::{DigestAlgorithm, DigestHasher};
use linscp_types::{FileEntry, ProtocolScheme};
use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::listing::{
    civil_from_days, format_utc_timestamp, parse_ftp_compact_utc, parse_list_output,
    parse_mlsx_line,
};
use crate::proxy::{connect_tcp_maybe_proxied, ProxyConfig};
use crate::sftp::HasherAsyncSink;
use crate::ssh::SshConnectConfig;
use crate::tls::{build_rustls_client_config, TlsSettings};
use crate::tunnel::{Socks5JumpRelay, SshJumpTunnel};
use crate::{ProgressCallback, ProtoError, RateLimiter, RemoteSession, TransferRequest};

const FTP_CHUNK_SIZE: usize = 32 * 1024;
const MAX_FTP_LINE_BYTES: usize = 16 * 1024;

/// Strictly parses an unsigned decimal integer in `[low, high]` (1..=5 ASCII
/// digits, no sign or trailing garbage), matching `ParseFtpReplyNumber` in
/// `FtpClient.cpp`.
pub fn parse_ftp_reply_number(text: &str, low: u32, high: u32) -> Option<u32> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let val: u32 = text.parse().ok()?;
    if val < low || val > high {
        return None;
    }
    Some(val)
}

/// Parses an RFC 2428 `229 Entering Extended Passive Mode (|||<port>|)` reply.
pub fn parse_epsv_reply(reply_text: &str) -> Option<u16> {
    let open = reply_text.find('(')?;
    let close = reply_text[open + 1..].find(')')? + open + 1;
    let fields = &reply_text[open + 1..close];
    let bytes = fields.as_bytes();
    if bytes.len() < 5 {
        return None;
    }
    let delim = bytes[0];
    if delim <= b' ' || delim > b'~' || delim.is_ascii_digit() || delim == b'(' || delim == b')' {
        return None;
    }
    if bytes[1] != delim || bytes[2] != delim || bytes[bytes.len() - 1] != delim {
        return None;
    }
    let port_str = &fields[3..fields.len() - 1];
    let port = parse_ftp_reply_number(port_str, 1, 65535)?;
    Some(port as u16)
}

/// Parses a `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` reply with strict
/// octet (`0..=255`) and non-zero port checks.
pub fn parse_pasv_reply(reply_text: &str) -> Option<(String, u16)> {
    let open = reply_text.find('(')?;
    let close = reply_text[open + 1..].find(')')? + open + 1;
    let inside = &reply_text[open + 1..close];
    let parts: Vec<&str> = inside.split(',').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut nums = [0u32; 6];
    for (i, part) in parts.iter().enumerate() {
        nums[i] = parse_ftp_reply_number(part.trim(), 0, 255)?;
    }
    let port = nums[4] * 256 + nums[5];
    if port == 0 || port > 65535 {
        return None;
    }
    let addr = format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]);
    Some((addr, port as u16))
}

/// Returns `true` when a `PASV` IPv4 address is unroutable (`0.0.0.0/8`,
/// `10/8`, `127/8`, `169.254/16`, `172.16/12`, `192.168/16`, `100.64/10`),
/// matching `FtpClient::IsUnroutablePasvAddress` in `FtpClient.cpp`.
pub fn is_unroutable_pasv_address(address: &str) -> bool {
    let parts: Vec<&str> = address.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    let mut octets = [0u32; 4];
    for (i, part) in parts.iter().enumerate() {
        let Some(v) = parse_ftp_reply_number(part, 0, 255) else {
            return false;
        };
        octets[i] = v;
    }
    if octets[0] == 0 || octets[0] == 10 || octets[0] == 127 {
        return true;
    }
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }
    false
}

fn validate_ftp_arg(arg: &str) -> Result<(), ProtoError> {
    if arg.bytes().any(|b| matches!(b, 0 | b'\r' | b'\n')) {
        return Err(ProtoError::Transport(
            "Refusing FTP argument containing NUL, CR, or LF characters.".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct FtpReply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl FtpReply {
    pub fn summary(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.trim())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Clone)]
pub struct FtpConnectConfig {
    pub scheme: ProtocolScheme,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<Zeroizing<String>>,
    pub account: Option<String>,
    /// Passive mode (`EPSV`/`PASV`) when `true` (default); active (`EPRT`/`PORT`) when `false`.
    pub pasv_mode: bool,
    /// Rewrite unroutable `PASV` IPv4 replies to the control connection host.
    pub force_pasv_ip: bool,
    /// Prefer `MLSD`/`MLST` when advertised in `FEAT`.
    pub use_mlsd: bool,
    /// Require `MLSD` (`FtpUseMlsd=2`); refuse rather than falling back to `LIST`.
    pub mlsd_required: bool,
    pub tls: TlsSettings,
    pub proxy: Option<ProxyConfig>,
    pub timeout: Duration,
}

impl Default for FtpConnectConfig {
    fn default() -> Self {
        Self {
            scheme: ProtocolScheme::Ftp,
            host: String::new(),
            port: 21,
            username: "anonymous".to_string(),
            password: None,
            account: None,
            pasv_mode: true,
            force_pasv_ip: true,
            use_mlsd: true,
            mlsd_required: false,
            tls: TlsSettings::default(),
            proxy: None,
            timeout: Duration::from_secs(20),
        }
    }
}

enum ControlStream {
    Plain(BufReader<TcpStream>),
    Tls(Box<BufReader<TlsStream<TcpStream>>>),
    Transitioning,
}

impl ControlStream {
    async fn read_line_capped(&mut self) -> Result<String, ProtoError> {
        let mut buf = Vec::with_capacity(128);
        loop {
            let n = match self {
                Self::Plain(r) => {
                    let avail = r.fill_buf().await.map_err(|e| {
                        ProtoError::Transport(format!("FTP control read failed: {e}"))
                    })?;
                    if avail.is_empty() {
                        0
                    } else if let Some(nl) = avail.iter().position(|&b| b == b'\n') {
                        buf.extend_from_slice(&avail[..=nl]);
                        let consumed = nl + 1;
                        r.consume(consumed);
                        return Ok(String::from_utf8_lossy(&buf).into_owned());
                    } else {
                        let len = avail.len();
                        buf.extend_from_slice(avail);
                        r.consume(len);
                        len
                    }
                }
                Self::Tls(r) => {
                    let avail = r.fill_buf().await.map_err(|e| {
                        ProtoError::Transport(format!("FTPS control read failed: {e}"))
                    })?;
                    if avail.is_empty() {
                        0
                    } else if let Some(nl) = avail.iter().position(|&b| b == b'\n') {
                        buf.extend_from_slice(&avail[..=nl]);
                        let consumed = nl + 1;
                        r.consume(consumed);
                        return Ok(String::from_utf8_lossy(&buf).into_owned());
                    } else {
                        let len = avail.len();
                        buf.extend_from_slice(avail);
                        r.consume(len);
                        len
                    }
                }
                Self::Transitioning => {
                    return Err(ProtoError::Transport(
                        "FTP control stream in invalid state.".to_string(),
                    ));
                }
            };
            if n == 0 {
                return Err(ProtoError::Transport(
                    "FTP server closed control connection unexpectedly.".to_string(),
                ));
            }
            if buf.len() > MAX_FTP_LINE_BYTES {
                return Err(ProtoError::Transport(
                    "FTP server reply line exceeded 16 KiB limit.".to_string(),
                ));
            }
        }
    }

    async fn write_command(&mut self, cmd_line: &str) -> Result<(), ProtoError> {
        let wire = format!("{cmd_line}\r\n");
        match self {
            Self::Plain(r) => {
                r.get_mut()
                    .write_all(wire.as_bytes())
                    .await
                    .map_err(|e| ProtoError::Transport(format!("FTP write failed: {e}")))?;
                r.get_mut()
                    .flush()
                    .await
                    .map_err(|e| ProtoError::Transport(format!("FTP flush failed: {e}")))?;
            }
            Self::Tls(r) => {
                r.get_mut()
                    .write_all(wire.as_bytes())
                    .await
                    .map_err(|e| ProtoError::Transport(format!("FTPS write failed: {e}")))?;
                r.get_mut()
                    .flush()
                    .await
                    .map_err(|e| ProtoError::Transport(format!("FTPS flush failed: {e}")))?;
            }
            Self::Transitioning => {
                return Err(ProtoError::Transport(
                    "FTP control stream in invalid state.".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Plain(r) => r.get_ref().local_addr().ok(),
            Self::Tls(r) => r.get_ref().get_ref().0.local_addr().ok(),
            Self::Transitioning => None,
        }
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Plain(r) => r.get_ref().peer_addr().ok(),
            Self::Tls(r) => r.get_ref().get_ref().0.peer_addr().ok(),
            Self::Transitioning => None,
        }
    }

    async fn upgrade_to_tls(
        &mut self,
        connector: &TlsConnector,
        server_name: ServerName<'static>,
    ) -> Result<(), ProtoError> {
        let prev = std::mem::replace(self, Self::Transitioning);
        let Self::Plain(buf_reader) = prev else {
            return Err(ProtoError::Transport(
                "Control connection is already TLS.".to_string(),
            ));
        };
        if !buf_reader.buffer().is_empty() {
            return Err(ProtoError::Transport(
                "Refusing AUTH TLS upgrade with buffered cleartext bytes.".to_string(),
            ));
        }
        let raw_tcp = buf_reader.into_inner();
        let tls_stream = connector
            .connect(server_name, raw_tcp)
            .await
            .map_err(|e| ProtoError::Transport(format!("FTPES AUTH TLS handshake failed: {e}")))?;
        *self = Self::Tls(Box::new(BufReader::new(tls_stream)));
        Ok(())
    }
}

enum DataStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl DataStream {
    async fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize, ProtoError> {
        match self {
            Self::Plain(s) => s
                .read(buf)
                .await
                .map_err(|e| ProtoError::Transport(format!("FTP data read failed: {e}"))),
            Self::Tls(s) => s
                .read(buf)
                .await
                .map_err(|e| ProtoError::Transport(format!("FTPS data read failed: {e}"))),
        }
    }

    async fn write_all_chunk(&mut self, buf: &[u8]) -> Result<(), ProtoError> {
        match self {
            Self::Plain(s) => s
                .write_all(buf)
                .await
                .map_err(|e| ProtoError::Transport(format!("FTP data write failed: {e}"))),
            Self::Tls(s) => s
                .write_all(buf)
                .await
                .map_err(|e| ProtoError::Transport(format!("FTPS data write failed: {e}"))),
        }
    }

    async fn finish_write(mut self) -> Result<(), ProtoError> {
        match &mut self {
            Self::Plain(s) => {
                s.flush()
                    .await
                    .map_err(|e| ProtoError::Transport(format!("FTP data flush failed: {e}")))?;
                s.shutdown()
                    .await
                    .map_err(|e| ProtoError::Transport(format!("FTP data shutdown failed: {e}")))?;
            }
            Self::Tls(s) => {
                s.flush()
                    .await
                    .map_err(|e| ProtoError::Transport(format!("FTPS data flush failed: {e}")))?;
                s.shutdown().await.map_err(|e| {
                    ProtoError::Transport(format!("FTPS data close_notify failed: {e}"))
                })?;
            }
        }
        Ok(())
    }
}

struct FtpInner {
    ctrl: ControlStream,
    // A failed data transfer can leave one or more completion replies on the
    // control channel. Never interpret them as replies to later commands.
    poisoned: bool,
    prot_private: bool,
    supports_mlst: bool,
    supports_size: bool,
    supports_mdtm: bool,
    supports_mfmt: bool,
    home_dir: String,
}

impl FtpInner {
    async fn read_reply(&mut self) -> Result<FtpReply, ProtoError> {
        if self.poisoned {
            return Err(ProtoError::Transport("FTP control connection is unusable after an interrupted transfer; reconnect.".to_string()));
        }
        let first = self.ctrl.read_line_capped().await?;
        let trimmed_first = first.trim_end_matches(['\r', '\n']);
        if trimmed_first.len() < 3
            || !trimmed_first.as_bytes()[..3]
                .iter()
                .all(|b| b.is_ascii_digit())
        {
            return Err(ProtoError::Transport(format!(
                "Malformed FTP server reply '{trimmed_first}'."
            )));
        }
        let code: u16 = trimmed_first[..3].parse().unwrap_or(0);
        let sep = trimmed_first.as_bytes().get(3).copied().unwrap_or(b' ');
        let mut lines = vec![trimmed_first.to_string()];

        if sep == b'-' {
            let end_prefix = format!("{code:03} ");
            loop {
                let line = self.ctrl.read_line_capped().await?;
                let clean = line.trim_end_matches(['\r', '\n']).to_string();
                let done = clean.starts_with(&end_prefix);
                lines.push(clean);
                if done {
                    break;
                }
            }
        }
        Ok(FtpReply { code, lines })
    }

    async fn command(&mut self, cmd: &str) -> Result<FtpReply, ProtoError> {
        if self.poisoned {
            return Err(ProtoError::Transport("FTP control connection is unusable after an interrupted transfer; reconnect.".to_string()));
        }
        self.ctrl.write_command(cmd).await?;
        self.read_reply().await
    }
}

fn parse_pwd_reply(reply: &FtpReply) -> Option<String> {
    let text = reply.lines.first()?;
    let open = text.find('"')?;
    let rest = &text[open + 1..];
    let mut out = String::new();
    let mut chars = rest.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '"' {
            if chars.peek() == Some(&'"') {
                let _ = chars.next();
                out.push('"');
            } else {
                return Some(out);
            }
        } else {
            out.push(ch);
        }
    }
    None
}

fn server_name_for(host: &str) -> Result<ServerName<'static>, ProtoError> {
    let bare = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    ServerName::try_from(bare.to_string())
        .map_err(|e| ProtoError::Transport(format!("Invalid TLS server name '{host}': {e}")))
}

pub struct FtpSession {
    cfg: FtpConnectConfig,
    tls_config: Option<Arc<ClientConfig>>,
    inner: Mutex<FtpInner>,
    jump_tunnel: Option<Arc<SshJumpTunnel>>,
    socks_relay: Mutex<Option<Socks5JumpRelay>>,
}

impl FtpSession {
    pub async fn connect(
        mut cfg: FtpConnectConfig,
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

        let needs_tls = matches!(cfg.scheme, ProtocolScheme::Ftps | ProtocolScheme::Ftpes);
        let tls_config = if needs_tls {
            Some(Arc::new(build_rustls_client_config(&cfg.tls)?))
        } else {
            None
        };

        let raw_tcp =
            connect_tcp_maybe_proxied(&cfg.host, cfg.port, cfg.proxy.as_ref(), cfg.timeout).await?;

        let ctrl = if cfg.scheme == ProtocolScheme::Ftps {
            let connector = TlsConnector::from(Arc::clone(tls_config.as_ref().unwrap()));
            let sname = server_name_for(&cfg.host)?;
            let tls_stream = connector
                .connect(sname, raw_tcp)
                .await
                .map_err(|e| ProtoError::Transport(format!("Implicit FTPS handshake failed: {e}")))?;
            ControlStream::Tls(Box::new(BufReader::new(tls_stream)))
        } else {
            ControlStream::Plain(BufReader::new(raw_tcp))
        };

        let mut inner = FtpInner {
            ctrl,
            poisoned: false,
            prot_private: false,
            supports_mlst: false,
            supports_size: false,
            supports_mdtm: false,
            supports_mfmt: false,
            home_dir: "/".to_string(),
        };

        let greet = inner.read_reply().await?;
        if greet.code != 220 {
            return Err(ProtoError::Transport(format!(
                "FTP greeting rejected: {}",
                greet.summary()
            )));
        }

        if cfg.scheme == ProtocolScheme::Ftpes {
            let auth_rep = inner.command("AUTH TLS").await?;
            if auth_rep.code != 234 {
                return Err(ProtoError::Transport(format!(
                    "FTPES server rejected AUTH TLS: {}",
                    auth_rep.summary()
                )));
            }
            let connector = TlsConnector::from(Arc::clone(tls_config.as_ref().unwrap()));
            let sname = server_name_for(&cfg.host)?;
            inner.ctrl.upgrade_to_tls(&connector, sname).await?;
        }

        validate_ftp_arg(&cfg.username)?;
        let user_rep = inner.command(&format!("USER {}", cfg.username)).await?;
        match user_rep.code {
            230 => {}
            331 => {
                let pass = cfg
                    .password
                    .as_deref()
                    .map(String::as_str)
                    .unwrap_or("anonymous@");
                validate_ftp_arg(pass)?;
                let pass_rep = inner.command(&format!("PASS {pass}")).await?;
                match pass_rep.code {
                    230 | 202 => {}
                    332 => {
                        let acct = cfg.account.as_deref().unwrap_or("");
                        validate_ftp_arg(acct)?;
                        let acct_rep = inner.command(&format!("ACCT {acct}")).await?;
                        if acct_rep.code != 230 && acct_rep.code != 202 {
                            return Err(ProtoError::Transport(format!(
                                "FTP ACCT rejected: {}",
                                acct_rep.summary()
                            )));
                        }
                    }
                    _ => {
                        return Err(ProtoError::Transport(format!(
                            "FTP authentication failed: {}",
                            pass_rep.summary()
                        )));
                    }
                }
            }
            _ => {
                return Err(ProtoError::Transport(format!(
                    "FTP USER rejected: {}",
                    user_rep.summary()
                )));
            }
        }

        if needs_tls {
            let pbsz = inner.command("PBSZ 0").await?;
            if pbsz.code != 200 {
                return Err(ProtoError::Transport(format!(
                    "FTPS PBSZ 0 failed: {}",
                    pbsz.summary()
                )));
            }
            let prot = inner.command("PROT P").await?;
            if prot.code != 200 {
                return Err(ProtoError::Transport(format!(
                    "FTPS PROT P failed: {}",
                    prot.summary()
                )));
            }
            inner.prot_private = true;
        }

        let feat = inner.command("FEAT").await?;
        if feat.code == 211 {
            let mut has_utf8 = false;
            for line in &feat.lines {
                let tok = line
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_uppercase();
                match tok.as_str() {
                    "MLST" | "MLSD" => inner.supports_mlst = true,
                    "SIZE" => inner.supports_size = true,
                    "MDTM" => inner.supports_mdtm = true,
                    "MFMT" => inner.supports_mfmt = true,
                    "UTF8" => has_utf8 = true,
                    _ => {}
                }
            }
            if has_utf8 {
                let _ = inner.command("OPTS UTF8 ON").await;
            }
        }

        let _ = inner.command("TYPE I").await;
        if let Ok(pwd_rep) = inner.command("PWD").await {
            if pwd_rep.code == 257 {
                if let Some(dir) = parse_pwd_reply(&pwd_rep) {
                    inner.home_dir = dir;
                }
            }
        }

        Ok(Self {
            cfg,
            tls_config,
            inner: Mutex::new(inner),
            jump_tunnel,
            socks_relay: Mutex::new(socks_relay),
        })
    }

    async fn upgrade_data_if_needed(
        &self,
        prot_private: bool,
        tcp: TcpStream,
    ) -> Result<DataStream, ProtoError> {
        let _ = tcp.set_nodelay(true);
        if !prot_private {
            return Ok(DataStream::Plain(tcp));
        }
        let tls_cfg = self.tls_config.as_ref().ok_or_else(|| {
            ProtoError::Transport("Missing TLS configuration for FTPS data channel.".to_string())
        })?;
        let connector = TlsConnector::from(Arc::clone(tls_cfg));
        let sname = server_name_for(&self.cfg.host)?;
        let tls = connector
            .connect(sname, tcp)
            .await
            .map_err(|e| ProtoError::Transport(format!("FTPS data TLS handshake failed: {e}")))?;
        Ok(DataStream::Tls(Box::new(tls)))
    }

    async fn open_data_command(
        &self,
        inner: &mut FtpInner,
        transfer_cmd: &str,
    ) -> Result<DataStream, ProtoError> {
        if self.cfg.pasv_mode {
            let (data_host, data_port) = self.enter_passive(inner).await?;
            let tcp = connect_tcp_maybe_proxied(
                &data_host,
                data_port,
                self.cfg.proxy.as_ref(),
                self.cfg.timeout,
            )
            .await?;
            let prelim = inner.command(transfer_cmd).await?;
            if prelim.code != 125 && prelim.code != 150 {
                return Err(ProtoError::Transport(format!(
                    "FTP '{transfer_cmd}' rejected: {}",
                    prelim.summary()
                )));
            }
            self.upgrade_data_if_needed(inner.prot_private, tcp).await
        } else {
            if self.cfg.proxy.is_some() {
                return Err(ProtoError::Transport(
                    "Active FTP (PORT/EPRT) cannot be used behind a client proxy or SOCKS tunnel; enable passive mode."
                        .to_string(),
                ));
            }
            let bind_ip = inner
                .ctrl
                .local_addr()
                .map(|a| a.ip())
                .unwrap_or(IpAddr::from([127, 0, 0, 1]));
            let listener = TcpListener::bind((bind_ip, 0))
                .await
                .map_err(|e| ProtoError::Transport(format!("Active FTP bind failed: {e}")))?;
            let bound = listener
                .local_addr()
                .map_err(|e| ProtoError::Transport(format!("Active FTP local_addr failed: {e}")))?;

            let port_ok = match bound.ip() {
                IpAddr::V4(v4) => {
                    let o = v4.octets();
                    let p = bound.port();
                    let p_cmd = format!(
                        "PORT {},{},{},{},{},{}",
                        o[0],
                        o[1],
                        o[2],
                        o[3],
                        p / 256,
                        p % 256
                    );
                    let rep = inner.command(&p_cmd).await?;
                    if rep.code == 200 {
                        true
                    } else {
                        let eprt = format!("EPRT |1|{v4}|{p}|");
                        inner.command(&eprt).await?.code == 200
                    }
                }
                IpAddr::V6(v6) => {
                    let eprt = format!("EPRT |2|{v6}|{}|", bound.port());
                    inner.command(&eprt).await?.code == 200
                }
            };
            if !port_ok {
                return Err(ProtoError::Transport(
                    "FTP server rejected active PORT/EPRT command.".to_string(),
                ));
            }

            inner.ctrl.write_command(transfer_cmd).await?;
            let accept_fut = tokio::time::timeout(self.cfg.timeout, listener.accept());
            let reply_fut = inner.read_reply();
            let (acc_res, rep_res) = tokio::join!(accept_fut, reply_fut);
            let prelim = rep_res?;
            if prelim.code != 125 && prelim.code != 150 {
                return Err(ProtoError::Transport(format!(
                    "FTP '{transfer_cmd}' rejected: {}",
                    prelim.summary()
                )));
            }
            let (tcp, _) = acc_res
                .map_err(|_| ProtoError::Transport("Timed out awaiting active FTP data connection.".to_string()))?
                .map_err(|e| ProtoError::Transport(format!("Active FTP accept failed: {e}")))?;
            self.upgrade_data_if_needed(inner.prot_private, tcp).await
        }
    }

    async fn enter_passive(&self, inner: &mut FtpInner) -> Result<(String, u16), ProtoError> {
        let epsv = inner.command("EPSV").await?;
        if epsv.code == 229 {
            let port = parse_epsv_reply(&epsv.summary()).ok_or_else(|| {
                ProtoError::Transport(format!("Malformed FTP EPSV reply: {}", epsv.summary()))
            })?;
            return Ok((self.cfg.host.clone(), port));
        }

        let pasv = inner.command("PASV").await?;
        if pasv.code != 227 {
            return Err(ProtoError::Transport(format!(
                "FTP passive mode failed: {}",
                pasv.summary()
            )));
        }
        let (pasv_addr, port) = parse_pasv_reply(&pasv.summary()).ok_or_else(|| {
            ProtoError::Transport(format!("Malformed FTP PASV reply: {}", pasv.summary()))
        })?;

        let resolved_host = if pasv_addr == "0.0.0.0"
            || (self.cfg.force_pasv_ip && is_unroutable_pasv_address(&pasv_addr))
        {
            if self.cfg.proxy.is_some() {
                self.cfg.host.clone()
            } else {
                inner
                    .ctrl
                    .peer_addr()
                    .map(|sa| sa.ip().to_string())
                    .unwrap_or_else(|| self.cfg.host.clone())
            }
        } else {
            pasv_addr
        };
        Ok((resolved_host, port))
    }

    async fn read_data_to_string(
        &self,
        inner: &mut FtpInner,
        mut data: DataStream,
    ) -> Result<String, ProtoError> {
        let mut bytes = Vec::new();
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            let n = data.read_chunk(&mut chunk).await?;
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..n]);
        }
        drop(data);
        let done = inner.read_reply().await?;
        if done.code != 226 && done.code != 250 {
            return Err(ProtoError::Transport(format!(
                "FTP data transfer failed: {}",
                done.summary()
            )));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[async_trait]
impl RemoteSession for FtpSession {
    fn scheme(&self) -> ProtocolScheme {
        self.cfg.scheme
    }

    async fn pwd(&self) -> Result<String, ProtoError> {
        let mut inner = self.inner.lock().await;
        let rep = inner.command("PWD").await?;
        if rep.code == 257 {
            if let Some(dir) = parse_pwd_reply(&rep) {
                return Ok(dir);
            }
        }
        Ok(inner.home_dir.clone())
    }

    async fn stat(&self, remote_path: &str) -> Result<Option<FileEntry>, ProtoError> {
        validate_ftp_arg(remote_path)?;
        let mut inner = self.inner.lock().await;
        if inner.supports_mlst && self.cfg.use_mlsd {
            let rep = inner.command(&format!("MLST {remote_path}")).await?;
            if rep.code == 250 {
                for line in &rep.lines {
                    if line.starts_with(' ') && line.contains('=') {
                        if let Ok(Some(mut parsed)) = parse_mlsx_line(line) {
                            let leaf = remote_path
                                .trim_end_matches('/')
                                .rsplit('/')
                                .next()
                                .filter(|s| !s.is_empty())
                                .unwrap_or("/");
                            parsed.name = leaf.to_string();
                            return Ok(Some(parsed.into_file_entry()));
                        }
                    }
                }
            } else if rep.code == 550 {
                return Ok(None);
            }
        }

        if inner.supports_size {
            let _ = inner.command("TYPE I").await;
            let sz_rep = inner.command(&format!("SIZE {remote_path}")).await?;
            if sz_rep.code == 213 {
                let sz_str = sz_rep
                    .lines
                    .first()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("0");
                let size = sz_str.parse::<u64>().unwrap_or(0);
                let mut mtime = 0i64;
                if inner.supports_mdtm {
                    let m_rep = inner.command(&format!("MDTM {remote_path}")).await?;
                    if m_rep.code == 213 {
                        if let Some(ts_tok) =
                            m_rep.lines.first().and_then(|l| l.split_whitespace().nth(1))
                        {
                            mtime = parse_ftp_compact_utc(ts_tok).unwrap_or(0);
                        }
                    }
                }
                let leaf = remote_path
                    .trim_end_matches('/')
                    .rsplit('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(remote_path)
                    .to_string();
                return Ok(Some(FileEntry {
                    name: leaf,
                    size,
                    is_dir: false,
                    is_symlink: false,
                    broken_link: false,
                    date: format_utc_timestamp(mtime),
                    mtime,
                    permissions: "-rw-r--r--".to_string(),
                    owner: None,
                    group: None,
                }));
            }
        }
        drop(inner);

        // Fallback: inspect parent directory listing
        let trimmed = remote_path.trim_end_matches('/');
        if trimmed.is_empty() || trimmed == "/" {
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
        }
        let (parent, leaf) = match trimmed.rsplit_once('/') {
            Some(("", name)) => ("/", name),
            Some((p, name)) => (p, name),
            None => (".", trimmed),
        };
        if let Ok(items) = self.list_dir(parent).await {
            return Ok(items.into_iter().find(|e| e.name == leaf));
        }
        Ok(None)
    }

    async fn list_dir(&self, remote_path: &str) -> Result<Vec<FileEntry>, ProtoError> {
        validate_ftp_arg(remote_path)?;
        let mut inner = self.inner.lock().await;
        let _ = inner.command("TYPE A").await;

        let target = if remote_path.is_empty() || remote_path == "." {
            None
        } else {
            Some(remote_path)
        };

        if self.cfg.mlsd_required && !inner.supports_mlst {
            return Err(ProtoError::Transport(
                "FTP server does not advertise MLSD support (FtpUseMlsd=2).".to_string(),
            ));
        }

        if (inner.supports_mlst && self.cfg.use_mlsd) || self.cfg.mlsd_required {
            let cmd = match target {
                Some(p) => format!("MLSD {p}"),
                None => "MLSD".to_string(),
            };
            match self.open_data_command(&mut inner, &cmd).await {
                Ok(data) => {
                    let raw = self.read_data_to_string(&mut inner, data).await?;
                    let mut entries = Vec::new();
                    for line in raw.lines() {
                        if let Some(parsed) =
                            parse_mlsx_line(line).map_err(ProtoError::Transport)?
                        {
                            entries.push(parsed.into_file_entry());
                        }
                    }
                    entries.sort_by(|a, b| a.name.cmp(&b.name));
                    return Ok(entries);
                }
                Err(e) if self.cfg.mlsd_required => {
                    return Err(ProtoError::Transport(format!(
                        "FTP MLSD refused by server (FtpUseMlsd=2): {e}"
                    )));
                }
                Err(_) => {}
            }
        }

        let list_cmd = match target {
            Some(p) => format!("LIST {p}"),
            None => "LIST".to_string(),
        };
        let data = self.open_data_command(&mut inner, &list_cmd).await?;
        let raw = self.read_data_to_string(&mut inner, data).await?;
        Ok(parse_list_output(&raw))
    }

    async fn mkdir(&self, remote_path: &str) -> Result<(), ProtoError> {
        validate_ftp_arg(remote_path)?;
        let mut inner = self.inner.lock().await;
        let rep = inner.command(&format!("MKD {remote_path}")).await?;
        if rep.code != 257 && rep.code != 250 {
            return Err(ProtoError::Transport(format!(
                "FTP MKD '{remote_path}' failed: {}",
                rep.summary()
            )));
        }
        Ok(())
    }

    async fn remove_file(&self, remote_path: &str) -> Result<(), ProtoError> {
        validate_ftp_arg(remote_path)?;
        let mut inner = self.inner.lock().await;
        let rep = inner.command(&format!("DELE {remote_path}")).await?;
        if rep.code != 250 {
            return Err(ProtoError::Transport(format!(
                "FTP DELE '{remote_path}' failed: {}",
                rep.summary()
            )));
        }
        Ok(())
    }

    async fn remove_dir(&self, remote_path: &str) -> Result<(), ProtoError> {
        validate_ftp_arg(remote_path)?;
        let mut inner = self.inner.lock().await;
        let rep = inner.command(&format!("RMD {remote_path}")).await?;
        if rep.code != 250 {
            return Err(ProtoError::Transport(format!(
                "FTP RMD '{remote_path}' failed: {}",
                rep.summary()
            )));
        }
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        validate_ftp_arg(from)?;
        validate_ftp_arg(to)?;
        let mut inner = self.inner.lock().await;
        let rnfr = inner.command(&format!("RNFR {from}")).await?;
        if rnfr.code != 350 {
            return Err(ProtoError::Transport(format!(
                "FTP RNFR '{from}' failed: {}",
                rnfr.summary()
            )));
        }
        let rnto = inner.command(&format!("RNTO {to}")).await?;
        if rnto.code != 250 {
            return Err(ProtoError::Transport(format!(
                "FTP RNTO '{to}' failed: {}",
                rnto.summary()
            )));
        }
        Ok(())
    }

    async fn copy_file(&self, _from: &str, _to: &str) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("copy_file", self.cfg.scheme))
    }

    async fn symlink(&self, _target: &str, _link_path: &str) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability("symlink", self.cfg.scheme))
    }

    async fn chmod(&self, remote_path: &str, mode: u32) -> Result<(), ProtoError> {
        validate_ftp_arg(remote_path)?;
        let mut inner = self.inner.lock().await;
        let rep = inner
            .command(&format!("SITE CHMOD {:04o} {remote_path}", mode & 0o7777))
            .await?;
        if rep.code != 200 && rep.code != 250 {
            return Err(ProtoError::Transport(format!(
                "FTP SITE CHMOD '{remote_path}' failed: {}",
                rep.summary()
            )));
        }
        Ok(())
    }

    async fn set_mtime(&self, remote_path: &str, mtime: i64) -> Result<(), ProtoError> {
        validate_ftp_arg(remote_path)?;
        let ts = mtime.max(0);
        let days = ts.div_euclid(86_400);
        let rem = ts.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        let stamp = format!(
            "{y:04}{m:02}{d:02}{:02}{:02}{:02}",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        );
        let mut inner = self.inner.lock().await;
        if inner.supports_mfmt {
            let rep = inner.command(&format!("MFMT {stamp} {remote_path}")).await?;
            if rep.code == 213 || rep.code == 250 {
                return Ok(());
            }
        }
        Err(ProtoError::UnsupportedCapability("set_mtime", self.cfg.scheme))
    }

    async fn checksum(&self, algorithm: &str, remote_path: &str) -> Result<String, ProtoError> {
        validate_ftp_arg(remote_path)?;
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
        validate_ftp_arg(remote_path)?;
        let mut inner = self.inner.lock().await;
        let tp = inner.command("TYPE I").await?;
        if tp.code != 200 {
            return Err(ProtoError::Transport(format!(
                "FTP TYPE I failed: {}",
                tp.summary()
            )));
        }

        let mut total_size = 0u64;
        if inner.supports_size {
            if let Ok(sz_rep) = inner.command(&format!("SIZE {remote_path}")).await {
                if sz_rep.code == 213 {
                    total_size = sz_rep
                        .lines
                        .first()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
            }
        }

        if opts.resume_offset > 0 {
            let rest = inner.command(&format!("REST {}", opts.resume_offset)).await?;
            if rest.code != 350 {
                return Err(ProtoError::Transport(format!(
                    "FTP REST {} rejected: {}",
                    opts.resume_offset,
                    rest.summary()
                )));
            }
        }

        let mut data = match self.open_data_command(&mut inner, &format!("RETR {remote_path}")).await {
            Ok(data) => data,
            Err(error) => { inner.poisoned = true; return Err(error); }
        };
        let mut buf = vec![0u8; FTP_CHUNK_SIZE];
        let mut transferred = 0u64;
        let mut limiter = RateLimiter::new(opts.speed_kbytes_per_sec);

        loop {
            let n = match data.read_chunk(&mut buf).await {
                Ok(n) => n,
                Err(error) => { inner.poisoned = true; return Err(error); }
            };
            if n == 0 {
                break;
            }
            if let Err(error) = sink.write_all(&buf[..n]).await {
                inner.poisoned = true;
                return Err(ProtoError::Transport(format!("Writing FTP sink failed: {error}; reconnect before using this session.")));
            }
            transferred += n as u64;
            if let Some(cb) = progress {
                cb(opts.resume_offset + transferred, total_size);
            }
            if opts.speed_kbytes_per_sec > 0 {
                if let Err(error) = sink.flush().await {
                    inner.poisoned = true;
                    return Err(ProtoError::Transport(format!("Flushing FTP sink failed: {error}; reconnect before using this session.")));
                }
            }
            limiter.consume(n).await;
        }
        drop(data);
        if let Err(error) = sink.flush().await {
            inner.poisoned = true;
            return Err(ProtoError::Transport(format!("Flushing FTP sink failed: {error}; reconnect before using this session.")));
        }

        let done = match inner.read_reply().await {
            Ok(done) => done,
            Err(error) => { inner.poisoned = true; return Err(error); }
        };
        if done.code != 226 && done.code != 250 {
            inner.poisoned = true;
            return Err(ProtoError::Transport(format!(
                "FTP RETR '{remote_path}' failed: {}",
                done.summary()
            )));
        }
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
        validate_ftp_arg(remote_path)?;
        let mut inner = self.inner.lock().await;
        let tp = inner.command("TYPE I").await?;
        if tp.code != 200 {
            return Err(ProtoError::Transport(format!(
                "FTP TYPE I failed: {}",
                tp.summary()
            )));
        }

        let verb = if opts.append {
            format!("APPE {remote_path}")
        } else {
            if opts.resume_offset > 0 {
                let rest = inner.command(&format!("REST {}", opts.resume_offset)).await?;
                if rest.code != 350 {
                    return Err(ProtoError::Transport(format!(
                        "FTP REST {} rejected: {}",
                        opts.resume_offset,
                        rest.summary()
                    )));
                }
            }
            format!("STOR {remote_path}")
        };

        let mut data = match self.open_data_command(&mut inner, &verb).await {
            Ok(data) => data,
            Err(error) => { inner.poisoned = true; return Err(error); }
        };
        let mut buf = vec![0u8; FTP_CHUNK_SIZE];
        let mut transferred = 0u64;
        let mut limiter = RateLimiter::new(opts.speed_kbytes_per_sec);
        let reported_total = total_size.unwrap_or(0);

        loop {
            let n = match source.read(&mut buf).await {
                Ok(n) => n,
                Err(error) => { inner.poisoned = true; return Err(ProtoError::Transport(format!("Reading FTP upload source: {error}; reconnect before using this session."))); }
            };
            if n == 0 {
                break;
            }
            if let Err(error) = data.write_all_chunk(&buf[..n]).await {
                inner.poisoned = true;
                return Err(error);
            }
            transferred += n as u64;
            if let Some(cb) = progress {
                cb(opts.resume_offset + transferred, reported_total);
            }
            limiter.consume(n).await;
        }
        if let Err(error) = data.finish_write().await {
            inner.poisoned = true;
            return Err(error);
        }

        let done = match inner.read_reply().await {
            Ok(done) => done,
            Err(error) => { inner.poisoned = true; return Err(error); }
        };
        if done.code != 226 && done.code != 250 {
            inner.poisoned = true;
            return Err(ProtoError::Transport(format!(
                "FTP upload '{remote_path}' failed: {}",
                done.summary()
            )));
        }

        if opts.preserve_time {
            if let Some(mtime) = opts.mtime {
                if inner.supports_mfmt {
                    drop(inner);
                    let _ = self.set_mtime(remote_path, mtime).await;
                }
            }
        }
        Ok(transferred)
    }

    async fn close(&self) -> Result<(), ProtoError> {
        {
            let mut inner = self.inner.lock().await;
            let _ = inner.command("QUIT").await;
        }
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
    fn pasv_and_epsv_parsers_reject_overflow_and_flag_unroutable_addresses() {
        assert_eq!(
            parse_epsv_reply("229 Entering Extended Passive Mode (|||21210|)"),
            Some(21210)
        );
        assert_eq!(parse_epsv_reply("229 Bad (|||99999|)"), None);
        assert_eq!(parse_epsv_reply("229 Bad (|||0|)"), None);

        assert_eq!(
            parse_pasv_reply("227 Entering Passive Mode (198,51,100,7,82,218)."),
            Some(("198.51.100.7".to_string(), 21210))
        );
        assert_eq!(
            parse_pasv_reply("227 Bad (999,999,999,999,999,999)"),
            None
        );

        assert!(is_unroutable_pasv_address("0.0.0.0"));
        assert!(is_unroutable_pasv_address("127.0.0.1"));
        assert!(is_unroutable_pasv_address("10.1.2.3"));
        assert!(is_unroutable_pasv_address("172.16.0.1"));
        assert!(is_unroutable_pasv_address("192.168.1.50"));
        assert!(is_unroutable_pasv_address("100.64.10.2"));
        assert!(!is_unroutable_pasv_address("198.51.100.7"));
    }
}
