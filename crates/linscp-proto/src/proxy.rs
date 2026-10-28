//! Async proxy dialer (Direct TCP, SOCKS5/SOCKS5h, SOCKS4/SOCKS4a, HTTP CONNECT)
//! and SOCKS5 wire framing shared by client proxy connections and the SSH
//! jump-host loopback SOCKS5 relay.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ProtoError;

const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 15;
const MAX_HTTP_CONNECT_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ProxyKind {
    #[default]
    None,
    Socks5,
    Socks4,
    HttpConnect,
    Telnet,
    LocalCommand,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Resolve DNS on the proxy (`socks5h` / `socks4a`) rather than locally.
    pub remote_dns: bool,
    /// Optional command template (`%host` / `%port`) for `Telnet` or `LocalCommand` proxies.
    pub command: Option<String>,
}

impl ProxyConfig {
    pub fn socks5_loopback(port: u16) -> Self {
        Self {
            kind: ProxyKind::Socks5,
            host: "127.0.0.1".to_string(),
            port,
            username: None,
            password: None,
            remote_dns: true,
            command: None,
        }
    }
}

fn validate_target_endpoint(host: &str, port: u16) -> Result<&str, ProtoError> {
    let trimmed = host.trim();
    if trimmed.is_empty() || trimmed == "*" {
        return Err(ProtoError::Transport(
            "Refusing empty or wildcard destination host.".to_string(),
        ));
    }
    if port == 0 {
        return Err(ProtoError::Transport(
            "Refusing destination port 0.".to_string(),
        ));
    }
    Ok(trimmed)
}

/// Builds a SOCKS5 `CONNECT` request packet (`VER=5, CMD=1, RSV=0, ATYP, DST.ADDR, DST.PORT`),
/// matching `BuildSocks5ConnectRequest` in `SshTunnel.cpp`.
pub fn build_socks5_connect_request(
    host: &str,
    port: u16,
    remote_dns: bool,
) -> Result<Vec<u8>, ProtoError> {
    let clean_host = validate_target_endpoint(host, port)?;
    let bare_host = clean_host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(clean_host);

    let mut packet = Vec::with_capacity(7 + bare_host.len());
    packet.extend_from_slice(&[0x05, 0x01, 0x00]);

    if let Ok(ip) = bare_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                packet.push(0x01);
                packet.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                packet.push(0x04);
                packet.extend_from_slice(&v6.octets());
            }
        }
    } else if remote_dns {
        if bare_host.len() > 255 {
            return Err(ProtoError::Transport(format!(
                "Destination hostname '{bare_host}' exceeds 255 bytes for SOCKS5."
            )));
        }
        packet.push(0x03);
        packet.push(bare_host.len() as u8);
        packet.extend_from_slice(bare_host.as_bytes());
    } else {
        return Err(ProtoError::Transport(format!(
            "Local DNS resolution required before building non-SOCKS5h packet for '{bare_host}'."
        )));
    }

    packet.extend_from_slice(&port.to_be_bytes());
    Ok(packet)
}

/// Parses a complete SOCKS5 `CONNECT` request buffer (`VER=5, CMD=1`),
/// returning `(host, port)`. Wildcard (`*`), empty hosts, and port `0` are
/// rejected, matching `ParseSocks5ConnectRequest` in `SshTunnel.cpp`.
pub fn parse_socks5_connect_request(data: &[u8]) -> Result<(String, u16), ProtoError> {
    if data.len() < 7 {
        return Err(ProtoError::Transport(
            "Truncated SOCKS5 request header.".to_string(),
        ));
    }
    if data[0] != 0x05 {
        return Err(ProtoError::Transport(format!(
            "Unsupported SOCKS version 0x{:02X}.",
            data[0]
        )));
    }
    if data[1] != 0x01 {
        return Err(ProtoError::Transport(format!(
            "Unsupported SOCKS5 command 0x{:02X} (only CONNECT is permitted).",
            data[1]
        )));
    }

    let (host, port_offset) = match data[3] {
        0x01 => {
            if data.len() != 10 {
                return Err(ProtoError::Transport(
                    "Invalid SOCKS5 IPv4 request length.".to_string(),
                ));
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            (ip.to_string(), 8usize)
        }
        0x03 => {
            let len = data[4] as usize;
            if len == 0 || data.len() != 5 + len + 2 {
                return Err(ProtoError::Transport(
                    "Invalid SOCKS5 domain request length.".to_string(),
                ));
            }
            let domain = std::str::from_utf8(&data[5..5 + len])
                .map_err(|_| ProtoError::Transport("Non-UTF8 SOCKS5 domain name.".to_string()))?;
            if domain.trim().is_empty()
                || domain == "*"
                || domain.bytes().any(|b| b < 0x20 || b == 0x7f)
            {
                return Err(ProtoError::Transport(
                    "Invalid or wildcard SOCKS5 domain name.".to_string(),
                ));
            }
            (domain.to_string(), 5 + len)
        }
        0x04 => {
            if data.len() != 22 {
                return Err(ProtoError::Transport(
                    "Invalid SOCKS5 IPv6 request length.".to_string(),
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            let ip = Ipv6Addr::from(octets);
            (ip.to_string(), 20usize)
        }
        other => {
            return Err(ProtoError::Transport(format!(
                "Unsupported SOCKS5 address type 0x{other:02X}."
            )));
        }
    };

    let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);
    if port == 0 {
        return Err(ProtoError::Transport(
            "SOCKS5 destination port 0 is not permitted.".to_string(),
        ));
    }
    Ok((host, port))
}

/// Performs a client-side SOCKS5 greeting, optional RFC 1929 username/password
/// authentication, and `CONNECT` handshake on an already-open stream.
pub async fn socks5_connect_on_stream<S>(
    stream: &mut S,
    dest_host: &str,
    dest_port: u16,
    auth: Option<(&str, &str)>,
    remote_dns: bool,
) -> Result<(), ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let target_host = if !remote_dns && dest_host.parse::<IpAddr>().is_err() {
        let mut resolved = tokio::net::lookup_host((dest_host, dest_port))
            .await
            .map_err(|e| {
                ProtoError::Transport(format!("Failed to resolve '{dest_host}': {e}"))
            })?;
        let sock = resolved.next().ok_or_else(|| {
            ProtoError::Transport(format!("No addresses resolved for '{dest_host}'."))
        })?;
        sock.ip().to_string()
    } else {
        dest_host.to_string()
    };

    let req = build_socks5_connect_request(&target_host, dest_port, true)?;

    if auth.is_some() {
        stream
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .map_err(|e| ProtoError::Transport(format!("SOCKS5 greeting write failed: {e}")))?;
    } else {
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|e| ProtoError::Transport(format!("SOCKS5 greeting write failed: {e}")))?;
    }
    stream
        .flush()
        .await
        .map_err(|e| ProtoError::Transport(format!("SOCKS5 greeting flush failed: {e}")))?;

    let mut method_reply = [0u8; 2];
    stream
        .read_exact(&mut method_reply)
        .await
        .map_err(|e| ProtoError::Transport(format!("SOCKS5 greeting reply failed: {e}")))?;
    if method_reply[0] != 0x05 {
        return Err(ProtoError::Transport(format!(
            "Invalid SOCKS5 server version 0x{:02X}.",
            method_reply[0]
        )));
    }
    match method_reply[1] {
        0x00 => {}
        0x02 => {
            let Some((user, pass)) = auth else {
                return Err(ProtoError::Transport(
                    "SOCKS5 proxy requires authentication but no credentials were supplied."
                        .to_string(),
                ));
            };
            if user.len() > 255 || pass.len() > 255 {
                return Err(ProtoError::Transport(
                    "SOCKS5 username/password exceeds 255 bytes.".to_string(),
                ));
            }
            let mut subneg = Vec::with_capacity(3 + user.len() + pass.len());
            subneg.push(0x01);
            subneg.push(user.len() as u8);
            subneg.extend_from_slice(user.as_bytes());
            subneg.push(pass.len() as u8);
            subneg.extend_from_slice(pass.as_bytes());
            stream
                .write_all(&subneg)
                .await
                .map_err(|e| ProtoError::Transport(format!("SOCKS5 auth write failed: {e}")))?;
            stream
                .flush()
                .await
                .map_err(|e| ProtoError::Transport(format!("SOCKS5 auth flush failed: {e}")))?;
            let mut auth_reply = [0u8; 2];
            stream
                .read_exact(&mut auth_reply)
                .await
                .map_err(|e| ProtoError::Transport(format!("SOCKS5 auth reply failed: {e}")))?;
            if auth_reply[1] != 0x00 {
                return Err(ProtoError::Transport(
                    "SOCKS5 proxy rejected username/password credentials.".to_string(),
                ));
            }
        }
        0xff => {
            return Err(ProtoError::Transport(
                "SOCKS5 proxy rejected all authentication methods.".to_string(),
            ));
        }
        other => {
            return Err(ProtoError::Transport(format!(
                "SOCKS5 proxy selected unsupported auth method 0x{other:02X}."
            )));
        }
    }

    stream
        .write_all(&req)
        .await
        .map_err(|e| ProtoError::Transport(format!("SOCKS5 CONNECT write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ProtoError::Transport(format!("SOCKS5 CONNECT flush failed: {e}")))?;

    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|e| ProtoError::Transport(format!("SOCKS5 CONNECT reply failed: {e}")))?;
    if hdr[0] != 0x05 {
        return Err(ProtoError::Transport(format!(
            "Invalid SOCKS5 reply version 0x{:02X}.",
            hdr[0]
        )));
    }
    if hdr[1] != 0x00 {
        return Err(ProtoError::Transport(format!(
            "SOCKS5 CONNECT failed with status 0x{:02X}.",
            hdr[1]
        )));
    }

    // Drain bound address + 2-byte bound port.
    let tail_len = match hdr[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut dlen = [0u8; 1];
            stream
                .read_exact(&mut dlen)
                .await
                .map_err(|e| ProtoError::Transport(format!("SOCKS5 bound domain read: {e}")))?;
            dlen[0] as usize + 2
        }
        other => {
            return Err(ProtoError::Transport(format!(
                "SOCKS5 reply carried unknown ATYP 0x{other:02X}."
            )));
        }
    };
    let mut discard = vec![0u8; tail_len];
    stream
        .read_exact(&mut discard)
        .await
        .map_err(|e| ProtoError::Transport(format!("SOCKS5 bound address read: {e}")))?;
    Ok(())
}

async fn socks4_connect_on_stream<S>(
    stream: &mut S,
    dest_host: &str,
    dest_port: u16,
    user_id: &str,
    remote_dns: bool,
) -> Result<(), ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let clean_host = validate_target_endpoint(dest_host, dest_port)?;
    if user_id.bytes().any(|b| b == 0) || clean_host.bytes().any(|b| b == 0) {
        return Err(ProtoError::Transport(
            "SOCKS4 parameters must not contain NUL bytes.".to_string(),
        ));
    }

    let mut pkt = Vec::with_capacity(16 + user_id.len() + clean_host.len());
    pkt.push(0x04);
    pkt.push(0x01);
    pkt.extend_from_slice(&dest_port.to_be_bytes());

    if let Ok(v4) = clean_host.parse::<Ipv4Addr>() {
        pkt.extend_from_slice(&v4.octets());
        pkt.extend_from_slice(user_id.as_bytes());
        pkt.push(0x00);
    } else if remote_dns {
        // SOCKS4a: 0.0.0.1 + userid\0 + domain\0
        pkt.extend_from_slice(&[0, 0, 0, 1]);
        pkt.extend_from_slice(user_id.as_bytes());
        pkt.push(0x00);
        pkt.extend_from_slice(clean_host.as_bytes());
        pkt.push(0x00);
    } else {
        let mut addrs = tokio::net::lookup_host((clean_host, dest_port))
            .await
            .map_err(|e| ProtoError::Transport(format!("Failed to resolve '{clean_host}': {e}")))?;
        let v4 = addrs
            .find_map(|sa| match sa {
                SocketAddr::V4(v4) => Some(*v4.ip()),
                SocketAddr::V6(_) => None,
            })
            .ok_or_else(|| {
                ProtoError::Transport(format!("No IPv4 address resolved for SOCKS4 '{clean_host}'."))
            })?;
        pkt.extend_from_slice(&v4.octets());
        pkt.extend_from_slice(user_id.as_bytes());
        pkt.push(0x00);
    }

    stream
        .write_all(&pkt)
        .await
        .map_err(|e| ProtoError::Transport(format!("SOCKS4 request write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ProtoError::Transport(format!("SOCKS4 request flush failed: {e}")))?;

    let mut reply = [0u8; 8];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|e| ProtoError::Transport(format!("SOCKS4 reply read failed: {e}")))?;
    if reply[1] != 0x5a {
        return Err(ProtoError::Transport(format!(
            "SOCKS4 CONNECT rejected with status 0x{:02X}.",
            reply[1]
        )));
    }
    Ok(())
}

async fn http_connect_on_stream<S>(
    stream: &mut S,
    dest_host: &str,
    dest_port: u16,
    auth: Option<(&str, &str)>,
) -> Result<(), ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let clean_host = validate_target_endpoint(dest_host, dest_port)?;
    if clean_host.bytes().any(|b| b == b'\r' || b == b'\n') {
        return Err(ProtoError::Transport(
            "Destination host contains invalid CR/LF characters.".to_string(),
        ));
    }
    let authority = if clean_host.contains(':') && !clean_host.starts_with('[') {
        format!("[{clean_host}]:{dest_port}")
    } else {
        format!("{clean_host}:{dest_port}")
    };

    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((user, pass)) = auth {
        let token = BASE64.encode(format!("{user}:{pass}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| ProtoError::Transport(format!("HTTP CONNECT write failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ProtoError::Transport(format!("HTTP CONNECT flush failed: {e}")))?;

    let mut response = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() >= MAX_HTTP_CONNECT_HEADER_BYTES {
            return Err(ProtoError::Transport(
                "HTTP CONNECT proxy response headers exceeded 16 KiB.".to_string(),
            ));
        }
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| ProtoError::Transport(format!("HTTP CONNECT reply read failed: {e}")))?;
        response.push(byte[0]);
    }

    let text = String::from_utf8_lossy(&response);
    let status_line = text.lines().next().unwrap_or_default();
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&code) {
        return Err(ProtoError::Transport(format!(
            "HTTP CONNECT proxy rejected tunnel: {status_line}"
        )));
    }
    Ok(())
}

/// Opens a TCP connection to `dest_host:dest_port`, optionally routing through
/// a configured SOCKS5, SOCKS4/4a, or HTTP CONNECT proxy within `timeout`.
pub async fn connect_tcp_maybe_proxied(
    dest_host: &str,
    dest_port: u16,
    proxy: Option<&ProxyConfig>,
    timeout: Duration,
) -> Result<TcpStream, ProtoError> {
    let clean_dest = validate_target_endpoint(dest_host, dest_port)?;
    let effective_timeout = if timeout.is_zero() {
        Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)
    } else {
        timeout
    };

    tokio::time::timeout(effective_timeout, async {
        match proxy {
            None | Some(ProxyConfig { kind: ProxyKind::None, .. }) => {
                let stream = TcpStream::connect((clean_dest, dest_port))
                    .await
                    .map_err(|e| {
                        ProtoError::Transport(format!(
                            "Could not connect to {clean_dest}:{dest_port}: {e}"
                        ))
                    })?;
                let _ = stream.set_nodelay(true);
                Ok(stream)
            }
            Some(cfg) => {
                let proxy_host = validate_target_endpoint(&cfg.host, cfg.port)?;
                let mut stream = TcpStream::connect((proxy_host, cfg.port))
                    .await
                    .map_err(|e| {
                        ProtoError::Transport(format!(
                            "Could not connect to proxy {proxy_host}:{}: {e}",
                            cfg.port
                        ))
                    })?;
                let _ = stream.set_nodelay(true);
                let creds = cfg
                    .username
                    .as_deref()
                    .filter(|u| !u.is_empty())
                    .map(|u| (u, cfg.password.as_deref().unwrap_or("")));
                match cfg.kind {
                    ProxyKind::None => unreachable!(),
                    ProxyKind::Socks5 => {
                        socks5_connect_on_stream(
                            &mut stream,
                            clean_dest,
                            dest_port,
                            creds,
                            cfg.remote_dns,
                        )
                        .await?;
                    }
                    ProxyKind::Socks4 => {
                        socks4_connect_on_stream(
                            &mut stream,
                            clean_dest,
                            dest_port,
                            cfg.username.as_deref().unwrap_or(""),
                            cfg.remote_dns,
                        )
                        .await?;
                    }
                    ProxyKind::HttpConnect => {
                        http_connect_on_stream(&mut stream, clean_dest, dest_port, creds).await?;
                    }
                    ProxyKind::Telnet => {
                        let tpl = cfg
                            .command
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .unwrap_or("connect %host %port");
                        let cmd = tpl
                            .replace("%host", clean_dest)
                            .replace("%port", &dest_port.to_string());
                        stream
                            .write_all(cmd.as_bytes())
                            .await
                            .map_err(|e| ProtoError::Transport(format!("Cannot write to the telnet proxy: {e}")))?;
                        if !cmd.ends_with("\r\n") && !cmd.ends_with('\n') {
                            stream
                                .write_all(b"\r\n")
                                .await
                                .map_err(|e| ProtoError::Transport(format!("Cannot write to the telnet proxy: {e}")))?;
                        }
                        stream
                            .flush()
                            .await
                            .map_err(|e| ProtoError::Transport(format!("Cannot flush the telnet proxy: {e}")))?;
                    }
                    ProxyKind::LocalCommand => {
                        return Err(ProtoError::Transport(
                            "This protocol connects through curl, which cannot run a local command proxy; use SOCKS4, SOCKS5 or HTTP, or a protocol this build serves with its own transport.".to_string(),
                        ));
                    }
                }
                Ok(stream)
            }
        }
    })
    .await
    .map_err(|_| {
        ProtoError::Transport(format!(
            "Timed out connecting to {clean_dest}:{dest_port}."
        ))
    })?
}

/// Opens an `AsyncStream` to `dest_host:dest_port`, supporting all proxy kinds
/// including `ProxyKind::LocalCommand` (`ProxyMethod=Cmd`).
pub async fn connect_stream_maybe_proxied(
    dest_host: &str,
    dest_port: u16,
    proxy: Option<&ProxyConfig>,
    timeout: Duration,
) -> Result<Box<dyn linscp_platform::AsyncStream>, ProtoError> {
    if let Some(cfg) = proxy.filter(|p| p.kind == ProxyKind::LocalCommand) {
        let clean_dest = validate_target_endpoint(dest_host, dest_port)?;
        let tpl = cfg
            .command
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                ProtoError::Transport(
                    "A local (Cmd) proxy needs a command: set ProxyTelnetCommand=COMMAND with %host and %port where the destination belongs.".to_string(),
                )
            })?;
        return linscp_platform::terminal::spawn_proxy_command_stream(tpl, clean_dest, dest_port)
            .map_err(|e| ProtoError::Transport(format!("Failed to start local command proxy: {e}")));
    }
    let tcp = connect_tcp_maybe_proxied(dest_host, dest_port, proxy, timeout).await?;
    Ok(Box::new(tcp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks5_packet_round_trips_ipv4_domain_ipv6_and_rejects_wildcard() {
        let v4 = build_socks5_connect_request("192.0.2.10", 22, true).unwrap();
        assert_eq!(
            parse_socks5_connect_request(&v4).unwrap(),
            ("192.0.2.10".to_string(), 22)
        );

        let dom = build_socks5_connect_request("internal.example", 8443, true).unwrap();
        assert_eq!(
            parse_socks5_connect_request(&dom).unwrap(),
            ("internal.example".to_string(), 8443)
        );

        let v6 = build_socks5_connect_request("[2001:db8::1]", 443, true).unwrap();
        assert_eq!(
            parse_socks5_connect_request(&v6).unwrap(),
            ("2001:db8::1".to_string(), 443)
        );

        assert!(build_socks5_connect_request("*", 22, true).is_err());
        assert!(build_socks5_connect_request("", 22, true).is_err());
        assert!(build_socks5_connect_request("example.com", 0, true).is_err());
    }
}
