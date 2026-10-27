//! SSH jump-host (`direct-tcpip`) tunnel, loopback SOCKS5h relay for non-SSH
//! destinations (FTP/FTPS/WebDAV/S3), and strict `-L`/`-R`/`-D` tunnel spec
//! parser porting `SshTunnel.{h,cpp}`.

use std::sync::Arc;

use russh::client;
use russh::ChannelStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::proxy::parse_socks5_connect_request;
use crate::ssh::{SshConnectConfig, SshConnection};
use crate::ProtoError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelType {
    Local,
    Remote,
    Dynamic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshTunnelSpec {
    pub kind: TunnelType,
    pub bind_address: String,
    pub bind_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

fn parse_strict_port(text: &str) -> Option<u16> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let val: u32 = text.parse().ok()?;
    if (1..=65535).contains(&val) {
        Some(val as u16)
    } else {
        None
    }
}

fn split_tunnel_tokens(spec: &str) -> Result<Vec<String>, ProtoError> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_brackets = false;
    for ch in spec.chars() {
        match ch {
            '[' if !in_brackets && cur.is_empty() => {
                in_brackets = true;
            }
            ']' if in_brackets => {
                in_brackets = false;
            }
            ':' if !in_brackets => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if in_brackets {
        return Err(ProtoError::Transport(format!(
            "Unclosed '[' in tunnel specification '{spec}'."
        )));
    }
    parts.push(cur);
    Ok(parts)
}

/// Parses an `ssh(1)`-style `-L`, `-R`, or `-D` forwarding specification with
/// strict port and host checks matching `ParseTunnelSpec` in `SshTunnel.cpp`.
pub fn parse_tunnel_spec(spec: &str, kind: TunnelType) -> Result<SshTunnelSpec, ProtoError> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(ProtoError::Transport(
            "Tunnel specification is empty.".to_string(),
        ));
    }
    let parts = split_tunnel_tokens(trimmed)?;
    match kind {
        TunnelType::Dynamic => match parts.as_slice() {
            [port_str] => {
                let bind_port = parse_strict_port(port_str).ok_or_else(|| {
                    ProtoError::Transport(format!("Invalid dynamic tunnel port '{port_str}'."))
                })?;
                Ok(SshTunnelSpec {
                    kind,
                    bind_address: String::new(),
                    bind_port,
                    remote_host: String::new(),
                    remote_port: 0,
                })
            }
            [bind_addr, port_str] => {
                let bind_port = parse_strict_port(port_str).ok_or_else(|| {
                    ProtoError::Transport(format!("Invalid dynamic tunnel port '{port_str}'."))
                })?;
                Ok(SshTunnelSpec {
                    kind,
                    bind_address: bind_addr.clone(),
                    bind_port,
                    remote_host: String::new(),
                    remote_port: 0,
                })
            }
            _ => Err(ProtoError::Transport(format!(
                "Invalid dynamic tunnel specification '{trimmed}' (expected [bind:]port)."
            ))),
        },
        TunnelType::Local | TunnelType::Remote => match parts.as_slice() {
            [bport, rhost, rport] => {
                let bind_port = parse_strict_port(bport).ok_or_else(|| {
                    ProtoError::Transport(format!("Invalid tunnel bind port '{bport}'."))
                })?;
                let remote_port = parse_strict_port(rport).ok_or_else(|| {
                    ProtoError::Transport(format!("Invalid tunnel destination port '{rport}'."))
                })?;
                if rhost.trim().is_empty() || rhost == "*" {
                    return Err(ProtoError::Transport(
                        "Tunnel destination host must not be empty or '*'.".to_string(),
                    ));
                }
                Ok(SshTunnelSpec {
                    kind,
                    bind_address: String::new(),
                    bind_port,
                    remote_host: rhost.clone(),
                    remote_port,
                })
            }
            [bind_addr, bport, rhost, rport] => {
                let bind_port = parse_strict_port(bport).ok_or_else(|| {
                    ProtoError::Transport(format!("Invalid tunnel bind port '{bport}'."))
                })?;
                let remote_port = parse_strict_port(rport).ok_or_else(|| {
                    ProtoError::Transport(format!("Invalid tunnel destination port '{rport}'."))
                })?;
                if rhost.trim().is_empty() || rhost == "*" {
                    return Err(ProtoError::Transport(
                        "Tunnel destination host must not be empty or '*'.".to_string(),
                    ));
                }
                Ok(SshTunnelSpec {
                    kind,
                    bind_address: bind_addr.clone(),
                    bind_port,
                    remote_host: rhost.clone(),
                    remote_port,
                })
            }
            _ => Err(ProtoError::Transport(format!(
                "Invalid tunnel specification '{trimmed}' (expected [bind:]port:host:hostport)."
            ))),
        },
    }
}

pub fn tunnel_ssh_flags(spec: &SshTunnelSpec) -> String {
    let bind_prefix = if spec.bind_address.is_empty() {
        String::new()
    } else if spec.bind_address.contains(':') {
        format!("[{}]:", spec.bind_address)
    } else {
        format!("{}:", spec.bind_address)
    };
    match spec.kind {
        TunnelType::Dynamic => format!("-D {}{}", bind_prefix, spec.bind_port),
        TunnelType::Local => {
            let rhost = if spec.remote_host.contains(':') {
                format!("[{}]", spec.remote_host)
            } else {
                spec.remote_host.clone()
            };
            format!(
                "-L {}{}:{}:{}",
                bind_prefix, spec.bind_port, rhost, spec.remote_port
            )
        }
        TunnelType::Remote => {
            let rhost = if spec.remote_host.contains(':') {
                format!("[{}]", spec.remote_host)
            } else {
                spec.remote_host.clone()
            };
            format!(
                "-R {}{}:{}:{}",
                bind_prefix, spec.bind_port, rhost, spec.remote_port
            )
        }
    }
}

/// Active loopback SOCKS5h relay forwarding every accepted `CONNECT` over a
/// fresh `direct-tcpip` channel on an authenticated bastion `SshConnection`.
pub struct Socks5JumpRelay {
    local_port: u16,
    shutdown_tx: watch::Sender<bool>,
    accept_task: JoinHandle<()>,
}

impl Socks5JumpRelay {
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub async fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.accept_task.await;
    }
}

/// Authenticated SSH jump-host (bastion) session capable of opening private
/// in-memory `direct-tcpip` streams (for SFTP/SCP/SSH) or a loopback-only
/// SOCKS5h relay (for FTP/FTPS/WebDAV/S3).
type TunnelWatchSignal = Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>;

pub struct SshJumpTunnel {
    ssh: Arc<SshConnection>,
    watcher_thread: std::sync::Mutex<Option<(TunnelWatchSignal, std::thread::JoinHandle<()>)>>,
}

impl SshJumpTunnel {
    pub async fn connect(mut bastion_cfg: SshConnectConfig) -> Result<Self, ProtoError> {
        bastion_cfg.role = "tunnel".to_string();
        let ssh = SshConnection::connect(&bastion_cfg)
            .await
            .map_err(|err| match err {
                ProtoError::HostKeyChallengeRequired { .. }
                | ProtoError::WeakHostKeyPolicy(_) => err,
                other => ProtoError::Transport(format!("SSH tunnel: {other}")),
            })?;
        let sig: TunnelWatchSignal =
            Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let sig_bg = Arc::clone(&sig);
        let handle = std::thread::Builder::new()
            .name("linscp-tunnel".to_string())
            .spawn(move || {
                let (lock, cvar) = &*sig_bg;
                if let Ok(mut done) = lock.lock() {
                    while !*done {
                        let Ok(next) = cvar.wait(done) else {
                            break;
                        };
                        done = next;
                    }
                }
            })
            .ok()
            .map(|jh| (sig, jh));
        Ok(Self {
            ssh: Arc::new(ssh),
            watcher_thread: std::sync::Mutex::new(handle),
        })
    }

    fn stop_watcher(&self) {
        if let Ok(mut guard) = self.watcher_thread.lock() {
            if let Some((sig, jh)) = guard.take() {
                let (lock, cvar) = &*sig;
                if let Ok(mut done) = lock.lock() {
                    *done = true;
                    cvar.notify_all();
                }
                let _ = jh.join();
            }
        }
    }

    pub fn observed_fingerprint(&self) -> &str {
        self.ssh.observed_fingerprint()
    }

    /// Opens an in-memory `direct-tcpip` stream to `dest_host:dest_port` with
    /// zero listening TCP sockets when `local_port == 0`. If `local_port > 0`,
    /// binds `127.0.0.1:<local_port>` for that single connection so local
    /// firewall rules naming `TunnelLocalPortNumber` observe it.
    pub async fn open_destination_stream(
        &self,
        dest_host: &str,
        dest_port: u16,
        local_port: u16,
    ) -> Result<Box<dyn linscp_platform::AsyncStream>, ProtoError> {
        if local_port == 0 {
            let stream: ChannelStream<client::Msg> =
                self.ssh.open_direct_tcpip_stream(dest_host, dest_port).await?;
            return Ok(Box::new(stream));
        }

        let listener = TcpListener::bind(("127.0.0.1", local_port))
            .await
            .map_err(|e| {
                ProtoError::Transport(format!(
                    "SSH tunnel forwarding to {dest_host}:{dest_port} failed: cannot bind TunnelLocalPortNumber 127.0.0.1:{local_port}: {e}"
                ))
            })?;
        let bound_addr = listener.local_addr().map_err(|e| {
            ProtoError::Transport(format!("Failed to read local tunnel address: {e}"))
        })?;
        let ssh = Arc::clone(&self.ssh);
        let target_host = dest_host.to_string();
        tokio::spawn(async move {
            if let Ok((mut accepted, _)) = listener.accept().await {
                drop(listener);
                if let Ok(mut remote) = ssh.open_direct_tcpip_stream(&target_host, dest_port).await
                {
                    let _ = tokio::io::copy_bidirectional(&mut accepted, &mut remote).await;
                }
            }
        });
        let client_sock = TcpStream::connect(bound_addr).await.map_err(|e| {
            ProtoError::Transport(format!("Failed to connect local jump port: {e}"))
        })?;
        let _ = client_sock.set_nodelay(true);
        Ok(Box::new(client_sock))
    }

    /// Starts a loopback-only (`127.0.0.1`) SOCKS5h listener whose `CONNECT`
    /// requests each open a fresh `direct-tcpip` channel on the jump host.
    pub async fn start_socks5_relay(&self, local_port: u16) -> Result<Socks5JumpRelay, ProtoError> {
        let listener = TcpListener::bind(("127.0.0.1", local_port))
            .await
            .map_err(|e| {
                ProtoError::Transport(format!(
                    "Failed to bind loopback SOCKS5 jump relay on 127.0.0.1:{local_port}: {e}"
                ))
            })?;
        let actual_port = listener
            .local_addr()
            .map_err(|e| ProtoError::Transport(format!("SOCKS5 local_addr failed: {e}")))?
            .port();

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let ssh = Arc::clone(&self.ssh);

        let accept_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        let Ok((stream, _peer)) = accepted else {
                            break;
                        };
                        let _ = stream.set_nodelay(true);
                        let ssh_conn = Arc::clone(&ssh);
                        tokio::spawn(async move {
                            let _ = handle_socks5_jump_client(stream, ssh_conn).await;
                        });
                    }
                }
            }
        });

        Ok(Socks5JumpRelay {
            local_port: actual_port,
            shutdown_tx,
            accept_task,
        })
    }

    pub async fn close(&self) -> Result<(), ProtoError> {
        let res = self.ssh.disconnect().await;
        self.stop_watcher();
        res
    }
}

impl Drop for SshJumpTunnel {
    fn drop(&mut self) {
        self.stop_watcher();
    }
}

async fn handle_socks5_jump_client(
    mut stream: TcpStream,
    ssh: Arc<SshConnection>,
) -> Result<(), ProtoError> {
    let mut greet = [0u8; 2];
    stream
        .read_exact(&mut greet)
        .await
        .map_err(|e| ProtoError::Transport(e.to_string()))?;
    if greet[0] != 0x05 || greet[1] == 0 {
        return Err(ProtoError::Transport("Invalid SOCKS5 greeting.".to_string()));
    }
    let mut methods = vec![0u8; greet[1] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|e| ProtoError::Transport(e.to_string()))?;
    if !methods.contains(&0x00) {
        let _ = stream.write_all(&[0x05, 0xff]).await;
        return Err(ProtoError::Transport(
            "SOCKS5 client did not offer No-Auth.".to_string(),
        ));
    }
    stream
        .write_all(&[0x05, 0x00])
        .await
        .map_err(|e| ProtoError::Transport(e.to_string()))?;

    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|e| ProtoError::Transport(e.to_string()))?;
    let mut req = Vec::from(hdr);
    match hdr[3] {
        0x01 => {
            let mut rest = [0u8; 6];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            req.extend_from_slice(&rest);
        }
        0x03 => {
            let mut dlen = [0u8; 1];
            stream
                .read_exact(&mut dlen)
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            req.push(dlen[0]);
            let mut rest = vec![0u8; dlen[0] as usize + 2];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            req.extend_from_slice(&rest);
        }
        0x04 => {
            let mut rest = [0u8; 18];
            stream
                .read_exact(&mut rest)
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            req.extend_from_slice(&rest);
        }
        _ => {
            let _ = stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(ProtoError::Transport("Unsupported SOCKS5 ATYP.".to_string()));
        }
    }

    let (dest_host, dest_port) = match parse_socks5_connect_request(&req) {
        Ok(target) => target,
        Err(err) => {
            let _ = stream
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(err);
        }
    };

    match ssh.open_direct_tcpip_stream(&dest_host, dest_port).await {
        Ok(mut channel_stream) => {
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            stream
                .flush()
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut channel_stream).await;
            Ok(())
        }
        Err(err) => {
            let _ = stream
                .write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_spec_parser_enforces_strict_ports_and_ipv6_brackets() {
        let local = parse_tunnel_spec("127.0.0.1:8080:[2001:db8::5]:443", TunnelType::Local)
            .expect("valid IPv6 local tunnel");
        assert_eq!(local.bind_address, "127.0.0.1");
        assert_eq!(local.bind_port, 8080);
        assert_eq!(local.remote_host, "2001:db8::5");
        assert_eq!(local.remote_port, 443);
        assert_eq!(
            tunnel_ssh_flags(&local),
            "-L 127.0.0.1:8080:[2001:db8::5]:443"
        );

        let dyn_spec = parse_tunnel_spec("1080", TunnelType::Dynamic).unwrap();
        assert_eq!(tunnel_ssh_flags(&dyn_spec), "-D 1080");

        assert!(parse_tunnel_spec("80x:example.com:80", TunnelType::Local).is_err());
        assert!(parse_tunnel_spec("70000:example.com:80", TunnelType::Local).is_err());
        assert!(parse_tunnel_spec("8080:*:80", TunnelType::Local).is_err());
    }
}
