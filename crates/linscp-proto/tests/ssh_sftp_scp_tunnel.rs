//! End-to-end loopback integration suite for Phase 2a & 2b (`ssh`, `sftp`,
//! `scp`, `tunnel`, `proxy`, and `gssapi`):
//! - Fail-closed host-key verification (unknown, changed, wildcard `*`, MD5 pin,
//!   and independent bastion vs destination challenges)
//! - Password, OpenSSH PEM, PuTTY `.ppk`, and SSH Agent (`AgentClient`) auth
//! - Full SFTP v3 lifecycle + OpenSSH `copy-data` and `check-file-name` extensions
//! - Native SCP (`scp -f` / `scp -t` + POSIX shell commands + traversal defense)
//! - SSH Jump Tunnel (`direct-tcpip` stream & loopback SOCKS5h relay)
//! - Client SOCKS5 (RFC 1929 auth) & HTTP CONNECT proxies

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use linscp_crypto::digests::{compute_digest, DigestAlgorithm};
use linscp_platform::AsyncStream;
use linscp_proto::gssapi::ensure_gssapi_available;
use linscp_proto::listing::{permissions_string, S_IFDIR, S_IFLNK, S_IFREG};
use linscp_proto::proxy::{ProxyConfig, ProxyKind};
use linscp_proto::scp::ScpSession;
use linscp_proto::sftp::{
    SftpClientSession, SftpPacketReader, SftpPacketWriter, SftpWireAttrs,
    SSH_FILEXFER_ATTR_ACMODTIME, SSH_FILEXFER_ATTR_PERMISSIONS, SSH_FILEXFER_ATTR_SIZE,
    SSH_FXF_APPEND, SSH_FXF_CREAT, SSH_FXF_TRUNC, SSH_FXP_ATTRS, SSH_FXP_CLOSE,
    SSH_FXP_DATA, SSH_FXP_EXTENDED, SSH_FXP_EXTENDED_REPLY, SSH_FXP_HANDLE, SSH_FXP_INIT,
    SSH_FXP_LSTAT, SSH_FXP_MKDIR, SSH_FXP_NAME, SSH_FXP_OPEN, SSH_FXP_OPENDIR, SSH_FXP_READ,
    SSH_FXP_READDIR, SSH_FXP_READLINK, SSH_FXP_REALPATH, SSH_FXP_REMOVE, SSH_FXP_RENAME,
    SSH_FXP_RMDIR, SSH_FXP_SETSTAT, SSH_FXP_STAT, SSH_FXP_STATUS, SSH_FXP_SYMLINK,
    SSH_FXP_VERSION, SSH_FXP_WRITE, SSH_FX_EOF, SSH_FX_NO_SUCH_FILE, SSH_FX_OK,
    SSH_FX_OP_UNSUPPORTED,
};
use linscp_proto::ssh::{SshAgentConnector, SshConnectConfig};
use linscp_proto::{download_bytes, upload_bytes, ProtoError, RemoteSession, TransferRequest};
use linscp_types::ProtocolScheme;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, Server as _, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
enum MemNode {
    Dir {
        mode: u32,
        mtime: u32,
    },
    File {
        data: Vec<u8>,
        mode: u32,
        mtime: u32,
    },
    Symlink {
        target: String,
        mtime: u32,
    },
}

struct MemFs {
    nodes: HashMap<String, MemNode>,
}

impl MemFs {
    fn new() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(
            "/".to_string(),
            MemNode::Dir {
                mode: 0o755,
                mtime: 1_760_000_000,
            },
        );
        nodes.insert(
            "/home".to_string(),
            MemNode::Dir {
                mode: 0o755,
                mtime: 1_760_000_000,
            },
        );
        nodes.insert(
            "/home/tester".to_string(),
            MemNode::Dir {
                mode: 0o755,
                mtime: 1_760_000_000,
            },
        );
        Self { nodes }
    }

    fn normalize(path: &str) -> String {
        if path.is_empty() || path == "." {
            return "/home/tester".to_string();
        }
        let abs = if let Some(rel) = path.strip_prefix("./") {
            format!("/home/tester/{rel}")
        } else if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/home/tester/{path}")
        };
        let mut segs: Vec<&str> = Vec::new();
        for seg in abs.split('/') {
            match seg {
                "" | "." => {}
                ".." => {
                    let _ = segs.pop();
                }
                s => segs.push(s),
            }
        }
        if segs.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", segs.join("/"))
        }
    }

    fn resolve_target(&self, path: &str) -> Option<String> {
        let norm = Self::normalize(path);
        match self.nodes.get(&norm)? {
            MemNode::Symlink { target, .. } => {
                let resolved = if target.starts_with('/') {
                    Self::normalize(target)
                } else {
                    let parent = norm.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                    Self::normalize(&format!("{parent}/{target}"))
                };
                if self.nodes.contains_key(&resolved) {
                    Some(resolved)
                } else {
                    None
                }
            }
            _ => Some(norm),
        }
    }

    fn attrs_for(&self, path: &str, follow_links: bool) -> Option<SftpWireAttrs> {
        let key = if follow_links {
            self.resolve_target(path)?
        } else {
            Self::normalize(path)
        };
        let node = self.nodes.get(&key)?;
        match node {
            MemNode::Dir { mode, mtime } => Some(SftpWireAttrs {
                flags: SSH_FILEXFER_ATTR_SIZE
                    | SSH_FILEXFER_ATTR_PERMISSIONS
                    | SSH_FILEXFER_ATTR_ACMODTIME,
                size: 0,
                uid: 1000,
                gid: 1000,
                permissions: S_IFDIR | (*mode & 0o7777),
                atime: *mtime,
                mtime: *mtime,
            }),
            MemNode::File { data, mode, mtime } => Some(SftpWireAttrs {
                flags: SSH_FILEXFER_ATTR_SIZE
                    | SSH_FILEXFER_ATTR_PERMISSIONS
                    | SSH_FILEXFER_ATTR_ACMODTIME,
                size: data.len() as u64,
                uid: 1000,
                gid: 1000,
                permissions: S_IFREG | (*mode & 0o7777),
                atime: *mtime,
                mtime: *mtime,
            }),
            MemNode::Symlink { target, mtime } => Some(SftpWireAttrs {
                flags: SSH_FILEXFER_ATTR_SIZE
                    | SSH_FILEXFER_ATTR_PERMISSIONS
                    | SSH_FILEXFER_ATTR_ACMODTIME,
                size: target.len() as u64,
                uid: 1000,
                gid: 1000,
                permissions: S_IFLNK | 0o777,
                atime: *mtime,
                mtime: *mtime,
            }),
        }
    }

    fn children_of(&self, dir: &str) -> Vec<(String, SftpWireAttrs, Option<String>)> {
        let norm = Self::normalize(dir);
        let prefix = if norm == "/" {
            "/".to_string()
        } else {
            format!("{norm}/")
        };
        let mut out = Vec::new();
        for (k, v) in &self.nodes {
            if k == &norm {
                continue;
            }
            if let Some(rest) = k.strip_prefix(&prefix) {
                if !rest.is_empty() && !rest.contains('/') {
                    let sym_target = match v {
                        MemNode::Symlink { target, .. } => Some(target.clone()),
                        _ => None,
                    };
                    if let Some(attrs) = self.attrs_for(k, false) {
                        out.push((rest.to_string(), attrs, sym_target));
                    }
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

#[derive(Clone)]
struct MockSshServer {
    fs: Arc<Mutex<MemFs>>,
    allowed_user: String,
    allowed_password: String,
    allowed_pubkey: PublicKey,
    allow_forwarding: bool,
}

impl russh::server::Server for MockSshServer {
    type Handler = MockSshSession;

    fn new_client(&mut self, _peer: Option<SocketAddr>) -> Self::Handler {
        MockSshSession {
            server: self.clone(),
            channels: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct MockSshSession {
    server: MockSshServer,
    channels: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl russh::server::Handler for MockSshSession {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if user == self.server.allowed_user && password == self.server.allowed_password {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if user == self.server.allowed_user
            && key.public_key.key_data() == self.server.allowed_pubkey.key_data()
        {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.lock().await.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if !self.server.allow_forwarding {
            return Ok(());
        }
        match TcpStream::connect((host_to_connect, port_to_connect as u16)).await {
            Ok(mut target_tcp) => {
                let _ = target_tcp.set_nodelay(true);
                reply.accept().await;
                let mut ssh_stream = channel.into_stream();
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut ssh_stream, &mut target_tcp).await;
                });
            }
            Err(_) => {}
        }
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            if let Some(channel) = self.channels.lock().await.remove(&channel_id) {
                session.channel_success(channel_id)?;
                let fs = Arc::clone(&self.server.fs);
                tokio::spawn(async move {
                    let _ = serve_mock_sftp(channel.into_stream(), fs).await;
                });
                return Ok(());
            }
        }
        session.channel_failure(channel_id)?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).into_owned();
        let Some(channel) = self.channels.lock().await.remove(&channel_id) else {
            session.channel_failure(channel_id)?;
            return Ok(());
        };
        session.channel_success(channel_id)?;
        let fs = Arc::clone(&self.server.fs);
        tokio::spawn(async move {
            handle_mock_exec(channel, cmd, fs).await;
        });
        Ok(())
    }
}

fn unquote_shell_args(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut cur = String::new();
    let mut in_sq = false;
    let mut chars = cmd.chars().peekable();
    let mut had_token = false;

    while let Some(ch) = chars.next() {
        if in_sq {
            if ch == '\'' {
                in_sq = false;
            } else {
                cur.push(ch);
            }
        } else if ch == '\'' {
            in_sq = true;
            had_token = true;
        } else if ch == '\\' {
            if let Some(nxt) = chars.next() {
                cur.push(nxt);
                had_token = true;
            }
        } else if ch.is_ascii_whitespace() {
            if had_token || !cur.is_empty() {
                args.push(std::mem::take(&mut cur));
                had_token = false;
            }
        } else {
            cur.push(ch);
            had_token = true;
        }
    }
    if had_token || !cur.is_empty() {
        args.push(cur);
    }
    args
}

fn format_ls_line(name: &str, attrs: &SftpWireAttrs, sym_target: Option<&str>) -> String {
    let pstr = permissions_string(attrs.permissions);
    let display = match sym_target {
        Some(t) => format!("{name} -> {t}"),
        None => name.to_string(),
    };
    format!(
        "{pstr} 1 tester tester {} 2026-03-15 12:00:00.000000000 +0000 {display}\n",
        attrs.size
    )
}

async fn handle_mock_exec(channel: Channel<Msg>, cmd: String, fs: Arc<Mutex<MemFs>>) {
    let tokens = unquote_shell_args(&cmd);
    let mut idx = 0usize;
    if tokens.get(idx).map(String::as_str) == Some("env") {
        idx += 1;
        while tokens.get(idx).is_some_and(|t| t.contains('=')) {
            idx += 1;
        }
    }
    let prog = tokens.get(idx).map(String::as_str).unwrap_or("");
    let args = &tokens[(idx + 1).min(tokens.len())..];

    if prog == "scp" {
        let is_source = args.iter().any(|a| a == "-f");
        let is_sink = args.iter().any(|a| a == "-t");
        let preserve = args.iter().any(|a| a == "-p");
        let target = args.last().cloned().unwrap_or_default();
        let mut stream = channel.into_stream();
        if is_source {
            let _ = run_mock_scp_source(&mut stream, &target, preserve, &fs).await;
        } else if is_sink {
            let _ = run_mock_scp_sink(&mut stream, &target, &fs).await;
        }
        let _ = stream.shutdown().await;
        return;
    }

    let mut code = 0u32;
    let mut stdout = String::new();
    let mut stderr = String::new();

    match prog {
        "pwd" => {
            stdout.push_str("/home/tester\n");
        }
        "ls" => {
            let is_dir_self = args.iter().any(|a| a == "-d");
            let path = args.last().map(String::as_str).unwrap_or(".");
            let guard = fs.lock().await;
            let norm = MemFs::normalize(path);
            if is_dir_self {
                match guard.attrs_for(&norm, false) {
                    Some(attrs) => {
                        let sym = match guard.nodes.get(&norm) {
                            Some(MemNode::Symlink { target, .. }) => Some(target.as_str()),
                            _ => None,
                        };
                        stdout.push_str(&format_ls_line(&norm, &attrs, sym));
                    }
                    None => {
                        code = 2;
                        stderr.push_str(&format!("ls: cannot access '{path}': No such file or directory\n"));
                    }
                }
            } else if matches!(guard.nodes.get(&norm), Some(MemNode::Dir { .. })) {
                stdout.push_str("total 4\n");
                for (name, attrs, sym) in guard.children_of(&norm) {
                    stdout.push_str(&format_ls_line(&name, &attrs, sym.as_deref()));
                }
            } else {
                code = 2;
                stderr.push_str(&format!("ls: cannot access '{path}': No such file or directory\n"));
            }
        }
        "mkdir" => {
            let path = args.last().map(String::as_str).unwrap_or("");
            fs.lock().await.nodes.insert(
                MemFs::normalize(path),
                MemNode::Dir {
                    mode: 0o755,
                    mtime: 1_760_000_000,
                },
            );
        }
        "rm" => {
            let path = args.last().map(String::as_str).unwrap_or("");
            fs.lock().await.nodes.remove(&MemFs::normalize(path));
        }
        "rmdir" => {
            let path = args.last().map(String::as_str).unwrap_or("");
            let norm = MemFs::normalize(path);
            let mut guard = fs.lock().await;
            if guard.children_of(&norm).is_empty() {
                guard.nodes.remove(&norm);
            } else {
                code = 1;
                stderr.push_str("rmdir: Directory not empty\n");
            }
        }
        "mv" => {
            if args.len() >= 2 {
                let dst = MemFs::normalize(&args[args.len() - 1]);
                let src = MemFs::normalize(&args[args.len() - 2]);
                let mut guard = fs.lock().await;
                if let Some(node) = guard.nodes.remove(&src) {
                    guard.nodes.insert(dst, node);
                } else {
                    code = 1;
                    stderr.push_str("mv: No such file or directory\n");
                }
            }
        }
        "cp" => {
            if args.len() >= 2 {
                let dst = MemFs::normalize(&args[args.len() - 1]);
                let src = MemFs::normalize(&args[args.len() - 2]);
                let mut guard = fs.lock().await;
                if let Some(node) = guard.nodes.get(&src).cloned() {
                    guard.nodes.insert(dst, node);
                } else {
                    code = 1;
                    stderr.push_str("cp: No such file or directory\n");
                }
            }
        }
        "chmod" => {
            if args.len() >= 2 {
                let path = MemFs::normalize(&args[args.len() - 1]);
                let mode_str = &args[0];
                let parsed_mode = u32::from_str_radix(mode_str, 8).unwrap_or(0o644);
                let mut guard = fs.lock().await;
                match guard.nodes.get_mut(&path) {
                    Some(MemNode::File { mode, .. }) | Some(MemNode::Dir { mode, .. }) => {
                        *mode = parsed_mode;
                    }
                    _ => {
                        code = 1;
                        stderr.push_str("chmod: No such file or directory\n");
                    }
                }
            }
        }
        "touch" => {}
        "ln" => {
            if args.len() >= 2 {
                let link_path = MemFs::normalize(&args[args.len() - 1]);
                let target = args[args.len() - 2].clone();
                fs.lock().await.nodes.insert(
                    link_path,
                    MemNode::Symlink {
                        target,
                        mtime: 1_760_000_000,
                    },
                );
            }
        }
        "sha256sum" => {
            let path = MemFs::normalize(args.last().map(String::as_str).unwrap_or(""));
            let guard = fs.lock().await;
            if let Some(MemNode::File { data, .. }) = guard.nodes.get(&path) {
                let hex: String = compute_digest(DigestAlgorithm::Sha256, data)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                stdout.push_str(&format!("{hex}  {path}\n"));
            } else {
                code = 1;
                stderr.push_str("sha256sum: No such file\n");
            }
        }
        _ => {
            code = 127;
            stderr.push_str(&format!("{prog}: command not found\n"));
        }
    }

    if !stdout.is_empty() {
        let _ = channel.data(stdout.as_bytes()).await;
    }
    if !stderr.is_empty() {
        let _ = channel.extended_data(1, stderr.as_bytes()).await;
    }
    let _ = channel.exit_status(code).await;
    let _ = channel.eof().await;
    let _ = channel.close().await;
}

async fn run_mock_scp_source(
    stream: &mut ChannelStream<Msg>,
    target: &str,
    preserve: bool,
    fs: &Arc<Mutex<MemFs>>,
) -> Result<(), std::io::Error> {
    let mut ack = [0u8; 1];
    stream.read_exact(&mut ack).await?;

    // Special path simulating a hostile SCP server attempting `../` traversal!
    if target.ends_with("malicious_escape") {
        stream.write_all(b"C0644 5 ../pwned.txt\n").await?;
        stream.flush().await?;
        return Ok(());
    }

    let norm = MemFs::normalize(target);
    let node_opt = fs.lock().await.nodes.get(&norm).cloned();
    let Some(MemNode::File { data, mode, mtime }) = node_opt else {
        stream.write_all(b"\x01scp: No such file or directory\n").await?;
        stream.flush().await?;
        return Ok(());
    };
    if preserve {
        stream
            .write_all(format!("T{mtime} 0 {mtime} 0\n").as_bytes())
            .await?;
        stream.flush().await?;
        stream.read_exact(&mut ack).await?;
    }
    let leaf = norm.rsplit('/').next().unwrap_or("file");
    stream
        .write_all(format!("C{:04o} {} {leaf}\n", mode & 0o7777, data.len()).as_bytes())
        .await?;
    stream.flush().await?;
    stream.read_exact(&mut ack).await?;

    stream.write_all(&data).await?;
    stream.write_all(&[0u8]).await?;
    stream.flush().await?;
    let _ = stream.read_exact(&mut ack).await;
    Ok(())
}

async fn run_mock_scp_sink(
    stream: &mut ChannelStream<Msg>,
    target: &str,
    fs: &Arc<Mutex<MemFs>>,
) -> Result<(), std::io::Error> {
    stream.write_all(&[0u8]).await?;
    stream.flush().await?;

    let mut mtime = 1_760_000_000u32;
    loop {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            if stream.read_exact(&mut b).await.is_err() {
                return Ok(());
            }
            line.push(b[0]);
            if b[0] == b'\n' {
                break;
            }
        }
        let s = String::from_utf8_lossy(&line);
        let trimmed = s.trim_end_matches(['\r', '\n']);
        if let Some(rest) = trimmed.strip_prefix('T') {
            mtime = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(mtime);
            stream.write_all(&[0u8]).await?;
            stream.flush().await?;
        } else if let Some(rest) = trimmed.strip_prefix('C') {
            let mut sp = rest.splitn(3, ' ');
            let mode = u32::from_str_radix(sp.next().unwrap_or("0644"), 8).unwrap_or(0o644);
            let sz: usize = sp.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            let leaf = sp.next().unwrap_or("upload");
            stream.write_all(&[0u8]).await?;
            stream.flush().await?;

            let mut data = vec![0u8; sz];
            stream.read_exact(&mut data).await?;
            let mut trailing = [0u8; 1];
            stream.read_exact(&mut trailing).await?;

            let dest_norm = MemFs::normalize(target);
            let mut guard = fs.lock().await;
            let final_path = if matches!(guard.nodes.get(&dest_norm), Some(MemNode::Dir { .. })) {
                MemFs::normalize(&format!("{dest_norm}/{leaf}"))
            } else {
                dest_norm
            };
            guard.nodes.insert(
                final_path,
                MemNode::File {
                    data,
                    mode,
                    mtime,
                },
            );
            drop(guard);

            stream.write_all(&[0u8]).await?;
            stream.flush().await?;
            return Ok(());
        } else {
            return Ok(());
        }
    }
}

enum OpenSftpHandle {
    File { path: String, pflags: u32 },
    Dir { entries: Vec<(String, SftpWireAttrs)>, returned: bool },
}

fn sftp_status_packet(req_id: u32, code: u32, msg: &str) -> Vec<u8> {
    let mut w = SftpPacketWriter::new();
    w.push_u32(code);
    w.push_str(msg);
    w.push_str("en");
    w.into_framed_packet(SSH_FXP_STATUS, Some(req_id))
}

async fn serve_mock_sftp(
    mut stream: ChannelStream<Msg>,
    fs: Arc<Mutex<MemFs>>,
) -> Result<(), std::io::Error> {
    let mut handles: HashMap<String, OpenSftpHandle> = HashMap::new();
    let mut next_h = 1u64;

    loop {
        let mut len_b = [0u8; 4];
        if stream.read_exact(&mut len_b).await.is_err() {
            return Ok(());
        }
        let len = u32::from_be_bytes(len_b) as usize;
        let mut pkt = vec![0u8; len];
        stream.read_exact(&mut pkt).await?;
        let ptype = pkt[0];
        let body = &pkt[1..];

        if ptype == SSH_FXP_INIT {
            let mut w = SftpPacketWriter::new();
            w.push_u32(3);
            w.push_str("posix-rename@openssh.com");
            w.push_str("1");
            w.push_str("copy-data");
            w.push_str("1");
            let reply = w.into_framed_packet(SSH_FXP_VERSION, None);
            stream.write_all(&reply).await?;
            stream.flush().await?;
            continue;
        }

        let mut r = SftpPacketReader::new(body);
        let Ok(req_id) = r.read_u32() else {
            return Ok(());
        };

        let response = match ptype {
            SSH_FXP_REALPATH => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let norm = MemFs::normalize(&raw);
                let mut w = SftpPacketWriter::new();
                w.push_u32(1);
                w.push_str(&norm);
                w.push_str(&norm);
                w.push_attrs(&SftpWireAttrs::default());
                w.into_framed_packet(SSH_FXP_NAME, Some(req_id))
            }
            SSH_FXP_STAT | SSH_FXP_LSTAT => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let follow = ptype == SSH_FXP_STAT;
                match fs.lock().await.attrs_for(&raw, follow) {
                    Some(attrs) => {
                        let mut w = SftpPacketWriter::new();
                        w.push_attrs(&attrs);
                        w.into_framed_packet(SSH_FXP_ATTRS, Some(req_id))
                    }
                    None => sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "No such file"),
                }
            }
            SSH_FXP_OPENDIR => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let norm = MemFs::normalize(&raw);
                let guard = fs.lock().await;
                if matches!(guard.nodes.get(&norm), Some(MemNode::Dir { .. })) {
                    let entries = guard
                        .children_of(&norm)
                        .into_iter()
                        .map(|(n, a, _)| (n, a))
                        .collect();
                    let hid = format!("d{next_h}");
                    next_h += 1;
                    handles.insert(
                        hid.clone(),
                        OpenSftpHandle::Dir {
                            entries,
                            returned: false,
                        },
                    );
                    let mut w = SftpPacketWriter::new();
                    w.push_str(&hid);
                    w.into_framed_packet(SSH_FXP_HANDLE, Some(req_id))
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "No such directory")
                }
            }
            SSH_FXP_READDIR => {
                let hid = r.read_string_lossy().unwrap_or_default();
                match handles.get_mut(&hid) {
                    Some(OpenSftpHandle::Dir { entries, returned }) if !*returned => {
                        *returned = true;
                        let mut w = SftpPacketWriter::new();
                        w.push_u32(entries.len() as u32);
                        for (name, attrs) in entries {
                            w.push_str(name);
                            w.push_str(name);
                            w.push_attrs(attrs);
                        }
                        w.into_framed_packet(SSH_FXP_NAME, Some(req_id))
                    }
                    Some(OpenSftpHandle::Dir { .. }) => sftp_status_packet(req_id, SSH_FX_EOF, "EOF"),
                    _ => sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Invalid handle"),
                }
            }
            SSH_FXP_OPEN => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let pflags = r.read_u32().unwrap_or(0);
                let attrs = r.read_attrs().unwrap_or_default();
                let norm = MemFs::normalize(&raw);
                let mut guard = fs.lock().await;
                let exists = guard.nodes.contains_key(&norm);
                if (pflags & SSH_FXF_CREAT) != 0 {
                    if !exists || (pflags & SSH_FXF_TRUNC) != 0 {
                        let mode = if (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 {
                            attrs.permissions & 0o7777
                        } else {
                            0o644
                        };
                        guard.nodes.insert(
                            norm.clone(),
                            MemNode::File {
                                data: Vec::new(),
                                mode,
                                mtime: 1_760_000_000,
                            },
                        );
                    }
                } else if !exists {
                    drop(guard);
                    let pkt = sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "No such file");
                    stream.write_all(&pkt).await?;
                    stream.flush().await?;
                    continue;
                }
                drop(guard);
                let hid = format!("f{next_h}");
                next_h += 1;
                handles.insert(
                    hid.clone(),
                    OpenSftpHandle::File {
                        path: norm,
                        pflags,
                    },
                );
                let mut w = SftpPacketWriter::new();
                w.push_str(&hid);
                w.into_framed_packet(SSH_FXP_HANDLE, Some(req_id))
            }
            SSH_FXP_READ => {
                let hid = r.read_string_lossy().unwrap_or_default();
                let offset = r.read_u64().unwrap_or(0) as usize;
                let max_len = r.read_u32().unwrap_or(0) as usize;
                if let Some(OpenSftpHandle::File { path, .. }) = handles.get(&hid) {
                    let guard = fs.lock().await;
                    if let Some(MemNode::File { data, .. }) = guard.nodes.get(path) {
                        if offset >= data.len() {
                            sftp_status_packet(req_id, SSH_FX_EOF, "EOF")
                        } else {
                            let end = (offset + max_len).min(data.len());
                            let mut w = SftpPacketWriter::new();
                            w.push_bytes(&data[offset..end]);
                            w.into_framed_packet(SSH_FXP_DATA, Some(req_id))
                        }
                    } else {
                        sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                    }
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Invalid handle")
                }
            }
            SSH_FXP_WRITE => {
                let hid = r.read_string_lossy().unwrap_or_default();
                let offset = r.read_u64().unwrap_or(0) as usize;
                let chunk = r.read_bytes().unwrap_or(&[]).to_vec();
                if let Some(OpenSftpHandle::File { path, pflags }) = handles.get(&hid) {
                    let mut guard = fs.lock().await;
                    if let Some(MemNode::File { data, .. }) = guard.nodes.get_mut(path) {
                        if (*pflags & SSH_FXF_APPEND) != 0 && offset >= data.len() {
                            data.extend_from_slice(&chunk);
                        } else {
                            if offset + chunk.len() > data.len() {
                                data.resize(offset + chunk.len(), 0);
                            }
                            data[offset..offset + chunk.len()].copy_from_slice(&chunk);
                        }
                        sftp_status_packet(req_id, SSH_FX_OK, "OK")
                    } else {
                        sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                    }
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Invalid handle")
                }
            }
            SSH_FXP_CLOSE => {
                let hid = r.read_string_lossy().unwrap_or_default();
                handles.remove(&hid);
                sftp_status_packet(req_id, SSH_FX_OK, "OK")
            }
            SSH_FXP_MKDIR => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let attrs = r.read_attrs().unwrap_or_default();
                let mode = if (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 {
                    attrs.permissions & 0o7777
                } else {
                    0o755
                };
                fs.lock().await.nodes.insert(
                    MemFs::normalize(&raw),
                    MemNode::Dir {
                        mode,
                        mtime: 1_760_000_000,
                    },
                );
                sftp_status_packet(req_id, SSH_FX_OK, "OK")
            }
            SSH_FXP_RMDIR | SSH_FXP_REMOVE => {
                let raw = r.read_string_lossy().unwrap_or_default();
                let norm = MemFs::normalize(&raw);
                if fs.lock().await.nodes.remove(&norm).is_some() {
                    sftp_status_packet(req_id, SSH_FX_OK, "OK")
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                }
            }
            SSH_FXP_RENAME => {
                let from = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                let to = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                let mut guard = fs.lock().await;
                if let Some(node) = guard.nodes.remove(&from) {
                    guard.nodes.insert(to, node);
                    sftp_status_packet(req_id, SSH_FX_OK, "OK")
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                }
            }
            SSH_FXP_SETSTAT => {
                let path = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                let attrs = r.read_attrs().unwrap_or_default();
                let mut guard = fs.lock().await;
                match guard.nodes.get_mut(&path) {
                    Some(MemNode::File { mode, mtime, .. })
                    | Some(MemNode::Dir { mode, mtime }) => {
                        if (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 {
                            *mode = attrs.permissions & 0o7777;
                        }
                        if (attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0 {
                            *mtime = attrs.mtime;
                        }
                        sftp_status_packet(req_id, SSH_FX_OK, "OK")
                    }
                    _ => sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing"),
                }
            }
            SSH_FXP_SYMLINK => {
                let target = r.read_string_lossy().unwrap_or_default();
                let link_path = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                fs.lock().await.nodes.insert(
                    link_path,
                    MemNode::Symlink {
                        target,
                        mtime: 1_760_000_000,
                    },
                );
                sftp_status_packet(req_id, SSH_FX_OK, "OK")
            }
            SSH_FXP_READLINK => {
                let link_path = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                let guard = fs.lock().await;
                if let Some(MemNode::Symlink { target, .. }) = guard.nodes.get(&link_path) {
                    let mut w = SftpPacketWriter::new();
                    w.push_u32(1);
                    w.push_str(target);
                    w.push_str(target);
                    w.push_attrs(&SftpWireAttrs::default());
                    w.into_framed_packet(SSH_FXP_NAME, Some(req_id))
                } else {
                    sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Not a symlink")
                }
            }
            SSH_FXP_EXTENDED => {
                let ext_name = r.read_string_lossy().unwrap_or_default();
                match ext_name.as_str() {
                    "posix-rename@openssh.com" => {
                        let from = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                        let to = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                        let mut guard = fs.lock().await;
                        if let Some(node) = guard.nodes.remove(&from) {
                            guard.nodes.insert(to, node);
                            sftp_status_packet(req_id, SSH_FX_OK, "OK")
                        } else {
                            sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                        }
                    }
                    "copy-data" => {
                        let rh = r.read_string_lossy().unwrap_or_default();
                        let read_off = r.read_u64().unwrap_or(0) as usize;
                        let read_len = r.read_u64().unwrap_or(0) as usize;
                        let wh = r.read_string_lossy().unwrap_or_default();
                        let write_off = r.read_u64().unwrap_or(0) as usize;
                        let src_path = match handles.get(&rh) {
                            Some(OpenSftpHandle::File { path, .. }) => Some(path.clone()),
                            _ => None,
                        };
                        let dst_path = match handles.get(&wh) {
                            Some(OpenSftpHandle::File { path, .. }) => Some(path.clone()),
                            _ => None,
                        };
                        match (src_path, dst_path) {
                            (Some(sp), Some(dp)) => {
                                let mut guard = fs.lock().await;
                                let copied = match guard.nodes.get(&sp) {
                                    Some(MemNode::File { data, .. }) => {
                                        let end = if read_len == 0 {
                                            data.len()
                                        } else {
                                            (read_off + read_len).min(data.len())
                                        };
                                        Some(data[read_off.min(end)..end].to_vec())
                                    }
                                    _ => None,
                                };
                                match (copied, guard.nodes.get_mut(&dp)) {
                                    (Some(bytes), Some(MemNode::File { data, .. })) => {
                                        if write_off + bytes.len() > data.len() {
                                            data.resize(write_off + bytes.len(), 0);
                                        }
                                        data[write_off..write_off + bytes.len()]
                                            .copy_from_slice(&bytes);
                                        sftp_status_packet(req_id, SSH_FX_OK, "OK")
                                    }
                                    _ => sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing"),
                                }
                            }
                            _ => sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Bad handle"),
                        }
                    }
                    "check-file-name" => {
                        let path = MemFs::normalize(&r.read_string_lossy().unwrap_or_default());
                        let alg_list = r.read_string_lossy().unwrap_or_default();
                        let first_alg = alg_list.split(',').next().unwrap_or("sha256");
                        let parsed_alg =
                            DigestAlgorithm::parse(first_alg).unwrap_or(DigestAlgorithm::Sha256);
                        let guard = fs.lock().await;
                        if let Some(MemNode::File { data, .. }) = guard.nodes.get(&path) {
                            let digest = compute_digest(parsed_alg, data);
                            let mut w = SftpPacketWriter::new();
                            w.push_str(parsed_alg.canonical_name());
                            w.push_u32(0);
                            w.push_bytes(&digest);
                            w.into_framed_packet(SSH_FXP_EXTENDED_REPLY, Some(req_id))
                        } else {
                            sftp_status_packet(req_id, SSH_FX_NO_SUCH_FILE, "Missing")
                        }
                    }
                    _ => sftp_status_packet(req_id, SSH_FX_OP_UNSUPPORTED, "Unsupported"),
                }
            }
            _ => sftp_status_packet(req_id, SSH_FX_OP_UNSUPPORTED, "Unsupported"),
        };

        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

async fn start_mock_ssh_server(
    host_seed: u8,
    user_pubkey: PublicKey,
    allow_forwarding: bool,
) -> (u16, String, String, Arc<Mutex<MemFs>>) {
    let host_key = common::generate_ed25519_ssh_key(host_seed, "server-host-key");
    let fs = Arc::new(Mutex::new(MemFs::new()));
    let mut server = MockSshServer {
        fs: Arc::clone(&fs),
        allowed_user: "tester".to_string(),
        allowed_password: "correct-horse-battery".to_string(),
        allowed_pubkey: user_pubkey,
        allow_forwarding,
    };
    let cfg = Arc::new(russh::server::Config {
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key.private_key],
        nodelay: true,
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ssh");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = server.run_on_socket(cfg, &listener).await;
    });
    (
        port,
        host_key.sha256_fingerprint,
        host_key.md5_fingerprint,
        fs,
    )
}

#[derive(Clone)]
struct DummyAgentPolicy;
impl russh::keys::agent::server::Agent for DummyAgentPolicy {}

struct DuplexAgentConnector {
    user_key: PrivateKey,
}

#[async_trait]
impl SshAgentConnector for DuplexAgentConnector {
    async fn connect(&self) -> Result<Option<Box<dyn AsyncStream>>, ProtoError> {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (agent_conn, agent_client_setup) = tokio::io::duplex(64 * 1024);

        // Minimal two-connection stream yielding `agent_conn` (to preload key) then `server_side`
        let key = self.user_key.clone();
        let stream_items = vec![Ok::<_, std::io::Error>(agent_conn), Ok(server_side)];
        tokio::spawn(async move {
            let incoming = TestVecStream {
                items: std::collections::VecDeque::from(stream_items),
            };
            let _ = russh::keys::agent::server::serve(incoming, DummyAgentPolicy).await;
        });

        let mut preload = russh::keys::agent::client::AgentClient::connect(agent_client_setup);
        preload
            .add_identity(&key, &[])
            .await
            .map_err(|e| ProtoError::Transport(format!("preload agent key: {e}")))?;
        drop(preload);

        Ok(Some(Box::new(client_side)))
    }
}

struct TestVecStream<T> {
    items: std::collections::VecDeque<T>,
}

impl<T: Unpin> futures_core::Stream for TestVecStream<T> {
    type Item = T;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(self.items.pop_front())
    }
}

#[tokio::test]
async fn sftp_full_lifecycle_auth_modes_and_extensions_succeed() {
    let user_key = common::generate_ed25519_ssh_key(0x77, "tester@linscp");
    let (port, host_sha256, host_md5, _fs) =
        start_mock_ssh_server(0x11, user_key.private_key.public_key().clone(), false).await;

    // 1. Fail-closed host-key checks: wildcard `*`, unknown key, and mismatched pin
    let mut bad_cfg = SshConnectConfig {
        tab_id: 42,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        password: Some(Zeroizing::new("correct-horse-battery".to_string())),
        pinned_host_key: Some("*".to_string()),
        ..Default::default()
    };
    assert_eq!(
        SftpClientSession::connect(ProtocolScheme::Sftp, &bad_cfg, None, 0)
            .await
            .err(),
        Some(ProtoError::WeakHostKeyPolicy("*".to_string()))
    );

    bad_cfg.pinned_host_key = None;
    match SftpClientSession::connect(ProtocolScheme::Sftp, &bad_cfg, None, 0).await {
        Err(ProtoError::HostKeyChallengeRequired {
            role,
            state,
            fingerprint,
            ..
        }) => {
            assert_eq!(role, "destination");
            assert_eq!(state, "unknown");
            assert_eq!(fingerprint, host_sha256);
        }
        other => panic!("expected unknown host key challenge, got {}", other.err().unwrap()),
    }

    // 2. Connect with SSH Agent over duplex stream + legacy MD5 host-key pin!
    let agent_cfg = SshConnectConfig {
        tab_id: 1,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port,
        username: "tester".to_string(),
        pinned_host_key: Some(host_md5),
        try_agent: true,
        agent_connector: Some(Arc::new(DuplexAgentConnector {
            user_key: user_key.private_key.clone(),
        })),
        ..Default::default()
    };
    let sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &agent_cfg, None, 0)
        .await
        .expect("SFTP agent auth + MD5 hostkey");

    assert_eq!(sftp.pwd().await.unwrap(), "/home/tester");
    sftp.mkdir("/home/tester/docs").await.unwrap();

    // Upload initial part, then resume at byte offset, then append!
    let part1 = b"Hello, pure-Rust ";
    let part2 = b"SFTP world!";
    upload_bytes(&sftp, "/home/tester/docs/note.txt", part1, TransferRequest::default())
        .await
        .unwrap();
    upload_bytes(
        &sftp,
        "/home/tester/docs/note.txt",
        part2,
        TransferRequest {
            resume_offset: part1.len() as u64,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    upload_bytes(
        &sftp,
        "/home/tester/docs/note.txt",
        b" [appended]",
        TransferRequest {
            append: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let full_expected = b"Hello, pure-Rust SFTP world! [appended]";
    let got = download_bytes(
        &sftp,
        "/home/tester/docs/note.txt",
        TransferRequest::default(),
    )
    .await
    .unwrap();
    assert_eq!(got, full_expected);

    // Resume download from offset 17
    let tail = download_bytes(
        &sftp,
        "/home/tester/docs/note.txt",
        TransferRequest {
            resume_offset: 17,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(tail, b"SFTP world! [appended]");

    // OpenSSH `copy-data` server-side copy & `check-file-name` server-side checksum!
    sftp.copy_file("/home/tester/docs/note.txt", "/home/tester/docs/copied.txt")
        .await
        .unwrap();
    let (used_alg, srv_hex) = sftp
        .checksum_extension_only("sha256", "/home/tester/docs/copied.txt")
        .await
        .unwrap()
        .expect("server supports check-file-name");
    assert_eq!(used_alg, "sha-256");
    let local_hex = linscp_crypto::digests::compute_digest_hex(DigestAlgorithm::Sha256, full_expected);
    assert_eq!(srv_hex, local_hex);
    assert_eq!(
        sftp.checksum("sha256", "/home/tester/docs/copied.txt")
            .await
            .unwrap(),
        local_hex
    );

    // Symlink, chmod, rename, list_dir, remove
    sftp.chmod("/home/tester/docs/copied.txt", 0o600)
        .await
        .unwrap();
    sftp.symlink("copied.txt", "/home/tester/docs/latest.txt")
        .await
        .unwrap();
    sftp.symlink("nonexistent.txt", "/home/tester/docs/broken.txt")
        .await
        .unwrap();

    let listing = sftp.list_dir("/home/tester/docs").await.unwrap();
    let latest = listing.iter().find(|e| e.name == "latest.txt").unwrap();
    assert!(latest.is_symlink);
    assert!(!latest.broken_link);
    let broken = listing.iter().find(|e| e.name == "broken.txt").unwrap();
    assert!(broken.is_symlink);
    assert!(broken.broken_link);

    sftp.rename("/home/tester/docs/copied.txt", "/home/tester/docs/renamed.txt")
        .await
        .unwrap();
    assert!(sftp.stat("/home/tester/docs/copied.txt").await.unwrap().is_none());
    assert!(sftp.stat("/home/tester/docs/renamed.txt").await.unwrap().is_some());

    sftp.remove_file("/home/tester/docs/note.txt").await.unwrap();
    sftp.remove_file("/home/tester/docs/renamed.txt").await.unwrap();
    sftp.remove_file("/home/tester/docs/latest.txt").await.unwrap();
    sftp.remove_file("/home/tester/docs/broken.txt").await.unwrap();
    sftp.remove_dir("/home/tester/docs").await.unwrap();
    sftp.close().await.unwrap();

    // GSSAPI fail-closed check when feature is not active
    if !cfg!(feature = "gssapi") {
        assert!(ensure_gssapi_available(false).is_err());
    }
}

#[tokio::test]
async fn scp_engine_jump_tunnel_and_proxy_dialers_work_end_to_end() {
    let user_key = common::generate_ed25519_ssh_key(0x88, "scp-user");
    let (bastion_port, bastion_fp, _, _) =
        start_mock_ssh_server(0x22, user_key.private_key.public_key().clone(), true).await;
    let (dest_port, dest_fp, _, _) =
        start_mock_ssh_server(0x33, user_key.private_key.public_key().clone(), false).await;

    // 1. Verify jump-host host-key challenge reports `role = "tunnel"` independently!
    let bad_bastion = SshConnectConfig {
        tab_id: 9,
        role: "tunnel".to_string(),
        host: "127.0.0.1".to_string(),
        port: bastion_port,
        username: "tester".to_string(),
        private_key_pem: Some(Zeroizing::new(user_key.openssh_pem.clone())),
        pinned_host_key: Some("SHA256:wrongBastionPin".to_string()),
        ..Default::default()
    };
    let dest_cfg = SshConnectConfig {
        tab_id: 9,
        role: "destination".to_string(),
        host: "127.0.0.1".to_string(),
        port: dest_port,
        username: "tester".to_string(),
        private_key_pem: Some(Zeroizing::new(user_key.openssh_pem.clone())),
        pinned_host_key: Some(dest_fp.clone()),
        ..Default::default()
    };
    match ScpSession::connect(&dest_cfg, Some(&bad_bastion), 0).await {
        Err(ProtoError::HostKeyChallengeRequired { role, state, .. }) => {
            assert_eq!(role, "tunnel");
            assert_eq!(state, "changed");
        }
        other => panic!("expected tunnel challenge, got {:?}", other.err()),
    }

    // 2. Connect SCP over verified SSH Jump Tunnel (`direct-tcpip`, zero local listener!)
    let mut good_bastion = bad_bastion;
    good_bastion.pinned_host_key = Some(bastion_fp);
    let scp = ScpSession::connect(&dest_cfg, Some(&good_bastion), 0)
        .await
        .expect("SCP over jump tunnel");

    scp.mkdir("/home/tester/scpdir").await.unwrap();
    let payload = b"SCP wire protocol payload across jump bastion!\n";
    upload_bytes(
        &scp,
        "/home/tester/scpdir/hello.txt",
        payload,
        TransferRequest {
            preserve_time: true,
            mtime: Some(1_760_123_456),
            permissions: Some(0o640),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let entries = scp.list_dir("/home/tester/scpdir").await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "hello.txt");
    assert_eq!(entries[0].size, payload.len() as u64);

    let downloaded = download_bytes(
        &scp,
        "/home/tester/scpdir/hello.txt",
        TransferRequest {
            preserve_time: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(downloaded, payload);

    // Malicious SCP server sending `C0644 5 ../pwned.txt` MUST be rejected!
    let escape_err = download_bytes(
        &scp,
        "/home/tester/malicious_escape",
        TransferRequest::default(),
    )
    .await
    .expect_err("path traversal filename from scp -f must be rejected");
    assert!(escape_err.to_string().contains("unsafe filename"));

    scp.copy_file(
        "/home/tester/scpdir/hello.txt",
        "/home/tester/scpdir/copy.txt",
    )
    .await
    .unwrap();
    scp.rename(
        "/home/tester/scpdir/copy.txt",
        "/home/tester/scpdir/moved.txt",
    )
    .await
    .unwrap();
    scp.chmod("/home/tester/scpdir/moved.txt", 0o600)
        .await
        .unwrap();
    assert_eq!(
        scp.checksum("sha256", "/home/tester/scpdir/moved.txt")
            .await
            .unwrap(),
        linscp_crypto::digests::compute_digest_hex(DigestAlgorithm::Sha256, payload)
    );
    scp.remove_file("/home/tester/scpdir/hello.txt").await.unwrap();
    scp.remove_file("/home/tester/scpdir/moved.txt").await.unwrap();
    scp.remove_dir("/home/tester/scpdir").await.unwrap();
    scp.close().await.unwrap();

    // 3. Test HTTP CONNECT proxy dialer with Basic auth!
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut client_sock, _)) = proxy_listener.accept().await {
            let mut req_buf = Vec::new();
            let mut b = [0u8; 1];
            while !req_buf.ends_with(b"\r\n\r\n") {
                if client_sock.read_exact(&mut b).await.is_err() {
                    return;
                }
                req_buf.push(b[0]);
            }
            let req_str = String::from_utf8_lossy(&req_buf);
            assert!(req_str.contains("Proxy-Authorization: Basic "));
            let target = req_str
                .lines()
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let mut upstream = TcpStream::connect(target).await.unwrap();
            client_sock
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client_sock, &mut upstream).await;
        }
    });

    let mut via_http_proxy = dest_cfg;
    via_http_proxy.proxy = Some(ProxyConfig {
        kind: ProxyKind::HttpConnect,
        host: "127.0.0.1".to_string(),
        port: proxy_port,
        username: Some("proxyuser".to_string()),
        password: Some("proxypass".to_string()),
        remote_dns: true,
    });
    let proxied_sftp = SftpClientSession::connect(ProtocolScheme::Sftp, &via_http_proxy, None, 0)
        .await
        .expect("SFTP over HTTP CONNECT proxy");
    assert_eq!(proxied_sftp.pwd().await.unwrap(), "/home/tester");
    proxied_sftp.close().await.unwrap();
}
