//! Pure-Rust SFTP v3 client engine (`SftpClientSession` implementing
//! `RemoteSession`) speaking SFTP v3 wire packets directly over `russh`'s
//! `"sftp"` subsystem stream, including OpenSSH `posix-rename@openssh.com`,
//! `copy-data`, and `check-file-name` extensions.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use linscp_crypto::digests::{DigestAlgorithm, DigestHasher};
use linscp_types::{FileEntry, ProtocolScheme};
use russh::client;
use russh::ChannelStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::listing::{format_utc_timestamp, permissions_string, S_IFDIR, S_IFLNK, S_IFMT};
use crate::ssh::{SshConnectConfig, SshConnection};
use crate::tunnel::SshJumpTunnel;
use crate::{ProgressCallback, ProtoError, RateLimiter, RemoteSession, TransferRequest};

pub const SSH_FXP_INIT: u8 = 1;
pub const SSH_FXP_VERSION: u8 = 2;
pub const SSH_FXP_OPEN: u8 = 3;
pub const SSH_FXP_CLOSE: u8 = 4;
pub const SSH_FXP_READ: u8 = 5;
pub const SSH_FXP_WRITE: u8 = 6;
pub const SSH_FXP_LSTAT: u8 = 7;
pub const SSH_FXP_FSTAT: u8 = 8;
pub const SSH_FXP_SETSTAT: u8 = 9;
pub const SSH_FXP_OPENDIR: u8 = 11;
pub const SSH_FXP_READDIR: u8 = 12;
pub const SSH_FXP_REMOVE: u8 = 13;
pub const SSH_FXP_MKDIR: u8 = 14;
pub const SSH_FXP_RMDIR: u8 = 15;
pub const SSH_FXP_REALPATH: u8 = 16;
pub const SSH_FXP_STAT: u8 = 17;
pub const SSH_FXP_RENAME: u8 = 18;
pub const SSH_FXP_READLINK: u8 = 19;
pub const SSH_FXP_SYMLINK: u8 = 20;
pub const SSH_FXP_STATUS: u8 = 101;
pub const SSH_FXP_HANDLE: u8 = 102;
pub const SSH_FXP_DATA: u8 = 103;
pub const SSH_FXP_NAME: u8 = 104;
pub const SSH_FXP_ATTRS: u8 = 105;
pub const SSH_FXP_EXTENDED: u8 = 200;
pub const SSH_FXP_EXTENDED_REPLY: u8 = 201;

pub const SSH_FX_OK: u32 = 0;
pub const SSH_FX_EOF: u32 = 1;
pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
pub const SSH_FX_FAILURE: u32 = 4;
pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;

pub const SSH_FXF_READ: u32 = 0x0000_0001;
pub const SSH_FXF_WRITE: u32 = 0x0000_0002;
pub const SSH_FXF_APPEND: u32 = 0x0000_0004;
pub const SSH_FXF_CREAT: u32 = 0x0000_0008;
pub const SSH_FXF_TRUNC: u32 = 0x0000_0010;
pub const SSH_FXF_EXCL: u32 = 0x0000_0020;

pub const SSH_FILEXFER_ATTR_SIZE: u32 = 0x0000_0001;
pub const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x0000_0002;
pub const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x0000_0004;
pub const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x0000_0008;
pub const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x8000_0000;

const SFTP_CHUNK_SIZE: usize = 32 * 1024;
const MAX_SFTP_PACKET_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SftpWireAttrs {
    pub flags: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub permissions: u32,
    pub atime: u32,
    pub mtime: u32,
}

#[derive(Default)]
pub struct SftpPacketWriter {
    buf: Vec<u8>,
}

impl SftpPacketWriter {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(64),
        }
    }

    pub fn push_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn push_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn push_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn push_bytes(&mut self, data: &[u8]) {
        self.push_u32(data.len() as u32);
        self.buf.extend_from_slice(data);
    }

    pub fn push_str(&mut self, text: &str) {
        self.push_bytes(text.as_bytes());
    }

    pub fn push_attrs(&mut self, attrs: &SftpWireAttrs) {
        self.push_u32(attrs.flags);
        if (attrs.flags & SSH_FILEXFER_ATTR_SIZE) != 0 {
            self.push_u64(attrs.size);
        }
        if (attrs.flags & SSH_FILEXFER_ATTR_UIDGID) != 0 {
            self.push_u32(attrs.uid);
            self.push_u32(attrs.gid);
        }
        if (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 {
            self.push_u32(attrs.permissions);
        }
        if (attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0 {
            self.push_u32(attrs.atime);
            self.push_u32(attrs.mtime);
        }
    }

    pub fn into_framed_packet(self, pkt_type: u8, request_id: Option<u32>) -> Vec<u8> {
        let extra = 1 + if request_id.is_some() { 4 } else { 0 };
        let total_payload = extra + self.buf.len();
        let mut out = Vec::with_capacity(4 + total_payload);
        out.extend_from_slice(&(total_payload as u32).to_be_bytes());
        out.push(pkt_type);
        if let Some(id) = request_id {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out.extend_from_slice(&self.buf);
        out
    }
}

pub struct SftpPacketReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SftpPacketReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn read_u32(&mut self) -> Result<u32, ProtoError> {
        if self.remaining() < 4 {
            return Err(ProtoError::Transport(
                "Truncated SFTP packet (u32).".to_string(),
            ));
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    pub fn read_u64(&mut self) -> Result<u64, ProtoError> {
        if self.remaining() < 8 {
            return Err(ProtoError::Transport(
                "Truncated SFTP packet (u64).".to_string(),
            ));
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.data[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(u64::from_be_bytes(b))
    }

    pub fn read_bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let len = self.read_u32()? as usize;
        if self.remaining() < len {
            return Err(ProtoError::Transport(
                "Truncated SFTP length-prefixed string.".to_string(),
            ));
        }
        let s = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }

    pub fn read_string_lossy(&mut self) -> Result<String, ProtoError> {
        let bytes = self.read_bytes()?;
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    pub fn read_attrs(&mut self) -> Result<SftpWireAttrs, ProtoError> {
        let flags = self.read_u32()?;
        let mut attrs = SftpWireAttrs {
            flags,
            ..Default::default()
        };
        if (flags & SSH_FILEXFER_ATTR_SIZE) != 0 {
            attrs.size = self.read_u64()?;
        }
        if (flags & SSH_FILEXFER_ATTR_UIDGID) != 0 {
            attrs.uid = self.read_u32()?;
            attrs.gid = self.read_u32()?;
        }
        if (flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0 {
            attrs.permissions = self.read_u32()?;
        }
        if (flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0 {
            attrs.atime = self.read_u32()?;
            attrs.mtime = self.read_u32()?;
        }
        if (flags & SSH_FILEXFER_ATTR_EXTENDED) != 0 {
            let ext_count = self.read_u32()?;
            for _ in 0..ext_count {
                let _ = self.read_bytes()?;
                let _ = self.read_bytes()?;
            }
        }
        Ok(attrs)
    }
}

struct SftpTransport {
    stream: ChannelStream<client::Msg>,
    next_id: u32,
    extensions: HashMap<String, String>,
}

impl SftpTransport {
    async fn init(mut stream: ChannelStream<client::Msg>) -> Result<Self, ProtoError> {
        let mut init_body = SftpPacketWriter::new();
        init_body.push_u32(3);
        let framed = init_body.into_framed_packet(SSH_FXP_INIT, None);
        stream
            .write_all(&framed)
            .await
            .map_err(|e| ProtoError::Transport(format!("SFTP INIT write failed: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| ProtoError::Transport(format!("SFTP INIT flush failed: {e}")))?;

        let (pkt_type, payload) = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            Self::read_raw_packet(&mut stream),
        )
        .await
        .map_err(|_| ProtoError::Transport("Timed out waiting for SFTP SSH_FXP_VERSION.".to_string()))??;
        if pkt_type != SSH_FXP_VERSION {
            return Err(ProtoError::Transport(format!(
                "Expected SSH_FXP_VERSION (2), got packet type {pkt_type}."
            )));
        }
        let mut reader = SftpPacketReader::new(&payload);
        let _version = reader.read_u32()?;
        let mut extensions = HashMap::new();
        while reader.remaining() > 0 {
            let k = reader.read_string_lossy()?;
            let v = reader.read_string_lossy()?;
            extensions.insert(k, v);
        }

        Ok(Self {
            stream,
            next_id: 1,
            extensions,
        })
    }

    async fn read_raw_packet<R: AsyncRead + Unpin>(
        stream: &mut R,
    ) -> Result<(u8, Vec<u8>), ProtoError> {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| ProtoError::Transport(format!("SFTP packet header read failed: {e}")))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_SFTP_PACKET_BYTES {
            return Err(ProtoError::Transport(format!(
                "Invalid SFTP packet length {len} bytes."
            )));
        }
        let mut body = vec![0u8; len];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|e| ProtoError::Transport(format!("SFTP packet body read failed: {e}")))?;
        let pkt_type = body.remove(0);
        Ok((pkt_type, body))
    }

    async fn request(
        &mut self,
        pkt_type: u8,
        body: SftpPacketWriter,
    ) -> Result<(u8, Vec<u8>), ProtoError> {
        let req_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let framed = body.into_framed_packet(pkt_type, Some(req_id));
        self.stream
            .write_all(&framed)
            .await
            .map_err(|e| ProtoError::Transport(format!("SFTP write failed: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| ProtoError::Transport(format!("SFTP flush failed: {e}")))?;

        let (resp_type, mut resp_body) = Self::read_raw_packet(&mut self.stream).await?;
        if resp_body.len() < 4 {
            return Err(ProtoError::Transport(
                "SFTP server reply missing request id.".to_string(),
            ));
        }
        let resp_id =
            u32::from_be_bytes([resp_body[0], resp_body[1], resp_body[2], resp_body[3]]);
        if resp_id != req_id {
            return Err(ProtoError::Transport(format!(
                "SFTP response ID mismatch (expected {req_id}, got {resp_id})."
            )));
        }
        resp_body.drain(..4);
        Ok((resp_type, resp_body))
    }

    fn parse_status(body: &[u8]) -> Result<(u32, String), ProtoError> {
        let mut reader = SftpPacketReader::new(body);
        let code = reader.read_u32()?;
        let msg = if reader.remaining() >= 4 {
            reader.read_string_lossy()?
        } else {
            String::new()
        };
        Ok((code, msg))
    }

    fn expect_ok_status(resp_type: u8, body: &[u8], context: &str) -> Result<(), ProtoError> {
        if resp_type != SSH_FXP_STATUS {
            return Err(ProtoError::Transport(format!(
                "{context}: unexpected SFTP packet type {resp_type}."
            )));
        }
        let (code, msg) = Self::parse_status(body)?;
        if code == SSH_FX_OK {
            return Ok(());
        }
        let detail = if msg.is_empty() {
            format!("status code {code}")
        } else {
            msg
        };
        Err(ProtoError::Transport(format!("{context}: {detail}")))
    }

    async fn open_handle(
        &mut self,
        remote_path: &str,
        pflags: u32,
        attrs: &SftpWireAttrs,
    ) -> Result<Vec<u8>, ProtoError> {
        let mut w = SftpPacketWriter::new();
        w.push_str(remote_path);
        w.push_u32(pflags);
        w.push_attrs(attrs);
        let (rtype, rbody) = self.request(SSH_FXP_OPEN, w).await?;
        if rtype == SSH_FXP_HANDLE {
            let mut r = SftpPacketReader::new(&rbody);
            return Ok(r.read_bytes()?.to_vec());
        }
        Self::expect_ok_status(rtype, &rbody, &format!("Opening '{remote_path}'"))?;
        Err(ProtoError::Transport(format!(
            "Opening '{remote_path}' returned no SFTP handle."
        )))
    }

    async fn close_handle(&mut self, handle: &[u8]) -> Result<(), ProtoError> {
        let mut w = SftpPacketWriter::new();
        w.push_bytes(handle);
        let (rtype, rbody) = self.request(SSH_FXP_CLOSE, w).await?;
        Self::expect_ok_status(rtype, &rbody, "Closing SFTP handle")
    }

    async fn stat_internal(
        &mut self,
        pkt_type: u8,
        remote_path: &str,
    ) -> Result<Option<SftpWireAttrs>, ProtoError> {
        let mut w = SftpPacketWriter::new();
        w.push_str(remote_path);
        let (rtype, rbody) = self.request(pkt_type, w).await?;
        if rtype == SSH_FXP_ATTRS {
            let mut r = SftpPacketReader::new(&rbody);
            return Ok(Some(r.read_attrs()?));
        }
        if rtype == SSH_FXP_STATUS {
            let (code, msg) = Self::parse_status(&rbody)?;
            if code == SSH_FX_NO_SUCH_FILE {
                return Ok(None);
            }
            return Err(ProtoError::Transport(format!(
                "Stat '{remote_path}' failed: {}",
                if msg.is_empty() {
                    format!("status code {code}")
                } else {
                    msg
                }
            )));
        }
        Err(ProtoError::Transport(format!(
            "Stat '{remote_path}' returned unexpected packet {rtype}."
        )))
    }
}

fn join_posix_path(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "." {
        name.to_string()
    } else if dir == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", dir.trim_end_matches('/'))
    }
}

fn wire_attrs_to_file_entry(
    name: String,
    attrs: &SftpWireAttrs,
    symlink_target_dir: Option<(bool, bool)>,
) -> FileEntry {
    let has_perms = (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0;
    let file_type = attrs.permissions & S_IFMT;
    let is_symlink = has_perms && file_type == S_IFLNK;
    let (is_dir, broken_link) = if is_symlink {
        symlink_target_dir.unwrap_or((false, false))
    } else {
        (has_perms && file_type == S_IFDIR, false)
    };
    let has_time = (attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0;
    let mtime = if has_time { i64::from(attrs.mtime) } else { 0 };
    FileEntry {
        name,
        size: if is_dir {
            0
        } else if (attrs.flags & SSH_FILEXFER_ATTR_SIZE) != 0 {
            attrs.size
        } else {
            0
        },
        is_dir,
        is_symlink,
        broken_link,
        date: if has_time {
            format_utc_timestamp(mtime)
        } else {
            String::new()
        },
        mtime,
        permissions: if has_perms {
            permissions_string(attrs.permissions)
        } else {
            String::new()
        },
        owner: if (attrs.flags & SSH_FILEXFER_ATTR_UIDGID) != 0 {
            Some(attrs.uid.to_string())
        } else {
            None
        },
        group: if (attrs.flags & SSH_FILEXFER_ATTR_UIDGID) != 0 {
            Some(attrs.gid.to_string())
        } else {
            None
        },
    }
}

/// Pure-Rust SFTP v3 session implementing `RemoteSession`.
pub struct SftpClientSession {
    scheme: ProtocolScheme,
    ssh: Arc<SshConnection>,
    dest_cfg: Option<SshConnectConfig>,
    jump_tunnel: Option<Arc<SshJumpTunnel>>,
    sftp: Mutex<SftpTransport>,
    home_dir: String,
}

impl SftpClientSession {
    async fn upload_inner(
        &self,
        remote_path: &str,
        opts: TransferRequest,
        source: &mut (dyn AsyncRead + Unpin + Send),
        total_size: Option<u64>,
        progress: Option<&ProgressCallback>,
        exclusive: bool,
    ) -> Result<u64, ProtoError> {
        let mut t = self.sftp.lock().await;
        let mut open_offset = opts.resume_offset;
        if exclusive && (opts.append || opts.resume_offset != 0) {
            return Err(ProtoError::Transport("Exclusive upload cannot resume or append.".to_string()));
        }
        let pflags = if exclusive {
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL
        } else if opts.append {
            if open_offset == 0 {
                open_offset = t
                    .stat_internal(SSH_FXP_STAT, remote_path)
                    .await?
                    .map(|a| a.size)
                    .unwrap_or(0);
            }
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_APPEND
        } else if opts.resume_offset > 0 {
            SSH_FXF_WRITE | SSH_FXF_CREAT
        } else {
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC
        };

        let create_attrs = match opts.permissions {
            Some(mode) => SftpWireAttrs {
                flags: SSH_FILEXFER_ATTR_PERMISSIONS,
                permissions: mode & 0o7777,
                ..Default::default()
            },
            None => SftpWireAttrs::default(),
        };

        let handle = t.open_handle(remote_path, pflags, &create_attrs).await?;
        let mut offset = open_offset;
        let mut transferred = 0u64;
        let mut buf = vec![0u8; SFTP_CHUNK_SIZE];
        let mut limiter = RateLimiter::new(opts.speed_kbytes_per_sec);
        let reported_total = total_size.unwrap_or(0);

        let res: Result<u64, ProtoError> = async {
            loop {
                let n = source
                    .read(&mut buf)
                    .await
                    .map_err(|e| ProtoError::Transport(format!("Reading upload source: {e}")))?;
                if n == 0 {
                    break;
                }
                let mut ww = SftpPacketWriter::new();
                ww.push_bytes(&handle);
                ww.push_u64(offset);
                ww.push_bytes(&buf[..n]);
                let (rtype, rbody) = t.request(SSH_FXP_WRITE, ww).await?;
                SftpTransport::expect_ok_status(
                    rtype,
                    &rbody,
                    &format!("Writing '{remote_path}'"),
                )?;
                offset += n as u64;
                transferred += n as u64;
                if let Some(cb) = progress {
                    cb(open_offset + transferred, reported_total);
                }
                limiter.consume(n).await;
            }
            Ok(transferred)
        }
        .await;

        let close_res = t.close_handle(&handle).await;
        let bytes = res?;
        close_res?;

        if opts.preserve_time {
            if let Some(mtime) = opts.mtime {
                drop(t);
                let _ = self.set_mtime(remote_path, mtime).await;
            }
        }
        Ok(bytes)
    }


    pub async fn connect(
        scheme: ProtocolScheme,
        dest_cfg: &SshConnectConfig,
        tunnel_cfg: Option<&SshConnectConfig>,
        tunnel_local_port: u16,
    ) -> Result<Self, ProtoError> {
        let (ssh, jump_tunnel) = if let Some(tcfg) = tunnel_cfg {
            let jump = Arc::new(SshJumpTunnel::connect(tcfg.clone()).await?);
            let stream = match jump
                .open_destination_stream(&dest_cfg.host, dest_cfg.port, tunnel_local_port)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    let _ = jump.close().await;
                    return Err(e);
                }
            };
            let conn = match SshConnection::connect_over_stream(dest_cfg, stream).await {
                Ok(c) => c,
                Err(e) => {
                    let _ = jump.close().await;
                    return Err(e);
                }
            };
            (Arc::new(conn), Some(jump))
        } else {
            (Arc::new(SshConnection::connect(dest_cfg).await?), None)
        };

        let ssh_cleanup = Arc::clone(&ssh);
        let mut session = match Self::from_ssh_connection(scheme, ssh, jump_tunnel.clone()).await {
            Ok(s) => s,
            Err(e) => {
                let _ = ssh_cleanup.disconnect().await;
                if let Some(j) = jump_tunnel {
                    let _ = j.close().await;
                }
                return Err(e);
            }
        };
        let mut stored_cfg = dest_cfg.clone();
        stored_cfg.host_key_decision = None;
        stored_cfg.event_logger = None;
        stored_cfg.danger_accept_any_host_key = false;
        stored_cfg.pinned_host_key = Some(session.ssh.observed_fingerprint().to_string());
        session.dest_cfg = Some(stored_cfg);
        Ok(session)
    }

    pub async fn from_ssh_connection(
        scheme: ProtocolScheme,
        ssh: Arc<SshConnection>,
        jump_tunnel: Option<Arc<SshJumpTunnel>>,
    ) -> Result<Self, ProtoError> {
        let stream = ssh.open_sftp_stream().await?;
        let mut transport = SftpTransport::init(stream).await?;
        let home_dir = Self::realpath_on(&mut transport, ".")
            .await
            .unwrap_or_else(|_| "/".to_string());

        Ok(Self {
            scheme,
            ssh,
            dest_cfg: None,
            jump_tunnel,
            sftp: Mutex::new(transport),
            home_dir,
        })
    }

    pub fn ssh_connection(&self) -> &Arc<SshConnection> {
        &self.ssh
    }

    pub fn observed_fingerprint(&self) -> &str {
        self.ssh.observed_fingerprint()
    }

    async fn realpath_on(t: &mut SftpTransport, path: &str) -> Result<String, ProtoError> {
        let mut w = SftpPacketWriter::new();
        w.push_str(path);
        let (rtype, rbody) = t.request(SSH_FXP_REALPATH, w).await?;
        if rtype == SSH_FXP_NAME {
            let mut r = SftpPacketReader::new(&rbody);
            let count = r.read_u32()?;
            if count == 0 {
                return Err(ProtoError::Transport(
                    "SSH_FXP_REALPATH returned empty name list.".to_string(),
                ));
            }
            return r.read_string_lossy();
        }
        SftpTransport::expect_ok_status(rtype, &rbody, &format!("Realpath '{path}'"))?;
        Err(ProtoError::Transport(format!("Realpath '{path}' failed.")))
    }

    pub async fn realpath(&self, path: &str) -> Result<String, ProtoError> {
        let mut t = self.sftp.lock().await;
        Self::realpath_on(&mut t, path).await
    }

    pub async fn readlink(&self, link_path: &str) -> Result<String, ProtoError> {
        let mut t = self.sftp.lock().await;
        let mut w = SftpPacketWriter::new();
        w.push_str(link_path);
        let (rtype, rbody) = t.request(SSH_FXP_READLINK, w).await?;
        if rtype == SSH_FXP_NAME {
            let mut r = SftpPacketReader::new(&rbody);
            let count = r.read_u32()?;
            if count == 0 {
                return Err(ProtoError::Transport(
                    "SSH_FXP_READLINK returned empty name list.".to_string(),
                ));
            }
            return r.read_string_lossy();
        }
        SftpTransport::expect_ok_status(rtype, &rbody, &format!("Readlink '{link_path}'"))?;
        Err(ProtoError::Transport(format!(
            "Readlink '{link_path}' failed."
        )))
    }

    /// Requests a server-side checksum strictly through SFTP `check-file-name`
    /// without streaming fallback. Returns `Ok(None)` when the server answers
    /// `SSH_FX_OP_UNSUPPORTED`.
    pub async fn checksum_extension_only(
        &self,
        algorithm: &str,
        remote_path: &str,
    ) -> Result<Option<(String, String)>, ProtoError> {
        let sftp_alg = match DigestAlgorithm::parse(algorithm) {
            Some(DigestAlgorithm::Sha256) => "sha-256",
            Some(DigestAlgorithm::Sha1) => "sha-1",
            Some(DigestAlgorithm::Md5) => "md5",
            Some(DigestAlgorithm::Crc32) => "crc32",
            None => algorithm.trim(),
        };
        let mut t = self.sftp.lock().await;
        let mut w = SftpPacketWriter::new();
        w.push_str("check-file-name");
        w.push_str(remote_path);
        w.push_str(sftp_alg);
        w.push_u64(0);
        w.push_u64(0);
        w.push_u32(0);
        let (rtype, rbody) = t.request(SSH_FXP_EXTENDED, w).await?;
        if rtype == SSH_FXP_STATUS {
            let (code, msg) = SftpTransport::parse_status(&rbody)?;
            if code == SSH_FX_OP_UNSUPPORTED {
                return Ok(None);
            }
            return Err(ProtoError::Transport(format!(
                "Checksum '{remote_path}' failed: {msg}"
            )));
        }
        if rtype != SSH_FXP_EXTENDED_REPLY {
            return Err(ProtoError::Transport(format!(
                "Unexpected SFTP reply {rtype} to check-file-name."
            )));
        }
        let mut r = SftpPacketReader::new(&rbody);
        let used_alg = r.read_string_lossy()?;
        let block_size = r.read_u32()?;
        // In `check-file-name`, after `used_alg`, some servers encode raw trailing
        // digest bytes and others encode `block_size=0` + length-prefixed digest
        // (matching `SftpClient.cpp`). Handle both cleanly!
        let digest_bytes = if block_size == 0 && r.remaining() >= 4 {
            r.read_bytes()?.to_vec()
        } else {
            return Err(ProtoError::Transport(
                "Malformed SFTP check-file-name reply.".to_string(),
            ));
        };
        if digest_bytes.is_empty() {
            return Err(ProtoError::Transport(
                "Empty digest in SFTP check-file-name reply.".to_string(),
            ));
        }
        let hex: String = digest_bytes.iter().map(|b| format!("{b:02x}")).collect();
        Ok(Some((used_alg, hex)))
    }
}

#[async_trait]
impl RemoteSession for SftpClientSession {
    fn scheme(&self) -> ProtocolScheme {
        self.scheme
    }

    fn ssh_connection(&self) -> Option<&Arc<SshConnection>> {
        Some(&self.ssh)
    }

    fn observed_host_key(&self) -> Option<&str> {
        Some(self.ssh.observed_fingerprint())
    }

    async fn pwd(&self) -> Result<String, ProtoError> {
        Ok(self.home_dir.clone())
    }

    async fn stat(&self, remote_path: &str) -> Result<Option<FileEntry>, ProtoError> {
        let mut t = self.sftp.lock().await;
        let Some(lstat_attrs) = t.stat_internal(SSH_FXP_LSTAT, remote_path).await? else {
            return Ok(None);
        };
        let is_link = (lstat_attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0
            && (lstat_attrs.permissions & S_IFMT) == S_IFLNK;
        let target_info = if is_link {
            match t.stat_internal(SSH_FXP_STAT, remote_path).await {
                Ok(Some(target)) => {
                    let tdir = (target.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0
                        && (target.permissions & S_IFMT) == S_IFDIR;
                    Some((tdir, false))
                }
                Ok(None) | Err(_) => Some((false, true)),
            }
        } else {
            None
        };
        let leaf = remote_path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or("/");
        Ok(Some(wire_attrs_to_file_entry(
            leaf.to_string(),
            &lstat_attrs,
            target_info,
        )))
    }

    async fn list_dir(&self, remote_path: &str) -> Result<Vec<FileEntry>, ProtoError> {
        let mut t = self.sftp.lock().await;
        let mut open_w = SftpPacketWriter::new();
        open_w.push_str(remote_path);
        let (rtype, rbody) = t.request(SSH_FXP_OPENDIR, open_w).await?;
        let handle = if rtype == SSH_FXP_HANDLE {
            let mut r = SftpPacketReader::new(&rbody);
            r.read_bytes()?.to_vec()
        } else {
            SftpTransport::expect_ok_status(rtype, &rbody, &format!("Listing '{remote_path}'"))?;
            return Ok(Vec::new());
        };

        let mut raw_items: Vec<(String, SftpWireAttrs)> = Vec::new();
        let read_outcome: Result<(), ProtoError> = async {
            loop {
                let mut rw = SftpPacketWriter::new();
                rw.push_bytes(&handle);
                let (rt, rb) = t.request(SSH_FXP_READDIR, rw).await?;
                if rt == SSH_FXP_NAME {
                    let mut r = SftpPacketReader::new(&rb);
                    let count = r.read_u32()?;
                    for _ in 0..count {
                        let name = r.read_string_lossy()?;
                        let _longname = r.read_string_lossy()?;
                        let attrs = r.read_attrs()?;
                        if !name.is_empty() && name != "." && name != ".." {
                            raw_items.push((name, attrs));
                        }
                    }
                } else if rt == SSH_FXP_STATUS {
                    let (code, msg) = SftpTransport::parse_status(&rb)?;
                    if code == SSH_FX_EOF {
                        break;
                    }
                    return Err(ProtoError::Transport(format!(
                        "Reading directory '{remote_path}' failed: {msg}"
                    )));
                } else {
                    return Err(ProtoError::Transport(format!(
                        "Unexpected packet {rt} during SFTP READDIR."
                    )));
                }
            }
            Ok(())
        }
        .await;

        let _ = t.close_handle(&handle).await;
        read_outcome?;

        let mut entries = Vec::with_capacity(raw_items.len());
        for (name, attrs) in raw_items {
            let is_link = (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0
                && (attrs.permissions & S_IFMT) == S_IFLNK;
            let target_info = if is_link {
                let full = join_posix_path(remote_path, &name);
                match t.stat_internal(SSH_FXP_STAT, &full).await {
                    Ok(Some(tattrs)) => {
                        let is_tdir = (tattrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0
                            && (tattrs.permissions & S_IFMT) == S_IFDIR;
                        Some((is_tdir, false))
                    }
                    Ok(None) | Err(_) => Some((false, true)),
                }
            } else {
                None
            };
            entries.push(wire_attrs_to_file_entry(name, &attrs, target_info));
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    async fn mkdir(&self, remote_path: &str) -> Result<(), ProtoError> {
        let mut t = self.sftp.lock().await;
        let mut w = SftpPacketWriter::new();
        w.push_str(remote_path);
        w.push_attrs(&SftpWireAttrs {
            flags: SSH_FILEXFER_ATTR_PERMISSIONS,
            permissions: 0o755,
            ..Default::default()
        });
        let (rtype, rbody) = t.request(SSH_FXP_MKDIR, w).await?;
        SftpTransport::expect_ok_status(rtype, &rbody, &format!("Creating '{remote_path}'"))
    }

    async fn remove_file(&self, remote_path: &str) -> Result<(), ProtoError> {
        let mut t = self.sftp.lock().await;
        let mut w = SftpPacketWriter::new();
        w.push_str(remote_path);
        let (rtype, rbody) = t.request(SSH_FXP_REMOVE, w).await?;
        SftpTransport::expect_ok_status(rtype, &rbody, &format!("Removing '{remote_path}'"))
    }

    async fn remove_dir(&self, remote_path: &str) -> Result<(), ProtoError> {
        let mut t = self.sftp.lock().await;
        let mut w = SftpPacketWriter::new();
        w.push_str(remote_path);
        let (rtype, rbody) = t.request(SSH_FXP_RMDIR, w).await?;
        SftpTransport::expect_ok_status(
            rtype,
            &rbody,
            &format!("Removing directory '{remote_path}'"),
        )
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        let mut t = self.sftp.lock().await;
        if t.extensions.contains_key("posix-rename@openssh.com") {
            let mut ext = SftpPacketWriter::new();
            ext.push_str("posix-rename@openssh.com");
            ext.push_str(from);
            ext.push_str(to);
            let (rt, rb) = t.request(SSH_FXP_EXTENDED, ext).await?;
            if rt == SSH_FXP_STATUS {
                let (code, _) = SftpTransport::parse_status(&rb)?;
                if code == SSH_FX_OK {
                    return Ok(());
                }
                if code != SSH_FX_OP_UNSUPPORTED {
                    return SftpTransport::expect_ok_status(
                        rt,
                        &rb,
                        &format!("Renaming '{from}' to '{to}'"),
                    );
                }
            }
        }
        let mut w = SftpPacketWriter::new();
        w.push_str(from);
        w.push_str(to);
        let (rtype, rbody) = t.request(SSH_FXP_RENAME, w).await?;
        SftpTransport::expect_ok_status(rtype, &rbody, &format!("Renaming '{from}' to '{to}'"))
    }

    async fn copy_file(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        let mut t = self.sftp.lock().await;
        let read_handle = t
            .open_handle(from, SSH_FXF_READ, &SftpWireAttrs::default())
            .await?;
        let write_handle = match t
            .open_handle(
                to,
                SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
                &SftpWireAttrs {
                    flags: SSH_FILEXFER_ATTR_PERMISSIONS,
                    permissions: 0o644,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(h) => h,
            Err(err) => {
                let _ = t.close_handle(&read_handle).await;
                return Err(err);
            }
        };

        let mut ext = SftpPacketWriter::new();
        ext.push_str("copy-data");
        ext.push_bytes(&read_handle);
        ext.push_u64(0);
        ext.push_u64(0);
        ext.push_bytes(&write_handle);
        ext.push_u64(0);
        let req_res = t.request(SSH_FXP_EXTENDED, ext).await;
        let _ = t.close_handle(&read_handle).await;
        let _ = t.close_handle(&write_handle).await;

        let (rtype, rbody) = req_res?;
        if rtype == SSH_FXP_STATUS {
            let (code, msg) = SftpTransport::parse_status(&rbody)?;
            if code == SSH_FX_OK {
                return Ok(());
            }
            if code == SSH_FX_OP_UNSUPPORTED {
                return Err(ProtoError::UnsupportedCapability("copy-data", self.scheme));
            }
            return Err(ProtoError::Transport(format!(
                "Server-side copy '{from}' -> '{to}' failed: {msg}"
            )));
        }
        Err(ProtoError::Transport(format!(
            "Unexpected SFTP packet {rtype} for copy-data."
        )))
    }

    async fn symlink(&self, target: &str, link_path: &str) -> Result<(), ProtoError> {
        let mut t = self.sftp.lock().await;
        let mut w = SftpPacketWriter::new();
        // Matches OpenSSH / SftpClient.cpp order: target first, link_path second.
        w.push_str(target);
        w.push_str(link_path);
        let (rtype, rbody) = t.request(SSH_FXP_SYMLINK, w).await?;
        SftpTransport::expect_ok_status(
            rtype,
            &rbody,
            &format!("Creating symbolic link '{link_path}'"),
        )
    }

    async fn chmod(&self, remote_path: &str, mode: u32) -> Result<(), ProtoError> {
        let mut t = self.sftp.lock().await;
        let mut w = SftpPacketWriter::new();
        w.push_str(remote_path);
        w.push_attrs(&SftpWireAttrs {
            flags: SSH_FILEXFER_ATTR_PERMISSIONS,
            permissions: mode & 0o7777,
            ..Default::default()
        });
        let (rtype, rbody) = t.request(SSH_FXP_SETSTAT, w).await?;
        SftpTransport::expect_ok_status(
            rtype,
            &rbody,
            &format!("Setting permissions on '{remote_path}'"),
        )
    }

    async fn set_mtime(&self, remote_path: &str, mtime: i64) -> Result<(), ProtoError> {
        let ts = u32::try_from(mtime.max(0)).unwrap_or(u32::MAX);
        let mut t = self.sftp.lock().await;
        let mut w = SftpPacketWriter::new();
        w.push_str(remote_path);
        w.push_attrs(&SftpWireAttrs {
            flags: SSH_FILEXFER_ATTR_ACMODTIME,
            atime: ts,
            mtime: ts,
            ..Default::default()
        });
        let (rtype, rbody) = t.request(SSH_FXP_SETSTAT, w).await?;
        SftpTransport::expect_ok_status(rtype, &rbody, &format!("Setting times on '{remote_path}'"))
    }

    async fn checksum(&self, algorithm: &str, remote_path: &str) -> Result<String, ProtoError> {
        if let Some((_used, hex)) = self.checksum_extension_only(algorithm, remote_path).await? {
            return Ok(hex);
        }
        // Fallback: stream file through `DigestHasher` when `check-file-name` is unsupported.
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
        let mut t = self.sftp.lock().await;
        let total_size = t
            .stat_internal(SSH_FXP_STAT, remote_path)
            .await?
            .map(|a| a.size)
            .unwrap_or(0);
        let handle = t
            .open_handle(remote_path, SSH_FXF_READ, &SftpWireAttrs::default())
            .await?;

        let mut offset = opts.resume_offset;
        let mut transferred = 0u64;
        let mut limiter = RateLimiter::new(opts.speed_kbytes_per_sec);

        let res: Result<u64, ProtoError> = async {
            loop {
                let mut rw = SftpPacketWriter::new();
                rw.push_bytes(&handle);
                rw.push_u64(offset);
                rw.push_u32(SFTP_CHUNK_SIZE as u32);
                let (rtype, rbody) = t.request(SSH_FXP_READ, rw).await?;
                if rtype == SSH_FXP_DATA {
                    let mut r = SftpPacketReader::new(&rbody);
                    let chunk = r.read_bytes()?;
                    if chunk.is_empty() {
                        break;
                    }
                    sink.write_all(chunk).await.map_err(|e| {
                        ProtoError::Transport(format!("Writing downloaded data failed: {e}"))
                    })?;
                    offset += chunk.len() as u64;
                    transferred += chunk.len() as u64;
                    if let Some(cb) = progress {
                        cb(opts.resume_offset + transferred, total_size);
                    }
                    if opts.speed_kbytes_per_sec > 0 {
                        sink.flush().await.map_err(|e| {
                            ProtoError::Transport(format!("Flushing download sink failed: {e}"))
                        })?;
                    }
                    limiter.consume(chunk.len()).await;
                } else if rtype == SSH_FXP_STATUS {
                    let (code, msg) = SftpTransport::parse_status(&rbody)?;
                    if code == SSH_FX_EOF {
                        break;
                    }
                    return Err(ProtoError::Transport(format!(
                        "Reading '{remote_path}' failed: {msg}"
                    )));
                } else {
                    return Err(ProtoError::Transport(format!(
                        "Unexpected SFTP packet {rtype} during READ."
                    )));
                }
            }
            sink.flush()
                .await
                .map_err(|e| ProtoError::Transport(format!("Flushing download sink failed: {e}")))?;
            Ok(transferred)
        }
        .await;

        let _ = t.close_handle(&handle).await;
        res
    }

    async fn upload(
        &self, remote_path: &str, opts: TransferRequest,
        source: &mut (dyn AsyncRead + Unpin + Send), total_size: Option<u64>,
        progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        self.upload_inner(remote_path, opts, source, total_size, progress, false).await
    }

    async fn upload_exclusive(
        &self, remote_path: &str, opts: TransferRequest,
        source: &mut (dyn AsyncRead + Unpin + Send), total_size: Option<u64>,
        progress: Option<&ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        self.upload_inner(remote_path, opts, source, total_size, progress, true).await
    }

    async fn realpath(&self, remote_path: &str) -> Result<String, ProtoError> {
        SftpClientSession::realpath(self, remote_path).await
    }

    async fn readlink(&self, link_path: &str) -> Result<String, ProtoError> {
        SftpClientSession::readlink(self, link_path).await
    }

    async fn exec_command(&self, command: &str) -> Result<crate::ssh::ExecOutput, ProtoError> {
        if let (Some(jump), Some(cfg)) = (&self.jump_tunnel, &self.dest_cfg) {
            let stream = jump.open_destination_stream(&cfg.host, cfg.port, 0).await?;
            let conn = SshConnection::connect_over_stream(cfg, stream).await?;
            let res = conn.exec_command(command).await;
            let _ = conn.disconnect().await;
            return res;
        }
        self.ssh.exec_command(command).await
    }

    async fn checksum_server_only(
        &self,
        algorithm: &str,
        remote_path: &str,
    ) -> Result<Option<String>, ProtoError> {
        Ok(self
            .checksum_extension_only(algorithm, remote_path)
            .await?
            .map(|(_alg, hex)| hex))
    }

    async fn close(&self) -> Result<(), ProtoError> {
        let res = self.ssh.disconnect().await;
        if let Some(jump) = &self.jump_tunnel {
            let _ = jump.close().await;
        }
        res
    }
}

pub(crate) struct HasherAsyncSink<'a> {
    pub hasher: &'a mut DigestHasher,
}

impl AsyncWrite for HasherAsyncSink<'_> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.hasher.update(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
