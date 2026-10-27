//! Native SCP wire (`scp -f` / `scp -t`) and POSIX shell metadata engine
//! (`ScpSession` implementing `RemoteSession`), porting `ScpClient.{h,cpp}`
//! with strict path-traversal rejection and POSIX shell quoting.

use std::sync::Arc;

use async_trait::async_trait;
use linscp_crypto::digests::{DigestAlgorithm, DigestHasher};
use linscp_types::{FileEntry, ProtocolScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::listing::{civil_from_days, parse_full_time_columns, parse_unix_listing_line};
use crate::sftp::HasherAsyncSink;
use crate::ssh::{SshConnectConfig, SshConnection};
use crate::tunnel::SshJumpTunnel;
use crate::{ProgressCallback, ProtoError, RateLimiter, RemoteSession, TransferRequest};

const SCP_CHUNK_SIZE: usize = 32 * 1024;
const MAX_SCP_HEADER_LINE: usize = 8 * 1024;

/// Quotes one word for a POSIX shell (`'...'`, turning embedded `'` into `'\''`),
/// matching `ScpShellQuote` in `ScpClient.cpp`.
pub fn scp_shell_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for ch in text.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Validates a remote path before passing it to a POSIX shell or `scp`:
/// non-empty and free of ASCII control characters (`0x00..=0x1f`, `0x7f`).
pub fn scp_valid_remote_path(path: &str) -> Result<(), ProtoError> {
    if path.is_empty() {
        return Err(ProtoError::Transport("The remote path is empty.".to_string()));
    }
    if path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(ProtoError::Transport(
            "Remote paths containing control characters are refused by the SCP engine.".to_string(),
        ));
    }
    Ok(())
}

/// Normalizes a remote path for shell invocations, stripping non-root trailing
/// `/` and prefixing `./` if the path begins with `-` so it is never parsed as
/// a command-line option by `ls`, `rm`, `scp`, or `touch`.
pub fn prepare_remote_path(remote_path: &str) -> Result<String, ProtoError> {
    scp_valid_remote_path(remote_path)?;
    let mut p = remote_path.to_string();
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    if p.is_empty() {
        p = ".".to_string();
    } else if p.starts_with('-') {
        p = format!("./{p}");
    }
    Ok(p)
}

/// Hardens SCP downloads (`scp -f`) against malicious server filenames
/// (CVE-2018-20685 / CVE-2019-6111): rejects empty names, `.`, `..`, path
/// separators (`/` or `\`), and control characters.
pub fn validate_scp_received_name(name: &str) -> Result<(), ProtoError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err(ProtoError::Transport(format!(
            "Refusing unsafe filename '{name}' sent by remote scp server."
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScpRecord {
    File {
        mode: u32,
        size: u64,
        name: String,
    },
    Directory {
        mode: u32,
        name: String,
    },
    EndDirectory,
    Timestamp {
        mtime: u64,
        atime: u64,
    },
    Error {
        fatal: bool,
        message: String,
    },
}

/// Parses one rcp/scp wire header line (`C`, `D`, `E`, `T`, `\x01`, `\x02`).
pub fn scp_parse_header_line(line: &str) -> Result<ScpRecord, ProtoError> {
    let trimmed = line.strip_suffix('\n').unwrap_or(line);
    let trimmed = trimmed.strip_suffix('\r').unwrap_or(trimmed);
    let Some(first) = trimmed.as_bytes().first().copied() else {
        return Err(ProtoError::Transport("Empty SCP header line.".to_string()));
    };

    match first {
        1 | 2 => Ok(ScpRecord::Error {
            fatal: first == 2,
            message: trimmed[1..].trim().to_string(),
        }),
        b'E' => {
            if trimmed != "E" {
                return Err(ProtoError::Transport(format!(
                    "Malformed SCP end-directory header '{trimmed}'."
                )));
            }
            Ok(ScpRecord::EndDirectory)
        }
        b'T' => {
            let parts: Vec<&str> = trimmed[1..].split(' ').collect();
            if parts.len() != 4
                || !parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            {
                return Err(ProtoError::Transport(format!(
                    "Malformed SCP timestamp header '{trimmed}'."
                )));
            }
            let mtime: u64 = parts[0]
                .parse()
                .map_err(|_| ProtoError::Transport("SCP mtime overflow.".to_string()))?;
            let usec1: u64 = parts[1]
                .parse()
                .map_err(|_| ProtoError::Transport("SCP mtime usec overflow.".to_string()))?;
            let atime: u64 = parts[2]
                .parse()
                .map_err(|_| ProtoError::Transport("SCP atime overflow.".to_string()))?;
            let usec2: u64 = parts[3]
                .parse()
                .map_err(|_| ProtoError::Transport("SCP atime usec overflow.".to_string()))?;
            if usec1 >= 1_000_000 || usec2 >= 1_000_000 {
                return Err(ProtoError::Transport(
                    "SCP timestamp microseconds out of range.".to_string(),
                ));
            }
            Ok(ScpRecord::Timestamp { mtime, atime })
        }
        b'C' | b'D' => {
            let rest = &trimmed[1..];
            let (mode_str, after_mode) = rest.split_once(' ').ok_or_else(|| {
                ProtoError::Transport(format!("Malformed SCP header '{trimmed}'."))
            })?;
            if mode_str.len() != 4 || !mode_str.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                return Err(ProtoError::Transport(format!(
                    "Invalid octal mode '{mode_str}' in SCP header."
                )));
            }
            let mode = u32::from_str_radix(mode_str, 8).unwrap_or(0o644);
            let (size_str, name) = after_mode.split_once(' ').ok_or_else(|| {
                ProtoError::Transport(format!("Malformed SCP size/name in '{trimmed}'."))
            })?;
            if size_str.is_empty() || !size_str.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ProtoError::Transport(format!(
                    "Invalid size '{size_str}' in SCP header."
                )));
            }
            let size: u64 = size_str
                .parse()
                .map_err(|_| ProtoError::Transport("SCP file size overflow.".to_string()))?;
            validate_scp_received_name(name)?;
            if first == b'C' {
                Ok(ScpRecord::File {
                    mode,
                    size,
                    name: name.to_string(),
                })
            } else {
                Ok(ScpRecord::Directory {
                    mode,
                    name: name.to_string(),
                })
            }
        }
        _ => Err(ProtoError::Transport(format!(
            "Unrecognized SCP wire header '{trimmed}'."
        ))),
    }
}

pub fn scp_file_header_line(mode: u32, size: u64, name: &str) -> Result<String, ProtoError> {
    validate_scp_received_name(name)?;
    Ok(format!("C{:04o} {size} {name}\n", mode & 0o7777))
}

pub fn scp_directory_header_line(mode: u32, name: &str) -> Result<String, ProtoError> {
    validate_scp_received_name(name)?;
    Ok(format!("D{:04o} 0 {name}\n", mode & 0o7777))
}

pub fn scp_time_header_line(mtime: u64, atime: u64) -> String {
    format!("T{mtime} 0 {atime} 0\n")
}

/// Formats Unix seconds as POSIX `touch -t` UTC stamp (`YYYYMMDDhhmm.ss`).
pub fn scp_touch_stamp(seconds_since_epoch: i64) -> String {
    let ts = seconds_since_epoch.max(0);
    let days = ts.div_euclid(86_400);
    let rem = ts.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}.{second:02}")
}

pub fn scp_parse_full_time(date_text: &str, time_text: &str, offset_text: &str) -> Option<i64> {
    parse_full_time_columns(date_text, time_text, offset_text)
}

pub fn scp_says_missing(stderr_text: &str) -> bool {
    let lower = stderr_text.to_ascii_lowercase();
    lower.contains("no such file or directory")
        || lower.contains("does not exist")
        || lower.contains("not found")
        || lower.contains("nonexistent")
}

fn option_unsupported(stderr_text: &str) -> bool {
    let lower = stderr_text.to_ascii_lowercase();
    lower.contains("unrecognized option")
        || lower.contains("unknown option")
        || lower.contains("invalid option")
        || lower.contains("illegal option")
        || lower.contains("--full-time")
}

async fn read_scp_line<R: AsyncRead + Unpin>(reader: &mut R) -> Result<String, ProtoError> {
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        reader
            .read_exact(&mut byte)
            .await
            .map_err(|e| ProtoError::Transport(format!("SCP channel closed while reading header: {e}")))?;
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if buf.len() > MAX_SCP_HEADER_LINE {
            return Err(ProtoError::Transport(
                "SCP header line exceeded 8 KiB limit.".to_string(),
            ));
        }
    }
    String::from_utf8(buf)
        .map_err(|_| ProtoError::Transport("SCP header contained invalid UTF-8.".to_string()))
}

async fn read_scp_ack<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(), ProtoError> {
    let mut b = [0u8; 1];
    reader
        .read_exact(&mut b)
        .await
        .map_err(|e| ProtoError::Transport(format!("SCP channel closed awaiting ack: {e}")))?;
    match b[0] {
        0 => Ok(()),
        1 | 2 => {
            let line = read_scp_line(reader).await.unwrap_or_default();
            let msg = line.trim();
            Err(ProtoError::Transport(if msg.is_empty() {
                "Remote scp reported an error.".to_string()
            } else {
                msg.to_string()
            }))
        }
        other => Err(ProtoError::Transport(format!(
            "Remote scp sent unexpected acknowledgement byte 0x{other:02X}."
        ))),
    }
}

/// Native SCP + POSIX shell session implementing `RemoteSession`.
pub struct ScpSession {
    ssh: Arc<SshConnection>,
    dest_cfg: Option<SshConnectConfig>,
    jump_tunnel: Option<Arc<SshJumpTunnel>>,
    home_dir: String,
}

impl ScpSession {
    pub async fn connect(
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
        let mut session = match Self::from_ssh_connection(ssh, jump_tunnel.clone()).await {
            Ok(s) => s,
            Err(e) => {
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
        let _ = session.ssh.disconnect().await;
        session.dest_cfg = Some(stored_cfg);
        Ok(session)
    }

    pub async fn from_ssh_connection(
        ssh: Arc<SshConnection>,
        jump_tunnel: Option<Arc<SshJumpTunnel>>,
    ) -> Result<Self, ProtoError> {
        let out = ssh.exec_command("pwd").await?;
        let home_dir = if out.exit_code == Some(0) {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .last()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("/")
                .to_string()
        } else {
            "/".to_string()
        };
        Ok(Self {
            ssh,
            dest_cfg: None,
            jump_tunnel,
            home_dir,
        })
    }

    pub fn observed_fingerprint(&self) -> &str {
        self.ssh.observed_fingerprint()
    }

    async fn acquire_ssh(&self) -> Result<(Arc<SshConnection>, bool), ProtoError> {
        if let Some(cfg) = &self.dest_cfg {
            let conn = if let Some(jump) = &self.jump_tunnel {
                let stream = jump.open_destination_stream(&cfg.host, cfg.port, 0).await?;
                SshConnection::connect_over_stream(cfg, stream).await?
            } else {
                SshConnection::connect(cfg).await?
            };
            Ok((Arc::new(conn), true))
        } else {
            Ok((Arc::clone(&self.ssh), false))
        }
    }

    async fn exec_one_shot(&self, cmd: &str) -> Result<crate::ssh::ExecOutput, ProtoError> {
        let (conn, owned) = self.acquire_ssh().await?;
        let res = conn.exec_command(cmd).await;
        if owned {
            let _ = conn.disconnect().await;
        }
        res
    }

    async fn run_shell_checked(&self, cmd: &str) -> Result<String, ProtoError> {
        let reply = self.exec_one_shot(cmd).await?;
        match reply.exit_code {
            Some(0) => Ok(String::from_utf8_lossy(&reply.stdout).into_owned()),
            Some(code) => {
                let err_txt = String::from_utf8_lossy(&reply.stderr).trim().to_string();
                Err(ProtoError::Transport(if err_txt.is_empty() {
                    format!("Remote command '{cmd}' failed with exit status {code}.")
                } else {
                    err_txt
                }))
            }
            None => Err(ProtoError::Transport(format!(
                "SSH channel closed without exit status while running '{cmd}'."
            ))),
        }
    }

    async fn run_ls(&self, flag: &str, path: &str) -> Result<(u32, String, String), ProtoError> {
        let quoted = scp_shell_quote(path);
        for (with_env, full_time) in [(true, true), (true, false), (false, true), (false, false)] {
            let env_prefix = if with_env { "env LC_ALL=C " } else { "" };
            let ft = if full_time { "--full-time " } else { "" };
            let cmd = format!("{env_prefix}ls -l {flag} {ft}{quoted}");
            let out = self.exec_one_shot(&cmd).await?;
            let Some(code) = out.exit_code else {
                return Err(ProtoError::Transport(
                    "Connection closed while running remote 'ls'.".to_string(),
                ));
            };
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            if code == 0 {
                return Ok((0, stdout, stderr));
            }
            if with_env && code == 127 {
                continue;
            }
            if full_time && option_unsupported(&stderr) {
                continue;
            }
            return Ok((code, stdout, stderr));
        }
        Err(ProtoError::Transport("Remote 'ls' invocation failed.".to_string()))
    }
}

#[async_trait]
impl RemoteSession for ScpSession {
    fn scheme(&self) -> ProtocolScheme {
        ProtocolScheme::Scp
    }

    async fn pwd(&self) -> Result<String, ProtoError> {
        Ok(self.home_dir.clone())
    }

    async fn stat(&self, remote_path: &str) -> Result<Option<FileEntry>, ProtoError> {
        let norm = prepare_remote_path(remote_path)?;
        let (code, stdout, stderr) = self.run_ls("-d", &norm).await?;
        if code != 0 {
            if scp_says_missing(&stderr) {
                return Ok(None);
            }
            return Err(ProtoError::Transport(if stderr.trim().is_empty() {
                format!("stat '{remote_path}' failed with exit status {code}.")
            } else {
                stderr.trim().to_string()
            }));
        }
        for line in stdout.lines() {
            if let Some(mut parsed) = parse_unix_listing_line(line) {
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
        Ok(None)
    }

    async fn list_dir(&self, remote_path: &str) -> Result<Vec<FileEntry>, ProtoError> {
        let norm = prepare_remote_path(remote_path)?;
        let (code, stdout, stderr) = self.run_ls("-a", &norm).await?;
        if code != 0 {
            return Err(ProtoError::Transport(if stderr.trim().is_empty() {
                format!("Listing '{remote_path}' failed with exit status {code}.")
            } else {
                stderr.trim().to_string()
            }));
        }
        let mut entries = Vec::new();
        for line in stdout.lines() {
            if let Some(parsed) = parse_unix_listing_line(line) {
                entries.push(parsed.into_file_entry());
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    async fn mkdir(&self, remote_path: &str) -> Result<(), ProtoError> {
        let norm = prepare_remote_path(remote_path)?;
        self.run_shell_checked(&format!("mkdir -p -- {}", scp_shell_quote(&norm)))
            .await?;
        Ok(())
    }

    async fn remove_file(&self, remote_path: &str) -> Result<(), ProtoError> {
        let norm = prepare_remote_path(remote_path)?;
        self.run_shell_checked(&format!("rm -f -- {}", scp_shell_quote(&norm)))
            .await?;
        Ok(())
    }

    async fn remove_dir(&self, remote_path: &str) -> Result<(), ProtoError> {
        let norm = prepare_remote_path(remote_path)?;
        self.run_shell_checked(&format!("rmdir -- {}", scp_shell_quote(&norm)))
            .await?;
        Ok(())
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        let nf = prepare_remote_path(from)?;
        let nt = prepare_remote_path(to)?;
        self.run_shell_checked(&format!(
            "mv -f -- {} {}",
            scp_shell_quote(&nf),
            scp_shell_quote(&nt)
        ))
        .await?;
        Ok(())
    }

    async fn copy_file(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        let nf = prepare_remote_path(from)?;
        let nt = prepare_remote_path(to)?;
        self.run_shell_checked(&format!(
            "cp -p -- {} {}",
            scp_shell_quote(&nf),
            scp_shell_quote(&nt)
        ))
        .await?;
        Ok(())
    }

    async fn symlink(&self, target: &str, link_path: &str) -> Result<(), ProtoError> {
        scp_valid_remote_path(target)?;
        let nl = prepare_remote_path(link_path)?;
        self.run_shell_checked(&format!(
            "ln -s -- {} {}",
            scp_shell_quote(target),
            scp_shell_quote(&nl)
        ))
        .await?;
        Ok(())
    }

    async fn chmod(&self, remote_path: &str, mode: u32) -> Result<(), ProtoError> {
        let norm = prepare_remote_path(remote_path)?;
        self.run_shell_checked(&format!(
            "chmod {:04o} -- {}",
            mode & 0o7777,
            scp_shell_quote(&norm)
        ))
        .await?;
        Ok(())
    }

    async fn set_mtime(&self, remote_path: &str, mtime: i64) -> Result<(), ProtoError> {
        let norm = prepare_remote_path(remote_path)?;
        let stamp = scp_touch_stamp(mtime);
        self.run_shell_checked(&format!(
            "env TZ=UTC0 touch -t {stamp} -- {}",
            scp_shell_quote(&norm)
        ))
        .await?;
        Ok(())
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
        if opts.resume_offset > 0 {
            return Err(ProtoError::Transport(
                "The SCP protocol does not support byte-offset resume.".to_string(),
            ));
        }
        let norm = prepare_remote_path(remote_path)?;
        let p_flag = if opts.preserve_time { "-p " } else { "" };
        let cmd = format!("scp {p_flag}-f -- {}", scp_shell_quote(&norm));

        let (conn, owned) = self.acquire_ssh().await?;
        let res: Result<u64, ProtoError> = async {
            let channel = conn.open_session_channel().await?;
            channel
                .exec(true, cmd.as_str())
                .await
                .map_err(|e| ProtoError::Transport(format!("Failed to start '{cmd}': {e}")))?;
            let mut stream = channel.into_stream();

            // Kick off source mode by sending initial NUL byte
            stream.write_all(&[0u8]).await.map_err(|e| {
                ProtoError::Transport(format!("SCP initial ack write failed: {e}"))
            })?;
            stream.flush().await.map_err(|e| {
                ProtoError::Transport(format!("SCP initial ack flush failed: {e}"))
            })?;

            loop {
                let line = read_scp_line(&mut stream).await?;
                match scp_parse_header_line(&line)? {
                    ScpRecord::Timestamp { .. } => {
                        stream.write_all(&[0u8]).await.map_err(|e| {
                            ProtoError::Transport(format!("SCP timestamp ack write failed: {e}"))
                        })?;
                        stream.flush().await.map_err(|e| {
                            ProtoError::Transport(format!("SCP timestamp ack flush failed: {e}"))
                        })?;
                    }
                    ScpRecord::File { size, .. } => {
                        stream.write_all(&[0u8]).await.map_err(|e| {
                            ProtoError::Transport(format!("SCP file header ack failed: {e}"))
                        })?;
                        stream.flush().await.map_err(|e| {
                            ProtoError::Transport(format!("SCP file header flush failed: {e}"))
                        })?;

                        let mut remaining = size;
                        let mut transferred = 0u64;
                        let mut buf = vec![0u8; SCP_CHUNK_SIZE];
                        let mut limiter = RateLimiter::new(opts.speed_kbytes_per_sec);
                        while remaining > 0 {
                            let to_read = (remaining as usize).min(SCP_CHUNK_SIZE);
                            let n = stream.read(&mut buf[..to_read]).await.map_err(|e| {
                                ProtoError::Transport(format!("SCP payload read failed: {e}"))
                            })?;
                            if n == 0 {
                                return Err(ProtoError::Transport(
                                    "Remote scp closed connection mid-file.".to_string(),
                                ));
                            }
                            sink.write_all(&buf[..n]).await.map_err(|e| {
                                ProtoError::Transport(format!("SCP local sink write failed: {e}"))
                            })?;
                            remaining -= n as u64;
                            transferred += n as u64;
                            if let Some(cb) = progress {
                                cb(transferred, size);
                            }
                            if opts.speed_kbytes_per_sec > 0 {
                                sink.flush().await.map_err(|e| {
                                    ProtoError::Transport(format!(
                                        "SCP local sink flush failed: {e}"
                                    ))
                                })?;
                            }
                            limiter.consume(n).await;
                        }
                        sink.flush().await.map_err(|e| {
                            ProtoError::Transport(format!("SCP local sink flush failed: {e}"))
                        })?;

                        // Read trailing status byte from `scp -f` and acknowledge with `\0`
                        read_scp_ack(&mut stream).await?;
                        let _ = stream.write_all(&[0u8]).await;
                        let _ = stream.flush().await;
                        return Ok(transferred);
                    }
                    ScpRecord::Error { message, .. } => {
                        return Err(ProtoError::Transport(if message.is_empty() {
                            "Remote scp reported an error.".to_string()
                        } else {
                            message
                        }));
                    }
                    ScpRecord::Directory { name, .. } => {
                        return Err(ProtoError::Transport(format!(
                            "Remote path '{name}' is a directory, not a regular file."
                        )));
                    }
                    ScpRecord::EndDirectory => {
                        return Err(ProtoError::Transport(
                            "Unexpected SCP 'E' record during single-file download.".to_string(),
                        ));
                    }
                }
            }
        }
        .await;
        if owned {
            let _ = conn.disconnect().await;
        }
        res
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
                "The SCP protocol does not support byte-offset resume or append.".to_string(),
            ));
        }
        let norm = prepare_remote_path(remote_path)?;
        let (target_arg, leaf_name) = match norm.rsplit_once('/') {
            Some(("", leaf)) => (format!("/{leaf}"), leaf.to_string()),
            Some((_dir, leaf)) => (norm.clone(), leaf.to_string()),
            None => (norm.clone(), norm.clone()),
        };
        validate_scp_received_name(&leaf_name)?;

        // SCP wire header requires exact file size upfront; buffer when caller did not supply it.
        let mut buffered_payload: Option<Vec<u8>> = None;
        let exact_size = match total_size {
            Some(sz) => sz,
            None => {
                let mut v = Vec::new();
                source.read_to_end(&mut v).await.map_err(|e| {
                    ProtoError::Transport(format!("Failed to read SCP upload source: {e}"))
                })?;
                let len = v.len() as u64;
                buffered_payload = Some(v);
                len
            }
        };

        let p_flag = if opts.preserve_time && opts.mtime.is_some() {
            "-p "
        } else {
            ""
        };
        let cmd = format!("scp {p_flag}-t -- {}", scp_shell_quote(&target_arg));

        let (conn, owned) = self.acquire_ssh().await?;
        let res: Result<u64, ProtoError> = async {
            let channel = conn.open_session_channel().await?;
            channel
                .exec(true, cmd.as_str())
                .await
                .map_err(|e| ProtoError::Transport(format!("Failed to start '{cmd}': {e}")))?;
            let mut stream = channel.into_stream();

            read_scp_ack(&mut stream).await?;

            if opts.preserve_time {
                if let Some(mtime) = opts.mtime {
                    let ts = mtime.max(0) as u64;
                    let thdr = scp_time_header_line(ts, ts);
                    stream.write_all(thdr.as_bytes()).await.map_err(|e| {
                        ProtoError::Transport(format!("SCP time header write failed: {e}"))
                    })?;
                    stream.flush().await.map_err(|e| {
                        ProtoError::Transport(format!("SCP time flush failed: {e}"))
                    })?;
                    read_scp_ack(&mut stream).await?;
                }
            }

            let mode = opts.permissions.unwrap_or(0o644);
            let chdr = scp_file_header_line(mode, exact_size, &leaf_name)?;
            stream.write_all(chdr.as_bytes()).await.map_err(|e| {
                ProtoError::Transport(format!("SCP file header write failed: {e}"))
            })?;
            stream
                .flush()
                .await
                .map_err(|e| ProtoError::Transport(format!("SCP file header flush failed: {e}")))?;
            read_scp_ack(&mut stream).await?;

            let mut transferred = 0u64;
            let mut limiter = RateLimiter::new(opts.speed_kbytes_per_sec);

            if let Some(bytes) = buffered_payload {
                for chunk in bytes.chunks(SCP_CHUNK_SIZE) {
                    stream.write_all(chunk).await.map_err(|e| {
                        ProtoError::Transport(format!("SCP data write failed: {e}"))
                    })?;
                    transferred += chunk.len() as u64;
                    if let Some(cb) = progress {
                        cb(transferred, exact_size);
                    }
                    limiter.consume(chunk.len()).await;
                }
            } else {
                let mut buf = vec![0u8; SCP_CHUNK_SIZE];
                while transferred < exact_size {
                    let want = ((exact_size - transferred) as usize).min(SCP_CHUNK_SIZE);
                    let n = source.read(&mut buf[..want]).await.map_err(|e| {
                        ProtoError::Transport(format!("SCP upload source read failed: {e}"))
                    })?;
                    if n == 0 {
                        return Err(ProtoError::Transport(format!(
                            "Upload source ended early after {transferred} of {exact_size} bytes."
                        )));
                    }
                    stream.write_all(&buf[..n]).await.map_err(|e| {
                        ProtoError::Transport(format!("SCP data write failed: {e}"))
                    })?;
                    transferred += n as u64;
                    if let Some(cb) = progress {
                        cb(transferred, exact_size);
                    }
                    limiter.consume(n).await;
                }
            }

            // Trailing NUL byte + final server ack
            stream
                .write_all(&[0u8])
                .await
                .map_err(|e| ProtoError::Transport(format!("SCP trailer write failed: {e}")))?;
            stream
                .flush()
                .await
                .map_err(|e| ProtoError::Transport(format!("SCP trailer flush failed: {e}")))?;
            read_scp_ack(&mut stream).await?;
            let _ = stream.shutdown().await;
            Ok(transferred)
        }
        .await;
        if owned {
            let _ = conn.disconnect().await;
        }
        res
    }

    async fn realpath(&self, remote_path: &str) -> Result<String, ProtoError> {
        let target = if remote_path.is_empty() || remote_path == "." {
            return Ok(self.home_dir.clone());
        } else {
            remote_path
        };
        scp_valid_remote_path(target)?;
        let cmd = format!("cd -- {} && pwd", scp_shell_quote(target));
        let out = self.run_shell_checked(&cmd).await?;
        Ok(out
            .lines()
            .last()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("/")
            .to_string())
    }

    async fn readlink(&self, link_path: &str) -> Result<String, ProtoError> {
        let norm = prepare_remote_path(link_path)?;
        let out = self
            .run_shell_checked(&format!("readlink -- {}", scp_shell_quote(&norm)))
            .await?;
        Ok(out.trim_end_matches(['\r', '\n']).to_string())
    }

    async fn exec_command(&self, command: &str) -> Result<crate::ssh::ExecOutput, ProtoError> {
        self.exec_one_shot(command).await
    }

    async fn close(&self) -> Result<(), ProtoError> {
        let res = self.ssh.disconnect().await;
        if let Some(jump) = &self.jump_tunnel {
            let _ = jump.close().await;
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quoting_and_path_hardening_reject_traversal_and_flags() {
        assert_eq!(scp_shell_quote("it's fine.txt"), "'it'\\''s fine.txt'");
        assert_eq!(prepare_remote_path("-rf").unwrap(), "./-rf");
        assert!(scp_valid_remote_path("bad\nname").is_err());

        assert!(validate_scp_received_name("..").is_err());
        assert!(validate_scp_received_name("../passwd").is_err());
        assert!(validate_scp_received_name("sub\\evil").is_err());
        assert!(validate_scp_received_name("clean.tar.gz").is_ok());
    }

    #[test]
    fn scp_wire_headers_and_touch_stamp_match_posix_forms() {
        assert_eq!(scp_touch_stamp(1_792_128_787), "202610160533.07");
        let parsed = scp_parse_header_line("C0640 512 notes.txt\n").unwrap();
        assert_eq!(
            parsed,
            ScpRecord::File {
                mode: 0o640,
                size: 512,
                name: "notes.txt".to_string()
            }
        );
        assert!(scp_parse_header_line("C0644 10 ../escape\n").is_err());
    }
}
