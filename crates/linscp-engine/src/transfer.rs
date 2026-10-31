//! Resumable `.filepart` transfer engine, ASCII/automatic EOL conversion,
//! speed throttling, permissions & timestamp preservation, S3 `-versionid=`,
//! and stdin/stdout (`-`) streaming.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use linscp_crypto::digests::sha256_hex;
use linscp_platform::terminal::{
    is_interrupted, set_local_file_times, set_local_permissions, stat_local_path,
};
use linscp_proto::{ProgressCallback, RemoteSession, TransferRequest};
use linscp_types::{FileEntry, ProtocolScheme, TransferMode};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, AsyncSeekExt};
use crate::filemask::{FileMask, join_remote_path, mode_from_permissions_str};
use crate::presets::{PresetPermissions, ResumeSupportMode, TransferPreset};
use crate::text_mode::{EolStyle, convert_eol_bytes, wants_ascii_conversion};
use crate::xml_log::SessionLogger;

const MAX_STAGE_NAME_BYTES: usize = 255;

#[derive(Debug, Clone)]
pub struct TransferFlags {
    pub transfer_mode: TransferMode,
    pub preserve_time: bool,
    pub preserve_time_dirs: bool,
    pub newer_only: bool,
    pub latest_only: bool,
    pub delete_source: bool,
    pub resume: bool,
    pub append: bool,
    pub recursive: bool,
    /// Do not replace an existing destination; fail if the protocol cannot enforce this.
    pub no_clobber: bool,
    /// User acknowledged FTP's non-atomic rename and overwrite race.
    pub ftp_risky_publish: bool,
    /// Server-side compare-and-replace using a previously approved strong ETag.
    pub overwrite_etag: Option<String>,
    /// Read only the remote representation matching this strong ETag.
    pub source_etag: Option<String>,
    /// Cooperative cancellation checked between I/O operations.
    pub cancel_flag: Option<Arc<AtomicBool>>,
    /// Use an owned temporary stage and remove it after a fresh download.
    pub cleanup_download_stage: bool,
    /// Merge an explicitly approved existing SFTP directory without replacing files.
    pub merge_directories: bool,
    pub resume_support: ResumeSupportMode,
    pub explicit_resume_support: bool,
    pub permissions: PresetPermissions,
    pub speed_kbytes_per_sec: Option<u64>,
    pub version_id: Option<String>,
    pub file_mask: FileMask,
    pub eol_override: Option<EolStyle>,
}

impl Default for TransferFlags {
    fn default() -> Self {
        Self {
            transfer_mode: TransferMode::Binary,
            preserve_time: true,
            preserve_time_dirs: false,
            newer_only: false,
            latest_only: false,
            delete_source: false,
            resume: false,
            append: false,
            recursive: false,
            no_clobber: false,
            ftp_risky_publish: false,
            overwrite_etag: None,
            source_etag: None,
            cancel_flag: None,
            cleanup_download_stage: false,
            merge_directories: false,
            resume_support: ResumeSupportMode::Smart(100 * 1024),
            explicit_resume_support: false,
            permissions: PresetPermissions::Off,
            speed_kbytes_per_sec: None,
            version_id: None,
            file_mask: FileMask::default(),
            eol_override: None,
        }
    }
}

impl TransferFlags {
    pub fn apply_preset(&mut self, preset: &TransferPreset) {
        if let Some(m) = preset.transfer_mode {
            self.transfer_mode = m;
        }
        if let Some(pt) = preset.preserve_time {
            self.preserve_time = pt;
        }
        if let Some(ptd) = preset.preserve_time_dirs {
            self.preserve_time_dirs = ptd;
        }
        if let Some(no) = preset.newer_only {
            self.newer_only = no;
        }
        if let Some(perms) = preset.permissions {
            self.permissions = perms;
        }
        if let Some(rs) = preset.resume_support {
            self.resume_support = rs;
        }
        if let Some(sp) = preset.speed_kbytes_per_sec {
            self.speed_kbytes_per_sec = if sp == 0 { None } else { Some(sp) };
        }
        if !preset.mask.is_empty() && self.file_mask.is_empty() {
            if let Ok(m) = FileMask::parse(&preset.mask) {
                self.file_mask = m;
            }
        }
    }
}

/// Computes the `.filepart` (or S3 version-scoped `.filepart.v<sha256>`) stage filename.
pub fn stage_suffix(version_id: Option<&str>) -> String {
    match version_id.filter(|s| !s.is_empty()) {
        Some(vid) => format!(".filepart.v{}", sha256_hex(vid.as_bytes())),
        None => ".filepart".to_string(),
    }
}

pub fn remote_stage_path(remote_target: &str, version_id: Option<&str>) -> Option<String> {
    let suffix = stage_suffix(version_id);
    let leaf = remote_target.rsplit('/').next().unwrap_or(remote_target);
    if leaf.len() + suffix.len() > MAX_STAGE_NAME_BYTES {
        return None;
    }
    Some(format!("{remote_target}{suffix}"))
}

pub fn local_stage_path(local_target: &Path, version_id: Option<&str>) -> Option<PathBuf> {
    let suffix = stage_suffix(version_id);
    let leaf = local_target.file_name()?.to_string_lossy();
    if leaf.len() + suffix.len() > MAX_STAGE_NAME_BYTES {
        return None;
    }
    let mut os = local_target.as_os_str().to_os_string();
    os.push(&suffix);
    Some(PathBuf::from(os))
}

/// Determines whether a file transfer should use `.filepart` temporary staging.
pub fn should_use_filepart(
    flags: &TransferFlags,
    scheme: ProtocolScheme,
    is_upload: bool,
    effective_ascii: bool,
    source_size: u64,
) -> bool {
    if effective_ascii || flags.append {
        return false;
    }
    // S3 uploads have native multipart checkpoints (`s3_multipart_resume.json`),
    // while S3 `CopyObject` for `.filepart` rename would double object writes unless requested.
    if is_upload && scheme == ProtocolScheme::S3 {
        return matches!(flags.resume_support, ResumeSupportMode::On);
    }
    if flags.resume {
        return !matches!(flags.resume_support, ResumeSupportMode::Off);
    }
    match flags.resume_support {
        ResumeSupportMode::On => true,
        ResumeSupportMode::Off => false,
        ResumeSupportMode::Smart(threshold) => source_size >= threshold,
    }
}

/// AsyncRead adapter that checks `linscp_platform::terminal::is_interrupted()` on every read,
/// returning `ErrorKind::Interrupted` immediately on Ctrl+C / SIGTERM so `.filepart` stays intact.
struct InterruptibleReader<R> {
    inner: R,
    cancel_flag: Option<Arc<AtomicBool>>,
}

impl<R: AsyncRead + Unpin> AsyncRead for InterruptibleReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.cancel_flag.as_ref().is_some_and(|flag| flag.load(Ordering::SeqCst)) {
            return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, "Transfer cancelled.")));
        }
        if is_interrupted() {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Transfer interrupted by signal.",
            )));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// AsyncWrite adapter that checks `linscp_platform::terminal::is_interrupted()` on every write.
struct InterruptibleWriter<W> {
    inner: W,
    cancel_flag: Option<Arc<AtomicBool>>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for InterruptibleWriter<W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.cancel_flag.as_ref().is_some_and(|flag| flag.load(Ordering::SeqCst)) {
            return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, "Transfer cancelled.")));
        }
        if is_interrupted() {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "Transfer interrupted by signal.",
            )));
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn speed_u32(speed: Option<u64>) -> u32 {
    speed
        .map(|s| s.min(u64::from(u32::MAX)) as u32)
        .unwrap_or(0)
}

fn is_webdav_scheme(scheme: ProtocolScheme) -> bool {
    matches!(
        scheme,
        ProtocolScheme::Dav
            | ProtocolScheme::Davs
            | ProtocolScheme::Webdav
            | ProtocolScheme::Webdavs
    )
}

fn is_ftp_scheme(scheme: ProtocolScheme) -> bool {
    matches!(
        scheme,
        ProtocolScheme::Ftp | ProtocolScheme::Ftps | ProtocolScheme::Ftpes
    )
}

fn validate_protocol_transfer_flags(
    flags: &TransferFlags,
    scheme: ProtocolScheme,
    is_upload: bool,
) -> Result<(), String> {
    if flags.resume && flags.append {
        return Err("Cannot combine '-resume' and '-append'.".to_string());
    }
    if flags.version_id.is_some() {
        if scheme != ProtocolScheme::S3 {
            return Err("'-versionid' is available only for S3 sessions.".to_string());
        }
        if is_upload {
            return Err("'-versionid' cannot be used with 'put'.".to_string());
        }
    }
    if flags.append {
        if !is_upload {
            return Err(
                "'-append' on 'get' is supported only when appending to a local file.".to_string(),
            );
        }
        if scheme != ProtocolScheme::Sftp && !is_ftp_scheme(scheme) {
            return Err(format!(
                "'-append' is not supported for {} protocol.",
                scheme.as_str().to_uppercase()
            ));
        }
    }
    if matches!(scheme, ProtocolScheme::Scp | ProtocolScheme::Ssh)
        && (flags.resume
            || matches!(flags.resume_support, ResumeSupportMode::On)
            || (flags.explicit_resume_support
                && matches!(flags.resume_support, ResumeSupportMode::Smart(_))))
    {
        return Err("The SCP protocol cannot resume transfers.".to_string());
    }
    Ok(())
}

/// Resume a WebDAV download only after comparing every existing partial byte
/// against the same ETag-pinned remote representation. The existing partial is
/// read-only and is never deleted or modified by this routine.
pub async fn download_verified_resume(
    session: &dyn RemoteSession, remote_path: &str, info: &FileEntry, local_dest: &Path,
    flags: &TransferFlags, logger: &mut SessionLogger, progress: Option<&ProgressCallback>,
) -> Result<(), String> {
    let etag = flags.source_etag.as_deref().ok_or("Verified resume requires a strong source ETag.")?;
    if !flags.no_clobber || flags.append || flags.delete_source || flags.transfer_mode != TransferMode::Binary {
        return Err("Verified resume requires a fresh binary, no-overwrite download.".to_string());
    }
    let checkpoint = local_stage_path(local_dest, None).ok_or("Cannot construct a safe partial-file name.")?;
    let existing = match std::fs::symlink_metadata(&checkpoint) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => true,
        Ok(_) => return Err("Resume partial must be a regular file, not a symlink or directory.".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(format!("Cannot inspect resume partial: {error}")),
    };
    let parent = local_dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let temp = tempfile::Builder::new().prefix(".linscp-download-").rand_bytes(16).tempfile_in(parent)
        .map_err(|e| format!("Cannot create temporary download: {e}"))?;
    let (std_file, stage) = temp.into_parts();
    let mut file = tokio::fs::File::from_std(std_file);
    let mut offset = 0u64;
    if existing {
        let input = tokio::fs::File::open(&checkpoint).await.map_err(|e| format!("Cannot open resume partial: {e}"))?;
        let reader = InterruptibleReader { inner: input, cancel_flag: flags.cancel_flag.clone() };
        let mut reader = reader.take(info.size.saturating_add(1));
        offset = tokio::io::copy(&mut reader, &mut file).await.map_err(|e| format!("Cannot copy resume partial: {e}"))?;
        if offset > info.size { return Err("Resume partial is larger than the remote file.".to_string()); }
        file.flush().await.map_err(|e| format!("Cannot flush resume staging file: {e}"))?;
        if offset > 0 {
            file.seek(std::io::SeekFrom::Start(0)).await.map_err(|e| e.to_string())?;
            let mut reader = InterruptibleReader { inner: &mut file, cancel_flag: flags.cancel_flag.clone() };
            session.verify_prefix_if_match(remote_path, etag, offset, info.size, &mut reader).await.map_err(|e| e.to_string())?;
        }
        file.seek(std::io::SeekFrom::End(0)).await.map_err(|e| e.to_string())?;
    }
    let result = if offset < info.size || info.size == 0 {
        let request = TransferRequest { resume_offset: offset, append: false, preserve_time: false, mtime: None, permissions: None, speed_kbytes_per_sec: speed_u32(flags.speed_kbytes_per_sec), version_id: None };
        let mut writer = InterruptibleWriter { inner: &mut file, cancel_flag: flags.cancel_flag.clone() };
        session.download_if_match(remote_path, etag, request, &mut writer, progress).await.map_err(|e| e.to_string())
    } else { Ok(0) };
    let flush = file.flush().await;
    drop(file);
    let received = match result {
        Ok(n) => n,
        Err(error) => {
            let cancelled = flags.cancel_flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst));
            if !existing && !cancelled && flush.is_ok() && std::fs::metadata(&stage).is_ok_and(|m| m.len() > 0) {
                if std::fs::hard_link(&stage, &checkpoint).is_ok() {
                    return Err(format!("{error}; a partial file was saved at '{}'.", checkpoint.display()));
                }
            }
            return Err(error);
        }
    };
    flush.map_err(|e| format!("Cannot flush resume staging file: {e}"))?;
    if offset.checked_add(received) != Some(info.size) { return Err("Remote file length changed during verified resume.".to_string()); }
    if flags.cancel_flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst)) { return Err("Transfer cancelled before publication.".to_string()); }
    std::fs::hard_link(&stage, local_dest).map_err(|e| format!("Cannot publish resumed file '{}': {e}", local_dest.display()))?;
    apply_downloaded_attrs(local_dest, info, flags);
    logger.record_transfer(false, remote_path, &local_dest.display().to_string(), Some(info.size), Ok(()));
    Ok(())
}

/// Downloads a single remote file (or streams to stdout when `local_dest == Path::new("-")`).
pub async fn download_single_file(
    session: &dyn RemoteSession,
    remote_path: &str,
    remote_entry: Option<&FileEntry>,
    local_dest: &Path,
    flags: &TransferFlags,
    logger: &mut SessionLogger,
    progress: Option<&ProgressCallback>,
) -> Result<bool, String> {
    if flags.source_etag.is_some() && (flags.delete_source || flags.append || flags.resume || local_dest == Path::new("-")) {
        return Err("Conditional downloads require a fresh staged file and separate conditional deletion.".to_string());
    }
    if flags.append {
        // Local append on download
    } else {
        validate_protocol_transfer_flags(flags, session.scheme(), false)?;
    }
    if flags.version_id.is_some() && session.scheme() != ProtocolScheme::S3 {
        return Err("'-versionid' is available only for S3 sessions.".to_string());
    }

    let owned_stat;
    let info = match remote_entry {
        Some(e) => e,
        None => {
            let st = if let Some(ref vid) = flags.version_id {
                session
                    .s3_stat_version(remote_path, vid)
                    .await
                    .map_err(|e| e.to_string())?
            } else {
                session
                    .stat(remote_path)
                    .await
                    .map_err(|e| e.to_string())?
            };
            let Some(found) = st else {
                let msg = format!("No such file or directory: '{remote_path}'.");
                logger.record_transfer(
                    false,
                    remote_path,
                    &local_dest.display().to_string(),
                    None,
                    Err(&msg),
                );
                return Err(msg);
            };
            owned_stat = found;
            &owned_stat
        }
    };

    if local_dest == Path::new("-") {
        let mut mem: Vec<u8> = Vec::with_capacity(info.size as usize);
        let req = TransferRequest {
            resume_offset: 0,
            append: false,
            preserve_time: false,
            mtime: None,
            permissions: None,
            speed_kbytes_per_sec: speed_u32(flags.speed_kbytes_per_sec),
            version_id: flags.version_id.clone(),
        };
        let mut writer = InterruptibleWriter { inner: &mut mem, cancel_flag: flags.cancel_flag.clone() };
        if let Err(e) = session
            .download(remote_path, req, &mut writer, progress)
            .await
        {
            let msg = e.to_string();
            logger.record_transfer(false, remote_path, "-", None, Err(&msg));
            return Err(msg);
        }
        let leaf = remote_path.rsplit('/').next().unwrap_or(remote_path);
        let out_bytes = if wants_ascii_conversion(flags.transfer_mode, leaf) {
            let eol = flags.eol_override.unwrap_or_else(EolStyle::local_native);
            convert_eol_bytes(&mem, eol)
        } else {
            mem
        };
        std::io::stdout()
            .write_all(&out_bytes)
            .and_then(|_| std::io::stdout().flush())
            .map_err(|e| format!("Writing downloaded stream to stdout failed: {e}"))?;
        logger.record_transfer(false, remote_path, "-", Some(out_bytes.len() as u64), Ok(()));
        if flags.delete_source {
            session
                .remove_file(remote_path)
                .await
                .map_err(|e| e.to_string())?;
        }
        return Ok(true);
    }

    let local_stat = stat_local_path(local_dest);
    if flags.newer_only
        && local_stat.exists
        && !local_stat.is_dir
        && info.mtime > 0
        && local_stat.mtime >= info.mtime
    {
        return Ok(false);
    }

    if let Some(parent) = local_dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Cannot create local directory '{}': {e}", parent.display()))?;
    }

    let leaf = remote_path.rsplit('/').next().unwrap_or(remote_path);
    let effective_ascii = wants_ascii_conversion(flags.transfer_mode, leaf);
    let dest_label = local_dest.display().to_string();

    if (flags.no_clobber || flags.source_etag.is_some()) && effective_ascii {
        return Err("Guarded downloads require binary transfer mode.".to_string());
    }
    if effective_ascii {
        let mut raw_bytes = Vec::with_capacity(info.size as usize);
        let req = TransferRequest {
            resume_offset: 0,
            append: false,
            preserve_time: false,
            mtime: None,
            permissions: None,
            speed_kbytes_per_sec: speed_u32(flags.speed_kbytes_per_sec),
            version_id: flags.version_id.clone(),
        };
        let mut writer = InterruptibleWriter {
            inner: &mut raw_bytes,
            cancel_flag: flags.cancel_flag.clone(),
        };
        if let Err(e) = session
            .download(remote_path, req, &mut writer, progress)
            .await
        {
            let msg = e.to_string();
            logger.record_transfer(false, remote_path, &dest_label, None, Err(&msg));
            return Err(msg);
        }
        let target_eol = flags.eol_override.unwrap_or_else(EolStyle::local_native);
        let converted = convert_eol_bytes(&raw_bytes, target_eol);
        if flags.append {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(local_dest)
                .map_err(|e| format!("Cannot open '{dest_label}': {e}"))?;
            f.write_all(&converted)
                .map_err(|e| format!("Cannot write '{dest_label}': {e}"))?;
        } else {
            std::fs::write(local_dest, &converted)
                .map_err(|e| format!("Cannot write '{dest_label}': {e}"))?;
        }
        apply_downloaded_attrs(local_dest, info, flags);
        logger.record_transfer(
            false,
            remote_path,
            &dest_label,
            Some(converted.len() as u64),
            Ok(()),
        );
        if flags.delete_source {
            session
                .remove_file(remote_path)
                .await
                .map_err(|e| e.to_string())?;
        }
        return Ok(true);
    }

    let use_stage = should_use_filepart(flags, session.scheme(), false, false, info.size);
    if flags.cleanup_download_stage && (flags.resume || flags.append || !use_stage) {
        return Err("Automatic cleanup requires a fresh staged download.".to_string());
    }
    // The private temp file is created exclusively in the destination directory
    // so publication stays on the same filesystem. TempPath removes only this
    // owned stage on early return, cancellation, or publication failure.
    let mut private_file = None;
    let mut _cleanup_stage = None;
    let stage_opt = if flags.cleanup_download_stage {
        let parent = local_dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        let temp = tempfile::Builder::new().prefix(".linscp-download-").rand_bytes(16)
            .tempfile_in(parent).map_err(|e| format!("Cannot create temporary download in '{}': {e}", parent.display()))?;
        let (file, path) = temp.into_parts();
        let stage = path.to_path_buf();
        private_file = Some(tokio::fs::File::from_std(file));
        _cleanup_stage = Some(path);
        Some(stage)
    } else if use_stage {
        local_stage_path(local_dest, flags.version_id.as_deref())
    } else {
        None
    };

    if flags.no_clobber && (stage_opt.is_none() || flags.resume || flags.append) {
        return Err("Safe no-overwrite downloads require a fresh staging file.".to_string());
    }
    let can_resume_proto = !matches!(session.scheme(), ProtocolScheme::Scp | ProtocolScheme::Ssh);
    let (write_path, resume_offset) = if flags.no_clobber {
        (stage_opt.as_ref().expect("checked above").clone(), 0u64)
    } else if let Some(ref sp) = stage_opt {
        if !flags.resume && !flags.append {
            // A fresh transfer must never adopt, truncate or remove somebody
            // else's staging file, even if it appeared after preflight.
            (sp.clone(), 0u64)
        } else {
            let sp_meta = stat_local_path(sp);
            if can_resume_proto && sp_meta.exists && sp_meta.is_regular {
                if sp_meta.size < info.size {
                    (sp.clone(), sp_meta.size)
                } else {
                    let _ = std::fs::remove_file(sp);
                    (sp.clone(), 0u64)
                }
            } else if can_resume_proto
                && flags.resume
                && local_stat.exists
                && local_stat.is_regular
                && local_stat.size < info.size
            {
                // Adopt existing partial target into stage path or resume directly
                let _ = std::fs::rename(local_dest, sp);
                let moved = stat_local_path(sp);
                (sp.clone(), if moved.exists { moved.size } else { 0 })
            } else {
                let _ = std::fs::remove_file(sp);
                (sp.clone(), 0u64)
            }
        }
    } else if flags.append && local_stat.exists && local_stat.is_regular {
        (local_dest.to_path_buf(), 0u64)
    } else if flags.resume && local_stat.exists && local_stat.is_regular && local_stat.size < info.size {
        (local_dest.to_path_buf(), local_stat.size)
    } else {
        (local_dest.to_path_buf(), 0u64)
    };

    let fresh_stage = stage_opt.is_some() && !flags.resume && !flags.append;
    let open_res = if let Some(file) = private_file.take() {
        Ok(file)
    } else if flags.no_clobber || fresh_stage {
        tokio::fs::OpenOptions::new().write(true).create_new(true).open(&write_path).await
    } else if resume_offset > 0 || flags.append {
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&write_path)
            .await
    } else {
        tokio::fs::File::create(&write_path).await
    };
    let mut file = open_res.map_err(|e| {
        let msg = format!("Cannot open local file '{}': {e}", write_path.display());
        logger.record_transfer(false, remote_path, &dest_label, None, Err(&msg));
        msg
    })?;

    let req = TransferRequest {
        resume_offset,
        append: false,
        preserve_time: false,
        mtime: None,
        permissions: None,
        speed_kbytes_per_sec: speed_u32(flags.speed_kbytes_per_sec),
        version_id: flags.version_id.clone(),
    };
    let dl_res = {
        let mut writer = InterruptibleWriter { inner: &mut file, cancel_flag: flags.cancel_flag.clone() };
        if let Some(etag) = flags.source_etag.as_deref() {
            session.download_if_match(remote_path, etag, req, &mut writer, progress).await
        } else {
            session.download(remote_path, req, &mut writer, progress).await
        }
    };
    let flush_res = tokio::io::AsyncWriteExt::flush(&mut file).await;
    drop(file);

    let bytes = match dl_res {
        Ok(n) => resume_offset + n,
        Err(err) => {
            let msg = err.to_string();
            logger.record_transfer(false, remote_path, &dest_label, None, Err(&msg));
            return Err(msg);
        }
    };

    if let Err(err) = flush_res {
        let msg = format!("Cannot flush downloaded file '{}': {err}", write_path.display());
        logger.record_transfer(false, remote_path, &dest_label, None, Err(&msg));
        return Err(msg);
    }
    if flags.source_etag.is_some() && bytes != info.size {
        return Err("Conditional download length does not match the source metadata; the source was not deleted.".to_string());
    }
    if flags.cancel_flag.as_ref().is_some_and(|flag| flag.load(Ordering::SeqCst)) {
        return Err("Transfer cancelled before publication.".to_string());
    }
    if let Some(ref sp) = stage_opt {
        let publish = if flags.no_clobber {
            // The hard link is an atomic create-if-absent on the same filesystem.
            // Never fall back to rename, which can replace a newly created target.
            std::fs::hard_link(sp, local_dest).map(|_| { let _ = std::fs::remove_file(sp); })
        } else {
            // Rename replaces atomically; never unlink the old destination first.
            // This still does not protect against changes after approval.
            std::fs::rename(sp, local_dest)
        };
        publish.map_err(|e| {
            let msg = format!(
                "Cannot finalize downloaded file '{}' -> '{}': {e}",
                sp.display(),
                dest_label
            );
            logger.record_transfer(false, remote_path, &dest_label, None, Err(&msg));
            msg
        })?;
    }

    apply_downloaded_attrs(local_dest, info, flags);
    logger.record_transfer(false, remote_path, &dest_label, Some(bytes), Ok(()));
    if flags.delete_source {
        session
            .remove_file(remote_path)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(true)
}

fn apply_downloaded_attrs(local_dest: &Path, info: &FileEntry, flags: &TransferFlags) {
    match flags.permissions {
        PresetPermissions::Off => {}
        PresetPermissions::FromFile => {
            let mode = mode_from_permissions_str(&info.permissions);
            if mode != 0 {
                let _ = set_local_permissions(local_dest, mode);
            }
        }
        PresetPermissions::Mode(m) => {
            let _ = set_local_permissions(local_dest, m);
        }
    }
    if flags.preserve_time && info.mtime > 0 {
        let _ = set_local_file_times(local_dest, info.mtime, info.mtime);
    }
}

/// Uploads a single local file (or stdin when `local_src == Path::new("-")`) to `remote_dest`.
pub async fn upload_single_file(
    session: &dyn RemoteSession,
    local_src: &Path,
    remote_dest: &str,
    flags: &TransferFlags,
    logger: &mut SessionLogger,
    progress: Option<&ProgressCallback>,
) -> Result<bool, String> {
    validate_protocol_transfer_flags(flags, session.scheme(), true)?;

    if local_src == Path::new("-") {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("Reading stdin for upload failed: {e}"))?;
        let leaf = remote_dest.rsplit('/').next().unwrap_or(remote_dest);
        let payload = if wants_ascii_conversion(flags.transfer_mode, leaf) {
            let eol = flags.eol_override.unwrap_or(EolStyle::Crlf);
            convert_eol_bytes(&buf, eol)
        } else {
            buf
        };
        let total = payload.len() as u64;
        let mut cursor = std::io::Cursor::new(payload);
        let mut reader = InterruptibleReader { inner: &mut cursor, cancel_flag: flags.cancel_flag.clone() };
        let req = TransferRequest {
            resume_offset: 0,
            append: flags.append,
            preserve_time: false,
            mtime: None,
            permissions: match flags.permissions {
                PresetPermissions::Mode(m) => Some(m),
                _ => None,
            },
            speed_kbytes_per_sec: speed_u32(flags.speed_kbytes_per_sec),
            version_id: None,
        };
        if let Err(e) = session
            .upload(remote_dest, req, &mut reader, Some(total), progress)
            .await
        {
            let msg = e.to_string();
            logger.record_transfer(true, "-", remote_dest, None, Err(&msg));
            return Err(msg);
        }
        logger.record_transfer(true, "-", remote_dest, Some(total), Ok(()));
        return Ok(true);
    }

    let local_info = stat_local_path(local_src);
    let src_label = local_src.display().to_string();
    if !local_info.exists || local_info.is_dir {
        let msg = format!("Local file '{src_label}' does not exist.");
        logger.record_transfer(true, &src_label, remote_dest, None, Err(&msg));
        return Err(msg);
    }

    if flags.newer_only {
        if let Ok(Some(remote_stat)) = session.stat(remote_dest).await {
            if !remote_stat.is_dir && remote_stat.mtime >= local_info.mtime && local_info.mtime > 0
            {
                return Ok(false);
            }
        }
    }

    let desired_perms = match flags.permissions {
        PresetPermissions::Off => None,
        PresetPermissions::FromFile => {
            if local_info.mode != 0 {
                Some(local_info.mode & 0o7777)
            } else {
                None
            }
        }
        PresetPermissions::Mode(m) => Some(m),
    };
    let desired_mtime = if flags.preserve_time && local_info.mtime > 0 {
        Some(local_info.mtime)
    } else {
        None
    };

    let leaf = local_src
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let effective_ascii = wants_ascii_conversion(flags.transfer_mode, &leaf);

    if (flags.no_clobber || flags.overwrite_etag.is_some()) && effective_ascii {
        return Err("Guarded uploads require binary transfer mode.".to_string());
    }
    if effective_ascii {
        let raw = std::fs::read(local_src)
            .map_err(|e| format!("Cannot read local file '{src_label}': {e}"))?;
        // Default server newline target on upload: CRLF unless overridden (`-eol=lf`)
        let target_eol = flags.eol_override.unwrap_or(EolStyle::Crlf);
        let converted = convert_eol_bytes(&raw, target_eol);
        let total = converted.len() as u64;
        let mut cursor = std::io::Cursor::new(converted);
        let mut reader = InterruptibleReader { inner: &mut cursor, cancel_flag: flags.cancel_flag.clone() };
        let req = TransferRequest {
            resume_offset: 0,
            append: flags.append,
            preserve_time: desired_mtime.is_some(),
            mtime: desired_mtime,
            permissions: desired_perms,
            speed_kbytes_per_sec: speed_u32(flags.speed_kbytes_per_sec),
            version_id: None,
        };
        if let Err(e) = session
            .upload(remote_dest, req, &mut reader, Some(total), progress)
            .await
        {
            let msg = e.to_string();
            logger.record_transfer(true, &src_label, remote_dest, None, Err(&msg));
            return Err(msg);
        }
        logger.record_transfer(true, &src_label, remote_dest, Some(total), Ok(()));
        if let Some(mt) = desired_mtime.filter(|_| session.scheme() != ProtocolScheme::S3) {
            logger.record_touch(remote_dest, mt, Ok(()));
        }
        if flags.delete_source {
            std::fs::remove_file(local_src)
                .map_err(|e| format!("Cannot remove source '{src_label}': {e}"))?;
        }
        return Ok(true);
    }

    if flags.ftp_risky_publish {
        if !is_ftp_scheme(session.scheme()) || flags.resume || flags.append || effective_ascii || flags.delete_source {
            return Err("FTP staged upload requires a fresh binary copy.".to_string());
        }
        let directory = remote_dest.rsplit_once('/').map(|(dir, _)| if dir.is_empty() { "/" } else { dir }).unwrap_or(".");
        let input = tokio::fs::File::open(local_src).await.map_err(|e| format!("Cannot open local file '{src_label}': {e}"))?;
        let mut reader = InterruptibleReader { inner: input, cancel_flag: flags.cancel_flag.clone() };
        let req = TransferRequest { resume_offset: 0, append: false, preserve_time: false, mtime: None, permissions: None, speed_kbytes_per_sec: speed_u32(flags.speed_kbytes_per_sec), version_id: None };
        let (bytes, stage) = session.upload_ftp_unique(directory, req, &mut reader, Some(local_info.size), progress).await.map_err(|e| e.to_string())?;
        if flags.cancel_flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst)) {
            return Err(format!("Cancelled before publication; temporary FTP file '{stage}' remains."));
        }
        if bytes != local_info.size { return Err(format!("Source size changed; temporary FTP file '{stage}' remains.")); }
        let current = session.stat(remote_dest).await.map_err(|e| format!("Cannot check FTP destination; temporary file '{stage}' remains: {e}"))?;
        if current.as_ref().is_some_and(|e| e.is_dir || e.is_symlink || flags.no_clobber) {
            return Err(format!("FTP destination changed; temporary file '{stage}' remains."));
        }
        if flags.cancel_flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst)) { return Err(format!("Cancelled before publication; temporary FTP file '{stage}' remains.")); }
        session.rename(&stage, remote_dest).await.map_err(|e| format!("FTP rename failed or could not be confirmed; '{stage}' may remain and destination may have changed: {e}"))?;
        if let Some(mt) = desired_mtime { let _ = session.set_mtime(remote_dest, mt).await; }
        logger.record_transfer(true, &src_label, remote_dest, Some(bytes), Ok(()));
        return Ok(true);
    }

    if flags.no_clobber || flags.overwrite_etag.is_some() {
        if flags.resume || flags.append || effective_ascii || (flags.no_clobber && flags.overwrite_etag.is_some()) {
            return Err("Exclusive uploads require a fresh binary transfer.".to_string());
        }
        let input = tokio::fs::File::open(local_src).await.map_err(|e| format!("Cannot open local file '{src_label}': {e}"))?;
        let mut reader = InterruptibleReader { inner: input, cancel_flag: flags.cancel_flag.clone() };
        let req = TransferRequest {
            resume_offset: 0, append: false, preserve_time: desired_mtime.is_some(),
            mtime: desired_mtime, permissions: desired_perms,
            speed_kbytes_per_sec: speed_u32(flags.speed_kbytes_per_sec), version_id: None,
        };
        let bytes = if let Some(etag) = flags.overwrite_etag.as_deref() {
            session.upload_if_match(remote_dest, etag, req, &mut reader, Some(local_info.size), progress).await
        } else {
            session.upload_exclusive(remote_dest, req, &mut reader, Some(local_info.size), progress).await
        }.map_err(|e| e.to_string())?;
        logger.record_transfer(true, &src_label, remote_dest, Some(bytes), Ok(()));
        if flags.delete_source {
            std::fs::remove_file(local_src).map_err(|e| format!("Cannot remove source '{src_label}': {e}"))?;
        }
        return Ok(true);
    }

    let use_stage = should_use_filepart(flags, session.scheme(), true, false, local_info.size);
    let stage_opt = if use_stage {
        remote_stage_path(remote_dest, None)
    } else {
        None
    };

    let can_resume_proto = !matches!(session.scheme(), ProtocolScheme::Scp | ProtocolScheme::Ssh);
    let (upload_path, resume_offset) = if let Some(ref sp) = stage_opt {
        if let Ok(Some(st)) = session.stat(sp).await {
            if can_resume_proto && !st.is_dir && st.size < local_info.size {
                (sp.clone(), st.size)
            } else {
                let _ = session.remove_file(sp).await;
                (sp.clone(), 0u64)
            }
        } else if can_resume_proto && flags.resume {
            if let Ok(Some(dst_st)) = session.stat(remote_dest).await {
                if !dst_st.is_dir && dst_st.size < local_info.size {
                    if session.rename(remote_dest, sp).await.is_ok() {
                        (sp.clone(), dst_st.size)
                    } else {
                        (remote_dest.to_string(), dst_st.size)
                    }
                } else {
                    (sp.clone(), 0u64)
                }
            } else {
                (sp.clone(), 0u64)
            }
        } else {
            (sp.clone(), 0u64)
        }
    } else if can_resume_proto && flags.resume {
        if let Ok(Some(dst_st)) = session.stat(remote_dest).await {
            if !dst_st.is_dir && dst_st.size < local_info.size {
                (remote_dest.to_string(), dst_st.size)
            } else {
                (remote_dest.to_string(), 0u64)
            }
        } else {
            (remote_dest.to_string(), 0u64)
        }
    } else {
        (remote_dest.to_string(), 0u64)
    };

    let mut std_file = std::fs::File::open(local_src)
        .map_err(|e| format!("Cannot open local file '{src_label}': {e}"))?;
    if resume_offset > 0 {
        std_file
            .seek(SeekFrom::Start(resume_offset))
            .map_err(|e| format!("Cannot seek local file '{src_label}': {e}"))?;
    }
    let async_file = tokio::fs::File::from_std(std_file);
    let mut reader = InterruptibleReader { inner: async_file, cancel_flag: flags.cancel_flag.clone() };
    let remaining = local_info.size.saturating_sub(resume_offset);

    let req = TransferRequest {
        resume_offset,
        append: flags.append,
        preserve_time: desired_mtime.is_some(),
        mtime: desired_mtime,
        permissions: desired_perms,
        speed_kbytes_per_sec: speed_u32(flags.speed_kbytes_per_sec),
        version_id: None,
    };

    if let Err(err) = session
        .upload(&upload_path, req, &mut reader, Some(remaining), progress)
        .await
    {
        let msg = err.to_string();
        logger.record_transfer(true, &src_label, remote_dest, None, Err(&msg));
        return Err(msg);
    }

    if flags.cancel_flag.as_ref().is_some_and(|flag| flag.load(Ordering::SeqCst)) {
        return Err("Transfer cancelled before publication.".to_string());
    }
    if let Some(ref sp) = stage_opt {
        if upload_path == *sp {
            // S3 CopyObject and WebDAV MOVE(Overwrite: T) replace atomically; POSIX/FTP servers may refuse rename over existing file
            if session.scheme() != ProtocolScheme::S3
                && !is_webdav_scheme(session.scheme())
                && session.stat(remote_dest).await.ok().flatten().is_some()
            {
                let _ = session.remove_file(remote_dest).await;
            }
            if let Err(err) = session.rename(sp, remote_dest).await {
                let msg = err.to_string();
                logger.record_transfer(true, &src_label, remote_dest, None, Err(&msg));
                return Err(msg);
            }
            if let Some(m) = desired_perms {
                let _ = session.chmod(remote_dest, m).await;
            }
            if let Some(mt) = desired_mtime {
                let _ = session.set_mtime(remote_dest, mt).await;
            }
        }
    }

    logger.record_transfer(true, &src_label, remote_dest, Some(local_info.size), Ok(()));
    if let Some(mt) = desired_mtime.filter(|_| session.scheme() != ProtocolScheme::S3) {
        logger.record_touch(remote_dest, mt, Ok(()));
    }
    if flags.delete_source {
        std::fs::remove_file(local_src)
            .map_err(|e| format!("Cannot remove source '{src_label}': {e}"))?;
    }
    Ok(true)
}

/// Recursively downloads a remote directory into `local_dir`.
pub async fn download_directory_recursive(
    session: &dyn RemoteSession,
    remote_dir: &str,
    local_dir: &Path,
    rel_prefix: &str,
    flags: &TransferFlags,
    logger: &mut SessionLogger,
    progress: Option<&ProgressCallback>,
) -> Result<u64, String> {
    std::fs::create_dir_all(local_dir)
        .map_err(|e| format!("Cannot create local directory '{}': {e}", local_dir.display()))?;
    let mut entries = session
        .list_dir(remote_dir)
        .await
        .map_err(|e| e.to_string())?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let mut count = 0u64;
    for entry in &entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        let rel = if rel_prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{rel_prefix}/{}", entry.name)
        };
        if !flags.file_mask.accepts(
            &entry.name,
            entry.is_dir,
            entry.size,
            entry.mtime.max(0) as u64,
            &rel,
        ) {
            continue;
        }
        let child_remote = join_remote_path(remote_dir, &entry.name);
        let child_local = local_dir.join(&entry.name);
        if entry.is_dir {
            count += Box::pin(download_directory_recursive(
                session,
                &child_remote,
                &child_local,
                &rel,
                flags,
                logger,
                progress,
            ))
            .await?;
            if flags.preserve_time && flags.preserve_time_dirs && entry.mtime > 0 {
                let _ = set_local_file_times(&child_local, entry.mtime, entry.mtime);
            }
        } else if download_single_file(
            session,
            &child_remote,
            Some(entry),
            &child_local,
            flags,
            logger,
            progress,
        )
        .await?
        {
            count += 1;
        }
    }
    if rel_prefix.is_empty() && flags.preserve_time && flags.preserve_time_dirs {
        if let Ok(Some(st)) = session.stat(remote_dir).await {
            if st.mtime > 0 {
                let _ = set_local_file_times(local_dir, st.mtime, st.mtime);
            }
        }
    }
    if flags.delete_source {
        let _ = session.remove_dir(remote_dir).await;
    }
    Ok(count)
}

/// Recursively uploads a local directory into `remote_dir`.
pub async fn upload_directory_recursive(
    session: &dyn RemoteSession,
    local_dir: &Path,
    remote_dir: &str,
    rel_prefix: &str,
    flags: &TransferFlags,
    logger: &mut SessionLogger,
    progress: Option<&ProgressCallback>,
) -> Result<u64, String> {
    if session.stat(remote_dir).await.map_err(|e| e.to_string())?.is_none() {
        session
            .mkdir(remote_dir)
            .await
            .map_err(|e| e.to_string())?;
        logger.record_mkdir(remote_dir, Ok(()));
    }

    let rd = std::fs::read_dir(local_dir)
        .map_err(|e| format!("Cannot read local directory '{}': {e}", local_dir.display()))?;
    let mut children: Vec<(String, PathBuf)> = Vec::new();
    for item in rd {
        let de = item.map_err(|e| format!("Directory iteration failed: {e}"))?;
        let name = de.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." {
            continue;
        }
        children.push((name, de.path()));
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));

    let mut count = 0u64;
    for (name, path) in children {
        let info = stat_local_path(&path);
        let rel = if rel_prefix.is_empty() {
            name.clone()
        } else {
            format!("{rel_prefix}/{name}")
        };
        if !flags.file_mask.accepts(
            &name,
            info.is_dir,
            info.size,
            info.mtime.max(0) as u64,
            &rel,
        ) {
            continue;
        }
        let child_remote = join_remote_path(remote_dir, &name);
        if info.is_dir {
            count += Box::pin(upload_directory_recursive(
                session,
                &path,
                &child_remote,
                &rel,
                flags,
                logger,
                progress,
            ))
            .await?;
            if flags.preserve_time && flags.preserve_time_dirs && info.mtime > 0 {
                let _ = session.set_mtime(&child_remote, info.mtime).await;
            }
        } else if upload_single_file(session, &path, &child_remote, flags, logger, progress).await?
        {
            count += 1;
        }
    }
    if rel_prefix.is_empty() && flags.preserve_time && flags.preserve_time_dirs {
        let info = stat_local_path(local_dir);
        if info.mtime > 0 {
            let _ = session.set_mtime(remote_dir, info.mtime).await;
        }
    }
    if flags.delete_source {
        let _ = std::fs::remove_dir(local_dir);
    }
    Ok(count)
}
