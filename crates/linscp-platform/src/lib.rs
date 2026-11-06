//! OS-isolated local filesystem, configuration directory, secret-vault, and
//! directory-watcher abstractions (`linux`, `windows`, and `android`).
//!
//! No crate outside `linscp-platform` and `linscp-tauri` may depend directly
//! on Win32, POSIX, or Android platform APIs.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use filetime::{set_file_mtime, FileTime};
use linscp_types::{FileEntry, LocalRootEntry};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

pub mod desktop;
pub mod password_vault;
pub mod gssapi_sys;
pub mod gui_os;
pub mod terminal;
pub mod watcher;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
use linux as sys;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
use windows as sys;

pub mod android;
#[cfg(target_os = "android")]
use android as sys;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
mod fallback_unix {
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use linscp_types::LocalRootEntry;

    use crate::PlatformError;

    pub fn default_config_dir() -> PathBuf {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(".config")
            .join("linscp")
    }

    pub fn list_roots() -> Vec<LocalRootEntry> {
        vec![LocalRootEntry {
            path: "/".to_string(),
            label: "/".to_string(),
            kind: "posix".to_string(),
            read_only: false,
        }]
    }

    pub fn format_permissions(_meta: &std::fs::Metadata) -> String {
        String::new()
    }

    pub fn set_mode(_path: &Path, _mode: u32) -> Result<(), PlatformError> {
        Ok(())
    }

    pub fn ensure_private_dir(dir: &Path) -> Result<(), PlatformError> {
        std::fs::create_dir_all(dir)?;
        Ok(())
    }

    pub fn open_private_temp_file(path: &Path) -> Result<File, PlatformError> {
        Ok(OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?)
    }

    pub fn create_exclusive_private_file(path: &Path, content: &[u8]) -> Result<(), PlatformError> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    PlatformError::AlreadyExists(path.display().to_string())
                } else {
                    PlatformError::Io(err)
                }
            })?;
        file.write_all(content)?;
        file.sync_all()?;
        Ok(())
    }

    pub fn atomic_replace(temp_path: &Path, target_path: &Path) -> Result<(), PlatformError> {
        std::fs::rename(temp_path, target_path)?;
        Ok(())
    }

    pub fn list_roots() -> Vec<LocalRootEntry> {
        vec![LocalRootEntry {
            path: "/".to_string(),
            label: "/".to_string(),
            kind: "filesystem".to_string(),
            read_only: false,
        }]
    }

    pub fn open_regular_file_no_follow(path: &Path) -> Option<File> {
        let file = OpenOptions::new().read(true).write(true).open(path).ok()?;
        let metadata = file.metadata().ok()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return None;
        }
        Some(file)
    }

    pub fn create_private_file(path: &Path) -> Result<File, PlatformError> {
        Ok(OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?)
    }

    pub fn create_fifo(_path: &Path) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("no FIFO on this platform".to_string()))
    }

    pub async fn connect_ssh_agent() -> Result<Option<Box<dyn crate::AsyncStream>>, PlatformError> {
        Ok(None)
    }
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
use fallback_unix as sys;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

const MASTER_KEY_LEN: usize = 32;
const DPAPI_KEY_PREFIX: &str = "dpapi1$";
#[cfg(target_os = "android")]
const ANDROID_KEYSTORE_PREFIX: &str = "aks1$";

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("Filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Target file already exists: {0}")]
    AlreadyExists(String),
    #[error("Unsupported local URI or path: {0}")]
    UnsupportedUri(String),
    #[error("Secret vault error: {0}")]
    SecretVault(String),
    #[error("Directory watcher error: {0}")]
    Watch(String),
    #[error("Not supported on this platform: {0}")]
    Unsupported(String),
}

/// Bidirectional async byte stream (e.g. Unix `SSH_AUTH_SOCK`, Windows
/// `\\.\pipe\openssh-ssh-agent`, or an in-memory duplex channel) usable by
/// platform-neutral protocol crates without exposing OS socket types.
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

impl<T> AsyncStream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// Connects to the host OS SSH agent if one is reachable (`SSH_AUTH_SOCK` on
/// Linux, `\\.\pipe\openssh-ssh-agent` on Windows, `None` on Android).
pub async fn connect_system_ssh_agent() -> Result<Option<Box<dyn AsyncStream>>, PlatformError> {
    sys::connect_ssh_agent().await
}

/// Platform-neutral local filesystem contract consumed by the transfer engine,
/// synchronizer, CLI, and Commander UI.
pub trait LocalFs: Send + Sync {
    fn list_roots(&self) -> Result<Vec<LocalRootEntry>, PlatformError>;
    fn list_dir(&self, path: &str) -> Result<Vec<FileEntry>, PlatformError>;
    fn stat(&self, path: &str) -> Result<FileEntry, PlatformError>;
    fn mkdir_all(&self, path: &str) -> Result<(), PlatformError>;
    fn remove_file(&self, path: &str) -> Result<(), PlatformError>;
    fn remove_dir_all(&self, path: &str) -> Result<(), PlatformError>;
    fn rename(&self, from: &str, to: &str) -> Result<(), PlatformError>;
    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, PlatformError>;
    fn write_bytes_atomic(&self, path: &str, data: &[u8]) -> Result<(), PlatformError>;
    fn set_mtime(&self, path: &str, mtime: i64) -> Result<(), PlatformError>;
    fn set_permissions_mode(&self, path: &str, mode: u32) -> Result<(), PlatformError>;
}

/// Platform-neutral `sessions.key` master-key vault (`0600` private file on
/// Linux, optional DPAPI wrapping on Windows, optional Keystore wrapping on Android).
pub trait SecretVault: Send + Sync {
    fn load_master_key(&self, config_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, PlatformError>;
    fn load_or_create_master_key(&self, config_dir: &Path) -> Result<Zeroizing<[u8; 32]>, PlatformError>;
}

#[derive(Default)]
pub struct NativeLocalFs {
    /// Android Storage Access Framework bridge. On every other platform this is
    /// `None`, but the field and the `content://` paths below exist everywhere so
    /// the same code can be unit-tested against a mock bridge on a desktop host.
    saf: Option<std::sync::Arc<dyn android::SafBridge>>,
}

impl NativeLocalFs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Local filesystem that can also reach user-granted SAF document trees.
    pub fn with_saf(saf: std::sync::Arc<dyn android::SafBridge>) -> Self {
        Self { saf: Some(saf) }
    }

    /// The registered SAF bridge, if the shell installed one.
    pub fn saf_bridge(&self) -> Option<&std::sync::Arc<dyn android::SafBridge>> {
        self.saf.as_ref()
    }
}

/// A `content://` tree or document URI split into the pieces `DocumentsContract`
/// needs: the authority, the granted tree id, and the document ids below it.
///
/// Only the URI structure is inspected here - never the decoded path segments -
/// so a document id that happens to contain `/` or `:` cannot be mistaken for a
/// traversal, and a name is always passed to the bridge as a single component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafDocumentPath<'a> {
    pub authority: &'a str,
    /// The granted tree id, as it appears after `/tree/` (`primary:Documents`).
    pub tree: &'a str,
    /// Document ids below the tree, outermost first.
    pub documents: Vec<&'a str>,
}

impl<'a> SafDocumentPath<'a> {
    /// The URI of the granted tree itself.
    pub fn tree_uri(&self) -> String {
        format!("content://{}/tree/{}", self.authority, self.tree)
    }

    /// The URI of the directory holding this document, or the tree when the
    /// URI names the tree itself.
    pub fn parent_uri(&self) -> String {
        let mut uri = self.tree_uri();
        for document in self.documents.iter().take(self.documents.len().saturating_sub(1)) {
            uri.push_str("/document/");
            uri.push_str(document);
        }
        uri
    }

    /// The URI's own leaf: a document id, or the tree id for a bare tree URI.
    pub fn leaf(&self) -> &'a str {
        self.documents.last().copied().unwrap_or(self.tree)
    }

    /// The leaf name with Android's `%XX` escapes resolved (`primary%3ADocs`).
    pub fn leaf_name(&self) -> String {
        percent_decode_saf(self.leaf())
    }
}

/// Parses `content://authority/tree/<tree>[/document/<id>[/document/<id>...]]`.
pub fn parse_saf_document_uri(uri: &str) -> Result<SafDocumentPath<'_>, PlatformError> {
    let unsupported = || PlatformError::UnsupportedUri(uri.to_string());
    if uri.contains("..") || uri.contains('\0') || uri.chars().any(char::is_control) {
        return Err(unsupported());
    }
    let rest = uri.strip_prefix("content://").ok_or_else(unsupported)?;
    let (authority, path) = rest.split_once('/').ok_or_else(unsupported)?;
    if authority.is_empty() {
        return Err(unsupported());
    }
    let tree_and_rest = path.strip_prefix("tree/").ok_or_else(unsupported)?;
    let (tree, tail) = match tree_and_rest.split_once('/') {
        Some((tree, tail)) => (tree, tail),
        None => (tree_and_rest, ""),
    };
    if tree.is_empty() {
        return Err(unsupported());
    }
    let mut documents = Vec::new();
    if !tail.is_empty() {
        let document = tail.strip_prefix("document/").ok_or_else(unsupported)?;
        for segment in document.split("/document/") {
            if segment.is_empty() {
                return Err(unsupported());
            }
            documents.push(segment);
        }
    }
    Ok(SafDocumentPath { authority, tree, documents })
}

fn saf_mkdir_all(bridge: &dyn android::SafBridge, path: &str) -> Result<(), PlatformError> {
    let parsed = parse_saf_document_uri(path)?;
    // The bridge creates one directory below a parent, so walk from the granted
    // tree down. An intermediate directory is created once, never twice, and an
    // existing one is accepted by the bridge.
    let mut parent = parsed.tree_uri();
    for document in &parsed.documents {
        let name = percent_decode_saf(document);
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        parent = bridge.mkdir_uri(&parent, &name)?;
    }
    Ok(())
}

fn saf_write_bytes(
    bridge: &dyn android::SafBridge,
    path: &str,
    data: &[u8],
) -> Result<(), PlatformError> {
    let parsed = parse_saf_document_uri(path)?;
    if parsed.documents.is_empty() {
        // A granted tree is a directory; writing over it would replace a whole
        // subtree with one file.
        return Err(PlatformError::UnsupportedUri(path.to_string()));
    }
    let name = parsed.leaf_name();
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(PlatformError::UnsupportedUri(path.to_string()));
    }
    bridge.write_uri_bytes(&parsed.parent_uri(), &name, data)?;
    Ok(())
}

fn saf_rename(
    bridge: &dyn android::SafBridge,
    from: &str,
    to: &str,
) -> Result<(), PlatformError> {
    if to.starts_with("content://") || to.contains('/') || to == "." || to == ".." {
        return Err(PlatformError::UnsupportedUri(to.to_string()));
    }
    bridge.rename_uri(from, to)?;
    Ok(())
}

/// Decodes the `%XX` escapes Android writes into a document id (`primary%3A`).
fn percent_decode_saf(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (
                (bytes[index + 1] as char).to_digit(16),
                (bytes[index + 2] as char).to_digit(16),
            ) {
                out.push(((high << 4) | low) as u8);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn resolve_os_path(path: &str) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        windows::to_extended_length_path(Path::new(path))
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from(path)
    }
}

fn entry_from_symlink_meta(
    name: String,
    full_path: &Path,
    meta: &std::fs::Metadata,
) -> FileEntry {
    let file_type = meta.file_type();
    let is_symlink = file_type.is_symlink();
    let (is_dir, broken_link) = if is_symlink {
        match std::fs::metadata(full_path) {
            Ok(target_meta) => (target_meta.is_dir(), false),
            Err(_) => (false, true),
        }
    } else {
        (file_type.is_dir(), false)
    };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    FileEntry {
        name,
        size: if is_dir { 0 } else { meta.len() },
        is_dir,
        is_symlink,
        broken_link,
        date: String::new(),
        mtime,
        permissions: sys::format_permissions(meta),
        owner: None,
        group: None,
    }
}

impl LocalFs for NativeLocalFs {
    fn list_roots(&self) -> Result<Vec<LocalRootEntry>, PlatformError> {
        // Each target collects its own roots and tree grants; a grant the
        // shell cannot enumerate is left out rather than hiding the roots that
        // did resolve.
        #[cfg(target_os = "android")]
        {
            sys::list_roots(self.saf.as_deref())
        }
        #[cfg(not(target_os = "android"))]
        {
            // Only a host with a SAF bridge (a test on a desktop) can have
            // granted trees on top of its own filesystem roots.
            let mut roots = sys::list_roots();
            if let Some(bridge) = self.saf.as_deref() {
                roots.extend(bridge.granted_trees()?);
            }
            Ok(roots)
        }
    }

    fn list_dir(&self, path: &str) -> Result<Vec<FileEntry>, PlatformError> {
        if path.starts_with("content://") {
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.list_tree(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }

        let resolved = resolve_os_path(path);
        let mut entries = Vec::new();
        for item in std::fs::read_dir(&resolved)? {
            let item = item?;
            let item_path = item.path();
            let meta = std::fs::symlink_metadata(&item_path)?;
            let name = item.file_name().to_string_lossy().into_owned();
            entries.push(entry_from_symlink_meta(name, &item_path, &meta));
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<FileEntry, PlatformError> {
        if path.starts_with("content://") {
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.stat_uri(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        let resolved = resolve_os_path(path);
        let meta = std::fs::symlink_metadata(&resolved)?;
        let name = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        Ok(entry_from_symlink_meta(name, &resolved, &meta))
    }

    fn mkdir_all(&self, path: &str) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            if let Some(bridge) = self.saf.as_deref() {
                return saf_mkdir_all(bridge, path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        std::fs::create_dir_all(resolve_os_path(path))?;
        Ok(())
    }

    fn remove_file(&self, path: &str) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.delete_uri(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        std::fs::remove_file(resolve_os_path(path))?;
        Ok(())
    }

    fn remove_dir_all(&self, path: &str) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.delete_uri(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        std::fs::remove_dir_all(resolve_os_path(path))?;
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), PlatformError> {
        if from.starts_with("content://") || to.starts_with("content://") {
            if let Some(bridge) = self.saf.as_deref() {
                return saf_rename(bridge, from, to);
            }
            return Err(PlatformError::UnsupportedUri(from.to_string()));
        }
        sys::atomic_replace(Path::new(from), Path::new(to))
    }

    fn read_bytes(&self, path: &str) -> Result<Vec<u8>, PlatformError> {
        if path.starts_with("content://") {
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.read_uri_bytes(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        Ok(std::fs::read(resolve_os_path(path))?)
    }

    fn write_bytes_atomic(&self, path: &str, data: &[u8]) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            // A SAF document has no pathname to rename onto, so the bridge
            // writes the bytes itself instead of stage-then-rename.
            if let Some(bridge) = self.saf.as_deref() {
                return saf_write_bytes(bridge, path, data);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        let target = Path::new(path);
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(resolve_os_path(&parent.to_string_lossy()))?;
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(
            ".{}.tmp.{}.{}",
            target
                .file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default(),
            std::process::id(),
            seq
        );
        let temp_path = parent.join(temp_name);
        {
            let mut f = std::fs::File::create(resolve_os_path(&temp_path.to_string_lossy()))?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        if let Err(err) = sys::atomic_replace(&temp_path, target) {
            let _ = std::fs::remove_file(resolve_os_path(&temp_path.to_string_lossy()));
            return Err(err);
        }
        Ok(())
    }

    fn set_mtime(&self, path: &str, mtime: i64) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            // `DocumentsContract` has no last-modified column the caller can
            // write, so preserving a timestamp fails loudly instead of
            // reporting a transfer as complete when it was not preserved.
            return Err(PlatformError::UnsupportedUri(
                "Timestamps cannot be set on a granted Android folder.".to_string(),
            ));
        }
        set_file_mtime(resolve_os_path(path), FileTime::from_unix_time(mtime, 0))?;
        Ok(())
    }

    fn set_permissions_mode(&self, path: &str, mode: u32) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            return Err(PlatformError::UnsupportedUri(
                "POSIX permissions do not exist on a granted Android folder.".to_string(),
            ));
        }
        sys::set_mode(Path::new(path), mode)
    }
}

/// Default per-user configuration directory (`~/.config/linscp` on Linux,
/// `%APPDATA%\LinSCP` on Windows, app-private `config` on Android).
pub fn default_config_dir() -> PathBuf {
    if let Some(override_dir) = std::env::var_os("LINSCP_CONFIG_DIR").filter(|v| !v.is_empty()) {
        return PathBuf::from(override_dir);
    }
    sys::default_config_dir()
}

/// Alias used by `CommanderService` for the active per-user config directory.
pub fn config_dir() -> PathBuf {
    default_config_dir()
}

/// Whether a process identifier is still live; used to reap private per-process
/// key material left behind by an unclean shutdown.
pub fn process_is_running(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    { return windows::process_is_running(pid); }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    { return Path::new("/proc").join(pid.to_string()).exists(); }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "android")))]
    { let _ = pid; true }
}

/// Atomically writes sensitive configuration files (`sessions.ini`,
/// `sessions.key`, `sshhostkeys`) with owner-only permissions.
pub fn write_private_file_atomic(target: &Path, content: &[u8]) -> Result<(), PlatformError> {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    sys::ensure_private_dir(parent)?;

    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "linscp".to_string());
    let temp_path = parent.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));

    {
        let mut file = sys::open_private_temp_file(&temp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }

    if let Err(err) = sys::atomic_replace(&temp_path, target) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(err);
    }
    Ok(())
}

/// Publishes `source` at `target` when, and only when, nothing exists there.
///
/// Publication happens on the destination's filesystem, so a crash leaves
/// either no file or the whole file - never a half-written one - and a
/// concurrent actor that created `target` first is reported as
/// [`PlatformError::AlreadyExists`] instead of being overwritten.
///
/// The no-replace move is the one primitive: a hard link is not. A link fails
/// on filesystems that do not support them (FAT, some network shares) and on
/// Android's own storage, where they are unavailable by policy, and the
/// fallback that would replace the destination is exactly what must not
/// happen. `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` on Windows,
/// `renameat2(RENAME_NOREPLACE)` on Linux and Android, and `renamex_np` on
/// macOS all answer `EEXIST`/`ERROR_ALREADY_EXISTS` for an occupied name and
/// never replace it.
pub fn publish_no_replace(source: &Path, target: &Path) -> Result<(), PlatformError> {
    match gui_os::rename_no_replace(source, target) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(PlatformError::AlreadyExists(target.display().to_string()))
        }
        Err(error) => Err(PlatformError::Io(error)),
    }
}

/// Creates `path` (and missing parent directories) with owner-only (`0700` on Unix) permissions.
pub fn create_private_dir(path: &Path) -> Result<(), PlatformError> {
    sys::ensure_private_dir(path)
}

/// Creates a brand-new owner-only file (`O_CREAT | O_EXCL`, `0600` on Unix),
/// refusing to overwrite an existing file (used by `ConvertPpkToOpenSsh`).
pub fn write_exclusive_private_file(target: &Path, content: &[u8]) -> Result<(), PlatformError> {
    sys::create_exclusive_private_file(target, content)
}

/// Opens an existing file for read/write that the caller locks or truncates,
/// refusing symbolic links, reparse points, special files, and files that are
/// hard-linked more than once. `None` means "not a private, ordinary file".
pub fn open_private_file_no_follow(target: &Path) -> Result<std::fs::File, PlatformError> {
    sys::open_regular_file_no_follow(target)
        .ok_or_else(|| PlatformError::Io(std::io::Error::other(
            "not an ordinary, singly-linked file")))
}

/// Creates a brand-new owner-only file (`0600` on Unix) for content the caller
/// writes and locks itself; unlike `write_exclusive_private_file` the handle
/// stays open, so the caller keeps an exclusive `flock` for its lifetime.
pub fn create_private_file(target: &Path) -> Result<std::fs::File, PlatformError> {
    sys::create_private_file(target)
}

/// Creates a FIFO at `target` for tests that must prove a special file is
/// refused. Only Unix can make one, so Windows reports `Unsupported` and the
/// caller skips the assertion instead of pretending the case is covered.
pub fn create_fifo_fixture(target: &Path) -> Result<(), PlatformError> {
    sys::create_fifo(target)
}

#[derive(Default)]
pub struct NativeSecretVault {
    #[cfg(target_os = "windows")]
    wrap_new_keys_with_dpapi: bool,
    #[cfg(target_os = "android")]
    keystore: Option<std::sync::Arc<dyn android::KeystoreBridge>>,
}

impl NativeSecretVault {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(target_os = "windows")]
    pub fn with_windows_dpapi() -> Self {
        Self {
            wrap_new_keys_with_dpapi: true,
        }
    }

    #[cfg(target_os = "android")]
    pub fn with_android_keystore(keystore: std::sync::Arc<dyn android::KeystoreBridge>) -> Self {
        Self {
            keystore: Some(keystore),
        }
    }
}

fn decode_stored_master_key(
    raw_bytes: &[u8],
    #[cfg(target_os = "android")] keystore: Option<&dyn android::KeystoreBridge>,
) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
    if raw_bytes.starts_with(b"LSCPVLT1") {
        return Err(PlatformError::SecretVault(
            "sessions.key is protected by the local vault; unlock it in LinSCP Commander first".to_string(),
        ));
    }
    if raw_bytes.len() == MASTER_KEY_LEN {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(raw_bytes);
        return Ok(out);
    }
    let text = std::str::from_utf8(raw_bytes)
        .map_err(|_| PlatformError::SecretVault("Invalid master key encoding".to_string()))?
        .trim();

    if let Some(dpapi_b64) = text.strip_prefix(DPAPI_KEY_PREFIX) {
        #[cfg(target_os = "windows")]
        {
            let blob = BASE64
                .decode(dpapi_b64.as_bytes())
                .map_err(|_| PlatformError::SecretVault("Corrupted DPAPI master key".to_string()))?;
            let unwrapped = windows::dpapi_unprotect(&blob)?;
            if unwrapped.len() != MASTER_KEY_LEN {
                return Err(PlatformError::SecretVault(
                    "Invalid DPAPI master key length".to_string(),
                ));
            }
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(&unwrapped);
            return Ok(out);
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = dpapi_b64;
            return Err(PlatformError::SecretVault(
                "DPAPI-protected sessions.key can only be unlocked on Windows".to_string(),
            ));
        }
    }

    #[cfg(target_os = "android")]
    if let Some(aks_b64) = text.strip_prefix(ANDROID_KEYSTORE_PREFIX) {
        let Some(bridge) = keystore else {
            return Err(PlatformError::SecretVault(
                "Android Keystore bridge is required to unlock sessions.key".to_string(),
            ));
        };
        let blob = BASE64
            .decode(aks_b64.as_bytes())
            .map_err(|_| PlatformError::SecretVault("Corrupted Keystore master key".to_string()))?;
        return bridge.unwrap_master_key(&blob);
    }

    let decoded = Zeroizing::new(
        BASE64
            .decode(text.as_bytes())
            .map_err(|_| PlatformError::SecretVault("Invalid base64 master key".to_string()))?,
    );
    if decoded.len() != MASTER_KEY_LEN {
        return Err(PlatformError::SecretVault(
            "Invalid sessions.key length".to_string(),
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&decoded);
    Ok(out)
}

impl SecretVault for NativeSecretVault {
    fn load_master_key(
        &self,
        config_dir: &Path,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, PlatformError> {
        let key_path = config_dir.join("sessions.key");
        let raw = match std::fs::read(&key_path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(PlatformError::Io(err)),
        };
        #[cfg(target_os = "android")]
        let key = decode_stored_master_key(&raw, self.keystore.as_deref())?;
        #[cfg(not(target_os = "android"))]
        let key = decode_stored_master_key(&raw)?;
        Ok(Some(key))
    }

    fn load_or_create_master_key(
        &self,
        config_dir: &Path,
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        if let Some(existing) = self.load_master_key(config_dir)? {
            return Ok(existing);
        }
        let mut generated = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *generated);
        let key_path = config_dir.join("sessions.key");

        #[cfg(target_os = "windows")]
        if self.wrap_new_keys_with_dpapi {
            let wrapped = windows::dpapi_protect(&*generated)?;
            let encoded = format!("{DPAPI_KEY_PREFIX}{}\n", BASE64.encode(wrapped));
            write_private_file_atomic(&key_path, encoded.as_bytes())?;
            return Ok(generated);
        }

        #[cfg(target_os = "android")]
        if let Some(bridge) = self.keystore.as_deref() {
            let wrapped = bridge.wrap_master_key(&generated)?;
            let encoded = format!("{ANDROID_KEYSTORE_PREFIX}{}\n", BASE64.encode(wrapped));
            write_private_file_atomic(&key_path, encoded.as_bytes())?;
            return Ok(generated);
        }

        let encoded = format!("{}\n", BASE64.encode(*generated));
        write_private_file_atomic(&key_path, encoded.as_bytes())?;
        Ok(generated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory SAF tree. It is deliberately strict: a name containing a
    /// separator is refused, so a caller that passes a path instead of a single
    /// component fails the test instead of silently creating a document id.
    #[derive(Default)]
    struct MockSaf {
        documents: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MockSaf {
        fn names(&self) -> Vec<String> {
            self.documents
                .lock()
                .unwrap()
                .iter()
                .map(|(uri, _)| uri.rsplit('/').next().unwrap_or_default().to_string())
                .collect()
        }
    }

    impl android::SafBridge for MockSaf {
        fn request_tree(&self) -> Result<Option<String>, PlatformError> {
            Ok(Some(
                "content://mock.tree/tree/primary%3ADownload".to_string(),
            ))
        }
        fn granted_trees(&self) -> Result<Vec<LocalRootEntry>, PlatformError> {
            Ok(vec![LocalRootEntry {
                path: "content://mock.tree/tree/primary%3ADownload".to_string(),
                label: "Downloads (SAF)".to_string(),
                kind: "saf_tree".to_string(),
                read_only: false,
            }])
        }
        fn list_tree(&self, _tree_uri: &str) -> Result<Vec<linscp_types::FileEntry>, PlatformError> {
            Ok(self
                .documents
                .lock()
                .unwrap()
                .iter()
                .map(|(uri, data)| linscp_types::FileEntry {
                    name: uri.rsplit('/').next().unwrap_or_default().to_string(),
                    size: data.len() as u64,
                    is_dir: false,
                    is_symlink: false,
                    broken_link: false,
                    date: String::new(),
                    mtime: 0,
                    permissions: String::new(),
                    owner: None,
                    group: None,
                })
                .collect())
        }
        fn stat_uri(&self, uri: &str) -> Result<linscp_types::FileEntry, PlatformError> {
            self.documents
                .lock()
                .unwrap()
                .iter()
                .find(|(name, _)| name == uri)
                .map(|(_, data)| linscp_types::FileEntry {
                    name: uri.rsplit('/').next().unwrap_or_default().to_string(),
                    size: data.len() as u64,
                    is_dir: false,
                    is_symlink: false,
                    broken_link: false,
                    date: String::new(),
                    mtime: 0,
                    permissions: String::new(),
                    owner: None,
                    group: None,
                })
                .ok_or_else(|| PlatformError::UnsupportedUri(uri.to_string()))
        }
        fn read_uri_bytes(&self, uri: &str) -> Result<Vec<u8>, PlatformError> {
            self.documents
                .lock()
                .unwrap()
                .iter()
                .find(|(name, _)| name == uri)
                .map(|(_, data)| data.clone())
                .ok_or_else(|| PlatformError::UnsupportedUri(uri.to_string()))
        }
        fn write_uri_bytes(
            &self,
            parent_uri: &str,
            name: &str,
            data: &[u8],
        ) -> Result<String, PlatformError> {
            if name.is_empty() || name.contains('/') || name.contains(char::is_control) {
                return Err(PlatformError::UnsupportedUri(name.to_string()));
            }
            let uri = format!("{parent_uri}/document/{name}");
            self.documents.lock().unwrap().push((uri.clone(), data.to_vec()));
            Ok(uri)
        }
        fn mkdir_uri(&self, parent_uri: &str, name: &str) -> Result<String, PlatformError> {
            if name.is_empty() || name.contains('/') {
                return Err(PlatformError::UnsupportedUri(name.to_string()));
            }
            Ok(format!("{parent_uri}/document/{name}"))
        }
        fn delete_uri(&self, uri: &str) -> Result<(), PlatformError> {
            self.documents.lock().unwrap().retain(|(name, _)| name != uri);
            Ok(())
        }
        fn rename_uri(&self, uri: &str, new_name: &str) -> Result<String, PlatformError> {
            if new_name.contains('/') {
                return Err(PlatformError::UnsupportedUri(new_name.to_string()));
            }
            let mut documents = self.documents.lock().unwrap();
            let Some((name, _)) = documents.iter_mut().find(|(name, _)| name == uri) else {
                return Err(PlatformError::UnsupportedUri(uri.to_string()));
            };
            let parent = name.rsplit_once('/').map(|(parent, _)| parent).unwrap_or_default().to_string();
            *name = format!("{parent}/document/{new_name}");
            Ok(name.clone())
        }
    }

    #[test]
    fn saf_trees_are_local_roots_and_support_the_whole_file_lifecycle() {
        let bridge = std::sync::Arc::new(MockSaf::default());
        let fs = NativeLocalFs::with_saf(bridge.clone());
        let roots = fs.list_roots().unwrap();
        assert!(
            roots.iter().any(|root| root.kind == "saf_tree"),
            "a granted tree has to appear next to the app's own roots: {roots:?}"
        );

        let tree = "content://mock.tree/tree/primary%3ADownload";
        let created = format!("{tree}/document/photos");
        fs.mkdir_all(&created).expect("mkdir inside a granted tree");

        let file = format!("{created}/document/note.txt");
        let bytes = b"granted folder bytes";
        fs.write_bytes_atomic(&file, bytes).expect("write");
        assert_eq!(fs.read_bytes(&file).unwrap(), bytes);
        // A size is bytes, so it comes from the fixture instead of a hand count.
        assert_eq!(fs.stat(&file).unwrap().size, bytes.len() as u64);

        // A rename inside a granted tree names one entry: `LocalFs` accepts a
        // bare new name and nothing else, so a name carrying a path cannot
        // escape the directory the caller is looking at.
        assert!(fs.rename(&file, "photos/escaped.txt").is_err());
        assert!(fs.rename(&file, "..").is_err());
        // The move itself is the provider's, and the bridge reports the id the
        // document has afterwards. The claim worth asserting is that the
        // document is at the returned id and the previous id no longer
        // resolves - not a guess at how a provider spells a document id.
        let renamed_uri = android::SafBridge::rename_uri(&*bridge, &file, "renamed.txt")
            .expect("the bridge renames a document inside a granted tree");
        assert_eq!(fs.read_bytes(&renamed_uri).unwrap(), bytes);
        assert!(fs.stat(&file).is_err(), "the renamed document's old id must be gone");
        assert!(
            fs.read_bytes("renamed.txt").is_err(),
            "a bare name is not a document id; LocalFs takes URIs or paths"
        );

        fs.remove_file(&renamed_uri).unwrap();
        assert!(fs.stat(&renamed_uri).is_err());

        // An encoded separator in the leaf decodes to a path, so it is refused
        // before it can reach the bridge as a document name - and the
        // POSIX-only attributes fail closed instead of pretending to work.
        assert!(fs.write_bytes_atomic(&format!("{created}/document/evil%2Fname.txt"), b"x").is_err());
        assert!(fs.write_bytes_atomic(tree, b"x").is_err(), "a granted tree is not a file");
        assert!(fs.set_mtime(&file, 1_700_000_000).is_err());
        assert!(fs.set_permissions_mode(&file, 0o644).is_err());
    }

    #[test]
    fn atomic_private_write_and_local_fs_operations_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "linscp-platform-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let fs = NativeLocalFs::new();
        fs.mkdir_all(&dir.to_string_lossy()).unwrap();

        let target = dir.join("sessions.ini");
        write_private_file_atomic(&target, b"[demo]\nhost=example.com\n").expect("write v1");
        write_private_file_atomic(&target, b"[demo]\nhost=updated.example.com\n")
            .expect("replace v2");

        let body = fs.read_bytes(&target.to_string_lossy()).expect("read back");
        assert_eq!(body, b"[demo]\nhost=updated.example.com\n");

        fs.set_mtime(&target.to_string_lossy(), 1_700_000_000)
            .expect("set mtime");
        let st = fs.stat(&target.to_string_lossy()).expect("stat");
        assert_eq!(st.mtime, 1_700_000_000);

        // Exclusive private write refuses to overwrite an existing file
        let excl_err = write_exclusive_private_file(&target, b"clobber").unwrap_err();
        assert!(matches!(excl_err, PlatformError::AlreadyExists(_)));

        // SecretVault round-trip
        let vault = NativeSecretVault::new();
        let k1 = vault.load_or_create_master_key(&dir).expect("create master key");
        let k2 = vault.load_master_key(&dir).expect("load master key").unwrap();
        assert_eq!(*k1, *k2);

        fs.remove_dir_all(&dir.to_string_lossy()).unwrap();
    }

    #[test]
    fn no_replace_publication_never_overwrites_and_reports_a_conflict() {
        let dir = std::env::temp_dir().join(format!(
            "linscp-publish-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join("staged");
        std::fs::write(&staged, b"new bytes").unwrap();
        let target = dir.join("target");

        publish_no_replace(&staged, &target).expect("fresh destination is published");
        assert_eq!(std::fs::read(&target).unwrap(), b"new bytes");

        // A second publication onto the same name is refused, not merged, and
        // the bytes already there stay untouched.
        std::fs::write(&staged, b"replacement").unwrap();
        let error = publish_no_replace(&staged, &target).unwrap_err();
        assert!(matches!(error, PlatformError::AlreadyExists(_)), "{error}");
        assert_eq!(std::fs::read(&target).unwrap(), b"new bytes");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn saf_document_uris_split_into_tree_parent_and_leaf() {
        let tree = parse_saf_document_uri(
            "content://com.android.externalstorage.documents/tree/primary%3ADownload",
        )
        .unwrap();
        assert_eq!(tree.authority, "com.android.externalstorage.documents");
        assert_eq!(tree.tree, "primary%3ADownload");
        assert!(tree.documents.is_empty());
        assert_eq!(tree.leaf(), "primary%3ADownload");
        assert_eq!(tree.tree_uri(), "content://com.android.externalstorage.documents/tree/primary%3ADownload");

        let nested = parse_saf_document_uri(
            "content://com.android.externalstorage.documents/tree/primary%3ADownload/document/primary%3ADownload%2Fphotos/document/inner",
        )
        .unwrap();
        assert_eq!(nested.documents, vec!["primary%3ADownload%2Fphotos", "inner"]);
        assert_eq!(nested.leaf(), "inner");
        // The parent keeps the encoded document id exactly as Android wrote it.
        assert_eq!(
            nested.parent_uri(),
            "content://com.android.externalstorage.documents/tree/primary%3ADownload/document/primary%3ADownload%2Fphotos"
        );
        assert_eq!(nested.leaf_name(), "inner");
    }

    #[test]
    fn saf_document_uris_reject_non_tree_and_traversal_forms() {
        for bad in [
            "file:///sdcard/Download",
            "content://authority/document/only",
            "content://authority/tree/",
            "content://authority/tree/primary%3ADownload/document/",
            "content://authority/tree/primary%3ADownload/../../etc",
            "content://authority/tree/primary%3ADownload/document/a\0b",
        ] {
            assert!(
                parse_saf_document_uri(bad).is_err(),
                "{bad} must not be accepted as a SAF tree"
            );
        }
    }
}
