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
use linscp_types::{FileEntry, LocalRootEntry};
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

pub mod cli_args;
pub mod url_registration;
pub mod desktop;
pub mod password_vault;
pub mod container_cipher;
pub mod container_file;
pub mod gssapi_sys;
pub mod gui_os;
pub mod terminal;
pub mod watcher;

/// Whether synchronization must conservatively detect case aliases on the
/// host filesystem. This is not a complete model of filesystem-specific rules.
pub fn sync_paths_case_insensitive() -> bool {
    cfg!(windows)
}

/// Refuse names that Win32 can alias or cannot safely open. Other platforms
/// still enforce common single-component validation in the synchronization engine.
pub fn is_sync_filename_supported(name: &str) -> bool {
    if !cfg!(windows) { return true; }
    if name.ends_with(['.', ' ']) || name.contains(['<', '>', '"', '|', '?', '*']) {
        return false;
    }
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        | "COM¹" | "COM²" | "COM³" | "LPT¹" | "LPT²" | "LPT³")
        || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9')) {
        return false;
    }
    true
}

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

    pub fn sync_directory(_path: &Path) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported("Directory durability is not implemented on this platform".to_string()))
    }

    pub fn atomic_replace(temp_path: &Path, target_path: &Path) -> Result<(), PlatformError> {
        std::fs::rename(temp_path, target_path)?;
        Ok(())
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

    pub fn ssh_agent_missing_reason() -> Option<&'static str> {
        None
    }

    pub async fn connect_ssh_agent() -> Result<Option<Box<dyn crate::AsyncStream>>, PlatformError> {
        Ok(None)
    }
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
use fallback_unix as sys;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

const MASTER_KEY_LEN: usize = 32;

/// User-facing reason reported when SSH agent authentication fails on a
/// platform that has no agent at all. Linux and Windows builds probe for an
/// agent socket instead, so they report no static reason.
pub const SSH_AGENT_MISSING_MESSAGE: &str = "SSH agent authentication is not available on Android: the platform has no agent. Use a private key file instead.";

/// Largest single document the granted-folder policy allows (64 MiB). Reads and
/// writes stream across the bridge in 1 MiB (`SAF_CHUNK_BYTES`) chunks when
/// supported (`readUriChunk`, `beginWriteUri`, `appendUriChunk`), while callers
/// keep this explicit per-document bound via `stat` before staging or publishing
/// and refuse larger documents naming the cap and the app-storage workaround.
pub const MAX_SAF_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

/// Names the document, its size and the bridge cap when a file is too large
/// to cross into or out of a granted folder. Every refusal that enforces
/// `MAX_SAF_DOCUMENT_BYTES` uses this sentence so the cap reads the same
/// from copies, transfers and synchronization.
pub fn saf_document_too_large(name: &str, size: u64) -> String {
    format!(
        "'{name}' is larger than a granted folder can carry ({} bytes; maximum 64 MiB per file). Move it to app storage first.",
        size
    )
}

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

    /// Streams `source` (`content://` or OS path) into `dest_path` without holding
    /// the entire file in memory when backed by a chunked SAF bridge.
    fn stage_to_file(&self, source: &str, dest_path: &Path) -> Result<u64, PlatformError> {
        let bytes = self.read_bytes(source)?;
        if let Some(parent) = dest_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(dest_path, &bytes)?;
        Ok(bytes.len() as u64)
    }

    /// Streams `staged_path` into `dest` (`content://` or OS path) without holding
    /// the entire file in memory when backed by a chunked SAF bridge.
    fn publish_from_file(&self, staged_path: &Path, dest: &str) -> Result<u64, PlatformError> {
        let bytes = std::fs::read(staged_path)?;
        self.write_bytes_atomic(dest, &bytes)?;
        Ok(bytes.len() as u64)
    }

    /// Copies a single regular file between any two `LocalFs` paths (`content://` or OS)
    /// in bounded chunks.
    fn copy_streamed(&self, source: &str, dest: &str) -> Result<u64, PlatformError> {
        let bytes = self.read_bytes(source)?;
        self.write_bytes_atomic(dest, &bytes)?;
        Ok(bytes.len() as u64)
    }
}

/// Optional storage override for the decoded session INI. `Unhandled` keeps
/// the legacy filesystem implementation; handled backends must fail closed.
pub enum SessionIniRead {
    Unhandled,
    Missing,
    Plaintext(Zeroizing<String>),
}

/// Optional virtual storage for a domain-separated protected file.
pub enum ProtectedFileRead {
    Unhandled,
    Missing,
    Plaintext(Zeroizing<Vec<u8>>),
}

/// Material referenced by a saved session and resolved by its vault backend.
#[derive(Clone, Copy)]
pub enum VaultMaterialKind { SshPrivate, SshPublic, Tls }

pub enum VaultMaterialRead {
    Unhandled,
    Missing,
    Plaintext(Zeroizing<Vec<u8>>),
}

/// Public SSH key metadata returned by a vault backend.
pub struct VaultSshKeyInfo {
    pub id: String,
    pub label: String,
}

pub struct VaultSshKeyImport {
    pub id: String,
    pub label: String,
    pub deduplicated: bool,
}

/// Platform-neutral `sessions.key` master-key vault. The key file itself is an
/// owner-only private file; secrecy comes from the password wrap (`LSCPVLT1`),
/// which is the only wrapping on every build.
pub trait SecretVault: Send + Sync {
    fn load_master_key(&self, config_dir: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, PlatformError>;
    fn load_or_create_master_key(&self, config_dir: &Path) -> Result<Zeroizing<[u8; 32]>, PlatformError>;
    /// Backends may store session INI in an authenticated container instead of
    /// `sessions.ini`. A handled write must be atomic and refuse locked access.
    fn read_session_ini(&self, _config_dir: &Path) -> Result<SessionIniRead, PlatformError> {
        Ok(SessionIniRead::Unhandled)
    }
    fn write_session_ini(&self, _config_dir: &Path, _text: &str) -> Result<bool, PlatformError> {
        Ok(false)
    }
    /// A handled backend must authenticate data, preserve domain separation,
    /// validate the requested location and fail closed when locked.
    fn read_protected_file(&self, _path: &Path, _domain: &str) -> Result<ProtectedFileRead, PlatformError> {
        Ok(ProtectedFileRead::Unhandled)
    }
    fn write_protected_file(&self, _path: &Path, _domain: &str, _value: &[u8]) -> Result<bool, PlatformError> {
        Ok(false)
    }
    /// Optional virtual key-material lookup; handled backends must not fall
    /// back to unrelated filesystem material for missing or locked entries.
    fn read_vault_material(&self, _config_dir: &Path, _kind: VaultMaterialKind, _id: &str) -> Result<VaultMaterialRead, PlatformError> {
        Ok(VaultMaterialRead::Unhandled)
    }
    /// None means the legacy filesystem implementation must handle the call.
    fn list_vault_ssh_keys(&self, _config_dir: &Path) -> Result<Option<Vec<VaultSshKeyInfo>>, PlatformError> { Ok(None) }
    fn import_vault_ssh_key(&self, _config_dir: &Path, _id: &str, _private: &[u8], _label: &str, _public: &str) -> Result<Option<VaultSshKeyImport>, PlatformError> { Ok(None) }
    /// Some(false) indicates a handled request whose key was not found.
    fn delete_vault_ssh_key(&self, _config_dir: &Path, _id: &str) -> Result<Option<bool>, PlatformError> { Ok(None) }
    /// The local password vault protects the entire session store, not just secrets.
    fn protects_session_store(&self) -> bool { false }
    fn seal_session_store(&self, _plaintext: &[u8]) -> Result<Vec<u8>, PlatformError> {
        Err(PlatformError::SecretVault("This vault cannot encrypt session metadata".into()))
    }
    fn open_session_store(&self, _encrypted: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        Err(PlatformError::SecretVault("Unlock the local vault to read encrypted sessions".into()))
    }
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

/// Escapes URI-reserved characters (`%`, `?`, `#`, `/`) in a single SAF child
/// display name so appending `/document/<encoded>` preserves literal `%XX`,
/// `?`, and `#` characters across `Uri.parse` and `percent_decode_saf`.
pub fn encode_saf_segment(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        match ch {
            '%' => out.push_str("%25"),
            '?' => out.push_str("%3F"),
            '#' => out.push_str("%23"),
            '/' => out.push_str("%2F"),
            _ => out.push(ch),
        }
    }
    out
}

fn saf_segment_has_dot_traversal(decoded: &str) -> bool {
    decoded.is_empty()
        || decoded.chars().any(char::is_control)
        || decoded
            .split(['/', '\\', ':'])
            .any(|part| part == "." || part == "..")
}

/// Parses `content://authority/tree/<tree>[/document/<id>[/document/<id>...]]`.
pub fn parse_saf_document_uri(uri: &str) -> Result<SafDocumentPath<'_>, PlatformError> {
    let unsupported = || PlatformError::UnsupportedUri(uri.to_string());
    if uri.contains('\0')
        || uri.contains('?')
        || uri.contains('#')
        || uri.chars().any(char::is_control)
    {
        return Err(unsupported());
    }
    let rest = uri.strip_prefix("content://").ok_or_else(unsupported)?;
    let (authority, path) = rest.split_once('/').ok_or_else(unsupported)?;
    if authority.is_empty() || authority == "." || authority == ".." {
        return Err(unsupported());
    }
    let tree_and_rest = path.strip_prefix("tree/").ok_or_else(unsupported)?;
    let (tree, tail) = match tree_and_rest.split_once('/') {
        Some((tree, tail)) => (tree, tail),
        None => (tree_and_rest, ""),
    };
    if tree.is_empty() || saf_segment_has_dot_traversal(&percent_decode_saf(tree)) {
        return Err(unsupported());
    }
    let mut documents = Vec::new();
    if !tail.is_empty() {
        let document = tail.strip_prefix("document/").ok_or_else(unsupported)?;
        for segment in document.split("/document/") {
            if segment.is_empty() || saf_segment_has_dot_traversal(&percent_decode_saf(segment)) {
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
    let parsed = parse_saf_document_uri(from)?;
    if parsed.documents.is_empty() {
        return Err(PlatformError::UnsupportedUri(from.to_string()));
    }
    if to.is_empty()
        || to.starts_with("content://")
        || to.contains('/')
        || to.contains('\\')
        || to.chars().any(char::is_control)
        || to == "."
        || to == ".."
    {
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
    let (is_dir, broken_link, effective_size) = if is_symlink {
        match std::fs::metadata(full_path) {
            Ok(target_meta) => {
                let dir = target_meta.is_dir();
                (dir, false, if dir { 0 } else { target_meta.len() })
            }
            Err(_) => (false, true, 0),
        }
    } else {
        let dir = file_type.is_dir();
        (dir, false, if dir { 0 } else { meta.len() })
    };
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    #[cfg(unix)]
    let (owner, group) = {
        use std::os::unix::fs::MetadataExt;
        (Some(meta.uid().to_string()), Some(meta.gid().to_string()))
    };
    #[cfg(not(unix))]
    let (owner, group) = (None, None);
    FileEntry {
        name,
        size: effective_size,
        is_dir,
        is_symlink,
        broken_link,
        date: if mtime > 0 {
            gui_os::format_listing_date(mtime)
        } else {
            String::new()
        },
        mtime,
        permissions: sys::format_permissions(meta),
        owner,
        group,
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
            let _ = parse_saf_document_uri(path)?;
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
            let _ = parse_saf_document_uri(path)?;
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
            let parsed = parse_saf_document_uri(path)?;
            if parsed.documents.is_empty() {
                return Err(PlatformError::UnsupportedUri(path.to_string()));
            }
            if let Some(bridge) = self.saf.as_deref() {
                return bridge.delete_uri(path);
            }
            return Err(PlatformError::UnsupportedUri(path.to_string()));
        }
        let resolved = resolve_os_path(path);
        #[cfg(windows)]
        {
            match std::fs::remove_file(&resolved) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    if std::fs::symlink_metadata(&resolved)
                        .map(|m| m.file_type().is_symlink())
                        .unwrap_or(false)
                    {
                        std::fs::remove_dir(&resolved)?;
                        return Ok(());
                    }
                    return Err(err.into());
                }
            }
        }
        #[cfg(not(windows))]
        {
            std::fs::remove_file(resolved)?;
            Ok(())
        }
    }

    fn remove_dir_all(&self, path: &str) -> Result<(), PlatformError> {
        if path.starts_with("content://") {
            let parsed = parse_saf_document_uri(path)?;
            if parsed.documents.is_empty() {
                return Err(PlatformError::UnsupportedUri(path.to_string()));
            }
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
            let parsed = parse_saf_document_uri(path)?;
            if parsed.documents.is_empty() {
                return Err(PlatformError::UnsupportedUri(path.to_string()));
            }
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
        let target = resolve_os_path(path);
        let file = terminal::open_path_for_set_times(&target)?;
        let times = std::fs::FileTimes::new()
            .set_modified(terminal::system_time_from_unix_secs(mtime));
        file.set_times(times)?;
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

    fn stage_to_file(&self, source: &str, dest_path: &Path) -> Result<u64, PlatformError> {
        if let Some(parent) = dest_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(resolve_os_path(&parent.to_string_lossy()))?;
        }
        if source.starts_with("content://") {
            let parsed = parse_saf_document_uri(source)?;
            if parsed.documents.is_empty() {
                return Err(PlatformError::UnsupportedUri(source.to_string()));
            }
            let Some(bridge) = self.saf.as_deref() else {
                return Err(PlatformError::UnsupportedUri(source.to_string()));
            };
            let mut out = sys::open_private_temp_file(&resolve_os_path(&dest_path.to_string_lossy()))?;
            let mut offset = 0u64;
            loop {
                let chunk = bridge.read_uri_chunk(source, offset, android::SAF_CHUNK_BYTES)?;
                if chunk.is_empty() {
                    break;
                }
                out.write_all(&chunk)?;
                let len = chunk.len();
                offset = offset.saturating_add(len as u64);
                if len < android::SAF_CHUNK_BYTES {
                    break;
                }
            }
            out.sync_all()?;
            return Ok(offset);
        }
        let mut src = std::fs::File::open(resolve_os_path(source))?;
        let mut out = sys::open_private_temp_file(&resolve_os_path(&dest_path.to_string_lossy()))?;
        let written = std::io::copy(&mut src, &mut out)?;
        out.sync_all()?;
        Ok(written)
    }

    fn publish_from_file(&self, staged_path: &Path, dest: &str) -> Result<u64, PlatformError> {
        if dest.starts_with("content://") {
            let Some(bridge) = self.saf.as_deref() else {
                return Err(PlatformError::UnsupportedUri(dest.to_string()));
            };
            if !bridge.supports_chunked_write() {
                let bytes = std::fs::read(resolve_os_path(&staged_path.to_string_lossy()))?;
                saf_write_bytes(bridge, dest, &bytes)?;
                return Ok(bytes.len() as u64);
            }
            let parsed = parse_saf_document_uri(dest)?;
            if parsed.documents.is_empty() {
                return Err(PlatformError::UnsupportedUri(dest.to_string()));
            }
            let name = parsed.leaf_name();
            if name.is_empty() || name == "." || name == ".." || name.contains('/') {
                return Err(PlatformError::UnsupportedUri(dest.to_string()));
            }
            let target_uri = bridge.begin_write_uri(&parsed.parent_uri(), &name)?;
            let mut src = std::fs::File::open(resolve_os_path(&staged_path.to_string_lossy()))?;
            let mut buf = vec![0u8; android::SAF_CHUNK_BYTES];
            let mut total = 0u64;
            loop {
                use std::io::Read as _;
                let n = src.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                bridge.append_uri_chunk(&target_uri, &buf[..n])?;
                total = total.saturating_add(n as u64);
            }
            return Ok(total);
        }
        let mut src = std::fs::File::open(resolve_os_path(&staged_path.to_string_lossy()))?;
        let target = Path::new(dest);
        let parent = target
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(resolve_os_path(&parent.to_string_lossy()))?;
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(
            ".{}.tmp.{}.{}",
            target.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
            std::process::id(),
            seq
        ));
        let written = {
            let mut out = std::fs::File::create(resolve_os_path(&temp_path.to_string_lossy()))?;
            let w = std::io::copy(&mut src, &mut out)?;
            out.sync_all()?;
            w
        };
        if let Err(err) = sys::atomic_replace(&temp_path, target) {
            let _ = std::fs::remove_file(resolve_os_path(&temp_path.to_string_lossy()));
            return Err(err);
        }
        Ok(written)
    }

    fn copy_streamed(&self, source: &str, dest: &str) -> Result<u64, PlatformError> {
        if !source.starts_with("content://") && !dest.starts_with("content://") {
            return self.publish_from_file(Path::new(source), dest);
        }
        let Some(bridge) = self.saf.as_deref() else {
            return Err(PlatformError::UnsupportedUri(
                if source.starts_with("content://") { source } else { dest }.to_string(),
            ));
        };
        if dest.starts_with("content://") && !bridge.supports_chunked_write() {
            let bytes = self.read_bytes(source)?;
            self.write_bytes_atomic(dest, &bytes)?;
            return Ok(bytes.len() as u64);
        }
        if source.starts_with("content://") && !dest.starts_with("content://") {
            let target = Path::new(dest);
            let parent = target
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            std::fs::create_dir_all(resolve_os_path(&parent.to_string_lossy()))?;
            let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let temp_path = parent.join(format!(
                ".{}.tmp.{}.{}",
                target.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(),
                std::process::id(),
                seq
            ));
            let written = self.stage_to_file(source, &temp_path)?;
            if let Err(err) = sys::atomic_replace(&temp_path, target) {
                let _ = std::fs::remove_file(resolve_os_path(&temp_path.to_string_lossy()));
                return Err(err);
            }
            return Ok(written);
        }
        if !source.starts_with("content://") && dest.starts_with("content://") {
            return self.publish_from_file(Path::new(source), dest);
        }
        let parsed_src = parse_saf_document_uri(source)?;
        if parsed_src.documents.is_empty() {
            return Err(PlatformError::UnsupportedUri(source.to_string()));
        }
        let parsed = parse_saf_document_uri(dest)?;
        if parsed.documents.is_empty() {
            return Err(PlatformError::UnsupportedUri(dest.to_string()));
        }
        let name = parsed.leaf_name();
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(PlatformError::UnsupportedUri(dest.to_string()));
        }
        let target_uri = bridge.begin_write_uri(&parsed.parent_uri(), &name)?;
        let mut offset = 0u64;
        loop {
            let chunk = bridge.read_uri_chunk(source, offset, android::SAF_CHUNK_BYTES)?;
            if chunk.is_empty() {
                break;
            }
            bridge.append_uri_chunk(&target_uri, &chunk)?;
            let len = chunk.len();
            offset = offset.saturating_add(len as u64);
            if len < android::SAF_CHUNK_BYTES {
                break;
            }
        }
        Ok(offset)
    }
}

/// Static reason a platform reports when it has no SSH agent to ask, or
/// `None` when the build probes for an agent socket instead.
pub fn ssh_agent_missing_reason() -> Option<&'static str> {
    sys::ssh_agent_missing_reason()
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

/// Atomically writes a sensitive file (such as an encrypted backup export)
/// with owner-only (`0600` / owner-only DACL) file permissions into an
/// arbitrary user directory WITHOUT altering the parent directory's existing
/// permissions or Windows DACL.
pub fn write_owner_only_file_atomic(target: &Path, content: &[u8]) -> Result<(), PlatformError> {
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(resolve_os_path(&parent.to_string_lossy()))?;

    let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_name = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "linscp".to_string());
    let temp_path = parent.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));

    {
        let mut file = sys::open_private_temp_file(&resolve_os_path(&temp_path.to_string_lossy()))?;
        file.write_all(content)?;
        file.sync_all()?;
    }

    if let Err(err) = sys::atomic_replace(&temp_path, target) {
        let _ = std::fs::remove_file(resolve_os_path(&temp_path.to_string_lossy()));
        return Err(err);
    }
    Ok(())
}

/// Atomically replaces `target_path` with `temp_path` on the same filesystem
/// (handling Windows `MOVEFILE_REPLACE_EXISTING` and extended-length paths).
pub fn atomic_replace_file(temp_path: &Path, target_path: &Path) -> Result<(), PlatformError> {
    sys::atomic_replace(temp_path, target_path)
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

/// Flush directory metadata for durable rename/create/delete ordering.
/// Fails closed on filesystems or platforms that cannot provide this barrier.
pub fn sync_directory(path: &Path) -> Result<(), PlatformError> {
    sys::sync_directory(path)
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

/// An advisory, interprocess exclusive lock for one configuration directory.
/// The persistent lock file must never be renamed or unlinked: all cooperating
/// processes must lock the same file for the full duration of their access.
/// This does not protect against older clients or arbitrary external writers.
pub struct ConfigDirectoryLock {
    _file: std::fs::File,
    root: PathBuf,
}

impl ConfigDirectoryLock {
    /// Try to acquire the lock without waiting. Dropping the returned guard,
    /// including on normal process termination, releases the OS lock. The OS
    /// also releases it if the process is killed.
    pub fn try_acquire(config_dir: &Path) -> Result<Self, PlatformError> {
        create_private_dir(config_dir)?;
        let path = config_dir.join(".configuration.lock");
        let file = match std::fs::symlink_metadata(&path) {
            Ok(_) => open_private_file_no_follow(&path)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                match create_private_file(&path) {
                    Ok(file) => file,
                    // Another cooperating process may create it first.
                    Err(PlatformError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => open_private_file_no_follow(&path)?,
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(PlatformError::Io(e)),
        };
        file.try_lock().map_err(|error| PlatformError::Io(std::io::Error::other(
            format!("Cannot acquire configuration directory lock: {error}"))))?;
        let root = std::fs::canonicalize(config_dir).map_err(PlatformError::Io)?;
        Ok(Self { _file: file, root })
    }

    /// Check that this guard was acquired for this configuration directory.
    pub fn covers_directory(&self, config_dir: &Path) -> bool {
        std::fs::canonicalize(config_dir).is_ok_and(|path| path == self.root)
    }
}

const INSTANCE_IPC_FILE: &str = ".instance-ipc";

fn constant_time_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Owner-authenticated loopback IPC listener used by the primary desktop window
/// so launching `linscp-gui` a second time activates/restores the existing
/// window instead of failing with a configuration directory lock error.
pub struct SingleInstanceServer {
    endpoint_file: PathBuf,
    addr: std::net::SocketAddr,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl SingleInstanceServer {
    pub fn start<F>(config_dir: &Path, on_activate: F) -> Result<Self, PlatformError>
    where
        F: Fn() + Send + Sync + 'static,
    {
        Self::start_with_urls(config_dir, move |url| {
            if url.is_some() { return false; }
            on_activate();
            true
        })
    }

    /// Authenticated activation with an optional untrusted URL. The callback must
    /// return false if it cannot retain the URL; credentials are never written to disk.
    pub fn start_with_urls<F>(config_dir: &Path, on_activate: F) -> Result<Self, PlatformError>
    where
        F: Fn(Option<String>) -> bool + Send + Sync + 'static,
    {
        create_private_dir(config_dir)?;
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        let mut raw_token = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *raw_token);
        let token_hex = Zeroizing::new(
            raw_token
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
        let endpoint_file = config_dir.join(INSTANCE_IPC_FILE);
        let record = Zeroizing::new(format!("{addr} {}\n", token_hex.as_str()));
        write_private_file_atomic(&endpoint_file, record.as_bytes())?;

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_thread = stop.clone();
        let expected_line = Zeroizing::new(format!("ACTIVATE {}", token_hex.as_str()));
        std::thread::Builder::new()
            .name("linscp-single-instance".to_string())
            .spawn(move || {
                use std::io::{BufRead, BufReader};
                for incoming in listener.incoming() {
                    if stop_thread.load(Ordering::Acquire) {
                        break;
                    }
                    let Ok(mut stream) = incoming else {
                        continue;
                    };
                    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(400)));
                    let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(400)));
                    let mut line = Zeroizing::new(String::new());
                    let read_ok = {
                        use std::io::Read;
                        let mut reader = BufReader::new((&stream).take(12000));
                        reader.read_line(&mut line).is_ok() && line.ends_with('\n')
                    };
                    if !read_ok { continue; }
                    let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                    let (auth, encoded) = trimmed.split_once(' ').and_then(|(command, rest)| {
                        let (token, payload) = rest.split_once(' ').unwrap_or((rest, ""));
                        (command == "ACTIVATE").then_some((format!("{command} {token}"), payload))
                    }).unwrap_or_default();
                    if !constant_time_bytes_eq(auth.as_bytes(), expected_line.as_bytes()) { continue; }
                    let url = if encoded.is_empty() { None } else {
                        let Ok(bytes) = BASE64.decode(encoded) else { continue; };
                        let Ok(value) = String::from_utf8(bytes) else { continue; };
                        if !cli_args::is_session_url(&value) { continue; }
                        Some(value)
                    };
                    if on_activate(url) {
                        let _ = stream.write_all(b"OK\n");
                        let _ = stream.flush();
                    }
                }
            })
            .map_err(PlatformError::Io)?;

        Ok(Self {
            endpoint_file,
            addr,
            stop,
        })
    }
}

impl Drop for SingleInstanceServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = std::fs::remove_file(&self.endpoint_file);
        let _ = std::net::TcpStream::connect_timeout(
            &self.addr,
            std::time::Duration::from_millis(50),
        );
    }
}

/// Signals an already-running primary desktop instance for `config_dir` to show
/// and focus its main window, returning `true` when the primary acknowledged.
pub fn try_signal_running_instance(config_dir: &Path) -> bool {
    try_signal_running_instance_with_url(config_dir, None)
}

/// Deliver a URL in memory over the authenticated channel, never via the endpoint file.
pub fn try_signal_running_instance_with_url(config_dir: &Path, url: Option<&str>) -> bool {
    if url.is_some_and(|value| !cli_args::is_session_url(value)) { return false; }
    use std::io::{BufRead, BufReader, Read};
    let endpoint_file = config_dir.join(INSTANCE_IPC_FILE);
    let Ok(mut file) = open_private_file_no_follow(&endpoint_file) else {
        return false;
    };
    let mut contents = Zeroizing::new(String::new());
    if file.read_to_string(&mut contents).is_err() {
        return false;
    }
    let mut parts = contents.split_whitespace();
    let (Some(addr_str), Some(token)) = (parts.next(), parts.next()) else {
        return false;
    };
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() else {
        return false;
    };
    if !addr.ip().is_loopback() {
        return false;
    }
    let Ok(mut stream) =
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(350))
    else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(350)));
    let _ = stream.set_write_timeout(Some(std::time::Duration::from_millis(350)));
    let msg = Zeroizing::new(match url {
        Some(value) => format!("ACTIVATE {token} {}\n", BASE64.encode(value)),
        None => format!("ACTIVATE {token}\n"),
    });
    if stream.write_all(msg.as_bytes()).is_err() || stream.flush().is_err() {
        return false;
    }
    let mut reply = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut reply).is_ok() && reply.trim() == "OK"
}

/// Creates a FIFO at `target` for tests that must prove a special file is
/// refused. Only Unix can make one, so Windows reports `Unsupported` and the
/// caller skips the assertion instead of pretending the case is covered.
pub fn create_fifo_fixture(target: &Path) -> Result<(), PlatformError> {
    sys::create_fifo(target)
}

/// Legacy master-key loader: reads `sessions.key` in the formats old builds
/// wrote (raw bytes or base64). The vault itself is password-only on every
/// build — the hardware-backed wrappers were never wired and have been
/// removed rather than left as dead surface.
#[derive(Default)]
pub struct NativeSecretVault {}

impl NativeSecretVault {
    pub fn new() -> Self {
        Self::default()
    }
}

fn decode_stored_master_key(raw_bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
    if raw_bytes.starts_with(b"LSCPVLT1") || raw_bytes.starts_with(b"LSCPKST1") {
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

        // New legacy keys are plain base64: the hardware-backed wrappers were
        // never wired and have been removed, so there is nothing to wrap with.
        let encoded = format!("{}\n", BASE64.encode(*generated));
        write_private_file_atomic(&key_path, encoded.as_bytes())?;
        Ok(generated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_lock_excludes_other_handles_until_released() {
        let root = std::env::temp_dir().join(format!("linscp-config-lock-{}-{}", std::process::id(), rand::random::<u64>()));
        let first = ConfigDirectoryLock::try_acquire(&root).unwrap();
        assert!(ConfigDirectoryLock::try_acquire(&root).is_err());
        drop(first);
        let next = ConfigDirectoryLock::try_acquire(&root).unwrap();
        drop(next);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn configuration_lock_rejects_non_regular_lock_file() {
        let root = std::env::temp_dir().join(format!("linscp-config-lock-bad-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir_all(root.join(".configuration.lock")).unwrap();
        assert!(ConfigDirectoryLock::try_acquire(&root).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn single_instance_server_activates_callback_and_cleans_up_on_drop() {
        let root = std::env::temp_dir().join(format!(
            "linscp-single-instance-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        assert!(!try_signal_running_instance(&root));
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let hits_cb = hits.clone();
        let server = SingleInstanceServer::start(&root, move || {
            hits_cb.fetch_add(1, Ordering::SeqCst);
        })
        .unwrap();
        assert!(try_signal_running_instance(&root));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        drop(server);
        assert!(!try_signal_running_instance(&root));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn single_instance_delivers_urls_only_to_authenticated_listener() {
        let root = std::env::temp_dir().join(format!("linscp-url-ipc-{}-{}", std::process::id(), rand::random::<u64>()));
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = received.clone();
        let server = SingleInstanceServer::start_with_urls(&root, move |url| {
            captured.lock().unwrap().push(url);
            true
        }).unwrap();
        let url = "sftp://user:secret@example.test/path%20name";
        assert!(try_signal_running_instance_with_url(&root, Some(url)));
        assert!(!try_signal_running_instance_with_url(&root, Some("javascript://evil")));
        assert_eq!(*received.lock().unwrap(), vec![Some(url.to_string())]);
        let record = std::fs::read_to_string(root.join(INSTANCE_IPC_FILE)).unwrap();
        assert!(!record.contains("secret"));
        let addr: std::net::SocketAddr = record.split_whitespace().next().unwrap().parse().unwrap();
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream.write_all(b"ACTIVATE wrong c2Z0cDovL2V4YW1wbGUudGVzdA==\n").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        std::io::Read::read_to_string(&mut stream, &mut reply).unwrap();
        assert!(reply.is_empty());
        assert_eq!(received.lock().unwrap().len(), 1);
        drop(server);
        let _ = std::fs::remove_dir_all(root);
    }

    /// In-memory SAF tree. It is deliberately strict: a name containing a
    /// separator is refused, so a caller that passes a path instead of a single
    /// component fails the test instead of silently creating a document id.
    #[derive(Default)]
    struct MockSaf {
        documents: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
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
            let mut docs = self.documents.lock().unwrap();
            if let Some((_, existing)) = docs.iter_mut().find(|(n, _)| n == &uri) {
                *existing = data.to_vec();
            } else {
                docs.push((uri.clone(), data.to_vec()));
            }
            Ok(uri)
        }
        fn append_uri_chunk(&self, uri: &str, data: &[u8]) -> Result<(), PlatformError> {
            let mut docs = self.documents.lock().unwrap();
            let Some((_, existing)) = docs.iter_mut().find(|(n, _)| n == uri) else {
                return Err(PlatformError::UnsupportedUri(uri.to_string()));
            };
            existing.extend_from_slice(data);
            Ok(())
        }
        fn supports_chunked_write(&self) -> bool {
            true
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
        assert!(!st.date.is_empty(), "local stat must format modification date");
        #[cfg(unix)]
        {
            assert!(st.owner.is_some() && st.group.is_some());
            let sub = dir.join("real_subdir");
            std::fs::create_dir_all(&sub).unwrap();
            std::fs::write(sub.join("inside.txt"), b"keep").unwrap();
            let dir_link = dir.join("subdir_link");
            std::os::unix::fs::symlink(&sub, &dir_link).unwrap();
            let link_st = fs.stat(&dir_link.to_string_lossy()).unwrap();
            assert!(link_st.is_symlink && link_st.is_dir && !link_st.broken_link);
            fs.remove_file(&dir_link.to_string_lossy()).unwrap();
            assert!(!dir_link.exists());
            assert!(sub.join("inside.txt").exists(), "unlinking a directory symlink must keep target intact");
        }

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

    #[test]
    fn ssh_agent_missing_message_names_platform_and_key_fallback() {
        assert!(SSH_AGENT_MISSING_MESSAGE.contains("Android"));
        assert!(SSH_AGENT_MISSING_MESSAGE.contains("private key"));
        #[cfg(not(target_os = "android"))]
        assert_eq!(ssh_agent_missing_reason(), None);
        #[cfg(target_os = "android")]
        assert_eq!(
            ssh_agent_missing_reason(),
            Some(SSH_AGENT_MISSING_MESSAGE)
        );
    }

    #[test]
    fn saf_chunked_stage_publish_and_streamed_copy_across_multi_chunk_payload() {
        let bridge = std::sync::Arc::new(MockSaf::default());
        let fs = NativeLocalFs::with_saf(bridge);
        let dir = std::env::temp_dir().join(format!(
            "linscp-saf-chunk-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // 2.5 MiB payload crosses three 1 MiB SAF chunks (`SAF_CHUNK_BYTES`).
        let total = android::SAF_CHUNK_BYTES * 2 + (512 * 1024);
        let payload: Vec<u8> = (0..total).map(|i| ((i * 31 + 7) & 0xff) as u8).collect();
        let local_src = dir.join("source.bin");
        std::fs::write(&local_src, &payload).unwrap();

        let tree = "content://mock.tree/tree/primary%3ADownload";
        let saf_a = format!("{tree}/document/multi_a.bin");
        let saf_b = format!("{tree}/document/multi_b.bin");

        let published = fs.publish_from_file(&local_src, &saf_a).expect("chunked publish");
        assert_eq!(published, total as u64);
        assert_eq!(fs.stat(&saf_a).unwrap().size, total as u64);

        let copied = fs.copy_streamed(&saf_a, &saf_b).expect("streamed SAF->SAF copy");
        assert_eq!(copied, total as u64);
        assert_eq!(fs.stat(&saf_b).unwrap().size, total as u64);

        let local_roundtrip = dir.join("roundtrip.bin");
        let staged = fs.stage_to_file(&saf_b, &local_roundtrip).expect("chunked stage");
        assert_eq!(staged, total as u64);
        assert_eq!(std::fs::read(&local_roundtrip).unwrap(), payload);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saf_uri_parser_allows_double_dots_in_names_and_rejects_traversal_and_raw_providers() {
        let tree = "content://mock.tree/tree/primary%3ADownload";
        // Legitimate filenames containing consecutive dots must not be rejected.
        let double_dot = format!("{tree}/document/notes..txt");
        assert_eq!(
            parse_saf_document_uri(&double_dot).unwrap().leaf_name(),
            "notes..txt"
        );
        // Special URI characters round-trip through encode_saf_segment -> leaf_name.
        let tricky = "budget_50%#1?.csv";
        let encoded_uri = format!("{tree}/document/{}", encode_saf_segment(tricky));
        assert_eq!(
            parse_saf_document_uri(&encoded_uri).unwrap().leaf_name(),
            tricky
        );

        // Actual dot-segment traversal (literal or percent-encoded) must be rejected.
        assert!(parse_saf_document_uri(&format!("{tree}/document/..")).is_err());
        assert!(parse_saf_document_uri(&format!("{tree}/document/%2e%2e")).is_err());
        assert!(parse_saf_document_uri(&format!("{tree}/document/sub%2F..%2Fsecret")).is_err());
        assert!(parse_saf_document_uri("content://com.android.contacts/contacts/1").is_err());

        // NativeLocalFs refuses non-tree providers and refuses deleting/renaming the tree root.
        let fs = NativeLocalFs::with_saf(std::sync::Arc::new(MockSaf::default()));
        assert!(fs.stat("content://com.android.contacts/contacts/1").is_err());
        assert!(fs.read_bytes("content://com.android.contacts/contacts/1").is_err());
        assert!(fs.remove_file(tree).is_err());
        assert!(fs.remove_dir_all(tree).is_err());
        assert!(fs.rename(tree, "renamed").is_err());
    }

    #[test]
    fn write_owner_only_file_atomic_preserves_parent_directory_permissions() {
        let dir = std::env::temp_dir().join(format!(
            "linscp-owner-file-test-{}-{}",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let target = dir.join("export.lscpbak");
        write_owner_only_file_atomic(&target, b"encrypted-payload").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"encrypted-payload");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            let file_mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o755, "parent folder mode must not be tightened to 0700");
            assert_eq!(file_mode, 0o600, "exported file itself must remain 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
