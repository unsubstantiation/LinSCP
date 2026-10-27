//! Cross-platform OS abstractions for LinSCP (`linux`, `windows`, `android`).
//!
//! All OS-specific conditional compilation (`#[cfg(windows)]`,
//! `#[cfg(target_os = "android")]`, `#[cfg(unix)]`) is isolated in this crate
//! so upper crates (`linscp-proto`, `linscp-engine`, `linscp-service`,
//! `linscp-http`, `linscp-cli`) remain 100% portable Rust.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use linscp_types::{FileEntry, LocalRootEntry};
use thiserror::Error;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod windows;
#[cfg(target_os = "android")]
pub mod android;

#[derive(Debug, Error)]
pub enum PlatformError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("Storage root '{0}' requires an Android SAF provider")]
    UnsupportedSafUri(String),
}

/// Platform-neutral local filesystem contract consumed by `linscp-engine` and
/// `linscp-service`.
pub trait LocalFs: Send + Sync {
    /// Enumerates selectable local roots (`/` on Linux, `C:\`/`D:\` on Windows,
    /// app-private + SAF document trees on Android).
    fn list_roots(&self) -> Result<Vec<LocalRootEntry>, PlatformError>;

    /// Lists a local directory or Android SAF document tree URI.
    fn list_dir(&self, path: &str) -> Result<Vec<FileEntry>, PlatformError>;

    /// Atomically replaces `destination` with `staging` (`.filepart` commit).
    fn atomic_replace(&self, staging: &Path, destination: &Path) -> Result<(), PlatformError>;

    /// Whether filename mask matching defaults to case-insensitive on this OS.
    fn default_case_insensitive_masks(&self) -> bool;
}

/// Default local filesystem implementation for the active host OS.
#[derive(Debug, Default, Clone)]
pub struct NativeLocalFs;

impl NativeLocalFs {
    pub fn new() -> Self {
        Self
    }
}

/// Resolves the active LinSCP configuration directory:
/// - `$LINSCP_CONFIG_DIR` / `%LINSCP_CONFIG_DIR%` override on every OS
/// - Linux: `$XDG_CONFIG_HOME/LinSCP` or `$HOME/.config/LinSCP`
/// - Windows: `%APPDATA%\LinSCP`
/// - Android: `$LINSCP_ANDROID_FILES_DIR/LinSCP` or `$HOME/.config/LinSCP`
pub fn config_dir() -> PathBuf {
    if let Some(explicit) = std::env::var_os("LINSCP_CONFIG_DIR") {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
    }
    #[cfg(target_os = "linux")]
    {
        linux::default_config_dir()
    }
    #[cfg(windows)]
    {
        windows::default_config_dir()
    }
    #[cfg(target_os = "android")]
    {
        android::default_config_dir()
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "android")))]
    {
        std::env::temp_dir().join("LinSCP")
    }
}

/// Creates a private configuration directory (`0700` on Unix/Android).
pub fn ensure_private_dir(path: &Path) -> Result<(), PlatformError> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes `contents` atomically via a sibling temporary file with owner-only
/// permissions (`0600` on Unix/Android).
pub fn write_private_file_atomic(path: &Path, contents: &[u8]) -> Result<(), PlatformError> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("linscp.tmp");
    let staging = path.with_file_name(format!(".{file_name}.tmp.{}", std::process::id()));
    std::fs::write(&staging, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o600))?;
    }
    NativeLocalFs.atomic_replace(&staging, path)
}

pub(crate) fn system_time_epoch_secs(time: Result<SystemTime, std::io::Error>) -> i64 {
    time.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn read_standard_dir_entries(dir: &Path) -> Result<Vec<FileEntry>, PlatformError> {
    let mut entries = Vec::new();
    for item in std::fs::read_dir(dir)? {
        let item = item?;
        let name = item.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." {
            continue;
        }
        let symlink_meta = std::fs::symlink_metadata(item.path())?;
        let is_symlink = symlink_meta.file_type().is_symlink();
        let (effective_meta, broken_link) = if is_symlink {
            match std::fs::metadata(item.path()) {
                Ok(target) => (target, false),
                Err(_) => (symlink_meta.clone(), true),
            }
        } else {
            (symlink_meta.clone(), false)
        };
        let is_dir = !broken_link && effective_meta.is_dir();
        let size = if is_dir { 0 } else { effective_meta.len() };
        let mtime = system_time_epoch_secs(effective_meta.modified());
        let permissions = format_permissions(&symlink_meta, is_dir, is_symlink);
        entries.push(FileEntry {
            name,
            size,
            is_dir,
            is_symlink,
            broken_link,
            date: String::new(),
            mtime,
            permissions,
            owner: None,
            group: None,
        });
    }
    entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
    Ok(entries)
}

fn format_permissions(meta: &std::fs::Metadata, is_dir: bool, is_symlink: bool) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        let kind = if is_symlink {
            'l'
        } else if is_dir {
            'd'
        } else {
            '-'
        };
        let mut s = String::with_capacity(10);
        s.push(kind);
        for shift in [6u32, 3, 0] {
            let bits = (mode >> shift) & 0o7;
            s.push(if bits & 0o4 != 0 { 'r' } else { '-' });
            s.push(if bits & 0o2 != 0 { 'w' } else { '-' });
            s.push(if bits & 0o1 != 0 { 'x' } else { '-' });
        }
        s
    }
    #[cfg(not(unix))]
    {
        let kind = if is_symlink {
            'l'
        } else if is_dir {
            'd'
        } else {
            '-'
        };
        let writable = if meta.permissions().readonly() { '-' } else { 'w' };
        format!("{kind}r{writable}-r--r--")
    }
}

impl LocalFs for NativeLocalFs {
    fn list_roots(&self) -> Result<Vec<LocalRootEntry>, PlatformError> {
        #[cfg(target_os = "linux")]
        {
            Ok(linux::list_roots())
        }
        #[cfg(windows)]
        {
            Ok(windows::list_roots())
        }
        #[cfg(target_os = "android")]
        {
            Ok(android::list_roots())
        }
        #[cfg(not(any(target_os = "linux", windows, target_os = "android")))]
        {
            Ok(vec![LocalRootEntry {
                path: "/".to_string(),
                label: "/".to_string(),
                kind: "posix".to_string(),
                read_only: false,
            }])
        }
    }

    fn list_dir(&self, path: &str) -> Result<Vec<FileEntry>, PlatformError> {
        #[cfg(target_os = "android")]
        if android::is_saf_uri(path) {
            return android::list_saf_dir(path);
        }
        read_standard_dir_entries(Path::new(path))
    }

    fn atomic_replace(&self, staging: &Path, destination: &Path) -> Result<(), PlatformError> {
        #[cfg(windows)]
        {
            windows::atomic_replace(staging, destination)
        }
        #[cfg(not(windows))]
        {
            std::fs::rename(staging, destination)?;
            Ok(())
        }
    }

    fn default_case_insensitive_masks(&self) -> bool {
        cfg!(windows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_local_fs_lists_roots_and_temp_dir() {
        let fs = NativeLocalFs::new();
        let roots = fs.list_roots().expect("roots");
        assert!(!roots.is_empty());

        let temp = std::env::temp_dir().join(format!("linscp-platform-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp);
        ensure_private_dir(&temp).expect("create private dir");

        let target = temp.join("sessions.ini");
        write_private_file_atomic(&target, b"[demo]\nhost=example.com\n").expect("atomic write");
        let entries = fs.list_dir(&temp.to_string_lossy()).expect("list temp dir");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "sessions.ini");
        let _ = std::fs::remove_dir_all(&temp);
    }
}
