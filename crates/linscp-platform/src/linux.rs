//! Linux-specific filesystem roots, POSIX `0600`/`0700` permission helpers,
//! and Wayland/X11 desktop session detection.

use std::fs::{File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use linscp_types::LocalRootEntry;

use crate::PlatformError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopSessionKind {
    Wayland,
    X11,
    Headless,
}

/// Detects the active Linux display session without hardcoding X11 assumptions.
pub fn detect_desktop_session() -> DesktopSessionKind {
    if std::env::var_os("WAYLAND_DISPLAY")
        .filter(|v| !v.is_empty())
        .is_some()
        || std::env::var("XDG_SESSION_TYPE")
            .map(|v| v.eq_ignore_ascii_case("wayland"))
            .unwrap_or(false)
    {
        return DesktopSessionKind::Wayland;
    }
    if std::env::var_os("DISPLAY")
        .filter(|v| !v.is_empty())
        .is_some()
    {
        return DesktopSessionKind::X11;
    }
    DesktopSessionKind::Headless
}

pub fn default_config_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(xdg).join("linscp");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join(".config").join("linscp");
    }
    std::env::temp_dir().join("linscp")
}

pub fn list_roots() -> Vec<LocalRootEntry> {
    let mut roots = vec![LocalRootEntry {
        path: "/".to_string(),
        label: "/".to_string(),
        kind: "posix".to_string(),
        read_only: false,
    }];
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        let home_str = PathBuf::from(home).to_string_lossy().into_owned();
        roots.insert(
            0,
            LocalRootEntry {
                path: home_str,
                label: "Home (~)".to_string(),
                kind: "posix".to_string(),
                read_only: false,
            },
        );
    }
    roots
}

pub fn format_permissions(meta: &std::fs::Metadata) -> String {
    format!("{:04o}", meta.mode() & 0o7777)
}

pub fn set_mode(path: &Path, mode: u32) -> Result<(), PlatformError> {
    std::fs::set_permissions(path, Permissions::from_mode(mode & 0o7777))?;
    Ok(())
}

pub fn ensure_private_dir(dir: &Path) -> Result<(), PlatformError> {
    let existed = dir.exists();
    std::fs::create_dir_all(dir)?;
    if let Err(err) = std::fs::set_permissions(dir, Permissions::from_mode(0o700)) {
        if !existed || err.kind() != std::io::ErrorKind::PermissionDenied {
            return Err(PlatformError::Io(err));
        }
    }
    Ok(())
}

pub fn open_private_temp_file(path: &Path) -> Result<File, PlatformError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    Ok(file)
}

pub fn create_exclusive_private_file(path: &Path, content: &[u8]) -> Result<(), PlatformError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                PlatformError::AlreadyExists(path.display().to_string())
            } else {
                PlatformError::Io(err)
            }
        })?;
    if let Err(err) = file.write_all(content).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(path);
        return Err(PlatformError::Io(err));
    }
    Ok(())
}

pub fn atomic_replace(temp_path: &Path, target_path: &Path) -> Result<(), PlatformError> {
    std::fs::rename(temp_path, target_path)?;
    Ok(())
}

pub async fn connect_ssh_agent() -> Result<Option<Box<dyn crate::AsyncStream>>, PlatformError> {
    let Some(sock) = std::env::var_os("SSH_AUTH_SOCK").filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    match tokio::net::UnixStream::connect(sock).await {
        Ok(stream) => Ok(Some(Box::new(stream))),
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(PlatformError::Io(err)),
    }
}

