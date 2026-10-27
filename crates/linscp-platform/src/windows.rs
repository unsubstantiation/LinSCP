//! Windows platform implementation (`%APPDATA%\LinSCP`, drive enumeration,
//! atomic `.filepart` replacement via `MoveFileExW`).

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use linscp_types::LocalRootEntry;
use windows_sys::Win32::Storage::FileSystem::{
    GetLogicalDrives, MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

use crate::PlatformError;

pub fn default_config_dir() -> PathBuf {
    if let Some(appdata) = std::env::var_os("APPDATA") {
        if !appdata.is_empty() {
            return PathBuf::from(appdata).join("LinSCP");
        }
    }
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        if !profile.is_empty() {
            return PathBuf::from(profile)
                .join("AppData")
                .join("Roaming")
                .join("LinSCP");
        }
    }
    std::env::temp_dir().join("LinSCP")
}

/// Enumerates mounted Windows logical drives (`A:\` .. `Z:\`).
pub fn list_roots() -> Vec<LocalRootEntry> {
    // SAFETY: `GetLogicalDrives` takes no arguments and returns a bitmask.
    let mask = unsafe { GetLogicalDrives() };
    let mut roots = Vec::new();
    for bit in 0u8..26u8 {
        if (mask & (1u32 << bit)) != 0 {
            let letter = (b'A' + bit) as char;
            roots.push(LocalRootEntry {
                path: format!("{letter}:\\"),
                label: format!("{letter}:\\"),
                kind: "drive".to_string(),
                read_only: false,
            });
        }
    }
    if roots.is_empty() {
        roots.push(LocalRootEntry {
            path: "C:\\".to_string(),
            label: "C:\\".to_string(),
            kind: "drive".to_string(),
            read_only: false,
        });
    }
    roots
}

fn to_wide_null(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Atomically replaces `destination` with `staging` using `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`.
pub fn atomic_replace(staging: &Path, destination: &Path) -> Result<(), PlatformError> {
    let src = to_wide_null(staging);
    let dst = to_wide_null(destination);
    // SAFETY: Both `src` and `dst` are valid NUL-terminated UTF-16 buffers that
    // outlive the `MoveFileExW` call.
    let ok = unsafe {
        MoveFileExW(
            src.as_ptr(),
            dst.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        return Err(PlatformError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}
