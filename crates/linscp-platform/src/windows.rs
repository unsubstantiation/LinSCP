//! Windows-specific drive-letter discovery, extended-length (`\\?\`) paths,
//! atomic `MoveFileExW` replacement, and DPAPI (`CryptProtectData` /
//! `CryptUnprotectData`) secret protection.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use linscp_types::LocalRootEntry;
use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetLogicalDrives, MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};
use zeroize::Zeroizing;

use crate::PlatformError;

const EXTENDED_PATH_THRESHOLD: usize = 240;

pub fn default_config_dir() -> PathBuf {
    if let Some(appdata) = std::env::var_os("APPDATA").filter(|v| !v.is_empty()) {
        return PathBuf::from(appdata).join("LinSCP");
    }
    if let Some(profile) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return PathBuf::from(profile)
            .join("AppData")
            .join("Roaming")
            .join("LinSCP");
    }
    std::env::temp_dir().join("LinSCP")
}

/// Converts long absolute Windows paths (`>= 240` UTF-16 code units) to `\\?\`
/// or `\\?\UNC\` extended-length syntax so paths exceeding `MAX_PATH` succeed.
pub fn to_extended_length_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw.starts_with(r"\\?\") || raw.len() < EXTENDED_PATH_THRESHOLD || !path.is_absolute() {
        return path.to_path_buf();
    }
    let normalized = raw.replace('/', r"\");
    if let Some(unc_tail) = normalized.strip_prefix(r"\\") {
        PathBuf::from(format!(r"\\?\UNC\{unc_tail}"))
    } else {
        PathBuf::from(format!(r"\\?\{normalized}"))
    }
}

pub fn list_roots() -> Vec<LocalRootEntry> {
    let mut roots = Vec::new();
    if let Some(profile) = std::env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        let home_str = PathBuf::from(profile).to_string_lossy().into_owned();
        roots.push(LocalRootEntry {
            path: home_str,
            label: "Home".to_string(),
            kind: "drive".to_string(),
            read_only: false,
        });
    }
    // SAFETY: `GetLogicalDrives` takes no arguments and returns a bitmask of
    // mounted `A:`..`Z:` drives (`0` on error).
    let mask = unsafe { GetLogicalDrives() };
    for bit in 0u32..26u32 {
        if (mask & (1u32 << bit)) != 0 {
            let letter = (b'A' + bit as u8) as char;
            let drive_path = format!("{letter}:\\");
            roots.push(LocalRootEntry {
                path: drive_path,
                label: format!("{letter}:"),
                kind: "drive".to_string(),
                read_only: false,
            });
        }
    }
    roots
}

pub fn format_permissions(meta: &std::fs::Metadata) -> String {
    if meta.permissions().readonly() {
        "r--r--r--".to_string()
    } else {
        "rw-rw-rw-".to_string()
    }
}

pub fn set_mode(path: &Path, mode: u32) -> Result<(), PlatformError> {
    let ext = to_extended_length_path(path);
    let mut perms = std::fs::metadata(&ext)?.permissions();
    perms.set_readonly((mode & 0o200) == 0);
    std::fs::set_permissions(&ext, perms)?;
    Ok(())
}

pub fn ensure_private_dir(dir: &Path) -> Result<(), PlatformError> {
    std::fs::create_dir_all(to_extended_length_path(dir))?;
    Ok(())
}

pub fn open_private_temp_file(path: &Path) -> Result<File, PlatformError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(to_extended_length_path(path))?;
    Ok(file)
}

pub fn create_exclusive_private_file(path: &Path, content: &[u8]) -> Result<(), PlatformError> {
    let ext = to_extended_length_path(path);
    if let Some(parent) = ext.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&ext)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                PlatformError::AlreadyExists(path.display().to_string())
            } else {
                PlatformError::Io(err)
            }
        })?;
    if let Err(err) = file.write_all(content).and_then(|()| file.sync_all()) {
        let _ = std::fs::remove_file(&ext);
        return Err(PlatformError::Io(err));
    }
    Ok(())
}

fn to_wide_null(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn atomic_replace(temp_path: &Path, target_path: &Path) -> Result<(), PlatformError> {
    let ext_src = to_extended_length_path(temp_path);
    let ext_dst = to_extended_length_path(target_path);
    let src = to_wide_null(&ext_src);
    let dst = to_wide_null(&ext_dst);
    // SAFETY: Both UTF-16 buffers are NUL-terminated and outlive the Win32 call.
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

pub async fn connect_ssh_agent() -> Result<Option<Box<dyn crate::AsyncStream>>, PlatformError> {
    let pipe_path = std::env::var_os("SSH_AUTH_SOCK")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| std::ffi::OsString::from(r"\\.\pipe\openssh-ssh-agent"));
    match tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_path) {
        Ok(client) => Ok(Some(Box::new(client))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(PlatformError::Io(err)),
    }
}

/// Encrypts `secret` under the current Windows user's DPAPI credential.
pub fn dpapi_protect(secret: &[u8]) -> Result<Vec<u8>, PlatformError> {
    let mut input_copy = Zeroizing::new(secret.to_vec());
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: input_copy.len() as u32,
        pbData: input_copy.as_mut_ptr(),
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: `in_blob` points to valid mutable memory for `cbData` bytes and
    // `out_blob` is initialized on success and freed via `LocalFree`.
    let ok = unsafe {
        CryptProtectData(
            &in_blob,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(PlatformError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY: `CryptProtectData` succeeded so `pbData`..`pbData + cbData` is valid.
    let encrypted =
        unsafe { std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec() };
    // SAFETY: `pbData` was allocated by Win32 `LocalAlloc` inside `CryptProtectData`.
    unsafe {
        let _ = LocalFree(out_blob.pbData as HLOCAL);
    }
    Ok(encrypted)
}

/// Decrypts a DPAPI blob produced by `dpapi_protect` for the current Windows user.
pub fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
    let mut cipher_copy = ciphertext.to_vec();
    let in_blob = CRYPT_INTEGER_BLOB {
        cbData: cipher_copy.len() as u32,
        pbData: cipher_copy.as_mut_ptr(),
    };
    let mut out_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: `in_blob` points to valid memory for `cbData` bytes and `out_blob`
    // is freed via `LocalFree` after copying and zeroizing.
    let ok = unsafe {
        CryptUnprotectData(
            &in_blob,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        )
    };
    if ok == 0 {
        return Err(PlatformError::SecretVault(
            "Windows DPAPI failed to unprotect master key".to_string(),
        ));
    }
    // SAFETY: `CryptUnprotectData` succeeded so `pbData`..`pbData + cbData` is valid.
    let plain = unsafe {
        let slice = std::slice::from_raw_parts_mut(out_blob.pbData, out_blob.cbData as usize);
        let copied = Zeroizing::new(slice.to_vec());
        slice.fill(0);
        let _ = LocalFree(out_blob.pbData as HLOCAL);
        copied
    };
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_dpapi_round_trip_protects_and_recovers_master_key() {
        let sample = [0x5au8; 32];
        let wrapped = dpapi_protect(&sample).expect("DPAPI protect");
        assert_ne!(wrapped.as_slice(), sample.as_slice());
        let unwrapped = dpapi_unprotect(&wrapped).expect("DPAPI unprotect");
        assert_eq!(unwrapped.as_slice(), sample.as_slice());
    }

    #[test]
    fn extended_length_helper_prefixes_deep_drive_paths() {
        let deep = format!(r"C:\{}", "segment\\".repeat(35));
        let converted = to_extended_length_path(Path::new(&deep));
        assert!(converted.to_string_lossy().starts_with(r"\\?\C:\"));
    }
}
