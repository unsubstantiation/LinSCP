//! Windows-specific drive-letter discovery, extended-length (`\\?\`) paths,
//! atomic `MoveFileExW` replacement.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use linscp_types::LocalRootEntry;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HLOCAL};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, ACL};
use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_sys::Win32::Storage::FileSystem::{
    GetLogicalDrives, MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

use crate::PlatformError;

const EXTENDED_PATH_THRESHOLD: usize = 240;

/// Returns whether a process identifier currently resolves to a live process.
pub fn process_is_running(pid: u32) -> bool {
    // SAFETY: OpenProcess receives only a PID and requests query-only access;
    // the returned handle is closed immediately and no process memory is read.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            false
        } else {
            CloseHandle(process) != 0
        }
    }
}

/// Takes the console of the process that started this one, if it has one.
///
/// The release GUI is built with `windows_subsystem = "windows"`, so it has no
/// console of its own. The one-shot actions (`--install-shell-integration`,
/// `--shell-upload …`) are run *by* a file manager or a script, which do have a
/// console and a user who wants to read the answer.
///
/// Attaching is not enough on its own: the inherited standard handles belong to the
/// windowing parent and point nowhere, so writing to `stdout` would still discard
/// the text. What is returned is the console itself (`CONOUT$`), which the caller
/// writes to directly. `None` is not an error — it means this process was started
/// without a console (a shortcut, a scheduled task) and has nobody to tell.
pub fn attach_parent_console() -> Option<std::fs::File> {
    // SAFETY: `AttachConsole` takes one constant; it either attaches this process to
    // its parent's console or fails harmlessly. It allocates nothing the caller owns
    // and does not touch any handle we keep.
    if unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } == 0 {
        return None;
    }
    // `CONOUT$` is the console screen buffer of whichever console this process is
    // attached to, so it is exactly where a console program's output goes.
    std::fs::OpenOptions::new().write(true).open("CONOUT$").ok()
}

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

/// SDDL for the configuration-directory DACL: protected (`P`, nothing inherited
/// from the parent), one ACE allowing (`A`) full access (`FA`) to the owner
/// (`OW`), with object+container inherit (`OICI`) so files created inside carry
/// their own owner-only ACE. The inherit flags are the point on Windows:
/// `SeChangeNotifyPrivilege` ("bypass traverse checking") is held by everyone,
/// so a file reached by direct path is governed by *its* DACL, not the
/// directory's — a directory-only ACE would leave `sessions.ini` readable.
const OWNER_ONLY_DACL_SDDL: &str = "D:P(A;OICI;FA;;;OW)";

// Small integer constants from the Windows SDK (`accctrl.h`, `WinNT.h`,
// `sddl.h`), kept as literals so the DACL this module applies can be verified
// by reading, without depending on constant paths in the bindings crate.
const SE_FILE_OBJECT: i32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const SDDL_REVISION_1: u32 = 1;
#[cfg(test)]
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x0;
#[cfg(test)]
const OBJECT_INHERIT_ACE: u8 = 0x1;
#[cfg(test)]
const CONTAINER_INHERIT_ACE: u8 = 0x2;
#[cfg(test)]
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

/// NUL-terminated UTF-16 for a Rust string (the `Path` form is `to_wide_null`).
fn str_to_wide_null(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Replaces the DACL of `dir` with the owner-only one, creating nothing.
/// Failing closed: a directory whose ACL cannot be locked down is an error,
/// never a silently shared one.
pub fn apply_owner_only_dacl(dir: &Path) -> Result<(), PlatformError> {
    let path = to_wide_null(dir);
    let sddl = str_to_wide_null(OWNER_ONLY_DACL_SDDL);
    // SAFETY: both buffers are NUL-terminated UTF-16 that outlive the calls;
    // `sd` is only read after a success return and is `LocalFree`'d exactly
    // once however the inner block below exits.
    unsafe {
        let mut sd: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut sd_len: u32 = 0;
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            &mut sd_len,
        ) == 0
        {
            return Err(PlatformError::Io(std::io::Error::last_os_error()));
        }
        let mut present: i32 = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut defaulted: i32 = 0;
        // SAFETY: `sd` is a valid self-relative descriptor from the call above.
        if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0
            || present == 0
            || dacl.is_null()
        {
            // SAFETY: `sd` was allocated by the conversion call above.
            LocalFree(sd as HLOCAL);
            return Err(PlatformError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: `path` names the directory, the DACL pointer comes from the
        // live descriptor, and owner/group/SACL are NULL because only the
        // DACL is being set. The `P` in the SDDL protects the in-memory
        // descriptor only — this call takes a bare ACL, not the descriptor,
        // so without `PROTECTED_DACL_SECURITY_INFORMATION` the directory
        // would keep inheriting its parent's ACEs beside the owner ACE.
        let status = SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            // No SACL is set; the parameter takes a const ACL pointer, so a
            // const NULL is exactly right.
            std::ptr::null(),
        );
        // SAFETY: `sd` was allocated by the conversion call above; the DACL
        // pointer is not read after this.
        LocalFree(sd as HLOCAL);
        if status != 0 {
            // `SetNamedSecurityInfoW` returns the DOS error itself; it does
            // not go through `GetLastError`.
            return Err(PlatformError::Io(std::io::Error::from_raw_os_error(
                status as i32,
            )));
        }
        Ok(())
    }
}

pub fn ensure_private_dir(dir: &Path) -> Result<(), PlatformError> {
    let ext = to_extended_length_path(dir);
    std::fs::create_dir_all(&ext)?;
    // Every call, not just creation: a configuration directory written before
    // this fix carries an inherited DACL until it is replaced.
    apply_owner_only_dacl(&ext)?;
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

/// Opens an existing file for read/write without following a reparse point
/// (symlink or junction) and without sharing a delete, which is what keeps a
/// second process from swapping the file underneath us. `None` means "not an
/// ordinary, singly-linked file": the caller must then treat it as untrusted.
pub fn open_regular_file_no_follow(path: &Path) -> Option<File> {
    use std::fs::OpenOptions as StdOpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let file = StdOpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(to_extended_length_path(path))
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || !handle_is_singly_linked(&file) {
        return None;
    }
    Some(file)
}

/// Reads the link count and reparse-point attribute of the *opened handle*
/// rather than of the pathname, so a name swapped after the open cannot
/// change the answer.
fn handle_is_singly_linked(file: &File) -> bool {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
    };
    // SAFETY: the handle is valid for `file`'s lifetime and `info` is a local
    // zeroed struct of the exact size the API expects.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    ok != 0 && info.nNumberOfLinks == 1 && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
}

/// Windows has no FIFO; a test that needs one cannot run here.
pub fn create_fifo(_path: &Path) -> Result<(), PlatformError> {
    Err(PlatformError::Unsupported("FIFOs do not exist on Windows".to_string()))
}

/// Creates a file that only the current user may read, refusing to follow a
/// reparse point at the final component.
pub fn create_private_file(path: &Path) -> Result<File, PlatformError> {
    use std::fs::OpenOptions as StdOpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    Ok(StdOpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(to_extended_length_path(path))?)
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

pub fn ssh_agent_missing_reason() -> Option<&'static str> {
    None
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;
    use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
    use windows_sys::Win32::Security::{GetAce, ACCESS_ALLOWED_ACE};

    /// Reads back what the DACL actually says: (ACE count, first ACE type,
    /// inherit flags, access mask). A directory that merely inherited its
    /// parent's DACL answers several ACEs here even for a single user, so the
    /// count alone tells "locked down" from "left as created".
    fn dacl_summary(path: &Path) -> Result<(u16, u8, u8, u32), PlatformError> {
        let wide = to_wide_null(path);
        // SAFETY: `wide` is NUL-terminated and outlives the call; `sd` is
        // `LocalFree`'d exactly once below, and the DACL/ACE pointers are only
        // read while it is alive.
        unsafe {
            let mut sd: *mut c_void = std::ptr::null_mut();
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let status = GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            );
            if status != 0 {
                return Err(PlatformError::Io(std::io::Error::from_raw_os_error(
                    status as i32,
                )));
            }
            if dacl.is_null() {
                LocalFree(sd as HLOCAL);
                return Err(PlatformError::Io(std::io::Error::other(
                    "no DACL on a directory that must have one",
                )));
            }
            // SAFETY: `dacl` is a valid ACL owned by the live descriptor `sd`.
            let count = (*dacl).AceCount;
            let mut ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: same descriptor; the ACE pointer is only read below.
            if GetAce(dacl, 0, &mut ace) == 0 || ace.is_null() {
                LocalFree(sd as HLOCAL);
                return Err(PlatformError::Io(std::io::Error::other(
                    "the owner ACE is missing",
                )));
            }
            // SAFETY: `ace` points at the first ACE of the live DACL; the
            // allow/deny layouts share the header and mask offsets.
            let first = &*(ace as *const ACCESS_ALLOWED_ACE);
            let summary = (count, first.Header.AceType, first.Header.AceFlags, first.Mask);
            // SAFETY: `sd` was allocated by the query above; nothing read from
            // it outlives this call.
            LocalFree(sd as HLOCAL);
            Ok(summary)
        }
    }

    #[test]
    fn extended_length_helper_prefixes_deep_drive_paths() {
        let deep = format!(r"C:\{}", "segment\\".repeat(35));
        let converted = to_extended_length_path(Path::new(&deep));
        assert!(converted.to_string_lossy().starts_with(r"\\?\C:\"));
    }

    #[test]
    fn a_private_dir_carries_only_the_owner_ace() {
        let dir = std::env::temp_dir().join(format!("linscp-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Pre-create it bare so the test covers the upgrade path too: a
        // configuration directory written before this fix carries an inherited
        // DACL until `ensure_private_dir` replaces it.
        std::fs::create_dir_all(&dir).expect("scratch dir");
        ensure_private_dir(&dir).expect("owner-only DACL applies");
        let (count, ace_type, ace_flags, mask) =
            dacl_summary(&dir).expect("the DACL reads back");
        assert_eq!(count, 1, "exactly the owner ACE, nothing inherited");
        assert_eq!(ace_type, ACCESS_ALLOWED_ACE_TYPE, "an allow ACE");
        assert_eq!(
            ace_flags,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            "children created inside inherit it"
        );
        assert_eq!(mask, FILE_ALL_ACCESS, "the owner keeps full access");
        // The child is what actually holds secrets, and bypass-traverse
        // checking means the directory's own ACE is not what protects it: the
        // file must carry the inherited owner-only ACE itself.
        let child = dir.join("sessions.ini");
        std::fs::write(&child, b"pretend secret").expect("child writes");
        let (child_count, _, _, child_mask) =
            dacl_summary(&child).expect("the child DACL reads back");
        assert_eq!(child_count, 1, "the child inherits exactly the owner ACE");
        assert_eq!(child_mask, FILE_ALL_ACCESS);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn locking_a_private_dir_twice_changes_nothing() {
        let dir = std::env::temp_dir().join(format!("linscp-acl-idem-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        ensure_private_dir(&dir).expect("first lock-down");
        ensure_private_dir(&dir).expect("second lock-down");
        let (count, _, _, _) = dacl_summary(&dir).expect("the DACL reads back");
        assert_eq!(count, 1, "re-applying replaces the DACL, never appends");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
