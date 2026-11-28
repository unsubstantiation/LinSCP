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

/// Create a new owner-only file in an existing directory without altering its DACL.
/// The protected DACL is supplied at creation, before any data can be written.
pub(crate) fn create_container_private_file(path: &Path) -> Result<File, PlatformError> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE};

    let name = to_wide_null(&to_extended_length_path(path));
    let sddl = str_to_wide_null("D:P(A;;FA;;;OW)");
    // SAFETY: all pointers passed to Windows are valid for the duration of the
    // calls; the security descriptor is released exactly once after CreateFileW.
    unsafe {
        let mut descriptor: *mut std::ffi::c_void = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut descriptor, std::ptr::null_mut()) == 0 {
            return Err(PlatformError::Io(std::io::Error::last_os_error()));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = CreateFileW(name.as_ptr(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, &attributes, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, std::ptr::null_mut());
        let create_error = if handle == INVALID_HANDLE_VALUE { Some(std::io::Error::last_os_error()) } else { None };
        LocalFree(descriptor as HLOCAL);
        if let Some(err) = create_error { return Err(PlatformError::Io(err)); }
        Ok(File::from_raw_handle(handle))
    }
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
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&ext)
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                PlatformError::AlreadyExists(path.display().to_string())
            } else {
                PlatformError::Io(err)
            }
        })?;
    if let Err(err) = file.write_all(content).and_then(|()| file.sync_all()) {
        drop(file);
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
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = StdOpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
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
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    Ok(StdOpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(to_extended_length_path(path))?)
}

/// Flush a directory handle opened with write access. A read-only handle
/// cannot be flushed by FlushFileBuffers. Reject reparse points and propagate
/// every open/flush error; do not silently downgrade the durability barrier.
pub fn sync_directory(path: &Path) -> Result<(), PlatformError> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let directory = OpenOptions::new()
        .write(true)
        // Hold the opened directory against rename or deletion until the flush.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(to_extended_length_path(path))?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PlatformError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput, "Directory sync requires a non-reparse-point directory",
        )));
    }
    directory.sync_all()?;
    Ok(())
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
    let explicit_sock = std::env::var_os("SSH_AUTH_SOCK").filter(|v| !v.is_empty());
    let pipe_path = explicit_sock
        .clone()
        .unwrap_or_else(|| std::ffi::OsString::from(r"\\.\pipe\openssh-ssh-agent"));
    match tokio::net::windows::named_pipe::ClientOptions::new().open(pipe_path) {
        Ok(client) => Ok(Some(Box::new(client))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if explicit_sock.is_none() {
                if let Some(stream) = pageant::connect_pageant_stream() {
                    return Ok(Some(stream));
                }
            }
            Ok(None)
        }
        Err(err) => Err(PlatformError::Io(err)),
    }
}

mod pageant {
    use std::ffi::c_void;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    use super::{str_to_wide_null, SDDL_REVISION_1};

    const AGENT_COPYDATA_ID: usize = 0x804e_50ba;
    const AGENT_MAX_MSGLEN: usize = 8192;
    const WM_COPYDATA: u32 = 0x004A;
    const SMTO_NORMAL: u32 = 0x0000;
    const PAGE_READWRITE: u32 = 0x04;
    const FILE_MAP_WRITE: u32 = 0x0002;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER_CLASS: u32 = 1;
    const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

    #[repr(C)]
    struct SecurityAttributes {
        n_length: u32,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: i32,
    }

    #[repr(C)]
    struct CopyDataStruct {
        dw_data: usize,
        cb_data: u32,
        lp_data: *const u8,
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn FindWindowW(lp_class_name: *const u16, lp_window_name: *const u16) -> isize;
        fn GetWindowThreadProcessId(hwnd: isize, lpdw_process_id: *mut u32) -> u32;
        fn SendMessageTimeoutA(
            hwnd: isize,
            msg: u32,
            w_param: usize,
            l_param: isize,
            fu_flags: u32,
            u_timeout: u32,
            lpdw_result: *mut usize,
        ) -> isize;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcess() -> HANDLE;
        fn GetCurrentThreadId() -> u32;
        fn CreateFileMappingA(
            h_file: HANDLE,
            lp_file_mapping_attributes: *const SecurityAttributes,
            fl_protect: u32,
            dw_maximum_size_high: u32,
            dw_maximum_size_low: u32,
            lp_name: *const u8,
        ) -> HANDLE;
        fn MapViewOfFile(
            h_file_mapping_object: HANDLE,
            dw_desired_access: u32,
            dw_file_offset_high: u32,
            dw_file_offset_low: u32,
            dw_number_of_bytes_to_map: usize,
        ) -> *mut u8;
        fn UnmapViewOfFile(lp_base_address: *const c_void) -> i32;
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: HANDLE,
            desired_access: u32,
            token_handle: *mut HANDLE,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: HANDLE,
            token_information_class: u32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn EqualSid(p_sid1: *mut c_void, p_sid2: *mut c_void) -> i32;
    }

    fn token_user_buf(process: HANDLE) -> Option<Vec<u8>> {
        // SAFETY: `OpenProcessToken` and `GetTokenInformation` query read-only
        // token metadata and close the token handle before returning.
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 || token.is_null() {
                return None;
            }
            let mut needed: u32 = 0;
            let _ = GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
            if needed == 0 || needed > 4096 {
                let _ = CloseHandle(token);
                return None;
            }
            let mut buf = vec![0u8; needed as usize];
            let ok = GetTokenInformation(
                token,
                TOKEN_USER_CLASS,
                buf.as_mut_ptr() as *mut c_void,
                needed,
                &mut needed,
            );
            let _ = CloseHandle(token);
            if ok == 0 {
                return None;
            }
            Some(buf)
        }
    }

    fn verify_same_user_hwnd(hwnd: isize) -> bool {
        // SAFETY: Queries the target HWND's owning PID, opens it with limited
        // query rights, and compares its user SID with the current process SID.
        unsafe {
            let mut pid: u32 = 0;
            if GetWindowThreadProcessId(hwnd, &mut pid) == 0 || pid == 0 {
                return false;
            }
            let Some(cur_buf) = token_user_buf(GetCurrentProcess()) else {
                return false;
            };
            let proc_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if proc_handle.is_null() {
                return false;
            }
            let target_buf = token_user_buf(proc_handle);
            let _ = CloseHandle(proc_handle);
            let Some(target_buf) = target_buf else {
                return false;
            };
            if cur_buf.len() < std::mem::size_of::<SidAndAttributes>()
                || target_buf.len() < std::mem::size_of::<SidAndAttributes>()
            {
                return false;
            }
            let cur_sid = (*(cur_buf.as_ptr() as *const SidAndAttributes)).sid;
            let target_sid = (*(target_buf.as_ptr() as *const SidAndAttributes)).sid;
            !cur_sid.is_null() && !target_sid.is_null() && EqualSid(cur_sid, target_sid) != 0
        }
    }

    fn find_verified_pageant_hwnd() -> Option<isize> {
        let name = str_to_wide_null("Pageant");
        // SAFETY: `name` is NUL-terminated UTF-16 and outlives `FindWindowW`.
        let hwnd = unsafe { FindWindowW(name.as_ptr(), name.as_ptr()) };
        if hwnd == 0 || !verify_same_user_hwnd(hwnd) {
            return None;
        }
        Some(hwnd)
    }

    pub(super) fn transact_hwnd(hwnd: isize, request: &[u8]) -> std::io::Result<Vec<u8>> {
        if request.len() < 4 || request.len() > AGENT_MAX_MSGLEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SSH agent message exceeds Pageant limit",
            ));
        }
        let sddl = str_to_wide_null("D:P(A;;GA;;;OW)");
        // SAFETY: Creates an owner-only anonymous file mapping, writes the
        // framed SSH agent request, sends `WM_COPYDATA`, copies the reply,
        // volatile-zeroes the shared view, and releases every Win32 handle.
        unsafe {
            let mut sd: *mut c_void = std::ptr::null_mut();
            let mut sd_len: u32 = 0;
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                &mut sd_len,
            ) == 0
                || sd.is_null()
            {
                return Err(std::io::Error::last_os_error());
            }
            let sa = SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as u32,
                lp_security_descriptor: sd,
                b_inherit_handle: 0,
            };
            let map_name = format!(
                "PageantRequest{:08x}{:08x}\0",
                GetCurrentThreadId(),
                rand::random::<u32>()
            );
            let mapping = CreateFileMappingA(
                INVALID_HANDLE_VALUE,
                &sa,
                PAGE_READWRITE,
                0,
                AGENT_MAX_MSGLEN as u32,
                map_name.as_ptr(),
            );
            let _ = LocalFree(sd as HLOCAL);
            if mapping.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            let view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, AGENT_MAX_MSGLEN);
            if view.is_null() {
                let err = std::io::Error::last_os_error();
                let _ = CloseHandle(mapping);
                return Err(err);
            }
            std::ptr::copy_nonoverlapping(request.as_ptr(), view, request.len());
            let cds = CopyDataStruct {
                dw_data: AGENT_COPYDATA_ID,
                cb_data: map_name.len() as u32,
                lp_data: map_name.as_ptr(),
            };
            let mut msg_res: usize = 0;
            let sent = SendMessageTimeoutA(
                hwnd,
                WM_COPYDATA,
                0,
                &cds as *const CopyDataStruct as isize,
                SMTO_NORMAL,
                15_000,
                &mut msg_res,
            );
            let reply = if sent != 0 && msg_res != 0 {
                let mut hdr = [0u8; 4];
                std::ptr::copy_nonoverlapping(view, hdr.as_mut_ptr(), 4);
                let reply_body_len = u32::from_be_bytes(hdr) as usize;
                if let Some(total) = reply_body_len.checked_add(4).filter(|&n| n <= AGENT_MAX_MSGLEN) {
                    let mut out = vec![0u8; total];
                    std::ptr::copy_nonoverlapping(view, out.as_mut_ptr(), total);
                    Ok(out)
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Pageant returned an oversized reply",
                    ))
                }
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "Pageant rejected or timed out the SSH agent request",
                ))
            };
            for i in 0..AGENT_MAX_MSGLEN {
                std::ptr::write_volatile(view.add(i), 0);
            }
            let _ = UnmapViewOfFile(view as *const c_void);
            let _ = CloseHandle(mapping);
            reply
        }
    }

    pub(super) fn connect_pageant_stream() -> Option<Box<dyn crate::AsyncStream>> {
        let _hwnd = find_verified_pageant_hwnd()?;
        let (client_stream, mut server_stream) = tokio::io::duplex(16384);
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 4];
                if server_stream.read_exact(&mut len_buf).await.is_err() {
                    break;
                }
                let msg_len = u32::from_be_bytes(len_buf) as usize;
                if msg_len == 0 || msg_len + 4 > AGENT_MAX_MSGLEN {
                    break;
                }
                let mut packet = vec![0u8; 4 + msg_len];
                packet[..4].copy_from_slice(&len_buf);
                if server_stream.read_exact(&mut packet[4..]).await.is_err() {
                    break;
                }
                let Some(hwnd) = find_verified_pageant_hwnd() else {
                    break;
                };
                let Ok(Ok(reply)) =
                    tokio::task::spawn_blocking(move || transact_hwnd(hwnd, &packet)).await
                else {
                    break;
                };
                if server_stream.write_all(&reply).await.is_err()
                    || server_stream.flush().await.is_err()
                {
                    break;
                }
            }
        });
        Some(Box::new(client_stream))
    }
}

mod win32_clipboard {
    use std::ffi::c_void;

    use crate::PlatformError;

    const CF_UNICODETEXT: u32 = 13;
    const GMEM_MOVEABLE: u32 = 0x0002;
    const MAX_CLIPBOARD_UTF16_UNITS: usize = 16 * 1024 * 1024;

    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(h_wnd_new_owner: isize) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn GetClipboardData(u_format: u32) -> *mut c_void;
        fn SetClipboardData(u_format: u32, h_mem: *mut c_void) -> *mut c_void;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalAlloc(u_flags: u32, dw_bytes: usize) -> *mut c_void;
        fn GlobalFree(h_mem: *mut c_void) -> *mut c_void;
        fn GlobalLock(h_mem: *mut c_void) -> *mut c_void;
        fn GlobalUnlock(h_mem: *mut c_void) -> i32;
        fn GlobalSize(h_mem: *mut c_void) -> usize;
    }

    fn open_with_retry() -> Result<(), PlatformError> {
        for attempt in 0..5 {
            // SAFETY: `OpenClipboard(0)` opens the task clipboard and takes no pointers.
            if unsafe { OpenClipboard(0) } != 0 {
                return Ok(());
            }
            if attempt < 4 {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
        Err(PlatformError::Io(std::io::Error::last_os_error()))
    }

    pub(super) fn read_text() -> Result<String, PlatformError> {
        open_with_retry()?;
        // SAFETY: Clipboard is open for this thread and closed before returning.
        let result = unsafe {
            let handle = GetClipboardData(CF_UNICODETEXT);
            if handle.is_null() {
                Ok(String::new())
            } else {
                let bytes = GlobalSize(handle);
                if bytes < 2 {
                    Ok(String::new())
                } else {
                    let ptr = GlobalLock(handle);
                    if ptr.is_null() {
                        Ok(String::new())
                    } else {
                        let units = (bytes / 2).min(MAX_CLIPBOARD_UTF16_UNITS);
                        let slice = std::slice::from_raw_parts(ptr as *const u16, units);
                        let end = slice.iter().position(|&ch| ch == 0).unwrap_or(slice.len());
                        let text = String::from_utf16_lossy(&slice[..end]);
                        let _ = GlobalUnlock(handle);
                        Ok(text)
                    }
                }
            }
        };
        // SAFETY: Matches the successful `OpenClipboard(0)` in `open_with_retry`.
        unsafe {
            let _ = CloseClipboard();
        }
        result
    }

    pub(super) fn write_text(text: &str) -> Result<(), PlatformError> {
        let wide = super::str_to_wide_null(text);
        let byte_len = wide
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .ok_or_else(|| {
                PlatformError::Unsupported("Clipboard text is too large.".to_string())
            })?;
        open_with_retry()?;
        // SAFETY: Clipboard is open; `GlobalAlloc` allocates `byte_len` moveable
        // bytes, unlocked before `SetClipboardData`, and freed only on failure.
        let result = unsafe {
            if EmptyClipboard() == 0 {
                Err(PlatformError::Io(std::io::Error::last_os_error()))
            } else {
                let hmem = GlobalAlloc(GMEM_MOVEABLE, byte_len);
                if hmem.is_null() {
                    Err(PlatformError::Io(std::io::Error::last_os_error()))
                } else {
                    let dst = GlobalLock(hmem);
                    if dst.is_null() {
                        let _ = GlobalFree(hmem);
                        Err(PlatformError::Io(std::io::Error::last_os_error()))
                    } else {
                        std::ptr::copy_nonoverlapping(wide.as_ptr(), dst as *mut u16, wide.len());
                        let _ = GlobalUnlock(hmem);
                        if SetClipboardData(CF_UNICODETEXT, hmem).is_null() {
                            let err = std::io::Error::last_os_error();
                            let _ = GlobalFree(hmem);
                            Err(PlatformError::Io(err))
                        } else {
                            Ok(())
                        }
                    }
                }
            }
        };
        // SAFETY: Matches `open_with_retry`.
        unsafe {
            let _ = CloseClipboard();
        }
        result
    }
}

/// Reads UTF-8 text from the Windows clipboard (`CF_UNICODETEXT`), even when the
/// target WebView window has not yet acquired focus on right-click.
pub fn read_clipboard_text() -> Result<String, PlatformError> {
    win32_clipboard::read_text()
}

/// Writes UTF-8 text to the Windows clipboard (`CF_UNICODETEXT`).
pub fn write_clipboard_text(text: &str) -> Result<(), PlatformError> {
    win32_clipboard::write_text(text)
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
    fn directory_sync_flushes_real_directory_and_rejects_invalid_paths() {
        let root = std::env::temp_dir().join(format!("linscp-win-dir-sync-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        sync_directory(&root).expect("a writable test directory must be flushed");
        let file = root.join("file");
        std::fs::write(&file, b"test").unwrap();
        assert!(sync_directory(&file).is_err());
        assert!(sync_directory(&root.join("missing")).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn directory_sync_refuses_directory_symlinks_when_supported() {
        let root = std::env::temp_dir().join(format!("linscp-win-dir-link-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let target = root.join("target");
        std::fs::create_dir(&target).unwrap();
        let link = root.join("link");
        match std::os::windows::fs::symlink_dir(&target, &link) {
            Ok(()) => {
                assert!(sync_directory(&link).is_err());
                std::fs::remove_dir(&link).unwrap();
            }
            Err(error) if error.raw_os_error() == Some(1314) => {} // symlink privilege unavailable
            Err(error) => panic!("could not create test symlink: {error}"),
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn extended_length_helper_prefixes_deep_drive_paths() {
        let deep = format!(r"C:\{}", "segment\\".repeat(35));
        let converted = to_extended_length_path(Path::new(&deep));
        assert!(converted.to_string_lossy().starts_with(r"\\?\C:\"));
    }

    #[test]
    fn container_file_has_private_dacl_without_changing_parent() {
        let dir = std::env::temp_dir().join(format!("linscp-container-acl-{}-{}", std::process::id(), rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let parent_before = dacl_summary(&dir).unwrap();
        let path = dir.join("vault.dat");
        let container = crate::container_file::ContainerFile::try_acquire(&path).unwrap();
        container.create("test password", b"first").unwrap();
        for expected in [b"first".as_slice(), b"second".as_slice()] {
            if expected == b"second" { container.save("test password", expected).unwrap(); }
            assert_eq!(container.open("test password").unwrap().as_slice(), expected);
            let (count, kind, flags, mask) = dacl_summary(&path).unwrap();
            assert_eq!(count, 1, "no inherited or additional ACEs");
            assert_eq!(kind, ACCESS_ALLOWED_ACE_TYPE);
            assert_eq!(flags, 0, "file ACE is not inherited");
            assert_eq!(mask, FILE_ALL_ACCESS);
            assert_eq!(dacl_summary(&dir).unwrap(), parent_before, "parent DACL must not change");
        }
        drop(container);
        std::fs::remove_dir_all(dir).unwrap();
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

    #[tokio::test]
    async fn pageant_agent_probe_returns_cleanly_when_no_pageant_window_exists() {
        // On a headless Windows CI runner without Pageant running, `connect_ssh_agent`
        // (and its Pageant fallback) must return cleanly without hanging or panicking.
        let probed = connect_ssh_agent().await.expect("ssh/pageant probe succeeds");
        if let Some(mut stream) = probed {
            use tokio::io::AsyncWriteExt;
            let _ = stream.shutdown().await;
        }
    }
}
