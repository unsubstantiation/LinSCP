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
    classify_desktop_session(
        std::env::var_os("WAYLAND_DISPLAY").as_deref(),
        std::env::var_os("XDG_SESSION_TYPE").as_deref(),
        std::env::var_os("DISPLAY").as_deref(),
    )
}

fn classify_desktop_session(wayland: Option<&std::ffi::OsStr>, session: Option<&std::ffi::OsStr>, display: Option<&std::ffi::OsStr>) -> DesktopSessionKind {
    if wayland.is_some_and(|v| !v.is_empty())
        || session.and_then(|v| v.to_str()).is_some_and(|v| v.eq_ignore_ascii_case("wayland")) {
        return DesktopSessionKind::Wayland;
    }
    if display.is_some_and(|v| !v.is_empty()) { return DesktopSessionKind::X11; }
    DesktopSessionKind::Headless
}

#[cfg(test)]
mod desktop_session_tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn session_environment_classification() {
        let val = |s: &'static str| Some(OsStr::new(s));
        assert_eq!(classify_desktop_session(None, None, None), DesktopSessionKind::Headless);
        assert_eq!(classify_desktop_session(val(""), None, val("")), DesktopSessionKind::Headless);
        assert_eq!(classify_desktop_session(None, None, val(":0")), DesktopSessionKind::X11);
        assert_eq!(classify_desktop_session(val("wayland-0"), None, val(":0")), DesktopSessionKind::Wayland);
        assert_eq!(classify_desktop_session(None, val("WaYlAnD"), None), DesktopSessionKind::Wayland);
    }
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

/// Opens an existing file for read/write without following a symbolic link
/// and without blocking on a FIFO; `None` means "not an ordinary file".
/// `O_NOFOLLOW` refuses a symlink at the last path component, `O_NONBLOCK`
/// keeps a special file from hanging the open, and a file that is not singly
/// linked is refused so a hard link to someone else's file is never truncated.
pub fn open_regular_file_no_follow(path: &Path) -> Option<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.nlink() != 1 || file_type_is_special(&metadata) {
        return None;
    }
    Some(file)
}

/// Rejects sockets, FIFOs and device nodes. On Linux the mode bits carry the
/// file kind, so no extra metadata call is needed.
fn file_type_is_special(metadata: &std::fs::Metadata) -> bool {
    metadata.mode() & libc::S_IFMT != libc::S_IFREG
}

/// Creates a FIFO (`mkfifo`) so a test can prove a special file is refused.
pub fn create_fifo(path: &Path) -> Result<(), PlatformError> {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| PlatformError::Unsupported("path contains a NUL byte".to_string()))?;
    // SAFETY: `name` is a NUL-terminated C string and the mode is a plain int.
    if unsafe { libc::mkfifo(name.as_ptr(), 0o600) } == 0 {
        Ok(())
    } else {
        Err(PlatformError::Io(std::io::Error::last_os_error()))
    }
}

/// Creates a file that only its owner may read (`0600`).
pub fn create_private_file(path: &Path) -> Result<File, PlatformError> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

pub fn sync_directory(path: &Path) -> Result<(), PlatformError> {
    File::open(path)?.sync_all()?;
    Ok(())
}

pub fn atomic_replace(temp_path: &Path, target_path: &Path) -> Result<(), PlatformError> {
    std::fs::rename(temp_path, target_path)?;
    Ok(())
}

pub fn ssh_agent_missing_reason() -> Option<&'static str> {
    None
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

mod gtk_clipboard {
    use std::ffi::{c_char, c_void, CStr};
    use std::sync::OnceLock;

    use crate::PlatformError;

    type FnMainContextDefault = unsafe extern "C" fn() -> *mut c_void;
    type FnMainContextIsOwner = unsafe extern "C" fn(*mut c_void) -> i32;
    type FnGdkDisplayGetDefault = unsafe extern "C" fn() -> *mut c_void;
    type FnGdkAtomInternStaticString = unsafe extern "C" fn(*const c_char) -> *mut c_void;
    type FnGtkClipboardGetForDisplay =
        unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void;
    type FnGtkClipboardWaitForText = unsafe extern "C" fn(*mut c_void) -> *mut c_char;
    type FnGtkClipboardSetText = unsafe extern "C" fn(*mut c_void, *const c_char, i32);
    type FnGFree = unsafe extern "C" fn(*mut c_void);

    struct GtkClipboardSymbols {
        main_context_default: FnMainContextDefault,
        main_context_is_owner: FnMainContextIsOwner,
        display_get_default: FnGdkDisplayGetDefault,
        atom_intern_static: FnGdkAtomInternStaticString,
        clipboard_get_for_display: FnGtkClipboardGetForDisplay,
        clipboard_wait_for_text: FnGtkClipboardWaitForText,
        clipboard_set_text: FnGtkClipboardSetText,
        g_free: FnGFree,
    }

    // SAFETY: All fields are plain C function pointers resolved from the
    // process's already-loaded GTK3/GDK3/GLib libraries; callers enforce GTK
    // main-thread affinity via `is_main_thread()`.
    unsafe impl Send for GtkClipboardSymbols {}
    // SAFETY: See above.
    unsafe impl Sync for GtkClipboardSymbols {}

    static GTK_CLIPBOARD: OnceLock<Option<GtkClipboardSymbols>> = OnceLock::new();

    unsafe fn sym<T: Copy>(name: &CStr) -> Option<T> {
        // SAFETY: `RTLD_DEFAULT` inspects already-loaded shared libraries in
        // this process without dlopening new ones, and `name` is NUL-terminated.
        let ptr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: Caller supplies the exact GTK3/GDK3/GLib C ABI signature `T`.
        Some(unsafe { std::mem::transmute_copy(&ptr) })
    }

    fn api() -> Option<&'static GtkClipboardSymbols> {
        GTK_CLIPBOARD
            .get_or_init(|| {
                // SAFETY: Resolves standard GTK3, GDK3, and GLib 2.0 C symbols
                // when `linscp-gui` has linked them into the process.
                unsafe {
                    Some(GtkClipboardSymbols {
                        main_context_default: sym(c"g_main_context_default")?,
                        main_context_is_owner: sym(c"g_main_context_is_owner")?,
                        display_get_default: sym(c"gdk_display_get_default")?,
                        atom_intern_static: sym(c"gdk_atom_intern_static_string")?,
                        clipboard_get_for_display: sym(c"gtk_clipboard_get_for_display")?,
                        clipboard_wait_for_text: sym(c"gtk_clipboard_wait_for_text")?,
                        clipboard_set_text: sym(c"gtk_clipboard_set_text")?,
                        g_free: sym(c"g_free")?,
                    })
                }
            })
            .as_ref()
    }

    pub(super) fn is_main_thread() -> bool {
        let Some(syms) = api() else {
            return false;
        };
        // SAFETY: `g_main_context_default` returns GLib's global main context
        // and `g_main_context_is_owner` is thread-safe.
        unsafe {
            let ctx = (syms.main_context_default)();
            !ctx.is_null() && (syms.main_context_is_owner)(ctx) != 0
        }
    }

    pub(super) fn read_text_on_main_thread() -> Result<String, PlatformError> {
        let Some(syms) = api() else {
            return Err(PlatformError::Unsupported(
                "GTK clipboard symbols are unavailable in this process.".to_string(),
            ));
        };
        if !is_main_thread() {
            return Err(PlatformError::Unsupported(
                "GTK clipboard access must run on the main thread.".to_string(),
            ));
        }
        // SAFETY: Running on the GTK main thread; `display` and `clipboard` are
        // owned by GDK/GTK (speaking Wayland `wl_data_device` or X11 `CLIPBOARD`
        // according to the active GdkDisplay), and any non-null buffer returned
        // by `gtk_clipboard_wait_for_text` is freed with `g_free`.
        unsafe {
            let display = (syms.display_get_default)();
            if display.is_null() {
                return Err(PlatformError::Unsupported(
                    "No active GDK display.".to_string(),
                ));
            }
            let atom = (syms.atom_intern_static)(c"CLIPBOARD".as_ptr());
            let clipboard = (syms.clipboard_get_for_display)(display, atom);
            if clipboard.is_null() {
                return Err(PlatformError::Unsupported(
                    "Cannot access the GDK clipboard.".to_string(),
                ));
            }
            let raw = (syms.clipboard_wait_for_text)(clipboard);
            if raw.is_null() {
                return Ok(String::new());
            }
            let text = CStr::from_ptr(raw).to_string_lossy().into_owned();
            (syms.g_free)(raw.cast::<c_void>());
            Ok(text)
        }
    }

    pub(super) fn write_text_on_main_thread(text: &str) -> Result<(), PlatformError> {
        let len = i32::try_from(text.len()).map_err(|_| {
            PlatformError::Unsupported("Clipboard text exceeds GTK size limit.".to_string())
        })?;
        let Some(syms) = api() else {
            return Err(PlatformError::Unsupported(
                "GTK clipboard symbols are unavailable in this process.".to_string(),
            ));
        };
        if !is_main_thread() {
            return Err(PlatformError::Unsupported(
                "GTK clipboard access must run on the main thread.".to_string(),
            ));
        }
        // SAFETY: Running on the GTK main thread; `gtk_clipboard_set_text` copies
        // `len` UTF-8 bytes synchronously before returning.
        unsafe {
            let display = (syms.display_get_default)();
            if display.is_null() {
                return Err(PlatformError::Unsupported(
                    "No active GDK display.".to_string(),
                ));
            }
            let atom = (syms.atom_intern_static)(c"CLIPBOARD".as_ptr());
            let clipboard = (syms.clipboard_get_for_display)(display, atom);
            if clipboard.is_null() {
                return Err(PlatformError::Unsupported(
                    "Cannot access the GDK clipboard.".to_string(),
                ));
            }
            let ptr = if text.is_empty() {
                c"".as_ptr()
            } else {
                text.as_ptr().cast::<c_char>()
            };
            (syms.clipboard_set_text)(clipboard, ptr, len);
            Ok(())
        }
    }
}

/// Returns whether the calling thread currently owns GLib/GTK's default main context.
pub fn is_gtk_main_thread() -> bool {
    gtk_clipboard::is_main_thread()
}

/// Reads UTF-8 text from the active Wayland or X11 `GdkDisplay` clipboard on the GTK main thread.
pub fn read_clipboard_text_on_main_thread() -> Result<String, PlatformError> {
    gtk_clipboard::read_text_on_main_thread()
}

/// Writes UTF-8 text to the active Wayland or X11 `GdkDisplay` clipboard on the GTK main thread.
pub fn write_clipboard_text_on_main_thread(text: &str) -> Result<(), PlatformError> {
    gtk_clipboard::write_text_on_main_thread(text)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "linscp-platform-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir
    }

    /// The temporary directory and the temporary file it holds belong to the
    /// user alone: nobody else may read what the session keeps there.
    #[test]
    fn the_private_directory_and_file_belong_to_the_user_alone() {
        let root = scratch("private");
        let dir = root.join("private-dir");
        ensure_private_dir(&dir).expect("the private directory is created");
        let mode = std::fs::metadata(&dir).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700, "the directory is readable by its owner only");

        // A directory that already exists is still made private.
        std::fs::set_permissions(&dir, Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&dir).expect("the private directory is created");
        let mode = std::fs::metadata(&dir).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o700, "the directory is readable by its owner only");

        let file = dir.join("secret.bin");
        create_exclusive_private_file(&file, b"secret").expect("the file is created");
        let mode = std::fs::metadata(&file).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "the file is readable by its owner only");
        assert_eq!(std::fs::read(&file).unwrap(), b"secret");

        // A file that is already there is never overwritten: the caller
        // created it, so replacing it would destroy what it held.
        let again = create_exclusive_private_file(&file, b"other");
        assert!(
            matches!(&again, Err(PlatformError::AlreadyExists(_))),
            "an existing file is not replaced: {again:?}"
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"secret");

        let _ = std::fs::remove_dir_all(root);
    }

    /// The configuration directory is the one the desktop expects: under
    /// `XDG_CONFIG_HOME` when it is set, and under the home directory
    /// otherwise.
    #[test]
    fn the_configuration_directory_is_the_one_the_desktop_expects() {
        let dir = default_config_dir();
        assert!(!dir.as_os_str().is_empty(), "the directory is named");
        let text = dir.to_string_lossy().into_owned();
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            assert_eq!(
                dir,
                PathBuf::from(xdg).join("linscp"),
                "the directory follows XDG_CONFIG_HOME"
            );
        } else if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            assert_eq!(
                dir,
                PathBuf::from(home).join(".config").join("linscp"),
                "the directory is under the home directory"
            );
        } else {
            assert!(text.ends_with("linscp"), "the directory is named: {text}");
        }

        // The roots the file pane offers start with the home directory.
        let roots = list_roots();
        assert!(!roots.is_empty(), "there is a root to offer");
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            assert_eq!(
                roots[0].path,
                PathBuf::from(home).to_string_lossy().into_owned(),
                "the home directory is the first root"
            );
        }
    }

}
