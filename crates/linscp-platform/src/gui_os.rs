//! OS-isolated GUI desktop helpers (`stat_extended`, `create_local_symlink`,
//! `open_url_in_browser`, file-manager shell integration, and OS username lookup)
//! keeping all platform `#[cfg]` branches inside `linscp-platform`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::UNIX_EPOCH;

use crate::terminal::local_ymdhms;
use crate::{sys, write_private_file_atomic, PlatformError};

/// Rich local metadata snapshot used by the Commander GUI properties dialog
/// and atomic local text editor (`mtime_ns` conflict guard).
#[derive(Debug, Clone)]
pub struct ExtendedLocalStat {
    pub size: u64,
    pub mtime_secs: i64,
    pub mtime_ns: i128,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub broken_link: bool,
    pub permissions: String,
    pub mode: u32,
    pub owner: String,
    pub group: String,
    pub link_target: Option<String>,
    pub date: String,
}

/// Formats a Unix epoch timestamp into a short Commander listing date (`"Oct 28 01:45"` or `"Oct 28  2025"`).
pub fn format_listing_date(epoch_secs: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (year, month, day, hour, min, _sec) = local_ymdhms(epoch_secs);
    let mon = MONTHS[(month.clamp(1, 12) - 1) as usize];
    let now_secs = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(epoch_secs);
    let (now_year, _, _, _, _, _) = local_ymdhms(now_secs);
    if (now_secs - epoch_secs).abs() < 15_552_000 && year == now_year {
        format!("{mon} {day:2} {hour:02}:{min:02}")
    } else {
        format!("{mon} {day:2}  {year:04}")
    }
}

/// Reads local symlink/target metadata including nanosecond `mtime_ns`, permissions,
/// owner/group IDs, and symlink target path.
pub fn stat_extended(path: &Path) -> Result<ExtendedLocalStat, PlatformError> {
    #[cfg(target_os = "windows")]
    let resolved = crate::windows::to_extended_length_path(path);
    #[cfg(not(target_os = "windows"))]
    let resolved = path.to_path_buf();

    let meta = std::fs::symlink_metadata(&resolved)?;
    let is_symlink = meta.file_type().is_symlink();
    let (is_dir, broken_link, effective_size) = if is_symlink {
        match std::fs::metadata(&resolved) {
            Ok(target) => (
                target.is_dir(),
                false,
                if target.is_dir() { 0 } else { target.len() },
            ),
            Err(_) => (false, true, 0),
        }
    } else {
        let dir = meta.is_dir();
        (dir, false, if dir { 0 } else { meta.len() })
    };

    let dur = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .unwrap_or_default();
    let mtime_secs = dur.as_secs() as i64;
    let mtime_ns = dur.as_nanos() as i128;

    #[cfg(unix)]
    let (mode, owner, group) = {
        use std::os::unix::fs::MetadataExt;
        (
            meta.mode() & 0o7777,
            meta.uid().to_string(),
            meta.gid().to_string(),
        )
    };
    #[cfg(not(unix))]
    let (mode, owner, group) = {
        let m = if meta.permissions().readonly() {
            if is_dir {
                0o555
            } else {
                0o444
            }
        } else if is_dir {
            0o755
        } else {
            0o644
        };
        (m, String::new(), String::new())
    };

    let link_target = if is_symlink {
        std::fs::read_link(&resolved)
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    } else {
        None
    };

    Ok(ExtendedLocalStat {
        size: effective_size,
        mtime_secs,
        mtime_ns,
        is_dir,
        is_symlink,
        broken_link,
        permissions: sys::format_permissions(&meta),
        mode,
        owner,
        group,
        link_target,
        date: format_listing_date(mtime_secs),
    })
}

/// Creates a local symbolic link at `link_path` pointing to `target`.
pub fn create_local_symlink(target: &str, link_path: &Path) -> Result<(), PlatformError> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link_path)?;
        Ok(())
    }
    #[cfg(windows)]
    {
        let target_path = Path::new(target);
        let target_is_dir = if target_path.is_absolute() {
            target_path.is_dir()
        } else {
            link_path
                .parent()
                .map(|p| p.join(target_path).is_dir())
                .unwrap_or(false)
        };
        if target_is_dir {
            std::os::windows::fs::symlink_dir(target, link_path)?;
        } else {
            std::os::windows::fs::symlink_file(target, link_path)?;
        }
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (target, link_path);
        Err(PlatformError::UnsupportedUri(
            "Symbolic links are not supported on this platform.".to_string(),
        ))
    }
}

/// Returns the current OS login name, falling back to `"user"`.
pub fn default_os_username() -> String {
    for key in ["USER", "LOGNAME", "USERNAME"] {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    "user".to_string()
}

#[allow(dead_code)]
fn find_program_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(m) = std::fs::metadata(&candidate) {
                    if (m.permissions().mode() & 0o111) != 0 {
                        return Some(candidate);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                return Some(candidate);
            }
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

/// Opens an `http://127.0.0.1:<port>/` URL in the user's desktop browser
/// (Wayland and X11 aware on Linux, `cmd /C start` on Windows, `termux-open-url` on Android).
pub fn open_url_in_browser(url: &str) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use crate::linux::{detect_desktop_session, DesktopSessionKind};
        if detect_desktop_session() == DesktopSessionKind::Headless {
            return Err("no graphical session (WAYLAND_DISPLAY or DISPLAY is not set)".to_string());
        }
        if let Ok(browser) = std::env::var("BROWSER") {
            let trimmed = browser.trim();
            if !trimmed.is_empty() {
                let first = trimmed.split(':').next().unwrap_or(trimmed).trim();
                let parts: Vec<&str> = first.split_whitespace().collect();
                if let Some((prog, args)) = parts.split_first() {
                    if let Some(resolved) = find_program_on_path(prog) {
                        Command::new(resolved)
                            .args(args)
                            .arg(url)
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .spawn()
                            .map_err(|e| format!("failed to launch BROWSER '{prog}': {e}"))?;
                        return Ok(());
                    }
                }
            }
        }
        let openers: &[(&str, &[&str], &str)] = &[
            ("xdg-open", &[], ""),
            ("gio", &["open"], ""),
            ("sensible-browser", &[], ""),
        ];
        for (prog, prefix_args, _backend) in openers {
            if let Some(resolved) = find_program_on_path(prog) {
                Command::new(resolved)
                    .args(*prefix_args)
                    .arg(url)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|e| format!("failed to launch '{prog}': {e}"))?;
                return Ok(());
            }
        }
        Err("neither xdg-open, gio nor BROWSER was found on PATH".to_string())
    }

    #[cfg(target_os = "windows")]
    {
        Command::new("cmd")
            .args(["/C", "start", "", url])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to open URL in Windows default browser: {e}"))?;
        Ok(())
    }

    #[cfg(target_os = "android")]
    {
        if let Some(opener) = find_program_on_path("termux-open-url") {
            Command::new(opener)
                .arg(url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("failed to run termux-open-url: {e}"))?;
            return Ok(());
        }
        Err("no browser launcher (termux-open-url) found on PATH".to_string())
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "android")))]
    {
        let _ = url;
        Err("automatic browser opening is not supported on this platform".to_string())
    }
}

/// Rejects launcher paths that cannot be carried into a file-manager action.
///
/// Two kinds of definition are written and they quote differently, so the rejection
/// has to depend on which one: a `.desktop` `Exec=` token takes double quotes, while
/// the GNOME Files script embeds the path in single quotes inside `sh`. A plain
/// `C:\Program Files\LinSCP\linscp-gui.exe` contains a backslash and a space and is
/// perfectly usable on Windows; a POSIX path is free to contain almost anything. The
/// characters refused here are the ones no quoting can rescue.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn validate_shell_launcher_path(launcher: &Path) -> Result<String, String> {
    let text = launcher.to_string_lossy().into_owned();
    if text.is_empty() {
        return Err("Could not locate the LinSCP GUI launcher executable.".to_string());
    }
    let refused = if cfg!(target_os = "windows") {
        // Windows: these are illegal in a path anyway, and `%` would be expanded by
        // the `.cmd` wrapper before the path is used.
        text.chars()
            .any(|c| c.is_control() || matches!(c, '"' | '|' | '%' | '*' | '?'))
    } else {
        // POSIX: the desktop actions quote the path with double quotes, so only a
        // control character or a double quote is impossible. A single quote is
        // refused later, by name, by the one definition that wraps it in `sh`
        // single quotes.
        text.chars().any(|c| c.is_control() || c == '"')
    };
    if refused {
        return Err(format!(
            "The launcher path '{text}' contains characters that cannot be carried safely in a file-manager action."
        ));
    }
    Ok(text)
}

/// The per-user definitions each Linux file manager reads. Not reachable on
/// Android or macOS: those have no XDG data directory to write them into, and
/// `install_shell_integration` refuses the request on anything but Linux/Windows.
#[cfg(target_os = "linux")]
fn linux_shell_targets() -> Result<Vec<(String, PathBuf, bool)>, String> {
    let data_home = std::env::var_os("XDG_DATA_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".local").join("share"))
        })
        .ok_or_else(|| "Neither XDG_DATA_HOME nor HOME is set.".to_string())?;

    Ok(vec![
        (
            "Dolphin (KDE)".to_string(),
            data_home
                .join("kio")
                .join("servicemenus")
                .join("linscp-upload.desktop"),
            false,
        ),
        (
            "Files (GNOME)".to_string(),
            data_home
                .join("nautilus")
                .join("scripts")
                .join("Upload with LinSCP"),
            true,
        ),
        (
            "Nemo (Cinnamon)".to_string(),
            data_home
                .join("nemo")
                .join("actions")
                .join("linscp-upload.nemo_action"),
            false,
        ),
    ])
}

/// Installs opt-in per-user file-manager context-menu actions (`--install-shell-integration`).
pub fn install_shell_integration(
    launcher_path: &Path,
) -> Result<Vec<(String, String, String)>, String> {
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        // Refuse before validating anything: on Android and macOS there is no XDG
        // data directory and no file manager reading these definitions, and an
        // Android build must never create directories inside the app sandbox for a
        // menu that does not exist.
        let _ = launcher_path;
        Err("Shell integration is available on Linux and Windows only.".to_string())
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        install_on_this_platform(launcher_path)
    }
}

/// The install body for the two platforms that have file managers to configure.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn install_on_this_platform(
    launcher_path: &Path,
) -> Result<Vec<(String, String, String)>, String> {
    let exec_path = validate_shell_launcher_path(launcher_path)?;

    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| "APPDATA is not set.".to_string())?;
        let sendto = appdata
            .join("Microsoft")
            .join("Windows")
            .join("SendTo")
            .join("Upload with LinSCP.cmd");
        let existed = sendto.exists();
        if let Some(parent) = sendto.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        // `%*` forwards Explorer's own argument list verbatim, which is the only
        // form that keeps one argument per selected file: wrapping it in quotes
        // (`"%*"`) collapses the whole selection into a single argument, because the
        // C runtime then strips the inner quotes and keeps the separating spaces.
        // `%*` is not perfect - cmd re-reads the line, so an unquoted file name
        // containing `&` would still be split - but it fails only for a name
        // Explorer itself passed unquoted, and it never mangles a normal selection.
        let body = format!("@echo off\r\n\"{exec_path}\" --shell-upload %*\r\n");
        write_private_file_atomic(&sendto, body.as_bytes()).map_err(|e| e.to_string())?;
        Ok(vec![(
            "Windows Explorer (Send To)".to_string(),
            sendto.display().to_string(),
            if existed { "updated" } else { "installed" }.to_string(),
        )])
    }

    #[cfg(target_os = "linux")]
    {
        // The GNOME Files script embeds the path in `sh` single quotes, so a quote
        // in the path is the one thing it cannot carry; everything else is fine.
        if exec_path.contains('\'') {
            return Err(format!(
                "The launcher path '{exec_path}' contains a quote, which a shell script cannot carry."
            ));
        }
        let exec_token = if exec_path.contains(' ') || exec_path.contains('\\') {
            format!("\"{exec_path}\"")
        } else {
            exec_path.clone()
        };
        let dolphin = format!(
            "[Desktop Entry]\nType=Service\nMimeType=all/all;\nActions=LinScpUpload;\nX-KDE-Priority=TopLevel\n\n[Desktop Action LinScpUpload]\nName=Upload with LinSCP\nIcon=linscp\nExec={exec_token} --shell-upload %F\n"
        );
        // GNOME Files hands a script the selection through an environment
        // variable, one path per line; only some versions pass it as arguments. The
        // fallback is therefore the normal path, not an edge case. The whole
        // selection goes to one `--shell-upload` so the window is offered one batch.
        let nautilus_script = format!(
            "#!/bin/sh\n\
# Written by LinSCP. GNOME Files runs this with the selection in\n\
# NAUTILUS_SCRIPT_SELECTED_FILE_PATHS, one path per line.\n\
set -eu\n\
if [ \"$#\" -eq 0 ] && [ -n \"${{NAUTILUS_SCRIPT_SELECTED_FILE_PATHS:-}}\" ]; then\n\
  newline='\n\
'\n\
  old_ifs=$IFS\n\
  IFS=$newline\n\
  set -f\n\
  set --\n\
  for selected in $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS; do\n\
    set -- \"$@\" \"$selected\"\n\
  done\n\
  set +f\n\
  IFS=$old_ifs\n\
fi\n\
if [ \"$#\" -gt 0 ]; then\n\
  exec '{exec_path}' --shell-upload \"$@\"\n\
fi\n\
exit 0\n"
        );
        let nemo = format!(
            "[Nemo Action]\nActive=true\nName=Upload with LinSCP\nComment=Stage selected files for LinSCP Commander\nExec={exec_token} --shell-upload %F\nIcon-Name=linscp\nSelection=notnone\nExtensions=any;\nQuote=double\n"
        );

        let targets = linux_shell_targets()?;
        let bodies = [dolphin, nautilus_script, nemo];
        let mut results = Vec::with_capacity(targets.len());
        for ((manager, path, executable), body) in targets.into_iter().zip(bodies) {
            let existed = path.symlink_metadata().is_ok();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            write_private_file_atomic(&path, body.as_bytes()).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            if executable {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700));
            }
            #[cfg(not(unix))]
            let _ = executable;
            results.push((
                manager,
                path.display().to_string(),
                if existed { "updated" } else { "installed" }.to_string(),
            ));
        }
        Ok(results)
    }
}

/// Removes per-user file-manager context-menu actions (`--uninstall-shell-integration`).
pub fn uninstall_shell_integration() -> Result<Vec<(String, String, String)>, String> {
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err("Shell integration is available on Linux and Windows only.".to_string())
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        uninstall_on_this_platform()
    }
}

/// The uninstall body for the two platforms that can have definitions to remove.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn uninstall_on_this_platform() -> Result<Vec<(String, String, String)>, String> {
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| "APPDATA is not set.".to_string())?;
        let sendto = appdata
            .join("Microsoft")
            .join("Windows")
            .join("SendTo")
            .join("Upload with LinSCP.cmd");
        let outcome = if sendto.exists() {
            std::fs::remove_file(&sendto).map_err(|e| e.to_string())?;
            "removed"
        } else {
            "not installed"
        };
        Ok(vec![(
            "Windows Explorer (Send To)".to_string(),
            sendto.display().to_string(),
            outcome.to_string(),
        )])
    }

    #[cfg(target_os = "linux")]
    {
        let targets = linux_shell_targets()?;
        let mut results = Vec::with_capacity(targets.len());
        for (manager, path, _) in targets {
            let outcome = if path.symlink_metadata().is_ok() {
                std::fs::remove_file(&path).map_err(|e| e.to_string())?;
                "removed"
            } else {
                "not installed"
            };
            results.push((manager, path.display().to_string(), outcome.to_string()));
        }
        Ok(results)
    }
}

/// Move on the same filesystem without replacing an existing destination.
/// Unsupported platforms and cross-filesystem moves fail rather than copying
/// and deleting a potentially changed source.
pub fn rename_no_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in source path"))?;
        let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in destination path"))?;
        // SAFETY: both paths are valid NUL-terminated strings for the duration of the call.
        let result = unsafe { libc::renameat2(libc::AT_FDCWD, source.as_ptr(), libc::AT_FDCWD, destination.as_ptr(), libc::RENAME_NOREPLACE) };
        if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }
    #[cfg(target_os = "android")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in source path"))?;
        let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in destination path"))?;
        // The syscall avoids depending on a newer Android libc symbol. If the
        // kernel or filesystem lacks RENAME_NOREPLACE, fail without replacing.
        // SAFETY: both paths remain valid NUL-terminated strings for the call.
        let result = unsafe { libc::syscall(libc::SYS_renameat2, libc::AT_FDCWD, source.as_ptr(), libc::AT_FDCWD, destination.as_ptr(), libc::RENAME_NOREPLACE) };
        if result == 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
        let source = crate::windows::to_extended_length_path(source);
        let destination = crate::windows::to_extended_length_path(destination);
        let source: Vec<u16> = source.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        let destination: Vec<u16> = destination.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        if source[..source.len() - 1].contains(&0) || destination[..destination.len() - 1].contains(&0) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path"));
        }
        // SAFETY: pointers address NUL-terminated UTF-16 strings; flags=0 forbids replacement and cross-volume copying.
        let result = unsafe { MoveFileExW(source.as_ptr(), destination.as_ptr(), 0) };
        if result != 0 { Ok(()) } else { Err(std::io::Error::last_os_error()) }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
    {
        let _ = (source, destination);
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "Atomic no-replace move is unavailable on this platform"))
    }
}

/// Serialises tests that edit `$XDG_DATA_HOME`.
///
/// Cargo runs a crate's tests as threads in one process, so the environment is
/// shared: two tests installing into different scratch directories at the same time
/// would each see the other's directory. Exposed to the crate's other test modules
/// (see `cli_args`) because they install through the same functions.
#[cfg(all(test, target_os = "linux"))]
pub(crate) fn data_home_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod shell_integration_tests {
    use super::*;

    fn scratch_data_home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("linscp-gui-os-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch data home");
        dir
    }

    /// A launcher path with a space in it is the ordinary case — every install
    /// directory on Windows contains one — and has to reach the definitions intact.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_launcher_path_with_a_space_is_quoted_not_refused() {
        let _guard = data_home_lock();
        let data_home = scratch_data_home("space");
        let previous = std::env::var_os("XDG_DATA_HOME");
        std::env::set_var("XDG_DATA_HOME", &data_home);
        let installed = install_shell_integration(Path::new("/opt/Lin SCP/linscp-gui"));
        match previous {
            Some(value) => std::env::set_var("XDG_DATA_HOME", value),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
        let installed = installed.expect("a space in the path is not an error");
        let dolphin = std::fs::read_to_string(&installed[0].1).expect("Dolphin definition");
        assert!(
            dolphin.contains("Exec=\"/opt/Lin SCP/linscp-gui\" --shell-upload %F"),
            "{dolphin}"
        );
        let _ = std::fs::remove_dir_all(&data_home);
    }

    /// The GNOME Files script is shell code: whatever else changes, it has to be
    /// valid `sh`, and it has to hand the executable the flag the parser knows.
    #[test]
    #[cfg(target_os = "linux")]
    fn the_gnome_files_script_is_a_shell_script_naming_the_upload_flag() {
        let _guard = data_home_lock();
        let data_home = scratch_data_home("nautilus");
        let previous = std::env::var_os("XDG_DATA_HOME");
        std::env::set_var("XDG_DATA_HOME", &data_home);
        let installed = install_shell_integration(Path::new("/opt/linscp/linscp-gui"));
        match previous {
            Some(value) => std::env::set_var("XDG_DATA_HOME", value),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
        let installed = installed.expect("install into the scratch directory");
        let (_, script_path, _) = installed
            .iter()
            .find(|(manager, _, _)| manager.contains("GNOME"))
            .expect("a GNOME Files entry");
        let script = std::fs::read_to_string(script_path).expect("the script");
        assert!(script.starts_with("#!/bin/sh\n"), "{script}");
        assert!(script.contains("--shell-upload \"$@\""), "{script}");
        assert!(
            script.contains("NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"),
            "GNOME Files passes the selection in this variable: {script}"
        );
        // The script is code, so the parser of the shell that will run it decides
        // whether it is valid, not this test. `sh -n` reads it without running it.
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-n")
            .arg(script_path)
            .output()
        {
            assert!(
                output.status.success(),
                "sh -n rejected the generated script: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(script_path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0o100, "the script must be executable");
        }
        let _ = std::fs::remove_dir_all(&data_home);
    }

    /// Refusals have to name the reason, because the launcher path is the only thing
    /// the user could change.
    #[test]
    #[cfg(target_os = "linux")]
    fn a_launcher_path_a_shell_script_cannot_carry_is_refused_by_name() {
        let _guard = data_home_lock();
        let data_home = scratch_data_home("refuse");
        let previous = std::env::var_os("XDG_DATA_HOME");
        std::env::set_var("XDG_DATA_HOME", &data_home);
        let refused = install_shell_integration(Path::new("/opt/lin'scp/linscp-gui"));
        match previous {
            Some(value) => std::env::set_var("XDG_DATA_HOME", value),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
        let message = refused.expect_err("a quote cannot be carried");
        assert!(message.contains("quote"), "{message}");
        assert!(
            std::fs::read_dir(&data_home).map(|mut d| d.next().is_none()).unwrap_or(true),
            "nothing may be written when the path is refused"
        );
        let _ = std::fs::remove_dir_all(&data_home);
    }

    /// Uninstalling must remove what installing wrote and report what it found, so
    /// `--uninstall-shell-integration` is not a silent no-op on a clean machine.
    #[test]
    #[cfg(target_os = "linux")]
    fn uninstalling_reports_every_definition_and_removes_them() {
        let _guard = data_home_lock();
        let data_home = scratch_data_home("uninstall");
        let previous = std::env::var_os("XDG_DATA_HOME");
        std::env::set_var("XDG_DATA_HOME", &data_home);
        let installed = install_shell_integration(Path::new("/opt/linscp/linscp-gui"));
        let removed = uninstall_shell_integration();
        let again = uninstall_shell_integration();
        match previous {
            Some(value) => std::env::set_var("XDG_DATA_HOME", value),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }
        let installed = installed.expect("install");
        let removed = removed.expect("uninstall");
        assert_eq!(installed.len(), removed.len());
        assert_eq!(installed.len(), 3, "Dolphin, GNOME Files and Nemo");
        for (_, path, outcome) in &removed {
            assert_eq!(outcome, "removed", "{path}");
            assert!(!Path::new(path).exists(), "{path} survived the uninstall");
        }
        for (_, _, outcome) in again.expect("a second uninstall still answers") {
            assert_eq!(outcome, "not installed");
        }
        let _ = std::fs::remove_dir_all(&data_home);
    }
}
