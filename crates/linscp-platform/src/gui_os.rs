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
        let openers: &[(&str, &[&str])] = &[
            ("xdg-open", &[]),
            ("gio", &["open"]),
            ("sensible-browser", &[]),
        ];
        for (prog, prefix_args) in openers {
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

fn validate_shell_launcher_path(launcher: &Path) -> Result<String, String> {
    let text = launcher.to_string_lossy().into_owned();
    if text.is_empty() {
        return Err("Could not locate the LinSCP GUI launcher executable.".to_string());
    }
    if text.chars().any(|c| {
        c.is_control()
            || matches!(
                c,
                '"' | '\'' | '\\' | '`' | '$' | ';' | '&' | '|' | '<' | '>' | '%'
            )
    }) {
        return Err(format!(
            "The launcher path '{text}' contains characters that cannot be carried safely in a desktop action."
        ));
    }
    Ok(text)
}

#[allow(dead_code)]
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
        let body = format!("@echo off\r\n\"{exec_path}\" --shell-upload %*\r\n");
        write_private_file_atomic(&sendto, body.as_bytes()).map_err(|e| e.to_string())?;
        Ok(vec![(
            "Windows Explorer (Send To)".to_string(),
            sendto.display().to_string(),
            if existed { "updated" } else { "installed" }.to_string(),
        )])
    }

    #[cfg(not(target_os = "windows"))]
    {
        let exec_token = if exec_path.contains(' ') {
            format!("\"{exec_path}\"")
        } else {
            exec_path.clone()
        };
        let dolphin = format!(
            "[Desktop Entry]\nType=Service\nMimeType=all/all;\nActions=LinScpUpload;\nX-KDE-Priority=TopLevel\n\n[Desktop Action LinScpUpload]\nName=Upload with LinSCP\nIcon=linscp\nExec={exec_token} --shell-upload %F\n"
        );
        let nautilus = format!(
            "#!/bin/sh\nset -eu\nif [ \"$#\" -gt 0 ]; then\n  exec '{exec_path}' --shell-upload \"$@\"\nfi\nif [ -n \"${{NAUTILUS_SCRIPT_SELECTED_FILE_PATHS:-}}\" ]; then\n  IFS='\n'\n  set -f\n  exec '{exec_path}' --shell-upload $NAUTILUS_SCRIPT_SELECTED_FILE_PATHS\nfi\nexit 0\n"
        );
        let nemo = format!(
            "[Nemo Action]\nActive=true\nName=Upload with LinSCP\nComment=Stage selected files for LinSCP Commander\nExec={exec_token} --shell-upload %F\nIcon-Name=linscp\nSelection=notnone\nExtensions=any;\nQuote=double\n"
        );

        let targets = linux_shell_targets()?;
        let bodies = [dolphin, nautilus, nemo];
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

    #[cfg(not(target_os = "windows"))]
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
