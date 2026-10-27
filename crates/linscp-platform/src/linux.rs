//! Linux platform implementation (XDG paths, POSIX root, Wayland + X11 session detection).

use std::path::{Path, PathBuf};

use linscp_types::LocalRootEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxDisplaySession {
    Wayland,
    X11,
    Headless,
}

pub fn default_config_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("LinSCP");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            return PathBuf::from(home).join(".config").join("LinSCP");
        }
    }
    std::env::temp_dir().join("LinSCP")
}

/// Detects the active Linux graphical session, consulting Wayland sockets
/// (`WAYLAND_DISPLAY` and `$XDG_RUNTIME_DIR/wayland-0`) before `$DISPLAY` so
/// pure-Wayland sessions without XWayland are never misclassified as headless.
pub fn detect_display_session() -> LinuxDisplaySession {
    if let Some(wayland) = std::env::var_os("WAYLAND_DISPLAY") {
        if !wayland.is_empty() {
            return LinuxDisplaySession::Wayland;
        }
    }
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !runtime_dir.is_empty() && Path::new(&runtime_dir).join("wayland-0").exists() {
            return LinuxDisplaySession::Wayland;
        }
    }
    if let Some(x11_display) = std::env::var_os("DISPLAY") {
        if !x11_display.is_empty() {
            return LinuxDisplaySession::X11;
        }
    }
    LinuxDisplaySession::Headless
}

pub fn list_roots() -> Vec<LocalRootEntry> {
    let mut roots = vec![LocalRootEntry {
        path: "/".to_string(),
        label: "/".to_string(),
        kind: "posix".to_string(),
        read_only: false,
    }];
    if let Some(home) = std::env::var_os("HOME") {
        let home_str = home.to_string_lossy().into_owned();
        if !home_str.is_empty() && home_str != "/" {
            roots.push(LocalRootEntry {
                path: home_str,
                label: "Home (~)".to_string(),
                kind: "posix".to_string(),
                read_only: false,
            });
        }
    }
    roots
}
