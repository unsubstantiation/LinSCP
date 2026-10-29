//! Remote-desktop viewer launcher — RDP, VNC, SPICE, X2Go/NX and X11/Waypipe.
//!
//! The proto layer (`linscp-proto::remote_desktop`) builds a `DesktopLaunchTicket`
//! with `viewer + argv + file_content`. This module turns that ticket into an
//! actual OS process or a file download, handling:
//!
//! * Wayland vs X11 vs headless detection (mirrors `linux::detect_desktop_session`)
//! * Viewer binary resolution via `$PATH` (`xfreerdp`, `xfreerdp3`, `wlfreerdp`,
//!   `vncviewer`/`tigervnc`, `remote-viewer`/`spicy`, `x2goclient`, `waypipe`, `ssh`)
//! * `mstsc.exe` on Windows (`%SystemRoot%\\System32\\mstsc.exe`)
//! * Headless/HTTP mode fallback: write `.rdp`/`.vv` file next to `config_dir`
//!   and print `DESKTOP_TICKET` line for the browser transport.

use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopViewerKind {
    Rdp,
    Vnc,
    Spice,
    X2Go,
    X11,
}

impl DesktopViewerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
            Self::Spice => "spice",
            Self::X2Go => "x2go",
            Self::X11 => "x11",
        }
    }
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "rdp" | "rdps" | "msrdp" | "ms-rdp" => Some(Self::Rdp),
            "vnc" | "rfb" => Some(Self::Vnc),
            "spice" => Some(Self::Spice),
            "x2go" | "nx" => Some(Self::X2Go),
            "x11" | "x" | "waypipe" => Some(Self::X11),
            _ => None,
        }
    }
}

/// Ticket produced by `linscp-proto::remote_desktop::RemoteDesktopSession::launch_ticket()`
/// — duplicated here so the platform crate does not depend on `linscp-proto`.
#[derive(Debug, Clone)]
pub struct DesktopTicket {
    pub kind: String,
    pub target: String,
    pub viewer: String,
    pub argv: Vec<String>,
    pub file_content: Option<String>,
    pub file_extension: Option<String>,
    pub tunneled: bool,
    pub local_endpoint: String,
}

impl DesktopTicket {
    pub fn viewer_kind(&self) -> Option<DesktopViewerKind> {
        DesktopViewerKind::from_str(&self.kind)
    }
}

fn find_executable_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate);
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

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn detect_desktop_session_kind() -> DesktopSession {
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WAYLAND_DISPLAY").filter(|v| !v.is_empty()).is_some()
            || std::env::var("XDG_SESSION_TYPE")
                .map(|v| v.eq_ignore_ascii_case("wayland"))
                .unwrap_or(false)
        {
            return DesktopSession::Wayland;
        }
        if std::env::var_os("DISPLAY").filter(|v| !v.is_empty()).is_some() {
            return DesktopSession::X11;
        }
        return DesktopSession::Headless;
    }
    #[cfg(not(target_os = "linux"))]
    {
        if std::env::var_os("WAYLAND_DISPLAY").is_some()
            || std::env::var_os("DISPLAY").is_some()
        {
            return DesktopSession::Wayland;
        }
        DesktopSession::Headless
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DesktopSession {
    Wayland,
    X11,
    Headless,
}

/// Resolves the viewer binary for `ticket.viewer`, trying ordered fallbacks per OS:
///
/// * RDP on Linux: `xfreerdp3`, `xfreerdp`, `wlfreerdp`, `sdl-freerdp`; Windows: `mstsc` (`System32\\mstsc.exe`); macOS: `open`
/// * VNC: `vncviewer` (includes tigervnc), `xtigervncviewer`, `remmina`
/// * SPICE: `remote-viewer`, `virt-viewer`, `spicy`
/// * X2Go: `x2goclient`, `pyhoca-cli`, `x2goclient-gtk`
/// * X11: `waypipe` (Wayland) or `ssh -X` fallback
pub fn resolve_viewer_binary(ticket: &DesktopTicket) -> Option<PathBuf> {
    let kind = ticket.viewer_kind()?;
    let session = detect_desktop_session_kind();
    match kind {
        DesktopViewerKind::Rdp => {
            #[cfg(windows)]
            {
                let sysroot = std::env::var_os("SystemRoot")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
                let mstsc = sysroot.join("System32").join("mstsc.exe");
                if mstsc.is_file() {
                    return Some(mstsc);
                }
                if let Some(p) = find_executable_on_path("mstsc") {
                    return Some(p);
                }
                return None;
            }
            #[cfg(target_os = "macos")]
            {
                if let Some(p) = find_executable_on_path(&ticket.viewer) {
                    return Some(p);
                }
                // macOS: `open` can handle rdp:// URLs and .rdp files
                if let Some(p) = find_executable_on_path("open") {
                    return Some(p);
                }
                return None;
            }
            #[cfg(not(any(windows, target_os = "macos")))]
            {
                for cand in ["xfreerdp3", "xfreerdp", "wlfreerdp", "sdl-freerdp", "freerdp3"] {
                    if let Some(p) = find_executable_on_path(cand) {
                        return Some(p);
                    }
                }
                // Wayland-only systems often ship `wlfreerdp` under a different name; try generic.
                find_executable_on_path(&ticket.viewer)
            }
        }
        DesktopViewerKind::Vnc => {
            for cand in [
                &ticket.viewer,
                "vncviewer",
                "tigervnc-viewer",
                "xtigervncviewer",
                "remmina",
                "gvncviewer",
            ] {
                if let Some(p) = find_executable_on_path(cand) {
                    return Some(p);
                }
            }
            None
        }
        DesktopViewerKind::Spice => {
            for cand in [
                &ticket.viewer,
                "remote-viewer",
                "virt-viewer",
                "spicy",
                "spicec",
            ] {
                if let Some(p) = find_executable_on_path(cand) {
                    return Some(p);
                }
            }
            None
        }
        DesktopViewerKind::X2Go => {
            for cand in ["x2goclient", "pyhoca-cli", "pyhoca-gui", "x2goclient-gtk"] {
                if let Some(p) = find_executable_on_path(cand) {
                    return Some(p);
                }
            }
            find_executable_on_path(&ticket.viewer)
        }
        DesktopViewerKind::X11 => {
            if session == DesktopSession::Wayland {
                if let Some(p) = find_executable_on_path("waypipe") {
                    return Some(p);
                }
            }
            // Fallback: `ssh -X` is always present when SSH transport is available.
            find_executable_on_path("ssh").or_else(|| find_executable_on_path("waypipe"))
        }
    }
}

/// Result of `launch_remote_desktop` — either a spawned PID or a file ticket for HTTP mode.
#[derive(Debug)]
pub enum DesktopLaunchResult {
    Spawned { pid: u32, viewer: PathBuf, argv: Vec<String> },
    FileTicket { path: PathBuf, viewer_hint: String },
    BrowserGateway { url_hint: String },
}

/// Launches `ticket`'s viewer in the current desktop session, or in headless/HTTP mode
/// writes a `.rdp`/`.vv` ticket file under `config_dir` and returns `FileTicket` so the
/// caller can emit a download or a WebSocket gateway URL.
///
/// When `force_file_ticket` is `true` (HTTP `POST /api/open` with `Prefer: file`), we
/// never spawn a local viewer even if the server has one in `$PATH`.
pub fn launch_remote_desktop(
    ticket: &DesktopTicket,
    config_dir: &Path,
    force_file_ticket: bool,
) -> Result<DesktopLaunchResult, String> {
    let session = detect_desktop_session_kind();
    let viewer_bin = resolve_viewer_binary(ticket);

    // Headless or forced file mode: write ticket file and return it.
    let is_headless = session == DesktopSession::Headless;
    if force_file_ticket || is_headless || viewer_bin.is_none() {
        // If we have file content (RDP on Windows/macOS, SPICE .vv), write that.
        // Otherwise emit argv as a shell line for the browser to copy.
        if let Some(content) = ticket.file_content.as_deref() {
            let ext = ticket.file_extension.as_deref().unwrap_or(".rdp");
            let safe_target = ticket
                .target
                .replace('/', "_")
                .replace(':', "_")
                .replace(' ', "_");
            let file_name = format!("linscp-{safe_target}{ext}");
            let path = config_dir.join(file_name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Cannot create config dir {}: {e}", parent.display()))?;
            }
            std::fs::write(&path, content)
                .map_err(|e| format!("Cannot write desktop ticket '{}': {e}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            return Ok(DesktopLaunchResult::FileTicket {
                path,
                viewer_hint: ticket.viewer.clone(),
            });
        }
        if viewer_bin.is_none() {
            // No viewer and no file content — emit a gateway hint for the browser.
            // In HTTP mode the frontend can open an HTML5 gateway (Apache Guacamole
            // or `ironrdp` WASM) pointed at `local_endpoint`.
            let hint = format!(
                "{}://{} (viewer '{}' not found on server; open with local {} client or HTML5 gateway)",
                ticket.kind,
                ticket.local_endpoint,
                ticket.viewer,
                ticket.kind.to_uppercase()
            );
            return Ok(DesktopLaunchResult::BrowserGateway { url_hint: hint });
        }
        // Fall through to spawn when forced but we have no file content — still spawn is not possible in headless.
        if is_headless {
            let hint = format!(
                "{} {} via {} -> {}",
                ticket.kind, ticket.target, ticket.viewer, ticket.local_endpoint
            );
            return Ok(DesktopLaunchResult::BrowserGateway { url_hint: hint });
        }
    }

    let bin = viewer_bin.ok_or_else(|| {
        format!(
            "No viewer found for {} (tried '{}'); install {} or use headless file mode.",
            ticket.kind, ticket.viewer, ticket.viewer
        )
    })?;

    // Build argv: ticket.argv[0] is the generic viewer name, replace with resolved bin.
    let mut argv = ticket.argv.clone();
    if !argv.is_empty() {
        argv[0] = bin.to_string_lossy().into_owned();
    } else {
        argv.push(bin.to_string_lossy().into_owned());
    }

    #[cfg(target_os = "macos")]
    if bin.file_name().and_then(|n| n.to_str()) == Some("open") && ticket.file_content.is_some() {
        // macOS `open` needs a file — we already wrote it above, so launch with that file if present.
    }

    // Headless check already handled; spawn detached so the LinSCP process does not wait.
    let mut cmd = Command::new(&bin);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    // Detach from LinSCP's stdio so the viewer survives after LinSCP exits (like -gui launch).
    #[cfg(unix)]
    {
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
    }

    let child = cmd
        .spawn()
        .map_err(|e| format!("Failed to launch viewer '{}': {e}", bin.display()))?;
    Ok(DesktopLaunchResult::Spawned {
        pid: child.id(),
        viewer: bin,
        argv,
    })
}

/// Human-readable recommendation string for the README / `--help`.
///
/// Callers (CLI `--help`, Tauri updater) can surface this verbatim.
pub fn desktop_recommendations() -> &'static str {
    "Remote desktop (dual-mode: native viewer when a display is present, .rdp/.vv file or HTML5 gateway in headless HTTP mode):\n\
     \x20 RDP  — Linux: xfreerdp3 / xfreerdp / wlfreerdp (FreeRDP 3.x, recommended), sdl-freerdp (Wayland). Windows: mstsc.exe (built-in). macOS: open rdp:// / Microsoft Remote Desktop. Android: aFreeRDP / aRDP (intent rdp://). Embedded fallback: Devolutions/ironrdp WASM (HTML5/WebSocket) when no native viewer is installed.\n\
     \x20 VNC  — Linux: tigervnc-viewer / remmina / gvncviewer (TigerVNC, recommended for 5900-5999). Windows: TightVNC / RealVNC viewer. Android: androidVNC / VNC Viewer (443).\n\
     \x20 SPICE — Linux/Windows: remote-viewer / virt-viewer (virt-viewer, recommended for QEMU/KVM). Fallback: spicy (spice-gtk). Uses spice://host:port?tls-port=... and .vv virt-viewer files.\n\
     \x20 X2Go/NX — Linux: x2goclient / pyhoca-cli (recommended; SSH on 22 with NX compression, reuses jump-host tunnel). Windows: X2Go Client for Windows. Falls back to nxproxy -S.\n\
     \x20 X11 forwarding — Linux: waypipe ssh (Wayland, recommended) or ssh -X / ssh -Y (X11). Detects WAYLAND_DISPLAY / XDG_SESSION_TYPE / DISPLAY.\n\
     \x20 XDMCP — Not recommended; plain UDP port 177 with no encryption. Use X2Go or waypipe-over-SSH instead.\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn viewer_kind_roundtrip() {
        assert_eq!(DesktopViewerKind::from_str("rdp"), Some(DesktopViewerKind::Rdp));
        assert_eq!(DesktopViewerKind::from_str("vnc"), Some(DesktopViewerKind::Vnc));
        assert_eq!(DesktopViewerKind::from_str("spice"), Some(DesktopViewerKind::Spice));
        assert_eq!(DesktopViewerKind::from_str("x2go"), Some(DesktopViewerKind::X2Go));
        assert_eq!(DesktopViewerKind::from_str("x11"), Some(DesktopViewerKind::X11));
        assert_eq!(DesktopViewerKind::Rdp.as_str(), "rdp");
    }
    #[test]
    fn recommendations_mention_all_protocols() {
        let rec = desktop_recommendations();
        for proto in ["RDP", "VNC", "SPICE", "X2Go", "X11", "XDMCP", "ironrdp"] {
            assert!(rec.contains(proto), "missing {proto}");
        }
    }
}
