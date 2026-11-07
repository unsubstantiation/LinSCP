//! Remote-desktop viewer launcher — RDP, VNC, SPICE, X2Go/NX and X11/Waypipe.
//!
//! The proto layer (`linscp-proto::remote_desktop`) builds a `DesktopLaunchTicket`
//! with `viewer + argv + file_content`. This module turns that ticket into an
//! actual OS process or a file download, handling:
//!
//! * Whether this host can start a GUI viewer at all — `host_can_spawn_gui_viewer`.
//!   On Linux that follows `linux::detect_desktop_session`; Windows and macOS can
//!   always start one even though neither defines `DISPLAY`; Android never can.
//! * Viewer binary resolution via `$PATH` (`xfreerdp`, `xfreerdp3`, `wlfreerdp`,
//!   `vncviewer`/`tigervnc`, `remote-viewer`/`spicy`, `x2goclient`, `waypipe`, `ssh`)
//! * `mstsc.exe` on Windows (`SystemRoot\System32\mstsc.exe`)
//! * Ticket-file fallback for a host that cannot show a viewer: write `.rdp`/`.vv`
//!   next to `config_dir` and return it so the caller can download or print it.
//!
//! # Who decides between "spawn a viewer" and "write a ticket file"
//!
//! Two different questions were once answered by the same test, which made every
//! Windows launch write a file instead of starting `mstsc.exe`:
//!
//! * *May this process start a GUI viewer?* — a property of the **host**:
//!   `host_can_spawn_gui_viewer`. True on Windows and macOS; on Linux true only
//!   with a live `WAYLAND_DISPLAY`/`DISPLAY`; never on Android (the host is a
//!   phone and the page opens an intent instead).
//! * *Can this client show a file?* — a property of the **transport**, and only
//!   the caller knows it. `launch_remote_desktop`'s `force_file_ticket` carries
//!   the answer and must be set by a headless/browser host; the scripting engine
//!   used to answer the host question itself (from `DISPLAY`) and pass the result
//!   here, which is how a Windows desktop came to be called headless.

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

/// Whether this host can start a GUI viewer process at all.
///
/// This is a property of the *host*, and it used to be answered by an X11 test on
/// every platform: `WAYLAND_DISPLAY`/`DISPLAY` are never set on Windows, so the
/// launcher decided it was headless and wrote a `.rdp` file instead of starting the
/// `System32\\mstsc.exe` it had just resolved. Only Linux can answer this from the
/// environment it inherits:
///
/// * **Linux** — `linux::detect_desktop_session`: a live Wayland or X11 session
///   means a viewer can be shown; without one the box is headless, and a session
///   over SSH is exactly the case a ticket file exists for.
/// * **Windows / macOS** — always yes: a process with a window station can start
///   `mstsc.exe` / `open`, and neither platform defines `DISPLAY`.
/// * **Android** (and any other target) — always no: there is no viewer binary to
///   start, and the page answers with a `rdp://`-style intent instead
///   (`source/gui/web/index.html`, `caps.platform === 'android'`).
pub fn host_can_spawn_gui_viewer() -> bool {
    #[cfg(target_os = "linux")]
    {
        crate::linux::detect_desktop_session() != crate::linux::DesktopSessionKind::Headless
    }
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    {
        true
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        false
    }
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
            // Wayland needs `waypipe`; on Windows/macOS/Android the session is not a
            // Linux one, so the `ssh -X` fallback below is the only answer.
            #[cfg(target_os = "linux")]
            let wayland = crate::linux::detect_desktop_session()
                == crate::linux::DesktopSessionKind::Wayland;
            #[cfg(not(target_os = "linux"))]
            let wayland = false;
            if wayland {
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

/// What `launch_remote_desktop` is about to do, decided without touching the
/// filesystem or starting a process so the rule is testable on any target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchPlan {
    /// Start the resolved viewer binary.
    Spawn,
    /// Write `.rdp`/`.vv` content under the config directory.
    WriteFile,
    /// Hand the client a hint (HTML5 gateway / copyable command line).
    Gateway,
}

/// Picks the outcome from three facts: may this host start a GUI viewer, is there
/// a viewer binary to start, and does the ticket carry file content.
///
/// The important property — the one A1 violated on Windows — is that
/// "this host can show a window" outranks "the ticket has a `.rdp` body". A
/// Windows install always has `mstsc.exe`, so it must spawn and never fall back to
/// writing a file just because `DISPLAY` is unset.
pub fn plan_launch(ticket: &DesktopTicket, spawn_allowed: bool, viewer_resolved: bool) -> LaunchPlan {
    if spawn_allowed && viewer_resolved {
        LaunchPlan::Spawn
    } else if ticket.file_content.is_some() {
        LaunchPlan::WriteFile
    } else {
        LaunchPlan::Gateway
    }
}

/// Launches `ticket`'s viewer in the current desktop session, or in headless/HTTP mode
/// writes a `.rdp`/`.vv` ticket file under `config_dir` and returns `FileTicket` so the
/// caller can emit a download or a WebSocket gateway URL.
///
/// When `force_file_ticket` is `true` — the caller cannot show a window (the browser
/// server, a server-mode script run) — we never spawn a local viewer even if this host
/// has one in `$PATH`; the caller gets the `.rdp`/`.vv` body or a gateway hint.
///
/// Whether *this host* can show a window is decided here by
/// `host_can_spawn_gui_viewer`, not by the caller: a caller that guesses from
/// `DISPLAY` (as the scripting engine did) declares every Windows launch headless.
pub fn launch_remote_desktop(
    ticket: &DesktopTicket,
    config_dir: &Path,
    force_file_ticket: bool,
) -> Result<DesktopLaunchResult, String> {
    let viewer_bin = resolve_viewer_binary(ticket);
    let spawn_allowed = !force_file_ticket && host_can_spawn_gui_viewer();
    let plan = plan_launch(ticket, spawn_allowed, viewer_bin.is_some());

    if plan == LaunchPlan::WriteFile {
        let content = ticket
            .file_content
            .as_deref()
            .ok_or_else(|| format!("No file content for a {} ticket", ticket.kind))?;
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

    // Nothing to start and nothing to write: describe the endpoint instead. A file
    // body would have gone to `WriteFile`; this branch only carries a hint.
    if plan == LaunchPlan::Gateway {
        let reason = if viewer_bin.is_some() {
            format!(
                "this host cannot open a window; open it with a local {} client or an HTML5 gateway",
                ticket.kind.to_uppercase()
            )
        } else {
            format!(
                "no {} viewer on this host; open it with a local {} client or an HTML5 gateway",
                ticket.viewer,
                ticket.kind.to_uppercase()
            )
        };
        return Ok(DesktopLaunchResult::BrowserGateway {
            url_hint: format!("{}://{} ({reason})", ticket.kind, ticket.local_endpoint),
        });
    }

    // `plan_launch` returns `Spawn` only when a viewer was resolved, so this is the
    // "spawn" path and the binary is present.
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

    // `open` must not be handed the FreeRDP flag list. A ticket built on macOS
    // already carries `open rdp://…`; this only repairs a ticket that came from
    // elsewhere (a stored session written on another platform).
    #[cfg(target_os = "macos")]
    if bin.file_name().and_then(|n| n.to_str()) == Some("open")
        && argv.iter().skip(1).any(|arg| arg.starts_with('/'))
    {
        argv.truncate(1);
        argv.push(format!("{}://{}", ticket.kind, ticket.local_endpoint));
    }

    // Detach from the LinSCP process so the viewer outlives it.
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

    fn rdp_ticket(file_content: Option<&str>) -> DesktopTicket {
        DesktopTicket {
            kind: "rdp".to_string(),
            target: "win.example.com:3389".to_string(),
            viewer: "mstsc".to_string(),
            argv: vec!["mstsc".to_string(), "/v:win.example.com:3389".to_string()],
            file_content: file_content.map(|s| s.to_string()),
            file_extension: Some(".rdp".to_string()),
            tunneled: false,
            local_endpoint: "win.example.com:3389".to_string(),
        }
    }

    /// A1: on a host that can show a window, an `.rdp` body in the ticket must not
    /// turn the launch into a file. This is exactly the Windows case: `mstsc.exe`
    /// resolves, `DISPLAY` never exists, and the old code wrote a ticket file.
    #[test]
    fn resolved_viewer_wins_over_file_content() {
        let ticket = rdp_ticket(Some("full address:s:win.example.com:3389\r\n"));
        assert_eq!(plan_launch(&ticket, true, true), LaunchPlan::Spawn);
        // The same ticket on a host that cannot show a window still writes the file,
        // so the Windows fix does not take the headless path away from the browser.
        assert_eq!(plan_launch(&ticket, false, true), LaunchPlan::WriteFile);
    }

    /// A caller that cannot show a window (headless host, `Prefer: file`) still gets
    /// the file — the A1 fix must not remove the headless path.
    #[test]
    fn forced_file_ticket_still_writes_the_file() {
        let ticket = rdp_ticket(Some("full address:s:win.example.com:3389\r\n"));
        assert_eq!(plan_launch(&ticket, false, true), LaunchPlan::WriteFile);
        // No viewer installed but file content present: writing a file is the
        // best available outcome, on every platform.
        assert_eq!(plan_launch(&ticket, true, false), LaunchPlan::WriteFile);
    }

    /// Nothing to spawn and nothing to write: hand the client a hint rather than
    /// pretending to have launched anything.
    #[test]
    fn no_viewer_and_no_content_yields_a_gateway() {
        let ticket = rdp_ticket(None);
        assert_eq!(plan_launch(&ticket, true, false), LaunchPlan::Gateway);
        assert_eq!(plan_launch(&ticket, false, false), LaunchPlan::Gateway);
    }

    /// Windows and macOS are never headless: the process owns a window station even
    /// though neither platform defines `DISPLAY`/`WAYLAND_DISPLAY`. On Linux the
    /// answer still follows the environment, so a CI container stays headless.
    #[test]
    fn host_gui_capability_matches_the_platform() {
        if cfg!(target_os = "windows") || cfg!(target_os = "macos") {
            assert!(host_can_spawn_gui_viewer(), "a desktop target must be able to open a viewer");
        }
        if cfg!(target_os = "linux") {
            // The same three variables `linux::detect_desktop_session` reads.
            let has_display = std::env::var_os("WAYLAND_DISPLAY").filter(|v| !v.is_empty()).is_some()
                || std::env::var("XDG_SESSION_TYPE")
                    .map(|v| v.eq_ignore_ascii_case("wayland"))
                    .unwrap_or(false)
                || std::env::var_os("DISPLAY").filter(|v| !v.is_empty()).is_some();
            assert_eq!(host_can_spawn_gui_viewer(), has_display);
        }
    }

    #[test]
    fn recommendations_mention_all_protocols() {
        let rec = desktop_recommendations();
        for proto in ["RDP", "VNC", "SPICE", "X2Go", "X11", "XDMCP", "ironrdp"] {
            assert!(rec.contains(proto), "missing {proto}");
        }
    }
}
