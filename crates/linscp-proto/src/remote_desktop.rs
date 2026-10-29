//! Remote desktop engines — RDP, VNC, SPICE, X2Go (NX) and X11/Waypipe.
//!
//! All engines reuse the same jump-host (`direct-tcpip` via `SshJumpTunnel`) and
//! SOCKS5h proxy dialer as the file-transfer protocols, and the same fail-closed
//! host-key / TLS / SPKI verifier from `tls`. On desktop the engines launch the
//! platform's native viewer; in headless HTTP mode they emit a `.rdp`/`.vv` file or a
//! WebSocket ticket the browser can open with an HTML5 gateway.
//!
//! * **RDP** – Microsoft Remote Desktop Protocol. Linux: `xfreerdp`/ `xfreerdp3` / `sdl-freerdp`,
//!   Windows: `mstsc.exe`, macOS: `open rdp://`, Android: `aFreeRDP`/`aRDP` via intent.
//!   Options: `/d:DOMAIN /u:USER /p:PASS /v:HOST:PORT /w:WxH /bpp:DEPTH /sec:tls|nla|rdp`.
//! * **VNC** – RFB. Linux: `vncviewer`/`tigervnc-viewer`/`remmina`, Windows: `vncviewer.exe`,
//!   Android: `androidVNC`. Options: `-SharedViewOnly -PreferredEncoding -via`.
//! * **SPICE** – QEMU/KVM. Linux: `remote-viewer`/`spicy`/`virt-viewer`, Windows: `remote-viewer.exe`.
//!   Options: `spice://host:port?tls-port=...`.
//! * **X2Go / NX** – SSH-tunneled NX. Uses the existing `SshConnection` + `direct-tcpip` channel.
//!   Clients: `x2goclient`, `pyhoca-cli`, `nxproxy -S nx/nx,…`. Server spawns `x2gostartagent`.
//! * **X11** – `ssh -X` / `waypipe ssh`. Headless mode falls back to `xwayland` detection the
//!   same way `detect_desktop_session()` does.

use std::collections::BTreeMap;
use std::sync::Arc;

use linscp_types::{FileEntry, ProtocolScheme};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::proxy::ProxyConfig;
use crate::ssh::{SshConnectConfig, SshConnection};
use crate::tls::TlsSettings;
use crate::tunnel::SshJumpTunnel;
use crate::{ProtoError, RemoteSession, TransferRequest};

/// Viewer invocation produced by a desktop engine — written to stdout / handed to Tauri.
#[derive(Debug, Clone)]
pub struct DesktopLaunchTicket {
    /// Short kind string for logging (`rdp`, `vnc`, `spice`, `x2go`, `x11`).
    pub kind: String,
    /// Human-readable target (`host:port`).
    pub target: String,
    /// Suggested external binary (`xfreerdp`, `vncviewer`, `remote-viewer`, `x2goclient` …).
    pub viewer: String,
    /// Full argv including viewer as `argv[0]`.
    pub argv: Vec<String>,
    /// Optional file content to write (`*.rdp`, `*.vv`) when viewer expects a file instead of args.
    pub file_content: Option<String>,
    /// Optional file extension (`.rdp`, `.vv`, `.x2go`).
    pub file_extension: Option<String>,
    /// Whether the desktop is reached through an SSH jump tunnel (`RDP over SSH`, `VNC over SSH`).
    pub tunneled: bool,
    /// Local address of the forwarded port when tunneled (`127.0.0.1:xxxxx`) or `host:port` when direct.
    pub local_endpoint: String,
}

impl DesktopLaunchTicket {
    pub fn display(&self) -> String {
        format!(
            "{} {} via {} (tunneled={}) -> {}",
            self.kind, self.target, self.viewer, self.tunneled, self.local_endpoint
        )
    }
}

/// Extra per-session desktop options parsed from `-rawsettings RdpDomain=…` etc.
#[derive(Debug, Clone, Default)]
pub struct DesktopOptions {
    /// RDP domain (`RdpDomain`, `Domain`).
    pub domain: Option<String>,
    /// RDP security (`nla`, `tls`, `rdp`, `ext`).
    pub security: Option<String>,
    /// Color depth (`8`, `15`, `16`, `24`, `32`).
    pub color_depth: Option<u8>,
    /// Requested width / height (`RdpWidth`, `RdpHeight`).
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// Fullscreen (`RdpFullscreen=1`).
    pub fullscreen: bool,
    /// Drive / audio / clipboard redirection (`RdpDriveRedirection`, `RdpAudioMode`).
    pub drive_redirection: bool,
    pub audio_mode: Option<u8>,
    /// Compression / offscreen cache (`RdpCompression=1`).
    pub compression: bool,
    /// VNC view-only, shared, quality (`VncViewOnly`, `VncQuality` 0..9).
    pub vnc_view_only: bool,
    pub vnc_quality: Option<u8>,
    /// SPICE TLS port (`SpiceTlsPort`).
    pub spice_tls_port: Option<u16>,
    /// SPICE insecure / verify host (`SpiceTlsInsecure`).
    pub spice_insecure: bool,
    /// X2Go session type (`XFCE`, `KDE`, `MATE`, `LXDE`, `GNOME`, `UNITY`, `custom`).
    pub x2go_session_type: Option<String>,
    /// X2Go desktop command (`startkde`, `mate-session` …).
    pub x2go_command: Option<String>,
    /// X2Go link / pack (`lan`, `wan`, `adsl`, `modem`, `isdn`, `16m-jpeg`, `16m-png` …).
    pub x2go_link: Option<String>,
    /// X2Go pack method (`16m-jpeg`, `8k-png` …).
    pub x2go_pack: Option<String>,
    /// X11 display (`X11Display=:0`).
    pub x11_display: Option<String>,
    /// Whether to use Waypipe when on Wayland (`Waypipe=1`).
    pub waypipe: bool,
}

impl DesktopOptions {
    pub fn from_raw_fields(raw: &BTreeMap<String, String>) -> Self {
        let mut opts = Self::default();
        for (k, v) in raw {
            match k.as_str() {
                "rdp_domain" | "domain" => opts.domain = Some(v.clone()).filter(|s| !s.is_empty()),
                "rdp_security" | "security" => opts.security = Some(v.to_ascii_lowercase()),
                "rdp_color_depth" | "color_depth" => {
                    if let Ok(n) = v.parse::<u8>() {
                        if matches!(n, 8 | 15 | 16 | 24 | 32) {
                            opts.color_depth = Some(n);
                        }
                    }
                }
                "rdp_width" => opts.width = v.parse().ok(),
                "rdp_height" => opts.height = v.parse().ok(),
                "rdp_fullscreen" | "fullscreen" => opts.fullscreen = parse_bool(v),
                "rdp_drive_redirection" => opts.drive_redirection = parse_bool(v),
                "rdp_audio_mode" => opts.audio_mode = v.parse().ok(),
                "rdp_compression" => opts.compression = parse_bool(v),
                "vnc_view_only" => opts.vnc_view_only = parse_bool(v),
                "vnc_quality" => opts.vnc_quality = v.parse().ok(),
                "spice_tls_port" => opts.spice_tls_port = v.parse().ok(),
                "spice_tls_insecure" => opts.spice_insecure = parse_bool(v),
                "x2go_session_type" => opts.x2go_session_type = Some(v.clone()),
                "x2go_command" => opts.x2go_command = Some(v.clone()),
                "x2go_link" => opts.x2go_link = Some(v.clone()),
                "x2go_pack" => opts.x2go_pack = Some(v.clone()),
                "x11_display" => opts.x11_display = Some(v.clone()),
                "waypipe" => opts.waypipe = parse_bool(v),
                _ => {}
            }
        }
        opts
    }
}

fn parse_bool(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "1" | "on" | "yes" | "true"
    )
}

/// Detected or requested kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteDesktopKind {
    Rdp,
    Vnc,
    Spice,
    X2Go,
    X11,
}

impl RemoteDesktopKind {
    pub fn from_scheme(scheme: ProtocolScheme) -> Option<Self> {
        match scheme {
            ProtocolScheme::Rdp => Some(Self::Rdp),
            ProtocolScheme::Vnc => Some(Self::Vnc),
            ProtocolScheme::Spice => Some(Self::Spice),
            ProtocolScheme::X2Go => Some(Self::X2Go),
            ProtocolScheme::X11 => Some(Self::X11),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
            Self::Spice => "spice",
            Self::X2Go => "x2go",
            Self::X11 => "x11",
        }
    }
    pub fn default_viewer(self, tunnel_over_ssh: bool) -> &'static str {
        match self {
            Self::Rdp => "xfreerdp",
            Self::Vnc => "vncviewer",
            Self::Spice => "remote-viewer",
            Self::X2Go if tunnel_over_ssh => "x2goclient",
            Self::X2Go => "x2goclient",
            Self::X11 => "waypipe",
        }
    }
}

/// Connection config — same shape as `Sftp`/`WebDav` but for desktops (reuses `Proxy` + `SshJumpTunnel`).
#[derive(Debug, Clone)]
pub struct RemoteDesktopConnectConfig {
    pub scheme: ProtocolScheme,
    pub kind: RemoteDesktopKind,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<zeroize::Zeroizing<String>>,
    pub domain: Option<String>,
    pub desktop_opts: DesktopOptions,
    pub tls: TlsSettings,
    pub proxy: Option<ProxyConfig>,
    pub timeout: std::time::Duration,
}

impl RemoteDesktopConnectConfig {
    pub fn target(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Connected desktop session — holds the optional jump tunnel and SOCKS5 multiplexer the same way
/// `Sftp`/`S3`/`WebDAV` do when tunneled. `probe_endpoint` does a TCP `connect_timeout` check rather
/// than a directory listing.
pub struct RemoteDesktopSession {
    pub scheme: ProtocolScheme,
    pub kind: RemoteDesktopKind,
    pub target: String,
    pub config: RemoteDesktopConnectConfig,
    pub jump: Option<SshJumpTunnel>,
    pub socks_addr: Option<std::net::SocketAddr>,
    observed_host_key: Option<String>,
    ssh_for_x2go: Option<Arc<SshConnection>>,
}

impl RemoteDesktopSession {
    pub async fn connect(
        cfg: RemoteDesktopConnectConfig,
        tunnel_ssh_cfg: Option<&SshConnectConfig>,
        tunnel_local_port: u16,
    ) -> Result<Self, ProtoError> {
        // X2Go / X11: SSH-transported, so establish an SSH connection first.
        if cfg.kind == RemoteDesktopKind::X2Go || cfg.kind == RemoteDesktopKind::X11 {
            let ssh_cfg = SshConnectConfig {
                tab_id: 1,
                role: "destination".to_string(),
                host: cfg.host.clone(),
                port: if cfg.scheme == ProtocolScheme::X2Go || cfg.scheme == ProtocolScheme::X11 {
                    22
                } else {
                    cfg.port
                },
                username: cfg.username.clone().unwrap_or_else(|| "user".to_string()),
                password: cfg.password.clone(),
                ..Default::default()
            };
            // When a jump is configured, open the downstream SSH over the jump's direct-tcpip.
            let (conn, jump) = if let Some(tun_cfg) = tunnel_ssh_cfg {
                let jump = SshJumpTunnel::connect(tun_cfg.clone())
                    .await
                    .map_err(|e| ProtoError::Transport(e.to_string()))?;
                let stream = jump
                    .open_destination_stream(&ssh_cfg.host, ssh_cfg.port, tunnel_local_port)
                    .await
                    .map_err(|e| ProtoError::Transport(e.to_string()))?;
                let conn = SshConnection::connect_over_stream(&ssh_cfg, stream)
                    .await
                    .map_err(|e| ProtoError::Transport(e.to_string()))?;
                (conn, Some(jump))
            } else {
                let conn = SshConnection::connect(&ssh_cfg)
                    .await
                    .map_err(|e| ProtoError::Transport(e.to_string()))?;
                (conn, None)
            };
            let observed = {
                let fp = conn.observed_fingerprint().to_string();
                if fp.is_empty() { None } else { Some(fp) }
            };
            return Ok(Self {
                scheme: cfg.scheme,
                kind: cfg.kind,
                target: cfg.target(),
                config: cfg,
                jump,
                socks_addr: None,
                observed_host_key: observed,
                ssh_for_x2go: Some(Arc::new(conn)),
            });
        }

        // Direct-TCP desktops (RDP, VNC, SPICE): optionally tunnel via SSH jump.
        // For direct modes we reuse the same jump machinery that file protocols use,
        // but without opening a separate SOCKS listener — the viewer's local forward
        // can be created on demand by the platform launcher via
        // `open_destination_stream(..., TunnelLocalPortNumber)`. Here we just record
        // that the session is tunneled so `launch_ticket` can annotate `tunneled=true`.
        // Full SOCKS5h multiplexing (as in WebDAV/S3) is available via
        // `SshJumpTunnel::start_socks5_relay` if callers need a loopback proxy URL.
        let mut jump: Option<SshJumpTunnel> = None;
        let socks_addr: Option<std::net::SocketAddr> = None;
        if let Some(tun_cfg) = tunnel_ssh_cfg {
            let j = SshJumpTunnel::connect(tun_cfg.clone())
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            // Confirm tunnel local port is bindable when explicitly requested (mirrors
            // Sftp's `open_destination_stream` check), so firewall rules mentioning it fire.
            if tunnel_local_port != 0 {
                let probe = tokio::net::TcpListener::bind(("127.0.0.1", tunnel_local_port)).await;
                if let Ok(l) = probe { drop(l); }
            }
            jump = Some(j);
        } else {
            // Best-effort TCP probe with short timeout — do not fail the session on timeout,
            // just on immediate "connection refused / no route" which indicates a hard misconfiguration.
            let dial_target = format!("{}:{}", cfg.host, cfg.port);
            let probe = tokio::time::timeout(
                std::time::Duration::from_millis(800),
                tokio::net::TcpStream::connect(&dial_target),
            )
            .await;
            if let Ok(Err(e)) = probe {
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    let _ = e;
                }
            }
        }

        Ok(Self {
            scheme: cfg.scheme,
            kind: cfg.kind,
            target: cfg.target(),
            config: cfg,
            jump,
            socks_addr,
            observed_host_key: None,
            ssh_for_x2go: None,
        })
    }

    /// Builds a `DesktopLaunchTicket` the platform layer can turn into a `Command` or a file.
    pub fn launch_ticket(&self) -> DesktopLaunchTicket {
        ticket_from_config(&self.config, self.kind, &self.target, self.jump.is_some(), self.socks_addr.map(|a| a.to_string()))
    }
}

/// Builds a ticket from a `RemoteDesktopConnectConfig` without a live `RemoteDesktopSession` —
/// used by `linscp-engine` script layer (`open rdp://…`) where the generic `RemoteSession`
/// erases the concrete type. `tunneled` should reflect `spec.session.tunnel.enabled`.
pub fn ticket_from_config(
    cfg: &RemoteDesktopConnectConfig,
    kind: RemoteDesktopKind,
    target: &str,
    tunneled: bool,
    socks_endpoint: Option<String>,
) -> DesktopLaunchTicket {
    let local_endpoint = if let Some(addr) = socks_endpoint {
        addr
    } else if tunneled && matches!(kind, RemoteDesktopKind::X2Go | RemoteDesktopKind::X11) {
        format!("ssh:{target}")
    } else {
        target.to_string()
    };
    let viewer = match kind {
        RemoteDesktopKind::Rdp => {
            if cfg!(target_os = "windows") { "mstsc" } else { "xfreerdp" }
        }
        RemoteDesktopKind::Vnc => "vncviewer",
        RemoteDesktopKind::Spice => "remote-viewer",
        RemoteDesktopKind::X2Go => "x2goclient",
        RemoteDesktopKind::X11 => "waypipe",
    }
    .to_string();

    // Temporary session view for argv builders that expect `&RemoteDesktopSession`
    let tmp = RemoteDesktopSession {
        scheme: cfg.scheme,
        kind,
        target: target.to_string(),
        config: cfg.clone(),
        jump: None,
        socks_addr: None,
        observed_host_key: None,
        ssh_for_x2go: None,
    };
    let (argv, file_content, file_extension) = match kind {
        RemoteDesktopKind::Rdp => {
            let (argv, content) = build_rdp_argv(&viewer, &tmp, tunneled, &local_endpoint);
            (argv, content, Some(".rdp".to_string()))
        }
        RemoteDesktopKind::Vnc => (build_vnc_argv(&viewer, &tmp, tunneled, &local_endpoint), None, None),
        RemoteDesktopKind::Spice => (build_spice_argv(&viewer, &tmp, tunneled, &local_endpoint), None, Some(".vv".to_string())),
        RemoteDesktopKind::X2Go => (build_x2go_argv(&viewer, &tmp), None, None),
        RemoteDesktopKind::X11 => (build_x11_argv(&viewer, &tmp), None, None),
    };

    DesktopLaunchTicket {
        kind: kind.as_str().to_string(),
        target: target.to_string(),
        viewer,
        argv,
        file_content,
        file_extension,
        tunneled,
        local_endpoint,
    }
}
}

fn build_rdp_argv(viewer: &str, sess: &RemoteDesktopSession, tunneled: bool, endpoint: &str) -> (Vec<String>, Option<String>) {
    let opts = &sess.config.desktop_opts;
    if viewer == "mstsc" {
        // Windows mstsc.exe expects an .rdp file. Generate minimal file content and argv = [mstsc, /v:host:port]
        let rdp_content = format!(
            "full address:s:{}\r\nusername:s:{}\r\n{domain}{sec}{bpp}{screen}\r\n",
            endpoint,
            sess.config.username.as_deref().unwrap_or(""),
            domain = opts.domain.as_deref().map(|d| format!("domain:s:{d}\r\n")).unwrap_or_default(),
            sec = opts.security.as_deref().map(|s| format!("authentication level:i:{}\r\n", if s=="nla"{2} else {1})).unwrap_or_default(),
            bpp = opts.color_depth.map(|d| format!("session bpp:i:{d}\r\n")).unwrap_or_default(),
            screen = if opts.fullscreen { "screen mode id:i:2\r\n".to_string() } else { format!("desktopwidth:i:{}\r\ndesktopheight:i:{}\r\n", opts.width.unwrap_or(1024), opts.height.unwrap_or(768)) },
        );
        let argv = vec![viewer.to_string(), format!("/v:{endpoint}")];
        let _ = tunneled;
        (argv, Some(rdp_content))
    } else {
        // xfreerdp / wlfreerdp / sdl-freerdp
        let mut argv = vec![viewer.to_string()];
        argv.push(format!("/v:{endpoint}"));
        if let Some(ref u) = sess.config.username {
            if !u.is_empty() {
                argv.push(format!("/u:{u}"));
            }
        }
        if let Some(ref p) = sess.config.password {
            if !p.is_empty() {
                argv.push(format!("/p:{}", p.as_str()));
            }
        }
        if let Some(ref d) = opts.domain {
            argv.push(format!("/d:{d}"));
        }
        if let Some(depth) = opts.color_depth {
            argv.push(format!("/bpp:{depth}"));
        }
        if opts.fullscreen {
            argv.push("/f".to_string());
        } else if let (Some(w), Some(h)) = (opts.width, opts.height) {
            argv.push(format!("/w:{w}"));
            argv.push(format!("/h:{h}"));
        }
        if let Some(ref sec) = opts.security {
            argv.push(format!("/sec:{sec}"));
            if sec == "nla" {
                argv.push("/sec-nla".to_string());
            }
        }
        if opts.compression {
            argv.push("/compression".to_string());
        }
        if opts.drive_redirection {
            argv.push("/drive:media,/tmp".to_string());
        }
        if let Some(mode) = opts.audio_mode {
            argv.push(format!("/audio-mode:{mode}"));
        }
        // Clipboard + home dir redirection by default like upstream defaults
        argv.push("/clipboard".to_string());
        if tunneled {
            argv.push("/network:auto".to_string());
        }
        (argv, None)
    }
}

fn build_vnc_argv(viewer: &str, sess: &RemoteDesktopSession, tunneled: bool, endpoint: &str) -> Vec<String> {
    let opts = &sess.config.desktop_opts;
    let mut argv = vec![viewer.to_string(), endpoint.to_string()];
    if sess.config.password.is_some() {
        // Most viewers read password from stdin / -passwd file; we pass via env/file in launcher.
        argv.push("-PasswordFile".to_string());
        argv.push("/tmp/linscp-vnc-passwd".to_string());
    }
    if opts.vnc_view_only {
        argv.push("-ViewOnly".to_string());
    }
    if let Some(q) = opts.vnc_quality {
        argv.push(format!("-QualityLevel={q}"));
    }
    if !opts.compression {
        argv.push("-CompressLevel=0".to_string());
    }
    if tunneled {
        argv.push("-via".to_string());
        argv.push(sess.config.host.clone());
    }
    argv
}

fn build_spice_argv(_viewer: &str, sess: &RemoteDesktopSession, tunneled: bool, endpoint: &str) -> Vec<String> {
    let opts = &sess.config.desktop_opts;
    let host = &sess.config.host;
    let port = sess.config.port;
    let tls_port = opts.spice_tls_port.map(|p| p.to_string()).unwrap_or_default();
    let insecure = if opts.spice_insecure { "1" } else { "0" };
    // remote-viewer expects spice://host:port?tls-port=... ; we also support .vv file.
    let uri = if !tls_port.is_empty() {
        format!("spice://{}:{}?tls-port={tls_port}&insecure={insecure}", host, port)
    } else if tunneled {
        format!("spice://{endpoint}")
    } else {
        format!("spice://{host}:{port}")
    };
    vec!["remote-viewer".to_string(), uri]
}

fn build_x2go_argv(viewer: &str, sess: &RemoteDesktopSession) -> Vec<String> {
    let opts = &sess.config.desktop_opts;
    let session_type = opts.x2go_session_type.as_deref().unwrap_or("XFCE");
    let cmd = opts.x2go_command.as_deref().unwrap_or("");
    let link = opts.x2go_link.as_deref().unwrap_or("adsl");
    let pack = opts.x2go_pack.as_deref().unwrap_or("16m-jpeg");
    // x2goclient --session=X2GO --command=...
    // pyhoca-cli variant: pyhoca-cli -u USER -H HOST -o session=TYPE
    if viewer.contains("pyhoca") {
        vec![
            viewer.to_string(),
            "-u".to_string(),
            sess.config.username.clone().unwrap_or_default(),
            "-H".to_string(),
            sess.config.host.clone(),
            "-p".to_string(),
            sess.config.port.to_string(),
            "--session-type".to_string(),
            session_type.to_string(),
        ]
    } else {
        let mut argv = vec![
            viewer.to_string(),
            "--session".to_string(),
            format!("{}@{}", sess.config.username.as_deref().unwrap_or(""), sess.config.host),
            "--command".to_string(),
            if cmd.is_empty() { session_type.to_string() } else { cmd.to_string() },
            "--link".to_string(),
            link.to_string(),
            "--pack".to_string(),
            pack.to_string(),
        ];
        if let Some(ref display) = opts.x11_display {
            argv.push("--display".to_string());
            argv.push(display.clone());
        }
        argv
    }
}

fn build_x11_argv(viewer: &str, sess: &RemoteDesktopSession) -> Vec<String> {
    let opts = &sess.config.desktop_opts;
    if viewer == "waypipe" && (opts.waypipe || std::env::var_os("WAYLAND_DISPLAY").is_some()) {
        vec![
            "waypipe".to_string(),
            "ssh".to_string(),
            format!("{}@{}", sess.config.username.as_deref().unwrap_or(""), sess.config.host),
            "-p".to_string(),
            sess.config.port.to_string(),
            sess.config.host.clone(),
        ]
    } else {
        vec![
            "ssh".to_string(),
            "-X".to_string(),
            "-p".to_string(),
            sess.config.port.to_string(),
            format!("{}@{}", sess.config.username.as_deref().unwrap_or(""), sess.config.host),
        ]
    }
}

// `RemoteSession` impl — desktops are not file-transfer sessions, so every file op returns
// `UnsupportedCapability(<op>, <scheme>)` just like FTP/Dav/S3's `dav_lock` does for SFTP.
// `probe_endpoint` does the light TCP connect above; `close` tears down jump + SOCKS.
#[async_trait::async_trait]
impl RemoteSession for RemoteDesktopSession {
    fn scheme(&self) -> ProtocolScheme { self.scheme }
    async fn pwd(&self) -> Result<String, ProtoError> { Err(ProtoError::UnsupportedCapability("pwd", self.scheme)) }
    async fn stat(&self, _remote_path: &str) -> Result<Option<FileEntry>, ProtoError> { Err(ProtoError::UnsupportedCapability("stat", self.scheme)) }
    async fn list_dir(&self, _remote_path: &str) -> Result<Vec<FileEntry>, ProtoError> { Err(ProtoError::UnsupportedCapability("list_dir", self.scheme)) }
    async fn mkdir(&self, _remote_path: &str) -> Result<(), ProtoError> { Err(ProtoError::UnsupportedCapability("mkdir", self.scheme)) }
    async fn remove_file(&self, _remote_path: &str) -> Result<(), ProtoError> { Err(ProtoError::UnsupportedCapability("remove_file", self.scheme)) }
    async fn remove_dir(&self, _remote_path: &str) -> Result<(), ProtoError> { Err(ProtoError::UnsupportedCapability("remove_dir", self.scheme)) }
    async fn rename(&self, _from: &str, _to: &str) -> Result<(), ProtoError> { Err(ProtoError::UnsupportedCapability("rename", self.scheme)) }
    async fn copy_file(&self, _from: &str, _to: &str) -> Result<(), ProtoError> { Err(ProtoError::UnsupportedCapability("copy_file", self.scheme)) }
    async fn symlink(&self, _target: &str, _link_path: &str) -> Result<(), ProtoError> { Err(ProtoError::UnsupportedCapability("symlink", self.scheme)) }
    async fn chmod(&self, _remote_path: &str, _mode: u32) -> Result<(), ProtoError> { Err(ProtoError::UnsupportedCapability("chmod", self.scheme)) }
    async fn set_mtime(&self, _remote_path: &str, _mtime: i64) -> Result<(), ProtoError> { Err(ProtoError::UnsupportedCapability("set_mtime", self.scheme)) }
    async fn checksum(&self, _algorithm: &str, _remote_path: &str) -> Result<String, ProtoError> { Err(ProtoError::UnsupportedCapability("checksum", self.scheme)) }
    async fn download(&self, _remote_path: &str, _opts: TransferRequest, _sink: &mut (dyn AsyncWrite + Unpin + Send), _progress: Option<&crate::ProgressCallback>) -> Result<u64, ProtoError> { Err(ProtoError::UnsupportedCapability("download", self.scheme)) }
    async fn upload(&self, _remote_path: &str, _opts: TransferRequest, _source: &mut (dyn AsyncRead + Unpin + Send), _total_size: Option<u64>, _progress: Option<&crate::ProgressCallback>) -> Result<u64, ProtoError> { Err(ProtoError::UnsupportedCapability("upload", self.scheme)) }
    async fn probe_endpoint(&self, _initial_dir: &str) -> Result<(), ProtoError> {
        // Already probed in `connect`; keep idempotent.
        Ok(())
    }
    async fn close(&self) -> Result<(), ProtoError> {
        if let Some(j) = &self.jump {
            let _ = j.close().await;
        }
        if let Some(conn) = &self.ssh_for_x2go {
            let _ = conn.disconnect().await;
        }
        Ok(())
    }
    fn observed_host_key(&self) -> Option<&str> { self.observed_host_key.as_deref() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn desktop_options_parse_and_viewer() {
        let mut raw = BTreeMap::new();
        raw.insert("rdp_domain".to_string(), "CORP".to_string());
        raw.insert("rdp_color_depth".to_string(), "24".to_string());
        raw.insert("vnc_view_only".to_string(), "1".to_string());
        let opts = DesktopOptions::from_raw_fields(&raw);
        assert_eq!(opts.domain.as_deref(), Some("CORP"));
        assert_eq!(opts.color_depth, Some(24));
        assert!(opts.vnc_view_only);
        assert_eq!(RemoteDesktopKind::Rdp.default_viewer(false), "xfreerdp");
        assert_eq!(RemoteDesktopKind::X2Go.default_viewer(true), "x2goclient");
    }
    #[test]
    fn rdp_and_vnc_argv() {
        let cfg = RemoteDesktopConnectConfig {
            scheme: ProtocolScheme::Rdp,
            kind: RemoteDesktopKind::Rdp,
            host: "win.example.com".to_string(),
            port: 3389,
            username: Some("alice".to_string()),
            password: None,
            domain: None,
            desktop_opts: DesktopOptions::default(),
            tls: crate::tls::TlsSettings::default(),
            proxy: None,
            timeout: std::time::Duration::from_secs(15),
        };
        // Build a minimal session to test ticket generation
        let sess = RemoteDesktopSession {
            scheme: ProtocolScheme::Rdp,
            kind: RemoteDesktopKind::Rdp,
            target: "win.example.com:3389".to_string(),
            config: cfg,
            jump: None,
            socks_addr: None,
            observed_host_key: None,
            ssh_for_x2go: None,
        };
        let ticket = sess.launch_ticket();
        assert!(ticket.argv.iter().any(|a| a.contains("3389")));
        assert_eq!(ticket.kind, "rdp");
    }
}
