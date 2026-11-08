//! Shared serializable domain models and dual-mode RPC payloads for LinSCP.
//!
//! Both `linscp-http` (standalone browser HTTP mode) and `linscp-tauri`
//! (native Linux, Windows, and Android app shell) exchange these types with
//! the TypeScript Commander frontend (`ui/`).

use serde::{Deserialize, Serialize};

/// Supported transport schemes, keeping explicit (`ftpes`) and implicit
/// (`ftps`) FTP-over-TLS distinct as well as local-to-local tabs (`local`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolScheme {
    Sftp,
    Scp,
    Ssh,
    Ftp,
    Ftps,
    Ftpes,
    Dav,
    Davs,
    Webdav,
    Webdavs,
    S3,
    Local,
    /// Microsoft Remote Desktop Protocol (RDP) — native Windows, xfreerdp/FreeRDP on Linux, aRDP/aFreeRDP on Android.
    Rdp,
    /// Virtual Network Computing (RFB) — TigerVNC, TightVNC, RealVNC.
    Vnc,
    /// SPICE (Simple Protocol for Independent Computing Environments) — QEMU/KVM `remote-viewer`/`spicy`.
    Spice,
    /// X2Go / NX — SSH-tunneled X11 with NX compression (`x2goclient`, `nxproxy`, `pyhoca`).
    X2Go,
    /// Generic X11 forwarding (`ssh -X`) — Wayland-aware via `waypipe`/`xwayland`.
    X11,
}

impl ProtocolScheme {
    /// Default TCP port for network protocols, or `0` for `local`.
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Sftp | Self::Scp | Self::Ssh => 22,
            Self::Ftp | Self::Ftpes => 21,
            Self::Ftps => 990,
            Self::Dav => 80,
            Self::Davs | Self::Webdav | Self::Webdavs | Self::S3 => 443,
            Self::Local => 0,
            Self::Rdp => 3389,
            Self::Vnc => 5900,
            Self::Spice => 5900,
            Self::X2Go => 22,
            Self::X11 => 22,
        }
    }

    /// Parses a protocol scheme token case-insensitively (`"sftp"`, `"ftpes"`, `"s3"`).
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sftp" => Some(Self::Sftp),
            "scp" => Some(Self::Scp),
            "ssh" => Some(Self::Ssh),
            "ftp" => Some(Self::Ftp),
            "ftps" => Some(Self::Ftps),
            "ftpes" => Some(Self::Ftpes),
            "dav" | "http" => Some(Self::Dav),
            "davs" | "https" => Some(Self::Davs),
            "webdav" => Some(Self::Webdav),
            "webdavs" => Some(Self::Webdavs),
            "s3" | "s3s" => Some(Self::S3),
            "local" => Some(Self::Local),
            "rdp" | "rdps" | "msrdp" | "ms-rdp" => Some(Self::Rdp),
            "vnc" | "rfb" => Some(Self::Vnc),
            "spice" => Some(Self::Spice),
            "x2go" | "nx" | "nx3" => Some(Self::X2Go),
            "x11" | "x" | "waypipe" => Some(Self::X11),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sftp => "sftp",
            Self::Scp => "scp",
            Self::Ssh => "ssh",
            Self::Ftp => "ftp",
            Self::Ftps => "ftps",
            Self::Ftpes => "ftpes",
            Self::Dav => "dav",
            Self::Davs => "davs",
            Self::Webdav => "webdav",
            Self::Webdavs => "webdavs",
            Self::S3 => "s3",
            Self::Local => "local",
            Self::Rdp => "rdp",
            Self::Vnc => "vnc",
            Self::Spice => "spice",
            Self::X2Go => "x2go",
            Self::X11 => "x11",
        }
    }

    /// Returns true for interactive remote-desktop protocols that open a viewer rather than a file tree.
    pub const fn is_remote_desktop(self) -> bool {
        matches!(
            self,
            Self::Rdp | Self::Vnc | Self::Spice | Self::X2Go | Self::X11
        )
    }

    /// True for desktop sessions that are transported over SSH (X2Go, X11) vs direct TCP (RDP/VNC/SPICE).
    pub const fn desktop_over_ssh(self) -> bool {
        matches!(self, Self::X2Go | Self::X11)
    }
}

/// Independent SSH jump-host (tunnel) configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyfile: Option<String>,
    #[serde(default)]
    pub hostkey: String,
    #[serde(default)]
    pub local_port: u16,
}

/// Stored or ad-hoc session descriptor shared between CLI and Commander UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    pub name: String,
    pub protocol: ProtocolScheme,
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyfile: Option<String>,
    #[serde(default)]
    pub hostkey: String,
    #[serde(default)]
    pub initial_dir: String,
    #[serde(default)]
    pub local_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<TunnelConfig>,
}

/// Non-secret summary of a saved session returned to Commander session lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSessionSummary {
    pub name: String,
    pub folder: String,
    pub leaf_name: String,
    pub protocol: ProtocolScheme,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub has_password: bool,
    pub has_unreadable_secret: bool,
    pub initial_dir: String,
    pub local_dir: String,
}

/// Session candidate parsed from OpenSSH `~/.ssh/config` or FileZilla XML.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedSite {
    pub source: String,
    pub name: String,
    pub protocol: ProtocolScheme,
    pub host: String,
    pub port: u16,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    #[serde(default)]
    pub remote_directory: String,
    #[serde(default)]
    pub local_directory: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedImportEntry {
    pub label: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportReport {
    pub imported: Vec<ImportedSite>,
    pub skipped: Vec<SkippedImportEntry>,
}

/// Saved directory bookmark pair (`bookmarks.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookmarkEntry {
    pub name: String,
    #[serde(default)]
    pub session_name: String,
    #[serde(default)]
    pub remote_dir: String,
    #[serde(default)]
    pub local_dir: String,
}

/// Saved tab inside a multi-session workspace (`workspaces.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceTabSnapshot {
    pub session_name: String,
    #[serde(default)]
    pub remote_dir: String,
    #[serde(default)]
    pub local_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceSnapshot {
    pub name: String,
    pub tabs: Vec<WorkspaceTabSnapshot>,
    #[serde(default)]
    pub active_index: usize,
}

/// File or directory entry returned to either Commander panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    #[serde(default)]
    pub is_symlink: bool,
    #[serde(default)]
    pub broken_link: bool,
    #[serde(default)]
    pub date: String,
    #[serde(default)]
    pub mtime: i64,
    #[serde(default)]
    pub permissions: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
}

/// Local volume, POSIX root, or Android SAF document-tree root selectable in
/// the Local panel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRootEntry {
    /// Machine-usable root path or URI (e.g. `"/"`, `"C:\\"`, or `"content://..."`).
    pub path: String,
    /// Short display label (e.g. `"/"`, `"C: (System)"`, `"Downloads (SAF)"`).
    pub label: String,
    /// `"posix"`, `"drive"`, `"unc"`, `"app_private"`, or `"saf_tree"`.
    pub kind: String,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferMode {
    #[default]
    Binary,
    Ascii,
    Automatic,
}

/// Persisted Commander user preferences (`preferences.json` shape).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPreferences {
    pub transfer: TransferMode,
    pub filemask: String,
    pub speed: u32,
    pub resumesupport: String,
    pub resume: bool,
    pub preserve_time: bool,
    pub newer_only: bool,
    pub append: bool,
    pub no_permissions: bool,
    pub priority: bool,
    pub confirm_overwrite: bool,
    pub confirm_delete: bool,
}

impl Default for UserPreferences {
    fn default() -> Self {
        Self {
            transfer: TransferMode::Binary,
            filemask: String::new(),
            speed: 0,
            resumesupport: String::new(),
            resume: false,
            preserve_time: true,
            newer_only: false,
            append: false,
            no_permissions: false,
            priority: false,
            confirm_overwrite: true,
            confirm_delete: true,
        }
    }
}

/// Summary of an open Commander tab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabSummary {
    pub id: u64,
    pub name: String,
    pub connected: bool,
    pub local_dir: String,
    pub remote_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionConfig>,
    #[serde(default)]
    pub observed_hostkey: String,
    #[serde(default)]
    pub error: String,
}

/// Queued background operation state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferQueueItem {
    pub id: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub status: String,
    pub source: String,
    pub destination: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub percent: u8,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub error: String,
}

/// Host-key challenge distinguishing the jump host from the destination server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKeyChallenge {
    pub tab_id: u64,
    /// `"destination"` or `"tunnel"`.
    pub role: String,
    /// `"unknown"` or `"changed"`.
    pub state: String,
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
}

/// Transport-neutral request envelope dispatched by both `TauriTransport` and
/// `HttpTransport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiEnvelope {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: serde_json::Value,
}

/// Transport-neutral response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiReply {
    pub status: u16,
    pub payload: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_distinguish_explicit_and_implicit_ftps() {
        assert_eq!(ProtocolScheme::Sftp.default_port(), 22);
        assert_eq!(ProtocolScheme::Ftp.default_port(), 21);
        assert_eq!(ProtocolScheme::Ftpes.default_port(), 21);
        assert_eq!(ProtocolScheme::Ftps.default_port(), 990);
        assert_eq!(ProtocolScheme::Local.default_port(), 0);
    }

    #[test]
    fn preferences_round_trip_matches_gui_json_keys() {
        let prefs = UserPreferences::default();
        let value = serde_json::to_value(&prefs).expect("serialize preferences");
        assert_eq!(value["transfer"], "binary");
        assert_eq!(value["confirm_overwrite"], true);
        assert_eq!(value["preserve_time"], true);
        let decoded: UserPreferences = serde_json::from_value(value).expect("deserialize");
        assert_eq!(decoded, prefs);
    }
}

/// One logical CPU's contribution to a physical core. Percentages are null
/// until two valid counters have been observed on the same SSH connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorCpuThread {
    pub id: u32,
    pub percent: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorCpuCore {
    pub socket: Option<u32>,
    pub core: u32,
    pub threads: Vec<MonitorCpuThread>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MonitorCpu {
    pub model: String,
    pub logical_count: u32,
    pub percent: Option<f64>,
    pub cores: Vec<MonitorCpuCore>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorMemory {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorDisk {
    pub device: String,
    pub mount: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub percent: f64,
}

/// Vendor-neutral telemetry. An absent sensor is null, never an invented
/// zero or a vendor-independent guessed power/thermal limit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorGpu {
    pub index: u32,
    pub vendor: String,
    pub name: String,
    pub percent: Option<f64>,
    pub memory_used_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub power_watts: Option<f64>,
    pub power_limit_watts: Option<f64>,
    pub temperature_c: Option<f64>,
    pub temperature_limit_c: Option<f64>,
    pub temperature_sensor: String,
    pub driver: String,
    pub pcie_generation: Option<u32>,
    pub pcie_width: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorSwap {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    /// Zero when the host has no swap; absent swap telemetry stays null.
    pub percent: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorNetwork {
    pub rx_bytes_total: u64,
    pub tx_bytes_total: u64,
    /// Null until two samples exist, or when counters reset/wrap.
    pub rx_bytes_per_sec: Option<f64>,
    pub tx_bytes_per_sec: Option<f64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorMetricParse {
    #[default]
    Number,
    Regex,
    Text,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorMetricDisplay {
    #[default]
    Sparkline,
    BigNumber,
    Text,
}

/// A user-approved remote command sampled alongside the fixed built-in probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorCustomMetric {
    pub id: String,
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub parse: MonitorMetricParse,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(default)]
    pub display: MonitorMetricDisplay,
    #[serde(default)]
    pub unit: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorCustomReading {
    pub id: String,
    pub name: String,
    pub parse: MonitorMetricParse,
    pub display: MonitorMetricDisplay,
    pub unit: String,
    pub value: Option<f64>,
    pub text: String,
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MonitorSnapshot {
    pub hostname: String,
    pub primary_ip: String,
    pub uptime_seconds: Option<f64>,
    pub load_average: Vec<f64>,
    pub cpu: MonitorCpu,
    pub memory: Option<MonitorMemory>,
    #[serde(default)]
    pub swap: Option<MonitorSwap>,
    #[serde(default)]
    pub network: Option<MonitorNetwork>,
    pub disks: Vec<MonitorDisk>,
    pub gpus: Vec<MonitorGpu>,
    pub cuda_version: String,
    #[serde(default)]
    pub custom: Vec<MonitorCustomReading>,
    /// Missing optional tools/sensors, distinct from a failed SSH sample.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorSample {
    pub tab: u64,
    /// Stable settings key for the saved site or unsaved SSH identity.
    #[serde(default)]
    pub key: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub protocol: String,
    /// ok, error, disconnected, unsupported or busy.
    pub status: String,
    pub sampled_at: u64,
    pub latency_ms: u64,
    pub error: String,
    pub snapshot: Option<MonitorSnapshot>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default)]
    pub outage_since_ms: Option<u64>,
    #[serde(default)]
    pub outage: bool,
    #[serde(default)]
    pub outage_started: bool,
    #[serde(default)]
    pub recovered: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorSettings {
    pub interval_secs: f64,
    pub connect_timeout_secs: f64,
    pub poll_timeout_secs: f64,
    pub outage_threshold: u32,
    pub notify_on_outage: bool,
    pub beep_on_outage: bool,
    pub beep_cooldown_secs: u32,
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            interval_secs: 5.0,
            connect_timeout_secs: 10.0,
            poll_timeout_secs: 10.0,
            outage_threshold: 3,
            notify_on_outage: true,
            beep_on_outage: false,
            beep_cooldown_secs: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorHostConfig {
    pub enabled_metrics: Vec<String>,
    pub custom_metrics: Vec<MonitorCustomMetric>,
    #[serde(default)]
    pub paused: bool,
}

impl Default for MonitorHostConfig {
    fn default() -> Self {
        Self {
            enabled_metrics: default_monitor_metrics(),
            custom_metrics: Vec::new(),
            paused: false,
        }
    }
}

pub fn default_monitor_metrics() -> Vec<String> {
    ["cpu", "mem", "swap", "disk", "load", "net", "gpu"]
        .iter().map(|s| s.to_string()).collect()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorSettingsDocument {
    pub version: u32,
    pub settings: MonitorSettings,
    pub hosts: std::collections::BTreeMap<String, MonitorHostConfig>,
}

impl Default for MonitorSettingsDocument {
    fn default() -> Self {
        Self { version: 1, settings: MonitorSettings::default(), hosts: std::collections::BTreeMap::new() }
    }
}
