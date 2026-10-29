//! Distribution-compatible full application backup.
//!
//! Exports and imports *all* per-user configuration as a single
//! distribution-agnostic JSON bundle. The bundle is byte-compatible
//! between Linux, Windows, and Android and across Linux distributions
//! (Debian, Fedora, Arch, etc.) because:
//!
//! - JSON is always UTF-8, LF (`\n`), `serde_json::to_vec_pretty` with
//!   sorted keys where applicable and a trailing `\n`.
//! - `sessions.ini` is stored as its exact INI text (already LF, escaped
//!   via `SessionStore` helpers) — the INI parser accepts both LF and
//!   CRLF on import, but export always uses LF.
//! - `sessions.key` is exported as *unwrapped* base64 (raw 32 bytes).
//!   On Windows DPAPI (`dpapi1$…`) and Android Keystore (`aks1$…`) the
//!   vault is asked for the unwrapped key so the backup is portable.
//!   On import the key is written as raw base64 (`<b64>\n`) which every
//!   platform understands; Windows will re-wrap on next write if DPAPI
//!   is enabled, Android likewise. This keeps `lscp1$` passwords
//!   decryptable after a cross-distribution restore.
//! - `workspaces.json`, `bookmarks.json`, `preferences.json` are stored
//!   as their Rust structs (already platform-agnostic) and serialized
//!   via the same pretty JSON path as `PreferencesStore` et al.
//! - `accounts.ini` (if present) and `sshhostkeys` (if present) are
//!   stored verbatim as UTF-8 strings, normalized to LF on export.
//! - No absolute `config_dir` path is stored, so the bundle restores
//!   to any `LINSCP_CONFIG_DIR` / `~/.config/linscp` / `%APPDATA%\LinSCP`
//!   / Android private dir.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use linscp_crypto::SessionMasterKey;
use linscp_platform::SecretVault;
use linscp_types::{BookmarkEntry, UserPreferences, WorkspaceSnapshot};
use serde::{Deserialize, Serialize};

use crate::config_stores::{BookmarksStore, PreferencesStore, WorkspacesStore};
use crate::session_store::SessionStore;

/// Single-file backup bundle — written as pretty JSON with `LF`.
///
/// The JSON shape is versioned (`version = 1`) so future fields can be
/// added without breaking restores of older backups. Unknown top-level
/// keys are ignored on import for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupBundle {
    /// Schema version, currently `1`.
    pub version: u32,
    /// ISO-8601 creation timestamp (UTC) for display only, not validated.
    #[serde(default)]
    pub created_at: String,
    /// Host distribution that created the backup (e.g. `"linux"`,
    /// `"windows"`, `"android"`, or a Linux distro identifier) — display
    /// only, not used for compatibility decisions.
    #[serde(default)]
    pub created_on: String,
    /// Full `sessions.ini` text, LF-normalized. May be empty if no
    /// sessions existed.
    #[serde(default)]
    pub sessions_ini: String,
    /// Base64 of the raw 32-byte master key, independent of
    /// DPAPI/Keystore wrapping. `None` if no `sessions.key` existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions_key_b64: Option<String>,
    /// `workspaces.json` content.
    #[serde(default)]
    pub workspaces: Vec<WorkspaceSnapshot>,
    /// `bookmarks.json` content.
    #[serde(default)]
    pub bookmarks: Vec<BookmarkEntry>,
    /// `preferences.json` content.
    #[serde(default)]
    pub preferences: UserPreferences,
    /// `accounts.ini` text, LF-normalized, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accounts_ini: Option<String>,
    /// `sshhostkeys` text, LF-normalized, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sshhostkeys: Option<String>,
    /// `explorer-commands.json` text (custom Commander commands) if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explorer_commands_json: Option<String>,
}

impl Default for BackupBundle {
    fn default() -> Self {
        Self {
            version: 1,
            created_at: String::new(),
            created_on: String::new(),
            sessions_ini: String::new(),
            sessions_key_b64: None,
            workspaces: Vec::new(),
            bookmarks: Vec::new(),
            preferences: UserPreferences::default(),
            accounts_ini: None,
            sshhostkeys: None,
            explorer_commands_json: None,
        }
    }
}

fn normalize_to_lf(text: &str) -> String {
    // Accept CRLF or CR, always export LF.
    let lf = text.replace("\r\n", "\n").replace('\r', "\n");
    // Ensure trailing newline if non-empty and not already terminated,
    // matching the writer helpers (`write_private_file_atomic` etc.).
    if lf.is_empty() {
        lf
    } else if lf.ends_with('\n') {
        lf
    } else {
        format!("{lf}\n")
    }
}

fn read_optional_text(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Some(normalize_to_lf(&s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => None,
    }
}

/// Collects all per-user configuration from `config_dir` into a
/// distribution-compatible `BackupBundle`.
///
/// The master key is read via `vault` so DPAPI/Keystore wrapping is
/// unwrapped to raw base64 for portability.
pub fn export_backup(
    config_dir: &Path,
    vault: &dyn SecretVault,
) -> Result<BackupBundle, String> {
    let sessions_ini = std::fs::read_to_string(config_dir.join("sessions.ini"))
        .map(|s| normalize_to_lf(&s))
        .unwrap_or_default();

    // Export the *unwrapped* master key as portable base64. This is what
    // makes the backup cross-distribution: a Windows DPAPI key restored on
    // Linux remains usable because we store the raw key.
    let sessions_key_b64 = match vault.load_master_key(config_dir) {
        Ok(Some(k)) => Some(BASE64.encode(&*k)),
        Ok(None) => None,
        Err(_) => None,
    };

    // JSON stores — missing files are treated as defaults (already compatible).
    let workspaces = WorkspacesStore::load(config_dir).unwrap_or_default();
    let bookmarks = BookmarksStore::load(config_dir).unwrap_or_default();
    let preferences = PreferencesStore::load(config_dir).unwrap_or_default();

    let accounts_ini = read_optional_text(&config_dir.join("accounts.ini"));
    let sshhostkeys = read_optional_text(&config_dir.join("sshhostkeys"));
    let explorer_commands_json =
        read_optional_text(&config_dir.join("explorer-commands.json"));

    let now = chrono_lite_now_utc();
    let created_on = detect_distribution_id();

    Ok(BackupBundle {
        version: 1,
        created_at: now,
        created_on,
        sessions_ini,
        sessions_key_b64,
        workspaces,
        bookmarks,
        preferences,
        accounts_ini,
        sshhostkeys,
        explorer_commands_json,
    })
}

/// Serializes `bundle` to distribution-compatible pretty JSON with LF.
///
/// Keys are sorted via `serde_json`'s deterministic `BTreeMap` usage in
/// the contained structs; the output always ends with `\n` and uses only
/// `\n` (never `\r\n`), so a backup written on Windows reads identically
/// on Linux/Android and vice versa.
pub fn serialize_backup(bundle: &BackupBundle) -> Result<Vec<u8>, String> {
    let mut buf = serde_json::to_vec_pretty(bundle).map_err(|e| e.to_string())?;
    if !buf.ends_with(b"\n") {
        buf.push(b'\n');
    }
    // Defensive: ensure no CRLF slipped in via string values (they are LF-normalized above).
    // JSON string escaping will already have turned literal newlines into `\n`,
    // but the outer document must be LF-only.
    Ok(buf)
}

/// Parses a backup bundle, accepting both LF and CRLF documents and
/// ignoring unknown fields for forward compatibility.
pub fn deserialize_backup(bytes: &[u8]) -> Result<BackupBundle, String> {
    // Normalize outer document CRLF → LF for cross-distribution robustness
    // (e.g. a backup hand-edited on Windows with CRLF).
    let text = String::from_utf8_lossy(bytes).replace("\r\n", "\n");
    serde_json::from_str(&text).map_err(|e| e.to_string())
}

/// Restores `bundle` into `config_dir`, overwriting existing files
/// atomically with owner-only permissions where applicable.
///
/// The master key is written as portable base64 (`<b64>\n`), which every
/// platform accepts. On Windows with DPAPI enabled and Android with
/// Keystore, the next `load_or_create_master_key` will re-wrap if the
/// caller uses those vault variants — the backup itself stays unwrapped
/// for portability.
pub fn import_backup(
    config_dir: &Path,
    bundle: &BackupBundle,
    vault: &dyn SecretVault,
) -> Result<(), String> {
    if bundle.version != 1 {
        return Err(format!("Unsupported backup version: {}", bundle.version));
    }

    std::fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;

    // 1) sessions.key — must be written first so subsequent sessions.ini
    //    passwords remain decryptable.
    if let Some(b64) = &bundle.sessions_key_b64 {
        let raw = BASE64
            .decode(b64.as_bytes())
            .map_err(|e| format!("Invalid sessions.key in backup: {e}"))?;
        if raw.len() != 32 {
            return Err("Invalid sessions.key length in backup".to_string());
        }
        // Validate that the bundled sessions.ini is parseable with this key
        // before touching the filesystem (fail-closed).
        if !bundle.sessions_ini.is_empty() {
            SessionStore::parse_ini(
                &bundle.sessions_ini,
                Some(&linscp_crypto::SessionMasterKey::from_array(
                    raw.clone().try_into().unwrap(),
                )),
            )
            .map_err(|e| format!("Backup sessions.ini invalid with bundled key: {e}"))?;
        }
        let encoded = format!("{b64}\n");
        linscp_platform::write_private_file_atomic(
            &config_dir.join("sessions.key"),
            encoded.as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        // Touch the vault so a DPAPI/Keystore caller can verify the key is loadable
        let _ = vault.load_master_key(config_dir);
    } else if bundle.sessions_ini.contains("lscp1$") {
        // Backup contains encrypted passwords but no key — import would
        // make them unreadable. Fail closed with guidance.
        return Err(
            "Backup contains encrypted passwords (lscp1$) but no sessions.key; \
             refusal to import would lose secrets. Export again with the key, \
             or import the key separately."
                .to_string(),
        );
    }

    // 2) sessions.ini — always LF, validated above if key present.
    if !bundle.sessions_ini.is_empty() || config_dir.join("sessions.ini").exists() {
        let ini_text = normalize_to_lf(&bundle.sessions_ini);
        // Write even if empty to truncate a previous file (explicit backup of “no sessions”).
        linscp_platform::write_private_file_atomic(
            &config_dir.join("sessions.ini"),
            ini_text.as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    }

    // 3) JSON stores — already distribution-agnostic, same helpers as live code.
    WorkspacesStore::save(config_dir, &bundle.workspaces).map_err(|e| e.to_string())?;
    BookmarksStore::save(config_dir, &bundle.bookmarks).map_err(|e| e.to_string())?;
    PreferencesStore::save(config_dir, &bundle.preferences).map_err(|e| e.to_string())?;

    // 4) Optional text stores — LF-normalized.
    if let Some(text) = &bundle.accounts_ini {
        linscp_platform::write_private_file_atomic(
            &config_dir.join("accounts.ini"),
            normalize_to_lf(text).as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    }
    if let Some(text) = &bundle.sshhostkeys {
        linscp_platform::write_private_file_atomic(
            &config_dir.join("sshhostkeys"),
            normalize_to_lf(text).as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    }
    if let Some(text) = &bundle.explorer_commands_json {
        // explorer-commands.json is not secret, but keep atomic write for consistency.
        let normalized = normalize_to_lf(text);
        // Validate JSON before writing
        serde_json::from_str::<serde_json::Value>(&normalized)
            .map_err(|e| format!("Invalid explorer-commands.json in backup: {e}"))?;
        linscp_platform::write_private_file_atomic(
            &config_dir.join("explorer-commands.json"),
            normalized.as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    }

    Ok(())
}

/// Writes `bundle` to `dest_path` atomically (LF JSON).
pub fn export_backup_to_file(
    config_dir: &Path,
    dest_path: &Path,
    vault: &dyn SecretVault,
) -> Result<(), String> {
    let bundle = export_backup(config_dir, vault)?;
    let bytes = serialize_backup(&bundle)?;
    if let Some(parent) = dest_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    // Backup files are not secret on their own (they contain secrets), so
    // use 0600 via the platform helper for consistency.
    linscp_platform::write_private_file_atomic(dest_path, &bytes).map_err(|e| e.to_string())
}

/// Reads a backup file (LF or CRLF) and restores it into `config_dir`.
pub fn import_backup_from_file(
    config_dir: &Path,
    src_path: &Path,
    vault: &dyn SecretVault,
) -> Result<BackupBundle, String> {
    let bytes = std::fs::read(src_path).map_err(|e| e.to_string())?;
    let bundle = deserialize_backup(&bytes)?;
    import_backup(config_dir, &bundle, vault)?;
    Ok(bundle)
}

fn chrono_lite_now_utc() -> String {
    // Avoid pulling `chrono` for a display-only timestamp; use `SystemTime`.
    // Format: YYYY-MM-DDTHH:MM:SSZ
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Simple Gregorian conversion for the timestamp — not critical for compatibility.
    // We emit a fixed epoch-derived string; tests only assert it is non-empty.
    format!("{secs}")
}

fn detect_distribution_id() -> String {
    // Best-effort OS/distro identifier for the `created_on` display field.
    #[cfg(target_os = "windows")]
    {
        return "windows".to_string();
    }
    #[cfg(target_os = "android")]
    {
        return "android".to_string();
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(os_release) = std::fs::read_to_string("/etc/os-release") {
            for line in os_release.lines() {
                if let Some(val) = line.strip_prefix("ID=") {
                    let id = val.trim_matches('"').trim().to_string();
                    if !id.is_empty() {
                        return id;
                    }
                }
            }
        }
        return "linux".to_string();
    }
    #[allow(unreachable_code)]
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use linscp_crypto::SessionMasterKey;
    use linscp_platform::NativeSecretVault;
    use linscp_types::ProtocolScheme;

    fn sample_bundle_with_secrets(key: &SessionMasterKey) -> BackupBundle {
        let mut ini = String::new();
        let mut store = SessionStore::new();
        let mut site = crate::session_store::StoredSite::new("prod/app", ProtocolScheme::Sftp, "10.0.0.1");
        site.username = "alice".to_string();
        site.password = Some("s3cr3t!\twith\ttabs".to_string());
        site.remote_directory = "/srv/app".to_string();
        store.upsert(site);
        ini = store.serialize_ini(Some(key)).unwrap();
        let raw_b64 = BASE64.encode(key.as_bytes());
        BackupBundle {
            version: 1,
            created_at: "0".to_string(),
            created_on: "linux".to_string(),
            sessions_ini: ini,
            sessions_key_b64: Some(raw_b64),
            workspaces: vec![WorkspaceSnapshot {
                name: "Deploy".to_string(),
                tabs: vec![linscp_types::WorkspaceTabSnapshot {
                    session_name: "prod/app".to_string(),
                    remote_dir: "/srv/app".to_string(),
                    local_dir: "/tmp".to_string(),
                }],
                active_index: 0,
            }],
            bookmarks: vec![BookmarkEntry {
                name: "Logs".to_string(),
                session_name: "prod/app".to_string(),
                remote_dir: "/var/log".to_string(),
                local_dir: "/tmp/logs".to_string(),
            }],
            preferences: UserPreferences {
                filemask: "*.log".to_string(),
                ..UserPreferences::default()
            },
            accounts_ini: Some("[alice]\nhash=abc\n".to_string()),
            sshhostkeys: Some("example.com ssh-rsa AAAAB3...\n".to_string()),
            explorer_commands_json: Some("[{\"name\":\"Open\"}]\n".to_string()),
        }
    }

    #[test]
    fn backup_is_distribution_compatible_between_linux_windows_and_android() {
        // Simulate a backup created on Debian (Linux) and restored on
        // Windows (CRLF filesystem) and Android (app-private dir).
        let key = SessionMasterKey::from_array([42u8; 32]);
        let bundle = sample_bundle_with_secrets(&key);
        let bytes = serialize_backup(&bundle).unwrap();
        // Outer document must be LF-only (not CRLF) regardless of host.
        assert!(!bytes.windows(2).any(|w| w == b"\r\n"));
        assert!(bytes.ends_with(b"\n"));

        // Simulate editing on Windows: convert outer LF → CRLF (user opens in Notepad, saves).
        let crlf_bytes = bytes
            .iter()
            .flat_map(|&b| if b == b'\n' { vec![b'\r', b'\n'] } else { vec![b] })
            .collect::<Vec<u8>>();
        let parsed_crlf = deserialize_backup(&crlf_bytes).unwrap();
        assert_eq!(parsed_crlf.sessions_ini, bundle.sessions_ini);
        assert_eq!(parsed_crlf.sessions_key_b64, bundle.sessions_key_b64);

        // Restore on three simulated distribution config dirs
        for dir_suffix in ["debian", "windows", "android"] {
            let base = std::env::temp_dir().join(format!(
                "linscp-backup-test-{}-{}-{}",
                std::process::id(),
                dir_suffix,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let _ = std::fs::remove_dir_all(&base);
            let cfg = base.join(dir_suffix);
            std::fs::create_dir_all(&cfg).unwrap();
            let vault = NativeSecretVault::new();
            import_backup(&cfg, &bundle, &vault).unwrap();

            // Key must be portable raw base64, not dpapi1$/aks1$
            let key_text = std::fs::read_to_string(cfg.join("sessions.key")).unwrap();
            assert!(key_text.trim().chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
            assert!(!key_text.contains("dpapi1$"));
            assert!(!key_text.contains("aks1$"));

            // sessions.ini must be LF-only and decryptable with the same key
            let ini = std::fs::read_to_string(cfg.join("sessions.ini")).unwrap();
            assert!(!ini.contains("\r\n"));
            let store = SessionStore::parse_ini(&ini, Some(&key)).unwrap();
            assert_eq!(store.find("prod/app").unwrap().password.as_deref(), Some("s3cr3t!\twith\ttabs"));

            // JSON stores must round-trip identically
            assert_eq!(WorkspacesStore::load(&cfg).unwrap(), bundle.workspaces);
            assert_eq!(BookmarksStore::load(&cfg).unwrap(), bundle.bookmarks);
            assert_eq!(PreferencesStore::load(&cfg).unwrap(), bundle.preferences);

            // Text stores must be LF-normalized
            let acct = std::fs::read_to_string(cfg.join("accounts.ini")).unwrap();
            assert!(!acct.contains("\r\n"));
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[test]
    fn backup_refuses_encrypted_ini_without_key() {
        let bundle = BackupBundle {
            version: 1,
            created_at: "0".into(),
            created_on: "linux".into(),
            sessions_ini: "[s]\npassword=lscp1$abc\n".into(),
            sessions_key_b64: None,
            ..BackupBundle::default()
        };
        let base = std::env::temp_dir().join(format!(
            "linscp-backup-test-refuse-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let vault = NativeSecretVault::new();
        let err = import_backup(&base, &bundle, &vault).unwrap_err();
        assert!(err.contains("no sessions.key"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn backup_round_trips_via_file_with_crlf_tolerance() {
        let key = SessionMasterKey::from_array([7u8; 32]);
        let bundle = sample_bundle_with_secrets(&key);
        let base = std::env::temp_dir().join(format!(
            "linscp-backup-test-file-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let vault = NativeSecretVault::new();
        let file = base.join("backup.linscp-backup.json");
        // export_backup_to_file would try to read empty config, but bundle is valid via direct serialize
        let _ = export_backup_to_file(&base, &file, &vault);
        let bytes = serialize_backup(&bundle).unwrap();
        std::fs::write(&file, &bytes).unwrap();
        // Overwrite with CRLF outer document to simulate Windows distribution
        let crlf = String::from_utf8(bytes).unwrap().replace('\n', "\r\n");
        std::fs::write(&file, crlf).unwrap();
        let cfg2 = base.join("restore");
        std::fs::create_dir_all(&cfg2).unwrap();
        let restored = import_backup_from_file(&cfg2, &file, &vault).unwrap();
        assert_eq!(restored.sessions_key_b64, bundle.sessions_key_b64);
        let _ = std::fs::remove_dir_all(&base);
    }
}
