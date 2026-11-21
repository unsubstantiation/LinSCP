//! Atomic JSON configuration stores (`preferences.json`, `bookmarks.json`,
//! and `workspaces.json`) shared by HTTP and Tauri hosts.

use std::collections::BTreeMap;
use std::path::Path;

use linscp_platform::write_private_file_atomic;
use linscp_proto::remote_desktop::{
    install_script_for_kind, x2go_xfce_install_script, RemoteDesktopKind,
};
use linscp_types::{BookmarkEntry, UserPreferences, WorkspaceSnapshot};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Upper bound on a customized remote installer script stored in preferences or
/// submitted for execution.
pub const MAX_CUSTOM_INSTALL_SCRIPT_BYTES: usize = 64 * 1024;

/// Canonical installer script targets customizable by the user.
pub const INSTALL_SCRIPT_TARGETS: &[&str] = &[
    "mosh",
    "rdp",
    "vnc",
    "spice",
    "x2go",
    "x2go_xfce",
    "x11",
];

/// Maps a target or protocol alias to its canonical installer script key.
pub fn canonical_install_script_target(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "mosh" => Some("mosh"),
        "rdp" | "xrdp" => Some("rdp"),
        "vnc" | "tigervnc" => Some("vnc"),
        "spice" => Some("spice"),
        "x2go" => Some("x2go"),
        "x2go_xfce" | "x2go-xfce" | "xfce" => Some("x2go_xfce"),
        "x11" | "x11-forwarding" | "ssh-x11" => Some("x11"),
        _ => None,
    }
}

/// Returns the shipped built-in installer script for a canonical or aliased target.
pub fn default_install_script_for_target(target: &str) -> Option<String> {
    match canonical_install_script_target(target)? {
        "mosh" => Some(linscp_proto::mosh::mosh_install_script()),
        "rdp" => Some(install_script_for_kind(RemoteDesktopKind::Rdp)),
        "vnc" => Some(install_script_for_kind(RemoteDesktopKind::Vnc)),
        "spice" => Some(install_script_for_kind(RemoteDesktopKind::Spice)),
        "x2go" => Some(install_script_for_kind(RemoteDesktopKind::X2Go)),
        "x2go_xfce" => Some(x2go_xfce_install_script().to_string()),
        "x11" => Some(install_script_for_kind(RemoteDesktopKind::X11)),
        _ => None,
    }
}

/// Validates and normalizes an edited or customized installer script (CRLF -> LF,
/// non-empty, no NUL bytes, bounded to `MAX_CUSTOM_INSTALL_SCRIPT_BYTES`).
pub fn normalize_install_script_text(raw: &str) -> Result<String, String> {
    if raw.contains('\0') {
        return Err("Installer script must not contain NUL bytes.".to_string());
    }
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    if normalized.len() > MAX_CUSTOM_INSTALL_SCRIPT_BYTES {
        return Err("Installer script exceeds the 64 KiB limit.".to_string());
    }
    if normalized.trim().is_empty() {
        return Err("Installer script must not be empty.".to_string());
    }
    Ok(normalized)
}

/// Validates and canonicalizes a `custom_install_scripts` map. Entries identical
/// to the shipped built-in script are omitted so `is_custom` reflects actual changes.
pub fn sanitize_custom_install_scripts_map(
    raw: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut cleaned = BTreeMap::new();
    for (key, value) in raw {
        let Some(canon) = canonical_install_script_target(key) else {
            return Err(format!("Unsupported installer script target '{key}'."));
        };
        let normalized = normalize_install_script_text(value)?;
        let default_norm = default_install_script_for_target(canon)
            .map(|d| d.replace("\r\n", "\n").replace('\r', "\n"))
            .unwrap_or_default();
        if normalized != default_norm {
            cleaned.insert(canon.to_string(), normalized);
        }
    }
    Ok(cleaned)
}

/// Resolves `(effective_script, default_script, is_custom)` for `target`.
pub fn resolve_install_script(
    prefs: &UserPreferences,
    target: &str,
) -> Option<(String, String, bool)> {
    let canon = canonical_install_script_target(target)?;
    let default_script = default_install_script_for_target(canon)?;
    if let Some(custom_raw) = prefs.custom_install_scripts.get(canon) {
        if let Ok(normalized) = normalize_install_script_text(custom_raw) {
            if normalized != default_script {
                return Some((normalized, default_script, true));
            }
        }
    }
    Some((default_script.clone(), default_script, false))
}

fn read_json_or_default<T: DeserializeOwned + Default>(path: &Path) -> Result<T, String> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .map_err(|err| format!("Invalid JSON in {}: {err}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(err) => Err(format!("Cannot read {}: {err}", path.display())),
    }
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let mut rendered = serde_json::to_vec_pretty(value)
        .map_err(|err| format!("Cannot serialize {}: {err}", path.display()))?;
    rendered.push(b'\n');
    write_private_file_atomic(path, &rendered).map_err(|err| err.to_string())
}

pub struct PreferencesStore;

impl PreferencesStore {
    pub fn load(config_dir: &Path) -> Result<UserPreferences, String> {
        read_json_or_default(&config_dir.join("preferences.json"))
    }

    pub fn save(config_dir: &Path, prefs: &UserPreferences) -> Result<(), String> {
        write_json_atomic(&config_dir.join("preferences.json"), prefs)
    }
}

pub struct BookmarksStore;

impl BookmarksStore {
    pub fn load(config_dir: &Path) -> Result<Vec<BookmarkEntry>, String> {
        read_json_or_default(&config_dir.join("bookmarks.json"))
    }

    pub fn save(config_dir: &Path, bookmarks: &[BookmarkEntry]) -> Result<(), String> {
        write_json_atomic(&config_dir.join("bookmarks.json"), &bookmarks)
    }
}

pub struct WorkspacesStore;

impl WorkspacesStore {
    pub fn load(config_dir: &Path) -> Result<Vec<WorkspaceSnapshot>, String> {
        read_json_or_default(&config_dir.join("workspaces.json"))
    }

    pub fn save(config_dir: &Path, workspaces: &[WorkspaceSnapshot]) -> Result<(), String> {
        write_json_atomic(&config_dir.join("workspaces.json"), &workspaces)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linscp_types::WorkspaceTabSnapshot;

    #[test]
    fn json_stores_round_trip_preferences_bookmarks_and_workspaces() {
        let dir = std::env::temp_dir().join(format!(
            "linscp-json-stores-{}",
            std::process::id()
        ));
        let prefs = UserPreferences {
            filemask: "*.rs".to_string(),
            newer_only: true,
            ..UserPreferences::default()
        };
        PreferencesStore::save(&dir, &prefs).unwrap();
        assert_eq!(PreferencesStore::load(&dir).unwrap(), prefs);

        let bookmarks = vec![BookmarkEntry {
            name: "Releases".to_string(),
            session_name: "prod".to_string(),
            remote_dir: "/var/www/releases".to_string(),
            local_dir: "/tmp/build".to_string(),
        }];
        BookmarksStore::save(&dir, &bookmarks).unwrap();
        assert_eq!(BookmarksStore::load(&dir).unwrap(), bookmarks);

        let workspaces = vec![WorkspaceSnapshot {
            name: "Deploy".to_string(),
            tabs: vec![WorkspaceTabSnapshot {
                session_name: "prod".to_string(),
                remote_dir: "/srv/app".to_string(),
                local_dir: "/tmp".to_string(),
            }],
            active_index: 0,
        }];
        WorkspacesStore::save(&dir, &workspaces).unwrap();
        assert_eq!(WorkspacesStore::load(&dir).unwrap(), workspaces);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn custom_install_scripts_normalize_crlf_enforce_bounds_and_fall_back_to_defaults() {
        for &target in INSTALL_SCRIPT_TARGETS {
            let prefs = UserPreferences::default();
            let (effective, default_script, is_custom) =
                resolve_install_script(&prefs, target).expect("known target");
            assert!(!is_custom);
            assert_eq!(effective, default_script);
            assert!(default_script.starts_with("#!/bin/bash\n"));
        }

        assert_eq!(
            normalize_install_script_text("#!/bin/sh\r\necho custom\r\n").unwrap(),
            "#!/bin/sh\necho custom\n"
        );
        assert!(normalize_install_script_text("   \n\t  ").is_err());
        assert!(normalize_install_script_text("#!/bin/sh\necho \0 bad\n").is_err());
        assert!(
            normalize_install_script_text(&"x".repeat(MAX_CUSTOM_INSTALL_SCRIPT_BYTES + 1))
                .is_err()
        );

        let mut raw = BTreeMap::new();
        raw.insert("XFCE".to_string(), "#!/bin/sh\r\ndoas apk add xfce4\r\n".to_string());
        raw.insert(
            "mosh".to_string(),
            default_install_script_for_target("mosh").unwrap(),
        );
        let cleaned = sanitize_custom_install_scripts_map(&raw).unwrap();
        assert_eq!(cleaned.len(), 1);
        assert_eq!(
            cleaned.get("x2go_xfce").map(String::as_str),
            Some("#!/bin/sh\ndoas apk add xfce4\n")
        );

        let mut prefs = UserPreferences::default();
        prefs.custom_install_scripts = cleaned;
        let (xfce_eff, xfce_def, xfce_custom) =
            resolve_install_script(&prefs, "x2go_xfce").unwrap();
        assert!(xfce_custom);
        assert_eq!(xfce_eff, "#!/bin/sh\ndoas apk add xfce4\n");
        assert_ne!(xfce_eff, xfce_def);

        let (mosh_eff, mosh_def, mosh_custom) = resolve_install_script(&prefs, "mosh").unwrap();
        assert!(!mosh_custom);
        assert_eq!(mosh_eff, mosh_def);
    }
}
