//! Atomic JSON configuration stores (`preferences.json`, `bookmarks.json`,
//! and `workspaces.json`) shared by HTTP and Tauri hosts.

use std::path::Path;

use linscp_platform::write_private_file_atomic;
use linscp_types::{BookmarkEntry, UserPreferences, WorkspaceSnapshot};
use serde::de::DeserializeOwned;
use serde::Serialize;

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
}
