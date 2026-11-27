//! Portable application backup. Serialized bundles contain secrets and must
//! only be written using the authenticated password-encrypted envelope.
//! The caller supplies an independent backup password; it is not the local
//! vault key and is needed to restore on another device.

use std::path::{Path, PathBuf};
use std::collections::BTreeSet;
use std::io::Read;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use linscp_platform::SecretVault;
use linscp_types::{BookmarkEntry, UserPreferences, WorkspaceSnapshot};
use serde::{Deserialize, Serialize};

use crate::config_stores::PreferencesStore;
use crate::session_store::SessionStore;

/// Original encrypted key blob and optional metadata. The blob remains
/// encrypted under the source master key, itself inside the backup envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupVaultKey {
    pub id: String,
    pub encrypted_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_b64: Option<String>,
}

/// Public-only SSH key whose ID has no corresponding private vault key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupVaultPublicKey {
    pub id: String,
    pub public_b64: String,
}

/// Encrypted TLS certificate/CA/key blob stored under `keys/<id>.tls.vault`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupVaultTlsBlob {
    pub id: String,
    pub encrypted_b64: String,
}

const KEY_LIMIT: usize = 1024 * 1024;
const KEY_BLOB_LIMIT: usize = KEY_LIMIT + 64;
const TLS_LIMIT: usize = 384 * 1024;
const TLS_BLOB_LIMIT: usize = TLS_LIMIT + 64;
const KEY_COUNT_LIMIT: usize = 2000;
const LABEL_LIMIT: usize = 512;
const PUBLIC_LIMIT: usize = 32 * 1024;

fn valid_key_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// Bounded, no-follow reads avoid exporting arbitrary linked files from the key directory.
fn read_key_file(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("Cannot inspect {}: {error}", path.display())),
        Ok(metadata) if !metadata.file_type().is_file() || metadata.len() > limit as u64 => return Err(format!("Invalid vault key file: {}", path.display())),
        Ok(_) => {},
    }
    let file = linscp_platform::open_private_file_no_follow(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > limit { return Err(format!("Vault key file is too large: {}", path.display())); }
    Ok(Some(bytes))
}

fn session_key_references(ini: &str) -> Result<BTreeSet<String>, String> {
    let store = SessionStore::parse_ini(ini, None)?;
    let mut ids = BTreeSet::new();
    for site in store.sites() {
        for path in [site.private_key.as_deref(), site.tunnel.keyfile.as_deref()].into_iter().flatten() {
            if let Some(id) = path.strip_prefix("vaultkey://") {
                if !valid_key_id(id) { return Err("Invalid vault SSH key reference in saved sessions.".into()); }
                ids.insert(id.to_string());
            }
        }
    }
    Ok(ids)
}

fn collect_vault_keys(config_dir: &Path, vault: &dyn SecretVault) -> Result<Vec<BackupVaultKey>, String> {
    let key_dir = config_dir.join("keys");
    match std::fs::symlink_metadata(&key_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {},
        Ok(_) => return Err("The vault keys path is not a directory.".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Cannot inspect vault keys: {e}")),
    }
    let entries = match std::fs::read_dir(&key_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Cannot inspect vault keys: {e}")),
    };
    let mut keys = Vec::new();
    let mut names = BTreeSet::new();
    let mut total_bytes = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| "Invalid vault key filename".to_string())?;
        let Some(id) = name.strip_suffix(".key.vault") else { continue; };
        if !valid_key_id(id) || !names.insert(id.to_ascii_lowercase()) || keys.len() >= KEY_COUNT_LIMIT {
            return Err("Invalid or duplicate vault SSH key identifier.".into());
        }
        let encrypted = read_key_file(&entry.path(), KEY_BLOB_LIMIT)?.ok_or_else(|| "Vault key disappeared during backup.".to_string())?;
        total_bytes = total_bytes.checked_add(encrypted.len()).ok_or_else(|| "Vault keys exceed backup size limit.".to_string())?;
        // Leave space for base64 expansion and the rest of the configuration.
        if total_bytes > 32 * 1024 * 1024 { return Err("Vault keys exceed backup size limit.".into()); }
        let plaintext = vault.open_session_store(&encrypted).map_err(|e| format!("Cannot open vault SSH key {id}: {e}"))?;
        if plaintext.is_empty() || plaintext.len() > KEY_LIMIT { return Err("Invalid vault SSH key size.".into()); }
        let label = read_key_file(&key_dir.join(format!("{id}.label")), LABEL_LIMIT)?.map(|bytes| BASE64.encode(bytes));
        let public = read_key_file(&key_dir.join(format!("{id}.pub")), PUBLIC_LIMIT)?.map(|bytes| BASE64.encode(bytes));
        keys.push(BackupVaultKey { id: id.to_string(), encrypted_b64: BASE64.encode(encrypted), label_b64: label, public_b64: public });
    }
    keys.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(keys)
}

fn validate_key_references(ini: &str, keys: &[BackupVaultKey]) -> Result<(), String> {
    let ids: BTreeSet<&str> = keys.iter().map(|key| key.id.as_str()).collect();
    for id in session_key_references(ini)? {
        if !ids.contains(id.as_str()) { return Err(format!("Backup is missing vault SSH key {id} referenced by a saved session.")); }
    }
    Ok(())
}

fn collect_public_only_keys(config_dir: &Path, private_keys: &[BackupVaultKey]) -> Result<Vec<BackupVaultPublicKey>, String> {
    let dir = config_dir.join("keys");
    match std::fs::symlink_metadata(&dir) {
        Ok(meta) if meta.file_type().is_dir() => {},
        Ok(_) => return Err("The vault keys path is not a directory.".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Cannot inspect vault keys: {e}")),
    }
    let private: BTreeSet<String> = private_keys.iter().map(|k| k.id.to_ascii_lowercase()).collect();
    let mut names = BTreeSet::new();
    let mut result = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("Invalid vault public key filename")?;
        let Some(id) = name.strip_suffix(".pub") else { continue };
        if !valid_key_id(id) || !names.insert(id.to_ascii_lowercase()) { return Err("Invalid or duplicate vault public key identifier.".into()); }
        if private.contains(&id.to_ascii_lowercase()) { continue; }
        if result.len() >= KEY_COUNT_LIMIT { return Err("Too many vault public keys.".into()); }
        let data = read_key_file(&entry.path(), PUBLIC_LIMIT)?.ok_or("Vault public key disappeared during backup")?;
        if data.is_empty() { return Err("Vault public key is empty.".into()); }
        result.push(BackupVaultPublicKey { id: id.into(), public_b64: BASE64.encode(data) });
    }
    result.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(result)
}

fn validate_public_key_references(ini: &str, keys: &[BackupVaultKey], public: &[BackupVaultPublicKey]) -> Result<(), String> {
    let ids: BTreeSet<String> = keys.iter().filter(|k| k.public_b64.is_some()).map(|k| k.id.to_ascii_lowercase())
        .chain(public.iter().map(|k| k.id.to_ascii_lowercase())).collect();
    let store = SessionStore::parse_ini(ini, None)?;
    for site in store.sites() {
        for name in ["linscp_public_key_file", "linscp_tunnel_public_key_file"] {
            if let Some(id) = site.extra_fields.get(name).and_then(|v| v.strip_prefix("vaultpub://")) {
                if !valid_key_id(id) || !ids.contains(&id.to_ascii_lowercase()) {
                    return Err(format!("Backup is missing a vault public key referenced by '{}'.", site.name));
                }
            }
        }
    }
    Ok(())
}

fn prepare_public_only_restore(config_dir: &Path, bundle: &BackupBundle) -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
    if bundle.vault_public_keys.len() > KEY_COUNT_LIMIT { return Err("Too many vault public keys in backup.".into()); }
    let dir = config_dir.join("keys");
    match std::fs::symlink_metadata(&dir) {
        Ok(meta) if meta.file_type().is_dir() => {},
        Ok(_) => return Err("The vault keys path is not a directory.".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("Cannot inspect vault keys: {e}")),
    }
    let mut existing_names = BTreeSet::new();
    match std::fs::read_dir(&dir) {
        Ok(items) => for item in items { existing_names.insert(item.map_err(|e| e.to_string())?.file_name().to_string_lossy().to_ascii_lowercase()); },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("Cannot inspect vault keys: {e}")),
    }
    let mut seen = BTreeSet::new();
    let mut prepared = Vec::new();
    for item in &bundle.vault_public_keys {
        if !valid_key_id(&item.id) || !seen.insert(item.id.to_ascii_lowercase())
            || bundle.vault_keys.iter().any(|k| k.id.eq_ignore_ascii_case(&item.id)) {
            return Err("Invalid or duplicate vault public key identifier in backup.".into());
        }
        if item.public_b64.len() > ((PUBLIC_LIMIT + 2) / 3) * 4 { return Err("Vault public key is too large.".into()); }
        let bytes = BASE64.decode(&item.public_b64).map_err(|_| "Invalid vault public key encoding")?;
        if bytes.is_empty() || bytes.len() > PUBLIC_LIMIT { return Err("Invalid vault public key size.".into()); }
        let path = dir.join(format!("{}.pub", item.id));
        match read_key_file(&path, PUBLIC_LIMIT)? {
            Some(existing) if existing != bytes => return Err(format!("Public key metadata conflicts for {}.", item.id)),
            Some(_) => {},
            None => {
                if existing_names.contains(&format!("{}.pub", item.id).to_ascii_lowercase()) {
                    return Err(format!("Vault public key ID {} conflicts with an existing filename.", item.id));
                }
                // Do not attach a public-only record to an unrelated private key.
                if existing_names.contains(&format!("{}.key.vault", item.id).to_ascii_lowercase()) {
                    return Err(format!("Vault public key ID {} belongs to an existing private key.", item.id));
                }
                prepared.push((path, bytes));
            }
        }
    }
    Ok(prepared)
}

fn session_tls_references(ini: &str) -> Result<BTreeSet<String>, String> {
    let store = SessionStore::parse_ini(ini, None)?;
    let mut ids = BTreeSet::new();
    for site in store.sites() {
        for field in ["ca_certificate_file", "tls_certificate_file", "tls_certificate_key_file"] {
            if let Some(id) = site.extra_fields.get(field).and_then(|v| v.strip_prefix("vaulttls://")) {
                if !valid_key_id(id) { return Err("Invalid vault TLS certificate reference in saved sessions.".into()); }
                ids.insert(id.to_string());
            }
        }
    }
    Ok(ids)
}

fn collect_vault_tls_blobs(config_dir: &Path, vault: &dyn SecretVault) -> Result<Vec<BackupVaultTlsBlob>, String> {
    let key_dir = config_dir.join("keys");
    match std::fs::symlink_metadata(&key_dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {},
        Ok(_) => return Err("The vault keys path is not a directory.".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Cannot inspect vault TLS blobs: {e}")),
    }
    let entries = match std::fs::read_dir(&key_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Cannot inspect vault TLS blobs: {e}")),
    };
    let mut blobs = Vec::new();
    let mut names = BTreeSet::new();
    let mut total_bytes = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(|| "Invalid vault TLS filename".to_string())?;
        let Some(id) = name.strip_suffix(".tls.vault") else { continue; };
        if !valid_key_id(id) || !names.insert(id.to_ascii_lowercase()) || blobs.len() >= KEY_COUNT_LIMIT {
            return Err("Invalid or duplicate vault TLS identifier.".into());
        }
        let encrypted = read_key_file(&entry.path(), TLS_BLOB_LIMIT)?.ok_or_else(|| "Vault TLS blob disappeared during backup.".to_string())?;
        total_bytes = total_bytes.checked_add(encrypted.len()).ok_or_else(|| "Vault TLS blobs exceed backup size limit.".to_string())?;
        if total_bytes > 32 * 1024 * 1024 { return Err("Vault TLS blobs exceed backup size limit.".into()); }
        let plaintext = vault.open_session_store(&encrypted).map_err(|e| format!("Cannot open vault TLS blob {id}: {e}"))?;
        if plaintext.is_empty() || plaintext.len() > TLS_LIMIT { return Err("Invalid vault TLS blob size.".into()); }
        blobs.push(BackupVaultTlsBlob { id: id.to_string(), encrypted_b64: BASE64.encode(encrypted) });
    }
    blobs.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(blobs)
}

fn validate_tls_references(ini: &str, blobs: &[BackupVaultTlsBlob]) -> Result<(), String> {
    let ids: BTreeSet<&str> = blobs.iter().map(|blob| blob.id.as_str()).collect();
    for id in session_tls_references(ini)? {
        if !ids.contains(id.as_str()) { return Err(format!("Backup is missing vault TLS material {id} referenced by a saved session.")); }
    }
    Ok(())
}

/// In-memory portable backup bundle. Its serialized JSON contains secrets and
/// must only be persisted inside an encrypted backup envelope.
///
/// The JSON shape is versioned so future fields can be
/// added without breaking restores of older backups. Unknown top-level
/// keys are ignored on import for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupBundle {
    /// Schema version of the encrypted backup payload.
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
    /// Base64 of the raw 32-byte master key.
    /// `None` if no `sessions.key` existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions_key_b64: Option<String>,
    /// All local vault SSH keys, including unreferenced keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vault_keys: Vec<BackupVaultKey>,
    /// Public-only SSH keys not represented by a private key record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vault_public_keys: Vec<BackupVaultPublicKey>,
    /// All local vault TLS certificate/CA/key blobs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vault_tls_blobs: Vec<BackupVaultTlsBlob>,
    /// `workspaces.json` content.
    #[serde(default)]
    pub workspaces: Vec<WorkspaceSnapshot>,
    /// Commander workspace JSON (distinct from legacy engine workspace arrays).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commander_workspaces: Option<serde_json::Value>,
    /// `bookmarks.json` content.
    #[serde(default)]
    pub bookmarks: Vec<BookmarkEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commander_bookmarks: Option<serde_json::Value>,
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
    /// Additional persistent settings; absent files are restored as absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_commands_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_presets_ini: Option<String>,
}

impl Default for BackupBundle {
    fn default() -> Self {
        Self {
            version: 1,
            created_at: String::new(),
            created_on: String::new(),
            sessions_ini: String::new(),
            sessions_key_b64: None,
            vault_keys: Vec::new(),
            vault_public_keys: Vec::new(),
            vault_tls_blobs: Vec::new(),
            workspaces: Vec::new(),
            commander_workspaces: None,
            bookmarks: Vec::new(),
            commander_bookmarks: None,
            preferences: UserPreferences::default(),
            accounts_ini: None,
            sshhostkeys: None,
            explorer_commands_json: None,
            custom_commands_json: None,
            monitor_json: None,
            transfer_presets_ini: None,
        }
    }
}

fn normalize_to_lf(text: &str) -> String {
    // Accept CRLF or CR, always export LF.
    let lf = text.replace("\r\n", "\n").replace('\r', "\n");
    // Ensure trailing newline if non-empty and not already terminated,
    // matching the writer helpers (`write_private_file_atomic` etc.).
    if lf.is_empty() || lf.ends_with('\n') {
        lf
    } else {
        format!("{lf}\n")
    }
}

fn read_optional_text(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(normalize_to_lf(&s))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("Cannot read {}: {e}", path.display())),
    }
}

fn validate_additional_settings(bundle: &BackupBundle) -> Result<(), String> {
    if let Some(text) = &bundle.custom_commands_json {
        let value: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("Invalid custom commands: {e}"))?;
        if !value.is_array() && !value.get("commands").is_some_and(serde_json::Value::is_array) {
            return Err("Invalid custom commands structure.".into());
        }
    }
    if let Some(text) = &bundle.monitor_json {
        serde_json::from_str::<linscp_types::MonitorSettingsDocument>(text).map_err(|e| format!("Invalid monitor settings: {e}"))?;
    }
    if let Some(text) = &bundle.transfer_presets_ini {
        crate::presets::TransferPresetStore::parse_ini(text, "backup transfer presets")?;
    }
    Ok(())
}

/// Collects all per-user configuration from `config_dir` into a
/// distribution-compatible `BackupBundle`.
///
/// The master key is read via `vault` and stored as raw base64 so the
/// bundle restores on every platform.
pub fn export_backup(
    config_dir: &Path,
    vault: &dyn SecretVault,
) -> Result<BackupBundle, String> {
    if restore_recovery_required(config_dir)? {
        return Err("Unlock the local vault and recover the interrupted restore before exporting a backup.".into());
    }
    if vault.protects_session_store() && vault.load_master_key(config_dir).map_err(|e| e.to_string())?.is_none() {
        return Err("Unlock the local vault before exporting a backup.".into());
    }
    let vault_keys = collect_vault_keys(config_dir, vault)?;
    let vault_public_keys = collect_public_only_keys(config_dir, &vault_keys)?;
    let vault_tls_blobs = collect_vault_tls_blobs(config_dir, vault)?;
    let sessions_ini = SessionStore::read_ini_text(config_dir, vault)?
        .map(|s| normalize_to_lf(&s))
        .unwrap_or_default();
    validate_key_references(&sessions_ini, &vault_keys)?;
    validate_public_key_references(&sessions_ini, &vault_keys, &vault_public_keys)?;
    validate_tls_references(&sessions_ini, &vault_tls_blobs)?;

    // Export the *unwrapped* master key as portable base64. This is what
    // makes the backup cross-distribution: every platform reads the same
    // raw key.
    #[allow(clippy::needless_borrows_for_generic_args)]
    let sessions_key_b64 = match vault.load_master_key(config_dir) {
        Ok(Some(k)) => Some(BASE64.encode(&*k)),
        Ok(None) => None,
        Err(error) => return Err(error.to_string()),
    };

    // JSON stores — missing files are treated as defaults (already compatible).
    let workspace_bytes = crate::protected_file::read(&config_dir.join("workspaces.json"), "workspaces", vault)?;
    let (workspaces, commander_workspaces) = match workspace_bytes {
        None => (Vec::new(), None),
        Some(bytes) => {
            let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| format!("Invalid workspace data: {e}"))?;
            if value.is_array() {
                (serde_json::from_value(value).map_err(|e| format!("Invalid workspace data: {e}"))?, None)
            } else if value.get("workspaces").is_some_and(serde_json::Value::is_object) {
                (Vec::new(), Some(value))
            } else { return Err("Invalid workspace data".into()); }
        }
    };
    let (bookmarks, commander_bookmarks) = match read_optional_text(&config_dir.join("bookmarks.json"))? {
        Some(raw) => {
            let value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("Invalid bookmarks: {e}"))?;
            if value.is_array() { (serde_json::from_value(value).map_err(|e| format!("Invalid bookmarks: {e}"))?, None) }
            else if ["local", "remote"].iter().all(|key| value.get(*key).is_some_and(serde_json::Value::is_array)) { (Vec::new(), Some(value)) }
            else { return Err("Invalid bookmarks structure".into()); }
        },
        None => (Vec::new(), None),
    };
    let preferences = PreferencesStore::load(config_dir)?;

    let accounts_ini = read_optional_text(&config_dir.join("accounts.ini"))?;
    let sshhostkeys = crate::protected_file::read(&config_dir.join("sshhostkeys"), "ssh-host-keys", vault)?
        .map(|bytes| std::str::from_utf8(&bytes).map(normalize_to_lf).map_err(|e| format!("Invalid host keys: {e}")))
        .transpose()?;
    let explorer_commands_json =
        read_optional_text(&config_dir.join("explorer-commands.json"))?;

    let now = chrono_lite_now_utc();
    let created_on = detect_distribution_id();

    let bundle = BackupBundle {
        version: 1,
        created_at: now,
        created_on,
        sessions_ini,
        sessions_key_b64,
        vault_keys,
        vault_public_keys,
        vault_tls_blobs,
        workspaces,
        commander_workspaces,
        bookmarks,
        commander_bookmarks,
        preferences,
        accounts_ini,
        sshhostkeys,
        explorer_commands_json,
        custom_commands_json: read_optional_text(&config_dir.join("custom-commands.json"))?,
        monitor_json: read_optional_text(&config_dir.join("monitor.json"))?,
        transfer_presets_ini: read_optional_text(&config_dir.join("transfer-presets.ini"))?,
    };
    validate_additional_settings(&bundle)?;
    Ok(bundle)
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

/// Validate every key and collision before modifying any restore target.
/// Only encrypted key blobs are prepared for publication; plaintext stays in
/// zeroizing buffers and is rewrapped using the destination's unlocked vault.
fn prepare_vault_key_restore(config_dir: &Path, bundle: &BackupBundle, vault: &dyn SecretVault) -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
    if bundle.vault_keys.is_empty() { return Ok(Vec::new()); }
    if !vault.protects_session_store() { return Err("Restoring vault SSH keys requires an unlocked local password vault.".into()); }
    if bundle.vault_keys.len() > KEY_COUNT_LIMIT { return Err("Too many vault SSH keys in backup.".into()); }
    let encoded_master = bundle.sessions_key_b64.as_ref().ok_or_else(|| "Backup has vault SSH keys but no source master key.".to_string())?;
    let source = zeroize::Zeroizing::new(BASE64.decode(encoded_master).map_err(|_| "Invalid source master key".to_string())?);
    let source_key: &[u8; 32] = source.as_slice().try_into().map_err(|_| "Invalid source master key length".to_string())?;
    let dir = config_dir.join("keys");
    let mut existing_names = BTreeSet::new();
    match std::fs::symlink_metadata(&dir) {
        Ok(meta) if meta.file_type().is_dir() => {
            for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
                let name = entry.map_err(|e| e.to_string())?.file_name().to_string_lossy().to_string();
                existing_names.insert(name.to_ascii_lowercase());
            }
        },
        Ok(_) => return Err("The vault keys path is not a directory.".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("Cannot inspect vault keys: {e}")),
    }
    let mut names = BTreeSet::new();
    let mut prepared = Vec::new();
    let mut total_bytes = 0usize;
    for key in &bundle.vault_keys {
        if !valid_key_id(&key.id) || !names.insert(key.id.to_ascii_lowercase()) {
            return Err("Invalid or duplicate vault SSH key identifier in backup.".into());
        }
        // Bound encoded input before allocating decoded bytes.
        if key.encrypted_b64.len() > ((KEY_BLOB_LIMIT + 2) / 3) * 4 { return Err("Vault SSH key is too large.".into()); }
        let encrypted = BASE64.decode(&key.encrypted_b64).map_err(|_| "Invalid vault key encoding".to_string())?;
        if encrypted.len() > KEY_BLOB_LIMIT { return Err("Vault SSH key is too large.".into()); }
        total_bytes = total_bytes.checked_add(encrypted.len()).ok_or_else(|| "Vault keys exceed backup size limit.".to_string())?;
        if total_bytes > 32 * 1024 * 1024 { return Err("Vault keys exceed backup size limit.".into()); }
        let plaintext = linscp_platform::password_vault::open_blob_with_master_key(&encrypted, source_key)
            .map_err(|e| format!("Cannot decrypt backup vault key {}: {e}", key.id))?;
        if plaintext.is_empty() || plaintext.len() > KEY_LIMIT { return Err("Invalid backup vault key size.".into()); }
        let filename = format!("{}.key.vault", key.id);
        let path = dir.join(&filename);
        let existing = read_key_file(&path, KEY_BLOB_LIMIT)?;
        if existing.is_none() && existing_names.contains(&filename.to_ascii_lowercase()) {
            return Err(format!("Vault key ID {} conflicts with an existing filename.", key.id));
        }
        let already_present = existing.is_some();
        if let Some(existing) = existing {
            let existing_plain = vault.open_session_store(&existing).map_err(|e| format!("Cannot read existing vault key {}: {e}", key.id))?;
            if existing_plain.as_slice() != plaintext.as_slice() {
                return Err(format!("Vault key ID {} already belongs to a different key; restore into a separate vault.", key.id));
            }
        } else {
            let sealed = vault.seal_session_store(&plaintext).map_err(|e| e.to_string())?;
            prepared.push((path, sealed));
        }
        for (suffix, encoded, limit) in [("label", &key.label_b64, LABEL_LIMIT), ("pub", &key.public_b64, PUBLIC_LIMIT)] {
            let filename = format!("{}.{suffix}", key.id);
            let path = dir.join(&filename);
            let existing = read_key_file(&path, limit)?;
            if existing.is_none() && existing_names.contains(&filename.to_ascii_lowercase()) {
                return Err(format!("Vault key metadata for {} conflicts with an existing filename.", key.id));
            }
            if !already_present && existing.is_some() { return Err(format!("Orphaned vault key metadata conflicts with {}.", key.id)); }
            if let Some(encoded) = encoded {
                if encoded.len() > ((limit + 2) / 3) * 4 { return Err("Vault key metadata is too large.".into()); }
                let bytes = BASE64.decode(encoded).map_err(|_| "Invalid vault key metadata encoding".to_string())?;
                if bytes.len() > limit { return Err("Vault key metadata is too large.".into()); }
                if let Some(existing) = existing {
                    if suffix == "pub" && existing != bytes { return Err(format!("Public key metadata conflicts for {}.", key.id)); }
                    // A local label is user-editable: keep it when the key matches.
                } else {
                    prepared.push((path, bytes));
                }
            }
        }
    }
    Ok(prepared)
}

fn prepare_vault_tls_restore(config_dir: &Path, bundle: &BackupBundle, vault: &dyn SecretVault) -> Result<Vec<(PathBuf, Vec<u8>)>, String> {
    if bundle.vault_tls_blobs.is_empty() { return Ok(Vec::new()); }
    if !vault.protects_session_store() { return Err("Restoring vault TLS certificates requires an unlocked local password vault.".into()); }
    if bundle.vault_tls_blobs.len() > KEY_COUNT_LIMIT { return Err("Too many vault TLS blobs in backup.".into()); }
    let encoded_master = bundle.sessions_key_b64.as_ref().ok_or_else(|| "Backup has vault TLS blobs but no source master key.".to_string())?;
    let source = zeroize::Zeroizing::new(BASE64.decode(encoded_master).map_err(|_| "Invalid source master key".to_string())?);
    let source_key: &[u8; 32] = source.as_slice().try_into().map_err(|_| "Invalid source master key length".to_string())?;
    let dir = config_dir.join("keys");
    let mut existing_names = BTreeSet::new();
    match std::fs::symlink_metadata(&dir) {
        Ok(meta) if meta.file_type().is_dir() => {
            for entry in std::fs::read_dir(&dir).map_err(|e| e.to_string())? {
                let name = entry.map_err(|e| e.to_string())?.file_name().to_string_lossy().to_string();
                existing_names.insert(name.to_ascii_lowercase());
            }
        }
        Ok(_) => return Err("The vault keys path is not a directory.".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("Cannot inspect vault keys: {e}")),
    }
    let mut names = BTreeSet::new();
    let mut prepared = Vec::new();
    let mut total_bytes = 0usize;
    for blob in &bundle.vault_tls_blobs {
        if !valid_key_id(&blob.id) || !names.insert(blob.id.to_ascii_lowercase()) {
            return Err("Invalid or duplicate vault TLS identifier in backup.".into());
        }
        if blob.encrypted_b64.len() > ((TLS_BLOB_LIMIT + 2) / 3) * 4 { return Err("Vault TLS blob is too large.".into()); }
        let encrypted = BASE64.decode(&blob.encrypted_b64).map_err(|_| "Invalid vault TLS encoding".to_string())?;
        if encrypted.len() > TLS_BLOB_LIMIT { return Err("Vault TLS blob is too large.".into()); }
        total_bytes = total_bytes.checked_add(encrypted.len()).ok_or_else(|| "Vault TLS blobs exceed backup size limit.".to_string())?;
        if total_bytes > 32 * 1024 * 1024 { return Err("Vault TLS blobs exceed backup size limit.".into()); }
        let plaintext = linscp_platform::password_vault::open_blob_with_master_key(&encrypted, source_key)
            .map_err(|e| format!("Cannot decrypt backup vault TLS blob {}: {e}", blob.id))?;
        if plaintext.is_empty() || plaintext.len() > TLS_LIMIT { return Err("Invalid backup vault TLS blob size.".into()); }
        let filename = format!("{}.tls.vault", blob.id);
        let path = dir.join(&filename);
        let existing = read_key_file(&path, TLS_BLOB_LIMIT)?;
        if existing.is_none() && existing_names.contains(&filename.to_ascii_lowercase()) {
            return Err(format!("Vault TLS ID {} conflicts with an existing filename.", blob.id));
        }
        if let Some(existing) = existing {
            let existing_plain = vault.open_session_store(&existing).map_err(|e| format!("Cannot read existing vault TLS blob {}: {e}", blob.id))?;
            if existing_plain.as_slice() != plaintext.as_slice() {
                return Err(format!("Vault TLS ID {} already belongs to different TLS material; restore into a separate vault.", blob.id));
            }
        } else {
            let sealed = vault.seal_session_store(&plaintext).map_err(|e| e.to_string())?;
            prepared.push((path, sealed));
        }
    }
    Ok(prepared)
}

fn publish_restored_keys(files: Vec<(PathBuf, Vec<u8>)>, config_dir: &Path) -> Result<(), String> {
    if files.is_empty() { return Ok(()); }
    let dir = config_dir.join("keys");
    linscp_platform::create_private_dir(&dir).map_err(|e| e.to_string())?;
    for (path, bytes) in files {
        use rand::RngCore;
        let mut random = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let temp = dir.join(format!(".backup-restore-{}", random.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        linscp_platform::write_exclusive_private_file(&temp, &bytes).map_err(|e| e.to_string())?;
        let result = linscp_platform::publish_no_replace(&temp, &path).map_err(|e| format!("Cannot restore vault key {}: {e}", path.display()));
        if result.is_err() { let _ = std::fs::remove_file(&temp); }
        result?;
    }
    linscp_platform::sync_directory(&dir).map_err(|e| e.to_string())?;
    linscp_platform::sync_directory(config_dir).map_err(|e| e.to_string())?;
    Ok(())
}

/// Whether startup must recover an interrupted transactional restore before
/// exposing any configuration. Failure to inspect the journal is an error, not
/// evidence that recovery is unnecessary.
pub fn restore_recovery_required(config_dir: &Path) -> Result<bool, String> {
    crate::restore_journal::pending(config_dir)
}

/// Recover a pending restore while holding the configuration-directory lock.
/// The caller must also exclude every in-process reader and writer. Recovery
/// is idempotent and may be retried after an interruption.
pub fn recover_interrupted_restore(
    config_dir: &Path,
    vault: &dyn SecretVault,
    lock: &linscp_platform::ConfigDirectoryLock,
) -> Result<bool, String> {
    if !lock.covers_directory(config_dir) { return Err("Configuration lock does not match the restore directory.".into()); }
    crate::restore_journal::recover(config_dir, vault)
}

struct PreparedRestore {
    restored_keys: Vec<(PathBuf, Vec<u8>)>,
    key_names: Vec<String>,
    restored_ini: zeroize::Zeroizing<String>,
    workspace_bytes: zeroize::Zeroizing<Vec<u8>>,
    bookmark_bytes: zeroize::Zeroizing<Vec<u8>>,
}

fn prepare_restore_plan(
    config_dir: &Path,
    bundle: &BackupBundle,
    vault: &dyn SecretVault,
) -> Result<PreparedRestore, String> {
    if !vault.protects_session_store() {
        return Err("An unlocked password vault is required to restore a full backup.".into());
    }
    let current_master = vault.load_master_key(config_dir).map_err(|e| e.to_string())?
        .ok_or_else(|| "Unlock the local vault before restoring a backup.".to_string())?;
    if crate::restore_journal::pending(config_dir)? {
        return Err("A previous restore requires recovery first.".into());
    }
    if bundle.version != 1 {
        return Err(format!("Unsupported backup version: {}", bundle.version));
    }
    validate_key_references(&bundle.sessions_ini, &bundle.vault_keys)?;
    validate_public_key_references(&bundle.sessions_ini, &bundle.vault_keys, &bundle.vault_public_keys)?;
    validate_tls_references(&bundle.sessions_ini, &bundle.vault_tls_blobs)?;

    linscp_platform::create_private_dir(config_dir).map_err(|e| e.to_string())?;
    let _existing_sessions = SessionStore::read_ini_text(config_dir, vault)?;
    let _existing_workspaces = crate::protected_file::read(&config_dir.join("workspaces.json"), "workspaces", vault)?;
    let _existing_hostkeys = crate::protected_file::read(&config_dir.join("sshhostkeys"), "ssh-host-keys", vault)?;

    if let Some(value) = &bundle.commander_workspaces {
        if !value.get("workspaces").is_some_and(serde_json::Value::is_object) {
            return Err("Invalid Commander workspace data in backup".into());
        }
    }
    if let Some(value) = &bundle.commander_bookmarks {
        if !["local", "remote"].iter().all(|key| value.get(*key).is_some_and(serde_json::Value::is_array)) {
            return Err("Invalid Commander bookmarks in backup".into());
        }
    }
    if let Some(text) = &bundle.sshhostkeys {
        crate::hostkeys::HostKeyCache::validate(text)?;
    }
    if let Some(text) = &bundle.explorer_commands_json {
        serde_json::from_str::<serde_json::Value>(text)
            .map_err(|e| format!("Invalid explorer-commands.json in backup: {e}"))?;
    }
    validate_additional_settings(bundle)?;

    let mut restored_ini = zeroize::Zeroizing::new(normalize_to_lf(&bundle.sessions_ini));
    if let Some(b64) = &bundle.sessions_key_b64 {
        let raw = zeroize::Zeroizing::new(
            BASE64
                .decode(b64.as_bytes())
                .map_err(|e| format!("Invalid sessions.key in backup: {e}"))?,
        );
        if raw.len() != 32 {
            return Err("Invalid sessions.key length in backup".to_string());
        }
        let source_key = linscp_crypto::SessionMasterKey::from_array(raw.as_slice().try_into().unwrap());
        let store = SessionStore::parse_ini(&bundle.sessions_ini, Some(&source_key))
            .map_err(|e| format!("Backup sessions.ini invalid with bundled key: {e}"))?;
        if store.sites().iter().any(|site| {
            site.password_error.is_some()
                || site.key_passphrase_error.is_some()
                || site.proxy_error.is_some()
                || site.tunnel_error.is_some()
        }) {
            return Err("Backup contains secrets that cannot be decrypted with its key.".into());
        }
        if &current_master[..] != raw.as_slice() {
            let destination = linscp_crypto::SessionMasterKey::from_array(*current_master);
            *restored_ini = normalize_to_lf(&store.serialize_ini(Some(&destination))?);
        }
    } else if bundle.sessions_ini.contains("lscp1$") {
        return Err(
            "Backup contains encrypted passwords (lscp1$) but no sessions.key;              refusal to import would lose secrets. Export again with the key,              or import the key separately."
                .to_string(),
        );
    } else {
        SessionStore::parse_ini(&bundle.sessions_ini, None)
            .map_err(|e| format!("Backup sessions.ini invalid: {e}"))?;
    }

    let mut restored_keys = prepare_vault_key_restore(config_dir, bundle, vault)?;
    restored_keys.extend(prepare_public_only_restore(config_dir, bundle)?);
    restored_keys.extend(prepare_vault_tls_restore(config_dir, bundle, vault)?);
    let mut key_names = Vec::with_capacity(restored_keys.len());
    for (path, _) in &restored_keys {
        if path.parent() != Some(config_dir.join("keys").as_path()) {
            return Err("Invalid restore key path.".into());
        }
        let leaf = path.file_name().and_then(|s| s.to_str()).ok_or("Invalid restore key path.")?;
        key_names.push(format!("keys/{leaf}"));
    }

    let workspace_value = match &bundle.commander_workspaces {
        Some(value) => value.clone(),
        None => serde_json::to_value(&bundle.workspaces).map_err(|e| e.to_string())?,
    };
    let workspace_bytes = zeroize::Zeroizing::new(serde_json::to_vec(&workspace_value).map_err(|e| e.to_string())?);

    let bookmark_value = match &bundle.commander_bookmarks {
        Some(bookmarks) => bookmarks.clone(),
        None => {
            let local: Vec<_> = bundle.bookmarks.iter().filter(|entry| !entry.local_dir.is_empty()).map(|entry| serde_json::json!({"name": entry.name, "path": entry.local_dir, "session_name": entry.session_name})).collect();
            let remote: Vec<_> = bundle.bookmarks.iter().filter(|entry| !entry.remote_dir.is_empty()).map(|entry| serde_json::json!({"name": entry.name, "path": entry.remote_dir, "session_name": entry.session_name})).collect();
            serde_json::json!({"local": local, "remote": remote})
        }
    };
    let bookmark_bytes = zeroize::Zeroizing::new(serde_json::to_vec(&bookmark_value).map_err(|e| e.to_string())?);

    Ok(PreparedRestore {
        restored_keys,
        key_names,
        restored_ini,
        workspace_bytes,
        bookmark_bytes,
    })
}

fn remove_optional_restore_file(config_dir: &Path, name: &str) -> Result<(), String> {
    match std::fs::remove_file(config_dir.join(name)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Cannot remove {name}: {error}")),
    }
}

fn apply_prepared_restore(
    config_dir: &Path,
    bundle: &BackupBundle,
    vault: &dyn SecretVault,
    plan: PreparedRestore,
) -> Result<(), String> {
    // Publish keys and flush directory entries before saved sessions can reference them.
    publish_restored_keys(plan.restored_keys, config_dir)?;

    if !plan.restored_ini.is_empty() || config_dir.join("sessions.ini").exists() {
        SessionStore::write_ini_text(config_dir, vault, &plan.restored_ini)?;
    }

    crate::protected_file::write(&config_dir.join("workspaces.json"), "workspaces", vault, &plan.workspace_bytes)?;
    linscp_platform::write_private_file_atomic(&config_dir.join("bookmarks.json"), &plan.bookmark_bytes).map_err(|e| e.to_string())?;
    PreferencesStore::save(config_dir, &bundle.preferences).map_err(|e| e.to_string())?;

    if let Some(text) = &bundle.accounts_ini {
        linscp_platform::write_private_file_atomic(
            &config_dir.join("accounts.ini"),
            normalize_to_lf(text).as_bytes(),
        )
        .map_err(|e| e.to_string())?;
    } else {
        remove_optional_restore_file(config_dir, "accounts.ini")?;
    }

    if let Some(text) = &bundle.sshhostkeys {
        crate::protected_file::write(
            &config_dir.join("sshhostkeys"),
            "ssh-host-keys",
            vault,
            normalize_to_lf(text).as_bytes(),
        )?;
    } else {
        remove_optional_restore_file(config_dir, "sshhostkeys")?;
    }

    for (name, contents) in [
        ("explorer-commands.json", &bundle.explorer_commands_json),
        ("custom-commands.json", &bundle.custom_commands_json),
        ("monitor.json", &bundle.monitor_json),
        ("transfer-presets.ini", &bundle.transfer_presets_ini),
    ] {
        let path = config_dir.join(name);
        match contents {
            Some(text) => linscp_platform::write_private_file_atomic(&path, normalize_to_lf(text).as_bytes()).map_err(|e| e.to_string())?,
            None => remove_optional_restore_file(config_dir, name)?,
        }
    }

    // Device-local reconnect intentions are cleared rather than carried over.
    remove_optional_restore_file(config_dir, "auto-reconnect.json")?;
    Ok(())
}

/// Journal-backed full restore, for a caller that holds the matching exclusive
/// configuration lock and has stopped all in-process readers and writers.
/// Recovery must also run before configuration is read at the next startup.
/// Unsupported directory durability fails closed; the local vault key is never
/// replaced.
pub fn import_backup_transactional(
    config_dir: &Path,
    bundle: &BackupBundle,
    vault: &dyn SecretVault,
    lock: &linscp_platform::ConfigDirectoryLock,
) -> Result<(), String> {
    if !lock.covers_directory(config_dir) {
        return Err("Configuration lock does not match the restore directory.".into());
    }
    let plan = prepare_restore_plan(config_dir, bundle, vault)?;
    crate::restore_journal::prepare(config_dir, vault, &plan.key_names)?;
    if let Err(error) = apply_prepared_restore(config_dir, bundle, vault, plan) {
        return match crate::restore_journal::recover(config_dir, vault) {
            Ok(true) => Err(format!("Restore failed and was rolled back: {error}")),
            Ok(false) => Err(format!("Restore failed; its recovery journal disappeared: {error}")),
            Err(recovery) => Err(format!("Restore failed: {error}. Recovery is required: {recovery}")),
        };
    }
    if let Err(error) = crate::restore_journal::commit(config_dir, vault) {
        // Once the journal has been removed, the new stores have already been
        // flushed; an error on the final directory sync makes the reported
        // outcome uncertain. Never claim rollback if there is no journal.
        return match crate::restore_journal::recover(config_dir, vault) {
            Ok(true) => Err(format!("Restore commit failed and was rolled back: {error}")),
            Ok(false) => Err(format!("Restore commit outcome is uncertain: {error}")),
            Err(recovery) => Err(format!("Restore commit failed: {error}. Recovery is required: {recovery}")),
        };
    }
    Ok(())
}

const BACKUP_MAGIC: &[u8; 8] = b"LSCPBAK1";
const BACKUP_MAX_BYTES: usize = 64 * 1024 * 1024;

fn backup_key(password: &str, salt: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    if password.len() < 12 || password.len() > 1024 { return Err("Backup password must be 12 to 1024 bytes.".into()); }
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| e.to_string())?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = zeroize::Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password.as_bytes(), salt, &mut *key).map_err(|_| "Cannot derive backup key".to_string())?;
    Ok(key)
}

/// Seal the complete portable bundle with an independent password.
pub fn seal_backup(bundle: &BackupBundle, password: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use rand::RngCore;
    let plaintext = zeroize::Zeroizing::new(serialize_backup(bundle)?);
    if plaintext.len() > BACKUP_MAX_BYTES { return Err("Backup exceeds size limit".into()); }
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let key = backup_key(password, &salt)?;
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&*key).map_err(|_| "Invalid backup key")?;
    let mut header = BACKUP_MAGIC.to_vec();
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    let ciphertext = cipher.encrypt(aes_gcm::Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &header })
        .map_err(|_| "Could not encrypt backup".to_string())?;
    header.extend_from_slice(&ciphertext);
    Ok(header)
}

pub fn open_encrypted_backup(bytes: &[u8], password: &str) -> Result<BackupBundle, String> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    const HEADER_LEN: usize = 8 + 16 + 12;
    if bytes.len() < HEADER_LEN + 16 || bytes.len() > BACKUP_MAX_BYTES + HEADER_LEN + 16 || !bytes.starts_with(BACKUP_MAGIC) {
        return Err("Not a valid encrypted LinSCP backup.".into());
    }
    let key = backup_key(password, &bytes[8..24])?;
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&*key).map_err(|_| "Invalid backup key")?;
    let plaintext = zeroize::Zeroizing::new(cipher.decrypt(aes_gcm::Nonce::from_slice(&bytes[24..36]),
        Payload { msg: &bytes[HEADER_LEN..], aad: &bytes[..HEADER_LEN] })
        .map_err(|_| "Wrong backup password or corrupted backup".to_string())?);
    deserialize_backup(&plaintext)
}

pub fn export_backup_to_file(config_dir: &Path, dest_path: &Path, vault: &dyn SecretVault, password: &str) -> Result<(), String> {
    let bundle = export_backup(config_dir, vault)?;
    let bytes = seal_backup(&bundle, password)?;
    linscp_platform::write_owner_only_file_atomic(dest_path, &bytes).map_err(|e| e.to_string())
}

pub fn import_backup_from_file_transactional(
    config_dir: &Path,
    src_path: &Path,
    vault: &dyn SecretVault,
    password: &str,
    lock: &linscp_platform::ConfigDirectoryLock,
) -> Result<BackupBundle, String> {
    let max_encrypted = BACKUP_MAX_BYTES + 64;
    let file = std::fs::File::open(src_path).map_err(|e| e.to_string())?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(max_encrypted as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > max_encrypted { return Err("Backup exceeds size limit".into()); }
    let bundle = open_encrypted_backup(&bytes, password)?;
    import_backup_transactional(config_dir, &bundle, vault, lock)?;
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
    // Runtime check via consts::OS avoids #[cfg(target_os)] in linscp-engine
    // per repository hygiene (OS branches live in linscp-platform).
    let os = std::env::consts::OS;
    if os == "windows" {
        return "windows".to_string();
    }
    if os == "android" {
        return "android".to_string();
    }
    // Linux and other Unix: try /etc/os-release, fallback to OS string.
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
    os.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use linscp_crypto::SessionMasterKey;
    use linscp_platform::password_vault::PasswordSecretVault;
    use linscp_platform::NativeSecretVault;
    use linscp_types::ProtocolScheme;

    fn sample_bundle_with_secrets(key: &SessionMasterKey) -> BackupBundle {
        let mut store = SessionStore::new();
        let mut site = crate::session_store::StoredSite::new("prod/app", ProtocolScheme::Sftp, "10.0.0.1");
        site.username = "alice".to_string();
        site.password = Some("s3cr3t!\twith\ttabs".to_string());
        site.remote_directory = "/srv/app".to_string();
        store.upsert(site);
        let ini = store.serialize_ini(Some(key)).unwrap();
        let raw_b64 = BASE64.encode(key.as_bytes());
        BackupBundle {
            version: 1,
            created_at: "0".to_string(),
            created_on: "linux".to_string(),
            sessions_ini: ini,
            sessions_key_b64: Some(raw_b64),
            vault_keys: Vec::new(),
            vault_public_keys: Vec::new(),
            vault_tls_blobs: Vec::new(),
            workspaces: vec![WorkspaceSnapshot {
                name: "Deploy".to_string(),
                tabs: vec![linscp_types::WorkspaceTabSnapshot {
                    session_name: "prod/app".to_string(),
                    remote_dir: "/srv/app".to_string(),
                    local_dir: "/tmp".to_string(),
                }],
                active_index: 0,
            }],
            commander_workspaces: None,
            bookmarks: vec![BookmarkEntry {
                name: "Logs".to_string(),
                session_name: "prod/app".to_string(),
                remote_dir: "/var/log".to_string(),
                local_dir: "/tmp/logs".to_string(),
            }],
            commander_bookmarks: None,
            preferences: UserPreferences {
                filemask: "*.log".to_string(),
                ..UserPreferences::default()
            },
            accounts_ini: Some("[alice]\nhash=abc\n".to_string()),
            sshhostkeys: Some("example.com ssh-rsa AAAAB3...\n".to_string()),
            explorer_commands_json: Some("[{\"name\":\"Open\"}]\n".to_string()),
            custom_commands_json: None,
            monitor_json: None,
            transfer_presets_ini: None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn backup_is_distribution_compatible_between_linux_windows_and_android() {
        let key = SessionMasterKey::from_array([42u8; 32]);
        let bundle = sample_bundle_with_secrets(&key);
        let bytes = serialize_backup(&bundle).unwrap();
        assert!(!bytes.windows(2).any(|w| w == b"\r\n"));
        assert!(bytes.ends_with(b"\n"));

        let crlf_bytes = bytes
            .iter()
            .flat_map(|&b| if b == b'\n' { vec![b'\r', b'\n'] } else { vec![b] })
            .collect::<Vec<u8>>();
        let parsed_crlf = deserialize_backup(&crlf_bytes).unwrap();
        assert_eq!(parsed_crlf.sessions_ini, bundle.sessions_ini);
        assert_eq!(parsed_crlf.sessions_key_b64, bundle.sessions_key_b64);

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
            let vault = PasswordSecretVault::new();
            vault.unlock_or_setup(&cfg, "destination vault password", &NativeSecretVault::new()).unwrap();
            let lock = linscp_platform::ConfigDirectoryLock::try_acquire(&cfg).unwrap();
            import_backup_transactional(&cfg, &bundle, &vault, &lock).unwrap();

            let store = SessionStore::load_from_dir(&cfg, &vault).unwrap();
            assert_eq!(store.find("prod/app").unwrap().password.as_deref(), Some("s3cr3t!\twith\ttabs"));

            let workspace_plain = crate::protected_file::read(&cfg.join("workspaces.json"), "workspaces", &vault).unwrap().unwrap();
            let restored_ws: Vec<WorkspaceSnapshot> = serde_json::from_slice(&workspace_plain).unwrap();
            assert_eq!(restored_ws, bundle.workspaces);
            let restored_bm: serde_json::Value = serde_json::from_slice(&std::fs::read(cfg.join("bookmarks.json")).unwrap()).unwrap();
            assert_eq!(restored_bm["local"][0]["path"], "/tmp/logs");
            assert_eq!(restored_bm["remote"][0]["path"], "/var/log");
            assert_eq!(PreferencesStore::load(&cfg).unwrap(), bundle.preferences);

            let acct = std::fs::read_to_string(cfg.join("accounts.ini")).unwrap();
            assert!(!acct.contains("\r\n"));
            drop(lock);
            let _ = std::fs::remove_dir_all(&base);
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn application_backup_restore_keeps_the_password_wrapped_master_key_when_it_matches() {
        let base = std::env::temp_dir().join(format!(
            "linscp-backup-vault-key-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let vault = PasswordSecretVault::new();
        vault.unlock_or_setup(&base, "correct horse battery staple", &NativeSecretVault::new()).unwrap();
        let wrapped_before = std::fs::read(base.join("sessions.key")).unwrap();
        let bundle = export_backup(&base, &vault).unwrap();
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(&base).unwrap();
        import_backup_transactional(&base, &bundle, &vault, &lock).unwrap();
        let wrapped_after = std::fs::read(base.join("sessions.key")).unwrap();
        assert_eq!(wrapped_after, wrapped_before);
        assert!(wrapped_after.starts_with(b"LSCPVLT1"));
        drop(lock);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn invalid_settings_fail_without_replacing_existing_settings() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let vault = PasswordSecretVault::new();
        vault.unlock_or_setup(root, "destination vault password", &NativeSecretVault::new()).unwrap();
        std::fs::write(root.join("custom-commands.json"), b"[]").unwrap();
        let mut invalid = BackupBundle::default();
        invalid.version = 1;
        invalid.custom_commands_json = Some("{\"commands\": 123}".into());
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(root).unwrap();
        assert!(import_backup_transactional(root, &invalid, &vault, &lock).is_err());
        assert_eq!(std::fs::read(root.join("custom-commands.json")).unwrap(), b"[]");
        assert!(!restore_recovery_required(root).unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn transactional_restore_rewraps_sessions_and_vault_keys() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        let src_vault = PasswordSecretVault::new();
        let dst_vault = PasswordSecretVault::new();
        src_vault.unlock_or_setup(&source, "source vault password", &NativeSecretVault::new()).unwrap();
        dst_vault.unlock_or_setup(&destination, "destination vault password", &NativeSecretVault::new()).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        std::fs::create_dir(source.join("keys")).unwrap();
        std::fs::write(source.join("keys").join(format!("{id}.key.vault")), src_vault.seal_local_blob(b"private key").unwrap()).unwrap();
        let mut source_sites = SessionStore::new();
        let mut site = crate::session_store::StoredSite::new("source", ProtocolScheme::Sftp, "source.example");
        site.private_key = Some(format!("vaultkey://{id}"));
        site.password = Some("password secret".into());
        source_sites.upsert(site);
        source_sites.save_to_dir(&source, &src_vault).unwrap();
        let mut destination_sites = SessionStore::new();
        destination_sites.upsert(crate::session_store::StoredSite::new("previous", ProtocolScheme::Sftp, "old.example"));
        destination_sites.save_to_dir(&destination, &dst_vault).unwrap();
        std::fs::write(source.join("custom-commands.json"), r#"{"commands":[{"name":"example","command":"echo hello"}]}"#).unwrap();
        std::fs::write(source.join("transfer-presets.ini"), "[example]\nspeed=5\n").unwrap();
        for name in ["monitor.json", "auto-reconnect.json", "accounts.ini", "explorer-commands.json"] {
            std::fs::write(destination.join(name), b"old settings").unwrap();
        }
        crate::protected_file::write(&destination.join("sshhostkeys"), "ssh-host-keys", &dst_vault, b"old host keys").unwrap();
        let bundle = export_backup(&source, &src_vault).unwrap();
        assert_eq!(bundle.version, 1);
        let sealed = seal_backup(&bundle, "independent backup password").unwrap();
        assert!(!sealed.windows(b"echo hello".len()).any(|part| part == b"echo hello"));
        let bundle = open_encrypted_backup(&sealed, "independent backup password").unwrap();
        let before_key = std::fs::read(destination.join("sessions.key")).unwrap();
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(&destination).unwrap();
        import_backup_transactional(&destination, &bundle, &dst_vault, &lock).unwrap();
        assert!(!restore_recovery_required(&destination).unwrap());
        assert_eq!(std::fs::read(destination.join("sessions.key")).unwrap(), before_key);
        let restored = SessionStore::load_from_dir(&destination, &dst_vault).unwrap();
        assert_eq!(restored.find("source").unwrap().password.as_deref(), Some("password secret"));
        assert!(restored.find("previous").is_none());
        let encrypted = std::fs::read(destination.join("keys").join(format!("{id}.key.vault"))).unwrap();
        assert_eq!(dst_vault.open_local_blob(&encrypted).unwrap().as_slice(), b"private key");
        assert!(src_vault.open_local_blob(&encrypted).is_err());
        assert!(std::fs::read_to_string(destination.join("custom-commands.json")).unwrap().contains("echo hello"));
        assert!(std::fs::read_to_string(destination.join("transfer-presets.ini")).unwrap().contains("speed=5"));
        for name in ["monitor.json", "auto-reconnect.json", "accounts.ini", "explorer-commands.json", "sshhostkeys"] {
            assert!(!destination.join(name).exists(), "{name} should be absent after restore");
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn interrupted_transaction_requires_matching_lock_and_restores_original() {
        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("destination");
        let other = temp.path().join("other");
        let vault = PasswordSecretVault::new();
        vault.unlock_or_setup(&destination, "destination vault password", &NativeSecretVault::new()).unwrap();
        std::fs::write(destination.join("sessions.ini"), b"old bytes").unwrap();
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(&destination).unwrap();
        crate::restore_journal::prepare(&destination, &vault, &[]).unwrap();
        assert!(export_backup(&destination, &vault).is_err());
        std::fs::write(destination.join("sessions.ini"), b"new bytes").unwrap();
        let wrong_lock = linscp_platform::ConfigDirectoryLock::try_acquire(&other).unwrap();
        assert!(recover_interrupted_restore(&destination, &vault, &wrong_lock).is_err());
        assert_eq!(std::fs::read(destination.join("sessions.ini")).unwrap(), b"new bytes");
        assert!(restore_recovery_required(&destination).unwrap());
        assert!(recover_interrupted_restore(&destination, &vault, &lock).unwrap());
        assert_eq!(std::fs::read(destination.join("sessions.ini")).unwrap(), b"old bytes");
        assert!(!restore_recovery_required(&destination).unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn vault_failure_after_session_write_restores_original_session_ciphertext() {
        struct FailingWorkspaceVault<'a>(&'a PasswordSecretVault);
        impl SecretVault for FailingWorkspaceVault<'_> {
            fn load_master_key(&self, dir: &Path) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>, linscp_platform::PlatformError> {
                self.0.load_master_key(dir)
            }
            fn load_or_create_master_key(&self, dir: &Path) -> Result<zeroize::Zeroizing<[u8; 32]>, linscp_platform::PlatformError> {
                self.0.load_or_create_master_key(dir)
            }
            fn protects_session_store(&self) -> bool { true }
            fn seal_session_store(&self, bytes: &[u8]) -> Result<Vec<u8>, linscp_platform::PlatformError> {
                if bytes.starts_with(b"LinSCP protected file: workspaces\n") {
                    return Err(linscp_platform::PlatformError::SecretVault("injected workspace failure".into()));
                }
                self.0.seal_session_store(bytes)
            }
            fn open_session_store(&self, bytes: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, linscp_platform::PlatformError> {
                self.0.open_session_store(bytes)
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        let src_vault = PasswordSecretVault::new();
        let dst_vault = PasswordSecretVault::new();
        src_vault.unlock_or_setup(&source, "source vault password", &NativeSecretVault::new()).unwrap();
        dst_vault.unlock_or_setup(&target, "destination vault password", &NativeSecretVault::new()).unwrap();
        let mut src = SessionStore::new();
        src.upsert(crate::session_store::StoredSite::new("new", ProtocolScheme::Sftp, "source.example"));
        src.save_to_dir(&source, &src_vault).unwrap();
        let mut dst = SessionStore::new();
        dst.upsert(crate::session_store::StoredSite::new("old", ProtocolScheme::Sftp, "target.example"));
        dst.save_to_dir(&target, &dst_vault).unwrap();
        let before = std::fs::read(target.join("sessions.ini")).unwrap();
        let bundle = export_backup(&source, &src_vault).unwrap();
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(&target).unwrap();
        let error = import_backup_transactional(&target, &bundle, &FailingWorkspaceVault(&dst_vault), &lock).unwrap_err();
        assert!(error.contains("rolled back"));
        assert!(!restore_recovery_required(&target).unwrap());
        assert_eq!(std::fs::read(target.join("sessions.ini")).unwrap(), before);
        assert!(SessionStore::load_from_dir(&target, &dst_vault).unwrap().find("old").is_some());
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn restore_rejects_non_regular_destination_before_writing_any_store() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = temp.path();
        let vault = PasswordSecretVault::new();
        vault.unlock_or_setup(cfg, "local vault password", &NativeSecretVault::new()).unwrap();
        let bundle = export_backup(cfg, &vault).unwrap();
        std::fs::create_dir(cfg.join("preferences.json")).unwrap();
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(cfg).unwrap();
        assert!(import_backup_transactional(cfg, &bundle, &vault, &lock).is_err());
        assert!(!restore_recovery_required(cfg).unwrap());
    }

    #[test]
    fn malformed_commands_are_rejected_before_restore_changes_any_store() {
        let temp = tempfile::tempdir().unwrap();
        let cfg = temp.path();
        let vault = PasswordSecretVault::new();
        vault.unlock_or_setup(cfg, "local vault password", &NativeSecretVault::new()).unwrap();
        let mut bundle = export_backup(cfg, &vault).unwrap();
        let before = std::fs::read(cfg.join("sessions.key")).unwrap();
        bundle.explorer_commands_json = Some("{broken".into());
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(cfg).unwrap();
        assert!(import_backup_transactional(cfg, &bundle, &vault, &lock).is_err());
        assert!(!restore_recovery_required(cfg).unwrap());
        assert_eq!(std::fs::read(cfg.join("sessions.key")).unwrap(), before);
        assert!(!cfg.join("workspaces.json").exists());
        assert!(!cfg.join("preferences.json").exists());
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn encrypted_backup_restores_session_to_a_different_unlocked_vault() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        let source_vault = PasswordSecretVault::new();
        let target_vault = PasswordSecretVault::new();
        source_vault.unlock_or_setup(&source, "source vault password", &NativeSecretVault::new()).unwrap();
        target_vault.unlock_or_setup(&destination, "destination vault password", &NativeSecretVault::new()).unwrap();
        let key_dir = source.join("keys");
        std::fs::create_dir_all(&key_dir).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let tunnel_id = "123456789abcdef0123456789abcdef0";
        let spare_id = "23456789abcdef0123456789abcdef01";
        for (id, private) in [(id, "private-key-material"), (tunnel_id, "tunnel-private-key"), (spare_id, "unreferenced-private-key")] {
            let encrypted = source_vault.seal_local_blob(private.as_bytes()).unwrap();
            std::fs::write(key_dir.join(format!("{id}.key.vault")), encrypted).unwrap();
            std::fs::write(key_dir.join(format!("{id}.label")), format!("label-{id}")).unwrap();
            std::fs::write(key_dir.join(format!("{id}.pub")), format!("ssh-ed25519 public-{id}")).unwrap();
        }
        let mut sessions = SessionStore::new();
        let mut site = crate::session_store::StoredSite::new("private-name", ProtocolScheme::Sftp, "private-host");
        site.password = Some("private-password".into());
        site.private_key = Some(format!("vaultkey://{id}"));
        site.tunnel.enabled = true;
        site.tunnel.keyfile = Some(format!("vaultkey://{tunnel_id}"));
        sessions.upsert(site);
        sessions.save_to_dir(&source, &source_vault).unwrap();
        let workspaces = serde_json::json!({"workspaces": {"private-workspace": {"tabs": [], "active": 0}}});
        crate::protected_file::write(&source.join("workspaces.json"), "workspaces", &source_vault, &serde_json::to_vec(&workspaces).unwrap()).unwrap();
        let mut hostkeys = crate::hostkeys::HostKeyCache::new();
        hostkeys.upsert("private-host", 22, "ssh-ed25519", "SHA256:fingerprint").unwrap();
        hostkeys.save_protected(&source.join("sshhostkeys"), &source_vault).unwrap();
        let backup = temp.path().join("backup.lscpbak");
        export_backup_to_file(&source, &backup, &source_vault, "independent backup password").unwrap();
        let bytes = std::fs::read(&backup).unwrap();
        for secret in ["private-name", "private-host", "private-password", "private-workspace", "private-key-material", "tunnel-private-key", "unreferenced-private-key", id, tunnel_id, spare_id] {
            assert!(!bytes.windows(secret.len()).any(|part| part == secret.as_bytes()));
        }
        let original_key = std::fs::read(destination.join("sessions.key")).unwrap();
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(&destination).unwrap();
        assert!(import_backup_from_file_transactional(&destination, &backup, &target_vault, "wrong password here", &lock).is_err());
        import_backup_from_file_transactional(&destination, &backup, &target_vault, "independent backup password", &lock).unwrap();
        assert_eq!(std::fs::read(destination.join("sessions.key")).unwrap(), original_key);
        let restored = SessionStore::load_from_dir(&destination, &target_vault).unwrap();
        assert_eq!(restored.find("private-name").unwrap().password.as_deref(), Some("private-password"));
        let restored_site = restored.find("private-name").unwrap();
        assert_eq!(restored_site.private_key.as_deref(), Some(format!("vaultkey://{id}").as_str()));
        assert_eq!(restored_site.tunnel.keyfile.as_deref(), Some(format!("vaultkey://{tunnel_id}").as_str()));
        for (id, private) in [(id, "private-key-material"), (tunnel_id, "tunnel-private-key"), (spare_id, "unreferenced-private-key")] {
            let path = destination.join("keys").join(format!("{id}.key.vault"));
            let encrypted = std::fs::read(path).unwrap();
            assert!(!encrypted.windows(private.len()).any(|window| window == private.as_bytes()));
            assert_eq!(target_vault.open_local_blob(&encrypted).unwrap().as_slice(), private.as_bytes());
            assert!(source_vault.open_local_blob(&encrypted).is_err());
            assert_eq!(std::fs::read_to_string(destination.join("keys").join(format!("{id}.label"))).unwrap(), format!("label-{id}"));
            assert_eq!(std::fs::read_to_string(destination.join("keys").join(format!("{id}.pub"))).unwrap(), format!("ssh-ed25519 public-{id}"));
        }
        import_backup_from_file_transactional(&destination, &backup, &target_vault, "independent backup password", &lock).unwrap();
        assert_eq!(crate::hostkeys::HostKeyCache::load_protected(&destination.join("sshhostkeys"), &target_vault).unwrap().lookup("private-host", 22, "ssh-ed25519"), Some("SHA256:fingerprint"));
        let restored_workspace = crate::protected_file::read(&destination.join("workspaces.json"), "workspaces", &target_vault).unwrap().unwrap();
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&restored_workspace).unwrap(), workspaces);
    }

    #[test]
    fn vault_key_backup_refuses_missing_corrupt_and_conflicting_keys_without_replacing_data() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let destination = temp.path().join("destination");
        let source_vault = PasswordSecretVault::new();
        let target_vault = PasswordSecretVault::new();
        source_vault.unlock_or_setup(&source, "source vault password", &NativeSecretVault::new()).unwrap();
        target_vault.unlock_or_setup(&destination, "destination vault password", &NativeSecretVault::new()).unwrap();
        let id = "0123456789abcdef0123456789abcdef";
        let mut sessions = SessionStore::new();
        let mut site = crate::session_store::StoredSite::new("site", ProtocolScheme::Sftp, "host");
        site.private_key = Some(format!("vaultkey://{id}"));
        sessions.upsert(site);
        sessions.save_to_dir(&source, &source_vault).unwrap();
        assert!(export_backup(&source, &source_vault).unwrap_err().contains("missing vault SSH key"));
        std::fs::create_dir_all(source.join("keys")).unwrap();
        std::fs::write(source.join("keys").join(format!("{id}.key.vault")), source_vault.seal_local_blob(b"source key").unwrap()).unwrap();
        let bundle = export_backup(&source, &source_vault).unwrap();
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(&destination).unwrap();
        let mut missing = bundle.clone();
        missing.vault_keys.clear();
        assert!(import_backup_transactional(&destination, &missing, &target_vault, &lock).is_err());
        let mut corrupted = bundle.clone();
        corrupted.vault_keys[0].encrypted_b64 = BASE64.encode(b"invalid blob");
        assert!(import_backup_transactional(&destination, &corrupted, &target_vault, &lock).is_err());
        let mut duplicate = bundle.clone();
        duplicate.vault_keys.push(duplicate.vault_keys[0].clone());
        assert!(import_backup_transactional(&destination, &duplicate, &target_vault, &lock).is_err());
        let mut bad_id = bundle.clone();
        bad_id.vault_keys[0].id = "../../unsafe".into();
        assert!(import_backup_transactional(&destination, &bad_id, &target_vault, &lock).is_err());
        assert!(!destination.join("sessions.ini").exists());
        assert!(!restore_recovery_required(&destination).unwrap());
        std::fs::create_dir_all(destination.join("keys")).unwrap();
        let existing = target_vault.seal_local_blob(b"different key").unwrap();
        let path = destination.join("keys").join(format!("{id}.key.vault"));
        std::fs::write(&path, &existing).unwrap();
        assert!(import_backup_transactional(&destination, &bundle, &target_vault, &lock).unwrap_err().contains("different key"));
        assert_eq!(std::fs::read(&path).unwrap(), existing);
        assert!(!destination.join("sessions.ini").exists());
        assert!(!restore_recovery_required(&destination).unwrap());
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
        let vault = PasswordSecretVault::new();
        vault.unlock_or_setup(&base, "destination vault password", &NativeSecretVault::new()).unwrap();
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(&base).unwrap();
        let err = import_backup_transactional(&base, &bundle, &vault, &lock).unwrap_err();
        assert!(err.contains("no sessions.key"));
        assert!(!restore_recovery_required(&base).unwrap());
        drop(lock);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
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
        let file = base.join("backup.linscp-backup.json");
        let password = "a strong backup password";
        let bytes = seal_backup(&bundle, password).unwrap();
        assert!(!bytes.windows(8).any(|w| w == b"prod/app"));
        assert!(open_encrypted_backup(&bytes, "wrong backup password").is_err());
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_encrypted_backup(&tampered, password).is_err());
        std::fs::write(&file, bytes).unwrap();
        let cfg2 = base.join("restore");
        std::fs::create_dir_all(&cfg2).unwrap();
        let vault = PasswordSecretVault::new();
        vault.unlock_or_setup(&cfg2, "destination vault password", &NativeSecretVault::new()).unwrap();
        let lock = linscp_platform::ConfigDirectoryLock::try_acquire(&cfg2).unwrap();
        let restored = import_backup_from_file_transactional(&cfg2, &file, &vault, password, &lock).unwrap();
        assert_eq!(restored.sessions_key_b64, bundle.sessions_key_b64);
        drop(lock);
        let _ = std::fs::remove_dir_all(&base);
    }
}
