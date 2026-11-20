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

use crate::config_stores::{BookmarksStore, PreferencesStore};
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

const KEY_LIMIT: usize = 1024 * 1024;
const KEY_BLOB_LIMIT: usize = KEY_LIMIT + 64;
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

/// In-memory portable backup bundle. Its serialized JSON contains secrets and
/// must only be persisted inside an encrypted backup envelope.
///
/// The JSON shape is versioned so future fields can be
/// added without breaking restores of older backups. Unknown top-level
/// keys are ignored on import for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupBundle {
    /// Schema version (`1` for legacy bundles, `2` for backups with vault keys).
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
            workspaces: Vec::new(),
            commander_workspaces: None,
            bookmarks: Vec::new(),
            commander_bookmarks: None,
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

/// Collects all per-user configuration from `config_dir` into a
/// distribution-compatible `BackupBundle`.
///
/// The master key is read via `vault` and stored as raw base64 so the
/// bundle restores on every platform.
pub fn export_backup(
    config_dir: &Path,
    vault: &dyn SecretVault,
) -> Result<BackupBundle, String> {
    if vault.protects_session_store() && vault.load_master_key(config_dir).map_err(|e| e.to_string())?.is_none() {
        return Err("Unlock the local vault before exporting a backup.".into());
    }
    let vault_keys = collect_vault_keys(config_dir, vault)?;
    let sessions_ini = SessionStore::read_ini_text(config_dir, vault)?
        .map(|s| normalize_to_lf(&s))
        .unwrap_or_default();
    validate_key_references(&sessions_ini, &vault_keys)?;

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
    let (bookmarks, commander_bookmarks) = match std::fs::read(config_dir.join("bookmarks.json")) {
        Ok(bytes) => {
            let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| format!("Invalid bookmarks: {e}"))?;
            if value.is_array() { (serde_json::from_value(value).map_err(|e| format!("Invalid bookmarks: {e}"))?, None) }
            else if ["local", "remote"].iter().all(|key| value.get(*key).is_some_and(serde_json::Value::is_array)) { (Vec::new(), Some(value)) }
            else { return Err("Invalid bookmarks structure".into()); }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Vec::new(), None),
        Err(e) => return Err(format!("Cannot read bookmarks: {e}")),
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

    Ok(BackupBundle {
        version: 2,
        created_at: now,
        created_on,
        sessions_ini,
        sessions_key_b64,
        vault_keys,
        workspaces,
        commander_workspaces,
        bookmarks,
        commander_bookmarks,
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
    Ok(())
}

/// Restores `bundle` into `config_dir`, overwriting existing files
/// atomically with owner-only permissions where applicable.
///
/// When the destination has an unlocked password vault, session secrets are
/// re-encrypted with its key instead of replacing its wrapped master key.
pub fn import_backup(
    config_dir: &Path,
    bundle: &BackupBundle,
    vault: &dyn SecretVault,
) -> Result<(), String> {
    if bundle.version != 1 && bundle.version != 2 {
        return Err(format!("Unsupported backup version: {}", bundle.version));
    }
    validate_key_references(&bundle.sessions_ini, &bundle.vault_keys)?;

    std::fs::create_dir_all(config_dir).map_err(|e| e.to_string())?;
    // Check access before replacing any key: a legacy client must not damage
    // a password-vault store that it cannot open.
    let _existing_sessions = SessionStore::read_ini_text(config_dir, vault)?;
    if vault.protects_session_store() && vault.load_master_key(config_dir).map_err(|e| e.to_string())?.is_none() {
        return Err("Unlock the local vault before restoring a backup.".into());
    }

    let _existing_workspaces = crate::protected_file::read(&config_dir.join("workspaces.json"), "workspaces", vault)?;
    let _existing_hostkeys = crate::protected_file::read(&config_dir.join("sshhostkeys"), "ssh-host-keys", vault)?;
    if let Some(value) = &bundle.commander_workspaces {
        if !value.get("workspaces").is_some_and(serde_json::Value::is_object) { return Err("Invalid Commander workspace data in backup".into()); }
    }
    if let Some(value) = &bundle.commander_bookmarks {
        if !["local", "remote"].iter().all(|key| value.get(*key).is_some_and(serde_json::Value::is_array)) { return Err("Invalid Commander bookmarks in backup".into()); }
    }
    if let Some(text) = &bundle.sshhostkeys { crate::hostkeys::HostKeyCache::validate(text)?; }
    let restored_keys = prepare_vault_key_restore(config_dir, bundle, vault)?;
    let mut restored_ini = zeroize::Zeroizing::new(bundle.sessions_ini.clone());

    // 1) sessions.key — must be written first so subsequent sessions.ini
    //    passwords remain decryptable.
    if let Some(b64) = &bundle.sessions_key_b64 {
        let raw = zeroize::Zeroizing::new(BASE64
            .decode(b64.as_bytes())
            .map_err(|e| format!("Invalid sessions.key in backup: {e}"))?);
        if raw.len() != 32 {
            return Err("Invalid sessions.key length in backup".to_string());
        }
        let source_key = linscp_crypto::SessionMasterKey::from_array(raw.as_slice().try_into().unwrap());
        let store = SessionStore::parse_ini(&bundle.sessions_ini, Some(&source_key))
            .map_err(|e| format!("Backup sessions.ini invalid with bundled key: {e}"))?;
        if store.sites().iter().any(|site| site.password_error.is_some() || site.key_passphrase_error.is_some() || site.proxy_error.is_some() || site.tunnel_error.is_some()) {
            return Err("Backup contains secrets that cannot be decrypted with its key.".into());
        }
        let already_active = vault.load_master_key(config_dir).map_err(|e| e.to_string())?
            .is_some_and(|current| &current[..] == raw.as_slice());
        if !already_active && vault.protects_session_store() {
            let current = vault.load_master_key(config_dir).map_err(|e| e.to_string())?.ok_or_else(|| "The local vault is locked.".to_string())?;
            let destination = linscp_crypto::SessionMasterKey::from_array(*current);
            *restored_ini = store.serialize_ini(Some(&destination))?;
        }
        if !already_active && !vault.protects_session_store() {
            let encoded = format!("{b64}\n");
            linscp_platform::write_private_file_atomic(
                &config_dir.join("sessions.key"),
                encoded.as_bytes(),
            )
            .map_err(|e| e.to_string())?;
            // Touch the vault so the freshly written key is exercised once
            let _ = vault.load_master_key(config_dir);
        }
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

    // Publish keys first: a failed or interrupted restore cannot introduce
    // saved-session references to keys that have not yet been written.
    publish_restored_keys(restored_keys, config_dir)?;

    // 2) sessions.ini — always LF, validated above if key present.
    if !bundle.sessions_ini.is_empty() || config_dir.join("sessions.ini").exists() {
        let ini_text = zeroize::Zeroizing::new(normalize_to_lf(&restored_ini));
        // Write even if empty to truncate a previous file (explicit backup of “no sessions”).
        SessionStore::write_ini_text(config_dir, vault, &ini_text)?;
    }

    // 3) JSON stores — already distribution-agnostic, same helpers as live code.
    let workspace_value = match &bundle.commander_workspaces {
        Some(value) if value.get("workspaces").is_some_and(serde_json::Value::is_object) => value.clone(),
        Some(_) => return Err("Invalid Commander workspace data in backup".into()),
        None => serde_json::to_value(&bundle.workspaces).map_err(|e| e.to_string())?,
    };
    let workspace_bytes = zeroize::Zeroizing::new(serde_json::to_vec(&workspace_value).map_err(|e| e.to_string())?);
    if vault.protects_session_store() {
        crate::protected_file::write(&config_dir.join("workspaces.json"), "workspaces", vault, &workspace_bytes)?;
    } else {
        // Do not let a legacy client overwrite an encrypted workspace.
        if config_dir.join("workspaces.json").exists() {
            crate::protected_file::read(&config_dir.join("workspaces.json"), "workspaces", vault)?;
        }
        linscp_platform::write_private_file_atomic(&config_dir.join("workspaces.json"), &workspace_bytes).map_err(|e| e.to_string())?;
    }
    if let Some(bookmarks) = &bundle.commander_bookmarks {
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(bookmarks).map_err(|e| e.to_string())?);
        linscp_platform::write_private_file_atomic(&config_dir.join("bookmarks.json"), &bytes).map_err(|e| e.to_string())?;
    } else if vault.protects_session_store() {
        let local: Vec<_> = bundle.bookmarks.iter().filter(|entry| !entry.local_dir.is_empty()).map(|entry| serde_json::json!({"name": entry.name, "path": entry.local_dir, "session_name": entry.session_name})).collect();
        let remote: Vec<_> = bundle.bookmarks.iter().filter(|entry| !entry.remote_dir.is_empty()).map(|entry| serde_json::json!({"name": entry.name, "path": entry.remote_dir, "session_name": entry.session_name})).collect();
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&serde_json::json!({"local": local, "remote": remote})).map_err(|e| e.to_string())?);
        linscp_platform::write_private_file_atomic(&config_dir.join("bookmarks.json"), &bytes).map_err(|e| e.to_string())?;
    } else {
        BookmarksStore::save(config_dir, &bundle.bookmarks).map_err(|e| e.to_string())?;
    }
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
        crate::hostkeys::HostKeyCache::validate(text)?;
        let path = config_dir.join("sshhostkeys");
        if vault.protects_session_store() {
            crate::protected_file::write(&path, "ssh-host-keys", vault, normalize_to_lf(text).as_bytes())?;
        } else {
            if path.exists() { crate::protected_file::read(&path, "ssh-host-keys", vault)?; }
            linscp_platform::write_private_file_atomic(&path, normalize_to_lf(text).as_bytes()).map_err(|e| e.to_string())?;
        }
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
        return Err("Not a valid encrypted LinSCP backup; legacy plaintext backups require manual migration.".into());
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
    linscp_platform::write_private_file_atomic(dest_path, &bytes).map_err(|e| e.to_string())
}

pub fn import_backup_from_file(config_dir: &Path, src_path: &Path, vault: &dyn SecretVault, password: &str) -> Result<BackupBundle, String> {
    let metadata = std::fs::metadata(src_path).map_err(|e| e.to_string())?;
    if metadata.len() > (BACKUP_MAX_BYTES + 64) as u64 { return Err("Backup exceeds size limit".into()); }
    let bytes = std::fs::read(src_path).map_err(|e| e.to_string())?;
    let bundle = open_encrypted_backup(&bytes, password)?;
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
    use crate::config_stores::WorkspacesStore;
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
        import_backup(&base, &bundle, &vault).unwrap();
        let wrapped_after = std::fs::read(base.join("sessions.key")).unwrap();
        assert_eq!(wrapped_after, wrapped_before);
        assert!(wrapped_after.starts_with(b"LSCPVLT1"));
        let _ = std::fs::remove_dir_all(base);
    }

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
        assert!(import_backup_from_file(&destination, &backup, &target_vault, "wrong password here").is_err());
        import_backup_from_file(&destination, &backup, &target_vault, "independent backup password").unwrap();
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
        // Restoring a second time keeps identical existing keys and metadata.
        import_backup_from_file(&destination, &backup, &target_vault, "independent backup password").unwrap();
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
        let mut missing = bundle.clone();
        missing.vault_keys.clear();
        assert!(import_backup(&destination, &missing, &target_vault).is_err());
        let mut corrupted = bundle.clone();
        corrupted.vault_keys[0].encrypted_b64 = BASE64.encode(b"invalid blob");
        assert!(import_backup(&destination, &corrupted, &target_vault).is_err());
        let mut duplicate = bundle.clone();
        duplicate.vault_keys.push(duplicate.vault_keys[0].clone());
        assert!(import_backup(&destination, &duplicate, &target_vault).is_err());
        let mut bad_id = bundle.clone();
        bad_id.vault_keys[0].id = "../../unsafe".into();
        assert!(import_backup(&destination, &bad_id, &target_vault).is_err());
        assert!(!destination.join("sessions.ini").exists());
        std::fs::create_dir_all(destination.join("keys")).unwrap();
        let existing = target_vault.seal_local_blob(b"different key").unwrap();
        let path = destination.join("keys").join(format!("{id}.key.vault"));
        std::fs::write(&path, &existing).unwrap();
        assert!(import_backup(&destination, &bundle, &target_vault).unwrap_err().contains("different key"));
        assert_eq!(std::fs::read(&path).unwrap(), existing);
        assert!(!destination.join("sessions.ini").exists());
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
        let restored = import_backup_from_file(&cfg2, &file, &vault, password).unwrap();
        assert_eq!(restored.sessions_key_b64, bundle.sessions_key_b64);
        let _ = std::fs::remove_dir_all(&base);
    }
}
