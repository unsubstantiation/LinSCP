//! Durable encrypted undo journal for a future full-restore transaction.
//!
//! This primitive is not connected to application restore yet. A caller must
//! hold an interprocess configuration lock and exclude all other writers before
//! starting, committing, or recovering. Startup must recover before exposing
//! configuration. Do not use this module as an atomicity guarantee by itself.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

use linscp_platform::SecretVault;
use zeroize::Zeroizing;

const JOURNAL: &str = ".full-restore-journal";
const CONTEXT: &[u8] = b"LinSCP full restore undo journal v1\n";
const MAX_BYTES: usize = 64 * 1024 * 1024;
// At most three paths per backed-up key, plus all fixed stores.
const MAX_RECORDS: usize = 6000 + STORES.len();
// Do not include sessions.key: recovery must be able to unlock the same vault
// after a crash. Only the password-vault restore path may use this primitive.
const STORES: &[&str] = &[
    "sessions.ini", "workspaces.json", "bookmarks.json", "preferences.json",
    "accounts.ini", "sshhostkeys", "explorer-commands.json",
    "custom-commands.json", "monitor.json", "transfer-presets.ini", "auto-reconnect.json",
];

type Record = (String, Option<Zeroizing<Vec<u8>>>);

fn valid_key_name(name: &str) -> bool {
    let Some(leaf) = name.strip_prefix("keys/") else { return false; };
    let id = [".key.vault", ".label", ".pub"].iter().find_map(|suffix| leaf.strip_suffix(suffix));
    id.is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn valid_name(name: &str) -> bool { STORES.contains(&name) || valid_key_name(name) }

fn read_file(path: &Path, limit: usize) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Cannot inspect {}: {e}", path.display())),
        Ok(m) if !m.file_type().is_file() || m.len() > limit as u64 => return Err(format!("Invalid restore target {}", path.display())),
        Ok(_) => {},
    }
    let file = linscp_platform::open_private_file_no_follow(path).map_err(|e| e.to_string())?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() > limit { return Err("Restore journal size limit exceeded.".into()); }
    Ok(Some(bytes))
}

fn check_key_directory(config: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(config.join("keys")) {
        Ok(meta) if meta.file_type().is_dir() => Ok(()),
        Ok(_) => Err("Vault key path is not a directory.".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

fn snapshot(config: &Path, key_names: &[String]) -> Result<Vec<Record>, String> {
    if key_names.len() > MAX_RECORDS - STORES.len() { return Err("Too many restore journal records.".into()); }
    check_key_directory(config)?;
    let mut names: Vec<String> = STORES.iter().map(|name| (*name).to_string()).collect();
    let mut unique = BTreeSet::new();
    for name in key_names {
        if !valid_key_name(name) || !unique.insert(name.to_ascii_lowercase()) {
            return Err("Invalid or duplicate restore key path.".into());
        }
        names.push(name.clone());
    }
    let mut remaining = MAX_BYTES;
    let mut entries = Vec::with_capacity(names.len());
    for name in names {
        let bytes = read_file(&config.join(&name), remaining)?;
        remaining -= bytes.as_ref().map_or(0, |bytes| bytes.len());
        entries.push((name, bytes));
    }
    Ok(entries)
}

fn encode(records: &[Record]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(CONTEXT);
    out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (name, value) in records {
        if !valid_name(name) || name.len() > u16::MAX as usize { return Err("Invalid journal record name.".into()); }
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        match value {
            None => out.push(0),
            Some(bytes) => {
                out.push(1);
                out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                out.extend_from_slice(bytes);
            }
        }
        if out.len() > MAX_BYTES + 512 * 1024 { return Err("Restore journal size limit exceeded.".into()); }
    }
    Ok(out)
}

fn take<'a>(bytes: &mut &'a [u8], size: usize) -> Result<&'a [u8], String> {
    if bytes.len() < size { return Err("Truncated restore journal.".into()); }
    let (head, rest) = bytes.split_at(size);
    *bytes = rest;
    Ok(head)
}

fn decode(mut bytes: &[u8]) -> Result<Vec<Record>, String> {
    if take(&mut bytes, CONTEXT.len())? != CONTEXT { return Err("Invalid restore journal context.".into()); }
    let count = u32::from_le_bytes(take(&mut bytes, 4)?.try_into().map_err(|_| "Invalid count")?) as usize;
    if !(STORES.len()..=MAX_RECORDS).contains(&count) { return Err("Invalid restore journal record count.".into()); }
    let mut records = Vec::with_capacity(count);
    let mut names = BTreeSet::new();
    let mut total = 0usize;
    for index in 0..count {
        let len = u16::from_le_bytes(take(&mut bytes, 2)?.try_into().map_err(|_| "Invalid name length")?) as usize;
        let name = std::str::from_utf8(take(&mut bytes, len)?).map_err(|_| "Invalid restore journal name")?.to_string();
        if !valid_name(&name) || !names.insert(name.to_ascii_lowercase()) ||
            (index < STORES.len() && name != STORES[index]) ||
            (index >= STORES.len() && !valid_key_name(&name)) {
            return Err("Invalid or duplicate restore journal record.".into());
        }
        let flag = take(&mut bytes, 1)?[0];
        let value = match flag {
            0 => None,
            1 => {
                let len = u64::from_le_bytes(take(&mut bytes, 8)?.try_into().map_err(|_| "Invalid data length")?);
                let len = usize::try_from(len).map_err(|_| "Invalid data length")?;
                total = total.checked_add(len).ok_or("Restore journal size limit exceeded")?;
                if total > MAX_BYTES { return Err("Restore journal size limit exceeded.".into()); }
                Some(Zeroizing::new(take(&mut bytes, len)?.to_vec()))
            }
            _ => return Err("Invalid restore journal record flag.".into()),
        };
        records.push((name, value));
    }
    if !bytes.is_empty() { return Err("Unexpected trailing restore journal data.".into()); }
    Ok(records)
}

fn sync_keys_if_present(config: &Path) -> Result<(), String> {
    check_key_directory(config)?;
    if config.join("keys").exists() {
        linscp_platform::sync_directory(&config.join("keys")).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Create and flush a complete encrypted journal before changing any target.
/// `key_names` must include every key and metadata path that restore can create.
/// Never replace an existing journal. A caller must recover it first.
pub(crate) fn prepare(config: &Path, vault: &dyn SecretVault, key_names: &[String]) -> Result<(), String> {
    if !vault.protects_session_store() || vault.load_master_key(config).map_err(|e| e.to_string())?.is_none() {
        return Err("Unlock the password vault before preparing restore.".into());
    }
    linscp_platform::create_private_dir(config).map_err(|e| e.to_string())?;
    // Probe the durability barrier before publishing anything: platforms
    // without a directory sync implementation must fail without a journal.
    linscp_platform::sync_directory(config).map_err(|e| format!("Restore durability is unavailable: {e}"))?;
    if pending(config)? { return Err("A previous restore requires recovery first.".into()); }
    let records = snapshot(config, key_names)?;
    let plaintext = encode(&records)?;
    let ciphertext = vault.seal_session_store(&plaintext).map_err(|e| e.to_string())?;
    use rand::RngCore;
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let temp = config.join(format!(".full-restore-journal-{}", random.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    linscp_platform::write_exclusive_private_file(&temp, &ciphertext).map_err(|e| e.to_string())?;
    if let Err(e) = linscp_platform::publish_no_replace(&temp, &config.join(JOURNAL)) {
        let _ = std::fs::remove_file(&temp);
        return Err(format!("Cannot publish restore journal: {e}"));
    }
    // If this fails, leave the journal in place and do not mutate targets.
    linscp_platform::sync_directory(config).map_err(|e| format!("Cannot sync restore journal: {e}"))
}

// Persist restored store directory entries before removing any newly created
// key. Otherwise power loss could resurrect the new sessions file after its
// newly referenced key has already been durably deleted. The journal stays in
// place on barrier failure and recovery can be repeated.
fn rollback_records(
    config: &Path,
    records: Vec<Record>,
    sync_stores: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    // decode has already validated the fixed store prefix.
    let (stores, keys) = records.split_at(STORES.len());
    for (name, original) in stores {
        restore_record(config, name, original)?;
    }
    sync_stores()?;
    for (name, original) in keys {
        restore_record(config, name, original)?;
    }
    Ok(())
}

fn restore_record(config: &Path, name: &str, original: &Option<Zeroizing<Vec<u8>>>) -> Result<(), String> {
    let path = config.join(name);
    let current = read_file(&path, MAX_BYTES)?;
    if current.as_deref().map(Vec::as_slice) == original.as_deref().map(Vec::as_slice) { return Ok(()); }
    match original {
        Some(bytes) => linscp_platform::write_private_file_atomic(&path, bytes).map_err(|e| format!("Cannot recover {name}: {e}")),
        None => std::fs::remove_file(&path).map_err(|e| format!("Cannot remove {name}: {e}")),
    }
}

/// Recover the old configuration idempotently. Journal removal is last, and
/// failure at any stage leaves it available for another recovery attempt.
pub(crate) fn recover(config: &Path, vault: &dyn SecretVault) -> Result<bool, String> {
    let Some(sealed) = read_file(&config.join(JOURNAL), MAX_BYTES + 1024 * 1024)? else { return Ok(false); };
    if !vault.protects_session_store() { return Err("A password vault is required to recover a restore.".into()); }
    let plaintext = vault.open_session_store(&sealed).map_err(|e| format!("Cannot decrypt restore journal: {e}"))?;
    let records = decode(&plaintext)?;
    check_key_directory(config)?;
    rollback_records(config, records, || {
        linscp_platform::sync_directory(config).map_err(|e| e.to_string())
    })?;
    sync_keys_if_present(config)?;
    linscp_platform::sync_directory(config).map_err(|e| e.to_string())?;
    std::fs::remove_file(config.join(JOURNAL)).map_err(|e| e.to_string())?;
    linscp_platform::sync_directory(config).map_err(|e| e.to_string())?;
    Ok(true)
}

/// Finish a restore only after all target file data and metadata are durable.
/// If an error occurs before journal removal, recovery must roll it back.
pub(crate) fn commit(config: &Path, vault: &dyn SecretVault) -> Result<(), String> {
    let path = config.join(JOURNAL);
    let sealed = read_file(&path, MAX_BYTES + 1024 * 1024)?.ok_or("Restore journal is missing.")?;
    let plaintext = vault.open_session_store(&sealed).map_err(|e| format!("Cannot authenticate restore journal: {e}"))?;
    decode(&plaintext)?;
    sync_keys_if_present(config)?;
    linscp_platform::sync_directory(config).map_err(|e| e.to_string())?;
    std::fs::remove_file(path).map_err(|e| e.to_string())?;
    linscp_platform::sync_directory(config).map_err(|e| e.to_string())
}

pub(crate) fn pending(config: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(config.join(JOURNAL)) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linscp_platform::{password_vault::PasswordSecretVault, NativeSecretVault};

    fn vault_at(path: &Path) -> PasswordSecretVault {
        let vault = PasswordSecretVault::new();
        vault.unlock_or_setup(path, "vault password for journal", &NativeSecretVault::new()).unwrap();
        vault
    }

    #[test]
    fn rejects_bad_names_duplicates_and_truncated_records() {
        let temp = tempfile::tempdir().unwrap();
        assert!(snapshot(temp.path(), &["keys/../../sessions.key".into()]).is_err());
        let key = "keys/0123456789abcdef0123456789abcdef.key.vault".to_string();
        assert!(snapshot(temp.path(), &[key.clone(), key.to_uppercase()]).is_err());
        let entries = snapshot(temp.path(), &[key]).unwrap();
        let encoded = encode(&entries).unwrap();
        assert!(decode(&encoded[..encoded.len() - 1]).is_err());
        assert_eq!(decode(&encoded).unwrap().len(), STORES.len() + 1);
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn encrypted_journal_recovers_after_vault_reopen_and_cleans_up_new_keys() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let vault = vault_at(root);
        std::fs::write(root.join("sessions.ini"), b"private original session").unwrap();
        std::fs::write(root.join("workspaces.json"), b"private original workspace").unwrap();
        std::fs::write(root.join("auto-reconnect.json"), b"old reconnect intentions").unwrap();
        let key = "keys/0123456789abcdef0123456789abcdef.key.vault".to_string();
        prepare(root, &vault, &[key.clone()]).unwrap();
        assert!(pending(root).unwrap());
        let bytes = std::fs::read(root.join(JOURNAL)).unwrap();
        assert!(!bytes.windows(b"private original session".len()).any(|s| s == b"private original session"));
        std::fs::write(root.join("sessions.ini"), b"new session").unwrap();
        std::fs::write(root.join("bookmarks.json"), b"new bookmarks").unwrap();
        std::fs::remove_file(root.join("auto-reconnect.json")).unwrap();
        std::fs::create_dir(root.join("keys")).unwrap();
        std::fs::write(root.join(&key), b"new key").unwrap();
        drop(vault);
        let reopened = vault_at(root);
        assert!(recover(root, &reopened).unwrap());
        assert_eq!(std::fs::read(root.join("sessions.ini")).unwrap(), b"private original session");
        assert_eq!(std::fs::read(root.join("workspaces.json")).unwrap(), b"private original workspace");
        assert_eq!(std::fs::read(root.join("auto-reconnect.json")).unwrap(), b"old reconnect intentions");
        assert!(!root.join("bookmarks.json").exists());
        assert!(!root.join(key).exists());
        assert!(!pending(root).unwrap());
        assert!(!recover(root, &reopened).unwrap());
    }

    // Real subprocess termination exercises persistence across process death;
    // it does not simulate power loss or cover every publication boundary.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn interrupted_restore_and_interrupted_recovery_are_retryable() {
        use std::io::{BufRead, Write};
        const KEY: &str = "keys/0123456789abcdef0123456789abcdef.key.vault";
        if let Ok(root) = std::env::var("LINSCP_JOURNAL_CHILD_ROOT") {
            let root = Path::new(&root);
            let vault = vault_at(root);
            match std::env::var("LINSCP_JOURNAL_CHILD_STAGE").unwrap().as_str() {
                "restore" => {
                    prepare(root, &vault, &[KEY.to_string()]).unwrap();
                    linscp_platform::write_private_file_atomic(&root.join("sessions.ini"), b"new sessions").unwrap();
                    std::fs::create_dir(root.join("keys")).unwrap();
                    linscp_platform::write_exclusive_private_file(&root.join(KEY), b"new key").unwrap();
                }
                "recovery" => {
                    let sealed = read_file(&root.join(JOURNAL), MAX_BYTES + 1024 * 1024).unwrap().unwrap();
                    let plaintext = vault.open_session_store(&sealed).unwrap();
                    rollback_records(root, decode(&plaintext).unwrap(), || {
                        println!("LINSCP_CHILD_READY");
                        std::io::stdout().flush().unwrap();
                        loop { std::thread::park(); }
                    }).unwrap();
                    unreachable!();
                }
                _ => panic!("unknown child stage"),
            }
            println!("LINSCP_CHILD_READY");
            std::io::stdout().flush().unwrap();
            loop { std::thread::park(); }
        }
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let vault = vault_at(root);
        std::fs::write(root.join("sessions.ini"), b"old sessions").unwrap();
        drop(vault);
        for stage in ["restore", "recovery"] {
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "restore_journal::tests::interrupted_restore_and_interrupted_recovery_are_retryable", "--nocapture"])
                .env("LINSCP_JOURNAL_CHILD_ROOT", root)
                .env("LINSCP_JOURNAL_CHILD_STAGE", stage)
                .stdout(std::process::Stdio::piped())
                .spawn().unwrap();
            let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
            let mut ready = false;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 { break; }
                if line.contains("LINSCP_CHILD_READY") { ready = true; break; }
            }
            if ready { child.kill().unwrap(); }
            let status = child.wait().unwrap();
            assert!(ready, "child {stage} did not reach its crash boundary: {status}");
            assert!(pending(root).unwrap());
            assert!(root.join(KEY).exists());
        }
        let vault = vault_at(root);
        assert!(recover(root, &vault).unwrap());
        assert_eq!(std::fs::read(root.join("sessions.ini")).unwrap(), b"old sessions");
        assert!(!root.join(KEY).exists());
        assert!(!pending(root).unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn failed_store_barrier_keeps_new_keys_and_journal_for_retry() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let vault = vault_at(root);
        let key = "keys/0123456789abcdef0123456789abcdef.key.vault".to_string();
        std::fs::write(root.join("sessions.ini"), b"old sessions").unwrap();
        prepare(root, &vault, &[key.clone()]).unwrap();
        std::fs::write(root.join("sessions.ini"), b"new sessions").unwrap();
        std::fs::create_dir(root.join("keys")).unwrap();
        std::fs::write(root.join(&key), b"new key").unwrap();
        let sealed = read_file(&root.join(JOURNAL), MAX_BYTES + 1024 * 1024).unwrap().unwrap();
        let plaintext = vault.open_session_store(&sealed).unwrap();
        let records = decode(&plaintext).unwrap();
        assert!(rollback_records(root, records, || Err("injected sync failure".into())).is_err());
        assert_eq!(std::fs::read(root.join("sessions.ini")).unwrap(), b"old sessions");
        assert!(root.join(&key).exists());
        assert!(pending(root).unwrap());
        assert!(recover(root, &vault).unwrap());
        assert!(!root.join(&key).exists());
        assert!(!pending(root).unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn tampered_journal_never_modifies_target_and_is_retained() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let vault = vault_at(root);
        std::fs::write(root.join("sessions.ini"), b"original").unwrap();
        prepare(root, &vault, &[]).unwrap();
        std::fs::write(root.join("sessions.ini"), b"current").unwrap();
        let path = root.join(JOURNAL);
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&path, bytes).unwrap();
        assert!(recover(root, &vault).is_err());
        assert_eq!(std::fs::read(root.join("sessions.ini")).unwrap(), b"current");
        assert!(pending(root).unwrap());
    }

    #[cfg(any(target_os = "linux", target_os = "android", windows))]
    #[test]
    fn commit_keeps_new_state_and_removes_journal() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let vault = vault_at(root);
        std::fs::write(root.join("sessions.ini"), b"old").unwrap();
        prepare(root, &vault, &[]).unwrap();
        linscp_platform::write_private_file_atomic(&root.join("sessions.ini"), b"new").unwrap();
        commit(root, &vault).unwrap();
        assert!(!pending(root).unwrap());
        assert_eq!(std::fs::read(root.join("sessions.ini")).unwrap(), b"new");
    }
}
