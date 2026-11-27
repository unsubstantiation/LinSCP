//! Shared, fail-closed primitives for files stored in the local vault's key directory.
//! Format-specific limits, metadata interpretation, and restore policies belong
//! to callers rather than this module.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;

/// Vault key and TLS blob identifiers are exactly 16 bytes encoded as hex.
pub fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Find regular files with `suffix`, rejecting unsafe names and case collisions.
/// A missing key directory is an empty vault; other errors are not ignored.
pub fn list_ids(dir: &Path, suffix: &str, limit: usize) -> Result<Vec<String>, String> {
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_dir() => {},
        Ok(_) => return Err("The vault keys path is not a directory.".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("Cannot inspect vault keys: {error}")),
    }
    let entries = std::fs::read_dir(dir).map_err(|error| format!("Cannot list vault keys: {error}"))?;
    let mut seen = BTreeSet::new();
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| format!("Cannot list vault keys: {error}"))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("Invalid vault key filename")?;
        let Some(id) = name.strip_suffix(suffix) else { continue };
        if !valid_id(id) || !seen.insert(id.to_ascii_lowercase())
            || !entry.file_type().map_err(|error| error.to_string())?.is_file() {
            return Err(format!("Invalid or duplicate vault key file: {name}"));
        }
        if ids.len() >= limit { return Err("Too many vault key files.".into()); }
        ids.push(id.to_string());
    }
    ids.sort();
    Ok(ids)
}

/// Read an optional vault file without following symlinks, bounded even if it
/// grows after inspection. The caller chooses the applicable format limit.
pub fn read_file(path: &Path, limit: usize) -> Result<Option<Vec<u8>>, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ids_are_exactly_hex_and_list_is_sorted() {
        assert!(valid_id("abcdef0123456789ABCDEF0123456789"));
        for id in ["", "123", "0123456789abcdef0123456789abcdeg", "0123456789abcdef0123456789abcd/0"] {
            assert!(!valid_id(id));
        }
        let temp = tempfile::tempdir().unwrap();
        let keys = temp.path().join("keys");
        assert!(list_ids(&keys, ".key.vault", 2000).unwrap().is_empty());
        std::fs::create_dir(&keys).unwrap();
        let a = "0123456789abcdef0123456789abcdef";
        let b = "ffffffffffffffffffffffffffffffff";
        std::fs::write(keys.join(format!("{b}.key.vault")), b"b").unwrap();
        std::fs::write(keys.join(format!("{a}.key.vault")), b"a").unwrap();
        assert_eq!(list_ids(&keys, ".key.vault", 2000).unwrap(), vec![a, b]);
        std::fs::write(keys.join("bad.key.vault"), b"bad").unwrap();
        assert!(list_ids(&keys, ".key.vault", 2000).is_err());
    }

    #[test]
    fn bounded_read_refuses_oversize_and_missing_is_distinct() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("key");
        assert_eq!(read_file(&path, 3).unwrap(), None);
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(read_file(&path, 3).unwrap().unwrap(), b"abc");
        assert!(read_file(&path, 2).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_case_collisions_are_rejected() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        let id = "abcdef0123456789abcdef0123456789";
        let path = dir.join(format!("{id}.key.vault"));
        std::fs::write(&path, b"secret").unwrap();
        let link = dir.join(format!("{}.key.vault", id.to_ascii_uppercase()));
        symlink(&path, &link).unwrap();
        assert!(read_file(&link, 100).is_err());
        assert!(list_ids(dir, ".key.vault", 2000).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::write(&link, b"different").unwrap();
        assert!(list_ids(dir, ".key.vault", 2000).is_err());
        let linked_dir = dir.join("linked");
        symlink(dir, &linked_dir).unwrap();
        assert!(list_ids(&linked_dir, ".key.vault", 2000).is_err());
    }
}
