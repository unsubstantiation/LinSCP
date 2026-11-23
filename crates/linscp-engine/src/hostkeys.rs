//! Persistent `<config_dir>/sshhostkeys` host-key cache compatible with
//! `source/linux/SshKeys.cpp` (`<lower_host>@<port> <key_type> <fingerprint>`).

use std::path::Path;

use base64::engine::general_purpose::{STANDARD as BASE64, STANDARD_NO_PAD as BASE64_NO_PAD};
use base64::Engine as _;
use linscp_platform::write_private_file_atomic;

const MAX_KNOWN_HOSTS_BYTES: usize = 2 * 1024 * 1024;
const KNOWN_SSH_KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

fn parse_known_hosts_host_token(token: &str) -> Option<(&str, u16)> {
    let t = token.trim();
    if t.is_empty()
        || t.starts_with('!')
        || t.contains('*')
        || t.contains('?')
        || t.contains('@')
        || has_unsafe_token_char(t)
    {
        return None;
    }
    if let Some(rest) = t.strip_prefix('[') {
        if let Some((host, port_str)) = rest.split_once("]:") {
            let port = port_str.parse::<u16>().ok().filter(|&p| p > 0)?;
            if host.is_empty() || host.contains('[') || host.contains(']') || has_unsafe_token_char(host) {
                return None;
            }
            return Some((host, port));
        }
        if let Some(host) = rest.strip_suffix(']') {
            if host.is_empty() || host.contains('[') || host.contains(']') || has_unsafe_token_char(host) {
                return None;
            }
            return Some((host, 22));
        }
        return None;
    }
    if t.contains('[') || t.contains(']') {
        return None;
    }
    Some((t, 22))
}

fn openssh_blob_sha256_fingerprint(key_type: &str, b64_blob: &str) -> Option<String> {
    if !KNOWN_SSH_KEY_TYPES.contains(&key_type) {
        return None;
    }
    let decoded = BASE64
        .decode(b64_blob)
        .or_else(|_| BASE64_NO_PAD.decode(b64_blob.trim_end_matches('=')))
        .ok()?;
    let kt_bytes = key_type.as_bytes();
    if decoded.len() < 4 + kt_bytes.len() + 4 {
        return None;
    }
    let header_len = u32::from_be_bytes([decoded[0], decoded[1], decoded[2], decoded[3]]) as usize;
    if header_len != kt_bytes.len() || &decoded[4..4 + kt_bytes.len()] != kt_bytes {
        return None;
    }
    let digest = linscp_crypto::digests::sha256_bytes(&decoded);
    Some(format!("SHA256:{}", BASE64_NO_PAD.encode(digest)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedHostKeyEntry {
    pub host_port: String,
    pub key_type: String,
    pub key: String,
}

#[derive(Debug, Clone, Default)]
pub struct HostKeyCache {
    entries: Vec<CachedHostKeyEntry>,
}

fn has_unsafe_token_char(s: &str) -> bool {
    s.is_empty()
        || s.bytes()
            .any(|b| b <= 0x20 || b == 0x7f)
}

pub fn format_host_port_key(host: &str, port: u16) -> String {
    let actual_port = if port == 0 { 22 } else { port };
    format!("{}@{actual_port}", host.trim().to_ascii_lowercase())
}

impl HostKeyCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> &[CachedHostKeyEntry] {
        &self.entries
    }

    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let (Some(hp), Some(kt), Some(k)) = (parts.next(), parts.next(), parts.next()) else {
                continue;
            };
            entries.push(CachedHostKeyEntry {
                host_port: hp.to_ascii_lowercase(),
                key_type: kt.to_string(),
                key: k.to_string(),
            });
        }
        Self { entries }
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) if text.starts_with("LSCP-PROTECTED-FILE-1\n") => Err("Unlock the local vault to read host keys".into()),
            Ok(text) => Ok(Self::parse(&text)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(err) => Err(format!("Cannot read {}: {err}", path.display())),
        }
    }

    pub fn load_protected(path: &Path, vault: &dyn linscp_platform::SecretVault) -> Result<Self, String> {
        let Some(bytes) = crate::protected_file::read(path, "ssh-host-keys", vault)? else { return Ok(Self::new()); };
        let text = std::str::from_utf8(&bytes).map_err(|e| format!("Invalid host-key cache: {e}"))?;
        Self::validate(text)?;
        Ok(Self::parse(text))
    }

    pub fn validate(text: &str) -> Result<(), String> {
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 3 || fields.iter().any(|s| has_unsafe_token_char(s)) {
                return Err("Invalid host-key cache entry".into());
            }
        }
        Ok(())
    }

    pub fn save_protected(&self, path: &Path, vault: &dyn linscp_platform::SecretVault) -> Result<(), String> {
        let text = zeroize::Zeroizing::new(self.serialize());
        crate::protected_file::write(path, "ssh-host-keys", vault, text.as_bytes())
    }

    pub fn lookup(&self, host: &str, port: u16, key_type: &str) -> Option<&str> {
        let hp = format_host_port_key(host, port);
        self.entries
            .iter()
            .find(|e| e.host_port == hp && e.key_type == key_type)
            .map(|e| e.key.as_str())
    }

    pub fn upsert(
        &mut self,
        host: &str,
        port: u16,
        key_type: &str,
        key: &str,
    ) -> Result<(), String> {
        let hp = format_host_port_key(host, port);
        if has_unsafe_token_char(&hp)
            || has_unsafe_token_char(key_type)
            || has_unsafe_token_char(key)
        {
            return Err("Invalid characters in SSH host-key cache entry".to_string());
        }
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.host_port == hp && e.key_type == key_type)
        {
            existing.key = key.to_string();
        } else {
            self.entries.push(CachedHostKeyEntry {
                host_port: hp,
                key_type: key_type.to_string(),
                key: key.to_string(),
            });
        }
        Ok(())
    }

    pub fn remove(&mut self, host_port: &str, key_type: &str) -> bool {
        let norm_hp = host_port.trim().to_ascii_lowercase();
        let kt = key_type.trim();
        let before = self.entries.len();
        self.entries
            .retain(|e| !(e.host_port == norm_hp && e.key_type == kt));
        self.entries.len() != before
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Imports plain OpenSSH `known_hosts` lines into the cache, returning
    /// `(imported_entries, skipped_items)`. Hashed (`|1|...`), wildcard,
    /// `@cert-authority`, `@revoked`, and malformed entries are skipped safely.
    pub fn import_openssh_known_hosts(&mut self, text: &str) -> Result<(usize, usize), String> {
        if text.len() > MAX_KNOWN_HOSTS_BYTES {
            return Err("known_hosts file is too large (limit 2 MiB).".to_string());
        }
        if text.contains('\0') {
            return Err("known_hosts content contains NUL bytes.".to_string());
        }
        let mut imported = 0usize;
        let mut skipped = 0usize;
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(first) = parts.next() else {
                continue;
            };
            if first.starts_with('@') {
                skipped += 1;
                continue;
            }
            let hosts_field = first;
            let (Some(key_type), Some(b64_blob)) = (parts.next(), parts.next()) else {
                skipped += 1;
                continue;
            };
            if hosts_field.starts_with('|') {
                skipped += 1;
                continue;
            }
            let Some(fingerprint) = openssh_blob_sha256_fingerprint(key_type, b64_blob) else {
                skipped += 1;
                continue;
            };
            for token in hosts_field.split(',') {
                let Some((host, port)) = parse_known_hosts_host_token(token) else {
                    skipped += 1;
                    continue;
                };
                if self.upsert(host, port, key_type, &fingerprint).is_ok() {
                    imported += 1;
                } else {
                    skipped += 1;
                }
            }
        }
        Ok((imported, skipped))
    }

    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            out.push_str(&entry.host_port);
            out.push(' ');
            out.push_str(&entry.key_type);
            out.push(' ');
            out.push_str(&entry.key);
            out.push('\n');
        }
        out
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        write_private_file_atomic(path, self.serialize().as_bytes()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostkey_cache_round_trips_and_rejects_control_injection() {
        let mut cache = HostKeyCache::new();
        cache
            .upsert("Prod.Example.com", 2222, "ssh-ed25519", "SHA256:AbCdEf123")
            .unwrap();
        assert!(cache
            .upsert("bad\nhost", 22, "ssh-ed25519", "SHA256:x")
            .is_err());

        let mut reparsed = HostKeyCache::parse(&cache.serialize());
        assert_eq!(
            reparsed.lookup("prod.example.com", 2222, "ssh-ed25519"),
            Some("SHA256:AbCdEf123")
        );
        assert!(!reparsed.remove("prod.example.com@2222", "ssh-rsa"));
        assert!(reparsed.remove("PROD.EXAMPLE.COM@2222", "ssh-ed25519"));
        assert_eq!(
            reparsed.lookup("prod.example.com", 2222, "ssh-ed25519"),
            None
        );
    }

    #[test]
    fn import_openssh_known_hosts_parses_hosts_ports_and_skips_hashed_or_revoked() {
        let ed_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";
        let expected_fp = "SHA256:mKqU+0K8OhKmA8bBQi9Rz0Q5l7/g160hIP+rJYSTNj4";
        let sample = format!(
            "# OpenSSH known_hosts sample\n\
             Git.Example.com,[git.example.com]:2222,[::1]:2200 ssh-ed25519 {ed_blob} deploy@ws\n\
             |1|F1E2D3C4=|A1B2C3D4= ssh-ed25519 {ed_blob}\n\
             @revoked bad.example.com ssh-ed25519 {ed_blob}\n\
             *.wildcard.example.com,plain.example.com ssh-ed25519 {ed_blob}\n\
             mismatch.example.com ssh-rsa {ed_blob}\n"
        );
        let mut cache = HostKeyCache::new();
        let (imported, skipped) = cache.import_openssh_known_hosts(&sample).unwrap();
        assert_eq!(imported, 4);
        assert_eq!(skipped, 4);
        assert_eq!(
            cache.lookup("git.example.com", 22, "ssh-ed25519"),
            Some(expected_fp)
        );
        assert_eq!(
            cache.lookup("git.example.com", 2222, "ssh-ed25519"),
            Some(expected_fp)
        );
        assert_eq!(
            cache.lookup("::1", 2200, "ssh-ed25519"),
            Some(expected_fp)
        );
        assert_eq!(
            cache.lookup("plain.example.com", 22, "ssh-ed25519"),
            Some(expected_fp)
        );
        assert_eq!(cache.lookup("bad.example.com", 22, "ssh-ed25519"), None);
        assert_eq!(cache.lookup("mismatch.example.com", 22, "ssh-rsa"), None);
    }
}
