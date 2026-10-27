//! Persistent `<config_dir>/sshhostkeys` host-key cache compatible with
//! `source/linux/SshKeys.cpp` (`<lower_host>@<port> <key_type> <fingerprint>`).

use std::path::Path;

use linscp_platform::write_private_file_atomic;

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
            Ok(text) => Ok(Self::parse(&text)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(err) => Err(format!("Cannot read {}: {err}", path.display())),
        }
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

        let reparsed = HostKeyCache::parse(&cache.serialize());
        assert_eq!(
            reparsed.lookup("prod.example.com", 2222, "ssh-ed25519"),
            Some("SHA256:AbCdEf123")
        );
    }
}
