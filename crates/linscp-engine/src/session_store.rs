//! Full `sessions.ini` codec and persistent `SessionStore`, byte-compatible
//! with `source/linux/SessionStore.cpp` and `source/gui/linscp_gui.py`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use linscp_crypto::{decrypt_password, encrypt_password, is_encrypted_password, SessionMasterKey};
use linscp_platform::{write_private_file_atomic, SecretVault};
use linscp_types::{ProtocolScheme, SessionConfig, StoredSessionSummary, TunnelConfig};

/// Escapes `\\`, `\n`, `\r`, and `\t` identically to `EscapeValue` in `SessionStore.cpp`.
pub fn escape_ini_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

/// Unescapes `\\`, `\n`, `\r`, and `\t` identically to `UnescapeValue` in `SessionStore.cpp`.
pub fn unescape_ini_value(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSite {
    pub name: String,
    pub protocol: ProtocolScheme,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    /// Preserved raw `lscp1$` ciphertext when `sessions.key` was unavailable or
    /// mismatched, preventing unrelated edits from wiping another site's secret.
    pub password_raw: Option<String>,
    pub password_error: Option<String>,
    pub private_key: Option<String>,
    pub hostkey: Option<String>,
    pub remote_directory: String,
    pub local_directory: String,
    pub preset: String,
    pub last_used: Option<u64>,

    // Proxy fields
    pub proxy_method: String,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_username: String,
    pub proxy_password: Option<String>,
    pub proxy_password_raw: Option<String>,
    pub proxy_command: String,
    pub proxy_exclude: String,
    pub proxy_dns: String,
    pub proxy_localhost: bool,

    // SSH jump / tunnel fields
    pub tunnel: TunnelConfig,
    pub tunnel_password_raw: Option<String>,
    pub tunnel_passphrase: Option<String>,
    pub tunnel_passphrase_raw: Option<String>,

    // Preserved protocol-specific & future INI keys (`s3_*`, `ftp_*`, `tls_*`, etc.)
    pub extra_fields: BTreeMap<String, String>,
}

impl StoredSite {
    pub fn new(name: impl Into<String>, protocol: ProtocolScheme, host: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            protocol,
            host: host.into(),
            port: protocol.default_port(),
            username: String::new(),
            password: None,
            password_raw: None,
            password_error: None,
            private_key: None,
            hostkey: None,
            remote_directory: String::new(),
            local_directory: String::new(),
            preset: String::new(),
            last_used: None,
            proxy_method: String::new(),
            proxy_host: String::new(),
            proxy_port: 0,
            proxy_username: String::new(),
            proxy_password: None,
            proxy_password_raw: None,
            proxy_command: String::new(),
            proxy_exclude: String::new(),
            proxy_dns: String::new(),
            proxy_localhost: false,
            tunnel: TunnelConfig::default(),
            tunnel_password_raw: None,
            tunnel_passphrase: None,
            tunnel_passphrase_raw: None,
            extra_fields: BTreeMap::new(),
        }
    }

    pub fn from_session_config(cfg: &SessionConfig) -> Self {
        let mut site = Self::new(&cfg.name, cfg.protocol, &cfg.host);
        site.port = if cfg.port == 0 {
            cfg.protocol.default_port()
        } else {
            cfg.port
        };
        site.username.clone_from(&cfg.username);
        site.password.clone_from(&cfg.password);
        site.private_key.clone_from(&cfg.keyfile);
        site.hostkey = if cfg.hostkey.is_empty() {
            None
        } else {
            Some(cfg.hostkey.clone())
        };
        site.remote_directory.clone_from(&cfg.initial_dir);
        site.local_directory.clone_from(&cfg.local_dir);
        if let Some(tunnel) = &cfg.tunnel {
            site.tunnel = tunnel.clone();
        }
        site
    }

    pub fn to_session_config(&self) -> SessionConfig {
        SessionConfig {
            name: self.name.clone(),
            protocol: self.protocol,
            host: self.host.clone(),
            port: if self.port == 0 {
                self.protocol.default_port()
            } else {
                self.port
            },
            username: self.username.clone(),
            password: self.password.clone(),
            keyfile: self.private_key.clone(),
            hostkey: self.hostkey.clone().unwrap_or_default(),
            initial_dir: self.remote_directory.clone(),
            local_dir: self.local_directory.clone(),
            tunnel: if self.tunnel.enabled || !self.tunnel.host.is_empty() {
                Some(self.tunnel.clone())
            } else {
                None
            },
        }
    }

    pub fn folder_and_leaf(&self) -> (&str, &str) {
        match self.name.split_once('/') {
            Some((folder, leaf)) if !folder.is_empty() && !leaf.is_empty() => (folder, leaf),
            _ => ("", self.name.as_str()),
        }
    }

    pub fn summary(&self) -> StoredSessionSummary {
        let (folder, leaf) = self.folder_and_leaf();
        StoredSessionSummary {
            name: self.name.clone(),
            folder: folder.to_string(),
            leaf_name: leaf.to_string(),
            protocol: self.protocol,
            host: self.host.clone(),
            port: if self.port == 0 {
                self.protocol.default_port()
            } else {
                self.port
            },
            username: self.username.clone(),
            has_password: self.password.as_deref().is_some_and(|p| !p.is_empty())
                || self.password_raw.is_some(),
            has_unreadable_secret: self.password_raw.is_some()
                || self.proxy_password_raw.is_some()
                || self.tunnel_password_raw.is_some()
                || self.tunnel_passphrase_raw.is_some(),
            initial_dir: self.remote_directory.clone(),
            local_dir: self.local_directory.clone(),
        }
    }

    pub fn needs_encryption_key(&self) -> bool {
        self.password.as_deref().is_some_and(|s| !s.is_empty())
            || self.proxy_password.as_deref().is_some_and(|s| !s.is_empty())
            || self.tunnel.password.as_deref().is_some_and(|s| !s.is_empty())
            || self.tunnel_passphrase.as_deref().is_some_and(|s| !s.is_empty())
    }
}

fn decode_secret_field(
    raw_value: &str,
    master_key: Option<&SessionMasterKey>,
) -> (Option<String>, Option<String>, Option<String>) {
    if raw_value.is_empty() {
        return (None, None, None);
    }
    if is_encrypted_password(raw_value) {
        let Some(key) = master_key else {
            return (
                None,
                Some(raw_value.to_string()),
                Some("Missing sessions.key needed to decrypt saved password".to_string()),
            );
        };
        match decrypt_password(raw_value, key) {
            Ok(plain) => (Some(plain), None, None),
            Err(err) => (None, Some(raw_value.to_string()), Some(err.to_string())),
        }
    } else {
        (Some(raw_value.to_string()), None, None)
    }
}

fn encode_secret_field(
    plaintext: Option<&str>,
    preserved_raw: Option<&str>,
    master_key: Option<&SessionMasterKey>,
) -> Result<Option<String>, String> {
    if let Some(plain) = plaintext.filter(|s| !s.is_empty()) {
        let key = master_key
            .ok_or_else(|| "Master key is required to encrypt saved passwords".to_string())?;
        let encrypted = encrypt_password(plain, key).map_err(|e| e.to_string())?;
        return Ok(Some(encrypted));
    }
    if let Some(raw) = preserved_raw.filter(|s| !s.is_empty()) {
        return Ok(Some(raw.to_string()));
    }
    Ok(None)
}

fn parse_bool_ini(val: &str) -> bool {
    matches!(
        val.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

#[derive(Debug, Clone, Default)]
pub struct SessionStore {
    sites: Vec<StoredSite>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sites(&self) -> &[StoredSite] {
        &self.sites
    }

    pub fn parse_ini(
        ini_text: &str,
        master_key: Option<&SessionMasterKey>,
    ) -> Result<Self, String> {
        let mut store = Self::new();
        let mut current_name: Option<String> = None;
        let mut current_fields: Vec<(String, String)> = Vec::new();

        let flush_section = |name_opt: Option<String>,
                             fields: &mut Vec<(String, String)>,
                             out: &mut Vec<StoredSite>| {
            let Some(section_name) = name_opt.filter(|s| !s.trim().is_empty()) else {
                fields.clear();
                return;
            };
            let mut map = BTreeMap::new();
            for (k, v) in fields.drain(..) {
                map.insert(k, v);
            }
            let protocol = map
                .remove("protocol")
                .and_then(|p| ProtocolScheme::parse(&p))
                .unwrap_or(ProtocolScheme::Sftp);
            let host = map.remove("host").unwrap_or_default();
            let mut site = StoredSite::new(section_name, protocol, host);
            site.port = map
                .remove("port")
                .and_then(|p| p.parse::<u16>().ok())
                .filter(|&p| p > 0)
                .unwrap_or_else(|| protocol.default_port());
            site.username = map.remove("username").unwrap_or_default();

            if let Some(pw) = map.remove("password") {
                let (plain, raw, err) = decode_secret_field(&pw, master_key);
                site.password = plain;
                site.password_raw = raw;
                site.password_error = err;
            }
            site.private_key = map.remove("private_key").filter(|s| !s.is_empty());
            site.hostkey = map.remove("hostkey").filter(|s| !s.is_empty());
            site.remote_directory = map.remove("remote_directory").unwrap_or_default();
            site.local_directory = map.remove("local_directory").unwrap_or_default();
            site.preset = map.remove("preset").unwrap_or_default();
            site.last_used = map
                .remove("last_used")
                .and_then(|v| v.parse::<u64>().ok());

            site.proxy_method = map.remove("proxy_method").unwrap_or_default();
            site.proxy_host = map.remove("proxy_host").unwrap_or_default();
            site.proxy_port = map
                .remove("proxy_port")
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(0);
            site.proxy_username = map.remove("proxy_username").unwrap_or_default();
            if let Some(ppw) = map.remove("proxy_password") {
                let (plain, raw, _) = decode_secret_field(&ppw, master_key);
                site.proxy_password = plain;
                site.proxy_password_raw = raw;
            }
            site.proxy_command = map.remove("proxy_command").unwrap_or_default();
            site.proxy_exclude = map.remove("proxy_exclude").unwrap_or_default();
            site.proxy_dns = map.remove("proxy_dns").unwrap_or_default();
            site.proxy_localhost = map
                .remove("proxy_localhost")
                .map(|v| parse_bool_ini(&v))
                .unwrap_or(false);

            site.tunnel.enabled = map
                .remove("tunnel")
                .map(|v| parse_bool_ini(&v))
                .unwrap_or(false);
            site.tunnel.host = map.remove("tunnel_host").unwrap_or_default();
            site.tunnel.port = map
                .remove("tunnel_port")
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(0);
            site.tunnel.username = map.remove("tunnel_username").unwrap_or_default();
            if let Some(tpw) = map.remove("tunnel_password") {
                let (plain, raw, _) = decode_secret_field(&tpw, master_key);
                site.tunnel.password = plain;
                site.tunnel_password_raw = raw;
            }
            site.tunnel.keyfile = map.remove("tunnel_private_key").filter(|s| !s.is_empty());
            if let Some(tpass) = map.remove("tunnel_passphrase") {
                let (plain, raw, _) = decode_secret_field(&tpass, master_key);
                site.tunnel_passphrase = plain;
                site.tunnel_passphrase_raw = raw;
            }
            site.tunnel.hostkey = map.remove("tunnel_hostkey").unwrap_or_default();
            site.tunnel.local_port = map
                .remove("tunnel_local_port")
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(0);

            site.extra_fields = map;
            if let Some(existing) = out.iter_mut().find(|s| s.name == site.name) {
                *existing = site;
            } else {
                out.push(site);
            }
        };

        for raw_line in ini_text.lines() {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                flush_section(current_name.take(), &mut current_fields, &mut store.sites);
                current_name = Some(unescape_ini_value(&trimmed[1..trimmed.len() - 1]));
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let clean_key = key.trim().to_ascii_lowercase();
                // Value strips leading spaces before unescaping, matching SessionStore.cpp
                let raw_val = value.trim_start_matches([' ', '\t']);
                current_fields.push((clean_key, unescape_ini_value(raw_val)));
            }
        }
        flush_section(current_name, &mut current_fields, &mut store.sites);
        Ok(store)
    }

    pub fn serialize_ini(&self, master_key: Option<&SessionMasterKey>) -> Result<String, String> {
        let mut out = String::from("# LinSCP saved sessions\n\n");
        for site in &self.sites {
            out.push('[');
            out.push_str(&escape_ini_value(&site.name));
            out.push_str("]\n");
            out.push_str(&format!("protocol={}\n", site.protocol.as_str()));
            if !site.host.is_empty() {
                out.push_str(&format!("host={}\n", escape_ini_value(&site.host)));
            }
            if site.port != 0 {
                out.push_str(&format!("port={}\n", site.port));
            }
            if !site.username.is_empty() {
                out.push_str(&format!("username={}\n", escape_ini_value(&site.username)));
            }
            if let Some(enc_pw) = encode_secret_field(
                site.password.as_deref(),
                site.password_raw.as_deref(),
                master_key,
            )? {
                out.push_str(&format!("password={}\n", escape_ini_value(&enc_pw)));
            }
            if let Some(pk) = site.private_key.as_deref().filter(|s| !s.is_empty()) {
                out.push_str(&format!("private_key={}\n", escape_ini_value(pk)));
            }
            if let Some(hk) = site.hostkey.as_deref().filter(|s| !s.is_empty()) {
                out.push_str(&format!("hostkey={}\n", escape_ini_value(hk)));
            }
            if !site.remote_directory.is_empty() {
                out.push_str(&format!(
                    "remote_directory={}\n",
                    escape_ini_value(&site.remote_directory)
                ));
            }
            if !site.local_directory.is_empty() {
                out.push_str(&format!(
                    "local_directory={}\n",
                    escape_ini_value(&site.local_directory)
                ));
            }
            if !site.preset.is_empty() {
                out.push_str(&format!("preset={}\n", escape_ini_value(&site.preset)));
            }
            if let Some(ts) = site.last_used {
                out.push_str(&format!("last_used={ts}\n"));
            }

            if !site.proxy_method.is_empty() {
                out.push_str(&format!(
                    "proxy_method={}\n",
                    escape_ini_value(&site.proxy_method)
                ));
            }
            if !site.proxy_host.is_empty() {
                out.push_str(&format!(
                    "proxy_host={}\n",
                    escape_ini_value(&site.proxy_host)
                ));
            }
            if site.proxy_port != 0 {
                out.push_str(&format!("proxy_port={}\n", site.proxy_port));
            }
            if !site.proxy_username.is_empty() {
                out.push_str(&format!(
                    "proxy_username={}\n",
                    escape_ini_value(&site.proxy_username)
                ));
            }
            if let Some(enc_ppw) = encode_secret_field(
                site.proxy_password.as_deref(),
                site.proxy_password_raw.as_deref(),
                master_key,
            )? {
                out.push_str(&format!(
                    "proxy_password={}\n",
                    escape_ini_value(&enc_ppw)
                ));
            }
            if !site.proxy_command.is_empty() {
                out.push_str(&format!(
                    "proxy_command={}\n",
                    escape_ini_value(&site.proxy_command)
                ));
            }
            if !site.proxy_exclude.is_empty() {
                out.push_str(&format!(
                    "proxy_exclude={}\n",
                    escape_ini_value(&site.proxy_exclude)
                ));
            }
            if !site.proxy_dns.is_empty() {
                out.push_str(&format!(
                    "proxy_dns={}\n",
                    escape_ini_value(&site.proxy_dns)
                ));
            }
            if site.proxy_localhost {
                out.push_str("proxy_localhost=1\n");
            }

            if site.tunnel.enabled {
                out.push_str("tunnel=1\n");
            }
            if !site.tunnel.host.is_empty() {
                out.push_str(&format!(
                    "tunnel_host={}\n",
                    escape_ini_value(&site.tunnel.host)
                ));
            }
            if site.tunnel.port != 0 {
                out.push_str(&format!("tunnel_port={}\n", site.tunnel.port));
            }
            if !site.tunnel.username.is_empty() {
                out.push_str(&format!(
                    "tunnel_username={}\n",
                    escape_ini_value(&site.tunnel.username)
                ));
            }
            if let Some(enc_tpw) = encode_secret_field(
                site.tunnel.password.as_deref(),
                site.tunnel_password_raw.as_deref(),
                master_key,
            )? {
                out.push_str(&format!(
                    "tunnel_password={}\n",
                    escape_ini_value(&enc_tpw)
                ));
            }
            if let Some(tpk) = site.tunnel.keyfile.as_deref().filter(|s| !s.is_empty()) {
                out.push_str(&format!("tunnel_private_key={}\n", escape_ini_value(tpk)));
            }
            if let Some(enc_tpass) = encode_secret_field(
                site.tunnel_passphrase.as_deref(),
                site.tunnel_passphrase_raw.as_deref(),
                master_key,
            )? {
                out.push_str(&format!(
                    "tunnel_passphrase={}\n",
                    escape_ini_value(&enc_tpass)
                ));
            }
            if !site.tunnel.hostkey.is_empty() {
                out.push_str(&format!(
                    "tunnel_hostkey={}\n",
                    escape_ini_value(&site.tunnel.hostkey)
                ));
            }
            if site.tunnel.local_port != 0 {
                out.push_str(&format!("tunnel_local_port={}\n", site.tunnel.local_port));
            }

            for (extra_k, extra_v) in &site.extra_fields {
                out.push_str(&format!("{extra_k}={}\n", escape_ini_value(extra_v)));
            }
            out.push('\n');
        }
        Ok(out)
    }

    pub fn load_from_dir(config_dir: &Path, vault: &dyn SecretVault) -> Result<Self, String> {
        let ini_path = config_dir.join("sessions.ini");
        let text = match std::fs::read_to_string(&ini_path) {
            Ok(s) => s,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(err) => return Err(format!("Cannot read {}: {err}", ini_path.display())),
        };
        let master = vault
            .load_master_key(config_dir)
            .ok()
            .flatten()
            .map(|z| SessionMasterKey::from_array(*z));
        Self::parse_ini(&text, master.as_ref())
    }

    pub fn save_to_dir(&self, config_dir: &Path, vault: &dyn SecretVault) -> Result<(), String> {
        let needs_key = self.sites.iter().any(StoredSite::needs_encryption_key);
        let master = if needs_key {
            let z = vault
                .load_or_create_master_key(config_dir)
                .map_err(|e| e.to_string())?;
            Some(SessionMasterKey::from_array(*z))
        } else {
            vault
                .load_master_key(config_dir)
                .map_err(|e| e.to_string())?
                .map(|z| SessionMasterKey::from_array(*z))
        };
        let rendered = self.serialize_ini(master.as_ref())?;
        write_private_file_atomic(&config_dir.join("sessions.ini"), rendered.as_bytes())
            .map_err(|e| e.to_string())
    }

    pub fn find(&self, name: &str) -> Option<&StoredSite> {
        self.sites
            .iter()
            .find(|s| s.name == name)
            .or_else(|| self.sites.iter().find(|s| s.name.eq_ignore_ascii_case(name)))
    }

    pub fn upsert(&mut self, mut site: StoredSite) {
        if let Some(existing) = self.sites.iter_mut().find(|s| s.name == site.name) {
            // Preserve unreadable raw secrets when caller leaves password unset
            if site.password.is_none() && site.password_raw.is_none() {
                site.password_raw = existing.password_raw.take();
                site.password_error = existing.password_error.take();
            }
            *existing = site;
        } else {
            self.sites.push(site);
        }
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.sites.len();
        self.sites.retain(|s| s.name != name);
        self.sites.len() != before
    }

    pub fn rename(&mut self, old_name: &str, new_name: &str) -> bool {
        if new_name.trim().is_empty() || self.sites.iter().any(|s| s.name == new_name) {
            return false;
        }
        if let Some(site) = self.sites.iter_mut().find(|s| s.name == old_name) {
            site.name = new_name.to_string();
            return true;
        }
        false
    }

    pub fn folders(&self) -> Vec<String> {
        let mut set = BTreeSet::new();
        for site in &self.sites {
            let (folder, _) = site.folder_and_leaf();
            if !folder.is_empty() {
                set.insert(folder.to_string());
            }
        }
        set.into_iter().collect()
    }

    pub fn remove_folder(&mut self, folder: &str) -> usize {
        if folder.is_empty() {
            return 0;
        }
        let prefix = format!("{folder}/");
        let before = self.sites.len();
        self.sites.retain(|s| !s.name.starts_with(&prefix));
        before - self.sites.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ini_escaping_and_unreadable_secret_preservation_match_cpp_store() {
        let key_a = SessionMasterKey::from_array([0x11; 32]);
        let key_b = SessionMasterKey::from_array([0x22; 32]);

        let mut store = SessionStore::new();
        let mut prod = StoredSite::new("prod/app", ProtocolScheme::Sftp, "10.0.0.5");
        prod.username = "deploy".to_string();
        prod.password = Some("s3cr3t\twith\ttabs".to_string());
        prod.remote_directory = "/srv\twith\ttab\nand\nline".to_string();
        store.upsert(prod);

        let ini_text = store.serialize_ini(Some(&key_a)).unwrap();
        assert!(ini_text.contains("remote_directory=/srv\\twith\\ttab\\nand\\nline\n"));

        // Load under a DIFFERENT master key (`key_b`): `prod/app` keeps `password_raw`
        let mut loaded_wrong_key = SessionStore::parse_ini(&ini_text, Some(&key_b)).unwrap();
        let site_wrong = loaded_wrong_key.find("prod/app").unwrap();
        assert!(site_wrong.password.is_none());
        assert!(site_wrong.password_raw.is_some());
        assert_eq!(site_wrong.remote_directory, "/srv\twith\ttab\nand\nline");

        // Add an unrelated site and re-save under `key_b`: `prod/app`'s original
        // ciphertext MUST survive intact and still decrypt under `key_a`!
        let staging = StoredSite::new("staging/web", ProtocolScheme::Https, "example.org");
        loaded_wrong_key.upsert(staging);
        let resaved_ini = loaded_wrong_key.serialize_ini(Some(&key_b)).unwrap();

        let recovered = SessionStore::parse_ini(&resaved_ini, Some(&key_a)).unwrap();
        assert_eq!(
            recovered.find("prod/app").unwrap().password.as_deref(),
            Some("s3cr3t\twith\ttabs")
        );
        assert_eq!(recovered.folders(), vec!["prod", "staging"]);
    }
}
