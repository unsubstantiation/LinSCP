#![allow(unused_variables, unused_imports, dead_code, clippy::all)]
//! Connection-pooled Commander tabs (`TabRuntime`), local-to-local tabs,
//! session JSON <-> `ParsedSiteSpec` conversion, and SSH host-key challenges.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use linscp_crypto::SessionMasterKey;
use linscp_engine::session_store::{SessionStore, StoredSite};
use linscp_engine::url_and_raw::{
    apply_env_credential_fallbacks, connect_gui_site_spec, parse_site_url, site_spec_from_stored,
    stored_site_from_spec, validate_session_settings, validate_ssh_gssapi_policy, GuiConnectError,
    GuiHostKeyChallenge, ParsedSiteSpec,
};
use linscp_platform::gui_os::default_os_username;
use linscp_platform::SecretVault;
use linscp_proto::RemoteSession;
use linscp_types::{ProtocolScheme, SessionConfig, TunnelConfig};
use serde_json::{json, Value};

#[derive(Clone)]
pub struct TabRuntime {
    pub id: u64,
    pub name: String,
    pub site_name: Option<String>,
    pub is_local: bool,
    pub connected: bool,
    pub local_dir: String,
    pub remote_dir: String,
    pub other_local_dir: String,
    pub observed_hostkey: String,
    pub hostkey_role: String,
    pub hostkey_changed: bool,
    pub error: String,
    pub spec: Option<ParsedSiteSpec>,
    pub session_json: Value,
    pub remote: Option<Arc<dyn RemoteSession>>,
}

impl TabRuntime {
    pub fn hostkey_challenge_json(&self) -> Value {
        let (host, port) = if self.hostkey_role == "tunnel" {
            let h = self
                .spec
                .as_ref()
                .and_then(|s| s.session.tunnel.as_ref().map(|t| t.host.clone()))
                .unwrap_or_default();
            let p = self
                .spec
                .as_ref()
                .and_then(|s| s.session.tunnel.as_ref().map(|t| if t.port == 0 { 22 } else { t.port }))
                .unwrap_or(22);
            (h, p)
        } else {
            let h = self
                .spec
                .as_ref()
                .map(|s| s.session.host.clone())
                .unwrap_or_default();
            let p = self
                .spec
                .as_ref()
                .map(|s| {
                    if s.session.port == 0 {
                        s.session.protocol.default_port()
                    } else {
                        s.session.port
                    }
                })
                .unwrap_or(22);
            (h, p)
        };
        json!({
            "tab": self.id,
            "host": host,
            "port": port,
            "fingerprint": self.observed_hostkey,
            "role": self.hostkey_role,
            "changed": self.hostkey_changed,
        })
    }

    pub fn describe(&self) -> Value {
        let mut redacted = self.session_json.clone();
        if let Some(obj) = redacted.as_object_mut() {
            for key in ["s3_secret_key", "s3_session_token", "proxy_password", "passphrase", "key_passphrase", "clear_password", "clear_key_passphrase", "clear_proxy_password", "keep_password", "keep_key_passphrase", "keep_proxy_password", "keep_tunnel_password", "keep_tunnel_passphrase"] { obj.remove(key); }
            obj.remove("password");
            obj.remove("tunnel_password");
            obj.remove("tunnel_passphrase");
        }
        let is_desktop = self.spec.as_ref().map(|s| s.session.protocol.is_remote_desktop()).unwrap_or(false);
        let protocol = self.spec.as_ref().map(|s| s.session.protocol.as_str().to_string()).unwrap_or_else(|| {
            redacted.get("protocol").and_then(|v| v.as_str()).unwrap_or("").to_string()
        });
        json!({
            "id": self.id,
            "name": self.name,
            "connected": self.connected,
            "is_local": self.is_local,
            "is_desktop": is_desktop,
            "protocol": protocol,
            "session": redacted,
            "remote_dir": if self.is_local { &self.other_local_dir } else { &self.remote_dir },
            "local_dir": self.local_dir,
            "other_local_dir": self.other_local_dir,
            "site": self.site_name,
            "observed_hostkey": self.observed_hostkey,
            "error": self.error,
        })
    }
}

pub fn parse_tab_id_value(val: Option<&Value>) -> Option<u64> {
    match val? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => parse_tab_id_str(Some(s.as_str())),
        _ => None,
    }
}

pub fn parse_tab_id_str(raw: Option<&str>) -> Option<u64> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() {
        return None;
    }
    let digits = trimmed.strip_prefix("tab-").unwrap_or(trimmed);
    digits.parse::<u64>().ok()
}

pub fn session_is_local(session: &Value) -> bool {
    let proto = session
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    proto == "local"
        || proto == "file"
        || session
            .get("is_local")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

pub fn load_or_create_master_key(
    config_root: &Path,
    vault: &dyn SecretVault,
) -> Result<SessionMasterKey, String> {
    let bytes = vault
        .load_or_create_master_key(config_root)
        .map_err(|e| e.to_string())?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&*bytes);
    Ok(SessionMasterKey::from_array(arr))
}

pub fn load_existing_master_key(
    config_root: &Path,
    vault: &dyn SecretVault,
) -> Option<SessionMasterKey> {
    let bytes = vault.load_master_key(config_root).ok().flatten()?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&*bytes);
    Some(SessionMasterKey::from_array(arr))
}

pub fn stored_site_to_gui_json(site: &StoredSite) -> Value {
    let proto = site.protocol.as_str();
    let has_password = site.password.as_ref().is_some_and(|p| !p.is_empty())
        || site.password_raw.as_ref().is_some_and(|p| !p.is_empty());
    let has_key_passphrase = site.key_passphrase.as_ref().is_some_and(|p| !p.is_empty())
        || site.key_passphrase_raw.as_ref().is_some_and(|p| !p.is_empty());
    let mut obj = serde_json::Map::new();
    obj.insert("name".into(), json!(site.name));
    if let Some((folder, _)) = site.name.rsplit_once('/') {
        obj.insert("folder".into(), json!(folder));
    } else {
        obj.insert("folder".into(), json!(""));
    }
    obj.insert("protocol".into(), json!(proto));
    obj.insert("is_local".into(), json!(site.protocol == ProtocolScheme::Local));
    obj.insert("host".into(), json!(site.host));
    obj.insert("port".into(), json!(site.port));
    obj.insert("username".into(), json!(site.username));
    obj.insert("user".into(), json!(site.username));
    obj.insert("has_password".into(), json!(has_password));
    obj.insert("sudo_password_auto".into(), json!(site.extra_fields.get("sudo_password_auto").is_some_and(|v| v == "1")));
    obj.insert("mosh".into(), json!(site.extra_fields.get("mosh").is_some_and(|v| v == "1")));
    obj.insert("mosh_port".into(), json!(site.extra_fields.get("mosh_port").cloned().unwrap_or_default()));
    obj.insert("auto_reconnect".into(), json!(crate::auto_reconnect::enabled(site)));
    obj.insert("auto_reconnect_seconds".into(), json!(crate::auto_reconnect::interval(site)));
    obj.insert("alt_hostname".into(), json!(site.extra_fields.get("alt_hostname").cloned().unwrap_or_default()));
    obj.insert("alt_port".into(), json!(effective_site_alt_port(site)));
    obj.insert("alt_fallback".into(), json!(site.extra_fields.get("alt_fallback").is_some_and(|v| v == "1")));
    obj.insert("has_key_passphrase".into(), json!(has_key_passphrase));
    obj.insert("has_unreadable_secret".into(), json!(site.summary().has_unreadable_secret));
    obj.insert(
        "keyfile".into(),
        json!(site.private_key.clone().unwrap_or_default()),
    );
    obj.insert(
        "private_key".into(),
        json!(site.private_key.clone().unwrap_or_default()),
    );
    obj.insert(
        "hostkey".into(),
        json!(site.hostkey.clone().unwrap_or_default()),
    );
    obj.insert("remote_dir".into(), json!(site.remote_directory));
    obj.insert("initial_dir".into(), json!(site.remote_directory));
    obj.insert("local_dir".into(), json!(site.local_directory));
    obj.insert(
        "other_local_dir".into(),
        json!(site.extra_fields.get("other_local_dir").cloned().unwrap_or_default()),
    );
    obj.insert("preset".into(), json!(site.preset));
    obj.insert("proxy_method".into(), json!(site.proxy_method));
    obj.insert("proxy_host".into(), json!(site.proxy_host));
    obj.insert("proxy_port".into(), json!(site.proxy_port));
    obj.insert("proxy_username".into(), json!(site.proxy_username));
    obj.insert("has_proxy_password".into(), json!(site.proxy_password.as_ref().is_some_and(|p| !p.is_empty()) || site.proxy_password_raw.as_ref().is_some_and(|p| !p.is_empty())));
    obj.insert("proxy_command".into(), json!(site.proxy_command));
    obj.insert("proxy_dns".into(), json!(site.proxy_dns));
    obj.insert("proxy_localhost".into(), json!(site.proxy_localhost));
    obj.insert("proxy_exclude".into(), json!(site.proxy_exclude));
    obj.insert("tunnel".into(), json!(site.tunnel.enabled));
    obj.insert("tunnel_enabled".into(), json!(site.tunnel.enabled));
    obj.insert("tunnel_host".into(), json!(site.tunnel.host));
    obj.insert("tunnel_port".into(), json!(site.tunnel.port));
    obj.insert("tunnel_user".into(), json!(site.tunnel.username));
    obj.insert("tunnel_username".into(), json!(site.tunnel.username));
    obj.insert("tunnel_keyfile".into(), json!(site.tunnel.keyfile));
    obj.insert("tunnel_private_key".into(), json!(site.tunnel.keyfile));
    obj.insert("tunnel_local_port".into(), json!(site.tunnel.local_port));
    obj.insert("tunnel_error".into(), json!(site.tunnel_error.clone().unwrap_or_default()));
    obj.insert(
        "has_tunnel_password".into(),
        json!(site.tunnel.password.as_ref().is_some_and(|p| !p.is_empty())
            || site.tunnel_password_raw.as_ref().is_some_and(|p| !p.is_empty())),
    );
    obj.insert(
        "has_tunnel_passphrase".into(),
        json!(site.tunnel_passphrase.as_ref().is_some_and(|p| !p.is_empty())
            || site.tunnel_passphrase_raw.as_ref().is_some_and(|p| !p.is_empty())),
    );
    obj.insert(
        "tunnel_hostkey".into(),
        json!(site.tunnel.hostkey.clone()),
    );
    obj.insert(
        "has_s3_session_token".into(),
        json!(site.extra_fields.get("s3_session_token").is_some_and(|t| !t.is_empty())),
    );
    for (k, v) in &site.extra_fields {
        if matches!(k.as_str(), "s3_secret_key" | "s3_session_token" | "proxy_password" | "passphrase" | "key_passphrase" | "tunnel_passphrase") { continue; }
        obj.entry(k.clone()).or_insert_with(|| json!(v));
    }
    if let Some(alg) = site.extra_fields.get("s3_sse_algorithm") {
        obj.entry("s3_sse").or_insert_with(|| json!(alg));
    }
    if let Some(kms) = site.extra_fields.get("s3_sse_kms_key_id") {
        obj.entry("s3_kms_key").or_insert_with(|| json!(kms));
    }
    Value::Object(obj)
}

fn str_field(obj: &Value, keys: &[&str]) -> String {
    for k in keys {
        if let Some(s) = obj.get(*k).and_then(Value::as_str) {
            return s.to_string();
        }
    }
    String::new()
}

fn u16_field(obj: &Value, keys: &[&str], default: u16) -> Result<u16, String> {
    for k in keys {
        if let Some(val) = obj.get(*k) {
            match val {
                Value::Null => continue,
                Value::Number(n) => {
                    let Some(u) = n.as_u64() else {
                        return Err(format!("Invalid numeric port in '{k}'."));
                    };
                    if u > 65535 {
                        return Err(format!("Port {u} is out of range (1..65535)."));
                    }
                    return Ok(u as u16);
                }
                Value::String(s) => {
                    let t = s.trim();
                    if t.is_empty() {
                        continue;
                    }
                    let u: u64 = t
                        .parse()
                        .map_err(|_| format!("Port '{t}' must be an integer."))?;
                    if u > 65535 {
                        return Err(format!("Port {u} is out of range (1..65535)."));
                    }
                    return Ok(u as u16);
                }
                _ => return Err(format!("Field '{k}' must be a port number.")),
            }
        }
    }
    Ok(default)
}

fn parse_s3_byte_size_field(raw: &str, label: &str) -> Result<u64, String> {
    let t = raw.trim();
    let digits = t.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return Err(format!("Invalid {label} '{raw}'."));
    }
    let base: u64 = t[..digits]
        .parse()
        .map_err(|_| format!("{label} '{raw}' is out of range."))?;
    let suffix = t[digits..].trim().to_ascii_uppercase();
    let shift = match suffix.as_str() {
        "" | "B" => 0u32,
        "K" | "KB" | "KIB" => 10u32,
        "M" | "MB" | "MIB" => 20u32,
        "G" | "GB" | "GIB" => 30u32,
        _ => return Err(format!("Invalid unit suffix in {label} '{raw}'.")),
    };
    base.checked_shl(shift)
        .ok_or_else(|| format!("{label} '{raw}' overflows byte size."))
}

/// Parses a GUI session JSON object (optionally inheriting stored credentials
/// from `site_name` when `password` is omitted) into a validated `ParsedSiteSpec`.
pub fn parse_gui_session_spec(
    session: &Value,
    site_name: Option<&str>,
    config_root: &Path,
    vault: &dyn SecretVault,
) -> Result<(ParsedSiteSpec, Value), String> {
    if !session.is_object() {
        return Err("The session must be a JSON object.".to_string());
    }

    let stored_base = if let Some(sname) = site_name.map(str::trim).filter(|s| !s.is_empty()) {
        let store = SessionStore::load_from_dir(config_root, vault)?;
        Some(store.find(sname).cloned().ok_or_else(|| format!("Saved site {sname:?} no longer exists."))?)
    } else {
        None
    };

    let proto_str = {
        let s = str_field(session, &["protocol", "scheme"]);
        if !s.trim().is_empty() {
            s.trim().to_ascii_lowercase()
        } else if let Some(ref b) = stored_base {
            b.protocol.as_str().to_string()
        } else {
            "sftp".to_string()
        }
    };

    let protocol = ProtocolScheme::parse(&proto_str)
        .ok_or_else(|| format!("Unsupported protocol '{proto_str}'."))?;

    let host = {
        let h = str_field(session, &["host", "hostname"]);
        if !h.trim().is_empty() {
            h.trim().to_string()
        } else if let Some(ref b) = stored_base {
            b.host.clone()
        } else {
            String::new()
        }
    };
    if protocol != ProtocolScheme::Local && host.is_empty() {
        return Err("A host name is required.".to_string());
    }
    if host.chars().any(char::is_control) {
        return Err("Host name contains invalid control characters.".to_string());
    }

    let default_port = stored_base
        .as_ref()
        .map(|b| b.port)
        .filter(|p| *p > 0)
        .unwrap_or_else(|| protocol.default_port());
    let port = {
        let p = u16_field(session, &["port"], default_port)?;
        if p == 0 {
            protocol.default_port()
        } else {
            p
        }
    };

    let stored_alt_port = stored_base.as_ref().and_then(site_alt_port);
    let default_alt_port = stored_alt_port.unwrap_or(port);
    let explicit_zero_alt_port = matches!(session.get("alt_port"), Some(Value::Number(n)) if n.as_u64() == Some(0))
        || matches!(session.get("alt_port"), Some(Value::String(text)) if text.trim() == "0");
    if protocol != ProtocolScheme::Local && explicit_zero_alt_port {
        return Err("Alt Port 0 is out of range (1..65535).".to_string());
    }
    let alt_port = {
        let p = u16_field(session, &["alt_port"], default_alt_port)?;
        if p == 0 { port } else { p }
    };

    let username = {
        let u = str_field(session, &["username", "user"]);
        if !u.is_empty() {
            u
        } else if let Some(ref b) = stored_base {
            b.username.clone()
        } else if matches!(
            protocol,
            ProtocolScheme::Sftp | ProtocolScheme::Scp | ProtocolScheme::Ssh
        ) {
            default_os_username()
        } else {
            String::new()
        }
    };

    let password = match session.get("password").and_then(Value::as_str) {
        Some(pw) if !pw.is_empty() => Some(pw.to_string()),
        Some(_) => {
            if session
                .get("clear_password")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                None
            } else {
                stored_base.as_ref().and_then(|b| b.password.clone())
            }
        }
        None => stored_base.as_ref().and_then(|b| b.password.clone()),
    };

    let keyfile = {
        let k = str_field(session, &["keyfile", "private_key", "privatekey"]);
        if !k.trim().is_empty() {
            Some(k.trim().to_string())
        } else if session.get("keyfile").is_some() || session.get("private_key").is_some() {
            None
        } else {
            stored_base.as_ref().and_then(|b| b.private_key.clone())
        }
    };

    let hostkey = {
        let hk = str_field(session, &["hostkey"]);
        if !hk.trim().is_empty() {
            Some(hk.trim().to_string())
        } else if session.get("hostkey").is_some() {
            None
        } else {
            stored_base.as_ref().and_then(|b| b.hostkey.clone())
        }
    };

    let initial_dir = {
        let r = str_field(session, &["remote_dir", "initial_dir", "remote_directory"]);
        if !r.is_empty() {
            r
        } else if let Some(ref b) = stored_base {
            b.remote_directory.clone()
        } else {
            String::new()
        }
    };

    let local_dir = {
        let l = str_field(session, &["local_dir", "local_directory"]);
        if !l.is_empty() {
            l
        } else if let Some(ref b) = stored_base {
            b.local_directory.clone()
        } else {
            String::new()
        }
    };

    // Tunnel fields (nested `tunnel` object OR flat `tunnel_*` keys)
    let nested_tun = session.get("tunnel");
    let tunnel_enabled = session
        .get("tunnel_enabled")
        .and_then(Value::as_bool)
        .or_else(|| {
            nested_tun
                .and_then(|t| t.get("enabled"))
                .and_then(Value::as_bool)
        })
        .unwrap_or_else(|| {
            let th = str_field(session, &["tunnel_host"]);
            if !th.trim().is_empty() {
                true
            } else {
                stored_base
                    .as_ref()
                    .map(|b| b.tunnel.enabled)
                    .unwrap_or(false)
            }
        });

    let tunnel_host = {
        let th = str_field(session, &["tunnel_host"]);
        if !th.is_empty() {
            th
        } else if let Some(nt) = nested_tun {
            str_field(nt, &["host"])
        } else if let Some(ref b) = stored_base {
            b.tunnel.host.clone()
        } else {
            String::new()
        }
    };
    let tunnel_port = u16_field(
        session,
        &["tunnel_port"],
        nested_tun
            .and_then(|nt| u16_field(nt, &["port"], 22).ok())
            .or_else(|| stored_base.as_ref().map(|b| b.tunnel.port))
            .filter(|p| *p > 0)
            .unwrap_or(22),
    )?;
    let tunnel_user = {
        let tu = str_field(session, &["tunnel_user", "tunnel_username"]);
        if !tu.is_empty() {
            tu
        } else if let Some(nt) = nested_tun {
            str_field(nt, &["user", "username"])
        } else if let Some(ref b) = stored_base {
            b.tunnel.username.clone()
        } else {
            String::new()
        }
    };
    let tunnel_password = session
        .get("tunnel_password")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| {
            nested_tun
                .and_then(|nt| nt.get("password"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .or_else(|| {
            stored_base
                .as_ref()
                .and_then(|b| b.tunnel.password.clone())
        });
    let tunnel_keyfile = {
        let tk = str_field(session, &["tunnel_keyfile", "tunnel_private_key"]);
        if !tk.is_empty() {
            Some(tk)
        } else if let Some(nt) = nested_tun {
            let k = str_field(nt, &["keyfile"]);
            (!k.is_empty()).then_some(k)
        } else {
            stored_base
                .as_ref()
                .and_then(|b| b.tunnel.keyfile.clone())
        }
    };
    let tunnel_local_port = u16_field(
        session,
        &["tunnel_local_port"],
        nested_tun
            .and_then(|nt| u16_field(nt, &["local_port"], 0).ok())
            .or_else(|| stored_base.as_ref().map(|b| b.tunnel.local_port))
            .unwrap_or(0),
    )?;
    let tunnel_hostkey = {
        let thk = str_field(session, &["tunnel_hostkey"]);
        if !thk.is_empty() {
            Some(thk)
        } else if let Some(nt) = nested_tun {
            let k = str_field(nt, &["hostkey"]);
            (!k.is_empty()).then_some(k)
        } else {
            stored_base
                .as_ref()
                .map(|b| b.tunnel.hostkey.clone())
        }
    };

    let tunnel = TunnelConfig {
        enabled: tunnel_enabled,
        host: tunnel_host,
        port: tunnel_port,
        username: tunnel_user,
        password: tunnel_password,
        keyfile: tunnel_keyfile,
        hostkey: tunnel_hostkey.unwrap_or_default(),
        local_port: tunnel_local_port,
    };

    let mut spec = if let Some(ref b) = stored_base {
        site_spec_from_stored(b)?
    } else {
        ParsedSiteSpec::default()
    };
    // A typed tunnel key passphrase wins over the stored one; an empty field
    // falls back to it (same rule as the passwords). It only applies to an
    // enabled tunnel - a typed passphrase for a disabled tunnel is dropped,
    // exactly like the tunnel password.
    if tunnel_enabled {
        if let Some(tp) = session
            .get("tunnel_passphrase")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            spec.raw_fields.insert("tunnel_passphrase".to_string(), tp.to_string());
        }
    }

    spec.session = SessionConfig {
        name: str_field(session, &["name"]),
        protocol,
        host: host.clone(),
        port,
        username: username.clone(),
        password,
        keyfile: keyfile.clone(),
        hostkey: hostkey.clone().unwrap_or_default(),
        initial_dir: initial_dir.clone(),
        local_dir: local_dir.clone(),
        tunnel: tunnel.enabled.then(|| tunnel.clone()),
    };
    spec.session.keyfile = keyfile.clone();
    spec.passphrase = match session
        .get("key_passphrase")
        .or_else(|| session.get("passphrase"))
        .and_then(Value::as_str)
    {
        Some(pp) if !pp.is_empty() => Some(pp.to_string()),
        Some(_) => {
            if session
                .get("clear_key_passphrase")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                None
            } else {
                stored_base.as_ref().and_then(|b| b.key_passphrase.clone())
            }
        }
        None => stored_base.as_ref().and_then(|b| b.key_passphrase.clone()),
    };
    if let Some(preset) = session.get("preset").and_then(Value::as_str) {
        if preset.chars().any(char::is_control) {
            return Err("Preset name contains invalid control characters.".to_string());
        }
        spec.preset_name = preset.trim().to_string();
    } else if let Some(ref base) = stored_base {
        spec.preset_name = base.preset.clone();
    }

    // Extra protocol fields (`s3_*`, `ftp_*`, `tls_*`, `proxy_*`, Kerberos)
    let extra_keys = [
        "other_local_dir",
        "color",
        "note",
        "sudo_password_auto",
        "mosh",
        "mosh_port",
        "alt_hostname",
        "alt_fallback",
        "s3_access_key",
        "s3_secret_key",
        "s3_session_token",
        "s3_region",
        "s3_protocol",
        "s3_url_style",
        "s3_default_region",
        "s3_sse",
        "s3_sse_algorithm",
        "s3_kms_key",
        "s3_sse_kms_key_id",
        "s3_acl",
        "s3_storage_class",
        "s3_metadata",
        "s3_request_payer",
        "s3_multipart_threshold",
        "s3_min_part_size",
        "ftp_pasv_mode",
        "ftp_account",
        "ftp_use_mlsd",
        "ftp_force_pasv_ip",
        "ftps",
        "tls_min_version",
        "tls_max_version",
        "tls_ca_file",
        "tls_cert_file",
        "tls_key_file",
        "tls_verify",
        "min_tls_version",
        "max_tls_version",
        "tls_certificate_file",
        "tls_certificate_key_file",
        "ca_certificate_file",
        "ca_certificate_dir",
        "pinned_public_key",
        "pinned_pubkey",
        "certificate",
        "proxy_method",
        "proxy_host",
        "proxy_port",
        "proxy_username",
        "proxy_password",
        "proxy_command",
        "proxy_exclude",
        "proxy_dns",
        "proxy_localhost",
        "auth_gssapi",
        "auth_gssapi_kex",
        "gssapi_fwd_tgt",
        "logical_host",
        "rdp_domain",
        "rdp_security",
        "rdp_color_depth",
        "rdp_width",
        "rdp_height",
        "rdp_fullscreen",
        "rdp_drive_redirection",
        "rdp_audio_mode",
        "rdp_compression",
        "vnc_view_only",
        "vnc_quality",
        "spice_tls_port",
        "x2go_session_type",
        "x2go_command",
        "x2go_link",
        "x2go_pack",
        "x11_display",
        "waypipe",
    ];
    for k in extra_keys {
        if let Some(v) = session.get(k) {
            match v {
                Value::String(s) => {
                    spec.raw_fields.insert(k.to_string(), s.clone());
                }
                Value::Bool(b) => {
                    spec.raw_fields
                        .insert(k.to_string(), if *b { "1" } else { "0" }.to_string());
                }
                Value::Number(n) => {
                    spec.raw_fields.insert(k.to_string(), n.to_string());
                }
                _ => {}
            }
        }
    }
    if protocol != ProtocolScheme::Local {
        spec.raw_fields.remove("other_local_dir");
    } else if let Some(other_dir) = spec.raw_fields.get("other_local_dir").cloned() {
        let trimmed = other_dir.trim();
        if trimmed.chars().any(char::is_control) {
            return Err("The other_local_dir must not contain control characters.".to_string());
        }
        if trimmed.is_empty() {
            spec.raw_fields.remove("other_local_dir");
        } else {
            spec.raw_fields.insert("other_local_dir".to_string(), trimmed.to_string());
        }
    }
    if session.get("alt_hostname").is_some_and(|v| !v.is_string()) ||
        session.get("alt_fallback").is_some_and(|v| !v.is_boolean()) {
        return Err("Invalid alternate hostname settings.".to_string());
    }
    if protocol != ProtocolScheme::Local && (session.get("alt_port").is_some() || stored_alt_port.is_some()) {
        spec.raw_fields.insert("alt_port".to_string(), alt_port.to_string());
    }
    if let Some(host) = spec.raw_fields.get("alt_hostname") {
        if !host.is_empty() && !valid_alternate_hostname(host) {
            return Err("Enter a valid alternate hostname without a port or URL.".to_string());
        }
    }
    if protocol != ProtocolScheme::Local && spec.raw_fields.get("alt_fallback").is_some_and(|v| v == "1") &&
        spec.raw_fields.get("alt_hostname").is_none_or(|v| v.is_empty()) {
        return Err("An alternate hostname is required when fallback is enabled.".to_string());
    }
    // Empty password inputs do not disclose saved secrets to the GUI.
    if session.get("proxy_password").and_then(Value::as_str) == Some("")
        && stored_base.is_some() && !session.get("clear_proxy_password").and_then(Value::as_bool).unwrap_or(false) {
        if let Some(password) = stored_base.as_ref().and_then(|site| site.proxy_password.as_ref()) {
            spec.raw_fields.insert("proxy_password".into(), password.clone());
        }
    }
    // The site form uses descriptive values, whereas the engine stores the
    // legacy-compatible numeric mode. Never let an unknown value silently
    // downgrade an FTP connection to plaintext.
    if let Some(mode) = session.get("ftps").and_then(Value::as_str) {
        match mode.trim().to_ascii_lowercase().as_str() {
            "" => { spec.raw_fields.remove("ftps"); }
            "implicit" | "1" => { spec.raw_fields.insert("ftps".into(), "1".into()); }
            "explicit" | "3" => { spec.raw_fields.insert("ftps".into(), "3".into()); }
            "0" | "2" => { spec.raw_fields.insert("ftps".into(), mode.trim().into()); }
            _ => return Err(format!("Invalid FTPS mode '{mode}'.")),
        }
    }
    if let Some(pin) = spec.raw_fields.remove("pinned_pubkey") {
        spec.raw_fields.insert("pinned_public_key".into(), pin);
    }
    for key in ["min_tls_version", "max_tls_version"] {
        if spec.raw_fields.get(key).is_some_and(|value| value.trim().is_empty()) {
            spec.raw_fields.remove(key);
        }
    }
    if protocol == ProtocolScheme::S3 {
        if let Some(access) = spec.raw_fields.remove("s3_access_key") {
            if spec.session.username.is_empty() { spec.session.username = access; }
        }
        if let Some(secret) = spec.raw_fields.remove("s3_secret_key") {
            if spec.session.password.is_none() && !secret.is_empty() { spec.session.password = Some(secret); }
        }
    }
    for (gui, engine) in [
        ("s3_sse", "s3_sse_algorithm"),
        ("s3_kms_key", "s3_sse_kms_key_id"),
    ] {
        if let Some(value) = spec.raw_fields.remove(gui) {
            spec.raw_fields
                .entry(engine.to_string())
                .or_insert(value);
        }
    }
    for s3_opt in [
        "s3_storage_class",
        "s3_acl",
        "s3_sse_algorithm",
        "s3_sse_kms_key_id",
        "s3_metadata",
    ] {
        if let Some(val) = spec.raw_fields.get(s3_opt).cloned() {
            let trimmed = val.trim();
            if trimmed.chars().any(char::is_control) {
                return Err(format!("S3 option '{s3_opt}' contains invalid control characters."));
            }
            if trimmed.is_empty() {
                spec.raw_fields.remove(s3_opt);
            } else {
                spec.raw_fields.insert(s3_opt.to_string(), trimmed.to_string());
            }
        }
    }
    if let Some(proto_val) = spec.raw_fields.get("s3_protocol").cloned() {
        let trimmed = proto_val.trim();
        if trimmed.is_empty() {
            spec.raw_fields.remove("s3_protocol");
        } else {
            let normalized = match trimmed.to_ascii_lowercase().as_str() {
                "1" | "https" => "1",
                "0" | "http" => "0",
                _ => {
                    return Err(format!(
                        "Invalid S3 protocol '{trimmed}' (expected https/1 or http/0)."
                    ));
                }
            };
            spec.raw_fields
                .insert("s3_protocol".to_string(), normalized.to_string());
            let has_explicit_port = session.get("port").is_some_and(|v| match v {
                Value::Number(n) => n.as_u64().unwrap_or(0) > 0,
                Value::String(s) => !s.trim().is_empty() && s.trim() != "0",
                _ => false,
            }) || stored_base.as_ref().is_some_and(|b| b.port > 0);
            if protocol == ProtocolScheme::S3 && !has_explicit_port {
                spec.session.port = if normalized == "1" { 443 } else { 80 };
            }
        }
    }
    if let Some(payer_val) = spec.raw_fields.get("s3_request_payer").cloned() {
        let trimmed = payer_val.trim();
        if trimmed.is_empty() {
            spec.raw_fields.remove("s3_request_payer");
        } else {
            let enabled = match trimmed.to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" | "requester" => true,
                "0" | "false" | "no" | "off" => false,
                _ => {
                    return Err(format!(
                        "Invalid S3 request payer setting '{trimmed}'."
                    ));
                }
            };
            if enabled {
                spec.raw_fields
                    .insert("s3_request_payer".to_string(), "1".to_string());
            } else {
                spec.raw_fields.remove("s3_request_payer");
            }
        }
    }
    if let Some(raw_thresh) = spec.raw_fields.get("s3_multipart_threshold").cloned() {
        let trimmed = raw_thresh.trim();
        if trimmed.is_empty() || trimmed == "0" {
            spec.raw_fields.remove("s3_multipart_threshold");
        } else {
            let bytes = parse_s3_byte_size_field(trimmed, "S3 multipart threshold")?;
            if bytes == 0 {
                spec.raw_fields.remove("s3_multipart_threshold");
            } else {
                spec.raw_fields
                    .insert("s3_multipart_threshold".to_string(), bytes.to_string());
            }
        }
    }
    if let Some(raw_part) = spec.raw_fields.get("s3_min_part_size").cloned() {
        let trimmed = raw_part.trim();
        if trimmed.is_empty() || trimmed == "0" {
            spec.raw_fields.remove("s3_min_part_size");
        } else {
            let bytes = parse_s3_byte_size_field(trimmed, "S3 minimum part size")?;
            if bytes < 5 * 1024 * 1024 {
                return Err(
                    "S3 minimum part size must be at least 5 MiB (5242880 bytes or 5M)."
                        .to_string(),
                );
            }
            spec.raw_fields
                .insert("s3_min_part_size".to_string(), bytes.to_string());
        }
    }
    if let Some(mlsd_val) = spec.raw_fields.get("ftp_use_mlsd").cloned() {
        let trimmed = mlsd_val.trim();
        if trimmed.is_empty() {
            spec.raw_fields.remove("ftp_use_mlsd");
        } else {
            let normalized = match trimmed.to_ascii_lowercase().as_str() {
                "0" | "false" | "off" => "0",
                "1" | "true" | "auto" => "1",
                "2" | "on" | "require" => "2",
                _ => {
                    return Err(format!(
                        "Invalid FTP MLSD setting '{trimmed}' (expected 0, 1, or 2)."
                    ));
                }
            };
            spec.raw_fields
                .insert("ftp_use_mlsd".to_string(), normalized.to_string());
        }
    }
    if let Some(pasv_ip_val) = spec.raw_fields.get("ftp_force_pasv_ip").cloned() {
        let trimmed = pasv_ip_val.trim();
        if trimmed.is_empty() {
            spec.raw_fields.remove("ftp_force_pasv_ip");
        } else {
            let normalized = match trimmed.to_ascii_lowercase().as_str() {
                "0" | "auto" => "0",
                "1" | "true" | "on" => "1",
                "2" | "false" | "off" => "2",
                _ => {
                    return Err(format!(
                        "Invalid FTP PASV IP substitution setting '{trimmed}' (expected 0, 1, or 2)."
                    ));
                }
            };
            spec.raw_fields
                .insert("ftp_force_pasv_ip".to_string(), normalized.to_string());
        }
    }
    if let Some(acct_val) = spec.raw_fields.get("ftp_account").cloned() {
        let trimmed = acct_val.trim();
        if trimmed.chars().any(char::is_control) {
            return Err("FTP account must not contain control characters.".to_string());
        }
        if trimmed.is_empty() {
            spec.raw_fields.remove("ftp_account");
        } else {
            spec.raw_fields
                .insert("ftp_account".to_string(), trimmed.to_string());
        }
    }
    if let Some(color_val) = spec.raw_fields.get("color").cloned() {
        let trimmed = color_val.trim();
        if trimmed.is_empty() {
            spec.raw_fields.remove("color");
        } else if trimmed.len() == 7
            && trimmed.starts_with('#')
            && trimmed[1..].chars().all(|c| c.is_ascii_hexdigit())
        {
            spec.raw_fields
                .insert("color".to_string(), trimmed.to_ascii_lowercase());
        } else {
            return Err("Session color must be empty or a 6-digit hex color (#rrggbb).".to_string());
        }
    }
    if let Some(note_val) = spec.raw_fields.get("note").cloned() {
        let trimmed = note_val.trim();
        if trimmed.chars().any(char::is_control) {
            return Err("Session note must not contain control characters.".to_string());
        }
        if trimmed.is_empty() {
            spec.raw_fields.remove("note");
        } else {
            spec.raw_fields.insert("note".to_string(), trimmed.to_string());
        }
    }
    for desktop_opt in [
        "rdp_domain",
        "rdp_security",
        "x2go_session_type",
        "x2go_command",
        "x2go_link",
        "x2go_pack",
        "x11_display",
    ] {
        if let Some(val) = spec.raw_fields.get(desktop_opt).cloned() {
            let trimmed = val.trim();
            if trimmed.chars().any(char::is_control) {
                return Err(format!("Desktop option '{desktop_opt}' contains invalid control characters."));
            }
            if trimmed.is_empty() {
                spec.raw_fields.remove(desktop_opt);
            } else {
                spec.raw_fields.insert(desktop_opt.to_string(), trimmed.to_string());
            }
        }
    }
    if let Some(depth) = spec.raw_fields.get("rdp_color_depth").cloned() {
        let trimmed = depth.trim();
        if trimmed.is_empty() {
            spec.raw_fields.remove("rdp_color_depth");
        } else if matches!(trimmed, "8" | "15" | "16" | "24" | "32") {
            spec.raw_fields.insert("rdp_color_depth".to_string(), trimmed.to_string());
        } else {
            return Err("RDP color depth must be 8, 15, 16, 24, or 32.".to_string());
        }
    }
    for dim_key in ["rdp_width", "rdp_height"] {
        if let Some(raw_dim) = spec.raw_fields.get(dim_key).cloned() {
            let trimmed = raw_dim.trim();
            if trimmed.is_empty() || trimmed == "0" {
                spec.raw_fields.remove(dim_key);
            } else if let Ok(px) = trimmed.parse::<u32>() {
                if (1..=16384).contains(&px) {
                    spec.raw_fields.insert(dim_key.to_string(), px.to_string());
                } else {
                    return Err(format!("Desktop dimension '{dim_key}' must be between 1 and 16384."));
                }
            } else {
                return Err(format!("Desktop dimension '{dim_key}' must be an integer."));
            }
        }
    }
    if let Some(raw_q) = spec.raw_fields.get("vnc_quality").cloned() {
        let trimmed = raw_q.trim();
        if trimmed.is_empty() {
            spec.raw_fields.remove("vnc_quality");
        } else if let Ok(q) = trimmed.parse::<u8>() {
            if q <= 9 {
                spec.raw_fields.insert("vnc_quality".to_string(), q.to_string());
            } else {
                return Err("VNC quality must be between 0 and 9.".to_string());
            }
        } else {
            return Err("VNC quality must be an integer between 0 and 9.".to_string());
        }
    }
    if let Some(raw_spice_tls) = spec.raw_fields.get("spice_tls_port").cloned() {
        let trimmed = raw_spice_tls.trim();
        if trimmed.is_empty() || trimmed == "0" {
            spec.raw_fields.remove("spice_tls_port");
        } else if let Ok(p) = trimmed.parse::<u16>() {
            if p > 0 {
                spec.raw_fields.insert("spice_tls_port".to_string(), p.to_string());
            } else {
                return Err("SPICE TLS port must be between 1 and 65535.".to_string());
            }
        } else {
            return Err("SPICE TLS port must be between 1 and 65535.".to_string());
        }
    }

    // Translate GUI TLS option names to the names consumed by the engine.
    for (gui, engine) in [
        ("tls_ca_file", "ca_certificate_file"),
        ("tls_cert_file", "tls_certificate_file"),
        ("tls_key_file", "tls_certificate_key_file"),
        ("tls_min_version", "min_tls_version"),
        ("tls_max_version", "max_tls_version"),
    ] {
        if let Some(value) = spec.raw_fields.remove(gui) {
            if !value.trim().is_empty() || !spec.raw_fields.contains_key(engine) {
                spec.raw_fields.insert(engine.to_string(), value);
            }
        }
    }
    for tls_key in [
        "ca_certificate_file",
        "ca_certificate_dir",
        "tls_certificate_file",
        "tls_certificate_key_file",
        "min_tls_version",
        "max_tls_version",
        "pinned_public_key",
    ] {
        if let Some(val) = spec.raw_fields.get(tls_key).cloned() {
            let trimmed = val.trim();
            if trimmed.chars().any(char::is_control) {
                return Err(format!(
                    "TLS option '{tls_key}' contains invalid control characters."
                ));
            }
            if trimmed.is_empty() {
                spec.raw_fields.remove(tls_key);
            } else {
                spec.raw_fields.insert(tls_key.to_string(), trimmed.to_string());
            }
        }
    }
    if let Some(value) = spec.raw_fields.remove("tls_verify") {
        if !matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "") {
            return Err("Disabling TLS certificate verification is not supported.".to_string());
        }
    }
    // proxy fields remain in raw_fields; no direct spec fields to set

    if let Some(mosh_port) = spec.raw_fields.get("mosh_port").cloned() {
        let trimmed = mosh_port.trim();
        if trimmed.is_empty() {
            spec.raw_fields.remove("mosh_port");
        } else {
            let parsed = linscp_proto::mosh::MoshPortSpec::parse_optional(trimmed)?;
            if let Some(p) = parsed {
                spec.raw_fields.insert("mosh_port".into(), p.as_cli_arg());
            }
        }
    }
    if let Some(mosh_val) = spec.raw_fields.get("mosh").cloned() {
        match mosh_val.trim().to_ascii_lowercase().as_str() {
            "" | "0" | "false" | "no" | "off" => {
                spec.raw_fields.insert("mosh".into(), "0".into());
            }
            "1" | "true" | "yes" | "on" => {
                spec.raw_fields.insert("mosh".into(), "1".into());
            }
            other => return Err(format!("Invalid Mosh setting '{other}'.")),
        }
    }

    apply_env_credential_fallbacks(&mut spec);
    if protocol != ProtocolScheme::Local {
        validate_session_settings(&spec)?;
        // The dialog's Kerberos section writes real settings now, so the same
        // fail-closed GSSAPI policy the connect paths run has to run here:
        // otherwise a Kerberos site parses on a build that can never open it.
        validate_ssh_gssapi_policy(&spec)?;
    }

    let mut clean_view = session.clone();
    if let Some(obj) = clean_view.as_object_mut() {
        obj.insert("protocol".into(), json!(protocol.as_str()));
        obj.insert("host".into(), json!(host));
        obj.insert("port".into(), json!(spec.session.port));
        obj.insert("alt_port".into(), json!(alt_port));
        obj.insert("username".into(), json!(spec.session.username));
        obj.insert("user".into(), json!(spec.session.username));
        obj.insert(
            "has_password".into(),
            json!(spec.session.password.as_ref().is_some_and(|p| !p.is_empty())),
        );
        obj.insert(
            "mosh".into(),
            json!(spec.raw_fields.get("mosh").is_some_and(|v| v == "1")),
        );
        obj.insert(
            "mosh_port".into(),
            json!(spec.raw_fields.get("mosh_port").cloned().unwrap_or_default()),
        );
        obj.insert("remote_dir".into(), json!(initial_dir));
        obj.insert("local_dir".into(), json!(local_dir));
        for key in ["s3_secret_key", "s3_session_token", "proxy_password", "passphrase", "key_passphrase", "clear_password", "clear_key_passphrase", "clear_proxy_password", "keep_password", "keep_key_passphrase", "keep_proxy_password", "keep_tunnel_password", "keep_tunnel_passphrase"] { obj.remove(key); }
        obj.remove("password");
        obj.remove("tunnel_password");
        obj.remove("tunnel_passphrase");
    }

    Ok((spec, clean_view))
}

/// An alternate is a hostname/IP only, never a URL, credential or port.
pub fn valid_alternate_hostname(host: &str) -> bool {
    !host.is_empty() && host == host.trim() && host != "*" && host.len() <= 253
        && !host.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '@' | '?' | '#' | '%'))
        && (!host.contains(':') || host.parse::<std::net::Ipv6Addr>().is_ok()
            || (host.starts_with('[') && host.ends_with(']') && host[1..host.len()-1].parse::<std::net::Ipv6Addr>().is_ok()))
}

pub fn site_alt_port(site: &StoredSite) -> Option<u16> {
    site.extra_fields
        .get("alt_port")
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
}

pub fn effective_site_alt_port(site: &StoredSite) -> u16 {
    site_alt_port(site).unwrap_or_else(|| {
        if site.port == 0 {
            site.protocol.default_port()
        } else {
            site.port
        }
    })
}

pub fn site_matches_host(site: &StoredSite, host: &str) -> bool {
    site.host == host || site.extra_fields.get("alt_hostname").is_some_and(|alt| alt == host && valid_alternate_hostname(alt))
}

pub fn site_matches_endpoint(site: &StoredSite, host: &str, port: u16) -> bool {
    let primary_port = if site.port == 0 {
        site.protocol.default_port()
    } else {
        site.port
    };
    let primary_match = site.host == host && primary_port == port;
    let alt_match = site
        .extra_fields
        .get("alt_hostname")
        .is_some_and(|alt| alt == host && valid_alternate_hostname(alt))
        && effective_site_alt_port(site) == port;
    primary_match || alt_match
}

pub fn alternate_endpoint(spec: &ParsedSiteSpec) -> Result<(String, u16), String> {
    let alt_host = spec.raw_fields.get("alt_hostname").cloned().unwrap_or_default();
    if !valid_alternate_hostname(&alt_host) {
        return Err("A valid alternate hostname is required.".to_string());
    }
    let fallback_port = if spec.session.port == 0 {
        spec.session.protocol.default_port()
    } else {
        spec.session.port
    };
    let alt_port = match spec.raw_fields.get("alt_port").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        Some(raw) => raw
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0)
            .ok_or_else(|| "Enter a valid alternate port from 1 to 65535.".to_string())?,
        None => fallback_port,
    };
    Ok((alt_host, alt_port))
}

/// The alternate gets its own port, SSH host-key cache entry and TLS hostname.
pub fn select_alternate(spec: &mut ParsedSiteSpec) -> Result<(), String> {
    let (alt_host, alt_port) = alternate_endpoint(spec)?;
    if alt_host != spec.session.host || alt_port != spec.session.port {
        spec.raw_fields
            .entry("linscp_primary_host".into())
            .or_insert_with(|| spec.session.host.clone());
        spec.raw_fields
            .entry("linscp_primary_port".into())
            .or_insert_with(|| spec.session.port.to_string());
        spec.raw_fields
            .entry("linscp_primary_hostkey".into())
            .or_insert_with(|| spec.session.hostkey.clone());
        spec.session.host = alt_host;
        spec.session.port = alt_port;
        spec.session.hostkey.clear();
    }
    Ok(())
}

/// Converts a `ParsedSiteSpec` into a `StoredSite` ready to write into `sessions.ini`.
pub fn build_stored_site_for_save(name: &str, spec: &ParsedSiteSpec) -> StoredSite {
    stored_site_from_spec(name, spec)
}

/// Parses a desktop URI (`sftp://user@host:2222/path`, `ftps://...`, `s3://...`, `davs://...`),
/// rejecting embedded passwords in desktop URIs with a clear security message when requested.
pub fn parse_desktop_uri(raw_url: &str, forbid_embedded_secrets: bool) -> Result<(ParsedSiteSpec, Value), String> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err("Empty session URL.".to_string());
    }
    if forbid_embedded_secrets {
        if let Some((scheme_split, rest)) = trimmed.split_once("://") {
            let authority = rest.split('/').next().unwrap_or(rest);
            if let Some((userinfo, _)) = authority.rsplit_once('@') {
                if userinfo.contains(':') || userinfo.contains(';') {
                    return Err(format!(
                        "Refusing {scheme_split}:// desktop URI with embedded credentials or options in authority."
                    ));
                }
            }
        }
    }
    let mut spec = parse_site_url(trimmed)?;
    if matches!(
        spec.session.protocol,
        ProtocolScheme::Sftp | ProtocolScheme::Scp | ProtocolScheme::Ssh
    ) && spec.session.username.is_empty()
    {
        spec.session.username = default_os_username();
    }
    let view = json!({
        "protocol": spec.session.protocol.as_str(),
        "host": spec.session.host,
        "port": if spec.session.port == 0 { spec.session.protocol.default_port() } else { spec.session.port },
        "username": spec.session.username,
        "user": spec.session.username,
        "has_password": spec.session.password.as_ref().is_some_and(|p| !p.is_empty()),
        "remote_dir": spec.session.initial_dir,
        "local_dir": spec.session.local_dir,
        "hostkey": spec.session.hostkey,
    });
    Ok((spec, view))
}

/// Formats a clean shareable session URL without passwords (`sftp://user@host:2222/dir`).
pub fn format_session_url(spec: &ParsedSiteSpec, remote_dir_override: Option<&str>) -> String {
    let proto = spec.session.protocol.as_str();
    let default_port = spec.session.protocol.default_port();
    let port = if spec.session.port == 0 {
        default_port
    } else {
        spec.session.port
    };
    let host_part = if spec.session.host.contains(':') && !spec.session.host.starts_with('[') {
        format!("[{}]", spec.session.host)
    } else {
        spec.session.host.clone()
    };
    let port_part = if port != default_port && port != 0 {
        format!(":{port}")
    } else {
        String::new()
    };
    let user_part = if !spec.session.username.is_empty() {
        format!("{}@", percent_encode_userinfo(&spec.session.username))
    } else {
        String::new()
    };
    let raw_dir = remote_dir_override
        .unwrap_or(&spec.session.initial_dir)
        .trim();
    let path_part = if raw_dir.is_empty() || raw_dir == "~" {
        "/".to_string()
    } else if raw_dir.starts_with('/') {
        raw_dir.to_string()
    } else {
        format!("/{raw_dir}")
    };
    format!("{proto}://{user_part}{host_part}{port_part}{path_part}")
}

pub(crate) fn percent_encode_userinfo(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub async fn dial_gui_tab_session(
    spec: &ParsedSiteSpec,
    config_root: &Path,
    cache_pinned_hostkeys: bool,
    locale: &str,
    log_sink: Option<linscp_proto::ssh::SshEventLogger>,
    vault: Arc<dyn SecretVault>,
) -> Result<(Arc<dyn RemoteSession>, String, String), GuiConnectError> {
    let session = connect_gui_site_spec(spec, config_root, cache_pinned_hostkeys, locale, log_sink.clone(), vault).await?;
    if let Some(log) = &log_sink { log("Connected; determining the initial remote directory."); }
    let resolved_dir = if spec.session.initial_dir.trim().is_empty()
        || spec.session.initial_dir.trim() == "~"
    {
        session.pwd().await.unwrap_or_else(|_| "/".to_string())
    } else {
        spec.session.initial_dir.clone()
    };
    let observed = session
        .observed_host_key()
        .unwrap_or_default()
        .to_string();
    let arc_session: Arc<dyn RemoteSession> = Arc::from(session);
    Ok((arc_session, resolved_dir, observed))
}

pub fn apply_challenge_to_tab(tab: &mut TabRuntime, ch: &GuiHostKeyChallenge) {
    tab.connected = false;
    tab.observed_hostkey = ch.display_fingerprint.clone();
    tab.hostkey_role = ch.role.clone();
    tab.hostkey_changed = ch.changed;
    tab.error = ch.error.clone();
}

pub fn collect_session_folders(sessions: &[Value]) -> Vec<String> {
    let mut folders = BTreeMap::<String, ()>::new();
    for s in sessions {
        if let Some(f) = s.get("folder").and_then(Value::as_str).filter(|f| !f.is_empty()) {
            let mut acc = String::new();
            for part in f.split('/') {
                if part.is_empty() {
                    continue;
                }
                if !acc.is_empty() {
                    acc.push('/');
                }
                acc.push_str(part);
                folders.insert(acc.clone(), ());
            }
        }
    }
    folders.into_keys().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alternate_host_settings_round_trip_and_never_reuse_primary_host_key() {
        let dir = tempfile::tempdir().unwrap();
        let vault = linscp_platform::NativeSecretVault::new();
        let (mut spec, _) = parse_gui_session_spec(&json!({
            "protocol": "sftp", "host": "primary.example", "port": 22, "username": "user",
            "hostkey": "ssh-ed25519 SHA256:primary", "alt_hostname": "backup.example", "alt_port": 2222, "alt_fallback": true,
            "auth_gssapi": false
        }), None, dir.path(), &vault).unwrap();
        let saved = build_stored_site_for_save("site", &spec);
        let view = stored_site_to_gui_json(&saved);
        assert_eq!(view["alt_hostname"], "backup.example");
        assert_eq!(view["alt_port"], 2222);
        assert_eq!(view["alt_fallback"], true);
        select_alternate(&mut spec).unwrap();
        assert_eq!(spec.session.host, "backup.example");
        assert_eq!(spec.session.port, 2222);
        assert!(spec.session.hostkey.is_empty());
        assert_eq!(spec.raw_fields["linscp_primary_port"], "22");
        assert_eq!(spec.raw_fields["linscp_primary_hostkey"], "ssh-ed25519 SHA256:primary");
        assert!(site_matches_host(&saved, &spec.session.host));
        assert!(site_matches_endpoint(&saved, "backup.example", 2222));
        assert!(!site_matches_endpoint(&saved, "backup.example", 22));
        assert!(site_matches_endpoint(&saved, "primary.example", 22));
        assert!(!site_matches_host(&saved, "other.example"));
        assert!(!valid_alternate_hostname("https://host/"));
        assert!(!valid_alternate_hostname("host:22"));
        assert!(!valid_alternate_hostname("user@host"));
        assert!(valid_alternate_hostname("[::1]"));
        assert!(parse_gui_session_spec(&json!({"host": "primary", "alt_fallback": true}), None, dir.path(), &vault).is_err());
        assert!(parse_gui_session_spec(&json!({"host": "primary", "alt_port": 0}), None, dir.path(), &vault).is_err());
        assert!(parse_gui_session_spec(&json!({"host": "primary", "alt_port": 70000}), None, dir.path(), &vault).is_err());
    }

    fn test_config_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "linscp-tabs-gssapi-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn gui_ftps_and_tls_fields_are_translated_and_fail_closed() {
        let dir = test_config_dir("tls-options");
        let vault = linscp_platform::NativeSecretVault::new();
        let session = json!({"protocol":"ftp", "host":"example.test", "ftps":"explicit",
            "min_tls_version":"1.2", "max_tls_version":"1.3", "tls_certificate_file":"client.pem",
            "ca_certificate_file":"ca.pem", "pinned_pubkey":"sha256//pin"});
        let (spec, _) = parse_gui_session_spec(&session, None, &dir, &vault).unwrap();
        for (key, expected) in [("ftps", "3"), ("min_tls_version", "1.2"), ("max_tls_version", "1.3"),
            ("tls_certificate_file", "client.pem"), ("ca_certificate_file", "ca.pem"), ("pinned_public_key", "sha256//pin")] {
            assert_eq!(spec.raw_fields.get(key).map(String::as_str), Some(expected));
        }
        let mut invalid = session.clone(); invalid["ftps"] = json!("unexpected");
        assert!(parse_gui_session_spec(&invalid, None, &dir, &vault).is_err());
        invalid["ftps"] = json!("implicit");
        assert_eq!(parse_gui_session_spec(&invalid, None, &dir, &vault).unwrap().0.raw_fields["ftps"], "1");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn gui_s3_ftp_and_tls_extended_fields_round_trip_and_validate() {
        let dir = test_config_dir("s3-ftp-tls-extended");
        let vault = linscp_platform::NativeSecretVault::new();
        let s3_session = json!({
            "protocol": "s3",
            "host": "s3.example.test",
            "username": "AKIAEXAMPLE",
            "s3_protocol": "http",
            "s3_request_payer": true,
            "s3_multipart_threshold": "32M",
            "s3_min_part_size": "8M",
        });
        let (s3_spec, _) = parse_gui_session_spec(&s3_session, None, &dir, &vault).unwrap();
        assert_eq!(s3_spec.raw_fields.get("s3_protocol").map(String::as_str), Some("0"));
        assert_eq!(s3_spec.session.port, 80);
        assert_eq!(s3_spec.raw_fields.get("s3_request_payer").map(String::as_str), Some("1"));
        assert_eq!(
            s3_spec.raw_fields.get("s3_multipart_threshold").map(String::as_str),
            Some("33554432")
        );
        assert_eq!(
            s3_spec.raw_fields.get("s3_min_part_size").map(String::as_str),
            Some("8388608")
        );
        let stored_s3 = build_stored_site_for_save("s3-site", &s3_spec);
        let gui_s3 = stored_site_to_gui_json(&stored_s3);
        assert_eq!(gui_s3["s3_protocol"], json!("0"));
        assert_eq!(gui_s3["s3_request_payer"], json!("1"));
        assert_eq!(gui_s3["s3_multipart_threshold"], json!("33554432"));
        assert_eq!(gui_s3["s3_min_part_size"], json!("8388608"));

        let mut too_small = s3_session.clone();
        too_small["s3_min_part_size"] = json!("4M");
        assert!(parse_gui_session_spec(&too_small, None, &dir, &vault).is_err());

        let ftp_session = json!({
            "protocol": "ftp",
            "host": "ftp.example.test",
            "ftps": "explicit",
            "ftp_use_mlsd": "2",
            "ftp_force_pasv_ip": "1",
            "ftp_account": "billing-acct",
            "tls_certificate_file": "/etc/ssl/client.pem",
            "tls_certificate_key_file": "/etc/ssl/client.key",
            "ca_certificate_dir": "/etc/ssl/certs",
        });
        let (ftp_spec, _) = parse_gui_session_spec(&ftp_session, None, &dir, &vault).unwrap();
        assert_eq!(ftp_spec.raw_fields.get("ftp_use_mlsd").map(String::as_str), Some("2"));
        assert_eq!(ftp_spec.raw_fields.get("ftp_force_pasv_ip").map(String::as_str), Some("1"));
        assert_eq!(ftp_spec.raw_fields.get("ftp_account").map(String::as_str), Some("billing-acct"));
        assert_eq!(
            ftp_spec.raw_fields.get("tls_certificate_key_file").map(String::as_str),
            Some("/etc/ssl/client.key")
        );
        assert_eq!(
            ftp_spec.raw_fields.get("ca_certificate_dir").map(String::as_str),
            Some("/etc/ssl/certs")
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_saved_site_does_not_connect_with_stale_settings() {
        let dir = test_config_dir("missing-site");
        let vault = linscp_platform::NativeSecretVault::new();
        assert!(parse_gui_session_spec(&json!({"host":"old.example"}), Some("deleted"), &dir, &vault).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn gui_sudo_opt_in_round_trips_without_exposing_password() {
        let dir = test_config_dir("sudo-option");
        let vault = linscp_platform::NativeSecretVault::new();
        let session = json!({"protocol": "sftp", "host": "host.example", "username": "alice",
            "password": "secret", "sudo_password_auto": true});
        let (spec, clean) = parse_gui_session_spec(&session, None, &dir, &vault).unwrap();
        assert_eq!(spec.raw_fields.get("sudo_password_auto").map(String::as_str), Some("1"));
        assert!(clean.get("password").is_none());
        let mut site = build_stored_site_for_save("example", &spec);
        // Exercise the INI codec without writing an unencrypted password.
        site.password = None;
        let mut store = SessionStore::new();
        store.upsert(site);
        let ini = store.serialize_ini(None).unwrap();
        let restored = SessionStore::parse_ini(&ini, None).unwrap();
        let view = stored_site_to_gui_json(restored.find("example").unwrap());
        assert_eq!(view["sudo_password_auto"], json!(true));
        assert!(view.get("password").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn gui_session_spec_keeps_gssapi_settings() {
        // The page sends four Kerberos settings; the parser must carry them
        // into raw_fields instead of dropping them, or the site manager's
        // Kerberos section is decorative. Try-only settings validate on every
        // build, so this asserts on all hosts.
        let dir = test_config_dir("keep");
        let vault = linscp_platform::NativeSecretVault::new();
        let session = json!({
            "protocol": "sftp",
            "host": "kerberos.example",
            "auth_gssapi": true,
            "auth_gssapi_kex": false,
            "gssapi_fwd_tgt": false,
            "logical_host": "",
        });
        let (spec, _) =
            parse_gui_session_spec(&session, None, &dir, &vault).expect("try-only settings validate");
        assert_eq!(
            spec.raw_fields.get("auth_gssapi").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            spec.raw_fields.get("auth_gssapi_kex").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            spec.raw_fields.get("gssapi_fwd_tgt").map(String::as_str),
            Some("0")
        );
        assert_eq!(
            spec.raw_fields.get("logical_host").map(String::as_str),
            Some("")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gui_session_kerberos_refusal_names_linux() {
        // Explicit Kerberos settings fail closed where no Kerberos runtime
        // exists, and the refusal names the requirement (Linux plus a
        // Kerberos runtime) instead of blaming libssh. Each setting is
        // exercised alone so a dropped key cannot hide behind another.
        let gssapi_here = linscp_platform::gssapi_sys::is_system_gssapi_available();
        for (key, value) in [
            ("gssapi_fwd_tgt", json!(true)),
            ("logical_host", json!("kerberos.example")),
        ] {
            let dir = test_config_dir("refuse");
            let vault = linscp_platform::NativeSecretVault::new();
            let mut session = json!({
                "protocol": "sftp",
                "host": "kerberos.example",
                "auth_gssapi": true,
                "auth_gssapi_kex": false,
                "gssapi_fwd_tgt": false,
                "logical_host": "",
            });
            session[key] = value;
            let result = parse_gui_session_spec(&session, None, &dir, &vault);
            if gssapi_here {
                assert!(result.is_ok(), "{key} must validate where Kerberos exists");
            } else {
                let err = result.unwrap_err();
                assert!(
                    err.contains("Linux"),
                    "{key} must fail closed naming Linux, got: {err}"
                );
            }
            let _ = std::fs::remove_dir_all(&dir);
        }
        // Key exchange is refused on every build, with or without Kerberos.
        let dir = test_config_dir("kex");
        let vault = linscp_platform::NativeSecretVault::new();
        let session = json!({
            "protocol": "sftp",
            "host": "kerberos.example",
            "auth_gssapi": true,
            "auth_gssapi_kex": true,
            "gssapi_fwd_tgt": false,
            "logical_host": "",
        });
        let err = parse_gui_session_spec(&session, None, &dir, &vault).unwrap_err();
        if gssapi_here {
            assert!(err.contains("key exchange"), "kex refusal, got: {err}");
        } else {
            assert!(err.contains("Linux"), "kex refusal names Linux, got: {err}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gui_s3_advanced_options_and_preset_round_trip() {
        let dir = test_config_dir("s3-options");
        let vault = linscp_platform::NativeSecretVault::new();
        let session = json!({
            "protocol": "s3",
            "host": "s3.amazonaws.com",
            "username": "AKIAEXAMPLE",
            "password": "secret",
            "s3_storage_class": "STANDARD_IA",
            "s3_acl": "bucket-owner-full-control",
            "s3_sse": "aws:kms",
            "s3_kms_key": "alias/my-key",
            "s3_metadata": "env=prod,team=storage",
            "preset": "TextLogs",
        });
        let (spec, _) = parse_gui_session_spec(&session, None, &dir, &vault).unwrap();
        assert_eq!(spec.preset_name, "TextLogs");
        let hdrs = linscp_engine::url_and_raw::collect_s3_object_write_headers(&spec.raw_fields);
        assert_eq!(
            hdrs.get("x-amz-storage-class").map(String::as_str),
            Some("STANDARD_IA")
        );
        assert_eq!(
            hdrs.get("x-amz-acl").map(String::as_str),
            Some("bucket-owner-full-control")
        );
        assert_eq!(
            hdrs.get("x-amz-server-side-encryption").map(String::as_str),
            Some("aws:kms")
        );
        assert_eq!(
            hdrs.get("x-amz-server-side-encryption-aws-kms-key-id")
                .map(String::as_str),
            Some("alias/my-key")
        );
        assert_eq!(
            hdrs.get("x-amz-meta-env").map(String::as_str),
            Some("prod")
        );
        assert_eq!(
            hdrs.get("x-amz-meta-team").map(String::as_str),
            Some("storage")
        );
        let mut site = build_stored_site_for_save("prod-s3", &spec);
        site.password = None;
        let gui_json = stored_site_to_gui_json(&site);
        assert_eq!(gui_json["s3_sse"], "aws:kms");
        assert_eq!(gui_json["s3_kms_key"], "alias/my-key");
        assert_eq!(gui_json["s3_metadata"], "env=prod,team=storage");
        assert_eq!(gui_json["preset"], "TextLogs");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gui_desktop_options_and_metadata_round_trip() {
        let dir = test_config_dir("desktop-options");
        let vault = linscp_platform::NativeSecretVault::new();
        let session = json!({
            "protocol": "rdp",
            "host": "winbox.example.test",
            "port": 3389,
            "username": "alice",
            "color": "#3B82F6",
            "note": "Primary jump workstation",
            "rdp_domain": "CORP",
            "rdp_security": "nla",
            "rdp_color_depth": "32",
            "rdp_width": 1920,
            "rdp_height": 1080,
            "rdp_fullscreen": true,
            "rdp_drive_redirection": false,
            "rdp_compression": true,
            "vnc_quality": "7",
            "spice_tls_port": 5901,
            "x2go_session_type": "XFCE",
            "x11_display": ":0",
            "waypipe": true,
        });
        let (spec, _) = parse_gui_session_spec(&session, None, &dir, &vault).unwrap();
        let opts = linscp_proto::remote_desktop::DesktopOptions::from_raw_fields(&spec.raw_fields);
        assert_eq!(opts.domain.as_deref(), Some("CORP"));
        assert_eq!(opts.security.as_deref(), Some("nla"));
        assert_eq!(opts.color_depth, Some(32));
        assert_eq!(opts.width, Some(1920));
        assert_eq!(opts.height, Some(1080));
        assert!(opts.fullscreen);
        assert!(!opts.drive_redirection);
        assert!(opts.compression);
        assert_eq!(opts.vnc_quality, Some(7));
        assert_eq!(opts.spice_tls_port, Some(5901));
        assert_eq!(opts.x2go_session_type.as_deref(), Some("XFCE"));
        assert_eq!(opts.x11_display.as_deref(), Some(":0"));
        assert!(opts.waypipe);

        let site = build_stored_site_for_save("corp-rdp", &spec);
        let gui_json = stored_site_to_gui_json(&site);
        assert_eq!(gui_json["color"], "#3b82f6");
        assert_eq!(gui_json["note"], "Primary jump workstation");
        assert_eq!(gui_json["rdp_domain"], "CORP");
        assert_eq!(gui_json["rdp_width"], "1920");
        assert_eq!(gui_json["spice_tls_port"], "5901");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
