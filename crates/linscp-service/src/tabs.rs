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
    stored_site_from_spec, validate_session_settings, GuiConnectError, GuiHostKeyChallenge,
    ParsedSiteSpec,
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
            obj.remove("password");
            obj.remove("tunnel_password");
            obj.remove("tunnel_passphrase");
        }
        json!({
            "id": self.id,
            "name": self.name,
            "connected": self.connected,
            "is_local": self.is_local,
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
    obj.insert("preset".into(), json!(site.preset));
    obj.insert("proxy_method".into(), json!(site.proxy_method));
    obj.insert("proxy_host".into(), json!(site.proxy_host));
    obj.insert("proxy_port".into(), json!(site.proxy_port));
    obj.insert("proxy_username".into(), json!(site.proxy_username));
    obj.insert("proxy_command".into(), json!(site.proxy_command));
    obj.insert("tunnel_enabled".into(), json!(site.tunnel.enabled));
    obj.insert("tunnel_host".into(), json!(site.tunnel.host));
    obj.insert("tunnel_port".into(), json!(site.tunnel.port));
    obj.insert("tunnel_user".into(), json!(site.tunnel.username));
    obj.insert("tunnel_keyfile".into(), json!(site.tunnel.keyfile));
    obj.insert(
        "tunnel_hostkey".into(),
        json!(site.tunnel.hostkey.clone()),
    );
    for (k, v) in &site.extra_fields {
        obj.entry(k.clone()).or_insert_with(|| json!(v));
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
        let store = SessionStore::load_from_dir(config_root, vault).unwrap_or_default();
        store.find(sname).cloned()
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
        let tk = str_field(session, &["tunnel_keyfile"]);
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
        local_port: 0,
    };

    let mut spec = if let Some(ref b) = stored_base {
        site_spec_from_stored(b).unwrap_or_default()
    } else {
        ParsedSiteSpec::default()
    };

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
    if let Some(pp) = session
        .get("passphrase")
        .or_else(|| session.get("key_passphrase"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        spec.passphrase = Some(pp.to_string());
    }

    // Extra protocol fields (`s3_*`, `ftp_*`, `tls_*`, `proxy_*`)
    let extra_keys = [
        "s3_access_key",
        "s3_secret_key",
        "s3_session_token",
        "s3_region",
        "s3_url_style",
        "s3_default_region",
        "s3_sse",
        "s3_kms_key",
        "s3_acl",
        "s3_storage_class",
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
    // proxy fields remain in raw_fields; no direct spec fields to set

    apply_env_credential_fallbacks(&mut spec);
    if protocol != ProtocolScheme::Local {
        validate_session_settings(&spec)?;
    }

    let mut clean_view = session.clone();
    if let Some(obj) = clean_view.as_object_mut() {
        obj.insert("protocol".into(), json!(protocol.as_str()));
        obj.insert("host".into(), json!(host));
        obj.insert("port".into(), json!(port));
        obj.insert("username".into(), json!(username));
        obj.insert("user".into(), json!(username));
        obj.insert(
            "has_password".into(),
            json!(spec.session.password.as_ref().is_some_and(|p| !p.is_empty())),
        );
        obj.insert("remote_dir".into(), json!(initial_dir));
        obj.insert("local_dir".into(), json!(local_dir));
        obj.remove("password");
        obj.remove("tunnel_password");
        obj.remove("tunnel_passphrase");
    }

    Ok((spec, clean_view))
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

fn percent_encode_userinfo(raw: &str) -> String {
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
) -> Result<(Arc<dyn RemoteSession>, String, String), GuiConnectError> {
    let session = connect_gui_site_spec(spec, config_root, cache_pinned_hostkeys, locale, None).await?;
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
