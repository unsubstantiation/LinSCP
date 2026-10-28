//! Strict session URL parser, `-rawsettings` validator, SSH host-key stdout/cache
//! policy (`HOSTKEY`, `TUNNELHOSTKEY`, `HOSTKEYSTATE` backed by `<config_dir>/sshhostkeys`),
//! TLS certificate/SPKI-pin loader, Kerberos V5 `dlopen` GSSAPI adapter, and
//! protocol session dialer (`connect_site_spec`, `connect_ssh_for_shell`).

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use linscp_i18n::{CatalogDomain, translate_with};
use linscp_platform::SecretVault;
use linscp_platform::gssapi_sys::{
    PlatformGssStep, SystemGssapiContext, is_system_gssapi_available,
    try_create_system_gssapi_context,
};
use linscp_proto::ftp::{FtpConnectConfig, FtpSession};
use linscp_proto::gssapi::{GssapiExchangeStep, GssapiTokenProvider};
use linscp_proto::proxy::{ProxyConfig, ProxyKind};
use linscp_proto::s3::{MultipartResumeStore, S3ConnectConfig, S3Session};
use linscp_proto::scp::ScpSession;
use linscp_proto::sftp::SftpClientSession;
use linscp_proto::ssh::{
    HostKeyDecisionCallback, KeyboardInteractiveResponder, ObservedServerHostKey, SshConnectConfig,
    SshConnection, SshEventLogger,
};
use linscp_proto::tls::{TlsSettings, TlsVersion};
use linscp_proto::tunnel::SshJumpTunnel;
use linscp_proto::webdav::{WebDavConnectConfig, WebDavSession};
use linscp_proto::{ProtoError, RemoteSession};
use linscp_types::{ProtocolScheme, SessionConfig, TunnelConfig};
use zeroize::Zeroizing;

use crate::filemask::matches_wildcard_icase;
use crate::hostkeys::HostKeyCache;
use crate::session_store::StoredSite;

static EMITTED_WILDCARD_HOSTKEYS: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn should_emit_wildcard_hostkey(tag: &str, host: &str, port: u16, fp: &str) -> bool {
    let set = EMITTED_WILDCARD_HOSTKEYS.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = set.lock().unwrap_or_else(|e| e.into_inner());
    guard.insert(format!("{tag}|{host}:{port}|{fp}"))
}

fn cache_pinned_hostkeys_enabled() -> bool {
    match std::env::var("LINSCP_CACHE_PINNED_HOSTKEYS") {
        Ok(val) => !matches!(
            val.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

/// Checks whether `observed` matches a semicolon-separated list of SSH host key pins,
/// supporting `SHA256:<b64>`, `MD5:<colon-hex>`, 64-char SHA-256 hex, `sha256//<b64>`,
/// `*` wildcard, or `<alg> [bits] <fp|pubkey_base64>`.
pub fn matches_extended_ssh_pin(pin_list: &str, observed: &ObservedServerHostKey) -> bool {
    for raw_item in pin_list.split(';') {
        let pin = raw_item.trim();
        if pin.is_empty() {
            continue;
        }
        if pin == "*" {
            return true;
        }
        let tokens: Vec<&str> = pin.split_whitespace().collect();
        let fp_tok = match tokens.as_slice() {
            [single] => *single,
            [alg, fp] => {
                if !observed.key_type.is_empty() && !alg.eq_ignore_ascii_case(&observed.key_type) {
                    continue;
                }
                *fp
            }
            [alg, _bits, fp, ..] => {
                if !observed.key_type.is_empty() && !alg.eq_ignore_ascii_case(&observed.key_type) {
                    continue;
                }
                *fp
            }
            [] => continue,
        };

        if fp_tok == observed.sha256_fingerprint || fp_tok == observed.pubkey_base64 {
            return true;
        }
        if let Some(rest) = fp_tok
            .strip_prefix("SHA256:")
            .or_else(|| fp_tok.strip_prefix("sha256:"))
            .or_else(|| fp_tok.strip_prefix("SHA256//"))
            .or_else(|| fp_tok.strip_prefix("sha256//"))
        {
            let norm = rest.trim().trim_end_matches('=');
            if observed.sha256_fingerprint == format!("SHA256:{norm}") {
                return true;
            }
        }
        if !observed.md5_fingerprint.is_empty() {
            let norm_md5: String = fp_tok
                .strip_prefix("MD5:")
                .or_else(|| fp_tok.strip_prefix("md5:"))
                .unwrap_or(fp_tok)
                .chars()
                .filter(|&c| c != ':' && c != '-')
                .collect();
            let obs_md5: String = observed
                .md5_fingerprint
                .strip_prefix("MD5:")
                .unwrap_or(&observed.md5_fingerprint)
                .chars()
                .filter(|&c| c != ':' && c != '-')
                .collect();
            if norm_md5.len() == 32
                && norm_md5.bytes().all(|b| b.is_ascii_hexdigit())
                && obs_md5.eq_ignore_ascii_case(&norm_md5)
            {
                return true;
            }
        }
        let hex_candidate: String = fp_tok
            .strip_prefix("SHA256:")
            .or_else(|| fp_tok.strip_prefix("sha256:"))
            .unwrap_or(fp_tok)
            .chars()
            .filter(|&c| c != ':' && c != '-')
            .collect();
        if hex_candidate.len() == 64 && hex_candidate.bytes().all(|b| b.is_ascii_hexdigit()) {
            if let Ok(raw_bytes) = hex_decode(&hex_candidate) {
                let b64_unpadded = BASE64
                    .encode(&raw_bytes)
                    .trim_end_matches('=')
                    .to_string();
                if observed.sha256_fingerprint == format!("SHA256:{b64_unpadded}") {
                    return true;
                }
            }
        }
    }
    false
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, ()> {
    if !hex.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().as_chunks::<2>().0 {
        let hi = (pair[0] as char).to_digit(16).ok_or(())?;
        let lo = (pair[1] as char).to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

pub fn looks_like_legacy_cert_fingerprint(pin: &str) -> bool {
    let stripped: String = pin.chars().filter(|&c| c != ':' && c != '-').collect();
    matches!(stripped.len(), 32 | 40 | 64) && stripped.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_valid_spki_pin_list(spec: &str) -> bool {
    let mut any = false;
    for raw in spec.split(';') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        if item == "*" {
            return false;
        }
        any = true;
        if let Some(rest) = item
            .strip_prefix("sha256//")
            .or_else(|| item.strip_prefix("SHA256//"))
        {
            let rest = rest.trim();
            if rest.len() == 64 && rest.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let mut padded = rest.to_string();
            while !padded.len().is_multiple_of(4) {
                padded.push('=');
            }
            if BASE64.decode(padded.as_bytes()).map(|b| b.len()).ok() == Some(32) {
                continue;
            }
            return false;
        }
        let expanded = linscp_platform::terminal::expand_tilde(item);
        if std::path::Path::new(&expanded).is_file() {
            continue;
        }
        return false;
    }
    any
}

#[derive(Debug, Clone)]
pub struct ParsedSiteSpec {
    pub session: SessionConfig,
    pub raw_fields: BTreeMap<String, String>,
    pub explicit_port: bool,
    pub preset_name: String,
    pub session_label: String,
    pub explicit_session_name: Option<String>,
    pub passphrase: Option<String>,
    pub timeout_secs: u64,
}

impl Default for ParsedSiteSpec {
    fn default() -> Self {
        Self {
            session: SessionConfig {
                name: String::new(),
                protocol: ProtocolScheme::Sftp,
                host: String::new(),
                port: 22,
                username: String::new(),
                password: None,
                keyfile: None,
                hostkey: String::new(),
                initial_dir: String::new(),
                local_dir: String::new(),
                tunnel: None,
            },
            raw_fields: BTreeMap::new(),
            explicit_port: false,
            preset_name: String::new(),
            session_label: String::new(),
            explicit_session_name: None,
            passphrase: None,
            timeout_secs: 30,
        }
    }
}

fn percent_decode_strict(input: &str, context: &str) -> Result<String, String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(format!(
                    "Invalid percent-encoding in URL {context} '{input}'."
                ));
            }
            let hi = (bytes[i + 1] as char)
                .to_digit(16)
                .ok_or_else(|| format!("Invalid percent-encoding in URL {context} '{input}'."))?;
            let lo = (bytes[i + 2] as char)
                .to_digit(16)
                .ok_or_else(|| format!("Invalid percent-encoding in URL {context} '{input}'."))?;
            let byte = ((hi << 4) | lo) as u8;
            if byte == 0 {
                return Err(format!("NUL byte (%00) is not allowed in URL {context}."));
            }
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|e| format!("Invalid UTF-8 in URL {context}: {e}"))
}

/// Strictly parses a session URL (`sftp://`, `ssh://`, `scp://`, `ftp://`, `ftps://`, `ftpes://`,
/// `dav://`, `davs://`, `http://`, `https://`, `webdav://`, `webdavs://`, `s3://`).
pub fn parse_site_url(url: &str) -> Result<ParsedSiteSpec, String> {
    if url.contains('?') || url.contains('#') {
        return Err(
            "Session URLs must not contain query ('?') or fragment ('#') components.".to_string(),
        );
    }
    let Some((raw_scheme, after_scheme)) = url.split_once("://") else {
        return Err(format!("'{url}' is not a session URL (missing '://')."));
    };
    let scheme_lc = raw_scheme.to_ascii_lowercase();
    let mut raw_fields = BTreeMap::new();
    let (protocol, default_port) = match scheme_lc.as_str() {
        "sftp" => (ProtocolScheme::Sftp, 22u16),
        "ssh" => (ProtocolScheme::Ssh, 22u16),
        "scp" => (ProtocolScheme::Scp, 22u16),
        "ftp" => (ProtocolScheme::Ftp, 21u16),
        "ftps" => {
            raw_fields.insert("ftps".to_string(), "1".to_string());
            (ProtocolScheme::Ftps, 990u16)
        }
        "ftpes" => {
            raw_fields.insert("ftps".to_string(), "3".to_string());
            (ProtocolScheme::Ftpes, 21u16)
        }
        "dav" | "http" => (ProtocolScheme::Dav, 80u16),
        "webdav" | "https" => (ProtocolScheme::Webdav, 443u16),
        "davs" => (ProtocolScheme::Davs, 443u16),
        "webdavs" => (ProtocolScheme::Webdavs, 443u16),
        "s3" => {
            raw_fields.insert("s3_protocol".to_string(), "1".to_string());
            (ProtocolScheme::S3, 443u16)
        }
        other => {
            return Err(format!(
                "Unsupported URL protocol scheme '{other}' (expected sftp, scp, ftp, ftps, ftpes, http, https, dav, davs, webdav, webdavs or s3)."
            ));
        }
    };

    let (authority, raw_path) = match after_scheme.find('/') {
        Some(slash) => (&after_scheme[..slash], &after_scheme[slash..]),
        None => (after_scheme, ""),
    };
    if authority.is_empty() {
        return Err(format!("Session URL '{url}' is missing a host name."));
    }

    let (userinfo_opt, hostport) = match authority.rfind('@') {
        Some(at_pos) => {
            let ui = &authority[..at_pos];
            if ui.contains('@') {
                return Err(
                    "Session URL userinfo contains an unencoded '@'; encode literal '@' as '%40'."
                        .to_string(),
                );
            }
            (Some(ui), &authority[at_pos + 1..])
        }
        None => (None, authority),
    };

    let (username, password) = if let Some(ui) = userinfo_opt {
        match ui.split_once(':') {
            Some((u, p)) => (
                percent_decode_strict(u, "username")?,
                Some(percent_decode_strict(p, "password")?),
            ),
            None => (percent_decode_strict(ui, "username")?, None),
        }
    } else {
        (String::new(), None)
    };

    let (host, port, explicit_port) = if let Some(rest) = hostport.strip_prefix('[') {
        let Some(close) = rest.find(']') else {
            return Err(format!(
                "Session URL '{url}' has an unclosed '[' in IPv6 host."
            ));
        };
        let ipv6_host = &rest[..close];
        if ipv6_host.is_empty() {
            return Err(format!("Session URL '{url}' has an empty IPv6 host."));
        }
        let tail = &rest[close + 1..];
        if tail.is_empty() {
            (ipv6_host.to_string(), default_port, false)
        } else if let Some(port_str) = tail.strip_prefix(':') {
            let p = parse_strict_port(port_str, url)?;
            (ipv6_host.to_string(), p, true)
        } else {
            return Err(format!(
                "Unexpected characters '{tail}' after IPv6 literal in '{url}'."
            ));
        }
    } else {
        let colon_count = hostport.matches(':').count();
        if colon_count > 1 {
            return Err(format!(
                "IPv6 host literal in '{url}' must be enclosed in '[' and ']'."
            ));
        }
        if let Some((h, port_str)) = hostport.split_once(':') {
            let p = parse_strict_port(port_str, url)?;
            (percent_decode_strict(h, "host")?, p, true)
        } else {
            (percent_decode_strict(hostport, "host")?, default_port, false)
        }
    };

    if host.is_empty()
        || host
            .chars()
            .any(|c| (c as u32) <= 0x20 || c == '\x7f' || c == '/')
    {
        return Err(format!("Invalid host name '{host}' in session URL '{url}'."));
    }

    let initial_dir = if raw_path.is_empty() {
        String::new()
    } else if raw_path == "/" {
        "/".to_string()
    } else {
        let decoded = percent_decode_strict(raw_path, "path")?;
        if decoded.len() > 1 {
            decoded.trim_end_matches('/').to_string()
        } else {
            decoded
        }
    };

    let mut spec = ParsedSiteSpec::default();
    spec.session.protocol = protocol;
    spec.session.host = host.clone();
    spec.session.port = port;
    spec.session.username = username.clone();
    spec.session.password = password;
    spec.session.initial_dir = initial_dir;
    spec.raw_fields = raw_fields;
    spec.explicit_port = explicit_port;
    spec.session_label = host;
    spec.session.name = spec.session_label.clone();
    Ok(spec)
}

fn parse_strict_port(port_str: &str, url: &str) -> Result<u16, String> {
    if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("Invalid port '{port_str}' in session URL '{url}'."));
    }
    let p: u16 = port_str
        .parse()
        .map_err(|_| format!("Port '{port_str}' in '{url}' is out of range (1..65535)."))?;
    if p == 0 {
        return Err(format!("Port in '{url}' must be between 1 and 65535."));
    }
    Ok(p)
}

/// Converts a `StoredSite` loaded from `sessions.ini` into a `ParsedSiteSpec`,
/// failing immediately if any stored secret or toggle was corrupt/unreadable.
pub fn site_spec_from_stored(site: &StoredSite) -> Result<ParsedSiteSpec, String> {
    if let Some(ref err) = site.setting_error {
        return Err(err.clone());
    }
    if let Some(ref err) = site.password_error {
        return Err(format!(
            "The stored password for '{}' cannot be used: {err}",
            site.name
        ));
    }
    if let Some(ref err) = site.proxy_error {
        return Err(err.clone());
    }
    if site.tunnel.enabled {
        if let Some(ref err) = site.tunnel_error {
            return Err(err.clone());
        }
    }

    let mut spec = ParsedSiteSpec {
        session: site.to_session_config(),
        raw_fields: site.extra_fields.clone(),
        explicit_port: site.port != 0,
        preset_name: site.preset.clone(),
        session_label: site.name.clone(),
        explicit_session_name: None,
        passphrase: None,
        timeout_secs: 30,
    };

    if !site.proxy_method.is_empty() {
        spec.raw_fields
            .insert("proxy_method".to_string(), site.proxy_method.clone());
    }
    if !site.proxy_host.is_empty() {
        spec.raw_fields
            .insert("proxy_host".to_string(), site.proxy_host.clone());
    }
    if site.proxy_port != 0 {
        spec.raw_fields
            .insert("proxy_port".to_string(), site.proxy_port.to_string());
    }
    if !site.proxy_username.is_empty() {
        spec.raw_fields
            .insert("proxy_username".to_string(), site.proxy_username.clone());
    }
    if let Some(ref ppw) = site.proxy_password {
        spec.raw_fields
            .insert("proxy_password".to_string(), ppw.clone());
    }
    if !site.proxy_command.is_empty() {
        spec.raw_fields
            .insert("proxy_command".to_string(), site.proxy_command.clone());
    }
    if !site.proxy_exclude.is_empty() {
        spec.raw_fields
            .insert("proxy_exclude".to_string(), site.proxy_exclude.clone());
    }
    if !site.proxy_dns.is_empty() {
        spec.raw_fields
            .insert("proxy_dns".to_string(), site.proxy_dns.clone());
    }
    if site.proxy_localhost {
        spec.raw_fields
            .insert("proxy_localhost".to_string(), "1".to_string());
    }
    if let Some(ref tp) = site.tunnel_passphrase {
        spec.raw_fields
            .insert("tunnel_passphrase".to_string(), tp.clone());
    }

    validate_stored_extra_fields(&spec.raw_fields)?;
    Ok(spec)
}

/// Converts an existing `StoredSite` into a baseline `ParsedSiteSpec` for `savesession`
/// updates without failing on unreadable encrypted secrets (`sessions.key` missing),
/// so unrelated `savesession` edits preserve opaque ciphertexts via `SessionStore::upsert`.
pub fn site_spec_from_stored_for_resave(site: &StoredSite) -> ParsedSiteSpec {
    let mut spec = ParsedSiteSpec {
        session: site.to_session_config(),
        raw_fields: site.extra_fields.clone(),
        explicit_port: site.port != 0,
        preset_name: site.preset.clone(),
        session_label: site.name.clone(),
        explicit_session_name: None,
        passphrase: None,
        timeout_secs: 30,
    };
    if !site.proxy_method.is_empty() {
        spec.raw_fields
            .insert("proxy_method".to_string(), site.proxy_method.clone());
    }
    if !site.proxy_host.is_empty() {
        spec.raw_fields
            .insert("proxy_host".to_string(), site.proxy_host.clone());
    }
    if site.proxy_port != 0 {
        spec.raw_fields
            .insert("proxy_port".to_string(), site.proxy_port.to_string());
    }
    if !site.proxy_username.is_empty() {
        spec.raw_fields
            .insert("proxy_username".to_string(), site.proxy_username.clone());
    }
    if let Some(ref ppw) = site.proxy_password {
        spec.raw_fields
            .insert("proxy_password".to_string(), ppw.clone());
    }
    if !site.proxy_command.is_empty() {
        spec.raw_fields
            .insert("proxy_command".to_string(), site.proxy_command.clone());
    }
    if !site.proxy_exclude.is_empty() {
        spec.raw_fields
            .insert("proxy_exclude".to_string(), site.proxy_exclude.clone());
    }
    if !site.proxy_dns.is_empty() {
        spec.raw_fields
            .insert("proxy_dns".to_string(), site.proxy_dns.clone());
    }
    if site.proxy_localhost {
        spec.raw_fields
            .insert("proxy_localhost".to_string(), "1".to_string());
    }
    if let Some(ref tp) = site.tunnel_passphrase {
        spec.raw_fields
            .insert("tunnel_passphrase".to_string(), tp.clone());
    }
    spec
}

fn validate_stored_extra_fields(fields: &BTreeMap<String, String>) -> Result<(), String> {
    for (k, v) in fields {
        match k.as_str() {
            "auth_gssapi" | "auth_gssapi_kex" | "gssapi_fwd_tgt" | "ftp_pasv_mode"
            | "s3_request_payer" | "s3_protocol" => {
                if parse_zero_one(v).is_none() {
                    return Err(format!("Invalid stored setting '{k}' value '{v}'."));
                }
            }
            "ftp_force_pasv_ip" | "ftp_use_mlsd" if !matches!(v.trim(), "0" | "1" | "2") => {
                return Err(format!("Invalid stored setting '{k}' value '{v}'."));
            }
            "ftps" if !matches!(v.trim(), "0" | "1" | "2" | "3") => {
                return Err(format!("Invalid stored setting 'ftps' value '{v}'."));
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_zero_one(val: &str) -> Option<bool> {
    match val.trim().to_ascii_lowercase().as_str() {
        "0" | "off" | "no" | "false" => Some(false),
        "1" | "on" | "yes" | "true" => Some(true),
        _ => None,
    }
}

pub fn is_ssh_scheme(p: ProtocolScheme) -> bool {
    matches!(
        p,
        ProtocolScheme::Sftp | ProtocolScheme::Scp | ProtocolScheme::Ssh
    )
}

pub fn is_ftp_scheme(p: ProtocolScheme) -> bool {
    matches!(
        p,
        ProtocolScheme::Ftp | ProtocolScheme::Ftps | ProtocolScheme::Ftpes
    )
}

pub fn is_webdav_scheme(p: ProtocolScheme) -> bool {
    matches!(
        p,
        ProtocolScheme::Dav
            | ProtocolScheme::Davs
            | ProtocolScheme::Webdav
            | ProtocolScheme::Webdavs
    )
}

/// Applies `-rawsettings Key=Value ...` pairs onto `spec`, strictly rejecting
/// unknown keys, invalid values, or settings belonging to another protocol.
pub fn apply_raw_settings(spec: &mut ParsedSiteSpec, pairs: &[String]) -> Result<(), String> {
    let proto = spec.session.protocol;
    let is_ssh = is_ssh_scheme(proto);
    let is_ftp = is_ftp_scheme(proto);
    let is_s3 = proto == ProtocolScheme::S3;

    for pair in pairs {
        let Some((raw_k, raw_v)) = pair.split_once('=') else {
            return Err(format!(
                "Invalid '-rawsettings' item '{pair}' (expected NAME=VALUE)."
            ));
        };
        let key_trimmed = raw_k.trim();
        let key_lc = key_trimmed.to_ascii_lowercase();
        let val = raw_v.trim();

        match key_lc.as_str() {
            "proxymethod" => {
                let norm = match val.to_ascii_lowercase().as_str() {
                    "none" | "0" => "",
                    "socks4" | "1" => "SOCKS4",
                    "socks5" | "socks" | "2" => "SOCKS5",
                    "http" | "3" => "HTTP",
                    "telnet" | "4" => {
                        if !is_ssh {
                            return Err(
                                "This protocol connects through curl, which cannot run a telnet proxy; use SOCKS4, SOCKS5 or HTTP, or a protocol this build serves with its own transport."
                                    .to_string(),
                            );
                        }
                        "Telnet"
                    }
                    "cmd" | "local" | "command" | "5" => {
                        if !is_ssh {
                            return Err(
                                "This protocol connects through curl, which cannot run a local command proxy; use SOCKS4, SOCKS5 or HTTP, or a protocol this build serves with its own transport."
                                    .to_string(),
                            );
                        }
                        "Local"
                    }
                    _ => {
                        return Err(format!(
                            "Unknown proxy method '{val}' in ProxyMethod (expected None, SOCKS4, SOCKS5, HTTP, Telnet or Cmd)."
                        ));
                    }
                };
                if norm.is_empty() {
                    spec.raw_fields.remove("proxy_method");
                    spec.raw_fields.remove("proxy_password");
                } else {
                    spec.raw_fields
                        .insert("proxy_method".to_string(), norm.to_string());
                }
            }
            "proxyhost" => {
                spec.raw_fields
                    .insert("proxy_host".to_string(), val.to_string());
            }
            "proxyport" => {
                let p: u16 = val
                    .parse()
                    .ok()
                    .filter(|&p| p > 0)
                    .ok_or_else(|| {
                        format!("Invalid proxy port '{val}' in ProxyPort (expected 1..65535).")
                    })?;
                spec.raw_fields
                    .insert("proxy_port".to_string(), p.to_string());
            }
            "proxyusername" => {
                spec.raw_fields
                    .insert("proxy_username".to_string(), val.to_string());
            }
            "proxypassword" => {
                spec.raw_fields
                    .insert("proxy_password".to_string(), raw_v.to_string());
            }
            "proxytelnetcommand" | "proxylocalcommand" | "proxycommand" => {
                spec.raw_fields
                    .insert("proxy_command".to_string(), raw_v.to_string());
            }
            "proxydns" => {
                if !matches!(
                    val.to_ascii_lowercase().as_str(),
                    "0" | "1" | "2" | "off" | "auto" | "on"
                ) {
                    return Err(format!("Invalid ProxyDNS '{val}' (expected 0, 1 or 2)."));
                }
                spec.raw_fields
                    .insert("proxy_dns".to_string(), val.to_string());
            }
            "proxylocalhost" => {
                let b = parse_zero_one(val)
                    .ok_or_else(|| format!("Invalid ProxyLocalhost '{val}' (expected 0 or 1)."))?;
                spec.raw_fields.insert(
                    "proxy_localhost".to_string(),
                    if b { "1" } else { "0" }.to_string(),
                );
            }
            "proxyexcludelist" => {
                spec.raw_fields
                    .insert("proxy_exclude".to_string(), val.to_string());
            }

            // SSH jump tunnel settings
            "tunnel" => {
                let b = parse_zero_one(val)
                    .ok_or_else(|| format!("Invalid Tunnel '{val}' (expected 0 or 1)."))?;
                let tun = spec.session.tunnel.get_or_insert_with(TunnelConfig::default);
                tun.enabled = b;
            }
            "tunnelhostname" | "tunnelhost" => {
                if val.chars().any(|c| c.is_whitespace() || c.is_control()) {
                    return Err(
                        "TunnelHostName must be a nonempty host name without whitespace or control characters."
                            .to_string(),
                    );
                }
                let tun = spec.session.tunnel.get_or_insert_with(TunnelConfig::default);
                tun.host = val.to_string();
                tun.enabled = !val.is_empty() || tun.enabled;
            }
            "tunnelportnumber" | "tunnelport" => {
                let p: u16 = val
                    .parse()
                    .ok()
                    .filter(|&p| p > 0)
                    .ok_or_else(|| format!("Invalid TunnelPortNumber '{val}'."))?;
                let tun = spec.session.tunnel.get_or_insert_with(TunnelConfig::default);
                tun.port = p;
            }
            "tunnelusername" | "tunneluser" => {
                let tun = spec.session.tunnel.get_or_insert_with(TunnelConfig::default);
                tun.username = val.to_string();
            }
            "tunnelpassword" | "tunnelpasswordplain" => {
                let tun = spec.session.tunnel.get_or_insert_with(TunnelConfig::default);
                tun.password = Some(raw_v.to_string());
            }
            "tunnelpublickeyfile" | "tunnelprivatekey" => {
                let tun = spec.session.tunnel.get_or_insert_with(TunnelConfig::default);
                tun.keyfile = if val.is_empty() {
                    None
                } else {
                    Some(linscp_platform::terminal::expand_tilde(val))
                };
            }
            "tunnelkeypassphrase" | "tunnelpassphrase" | "tunnelpassphraseplain" => {
                spec.raw_fields
                    .insert("tunnel_passphrase".to_string(), raw_v.to_string());
            }
            "tunnelhostkey" => {
                let tun = spec.session.tunnel.get_or_insert_with(TunnelConfig::default);
                tun.hostkey = val.to_string();
            }
            "tunnellocalportnumber" | "tunnellocalport" => {
                let p: u16 = val
                    .parse()
                    .map_err(|_| format!("Invalid TunnelLocalPortNumber '{val}'."))?;
                let tun = spec.session.tunnel.get_or_insert_with(TunnelConfig::default);
                tun.local_port = p;
            }

            // SSH / GSSAPI settings
            "authgssapi" => {
                if !is_ssh {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for SSH/SFTP/SCP sessions."
                    ));
                }
                let b = parse_zero_one(val)
                    .ok_or_else(|| format!("Invalid AuthGSSAPI '{val}' (expected 0 or 1)."))?;
                spec.raw_fields.insert(
                    "auth_gssapi".to_string(),
                    if b { "1" } else { "0" }.to_string(),
                );
            }
            "authgssapikex" => {
                if !is_ssh {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for SSH/SFTP/SCP sessions."
                    ));
                }
                let b = parse_zero_one(val)
                    .ok_or_else(|| format!("Invalid AuthGSSAPIKEX '{val}' (expected 0 or 1)."))?;
                spec.raw_fields.insert(
                    "auth_gssapi_kex".to_string(),
                    if b { "1" } else { "0" }.to_string(),
                );
            }
            "gssapifwdtgt" => {
                if !is_ssh {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for SSH/SFTP/SCP sessions."
                    ));
                }
                let b = parse_zero_one(val)
                    .ok_or_else(|| format!("Invalid GSSAPIFwdTGT '{val}' (expected 0 or 1)."))?;
                spec.raw_fields.insert(
                    "gssapi_fwd_tgt".to_string(),
                    if b { "1" } else { "0" }.to_string(),
                );
            }
            "logicalhostname" => {
                if !is_ssh {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for SSH/SFTP/SCP sessions."
                    ));
                }
                spec.raw_fields
                    .insert("logical_host".to_string(), val.to_string());
            }

            // FTP settings
            "ftppasvmode" => {
                if !is_ftp {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for FTP/FTPS sessions."
                    ));
                }
                let b = parse_zero_one(val)
                    .ok_or_else(|| format!("Invalid FtpPasvMode '{val}' (expected 0 or 1)."))?;
                spec.raw_fields.insert(
                    "ftp_pasv_mode".to_string(),
                    if b { "1" } else { "0" }.to_string(),
                );
            }
            "ftpforcepasvip" => {
                if !is_ftp {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for FTP/FTPS sessions."
                    ));
                }
                if !matches!(val, "0" | "1" | "2") {
                    return Err(format!(
                        "Invalid FtpForcePasvIp '{val}' (expected 0, 1 or 2)."
                    ));
                }
                spec.raw_fields
                    .insert("ftp_force_pasv_ip".to_string(), val.to_string());
            }
            "ftpusemlsd" => {
                if !is_ftp {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for FTP/FTPS sessions."
                    ));
                }
                if !matches!(val, "0" | "1" | "2") {
                    return Err(format!("Invalid FtpUseMlsd '{val}' (expected 0, 1 or 2)."));
                }
                spec.raw_fields
                    .insert("ftp_use_mlsd".to_string(), val.to_string());
            }
            "ftpaccount" => {
                if !is_ftp {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for FTP/FTPS sessions."
                    ));
                }
                spec.raw_fields
                    .insert("ftp_account".to_string(), val.to_string());
            }
            "ftps" => {
                if !is_ftp {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for FTP/FTPS sessions."
                    ));
                }
                if !matches!(val, "0" | "1" | "2" | "3") {
                    return Err(format!("Invalid Ftps '{val}' (expected 0, 1, 2 or 3)."));
                }
                spec.raw_fields.insert("ftps".to_string(), val.to_string());
                match val {
                    "1" => {
                        spec.session.protocol = ProtocolScheme::Ftps;
                        if !spec.explicit_port {
                            spec.session.port = 990;
                        }
                    }
                    "2" | "3" => {
                        spec.session.protocol = ProtocolScheme::Ftpes;
                        if !spec.explicit_port && spec.session.port == 990 {
                            spec.session.port = 21;
                        }
                    }
                    _ => {
                        spec.session.protocol = ProtocolScheme::Ftp;
                        if !spec.explicit_port && spec.session.port == 990 {
                            spec.session.port = 21;
                        }
                    }
                }
            }

            // TLS settings
            "mintlsversion" | "maxtlsversion" => {
                if is_ssh {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is not applicable to SSH sessions."
                    ));
                }
                parse_tls_version_bound(val)?;
                let store_k = if key_lc == "mintlsversion" {
                    "min_tls_version"
                } else {
                    "max_tls_version"
                };
                spec.raw_fields.insert(store_k.to_string(), val.to_string());
                if let (Some(min_s), Some(max_s)) = (
                    spec.raw_fields.get("min_tls_version"),
                    spec.raw_fields.get("max_tls_version"),
                ) {
                    let min_b = parse_tls_version_bound(min_s)?;
                    let max_b = parse_tls_version_bound(max_s)?;
                    if min_b > max_b {
                        return Err(
                            "MinTlsVersion (TLS 1.3) cannot exceed MaxTlsVersion (TLS 1.2)."
                                .to_string(),
                        );
                    }
                }
            }
            "tlscertificatefile" => {
                if is_ssh {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is not applicable to SSH sessions."
                    ));
                }
                spec.raw_fields.insert(
                    "tls_certificate_file".to_string(),
                    linscp_platform::terminal::expand_tilde(val),
                );
            }
            "tlscertificatekeyfile" => {
                if is_ssh {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is not applicable to SSH sessions."
                    ));
                }
                spec.raw_fields.insert(
                    "tls_certificate_key_file".to_string(),
                    linscp_platform::terminal::expand_tilde(val),
                );
            }
            "cacertificatefile" => {
                if is_ssh {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is not applicable to SSH sessions."
                    ));
                }
                spec.raw_fields.insert(
                    "ca_certificate_file".to_string(),
                    linscp_platform::terminal::expand_tilde(val),
                );
            }
            "cacertificatedir" => {
                if is_ssh {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is not applicable to SSH sessions."
                    ));
                }
                spec.raw_fields.insert(
                    "ca_certificate_dir".to_string(),
                    linscp_platform::terminal::expand_tilde(val),
                );
            }
            "pinnedpublickey" => {
                if is_ssh {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is not applicable to SSH sessions (use -hostkey)."
                    ));
                }
                if !val.is_empty() && !is_valid_spki_pin_list(val) {
                    return Err(format!(
                        "Invalid PinnedPublicKey '{val}' (expected 'sha256//<base64>' or a public-key/certificate file)."
                    ));
                }
                let normalized_pin = val
                    .split(';')
                    .map(|p| {
                        let t = p.trim();
                        if t.starts_with("sha256//") || t.starts_with("SHA256//") || t.is_empty() {
                            t.to_string()
                        } else {
                            linscp_platform::terminal::expand_tilde(t)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(";");
                spec.raw_fields
                    .insert("pinned_public_key".to_string(), normalized_pin);
            }

            // S3 settings
            "s3protocol" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                let use_https = match val.to_ascii_lowercase().as_str() {
                    "0" | "http" => false,
                    "1" | "https" => true,
                    _ => {
                        return Err(format!(
                            "Invalid S3Protocol '{val}' (expected 0/http or 1/https)."
                        ));
                    }
                };
                spec.raw_fields.insert(
                    "s3_protocol".to_string(),
                    if use_https { "1" } else { "0" }.to_string(),
                );
                if !spec.explicit_port {
                    spec.session.port = if use_https { 443 } else { 80 };
                }
            }
            "s3urlstyle" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                let style = match val.to_ascii_lowercase().as_str() {
                    "0" | "vhost" | "virtual" => "0",
                    "1" | "path" => "1",
                    _ => {
                        return Err(format!(
                            "Invalid S3UrlStyle '{val}' (expected 0/vhost or 1/path)."
                        ));
                    }
                };
                spec.raw_fields
                    .insert("s3_url_style".to_string(), style.to_string());
            }
            "s3defaultregion" | "s3region" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                spec.raw_fields
                    .insert("s3_region".to_string(), val.to_string());
            }
            "s3sessiontoken" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                spec.raw_fields
                    .insert("s3_session_token".to_string(), raw_v.to_string());
            }
            "s3storageclass" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                spec.raw_fields
                    .insert("s3_storage_class".to_string(), val.to_string());
            }
            "s3acl" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                spec.raw_fields
                    .insert("s3_acl".to_string(), val.to_string());
            }
            "s3ssealgorithm" | "s3serversideencryption" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                spec.raw_fields
                    .insert("s3_sse_algorithm".to_string(), val.to_string());
            }
            "s3ssekmskeyid" | "s3kmskeyid" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                spec.raw_fields
                    .insert("s3_sse_kms_key_id".to_string(), val.to_string());
            }
            "s3metadata" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                spec.raw_fields
                    .insert("s3_metadata".to_string(), val.to_string());
            }
            "s3minpartsize" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                let n = parse_byte_size_setting(val, "S3MinPartSize")?;
                spec.raw_fields
                    .insert("s3_min_part_size".to_string(), n.to_string());
            }
            "s3multipartthreshold" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                let n = parse_byte_size_setting(val, "S3MultipartThreshold")?;
                spec.raw_fields
                    .insert("s3_multipart_threshold".to_string(), n.to_string());
            }
            "s3requestpayer" => {
                if !is_s3 {
                    return Err(format!(
                        "Raw setting '{key_trimmed}' is supported only for S3 sessions."
                    ));
                }
                let b = if val.eq_ignore_ascii_case("requester") {
                    true
                } else {
                    parse_zero_one(val).ok_or_else(|| {
                        format!("Invalid S3RequestPayer '{val}' (expected 0, 1 or requester).")
                    })?
                };
                spec.raw_fields.insert(
                    "s3_request_payer".to_string(),
                    if b { "1" } else { "0" }.to_string(),
                );
            }

            _ => {
                return Err(format!(
                    "Unsupported raw session setting '{key_trimmed}'; supported settings include ProxyMethod, ProxyHost, ProxyPort, Tunnel, Ftps, S3UrlStyle, and AuthGSSAPI."
                ));
            }
        }
    }
    Ok(())
}

/// Validates cross-field session constraints (such as `ProxyMethod` requiring `ProxyHost`
/// and `Tunnel=1` requiring `TunnelHostName`) before saving or opening a session.
pub fn validate_session_settings(spec: &ParsedSiteSpec) -> Result<(), String> {
    if let Some(pm) = spec
        .raw_fields
        .get("proxy_method")
        .map(|s| s.trim().to_ascii_lowercase())
    {
        if !pm.is_empty() && pm != "none" && pm != "0" {
            if matches!(pm.as_str(), "cmd" | "local" | "command" | "5") {
                if spec
                    .raw_fields
                    .get("proxy_command")
                    .is_none_or(|c| c.trim().is_empty())
                {
                    return Err("ProxyMethod=Cmd requires ProxyLocalCommand.".to_string());
                }
            } else if spec
                .raw_fields
                .get("proxy_host")
                .is_none_or(|h| h.trim().is_empty())
            {
                return Err(
                    "ProxyMethod requires a non-empty ProxyHost.".to_string(),
                );
            }
        }
    }
    if let Some(ref tun) = spec.session.tunnel {
        if tun.enabled
            && (tun.host.trim().is_empty()
                || tun.host.chars().any(|c| c.is_whitespace() || c.is_control()))
        {
            return Err(
                "TunnelHostName must be a nonempty host name without whitespace or control characters."
                    .to_string(),
            );
        }
    }
    Ok(())
}

fn parse_byte_size_setting(val: &str, name: &str) -> Result<u64, String> {
    let t = val.trim();
    let digits = t.bytes().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 {
        return Err(format!("Invalid {name} '{val}'."));
    }
    let base: u64 = t[..digits]
        .parse()
        .map_err(|_| format!("{name} '{val}' is out of range."))?;
    let shift = match t[digits..].to_ascii_uppercase().as_str() {
        "" | "B" => 0u32,
        "K" | "KB" => 10u32,
        "M" | "MB" => 20u32,
        "G" | "GB" => 30u32,
        _ => return Err(format!("Invalid unit suffix in {name} '{val}'.")),
    };
    base.checked_shl(shift)
        .filter(|&n| n > 0)
        .ok_or_else(|| format!("{name} '{val}' must be positive."))
}

fn parse_tls_version_bound(val: &str) -> Result<TlsVersion, String> {
    if let Some(v) = TlsVersion::parse(val) {
        return Ok(v);
    }
    let low = val.trim().to_ascii_lowercase();
    if matches!(
        low.as_str(),
        "10" | "1.0" | "11" | "1.1" | "tls1.0" | "tls1.1" | "tlsv1.0" | "tlsv1.1"
    ) {
        return Err(format!(
            "TLS version '{val}' is obsolete and not supported (use 12/1.2 or 13/1.3)."
        ));
    }
    Err(format!(
        "Invalid TLS version '{val}' (expected 12, 13, 1.2 or 1.3)."
    ))
}

fn host_bypassed_by_proxy(host: &str, proxy_localhost: bool, exclude_list: &str) -> bool {
    let h = host.trim().to_ascii_lowercase();
    let is_loopback = matches!(h.as_str(), "localhost" | "127.0.0.1" | "::1")
        || h.starts_with("127.");
    if is_loopback && !proxy_localhost {
        return true;
    }
    for raw in exclude_list.split([';', ',']) {
        let pat = raw.trim();
        if pat.is_empty() {
            continue;
        }
        if matches_wildcard_icase(pat, &h) {
            return true;
        }
        if let Some(suffix) = pat.strip_prefix('.') {
            if h.eq_ignore_ascii_case(suffix) || h.ends_with(&pat.to_ascii_lowercase()) {
                return true;
            }
        }
    }
    false
}

/// Converts a `ParsedSiteSpec` back into a `StoredSite` for `savesession`.
pub fn stored_site_from_spec(name: &str, spec: &ParsedSiteSpec) -> StoredSite {
    let mut rem = spec.raw_fields.clone();
    // Normalize `ftpes` into `protocol = ftp` + `ftps = 3` in `sessions.ini`, matching C++ store
    let proto_for_store = if spec.session.protocol == ProtocolScheme::Ftpes {
        rem.entry("ftps".to_string())
            .or_insert_with(|| "3".to_string());
        ProtocolScheme::Ftp
    } else {
        spec.session.protocol
    };

    let mut site = StoredSite::new(name.to_string(), proto_for_store, spec.session.host.clone());
    site.port = spec.session.port;
    site.username = spec.session.username.clone();
    site.password = spec.session.password.clone();
    site.private_key = spec.session.keyfile.clone();
    site.hostkey = if spec.session.hostkey.is_empty() {
        None
    } else {
        Some(spec.session.hostkey.clone())
    };
    site.remote_directory = spec.session.initial_dir.clone();
    site.local_directory = spec.session.local_dir.clone();
    site.preset = spec.preset_name.clone();

    site.proxy_method = rem.remove("proxy_method").unwrap_or_default();
    site.proxy_host = rem.remove("proxy_host").unwrap_or_default();
    site.proxy_port = rem
        .remove("proxy_port")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    site.proxy_username = rem.remove("proxy_username").unwrap_or_default();
    site.proxy_password = rem.remove("proxy_password");
    site.proxy_command = rem.remove("proxy_command").unwrap_or_default();
    site.proxy_exclude = rem.remove("proxy_exclude").unwrap_or_default();
    site.proxy_dns = rem.remove("proxy_dns").unwrap_or_default();
    site.proxy_localhost = rem
        .remove("proxy_localhost")
        .and_then(|v| parse_zero_one(&v))
        .unwrap_or(false);

    if let Some(ref tun) = spec.session.tunnel {
        site.tunnel = tun.clone();
    }
    site.tunnel_passphrase = rem.remove("tunnel_passphrase");
    site.extra_fields = rem;
    site
}

struct LazyDlopenKrb5Provider {
    service_host: String,
    delegate_creds: bool,
    ctx: Option<Box<dyn SystemGssapiContext>>,
}

#[async_trait::async_trait]
impl GssapiTokenProvider for LazyDlopenKrb5Provider {
    async fn step(
        &mut self,
        _selected_mechanism: Option<Vec<u8>>,
        input_token: Option<Vec<u8>>,
        mic_data: Vec<u8>,
    ) -> Result<GssapiExchangeStep, ProtoError> {
        if self.ctx.is_none() {
            self.ctx = try_create_system_gssapi_context(&self.service_host, self.delegate_creds);
            if self.ctx.is_none() {
                return Err(ProtoError::Transport(
                    "GSSAPI Kerberos V5 security context could not be initialized.".to_string(),
                ));
            }
        }
        let ctx = self.ctx.as_mut().unwrap();
        match ctx
            .step(input_token.as_deref(), &mic_data)
            .map_err(ProtoError::Transport)?
        {
            PlatformGssStep::Continue(tok) => Ok(GssapiExchangeStep::Continue(tok)),
            PlatformGssStep::Complete { token, mic } => Ok(GssapiExchangeStep::Complete {
                token,
                mic: Some(mic),
            }),
        }
    }
}

struct TtyKeyboardInteractiveResponder;

#[async_trait::async_trait]
impl KeyboardInteractiveResponder for TtyKeyboardInteractiveResponder {
    async fn respond(
        &self,
        name: &str,
        instructions: &str,
        prompts: &[(String, bool)],
    ) -> Result<Vec<String>, ProtoError> {
        if !name.trim().is_empty() {
            let _ = writeln!(std::io::stderr(), "{}", name.trim());
        }
        if !instructions.trim().is_empty() {
            let _ = writeln!(std::io::stderr(), "{}", instructions.trim());
        }
        let mut answers = Vec::with_capacity(prompts.len());
        for (prompt, echo) in prompts {
            if *echo {
                eprint!("{prompt}");
                let _ = std::io::stderr().flush();
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|e| ProtoError::Transport(format!("Reading prompt failed: {e}")))?;
                answers.push(line.trim_end_matches(['\r', '\n']).to_string());
            } else {
                let ans = linscp_platform::terminal::read_password_no_echo(prompt)
                    .map_err(|e| ProtoError::Transport(format!("Reading secret prompt failed: {e}")))?
                    .ok_or_else(|| {
                        ProtoError::Transport("Authentication cancelled.".to_string())
                    })?;
                answers.push(ans);
            }
        }
        Ok(answers)
    }
}

fn build_proxy_config(spec: &ParsedSiteSpec) -> Result<Option<ProxyConfig>, String> {
    let proxy_method = spec
        .raw_fields
        .get("proxy_method")
        .map(String::as_str)
        .unwrap_or("none");
    let kind = match proxy_method.to_ascii_lowercase().as_str() {
        "" | "none" | "0" => return Ok(None),
        "socks4" | "1" => ProxyKind::Socks4,
        "socks5" | "socks" | "2" => ProxyKind::Socks5,
        "http" | "3" => ProxyKind::HttpConnect,
        "telnet" | "4" => ProxyKind::Telnet,
        "cmd" | "local" | "command" | "5" => ProxyKind::LocalCommand,
        other => return Err(format!("Unknown proxy method '{other}'.")),
    };
    let proxy_localhost = spec
        .raw_fields
        .get("proxy_localhost")
        .and_then(|v| parse_zero_one(v))
        .unwrap_or(false);
    let exclude = spec
        .raw_fields
        .get("proxy_exclude")
        .map(String::as_str)
        .unwrap_or("");
    if host_bypassed_by_proxy(&spec.session.host, proxy_localhost, exclude) {
        return Ok(None);
    }

    let p_host = spec
        .raw_fields
        .get("proxy_host")
        .cloned()
        .unwrap_or_default();
    let p_port: u16 = spec
        .raw_fields
        .get("proxy_port")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1080);
    let p_cmd = spec
        .raw_fields
        .get("proxy_command")
        .cloned()
        .unwrap_or_default();

    if kind == ProxyKind::LocalCommand && p_cmd.trim().is_empty() {
        return Err("ProxyMethod=Cmd requires ProxyLocalCommand.".to_string());
    }
    if kind != ProxyKind::LocalCommand && p_host.trim().is_empty() {
        return Err("ProxyMethod requires a non-empty ProxyHost.".to_string());
    }
    let remote_dns = !matches!(
        spec.raw_fields
            .get("proxy_dns")
            .map(|s| s.to_ascii_lowercase())
            .as_deref(),
        Some("0" | "off" | "no" | "false")
    );
    Ok(Some(ProxyConfig {
        kind,
        host: p_host,
        port: p_port,
        username: spec
            .raw_fields
            .get("proxy_username")
            .cloned()
            .filter(|s| !s.is_empty()),
        password: spec
            .raw_fields
            .get("proxy_password")
            .cloned()
            .filter(|s| !s.is_empty()),
        remote_dns,
        command: (!p_cmd.is_empty()).then_some(p_cmd),
    }))
}

fn build_tls_settings(spec: &ParsedSiteSpec) -> Result<TlsSettings, String> {
    let mut tls = TlsSettings::default();
    if is_ssh_scheme(spec.session.protocol) {
        return Ok(tls);
    }
    let hk = spec.session.hostkey.trim();
    if hk == "*" {
        tls.accept_invalid_certs = true;
    } else if !hk.is_empty() {
        if looks_like_legacy_cert_fingerprint(hk) {
            return Err(format!(
                "Certificate fingerprint '{hk}' is not supported by this build; use SPKI pinning via PinnedPublicKey=sha256//<base64> or -hostkey=sha256//<base64>."
            ));
        }
        if is_valid_spki_pin_list(hk) {
            tls.pinned_public_key = Some(hk.to_string());
        } else {
            return Err(format!(
                "Invalid TLS certificate fingerprint or host key pin '{hk}'; use PinnedPublicKey=sha256//<base64> or -hostkey=*."
            ));
        }
    }
    if let Some(pin) = spec
        .raw_fields
        .get("pinned_public_key")
        .filter(|s| !s.is_empty())
    {
        tls.pinned_public_key = Some(pin.clone());
    }
    if let Some(min_s) = spec.raw_fields.get("min_tls_version") {
        tls.min_version = Some(parse_tls_version_bound(min_s)?);
    }
    if let Some(max_s) = spec.raw_fields.get("max_tls_version") {
        tls.max_version = Some(parse_tls_version_bound(max_s)?);
    }
    if let Some(ca_file) = spec
        .raw_fields
        .get("ca_certificate_file")
        .filter(|s| !s.is_empty())
    {
        let pem = std::fs::read(ca_file)
            .map_err(|e| format!("Cannot read CaCertificateFile '{ca_file}': {e}"))?;
        tls.ca_cert_pem = Some(pem);
    }
    if let Some(ca_dir) = spec
        .raw_fields
        .get("ca_certificate_dir")
        .filter(|s| !s.is_empty())
    {
        let rd = std::fs::read_dir(ca_dir)
            .map_err(|e| format!("Cannot read CaCertificateDir '{ca_dir}': {e}"))?;
        let mut bundle = tls.ca_cert_pem.take().unwrap_or_default();
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Ok(bytes) = std::fs::read(&p) {
                    if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
                        bundle.extend_from_slice(&bytes);
                        bundle.push(b'\n');
                    }
                }
            }
        }
        if !bundle.is_empty() {
            tls.ca_cert_pem = Some(bundle);
        }
    }
    if let Some(cert_file) = spec
        .raw_fields
        .get("tls_certificate_file")
        .filter(|s| !s.is_empty())
    {
        let pem = std::fs::read(cert_file)
            .map_err(|e| format!("Cannot read TlsCertificateFile '{cert_file}': {e}"))?;
        let key_pem = if let Some(key_file) = spec
            .raw_fields
            .get("tls_certificate_key_file")
            .filter(|s| !s.is_empty())
        {
            std::fs::read(key_file)
                .map_err(|e| format!("Cannot read TlsCertificateKeyFile '{key_file}': {e}"))?
        } else {
            pem.clone()
        };
        tls.client_cert_pem = Some(pem);
        tls.client_key_pem = Some(key_pem);
    }
    Ok(tls)
}

fn validate_ssh_gssapi_policy(spec: &ParsedSiteSpec) -> Result<(), String> {
    if !is_ssh_scheme(spec.session.protocol) {
        return Ok(());
    }
    let auth_kex = spec
        .raw_fields
        .get("auth_gssapi_kex")
        .and_then(|v| parse_zero_one(v))
        .unwrap_or(false);
    let gss_delegate = spec
        .raw_fields
        .get("gssapi_fwd_tgt")
        .and_then(|v| parse_zero_one(v))
        .unwrap_or(false);
    let has_logical_host = spec
        .raw_fields
        .get("logical_host")
        .or_else(|| spec.raw_fields.get("logical_hostname"))
        .is_some_and(|s| !s.trim().is_empty());
    let hk = spec.session.hostkey.trim();
    if auth_kex && !hk.is_empty() && hk != "*" {
        return Err(
            "AuthGSSAPIKEX cannot be used with a pinned host key because GSSAPI key exchange does not present a host key."
                .to_string(),
        );
    }
    if !is_system_gssapi_available() && (auth_kex || gss_delegate || has_logical_host) {
        return Err(
            "This build's libssh cannot use GSSAPI, so the session's Kerberos settings (AuthGSSAPIKEX, GSSAPIFwdTGT, LogicalHostName) would be dropped."
                .to_string(),
        );
    }
    if auth_kex {
        return Err(
            "This build's libssh does not support GSSAPI key exchange, so AuthGSSAPIKEX cannot be honored."
                .to_string(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_ssh_configs(
    spec: &ParsedSiteSpec,
    config_dir: &Path,
    interactive_confirm: bool,
    interactive_auth: bool,
    locale: &str,
    log_level: i32,
    ssh_log_sink: Option<SshEventLogger>,
    proxy: Option<ProxyConfig>,
) -> (SshConnectConfig, Option<SshConnectConfig>, u16) {
    let verbose_stderr = log_level >= 1;
    let event_logger: Option<SshEventLogger> = if verbose_stderr || ssh_log_sink.is_some() {
        Some(Arc::new(move |msg: &str| {
            if verbose_stderr {
                let _ = writeln!(std::io::stderr(), "{msg}");
            }
            if let Some(ref sink) = ssh_log_sink {
                sink(msg);
            }
        }))
    } else {
        None
    };

    let kbd: Option<Arc<dyn KeyboardInteractiveResponder>> = if interactive_auth {
        Some(Arc::new(TtyKeyboardInteractiveResponder))
    } else {
        None
    };

    let try_gssapi = spec
        .raw_fields
        .get("auth_gssapi")
        .and_then(|v| parse_zero_one(v))
        .unwrap_or(true);
    let request_gssapi_kex = spec
        .raw_fields
        .get("auth_gssapi_kex")
        .and_then(|v| parse_zero_one(v))
        .unwrap_or(false);
    let gss_delegate = spec
        .raw_fields
        .get("gssapi_fwd_tgt")
        .and_then(|v| parse_zero_one(v))
        .unwrap_or(false);
    let service_host = spec
        .raw_fields
        .get("logical_host")
        .or_else(|| spec.raw_fields.get("logical_hostname"))
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| spec.session.host.clone());

    let gssapi_provider: Option<Arc<tokio::sync::Mutex<Box<dyn GssapiTokenProvider>>>> =
        if try_gssapi && is_system_gssapi_available() {
            if gss_delegate {
                if let Some(ref log) = event_logger {
                    log("Kerberos credentials will be delegated to the server (GSSAPIFwdTGT)");
                }
            }
            Some(Arc::new(tokio::sync::Mutex::new(Box::new(
                LazyDlopenKrb5Provider {
                    service_host,
                    delegate_creds: gss_delegate,
                    ctx: None,
                },
            ))))
        } else {
            None
        };

    let port = if spec.session.port == 0 {
        spec.session.protocol.default_port()
    } else {
        spec.session.port
    };
    let ssh_user = if spec.session.username.is_empty() {
        linscp_platform::terminal::current_username()
    } else {
        spec.session.username.clone()
    };

    let dest_cfg = SshConnectConfig {
        tab_id: 1,
        role: "destination".to_string(),
        host: spec.session.host.clone(),
        port,
        username: ssh_user,
        password: spec.session.password.clone().map(Zeroizing::new),
        private_key_pem: None,
        private_key_path: spec.session.keyfile.clone(),
        key_passphrase: spec.passphrase.clone().map(Zeroizing::new),
        pinned_host_key: None,
        known_host_key: None,
        danger_accept_any_host_key: spec.session.hostkey.trim() == "*",
        host_key_decision: Some(make_ssh_host_key_callback(
            false,
            spec.session.hostkey.clone(),
            config_dir.to_path_buf(),
            interactive_confirm,
            locale.to_string(),
        )),
        try_agent: spec.session.keyfile.is_none() && spec.session.password.is_none(),
        agent_connector: None,
        keyboard_interactive: kbd.clone(),
        try_gssapi,
        request_gssapi: false,
        request_gssapi_kex,
        gssapi_provider,
        event_logger: event_logger.clone(),
        proxy: proxy.clone(),
        connect_timeout: Duration::from_secs(spec.timeout_secs.max(1)),
    };

    let (tunnel_cfg, tunnel_local_port) = match spec
        .session
        .tunnel
        .as_ref()
        .filter(|t| t.enabled && !t.host.is_empty())
    {
        Some(t) => {
            let tport = if t.port == 0 { 22 } else { t.port };
            let tuser = if t.username.is_empty() {
                linscp_platform::terminal::current_username()
            } else {
                t.username.clone()
            };
            let tpass = spec
                .raw_fields
                .get("tunnel_passphrase")
                .cloned()
                .or_else(|| {
                    std::env::var("LINSCP_TUNNEL_PASSPHRASE")
                        .ok()
                        .filter(|s| !s.is_empty())
                });
            let cfg = SshConnectConfig {
                tab_id: 1,
                role: "tunnel".to_string(),
                host: t.host.clone(),
                port: tport,
                username: tuser,
                password: t.password.clone().map(Zeroizing::new),
                private_key_pem: None,
                private_key_path: t.keyfile.clone(),
                key_passphrase: tpass.map(Zeroizing::new),
                pinned_host_key: None,
                known_host_key: None,
                danger_accept_any_host_key: t.hostkey.trim() == "*",
                host_key_decision: Some(make_ssh_host_key_callback(
                    true,
                    t.hostkey.clone(),
                    config_dir.to_path_buf(),
                    interactive_confirm,
                    locale.to_string(),
                )),
                try_agent: t.keyfile.is_none() && t.password.is_none(),
                agent_connector: None,
                keyboard_interactive: kbd,
                try_gssapi: false,
                request_gssapi: false,
                request_gssapi_kex: false,
                gssapi_provider: None,
                event_logger,
                proxy,
                connect_timeout: Duration::from_secs(spec.timeout_secs.max(1)),
            };
            (Some(cfg), t.local_port)
        }
        None => (None, 0),
    };

    (dest_cfg, tunnel_cfg, tunnel_local_port)
}

/// Connects a `ParsedSiteSpec` and verifies endpoint reachability (`probe_endpoint`).
#[allow(clippy::too_many_arguments)]
pub async fn connect_site_spec(
    spec: &ParsedSiteSpec,
    config_dir: &Path,
    interactive_confirm: bool,
    interactive_auth: bool,
    locale: &str,
    log_level: i32,
    ssh_log_sink: Option<SshEventLogger>,
) -> Result<Box<dyn RemoteSession>, String> {
    validate_ssh_gssapi_policy(spec)?;
    let proxy = build_proxy_config(spec)?;
    let tls = build_tls_settings(spec)?;
    let (dest_ssh_cfg, tunnel_ssh_cfg, tunnel_local_port) = build_ssh_configs(
        spec,
        config_dir,
        interactive_confirm,
        interactive_auth,
        locale,
        log_level,
        ssh_log_sink,
        proxy.clone(),
    );

    let timeout = Duration::from_secs(spec.timeout_secs.max(1));
    let port = if spec.session.port == 0 {
        spec.session.protocol.default_port()
    } else {
        spec.session.port
    };

    let session: Box<dyn RemoteSession> = match spec.session.protocol {
        ProtocolScheme::Sftp => {
            let sftp = SftpClientSession::connect(
                spec.session.protocol,
                &dest_ssh_cfg,
                tunnel_ssh_cfg.as_ref(),
                tunnel_local_port,
            )
            .await
            .map_err(|e| e.to_string())?;
            Box::new(sftp)
        }
        ProtocolScheme::Scp | ProtocolScheme::Ssh => {
            let scp = ScpSession::connect(
                &dest_ssh_cfg,
                tunnel_ssh_cfg.as_ref(),
                tunnel_local_port,
            )
            .await
            .map_err(|e| e.to_string())?;
            Box::new(scp)
        }
        ProtocolScheme::Ftp | ProtocolScheme::Ftps | ProtocolScheme::Ftpes => {
            let ftp_scheme = match spec.raw_fields.get("ftps").map(String::as_str) {
                Some("1") => ProtocolScheme::Ftps,
                Some("2" | "3") => ProtocolScheme::Ftpes,
                Some("0") => ProtocolScheme::Ftp,
                _ => spec.session.protocol,
            };
            let ftp_cfg = FtpConnectConfig {
                scheme: ftp_scheme,
                host: spec.session.host.clone(),
                port,
                username: if spec.session.username.is_empty() {
                    "anonymous".to_string()
                } else {
                    spec.session.username.clone()
                },
                password: spec.session.password.clone().map(Zeroizing::new),
                account: spec
                    .raw_fields
                    .get("ftp_account")
                    .cloned()
                    .filter(|s| !s.is_empty()),
                pasv_mode: spec
                    .raw_fields
                    .get("ftp_pasv_mode")
                    .and_then(|v| parse_zero_one(v))
                    .unwrap_or(true),
                force_pasv_ip: spec.raw_fields.get("ftp_force_pasv_ip").map(String::as_str)
                    != Some("0"),
                use_mlsd: spec.raw_fields.get("ftp_use_mlsd").map(String::as_str) != Some("0"),
                mlsd_required: spec.raw_fields.get("ftp_use_mlsd").map(String::as_str)
                    == Some("2"),
                tls,
                proxy,
                timeout,
            };
            let ftp = FtpSession::connect(ftp_cfg, tunnel_ssh_cfg.as_ref(), tunnel_local_port)
                .await
                .map_err(|e| e.to_string())?;
            Box::new(ftp)
        }
        ProtocolScheme::Dav
        | ProtocolScheme::Davs
        | ProtocolScheme::Webdav
        | ProtocolScheme::Webdavs => {
            let dav_cfg = WebDavConnectConfig {
                scheme: spec.session.protocol,
                host: spec.session.host.clone(),
                port,
                base_path: if spec.session.initial_dir.is_empty() {
                    "/".to_string()
                } else {
                    spec.session.initial_dir.clone()
                },
                username: if spec.session.username.is_empty() {
                    None
                } else {
                    Some(spec.session.username.clone())
                },
                password: spec.session.password.clone().map(Zeroizing::new),
                tls,
                proxy,
                timeout,
            };
            let dav = WebDavSession::connect(dav_cfg, tunnel_ssh_cfg.as_ref(), tunnel_local_port)
                .await
                .map_err(|e| e.to_string())?;
            Box::new(dav)
        }
        ProtocolScheme::S3 => {
            let use_https = spec.raw_fields.get("s3_protocol").map(String::as_str) != Some("0");
            let path_style = match spec.raw_fields.get("s3_url_style").map(String::as_str) {
                Some("0") => false,
                Some("1") => true,
                _ => !spec.session.host.ends_with(".amazonaws.com"),
            };
            let region = spec
                .raw_fields
                .get("s3_region")
                .cloned()
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var("AWS_REGION").ok().filter(|s| !s.is_empty()))
                .or_else(|| {
                    std::env::var("AWS_DEFAULT_REGION")
                        .ok()
                        .filter(|s| !s.is_empty())
                });
            let session_token = spec
                .raw_fields
                .get("s3_session_token")
                .cloned()
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    std::env::var("AWS_SESSION_TOKEN")
                        .ok()
                        .filter(|s| !s.is_empty())
                })
                .map(Zeroizing::new);
            let mut extra_signed_headers = BTreeMap::new();
            if spec
                .raw_fields
                .get("s3_request_payer")
                .and_then(|v| parse_zero_one(v))
                .unwrap_or(false)
            {
                extra_signed_headers
                    .insert("x-amz-request-payer".to_string(), "requester".to_string());
            }
            let object_write_headers = collect_s3_object_write_headers(&spec.raw_fields);
            let resume_store =
                MultipartResumeStore::with_sidecar_file(config_dir.join("s3_multipart_resume.json"));

            let mut s3_cfg = S3ConnectConfig {
                use_https,
                host: spec.session.host.clone(),
                port,
                region,
                access_key_id: spec.session.username.clone(),
                secret_access_key: Zeroizing::new(
                    spec.session.password.clone().unwrap_or_default(),
                ),
                session_token,
                default_bucket: spec
                    .session
                    .initial_dir
                    .trim_matches('/')
                    .split('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                path_style,
                abort_multipart_on_error: false,
                resume_store,
                extra_signed_headers,
                object_write_headers,
                tls,
                proxy,
                timeout,
                ..S3ConnectConfig::default()
            };
            if let Some(mp) = spec
                .raw_fields
                .get("s3_min_part_size")
                .and_then(|v| v.parse().ok())
            {
                s3_cfg.min_part_size = mp;
            }
            if let Some(mt) = spec
                .raw_fields
                .get("s3_multipart_threshold")
                .and_then(|v| v.parse().ok())
            {
                s3_cfg.multipart_threshold = mt;
            }

            let s3 = S3Session::connect(s3_cfg, tunnel_ssh_cfg.as_ref(), tunnel_local_port)
                .await
                .map_err(|e| e.to_string())?;
            Box::new(s3)
        }
        ProtocolScheme::Local => {
            return Err("Local sessions cannot be opened as remote network sessions.".to_string());
        }
    };

    if let Err(err) = session.probe_endpoint(&spec.session.initial_dir).await {
        let _ = session.close().await;
        return Err(err.to_string());
    }

    Ok(session)
}

/// Opens a direct (or jump-tunneled) SSH connection for `-shell` or `terminal`.
#[allow(clippy::too_many_arguments)]
pub async fn connect_ssh_for_shell(
    spec: &ParsedSiteSpec,
    config_dir: &Path,
    interactive_confirm: bool,
    interactive_auth: bool,
    locale: &str,
    log_level: i32,
    ssh_log_sink: Option<SshEventLogger>,
) -> Result<(SshConnection, Option<SshJumpTunnel>), String> {
    if !is_ssh_scheme(spec.session.protocol) {
        return Err(format!(
            "Interactive SSH shell is not supported for {} protocol.",
            spec.session.protocol.as_str().to_uppercase()
        ));
    }
    validate_ssh_gssapi_policy(spec)?;
    let proxy = build_proxy_config(spec)?;
    let (mut dest_ssh_cfg, tunnel_ssh_cfg, tunnel_local_port) = build_ssh_configs(
        spec,
        config_dir,
        interactive_confirm,
        interactive_auth,
        locale,
        log_level,
        ssh_log_sink,
        proxy,
    );

    if let Some(tun_cfg) = tunnel_ssh_cfg {
        let jump = SshJumpTunnel::connect(tun_cfg)
            .await
            .map_err(|e| e.to_string())?;
        dest_ssh_cfg.proxy = None;
        let stream = match jump
            .open_destination_stream(&dest_ssh_cfg.host, dest_ssh_cfg.port, tunnel_local_port)
            .await
        {
            Ok(s) => s,
            Err(e) => {
                let _ = jump.close().await;
                return Err(e.to_string());
            }
        };
        let conn = match SshConnection::connect_over_stream(&dest_ssh_cfg, stream).await {
            Ok(c) => c,
            Err(e) => {
                let _ = jump.close().await;
                return Err(e.to_string());
            }
        };
        Ok((conn, Some(jump)))
    } else {
        let conn = SshConnection::connect(&dest_ssh_cfg)
            .await
            .map_err(|e| e.to_string())?;
        Ok((conn, None))
    }
}

pub fn collect_s3_object_write_headers(
    raw_fields: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut hdrs = BTreeMap::new();
    if let Some(sc) = raw_fields.get("s3_storage_class").filter(|s| !s.is_empty()) {
        hdrs.insert("x-amz-storage-class".to_string(), sc.clone());
    }
    if let Some(acl) = raw_fields.get("s3_acl").filter(|s| !s.is_empty()) {
        hdrs.insert("x-amz-acl".to_string(), acl.clone());
    }
    if let Some(sse) = raw_fields.get("s3_sse_algorithm").filter(|s| !s.is_empty()) {
        hdrs.insert("x-amz-server-side-encryption".to_string(), sse.clone());
    }
    if let Some(kms) = raw_fields
        .get("s3_sse_kms_key_id")
        .filter(|s| !s.is_empty())
    {
        hdrs.insert(
            "x-amz-server-side-encryption-aws-kms-key-id".to_string(),
            kms.clone(),
        );
    }
    if let Some(meta) = raw_fields.get("s3_metadata").filter(|s| !s.is_empty()) {
        for item in meta.split(';') {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            if let Some((mk, mv)) = item.split_once('=') {
                let clean_k = mk.trim().to_ascii_lowercase();
                if !clean_k.is_empty() {
                    let full_k = if clean_k.starts_with("x-amz-meta-") {
                        clean_k
                    } else {
                        format!("x-amz-meta-{clean_k}")
                    };
                    hdrs.insert(full_k, mv.trim().to_string());
                }
            }
        }
    }
    hdrs
}

fn make_ssh_host_key_callback(
    is_tunnel: bool,
    pinned_hostkey: String,
    config_dir: std::path::PathBuf,
    interactive_confirm: bool,
    locale: String,
) -> HostKeyDecisionCallback {
    Arc::new(move |obs: &ObservedServerHostKey| -> Result<(), ProtoError> {
        let prefix = if is_tunnel { "TUNNELHOSTKEY" } else { "HOSTKEY" };
        let role = if is_tunnel { "tunnel" } else { "destination" };
        let cache_path = config_dir.join("sshhostkeys");
        let mut cache = HostKeyCache::load_from_path(&cache_path).unwrap_or_default();
        let cached_fp = cache
            .lookup(&obs.host, obs.port, &obs.key_type)
            .map(str::to_string);

        let pin = pinned_hostkey.trim();
        if pin == "*" {
            if should_emit_wildcard_hostkey(prefix, &obs.host, obs.port, &obs.sha256_fingerprint) {
                println!("{prefix} {} {}", obs.key_type, obs.sha256_fingerprint);
                let _ = std::io::stdout().flush();
                if cached_fp.is_none() {
                    let _ = writeln!(
                        std::io::stderr(),
                        "WARNING! Giving up security and accepting any host key as configured!"
                    );
                }
            }
            return Ok(());
        }

        if !pin.is_empty() {
            if matches_extended_ssh_pin(pin, obs) {
                if cache_pinned_hostkeys_enabled() {
                    let _ = cache.upsert(
                        &obs.host,
                        obs.port,
                        &obs.key_type,
                        &obs.sha256_fingerprint,
                    );
                    let _ = cache.save_to_path(&cache_path);
                }
                return Ok(());
            }
            println!("{prefix} {} {}", obs.key_type, obs.sha256_fingerprint);
            println!("HOSTKEYSTATE {role} changed");
            let _ = std::io::stdout().flush();
            let port_s = obs.port.to_string();
            let msg = translate_with(
                CatalogDomain::Cli,
                &locale,
                "The host key of {host} (port {port}) is not the expected one.\n  {type} key fingerprint: {fingerprint}\n  expected fingerprint:           {expected}\nThe connection may be intercepted; refusing to continue.",
                &[
                    ("host", &obs.host),
                    ("port", &port_s),
                    ("type", &obs.key_type),
                    ("fingerprint", &obs.sha256_fingerprint),
                    ("expected", pin),
                ],
            );
            return Err(ProtoError::Transport(msg));
        }

        match cached_fp {
            Some(ref c) if c == &obs.sha256_fingerprint => Ok(()),
            Some(expected_fp) => {
                println!("{prefix} {} {}", obs.key_type, obs.sha256_fingerprint);
                println!("HOSTKEYSTATE {role} changed");
                let _ = std::io::stdout().flush();
                if interactive_confirm {
                    let prompt = format!(
                        "WARNING - POTENTIAL SECURITY BREACH! The {} server's host key ({} {}) does not match cached key ({expected_fp}). Update cached key? (y/n): ",
                        obs.host, obs.key_type, obs.sha256_fingerprint
                    );
                    if prompt_yes_no_tty(&prompt, &locale) {
                        let _ = cache.upsert(
                            &obs.host,
                            obs.port,
                            &obs.key_type,
                            &obs.sha256_fingerprint,
                        );
                        let _ = cache.save_to_path(&cache_path);
                        return Ok(());
                    }
                }
                let port_s = obs.port.to_string();
                let msg = translate_with(
                    CatalogDomain::Cli,
                    &locale,
                    "The host key of {host} (port {port}) does not match the cached key.\n  {type} key fingerprint: {fingerprint}\nThe connection may be intercepted; refusing to continue.",
                    &[
                        ("host", &obs.host),
                        ("port", &port_s),
                        ("type", &obs.key_type),
                        ("fingerprint", &obs.sha256_fingerprint),
                    ],
                );
                Err(ProtoError::Transport(msg))
            }
            None => {
                println!("{prefix} {} {}", obs.key_type, obs.sha256_fingerprint);
                let _ = std::io::stdout().flush();
                if interactive_confirm {
                    let prompt = format!(
                        "The server's host key is not cached ({} {}). Continue connecting and add host key to the cache? (y/n): ",
                        obs.key_type, obs.sha256_fingerprint
                    );
                    if prompt_yes_no_tty(&prompt, &locale) {
                        let _ = cache.upsert(
                            &obs.host,
                            obs.port,
                            &obs.key_type,
                            &obs.sha256_fingerprint,
                        );
                        let _ = cache.save_to_path(&cache_path);
                        return Ok(());
                    }
                }
                if is_tunnel {
                    Err(ProtoError::Transport(format!(
                        "Unknown tunnel SSH host key for {}:{} ({}); verify and pass -rawsettings TunnelHostKey=\"{}\".",
                        obs.host, obs.port, obs.sha256_fingerprint, obs.sha256_fingerprint
                    )))
                } else {
                    Err(ProtoError::Transport(format!(
                        "The server's host key is not cached ({} {}). Verify the fingerprint and pass -hostkey=\"{}\".",
                        obs.key_type, obs.sha256_fingerprint, obs.sha256_fingerprint
                    )))
                }
            }
        }
    })
}

pub fn prompt_yes_no_tty(prompt: &str, locale: &str) -> bool {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(
        linscp_i18n::parse_confirmation_answer(locale, false, &line),
        Some(true)
    )
}

/// Resolves credentials from `LINSCP_PASSWORD` / `LINSCP_TUNNEL_PASSWORD` / `AWS_SECRET_ACCESS_KEY`
/// when not already supplied on the command line or stored site.
pub fn apply_env_credential_fallbacks(spec: &mut ParsedSiteSpec) {
    if spec.session.password.is_none() {
        if let Ok(pw) = std::env::var("LINSCP_PASSWORD") {
            if !pw.is_empty() {
                spec.session.password = Some(pw);
            }
        }
    }
    if spec.session.protocol == ProtocolScheme::S3 {
        if spec.session.username.is_empty() {
            if let Ok(ak) = std::env::var("AWS_ACCESS_KEY_ID") {
                spec.session.username = ak;
            }
        }
        if spec.session.password.is_none() {
            if let Ok(sk) = std::env::var("AWS_SECRET_ACCESS_KEY") {
                spec.session.password = Some(sk);
            }
        }
    }
    if let Some(ref mut tun) = spec.session.tunnel {
        if tun.password.is_none() {
            if let Ok(tpw) = std::env::var("LINSCP_TUNNEL_PASSWORD") {
                if !tpw.is_empty() {
                    tun.password = Some(tpw);
                }
            }
        }
    }
}

pub struct DefaultOsVault;

impl SecretVault for DefaultOsVault {
    fn load_master_key(
        &self,
        config_dir: &Path,
    ) -> Result<Option<Zeroizing<[u8; 32]>>, linscp_platform::PlatformError> {
        linscp_platform::NativeSecretVault::new().load_master_key(config_dir)
    }

    fn load_or_create_master_key(
        &self,
        config_dir: &Path,
    ) -> Result<Zeroizing<[u8; 32]>, linscp_platform::PlatformError> {
        linscp_platform::NativeSecretVault::new().load_or_create_master_key(config_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parser_enforces_schemes_ipv6_brackets_and_percent_encoding() {
        let s = parse_site_url("ftps://alice:pw@example.com/pub").unwrap();
        assert_eq!(s.session.protocol, ProtocolScheme::Ftps);
        assert_eq!(s.session.port, 990);

        let e = parse_site_url("ftpes://alice@example.com/").unwrap();
        assert_eq!(e.session.port, 21);
        assert_eq!(e.raw_fields.get("ftps").map(String::as_str), Some("3"));

        assert!(parse_site_url("sftp://u@1:pw@example.com/").is_err());
        assert!(parse_site_url("sftp://::1/").is_err());
        assert!(parse_site_url("sftp://[::1]:2222/dir").is_ok());
        assert!(parse_site_url("https://example.com/path?x=1").is_err());
    }
}
