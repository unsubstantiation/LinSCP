//! Shared transfer, synchronization, filemask, permission, session-storage,
//! host-key cache, and session-importer engine.

pub mod config_stores;
pub mod hostkeys;
pub mod importers;
pub mod session_store;

use linscp_crypto::SessionMasterKey;
use linscp_types::SessionConfig;

pub use config_stores::{BookmarksStore, PreferencesStore, WorkspacesStore};
pub use hostkeys::{format_host_port_key, CachedHostKeyEntry, HostKeyCache};
pub use importers::{decode_filezilla_remote_dir, parse_filezilla_xml, parse_openssh_config};
pub use session_store::{escape_ini_value, unescape_ini_value, SessionStore, StoredSite};

/// Standard partial-upload suffix used before atomic rename to destination.
pub fn filepart_name(target_name: &str) -> String {
    format!("{target_name}.filepart")
}

/// Evaluates LinSCP wildcard masks (`*`, `?`) with semicolon-separated
/// include patterns and optional `|` exclude patterns (`*.log;*.txt|debug*`).
pub fn filemask_matches(mask_spec: &str, name: &str, case_sensitive: bool) -> bool {
    let trimmed = mask_spec.trim();
    if trimmed.is_empty() || trimmed == "*" || trimmed == "*.*" {
        return true;
    }
    let (include_part, exclude_part) = trimmed.split_once('|').unwrap_or((trimmed, ""));
    let candidate = if case_sensitive {
        name.to_string()
    } else {
        name.to_ascii_lowercase()
    };

    for excl in exclude_part.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let pat = if case_sensitive {
            excl.to_string()
        } else {
            excl.to_ascii_lowercase()
        };
        if glob_match(pat.as_bytes(), candidate.as_bytes()) {
            return false;
        }
    }

    let includes: Vec<&str> = include_part
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if includes.is_empty() {
        return true;
    }
    includes.into_iter().any(|inc| {
        let pat = if case_sensitive {
            inc.to_string()
        } else {
            inc.to_ascii_lowercase()
        };
        glob_match(pat.as_bytes(), candidate.as_bytes())
    })
}

fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star_idx = Some(p);
            match_idx = t;
            p += 1;
        } else if let Some(star) = star_idx {
            p = star + 1;
            match_idx += 1;
            t = match_idx;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Parses an octal (`0644`, `755`) or symbolic (`u+x,go-w`) permission mode
/// against `current_mode`, matching `chmod` semantics in `Commands.cpp`.
pub fn parse_chmod_spec(spec: &str, current_mode: u32) -> Result<u32, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("Empty permission mode".to_string());
    }
    if trimmed.bytes().all(|b| (b'0'..=b'7').contains(&b)) && trimmed.len() <= 4 {
        return u32::from_str_radix(trimmed, 8).map_err(|e| e.to_string());
    }

    let mut mode = current_mode & 0o7777;
    for clause in trimmed.split(',') {
        if clause.is_empty() {
            return Err(format!("Invalid chmod clause in '{spec}'"));
        }
        let op_pos = clause
            .find(['+', '-', '='])
            .ok_or_else(|| format!("Invalid chmod clause '{clause}'"))?;
        let (who_str, rest) = clause.split_at(op_pos);
        let op = rest.as_bytes()[0] as char;
        let perms_str = &rest[1..];

        let mut who_mask = 0u32;
        if who_str.is_empty() || who_str.contains('a') {
            who_mask = 0o777;
        } else {
            for ch in who_str.chars() {
                match ch {
                    'u' => who_mask |= 0o700,
                    'g' => who_mask |= 0o070,
                    'o' => who_mask |= 0o007,
                    _ => return Err(format!("Unknown chmod subject '{ch}'")),
                }
            }
        }

        let mut bits = 0u32;
        for ch in perms_str.chars() {
            match ch {
                'r' => bits |= 0o444 & who_mask,
                'w' => bits |= 0o222 & who_mask,
                'x' => bits |= 0o111 & who_mask,
                _ => return Err(format!("Unsupported chmod permission '{ch}'")),
            }
        }

        match op {
            '+' => mode |= bits,
            '-' => mode &= !bits,
            '=' => mode = (mode & !who_mask) | bits,
            _ => unreachable!(),
        }
    }
    Ok(mode)
}

/// Convenience wrapper parsing `sessions.ini` into `SessionConfig` profiles.
pub fn parse_sessions_ini(
    ini_text: &str,
    master_key: Option<&SessionMasterKey>,
) -> Result<Vec<SessionConfig>, String> {
    let store = SessionStore::parse_ini(ini_text, master_key)?;
    Ok(store
        .sites()
        .iter()
        .map(StoredSite::to_session_config)
        .collect())
}

/// Convenience wrapper serializing `SessionConfig` profiles into `sessions.ini`.
pub fn serialize_sessions_ini(
    sessions: &[SessionConfig],
    master_key: Option<&SessionMasterKey>,
) -> Result<String, String> {
    let mut store = SessionStore::new();
    for cfg in sessions {
        store.upsert(StoredSite::from_session_config(cfg));
    }
    store.serialize_ini(master_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linscp_types::ProtocolScheme;

    #[test]
    fn filemask_supports_include_and_exclude_lists() {
        assert!(filemask_matches("*.rs;*.toml|target*", "lib.rs", true));
        assert!(!filemask_matches("*.rs;*.toml|*test*", "lib_test.rs", true));
        assert!(filemask_matches("*.LOG", "transfer.log", false));
    }

    #[test]
    fn chmod_supports_octal_and_symbolic_modes() {
        assert_eq!(parse_chmod_spec("0640", 0o777).unwrap(), 0o640);
        assert_eq!(parse_chmod_spec("u+x,go-w", 0o664).unwrap(), 0o744);
        assert_eq!(parse_chmod_spec("a=r", 0o755).unwrap(), 0o444);
    }

    #[test]
    fn sessions_ini_round_trips_encrypted_passwords() {
        let key = SessionMasterKey::from_bytes([9u8; 32]);
        let sample = vec![SessionConfig {
            name: "prod-sftp".to_string(),
            protocol: ProtocolScheme::Sftp,
            host: "10.0.0.12".to_string(),
            port: 2222,
            username: "deploy".to_string(),
            password: Some("hunter2!".to_string()),
            keyfile: None,
            hostkey: "SHA256:abc123".to_string(),
            initial_dir: "/var/www".to_string(),
            local_dir: String::new(),
            tunnel: None,
        }];
        let rendered = serialize_sessions_ini(&sample, Some(&key)).expect("serialize");
        assert!(rendered.contains("password=lscp1$"));
        assert!(!rendered.contains("hunter2!"));
        let parsed = parse_sessions_ini(&rendered, Some(&key)).expect("parse");
        assert_eq!(parsed, sample);
    }
}
