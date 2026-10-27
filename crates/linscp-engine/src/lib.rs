//! Portable transfer, mask, permission, `.filepart` staging, and `sessions.ini`
//! engine shared by CLI, HTTP server, and Tauri apps.

use std::collections::BTreeMap;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EngineError {
    #[error("Invalid permission mode '{0}'")]
    InvalidMode(String),
}

/// `.filepart` temporary name used while a download or upload is in flight.
/// When transferring a specific S3 object version, embeds a sanitized suffix so
/// distinct object versions never collide on a shared partial file.
pub fn filepart_name(base_name: &str, version_id: Option<&str>) -> String {
    match version_id.filter(|v| !v.is_empty()) {
        None => format!("{base_name}.filepart"),
        Some(ver) => {
            let safe: String = ver
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            format!("{base_name}.v-{safe}.filepart")
        }
    }
}

/// Wildcard glob matcher supporting `*` and `?` with explicit case sensitivity.
pub fn wildcard_match(pattern: &str, candidate: &str, case_insensitive: bool) -> bool {
    let pat: Vec<char> = if case_insensitive {
        pattern.chars().map(|c| c.to_ascii_lowercase()).collect()
    } else {
        pattern.chars().collect()
    };
    let text: Vec<char> = if case_insensitive {
        candidate.chars().map(|c| c.to_ascii_lowercase()).collect()
    } else {
        candidate.chars().collect()
    };

    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None::<usize>, 0usize);

    while t < text.len() {
        if p < pat.len() && (pat[p] == '?' || pat[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == '*' {
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
    while p < pat.len() && pat[p] == '*' {
        p += 1;
    }
    p == pat.len()
}

/// Evaluates a LinSCP filemask (`include1;include2 | exclude1;exclude2/`,
/// where trailing `/` restricts a token to directories).
pub fn matches_filemask(
    mask_expr: &str,
    name: &str,
    is_dir: bool,
    case_insensitive: bool,
) -> bool {
    let trimmed = mask_expr.trim();
    if trimmed.is_empty() {
        return true;
    }
    let (inc_part, exc_part) = match trimmed.split_once('|') {
        Some((inc, exc)) => (inc.trim(), exc.trim()),
        None => (trimmed, ""),
    };

    let matches_token = |token: &str| -> bool {
        let tok = token.trim();
        if tok.is_empty() {
            return false;
        }
        if let Some(dir_pat) = tok.strip_suffix('/') {
            is_dir && wildcard_match(dir_pat, name, case_insensitive)
        } else {
            wildcard_match(tok, name, case_insensitive)
        }
    };

    let include_tokens: Vec<&str> = inc_part
        .split([';', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let included = if include_tokens.is_empty() {
        true
    } else {
        include_tokens.iter().any(|tok| matches_token(tok))
    };
    if !included {
        return false;
    }

    let exclude_tokens: Vec<&str> = exc_part
        .split([';', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    !exclude_tokens.iter().any(|tok| matches_token(tok))
}

/// Parses an octal (`"755"`, `"0644"`) or symbolic (`"u+x,go-w"`, `"a=rX"`)
/// permission specification against `current_mode` and `is_dir`.
pub fn parse_chmod_mode(spec: &str, current_mode: u32, is_dir: bool) -> Result<u32, EngineError> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(EngineError::InvalidMode(spec.to_string()));
    }
    if trimmed.bytes().all(|b| (b'0'..=b'7').contains(&b)) && trimmed.len() <= 4 {
        return u32::from_str_radix(trimmed, 8)
            .map_err(|_| EngineError::InvalidMode(spec.to_string()));
    }

    let mut mode = current_mode & 0o7777;
    for clause in trimmed.split(',') {
        if clause.is_empty() {
            return Err(EngineError::InvalidMode(spec.to_string()));
        }
        let bytes = clause.as_bytes();
        let mut idx = 0;
        let mut who_mask = 0u32;
        let mut explicit_who = false;
        while idx < bytes.len() {
            match bytes[idx] {
                b'u' => {
                    who_mask |= 0o4700;
                    explicit_who = true;
                }
                b'g' => {
                    who_mask |= 0o2070;
                    explicit_who = true;
                }
                b'o' => {
                    who_mask |= 0o1007;
                    explicit_who = true;
                }
                b'a' => {
                    who_mask |= 0o7777;
                    explicit_who = true;
                }
                _ => break,
            }
            idx += 1;
        }
        if !explicit_who {
            who_mask = 0o7777;
        }
        if idx >= bytes.len() {
            return Err(EngineError::InvalidMode(spec.to_string()));
        }
        while idx < bytes.len() {
            let op = bytes[idx];
            if !matches!(op, b'+' | b'-' | b'=') {
                return Err(EngineError::InvalidMode(spec.to_string()));
            }
            idx += 1;
            let mut perm_bits = 0u32;
            while idx < bytes.len() && !matches!(bytes[idx], b'+' | b'-' | b'=') {
                match bytes[idx] {
                    b'r' => perm_bits |= 0o0444,
                    b'w' => perm_bits |= 0o0222,
                    b'x' => perm_bits |= 0o0111,
                    b'X' => {
                        if is_dir || (mode & 0o0111) != 0 {
                            perm_bits |= 0o0111;
                        }
                    }
                    b's' => perm_bits |= 0o6000,
                    b't' => perm_bits |= 0o1000,
                    _ => return Err(EngineError::InvalidMode(spec.to_string())),
                }
                idx += 1;
            }
            let effective = perm_bits & who_mask;
            match op {
                b'+' => mode |= effective,
                b'-' => mode &= !effective,
                b'=' => {
                    let clear_rwx = who_mask & 0o7777;
                    mode = (mode & !clear_rwx) | effective;
                }
                _ => unreachable!(),
            }
        }
    }
    Ok(mode)
}

/// Parses `sessions.ini` text into an ordered map of `section -> (key -> value)`.
pub fn parse_ini_sections(text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current: Option<String> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let sec = inner.trim().to_string();
            sections.entry(sec.clone()).or_default();
            current = Some(sec);
            continue;
        }
        if let (Some(sec), Some((k, v))) = (current.as_ref(), line.split_once('=')) {
            sections
                .entry(sec.clone())
                .or_default()
                .insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    sections
}

/// Serializes `section -> (key -> value)` into clean UTF-8 `.ini` format.
pub fn serialize_ini_sections(sections: &BTreeMap<String, BTreeMap<String, String>>) -> String {
    let mut out = String::new();
    for (idx, (section, kv)) in sections.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push('[');
        out.push_str(section);
        out.push_str("]\n");
        for (k, v) in kv {
            out.push_str(k);
            out.push('=');
            out.push_str(v);
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filemask_supports_include_exclude_and_case_modes() {
        assert!(matches_filemask("*.rs;*.toml | target/", "lib.rs", false, false));
        assert!(!matches_filemask("*.rs;*.toml | target/", "target", true, false));
        assert!(!matches_filemask("*.TXT", "readme.txt", false, false));
        assert!(matches_filemask("*.TXT", "readme.txt", false, true));
    }

    #[test]
    fn chmod_parser_handles_octal_and_symbolic_modes() {
        assert_eq!(parse_chmod_mode("0755", 0o600, false).unwrap(), 0o755);
        assert_eq!(parse_chmod_mode("u+x,go-w", 0o664, false).unwrap(), 0o744);
        assert_eq!(parse_chmod_mode("a+X", 0o644, false).unwrap(), 0o644);
        assert_eq!(parse_chmod_mode("a+X", 0o644, true).unwrap(), 0o755);
    }

    #[test]
    fn filepart_embeds_version_id_without_unsafe_path_chars() {
        assert_eq!(filepart_name("archive.tar.gz", None), "archive.tar.gz.filepart");
        assert_eq!(
            filepart_name("report.csv", Some("v1/2026:10")),
            "report.csv.v-v1_2026_10.filepart"
        );
    }
}
