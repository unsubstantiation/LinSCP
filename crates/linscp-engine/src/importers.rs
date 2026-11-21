//! OpenSSH `~/.ssh/config` and FileZilla `sitemanager.xml` session importers.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use linscp_types::{ImportReport, ImportedSite, ProtocolScheme, SkippedImportEntry};

const MAX_IMPORT_ENTRIES: usize = 500;
const MAX_XML_BYTES: usize = 2 * 1024 * 1024;
const MAX_INCLUDE_DEPTH: usize = 3;
const MAX_INCLUDE_FILES: usize = 64;
const MAX_INCLUDE_FILE_BYTES: u64 = 256 * 1024;

fn has_control_char(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

fn split_ssh_config_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        if ch == '#' && !in_quotes {
            break;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if !in_quotes && ch.is_ascii_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn expand_tilde(raw: &str, home_dir: Option<&Path>) -> String {
    if let (Some(rest), Some(home)) = (raw.strip_prefix("~/"), home_dir) {
        return home.join(rest).to_string_lossy().into_owned();
    }
    raw.to_string()
}

fn expand_openssh_tokens(
    raw: &str,
    alias: &str,
    host: &str,
    port: u16,
    user: &str,
    home_dir: Option<&Path>,
) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    let effective_user = if user.is_empty() {
        std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_default()
    } else {
        user.to_string()
    };
    while let Some(ch) = chars.next() {
        if ch == '%' {
            match chars.peek().copied() {
                Some('%') => {
                    chars.next();
                    out.push('%');
                }
                Some('h') => {
                    chars.next();
                    out.push_str(host);
                }
                Some('n') => {
                    chars.next();
                    out.push_str(alias);
                }
                Some('p') => {
                    chars.next();
                    out.push_str(&port.to_string());
                }
                Some('r') if !effective_user.is_empty() => {
                    chars.next();
                    out.push_str(&effective_user);
                }
                Some('d') if home_dir.is_some() => {
                    chars.next();
                    out.push_str(&home_dir.unwrap().to_string_lossy());
                }
                _ => out.push('%'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn simple_glob_matches(pattern: &str, candidate: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let c: Vec<char> = candidate.chars().collect();
    let (mut pi, mut ci) = (0usize, 0usize);
    let (mut star_pi, mut star_ci) = (None::<usize>, 0usize);
    while ci < c.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == c[ci]) {
            pi += 1;
            ci += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = Some(pi);
            pi += 1;
            star_ci = ci;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ci += 1;
            ci = star_ci;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn resolve_ssh_include_files(
    patterns: &[String],
    home_dir: Option<&Path>,
    included_budget: &mut usize,
) -> Vec<String> {
    let Some(home) = home_dir else {
        return Vec::new();
    };
    let Ok(canon_home) = std::fs::canonicalize(home) else {
        return Vec::new();
    };
    let ssh_dir = home.join(".ssh");
    let mut contents = Vec::new();
    for raw_pat in patterns {
        if *included_budget >= MAX_INCLUDE_FILES || has_control_char(raw_pat) {
            break;
        }
        let expanded = if raw_pat.starts_with("~/") {
            home.join(&raw_pat[2..])
        } else {
            let p = Path::new(raw_pat);
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                ssh_dir.join(p)
            }
        };
        let Some(file_pat) = expanded.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(parent_dir) = expanded.parent() else {
            continue;
        };
        if parent_dir.to_string_lossy().contains(['*', '?']) {
            continue;
        }
        let Ok(canon_parent) = std::fs::canonicalize(parent_dir) else {
            continue;
        };
        if !canon_parent.starts_with(&canon_home) {
            continue;
        }
        let mut matched_paths = Vec::new();
        if file_pat.contains(['*', '?']) {
            let Ok(entries) = std::fs::read_dir(&canon_parent) else {
                continue;
            };
            for entry in entries.flatten() {
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if simple_glob_matches(file_pat, &name) {
                    matched_paths.push(entry.path());
                }
            }
            matched_paths.sort();
        } else {
            matched_paths.push(canon_parent.join(file_pat));
        }
        for candidate in matched_paths {
            if *included_budget >= MAX_INCLUDE_FILES {
                break;
            }
            let Ok(meta) = std::fs::symlink_metadata(&candidate) else {
                continue;
            };
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_INCLUDE_FILE_BYTES {
                continue;
            }
            let Ok(canon_file) = std::fs::canonicalize(&candidate) else {
                continue;
            };
            if !canon_file.starts_with(&canon_home) {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&canon_file) {
                *included_budget += 1;
                contents.push(text);
            }
        }
    }
    contents
}

fn parse_proxy_jump_spec(raw: &str) -> Option<(Option<String>, String, Option<u16>)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") || has_control_char(trimmed) {
        return None;
    }
    // For comma-chained ProxyJump hops (`bastion1,bastion2`), use the final jump hop
    // directly when single-hop tunnel settings are stored; reject multi-hop chains
    // that cannot be represented faithfully by a single SSH jump tunnel.
    if trimmed.contains(',') {
        return None;
    }
    let (user_opt, host_port) = if let Some((u, rest)) = trimmed.rsplit_once('@') {
        let u = u.trim();
        ((!u.is_empty()).then(|| u.to_string()), rest.trim())
    } else {
        (None, trimmed)
    };
    let (host, port_opt) = if let Some(rest) = host_port.strip_prefix('[') {
        if let Some((ipv6, tail)) = rest.split_once(']') {
            let port = if let Some(p_str) = tail.strip_prefix(':') {
                Some(p_str.parse::<u16>().ok().filter(|p| *p > 0)?)
            } else if tail.is_empty() {
                None
            } else {
                return None;
            };
            (format!("[{ipv6}]"), port)
        } else {
            return None;
        }
    } else if host_port.matches(':').count() == 1 {
        let (h, p_str) = host_port.split_once(':').unwrap();
        let p = p_str.parse::<u16>().ok().filter(|p| *p > 0)?;
        (h.trim().to_string(), Some(p))
    } else {
        (host_port.to_string(), None)
    };
    if host.is_empty() {
        return None;
    }
    Some((user_opt, host, port_opt))
}

/// Parses an OpenSSH `~/.ssh/config` file into `ImportedSite` entries,
/// expanding multi-alias `Host` blocks, `ProxyJump`, `ProxyCommand` (`%h`/`%p`/`%r`),
/// and safe `Include` files under `home_dir`, while skipping wildcard hosts and `Match` blocks.
pub fn parse_openssh_config(text: &str, home_dir: Option<&Path>) -> ImportReport {
    #[derive(Default)]
    struct PendingBlock {
        aliases: Vec<String>,
        hostname: Option<String>,
        user: Option<String>,
        port: Option<String>,
        identity_file: Option<String>,
        proxy_jump: Option<String>,
        proxy_command: Option<String>,
    }

    fn flush_block(
        blk: Option<PendingBlock>,
        home_dir: Option<&Path>,
        out: &mut ImportReport,
    ) {
        let Some(block) = blk else { return };
        for alias in block.aliases {
            if out.imported.len() >= MAX_IMPORT_ENTRIES {
                return;
            }
            let raw_host = block
                .hostname
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(&alias);
            let host = expand_openssh_tokens(raw_host, &alias, &alias, 22, "", home_dir);
            if host.is_empty() || has_control_char(&host) || host.contains('%') {
                out.skipped.push(SkippedImportEntry {
                    label: alias,
                    reason: "Invalid HostName".to_string(),
                });
                continue;
            }
            let port = match block.port.as_deref() {
                None | Some("") => 22u16,
                Some(raw_p) => match raw_p.parse::<u16>() {
                    Ok(p) if p > 0 => p,
                    _ => {
                        out.skipped.push(SkippedImportEntry {
                            label: alias,
                            reason: format!("Invalid Port: {raw_p}"),
                        });
                        continue;
                    }
                },
            };
            let username = block.user.clone().unwrap_or_default();
            if has_control_char(&username) {
                out.skipped.push(SkippedImportEntry {
                    label: alias,
                    reason: "Invalid User".to_string(),
                });
                continue;
            }
            let mut private_key = None;
            if let Some(raw_key) = block.identity_file.as_deref().filter(|s| !s.is_empty()) {
                let expanded_tok =
                    expand_openssh_tokens(raw_key, &alias, &host, port, &username, home_dir);
                if !expanded_tok.contains('%') {
                    let expanded = expand_tilde(&expanded_tok, home_dir);
                    if !has_control_char(&expanded) {
                        private_key = Some(expanded);
                    }
                }
            }
            let mut tunnel_host = None;
            let mut tunnel_port = None;
            let mut tunnel_username = None;
            let mut tunnel_private_key = None;
            if let Some(ref pj) = block.proxy_jump {
                if !pj.trim().eq_ignore_ascii_case("none") && !pj.trim().is_empty() {
                    if let Some((pj_user, pj_host, pj_port)) = parse_proxy_jump_spec(pj) {
                        // Resolve against an already-imported Host alias if ProxyJump names one.
                        if let Some(jump_site) = out.imported.iter().find(|s| s.name == pj_host) {
                            tunnel_host = Some(jump_site.host.clone());
                            tunnel_port = Some(pj_port.unwrap_or(jump_site.port));
                            let eff_u = pj_user.unwrap_or_else(|| jump_site.username.clone());
                            if !eff_u.is_empty() {
                                tunnel_username = Some(eff_u);
                            }
                            tunnel_private_key = jump_site.private_key.clone();
                        } else {
                            tunnel_host = Some(pj_host);
                            tunnel_port = Some(pj_port.unwrap_or(22));
                            tunnel_username = pj_user;
                        }
                    } else {
                        out.skipped.push(SkippedImportEntry {
                            label: format!("{alias} (ProxyJump {pj})"),
                            reason: "Unsupported multi-hop or malformed ProxyJump".to_string(),
                        });
                    }
                }
            }
            let proxy_command = block
                .proxy_command
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("none"))
                .map(|raw_cmd| {
                    expand_openssh_tokens(raw_cmd, &alias, &host, port, &username, home_dir)
                })
                .filter(|cmd| !has_control_char(cmd));

            out.imported.push(ImportedSite {
                source: "openssh".to_string(),
                name: alias,
                protocol: ProtocolScheme::Sftp,
                host,
                port,
                username,
                password: None,
                private_key,
                remote_directory: String::new(),
                local_directory: String::new(),
                tunnel_host,
                tunnel_port,
                tunnel_username,
                tunnel_private_key,
                proxy_command,
            });
        }
    }

    fn parse_text_recursive(
        text: &str,
        home_dir: Option<&Path>,
        depth: usize,
        included_budget: &mut usize,
        current: &mut Option<PendingBlock>,
        report: &mut ImportReport,
    ) {
        for raw_line in text.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, val_tokens) = if let Some((lhs, rhs)) = line.split_once('=') {
                let k = lhs.trim();
                if !k.contains(char::is_whitespace) {
                    (k.to_ascii_lowercase(), split_ssh_config_tokens(rhs))
                } else {
                    let mut toks = split_ssh_config_tokens(line);
                    if toks.len() < 2 {
                        continue;
                    }
                    let first = toks.remove(0).to_ascii_lowercase();
                    (first, toks)
                }
            } else {
                let mut toks = split_ssh_config_tokens(line);
                if toks.len() < 2 {
                    continue;
                }
                let first = toks.remove(0).to_ascii_lowercase();
                (first, toks)
            };
            if val_tokens.is_empty() {
                continue;
            }

            match key.as_str() {
                "host" => {
                    flush_block(current.take(), home_dir, report);
                    let mut plain = Vec::new();
                    let mut skipped_patterns = Vec::new();
                    for tok in &val_tokens {
                        if tok.contains(['*', '?', '!']) || has_control_char(tok) {
                            skipped_patterns.push(tok.clone());
                        } else {
                            plain.push(tok.clone());
                        }
                    }
                    if !skipped_patterns.is_empty() {
                        report.skipped.push(SkippedImportEntry {
                            label: skipped_patterns.join(" "),
                            reason: "Wildcard or negated Host pattern".to_string(),
                        });
                    }
                    if !plain.is_empty() {
                        *current = Some(PendingBlock {
                            aliases: plain,
                            ..PendingBlock::default()
                        });
                    }
                }
                "match" => {
                    flush_block(current.take(), home_dir, report);
                    report.skipped.push(SkippedImportEntry {
                        label: format!("Match {}", val_tokens.join(" ")),
                        reason: "Conditional Match blocks are not supported".to_string(),
                    });
                }
                "include" => {
                    if depth < MAX_INCLUDE_DEPTH {
                        let included =
                            resolve_ssh_include_files(&val_tokens, home_dir, included_budget);
                        if !included.is_empty() {
                            for sub_text in included {
                                parse_text_recursive(
                                    &sub_text,
                                    home_dir,
                                    depth + 1,
                                    included_budget,
                                    current,
                                    report,
                                );
                            }
                            continue;
                        }
                    }
                    report.skipped.push(SkippedImportEntry {
                        label: format!("Include {}", val_tokens.join(" ")),
                        reason: "Include directives matched no readable files under ~/.ssh"
                            .to_string(),
                    });
                }
                "hostname" => {
                    if let Some(blk) = current.as_mut() {
                        blk.hostname.get_or_insert_with(|| val_tokens[0].clone());
                    }
                }
                "user" => {
                    if let Some(blk) = current.as_mut() {
                        blk.user.get_or_insert_with(|| val_tokens[0].clone());
                    }
                }
                "port" => {
                    if let Some(blk) = current.as_mut() {
                        blk.port.get_or_insert_with(|| val_tokens[0].clone());
                    }
                }
                "identityfile" => {
                    if let Some(blk) = current.as_mut() {
                        blk.identity_file
                            .get_or_insert_with(|| val_tokens.join(" "));
                    }
                }
                "proxyjump" => {
                    if let Some(blk) = current.as_mut() {
                        blk.proxy_jump
                            .get_or_insert_with(|| val_tokens.join(" "));
                    }
                }
                "proxycommand" => {
                    if let Some(blk) = current.as_mut() {
                        blk.proxy_command
                            .get_or_insert_with(|| val_tokens.join(" "));
                    }
                }
                _ => {}
            }
        }
    }

    let mut report = ImportReport::default();
    let mut current: Option<PendingBlock> = None;
    let mut included_budget = 0usize;
    parse_text_recursive(
        text,
        home_dir,
        0,
        &mut included_budget,
        &mut current,
        &mut report,
    );
    flush_block(current, home_dir, &mut report);
    report
}

/// Decodes FileZilla's length-prefixed `<RemoteDir>` format
/// (`"1 0 3 srv 4 data"` -> `"/srv/data"`).
pub fn decode_filezilla_remote_dir(encoded: &str) -> String {
    let trimmed = encoded.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let parts: Vec<&str> = trimmed.split(' ').collect();
    if parts.len() < 3 {
        return String::new();
    }
    let Ok(prefix_len) = parts[1].parse::<usize>() else {
        return String::new();
    };
    let mut idx = 2usize;
    if prefix_len > 0 {
        idx += 1;
    }
    let mut segments = Vec::new();
    while idx + 1 < parts.len() {
        let Ok(seg_len) = parts[idx].parse::<usize>() else {
            break;
        };
        idx += 1;
        let mut seg = parts[idx].to_string();
        while seg.chars().count() < seg_len && idx + 1 < parts.len() {
            idx += 1;
            seg.push(' ');
            seg.push_str(parts[idx]);
        }
        segments.push(seg);
        idx += 1;
    }
    if segments.is_empty() {
        String::new()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn element_text(node: roxmltree::Node<'_, '_>) -> String {
    node.children()
        .filter(|c| c.is_text())
        .filter_map(|c| c.text())
        .collect::<String>()
        .trim()
        .to_string()
}

fn child_text(parent: roxmltree::Node<'_, '_>, tag: &str) -> String {
    parent
        .children()
        .find(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case(tag))
        .map(element_text)
        .unwrap_or_default()
}

/// Parses a FileZilla `sitemanager.xml` export while blocking XXE (`<!DOCTYPE` /
/// `<!ENTITY`) and mapping protocols (`0`->`ftp`, `1`->`sftp`, `3`->`ftpes`, `4`->`ftps`).
pub fn parse_filezilla_xml(text: &str) -> Result<ImportReport, String> {
    if text.len() > MAX_XML_BYTES {
        return Err("XML file exceeds 2 MiB safety limit".to_string());
    }
    let lower_head = text.to_ascii_lowercase();
    if lower_head.contains("<!doctype") || lower_head.contains("<!entity") {
        return Err("DOCTYPE and ENTITY declarations are not allowed in FileZilla XML".to_string());
    }
    let doc = roxmltree::Document::parse(text)
        .map_err(|err| format!("Invalid XML syntax: {err}"))?;
    let root = doc.root_element();
    let root_tag = root.tag_name().name();
    if !root_tag.eq_ignore_ascii_case("FileZilla3")
        && !root_tag.eq_ignore_ascii_case("FileZillaServer")
    {
        return Err(format!("Not a FileZilla Site Manager export (<{root_tag}>)"));
    }

    let mut report = ImportReport::default();
    for server in doc
        .descendants()
        .filter(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("Server"))
    {
        if report.imported.len() >= MAX_IMPORT_ENTRIES {
            break;
        }
        let host = child_text(server, "Host");
        let name = {
            let n = child_text(server, "Name");
            if n.is_empty() {
                host.clone()
            } else {
                n
            }
        };
        if host.is_empty() || has_control_char(&host) || has_control_char(&name) {
            report.skipped.push(SkippedImportEntry {
                label: if name.is_empty() { "(unnamed)".to_string() } else { name },
                reason: "Missing or invalid Host".to_string(),
            });
            continue;
        }

        let proto_code = child_text(server, "Protocol");
        let protocol = match proto_code.as_str() {
            "" | "0" => ProtocolScheme::Ftp,
            "1" => ProtocolScheme::Sftp,
            "3" => ProtocolScheme::Ftpes,
            "4" => ProtocolScheme::Ftps,
            other => {
                report.skipped.push(SkippedImportEntry {
                    label: name,
                    reason: format!("Unsupported FileZilla Protocol code: {other}"),
                });
                continue;
            }
        };

        let port_raw = child_text(server, "Port");
        let port = if port_raw.is_empty() {
            protocol.default_port()
        } else {
            match port_raw.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => {
                    report.skipped.push(SkippedImportEntry {
                        label: name,
                        reason: format!("Invalid Port: {port_raw}"),
                    });
                    continue;
                }
            }
        };

        let logon_type = child_text(server, "Logontype");
        let mut username = child_text(server, "User");
        if username.is_empty() && (logon_type == "0" || protocol == ProtocolScheme::Ftp) {
            username = "anonymous".to_string();
        }
        if has_control_char(&username) {
            report.skipped.push(SkippedImportEntry {
                label: name,
                reason: "Invalid User".to_string(),
            });
            continue;
        }

        let mut password = None;
        if let Some(pass_el) = server
            .children()
            .find(|n| n.is_element() && n.tag_name().name().eq_ignore_ascii_case("Pass"))
        {
            let enc = pass_el
                .attribute("encoding")
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            let raw_pass = element_text(pass_el);
            if !raw_pass.is_empty() {
                password = match enc.as_str() {
                    "base64" => BASE64
                        .decode(raw_pass.as_bytes())
                        .ok()
                        .and_then(|bytes| String::from_utf8(bytes).ok()),
                    "crypt" => None,
                    _ => Some(raw_pass),
                };
            }
        }

        let keyfile = child_text(server, "Keyfile");
        let private_key = if !keyfile.is_empty() && !has_control_char(&keyfile) {
            Some(keyfile)
        } else {
            None
        };
        let remote_dir = decode_filezilla_remote_dir(&child_text(server, "RemoteDir"));
        let local_dir = child_text(server, "LocalDir");

        report.imported.push(ImportedSite {
            source: "filezilla".to_string(),
            name,
            protocol,
            host,
            port,
            username,
            password,
            private_key,
            remote_directory: if has_control_char(&remote_dir) {
                String::new()
            } else {
                remote_dir
            },
            local_directory: if has_control_char(&local_dir) {
                String::new()
            } else {
                local_dir
            },
            tunnel_host: None,
            tunnel_port: None,
            tunnel_username: None,
            tunnel_private_key: None,
            proxy_command: None,
        });
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssh_importer_imports_plain_hosts_and_skips_wildcards_and_match() {
        let cfg = "\
            Include ~/.ssh/conf.d/*.conf\n\
            Host *\n\
              ServerAliveInterval 30\n\
            Host prod-db\n\
              HostName 10.20.30.40\n\
              User postgres\n\
              Port 2222\n\
              IdentityFile ~/.ssh/id_ed25519\n\
            Match host *.corp\n\
              User jump\n";
        let home = Path::new("/home/alice");
        let report = parse_openssh_config(cfg, Some(home));
        assert_eq!(report.imported.len(), 1);
        let site = &report.imported[0];
        assert_eq!(site.name, "prod-db");
        assert_eq!(site.host, "10.20.30.40");
        assert_eq!(site.port, 2222);
        assert_eq!(site.username, "postgres");
        let expected_key = home.join(".ssh/id_ed25519").to_string_lossy().into_owned();
        assert_eq!(site.private_key.as_deref(), Some(expected_key.as_str()));
        assert_eq!(report.skipped.len(), 3);
    }

    #[test]
    fn openssh_importer_expands_multi_alias_proxy_jump_tokens_and_safe_includes() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let conf_d = home.join(".ssh").join("conf.d");
        std::fs::create_dir_all(&conf_d).unwrap();
        std::fs::write(
            conf_d.join("included.conf"),
            "Host bastion\n  HostName 203.0.113.5\n  User jump\n  Port 2200\n",
        )
        .unwrap();
        let cfg = "\
            Include ~/.ssh/conf.d/*.conf\n\
            Host app-a app-b\n\
              HostName %n.internal.example\n\
              User deploy\n\
              Port 2222\n\
              ProxyJump bastion\n\
              ProxyCommand ssh -W %h:%p gateway.example\n";
        let report = parse_openssh_config(cfg, Some(home));
        assert!(report.skipped.is_empty(), "{:?}", report.skipped);
        assert_eq!(report.imported.len(), 3);
        assert_eq!(report.imported[0].name, "bastion");
        let app_a = report.imported.iter().find(|s| s.name == "app-a").unwrap();
        assert_eq!(app_a.host, "app-a.internal.example");
        assert_eq!(app_a.tunnel_host.as_deref(), Some("203.0.113.5"));
        assert_eq!(app_a.tunnel_port, Some(2200));
        assert_eq!(app_a.tunnel_username.as_deref(), Some("jump"));
        assert_eq!(
            app_a.proxy_command.as_deref(),
            Some("ssh -W app-a.internal.example:2222 gateway.example")
        );
        let app_b = report.imported.iter().find(|s| s.name == "app-b").unwrap();
        assert_eq!(app_b.host, "app-b.internal.example");
        assert_eq!(app_b.tunnel_host.as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn filezilla_parser_handles_multibyte_boundary_and_late_doctype() {
        let xml = format!("<!--{}é--><FileZilla3/>", "a".repeat(8187));
        assert!(parse_filezilla_xml(&xml).is_ok());
        let xxe = format!("{}<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><FileZilla3/>", " ".repeat(9000));
        assert!(parse_filezilla_xml(&xxe).is_err());
    }

    #[test]
    fn filezilla_importer_blocks_xxe_and_decodes_base64_pass_and_remote_dir() {
        let xxe = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><FileZilla3/>";
        assert!(parse_filezilla_xml(xxe).is_err());

        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.66.5" platform="linux">
  <Servers>
    <Server>
      <Host>files.example.com</Host>
      <Port>21</Port>
      <Protocol>3</Protocol>
      <User>deploy</User>
      <Pass encoding="base64">c2VjcmV0</Pass>
      <Name>Prod FTPES</Name>
      <RemoteDir>1 0 3 srv 9 my folder</RemoteDir>
      <LocalDir>/tmp/uploads</LocalDir>
    </Server>
  </Servers>
</FileZilla3>"#;
        let report = parse_filezilla_xml(xml).expect("parse FileZilla XML");
        assert_eq!(report.imported.len(), 1);
        let site = &report.imported[0];
        assert_eq!(site.name, "Prod FTPES");
        assert_eq!(site.protocol, ProtocolScheme::Ftpes);
        assert_eq!(site.port, 21);
        assert_eq!(site.password.as_deref(), Some("secret"));
        assert_eq!(site.remote_directory, "/srv/my folder");
        assert_eq!(site.local_directory, "/tmp/uploads");
    }
}
