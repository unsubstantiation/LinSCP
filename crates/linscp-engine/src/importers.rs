//! OpenSSH `~/.ssh/config` and FileZilla `sitemanager.xml` session importers,
//! matching the validation and security rules in `source/gui/linscp_gui.py`.

use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use linscp_types::{ImportReport, ImportedSite, ProtocolScheme, SkippedImportEntry};

const MAX_IMPORT_ENTRIES: usize = 500;
const MAX_XML_BYTES: usize = 2 * 1024 * 1024;

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

/// Parses an OpenSSH `~/.ssh/config` file into `ImportedSite` entries,
/// skipping wildcard hosts, `Match` blocks, `Include` directives, and `%` tokens.
pub fn parse_openssh_config(text: &str, home_dir: Option<&Path>) -> ImportReport {
    let mut report = ImportReport::default();

    struct PendingBlock {
        alias: String,
        hostname: Option<String>,
        user: Option<String>,
        port: Option<String>,
        identity_file: Option<String>,
    }

    let mut current: Option<PendingBlock> = None;

    let flush_block = |blk: Option<PendingBlock>, out: &mut ImportReport| {
        let Some(block) = blk else { return };
        if out.imported.len() >= MAX_IMPORT_ENTRIES {
            return;
        }
        let host = block
            .hostname
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&block.alias)
            .to_string();
        if host.is_empty() || has_control_char(&host) {
            out.skipped.push(SkippedImportEntry {
                label: block.alias,
                reason: "Invalid HostName".to_string(),
            });
            return;
        }
        let port = match block.port.as_deref() {
            None | Some("") => 22u16,
            Some(raw_p) => match raw_p.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => {
                    out.skipped.push(SkippedImportEntry {
                        label: block.alias,
                        reason: format!("Invalid Port: {raw_p}"),
                    });
                    return;
                }
            },
        };
        let username = block.user.unwrap_or_default();
        if has_control_char(&username) {
            out.skipped.push(SkippedImportEntry {
                label: block.alias,
                reason: "Invalid User".to_string(),
            });
            return;
        }
        let mut private_key = None;
        if let Some(raw_key) = block.identity_file.filter(|s| !s.is_empty()) {
            if raw_key.contains('%') {
                // Match linscp_gui.py: ignore OpenSSH %-tokens without aborting the host
            } else {
                let expanded = expand_tilde(&raw_key, home_dir);
                if !has_control_char(&expanded) {
                    private_key = Some(expanded);
                }
            }
        }
        out.imported.push(ImportedSite {
            source: "openssh".to_string(),
            name: block.alias,
            protocol: ProtocolScheme::Sftp,
            host,
            port,
            username,
            password: None,
            private_key,
            remote_directory: String::new(),
            local_directory: String::new(),
        });
    };

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
                flush_block(current.take(), &mut report);
                let plain: Vec<&String> = val_tokens
                    .iter()
                    .filter(|p| !p.contains(['*', '?', '!']))
                    .collect();
                if plain.len() == 1 && val_tokens.len() == 1 && !has_control_char(plain[0]) {
                    current = Some(PendingBlock {
                        alias: plain[0].clone(),
                        hostname: None,
                        user: None,
                        port: None,
                        identity_file: None,
                    });
                } else {
                    report.skipped.push(SkippedImportEntry {
                        label: val_tokens.join(" "),
                        reason: "Wildcard or multi-pattern Host block".to_string(),
                    });
                }
            }
            "match" => {
                flush_block(current.take(), &mut report);
                report.skipped.push(SkippedImportEntry {
                    label: format!("Match {}", val_tokens.join(" ")),
                    reason: "Conditional Match blocks are not supported".to_string(),
                });
            }
            "include" => {
                report.skipped.push(SkippedImportEntry {
                    label: format!("Include {}", val_tokens.join(" ")),
                    reason: "Include directives are not expanded automatically".to_string(),
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
            _ => {}
        }
    }
    flush_block(current, &mut report);
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
    let lower_head = text[..text.len().min(8192)].to_ascii_lowercase();
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
