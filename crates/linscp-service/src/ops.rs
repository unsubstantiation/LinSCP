#![allow(unused_variables, unused_imports, dead_code, clippy::all)]
//! Filesystem, editor, bounded UTF-8 search, custom-command, `command/exec`,
//! checksum, `copyid`, cleanup, and shell-upload manifest operations for `CommanderService`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use linscp_crypto::digests::{crc32_hex, md5_hex, sha1_hex, sha256_hex};
use linscp_engine::filemask::{join_remote_path, mode_from_permissions_str, FileMask};
use linscp_engine::parse_chmod_spec;
use linscp_engine::transfer::{upload_single_file, TransferFlags};
use linscp_engine::xml_log::SessionLogger;
use linscp_platform::gui_os::{create_local_symlink, format_listing_date, stat_extended};
use linscp_platform::terminal::set_local_permissions;
use linscp_platform::{create_private_dir, write_private_file_atomic};
use linscp_proto::ssh::extract_openssh_public_key_line;
use linscp_proto::{download_bytes, RemoteSession, TransferRequest};
use rand::RngCore;
use serde_json::{json, Value};

use crate::queue::remove_path_any;
use crate::tabs::TabRuntime;

pub const MAX_GUI_EDIT_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_SEARCH_DEPTH: usize = 16;
pub const MAX_SEARCH_CONTENT_FILES: usize = 200;
pub const MAX_SEARCH_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_SEARCH_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

const DEFAULT_EXPLORER_COMMANDS_JSON: &str =
    include_str!("../../../source/gui/explorer-commands.json");

/// Validates a single relative file/folder name (rejecting empty, `.`, `..`, `/`, `\`, NUL).
pub fn validate_leaf_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return Err("Invalid file or directory name.".to_string());
    }
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains('\0') {
        return Err("File name must not contain path separators or NUL bytes.".to_string());
    }
    Ok(trimmed.to_string())
}

/// Validates a relative path from directory drag-and-drop (`sub/dir/file.txt`).
pub fn validate_relative_subpath(rel: &str) -> Result<PathBuf, String> {
    let normalized = rel.replace('\\', "/");
    let mut out = PathBuf::new();
    let mut count = 0usize;
    for seg in normalized.split('/') {
        if seg.is_empty() {
            continue;
        }
        if seg == "." || seg == ".." || seg.contains('\0') {
            return Err("Relative drop path contains unsafe segments.".to_string());
        }
        out.push(seg);
        count += 1;
    }
    if count == 0 {
        return Err("Relative drop path must not be empty.".to_string());
    }
    Ok(out)
}

/// Reads a UTF-8 text file locally for the Commander editor, enforcing `MAX_GUI_EDIT_BYTES`
/// and rejecting binary files containing NUL bytes.
pub fn read_local_text_file(path: &Path, max_bytes: u64) -> Result<(String, Value), String> {
    let info = stat_extended(path).map_err(|e| format!("Cannot read '{}': {e}", path.display()))?;
    if info.is_dir {
        return Err("Cannot open a directory in the text editor.".to_string());
    }
    if info.size > max_bytes {
        return Err(format!(
            "File is too large for the built-in editor ({} bytes; maximum {} bytes).",
            info.size, max_bytes
        ));
    }
    let bytes =
        std::fs::read(path).map_err(|e| format!("Cannot read '{}': {e}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        return Err("File is too large for the built-in editor.".to_string());
    }
    if bytes.contains(&0) {
        return Err("Refusing to edit binary file containing NUL bytes.".to_string());
    }
    let content = String::from_utf8(bytes)
        .map_err(|_| "File is not valid UTF-8 binary/encoded text.".to_string())?;
    let meta_json = json!({
        "size": info.size,
        "mtime": info.mtime_secs,
        "mtime_ns": info.mtime_ns.to_string(),
        "mtime_ns_num": info.mtime_ns as i64,
        "permissions": info.permissions,
    });
    Ok((content, meta_json))
}

/// Atomically saves edited UTF-8 text to `path`, refusing symlinks and stale `expected_mtime_ns`.
pub fn write_local_text_file(
    path: &Path,
    content: &str,
    expected_mtime_ns: Option<i128>,
) -> Result<Value, String> {
    if content.len() as u64 > MAX_GUI_EDIT_BYTES {
        return Err("Edited content is too large for the built-in editor.".to_string());
    }
    let existing = stat_extended(path).ok();
    if let Some(ref info) = existing {
        if info.is_symlink {
            return Err("Refusing to overwrite a symbolic link from the editor.".to_string());
        }
        if info.is_dir {
            return Err("Cannot overwrite a directory.".to_string());
        }
        if let Some(exp) = expected_mtime_ns {
            if exp > 0 && info.mtime_ns != exp {
                return Err(
                    "The file changed while it was open in the editor; reload before saving."
                        .to_string(),
                );
            }
        }
    }

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut rnd = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut rnd);
    let tmp = parent.join(format!(
        ".linscp-edit-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));

    let write_res = (|| -> Result<(), String> {
        write_private_file_atomic(&tmp, content.as_bytes()).map_err(|e| e.to_string())?;
        if let Some(ref info) = existing {
            let _ = set_local_permissions(&tmp, info.mode);
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.flush().map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = std::fs::remove_file(&tmp);
        write_res?;
    }

    let saved = stat_extended(path).map_err(|e| e.to_string())?;
    Ok(json!({
        "size": saved.size,
        "mtime": saved.mtime_secs,
        "mtime_ns": saved.mtime_ns.to_string(),
        "mtime_ns_num": saved.mtime_ns as i64,
        "permissions": saved.permissions,
    }))
}

/// Reads a remote UTF-8 text file via `<config_root>/edit-tmp` (`0700`) for editing.
pub async fn read_remote_text_file(
    session: &dyn RemoteSession,
    remote_path: &str,
    config_root: &Path,
) -> Result<(String, Value), String> {
    let entry = session
        .stat(remote_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Remote file '{remote_path}' does not exist."))?;
    if entry.is_dir {
        return Err("Cannot open a directory in the text editor.".to_string());
    }
    if entry.size > MAX_GUI_EDIT_BYTES {
        return Err(format!(
            "Remote file is too large for the built-in editor ({} bytes; maximum {} bytes).",
            entry.size, MAX_GUI_EDIT_BYTES
        ));
    }
    let edit_tmp = config_root.join("edit-tmp");
    create_private_dir(&edit_tmp).map_err(|e| e.to_string())?;
    let bytes = download_bytes(session, remote_path, TransferRequest::default())
        .await
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_GUI_EDIT_BYTES {
        return Err("Remote file is too large for the built-in editor.".to_string());
    }
    if bytes.contains(&0) {
        return Err("Refusing to edit binary file containing NUL bytes.".to_string());
    }
    let content = String::from_utf8(bytes)
        .map_err(|_| "Remote file is not valid UTF-8 text.".to_string())?;
    let info = json!({
        "size": entry.size,
        "mtime": entry.mtime,
        "permissions": entry.permissions,
    });
    Ok((content, info))
}

/// Saves edited UTF-8 text back to `remote_path`, optionally checking `base_mtime` for conflicts.
pub async fn write_remote_text_file(
    session: &dyn RemoteSession,
    remote_path: &str,
    content: &str,
    base_mtime: Option<i64>,
    config_root: &Path,
) -> Result<Value, String> {
    if content.len() as u64 > MAX_GUI_EDIT_BYTES {
        return Err("Edited content is too large for the built-in editor.".to_string());
    }
    let existing = session.stat(remote_path).await.map_err(|e| e.to_string())?;
    if let (Some(ref entry), Some(exp_mtime)) = (&existing, base_mtime) {
        if exp_mtime > 0 && entry.mtime > 0 && entry.mtime != exp_mtime {
            return Err(
                "The remote file changed while it was open in the editor; reload before saving."
                    .to_string(),
            );
        }
    }

    let edit_tmp = config_root.join("edit-tmp");
    create_private_dir(&edit_tmp).map_err(|e| e.to_string())?;
    let mut rnd = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut rnd);
    let stage = edit_tmp.join(format!(
        "save-{}.tmp",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    write_private_file_atomic(&stage, content.as_bytes()).map_err(|e| e.to_string())?;

    let mut logger = SessionLogger::open(None, 0, false, None, None, false, "").unwrap();
    let mut flags = TransferFlags::default();
    flags.preserve_time = false;
    let upload_res = upload_single_file(session, &stage, remote_path, &flags, &mut logger, None).await;
    let _ = std::fs::remove_file(&stage);
    upload_res?;

    if let Some(ref prev) = existing {
        let mode = mode_from_permissions_str(&prev.permissions);
            let _ = session.chmod(remote_path, mode).await;
    }
    let updated = session.stat(remote_path).await.ok().flatten();
    Ok(json!({
        "size": updated.as_ref().map(|e| e.size).unwrap_or(content.len() as u64),
        "mtime": updated.as_ref().map(|e| e.mtime).unwrap_or(0),
        "permissions": updated.as_ref().map(|e| e.permissions.clone()).unwrap_or_default(),
    }))
}

#[derive(Default)]
pub struct SearchStats {
    pub matches: Vec<Value>,
    pub truncated: bool,
    pub scanned: usize,
    pub skipped: usize,
    pub bytes_scanned: u64,
}

fn find_text_line(content: &str, needle: &str, case_sensitive: bool) -> Option<(usize, String)> {
    let needle_cmp = if case_sensitive {
        needle.to_string()
    } else {
        needle.to_lowercase()
    };
    for (idx, line) in content.lines().enumerate() {
        let matched = if case_sensitive {
            line.contains(&needle_cmp)
        } else {
            line.to_lowercase().contains(&needle_cmp)
        };
        if matched {
            let preview: String = line.trim().chars().take(200).collect();
            return Some((idx + 1, preview));
        }
    }
    None
}

/// Bounded recursive remote search supporting filename mask AND optional UTF-8 content substring.
pub async fn search_remote_bounded(
    session: &dyn RemoteSession,
    root_dir: &str,
    mask: &FileMask,
    text_query: Option<&str>,
    case_sensitive: bool,
    max_results: usize,
) -> Result<SearchStats, String> {
    let mut stats = SearchStats::default();
    let limit = max_results.clamp(1, 2000);
    search_remote_walk(
        session,
        root_dir,
        0,
        mask,
        text_query,
        case_sensitive,
        limit,
        &mut stats,
    )
    .await?;
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
async fn search_remote_walk(
    session: &dyn RemoteSession,
    dir: &str,
    depth: usize,
    mask: &FileMask,
    text_query: Option<&str>,
    case_sensitive: bool,
    limit: usize,
    stats: &mut SearchStats,
) -> Result<(), String> {
    if depth > MAX_SEARCH_DEPTH || stats.truncated {
        stats.truncated = true;
        return Ok(());
    }
    let entries = match session.list_dir(dir).await {
        Ok(list) => list,
        Err(e) => {
            if depth == 0 {
                return Err(e.to_string());
            }
            stats.skipped += 1;
            return Ok(());
        }
    };

    for entry in entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        if stats.matches.len() >= limit {
            stats.truncated = true;
            return Ok(());
        }
        let full_path = join_remote_path(dir, &entry.name);
        if entry.is_symlink {
            stats.skipped += 1;
            continue;
        }
        if entry.is_dir {
            if text_query.is_none() && mask.accepts_name(&entry.name, true) {
                stats.matches.push(json!({
                    "path": full_path,
                    "name": entry.name,
                    "is_dir": true,
                    "size": 0,
                    "mtime": entry.mtime,
                    "permissions": entry.permissions,
                }));
            }
            if depth + 1 <= MAX_SEARCH_DEPTH {
                Box::pin(search_remote_walk(
                    session,
                    &full_path,
                    depth + 1,
                    mask,
                    text_query,
                    case_sensitive,
                    limit,
                    stats,
                ))
                .await?;
            } else {
                stats.truncated = true;
            }
            continue;
        }

        if !mask.accepts(&entry.name, false, entry.size, entry.mtime as u64, &entry.name) {
            continue;
        }

        if let Some(needle) = text_query {
            if stats.scanned >= MAX_SEARCH_CONTENT_FILES {
                stats.truncated = true;
                return Ok(());
            }
            if entry.size > MAX_SEARCH_FILE_BYTES {
                stats.skipped += 1;
                continue;
            }
            if stats.bytes_scanned.saturating_add(entry.size) > MAX_SEARCH_TOTAL_BYTES {
                stats.truncated = true;
                return Ok(());
            }
            let Ok(bytes) = download_bytes(session, &full_path, TransferRequest::default()).await
            else {
                stats.skipped += 1;
                continue;
            };
            stats.scanned += 1;
            stats.bytes_scanned = stats.bytes_scanned.saturating_add(bytes.len() as u64);
            if bytes.contains(&0) {
                stats.skipped += 1;
                continue;
            }
            let Ok(text) = String::from_utf8(bytes) else {
                stats.skipped += 1;
                continue;
            };
            if let Some((line_no, preview)) = find_text_line(&text, needle, case_sensitive) {
                stats.matches.push(json!({
                    "path": full_path,
                    "name": entry.name,
                    "is_dir": false,
                    "size": entry.size,
                    "mtime": entry.mtime,
                    "permissions": entry.permissions,
                    "line": line_no,
                    "preview": preview,
                    // The page draws the match as `snippet`; both keys carry the
                    // same text so an older caller keeps working.
                    "snippet": preview,
                }));
            }
        } else {
            stats.scanned += 1;
            stats.matches.push(json!({
                "path": full_path,
                "name": entry.name,
                "is_dir": false,
                "size": entry.size,
                "mtime": entry.mtime,
                "permissions": entry.permissions,
            }));
        }
    }
    Ok(())
}

/// Bounded recursive local search used when `/api/remote/search` runs on a local-to-local tab.
pub fn search_local_bounded(
    root_dir: &Path,
    mask: &FileMask,
    text_query: Option<&str>,
    case_sensitive: bool,
    max_results: usize,
) -> Result<SearchStats, String> {
    let mut stats = SearchStats::default();
    let limit = max_results.clamp(1, 2000);
    search_local_walk(
        root_dir,
        0,
        mask,
        text_query,
        case_sensitive,
        limit,
        &mut stats,
    )?;
    Ok(stats)
}

fn search_local_walk(
    dir: &Path,
    depth: usize,
    mask: &FileMask,
    text_query: Option<&str>,
    case_sensitive: bool,
    limit: usize,
    stats: &mut SearchStats,
) -> Result<(), String> {
    if depth > MAX_SEARCH_DEPTH || stats.truncated {
        stats.truncated = true;
        return Ok(());
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            if depth == 0 {
                return Err(e.to_string());
            }
            stats.skipped += 1;
            return Ok(());
        }
    };
    let mut items: Vec<_> = rd.flatten().collect();
    items.sort_by_key(|e| e.file_name());

    for item in items {
        if stats.matches.len() >= limit {
            stats.truncated = true;
            return Ok(());
        }
        let path = item.path();
        let name = item.file_name().to_string_lossy().into_owned();
        let Ok(info) = stat_extended(&path) else {
            stats.skipped += 1;
            continue;
        };
        if info.is_symlink {
            stats.skipped += 1;
            continue;
        }
        if info.is_dir {
            if text_query.is_none() && mask.accepts_name(&name, true) {
                stats.matches.push(json!({
                    "path": path.to_string_lossy(),
                    "name": name,
                    "is_dir": true,
                    "size": 0,
                    "mtime": info.mtime_secs,
                    "permissions": info.permissions,
                }));
            }
            if depth + 1 <= MAX_SEARCH_DEPTH {
                search_local_walk(&path, depth + 1, mask, text_query, case_sensitive, limit, stats)?;
            } else {
                stats.truncated = true;
            }
            continue;
        }

        if !mask.accepts(&name, false, info.size, info.mtime_secs as u64, &name) {
            continue;
        }
        if let Some(needle) = text_query {
            if stats.scanned >= MAX_SEARCH_CONTENT_FILES {
                stats.truncated = true;
                return Ok(());
            }
            if info.size > MAX_SEARCH_FILE_BYTES {
                stats.skipped += 1;
                continue;
            }
            if stats.bytes_scanned.saturating_add(info.size) > MAX_SEARCH_TOTAL_BYTES {
                stats.truncated = true;
                return Ok(());
            }
            let Ok(bytes) = std::fs::read(&path) else {
                stats.skipped += 1;
                continue;
            };
            stats.scanned += 1;
            stats.bytes_scanned = stats.bytes_scanned.saturating_add(bytes.len() as u64);
            if bytes.contains(&0) {
                stats.skipped += 1;
                continue;
            }
            let Ok(text) = String::from_utf8(bytes) else {
                stats.skipped += 1;
                continue;
            };
            if let Some((line_no, preview)) = find_text_line(&text, needle, case_sensitive) {
                stats.matches.push(json!({
                    "path": path.to_string_lossy(),
                    "name": name,
                    "is_dir": false,
                    "size": info.size,
                    "mtime": info.mtime_secs,
                    "permissions": info.permissions,
                    "line": line_no,
                    "preview": preview,
                }));
            }
        } else {
            stats.scanned += 1;
            stats.matches.push(json!({
                "path": path.to_string_lossy(),
                "name": name,
                "is_dir": false,
                "size": info.size,
                "mtime": info.mtime_secs,
                "permissions": info.permissions,
            }));
        }
    }
    Ok(())
}

/// Computes a remote file digest via SFTP `check-file-name` extension or streaming download fallback.
pub async fn compute_remote_checksum(
    session: &dyn RemoteSession,
    remote_path: &str,
    algorithm: &str,
) -> Result<(String, String), String> {
    let alg = algorithm.trim().to_ascii_lowercase();
    let canonical = match alg.as_str() {
        "" | "sha-256" | "sha256" => "sha-256",
        "sha-1" | "sha1" => "sha-1",
        "sha-512" | "sha512" => "sha-512",
        "md5" => "md5",
        "crc32" => "crc32",
        other => return Err(format!("Unsupported checksum algorithm '{other}'.")),
    };

    if let Ok(hex) = session.checksum(canonical, remote_path).await {
        return Ok((canonical.to_string(), hex));
    }

    let bytes = download_bytes(session, remote_path, TransferRequest::default())
        .await
        .map_err(|e| e.to_string())?;
    let digest = compute_bytes_digest(canonical, &bytes);
    Ok((canonical.to_string(), digest))
}

pub fn compute_bytes_digest(canonical_alg: &str, bytes: &[u8]) -> String {
    match canonical_alg {
        "sha-1" | "sha1" => sha1_hex(bytes),
        "md5" => md5_hex(bytes),
        "crc32" => crc32_hex(bytes),
        _ => sha256_hex(bytes),
    }
}

/// Appends the session's SSH public key to `~/.ssh/authorized_keys` (`0700` dir, `0600` file, idempotent).
pub async fn run_ssh_copyid(
    session: &dyn RemoteSession,
    pubkey_input: Option<&str>,
    keyfile_fallback: Option<&str>,
) -> Result<String, String> {
    let ssh = session
        .ssh_connection()
        .ok_or_else(|| "Public-key installation requires an active SSH/SFTP/SCP session.".to_string())?;

    let raw_key_material = if let Some(pk) = pubkey_input.map(str::trim).filter(|s| !s.is_empty()) {
        pk.to_string()
    } else if let Some(path) = keyfile_fallback.map(str::trim).filter(|s| !s.is_empty()) {
        let pub_candidate = format!("{path}.pub");
        if let Ok(text) = std::fs::read_to_string(&pub_candidate) {
            text
        } else {
            std::fs::read_to_string(path)
                .map_err(|e| format!("Cannot read SSH key file '{path}': {e}"))?
        }
    } else {
        return Err("Provide a public key or configure an SSH key file on this session.".to_string());
    };

    let pub_line = extract_openssh_public_key_line(&raw_key_material, None)
        .map_err(|e| e.to_string())?;
    let escaped = pub_line.replace('\'', "'\\''");
    let script = format!(
        "umask 077 && mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && (grep -qxF '{escaped}' ~/.ssh/authorized_keys || printf '%s\\n' '{escaped}' >> ~/.ssh/authorized_keys)"
    );
    let out = ssh.exec_command(&script).await.map_err(|e| e.to_string())?;
    if out.exit_code.unwrap_or(0) != 0 {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if err.is_empty() {
            "Remote authorized_keys update failed.".to_string()
        } else {
            err
        });
    }
    Ok("Public key installed in ~/.ssh/authorized_keys.".to_string())
}

// ---------------------------------------------------------------------------
// Custom commands (`custom-commands.json` + shipped `explorer-commands.json`)
// ---------------------------------------------------------------------------

pub fn read_custom_commands(config_root: &Path) -> Vec<Value> {
    let custom_path = config_root.join("custom-commands.json");
    if let Ok(raw) = std::fs::read_to_string(&custom_path) {
        if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&raw) {
            if let Some(Value::Array(arr)) = map.get("commands") {
                return arr.clone();
            }
        }
        if let Ok(Value::Array(arr)) = serde_json::from_str::<Value>(&raw) {
            return arr;
        }
    }
    if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(DEFAULT_EXPLORER_COMMANDS_JSON) {
        if let Some(Value::Array(arr)) = map.get("commands") {
            return arr.clone();
        }
    }
    Vec::new()
}

pub fn write_custom_commands(config_root: &Path, commands: &[Value]) -> Result<(), String> {
    let doc = json!({
        "version": 1,
        "commands": commands,
    });
    let mut rendered = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
    rendered.push(b'\n');
    write_private_file_atomic(&config_root.join("custom-commands.json"), &rendered)
        .map_err(|e| e.to_string())
}

pub fn normalize_custom_command(body: &Value) -> Option<Value> {
    let src = body.get("command_obj").unwrap_or(body);
    let name = src.get("name")?.as_str()?.trim();
    let cmd = src.get("command")?.as_str()?.trim();
    if name.is_empty() || cmd.is_empty() || cmd.contains('\n') || cmd.contains('\r') {
        return None;
    }
    let scope = match src.get("scope").and_then(Value::as_str).unwrap_or("remote") {
        "local" => "local",
        _ => "remote",
    };
    let apply_to_dirs = src
        .get("apply_to_directories")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let description = src
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    Some(json!({
        "name": name,
        "command": cmd,
        "scope": scope,
        "apply_to_directories": apply_to_dirs,
        "description": description,
    }))
}

/// Quotes one word for the LinSCP command line's own tokenizer.
///
/// This is **not** shell quoting and must never be described as such. Nothing
/// interpolated here reaches a shell: the words are handed to
/// `linscp_engine::script::tokenize_script_line`, which drops the quotes and keeps
/// one token. Single quotes work there (`'a b'` is one word) and so do backslash
/// escapes, so a name holding a quote needs neither doubled quotes nor `'\''`.
fn quote_operand(word: &str) -> String {
    let needs_quotes = word.is_empty()
        || word
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '"' | '\'' | '\\'));
    if !needs_quotes {
        return word.to_string();
    }
    let mut out = String::with_capacity(word.len() + 2);
    out.push('\'');
    for c in word.chars() {
        if c == '\'' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// Which side of the tab a command runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandSide {
    Local,
    Remote,
}

/// Where a template runs and which directory its names are relative to.
///
/// Two inputs decide this and they can disagree: the template's own `scope` says
/// what the command is written for, and the page's focused pane says which pane
/// the names came from. Running a remote `checksum` on the local pane's names
/// would check a different file of the same name on the server, so a disagreement
/// is refused instead of guessed.
pub fn resolve_command_target(
    scope: &str,
    pane: &str,
    tab: &TabRuntime,
) -> Result<(CommandSide, String), String> {
    // A local-only tab has no server: a remote-scoped template falls back to the
    // tab's other local pane, which is what the page shows in its right-hand
    // ("remote") panel.
    let run_side = if scope == "local" || tab.is_local {
        CommandSide::Local
    } else {
        CommandSide::Remote
    };
    let pane = match pane {
        "local" | "remote" => pane,
        _ => return Ok((run_side, side_directory(run_side, pane, tab))),
    };
    let selection_side = if pane == "local" || tab.is_local {
        CommandSide::Local
    } else {
        CommandSide::Remote
    };
    if selection_side != run_side {
        let where_it_runs = if run_side == CommandSide::Remote { "remote" } else { "local" };
        return Err(format!(
            "This command is saved for the {where_it_runs} side, and the {pane} panel is selected. \
             Select the files in the {where_it_runs} panel, or save the command for the {pane} side."
        ));
    }
    Ok((run_side, side_directory(selection_side, pane, tab)))
}

/// The directory a side's names are relative to, as the page's panes show it.
fn side_directory(side: CommandSide, pane: &str, tab: &TabRuntime) -> String {
    match side {
        // The right-hand panel of a local-only tab is the tab's other local dir.
        CommandSide::Local if pane == "remote" && tab.is_local => tab.other_local_dir.clone(),
        CommandSide::Local => tab.local_dir.clone(),
        CommandSide::Remote => tab.remote_dir.clone(),
    }
}

/// Expands one saved template for one selected entry.
///
/// The placeholders are the documented ones (`{file}` and `{files}`, plus
/// upstream's `!`/`!/`/`!@`/`!#`/`!U`/`!S` forms). Every substituted value is
/// quoted for the command line's tokenizer, so a name with a space, a quote or a
/// backslash stays one operand and never starts a second command.
///
/// `{files}` is the whole selection; the caller expands it once per run and hands
/// the result in as `all_files`, so a template written for a multi-file command
/// (`tar czf out.tgz {files}`) runs once rather than once per file.
pub fn expand_custom_command(
    template_cmd: &str,
    filename: &str,
    all_files: &[String],
    dir: &str,
    tab: &TabRuntime,
) -> String {
    let host = tab
        .spec
        .as_ref()
        .map(|s| s.session.host.as_str())
        .unwrap_or("localhost");
    let port = tab
        .spec
        .as_ref()
        .map(|s| {
            if s.session.port == 0 {
                s.session.protocol.default_port()
            } else {
                s.session.port
            }
        })
        .unwrap_or(22)
        .to_string();
    let user = tab
        .spec
        .as_ref()
        .map(|s| s.session.username.as_str())
        .unwrap_or("");
    let dir_slash = if dir.ends_with('/') {
        dir.to_string()
    } else {
        format!("{dir}/")
    };
    let joined: Vec<String> = all_files.iter().map(|name| quote_operand(name)).collect();
    let all_quoted = joined.join(" ");

    let mut out = String::with_capacity(template_cmd.len() + 32);
    let chars: Vec<char> = template_cmd.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // `{file}` / `{files}`: the form this GUI documents, and the one a saved
        // template from a previous version is most likely to use.
        if chars[i] == '{' {
            // Scan the character vector, not the string: `{` and `}` are ASCII,
            // but the template between them need not be, and a byte offset into
            // a multi-byte character would slice a name in half.
            if let Some(rel) = chars[i..].iter().position(|c| *c == '}') {
                let name: String = chars[i + 1..i + rel].iter().collect();
                let replacement = match name.as_str() {
                    "file" => Some(quote_operand(filename)),
                    "files" => Some(all_quoted.clone()),
                    _ => None,
                };
                if let Some(replacement) = replacement {
                    out.push_str(&replacement);
                    i += rel + 1;
                    continue;
                }
            }
            out.push('{');
            i += 1;
            continue;
        }
        if chars[i] == '!' {
            if i + 1 < chars.len() {
                match chars[i + 1] {
                    '!' => {
                        out.push('!');
                        i += 2;
                        continue;
                    }
                    '/' => {
                        out.push_str(&quote_operand(&dir_slash));
                        i += 2;
                        continue;
                    }
                    '@' => {
                        out.push_str(&quote_operand(host));
                        i += 2;
                        continue;
                    }
                    '#' => {
                        out.push_str(&port);
                        i += 2;
                        continue;
                    }
                    'U' => {
                        out.push_str(&quote_operand(user));
                        i += 2;
                        continue;
                    }
                    'S' => {
                        out.push_str(&quote_operand(&tab.name));
                        i += 2;
                        continue;
                    }
                    _ => {}
                }
            }
            out.push_str(&quote_operand(filename));
            i += 1;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// One entry of the page's result list: a file, what ran, and what it printed.
///
/// `error` carries only a reason the command never ran (a name the page should
/// not have sent). What the command itself reported is on `stdout`/`stderr`, so
/// the page's `error + stdout + stderr` detail block does not print it twice.
fn command_result(file: &str, command: &str, exit_code: i32, stdout: String, stderr: String) -> Value {
    json!({
        "file": file,
        "command": command,
        "success": exit_code == 0,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "error": "",
    })
}

/// A refusal that never reached the interpreter, reported against one file.
fn rejected_result(file: &str, error: String) -> Value {
    json!({
        "file": file,
        "command": "",
        "success": false,
        "exit_code": 1,
        "stdout": "",
        "stderr": "",
        "error": error,
    })
}

/// The tab as one command should see it: the pane the template applies to is
/// the pane its names are relative to, whichever side that is.
fn tab_for_side(tab: &TabRuntime, side: CommandSide, work_dir: &str) -> TabRuntime {
    let mut tab = tab.clone();
    match side {
        CommandSide::Local => tab.local_dir = work_dir.to_string(),
        CommandSide::Remote => tab.remote_dir = work_dir.to_string(),
    }
    // A command on a tab's local side runs with or without a server: `checksum`,
    // `chmod`, `lls` and `call` act on the local pane through the interpreter's
    // own local paths. A local-only tab never had a session to be missing, so it
    // is presented as connected; a remote tab that dropped its connection keeps
    // saying so, because its remote side really is gone.
    if side == CommandSide::Local && tab.is_local {
        tab.connected = true;
    }
    tab
}

/// Runs one saved command template over the selection.
///
/// The command is a **LinSCP command line**, not a shell line: it goes through the
/// same `ScriptInterpreter` the console panel uses, so `checksum`, `chmod`, `lls`,
/// `call` and the rest mean exactly what they mean there, on all three builds.
///
/// The previous implementation built a `sh -c` string and ran it with
/// `std::process::Command`, which meant a Windows build had no way to run a local
/// command at all and a POSIX build handed the selection to a shell. Nothing here
/// spawns a process directly; the interpreter's own `call` (`!`) command is the
/// single, opt-in way a template reaches a shell.
///
/// When a template names no `{file}`/`{files}`/`!` operand the command does not
/// depend on the selection, so it runs once instead of once per selected file.
pub async fn execute_custom_command_template(
    make_interpreter: &mut dyn FnMut(&TabRuntime) -> Result<linscp_engine::script::ScriptInterpreter, String>,
    template: &Value,
    filenames: &[String],
    pane: &str,
    tab: &TabRuntime,
    on_command: &mut dyn FnMut(&str),
) -> Result<Vec<Value>, String> {
    let raw_cmd = template
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| "Invalid command template.".to_string())?;
    let scope = template.get("scope").and_then(Value::as_str).unwrap_or("remote");
    let (side, work_dir) = resolve_command_target(scope, pane, tab)?;

    // Every name is checked before anything runs: a hostile entry must not stop
    // the rest of the selection, but it must not be substituted either. The group
    // operand is built from the validated names only.
    let validated: Vec<String> = filenames
        .iter()
        .filter_map(|name| validate_leaf_name(name).ok())
        .collect();

    let per_file = raw_cmd.contains("{file}") || names_an_operand(raw_cmd);
    let targets: Vec<Option<String>> = if per_file {
        filenames.iter().map(|name| Some(name.clone())).collect()
    } else {
        // The command does not mention the selection: run it exactly once.
        vec![None]
    };

    let mut results = Vec::with_capacity(targets.len());
    for target in targets {
        let leaf = match &target {
            Some(name) => match validate_leaf_name(name) {
                Ok(leaf) => leaf,
                Err(error) => {
                    results.push(rejected_result(name, error));
                    continue;
                }
            },
            None => String::new(),
        };
        let expanded = expand_custom_command(raw_cmd, &leaf, &validated, &work_dir, tab);
        // One interpreter per file, starting in the pane's directory: a command
        // that fails half way must not leave the next file running in its
        // wreckage, and a `cd` in one template run is that run's own business.
        let mut interpreter = match make_interpreter(&tab_for_side(tab, side, &work_dir)) {
            Ok(interpreter) => interpreter,
            Err(error) => {
                results.push(rejected_result(&leaf, error));
                break;
            }
        };
        on_command(&expanded);
        let (ok, stdout, stderr) = Box::pin(interpreter.run_captured(&expanded)).await;
        let exit_code = if ok && interpreter.error_count() == 0 { 0 } else { 1 };
        results.push(command_result(&leaf, &expanded, exit_code, stdout, stderr));
    }
    Ok(results)
}

/// Whether a template names the selection, and so needs one to run.
pub fn template_names_a_file(template: &Value) -> bool {
    template
        .get("command")
        .and_then(Value::as_str)
        .map(|cmd| cmd.contains("{file}") || cmd.contains("{files}") || names_an_operand(cmd))
        .unwrap_or(false)
}

/// Whether a template line mentions the current entry at all. `!` on its own does;
/// the escapes `!!`, `!/`, `!@`, `!#`, `!U` and `!S` do not, because they name the
/// directory, the host, the port, the user or the session rather than the file.
fn names_an_operand(template_cmd: &str) -> bool {
    let chars: Vec<char> = template_cmd.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '!' {
            match chars.get(i + 1) {
                Some('!') | Some('/') | Some('@') | Some('#') | Some('U') | Some('S') => {
                    i += 2;
                    continue;
                }
                _ => return true,
            }
        }
        i += 1;
    }
    false
}

// ---------------------------------------------------------------------------
// Cleanup inventory & deletion (`GET / POST /api/cleanup`)
// ---------------------------------------------------------------------------

fn path_byte_size_no_create(path: &Path) -> (bool, u64) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return (false, 0);
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return (true, meta.len());
    }
    let mut sum = 0u64;
    if let Ok(rd) = std::fs::read_dir(path) {
        for entry in rd.flatten() {
            let (_, sz) = path_byte_size_no_create(&entry.path());
            sum = sum.saturating_add(sz);
        }
    }
    (true, sum)
}

fn cleanup_catalog(config_root: &Path) -> Vec<(&'static str, &'static str, PathBuf)> {
    vec![
        (
            "sessions",
            "Saved site profiles (sessions.ini)",
            config_root.join("sessions.ini"),
        ),
        (
            "passwords",
            "Master encryption key (sessions.key)",
            config_root.join("sessions.key"),
        ),
        (
            "hostkeys",
            "Cached SSH server host keys (sshhostkeys)",
            config_root.join("sshhostkeys"),
        ),
        (
            "workspaces",
            "Named Commander workspaces (workspaces.json)",
            config_root.join("workspaces.json"),
        ),
        (
            "bookmarks",
            "Directory bookmarks (bookmarks.json)",
            config_root.join("bookmarks.json"),
        ),
        (
            "commands",
            "Custom Explorer commands (custom-commands.json)",
            config_root.join("custom-commands.json"),
        ),
        (
            "preferences",
            "Commander preferences (preferences.json)",
            config_root.join("preferences.json"),
        ),
        (
            "shell",
            "Pending shell-upload manifests",
            config_root.join("shell-manifests"),
        ),
        (
            "editing",
            "Temporary remote editor buffers",
            config_root.join("edit-tmp"),
        ),
    ]
}

pub fn list_cleanup_locations(config_root: &Path) -> Vec<Value> {
    cleanup_catalog(config_root)
        .into_iter()
        .map(|(id, label, path)| {
            let (exists, bytes) = path_byte_size_no_create(&path);
            json!({
                "id": id,
                "label": label,
                "path": path.to_string_lossy(),
                "exists": exists,
                "bytes": bytes,
            })
        })
        .collect()
}

pub fn execute_cleanup(config_root: &Path, ids: &[String]) -> Result<Vec<Value>, String> {
    let catalog: BTreeMap<&str, (&str, PathBuf)> = cleanup_catalog(config_root)
        .into_iter()
        .map(|(id, label, path)| (id, (label, path)))
        .collect();

    for id in ids {
        if !catalog.contains_key(id.as_str()) {
            return Err(format!("Unknown cleanup target '{id}'."));
        }
    }

    let mut removed = Vec::new();
    for id in ids {
        if let Some((label, path)) = catalog.get(id.as_str()) {
            let existed = std::fs::symlink_metadata(path).is_ok();
            if existed {
                remove_path_any(path)?;
            }
            removed.push(json!({
                "id": id,
                "label": label,
                "path": path.to_string_lossy(),
                "removed": existed,
            }));
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Shell-upload staging manifests (`--shell-upload`, `/api/shell/*`)
// ---------------------------------------------------------------------------

pub fn record_shell_upload_manifest(
    config_root: &Path,
    paths: &[PathBuf],
) -> Result<Value, String> {
    if paths.is_empty() {
        return Err("Provide at least one local file or folder to stage for upload.".to_string());
    }
    let mut items = Vec::with_capacity(paths.len());
    for raw in paths {
        let abs = if raw.is_absolute() {
            raw.clone()
        } else {
            std::env::current_dir()
                .map_err(|e| e.to_string())?
                .join(raw)
        };
        let info = stat_extended(&abs)
            .map_err(|e| format!("Cannot stage '{}': {e}", abs.display()))?;
        let name = abs
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| format!("Path '{}' has no file name.", abs.display()))?;
        items.push(json!({
            "path": abs.to_string_lossy(),
            "name": name,
            "size": info.size,
            "is_dir": info.is_dir,
            "is_symlink": info.is_symlink,
            "date": format_listing_date(info.mtime_secs),
        }));
    }

    let manifests_dir = config_root.join("shell-manifests");
    create_private_dir(&manifests_dir).map_err(|e| e.to_string())?;
    let mut rnd = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut rnd);
    let id = rnd.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let doc = json!({
        "id": id,
        "created": created,
        "items": items,
    });
    let mut bytes = serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    write_private_file_atomic(&manifests_dir.join(format!("{id}.json")), &bytes)
        .map_err(|e| e.to_string())?;
    Ok(doc)
}

pub fn list_shell_manifests(config_root: &Path) -> Vec<Value> {
    let dir = config_root.join("shell-manifests");
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(raw) = std::fs::read_to_string(&p) {
            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                out.push(val);
            }
        }
    }
    out.sort_by_key(|v| v.get("created").and_then(Value::as_u64).unwrap_or(0));
    out
}

pub fn take_shell_manifest(config_root: &Path, id: &str) -> Result<Value, String> {
    let safe_id = validate_leaf_name(id)?;
    let path = config_root
        .join("shell-manifests")
        .join(format!("{safe_id}.json"));
    let raw = std::fs::read_to_string(&path)
        .map_err(|_| format!("Pending shell upload '{safe_id}' is no longer available."))?;
    let val: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&path);
    Ok(val)
}

pub fn dismiss_shell_manifest(config_root: &Path, id: &str) -> Result<(), String> {
    let safe_id = validate_leaf_name(id)?;
    let path = config_root
        .join("shell-manifests")
        .join(format!("{safe_id}.json"));
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Parses either octal `"755"` / `"0644"` or symbolic `"u+x,go-w"` chmod modes.
pub fn resolve_chmod_mode(mode_spec: &str, current_mode: u32) -> Result<u32, String> {
    let trimmed = mode_spec.trim();
    if trimmed.is_empty() {
        return Err("Permissions mode is required.".to_string());
    }
    let new_mode = parse_chmod_spec(trimmed, current_mode)?;
    Ok(new_mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use linscp_engine::script::{ScriptInterpreter, ScriptRunConfig};
    use linscp_engine::xml_log::SessionLogger;
    use serde_json::json;

    fn tab(is_local: bool) -> TabRuntime {
        TabRuntime {
            id: 1,
            name: "session".into(),
            site_name: None,
            is_local,
            connected: true,
            local_dir: "/home/u/Local".into(),
            remote_dir: "/srv/Remote".into(),
            other_local_dir: "/home/u/Other".into(),
            observed_hostkey: String::new(),
            hostkey_role: String::new(),
            hostkey_changed: false,
            error: String::new(),
            spec: None,
            session_json: json!({}),
            remote: None,
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "linscp-custom-commands-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        dir.canonicalize().expect("canonical scratch directory")
    }

    /// An interpreter that has no session and therefore only reaches local
    /// commands, which is the only thing a template must need to work.
    fn local_interpreter(tab: &TabRuntime) -> Result<ScriptInterpreter, String> {
        let logger = SessionLogger::open(None, 0, false, None, None, false, "")
            .map_err(|e| e.to_string())?;
        let mut cfg = ScriptRunConfig::default();
        // Nothing behind the window can answer a question, and the page already
        // asked before it posted the run.
        cfg.batch_mode = linscp_engine::script::BatchMode::Abort;
        let mut interpreter = ScriptInterpreter::new(cfg, logger);
        interpreter.set_local_dir(PathBuf::from(&tab.local_dir));
        Ok(interpreter)
    }

    /// A name with a space is one operand, not two, and a name that starts a
    /// second command stays inside its quotes: the quote the template gets is
    /// the command line's own, and it is what the interpreter's tokenizer reads.
    #[test]
    fn a_hostile_name_stays_one_operand_of_the_command_line() {
        let tab = tab(true);
        let cases = [
            ("my report.txt", "'my report.txt'"),
            ("`whoami`.txt", "`whoami`.txt"),
            ("a; rm -rf ~.txt", "'a; rm -rf ~.txt'"),
            ("it's.txt", "'it\\'s.txt'"),
            ("a\"b.txt", "'a\"b.txt'"),
            ("plain.txt", "plain.txt"),
            // A non-ASCII name must not be sliced by the placeholder scanner.
            ("für alle.txt", "'für alle.txt'"),
        ];
        for (raw, expected) in cases {
            let expanded = expand_custom_command("chmod 644 {file}", raw, &[], "/tmp", &tab);
            assert_eq!(expanded, format!("chmod 644 {expected}"), "{raw}");
            // And the tokenizer the interpreter uses agrees: one operand, with
            // the original name intact.
            let tokens =
                linscp_engine::script_params::tokenize_script_line(&expanded).expect("tokens");
            assert_eq!(tokens.len(), 3, "{expanded}");
            assert_eq!(tokens[2], raw, "the name survives quoting: {expanded}");
        }
    }

    /// `{files}` is the whole selection in one run, quoted per operand.
    #[test]
    fn the_group_placeholder_quotes_every_member() {
        let prefixed =
            expand_custom_command("call echo größer {file}", "a.txt", &[], "/tmp", &tab(true));
        assert_eq!(prefixed, "call echo größer a.txt");

        let expanded = expand_custom_command(
            "call tar czf out.tgz {files}",
            "",
            &["a.txt".to_string(), "two words.txt".to_string()],
            "/tmp",
            &tab(true),
        );
        assert_eq!(expanded, "call tar czf out.tgz a.txt 'two words.txt'");
    }

    /// A template with no operand at all runs once, even with a whole selection,
    /// and a template that names the file runs once per file - in the pane the
    /// template applies to.
    #[tokio::test]
    async fn only_a_template_that_names_the_file_runs_once_per_file() {
        let dir = scratch("once");
        std::fs::write(dir.join("a.txt"), b"payload").expect("write a test file");
        std::fs::write(dir.join("two words.txt"), b"payload").expect("write a test file");
        let mut test_tab = tab(true);
        test_tab.local_dir = dir.to_string_lossy().into_owned();
        let files = vec!["a.txt".to_string(), "two words.txt".to_string()];

        let once = json!({"name": "where", "command": "lpwd", "scope": "local"});
        let results = execute_custom_command_template(
            &mut local_interpreter,
            &once,
            &files,
            "local",
            &test_tab,
            &mut |_| {},
        )
        .await
        .expect("the template runs");
        assert_eq!(results.len(), 1, "a template that names no file runs once");
        assert_eq!(results[0]["success"], true, "{}", results[0]);
        assert!(
            results[0]["stdout"]
                .as_str()
                .unwrap_or("")
                .contains(&dir.display().to_string()),
            "and it starts in the pane's directory: {}",
            results[0]
        );

        // `lls` prints the entry it listed, so a name with a space shows up as
        // one name rather than as two names that are both missing.
        let per_file = json!({"name": "look", "command": "lls {file}", "scope": "local"});
        let results = execute_custom_command_template(
            &mut local_interpreter,
            &per_file,
            &files,
            "local",
            &test_tab,
            &mut |_| {},
        )
        .await
        .expect("the template runs");
        assert_eq!(results.len(), 2, "one result per selected file: {results:?}");
        let ran: Vec<&str> = results
            .iter()
            .map(|r| r["file"].as_str().unwrap_or(""))
            .collect();
        assert_eq!(ran, vec!["a.txt", "two words.txt"]);
        for result in &results {
            assert_eq!(result["success"], true, "{}", result);
            let file = result["file"].as_str().unwrap_or("");
            assert!(
                result["stdout"].as_str().unwrap_or("").contains(file),
                "the entry it listed is the one that was selected: {result}"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// One file's refusal or failure never stops the rest of the selection, and
    /// the failure is reported against the file it happened to.
    #[tokio::test]
    async fn one_files_failure_does_not_stop_the_others() {
        let dir = scratch("continue");
        std::fs::create_dir_all(dir.join("sub")).expect("a directory to select");
        let mut test_tab = tab(true);
        test_tab.local_dir = dir.to_string_lossy().into_owned();
        // The first entry exists, the second cannot be an entry of the panel at
        // all, and the third is a name that is simply not there.
        let files = vec![
            "sub".to_string(),
            "../escape".to_string(),
            "missing".to_string(),
        ];
        let template = json!({"name": "go", "command": "lcd {file}", "scope": "local"});
        let results = execute_custom_command_template(
            &mut local_interpreter,
            &template,
            &files,
            "local",
            &test_tab,
            &mut |_| {},
        )
        .await
        .expect("the run itself succeeds");
        assert_eq!(results.len(), 3, "every file is answered: {results:?}");
        assert_eq!(results[0]["success"], true, "{}", results[0]);
        assert_eq!(results[1]["success"], false, "{}", results[1]);
        assert_eq!(results[1]["file"], "../escape");
        assert_eq!(
            results[1]["command"], "",
            "a refused name never becomes a command line: {}",
            results[1]
        );
        assert!(
            !results[1]["error"].as_str().unwrap_or("").is_empty(),
            "the refused name says why: {}",
            results[1]
        );
        assert_eq!(results[2]["success"], false, "{}", results[2]);
        assert_eq!(results[2]["file"], "missing");
        assert!(
            results[2]["stderr"].as_str().unwrap_or("").contains("missing"),
            "the command's own failure is on its own channel: {}",
            results[2]
        );
        assert_eq!(
            results[2]["error"], "",
            "and is not repeated as a refusal: {}",
            results[2]
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The shipped templates are lines this interpreter actually understands.
    /// They are the ones the dialog offers on a fresh install, so a command the
    /// interpreter would reject by name would make Run fail out of the box.
    #[test]
    fn every_shipped_template_is_a_command_the_interpreter_knows() {
        use linscp_engine::script::COMMAND_NAMES;
        use linscp_engine::script_params::{resolve_prefixed_name, PrefixMatch};
        let shipped: Value =
            serde_json::from_str(DEFAULT_EXPLORER_COMMANDS_JSON).expect("shipped defaults parse");
        let commands = shipped.as_array().expect("an array of templates");
        assert!(!commands.is_empty(), "a fresh install offers something to run");
        for template in commands {
            let line = template["command"]
                .as_str()
                .unwrap_or_else(|| panic!("a template without a command: {template}"));
            let first = line.split_whitespace().next().unwrap_or("");
            assert!(
                matches!(resolve_prefixed_name(COMMAND_NAMES, first), PrefixMatch::ExactOrUnique(_)),
                "'{line}' starts with a command the interpreter does not know"
            );
            // And the placeholder it uses is one this expansion implements.
            for placeholder in line.split_whitespace().filter(|word| word.contains('{')) {
                assert!(
                    placeholder.contains("{file}") || placeholder.contains("{files}"),
                    "'{line}' uses a placeholder nothing expands: {placeholder}"
                );
            }
        }
    }

    /// The template's side and the pane the selection came from have to agree,
    /// or a remote command silently acts on a same-named file that is not the
    /// one the user selected.
    #[test]
    fn a_side_mismatch_is_refused_rather_than_guessed() {
        let remote_tab = tab(false);
        let (side, dir) =
            resolve_command_target("remote", "remote", &remote_tab).expect("both remote");
        assert_eq!(side, CommandSide::Remote);
        assert_eq!(dir, "/srv/Remote");

        let (side, dir) = resolve_command_target("local", "local", &remote_tab).expect("both local");
        assert_eq!(side, CommandSide::Local);
        assert_eq!(dir, "/home/u/Local");

        let error = resolve_command_target("remote", "local", &remote_tab)
            .expect_err("remote template, local selection");
        assert!(error.contains("remote side"), "{error}");
        assert!(error.contains("local panel"), "{error}");

        // A local-only tab has no server, so a remote-scoped template applies to
        // the pane the page draws on the right.
        let local_tab = tab(true);
        let (side, dir) =
            resolve_command_target("remote", "remote", &local_tab).expect("local-only tab");
        assert_eq!(side, CommandSide::Local);
        assert_eq!(dir, "/home/u/Other");

        // A page that sends no pane (an older client) keeps the saved scope.
        let (side, _) = resolve_command_target("remote", "", &remote_tab).expect("no pane given");
        assert_eq!(side, CommandSide::Remote);
    }

    /// The store the dialog saves into is the store the run reads from.
    #[test]
    fn a_saved_template_is_the_one_that_runs() {
        let config = scratch("store");
        assert!(
            read_custom_commands(&config)
                .iter()
                .any(|c| c["name"] == "Checksum"),
            "the shipped defaults are what an empty store lists"
        );
        let saved = normalize_custom_command(&json!({
            "name": " Word count ", "command": " call wc {file} ",
            "scope": "local", "apply_to_directories": true,
            "description": " counts lines "
        }))
        .expect("a one-line command with a name");
        assert_eq!(saved["name"], "Word count");
        assert_eq!(saved["command"], "call wc {file}");
        assert_eq!(saved["scope"], "local");
        assert_eq!(saved["apply_to_directories"], true);
        assert_eq!(saved["description"], "counts lines");
        assert!(
            normalize_custom_command(&json!({"name": "x", "command": "one\ntwo"})).is_none(),
            "a command with a newline would run a second command nobody typed"
        );
        assert!(
            normalize_custom_command(&json!({"name": "  ", "command": "ls"})).is_none(),
            "a nameless command cannot be selected or run"
        );
        write_custom_commands(&config, &[saved.clone()]).expect("write the store");
        let reloaded = read_custom_commands(&config);
        assert_eq!(reloaded.len(), 1, "{reloaded:?}");
        assert_eq!(reloaded[0]["command"], "call wc {file}");
        let _ = std::fs::remove_dir_all(config);
    }
}
