//! Directory tree comparison, persistent two-way state (`<config_dir>/sync/<hash>.state`),
//! conflict resolution (`-conflict=skip|local|remote|newer`), and execution of
//! `synchronize local|remote|both`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use linscp_crypto::digests::sha256_hex;
use linscp_platform::terminal::stat_local_path;
use linscp_platform::write_private_file_atomic;
use linscp_platform::{saf_document_too_large, LocalFs, MAX_SAF_DOCUMENT_BYTES};
use linscp_proto::{ProtoError, RemoteSession};
use linscp_types::{FileEntry, ProtocolScheme, TransferMode};

use crate::filemask::{FileMask, join_remote_path, mode_from_permissions_str};
use crate::transfer::{
    TransferFlags, download_single_file, join_saf_child, publish_staged_file_to_saf,
    stage_saf_upload_source, upload_single_file,
};
use crate::xml_log::{SessionLogger, XmlDiffRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    Local,
    Remote,
    Both,
}

impl SyncMode {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "local" => Some(Self::Local),
            "remote" => Some(Self::Remote),
            "both" => Some(Self::Both),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Both => "both",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncCriteria {
    pub time: bool,
    pub size: bool,
    pub checksum: bool,
}

impl Default for SyncCriteria {
    fn default() -> Self {
        Self {
            time: true,
            size: false,
            checksum: false,
        }
    }
}

impl SyncCriteria {
    pub fn is_empty(self) -> bool {
        !self.time && !self.size && !self.checksum
    }

    pub fn name(self) -> String {
        if self.is_empty() {
            return "none".to_string();
        }
        if self.time && self.size && !self.checksum {
            return "either".to_string();
        }
        let mut parts = Vec::new();
        if self.time {
            parts.push("time");
        }
        if self.size {
            parts.push("size");
        }
        if self.checksum {
            parts.push("checksum");
        }
        parts.join(",")
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(
                "'-criteria=' needs a value: none, either, both, or a comma-separated list of time, size and checksum."
                    .to_string(),
            );
        }
        let mut res = Self {
            time: false,
            size: false,
            checksum: false,
        };
        let mut whole: Option<String> = None;
        for raw in text.split(',') {
            let item = raw.trim();
            if let Some(ref w) = whole {
                let tail = if item.is_empty() {
                    "nothing may follow it in the list.".to_string()
                } else {
                    format!("'{item}' cannot follow it in the list.")
                };
                return Err(format!(
                    "'{w}' already names the whole set of criteria, so {tail}"
                ));
            }
            if item.is_empty() {
                return Err(
                    "The criteria list has an empty item; it takes 'time', 'size' and 'checksum' separated by commas."
                        .to_string(),
                );
            }
            match item.to_ascii_lowercase().as_str() {
                "none" => {
                    if res.time || res.size || res.checksum {
                        return Err(format!("'{item}' cannot be combined with other criteria."));
                    }
                    whole = Some(item.to_string());
                }
                "either" | "both" => {
                    if res.time || res.size || res.checksum {
                        return Err(format!("'{item}' cannot be combined with other criteria."));
                    }
                    res.time = true;
                    res.size = true;
                    whole = Some(item.to_string());
                }
                "time" => res.time = true,
                "size" => res.size = true,
                "checksum" => res.checksum = true,
                _ => {
                    return Err(format!(
                        "Unknown synchronization criterion '{item}' (use none, either, both, time, size or checksum)."
                    ));
                }
            }
        }
        Ok(res)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncConflictPolicy {
    Skip,
    Local,
    Remote,
    Newer,
}

impl SyncConflictPolicy {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "skip" => Ok(Self::Skip),
            "local" => Ok(Self::Local),
            "remote" => Ok(Self::Remote),
            "newer" => Ok(Self::Newer),
            other => Err(format!(
                "Unknown conflict policy '{other}' (use skip, local, remote or newer)."
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Newer => "newer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncAction {
    None,
    Download,
    Upload,
    DeleteLocal,
    DeleteRemote,
    Conflict,
}

impl SyncAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Download => "download",
            Self::Upload => "upload",
            Self::DeleteLocal => "deletelocal",
            Self::DeleteRemote => "deleteremote",
            Self::Conflict => "conflict",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyncItem {
    pub action: SyncAction,
    pub rel_path: String,
    pub is_directory: bool,
    pub local_size: u64,
    pub remote_size: u64,
    pub local_mtime: i64,
    pub remote_mtime: i64,
    pub local_mode: u32,
    pub remote_mode: u32,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct SyncOptions {
    pub mode: SyncMode,
    pub criteria: SyncCriteria,
    pub conflict_policy: SyncConflictPolicy,
    pub delete_obsolete: bool,
    pub mirror: bool,
    pub recursive: bool,
    pub preview_only: bool,
    pub transfer_mode: TransferMode,
    pub preserve_time: bool,
    pub permissions: crate::presets::PresetPermissions,
    pub speed_kbytes_per_sec: Option<u64>,
    pub file_mask: FileMask,
    /// The user acknowledged the staged SFTP publish (see `TransferFlags::sftp_risky_publish`).
    pub sftp_risky_publish: bool,
    /// Optional per-task cancellation flag for GUI queue / session teardown.
    pub cancel_flag: Option<Arc<AtomicBool>>,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            mode: SyncMode::Local,
            criteria: SyncCriteria::default(),
            conflict_policy: SyncConflictPolicy::Skip,
            delete_obsolete: false,
            mirror: false,
            recursive: true,
            preview_only: false,
            transfer_mode: TransferMode::Binary,
            preserve_time: true,
            permissions: crate::presets::PresetPermissions::Off,
            speed_kbytes_per_sec: None,
            file_mask: FileMask::default(),
            sftp_risky_publish: false,
            cancel_flag: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncStateEntry {
    pub local_time: u64,
    pub remote_time: u64,
    pub size: u64,
}

/// Persistent baseline for `synchronize both`, compatible with `<config_dir>/sync/<hash>.state`.
#[derive(Debug, Clone, Default)]
pub struct SyncState {
    entries: BTreeMap<String, SyncStateEntry>,
}

impl SyncState {
    pub fn make_key(host: &str, local_root: &str, remote_root: &str) -> String {
        format!("{host}|{local_root}|{remote_root}")
    }

    /// Computes the exact 16-hex hash used by `SyncPlanner.cpp` (`1469598103934665603ULL`).
    pub fn hash_key(key: &str) -> String {
        let mut hash: u64 = 1_469_598_103_934_665_603;
        for &b in key.as_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(1_099_511_628_211);
        }
        format!("{hash:016x}")
    }

    pub fn state_path(config_dir: &Path, key: &str) -> PathBuf {
        config_dir
            .join("sync")
            .join(format!("{}.state", Self::hash_key(key)))
    }

    pub fn lookup(&self, rel_path: &str) -> Option<SyncStateEntry> {
        self.entries.get(rel_path).copied()
    }

    pub fn update(&mut self, rel_path: String, entry: SyncStateEntry) {
        self.entries.insert(rel_path, entry);
    }

    pub fn remove(&mut self, rel_path: &str) {
        self.entries.remove(rel_path);
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(format!(
                    "Cannot read synchronization state '{}': {e}",
                    path.display()
                ));
            }
        };
        let mut state = Self::default();
        for raw in text.lines() {
            let line = raw.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() != 4 || fields[0].is_empty() {
                return Err(format!("Invalid synchronization state '{}': malformed record", path.display()));
            }
            let rel = unescape_state_value(fields[0]);
            let invalid = || format!("Invalid synchronization state '{}': malformed number", path.display());
            let local_time = fields[1].parse::<u64>().map_err(|_| invalid())?;
            let remote_time = fields[2].parse::<u64>().map_err(|_| invalid())?;
            let size = fields[3].parse::<u64>().map_err(|_| invalid())?;
            state.entries.insert(
                rel,
                SyncStateEntry {
                    local_time,
                    remote_time,
                    size,
                },
            );
        }
        Ok(state)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut out = format!("# LinSCP synchronization state, written {now}\n");
        for (rel, e) in &self.entries {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                escape_state_value(rel),
                e.local_time,
                e.remote_time,
                e.size
            ));
        }
        write_private_file_atomic(path, out.as_bytes())
            .map_err(|e| format!("Cannot write the synchronization state '{}': {e}", path.display()))
    }
}

fn escape_state_value(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

fn unescape_state_value(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[derive(Debug, Clone)]
struct TreeEntry {
    is_dir: bool,
    size: u64,
    mtime: i64,
    mode: u32,
}

/// True when a sync root is a granted Android folder (`content://` tree URI).
fn is_saf_sync_root(root: &str) -> bool {
    root.starts_with("content://")
}

/// Joins a `/`-separated plan path onto a granted root URI, one document
/// segment per level. Plan paths from the local walk carry names the walk
/// checked for separators, so no segment can escape the tree.
fn join_saf_rel(root_uri: &str, rel: &str) -> String {
    let mut uri = root_uri.trim_end_matches('/').to_string();
    if rel.is_empty() {
        return uri;
    }
    for segment in rel.split('/') {
        uri = join_saf_child(&uri, segment);
    }
    uri
}

/// The `collect_local_tree` walk over `LocalFs`, for a granted root: same
/// skips, same mask, same map. Provider names are untrusted, so a separator
/// in one refuses the plan — it would join onto the wrong document — while
/// links are skipped, as they refuse on transfer anyway.
fn mark_ancestor_retained(retained: &mut BTreeSet<String>, rel_dir: &str) {
    let mut cur = rel_dir;
    while !cur.is_empty() {
        retained.insert(cur.to_string());
        cur = match cur.rsplit_once('/') {
            Some((parent, _)) => parent,
            None => "",
        };
    }
}

fn collect_local_tree_fs(
    fs: &dyn LocalFs,
    root_uri: &str,
    rel_prefix: &str,
    recursive: bool,
    mask: &FileMask,
    out: &mut BTreeMap<String, TreeEntry>,
    retained_dirs: &mut BTreeSet<String>,
) -> Result<(), String> {
    let mut children = fs.list_dir(root_uri).map_err(|e| format!("Cannot read local directory '{root_uri}': {e}"))?;
    children.sort_by(|a, b| a.name.cmp(&b.name));
    for child in children {
        if child.name == "." || child.name == ".." {
            continue;
        }
        if !valid_sync_entry_name(&child.name) {
            return Err("Invalid directory entry name.".to_string());
        }
        if child.name.ends_with(".filepart") || child.name.contains(".filepart.v") {
            continue;
        }
        if child.is_symlink {
            mark_ancestor_retained(retained_dirs, rel_prefix);
            continue;
        }
        let rel = if rel_prefix.is_empty() {
            child.name.clone()
        } else {
            format!("{rel_prefix}/{}", child.name)
        };
        if !mask.accepts(&child.name, child.is_dir, child.size, child.mtime.max(0) as u64, &rel) {
            mark_ancestor_retained(retained_dirs, rel_prefix);
            continue;
        }
        out.insert(
            rel.clone(),
            TreeEntry {
                is_dir: child.is_dir,
                size: child.size,
                mtime: child.mtime,
                mode: mode_from_permissions_str(&child.permissions),
            },
        );
        if child.is_dir {
            if recursive {
                collect_local_tree_fs(
                    fs,
                    &join_saf_child(root_uri, &child.name),
                    &rel,
                    true,
                    mask,
                    out,
                    retained_dirs,
                )?;
            } else {
                mark_ancestor_retained(retained_dirs, &rel);
            }
        }
    }
    Ok(())
}

fn collect_local_tree(
    root: &Path,
    rel_prefix: &str,
    recursive: bool,
    mask: &FileMask,
    out: &mut BTreeMap<String, TreeEntry>,
    retained_dirs: &mut BTreeSet<String>,
) -> Result<(), String> {
    let rd = std::fs::read_dir(root)
        .map_err(|e| format!("Cannot read local directory '{}': {e}", root.display()))?;
    for item in rd {
        let de = item.map_err(|e| format!("Local directory read failed: {e}"))?;
        let name = de.file_name().into_string()
            .map_err(|_| format!("Cannot synchronize a non-UTF-8 name in '{}'.", root.display()))?;
        if !valid_sync_entry_name(&name) {
            return Err(format!("Invalid local directory entry name in '{}'.", root.display()));
        }
        if name.ends_with(".filepart") || name.contains(".filepart.v")
        {
            continue;
        }
        let full = de.path();
        let st = stat_local_path(&full);
        if st.is_symlink || (!st.is_dir && !st.is_regular) {
            mark_ancestor_retained(retained_dirs, rel_prefix);
            continue;
        }
        let rel = if rel_prefix.is_empty() {
            name.clone()
        } else {
            format!("{rel_prefix}/{name}")
        };
        if !mask.accepts(&name, st.is_dir, st.size, st.mtime.max(0) as u64, &rel) {
            mark_ancestor_retained(retained_dirs, rel_prefix);
            continue;
        }
        out.insert(
            rel.clone(),
            TreeEntry {
                is_dir: st.is_dir,
                size: st.size,
                mtime: st.mtime,
                mode: st.mode,
            },
        );
        if st.is_dir {
            if recursive {
                collect_local_tree(&full, &rel, true, mask, out, retained_dirs)?;
            } else {
                mark_ancestor_retained(retained_dirs, &rel);
            }
        }
    }
    Ok(())
}

// Server/provider listings are untrusted path components, not relative paths.
// Never let them escape the selected roots or be interpreted as separators on
// another platform. Preserve ordinary whitespace in valid names.
fn valid_sync_entry_name(name: &str) -> bool {
    if crate::transfer::safe_tree_name(name).is_err() { return false; }
    // Windows silently aliases trailing dots/spaces and reserves device names;
    // reject those before a remote path can alias an unrelated local file.
    #[cfg(windows)]
    {
        if name.ends_with(['.', ' ']) || name.contains(['<', '>', '"', '|', '?', '*']) {
            return false;
        }
        let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
        if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
            || (stem.len() == 4 && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9')) {
            return false;
        }
    }
    true
}

async fn collect_remote_tree(
    session: &dyn RemoteSession,
    root: &str,
    rel_prefix: &str,
    recursive: bool,
    mask: &FileMask,
    out: &mut BTreeMap<String, TreeEntry>,
    retained_dirs: &mut BTreeSet<String>,
) -> Result<(), String> {
    let entries = session
        .list_dir(root)
        .await
        .map_err(|e| format!("Cannot list remote directory '{root}': {e}"))?;
    for entry in entries {
        if entry.name == "." || entry.name == ".." {
            continue;
        }
        if !valid_sync_entry_name(&entry.name) {
            return Err("Invalid remote directory entry name.".to_string());
        }
        if entry.name.ends_with(".filepart") || entry.name.contains(".filepart.v") {
            continue;
        }
        if entry.is_symlink {
            mark_ancestor_retained(retained_dirs, rel_prefix);
            continue;
        }
        let rel = if rel_prefix.is_empty() {
            entry.name.clone()
        } else {
            format!("{rel_prefix}/{}", entry.name)
        };
        if !mask.accepts(
            &entry.name,
            entry.is_dir,
            entry.size,
            entry.mtime.max(0) as u64,
            &rel,
        ) {
            mark_ancestor_retained(retained_dirs, rel_prefix);
            continue;
        }
        out.insert(
            rel.clone(),
            TreeEntry {
                is_dir: entry.is_dir,
                size: entry.size,
                mtime: entry.mtime,
                mode: mode_from_permissions_str(&entry.permissions),
            },
        );
        if entry.is_dir {
            if recursive {
                let child = join_remote_path(root, &entry.name);
                Box::pin(collect_remote_tree(
                    session,
                    &child,
                    &rel,
                    true,
                    mask,
                    out,
                    retained_dirs,
                ))
                .await?;
            } else {
                mark_ancestor_retained(retained_dirs, &rel);
            }
        }
    }
    Ok(())
}

/// Builds a deterministic, sorted synchronization plan without mutating either filesystem.
/// A granted local root is walked through `local_fs`; any other root walks the
/// direct path, whether a filesystem was passed or not.
pub async fn plan_synchronization(
    session: &dyn RemoteSession,
    local_root: &Path,
    remote_root: &str,
    opts: &SyncOptions,
    state: &SyncState,
    local_fs: Option<&dyn LocalFs>,
) -> Result<Vec<SyncItem>, String> {
    if opts.cancel_flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst)) {
        return Err("Synchronization cancelled.".to_string());
    }
    if opts.mode == SyncMode::Both {
        if opts.criteria.checksum {
            return Err(
                "Bidirectional ('both') synchronization does not support '-criteria=checksum'."
                    .to_string(),
            );
        }
        if opts.criteria.is_empty() {
            return Err(
                "Bidirectional ('both') synchronization does not support '-criteria=none'."
                    .to_string(),
            );
        }
        if opts.mirror {
            return Err(
                "'-mirror' cannot be combined with bidirectional ('both') synchronization."
                    .to_string(),
            );
        }
    }

    let local_root_str = local_root.to_string_lossy();
    let saf_fs = local_fs.filter(|_| is_saf_sync_root(&local_root_str));
    let mut local_map = BTreeMap::new();
    let mut remote_map = BTreeMap::new();
    let mut local_retained = BTreeSet::new();
    let mut remote_retained = BTreeSet::new();
    if let Some(fs) = saf_fs {
        collect_local_tree_fs(
            fs,
            &local_root_str,
            "",
            opts.recursive,
            &opts.file_mask,
            &mut local_map,
            &mut local_retained,
        )?;
    } else {
        collect_local_tree(
            local_root,
            "",
            opts.recursive,
            &opts.file_mask,
            &mut local_map,
            &mut local_retained,
        )?;
    }
    collect_remote_tree(
        session,
        remote_root,
        "",
        opts.recursive,
        &opts.file_mask,
        &mut remote_map,
        &mut remote_retained,
    )
    .await?;

    let mut all_paths = BTreeSet::new();
    all_paths.extend(local_map.keys().cloned());
    all_paths.extend(remote_map.keys().cloned());

    let mut items = Vec::new();
    for rel in all_paths {
        let loc = local_map.get(&rel);
        let rem = remote_map.get(&rel);

        match (loc, rem) {
            (Some(l), Some(r)) => {
                if l.is_dir != r.is_dir {
                    items.push(SyncItem {
                        action: SyncAction::Conflict,
                        rel_path: rel,
                        is_directory: l.is_dir,
                        local_size: l.size,
                        remote_size: r.size,
                        local_mtime: l.mtime,
                        remote_mtime: r.mtime,
                        local_mode: l.mode,
                        remote_mode: r.mode,
                        reason: "type mismatch (file vs directory)".to_string(),
                    });
                    continue;
                }
                if l.is_dir {
                    continue;
                }
                let action_and_reason = match opts.mode {
                    SyncMode::Local => {
                        let local_uri = join_saf_rel(&local_root_str, &rel);
                        let diff = one_way_differs(
                            session,
                            &join_remote_path(remote_root, &rel),
                            &local_root.join(&rel),
                            r,
                            l,
                            opts.criteria,
                            opts.mirror,
                            saf_fs.map(|fs| (fs, local_uri.as_str())),
                        )
                        .await?;
                        diff.map(|reason| (SyncAction::Download, reason))
                    }
                    SyncMode::Remote => {
                        let local_uri = join_saf_rel(&local_root_str, &rel);
                        let diff = one_way_differs_upload(
                            session,
                            &local_root.join(&rel),
                            &join_remote_path(remote_root, &rel),
                            l,
                            r,
                            opts.criteria,
                            opts.mirror,
                            saf_fs.map(|fs| (fs, local_uri.as_str())),
                        )
                        .await?;
                        diff.map(|reason| (SyncAction::Upload, reason))
                    }
                    SyncMode::Both => decide_both_existing(l, r, state.lookup(&rel), opts),
                };

                if let Some((action, reason)) = action_and_reason {
                    items.push(SyncItem {
                        action,
                        rel_path: rel,
                        is_directory: false,
                        local_size: l.size,
                        remote_size: r.size,
                        local_mtime: l.mtime,
                        remote_mtime: r.mtime,
                        local_mode: l.mode,
                        remote_mode: r.mode,
                        reason,
                    });
                } else {
                    items.push(SyncItem {
                        action: SyncAction::None,
                        rel_path: rel,
                        is_directory: false,
                        local_size: l.size,
                        remote_size: r.size,
                        local_mtime: l.mtime,
                        remote_mtime: r.mtime,
                        local_mode: l.mode,
                        remote_mode: r.mode,
                        reason: "up to date".to_string(),
                    });
                }
            }
            (None, Some(r)) => {
                let act = match opts.mode {
                    SyncMode::Local => Some((SyncAction::Download, "missing locally")),
                    SyncMode::Remote => {
                        if opts.delete_obsolete && !(r.is_dir && remote_retained.contains(&rel)) {
                            Some((SyncAction::DeleteRemote, "deleted locally"))
                        } else {
                            None
                        }
                    }
                    SyncMode::Both => {
                        if !r.is_dir && state.lookup(&rel).is_some() && opts.delete_obsolete {
                            Some((SyncAction::DeleteRemote, "removed locally since last sync"))
                        } else {
                            Some((SyncAction::Download, "new on remote"))
                        }
                    }
                };
                if let Some((action, reason)) = act {
                    items.push(SyncItem {
                        action,
                        rel_path: rel,
                        is_directory: r.is_dir,
                        local_size: 0,
                        remote_size: r.size,
                        local_mtime: 0,
                        remote_mtime: r.mtime,
                        local_mode: 0,
                        remote_mode: r.mode,
                        reason: reason.to_string(),
                    });
                }
            }
            (Some(l), None) => {
                let act = match opts.mode {
                    SyncMode::Remote => Some((SyncAction::Upload, "missing on remote")),
                    SyncMode::Local => {
                        if opts.delete_obsolete && !(l.is_dir && local_retained.contains(&rel)) {
                            Some((SyncAction::DeleteLocal, "deleted on remote"))
                        } else {
                            None
                        }
                    }
                    SyncMode::Both => {
                        if !l.is_dir && state.lookup(&rel).is_some() && opts.delete_obsolete {
                            Some((SyncAction::DeleteLocal, "removed on remote since last sync"))
                        } else {
                            Some((SyncAction::Upload, "new locally"))
                        }
                    }
                };
                if let Some((action, reason)) = act {
                    items.push(SyncItem {
                        action,
                        rel_path: rel,
                        is_directory: l.is_dir,
                        local_size: l.size,
                        remote_size: 0,
                        local_mtime: l.mtime,
                        remote_mtime: 0,
                        local_mode: l.mode,
                        remote_mode: 0,
                        reason: reason.to_string(),
                    });
                }
            }
            (None, None) => {}
        }
    }

    sort_sync_items(&mut items);
    Ok(items)
}

async fn one_way_differs(
    session: &dyn RemoteSession,
    remote_path: &str,
    local_path: &Path,
    src_remote: &TreeEntry,
    dst_local: &TreeEntry,
    criteria: SyncCriteria,
    mirror: bool,
    local_saf: Option<(&dyn LocalFs, &str)>,
) -> Result<Option<String>, String> {
    if criteria.is_empty() {
        return Ok(Some("criteria=none".to_string()));
    }
    if criteria.time && src_remote.mtime > 0 && dst_local.mtime > 0 {
        if src_remote.mtime > dst_local.mtime {
            return Ok(Some("remote is newer".to_string()));
        }
        if mirror && src_remote.mtime != dst_local.mtime {
            return Ok(Some("timestamp differs (-mirror)".to_string()));
        }
    }
    if criteria.size && src_remote.size != dst_local.size {
        return Ok(Some("size differs".to_string()));
    }
    if criteria.checksum {
        // The bridge carries whole documents, so an over-cap file refuses
        // the plan on its fresh stat, before the read spends the memory.
        let local_bytes = match local_saf {
            Some((fs, uri)) => {
                let size = fs.stat(uri).map_err(|e| format!("Cannot inspect '{uri}' for checksum: {e}"))?.size;
                if size > MAX_SAF_DOCUMENT_BYTES {
                    return Err(saf_document_too_large(uri.rsplit('/').next().unwrap_or(uri), size));
                }
                fs.read_bytes(uri).map_err(|e| format!("Cannot read '{uri}' for checksum: {e}"))?
            }
            None => std::fs::read(local_path)
                .map_err(|e| format!("Cannot read '{}' for checksum: {e}", local_path.display()))?,
        };
        let local_hex = sha256_hex(&local_bytes);
        let remote_hex = session
            .checksum("sha-256", remote_path)
            .await
            .map_err(|e| format!("Cannot hash remote '{remote_path}': {e}"))?;
        if !local_hex.eq_ignore_ascii_case(&remote_hex) {
            return Ok(Some("contents differ".to_string()));
        }
    }
    Ok(None)
}

async fn one_way_differs_upload(
    session: &dyn RemoteSession,
    local_path: &Path,
    remote_path: &str,
    src_local: &TreeEntry,
    dst_remote: &TreeEntry,
    criteria: SyncCriteria,
    mirror: bool,
    local_saf: Option<(&dyn LocalFs, &str)>,
) -> Result<Option<String>, String> {
    if criteria.is_empty() {
        return Ok(Some("criteria=none".to_string()));
    }
    if criteria.time && src_local.mtime > 0 && dst_remote.mtime > 0 {
        if src_local.mtime > dst_remote.mtime {
            return Ok(Some("local is newer".to_string()));
        }
        if mirror && src_local.mtime != dst_remote.mtime {
            return Ok(Some("timestamp differs (-mirror)".to_string()));
        }
    }
    if criteria.size && src_local.size != dst_remote.size {
        return Ok(Some("size differs".to_string()));
    }
    if criteria.checksum {
        // The bridge carries whole documents, so an over-cap file refuses
        // the plan on its fresh stat, before the read spends the memory.
        let local_bytes = match local_saf {
            Some((fs, uri)) => {
                let size = fs.stat(uri).map_err(|e| format!("Cannot inspect '{uri}' for checksum: {e}"))?.size;
                if size > MAX_SAF_DOCUMENT_BYTES {
                    return Err(saf_document_too_large(uri.rsplit('/').next().unwrap_or(uri), size));
                }
                fs.read_bytes(uri).map_err(|e| format!("Cannot read '{uri}' for checksum: {e}"))?
            }
            None => std::fs::read(local_path)
                .map_err(|e| format!("Cannot read '{}' for checksum: {e}", local_path.display()))?,
        };
        let local_hex = sha256_hex(&local_bytes);
        let remote_hex = session
            .checksum("sha-256", remote_path)
            .await
            .map_err(|e| format!("Cannot hash remote '{remote_path}': {e}"))?;
        if !local_hex.eq_ignore_ascii_case(&remote_hex) {
            return Ok(Some("contents differ".to_string()));
        }
    }
    Ok(None)
}

fn decide_both_existing(
    loc: &TreeEntry,
    rem: &TreeEntry,
    baseline: Option<SyncStateEntry>,
    opts: &SyncOptions,
) -> Option<(SyncAction, String)> {
    let lt = loc.mtime.max(0) as u64;
    let rt = rem.mtime.max(0) as u64;
    let same_time = !opts.criteria.time || lt == rt;
    let same_size = !opts.criteria.size || loc.size == rem.size;
    if same_time && same_size {
        return None;
    }

    if let Some(base) = baseline {
        let local_changed = (opts.criteria.time && lt != base.local_time)
            || (opts.criteria.size && loc.size != base.size);
        let remote_changed = (opts.criteria.time && rt != base.remote_time)
            || (opts.criteria.size && rem.size != base.size);
        match (local_changed, remote_changed) {
            (true, false) => return Some((SyncAction::Upload, "modified locally".to_string())),
            (false, true) => return Some((SyncAction::Download, "modified on remote".to_string())),
            (false, false) => return None,
            (true, true) => {
                return Some(resolve_conflict(loc, rem, opts.conflict_policy));
            }
        }
    }

    // Without baseline state, if timestamps differ and `-criteria=time` is active without size conflict:
    if opts.criteria.time && lt != rt && (!opts.criteria.size || loc.size != rem.size) {
        if opts.conflict_policy == SyncConflictPolicy::Skip && opts.criteria.size && loc.size != rem.size {
            return Some(resolve_conflict(loc, rem, opts.conflict_policy));
        }
        if lt > rt {
            return Some((SyncAction::Upload, "local is newer".to_string()));
        } else {
            return Some((SyncAction::Download, "remote is newer".to_string()));
        }
    }

    Some(resolve_conflict(loc, rem, opts.conflict_policy))
}

fn resolve_conflict(
    loc: &TreeEntry,
    rem: &TreeEntry,
    policy: SyncConflictPolicy,
) -> (SyncAction, String) {
    match policy {
        SyncConflictPolicy::Skip => (
            SyncAction::Conflict,
            "modified on both sides (conflict)".to_string(),
        ),
        SyncConflictPolicy::Local => (
            SyncAction::Upload,
            "conflict resolved in favour of local".to_string(),
        ),
        SyncConflictPolicy::Remote => (
            SyncAction::Download,
            "conflict resolved in favour of remote".to_string(),
        ),
        SyncConflictPolicy::Newer => {
            if loc.mtime > rem.mtime {
                (
                    SyncAction::Upload,
                    "conflict resolved in favour of newer local file".to_string(),
                )
            } else if rem.mtime > loc.mtime {
                (
                    SyncAction::Download,
                    "conflict resolved in favour of newer remote file".to_string(),
                )
            } else {
                (
                    SyncAction::Conflict,
                    "modified on both sides with identical timestamps".to_string(),
                )
            }
        }
    }
}

fn sort_sync_items(items: &mut [SyncItem]) {
    items.sort_by(|a, b| {
        let phase = |act: SyncAction| -> u8 {
            match act {
                SyncAction::Conflict => 0,
                SyncAction::Download | SyncAction::Upload => 1,
                SyncAction::DeleteLocal | SyncAction::DeleteRemote => 2,
                SyncAction::None => 3,
            }
        };
        let pa = phase(a.action);
        let pb = phase(b.action);
        if pa != pb {
            return pa.cmp(&pb);
        }
        let depth_a = a.rel_path.matches('/').count();
        let depth_b = b.rel_path.matches('/').count();
        if matches!(a.action, SyncAction::DeleteLocal | SyncAction::DeleteRemote) {
            // Deletions: files before directories, deepest paths first
            if a.is_directory != b.is_directory {
                return a.is_directory.cmp(&b.is_directory);
            }
            depth_b.cmp(&depth_a).then_with(|| a.rel_path.cmp(&b.rel_path))
        } else {
            // Creations & transfers: directories before files, shallowest paths first
            if a.is_directory != b.is_directory {
                return b.is_directory.cmp(&a.is_directory);
            }
            depth_a.cmp(&depth_b).then_with(|| a.rel_path.cmp(&b.rel_path))
        }
    });
}

/// Applies `items` (after recording XML `<difference>` entries), updates `state`, and returns
/// `(applied_count, conflict_count)`. A granted local root applies through `local_fs`,
/// staging file bytes both ways; any other root applies through the direct path.
pub async fn apply_sync_plan(
    session: &dyn RemoteSession,
    local_root: &Path,
    remote_root: &str,
    items: &[SyncItem],
    opts: &SyncOptions,
    state: &mut SyncState,
    logger: &mut SessionLogger,
    local_fs: Option<&dyn LocalFs>,
) -> Result<(usize, usize), String> {
    let mut applied = 0usize;
    let mut conflicts = 0usize;

    for item in items {
        if item.action == SyncAction::None {
            continue;
        }
        let diff_rec = XmlDiffRecord {
            action: item.action.as_str().to_string(),
            is_directory: item.is_directory,
            filename: item.rel_path.clone(),
            size: match item.action {
                SyncAction::Upload | SyncAction::DeleteLocal => Some(item.local_size),
                SyncAction::Download | SyncAction::DeleteRemote => Some(item.remote_size),
                _ => None,
            },
            mtime: match item.action {
                SyncAction::Upload | SyncAction::DeleteLocal => Some(item.local_mtime),
                SyncAction::Download | SyncAction::DeleteRemote => Some(item.remote_mtime),
                _ => None,
            },
        };
        logger.record_difference(&diff_rec, Ok(()));
        if item.action == SyncAction::Conflict {
            conflicts += 1;
        }
    }

    if opts.preview_only {
        return Ok((0, conflicts));
    }

    let tflags = TransferFlags {
        transfer_mode: opts.transfer_mode,
        preserve_time: opts.preserve_time,
        permissions: opts.permissions,
        speed_kbytes_per_sec: opts.speed_kbytes_per_sec,
        sftp_risky_publish: opts.sftp_risky_publish,
        cancel_flag: opts.cancel_flag.clone(),
        ..TransferFlags::default()
    };

    let local_root_str = local_root.to_string_lossy();
    let saf_fs = local_fs.filter(|_| is_saf_sync_root(&local_root_str));
    let no_cancel = AtomicBool::new(false);
    let cancel_switch: &AtomicBool = opts.cancel_flag.as_deref().unwrap_or(&no_cancel);

    for item in items {
        if cancel_switch.load(Ordering::SeqCst) {
            return Err("Synchronization cancelled.".to_string());
        }
        let local_path = local_root.join(&item.rel_path);
        let remote_path = join_remote_path(remote_root, &item.rel_path);
        match item.action {
            SyncAction::None => {
                if !item.is_directory {
                    state.update(
                        item.rel_path.clone(),
                        SyncStateEntry {
                            local_time: item.local_mtime.max(0) as u64,
                            remote_time: item.remote_mtime.max(0) as u64,
                            size: item.local_size,
                        },
                    );
                }
            }
            SyncAction::Conflict => {}
            SyncAction::Download => {
                if item.is_directory {
                    if let Some(fs) = saf_fs {
                        fs.mkdir_all(&join_saf_rel(&local_root_str, &item.rel_path)).map_err(|e| e.to_string())?;
                    } else {
                        std::fs::create_dir_all(&local_path).map_err(|e| {
                            format!("Cannot create local directory '{}': {e}", local_path.display())
                        })?;
                    }
                } else if let Some(fs) = saf_fs {
                    // The guarded download lands in a private stage and
                    // publishes across the bridge, replacing like the plain
                    // path does.
                    let stage = tempfile::Builder::new().prefix("linscp-sync-download-").rand_bytes(16).tempdir()
                        .map_err(|e| format!("Cannot create download staging directory: {e}"))?;
                    let staged_file = stage.path().join("contents");
                    download_single_file(session, &remote_path, None, &staged_file, &tflags, logger, None).await?;
                    let dest_uri = join_saf_rel(&local_root_str, &item.rel_path);
                    publish_staged_file_to_saf(fs, &staged_file, &dest_uri, false, cancel_switch)?;
                    let l_after = fs.stat(&dest_uri).map_err(|e| e.to_string())?;
                    let r_mtime = if item.remote_mtime > 0 {
                        item.remote_mtime as u64
                    } else {
                        l_after.mtime.max(0) as u64
                    };
                    state.update(
                        item.rel_path.clone(),
                        SyncStateEntry {
                            local_time: l_after.mtime.max(0) as u64,
                            remote_time: r_mtime,
                            size: l_after.size,
                        },
                    );
                } else {
                    download_single_file(
                        session,
                        &remote_path,
                        None,
                        &local_path,
                        &tflags,
                        logger,
                        None,
                    )
                    .await?;
                    let l_after = stat_local_path(&local_path);
                    let r_mtime = if item.remote_mtime > 0 {
                        item.remote_mtime as u64
                    } else {
                        l_after.mtime.max(0) as u64
                    };
                    state.update(
                        item.rel_path.clone(),
                        SyncStateEntry {
                            local_time: l_after.mtime.max(0) as u64,
                            remote_time: r_mtime,
                            size: l_after.size,
                        },
                    );
                }
                applied += 1;
            }
            SyncAction::Upload => {
                if item.is_directory {
                    if session
                        .stat(&remote_path)
                        .await
                        .map_err(|e| e.to_string())?
                        .is_none()
                    {
                        session
                            .mkdir(&remote_path)
                            .await
                            .map_err(|e| e.to_string())?;
                        logger.record_mkdir(&remote_path, Ok(()));
                    }
                } else {
                    if let Some(fs) = saf_fs {
                        let stage = stage_saf_upload_source(fs, &join_saf_rel(&local_root_str, &item.rel_path), cancel_switch)?;
                        upload_single_file(session, &stage.root, &remote_path, &tflags, logger, None).await?;
                    } else {
                        upload_single_file(session, &local_path, &remote_path, &tflags, logger, None)
                            .await?;
                    }
                    let r_after = session
                        .stat(&remote_path)
                        .await
                        .ok()
                        .flatten();
                    let r_mtime = r_after
                        .as_ref()
                        .map(|e| e.mtime.max(0) as u64)
                        .unwrap_or(item.local_mtime.max(0) as u64);
                    state.update(
                        item.rel_path.clone(),
                        SyncStateEntry {
                            local_time: item.local_mtime.max(0) as u64,
                            remote_time: r_mtime,
                            size: item.local_size,
                        },
                    );
                }
                applied += 1;
            }
            SyncAction::DeleteLocal => {
                if conflicts > 0 {
                    continue;
                }
                if let Some(fs) = saf_fs {
                    let uri = join_saf_rel(&local_root_str, &item.rel_path);
                    if item.is_directory {
                        if fs.list_dir(&uri).map(|v| v.is_empty()).unwrap_or(false) {
                            let _ = fs.remove_dir_all(&uri);
                        }
                    } else if fs.stat(&uri).is_ok() {
                        fs.remove_file(&uri).map_err(|e| e.to_string())?;
                    }
                } else if item.is_directory {
                    // Remove only empty directories so excluded files or skipped symlinks survive!
                    let _ = std::fs::remove_dir(&local_path);
                } else if local_path.exists() {
                    std::fs::remove_file(&local_path).map_err(|e| {
                        format!("Cannot remove local file '{}': {e}", local_path.display())
                    })?;
                }
                state.remove(&item.rel_path);
                applied += 1;
            }
            SyncAction::DeleteRemote => {
                if conflicts > 0 {
                    continue;
                }
                if item.is_directory {
                    if let Err(e) = session.remove_dir(&remote_path).await {
                        let msg = e.to_string();
                        logger.record_rm(&remote_path, false, Err(&msg));
                        return Err(msg);
                    }
                    logger.record_rm(&remote_path, false, Ok(()));
                } else {
                    if let Err(e) = session.remove_file(&remote_path).await {
                        let msg = e.to_string();
                        logger.record_rm(&remote_path, false, Err(&msg));
                        return Err(msg);
                    }
                    logger.record_rm(&remote_path, false, Ok(()));
                }
                state.remove(&item.rel_path);
                applied += 1;
            }
        }
    }

    Ok((applied, conflicts))
}

/// Adapts a local directory (OS path or Android SAF `content://` tree) to
/// [`RemoteSession`] so dual-local tabs can preview and execute one-way,
/// mirror, checksum, and stateful bidirectional (`both`) synchronizations
/// through [`plan_synchronization`] and [`apply_sync_plan`].
pub struct LocalSyncSession {
    root: String,
    local_fs: Arc<dyn LocalFs>,
}

impl LocalSyncSession {
    pub fn new(root: String, local_fs: Arc<dyn LocalFs>) -> Self {
        Self { root, local_fs }
    }

    fn resolve(&self, virtual_path: &str) -> Result<String, ProtoError> {
        let trimmed = virtual_path.trim().trim_matches('/');
        if trimmed.is_empty() {
            return Ok(self.root.clone());
        }
        for seg in trimmed.split('/') {
            if seg.is_empty()
                || seg == "."
                || seg == ".."
                || seg.contains('\\')
                || seg.chars().any(char::is_control)
            {
                return Err(ProtoError::Transport(format!(
                    "Invalid synchronization path '{virtual_path}'."
                )));
            }
        }
        if is_saf_sync_root(&self.root) {
            Ok(join_saf_rel(&self.root, trimmed))
        } else {
            let mut pb = PathBuf::from(&self.root);
            for seg in trimmed.split('/') {
                pb.push(seg);
            }
            Ok(pb.to_string_lossy().into_owned())
        }
    }
}

#[async_trait::async_trait]
impl RemoteSession for LocalSyncSession {
    fn scheme(&self) -> ProtocolScheme {
        ProtocolScheme::Local
    }

    async fn pwd(&self) -> Result<String, ProtoError> {
        Ok("/".to_string())
    }

    async fn stat(&self, remote_path: &str) -> Result<Option<FileEntry>, ProtoError> {
        let target = self.resolve(remote_path)?;
        match self.local_fs.stat(&target) {
            Ok(entry) => Ok(Some(entry)),
            Err(linscp_platform::PlatformError::Io(ref err))
                if err.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(err) => Err(ProtoError::Transport(err.to_string())),
        }
    }

    async fn list_dir(&self, remote_path: &str) -> Result<Vec<FileEntry>, ProtoError> {
        let target = self.resolve(remote_path)?;
        self.local_fs
            .list_dir(&target)
            .map_err(|err| ProtoError::Transport(err.to_string()))
    }

    async fn mkdir(&self, remote_path: &str) -> Result<(), ProtoError> {
        let target = self.resolve(remote_path)?;
        self.local_fs
            .mkdir_all(&target)
            .map_err(|err| ProtoError::Transport(err.to_string()))
    }

    async fn remove_file(&self, remote_path: &str) -> Result<(), ProtoError> {
        let target = self.resolve(remote_path)?;
        self.local_fs
            .remove_file(&target)
            .map_err(|err| ProtoError::Transport(err.to_string()))
    }

    async fn remove_dir(&self, remote_path: &str) -> Result<(), ProtoError> {
        let target = self.resolve(remote_path)?;
        self.local_fs
            .remove_dir_all(&target)
            .map_err(|err| ProtoError::Transport(err.to_string()))
    }

    async fn rename(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        let src = self.resolve(from)?;
        let dst = self.resolve(to)?;
        self.local_fs
            .rename(&src, &dst)
            .map_err(|err| ProtoError::Transport(err.to_string()))
    }

    async fn copy_file(&self, from: &str, to: &str) -> Result<(), ProtoError> {
        let src = self.resolve(from)?;
        let dst = self.resolve(to)?;
        self.local_fs
            .copy_streamed(&src, &dst)
            .map(|_| ())
            .map_err(|err| ProtoError::Transport(err.to_string()))
    }

    async fn symlink(&self, _target: &str, _link_path: &str) -> Result<(), ProtoError> {
        Err(ProtoError::UnsupportedCapability(
            "symlink",
            ProtocolScheme::Local,
        ))
    }

    async fn chmod(&self, remote_path: &str, mode: u32) -> Result<(), ProtoError> {
        let target = self.resolve(remote_path)?;
        self.local_fs
            .set_permissions_mode(&target, mode)
            .map_err(|err| ProtoError::Transport(err.to_string()))
    }

    async fn set_mtime(&self, remote_path: &str, mtime: i64) -> Result<(), ProtoError> {
        let target = self.resolve(remote_path)?;
        self.local_fs
            .set_mtime(&target, mtime)
            .map_err(|err| ProtoError::Transport(err.to_string()))
    }

    async fn checksum(&self, algorithm: &str, remote_path: &str) -> Result<String, ProtoError> {
        use linscp_crypto::digests::{DigestAlgorithm, DigestHasher};
        use std::io::Read;

        let alg = DigestAlgorithm::parse(algorithm).ok_or_else(|| {
            ProtoError::Transport(format!("Unsupported checksum algorithm '{algorithm}'."))
        })?;
        let target = self.resolve(remote_path)?;
        if is_saf_sync_root(&target) {
            let stage = tempfile::Builder::new()
                .prefix("linscp-local-sync-hash-")
                .rand_bytes(16)
                .tempdir()
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            let staged_file = stage.path().join("contents");
            self.local_fs
                .stage_to_file(&target, &staged_file)
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            let mut file = std::fs::File::open(&staged_file)
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            let mut hasher = DigestHasher::new(alg);
            let mut buf = [0u8; 64 * 1024];
            loop {
                let n = file
                    .read(&mut buf)
                    .map_err(|e| ProtoError::Transport(e.to_string()))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            return Ok(hasher.finalize_hex());
        }
        let mut file =
            std::fs::File::open(&target).map_err(|e| ProtoError::Transport(e.to_string()))?;
        let mut hasher = DigestHasher::new(alg);
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize_hex())
    }

    async fn checksum_server_only(
        &self,
        algorithm: &str,
        remote_path: &str,
    ) -> Result<Option<String>, ProtoError> {
        self.checksum(algorithm, remote_path).await.map(Some)
    }

    async fn download(
        &self,
        remote_path: &str,
        opts: linscp_proto::TransferRequest,
        sink: &mut (dyn tokio::io::AsyncWrite + Unpin + Send),
        progress: Option<&linscp_proto::ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

        let target = self.resolve(remote_path)?;
        let mut stage_holder = None;
        let open_path = if is_saf_sync_root(&target) {
            let stage = tempfile::Builder::new()
                .prefix("linscp-local-sync-dl-")
                .rand_bytes(16)
                .tempdir()
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            let staged_file = stage.path().join("contents");
            self.local_fs
                .stage_to_file(&target, &staged_file)
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            stage_holder = Some(stage);
            staged_file
        } else {
            PathBuf::from(&target)
        };
        let mut file = tokio::fs::File::open(&open_path)
            .await
            .map_err(|e| ProtoError::Transport(e.to_string()))?;
        let total = file
            .metadata()
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        if opts.resume_offset > 0 {
            file.seek(std::io::SeekFrom::Start(opts.resume_offset))
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
        }
        let mut limiter = linscp_proto::RateLimiter::new(opts.speed_kbytes_per_sec);
        let mut copied = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = file
                .read(&mut buf)
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            if n == 0 {
                break;
            }
            sink.write_all(&buf[..n])
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            copied += n as u64;
            limiter.consume(n).await;
            if let Some(cb) = progress {
                cb(opts.resume_offset + copied, total);
            }
        }
        sink.flush()
            .await
            .map_err(|e| ProtoError::Transport(e.to_string()))?;
        drop(stage_holder);
        Ok(copied)
    }

    async fn upload(
        &self,
        remote_path: &str,
        opts: linscp_proto::TransferRequest,
        source: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
        total_size: Option<u64>,
        progress: Option<&linscp_proto::ProgressCallback>,
    ) -> Result<u64, ProtoError> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

        let target = self.resolve(remote_path)?;
        if is_saf_sync_root(&target) {
            let stage = tempfile::Builder::new()
                .prefix("linscp-local-sync-ul-")
                .rand_bytes(16)
                .tempdir()
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            let staged_file = stage.path().join("contents");
            let mut out = tokio::fs::File::create(&staged_file)
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            let mut limiter = linscp_proto::RateLimiter::new(opts.speed_kbytes_per_sec);
            let mut written = 0u64;
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = source
                    .read(&mut buf)
                    .await
                    .map_err(|e| ProtoError::Transport(e.to_string()))?;
                if n == 0 {
                    break;
                }
                out.write_all(&buf[..n])
                    .await
                    .map_err(|e| ProtoError::Transport(e.to_string()))?;
                written += n as u64;
                limiter.consume(n).await;
                if let Some(cb) = progress {
                    cb(written, total_size.unwrap_or(written));
                }
            }
            out.flush()
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            drop(out);
            self.local_fs
                .publish_from_file(&staged_file, &target)
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            if opts.preserve_time {
                if let Some(mt) = opts.mtime {
                    let _ = self.local_fs.set_mtime(&target, mt);
                }
            }
            return Ok(written);
        }

        let target_pb = PathBuf::from(&target);
        if let Some(parent) = target_pb.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
        }
        let mut out = if opts.append {
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&target_pb)
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?
        } else if opts.resume_offset > 0 {
            let mut f = tokio::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(&target_pb)
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            f.seek(std::io::SeekFrom::Start(opts.resume_offset))
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            f
        } else {
            tokio::fs::File::create(&target_pb)
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?
        };
        let mut limiter = linscp_proto::RateLimiter::new(opts.speed_kbytes_per_sec);
        let mut written = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = source
                .read(&mut buf)
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])
                .await
                .map_err(|e| ProtoError::Transport(e.to_string()))?;
            written += n as u64;
            limiter.consume(n).await;
            if let Some(cb) = progress {
                cb(
                    opts.resume_offset + written,
                    total_size.unwrap_or(opts.resume_offset + written),
                );
            }
        }
        out.flush()
            .await
            .map_err(|e| ProtoError::Transport(e.to_string()))?;
        drop(out);
        if let Some(mode) = opts.permissions {
            let _ = self.local_fs.set_permissions_mode(&target, mode);
        }
        if opts.preserve_time {
            if let Some(mt) = opts.mtime {
                let _ = self.local_fs.set_mtime(&target, mt);
            }
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_sync_entry_names_are_refused() {
        for name in ["", ".", "..", "../x.filepart", "a/b", "a\\b", "x:y", "bad\nname"] {
            assert!(!valid_sync_entry_name(name), "accepted {name:?}");
        }
        assert!(valid_sync_entry_name("normal file.txt"));
        #[cfg(windows)]
        for name in ["CON", "con.txt", "AUX.txt", "LPT1.txt", "COM9", "trailing.", "trailing ", "a?b"] {
            assert!(!valid_sync_entry_name(name), "accepted {name:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn invalid_utf8_local_names_are_not_lossily_synchronized() {
        use std::os::unix::ffi::OsStringExt;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(std::ffi::OsString::from_vec(vec![0xff])), b"data").unwrap();
        let mut entries = BTreeMap::new();
        let mut retained = BTreeSet::new();
        let error = collect_local_tree(tmp.path(), "", true, &FileMask::default(), &mut entries, &mut retained).unwrap_err();
        assert!(error.contains("non-UTF-8"), "{error}");
    }

    #[test]
    fn corrupt_sync_state_is_not_an_empty_baseline() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("history");
        assert!(SyncState::load(&file).is_ok());
        std::fs::write(&file, "file\tbad\t10\t20\n").unwrap();
        assert!(SyncState::load(&file).is_err());
        std::fs::write(&file, "truncated\n").unwrap();
        assert!(SyncState::load(&file).is_err());
    }

    #[test]
    fn sync_state_hash_and_tsv_match_cpp_planner() {
        let key = SyncState::make_key("example.com:22", "/local", "/remote");
        assert_eq!(SyncState::hash_key(&key).len(), 16);
        let tmp_dir =
            std::env::temp_dir().join(format!("linscp_syncstate_dir_{}", std::process::id()));
        let tmp = tmp_dir.join("sync.state");
        let mut st = SyncState::default();
        st.update(
            "dir/a\tb.txt".to_string(),
            SyncStateEntry {
                local_time: 100,
                remote_time: 100,
                size: 42,
            },
        );
        st.save(&tmp).unwrap();
        let loaded = SyncState::load(&tmp).unwrap();
        let _ = std::fs::remove_dir_all(&tmp_dir);
        assert_eq!(loaded.lookup("dir/a\tb.txt").unwrap().size, 42);
    }
}
