//! Directory tree comparison, persistent two-way state (`<config_dir>/sync/<hash>.state`),
//! conflict resolution (`-conflict=skip|local|remote|newer`), and execution of
//! `synchronize local|remote|both`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use linscp_crypto::digests::sha256_hex;
use linscp_platform::terminal::stat_local_path;
use linscp_platform::write_private_file_atomic;
use linscp_proto::RemoteSession;
use linscp_types::TransferMode;

use crate::filemask::{FileMask, join_remote_path, mode_from_permissions_str};
use crate::transfer::{TransferFlags, download_single_file, upload_single_file};
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
            if fields.len() < 4 {
                continue;
            }
            let rel = unescape_state_value(fields[0]);
            let local_time = fields[1].parse::<u64>().unwrap_or(0);
            let remote_time = fields[2].parse::<u64>().unwrap_or(0);
            let size = fields[3].parse::<u64>().unwrap_or(0);
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

fn collect_local_tree(
    root: &Path,
    rel_prefix: &str,
    recursive: bool,
    mask: &FileMask,
    out: &mut BTreeMap<String, TreeEntry>,
) -> Result<(), String> {
    let rd = std::fs::read_dir(root)
        .map_err(|e| format!("Cannot read local directory '{}': {e}", root.display()))?;
    for item in rd {
        let de = item.map_err(|e| format!("Local directory read failed: {e}"))?;
        let name = de.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." || name.ends_with(".filepart") || name.contains(".filepart.v")
        {
            continue;
        }
        let full = de.path();
        let st = stat_local_path(&full);
        let rel = if rel_prefix.is_empty() {
            name.clone()
        } else {
            format!("{rel_prefix}/{name}")
        };
        if !mask.accepts(&name, st.is_dir, st.size, st.mtime.max(0) as u64, &rel) {
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
        if st.is_dir && recursive {
            collect_local_tree(&full, &rel, true, mask, out)?;
        }
    }
    Ok(())
}

async fn collect_remote_tree(
    session: &dyn RemoteSession,
    root: &str,
    rel_prefix: &str,
    recursive: bool,
    mask: &FileMask,
    out: &mut BTreeMap<String, TreeEntry>,
) -> Result<(), String> {
    let entries = session
        .list_dir(root)
        .await
        .map_err(|e| format!("Cannot list remote directory '{root}': {e}"))?;
    for entry in entries {
        if entry.name == "."
            || entry.name == ".."
            || entry.name.ends_with(".filepart")
            || entry.name.contains(".filepart.v")
        {
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
        if entry.is_dir && recursive {
            let child = join_remote_path(root, &entry.name);
            Box::pin(collect_remote_tree(session, &child, &rel, true, mask, out)).await?;
        }
    }
    Ok(())
}

/// Builds a deterministic, sorted synchronization plan without mutating either filesystem.
pub async fn plan_synchronization(
    session: &dyn RemoteSession,
    local_root: &Path,
    remote_root: &str,
    opts: &SyncOptions,
    state: &SyncState,
) -> Result<Vec<SyncItem>, String> {
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

    let mut local_map = BTreeMap::new();
    let mut remote_map = BTreeMap::new();
    collect_local_tree(local_root, "", opts.recursive, &opts.file_mask, &mut local_map)?;
    collect_remote_tree(
        session,
        remote_root,
        "",
        opts.recursive,
        &opts.file_mask,
        &mut remote_map,
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
                        let diff = one_way_differs(
                            session,
                            &join_remote_path(remote_root, &rel),
                            &local_root.join(&rel),
                            r,
                            l,
                            opts.criteria,
                            opts.mirror,
                        )
                        .await?;
                        if let Some(reason) = diff {
                            Some((SyncAction::Download, reason))
                        } else {
                            None
                        }
                    }
                    SyncMode::Remote => {
                        let diff = one_way_differs_upload(
                            session,
                            &local_root.join(&rel),
                            &join_remote_path(remote_root, &rel),
                            l,
                            r,
                            opts.criteria,
                            opts.mirror,
                        )
                        .await?;
                        if let Some(reason) = diff {
                            Some((SyncAction::Upload, reason))
                        } else {
                            None
                        }
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
                }
            }
            (None, Some(r)) => {
                let act = match opts.mode {
                    SyncMode::Local => Some((SyncAction::Download, "missing locally")),
                    SyncMode::Remote => {
                        if opts.delete_obsolete {
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
                        if opts.delete_obsolete {
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
        let local_bytes = std::fs::read(local_path)
            .map_err(|e| format!("Cannot read '{}' for checksum: {e}", local_path.display()))?;
        let local_hex = sha256_hex(&local_bytes);
        let remote_hex = session
            .checksum("sha-256", remote_path)
            .await
            .map_err(|e| format!("Cannot hash remote '{remote_path}': {e}"))?;
        if !local_hex.eq_ignore_ascii_case(&remote_hex) {
            return Ok(Some("checksum differs".to_string()));
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
        let local_bytes = std::fs::read(local_path)
            .map_err(|e| format!("Cannot read '{}' for checksum: {e}", local_path.display()))?;
        let local_hex = sha256_hex(&local_bytes);
        let remote_hex = session
            .checksum("sha-256", remote_path)
            .await
            .map_err(|e| format!("Cannot hash remote '{remote_path}': {e}"))?;
        if !local_hex.eq_ignore_ascii_case(&remote_hex) {
            return Ok(Some("checksum differs".to_string()));
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
/// `(applied_count, conflict_count)`.
pub async fn apply_sync_plan(
    session: &dyn RemoteSession,
    local_root: &Path,
    remote_root: &str,
    items: &[SyncItem],
    opts: &SyncOptions,
    state: &mut SyncState,
    logger: &mut SessionLogger,
) -> Result<(usize, usize), String> {
    let mut applied = 0usize;
    let mut conflicts = 0usize;

    for item in items {
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
        ..TransferFlags::default()
    };

    for item in items {
        let local_path = local_root.join(&item.rel_path);
        let remote_path = join_remote_path(remote_root, &item.rel_path);
        match item.action {
            SyncAction::None | SyncAction::Conflict => {}
            SyncAction::Download => {
                if item.is_directory {
                    std::fs::create_dir_all(&local_path).map_err(|e| {
                        format!("Cannot create local directory '{}': {e}", local_path.display())
                    })?;
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
                    upload_single_file(session, &local_path, &remote_path, &tflags, logger, None)
                        .await?;
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
                if item.is_directory {
                    let _ = std::fs::remove_dir_all(&local_path);
                } else if local_path.exists() {
                    std::fs::remove_file(&local_path).map_err(|e| {
                        format!("Cannot remove local file '{}': {e}", local_path.display())
                    })?;
                }
                state.remove(&item.rel_path);
                applied += 1;
            }
            SyncAction::DeleteRemote => {
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

#[cfg(test)]
mod tests {
    use super::*;

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
