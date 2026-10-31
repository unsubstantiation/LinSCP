#![allow(unused_variables, unused_imports, dead_code, clippy::all)]
//! Priority transfer queue (`QueueManager`) with background Tokio worker,
//! pause/resume/cancel/retry/prioritize/clear, remote upload/download/move,
//! local-to-local copy/move (`ask`/`overwrite`/`skip`/`rename`), remote-to-remote
//! copy/move, staging file cleanup (`cleanup_path`), and `sync/run` + `keepuptodate`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use linscp_engine::filemask::join_remote_path;
use linscp_engine::keepuptodate::{run_keep_up_to_date, KeepUpToDateOptions};
use linscp_engine::sync_planner::{
    apply_sync_plan, plan_synchronization, SyncOptions, SyncState,
};
use linscp_engine::transfer::{
    download_directory_recursive, download_single_file, upload_directory_recursive,
    upload_single_file, TransferFlags,
};
use linscp_engine::xml_log::SessionLogger;
use linscp_platform::gui_os::create_local_symlink;
use linscp_platform::terminal::{set_local_file_times, set_local_permissions};
use linscp_proto::{ProgressCallback, RemoteSession};
use linscp_types::ProtocolScheme;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::sync::{broadcast, Notify};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictPolicy {
    Ask,
    Overwrite,
    Skip,
    Rename,
}

impl ConflictPolicy {
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.unwrap_or("ask").trim().to_ascii_lowercase().as_str() {
            "" | "ask" => Ok(Self::Ask),
            "overwrite" | "replace" => Ok(Self::Overwrite),
            "skip" => Ok(Self::Skip),
            "rename" => Ok(Self::Rename),
            other => Err(format!("Unsupported overwrite policy '{other}'.")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalConflictError {
    pub message: String,
    pub conflicts: Vec<String>,
}

#[derive(Clone)]
pub enum QueueJob {
    RemoteDownload {
        session: Arc<dyn RemoteSession>,
        remote_path: String,
        local_dest: PathBuf,
        allow_overwrite: bool,
        delete_source: bool,
        flags: TransferFlags,
    },
    RemoteUpload {
        session: Arc<dyn RemoteSession>,
        local_src: PathBuf,
        remote_dest: String,
        allow_overwrite: bool,
        delete_source: bool,
        cleanup_path: Option<PathBuf>,
        flags: TransferFlags,
    },
    LocalCopyOrMove {
        source: PathBuf,
        target: PathBuf,
        move_item: bool,
        policy: ConflictPolicy,
    },
    DavMove {
        session: Arc<dyn RemoteSession>,
        source: String,
        target: String,
        etag: String,
        is_dir: bool,
    },
    CrossServerMove {
        source_session: Arc<dyn RemoteSession>,
        target_session: Arc<dyn RemoteSession>,
        source: String,
        target: String,
        etag: String,
        source_entry: linscp_types::FileEntry,
    },
    RemoteToRemote {
        src_session: Arc<dyn RemoteSession>,
        dst_session: Arc<dyn RemoteSession>,
        same_endpoint: bool,
        src_path: String,
        dst_path: String,
        move_item: bool,
        staging_root: PathBuf,
    },
    SyncRun {
        session: Arc<dyn RemoteSession>,
        config_dir: PathBuf,
        host_key: String,
        local_root: PathBuf,
        remote_root: String,
        opts: SyncOptions,
    },
    KeepUpToDate {
        session: Arc<dyn RemoteSession>,
        local_root: PathBuf,
        remote_root: String,
        opts: KeepUpToDateOptions,
    },
}

// Directory copies reject symlinks and use no-replace publication for files.
// Approved merges do not replace files and may leave already-copied entries on
// error. New downloaded trees are staged privately before atomic publication.
fn safe_tree_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name == "." || name == ".." || (name.contains('/') || name.contains('\\') || name.contains(':')) || name.chars().any(char::is_control) || Path::new(name).components().count() != 1 {
        return Err("Invalid directory entry name.".to_string());
    }
    Ok(())
}

// The staged tree is on the destination filesystem. Publication uses atomic
// create-if-absent hard links; never delete entries already merged on failure,
// since another actor may have replaced them in the meantime.
fn merge_staged_local_tree(stage: &Path, target: &Path, cancel: &AtomicBool, depth: usize) -> Result<(), String> {
    if depth > 64 { return Err("Directory nesting limit exceeded.".to_string()); }
    if cancel.load(Ordering::SeqCst) { return Err("Transfer cancelled during merge publication.".to_string()); }
    let target_meta = std::fs::symlink_metadata(target).map_err(|e| format!("Cannot inspect merge directory '{}': {e}", target.display()))?;
    if !target_meta.is_dir() || target_meta.file_type().is_symlink() { return Err(format!("Merge destination '{}' is not a directory.", target.display())); }
    for entry in std::fs::read_dir(stage).map_err(|e| format!("Cannot read staged tree: {e}"))? {
        if cancel.load(Ordering::SeqCst) { return Err("Transfer cancelled during merge publication.".to_string()); }
        let entry = entry.map_err(|e| format!("Cannot read staged entry: {e}"))?;
        let name = entry.file_name();
        let name_text = name.to_str().ok_or("Invalid staged entry name")?;
        safe_tree_name(name_text)?;
        let src = entry.path(); let dst = target.join(&name);
        let meta = std::fs::symlink_metadata(&src).map_err(|e| format!("Cannot inspect staged entry: {e}"))?;
        if meta.file_type().is_symlink() { return Err("Refusing a staged symlink.".to_string()); }
        if meta.is_dir() {
            match std::fs::create_dir(&dst) {
                Ok(()) => {},
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {},
                Err(error) => return Err(format!("Cannot create merge directory '{}': {error}", dst.display())),
            }
            merge_staged_local_tree(&src, &dst, cancel, depth + 1)?;
        } else if meta.is_file() {
            std::fs::hard_link(&src, &dst).map_err(|e| format!("Cannot publish merge file '{}': {e}", dst.display()))?;
        } else { return Err("Refusing a staged non-file.".to_string()); }
    }
    Ok(())
}

async fn download_new_sftp_tree(
    session: &dyn RemoteSession, remote: &str, local: &Path,
    flags: &TransferFlags, logger: &mut SessionLogger, progress: Option<&ProgressCallback>, depth: usize,
) -> Result<(), String> {
    if depth > 64 { return Err("Directory nesting limit exceeded.".to_string()); }
    if flags.cancel_flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst)) { return Err("Transfer cancelled.".to_string()); }
    let entry = session.stat(remote).await.map_err(|e| e.to_string())?.ok_or("Remote directory disappeared.")?;
    if !entry.is_dir || entry.is_symlink { return Err("Remote directory changed or is a symlink.".to_string()); }
    match std::fs::symlink_metadata(local) {
        Ok(meta) if flags.merge_directories && meta.is_dir() && !meta.file_type().is_symlink() => {},
        Ok(_) => return Err(format!("Directory destination '{}' already exists or is not a directory.", local.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(local).map_err(|e| format!("Cannot create new directory '{}': {e}", local.display()))?,
        Err(error) => return Err(format!("Cannot inspect directory '{}': {error}", local.display())),
    }
    let entries = session.list_dir(remote).await.map_err(|e| e.to_string())?;
    if entries.len() > 100_000 { return Err("Directory entry limit exceeded.".to_string()); }
    for item in entries {
        if item.name == "." || item.name == ".." { continue; }
        safe_tree_name(&item.name)?;
        if item.is_symlink { return Err("Refusing to transfer a remote symlink.".to_string()); }
        let from = join_remote_path(remote, &item.name);
        let to = local.join(&item.name);
        let current = session.stat(&from).await.map_err(|e| e.to_string())?.ok_or("Remote entry disappeared.")?;
        if current.is_symlink { return Err("Refusing to transfer a remote symlink.".to_string()); }
        if current.is_dir {
            Box::pin(download_new_sftp_tree(session, &from, &to, flags, logger, progress, depth + 1)).await?;
        } else {
            if flags.merge_directories {
                match std::fs::symlink_metadata(&to) {
                    Ok(_) => return Err(format!("Cannot merge: destination '{}' already exists.", to.display())),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
                    Err(error) => return Err(format!("Cannot inspect '{}': {error}", to.display())),
                }
            }
            download_single_file(session, &from, Some(&current), &to, flags, logger, progress).await?;
        }
    }
    Ok(())
}

async fn upload_new_sftp_tree(
    session: &dyn RemoteSession, local: &Path, remote: &str,
    flags: &TransferFlags, logger: &mut SessionLogger, progress: Option<&ProgressCallback>, depth: usize,
) -> Result<(), String> {
    if depth > 64 { return Err("Directory nesting limit exceeded.".to_string()); }
    if flags.cancel_flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst)) { return Err("Transfer cancelled.".to_string()); }
    let meta = std::fs::symlink_metadata(local).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.file_type().is_symlink() { return Err("Local directory changed or is a symlink.".to_string()); }
    match session.stat(remote).await.map_err(|e| e.to_string())? {
        Some(entry) if flags.merge_directories && entry.is_dir && !entry.is_symlink => {},
        Some(_) => return Err(format!("Directory destination '{remote}' already exists or is not a directory.")),
        None => session.mkdir(remote).await.map_err(|e| e.to_string())?,
    }
    let entries = std::fs::read_dir(local).map_err(|e| e.to_string())?;
    let mut count = 0usize;
    for entry in entries {
        count += 1;
        if count > 100_000 { return Err("Directory entry limit exceeded.".to_string()); }
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().into_string().map_err(|_| "Non-UTF-8 file name is not supported.".to_string())?;
        safe_tree_name(&name)?;
        let from = entry.path();
        let to = join_remote_path(remote, &name);
        let meta = std::fs::symlink_metadata(&from).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() { return Err("Refusing to transfer a local symlink.".to_string()); }
        if meta.is_dir() {
            Box::pin(upload_new_sftp_tree(session, &from, &to, flags, logger, progress, depth + 1)).await?;
        } else if meta.is_file() {
            if flags.merge_directories {
                match session.stat(&to).await.map_err(|e| e.to_string())? {
                    Some(_) => return Err(format!("Cannot merge: destination '{to}' already exists.")),
                    None => {},
                }
            }
            upload_single_file(session, &from, &to, flags, logger, progress).await?;
        } else { return Err("Refusing to transfer a non-file.".to_string()); }
    }
    Ok(())
}

fn task_supports_cancellation(job: &QueueJob) -> bool {
    match job {
        QueueJob::LocalCopyOrMove { .. } | QueueJob::CrossServerMove { .. } => true,
        QueueJob::RemoteDownload { session, .. } => {
            matches!(session.scheme(), ProtocolScheme::Sftp | ProtocolScheme::Dav | ProtocolScheme::Davs | ProtocolScheme::Webdav | ProtocolScheme::Webdavs | ProtocolScheme::S3 | ProtocolScheme::Ftp | ProtocolScheme::Ftps | ProtocolScheme::Ftpes)
        }
        QueueJob::RemoteUpload { session, .. } => {
            matches!(session.scheme(), ProtocolScheme::Sftp | ProtocolScheme::Dav | ProtocolScheme::Davs | ProtocolScheme::Webdav | ProtocolScheme::Webdavs)
        }
        _ => false,
    }
}

#[derive(Clone)]
pub struct QueuedTransferTask {
    pub id: u64,
    pub tab_id: Option<u64>,
    pub direction: String,
    pub label: String,
    pub source: String,
    pub destination: String,
    pub status: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub speed_bps: u64,
    pub error: Option<String>,
    pub cancel_flag: Arc<AtomicBool>,
    pub job: QueueJob,
}

impl QueuedTransferTask {
    pub fn as_json(&self) -> Value {
        let progress = if self.status == "completed" {
            100.0
        } else if self.bytes_total > 0 {
            ((self.bytes_done as f64 / self.bytes_total as f64) * 100.0).clamp(0.0, 100.0)
        } else {
            0.0
        };
        let (local_path, remote_path) = if self.direction.starts_with("upload")
            || self.direction == "keepuptodate"
        {
            (&self.source, &self.destination)
        } else {
            (&self.destination, &self.source)
        };
        json!({
            "id": self.id,
            "tab_id": self.tab_id,
            "direction": self.direction,
            "label": self.label,
            "source": self.source,
            "destination": self.destination,
            "local_path": local_path,
            "remote_path": remote_path,
            "status": match self.status.as_str() { "queued" => "Queued", "running" => "Running", "completed" => "Completed", "failed" => "Failed", "cancelled" => "Cancelled", other => other },
            "type": self.direction,
            "percent": progress,
            "bytes_done": self.bytes_done,
            "bytes_transferred": self.bytes_done,
            "bytes_total": self.bytes_total,
            "progress": progress,
            "speed_bps": self.speed_bps,
            "error": self.error,
        })
    }

    pub fn cleanup_staging(&self) {
        if let QueueJob::RemoteUpload {
            cleanup_path: Some(ref p),
            ..
        } = self.job
        {
            let _ = remove_path_any(p);
        }
    }
}

struct QueueState {
    next_id: u64,
    paused: bool,
    worker_started: bool,
    tasks: Vec<QueuedTransferTask>,
}

#[derive(Clone)]
pub struct QueueManager {
    inner: Arc<Mutex<QueueState>>,
    notify: Arc<Notify>,
    event_tx: broadcast::Sender<Value>,
}

impl QueueManager {
    pub fn new(event_tx: broadcast::Sender<Value>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(QueueState {
                next_id: 1,
                paused: false,
                worker_started: false,
                tasks: Vec::new(),
            })),
            notify: Arc::new(Notify::new()),
            event_tx,
        }
    }

    fn ensure_worker_running(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let should_spawn = {
            let mut g = self.inner.lock().expect("queue mutex");
            if g.worker_started {
                false
            } else {
                g.worker_started = true;
                true
            }
        };
        if should_spawn {
            let q = self.clone();
            handle.spawn(async move {
                q.worker_loop().await;
            });
        }
    }

    pub fn snapshot(&self) -> (Vec<Value>, bool) {
        let g = self.inner.lock().expect("queue mutex");
        let list = g.tasks.iter().map(QueuedTransferTask::as_json).collect();
        (list, g.paused)
    }

    pub fn is_paused(&self) -> bool {
        self.inner.lock().map(|g| g.paused).unwrap_or(false)
    }

    pub fn enqueue(
        &self,
        tab_id: Option<u64>,
        direction: &str,
        label: String,
        source: String,
        destination: String,
        bytes_total: u64,
        high_priority: bool,
        job: QueueJob,
    ) -> u64 {
        let id = {
            let mut g = self.inner.lock().expect("queue mutex");
            let id = g.next_id;
            g.next_id += 1;
            let task = QueuedTransferTask {
                id,
                tab_id,
                direction: direction.to_string(),
                label,
                source,
                destination,
                status: "queued".to_string(),
                bytes_done: 0,
                bytes_total,
                speed_bps: 0,
                error: None,
                cancel_flag: Arc::new(AtomicBool::new(false)),
                job,
            };
            if high_priority {
                let pos = g
                    .tasks
                    .iter()
                    .position(|t| t.status == "queued")
                    .unwrap_or(g.tasks.len());
                g.tasks.insert(pos, task);
            } else {
                g.tasks.push(task);
            }
            id
        };
        self.broadcast_snapshot();
        self.ensure_worker_running();
        self.notify.notify_waiters();
        id
    }

    pub fn pause(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.paused = true;
        }
        self.broadcast_snapshot();
    }

    pub fn resume(&self) {
        if let Ok(mut g) = self.inner.lock() {
            g.paused = false;
        }
        self.broadcast_snapshot();
        self.ensure_worker_running();
        self.notify.notify_waiters();
    }

    pub fn cancel(&self, id: u64) -> bool {
        let mut changed = false;
        let mut to_clean: Option<QueuedTransferTask> = None;
        {
            let mut g = self.inner.lock().expect("queue mutex");
            if let Some(t) = g.tasks.iter_mut().find(|t| t.id == id) {
                if t.status == "queued" {
                    t.cancel_flag.store(true, Ordering::SeqCst);
                    t.status = "cancelled".to_string();
                    t.error = Some("Cancelled by user.".to_string());
                    to_clean = Some(t.clone());
                    changed = true;
                } else if t.status == "running" && task_supports_cancellation(&t.job) {
                    t.cancel_flag.store(true, Ordering::SeqCst);
                    changed = true;
                }
            }
        }
        if let Some(task) = to_clean {
            task.cleanup_staging();
        }
        if changed {
            self.broadcast_snapshot();
            self.notify.notify_waiters();
        }
        changed
    }

    pub fn cancel_for_tab(&self, tab_id: u64) {
        let mut clean_list = Vec::new();
        {
            let mut g = self.inner.lock().expect("queue mutex");
            for t in &mut g.tasks {
                if t.tab_id == Some(tab_id) && (t.status == "queued" || (t.status == "running" && task_supports_cancellation(&t.job))) {
                    t.cancel_flag.store(true, Ordering::SeqCst);
                    if t.status == "queued" {
                        t.status = "cancelled".to_string();
                        t.error = Some("Tab closed.".to_string());
                        clean_list.push(t.clone());
                    }
                }
            }
        }
        for t in clean_list {
            t.cleanup_staging();
        }
        self.broadcast_snapshot();
    }

    pub fn retry(&self, id: u64) -> bool {
        let mut ok = false;
        {
            let mut g = self.inner.lock().expect("queue mutex");
            if let Some(t) = g.tasks.iter_mut().find(|t| t.id == id) {
                if t.status == "failed" || t.status == "cancelled" {
                    if let QueueJob::RemoteUpload {
                        cleanup_path: Some(ref p),
                        ..
                    } = t.job
                    {
                        if !p.exists() {
                            return false;
                        }
                    }
                    t.status = "queued".to_string();
                    t.bytes_done = 0;
                    t.speed_bps = 0;
                    t.error = None;
                    t.cancel_flag = Arc::new(AtomicBool::new(false));
                    ok = true;
                }
            }
        }
        if ok {
            self.broadcast_snapshot();
            self.ensure_worker_running();
            self.notify.notify_waiters();
        }
        ok
    }

    pub fn prioritize(&self, id: u64, action: &str) -> bool {
        let mut g = self.inner.lock().expect("queue mutex");
        let Some(idx) = g
            .tasks
            .iter()
            .position(|t| t.id == id && t.status == "queued")
        else {
            return false;
        };
        let queued_indices: Vec<usize> = g
            .tasks
            .iter()
            .enumerate()
            .filter_map(|(i, t)| (t.status == "queued").then_some(i))
            .collect();
        let Some(qpos) = queued_indices.iter().position(|&i| i == idx) else {
            return false;
        };
        match action {
            "top" => {
                let first = queued_indices[0];
                if idx != first {
                    let item = g.tasks.remove(idx);
                    g.tasks.insert(first, item);
                }
            }
            "bottom" => {
                let last = *queued_indices.last().unwrap_or(&idx);
                if idx != last {
                    let item = g.tasks.remove(idx);
                    g.tasks.insert(last, item);
                }
            }
            "up" => {
                if qpos > 0 {
                    let prev_idx = queued_indices[qpos - 1];
                    g.tasks.swap(idx, prev_idx);
                }
            }
            "down" => {
                if qpos + 1 < queued_indices.len() {
                    let next_idx = queued_indices[qpos + 1];
                    g.tasks.swap(idx, next_idx);
                }
            }
            _ => return false,
        }
        drop(g);
        self.broadcast_snapshot();
        true
    }

    pub fn clear_finished(&self) {
        let removed: Vec<QueuedTransferTask> = {
            let mut g = self.inner.lock().expect("queue mutex");
            let mut rem = Vec::new();
            g.tasks.retain(|t| {
                let done = matches!(t.status.as_str(), "completed" | "failed" | "cancelled");
                if done {
                    rem.push(t.clone());
                }
                !done
            });
            rem
        };
        for t in removed {
            t.cleanup_staging();
        }
        self.broadcast_snapshot();
    }

    fn broadcast_snapshot(&self) {
        if self.event_tx.receiver_count() > 0 {
            let (transfers, paused) = self.snapshot();
            let _ = self.event_tx.send(json!({
                "type": "transfers",
                "transfers": transfers,
                "paused": paused,
            }));
        }
    }

    async fn worker_loop(&self) {
        loop {
            let next_task = {
                let mut g = self.inner.lock().expect("queue mutex");
                if g.paused {
                    None
                } else if let Some(t) = g.tasks.iter_mut().find(|t| t.status == "queued") {
                    t.status = "running".to_string();
                    t.error = None;
                    Some(t.clone())
                } else {
                    None
                }
            };

            let Some(task) = next_task else {
                self.notify.notified().await;
                continue;
            };
            self.broadcast_snapshot();

            let result = self.execute_task(&task).await;
            let cancelled = task.cancel_flag.load(Ordering::SeqCst);

            let should_cleanup = {
                let mut g = self.inner.lock().expect("queue mutex");
                let mut clean = false;
                if let Some(t) = g.tasks.iter_mut().find(|t| t.id == task.id) {
                    let committed_move_failure = result.as_ref().is_err_and(|e| e.starts_with("Move incomplete:"));
                    if cancelled && result.is_err() && !committed_move_failure {
                        t.status = "cancelled".to_string();
                        let reconnect = match &task.job { QueueJob::RemoteDownload { session, .. } | QueueJob::RemoteUpload { session, .. } => matches!(session.scheme(), ProtocolScheme::Ftp | ProtocolScheme::Ftps | ProtocolScheme::Ftpes), _ => false };
                        t.error = Some(if reconnect { format!("Cancelled by user. Reconnect the FTP session before further transfers. {}", result.as_ref().err().map(String::as_str).unwrap_or("A temporary file may remain.")) } else if matches!(&task.job, QueueJob::RemoteDownload { flags, .. } if flags.merge_directories) { "Cancelled by user. A merge that had begun publication may have left files in the destination.".to_string() } else if matches!(&task.job, QueueJob::RemoteUpload { .. }) { "Cancelled by user. A partial or completed remote destination or temporary file may remain; inspect it before retrying.".to_string() } else { "Cancelled by user.".to_string() });
                        clean = true;
                    } else {
                        match result {
                            Ok(()) => {
                                t.status = "completed".to_string();
                                if t.bytes_total > 0 {
                                    t.bytes_done = t.bytes_total;
                                }
                                clean = true;
                            }
                            Err(err) => {
                                t.status = "failed".to_string();
                                t.error = Some(err);
                            }
                        }
                    }
                    t.speed_bps = 0;
                }
                clean
            };

            if should_cleanup {
                task.cleanup_staging();
            }
            self.broadcast_snapshot();
        }
    }

    fn make_progress_cb(&self, task_id: u64, cancel_flag: Arc<AtomicBool>) -> Arc<dyn Fn(u64, u64) + Send + Sync> {
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();
        let started = Instant::now();
        let last_emit = Mutex::new(Instant::now() - Duration::from_secs(1));
        Arc::new(move |done: u64, total: u64| {
            if cancel_flag.load(Ordering::SeqCst) {
                return;
            }
            loop {
                let paused = inner.lock().map(|g| g.paused).unwrap_or(false);
                if !paused {
                    break;
                }
                if cancel_flag.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
            let elapsed = started.elapsed().as_secs_f64().max(0.001);
            let speed = (done as f64 / elapsed) as u64;
            if let Ok(mut g) = inner.lock() {
                if let Some(t) = g.tasks.iter_mut().find(|t| t.id == task_id) {
                    t.bytes_done = done;
                    if total > 0 {
                        t.bytes_total = total;
                    }
                    t.speed_bps = speed;
                }
            }
            if let Ok(mut le) = last_emit.lock() {
                if le.elapsed() >= Duration::from_millis(120) {
                    *le = Instant::now();
                    if event_tx.receiver_count() > 0 {
                        if let Ok(g) = inner.lock() {
                            let list: Vec<Value> =
                                g.tasks.iter().map(QueuedTransferTask::as_json).collect();
                            let _ = event_tx.send(json!({
                                "type": "transfers",
                                "transfers": list,
                                "paused": g.paused,
                            }));
                        }
                    }
                }
            }
        })
    }

    async fn execute_task(&self, task: &QueuedTransferTask) -> Result<(), String> {
        if task.cancel_flag.load(Ordering::SeqCst) {
            return Err("Cancelled by user.".to_string());
        }
        let progress = self.make_progress_cb(task.id, Arc::clone(&task.cancel_flag));
        let mut logger = SessionLogger::open(None, 0, false, None, None, false, "").unwrap();

        match &task.job {
            QueueJob::RemoteDownload {
                session,
                remote_path,
                local_dest,
                allow_overwrite,
                delete_source,
                flags,
            } => {
                let entry = session
                    .stat(remote_path)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("Remote item '{remote_path}' does not exist."))?;
                if let Ok(meta) = std::fs::symlink_metadata(local_dest) {
                    let allowed_dir = entry.is_dir && flags.merge_directories && meta.is_dir() && !meta.file_type().is_symlink();
                    let allowed_file = !entry.is_dir && *allow_overwrite && meta.is_file() && !meta.file_type().is_symlink();
                    if !allowed_dir && !allowed_file { return Err("Destination changed or merge/overwrite was not approved.".to_string()); }
                }
                let mut f = flags.clone();
                // Moves delete separately with the original ETag, only after
                // no-replace local publication has succeeded.
                f.delete_source = false;
                f.cancel_flag = Some(Arc::clone(&task.cancel_flag));
                f.no_clobber = !allow_overwrite;
                f.cleanup_download_stage = true;
                if entry.is_dir {
                    if session.scheme() != ProtocolScheme::Sftp || *delete_source { return Err("Only SFTP directory copies are supported.".to_string()); }
                    f.no_clobber = true;
                    // Stage both new trees and merges privately. Cancelling a
                    // download before publication leaves an existing tree alone.
                    let parent = local_dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
                    let stage = tempfile::Builder::new().prefix(".linscp-tree-").rand_bytes(16).tempdir_in(parent)
                        .map_err(|e| format!("Cannot create temporary directory in '{}': {e}", parent.display()))?;
                    let staged_tree = stage.path().join("contents");
                    let mut stage_flags = f.clone(); stage_flags.merge_directories = false;
                    download_new_sftp_tree(session.as_ref(), remote_path, &staged_tree, &stage_flags, &mut logger, Some(&*progress), 0).await?;
                    if task.cancel_flag.load(Ordering::SeqCst) { return Err("Transfer cancelled before publication.".to_string()); }
                    if f.merge_directories {
                        merge_staged_local_tree(&staged_tree, local_dest, &task.cancel_flag, 0)?;
                    } else {
                        linscp_platform::gui_os::rename_no_replace(&staged_tree, local_dest)
                            .map_err(|e| format!("Cannot publish downloaded directory '{}': {e}", local_dest.display()))?;
                    }
                } else {
                    if entry.is_symlink { return Err("Refusing to transfer a remote symlink.".to_string()); }
                    if f.resume {
                        linscp_engine::transfer::download_verified_resume(session.as_ref(), remote_path, &entry, local_dest, &f, &mut logger, Some(&*progress)).await?;
                    } else {
                        download_single_file(session.as_ref(), remote_path, Some(&entry), local_dest, &f, &mut logger, Some(&*progress)).await?;
                    }
                    if *delete_source {
                        let etag = f.source_etag.as_deref().ok_or("Move incomplete: local file was published but source identity is missing.")?;
                        session.remove_if_match(remote_path, etag).await.map_err(|e| format!("Move incomplete: local file was published, but remote source deletion could not be confirmed; the source may or may not exist: {e}"))?;
                    }
                }
                Ok(())
            }
            QueueJob::RemoteUpload {
                session,
                local_src,
                remote_dest,
                allow_overwrite,
                delete_source,
                flags,
                ..
            } => {
                let source_meta = std::fs::symlink_metadata(local_src).map_err(|e| format!("Cannot inspect local source '{}': {e}", local_src.display()))?;
                if let Some(entry) = session.stat(remote_dest).await.map_err(|e| e.to_string())? {
                    let allowed_dir = source_meta.is_dir() && !source_meta.file_type().is_symlink() && flags.merge_directories && entry.is_dir && !entry.is_symlink;
                    let allowed_file = source_meta.is_file() && *allow_overwrite && !entry.is_dir && !entry.is_symlink;
                    if !allowed_dir && !allowed_file { return Err("Destination changed or merge/overwrite was not approved.".to_string()); }
                }
                if !flags.ftp_risky_publish { if let Some(stage) = linscp_engine::transfer::remote_stage_path(remote_dest, None) {
                    if session.stat(&stage).await.map_err(|e| e.to_string())?.is_some() {
                        return Err(format!("A partial file already exists at '{stage}'; remove it before retrying."));
                    }
                }
                }
                let meta = source_meta;
                let mut f = flags.clone();
                f.delete_source = *delete_source;
                f.cancel_flag = Some(Arc::clone(&task.cancel_flag));
                // Fail closed if the protocol has no atomic exclusive-create capability.
                f.no_clobber = !allow_overwrite;
                if meta.is_dir() {
                    if session.scheme() != ProtocolScheme::Sftp || *delete_source { return Err("Only SFTP directory copies are supported.".to_string()); }
                    f.no_clobber = true;
                    upload_new_sftp_tree(session.as_ref(), local_src, remote_dest, &f, &mut logger, Some(&*progress), 0).await
                        .map_err(|e| format!("Upload failed; a partial remote tree may remain: {e}"))?;
                } else {
                    if meta.file_type().is_symlink() || !meta.is_file() { return Err("Refusing to transfer a symlink or non-file.".to_string()); }
                    upload_single_file(
                        session.as_ref(),
                        local_src,
                        remote_dest,
                        &f,
                        &mut logger,
                        Some(&*progress),
                    )
                    .await.map_err(|e| format!("Upload failed; a partial or completed remote destination or temporary file may remain: {e}"))?;
                }
                Ok(())
            }
            QueueJob::LocalCopyOrMove {
                source,
                target,
                move_item,
                policy,
            } => {
                let src = source.clone();
                let dst = target.clone();
                let mv = *move_item;
                let pol = *policy;
                let cancel = Arc::clone(&task.cancel_flag);
                let prog = progress.clone();
                tokio::task::spawn_blocking(move || {
                    execute_local_item(&src, &dst, mv, pol, &cancel, &*prog)
                })
                .await
                .map_err(|e| format!("Local worker panicked: {e}"))?
            }
            QueueJob::CrossServerMove { source_session, target_session, source, target, etag, source_entry } => {
                let stage = tempfile::Builder::new().prefix("linscp-cross-move-").rand_bytes(16).tempdir()
                    .map_err(|e| format!("Cannot create local move staging directory: {e}"))?;
                let payload = stage.path().join("payload");
                let mut download_flags = TransferFlags::default();
                download_flags.no_clobber = true;
                download_flags.cleanup_download_stage = true;
                download_flags.resume_support = linscp_engine::presets::ResumeSupportMode::On;
                download_flags.source_etag = Some(etag.clone());
                download_flags.cancel_flag = Some(Arc::clone(&task.cancel_flag));
                download_single_file(source_session.as_ref(), source, Some(source_entry), &payload, &download_flags, &mut logger, Some(&*progress)).await?;
                let staged_len = std::fs::metadata(&payload).map_err(|e| format!("Cannot inspect staged move: {e}"))?.len();
                if staged_len != source_entry.size { return Err("Source length changed during conditional download; source remains.".to_string()); }
                if task.cancel_flag.load(Ordering::SeqCst) { return Err("Cancelled before upload; source remains.".to_string()); }
                let mut upload_flags = TransferFlags::default();
                upload_flags.no_clobber = true;
                upload_flags.preserve_time = false;
                upload_flags.cancel_flag = Some(Arc::clone(&task.cancel_flag));
                upload_single_file(target_session.as_ref(), &payload, target, &upload_flags, &mut logger, Some(&*progress)).await
                    .map_err(|e| format!("Move incomplete: source remains; destination may contain a partial or completed file: {e}"))?;
                if task.cancel_flag.load(Ordering::SeqCst) { return Err("Move incomplete: destination was uploaded; cancellation left the source in place.".to_string()); }
                source_session.remove_if_match(source, etag).await
                    .map_err(|e| format!("Move incomplete: destination was uploaded; source deletion was not confirmed and the source may or may not remain: {e}"))?;
                Ok(())
            }
            QueueJob::DavMove { session, source, target, etag, is_dir } => {
                if task.cancel_flag.load(Ordering::SeqCst) { return Err("Cancelled by user.".to_string()); }
                session.dav_move_if_match(source, target, etag, *is_dir).await
                    .map_err(|e| format!("Move incomplete: {e}"))?;
                Ok(())
            }
            QueueJob::RemoteToRemote {
                src_session,
                dst_session,
                same_endpoint,
                src_path,
                dst_path,
                move_item,
                staging_root,
            } => {
                execute_remote_to_remote(
                    src_session.as_ref(),
                    dst_session.as_ref(),
                    *same_endpoint,
                    src_path,
                    dst_path,
                    *move_item,
                    staging_root,
                    &*progress,
                )
                .await
            }
            QueueJob::SyncRun {
                session,
                config_dir,
                host_key,
                local_root,
                remote_root,
                opts,
            } => {
                let state_key = SyncState::make_key(
                    host_key,
                    &local_root.to_string_lossy(),
                    remote_root,
                );
                let state_file = SyncState::state_path(config_dir, &state_key);
                let mut state = SyncState::load(&state_file).unwrap_or_default();
                let items = plan_synchronization(
                    session.as_ref(),
                    local_root,
                    remote_root,
                    opts,
                    &state,
                )
                .await?;
                apply_sync_plan(
                    session.as_ref(),
                    local_root,
                    remote_root,
                    &items,
                    opts,
                    &mut state,
                    &mut logger,
                )
                .await?;
                let _ = state.save(&state_file);
                Ok(())
            }
            QueueJob::KeepUpToDate {
                session,
                local_root,
                remote_root,
                opts,
            } => {
                run_keep_up_to_date(
                    session.as_ref(),
                    local_root,
                    remote_root,
                    opts,
                    &mut logger,
                    |_| {},
                )
                .await
                .map(|_| ())
            }
        }
    }
}

pub fn check_local_conflicts_and_overlap(
    sources: &[PathBuf],
    dest_dir: &Path,
    policy: ConflictPolicy,
) -> Result<(), LocalConflictError> {
    let canon_dest = std::fs::canonicalize(dest_dir).unwrap_or_else(|_| dest_dir.to_path_buf());
    let mut conflicts = Vec::new();

    for src in sources {
        let Some(name_os) = src.file_name() else {
            return Err(LocalConflictError {
                message: format!("Invalid source path '{}'.", src.display()),
                conflicts: Vec::new(),
            });
        };
        let name = name_os.to_string_lossy().into_owned();
        let target = dest_dir.join(name_os);

        if src == &target {
            return Err(LocalConflictError {
                message: format!("Source and destination are identical ('{name}')."),
                conflicts: Vec::new(),
            });
        }
        if let Ok(canon_src) = std::fs::canonicalize(src) {
            if canon_src.is_dir() && canon_dest.starts_with(&canon_src) {
                return Err(LocalConflictError {
                    message: format!(
                        "Cannot copy or move directory '{name}' into itself or one of its subdirectories."
                    ),
                    conflicts: Vec::new(),
                });
            }
        }

        if policy == ConflictPolicy::Ask && std::fs::symlink_metadata(&target).is_ok() {
            conflicts.push(name);
        }
    }

    if !conflicts.is_empty() {
        return Err(LocalConflictError {
            message: format!(
                "{} destination item(s) already exist: {}",
                conflicts.len(),
                conflicts.join(", ")
            ),
            conflicts,
        });
    }
    Ok(())
}

fn unique_local_target(target: &Path) -> PathBuf {
    if std::fs::symlink_metadata(target).is_err() {
        return target.to_path_buf();
    }
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let file_name = target
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "item".to_string());
    let (stem, ext) = match file_name.rfind('.') {
        Some(idx) if idx > 0 => (&file_name[..idx], &file_name[idx..]),
        _ => (file_name.as_str(), ""),
    };
    for n in 1..10_000 {
        let candidate = parent.join(format!("{stem} ({n}){ext}"));
        if std::fs::symlink_metadata(&candidate).is_err() {
            return candidate;
        }
    }
    let mut rnd = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut rnd);
    parent.join(format!(
        "{stem}-{}{ext}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

pub fn remove_path_any(path: &Path) -> Result<(), String> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        std::fs::remove_file(path).map_err(|e| e.to_string())
    } else {
        std::fs::remove_dir_all(path).map_err(|e| e.to_string())
    }
}

fn execute_local_item(
    source: &Path,
    target: &Path,
    move_item: bool,
    policy: ConflictPolicy,
    cancel: &AtomicBool,
    progress: &ProgressCallback,
) -> Result<(), String> {
    if cancel.load(Ordering::SeqCst) {
        return Err("Cancelled by user.".to_string());
    }
    let src_meta = std::fs::symlink_metadata(source)
        .map_err(|e| format!("Cannot inspect '{}': {e}", source.display()))?;
    if move_item {
        if policy != ConflictPolicy::Ask || src_meta.file_type().is_symlink() {
            return Err("Local moves require a new destination and a non-symlink source.".to_string());
        }
        return linscp_platform::gui_os::rename_no_replace(source, target)
            .map_err(|e| format!("Cannot atomically move '{}' to '{}': {e}", source.display(), target.display()));
    }

    let mut effective_target = target.to_path_buf();
    if std::fs::symlink_metadata(&effective_target).is_ok() {
        match policy {
            ConflictPolicy::Skip => {
                if !src_meta.is_dir() || src_meta.file_type().is_symlink() {
                    return Ok(());
                }
            }
            ConflictPolicy::Rename => {
                effective_target = unique_local_target(&effective_target);
            }
            ConflictPolicy::Overwrite => {
                // Keep the old file in place until the replacement has been
                // completely copied and is ready to publish.
                if src_meta.file_type().is_symlink() {
                    remove_path_any(&effective_target)?;
                }
            }
            ConflictPolicy::Ask => {
                return Err(format!(
                    "Destination '{}' already exists.",
                    effective_target.display()
                ));
            }
        }
    }

    let mut copied = 0u64;
    let total = compute_local_size(source);
    local_copy_recursive(
        source,
        &effective_target,
        policy,
        cancel,
        &mut copied,
        total,
        progress,
    )?;

    Ok(())
}

fn compute_local_size(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if meta.file_type().is_symlink() {
        return 0;
    }
    if !meta.is_dir() {
        return meta.len();
    }
    let mut sum = 0u64;
    if let Ok(rd) = std::fs::read_dir(path) {
        for entry in rd.flatten() {
            sum = sum.saturating_add(compute_local_size(&entry.path()));
        }
    }
    sum
}

fn local_copy_recursive(
    source: &Path,
    target: &Path,
    policy: ConflictPolicy,
    cancel: &AtomicBool,
    copied: &mut u64,
    total: u64,
    progress: &ProgressCallback,
) -> Result<(), String> {
    if cancel.load(Ordering::SeqCst) {
        return Err("Cancelled by user.".to_string());
    }
    let meta = std::fs::symlink_metadata(source).map_err(|e| e.to_string())?;
    let ft = meta.file_type();

    if ft.is_symlink() {
        if std::fs::symlink_metadata(target).is_ok() {
            match policy {
                ConflictPolicy::Skip => return Ok(()),
                ConflictPolicy::Overwrite => remove_path_any(target)?,
                ConflictPolicy::Rename => {
                    let alt = unique_local_target(target);
                    return local_copy_recursive(source, &alt, policy, cancel, copied, total, progress);
                }
                ConflictPolicy::Ask => {
                    return Err(format!("Destination '{}' already exists.", target.display()));
                }
            }
        }
        let link_dest = std::fs::read_link(source).map_err(|e| e.to_string())?;
        create_local_symlink(&link_dest.to_string_lossy(), target).map_err(|e| e.to_string())?;
        return Ok(());
    }

    if ft.is_dir() {
        if let Ok(existing) = std::fs::symlink_metadata(target) {
            if existing.file_type().is_symlink() || !existing.is_dir() {
                match policy {
                    ConflictPolicy::Skip => return Ok(()),
                    ConflictPolicy::Overwrite => remove_path_any(target)?,
                    ConflictPolicy::Rename => {
                        let alt = unique_local_target(target);
                        return local_copy_recursive(source, &alt, policy, cancel, copied, total, progress);
                    }
                    ConflictPolicy::Ask => {
                        return Err("Destination is not a directory.".to_string());
                    }
                }
            }
        }
        std::fs::create_dir_all(target).map_err(|e| e.to_string())?;
        let mut children: Vec<_> = std::fs::read_dir(source)
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        children.sort_by_key(|e| e.file_name());
        for child in children {
            let child_src = child.path();
            let child_dst = target.join(child.file_name());
            local_copy_recursive(&child_src, &child_dst, policy, cancel, copied, total, progress)?;
        }
        return Ok(());
    }

    if let Ok(existing) = std::fs::symlink_metadata(target) {
        match policy {
            ConflictPolicy::Skip => return Ok(()),
            ConflictPolicy::Overwrite if existing.is_file() && !existing.file_type().is_symlink() => {},
            ConflictPolicy::Overwrite => return Err("Refusing to overwrite a symlink or non-file.".to_string()),
            ConflictPolicy::Rename => {
                let alt = unique_local_target(target);
                return local_copy_recursive(source, &alt, policy, cancel, copied, total, progress);
            }
            ConflictPolicy::Ask => {
                return Err(format!("Destination '{}' already exists.", target.display()));
            }
        }
    }

    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut rnd = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut rnd);
    let tmp_name = format!(
        ".linscp-part-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let tmp_path = parent.join(tmp_name);

    let mut created_tmp = false;
    let copy_res = (|| -> Result<(), String> {
        let mut reader = std::fs::File::open(source).map_err(|e| e.to_string())?;
        let mut writer = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp_path).map_err(|e| e.to_string())?;
        created_tmp = true;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            if cancel.load(Ordering::SeqCst) {
                return Err("Cancelled by user.".to_string());
            }
            let n = reader.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n]).map_err(|e| e.to_string())?;
            *copied = copied.saturating_add(n as u64);
            progress(*copied, total);
            if cancel.load(Ordering::SeqCst) {
                return Err("Cancelled by user.".to_string());
            }
        }
        writer.sync_all().map_err(|e| e.to_string())?;
        drop(writer);

        if let Ok(ext) = linscp_platform::gui_os::stat_extended(source) {
            let _ = set_local_permissions(&tmp_path, ext.mode);
            let _ = set_local_file_times(&tmp_path, ext.mtime_secs, ext.mtime_secs);
        }
        if policy == ConflictPolicy::Ask || policy == ConflictPolicy::Skip || policy == ConflictPolicy::Rename {
            // Publish without replacing a destination created after preflight.
            std::fs::hard_link(&tmp_path, target).map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(&tmp_path);
        } else {
            std::fs::rename(&tmp_path, target).map_err(|e| e.to_string())?;
        }
        Ok(())
    })();

    if copy_res.is_err() && created_tmp {
        let _ = std::fs::remove_file(&tmp_path);
    }
    copy_res
}

#[allow(clippy::too_many_arguments)]
async fn execute_remote_to_remote(
    src_session: &dyn RemoteSession,
    dst_session: &dyn RemoteSession,
    same_endpoint: bool,
    src_path: &str,
    dst_path: &str,
    move_item: bool,
    staging_root: &Path,
    progress: &ProgressCallback,
) -> Result<(), String> {
    if same_endpoint && move_item {
        src_session
            .rename(src_path, dst_path)
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    let entry = src_session
        .stat(src_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Remote item '{src_path}' does not exist."))?;

    if same_endpoint && !entry.is_dir {
        if src_session.copy_file(src_path, dst_path).await.is_ok() {
            if move_item {
                let _ = src_session.remove_file(src_path).await;
            }
            return Ok(());
        }
    }

    let mut rnd = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut rnd);
    let stage_dir = staging_root.join(format!(
        "r2r-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::create_dir_all(&stage_dir).map_err(|e| e.to_string())?;

    let mut logger = SessionLogger::open(None, 0, false, None, None, false, "").unwrap();
    let mut flags = TransferFlags::default();
    let res = if entry.is_dir {
        flags.recursive = true;
        let local_tree = stage_dir.join("tree");
        let r1 = download_directory_recursive(
            src_session,
            src_path,
            &local_tree,
            "",
            &flags,
            &mut logger,
            Some(progress),
        )
        .await;
        match r1 {
            Ok(_) => upload_directory_recursive(
                dst_session,
                &local_tree,
                dst_path,
                "",
                &flags,
                &mut logger,
                Some(progress),
            )
            .await
            .map(|_| ()),
            Err(e) => Err(e),
        }
    } else {
        let local_file = stage_dir.join("payload.bin");
        let r1 = download_single_file(
            src_session,
            src_path,
            Some(&entry),
            &local_file,
            &flags,
            &mut logger,
            Some(progress),
        )
        .await;
        match r1 {
            Ok(_) => upload_single_file(
                dst_session,
                &local_file,
                dst_path,
                &flags,
                &mut logger,
                Some(progress),
            )
            .await
            .map(|_| ()),
            Err(e) => Err(e),
        }
    };

    let _ = std::fs::remove_dir_all(&stage_dir);
    res?;

    if move_item {
        if entry.is_dir {
            delete_remote_recursive_quiet(src_session, src_path).await?;
        } else {
            src_session
                .remove_file(src_path)
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub async fn delete_remote_recursive_quiet(
    session: &dyn RemoteSession,
    remote_path: &str,
) -> Result<(), String> {
    let Some(entry) = session.stat(remote_path).await.map_err(|e| e.to_string())? else {
        return Ok(());
    };
    if entry.is_symlink || !entry.is_dir {
        return session
            .remove_file(remote_path)
            .await
            .map_err(|e| e.to_string());
    }
    let children = session
        .list_dir(remote_path)
        .await
        .map_err(|e| e.to_string())?;
    for child in children {
        if child.name == "." || child.name == ".." {
            continue;
        }
        let child_path = join_remote_path(remote_path, &child.name);
        if child.is_dir && !child.is_symlink {
            Box::pin(delete_remote_recursive_quiet(session, &child_path)).await?;
        } else {
            session
                .remove_file(&child_path)
                .await
                .map_err(|e| e.to_string())?;
        }
    }
    session
        .remove_dir(remote_path)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod transfer_safety_tests {
    use super::*;

    #[test]
    fn tree_names_cannot_escape_destination() {
        for name in ["", ".", "..", "a/b", "a\\b", "c:d", "bad\nname"] {
            assert!(safe_tree_name(name).is_err(), "accepted {name:?}");
        }
        assert!(safe_tree_name("safe.txt").is_ok());
    }

    #[test]
    fn local_copy_does_not_replace_destination_created_during_copy() {
        let dir = std::env::temp_dir().join(format!("linscp-copy-race-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source");
        let target = dir.join("target");
        std::fs::write(&source, vec![42u8; 1024 * 1024]).unwrap();
        let target_for_callback = target.clone();
        let progress = move |_: u64, _: u64| {
            if !target_for_callback.exists() {
                std::fs::write(&target_for_callback, b"concurrent data").unwrap();
            }
        };
        assert!(execute_local_item(&source, &target, false, ConflictPolicy::Ask, &AtomicBool::new(false), &progress).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"concurrent data");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn local_copy_cancellation_does_not_publish_partial_file() {
        let dir = std::env::temp_dir().join(format!("linscp-copy-cancel-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("source");
        let target = dir.join("target");
        std::fs::write(&source, vec![42u8; 1024 * 1024]).unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let progress = move |_: u64, _: u64| flag.store(true, Ordering::SeqCst);
        assert!(execute_local_item(&source, &target, false, ConflictPolicy::Ask, &cancel, &progress).is_err());
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::write(&target, b"original").unwrap();
        cancel.store(false, Ordering::SeqCst);
        assert!(execute_local_item(&source, &target, false, ConflictPolicy::Overwrite, &cancel, &progress).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
        let _ = std::fs::remove_dir_all(dir);
    }
}
