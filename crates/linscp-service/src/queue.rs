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
        delete_source: bool,
        flags: TransferFlags,
    },
    RemoteUpload {
        session: Arc<dyn RemoteSession>,
        local_src: PathBuf,
        remote_dest: String,
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
            "status": self.status,
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
                t.cancel_flag.store(true, Ordering::SeqCst);
                if t.status == "queued" {
                    t.status = "cancelled".to_string();
                    t.error = Some("Cancelled by user.".to_string());
                    to_clean = Some(t.clone());
                    changed = true;
                } else if t.status == "running" {
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
                if t.tab_id == Some(tab_id) && (t.status == "queued" || t.status == "running") {
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
                    if cancelled {
                        t.status = "cancelled".to_string();
                        t.error = Some("Cancelled by user.".to_string());
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
                    if let Some(tot) = total {
                        if tot > 0 {
                            t.bytes_total = tot;
                        }
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
        let mut logger = SessionLogger::disabled();

        match &task.job {
            QueueJob::RemoteDownload {
                session,
                remote_path,
                local_dest,
                delete_source,
                flags,
            } => {
                let entry = session
                    .stat(remote_path)
                    .await
                    .map_err(|e| e.to_string())?
                    .ok_or_else(|| format!("Remote item '{remote_path}' does not exist."))?;
                let mut f = flags.clone();
                f.delete_source = *delete_source;
                if entry.is_dir {
                    f.recursive = true;
                    download_directory_recursive(
                        session.as_ref(),
                        remote_path,
                        local_dest,
                        "",
                        &f,
                        &mut logger,
                        Some(&*progress),
                    )
                    .await?;
                    if *delete_source {
                        let _ = session.rmdir(remote_path).await;
                    }
                } else {
                    download_single_file(
                        session.as_ref(),
                        remote_path,
                        Some(&entry),
                        local_dest,
                        &f,
                        &mut logger,
                        Some(&*progress),
                    )
                    .await?;
                }
                Ok(())
            }
            QueueJob::RemoteUpload {
                session,
                local_src,
                remote_dest,
                delete_source,
                flags,
                ..
            } => {
                let meta = std::fs::symlink_metadata(local_src).map_err(|e| {
                    format!("Cannot inspect local source '{}': {e}", local_src.display())
                })?;
                let mut f = flags.clone();
                f.delete_source = *delete_source;
                if meta.is_dir() {
                    f.recursive = true;
                    upload_directory_recursive(
                        session.as_ref(),
                        local_src,
                        remote_dest,
                        "",
                        &f,
                        &mut logger,
                        Some(&*progress),
                    )
                    .await?;
                    if *delete_source {
                        let _ = std::fs::remove_dir_all(local_src);
                    }
                } else {
                    upload_single_file(
                        session.as_ref(),
                        local_src,
                        remote_dest,
                        &f,
                        &mut logger,
                        Some(&*progress),
                    )
                    .await?;
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
                if !src_meta.is_dir() || src_meta.file_type().is_symlink() {
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

    if move_item && std::fs::symlink_metadata(&effective_target).is_err() {
        if std::fs::rename(source, &effective_target).is_ok() {
            return Ok(());
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

    if move_item {
        remove_path_any(source)?;
    }
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

    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let mut rnd = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut rnd);
    let tmp_name = format!(
        ".linscp-part-{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let tmp_path = parent.join(tmp_name);

    let copy_res = (|| -> Result<(), String> {
        let mut reader = std::fs::File::open(source).map_err(|e| e.to_string())?;
        let mut writer = std::fs::File::create(&tmp_path).map_err(|e| e.to_string())?;
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
            let _ = set_local_file_times(&tmp_path, ext.mtime_secs);
        }
        std::fs::rename(&tmp_path, target).map_err(|e| e.to_string())?;
        Ok(())
    })();

    if copy_res.is_err() {
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

    let mut logger = SessionLogger::disabled();
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
        .rmdir(remote_path)
        .await
        .map_err(|e| e.to_string())
}
