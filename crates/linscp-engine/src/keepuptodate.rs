//! Continuous local-to-remote directory mirroring (`keepuptodate`), combining
//! `linscp_platform::watcher::LocalDirWatcher` with deterministic tree snapshots.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use linscp_platform::terminal::{
    clear_interrupted, install_cli_signal_handlers, is_interrupted, restore_default_signal_handlers,
};
use linscp_platform::watcher::LocalDirWatcher;
use linscp_platform::LocalFs;
use linscp_proto::RemoteSession;
use linscp_types::TransferMode;

use crate::filemask::FileMask;
use crate::presets::PresetPermissions;
use crate::sync_planner::{
    SyncAction, SyncCriteria, SyncMode, SyncOptions, SyncState, apply_sync_plan,
    plan_synchronization,
};
use crate::xml_log::SessionLogger;

struct SignalHandlerGuard;

impl SignalHandlerGuard {
    fn acquire() -> Self {
        install_cli_signal_handlers();
        clear_interrupted();
        Self
    }
}

impl Drop for SignalHandlerGuard {
    fn drop(&mut self) {
        clear_interrupted();
        restore_default_signal_handlers();
    }
}

#[derive(Debug, Clone)]
pub struct KeepUpToDateOptions {
    pub delete_obsolete: bool,
    pub continue_on_error: bool,
    pub interval_ms: u64,
    /// Stop automatically after `max_passes` change-check passes (`0` = run until interrupted).
    pub max_passes: u32,
    pub transfer_mode: TransferMode,
    pub preserve_time: bool,
    pub permissions: PresetPermissions,
    pub speed_kbytes_per_sec: Option<u64>,
    pub file_mask: FileMask,
    /// The user acknowledged the staged SFTP publish (see `TransferFlags::sftp_risky_publish`).
    pub sftp_risky_publish: bool,
    /// Optional per-task cancellation flag for GUI queue / session teardown.
    pub cancel_flag: Option<Arc<AtomicBool>>,
    /// Install process-wide CLI signal handlers (`SIGINT`/`SIGTERM`); `false` inside GUI hosts.
    pub install_signal_handlers: bool,
}

impl Default for KeepUpToDateOptions {
    fn default() -> Self {
        Self {
            delete_obsolete: false,
            continue_on_error: false,
            interval_ms: 500,
            max_passes: 0,
            transfer_mode: TransferMode::Binary,
            preserve_time: true,
            permissions: PresetPermissions::Off,
            speed_kbytes_per_sec: None,
            file_mask: FileMask::default(),
            sftp_risky_publish: false,
            cancel_flag: None,
            install_signal_handlers: true,
        }
    }
}

/// Performs an initial local->remote sync pass and then watches `local_root` for
/// modifications, creations, and (with `-delete`) removals until interrupted or
/// `max_passes` watch cycles have completed. A granted root is statted through
/// `local_fs` and polled — the watcher cannot observe a `content://` tree —
/// while any other root keeps the direct path.
pub async fn run_keep_up_to_date<F>(
    session: &dyn RemoteSession,
    local_root: &Path,
    remote_root: &str,
    local_fs: Option<&dyn LocalFs>,
    opts: &KeepUpToDateOptions,
    logger: &mut SessionLogger,
    on_status: F,
) -> Result<usize, String>
where
    F: FnMut(&str),
{
    run_with_watcher_factory(session, local_root, remote_root, local_fs, opts, logger, on_status, LocalDirWatcher::watch).await
}

// Isolate watcher creation so its failure and fallback can be exercised without
// depending on exhausting OS watches or changing process-wide limits.
async fn run_with_watcher_factory<F, W>(
    session: &dyn RemoteSession,
    local_root: &Path,
    remote_root: &str,
    local_fs: Option<&dyn LocalFs>,
    opts: &KeepUpToDateOptions,
    logger: &mut SessionLogger,
    mut on_status: F,
    watch: W,
) -> Result<usize, String>
where
    F: FnMut(&str),
    W: FnOnce(&Path, bool) -> Result<LocalDirWatcher, linscp_platform::PlatformError>,
{
    let saf_fs = local_fs.filter(|_| local_root.to_string_lossy().starts_with("content://"));
    if let Some(fs) = saf_fs {
        match fs.stat(&local_root.to_string_lossy()) {
            Ok(info) if info.is_dir && !info.is_symlink => {},
            _ => return Err(format!(
                "Local directory '{}' does not exist.",
                local_root.display()
            )),
        }
    } else if !local_root.is_dir() {
        return Err(format!(
            "Local directory '{}' does not exist.",
            local_root.display()
        ));
    }

    let is_cancelled = || opts.cancel_flag.as_ref().is_some_and(|f| f.load(Ordering::SeqCst));
    let is_stopped = || is_interrupted() || is_cancelled();
    if is_cancelled() {
        return Err("Cancelled by user.".to_string());
    }

    let sync_opts = SyncOptions {
        mode: SyncMode::Remote,
        criteria: SyncCriteria {
            time: true,
            size: true,
            checksum: false,
        },
        delete_obsolete: opts.delete_obsolete,
        recursive: true,
        transfer_mode: opts.transfer_mode,
        preserve_time: opts.preserve_time,
        permissions: opts.permissions,
        speed_kbytes_per_sec: opts.speed_kbytes_per_sec,
        file_mask: opts.file_mask.clone(),
        sftp_risky_publish: opts.sftp_risky_publish,
        cancel_flag: opts.cancel_flag.clone(),
        ..SyncOptions::default()
    };

    let mut dummy_state = SyncState::default();
    let mut total_applied = 0usize;
    let mut passes = 1u32;

    // A granted tree has no watcher to attach: the passes below poll it on
    // the interval instead, through the same no-watcher path.
    let watcher = if opts.max_passes == 1 || saf_fs.is_some() {
        None
    } else {
        match watch(local_root, true) {
            Ok(watcher) => Some(watcher),
            Err(_) => {
                on_status("Filesystem notifications are unavailable; checking for changes at the polling interval.");
                None
            }
        }
    };
    let _sig_guard = if !opts.install_signal_handlers || opts.max_passes == 1 {
        None
    } else {
        Some(SignalHandlerGuard::acquire())
    };
    if opts.max_passes != 1 {
        on_status(&format!(
            "Watching '{}' -> '{remote_root}' for changes...",
            local_root.display()
        ));
    }

    // Initial catch-up pass (Pass 1)
    let pass1_status = match plan_synchronization(session, local_root, remote_root, &sync_opts, &dummy_state, local_fs).await {
        Ok(plan) if plan.iter().any(|i| i.action != SyncAction::None) => {
            match apply_sync_plan(
                session,
                local_root,
                remote_root,
                &plan,
                &sync_opts,
                &mut dummy_state,
                logger,
                local_fs,
            )
            .await
            {
                Ok((applied, _)) => {
                    total_applied += applied;
                    format!("Pass {passes}: synchronized {applied} item(s).")
                }
                Err(_) if is_cancelled() => return Err("Cancelled by user.".to_string()),
                Err(e) if opts.continue_on_error => format!("Error: {e}"),
                Err(e) => return Err(e),
            }
        }
        Ok(_) => format!("Pass {passes}: nothing to do (every file is up to date)."),
        Err(_) if is_cancelled() => return Err("Cancelled by user.".to_string()),
        Err(e) if opts.continue_on_error => format!("Error: {e}"),
        Err(e) => return Err(e),
    };
    // Do not discard events that arrived while the initial snapshot was being
    // planned or applied: a change after enumeration needs another pass now,
    // not only when the safety-net polling interval expires.
    on_status(&pass1_status);
    let _ = std::io::Write::flush(&mut std::io::stdout());

    if is_cancelled() {
        return Err("Cancelled by user.".to_string());
    }
    if opts.max_passes > 0 && passes >= opts.max_passes {
        return Ok(total_applied);
    }

    let wait_dur = Duration::from_millis(opts.interval_ms.max(50));
    let poll_dur = Duration::from_millis(50);

    while !is_stopped() {
        if opts.max_passes > 0 && passes >= opts.max_passes {
            break;
        }
        let deadline = tokio::time::Instant::now() + wait_dur;
        while !is_stopped() {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            if let Some(ref w) = watcher {
                if !w.drain_changed_paths().is_empty() {
                    // Brief quiet settle so multi-step writes/renames coalesce into one pass.
                    tokio::time::sleep(poll_dur).await;
                    let _ = w.drain_changed_paths();
                    break;
                }
            }
            tokio::time::sleep((deadline - now).min(poll_dur)).await;
        }
        if is_stopped() {
            break;
        }
        passes += 1;

        match plan_synchronization(session, local_root, remote_root, &sync_opts, &dummy_state, local_fs).await
        {
            Ok(plan) if plan.iter().any(|i| i.action != SyncAction::None) => {
                match apply_sync_plan(
                    session,
                    local_root,
                    remote_root,
                    &plan,
                    &sync_opts,
                    &mut dummy_state,
                    logger,
                    local_fs,
                )
                .await
                {
                    Ok((applied, _)) => {
                        total_applied += applied;
                        on_status(&format!("Pass {passes}: synchronized {applied} item(s)."));
                    }
                    Err(_) if is_cancelled() => return Err("Cancelled by user.".to_string()),
                    Err(e) if opts.continue_on_error => on_status(&format!("Error: {e}")),
                    Err(e) => return Err(e),
                }
            }
            Ok(_) => {
                on_status(&format!(
                    "Pass {passes}: nothing to do (every file is up to date)."
                ));
            }
            Err(_) if is_cancelled() => return Err("Cancelled by user.".to_string()),
            Err(e) if opts.continue_on_error => on_status(&format!("Error: {e}")),
            Err(e) => return Err(e),
        }
    }

    if is_cancelled() {
        return Err("Cancelled by user.".to_string());
    }
    Ok(total_applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync_planner::LocalSyncSession;
    use linscp_platform::NativeLocalFs;

    #[tokio::test]
    async fn failed_native_watch_falls_back_to_polling_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(source.join("first.txt"), b"first").unwrap();
        let fs = Arc::new(NativeLocalFs::new());
        let session = LocalSyncSession::new(target.to_string_lossy().into_owned(), fs);
        let opts = KeepUpToDateOptions { interval_ms: 400, max_passes: 2, install_signal_handlers: false, ..Default::default() };
        let mut logger = SessionLogger::open(None, 0, false, None, None, false, "test").unwrap();
        let mut statuses = Vec::new();
        let mut first_pass = None;
        let applied = run_with_watcher_factory(&session, &source, "/", None, &opts, &mut logger, |status| {
            statuses.push(status.to_string());
            if status.starts_with("Pass 1:") {
                assert_eq!(std::fs::read(target.join("first.txt")).unwrap(), b"first");
                first_pass = Some(std::time::Instant::now());
                std::fs::write(source.join("later.txt"), b"later").unwrap();
            }
        }, |_path, _recursive| Err(linscp_platform::PlatformError::Watch("injected failure".into()))).await.unwrap();
        assert!(first_pass.unwrap().elapsed() >= Duration::from_millis(350));
        assert!(statuses.iter().any(|s| s.contains("notifications are unavailable")), "{statuses:?}");
        assert!(statuses.iter().any(|s| s.starts_with("Pass 2:")), "{statuses:?}");
        assert!(applied >= 2);
        assert_eq!(std::fs::read(target.join("later.txt")).unwrap(), b"later");
    }
    // A source change is injected after local enumeration, while the first
    // remote listing is being planned. The installed watcher must keep it.
    struct ChangeDuringFirstPlan {
        inner: NativeLocalFs,
        source: std::path::PathBuf,
        fired: std::sync::atomic::AtomicBool,
    }
    impl LocalFs for ChangeDuringFirstPlan {
        fn list_roots(&self) -> Result<Vec<linscp_types::LocalRootEntry>, linscp_platform::PlatformError> { self.inner.list_roots() }
        fn list_dir(&self, path: &str) -> Result<Vec<linscp_types::FileEntry>, linscp_platform::PlatformError> {
            if !self.fired.swap(true, Ordering::SeqCst) {
                std::fs::write(self.source.join("during.txt"), b"during").unwrap();
                std::thread::sleep(Duration::from_millis(300));
            }
            self.inner.list_dir(path)
        }
        fn stat(&self, path: &str) -> Result<linscp_types::FileEntry, linscp_platform::PlatformError> { self.inner.stat(path) }
        fn mkdir_all(&self, path: &str) -> Result<(), linscp_platform::PlatformError> { self.inner.mkdir_all(path) }
        fn remove_file(&self, path: &str) -> Result<(), linscp_platform::PlatformError> { self.inner.remove_file(path) }
        fn remove_dir_all(&self, path: &str) -> Result<(), linscp_platform::PlatformError> { self.inner.remove_dir_all(path) }
        fn rename(&self, from: &str, to: &str) -> Result<(), linscp_platform::PlatformError> { self.inner.rename(from, to) }
        fn read_bytes(&self, path: &str) -> Result<Vec<u8>, linscp_platform::PlatformError> { self.inner.read_bytes(path) }
        fn write_bytes_atomic(&self, path: &str, data: &[u8]) -> Result<(), linscp_platform::PlatformError> { self.inner.write_bytes_atomic(path, data) }
        fn set_mtime(&self, path: &str, mtime: i64) -> Result<(), linscp_platform::PlatformError> { self.inner.set_mtime(path, mtime) }
        fn set_permissions_mode(&self, path: &str, mode: u32) -> Result<(), linscp_platform::PlatformError> { self.inner.set_permissions_mode(path, mode) }
    }

    #[tokio::test]
    async fn changes_during_initial_sync_trigger_an_immediate_second_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        let target = tmp.path().join("target");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(source.join("first.txt"), b"first").unwrap();
        let fs = Arc::new(ChangeDuringFirstPlan { inner: NativeLocalFs::new(), source: source.clone(), fired: AtomicBool::new(false) });
        let session = LocalSyncSession::new(target.to_string_lossy().into_owned(), fs);
        let opts = KeepUpToDateOptions { interval_ms: 30_000, max_passes: 2, install_signal_handlers: false, ..Default::default() };
        let mut logger = SessionLogger::open(None, 0, false, None, None, false, "test").unwrap();
        tokio::time::timeout(Duration::from_secs(6), run_keep_up_to_date(&session, &source, "/", None, &opts, &mut logger, |_| {}))
            .await.expect("watcher did not wake before the polling interval").unwrap();
        assert_eq!(std::fs::read(target.join("during.txt")).unwrap(), b"during");
    }

}
