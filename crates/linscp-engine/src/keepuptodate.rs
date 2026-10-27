//! Continuous local-to-remote directory mirroring (`keepuptodate`), combining
//! `linscp_platform::watcher::LocalDirWatcher` with deterministic tree snapshots.

use std::path::Path;
use std::time::Duration;

use linscp_platform::terminal::{
    clear_interrupted, install_cli_signal_handlers, is_interrupted, restore_default_signal_handlers,
};
use linscp_platform::watcher::LocalDirWatcher;
use linscp_proto::RemoteSession;
use linscp_types::TransferMode;

use crate::filemask::FileMask;
use crate::presets::PresetPermissions;
use crate::sync_planner::{SyncCriteria, SyncMode, SyncOptions, SyncState, apply_sync_plan, plan_synchronization};
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
        }
    }
}

/// Performs an initial local->remote sync pass and then watches `local_root` for
/// modifications, creations, and (with `-delete`) removals until interrupted or
/// `max_passes` watch cycles have completed.
pub async fn run_keep_up_to_date<F>(
    session: &dyn RemoteSession,
    local_root: &Path,
    remote_root: &str,
    opts: &KeepUpToDateOptions,
    logger: &mut SessionLogger,
    mut on_status: F,
) -> Result<usize, String>
where
    F: FnMut(&str),
{
    if !local_root.is_dir() {
        return Err(format!(
            "Local directory '{}' does not exist.",
            local_root.display()
        ));
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
        ..SyncOptions::default()
    };

    let mut dummy_state = SyncState::default();
    let mut total_applied = 0usize;
    let mut passes = 1u32;

    let watcher = if opts.max_passes == 1 {
        None
    } else {
        LocalDirWatcher::watch(local_root, true).ok()
    };
    let _sig_guard = if opts.max_passes == 1 {
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
    let pass1_status = match plan_synchronization(session, local_root, remote_root, &sync_opts, &dummy_state).await {
        Ok(plan) if !plan.is_empty() => {
            match apply_sync_plan(
                session,
                local_root,
                remote_root,
                &plan,
                &sync_opts,
                &mut dummy_state,
                logger,
            )
            .await
            {
                Ok((applied, _)) => {
                    total_applied += applied;
                    format!("Pass {passes}: synchronized {applied} item(s).")
                }
                Err(e) if opts.continue_on_error => format!("Error: {e}"),
                Err(e) => return Err(e),
            }
        }
        Ok(_) => format!("Pass {passes}: nothing to do (every file is up to date)."),
        Err(e) if opts.continue_on_error => format!("Error: {e}"),
        Err(e) => return Err(e),
    };
    if let Some(ref w) = watcher {
        let _ = w.drain_changed_paths();
    }
    on_status(&pass1_status);
    let _ = std::io::Write::flush(&mut std::io::stdout());

    if opts.max_passes > 0 && passes >= opts.max_passes {
        return Ok(total_applied);
    }

    let wait_dur = Duration::from_millis(opts.interval_ms.max(50));
    let slice_dur = Duration::from_millis(200);

    while !is_interrupted() {
        if opts.max_passes > 0 && passes >= opts.max_passes {
            break;
        }
        if let Some(ref w) = watcher {
            let deadline = std::time::Instant::now() + wait_dur;
            while !is_interrupted() {
                let now = std::time::Instant::now();
                if now >= deadline {
                    break;
                }
                let rem = (deadline - now).min(slice_dur);
                if w.recv_timeout(rem).is_some() {
                    // Brief quiet settle so multi-step writes/renames coalesce into one pass
                    let _ = w.recv_timeout(Duration::from_millis(50));
                    break;
                }
            }
        } else {
            let deadline = tokio::time::Instant::now() + wait_dur;
            while !is_interrupted() {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    break;
                }
                tokio::time::sleep((deadline - now).min(slice_dur)).await;
            }
        }
        if is_interrupted() {
            break;
        }
        passes += 1;

        match plan_synchronization(session, local_root, remote_root, &sync_opts, &dummy_state).await
        {
            Ok(plan) if !plan.is_empty() => {
                match apply_sync_plan(
                    session,
                    local_root,
                    remote_root,
                    &plan,
                    &sync_opts,
                    &mut dummy_state,
                    logger,
                )
                .await
                {
                    Ok((applied, _)) => {
                        total_applied += applied;
                        on_status(&format!("Pass {passes}: synchronized {applied} item(s)."));
                    }
                    Err(e) if opts.continue_on_error => on_status(&format!("Error: {e}")),
                    Err(e) => return Err(e),
                }
            }
            Ok(_) => {
                on_status(&format!(
                    "Pass {passes}: nothing to do (every file is up to date)."
                ));
            }
            Err(e) if opts.continue_on_error => on_status(&format!("Error: {e}")),
            Err(e) => return Err(e),
        }
    }

    Ok(total_applied)
}
