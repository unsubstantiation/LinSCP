//! Remote file editing workflow (`edit [-force] [-keep] [-binary] [-editor=CMD]
//! [-eol=preserve|lf|crlf] [-encoding=NAME] [-monitor[=PASSES]] <remotefile>`).

use std::path::{Path, PathBuf};

use linscp_platform::create_private_dir;
use linscp_platform::terminal::{
    clear_interrupted, install_cli_signal_handlers, is_interrupted, resolve_default_editor,
    spawn_editor_process,
};
use linscp_proto::RemoteSession;

use crate::text_mode::{
    EolStyle, convert_eol_bytes, decode_to_utf8_strict, encode_from_utf8_strict, looks_like_text,
    uses_pure_crlf,
};
use crate::transfer::{TransferFlags, download_single_file, upload_single_file};
use crate::xml_log::SessionLogger;

#[derive(Debug, Clone)]
pub struct EditOptions {
    pub editor: String,
    pub max_size: u64,
    pub force: bool,
    pub keep_temp_file: bool,
    pub allow_binary: bool,
    /// `"preserve"` (default), `"lf"`, or `"crlf"`.
    pub eol: String,
    /// Optional legacy character encoding (`""` / `"utf-8"` default, or e.g. `"iso-8859-1"`).
    pub encoding: String,
    pub monitor: bool,
    pub monitor_passes: u32,
    pub monitor_interval_ms: u64,
    pub confirm_upload: bool,
}

impl Default for EditOptions {
    fn default() -> Self {
        Self {
            editor: String::new(),
            max_size: 16 * 1024 * 1024,
            force: false,
            keep_temp_file: false,
            allow_binary: false,
            eol: "preserve".to_string(),
            encoding: String::new(),
            monitor: false,
            monitor_passes: 0,
            monitor_interval_ms: 50,
            confirm_upload: false,
        }
    }
}

fn sanitize_for_temp_name(remote_path: &str) -> String {
    let mut out = String::new();
    for c in remote_path.chars() {
        let safe = c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_');
        out.push(if safe { c } else { '_' });
    }
    if out.len() > 64 {
        out = out[out.len() - 64..].to_string();
    }
    if out.is_empty() || out == "." || out == ".." {
        "file".to_string()
    } else {
        out
    }
}

/// Runs the `edit` workflow on `remote_path`, printing status messages via `on_status`.
pub async fn edit_remote_file<F>(
    session: &dyn RemoteSession,
    remote_path: &str,
    opts: &EditOptions,
    logger: &mut SessionLogger,
    mut on_status: F,
) -> Result<(), String>
where
    F: FnMut(&str),
{
    let editor_cmd = resolve_default_editor(&opts.editor)?;
    let info = session
        .stat(remote_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("Remote file '{remote_path}' does not exist."))?;
    if info.is_dir {
        return Err(format!("'{remote_path}' is a directory and cannot be edited."));
    }
    if !opts.force && opts.max_size > 0 && info.size > opts.max_size {
        return Err(format!(
            "'{remote_path}' is {} bytes, which exceeds 'editmaxsize' ({} bytes); pass '-force' to edit anyway.",
            info.size, opts.max_size
        ));
    }

    let work_dir = std::env::temp_dir().join(format!(
        "linscp-edit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    create_private_dir(&work_dir).map_err(|e| format!("Cannot create temporary edit dir: {e}"))?;
    let temp_path: PathBuf = work_dir.join(sanitize_for_temp_name(remote_path));

    let dl_flags = TransferFlags {
        preserve_time: false,
        ..TransferFlags::default()
    };
    download_single_file(
        session,
        remote_path,
        Some(&info),
        &temp_path,
        &dl_flags,
        logger,
        None,
    )
    .await?;

    let original_wire_bytes = std::fs::read(&temp_path).map_err(|e| {
        cleanup_temp(&temp_path, &work_dir, opts.keep_temp_file);
        format!("Cannot read downloaded file '{}': {e}", temp_path.display())
    })?;

    if !opts.allow_binary && !looks_like_text(&original_wire_bytes) {
        cleanup_temp(&temp_path, &work_dir, opts.keep_temp_file);
        return Err(format!(
            "'{remote_path}' appears to be a binary file (contains NUL bytes); pass '-binary' to edit anyway."
        ));
    }

    let original_was_crlf = uses_pure_crlf(&original_wire_bytes);
    let mut had_utf8_bom = false;
    let editor_initial_bytes = if !opts.encoding.trim().is_empty() || !opts.allow_binary {
        let enc_label = if opts.encoding.trim().is_empty() {
            // Only enforce strict transcoding when an explicit encoding was requested
            ""
        } else {
            opts.encoding.trim()
        };
        if !enc_label.is_empty() {
            let (utf8_text, bom) = decode_to_utf8_strict(&original_wire_bytes, enc_label)
                .inspect_err(|_| cleanup_temp(&temp_path, &work_dir, opts.keep_temp_file))?;
            had_utf8_bom = bom;
            convert_eol_bytes(utf8_text.as_bytes(), EolStyle::Lf)
        } else if original_was_crlf {
            convert_eol_bytes(&original_wire_bytes, EolStyle::Lf)
        } else {
            original_wire_bytes.clone()
        }
    } else {
        original_wire_bytes.clone()
    };

    if editor_initial_bytes != original_wire_bytes {
        std::fs::write(&temp_path, &editor_initial_bytes)
            .map_err(|e| format!("Cannot prepare editor file '{}': {e}", temp_path.display()))?;
    }

    let mut expected_remote_mtime = info.mtime;
    let mut last_uploaded_wire = original_wire_bytes;

    let mut child = spawn_editor_process(&editor_cmd, &temp_path).inspect_err(|_| {
        cleanup_temp(&temp_path, &work_dir, opts.keep_temp_file);
    })?;

    if !opts.monitor {
        let status = child
            .wait()
            .map_err(|e| format!("Waiting for editor failed: {e}"))?;
        if !status.success() {
            cleanup_temp(&temp_path, &work_dir, opts.keep_temp_file);
            return Err(format!(
                "Editor '{editor_cmd}' exited with status {}.",
                status.code().unwrap_or(1)
            ));
        }
    } else {
        // In `-monitor` mode, wait briefly if editor is a one-shot script or poll while running
        let _ = child.try_wait();
    }

    let encode_edited = |raw_local: &[u8]| -> Result<Vec<u8>, String> {
        let target_eol = match opts.eol.as_str() {
            "lf" => Some(EolStyle::Lf),
            "crlf" => Some(EolStyle::Crlf),
            _ => {
                if original_was_crlf {
                    Some(EolStyle::Crlf)
                } else {
                    None
                }
            }
        };
        let eol_adjusted = if let Some(style) = target_eol {
            convert_eol_bytes(raw_local, style)
        } else {
            raw_local.to_vec()
        };
        if !opts.encoding.trim().is_empty() {
            let utf8_str = std::str::from_utf8(&eol_adjusted).map_err(|e| {
                format!("Edited file is not valid UTF-8 for re-encoding: {e}")
            })?;
            encode_from_utf8_strict(utf8_str, opts.encoding.trim(), had_utf8_bom)
        } else {
            Ok(eol_adjusted)
        }
    };

    let first_uploaded = upload_edited_if_changed(
        session,
        remote_path,
        &temp_path,
        &work_dir,
        opts.force,
        &encode_edited,
        &mut last_uploaded_wire,
        &mut expected_remote_mtime,
        logger,
    )
    .await?;
    if first_uploaded {
        on_status(&format!("Uploaded '{remote_path}'."));
    }

    if !opts.monitor {
        if !first_uploaded {
            on_status(&format!("No changes to upload; '{remote_path}' is unchanged."));
        }
        cleanup_temp(&temp_path, &work_dir, opts.keep_temp_file);
        return Ok(());
    }

    install_cli_signal_handlers();
    clear_interrupted();
    let target_passes = opts.monitor_passes.max(1);
    let mut completed_passes = u32::from(first_uploaded);
    let mut idle_polls = 0u32;
    on_status(&format!("Monitoring '{}' for local saves...", temp_path.display()));

    while !is_interrupted() && completed_passes < target_passes {
        tokio::time::sleep(std::time::Duration::from_millis(
            opts.monitor_interval_ms.max(25),
        ))
        .await;
        if upload_edited_if_changed(
            session,
            remote_path,
            &temp_path,
            &work_dir,
            opts.force,
            &encode_edited,
            &mut last_uploaded_wire,
            &mut expected_remote_mtime,
            logger,
        )
        .await?
        {
            on_status(&format!("Uploaded '{remote_path}'."));
            completed_passes += 1;
            idle_polls = 0;
        } else {
            idle_polls += 1;
            // If editor process already exited and no new saves arrive within ~10s, exit cleanly
            if child.try_wait().ok().flatten().is_some() && idle_polls > 200 {
                break;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    clear_interrupted();
    cleanup_temp(&temp_path, &work_dir, opts.keep_temp_file);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn upload_edited_if_changed<E>(
    session: &dyn RemoteSession,
    remote_path: &str,
    temp_path: &Path,
    work_dir: &Path,
    force: bool,
    encode_edited: &E,
    last_wire: &mut Vec<u8>,
    exp_mtime: &mut i64,
    logger: &mut SessionLogger,
) -> Result<bool, String>
where
    E: Fn(&[u8]) -> Result<Vec<u8>, String>,
{
    let cur_local = std::fs::read(temp_path)
        .map_err(|e| format!("Cannot read edited file '{}': {e}", temp_path.display()))?;
    let cur_wire = encode_edited(&cur_local)?;
    if cur_wire == *last_wire {
        return Ok(false);
    }

    let now_stat = session
        .stat(remote_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| {
            format!(
                "'{remote_path}' no longer exists; the edited copy is kept at '{}'.",
                temp_path.display()
            )
        })?;
    if !force && *exp_mtime != 0 && now_stat.mtime != 0 && now_stat.mtime != *exp_mtime {
        return Err(format!(
            "'{remote_path}' changed on the server while it was being edited, so it was not overwritten. Your copy is kept at '{}'.",
            temp_path.display()
        ));
    }

    let upload_stage_file = work_dir.join(".linscp-upload-wire.tmp");
    std::fs::write(&upload_stage_file, &cur_wire)
        .map_err(|e| format!("Cannot stage encoded upload: {e}"))?;
    let up_flags = TransferFlags {
        preserve_time: false,
        ..TransferFlags::default()
    };
    upload_single_file(
        session,
        &upload_stage_file,
        remote_path,
        &up_flags,
        logger,
        None,
    )
    .await?;
    let _ = std::fs::remove_file(&upload_stage_file);
    if let Ok(Some(updated)) = session.stat(remote_path).await {
        if updated.mtime != 0 {
            *exp_mtime = updated.mtime;
        }
    }
    *last_wire = cur_wire;
    Ok(true)
}

fn cleanup_temp(temp_path: &PathBuf, work_dir: &PathBuf, keep: bool) {
    if !keep {
        let _ = std::fs::remove_file(temp_path);
        let _ = std::fs::remove_dir_all(work_dir);
    }
}
