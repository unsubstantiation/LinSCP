//! Full-backup and key/session interchange service handlers.
//!
//! The engine owns the backup formats and transactional restore; the shared
//! key helpers remain in the parent module until vault-key consolidation.
use super::*;

impl CommanderService {
    // Full backup data crosses IPC only as an authenticated encrypted envelope.
    // The GUI uses a smaller bound than the engine to limit WebView allocations.
    /// The exclusive configuration-activity permit must be held when calling
    /// this: it prevents IPC enqueue/retry and new connections between the
    /// check and the subsequent restore. Background work itself is tracked by
    /// the queue until its cleanup has finished.
    pub(super) fn ensure_full_restore_quiescent(&self) -> Result<(), String> {
        if self.queue.has_unfinished_work() {
            return Err("Finish or cancel all queued transfers and synchronization jobs before restoring.".into());
        }
        let state = self.state.lock().map_err(|_| "Configuration state is unavailable.".to_string())?;
        if state.tabs.values().any(|tab| tab.connected && !tab.is_local)
            || !state.pending_connections.is_empty()
            || !state.challenges.is_empty()
            || !state.auto_inflight.is_empty()
            || !state.x2go_pending.is_empty()
            || !state.x2go.is_empty()
            || !state.terminals.summaries().is_empty()
        {
            return Err("Disconnect remote sessions, close terminals, and wait for connection attempts to finish before restoring.".into());
        }
        Ok(())
    }

    fn execute_full_backup_restore(
        &self,
        bundle: &linscp_engine::backup::BackupBundle,
    ) -> Result<(), ApiReply> {
        let _guard = self.session_key_lock.lock().expect("session key lock");
        if let Err(error) = self.config_lock.lock().expect("config lock mutex").as_ref() {
            return Err(api_error(503, error));
        }
        let cfg = self.config_root();
        match self.secret_vault.load_master_key(&cfg) {
            Ok(Some(_)) => {}
            Ok(None) => return Err(api_error(423, "Unlock the local vault before restoring a full backup.")),
            Err(error) => return Err(api_error(500, error.to_string())),
        }
        if let Err(error) = self.ensure_full_restore_quiescent() {
            return Err(api_error(409, error));
        }
        let restore_result = {
            let lock_guard = self.config_lock.lock().expect("config lock mutex");
            let lock = match lock_guard.as_ref() {
                Ok(lock) => lock,
                Err(error) => return Err(api_error(503, error)),
            };
            linscp_engine::backup::import_backup_transactional(&cfg, bundle, self.secret_vault.as_ref(), lock)
        };
        match restore_result {
            Ok(()) => {
                let preferences = PreferencesStore::load(&cfg).unwrap_or_default();
                self.queue.clear_finished();
                {
                    let mut state = self.state.lock().expect("state mutex");
                    state.preferences = preferences;
                    let removed_tabs: Vec<u64> = state
                        .tabs
                        .iter()
                        .filter_map(|(id, tab)| (!tab.is_local).then_some(*id))
                        .collect();
                    for tab_id in removed_tabs {
                        state.terminals.close_for_tab(tab_id);
                        state.tabs.remove(&tab_id);
                    }
                    if state.active_tab_id.is_some_and(|id| !state.tabs.contains_key(&id)) {
                        state.active_tab_id = state.tabs.keys().min().copied();
                    }
                    state.challenges.clear();
                    state.pending_sites.clear();
                    state.auto_pending.clear();
                    state.auto_retry_at.clear();
                    state.auto_suspended.clear();
                    let live: std::collections::BTreeSet<u64> = state.tabs.keys().copied().collect();
                    state.monitors.retain(&live);
                }
                let stale_temp_dir = cfg.join("tmp").join("unlocked-keys").join(std::process::id().to_string());
                let _ = std::fs::remove_dir_all(stale_temp_dir);
                Ok(())
            }
            Err(error) => {
                if !matches!(linscp_engine::backup::restore_recovery_required(&cfg), Ok(false)) {
                    self.recovery_gate.store(true, std::sync::atomic::Ordering::Release);
                    let _ = self.secret_vault.lock();
                    return Err(api_error(503, error));
                }
                Err(api_error(400, error))
            }
        }
    }

    pub(super) fn handle_full_backup_import(&self, mut body: Value) -> ApiReply {
        const MAX_BACKUP: usize = 16 * 1024 * 1024;
        const MAX_ENCRYPTED: usize = MAX_BACKUP + 64;
        let result = (|| -> Result<(), ApiReply> {
            if body.get("confirm_replace").and_then(Value::as_bool) != Some(true) {
                return Err(api_error(400, "Confirm replacing current configuration before restoring a full backup."));
            }
            let password = body.get("password").and_then(Value::as_str).unwrap_or("");
            let encoded = body.get("data_base64").and_then(Value::as_str).unwrap_or("");
            if encoded.is_empty() {
                return Err(api_error(400, "Choose a full backup file first."));
            }
            if encoded.len() > ((MAX_ENCRYPTED + 2) / 3) * 4 {
                return Err(api_error(400, "Full backups are limited to 16 MiB in the GUI."));
            }
            let decoded = zeroize::Zeroizing::new(
                BASE64_STD
                    .decode(encoded.as_bytes())
                    .map_err(|_| api_error(400, "Invalid backup file encoding."))?,
            );
            if decoded.len() > MAX_ENCRYPTED {
                return Err(api_error(400, "Full backups are limited to 16 MiB in the GUI."));
            }
            let bundle = linscp_engine::backup::open_encrypted_backup(&decoded, password)
                .map_err(|error| api_error(400, error))?;
            self.execute_full_backup_restore(&bundle)
        })();
        if let Some(Value::String(password)) = body.get_mut("password") {
            zeroize::Zeroize::zeroize(password);
        }
        if let Some(Value::String(encoded)) = body.get_mut("data_base64") {
            zeroize::Zeroize::zeroize(encoded);
        }
        match result {
            Ok(()) => ApiReply { status: 200, payload: json!({"success": true}) },
            Err(reply) => reply,
        }
    }

    pub(super) fn exec_cli_backup_import(&self, line: &str) -> ApiReply {
        use std::io::Read;
        const MAX_CLI_BACKUP: usize = 64 * 1024 * 1024 + 64;
        let reply_err = |msg: String| ApiReply {
            status: 200,
            payload: json!({"success": false, "stdout": "", "stderr": format!("{msg}\n"), "exit_code": 1}),
        };
        let tokens = match linscp_engine::script_params::tokenize_script_line(line.trim()) {
            Ok(tokens) => tokens,
            Err(error) => return reply_err(error),
        };
        if tokens.len() != 3 {
            return reply_err("Syntax: backup export <file> | import <file>.".into());
        }
        let password = match std::env::var("LINSCP_BACKUP_PASSWORD") {
            Ok(value) => zeroize::Zeroizing::new(value),
            Err(_) => return reply_err("Set LINSCP_BACKUP_PASSWORD to an independent backup password (12 or more bytes).".into()),
        };
        let expanded = PathBuf::from(linscp_platform::terminal::expand_tilde(&tokens[2]));
        let file = match std::fs::File::open(&expanded) {
            Ok(file) => file,
            Err(error) => return reply_err(format!("Cannot restore backup from '{}': {error}", tokens[2])),
        };
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        if let Err(error) = file.take(MAX_CLI_BACKUP as u64 + 1).read_to_end(&mut bytes) {
            return reply_err(format!("Cannot restore backup from '{}': {error}", tokens[2]));
        }
        if bytes.len() > MAX_CLI_BACKUP {
            return reply_err(format!("Cannot restore backup from '{}': Backup exceeds size limit", tokens[2]));
        }
        let bundle = match linscp_engine::backup::open_encrypted_backup(&bytes, &password) {
            Ok(bundle) => bundle,
            Err(error) => return reply_err(format!("Cannot restore backup from '{}': {error}", tokens[2])),
        };
        match self.execute_full_backup_restore(&bundle) {
            Ok(()) => ApiReply {
                status: 200,
                payload: json!({
                    "success": true,
                    "stdout": format!("Full backup restored from '{}'.\n", tokens[2]),
                    "stderr": "",
                    "exit_code": 0,
                }),
            },
            Err(reply) => {
                let message = reply
                    .payload
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("Restore failed.");
                reply_err(format!("Cannot restore backup from '{}': {message}", tokens[2]))
            }
        }
    }

    fn write_backup_export_to_dir(&self, save_dir: &str, filename: &str, bytes: &[u8]) -> Result<String, String> {
        let checked_dir = check_local_pane_directory(save_dir, "save_dir")?;
        let dest = resolve_contained(&checked_dir, filename)?;
        if is_saf_path(&dest) {
            self.local_fs
                .write_bytes_atomic(&dest, bytes)
                .map_err(|e| e.to_string())?;
        } else {
            linscp_platform::write_owner_only_file_atomic(Path::new(&dest), bytes)
                .map_err(|e| e.to_string())?;
        }
        Ok(dest)
    }

    pub(super) fn handle_full_backup_export(&self, mut body: Value) -> ApiReply {
        const MAX_BACKUP: usize = 16 * 1024 * 1024;
        let _guard = self.session_key_lock.lock().expect("session key lock");
        let cfg = self.config_root();
        let result = (|| -> Result<Value, String> {
            let password = body.get("password").and_then(Value::as_str).unwrap_or("");
            if self.secret_vault.load_master_key(&cfg).map_err(|e| e.to_string())?.is_none() {
                return Err("Unlock the local vault before using a full backup.".into());
            }
            let bundle = linscp_engine::backup::export_backup(&cfg, self.secret_vault.as_ref())?;
            let bytes = linscp_engine::backup::seal_backup(&bundle, password)?;
            if bytes.len() > MAX_BACKUP { return Err("Full backups are limited to 16 MiB in the GUI.".into()); }
            let filename = format!("linscp-full-backup-{}.lscpbak", unix_now_seconds());
            let saved_path = match body.get("save_dir").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) {
                Some(dir) => Some(self.write_backup_export_to_dir(dir, &filename, &bytes)?),
                None => None,
            };
            let mut resp = json!({
                "success": true,
                "data_base64": BASE64_STD.encode(&bytes),
                "filename": filename,
            });
            if let Some(saved) = saved_path {
                resp["saved_path"] = json!(saved);
            }
            Ok(resp)
        })();
        if let Some(Value::String(password)) = body.get_mut("password") {
            zeroize::Zeroize::zeroize(password);
        }
        match result {
            Ok(payload) => ApiReply { status: 200, payload },
            Err(error) => api_error(400, error),
        }
    }

    pub(super) fn handle_export_offlineotp_vault(&self, mut body: Value) -> ApiReply {
        let _guard = self.session_key_lock.lock().expect("session key lock");
        let result = (|| -> Result<ApiReply, ApiReply> {
            let plain_text = body.get("plain_text").and_then(Value::as_bool).unwrap_or(false);
            let password = body.get("password").and_then(Value::as_str).unwrap_or("");
            if plain_text {
                return Err(api_error(400, "Plain-text backup exports are disabled."));
            }
            if password.is_empty() {
                return Err(api_error(400, "Choose a non-empty backup password."));
            }
            // Optional selection: an explicit array of saved-session names. When
            // present, only those sites (and the SSH keys they reference) are
            // exported; an empty array exports nothing and says so.
            let selection = parse_name_selection(body.get("sessions"))
                .map_err(|error| api_error(400, &error))?;
            let cfg = self.state.lock().expect("m").config_root.clone();
            let store = SessionStore::load_from_dir(&cfg, self.secret_vault.as_ref())
                .map_err(|error| api_error(500, &error))?;
            let include_vault_keys = body.get("include_vault_keys").and_then(Value::as_bool).unwrap_or(selection.is_none());
            if let Some(set) = selection.as_ref() {
                if set.is_empty() && !include_vault_keys {
                    return Err(api_error(400, "Select at least one session to export."));
                }
                for name in body
                    .get("sessions")
                    .and_then(Value::as_array)
                    .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
                    .unwrap_or_default()
                {
                    if store.find(name).is_none() {
                        return Err(api_error(400, &format!("Saved session '{name}' was not found.")));
                    }
                }
            }
            let entries = offlineotp_entries_from_sessions(
                &store,
                &cfg,
                self.secret_vault.as_ref(),
                selection.as_ref(),
                include_vault_keys,
            )
            .map_err(|error| api_error(400, &error))?;
            let unix_seconds = unix_now_seconds();
            let (data, filename) = offlineotp_vault::seal(&entries, password)
                .map(|data| (data, offlineotp_vault::timestamped_filename(unix_seconds)))
                .map_err(|error| api_error(400, &error))?;
            let saved_path = match body.get("save_dir").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()) {
                Some(dir) => Some(self.write_backup_export_to_dir(dir, &filename, &data).map_err(|error| api_error(400, &error))?),
                None => None,
            };
            let mut payload = json!({
                "success": true,
                "filename": filename,
                "data_base64": BASE64_STD.encode(&data),
                "entry_count": entries.len(),
                "plain_text": plain_text,
            });
            if let Some(saved) = saved_path {
                payload["saved_path"] = json!(saved);
            }
            Ok(ApiReply {
                status: 200,
                payload,
            })
        })();
        zeroize_json_secret_fields(&mut body, &["password"]);
        match result {
            Ok(reply) => reply,
            Err(reply) => reply,
        }
    }

    /// Reads the backup the user picked and lists the sessions it contains,
    /// so the page can show a tick-list without importing anything. Never
    /// returns secret material.
    pub(super) fn handle_scan_key_session_backup(&self, mut body: Value) -> ApiReply {
        let result = (|| -> Result<ApiReply, ApiReply> {
            let password = body.get("password").and_then(Value::as_str).unwrap_or("");
            let encoded = body.get("data_base64").and_then(Value::as_str).unwrap_or("");
            if encoded.len() > 22 * 1024 * 1024 {
                return Err(api_error(413, "The key/session backup exceeds the 16 MiB limit."));
            }
            let bytes = zeroize::Zeroizing::new(
                BASE64_STD
                    .decode(encoded.as_bytes())
                    .map_err(|_| api_error(400, "The selected file is not valid base64 data."))?,
            );
            let fingerprint = linscp_crypto::digests::sha256_hex(&bytes);
            let encrypted = offlineotp_vault::is_encrypted_backup(&bytes);
            if encrypted && password.is_empty() {
                return Err(api_error(400, "Enter the password used to encrypt this backup."));
            }
            let imported = open_key_session_backup(&bytes, password, encrypted)
                .map_err(|error| api_error(400, &error))?;
            let ignored_entries = imported.ignored_entries;
            let cfg = self.state.lock().expect("m").config_root.clone();
            let existing_names: std::collections::HashSet<String> =
                SessionStore::load_from_dir(&cfg, self.secret_vault.as_ref())
                    .map(|store| store.sites().iter().map(|site| site.name.clone()).collect())
                    .unwrap_or_default();
            let planned = plan_offlineotp_import(imported, None)
                .map_err(|error| api_error(400, &error))?;
            let entries: Vec<Value> = planned
                .sites
                .iter()
                .map(|candidate| {
                    json!({
                        "name": candidate.site.name,
                        "exists_in_store": existing_names.contains(&candidate.site.name),
                        "protocol": candidate.site.protocol.as_str(),
                        "host": candidate.site.host,
                        "port": candidate.site.port,
                        "username": candidate.site.username,
                        "local_dir": candidate.site.local_directory,
                        "other_local_dir": candidate.site.extra_fields.get("other_local_dir").cloned().unwrap_or_default(),
                        "has_password": candidate.site.password.as_ref().is_some_and(|p| !p.is_empty())
                            || candidate.site.proxy_password.as_ref().is_some_and(|p| !p.is_empty())
                            || (candidate.site.tunnel.enabled
                                && candidate.site.tunnel.password.as_ref().is_some_and(|p| !p.is_empty())),
                        "has_key_passphrase": candidate.site.key_passphrase.as_ref().is_some_and(|p| !p.is_empty())
                            || (candidate.site.tunnel.enabled
                                && candidate.site.tunnel_passphrase.as_ref().is_some_and(|p| !p.is_empty())),
                        "has_ssh_key": candidate.ssh_key.is_some() || candidate.tunnel_key.is_some(),
                    })
                })
                .collect();
            Ok(ApiReply {
                status: 200,
                payload: json!({
                    "success": true,
                    "encrypted": encrypted,
                    "fingerprint": fingerprint,
                    "entries": entries,
                    "entry_count": entries.len(),
                    "vault_key_count": planned.vault_keys.len(),
                    "ignored_entries": ignored_entries,
                }),
            })
        })();
        zeroize_json_secret_fields(&mut body, &["password", "data_base64"]);
        match result {
            Ok(reply) => reply,
            Err(reply) => reply,
        }
    }

    pub(super) fn handle_import_offlineotp_vault(&self, mut body: Value) -> ApiReply {
        let _guard = self.session_key_lock.lock().expect("session key lock");
        let result = (|| -> Result<ApiReply, ApiReply> {
            let password = body.get("password").and_then(Value::as_str).unwrap_or("");
            let encoded = body.get("data_base64").and_then(Value::as_str).unwrap_or("");
            if encoded.len() > 22 * 1024 * 1024 {
                return Err(api_error(413, "The key/session backup exceeds the 16 MiB limit."));
            }
            let bytes = zeroize::Zeroizing::new(
                BASE64_STD
                    .decode(encoded.as_bytes())
                    .map_err(|_| api_error(400, "The selected file is not valid base64 data."))?,
            );
            let actual_fingerprint = linscp_crypto::digests::sha256_hex(&bytes);
            if let Some(expected_fingerprint) = body
                .get("fingerprint")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if expected_fingerprint != actual_fingerprint {
                    return Err(api_error(
                        409,
                        "The selected backup file changed since it was read. Read the backup again before importing.",
                    ));
                }
            }
            // Encrypted backups require their password; plain-text backups carry
            // no envelope and need none. The two are told apart by the magic
            // marker, never by the file extension.
            let encrypted = offlineotp_vault::is_encrypted_backup(&bytes);
            if encrypted && password.is_empty() {
                return Err(api_error(400, "Enter the password used to encrypt this backup."));
            }
            let imported = open_key_session_backup(&bytes, password, encrypted)
                .map_err(|error| api_error(400, &error))?;
            let selection = parse_name_selection(body.get("sessions"))
                .map_err(|error| api_error(400, &error))?;
            if matches!(selection.as_ref(), Some(set) if set.is_empty())
                && plan_offlineotp_import(imported.clone(), None).map_err(|error| api_error(400, error))?.vault_keys.is_empty() {
                return Err(api_error(400, "Select at least one session to import."));
            }
            let replace = body.get("replace").and_then(Value::as_bool).unwrap_or(false);
            let cfg = self.state.lock().expect("m").config_root.clone();
            // `replace` never discards saved sessions: the store is always merged,
            // and same-named sessions are overwritten only for names present in
            // the backup and selected for import.
            let existing = SessionStore::load_from_dir(&cfg, self.secret_vault.as_ref())
                .map_err(|error| api_error(500, &error))?;
            let (count, skipped, ignored) = import_offlineotp_entries(
                &cfg,
                existing,
                imported,
                self.secret_vault.as_ref(),
                selection.as_ref(),
                replace,
            )
            .map_err(|error| api_error(400, &error))?;
            Ok(ApiReply {
                status: 200,
                payload: json!({
                    "success": true,
                    "imported": count,
                    "skipped_existing": skipped,
                    "ignored_entries": ignored,
                }),
            })
        })();
        zeroize_json_secret_fields(&mut body, &["password", "data_base64"]);
        match result {
            Ok(reply) => reply,
            Err(reply) => reply,
        }
    }

}
