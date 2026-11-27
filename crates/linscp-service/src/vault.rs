//! Vault lifecycle and SSH key-management endpoints.
//!
//! Backup/interchange handlers and shared key helpers remain in the parent
//! module until their separate extraction, so this move preserves behavior.
use super::*;

impl CommanderService {
    pub(super) fn handle_vault_retry_lock(&self) -> ApiReply {
        match self.retry_config_lock() {
            Ok(()) => ApiReply { status: 200, payload: json!({ "success": true }) },
            Err(error) => api_error(503, error),
        }
    }

    pub(super) fn handle_vault_status(&self) -> ApiReply {
        let config_root = self.config_root();
        match self.secret_vault.status(&config_root) {
            Ok("setup_required") if matches!(linscp_engine::backup::restore_recovery_required(&config_root), Ok(true)) =>
                api_error(503, "Cannot recover restore: the existing password-wrapped vault key is missing or unavailable."),
            Ok(status) => ApiReply { status: 200, payload: json!({"success": true, "vault": status}) },
            Err(error) => api_error(500, error.to_string()),
        }
    }

    pub(super) fn handle_vault_unlock(&self, mut body: Value) -> ApiReply {
        let _guard = self.session_key_lock.lock().expect("session key lock");
        let config_root = self.config_root();
        let pending = match linscp_engine::backup::restore_recovery_required(&config_root) {
            Ok(pending) => pending,
            Err(error) => return api_error(503, error),
        };
        if pending && !matches!(self.secret_vault.status(&config_root), Ok("locked" | "unlocked")) {
            if let Some(Value::String(password)) = body.get_mut("password") { zeroize::Zeroize::zeroize(password); }
            return api_error(503, "Cannot recover restore: the existing password-wrapped vault key is missing or unavailable.");
        }
        let unlock_result = {
            let password = body.get("password").and_then(Value::as_str).unwrap_or("");
            self.secret_vault.unlock_or_setup(&config_root, password, self.legacy_secret_vault.as_ref())
        };
        if let Some(Value::String(password)) = body.get_mut("password") {
            zeroize::Zeroize::zeroize(password);
        }
        if let Err(error) = unlock_result {
            return api_error(400, error.to_string());
        }
        if pending {
            let lock_guard = self.config_lock.lock().expect("config lock mutex");
            let lock = match lock_guard.as_ref() {
                Ok(lock) => lock,
                Err(error) => {
                    let msg = error.clone();
                    drop(lock_guard);
                    let _ = self.secret_vault.lock();
                    return api_error(503, msg);
                }
            };
            match linscp_engine::backup::recover_interrupted_restore(&config_root, self.secret_vault.as_ref(), lock) {
                Ok(true) => {}
                Ok(false) => { let _ = self.secret_vault.lock(); return api_error(503, "Restore journal disappeared during recovery."); },
                Err(error) => { let _ = self.secret_vault.lock(); return api_error(503, format!("Restore recovery failed: {error}")); },
            }
        }
        if let Err(error) = SessionStore::protect_existing(&config_root, self.secret_vault.as_ref())
            .and_then(|_| auto_reconnect::protect_existing(&config_root, self.secret_vault.as_ref()))
            .and_then(|_| linscp_engine::protected_file::migrate(&config_root.join("sshhostkeys"), "ssh-host-keys", self.secret_vault.as_ref(), |bytes| {
                let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
                linscp_engine::hostkeys::HostKeyCache::validate(text)
            }))
            .and_then(|_| linscp_engine::protected_file::migrate(&config_root.join("workspaces.json"), "workspaces", self.secret_vault.as_ref(), |bytes| {
                let value: Value = serde_json::from_slice(bytes).map_err(|e| format!("Invalid workspace file: {e}"))?;
                // Older engine versions used an array; preserve it for compatibility.
                if value.is_array() || value.get("workspaces").is_some_and(Value::is_object) { Ok(()) } else { Err("Invalid workspace structure".into()) }
            })) {
            let _ = self.secret_vault.lock();
            return api_error(500, format!("Could not protect existing session data: {error}"));
        }
        if self.recovery_gate.load(std::sync::atomic::Ordering::Acquire) {
            let preferences = PreferencesStore::load(&config_root).unwrap_or_default();
            self.state.lock().expect("state mutex").preferences = preferences;
            self.recovery_gate.store(false, std::sync::atomic::Ordering::Release);
        }
        let _ = linscp_platform::create_private_dir(&config_root.join("shell-manifests"));
        let stale_temp_dir = config_root.join("tmp").join("unlocked-keys").join(std::process::id().to_string());
        let _ = std::fs::remove_dir_all(stale_temp_dir);
        ApiReply { status: 200, payload: json!({"success": true, "vault": "unlocked"}) }
    }

    pub(super) fn handle_vault_lock(&self) -> ApiReply {
        let _guard = self.session_key_lock.lock().expect("session key lock");
        // Locking explicitly disconnects every tab; do not restore them later.
        {
            let state = self.state.lock().expect("state mutex");
            let result = auto_reconnect::load(&state.config_root, self.secret_vault.as_ref()).and_then(|mut intentions| {
                let before = intentions.len();
                intentions.clear();
                if intentions.len() != before { auto_reconnect::save(&state.config_root, self.secret_vault.as_ref(), &intentions)?; }
                Ok(())
            });
            if let Err(error) = result { return api_error(500, error); }
        }
        if let Err(error) = self.secret_vault.lock() {
            return api_error(500, error.to_string());
        }
        let mut state = self.state.lock().expect("state mutex");
        let tab_ids: Vec<u64> = state.tabs.keys().copied().collect();
        for tab_id in tab_ids {
            self.queue.cancel_for_tab(tab_id);
            state.terminals.close_for_tab(tab_id);
            state.monitors.forget(tab_id);
        }
        self.queue.clear_finished();
        let drained_tunnels: Vec<_> = state.desktop_tunnels.drain().collect();
        let drained_x2go: Vec<_> = state.x2go.drain().collect();
        state.x2go_pending.clear();
        let drained_edits: Vec<ExternalEditSession> =
            state.external_edits.drain().map(|(_, e)| e).collect();
        state.tabs.clear();
        state.challenges.clear();
        state.pending_connections.clear();
        state.pending_sites.clear();
        state.auto_pending.clear();
        state.auto_retry_at.clear();
        state.auto_suspended.clear();
        state.active_tab_id = None;
        wipe_logs(&mut state.logs);
        drop(state);
        drop(drained_tunnels);
        drop(drained_x2go);
        for edit in drained_edits {
            edit.closed.store(true, std::sync::atomic::Ordering::Release);
            if let Some(dir) = edit.staged_dir {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
        ApiReply { status: 200, payload: json!({"success": true, "vault": "locked"}) }
    }

    pub(super) fn handle_vault_ssh_keys(&self) -> ApiReply {
        let config_root = self.config_root();
        match self.secret_vault.status(&config_root) {
            Ok("unlocked") => {}
            Ok(_) => return api_error(423, "Unlock the local vault before choosing an SSH key."),
            Err(error) => return api_error(500, error.to_string()),
        }
        let key_dir = config_root.join("keys");
        let entries = match std::fs::read_dir(&key_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return ApiReply { status: 200, payload: json!({"success": true, "keys": []}) };
            }
            Err(error) => return api_error(500, format!("Cannot list vault keys: {error}")),
        };
        let mut keys = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !entry.file_type().map(|kind| kind.is_file()).unwrap_or(false) { continue; }
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else { continue; };
            let Some(id) = file_name.strip_suffix(".key.vault") else { continue; };
            if id.len() != 32 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) { continue; }
            let label = read_vault_key_label(&key_dir, id);
            keys.push(json!({
                "reference": format!("{LOCAL_VAULT_KEY_PREFIX}{id}"),
                "label": label,
            }));
        }
        keys.sort_by(|left, right| left["label"].as_str().cmp(&right["label"].as_str()));
        ApiReply { status: 200, payload: json!({"success": true, "keys": keys}) }
    }

    /// Remove only one explicitly confirmed vault key and its metadata. Saved
    /// sites using the key must first be updated or removed.
    pub(super) fn handle_vault_ssh_key_delete(&self, body: Value) -> ApiReply {
        let _guard = self.session_key_lock.lock().expect("session key lock");
        let config_root = self.config_root();
        match self.secret_vault.status(&config_root) {
            Ok("unlocked") => {}
            Ok(_) => return api_error(423, "Unlock the local vault before deleting an SSH key."),
            Err(error) => return api_error(500, error.to_string()),
        }
        if body.get("confirm").and_then(Value::as_bool) != Some(true) {
            return api_error(400, "Confirm SSH key deletion first.");
        }
        let Some(id) = body.get("reference").and_then(Value::as_str)
            .and_then(|reference| reference.strip_prefix(LOCAL_VAULT_KEY_PREFIX))
            .filter(|id| id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())) else {
            return api_error(400, "Invalid encrypted SSH key reference.");
        };
        let reference = format!("{LOCAL_VAULT_KEY_PREFIX}{id}");
        let store = match SessionStore::load_from_dir(&config_root, self.secret_vault.as_ref()) {
            Ok(store) => store,
            Err(error) => return api_error(500, format!("Cannot check stored sessions: {error}")),
        };
        let users: Vec<&str> = store.sites().iter().filter(|site|
            site.private_key.as_deref() == Some(reference.as_str()) ||
            site.tunnel.keyfile.as_deref() == Some(reference.as_str())
        ).map(|site| site.name.as_str()).collect();
        if !users.is_empty() {
            return api_error(409, format!("Cannot delete this key: stored sessions use it: {}. Change or delete those sessions first.", users.join(", ")));
        }
        let key_dir = config_root.join("keys");
        // Never traverse a symlink masquerading as the vault key directory.
        match std::fs::symlink_metadata(&key_dir) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return api_error(400, "Invalid vault key directory."),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return api_error(404, "SSH key is no longer in the vault."),
            Err(error) => return api_error(500, format!("Cannot inspect vault keys: {error}")),
        }
        let private_path = key_dir.join(format!("{id}.key.vault"));
        match std::fs::symlink_metadata(&private_path) {
            Ok(metadata) if metadata.file_type().is_file() => {}
            Ok(_) => return api_error(400, "Invalid encrypted SSH key file."),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return api_error(404, "SSH key is no longer in the vault."),
            Err(error) => return api_error(500, format!("Cannot inspect encrypted SSH key: {error}")),
        }
        if let Err(error) = std::fs::remove_file(&private_path) {
            return api_error(500, format!("Could not delete the encrypted SSH key: {error}"));
        }
        // Metadata cleanup is best effort, but report partial failure honestly.
        // remove_file removes a symlink itself, never the target.
        let mut metadata_failed = false;
        for extension in ["label", "pub"] {
            if let Err(error) = std::fs::remove_file(key_dir.join(format!("{id}.{extension}"))) {
                if error.kind() != std::io::ErrorKind::NotFound { metadata_failed = true; }
            }
        }
        if metadata_failed {
            return ApiReply { status: 500, payload: json!({"success": false, "deleted": true,
                "error": "The encrypted SSH key was deleted, but some metadata could not be removed."}) };
        }
        ApiReply { status: 200, payload: json!({"success": true, "deleted": true}) }
    }

    pub(super) fn handle_vault_ssh_key_import(&self, mut body: Value) -> ApiReply {
        let _guard = self.session_key_lock.lock().expect("session key lock");
        let config_root = self.config_root();
        let name = body.get("name").and_then(Value::as_str).unwrap_or("")
            .rsplit(['/', '\\']).next().unwrap_or("")
            .chars().filter(|character| !character.is_control()).take(128).collect::<String>();
        let private_key = body.get("private_key").and_then(Value::as_str).unwrap_or("");
        if private_key.is_empty() || private_key.as_bytes().len() > 1024 * 1024 || private_key.contains('\0') {
            if let Some(Value::String(private_key)) = body.get_mut("private_key") {
                zeroize::Zeroize::zeroize(private_key);
            }
            return api_error(400, "Choose a non-empty SSH key file no larger than 1 MiB.");
        }
        if looks_like_public_ssh_key(private_key) {
            if let Some(Value::String(private_key)) = body.get_mut("private_key") {
                zeroize::Zeroize::zeroize(private_key);
            }
            return api_error(400, "Choose a private SSH key file, not a public key (.pub).");
        }
        let derived_public = derive_public_ssh_key_optional(private_key).unwrap_or_default();
        let plaintext = zeroize::Zeroizing::new(private_key.as_bytes().to_vec());
        let encryption_result = self.secret_vault.seal_local_blob(&plaintext);
        if let Some(Value::String(private_key)) = body.get_mut("private_key") {
            zeroize::Zeroize::zeroize(private_key);
        }
        let encrypted = match encryption_result {
            Ok(encrypted) => encrypted,
            Err(error) => return api_error(400, error.to_string()),
        };
        let key_dir = config_root.join("keys");
        if let Err(error) = linscp_platform::create_private_dir(&key_dir) {
            return api_error(500, error.to_string());
        }
        if let Some(existing_id) = find_existing_vault_key_id(&key_dir, &plaintext, self.secret_vault.as_ref()) {
            backfill_vault_key_metadata(
                &key_dir,
                &existing_id,
                (!name.is_empty()).then_some(name.as_str()),
                &derived_public,
                false,
            );
            let label = read_vault_key_label(&key_dir, &existing_id);
            return ApiReply { status: 200, payload: json!({
                "success": true,
                "reference": format!("{LOCAL_VAULT_KEY_PREFIX}{existing_id}"),
                "label": label,
                "deduplicated": true,
            }) };
        }
        for _ in 0..8 {
            let mut random = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut random);
            let id = random.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
            let encrypted_path = key_dir.join(format!("{id}.key.vault"));
            match write_exclusive_private_file(&encrypted_path, &encrypted) {
                Ok(()) => {}
                Err(linscp_platform::PlatformError::AlreadyExists(_)) => continue,
                Err(error) => {
                    let _ = std::fs::remove_file(&encrypted_path);
                    return api_error(500, error.to_string());
                }
            }
            let label = derive_vault_key_label(&name, &derived_public, &id);
            let label_path = key_dir.join(format!("{id}.label"));
            match write_exclusive_private_file(&label_path, label.as_bytes()) {
                Ok(()) => {}
                Err(linscp_platform::PlatformError::AlreadyExists(_)) => {
                    let _ = std::fs::remove_file(&encrypted_path);
                    continue;
                }
                Err(error) => {
                    let _ = std::fs::remove_file(&encrypted_path);
                    return api_error(500, error.to_string());
                }
            }
            if !derived_public.is_empty() {
                let public_path = key_dir.join(format!("{id}.pub"));
                match write_exclusive_private_file(&public_path, derived_public.as_bytes()) {
                    Ok(()) => {}
                    Err(linscp_platform::PlatformError::AlreadyExists(_)) => {
                        let _ = std::fs::remove_file(&label_path);
                        let _ = std::fs::remove_file(&encrypted_path);
                        continue;
                    }
                    Err(error) => {
                        let _ = std::fs::remove_file(&public_path);
                        let _ = std::fs::remove_file(&label_path);
                        let _ = std::fs::remove_file(&encrypted_path);
                        return api_error(500, error.to_string());
                    }
                }
            }
            return ApiReply { status: 200, payload: json!({
                "success": true,
                "reference": format!("{LOCAL_VAULT_KEY_PREFIX}{id}"),
                "label": label,
            }) };
        }
        api_error(500, "Cannot allocate a unique encrypted SSH key file.")
    }

}
