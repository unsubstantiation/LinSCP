# Full application restore: crash-recovery transaction

Full application restore is enabled in the GUI (`POST /api/backup/import`),
and the GUI-hosted console (`backup import <file>`). The internal script
interpreter supports the same command, but no standalone CLI is shipped. Full
restore paths execute the same
preflight-first, undo-journaled transaction in
`crates/linscp-engine/src/backup.rs` backed by
`crates/linscp-engine/src/restore_journal.rs`. Legacy non-transactional restore
and in-memory-only rollback paths have been removed.

## Transaction lifecycle

1. **Interprocess lock and quiescence:** `CommanderService` acquires
   `ConfigDirectoryLock` (`config.lock`) for its lifetime and takes an
   exclusive `config_activity` write permit for `/api/backup/import`,
   `/api/vault/unlock`, and GUI-hosted `backup import <file>`, draining active
   IPC and Android share operations first. Restore requires an unlocked local
   password vault and refuses (`409`) when queued or running transfer/cleanup
   jobs, connected remote tabs, pending connection attempts or host-key
   challenges, auto-reconnect attempts, open SSH terminals, or X2Go sessions
   are active. Standalone `ScriptInterpreter` `backup import <file>` acquires
   `ConfigDirectoryLock` directly and refuses when any remote session slot is
   open.
2. **Preflight before mutation:** `prepare_restore_plan` validates all bundle
   stores (`sessions.ini`, `workspaces.json`, `bookmarks.json`,
   `preferences.json`, `accounts.ini`, `sshhostkeys`,
   `explorer-commands.json`, `custom-commands.json`, `monitor.json`, and
   `transfer-presets.ini`), verifies vault-key references, decrypts and
   re-encrypts all session secrets and vault SSH keys under the destination's
   existing `sessions.key` master key, checks key collisions without
   overwriting existing keys, and serializes encrypted `workspaces.json` and
   `sshhostkeys` before creating `.full-restore-journal`.
3. **Authenticated undo journal:** `restore_journal::prepare` snapshots the
   pre-restore state (presence and contents) of all 11 managed configuration
   stores (including `auto-reconnect.json`) and records which vault key and
   `.meta` paths are newly created by this restore, encrypts and authenticates
   the bounded v1 journal under the destination vault's master key, writes it
   atomically, and syncs `config_dir`.
4. **Ordered publication and commit:** Newly imported vault key and `.meta`
   files are written with exclusive no-replace semantics (`rename_no_replace`),
   then `keys/` and `config_dir` are synced before `sessions.ini` or other
   stores are modified. Present stores are written atomically, absent optional
   stores are removed, `auto-reconnect.json` is cleared so pre-restore sessions
   are not reconnected against replaced configuration, and `config_dir` is
   synced before `restore_journal::commit` removes `.full-restore-journal` and
   syncs `config_dir` again. After commit in `CommanderService`, in-memory
   preferences are reloaded and disconnected remote tabs, challenges, pending
   sites, reconnect timers, stale monitors, and finished queue entries are
   cleared.
5. **Startup and post-failure recovery:** If `.full-restore-journal` exists on
   startup (or remains after an interrupted/failed restore), `CommanderService`
   raises `recovery_gate`, defers preference loading and temporary-key cleanup,
   and blocks all routes except `GET /api/vault/status` and
   `POST /api/vault/unlock` with `503`. Unlocking the vault authenticates the
   journal and runs idempotent `recover_interrupted_restore`, restoring all 11
   stores and syncing `config_dir` **before** deleting any newly published
   vault key files so sessions never reference missing keys if recovery itself
   is interrupted. Corrupt or unauthenticated journals fail closed without
   creating a replacement `sessions.key` or deleting the journal.

## Platform durability and cross-process boundaries

- **Directory durability:** `sync_directory` uses `O_DIRECTORY | O_NOFOLLOW` +
  `fsync` on Linux and Android, and opens the directory handle on Windows with
  `GENERIC_WRITE`, `FILE_SHARE_READ | FILE_SHARE_WRITE` (omitting
  `FILE_SHARE_DELETE`), and `FILE_FLAG_BACKUP_SEMANTICS |
  FILE_FLAG_OPEN_REPARSE_POINT`, rejecting reparse points before calling
  `FlushFileBuffers`. Windows `atomic_replace` and `rename_no_replace` pass
  `MOVEFILE_WRITE_THROUGH`, and private/regular file helpers omit
  `FILE_SHARE_DELETE`.
- **One-shot `--shell-upload` coexistence:** `CommanderService` pre-creates
  `shell-manifests/` under `ConfigDirectoryLock` at startup/unlock, and
  `--shell-upload` writes only leaf `<16-hex>.json` manifests inside
  `shell-manifests/` while `ops.rs` reads them with bounded
  `open_private_file_no_follow`, allowing file-manager upload handoff to a
  running GUI without racing configuration store renames.
- **External writers and verification scope:** `ConfigDirectoryLock` is
  advisory; external editors or older binaries that do not honor `config.lock`
  must not modify the configuration directory concurrently. See the
  [final parity review](final-parity-review.md) for subsequent CI evidence and
  its platform and device limitations. Selective imports are not covered by
  this full-restore transaction.
