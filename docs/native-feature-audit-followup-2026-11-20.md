# Native feature audit follow-up — 2026-11-20

**Implementation follow-up:** This branch now contains fixes for the findings below and for stale monitor candidates. Treat this report as the pre-fix audit, not a statement that every issue remains unfixed. The Rust changes and live protocol behavior still require a full build and acceptance testing. The new synchronization baseline is keyed by protocol and username as well as endpoint and directories. If an older baseline exists, synchronization refuses to proceed until the user reviews and backs up/removes it; it is not silently reused across accounts.

Scope: source trace of the shared GUI, Tauri's asynchronous service dispatch, session persistence, synchronization and import. This is a prioritized review, not an exhaustive feature certification. The earlier `feature-audit-2026-11-20.md` is a historical baseline; its import, folder-delete and session-file read-error findings were addressed in merged PR #126, not re-reported here. Findings below are confirmed by code paths unless marked as requiring reproduction. No application fixes were made in this audit.

## Priority 0 — FTP security selector can select plaintext

The site form's advanced FTPS selector sends `ftps` as `explicit`, `implicit`, or an empty string (`source/gui/web/index.html`, `siteFtps` and `currentSiteForm`). `parse_gui_session_spec` passes those strings through (`crates/linscp-service/src/tabs.rs`, `extra_keys`), but the connection engine recognizes only numeric strings `1`, `2`, `3`, and `0` (`crates/linscp-engine/src/url_and_raw.rs`, FTP branch of `connect_gui_site_spec`). For a session whose protocol is FTP, the unrecognized `explicit` or `implicit` value falls back to FTP, not FTPS. An accepting plaintext FTP server could therefore receive credentials/data without the TLS the user selected. Separately, the stored-field validator rejects these strings, including the empty string, on strict stored-site conversion; the GUI parser masks conversion errors with `unwrap_or_default`.

**Immediate precaution:** Do not rely on the advanced FTPS selector for an FTP session. Verify the actual connection protocol independently before sending credentials or files. Fix by mapping UI choices to validated engine values and failing closed on unknown values; add GUI-to-engine and live FTP/FTPS regression tests, including a server that accepts plaintext.

## Priority 1 — Advanced TLS fields do not reach the engine

`currentSiteForm` sends `min_tls_version`, `max_tls_version`, `tls_certificate_file`, `ca_certificate_file`, and `pinned_pubkey`; the GUI parser's allowlist instead accepts `tls_min_version`, `tls_max_version`, `tls_cert_file`, and `tls_ca_file`, and does not accept `pinned_pubkey` (`source/gui/web/index.html`, `crates/linscp-service/src/tabs.rs`). Thus those visible controls are dropped for a newly entered session. The engine consumes the canonical TLS keys and `pinned_public_key` (`crates/linscp-engine/src/url_and_raw.rs`, `build_tls_settings`). This includes the user-specified pin, so the UI must not be treated as enforcing it. Confirm behavior with a live TLS server and add round-trip, connection-config, pin mismatch and invalid-setting tests. Recheck legacy stored fields and the supported pin format during the fix.

## Priority 1 — synchronization baseline errors are hidden

The preview uses `SyncState::load(...).unwrap_or_default()` (`crates/linscp-service/src/lib.rs`, `sync_preview_async`), and queued runs do the same and discard `state.save` errors (`crates/linscp-service/src/queue.rs`, `QueueJob::SyncRun`). A read failure is treated as no baseline, while a failed write can still report successful completion. The planner uses that baseline to decide two-way changes and some deletions (`crates/linscp-engine/src/sync_planner.rs`, `plan_synchronization`), so a later plan may differ from one with the proper history. Malformed records are also silently skipped or parsed as zero. This does not prove a specific file will be lost; it does establish silent failure of the recorded history. Propagate read errors, validate corrupt state, and report a baseline-save failure distinctly after already-completed file operations. Test absent versus unreadable/corrupt state and failed writes, including two-way delete/conflict cases.

The state key also uses only host and port plus paths (`sync_target` in service), not username or protocol: accounts on the same host may have different contents at the same remote path. Test and isolate identities without silently migrating an incompatible baseline.

## Priority 1 — stored data can be silently replaced after parse failure

Bookmark and workspace list/save handlers use `read_to_string(...).ok().and_then(parse).unwrap_or(default)` (`crates/linscp-service/src/lib.rs`, `handle_get_bookmarks`, `handle_bookmarks_save`, `handle_get_workspaces`, `handle_workspaces_save`). A malformed JSON file is presented as empty; a subsequent save can atomically replace it with the newly created entries, losing the earlier contents. A read error can likewise be treated as empty if a subsequent replacement succeeds. Missing files should still initialize normally, but other read/parse/shape errors should stop mutation and be shown to the user. Bookmark and workspace delete handlers also discard write errors and return success; bookmark save can report success without adding anything when the requested side is absent or not an array. Cover all of these with service tests and read-only/fault-injected filesystem tests.

A related but distinct risk remains in `SessionStore::parse_ini`: unrecognized lines are skipped, invalid protocol and port default, and parsing returns `Ok` (`crates/linscp-engine/src/session_store.rs`). For example a damaged section header can cause entries to disappear from the parsed store, which a later successful save can serialize back over the original. PR #126 prevents overwriting on **read** errors, not on parse corruption. Define compatible validation and recovery/backup behavior before making it strict; test corrupted and legacy files.

## Priority 2 — proxy passwords do not round-trip in the GUI

The list response intentionally removes `proxy_password` (`stored_site_to_gui_json`), so `fillSiteForm` fills it with an empty value. The form always sends this empty value, and the parser inserts it into `raw_fields`, overriding the saved value when connecting a selected site. Save has keep flags for user/tunnel credentials but no corresponding proxy flag (`handle_save_session`); an unrelated re-save therefore drops a decryptable proxy password. The remember-password checkbox also does not clear a newly typed proxy password. Check authenticated proxy behavior live, then add explicit secret presence/keep/clear semantics and tests without exposing the secret to the frontend.

## Priority 2 — out-of-order pane results may target the wrong context

`loadLocal` and `loadRemote` apply every successful asynchronous response to global pane state without checking request sequence or whether the active tab changed (`source/gui/web/index.html`). A slower old response can overwrite the newer listing after navigation or a tab switch. Subsequent transfer operations combine current tab ID with the displayed state paths, and deletion combines current tab ID with selected displayed names. The exact consequences depend on service-side current directory and timing, so reproduce with controlled delayed replies before characterizing a specific destructive outcome. Use per-pane request generations and tab identity checks, and cover navigation, tab switch, failure, and destructive action races.

## Deliberate restrictions and verification gaps

- OpenSSH import is a subset: wildcard/multiple host patterns, `Match`, `Include`, and percent-token handling have explicit skips (`crates/linscp-engine/src/importers.rs`); inspect the scan's reported skips before importing. Unsupported ordinary directives can also be ignored, so import is not an `ssh_config` evaluator.
- Vault-key deletion protection is process-local, not cross-process transactional locking (`docs/local-credential-vault.md`). Avoid concurrent writers or external edits to the session/key store.
- Automatic sudo password entry is opt-in and prompt-based; a remote program can spoof the prompt. This cannot guarantee the user's requested isolation from remote programs on a shared PTY.
- X2Go remains experimental; real server/session interoperability, native rendering, keyboard handling and cleanup need end-to-end testing. Android SAF, sharing, lifecycle and actual devices, Windows packaging, SSH/FTP/WebDAV/S3 interoperability, interruption and recovery were not live-tested in this audit.
- Static route checking establishes literal endpoint/method coverage, not behavior. Mocked GUI tests cannot prove service or server semantics.

## Checks performed

- `cd ui && npm ci --ignore-scripts && npm test`: passed; one optional native-canvas test skipped, 177 localization checks passed. jsdom printed its known unimplemented-navigation warnings; the command exited successfully. The first attempt without installed dependencies failed because `tsc` was absent; `npm ci` resolved it.
- `python3 tools/check_shared_frontend.py`, `tools/check_upstream_parity.py`, `tools/tests/test_shared_frontend.py` (5), `tools/tests/test_ppk_fixture_format.py` (1), `tools/tests/test_workflow_triggers.py` (10), `tools/check_ci_test_execution.py`, and `tools/compile_translations.py --check`: passed. Parity inventory validation is not evidence that all GUI features work.
- Full Rust compile/tests and live server/device acceptance were not run: previous local Cargo resolution failed on crates.io TLS, and the partial vendored cache lacked dependencies. As last checked during this audit, PR #126 Android unsigned, Debian, Linux and Windows jobs were still in progress; signed Android release was skipped. Their eventual outcomes are not established here.

## Suggested sequence

1. Fail closed on FTP mode and repair TLS/pin field mapping, with end-to-end security tests.
2. Make persistence and sync state failures explicit and preserve original files; cover failure injection and recovery.
3. Fix proxy secret lifetime/keep/clear behavior and pane request races.
4. Run the complete Rust CI and protocol/platform acceptance matrix, then revisit experimental and deliberately restricted features separately.
