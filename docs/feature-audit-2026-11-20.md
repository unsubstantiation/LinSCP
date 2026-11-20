# Feature and release-readiness audit — 2026-11-20

**Baseline:** `4987880ca4adea91a8d3a8e056217620d39859ed` (includes PR #125). This is a focused static audit of the current native GUI, service routes, known limitations and CI, not an exhaustive security review or a claim that unmentioned features are complete. Prior reports and the generated parity ledger include historical CLI and removed-host material; their counts are not a count of broken GUI features.

> **Follow-up status on `arena/7562cb1f-linscp` (after PR #128):** portable
> encrypted full application backup and crash-safe transactional restore (with
> vault SSH key rewrapping, encrypted undo journal `.full-restore-journal`,
> startup recovery gate, advisory `ConfigDirectoryLock`, and Linux/Android/
> Windows directory durability barriers) are now implemented and enabled in the
> GUI and console, alongside encrypted `sessions.ini`/`sshhostkeys`/
> `workspaces.json`/`auto-reconnect.json` and memory-only Commander logs from
> PR #128. Full CI Rust workspace builds/tests on Linux, Windows, and Android
> still need to run on GitHub Actions; X2Go live interoperability, Android
> Keystore/device verification, and transfer/queue parity gaps below remain
> open.

**Status vocabulary:** *broken* means a concrete mismatch visible in current source; *limited* means intentionally restricted or missing behavior; *unverified* means there is insufficient end-to-end evidence, not proof of failure. Priority is suggested by user impact and risk, not a release commitment.

## P0 — release and data safety

### 1. CI is red: the new PPK fixture test is not registered (broken)

`tools/tests/test_workflow_triggers.py::test_every_tools_test_is_named_by_some_workflow` fails because `test_ppk_fixture_format.py` is not named in a workflow. This was reproduced locally. In PR #125, Linux checks failed at “Check GUI distribution, workflow triggers, and X2Go”; the Rust test steps did not run. At the time of this audit the other PR jobs were cancelled during build/test steps, not independently demonstrated to fail. See [PR checks](https://github.com/unsubstantiation/LinSCP/pull/125/checks). Logs were inaccessible from this environment, but the job step status and the same local failure are available.

**Next:** register the test in CI, rerun Linux/Windows/Android and packaging, inspect all results, and address any newly exposed compilation or integration failures. Do not infer a passing Rust build from the frontend suite.

### 2. Saving a site can discard other sites if the store cannot be read (source-confirmed risk)

`handle_save_session` in `crates/linscp-service/src/lib.rs` uses `SessionStore::load_from_dir(...).unwrap_or_default()` immediately before `upsert` and `save_to_dir`. `load_from_dir` in `crates/linscp-engine/src/session_store.rs` returns errors for read failures; the fallback treats such a failure as an empty store. If the subsequent write succeeds, it can replace the existing store with only the submitted session. It also uses a default when looking up secrets to preserve. No failure-injection test was run here.

**Next:** fail closed on load errors before making persistent changes; test read and parse/write failures and verify original bytes and secrets remain intact. Review other store read-modify-write paths for the same pattern.

### 3. Vault-key deletion protection is only process-local (limitation/risk)

`session_key_lock` is an `Arc<Mutex<()>>` initialized per `CommanderService` instance. It coordinates key deletion with several session operations inside that instance, but it is not a cross-process lock and cannot serialize an external editor or another independent service instance. A concurrent writer could add a reference after the deletion check. The current code does check both destination and tunnel references and refuses deletion when it observes users.

**Next:** define the supported multi-instance/external-writer model; if concurrent instances are supported, use a shared interprocess locking or transactional strategy across all session writers and key deletion, and add deterministic race tests. Do not promise protection against arbitrary external edits without such a mechanism.

## P1 — user-visible broken flows

### 4. Import stored sessions UI is not connected to a working import flow (broken)

The import dialog calls `GET /api/sessions/import` and then `POST /api/sessions/import` (`source/gui/web/index.html`, `scanImportSource` and `runSessionImport`). The GET handler in `crates/linscp-service/src/lib.rs` always returns an empty `sources` array, and the dispatch table has no POST handler for that path. Separate OpenSSH and FileZilla parser routes exist, but they only parse submitted text and are not the dialog's scan-and-save flow. The key/session backup import is a separate feature and is not the same path.

**Next:** implement scan, selectable import, collision policy, persistence and platform-specific path access, or disable the dialog with a clear explanation. Add tests through the actual frontend-to-service boundary for OpenSSH/FileZilla, invalid files and overwrite behavior.

### 5. Site-folder deletion does not implement the UI's contract (broken; possible wrong-target deletion)

`deleteSiteFolder` sends `{name: folder, folder: true}` and asks to remove all sessions in that folder. `handle_delete_session` ignores `folder` and calls `store.remove(&name)` for an exact session name. Normally it returns an error instead of deleting the folder's sessions; if an exact session has the same name as the folder, it can delete that session rather than the confirmed folder contents. The client test only checks that the flag was posted using a mocked response (`source/gui/tests/ClientTest.js`).

**Next:** implement explicit folder deletion with a well-defined nested-folder boundary and confirmation, or remove/disable the control. Test a folder and same-named session together, nested folders, cancellation and storage failures through the real service.

### 6. SSH terminal automatic sudo password is inherently spoofable (limited/security)

The opt-in responder in `crates/linscp-service/src/terminal_bridge.rs` matches terminal output after a submitted line; a remote process can print the same prompt and receive the password. The GUI warns about this, and only the standard English prompt is recognized (`source/gui/web/index.html`, `siteSudoPassword`). This cannot satisfy a strict guarantee that only sudo, and never another remote program, receives the secret through an untrusted remote PTY.

**Next:** keep explicit opt-in and warning; investigate a separately authenticated privileged-operation design or manual entry rather than claiming prompt matching provides process isolation. Test rejected/repeated prompts, chunking, disconnect and secret redaction; document localization limitations.

## P1/P2 — major incomplete capabilities

### 7. Built-in X2Go/KDrive viewer (experimental, unverified)

The GUI and service have an experimental KDrive path, but `docs/x2go-rendering.md` explicitly records no live X2Go-server interoperability test or complete Rust build in the environment where it was developed. Clipboard, sound, file sharing, resizing and session resume are not implemented; NX3 is not supported. Keyboard/IME, AltGr, synchronization barriers, image decoding and cleanup have known limitations. Older descriptions in `docs/native-feature-audit.md`, `crates/linscp-types/src/lib.rs` and `crates/linscp-platform/src/desktop.rs` still say the viewer is not implemented, so documentation and code paths conflict.

**Next:** first establish full builds and a live KDrive-backed X2Go test on supported platforms, including input, latency, teardown and server failure; correct stale descriptions. Then prioritize missing session and desktop features. A KDrive implementation does not imply compatibility with ordinary NX3 servers.

### 8. Transfers and synchronization (implemented subsets, restricted)

`readme.md` and `crates/linscp-service/src/lib.rs` document or enforce restrictions: no cross-server directory moves or S3-source moves; limited cross-protocol directory copies; safe approved overwrites unavailable for some transfers; S3 directory creation is refused where exclusivity cannot be guaranteed; symlink creation is SFTP-only. Cancellation and remote tree operations may leave partial files or trees; FTP/SFTP cleanup and FTP publication have race constraints. These refusals are safety boundaries, not permission to silently use an unsafe fallback.

**Next:** build a protocol/operation/platform matrix and add live acceptance tests for each claimed combination, interruption, conflicts and recovery. Where a safe guarantee is impossible, keep refusal and explain the limitation rather than pretending support.

### 9. Android platform integration (partial/unverified)

`docs/android.md` says Android Keystore/biometrics are not wired and the session master key is in the app sandbox. Direct RDP/VNC/SPICE viewer handoff is supported, but X2Go/X11 and SSH jump-tunnel viewer handoff are not. `docs/android-outgoing-share-plan.md` describes implemented private staging with outstanding real receiver/device tests and no progress or cancellation. The parity plan records SAF synchronization tested with mocks rather than real document providers.

**Next:** prioritize Keystore-backed protection and lifecycle/recovery design; exercise SAF, sharing, foreground transfer and viewer intents with real providers/receivers on emulator and device, including failure, process recreation and permissions. Record which OS versions and devices were tested.

### 10. Editor encoding, authentication and desktop integrations (limited)

The GUI editor/search is UTF-8-only according to `docs/remaining-parity-plan.md` (`editing.non-utf8-encodings`); the historical CLI description is not evidence for the native GUI. Native account sign-in is not implemented: service login returns “Accounts not enabled”. Workspace restoration does not interactively resolve host-key challenges during batch restore (`docs/native-feature-audit.md`). Desktop file-manager/viewer integrations still need real platform validation.

**Next:** decide whether legacy encodings and native accounts are in scope; if so implement with security and round-trip tests. Improve workspace challenge recovery and test native integrations on each platform.

## P1 — verification and audit infrastructure

### 11. UI tests can pass while the real API contract is broken (confirmed coverage gap)

`npm --prefix ui test` includes jsdom client tests with mocked responses. The import and folder-delete mismatches above pass because mocks implement expected behavior, not the service's actual behavior. `tools/check_shared_frontend.py` reports that every endpoint is served despite the missing POST import route: the check is not proof of method-level or semantic compatibility.

**Next:** add method-aware route checks and integration tests using the actual `CommanderService` and frontend bridge, with non-mocked persistence and negative cases. Maintain separate component, service, end-to-end and live-server evidence.

### 12. Cross-platform and legacy parity evidence is incomplete (unverified)

`docs/linux-feature-inventory.md` records 117 historical capabilities: 30 verified, 83 partial and 4 missing; its header explicitly cautions that older CLI-based evidence does not establish current GUI behavior. `docs/remaining-parity-plan.md` lists 87 capability gaps, many reflecting missing evidence rather than missing code. Current Debian CI defines Rust unit and live fixture tests; Windows defines workspace tests and native smoke; Android defines APK and emulator smoke workflows, but not equivalent Rust test execution or real-device SAF coverage. Workflow definitions are not proof of passing runs.

**Next:** publish a current native-GUI feature matrix with per-platform runnable tests, test results and restrictions; distinguish legacy CLI-only material and mock tests from live/device evidence. Run the actual CI after item 1, then add missing platform and end-to-end coverage.

## Checks executed during this audit

- `npm ci --prefix ui --no-audit --no-fund` and `npm --prefix ui test`: passed; Node suite 135 tests, 134 passed, one skipped; localization 177 checks passed. Client tests include mocks.
- `python3 tools/check_upstream_parity.py`, `python3 tools/check_shared_frontend.py`, `python3 tools/compile_translations.py --check`: passed; these validate consistency, not complete behavior.
- Python `test_shared_frontend.py` (4) and `test_gui_distribution.py` (10): passed. `test_x2go_installer.py` (6): passed.
- Python `test_workflow_triggers.py`: **failed** (1 of 10) as described in item 1.
- No Rust compiler/build or live server/device test was run in this audit environment. Prior isolated harness results are not full integration evidence.

## Suggested order

1. Restore CI and run the full supported build/test matrix; fix the session-store data-loss risk.
2. Fix folder deletion and session import, with real service/frontend integration tests.
3. Clarify and strengthen vault multi-instance safety and sudo threat boundaries.
4. Verify X2Go on a live KDrive server; validate Android security and device integrations.
5. Work through the transfer matrix, editor gaps and platform-specific evidence using the historical ledger only as a starting point.
