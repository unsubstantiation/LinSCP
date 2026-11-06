# Native desktop feature audit

This is an audit of the native Tauri service, not a claim of parity with the
upstream client or of production readiness. An engine module or a legacy HTML control does
not by itself mean a feature is wired into the native application. See the
transfer limitations in `readme.md` before using remote operations.

## Connected paths

- Local tabs, pane listings, local file operations, saved sites, preferences,
  bookmarks, and the transfer queue have native handlers. Local moves and
  no-replace publication rely on platform support and a trusted destination
  directory.
- Remote connections, host-key approval, listings, reconnect, SFTP/FTP/FTPS/
  WebDAV folder creation, and remote properties use native sessions. Reconnect
  makes a new connection; a changed SSH key requires approval. Cancelling or
  closing a pending connection cannot resurrect a closed tab. S3 folder creation
  remains disabled because its current marker write is not exclusive.
- Workspaces list and restore local tabs and remote tabs backed by saved sites.
  They do not store credentials. Unsaved remote sessions cannot be saved as a
  workspace; a missing site, inaccessible directory, failed connection, or SSH
  host-key challenge is reported as a failed tab rather than silently approved.
  Opening adds tabs instead of closing the existing ones.
- Queued transfers support the protocol-specific subsets and warnings described
  in `readme.md`. WebDAV and S3 verified download resume retransfers and checks
  the entire partial prefix. SFTP and FTP partial-upload cleanup remains
  fail-closed on unmodified servers: pathname deletion cannot identify an upload
  atomically, so leftovers require inspection.

## Known incomplete or restricted paths

- Remote editing/saving, permissions changes, checksum, search, symlink
  creation, synchronize/keep-up-to-date and terminal/command execution are not
  wired into every native path; several corresponding GUI controls are still
  visible and return errors.
- Remote deletion goes through the session and the queue's own tree walk, and is
  exercised against a live WebDAV server (a leaf-invalid name refused per name
  while the valid names still run, a tree emptied and removed, a name the server
  no longer has counted as deleted). It is not transactional: a directory is
  emptied before it is removed, so an interruption can leave part of a tree
  behind.
- An operating-system drop in the native window is delivered as paths
  (`native:file-drop`), staged by the service and queued through the same
  endpoint the browser's byte drop uses, so conflict and overwrite handling is
  one implementation. Android's share hand-off records the same pending
  manifest the desktop `--shell-upload` selection does, and the page queues it
  through that same drop path instead of asking again. A dropped folder is
  staged under its own leaf name - the directories above it on the machine are
  not part of the drop - and a staging entry another request is uploading from
  is never replaced. The page decides which pane a drop lands in (the focused
  pane, unless the shell names one), an OS drop no longer defaults to the remote
  pane regardless of where it was dropped, and a staged copy is removed again
  when the queue refuses the drop, so the retry the overwrite question asks for
  is not blocked by the first attempt's own staging.
- Several remote directory transfers, cross-server directory moves, S3-source
  moves, overwrite combinations, and resume modes remain unsupported. FTP
  staged publication requires an explicit race acknowledgement. A failed or
  cancelled transfer may leave remote files or partial trees; guarantees depend
  on the server and are not equivalent to transactions.
- Native account/login features are not implemented. Android has a Rust-backed
  experimental debug APK but lacks SAF, sharing, background transfers and
  Keystore integration; see `docs/android.md`. Desktop integration, import sources,
  and other legacy UI actions require further native end-to-end validation.
- SSH host-key changes during workspace restoration are not auto-accepted or
  interactively resolved as part of a batch; the failed tab must be connected
  separately.

## Windows, Debian, and Android parity status

Windows and Debian run the same Rust `CommanderService` and frontend bundle;
Android also builds that service and bundle. This gives the core API a shared
implementation, not complete product parity: the `SHARED_FEATURES` list is a
contract for intended common UI surface, not evidence that every listed action
is wired end to end. The incomplete paths above apply to all native hosts unless
called out otherwise. Android additionally lacks registered SAF, share-intent,
foreground-service, and Keystore implementations; its UI now reports those
capabilities unavailable rather than advertising nonfunctional controls.

Parity should only be called complete after each shared feature has equivalent
behavioral acceptance coverage on Windows, Debian, and Android, and each
platform-specific integration has real-device evidence. The current CI and
source-level checks do not meet that bar.

## Verification

`npm test --prefix ui` tests the built frontend and legacy client. The Debian
workflow exercises live SFTP, WebDAV, FTP/FTPS and S3 fixtures, workspace
round-tripping, folder creation, and reconnect/cancellation regressions, then
builds and smoke-tests the package. The Windows workflow runs Rust workspace
unit tests, frontend tests, and a portable native-window smoke test. Android CI
builds/verifies the debug APK and runs a WebView/Rust IPC plus WebDAV transfer
smoke test in an emulator. None of these runs exercises the absent Android SAF,
share-intent, foreground-service, or Keystore implementations, and they do not
establish correctness against every server, concurrent actor, network failure,
or platform.
