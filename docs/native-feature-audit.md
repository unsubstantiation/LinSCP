# Native desktop feature audit

This is an audit of the native Tauri service, not a claim of upstream WinSCP
parity or production readiness. An engine module or a legacy HTML control does
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

- Remote deletion, remote editing/saving, permissions changes, checksum, search,
  symlink creation, synchronize/keep-up-to-date, terminal/command execution,
  file-manager shell uploads and desktop drag/drop uploads are not wired into
  the native service. Several corresponding GUI controls are still visible and
  return errors. Shell consumption does not remove pending manifests or report a
  queued upload when no upload was performed.
- Several remote directory transfers, cross-server directory moves, S3-source
  moves, overwrite combinations, and resume modes remain unsupported. FTP
  staged publication requires an explicit race acknowledgement. A failed or
  cancelled transfer may leave remote files or partial trees; guarantees depend
  on the server and are not equivalent to transactions.
- Native account/login features are not implemented. Android has a Rust-backed
  experimental debug APK with document-picker copy-in/copy-out, but lacks direct
  SAF folder browsing, sharing, background transfers and Keystore integration;
  see `docs/android.md`. Desktop integration, import sources,
  and other legacy UI actions require further native end-to-end validation.
- SSH host-key changes during workspace restoration are not auto-accepted or
  interactively resolved as part of a batch; the failed tab must be connected
  separately.

## Verification

`npm test --prefix ui` tests the built frontend and legacy client. The Debian
workflow exercises live SFTP, WebDAV, FTP/FTPS and S3 fixtures, workspace
round-tripping, folder creation, and reconnect/cancellation regressions, then
builds and smoke-tests the package. The Windows workflow runs Rust workspace
unit tests, frontend tests, and a portable native-window smoke test. Android CI
builds a debug APK and runs a WebView, protocol and document-picker emulator smoke test. These tests do not establish correctness
against every server, concurrent actor, network failure, or platform.
