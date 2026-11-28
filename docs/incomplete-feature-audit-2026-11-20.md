# Incomplete feature audit — 2026-11-20

## Scope and method

This is a prioritization of incomplete functionality and validation in the
native GUI product at base commit `942381eec6f49bc9307f02d255a7785874d3c113`.
It reviews the parity ledger, final review and focused safety documents, with
spot checks of implementation paths; it is not a fresh exhaustive source,
security or usability audit. `python3 tools/check_upstream_parity.py` passes
inventory consistency checks, not feature tests or a parity certification.
Previously recorded CI evidence is linked in the
[final review](final-parity-review.md); it was not rerun for this audit.

The ledger records **117 capabilities: 72 verified, 41 partial and 4 missing**.
“Verified” is scoped to cited checks and does not mean production-ready. The
four missing rows all describe external automation intentionally absent from
the GUI-only product, not four newly discovered regressions. Many partial rows
need evidence or a product decision rather than a code change. LinSCP remains
experimental and is not ready for production transfers.

## Recommended priorities

### 1. Transfer reliability and data safety — implemented with material restrictions

- **Resume:** GUI upload resume, ASCII resume and verified resume to Android
  granted folders are refused. FTP/SFTP download resume requires explicit
  best-effort approval because neither pins an atomic source snapshot; even
  matching metadata cannot rule out concurrent changes. WebDAV/S3 conditional
  resume depends on server enforcement and trusted local destination paths.
  **Next:** decide whether safe guarded-upload and provider resume are worth
  implementing; retain refusals where guarantees are unavailable, and test
  third-party servers and physical devices. [Resume safety](transfer-resume-safety.md);
  `transfer.filepart-resume`, `transfer.resume-modes`.
- **Publication, moves and cleanup:** FTP/FTPS staged upload has an acknowledged
  rename race and can overwrite a competing target. Directory merges and
  cross-server moves are not transactional; some moves and merges are refused.
  Cancellation, network errors and unconfirmed S3 multipart operations can
  leave partial trees, duplicates or remote artifacts. **Next:** prioritize
  recovery and failure reporting, and test interruption and real servers rather
  than implying no-clobber or cleanup guarantees that protocols cannot supply.
  [Transfer safety](transfer-safety.md).
- **Synchronization and editing:** recursive remote deletion can partially
  succeed. Remote editor saves compare modification times, not an atomic
  compare-and-swap, so concurrent writes can still be overwritten. This branch
  reports baseline-save failures following an incomplete sync rather than
  discarding them, and preserves cancellation diagnostics. **Next:**
  assess protocol-specific conditional saves and clearer partial-result recovery;
  exercise watcher and provider behavior on real systems.
  [Synchronization and editing](synchronization-editing.md);
  `sync.one-way`, `sync.keepuptodate-inotify`, `gui.remote-delete`.
- **Backup:** full restore uses an encrypted undo journal, but selective
  key/session import is not a durable multi-file transaction and can leave a
  partial merge or staged keys. Full exports refuse certain external file
  references instead of pretending they are portable. **Next:** design
  transactional selective import and test cross-OS recovery and restored
  authentication on real devices. [Backup portability](backup-portability.md);
  `backup.full-export-import`.

### 2. Security and authentication — implementation and assurance gaps

- **Kerberos:** Android system GSSAPI, GSSAPI key exchange, and jump-host
  GSSAPI/delegation are unsupported. Linux isolated KDC tests do not establish
  Windows AD, production KDCs or cross-realm behavior. Delegation is opt-in and
  needs independent review. **Next:** independent review and production-KDC /
  Windows testing before expanding claims; decide whether missing mechanisms
  are in product scope. [Delegation brief](gssapi-delegation-review.md);
  `security.gssapi-and-tunnels`.
- **IPC and viewers:** packaged IPC and hostile rendering surfaces need broader
  security testing. Inline scripts mean CSP is not an XSS boundary. External
  desktop-viewer tunnel forwards are unauthenticated loopback ports and require
  a trusted local environment. **Next:** independent threat review and packaged
  runtime tests; assess stronger isolation for viewer forwards.
  [Authentication and IPC](authentication-ipc-security.md);
  `security.gui-api-token`, `security.proxy-isolation`.

### 3. Android and native integration — partial implementation and device evidence

- **SAF:** editing, copy/move, transfers and synchronization have implemented
  paths and emulator coverage, but arbitrary providers, opaque IDs, revocation,
  multiple granted trees, failure cases and physical devices need more testing.
  Some local copy/drop paths read whole files into memory. **Next:** test a
  provider/device matrix and address any observed limit or streaming defects.
  [Native integration](native-android-integration.md); `platform.android-saf-*`.
- **Sharing:** incoming share staging is bounded but not exactly-once across
  crashes; emulator coverage uses an explicit SEND intent, not real share-sheet
  resolution, SEND_MULTIPLE or all conflict paths. Outgoing sharing needs
  receiver, permission, lifecycle and provider tests. **Next:** exercise real
  senders/receivers and crash recovery; decide whether durable delivery is
  required. [Native integration](native-android-integration.md),
  [outgoing sharing](android-outgoing-share-plan.md).
- **Desktop integration:** real OS drag-and-drop, desktop URI defaults,
  full Wayland input/rendering/scaling and historical Debian upgrades are not
  established by the existing stubs and headless smokes. **Next:** test actual
  desktop environments and installed packages. `gui.native-path-drop`,
  `desktop.scheme-handlers`, `desktop.wayland-session`, `platform.debian-package`.

### 4. Remote desktop and optional parity

- **Remote desktop:** X2Go is experimental, with live server interoperability,
  rendering, input, lifecycle and cleanup still open. External RDP/VNC/SPICE
  launches are partial; saved RDP passwords are not passed to viewers, and
  tunneled SPICE with a separate TLS port is refused. **Next:** decide supported
  viewer/server combinations, test end to end and review cleanup/security.
  [Final review](final-parity-review.md); `desktop.remote`.
- **SCP:** single-file transfers exist, but recursive SCP `D`/`E` wire streams
  and SCP resume do not. The engine's file-by-file tree walk does not imply
  every GUI directory operation is allowed. **Next:** defer wire recursion unless
  needed; design and test malicious records, containment and interruption first.
  [Priority assessment](remaining-parity-priorities.md); `scp.curl-file-transfer`.
- **Localization:** English, Spanish, German and French ship; other languages,
  plural categories beyond the current model and human translation review are
  incomplete. **Next:** prioritize languages with maintainers and user demand.
  `locale.translations`.
- **XML action logging:** the project-derived schema and fixture tests cover a
  subset, not independent upstream consumers or every operation. Logging is
  best-effort, with errors not surfaced to the operation caller; it is not a
  tamper-proof audit trail. **Next:** surface failures and validate desired
  consumers and protocol/failure cases. [Priority assessment](remaining-parity-priorities.md);
  `automation.xml-action-log`, `automation.upstream-xml-compatibility`.

## Explicitly outside the current product

The missing `automation.command-interpreter`, `automation.literal-gui-command`,
`automation.dotnet` and `automation.powershell` ledger entries describe retired
external CLI/.NET/PowerShell interfaces. The internal interpreter and GUI-hosted
console do not mean a standalone CLI is shipped. Multi-user server accounts
(`security.gui-account`) likewise need a product scope decision, not an implied
commitment to restore a server deployment.

## Complete tracked list and evidence

The generated [remaining parity plan](remaining-parity-plan.md) lists all 45
partial/missing capabilities and their acceptance criteria. The
[feature-development triage](feature-development-triage.md) classifies each as
implementation, evidence, optional or out of scope. Consult the
[ledger](upstream-parity.json) and [final review](final-parity-review.md) for
platform-specific evidence; neither the counts nor this prioritized summary
establish that unlisted features are complete or secure.
