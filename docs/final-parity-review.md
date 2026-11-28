# Final parity review

This review covers the work through chunk 9, tested at commit `7a71b27` (which
also added temporary branch-only review workflows). Those temporary workflows
were removed after the runs; they are not intended to change the repository's
master-only workflow policy. The current native GUI remains **experimental and
not ready for production transfers**. Neither passing checks nor this review
certify security or complete upstream parity.

## Verification

- Local `npm --prefix ui test`: passed; Node tests 157 passed, one skipped,
  plus the jsdom client and 182 localization checks. These use mocked browser
  and service interfaces and do not replace packaged end-to-end tests.
- Local Python discovery: 242 tests run, 11 skipped, none failed. The optional local
  XML-schema dependency was absent; schema validation ran separately in Linux
  CI. Translation drift, shared frontend route checks, repository hygiene,
  CI test wiring, parity inventory validation and `git diff --check` passed.
- [Linux final review](https://github.com/unsubstantiation/LinSCP/actions/runs/46124619208): full Linux test job and fresh Debian package job passed. These
  include Rust host suites, isolated MIT KDC/OpenSSH authentication and
  delegation, loopback SFTP/WebDAV/FTP/FTPS/S3 fixtures, XML schema checks,
  Xvfb and headless Weston native window smokes, custom-prefix Make/CMake
  GIO launches, file-manager action smoke, and synthetic same-payload Debian
  upgrade/removal/purge. They are specific fixtures and environments, not all
  real servers or desktop environments.
- [Windows final review](https://github.com/unsubstantiation/LinSCP/actions/runs/46124619141): passed the UI and Rust workspace tests, release native build, window launch, isolated Explorer action and per-user URL registration/removal smokes. These do not demonstrate real OS drag-and-drop or default-handler selection.
- [Android final review](https://github.com/unsubstantiation/LinSCP/actions/runs/46124619130): passed the UI and Linux-host Rust suites, unsigned debug builds for arm64 and x86_64, APK verification, and API 35 x86_64 emulator WebView/IPC scenarios. Those scenarios include external-storage SAF, WebDAV and SFTP resume, backup/restore, and selected share and viewer-URI refusals. The APKs are debug builds; the signed release workflow and physical devices were not tested.

The Linux test job removed the branch-only temporary workflow files from its
checkout before checking the repository workflow-trigger policy; local policy
checks also ran after removing them. The tested application code was unchanged
by that removal. Host-side Rust tests in the Android workflow run on Linux and
are not themselves Android runtime evidence.

## Outcome and remaining limits

The ledger records 117 granular capabilities: 72 verified, 41 partial and 4
missing. Across all 185 comparison entries, 78 are marked verified; 45
capability gaps remain. Counts reflect the ledger's scoped definitions, not
release readiness. Historical tests requiring the removed CLI are not evidence
for a shipped GUI.

- **Transfers:** isolated checkpoint staging assumes a trusted destination and
  no same-account adversary. FTP/SFTP resume needs explicit best-effort consent
  and cannot provide a source snapshot; WebDAV/S3 rely on conforming server
  preconditions. Guarded uploads and granted-folder resume have explicit
  refusals. Interrupted operations and non-transactional directory merges can
  leave partial trees, temporary objects or duplicates.
- **Backups:** full restore uses an encrypted recovery journal; selected
  key/session import is not a durable multi-file transaction. External keys
  and certificates have portability limitations. Cross-OS and physical-device
  restore/authentication are not comprehensively validated.
- **Security:** proxy and jump fail-closed checks and isolated Linux Kerberos
  fixtures are not validation against production proxies, Windows AD or
  cross-realm KDCs. Delegation needs independent review; Android system GSSAPI
  and GSSAPI key exchange are unsupported. Desktop viewer forwards are
  unauthenticated loopback ports and require a trusted local environment.
  Static IPC/CSP checks are not a security proof.
- **Native/Android:** emulator tests cover a specific external-storage
  DocumentsProvider and explicit intent; they do not establish physical-device,
  alternate-provider, share-sheet resolver, true OS drag/drop or DPI behavior.
  Share staging and manifest claims are not exactly-once across crashes.
- **Synchronization/editing:** watcher coverage includes an initial-pass event;
  untrusted path and read limits have host/fixture tests. Remote saves use a
  non-atomic mtime check, recursive deletion can be partially applied, and
  physical devices and additional server/provider behavior remain unverified.
- **Desktop/packaging:** a headless Weston window smoke is not a full Wayland
  desktop, pixel, input, drag or scaling test. Historical Debian upgrades,
  menu/default association behavior and other distributions remain unverified.
  Live RDP, VNC, SPICE and X2Go interoperability remains open; saved RDP
  passwords are not passed to viewers, and tunneled SPICE with a separate TLS
  port is refused.
- **Remaining parity:** only English, Spanish, German and French catalogs ship;
  translation quality and other languages need human review. Recursive SCP
  D/E wire streams are deferred. XML compatibility uses a project-derived
  schema and is best-effort, not a tamper-proof audit log or independently
  certified upstream consumer compatibility.

Detailed boundaries and evidence are in [transfer resume safety](transfer-resume-safety.md),
[backup portability](backup-portability.md), [authentication and IPC](authentication-ipc-security.md),
[native/Android integration](native-android-integration.md),
[synchronization and editing](synchronization-editing.md), and
[remaining parity priorities](remaining-parity-priorities.md).
