# Feature-development triage

This is an audit of the 45 non-verified capability rows in [upstream-parity.json](upstream-parity.json), not new runtime evidence or a parity certification. Statuses and platform citations remain in the ledger. “Evidence” means implementation exists but the stated acceptance still needs proof; it does not guarantee no bugs. “Development + evidence” identifies a plausible implementation or policy gap that still needs inspection. Optional and scope-decision items are not commitments to add features.

Historical CLI-dependent suites and generic all-platform criteria in the generated plan may not apply to this GUI-only product. Use supported GUI/service harnesses and platform-specific acceptance instead; keep historical comparisons visible. FTP/SFTP resume without an atomic source snapshot remains refused by default, with explicit best-effort consent where offered. See [transfer resume safety](transfer-resume-safety.md) for protocol limitations and the remaining legacy pathname race.

## Capability triage

| Capability | Triage | Next focused step |
| --- | --- | --- |
| [`scp.curl-file-transfer`](remaining-parity-plan.md#scpcurl-file-transfer) | Optional parity | Assess recursive SCP wire protocol; current tree engine already sends individual files. |
| [`transfer.ascii-automatic`](remaining-parity-plan.md#transferascii-automatic) | Evidence | Test Android and relevant live servers; conversion and guarded uploads exist. |
| [`transfer.filepart-resume`](remaining-parity-plan.md#transferfilepart-resume) | Development + evidence | Assess guarded-upload resume and provider limitations; retain default FTP/SFTP refusal without atomic source and explicit best-effort consent. |
| [`transfer.resume-modes`](remaining-parity-plan.md#transferresume-modes) | Evidence | Validate GUI resume safety on physical devices and third-party servers. |
| [`transfer.presets`](remaining-parity-plan.md#transferpresets) | Evidence | Host tests cover manual, site and per-item rule precedence; see [preset precedence](transfer-presets.md). The new Android smoke case, physical devices and live servers still require runs. |
| [`transfer.curl-progress`](remaining-parity-plan.md#transfercurl-progress) | Scope + evidence | GUI progress exists; terminal progress is historical CLI parity, not a shipped CLI requirement. |
| [`sync.one-way`](remaining-parity-plan.md#syncone-way) | Evidence | Exercise supported synchronization workflows using runnable GUI/service fixtures. |
| [`sync.keepuptodate-inotify`](remaining-parity-plan.md#synckeepuptodate-inotify) | Evidence | Exercise watcher and polling behavior on supported platforms and protocols. |
| [`sessions.site-manager`](remaining-parity-plan.md#sessionssite-manager) | Evidence | Extend packaged workflows and persistence tests rather than relying on retired CLI tests. |
| [`sessions.password-at-rest`](remaining-parity-plan.md#sessionspassword-at-rest) | Evidence | Test physical Android Keystore variants and tamper/lifecycle behavior. |
| [`sessions.proxy-settings`](remaining-parity-plan.md#sessionsproxy-settings) | Evidence | Exercise saved proxy configuration and actual proxy routing on target platforms. |
| [`sessions.rawsettings`](remaining-parity-plan.md#sessionsrawsettings) | Evidence + scope | Test supported saved settings in GUI/service; unsupported settings must remain explicit refusals. |
| [`security.proxy-isolation`](remaining-parity-plan.md#securityproxy-isolation) | Evidence | Test proxy isolation and negative routing behavior on supported deployments. |
| [`security.gui-api-token`](remaining-parity-plan.md#securitygui-api-token) | Evidence + audit | Test packaged IPC and local-process boundaries and untrusted rendering surfaces. |
| [`security.gssapi-and-tunnels`](remaining-parity-plan.md#securitygssapi-and-tunnels) | Development + evidence | Port live KDC tests to the current transport; validate existing Windows SSPI and obtain delegation review. |
| [`security.gui-account`](remaining-parity-plan.md#securitygui-account) | Scope decision | Single-user native app; multi-user authentication and isolation only if server deployment becomes a goal. |
| [`gui.native-path-drop`](remaining-parity-plan.md#guinative-path-drop) | Evidence | Exercise real desktop drop and existing Android share filter, conflict handling and bounded staging. |
| [`editing.encoding-policy`](remaining-parity-plan.md#editingencoding-policy) | Evidence | Exercise actual editing flows and encoding decisions on supported platforms. |
| [`automation.command-interpreter`](remaining-parity-plan.md#automationcommand-interpreter) | Out of scope | Retired CLI interface; no restoration planned. |
| [`automation.literal-gui-command`](remaining-parity-plan.md#automationliteral-gui-command) | Out of scope | Retired command interface; no restoration planned. |
| [`automation.xml-action-log`](remaining-parity-plan.md#automationxml-action-log) | Evidence | Expand XML-log coverage via supported service workflows, not the retired CLI. |
| [`automation.dotnet`](remaining-parity-plan.md#automationdotnet) | Out of scope | The .NET assembly is not planned for the GUI-only distribution. |
| [`automation.powershell`](remaining-parity-plan.md#automationpowershell) | Out of scope | The PowerShell interface is not planned for the GUI-only distribution. |
| [`desktop.scheme-handlers`](remaining-parity-plan.md#desktopscheme-handlers) | Development + evidence | Test real URI registration and delivery; implement missing target-platform registration if in scope. |
| [`desktop.launcher-prefix`](remaining-parity-plan.md#desktoplauncher-prefix) | Evidence | Validate real custom-prefix desktop integration; limit platform-specific claims. |
| [`desktop.wayland-session`](remaining-parity-plan.md#desktopwayland-session) | Evidence | Exercise Linux Wayland/compositor workflows; do not require Wayland tests on unrelated platforms. |
| [`locale.translations`](remaining-parity-plan.md#localetranslations) | Optional expansion | Add languages beyond the four shipped catalogs if product scope requires them. |
| [`platform.make-linux`](remaining-parity-plan.md#platformmake-linux) | Evidence | Validate real menu discovery and scheme selection for custom-prefix Make installs. |
| [`platform.cmake-linux`](remaining-parity-plan.md#platformcmake-linux) | Evidence | Validate real desktop integration and registered CTest entries for CMake installs. |
| [`platform.debian-package`](remaining-parity-plan.md#platformdebian-package) | Investigation + evidence | Investigate recorded launch-smoke issue; test package upgrade and removal. |
| [`platform.prefix-lookup`](remaining-parity-plan.md#platformprefix-lookup) | Evidence | Check platform-appropriate executable and resource lookup; avoid an artificial all-platform gate. |
| [`platform.posix-runtime-services`](remaining-parity-plan.md#platformposix-runtime-services) | Evidence + scope | Test supported child-process I/O, Windows console controls and Android runtime paths as applicable. |
| [`platform.terminal-and-console`](remaining-parity-plan.md#platformterminal-and-console) | Evidence + scope | Test the shipped terminal and embedded console; do not assume the retired CLI is installed. |
| [`platform.linux-file-events`](remaining-parity-plan.md#platformlinux-file-events) | Evidence | Validate Linux file-event behavior; platform-specific requirements must stay scoped. |
| [`platform.conversion-completeness`](remaining-parity-plan.md#platformconversion-completeness) | Scope + evidence | Clarify the selected legacy conversion checker’s exclusions; it is not whole-repository certification. |
| [`platform.android-saf-editing`](remaining-parity-plan.md#platformandroid-saf-editing) | Evidence | Test opaque-ID providers, properties, revocation, large files and physical devices. |
| [`platform.android-saf-local-copy-move`](remaining-parity-plan.md#platformandroid-saf-local-copy-move) | Evidence | Test two granted trees, other providers, races and physical devices beyond the existing emulator fixture. |
| [`platform.android-saf-session-transfers`](remaining-parity-plan.md#platformandroid-saf-session-transfers) | Evidence | Extend existing emulator transfer/limit coverage to other providers, races and physical devices. |
| [`editing.non-utf8-encodings`](remaining-parity-plan.md#editingnon-utf8-encodings) | Evidence | Test non-UTF-8 and binary rejection in both editor and search. |
| [`automation.upstream-xml-compatibility`](remaining-parity-plan.md#automationupstream-xml-compatibility) | Evidence | Expand schema and compatibility coverage for supported operations. |
| [`gui.local-symlink`](remaining-parity-plan.md#guilocal-symlink) | Evidence | Validate Windows privilege behavior and Android app-storage link creation. |
| [`gui.remote-delete`](remaining-parity-plan.md#guiremote-delete) | Evidence | Test interrupted deletion and partial-failure reporting, including Android. |
| [`backup.full-export-import`](remaining-parity-plan.md#backupfull-export-import) | Evidence | Test portability and restored SSH authentication across real platforms, plus Android interrupted recovery. |
| [`desktop.remote`](remaining-parity-plan.md#desktopremote) | Development + evidence | Validate existing experimental X2Go and external viewers against servers; resolve advertised fallback and security review. |
| [`platform.android-saf-synchronization`](remaining-parity-plan.md#platformandroid-saf-synchronization) | Evidence | Extend existing sync/poll/cancel coverage to other providers, over-cap paths and physical devices. |

## Audit notes

- GSSAPI: the historical libssh/KDC plan was for retired CLI tests. Current russh uses runtime Linux GSSAPI or Windows SSPI; provider construction is not live authentication evidence.
- Remote desktop: an experimental KDrive viewer exists; real server interoperability remains open. The desktop help advertises an ironrdp fallback not found in the audited code.
- Android: generated share filters and emulator SAF fixtures already exist. The remaining plan now names untested providers, physical devices and other missing cases rather than asking to re-register or repeat covered behavior.
- These classifications are planning aids. New tests may uncover implementation defects, and a user/product decision may change optional scope.
