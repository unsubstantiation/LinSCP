# Remaining parity implementation plan

Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. Full upstream parity is the target, **not a completed claim**.

11 tracked capability gaps. Each requires implementation and acceptance evidence; recording a plan does not satisfy its tests.

Regenerate with `python3 tools/check_upstream_parity.py --write-report`.

## security.gssapi-and-tunnels

**Area:** Security/authentication · **Status:** missing

GSSAPI is compiled out; SSH tunnel configuration is not implemented.

**Next:** Implement and test GSSAPI/SSH tunnels only with an explicit security review.

**Acceptance criteria:**

- [ ] Enable optional GSSAPI with dependency detection and a Kerberos test realm. Add authenticated SSH forwarding, destination host-key verification and lifecycle cleanup. Security-review credentials, forwarding exposure and failure paths before enabling either by default.

## security.gui-account

**Area:** Security/authentication · **Status:** missing

The loopback GUI has no multi-user account or authorization roles.

**Next:** Add authenticated accounts before claiming multi-user/server deployment support.

**Acceptance criteria:**

- [ ] Define deployment/isolation boundaries before enabling network access. Add password hashing, login/session expiry, CSRF protection and per-user configuration, filesystem and queue isolation. Negative authorization tests must cover every API route, not just login.

## gui.explorer-custom-commands

**Area:** GUI · **Status:** missing

No separate upstream Explorer-style UI or custom-command framework.

**Next:** Build/test Explorer navigation and custom-command execution with appropriate safety prompts.

**Acceptance criteria:**

- [ ] Implement single-pane Explorer navigation plus persisted command templates, explicit confirmation and safe filename substitution. Test local/remote scope, multiple selections and hostile filenames; never interpolate into a shell implicitly.

## automation.dotnet

**Area:** Automation · **Status:** missing

No WinSCP .NET assembly or equivalent object model for Linux.

**Next:** Define an API contract and test automation clients; a CLI is not the assembly.

**Acceptance criteria:**

- [ ] Define the Linux object-model contract and upstream compatibility boundary. Build and test an actual .NET library for session lifecycle, listing, transfer, synchronization, cancellation, structured results and error propagation. A subprocess helper alone is not assembly parity.

## automation.powershell

**Area:** Automation · **Status:** partial

automation/LinSCP.psm1 is a PowerShell 7 (pwsh) module that wraps the console client in -server mode and exports Open-LScpSession, Close-LScpSession, Get-LScpItem, Send-LScpItem, Get-LScpDirectory and Sync-LScpDirectory; 'make install' puts it in PREFIX/share/linscp/automation. Nothing exercises it: no automated case runs PowerShell, so its session lifetime, pipeline objects, terminating errors, cancellation and secret handling are unevidenced, and it is a shim over the CLI rather than upstream's assembly API.

**Next:** Exercise the shipped module with PowerShell on Linux: a session opened and closed, an upload and a download of exact bytes, a listing as pipeline objects, a terminating error, a cancelled transfer, and a password that appears neither in the process list nor in the output.

**Acceptance criteria:**

- [ ] Build cmdlets or a documented compatibility module on the tested automation contract. Exercise them with PowerShell on Linux, including pipeline objects, terminating errors, cancellation and secret handling.

## desktop.shell-and-extensions

**Area:** Desktop integration · **Status:** missing

No system file-manager shell commands or upstream extension system.

**Next:** Specify desired desktop environment integrations and build/test them individually.

**Acceptance criteria:**

- [ ] Specify supported file managers and extension API. Add explicit, opt-in installation and removal, selection transport without shell interpolation, confirmation and extension permission boundaries. Test packaged installation as well as source-tree execution.

## locale.translations

**Area:** Localization/accessibility · **Status:** partial

English/Spanish catalogs cover the browser interface (menus, dialogs, help, ARIA/tooltips, dynamic status/queue/sync/editor/search messages) and shared CLI messages, CLI -help/option errors, host-key warnings, passphrase/destructive-action prompts and connection status. Locale precedence, regional fallback, plurals, literal data, safe embedded JSON and internal protocol isolation are tested. Raw server/OS diagnostics and core logs are intentionally preserved.

**Next:** Translate command-specific help and remaining human-facing Script.cpp status and argument/engine error strings that bypass the shared Texts functions; no full upstream language-catalog coverage is claimed.

**Acceptance criteria:**

- [ ] Route command-specific help and every remaining human-facing script status/argument/engine message through English/Spanish catalogs, keeping paths, command tokens and server/OS diagnostics literal.
- [ ] Add coverage checks that detect new uncatalogued messages and run translated positive/negative CLI workflows, including help, synchronization, editing, sessions and transfer failures.
- [ ] Preserve host-key refusal behavior, machine protocol values and secret masking; review security-warning translations before adding more supported locales.

## ftp.non-unix-listings

**Area:** FTP/FTPS · **Status:** missing

The shared LIST parser accepts Unix long listings. MLSD provides a structured alternative, but DOS/VMS and other non-Unix LIST dialects have no parser.

**Next:** Implement the non-Unix LIST formats selected for support without treating an unparsed directory as empty.

**Acceptance criteria:**

- [ ] Add fixture-based DOS/VMS listing cases with spaces, date/size variants and directory types, plus malformed-input rejection.
- [ ] Exercise LIST fallback against live servers that emit the supported formats; document formats still unsupported.

## s3.versioned-objects

**Area:** Amazon S3 · **Status:** missing

The client manages current bucket objects; it does not expose version IDs, version listing, version-specific retrieval or delete markers.

**Next:** Define and implement version-aware operations rather than claiming current-object CRUD is versioning support.

**Acceptance criteria:**

- [ ] Test version listing with pagination and exact version-specific reads against a versioned S3 endpoint.
- [ ] Test deletion of a named version versus creation/removal of delete markers without losing unrelated versions.

## editing.non-utf8-encodings

**Area:** Editing/search · **Status:** missing

The browser editor/search require UTF-8. CLI editing supports EOL/BOM preservation, but there is no explicit legacy-encoding selection or transcoding policy.

**Next:** Add an explicit encoding contract and conversion implementation for any supported non-UTF-8 encodings.

**Acceptance criteria:**

- [ ] Round-trip each supported encoding through CLI and browser editing with byte-exact fixtures and a documented BOM/EOL policy.
- [ ] Reject invalid input or unrepresentable output without replacing bytes silently or overwriting the original file.

## automation.upstream-xml-compatibility

**Area:** Automation · **Status:** partial

The XML action log emits structured command, message and transfer actions with secret masking. Its structure resembles upstream but schema/consumer equivalence has not been established.

**Next:** Pin the intended upstream XML schema and validate successful/failing operations with actual automation consumers.

**Acceptance criteria:**

- [ ] Compare schema-valid fixtures for command results, transfer errors, cancellation and session lifecycle against the pinned upstream format.
- [ ] Test at least one upstream-compatible parser and prove secret redaction preserves a valid document.

## Cross-cutting release gate

Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, report dependency skips, and update the ledger and generated reports. `python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. The normal checker validates consistency, not behavioral parity.
