# Remaining parity implementation plan

Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. Full upstream parity is the target, **not a completed claim**.

9 tracked capability gaps. Each requires implementation and acceptance evidence; recording a plan does not satisfy its tests.

Regenerate with `python3 tools/check_upstream_parity.py --write-report`.

## security.gssapi-and-tunnels

**Area:** Security/authentication · **Status:** partial

Authenticated SSH jump-host connections now work for SFTP/SCP/SSH, including GUI tabs, background operations and the embedded terminal. Tunnel* raw settings, independent host-key verification, inherited proxy settings, encrypted stored jump credentials and bounded lifecycle cleanup are implemented. GSSAPI remains unavailable; removing NO_GSSAPI no longer pretends otherwise.

**Next:** GSSAPI/Kerberos authentication still needs implementation, dependency detection, realm tests and credential-delegation review. Tunnels for non-SSH destination protocols and fixed local-listener ports are not supported; they fail closed rather than connect directly.

**Acceptance criteria:**

- [ ] Implement optional GSSAPI against an isolated Kerberos realm, testing principal selection, missing/expired credentials, mutual authentication and opt-in delegation; obtain security review before enabling it by default.
- [ ] Define and test tunneling for FTP/FTPS/WebDAV/S3, including data-channel routing, TLS SNI/certificate verification and S3 signing for the original destination. If fixed listener ports are supported, bind loopback only, test collisions/authorization and clean up on every failure.

## security.gui-account

**Area:** Security/authentication · **Status:** partial

Optional account login exists: PBKDF2 password hashes, session expiry, per-login CSRF tokens and login throttling have automated coverage. This is a LinSCP server-deployment extension, not a feature of the WinSCP desktop client. Tabs, queues, configuration and local-process privileges remain shared across signed-in users; login alone is not multi-user isolation.

**Next:** Do not deploy the GUI to mutually untrusted users. Isolate each user's configuration, tabs, queue, logs, terminals and filesystem access (including command execution), or run separate GUI processes under separate OS accounts.

**Acceptance criteria:**

- [ ] Define the deployment trust boundary and implement per-user ownership/isolation for every API resource and filesystem operation. Run negative authorization tests across every route, not just login, before claiming multi-user/server deployment support.

## automation.dotnet

**Area:** Automation · **Status:** missing

No WinSCP .NET assembly or equivalent object model for Linux. The C ABI header the Windows port left behind (source/linux/liblinscp.h) is gone: it declared a library that no build produced, and a public header for an API that does not exist is worse than none. The gap is unchanged - the automation object model still has to be built.

**Next:** Define an API contract and test automation clients; a CLI is not the assembly.

**Acceptance criteria:**

- [ ] Define the Linux object-model contract and upstream compatibility boundary. Build and test an actual .NET library for session lifecycle, listing, transfer, synchronization, cancellation, structured results and error propagation. A subprocess helper alone is not assembly parity.

## automation.powershell

**Area:** Automation · **Status:** partial

automation/LinSCP.psm1 is a PowerShell 7 (pwsh) module that wraps the console client in -server mode and exports Open-LScpSession, Close-LScpSession, Get-LScpItem, Send-LScpItem, Get-LScpDirectory and Sync-LScpDirectory; 'make install', 'cmake --install' and the Debian package all put it in PREFIX/share/linscp/automation. Passwords travel on stdin to -server, never on a command line. The module has a test harness (automation/test_psmodule.py, run by make check-live, CTest and CI): static checks that always run, and a Pester suite against the throwaway WebDAV endpoint covering open/close, byte-exact transfers, listing objects, terminating errors, timeout cancellation and password hygiene. The live Pester run needs pwsh, which CI installs; no green live run has been recorded in this ledger yet, and the module remains a shim over the CLI rather than upstream's assembly API.

**Next:** Record a green live Pester run (CI installs pwsh and runs the harness): a session opened and closed, an upload and a download of exact bytes, a listing as pipeline objects, a terminating error, a cancelled transfer, and a password that appears neither in the process list nor in the output.

**Acceptance criteria:**

- [ ] Build cmdlets or a documented compatibility module on the tested automation contract. Exercise them with PowerShell on Linux, including pipeline objects, terminating errors, cancellation and secret handling.

## desktop.shell-and-extensions

**Area:** Desktop integration · **Status:** missing

No system file-manager shell commands or upstream extension system. The half-translated Nautilus extension the Windows Explorer integration left behind is gone: it ran no session, so it uploaded nothing, and it was neither installed nor documented. The command templates of the graphical client (source/gui/explorer-commands.json) are its own feature and are shipped by all three installers.

**Next:** Specify desired desktop environment integrations and build/test them individually.

**Acceptance criteria:**

- [ ] Specify supported file managers and extension API. Add explicit, opt-in installation and removal, selection transport without shell interpolation, confirmation and extension permission boundaries. Test packaged installation as well as source-tree execution.

## locale.translations

**Area:** Localization/accessibility · **Status:** partial

English/Spanish catalogs cover the browser interface (menus, dialogs, help, ARIA/tooltips, dynamic status/queue/sync/editor/search messages) and the whole command-line client: the per-command help texts, the status, argument, switch and engine messages of the script engine, the operations the error helpers name and the option listing. The translation compiler rejects a message that reaches the user without a catalog entry, a command help text that nobody translated and an error operation that is not in the catalog. Locale precedence, regional fallback, plurals, literal data, safe embedded JSON and internal protocol isolation are tested. Raw server/OS diagnostics, the 'LSCP-' protocol banners and core logs are intentionally preserved.

**Next:** Only English and Spanish catalogs are shipped; upstream ships catalogs for many more languages, and the upstream .NET interface has strings that this client does not have at all. No full upstream language-catalog coverage is claimed.

**Acceptance criteria:**

- [ ] Ship a catalog for every language the project claims to support and translate the whole interface into it, starting with the languages the upstream project already ships.
- [ ] Add a test that walks the catalogs and reports the messages of the client that are still answered in English, so a new interface string cannot slip through untranslated.

## automation.upstream-xml-compatibility

**Area:** Automation · **Status:** partial

The XML action log emits structured command, message and transfer actions with secret masking. Its structure resembles upstream but schema/consumer equivalence has not been established.

**Next:** Pin the intended upstream XML schema and validate successful/failing operations with actual automation consumers.

**Acceptance criteria:**

- [ ] Compare schema-valid fixtures for command results, transfer errors, cancellation and session lifecycle against the pinned upstream format.
- [ ] Test at least one upstream-compatible parser and prove secret redaction preserves a valid document.

## gui.local-to-local

**Area:** GUI · **Status:** missing

Upstream SessionData exposes IsLocalBrowser and OtherLocalDirectory for two-local-directory sessions. LinSCP can manage its local pane and accept local browser drops, but its opposite pane and cross-panel transfer routes require a remote session; there is no local-to-local session mode.

**Next:** Implement a no-network two-local-pane mode; local uploads into one pane are not local-to-local transfer parity.

**Acceptance criteria:**

- [ ] Open two independent local panes without a remote connection and test recursive copies/moves, overwrite decisions, metadata and symlink policy, queue progress/cancellation and safe handling of source/destination overlap.

## sessions.workspaces

**Area:** Sessions/configuration · **Status:** missing

Upstream TStoredSessionList implements named workspaces (NewWorkspace, GetWorkspaces, SaveWorkspaceData). LinSCP stores individual sites/folders and has live tabs, but no save/restore of a named group of tabs with their navigation state.

**Next:** Add named workspace save/restore rather than treating stored-session folders or in-memory tabs as workspace support.

**Acceptance criteria:**

- [ ] Persist and restore named workspaces with tab order, active tab and both pane paths; test partial connection failures, renamed/deleted sites, process restart and preservation of host-key and credential-storage policies.

## Cross-cutting release gate

Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, report dependency skips, and update the ledger and generated reports. `python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. The normal checker validates consistency, not behavioral parity.
