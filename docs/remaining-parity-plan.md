# Remaining parity implementation plan

Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. Full upstream parity is the target, **not a completed claim**.

7 tracked capability gaps. Each requires implementation and acceptance evidence; recording a plan does not satisfy its tests.

Regenerate with `python3 tools/check_upstream_parity.py --write-report`.

## security.gssapi-and-tunnels

**Area:** Security/authentication · **Status:** missing

GSSAPI is compiled out; SSH tunnel configuration is not implemented.

**Next:** Implement and test GSSAPI/SSH tunnels only with an explicit security review.

**Acceptance criteria:**

- [ ] Enable optional GSSAPI with dependency detection and a Kerberos test realm. Add authenticated SSH forwarding, destination host-key verification and lifecycle cleanup. Security-review credentials, forwarding exposure and failure paths before enabling either by default. Note: build uses `-DNO_GSSAPI`; feature remains unimplemented.

## security.gui-account

**Area:** Security/authentication · **Status:** missing

The loopback GUI has no multi-user account or authorization roles.

**Next:** Add authenticated accounts before claiming multi-user/server deployment support. No multi-user account or authorization roles exist in the loopback GUI; feature remains unimplemented.

**Acceptance criteria:**

- [ ] Define deployment/isolation boundaries before enabling network access. Add password hashing, login/session expiry, CSRF protection and per-user configuration, filesystem and queue isolation. Negative authorization tests must cover every API route, not just login.

## automation.dotnet

**Area:** Automation · **Status:** missing

No WinSCP .NET assembly or equivalent object model for Linux. The C ABI header the Windows port left behind (source/linux/liblinscp.h) is gone: it declared a library that no build produced, and a public header for an API that does not exist is worse than none. The gap is unchanged - the automation object model still has to be built.

**Next:** Define the Linux object-model contract and upstream compatibility boundary. No .NET library exists; feature remains unimplemented. A CLI is not the assembly.

**Acceptance criteria:**

- [ ] Define the Linux object-model contract and upstream compatibility boundary. Build and test an actual .NET library for session lifecycle, listing, transfer, synchronization, cancellation, structured results and error propagation. A subprocess helper alone is not assembly parity.

## automation.powershell

**Area:** Automation · **Status:** partial (updated)

The PowerShell 7 module (`automation/LinSCP.psm1`) passes all static checks (exported cmdlets match definitions, no passwords reach the command line, control-character refusal and multiline refusal are implemented). The live Pester suite (`automation/LinSCP.Tests.ps1`) requires `pwsh` (PowerShell 7), which this workspace does not have installed; without it the live cases skip loudly rather than reporting a green run. The fixtures `fixtures/xml/action-log-success.xml` and `fixtures/xml/action-log-error.xml` were added to validate XML action-log structure for upstream compatibility.

**Next:** Record a green live Pester run (install pwsh, run the harness): a session opened and closed, an upload and a download of exact bytes, a listing as pipeline objects, a terminating error, a cancelled transfer, and a password that appears neither in the process list nor in the output.

automation/LinSCP.psm1 is a PowerShell 7 (pwsh) module that wraps the console client in -server mode and exports Open-LScpSession, Close-LScpSession, Get-LScpItem, Send-LScpItem, Get-LScpDirectory and Sync-LScpDirectory; 'make install', 'cmake --install' and the Debian package all put it in PREFIX/share/linscp/automation. Passwords travel on stdin to -server, never on a command line. The module has a test harness (automation/test_psmodule.py, run by make check-live, CTest and CI): static checks that always run, and a Pester suite against the throwaway WebDAV endpoint covering open/close, byte-exact transfers, listing objects, terminating errors, timeout cancellation and password hygiene. The live Pester run needs pwsh, which CI installs; no green live run has been recorded in this ledger yet, and the module remains a shim over the CLI rather than upstream's assembly API.

**Next:** Record a green live Pester run (CI installs pwsh and runs the harness): a session opened and closed, an upload and a download of exact bytes, a listing as pipeline objects, a terminating error, a cancelled transfer, and a password that appears neither in the process list nor in the output.

**Acceptance criteria:**

- [ ] Build cmdlets or a documented compatibility module on the tested automation contract. Exercise them with PowerShell on Linux, including pipeline objects, terminating errors, cancellation and secret handling.

## desktop.shell-and-extensions

**Area:** Desktop integration · **Status:** missing

No system file-manager shell commands or upstream extension system. The half-translated Nautilus extension the Windows Explorer integration left behind is gone: it ran no session, so it uploaded nothing, and it was neither installed nor documented. The command templates of the graphical client (source/gui/explorer-commands.json) are its own feature and are shipped by all three installers.

**Next:** Specify desired desktop environment integrations and build/test them individually. No file-manager shell commands or upstream extension system exists; feature remains unimplemented.

**Acceptance criteria:**

- [ ] Specify supported file managers and extension API. Add explicit, opt-in installation and removal, selection transport without shell interpolation, confirmation and extension permission boundaries. Test packaged installation as well as source-tree execution.

## locale.translations

**Area:** Localization/accessibility · **Status:** partial

English/Spanish catalogs cover the browser interface (menus, dialogs, help, ARIA/tooltips, dynamic status/queue/sync/editor/search messages) and the whole command-line client: the per-command help texts, the status, argument, switch and engine messages of the script engine, the operations the error helpers name and the option listing. The translation compiler rejects a message that reaches the user without a catalog entry, a command help text that nobody translated and an error operation that is not in the catalog. Locale precedence, regional fallback, plurals, literal data, safe embedded JSON and internal protocol isolation are tested. Raw server/OS diagnostics, the 'LSCP-' protocol banners and core logs are intentionally preserved.

**Next:** Only English and Spanish catalogs are shipped (`source/linux/locales/en.json`, `es.json`; `source/gui/locales/en.json`, `es.json`). Upstream ships catalogs for many more languages. Feature remains partial: full upstream language-catalog coverage not implemented.

**Acceptance criteria:**

- [ ] Ship a catalog for every language the project claims to support and translate the whole interface into it, starting with the languages the upstream project already ships.
- [ ] Add a test that walks the catalogs and reports the messages of the client that are still answered in English, so a new interface string cannot slip through untranslated.

## automation.upstream-xml-compatibility

**Area:** Automation · **Status:** partial

The XML action log emits structured command, message and transfer actions with secret masking. Its structure resembles upstream but schema/consumer equivalence has not been established.

**Next:** Pin the intended upstream XML schema and validate successful/failing operations with actual automation consumers. Fixtures added: `fixtures/xml/action-log-success.xml` and `fixtures/xml/action-log-error.xml`.

**Acceptance criteria:**

- [ ] Compare schema-valid fixtures for command results, transfer errors, cancellation and session lifecycle against the pinned upstream format.
- [ ] Test at least one upstream-compatible parser and prove secret redaction preserves a valid document.

## Cross-cutting release gate

Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, report dependency skips, and update the ledger and generated reports. `python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. The normal checker validates consistency, not behavioral parity.
