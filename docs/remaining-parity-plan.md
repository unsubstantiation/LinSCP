# Remaining parity implementation plan

Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. Full upstream parity is the target, **not a completed claim**.

4 tracked capability gaps. Each requires implementation and acceptance evidence; recording a plan does not satisfy its tests.

Regenerate with `python3 tools/check_upstream_parity.py --write-report`.

## security.gssapi-and-tunnels

**Area:** Security/authentication · **Status:** partial

Authenticated SSH jump-host connections now work for SFTP/SCP/SSH, including GUI tabs, background operations and the embedded terminal. Tunnel* raw settings, independent host-key verification, inherited proxy settings, encrypted stored jump credentials and bounded lifecycle cleanup are implemented. Kerberos/GSSAPI is now wired through libssh: AuthGSSAPI, AuthGSSAPIKEX, GSSAPIFwdTGT and LogicalHostName persist in stored sessions and the GUI; gssapi-with-mic is attempted before public-key auth with fallback to the existing methods; optional RFC 4462 GSSAPI key exchange is offered only when no host key is pinned; credential delegation stays off unless GSSAPIFwdTGT=1 is explicitly set. Runtime support is detected from libssh's advertised version so stub builds refuse explicit Kerberos delegation/logical-host/key-exchange settings by name instead of silently dropping them. TunnelLocalPortNumber now binds the requested loopback port for the jump session's own destination connection; 0 keeps the private socket pair. Non-SSH destination tunnels still fail closed, and no isolated Kerberos/KDC realm is certified by the current fixtures.

**Next:** Validate GSSAPI/Kerberos against an isolated realm (principal selection, missing/expired credentials, mutual authentication and opt-in delegation) before claiming realm parity. Tunnels for non-SSH destination protocols are not supported; they fail closed rather than connect directly.

**Acceptance criteria:**

- [ ] Validate optional GSSAPI against an isolated Kerberos realm, testing principal selection, missing/expired credentials, mutual authentication and opt-in delegation; obtain security review before treating delegation as fully certified.
- [ ] Define and test tunneling for FTP/FTPS/WebDAV/S3, including data-channel routing, TLS SNI/certificate verification and S3 signing for the original destination. Fixed SSH tunnel listener ports must remain loopback-only, fail on collisions and clean up on every failure.

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

## locale.translations

**Area:** Localization/accessibility · **Status:** partial

English/Spanish catalogs cover the browser interface (menus, dialogs, help, ARIA/tooltips, dynamic status/queue/sync/editor/search messages) and the whole command-line client: the per-command help texts, the status, argument, switch and engine messages of the script engine, the operations the error helpers name and the option listing. The translation compiler rejects a message that reaches the user without a catalog entry, a command help text that nobody translated and an error operation that is not in the catalog. Locale precedence, regional fallback, plurals, literal data, safe embedded JSON and internal protocol isolation are tested. Raw server/OS diagnostics, the 'LSCP-' protocol banners and core logs are intentionally preserved.

**Next:** Only English and Spanish catalogs are shipped; upstream ships catalogs for many more languages, and the upstream .NET interface has strings that this client does not have at all. No full upstream language-catalog coverage is claimed.

**Acceptance criteria:**

- [ ] Ship a catalog for every language the project claims to support and translate the whole interface into it, starting with the languages the upstream project already ships.
- [ ] Add a test that walks the catalogs and reports the messages of the client that are still answered in English, so a new interface string cannot slip through untranslated.

## Cross-cutting release gate

Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, report dependency skips, and update the ledger and generated reports. `python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. The normal checker validates consistency, not behavioral parity.
