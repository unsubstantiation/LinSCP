# Remaining parity implementation plan

Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. Full upstream parity is the target, **not a completed claim**.

2 tracked capability gaps. Each requires implementation and acceptance evidence; recording a plan does not satisfy its tests.

Regenerate with `python3 tools/check_upstream_parity.py --write-report`.

## security.gssapi-and-tunnels

**Area:** Security/authentication · **Status:** partial

Authenticated SSH jump-host connections work for SFTP/SCP/SSH and for FTP/FTPS/WebDAV/S3 destinations. SSH destinations still use a private socketpair (or TunnelLocalPortNumber on loopback); curl and native FTP/S3 sessions start a loopback SOCKS5 multiplexer on the jump so each CONNECT or data channel is a separate direct-tcpip, TLS SNI and S3 signing keep the original hostname, and a refused forward never falls back to a direct connection. Kerberos/GSSAPI is wired through libssh: AuthGSSAPI, AuthGSSAPIKEX, GSSAPIFwdTGT and LogicalHostName persist; gssapi-with-mic is attempted before public-key with password fallback; credential delegation stays off unless GSSAPIFwdTGT=1. Runtime support is detected from libssh so stub builds refuse explicit Kerberos settings by name. No isolated Kerberos/KDC realm is certified by the current fixtures; those cases skip without kinit, krb5-kdc and LSCP_TEST_KRB5_REALM.

**Next:** Validate GSSAPI/Kerberos against an isolated realm (principal selection, missing/expired credentials, mutual authentication and opt-in delegation) before claiming realm parity.

**Acceptance criteria:**

- [ ] Validate optional GSSAPI against an isolated Kerberos realm, testing principal selection, missing/expired credentials, mutual authentication and opt-in delegation; obtain security review before treating delegation as fully certified.

## locale.translations

**Area:** Localization/accessibility · **Status:** partial

English/Spanish catalogs cover the browser interface (menus, dialogs, help, ARIA/tooltips, dynamic status/queue/sync/editor/search messages) and the whole command-line client. The translation compiler rejects a message that reaches the user without a catalog entry. A catalog walker reports interface strings still answered in English so a new string cannot slip through untranslated. The language selector is filled from the shipped catalogs. Only English and Spanish catalogs are shipped; upstream ships catalogs for many more languages.

**Next:** Only English and Spanish catalogs are shipped; upstream ships catalogs for many more languages, and the upstream .NET interface has strings that this client does not have at all. No full upstream language-catalog coverage is claimed. A walker already reports catalog messages still answered in English.

**Acceptance criteria:**

- [ ] Ship a catalog for every language the project claims to support and translate the whole interface into it, starting with the languages the upstream project already ships.

## Cross-cutting release gate

Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, report dependency skips, and update the ledger and generated reports. `python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. The normal checker validates consistency, not behavioral parity.
