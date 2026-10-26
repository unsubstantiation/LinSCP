# Remaining parity implementation plan

Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. Full upstream parity is the target, **not a completed claim**.

2 tracked capability gaps. Each requires implementation and acceptance evidence; recording a plan does not satisfy its tests.

Regenerate with `python3 tools/check_upstream_parity.py --write-report`.

## security.gssapi-and-tunnels

**Area:** Security/authentication · **Status:** partial

Authenticated SSH jump-host connections work for SFTP/SCP/SSH and for FTP/FTPS/WebDAV/S3 destinations. SSH destinations still use a private socketpair (or TunnelLocalPortNumber on loopback); curl and native FTP/S3 sessions start a loopback SOCKS5 multiplexer on the jump so each CONNECT or data channel is a separate direct-tcpip, TLS SNI and S3 signing keep the original hostname, and a refused forward never falls back to a direct connection. Kerberos/GSSAPI settings persist and gssapi-with-mic is attempted before public-key with password fallback; credential delegation stays off unless GSSAPIFwdTGT=1. GSSAPI authentication support is detected through libssh's public ssh_gssapi_set_creds symbol, not its version string. RFC 4462 KEX support is probed independently; AuthGSSAPIKEX is refused if the loaded libssh cannot honor it or a host-key pin is configured, rather than silently skipping either policy. The live SFTP suite provisions an isolated loopback MIT KDC and OpenSSH server and tests principal selection, missing/expired tickets, the service identity, and default-off versus opt-in TGT delegation. CI requires a GSSAPI-enabled libssh and zero skips for these cases. Production/cross-realm compatibility and an independent review of delegation remain open.

**Next:** Production/cross-realm compatibility and independent security review of opt-in TGT delegation remain outstanding.

**Acceptance criteria:**

- [ ] Run the isolated-realm GSSAPI cases in CI with a GSSAPI-enabled libssh and no skipped cases; cover principal selection, missing/expired credentials, service mutual authentication, default-off delegation and opt-in TGT delegation.
- [ ] Obtain an independent security review of delegated TGT handling and validate cross-realm/production-KDC behavior before claiming general Kerberos parity.

## locale.translations

**Area:** Localization/accessibility · **Status:** partial

English, Spanish and German catalogs cover the browser interface (menus, dialogs, help, ARIA/tooltips, dynamic status/queue/sync/editor/search messages) and the whole command-line client, including the external-editor prompts. The translation compiler rejects a message that reaches the user without a catalog entry. A catalog walker reports interface strings still answered in English so a new string cannot slip through untranslated, and the translation tests keep switches, values, command names and protocol words literal in every catalog. The language selector and the backend's locale selection are filled from the shipped catalogs, and a confirmation accepts the yes letter its translated hint shows. Only English, Spanish and German catalogs are shipped; upstream ships catalogs for many more languages.

**Next:** Only English, Spanish and German catalogs are shipped; upstream ships catalogs for many more languages, and the upstream .NET interface has strings that this client does not have at all. No full upstream language-catalog coverage is claimed. A walker already reports catalog messages still answered in English.

**Acceptance criteria:**

- [ ] Ship a catalog for every language the project claims to support and translate the whole interface into it, starting with the languages the upstream project already ships.

## Cross-cutting release gate

Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, report dependency skips, and update the ledger and generated reports. `python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. The normal checker validates consistency, not behavioral parity.
