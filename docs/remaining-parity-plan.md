# Remaining parity implementation plan

> **Historical:** This plan predates the native GUI-only conversion; removed CLI interfaces are not planned for restoration.

Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. Full upstream parity is the target, **not a completed claim**.

7 tracked capability gaps. Each requires implementation and acceptance evidence; recording a plan does not satisfy its tests.

Regenerate with `python3 tools/check_upstream_parity.py --write-report`.

## security.gssapi-and-tunnels

**Area:** Security/authentication · **Status:** partial

Authenticated SSH jump-host connections work for SFTP/SCP/SSH and for FTP/FTPS/WebDAV/S3 destinations. SSH destinations still use a private socketpair (or TunnelLocalPortNumber on loopback); curl and native FTP/S3 sessions start a loopback SOCKS5 multiplexer on the jump so each CONNECT or data channel is a separate direct-tcpip, TLS SNI and S3 signing keep the original hostname, and a refused forward never falls back to a direct connection. Kerberos/GSSAPI settings persist and gssapi-with-mic is attempted before public-key with password fallback; credential delegation stays off unless GSSAPIFwdTGT=1. GSSAPI authentication support is detected through libssh's public ssh_gssapi_set_creds symbol, not its version string. RFC 4462 KEX support is probed independently; AuthGSSAPIKEX is refused if the loaded libssh cannot honor it or a host-key pin is configured, rather than silently skipping either policy. The live SFTP suite provisions an isolated loopback MIT KDC and OpenSSH server and tests principal selection, missing/expired tickets, the service identity, and default-off versus opt-in TGT delegation. A second realm, PARTNER.TEST, is trusted directly through krbtgt/LINSCP.TEST@PARTNER.TEST. It covers cross-realm login, refusal of an unmapped principal of the trusted realm, and default-off versus opt-in delegation of the partner realm's TGT. CI requires a GSSAPI-enabled libssh and zero skips for these cases. As upstream's CreateTunnelData does, the jump session inherits the destination's Kerberos settings except LogicalHostName, so GSSAPIFwdTGT=1 also delegates to the jump host. docs/gssapi-delegation-review.md is the brief for the independent review; that review and production-KDC validation remain open.

**Next:** Production-KDC validation (for example Active Directory, FreeIPA or Heimdal) and an independent security review of opt-in TGT delegation remain outstanding; the review brief is docs/gssapi-delegation-review.md. The isolated CI realms already cover a direct cross-realm trust.

**Acceptance criteria:**

- [ ] Run the isolated-realm GSSAPI cases in CI with a GSSAPI-enabled libssh and no skipped cases; cover principal selection, missing/expired credentials, service mutual authentication, default-off delegation and opt-in TGT delegation.
- [ ] Obtain an independent security review of delegated TGT handling and validate cross-realm/production-KDC behavior before claiming general Kerberos parity.

## automation.command-interpreter

**Area:** Automation · **Status:** missing

The CLI and its external automation interfaces were removed in the GUI-only conversion.

**Next:** This interface is not part of the GUI-only distribution.

**Acceptance criteria:**

- [ ] No restoration is planned for the GUI-only distribution.

## automation.literal-gui-command

**Area:** Automation · **Status:** missing

The CLI and its external automation interfaces were removed in the GUI-only conversion.

**Next:** This interface is not part of the GUI-only distribution.

**Acceptance criteria:**

- [ ] No restoration is planned for the GUI-only distribution.

## automation.dotnet

**Area:** Automation · **Status:** missing

The CLI and its external automation interfaces were removed in the GUI-only conversion.

**Next:** This interface is not part of the GUI-only distribution.

**Acceptance criteria:**

- [ ] No restoration is planned for the GUI-only distribution.

## automation.powershell

**Area:** Automation · **Status:** missing

The CLI and its external automation interfaces were removed in the GUI-only conversion.

**Next:** This interface is not part of the GUI-only distribution.

**Acceptance criteria:**

- [ ] No restoration is planned for the GUI-only distribution.

## locale.translations

**Area:** Localization/accessibility · **Status:** partial

English, Spanish, German and French catalogs cover the browser interface (menus, dialogs, help, ARIA/tooltips, dynamic status/queue/sync/editor/search messages) and the whole command-line client, including the external-editor prompts. The translation compiler rejects a message that reaches the user without a catalog entry. A catalog walker reports interface strings still answered in English so a new string cannot slip through untranslated, and the translation tests keep switches, values, command names and protocol words literal in every catalog. The language selector and the backend's locale selection are filled from the shipped catalogs, and a confirmation accepts the yes letter its translated hint shows. Only English, Spanish, German and French catalogs are shipped; upstream ships catalogs for many more languages.

**Next:** Only English, Spanish, German and French catalogs are shipped; upstream ships catalogs for many more languages, and the upstream .NET interface has strings that this client does not have at all. No full upstream language-catalog coverage is claimed. A walker already reports catalog messages still answered in English.

**Acceptance criteria:**

- [ ] Ship a catalog for every language the project claims to support and translate the whole interface into it, starting with the languages the upstream project already ships.

## desktop.remote

**Area:** Desktop integration · **Status:** partial

RDP/VNC/SPICE are direct-TCP (3389/5900) with optional SSH jump SOCKS5h relay; X2Go/X11 are SSH-transported via direct-tcpip. Native viewers are resolved via PATH (xfreerdp3→xfreerdp→wlfreerdp/sdl-freerdp, mstsc, open, vncviewer, remote-viewer/spicy, x2goclient/pyhoca-cli, waypipe/ssh -X) with Windows/macOS/Android specifics, and dial the same proxy/tunnel/TLS/SPKI stack as file protocols. Headless mode falls back to .rdp/.vv file tickets or BrowserGateway hints for HTML5 gateways; XDMCP (UDP 177, unencrypted) is explicitly refused/recommended against. Wayland vs X11 detection drives waypipe vs ssh -X. Verified by unit ticket/argv tests; live viewer integration and ironrdp gateway tests are outstanding.

**Next:** Ironrdp WASM / Guacamole gateway HTML5 fallback credential isolation review remains; live viewer launches (xfreerdp/vncviewer/remote-viewer/x2goclient/waypipe, headless .rdp/.vv, jump tunnel inheritance, XDMCP refusal, SSH prompt + installer) are now gated via live-desktop.

**Acceptance criteria:**

- [ ] Live RDP launch with xfreerdp/mstsc against a throwaway RDP stub verifies argv, port 3389, TLS/NLA option, and jump-host SOCKS5h relay without exposing credentials (live-desktop).
- [ ] Live VNC (5900) and SPICE (5900/.vv) launches verify viewer resolution (tigervnc/remote-viewer), TLS port, and headless .vv/.rdp ticket generation (live-desktop).
- [ ] Live X2Go/NX and X11/Waypipe launches verify SSH-transported NX compression over direct-tcpip, WAYLAND_DISPLAY detection, and that jump-host proxy/TLS/SPKI settings are inherited without fallback (live-desktop).
- [ ] Obtain independent review that ironrdp WASM / Guacamole gateway fallback correctly isolates credentials and that XDMCP (UDP 177) remains refusing/not recommended.

## Cross-cutting release gate

Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, report dependency skips, and update the ledger and generated reports. `python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. The normal checker validates consistency, not behavioral parity.
