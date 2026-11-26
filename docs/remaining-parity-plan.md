# Remaining parity implementation plan

> **Historical:** This plan predates the native GUI-only conversion; removed CLI interfaces are not planned for restoration.

Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. Full upstream parity is the target, **not a completed claim**.

46 tracked capability gaps. Each requires implementation and acceptance evidence; recording a plan does not satisfy its tests.

Regenerate with `python3 tools/check_upstream_parity.py --write-report`.

## scp.curl-file-transfer

**Area:** SCP · **Status:** partial

The id is the row's history: an scp:// transfer is not curl's any more. The bytes go over an SSH exec channel running the server's own 'scp -f' and 'scp -t', with the rcp wire protocol spoken by the client - a timestamp header, a mode/size/name header, exactly the stated bytes and an acknowledgement per step, in both directions. A download stages through '.filepart' and is renamed onto the destination when it is whole; an interrupted one leaves the staging file and nothing under the final name. Uploads carry '-permissions' and '-preservetime'. Continuing a partial file is refused by name instead of attempted, because the protocol has no offset to continue from. ASCII conversion, masks, the speed limit, the progress meter and the interrupt behavior are the shared transfer path's and are checked here as well.

**Next:** The recursive form of the rcp protocol is not used: the client's own directory engine walks the tree and each file travels in the single-file form, so no 'E' record closes a level. Everything else the row states is checked by the cited cases.

**Acceptance criteria:**

- [ ] A transfer of a tree that speaks the recursive rcp form, with an 'E' record closing each level, proved by a case that runs.

## transfer.ascii-automatic

**Area:** Transfers · **Status:** partial

The ASCII mode converts the line endings, the binary mode keeps the bytes, and the automatic mode converts the files its mask names and leaves the others alone. A download is converted to the local native end of line unless '-eol=' names another one; an upload is converted to CRLF unless '-eol=' says otherwise. Fresh ASCII uploads can use server-enforced exclusive creation or an ETag precondition; acknowledged SFTP and FTP staged publication convert before staging; the FTP rename remains explicitly acknowledged as non-atomic and racy.

**Next:** Linux and Windows CI exercise exclusive and staged SFTP, staged FTP and ETag-conditional WebDAV ASCII uploads using loopback fixtures, including guard refusals. Android-device behavior and live third-party server behavior remain unverified. The upstream live WebDAV suite requires a CLI binary this GUI-only build does not ship.

**Acceptance criteria:**

- [ ] Exercise Android-device behavior where applicable.
- [ ] Cover remaining desired live-server behavior without depending on the removed CLI.

## transfer.filepart-resume

**Area:** Transfers · **Status:** partial

Downloads can stage in a `.filepart` file beside the destination and resume from that staging file. A mid-flight interruption test verifies the old destination remains untouched, the partial survives and the resumed download is published. SFTP and FTP guarded uploads do not provide this `.filepart` resume behavior; their acknowledged staged publication requires a fresh copy. The GUI verified-resume path compares the checkpoint against remote bytes before resuming and publishes without replacing an existing destination. Ordinary SFTP resume now compares an existing prefix before continuing or adopting a destination, and refuses unsafe, complete, or oversized existing stages rather than deleting them. Ordinary FTP resume also compares the saved prefix before modifying local files; FTP verification drains the full remote file with bounded memory and retains the control connection on mismatch. Ordinary WebDAV and S3 resumes compare the prefix under a strong ETag and use the same condition for the remaining download. Versioned S3 resumes additionally send the version ID and require the server to confirm it on HEAD and each conditional GET; versioned source deletion is refused. FTP/SFTP partial reuse is refused unless the user explicitly accepts best-effort resume for that transfer. The GUI warns that concurrent changes can corrupt the result, and the engine independently enforces the opt-in. A staged partial selected after verification must match the path and length that were checked. The S3 versions dialog offers opt-in verified resume to a new destination, with version-scoped checkpoints; the Linux S3 service fixture exercises an older version, stale partial refusal, and no-overwrite behavior. Granted-folder resume remains unsupported. WebDAV conditional prefix and download responses must return the expected ETag; missing or mismatching tags fail before bytes are written. A Linux service fixture verifies refusal when a WebDAV server ignores If-Match but reports a changed tag.

**Next:** Linux and Windows loopback CI exercise stale FTP/SFTP/WebDAV/S3 prefixes and conditional WebDAV/S3 source changes. FTP/SFTP resume is best-effort only with explicit per-transfer approval: size/mtime checks cannot pin an atomic snapshot, and concurrent remote or local modifications can still corrupt a result. WebDAV/S3 conditional behavior requires a conforming server, and WebDAV endpoints that omit ETags on conditional GETs are refused; versioned resume is not available for Android granted folders. Guarded SFTP/FTP uploads still cannot resume; Android-device and live third-party server behavior remain unverified.

**Acceptance criteria:**

- [ ] Consider stronger protections for concurrent local and remote changes; FTP/SFTP cannot provide atomic snapshots and best-effort resume requires explicit consent.
- [ ] Implement safe resumable guarded uploads, or document protocol-specific refusals and alternatives.
- [ ] Exercise Android-device and relevant live-server behavior without the removed CLI.

## transfer.resume-modes

**Area:** Transfers · **Status:** partial

The internal interpreter parses automatic/on/off and per-transfer -resumesupport thresholds. Mock SFTP tests drive the interpreter through resume-off, a per-transfer off override, below/at-threshold staging, and an on-mode refusal when an existing unapproved checkpoint is present. They also verify an existing checkpoint is never altered. FTP/SFTP continuation without an atomic snapshot is refused by default; explicit per-transfer best-effort approval is required where exposed. The GUI-only distribution does not expose the historical script CLI.

**Next:** Linux and Windows host tests exercise option propagation and checkpoint preservation against a mock SFTP server; they do not prove real-server behavior or Android device behavior. The historical live-sftp suite requires a CLI binary this distribution does not build.

**Acceptance criteria:**

- [ ] Validate the supported GUI workflows and safety behavior on Android and against real servers; do not claim the removed CLI interface is shipped.

## transfer.presets

**Area:** Transfers · **Status:** partial

Named, per-site and rule-selected presets change live transfer settings.

**Next:** The live half is still unevidenced: live-dav needs a `linscp` binary this repo does not build. Runnable residue: engine-script, which checks the preset store, the rules that match a session or a file mask, and the preset a site stores with itself.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## transfer.curl-progress

**Area:** Transfers · **Status:** partial

The HTTP-backed downloads and uploads report the bytes as they move: the byte-progress callback is told what has been transferred and how much there is, while the transfer runs, and a download that stages its bytes writes them to the `.filepart` file first. Upstream reads the same numbers out of curl's progress meter and renders them live in the terminal; this build has no curl meter and no live percentage line, so that half of the upstream claim is not implemented here.

**Next:** The upstream half is still unevidenced: live-curl needs a `linscp` binary this repo does not build, and unit has no build target and cannot be compiled. Runnable residue: proto-dav-s3, which reports the byte progress of an upload and of a download while they run. The live percentage line is not implemented in this build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Render the transfer progress as a live percentage line in the terminal, the way upstream does.

## sync.one-way

**Area:** Synchronization · **Status:** partial

Local-to-remote keepuptodate and recursive one-way planning/upload run against the live WebDAV server; the same plan and upload run against the mock SFTP server.

**Next:** The live half is still unevidenced: live-dav needs a `linscp` binary this repo does not build. Runnable residue: engine-sftp, which mirrors the local tree onto the remote side and prunes the excluded subtrees from the plan.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sync.keepuptodate-inotify

**Area:** Synchronization · **Status:** partial

A file that arrives in the watched tree wakes the watcher, so the next pass runs straight away instead of waiting for the rescan interval.

**Next:** The live half is still unevidenced: live-dav needs a `linscp` binary this repo does not build. Runnable residue: engine-sftp, which shows the arrival waking the watcher with an interval far longer than the wait it took.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sessions.site-manager

**Area:** Sessions/configuration · **Status:** partial

Stored sites can be saved, renamed (including nested folders), filtered, sorted by name or last-connected timestamp (last_used), opened, removed, exported and imported.

**Next:** The rename path and the site's own cleanup still rest on the service suite, which no Android step executes. Runnable residue: engine-script (the store, the folders, the export and the import), the service suite and the GUI suite on Linux and Windows.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sessions.password-at-rest

**Area:** Sessions/configuration · **Status:** partial

The native service encrypts saved session metadata in an authenticated vault envelope and encrypts site secrets with a data key wrapped in sessions.key by the local password vault. A locked vault refuses access. On Windows the configuration directory is additionally owner-only: ensure_private_dir applies D:P(A;OICI;FA;;;OW), inherited by children. Legacy compatibility does not imply that the retired CLI or Python client can read the current vault format.

**Next:** Linux and Windows host tests cover vault sealing, reopen with the correct password, wrong-password refusal, tamper refusal and preservation, migration, and redaction. Android device behavior and compatibility with the retired Python/core clients are not established; the old live-sftp suite requires a CLI binary this distribution does not build.

**Acceptance criteria:**

- [ ] Validate vault setup, lock, restart, unlock, tamper refusal and site-secret recovery on an Android device or emulator.
- [ ] Only claim compatibility with historical Python/core clients if the actual current encrypted vault format is tested with them.

## sessions.proxy-settings

**Area:** Sessions/configuration · **Status:** partial

Upstream proxy setting names are applied by open and stored with a site; both SOCKS5 and HTTP CONNECT proxies carry live SFTP sessions and refuse bad credentials. A proxy method the protocol cannot run, and a proxy without a host, are refused when they are set rather than dropped.

**Next:** The live half is still unevidenced: live-sftp needs a `linscp` binary this repo does not build. Runnable residue: engine-script, which keeps the proxy a site stores and refuses a proxy method the protocol cannot run or one without a host.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sessions.rawsettings

**Area:** Sessions/configuration · **Status:** partial

'open' and 'savesession' take '-rawsettings' with upstream's names: the proxy settings (ProxyMethod, ProxyHost, ProxyPort, ProxyUsername, ProxyPassword, ProxyTelnetCommand, ProxyLocalCommand, ProxyDNS, ProxyLocalhost, ProxyExcludeList), the FTP engine's policy (FtpPasvMode, FtpForcePasvIp, FtpUseMlsd, FtpAccount) and the TLS policy (Ftps, MinTlsVersion, MaxTlsVersion, TlsCertificateFile, TlsCertificateKeyFile, CaCertificateFile, CaCertificateDir, PinnedPublicKey). A name or value outside that set is refused by name before any connection, so a setting is never stored and then dropped at open time, and 'savesession' writes what it applied under the keys a saved site reads back.

**Next:** The live half is still unevidenced: live-curl needs a `linscp` binary this repo does not build, and unit has no build target and cannot be compiled. Runnable residue: engine-script, which refuses an unknown setting by name, validates every value, and reads the stored settings back.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## security.agent-android-refusal

**Area:** Security/authentication · **Status:** partial

Agent authentication explains itself when there is no agent to ask. The auth chain asks the connector for a missing reason when its stream comes back empty: SshAgentConnector gains a defaulted missing_reason, SystemSshAgentConnector answers with a platform reason (SSH_AGENT_MISSING_MESSAGE on Android, none where the build probes for a socket), and the reason becomes the terminal error instead of the generic auth failure. The site dialog shows the same story up front through a hostDifferenceReason-backed hint wired to a new bundle sshAgent flag; the hint fails open (any non-Android host is assumed to have an agent) because the page cannot see the server OS, so the backend refusal is the layer that cannot be skipped.

**Next:** The Android-Rust arm — the real connector reporting the platform message through the real chain — executes in no step: Android runs no Rust tests, and the emulator smoke does not attempt agent authentication. Message selection on device is review-level.

**Acceptance criteria:**

- [ ] An emulator or device run attempting agent authentication and showing the platform reason instead of the generic failure.

## security.proxy-isolation

**Area:** Security/authentication · **Status:** partial

SFTP SOCKS5 and HTTP CONNECT proxies and curl proxy routing are verified live; wrong proxy credentials and unsupported proxy modes are refused rather than bypassed. A proxy the protocol cannot run never reaches the transport.

**Next:** The live half is still unevidenced: live-dav and live-sftp need a `linscp` binary this repo does not build. Runnable residue: engine-script, which refuses a proxy method the protocol cannot run and a proxy without a host.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## security.gui-api-token

**Area:** Security/authentication · **Status:** partial

The native GUI calls the service in-process through Tauri IPC rather than a separately configured local HTTP API. The webview has access to privileged commands: content injection in it could drive the service. The page escapes tab and transfer text, binds tab-close actions without interpolating IDs, rejects malformed queue IDs, and validates numeric progress before inserting it into markup. These defenses do not establish isolation from other local processes or rule out other injection paths.

**Next:** The GUI cases run in jsdom with a mock backend, not a packaged WebView. No test proves the running binary opens no API listener or that Tauri IPC is inaccessible to other local processes; the native-shell IPC path, remaining rendering surfaces, and Android device behavior need security validation.

**Acceptance criteria:**

- [ ] Exercise packaged desktop and Android IPC boundaries, including attempts from untrusted web content and local processes.
- [ ] Audit and test the remaining untrusted-data rendering surfaces, and validate the absence of any unintended API listener in the shipped application.

## security.gssapi-and-tunnels

**Area:** Security/authentication · **Status:** partial

Authenticated SSH jump-host connections work for SFTP/SCP/SSH and for FTP/FTPS/WebDAV/S3 destinations. SSH destinations still use a private socketpair (or TunnelLocalPortNumber on loopback); curl and native FTP/S3 sessions start a loopback SOCKS5 multiplexer on the jump so each CONNECT or data channel is a separate direct-tcpip, TLS SNI and S3 signing keep the original hostname, and a refused forward never falls back to a direct connection. Kerberos/GSSAPI settings persist and gssapi-with-mic is attempted before public-key with password fallback; credential delegation stays off unless GSSAPIFwdTGT=1. GSSAPI authentication support is detected through libssh's public ssh_gssapi_set_creds symbol, not its version string. RFC 4462 KEX support is probed independently; AuthGSSAPIKEX is refused if the loaded libssh cannot honor it or a host-key pin is configured, rather than silently skipping either policy. The live SFTP suite provisions an isolated loopback MIT KDC and OpenSSH server and tests principal selection, missing/expired tickets, the service identity, and default-off versus opt-in TGT delegation. A second realm, PARTNER.TEST, is trusted directly through krbtgt/LINSCP.TEST@PARTNER.TEST. It covers cross-realm login, refusal of an unmapped principal of the trusted realm, and default-off versus opt-in delegation of the partner realm's TGT. CI requires a GSSAPI-enabled libssh and zero skips for these cases. As upstream's CreateTunnelData does, the jump session inherits the destination's Kerberos settings except LogicalHostName, so GSSAPIFwdTGT=1 also delegates to the jump host. docs/gssapi-delegation-review.md is the brief for the independent review; that review and production-KDC validation remain open. On Linux the GUI settings now flow to a real GSSAPI attempt (the parser used to drop all four Kerberos keys); on Windows and Android the site manager labels the section Linux-only, key exchange is noted as unsupported on every build, and explicit settings fail closed naming the requirement. The Windows and Android citations below evidence that labeling and refusal, not Kerberos authentication itself. Windows loads System32\secur32.dll SSPI (AcquireCredentialsHandleW/InitializeSecurityContextW/MakeSignature for Kerberos HOST/<host>) behind GssapiTokenProvider.

**Next:** The live half is still unevidenced: live-tunnel and live-sftp need a `linscp` binary this repo does not build, and unit has no build target and cannot be compiled. Runnable residue: engine-script, which keeps the jump-host and Kerberos settings a site stores and refuses a jump host that is not named.

**Acceptance criteria:**

- [ ] Run the isolated-realm GSSAPI cases in CI with a GSSAPI-enabled libssh and no skipped cases; cover principal selection, missing/expired credentials, service mutual authentication, default-off delegation and opt-in TGT delegation.
- [ ] Obtain an independent security review of delegated TGT handling and validate cross-realm/production-KDC behavior before claiming general Kerberos parity.
- [ ] Provide a Windows SSPI (or sspi-crate) context provider behind the GssapiTokenProvider trait, with tests against an AD or Samba KDC, before claiming Kerberos on Windows.

## security.gui-account

**Area:** Security/authentication · **Status:** partial

The shipped native service is single-user and does not implement account login, per-user isolation, CSRF sessions, or a home-directory jail. GET /api/login reports accounts disabled, POST /api/login refuses, and logout is a compatibility no-op, even if a legacy accounts.ini is present. The backup preserves that file but does not enable accounts. Do not expose this dispatcher as a multi-user server or rely on it to isolate mutually untrusted users; use separate OS accounts and an appropriate security boundary.

**Next:** The former server-deployment account system is not shipped. Host tests establish the native compatibility responses and lack of an account authorization gate; they do not test a server, per-route isolation, or Android device behavior.

**Acceptance criteria:**

- [ ] If multi-user server deployment is desired, first define its security boundary and restore or replace account authentication and authorization, including per-route negative tests and isolation. Otherwise retain the explicit single-user limitation.

## gui.native-path-drop

**Area:** GUI · **Status:** partial

An operating-system drop in a native window arrives as paths, not as a File: `dragDropEnabled` makes the Tauri window consume the drop before the page sees it. The shell emits `native:file-drop` with those paths, the shared bundle turns them into one request (the first path plus the list, with the folders named), and the service stages and queues exactly what the browser's byte drop would - the same endpoints, the same queue, the same conflict answer, so one set of overwrite rules answers for all three apps. Dropped files and folders are streamed in 64 KiB chunks into private per-drop staging with cumulative file-count (`MAX_DROP_STAGING_FILES`), byte-size (`MAX_DROP_STAGING_BYTES`), and directory-depth (`MAX_DROP_STAGING_DEPTH`) bounds, cleaning up partial staging trees on refusal. A local drop copies the tree directly; a grant-URI source is read through `LocalFs`; a link inside a dropped folder is refused rather than followed. Android's share hand-off records the desktop's pending manifest and the page queues it through the same path. What the drop still lacks is end-to-end evidence on a real window: the jsdom suite drives the request shape and the service test drives the filesystem, but neither can produce a WebKit drop event, and the share intent filter is registered by the generated Kotlin project rather than by this tree.

**Next:** The path a native window drops is streamed into bounded private staging and queued, but no automated test drives a real WebKit drop event or the Android share filter.

**Acceptance criteria:**

- [ ] Drive a real WebKit/GTK drop onto the native window and show the queued task names the dropped paths (the shell's `dragDropEnabled` handler cannot be exercised by jsdom).
- [ ] Register the Android share intent filter in the generated Kotlin project and prove a shared file reaches the same drop path, including the conflict question and the queue entry.
- [ ] Prove a dropped folder larger than memory is staged without holding it in the page, and that a partial staging tree is removed when the queue refuses the drop.

## editing.encoding-policy

**Area:** Editing/search · **Status:** partial

The browser editor and search enforce UTF-8 text and reject binary files, while CLI 'edit -eol=lf|crlf' normalizes line endings before upload.

**Next:** The live half is still unevidenced: live-sftp needs a `linscp` binary this repo does not build. Runnable residue: service-commands, which refuses a binary file and a byte sequence the encoding cannot hold; and engine-editor, which normalizes the line endings before the upload (the editor double is a shell command, so that case runs on the Unix hosts).

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

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

## automation.xml-action-log

**Area:** Automation · **Status:** partial

The XML action log (-xmllog=) writes the upstream session format (http://winscp.net/schema/session/1.0): '<group>' per command and structured '<upload>', '<download>', '<rm>', '<mkdir>', '<mv>', '<cp>', '<chmod>', '<touch>', '<call>', '<ls>', '<stat>', '<checksum>' and '<cwd>' elements with '<result success>' children and secrets masked. Schema and consumer equivalence are automation.upstream-xml-compatibility.

**Next:** The operation elements of a real session (upload, download, ls, ...) are still unevidenced: live-sftp needs a `linscp` binary this repo does not build, and unit has no build target and cannot be compiled. Runnable residue: engine-script, which checks the group and failure structure, the masking of the secrets and the shipped fixtures. Host-side logger tests exercise masking multiple credential-bearing URL authorities and recognized secret switches, including multiline quoted values, in failure messages; this is not proof that every possible secret or malformed URL is redacted. Sensitive text logging explicitly opts out.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

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

## desktop.scheme-handlers

**Area:** Desktop integration · **Status:** partial

The GUI can parse a manually pasted session URL through /api/session/url, including FTPS variants and escaped paths. Invalid URL diagnostics do not echo input, because URLs may contain credentials. The Linux desktop entry does not register URI handlers or pass a URL, and the native launcher does not consume startup URLs.

**Next:** Manual URL parsing has host-side coverage, but desktop scheme registration and startup URL delivery are not implemented. Android deep-link behavior and real desktop integration are not tested.

**Acceptance criteria:**

- [ ] If startup URI handling is desired, design and implement registration and secure delivery on each intended platform, with tests for untrusted URLs, credential handling, explicit user confirmation, and host-key validation.
- [ ] Test launching a registered URI through the actual desktop or device.

## desktop.launcher-prefix

**Area:** Desktop integration · **Status:** partial

Installed, Makefile and CMake binaries select their own GUI launcher; the GUI finds the matching core under a relocatable prefix.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## desktop.wayland-session

**Area:** Desktop integration · **Status:** partial

A desktop session is recognised as Wayland or as X11 before anything is asked of it, and only a program that can draw on it is started. The console client finds the compositor by its socket in XDG_RUNTIME_DIR - the default 'wayland-0' when WAYLAND_DISPLAY is not exported, so a session started by a launcher or a user service is still found - and refuses a Wayland-only terminal under X11, where it exits before mapping a window, while an X11-only one under Wayland is a reported XWayland fallback rather than a silent choice. The graphical client draws no window itself and asks the desktop's own URI launcher ($BROWSER, xdg-open, gio) for a browser, which needs no X11 and no window manager of the X11 kind; linscp.desktop starts it with that option and does not claim a startup notification it could never complete. Covered by unit, the retired GUI harness and wayland-compatibility; no case runs against a live compositor, so the interaction with one is not certified here.

**Next:** The source-shape checks in wayland-compatibility run on every platform, but the C++ session detector and the console launcher it describes are exercised by UnitTest.cpp and ScriptTest.py, which have no build target and need a `linscp` binary this repo does not build - so they are not evidence. No case runs against a live compositor either, so what a real Wayland session does with this build is not certified here.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] wayland-compatibility cannot run on Windows or Android (it is a Linux display-server guard); record platform-scoped evidence for the Linux-only behavior, or cite additional runnable suites there.

## locale.translations

**Area:** Localization/accessibility · **Status:** partial

English, Spanish, German and French catalogs cover the browser interface (menus, dialogs, help, ARIA/tooltips, dynamic status/queue/sync/editor/search messages) and the whole command-line client, including the external-editor prompts. The translation compiler rejects a message that reaches the user without a catalog entry. A catalog walker reports interface strings still answered in English so a new string cannot slip through untranslated, and the translation tests keep switches, values, command names and protocol words literal in every catalog. The language selector and the backend's locale selection are filled from the shipped catalogs, and a confirmation accepts the yes letter its translated hint shows. Only English, Spanish, German and French catalogs are shipped; upstream ships catalogs for many more languages.

**Next:** Only English, Spanish, German and French catalogs are shipped; upstream ships catalogs for many more languages, and the upstream .NET interface has strings that this client does not have at all. No full upstream language-catalog coverage is claimed. A walker already reports catalog messages still answered in English.

**Acceptance criteria:**

- [ ] Ship a catalog for every language the project claims to support and translate the whole interface into it, starting with the languages the upstream project already ships.

## platform.make-linux

**Area:** Packaging/platforms · **Status:** partial

source/linux/Makefile builds the native Linux/libssh client, refuses non-Linux hosts and provides an install target staged under DESTDIR/PREFIX.

**Next:** No runnable suite evidences this: script needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## platform.cmake-linux

**Area:** Packaging/platforms · **Status:** partial

CMakeLists.txt builds the Linux binaries, registers CTest suites, refuses non-Linux hosts and installs the CLI, GUI, desktop entry and man page.

**Next:** No runnable suite evidences this: script needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## platform.debian-package

**Area:** Packaging/platforms · **Status:** partial

debian/rules and debian/control package the CLI, GUI, desktop entry, icons and man page matching the staged Linux install tree.

**Next:** No runnable suite evidences this: script needs a `linscp` binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## platform.prefix-lookup

**Area:** Packaging/platforms · **Status:** partial

An arbitrary PREFIX/share/linscp/gui resolves PREFIX/bin/linscp before /usr/bin.

**Next:** No runnable suite evidences this: the Python GUI harness the ledger used to cite is retired, and no shipped suite replaces it yet.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## platform.posix-runtime-services

**Area:** Packaging/platforms · **Status:** partial

Linux provides private filesystem and configuration helpers and signal handling. The native implementation differs from upstream POSIX runtime services and does not use the retired curl subprocess. Linux and Windows host tests exercise bounded SSH exec capture over a mock server, including interleaved stdout/stderr, a combined limit, timeout, and connection reuse; that is not a local child-process test. An isolated Linux subprocess checks SIGINT, SIGTERM and SIGWINCH delivery, flag clearing, inherited-ignore reset, and restored default termination.

**Next:** Linux host tests cover isolated signal handling as well as filesystem/configuration, and Linux/Windows tests cover bounded mock-SSH exec output. Local child stdout/stderr capture, real SSH servers, Windows console control events, and Android runtime behavior remain unverified.

**Acceptance criteria:**

- [ ] If local child output capture remains a supported requirement, test the actual child-process path with simultaneous stdout and stderr output.
- [ ] Validate Windows console control events and relevant runtime behavior on an Android device.

## platform.terminal-and-console

**Area:** Packaging/platforms · **Status:** partial

Linux command-line parsing, terminal-facing configuration and the native console entry point are built from the Linux sources. Which terminal 'terminal' starts depends on the display server the session runs on; that behavior is its own row, desktop.wayland-session.

**Next:** The Linux build targets themselves are still unevidenced: unit has no build target and cannot be compiled. Runnable residue: engine-script, which checks the command list and each command's own help.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## platform.linux-file-events

**Area:** Packaging/platforms · **Status:** partial

The synchronization watcher uses filesystem events and retains interval polling as a safety net when a watch cannot be installed.

**Next:** Native watcher wakeup and injected watcher-install failure followed by timed polling are covered on Linux and Windows hosts. Actual OS resource-exhaustion behavior, real third-party server behavior, and Android device behavior remain unverified; the live-dav suite requires a binary this repo does not build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## platform.conversion-completeness

**Area:** Packaging/platforms · **Status:** partial

LinSCP is a Linux-only client and the check that says so is part of the build: tools/check_platform_conversion.py reads the client's own sources and refuses a Windows API call, a Windows header, a Windows-only compilation branch, a Windows environment variable, a Windows executable, a Windows path, a file of another platform, an installer that does not ship what the other installers ship, and an error message whose operation phrase contradicts the template it is filled into. It runs in 'make -C source/linux check', as the CTest case 'platform-conversion-check', and in CI. Third-party code is not scanned; everything else in the tree is this project's own.

**Next:** Runnable evidence exists on Linux only (platform-conversion); Windows and Android have none (see the suite registry).

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Extend the runnable residue (platform-conversion) to Windows and Android, or cite additional runnable suites there.

## platform.android-saf-editing

**Area:** Packaging/platforms · **Status:** partial

Opening, saving and reading properties in a granted Android folder go through LocalFs to the SAF bridge instead of the refusal: the editor reads the document bytes, saves create-or-replace the document, and properties rows carry the bridge's stat, on the main pane and on a granted other pane alike. The stale-save guard compares at the bridge's seconds precision, the same granularity remote saves use. A save whose stat fails proceeds to the bridge write, because a missing document and an unreadable one are indistinguishable there and the write creates what is missing; a genuinely broken write still surfaces its own error. The page offers the editor for granted folders again; chmod, synchronization, transfers, copy/move and watching keep their named refusals (see platform.android-saf-refusals).

**Next:** No suite has touched a real DocumentsProvider: the bridge is an in-memory mock, so provider behaviour (mtime precision, create-or-replace error cases, large documents) is unproven on a device.

**Acceptance criteria:**

- [ ] Open, edit, save and re-read a file in a granted folder on an Android device or emulator, covering the stale-save refusal and the properties rows the dialog shows.

## platform.android-saf-local-copy-move

**Area:** Packaging/platforms · **Status:** partial

Local copies and moves with a granted end run on LocalFs in the queue worker: bytes cross the bridge whole between plain and granted panes and between two granted trees, with the same conflict policies as plain pairs. Every granted move is a copy that deletes its source (queue jobs always carry the same leaf on both sides, so a provider-side rename could only retarget a name onto itself); same-directory renames stay on the rename endpoint, which renames directly. Files over the 64 MiB document cap refuse at enqueue time and in the worker naming the file; symbolic links refuse by name; a plain target keeps the source's seconds while a granted target gets fresh stamps, and directory copies keep the plain panes' refusal word for word. The page offers transfers and moves on local tabs and still gates session transfers and moves on remote tabs. Chunked 1 MiB SAF streaming (readUriChunk/beginWriteUri/appendUriChunk and LocalFs::copy_streamed) eliminates whole-file Base64/JSON heap spikes.

**Next:** No suite has touched a real DocumentsProvider: the bridge is an in-memory mock, so provider behaviour (nested document URIs, large-document memory pressure, concurrent-creator races on moves) is unproven on a device.

**Acceptance criteria:**

- [ ] Copy and move files between a granted folder and app storage and between two granted trees on an Android device or emulator, covering the document-cap refusal and a move onto an existing name.

## platform.android-saf-session-transfers

**Area:** Packaging/platforms · **Status:** partial

Session transfers with a granted local side stage through private temporary files in the queue worker: uploads stage the granted source (keeping its seconds, so the remote keeps its stamps) and run the guarded upload unchanged from the stage; downloads land in a stage and publish across the bridge file by file. Trees stage and publish whole in both directions; merges add to an existing granted tree without replacing any file and fail instead of replacing. Files over the 64 MiB document cap refuse at enqueue time naming the file; verified resume refuses for granted folders, since the bridge has no appends or partial files; WebDAV moves delete the remote source by ETag after the staged download publishes. The page offers transfers and moves for granted folders on both tab kinds. Staging and publication stream in 1 MiB chunks via LocalFs::stage_to_file and LocalFs::publish_from_file.

**Next:** Both remotes are in-memory mocks: no suite has uploaded from or downloaded into a real DocumentsProvider, so provider behaviour (nested document URIs, large-document memory pressure, concurrent writers during a merge) is unproven on a device.

**Acceptance criteria:**

- [ ] Upload, download and move files between a granted folder and a server on an Android device or emulator, covering a tree transfer, the document-cap refusal and the resume refusal.

## editing.non-utf8-encodings

**Area:** Editing/search · **Status:** partial

CLI editing supports explicit legacy-encoding selection ('edit -encoding=ENC'): the file is converted between its encoding and UTF-8, the round trip is byte exact with the BOM preserved, and invalid sequences or unrepresentable output are refused without a silent replacement. Browser editor/search remain UTF-8-only and reject binary files.

**Next:** The live half is still unevidenced: unit has no build target and cannot be compiled. Runnable residue: service-commands, which refuses a binary file, an invalid byte sequence and an unknown encoding, and round-trips a legacy encoding byte exactly with its byte-order mark; and engine-editor, which edits a file in a legacy encoding and uploads it in that encoding (the editor double is a shell command, so that case runs on the Unix hosts).

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Cover the search path as well as the editor path: the browser search rejects binary files too.

## automation.upstream-xml-compatibility

**Area:** Automation · **Status:** partial

The XML action log (-xmllog=) now writes the upstream session format instead of a look-alike: root '<session xmlns="http://winscp.net/schema/session/1.0" name="user@host"|site|nosession start="...Z">', one '<group>' per script command named by its masked line (grouping is always on, so a continuous reader knows a command finished when its group closes), one element per physical operation - upload, download (both with '<size>'), rm (including rmdir and S3 exact-version removal), mkdir, mv, cp, chmod ('<permissions>' as 'rwxr-xr-x' letters), touch ('<modification>'), call ('<output>'/'<erroroutput>' streams and '<exitcode>' from a captured run), ls ('<files>' of '<file>' with the upper-case type character), stat (one '<file>' with no '<filename>'), checksum ('<algorithm>'/'<checksum>') and cwd - each ending in '<result success="true|false">' with '<message>' on failure, and a '<failure>' with the command's masked errors closing a failed group. Attribute and text escaping follow upstream's XmlAttributeEscape/XmlEscape pair (newline as '&#10;' in attributes, CR and unrepresentable controls dropped), timestamps are the one UTC '....NNNZ' spelling. The format is pinned in the repository as docs/linscp-session-1.0.xsd, written from upstream's emitter (source/core/SessionInfo.cpp) and its XML Logging documentation. The engine-script suite reads the shipped fixtures (fixtures/xml/) and a freshly produced log back the way an upstream-style consumer does - the namespace, the groups, the failure and the masked-password failure - and holds the log to the operation elements the fixtures show; the live SFTP suite validates a full real session log the same way and checks every action element's parameters against the bytes it moved. Boundaries kept: console output is not recorded (as upstream), operations with no upstream element (symlink creation) are absent (as upstream), 'difference' elements for a bare synchronization comparison are schema-defined but only emitted through the transfer/mkdir/rm elements a synchronization actually performs, and a run that never connects keeps the upstream fallback session name 'nosession'.

**Next:** The XSD validation with xmlschema and the operation elements of a real session are still unevidenced: live-sftp needs a `linscp` binary this repo does not build, and unit has no build target and cannot be compiled. Runnable residue: engine-script, which reads the shipped fixtures and a produced log back as an upstream-style consumer does. Host-side logger tests exercise masking multiple credential-bearing URL authorities and recognized secret switches, including multiline quoted values, in failure messages; this is not proof that every possible secret or malformed URL is redacted. Sensitive text logging explicitly opts out.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Give UnitTest.cpp a build target, or port its cases to Rust tests.

## gui.local-symlink

**Area:** GUI · **Status:** partial

Symbolic links can be created in a local pane, not just over SFTP: the other pane of a local tab goes through a new local branch in link_remote_async, the main pane through a new /api/local/link endpoint, and both share one helper (create_local_link) that validates two different single-leaf names, refuses a taken link name, and calls gui_os.create_local_symlink after resolve_contained. The page dialog is one pane-aware promptLink(side), offered from the Local menu for the local pane and the Commands menu for the remote pane with no new translatable strings; a granted folder is refused by the shared app-storage message in both layers.

**Next:** Link creation itself is proven only on Unix: the creation test is cfg(unix) because Windows needs a symlink privilege (or developer mode) this suite cannot grant itself, and Android runs no Rust tests. Validation and the granted-folder refusal run on every platform.

**Acceptance criteria:**

- [ ] A Windows CI run proving link creation in a plain directory, or a documented privilege requirement the backend reports.
- [ ] A device or emulator run proving link creation in Android app storage.

## gui.remote-delete

**Area:** GUI · **Status:** partial

Remote deletes walk the selected tree, unlink symlinks without following them, reject unsafe server-provided child names, and report errors per selected name. A missing top-level entry is treated as already deleted. Partial failures are included in the service response and shown in the GUI error log; a failed child operation never counts the whole tree as deleted.

**Next:** Recursive remote deletion is not transactional and may leave a partially deleted tree after an error. Linux and Windows mock-session tests inject a child deletion failure and verify the partial result is reported; the GUI test verifies the message reaches the error log. Live-server interruption and Android-device behavior remain unverified.

**Acceptance criteria:**

- [ ] Exercise actual connection interruption and resulting partial deletion against a live server.
- [ ] Exercise the partial-failure report on Android and retain the non-transactional warning.

## backup.full-export-import

**Area:** Sessions/configuration · **Status:** partial

Encrypted portable full application backup (`LSCPBAK1`, independent password, Argon2id + AES-256-GCM, LF-normalized, CRLF-tolerant, no absolute config_dir) and transactional undo-journaled restore (`restore_journal.rs` + `ConfigDirectoryLock` + Linux/Android/Windows directory sync barriers). Covers sessions.ini, vault SSH keys + metadata rewrapped under the destination's unlocked vault key, workspaces.json, bookmarks.json, preferences.json, accounts.ini, sshhostkeys, explorer-commands.json, custom-commands.json, monitor.json, and transfer-presets.ini, and clears device-local auto-reconnect.json. `backup_is_distribution_compatible_between_linux_windows_and_android` proves Linux→Windows→Android round-trip with vault SSH key rewrapping, encrypted stores, fail-closed validation, and CRLF file tolerance. Implemented in crates/linscp-engine/src/{backup.rs,restore_journal.rs}, `backup export|import <file>` in script.rs, and `POST /api/backup/{export,import}` in crates/linscp-service/src/lib.rs.

**Next:** The script-level export and import path is evidenced by engine-script; the backup bundle itself is evidenced by the backup suite on all three platforms.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Extend the runnable residue (backup) to Android, or cite additional runnable suites there.

## desktop.remote

**Area:** Desktop integration · **Status:** partial

RDP/VNC/SPICE support direct TCP (3389/5900), SSH jump SOCKS5h relays, and on-demand loopback SSH port forwarders (/api/desktop/launch tunnel_via_ssh + /api/desktop/tunnel-close), including Android external viewer launch with foreground keepalive. The built-in experimental X2Go KDrive viewer supports session listing, resume, suspend, termination, server cursors, live window resize, and opt-in clipboard sync (/api/x2go/{sessions,open,poll,input,clipboard,suspend,terminate,close}).

**Next:** Live desktop server validation (xrdp, TigerVNC, SPICE, and live X2Go KDrive server) and gateway security review remain open.

**Acceptance criteria:**

- [ ] Live RDP launch with xfreerdp/mstsc against a throwaway RDP stub verifies argv, port 3389, TLS/NLA option, and jump-host SOCKS5h relay without exposing credentials (live-desktop).
- [ ] Live VNC (5900) and SPICE (5900/.vv) launches verify viewer resolution (tigervnc/remote-viewer), TLS port, and headless .vv/.rdp ticket generation (live-desktop).
- [ ] Implement and test a built-in X2Go KDrive viewer on Linux, Windows and macOS, including graphics, input, SSH forwarding, and safe session lifecycle. Separately test X11/Waypipe launches and jump-host policy (live-desktop).
- [ ] Obtain independent review that ironrdp WASM / Guacamole gateway fallback correctly isolates credentials and that XDMCP (UDP 177) remains refusing/not recommended.

## platform.android-saf-synchronization

**Area:** Packaging/platforms · **Status:** partial

Synchronization with a granted local side plans and applies through LocalFs: the planner walks the tree through the bridge, checksum criteria stat each document fresh and refuse an over-cap file naming it before its bytes are read, downloads land in a private stage and publish across the bridge replacing like the plain path, and uploads stage the granted source and run the guarded upload unchanged from the stage. Granted-side deletions stay lenient; keep-up-to-date cannot watch a content:// tree, so it polls it on the interval instead. The page offers both dialogues for granted folders.

**Next:** Host-side mock-bridge tests cover a second timed polling pass and cancellation, but no suite has planned against or published into a real DocumentsProvider. Provider behavior (mtime fidelity after a publish, nested document URIs, large-tree walk time, and polling cadence) remains unproven on a device.

**Acceptance criteria:**

- [ ] Synchronize both directions with delete against a granted folder on an Android device or emulator, covering a checksum comparison, the over-cap refusal and one keep-up-to-date pass.

## Cross-cutting release gate

Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, report dependency skips, and update the ledger and generated reports. `python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. The normal checker validates consistency, not behavioral parity.
