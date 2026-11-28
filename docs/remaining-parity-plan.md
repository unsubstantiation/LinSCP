# Remaining parity implementation plan

> **Scope:** Historical upstream and CLI references are retained for comparison; removed CLI interfaces are not planned for restoration.

Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. It is a comparison with upstream, **not a completed parity claim**; the current product is GUI-only.

45 tracked capability gaps. Some require development, others require evidence or a scope decision; recording a plan does not satisfy its tests. See [feature development triage](feature-development-triage.md).

Regenerate with `python3 tools/check_upstream_parity.py --write-report`.

## scp.curl-file-transfer

**Area:** SCP · **Status:** partial

SCP single files use native SSH exec and scp -f/-t wire framing. Engine tests exercise file transfers and a tree walked file by file against a mock SSH/SCP server. The GUI adds protocol-specific safety refusals; engine tree-walk support does not imply every GUI SCP directory operation is allowed. SCP resume is refused. The historical CLI-dependent live suite does not run in the GUI-only distribution.

**Next:** Recursive SCP D/E wire streams are not implemented. They are deferred pending demonstrated product need and a design for untrusted records, containment, no-overwrite, symlinks, bounds, cancellation and partial-tree cleanup; no recursive stream or real-server GUI interoperability is claimed.

**Acceptance criteria:**

- [ ] If recursive wire SCP is prioritized, implement and test nested D/E streams with malicious-server, containment, interruption and live OpenSSH coverage without weakening GUI safety refusals.

## transfer.ascii-automatic

**Area:** Transfers · **Status:** partial

The ASCII mode converts the line endings, the binary mode keeps the bytes, and the automatic mode converts the files its mask names and leaves the others alone. A download is converted to the local native end of line unless '-eol=' names another one; an upload is converted to CRLF unless '-eol=' says otherwise. Fresh ASCII uploads can use server-enforced exclusive creation or an ETag precondition; acknowledged SFTP and FTP staged publication convert before staging; the FTP rename remains explicitly acknowledged as non-atomic and racy.

**Next:** Linux and Windows CI exercise exclusive and staged SFTP, staged FTP and ETag-conditional WebDAV ASCII uploads using loopback fixtures, including guard refusals. Android-device behavior and live third-party server behavior remain unverified. The upstream live WebDAV suite requires a CLI binary this GUI-only build does not ship.

**Acceptance criteria:**

- [ ] Exercise Android-device behavior where applicable.
- [ ] Cover remaining desired live-server behavior without depending on the removed CLI.

## transfer.filepart-resume

**Area:** Transfers · **Status:** partial

Downloads can stage in a `.filepart` file beside the destination and resume from that staging file. A mid-flight interruption test verifies the old destination remains untouched, the partial survives and the resumed download is published. SFTP and FTP guarded uploads do not provide this `.filepart` resume behavior; their acknowledged staged publication requires a fresh copy. The GUI verified-resume path compares the checkpoint against remote bytes before resuming and publishes without replacing an existing destination. Ordinary SFTP resume now compares an existing prefix before continuing or adopting a destination, and refuses unsafe, complete, or oversized existing stages rather than deleting them. Ordinary FTP resume also compares the saved prefix before modifying local files; FTP verification drains the full remote file with bounded memory and retains the control connection on mismatch. Ordinary WebDAV and S3 resumes compare the prefix under a strong ETag and use the same condition for the remaining download. Versioned S3 resumes additionally send the version ID and require the server to confirm it on HEAD and each conditional GET; versioned source deletion is refused. FTP/SFTP partial reuse is refused unless the user explicitly accepts best-effort resume for that transfer. The GUI warns that concurrent changes can corrupt the result, and the engine independently enforces the opt-in. Ordinary and GUI resume copy checkpoints into owner-restricted temporary directories and verify the copy; they do not mutate or publish the shared checkpoint, which remains after success or failure. Their pathname-based publication still requires a trusted destination directory and ancestors. ASCII-converted resume and complete or oversized direct partials are refused. The S3 versions dialog offers opt-in verified resume to a new destination, with version-scoped checkpoints; the Linux S3 service fixture exercises an older version, stale partial refusal, and no-overwrite behavior. Granted-folder resume remains unsupported. WebDAV conditional prefix and download responses must return the expected ETag; missing or mismatching tags fail before bytes are written. A Linux service fixture verifies refusal when a WebDAV server ignores If-Match but reports a changed tag. A packaged Android debug APK emulator smoke checks successful WebDAV resume, stale-prefix refusal, and refusal after the source changes while a task is paused; it verifies rejected checkpoints remain intact and no destination appears. The emulator also uses a disposable Paramiko SFTP server to confirm default refusal, successful explicit best-effort resume, and stale-prefix refusal without changing the checkpoint or publishing a destination. This does not make SFTP snapshots atomic. The packaged API 35 x86_64 Android emulator scenarios were rerun successfully with later code in branch run 46124619130; coverage is limited to the specific scripted provider and operations.

**Next:** Linux and Windows loopback CI exercise stale FTP/SFTP/WebDAV/S3 prefixes and conditional WebDAV/S3 source changes. FTP/SFTP resume is best-effort only with explicit per-transfer approval: size/mtime checks cannot pin an atomic snapshot, and concurrent remote or local modifications can still corrupt a result. WebDAV/S3 conditional behavior requires a conforming server, and WebDAV endpoints that omit ETags on conditional GETs are refused; versioned resume is not available for Android granted folders. Resume publication still requires a trusted local destination directory and ancestors; a process with the same account privileges can modify the private stage or destination. Guarded SFTP/FTP uploads still cannot resume; physical Android devices, Android granted-folder resume, and live third-party server behavior remain unverified; the emulator uses a disposable SFTP fixture.

**Acceptance criteria:**

- [ ] Consider stronger protections for concurrent local and remote changes; FTP/SFTP cannot provide atomic snapshots and best-effort resume requires explicit consent.
- [ ] Implement safe resumable guarded uploads, or document protocol-specific refusals and alternatives.
- [ ] Exercise Android-device and relevant live-server behavior without the removed CLI.

## transfer.resume-modes

**Area:** Transfers · **Status:** partial

The internal interpreter parses automatic/on/off and per-transfer -resumesupport thresholds. Mock SFTP tests drive the interpreter through resume-off, a per-transfer off override, below/at-threshold staging, and an on-mode refusal when an existing unapproved checkpoint is present. They also verify an existing checkpoint is never altered. FTP/SFTP continuation without an atomic snapshot is refused by default; explicit per-transfer best-effort approval is required where exposed. The GUI-only distribution does not expose the historical script CLI. The packaged Android emulator exercises GUI SFTP resume with a disposable server: risk confirmation, explicit opt-in, successful continuation and stale-prefix refusal.

**Next:** Linux and Windows host tests exercise option propagation and checkpoint preservation against a mock SFTP server; the packaged emulator additionally exercises the GUI resume safety path against a disposable Paramiko SFTP server, but the internal interpreter modes, physical devices and third-party servers remain unverified. The historical live-sftp suite requires a CLI binary this distribution does not build.

**Acceptance criteria:**

- [ ] Validate the supported GUI workflows and safety behavior on Android and against real servers; do not claim the removed CLI interface is shipped.

## transfer.presets

**Area:** Transfers · **Status:** partial

Named, per-site and rule-selected presets change transfer settings. The queue refuses an unreadable or malformed preset store and a missing site preset rather than silently using defaults; explicit preset opt-out bypasses the store, and site-level opt-out does not fall through to matching rules. The GUI distinguishes automatic matching from explicit manual opt-out, persists the selection, and keeps a missing saved preset visibly selected instead of silently switching it to automatic. Host service tests exercise filtering and refusals, while a packaged Android emulator verifies an explicitly named mask, deleted preset refusal, and mixed per-file automatic matching against a disposable WebDAV server. Explicit transfer settings override preset fields; untouched GUI defaults inherit them. Automatic matching evaluates each selected top-level item, combines filename and session rules, and prioritizes filename rules over session-only rules. Saved override markers retain explicit default-valued settings; old preferences infer non-default overrides. See docs/transfer-presets.md for precedence and migration. The packaged API 35 x86_64 Android emulator scenarios were rerun successfully with later code in branch run 46124619130; coverage is limited to the specific scripted provider and operations.

**Next:** The packaged Android emulator verifies a named mask and mixed automatic-matching rules against the WebDAV fixture (run 46045911600). Per-site selection and every transfer setting are not exercised on physical Android devices or third-party servers. The historical live-dav suite needs the retired CLI. GUI manual transfer settings can override preset settings, and physical devices remain unverified.

**Acceptance criteria:**

- [ ] Exercise per-site presets and transfer-mode and permission settings on Android and against relevant live servers.
- [ ] Clarify and test precedence between manual settings and automatic preset values.

## transfer.curl-progress

**Area:** Transfers · **Status:** partial

The HTTP-backed downloads and uploads report the bytes as they move: the byte-progress callback is told what has been transferred and how much there is, while the transfer runs, and a download that stages its bytes writes them to the `.filepart` file first. Upstream reads the same numbers out of curl's progress meter and renders them live in the terminal; this build has no curl meter and no live percentage line, so that half of the upstream claim is not implemented here.

**Next:** The upstream half is still unevidenced: live-curl needs a `linscp` binary this repo does not build, and unit has no build target and cannot be compiled. Runnable residue: proto-dav-s3, which reports the byte progress of an upload and of a download while they run. The live percentage line is not implemented in this build.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Render the transfer progress as a live percentage line in the terminal, the way upstream does.

## sync.one-way

**Area:** Synchronization · **Status:** partial

One-way synchronization can preview and queue recursive uploads and downloads; host tests cover mock SFTP and loopback WebDAV. A packaged Android emulator covers synchronization in both directions through an external-storage DocumentsProvider and WebDAV.

**Next:** The loopback WebDAV upload and mock SFTP cases do not establish compatibility with production servers, other Android providers, or physical devices. Windows service evidence uses the mock provider; the live WebDAV case is Linux-only.

**Acceptance criteria:**

- [ ] Exercise one-way synchronization on production-like servers and other Android providers and physical devices.

## sync.keepuptodate-inotify

**Area:** Synchronization · **Status:** partial

Keep-up-to-date uses filesystem notifications with polling fallback for native roots and polls granted Android folders. An event received during the initial pass is retained so a subsequent pass can discover changes not in its initial snapshot.

**Next:** Linux and Windows host tests exercise native watcher and fallback; the packaged Android emulator exercises interval polling and cancellation with the external-storage provider. Other providers, physical devices and broader live-server behavior remain unverified.

**Acceptance criteria:**

- [ ] Exercise long-running watcher and polling behavior with other providers, real servers and physical devices.

## sessions.site-manager

**Area:** Sessions/configuration · **Status:** partial

Stored sites can be saved, renamed (including nested folders), filtered, sorted by name or last-connected timestamp (last_used), opened, removed, exported and imported. A packaged Android emulator exercises nested folder and site rename, conflict refusal, reconnection with retained credentials, scoped site/folder deletion and persistence of deletions after restart against a WebDAV fixture.

**Next:** Android emulator coverage now includes rename, connection and site/folder deletion through the packaged app, but not site import/export, filter/sort interaction or physical devices. Linux and Windows exercise the service and GUI with host tests.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## sessions.password-at-rest

**Area:** Sessions/configuration · **Status:** partial

The native service encrypts saved session metadata in an authenticated vault envelope and encrypts site secrets with a data key wrapped in sessions.key by the local password vault. A locked vault refuses access. On Windows the configuration directory is additionally owner-only: ensure_private_dir applies D:P(A;OICI;FA;;;OW), inherited by children. Legacy compatibility does not imply that the retired CLI or Python client can read the current vault format. A packaged Android debug APK emulator test checks setup, Keystore envelope and sealed site metadata, explicit lock, process restart, wrong-password refusal and successful reconnection using recovered saved credentials. The emulator also independently corrupts the Keystore-wrapped key and sealed site store, verifies unlock and save refusal, compares both on-disk files byte-for-byte after each failure, and reconnects after restoring the originals.

**Next:** Linux and Windows host tests cover vault sealing, reopen, wrong-password and tamper refusal and preservation, migration, and redaction. The Android emulator covers setup, lock, restart, wrong-password refusal, Keystore wrapping, separate key and site-store corruption refusals with file preservation, and saved-site credential recovery. Physical-device behavior and compatibility with retired Python/core clients remain unverified; the old live-sftp suite requires a CLI binary this distribution does not build.

**Acceptance criteria:**

- [ ] Exercise vault lifecycle and tamper refusal on physical Android devices, including different Keystore implementations.
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

## security.proxy-isolation

**Area:** Security/authentication · **Status:** partial

The current Rust proxy tests reject a no-auth downgrade when SOCKS credentials are configured and confirm a refused HTTP CONNECT is not retried directly. A loopback mock SSH bastion test checks independently pinned jump authentication, rejects unauthenticated and wrong-password local SOCKS clients, and uses reqwest successfully through the authenticated relay. Linux and Windows passed GitHub Actions run 46108545284; proxy bypass is evaluated on the actual network hop and loopback detection requires a real loopback IP. User-configured localhost and exclusion bypasses are intentional. Historical live-sftp and live-dav tests below require a retired binary and do not supply current evidence.

**Next:** Mock SSH jump, authenticated SOCKS relay, failed HTTP CONNECT and bypass regressions now run on Linux and Windows. Broader live protocol and Android proxy coverage is still needed; the historical live-dav and live-sftp suites require a retired binary.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.

## security.gui-api-token

**Area:** Security/authentication · **Status:** partial

Static configuration tests verify that packaged capabilities do not grant remote origins and that CSP connect-src names only Tauri IPC; inline scripts remain permitted and this is not a runtime IPC-isolation proof. The native GUI calls the service in-process through Tauri IPC rather than a separately configured local HTTP API. The webview has access to privileged commands: content injection in it could drive the service. The page escapes tab and transfer text, binds tab-close actions without interpolating IDs, rejects malformed queue IDs, and validates numeric progress before inserting it into markup. These defenses do not establish isolation from other local processes or rule out other injection paths. A packaged Android debug APK emulator test checks a hostile-looking filename returned by the real native IPC listing, plus injected malformed tab and transfer-queue data, renders as inert text in the WebView. An idle packaged Linux GUI was checked via procfs in CI: it owned only its private loopback activation listener, whose record had private permissions; an HTTP request and a wrong activation token received no reply. This is a point-in-time process-level smoke, not proof about child processes, every runtime state, same-user access or Tauri IPC isolation.

**Next:** The idle Linux package smoke sees no GUI-process HTTP listener, but does not audit child processes or active sessions. The Android WebView smoke covers file-pane rendering from a real IPC listing and injected tab/queue data; neither establishes IPC isolation. Desktop GUI rendering cases use jsdom with a mock backend. Tauri IPC accessibility to other local processes, other rendering surfaces, untrusted web content and physical-device behavior need security validation.

**Acceptance criteria:**

- [ ] Exercise packaged desktop and Android IPC boundaries, including attempts from untrusted web content and local processes.
- [ ] Audit and test the remaining untrusted-data rendering surfaces, and validate the absence of any unintended API listener in the shipped application.

## security.gssapi-and-tunnels

**Area:** Security/authentication · **Status:** partial

SSH jump-host support is tracked separately under security.ssh-jump-hosts. The current Rust SSH transport uses russh's gssapi-with-mic bridge and a system Kerberos context provider: Linux dynamically loads libgssapi_krb5 and Windows loads SSPI from System32. Android has no system provider here. GSSAPI authentication can be attempted when a provider is available; delegation is opt-in. GSSAPI key exchange is not implemented and explicit requests fail closed. The historical isolated MIT KDC and cross-realm cases in LiveSftpTest.py require the retired linscp CLI and are not runnable against the shipped GUI-only distribution. Windows SSPI loader/context construction has a platform unit test, but that does not establish successful Kerberos authentication. GUI and service-tabs tests cover settings and capability/refusal policy, not a live KDC exchange.

**Next:** An isolated Linux MIT KDC and OpenSSH fixture now tests the current russh path with a missing cache, wrong service principal, successful mutually authenticated login, default-off and opt-in delegated credentials, in GitHub Actions run 46108545284. Expired tickets, cross-realm trust, production KDC behavior and Windows SSPI end-to-end authentication remain unverified. Android has no provider; GSSAPI key exchange and jump-host GSSAPI are unsupported; independent delegation security review remains open.

**Acceptance criteria:**

- [ ] Port isolated-realm and cross-realm GSSAPI tests to a supported service or Rust harness; exercise Linux principal selection, missing/expired credentials, mutual authentication and default-off versus opt-in delegation with no silent skips.
- [ ] Exercise the existing Windows SSPI provider end to end against an AD or Samba KDC, including failures and delegation policy; address any implementation gaps before claiming Windows Kerberos interoperability.
- [ ] Obtain an independent security review of delegated TGT handling and validate production KDC behavior; decide separately whether unsupported GSSAPI key exchange is in product scope.

## security.gui-account

**Area:** Security/authentication · **Status:** partial

The shipped native service is single-user and does not implement account login, per-user isolation, CSRF sessions, or a home-directory jail. GET /api/login reports accounts disabled, POST /api/login refuses, and logout is a compatibility no-op, even if a legacy accounts.ini is present. The backup preserves that file but does not enable accounts. Do not expose this dispatcher as a multi-user server or rely on it to isolate mutually untrusted users; use separate OS accounts and an appropriate security boundary.

**Next:** The former server-deployment account system is not shipped. Host tests establish the native compatibility responses and lack of an account authorization gate; they do not test a server, per-route isolation, or Android device behavior.

**Acceptance criteria:**

- [ ] If multi-user server deployment is desired, first define its security boundary and restore or replace account authentication and authorization, including per-route negative tests and isolation. Otherwise retain the explicit single-user limitation.

## gui.native-path-drop

**Area:** GUI · **Status:** partial

Native Tauri drops register a numeric transformCallback ID and carry physical pointer coordinates for CSS-pixel pane hit-testing; jsdom exercises that event contract and right-pane routing; missing coordinates fall back to the focused pane. The backend treats source_paths as authoritative instead of duplicating source_path, and rejects top-level names with surrounding whitespace rather than silently renaming them. Native filesystem upload drops, including a single file, stream to private bounded per-drop staging; errors remove the whole batch. Local file copies and SAF-URI drops can still read a whole file into memory. Android sharing instead stages content URIs and publishes one shell-upload manifest per file. Pending paths survive a failed manifest write and process restart, and concurrent manifest consumers claim by rename. Shared items are queued through /api/shell/consume, not the native-drop conflict dialog; refusals are reported and consumed refusals are not retried automatically. The packaged emulator test uses an explicit SEND of a granted external-storage document, forces publication failure, restarts the process, and verifies the recovered manifest and bytes; it also checks partial staging cleanup after an invalid second URI. This is not an exactly-once guarantee; see docs/native-android-integration.md. Windows final-review run 46124619141 passed an isolated Explorer action smoke; it did not exercise a real OS drag.

**Next:** Real desktop OS drag delivery, Android share-sheet resolution and SEND_MULTIPLE, upload conflict behavior, files larger than memory and physical devices remain unverified. The share hand-off is not transactional or exactly once; local and SAF drop copies may buffer complete files.

**Acceptance criteria:**

- [ ] Drive a real WebKit/GTK drop onto the native window and show the queued task names the dropped paths (the shell's `dragDropEnabled` handler cannot be exercised by jsdom).
- [ ] Exercise the existing generated Android SEND/SEND_MULTIPLE filters end to end with a shared file, including the conflict question and queue entry.
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

The optional GUI XML action log uses the upstream session namespace and operation-shaped elements. Queue and direct GUI records serialize with one in-process lock per complete record; a transfer does not hold the lock across network awaits. Incomplete existing logs lacking the expected closing tag are preserved rather than overwritten; preview reads a bounded tail. Tests validate interleaved GUI and queue records against the project-authored pinned schema on Linux. The standalone -xmllog CLI is not shipped. See docs/remaining-parity-priorities.md for supported scope and failure boundaries. Focused Linux/Windows Rust tests and Linux GUI plus live WebDAV schema checks passed in branch run 46123944392. Full Linux final-review checks including loopback WebDAV and schema validation passed in run 46124619208. Windows full workspace tests passed in final-review run 46124619141.

**Next:** The schema is derived locally from the pinned upstream emitter, not independent proof of full upstream or consumer compatibility. Linux live WebDAV upload/download and GUI service samples are schema-checked; other real-server operations and Android schema behavior remain unverified. Logging is best-effort and errors can be silent; concurrent external writers, crashes and I/O failure can still cause loss or malformed logs. Secret redaction is not exhaustive.

**Acceptance criteria:**

- [ ] Validate additional supported GUI operations and failures against real protocol fixtures and independent consumers.
- [ ] Improve logging error visibility and crash/interprocess handling before treating it as a reliable audit trail; test Android where applicable.

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

The GUI can parse a manually pasted session URL through /api/session/url, including FTPS variants and escaped paths. Invalid URL diagnostics do not echo input, because URLs may contain credentials. The Debian desktop entry advertises selected transfer URI handlers and passes a URL to the native launcher. Cold launches and authenticated running-instance delivery place URLs in a bounded in-memory queue, and the main window offers them for explicit review without connecting automatically. URL text is not stored in the instance endpoint file or printed in argument Debug output. Split URL arguments cannot invoke one-shot actions. Windows users can opt in to per-user URL registration without changing existing defaults; Windows Settings selects the handler. Registry tests use isolated keys, and Windows CI drives install and uninstall through the built binary. Linux and Windows platform tests cover authenticated delivery, bad-token refusal and queue limits; jsdom covers modal deferral and review. A local GIO test selects an isolated XDG default and launches the installed custom-prefix entry with an escaped URI; its executable is a capture stub, not the real GUI. See docs/native-android-integration.md for the remaining boundary.

**Next:** The Debian entry declares transfer URI handlers and the native launcher offers URLs for review. Actual selection and end-to-end launch through desktop defaults, Android deep links, and comprehensive untrusted-URL security validation remain unverified; Windows registration is opt-in rather than a default change.

**Acceptance criteria:**

- [ ] Validate end-to-end URI delivery and default selection on real desktops, including untrusted URLs, credential handling, confirmation and host-key validation; implement registration on other intended platforms.
- [ ] Test launching a registered URI through the actual desktop or device.

## desktop.launcher-prefix

**Area:** Desktop integration · **Status:** partial

The native GUI embeds its frontend and engine in one executable; there is no separate core to locate. Make and CMake now generate a desktop entry targeting the runtime prefix instead of PATH; a GIO test launches a stub with a URL from a special-character prefix. Native desktop menu and default-handler selection remain untested. Linux CI also launched the real custom-prefix GUI via its desktop entry using GIO and an SFTP URL, with the prefix absent from PATH. An isolated XDG configuration selects the generated entry as the default SFTP handler; GIO discovers it and passes the URL to a stub without PATH lookup.

**Next:** The historical separate-core launcher no longer exists; desktop menu resolution and scheme selection at a custom prefix have not been tested. The old Python tests require the retired CLI.

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Drive the protocol cases from a binary this repo builds, or port them to Rust tests over the existing mock fixtures.
- [ ] Write a suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.

## desktop.wayland-session

**Area:** Desktop integration · **Status:** partial

The Linux platform detects Wayland from nonempty WAYLAND_DISPLAY or XDG_SESSION_TYPE=wayland, then X11 from nonempty DISPLAY, otherwise headless. The native Tauri/WebKitGTK GUI is launched directly by the desktop entry. The Wayland compatibility suite checks source shape, not compositor behavior. The old C++ console and browser launcher are not the shipped GUI. The pure environment classification test ran on Linux in branch run 46120074371. An installed Debian package was launched on a real headless Weston compositor with DISPLAY unset and GDK_BACKEND=wayland; the test observed a LinSCP xdg-toplevel title, configuration acknowledgement and surface commit, and checked native listeners (branch run 46121989363). It used the package artifact built in run 46120074436, not a fresh build. The full Linux final-review package job also passed its fresh-build Weston smoke in branch run 46124619208.

**Next:** A basic headless Weston launch is tested, but full desktop environments, user interaction, clipboard, drag-and-drop, DPI, XWayland interoperability and other compositors are not verified. Protocol logging does not validate rendered pixels.

**Acceptance criteria:**

- [ ] Exercise native GUI and terminal selection on full supported Wayland compositors and X11, including mixed XWayland sessions, scaling, rendering and native desktop interactions.

## locale.translations

**Area:** Localization/accessibility · **Status:** partial

English, Spanish, German and French catalogs are embedded for the native GUI and internal engine. Automated catalog, placeholder and GUI tests cover selected messages and locale behavior; they do not prove human translation quality or cover every dynamic diagnostic. Server/OS diagnostics and protocol data can remain untranslated. The standalone CLI is not shipped. Additional languages should be prioritized with community demand and human review; adding one requires registering it in Rust and assessing plural rules, RTL and input behavior.

**Next:** Only four catalogs ship. Other upstream languages are not supported; the current singular/other API cannot express every CLDR plural category. User-facing dynamic errors and real-device/assistive-technology behavior require further review.

**Acceptance criteria:**

- [ ] Choose additional languages based on user demand and maintained human review; register and test any new catalogs and expand plural/RTL support when needed.
- [ ] Validate supported GUI strings and accessibility in real platform workflows; do not imply untranslated protocol data or server diagnostics are localized.

## platform.make-linux

**Area:** Packaging/platforms · **Status:** partial

source/linux/Makefile wraps the native Tauri build and installs the GUI, desktop entry and icons under PREFIX (default /usr), optionally staged under DESTDIR. The Debian CI distribution suite runs the install recipe with an isolated stub binary and checks custom paths, default paths and permissions. A Linux CI run built via Make, staged under a custom prefix and opened the resulting GUI under Xvfb; the Debian workflow repeats this smoke. There is no CLI in this distribution. The desktop entry now names the runtime prefix, not DESTDIR or the session PATH; GIO launches a stub from a prefix with spaces and special characters. Linux CI also launched the real custom-prefix GUI via its desktop entry using GIO and an SFTP URL, with the prefix absent from PATH. An isolated XDG configuration selects the generated entry as the default SFTP handler; GIO discovers it and passes the URL to a stub without PATH lookup.

**Next:** The supported Linux GUI build and staged launch are exercised, but desktop menu discovery and scheme-handler selection under a custom prefix are unverified. The former console client is not shipped.

**Acceptance criteria:**

- [ ] Validate desktop menu discovery and scheme-handler selection from a custom-prefix install.
- [ ] Do not claim the retired console client is installed.

## platform.cmake-linux

**Area:** Packaging/platforms · **Status:** partial

CMake wraps the native Tauri build, registers Rust and UI CTest entries, and installs the GUI, desktop entry and icons using CMAKE_INSTALL_PREFIX and DESTDIR. A Linux CI run built with CMake and opened the staged GUI under Xvfb; the Debian workflow repeats this smoke. A distribution test also exercises a custom prefix containing spaces with a stub executable. The retired CLI and man page are not installed, and CMake does not explicitly reject non-Linux hosts. The desktop entry is generated at install time using the effective runtime prefix, including cmake --install --prefix, independent of DESTDIR or the session PATH. Linux CI also launched the real custom-prefix GUI via its desktop entry using GIO and an SFTP URL, with the prefix absent from PATH. An isolated XDG configuration selects the generated entry as the default SFTP handler; GIO discovers it and passes the URL to a stub without PATH lookup.

**Next:** The native Linux build and staged GUI launch are covered, but desktop menu discovery and scheme-handler selection from a custom prefix are unverified. CMake registers CTest entries, but this smoke does not execute them. The upstream console client is not shipped.

**Acceptance criteria:**

- [ ] Exercise desktop menu discovery and scheme-handler selection for a custom-prefix install and run the registered CTest entries.
- [ ] Do not claim the retired CLI is installed.

## platform.debian-package

**Area:** Packaging/platforms · **Status:** partial

debian/rules and debian/control build a native GUI-only package with its desktop entry, icons and documentation. Linux CI builds the actual package, checks its contents, installs it and launches a window under Xvfb. A branch run passed these checks; an earlier run built and installed successfully but failed the GUI smoke without enough diagnostic output, so launch reliability is not established. The retired CLI and its man page are not packaged. CI also defines a synthetic same-payload older-version upgrade, removal and purge test; this is not a migration test from a historical release. Shell integration is per-user and is not removed by dpkg. The package job in branch run 46120074436 passed the synthetic upgrade, removal, purge and custom-prefix GIO/Xvfb smokes on Ubuntu 24.04. The separate general-check job failed on temporary workflow trigger policy; it is not evidence. The full final-review package job passed again in branch run 46124619208.

**Next:** A same-payload synthetic version upgrade and removal passed on Ubuntu 24.04; migration from a historical release, real desktop menus/default selection and other Debian environments remain unverified. An earlier GUI-launch smoke failed without enough diagnostics; one later run does not establish reliability. The upstream CLI is deliberately omitted.

**Acceptance criteria:**

- [ ] Investigate the intermittent launch-smoke failure and exercise package upgrade/removal and desktop integration on supported Debian environments.
- [ ] Do not claim the retired console client is shipped.

## platform.prefix-lookup

**Area:** Packaging/platforms · **Status:** partial

The GUI embeds its engine and does not look up a separate PREFIX/bin/linscp core. The Make and CMake installers generate desktop entries pointing to the effective runtime prefix; DESTDIR is excluded. A GIO test launches a stub with a URL without the prefix on PATH. Linux CI also launched the real custom-prefix GUI via its desktop entry using GIO and an SFTP URL, with the prefix absent from PATH. An isolated XDG configuration selects the generated entry as the default SFTP handler; GIO discovers it and passes the URL to a stub without PATH lookup.

**Next:** The separate-core prefix lookup described by the retired Python harness is not part of the GUI-only product. Desktop menu and scheme-handler discovery under a custom prefix remain unverified.

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

LinSCP ships Linux, Windows and Android hosts. The legacy Linux conversion guard checks selected repository text and Linux packaging for retired constructs and installer-list drift; platform-specific host code and fixtures are intentionally excluded. It reports selected text that cannot be read as UTF-8 rather than silently passing an incomplete scan. It runs in 'make -C source/linux check', as the CTest case 'platform-conversion-check', and in Linux CI. This repository-state check does not certify Windows or Android runtime behavior or conversion of every file.

**Next:** Runnable evidence exists on Linux only (platform-conversion); Windows and Android have none (see the suite registry).

**Acceptance criteria:**

- [ ] A suite that executes in CI on Linux, Windows and Android covering the stated behavior, with its cases named in checks and cited per platform in verified_on.
- [ ] Extend the runnable residue (platform-conversion) to Windows and Android, or cite additional runnable suites there.

## platform.android-saf-editing

**Area:** Packaging/platforms · **Status:** partial

Opening, saving and reading properties in a granted Android folder go through LocalFs to the SAF bridge instead of the refusal: the editor reads the document bytes, saves create-or-replace the document, and properties rows carry the bridge's stat, on the main pane and on a granted other pane alike. The stale-save guard compares at the bridge's seconds precision, the same granularity remote saves use. A save whose stat fails proceeds to the bridge write, because a missing document and an unreadable one are indistinguishable there and the write creates what is missing; a genuinely broken write still surfaces its own error. The page offers the editor for granted folders again; chmod and other unsupported operations retain named refusals (see platform.android-saf-refusals); transfers, copy/move and polling are tracked separately. Android whole-document and chunked reads resolve documents inside the I/O error handler, so provider resolution errors are reported through the bridge rather than escaping the worker setup. A packaged Android emulator test obtains a real shared-storage folder grant through DocumentsUI, lists and reads an existing file, refuses a stale editor save, edits and creates files, checks file properties and the edited bytes outside the app, and reopens the granted folder after a process restart. Structured SAF editor URIs must name an immediate child of the active pane; host tests cover both panes and the emulator tests a sibling read/write refusal. The Android bridge resolves document IDs against each parent listing rather than querying arbitrary descendant IDs directly, and retains structured parent paths across staged writes. A packaged emulator checks that a direct child ID works and a flattened descendant ID is refused, as well as nested files named document. This relies on the provider reporting truthful child listings. The packaged API 35 x86_64 Android emulator scenarios were rerun successfully with later code in branch run 46124619130; coverage is limited to the specific scripted provider and operations.

**Next:** The emulator exercises the Android external-storage DocumentsProvider for a single granted folder, including stale-save refusal and grant persistence. The descendant-ID refusal is exercised with the Android external-storage DocumentsProvider; opaque-ID providers, directory properties, revoked access races, large documents and physical-device behavior remain unverified.

**Acceptance criteria:**

- [ ] Validate provider-aware containment and properties with opaque-ID providers, and test revoked permissions and large files on different DocumentsProviders and physical Android devices.

## platform.android-saf-local-copy-move

**Area:** Packaging/platforms · **Status:** partial

Local copies and moves with a granted end run on LocalFs in the queue worker: bytes cross the bridge between plain and granted panes and between two granted trees, with the same conflict policies as plain pairs. Every granted move is a copy that deletes its source (queue jobs always carry the same leaf on both sides, so a provider-side rename could only retarget a name onto itself); same-directory renames stay on the rename endpoint, which renames directly. Files over the 64 MiB document cap refuse at enqueue time and in the worker naming the file; symbolic links refuse by name; a plain target keeps the source's seconds while a granted target gets fresh stamps, and directory copies walk nested files through the bridge. The page offers transfers and moves on local tabs and still gates session transfers and moves on remote tabs. Chunked 1 MiB SAF streaming (readUriChunk/beginWriteUri/appendUriChunk and LocalFs::copy_streamed) avoids whole-file Base64/JSON heap spikes. A packaged Android emulator exercises a real external-storage provider for a nested copy from a granted folder into app storage, a move from app storage into a grant, and an existing-destination move refusal that preserves both files. The emulator also refuses a provider file one byte above the 64 MiB cap when copying it into app storage, preserving the source and leaving no destination. The packaged API 35 x86_64 Android emulator scenarios were rerun successfully with later code in branch run 46124619130; coverage is limited to the specific scripted provider and operations.

**Next:** The emulator covers the external-storage DocumentsProvider in one granted tree, including nested copy, over-cap copy refusal and a move conflict. Two separate granted trees, other providers, large-document memory pressure, concurrent-creator races and physical devices remain unverified.

**Acceptance criteria:**

- [ ] Exercise copy and move between two separately granted trees, including name conflicts, document-cap refusals and concurrent-creator races; repeat representative cases with other providers and physical devices.

## platform.android-saf-session-transfers

**Area:** Packaging/platforms · **Status:** partial

Session transfers with a granted local side stage through private temporary files in the queue worker: uploads stage the granted source (keeping its seconds, so the remote keeps its stamps) and run the guarded upload unchanged from the stage; downloads land in a stage and publish across the bridge file by file. Trees stage and publish whole in both directions; merges add to an existing granted tree without replacing any file and fail instead of replacing. Files over the 64 MiB document cap refuse at enqueue time naming the file; verified resume refuses for granted folders, since the bridge has no appends or partial files; WebDAV moves delete the remote source by ETag after the staged download publishes. The page offers transfers for granted folders on both tab kinds and selected move directions. Moving from a granted folder to a remote session is refused because the provider bridge cannot conditionally delete an unchanged source; copy and verify before manually deleting. Staging and publication stream in 1 MiB chunks via LocalFs::stage_to_file and LocalFs::publish_from_file. A packaged Android emulator test uses a DocumentsUI grant and a WebDAV fixture to upload, download, move, protect an existing destination, refuse verified resume, and transfer nested trees in both directions after explicit WebDAV directory-copy risk confirmation. The emulator refuses upload of a provider file one byte above the cap and preserves it. It also refuses download and move of an over-cap WebDAV file before queueing, leaving no provider document and preserving the remote source. A WebDAV-to-provider tree merge requires confirmation, adds a new file, and refuses an overlapping merge without replacing the existing provider file. The emulator also exercises provider-to-WebDAV merge confirmation, addition and refusal to overwrite an existing remote file. The packaged API 35 x86_64 Android emulator scenarios were rerun successfully with later code in branch run 46124619130; coverage is limited to the specific scripted provider and operations.

**Next:** Single-file transfers, move, nested tree upload/download, tree merges in both directions and over-cap upload, download and move refusals are exercised on an Android emulator with the external-storage DocumentsProvider and a WebDAV fixture; other providers, large-document memory pressure, concurrent writers and physical devices remain unverified.

**Acceptance criteria:**

- [ ] Extend the existing emulator transfer and cap-refusal coverage to other document providers, large-document memory pressure, concurrent writers and physical devices; keep granted-folder resume refused until safely supported.

## editing.non-utf8-encodings

**Area:** Editing/search · **Status:** partial

CLI and browser editor support explicit legacy encodings with strict decoding and encoding, line-ending and BOM controls. When opening undecodable text the browser offers an encoding retry; content search accepts an encoding and skips binary or undecodable files. Remote editor and search downloads are bounded by streamed bytes, not just server-reported sizes.

**Next:** Linux loopback WebDAV and a packaged Android emulator cover Windows-1252 editing and content search; Linux additionally exercises UTF-16LE with a BOM; GUI encoding retry is exercised with a stub service. Binary detection is heuristic, remote editor mtime checks are not atomic, and production servers and physical devices remain unverified.

**Acceptance criteria:**

- [ ] Exercise additional encodings and negative cases against other servers, Android providers and physical devices.
- [ ] Retain strict refusal of unrepresentable output and document binary detection limits.

## automation.upstream-xml-compatibility

**Area:** Automation · **Status:** partial

The optional GUI XML action log uses the upstream session namespace and operation-shaped elements. Queue and direct GUI records serialize with one in-process lock per complete record; a transfer does not hold the lock across network awaits. Incomplete existing logs lacking the expected closing tag are preserved rather than overwritten; preview reads a bounded tail. Tests validate interleaved GUI and queue records against the project-authored pinned schema on Linux. The standalone -xmllog CLI is not shipped. See docs/remaining-parity-priorities.md for supported scope and failure boundaries. Focused Linux/Windows Rust tests and Linux GUI plus live WebDAV schema checks passed in branch run 46123944392. Full Linux final-review checks including loopback WebDAV and schema validation passed in run 46124619208. Windows full workspace tests passed in final-review run 46124619141.

**Next:** The schema is derived locally from the pinned upstream emitter, not independent proof of full upstream or consumer compatibility. Linux live WebDAV upload/download and GUI service samples are schema-checked; other real-server operations and Android schema behavior remain unverified. Logging is best-effort and errors can be silent; concurrent external writers, crashes and I/O failure can still cause loss or malformed logs. Secret redaction is not exhaustive.

**Acceptance criteria:**

- [ ] Validate additional supported GUI operations and failures against real protocol fixtures and independent consumers.
- [ ] Improve logging error visibility and crash/interprocess handling before treating it as a reliable audit trail; test Android where applicable.

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

**Next:** Recursive remote deletion is not transactional and can leave a partially deleted tree. Linux loopback WebDAV and a packaged Android emulator deliberately drop TCP during a child delete and verify the partial result; Windows uses a mock failure. Physical devices and production-server interruption remain unverified.

**Acceptance criteria:**

- [ ] Exercise interruption against other production-like servers and physical devices; retain the non-transactional warning.

## backup.full-export-import

**Area:** Sessions/configuration · **Status:** partial

Full exports refuse external SSH/TLS material, CA directories and file-based public-key pins; use supported key/session export or migrate material first. Key/session merges refuse conflicting shared presets and host keys, but are not a crash-transactional multi-file restore. Linux and Windows backup and interchange regression checks passed at b46fdca (GitHub Actions run 46104449707); see docs/backup-portability.md for limitations. Encrypted portable full application backup (`LSCPBAK1`, independent password, Argon2id + AES-256-GCM, LF-normalized, CRLF-tolerant, no absolute config_dir) and transactional undo-journaled restore (`restore_journal.rs` + `ConfigDirectoryLock` + Linux/Android/Windows directory sync barriers). Covers sessions.ini, vault SSH keys + metadata rewrapped under the destination's unlocked vault key, workspaces.json, bookmarks.json, preferences.json, accounts.ini, sshhostkeys, explorer-commands.json, custom-commands.json, monitor.json, and transfer-presets.ini, and clears device-local auto-reconnect.json. `backup_is_distribution_compatible_between_linux_windows_and_android` tests simulated Linux→Windows→Android format round-trip on CI hosts with vault SSH key rewrapping, encrypted stores, fail-closed validation, and CRLF file tolerance. Implemented in crates/linscp-engine/src/{backup.rs,restore_journal.rs}, `backup export|import <file>` in script.rs, and `POST /api/backup/{export,import}` in crates/linscp-service/src/lib.rs. A packaged Android debug APK emulator test exports an encrypted backup, checks refusal of unconfirmed, wrong-password and corrupted imports and active-session restore, then restores over a changed site list. It verifies the existing Keystore-wrapped key stays unchanged, no restore journal remains, and restored credentials reconnect after process restart. A second emulator test exports from one vault, clears the disposable app data, creates a fresh vault with a different password, imports the backup without replacing its destination key, and reconnects with restored credentials before and after process restart. The cross-vault Android test also restores an encrypted SSH-key fixture and its saved-site reference and label. Import deduplication decrypts the destination key and compares the original fixture both before and after restart; the destination ciphertext differs from the source. A disposable Ed25519 key authorized by a Paramiko SFTP fixture authenticates and lists the server after restoration into the fresh vault and again after an app restart; the test does not involve a physical device or a different operating system. A damaged-journal Android emulator test verifies the startup recovery gate rejects session access and unlock, preserves the journal, saved sites and vault key byte-for-byte, and allows reconnection after the test removes the damaged fixture. The packaged API 35 x86_64 Android emulator scenarios were rerun successfully with later code in branch run 46124619130; coverage is limited to the specific scripted provider and operations.

**Next:** Android emulator coverage includes same-install restore, saved-site and SSH-key-fixture recovery into a fresh vault, and fail-closed handling of a damaged recovery journal. SSH authentication with the restored key is exercised against a disposable fixture on the same emulator, not across physical devices or operating systems. Cross-device and cross-OS portability, recovery from a valid interrupted transaction, and physical-device behavior remain unverified; Rust backup format tests run on CI hosts.

**Acceptance criteria:**

- [ ] Test backup portability across real Linux, Windows and Android devices, including authentication with restored SSH keys on each destination.
- [ ] Exercise Android interrupted-restore recovery and physical-device behavior.

## desktop.remote

**Area:** Desktop integration · **Status:** partial

RDP/VNC/SPICE can use direct viewers or an on-demand loopback SSH port forwarder; requested tunnels fail closed if no usable forward exists, and downloadable tickets cannot establish a tunnel. A separate SPICE TLS port is not supported through the single-port forward. RDP saved passwords are not passed in process arguments; viewers must prompt or use their own credential facilities. X11/Waypipe binary and argv must match. The built-in X2Go KDrive viewer remains experimental. Android external URI validation rejects unsupported or unsafe targets. Focused ticket, launcher and fail-closed tests passed on Linux and Windows in branch run 46120074371.

**Next:** The experimental KDrive viewer and native viewer launching have unit/GUI coverage, but live X2Go, RDP, VNC, SPICE and X11/Waypipe interoperability, credential handling and lifecycle behavior remain unverified on target desktops. Android emulator coverage is limited to specific unsafe native URI refusals. The desktop help no longer advertises an unimplemented embedded RDP fallback; gateway responses are hints rather than a bundled viewer.

**Acceptance criteria:**

- [ ] Test RDP launches against a disposable server, including viewer resolution, TLS/NLA options, jump-host relay and credential handling.
- [ ] Test VNC and SPICE viewer launches against disposable servers, including TLS options and generated viewer tickets where supported.
- [ ] Validate and complete the existing experimental X2Go KDrive viewer against real servers on intended platforms, including rendering, input, SSH forwarding and lifecycle; test X11/Waypipe and jump-host policy separately.
- [ ] Independently review any credential-bearing gateway actually shipped; keep XDMCP risk explicit.

## platform.android-saf-synchronization

**Area:** Packaging/platforms · **Status:** partial

Synchronization with a granted local side plans and applies through LocalFs: the planner walks the tree through the bridge, checksum criteria stat each document fresh and refuse an over-cap file naming it before its bytes are read, downloads land in a private stage and publish across the bridge replacing like the plain path, and uploads stage the granted source and run the guarded upload unchanged from the stage. Granted-side deletions stay lenient; keep-up-to-date cannot watch a content:// tree, so it polls it on the interval instead. The page offers both dialogues for granted folders. A packaged Android emulator exercises a real DocumentsUI grant with WebDAV: preview, upload, download, checksum comparison, local obsolete-file deletion and nested synchronization in both directions. A two-pass keep-up-to-date run uploads a file created after the first pass started, exercising interval polling with the external-storage provider. A checksum preview against WebDAV refuses a real provider file one byte over the cap and preserves both files. A separate long-interval polling task is cancelled after its first upload; cancellation finishes promptly and a subsequently created file remains local. The packaged API 35 x86_64 Android emulator scenarios were rerun successfully with later code in branch run 46124619130; coverage is limited to the specific scripted provider and operations.

**Next:** The emulator exercises nested synchronization, repeated polling, cancellation and checksum preview over-cap refusal with the external-storage DocumentsProvider and a WebDAV fixture. Other over-cap paths, other providers and physical devices remain unverified; mtime fidelity and concurrent provider behavior also need validation.

**Acceptance criteria:**

- [ ] Extend the existing nested-sync, polling, cancellation and checksum cap tests to other providers, physical devices, other over-cap paths, timestamp fidelity and concurrent provider changes.

## Cross-cutting release gate

Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, report dependency skips, and update the ledger and generated reports. `python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. The normal checker validates consistency, not behavioral parity.
