# Cross-Platform Pure-Rust & Tauri v2 Migration Specification

## 1. Purpose and Architectural Goals

This document specifies the architecture, crate selection, platform abstractions, and phased parity gates for migrating LinSCP from its current Linux-only C++17 + Python 3 + `curl`-subprocess stack to a **pure-Rust + Tauri v2 + TypeScript** stack supporting **Linux**, **Windows**, and **Android**.

### Core Decisions

1. **Pure-Rust backend and protocol core:** All transport protocols (SSH, SFTP, SCP, jump tunnels, FTP/FTPS, WebDAV, Amazon S3), session/key cryptography, synchronization planning, CLI scripting, and GUI task orchestration live in one Cargo workspace with zero C/C++ cross-compilation dependencies in the default build.
2. **Dual-mode graphical client:** A single modular **TypeScript + CSS** Commander frontend (`ui/`) runs both:
   - **Natively inside Tauri v2** on Linux, Windows (WebView2), and Android (Android WebView) via in-process IPC (`invoke` + event streams), and
   - **In any standard web browser** against a built-in Rust HTTP/WebSocket server (`linscp-http`, invoked via `linscp-gui` or `linscp --serve-http`) for headless, remote, and multi-user deployments.
3. **Maximum resource sharing:** One in-process session and thread pool replaces the current multi-process chain (`Python HTTP server` -> per-tab `linscp -server` -> per-task `linscp` -> external `curl`), and shared crates eliminate duplicate logic across CLI and GUI for session encryption, configuration files, permission/mask parsing, and localization catalogs.
4. **Strangler-fig verification:** The Rust workspace builds alongside `source/linux/` and `source/gui/` until every capability tracked in [`docs/upstream-parity.json`](upstream-parity.json) passes the existing Python/Node live and offline regression suites against the Rust binaries.

### Non-Negotiable Compatibility & Security Invariants

- **On-disk compatibility:** Existing `sessions.ini`, `sessions.key` (`lscp1$` HMAC-SHA256 cipher + MAC), `workspaces.json`, `bookmarks.json`, `preferences.json`, `accounts.ini`, and `explorer-commands.json` files must read and write byte-compatibly without forcing users to re-create sites or re-enter stored secrets.
- **Automation & CLI parity:** All 40 upstream script commands, 11 LinSCP addition groups, `-server` stdin/stdout framing (consumed by `automation/LinSCP.psm1` and `automation/dotnet/LinSCP`), and `-xmllog=` output conforming to [`docs/linscp-session-1.0.xsd`](linscp-session-1.0.xsd) (`http://winscp.net/schema/session/1.0`) are preserved.
- **Fail-closed security:**
  - Unknown or mismatched SSH host keys and jump-host keys are never auto-accepted; jump and destination fingerprints are verified and remembered independently.
  - Refused proxy or SSH tunnel forwards never fall back to a direct connection.
  - Passwords and passphrases never appear on OS process command lines or unredacted in console/XML logs.
  - Browser HTTP mode retains per-run `X-LSCP-Token` checks, strict `Host`/`Origin` allowlists, optional PBKDF2 account login with per-session CSRF tokens, and per-panel/per-account local path confinement.
- **Evidence discipline:** Live and offline test suites continue to enforce non-zero executed case counts (`ran>0`, explicit skip reporting) across Linux, Windows, and Android CI jobs.

---

## 2. Target Workspace and Directory Layout

During migration (Phases 0–5), the Rust workspace and TypeScript UI coexist cleanly beside `source/linux/` and `source/gui/`:

```text
LinSCP/
├── Cargo.toml                  # Workspace manifest, shared dependencies & lints
├── crates/
│   ├── linscp-types/           # Shared domain, config, & IPC/HTTP DTOs (serde + TS codegen)
│   ├── linscp-i18n/            # Unified localization catalog compiler & runtime lookup
│   ├── linscp-crypto/          # lscp1$ cipher, PBKDF2, PPK v2/v3 + Argon2, digests, SigV4
│   ├── linscp-platform/        # OS traits + cfg-gated backends (linux, windows, android)
│   ├── linscp-proto/           # Pure-Rust SFTP, SCP, SSH tunnel/PTY, FTP/FTPS, WebDAV, S3
│   ├── linscp-engine/          # Transfers (.filepart, presets, ASCII), SyncPlanner, Script
│   ├── linscp-service/         # Transport-agnostic Commander state, session pool & queue
│   ├── linscp-http/            # Axum HTTP + WebSocket server for standalone browser mode
│   ├── linscp-cli/             # `linscp` CLI / `-server` / `-shell` / `linscp-gui` binary
│   └── linscp-tauri/           # Tauri v2 desktop (Linux/Windows) & mobile (Android) host
│       ├── src/
│       ├── tauri.conf.json
│       └── gen/android/        # Generated Tauri Android Gradle/Kotlin project + SAF plugin
├── locales/                    # Single shared translation source (en, es, de, fr)
├── ui/                         # Modular TypeScript + CSS Commander frontend
│   ├── package.json
│   ├── tsconfig.json
│   ├── index.html
│   └── src/
│       ├── transport/          # Tauri invoke/event adapter + HTTP fetch/WS adapter
│       ├── state/              # Reactive Commander state (tabs, panes, queue, modals)
│       ├── components/         # Dual/single panes, dialogs, mobile extra-keys bar, terminal
│       ├── styles/             # Desktop + touch/mobile responsive CSS
│       └── vendor/             # Vendored xterm.js 6.0.0 + FitAddon
├── automation/                 # PowerShell 7 module & .NET assembly (cross-platform)
├── source/                     # Existing C++ & Python implementation (kept until Phase 6)
└── tools/                      # Parity, translation, hygiene, and Wayland checks
```

---

## 3. Crate Responsibilities and Pure-Rust Dependency Mapping

Replacing `libssh`, `OpenSSL`, `libargon2`, `iconv`, and subprocess `curl` with pure-Rust crates allows `cargo build --target ...` to compile the entire engine for Linux (`x86_64`/`aarch64`), Windows (`x86_64`/`aarch64-pc-windows-msvc`), and Android (`aarch64-linux-android`, `armv7-linux-androideabi`, `x86_64-linux-android`) without CMake/NDK C library cross-compilation.

| Subsystem | Current Implementation | Target Crate(s) & Libraries | Notes & Edge-Case Handling |
| :--- | :--- | :--- | :--- |
| **Async Runtime** | POSIX `poll`, `std::thread`, `fork` | `tokio` | Shared multi-threaded runtime on desktop/CLI; bounded worker pool on Android. |
| **SSH / SFTP / SCP / Jump Tunnels** | `libssh` + `SftpClient.cpp` + `ScpClient.cpp` + `SshTunnel.cpp` | `russh`, `russh-sftp`, `ssh-key`, `ssh-encoding` | Supports `direct-tcpip` jump channels over in-memory `tokio::io::duplex` streams (no OS `socketpair` needed!), SSH agent (`SSH_AUTH_SOCK` on Unix, Pageant/OpenSSH named pipe `\\.\pipe\openssh-ssh-agent` on Windows), custom SFTP `copy-data` & `check-file-name` extensions, and embedded SSH PTY shell channels. |
| **PPK v2/v3 Keys & `-convertkey`** | `PpkKey.cpp` (`OpenSSL` + `libargon2`) | `linscp-crypto` (`argon2`, `aes`, `cbc`, `hmac`, `sha1`, `sha2`, `ssh-key`) | Native pure-Rust PPK v2/v3 parser, MAC verifier, Argon2d/i/id KDF, and OpenSSH/PEM serializer preserving passphrase encryption. |
| **Stored Secrets (`lscp1$`) & Accounts** | `SessionStore.cpp` + `linscp_crypto.py` + `linscp_gui.py` | `linscp-crypto` (`hmac`, `sha2`, `pbkdf2`, `base64`, `zeroize`) | One shared implementation of `lscp1$` encryption/decryption and 300k-iteration PBKDF2-HMAC-SHA256 login hashes; secrets zeroized on drop. |
| **WebDAV & Amazon S3** | `ProtocolClient.cpp` + `S3Client.cpp` (external `curl`) | `reqwest` (`rustls-tls`), `quick-xml`, `http`, `bytes` | In-process connection pooling, streaming byte-range resume, WebDAV `PROPFIND`/`PROPPATCH`/`LOCK`/`UNLOCK` + RFC 4918 `If` ETag/lock lists, and S3 SigV4 + resumable multipart uploads. |
| **FTP & FTPS** | `FtpClient.cpp` + external `curl` | `suppaftp` (`async-rustls`) + custom Unix/DOS/VMS `LIST` & `MLSD` parser | Keeps LinSCP's hardened Unix, DOS/IIS, and VMS listing parsers (`ListingParse`), `EPSV`/`PASV`/`PORT`/`EPRT`, `FtpForcePasvIp`, and explicit (`ftpes://`) / implicit (`ftps://`) TLS. |
| **TLS Policy & Public-Key Pinning** | `curl` (`--pinnedpubkey`, `--tlsv1.x`, `--cacert`, `--cert`) | `rustls`, `webpki-roots`, `rustls-native-certs` | Custom `ServerCertVerifier` wrapping `WebPkiServerVerifier` enforces SPKI SHA-256 `PinnedPublicKey`, custom CA bundles, client certificates, and `MinTlsVersion`/`MaxTlsVersion` identically on Linux, Windows, and Android. |
| **Checksums** | `HashUtil.c` (`OpenSSL`) | `sha2`, `sha1`, `md-5`, `crc32fast` | Streaming `sha-256`, `sha-1`, `md5`, and `crc32`. |
| **Legacy Text Encodings (`edit -encoding=`)** | `Editor.cpp` (`<iconv.h>`) | `encoding_rs` | Pure-Rust ISO-8859-*, Windows-1252, Shift-JIS, EUC-JP, and UTF-16 conversions with strict unmappable/invalid-sequence rejection (no silent replacement characters). |
| **Filesystem Watching (`keepuptodate`)** | `Script.cpp` (`<sys/inotify.h>`) | `notify` | Uses `inotify` on Linux/Android and `ReadDirectoryChangesW` on Windows behind one event stream, retaining `-interval=` full-rescan fallback. |
| **Local Console & PTY** | `termios`, `pty.openpty()` | `crossterm`, `portable-pty` | Cross-platform password `EchoOff`, raw console `-shell`, and optional local PTY where needed (note: remote SSH terminals connect `xterm.js` directly to a `russh` PTY channel without requiring an OS PTY). |
| **HTTP / Browser Mode** | `linscp_gui.py` (`ThreadingHTTPServer`) | `axum`, `tokio-tungstenite`, `tower`, `rust-embed` | Serves embedded `ui/dist/` assets, REST `/api/*` endpoints, streaming browser uploads, and WebSocket terminal/progress feeds. |
| **Native App Shell** | Browser-only via `xdg-open` | `tauri` v2 + plugins (`dialog`, `fs`, `notification`, `shell`) | Native desktop windows on Linux (WebKitGTK) and Windows (WebView2), plus Android APK/AAB (`gen/android`). |
| **Type Safety Across Rust ↔ TS** | Untyped JSON dicts | `ts-rs` or `specta` | Generates `ui/src/transport/types.generated.ts` directly from `linscp-types` Rust structs in CI. |

### Special Callout: Kerberos / GSSAPI (`security.gssapi-and-tunnels`)

Stock `russh` does not ship built-in RFC 4462 GSSAPI authentication or key exchange. To preserve the existing fail-closed contract without blocking pure-Rust builds on Windows or Android:
- Define a Cargo feature `gssapi` in `linscp-proto`:
  - **Linux:** Optional dynamic/FFI binding via `libgssapi` (MIT Kerberos / Heimdal) into custom `SSH_MSG_USERAUTH_REQUEST` (`gssapi-with-mic`) and RFC 4462 KEX handlers in `russh`, preserving `GSSAPIFwdTGT=0` default-off delegation and the isolated-realm CI suite (`LiveSftpTest.py`).
  - **Windows:** Optional pure-Rust `sspi` crate (or Windows native SSPI `secur32.dll`) integration for Active Directory environments.
  - **Android (and builds without `gssapi`):** `IsGssapiSupported()` returns `false` and refuses Kerberos/GSSAPI settings explicitly by name before opening a socket, matching current stub-`libssh` behavior.

---

## 4. Dual-Mode Architecture (Tauri Native + Standalone Browser HTTP)

Both deployment modes execute the exact same application logic in `crates/linscp-service`:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    TypeScript Commander UI (ui/src/)                    │
│   Dual/Single Panes · Queue · Sync Preview · Editor · xterm.js · i18n   │
├───────────────────────────────────┬─────────────────────────────────────┤
│         TauriTransport            │            HttpTransport            │
│  invoke("api_call") + Tauri Event │  fetch("/api/*") + WebSocket/SSE    │
└─────────────────┬─────────────────┴──────────────────┬──────────────────┘
                  │ In-process IPC                     │ Loopback / LAN HTTP
┌─────────────────▼─────────────────┐ ┌────────────────▼──────────────────┐
│        crates/linscp-tauri        │ │        crates/linscp-http         │
│  Linux / Windows / Android App    │ │  Token + Host + Account/CSRF Auth │
└─────────────────┬─────────────────┘ └────────────────┬──────────────────┘
                  └─────────────────┬──────────────────┘
                                    ▼
                  ┌────────────────────────────────────┐
                  │       crates/linscp-service        │
                  │ Tabs · Session Pool · Task Queue   │
                  │ Workspaces · Bookmarks · Templates │
                  └─────────────────┬──────────────────┘
                                    ▼
                  ┌────────────────────────────────────┐
                  │  linscp-engine + linscp-proto +    │
                  │  linscp-platform + linscp-crypto   │
                  └────────────────────────────────────┘
```

### Transport Adapter Rules (`ui/src/transport/`)

1. **Runtime detection:** At startup, `createTransport()` checks `window.__TAURI_INTERNALS__`. If present, it instantiates `TauriTransport`; otherwise it instantiates `HttpTransport` using the server-injected bootstrap configuration (API token, locale, login state).
2. **Real-time events instead of polling:**
   - Queue byte progress, host-key challenges, `keepuptodate` events, and `xterm.js` terminal streams flow over **Tauri events / `tauri::ipc::Channel`** in native mode and **WebSocket (`/api/events`, `/api/terminal/ws`)** in browser mode (retaining HTTP polling fallback routes so existing `SecurityTest.py` and `ClientTest.js` suites continue to work).
3. **Zero-copy local transfers in native desktop mode:**
   - In browser HTTP mode, desktop drag-and-drop uploads stream raw bytes to a private staging directory (bounded by `MAX_BROWSER_UPLOAD_BYTES`) because browsers hide full local paths.
   - In Tauri desktop mode (Linux/Windows), Tauri's native file-drop event provides validated local filesystem paths directly to `linscp-service`, allowing multi-gigabyte uploads and local-to-local copies without staging duplicates on disk.

---

## 5. Consolidating Shared Resources

Moving from `C++ + Python + JS + curl` to `Rust + TypeScript` eliminates major runtime and maintenance duplication:

1. **In-Process SSH & HTTP Connection Pooling (`linscp-service`):**
   - Today, queuing 20 file transfers or running a remote content search spawns short-lived `linscp` OS processes, repeating TCP, proxy, jump-host, SSH/TLS, and authentication handshakes each time.
   - In `linscp-service`, an open tab owns a pooled `SessionHandle`:
     - **SSH/SFTP/SCP:** Multiplexes concurrent SFTP, `scp`, `exec`, and interactive PTY `shell` channels over the tab's already-authenticated `russh` session (automatically opening a secondary verified session only if a server restricts `MaxSessions` to `1`).
     - **WebDAV/S3:** Shares one `reqwest::Client` connection pool per session/proxy/TLS configuration, reusing HTTP/1.1 keep-alive and HTTP/2 streams across queue workers.
2. **Single Localization Source (`locales/` + `crates/linscp-i18n`):**
   - Merges `source/linux/locales/*.json` and `source/gui/locales/*.json` into one top-level `locales/{en,es,de,fr}.json` catalog set with domain namespaces (`cli.*`, `proto.*`, `gui.*`, `common.*`).
   - `linscp-i18n` validates named placeholders (`{path}`, `{host}`), plural rules (including French `0` singular), yes/no confirmation letters, and untranslated CLI switches at build time.
3. **Single Configuration & Crypto Implementation (`linscp-crypto` + `linscp-engine`):**
   - `sessions.ini`, `sessions.key` (`lscp1$`), transfer presets, OpenSSH/FileZilla session importers, symbolic permission parser (`u+x,go-w`), and LinSCP file masks exist once in Rust and are called by CLI, HTTP server, and Tauri alike.
4. **Embedded Web Assets (`rust-embed`):**
   - Compiled `ui/dist/` assets are embedded into `linscp-http` and `linscp-tauri`, eliminating runtime asset-path mismatches across `/usr/share`, custom CMake prefixes, Windows portable `.exe` builds, and Android APKs.

---

## 6. Platform-Specific Architecture (`crates/linscp-platform`)

All OS-dependent behavior sits behind traits in `crates/linscp-platform` (`LocalFs`, `SecretStore`, `DirWatcher`, `SystemPaths`, `DesktopLauncher`):

### 6.1 Linux (`linux`)

- **Paths & permissions:** Honors `$LINSCP_CONFIG_DIR`, then `$XDG_CONFIG_HOME/LinSCP`, then `~/.config/LinSCP`; enforces `0700` private directories and `0600` secret/state files (`fsync` + atomic rename).
- **Wayland & X11 compatibility:** Carries forward `DetectDesktopSession` (`$WAYLAND_DISPLAY`, `$XDG_RUNTIME_DIR/wayland-0` fallback, `$DISPLAY`), terminal selection (`KnownTerminalPrograms`), `xdg-open`/`gio`/`$BROWSER` launching, `debian/linscp.desktop` URL handlers, and opt-in Dolphin / GNOME Files / Nemo `--install-shell-integration`.
- **Optional keyring integration:** Supports storing `sessions.key` in `sessions.key` (default, CLI-compatible) or unlocking it from Freedesktop Secret Service (`oo7`).

### 6.2 Windows (`windows`)

- **Filesystem & paths (`WinLocalFs`):**
  - Full UTF-8 internal representation converted to wide UTF-16 (`\\?\` extended-length path prefix when needed) at Win32 API boundaries—no legacy ANSI code-page truncation.
  - Native support for drive roots (`C:\`, `D:\`), UNC network paths (`\\server\share\...`), and a **virtual local root** in the Commander UI so navigating above `C:\` lists available drives/volumes with labels and free space.
  - Case-insensitive local wildcard matching (`MatchesMask`) while preserving case-sensitive remote POSIX matching.
  - Atomic `.filepart` completion via `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` (since CRT `rename` fails when the destination exists on Windows).
- **Configuration & secret protection:**
  - Defaults `ConfigDirectory()` to `%APPDATA%\LinSCP` (`FOLDERID_RoamingAppData`) when `LINSCP_CONFIG_DIR` is unset.
  - Replaces no-op `_chmod(0600)` with an explicit owner-only Windows DACL (`D:P(A;;FA;;;OW)`) on the configuration and upload-staging directories, plus optional **Windows DPAPI** (`CryptProtectData`) wrapping for `sessions.key`.
- **Console, SSH agent & shell integration:**
  - Console UTF-8 input/output (`SetConsoleCP(CP_UTF8)` / `SetConsoleOutputCP(CP_UTF8)`), `CTRL_C_EVENT`/`CTRL_BREAK_EVENT` graceful interrupt handling, and password echo suppression via `SetConsoleMode`.
  - Connects to Windows OpenSSH Agent (`\\.\pipe\openssh-ssh-agent`) and Pageant shared memory for key authentication.
  - External `terminal` command supports Windows Terminal (`wt.exe`), PowerShell (`pwsh`), and Windows' built-in `ssh.exe`.
  - Per-user (`HKCU\Software\Classes`) opt-in registration for `sftp://`, `ftp://`, `ftps://`, and `ftpes://` URLs and Windows Explorer context-menu upload staging.
- **Automation compatibility:** `automation/LinSCP.psm1` and `automation/dotnet/LinSCP` resolve `linscp.exe` alongside `linscp` with identical `-server` stdin/stdout behavior.

### 6.3 Android (`android`)

#### Track A: Standalone Native Android App (`linscp-tauri` APK / AAB)

- **Storage Access Framework (`AndroidSafFs`):**
  - Android 11+ Scoped Storage prevents arbitrary POSIX `opendir` across shared storage without restricted permissions. `LocalFs` abstracts local paths and `content://` tree URIs through a small Tauri Kotlin plugin backed by `ContentResolver` and `DocumentsContract`:
    - App-private workspace directory (`context.filesDir`) works out of the box.
    - User-granted folders ("Grant folder access" via `ACTION_OPEN_DOCUMENT_TREE` with persisted URI permissions) appear as roots/bookmarks in the Local pane.
    - Optional sideload/non-store build flavor can additionally toggle `MANAGE_EXTERNAL_STORAGE` for direct `/storage/emulated/0` browsing.
  - **Android Share Sheet (`ACTION_SEND` / `ACTION_SEND_MULTIPLE`):** Incoming shared files from other Android apps register into the exact same validated pending-upload manifest flow used by Linux's `--shell-upload` dialog, prompting the user to confirm the target session tab before transferring bytes.
- **Background transfer survival (`ForegroundService`):**
  - Android suspends WebView and background sockets within seconds when the screen locks or the user switches apps. When a session is connected with active transfers or `keepuptodate` running, the Kotlin plugin promotes the process via an Android `ForegroundService` (`dataSync` / `connectedDevice`), holding a partial `WakeLock` and `WifiLock` and displaying a live transfer-progress notification with a **Cancel** action.
- **Hardware-backed credential security:**
  - `sessions.key` is sealed inside `context.filesDir` using an **Android Keystore** AES-256-GCM master key, with optional `BiometricPrompt` lock before opening stored sessions.
  - `.ppk` and OpenSSH private keys can be imported through the Android system document picker into encrypted app-private key storage.
- **Mobile & touch UX in `ui/`:**
  - **Responsive single-pane default:** On `pointer: coarse` or viewports `< 720px`, the Commander defaults to single-pane mode with a persistent bottom navigation bar (`Local`, `Remote`, `Queue`, `Terminal`) and horizontal swipe switching, while keeping dual-pane side-by-side mode on tablets/foldables and desktop.
  - **Touch interaction model:** Single-tap enters directories or opens file actions; long-press (or leading selection checkboxes) enters multi-select mode with a floating Transfer/Delete/More action bar; row height scales to `>= 44px` touch targets; `env(safe-area-inset-*)` pads status bars and gesture handles.
  - **Touch terminal toolbar:** When `xterm.js` is focused on touch devices, an accessory key strip renders above the soft keyboard with `Esc`, `Tab`, `Ctrl` (sticky), `Alt` (sticky), `↑`, `↓`, `←`, `→`, `/`, `-`, `|`, and `~`.

#### Track B: Termux CLI & Headless HTTP Build

- `cargo build --target aarch64-linux-android -p linscp-cli` produces a self-contained `linscp` binary for Termux users (`$TMPDIR` respected, `termux-open-url` supported for `--open-browser`).

---

## 7. Repository Guardrails, Licensing, and Test Strategy

### 7.1 Evolving `tools/check_platform_conversion.py`

Currently, `tools/check_platform_conversion.py` enforces that LinSCP is Linux-only by rejecting any Windows API, Windows path, `#ifdef _WIN32`, or `runs-on: windows` workflow. In Phase 0, replace those Linux-only rules with **`tools/check_repo_hygiene.py`** while keeping every safety invariant that still applies:

- **Retain unchanged:**
  - `check_brand_references`: Enforces the upstream product-name allowlist across code, tests, CI, and documentation.
  - `check_removed_artefacts`: Prevents obsolete historical files from returning.
  - `check_installed_files` (updated in Phase 6 for the Rust packaging manifests).
- **Replace anti-Windows bans with crate-boundary rules:**
  - Forbid `#[cfg(windows)]`, `#[cfg(target_os = "android")]`, `windows_sys`, `jni`, or `nix` outside `crates/linscp-platform/` and `crates/linscp-tauri/`, guaranteeing that `linscp-proto`, `linscp-engine`, and `linscp-service` remain 100% OS-agnostic.
- **Scope `tools/check_wayland_compatibility.py`:**
  - Continue enforcing Wayland + X11 session parity across `crates/linscp-platform/src/linux/`, `debian/linscp.desktop`, and `ui/`.

### 7.2 Licensing & Third-Party Notices (`LICENSE` / `NOTICE`)

- LinSCP remains under the **PolyForm Noncommercial License 1.0.0**.
- Replacing dynamically linked `libssh` (LGPL-2.1-or-later) with permissive MIT/Apache-2.0 pure-Rust crates (`russh`, `rustls`, `reqwest`, `argon2`, `tauri`, `tokio`) removes LGPL dynamic-relinking constraints, allowing single-file static `linscp.exe` CLI binaries on Windows and single-`liblinscp.so` packaging on Android.
- Update `NOTICE` during cutover with exact third-party Rust crate and `xterm.js` attributions (generated and checked in CI via `cargo-about` or `cargo-deny`).
- *Distribution note:* PolyForm Noncommercial 1.0.0 is compatible with GitHub Releases, Debian/apt self-hosted repos, `winget` / Microsoft Store (noncommercial terms noted), Obtainium, and free noncommercial Google Play listings; main-repo F-Droid requires an OSI/FSF Free Software license, so Android F-Droid distribution would use either a custom F-Droid repo or a separate licensing decision.

### 7.3 Reusing the Existing Automated Test Suites

The existing Python and Node test suites are black-box harnesses that drive `linscp` by executable path (`sys.argv[1]`) or HTTP endpoints—meaning they serve directly as the **parity oracle** for the Rust rewrite:

- **CLI & Live Protocol Suites (`ScriptTest.py`, `LiveSftpTest.py`, `LiveTunnelTest.py`, `LiveScpTest.py`, `LiveDavTest.py`, `LiveS3Test.py`, `LiveCurlTest.py`, `test_psmodule.py`, `test_dotnet.py`):** Run directly against `target/release/linscp` (`crates/linscp-cli`).
- **GUI Backend & Security Suites (`SecurityTest.py`, `BrowserUploadTest.py`, `LocalWorkspaceTest.py`, `LocalEditorTest.py`, `RemoteSearchTest.py`, `DesktopUriTest.py`, `ShellIntegrationTest.py`, `TerminalTest.py`):** Run against `linscp --serve-http` (`crates/linscp-http`).
- **Frontend Suites (`ClientTest.js`, `LocalizationTest.js`):** Run in Node + `jsdom` against the built `ui/` bundle across both mock `TauriTransport` and `HttpTransport`.

---

## 8. Phased Implementation Plan and Acceptance Gates

Each phase is self-contained, keeps CI green, and has explicit acceptance criteria before advancing.

### Phase 0: Workspace, UI Build Pipeline & Guardrails
- **Scope:**
  - Create root `Cargo.toml` workspace and empty crate skeletons (`linscp-types` .. `linscp-tauri`).
  - Set up `ui/` TypeScript + Vite build modularizing `source/gui/web/index.html` and `theme.css` with `TransportClient` (`HttpTransport` + `TauriTransport` stub) while keeping the existing Python GUI tests passing.
  - Evolve `tools/check_platform_conversion.py` (preserving brand checks, enforcing `linscp-platform` crate boundaries) and add GitHub Actions CI jobs for `ubuntu-24.04`, `windows-latest`, and Android NDK `cargo check --target aarch64-linux-android`.
- **Acceptance gate:** `cargo test --workspace` compiles cleanly on Linux, Windows, and Android target triples; `ClientTest.js` and `LocalizationTest.js` pass against the TypeScript `ui/` build; repo hygiene and brand checks pass.

### Phase 1: Cryptography, Storage, Localization & Platform Layer
- **Scope:**
  - Implement `linscp-crypto`: `lscp1$` session encryption (cross-tested against C++ and `linscp_crypto.py` test vectors), PBKDF2 account hashes, PPK v2/v3 + Argon2 parser/PEM converter, SHA-256/SHA-1/MD5/CRC32 digests, and AWS SigV4 signing.
  - Implement `linscp-i18n`: unified `locales/{en,es,de,fr}.json` compiler and parity walker.
  - Implement `linscp-platform`: `LocalFs` (Linux POSIX, Windows UTF-16/drive-roots/atomic `MoveFileExW`/DACL+DPAPI, Android `LocalFs` + SAF trait boundary), `notify` directory watcher, and Linux Wayland/X11 session detection.
  - Implement `sessions.ini`, `workspaces.json`, `bookmarks.json`, `preferences.json`, and OpenSSH/FileZilla session importers.
- **Acceptance gate:** Cross-language round-trip tests prove `sessions.ini` / `sessions.key` and `.ppk` files written by C++/Python open in Rust and vice versa on Linux and Windows; `test_translations.py` passes on unified catalogs.

### Phase 2: Pure-Rust Protocol Engines (`linscp-proto`)
- **Scope:**
  - **2a — SSH, SFTP & Jump Tunnels:** `russh` + `russh-sftp` session, SHA-256/MD5 host-key pinning, password/key/agent auth, jump-host `direct-tcpip` over `tokio::io::duplex`, loopback SOCKS5 relay for non-SSH protocols, SFTP `copy-data` & `check-file-name`, and optional Linux/Windows `gssapi` feature.
  - **2b — Native SCP Engine:** SSH exec `scp -f`/`scp -t` wire engine + POSIX shell directory/metadata engine (`ls -la --full-time`, `stat`, `chmod`, `ln -s`, `cp -p`, `touch -t`, traversal hardening).
  - **2c — WebDAV & S3:** `reqwest` + `rustls` custom SPKI pin/TLS-version verifier; WebDAV `PROPFIND`/`MKCOL`/`MOVE`/`COPY`/`LOCK`/`UNLOCK`/`PROPPATCH` + `If` ETag/lock headers; S3 SigV4 bucket/object CRUD, range `GET`, resumable multipart upload/copy, signed object headers, and `versions`/`-versionid=`.
  - **2d — FTP & FTPS:** `suppaftp` + `MLSD`/`MLST`, Unix/DOS/VMS `LIST` parser, active/passive modes, `FtpForcePasvIp`, explicit/implicit TLS.
- **Acceptance gate:** Rust protocol integration suites pass on `ubuntu-24.04` and `windows-latest`; `cargo check --target aarch64-linux-android` succeeds with zero C library dependencies.

### Phase 3: Transfer Engine, Sync Planner, Script Interpreter & CLI (`linscp-engine`, `linscp-cli`)
- **Scope:**
  - Implement `.filepart` resumable transfers, ASCII/automatic EOL conversion, file masks, speed throttling, transfer presets, one-way/two-way `SyncPlanner` with persistent state & conflict policies, `keepuptodate`, `edit` (`encoding_rs` + `-monitor`), `-xmllog=`, `-server`, and `-shell`.
- **Acceptance gate:** `ScriptTest.py`, `LiveSftpTest.py`, `LiveTunnelTest.py`, `LiveScpTest.py`, `LiveDavTest.py`, `LiveS3Test.py`, `LiveCurlTest.py`, `test_psmodule.py`, and `test_dotnet.py` pass against `target/release/linscp` on Linux (and applicable server-free/loopback suites on `windows-latest`).

### Phase 4: Unified Service, Browser HTTP Mode & Desktop Tauri v2 App (`linscp-service`, `linscp-http`, `linscp-tauri`)
- **Scope:**
  - Implement `CommanderService` (connection-pooled tabs, priority transfer queue with pause/cancel/retry, local-to-local transfers, remote-to-remote copy, bounded UTF-8 search, custom commands, embedded `xterm.js` SSH channel bridge).
  - Ship `linscp-http` (`axum`) for standalone browser mode and `linscp-tauri` for native Linux and Windows desktop windows, adding the Windows local drive/volume selector in `ui/`.
- **Acceptance gate:** All 8 Python GUI suites (`SecurityTest.py`, `BrowserUploadTest.py`, `LocalWorkspaceTest.py`, `LocalEditorTest.py`, `RemoteSearchTest.py`, `DesktopUriTest.py`, `ShellIntegrationTest.py`, `TerminalTest.py`) and both JS suites pass; CI builds Linux `.deb`/`.AppImage` and Windows `.msi`/`.exe` artifacts.

### Phase 5: Android Native App & Touch UX
- **Scope:**
  - Generate and wire `crates/linscp-tauri/gen/android` with the Kotlin plugin for SAF (`ContentResolver` / `ACTION_OPEN_DOCUMENT_TREE`), Share Sheet upload staging (`ACTION_SEND`), `ForegroundService` background transfer lock + notification, and Android Keystore wrapping for `sessions.key`.
  - Deliver mobile single-pane swipe navigation, touch selection/long-press gestures, safe-area insets, and the `xterm.js` extra-keys bar in `ui/`.
  - Add Termux build recipe/job (`aarch64-linux-android` `linscp-cli`).
- **Acceptance gate:** Android `.apk`/`.aab` builds cleanly in CI; headless Android Emulator (or JVM/instrumented test) verifies session open, SAF local transfer, host-key prompt, and background service lifecycle; mobile viewport/touch tests pass in `ClientTest.js`.

### Phase 6: Cutover, Packaging & Legacy Retirement
- **Scope:**
  - Verify 100% parity in `docs/upstream-parity.json` (`python3 tools/check_upstream_parity.py`) with implementation paths updated to `crates/*` and `ui/*`.
  - Update `debian/` packaging, `CMakeLists.txt` (if retained as a convenience wrapper) or release scripts, `NOTICE` crate attributions, `docs/linscp.1`, and `readme.md`.
  - Remove superseded `source/linux/*.cpp` and `source/gui/*.py` production files while retaining and adapting all cross-platform regression suites.
- **Acceptance gate:** Full CI matrix green on Linux, Windows, and Android with `ran>0` evidence annotations across every suite.
