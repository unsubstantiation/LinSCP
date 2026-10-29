<p align="center">
  <img src="logo/linscp-mark.png" alt="LinSCP logo" width="160" height="160" />
</p>

<img src="pic.jpg" />

# LinSCP

LinSCP is a noncommercial file transfer client for Debian GNU/Linux. It has
a command-line client with an upstream-compatible scripting language, and a
browser-based dual-pane Commander (`linscp-gui`).

LinSCP implements a subset of the upstream feature set. It does **not**
provide full upstream parity: see [Protocols](#protocols) and the
[parity audit](docs/upstream-parity.md). The inventory tracks upstream master
as of 2026-10-26; command registrations are current, but two capability gaps
remain.

## Requirements

- Debian 13 (trixie) or newer, with Rust 1.89+ (`cargo`, `rustc`) and `pkg-config`.
  No C/C++ cross-compilation is required for the pure-Rust workspace.
- `xdg-utils` (recommended), so `linscp-gui --open-browser` can ask the desktop
  for a browser window on Wayland as well as under X11.
- Node 22 or newer with `npm`, for the TypeScript UI build (`ui/`) and its tests.
- Python 3, for the live regression suites (the test harnesses drive `target/release/linscp`).

```sh
sudo apt install dpkg-dev pkg-config cargo rustc xdg-utils python3 nodejs npm
# or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

LinSCP builds pure-Rust on Linux, Windows (`x86_64-pc-windows-msvc`) and Android
(`aarch64-linux-android` via `cargo ndk`). The `debian/rules` and `CMakeLists.txt`
wrappers now delegate to `cargo`.

## Building and testing

Pure-Rust (primary):

```sh
cargo build --release --workspace      # -> target/release/linscp + linscp-gui
cargo test --workspace --all-targets   # Rust unit + integration tests
cargo run -p linscp-cli --release -- -help
```

The live suites are Python harnesses that drive `target/release/linscp`
(the same binary CI uses on `ubuntu-24.04` and `windows-latest`):

```sh
python3 source/linux/tests/ScriptTest.py target/release/linscp
python3 source/linux/tests/LiveSftpTest.py target/release/linscp
# ... LiveTunnel/S3/Dav/Scp/Curl, plus gui suites via linscp --serve-http
```

The UI is TypeScript:

```sh
npm --prefix ui install
npm --prefix ui run build   # -> ui/dist (embedded in linscp-http)
npm --prefix ui test
```

Legacy wrappers remain for compatibility: `make -C source/linux` and
`cmake -S . -B build && cmake --build build` now delegate to `cargo`
and exist only for CI parity and Debian `cmake --install` expectations.

The live suites use optional Python packages: `paramiko` (SFTP),
`botocore` (S3 signature reference), `xmlschema` (XML log schema
validation), and `pyftpdlib` with `pyOpenSSL`
(FTP/FTPS). The GSSAPI cases in the SFTP suite need `krb5-kdc`,
`krb5-admin-server`, `krb5-user`, `openssh-server` and a GSSAPI-enabled libssh;
they start an isolated KDC and `sshd` bound to loopback. The SCP suite also
needs `openssh-server`; it starts its own `sshd` on a free port. A suite that
skips a case says so on its evidence line.

The GUI suites (`source/gui/tests/` + `ui/tests/`) run separately, as in CI.
`ui/tests/TransportAndPlatform.test.mjs` exercises the dual-mode
`HttpTransport`/`TauriTransport` and the Windows drive selector / Android
mobile UX. `SecurityTest.py` drives the `linscp-http` server itself, with no
browser: tokens, sign-in, the absence of CORS permission, response headers,
command quoting, and the confinement of every local path to its pane.

`cargo test` also runs `tools/check_platform_conversion.py` (now
`tools/check_repo_hygiene.py` scope: it forbids Windows/Android `cfg`
outside `crates/linscp-platform`/`linscp-tauri` and keeps brand/wayland checks).
A second check guards Wayland: `tools/check_wayland_compatibility.py`
refuses a display-server test that reads `DISPLAY` without `WAYLAND_DISPLAY`,
etc. Both run in CI. For the Debian package:

```sh
dpkg-buildpackage -b -us -uc         # -> ../linscp_1.0-5_<arch>.deb
```

## Usage

```sh
linscp -batch -script=script.txt
linscp -batch -command="open sftp://user@example.com/; cd /data; get *.csv /tmp"
linscp-gui                         # browser Commander on 127.0.0.1:8080
linscp-gui --open-browser          # ... and ask the desktop to show it
```

Run `linscp -help` for the options and `man linscp` for the full reference.

## Protocols

| URL | Served by | Notes |
| --- | --- | --- |
| `sftp://` | pure-Rust `russh` + `russh-sftp` (copy-data / check-file-name extensions) | full command set |
| `scp://`, `ssh://` | pure-Rust `russh` SSH: the server's shell for directory work, rcp for bytes | no resume; the protocol has no offset |
| `ftp://` | pure-Rust `suppaftp` + native Unix/DOS/VMS LIST + MLSD parser | |
| `ftps://` | `suppaftp` (async-rustls), implicit TLS | |
| `ftpes://` | `suppaftp` (async-rustls), explicit TLS on FTP (same session as `ftp://` with `Ftps=2` or `3`) | |
| `dav://`, `webdav://` | pure-Rust `reqwest` + `rustls` (WebPki, SPKI pin, Min/MaxTlsVersion), PROPFIND/MOVE/COPY/locks/dead props/ETag | |
| `s3://` | pure-Rust `reqwest` + `rustls`, SigV4 signing, multipart, versioning | partial |
| `rdp://` | `xfreerdp`/`xfreerdp3`/`wlfreerdp` (Linux), `mstsc.exe` (Windows), `aRDP`/`aFreeRDP` (Android), fallback `ironrdp` WASM gateway | optional viewer |
| `vnc://` | `vncviewer`/`tigervnc`/`remmina` (Linux), `vncviewer.exe` (Windows), `androidVNC` | 5900-range |
| `spice://` | `remote-viewer`/`virt-viewer`/`spicy` (virt-viewer, QEMU/KVM), `.vv` virt-viewer files | |
| `x2go://` | `x2goclient`/`pyhoca-cli`, `nxproxy` — SSH (22) with NX compression, reuses jump-host tunnel | |
| `x11://` | `waypipe ssh` (Wayland, preferred) or `ssh -X`/`-Y` (X11) — detected via `WAYLAND_DISPLAY`/`XDG_SESSION_TYPE`/`DISPLAY` | headless prints `DESKTOP_TICKET` |

Host keys are verified. `-hostkey=` takes a SHA-256 or MD5 fingerprint. An
unknown key in a run that cannot prompt is refused, and the key is printed so
it can be pinned.

## Features

- **Transfers:** binary, ASCII and automatic modes; LinSCP file masks; recursive
  `get` and `put`; resume through `.filepart` staging; `-append` (SFTP only);
  `-speed=` limits; `-preservetime`; transfer presets.
- **Synchronization:** `synchronize` in one or both directions, and
  `keepuptodate`, which watches the local tree with inotify.
- **SSH keys:** native PPK v2/v3 parsing for authentication and `copyid`,
  including encrypted keys (Argon2 for encrypted v3), plus
  `linscp -convertkey=input.ppk -output=output.pem` for a validated PEM copy;
  encrypted inputs stay encrypted with the same passphrase.
- **Remote operations:** `chmod` (octal and symbolic), `cp`, `mv`, `ln`,
  `rm`, `mkdir`, `stat`, `checksum`, `edit`, `call`, and `copyid`.
- **Scripting:** unambiguous command and option abbreviations, `%1%`..`%9%`
  parameters, `%TIMESTAMP%` and environment expansion, `option batch` and
  `option confirm`, and an XML action log (`-xmllog=`).
- **Stored sessions:** shared between the CLI and the GUI, with folders,
  encrypted passwords in `sessions.ini` (key in `sessions.key`), and proxy
  settings through `-rawsettings`.
- **SSH jump hosts:** independent jump/destination authentication and host-key
  verification, encrypted saved jump credentials, GUI/queue/terminal support,
  and fail-closed proxy/forwarding behavior. See [SSH tunnels](docs/ssh-tunnels.md)
  for configuration and limits.
- **Graphical client:** dual-pane layout, transfer queue with pause, retry and
  priority reordering, transfer settings, sync preview, `keepuptodate`, remote
  search, checksums, session bookmarks, a session URL, session import, cleanup
  of stored data, a copy between two servers, properties with a rights editor,
  preferences stored by the backend, saved command templates, multi-user
  sign-in, local file editing and drag-and-drop in both panes. Sign-in does not
  isolate users' tabs, files or commands: do not share one backend among
  untrusted users.
- **Localization:** English, Spanish, German and French, for the CLI and the GUI.
- **Desktop sessions:** works on Wayland and on X11 alike. The clients draw no
  window of their own; the terminal `terminal` opens is chosen among the ones
  that can draw on this display server, and `--open-browser` asks the desktop's
  own launcher (`xdg-open`, `$BROWSER`) for a browser window. No `xclip`,
  `xdotool`, `wmctrl` or `xrandr`, which is what makes a Linux application
  X11-only.
- **Remote desktop:** `open rdp://host:3389`, `vnc://`, `spice://`, `x2go://` and `x11://` launch the platform viewer (xfreerdp/tigervnc/remote-viewer/x2goclient/waypipe or the Windows/macOS/Android equivalent) or, in headless HTTP mode, write a `.rdp`/`.vv` ticket file and return `DESKTOP_TICKET`/gateway JSON for the browser (embedded `ironrdp` WASM fallback). Shares proxy/SSH-jump/TLS/SPKI verification; XDMCP (UDP 177, unencrypted) is not recommended — use X2Go or `waypipe` over SSH instead.

Full upstream parity is **not** implemented. Remaining gaps include complete
compatibility with the upstream .NET object model, broader localization beyond
English/Spanish/German/French, and an independent security review plus broader production-realm
validation of GSSAPI. The live SFTP suite exercises GSSAPI against a throwaway
Kerberos realm; this does not certify every KDC deployment. Local-to-local sessions with two
local panes, named multi-tab workspaces, directory bookmarks, session import
from OpenSSH/FileZilla and session-URL generation are implemented and covered
by the `gui-local` and `gui` suites.
The .NET-compatible assembly (`LinSCP.Session`, with an upstream compatibility
namespace) covers session lifecycle, listing, transfers, synchronization,
cancellation and structured errors; it is not every type of the upstream
object model.
`automation/LinSCP.psm1` is a PowerShell 7 CLI wrapper with static tests and
optional live Pester tests, not the upstream .NET API. Optional account sign-in
isolates users at the application layer; the backend still runs as one OS user.
See the
[remaining parity plan](docs/remaining-parity-plan.md) for scope and acceptance
criteria; passing the inventory checker is not a full-parity certification.

A small allowlist preserves upstream repository paths, XML/.NET identifiers,
external documentation URLs, Windows-executable detection and the fork notice
in NOTICE. These are interoperability or historical identifiers, not product
branding.

## Documentation

- [`docs/debian.md`](docs/debian.md): options, commands, protocols,
  authentication, packaging and troubleshooting.
- [`docs/linscp.1`](docs/linscp.1): the manual page.
- [`docs/upstream-parity.md`](docs/upstream-parity.md): the parity audit, its
  evidence rules and how to maintain them.
- [`docs/linux-feature-inventory.md`](docs/linux-feature-inventory.md) and
  [`docs/remaining-parity-plan.md`](docs/remaining-parity-plan.md): generated
  from `docs/upstream-parity.json`. Regenerate them with
  `python3 tools/check_upstream_parity.py --write-report`.
- [`docs/localization.md`](docs/localization.md): language selection and catalogues.

## Repository layout

```
.github/       CI workflows (Build & test, Cross-Platform Rust & UI, Debian, Android)
automation/    PowerShell 7 wrapper and .NET assembly, with their tests
crates/        pure-Rust workspace: linscp-types, linscp-i18n, linscp-crypto,
               linscp-platform (linux/windows/android), linscp-proto (SFTP/SCP/FTP/WebDAV/S3),
               linscp-engine (transfers/sync/script), linscp-service (Commander),
               linscp-http (axum browser mode), linscp-cli (linscp/linscp-gui), linscp-tauri
locales/       unified translation catalogs (de, en, es, fr - single source for CLI+GUI)
ui/            TypeScript + CSS Commander frontend (dual-mode: Tauri IPC + HTTP)
debian/        Debian packaging (now cargo-based, wraps ui/dist embedding)
docs/          documentation, manual page, schema and parity inventory
fixtures/      XML action-log examples used by tests
logo/          logo artwork
source/        legacy C++ / Python reference (retained for regression-suite harnesses;
               production code retired to crates/* in Phase 6; tests still drive
               target/release/linscp via the same Python/Node suites)
tools/         parity, translation, Wayland and hygiene checkers
```

## Licence

LinSCP is distributed under the [PolyForm Noncommercial License
1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0):
noncommercial use only. This is not an open source licence. The full terms are
in [`LICENSE`](LICENSE); the copyright line, the MIT notice for the
third-party components and the artwork terms are in [`NOTICE`](NOTICE).
