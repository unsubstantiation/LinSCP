<p align="center"><img src="logo/linscp-mark.png" alt="LinSCP logo" width="160" /></p>

# LinSCP

LinSCP is an experimental, noncommercial graphical file-transfer client for
Linux, Windows and Android. Its Tauri application uses an in-process Rust
service; there is no standalone browser/server build or separate CLI. The
**native GUI is not ready for production transfers**.

The Commander provides local and remote panes, saved sites, a transfer queue,
synchronization, editing and an SSH terminal. A multi-server monitor provides
Linux telemetry over SSH; see [monitor limitations](docs/server-monitor.md).
External RDP/VNC/SPICE launch and the built-in X2Go viewer are experimental;
real-server interoperability remains unverified.

## Transfer safety

- Transfers and directory operations have protocol-specific restrictions.
  Failed or cancelled operations can leave partial files, trees, temporary
  objects or duplicates; directory merges and cross-server moves are not
  transactional. Use trusted local destination directories.
- WebDAV/S3 verified download resume relies on server-enforced conditions.
  FTP/SFTP resume is refused unless explicitly approved as best-effort: neither
  protocol pins an atomic source snapshot. Upload resume and verified resume to
  Android granted folders are unsupported. See [resume safety](docs/transfer-resume-safety.md).
- FTP/FTPS uploads require an explicit rename-race warning: a competing target
  may be overwritten, and a temporary file can remain. Never use this mode when
  no-clobber guarantees are required. SFTP/FTP interrupted uploads are not
  blindly deleted by pathname. WebDAV/S3 conditional writes depend on server
  enforcement; an unchanged ETag is not necessarily a unique version.
- S3 conditional uploads are limited to 1 GiB. Interrupted multipart uploads
  may leave remote parts; configure an S3 lifecycle rule for abandoned uploads.

See [transfer details](docs/transfer-safety.md) for protocol and cleanup
boundaries, and the [final parity review](docs/final-parity-review.md) for test
scope and remaining gaps.

## Build the desktop application

Install Rust 1.89 or newer, Node.js 22 and npm. On Linux also install the
Tauri system dependencies (on Debian: `pkg-config libwebkit2gtk-4.1-dev
libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev`). On Windows, install
the MSVC build tools and WebView2 runtime.

From the repository root:

```sh
npm --prefix ui ci
npm --prefix ui run build
cargo build --release -p linscp-tauri --features native-shell
```

Run `target/release/linscp-gui` on Linux or
`target/release/linscp-gui.exe` on Windows. The frontend is embedded in the
executable; the system WebView and its platform dependencies are still
required. User settings are stored in the normal platform configuration
directory, not alongside the executable. Windows CI uploads the executable
as a portable, uninstalled application.

The binary also carries the file-manager integration, which is what its own
command line is for:

```sh
linscp-gui --install-shell-integration    # add "Upload with LinSCP" for this user
linscp-gui --shell-upload FILE...         # what that action runs; stages, then exits
linscp-gui --uninstall-shell-integration  # remove exactly what install wrote
linscp-gui --help
```

On Linux this writes a Dolphin service menu, a GNOME Files script and a Nemo
action into the XDG data directory; on Windows it writes an Explorer *Send To*
shortcut. A right-click stages the selection and returns immediately — nothing is
transferred — and the running window offers it for confirmation, or the next
launch does. A supported session URL opens for review, not an automatic
connection. See [Windows URL handlers](docs/windows-url-handlers.md).

Run `cargo test --workspace --all-targets` and `npm --prefix ui test` for the
Rust and frontend tests. CMake and `source/linux/Makefile` are convenience
wrappers around the same build and install the one application.
The Makefile installs under `/usr` by default; for a staged custom prefix use
`make -C source/linux install PREFIX=/opt/linscp DESTDIR=/tmp/package-root`.
CMake uses its standard `CMAKE_INSTALL_PREFIX` (or `cmake --install --prefix`).
The Make and CMake desktop entries point to the installed binary under that
prefix rather than depending on the desktop session's `PATH`. `DESTDIR` is only
a staging root, not a runtime prefix. Desktop discovery may still require the
prefix's `share` directory in `XDG_DATA_DIRS`.

The version shown in the app is the date of the build, not a release
counter; see [docs/versioning.md](docs/versioning.md).

## Debian package

Install the build dependencies listed in `debian/control`, then run
`dpkg-buildpackage -b -us -uc`. The package installs the native GUI and its
desktop entry; see [docs/debian.md](docs/debian.md).

## Android

The experimental Android target uses the Tauri WebView and Rust backend. See
[docs/android.md](docs/android.md) for the signed release APK's build and signing
instructions and important limitations, including app-private storage defaults and
non-durable foreground-service transfers.

## Continuous integration

The workflows in `.github/workflows/` run on pushes to `master` (not when
creating or updating pull requests) and can also be started by hand from the
Actions tab ("Run workflow") or with, for example,
`gh workflow run "Android build" --ref <branch>`. GitHub only offers manual
dispatch when the default-branch workflow declares `workflow_dispatch`.

On `master`, the Debian, Windows and Android jobs build, test, smoke-test and
upload uncompressed build artifacts for the manual release process; no GitHub
Release is created by these workflows. The `master` Android build runs in the
`android-release` environment using the release keystore to sign, verify and
launch-check the release APK; manual Android runs on non-`master` branches run
the unsigned debug build and emulator smoke check without release secrets.

## Historical material

Older parity reports, scripts and live-test harnesses in `docs/` and `source/`
may describe the retired CLI and browser-server architecture. They are not
current build or usage instructions, and CLI-dependent harnesses cannot be run
against the native application.
