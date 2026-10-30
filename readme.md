<p align="center"><img src="logo/linscp-mark.png" alt="LinSCP logo" width="160" /></p>

# LinSCP

LinSCP is a noncommercial graphical file-transfer client. Its Commander UI
runs in a native Tauri window backed by the Rust transfer engine. No separate
command-line client or browser server is built or distributed. **The native GUI
is experimental and is not ready for production transfers.** Remote listing
and queued file uploads and downloads are implemented. SFTP and plain HTTP
WebDAV connections and transfers have live integration tests; FTP connection,
listing and download also have a live test. SFTP directory
copies are supported only into new destinations; directory merges, moves and
resumption are unsupported. Running local copies and SFTP transfers can be
cancelled cooperatively; cancellation may leave partial files or directories.
Without overwrite approval, local copies and downloads use no-replace publication,
and SFTP and WebDAV uploads use exclusive creation. Other protocols cannot yet
perform unapproved-overwrite uploads. Approving overwrite does not protect against
a destination changing after approval. FTP uploads and other protocols and configurations remain unverified.
Unsupported operations return an error rather than reporting success.

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

Run `cargo test --workspace --all-targets` and `npm --prefix ui test` for the
Rust and frontend tests. CMake and `source/linux/Makefile` are convenience
wrappers around the same desktop build.

## Debian package

Install the build dependencies listed in `debian/control`, then run
`dpkg-buildpackage -b -us -uc`. The package installs the native GUI and its
desktop entry; see [docs/debian.md](docs/debian.md).

## Android

The Android Gradle project is an experimental WebView scaffold, not a complete
native Tauri application. Its debug APK should not be treated as a functioning
release of the desktop client.

## Historical material

Older parity reports, scripts and live-test harnesses in `docs/` and `source/`
may describe the retired CLI and browser-server architecture. They are not
current build or usage instructions, and CLI-dependent harnesses cannot be run
against the native application.
