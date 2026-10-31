<p align="center"><img src="logo/linscp-mark.png" alt="LinSCP logo" width="160" /></p>

# LinSCP

LinSCP is a noncommercial graphical file-transfer client. Its Commander UI
runs in a native Tauri window backed by the Rust transfer engine. No separate
command-line client or browser server is built or distributed. **The native GUI
is experimental and is not ready for production transfers.** Remote listing
and queued file uploads and downloads are implemented. SFTP and plain HTTP
WebDAV connections and transfers have live integration tests; FTP, explicit FTPS
and implicit FTPS staged uploads, plus FTP/explicit FTPS downloads and S3 small-file
transfers, also have live tests. SFTP directories can be copied to new destinations or
merged into explicitly approved existing directories. Merges fail rather than
replace conflicting files and are not transactional; concurrent directory path
changes can still affect them. Other directory merges are unsupported. WebDAV files can be moved to a new local
name using conditional GET and DELETE with the original strong ETag; this relies
on server enforcement and can leave a duplicate if deletion cannot be confirmed.
WebDAV files and directories can also be renamed or queued for a move to
another directory in the same session using a strong source ETag and no-replace
MOVE, relying on server enforcement. A directory ETag may not cover its entire
subtree, so moving directories requires acknowledgement that concurrent changes
may be included. Queued moves can be cancelled before they start, not during the
MOVE request; a lost or ambiguous response means the item may already have moved.
WebDAV files can also be moved to a connected WebDAV, SFTP or S3 session, with
explicit confirmation: an ETag-pinned download is followed by an exclusive
upload and conditional source deletion. Cross-server moves are not transactional;
errors or cancellation can leave a duplicate or partial destination, and source
deletion may be unconfirmed. S3 destinations are limited to 16 MiB per file.
Cross-server directory moves and other remote move combinations are unsupported.
Local moves are supported on the same filesystem on Linux
and Windows, without replacing existing destinations. WebDAV file downloads can
resume from a `.filepart` after comparing its entire prefix with the ETag-pinned
remote file; verification retransfers that prefix. Existing partials are never
removed or modified. A network failure may save a new partial for retry; other
resumption modes are unsupported.
Running local copies, SFTP and WebDAV transfers, FTP/FTPS transfers, and S3 downloads
can be cancelled cooperatively. An interrupted FTP/FTPS transfer invalidates its
control connection; reconnect before further transfers. Fresh queued file downloads use owned temporary files
that are removed on cancellation or failure on a best-effort basis; cleanup can
fail. New SFTP directory downloads are staged as a tree and published without
replacement on Linux and Windows; their cleanup is best-effort. SFTP download
merges are also staged before publication; cancellation during download leaves the
existing tree untouched, but publication is not transactional. Uploads and
published merges may leave partial files or directories.
Without overwrite approval, local copies and downloads use no-replace publication,
and SFTP, WebDAV and S3 uploads use exclusive creation. S3 exclusive uploads are
limited to 16 MiB. FTP/FTPS file uploads are available only after explicitly
accepting a destination-race warning: a server-created STOU temporary file is
renamed to the target, and the server may overwrite a destination created or
changed after the last check. Existing targets also require overwrite approval.
Servers must support STOU with an RFC 1123 FILE response; an interruption or
failed rename may leave a temporary file that must be inspected and removed
manually. Never use this mode if no-clobber guarantees are required.
Queued WebDAV and S3 file overwrites require a strong ETag and use conditional
PUT, relying on server enforcement; S3 conditional uploads are limited to 16 MiB.
An ETag is not necessarily a unique version: changes that retain the same ETag
may not be detected. Other queued overwrites are rejected until they can be made
safe. Other protocols and configurations require further verification.
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
