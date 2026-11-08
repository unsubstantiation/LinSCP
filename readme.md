<p align="center"><img src="logo/linscp-mark.png" alt="LinSCP logo" width="160" /></p>

# LinSCP

LinSCP is a noncommercial graphical file-transfer client. Its Commander UI is a
single page in a native Tauri window (`linscp-gui`) on Linux and Windows, and in
the Android app. There is no browser or web build: the page reaches the Rust
transfer engine only through the shell's in-process IPC, so there is no local
HTTP server, no access token and no server-side sign-in. No separate
command-line client is built or distributed. **The native
GUI is experimental and is not ready for production transfers.** Remote listing
and queued file uploads and downloads are implemented. A shared multi-server
monitor displays Linux CPU/per-core, RAM, swap, disk, load, network and NVIDIA/AMD
GPU telemetry over authenticated SSH sessions, with saved-site selection,
sparklines, custom metrics, outage alerts, persisted settings, compact GPU cards
and an embedded SSH shell; see `docs/server-monitor.md`. SFTP and plain HTTP
WebDAV connections and transfers have live integration tests; FTP, explicit FTPS
and implicit FTPS staged uploads, plus FTP/explicit FTPS downloads and S3 small-file
transfers, also have live tests. SFTP and WebDAV directories can be copied between
a remote session and the local pane, including explicitly approved merges. WebDAV
copies require acknowledgement that trees are not snapshots and path changes may
redirect writes. Merges fail rather than replace conflicting files and are not
transactional; concurrent directory path changes can still affect them. Other
directory merges are unsupported. WebDAV files can be moved to a new local
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
deletion may be unconfirmed. S3 destinations are limited to 1 GiB per file.
WebDAV and S3 files can also be copied to a new name in the same session or to a connected WebDAV, SFTP or S3 session via a conditional temporary local download and exclusive upload. S3 source ETags depend on provider enforcement and may not uniquely identify a version. Copies can leave partial remote destinations on failure or cancellation. SFTP file copies to WebDAV, SFTP or S3, and directory copies from SFTP or WebDAV to a new SFTP or WebDAV directory, use local staging and require risk confirmation: Neither directory copy is a tree-wide snapshot: SFTP cannot pin source versions, WebDAV pins each file but collection ETags may not cover descendants, and concurrent source or destination path changes can affect the result. Directory copies do not merge and may leave partial remote trees after interruption. Cross-server directory moves, S3-source moves, and other source protocols remain unsupported.
Local moves are supported on the same filesystem on Linux
and Windows, without replacing existing destinations. WebDAV and S3 file downloads can
resume from a `.filepart` after comparing its entire prefix with the ETag-pinned
remote file; verification retransfers that prefix and relies on the server enforcing
conditional requests. An unchanged ETag does not necessarily identify a unique version. Existing partials are never
removed or modified. A network failure may save a new partial for retry; other
resumption modes are unsupported.
Running local copies, SFTP and WebDAV transfers, FTP/FTPS transfers, and S3 transfers
can be cancelled cooperatively. An interrupted FTP/FTPS transfer invalidates its
control connection; reconnect before further transfers. Fresh queued file downloads use owned temporary files
that are removed on cancellation or failure on a best-effort basis; cleanup can
fail. New SFTP and WebDAV directory downloads are staged as a tree and published without
replacement on Linux and Windows; their cleanup is best-effort. Local staging
and cleanup assume a trusted destination directory: concurrent pathname
replacement can affect the temporary files. SFTP and WebDAV download
merges are also staged before publication; cancellation during download leaves the
existing tree untouched, but publication is not transactional. Uploads and
published merges may leave partial files or directories. For new WebDAV uploads,
servers supporting conditional lock-null resources can use a randomly named locked
stage: on failure the app attempts deletion only while its lock token is still valid.
If cleanup is unconfirmed, the app retains the token in memory and retries in the
background and on later staged uploads in the same session; tokens are not persisted
across restarts.
This relies on server lock and precondition enforcement; locks can expire, and
cleanup or lock acquisition can be unconfirmed, leaving a temporary resource.
When locking is unsupported, uploads fall back to direct exclusive or conditional
PUT, which can leave partial remote files. Approved overwrites on lock-capable
servers use tagged source-lock and destination-ETag conditions on MOVE; both
conditions depend on server enforcement.
SFTP and FTP cannot safely delete an interrupted upload by pathname: another
client may have replaced it. The app leaves such files for inspection rather than
blindly removing them, and rejects legacy unguarded SFTP/FTP upload paths. Automatic
safe cleanup requires a server-side ownership or conditional-delete facility that
these protocols do not generally provide.
Without overwrite approval, local copies and downloads use no-replace publication,
and SFTP, WebDAV and S3 uploads use exclusive creation. S3 exclusive uploads are
limited to 1 GiB. FTP/FTPS file uploads are available only after explicitly
accepting a destination-race warning: a server-created STOU temporary file is
renamed to the target, and the server may overwrite a destination created or
changed after the last check. Existing targets also require overwrite approval.
Servers must support STOU with an RFC 1123 FILE response; an interruption or
failed rename may leave a temporary file that must be inspected and removed
manually. Never use this mode if no-clobber guarantees are required.
Queued WebDAV and S3 file overwrites require a strong ETag and use conditional
PUT or conditional multipart completion, relying on server enforcement; S3 conditional uploads are limited to 1 GiB. S3 uploads over 16 MiB use a fresh multipart upload ID and attempt to abort that ID on failure or cancellation without deleting the destination pathname. Abort can fail or initiation can be unconfirmed, leaving an unfinished multipart upload; even a successful abort may leave parts that were in flight, and a lost completion response can mean the destination exists. Known upload IDs are recorded privately and retried on a later connection to the same endpoint and account, using file locks to avoid aborting an active instance; retries depend on the provider's upload-ID uniqueness and may fail. Recovery requires a trusted configuration directory and working OS file locks; Windows journal files inherit the directory's access controls. A crash before the ID is recorded cannot be recovered this way. Configure an S3 lifecycle rule to remove abandoned multipart uploads.
An ETag is not necessarily a unique version: changes that retain the same ETag
may not be detected. Other queued overwrites are rejected until they can be made
safe. Other protocols and configurations require further verification.
Unsupported operations return an error rather than reporting success. A current
native feature audit, including visible but unwired actions, is in
[`docs/native-feature-audit.md`](docs/native-feature-audit.md). Workspaces restore
local tabs and remote tabs backed by saved sites; they do not store credentials.

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
launch does. Any other argument, including none, opens the window, so a desktop
launcher's own flags are harmless.

Run `cargo test --workspace --all-targets` and `npm --prefix ui test` for the
Rust and frontend tests. CMake and `source/linux/Makefile` are convenience
wrappers around the same build and install the one application.

## Debian package

Install the build dependencies listed in `debian/control`, then run
`dpkg-buildpackage -b -us -uc`. The package installs the native GUI and its
desktop entry; see [docs/debian.md](docs/debian.md).

## Android

The experimental Android target uses the Tauri WebView and Rust backend. See
[docs/android.md](docs/android.md) for the signed release APK's build and signing
instructions and important limitations, including app-private storage only and
no background transfers.

## Continuous integration

The workflows in `.github/workflows/` build the Debian package, the Windows
application and the signed Android APK. Each runs on a push to `master` and can
also be started by hand, from the Actions tab ("Run workflow", where the branch
to build can be chosen) or with `gh workflow run "Android build" --ref <branch>`.
GitHub only offers that button for workflows whose default-branch copy declares
`workflow_dispatch`, which all three do; a run of the Android build uses the
`android-release` environment and therefore its release keystore.

## Historical material

Older parity reports, scripts and live-test harnesses in `docs/` and `source/`
may describe the retired CLI and browser-server architecture. They are not
current build or usage instructions, and CLI-dependent harnesses cannot be run
against the native application.
