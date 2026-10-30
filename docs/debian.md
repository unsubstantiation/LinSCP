# LinSCP on Debian

**The native desktop application is experimental and not ready for production transfers.** SFTP and plain HTTP WebDAV transfers, plus FTP and explicit FTPS connection, listing and download and S3 small-file transfers, have live integration tests. SFTP directory copies support explicitly approved merges, but conflicting files fail without replacement; merges are not transactional and concurrent directory path changes can affect them. Other directory merges and resumption are unsupported. WebDAV files can be moved to a new local destination using conditional GET and DELETE with the original strong ETag, relying on server enforcement; if deletion cannot be confirmed, a duplicate may remain. Other remote moves are unsupported. Local moves require a new destination on the same filesystem. Local copies, SFTP and WebDAV transfers, and FTP, FTPS and S3 downloads support cooperative cancellation. An interrupted FTP/FTPS transfer invalidates the control connection and requires reconnecting. Fresh queued file downloads use owned temporary files that are removed on cancellation or failure on a best-effort basis; cleanup can fail. New SFTP directory downloads are staged as a tree and published without replacement on Linux and Windows; their cleanup is best-effort. Uploads and merges can leave partial files or directories. No-overwrite uploads require an exclusive-create capability (currently SFTP, WebDAV and S3; S3 is limited to 16 MiB); Queued WebDAV and S3 file overwrites require a strong ETag and use conditional PUT, relying on server enforcement; S3 conditional uploads are limited to 16 MiB. An unchanged ETag does not necessarily mean the object has not changed. Other queued overwrites are rejected until they can be made safe. FTP/FTPS uploads and other protocols and configurations remain unverified.

LinSCP is a native Tauri desktop application. It does not ship the retired
console client, browser-server launcher, PowerShell module or .NET CLI wrapper.

## Build

Install Rust 1.89+, Node.js 22+, npm, `dpkg-dev`, `pkg-config`,
`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, and
`librsvg2-dev`. Build from the repository root:

```sh
dpkg-buildpackage -b -us -uc
```

The resulting package installs `linscp-gui`, a desktop entry and icons. The
frontend is embedded in the executable, but WebKitGTK and other shared
libraries are runtime dependencies. Launch LinSCP from the desktop menu or run
`linscp-gui` in a graphical session. Settings live in the normal user
configuration directory.

For an uninstalled build and test commands, see the [main README](../readme.md).
