# LinSCP on Debian

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
