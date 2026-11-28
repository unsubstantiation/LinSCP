# LinSCP on Debian

**The native desktop application is experimental and not ready for production
transfers.** See the [README](../readme.md#transfer-safety) and
[transfer safety](transfer-safety.md) for protocol restrictions and recovery
caveats.

The Debian package contains the native Tauri application, not a standalone
browser server, CLI, PowerShell module or .NET wrapper.

## Build

Install Rust 1.89+, Node.js 22+, npm, `dpkg-dev`, `pkg-config`,
`libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`, and
`librsvg2-dev`. Build from the repository root:

```sh
dpkg-buildpackage -b -us -uc
```

The resulting package installs `linscp-gui`, one desktop entry and icons.
`linscp-gui` also carries the optional, per-user file-manager
integration: `linscp-gui --install-shell-integration` adds an "Upload with LinSCP"
entry to Dolphin, GNOME Files and Nemo, which stages the selection and returns,
and `linscp-gui --uninstall-shell-integration` removes exactly what it wrote. The
window then offers the staged selection for confirmation; nothing is transferred
without it. The frontend is embedded in the executable, but WebKitGTK and other
shared libraries are runtime dependencies. Launch LinSCP from the desktop menu
or run `linscp-gui` in a graphical session; settings live in the normal user
configuration directory.

The Debian CI smoke runs the installed GUI under Xvfb and headless Weston
(with the GTK Wayland backend forced). The Weston check observes a configured
and committed Wayland toplevel, not rendered pixels or user interaction. CI
also tests upgrade from a synthetic older version of the same package payload,
then removal and purge; it does not validate migration from a released version.
Package removal does not remove optional per-user file-manager integration or
user configuration. Uninstall the integration using the command above before
removing the package if those actions should also be removed.

For an uninstalled build and test commands, see the [main README](../readme.md).
