# Desktop and Android feature parity

Desktop and Android use the same embedded UI, service, transfer queue and
protocol implementations, but that alone does **not** establish parity. This
matrix records current differences and verification; unsupported features are
not made safe by hiding their controls.

| Area | Desktop | Android | Evidence / limitations |
| --- | --- | --- | --- |
| Connection, host-key approval, browsing and queue | Native service | Same service | Live desktop SFTP, FTP/FTPS, WebDAV, S3 tests. Android emulator exercises WebDAV connection and file transfer; other protocols still need device-level tests. |
| Local files | Native filesystem directories | App-private filesystem and picker copy-in/copy-out | Android picker copies selected files into app storage; export copies one file out. No direct shared-directory browsing, directory selection, or persistent SAF grants. |
| Local navigation, rename, atomic no-replace | Native filesystem | App-private filesystem | Shared navigation regression; Android emulator exercises rename, transfers and conflict protection. Filesystem support can vary. |
| Verified download resume | WebDAV and S3 subsets | Same implementations | Android emulator exercises WebDAV with a partial file. Other protocols or unsupported cases fail closed. |
| Background transfers | While app remains running; OS behavior varies | App must remain open | Android foreground service, restart recovery and notifications are not implemented. |
| Saved credentials | Platform-local encrypted session store, protection varies by OS | App-private session store | Android key is not protected by Android Keystore or biometrics. Android backups disabled in generated project. |
| File-manager integration | Shell upload and drag/drop native paths are not wired | Share intents and folder grants not wired | Neither currently has complete OS integration. |
| Packaging | Debian and Windows artifacts | Debug-signed ARM64/x86-64 APK | Android is experimental, not a release-signed or Play Store build. |

Common gaps are listed in [native-feature-audit.md](native-feature-audit.md),
and Android-specific constraints in [android.md](android.md). Existing CI does
not prove parity for every protocol, server, operating system version, device,
failure or concurrency scenario. In particular, SFTP/FTP partial-upload cleanup
must remain fail-closed on unmodified servers because pathname deletion cannot
atomically identify the original upload.
