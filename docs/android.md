# Experimental Android APK

The Android target builds the same Tauri WebView and Rust `CommanderService` as
the desktop application. This is an **experimental, debug-signed APK**, not a
production or Play Store release. Android support is incomplete:

- The generated Android host registers the Storage Access Framework picker,
  persists the returned tree grants, and routes `content://` list/stat/read/write/
  create/rename/delete operations through the local filesystem. It also accepts
  `ACTION_SEND` and `ACTION_SEND_MULTIPLE`, stages received content URIs in the
  app-private cache, and presents them through the existing upload-offer flow.
  Shared files are not written to public Downloads; uninstalling the app removes
  app-private files and configuration.
- An Android foreground service displays an ongoing transfer notification while
  queued work is active, so the Rust process can continue when the activity is
  backgrounded. Android can still stop work after a force-stop, device shutdown,
  or other process termination; this is not a durable job queue. Android
  Keystore/biometric integration remains unwired, and the session master key is
  stored in the app sandbox rather than backed by Android Keystore.
- One `hostCapabilities()` description drives host-dependent controls. SAF,
  incoming share intents, foreground transfers, and external viewer intents are
  reported for the registered native Android build; a browser running on Android
  does not inherit those native capabilities. Android can hand direct RDP, VNC,
  and SPICE targets to installed viewer apps. X2Go/X11 and SSH jump-tunnel viewer
  launches are not supported by Android intents yet. Debian/Windows use native
  desktop viewers and OS file-drop events; Android uses document grants and the
  Share Sheet instead. `hostDifferenceReason()` explains unavailable
  integrations.
- Remote transfer restrictions and cleanup caveats in the main README still
  apply. The shared GUI actions listed in the native feature audit are routed
  through the service, but some remain protocol-limited or lack Android
  end-to-end coverage; see that audit before relying on them.
- The debug APK is signed with a development key. It is intended for testing,
  not distribution, updates to a release-signed installation, or sensitive data.

## Application ID and install directory

The app is installed as **`com.fairuniversal.linscp`**, defined once in
`crates/linscp-tauri/tauri.conf.json` (`identifier`). Tauri renders that into the
Gradle `applicationId` of the generated project
(`namespace`/`applicationId = "<identifier>"`, no `applicationIdSuffix` unless
`bundle.android.debugApplicationIdSuffix` is configured — this repository does
not configure it) and into the `MainActivity` package directory. Android then
places the installed app in the sandbox named after that `applicationId`:

```
/data/user/0/com.fairuniversal.linscp         Activity.dataDir (`/data/data/...` is the same dir)
/data/user/0/com.fairuniversal.linscp/config  linscp_platform::default_config_dir()
/data/user/0/com.fairuniversal.linscp/cache   TMPDIR (Activity.cacheDir)
```

Tauri's `app_data_dir()` on Android is `Activity.dataDir` itself, not a
`files/config` subdirectory: `PathPlugin.getDataDir()` resolves
`activity.dataDir`, and `app.path().app_data_dir()` in
`crates/linscp-tauri/src/lib.rs` is what the shell exports as
`LINSCP_ANDROID_FILES_DIR`. The `App Storage` local root the page shows and the
`config_root()` the service loads preferences and sessions from are therefore
both inside the folder named after the application ID, with no `app >
appDirectoriesOverride` in the configuration pointing anywhere else.

The emulator harness proves this on the device rather than assuming it. After
the WebView smoke test writes a marker file through the Rust service,
`tools/android_emulator_smoke.sh` asks the system package manager for the
installed package, enters that package's sandbox (`adb shell run-as`), checks
the sandbox is `/data/user/0/com.fairuniversal.linscp`, and looks for the marker
there. A build installed under another name, or reading another package's
storage, fails the run; nothing in that check comes from this repository's own
configuration.

Two consequences of a rename are worth stating: the new package installs
*beside* an older build rather than updating it, and an older build's
app-private settings and stored sessions live under `/data/user/0/io.linscp.commander`,
so they are not carried over — re-import or re-enter the sites you need, then
uninstall the old app. A generated `gen/android` project from before the rename
must be regenerated (`tauri android init`) or the build stops with the mismatch
rather than shipping the old name.

## Build

Install Node.js 22, Rust stable, Java 17, Android SDK platform 36/build-tools
36.0.0, and the Android NDK. Set `ANDROID_HOME` and `NDK_HOME` to the SDK and
NDK directories. From the repository root:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
npm ci --prefix ui
npm run build --prefix ui
cd crates/linscp-tauri
npm run tauri -- android init --ci --skip-targets-install
python3 ../../tools/prepare_android_project.py
npm run tauri -- android build --ci --debug --apk true --aab false --target aarch64 x86_64 --features native-shell
```

The Android Gradle project under `gen/android` is generated and ignored; the
pinned Tauri CLI version is in `ui/package-lock.json`. The preparation script
turns off Android backup so the app-private session key and settings are not
silently included in Android backups. Generate a fresh project when changing
Tauri CLI versions. The APK is under `gen/android/app/build/outputs/apk/`.

The Android GitHub Actions workflow builds and verifies an APK for ARM64 and
x86-64 and publishes the `linscp-android-debug` artifact. It does not create a
release-signed APK or AAB.
