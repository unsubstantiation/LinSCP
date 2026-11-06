# Experimental Android APK

The Android target builds the same Tauri WebView and Rust `CommanderService` as
the desktop application. This is an **experimental, debug-signed APK**, not a
production or Play Store release. Android support is incomplete:

- Only app-private storage is exposed. The Rust shell contains the Storage
  Access Framework and share-hand-off command contracts
  (`linscp_request_saf_tree`, `linscp_pick_saf_tree`,
  `linscp_handle_share_intent`), but this repository does not register their
  Kotlin implementations, picker activity result, or share intent filter.
  Android capability detection therefore keeps folder grants and share intents
  disabled instead of presenting controls that fail when used. Downloads/shared
  storage is not exposed. Uninstalling the app removes app-private files and
  configuration.
- Background/foreground-service transfer survival and Android Keystore/biometric
  integration are not wired in. The Rust shell exposes foreground-service
  commands, but no Android service implements them. The page now keeps these
  capabilities disabled unless an embedder explicitly reports a real
  implementation; keep the app open during transfers. The session master key
  is stored in the app sandbox, not backed by Android Keystore.
- The page no longer probes the native bridge at each call site. One
  `hostCapabilities()` description drives host-dependent controls. Android-only
  integrations stay off until explicitly enabled by a host that has registered
  them; desktop launchers and OS drop listeners are desktop-only. A control the
  current host cannot serve is omitted with the reason
  `hostDifferenceReason()` provides. This prevents false capability claims; it
  does not establish feature parity while the integrations remain unimplemented.
- Remote transfer restrictions and cleanup caveats in the main README still
  apply. Other native GUI actions remain incomplete; see the feature audit.
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
