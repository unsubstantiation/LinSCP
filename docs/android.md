# Experimental Android APK

The Android target builds the same Tauri WebView and Rust `CommanderService` as
the desktop application. This is an **experimental, debug-signed APK**, not a
production or Play Store release. Android support is incomplete:

- Only app-private storage is exposed unless a folder is granted. The Storage
  Access Framework bridge and the share hand-off exist in the Rust shell
  (`linscp_request_saf_tree`, `linscp_pick_saf_tree`,
  `linscp_handle_share_intent`), but the generated Kotlin project has to register
  the picker and the intent filter for them to be reachable; until it does, a
  share or a folder grant fails closed instead of silently doing nothing.
  Downloads/shared storage is not exposed. Uninstalling the app removes
  app-private files and configuration.
- Background/foreground-service transfer survival and Android Keystore/biometric
  integration are not wired in. The page starts and stops the service from the
  transfer queue (`ForegroundTransferBridge`, gated on the `foregroundTransfers`
  capability) and the Rust shell exposes the three commands, but nothing
  implements the service itself yet, so the calls fail closed. Keep the app open
  during transfers. The session master key is stored in the app sandbox, not
  backed by Android Keystore.
- The page no longer probes the native bridge at each call site. One
  `hostCapabilities()` description drives the controls that differ between
  hosts (folder grants, share hand-offs, the foreground service, the OS drop
  listener), and a control this host cannot serve is left out with the reason
  `hostDifferenceReason()` gives.
- Remote transfer restrictions and cleanup caveats in the main README still
  apply. Other native GUI actions remain incomplete; see the feature audit.
- The debug APK is signed with a development key. It is intended for testing,
  not distribution, updates to a release-signed installation, or sensitive data.

## Application ID

The app is installed as **`com.fairuniversal.linscp`**, defined once in
`crates/linscp-tauri/tauri.conf.json` (`identifier`). Tauri derives the Gradle
`applicationId`, the `MainActivity` package and the app's private data directory
from it, so the emulator harness, the APK check and the smoke test all read it
through `tools/android_application_id.py` instead of repeating the string.
`tools/prepare_android_project.py` refuses a generated project whose
`applicationId` or `MainActivity` package disagrees, and
`tools/verify_android_apk.py` refuses an APK built under another name.

Two consequences of a rename are worth stating: the new package installs
*beside* an older build rather than updating it, and an older build's
app-private settings and stored sessions live under the old directory, so they
are not carried over — re-import or re-enter the sites you need, then uninstall
the old app. A generated `gen/android` project from before the rename must be
regenerated (`tauri android init`) or the build stops with the mismatch rather
than shipping the old name.

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
