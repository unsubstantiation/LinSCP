# Experimental Android APK

The Android target builds the same Tauri WebView and Rust `CommanderService` as
the desktop application. This is an **experimental, debug-signed APK**, not a
production or Play Store release. Android support is incomplete:

- Only app-private storage is exposed. The Android Storage Access Framework,
  document picker, share intents and Downloads/shared storage are not wired in.
  Uninstalling the app removes app-private files and configuration.
- Background/foreground-service transfer survival and Android Keystore/biometric
  integration are not wired in. Keep the app open during transfers. The session
  master key is stored in the app sandbox, not backed by Android Keystore.
- Remote transfer restrictions and cleanup caveats in the main README still
  apply. Other native GUI actions remain incomplete; see the feature audit.
- The debug APK is signed with a development key. It is intended for testing,
  not distribution, updates to a release-signed installation, or sensitive data.

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
