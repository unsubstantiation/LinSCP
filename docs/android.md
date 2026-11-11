# Experimental Android APK

The Android target builds the same Tauri WebView and Rust `CommanderService` as
the desktop application. The APK CI publishes is an **experimental build signed
with the project's release key**: it installs, updates and can be sideloaded like
any other APK, but it is not a production or Play Store release (no AAB, no
upload). Android support is incomplete:

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
  integrations. `linscp-gui --install-shell-integration` is one of those
  differences: it writes per-user file-manager menus into an XDG data directory,
  which Android has neither of, so the command refuses by name ("available on
  Linux and Windows only") rather than creating directories inside the sandbox.
  The receiving half is shared: a Share Sheet selection and a desktop
  `--shell-upload` end up in the same pending manifest, offered by the same
  confirmation dialog.
- Remote transfer restrictions and cleanup caveats in the main README still
  apply. The shared GUI actions listed in the native feature audit are routed
  through the service, but some remain protocol-limited or lack Android
  end-to-end coverage; see that audit before relying on them.
- The published APK is a **release** build: R8-minified, not debuggable, and
  signed with the release keystore (see [Signing](#signing)). A debug build -
  still signed with the development key - is used only by CI, where the
  emulator smoke test needs the WebView DevTools endpoint that a release build
  deliberately does not expose.

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

## Signing

Tauri's Android template configures no signing at all, so `tauri android build`
without `--debug` writes `app-release-unsigned.apk`: an APK no device installs
and whose bytes anything can replace. `tools/android_release_signing.py` fills
that gap. It decodes the keystore from the environment, refuses bytes that are
not a keystore, a keystore the password does not open, or an alias that is not a
private key, and writes the two files Gradle needs into the generated (ignored)
project:

```
crates/linscp-tauri/gen/android/linscp-release.jks       the keystore, mode 0600
crates/linscp-tauri/gen/android/app/keystore.properties  storeFile, storePassword, keyAlias, keyPassword
```

It also patches `signingConfigs { create("release") { … } }` and
`signingConfig = signingConfigs.getByName("release")` into
`app/build.gradle.kts`. The patch is anchored on the template it expects, so a
Tauri template that moves fails the build instead of quietly producing an
unsigned release. The debug build type keeps the development key.

| Environment variable | Meaning |
| --- | --- |
| `ANDROID_KEYSTORE_BASE64` | required; base64 of the `.jks`/`.keystore` file itself |
| `ANDROID_KEYSTORE_PASSWORD` | required; the keystore password |
| `ANDROID_KEY_ALIAS` | optional; when unset, the single private-key entry is used |
| `ANDROID_KEY_PASSWORD` | optional; defaults to the store password |

GitHub Actions keeps the first two as secrets of the **`android-release`**
environment, which the build job names (`environment: android-release`) so that
no other run can reach the key that signs the app users install. An empty
secret fails the signing step before the build starts.

A maintainer creates the keystore once, outside the repository, and pastes its
base64 into the environment secret:

```sh
keytool -genkeypair -v -keystore linscp-release.jks -alias linscp \
  -keyalg RSA -keysize 4096 -validity 10000 \
  -dname "CN=LinSCP, O=Fair Universal"
base64 -w0 linscp-release.jks        # ANDROID_KEYSTORE_BASE64
```

That file and its password are the only things that can sign an update an
existing installation accepts: lose them and the next APK is, to Android, a
different app whose users have to uninstall first. Back them up, and keep them
out of the repository - `.gitignore` refuses `*.jks`, `*.keystore`, `*.p12`,
`*.pfx` and `keystore.properties`, and the generated `gen/android` project they
are written into is ignored as a whole.

`tools/verify_android_apk.py --build-type release` then checks the output
against the keystore rather than trusting the build that produced it: the
package is the configured application ID, each requested ABI carries an
`index.html`-embedding `liblinscp_tauri.so`, the APK is **not**
`application-debuggable`, `apksigner` accepts it under the v2 scheme, and the
signing certificate's SHA-256 digest is the one `keytool` reports for the
configured alias. An APK signed with the debug key, or with any other key, fails
the run.

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
cd ../..
python3 tools/prepare_android_project.py
python3 tools/android_release_signing.py     # reads the signing environment above
cd crates/linscp-tauri
npm run tauri -- android build --ci --apk true --aab false --target aarch64 x86_64 --features native-shell
cd ../..
python3 tools/verify_android_apk.py --build-type release
```

The Android Gradle project under `gen/android` is generated and ignored; the
pinned Tauri CLI version is in `ui/package-lock.json`. The preparation script
turns off Android backup so the app-private session key and settings are not
silently included in Android backups. Generate a fresh project when changing
Tauri CLI versions. The signed APK is the `universal` flavor Tauri's Gradle
plugin defines for the requested ABIs:
`gen/android/app/build/outputs/apk/universal/release/app-universal-release.apk`.

Adding `--debug` to the build command instead produces the debuggable APK the
emulator smoke test runs against, signed with the development key:

```sh
npm run tauri -- android build --ci --debug --apk true --aab false --target aarch64 x86_64 --features native-shell
```

The Android GitHub Actions workflow runs on every push to `master` - and by
hand, from the Actions tab or `gh workflow run "Android build" --ref <branch>`,
which is how a branch is built before it is merged - and builds, verifies and
publishes `android-artifacts/linscp-android-release.apk` as the
`linscp-android-release` artifact. It then builds an x86-64 debug APK, exercises
the WebView, Rust IPC and WebDAV transfers on an emulator through the debug
build's DevTools endpoint, and finally installs the release APK itself with
`tools/android_release_launch_check.sh`, which proves it starts, keeps running,
is not debuggable and installs under the configured application ID. It does not
create an AAB.

### A granted folder, on a real device

The emulator run above proves the app reaches its own private storage through
Rust. It says nothing about a folder the user granted, because a Storage Access
Framework tree is handed over by a system picker that no harness can click - so
every `platform.android-saf-*` capability is evidenced only against an
in-memory mock in `crates/linscp-service`.

`tools/android_saf_smoke.sh` closes that gap by starting from a grant that
already exists. It runs on any device or emulator with the app installed and a
folder already granted, which makes the provider real and the run reproducible:
the same device and the same permission produce the same result every time.

```sh
adb devices                                    # one device, unlocked, trusted
adb shell mkdir -p /sdcard/Documents/linscp-saf
adb push some-file.txt /sdcard/Documents/linscp-saf/
# launch the app, add that folder with the local-root switcher's system picker
python3 tools/run_cargo_ci.py bash tools/android_saf_smoke.sh
```

The suite reads the granted tree back from the service rather than being told a
URI, so a misspelt or stale URI cannot pass, and it asserts that the root the
service enumerates is the one the picker granted. It then opens a local tab on
that folder and drives the same routes the page uses - list, mkdir, save, read
back, the stale-mtime refusal, delete - which is what the four
`platform.android-saf-*` rows describe.

Three properties make it safe to run against a phone with your own files on it:
it creates one folder named `linscp-saf-<timestamp>` and keeps every write
inside it; a device with no grant is a skip rather than a failure, because
nobody granting a folder is a fact about the device and not a defect in the
build; and it never clicks the picker, so it cannot wander into a folder you did
not choose.

`tools/tests/test_android_saf_smoke.py` keeps it honest without a device. It
checks that every route the harness calls is a real service route, that no write
escapes the run folder, and that the ledger rows it claims to evidence still
carry the provider gap - so upgrading a row without updating the suite fails.
