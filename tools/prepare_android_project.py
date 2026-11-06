#!/usr/bin/env python3
"""Apply the small, security-critical customizations to Tauri's pinned template."""
from pathlib import Path

from android_application_id import application_id

root = Path(__file__).resolve().parents[1]
manifest = root / 'crates/linscp-tauri/gen/android/app/src/main/AndroidManifest.xml'
text = manifest.read_text()
if text.count('<application') != 1 or 'android:allowBackup=' in text:
    raise SystemExit('Unexpected Tauri Android manifest; review backup policy')
text = text.replace('<application', '<application\n        android:allowBackup="false"', 1)
manifest.write_text(text)

# The generated project carries the identifier Tauri read when it was created.
# A project generated before a rename would ship under the old name - and its
# existing installs would keep a data directory the new name never reads - so
# the two are compared instead of trusted, and the mismatch fails the build.
application = application_id()
gradle = root / 'crates/linscp-tauri/gen/android/app/build.gradle.kts'
if not gradle.is_file():
    raise SystemExit(f'The generated Gradle module is missing: {gradle}')
gradle_text = gradle.read_text()
if f'applicationId = "{application}"' not in gradle_text and \
        f'applicationId "{application}"' not in gradle_text:
    raise SystemExit(
        f'The generated Android project does not use the configured application '
        f'identifier {application}; regenerate it (tauri android init) after an '
        f'identifier change')
# A debug `applicationIdSuffix` would install the APK as a different package, and
# with it a different install directory, while the configuration kept naming the
# plain identifier. Tauri only writes one when the configuration asks for it.
if 'applicationIdSuffix' in gradle_text:
    raise SystemExit(
        'The generated Android project installs under a suffixed application ID, '
        'so its data directory would not be the configured identifier; remove '
        'bundle.android.debugApplicationIdSuffix and regenerate the project')
activities = list((root / 'crates/linscp-tauri/gen/android/app/src/main').rglob('MainActivity.kt'))
if len(activities) != 1:
    raise SystemExit('Unexpected Tauri Android activity layout')
activity = activities[0]
if application.replace('.', '/') not in str(activity).replace('\\', '/'):
    raise SystemExit(
        f'The generated MainActivity does not live under the package {application}')
text = activity.read_text()
needle = 'super.onCreate(savedInstanceState)'
if text.count(needle) != 1:
    raise SystemExit('Unexpected Tauri activity; review debug WebView inspection')
# A debug-only DevTools endpoint lets CI verify the actual WebView-to-Rust IPC.
text = text.replace(needle, 'if (BuildConfig.DEBUG) android.webkit.WebView.setWebContentsDebuggingEnabled(true)\n        ' + needle)
activity.write_text(text)
