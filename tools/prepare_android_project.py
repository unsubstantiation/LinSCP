#!/usr/bin/env python3
"""Apply the small, security-critical customizations to Tauri's pinned template."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
manifest = root / 'crates/linscp-tauri/gen/android/app/src/main/AndroidManifest.xml'
text = manifest.read_text()
if text.count('<application') != 1 or 'android:allowBackup=' in text:
    raise SystemExit('Unexpected Tauri Android manifest; review backup policy')
text = text.replace('<application', '<application\n        android:allowBackup="false"', 1)
manifest.write_text(text)

activities = list((root / 'crates/linscp-tauri/gen/android/app/src/main').rglob('MainActivity.kt'))
if len(activities) != 1:
    raise SystemExit('Unexpected Tauri Android activity layout')
activity = activities[0]
text = activity.read_text()
needle = 'super.onCreate(savedInstanceState)'
if text.count(needle) != 1:
    raise SystemExit('Unexpected Tauri activity; review debug WebView inspection')
# A debug-only DevTools endpoint lets CI verify the actual WebView-to-Rust IPC.
text = text.replace(needle, 'if (BuildConfig.DEBUG) android.webkit.WebView.setWebContentsDebuggingEnabled(true)\n        ' + needle)
activity.write_text(text)

# The plugin is compiled as part of the generated Android app.
storage = root / 'crates/linscp-tauri/android/StoragePlugin.kt'
(activities[0].parent / 'StoragePlugin.kt').write_text(storage.read_text())
