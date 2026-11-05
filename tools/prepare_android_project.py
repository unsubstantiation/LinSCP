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
