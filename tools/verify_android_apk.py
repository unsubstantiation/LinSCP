#!/usr/bin/env python3
"""Reject fake, unsigned, or wrong-architecture Android APK artifacts."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import zipfile

root = Path(__file__).resolve().parents[1]
outputs = root / 'crates/linscp-tauri/gen/android/app/build/outputs/apk'
apks = sorted(outputs.rglob('*.apk'))
if not apks:
    raise SystemExit(f'No APK found in {outputs}')
required = ['lib/arm64-v8a/liblinscp_tauri.so', 'lib/x86_64/liblinscp_tauri.so']
for apk in apks:
    print(f'Inspecting {apk}', flush=True)
    with zipfile.ZipFile(apk) as archive:
        names = set(archive.namelist())
        missing = [item for item in required if item not in names]
        if missing:
            print(f'Missing: {missing}; libraries: {[name for name in sorted(names) if name.endswith(".so")]}', flush=True)
            continue
        if 'AndroidManifest.xml' not in names:
            raise SystemExit('APK is missing its Android manifest')
        # Tauri embeds frontend assets in the Rust library via custom-protocol.
        for name in required:
            lib = archive.read(name)
            if len(lib) < 100_000 or b'index.html' not in lib:
                raise SystemExit(f'{name} is not a real app library with embedded UI')
    sdk = Path(os.environ['ANDROID_HOME'])
    subprocess.run([str(sdk / 'build-tools/36.0.0/apksigner'), 'verify', '--verbose', str(apk)], check=True)
    destination = root / 'android-artifacts/linscp-android-debug.apk'
    destination.parent.mkdir(exist_ok=True)
    shutil.copyfile(apk, destination)
    print(f'Verified {destination}', flush=True)
    sys.exit(0)
raise SystemExit('No universal APK with both requested architectures was found')
