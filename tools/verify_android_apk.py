#!/usr/bin/env python3
"""Reject fake, unsigned, wrong-architecture or wrong-package Android APKs."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import zipfile

from android_application_id import application_id

root = Path(__file__).resolve().parents[1]
# The identifier the APK has to carry. A package built from a stale generated
# project installs beside the real app and writes to a data directory nothing
# else reads, which the emulator harness then cannot tell apart from a failure.
expected = application_id()
outputs = root / 'crates/linscp-tauri/gen/android/app/build/outputs/apk'
apks = sorted(outputs.rglob('*.apk'))
if not apks:
    raise SystemExit(f'No APK found in {outputs}')
required = ['lib/arm64-v8a/liblinscp_tauri.so', 'lib/x86_64/liblinscp_tauri.so']


def manifest_package(apk):
    """The package name the APK declares, asked of the SDK's own tool.

    The manifest inside an APK is binary, so the answer comes from `aapt2` (or
    `aapt`) rather than from reading the file: a package name is not something
    to guess at from bytes.
    """
    sdk = Path(os.environ['ANDROID_HOME'])
    for tool in ('aapt2', 'aapt'):
        for candidate in sorted((sdk / 'build-tools').glob(f'*/{tool}'), reverse=True):
            result = subprocess.run([str(candidate), 'dump', 'packagename', str(apk)],
                                    capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip().splitlines()[-1].strip()
            result = subprocess.run([str(candidate), 'dump', 'badging', str(apk)],
                                    capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.startswith('package:'):
                    return line.split()[1].split('=')[1].strip("'\"")
    raise SystemExit('No aapt2/aapt in build-tools to read the APK package name')

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
        package = manifest_package(apk)
        if package != expected:
            raise SystemExit(
                f'{apk.name} is built as {package!r}, not {expected!r}; regenerate the '
                f'Android project after an identifier change')
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
