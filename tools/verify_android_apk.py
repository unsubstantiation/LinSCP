#!/usr/bin/env python3
"""Reject fake, unsigned, wrong-architecture or wrong-package Android APKs.

The build type decides what "signed" has to mean:

- `debug` is the APK the emulator smoke test drives through its WebView
  DevTools endpoint, so it has to be a debuggable build of the configured
  package - otherwise the harness is testing something other than what it
  claims to.
- `release` is the artifact that ships. It has to carry the release
  certificate from the configured keystore and it must *not* be debuggable: a
  release APK signed with a development key cannot be updated by a properly
  signed one later, and a debuggable one exposes its WebView to whoever can
  reach adb.

Usage:
    python3 tools/verify_android_apk.py [--build-type debug|release] [--abi ABI ...]
"""
import argparse
import os
import pathlib
import re
import shutil
import subprocess
import sys
import zipfile

from android_application_id import application_id
from android_release_signing import (
    KEYALIAS, STOREFILE, STOREPASSWORD, certificate_digest, read_signing_properties)

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Cargo target names and the ABI directory Android packs each library into.
ABI_LIBRARIES = {
    'aarch64': 'arm64-v8a',
    'armv7': 'armeabi-v7a',
    'i686': 'x86',
    'x86_64': 'x86_64',
}
DEFAULT_ABIS = ('aarch64', 'x86_64')


def sdk_tool(name):
    """The newest `name` in the SDK's build-tools, whatever version it is."""
    sdk = os.environ.get('ANDROID_HOME', '')
    if not sdk:
        raise SystemExit(
            'ANDROID_HOME is not set; the APK is checked with the SDK\'s own '
            'aapt2 and apksigner (tools/prepare_android_sdk.sh exports it)')
    candidates = sorted((pathlib.Path(sdk) / 'build-tools').glob(f'*/{name}'), reverse=True)
    if not candidates:
        raise SystemExit(f'No {name} in {sdk}/build-tools')
    return candidates[0]


def optional_sdk_tool(name):
    sdk = os.environ.get('ANDROID_HOME', '')
    candidates = sorted((pathlib.Path(sdk or '.') / 'build-tools').glob(f'*/{name}'),
                        reverse=True)
    return candidates[0] if sdk and candidates else None


def apk_manifest_package(apk):
    """The package name the APK declares, asked of the SDK's own tool.

    The manifest inside an APK is binary, so the answer comes from `aapt2` (or
    `aapt`) rather than from reading the file: a package name is not something
    to guess at from bytes.
    """
    tools = [tool for tool in (optional_sdk_tool('aapt2'), optional_sdk_tool('aapt'))
             if tool is not None]
    for tool in tools:
        result = subprocess.run([str(tool), 'dump', 'packagename', str(apk)],
                                capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().splitlines()[-1].strip()
        result = subprocess.run([str(tool), 'dump', 'badging', str(apk)],
                                capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if line.startswith('package:'):
                return line.split()[1].split('=')[1].strip("'\"")
    raise SystemExit('No aapt2/aapt in build-tools to read the APK package name')


def badging(apk):
    result = subprocess.run([str(sdk_tool('aapt2')), 'dump', 'badging', str(apk)],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f'aapt2 could not read {apk.name}: {result.stderr.strip()}')
    return result.stdout


def signature(apk):
    """`apksigner verify` output for the APK, refusing one that does not verify."""
    result = subprocess.run(
        [str(sdk_tool('apksigner')), 'verify', '--verbose', '--print-certs', str(apk)],
        capture_output=True, text=True)
    if result.returncode != 0:
        detail = (result.stdout + result.stderr).strip().splitlines()
        raise SystemExit(
            f'{apk.name} is not signed by a key Android would accept: '
            + (' / '.join(line for line in detail[-3:]) or 'no output'))
    return result.stdout


def signer_digest(apksigner_output):
    found = re.search(r'Signer #1 certificate SHA-256 digest: ([0-9a-fA-F]+)',
                      apksigner_output)
    if not found:
        raise SystemExit('apksigner printed no signer certificate digest')
    return found.group(1).lower()


def expected_release_digest():
    """The certificate the release APK has to carry, from the keystore itself."""
    properties = read_signing_properties(
        ROOT / 'crates/linscp-tauri/gen/android/app/keystore.properties')
    if not properties or STOREFILE not in properties or STOREPASSWORD not in properties \
            or KEYALIAS not in properties:
        raise SystemExit(
            'The release APK has to be signed, but no signing configuration was '
            'found; run tools/android_release_signing.py (it reads '
            'ANDROID_KEYSTORE_BASE64 and ANDROID_KEYSTORE_PASSWORD) before the '
            'build')
    return certificate_digest(properties[STOREFILE], properties[STOREPASSWORD],
                              properties[KEYALIAS])


def inspect(apk, build_type, required, expected_digest):
    """Everything the APK has to prove about itself, or a SystemExit."""
    with zipfile.ZipFile(apk) as archive:
        names = set(archive.namelist())
        missing = [item for item in required if item not in names]
        if missing:
            print(f'Missing: {missing}; libraries: '
                  f'{[name for name in sorted(names) if name.endswith(".so")]}',
                  flush=True)
            return False
        if 'AndroidManifest.xml' not in names:
            raise SystemExit('APK is missing its Android manifest')
        # Tauri embeds frontend assets in the Rust library via custom-protocol.
        for name in required:
            library = archive.read(name)
            if len(library) < 100_000 or b'index.html' not in library:
                raise SystemExit(f'{name} is not a real app library with embedded UI')
    package = apk_manifest_package(apk)
    expected = application_id()
    if package != expected:
        raise SystemExit(
            f'{apk.name} is built as {package!r}, not {expected!r}; regenerate the '
            f'Android project after an identifier change')
    debuggable = 'application-debuggable' in badging(apk)
    if build_type == 'debug' and not debuggable:
        raise SystemExit(
            f'{apk.name} is not a debuggable build, so the emulator smoke test '
            f'cannot reach its WebView DevTools endpoint; build it with --debug')
    if build_type == 'release' and debuggable:
        raise SystemExit(
            f'{apk.name} is a debuggable build; a signed release APK must not be')
    apksigner_output = signature(apk)
    digest = signer_digest(apksigner_output)
    if build_type == 'release':
        if digest != expected_digest:
            raise SystemExit(
                f'{apk.name} is signed by certificate {digest}, not by the '
                f'release certificate {expected_digest} of the configured '
                f'keystore; the APK was signed with some other key')
        if 'Verified using v2 APK Signature Scheme v2: true' not in apksigner_output:
            raise SystemExit(
                f'{apk.name} is not signed with the v2 scheme; Android 7+ '
                f'expects it and the app updates would not verify')
        print(f'Signed by the release certificate {digest}', flush=True)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-type', choices=('debug', 'release'), default='debug',
                        help='which Gradle build type to inspect (default: debug)')
    parser.add_argument('--abi', action='append', choices=sorted(ABI_LIBRARIES),
                        help='an ABI the APK must carry (default: '
                             + ' and '.join(DEFAULT_ABIS) + ')')
    arguments = parser.parse_args()
    abis = arguments.abi or list(DEFAULT_ABIS)
    required = [f'lib/{ABI_LIBRARIES[abi]}/liblinscp_tauri.so' for abi in abis]
    outputs = ROOT / 'crates/linscp-tauri/gen/android/app/build/outputs/apk'
    apks = sorted(path for path in outputs.rglob('*.apk')
                  if arguments.build_type in path.parts)
    if not apks:
        raise SystemExit(f'No {arguments.build_type} APK found in {outputs}')
    expected_digest = expected_release_digest() if arguments.build_type == 'release' else None
    for apk in apks:
        print(f'Inspecting {apk}', flush=True)
        if not inspect(apk, arguments.build_type, required, expected_digest):
            continue
        destination = ROOT / f'android-artifacts/linscp-android-{arguments.build_type}.apk'
        destination.parent.mkdir(exist_ok=True)
        shutil.copyfile(apk, destination)
        print(f'Verified {destination}', flush=True)
        return 0
    raise SystemExit(
        'No ' + arguments.build_type + ' APK with these architectures was found: '
        + ' '.join(abis))


if __name__ == '__main__':
    sys.exit(main())
