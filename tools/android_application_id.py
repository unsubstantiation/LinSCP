#!/usr/bin/env python3
"""Print the Android application ID, read from the one place that defines it.

The identifier in `crates/linscp-tauri/tauri.conf.json` is the Android
`applicationId` (and the desktop bundle identifier): Tauri derives the
generated Gradle project, the Java package of `MainActivity` and the app's
private data directory from it. Anything that addresses the installed app -
the emulator harness launching the activity, the smoke test checking which
storage the app runs in, the APK check comparing the built package - therefore
has to read it here instead of repeating the string, or a rename leaves one of
them addressing an app that no longer exists.

Usage:
    python3 tools/android_application_id.py
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONFIG = ROOT / 'crates/linscp-tauri/tauri.conf.json'

# Java package rules: dot-separated segments, each starting with a letter.
PACKAGE = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$')


def application_id(config=CONFIG):
    """The configured identifier, refusing one that Android would not accept."""
    identifier = json.loads(pathlib.Path(config).read_text(encoding='utf-8')).get('identifier')
    if not isinstance(identifier, str) or not PACKAGE.match(identifier):
        raise SystemExit(
            f'{config} has no usable application identifier: {identifier!r}')
    return identifier


def main():
    print(application_id())
    return 0


if __name__ == '__main__':
    sys.exit(main())
