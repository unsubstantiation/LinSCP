#!/usr/bin/env python3
"""The version scheme: one date-derived version, no bypassed hyphens.

LinSCP dropped the arbitrary 0.1.0 / 1.0-7 version numbers for the date of
the build. This test keeps every place that carries a version on the scheme,
so a release cannot ship half a stale one:

* the user-visible build stamp (injected by ui/scripts/build.mjs into the
  page as window.LinSCPBuildVersion) is VYYYY-MM-DD-HH-MM, Alaska Standard
  Time (UTC-9, fixed), minutes precision - the minute the build ran, or the
  minute SOURCE_DATE_EPOCH names;
* the crate workspace, the Tauri bundle, the frontend package and the CMake
  project carry the same date-based semver (YYYY.M.D, no leading zeros);
* the Debian package carries the same date plus the HHMM of the top changelog
  entry, dots only - Debian's grammar allows exactly one hyphen, which the
  scheme does not consume, so the changelog is a native-style version.

What this test deliberately does not do is pin the *value*: the date moves.
It pins the shape, and that all the carriers agree with each other.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

SEMVER_DATE = re.compile(r'^([1-9]\d*)\.(\d{1,2})\.(\d{1,2})$')
DEB_TOP = re.compile(r'^linscp \((\d{4})\.(\d{1,2})\.(\d{1,2})\.(\d{2})(\d{2})\) unstable; urgency=', re.M)


def cargo_workspace_version():
    text = (ROOT / 'Cargo.toml').read_text(encoding='utf-8')
    match = re.search(r'(?m)^\[workspace\.package\]\s*\nversion = "([^"]+)"', text)
    assert match, 'Cargo.toml has no [workspace.package] version'
    return match.group(1)


def date_semver_parts(version):
    match = SEMVER_DATE.match(version)
    assert match, f'not a date-based semver (YYYY.M.D): {version!r}'
    year, month, day = (int(part) for part in match.groups())
    assert 1970 <= year and 1 <= month <= 12 and 1 <= day <= 31, version
    # Semver forbids leading zeros in numeric identifiers.
    assert match.group(2) == str(int(match.group(2))), f'leading zero in {version!r}'
    assert match.group(3) == str(int(match.group(3))), f'leading zero in {version!r}'
    return year, month, day


class BuildVersionTests(unittest.TestCase):
    def test_cargo_workspace_version_is_date_semver(self):
        date_semver_parts(cargo_workspace_version())

    def test_tauri_bundle_version_matches_cargo(self):
        config = json.loads((ROOT / 'crates/linscp-tauri/tauri.conf.json').read_text(encoding='utf-8'))
        self.assertEqual(config['version'], cargo_workspace_version())

    def test_frontend_package_versions_match_cargo(self):
        package = json.loads((ROOT / 'ui/package.json').read_text(encoding='utf-8'))
        self.assertEqual(package['version'], cargo_workspace_version())
        lock = json.loads((ROOT / 'ui/package-lock.json').read_text(encoding='utf-8'))
        self.assertEqual(lock['version'], cargo_workspace_version())
        self.assertEqual(lock['packages']['']['version'], cargo_workspace_version())

    def test_cmake_project_version_matches_cargo(self):
        cmake = (ROOT / 'CMakeLists.txt').read_text(encoding='utf-8')
        match = re.search(r'project\(LinSCP VERSION ([0-9.]+) LANGUAGES NONE\)', cmake)
        self.assertIsNotNone(match, 'CMake project() carries no version')
        self.assertEqual(match.group(1), cargo_workspace_version())

    def test_debian_changelog_top_is_date_dots_no_hyphen(self):
        changelog = (ROOT / 'debian/changelog').read_text(encoding='utf-8')
        top = changelog.split('\n\n', 1)[0] + '\n'
        self.assertNotIn('-', top.splitlines()[0].split('(', 1)[1].split(')', 1)[0],
                         "Debian's single hyphen is reserved and the scheme skips it")
        match = DEB_TOP.search(top)
        self.assertIsNotNone(match, 'the top changelog entry is not a date-stamped native version')
        year, month, day, hour, minute = (int(part) for part in match.groups())
        self.assertEqual((year, month, day), date_semver_parts(cargo_workspace_version()))
        self.assertLess(hour, 24)
        self.assertLess(minute, 60)

    def test_no_stale_placeholder_versions_remain(self):
        for relative in ('Cargo.toml', 'crates/linscp-tauri/tauri.conf.json',
                         'ui/package.json', 'ui/package-lock.json'):
            text = (ROOT / relative).read_text(encoding='utf-8')
            for version in ('0.1.0', '1.0-7'):
                self.assertNotIn(f'"{version}"', text, f'{relative} still carries {version}')
        cmake = (ROOT / 'CMakeLists.txt').read_text(encoding='utf-8')
        self.assertNotIn('VERSION 1.0 ', cmake)


if __name__ == '__main__':
    unittest.main()
