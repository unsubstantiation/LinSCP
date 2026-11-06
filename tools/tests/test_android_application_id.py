"""The Android application ID has one definition, and everything reads it there.

The identifier in `crates/linscp-tauri/tauri.conf.json` is the Android
`applicationId`: Tauri derives the Gradle project, the `MainActivity` package
and the app's private data directory from it. The emulator harness launches the
activity by name and the smoke test checks which storage the app is using, so a
copy of the string in either place survives a rename in the other - and the
symptom is a "the app did not start" failure rather than a wrong package.

The ID is a product decision, so it is asserted here by value: changing it has
to be a deliberate edit of this test as well, not a side effect.
"""
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from android_application_id import application_id  # noqa: E402

EXPECTED = 'com.fairuniversal.linscp'


class AndroidApplicationIdTests(unittest.TestCase):
    def test_the_identifier_is_the_expected_package(self):
        self.assertEqual(application_id(), EXPECTED)

    def test_the_identifier_is_a_valid_java_package(self):
        self.assertRegex(EXPECTED, r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$')

    def test_the_identifier_is_defined_once(self):
        # Every tool that addresses the installed app reads the helper instead
        # of repeating the string; only the configuration and this test name it.
        readers = ['tools/android_emulator_smoke.sh',
                   'tools/android_emulator_smoke.mjs',
                   'tools/verify_android_apk.py',
                   'tools/prepare_android_project.py']
        for name in readers:
            text = (ROOT / name).read_text(encoding='utf-8')
            self.assertNotIn(EXPECTED, text, f'{name} repeats the application ID')
        config = json.loads((ROOT / 'crates/linscp-tauri/tauri.conf.json').read_text())
        self.assertEqual(config['identifier'], EXPECTED)

    def test_the_android_harness_passes_the_identifier_to_the_smoke_test(self):
        harness = (ROOT / 'tools/android_emulator_smoke.sh').read_text(encoding='utf-8')
        self.assertIn('tools/android_application_id.py', harness)
        # The activity, `pidof` and the smoke test all take it from the shell
        # variable, so none of them can address a package of their own.
        self.assertIn('am start -n', harness)
        self.assertIn('pidof', harness)
        application = chr(36) + 'application'          # "$application"
        self.assertGreaterEqual(harness.count(application), 3, harness)
        smoke = (ROOT / 'tools/android_emulator_smoke.mjs').read_text(encoding='utf-8')
        self.assertIn('JSON.stringify(application)', smoke)
        self.assertIn('process.argv[3]', smoke)

    def test_the_apk_check_rejects_a_stale_generated_package(self):
        check = (ROOT / 'tools/verify_android_apk.py').read_text(encoding='utf-8')
        self.assertIn('application_id()', check)
        self.assertIn('manifest_package', check)
        self.assertIn('regenerate the', check)
        prepare = (ROOT / 'tools/prepare_android_project.py').read_text(encoding='utf-8')
        self.assertIn('application_id()', prepare)
        self.assertIn('applicationId', prepare)
        self.assertIn('applicationIdSuffix', prepare)

    def test_the_emulator_harness_checks_the_install_directory_on_the_device(self):
        # The package name in the configuration only decides the install
        # directory if the built APK carries it, so the harness asks the device
        # which directory belongs to the running package and looks for a file
        # the app wrote there. Nothing in this check comes from the repository's
        # own configuration, so a build installed under another name fails.
        harness = (ROOT / 'tools/android_emulator_smoke.sh').read_text(encoding='utf-8')
        self.assertIn('cmd package list packages', harness)
        self.assertIn('run-as', harness)
        self.assertIn('android-smoke-marker.txt', harness)
        smoke = (ROOT / 'tools/android_emulator_smoke.mjs').read_text(encoding='utf-8')
        self.assertIn('android-smoke-marker.txt', smoke)
        # The root the service reported and the directory the device reports for
        # the installed package have to be the same path.
        self.assertIn('process.argv[4]', smoke)
        self.assertIn('"$app_root" != "$sandbox"', harness)
        # `/data/user/0/<application ID>` is the install directory, assembled
        # from the variable, never typed out.
        self.assertIn('/data/user/0/$application', harness)
        self.assertIn('Not using app-private storage', smoke)

    def test_no_configuration_moves_the_install_directory(self):
        # `appDirectoriesOverride` would relocate the storage, and a debug
        # `applicationIdSuffix` would install under a different name than the
        # one asserted here. Neither is configured, so the folder keeps the
        # application ID's name in both debug and release builds.
        config = json.loads((ROOT / 'crates/linscp-tauri/tauri.conf.json').read_text())
        self.assertNotIn('appDirectoriesOverride', config.get('app', {}))
        android = config.get('bundle', {}).get('android', {})
        self.assertNotIn('debugApplicationIdSuffix', android)

    def test_the_docs_name_the_install_directory(self):
        docs = (ROOT / 'docs/android.md').read_text(encoding='utf-8')
        self.assertIn('/data/user/0/' + EXPECTED, docs)
        self.assertIn('app_data_dir', docs)

    def test_a_launcher_does_not_claim_the_old_identifier(self):
        # The desktop entries name executables, not the bundle identifier, so a
        # rename must not have left a launcher pointing at the old name.
        for name in ['debian/linscp.desktop', 'debian/linscp-web.desktop']:
            desktop = (ROOT / name).read_text(encoding='utf-8')
            self.assertNotIn('io.', desktop, name)
        self.assertIn('Exec=linscp-gui',
                      (ROOT / 'debian/linscp.desktop').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
