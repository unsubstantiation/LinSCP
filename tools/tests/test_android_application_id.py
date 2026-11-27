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
import re
import sys
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

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

    def test_android_native_bridge_is_copied_and_registered(self):
        source = ROOT / 'crates/linscp-tauri/android/LinSCPAndroidPlugin.kt'
        self.assertTrue(source.is_file())
        kotlin = source.read_text(encoding='utf-8')
        for command in ['pickTree', 'grantedTrees', 'listTree', 'statUri', 'readUri',
                        'readUriChunk', 'writeUri', 'beginWriteUri', 'appendUriChunk',
                        'mkdirUri', 'deleteUri', 'renameUri',
                        'stageUris', 'takePendingShares', 'openExternalUri',
                        'foregroundStart', 'foregroundUpdate', 'foregroundStop']:
            self.assertIn('fun ' + command + '(', kotlin)
        self.assertIn('"rdp", "vnc", "spice"', kotlin)
        self.assertIn('commands::linscp_open_external_uri',
                      (ROOT / 'crates/linscp-tauri/src/lib.rs').read_text(encoding='utf-8'))
        rust_bridge = (ROOT / 'crates/linscp-tauri/src/android.rs').read_text(encoding='utf-8')
        self.assertIn('use super::AndroidState;', rust_bridge)
        self.assertIn('set_external_uri(bridge.clone())', rust_bridge)
        smoke = (ROOT / 'tools/android_emulator_smoke.mjs').read_text(encoding='utf-8')
        self.assertIn("'linscp_open_external_uri'", smoke)
        self.assertIn('unsafeUriRejected', smoke)
        page = (ROOT / 'source/gui/web/index.html').read_text(encoding='utf-8')
        self.assertIn('LinSCPCore.androidDesktopViewerUri(kind, endpoint, !!data.tunneled)', page)
        self.assertIn("androidViewers.includes(option.value)", page)
        self.assertIn("kindSelect.value = 'rdp'", page)
        # Content providers may block for remote/cloud-backed documents. Keep
        # their work off the Activity thread and marshal only the result back.
        for command in ['grantedTrees', 'listTree', 'statUri', 'readUri',
                        'readUriChunk', 'writeUri', 'beginWriteUri', 'appendUriChunk',
                        'mkdirUri', 'deleteUri', 'renameUri', 'stageUris']:
            match = re.search(
                r'fun ' + command + r'\(invoke: Invoke\) \{(.*?)(?=\n  @Command|\n  private fun)',
                kotlin, re.DOTALL)
            self.assertIsNotNone(match, command)
            self.assertIn('runIo(invoke,', match.group(1), command)
        # Resolution may query a DocumentsProvider and throw (for example if
        # a grant was revoked). It must run inside the error-catching I/O
        # worker, not synchronously before it starts.
        for command in ['readUri', 'readUriChunk']:
            match = re.search(
                r'fun ' + command + r'\(invoke: Invoke\) \{(.*?)(?=\n  @Command|\n  private fun)',
                kotlin, re.DOTALL)
            body = match.group(1)
            self.assertLess(body.index('runIo(invoke,'), body.index('resolveDocument('), command)
        self.assertIn('activity.runOnUiThread', kotlin)
        self.assertIn('synchronized(stageLock)', kotlin)
        self.assertIn('Thread({', kotlin[kotlin.index('private fun stageShareIntent'):])
        prepare = (ROOT / 'tools/prepare_android_project.py').read_text(encoding='utf-8')
        self.assertIn('plugin_source', prepare)
        self.assertIn('android.intent.action.SEND_MULTIPLE', prepare)
        self.assertIn('LinSCPTransferService', prepare)
        host = (ROOT / 'crates/linscp-tauri/src/lib.rs').read_text(encoding='utf-8')
        self.assertIn('android::mobile_plugin()', host)

    def test_outgoing_share_provider_is_private_and_prepare_is_idempotent(self):
        # Exercise the real preparation script against a disposable generated
        # project, not just a string assertion about what it might produce.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name in ['tools/prepare_android_project.py', 'tools/android_application_id.py',
                         'crates/linscp-tauri/tauri.conf.json', 'crates/linscp-tauri/android/LinSCPAndroidPlugin.kt']:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            app = root / 'crates/linscp-tauri/gen/android/app'
            manifest = app / 'src/main/AndroidManifest.xml'
            manifest.parent.mkdir(parents=True)
            manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />
    <application>
        <activity android:name=".MainActivity"></activity>
    </application>
</manifest>''')
            (app / 'build.gradle.kts').write_text(f'applicationId = "{EXPECTED}"\n')
            activity = app / 'src/main/java' / pathlib.Path(*EXPECTED.split('.')) / 'MainActivity.kt'
            activity.parent.mkdir(parents=True, exist_ok=True)
            activity.write_text('super.onCreate(savedInstanceState)\n')
            command = [sys.executable, str(root / 'tools/prepare_android_project.py')]
            for _ in range(2):
                subprocess.run(command, check=True, capture_output=True, text=True)
            android = '{http://schemas.android.com/apk/res/android}'
            manifest_root = ET.parse(manifest).getroot()
            permissions = manifest_root.findall('uses-permission')
            names = [item.get(android + 'name') for item in permissions]
            self.assertEqual(names.count('android.permission.USE_BIOMETRIC'), 1)
            self.assertEqual(names.count('android.permission.USE_FINGERPRINT'), 1)
            fingerprint = next(item for item in permissions if item.get(android + 'name') == 'android.permission.USE_FINGERPRINT')
            self.assertEqual(fingerprint.get(android + 'maxSdkVersion'), '28')
            main_activity = manifest_root.find('application').find('activity')
            config_changes = set((main_activity.get(android + 'configChanges') or '').split('|'))
            for required_flag in ('orientation', 'keyboardHidden', 'keyboard', 'screenSize',
                                  'locale', 'smallestScreenSize', 'screenLayout',
                                  'uiMode', 'navigation', 'density', 'fontScale', 'layoutDirection'):
                self.assertIn(required_flag, config_changes)
            self.assertEqual(main_activity.get(android + 'launchMode'), 'singleTask')
            providers = manifest_root.find('application').findall('provider')
            self.assertEqual(len(providers), 1)
            provider = providers[0]
            self.assertEqual(provider.get(android + 'name'), '.LinSCPExportProvider')
            self.assertEqual(provider.get(android + 'exported'), 'false')
            self.assertEqual(provider.get(android + 'grantUriPermissions'), 'true')
            self.assertEqual(provider.get(android + 'authorities'), '${applicationId}.outgoing')
            paths = ET.parse(app / 'src/main/res/xml/linscp_outgoing_files.xml').getroot()
            self.assertEqual([(item.tag, item.get('path')) for item in paths], [('cache-path', 'outgoing-shares/')])
            # A pre-existing provider that weakens the policy must fail closed.
            manifest.write_text(manifest.read_text().replace('android:exported="false"\n            android:grantUriPermissions', 'android:exported="true"\n            android:grantUriPermissions'))
            rejected = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
            self.assertIn('Invalid outgoing share provider', rejected.stderr)

    def test_outgoing_share_uses_read_grants_and_an_isolated_cache(self):
        kotlin = (ROOT / 'crates/linscp-tauri/android/LinSCPAndroidPlugin.kt').read_text(encoding='utf-8')
        for command in ['prepareExport', 'stageLocalExport', 'openExport', 'discardExport']:
            self.assertIn('fun ' + command + '(invoke: Invoke)', kotlin)
        self.assertIn('class LinSCPExportProvider : FileProvider()', kotlin)
        self.assertIn('FileProvider.getUriForFile', kotlin)
        self.assertIn('Intent.ACTION_SEND_MULTIPLE', kotlin)
        self.assertIn('ClipData.Item(it)', kotlin)
        self.assertIn('Intent.FLAG_GRANT_READ_URI_PERMISSION', kotlin)
        export_section = kotlin[kotlin.index('private fun cleanupOldExports'):kotlin.index('fun foregroundStart')]
        self.assertNotIn('FLAG_GRANT_WRITE_URI_PERMISSION', export_section)
        self.assertIn('batch.absolutePath !in activeExports', export_section)
        self.assertIn('batch.setLastModified', export_section)
        self.assertIn('resolveDocument(uri)', export_section)
        host = (ROOT / 'crates/linscp-tauri/src/lib.rs').read_text(encoding='utf-8')
        self.assertIn('if result.is_err() { let _ = bridge.discard_export(&batch); }', host)
        self.assertIn('state.service.stage_remote_share', host)
        service = (ROOT / 'crates/linscp-service/src/share_export.rs').read_text(encoding='utf-8')
        self.assertIn('pub const MAX_EXPORT_BYTES', service)
        self.assertIn('struct LimitedWriter', service)

    def test_the_android_workflow_installs_the_cli_and_builds_the_frontend(self):
        # `tauri android init` runs the locally installed Tauri CLI, and the APK
        # embeds `ui/dist`. A workflow that checks the application ID but no
        # longer installs either fails at the generation step, which says
        # nothing about the ID it was meant to check.
        workflow = (ROOT / '.github/workflows/android-build.yml').read_text(encoding='utf-8')
        self.assertIn('npm ci --prefix ui', workflow)
        self.assertIn('npm --prefix ui test', workflow)
        self.assertIn('tauri', workflow)

    def test_a_launcher_does_not_claim_the_old_identifier(self):
        # The desktop entries name executables, not the bundle identifier, so a
        # rename must not have left a launcher pointing at the old name.
        for name in ['debian/linscp.desktop']:
            desktop = (ROOT / name).read_text(encoding='utf-8')
            self.assertNotIn('io.', desktop, name)
        self.assertIn('Exec=linscp-gui',
                      (ROOT / 'debian/linscp.desktop').read_text(encoding='utf-8'))

    def test_foreground_service_declares_data_sync_type_timeout_and_resume_intent(self):
        kotlin = (ROOT / 'crates/linscp-tauri/android/LinSCPAndroidPlugin.kt').read_text(encoding='utf-8')
        self.assertIn('ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC', kotlin)
        self.assertIn('override fun onTimeout(startId: Int)', kotlin)
        self.assertIn('Intent.FLAG_ACTIVITY_SINGLE_TOP', kotlin)
        self.assertIn('PendingIntent.FLAG_IMMUTABLE', kotlin)
        page = (ROOT / 'source/gui/web/index.html').read_text(encoding='utf-8')
        self.assertIn('embeddedTerminal && embeddedTerminal.view', page)
        self.assertIn('restoreOpenInPageTerminal', page)

    def test_emulator_smoke_creates_resume_dir_under_app_root_after_subdir_list(self):
        # Listing `root + '/smoke-download'` without a tab updates the service's
        # tabless `current_local_dir`, so creating `smoke-resume` afterwards
        # must address the root tab (`{tab, name: 'smoke-resume'}`) rather than
        # silently creating `smoke-download/smoke-resume` and failing the `.filepart`
        # save with ENOENT (`os error 2`).
        smoke = (ROOT / 'tools/android_emulator_smoke.mjs').read_text(encoding='utf-8')
        subdir_list = smoke.index("encodeURIComponent(root + '/smoke-download')")
        partial_save = smoke.index("root + '/smoke-resume/smoke-upload.txt.filepart'")
        between = smoke[subdir_list:partial_save]
        self.assertIn("{tab, name: 'smoke-resume'}", between)
        self.assertNotIn("{name: 'smoke-resume'}", smoke)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed to parse the WebView smoke expression')
    def test_emulator_smoke_template_expands_to_valid_javascript(self):
        # Node's --check parses the outer template, not its interpolated
        # contents; escaped slashes and other template escapes can break only
        # after it is sent to the WebView. Compile representative expansions.
        script = r"""
const fs = require('fs'), vm = require('vm');
const source = fs.readFileSync('tools/android_emulator_smoke.mjs', 'utf8');
const match = source.match(/const expression = (`[\s\S]*?`);\nlet nextId/);
if (!match) throw new Error('Cannot find smoke expression');
const build = Function('phase', 'portableBackup', 'application', 'port', 'sshPort', 'fixtureKey', 'return ' + match[1]);
for (const phase of ['initial', 'portable-import', 'portable-reopen']) {
  new vm.Script(build(phase, {backupBase64: 'Zm9v', keyReference: 'vaultkey://abc'}, 'com.example.app', 8080, 2222, 'Zm9v'));
}
"""
        subprocess.run(['node', '-e', script], cwd=ROOT, check=True, capture_output=True, text=True)

    def test_android_navigation_bar_is_hidden_while_app_is_active(self):
        kotlin = (ROOT / 'crates/linscp-tauri/android/LinSCPAndroidPlugin.kt').read_text(encoding='utf-8')
        self.assertIn('internal fun hideAndroidNavigationBar(activity: Activity)', kotlin)
        self.assertIn('WindowCompat.getInsetsController(', kotlin)
        self.assertIn('WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE', kotlin)
        self.assertIn('controller.hide(WindowInsetsCompat.Type.navigationBars())', kotlin)
        self.assertNotIn('controller.hide(WindowInsetsCompat.Type.systemBars())', kotlin)
        self.assertNotIn('controller.hide(WindowInsetsCompat.Type.statusBars())', kotlin)
        self.assertIn('installNavigationBarInsetsGuard(webView)', kotlin)
        self.assertIn('WindowInsetsCompat.Type.ime()', kotlin)
        self.assertIn('addOnWindowFocusChangeListener', kotlin)

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name in ['tools/prepare_android_project.py', 'tools/android_application_id.py',
                         'crates/linscp-tauri/tauri.conf.json', 'crates/linscp-tauri/android/LinSCPAndroidPlugin.kt']:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            app = root / 'crates/linscp-tauri/gen/android/app'
            manifest = app / 'src/main/AndroidManifest.xml'
            manifest.parent.mkdir(parents=True)
            manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />
    <application>
        <activity android:name=".MainActivity"></activity>
    </application>
</manifest>''')
            (app / 'build.gradle.kts').write_text(f'applicationId = "{EXPECTED}"\n')
            activity = app / 'src/main/java' / pathlib.Path(*EXPECTED.split('.')) / 'MainActivity.kt'
            activity.parent.mkdir(parents=True, exist_ok=True)
            activity.write_text(
                f'package {EXPECTED}\n\n'
                'import android.os.Bundle\n'
                'import androidx.activity.enableEdgeToEdge\n\n'
                'class MainActivity : TauriActivity() {\n'
                '  override fun onCreate(savedInstanceState: Bundle?) {\n'
                '    enableEdgeToEdge()\n'
                '    super.onCreate(savedInstanceState)\n'
                '  }\n'
                '}\n'
            )
            command = [sys.executable, str(root / 'tools/prepare_android_project.py')]
            subprocess.run(command, check=True, capture_output=True, text=True)
            first_pass = activity.read_text(encoding='utf-8')
            subprocess.run(command, check=True, capture_output=True, text=True)
            second_pass = activity.read_text(encoding='utf-8')
            self.assertEqual(first_pass, second_pass)
            self.assertEqual(first_pass.count('hideAndroidNavigationBar(this)'), 3)
            self.assertIn('override fun onResume()', first_pass)
            self.assertIn('override fun onWindowFocusChanged(hasFocus: Boolean)', first_pass)


if __name__ == '__main__':
    unittest.main()
