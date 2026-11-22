#!/usr/bin/env python3
"""Apply the small, security-critical customizations to Tauri's pinned template."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from android_application_id import application_id

REQUIRED_ACTIVITY_CONFIG_CHANGES = (
    'orientation',
    'keyboardHidden',
    'keyboard',
    'screenSize',
    'locale',
    'smallestScreenSize',
    'screenLayout',
    'uiMode',
    'navigation',
    'density',
)

root = Path(__file__).resolve().parents[1]
manifest = root / 'crates/linscp-tauri/gen/android/app/src/main/AndroidManifest.xml'
text = manifest.read_text()
if text.count('<application') != 1:
    raise SystemExit('Unexpected Tauri Android manifest; review backup policy')
if 'android:allowBackup=' in text:
    if 'android:allowBackup="false"' not in text:
        raise SystemExit('Android backup must remain disabled for the app-private vault')
else:
    text = text.replace('<application', '<application\n        android:allowBackup="false"', 1)
if 'android.permission.FOREGROUND_SERVICE_DATA_SYNC' not in text:
    internet_permission = '    <uses-permission android:name="android.permission.INTERNET" />'
    if internet_permission not in text:
        raise SystemExit('Unexpected Android manifest permissions; add foreground-service permissions')
    text = text.replace(internet_permission,
        internet_permission + '\n'
        '    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />\n'
        '    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />\n'
        '    <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />')
if text.count('android:name=".MainActivity"') != 1:
    raise SystemExit('Unexpected Android activity layout; review share intent filters')


def _ensure_main_activity_config_changes(match: re.Match[str]) -> str:
    tag = match.group(0)
    existing = re.search(r'android:configChanges="([^"]*)"', tag)
    tokens: list[str] = []
    if existing:
        for item in existing.group(1).split('|'):
            cleaned = item.strip()
            if cleaned and cleaned not in tokens:
                tokens.append(cleaned)
    for required in REQUIRED_ACTIVITY_CONFIG_CHANGES:
        if required not in tokens:
            tokens.append(required)
    joined = '|'.join(tokens)
    if existing:
        return tag[:existing.start()] + f'android:configChanges="{joined}"' + tag[existing.end():]
    if tag.endswith('/>'):
        return tag[:-2] + f' android:configChanges="{joined}" />'
    return tag[:-1] + f' android:configChanges="{joined}">'


text, replaced_activities = re.subn(
    r'<activity\b[^>]*android:name="\.MainActivity"[^>]*>',
    _ensure_main_activity_config_changes,
    text,
    count=1,
)
if replaced_activities != 1:
    raise SystemExit('Unexpected Android MainActivity tag; review configChanges policy')
if 'android.intent.action.SEND_MULTIPLE' not in text:
    if text.count('</activity>') != 1:
        raise SystemExit('Unexpected Android activity closing tag; review share intent filters')
    filters = (
        '            <intent-filter>\n'
        '                <action android:name="android.intent.action.SEND" />\n'
        '                <category android:name="android.intent.category.DEFAULT" />\n'
        '                <data android:mimeType="*/*" />\n'
        '            </intent-filter>\n'
        '            <intent-filter>\n'
        '                <action android:name="android.intent.action.SEND_MULTIPLE" />\n'
        '                <category android:name="android.intent.category.DEFAULT" />\n'
        '                <data android:mimeType="*/*" />\n'
        '            </intent-filter>\n'
    )
    text = text.replace('</activity>', filters + '        </activity>', 1)
if 'LinSCPTransferService' not in text:
    if text.count('</application>') != 1:
        raise SystemExit('Unexpected Android application closing tag; register the transfer service')
    text = text.replace('    </application>',
        '        <service android:name=".LinSCPTransferService" '
        'android:exported="false" android:foregroundServiceType="dataSync" />\n'
        '    </application>', 1)
# Only this app-private cache subtree can be handed to another app. The
# provider itself is not exported; chooser recipients get explicit read grants.
if '@xml/linscp_outgoing_files' not in text:
    if text.count('    </application>') != 1:
        raise SystemExit('Unexpected Android application closing tag; register outgoing share provider')
    text = text.replace('    </application>',
        '        <provider android:name=".LinSCPExportProvider"\n'
        '            android:authorities="${applicationId}.outgoing" android:exported="false"\n'
        '            android:grantUriPermissions="true">\n'
        '            <meta-data android:name="android.support.FILE_PROVIDER_PATHS"\n'
        '                android:resource="@xml/linscp_outgoing_files" />\n'
        '        </provider>\n'
        '    </application>', 1)
android = '{http://schemas.android.com/apk/res/android}'
application_node = ET.fromstring(text).find('application')
providers = [] if application_node is None else [p for p in application_node.findall('provider')
    if p.get(android + 'name') == '.LinSCPExportProvider']
if len(providers) != 1 or providers[0].get(android + 'exported') != 'false' or \
        providers[0].get(android + 'grantUriPermissions') != 'true' or \
        providers[0].get(android + 'authorities') != '${applicationId}.outgoing' or \
        not any(m.get(android + 'name') == 'android.support.FILE_PROVIDER_PATHS' and
                m.get(android + 'resource') == '@xml/linscp_outgoing_files'
                for m in providers[0].findall('meta-data')):
    raise SystemExit('Invalid outgoing share provider configuration')
manifest.write_text(text)
share_paths = root / 'crates/linscp-tauri/gen/android/app/src/main/res/xml/linscp_outgoing_files.xml'
share_paths.parent.mkdir(parents=True, exist_ok=True)
share_paths.write_text('<?xml version="1.0" encoding="utf-8"?>\n'
    '<paths xmlns:android="http://schemas.android.com/apk/res/android">\n'
    '    <cache-path name="exports" path="outgoing-shares/" />\n'
    '</paths>\n')

# The generated project carries the identifier Tauri read when it was created.
# A project generated before a rename would ship under the old name - and its
# existing installs would keep a data directory the new name never reads - so
# the two are compared instead of trusted, and the mismatch fails the build.
application = application_id()
# Tauri's Android project is generated under an ignored directory. Keep the
# native bridge source tracked here and copy it into the generated app each time
# the project is prepared.
plugin_source = root / 'crates/linscp-tauri/android/LinSCPAndroidPlugin.kt'
plugin_target = root / 'crates/linscp-tauri/gen/android/app/src/main/java' / Path(*application.split('.')) / plugin_source.name
plugin_target.parent.mkdir(parents=True, exist_ok=True)
plugin_target.write_text(plugin_source.read_text())
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
if 'WebView.setWebContentsDebuggingEnabled' not in text:
    text = text.replace(needle, 'if (BuildConfig.DEBUG) android.webkit.WebView.setWebContentsDebuggingEnabled(true)\n        ' + needle)
if 'hideAndroidNavigationBar(this)' not in text:
    text = text.replace(needle, needle + '\n        hideAndroidNavigationBar(this)', 1)
if 'class MainActivity' in text and 'override fun onResume()' not in text:
    closing = text.rfind('}')
    if closing == -1:
        raise SystemExit('Unexpected MainActivity class body; review navigation-bar lifecycle hooks')
    lifecycle_hooks = (
        '\n'
        '  override fun onResume() {\n'
        '    super.onResume()\n'
        '    hideAndroidNavigationBar(this)\n'
        '  }\n'
        '\n'
        '  override fun onWindowFocusChanged(hasFocus: Boolean) {\n'
        '    super.onWindowFocusChanged(hasFocus)\n'
        '    if (hasFocus) {\n'
        '      hideAndroidNavigationBar(this)\n'
        '    }\n'
        '  }\n'
        '}'
    )
    text = text[:closing] + lifecycle_hooks + text[closing + 1:]
activity.write_text(text)
