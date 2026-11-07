"""The Android release build is signed by the release keystore, not the debug key.

`tauri android build` without `--debug` writes `app-release-unsigned.apk` unless
Gradle is told how to sign, and an unsigned APK installs nowhere. The signing
step therefore has to be explicit, has to refuse a half-configured environment,
and has to leave the repository without a keystore in it. These tests hold those
properties without needing a JDK: they cover the decoding, the environment
contract, the Gradle patch and the properties file, and they pin the workflow
and the docs to the environment the secrets actually live in.
"""
import base64
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import android_release_signing as signing  # noqa: E402

# The anchors the patch relies on, at the indentation Tauri's template uses.
TEMPLATE = '''import java.util.Properties

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

android {
    compileSdk = 36
    namespace = "com.example.app"
    defaultConfig {
        applicationId = "com.example.app"
    }
    buildTypes {
        getByName("debug") {
            isDebuggable = true
        }
        getByName("release") {
            isMinifyEnabled = true
        }
    }
}
'''

JKS = signing.JKS_MAGIC + b'\x00\x00\x00\x02mock-keystore'


class KeystoreDecodingTests(unittest.TestCase):
    def test_a_base64_jks_keystore_is_accepted(self):
        encoded = base64.b64encode(JKS).decode()
        self.assertEqual(signing.decode_keystore(encoded), JKS)

    def test_line_wrapped_base64_is_accepted(self):
        # `base64` on the command line wraps at 76 columns, and that is how a
        # key is usually pasted into a GitHub secret.
        wrapped = '\n'.join(base64.b64encode(JKS).decode()[i:i + 76]
                            for i in range(0, len(base64.b64encode(JKS).decode()), 76))
        self.assertEqual(signing.decode_keystore(wrapped), JKS)

    def test_a_pkcs12_keystore_is_accepted(self):
        data = signing.PKCS12_MAGIC[0] + b'\x00' * 16
        self.assertEqual(signing.decode_keystore(base64.b64encode(data).decode()), data)

    def test_a_pem_block_is_rejected(self):
        encoded = base64.b64encode(b'-----BEGIN CERTIFICATE-----\n').decode()
        with self.assertRaises(SystemExit) as raised:
            signing.decode_keystore('-----BEGIN CERTIFICATE-----\nAAAA\n')
        self.assertIn('PEM', str(raised.exception))
        self.assertTrue(encoded)

    def test_bytes_that_are_not_a_keystore_are_rejected(self):
        with self.assertRaises(SystemExit) as raised:
            signing.decode_keystore(base64.b64encode(b'not a keystore').decode())
        self.assertIn('JKS', str(raised.exception))

    def test_invalid_base64_is_rejected(self):
        with self.assertRaises(SystemExit) as raised:
            signing.decode_keystore('not base64 at all!')
        self.assertIn('not base64', str(raised.exception))

    def test_an_empty_secret_is_rejected(self):
        with self.assertRaises(SystemExit):
            signing.decode_keystore('   \n')


class EnvironmentTests(unittest.TestCase):
    def test_a_missing_keystore_and_password_are_named(self):
        with self.assertRaises(SystemExit) as raised:
            signing.credentials({})
        message = str(raised.exception)
        self.assertIn('ANDROID_KEYSTORE_BASE64', message)
        self.assertIn('ANDROID_KEYSTORE_PASSWORD', message)
        self.assertIn('android-release', message)

    def test_the_key_password_defaults_to_the_store_password(self):
        credentials = signing.credentials({
            'ANDROID_KEYSTORE_BASE64': base64.b64encode(JKS).decode(),
            'ANDROID_KEYSTORE_PASSWORD': 'store-secret',
        })
        self.assertEqual(credentials.password, 'store-secret')
        self.assertEqual(credentials.key_password, 'store-secret')
        self.assertIsNone(credentials.alias)

    def test_an_explicit_alias_and_key_password_are_used(self):
        credentials = signing.credentials({
            'ANDROID_KEYSTORE_BASE64': base64.b64encode(JKS).decode(),
            'ANDROID_KEYSTORE_PASSWORD': 'store-secret',
            'ANDROID_KEY_ALIAS': 'release',
            'ANDROID_KEY_PASSWORD': 'key-secret',
        })
        self.assertEqual(credentials.alias, 'release')
        self.assertEqual(credentials.key_password, 'key-secret')

    def test_the_only_key_in_the_keystore_is_used_when_no_alias_is_given(self):
        self.assertEqual(
            signing.resolve_alias({'release': 'PrivateKeyEntry'}, None), 'release')

    def test_an_explicit_alias_has_to_be_a_private_key(self):
        with self.assertRaises(SystemExit) as raised:
            signing.resolve_alias({'release': 'trustedCertEntry'}, 'release')
        self.assertIn('not a signing key', str(raised.exception))

    def test_an_unknown_alias_lists_the_keystore_contents(self):
        with self.assertRaises(SystemExit) as raised:
            signing.resolve_alias({'linscp': 'PrivateKeyEntry'}, 'release')
        self.assertIn('linscp', str(raised.exception))

    def test_several_keys_need_an_explicit_alias(self):
        with self.assertRaises(SystemExit) as raised:
            signing.resolve_alias(
                {'one': 'PrivateKeyEntry', 'two': 'PrivateKeyEntry'}, None)
        self.assertIn('ANDROID_KEY_ALIAS', str(raised.exception))


class GradleSigningTests(unittest.TestCase):
    def test_signing_is_added_inside_the_android_block(self):
        patched = signing.gradle_signing_configuration(TEMPLATE)
        self.assertIn(signing.MARKER, patched)
        self.assertLess(patched.index('signingConfigs {'), patched.index('buildTypes {'))
        self.assertIn('applicationId = "com.example.app"', patched)
        # The configuration is loaded from the properties file the signing step
        # writes, not from values baked into the generated project.
        self.assertIn('file("keystore.properties")', patched)
        self.assertIn('file(keystoreProperties.getProperty("storeFile"))', patched)

    def test_the_release_build_type_uses_the_release_signing_config(self):
        patched = signing.gradle_signing_configuration(TEMPLATE)
        release = patched.index('getByName("release") {')
        self.assertIn(signing.RELEASE_SIGNING, patched[release:])
        self.assertLess(release, patched.index(signing.RELEASE_SIGNING))
        # The debug build type keeps the development key: the emulator smoke
        # test installs it, and it must not be the artifact users update from.
        debug = patched.index('getByName("debug") {')
        self.assertNotIn('signingConfig',
                         patched[debug:patched.index('getByName("release") {')])

    def test_patching_is_idempotent(self):
        once = signing.gradle_signing_configuration(TEMPLATE)
        self.assertEqual(signing.gradle_signing_configuration(once), once)
        self.assertEqual(once.count('signingConfigs {'), 1)
        self.assertEqual(once.count(signing.RELEASE_SIGNING), 1)

    def test_an_unexpected_template_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            signing.gradle_signing_configuration(
                TEMPLATE.replace('    buildTypes {\n', 'buildTypes { // moved\n'))
        self.assertIn('Unexpected Tauri Android Gradle template', str(raised.exception))

    def test_a_project_that_already_signs_is_not_patched_twice(self):
        already = TEMPLATE.replace(
            '    buildTypes {',
            '    signingConfigs {\n        create("release") { }\n    }\n    buildTypes {')
        with self.assertRaises(SystemExit) as raised:
            signing.gradle_signing_configuration(already)
        self.assertIn('already configures signing', str(raised.exception))

    def test_a_partial_patch_is_refused(self):
        partial = signing.gradle_signing_configuration(TEMPLATE).replace(
            signing.RELEASE_SIGNING, '')
        with self.assertRaises(SystemExit) as raised:
            signing.gradle_signing_configuration(partial)
        self.assertIn('does not use it', str(raised.exception))


class PropertiesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def test_the_properties_file_round_trips_and_stays_private(self):
        keystore = self.root / 'release.jks'
        path = self.root / 'keystore.properties'
        body = signing.signing_properties(keystore, 'release', r'pa\ss:word', 'key')
        signing.write_private(path, body)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        properties = signing.read_signing_properties(path)
        self.assertEqual(properties[signing.STOREFILE], str(keystore))
        self.assertEqual(properties[signing.STOREPASSWORD], r'pa\ss:word')
        self.assertEqual(properties[signing.KEYALIAS], 'release')
        self.assertEqual(properties[signing.KEYPASSWORD], 'key')

    def test_a_missing_properties_file_reads_as_none(self):
        self.assertIsNone(signing.read_signing_properties(self.root / 'absent.properties'))

    def test_the_properties_file_never_mentions_the_keystore_contents(self):
        body = signing.signing_properties(self.root / 'release.jks', 'release',
                                          'store-secret', 'store-secret')
        self.assertIn('storePassword=store-secret', body)
        self.assertTrue(body.startswith('#'))


class ApkVerificationTests(unittest.TestCase):
    """The digest the APK is compared against comes from the keystore."""

    # The shape build-tools 31 and later print, with a real-length digest.
    DIGEST = '0123456789abcdef' * 4
    APKSIGNER = ('Verifies\n'
                 'Verified using v1 scheme (JAR signing): false\n'
                 'Verified using v2 APK Signature Scheme v2: true\n'
                 'Number of signers: 1\n'
                 'Signer #1 certificate DN: CN=LinSCP\n'
                 f'Signer #1 certificate SHA-256 digest: {DIGEST}\n'
                 'Signer #1 certificate SHA-1 digest: abcd0123\n')

    def proof(self, keystore='release.jks', password='secret', alias='linscp'):
        path = self.root / 'crates/linscp-tauri/gen/android/app/keystore.properties'
        path.parent.mkdir(parents=True, exist_ok=True)
        signing.write_private(path, signing.signing_properties(
            keystore, alias, password, password))

    def setUp(self):
        import verify_android_apk
        self.verify = verify_android_apk
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.saved = (self.verify.ROOT, self.verify.certificate_digest)
        self.verify.ROOT = self.root

        def restore():
            self.verify.ROOT, self.verify.certificate_digest = self.saved
        self.addCleanup(restore)

    def test_the_signer_digest_is_read_from_apksigner(self):
        self.assertEqual(self.verify.signer_digest(self.APKSIGNER), self.DIGEST)

    def test_a_colon_separated_uppercase_digest_is_normalised(self):
        # `keytool` prints fingerprints this way, and some apksigner builds do
        # too; the comparison against the keystore is on lowercase hex.
        fingerprint = ':'.join(self.DIGEST[i:i + 2] for i in range(0, 64, 2)).upper()
        self.assertEqual(
            self.verify.signer_digest(
                f'Signer #1 certificate SHA-256 digest: {fingerprint}\n'),
            self.DIGEST)

    def test_the_older_v2_scheme_spelling_counts_as_signed(self):
        # build-tools 28-30 word the line differently; a release APK signed by
        # hand with an older SDK is still a v2-signed APK.
        self.assertTrue(self.verify.V2_SCHEME.search(
            'Verified using v2 scheme (APK Signature Scheme v2): true'))

    def test_apksigner_output_without_a_signer_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            self.verify.signer_digest('Signer #1 certificate SHA-1 digest: abcd\n')
        # The message has to carry what apksigner said, or the next failure in
        # CI is another guess rather than a reading.
        self.assertIn('It said:', str(raised.exception))

    def test_the_expected_digest_is_asked_of_the_keystore(self):
        self.proof(keystore='/keys/release.jks', password='store-secret', alias='linscp')
        asked = []
        self.verify.certificate_digest = \
            lambda keystore, password, alias: asked.append((keystore, password, alias)) or 'abc'
        self.assertEqual(self.verify.expected_release_digest(), 'abc')
        # The store password from the properties file opens the keystore; the
        # alias is the one the signing step resolved, not one invented here.
        self.assertEqual(asked, [('/keys/release.jks', 'store-secret', 'linscp')])

    def test_a_release_build_without_signing_material_is_refused(self):
        with self.assertRaises(SystemExit) as raised:
            self.verify.expected_release_digest()
        self.assertIn('tools/android_release_signing.py', str(raised.exception))


class RepositoryConfigurationTests(unittest.TestCase):
    def workflow(self):
        return (ROOT / '.github/workflows/android-build.yml').read_text(encoding='utf-8')

    def test_the_workflow_reads_the_release_environment_secrets(self):
        workflow = self.workflow()
        self.assertIn('environment: android-release', workflow)
        self.assertIn('secrets.ANDROID_KEYSTORE_BASE64', workflow)
        self.assertIn('secrets.ANDROID_KEYSTORE_PASSWORD', workflow)
        self.assertIn('tools/android_release_signing.py', workflow)

    def test_the_published_apk_is_the_release_build(self):
        workflow = self.workflow()
        self.assertIn('name: linscp-android-release', workflow)
        self.assertIn('path: android-artifacts/linscp-android-release.apk', workflow)
        self.assertNotIn('linscp-android-debug', workflow)
        # The release build is the one without --debug; the debug flag may only
        # appear on builds that feed a test (the DevTools smoke test, or the
        # pull-request check job's unsigned verification) — never on the build
        # whose APK is published. Exactly one build is published, and it is
        # the release one.
        commands = [line for line in workflow.splitlines() if 'android build --ci' in line]
        release = [line for line in commands if '--debug' not in line]
        self.assertEqual(len(release), 1, commands)
        for line in commands:
            if line != release[0]:
                self.assertIn('--debug', line)
        self.assertEqual(workflow.count('actions/upload-artifact'), 1, workflow)

    def test_the_apk_checks_distinguish_debug_from_release(self):
        workflow = self.workflow()
        self.assertIn('tools/verify_android_apk.py --build-type release', workflow)
        self.assertIn('tools/verify_android_apk.py --build-type debug', workflow)
        self.assertIn('tools/android_release_launch_check.sh', workflow)
        verifier = (ROOT / 'tools/verify_android_apk.py').read_text(encoding='utf-8')
        self.assertIn('--print-certs', verifier)
        self.assertIn('Signer #1 certificate SHA-256 digest', verifier)
        self.assertIn('application-debuggable', verifier)

    def test_the_release_build_type_is_not_debuggable(self):
        # A debug `applicationIdSuffix` would install under another name, and a
        # debuggable release build would expose the WebView to adb.
        config = (ROOT / 'crates/linscp-tauri/tauri.conf.json').read_text(encoding='utf-8')
        self.assertNotIn('debugApplicationIdSuffix', config)

    def test_signing_material_cannot_be_committed(self):
        ignored = (ROOT / '.gitignore').read_text(encoding='utf-8')
        for pattern in ('*.jks', '*.keystore', 'keystore.properties'):
            self.assertIn(pattern, ignored)

    def test_the_docs_name_the_secrets_and_the_signing_step(self):
        docs = (ROOT / 'docs/android.md').read_text(encoding='utf-8')
        for expected in ('ANDROID_KEYSTORE_BASE64', 'ANDROID_KEYSTORE_PASSWORD',
                         'android-release', 'tools/android_release_signing.py',
                         'linscp-android-release.apk'):
            self.assertIn(expected, docs)


@unittest.skipUnless(shutil.which('keytool'), 'needs a JDK to create a keystore')
class KeytoolIntegrationTests(unittest.TestCase):
    """The real keytool on a real keystore, because the parser above reads it.

    A JDK that words `Alias name:` or the fingerprint differently has to fail
    here rather than in the release build. CI installs Java 17 for the Android
    job, so this runs there; elsewhere it is skipped.
    """

    PASSWORD = 'store-secret'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)
        self.generated = self.root / 'crates/linscp-tauri/gen/android'
        (self.generated / 'app').mkdir(parents=True)
        self.gradle = self.generated / 'app/build.gradle.kts'
        self.gradle.write_text(TEMPLATE, encoding='utf-8')
        self.keystore = self.root / 'release.jks'

    def make_keystore(self, *aliases):
        for alias in aliases:
            subprocess.run(
                ['keytool', '-genkeypair', '-keystore', str(self.keystore),
                 '-alias', alias, '-keyalg', 'RSA', '-keysize', '2048',
                 '-validity', '100', '-storetype', 'PKCS12',
                 '-storepass', self.PASSWORD, '-keypass', self.PASSWORD,
                 '-dname', f'CN={alias}'],
                check=True, capture_output=True)

    def environment(self, **extra):
        return {
            'ANDROID_KEYSTORE_BASE64':
                base64.b64encode(self.keystore.read_bytes()).decode(),
            'ANDROID_KEYSTORE_PASSWORD': self.PASSWORD,
            **extra,
        }

    def test_a_real_keystore_signs_the_release_build_type(self):
        self.make_keystore('linscp')
        configured = signing.configure(self.generated, self.environment())
        self.assertEqual(configured['alias'], 'linscp')
        # The digest is what verify_android_apk.py compares an APK against, so
        # it has to be the certificate's, not a hash of something else.
        self.assertEqual(configured['digest'],
                         signing.certificate_digest(self.keystore, self.PASSWORD, 'linscp'))
        self.assertEqual(len(configured['digest']), 64)
        self.assertEqual(configured['keystore'].stat().st_mode & 0o777, 0o600)
        self.assertEqual(configured['properties'].stat().st_mode & 0o777, 0o600)
        self.assertIn(signing.RELEASE_SIGNING, configured['gradle'].read_text())
        properties = signing.read_signing_properties(configured['properties'])
        self.assertEqual(properties[signing.STOREPASSWORD], self.PASSWORD)
        self.assertEqual(pathlib.Path(properties[signing.STOREFILE]).read_bytes(),
                         self.keystore.read_bytes())

    def test_running_it_twice_changes_nothing(self):
        self.make_keystore('linscp')
        first = signing.configure(self.generated, self.environment())
        patched = first['gradle'].read_text()
        second = signing.configure(self.generated, self.environment())
        self.assertEqual(second['digest'], first['digest'])
        self.assertEqual(second['gradle'].read_text(), patched)

    def test_a_wrong_password_fails_and_leaves_the_project_unsigned(self):
        self.make_keystore('linscp')
        environment = dict(self.environment(), ANDROID_KEYSTORE_PASSWORD='not-the-password')
        with self.assertRaises(SystemExit) as raised:
            signing.configure(self.generated, environment)
        self.assertIn('keytool error', str(raised.exception))
        self.assertFalse((self.generated / 'linscp-release.jks').exists())
        self.assertFalse((self.generated / 'linscp-release.staged').exists())
        self.assertEqual(self.gradle.read_text(encoding='utf-8'), TEMPLATE)

    def test_two_keys_need_an_alias_and_the_alias_picks_the_certificate(self):
        self.make_keystore('first', 'second')
        with self.assertRaises(SystemExit) as raised:
            signing.configure(self.generated, self.environment())
        self.assertIn('ANDROID_KEY_ALIAS', str(raised.exception))
        configured = signing.configure(
            self.generated, self.environment(ANDROID_KEY_ALIAS='second'))
        self.assertEqual(configured['alias'], 'second')
        self.assertEqual(configured['digest'],
                         signing.certificate_digest(self.keystore, self.PASSWORD, 'second'))


if __name__ == '__main__':
    unittest.main()
