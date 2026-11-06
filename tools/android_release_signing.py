#!/usr/bin/env python3
"""Sign the Android release APK with the release keystore, not the debug key.

Tauri's Android template configures no signing at all, so `tauri android build`
without `--debug` hands Gradle a release build type whose output is an
*unsigned* APK - one Android refuses to install, and one whose bytes anything
can replace. This module supplies what the template leaves out: it decodes the
release keystore from the CI environment, writes the two files Gradle needs,
and patches the signing configuration into the generated Gradle module.

The files it writes live in the generated Android project, which Git ignores,
so neither the keystore nor its passwords can be committed by accident:

    crates/linscp-tauri/gen/android/linscp-release.jks         (mode 0600)
    crates/linscp-tauri/gen/android/app/keystore.properties    (mode 0600)

The same module answers "which certificate should this APK carry?" for
`tools/verify_android_apk.py`, which asks the keystore rather than trusting a
digest recorded earlier: an APK signed by some other key has to fail the build,
not pass because both sides read the same note.

Environment:
    ANDROID_KEYSTORE_BASE64    base64 of the .jks/.keystore file (required);
                               the file itself must never be in the repository
    ANDROID_KEYSTORE_PASSWORD  the keystore password (required)
    ANDROID_KEY_ALIAS          alias of the signing key; when unset, the one
                               private-key entry in the keystore is used
    ANDROID_KEY_PASSWORD       the key's password; defaults to the store
                               password, which is how Android keystores made
                               with `keytool -genkeypair` are usually set up

Usage:
    python3 tools/android_release_signing.py
"""
import base64
import binascii
import os
import pathlib
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
GENERATED = ROOT / 'crates/linscp-tauri/gen/android'
APP_DIR = GENERATED / 'app'
GRADLE = APP_DIR / 'build.gradle.kts'
KEYSTORE = GENERATED / 'linscp-release.jks'
PROPERTIES = APP_DIR / 'keystore.properties'

# Both container formats start with a known header. Checking it turns "the
# base64 held the certificate export" or "you base64'd the wrong file" into an
# immediate error instead of a Gradle failure minutes into a release build.
JKS_MAGIC = b'\xfe\xed\xfe\xed'
PKCS12_MAGIC = (b'\x30\x82', b'\x30\x81')

MARKER = '// LinSCP release signing, added by tools/android_release_signing.py.'
SIGNING_CONFIGS = f'''    {MARKER}
    // The keystore is CI's; it is decoded into this generated, ignored project.
    signingConfigs {{
        create("release") {{
            val keystoreProperties = Properties().apply {{
                file("keystore.properties").inputStream().use {{ load(it) }}
            }}
            storeFile = file(keystoreProperties.getProperty("storeFile"))
            storePassword = keystoreProperties.getProperty("storePassword")
            keyAlias = keystoreProperties.getProperty("keyAlias")
            keyPassword = keystoreProperties.getProperty("keyPassword")
        }}
    }}
'''
BUILD_TYPES = '    buildTypes {\n'
RELEASE_BUILD_TYPE = '        getByName("release") {\n'
RELEASE_SIGNING = '            signingConfig = signingConfigs.getByName("release")\n'

ALIAS_LINE = re.compile(r'^Alias name:\s*(.+?)\s*$')
ENTRY_LINE = re.compile(r'^Entry type:\s*(.+?)\s*$')
SHA256_LINE = re.compile(r'^SHA256:\s*([0-9a-fA-F:]{95})$')

STOREFILE, STOREPASSWORD, KEYALIAS, KEYPASSWORD = (
    'storeFile', 'storePassword', 'keyAlias', 'keyPassword')


@dataclass(frozen=True)
class Credentials:
    """What the environment says about the keystore, once it is complete."""
    encoded_keystore: str
    password: str
    key_password: str
    alias: str | None


def credentials(environment=None):
    """Read the signing environment, refusing a half-configured one."""
    environment = os.environ if environment is None else environment
    missing = [name for name in ('ANDROID_KEYSTORE_BASE64', 'ANDROID_KEYSTORE_PASSWORD')
               if not environment.get(name, '').strip()]
    if missing:
        raise SystemExit(
            'Android release signing is not configured: '
            + ' and '.join(missing) + ' '
            + ('is' if len(missing) == 1 else 'are') + ' empty. '
            'CI reads them from the `android-release` environment; a local '
            'release build exports them for the keystore it signs with.')
    password = environment['ANDROID_KEYSTORE_PASSWORD']
    alias = environment.get('ANDROID_KEY_ALIAS', '').strip() or None
    key_password = environment.get('ANDROID_KEY_PASSWORD', '') or password
    return Credentials(environment['ANDROID_KEYSTORE_BASE64'].strip(),
                       password, key_password, alias)


def decode_keystore(encoded):
    """The keystore bytes, checked for being a keystore before anything uses it."""
    compact = ''.join(encoded.split())
    if not compact:
        raise SystemExit('ANDROID_KEYSTORE_BASE64 is empty')
    if '-----BEGIN' in encoded:
        raise SystemExit(
            'ANDROID_KEYSTORE_BASE64 holds a PEM block; it has to be the base64 '
            'of the .jks/.keystore file itself, not of an exported certificate')
    try:
        data = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SystemExit(f'ANDROID_KEYSTORE_BASE64 is not base64: {error}') from error
    if not data.startswith(JKS_MAGIC) and not any(
            data.startswith(magic) for magic in PKCS12_MAGIC):
        raise SystemExit(
            'ANDROID_KEYSTORE_BASE64 does not decode to a JKS or PKCS#12 '
            'keystore; export the keystore file itself and base64-encode it')
    return data


def keytool(arguments, password):
    """Run keytool with the store password passed through the environment.

    The password is not an argument: process argument lists are visible to
    every process on the machine, and CI logs them on failure.
    """
    executable = shutil.which('keytool')
    if not executable:
        raise SystemExit(
            'keytool is not on PATH; Android release signing needs a JDK '
            '(CI installs Java 17 with setup-java)')
    environment = dict(os.environ, LINSCP_KEYSTORE_PASSWORD=password)
    return subprocess.run(
        [executable, '-J-Duser.language=en', *arguments],
        capture_output=True, text=True, env=environment, check=False)


def keytool_failure(result):
    """The one line of a failed keytool run that says what went wrong.

    keytool prints its errors on stdout, followed by a Java stack trace whose
    last line ("... 8 more") explains nothing, so the summary line is picked
    out rather than taken from the end.
    """
    lines = [line.strip() for line in (result.stdout + result.stderr).splitlines()
             if line.strip()]
    for line in lines:
        if line.startswith('keytool error:'):
            return line
    return lines[0] if lines else 'no output'


def keystore_entries(keystore, password):
    """Map each alias in the keystore to its entry type, as keytool reports it."""
    result = keytool(['-list', '-v', '-keystore', str(keystore),
                      '-storepass:env', 'LINSCP_KEYSTORE_PASSWORD'], password)
    if result.returncode != 0:
        raise SystemExit(
            f'keytool could not open {keystore}: {keytool_failure(result)} '
            f'(is ANDROID_KEYSTORE_PASSWORD the password of this keystore?)')
    entries = {}
    alias = None
    for line in result.stdout.splitlines():
        stripped = line.strip()
        found = ALIAS_LINE.match(stripped)
        if found:
            alias = found.group(1)
            entries.setdefault(alias, '')
            continue
        found = ENTRY_LINE.match(stripped)
        if found and alias:
            entries[alias] = found.group(1)
    return entries


def resolve_alias(entries, requested):
    """The alias to sign with: the one named, or the only key in the keystore."""
    if requested:
        if requested not in entries:
            known = ', '.join(sorted(entries)) or 'none'
            raise SystemExit(
                f'ANDROID_KEY_ALIAS is {requested!r}, which the keystore does '
                f'not contain (it holds: {known})')
        if 'PrivateKeyEntry' not in entries[requested]:
            raise SystemExit(
                f'the keystore entry {requested!r} is '
                f'{entries[requested] or "of an unknown type"}, not a signing key')
        return requested
    keys = sorted(alias for alias, kind in entries.items() if 'PrivateKeyEntry' in kind)
    if len(keys) == 1:
        return keys[0]
    if not keys:
        raise SystemExit('the keystore holds no private key to sign with')
    raise SystemExit(
        'the keystore holds more than one signing key ('
        + ', '.join(keys) + '); set ANDROID_KEY_ALIAS to the one to sign with')


def certificate_digest(keystore, password, alias):
    """The SHA-256 fingerprint of the signing certificate, lowercase hex.

    `apksigner` reports the same value for a signed APK, so the two can be
    compared without either side trusting the other's opinion of the file.
    """
    result = keytool(['-list', '-v', '-alias', alias, '-keystore', str(keystore),
                      '-storepass:env', 'LINSCP_KEYSTORE_PASSWORD'], password)
    if result.returncode != 0:
        raise SystemExit(
            f'keytool could not read the certificate of alias {alias!r}: '
            f'{keytool_failure(result)}')
    for line in result.stdout.splitlines():
        found = SHA256_LINE.match(line.strip())
        if found:
            return found.group(1).replace(':', '').lower()
    raise SystemExit(f'keytool printed no SHA-256 fingerprint for alias {alias!r}')


def gradle_signing_configuration(text):
    """Add the release signing config to the generated Gradle module.

    The template is Tauri's, so this is a patch of a known shape rather than a
    text substitution that silently does nothing when the template changes: a
    missing anchor fails the build instead of producing an unsigned APK.
    """
    if MARKER in text:
        if RELEASE_SIGNING not in text:
            raise SystemExit(
                f'{GRADLE} carries the release signing config but its release '
                f'build type does not use it; regenerate the Android project')
        return text
    if 'signingConfig =' in text or 'signingConfigs {' in text:
        raise SystemExit(
            f'{GRADLE} already configures signing; review it rather than '
            f'layering the release keystore on top')
    if 'import java.util.Properties' not in text:
        raise SystemExit(
            f'{GRADLE} no longer imports java.util.Properties; the release '
            f'signing block would not compile')
    if text.count(BUILD_TYPES) != 1 or text.count(RELEASE_BUILD_TYPE) != 1:
        raise SystemExit(
            f'Unexpected Tauri Android Gradle template in {GRADLE}; cannot add '
            f'release signing')
    text = text.replace(BUILD_TYPES, SIGNING_CONFIGS + BUILD_TYPES, 1)
    return text.replace(RELEASE_BUILD_TYPE,
                        RELEASE_BUILD_TYPE + RELEASE_SIGNING, 1)


def signing_properties(keystore, alias, password, key_password):
    """The `keystore.properties` body Gradle loads, in the order it reads it."""
    def value(item):
        # java.util.Properties treats a backslash as an escape character in
        # values; a password may well contain one.
        return item.replace('\\', '\\\\')

    lines = [
        '# Written by tools/android_release_signing.py; never commit this file.',
        f'{STOREFILE}={value(str(keystore))}',
        f'{STOREPASSWORD}={value(password)}',
        f'{KEYALIAS}={value(alias)}',
        f'{KEYPASSWORD}={value(key_password)}',
    ]
    return '\n'.join(lines) + '\n'


def read_signing_properties(path=PROPERTIES):
    """The signing properties Gradle was given, or None if there are none."""
    path = pathlib.Path(path)
    if not path.is_file():
        return None
    properties = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or '=' not in stripped:
            continue
        key, _, value = stripped.partition('=')
        properties[key.strip()] = value.strip().replace('\\\\', '\\')
    return properties


def write_private(path, text):
    """Write a file only the build user can read, before it holds a secret."""
    path.write_text(text, encoding='utf-8')
    path.chmod(0o600)


def configure(generated=GENERATED, environment=None):
    """Configure release signing for a generated Android project.

    Returns the alias, the certificate digest and the paths it wrote, so the
    caller can report them and a test can check them against keytool.
    """
    signing = credentials(environment)
    data = decode_keystore(signing.encoded_keystore)
    gradle = generated / 'app/build.gradle.kts'
    keystore = generated / 'linscp-release.jks'
    properties = generated / 'app/keystore.properties'
    if not gradle.is_file():
        raise SystemExit(
            f'The generated Android project is missing ({gradle}); run '
            f'`tauri android init` before configuring release signing')
    # The bytes are checked in a scratch file first: a keystore that does not
    # open has to fail the step, not stay behind in the project for a later
    # build to sign with.
    staged = keystore.with_suffix('.staged')
    staged.write_bytes(data)
    staged.chmod(0o600)
    try:
        entries = keystore_entries(staged, signing.password)
        alias = resolve_alias(entries, signing.alias)
        digest = certificate_digest(staged, signing.password, alias)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    staged.replace(keystore)
    keystore.chmod(0o600)
    write_private(properties, signing_properties(
        keystore, alias, signing.password, signing.key_password))
    gradle.write_text(gradle_signing_configuration(gradle.read_text(encoding='utf-8')),
                      encoding='utf-8')
    return {'alias': alias, 'digest': digest, 'keystore': keystore,
            'properties': properties, 'gradle': gradle}


def main():
    configured = configure()
    print(f"Release signing configured: alias {configured['alias']!r}, "
          f"certificate SHA-256 {configured['digest']}, "
          f"keystore {configured['keystore'].relative_to(ROOT)}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
