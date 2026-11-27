"""Tests for the disposable Android biometric drivers and security wiring."""
import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
spec = importlib.util.spec_from_file_location('biometric_enroll', ROOT / 'tools/android_enroll_emulator_fingerprint.py')
enroll = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enroll)


def screen(*labels):
    return '<hierarchy>' + ''.join(f'<node text="{label}" enabled="true" bounds="[0,0][100,100]" />' for label in labels) + '</hierarchy>'


class BiometricTests(unittest.TestCase):
    def test_emulator_enrollment_drives_leaf_buttons_and_fingerprint(self):
        screens = [screen('Re-enter your PIN'), screen('MORE'), screen('Touch the sensor'), screen('DONE')]
        calls = []
        clicks = []
        with patch.object(enroll, 'dump', side_effect=screens), \
             patch.object(enroll.time, 'sleep'), \
             patch.object(enroll, 'adb', side_effect=lambda *args: calls.append(args)), \
             patch.object(enroll, 'click', side_effect=lambda node: clicks.append(node.get('text'))):
            enroll.main([])
        self.assertEqual(clicks, ['MORE', 'DONE'])
        self.assertIn(('emu', 'finger', 'touch', '1'), calls)

    def test_additional_enrollment_keeps_existing_pin_and_uses_new_fingerprint(self):
        calls = []
        with patch.object(enroll, 'dump', side_effect=[screen('Enter PIN'), screen('Touch the sensor'), screen('DONE')]), \
             patch.object(enroll.time, 'sleep'), \
             patch.object(enroll, 'adb', side_effect=lambda *args: calls.append(args)), \
             patch.object(enroll, 'click'):
            enroll.main(['--additional'])
        self.assertIn(('emu', 'finger', 'touch', '2'), calls)
        self.assertNotIn(('shell', 'locksettings', 'set-pin', '1234'), calls)

    def test_android_biometrics_use_per_operation_keystore_crypto_and_no_backup(self):
        kotlin = (ROOT / 'crates/linscp-tauri/android/LinSCPAndroidPlugin.kt').read_text()
        for fragment in ['setUserAuthenticationRequired(true)', 'AUTH_BIOMETRIC_STRONG',
                         'setInvalidatedByBiometricEnrollment(true)', 'BiometricPrompt.CryptoObject(cipher)',
                         'activity.noBackupFilesDir', 'AtomicFile(biometricFile)']:
            self.assertIn(fragment, kotlin)
        biometric = kotlin[kotlin.index('private fun biometricPrompt'):kotlin.index('private val keystoreLock')]
        self.assertGreater(biometric.index('authenticated.updateAAD(biometricAad)'),
                           biometric.index('onAuthenticationSucceeded'))
        host = (ROOT / 'crates/linscp-tauri/src/lib.rs').read_text()
        unlock = host[host.index('pub async fn linscp_biometric_unlock'):host.index('pub async fn linscp_biometric_disable')]
        self.assertIn('"/api/vault/unlock"', unlock)
        self.assertIn('"vault"] != "locked"', unlock)
        self.assertNotIn('"password": password', unlock)


if __name__ == '__main__':
    unittest.main()
