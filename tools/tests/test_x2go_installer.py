"""Exercise the shipped Debian X2Go installer with fake commands, never apt."""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/linscp-proto/src/remote_desktop.rs'


@unittest.skipUnless(shutil.which('bash'), 'requires bash')
class X2GoInstallerTests(unittest.TestCase):
    def run_installer(self, fail_update=False, desktop=False):
        source = SOURCE.read_text(encoding='utf-8')
        pattern = (r'pub fn x2go_xfce_install_script\(\) -> &\'static str \{\s*r#"(#!/bin/bash\n.*?)"#'
                   if desktop else r'RemoteDesktopKind::X2Go => r#"(#!/bin/bash\n.*?)"#\.to_string\(\)')
        match = re.search(pattern, source, re.S)
        self.assertIsNotNone(match)
        script = match.group(1)
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            bin_dir = base / 'bin'
            bin_dir.mkdir()
            release = base / 'os-release'
            release.write_text('ID=debian\n')
            script = script.replace('/etc/os-release', str(release))
            log = base / 'calls'
            def command(name, content):
                path = bin_dir / name
                path.write_text('#!/bin/sh\n' + content + '\n')
                path.chmod(0o755)
            command('id', 'echo 1000')
            command('sudo', 'exec "$@"')
            command('apt-get', 'echo "$*" >> "$LOG"\nif [ "$1" = update ] && [ "$FAIL_UPDATE" = 1 ]; then exit 1; fi')
            command('x2gostartagent', 'exit 0')
            command('startxfce4', 'exit 0')
            env = dict(os.environ, PATH=f'{bin_dir}:/usr/bin:/bin', LOG=str(log),
                       FAIL_UPDATE='1' if fail_update else '0')
            result = subprocess.run(['bash', '-c', script], env=env, text=True,
                                    capture_output=True, timeout=10)
            calls = log.read_text().splitlines() if log.exists() else []
            return script, result, calls

    def test_debian_installs_only_x2go_from_existing_repositories(self):
        script, result, calls = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['update -qq', 'install -y x2goserver x2goserver-xsession'])
        self.assertNotIn('add-apt-repository', script)
        self.assertNotIn('ppa:', script)
        self.assertIn('X2Go server installation completed', result.stdout)

    def test_xfce_is_a_separate_installer(self):
        _, result, calls = self.run_installer(desktop=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['update -qq', 'install -y xfce4'])
        self.assertIn('XFCE installation completed', result.stdout)

    def test_desktop_probe_recognizes_common_sessions_and_reports_unknown(self):
        source = SOURCE.read_text(encoding='utf-8')
        match = re.search(r'pub const X2GO_DESKTOP_PROBE: &str = "([^"]+)";', source)
        self.assertIsNotNone(match)
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = pathlib.Path(tmp)
            for binaries, expected in [([], 'NONE'), (['mate-session'], 'MATE'),
                                       (['startlxde'], 'LXDE'), (['startxfce4'], 'XFCE')]:
                for entry in bin_dir.iterdir(): entry.unlink()
                for name in binaries:
                    path = bin_dir / name
                    path.write_text('#!/bin/sh\nexit 0\n')
                    path.chmod(0o755)
                result = subprocess.run(['/bin/sh', '-c', match.group(1)],
                                        env={'PATH': str(bin_dir)}, text=True,
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)

    def test_failed_update_does_not_claim_success_or_install(self):
        _, result, calls = self.run_installer(fail_update=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ['update -qq'])
        self.assertNotIn('X2Go server installation completed', result.stdout)


if __name__ == '__main__':
    unittest.main()
