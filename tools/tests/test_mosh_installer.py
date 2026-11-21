"""Exercise the shipped Mosh server installer with fake commands in a sandbox."""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'crates/linscp-proto/src/mosh.rs'


@unittest.skipUnless(shutil.which('bash'), 'requires bash')
class MoshInstallerTests(unittest.TestCase):
    def extract_script(self):
        source = SOURCE.read_text(encoding='utf-8')
        match = re.search(
            r'pub fn mosh_install_script\(\) -> String \{\s*r#"(#!/bin/bash\n.*?)"#\s*\.to_string\(\)',
            source,
            re.S,
        )
        self.assertIsNotNone(match, 'mosh_install_script() raw string not found')
        return match.group(1)

    def run_installer(
        self,
        distro_id='debian',
        uid=1000,
        already_installed=False,
        install_creates_binary=True,
        fail_update=False,
        dnf_fails=False,
    ):
        raw_script = self.extract_script()
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            bin_dir = base / 'bin'
            bin_dir.mkdir()
            log = base / 'calls'

            if distro_id is not None:
                release = base / 'os-release'
                release.write_text(f'ID={distro_id}\n', encoding='utf-8')
                script = raw_script.replace('/etc/os-release', str(release))
            else:
                script = raw_script.replace('/etc/os-release', str(base / 'no-os-release'))

            # Isolate hardcoded fallback paths from the host OS.
            script = script.replace('PATH="$PATH:/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin"', f'PATH="{bin_dir}"')
            script = script.replace('/usr/bin/mosh-server', str(base / 'usr-bin-mosh-server'))
            script = script.replace('/usr/local/bin/mosh-server', str(base / 'usr-local-mosh-server'))

            # Copy essential POSIX utilities into isolated bin_dir so host mosh-server cannot leak in.
            for util in ('env', 'uname', 'tr', 'cat', 'chmod', 'sh'):
                real = shutil.which(util)
                if real:
                    os.symlink(real, bin_dir / util)

            def command(name, body):
                path = bin_dir / name
                path.write_text('#!/bin/sh\n' + body + '\n', encoding='utf-8')
                path.chmod(0o755)

            command('id', f'echo {uid}')
            command('sudo', 'echo "sudo:$*" >> "$LOG"\nexec "$@"')

            create_bin_snippet = (
                f'printf "#!/bin/sh\\nexit 0\\n" > "{bin_dir / "mosh-server"}" && chmod 755 "{bin_dir / "mosh-server"}"'
                if install_creates_binary
                else 'true'
            )

            if already_installed:
                command('mosh-server', 'exit 0')

            command(
                'apt-get',
                'echo "apt-get:$*" >> "$LOG"\n'
                'if [ "$1" = update ] && [ "$FAIL_UPDATE" = 1 ]; then exit 1; fi\n'
                f'if [ "$1" = install ]; then {create_bin_snippet}; fi',
            )
            command(
                'dnf',
                'echo "dnf:$*" >> "$LOG"\n'
                'if [ "$DNF_FAILS" = 1 ]; then exit 1; fi\n'
                f'{create_bin_snippet}',
            )
            command('yum', f'echo "yum:$*" >> "$LOG"\n{create_bin_snippet}')
            command('pacman', f'echo "pacman:$*" >> "$LOG"\n{create_bin_snippet}')
            command('zypper', f'echo "zypper:$*" >> "$LOG"\n{create_bin_snippet}')
            command('apk', f'echo "apk:$*" >> "$LOG"\n{create_bin_snippet}')
            command('pkg', f'echo "pkg:$*" >> "$LOG"\n{create_bin_snippet}')

            env = dict(
                os.environ,
                PATH=str(bin_dir),
                LOG=str(log),
                FAIL_UPDATE='1' if fail_update else '0',
                DNF_FAILS='1' if dnf_fails else '0',
            )
            bash_bin = shutil.which('bash')
            result = subprocess.run(
                [bash_bin, '-c', script],
                env=env,
                text=True,
                capture_output=True,
                timeout=10,
            )
            calls = log.read_text(encoding='utf-8').splitlines() if log.exists() else []
            return raw_script, result, calls

    def test_static_security_invariants_no_third_party_repos_or_firewall_mutation(self):
        script = self.extract_script()
        for forbidden in (
            'curl ',
            'wget ',
            'add-apt-repository',
            'ppa:',
            'epel-release',
            'rpm --import',
            'ufw ',
            'firewall-cmd',
            'iptables',
        ):
            self.assertNotIn(forbidden, script)

    def test_already_installed_exits_cleanly_without_invoking_sudo_or_pkg_manager(self):
        _, result, calls = self.run_installer(already_installed=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [])
        self.assertIn('already installed', result.stdout)

    def test_debian_non_root_uses_sudo_and_verifies_mosh_server(self):
        _, result, calls = self.run_installer(distro_id='ubuntu', uid=1000)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('sudo:apt-get update -qq', calls)
        self.assertIn('apt-get:install -y mosh', calls)
        self.assertIn('Mosh server installation completed', result.stdout)

    def test_root_skips_sudo_across_supported_distros(self):
        cases = [
            ('fedora', 'dnf:install -y mosh'),
            ('arch', 'pacman:-S --needed --noconfirm mosh'),
            ('opensuse-leap', 'zypper:--non-interactive install mosh'),
            ('alpine', 'apk:add mosh'),
            ('freebsd', 'pkg:install mosh'),
        ]
        for distro, expected in cases:
            with self.subTest(distro=distro):
                _, result, calls = self.run_installer(distro_id=distro, uid=0)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any(c.startswith('sudo:') for c in calls), calls)
                self.assertIn(expected, calls)

    def test_rhel_falls_back_from_dnf_to_yum(self):
        _, result, calls = self.run_installer(distro_id='rocky', uid=0, dnf_fails=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ['dnf:install -y mosh', 'yum:install -y mosh'])

    def test_failed_apt_update_stops_before_install(self):
        _, result, calls = self.run_installer(distro_id='debian', uid=0, fail_update=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ['apt-get:update -qq'])

    def test_missing_mosh_server_after_install_fails_closed(self):
        _, result, _ = self.run_installer(distro_id='debian', uid=0, install_creates_binary=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('could not be verified', result.stderr)
        self.assertNotIn('installation completed', result.stdout)

    def test_unknown_distro_fails_closed_with_manual_guidance(self):
        _, result, calls = self.run_installer(distro_id='gentoo', uid=0)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [])
        self.assertIn('Automatic Mosh package selection is unavailable', result.stderr)


if __name__ == '__main__':
    unittest.main()
