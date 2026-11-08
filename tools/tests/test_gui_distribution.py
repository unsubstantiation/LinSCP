"""Guard the native-only desktop distribution against CLI regressions."""
import json
import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]


class GuiDistributionTests(unittest.TestCase):
    def test_workspace_contains_no_cli_binary(self):
        workspace = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']
        self.assertNotIn('crates/linscp-cli', workspace['members'])
        self.assertFalse((ROOT / 'crates/linscp-cli/Cargo.toml').exists())

    def test_native_shell_has_a_binary_and_embedded_frontend(self):
        manifest = tomllib.loads((ROOT / 'crates/linscp-tauri/Cargo.toml').read_text())
        binary = next(b for b in manifest['bin'] if b['name'] == 'linscp-gui')
        self.assertIn('native-shell', binary['required-features'])
        self.assertIn('tauri/custom-protocol', manifest['features']['native-shell'])
        main = (ROOT / 'crates/linscp-tauri/src/main.rs').read_text()
        self.assertIn('run_native_app(tauri::generate_context!())', main)
        config = json.loads((ROOT / 'crates/linscp-tauri/tauri.conf.json').read_text())
        csp = config['app']['security']['csp']
        # Commander controls currently use HTML click handlers. Keep their
        # policy explicit: WebViews can distinguish script elements from
        # event-handler attributes, so `script-src` alone is not enough.
        self.assertIn("script-src-attr 'unsafe-inline'", csp)
        frontend = ROOT / 'crates/linscp-tauri' / config['build']['frontendDist']
        self.assertEqual(frontend.resolve(), (ROOT / 'ui/dist').resolve())
        for icon in config['bundle']['icon']:
            self.assertTrue((ROOT / 'crates/linscp-tauri' / icon).is_file(), icon)

    def test_both_hosts_of_the_page_are_built_and_installed(self):
        # The native window and the browser server are the same application in
        # two hosts. Building and installing only one of them is the parity gap
        # this guards: a shipped package that cannot serve the page at all.
        server = tomllib.loads((ROOT / 'crates/linscp-http/Cargo.toml').read_text())
        binary = next(b for b in server.get('bin', []) if b['name'] == 'linscp-web')
        self.assertTrue((ROOT / 'crates/linscp-http' / binary['path']).is_file())
        main = (ROOT / 'crates/linscp-http/src/main.rs').read_text()
        self.assertIn('BrowserServer::bind', main)
        for name in ['CMakeLists.txt', 'source/linux/Makefile', 'debian/rules']:
            text = (ROOT / name).read_text()
            self.assertIn('linscp-http', text, name)
            self.assertIn('linscp-web', text, name)

    def test_ci_builds_and_smoke_tests_both_hosts(self):
        # A host that is built but never started is a host nobody has run. Each
        # desktop workflow therefore builds `linscp-web` and asks the running
        # server for the page and for one API answer.
        for name in ['.github/workflows/debian-build.yml',
                     '.github/workflows/windows-build.yml']:
            text = (ROOT / name).read_text()
            # The Debian workflow builds through `debian/rules`, which names the
            # crate; the Windows one builds it directly. Both start it.
            self.assertIn('linscp-web', text, name)
            self.assertIn('Smoke test the browser host', text, name)
            self.assertIn('X-LSCP-Token', text, name)
            self.assertIn('879', text, name)  # the port the smoke test uses
        self.assertIn('cargo build --release -p linscp-http',
                      (ROOT / '.github/workflows/windows-build.yml').read_text())
        self.assertIn('linscp-http', (ROOT / 'debian/rules').read_text())
        # The browser host is installed next to the native window, not instead
        # of it, and the package check names both.
        rules = (ROOT / 'debian/rules').read_text()
        self.assertIn('usr/bin/linscp-gui', rules)
        self.assertIn('usr/bin/linscp-web', rules)
        # Two launchers, two files: the desktop-entry spec allows only one
        # [Desktop Entry] group per file, so the browser host gets its own.
        desktop = (ROOT / 'debian/linscp.desktop').read_text()
        self.assertIn('\nExec=linscp-gui\n', desktop)
        self.assertNotIn('linscp-web', desktop)
        browser = (ROOT / 'debian/linscp-web.desktop').read_text()
        self.assertEqual(browser.count('[Desktop Entry]'), 1)
        self.assertIn('\nExec=linscp-web\n', browser)
        self.assertIn('\nTerminal=true\n', browser)
        for name in ['CMakeLists.txt', 'source/linux/Makefile', 'debian/rules']:
            self.assertIn('linscp-web.desktop', (ROOT / name).read_text(), name)

    def test_the_shipped_binary_reads_the_command_line_it_documents(self):
        # A3: `--install-shell-integration` and `--shell-upload` were documented,
        # written into the file-manager definitions and implemented in the service,
        # and no shipped entry point looked at argv, so none of it could ever run.
        # The gate is that the binary parses its arguments before it starts the
        # window, and that both desktop workflows drive the real binary.
        main = (ROOT / 'crates/linscp-tauri/src/main.rs').read_text()
        self.assertIn('cli_args::parse(&std::env::args()', main)
        self.assertLess(
            main.index('cli_args::parse'),
            main.index('run_native_app(tauri::generate_context!())'),
            'the window must not start before the arguments are read',
        )
        for action in ['InstallShellIntegration', 'UninstallShellIntegration',
                       'ShellUpload', 'Help']:
            self.assertIn('Action::' + action, main, action)
        # The parser is pure Rust in the platform crate, so the same code decides
        # on every target; it must carry its own tests.
        parser = (ROOT / 'crates/linscp-platform/src/cli_args.rs').read_text()
        self.assertIn('#[cfg(test)]', parser)
        self.assertIn('"--shell-upload"', parser)
        self.assertIn('pub mod cli_args;', (ROOT / 'crates/linscp-platform/src/lib.rs').read_text())
        self.assertIn('pub mod cli_actions;',
                      (ROOT / 'crates/linscp-service/src/lib.rs').read_text())

    def test_ci_exercises_the_file_manager_actions_on_both_desktops(self):
        debian = (ROOT / '.github/workflows/debian-build.yml').read_text()
        self.assertIn('Smoke test the file-manager actions', debian)
        for flag in ['--install-shell-integration', '--shell-upload',
                     '--uninstall-shell-integration']:
            self.assertIn(flag, debian, flag)
        # The GNOME Files script is driven the way GNOME Files drives it, through
        # the environment variable, not through argv.
        self.assertIn('NAUTILUS_SCRIPT_SELECTED_FILE_PATHS', debian)
        windows = (ROOT / '.github/workflows/windows-build.yml').read_text()
        self.assertIn('Smoke test the Explorer action', windows)
        self.assertIn('Upload with LinSCP.cmd', windows)
        self.assertIn('--shell-upload', windows)

    def test_shell_integration_is_not_offered_where_there_is_no_file_manager(self):
        # The definitions are written to an XDG data directory. Android would have
        # compiled the "not Windows" arm and created that directory inside the app
        # sandbox, so the arms are narrowed to Linux/Windows and everything else
        # refuses by name.
        gui_os = (ROOT / 'crates/linscp-platform/src/gui_os.rs').read_text()
        start = gui_os.index('pub fn install_shell_integration')
        end = gui_os.index('pub fn rename_no_replace')
        section = gui_os[start:end]
        self.assertNotIn('#[cfg(not(target_os = "windows"))]', section,
                         'the "not Windows" arm would compile for Android')
        self.assertEqual(
            section.count('#[cfg(not(any(target_os = "linux", target_os = "windows")))]'), 2,
            'both install and uninstall refuse on every other platform',
        )
        self.assertIn('Shell integration is available on Linux and Windows only.', section)
        self.assertIn('#[cfg(target_os = "linux")]\nfn linux_shell_targets', gui_os)

    def test_active_distribution_paths_do_not_build_or_ship_cli(self):
        for name in ['.github/workflows/windows-build.yml',
                     '.github/workflows/debian-build.yml',
                     '.github/workflows/android-build.yml',
                     'CMakeLists.txt', 'source/linux/Makefile', 'debian/rules']:
            text = (ROOT / name).read_text()
            self.assertNotIn('linscp-cli', text, name)
            self.assertNotIn('target/release/linscp.exe', text, name)
        desktop = (ROOT / 'debian/linscp.desktop').read_text()
        self.assertIn('\nExec=linscp-gui\n', desktop)
        self.assertNotIn('--open-browser', desktop)


if __name__ == '__main__':
    unittest.main()
