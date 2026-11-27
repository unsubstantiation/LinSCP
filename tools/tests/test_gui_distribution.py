"""Guard the native-only desktop distribution against CLI regressions."""
import json
import pathlib
import shutil
import subprocess
import tempfile
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

    def test_the_product_is_one_native_application_with_no_web_host(self):
        # The Windows build used to produce two apps from this workspace: the
        # native window and `linscp-web`, a browser server that served the same
        # page over HTTP. There is no web app in this product, so the crate, its
        # binary and its launcher are gone and nothing may build them again.
        workspace = tomllib.loads((ROOT / 'Cargo.toml').read_text())['workspace']
        self.assertNotIn('crates/linscp-http', workspace['members'])
        self.assertNotIn('linscp-http', workspace['dependencies'])
        self.assertFalse((ROOT / 'crates/linscp-http').exists())
        self.assertFalse((ROOT / 'debian/linscp-web.desktop').exists())
        for name in ['CMakeLists.txt', 'source/linux/Makefile', 'debian/rules',
                     '.github/workflows/windows-build.yml',
                     '.github/workflows/debian-build.yml']:
            text = (ROOT / name).read_text()
            for token in ['linscp-http', 'linscp-web']:
                self.assertNotIn(token, text, name + ' still names ' + token)

    def test_the_native_application_is_the_only_thing_built_and_installed(self):
        for name in ['CMakeLists.txt', 'source/linux/Makefile', 'debian/rules']:
            text = (ROOT / name).read_text()
            self.assertIn('linscp-tauri', text, name)
            self.assertIn('target/release/linscp-gui', text, name)
        desktop = (ROOT / 'debian/linscp.desktop').read_text()
        self.assertEqual(desktop.count('[Desktop Entry]'), 1)
        self.assertIn('\nExec=linscp-gui %u\n', desktop)
        handlers = next(line for line in desktop.splitlines() if line.startswith('MimeType='))
        for scheme in ['sftp', 'scp', 'ftp', 'ftps', 'ftpes', 'dav', 'davs', 'webdav', 'webdavs', 's3']:
            self.assertIn('x-scheme-handler/' + scheme + ';', handlers)
        self.assertNotIn('x-scheme-handler/https;', handlers)
        windows = (ROOT / '.github/workflows/windows-build.yml').read_text()
        self.assertIn('target/release/linscp-gui.exe', windows)
        # Releases are managed by hand, so the artifact is only how the built
        # exe leaves the run - stored uncompressed in the envelope GitHub
        # always zips (compression-level: 0).
        upload = windows[windows.index('Upload the portable application'):]
        self.assertEqual(upload.count('.exe'), 1, 'the artifact must be one app')
        self.assertIn('compression-level: 0', upload)

    @unittest.skipUnless(shutil.which('make') and shutil.which('install'), 'make and install required')
    def test_make_install_honors_prefix_and_destdir(self):
        # Stage a fake build output in an isolated source tree. -o all tests
        # the real install recipe without compiling or touching the checkout.
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / 'source'
            (root / 'source/linux').mkdir(parents=True)
            (root / 'target/release').mkdir(parents=True)
            (root / 'debian').mkdir()
            shutil.copy(ROOT / 'source/linux/Makefile', root / 'source/linux/Makefile')
            (root / 'tools').mkdir()
            shutil.copy(ROOT / 'tools/install_desktop_entry.py', root / 'tools/install_desktop_entry.py')
            (root / 'target/release/linscp-gui').write_text('stub executable')
            for asset in ['linscp.desktop', 'linscp.png', 'linscp.svg']:
                shutil.copy(ROOT / 'debian' / asset, root / 'debian' / asset)
            stage = pathlib.Path(tmp) / 'stage with spaces'
            subprocess.run(['make', '-C', str(root / 'source/linux'), '-o', 'all', 'install',
                            'PREFIX=/opt/linscp custom', 'DESTDIR=' + str(stage)], check=True, capture_output=True, text=True)
            prefix = stage / 'opt/linscp custom'
            binary = prefix / 'bin/linscp-gui'
            self.assertEqual(binary.read_text(), 'stub executable')
            self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
            for path in ['share/applications/linscp.desktop', 'share/pixmaps/linscp.png',
                         'share/icons/hicolor/scalable/apps/linscp.svg']:
                self.assertTrue((prefix / path).is_file(), path)
            desktop = (prefix / 'share/applications/linscp.desktop').read_text()
            self.assertIn('\nExec="/opt/linscp custom/bin/linscp-gui" %u\n', desktop)
            self.assertIn('\nTryExec=/opt/linscp custom/bin/linscp-gui\n', desktop)
            self.assertNotIn(str(stage), desktop)
            self.assertFalse((stage / 'usr').exists())
            default_stage = pathlib.Path(tmp) / 'default stage'
            subprocess.run(['make', '-C', str(root / 'source/linux'), '-o', 'all', 'install',
                            'DESTDIR=' + str(default_stage)], check=True, capture_output=True, text=True)
            self.assertTrue((default_stage / 'usr/bin/linscp-gui').is_file())

    @unittest.skipUnless(shutil.which('cmake'), 'cmake required')
    def test_cmake_install_honors_prefix_and_destdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / 'source'
            root.mkdir()
            (root / 'target/release').mkdir(parents=True)
            (root / 'debian').mkdir()
            shutil.copy(ROOT / 'CMakeLists.txt', root / 'CMakeLists.txt')
            (root / 'tools').mkdir()
            shutil.copy(ROOT / 'tools/install_desktop_entry.py', root / 'tools/install_desktop_entry.py')
            (root / 'target/release/linscp-gui').write_text('stub executable')
            for asset in ['linscp.desktop', 'linscp.png', 'linscp.svg']:
                shutil.copy(ROOT / 'debian' / asset, root / 'debian' / asset)
            build = pathlib.Path(tmp) / 'build'
            stage = pathlib.Path(tmp) / 'stage with spaces'
            subprocess.run(['cmake', '-S', str(root), '-B', str(build),
                            '-DCARGO=' + shutil.which('true'), '-DNPM=' + shutil.which('true'),
                            '-DCMAKE_INSTALL_PREFIX=/opt/linscp custom'], check=True, capture_output=True, text=True)
            import os
            subprocess.run(['cmake', '--install', str(build)], env={**os.environ, 'DESTDIR': str(stage)},
                           check=True, capture_output=True, text=True)
            prefix = stage / 'opt/linscp custom'
            binary = prefix / 'bin/linscp-gui'
            self.assertEqual(binary.read_text(), 'stub executable')
            self.assertEqual(binary.stat().st_mode & 0o777, 0o755)
            for path in ['share/applications/linscp.desktop', 'share/pixmaps/linscp.png',
                         'share/icons/hicolor/scalable/apps/linscp.svg']:
                self.assertTrue((prefix / path).is_file(), path)
            desktop = (prefix / 'share/applications/linscp.desktop').read_text()
            self.assertIn('\nExec="/opt/linscp custom/bin/linscp-gui" %u\n', desktop)
            self.assertIn('\nTryExec=/opt/linscp custom/bin/linscp-gui\n', desktop)
            self.assertNotIn(str(stage), desktop)
            self.assertFalse((stage / 'usr').exists())
            override = '/opt/override prefix'
            subprocess.run(['cmake', '--install', str(build), '--prefix', override],
                           env={**os.environ, 'DESTDIR': str(stage)}, check=True, capture_output=True, text=True)
            desktop = (stage / 'opt/override prefix/share/applications/linscp.desktop').read_text()
            self.assertIn('\nExec="/opt/override prefix/bin/linscp-gui" %u\n', desktop)
            self.assertNotIn(str(stage), desktop)

    @unittest.skipUnless(__import__('ctypes.util', fromlist=['find_library']).find_library('gio-2.0'), 'GIO required')
    def test_custom_prefix_desktop_entry_launches_uri_without_path_lookup(self):
        import os
        import sys
        import time
        with tempfile.TemporaryDirectory() as tmp:
            prefix = pathlib.Path(tmp) / 'prefix % space "quote" $dollar \\backslash'
            binary = prefix / 'bin/linscp-gui'
            binary.parent.mkdir(parents=True)
            binary.write_text('#!/bin/sh\nprintf "%s" "$1" > "$LINSCP_TEST_CAPTURE"\n')
            binary.chmod(0o755)
            subprocess.run([sys.executable, str(ROOT / 'tools/install_desktop_entry.py'),
                            '--prefix', str(prefix), '--template', str(ROOT / 'debian/linscp.desktop')], check=True)
            desktop = prefix / 'share/applications/linscp.desktop'
            capture = pathlib.Path(tmp) / 'argument'
            uri = 'sftp://example.invalid/path%20with%20spaces'
            config = pathlib.Path(tmp) / 'xdg-config'
            data_home = pathlib.Path(tmp) / 'xdg-data'
            config.mkdir()
            data_home.mkdir()
            (config / 'mimeapps.list').write_text('[Default Applications]\nx-scheme-handler/sftp=linscp.desktop;\n')
            # GIO parses and launches the actual desktop entry, not a shell
            # approximation of Exec. The prefix bin is deliberately off PATH.
            # A second invocation discovers it through isolated XDG defaults.
            code = '''
import ctypes, ctypes.util, sys
gio = ctypes.CDLL(ctypes.util.find_library("gio-2.0"))
glib = ctypes.CDLL(ctypes.util.find_library("glib-2.0"))
gio.g_desktop_app_info_new_from_filename.argtypes = [ctypes.c_char_p]
gio.g_desktop_app_info_new_from_filename.restype = ctypes.c_void_p
gio.g_app_info_launch_uris.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
gio.g_app_info_launch_uris.restype = ctypes.c_int
glib.g_list_append.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
glib.g_list_append.restype = ctypes.c_void_p
if sys.argv[3] == 'default':
    gio.g_app_info_get_default_for_uri_scheme.argtypes = [ctypes.c_char_p]
    gio.g_app_info_get_default_for_uri_scheme.restype = ctypes.c_void_p
    gio.g_app_info_get_id.argtypes = [ctypes.c_void_p]
    gio.g_app_info_get_id.restype = ctypes.c_char_p
    app = gio.g_app_info_get_default_for_uri_scheme(b'sftp')
    if not app or gio.g_app_info_get_id(app) != b'linscp.desktop':
        raise RuntimeError('GIO did not discover the configured SFTP handler')
else:
    app = gio.g_desktop_app_info_new_from_filename(sys.argv[1].encode())
if not app: raise RuntimeError("GIO rejected desktop entry or TryExec")
uri = ctypes.create_string_buffer(sys.argv[2].encode())
uris = glib.g_list_append(None, ctypes.cast(uri, ctypes.c_void_p))
error = ctypes.c_void_p()
if not gio.g_app_info_launch_uris(app, uris, None, ctypes.byref(error)):
    raise RuntimeError("GIO desktop launch failed")
'''
            env = {**os.environ, 'PATH': '/usr/bin:/bin', 'LINSCP_TEST_CAPTURE': str(capture),
                   'XDG_CONFIG_HOME': str(config), 'XDG_DATA_HOME': str(data_home),
                   'XDG_CONFIG_DIRS': str(config), 'XDG_DATA_DIRS': str(prefix / 'share')}
            for mode in ('explicit', 'default'):
                subprocess.run([sys.executable, '-c', code, str(desktop), uri, mode], check=True,
                               env=env, timeout=15)
                deadline = time.monotonic() + 10
                while not capture.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(capture.exists(), f'{mode} desktop entry did not launch the installed executable')
                self.assertEqual(capture.read_text(), uri)
                capture.unlink()

    def test_the_shared_page_reaches_the_native_bridge_only(self):
        # The page used to fall back to `fetch()` with a bearer token when no
        # `__TAURI_INTERNALS__` was present, because a browser server could
        # serve it. The browser host is gone, so HTTP transport, the token and
        # the server-account sign-in went with it.
        page = (ROOT / 'source/gui/web/index.html').read_text()
        for token in ['LSCP_TOKEN', 'X-LSCP-Token', 'X-LSCP-CSRF', 'csrfToken',
                      'loginModal', 'accountsEnabled', '/api/login']:
            self.assertNotIn(token, page, 'the page still carries ' + token)
        self.assertIn('window.LinSCPTransport.request', page)
        self.assertFalse((ROOT / 'ui/src/transport/http.ts').exists())
        transport = (ROOT / 'ui/src/transport/index.ts').read_text()
        self.assertNotIn('HttpTransport', transport)
        build = (ROOT / 'ui/scripts/build.mjs').read_text()
        self.assertNotIn('bearerToken', build)
        self.assertNotIn('fetch(', build)

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
        self.assertIn('\nExec=linscp-gui %u\n', desktop)
        self.assertNotIn('--open-browser', desktop)

    def test_the_shared_page_declares_no_name_twice(self):
        """A second `function f() {}` silently replaces the first.

        The page is one long script, so a helper added a second time does not
        collide loudly - the later definition simply wins, and the earlier one
        becomes dead code that still looks live. That happened to the terminal's
        own byte sender: two `sendTerminalBytes` existed, and whether the
        extra-keys row worked came down to which was parsed last.
        """
        import re
        page = (ROOT / 'source/gui/web/index.html').read_text()
        declared = {}
        for match in re.finditer(
            r'^  (?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(', page, re.MULTILINE
        ):
            declared.setdefault(match.group(1), []).append(match.start())
        duplicates = {name: at for name, at in declared.items() if len(at) > 1}
        if duplicates:
            detail = {
                name: [page.count('\n', 0, offset) + 1 for offset in offsets]
                for name, offsets in duplicates.items()
            }
            self.fail(f'these page functions are declared more than once: {detail}')

        # The helpers the terminal path depends on are declared, so a rename
        # cannot leave a call behind that only fails when it is reached.
        for name in ('sendTerminalBytes', 'openTerminalInPage', 'bootTerminalWindow'):
            self.assertIn(name, declared)


if __name__ == '__main__':
    unittest.main()
