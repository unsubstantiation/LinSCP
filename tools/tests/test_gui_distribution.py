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
        frontend = ROOT / 'crates/linscp-tauri' / config['build']['frontendDist']
        self.assertEqual(frontend.resolve(), (ROOT / 'ui/dist').resolve())
        for icon in config['bundle']['icon']:
            self.assertTrue((ROOT / 'crates/linscp-tauri' / icon).is_file(), icon)

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
