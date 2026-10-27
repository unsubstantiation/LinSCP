"""Regressions for tools/check_repo_hygiene.py."""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_repo_hygiene as hygiene


class RepoHygieneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def names(self, findings):
        return [name for _, _, name, _, _ in findings]

    def test_real_repository_passes_hygiene(self):
        self.assertEqual(hygiene.collect(), [])

    def test_os_cfg_in_portable_crate_is_rejected(self):
        self.write(
            'crates/linscp-proto/src/lib.rs',
            '#[cfg(target_os = "windows")]\npub fn bad() {}\n',
        )
        findings = hygiene.check_crate_boundaries(self.root)
        self.assertIn('crate-os-cfg', self.names(findings))

    def test_os_dependency_in_portable_crate_manifest_is_rejected(self):
        self.write(
            'crates/linscp-engine/Cargo.toml',
            '[package]\nname = "linscp-engine"\n[dependencies]\nwindows-sys = "0.59"\n',
        )
        findings = hygiene.check_crate_boundaries(self.root)
        self.assertIn('crate-os-dependency', self.names(findings))

    def test_os_cfg_and_deps_in_platform_and_tauri_crates_are_allowed(self):
        self.write(
            'crates/linscp-platform/Cargo.toml',
            '[package]\nname = "linscp-platform"\n'
            '[target.\'cfg(windows)\'.dependencies]\nwindows-sys = "0.59"\n',
        )
        self.write(
            'crates/linscp-platform/src/lib.rs',
            '#[cfg(windows)]\npub mod windows;\n'
            '#[cfg(target_os = "android")]\npub mod android;\n',
        )
        self.write(
            'crates/linscp-tauri/src/lib.rs',
            '#[cfg_attr(mobile, tauri::mobile_entry_point)]\npub fn run() {}\n',
        )
        self.assertEqual(hygiene.check_crate_boundaries(self.root), [])

    def test_raw_fetch_or_tauri_outside_ui_transport_is_rejected(self):
        self.write(
            'ui/src/components/pane.ts',
            'export async function load() { return fetch("/api/status"); }\n',
        )
        self.write(
            'ui/src/state/store.ts',
            'export const isNative = Boolean((window as any).__TAURI_INTERNALS__);\n',
        )
        findings = hygiene.check_ui_transport_boundary(self.root)
        self.assertEqual(self.names(findings), ['ui-raw-transport', 'ui-raw-transport'])

    def test_fetch_and_tauri_inside_ui_transport_are_allowed(self):
        self.write(
            'ui/src/transport/client.ts',
            'export function hasTauri() { return Boolean((window as any).__TAURI_INTERNALS__); }\n'
            'export function httpCall(u: string) { return fetch(u); }\n',
        )
        self.assertEqual(hygiene.check_ui_transport_boundary(self.root), [])

    def test_unlisted_brand_in_rust_or_ui_is_rejected(self):
        bad = 'Win' + 'SCP'
        self.write('crates/linscp-types/src/lib.rs', f'// {bad} helper\n')
        findings = hygiene.collect(self.root)
        self.assertIn('brand-reference', self.names(findings))


if __name__ == '__main__':
    unittest.main()
