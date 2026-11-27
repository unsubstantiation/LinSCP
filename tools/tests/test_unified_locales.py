"""Tests for tools/build_unified_locales.py and locales/*.json."""
import contextlib
import io
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from unittest import mock
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import build_unified_locales as unified
import update_translations as update

PLACEHOLDER_RE = re.compile(r'\{([a-z]+)\}')


class UnifiedLocalesTests(unittest.TestCase):
    def test_checked_in_unified_locales_are_current(self):
        stale, catalogs = unified.write_or_check(check_only=True)
        self.assertEqual(stale, [])
        self.assertEqual(sorted(catalogs.keys()), ['de', 'en', 'es', 'fr'])

    def test_single_command_checks_all_current_outputs(self):
        self.assertEqual(update.main(['--check']), 0)
        outputs = update.render_all()
        self.assertIn(update.translations.GUI_PAGE, outputs)
        self.assertTrue(all(unified.UNIFIED_DIR / f'{locale}.json' in outputs
                            for locale in ('en', 'de', 'es', 'fr')))

    def test_check_reports_missing_and_stale_without_writing_and_regenerate_repairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            html, catalog = root / 'index.html', root / 'locales/en.json'
            html.write_text('old', encoding='utf-8')
            outputs = {html: 'new', catalog: 'catalog'}
            self.assertEqual(update.apply_outputs(outputs, check_only=True), [html, catalog])
            self.assertEqual(html.read_text(encoding='utf-8'), 'old')
            self.assertFalse(catalog.exists())
            self.assertEqual(update.apply_outputs(outputs), [])
            self.assertEqual(update.apply_outputs(outputs, check_only=True), [])
            self.assertEqual(html.read_text(encoding='utf-8'), 'new')
            self.assertEqual(catalog.read_text(encoding='utf-8'), 'catalog')

    def test_invalid_sources_or_unexpected_locales_do_not_write_any_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            page = root / 'index.html'
            page.write_text('original', encoding='utf-8')
            orphan = root / 'zz.json'
            orphan.write_text('user data', encoding='utf-8')
            with mock.patch.object(update.translations, 'render_outputs', return_value={page: 'new'}), \
                 mock.patch.object(unified, 'UNIFIED_DIR', root):
                with contextlib.redirect_stderr(io.StringIO()) as error:
                    self.assertEqual(update.main([]), 1)
                self.assertIn('Unexpected unified locale', error.getvalue())
                self.assertEqual(page.read_text(encoding='utf-8'), 'original')
                self.assertEqual(orphan.read_text(encoding='utf-8'), 'user data')
            with mock.patch.object(update.translations, 'render_outputs', side_effect=ValueError('invalid catalog')):
                with contextlib.redirect_stderr(io.StringIO()) as error:
                    self.assertEqual(update.main([]), 1)
                self.assertIn('invalid catalog', error.getvalue())
                self.assertEqual(page.read_text(encoding='utf-8'), 'original')

    def test_command_round_trips_all_outputs_in_an_isolated_checkout(self):
        root = unified.ROOT
        with tempfile.TemporaryDirectory() as tmp:
            clone = pathlib.Path(tmp)
            (clone / 'tools').mkdir()
            for script in ('update_translations.py', 'compile_translations.py', 'build_unified_locales.py'):
                shutil.copy(root / 'tools' / script, clone / 'tools' / script)
            for directory in ('source/linux/locales', 'source/gui/locales', 'source/gui/web', 'locales'):
                shutil.copytree(root / directory, clone / directory)
            command = [sys.executable, str(clone / 'tools/update_translations.py')]
            def run(*args):
                return subprocess.run(command + list(args), capture_output=True, text=True)
            self.assertEqual(run('--check').returncode, 0)
            page = clone / 'source/gui/web/index.html'
            catalog = clone / 'locales/es.json'
            # Alter only the generated block, not source messages.
            page.write_text(page.read_text(encoding='utf-8').replace('const GUI_CATALOGS = ', 'const GUI_CATALOGS =  ', 1), encoding='utf-8')
            catalog.write_text('stale', encoding='utf-8')
            result = run('--check')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('index.html', result.stderr)
            self.assertIn('es.json', result.stderr)
            self.assertEqual(catalog.read_text(encoding='utf-8'), 'stale')
            self.assertEqual(run().returncode, 0)
            self.assertEqual(run('--check').returncode, 0)
            baseline = page.read_bytes(), catalog.read_bytes()
            (clone / 'source/gui/locales/fr.json').unlink()
            self.assertNotEqual(run().returncode, 0)
            self.assertEqual((page.read_bytes(), catalog.read_bytes()), baseline)

    def test_cli_and_gui_namespaces_preserve_distinct_translations(self):
        data = json.loads((unified.UNIFIED_DIR / 'es.json').read_text(encoding='utf-8'))
        self.assertIn('cli', data)
        self.assertIn('gui', data)
        # "upload" is an operation noun in CLI error templates ("subida") and
        # an action label in GUI synchronization previews ("subir").
        self.assertEqual(data['cli']['upload'], 'subida')
        self.assertEqual(data['gui']['upload'], 'subir')

    def test_placeholders_and_yes_no_prompts_hold_across_unified_catalogs(self):
        _, catalogs = unified.write_or_check(check_only=True)
        en = catalogs['en']
        for locale in ('de', 'es', 'fr'):
            with self.subTest(locale=locale):
                for domain in ('cli', 'gui'):
                    self.assertEqual(set(catalogs[locale][domain]), set(en[domain]))
                    for key, en_val in en[domain].items():
                        tr_val = catalogs[locale][domain][key]
                        self.assertEqual(
                            sorted(set(PLACEHOLDER_RE.findall(en_val))),
                            sorted(set(PLACEHOLDER_RE.findall(tr_val))),
                            msg=f'{locale}/{domain} placeholder mismatch for {key!r}',
                        )
                upper = re.fullmatch(r' \[(.)/(.)\]: ', catalogs[locale]['cli'][' [Y/n]: '])
                lower = re.fullmatch(r' \[(.)/(.)\]: ', catalogs[locale]['cli'][' [y/N]: '])
                self.assertTrue(upper and lower)
                self.assertEqual(upper.group(1).lower(), lower.group(1).lower())
                self.assertNotEqual(upper.group(1).lower(), upper.group(2).lower())


if __name__ == '__main__':
    unittest.main()
