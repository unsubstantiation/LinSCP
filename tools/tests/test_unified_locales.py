"""Tests for tools/build_unified_locales.py and locales/*.json."""
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import build_unified_locales as unified


class UnifiedLocalesTests(unittest.TestCase):
    def test_checked_in_unified_locales_are_current(self):
        stale, catalogs = unified.write_or_check(check_only=True)
        self.assertEqual(stale, [])
        self.assertEqual(sorted(catalogs.keys()), ['de', 'en', 'es', 'fr'])

    def test_cli_and_gui_namespaces_preserve_distinct_translations(self):
        data = json.loads((unified.UNIFIED_DIR / 'es.json').read_text(encoding='utf-8'))
        self.assertIn('cli', data)
        self.assertIn('gui', data)
        # "upload" is an operation noun in CLI error templates ("subida") and
        # an action label in GUI synchronization previews ("subir").
        self.assertEqual(data['cli']['upload'], 'subida')
        self.assertEqual(data['gui']['upload'], 'subir')


if __name__ == '__main__':
    unittest.main()
