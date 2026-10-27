"""Tests for tools/build_unified_locales.py and locales/*.json."""
import json
import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import build_unified_locales as unified

PLACEHOLDER_RE = re.compile(r'\{([a-z]+)\}')


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
