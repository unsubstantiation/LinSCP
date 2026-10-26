"""Catalog compiler regressions; no gettext or installed locales required."""
import json
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from compile_translations import (generate, ROOT, OUTPUT, load_catalogs,
                                  gui_page, GUI_PAGE, GUI_DIRECTORY,
                                  check_gui_coverage, check_cli_coverage)


class TranslationTests(unittest.TestCase):
    def test_checked_in_table_is_current(self):
        self.assertEqual(generate(ROOT / 'source/linux/locales'), OUTPUT.read_text(encoding='utf-8'))

    def test_gui_is_current_and_all_source_messages_have_catalogs(self):
        catalogs = load_catalogs(GUI_DIRECTORY)
        page = GUI_PAGE.read_text(encoding='utf-8')
        self.assertEqual(page, gui_page(catalogs, page))
        check_gui_coverage(catalogs, page)
        check_cli_coverage(load_catalogs(ROOT / 'source/linux/locales'))
        with self.assertRaises(ValueError):
            check_gui_coverage(catalogs, page.replace('Site Manager', 'Uncatalogued UI label'))
        with self.assertRaises(ValueError):
            check_gui_coverage(catalogs, page.replace('tn(', 'tn("new singular", "new plural", 2); tn(', 1))

    def test_inline_catalog_cannot_end_the_script(self):
        catalogs = {'en': {'attack': '</script><img src=x onerror=alert(1)>&\u2028'}}
        page = gui_page(catalogs, GUI_PAGE.read_text(encoding='utf-8'))
        data = page.split('const GUI_CATALOGS = ', 1)[1].split(';\n', 1)[0]
        self.assertNotIn('<', data)
        self.assertNotIn('&', data)
        self.assertEqual(json.loads(data), catalogs)

    def test_invalid_catalogs_are_rejected(self):
        invalid = [
            '{"Hello {name}": "Hola"}',
            '{"Hello {name}": "Hola {name} {extra}"}',
            '{"Hello {name}": "Hola {name"}',
            '{"Hello {name}": ""}',
            '{"Hello {name}": 3}',
            '{"Hello {name}": "a", "Hello {name}": "b"}',
            '{"Different": "Diferente"}',
        ]
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            (directory / 'en.json').write_text(json.dumps({'Hello {name}': 'Hello {name}'}))
            for text in invalid:
                with self.subTest(text=text):
                    (directory / 'es.json').write_text(text)
                    with self.assertRaises(ValueError):
                        generate(directory)

    def test_non_english_catalogs_are_not_left_in_english(self):
        """Walk every catalog and report messages still answered in English.

        Proper nouns, protocol tokens and identical technical words are
        allowed to match the English key; a newly added interface string
        that nobody translated is not.
        """
        allow = {
            "LinSCP", "SFTP", "SCP", "FTP", "FTPS", "WebDAV", "Amazon S3",
            "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "F9", "F10",
            "Ctrl+A", "Ctrl+L", "Ctrl+N", "Ctrl+R", "KiB", "ASCII", "Binary",
            "0", "lscp>", "path/to/key", "Servers/web1", "English", "Español",
            "{mode} {path}", "LinSCP Commander", "Kerberos (GSSAPI)",
            "SFTP (SSH)", "WebDAV (HTTPS)", " [{size} bytes]", "[{size} bytes]",
        }
        leftover = []
        for directory in (ROOT / "source/linux/locales", GUI_DIRECTORY):
            catalogs = load_catalogs(directory)
            for locale, catalog in catalogs.items():
                if locale == "en":
                    continue
                for key, value in catalog.items():
                    if value != key:
                        continue
                    if key in allow:
                        continue
                    if re.fullmatch(r"[A-Za-z0-9_./:+-]+", key) and len(key) <= 8:
                        continue
                    # Machine tokens and placeholder-only templates stay English
                    # on purpose so parsers and logs keep a stable spelling.
                    stripped = re.sub(r"\{[a-z]+\}", "", key)
                    stripped = re.sub(r"[0-9\s\[\]:'\"=._/-]", "", stripped)
                    if not stripped:
                        continue
                    if re.fullmatch(r"[A-Za-z]+", stripped) and stripped[0].isupper():
                        continue
                    leftover.append("%s:%s" % (locale, key[:80]))
        self.assertEqual(leftover, [], leftover[:20])

    def test_cli_literals_survive_translation(self):
        """Switches, values, commands and protocol words stay verbatim.

        A translated '-filemask' or 'on|off' would tell the user to type
        something the client rejects, and 'LSCP-RESULT' or 'SizeBytes' are
        read by programs. Metavariables such as <file> and FILE may be
        translated, including inside a quoted command such as 'lock <file>'.
        """
        switch = re.compile(r"(?<![A-Za-z0-9<_])-[a-z][a-z0-9]*(?![A-Za-z])")
        values = re.compile(r"(?<![A-Za-z])[a-z0-9]+(?:\|[a-z0-9]+)+(?![A-Za-z])")
        protocol = re.compile(r"\b(?:LSCP-RESULT|SizeBytes|ModifiedEpoch|AccessedEpoch)\b")
        quoted = re.compile(r"'([^'\n]+)'")
        commands = {"option", "savepreset", "rmspreset", "help", "lock", "etag",
                    "open", "savesession", "sessions", "both", "local", "remote",
                    "time", "size", "checksum", "none", "either", "!", "ln"}
        problems = []
        for locale, catalog in sorted(load_catalogs(ROOT / "source/linux/locales").items()):
            if locale == "en":
                continue
            for key, value in catalog.items():
                wanted = (set(switch.findall(key)) | set(values.findall(key)) |
                          set(protocol.findall(key)))
                missing = sorted(token for token in wanted if token not in value)
                for literal in quoted.findall(key):
                    if not literal.startswith("-") and literal.split()[0] not in commands:
                        continue
                    pattern = re.sub(r"<[^>]*>", "<[^>]+>", re.escape(literal))
                    if not re.search("'" + pattern + "'", value):
                        missing.append("'%s'" % literal)
                if missing:
                    problems.append("%s:%s: %s" % (locale, key[:60], missing))
        self.assertEqual(problems, [], problems[:10])

    def test_cli_help_keeps_every_option_and_command(self):
        """Each catalog's main help lists the same options and commands in order."""
        def entries(text):
            return [re.match(r"[-a-z/]+", line[2:]).group(0)
                    for line in text.split("\n") if re.match(r"  [-a-z]", line)]
        catalogs = load_catalogs(ROOT / "source/linux/locales")
        key = next(k for k in catalogs["en"] if k.startswith("LinSCP {version} - "))
        self.assertIn("-shell", entries(key))
        for locale, catalog in sorted(catalogs.items()):
            with self.subTest(locale=locale):
                self.assertEqual(entries(catalog[key]), entries(key))

    def test_yes_no_prompts_offer_one_yes_letter(self):
        """Console::Confirm accepts the letter each prompt shows after '['."""
        for locale, catalog in sorted(load_catalogs(ROOT / "source/linux/locales").items()):
            with self.subTest(locale=locale):
                upper = re.fullmatch(r" \[(.)/(.)\]: ", catalog[" [Y/n]: "])
                lower = re.fullmatch(r" \[(.)/(.)\]: ", catalog[" [y/N]: "])
                self.assertTrue(upper and lower)
                self.assertEqual(upper.group(1).lower(), lower.group(1).lower())
                self.assertEqual(upper.group(2).lower(), lower.group(2).lower())
                self.assertNotEqual(upper.group(1).lower(), upper.group(2).lower())

    def test_cpp_strings_are_escaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = pathlib.Path(tmp)
            text = 'Quote " and newline\n and backslash \\'
            (directory / 'en.json').write_text(json.dumps({text: text}))
            self.assertIn(json.dumps(text), generate(directory))


if __name__ == '__main__':
    unittest.main()
