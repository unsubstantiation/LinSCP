"""Regressions of the Wayland compatibility check.

The check is the guard that keeps LinSCP usable on a Wayland desktop as well as
under X11, so it has to be shown to fail on the things it claims to catch and to
stay quiet about the ones it does not.
"""
import pathlib
import re
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_wayland_compatibility as check

TERMINAL_TABLE = 'crates/linscp-platform/src/terminal.rs'
GUI_LAUNCHER = 'crates/linscp-platform/src/linux.rs'


class WaylandCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        for directory in ('source/linux', 'source/gui', 'crates/linscp-platform/src', 'automation', 'debian',
                          'docs', 'tools', '.github'):
            (self.root / directory).mkdir(parents=True)
        self.addCleanup(self.tmp.cleanup)

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def names(self, findings):
        return sorted(name for _, _, name, _, _ in findings)

    def constructs_in(self, relative, text):
        """What the per-line rules say about one file's text."""
        path = self.write(relative, text)
        return check.find_constructs(
            path, check.strip_comments(path, path.read_text()), self.root)

    def display_findings_in(self, text, relative=TERMINAL_TABLE):
        """What the display-server decision rules say about one file."""
        self.write(relative, text)
        return check.check_display_reads(self.root)

    # --- the tree as it stands -----------------------------------------

    def test_the_real_tree_needs_no_x11(self):
        self.assertEqual(check.collect(), [])

    def test_the_real_desktop_entry_is_one_a_launcher_can_use(self):
        text = (check.ROOT / check.DESKTOP_ENTRY).read_text()
        self.assertIn('StartupNotify=false', text)
        self.assertIn('TryExec=linscp-gui', text)
        # The desktop entry runs the native GUI directly, not a browser server.
        self.assertIn('Exec=linscp-gui\n', text)
        self.assertNotIn('--open-browser', text)

    def test_the_real_detection_reads_both_display_servers(self):
        for relative in check.SESSION_DETECTORS:
            text = (check.ROOT / relative).read_text()
            for variable in check.SESSION_VARIABLES:
                # Pure-Rust detectors in crates/ only need WAYLAND_DISPLAY/DISPLAY;
                # XDG_RUNTIME_DIR and wayland-0 are legacy source/ requirements.
                if relative.startswith('crates/') and variable == 'XDG_RUNTIME_DIR':
                    continue
                self.assertIn(variable, text, '%s: %s' % (relative, variable))
            if relative.startswith('source/'):
                self.assertIn(check.DEFAULT_WAYLAND_SOCKET, text, relative)

    def test_the_real_terminal_table_classifies_every_program(self):
        text = (check.ROOT / TERMINAL_TABLE).read_text()
        rows = terminal_rows(text)
        self.assertTrue(len(rows) >= 13)
        for name, _leading, backend in rows:
            self.assertIn(backend, ('', 'wayland', 'x11'), name)
        # A session has to have something to be offered: at least one program
        # that draws on Wayland, one that draws on X11 and one that does both.
        backends = {backend for _, _, backend in rows}
        self.assertEqual(backends, {'', 'wayland', 'x11'})

    # --- a display server found by half its variables ------------------

    def test_an_x11_only_display_test_is_found(self):
        findings = self.display_findings_in(
            'void choose() {\n'
            '    if (getenv("DISPLAY") == NULL) { return no_session(); }\n'
            '}\n')
        self.assertIn('display-server-detection', self.names(findings))
        self.assertEqual(len(findings), 1)

    def test_a_display_test_that_asks_wayland_too_is_clean(self):
        self.assertEqual(self.display_findings_in(
            'void choose() {\n'
            '    if (getenv("DISPLAY") == NULL &&\n'
            '        getenv("WAYLAND_DISPLAY") == NULL) { return; }\n'
            '}\n'), [])

    def test_a_shell_launcher_reading_two_variables_is_clean(self):
        self.assertEqual(self.display_findings_in(
            'if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then open; fi\n',
            GUI_LAUNCHER), [])

    def test_a_wayland_variable_far_from_the_test_is_no_answer(self):
        # One file, two decisions: the mention of Wayland has to be part of the
        # choice that asks about X11, or the choice is still an X11 one. The
        # filler is what puts them out of reach of each other.
        far = ''.join('int unrelated_%d(int value) { return value + %d; }\n'
                      % (i, i) for i in range(24))
        self.assertTrue(len(far) > check.DISPLAY_WINDOW)
        findings = self.display_findings_in(
            'static const char * kNames[] = {"WAYLAND_DISPLAY",\n'
            '    "XDG_RUNTIME_DIR", "LINSCP_TERMINAL"};\n' + far +
            'void choose() {\n'
            '    if (getenv("DISPLAY") == NULL) { return no_session(); }\n'
            '}\n')
        self.assertIn('display-server-detection', self.names(findings))

    def test_a_comment_about_the_display_variable_is_not_a_finding(self):
        # A comment may explain what the code deliberately does not do.
        self.assertEqual(self.display_findings_in(
            '/* No $DISPLAY test here: this program draws no window. */\n'
            'int answer() { return 42; }\n'), [])

    # --- one display server's helper programs --------------------------

    def test_an_x11_only_helper_is_found(self):
        findings = self.constructs_in(GUI_LAUNCHER,
                                      'subprocess.run(["xclip", "-o"])\n')
        self.assertIn('x11-only-tool', self.names(findings))
        findings = self.constructs_in(TERMINAL_TABLE,
                                      '  execlp("/usr/bin/wmctrl", NULL);\n')
        self.assertIn('x11-only-tool', self.names(findings))

    def test_a_wayland_only_helper_is_found(self):
        findings = self.constructs_in(TERMINAL_TABLE, '  run("grim", "out.png");\n')
        self.assertIn('wayland-only-tool', self.names(findings))

    def test_a_helper_named_in_a_comment_is_not_a_finding(self):
        self.assertEqual(self.constructs_in(TERMINAL_TABLE,
                                            '/* No xclip here: a Wayland session does not answer it. */\n'
                                            '// xdotool would work under X11 only.\n'), [])

    # --- a terminal that may not be able to show a window --------------

    def test_a_terminal_row_without_a_display_server_is_found(self):
        findings = self.constructs_in(TERMINAL_TABLE,
                                      'const TerminalProgram kTable[] = {\n'
                                      '    {"foot", {NULL}},\n};\n')
        self.assertIn('terminal-backend-missing', self.names(findings))

    def test_a_terminal_row_with_an_unknown_display_server_is_found(self):
        findings = self.constructs_in(TERMINAL_TABLE,
                                      'const TerminalProgram kTable[] = {\n'
                                      '    {"foot", {NULL}, "drm"},\n};\n')
        self.assertIn('terminal-backend-unknown', self.names(findings))

    def test_a_terminal_row_that_says_what_it_draws_on_is_clean(self):
        self.assertEqual(self.constructs_in(TERMINAL_TABLE,
                                            'const TerminalProgram kTable[] = {\n'
                                            '    {"foot", {NULL}, "wayland"},\n'
                                            '    {"xterm", {"-e", NULL}, "x11"},\n'
                                            '    {"konsole", {"-e", NULL}, ""},\n};\n'), [])

    # --- the desktop entry ---------------------------------------------

    def test_startup_notification_nobody_can_complete_is_found(self):
        self.write(check.DESKTOP_ENTRY,
                   '[Desktop Entry]\nType=Application\nExec=linscp-gui %u\n'
                   'StartupNotify=true\n')
        self.assertIn('desktop-entry', self.names(check.check_desktop_entry(self.root)))

    def test_startup_notification_with_a_window_class_is_not_a_finding(self):
        self.write(check.DESKTOP_ENTRY,
                   '[Desktop Entry]\nType=Application\nExec=linscp %u\n'
                   'StartupNotify=true\nStartupWMClass=linscp\n')
        self.assertEqual(check.check_desktop_entry(self.root), [])

    def test_an_entry_that_maps_no_window_says_so(self):
        # A server and a printed address: nothing to notify about, and 'false'
        # is what keeps a compositor from waiting for a window that never
        # arrives. This is the shape of the entry the package ships.
        self.write(check.DESKTOP_ENTRY,
                   '[Desktop Entry]\nType=Application\n'
                   'Exec=linscp-gui --open-browser %u\nTryExec=linscp-gui\n'
                   'StartupNotify=false\n')
        self.assertEqual(check.check_desktop_entry(self.root), [])

    def test_a_comment_about_the_entry_is_not_its_setting(self):
        self.write(check.DESKTOP_ENTRY,
                   '[Desktop Entry]\nType=Application\nExec=linscp-gui %u\n'
                   '# StartupNotify=true would be wrong here\n')
        self.assertEqual(check.check_desktop_entry(self.root), [])

    def test_an_entry_without_an_exec_is_found(self):
        self.write(check.DESKTOP_ENTRY, '[Desktop Entry]\nType=Application\n')
        self.assertIn('desktop-entry', self.names(check.check_desktop_entry(self.root)))

    def test_a_missing_desktop_entry_is_found(self):
        self.assertIn('desktop-entry', self.names(check.check_desktop_entry(self.root)))

    # --- the two detections of the session -----------------------------

    def test_detectors_that_disagree_are_found(self):
        # For crates/ detectors, only DISPLAY vs WAYLAND_DISPLAY matters;
        # XDG_RUNTIME_DIR and wayland-0 are legacy source/ requirements.
        self.write(TERMINAL_TABLE,
                   'getenv("DISPLAY");\n')
        self.write(GUI_LAUNCHER,
                   'environment.get("WAYLAND_DISPLAY")\n')
        findings = check.check_detectors_agree(self.root)
        self.assertTrue(findings)
        self.assertTrue(all(name == 'session-detection-parity'
                            for _, _, name, _, _ in findings))
        reported = ' '.join(text for _, _, _, _, text in findings)
        # Should report disagreement on DISPLAY or WAYLAND_DISPLAY
        self.assertTrue('DISPLAY' in reported or 'WAYLAND_DISPLAY' in reported)

    def test_detectors_that_read_the_same_thing_agree(self):
        for relative in (TERMINAL_TABLE, GUI_LAUNCHER):
            self.write(relative,
                       'DISPLAY WAYLAND_DISPLAY XDG_RUNTIME_DIR wayland-0\n')
        self.assertEqual(check.check_detectors_agree(self.root), [])

    def test_a_missing_detection_is_found(self):
        self.write(TERMINAL_TABLE,
                   'DISPLAY WAYLAND_DISPLAY XDG_RUNTIME_DIR wayland-0\n')
        self.assertIn('session-detection-parity',
                      self.names(check.check_detectors_agree(self.root)))

    # --- the documentation of the choice -------------------------------

    def test_documentation_of_the_terminal_without_the_display_server(self):
        self.write('docs/debian.md',
                   'The program is taken from LINSCP_TERMINAL or the first\n'
                   'installed terminal.\n')
        self.assertIn('docs-display-server',
                      self.names(check.check_terminal_docs(self.root)))

    def test_documentation_that_names_the_session_is_clean(self):
        self.write('docs/debian.md',
                   'The program is taken from LINSCP_TERMINAL, or from the\n'
                   'installed one that draws on Wayland or on X11.\n')
        self.assertEqual(check.check_terminal_docs(self.root), [])


def terminal_rows(text):
    """The terminal candidates of a table, as (name, leading, backend)."""
    rows = []
    for match in re.finditer(
            r'\{\s*"([a-z0-9._-]+)"\s*,\s*\{([^{}]*)\}\s*(?:,\s*"([a-z0-9_-]*)")?\s*\}',
            text):
        rows.append((match.group(1), match.group(2).strip(),
                     match.group(3) if match.group(3) is not None else None))
    # Rust pure-Rust table: ("name", &["args"], "backend")
    for match in re.finditer(
            r'\(\s*"([a-z0-9._-]+)"\s*,\s*&\[[^\]]*\]\s*(?:,\s*"([a-z0-9_-]*)")?\s*\)',
            text):
        rows.append((match.group(1), "", match.group(2) if match.group(2) is not None else None))
    return rows


if __name__ == '__main__':
    unittest.main()
