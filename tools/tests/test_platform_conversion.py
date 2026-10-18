"""Regressions of the platform-conversion check.

The check is the guard that keeps LinSCP a Linux-only client, so it
has to be shown to fail on the things it claims to catch and to stay
quiet about the ones it does not.
"""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_platform_conversion as check


class ConversionCheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        (self.root / 'source/linux').mkdir(parents=True)
        (self.root / 'source/gui').mkdir(parents=True)
        (self.root / 'automation').mkdir(parents=True)
        (self.root / 'debian').mkdir(parents=True)
        (self.root / 'docs').mkdir(parents=True)
        (self.root / 'tools').mkdir(parents=True)
        (self.root / '.github').mkdir(parents=True)
        self.addCleanup(self.tmp.cleanup)

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def names(self, findings):
        return sorted(name for _, _, name, _, _ in findings)

    def test_the_real_tree_has_no_windows_construct(self):
        self.assertEqual(check.collect(), [])

    def test_a_windows_api_call_is_found(self):
        path = self.write('source/linux/Platform.cpp',
                          'int f() { return (int)GetTempPath(MAX_PATH, buf); }\n')
        findings = check.find_windows_constructs(
            path, check.strip_comments(path, path.read_text()), self.root)
        self.assertIn('win32-api', self.names(findings))

    def test_a_windows_header_is_found(self):
        path = self.write('source/linux/Platform.cpp',
                          '#include <windows.h>\n')
        findings = check.find_windows_constructs(
            path, check.strip_comments(path, path.read_text()), self.root)
        self.assertIn('win32-headers', self.names(findings))

    def test_a_windows_only_branch_is_found(self):
        path = self.write('source/linux/Platform.cpp',
                          '#ifdef _WIN32\nint f() { return 1; }\n#endif\n')
        findings = check.find_windows_constructs(
            path, check.strip_comments(path, path.read_text()), self.root)
        self.assertIn('win32-macros', self.names(findings))

    def test_a_windows_environment_variable_is_found(self):
        path = self.write('source/gui/linscp_gui.py',
                          'root = os.environ["APPDATA"]\n')
        findings = check.find_windows_constructs(
            path, check.strip_comments(path, path.read_text()), self.root)
        self.assertIn('win32-env', self.names(findings))

    def test_a_windows_drive_letter_is_found(self):
        path = self.write('source/linux/PathUtil.cpp',
                          'const char * p = "C:\\\\Users";\n')
        findings = check.find_windows_constructs(
            path, check.strip_comments(path, path.read_text()), self.root)
        self.assertIn('win32-drive-letter', self.names(findings))

    def test_a_comment_naming_a_windows_path_is_not_a_finding(self):
        path = self.write('source/linux/PathUtil.cpp',
                          '// a path like "C:\\\\Users" keeps its backslashes\n'
                          '/* and so does "D:\\\\Data" */\n')
        findings = check.find_windows_constructs(
            path, check.strip_comments(path, path.read_text()), self.root)
        self.assertEqual(findings, [])

    def test_a_test_fixture_may_hold_a_windows_path(self):
        path = self.write('source/linux/tests/UnitTest.cpp',
                          'const char * p = "C:\\\\Users";\n')
        findings = check.find_windows_constructs(
            path, check.strip_comments(path, path.read_text()), self.root)
        self.assertEqual(findings, [])

    def test_a_windows_file_in_the_tree_is_found(self):
        self.write('debian/install.bat', '@echo off\n')
        findings = check.check_windows_files(self.root)
        self.assertIn('windows-file', self.names(findings))

    def test_a_removed_artefact_is_found(self):
        self.write('source/linux/liblinscp.h', '/* the Windows C ABI */\n')
        findings = check.check_removed_artefacts(self.root)
        self.assertIn('windows-artefact', self.names(findings))

    def test_an_installer_that_misses_a_file_is_found(self):
        for relative in check.INSTALLERS.values():
            self.write(relative, '\n')
        findings = check.check_installed_files(self.root)
        self.assertIn('install-layout', self.names(findings))
        self.assertEqual(len(findings), len(check.INSTALLED_FILES) * 3)

    def test_an_operation_phrase_ending_in_a_preposition_is_found(self):
        self.write('source/linux/Script.cpp',
                   'Texts::LocalError("expansion of", path, error);\n')
        findings = check.check_error_templates(self.root)
        self.assertIn('error-template', self.names(findings))

    def test_an_operation_phrase_that_fits_is_not_a_finding(self):
        self.write('source/linux/Script.cpp',
                   'Texts::LocalError("expand the file name", path, error);\n')
        self.assertEqual(check.check_error_templates(self.root), [])


if __name__ == '__main__':
    unittest.main()
