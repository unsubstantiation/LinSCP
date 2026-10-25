#!/usr/bin/env python3
"""Tests for the PowerShell module (automation/LinSCP.psm1).

Two layers, because the module's host may or may not be installed:

* Static checks, which always run: the exported cmdlets are all defined,
  no password reaches a process command line, quoting refuses control
  characters and multiline commands are refused.
* The live Pester suite (automation/LinSCP.Tests.ps1) against the
  throwaway WebDAV endpoint, when `pwsh` is installed. Without it the
  live cases skip loudly instead of passing quietly.

Evidence convention (same as every other suite):

    evidence: suite=powershell platform=linux ran=N skipped=N failed=N
"""

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
MODULE = HERE / "LinSCP.psm1"
PESTER = HERE / "LinSCP.Tests.ps1"
PESTER_RUNNER = HERE / "Invoke-LinSCPPester.ps1"
DAV_SERVER = ROOT / "source" / "linux" / "tests" / "TestDavServer.py"
BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve()) \
    if len(sys.argv) > 1 else shutil.which("linscp")

USER = "testuser"
PASSWORD = "testpass"


class StaticModuleTests(unittest.TestCase):
    """What can be checked without a PowerShell host."""

    @classmethod
    def setUpClass(cls):
        cls.text = MODULE.read_text(encoding="utf-8")

    def test_every_exported_cmdlet_is_defined(self):
        """Export-ModuleMember must name functions the file contains."""
        exported = re.search(
            r"Export-ModuleMember -Function @\((.*?)\)",
            self.text, re.S)
        self.assertIsNotNone(exported, "no Export-ModuleMember block")
        names = re.findall(r'"([^"]+)"', exported.group(1))
        self.assertTrue(names, "no exported function names")
        for name in names:
            self.assertRegex(
                self.text, r"(?m)^function %s \{" % re.escape(name),
                "exported but not defined: %s" % name)

    def test_no_password_reaches_a_process_command_line(self):
        """Passwords travel on stdin to -server, never in Arguments."""
        # The only '-password=' the module builds is the 'open' command
        # sent over stdin (Open-LScpSession); ProcessStartInfo argument
        # lists must never carry one.
        for match in re.finditer(r"-password=", self.text):
            before = self.text[max(0, match.start() - 400):match.start()]
            self.assertIn("$openCmd", before,
                          "a -password= outside the stdin open command")
        self.assertIn("never to its command line", self.text)

    def test_quoting_refuses_control_characters(self):
        """A newline in a value would be a second server command."""
        self.assertIn('[\\x00-\\x1F\\x7F]', self.text)
        self.assertIn("ConvertTo-LScpArgument", self.text)

    def test_multiline_commands_are_refused(self):
        self.assertIn('A LinSCP command must be a single line.', self.text)

    def test_server_answers_are_read_to_the_marker(self):
        """Every command is answered up to LSCP-RESULT, never a fixed count."""
        self.assertIn("LSCP-RESULT", self.text)
        self.assertIn("LSCP-SERVER", self.text)

    def test_listing_parser_skips_status_lines(self):
        self.assertIn("Reading directory", self.text)

    def function_body(self, name):
        """The text of one function, without the next one."""
        start = self.text.index("function %s {" % name)
        following = self.text.find("\nfunction ", start + 1)
        return self.text[start:following if following != -1 else len(self.text)]

    def test_listing_fields_are_read_before_the_mode_check(self):
        """$Matches has to be read before another -match replaces it.

        A -match/-notmatch that succeeds replaces $Matches with its own
        result. The listing line's fields were read after the mode check,
        which is such a match, so the owner, the size and the name of every
        entry came back empty and the parser returned objects without a name.
        """
        body = self.function_body("ConvertFrom-LScpListing")
        check = body.find("-notmatch $Script:ListingMode")
        self.assertGreater(check, 0, "the mode check is gone")
        self.assertNotIn("$Matches", body[check:],
                         "a listing field is read after $Matches was replaced")

    def test_a_result_code_is_read_before_anything_else_runs(self):
        """The code of 'LSCP-RESULT n' is read from its own match."""
        body = self.function_body("Read-LScpResponse")
        match = body.find("-match '^LSCP-RESULT")
        self.assertGreater(match, 0, "the result marker is not read here")
        after = body[match:]
        self.assertIn("$code = [int]$Matches[1]", after,
                      "the result code has to be taken from the marker line")
        self.assertNotIn("[int]$Matches[1]", body[body.find("$code = [int]$Matches[1]")
                                                 + len("$code = [int]$Matches[1]"):],
                         "the result code is read again after other commands")

    def test_closing_a_session_leaves_its_process_readable(self):
        """A caller checks HasExited, which a disposed Process cannot answer."""
        body = self.function_body("Stop-LScpProcess")
        self.assertNotIn("$Session.Process)", body,
                         "the Process object must not be disposed")
        self.assertNotIn("$Session.Process.Dispose", body)


class LivePesterTests(unittest.TestCase):
    """The Pester suite, when pwsh exists."""

    @classmethod
    def setUpClass(cls):
        cls.pwsh = shutil.which("pwsh")
        if cls.pwsh is None:
            raise unittest.SkipTest(
                "pwsh is not installed; the live PowerShell tests are "
                "skipped. Install PowerShell 7 to run them.")
        if not BINARY or not pathlib.Path(BINARY).is_file():
            raise unittest.SkipTest(
                "no linscp binary was given; run as "
                "test_psmodule.py <path-to-linscp>.")
        cls.workdir = tempfile.TemporaryDirectory(prefix="live-pwsh-")
        cls.root = pathlib.Path(cls.workdir.name) / "local"
        cls.root.mkdir()
        cls.addClassCleanup(cls.workdir.cleanup)
        cls.server = subprocess.Popen(
            [sys.executable, str(DAV_SERVER)],
            env=dict(os.environ, LSCP_TEST_PORT="0"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True)
        cls.port = None
        timer = threading.Timer(30.0, cls.server.kill)
        timer.start()
        try:
            for line in cls.server.stdout:
                if line.strip().startswith("READY "):
                    cls.port = int(line.strip().split()[1])
                    break
            if cls.port is None:
                raise unittest.SkipTest("the WebDAV test server did not start")
        finally:
            timer.cancel()
        cls.addClassCleanup(cls.stop_server)

    @classmethod
    def stop_server(cls):
        if getattr(cls, "server", None) is None:
            return
        cls.server.terminate()
        try:
            cls.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.server.wait(timeout=5)
        cls.server = None

    def test_pester_suite_passes(self):
        results = pathlib.Path(self.workdir.name) / "pester.xml"
        env = dict(os.environ,
                   LSCP_TEST_BINARY=BINARY,
                   LSCP_TEST_URL_BASE="dav://%s@127.0.0.1:%d/" % (USER, self.port),
                   LSCP_TEST_USER=USER,
                   LSCP_TEST_PASSWORD=PASSWORD,
                   LSCP_TEST_ROOT=str(self.root))
        proc = subprocess.run(
            [self.pwsh, "-NoProfile", "-NonInteractive",
             "-File", str(PESTER_RUNNER),
             "-TestPath", str(PESTER), "-ResultsPath", str(results)],
            capture_output=True, text=True, timeout=300, env=env)
        self.assertEqual(proc.returncode, 0,
                         "pwsh failed:\n%s\n%s" % (proc.stdout, proc.stderr))
        tree = ET.parse(str(results))
        suite = tree.getroot()
        total = int(suite.get("total", "0"))
        failures = int(suite.get("failures", "0"))
        errors = int(suite.get("errors", "0"))
        skipped = int(suite.get("skipped", suite.get("not-run", "0")))
        self.assertGreater(total, 0, "Pester ran no tests")
        # No case in LinSCP.Tests.ps1 is skippable: a skip here would
        # mean the suite did less than the evidence line below claims.
        ignored = [case.get("name") for case in suite.iter("test-case")
                   if case.get("result") in ("Ignored", "Skipped", "Pending")]
        self.assertEqual(skipped, 0, "Pester skipped tests: %s" % ignored)
        self.assertEqual(ignored, [], "Pester ignored tests")
        failed_names = [
            "%s :: %s" % (case.get("classname"), case.get("name"))
            for case in suite.iter("test-case")
            if case.get("result") in ("Failure", "Error")]
        self.assertEqual(failures + errors, 0,
                         "Pester failures:\n" + "\n".join(failed_names))
        print("pester: total=%d skipped=%d" % (total, skipped))


def main():
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(StaticModuleTests))
    suite.addTests(loader.loadTestsFromTestCase(LivePesterTests))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=powershell platform=linux ran=%d skipped=%d failed=%d"
          % (result.testsRun, len(result.skipped), failed))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
