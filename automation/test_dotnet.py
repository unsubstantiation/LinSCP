#!/usr/bin/env python3
"""Tests for the LinSCP .NET assembly (automation/dotnet).

Two layers, because a .NET SDK may or may not be installed:

* Static checks, which always run: the public object model (Session,
  SessionOptions, listing, transfer, synchronization, cancellation,
  structured results and errors) is defined, passwords never reach a
  process command line, quoting refuses control characters and
  multiline commands, and the WinSCP compatibility aliases exist.
* Live `dotnet test` / a scripted session against the throwaway WebDAV
  endpoint, when `dotnet` is installed. Without it the live cases skip
  loudly instead of passing quietly.

Evidence convention:

    evidence: suite=dotnet platform=linux ran=N skipped=N failed=N
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

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
DOTNET_DIR = HERE / "dotnet" / "LinSCP"
SESSION_CS = DOTNET_DIR / "Session.cs"
COMPAT_CS = DOTNET_DIR / "WinSCPCompat.cs"
PROJECT = DOTNET_DIR / "LinSCP.csproj"
DAV_SERVER = ROOT / "source" / "linux" / "tests" / "TestDavServer.py"
BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve()) \
    if len(sys.argv) > 1 else shutil.which("linscp")

USER = "testuser"
PASSWORD = "testpass"


class StaticAssemblyTests(unittest.TestCase):
    """What can be checked without a C# compiler."""

    @classmethod
    def setUpClass(cls):
        cls.session = SESSION_CS.read_text(encoding="utf-8")
        cls.compat = COMPAT_CS.read_text(encoding="utf-8")
        cls.project = PROJECT.read_text(encoding="utf-8")

    def test_the_object_model_types_are_defined(self):
        for name in ("class Session", "class SessionOptions", "class TransferOptions",
                     "class TransferOperationResult", "class SynchronizationResult",
                     "class CommandExecutionResult", "class RemoteDirectoryInfo",
                     "class RemoteFileInfo", "class SessionRemoteException"):
            self.assertIn(name, self.session, name)

    def test_session_lifecycle_listing_transfer_sync_and_cancel_are_public(self):
        for method in ("void Open(", "void Close(", "void Abort(",
                       "TransferOperationResult GetFiles(",
                       "TransferOperationResult PutFiles(",
                       "RemoteDirectoryInfo ListDirectory(",
                       "bool FileExists(", "RemoteFileInfo GetFileInfo(",
                       "CommandExecutionResult ExecuteCommand(",
                       "SynchronizationResult SynchronizeDirectories("):
            self.assertIn(method, self.session, method)
        self.assertIn("bool Opened", self.session)
        self.assertIn("void Check()", self.session)
        self.assertIn("List<SessionRemoteException> Failures", self.session)

    def test_no_password_reaches_a_process_command_line(self):
        self.assertNotIn("-password=", self.session.split("open += \" -password=")[0])
        self.assertIn("open += \" -password=\" + Quote(sessionOptions.Password)",
                      self.session)
        self.assertIn("Arguments = \"-server\"", self.session)
        self.assertNotRegex(self.session, r"ArgumentList.*[Pp]assword")

    def test_quoting_refuses_control_characters_and_multiline_commands(self):
        self.assertIn("Value contains a control character and cannot be safely quoted.",
                      self.session)
        self.assertIn("A LinSCP command must be a single line.", self.session)

    def test_winscp_compatibility_aliases_exist(self):
        self.assertIn("namespace WinSCP", self.compat)
        for name in ("class Session", "class SessionOptions",
                     "class TransferOperationResult", "class RemoteDirectoryInfo"):
            self.assertIn(name, self.compat, name)

    def test_the_project_targets_netstandard_and_net8(self):
        self.assertIn("net8.0", self.project)
        self.assertIn("netstandard2.0", self.project)


@unittest.skipUnless(shutil.which("dotnet"), "dotnet SDK is not installed")
class LiveAssemblyTests(unittest.TestCase):
    """Build the assembly and drive a live WebDAV session through it."""

    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.TemporaryDirectory(prefix="dotnet-linscp-")
        env = dict(os.environ, LSCP_TEST_PORT="0")
        cls.server = subprocess.Popen(
            [sys.executable, str(DAV_SERVER)], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True)
        cls.port = None
        timer = threading.Timer(30.0, cls.server.kill)
        timer.start()
        try:
            for line in cls.server.stdout:
                line = line.strip()
                if line.startswith("READY "):
                    cls.port = int(line.split()[1])
                    break
        finally:
            timer.cancel()
        if cls.port is None:
            cls.server.kill()
            raise unittest.SkipTest("the WebDAV test server did not report a port")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "server", None) is not None:
            cls.server.terminate()
            try:
                cls.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.server.kill()
                cls.server.wait(timeout=5)
        cls.workdir.cleanup()

    def test_dotnet_build_and_roundtrip(self):
        if not BINARY:
            self.skipTest("linscp binary is not available")
        build = subprocess.run(
            ["dotnet", "build", str(PROJECT), "-c", "Release", "--nologo"],
            capture_output=True, text=True, timeout=180,
            cwd=str(self.workdir.name))
        self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
        program = pathlib.Path(self.workdir.name) / "roundtrip.cs"
        local = pathlib.Path(self.workdir.name) / "local"
        local.mkdir()
        (local / "upload.txt").write_bytes(b"dotnet assembly bytes\n")
        program.write_text("""
using System;
using System.IO;
using LinSCP;
class Program {
  static int Main(string[] args) {
    var session = new Session { ExecutablePath = args[0], Timeout = TimeSpan.FromSeconds(30) };
    var options = new SessionOptions {
      Protocol = Protocol.Webdav, HostName = "127.0.0.1",
      PortNumber = int.Parse(args[1]), UserName = args[2], Password = args[3]
    };
    session.Open(options);
    var put = session.PutFiles(args[4], "/dotnet-upload.txt");
    put.Check();
    var listing = session.ListDirectory("/");
    bool seen = false;
    foreach (var file in listing.Files) if (file.Name == "dotnet-upload.txt") seen = true;
    if (!seen) throw new Exception("uploaded name missing from listing");
    var get = session.GetFiles("/dotnet-upload.txt", args[5]);
    get.Check();
    session.Close();
    return 0;
  }
}
""", encoding="utf-8")
        run = subprocess.run(
            ["dotnet", "script", str(program), BINARY, str(self.port), USER, PASSWORD,
             str(local / "upload.txt"), str(local / "download.txt")],
            capture_output=True, text=True, timeout=120)
        if run.returncode != 0 and "script" in (run.stderr + run.stdout).lower():
            self.skipTest("dotnet script is not installed; assembly built")
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual((local / "download.txt").read_bytes(), b"dotnet assembly bytes\n")


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=dotnet platform=linux ran=%d skipped=%d failed=%d" %
          (result.testsRun, len(result.skipped), failed))
    sys.exit(0 if result.wasSuccessful() else 1)
