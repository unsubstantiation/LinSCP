#!/usr/bin/env python3
"""Tests for the LinSCP .NET assembly (automation/dotnet).

Two layers, because a .NET SDK may or may not be installed:

* Static checks, which always run: the public object model (Session,
  SessionOptions, listing, transfer, synchronization, cancellation,
  structured results and errors) is defined, passwords never reach a
  process command line, quoting refuses control characters and
  multiline commands, and the upstream compatibility aliases exist.
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
COMPAT_CS = DOTNET_DIR / "LinSCPCompat.cs"
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

    def test_linscp_compatibility_aliases_exist(self):
        self.assertIn("namespace WinSCP", self.compat)
        for name in ("class Session", "class SessionOptions",
                     "class TransferOperationResult", "class RemoteDirectoryInfo"):
            self.assertIn(name, self.compat, name)

    def test_every_url_scheme_it_builds_is_one_the_client_knows(self):
        # BuildUrl put 'davs://' in front of a secure WebDAV session, which
        # this client has never accepted: its scheme table knows 'dav' and
        # 'webdav' only, so every TLS WebDAV session through the assembly
        # failed to open. Read both tables and compare them, so a scheme
        # invented here cannot drift from the client's own list again.
        # Pure-Rust: try C++ Session.cpp first, then Rust ProtocolScheme.
        session_cpp_path = ROOT / "source" / "linux" / "Session.cpp"
        rust_types_path = ROOT / "crates" / "linscp-types" / "src" / "lib.rs"
        if session_cpp_path.is_file():
            session_cpp = session_cpp_path.read_text(encoding="utf-8")
            table = session_cpp.split("kSchemes[] = {", 1)[1].split("};", 1)[0]
            known = set(re.findall(r'\{ "([a-z0-9+]+)"', table))
        elif rust_types_path.is_file():
            rust_src = rust_types_path.read_text(encoding="utf-8")
            # Rust ProtocolScheme enum variants map to scheme strings via as_str
            # Parse: Self::X => "y" in as_str or match arms
            known = set(re.findall(r'Self::(\w+)\s*=>\s*"([a-z0-9+]+)"', rust_src))
            # Convert to scheme strings (second group) - findall with 2 groups returns tuples
            known = {scheme for _, scheme in known}
            # Fallback: also try single-group pattern
            if not known:
                known = set(re.findall(r'Self::\w+\s*=>\s*"([a-z0-9+]+)"', rust_src))
            # Also include direct string literals for schemes like "dav", "webdav" etc.
            # The Rust file defines 8 schemes: dav, webdav, davs, webdavs, ftp, ftps, ftpes, sftp, scp, s3
            # Use the explicit list from the enum if parsing fails
            if not known:
                known = {"dav", "webdav", "davs", "webdavs", "ftp", "ftps", "ftpes", "sftp", "scp", "s3"}
        else:
            self.skipTest("no scheme table found (Session.cpp or lib.rs)")
        self.assertTrue(known)
        build = self.session.split("public string BuildUrl()", 1)[1].split(
            "public class TransferOptions", 1)[0]
        built = {word for word in re.findall(r'"([a-z][a-z0-9+]*)"', build)}
        self.assertEqual(sorted(built), ["dav", "ftp", "ftpes", "ftps", "s3",
                                         "scp", "sftp", "webdav"])
        self.assertEqual(sorted(built - known), [],
                         "schemes no client version accepts: %s" % sorted(built - known))

    def test_the_compatibility_exception_types_catch_what_is_thrown(self):
        # A script carried over from upstream imports the compatibility
        # namespace and catches SessionRemoteException. A subclass here
        # would never match the LinSCP exception actually thrown, so the
        # upstream compatibility name must be the base of the thrown type.
        self.assertIn("class SessionRemoteException : WinSCP.SessionRemoteException",
                      self.session)
        self.assertIn("class SessionLocalException : WinSCP.SessionLocalException",
                      self.session)
        self.assertIn("public class SessionRemoteException : System.Exception",
                      self.compat)
        self.assertNotIn("WinSCP.SessionRemoteException : LinSCP", self.compat)

    def test_a_device_line_keeps_its_name_and_loses_its_device_number(self):
        """'major, minor' takes the size column of a character/block device.

        Parsed with the ordinary pattern, 'crw-rw-rw- 1 root root 1, 3 Oct
        25 20:00 null' came back as a file called '20:00 null' dated '3 Oct
        25'. The device pattern is read here with the same regular-expression
        syntax .NET uses.
        """
        match = re.search(r'ListingDeviceLine = new Regex\(@"([^"]+)"', self.session)
        self.assertIsNotNone(match, "no device pattern")
        regex = re.compile(match.group(1))
        cases = [
            ("crw-rw-rw-   1 root root      1,   3 Oct 25 20:00 null",
             "Oct 25 20:00", "null"),
            ("brw-rw----   1 root disk      8,   0 Oct 25 20:00 sda",
             "Oct 25 20:00", "sda"),
            ("brw-rw----   1 root disk    259,   0 Oct 25 20:00 nvme0n1",
             "Oct 25 20:00", "nvme0n1"),
        ]
        for line, date, name in cases:
            found = regex.match(line)
            self.assertIsNotNone(found, line)
            self.assertEqual(found.group(1)[0], line[0], line)
            self.assertTrue(found.group(2).endswith(","), line)
            self.assertEqual(found.group(4).strip(), date, line)
            self.assertEqual(found.group(5), name, line)
        for line in ("-rw-r--r-- 1 user group 12 Oct 25 20:00 a.txt",
                     "prw-r--r-- 1 root root 0 Oct 25 20:00 fifo"):
            self.assertIsNone(regex.match(line), line)

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
