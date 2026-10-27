"""Live tests against the throwaway WebDAV endpoint in this directory.

TestSftpServer.py covers SFTP, TestS3Server.py covers signed HTTP, and
WebDAV is a third dialect again: PROPFIND listings, MKCOL, MOVE, the
Depth header and 401 challenges rather than signatures. This suite
starts TestDavServer.py (plain HTTP on a kernel-picked port, Basic
credentials testuser/testpass) and drives the console client through
what a DAV filesystem has to answer:

  - a wrong password refused by the challenge, before any command runs;
  - listings built from PROPFIND properties (type, size, date), which
    is what a server that refuses GET on collections can only answer;
  - stat with the real size and time, and a missing path that says so;
  - mkdir refusing an existing name, rmdir refusing a non-empty
    directory, remove of a missing file failing;
  - rename through MOVE leaving exactly the destination behind;
  - `cp` through server-side COPY, with the source retained and the copied
    bytes checked independently (the mock records which HTTP method ran);
  - `cp` falling back to a streamed download/upload when the mock refuses
    COPY with 405, again checked byte-for-byte;
  - an upload/download roundtrip with a checksum, including escaped names
    containing spaces, %, ? and # across PUT/GET/PROPFIND/MOVE/COPY;
  - mkdir -parents creating nested remote paths and refusing a file as parent;
  - keepuptodate uploading local changes and waking on a nested file event;
  - ETag preconditions: '-get' reading the server's tag, a matching
    '-match=' writing, a stale one refused with 412 and the destination
    left untouched, '-nomatch=' writing only where the version differs, a
    lock and a tag travelling in one condition list, and what a
    precondition recorded on a collection guards.

The client uses curl over plain HTTP and the server is the standard
library, so the suite needs nothing beyond Python and curl.

Evidence convention (same as every other suite):

    evidence: suite=live-dav platform=linux ran=N skipped=N failed=N
"""

import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request

BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())
SUITE_NAME = "live-dav"
HERE = pathlib.Path(__file__).resolve().parent

USER = "testuser"
PASSWORD = "testpass"


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class LiveDavTests(unittest.TestCase):
    """A fresh server (and therefore a fresh store) per test."""

    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.TemporaryDirectory(prefix="live-dav-")
        cls.root = pathlib.Path(cls.workdir.name) / "local"
        cls.root.mkdir()
        cls.config = pathlib.Path(cls.workdir.name) / "config"
        cls.config.mkdir()
        cls.addClassCleanup(cls.workdir.cleanup)

    def setUp(self):
        self.proxies = []
        self.start_server()

    def tearDown(self):
        self.stop_server()
        while self.proxies:
            self.stop_proxy(*self.proxies.pop())

    # -- the server ---------------------------------------------------------
    def start_server(self):
        env = dict(os.environ, LSCP_TEST_PORT="0")
        # Its own process group, so that teardown can stop the server and
        # anything it left behind without touching the test runner.
        popen_args = dict(env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True,
                          start_new_session=True)
        self.server = subprocess.Popen(
            [sys.executable, str(HERE / "TestDavServer.py")], **popen_args)
        self.port = None
        timer = threading.Timer(30.0, self.server.kill)
        timer.start()
        try:
            for line in self.server.stdout:
                line = line.strip()
                if line.startswith("READY "):
                    self.port = int(line.split()[1])
                    break
            if self.port is None:
                self.fail("the WebDAV test server did not report a port")
        finally:
            timer.cancel()

    def stop_server(self):
        if getattr(self, "server", None) is None:
            return
        self.server.terminate()
        try:
            self.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.server.kill()
            self.server.wait(timeout=5)
        self.server = None

    # -- the proxy ----------------------------------------------------------
    def start_proxy(self, kind="socks5", credentials=""):
        """Start TestProxyServer.py and collect the requests it reports.

        This suite is the one that also runs where the native transport does
        not, so it is where the proxy support of the curl paths is proved:
        a listing that arrives is not evidence on its own, the proxy has to
        have seen the connection.
        """
        env = dict(os.environ, LSCP_TEST_PORT="0", LSCP_TEST_PROXY_KIND=kind,
                   LSCP_TEST_PROXY_AUTH=credentials)
        popen_args = dict(env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True,
                          start_new_session=True)
        proxy = subprocess.Popen(
            [sys.executable, str(HERE / "TestProxyServer.py")], **popen_args)
        lines = []
        port = []
        ready = threading.Event()

        def collect():
            for line in proxy.stdout:
                line = line.strip()
                if not line:
                    continue
                lines.append(line)
                if line.startswith("READY ") and not port:
                    port.append(int(line.split()[1]))
                    ready.set()

        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        if not ready.wait(30.0):
            self.stop_proxy(proxy, reader)
            self.fail("the test proxy did not start")
        self.proxies.append((proxy, reader))
        return port[0], lines

    def stop_proxy(self, proxy, reader):
        if proxy.poll() is None:
            try:
                os.killpg(os.getpgid(proxy.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                proxy.terminate()
            try:
                proxy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=10)
        if proxy.stdout is not None:
            proxy.stdout.close()
        reader.join(timeout=5)

    # -- driving the client -------------------------------------------------
    def run_script(self, commands, creds=None, timeout=60, open_args=()):
        user, secret = creds if creds else (USER, PASSWORD)
        argv = [BINARY, "-batch", "-hostkey=*",
                "-log=" + str(self.config / "session.log"),
                "-command=open dav://%s:%s@127.0.0.1:%d/ %s ; %s" %
                (user, secret, self.port, " ".join(open_args), commands)]
        env = dict(os.environ, LINSCP_CONFIG_DIR=str(self.config))
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, env=env)

    def start_script(self, commands, creds=None, open_args=()):
        user, secret = creds if creds else (USER, PASSWORD)
        argv = [BINARY, "-batch", "-hostkey=*",
                "-log=" + str(self.config / "session.log"),
                "-command=open dav://%s:%s@127.0.0.1:%d/ %s ; %s" %
                (user, secret, self.port, " ".join(open_args), commands)]
        env = dict(os.environ, LINSCP_CONFIG_DIR=str(self.config))
        return subprocess.Popen(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env)

    def server_state(self):
        url = "http://127.0.0.1:%d/__test__/state" % self.port
        with urllib.request.urlopen(url, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))

    def reject_next_server_copy(self):
        url = "http://127.0.0.1:%d/__test__/reject-next-copy" % self.port
        with urllib.request.urlopen(url, timeout=10) as response:
            self.assertEqual(response.status, 204)

    # -- tests --------------------------------------------------------------
    def test_wrong_password_is_refused_by_the_challenge(self):
        """--anyauth lets the server challenge, and the second attempt
        with the wrong password still comes back 401 - so 'open' stops
        there instead of running commands against a server that will
        never accept them."""
        result = self.run_script("echo SHOULD_NOT_RUN",
                                 creds=(USER, "not-the-password"))
        self.assertEqual(result.returncode, 1,
                         result.stdout + result.stderr)
        self.assertIn("401 Unauthorized", result.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

    def test_listing_comes_from_propfind_properties(self):
        """mkdir, put and then two levels of listing: the directory as
        a directory, the object with its byte count and date."""
        source = self.root / "hello.txt"
        # Bytes, not write_text: the size this test asserts on is the size
        # of exactly these bytes.
        source.write_bytes(b"hello dav world\n")
        result = self.run_script(
            "mkdir /docs ; mkdir /docs/2026 ; "
            "put %s /docs/hello.txt ; "
            "ls ; ls -l /docs ; echo LIST_OK" % source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("LIST_OK", result.stdout)
        root_part = result.stdout.split("Reading directory /...")[1]
        self.assertRegex(root_part, r"drwx[-rwx]+\s+\S+\s+\S+\s+\S+\s+\d+\s+"
                                    r"\S+\s+\S+\s+\S+\s+docs")
        bucket_part = result.stdout.split("Reading directory /docs...")[1]
        self.assertIn("hello.txt", bucket_part)
        self.assertRegex(bucket_part, r"\s16\s.*hello\.txt")
        self.assertIn("2026", bucket_part)

        # A second session still sees it: the store is the server's.
        result = self.run_script("ls -l /docs ; echo STILL_THERE")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("hello.txt", result.stdout)

    def test_mkdir_parents_is_retryable_and_stops_on_a_file(self):
        """The desktop queue creates parents for every upload and retries
        independently, including folders with spaces and % in their names."""
        source = self.root / "drop-payload.bin"
        source.write_bytes(b"exact dropped bytes\x00")
        target = "/dropped/empty folder/%TIMESTAMP%/nested"
        # Use -literal, as the GUI does, so the percent signs in names
        # stay literal rather than expanding into the current time.
        argv = [BINARY, "-batch", "-hostkey=*", "-literal",
                "-command=open dav://%s:%s@127.0.0.1:%d/ ; "
                "mkdir -parents \"%s\" ; mkdir -parents \"%s\" ; "
                "put %s \"%s/payload.bin\" ; echo DROPPED" %
                (USER, PASSWORD, self.port, target, target, source, target)]
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=30, env=dict(os.environ,
                                                     LINSCP_CONFIG_DIR=str(self.config)))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("DROPPED", result.stdout)
        received = self.root / "received-drop.bin"
        # The regular script runner expands %TIMESTAMP%; use the literal
        # argv for the readback too.
        verify = subprocess.run([
            BINARY, "-batch", "-hostkey=*", "-literal",
            "-command=open dav://%s:%s@127.0.0.1:%d/ ; get \"%s/payload.bin\" %s" %
            (USER, PASSWORD, self.port, target, received)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertEqual(received.read_bytes(), source.read_bytes())

        # URL escaping also applies to the WebDAV Destination header on COPY
        # and MOVE, and to PROPFIND href comparisons. '#' and '?' are file
        # name bytes here, not URL fragment/query delimiters; '%25' is a
        # literal percent followed by two digits, not a double-decoded '%'.
        odd = target + "/report #1? 100%25.txt"
        copied = target + "/copy #1? 100%25.txt"
        moved = target + "/moved #1? 100%25.txt"
        result = subprocess.run([
            BINARY, "-batch", "-hostkey=*", "-literal",
            "-command=open dav://%s:%s@127.0.0.1:%d/ ; "
            "put %s \"%s\" ; cp \"%s\" \"%s\" ; "
            "mv \"%s\" \"%s\" ; stat \"%s\" ; echo SPECIAL_OK" %
            (USER, PASSWORD, self.port, source, odd, odd, copied,
             copied, moved, moved)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SPECIAL_OK", result.stdout)
        self.assertIn("Copied '", result.stdout)
        self.assertIn("moved #1? 100%25.txt", result.stdout)
        received2 = self.root / "received-special.bin"
        readback = subprocess.run([
            BINARY, "-batch", "-hostkey=*", "-literal",
            "-command=open dav://%s:%s@127.0.0.1:%d/ ; get \"%s\" %s" %
            (USER, PASSWORD, self.port, moved, received2)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(readback.returncode, 0,
                         readback.stdout + readback.stderr)
        self.assertEqual(received2.read_bytes(), source.read_bytes())

        # It is not permitted to turn an existing file into a directory;
        # batch abort prevents the command after the error from running.
        denied = subprocess.run([
            BINARY, "-batch", "-hostkey=*", "-literal",
            "-command=open dav://%s:%s@127.0.0.1:%d/ ; "
            "mkdir -parents \"%s/payload.bin/child\" ; echo SHOULD_NOT_RUN" %
            (USER, PASSWORD, self.port, target)],
            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(denied.returncode, 0)
        self.assertIn("not a directory", denied.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", denied.stdout)

    def test_stat_reports_size_and_time_and_missing_paths(self):
        source = self.root / "sized.bin"
        source.write_bytes(b"x" * 4321)
        self.assertEqual(self.run_script(
            "mkdir /docs ; put %s /docs/sized.bin" % source).returncode, 0)

        result = self.run_script("stat /docs/sized.bin ; echo STAT_OK")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # One listing line like upstream's, carrying the size in its
        # column; the key/value breakdown is what 'attr' prints now.
        stat_lines = [line for line in result.stdout.splitlines()
                      if line.rstrip().endswith("sized.bin")]
        self.assertEqual(len(stat_lines), 1, result.stdout)
        self.assertIn("4321", stat_lines[0])
        self.assertNotIn("SizeBytes:", result.stdout)
        self.assertIn("STAT_OK", result.stdout)
        result = self.run_script("attr /docs/sized.bin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SizeBytes:   4321", result.stdout)

        result = self.run_script("stat /docs/no-such-file ; echo NOPE")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("No such file or directory", result.stderr)
        self.assertNotIn("NOPE", result.stdout)

    def test_upload_and_download_roundtrip(self):
        source = self.root / "roundtrip.bin"
        source.write_bytes(bytes(range(256)) * 32)
        downloaded = self.root / "roundtrip-downloaded.bin"
        result = self.run_script(
            "mkdir /docs ; put %s /docs/roundtrip.bin ; "
            "get /docs/roundtrip.bin %s ; echo ROUNDTRIP_OK" %
            (source, downloaded))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ROUNDTRIP_OK", result.stdout)
        self.assertEqual(sha256_of(source), sha256_of(downloaded))

    def test_keepuptodate_reflects_local_files_on_the_remote_side(self):
        """`keepuptodate` watches the local side and reflects its files
        onto the remote directory; one bounded pass must therefore upload."""
        local_dir = self.root / "keepuptodate-once"
        local_dir.mkdir()
        payload = b"local changes go to the remote side\n"
        source = local_dir / "payload.txt"
        source.write_bytes(payload)
        downloaded = self.root / "keepuptodate-once-downloaded.txt"
        result = self.run_script(
            "mkdir /keepuptodate-once ; "
            "keepuptodate -count=1 %s /keepuptodate-once ; "
            "get /keepuptodate-once/payload.txt %s" %
            (local_dir, downloaded))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(downloaded.read_bytes(), payload)

    def test_keepuptodate_wakes_on_a_local_change(self):
        """A completed file arrival wakes the native watcher immediately
        instead of waiting for its 30-second safety-rescan interval."""
        local_dir = self.root / "keepuptodate-watch"
        local_dir.mkdir()
        nested = local_dir / "nested"
        nested.mkdir()
        pending_file = self.root / "keepuptodate-pending.bin"
        pending_file.write_bytes(b"the native directory event woke the next pass\n")
        self.assertEqual(self.run_script(
            "mkdir /keepuptodate-watch ; mkdir /keepuptodate-watch/nested"
        ).returncode, 0)

        process = self.start_script(
            "keepuptodate -interval=30 -count=2 %s /keepuptodate-watch" %
            local_dir)
        stdout_lines = []
        stderr_lines = []
        first_pass = threading.Event()

        def read_output(stream, lines, watch_first_pass=False):
            for line in stream:
                lines.append(line)
                if watch_first_pass and "Pass 1:" in line:
                    first_pass.set()

        readers = [
            threading.Thread(target=read_output,
                             args=(process.stdout, stdout_lines, True),
                             daemon=True),
            threading.Thread(target=read_output,
                             args=(process.stderr, stderr_lines),
                             daemon=True),
        ]
        for reader in readers:
            reader.start()
        try:
            self.assertTrue(first_pass.wait(timeout=15),
                            "initial pass did not finish; stdout=%r stderr=%r" %
                            (stdout_lines, stderr_lines))
            os.replace(pending_file, nested / "arrived-after-start.txt")
            returncode = process.wait(timeout=12)
        except Exception:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            raise
        finally:
            for reader in readers:
                reader.join(timeout=3)

        self.assertEqual(returncode, 0,
                         "stdout=%r stderr=%r" % (stdout_lines, stderr_lines))
        downloaded = self.root / "keepuptodate-watch-downloaded.txt"
        result = self.run_script(
            "get /keepuptodate-watch/nested/arrived-after-start.txt %s" %
            downloaded)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(downloaded.read_bytes(),
                         b"the native directory event woke the next pass\n")

    def test_transfer_preset_drives_ascii_and_loads_with_the_site(self):
        """Transfer presets against a real server: the active preset
        converts a text upload exactly like -transfer=ascii would, and a
        site that stores the preset loads it when it is opened."""
        source = self.root / "preset-lf.txt"
        source.write_bytes(b"a\nb\n")
        out_active = self.root / "preset-active.txt"
        out_off = self.root / "preset-off.txt"
        out_site = self.root / "preset-site.txt"

        # An active preset supplies the settings; 'option preset off'
        # hands the transfer back to its own (binary) defaults.
        result = self.run_script(
            "mkdir /docs ; "
            "savepreset presetascii -transfer=ascii -host=127.0.0.1 ; "
            "presets ; option preset presetascii ; "
            "put %s /docs/preset-ascii.txt ; "
            "savepreset presetbinary -transfer=binary -host=127.0.0.1 ; "
            "option preset presetbinary ; "
            "put %s /docs/preset-binary.txt ; "
            "option preset off ; "
            "get /docs/preset-ascii.txt %s ; "
            "get /docs/preset-binary.txt %s ; "
            "echo PRESET_OK" % (source, source, out_active, out_off))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PRESET_OK", result.stdout)
        self.assertIn("presetascii", result.stdout)
        self.assertEqual(out_active.read_bytes(), b"a\r\nb\r\n")
        self.assertEqual(out_off.read_bytes(), b"a\nb\n")

        # The same preset stored with the site: opening the site restores
        # it, and the conversion happens without any switch on 'put'.
        result = self.run_script(
            "savepreset sitepreset -transfer=ascii -host=127.0.0.1 ; "
            "savesession dasite -protocol=dav -host=127.0.0.1 -port=%d "
            "-username=%s -password=%s -preset=sitepreset ; "
            "sessions dasite ; "
            "put %s /docs/site-ascii.txt ; "
            "option preset off ; "
            "get /docs/site-ascii.txt %s ; "
            "echo SITE_OK" % (self.port, USER, PASSWORD, source, out_site))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("SITE_OK", result.stdout)
        self.assertEqual(out_site.read_bytes(), b"a\r\nb\r\n")

        # Removing the preset leaves the file without it, and the test
        # takes its presets and site out of the shared configuration
        # again: a host-matching preset would otherwise (correctly!)
        # apply to every later test that connects to this server.
        result = self.run_script(
            "rmspreset sitepreset ; rmspreset presetascii ; "
            "rmspreset presetbinary ; rmsession dasite ; presets")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Removed transfer preset", result.stdout)
        self.assertNotIn("  sitepreset", result.stdout)
        self.assertNotIn("  presetascii", result.stdout)
        self.assertNotIn("  presetbinary", result.stdout)

    def test_download_permissions_and_raw_transfer_settings(self):
        """Two switch families against the wire: a raw transfer setting
        in upstream's key vocabulary converting an upload, and
        '-permissions=<mode>' giving the downloaded local file that
        mode."""
        source = self.root / "raw-lf.txt"
        source.write_bytes(b"x\ny\n")
        got = self.root / "raw-got.txt"
        protected = self.root / "raw-protected.txt"
        result = self.run_script(
            "mkdir /docs ; "
            "put -rawtransfersettings=1 TransferMode=1 %s /docs/raw.txt ; "
            "get /docs/raw.txt %s ; "
            "get -permissions=444 /docs/raw.txt %s ; "
            "echo RAW_OK" % (source, got, protected))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RAW_OK", result.stdout)
        # TransferMode=1 in the raw settings means ascii: the upload
        # converted LF to CRLF, and the plain binary download shows it.
        self.assertEqual(got.read_bytes(), b"x\r\ny\r\n")
        # The download was told to make the local file read-only.
        self.assertEqual(os.stat(protected).st_mode & 0o200, 0)

    def test_mkdir_refuses_an_existing_name(self):
        result = self.run_script(
            "mkdir /docs ; mkdir /docs ; echo SHOULD_NOT_SEE")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("already exists", result.stderr)
        self.assertNotIn("SHOULD_NOT_SEE", result.stdout)

    def test_rmdir_refuses_a_nonempty_directory(self):
        source = self.root / "keep.txt"
        source.write_text("keep\n", encoding="utf-8")
        result = self.run_script(
            "option confirm off ; "
            "mkdir /docs ; mkdir /docs/full ; "
            "put %s /docs/full/keep.txt ; "
            "rmdir /docs/full ; echo SHOULD_NOT_SEE" % source)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not empty", result.stderr)
        self.assertNotIn("SHOULD_NOT_SEE", result.stdout)

        # Empty it and the same rmdir has to go through - and the
        # directory with it.
        result = self.run_script(
            "option confirm off ; rm /docs/full/keep.txt ; "
            "rmdir /docs/full ; ls /docs ; echo RMDIR_OK")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RMDIR_OK", result.stdout)
        listing = result.stdout.split("Reading directory /docs...")[1]
        self.assertNotIn("full", listing)

    def test_webdav_lock_makes_the_other_writer_wait(self):
        """A lock is only worth taking if the server enforces it.

        The lock stays with the server, so a second session - a writer that
        never took it - is refused with 423 for both an upload and a
        delete, and the remote file keeps its old content. A session that
        holds the token uploads with it (the If header) and releases the
        lock again with 'unlock', after which the unprotected writer goes
        through.
        """
        source = self.root / "dav-lock-source.txt"
        source.write_text("locked content\n", encoding="utf-8")
        rival = self.root / "dav-lock-rival.txt"
        rival.write_text("rival content\n", encoding="utf-8")

        # One session takes the lock and leaves it standing.
        locked = self.run_script(
            "option confirm off ; put %s /locked.txt ; lock /locked.txt "
            "-timeout=600 ; echo LOCKED" % source)
        self.assertEqual(locked.returncode, 0, locked.stdout + locked.stderr)
        token = self.server_state()["locks"]["/locked.txt"]
        self.assertTrue(token.startswith("opaquelocktoken:"))
        self.assertIn("LOCKED", locked.stdout)
        self.assertIn("Locked /locked.txt with token " + token, locked.stdout)

        # A second session holds no token, so the server refuses the write
        # and the file the lock protects is untouched.
        refused = self.run_script(
            "option confirm off ; put %s /locked.txt ; echo SHOULD_NOT_RUN" %
            rival)
        self.assertEqual(refused.returncode, 1, refused.stdout + refused.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", refused.stdout)
        self.assertIn("423", refused.stderr)

        # The same refusal protects the delete: a lock that only stopped
        # uploads would not be a lock.
        remove = self.run_script(
            "option confirm off ; rm /locked.txt ; echo SHOULD_NOT_RUN")
        self.assertEqual(remove.returncode, 1, remove.stdout + remove.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", remove.stdout)
        self.assertIn("423", remove.stderr)

        # One session takes a lock, writes through it and releases it: the
        # token travels as the If header of the upload, and 'unlock' ends
        # the protection.
        changed = self.root / "dav-lock-changed.txt"
        changed.write_text("the owner's new content\n", encoding="utf-8")
        owner = self.run_script(
            "option confirm off ; put %s /owned.txt ; lock /owned.txt ; "
            "put %s /owned.txt ; echo OWNER_OK ; unlock /owned.txt ; "
            "echo UNLOCKED" % (source, changed))
        self.assertEqual(owner.returncode, 0, owner.stdout + owner.stderr)
        self.assertIn("OWNER_OK", owner.stdout)
        self.assertIn("Unlocked /owned.txt.", owner.stdout)
        self.assertIn("UNLOCKED", owner.stdout)
        self.assertNotIn("/owned.txt", self.server_state()["locks"])

        # Nothing holds the lock any more, so the unprotected writer is
        # allowed to replace the file.
        after = self.run_script(
            "option confirm off ; put %s /owned.txt ; echo AFTER_OK" % rival)
        self.assertEqual(after.returncode, 0, after.stdout + after.stderr)
        self.assertIn("AFTER_OK", after.stdout)

        readback = self.root / "dav-lock-readback.txt"
        got = self.run_script("get /owned.txt %s" % readback)
        self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
        self.assertEqual(readback.read_bytes(), rival.read_bytes())

    def test_webdav_dead_property_roundtrip(self):
        """A dead property is stored on the server and read back by the
        named-property PROPFIND, from another session too."""
        source = self.root / "dav-property.txt"
        source.write_text("a file with a property\n", encoding="utf-8")
        written = self.run_script(
            "option confirm off ; put %s /property.txt ; "
            "property /property.txt -set=author=Ada ; "
            "echo STORED" % source)
        self.assertEqual(written.returncode, 0, written.stdout + written.stderr)
        self.assertIn("Set author on /property.txt.", written.stdout)
        self.assertEqual(
            self.server_state()["properties"]["/property.txt"]["author"],
            "Ada")

        read = self.run_script("property /property.txt -get=author")
        self.assertEqual(read.returncode, 0, read.stdout + read.stderr)
        self.assertIn("author=Ada", read.stdout)

        # A property nobody set is an answer, not a failure.
        missing = self.run_script("property /property.txt -get=revision")
        self.assertEqual(missing.returncode, 0,
                         missing.stdout + missing.stderr)
        self.assertIn("revision is not set on /property.txt.", missing.stdout)

        # A property name that would build invalid XML is refused before
        # any request, and the lock/property verbs on a non-WebDAV session
        # say so instead of asking the server.
        invalid = self.run_script("property /property.txt -get=no such name")
        self.assertEqual(invalid.returncode, 1,
                         invalid.stdout + invalid.stderr)

    # -- ETag preconditions -------------------------------------------------
    def etag_of(self, path):
        """The entity tag the server has for a path, quotes and all."""
        return self.server_state()["etags"][path]

    def if_headers(self, command=None, path=None):
        """The If headers the server was asked to honour, in order."""
        return [entry["header"] for entry in self.server_state()["if_headers"]
                if (command is None or entry["command"] == command) and
                (path is None or entry["path"] == path)]

    def test_etag_get_reads_the_version_the_server_has(self):
        """'-get' is what a script records a precondition from, so it has to
        answer with the server's own tag - and a path that is not there has
        to say so rather than print nothing at all."""
        source = self.root / "dav-etag-source.txt"
        source.write_text("the first version\n", encoding="utf-8")
        stored = self.run_script(
            "option confirm off ; put %s /etag.txt ; etag /etag.txt -get" %
            source)
        self.assertEqual(stored.returncode, 0, stored.stdout + stored.stderr)
        etag = self.etag_of("/etag.txt")
        self.assertTrue(etag.startswith('"') and etag.endswith('"'), etag)
        self.assertIn(etag, stored.stdout)

        # Writing moves the tag: a precondition recorded from the old one
        # is what makes the next write conditional at all.
        self.run_script("option confirm off ; put %s /etag.txt" % source)
        second = self.run_script("etag /etag.txt -get")
        self.assertIn(self.etag_of("/etag.txt"), second.stdout)

        missing = self.run_script("etag /no-such-file.txt -get")
        self.assertEqual(missing.returncode, 0,
                         missing.stdout + missing.stderr)
        self.assertIn("No ETag: '/no-such-file.txt' does not exist.",
                      missing.stdout)

    def test_a_matching_etag_writes_and_a_stale_one_is_refused(self):
        """The server has to be the one that decides, and a refused write
        has to leave the destination exactly as it was.

        '-match=' records the version the script read; the upload that
        follows carries it in the If header. A tag the server has moved on
        from is answered with 412, the command fails, and the bytes on the
        server are still the ones that were there before - not a partial
        write and not the content the refused upload offered.
        """
        first = self.root / "dav-cond-first.txt"
        first.write_text("the version the script read\n", encoding="utf-8")
        second = self.root / "dav-cond-second.txt"
        second.write_text("the version the script writes\n", encoding="utf-8")
        rival = self.root / "dav-cond-rival.txt"
        rival.write_text("a write over a version nobody read\n",
                         encoding="utf-8")

        created = self.run_script(
            "option confirm off ; put %s /cond.txt" % first)
        self.assertEqual(created.returncode, 0,
                         created.stdout + created.stderr)
        read = self.etag_of("/cond.txt")

        allowed = self.run_script(
            "option confirm off ; etag /cond.txt -match=%s ; "
            "put %s /cond.txt ; echo WROTE" % (read, second))
        self.assertEqual(allowed.returncode, 0,
                         allowed.stdout + allowed.stderr)
        self.assertIn("WROTE", allowed.stdout)
        self.assertIn("If-Match: %s on /cond.txt." % read, allowed.stdout)
        # The tag went into the header quoted, the way a server compares
        # one, even though the command splitter took the quotes the user
        # pasted for the quoting of the argument.
        self.assertEqual(self.if_headers("PUT", "/cond.txt")[-1],
                         "([%s])" % read)

        back = self.root / "dav-cond-readback.txt"
        self.assertEqual(self.run_script("get /cond.txt %s" % back).returncode,
                         0)
        self.assertEqual(back.read_bytes(), second.read_bytes())

        # The tag of the version that has now been written over is stale.
        refused = self.run_script(
            "option confirm off ; etag /cond.txt -match=%s ; "
            "put %s /cond.txt ; echo SHOULD_NOT_RUN" % (read, rival))
        self.assertEqual(refused.returncode, 1,
                         refused.stdout + refused.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", refused.stdout)
        self.assertIn("412", refused.stderr)
        self.assertEqual(self.if_headers("PUT", "/cond.txt")[-1],
                         "([%s])" % read)

        untouched = self.root / "dav-cond-untouched.txt"
        self.assertEqual(
            self.run_script("get /cond.txt %s" % untouched).returncode, 0)
        self.assertEqual(untouched.read_bytes(), second.read_bytes())

        # A delete is guarded by the same recorded version, and so is a
        # move: a precondition that only stopped uploads would not be one.
        for command, expected in (
                ("rm /cond.txt", "412"),
                # A 412 on a move answers two questions, and the one about
                # the destination is not the one being asked here.
                ("mv /cond.txt /moved.txt", "ETag precondition")):
            with self.subTest(command=command):
                refused = self.run_script(
                    "option confirm off ; etag /cond.txt -match=%s ; %s ; "
                    "echo SHOULD_NOT_RUN" % (read, command))
                self.assertEqual(refused.returncode, 1,
                                 refused.stdout + refused.stderr)
                self.assertNotIn("SHOULD_NOT_RUN", refused.stdout)
                self.assertIn(expected, refused.stderr)
        self.assertEqual(self.etag_of("/cond.txt"),
                         self.server_state()["etags"]["/cond.txt"])
        self.assertNotIn("/moved.txt", self.server_state()["etags"])

        # Clearing the precondition lets the same write through.
        cleared = self.run_script(
            "option confirm off ; etag /cond.txt -clear ; "
            "put %s /cond.txt ; echo CLEARED" % rival)
        self.assertEqual(cleared.returncode, 0,
                         cleared.stdout + cleared.stderr)
        self.assertIn("Cleared ETag precondition on /cond.txt.",
                      cleared.stdout)
        self.assertIn("CLEARED", cleared.stdout)

    def test_if_none_match_writes_only_where_the_version_differs(self):
        """'-nomatch=' is If-None-Match: write only where the server does
        NOT have this version.

        Spelled without the 'Not' the condition asks for the opposite, and
        a script that meant "only if nobody changed it" would have written
        only over a file it had already seen replaced. A path that is not
        there at all has no version to differ from, so the write that
        creates it goes through - which is what makes this the guard a
        script reads a file with before deciding to create it.
        """
        source = self.root / "dav-nomatch-source.txt"
        source.write_text("what the script offers\n", encoding="utf-8")
        rival = self.root / "dav-nomatch-rival.txt"
        rival.write_text("what would overwrite it\n", encoding="utf-8")

        # A tag from a path that does not exist yet: nothing to match, so
        # the condition holds and the file is created. The root's own tag
        # is read once, before the create moves the listing it names.
        absent = self.etag_of("/")
        created = self.run_script(
            "option confirm off ; etag /fresh.txt -nomatch=%s ; "
            "put %s /fresh.txt ; echo CREATED" % (absent, source))
        self.assertEqual(created.returncode, 0,
                         created.stdout + created.stderr)
        self.assertIn("CREATED", created.stdout)
        self.assertIn("If-None-Match: %s on /fresh.txt." % absent,
                      created.stdout)
        self.assertEqual(self.if_headers("PUT", "/fresh.txt")[-1],
                         "(Not [%s])" % absent)

        # The same tag now names a version the server does not have - the
        # file it just created has its own - so the write still goes
        # through, and one that names the version it does have is refused.
        # The tag for the refusal is read after the allowed write: every
        # write moves the version, so the tag from before it is stale by
        # the time the refused write runs.
        stale = absent
        allowed = self.run_script(
            "option confirm off ; etag /fresh.txt -nomatch=%s ; "
            "put %s /fresh.txt ; echo DIFFERENT_OK" % (stale, source))
        self.assertEqual(allowed.returncode, 0,
                         allowed.stdout + allowed.stderr)
        self.assertIn("DIFFERENT_OK", allowed.stdout)
        # The allowed write has now created a newer version; capture that
        # current tag after the write, not before it, so this test remains
        # correct even when the server's one-second timestamp crosses a
        # boundary during the upload.
        current = self.etag_of("/fresh.txt")
        before_refused_state = self.server_state()
        self.assertEqual(before_refused_state["etags"]["/fresh.txt"], current,
                         json.dumps(before_refused_state, sort_keys=True))
        refused = self.run_script(
            "option confirm off ; etag /fresh.txt -nomatch=%s ; "
            "put %s /fresh.txt ; echo SHOULD_NOT_RUN" % (current, rival))
        refused_state = self.server_state()
        self.assertEqual(refused.returncode, 1,
                         refused.stdout + refused.stderr +
                         "\nServer state: " + json.dumps(refused_state,
                                                         sort_keys=True))
        self.assertNotIn("SHOULD_NOT_RUN", refused.stdout)
        self.assertIn("412", refused.stderr)
        self.assertEqual(self.if_headers("PUT", "/fresh.txt")[-1],
                         "(Not [%s])" % current)

        untouched = self.root / "dav-nomatch-readback.txt"
        self.assertEqual(
            self.run_script("get /fresh.txt %s" % untouched).returncode, 0)
        self.assertEqual(untouched.read_bytes(), source.read_bytes())

    def test_an_asterisk_is_refused_rather_than_sent_as_a_precondition(self):
        """'*' is the "only if absent" of a bare If-None-Match header, and
        the If header a condition travels in has no room for it: a quoted
        asterisk is a tag no resource carries, so the condition would hold
        on every write and guard nothing while looking like a guard."""
        for switch in ("-nomatch=*", "-match=*"):
            with self.subTest(switch=switch):
                refused = self.run_script(
                    "etag /whatever.txt %s ; echo SHOULD_NOT_RUN" % switch)
                self.assertEqual(refused.returncode, 1,
                                 refused.stdout + refused.stderr)
                self.assertIn("is not an entity tag", refused.stderr)
                self.assertNotIn("SHOULD_NOT_RUN", refused.stdout)
        self.assertEqual(self.if_headers(), [])

    def test_a_lock_and_an_etag_travel_in_one_condition_list(self):
        """A path that is both locked and has a version recorded states both
        in one If header.

        RFC 4918 reads an If header as either no-tag lists or tagged lists
        and never as both, and every condition of one list has to hold. A
        header that put the token in one list and the tag in another was
        one no server is asked to parse, and a token sent without the angle
        brackets of a Coded-URL was one a standard server did not find.
        """
        source = self.root / "dav-both-source.txt"
        source.write_text("the version under the lock\n", encoding="utf-8")
        changed = self.root / "dav-both-changed.txt"
        changed.write_text("the owner's new version\n", encoding="utf-8")
        rival = self.root / "dav-both-rival.txt"
        rival.write_text("a writer with no lock and no version\n",
                         encoding="utf-8")

        written = self.run_script(
            "option confirm off ; put %s /both.txt ; echo WRITTEN" % source)
        self.assertEqual(written.returncode, 0,
                         written.stdout + written.stderr)
        read = self.etag_of("/both.txt")

        # Both belong to one session: the lock token and the recorded
        # version live with the connection that took them, so the write
        # that carries them has to be the same run that has them.
        owner = self.run_script(
            "option confirm off ; etag /both.txt -match=%s ; "
            "lock /both.txt -timeout=600 ; put %s /both.txt ; "
            "echo OWNER_OK" % (read, changed))
        self.assertEqual(owner.returncode, 0, owner.stdout + owner.stderr)
        self.assertIn("OWNER_OK", owner.stdout)
        token = self.server_state()["locks"]["/both.txt"]
        # One list, both conditions, the token as a Coded-URL.
        self.assertEqual(self.if_headers("PUT", "/both.txt")[-1],
                         "(<%s> [%s])" % (token, read))

        # A session that holds neither is refused by the lock, and the file
        # keeps the version the owner wrote.
        refused = self.run_script(
            "option confirm off ; put %s /both.txt ; echo SHOULD_NOT_RUN" %
            rival)
        self.assertEqual(refused.returncode, 1,
                         refused.stdout + refused.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", refused.stdout)
        self.assertIn("423", refused.stderr)

        self.run_script("unlock /both.txt")
        back = self.root / "dav-both-readback.txt"
        self.assertEqual(self.run_script("get /both.txt %s" % back).returncode,
                         0)
        self.assertEqual(back.read_bytes(), changed.read_bytes())

    def test_a_precondition_names_the_path_it_was_recorded_for(self):
        """What a precondition on a collection means: it guards the
        collection, and nothing below it.

        A collection's tag names its listing, so a member that inherited
        it would be refused by the first change the listing made - the tag
        goes stale, and every later write below that directory fails too.
        The rule recorded for a path is therefore the rule that path is
        written under, and a member states its own.
        """
        source = self.root / "dav-coll-source.txt"
        source.write_text("a member of the collection\n", encoding="utf-8")
        changed = self.root / "dav-coll-changed.txt"
        changed.write_text("the same member, changed\n", encoding="utf-8")

        made = self.run_script(
            "option confirm off ; mkdir /col ; put %s /col/inner.txt ; "
            "echo READY" % source)
        self.assertEqual(made.returncode, 0, made.stdout + made.stderr)
        listing = self.etag_of("/col")

        # The member's own write carries no precondition, even though the
        # collection above it has one recorded: nothing was stated for its
        # path, and the listing the tag names does not move when a member
        # changes its content.
        guarded = self.run_script(
            "option confirm off ; etag /col -match=%s ; "
            "put %s /col/inner.txt ; echo MEMBER_WRITTEN" % (listing, changed))
        self.assertEqual(guarded.returncode, 0,
                         guarded.stdout + guarded.stderr)
        self.assertIn("MEMBER_WRITTEN", guarded.stdout)
        self.assertEqual(self.if_headers("PUT", "/col/inner.txt"), [])
        self.assertEqual(self.etag_of("/col"), listing)

        # Removing the member moves the listing, so the tag recorded before
        # it is stale for the collection - which is exactly why a member
        # cannot inherit one.
        emptied = self.run_script(
            "option confirm off ; etag /col -match=%s ; "
            "rm /col/inner.txt ; echo MEMBER_REMOVED" % listing)
        self.assertEqual(emptied.returncode, 0,
                         emptied.stdout + emptied.stderr)
        self.assertIn("MEMBER_REMOVED", emptied.stdout)
        self.assertEqual(self.if_headers("DELETE", "/col/inner.txt"), [])
        emptied_tag = self.etag_of("/col")
        self.assertNotEqual(emptied_tag, listing)

        # A write aimed at the collection itself is refused by a tag that
        # is not its own, and by the one it had before its listing moved;
        # both leave it standing.
        for stale in ('"not-this-tag"', listing):
            with self.subTest(tag=stale):
                refused = self.run_script(
                    "option confirm off ; etag /col -match=%s ; "
                    "rmdir /col ; echo SHOULD_NOT_RUN" % stale)
                self.assertEqual(refused.returncode, 1,
                                 refused.stdout + refused.stderr)
                self.assertIn("412", refused.stderr)
                self.assertNotIn("SHOULD_NOT_RUN", refused.stdout)
                self.assertIn("/col", self.server_state()["etags"])

        # The collection's current tag lets its own removal through.
        removed = self.run_script(
            "option confirm off ; etag /col -match=%s ; "
            "rmdir /col ; echo REMOVED" % emptied_tag)
        self.assertEqual(removed.returncode, 0,
                         removed.stdout + removed.stderr)
        self.assertIn("REMOVED", removed.stdout)
        self.assertNotIn("/col", self.server_state()["etags"])

    def test_cp_uses_webdav_copy_and_preserves_the_source(self):
        """COPY is a server-side operation: the destination has to match
        byte-for-byte, the original remains, and the mock's COPY counter
        proves no GET/PUT stream-copy fallback was used."""
        source = self.root / "dav-copy-source.bin"
        payload = bytes(range(256)) * 128
        source.write_bytes(payload)
        downloaded = self.root / "dav-copy-destination.bin"
        result = self.run_script(
            "option confirm off ; mkdir /docs ; "
            "put %s /docs/source.bin ; "
            "cp /docs/source.bin /docs/copied.bin ; "
            "get /docs/copied.bin %s ; ls -l /docs ; echo COPY_OK" %
            (source, downloaded))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("COPY_OK", result.stdout)
        self.assertIn("source.bin", result.stdout)
        self.assertIn("copied.bin", result.stdout)
        self.assertEqual(downloaded.read_bytes(), payload)
        self.assertEqual(self.server_state()["copy_count"], 1)

    def test_cp_falls_back_to_streaming_when_webdav_copy_is_refused(self):
        source = self.root / "dav-fallback-source.bin"
        payload = bytes(range(251)) * 257
        source.write_bytes(payload)
        downloaded = self.root / "dav-fallback-destination.bin"
        result = self.run_script(
            "option confirm off ; mkdir /docs ; put %s /docs/source.bin" %
            source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.reject_next_server_copy()

        result = self.run_script(
            "cp /docs/source.bin /docs/copied.bin ; "
            "get /docs/copied.bin %s ; echo COPY_FALLBACK_OK" % downloaded)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("COPY_FALLBACK_OK", result.stdout)
        self.assertEqual(downloaded.read_bytes(), payload)
        self.assertEqual(self.server_state()["copy_count"], 0)

    def test_rename_moves_and_remove_reports_a_missing_file(self):
        first = self.root / "a.txt"
        first.write_text("alpha\n", encoding="utf-8")
        second = self.root / "b.txt"
        second.write_text("bravo\n", encoding="utf-8")
        result = self.run_script(
            "option confirm off ; "
            "mkdir /docs ; put %s /docs/a.txt ; put %s /docs/b.txt ; "
            "mv /docs/a.txt /docs/renamed.txt ; "
            "ls -l /docs ; "
            "get /docs/renamed.txt %s/renamed.txt ; "
            "rm /docs/b.txt ; "
            "rm /docs/b.txt ; echo SHOULD_NOT_SEE" %
            (first, second, self.root))
        # The second rm (b.txt is gone) is what fails the script.
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual((self.root / "renamed.txt").read_text(), "alpha\n")
        self.assertIn("No such file or directory", result.stderr)
        self.assertNotIn("SHOULD_NOT_SEE", result.stdout)

        # The source of the rename is gone; the destination survived.
        listing = self.run_script("ls -l /docs")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertIn("renamed.txt", listing.stdout)
        self.assertNotIn("a.txt", listing.stdout.split("a.txt")[0])
        self.assertNotIn(
            " a.txt", listing.stdout.replace("renamed.txt", ""))

        # And a move of something that was never there reports it.
        result = self.run_script(
            "option confirm off ; mv /docs/ghost.txt /docs/x ; "
            "echo SHOULD_NOT_SEE")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("No such file or directory", result.stderr)


    def test_session_stat_close_and_no_match_follow_upstream(self):
        """The console outputs that need a live session, checked against
        the shapes upstream produces: the open-session listing of
        'session', the single listing line of 'stat', the line 'close'
        prints, and the no-match sentence of a mask that matched
        nothing - with and without failonnomatch."""
        source = self.root / "hello.txt"
        source.write_bytes(b"hello dav world\n")
        # stat in its own run, so its one listing line is unambiguous.
        result = self.run_script(
            "mkdir /docs ; put %s /docs/hello.txt ; stat /docs/hello.txt" %
            source)
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        stat_lines = [line for line in result.stdout.splitlines()
                      if line.startswith("-")
                      and line.rstrip().endswith("hello.txt")]
        self.assertEqual(len(stat_lines), 1, result.stdout)
        self.assertNotIn("SizeBytes:", result.stdout)

        # cd, pwd, dir, session and close in a second run against it.
        result = self.run_script(
            "cd /docs ; pwd ; dir ; session ; session 1 ; "
            "close ; echo AFTER_CLOSE")
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        # cd and pwd print the directory, like upstream, and dir is ls.
        self.assertRegex(result.stdout, r"(?m)^/docs$")
        self.assertIn("hello.txt", result.stdout.split("Active session")[0])
        # session: '%3d  name' for every open session plus the active line.
        self.assertRegex(result.stdout, r"(?m)^\s*1  127\.0\.0\.1$")
        self.assertIn("Active session: 1 (127.0.0.1)", result.stdout)
        # close: the closed session named, and the script carried on.
        self.assertIn("Session '127.0.0.1' closed.", result.stdout)
        self.assertIn("AFTER_CLOSE", result.stdout)

        # An index that does not exist is refused while connected.
        result = self.run_script("session 5 ; echo SHOULD_NOT_RUN")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("Invalid session index", result.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

        # After close the session is gone and the next command says so.
        result = self.run_script("close ; pwd ; echo SHOULD_NOT_RUN")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("Session '127.0.0.1' closed.", result.stdout)
        self.assertIn("Not connected", result.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

        # An empty mask prints the no-match sentence instead of failing;
        # failonnomatch turns the same sentence into the script's error.
        result = self.run_script(
            "mkdir /empty ; ls /empty/*.txt ; echo AFTER_MATCH")
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertIn("No files found matching", result.stdout)
        self.assertIn("AFTER_MATCH", result.stdout)
        result = self.run_script(
            "option failonnomatch on ; ls /empty/*.txt ; "
            "echo SHOULD_NOT_RUN")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("No files found matching", result.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)


    def test_alias_names_reach_the_commands_they_stand_for(self):
        """md, rename, recv, mget, mput and del are this client's aliases;
        they have to do the work of the command, and the script stops at
        quit like it stops at exit."""
        source = self.root / "alias.txt"
        source.write_bytes(b"alias data\n")
        downloaded = self.root / "alias-downloaded.txt"
        reuploaded = self.root / "alias-reuploaded.txt"
        result = self.run_script(
            "option confirm off ; "
            "mkdir /docs ; md /docs/sub ; put %s /docs/a.txt ; "
            "rename /docs/a.txt /docs/b.txt ; "
            "recv /docs/b.txt %s ; mget /docs/b.txt %s ; "
            "mput %s /docs/c.txt ; del /docs/b.txt ; del /docs/c.txt ; "
            "ls /docs ; echo ALIASES_OK ; quit ; echo SHOULD_NOT_RUN" %
            (source, downloaded, reuploaded, reuploaded))
        self.assertEqual(result.returncode, 0,
                         result.stdout + result.stderr)
        self.assertIn("ALIASES_OK", result.stdout)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)
        self.assertEqual(sha256_of(source), sha256_of(downloaded))
        self.assertEqual(sha256_of(source), sha256_of(reuploaded))
        listing = self.run_script("ls /docs")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        self.assertIn("sub", listing.stdout)
        self.assertNotIn("a.txt", listing.stdout)
        self.assertNotIn("b.txt", listing.stdout)
        self.assertNotIn("c.txt", listing.stdout)


    def test_proxy_localhost_off_bypasses_loopback(self):
        """ProxyLocalhost=0 is the upstream default: loopback destinations
        must bypass the configured proxy."""
        proxy_port, proxy_lines = self.start_proxy()
        source = self.root / "local-bypass.txt"
        source.write_bytes(b"loopback bypass\n")
        downloaded = self.root / "local-bypass-back.txt"
        result = self.run_script(
            "put %s /local-bypass.txt ; get /local-bypass.txt %s" %
            (source, downloaded),
            open_args=["-rawsettings", "ProxyMethod=SOCKS5",
                       "ProxyHost=127.0.0.1", "ProxyPort=%d" % proxy_port,
                       "ProxyLocalhost=0"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(downloaded.read_bytes(), source.read_bytes())
        self.assertFalse(
            any(line.startswith("CONNECT ") for line in proxy_lines),
            "loopback request unexpectedly went through the proxy: %s" %
            (proxy_lines,))

    def test_the_curl_path_goes_through_a_proxy(self):
        """A SOCKS5 proxy set with '-rawsettings' carries a WebDAV session
        too: curl is given the proxy, the requests reach the server through
        it, and a proxy method curl cannot speak is refused instead of
        silently connecting around it."""
        proxy_port, proxy_lines = self.start_proxy()
        source = self.root / "proxied.txt"
        source.write_bytes(b"through the proxy\n")
        downloaded = self.root / "proxied-back.txt"
        result = self.run_script(
            "mkdir /proxied ; put %s /proxied/file.txt ; "
            "get /proxied/file.txt %s ; echo PROXY_OK" % (source, downloaded),
            open_args=["-rawsettings", "ProxyMethod=SOCKS5",
                       "ProxyHost=127.0.0.1", "ProxyPort=%d" % proxy_port,
                       "ProxyLocalhost=1"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PROXY_OK", result.stdout)
        self.assertEqual(sha256_of(source), sha256_of(downloaded))
        self.assertTrue(
            any(line.startswith("CONNECT 127.0.0.1:%d" % self.port)
                for line in proxy_lines),
            "no request reached the server through the proxy: %s" %
            (proxy_lines,))

        refused = self.run_script(
            "echo SHOULD_NOT_RUN",
            open_args=["-rawsettings", "ProxyMethod=Telnet",
                       "ProxyHost=127.0.0.1", "ProxyPort=%d" % proxy_port,
                       "ProxyTelnetCommand=nc"])
        self.assertEqual(refused.returncode, 1,
                         refused.stdout + refused.stderr)
        self.assertIn("curl", refused.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", refused.stdout)


def run_and_report():
    """Run the suite, then print one line that says what was actually
    run (the convention every suite shares for CI annotations)."""
    suite = unittest.defaultTestLoader.loadTestsFromModule(
        sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    line = ("evidence: suite=%s platform=linux ran=%d skipped=%d failed=%d" %
            (SUITE_NAME, result.testsRun, len(result.skipped),
             len(result.failures) + len(result.errors)))
    if not result.testsRun and result.skipped:
        reasons = "; ".join(sorted(set(str(reason)[:160]
                                       for _, reason in result.skipped)))
        line += " because: " + reasons
    print(line)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_and_report())
