"""Live tests against the throwaway S3 endpoint in this directory.

TestSftpServer.py covers the SFTP protocol; Amazon S3 is a signed-HTTP
protocol and needs its own server, so this file exists: it starts
TestS3Server.py (TLS on a port the kernel picks, credentials fixed to
AKIDTEST/testsecret42) and drives the console client against it -
bucket and object listings, mkdir/rmdir markers, upload, download,
server-side CopyObject for `cp` and rename, multipart upload of a large
object (with per-part ETags and completion), embedded HTTP-200 errors from
CopyObject and multipart completion (with abort cleanup), remove, a resumed download
that must go through an HTTP byte range, and the two refusal paths: a wrong secret
rejected by signature verification and missing credentials refused
before any request. One test additionally signs a request with
botocore, Amazon's own reference implementation, so that the server's
verification and the client's signing are both checked against
something neither of them wrote.

No third-party requirement beyond the standard library - botocore is
optional and the test that needs it skips with that as its reason, the
same way the SFTP suite treats paramiko. The suite is POSIX in
practice (it shells out to curl over TLS against 127.0.0.1); where it
cannot run it says so per test.

Evidence convention (same as every other suite):

    evidence: suite=live-s3 platform=linux ran=N skipped=N failed=N
"""

import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())
SUITE_NAME = "live-s3"
HERE = pathlib.Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures"
CERT = FIXTURES / "s3-server-cert.pem"
KEY = FIXTURES / "s3-server-key.pem"

ACCESS_KEY = "AKIDTEST"
SECRET_KEY = "testsecret42"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class LiveS3Tests(unittest.TestCase):
    """A fresh server (and therefore a fresh in-memory store) per test,
    started over TLS on a kernel-picked port."""

    @classmethod
    def setUpClass(cls):
        if not CERT.is_file() or not KEY.is_file():
            raise unittest.SkipTest(
                "the TLS fixtures in fixtures/ are missing; generate them "
                "with openssl (see TestS3Server.py)")
        cls.workdir = tempfile.TemporaryDirectory(prefix="live-s3-")
        cls.root = pathlib.Path(cls.workdir.name) / "local"
        cls.root.mkdir()
        cls.config = pathlib.Path(cls.workdir.name) / "config"
        cls.config.mkdir()
        cls.addClassCleanup(cls.workdir.cleanup)

    def setUp(self):
        self.start_server()

    def tearDown(self):
        self.stop_server()

    # -- the server ---------------------------------------------------------
    def start_server(self):
        env = dict(os.environ, LSCP_TEST_PORT="0")
        # Its own process group, so that teardown can stop the server and
        # anything it left behind without touching the test runner.
        popen_args = dict(env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True,
                          start_new_session=True)
        self.server = subprocess.Popen(
            [sys.executable, str(HERE / "TestS3Server.py")], **popen_args)
        self.port = None
        timer = threading.Timer(30.0, self.server.kill)
        timer.start()
        try:
            for line in self.server.stdout:
                line = line.strip()
                if line.startswith("READY "):
                    self.port = int(line.split()[1])
                    break
                if line.startswith("MISSING-FIXTURES"):
                    self.fail(line)
            if self.port is None:
                self.fail("the S3 test server did not report a port")
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

    # -- driving the client -------------------------------------------------
    def run_script(self, commands, creds=None, extra_args=(), timeout=60):
        """'open sftp-style' by URL, then the script; creds defaults to
        the server's fixed pair."""
        user, secret = creds if creds else (ACCESS_KEY, SECRET_KEY)
        argv = [BINARY, "-batch", "-hostkey=*",
                "-log=" + str(self.config / "session.log")]
        argv += list(extra_args)
        argv.append("-command=open s3://%s:%s@127.0.0.1:%d/ ; %s" %
                    (user, secret, self.port, commands))
        env = dict(os.environ, LINSCP_CONFIG_DIR=str(self.config))
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, env=env)

    def open_only(self, creds=None, extra_args=()):
        user, secret = creds if creds else (ACCESS_KEY, SECRET_KEY)
        return self.run_script("echo OPENED", creds=creds,
                               extra_args=extra_args)

    def server_state(self):
        context = ssl._create_unverified_context()
        url = "https://127.0.0.1:%d/__test__/state" % self.port
        with urllib.request.urlopen(url, context=context, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))

    def inject_embedded_error(self, operation):
        context = ssl._create_unverified_context()
        url = "https://127.0.0.1:%d/__test__/inject-error?operation=%s" % (
            self.port, operation)
        with urllib.request.urlopen(url, context=context, timeout=15) as response:
            self.assertEqual(response.status, 204)

    def seed_versions(self, bucket, key, count):
        context = ssl._create_unverified_context()
        query = urllib.parse.urlencode({
            "bucket": bucket, "key": key, "count": count,
        })
        url = "https://127.0.0.1:%d/__test__/seed-versions?%s" % (
            self.port, query)
        with urllib.request.urlopen(url, context=context, timeout=30) as response:
            self.assertEqual(response.status, 204)

    def seed_objects(self, bucket, count):
        context = ssl._create_unverified_context()
        query = urllib.parse.urlencode({"bucket": bucket, "count": count})
        url = "https://127.0.0.1:%d/__test__/seed-objects?%s" % (
            self.port, query)
        with urllib.request.urlopen(url, context=context, timeout=30) as response:
            self.assertEqual(response.status, 204)

    def inject_pagination_fault(self, target, fault):
        context = ssl._create_unverified_context()
        query = urllib.parse.urlencode({"target": target, "fault": fault})
        url = "https://127.0.0.1:%d/__test__/inject-pagination-fault?%s" % (
            self.port, query)
        with urllib.request.urlopen(url, context=context, timeout=15) as response:
            self.assertEqual(response.status, 204)

    # -- tests --------------------------------------------------------------
    def test_missing_secret_is_refused_before_any_request(self):
        """A site without a secret key cannot be signed at all, and says
        so instead of trying anonymously."""
        argv = [BINARY, "-batch", "-hostkey=*",
                "-command=open s3://%s@127.0.0.1:%d/ ; echo SHOULD_NOT_RUN" %
                (ACCESS_KEY, self.port)]
        result = subprocess.run(argv, capture_output=True, text=True,
                                timeout=60,
                                env=dict(os.environ,
                                         LINSCP_CONFIG_DIR=str(self.config)))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("secret access key", result.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

    def test_wrong_secret_is_rejected_by_signature_verification(self):
        """The server re-derives every signature; a wrong secret has to
        come back as a named S3 error, not a silent open."""
        result = self.run_script("echo SHOULD_NOT_RUN",
                                 creds=(ACCESS_KEY, "not-the-secret"))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("SignatureDoesNotMatch", result.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

    def test_listing_shows_buckets_directories_and_objects(self):
        """mkdir creates buckets and markers, put creates objects, and
        both levels of listing report them with sizes."""
        source = self.root / "hello.txt"
        source.write_text("hello s3 world\n", encoding="utf-8")
        result = self.run_script(
            "mkdir /photos ; mkdir /photos/2026 ; "
            "put %s /photos/hello.txt ; "
            "ls ; ls -l /photos ; echo LIST_OK" % source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("LIST_OK", result.stdout)
        # Root listing: the bucket as a directory.
        root_part = result.stdout.split("Reading directory /...")[1]
        self.assertRegex(root_part, r"drwx[-rwx]+\s+\S+\s+\S+\s+\S+\s+\d+\s+"
                                    r"\S+\s+\S+\s+\S+\s+photos")
        # Bucket listing: the object with its size, the directory.
        bucket_part = result.stdout.split("Reading directory /photos...")[1]
        self.assertIn("hello.txt", bucket_part)
        self.assertRegex(bucket_part, r"\s15\s.*hello\.txt")
        self.assertIn("2026", bucket_part)

        # And a fresh connection still sees it all (the store is the
        # server's, not the session's).
        result = self.run_script("ls -l /photos ; echo STILL_THERE")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("hello.txt", result.stdout)

    def test_rmdir_refuses_nonempty_and_accepts_virtual_directories(self):
        """rmdir on S3 has to behave like everywhere else: a directory
        with contents fails, a marker-less 'virtual' prefix with none
        succeeds, and the bucket itself is not a directory."""
        source = self.root / "payload.txt"
        source.write_text("payload\n", encoding="utf-8")
        result = self.run_script(
            "option confirm off ; "
            "mkdir /photos ; mkdir /photos/full ; "
            "put %s /photos/full/keep.txt ; "
            "rmdir /photos/full ; echo SHOULD_NOT_SEE" % source)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not empty", result.stderr)
        self.assertNotIn("SHOULD_NOT_SEE", result.stdout)

        # A prefix that was never mkdir'd: object underneath, then the
        # object removed - rmdir has nothing marker-wise to delete and
        # must still succeed.
        result = self.run_script(
            "option confirm off ; "
            "put %s /photos/virtual/deep.txt ; "
            "rm /photos/virtual/deep.txt ; rmdir /photos/virtual ; "
            "ls /photos ; echo VIRTUAL_OK" % source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VIRTUAL_OK", result.stdout)
        listing = result.stdout.split("Reading directory /photos...")[1]
        listing = listing.split("VIRTUAL_OK")[0]
        self.assertNotIn("virtual", listing)

        # rmdir on the bucket itself is refused with a way out.
        result = self.run_script(
            "option confirm off ; rmdir /photos ; echo SHOULD_NOT_SEE")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("bucket itself", result.stderr)

    def test_upload_and_download_roundtrip(self):
        source = self.root / "roundtrip.bin"
        source.write_bytes(bytes(range(256)) * 64)
        downloaded = self.root / "roundtrip-downloaded.bin"
        result = self.run_script(
            "mkdir /photos ; put %s /photos/roundtrip.bin ; "
            "get /photos/roundtrip.bin %s ; echo ROUNDTRIP_OK" %
            (source, downloaded))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ROUNDTRIP_OK", result.stdout)
        self.assertEqual(sha256_of(source), sha256_of(downloaded))

        # attr reports the size the server does; stat prints the single
        # listing line upstream prints, with no key/value lines at all.
        result = self.run_script("attr /photos/roundtrip.bin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SizeBytes:   %d" % source.stat().st_size,
                      result.stdout)
        result = self.run_script("stat /photos/roundtrip.bin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("SizeBytes:", result.stdout)
        self.assertRegex(result.stdout, r"(?m)^\S.* roundtrip\.bin$")

    def test_version_listing_get_delete_markers_and_versioned_resume(self):
        """Opaque version IDs round-trip through SigV4 query encoding;
        downloads resume into a per-version staging file, and deletion can
        remove one historical version or a delete marker without touching
        the remaining versions."""
        old_source = self.root / "version-old.bin"
        new_source = self.root / "version-new.bin"
        old_payload = bytes(bytearray((i * 13 + 7) % 256
                                      for i in range(180000)))
        new_payload = b"new current version\n" * 9000
        old_source.write_bytes(old_payload)
        new_source.write_bytes(new_payload)

        result = self.run_script(
            "option confirm off ; mkdir /photos ; "
            "put %s /photos/versioned.bin ; "
            "put %s /photos/versioned.bin ; "
            "versions /photos/versioned.bin" % (old_source, new_source))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        records = []
        for line in result.stdout.splitlines():
            marker = "  /photos/versioned.bin  "
            if marker in line:
                state, rest = line.split(marker, 1)
                records.append((state.strip(), rest.split("  ", 1)[0]))
        self.assertEqual(len(records), 2, result.stdout)
        old_version = next(version_id for state, version_id in records
                           if state == "version")
        current_version = next(version_id for state, version_id in records
                               if state == "latest")
        # The server's IDs contain '/', '+', '%', '&', '=' and '?'; they
        # must be treated as opaque query values, not shell or URL syntax.
        self.assertIn("/", old_version)
        self.assertIn("%", old_version)
        self.assertIn("&", old_version)

        destination = self.root / "versioned-download.bin"
        version_stage = pathlib.Path(
            str(destination) + ".filepart.v" +
            hashlib.sha256(old_version.encode("utf-8")).hexdigest())
        version_stage.write_bytes(old_payload[:76543])
        unrelated_stage = pathlib.Path(str(destination) + ".filepart")
        unrelated_stage.write_bytes(new_payload[:80000])
        current_download = self.root / "current-download.bin"
        command = (
            "option confirm off ; "
            "get -resume -versionid=%s /photos/versioned.bin %s ; "
            "get -versionid=%s /photos/versioned.bin %s ; echo VERSION_GET_OK" %
            (old_version, destination, current_version, current_download))
        result = self.run_script(command, extra_args=("-literal",))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("VERSION_GET_OK", result.stdout)
        self.assertEqual(sha256_of(old_source), sha256_of(destination))
        self.assertEqual(sha256_of(new_source), sha256_of(current_download))
        self.assertFalse(version_stage.exists())
        self.assertTrue(unrelated_stage.exists())

        result = self.run_script(
            "option confirm off ; rm -versionid=%s /photos/versioned.bin ; "
            "versions /photos/versioned.bin" % old_version,
            extra_args=("-literal",))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        remaining = []
        for line in result.stdout.splitlines():
            marker = "  /photos/versioned.bin  "
            if marker in line:
                remaining.append(line.split(marker, 1)[1].split("  ", 1)[0])
        self.assertEqual(remaining, [current_version], result.stdout)

        result = self.run_script(
            "option confirm off ; rm /photos/versioned.bin ; "
            "versions /photos/versioned.bin")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        marker_records = []
        for line in result.stdout.splitlines():
            marker = "  /photos/versioned.bin  "
            if marker in line:
                state, rest = line.split(marker, 1)
                if state.strip() == "delete marker":
                    marker_records.append(rest.split("  ", 1)[0])
        self.assertEqual(len(marker_records), 1, result.stdout)
        delete_marker_id = marker_records[0]

        failed = self.root / "delete-marker-download.bin"
        result = self.run_script(
            "get -versionid=%s /photos/versioned.bin %s" %
            (delete_marker_id, failed), extra_args=("-literal",))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("delete marker", result.stderr)
        self.assertFalse(failed.exists())

        result = self.run_script(
            "option confirm off ; rm -versionid=%s /photos/versioned.bin ; "
            "get /photos/versioned.bin %s" % (delete_marker_id, failed),
            extra_args=("-literal",))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sha256_of(new_source), sha256_of(failed))

    def test_version_listing_paginates_all_versions(self):
        """A listing spanning the S3 page boundary must include records
        from both pages and preserve the exact key's version count."""
        self.seed_versions("test-bucket", "pagination/object", 1001)
        result = self.run_script("versions /test-bucket/pagination/object",
                                 timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        marker = "  /test-bucket/pagination/object  "
        records = [line for line in result.stdout.splitlines()
                   if marker in line]
        self.assertEqual(len(records), 1001, result.stdout[-2000:])

    def test_object_listing_rejects_broken_pagination_state(self):
        """ListObjects must fail closed on a missing or repeated token,
        rather than claim that one page was the complete directory."""
        self.seed_objects("test-bucket", 1001)
        for fault, expected in (
                ("repeat-token", "repeated a continuation token"),
                ("missing-token", "has no continuation token")):
            with self.subTest(fault=fault):
                self.inject_pagination_fault("objects", fault)
                result = self.run_script("ls /test-bucket", timeout=90)
                self.assertEqual(result.returncode, 1,
                                 result.stdout + result.stderr)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("item-0000.txt", result.stdout)

    def test_version_listing_rejects_broken_pagination_state(self):
        """A truncated ListObjectVersions response must provide a new
        key/version marker, and the client must reject a repeated marker."""
        self.seed_versions("test-bucket", "pagination/object", 1001)
        for fault, expected in (
                ("repeat-marker", "repeated its pagination marker"),
                ("missing-version-marker", "has no next version ID marker")):
            with self.subTest(fault=fault):
                self.inject_pagination_fault("versions", fault)
                result = self.run_script(
                    "versions /test-bucket/pagination/object", timeout=90)
                self.assertEqual(result.returncode, 1,
                                 result.stdout + result.stderr)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("Object versions for", result.stdout)

    def test_cp_uses_s3_copy_object_and_keeps_the_source(self):
        source = self.root / "copy-source.txt"
        payload = b"server-side copy on S3\n" * 100
        source.write_bytes(payload)
        downloaded = self.root / "copy-destination.txt"
        result = self.run_script(
            "option confirm off ; mkdir /photos ; "
            "put %s /photos/source.txt ; "
            "cp /photos/source.txt /photos/copied.txt ; "
            "get /photos/copied.txt %s ; ls -l /photos ; echo COPY_OK" %
            (source, downloaded))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("COPY_OK", result.stdout)
        self.assertIn("source.txt", result.stdout)
        self.assertIn("copied.txt", result.stdout)
        self.assertEqual(downloaded.read_bytes(), payload)
        self.assertEqual(self.server_state()["copy_count"], 1)

    def test_copy_object_embedded_http_200_error_is_reported(self):
        source = self.root / "copy-error-source.txt"
        source.write_text("copy source\n", encoding="utf-8")
        result = self.run_script(
            "mkdir /photos ; put %s /photos/source.txt" % source)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        self.inject_embedded_error("copy")
        result = self.run_script(
            "cp /photos/source.txt /photos/failed-copy.txt")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("InjectedCopyError", result.stderr)
        self.assertIn("Embedded copy failure", result.stderr)
        self.assertEqual(self.server_state()["copy_count"], 0)

    def test_large_upload_uses_multipart_and_roundtrips(self):
        """Large S3 objects must go through initiate/parts/complete rather
        than one unbounded PUT; every returned part ETag is used to commit
        the object, and the object that becomes visible is byte-exact."""
        source = self.root / "multipart.bin"
        expected_size = 20 * 1024 * 1024 + 123
        block = bytes(range(256)) * 4096  # one MiB, deterministic bytes
        with source.open("wb") as handle:
            remaining = expected_size
            while remaining:
                chunk = block[:min(len(block), remaining)]
                handle.write(chunk)
                remaining -= len(chunk)

        downloaded = self.root / "multipart-downloaded.bin"
        result = self.run_script(
            "mkdir /photos ; put %s /photos/multipart.bin ; "
            "get /photos/multipart.bin %s ; echo MULTIPART_OK" %
            (source, downloaded), timeout=180)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MULTIPART_OK", result.stdout)
        self.assertEqual(source.stat().st_size, expected_size)
        self.assertEqual(sha256_of(source), sha256_of(downloaded))

        state = self.server_state()
        history = state["multipart_history"]
        actions = [event["action"] for event in history]
        self.assertEqual(actions, ["initiate", "part", "part", "part", "complete"])
        part_events = [event for event in history if event["action"] == "part"]
        self.assertEqual([event["part"] for event in part_events], [1, 2, 3])
        self.assertEqual(sum(event["size"] for event in part_events), expected_size)
        self.assertEqual(state["active_uploads"], 0)
        complete = history[-1]
        self.assertEqual(complete["size"], expected_size)
        self.assertEqual(complete["parts"], 3)

    def test_multipart_completion_embedded_http_200_error_is_reported_and_aborted(self):
        source = self.root / "multipart-error.bin"
        expected_size = 20 * 1024 * 1024 + 17
        block = bytes(range(256)) * 4096
        with source.open("wb") as handle:
            remaining = expected_size
            while remaining:
                chunk = block[:min(len(block), remaining)]
                handle.write(chunk)
                remaining -= len(chunk)

        self.inject_embedded_error("complete")
        result = self.run_script(
            "mkdir /photos ; put %s /photos/multipart-error.bin" % source,
            timeout=180)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("InjectedCompleteError", result.stdout + result.stderr)
        self.assertIn("Embedded completion failure", result.stdout + result.stderr)

        state = self.server_state()
        actions = [event["action"] for event in state["multipart_history"]]
        self.assertEqual(actions,
            ["initiate", "part", "part", "part", "abort"])
        self.assertEqual(state["active_uploads"], 0)

    def test_resumed_download_continues_through_a_byte_range(self):
        """A pre-existing staging file makes the download resume with
        curl -C; the server answers only with a range, so a client that
        ignored the offset would get a whole-object 200 and curl would
        refuse it (exit 33) - completion and checksum prove the range
        path was taken."""
        source = self.root / "large.bin"
        payload = bytes(bytearray((i * 7 + 3) % 256 for i in range(300000)))
        source.write_bytes(payload)
        destination = self.root / "large-dl.bin"
        staging = pathlib.Path(str(destination) + ".filepart")
        staging.write_bytes(payload[:123456])  # resume from here

        result = self.run_script(
            "mkdir /photos ; put %s /photos/large.bin ; "
            "get -resume /photos/large.bin %s ; echo RESUME_OK" %
            (source, destination))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RESUME_OK", result.stdout)
        self.assertFalse(staging.exists())
        self.assertEqual(sha256_of(source), sha256_of(destination))

    def test_rename_and_remove(self):
        """Rename is CopyObject plus a delete marker on the source; a
        repeated S3 DELETE creates another marker, while current reads still
        see the key as absent."""
        first = self.root / "a.txt"
        first.write_text("alpha\n", encoding="utf-8")
        second = self.root / "b.txt"
        second.write_text("bravo\n", encoding="utf-8")
        result = self.run_script(
            "option confirm off ; "
            "mkdir /photos ; put %s /photos/a.txt ; put %s /photos/b.txt ; "
            "mv /photos/a.txt /photos/renamed.txt ; "
            "ls -l /photos ; "
            "get /photos/renamed.txt %s/renamed.txt ; "
            "rm /photos/b.txt ; "
            "rm /photos/b.txt ; versions /photos/b.txt ; echo REMOVE_OK" %
            (first, second, self.root))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("renamed.txt", result.stdout)
        self.assertIn("REMOVE_OK", result.stdout)
        self.assertIn("delete marker", result.stdout)
        # renamed.txt is the copy of a.txt; b.txt was hidden by two markers.
        self.assertEqual((self.root / "renamed.txt").read_text(),
                         "alpha\n")

        # A current-version read still sees b.txt as absent.
        result = self.run_script(
            "get /photos/b.txt %s/gone-b.txt ; echo SHOULD_NOT_SEE" % self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("SHOULD_NOT_SEE", result.stdout)

        # a.txt really moved: the old name is gone.
        result = self.run_script(
            "get /photos/a.txt %s/gone.txt ; echo SHOULD_NOT_SEE" % self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("SHOULD_NOT_SEE", result.stdout)

    def test_unsigned_and_botocore_signed_requests(self):
        """Two directions of agreement: a request with no signature at
        all is refused, and a request signed by botocore - the AWS
        reference implementation - is accepted by this server, which is
        what makes the client's signatures mean something."""
        context = ssl._create_unverified_context()

        unsigned = urllib.request.Request(
            "https://127.0.0.1:%d/" % self.port, method="GET")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(unsigned, context=context, timeout=15)
        self.assertEqual(caught.exception.code, 403)
        body = caught.exception.read().decode("utf-8", "replace")
        self.assertIn("InvalidRequest", body)

        if importlib.util.find_spec("botocore") is None:
            self.skipTest(
                "botocore is not installed; skipping the reference-"
                "implementation signature check (pip install botocore)")
        import botocore.auth
        import botocore.awsrequest
        from botocore.credentials import Credentials

        # Seed a bucket the botocore request can list.
        self.assertEqual(self.run_script(
            "mkdir /botobucket").returncode, 0)

        request = botocore.awsrequest.AWSRequest(
            method="GET", url="https://127.0.0.1:%d/" % self.port,
            headers={"x-amz-content-sha256": EMPTY_SHA256})
        botocore.auth.SigV4Auth(
            Credentials(ACCESS_KEY, SECRET_KEY), "s3",
            "us-east-1").add_auth(request)
        prepared = request.prepare()
        wire = urllib.request.Request(prepared.url, method="GET")
        for name, value in request.headers.items():
            if name.lower() != "host":
                wire.add_header(name, value)
        response = urllib.request.urlopen(wire, context=context, timeout=15)
        self.assertEqual(response.status, 200)
        xml = response.read().decode("utf-8")
        self.assertIn("<Name>botobucket</Name>", xml)

    def test_object_write_headers_and_requester_pays(self):
        """S3 raw settings (S3StorageClass, S3Acl, S3ServerSideEncryption,
        S3KmsKeyId, S3RequestPayer, S3Metadata) are signed with SigV4 and
        delivered on object writes and requests."""
        source = self.root / "meta-item.txt"
        source.write_text("classified payload\n", encoding="utf-8")
        argv = [
            BINARY, "-batch", "-hostkey=*",
            "-command="
            "open s3://%s:%s@127.0.0.1:%d/ -rawsettings "
            "S3StorageClass=STANDARD_IA "
            "S3Acl=bucket-owner-full-control "
            "S3ServerSideEncryption=aws:kms "
            "S3KmsKeyId=alias/linscp-key "
            "S3RequestPayer=1 "
            "S3Metadata=Author=Ada,Project=linscp ; "
            "mkdir /vault ; "
            "put %s /vault/item.txt ; "
            "exit" % (ACCESS_KEY, SECRET_KEY, self.port, source)
        ]
        env = dict(os.environ, LINSCP_CONFIG_DIR=str(self.config))
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        state = self.server_state()
        headers = state["object_headers"].get("vault/item.txt", {})
        self.assertEqual(headers.get("x-amz-storage-class"), "STANDARD_IA")
        self.assertEqual(headers.get("x-amz-acl"), "bucket-owner-full-control")
        self.assertEqual(
            headers.get("x-amz-server-side-encryption"), "aws:kms")
        self.assertEqual(
            headers.get("x-amz-server-side-encryption-aws-kms-key-id"),
            "alias/linscp-key")
        self.assertEqual(headers.get("x-amz-meta-author"), "Ada")
        self.assertEqual(headers.get("x-amz-meta-project"), "linscp")
        self.assertIn("requester", state["request_payers"])

    def test_multipart_upload_resume_and_multipart_copy(self):
        """An interrupted multipart upload resumes from its persisted state
        sidecar without re-uploading completed parts, and 'cp' on an object
        above the multipart threshold uses multipart UploadPartCopy."""
        source = self.root / "resume-multipart.bin"
        expected_size = 18 * 1024 * 1024 + 321
        block = bytes(range(256)) * 4096
        with source.open("wb") as handle:
            remaining = expected_size
            while remaining:
                chunk = block[:min(len(block), remaining)]
                handle.write(chunk)
                remaining -= len(chunk)

        self.assertEqual(
            self.run_script("mkdir /big").returncode, 0)
        # Fail part 2 on the first upload attempt; part 1 is saved in the
        # multipart resume sidecar and the upload remains active.
        self.inject_embedded_error("part2")
        first = self.run_script(
            "put %s /big/object.bin" % source, timeout=180)
        self.assertNotEqual(first.returncode, 0)
        state1 = self.server_state()
        self.assertEqual(state1["active_uploads"], 1)

        # Retry the upload: it resumes the existing UploadId and skips part 1.
        second = self.run_script(
            "put %s /big/object.bin" % source, timeout=180)
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        state2 = self.server_state()
        self.assertEqual(state2["active_uploads"], 0)
        initiates = [
            e for e in state2["multipart_history"] if e["action"] == "initiate"
        ]
        self.assertEqual(len(initiates), 1)
        part1_uploads = [
            e for e in state2["multipart_history"]
            if e["action"] == "part" and e["part"] == 1
        ]
        self.assertEqual(len(part1_uploads), 1)

        # Server-side 'cp' of the >16 MiB object uses multipart UploadPartCopy.
        copied_dl = self.root / "copied-multipart.bin"
        copy_res = self.run_script(
            "cp /big/object.bin /big/copied.bin ; "
            "get /big/copied.bin %s" % copied_dl, timeout=180)
        self.assertEqual(
            copy_res.returncode, 0, copy_res.stdout + copy_res.stderr)
        self.assertEqual(sha256_of(source), sha256_of(copied_dl))
        state3 = self.server_state()
        copy_parts = [
            e for e in state3["multipart_history"] if e["action"] == "copy_part"
        ]
        self.assertEqual([e["part"] for e in copy_parts], [1, 2, 3])


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
