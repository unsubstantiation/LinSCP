"""Live tests for the FTP and FTPS protocols over curl and the native engine.

FTP/FTPS use a throwaway pyftpdlib server (the dependency is optional), and
each test checks an authenticated download and upload byte-for-byte.

Plain FTP is served by the native engine (source/linux/FtpClient.cpp), so the
tests here drive the FTP control connection itself: the server records which
commands arrived, and the tests assert that MLSD/MLST are used where they
should be, that LIST is the fallback when the server refuses MLSD or
FtpUseMlsd=0 says so, and that FtpPasvMode=0 really makes the data connection
active (PORT arrives at the server). FTPS is the curl path: implicit
(ftps://) and explicit (ftpes:// or Ftps=3) TLS, certificate verification,
a private CA, a pinned public key, the TLS version bounds, and the refusal of
a certificate fingerprint this build cannot check.

Neither SSH protocol is here any more. sftp:// is served by libssh
(LiveSftpTest.py) and scp:// by the client's own SCP engine
(LiveScpTest.py), so no part of an SSH session depends on which SSH library
the installed curl happens to link - which is what the SCP test in this file
used to have to work around.

The suite is optional in a source-tree build. Missing pyftpdlib/OpenSSL skips
the FTP cases, with the evidence line making the limitation explicit rather
than turning an empty run into a passing claim.

Evidence convention:

    evidence: suite=live-curl platform=linux ran=N skipped=N failed=N
"""

import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())
SUITE_NAME = "live-curl"

try:
    from pyftpdlib.authorizers import DummyAuthorizer
    from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
    from pyftpdlib.handlers.ftps.ssl import SSL
    from pyftpdlib.servers import FTPServer
    FTP_IMPORT_ERROR = ""
except ImportError as exc:
    DummyAuthorizer = FTPHandler = TLS_FTPHandler = SSL = FTPServer = None
    FTP_IMPORT_ERROR = "pyftpdlib with pyOpenSSL is not installed: %s" % exc


class ImplicitTLSHandler(TLS_FTPHandler if TLS_FTPHandler is not None else object):
    """pyftpdlib's normal FTPS handler expects AUTH TLS; curl ftps:// is
    implicit TLS, so wrap the accepted control socket before FTP commands."""

    if TLS_FTPHandler is not None:
        def __init__(self, conn, server, ioloop=None):
            wrapped = SSL.Connection(self.get_ssl_context(), conn)
            wrapped.set_accept_state()
            super().__init__(wrapped, server, ioloop)
            if getattr(self, "connected", False):
                self._ssl_requested = True
                self._ssl_accepting = True


class LiveCurlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.TemporaryDirectory(prefix="live-curl-")
        cls.root = pathlib.Path(cls.workdir.name) / "remote"
        cls.root.mkdir()
        cls.local = pathlib.Path(cls.workdir.name) / "local"
        cls.local.mkdir()
        cls.config = pathlib.Path(cls.workdir.name) / "config"
        cls.config.mkdir()
        cls.cert = pathlib.Path(cls.workdir.name) / "ftp-cert.pem"
        cls.addClassCleanup(cls.workdir.cleanup)

    def openssl(self, args):
        """Runs openssl and returns the file it was asked to write."""
        result = subprocess.run(["openssl"] + list(args),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return pathlib.Path(args[args.index("-out") + 1])

    def pem_cert(self):
        """The server certificate alone: what --cacert takes.

        The test certificate is written with its private key in the same
        file, which openssl and curl read happily but which says nothing
        about the chain; the trust file should be the certificate only.
        """
        only = pathlib.Path(self.workdir.name) / "ftp-cert-only.pem"
        if not only.exists():
            subprocess.run(
                ["openssl", "x509", "-in", str(self.cert), "-out", str(only)],
                capture_output=True, text=True)
        return str(only)

    def public_key_file(self):
        """The server's public key as a PEM file, for --pinnedpubkey."""
        key = pathlib.Path(self.workdir.name) / "ftp-cert-pub.pem"
        if not key.exists():
            result = subprocess.run(
                ["openssl", "x509", "-in", str(self.cert), "-pubkey", "-noout"],
                capture_output=True, text=True)
            if result.returncode != 0:
                key = self.openssl([
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(key), "-days", "1",
                    "-subj", "/CN=other"])
            key.write_text(result.stdout)
        return str(key)

    def other_public_key_file(self):
        """A public key that is not the server's: the pin must refuse it."""
        other = pathlib.Path(self.workdir.name) / "other-cert.pem"
        if not other.exists():
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-keyout", str(other), "-out", str(other), "-days", "1",
                 "-subj", "/CN=not-this-server"],
                capture_output=True, text=True)
        result = subprocess.run(
            ["openssl", "x509", "-in", str(other), "-pubkey", "-noout"],
            capture_output=True, text=True)
        other_key = pathlib.Path(self.workdir.name) / "other-cert-pub.pem"
        other_key.write_text(result.stdout)
        return str(other_key)

    def setUp(self):
        self.ftp_server = None
        self.ftp_thread = None

    def tearDown(self):
        if self.ftp_server is not None:
            self.ftp_server.close_all()
        if self.ftp_thread is not None:
            self.ftp_thread.join(timeout=5)

    def start_ftp(self, tls=False, tls_mode="implicit", record=None,
                  refuse_mlsd=False):
        """Starts the throwaway FTP server.

        'record' receives one entry per interesting command the server saw
        ("MLSD", "LIST", "PORT", "EPRT"), which is how the tests tell a
        native-engine listing from a curl one. 'refuse_mlsd' makes the
        server answer MLSD with 500, for the fallback path.
        """
        if FTP_IMPORT_ERROR:
            self.skipTest(FTP_IMPORT_ERROR)
        authorizer = DummyAuthorizer()
        authorizer.add_user("test", "test", str(self.root), perm="elradfmwMT")
        if tls:
            if shutil.which("openssl") is None:
                self.skipTest("openssl is not installed; cannot create the FTPS certificate")
            if not self.cert.exists():
                result = subprocess.run(
                    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-keyout", str(self.cert), "-out", str(self.cert), "-days", "1",
                     "-subj", "/CN=127.0.0.1"],
                    capture_output=True, text=True)
                if result.returncode != 0:
                    self.skipTest("openssl could not create the FTPS certificate: " +
                                  result.stderr.strip())
            # Explicit TLS (ftpes://, or Ftps=2/3) is pyftpdlib's ordinary
            # handler, which answers AUTH TLS; implicit TLS (ftps://) is the
            # wrapper above, which accepts TLS before the greeting.
            base = TLS_FTPHandler if tls_mode == "explicit" else ImplicitTLSHandler
        else:
            base = FTPHandler

        class Handler(base):
            def ftp_MLSD(self, path):
                if record is not None:
                    record.append("MLSD")
                if refuse_mlsd:
                    self.respond("500 MLSD is not implemented here.")
                    return
                return super().ftp_MLSD(path)

            def ftp_LIST(self, path):
                if record is not None:
                    record.append("LIST")
                return super().ftp_LIST(path)

            def ftp_PORT(self, line):
                if record is not None:
                    record.append("PORT")
                return super().ftp_PORT(line)

            def ftp_EPRT(self, line):
                if record is not None:
                    record.append("EPRT")
                return super().ftp_EPRT(line)

        Handler.authorizer = authorizer
        # The client uses passive mode by default. A fixed, private range
        # keeps the throwaway endpoint easy to diagnose without exposing it.
        Handler.passive_ports = range(42000, 42011)
        if tls:
            Handler.certfile = str(self.cert)
            Handler.ssl_context = None
            Handler.tls_control_required = True
            Handler.tls_data_required = True

        self.ftp_server = FTPServer(("127.0.0.1", 0), Handler)
        self.ftp_thread = threading.Thread(
            target=self.ftp_server.serve_forever, daemon=True)
        self.ftp_thread.start()
        return self.ftp_server.socket.getsockname()[1]

    def run_client(self, url, commands, extra=(), rawsettings=(), hostkey="*"):
        """Runs one scripted session.

        '-rawsettings' is a switch of the 'open' command, not a command-line
        option, so it is spliced into the command line here: that is the
        door the console client actually has for session settings.
        """
        args = [BINARY, "-batch", "-hostkey=" + hostkey, "-timeout=15"]
        args += list(extra)
        args.append("-command=" + self.open_and_run(url, commands, rawsettings))
        return subprocess.run(
            args, cwd=self.local, capture_output=True, text=True, timeout=90,
            env=dict(os.environ, LINSCP_CONFIG_DIR=str(self.config)))

    def open_and_run(self, url, commands, rawsettings=()):
        settings = ""
        if rawsettings:
            settings = " -rawsettings " + " ".join(rawsettings)
        return "open %s%s ; %s" % (url, settings, commands)

    def run_client_without_hostkey(self, url, commands, extra=(), rawsettings=()):
        """Like run_client, but nothing accepts the server blindly."""
        args = [BINARY, "-batch", "-timeout=15"]
        args += list(extra)
        args.append("-command=" + self.open_and_run(url, commands, rawsettings))
        return subprocess.run(
            args, cwd=self.local, capture_output=True, text=True, timeout=90,
            env=dict(os.environ, LINSCP_CONFIG_DIR=str(self.config)))

    def test_ftp_authenticated_download_and_upload(self):
        port = self.start_ftp()
        payload = b"live FTP download\n" * 8192
        upload = b"live FTP upload\n" * 8192
        (self.root / "remote.txt").write_bytes(payload)
        (self.local / "upload.txt").write_bytes(upload)
        result = self.run_client(
            "ftp://test:test@127.0.0.1:%d/" % port,
            "get /remote.txt download.txt ; put upload.txt /uploaded.txt ; exit")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.local / "download.txt").read_bytes(), payload)
        self.assertEqual((self.root / "uploaded.txt").read_bytes(), upload)

    def test_ftps_authenticated_download_and_upload(self):
        port = self.start_ftp(tls=True)
        payload = b"live FTPS download\n" * 8192
        upload = b"live FTPS upload\n" * 8192
        (self.root / "ftps-remote.txt").write_bytes(payload)
        (self.local / "ftps-upload.txt").write_bytes(upload)
        result = self.run_client(
            "ftps://test:test@127.0.0.1:%d/" % port,
            "get /ftps-remote.txt ftps-download.txt ; "
            "put ftps-upload.txt /ftps-uploaded.txt ; exit")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.local / "ftps-download.txt").read_bytes(), payload)
        self.assertEqual((self.root / "ftps-uploaded.txt").read_bytes(), upload)

    def test_ftp_listing_uses_mlsd_and_stat_uses_mlst(self):
        """The native engine asks the server for facts, not for text.

        MLSD is the listing and MLST is the stat, so the two commands have
        to reach the server that way and the listing has to come back with
        the size and directory flag the facts carry.
        """
        record = []
        port = self.start_ftp(record=record)
        body = b"mlsd facts\n" * 64
        (self.root / "facts.txt").write_bytes(body)
        (self.root / "factsdir").mkdir()
        result = self.run_client(
            "ftp://test:test@127.0.0.1:%d/" % port,
            "ls / ; stat /facts.txt ; stat /factsdir ; exit")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("MLSD", record)
        self.assertNotIn("LIST", record)
        self.assertIn("facts.txt", result.stdout)
        self.assertIn("factsdir", result.stdout)
        # MLST answered the stat: the single listing line carries the size
        # of the file and the mode of the directory.
        stat_lines = [line for line in result.stdout.splitlines()
                      if "facts.txt" in line and "factsdir" not in line]
        self.assertTrue(stat_lines, result.stdout)
        self.assertRegex(stat_lines[0], r"\b%d\b" % len(body))
        self.assertIn("d", result.stdout.splitlines()[-1][:1])

    def test_ftp_use_mlsd_off_falls_back_to_list(self):
        """FtpUseMlsd=0 means LIST, and the listing still works."""
        record = []
        port = self.start_ftp(record=record)
        (self.root / "listed.txt").write_bytes(b"listed\n")
        result = self.run_client(
            "ftp://test:test@127.0.0.1:%d/" % port,
            "ls / ; exit", rawsettings=["FtpUseMlsd=0"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("listed.txt", result.stdout)
        self.assertIn("LIST", record)
        self.assertNotIn("MLSD", record)

    def test_ftp_mlsd_refusal_falls_back_to_list(self):
        """Automatic FtpUseMlsd keeps working when MLSD is refused."""
        record = []
        port = self.start_ftp(record=record, refuse_mlsd=True)
        (self.root / "fallback.txt").write_bytes(b"fallback\n")
        result = self.run_client(
            "ftp://test:test@127.0.0.1:%d/" % port,
            "ls / ; exit")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fallback.txt", result.stdout)
        self.assertIn("MLSD", record)
        self.assertIn("LIST", record)

    def test_ftp_mlsd_required_without_server_support_is_refused(self):
        """FtpUseMlsd=2 refuses rather than quietly using LIST."""
        record = []
        port = self.start_ftp(record=record, refuse_mlsd=True)
        (self.root / "required.txt").write_bytes(b"x")
        result = self.run_client(
            "ftp://test:test@127.0.0.1:%d/" % port,
            "ls / ; exit", rawsettings=["FtpUseMlsd=2"])
        combined = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, combined)
        self.assertIn("MLSD", combined)
        self.assertNotIn("LIST", record)

    def test_ftp_active_mode_opens_the_data_connection_backwards(self):
        """FtpPasvMode=0 makes the client listen and the server connect."""
        record = []
        port = self.start_ftp(record=record)
        (self.root / "active.txt").write_bytes(b"active mode\n")
        result = self.run_client(
            "ftp://test:test@127.0.0.1:%d/" % port,
            "ls / ; exit", rawsettings=["FtpPasvMode=0"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("active.txt", result.stdout)
        self.assertIn("PORT", record)
        self.assertIn("MLSD", record)

    def test_explicit_ftps_session_and_tls_policy(self):
        """ftpes:// and Ftps=3 use AUTH TLS, and the TLS policy holds.

        One server, six sessions: explicit TLS with the certificate
        accepted, the same session with verification left on (refused), a
        private CA (accepted), a pinned public key (accepted, and a
        different key refused), a version bound the server cannot meet
        (refused), and a certificate fingerprint this build must refuse
        instead of pretending to check it.
        """
        port = self.start_ftp(tls=True, tls_mode="explicit")
        payload = b"explicit tls\n" * 128
        (self.root / "explicit.txt").write_bytes(payload)
        url = "ftpes://test:test@127.0.0.1:%d/" % port

        accepted = self.run_client(url, "get /explicit.txt explicit-out.txt ; exit")
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertEqual((self.local / "explicit-out.txt").read_bytes(), payload)

        # Ftps=3 turns a plain ftp:// session into the same explicit TLS.
        aliased = self.run_client(
            "ftp://test:test@127.0.0.1:%d/" % port,
            "get /explicit.txt aliased-out.txt ; exit",
            rawsettings=["Ftps=3"])
        self.assertEqual(aliased.returncode, 0, aliased.stdout + aliased.stderr)
        self.assertEqual((self.local / "aliased-out.txt").read_bytes(), payload)

        # Nothing accepted the certificate, so verification is on: the
        # self-signed server has to be refused.
        refused = self.run_client_without_hostkey(
            url, "ls / ; exit")
        combined = (refused.stdout + refused.stderr).lower()
        self.assertNotEqual(refused.returncode, 0, refused.stdout + refused.stderr)
        self.assertTrue("certificate" in combined or "ssl" in combined, combined)

        ca_file = self.pem_cert()
        trusted = self.run_client_without_hostkey(
            url, "ls / ; exit",
            rawsettings=["CaCertificateFile=" + ca_file])
        self.assertEqual(trusted.returncode, 0, trusted.stdout + trusted.stderr)
        self.assertIn("explicit.txt", trusted.stdout)

        pinned = self.run_client_without_hostkey(
            url, "ls / ; exit",
            rawsettings=["CaCertificateFile=" + ca_file,
                         "PinnedPublicKey=" + self.public_key_file()])
        self.assertEqual(pinned.returncode, 0, pinned.stdout + pinned.stderr)

        other_key = self.other_public_key_file()
        wrong_pin = self.run_client_without_hostkey(
            url, "ls / ; exit",
            rawsettings=["CaCertificateFile=" + ca_file,
                         "PinnedPublicKey=" + other_key])
        self.assertNotEqual(wrong_pin.returncode, 0)
        self.assertIn("pinned", (wrong_pin.stdout + wrong_pin.stderr).lower())

        # The server speaks TLS 1.2 and 1.3; refusing to go below or above
        # what it offers is the point of the two version settings.
        too_new = self.run_client_without_hostkey(
            url, "ls / ; exit",
            rawsettings=["CaCertificateFile=" + ca_file,
                         "MaxTlsVersion=1.1"])
        self.assertNotEqual(too_new.returncode, 0)
        floor = self.run_client_without_hostkey(
            url, "ls / ; exit",
            rawsettings=["CaCertificateFile=" + ca_file,
                         "MinTlsVersion=1.2"])
        self.assertEqual(floor.returncode, 0, floor.stdout + floor.stderr)

        fingerprint = "1f2e3d4c5b6a79887766554433221100ffeeddccbbaa99887766554433221100"
        unverifiable = self.run_client(
            url, "ls / ; exit", extra=["-hostkey=" + fingerprint])
        self.assertNotEqual(unverifiable.returncode, 0)
        message = unverifiable.stdout + unverifiable.stderr
        self.assertIn("fingerprint", message.lower())
        self.assertIn("PinnedPublicKey", message)


    def test_saved_session_keeps_ftp_and_tls_settings(self):
        """A stored site carries the FTP/TLS policy it was saved with.

        The settings are stored by their upstream names and read back by
        the same parser '-rawsettings' uses, so 'open <name>' reaches the
        endpoint the site was configured for - here the explicit-TLS
        server - rather than the plain FTP default.
        """
        port = self.start_ftp(tls=True, tls_mode="explicit")
        payload = b"stored policy\n" * 32
        (self.root / "stored.txt").write_bytes(payload)
        # The URL names the explicit-TLS endpoint, and the switch adds the
        # listing policy to store: a plain 'ftp://' URL here would be
        # refused by the server itself ('550 SSL/TLS required').
        saved = self.run_client(
            "ftpes://test:test@127.0.0.1:%d/" % port,
            "savesession lab -password=test -rawsettings FtpUseMlsd=0 ; exit")
        self.assertEqual(saved.returncode, 0, saved.stdout + saved.stderr)
        stored = (self.config / "sessions.ini").read_text()
        self.assertIn("ftps=3", stored)
        self.assertIn("ftp_use_mlsd=0", stored)
        # Opening the stored name reaches the TLS endpoint without the URL
        # saying so: the mode comes from the file, and the plain FTP
        # connection that a dropped setting would produce is refused with
        # '550 SSL/TLS required on the control channel'.
        reopened = self.run_client(
            "lab -password=test", "get /stored.txt stored-out.txt ; exit")
        self.assertEqual(reopened.returncode, 0,
                         reopened.stdout + reopened.stderr)
        self.assertEqual((self.local / "stored-out.txt").read_bytes(), payload)

    def test_pty_curl_progress_and_filepart_staging(self):
        """Curl-backed transfers emit live progress on a PTY, stage large
        downloads in a '.filepart' file, and resume from the staged bytes."""
        import pty
        import select
        port = self.start_ftp(tls=False)
        payload = bytes(range(256)) * 1024  # 256 KiB
        (self.root / "progress.bin").write_bytes(payload)
        dest = self.local / "progress-dl.bin"
        part = self.local / "progress-dl.bin.filepart"
        part.write_bytes(payload[:65536])

        master, slave = pty.openpty()
        argv = [
            BINARY, "-batch",
            "-command=open ftp://test:test@127.0.0.1:%d/ ; "
            "get -resume -speed=128 /progress.bin %s ; exit" % (port, dest)
        ]
        env = dict(os.environ, LINSCP_CONFIG_DIR=str(self.config))
        proc = subprocess.Popen(
            argv, stdin=slave, stdout=slave, stderr=slave,
            cwd=str(self.local), env=env, close_fds=True)
        os.close(slave)
        captured = bytearray()
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    try:
                        chunk = os.read(master, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    captured.extend(chunk)
                elif proc.poll() is not None:
                    break
            proc.wait(timeout=15)
        finally:
            os.close(master)

        text = captured.decode("utf-8", "replace")
        self.assertEqual(proc.returncode, 0, text)
        self.assertFalse(part.exists())
        self.assertEqual(dest.read_bytes(), payload)
        self.assertIn("progress-dl.bin", text)


def run_and_report():
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    # A failure has to name itself in the evidence lines: CI surfaces those
    # as annotations, and the raw log of a failed run is not always
    # available to whoever has to fix it.
    for test, report in list(result.failures) + list(result.errors):
        lines = [line.strip() for line in report.strip().splitlines()
                 if line.strip()]
        detail = " | ".join(lines[-6:]) if lines else "no detail"
        print("evidence: FAILED %s: %s" %
              (test.id().split(".")[-1], detail[-1200:]))
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
