#!/usr/bin/env python3
"""Tests for Linux desktop scheme-handler startup URLs."""

import pathlib
import sys
import tempfile
import threading
import time
import types
import unittest

GUI_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GUI_DIR))
import linscp_gui as gui  # noqa: E402


class DesktopUriTests(unittest.TestCase):
    def test_nonstandard_linux_prefix_finds_its_own_core_binary(self):
        # The CMake install prefix is arbitrary; an /usr/bin binary from an
        # older .deb must never override this GUI's sibling prefix/bin.
        with tempfile.TemporaryDirectory(prefix="linscp-prefix-") as temp:
            prefix = pathlib.Path(temp)
            module_dir = prefix / "share" / "linscp" / "gui"
            module_dir.mkdir(parents=True)
            binary = prefix / "bin" / "linscp"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\necho prefix-binary\n")
            binary.chmod(0o755)
            old_base = gui.BASE_DIR
            gui.BASE_DIR = str(module_dir)
            try:
                self.assertEqual(gui.find_linscp_binary(), str(binary))
            finally:
                gui.BASE_DIR = old_base

    def test_sftp_url_parses_credentials_ipv6_port_and_remote_path(self):
        session = gui.parse_desktop_site_url(
            "sftp://alice:p%40ss@[2001:db8::4]:2202/etc/my%20files")
        self.assertEqual(session["protocol"], "sftp")
        self.assertEqual(session["username"], "alice")
        self.assertEqual(session["password"], "p@ss")
        self.assertEqual(session["host"], "2001:db8::4")
        self.assertEqual(session["port"], 2202)
        self.assertEqual(session["initial_dir"], "/etc/my files")
        self.assertEqual(gui.session_url(session, session["initial_dir"],
                                         include_password=True),
                         "sftp://alice:p%40ss@[2001:db8::4]:2202/etc/my%20files")
        # By default the password stays out of the URL: a URL on a command
        # line is visible in the process list, so the core reads the
        # password from the environment instead.
        self.assertEqual(gui.session_url(session, session["initial_dir"]),
                         "sftp://alice@[2001:db8::4]:2202/etc/my%20files")

    def test_ftp_and_ftps_default_ports(self):
        ftp = gui.parse_desktop_site_url("ftp://files.example.org/pub")
        ftps = gui.parse_desktop_site_url("ftps://files.example.org/pub")
        self.assertEqual((ftp["protocol"], ftp["port"]), ("ftp", 21))
        self.assertEqual((ftps["protocol"], ftps["port"]), ("ftps", 990))
        self.assertEqual(ftp["initial_dir"], "/pub")

    def test_session_url_writes_the_port_the_protocol_does_not_imply(self):
        # The port used to be written whenever it was not 22, whatever the
        # protocol: an SFTP site on port 21 reached the server only because
        # 21 is not 22, and an FTP site on port 22 reached port 21 only
        # because 22 was dropped. The protocol decides which port is implied.
        def url(protocol, port):
            session = gui.new_session()
            session.update({"protocol": protocol, "host": "h",
                            "username": "u", "port": port})
            return gui.session_url(session)
        self.assertEqual(url("sftp", 22), "sftp://u@h/")
        self.assertEqual(url("sftp", 2222), "sftp://u@h:2222/")
        self.assertEqual(url("sftp", 21), "sftp://u@h:21/")
        self.assertEqual(url("ftp", 21), "ftp://u@h/")
        self.assertEqual(url("ftp", 2121), "ftp://u@h:2121/")
        self.assertEqual(url("ftps", 990), "ftps://u@h/")
        self.assertEqual(url("dav", 80), "dav://u@h/")
        self.assertEqual(url("webdav", 443), "webdav://u@h/")
        self.assertEqual(url("s3", 443), "s3://u@h/")
        self.assertEqual(url("s3", 9000), "s3://u@h:9000/")
        self.assertEqual(url("ftp", 0), "ftp://u@h/")

    def test_stored_sites_without_a_port_take_the_port_of_their_protocol(self):
        # Earlier versions wrote port=22 for every protocol the site manager
        # offered, so a sessions.ini may hold an FTP site on 'port 22'. It
        # is read as the FTP port, as the console client reads it; a real
        # port is kept, and so is the SSH port of an SSH protocol.
        with tempfile.TemporaryDirectory(prefix="linscp-sessions-") as temp:
            path = pathlib.Path(temp) / "sessions.ini"
            path.write_text(
                "[legacy-ftp]\nprotocol=ftp\nhost=h\nport=22\n\n"
                "[no-port]\nprotocol=s3\nhost=h\n\n"
                "[real-port]\nprotocol=ftp\nhost=h\nport=2121\n\n"
                "[ssh]\nprotocol=sftp\nhost=h\nport=22\n\n"
                "[dav-https]\nprotocol=webdav\nhost=h\nport=22\n",
                encoding="utf-8")
            old = dict(gui.os.environ)
            gui.os.environ["LINSCP_CONFIG_DIR"] = temp
            try:
                ports = {item["name"]: item["port"]
                         for item in gui.read_stored_sessions()}
            finally:
                gui.os.environ.clear()
                gui.os.environ.update(old)
        self.assertEqual(ports, {"legacy-ftp": 21, "no-port": 443,
                                 "real-port": 2121, "ssh": 22,
                                 "dav-https": 443})

    def test_bad_or_unsupported_site_urls_are_refused(self):
        for uri in (
                "https://example.org/",
                "sftp:///missing-host",
                "sftp://host:0/",
                "sftp://host:65536/",
                "sftp://host/%zz",
                "sftp://host/path?query=1",
                "sftp://host/path#fragment"):
            with self.subTest(uri=uri):
                with self.assertRaises(ValueError):
                    gui.parse_desktop_site_url(uri)

    def test_desktop_launch_creates_and_activates_a_site_tab(self):
        connected = threading.Event()

        class FakeCoreSession:
            def __init__(self, tab_id, session):
                self.id = tab_id
                self.session = dict(session)
                self.name = "desktop-site"
                self.observed_hostkey = ""

            def connect(self):
                connected.set()
                return True, ""

        old = (gui.CoreSession, gui.STATE["tabs"], gui.STATE["active_tab"],
               gui.STATE["next_tab"])
        gui.CoreSession = FakeCoreSession
        gui.STATE["tabs"] = []
        gui.STATE["active_tab"] = None
        gui.STATE["next_tab"] = 1
        try:
            session = gui.parse_desktop_site_url("sftp://user@localhost/home")
            tab = gui.open_desktop_site(session)
            self.assertTrue(connected.wait(2))
            self.assertEqual(tab.id, 1)
            self.assertEqual(gui.STATE["active_tab"], 1)
            self.assertEqual(gui.STATE["tabs"], [tab])
        finally:
            gui.CoreSession, gui.STATE["tabs"], gui.STATE["active_tab"], \
                gui.STATE["next_tab"] = old

    def test_unknown_host_key_stays_pending_for_the_verification_ui(self):
        observed = threading.Event()

        class FakeCoreSession:
            def __init__(self, tab_id, session):
                self.id = tab_id
                self.session = dict(session)
                self.name = "unverified-site"
                self.observed_hostkey = ""

            def connect(self):
                self.observed_hostkey = "ssh-ed25519 255 SHA256:test"
                observed.set()
                return False, "Unknown host key"

        old = (gui.CoreSession, gui.STATE["tabs"], gui.STATE["active_tab"],
               gui.STATE["next_tab"], gui.STATE["challenges"])
        gui.CoreSession = FakeCoreSession
        gui.STATE["tabs"] = []
        gui.STATE["active_tab"] = None
        gui.STATE["next_tab"] = 1
        gui.STATE["challenges"] = {}
        try:
            session = gui.parse_desktop_site_url("sftp://user@localhost/")
            tab = gui.open_desktop_site(session)
            self.assertTrue(observed.wait(2))
            for _ in range(100):
                if gui.STATE["challenges"].get(tab.id) is tab:
                    break
                time.sleep(0.01)
            self.assertIs(gui.STATE["challenges"].get(tab.id), tab)
            self.assertEqual(tab.observed_hostkey, "ssh-ed25519 255 SHA256:test")
        finally:
            gui.CoreSession, gui.STATE["tabs"], gui.STATE["active_tab"], \
                gui.STATE["next_tab"], gui.STATE["challenges"] = old


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DesktopUriTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=gui-desktop-uri platform=linux ran=%d skipped=%d failed=%d" %
          (result.testsRun, len(result.skipped), failed))
    sys.exit(0 if result.wasSuccessful() else 1)
