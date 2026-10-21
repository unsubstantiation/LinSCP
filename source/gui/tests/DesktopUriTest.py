#!/usr/bin/env python3
"""Tests for the Linux desktop integration of the GUI.

Two things a desktop does to this client: hand it a site URL through a scheme
handler, and decide whether a window can be shown at all - which on a Wayland
session is a different question from the one X11 answers.
"""

import os
import pathlib
import stat
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.parse
from unittest import mock

GUI_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GUI_DIR))
import linscp_gui as gui  # noqa: E402


def write_executable(path, body="#!/bin/sh\nexit 0\n"):
    """An executable file, so that a launcher lookup finds what it names."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC | stat.S_IXGRP)


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
        # 'ftpes://' is FTP with explicit TLS, upstream's other spelling:
        # the scheme survives the round trip and its port is FTP's 21.
        explicit = gui.parse_desktop_site_url(
            "ftpes://alice@files.example.org:2121/pub")
        self.assertEqual((explicit["protocol"], explicit["port"]),
                         ("ftpes", 2121))
        self.assertEqual(explicit["initial_dir"], "/pub")
        self.assertEqual(gui.session_url(explicit, explicit["initial_dir"]),
                         "ftpes://alice@files.example.org:2121/pub")
        default = gui.parse_desktop_site_url("ftpes://files.example.org/")
        self.assertEqual((default["protocol"], default["port"]), ("ftpes", 21))
        # new_session() names the default user, which the URL then carries.
        self.assertEqual(gui.session_url(default),
                         "ftpes://user@files.example.org/")

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


class DesktopSessionTests(unittest.TestCase):
    """Which display server this is, and how a window is asked for."""

    def wayland_environment(self, directory, name="wayland-0"):
        """An environment whose runtime directory holds a compositor socket."""
        socket = os.path.join(directory, name)
        with open(socket, "wb"):
            pass
        return {"XDG_RUNTIME_DIR": directory}, socket

    def test_a_wayland_session_is_found_by_its_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            environment, _socket = self.wayland_environment(directory)
            self.assertEqual(gui.detect_desktop_session(environment),
                             (True, False, "wayland-0"))
            self.assertTrue(gui.has_desktop_session(environment))

    def test_an_exported_socket_name_is_used_as_it_stands(self):
        with tempfile.TemporaryDirectory() as directory:
            environment, _socket = self.wayland_environment(
                directory, name="wayland-2")
            environment["WAYLAND_DISPLAY"] = "wayland-2"
            wayland, x11, inferred = gui.detect_desktop_session(environment)
            self.assertTrue(wayland)
            self.assertFalse(x11)
            # Nothing to add to a child: the environment says it already.
            self.assertEqual(inferred, "")

    def test_an_absolute_socket_path_is_honoured(self):
        # A compositor socket handed out by a container or a service manager
        # can be named by path, which libwayland accepts in the variable.
        with tempfile.TemporaryDirectory() as directory:
            _environment, socket = self.wayland_environment(directory)
            wayland, _x11, _inferred = gui.detect_desktop_session(
                {"WAYLAND_DISPLAY": socket})
            self.assertTrue(wayland)

    def test_a_variable_without_its_directory_names_no_session(self):
        # WAYLAND_DISPLAY with no XDG_RUNTIME_DIR is a compositor no client can
        # reach: the runtime directory is the only place a socket is looked for.
        wayland, _x11, _inferred = gui.detect_desktop_session(
            {"WAYLAND_DISPLAY": "wayland-0"})
        self.assertFalse(wayland)
        self.assertFalse(gui.has_desktop_session({"WAYLAND_DISPLAY": "wayland-0"}))

    def test_x11_is_taken_from_the_display_variable_alone(self):
        # $DISPLAY may name a forwarded server on another machine, where this
        # process could not find a socket and the display still is there.
        environment = {"DISPLAY": "localhost:10.0"}
        self.assertEqual(gui.detect_desktop_session(environment),
                         (False, True, ""))
        self.assertTrue(gui.has_desktop_session(environment))

    def test_a_headless_environment_reports_no_session(self):
        self.assertEqual(gui.detect_desktop_session({}), (False, False, ""))
        self.assertFalse(gui.has_desktop_session({}))

    def test_an_absent_compositor_socket_is_no_session(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                gui.detect_desktop_session({"XDG_RUNTIME_DIR": directory}),
                (False, False, ""))

    def test_a_wayland_session_with_xwayland_reports_both(self):
        # A session that exports both can show either kind of window, and the
        # name is already there for a child to find.
        with tempfile.TemporaryDirectory() as directory:
            environment, _socket = self.wayland_environment(directory)
            environment["DISPLAY"] = ":0"
            environment["WAYLAND_DISPLAY"] = "wayland-0"
            self.assertEqual(gui.detect_desktop_session(environment),
                             (True, True, ""))

    def test_the_users_own_browser_is_asked_first(self):
        # $BROWSER is the variable that says which browser a user means, it
        # holds a colon-separated list, and a program in it may want the URL
        # where its %s is. Only the first entry is a browser.
        with tempfile.TemporaryDirectory() as directory:
            firefox = os.path.join(directory, "firefox")
            write_executable(firefox)
            fallback = os.path.join(directory, "epiphany")
            write_executable(fallback)
            environment = {"PATH": directory}
            self.assertEqual(
                gui.browser_open_command(
                    "http://localhost:8080/",
                    dict(environment, BROWSER=fallback + " --private-window")),
                [fallback, "--private-window", "http://localhost:8080/"])
            # An entry whose program is missing is passed over, because the
            # variable is a preference list and not a single command.
            self.assertEqual(
                gui.browser_open_command(
                    "http://localhost:8080/",
                    dict(environment, BROWSER="no-such-browser:%s" % fallback)),
                [fallback, "http://localhost:8080/"])
            self.assertEqual(
                gui.browser_open_command(
                    "http://localhost:8080/",
                    dict(environment, BROWSER=firefox + " --app=%s")),
                [firefox, "--app=http://localhost:8080/"])

    def test_a_browser_that_is_not_there_falls_back_to_the_desktop(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = os.path.join(directory, "xdg-open")
            write_executable(launcher)
            self.assertEqual(
                gui.browser_open_command("http://localhost:8080/",
                                         {"PATH": directory,
                                          "BROWSER": "no-such-browser-here"}),
                [launcher, "http://localhost:8080/"])

    def test_the_desktop_uri_launcher_is_the_way_that_needs_no_x11(self):
        # xdg-open is the freedesktop launcher, and on a sandboxed or Wayland
        # session it hands the request to the portal. gio is the same from GLib.
        with tempfile.TemporaryDirectory() as directory:
            xdg = os.path.join(directory, "xdg-open")
            write_executable(xdg)
            self.assertEqual(gui.browser_open_command("http://l/", {"PATH": directory}),
                             [xdg, "http://l/"])
            os.remove(xdg)
            write_executable(os.path.join(directory, "gio"))
            self.assertEqual(gui.browser_open_command("http://l/", {"PATH": directory}),
                             ["gio", "open", "http://l/"])

    def test_no_launcher_is_reported_rather_than_guessed(self):
        # Naming a browser of its own is how a launcher overrides the user, so
        # the answer to 'no launcher' is the address and the reason.
        with tempfile.TemporaryDirectory() as directory:
            self.assertIsNone(gui.browser_open_command("http://l/",
                                                       {"PATH": directory}))

    def test_the_address_opened_carries_the_bound_name(self):
        # The server answers a Host header naming loopback or --host=; a URL
        # with any other name would be refused by the server that just opened
        # it, which is how a window ends up showing 'connection refused'.
        for host, name in (("127.0.0.1", "127.0.0.1"),
                           ("localhost", "localhost"),
                           ("::1", "::1"),
                           ("10.0.0.5", "10.0.0.5"),
                           ("fe80::1", "fe80::1"),
                           ("Files.Example.ORG", "files.example.org"),
                           ("0.0.0.0", "localhost"),
                           ("::", "localhost"),
                           ("", "localhost")):
            url = gui.browser_url_for(host, 8080)
            self.assertEqual(urllib.parse.urlparse(url).hostname, name, host)
            self.assertTrue(url.endswith(":8080/"), url)

    def test_no_window_is_requested_without_a_session(self):
        with tempfile.TemporaryDirectory() as directory:
            write_executable(os.path.join(directory, "xdg-open"))
            with mock.patch.object(gui.subprocess, "Popen") as popened:
                reason = gui.open_in_browser("http://localhost:8080/",
                                             {"PATH": directory})
            self.assertIn("no desktop session", reason)
            popened.assert_not_called()

    def test_the_launcher_is_started_detached_and_quiet(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = os.path.join(directory, "xdg-open")
            write_executable(launcher)
            environment = {"PATH": directory, "DISPLAY": ":0"}
            with mock.patch.object(gui.subprocess, "Popen") as popened:
                reason = gui.open_in_browser("http://localhost:8080/",
                                             environment)
            self.assertEqual(reason, "")
            argv = popened.call_args[0][0]
            self.assertEqual(argv, [launcher, "http://localhost:8080/"])
            self.assertTrue(popened.call_args[1]["start_new_session"])
            # The API token of the run never reaches a command line, where any
            # process listing on the machine would show it.
            self.assertNotIn("token", " ".join(argv))

    def test_a_found_compositor_is_handed_to_the_child(self):
        # The child looks the socket up by name, and a name the environment
        # does not carry has to be exported for it.
        with tempfile.TemporaryDirectory() as directory:
            environment, _socket = self.wayland_environment(directory)
            environment["PATH"] = directory
            write_executable(os.path.join(directory, "xdg-open"))
            with mock.patch.object(gui.subprocess, "Popen") as popened:
                self.assertEqual(gui.open_in_browser("http://l/", environment), "")
            self.assertEqual(
                popened.call_args[1]["env"].get("WAYLAND_DISPLAY"), "wayland-0")

    def test_a_launcher_that_cannot_be_started_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = os.path.join(directory, "xdg-open")
            write_executable(launcher)
            with mock.patch.object(gui.subprocess, "Popen",
                                   side_effect=OSError("no such file")):
                reason = gui.open_in_browser("http://l/",
                                             {"PATH": directory,
                                              "DISPLAY": ":0"})
            self.assertIn("xdg-open", reason)
            self.assertIn("no such file", reason)

    def test_the_launcher_receives_the_server_address_after_it_listens(self):
        # main() opens the browser only once the port is bound: a launcher told
        # about the address first would open an error page.
        source = (GUI_DIR / "linscp_gui.py").read_text()
        bound = source.index("bound_port = httpd.server_address[1]")
        opened = source.index("reason = open_in_browser(")
        self.assertLess(bound, opened)
        self.assertLess(opened, source.index("httpd.serve_forever()"))



if __name__ == "__main__":
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite([loader.loadTestsFromTestCase(DesktopUriTests),
                                loader.loadTestsFromTestCase(DesktopSessionTests)])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=gui-desktop-uri platform=linux ran=%d skipped=%d failed=%d" %
          (result.testsRun, len(result.skipped), failed))
    sys.exit(0 if result.wasSuccessful() else 1)
