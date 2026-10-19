#!/usr/bin/env python3
"""Tests for the opt-in file-manager ("shell") integration of the GUI.

A right-click in a file manager must never send anything anywhere: the
definition only runs 'linscp-gui --shell-upload FILES...', which records
a validated, per-user manifest, and the page queues uploads only after
the user confirms against a session tab. These tests drive the
install/uninstall commands, the manifest functions, and the three HTTP
routes with a stub tab and a recording task manager, so no server or
file manager is needed.
"""

import http.server
import json
import os
import pathlib
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.error
import urllib.request
from unittest import mock

GUI_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GUI_DIR))
import linscp_gui as gui  # noqa: E402


class ShellEnvironment:
    """A throwaway home with a findable launcher, per test."""

    def __init__(self, test):
        self.temp = tempfile.TemporaryDirectory(prefix="linscp-shell-")
        root = pathlib.Path(self.temp.name)
        self.data = root / "data"
        self.config = root / "cfg" / "LinSCP"
        bindir = root / "bin"
        bindir.mkdir(parents=True)
        launcher = bindir / "linscp-gui"
        launcher.write_text("#!/bin/sh\nexit 0\n")
        os.chmod(launcher, 0o755)
        self.launcher = str(launcher)
        self.patch = mock.patch.dict(os.environ, {
            "HOME": str(root),
            "XDG_DATA_HOME": str(self.data),
            "LINSCP_CONFIG_DIR": str(self.config),
            "PATH": str(bindir) + os.pathsep + os.environ.get("PATH", ""),
        })
        self.patch.start()
        test.addCleanup(self.patch.stop)
        test.addCleanup(self.temp.cleanup)

    def workfile(self, name="report.txt", body=b"data"):
        path = pathlib.Path(self.temp.name) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return str(path)


class InstallTests(unittest.TestCase):
    def setUp(self):
        self.env = ShellEnvironment(self)

    def test_install_writes_one_definition_per_manager(self):
        results = dict((manager, outcome)
                       for manager, _p, outcome in gui.install_shell_integration())
        self.assertEqual(results["Dolphin (KDE)"], "installed")
        self.assertEqual(results["Files (GNOME)"], "installed")
        self.assertEqual(results["Nemo (Cinnamon)"], "installed")

        dolphin = (self.env.data / "kio" / "servicemenus" /
                   "linscp-upload.desktop").read_text()
        self.assertIn("Type=Service", dolphin)
        self.assertIn("Exec=%s --shell-upload %%F" % self.env.launcher, dolphin)
        nautilus = (self.env.data / "nautilus" / "scripts" / "LinSCP Upload")
        self.assertTrue(os.access(nautilus, os.X_OK))
        # The Nautilus script passes the selection as separate words.
        self.assertIn('exec "%s" --shell-upload "$@"' % self.env.launcher,
                      nautilus.read_text())
        nemo = (self.env.data / "nemo" / "actions" /
                "linscp-upload.nemo_action").read_text()
        self.assertIn("[Nemo Action]", nemo)
        self.assertIn("Quote=double", nemo)

        # No definition builds a command line a filename could break
        # out of: the only substitution is the whole-selection %F, and
        # nothing names a shell or carries a shell separator.
        for text in (dolphin, nemo, nautilus.read_text()):
            for line in text.splitlines():
                if line.startswith("Exec=") or line.startswith("exec "):
                    self.assertNotIn("sh -c", line)
                    self.assertNotIn("bash", line)
                    self.assertNotIn(";", line)
                    self.assertNotIn("&&", line)
                    self.assertNotIn("$(", line)
                    self.assertNotIn("`", line)

    def test_reinstall_updates_and_uninstall_removes_only_ours(self):
        gui.install_shell_integration()
        again = gui.install_shell_integration()
        self.assertTrue(all(outcome == "updated"
                            for _m, _p, outcome in again))
        # The user's own file at a path we would use is never touched.
        foreign = (self.env.data / "nemo" / "actions" /
                   "linscp-upload.nemo_action")
        foreign.write_text("[Nemo Action]\nName=mine\n")
        outcomes = dict((manager, outcome) for manager, _p, outcome
                        in gui.install_shell_integration())
        self.assertEqual(outcomes["Nemo (Cinnamon)"],
                         "kept (not written by LinSCP)")
        self.assertEqual(foreign.read_text(), "[Nemo Action]\nName=mine\n")

        removed = gui.uninstall_shell_integration()
        self.assertTrue(foreign.exists())
        self.assertFalse((self.env.data / "kio" / "servicemenus" /
                          "linscp-upload.desktop").exists())
        outcomes = dict((manager, outcome)
                        for manager, _p, outcome in removed)
        self.assertEqual(outcomes["Nemo (Cinnamon)"],
                         "kept (not written by LinSCP)")
        self.assertTrue(all(
            gui._shell_target_status(path) == "missing"
            for _m, path, _o in removed
            if pathlib.Path(path) != foreign))

    def test_a_launcher_path_a_shell_could_read_is_refused(self):
        bindir = pathlib.Path(self.env.temp.name) / 'bi"n'
        bindir.mkdir(parents=True)
        launcher = bindir / "linscp-gui"
        launcher.write_text("#!/bin/sh\n")
        os.chmod(launcher, 0o755)
        with mock.patch.dict(os.environ,
                             {"PATH": str(bindir)}):
            with self.assertRaises(ValueError) as caught:
                gui.install_shell_integration()
        self.assertIn("cannot be carried safely", str(caught.exception))

    def test_install_command_line(self):
        env = dict(os.environ)
        run = subprocess.run(
            [sys.executable, str(GUI_DIR / "linscp_gui.py"),
             "--install-shell-integration"],
            capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("(installed)", run.stdout)
        run = subprocess.run(
            [sys.executable, str(GUI_DIR / "linscp_gui.py"),
             "--uninstall-shell-integration"],
            capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("(removed)", run.stdout)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.env = ShellEnvironment(self)

    def test_record_list_and_dismiss_round_trip(self):
        one = self.env.workfile("one.txt")
        spaced = self.env.workfile("two words.bin")
        folder = pathlib.Path(self.env.temp.name) / "folder"
        folder.mkdir()
        (folder / "inner").write_text("x")
        manifest_id, files = gui.record_shell_upload(
            [one, spaced, str(folder), one])
        # Duplicates collapse; names with spaces are data, not syntax.
        self.assertEqual([f["name"] for f in files],
                         ["one.txt", "two words.bin", "folder"])
        pending = gui.list_shell_pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["id"], manifest_id)
        self.assertEqual(pending[0]["files"][1]["path"], spaced)

        directory = pathlib.Path(gui._shell_manifest_dir())
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        record = directory / (manifest_id + ".json")
        self.assertEqual(stat.S_IMODE(record.stat().st_mode), 0o600)

        self.assertTrue(gui.dismiss_shell_upload(manifest_id))
        self.assertFalse(gui.dismiss_shell_upload(manifest_id))
        self.assertEqual(gui.list_shell_pending(), [])

    def test_record_refusals(self):
        good = self.env.workfile()
        with self.assertRaises(ValueError):
            gui.record_shell_upload([])
        with self.assertRaises(ValueError):
            gui.record_shell_upload(["relative.txt"])
        with self.assertRaises(ValueError):
            gui.record_shell_upload([self.env.temp.name + "/missing"])
        with self.assertRaises(ValueError):
            gui.record_shell_upload([good + "\n"])
        with self.assertRaises(ValueError):
            gui.record_shell_upload([good] * (gui.SHELL_UPLOAD_MAX_FILES + 1))
        fifo = pathlib.Path(self.env.temp.name) / "pipe"
        os.mkfifo(str(fifo))
        with self.assertRaises(ValueError):
            gui.record_shell_upload([str(fifo)])
        self.assertEqual(gui.list_shell_pending(), [])

    def test_stale_and_foreign_manifests_are_ignored(self):
        manifest_id, _files = gui.record_shell_upload(
            [self.env.workfile()])
        record = pathlib.Path(gui._shell_manifest_path(manifest_id))
        data = json.loads(record.read_text())
        data["created"] = time.time() - gui.SHELL_MANIFEST_MAX_AGE - 1
        record.write_text(json.dumps(data))
        (pathlib.Path(gui._shell_manifest_dir()) / "notes.json").write_text(
            "{}")
        self.assertEqual(gui.list_shell_pending(), [])
        self.assertFalse(record.exists())

    def test_a_shell_upload_invocation_records_without_sending(self):
        target = self.env.workfile()
        # Hold the port so the GUI cannot start: the selection must
        # still be recorded and reported as waiting, not sent anywhere.
        with socket.socket() as hold:
            hold.bind(("127.0.0.1", 0))
            port = hold.getsockname()[1]
            run = subprocess.run(
                [sys.executable, str(GUI_DIR / "linscp_gui.py"),
                 "--port=%d" % port, "--shell-upload", target],
                capture_output=True, text=True, timeout=60,
                env=dict(os.environ,
                         LINSCP_CONFIG_DIR=str(self.env.config)))
        self.assertEqual(run.returncode, 1)
        self.assertIn("will offer to upload them", run.stdout)
        pending = gui.list_shell_pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["files"][0]["path"], target)

    def test_a_shell_upload_invocation_with_no_files_fails_fast(self):
        run = subprocess.run(
            [sys.executable, str(GUI_DIR / "linscp_gui.py"), "--shell-upload"],
            capture_output=True, text=True, timeout=60,
            env=dict(os.environ, LINSCP_CONFIG_DIR=str(self.env.config)))
        self.assertEqual(run.returncode, 2)
        self.assertIn("was given no files", run.stderr)


class RecordingTasks:
    def __init__(self):
        self.submitted = []

    def submit(self, kind, command, session, source, destination, tab_id,
               **kwargs):
        task = types.SimpleNamespace(bytes_total=None, command=command,
                                     source=source, destination=destination)
        self.submitted.append(task)
        return task


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.env = ShellEnvironment(self)
        self.tasks = RecordingTasks()
        self.tab = types.SimpleNamespace(
            id=1, connected=True, is_local=False, remote_dir="/srv/up",
            local_dir=self.env.temp.name, session={"host": "example"})
        self.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), gui.LinScpGuiHandler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        patchers = [
            mock.patch.object(gui, "API_TOKEN", "shell-test-token"),
            mock.patch.object(gui, "REQUIRE_TOKEN", True),
            mock.patch.object(gui, "ACCOUNTS_FILE", None),
            mock.patch.object(gui, "TASKS", self.tasks),
        ]
        for patcher in patchers:
            patcher.start()
            self.addCleanup(patcher.stop)
        self.saved_state = (gui.STATE["tabs"], gui.STATE["active_tab"])
        gui.STATE["tabs"] = [self.tab]
        gui.STATE["active_tab"] = 1
        self.addCleanup(self._restore_state)
        self.thread.start()
        self.addCleanup(self.server.shutdown)
        self.addCleanup(self.server.server_close)
        self.port = self.server.server_address[1]

    def _restore_state(self):
        gui.STATE["tabs"], gui.STATE["active_tab"] = self.saved_state

    def call(self, path, body=None, token="shell-test-token"):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        headers = {}
        data = None
        if token:
            headers["X-LSCP-Token"] = token
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers,
                                         method="POST" if body else "GET")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                return error.code, json.loads(raw)
            except ValueError:
                return error.code, {}

    def test_pending_consume_and_dismiss_over_http(self):
        status, body = self.call("/api/shell/pending")
        self.assertEqual((status, body["pending"]), (200, []))

        # The selection is only held until the page confirms it.
        status, body = self.call("/api/shell/pending", token=None)
        self.assertIn(status, (401, 403))

        first = self.env.workfile("a.txt", b"1234")
        gone = self.env.workfile("gone.txt")
        manifest_id, _files = gui.record_shell_upload([first, gone])
        status, body = self.call("/api/shell/pending")
        self.assertEqual([f["name"] for f in body["pending"][0]["files"]],
                         ["a.txt", "gone.txt"])
        self.assertEqual(self.tasks.submitted, [])

        os.unlink(gone)  # deleted between the right-click and the dialog
        status, body = self.call(
            "/api/shell/consume", {"id": manifest_id, "tab": 1})
        self.assertEqual(status, 200, body)
        self.assertEqual(body["queued"], ["a.txt"])
        self.assertEqual(body["missing"], ["gone.txt"])
        self.assertEqual(body["remote_dir"], "/srv/up")
        self.assertEqual(len(self.tasks.submitted), 1)
        task = self.tasks.submitted[0]
        self.assertIn("put", task.command)
        self.assertIn("a.txt", task.command)
        self.assertEqual(task.destination, "/srv/up/a.txt")
        self.assertEqual(task.bytes_total, 4)

        # A consumed selection is not offered twice.
        status, _body = self.call(
            "/api/shell/consume", {"id": manifest_id, "tab": 1})
        self.assertEqual(status, 400)
        status, body = self.call("/api/shell/pending")
        self.assertEqual(body["pending"], [])

        manifest_id, _files = gui.record_shell_upload([first])
        status, _body = self.call("/api/shell/dismiss", {"id": manifest_id})
        self.assertEqual(status, 200)
        self.assertEqual(gui.list_shell_pending(), [])

    def test_consume_refusals(self):
        manifest_id, _files = gui.record_shell_upload(
            [self.env.workfile()])
        # A path-shaped id is refused before anything touches a file.
        status, _body = self.call(
            "/api/shell/consume", {"id": "../" + manifest_id, "tab": 1})
        self.assertEqual(status, 400)
        # A local-only tab cannot receive an upload.
        self.tab.is_local = True
        status, body = self.call(
            "/api/shell/consume", {"id": manifest_id, "tab": 1})
        self.assertEqual(status, 400)
        self.assertIn("session tab", body["error"])
        self.assertEqual(self.tasks.submitted, [])
        # The selection survived both refusals and can still be sent.
        self.tab.is_local = False
        status, body = self.call(
            "/api/shell/consume", {"id": manifest_id, "tab": 1})
        self.assertEqual(status, 200, body)
        self.assertEqual(len(self.tasks.submitted), 1)

    def test_page_offers_pending_selections(self):
        page = (GUI_DIR / "web" / "index.html").read_text()
        self.assertIn('id="shellUploadModal"', page)
        self.assertIn("/api/shell/pending", page)
        self.assertIn("/api/shell/consume", page)
        self.assertIn("checkShellPending();", page)
        # The dialog lists names as text, never as markup.
        self.assertIn("escapeHtml(file.name", page)


if __name__ == "__main__":
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite([
        loader.loadTestsFromTestCase(InstallTests),
        loader.loadTestsFromTestCase(ManifestTests),
        loader.loadTestsFromTestCase(RouteTests)])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=gui-shell platform=linux ran=%d skipped=%d failed=%d" %
          (result.testsRun, len(result.skipped), failed))
    sys.exit(0 if result.wasSuccessful() else 1)
