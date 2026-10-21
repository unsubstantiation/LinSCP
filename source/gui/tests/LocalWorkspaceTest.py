#!/usr/bin/env python3
"""Tests for the two local panes and for named workspaces.

The local-to-local mode is a tab whose two directories are on this machine:
there is no server, no core process and no credentials. The workspace store
is the named group of tabs that reopens them in order. Both are exercised
against the HTTP server and, where a queue cannot be driven deterministically
over HTTP, against the functions the queue calls.
"""

import base64
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request
import uuid

GUI_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GUI_DIR))
import linscp_gui as gui  # noqa: E402


def _wait_for(predicate, timeout=15.0, interval=0.05):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


class GuiServer(object):
    """A real GUI server on a kernel-chosen port, with a private config."""

    def __init__(self, config_dir):
        self.config_dir = config_dir
        environment = dict(os.environ)
        environment["LINSCP_CONFIG_DIR"] = config_dir
        environment["PYTHONPATH"] = str(GUI_DIR)
        # The binary does not exist: a local tab must not need it, and a
        # test that accidentally starts one would fail rather than connect.
        environment["LINSCP_BIN"] = os.path.join(config_dir, "missing-linscp")
        self.process = subprocess.Popen(
            [sys.executable, str(GUI_DIR / "linscp_gui.py"),
             "--host=127.0.0.1", "--port=0", "--print-token"],
            cwd=str(GUI_DIR), env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.output = []
        self.reader = threading.Thread(target=self._collect, daemon=True)
        self.reader.start()
        self.port = None
        self.token = None
        deadline = time.time() + 45
        while time.time() < deadline and not (self.port and self.token):
            if self.process.poll() is not None:
                break
            for line in list(self.output):
                match = re.search(r"http://[^/]*?(?::)(\d+)/", line)
                if match and self.port is None:
                    self.port = int(match.group(1))
                if line.startswith("Token: ") and self.token is None:
                    self.token = line.split(":", 1)[1].strip()
            time.sleep(0.05)
        if not self.port or not self.token:
            self.stop()
            raise unittest.SkipTest(
                "the GUI server did not report its address: %s"
                % " | ".join(self.output[-6:]))

    def _collect(self):
        try:
            for line in self.process.stdout:
                self.output.append(line.rstrip("\n"))
        except (OSError, ValueError):
            pass

    @property
    def base(self):
        return "http://127.0.0.1:%d" % self.port

    def request(self, path, body=None, method=None, raw=None, headers=None):
        data = None
        request_headers = {"X-LSCP-Token": self.token}
        if raw is not None:
            data = raw
            request_headers["Content-Type"] = "application/octet-stream"
        elif body is not None:
            data = json.dumps(body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(
            self.base + path, data=data, method=method or
            ("POST" if data is not None else "GET"), headers=request_headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(
                    response.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                payload = {}
            return exc.code, payload

    def get(self, path):
        return self.request(path)

    def post(self, path, body=None):
        return self.request(path, body if body is not None else {})

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        self.reader.join(timeout=2)
        if self.process.stdout:
            self.process.stdout.close()


class GuiApiBase(object):
    @classmethod
    def setUpClass(cls):
        cls.config_dir = tempfile.mkdtemp(prefix="linscp-local-ws-")
        cls.server = GuiServer(cls.config_dir)
        cls.opened = []

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        shutil.rmtree(cls.config_dir, ignore_errors=True)

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="linscp-panes-")
        self.left = os.path.join(self.root, "left")
        self.right = os.path.join(self.root, "right")
        os.makedirs(self.left)
        os.makedirs(self.right)
        self.tabs = []

    def tearDown(self):
        for tab_id in self.tabs:
            try:
                self.server.post("/api/tabs/close", {"tab": tab_id})
            except Exception:
                pass
        shutil.rmtree(self.root, ignore_errors=True)

    def open_local(self, name=None):
        status, payload = self.server.post("/api/tabs/open", {
            "session": {"protocol": "local", "local_dir": self.left,
                        "other_local_dir": self.right},
            "name": name or "local-%s" % uuid.uuid4().hex[:8]})
        self.assertEqual(status, 200, payload)
        tab = payload["tab"]
        self.tabs.append(tab["id"])
        return tab

    def wait_task(self, source, timeout=20.0):
        def finished():
            status, payload = self.server.get("/api/transfers")
            if status != 200:
                return None
            for task in payload.get("transfers", []):
                if task.get("source") == source and task.get("status") in (
                        "Completed", "Failed", "Cancelled"):
                    return task
            return None
        task = _wait_for(finished, timeout=timeout)
        self.assertIsNotNone(task, "the queued task did not finish")
        return task

class LocalPanesTests(GuiApiBase, unittest.TestCase):
    def test_a_local_tab_opens_two_independent_panes_without_a_core(self):
        tab = self.open_local()
        self.assertTrue(tab["is_local"])
        self.assertTrue(tab["connected"])
        self.assertEqual(tab["local_dir"], os.path.abspath(self.left))
        self.assertEqual(tab["other_local_dir"], os.path.abspath(self.right))
        self.assertEqual(tab["session"].get("host"), "")
        self.assertEqual(tab["session"].get("username"), "")
        # Secrets are not in the description at all, not even blank.
        self.assertNotIn("password", tab["session"])
        status, listing = self.server.get(
            "/api/local/list?tab=%s" % tab["id"])
        self.assertEqual(status, 200, listing)
        self.assertEqual(listing["path"], os.path.abspath(self.left))
        status, listing = self.server.get(
            "/api/remote/list?tab=%s" % tab["id"])
        self.assertEqual(status, 200, listing)
        self.assertEqual(listing["path"], os.path.abspath(self.right))
        self.assertEqual(listing["entries"], [])

    def test_a_local_tab_is_created_without_starting_a_process(self):
        session = dict(gui.new_session())
        session.update({"protocol": "local", "local_dir": self.left,
                        "other_local_dir": self.right})
        with mock.patch.object(gui.subprocess, "Popen") as popen:
            tab = gui.CoreSession(9001, session)
            ok, error = tab.connect()
        self.assertEqual((ok, error), (True, ""))
        popen.assert_not_called()
        self.assertIsNone(tab.proc)
        self.assertTrue(tab.is_local)
        self.assertEqual(tab.remote_dir, os.path.abspath(self.right))
        self.assertIn("left", tab.name)
        self.assertIn("right", tab.name)

    def test_recursive_copy_preserves_tree_metadata_and_symlinks(self):
        source = os.path.join(self.left, "tree")
        os.makedirs(os.path.join(source, "sub"))
        with open(os.path.join(source, "a.txt"), "w") as handle:
            handle.write("alpha")
        with open(os.path.join(source, "sub", "b.bin"), "wb") as handle:
            handle.write(b"\x00\x01" * 500)
        os.symlink("../a.txt", os.path.join(source, "sub", "link"))
        os.utime(source, (1_600_000_000, 1_600_000_000))
        tab = self.open_local()
        status, payload = self.server.post("/api/transfer/upload", {
            "tab": tab["id"], "names": ["tree"]})
        self.assertEqual(status, 200, payload)
        task = self.wait_task(source)
        self.assertEqual(task["status"], "Completed", task)
        self.assertEqual(task["bytes_done"], task["bytes_total"])
        destination = os.path.join(self.right, "tree")
        self.assertEqual(open(os.path.join(destination, "a.txt")).read(),
                         "alpha")
        self.assertEqual(open(os.path.join(destination, "sub", "b.bin"),
                              "rb").read(), b"\x00\x01" * 500)
        link = os.path.join(destination, "sub", "link")
        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.readlink(link), "../a.txt")
        self.assertEqual(int(os.stat(destination).st_mtime), 1_600_000_000)

    def test_overwrite_ask_reports_conflicts_then_overwrite_replaces(self):
        with open(os.path.join(self.left, "same.txt"), "w") as handle:
            handle.write("new")
        with open(os.path.join(self.right, "same.txt"), "w") as handle:
            handle.write("old")
        tab = self.open_local()
        status, payload = self.server.post("/api/transfer/upload", {
            "tab": tab["id"], "names": ["same.txt"]})
        self.assertEqual(status, 409, payload)
        self.assertEqual(payload["conflicts"], ["same.txt"])
        self.assertEqual(open(os.path.join(self.right, "same.txt")).read(),
                         "old")
        status, payload = self.server.post("/api/transfer/upload", {
            "tab": tab["id"], "names": ["same.txt"],
            "overwrite": "overwrite"})
        self.assertEqual(status, 200, payload)
        task = self.wait_task(os.path.join(self.left, "same.txt"))
        self.assertEqual(task["status"], "Completed", task)
        self.assertEqual(open(os.path.join(self.right, "same.txt")).read(),
                         "new")

    def test_skip_and_rename_are_distinct_overwrite_decisions(self):
        with open(os.path.join(self.left, "same.txt"), "w") as handle:
            handle.write("new")
        with open(os.path.join(self.right, "same.txt"), "w") as handle:
            handle.write("old")
        tab = self.open_local()
        status, payload = self.server.post("/api/transfer/upload", {
            "tab": tab["id"], "names": ["same.txt"], "overwrite": "skip"})
        self.assertEqual(status, 200, payload)
        task = self.wait_task(os.path.join(self.left, "same.txt"))
        self.assertEqual(task["status"], "Completed", task)
        self.assertEqual(open(os.path.join(self.right, "same.txt")).read(),
                         "old")
        status, payload = self.server.post("/api/transfer/upload", {
            "tab": tab["id"], "names": ["same.txt"], "overwrite": "rename"})
        self.assertEqual(status, 200, payload)
        self.assertTrue(_wait_for(
            lambda: os.path.exists(os.path.join(self.right, "same (2).txt"))))
        self.assertEqual(open(os.path.join(self.right, "same.txt")).read(),
                         "old")
        self.assertEqual(open(os.path.join(self.right,
                                           "same (2).txt")).read(), "new")

    def test_move_removes_the_source_only_after_a_complete_copy(self):
        source = os.path.join(self.left, "folder")
        os.makedirs(os.path.join(source, "nested"))
        with open(os.path.join(source, "nested", "f.txt"), "w") as handle:
            handle.write("move me")
        tab = self.open_local()
        status, payload = self.server.post("/api/transfer/move", {
            "tab": tab["id"], "direction": "upload", "names": ["folder"]})
        self.assertEqual(status, 200, payload)
        task = self.wait_task(source)
        self.assertEqual(task["status"], "Completed", task)
        self.assertFalse(os.path.exists(source))
        self.assertEqual(open(os.path.join(self.right, "folder", "nested",
                                           "f.txt")).read(), "move me")

    def test_source_and_destination_overlap_is_refused_before_queueing(self):
        os.makedirs(os.path.join(self.left, "nested"))
        status, payload = self.server.post("/api/tabs/open", {
            "session": {"protocol": "local", "local_dir": self.left,
                        "other_local_dir": os.path.join(self.left, "nested")},
            "name": "overlap"})
        self.assertEqual(status, 200, payload)
        tab = payload["tab"]
        self.tabs.append(tab["id"])
        status, payload = self.server.post("/api/transfer/upload", {
            "tab": tab["id"], "names": ["nested"]})
        self.assertEqual(status, 400, payload)
        self.assertTrue("inside the source" in payload["error"] or
                        "same path" in payload["error"], payload["error"])
        status, payload = self.server.post("/api/transfer/download", {
            "tab": tab["id"], "names": [".."]})
        self.assertEqual(status, 400, payload)

    def test_second_local_pane_supports_crud_properties_and_checksums(self):
        tab = self.open_local()
        status, payload = self.server.post("/api/remote/mkdir", {
            "tab": tab["id"], "name": "made"})
        self.assertEqual(status, 200, payload)
        self.assertTrue(os.path.isdir(os.path.join(self.right, "made")))
        with open(os.path.join(self.right, "made", "file.txt"), "w") as handle:
            handle.write("checksum me")
        status, payload = self.server.post("/api/remote/rename", {
            "tab": tab["id"], "old_name": "made", "new_name": "renamed"})
        self.assertEqual(status, 200, payload)
        self.assertTrue(os.path.isdir(os.path.join(self.right, "renamed")))
        status, payload = self.server.post("/api/remote/chmod", {
            "tab": tab["id"], "name": "renamed",
            "permissions": "u=rwx,go=rx"})
        self.assertEqual(status, 200, payload)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(
            self.right, "renamed")).st_mode), 0o755)
        status, payload = self.server.post("/api/remote/properties", {
            "tab": tab["id"], "name": "renamed/file.txt"})
        self.assertEqual(status, 400, payload)
        status, payload = self.server.post("/api/remote/properties", {
            "tab": tab["id"], "name": "file.txt"})
        self.assertEqual(status, 400, payload)
        # The panel resolves one entry; a nested name is not one entry.
        os.rename(os.path.join(self.right, "renamed", "file.txt"),
                  os.path.join(self.right, "file.txt"))
        status, payload = self.server.post("/api/remote/properties", {
            "tab": tab["id"], "name": "file.txt"})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["attributes"]["size"], len("checksum me"))
        status, payload = self.server.post("/api/remote/checksum", {
            "tab": tab["id"], "algorithm": "sha-256", "names": ["file.txt"]})
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"][0]["checksum"]), 64)
        status, payload = self.server.post("/api/remote/search", {
            "tab": tab["id"], "path": self.right, "pattern": "file.txt",
            "case_sensitive": True})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["matches"][0]["name"], "file.txt")
        status, payload = self.server.post("/api/remote/delete", {
            "tab": tab["id"], "names": [{"name": "file.txt",
                                         "is_dir": False}]})
        self.assertEqual(status, 200, payload)
        self.assertFalse(os.path.exists(os.path.join(self.right, "file.txt")))

    def test_second_local_pane_editor_reads_and_saves_with_conflict_check(self):
        target = os.path.join(self.right, "edit.txt")
        with open(target, "w") as handle:
            handle.write("one")
        tab = self.open_local()
        status, payload = self.server.get(
            "/api/remote/edit?tab=%s&path=%s" % (tab["id"], target))
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["content"], "one")
        status, payload = self.server.post("/api/remote/save", {
            "tab": tab["id"], "path": target, "content": "two",
            "base_mtime_ns": payload["info"]["mtime_ns"]})
        self.assertEqual(status, 200, payload)
        self.assertEqual(open(target).read(), "two")
        path = os.path.join(self.right, "stale.txt")
        with open(path, "w") as handle:
            handle.write("original")
        status, payload = self.server.get(
            "/api/remote/edit?tab=%s&path=%s" % (tab["id"], path))
        base = payload["info"]["mtime_ns"]
        time.sleep(0.01)
        with open(path, "w") as handle:
            handle.write("changed elsewhere")
        status, payload = self.server.post("/api/remote/save", {
            "tab": tab["id"], "path": path, "content": "lost",
            "base_mtime_ns": base})
        self.assertEqual(status, 400, payload)
        self.assertEqual(open(path).read(), "changed elsewhere")

    def test_browser_drops_land_in_the_second_local_pane(self):
        tab = self.open_local()
        status, payload = self.server.post("/api/transfer/drop-dir", {
            "tab": tab["id"], "remote_dir": self.right,
            "relative_path": "dropped/empty"})
        self.assertEqual(status, 200, payload)
        self.assertTrue(os.path.isdir(os.path.join(
            self.right, "dropped", "empty")))
        status, payload = self.server.request(
            "/api/transfer/drop?tab=%s&name=drop.txt&remote_dir=%s"
            "&relative_path=drop.txt" % (tab["id"], self.right),
            raw=b"browser bytes")
        self.assertEqual(status, 200, payload)
        self.assertEqual(open(os.path.join(self.right, "drop.txt"), "rb").read(),
                         b"browser bytes")

    def test_the_queue_reports_bytes_and_a_cancel_leaves_no_partial_file(self):
        source = os.path.join(self.left, "big.bin")
        with open(source, "wb") as handle:
            handle.write(b"x" * (3 * 1024 * 1024))
        tab = self.open_local()
        task = gui.Task(7001, "Copy (local)", "", {}, source,
                        os.path.join(self.right, "big.bin"),
                        tab["id"], native=lambda entry: None,
                        local_source=source,
                        local_target=os.path.join(self.right, "big.bin"),
                        local_policy="overwrite",
                        local_root=os.path.abspath(self.right))
        task.status = "Cancelling"
        with self.assertRaises(gui.LocalTransferCancelled):
            gui.local_copy_task(task)
        self.assertEqual(task.bytes_done, 0)
        self.assertFalse(os.path.exists(os.path.join(self.right, "big.bin")))
        self.assertEqual([name for name in os.listdir(self.right)
                          if name.startswith(".linscp-part-")], [])
        # A completed direct run reports its byte count for the queue.
        task.status = "Running"
        task.bytes_done = 0
        task.skipped = 0
        gui.local_copy_task(task)
        self.assertEqual(task.bytes_done, 3 * 1024 * 1024)
        self.assertEqual(task.bytes_total, 3 * 1024 * 1024)


class WorkspaceApiTests(GuiApiBase, unittest.TestCase):
    def open_named_local(self, name, left, right):
        return self.open_local(name)

    def test_workspace_round_trip_preserves_order_active_tab_and_panes(self):
        first = self.open_local("first")
        os.makedirs(os.path.join(self.left, "one"))
        os.makedirs(os.path.join(self.right, "two"))
        second = self.open_local("second")
        self.server.post("/api/tabs/select", {"tab": second["id"]})
        status, payload = self.server.post("/api/workspaces/save",
                                           {"name": "work"})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["workspace"]["tab_count"], 2)
        self.assertEqual(payload["workspace"]["active"], 1)
        for tab in (first, second):
            self.server.post("/api/tabs/close", {"tab": tab["id"]})
            self.tabs.remove(tab["id"])
        status, payload = self.server.get("/api/workspaces")
        self.assertEqual(status, 200, payload)
        listed = [item for item in payload["workspaces"]
                  if item["name"] == "work"]
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0]["tab_count"], 2)
        self.assertEqual([tab["name"] for tab in listed[0]["tabs"]],
                         ["first", "second"])
        status, payload = self.server.post("/api/workspaces/open",
                                           {"name": "work"})
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["opened"]), 2)
        self.assertEqual(payload["failed"], [])
        self.assertEqual(payload["active_tab"], payload["opened"][1])
        status, status_payload = self.server.get("/api/status")
        self.assertEqual(status, 200, status_payload)
        self.assertEqual(status_payload["active_tab"], payload["opened"][1])
        self.assertEqual([tab["id"] for tab in status_payload["tabs"]
                          if tab["is_local"]][-2:], payload["opened"])
        # Restored panes are the directories that were open, not the defaults.
        for tab in status_payload["tabs"]:
            if tab["id"] in payload["opened"]:
                self.assertEqual(tab["local_dir"], os.path.abspath(self.left))
                self.assertEqual(tab["other_local_dir"],
                                 os.path.abspath(self.right))
                self.tabs.append(tab["id"])
        status, payload = self.server.post("/api/workspaces/delete",
                                           {"name": "work"})
        self.assertEqual(status, 200, payload)

    def test_a_local_site_is_saved_without_the_console_client(self):
        path = os.path.join(self.config_dir, "sessions.ini")
        remote_block = ("[keep me]\nprotocol=sftp\nhost=example.test\n"
                        "password=lscp1$unchanged\n")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(remote_block)
        status, payload = self.server.post("/api/sessions/save", {
            "name": "pairs/local", "session": {
                "protocol": "local", "local_dir": self.left,
                "other_local_dir": self.right}})
        self.assertEqual(status, 200, payload)
        sessions = payload["sessions"]
        saved = next(item for item in sessions if item["name"] == "pairs/local")
        self.assertEqual(saved["protocol"], "local")
        self.assertEqual(saved["local_dir"], os.path.abspath(self.left))
        self.assertEqual(saved["other_local_dir"], os.path.abspath(self.right))
        text = open(path, encoding="utf-8").read()
        self.assertIn(remote_block.splitlines()[1], text)
        self.assertIn("password=lscp1$unchanged", text)
        # A panel that saves the site again does not lose its second pane.
        status, payload = self.server.post("/api/sessions/save", {
            "name": "pairs/local", "session": {
                "protocol": "local", "local_dir": self.left,
                "other_local_dir": self.right}})
        self.assertEqual(status, 200, payload)
        text = open(path, encoding="utf-8").read()
        self.assertEqual(text.count("[pairs/local]"), 1)

    def test_a_duplicate_workspace_needs_explicit_overwrite(self):
        self.open_local()
        status, payload = self.server.post("/api/workspaces/save",
                                           {"name": "dupe"})
        self.assertEqual(status, 200, payload)
        status, payload = self.server.post("/api/workspaces/save",
                                           {"name": "dupe"})
        self.assertEqual(status, 409, payload)
        self.assertTrue(payload.get("exists"))
        status, payload = self.server.post("/api/workspaces/save",
                                           {"name": "dupe",
                                            "overwrite": True})
        self.assertEqual(status, 200, payload)

    def test_a_failed_tab_does_not_stop_the_rest_of_the_workspace(self):
        self.open_local()
        path = os.path.join(self.config_dir, "workspaces.json")
        with open(path, "r", encoding="utf-8") as handle:
            store = json.load(handle)
        store["workspaces"]["partial"] = {
            "active": 1,
            "updated": int(time.time()),
            "tabs": [
                {"kind": "local", "name": "present",
                 "local_dir": self.left, "other_local_dir": self.right},
                {"kind": "remote", "name": "gone", "site": "Deleted Site",
                 "local_dir": self.left, "remote_dir": "/"},
            ],
        }
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(store, handle)
        status, payload = self.server.post("/api/workspaces/open",
                                           {"name": "partial"})
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["opened"]), 1)
        self.assertEqual(len(payload["failed"]), 1)
        self.assertEqual(payload["failed"][0]["name"], "gone")
        self.assertIn("Deleted Site", payload["failed"][0]["error"])
        self.tabs.append(payload["opened"][0])

    def test_the_workspace_file_is_private_and_contains_no_credentials(self):
        session = dict(gui.new_session())
        session.update({"protocol": "sftp", "host": "example.test",
                        "username": "user", "password": "top-secret",
                        "tunnel_password": "tunnel-secret",
                        "tunnel_passphrase": "passphrase",
                        "site": "live-site", "local_dir": self.left,
                        "initial_dir": "/home"})
        tab = gui.CoreSession(7100, session)
        with gui.STATE_LOCK:
            old_tabs = gui.STATE["tabs"]
            old_active = gui.STATE["active_tab"]
            gui.STATE["tabs"] = [tab]
            gui.STATE["active_tab"] = tab.id
        old_config = os.environ.get("LINSCP_CONFIG_DIR")
        os.environ["LINSCP_CONFIG_DIR"] = self.config_dir
        try:
            gui.save_workspace("secret-workspace", overwrite=True)
        finally:
            if old_config is None:
                os.environ.pop("LINSCP_CONFIG_DIR", None)
            else:
                os.environ["LINSCP_CONFIG_DIR"] = old_config
            with gui.STATE_LOCK:
                gui.STATE["tabs"] = old_tabs
                gui.STATE["active_tab"] = old_active
        path = os.path.join(self.config_dir, "workspaces.json")
        text = open(path, encoding="utf-8").read()
        for secret in ("top-secret", "tunnel-secret", "passphrase"):
            self.assertNotIn(secret, text)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertNotIn("live-site", text)
        self.assertIn("example.test", text)


class WorkspaceFunctionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="linscp-ws-fn-")
        self.previous = os.environ.get("LINSCP_CONFIG_DIR")
        os.environ["LINSCP_CONFIG_DIR"] = self.directory
        self.left = os.path.join(self.directory, "left")
        self.right = os.path.join(self.directory, "right")
        os.makedirs(self.left)
        os.makedirs(self.right)

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("LINSCP_CONFIG_DIR", None)
        else:
            os.environ["LINSCP_CONFIG_DIR"] = self.previous
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_a_deleted_site_is_resolved_from_sessions_ini_every_time(self):
        with open(gui.session_store_path(), "w", encoding="utf-8") as handle:
            handle.write("[live]\nprotocol=sftp\nhost=example.test\n"
                         "username=user\npassword=plain-secret\n"
                         "local_directory=%s\n" % self.left)
        stored = {item["name"]: item for item in gui.read_stored_sessions()}
        snapshot = {"kind": "remote", "name": "tab", "site": "live",
                    "local_dir": self.left, "remote_dir": "/data"}
        session, site, error = gui._workspace_tab_session(snapshot, stored)
        self.assertEqual((site, error), ("live", ""))
        self.assertEqual(session["password"], "plain-secret")
        self.assertEqual(session["initial_dir"], "/data")
        # The password is in sessions.ini only: the workspace record has no
        # secret for the restore to cache or leak.
        self.assertNotIn("password", gui._workspace_session_snapshot(session))
        session, site, error = gui._workspace_tab_session(
            dict(snapshot, site="deleted"), stored)
        self.assertIsNone(session)
        self.assertIn("deleted", error)

    def test_a_workspace_survives_a_restart_and_key_policies_are_kept(self):
        with open(gui.session_store_path(), "w", encoding="utf-8") as handle:
            handle.write("[pinned]\nprotocol=sftp\nhost=example.test\n"
                         "hostkey=ssh-ed25519 AAAA\n")
        stored = {item["name"]: item for item in gui.read_stored_sessions()}
        snapshot = {"kind": "remote", "name": "tab", "site": "pinned",
                    "local_dir": self.left, "remote_dir": "/"}
        session, _, error = gui._workspace_tab_session(snapshot, stored)
        self.assertEqual(error, "")
        self.assertEqual(session["hostkey"], "ssh-ed25519 AAAA")
        # A fresh read of the file is what a restarted process sees.
        self.assertEqual(gui.read_stored_sessions()[0]["hostkey"],
                         "ssh-ed25519 AAAA")

    def test_an_invalid_workspace_name_and_store_are_refused(self):
        for name in ("", " ", "../escape", "a/b", "a" * 129, "bad\nname"):
            with self.assertRaises(ValueError, msg=repr(name)):
                gui.validate_workspace_name(name)
        with open(os.path.join(self.directory, "workspaces.json"), "w") as handle:
            handle.write("{not json")
        with self.assertRaises(ValueError):
            gui.list_workspaces()


class BookmarkTests(GuiApiBase, unittest.TestCase):
    """Directory bookmarks: a name and a directory, never a credential."""

    def bookmark_file(self):
        return os.path.join(self.config_dir, "bookmarks.json")

    def test_a_bookmark_is_saved_privately_and_replaced_by_name(self):
        self.open_local()
        name = "home-%s" % uuid.uuid4().hex[:8]
        status, payload = self.server.post("/api/bookmarks/save", {
            "side": "local", "name": name, "path": self.left})
        self.assertEqual(status, 200, payload)
        path = self.bookmark_file()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        text = open(path, encoding="utf-8").read()
        self.assertIn(name, text)
        self.assertNotIn("password", text.lower())
        # The same name updates the directory instead of adding a second row.
        status, payload = self.server.post("/api/bookmarks/save", {
            "side": "local", "name": name, "path": self.right})
        self.assertEqual(status, 200, payload)
        status, payload = self.server.get("/api/bookmarks?side=local")
        self.assertEqual(status, 200, payload)
        matching = [item for item in payload["bookmarks"]
                    if item["name"] == name]
        self.assertEqual(len(matching), 1, payload)
        self.assertEqual(matching[0]["path"], os.path.abspath(self.right))
        # A remote bookmark is a path, not a file and not a session.
        status, payload = self.server.post("/api/bookmarks/save", {
            "side": "remote", "name": name, "path": "/var/log"})
        self.assertEqual(status, 200, payload)
        status, payload = self.server.get("/api/bookmarks")
        self.assertEqual(status, 200, payload)
        self.assertEqual([item["name"] for item in payload["bookmarks"]["remote"]
                          if item["name"] == name], [name])
        status, payload = self.server.post("/api/bookmarks/delete", {
            "side": "local", "name": name})
        self.assertEqual(status, 200, payload)
        status, payload = self.server.get("/api/bookmarks?side=local")
        self.assertNotIn(name, [item["name"] for item in payload["bookmarks"]])
        status, payload = self.server.post("/api/bookmarks/delete", {
            "side": "local", "name": name})
        self.assertEqual(status, 400, payload)

    def test_a_bookmark_rejects_controls_relative_remote_paths_and_bad_sides(self):
        invalid = [
            {"side": "sideways", "name": "x", "path": self.left},
            {"side": "local", "name": "", "path": self.left},
            {"side": "local", "name": "bad\nname", "path": self.left},
            {"side": "local", "name": "x" * 129, "path": self.left},
            {"side": "local", "name": "x", "path": self.left + "\n"},
            {"side": "remote", "name": "x", "path": "relative/path"},
            {"side": "remote", "name": "x", "path": ""},
        ]
        for body in invalid:
            status, payload = self.server.post("/api/bookmarks/save", body)
            self.assertEqual(status, 400, (body, payload))
        status, payload = self.server.get("/api/bookmarks?side=sideways")
        self.assertEqual(status, 400, payload)

    def test_a_hand_edited_bookmark_file_cannot_hide_good_entries(self):
        name = "kept-%s" % uuid.uuid4().hex[:8]
        with open(self.bookmark_file(), "w", encoding="utf-8") as handle:
            json.dump({"version": 1, "bookmarks": {
                "local": [
                    {"name": name, "path": self.left},
                    {"name": "bad", "path": "/tmp/\n"},
                    {"name": name, "path": self.right},
                    "not a record",
                ],
                "remote": "not a list",
            }}, handle)
        status, payload = self.server.get("/api/bookmarks?side=local")
        self.assertEqual(status, 200, payload)
        self.assertEqual([item["name"] for item in payload["bookmarks"]],
                         [name])
        self.assertEqual(payload["bookmarks"][0]["path"], self.left)


class SessionUrlTests(GuiApiBase, unittest.TestCase):
    def test_generate_url_leaves_the_password_out_unless_asked(self):
        class Tab(object):
            is_local = False
            remote_dir = "/data"
            session = {"protocol": "sftp", "host": "example.test", "port": 22,
                       "username": "user", "password": "p@ss word",
                       "initial_dir": "/"}
        result = gui.generate_session_url(Tab(), False)
        self.assertNotIn("p%40ss", result["url"])
        self.assertNotIn("p@ss", result["url"])
        self.assertFalse(result["include_password"])
        self.assertTrue(result["has_password"])
        self.assertEqual(result["url"], "sftp://user@example.test/data")
        self.assertEqual(result["open_command"],
                         "open sftp://user@example.test/data")
        result = gui.generate_session_url(Tab(), True)
        self.assertIn("user:p%40ss%20word@example.test", result["url"])
        self.assertTrue(result["include_password"])
        # A local tab is not a session and has no URL to hand out.
        class LocalTab(object):
            is_local = True
            remote_dir = "/"
            session = {}
        with self.assertRaises(ValueError):
            gui.generate_session_url(LocalTab(), False)

    def test_explicit_and_implicit_ftps_have_their_own_schemes(self):
        class Tab(object):
            is_local = False
            remote_dir = "/"
            session = {"protocol": "ftpes", "host": "ftp.example.test",
                       "port": 21, "username": "user", "password": ""}
        result = gui.generate_session_url(Tab(), False)
        self.assertEqual(result["url"], "ftpes://user@ftp.example.test/")
        Tab.session = {"protocol": "ftps", "host": "ftp.example.test",
                       "port": 990, "username": "user", "password": ""}
        result = gui.generate_session_url(Tab(), False)
        self.assertEqual(result["url"], "ftps://user@ftp.example.test/")
        # A stored site is upstream's shape: protocol=ftp with a mode.
        self.assertEqual(gui.session_protocol_name("ftp", 3), "ftpes")
        self.assertEqual(gui.session_protocol_name("ftp", 1), "ftps")
        self.assertEqual(gui.session_protocol_name("ftp", 0), "ftp")
        block = "\n".join(gui._session_ini_block({
            "name": "explicit", "protocol": "ftpes", "host": "h",
            "port": 21, "username": "u", "password": "",
            "keyfile": "", "remote_dir": "/", "local_dir": ""}, "/tmp/x.ini"))
        self.assertIn("protocol=ftp", block)
        self.assertIn("ftps=3", block)
        self.assertNotIn("protocol=ftpes", block)

    def test_a_local_tab_api_call_is_refused(self):
        tab = self.open_local()
        status, payload = self.server.get(
            "/api/session/url?tab=%s&password=1" % tab["id"])
        self.assertEqual(status, 400, payload)
        self.assertIn("local", payload["error"].lower())


class SessionProtocolTests(unittest.TestCase):
    """How a stored site spells its TLS mode.

    The console client keeps upstream's shape in sessions.ini - protocol=ftp
    with a separate ftps mode - so the Commander has to translate between
    that and the ftps:// (implicit) / ftpes:// (explicit) schemes the site
    form and the generated URL use.
    """

    def _saved_command(self, session):
        with mock.patch.object(gui, "run_linscp",
                               return_value=(0, "", "")) as run:
            ok, message = gui.save_stored_session("site", session)
        self.assertEqual((ok, message), (True, ""))
        return run.call_args[0][0]

    def test_an_explicit_tls_site_is_written_as_ftp_with_a_mode(self):
        command = self._saved_command({
            "protocol": "ftpes", "host": "ftp.example.test", "port": 21,
            "username": "user"})
        self.assertIn("-protocol=ftp", command)
        self.assertNotIn("ftpes", command)
        self.assertIn("Ftps=3", command)
        # A TLS-only session must not acquire a tunnel it never had.
        self.assertNotIn("Tunnel=", command)

    def test_an_implicit_tls_site_keeps_its_scheme(self):
        command = self._saved_command({
            "protocol": "ftps", "host": "ftp.example.test", "port": 990,
            "username": "user"})
        self.assertIn("-protocol=ftps", command)
        self.assertIn("Ftps=1", command)

    def test_a_plain_session_gains_no_tls_setting(self):
        command = self._saved_command({
            "protocol": "ftp", "host": "ftp.example.test", "port": 21,
            "username": "user"})
        self.assertIn("-protocol=ftp", command)
        self.assertNotIn("Ftps=", command)
        self.assertNotIn("-rawsettings", command)


class SessionImportTests(GuiApiBase, unittest.TestCase):
    def openssh_config(self, wildcard=True):
        path = os.path.join(self.root, "ssh_config")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(
                "# an OpenSSH client configuration\n"
                "Host alpha\n"
                "    HostName alpha.example.test\n"
                "    User deploy\n"
                "    Port 2222\n"
                "    IdentityFile ~/.ssh/id_alpha\n"
                "Host beta gamma\n"
                "    HostName ignored.example.test\n"
                "Include ~/.ssh/other\n")
        return path

    def test_openssh_import_creates_sites_and_reports_skipped_blocks(self):
        path = self.openssh_config()
        # Keep a section this import does not own.
        sessions_path = os.path.join(self.config_dir, "sessions.ini")
        with open(sessions_path, "w", encoding="utf-8") as handle:
            handle.write("# keep this comment\n[keep me]\nprotocol=sftp\n"
                         "host=keep.example.test\n")
        status, payload = self.server.get(
            "/api/sessions/import?source=openssh&path=" +
            urllib.parse.quote(path))
        self.assertEqual(status, 200, payload)
        record = payload["sources"][0]
        self.assertTrue(record["exists"])
        self.assertEqual([entry["name"] for entry in record["entries"]],
                         ["alpha"])
        self.assertTrue(any("plain alias" in item["reason"]
                            for item in record["skipped"]))
        self.assertTrue(any("Included files" in item["reason"]
                            for item in record["skipped"]))
        status, payload = self.server.post("/api/sessions/import", {
            "source": "openssh", "path": path, "names": ["alpha"]})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["imported"], ["alpha"])
        names = [item["name"] for item in payload["sessions"]]
        self.assertIn("alpha", names)
        self.assertIn("keep me", names)
        alpha = next(item for item in payload["sessions"]
                     if item["name"] == "alpha")
        self.assertEqual(alpha["host"], "alpha.example.test")
        self.assertEqual(alpha["port"], 2222)
        self.assertEqual(alpha["username"], "deploy")
        self.assertTrue(alpha["keyfile"].endswith(".ssh/id_alpha"))
        stored = open(sessions_path, encoding="utf-8").read()
        self.assertIn("# keep this comment", stored)
        self.assertIn("host=keep.example.test", stored)
        # A second import does not silently replace the site.
        status, payload = self.server.post("/api/sessions/import", {
            "source": "openssh", "path": path, "names": ["alpha"]})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["imported"], [])
        self.assertTrue(any(item["name"] == "alpha"
                            for item in payload["skipped"]))
        # ... until it is asked to.
        status, payload = self.server.post("/api/sessions/import", {
            "source": "openssh", "path": path, "names": ["alpha"],
            "overwrite": True})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["imported"], ["alpha"])

    def filezilla_xml(self, password="filezilla-secret"):
        encoded = base64.b64encode(password.encode("utf-8")).decode("ascii")
        return (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            "<FileZilla3><Servers><Server>"
            "<Host>fz.example.test</Host><Port>2222</Port>"
            "<Protocol>1</Protocol><Type>0</Type>"
            "<User>deploy</User><Pass>%s</Pass>"
            "<Keyfile>/home/user/.ssh/id_fz</Keyfile>"
            "<RemoteDir>/srv/data</RemoteDir>"
            "</Server><Server>"
            "<Host>ftps.example.test</Host><Port>21</Port>"
            "<Protocol>3</Protocol><User>deploy</User>"
            "</Server></Servers></FileZilla3>" % encoded)

    def test_filezilla_import_encrypts_passwords_and_reports_ftps(self):
        path = os.path.join(self.root, "sitemanager.xml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(self.filezilla_xml())
        status, payload = self.server.get(
            "/api/sessions/import?source=filezilla&path=" +
            urllib.parse.quote(path))
        self.assertEqual(status, 200, payload)
        record = payload["sources"][0]
        self.assertEqual([entry["name"] for entry in record["entries"]],
                         ["fz.example.test", "ftps.example.test"])
        self.assertEqual([entry["protocol"] for entry in record["entries"]],
                         ["sftp", "ftpes"])
        self.assertTrue(record["entries"][0]["has_password"])
        self.assertNotIn("filezilla-secret",
                         json.dumps(record))
        status, payload = self.server.post("/api/sessions/import", {
            "source": "filezilla", "path": path})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["imported"],
                         ["fz.example.test", "ftps.example.test"])
        sessions_path = os.path.join(self.config_dir, "sessions.ini")
        text = open(sessions_path, encoding="utf-8").read()
        self.assertIn("password=lscp1$", text)
        self.assertNotIn("filezilla-secret", text)
        self.assertIn("ftps=3", text)
        key_path = os.path.join(self.config_dir, "sessions.key")
        self.assertEqual(stat.S_IMODE(os.stat(key_path).st_mode), 0o600)
        status, listing = self.server.get("/api/sessions")
        self.assertEqual(status, 200, listing)
        stored = next(item for item in listing["sessions"]
                      if item["name"] == "fz.example.test")
        self.assertEqual(stored["password"], "filezilla-secret")
        self.assertEqual(stored["initial_dir"], "/srv/data")
        explicit = next(item for item in listing["sessions"]
                        if item["name"] == "ftps.example.test")
        self.assertEqual(explicit["protocol"], "ftpes")
        self.assertEqual(explicit["port"], 21)

    def test_dangerous_or_malformed_xml_is_refused(self):
        doctype = os.path.join(self.root, "doctype.xml")
        with open(doctype, "w", encoding="utf-8") as handle:
            handle.write('<?xml version="1.0"?>\n'
                         '<!DOCTYPE x [<!ENTITY y "z">]><FileZilla3/>')
        status, payload = self.server.post("/api/sessions/import", {
            "source": "filezilla", "path": doctype})
        self.assertEqual(status, 400, payload)
        self.assertIn("DOCTYPE", payload["error"])
        broken = os.path.join(self.root, "broken.xml")
        with open(broken, "w", encoding="utf-8") as handle:
            handle.write("<FileZilla3><Servers>")
        status, payload = self.server.get(
            "/api/sessions/import?source=filezilla&path=" +
            urllib.parse.quote(broken))
        self.assertEqual(status, 200, payload)
        self.assertIn("not valid XML", payload["sources"][0]["error"])




class PreferenceFunctionTests(unittest.TestCase):
    """The defaults a transfer and a confirmation start from."""

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="linscp-prefs-")
        self.previous = os.environ.get("LINSCP_CONFIG_DIR")
        os.environ["LINSCP_CONFIG_DIR"] = self.directory

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("LINSCP_CONFIG_DIR", None)
        else:
            os.environ["LINSCP_CONFIG_DIR"] = self.previous
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_the_defaults_are_used_until_something_is_saved(self):
        self.assertEqual(gui.read_preferences(), gui.PREFERENCE_DEFAULTS)
        self.assertTrue(gui.read_preferences()["confirm_overwrite"])

    def test_a_saved_preference_round_trips_and_is_private(self):
        values = dict(gui.PREFERENCE_DEFAULTS, transfer="binary", speed=64,
                      confirm_delete=False)
        stored = gui.write_preferences(values)
        self.assertEqual(stored, values)
        self.assertEqual(gui.read_preferences(), values)
        path = gui.preferences_path()
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        # The temporary file an atomic write needs is gone once it lands.
        self.assertEqual([name for name in os.listdir(self.directory)
                          if ".tmp-" in name], [])

    def test_an_unknown_key_or_a_wrong_type_is_refused(self):
        for bad in ({"nope": 1}, {"speed": "fast"}, {"speed": True},
                    {"speed": -1}, {"speed": 100000001}, {"resume": "yes"},
                    {"transfer": "text"}, {"filemask": "a" * 1025},
                    {"filemask": "a\nb"}, {"resumesupport": "sometimes"},
                    {"filemask": 7}):
            values = dict(gui.PREFERENCE_DEFAULTS)
            values.update(bad)
            with self.assertRaises(ValueError, msg=repr(bad)):
                gui.write_preferences(values)
        self.assertFalse(os.path.exists(gui.preferences_path()))

    def test_a_hand_edited_file_falls_back_per_key(self):
        with open(gui.preferences_path(), "w", encoding="utf-8") as handle:
            json.dump({"speed": 32, "transfer": "text", "unknown": 1,
                       "resume": "no"}, handle)
        preferences = gui.read_preferences()
        self.assertEqual(preferences["speed"], 32)
        self.assertEqual(preferences["transfer"],
                         gui.PREFERENCE_DEFAULTS["transfer"])
        self.assertTrue(preferences["resume"])
        self.assertEqual(set(preferences), set(gui.PREFERENCE_DEFAULTS))

    def test_an_unreadable_file_does_not_stop_the_client(self):
        with open(gui.preferences_path(), "w", encoding="utf-8") as handle:
            handle.write("{not json")
        self.assertEqual(gui.read_preferences(), gui.PREFERENCE_DEFAULTS)
        with open(gui.preferences_path(), "w", encoding="utf-8") as handle:
            handle.write("[]")
        self.assertEqual(gui.read_preferences(), gui.PREFERENCE_DEFAULTS)


class PreferenceApiTests(GuiApiBase, unittest.TestCase):
    def test_the_api_serves_saves_and_resets_the_preferences(self):
        status, payload = self.server.get("/api/preferences")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["preferences"], gui.PREFERENCE_DEFAULTS)
        self.assertTrue(payload["file"].endswith("preferences.json"))
        values = dict(gui.PREFERENCE_DEFAULTS, transfer="binary", speed=16,
                      confirm_overwrite=False)
        status, payload = self.server.post(
            "/api/preferences", {"action": "save", "preferences": values})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["preferences"]["transfer"], "binary")
        path = os.path.join(self.config_dir, "preferences.json")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        status, payload = self.server.get("/api/preferences")
        self.assertFalse(payload["preferences"]["confirm_overwrite"])
        status, payload = self.server.post(
            "/api/preferences", {"action": "save",
                                 "preferences": {"nope": 1}})
        self.assertEqual(status, 400, payload)
        self.assertIn("not known", payload["error"])
        status, payload = self.server.post("/api/preferences",
                                           {"action": "save"})
        self.assertEqual(status, 400, payload)
        status, payload = self.server.post("/api/preferences",
                                           {"action": "reset"})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["preferences"], gui.PREFERENCE_DEFAULTS)


class CleanupFunctionTests(unittest.TestCase):
    """Removing stored data, one named location at a time."""

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="linscp-cleanup-")
        self.previous = os.environ.get("LINSCP_CONFIG_DIR")
        os.environ["LINSCP_CONFIG_DIR"] = self.directory
        with open(os.path.join(self.directory, "sessions.ini"), "w",
                  encoding="utf-8") as handle:
            handle.write("[site]\nhost=h\n")
        with open(os.path.join(self.directory, "bookmarks.json"), "w",
                  encoding="utf-8") as handle:
            handle.write('{"version": 1}')
        with open(os.path.join(self.directory, "keep.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("not ours\n")

    def tearDown(self):
        if self.previous is None:
            os.environ.pop("LINSCP_CONFIG_DIR", None)
        else:
            os.environ["LINSCP_CONFIG_DIR"] = self.previous
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_every_stored_location_is_listed_by_name(self):
        locations = {item["id"]: item for item in gui.cleanup_locations()}
        for expected in ("sessions", "passwords", "hostkeys", "workspaces",
                         "bookmarks", "commands", "preferences", "shell",
                         "editing"):
            self.assertIn(expected, locations)
        self.assertTrue(locations["sessions"]["exists"])
        self.assertTrue(locations["bookmarks"]["exists"])
        self.assertFalse(locations["hostkeys"]["exists"])
        self.assertEqual(locations["passwords"]["path"],
                         os.path.join(self.directory, "sessions.key"))
        self.assertEqual(locations["hostkeys"]["path"],
                         os.path.join(self.directory, "sshhostkeys"))

    def test_only_the_selected_location_is_removed(self):
        results = gui.cleanup_data(["sessions"])
        self.assertTrue(results[0]["removed"])
        self.assertEqual(results[0]["error"], "")
        self.assertFalse(os.path.exists(os.path.join(self.directory,
                                                     "sessions.ini")))
        self.assertTrue(os.path.exists(os.path.join(self.directory,
                                                    "bookmarks.json")))
        self.assertTrue(os.path.exists(os.path.join(self.directory,
                                                    "keep.txt")))

    def test_an_unknown_id_and_an_empty_list_are_refused(self):
        with self.assertRaises(ValueError):
            gui.cleanup_data([])
        with self.assertRaises(ValueError):
            gui.cleanup_data(["../../etc/passwd"])
        with self.assertRaises(ValueError):
            gui.cleanup_data([self.directory])
        self.assertTrue(os.path.isdir(self.directory))
        self.assertTrue(os.path.exists(os.path.join(self.directory,
                                                    "sessions.ini")))

    def test_removing_something_twice_is_not_an_error(self):
        gui.cleanup_data(["bookmarks"])
        results = gui.cleanup_data(["bookmarks"])
        self.assertFalse(results[0]["removed"])
        self.assertEqual(results[0]["error"], "")


class CleanupApiTests(GuiApiBase, unittest.TestCase):
    def test_the_api_removes_only_confirmed_locations(self):
        sessions = os.path.join(self.config_dir, "sessions.ini")
        with open(sessions, "w", encoding="utf-8") as handle:
            handle.write("[site]\nhost=h\n")
        keep = os.path.join(self.config_dir, "keep.txt")
        with open(keep, "w", encoding="utf-8") as handle:
            handle.write("keep\n")
        status, payload = self.server.get("/api/cleanup")
        self.assertEqual(status, 200, payload)
        entry = next(item for item in payload["locations"]
                     if item["id"] == "sessions")
        self.assertTrue(entry["exists"])
        status, payload = self.server.post("/api/cleanup",
                                           {"ids": ["sessions"]})
        self.assertEqual(status, 400, payload)
        self.assertTrue(os.path.exists(sessions))
        status, payload = self.server.post("/api/cleanup",
                                           {"ids": ["sessions"],
                                            "confirm": True})
        self.assertEqual(status, 200, payload)
        self.assertFalse(os.path.exists(sessions))
        self.assertTrue(os.path.exists(keep))
        entry = next(item for item in payload["locations"]
                     if item["id"] == "sessions")
        self.assertFalse(entry["exists"])
        status, payload = self.server.post(
            "/api/cleanup", {"ids": ["elsewhere"], "confirm": True})
        self.assertEqual(status, 400, payload)


class PropertiesRightsTests(GuiApiBase, unittest.TestCase):
    def _file(self, name, content=b"hello"):
        path = os.path.join(self.right, name)
        with open(path, "wb") as handle:
            handle.write(content)
        return path

    def test_a_permission_string_maps_to_its_mode(self):
        self.assertEqual(gui.permissions_to_mode("-rw-r--r--"), 0o644)
        self.assertEqual(gui.permissions_to_mode("drwxr-xr-x"), 0o755)
        self.assertEqual(gui.permissions_to_mode("-rwsr-xr-x"), 0o4755)
        self.assertEqual(gui.permissions_to_mode("-rwxr-sr-x"), 0o2755)
        self.assertEqual(gui.permissions_to_mode("drwxrwxrwt"), 0o1777)
        self.assertEqual(gui.permissions_to_mode(""), 0)

    def test_several_entries_are_read_in_one_answer(self):
        self._file("one.txt")
        os.makedirs(os.path.join(self.right, "folder"))
        tab = self.open_local()
        status, payload = self.server.post(
            "/api/remote/properties",
            {"tab": tab["id"], "names": ["one.txt", "folder"]})
        self.assertEqual(status, 200, payload)
        rows = payload["properties"]
        self.assertEqual([row["name"] for row in rows], ["one.txt", "folder"])
        self.assertEqual(rows[0]["size"], 5)
        self.assertTrue(rows[1]["is_dir"])
        self.assertTrue(rows[0]["permissions"].startswith("-"))
        self.assertEqual(rows[0]["mode"],
                         gui.permissions_to_mode(rows[0]["permissions"]))
        self.assertNotIn("attributes", payload)
        status, payload = self.server.post(
            "/api/remote/properties", {"tab": tab["id"], "names": ["one.txt"]})
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["attributes"]["name"], "one.txt")

    def test_rights_are_changed_for_the_selection_and_bad_modes_refused(self):
        path = self._file("one.txt")
        tab = self.open_local()
        status, payload = self.server.post(
            "/api/remote/rights",
            {"tab": tab["id"], "names": ["one.txt"], "mode": "600"})
        self.assertEqual(status, 200, payload)
        self.assertGreaterEqual(payload["changed"], 1)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        status, payload = self.server.post(
            "/api/remote/rights",
            {"tab": tab["id"], "names": ["one.txt"], "mode": "u=rw,go=r"})
        self.assertEqual(status, 200, payload)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
        status, payload = self.server.post(
            "/api/remote/rights",
            {"tab": tab["id"], "names": ["one.txt"], "mode": "nonsense"})
        self.assertEqual(status, 400, payload)
        status, payload = self.server.post(
            "/api/remote/rights",
            {"tab": tab["id"], "names": ["../../etc/passwd"], "mode": "600"})
        self.assertEqual(status, 400, payload)
        status, payload = self.server.post(
            "/api/remote/rights",
            {"tab": tab["id"], "names": [], "mode": "600"})
        self.assertEqual(status, 400, payload)


class RemoteTransferFunctionTests(unittest.TestCase):
    def _tab(self, tab_id=7):
        tab = mock.Mock()
        tab.id = tab_id
        tab.name = "source"
        tab.connected = True
        tab.is_local = False
        tab.remote_dir = "/data"
        tab.session = {"protocol": "sftp", "host": "one.test", "username": "u"}
        return tab

    def test_the_file_mask_selects_the_names_to_copy(self):
        names = ["a.txt", "b.bin", "c.txt"]
        self.assertEqual(gui.filter_remote_names(names, "*.txt"),
                         ["a.txt", "c.txt"])
        self.assertEqual(gui.filter_remote_names(names, "*.txt|*.bin"), names)
        self.assertEqual(gui.filter_remote_names(names, ""), names)
        self.assertEqual(gui.filter_remote_names(names, "*.log"), [])

    def test_a_relative_or_malformed_directory_is_refused(self):
        for directory in ("", "relative/path", "/tmp/\u0001bad"):
            with self.assertRaises(ValueError, msg=repr(directory)):
                gui.check_remote_directory(directory)
        self.assertEqual(gui.check_remote_directory("/target"), "/target")

    def test_only_a_connected_remote_tab_can_start_a_copy(self):
        with self.assertRaises(ValueError):
            gui.remote_transfer_targets(None)
        local = self._tab()
        local.is_local = True
        with self.assertRaises(ValueError):
            gui.remote_transfer_targets(local)

    def test_a_copy_inside_one_session_is_a_server_side_cp(self):
        tab = self._tab()
        with mock.patch.object(gui, "TASKS") as tasks, \
                mock.patch.object(gui, "_current_workspace",
                                  return_value={"tabs": [tab]}):
            tasks.submit.return_value = mock.Mock()
            gui.queue_remote_transfer(tab, ["a.txt", "b.bin"], "tab:7",
                                      "/backup", "*.txt")
        kind, command = tasks.submit.call_args[0][0], tasks.submit.call_args[0][1]
        self.assertEqual(kind, "Copy (remote)")
        self.assertIn("cd ", command)
        self.assertIn("/backup/a.txt", command)
        # The mask decided what goes: b.bin was not selected.
        self.assertNotIn("b.bin", command)
        self.assertEqual(tasks.submit.call_args[0][4], "/backup")

    def test_another_session_is_queued_as_a_temporary_copy(self):
        tab = self._tab()
        site = {"name": "mirror", "protocol": "sftp", "host": "two.test"}
        with mock.patch.object(gui, "TASKS") as tasks, \
                mock.patch.object(gui, "read_stored_sessions",
                                  return_value=[site]), \
                mock.patch.object(gui, "_current_workspace",
                                  return_value={"tabs": [tab]}):
            tasks.submit.return_value = mock.Mock()
            gui.queue_remote_transfer(tab, ["a.txt"], "site:mirror",
                                      "/backup", "")
        kwargs = tasks.submit.call_args[1]
        self.assertEqual(kwargs["native"], gui.remote_copy_task)
        task = tasks.submit.return_value
        self.assertEqual(task.extra["directory"], "/backup")
        self.assertEqual(task.extra["names"], ["a.txt"])
        self.assertEqual(task.extra["destination"]["host"], "two.test")
        self.assertEqual(task.extra["label"], "mirror")

    def test_an_unknown_target_is_refused_before_queueing(self):
        tab = self._tab()
        with mock.patch.object(gui, "TASKS") as tasks, \
                mock.patch.object(gui, "read_stored_sessions",
                                  return_value=[]), \
                mock.patch.object(gui, "_current_workspace",
                                  return_value={"tabs": [tab]}):
            with self.assertRaises(ValueError):
                gui.queue_remote_transfer(tab, ["a.txt"], "site:gone",
                                          "/backup", "")
            with self.assertRaises(ValueError):
                gui.queue_remote_transfer(tab, [], "tab:7", "/backup", "")
            with self.assertRaises(ValueError):
                gui.queue_remote_transfer(tab, ["a.txt"], "tab:7",
                                          "relative", "")
        self.assertFalse(tasks.submit.called)


class RemoteCopyTaskTests(unittest.TestCase):
    def _task(self, names=("a.txt", "b.bin")):
        return gui.Task(1, "Copy (remote)", "", {}, "src", "dst", 5,
                        native=gui.remote_copy_task,
                        extra={"destination": {"protocol": "sftp",
                                               "host": "two.test"},
                               "label": "mirror", "directory": "/backup",
                               "names": list(names)})

    def test_each_file_is_downloaded_then_uploaded_and_the_temp_copy_removed(self):
        source = mock.Mock()
        source.connected = True
        source.is_local = False
        source.run_many_capture.return_value = (0, [], [])
        destination = mock.Mock()
        destination.start.return_value = (True, "")
        destination.connect.return_value = (True, "")
        destination.run_many_capture.return_value = (0, [], [])
        task = self._task()
        with mock.patch.object(gui, "get_tab", return_value=source), \
                mock.patch.object(gui, "CoreSession",
                                  return_value=destination), \
                mock.patch.object(gui.shutil, "rmtree") as rmtree:
            gui.remote_copy_task(task)
        self.assertEqual(source.run_many_capture.call_count, 2)
        self.assertEqual(destination.run_many_capture.call_count, 2)
        self.assertIn("a.txt", source.run_many_capture.call_args_list[0][0][0][0])
        self.assertIn("/backup/b.bin",
                      destination.run_many_capture.call_args_list[1][0][0][0])
        self.assertEqual(task.detail, "2 of 2 copied")
        destination.close.assert_called_once()
        rmtree.assert_called_once()
        self.assertIn("linscp-remote-copy-", rmtree.call_args[0][0])

    def test_a_failed_download_names_the_file_and_leaves_no_temporary_copy(self):
        source = mock.Mock()
        source.connected = True
        source.is_local = False
        source.run_many_capture.return_value = (1, [], ["permission denied"])
        destination = mock.Mock()
        destination.start.return_value = (True, "")
        destination.connect.return_value = (True, "")
        task = self._task(("secret.txt",))
        with mock.patch.object(gui, "get_tab", return_value=source), \
                mock.patch.object(gui, "CoreSession",
                                  return_value=destination), \
                mock.patch.object(gui.shutil, "rmtree") as rmtree:
            with self.assertRaises(ValueError) as caught:
                gui.remote_copy_task(task)
        self.assertIn("secret.txt", str(caught.exception))
        self.assertIn("permission denied", str(caught.exception))
        destination.close.assert_called_once()
        rmtree.assert_called_once()

    def test_a_source_session_that_is_gone_fails_before_copying(self):
        with mock.patch.object(gui, "get_tab", return_value=None):
            with self.assertRaises(ValueError):
                gui.remote_copy_task(self._task())


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=gui-local platform=linux ran=%d skipped=%d failed=%d" %
          (result.testsRun, len(result.skipped), failed))
    sys.exit(0 if result.wasSuccessful() else 1)
