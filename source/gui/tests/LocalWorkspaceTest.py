#!/usr/bin/env python3
"""Tests for the two local panes and for named workspaces.

The local-to-local mode is a tab whose two directories are on this machine:
there is no server, no core process and no credentials. The workspace store
is the named group of tabs that reopens them in order. Both are exercised
against the HTTP server and, where a queue cannot be driven deterministically
over HTTP, against the functions the queue calls.
"""

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


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=gui-local platform=linux ran=%d skipped=%d failed=%d" %
          (result.testsRun, len(result.skipped), failed))
    sys.exit(0 if result.wasSuccessful() else 1)
