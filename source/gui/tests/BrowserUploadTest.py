#!/usr/bin/env python3
"""Offline tests for desktop-file upload staging and task construction."""

import http.client
import io
import json
import os
import pathlib
import re
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock
from http.server import ThreadingHTTPServer

GUI_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GUI_DIR))
import linscp_gui as gui  # noqa: E402


class FakeTasks:
    def __init__(self):
        self.args = None
        self.submitted = []
        self.task = types.SimpleNamespace(id=5)

    def submit(self, *args, **kwargs):
        self.args = (args, kwargs)
        self.submitted.append(self.args)
        self.task.cleanup_path = kwargs.get("cleanup_path")
        return self.task


class BrowserUploadTests(unittest.TestCase):
    def setUp(self):
        self.tasks = FakeTasks()
        self.original_tasks = gui.TASKS
        gui.TASKS = self.tasks
        self.tab = types.SimpleNamespace(
            id=7, session={"protocol": "sftp"}, remote_dir="/default")

    def tearDown(self):
        gui.TASKS = self.original_tasks
        for _, kwargs in self.tasks.submitted:
            path = kwargs.get("cleanup_path")
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def test_ui_locale_selection_and_core_protocol_isolation(self):
        self.assertEqual(gui.ui_language({"LANG": "es_MX.UTF-8"}), "es")
        self.assertEqual(gui.ui_language({"LC_ALL": "C", "LANG": "es"}), "en")
        self.assertEqual(gui.ui_language({"LC_ALL": "", "LC_MESSAGES": "es"}), "es")
        self.assertEqual(gui.ui_language({"LINSCP_LANGUAGE": "en", "LANG": "es"}), "en")
        self.assertEqual(gui.ui_language({"LANG": "xx"}), "en")
        with mock.patch.dict(os.environ, {"LINSCP_LANGUAGE": "es", "LC_ALL": "es_ES.UTF-8"}):
            kwargs = gui.popen_kwargs()
            self.assertEqual(kwargs["env"]["LINSCP_LANGUAGE"], "en")
            self.assertEqual(os.environ["LINSCP_LANGUAGE"], "es")
            self.assertEqual(kwargs["encoding"], "utf-8")

    def test_served_page_has_safe_locale_and_token_data(self):
        class QuietHandler(gui.LinScpGuiHandler):
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            token = '</script><script>alert("injection")</script>'
            with mock.patch.object(gui, "API_TOKEN", token), \
                 mock.patch.dict(os.environ, {"LINSCP_LANGUAGE": "es"}):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
                try:
                    conn.request("GET", "/")
                    response = conn.getresponse()
                    self.assertEqual(response.status, 200)
                    page = response.read().decode("utf-8")
                finally:
                    conn.close()
            config = re.search(r'const LSCP_CONFIG = (.*?);window.LSCP_TOKEN', page)[1]
            self.assertNotIn('<', config)
            self.assertEqual(json.loads(config), {"token": token, "language": "es"})
            self.assertIn('const GUI_CATALOGS = ', page)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_upload_stages_bytes_and_queues_the_exact_remote_path(self):
        stream = io.BytesIO(b"binary\x00payload")
        task = gui.queue_browser_upload(
            self.tab, "/incoming files", "note \"one\".txt", stream, 14)
        args, kwargs = self.tasks.args
        self.assertIs(task, self.tasks.task)
        self.assertEqual(args[0], "Upload")
        self.assertIn("mkdir -parents ", args[1])
        self.assertIn("put ", args[1])
        self.assertEqual(args[3], "Browser: note \"one\".txt")
        self.assertEqual(args[4], "/incoming files/note \"one\".txt")
        self.assertEqual(args[5], 7)
        self.assertEqual(kwargs["progress_remote"],
                         (7, "/incoming files/note \"one\".txt"))
        self.assertEqual(kwargs["cleanup_path"], self.tasks.task.cleanup_path)
        self.assertEqual(pathlib.Path(kwargs["cleanup_path"]).read_bytes(),
                         b"binary\x00payload")
        self.assertEqual(self.tasks.task.bytes_total, 14)

    def test_folder_entries_keep_relative_paths_and_queue_empty_directories(self):
        directory = gui.queue_browser_directory(
            self.tab, "/incoming files", "Project/empty folder")
        self.assertIs(directory, self.tasks.task)
        args, kwargs = self.tasks.args
        self.assertEqual(args[0], "Create directory")
        self.assertEqual(args[1], 'mkdir -parents "/incoming files/Project/empty folder"')
        self.assertEqual(args[4], "/incoming files/Project/empty folder")
        self.assertFalse(kwargs.get("cleanup_path"))

        file = 'daily %TIMESTAMP%.txt'
        gui.queue_browser_upload(self.tab, "/incoming files", file,
                                 io.BytesIO(b"abc"), 3,
                                 "Project/notes/" + file)
        args, kwargs = self.tasks.args
        self.assertEqual(args[4], "/incoming files/Project/notes/" + file)
        self.assertIn('mkdir -parents "/incoming files/Project/notes" ; put ',
                      args[1])
        self.assertIn('"/incoming files/Project/notes/' + file + '"', args[1])
        self.assertEqual(args[3], "Browser: Project/notes/" + file)
        self.assertEqual(pathlib.Path(kwargs["cleanup_path"]).read_bytes(), b"abc")

    def test_gui_queue_uses_the_literal_server_protocol_for_percent_filenames(self):
        # The -server input protocol does not expand script placeholders, and
        # it keeps a password-bearing site URL out of the process arguments.
        task = gui.Task(5, "Upload", 'put /tmp/file "/remote/%TIMESTAMP%.txt"',
                        {}, "file", "/remote/%TIMESTAMP%.txt", None)
        manager = gui.TaskManager.__new__(gui.TaskManager)
        with mock.patch.object(gui, "core_command_line", return_value=["linscp"]), \
             mock.patch.object(gui, "session_url", return_value="sftp://host/"), \
             mock.patch.object(gui, "add_log"), \
             mock.patch.object(gui.subprocess, "Popen",
                               side_effect=OSError("stub")) as popen:
            manager._run(task)
        command = popen.call_args.args[0]
        self.assertIn("-server", command)
        self.assertFalse(any(arg == "-literal" or arg.startswith("-command=")
                             for arg in command))
        self.assertIn("%TIMESTAMP%", task.command)
        self.assertEqual(task.status, "Failed")

    def test_dropped_paths_are_validated_before_staging_or_queueing(self):
        for path in ("../escape.txt", "/absolute.txt", "folder/../escape.txt",
                     "folder//file.txt", "folder/./file.txt", "folder/",
                     "folder\\file.txt", "folder/hello\n.txt",
                     "folder/\ud800.txt", "/".join(["nest"] * 33) + "/file.txt"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                gui.browser_destination("/incoming", path)
        for remote_dir in ("relative", "/incoming/../other", "/wrong\nname"):
            with self.subTest(dir=remote_dir), self.assertRaises(ValueError):
                gui.browser_destination(remote_dir, "file.txt")
        self.assertEqual(gui.browser_destination("/incoming/", "Project/n.txt"),
                         "/incoming/Project/n.txt")
        with self.assertRaises(ValueError):
            gui.queue_browser_upload(self.tab, "/incoming", "different.txt",
                                     io.BytesIO(b"secret"), 6,
                                     "other/file.txt")
        self.assertIsNone(self.tasks.args)

    def test_json_request_bodies_are_bounded_and_errors_use_api_statuses(self):
        def fake_handler(length, payload=b""):
            headers = mock.Mock()
            headers.get.return_value = None
            headers.get_all.return_value = [] if length is None else [str(length)]
            handler = types.SimpleNamespace(headers=headers, rfile=io.BytesIO(payload))
            handler.request_content_length = lambda: \
                gui.LinScpGuiHandler.request_content_length(handler)
            return handler

        handler = fake_handler(gui.MAX_JSON_BODY_BYTES + 1)
        with self.assertRaises(gui.RequestTooLarge):
            gui.LinScpGuiHandler.read_json_body(handler)

        handler = fake_handler(8, b"not-json")
        with self.assertRaisesRegex(ValueError, "valid UTF-8 JSON"):
            gui.LinScpGuiHandler.read_json_body(handler)
        nested = b"[" * 1200 + b"0" + b"]" * 1200
        handler = fake_handler(len(nested), nested)
        with self.assertRaisesRegex(ValueError, "valid UTF-8 JSON"):
            gui.LinScpGuiHandler.read_json_body(handler)

        handler = fake_handler(2)
        handler.headers.get_all.return_value = ["2", "2"]
        with self.assertRaisesRegex(ValueError, "Multiple Content-Length"):
            gui.LinScpGuiHandler.read_json_body(handler)
        handler = fake_handler(0)
        handler.headers.get.return_value = "chunked"
        with self.assertRaisesRegex(ValueError, "Transfer-Encoding"):
            gui.LinScpGuiHandler.read_json_body(handler)

        def raise_too_large():
            raise gui.RequestTooLarge("body is too large")

        response = {}
        handler = types.SimpleNamespace(
            close_connection=False, _dispatch_post=raise_too_large,
            send_json=lambda data, status=200: response.update(
                data=data, status=status))
        gui.LinScpGuiHandler.do_POST(handler)
        self.assertTrue(handler.close_connection)
        self.assertEqual(response["status"], 413)

    def test_http_endpoint_requires_token_and_queues_raw_file_bytes(self):
        class Tab:
            id = 77
            connected = True
            remote_dir = "/default"
            session = {"protocol": "sftp"}

        class QuietHandler(gui.LinScpGuiHandler):
            def log_message(self, *_args):
                pass

        old_config = (gui.API_TOKEN, gui.REQUIRE_TOKEN, gui.ALLOWED_HOSTS,
                      gui.ALLOW_ANY_HOST, gui.STATE["tabs"],
                      gui.STATE["active_tab"])
        gui.API_TOKEN = "browser-upload-test-token"
        gui.REQUIRE_TOKEN = True
        gui.ALLOWED_HOSTS = {"127.0.0.1"}
        gui.ALLOW_ANY_HOST = False
        gui.STATE["tabs"] = [Tab()]
        gui.STATE["active_tab"] = 77
        server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        path = None
        try:
            body = b"actual HTTP file\x00bytes"
            target = ("/api/transfer/drop?tab=77&remote_dir=%2Fincoming"
                      "&name=desktop.bin")
            denied = http.client.HTTPConnection("127.0.0.1", server.server_port)
            denied.request("POST", target, body,
                           {"Content-Type": "application/octet-stream"})
            response = denied.getresponse()
            response.read()
            self.assertEqual(response.status, 401)
            denied.close()
            self.assertIsNone(self.tasks.args)

            conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
            conn.request("POST", target, body,
                         {"X-LSCP-Token": gui.API_TOKEN,
                          "Content-Type": "application/octet-stream"})
            response = conn.getresponse()
            payload = response.read()
            conn.close()
            self.assertEqual(response.status, 200, payload)
            self.assertEqual(json.loads(payload.decode("utf-8"))["task_id"], 5)
            args, kwargs = self.tasks.args
            path = kwargs["cleanup_path"]
            self.assertEqual(pathlib.Path(path).read_bytes(), body)
            self.assertEqual(args[4], "/incoming/desktop.bin")

            def post(url, data, mime, token=True):
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
                headers = {"Content-Type": mime}
                if token:
                    headers["X-LSCP-Token"] = gui.API_TOKEN
                conn.request("POST", url, data, headers)
                response = conn.getresponse()
                code, result = response.status, response.read()
                conn.close()
                return code, json.loads(result.decode("utf-8"))

            directory = json.dumps({"tab": 77, "remote_dir": "/incoming",
                                    "relative_path": "Folder/empty"}).encode()
            code, _ = post("/api/transfer/drop-dir", directory,
                           "application/json", token=False)
            self.assertEqual(code, 401)
            code, result = post("/api/transfer/drop-dir", directory,
                                "application/json")
            self.assertEqual(code, 200, result)
            self.assertEqual(self.tasks.args[0][4], "/incoming/Folder/empty")
            self.assertEqual(self.tasks.args[0][1],
                             "mkdir -parents /incoming/Folder/empty")
            before = len(self.tasks.submitted)
            invalid = json.dumps({"tab": 77, "remote_dir": "/incoming",
                                  "relative_path": "Folder/../outside"}).encode()
            code, result = post("/api/transfer/drop-dir", invalid,
                                "application/json")
            self.assertEqual(code, 400, result)
            code, result = post("/api/transfer/drop-dir", b"[]",
                                "application/json")
            self.assertEqual(code, 400, result)
            code, result = post(
                "/api/transfer/drop?tab=77&remote_dir=%2Fincoming"
                "&name=desktop.bin&relative_path=..%2Fdesktop.bin", body,
                "application/octet-stream")
            self.assertEqual(code, 400, result)
            code, result = post(
                "/api/transfer/drop?tab=999&remote_dir=%2Fincoming"
                "&name=desktop.bin", body, "application/octet-stream")
            self.assertEqual(code, 400, result)
            self.assertEqual(len(self.tasks.submitted), before)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            gui.API_TOKEN, gui.REQUIRE_TOKEN, gui.ALLOWED_HOSTS, \
                gui.ALLOW_ANY_HOST = old_config[:4]
            gui.STATE["tabs"], gui.STATE["active_tab"] = old_config[4:]
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def test_incomplete_upload_does_not_leave_a_temporary_file_or_queue(self):
        with self.assertRaises(IOError):
            gui.queue_browser_upload(self.tab, "/incoming", "short.bin",
                                     io.BytesIO(b"short"), 20)
        self.assertIsNone(self.tasks.args)

    def test_local_pane_drop_and_queue_priority_and_cancel(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest_file = gui.save_local_browser_upload(
                tmp, "note.txt", io.BytesIO(b"local-drop\n"), 11,
                "nested/dir/note.txt")
            self.assertEqual(
                pathlib.Path(dest_file).read_bytes(), b"local-drop\n")
            dest_dir = gui.save_local_browser_directory(
                tmp, "nested/empty-folder")
            self.assertTrue(pathlib.Path(dest_dir).is_dir())
            with self.assertRaises(ValueError):
                gui.save_local_browser_upload(
                    tmp, "bad.txt", io.BytesIO(b"bad"), 3, "../bad.txt")

        # Verify TaskManager queue prioritization and build_sync_command conflict flag.
        self.assertIn(
            "-conflict=newer",
            gui.build_sync_command("both", "/local", "/remote",
                                   conflict="newer"))
        real_mgr = self.original_tasks
        with gui.STATE_LOCK:
            old_tasks = list(gui.STATE["tasks"])
            old_paused = gui.STATE["paused"]
            gui.STATE["paused"] = True
            gui.STATE["tasks"] = []
        try:
            t1 = real_mgr.submit("Upload", "put a", {}, "/a", "/a", 1)
            t2 = real_mgr.submit("Upload", "put b", {}, "/b", "/b", 1)
            self.assertEqual(gui.STATE["tasks"][-1].id, t1.id)
            self.assertTrue(real_mgr.prioritize(t2.id, "top"))
            self.assertEqual(gui.STATE["tasks"][-1].id, t2.id)
        finally:
            with gui.STATE_LOCK:
                gui.STATE["tasks"] = old_tasks
                gui.STATE["paused"] = old_paused


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(BrowserUploadTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=gui-browser-upload platform=linux ran=%d skipped=%d failed=%d" %
          (result.testsRun, len(result.skipped), failed))
    sys.exit(0 if result.wasSuccessful() else 1)
