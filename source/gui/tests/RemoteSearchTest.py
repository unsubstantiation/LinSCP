#!/usr/bin/env python3
"""Offline tests for the GUI's bounded remote full-text search."""

import pathlib
import shlex
import sys
import unittest

GUI_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GUI_DIR))
import linscp_gui as gui  # noqa: E402


class FakeTab:
    def __init__(self, directories, files):
        self.directories = directories
        self.files = files
        self.downloads = []

    def run_many(self, commands, timeout=120):
        path = shlex.split(commands[0])[1]
        if path not in self.directories:
            return 1, ["No such directory."]
        entries = self.directories[path]
        lines = ["Reading directory %s..." % path,
                 "%d entries" % len(entries)]
        for name, is_dir in entries:
            remote = path.rstrip("/") + "/" + name
            if is_dir:
                permissions = "drwxr-xr-x"
                size = 0
            else:
                permissions = "-rw-r--r--"
                size = len(self.files[remote])
            lines.append("%s 1 user group %d Jan 01 00:00 %s" %
                         (permissions, size, name))
        return 0, lines

    def run(self, command, timeout=120):
        args = shlex.split(command)
        remote = args[1]
        if remote in self.directories:
            permissions = "drwxr-xr-x"
            size = 0
        elif remote in self.files:
            permissions = "-rw-r--r--"
            size = len(self.files[remote])
        else:
            return 1, ["No such file."]
        return 0, ["SizeBytes: %d" % size,
                   "ModifiedEpoch: 1792080000",
                   "Permissions: %s" % permissions]

    def run_capture(self, command, timeout=120):
        args = shlex.split(command)
        if len(args) < 4 or args[0] != "get" or args[1] != "-transfer=binary":
            return 1, [], ["Unexpected command"]
        remote, local = args[-2], args[-1].strip('"')
        if remote not in self.files:
            return 1, [], ["No such file"]
        pathlib.Path(local).write_bytes(self.files[remote])
        self.downloads.append(remote)
        return 0, [], []


def make_tab():
    large = b"x" * (gui.MAX_CONTENT_SEARCH_FILE_BYTES + 1)
    files = {
        "/docs/readme.txt": b"A Needle appears on this line.\n",
        "/docs/large.txt": large,
        "/docs/binary.txt": b"prefix\x00needle\n",
        "/docs/invalid.txt": b"invalid \xff UTF-8\n",
        "/docs/plain.txt": b"nothing to see here\n",
        "/docs/sub/nested.TXT": b"nested NEEDLE result\n",
    }
    directories = {
        "/docs": [("sub", True), ("readme.txt", False),
                   ("large.txt", False), ("binary.txt", False),
                   ("invalid.txt", False), ("plain.txt", False)],
        "/docs/sub": [("nested.TXT", False)],
    }
    return FakeTab(directories, files)


class RemoteSearchTests(unittest.TestCase):
    def test_content_search_filters_by_mask_and_reports_skips(self):
        tab = make_tab()
        stats = {"scanned": 0, "skipped": 0, "bytes_scanned": 0,
                 "truncated": False}
        matches = gui.remote_search(tab, "/docs", "*.txt", 500, False,
                                    content_query="needle", stats=stats)
        self.assertEqual([item["path"] for item in matches],
                         ["/docs/readme.txt", "/docs/sub/nested.TXT"])
        self.assertEqual(matches[0]["line"], 1)
        self.assertIn("Needle", matches[0]["snippet"])
        self.assertEqual(stats["scanned"], 5)
        self.assertEqual(stats["skipped"], 3)  # oversize, binary and non-UTF-8
        self.assertFalse(stats["truncated"])
        self.assertNotIn("/docs/large.txt", tab.downloads)

    def test_content_search_respects_case_sensitivity(self):
        tab = make_tab()
        stats = {"scanned": 0, "skipped": 0, "bytes_scanned": 0,
                 "truncated": False}
        matches = gui.remote_search(tab, "/docs", "*", 500, True,
                                    content_query="NEEDLE", stats=stats)
        self.assertEqual([item["path"] for item in matches],
                         ["/docs/sub/nested.TXT"])

    def test_filename_search_remains_download_free(self):
        tab = make_tab()
        stats = {"scanned": 0, "skipped": 0, "bytes_scanned": 0,
                 "truncated": False}
        matches = gui.remote_search(tab, "/docs", "*.txt", 500, False,
                                    stats=stats)
        self.assertEqual({item["name"] for item in matches},
                         {"readme.txt", "large.txt", "binary.txt",
                          "invalid.txt", "plain.txt", "nested.TXT"})
        self.assertEqual(tab.downloads, [])
        self.assertEqual(stats["scanned"], 0)

    def test_listing_keeps_entries_named_like_the_status_lines(self):
        """The status line that closes a listing was recognised by its
        word, anywhere in the line, so a file called 'entries.txt' or a
        directory called 'log-entries' was missing from the remote panel
        and from a search. An entry is told by its mode string."""
        lines = [
            "Reading directory /data with many words in its name a b c...",
            "-rw-r--r--    1 alice users 1234 Oct 18 06:00 entries.txt",
            "drwxr-xr-x    2 alice users 4096 Oct 18 06:00 log-entries",
            "drwxr-xr-x+   2 alice users 4096 Oct 18 06:00 acl dir",
            "lrwxrwxrwx    1 alice users   10 Oct 18 06:00 link -> target",
            "-rw-r--r--    1 alice users   10 Oct 18 06:00 Connected report",
            "5 entries",
        ]
        entries = gui.parse_ls_output(lines)
        self.assertEqual([item["name"] for item in entries],
                         ["acl dir", "log-entries", "Connected report",
                          "entries.txt", "link"])
        self.assertEqual(entries[-1]["link_target"], "target")
        self.assertTrue(entries[0]["is_dir"])
        tab = FakeTab({"/data": [("entries.txt", False),
                                 ("log-entries", True)],
                       "/data/log-entries": [("2026.log", False)]},
                      {"/data/entries.txt": b"x",
                       "/data/log-entries/2026.log": b"y"})
        matches = gui.remote_search(tab, "/data", "*", 500, False)
        self.assertEqual({item["path"] for item in matches},
                         {"/data/entries.txt", "/data/log-entries",
                          "/data/log-entries/2026.log"})

    def test_content_search_stops_at_the_scan_budget(self):
        directories = {"/docs": [("%03d.txt" % i, False)
                                  for i in range(gui.MAX_CONTENT_SEARCH_FILES + 1)]}
        files = {"/docs/%03d.txt" % i: b"hit" for i in range(
            gui.MAX_CONTENT_SEARCH_FILES + 1)}
        tab = FakeTab(directories, files)
        stats = {"scanned": 0, "skipped": 0, "bytes_scanned": 0,
                 "truncated": False}
        matches = gui.remote_search(tab, "/docs", "*.txt", 500, False,
                                    content_query="hit", stats=stats)
        self.assertEqual(stats["scanned"], gui.MAX_CONTENT_SEARCH_FILES)
        self.assertEqual(len(matches), gui.MAX_CONTENT_SEARCH_FILES)
        self.assertTrue(stats["truncated"])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RemoteSearchTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=gui-search platform=linux ran=%d skipped=%d failed=%d" %
          (result.testsRun, len(result.skipped), failed))
    sys.exit(0 if result.wasSuccessful() else 1)
