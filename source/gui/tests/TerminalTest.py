#!/usr/bin/env python3
"""Regression tests for the GUI's PTY-backed xterm transport."""
import fcntl
import os
import pathlib
import struct
import sys
import termios
import time
import unittest

GUI_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GUI_DIR))
import linscp_gui as gui  # noqa: E402


class TerminalProcessTests(unittest.TestCase):
    def start(self, code, cls=gui.TerminalProcess):
        return cls([sys.executable, "-u", "-c", code], dict(os.environ))

    def collect_until(self, terminal, marker, timeout=3):
        offset = 0
        chunks = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            data, offset, alive, _exit_code = terminal.poll(offset)
            chunks.append(data)
            joined = b"".join(chunks)
            if marker in joined or not alive:
                return joined
            time.sleep(0.01)
        self.fail("terminal did not produce %r" % marker)

    def test_input_output_and_pty_resize_are_forwarded(self):
        terminal = self.start(
            "import os; os.write(1, b'READY'); data = os.read(0, 128); "
            "os.write(1, b'GOT:' + data)")
        try:
            self.assertIn(b"READY", self.collect_until(terminal, b"READY"))
            terminal.resize(132, 43)
            size = bytearray(8)
            fcntl.ioctl(terminal.master, termios.TIOCGWINSZ, size, True)
            rows, cols, _xp, _yp = struct.unpack("HHHH", size)
            self.assertEqual((cols, rows), (132, 43))

            terminal.write(b"hello\n")
            output = self.collect_until(terminal, b"GOT:hello\r\n")
            self.assertIn(b"GOT:hello\r\n", output)
        finally:
            terminal.close()
        self.assertIsNotNone(terminal.proc.poll())

    def test_output_buffer_is_bounded_and_offsets_are_absolute(self):
        class SmallBufferTerminal(gui.TerminalProcess):
            BUFFER_LIMIT = 32

        terminal = self.start(
            "import os; os.write(1, b'x' * 200)",
            cls=SmallBufferTerminal)
        try:
            deadline = time.monotonic() + 3
            while terminal.alive and time.monotonic() < deadline:
                time.sleep(0.01)
            data, offset, alive, exit_code = terminal.poll(0)
            self.assertFalse(alive)
            self.assertIsNotNone(exit_code)
            self.assertEqual(len(data), 32)
            self.assertEqual(terminal.dropped, 168)
            self.assertEqual(offset, 200)
            self.assertEqual(data, b'x' * 32)
        finally:
            terminal.close()

    def test_resize_rejects_out_of_range_dimensions(self):
        terminal = self.start("import time; time.sleep(2)")
        try:
            terminal.resize(1001, 24)
            size = bytearray(8)
            fcntl.ioctl(terminal.master, termios.TIOCGWINSZ, size, True)
            rows, cols, _xp, _yp = struct.unpack("HHHH", size)
            self.assertEqual((cols, rows), (100, 30))
        finally:
            terminal.close()


if __name__ == "__main__":
    unittest.main()
