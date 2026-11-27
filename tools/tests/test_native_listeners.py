"""Exercise the Linux listener smoke check without launching the GUI."""
import importlib.util
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('check_native_listeners', ROOT / 'tools/check_native_listeners.py')
checkers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checkers)


@unittest.skipUnless(sys.platform.startswith('linux') and Path('/proc/self/net/tcp').exists(), 'Linux procfs required')
class NativeListenerCheckTests(unittest.TestCase):
    def test_only_private_listener_and_no_unauthenticated_replies(self):
        with tempfile.TemporaryDirectory() as tmp, socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(4)
            port = listener.getsockname()[1]
            endpoint = Path(tmp) / '.instance-ipc'
            endpoint.write_text(f'127.0.0.1:{port} ' + 'a' * 64 + '\n')
            endpoint.chmod(0o600)
            received = []
            def serve():
                for _ in range(2):
                    with listener.accept()[0] as conn:
                        received.append(conn.recv(1024))
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            checkers.check(os.getpid(), tmp)
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertTrue(received[0].startswith(b'GET /api/status'))
            self.assertTrue(received[1].startswith(b'ACTIVATE '))
            self.assertNotEqual(received[1].split()[1], b'a' * 64)
            endpoint.chmod(0o644)
            with self.assertRaisesRegex(AssertionError, 'non-private'):
                checkers.check(os.getpid(), tmp)
            endpoint.chmod(0o600)
            with socket.socket() as extra:
                extra.bind(('127.0.0.1', 0))
                extra.listen()
                with self.assertRaisesRegex(AssertionError, 'unexpected GUI TCP listeners'):
                    checkers.check(os.getpid(), tmp)
