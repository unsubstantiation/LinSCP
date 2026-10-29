"""Cross-language parity tests pinning Python (`linscp_crypto.py`) and the
shared Rust `crates/linscp-engine/tests/cross_language_sessions.rs` fixtures."""
import base64
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "source" / "gui"))
try:
    import linscp_crypto as lc
except ModuleNotFoundError:
    lc = None


class CrossLanguageParityTests(unittest.TestCase):
    def test_shared_rust_sessions_ini_fixture_decrypts_in_python(self):
        if lc is None:
            self.skipTest("linscp_crypto Python module not available in pure-Rust build")
        rust_test = (
            ROOT / "crates" / "linscp-engine" / "tests" / "cross_language_sessions.rs"
        ).read_text(encoding="utf-8")

        key_bytes = bytes(range(32))
        with tempfile.TemporaryDirectory() as td:
            key_path = pathlib.Path(td) / "sessions.key"
            key_path.write_text(base64.b64encode(key_bytes).decode("ascii") + "\n", encoding="utf-8")
            loaded = lc.load_key(str(key_path))
            self.assertEqual(loaded, key_bytes)

        expected_app = lc.encrypt("Pr0d$Pass\t2026!", key_bytes, nonce=bytes(range(16, 32)))
        expected_tun = lc.encrypt("Bastion#Key99", key_bytes, nonce=bytes(range(32, 48)))
        self.assertIn(f"password={expected_app}", rust_test)
        self.assertIn(f"tunnel_password={expected_tun}", rust_test)
        self.assertEqual(lc.decrypt(expected_app, key_bytes), "Pr0d$Pass\t2026!")
        self.assertEqual(lc.decrypt(expected_tun, key_bytes), "Bastion#Key99")


if __name__ == "__main__":
    unittest.main()
