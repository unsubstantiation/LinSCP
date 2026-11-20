"""Independently validate the public, PuTTYgen-created unencrypted test keys."""
import base64
import hashlib
import hmac
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'crates/linscp-crypto/tests/fixtures/ppk'


class PuttyFixtureTests(unittest.TestCase):
    def test_unencrypted_v2_and_v3_mac_and_headers(self):
        for version in (2, 3):
            with self.subTest(version=version):
                lines = iter((FIXTURES / f'v{version}-none.ppk').read_text().splitlines())
                self.assertEqual(next(lines), f'PuTTY-User-Key-File-{version}: ssh-ed25519')
                self.assertEqual(next(lines), 'Encryption: none')
                comment = next(lines).removeprefix('Comment: ').encode()
                count = int(next(lines).removeprefix('Public-Lines: '))
                public = base64.b64decode(''.join(next(lines) for _ in range(count)), validate=True)
                # PuTTY v3 unencrypted keys omit all Key-Derivation headers.
                count = int(next(lines).removeprefix('Private-Lines: '))
                private = base64.b64decode(''.join(next(lines) for _ in range(count)), validate=True)
                expected = next(lines).removeprefix('Private-MAC: ')
                self.assertEqual(list(lines), [])
                fields = (b'ssh-ed25519', b'none', comment, public, private)
                data = b''.join(struct.pack('>I', len(field)) + field for field in fields)
                key = hashlib.sha1(b'putty-private-key-file-mac-key').digest() if version == 2 else b''
                digest = hashlib.sha1 if version == 2 else hashlib.sha256
                self.assertTrue(hmac.compare_digest(hmac.new(key, data, digest).hexdigest(), expected))


if __name__ == '__main__':
    unittest.main()
