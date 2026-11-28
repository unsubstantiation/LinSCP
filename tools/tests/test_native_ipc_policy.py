"""Static checks for shipped WebView configuration, not a runtime isolation proof."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class NativeIpcPolicyTests(unittest.TestCase):
    def test_capability_does_not_grant_remote_web_origins(self):
        capabilities = ROOT / 'crates/linscp-tauri/capabilities'
        for path in capabilities.glob('*.json'):
            policy = json.loads(path.read_text(encoding='utf-8'))
            self.assertNotIn('remote', policy, f'{path}: remote origins require security review')
            self.assertEqual(set(policy['windows']), {'main', 'terminal-*'})

    def test_packaged_webview_connect_policy_is_limited_to_ipc(self):
        config = json.loads((ROOT / 'crates/linscp-tauri/tauri.conf.json').read_text(encoding='utf-8'))
        directives = dict(part.strip().split(None, 1) for part in config['app']['security']['csp'].split(';') if part.strip())
        self.assertEqual(set(directives['connect-src'].split()), {'ipc:', 'http://ipc.localhost'})
        self.assertEqual(directives['default-src'], "'self'")
        # Inline scripts currently remain allowed: this is not an XSS defense.
        self.assertIn("'unsafe-inline'", directives['script-src'])
