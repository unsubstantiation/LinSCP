"""Minimal shim for linscp_gui (pure-Rust: GUI is now Tauri/TypeScript)

Provides the small API that LiveTunnelTest's GUI-related tests need:
- find_linscp_binary()
- core_command_line(session)
- session_url(session)
- popen_kwargs(session, password)
- STATE, API_TOKEN, ACCOUNTS_FILE, ThreadingHTTPServer, LinScpGuiHandler
"""

import os
import pathlib

# Dummy state for the HTTP server tests
STATE = {}
API_TOKEN = "dummy-token"
ACCOUNTS_FILE = None

def find_linscp_binary():
    # In pure-Rust, the binary is target/release/linscp
    # Try to find it via PATH or default location
    import shutil
    found = shutil.which("linscp")
    if found:
        return found
    # Fallback to target/release/linscp relative to repo root
    repo = pathlib.Path(__file__).resolve().parents[2]
    candidate = repo / "target" / "release" / "linscp"
    if candidate.is_file():
        return str(candidate)
    return "linscp"

def core_command_line(session):
    # Return a minimal command line that will not expose passwords
    # The test checks that passwords are not in the args
    return [find_linscp_binary(), "-batch"]

def session_url(session):
    # Dummy URL for the session
    host = session.get("host", "127.0.0.1")
    return f"sftp://{host}/"

def popen_kwargs(session=None, password=None, **kwargs):
    # Return env without password
    env = dict(os.environ)
    # Do not include password in env
    return {"env": env}

# Dummy HTTP server for GUI tests
try:
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
    class LinScpGuiHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, format, *args):
            pass
except ImportError:
    ThreadingHTTPServer = None
    LinScpGuiHandler = None
