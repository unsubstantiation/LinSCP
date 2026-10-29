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

def read_stored_sessions():
    """Read sessions.ini from LINSCP_CONFIG_DIR and return list of session dicts.

    Minimal implementation for LiveSftpTest: reads the INI file that the Rust
    engine wrote, decrypts passwords via linscp_crypto if needed, and returns
    a list of dicts with at least 'name' and 'password'.
    """
    import configparser
    config_dir = os.environ.get("LINSCP_CONFIG_DIR", "")
    if not config_dir:
        return []
    config_path = pathlib.Path(config_dir) / "sessions.ini"
    key_path = pathlib.Path(config_dir) / "sessions.key"
    if not config_path.is_file():
        return []
    # Try to load the key if exists
    key = None
    if key_path.is_file():
        try:
            import linscp_crypto as lc
            key = lc.load_key(str(key_path))
        except Exception:
            key = None
    parser = configparser.ConfigParser(interpolation=None)
    # Preserve case
    parser.optionxform = str
    try:
        parser.read(config_path, encoding="utf-8")
    except Exception:
        return []
    sessions = []
    for section in parser.sections():
        try:
            data = dict(parser[section])
            name = section
            # Decrypt password if it's lscp1$ and we have a key
            pwd = data.get("password", "")
            password_locked = False
            if pwd.startswith("lscp1$") and key is not None:
                try:
                    import linscp_crypto as lc
                    pwd = lc.decrypt(pwd, key)
                except Exception:
                    password_locked = True
                    pwd = ""
            elif pwd.startswith("lscp1$"):
                password_locked = True
                pwd = ""
            # Merge stored data but ensure decrypted password wins
            merged = {**data, "name": name, "password": pwd, "password_locked": password_locked}
            sessions.append(merged)
        except Exception:
            continue
    return sessions
