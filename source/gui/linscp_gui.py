#!/usr/bin/env python3
"""
LinSCP Graphical Commander Interface Server
Provides a web-based dual-pane WinSCP Commander-style interface
backed by the LinSCP protocol engine.

Architecture
------------
* One *persistent core process* per tab (``linscp -server``). It holds
  the SSH connection, so browsing, renaming and editing do not log in
  again for every operation.
* Transfers, synchronizations and searches run as *tasks* in their own
  short-lived core processes, so they can be cancelled, retried and
  reported on without blocking the session they belong to.
* Stored sessions are read from (and written through) the same file the
  console client uses, ``sessions.ini`` in the configuration directory.

Access
------
The server listens on the loopback interface only, unless ``--host`` says
otherwise, and every ``/api/`` call has to carry this run's token in an
``X-LSCP-Token`` header. The token is generated when the server starts and
is injected into the page it serves, so the browser client knows it without
the user copying anything: a cross-origin page cannot read it, and a request
that guessed it is still refused by the ``Host`` check. ``--allow-host``
lets a reverse proxy in front of the server (a sandbox preview, a container
host name) through; ``--allow-any-host`` turns the check off.

Host keys are verified rather than accepted: a new site starts with no host
key, so the first connection reports the fingerprint it was offered and
waits for the user to pin it (once, or remembered in the stored session)
instead of connecting with ``-hostkey=*``.

Display servers
---------------
The server talks to no display server of its own: the Commander is a page, and
the browser that shows it is a window like any other, mapped by the compositor
rather than by this process. ``--open-browser`` asks the desktop's URI launcher
(``xdg-open``, or ``gio`` where there is none) to show the address, which is
the route that works on Wayland and on X11 alike; it does not need XWayland,
``xdotool`` or ``wmctrl``, none of which a Wayland session can answer.
"""

import os
import sys
import json
import time
import secrets
import shutil
import signal
import stat
import re
import getpass
import queue
import posixpath
import subprocess
import tempfile
import threading
import urllib.parse
import base64
import fcntl
import hashlib
import hmac
import pty
import struct
import termios
import zlib
import shlex
import xml.etree.ElementTree as ElementTree
from fnmatch import fnmatch, fnmatchcase
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

import linscp_crypto

PORT = 8080
HOST = "127.0.0.1"
MAX_BROWSER_UPLOAD_BYTES = 1024 * 1024 * 1024
MAX_JSON_BODY_BYTES = 2 * 1024 * 1024
# Filled in by main(): one random token per run, required on every /api/ call.
API_TOKEN = ""
REQUIRE_TOKEN = True


class RequestTooLarge(ValueError):
    """A JSON API request exceeded its bounded request-body size."""

# Host names a request may be addressed to. The loopback names are always
# allowed; --allow-host adds more (a reverse proxy, for example).
ALLOWED_HOSTS = set(["localhost", "127.0.0.1", "::1"])
ALLOW_ANY_HOST = False
# Browser origins allowed to read a response. Empty by default: the web
# client is served by this server, so every request it makes is same-origin
# and needs no CORS permission at all. --allow-origin=URL adds one, for a
# front end that really is served from somewhere else.
ALLOWED_ORIGINS = set()

# --- Multi-user account and CSRF protection ---
# When --accounts-file is given, the GUI authenticates users with
# PBKDF2-hashed passwords and issues per-session CSRF tokens.
ACCOUNTS_FILE = None     # path to accounts.ini, or None for single-user
SESSION_SECS = 3600      # login session lifetime in seconds

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
if not os.path.isdir(WEB_DIR):
    # The installed locations: the package puts this module and the web
    # client under /usr/share/linscp/gui.
    for candidate in ["/usr/share/linscp/gui/web", "/usr/share/linscp/gui"]:
        if os.path.isdir(candidate):
            WEB_DIR = candidate
            break


# ---- Multi-user account support (PBKDF2 password hashing) ---------------

def _hash_password(password, salt=None):
    """Hash a password with PBKDF2-HMAC-SHA256.  Returns (hash_hex, salt_hex)."""
    if salt is None:
        salt = secrets.token_bytes(16)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                              salt, iterations=300000, dklen=32)
    return dk.hex(), salt.hex()


def _verify_password(password, stored_hash, stored_salt):
    """Verify a password against the stored PBKDF2 hash.

    A corrupted accounts file (a salt that is not hex, a missing hash)
    answers False rather than raising: a login attempt against a broken
    record is a failed login, not a server error with a traceback.
    """
    try:
        salt_bytes = bytes.fromhex(stored_salt or "")
        if len(salt_bytes) != 16:
            return False
        if not stored_hash or len(stored_hash) != 64:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                  salt_bytes,
                                  iterations=300000, dklen=32)
        return hmac.compare_digest(dk.hex(), stored_hash)
    except (ValueError, TypeError):
        return False


def _read_accounts():
    """Parse accounts.ini into {username: {hash, salt, home_dir}}."""
    if not ACCOUNTS_FILE or not os.path.isfile(ACCOUNTS_FILE):
        return {}
    accounts = {}
    current = None
    with open(ACCOUNTS_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1]
                accounts[current] = {}
            elif current and "=" in line:
                key, val = line.split("=", 1)
                accounts[current][key.strip()] = val.strip()
    return accounts


def _write_account(username, password, home_dir=""):
    """Create or update a user account in accounts.ini.

    The user name and the home directory are lines of the file, so a
    newline in either would be a second line - a forged account section
    or a forged key. Both are refused rather than written.
    """
    if not ACCOUNTS_FILE:
        raise ValueError("No accounts file was given; start the server with "
                         "--accounts-file=FILE to say where to keep them.")
    username = str(username or "")
    home_dir = str(home_dir or "")
    if not username or len(username) > 64:
        raise ValueError("A user name of 1 to 64 characters is required.")
    if (any(ord(ch) < 32 or ord(ch) == 127 for ch in username) or
            "\n" in username or "\r" in username or
            "[" in username or "]" in username or "=" in username):
        raise ValueError("The user name contains a character that cannot "
                         "be stored in the accounts file.")
    if (any(ord(ch) < 32 or ord(ch) == 127 for ch in home_dir) or
            "\n" in home_dir or "\r" in home_dir):
        raise ValueError("The home directory contains a control character "
                         "and cannot be stored.")
    if home_dir and not home_dir.startswith("/"):
        raise ValueError("The home directory must be an absolute path, "
                         "or blank for none.")
    if not password:
        raise ValueError("An empty password is not accepted.")
    hash_hex, salt_hex = _hash_password(password)
    accounts = _read_accounts()
    if username in accounts:
        accounts[username]["hash"] = hash_hex
        accounts[username]["salt"] = salt_hex
        if home_dir:
            accounts[username]["home_dir"] = home_dir
    else:
        accounts[username] = {"hash": hash_hex, "salt": salt_hex,
                              "home_dir": home_dir}
    # Write back. The file holds the hashes and salts every login is
    # checked against, so it is created for this user only: a world-readable
    # copy is an offline password attack waiting to happen.
    path = ACCOUNTS_FILE
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w") as f:
        for user, data in accounts.items():
            f.write("[%s]\n" % user)
            for key, val in data.items():
                f.write("%s=%s\n" % (key, val))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _authenticate_user(username, password):
    """Returns True if the username/password pair is valid."""
    accounts = _read_accounts()
    acct = accounts.get(username)
    if not acct:
        return False
    return _verify_password(password, acct.get("hash", ""), acct.get("salt", ""))


# Session store: {session_id: {username, created, home_dir}}
_LOGIN_SESSIONS = {}
_LOGIN_LOCK = threading.Lock()


def _create_login_session(username):
    """Issue a login session and return (session_id, csrf_token).

    The CSRF token belongs to this one login session rather than to the
    server run: a token every user shared was not a per-session secret at
    all, and one leaked copy would have served for everybody until the
    process was restarted.
    """
    sid = secrets.token_hex(32)
    csrf = secrets.token_hex(32)
    accounts = _read_accounts()
    home_dir = accounts.get(username, {}).get("home_dir", "")
    with _LOGIN_LOCK:
        _LOGIN_SESSIONS[sid] = {
            "username": username,
            "created": time.time(),
            "home_dir": home_dir,
            "csrf": csrf,
        }
        # Sessions are only ever added, so an expired one that nobody asks
        # about again would stay in the table for the life of the process.
        now = time.time()
        for stale in [key for key, value in _LOGIN_SESSIONS.items()
                      if now - value["created"] > SESSION_SECS]:
            _LOGIN_SESSIONS.pop(stale, None)
    return sid, csrf


def _login_session_record(sid):
    """The live record behind a session id, or None once it has expired."""
    if not sid:
        return None
    with _LOGIN_LOCK:
        sess = _LOGIN_SESSIONS.get(sid)
        if not sess:
            return None
        if time.time() - sess["created"] > SESSION_SECS:
            _LOGIN_SESSIONS.pop(sid, None)
            return None
        return dict(sess)


def _validate_login_session(sid):
    """Returns the username if the session is valid, else None."""
    sess = _login_session_record(sid)
    return sess.get("username") if sess else None


def _session_home_dir(sid):
    """The directory a logged-in user's own panel starts in, if one is set."""
    sess = _login_session_record(sid)
    return (sess or {}).get("home_dir") or ""


def _csrf_ok(handler, sid):
    """Constant-time check of a request's CSRF token against its session's."""
    sess = _login_session_record(sid)
    if not sess or not sess.get("csrf"):
        return False
    supplied = handler.headers.get("X-LSCP-CSRF") or ""
    return hmac.compare_digest(supplied, sess["csrf"])


# Failed sign-ins per user name, and when the lockout they earned expires.
# An account endpoint reachable from anything that can open the port is an
# online guessing target without one, however strong the stored hash is.
_LOGIN_ATTEMPTS = {}
_LOGIN_LOCKOUT_UNTIL = {}
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECS = 60

def _login_throttle(username):
    """Seconds a caller has to wait before this user name may try again."""
    with _LOGIN_LOCK:
        until = _LOGIN_LOCKOUT_UNTIL.get(username, 0)
        remaining = until - time.time()
        return int(remaining) + 1 if remaining > 0 else 0


def _login_failed(username):
    with _LOGIN_LOCK:
        attempts = _LOGIN_ATTEMPTS.get(username, 0) + 1
        _LOGIN_ATTEMPTS[username] = attempts
        if attempts >= LOGIN_MAX_FAILURES:
            _LOGIN_LOCKOUT_UNTIL[username] = time.time() + LOGIN_LOCKOUT_SECS
            _LOGIN_ATTEMPTS[username] = 0


def _login_succeeded(username):
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.pop(username, None)
        _LOGIN_LOCKOUT_UNTIL.pop(username, None)


def _extract_login_cookie(handler):
    """Extract the login session ID from the Cookie header."""
    cookie = handler.headers.get("Cookie") or ""
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("LSCP_SID="):
            return part[len("LSCP_SID="):]
    return ""


def _default_user():
    try:
        return getpass.getuser() or "user"
    except Exception:
        return "user"


def find_linscp_binary():
    name = "linscp"
    candidates = [
        # Next to the GUI script, then the usual build trees, then the
        # installed locations.
        os.path.join(BASE_DIR, name),
        os.path.join(BASE_DIR, "..", "linux", "build", name),
        os.path.join(BASE_DIR, "..", "..", "source", "linux", "build", name),
        os.path.join(BASE_DIR, "..", "..", "build", name),
        # CMake installs into any prefix, not just /usr. With the module at
        # PREFIX/share/linscp/gui, the executable is PREFIX/bin/linscp.
        os.path.join(BASE_DIR, "..", "..", "..", "bin", name),
    ]
    found = shutil.which(name)
    if found:
        candidates.append(found)
    candidates.extend(["/usr/bin/linscp", "/usr/local/bin/linscp"])
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return os.path.abspath(c)
    return name


LINSCP_BIN = find_linscp_binary()

STATE_LOCK = threading.RLock()
_TLS = threading.local()
_USER_WORKSPACES = {}
_USER_WORKSPACES_LOCK = threading.Lock()


def empty_workspace(username="", home_dir="", config_dir=""):
    """One signed-in user's tabs, queue, logs, terminals and config root.

    The GUI process still runs as a single OS user; this is application-level
    isolation for --accounts-file deployments, not a substitute for separate
    OS accounts when callers are mutually hostile.
    """
    return {
        "logs": [],
        "tabs": [],          # list of CoreSession
        "active_tab": None,
        "tasks": [],         # newest first
        "paused": False,
        "next_tab": 1,
        "next_task": 1,
        "challenges": {},   # tab id -> CoreSession waiting for a host key decision
        "terminals": {},
        "username": username,
        "home_dir": home_dir or "",
        "config_dir": config_dir or "",
        "task_manager": None,
    }


_DEFAULT_WORKSPACE = empty_workspace()


def _current_workspace():
    return getattr(_TLS, "workspace", None) or _DEFAULT_WORKSPACE


class _StateView(object):
    """Dict-like view of the workspace bound to this thread.

    Existing call sites keep writing STATE['tabs']; with accounts enabled a
    request thread is bound to that login's workspace so two users never share
    tabs, queues, logs or terminals.
    """

    def __getitem__(self, key):
        return _current_workspace()[key]

    def __setitem__(self, key, value):
        _current_workspace()[key] = value

    def get(self, key, default=None):
        return _current_workspace().get(key, default)

    def __contains__(self, key):
        return key in _current_workspace()


STATE = _StateView()


def _accounts_users_root():
    if ACCOUNTS_FILE:
        return os.path.join(os.path.dirname(os.path.abspath(ACCOUNTS_FILE)),
                            "users")
    override = os.environ.get("LINSCP_CONFIG_DIR")
    if override:
        return os.path.join(override, "users")
    return os.path.join(_default_config_root(), "users")


def _default_config_root():
    override = os.environ.get("LINSCP_CONFIG_DIR")
    if override:
        return override
    root = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config")
    return os.path.join(root, "LinSCP")


def workspace_for_user(username, home_dir=""):
    """The isolated workspace owned by one account name."""
    username = str(username or "")
    if not username:
        return _DEFAULT_WORKSPACE
    with _USER_WORKSPACES_LOCK:
        ws = _USER_WORKSPACES.get(username)
        if ws is None:
            safe_dir = username
            if ("/" in safe_dir or "\\" in safe_dir or
                    safe_dir in (".", "..") or "\x00" in safe_dir):
                safe_dir = "user-" + hashlib.sha256(
                    username.encode("utf-8")).hexdigest()[:16]
            config_dir = os.path.join(_accounts_users_root(), safe_dir)
            ws = empty_workspace(username=username, home_dir=home_dir or "",
                                 config_dir=config_dir)
            _USER_WORKSPACES[username] = ws
        elif home_dir and ws.get("home_dir") != home_dir:
            ws["home_dir"] = home_dir
        return ws


def bind_workspace(workspace):
    _TLS.workspace = workspace
    return workspace


def unbind_workspace():
    _TLS.workspace = None


def account_home_dir():
    return str(_current_workspace().get("home_dir") or "").strip()


def confined_local_path(path):
    """Resolve a local path, jailed to this login's home when accounts are on.

    An account without a home_dir cannot touch the server filesystem at all:
    login is not an invitation to browse the process owner's files.
    """
    if path is None or path == "":
        return "", "No path given."
    path = str(path)
    if ACCOUNTS_FILE:
        home = account_home_dir()
        if not home:
            return "", "This account has no home directory."
        if not os.path.isabs(path):
            path = os.path.join(home, path)
        path = os.path.abspath(path)
        home_abs = os.path.abspath(home)
        try:
            if os.path.commonpath([home_abs, path]) != home_abs:
                return "", "The path is outside this account's home directory."
        except ValueError:
            return "", "The path is outside this account's home directory."
        home_real = os.path.realpath(home_abs)
        real = os.path.realpath(path)
        try:
            if os.path.commonpath([home_real, real]) != home_real:
                return "", "The path is outside this account's home directory."
        except ValueError:
            return "", "The path is outside this account's home directory."
        return path, ""
    if not os.path.isabs(path):
        path = os.path.abspath(os.path.join(os.path.expanduser("~"), path))
    else:
        path = os.path.abspath(path)
    return path, ""


def default_local_dir():
    if ACCOUNTS_FILE:
        return account_home_dir() or ""
    return os.path.expanduser("~")


def add_log(message, level="info"):
    # Core diagnostics and command strings can contain credentials even when
    # the call site did not construct the message itself.
    message = redact_command_for_log(str(message))
    timestamp = time.strftime("%H:%M:%S")
    with STATE_LOCK:
        entry = {"time": timestamp, "text": message, "level": level}
        STATE["logs"].append(entry)
        if len(STATE["logs"]) > 400:
            del STATE["logs"][:-200]


# ---------------------------------------------------------------------------
# Stored sessions (the site manager)
# ---------------------------------------------------------------------------

def session_store_path():
    """The sessions.ini the console client and this server share.

    With --accounts-file each login keeps its own file under users/<name>/,
    so one account cannot read or overwrite another's stored sites.
    """
    ws = _current_workspace()
    if ws.get("config_dir"):
        os.makedirs(ws["config_dir"], mode=0o700, exist_ok=True)
        return os.path.join(ws["config_dir"], "sessions.ini")
    override = os.environ.get("LINSCP_CONFIG_DIR")
    if override:
        return os.path.join(override, "sessions.ini")
    root = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(root, "LinSCP", "sessions.ini")


def _unescape(text):
    out = []
    i = 0
    while i < len(text):
        char = text[i]
        if char == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append({"n": "\n", "r": "\r", "t": "\t"}.get(nxt, nxt))
            i += 2
            continue
        out.append(char)
        i += 1
    return "".join(out)


def _escape(text):
    return (text.replace("\\", "\\\\").replace("\n", "\\n")
                .replace("\r", "\\r").replace("\t", "\\t"))


SESSION_KEYS = {
    "protocol": "protocol",
    "host": "host",
    "hostname": "host",
    "port": "port",
    "username": "username",
    "user": "username",
    "private_key": "keyfile",
    "privatekey": "keyfile",
    "keyfile": "keyfile",
    "hostkey": "hostkey",
    "host_key": "hostkey",
    "remote_directory": "initial_dir",
    "remotedir": "initial_dir",
    "local_directory": "local_dir",
    "localdir": "local_dir",
    # Upstream's local browser persists its second local directory beside
    # the first. The console client has no local protocol, but the GUI's
    # local tabs and workspaces do, and a site saved from one has to carry
    # both panes or restoring it would silently drop a pane.
    "other_local_directory": "other_local_dir",
    "otherlocaldir": "other_local_dir",
    "password": "password",
    "ftps": "ftps",
    "last_used": "last_used",
}


# Field names are shared with sessions.ini; credentials never enter argv.
TUNNEL_RAW_FIELDS = {
    "tunnel": "Tunnel", "tunnel_host": "TunnelHostName",
    "tunnel_port": "TunnelPortNumber", "tunnel_username": "TunnelUserName",
    "tunnel_private_key": "TunnelPublicKeyFile", "tunnel_hostkey": "TunnelHostKey",
    "tunnel_password": "TunnelPassword", "tunnel_passphrase": "TunnelPassphrase",
    "tunnel_local_port": "TunnelLocalPortNumber",
}
SESSION_KEYS.update({field: field for field in TUNNEL_RAW_FIELDS})

# Kerberos policy travels the same way, under the core's raw names. The
# defaults are upstream's: gssapi-with-mic tried, key exchange and
# credential delegation off (delegation in particular is never on
# unless a site asks for it).
GSSAPI_RAW_FIELDS = {
    "auth_gssapi": "AuthGSSAPI", "auth_gssapi_kex": "AuthGSSAPIKEX",
    "gssapi_fwd_tgt": "GSSAPIFwdTGT", "logical_host": "LogicalHostName",
}
GSSAPI_DEFAULTS = {"auth_gssapi": "1", "auth_gssapi_kex": "0",
                   "gssapi_fwd_tgt": "0", "logical_host": ""}
SESSION_KEYS.update({field: field for field in GSSAPI_RAW_FIELDS})


def _raw_bool(value, default):
    """One session flag as the '0'/'1' a raw setting takes."""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return "1" if value else "0"
    return "0" if str(value).strip().lower() in ("0", "false") else "1"


def gssapi_raw_settings(session):
    """The session's Kerberos settings as 'Name=value' raw settings."""
    settings = []
    for field, name in GSSAPI_RAW_FIELDS.items():
        if field == "logical_host":
            value = str(session.get(field) or "")
        else:
            value = _raw_bool(session.get(field), GSSAPI_DEFAULTS[field])
        settings.append(name + "=" + value)
    return settings


# The port each protocol listens on when the site does not say: the same
# table the console client applies to a URL without a port. 'dav' is
# WebDAV over plain HTTP and 'webdav' over HTTPS, as in the client.
DEFAULT_PORTS = {
    "sftp": 22, "scp": 22, "ssh": 22, "ftp": 21, "ftps": 990,
    "ftpes": 21,
    "dav": 80, "http": 80, "webdav": 443, "https": 443, "s3": 443,
}


def default_port(protocol):
    return DEFAULT_PORTS.get((protocol or "sftp").lower(), 22)


def session_is_local(session):
    """Whether a session names two local directories instead of a server.

    Upstream's TSessionData calls this a local browser: LocalDirectory and
    OtherLocalDirectory are set and there is no host to log in to. The GUI
    uses the same shape so a local tab can be stored and restored without a
    core process.
    """
    return (isinstance(session, dict) and
            str(session.get("protocol") or "").lower() == "local")


def validate_local_directory(path, label):
    """Validate one pane directory of a local-to-local session."""
    if not isinstance(path, str) or not path:
        return "The %s is required." % label
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        return "The %s must not contain control characters." % label
    if not os.path.isabs(path):
        return "The %s must be an absolute path." % label
    if not os.path.isdir(path):
        return "The %s is not a directory." % label
    return ""


def validate_local_panes(local_dir, other_dir):
    error = validate_local_directory(local_dir, "local directory")
    if error:
        return error
    return validate_local_directory(other_dir, "other local directory")


def validate_session_data(session, require_host=False):
    """Reject malformed session values before they reach a core process."""
    if not isinstance(session, dict):
        return "A session must be a JSON object."
    protocol = session.get("protocol", "sftp")
    if protocol is None or protocol == "":
        protocol = "sftp"
    if not isinstance(protocol, str) or protocol.lower() not in (
            "sftp", "ssh", "scp", "ftp", "ftps", "ftpes", "http",
            "https", "dav", "webdav", "s3", "local"):
        return "The session protocol is not supported."
    if protocol.lower() == "local":
        # A local-to-local session has no server, port, credentials or
        # tunnel: every remote field is irrelevant, and validating a port
        # it does not have would reject a perfectly good local workspace.
        for field in ("local_dir", "other_local_dir"):
            value = session.get(field)
            if value is not None and not isinstance(value, str):
                return "The session %s must be text." % field.replace("_", " ")
            if isinstance(value, str) and any(
                    ord(char) < 32 or ord(char) == 127 for char in value):
                return ("The session %s must not contain control characters."
                        % field.replace("_", " "))
        return validate_local_panes(session.get("local_dir") or "",
                                    session.get("other_local_dir") or "")
    host = session.get("host", "")
    if host is None:
        host = ""
    if not isinstance(host, str):
        return "The host name must be text."
    if require_host and not host.strip():
        return "A host name is required."
    if any(ord(char) < 32 or ord(char) == 127 for char in host):
        return "The host name must not contain control characters."
    for field in ("username", "password", "keyfile", "hostkey",
                  "initial_dir", "local_dir", "other_local_dir",
                  "tunnel_host", "tunnel_username",
                  "tunnel_private_key", "tunnel_hostkey", "tunnel_password", "tunnel_passphrase",
                  "logical_host"):
        value = session.get(field)
        if value is not None and not isinstance(value, str):
            return "The session %s must be text." % field.replace("_", " ")
        if isinstance(value, str) and any(
                ord(char) < 32 or ord(char) == 127 for char in value):
            return "The session %s must not contain control characters." % field.replace(
                "_", " ")
    port = session.get("port")
    if port not in (None, ""):
        port_text = str(port)
        if (isinstance(port, bool) or len(port_text) > 5 or
                not re.fullmatch(r"[0-9]+", port_text)):
            return "The port must be a number from 1 through 65535."
        if not 1 <= int(port_text) <= 65535:
            return "The port must be a number from 1 through 65535."
    if "tunnel" in session and not isinstance(session["tunnel"], bool):
        return "The SSH tunnel setting must be true or false."
    if session.get("tunnel"):
        if protocol.lower() not in ("sftp", "scp", "ssh"):
            return "SSH tunnels require an SFTP or SCP session."
        tunnel_host = session.get("tunnel_host") or ""
        if not tunnel_host or any(char.isspace() for char in tunnel_host):
            return "An SSH tunnel host name without whitespace is required."
        tunnel_port = str(session.get("tunnel_port", 22))
        if (len(tunnel_port) > 5 or not re.fullmatch(r"[0-9]+", tunnel_port) or
                not 1 <= int(tunnel_port) <= 65535):
            return "The SSH tunnel port must be a number from 1 through 65535."
        local_port = str(session.get("tunnel_local_port", 0) or 0)
        if (len(local_port) > 5 or not re.fullmatch(r"[0-9]+", local_port) or
                not 0 <= int(local_port) <= 65535):
            return "The tunnel local port must be 0 or a number from 1 through 65535."
        if session.get("tunnel_error"):
            return "The stored SSH tunnel credentials cannot be read; store them again."
    for field in ("auth_gssapi", "auth_gssapi_kex", "gssapi_fwd_tgt"):
        value = session.get(field)
        if value is not None and not isinstance(value, (bool, int, str)):
            return "The session Kerberos settings must be true or false."
    logical_host = session.get("logical_host")
    if logical_host and any(char.isspace() for char in str(logical_host)):
        return "The logical host name must not contain whitespace."
    return ""


def read_stored_sessions():
    """Parse sessions.ini into the dictionaries the web client uses."""
    path = session_store_path()
    sessions = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()
    except OSError:
        return sessions
    current = None
    for line in raw.splitlines():
        text = line.strip()
        if not text or text[0] in "#;":
            continue
        if text.startswith("[") and text.endswith("]"):
            if current:
                sessions.append(current)
            current = {
                "name": _unescape(text[1:-1]),
                "protocol": "sftp", "host": "", "port": 22, "username": "",
                "password": "", "keyfile": "", "hostkey": "",
                "initial_dir": "/", "local_dir": "",
                "other_local_dir": "", "last_used": 0,
            }
            continue
        if current is None or "=" not in text:
            continue
        key, raw_val = line.rstrip("\r\n").split("=", 1)
        field = SESSION_KEYS.get(key.strip().lower())
        if field is None:
            continue
        trimmed = _unescape(raw_val.strip())
        value = _unescape(raw_val)
        if field == "tunnel":
            # Keep malformed values invalid rather than silently connecting directly.
            current[field] = trimmed == "1" if trimmed in ("0", "1") else trimmed
        elif field == "tunnel_port":
            current[field] = int(trimmed) if trimmed.isascii() and trimmed.isdigit() and len(trimmed) <= 5 else trimmed
        elif field in ("auth_gssapi", "auth_gssapi_kex", "gssapi_fwd_tgt"):
            current[field] = trimmed == "1" if trimmed in ("0", "1") else trimmed
        elif field == "tunnel_local_port":
            current[field] = int(trimmed) if trimmed.isascii() and trimmed.isdigit() and len(trimmed) <= 5 else trimmed
        elif field == "port":
            try:
                current["port"] = int(trimmed)
            except ValueError:
                current["port"] = 22
        elif field == "ftps":
            current["ftps"] = int(trimmed) if trimmed.isascii() and trimmed.isdigit() else trimmed
        elif field == "last_used":
            try:
                current["last_used"] = int(trimmed)
            except ValueError:
                pass
        else:
            current[field] = value
    if current:
        sessions.append(current)
    for item in sessions:
        # A stored FTP site carries its TLS mode in 'ftps'; the Commander
        # shows and connects with the scheme that mode means. 'ftps://' is
        # implicit TLS, 'ftpes://' explicit TLS on port 21.
        item["protocol"] = session_protocol_name(
            item.get("protocol"), item.get("ftps"))
        # A site without a port, and one written with the SSH port by an
        # earlier version that defaulted every protocol to 22, takes the
        # port of its protocol: the console client reads the file the
        # same way, and the site manager then shows the port that is
        # really used instead of 22 beside 'FTP'.
        implied = default_port(item.get("protocol"))
        if item.get("port") in (None, 0, 22) and implied != 22:
            item["port"] = implied
        value = item.get("password") or ""
        item["password_locked"] = False
        item["password_error"] = ""
        if value.startswith("lscp1$"):
            # Encrypted under the key file next to sessions.ini; a
            # failure here leaves the session usable without the
            # password (a key may be enough) but says why.
            item["password"] = ""
            try:
                key = linscp_crypto.load_key(
                    linscp_crypto.key_path_for(path))
                item["password"] = linscp_crypto.decrypt(value, key)
                if not item["password"]:
                    item["password"] = ""
                    item["password_locked"] = True
                    item["password_error"] = \
                        "the stored password in the file is empty"
            except linscp_crypto.PasswordError as exc:
                item["password_locked"] = True
                item["password_error"] = str(exc)
        elif value:
            # Plaintext from a file written before the encryption
            # existed; the console client rewrites it encrypted on the
            # next save.
            pass
        item["tunnel_error"] = ""
        for field in ("tunnel_password", "tunnel_passphrase"):
            value = item.get(field) or ""
            if value.startswith("lscp1$"):
                item[field] = ""
                try:
                    key = linscp_crypto.load_key(linscp_crypto.key_path_for(path))
                    item[field] = linscp_crypto.decrypt(value, key)
                    if not item[field]:
                        item["tunnel_error"] = "The stored SSH tunnel credential is empty."
                except linscp_crypto.PasswordError as exc:
                    item["tunnel_error"] = str(exc)
    sessions.sort(key=lambda item: item["name"].lower())
    return sessions


def parse_desktop_site_url(uri):
    """Convert a registered Linux sftp://, ftp://, ftps:// or ftpes:// URL."""
    parsed = urllib.parse.urlsplit(uri)
    protocol = parsed.scheme.lower()
    if protocol not in ("sftp", "ftp", "ftps", "ftpes"):
        raise ValueError("Only sftp://, ftp:// and ftps:// URLs can be opened.")
    if not parsed.hostname:
        raise ValueError("The site URL has no host name.")
    if parsed.query or parsed.fragment:
        raise ValueError("Site URLs must not contain a query or fragment.")

    def decode_component(value, label):
        if re.search(r"%(?![0-9A-Fa-f]{2})", value):
            raise ValueError("The site URL has an invalid escape in its %s." % label)
        try:
            return urllib.parse.unquote(value, errors="strict")
        except UnicodeDecodeError:
            raise ValueError("The site URL has invalid UTF-8 in its %s." % label)

    try:
        port = parsed.port
    except ValueError:
        raise ValueError("The site URL has an invalid port.")
    defaults = {"sftp": 22, "ftp": 21, "ftps": 990, "ftpes": 21}
    session = new_session()
    session["protocol"] = protocol
    session["host"] = parsed.hostname
    session["port"] = port if port is not None else defaults[protocol]
    if session["port"] < 1 or session["port"] > 65535:
        raise ValueError("The site URL port must be between 1 and 65535.")
    if parsed.username is not None:
        username = decode_component(parsed.username, "user name")
        if not username:
            raise ValueError("The site URL user name is empty.")
        session["username"] = username
    if parsed.password is not None:
        session["password"] = decode_component(parsed.password, "password")
    path = decode_component(parsed.path or "/", "path")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError("The site URL path contains a control character.")
    session["initial_dir"] = path if path.startswith("/") else "/" + path
    return session


def open_desktop_site(session):
    """Start the GUI with a URL supplied by a Linux desktop scheme handler."""
    with STATE_LOCK:
        tab = CoreSession(STATE["next_tab"], session)
        STATE["next_tab"] += 1
        STATE["tabs"].append(tab)
        STATE["active_tab"] = tab.id

    def connect():
        add_log("Connecting to %s (%s)..." %
                (session.get("host"), session.get("protocol")), "info")
        ok, error = tab.connect()
        if ok:
            add_log("Connected to %s" % tab.name, "success")
        else:
            add_log("Connection failed: %s" % error, "error")
            if tab.observed_hostkey:
                with STATE_LOCK:
                    STATE["challenges"][tab.id] = tab

    threading.Thread(target=connect, daemon=True).start()
    return tab


# ---------------------------------------------------------------------------
# Showing the Commander in a window of the desktop session
#
# A Wayland client cannot ask to be mapped, placed or focused: the compositor
# decides all three, and the X11 helpers a launcher used to reach for
# (xdotool, wmctrl, xprop) cannot talk to it at all. So the server never
# touches the display server itself. It asks the desktop's own URI launcher to
# open its address, which is the one route that works on Wayland and on X11
# alike, and the browser window that answers is a window like any other.
#
# The rules about which session this is are the ones
# source/linux/Platform.cpp applies to the terminal window of 'terminal', and
# they are kept in step by tools/check_wayland_compatibility.py.
# ---------------------------------------------------------------------------

def detect_desktop_session(environment=None):
    """The display servers a window started from here could be shown on.

    Returns ``(wayland, x11, wayland_display)``, where ``wayland_display`` is
    the name to put into a child's environment when this environment does not
    name it and yet the compositor's socket is there - empty when there is
    nothing to add.

    X11 is taken from ``$DISPLAY``, which may name a forwarded server on
    another machine. Wayland is recognised by the socket in
    ``$XDG_RUNTIME_DIR`` rather than by ``$WAYLAND_DISPLAY`` alone, because
    the two fail in opposite directions: a session started by a launcher or a
    user service often carries no variable while the default ``wayland-0``
    socket sits in the runtime directory, and a variable without that
    directory names a socket no Wayland client can find.
    """
    environment = os.environ if environment is None else environment
    x11 = bool(environment.get("DISPLAY"))
    named = environment.get("WAYLAND_DISPLAY") or ""
    runtime = environment.get("XDG_RUNTIME_DIR") or ""
    socket = ""
    if named.startswith("/"):
        socket = named
    elif runtime:
        socket = os.path.join(runtime, named or "wayland-0")
    wayland = bool(socket) and os.path.exists(socket)
    # Found by its default name rather than announced: a Wayland client
    # started as our child has to be given that name to look the socket up.
    return wayland, x11, ("wayland-0" if wayland and not named else "")


def has_desktop_session(environment=None):
    """Whether a window started from here could be shown at all."""
    wayland, x11, _inferred = detect_desktop_session(environment)
    return wayland or x11


def find_on_path(program, environment):
    """The executable ``program`` names, as the environment under
    consideration would find it.

    ``shutil.which`` looks at the interpreter's own ``PATH``, which is a
    different thing from the session being asked about - and the answer has to
    come from the session, because it is the session's launcher that gets
    started. A name with a separator in it is a path already.
    """
    if not program:
        return None
    if os.path.sep in program:
        expanded = os.path.expanduser(program)
        if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
            return expanded
        return None
    return shutil.which(program, path=environment.get("PATH"))


def browser_open_command(url, environment=None):
    """The command that asks the desktop to show ``url``, or ``None``.

    ``$BROWSER`` comes first because it is the variable a user sets to say
    which browser they mean: a colon-separated preference list, walked left to
    right, where an entry whose program is not installed is passed over and a
    program may want the URL where its ``%s`` is. ``xdg-open`` is the
    freedesktop launcher, which on a Wayland or otherwise sandboxed session
    hands the request to the desktop's portal instead of starting a program
    directly; ``gio open`` is the same thing from GLib. Nothing here names a
    browser of its own: guessing one is how a launcher ends up overriding the
    user.
    """
    environment = os.environ if environment is None else environment
    for entry in (environment.get("BROWSER") or "").split(":"):
        words = entry.split()
        if not words:
            continue
        program = find_on_path(words[0], environment)
        if program is None:
            # An entry naming a browser that is not installed is skipped
            # rather than reported: the variable is a preference list, and the
            # desktop launcher behind it is the desktop's own answer.
            continue
        rest = words[1:]
        if any("%s" in word for word in rest):
            return [program] + [word.replace("%s", url) for word in rest]
        return [program] + rest + [url]
    launcher = find_on_path("xdg-open", environment)
    if launcher:
        return [launcher, url]
    if find_on_path("gio", environment):
        return ["gio", "open", url]
    return None


def browser_url_for(host, port):
    """The address to ask the desktop to open for this bind.

    A wildcard bind has no name of its own, so the loopback name is used; a
    bound address is used as it was given, because that is the name the Host
    check was told to answer, and an IPv6 literal needs the brackets a URL
    requires. Opening a name the server would refuse is how a launcher ends up
    showing an error page for a server that is running happily.
    """
    name = (host or "").strip().lower()
    if name in ("", "0.0.0.0", "::", "::0"):
        name = "localhost"
    elif name == "::1":
        name = "[::1]"
    elif ":" in name and not name.startswith("["):
        name = "[%s]" % name
    return "http://%s:%d/" % (name, port)


def open_in_browser(url, environment=None):
    """Open the Commander's address in a window of the desktop session.

    Returns an empty string on success and the reason it did not happen
    otherwise, so that the caller can print advice instead of staying silent:
    a server started over ssh has no session to open a window in, and the
    address it printed is still the one to paste into a browser elsewhere.

    The URL carries no token - the page the server serves carries it, so
    nothing a ``ps`` of this machine shows is a secret. A child that has to be
    told where the compositor is gets the name that was found for it, which is
    what a Wayland client looks for first.
    """
    environment = os.environ if environment is None else environment
    wayland, x11, inferred = detect_desktop_session(environment)
    if not wayland and not x11:
        return ("no desktop session was found (neither DISPLAY nor a Wayland "
                "socket in XDG_RUNTIME_DIR is set here)")
    command = browser_open_command(url, environment)
    if command is None:
        return ("no desktop URI launcher is installed (looked for xdg-open "
                "and gio)")
    child = dict(os.environ)
    if inferred:
        child.setdefault("WAYLAND_DISPLAY", inferred)
    try:
        subprocess.Popen(command, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True, env=child)
    except OSError as exc:
        return "the desktop launcher '%s' could not be started: %s" % (
            command[0], exc)
    return ""


def new_session():
    return {
        "protocol": "sftp",
        "ftps": 0,
        "host": "localhost",
        "port": 22,
        "username": os.environ.get("USERNAME") or os.environ.get("USER") or _default_user(),
        "password": "",
        "keyfile": "",
        # Empty means 'verify': the core checks the key against its cache and
        # reports an unknown one instead of connecting. '*' still works, but
        # it has to be asked for.
        "hostkey": "",
        "initial_dir": "/",
        "local_dir": default_local_dir() or os.path.expanduser("~"),
        "other_local_dir": "",
        "tunnel": False, "tunnel_host": "", "tunnel_port": 22,
        "tunnel_username": "", "tunnel_password": "", "tunnel_passphrase": "",
        "tunnel_private_key": "", "tunnel_hostkey": "", "tunnel_error": "",
        "tunnel_local_port": 0,
        "auth_gssapi": True, "auth_gssapi_kex": False,
        "gssapi_fwd_tgt": False, "logical_host": "",
    }


def session_protocol_name(protocol, ftps_mode=None):
    """The spelling of a session's protocol, including the TLS mode.

    'ftps://' is implicit TLS and 'ftpes://' is FTP with explicit TLS, as
    upstream spells them. A stored site keeps the upstream shape - protocol
    'ftp' with an 'ftps' mode beside it - because that is what the console
    client writes; the Commander shows and connects with the scheme, so the
    user sees which kind of TLS a site uses instead of a bare 'FTP'.
    """
    protocol = (protocol or "sftp").strip().lower()
    if protocol == "ftp" and ftps_mode not in (None, "", 0):
        try:
            mode = int(ftps_mode)
        except (TypeError, ValueError):
            return protocol
        if mode == 1:
            return "ftps"
        if mode in (2, 3):
            return "ftpes"
    return protocol


def session_url(session, path=None, include_password=False):
    """The site URL of a session, without its password by default.

    A password in a URL reaches the process list when the URL is part of
    a '-command=' argument, where any user on the machine can read it.
    The core reads LINSCP_PASSWORD into every session it opens, so the
    password travels in the environment instead - readable only by this
    user - and the URL carries the user name alone. Pass
    include_password=True only for a URL that stays inside this process
    (never one placed on a command line).
    """
    proto = session_protocol_name(
        session.get("protocol") or "sftp", session.get("ftps"))
    host = session.get("host") or "localhost"
    port = int(session.get("port") or default_port(proto))
    user = session.get("username") or ""
    password = (session.get("password") or "") if include_password else ""
    url = proto + "://"
    if user:
        url += urllib.parse.quote(user, safe="")
        if password:
            url += ":" + urllib.parse.quote(password, safe="")
        url += "@"
    if ":" in host and not host.startswith("["):
        url += "[" + host + "]"
    else:
        url += host
    # The port is written whenever it is not the protocol's own default.
    # Comparing with the SSH port alone sent an FTP site stored with port
    # 22 to the FTP default and an SFTP site on port 21 to port 21 only
    # by accident; the protocol decides which port is implied.
    if port and port != default_port(proto):
        url += ":%d" % port
    url += "/"
    if path:
        url += urllib.parse.quote(path.lstrip("/"), safe="/")
    return url


def core_command_line(session):
    """Build safe process arguments for a session.

    A blank host-key field means "verify it", not "accept anything". The
    previous fallback to ``*`` silently disabled SSH host-key checking and
    TLS certificate verification for every queued operation. Passwords are
    never process arguments: the core reads LINSCP_PASSWORD from its
    per-session environment, and GUI commands travel over its stdin protocol.
    """
    cmd = [find_linscp_binary(), "-batch=on"]
    if not isinstance(session, dict):
        return cmd
    hostkey = str(session.get("hostkey") or "").strip()
    if hostkey:
        cmd.append("-hostkey=" + hostkey)
    if session.get("keyfile"):
        cmd.append("-privatekey=" + str(session["keyfile"]))
    if session.get("username"):
        cmd.append("-username=" + str(session["username"]))
    if session.get("tunnel"):
        error = validate_session_data(session)
        if error:
            raise ValueError(error)
        settings = []
        for field, name in TUNNEL_RAW_FIELDS.items():
            if field in ("tunnel_password", "tunnel_passphrase"):
                continue
            default = 22 if field == "tunnel_port" else (
                0 if field == "tunnel_local_port" else "")
            value = "1" if field == "tunnel" else str(session.get(field, default))
            settings.append(name + "=" + value)
    else:
        settings = []
    settings += gssapi_raw_settings(session)
    if settings:
        cmd += ["-rawsettings=" + str(len(settings))] + settings
    return cmd


def _censored_command(text):
    """Compatibility helper; every log path shares the same credential mask."""
    return redact_command_for_log(text, replacement="***", preserve_quotes=True)


# ---------------------------------------------------------------------------
# Running the console client
# ---------------------------------------------------------------------------

def ui_language(environment=None):
    """Messages only: never call setlocale or change protocol number formats."""
    environment = os.environ if environment is None else environment
    value = next((environment.get(key) for key in
                  ("LINSCP_LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG")
                  if environment.get(key)), "en")
    base = re.split(r"[-_.@]", value.lower())[0]
    return "es" if base == "es" else "en"


def popen_kwargs(password=None, session=None):
    # These processes speak an internal machine protocol. Browser messages
    # are localized separately; changing these diagnostics breaks parsers.
    # Only the GUI's explicit Remember action may persist a key. In
    # particular, accepting one hop must not cache the other hop's pin.
    environment = dict(os.environ, LINSCP_LANGUAGE="en", LINSCP_CACHE_PINNED_HOSTKEYS="0")
    if password:
        # The password of the session, where the process list cannot see
        # it: the core reads LINSCP_PASSWORD into every session it opens.
        # An empty password is left unset so that a password exported for
        # another purpose is not silently reused here.
        environment["LINSCP_PASSWORD"] = password
    else:
        environment.pop("LINSCP_PASSWORD", None)
    for field, name in (("tunnel_password", "LINSCP_TUNNEL_PASSWORD"),
                        ("tunnel_passphrase", "LINSCP_TUNNEL_PASSPHRASE")):
        value = (session or {}).get(field) if (session or {}).get("tunnel") else None
        if value:
            environment[name] = value
        else:
            environment.pop(name, None)
    kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "env": environment,
    }
    return kwargs


def split_linscp_commands(text):
    """Split semicolon-separated commands without splitting quoted data.

    This mirrors PathUtil::SplitCommands. GUI-generated commands are sent
    one at a time over ``-server`` stdin, both to keep credentials out of
    argv and to preserve literal percent signs in file names.
    """
    if not isinstance(text, str):
        raise ValueError("A LinSCP command must be text.")
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError("A LinSCP command must not contain control characters.")
    result = []
    current = []
    quote = ""
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\" and quote == '"' and index + 1 < len(text):
                current.extend((char, text[index + 1]))
                index += 2
                continue
            current.append(char)
            if char == quote:
                quote = ""
        elif char in ("'", '"'):
            quote = char
            current.append(char)
        elif char == "\\" and index + 1 < len(text):
            current.extend((char, text[index + 1]))
            index += 2
            continue
        elif char == ";":
            part = "".join(current).strip()
            if part:
                result.append(part)
            current = []
        else:
            current.append(char)
        index += 1
    part = "".join(current).strip()
    if part:
        result.append(part)
    return result


def redact_command_for_log(command, replacement="<redacted>", preserve_quotes=False):
    """Mask credentials in both Name="value" and "Name=value" spellings."""
    token_pattern = r"(?:[^\s\"'\\]+|\\.|\"(?:\\.|[^\"])*\"|'[^']*')+"
    secret_pattern = re.compile(r"(?i)(?:-password|-passphrase|proxypassword|tunnelpassword|tunnelpassphrase)(?:plain)?=")

    def redact_token(match):
        token = match.group()
        secret = secret_pattern.search(token)
        if secret:
            prefix = token[:secret.end()].lstrip('\"\'')
            quote = token[secret.end():secret.end() + 1]
            if preserve_quotes and quote in ("'", '"'):
                return prefix + quote + replacement + quote
            return prefix + replacement
        return token

    text = re.sub(token_pattern, redact_token, command)
    return re.sub(
        r'(?i)([a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@/\s]*@',
        lambda match: match.group(1) + replacement + "@", text)


class CoreCommandProcess:
    """A short-lived, line-protocol core process with bounded command waits."""

    def __init__(self, session=None):
        self.session = session
        self.process = None
        self.events = queue.Queue()
        self.pending_events = []
        self.deferred_errors = []

    def _pump(self, stream, name):
        try:
            for line in stream:
                self.events.put((name, line.rstrip("\r\n")))
        except (OSError, ValueError):
            pass
        finally:
            self.events.put((name, None))

    def _next_event(self, timeout):
        if self.pending_events:
            return self.pending_events.pop(0)
        return self.events.get(timeout=timeout)

    def _drain_after_result(self, errors, on_error):
        # Stdout and stderr are separate pipes. The core writes an error to
        # stderr before its result marker on stdout, but the reader threads
        # can enqueue those lines in the opposite order. Briefly drain the
        # already-written diagnostics before returning this command's result.
        started = time.monotonic()
        quiet_until = started + 0.04
        deadline = started + 0.2
        pending = []
        while time.monotonic() < quiet_until and time.monotonic() < deadline:
            wait = min(quiet_until - time.monotonic(),
                       deadline - time.monotonic())
            if wait <= 0:
                break
            try:
                event = self.events.get(timeout=wait)
            except queue.Empty:
                break
            if event[0] == "stderr" and event[1] is not None:
                errors.append(event[1])
                if on_error is not None:
                    on_error(event[1])
            else:
                pending.append(event)
            quiet_until = time.monotonic() + 0.04
        self.pending_events.extend(pending)

    def start(self, timeout=15):
        command = core_command_line(self.session) + ["-server"]
        self.process = subprocess.Popen(
            command, **popen_kwargs(self.session.get("password"), self.session))
        for name, stream in (("stdout", self.process.stdout),
                             ("stderr", self.process.stderr)):
            threading.Thread(target=self._pump, args=(stream, name),
                             daemon=True).start()
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.terminate()
                raise RuntimeError("The LinSCP core server did not start in time.")
            try:
                name, line = self.events.get(timeout=remaining)
            except queue.Empty:
                self.terminate()
                raise RuntimeError("The LinSCP core server did not start in time.")
            if name == "stderr":
                if line is None:
                    continue
                self.deferred_errors.append(line)
                continue
            if line is None:
                detail = "\n".join(self.deferred_errors).strip()
                raise RuntimeError(detail or "The LinSCP core server ended before it was ready.")
            if line.startswith("LSCP-SERVER "):
                return

    def run_command(self, command, timeout=120, on_output=None, on_error=None,
                    on_wait=None, should_cancel=None):
        if self.process is None or self.process.poll() is not None:
            return 1, [], ["The LinSCP core server is not running."]
        if not isinstance(command, str) or any(
                ord(char) < 32 or ord(char) == 127 for char in command):
            return 1, [], ["A LinSCP command must be a single line without control characters."]
        try:
            self.process.stdin.write(command + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError):
            return 1, [], ["The LinSCP core server is not accepting commands."]

        output = []
        errors = self.deferred_errors
        self.deferred_errors = []
        deadline = time.monotonic() + timeout if timeout and timeout > 0 else None
        interrupt_sent = False
        kill_deadline = None
        while True:
            if on_wait is not None:
                on_wait()
            if should_cancel is not None and should_cancel() and not interrupt_sent:
                interrupt_sent = True
                kill_deadline = time.monotonic() + 2
                try:
                    self.process.send_signal(signal.SIGINT)
                except OSError:
                    pass
            if interrupt_sent and kill_deadline is not None and \
                    time.monotonic() >= kill_deadline and self.process.poll() is None:
                try:
                    self.process.kill()
                except OSError:
                    pass
                kill_deadline = None
            if deadline is not None and time.monotonic() >= deadline:
                self.terminate()
                errors.append("The LinSCP command timed out.")
                return 1, output, errors
            wait = 0.2
            if deadline is not None:
                wait = max(0.01, min(wait, deadline - time.monotonic()))
            try:
                name, line = self._next_event(wait)
            except queue.Empty:
                if self.process.poll() is not None:
                    return 1, output, errors + ["The LinSCP core server ended unexpectedly."]
                continue
            if name == "stderr":
                if line is None:
                    continue
                errors.append(line)
                if on_error is not None:
                    on_error(line)
                continue
            if line is None:
                return 1, output, errors + ["The LinSCP core server ended unexpectedly."]
            match = re.fullmatch(r"LSCP-RESULT ([0-9]+)", line)
            if match:
                self._drain_after_result(errors, on_error)
                return int(match.group(1)), output, errors
            output.append(line)
            if on_output is not None:
                on_output(line)

    def _close_streams(self):
        if self.process is None:
            return
        for name in ("stdin", "stdout", "stderr"):
            stream = getattr(self.process, name, None)
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass

    def terminate(self):
        if self.process is None:
            return
        try:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        finally:
            self._close_streams()

    def close(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            try:
                self.run_command("exit", timeout=5)
            except Exception:
                pass
            try:
                self.process.stdin.close()
            except (AttributeError, OSError, ValueError):
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.terminate()
        self._close_streams()
        self.process = None


def run_linscp(command_script, session=None, timeout=300):
    """Run commands in a short-lived core process. Returns (code, out, err).

    Commands and site URLs travel over the server's stdin protocol instead
    of appearing in ``/proc/<pid>/cmdline``; the password is supplied only
    through that process's per-session environment. Running each command
    separately also preserves the old batch behavior:
    first failure stops the script rather than allowing later commands to
    act on a half-open session.
    """
    if not isinstance(command_script, str):
        return 1, "", "A LinSCP command must be text."
    session = session or new_session()
    bin_path = find_linscp_binary()
    add_log("Executing: " + redact_command_for_log(command_script), "cmd")
    try:
        commands = ["option confirm off"] + split_linscp_commands(command_script)
    except ValueError as exc:
        return 1, "", str(exc)
    runner = CoreCommandProcess(session)
    output, errors = [], []
    code = 1
    deadline = time.monotonic() + timeout if timeout and timeout > 0 else None
    try:
        start_timeout = 15 if deadline is None else max(
            0.01, min(15, deadline - time.monotonic()))
        runner.start(timeout=start_timeout)
        for command in commands:
            remaining = 0 if deadline is None else deadline - time.monotonic()
            if deadline is not None and remaining <= 0:
                errors.append("The LinSCP core timed out.")
                break
            code, lines, diagnostics = runner.run_command(
                command, timeout=remaining if deadline is not None else 0)
            output.extend(lines)
            errors.extend(diagnostics)
            if code != 0:
                break
    except (OSError, ValueError) as exc:
        message = ("Cannot start the LinSCP core binary '%s': %s. "
                   "Build it first (make -C source/linux) or put linscp "
                   "on PATH." % (bin_path, exc))
        add_log(message, "error")
        return 1, "", message
    except RuntimeError as exc:
        errors.extend(runner.deferred_errors)
        if str(exc):
            errors.append(str(exc))
        code = 1
    finally:
        runner.close()
    output = [redact_command_for_log(line) for line in output]
    errors = [redact_command_for_log(line) for line in errors]
    if errors:
        add_log("\n".join(errors).strip(), "error")
    return code, "\n".join(output), "\n".join(errors)


# ---------------------------------------------------------------------------
# A persistent session: one core process, one connection
# ---------------------------------------------------------------------------

class CoreSession(object):
    """A tab: a core process in server mode, with its connection open."""

    def __init__(self, tab_id, session, name=None):
        self.id = tab_id
        self.session = dict(session)
        self.remote_dir = session.get("initial_dir") or "/"
        self.local_dir = session.get("local_dir") or default_local_dir() or os.path.expanduser("~")
        jailed, jail_error = confined_local_path(self.local_dir)
        if not jail_error:
            self.local_dir = jailed
        elif ACCOUNTS_FILE and account_home_dir():
            self.local_dir = account_home_dir()
        self.other_local_dir = session.get("other_local_dir") or ""
        self.site_name = session.get("site") or ""
        # A local tab's default name is built from both pane directories,
        # so the fields have to exist before the name is decided.
        self.name = name or self._default_name()
        self.connected = False
        self.observed_hostkey = ""
        self.hostkey_role = "destination"
        self.hostkey_changed = False
        self.error = ""
        self.proc = None
        self.lock = threading.RLock()
        self._queue = None
        self._stderr = []
        self._stderr_lock = threading.Lock()
        self._stderr_events = queue.Queue()

    @property
    def is_local(self):
        return session_is_local(self.session)

    def _default_name(self):
        if self.is_local:
            left = os.path.basename(self.local_dir.rstrip(os.sep)) or self.local_dir
            right = os.path.basename(self.other_local_dir.rstrip(os.sep)) or self.other_local_dir
            return "%s \u2194 %s" % (left, right)
        host = self.session.get("host") or "localhost"
        user = self.session.get("username") or ""
        return "%s@%s" % (user, host) if user else host

    # -- process management ------------------------------------------------

    def start(self):
        if self.is_local:
            return True, ""
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                return True, ""
            cmd = core_command_line(self.session) + ["-server"]
            try:
                self.proc = subprocess.Popen(
                    cmd, **popen_kwargs(self.session.get("password"), self.session))
            except OSError as exc:
                self.error = str(exc)
                return False, self.error
            self._queue = queue.Queue()
            event_queue = self._queue
            self._stderr_events = queue.Queue()
            stderr_events = self._stderr_events
            process = self.proc
            threading.Thread(target=self._read_stdout,
                             args=(process.stdout, event_queue), daemon=True).start()
            threading.Thread(target=self._read_stderr,
                             args=(process.stderr, stderr_events), daemon=True).start()
            deadline = time.monotonic() + 15
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.error = "The core process did not start."
                    self.terminate()
                    return False, self.error
                try:
                    line = event_queue.get(timeout=remaining)
                except queue.Empty:
                    self.error = "The core process did not start."
                    self.terminate()
                    return False, self.error
                if line is None:
                    self.error = "The core process ended before it started."
                    self.terminate()
                    return False, self.error
                if line.startswith("LSCP-SERVER "):
                    return True, ""

    def connect(self):
        if self.is_local:
            error = validate_local_panes(self.local_dir, self.other_local_dir)
            if error:
                self.connected = False
                self.error = error
                return False, error
            self.local_dir = os.path.abspath(self.local_dir)
            self.other_local_dir = os.path.abspath(self.other_local_dir)
            self.remote_dir = self.other_local_dir
            # A local browser has no server to log in to: there is no host,
            # user, password, key or tunnel. Clearing them keeps a session
            # created from the site-manager form (which fills in its last
            # protocol's fields) from looking like a connection that could
            # be made, or storing credentials it never used.
            for key in ("host", "username", "password", "keyfile",
                        "hostkey", "tunnel_host", "tunnel_username",
                        "tunnel_password", "tunnel_private_key",
                        "tunnel_passphrase", "tunnel_hostkey", "tunnel_error"):
                self.session[key] = ""
            self.session["tunnel"] = False
            self.session["port"] = 0
            self.connected = True
            self.error = ""
            return True, ""
        ok, error = self.start()
        if not ok:
            self.connected = False
            self.error = error
            return False, error
        self.observed_hostkey = ""
        self.hostkey_role = "destination"
        self.hostkey_changed = False
        path = self.session.get("initial_dir") or "/"
        code, output, errors = self.run_capture(
            "open " + quote_remote(session_url(self.session, path)))
        # Whatever the server offered is worth remembering, connected or
        # not: a refused connection is exactly when a client needs it, to
        # offer pinning the key that was turned down.
        for line in output + errors:
            if line.startswith(("HOSTKEY ", "TUNNELHOSTKEY ")):
                self.observed_hostkey = line.split(" ", 2)[-1].strip()
                self.hostkey_role = "tunnel" if line.startswith("TUNNELHOSTKEY ") else "destination"
            elif line == "HOSTKEYSTATE %s changed" % self.hostkey_role:
                self.hostkey_changed = True
        if code != 0:
            detail = output + errors
            self.error = redact_command_for_log(
                "\n".join(detail).strip() or "Cannot connect.")
            self.connected = False
            return False, self.error
        self.run("option confirm off")
        code, output = self.run("pwd")
        if code == 0:
            for line in output:
                if line.startswith("/"):
                    self.remote_dir = line.strip()
                    break
        self.connected = True
        self.error = ""
        return True, ""

    def run_many(self, commands, timeout=120):
        """Run several commands, stopping at the first failure.

        The server takes one command per line; unlike '-command=' it does
        not split a line on ';'.
        """
        code, lines, errors = 0, [], []
        for command in commands:
            code, output, errs = self.run_capture(command, timeout=timeout)
            lines.extend(output)
            errors.extend(errs)
            if code != 0:
                break
        return code, lines

    def run_many_capture(self, commands, timeout=120):
        """run_many that also reports what the core wrote to stderr."""
        code, lines, errors = 0, [], []
        for command in commands:
            code, output, errs = self.run_capture(command, timeout=timeout)
            lines.extend(output)
            errors.extend(errs)
            if code != 0:
                break
        return code, lines, errors

    def _read_stdout(self, stream, event_queue):
        try:
            for line in stream:
                event_queue.put(line.rstrip("\r\n"))
        except (ValueError, OSError):
            pass
        event_queue.put(None)

    def _read_stderr(self, stream, event_queue):
        try:
            for line in stream:
                text = redact_command_for_log(line.strip())
                if text:
                    add_log("[%s] %s" % (self.name, text), "error")
                    with self._stderr_lock:
                        self._stderr.append(text)
                    event_queue.put(text)
        except (ValueError, OSError):
            pass
        finally:
            event_queue.put(None)

    def _settle_stderr(self):
        """Let diagnostics already written before the result marker drain."""
        started = time.monotonic()
        quiet_until = started + 0.04
        deadline = started + 0.2
        while time.monotonic() < quiet_until and time.monotonic() < deadline:
            wait = min(quiet_until - time.monotonic(),
                       deadline - time.monotonic())
            if wait <= 0:
                break
            try:
                self._stderr_events.get(timeout=wait)
            except queue.Empty:
                break
            quiet_until = time.monotonic() + 0.04

    def _stderr_snapshot(self):
        with self._stderr_lock:
            return list(self._stderr)

    def alive(self):
        if self.is_local:
            return self.connected
        return self.proc is not None and self.proc.poll() is None

    def run(self, command, timeout=120):
        """Run one command in the session. Returns (code, output lines)."""
        code, lines, _ = self.run_capture(command, timeout)
        return code, lines

    def run_capture(self, command, timeout=120):
        """Run one command, also reporting what the core wrote to stderr."""
        if self.is_local:
            return 1, ["The local panel has no server session."], []
        with self.lock:
            if not self.alive():
                if not self.connected:
                    return 1, ["Not connected."], []
                prev_remote = self.remote_dir
                reconnected, error = self.connect()
                if not reconnected or not self.alive():
                    self.connected = False
                    return 1, [error or "The session process is gone."], []
                if prev_remote and prev_remote != self.remote_dir:
                    try:
                        self.run_capture("cd " + quote_remote(prev_remote),
                                         timeout=30)
                        self.remote_dir = prev_remote
                    except ValueError:
                        pass
            with self._stderr_lock:
                self._stderr.clear()
            # The core reads one command per line, so a command that holds
            # a newline is really two commands and the second one was
            # supplied by whatever reached this point - a file name on the
            # server, a query parameter, a dropped path. Refusing it here
            # protects every caller at once, including the ones that
            # forget to quote.
            if "\n" in command or "\r" in command:
                return 1, ["Refused: a command must be a single line."], []
            try:
                self.proc.stdin.write(command + "\n")
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                self.connected = False
                return 1, ["The session process is gone."], []
            lines = []
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.terminate()
                    self._settle_stderr()
                    self.connected = False
                    return 1, lines + ["The command timed out after %d seconds." % timeout], \
                        self._stderr_snapshot()
                try:
                    line = self._queue.get(timeout=min(remaining, 0.5))
                except queue.Empty:
                    continue
                if line is None:
                    self._settle_stderr()
                    self.connected = False
                    return 1, lines + ["The session process ended unexpectedly."], \
                        self._stderr_snapshot()
                match = re.fullmatch(r"LSCP-RESULT ([0-9]+)", line)
                if match:
                    self._settle_stderr()
                    return int(match.group(1)), lines, self._stderr_snapshot()
                lines.append(line)

    def terminate(self):
        with self.lock:
            process = self.proc
            if process is None:
                return
            try:
                if process.poll() is None:
                    process.kill()
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except Exception:
                pass
            for name in ("stdin", "stdout", "stderr"):
                stream = getattr(process, name, None)
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
            self.proc = None
            self.connected = False

    close = terminate

    def hostkey_challenge(self):
        prefix = "tunnel_" if self.hostkey_role == "tunnel" else ""
        return {"tab": self.id, "host": self.session.get(prefix + "host"),
                "port": self.session.get(prefix + "port", 22),
                "fingerprint": self.observed_hostkey, "role": self.hostkey_role,
                "changed": self.hostkey_changed}

    def describe(self):
        return {
            "id": self.id,
            "name": self.name,
            "connected": self.connected and self.alive(),
            "is_local": self.is_local,
            "session": {key: value for key, value in self.session.items()
                        if key not in ("password", "tunnel_password", "tunnel_passphrase")},
            "remote_dir": self.remote_dir,
            "local_dir": self.local_dir,
            "other_local_dir": self.other_local_dir,
            "site": self.site_name,
            "observed_hostkey": self.observed_hostkey,
            "error": self.error,
        }


def get_tab(tab_id=None):
    with STATE_LOCK:
        if not STATE["tabs"]:
            return None
        if tab_id is None:
            tab_id = STATE["active_tab"]
            if tab_id is None:
                return STATE["tabs"][0]
        for tab in STATE["tabs"]:
            if str(tab.id) == str(tab_id):
                return tab
        # An explicit stale or malformed tab id must not silently operate
        # on the first (possibly unrelated) connection.
        return None


def require_tab(tab_id=None):
    tab = get_tab(tab_id)
    if tab is None or not tab.connected:
        return None
    return tab


# ---------------------------------------------------------------------------
# Named workspaces (upstream TStoredSessionList's NewWorkspace/GetWorkspaces)
# ---------------------------------------------------------------------------
#
# A workspace is a named, ordered group of tabs with both pane paths and the
# active tab. It is not a stored-session folder: a folder groups sites, while
# a workspace restores what the Commander was showing. The file holds no
# passwords and no tunnel credentials. A tab opened from a stored site
# records that site's name and reopens the site from sessions.ini, so the
# site's own password encryption, host-key pin and credential policy are the
# ones that apply. An ad-hoc tab records a sanitized session without secrets;
# on restore it may need a password again, and a host-key decision is still
# required if the key was never pinned.

WORKSPACE_VERSION = 1
WORKSPACE_LOCK = threading.RLock()


class WorkspaceExists(ValueError):
    pass


def workspace_store_path():
    return os.path.join(os.path.dirname(session_store_path()), "workspaces.json")


def validate_workspace_name(name):
    if not isinstance(name, str):
        raise ValueError("The workspace name must be text.")
    name = name.strip()
    if not name:
        raise ValueError("A workspace name is required.")
    if len(name) > 128:
        raise ValueError("The workspace name is too long (maximum 128 characters).")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("The workspace name must not contain control characters.")
    if "/" in name or "\\" in name:
        raise ValueError("A workspace name cannot contain a path separator.")
    if name in (".", ".."):
        raise ValueError("That is not a workspace name.")
    return name


def _empty_workspace_store():
    return {"version": WORKSPACE_VERSION, "workspaces": {}}


def read_workspace_store():
    path = workspace_store_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return _empty_workspace_store()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError("Cannot read the workspace file: %s" % exc)
    if not isinstance(data, dict) or not isinstance(data.get("workspaces"), dict):
        raise ValueError("The workspace file is not a valid workspace collection.")
    return data


def write_workspace_store(data):
    path = workspace_store_path()
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, prefix=".workspaces-",
        delete=False)
    temporary = handle.name
    try:
        os.chmod(temporary, 0o600)
        with handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _workspace_session_snapshot(session):
    """A session that may be written down: every credential removed."""
    snapshot = dict(session or {})
    for secret in ("password", "tunnel_password", "tunnel_passphrase"):
        snapshot.pop(secret, None)
    snapshot.pop("site", None)
    return snapshot


def capture_workspace_tabs():
    """The current tabs as workspace entries, in tab order."""
    with STATE_LOCK:
        tabs = list(STATE["tabs"])
        active = STATE["active_tab"]
    stored = {item["name"]: item for item in read_stored_sessions()}
    entries = []
    active_index = 0
    for index, tab in enumerate(tabs):
        if str(tab.id) == str(active):
            active_index = index
        if getattr(tab, "is_local", False):
            entries.append({
                "kind": "local",
                "name": tab.name,
                "local_dir": tab.local_dir,
                "other_local_dir": tab.other_local_dir,
            })
            continue
        entry = {
            "kind": "remote",
            "name": tab.name,
            "local_dir": tab.local_dir,
            "remote_dir": tab.remote_dir,
        }
        if tab.site_name and tab.site_name in stored:
            entry["site"] = tab.site_name
        else:
            entry["session"] = _workspace_session_snapshot(tab.session)
        entries.append(entry)
    return {"tabs": entries, "active": active_index}


def list_workspaces():
    data = read_workspace_store()
    result = []
    for name, record in data["workspaces"].items():
        if not isinstance(record, dict):
            continue
        tabs = record.get("tabs") if isinstance(record.get("tabs"), list) else []
        result.append({
            "name": name,
            "tab_count": len(tabs),
            "active": record.get("active", 0),
            "updated": record.get("updated", 0),
            "tabs": [{
                "name": tab.get("name", ""),
                "kind": tab.get("kind", "remote"),
                "site": tab.get("site", ""),
                "local_dir": tab.get("local_dir", ""),
                "remote_dir": tab.get("remote_dir", ""),
            } for tab in tabs if isinstance(tab, dict)],
        })
    result.sort(key=lambda item: item["name"].lower())
    return result


def save_workspace(name, overwrite=False):
    name = validate_workspace_name(name)
    captured = capture_workspace_tabs()
    if not captured["tabs"]:
        raise ValueError("There are no open tabs to save.")
    with WORKSPACE_LOCK:
        data = read_workspace_store()
        if name in data["workspaces"] and not overwrite:
            raise WorkspaceExists(
                "A workspace named \"%s\" already exists." % name)
        data["workspaces"][name] = {
            "tabs": captured["tabs"],
            "active": captured["active"],
            "updated": int(time.time()),
        }
        write_workspace_store(data)
    add_log("Saved workspace '%s' (%d tab(s))." %
            (name, len(captured["tabs"])), "success")
    return {"name": name, "tab_count": len(captured["tabs"]),
            "active": captured["active"]}


def delete_workspace(name):
    name = validate_workspace_name(name)
    with WORKSPACE_LOCK:
        data = read_workspace_store()
        if name not in data["workspaces"]:
            raise ValueError("No workspace named \"%s\" exists." % name)
        del data["workspaces"][name]
        write_workspace_store(data)
    add_log("Deleted workspace '%s'." % name, "info")
    return True


def _workspace_tab_session(entry, stored):
    """Build one tab's session from a workspace entry.

    Returns (session, site_name, error). A site reference is resolved from
    sessions.ini every time, never from a copy saved in the workspace file:
    that is what keeps a stored password, a pinned host key and a changed
    site definition authoritative after a restart.
    """
    if not isinstance(entry, dict):
        return None, "", "The workspace entry is not an object."
    if entry.get("kind") == "local":
        session = dict(new_session())
        session["protocol"] = "local"
        session["local_dir"] = entry.get("local_dir") or ""
        session["other_local_dir"] = entry.get("other_local_dir") or ""
        session["initial_dir"] = session["other_local_dir"]
        session["host"] = ""
        return session, "", ""
    site_name = entry.get("site") or ""
    if site_name:
        site = stored.get(site_name)
        if site is None:
            return None, site_name, ("The stored site \"%s\" used by this "
                                     "workspace no longer exists." % site_name)
        session = dict(site)
        session["site"] = site_name
        session["local_dir"] = entry.get("local_dir") or session.get("local_dir") or ""
        session["initial_dir"] = entry.get("remote_dir") or session.get("initial_dir") or "/"
        return session, site_name, ""
    snapshot = entry.get("session")
    if not isinstance(snapshot, dict):
        return None, "", "The workspace entry has no site or session."
    session = dict(snapshot)
    session["local_dir"] = entry.get("local_dir") or session.get("local_dir") or ""
    session["initial_dir"] = entry.get("remote_dir") or session.get("initial_dir") or "/"
    return session, "", ""


def restore_workspace(name):
    """Open the tabs of a named workspace, in order and independently.

    A tab that cannot connect does not stop the others: the caller gets the
    tabs that opened and the failures by name. A stored site that was
    deleted or renamed is a failure, not a reason to connect somewhere with
    stale credentials. A host-key challenge is parked in the normal
    challenge table, so the user can verify it exactly as after 'Connect'.
    """
    name = validate_workspace_name(name)
    with WORKSPACE_LOCK:
        data = read_workspace_store()
    record = data["workspaces"].get(name)
    if not isinstance(record, dict):
        raise ValueError("No workspace named \"%s\" exists." % name)
    entries = record.get("tabs")
    if not isinstance(entries, list) or not entries:
        raise ValueError("The workspace has no tabs.")
    stored = {item["name"]: item for item in read_stored_sessions()}
    opened = []
    failed = []
    active_opened = None
    saved_active = record.get("active", 0)
    try:
        saved_active = int(saved_active)
    except (TypeError, ValueError):
        saved_active = 0
    for index, entry in enumerate(entries):
        session, site_name, error = _workspace_tab_session(entry, stored)
        label = (entry.get("name") if isinstance(entry, dict) else "") or             site_name or ("tab %d" % (index + 1))
        if error:
            failed.append({"name": label, "site": site_name, "error": error})
            continue
        error = validate_session_data(session, require_host=not session_is_local(session))
        if error:
            failed.append({"name": label, "site": site_name, "error": error})
            continue
        with STATE_LOCK:
            tab_id = STATE["next_tab"]
            STATE["next_tab"] += 1
        tab = CoreSession(tab_id, session, name=entry.get("name") or None)
        ok, error = tab.connect()
        if not ok:
            challenge = None
            if tab.observed_hostkey:
                challenge = tab.hostkey_challenge()
                with STATE_LOCK:
                    STATE["challenges"][tab.id] = tab
                add_log("Host key offered by %s: %s" %
                        (session.get("host"), tab.observed_hostkey), "info")
            else:
                tab.terminate()
            failed.append({"name": label, "site": site_name,
                           "error": error, "challenge": challenge})
            continue
        opened.append(tab)
        if index == saved_active:
            active_opened = tab.id
    with STATE_LOCK:
        for tab in opened:
            if tab not in STATE["tabs"]:
                STATE["tabs"].append(tab)
        if active_opened is not None:
            STATE["active_tab"] = active_opened
        elif opened:
            STATE["active_tab"] = opened[0].id
        elif STATE["tabs"]:
            STATE["active_tab"] = STATE["tabs"][0].id
    add_log("Opened workspace '%s': %d tab(s) opened, %d failed." %
            (name, len(opened), len(failed)), "success" if not failed else "error")
    return {
        "name": name,
        "opened": [tab.id for tab in opened],
        "failed": failed,
        "active_tab": active_opened if active_opened is not None else (
            opened[0].id if opened else None),
    }


# ---------------------------------------------------------------------------
# Directory bookmarks (upstream TBookmarks / TBookmarkList)
# ---------------------------------------------------------------------------
#
# Upstream keeps a separate bookmark list for each panel and for each scope
# (local and remote), with a name, a directory and an optional shortcut. The
# Commander stores the same two lists beside sessions.ini, one file for this
# user, with no credentials and no host data: a bookmark names a directory,
# nothing else. A path is validated when it is written and again when it is
# used, so a file edited by hand cannot make the local pane leave its jail.

BOOKMARK_VERSION = 1
BOOKMARK_SIDES = ("local", "remote")
BOOKMARK_MAX_NAME = 128
BOOKMARK_MAX_PATH = 4096
BOOKMARK_LOCK = threading.RLock()


def bookmark_store_path():
    return os.path.join(os.path.dirname(session_store_path()),
                        "bookmarks.json")


def _empty_bookmark_store():
    return {"version": BOOKMARK_VERSION,
            "bookmarks": {side: [] for side in BOOKMARK_SIDES}}


def _bookmark_entry(value):
    """One stored bookmark, or None when the record is not usable."""
    if not isinstance(value, dict):
        return None
    name = value.get("name")
    path = value.get("path")
    if not isinstance(name, str) or not isinstance(path, str):
        return None
    # A control character is refused before trimming: a trailing newline is
    # still a character no directory name contains, and silently trimming it
    # would hide the fact that the file says something else than it means.
    if any(ord(char) < 32 or ord(char) == 127 for char in name + path):
        return None
    name = name.strip()
    path = path.strip()
    if not name or not path:
        return None
    if len(name) > BOOKMARK_MAX_NAME or len(path) > BOOKMARK_MAX_PATH:
        return None
    return {"name": name, "path": path}


def read_bookmark_store():
    """The bookmark file, with every unusable record left out.

    A hand-edited or truncated entry is skipped rather than failing the
    whole list: one bad line must not hide the bookmarks that are fine.
    """
    path = bookmark_store_path()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return _empty_bookmark_store()
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ValueError("Cannot read the bookmark file: %s" % exc)
    if not isinstance(data, dict):
        raise ValueError("The bookmark file is not a bookmark collection.")
    bookmarks = data.get("bookmarks")
    if not isinstance(bookmarks, dict):
        raise ValueError("The bookmark file has no bookmark lists.")
    result = _empty_bookmark_store()
    for side in BOOKMARK_SIDES:
        entries = bookmarks.get(side)
        if not isinstance(entries, list):
            continue
        seen = set()
        for value in entries:
            entry = _bookmark_entry(value)
            if entry is None or entry["name"].lower() in seen:
                continue
            seen.add(entry["name"].lower())
            result["bookmarks"][side].append(entry)
        result["bookmarks"][side].sort(
            key=lambda item: item["name"].lower())
    return result


def write_bookmark_store(data):
    path = bookmark_store_path()
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, prefix=".bookmarks-",
        delete=False)
    temporary = handle.name
    try:
        os.chmod(temporary, 0o600)
        with handle:
            json.dump(data, handle, ensure_ascii=False, indent=2,
                      sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def validate_bookmark(side, name, path):
    """A bookmark as it may be stored. Returns (side, name, path)."""
    side = str(side or "").strip().lower()
    if side not in BOOKMARK_SIDES:
        raise ValueError("A bookmark belongs to the local or the remote panel.")
    if not isinstance(name, str):
        raise ValueError("The bookmark name must be text.")
    if not isinstance(path, str):
        raise ValueError("The bookmark path must be text.")
    if any(ord(char) < 32 or ord(char) == 127 for char in name + path):
        raise ValueError("The bookmark must not contain control characters.")
    name = name.strip()
    path = path.strip()
    if not name:
        raise ValueError("A bookmark name is required.")
    if len(name) > BOOKMARK_MAX_NAME:
        raise ValueError("The bookmark name is too long (maximum %d characters)."
                         % BOOKMARK_MAX_NAME)
    if not path:
        raise ValueError("A bookmark path is required.")
    if len(path) > BOOKMARK_MAX_PATH:
        raise ValueError("The bookmark path is too long.")
    if side == "local":
        # The local pane is confined to the signed-in account's home (or the
        # whole file system when no accounts are configured); a bookmark that
        # names somewhere else would have to be refused when it was used, so
        # it is refused when it is stored.
        path, error = confined_local_path(path)
        if error:
            raise ValueError(error)
    else:
        if not path.startswith("/"):
            raise ValueError("A remote bookmark needs an absolute path.")
    return side, name, path


def list_bookmarks(side=None):
    data = read_bookmark_store()
    if side:
        side = str(side).strip().lower()
        if side not in BOOKMARK_SIDES:
            raise ValueError("There is no %s bookmark list." % side)
        return list(data["bookmarks"][side])
    return data["bookmarks"]


def add_bookmark(side, name, path):
    side, name, path = validate_bookmark(side, name, path)
    with BOOKMARK_LOCK:
        data = read_bookmark_store()
        entries = data["bookmarks"][side]
        replaced = False
        for entry in entries:
            if entry["name"].lower() == name.lower():
                entry["name"] = name
                entry["path"] = path
                replaced = True
                break
        if not replaced:
            entries.append({"name": name, "path": path})
        entries.sort(key=lambda item: item["name"].lower())
        write_bookmark_store(data)
    add_log("Saved the %s bookmark '%s'." % (side, name), "success")
    return {"side": side, "name": name, "path": path,
            "bookmarks": data["bookmarks"]}


def delete_bookmark(side, name):
    side = str(side or "").strip().lower()
    if side not in BOOKMARK_SIDES:
        raise ValueError("There is no %s bookmark list." % side)
    if not isinstance(name, str) or not name.strip():
        raise ValueError("A bookmark name is required.")
    name = name.strip()
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ValueError("The bookmark name is not usable.")
    with BOOKMARK_LOCK:
        data = read_bookmark_store()
        entries = data["bookmarks"][side]
        kept = [entry for entry in entries
                if entry["name"].lower() != name.lower()]
        if len(kept) == len(entries):
            raise ValueError("No %s bookmark named \"%s\" exists."
                             % (side, name))
        data["bookmarks"][side] = kept
        write_bookmark_store(data)
    add_log("Deleted the %s bookmark '%s'." % (side, name), "info")
    return {"side": side, "name": name, "bookmarks": data["bookmarks"]}


# ---------------------------------------------------------------------------
# Session URLs and transfer code (upstream Generate URL dialog)
# ---------------------------------------------------------------------------

def generate_session_url(tab, include_password=False, path=""):
    """The site URL and a safe 'open' line for the active tab.

    A password is included only when the caller asks for it explicitly, and
    the answer says so, because a URL with a password is a secret to copy
    somewhere else. Nothing here writes the URL to the log: the log is
    shared, the dialog is not.
    """
    if tab is None:
        raise ValueError("Not connected.")
    if getattr(tab, "is_local", False):
        raise ValueError("A local tab has no session URL.")
    session = dict(tab.session or {})
    target = (path or tab.remote_dir or session.get("initial_dir") or "/")
    if not isinstance(target, str) or any(
            ord(char) < 32 or ord(char) == 127 for char in target):
        raise ValueError("The path is not usable in a URL.")
    url = session_url(session, target, bool(include_password))
    safe_url = session_url(session, target, False)
    result = {
        "success": True,
        "url": url,
        "open_command": "open " + safe_url,
        "path": target,
        "include_password": bool(include_password and session.get("password")),
        "has_password": bool(session.get("password")),
        "protocol": session.get("protocol") or "sftp",
        "host": session.get("host") or "",
    }
    add_log("Generated a session URL for %s." %
            (session.get("host") or "the active site"), "cmd")
    return result


# ---------------------------------------------------------------------------
# Importing sessions from other clients (upstream Import Sessions)
# ---------------------------------------------------------------------------
#
# Upstream offers PuTTY, KiTTY, FileZilla, OpenSSH, its own .ini export and
# known_hosts. On Linux the two sources that exist are an OpenSSH client
# configuration and FileZilla's sitemanager.xml, so those are the two this
# server reads. The file is parsed here, not handed to the console client:
# a password from another client is encrypted with sessions.key before it is
# written, and an entry this build cannot represent is reported instead of
# being imported as something it is not.

IMPORT_MAX_BYTES = 4 * 1024 * 1024
IMPORT_MAX_ENTRIES = 1000
IMPORT_SOURCES = ("openssh", "filezilla")


def _import_source_paths(source):
    home = os.path.expanduser("~")
    if source == "openssh":
        return [os.path.join(home, ".ssh", "config")]
    if source == "filezilla":
        return [os.path.join(home, ".config", "filezilla",
                             "sitemanager.xml"),
                os.path.join(home, ".filezilla", "sitemanager.xml")]
    return []


def _read_import_file(path):
    path, error = confined_local_path(path)
    if error:
        raise ValueError(error)
    try:
        info = os.stat(path)
    except OSError as exc:
        raise ValueError("Cannot read '%s': %s" % (path, exc))
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("'%s' is not a regular file." % path)
    if info.st_size > IMPORT_MAX_BYTES:
        raise ValueError("'%s' is larger than the import limit (%d bytes)."
                         % (path, IMPORT_MAX_BYTES))
    try:
        with open(path, "r", encoding="utf-8", errors="strict") as handle:
            return path, handle.read(IMPORT_MAX_BYTES + 1)
    except UnicodeDecodeError:
        raise ValueError("'%s' is not UTF-8 text." % path)
    except OSError as exc:
        raise ValueError("Cannot read '%s': %s" % (path, exc))


def _import_entry(name, host, port, username="", password="", keyfile="",
                  protocol="sftp", local_dir="", remote_dir=""):
    """One candidate session, normalized and safe to put in sessions.ini."""
    name = (name or "").strip()
    host = (host or "").strip()
    username = (username or "").strip()
    keyfile = (keyfile or "").strip()
    local_dir = (local_dir or "").strip()
    remote_dir = (remote_dir or "").strip()
    if not name:
        name = host
    if not name:
        raise ValueError("The entry has no name.")
    if len(name) > 256:
        raise ValueError("The entry name is too long.")
    if not host:
        raise ValueError("The entry has no host name.")
    if any(ord(char) < 32 or ord(char) == 127
           for char in name + host + username + keyfile + local_dir +
           remote_dir + password):
        raise ValueError("The entry contains a control character.")
    if protocol not in ("sftp", "ftp", "ftps", "ftpes"):
        raise ValueError("The entry's protocol is not supported.")
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = default_port(protocol)
    if port < 1 or port > 65535:
        raise ValueError("The entry has an invalid port.")
    if protocol == "ftp" and not username:
        username = "anonymous"
    return {
        "name": name,
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "keyfile": keyfile,
        "protocol": protocol,
        "local_dir": local_dir,
        "remote_dir": remote_dir or "/",
    }


def parse_openssh_config(text):
    """Hosts of an OpenSSH client configuration.

    Returns (entries, skipped). Only a block whose 'Host' line names one
    plain alias is read: a wildcard, a negated pattern or a 'Match' block
    describes a rule rather than a site, and importing it would invent a
    host name nobody configured. 'Include' is reported instead of followed,
    so an import never walks to a file the caller did not name.
    """
    entries = []
    skipped = []
    current = None

    def finish():
        nonlocal current
        if current is not None:
            try:
                entries.append(_import_entry(
                    current["name"], current.get("hostname") or current["name"],
                    current.get("port", 22),
                    username=current.get("user", ""),
                    keyfile=current.get("identityfile", ""),
                    protocol="sftp"))
            except ValueError as exc:
                skipped.append({"name": current["name"],
                                "reason": str(exc)})
        current = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = re.split(r"(?:\s*=\s*|\s+)", stripped, maxsplit=1)
        keyword = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""
        if keyword in ("host", "match"):
            finish()
            if keyword == "match":
                skipped.append({"name": "Match block",
                                "reason": "Match blocks do not name a site."})
                continue
            try:
                patterns = shlex.split(value)
            except ValueError:
                patterns = value.split()
            if len(patterns) != 1 or any(
                    char in patterns[0] for char in "*?!") or not patterns[0]:
                skipped.append({
                    "name": value or "(empty Host)",
                    "reason": "Only a Host line with one plain alias is "
                              "imported."})
                continue
            current = {"name": patterns[0]}
            continue
        if keyword == "include":
            skipped.append({"name": "Include " + value,
                            "reason": "Included files are not followed."})
            continue
        if current is None:
            # A setting before the first Host applies to every host; it is
            # not a site of its own.
            continue
        if value and value[0] in ("'", '"'):
            try:
                unquoted = shlex.split(value)
                if len(unquoted) == 1:
                    value = unquoted[0]
            except ValueError:
                pass
        if keyword == "hostname" and value:
            current.setdefault("hostname", value)
        elif keyword == "user" and value:
            current.setdefault("user", value)
        elif keyword == "port" and value and "port" not in current:
            try:
                port = int(value)
            except ValueError:
                skipped.append({"name": current["name"],
                                "reason": "The port is not a number."})
                continue
            if port < 1 or port > 65535:
                skipped.append({"name": current["name"],
                                "reason": "The port is out of range."})
                continue
            current["port"] = port
        elif keyword == "identityfile" and value and "identityfile" not in current:
            if "%" in value:
                skipped.append({"name": current["name"],
                                "reason": "An IdentityFile with a % token "
                                          "is not imported."})
                continue
            current["identityfile"] = os.path.expanduser(value)
    finish()
    return entries, skipped


def _xml_text(element, tag):
    for child in element:
        if child.tag.split("}")[-1].lower() == tag.lower():
            return (child.text or "").strip()
    return ""


def parse_filezilla_xml(text):
    """Sites of a FileZilla sitemanager.xml.

    Returns (entries, skipped). A DOCTYPE or entity declaration is refused
    before parsing, so a crafted file cannot expand entities, and every
    field is checked for control characters. FileZilla's FileZilla3 and the
    older FileZillaServer root are both accepted.
    """
    lowered = text.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ValueError("The FileZilla file must not declare a DOCTYPE or "
                         "an entity.")
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ValueError("The FileZilla file is not valid XML: %s" % exc)
    servers = [element for element in root.iter()
               if element.tag.split("}")[-1].lower() == "server"]
    entries = []
    skipped = []
    for element in servers:
        name = _xml_text(element, "name")
        host = _xml_text(element, "host")
        protocol = _xml_text(element, "protocol")
        if protocol not in ("", "0", "1", "3", "4"):
            skipped.append({"name": name or host,
                            "reason": "The FileZilla protocol is not "
                                      "supported."})
            continue
        password = ""
        pass_elem = next(
            (child for child in element
             if child.tag.split("}")[-1].lower() == "pass"), None)
        encoded = (pass_elem.text or "").strip() if pass_elem is not None else ""
        pass_encoding = (pass_elem.attrib.get("encoding", "")
                         if pass_elem is not None else "").strip().lower()
        if encoded:
            if pass_encoding == "plain":
                password = encoded
            elif pass_encoding == "crypt":
                password = ""
            else:
                try:
                    password = base64.b64decode(encoded.encode("ascii"),
                                                validate=True).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    skipped.append({"name": name or host,
                                    "reason": "The stored FileZilla password is "
                                              "not valid base64 text."})
                    continue
        remote_dir = _xml_text(element, "remotedir")
        if remote_dir and not remote_dir.startswith("/"):
            # FileZilla writes length-prefixed segments ("1 0 3 srv 4 data")
            # or a prefix before a literal path; decode both cleanly.
            decoded_dir = ""
            tokens = remote_dir.split()
            if len(tokens) >= 2 and tokens[0].isdigit() and tokens[1].isdigit():
                try:
                    pos = 2
                    if int(tokens[1]) > 0:
                        pos += 1
                    segs = []
                    valid_fz = pos <= len(tokens)
                    while valid_fz and pos < len(tokens):
                        seg_len = int(tokens[pos])
                        if pos + 1 >= len(tokens) or len(tokens[pos + 1]) != seg_len:
                            valid_fz = False
                            break
                        segs.append(tokens[pos + 1])
                        pos += 2
                    if valid_fz and segs:
                        decoded_dir = "/" + "/".join(segs)
                except ValueError:
                    decoded_dir = ""
            if decoded_dir:
                remote_dir = decoded_dir
            else:
                candidate = tokens[-1] if tokens else ""
                remote_dir = candidate if candidate.startswith("/") else ""
        local_dir = _xml_text(element, "localdir")
        if local_dir and not local_dir.startswith("/"):
            local_dir = ""
        try:
            if protocol == "1":
                entry_protocol, default_import_port = "sftp", 22
            elif protocol == "3":
                # FileZilla's explicit TLS is upstream's 'ftpes://'.
                entry_protocol, default_import_port = "ftpes", 21
            elif protocol == "4":
                entry_protocol, default_import_port = "ftps", 990
            else:
                entry_protocol, default_import_port = "ftp", 21
            entries.append(_import_entry(
                name, host,
                _xml_text(element, "port") or default_import_port,
                username=_xml_text(element, "user"),
                password=password,
                keyfile=os.path.expanduser(_xml_text(element, "keyfile")),
                protocol=entry_protocol,
                local_dir=local_dir, remote_dir=remote_dir))
        except ValueError as exc:
            skipped.append({"name": name or host, "reason": str(exc)})
        if len(entries) >= IMPORT_MAX_ENTRIES:
            skipped.append({"name": "(further entries)",
                            "reason": "The import limit of %d sites was "
                                      "reached." % IMPORT_MAX_ENTRIES})
            break
    return entries, skipped


def scan_import_source(source, path=""):
    """One import source as the dialog lists it, without any password."""
    source = str(source or "").strip().lower()
    if source not in IMPORT_SOURCES:
        raise ValueError("Unknown import source '%s'." % source)
    candidates = [path] if path else _import_source_paths(source)
    errors = []
    for candidate in candidates:
        try:
            resolved, text = _read_import_file(candidate)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        try:
            if source == "openssh":
                entries, skipped = parse_openssh_config(text)
            else:
                entries, skipped = parse_filezilla_xml(text)
        except ValueError as exc:
            # A source that exists but cannot be read is reported in the
            # dialog with the reason, not as an endpoint failure: the user
            # can point the dialog at another file.
            return {"source": source, "path": resolved, "exists": True,
                    "entries": [], "skipped": [], "error": str(exc)}
        public = [{"name": entry["name"], "host": entry["host"],
                   "port": entry["port"],
                   "username": entry["username"],
                   "protocol": entry["protocol"],
                   "has_password": bool(entry["password"]),
                   "keyfile": entry["keyfile"]} for entry in entries]
        return {"source": source, "path": resolved, "exists": True,
                "entries": public, "skipped": skipped, "error": ""}
    return {"source": source, "path": candidates[0] if candidates else "",
            "exists": False, "entries": [], "skipped": [],
            "error": "; ".join(errors) or "The file does not exist."}


def scan_import_sources():
    """Every default source, including the ones that are not there."""
    return [scan_import_source(source) for source in IMPORT_SOURCES]


def _session_ini_block(entry, ini_path):
    """The [section] an imported entry becomes, password encrypted."""
    protocol = entry["protocol"]
    tls_mode = ""
    if protocol == "ftpes":
        # The console client stores explicit TLS as FTP with mode 3; that
        # is also how it reads the site back.
        protocol, tls_mode = "ftp", "ftps=3"
    elif protocol == "ftps":
        tls_mode = "ftps=1"
    lines = ["[%s]" % _escape(entry["name"]),
             "protocol=%s" % protocol]
    if tls_mode:
        lines.append(tls_mode)
    lines += ["host=%s" % _escape(entry["host"]),
              "port=%d" % entry["port"]]
    for key, field in (("username", "username"), ("private_key", "keyfile"),
                       ("remote_directory", "remote_dir"),
                       ("local_directory", "local_dir")):
        value = entry.get(field) or ""
        if value:
            lines.append("%s=%s" % (key, _escape(value)))
    password = entry.get("password") or ""
    if password:
        lines.append("password=%s" % _encrypt_stored_password(
            password, ini_path))
    lines.append("last_used=%d" % int(time.time()))
    return lines


def _encrypt_stored_password(password, ini_path):
    """Encrypt for sessions.ini, creating sessions.key exactly as the core does."""
    key_path = linscp_crypto.key_path_for(ini_path)
    try:
        key = linscp_crypto.load_key(key_path)
    except linscp_crypto.PasswordError as exc:
        if "does not exist" not in str(exc):
            raise ValueError(str(exc))
        # The console client creates the same 32 random bytes, base64 and
        # newline, mode 0600, and never overwrites a key another process
        # created at the same moment.
        os.makedirs(os.path.dirname(key_path) or ".", mode=0o700,
                    exist_ok=True)
        content = (base64.b64encode(os.urandom(32)).decode("ascii") +
                   "\n").encode("ascii")
        try:
            handle = os.open(key_path,
                             os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(handle, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
        key = linscp_crypto.load_key(key_path)
    return linscp_crypto.encrypt(password, key)


def _write_imported_sessions(imported, overwrite):
    """Merge imported sections into sessions.ini atomically.

    Existing sites are kept unless 'overwrite' says otherwise; the rest of
    the file - comments, folders, settings this module does not know - is
    copied through. Returns (imported names, skipped records).
    """
    path = session_store_path()
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except FileNotFoundError:
        lines = []
    preamble = []
    sections = []
    current = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = {"name": _unescape(stripped[1:-1]),
                       "lines": [line]}
            sections.append(current)
        elif current is None:
            preamble.append(line)
        else:
            current["lines"].append(line)
    existing = {section["name"].lower() for section in sections}
    output = list(preamble)
    added = []
    skipped = []
    for entry in imported:
        block = _session_ini_block(entry, path)
        replaced = False
        for section in sections:
            if section["name"].lower() != entry["name"].lower():
                continue
            if not overwrite:
                skipped.append({"name": entry["name"],
                                "reason": "A site with this name already "
                                          "exists."})
                replaced = True
                break
            section["lines"] = block
            replaced = True
            break
        if not replaced:
            if entry["name"].lower() in existing and not overwrite:
                skipped.append({"name": entry["name"],
                                "reason": "A site with this name already "
                                          "exists."})
                continue
            sections.append({"name": entry["name"], "lines": block})
            existing.add(entry["name"].lower())
            added.append(entry["name"])
        elif overwrite:
            added.append(entry["name"])
    for section in sections:
        output.extend(section["lines"])
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, prefix=".sessions-",
        delete=False)
    temporary = handle.name
    try:
        os.chmod(temporary, 0o600)
        with handle:
            handle.write("\n".join(output).rstrip("\n") + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return added, skipped


def import_sessions(source, path="", names=None, overwrite=False):
    """Import the named (or all) entries of one source into sessions.ini."""
    scanned = scan_import_source(source, path)
    if not scanned["exists"]:
        raise ValueError(scanned["error"] or "The import source does not exist.")
    resolved, text = _read_import_file(scanned["path"])
    if scanned["source"] == "openssh":
        entries, skipped = parse_openssh_config(text)
    else:
        entries, skipped = parse_filezilla_xml(text)
    wanted = None
    if names is not None:
        if not isinstance(names, list) or not all(
                isinstance(name, str) for name in names):
            raise ValueError("The selected sites must be a list of names.")
        wanted = {name.strip().lower() for name in names if name.strip()}
        if not wanted:
            raise ValueError("Select at least one site to import.")
    selected = [entry for entry in entries
                if wanted is None or entry["name"].lower() in wanted]
    if not selected:
        raise ValueError("No site of that source was selected.")
    added, merge_skipped = _write_imported_sessions(selected, bool(overwrite))
    add_log("Imported %d site(s) from %s." %
            (len(added), scanned["path"]), "success" if added else "info")
    return {"success": True, "source": scanned["source"],
            "path": resolved, "imported": added,
            "skipped": skipped + merge_skipped,
            "sessions": read_stored_sessions(),
            "file": session_store_path()}


# ---------------------------------------------------------------------------
# Preferences: the defaults a transfer and a confirmation start from
# ---------------------------------------------------------------------------

# The keys the dialog offers and the value each one may hold. The defaults
# are used as they are by the page until the user saves something else, so
# a first run behaves exactly as it did before the dialog existed.
PREFERENCE_DEFAULTS = {
    "transfer": "",            # '' = automatic, otherwise 'binary' or 'ascii'
    "filemask": "",
    "speed": 0,                # KiB/s, 0 = unlimited
    "resumesupport": "",       # '' = protocol default, 'on', 'off' or KiB
    "resume": True,
    "preserve_time": True,
    "newer_only": False,
    "append": False,
    "no_permissions": False,
    "priority": False,
    "confirm_overwrite": True,
    "confirm_delete": True,
}

PREFERENCE_TEXT_LIMITS = {"filemask": 1024, "resumesupport": 32}
PREFERENCE_SWITCHES = ("resume", "preserve_time", "newer_only", "append",
                       "no_permissions", "priority", "confirm_overwrite",
                       "confirm_delete")
MAX_PREFERENCES_BYTES = 64 * 1024


def preferences_path():
    return os.path.join(_config_root(), "preferences.json")


def _preference_error(key, message):
    return "The preference '%s' %s" % (key, message)


def check_preference(key, value):
    """Validate one preference value, or raise ValueError with the reason.

    A boolean is not a number here: 'true' stored where a speed belongs, or
    1 stored where a switch belongs, is refused rather than read as one of
    them, because either reading would be a guess about what was meant.
    """
    if key in PREFERENCE_SWITCHES:
        if not isinstance(value, bool):
            raise ValueError(_preference_error(key, "must be true or false."))
        return value
    if key == "transfer":
        if value not in ("", "automatic", "binary", "ascii"):
            raise ValueError(_preference_error(
                key, "must be automatic, binary or ascii."))
        return value
    if key == "speed":
        if isinstance(value, bool) or not isinstance(value, int) or \
                not 0 <= value <= 100000000:
            raise ValueError(_preference_error(
                key, "must be a whole number of KiB/s from 0 through 100000000."))
        return value
    if key in PREFERENCE_TEXT_LIMITS:
        if not isinstance(value, str):
            raise ValueError(_preference_error(key, "must be text."))
        if len(value) > PREFERENCE_TEXT_LIMITS[key]:
            raise ValueError(_preference_error(
                key, "must be at most %d characters long."
                % PREFERENCE_TEXT_LIMITS[key]))
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(_preference_error(
                key, "must not contain control characters."))
        if key == "resumesupport" and value not in ("", "on", "off") and \
                not re.fullmatch(r"\d{1,9}", value):
            raise ValueError(_preference_error(
                key, "must be 'on', 'off', a size in KiB or empty."))
        return value
    raise ValueError("The preference '%s' is not known." % key)


def check_preferences(values):
    """Validate a whole preferences document and return a clean copy."""
    if not isinstance(values, dict):
        raise ValueError("The preferences must be a JSON object.")
    clean = {}
    for key, value in values.items():
        if key not in PREFERENCE_DEFAULTS:
            raise ValueError("The preference '%s' is not known." % key)
        clean[key] = check_preference(key, value)
    return clean


def read_preferences():
    """The stored preferences, with anything unusable left at its default.

    A hand-edited file must not stop the client: an unknown key or a value
    of the wrong type is ignored here, while saving through the dialog
    refuses it. The result always has every key, so callers read a value
    without asking whether the file has it.
    """
    preferences = dict(PREFERENCE_DEFAULTS)
    path = preferences_path()
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read(MAX_PREFERENCES_BYTES + 1)
    except FileNotFoundError:
        return preferences
    except OSError as exc:
        add_log("Cannot read the preferences: %s" % exc, "error")
        return preferences
    if len(text) > MAX_PREFERENCES_BYTES:
        add_log("The preferences file is too large; using the defaults.", "error")
        return preferences
    try:
        stored = json.loads(text)
    except ValueError:
        add_log("The preferences file is not valid JSON; using the defaults.",
                "error")
        return preferences
    if not isinstance(stored, dict):
        add_log("The preferences file is not an object; using the defaults.",
                "error")
        return preferences
    for key, value in stored.items():
        if key not in PREFERENCE_DEFAULTS:
            continue
        try:
            preferences[key] = check_preference(key, value)
        except ValueError:
            continue
    return preferences


def write_preferences(values):
    """Validate and store the preferences atomically, readable by the owner."""
    clean = check_preferences(values)
    path = preferences_path()
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    temporary = path + ".tmp-%d" % os.getpid()
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(clean, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    add_log("Stored the preferences.", "success")
    return clean


# ---------------------------------------------------------------------------
# Cleanup: remove the data this client stores, one named location at a time
# ---------------------------------------------------------------------------

def _session_key_path(ini_path):
    """The key file that belongs to an ini path, as the core names it.

    'sessions.ini' pairs with 'sessions.key'; any other name gains '.key'.
    """
    stem, suffix = os.path.splitext(ini_path)
    if suffix.lower() == ".ini":
        return stem + ".key"
    return ini_path + ".key"


def _cleanup_candidates():
    """Every stored location, keyed by a stable id, in the order shown.

    The paths are computed here and never come from the request: the page
    names an id, and this table is the only thing that turns an id into a
    path, so a request cannot name a file to delete.
    """
    ini = session_store_path()
    directory = os.path.dirname(ini)
    return [
        ("sessions", "Stored sessions (sites, user names and host keys)",
         ini, "file"),
        ("passwords", "Stored passwords (sessions.key)",
         _session_key_path(ini), "file"),
        ("hostkeys", "Cached SSH host keys",
         os.path.join(directory, "sshhostkeys"), "file"),
        ("workspaces", "Saved workspaces", workspace_store_path(), "file"),
        ("bookmarks", "Saved bookmarks", bookmark_store_path(), "file"),
        ("commands", "Custom commands", _custom_commands_path(), "file"),
        ("preferences", "Preferences", preferences_path(), "file"),
        # These two directories are normally created on first use, so the
        # paths are built here rather than asked of the helpers: listing the
        # stored data must not create the data it is about to report.
        ("shell", "Pending file-manager uploads",
         os.path.join(_config_root(), "shell-manifests"), "directory"),
        ("editing", "Temporary copies of edited files",
         os.path.join(tempfile.gettempdir(), "linscp-gui-edit"), "directory"),
    ]


def cleanup_locations():
    """What the Cleanup dialog lists: id, caption, path and whether it exists."""
    locations = []
    for location_id, caption, path, kind in _cleanup_candidates():
        absolute = os.path.abspath(path)
        locations.append({"id": location_id, "caption": caption,
                          "path": absolute, "kind": kind,
                          "exists": os.path.lexists(absolute)})
    return locations


def _remove_cleanup_path(path, kind):
    """Remove one enumerated location; returns whether anything was removed."""
    if kind == "directory":
        if os.path.islink(path):
            os.unlink(path)
            return True
        if os.path.isdir(path):
            shutil.rmtree(path)
            return True
        return False
    if os.path.lexists(path):
        os.unlink(path)
        return True
    return False


def cleanup_data(ids):
    """Remove the selected stored locations.

    Removing data is not undoable, so the caller has to say which ids it
    means and the ids are matched against the table above. A location that
    is already gone is not an error - asking to remove it twice is not a
    failure - and the result reports each id so the page can say what
    happened to which.
    """
    if not isinstance(ids, list) or not ids:
        raise ValueError("Select at least one item to remove.")
    if any(not isinstance(item, str) or not item.strip() for item in ids):
        raise ValueError("The cleanup items must be named by id.")
    table = {entry["id"]: entry for entry in cleanup_locations()}
    root = os.path.realpath(_config_root())
    results = []
    for location_id in dict.fromkeys(ids):
        entry = table.get(location_id)
        if entry is None:
            raise ValueError("The cleanup item '%s' is not known." % location_id)
        path = entry["path"]
        if os.path.abspath(path) == root:
            raise ValueError("The configuration directory itself cannot be removed.")
        removed = False
        error = ""
        try:
            removed = _remove_cleanup_path(path, entry["kind"])
        except OSError as exc:
            error = str(exc)
        results.append({"id": location_id, "caption": entry["caption"],
                        "path": entry["path"], "removed": removed,
                        "error": error})
        if removed:
            add_log("Removed %s (%s)." % (entry["caption"], entry["path"]),
                    "success")
        elif error:
            add_log("Cannot remove %s: %s" % (entry["path"], error), "error")
    return results


# ---------------------------------------------------------------------------
# Properties and rights
# ---------------------------------------------------------------------------

def local_properties(path):
    """The properties dialog's rows for a local entry."""
    info = local_stat_info(path)
    permissions = info.get("permissions") or ""
    owner, _, group = (info.get("owner") or "").partition(":")
    link_target = ""
    if info.get("is_link"):
        try:
            link_target = os.readlink(path)
        except OSError:
            link_target = ""
    return {
        "name": os.path.basename(path.rstrip("/")) or path,
        "path": path,
        "is_dir": bool(info.get("is_dir")),
        "is_link": bool(info.get("is_link")),
        "size": info.get("size") or 0,
        "mtime": info.get("mtime") or 0,
        "permissions": permissions,
        "mode": permissions_to_mode(permissions),
        "owner": owner,
        "group": group,
        "link_target": link_target,
    }


def _parse_remote_attributes(raw, path):
    """Read the key/value lines 'attr' prints into a properties row."""
    row = {"name": os.path.basename(path.rstrip("/")) or path, "path": path,
           "is_dir": False, "is_link": False, "size": 0, "mtime": 0,
           "permissions": "", "mode": 0, "owner": "", "group": "",
           "link_target": ""}
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("Permissions:"):
            row["permissions"] = stripped.split(":", 1)[1].strip()
            row["is_dir"] = row["permissions"].startswith("d")
            row["is_link"] = row["permissions"].startswith("l")
        elif stripped.startswith("SizeBytes:"):
            try:
                row["size"] = int(stripped.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif stripped.startswith("ModifiedEpoch:"):
            try:
                row["mtime"] = int(stripped.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif stripped.startswith("Owner:"):
            owner = stripped.split(":", 1)[1].strip()
            if owner and owner != "unknown" and ":" in owner:
                row["owner"], row["group"] = owner.split(":", 1)
            elif owner and owner != "unknown":
                row["owner"] = owner
    if row["permissions"]:
        row["mode"] = permissions_to_mode(row["permissions"])
    return row


def permissions_to_mode(permissions):
    """The octal mode of an ls-style permission string, or 0 if it has none."""
    if not permissions or len(permissions) < 10:
        return 0
    mode = 0
    for index, letter in enumerate(permissions[1:10]):
        if letter in "- ":
            continue
        mode |= 1 << (8 - index)
        if letter in "sS":
            mode |= 0o4000 if index < 3 else 0o2000
        elif letter in "tT":
            mode |= 0o1000
    return mode


def remote_properties(tab, names):
    """Read the attributes of one or more entries of the tab's directory."""
    if tab is None or not tab.connected:
        raise ValueError("Not connected.")
    if not isinstance(names, list) or not names or not all(
            isinstance(name, str) and name for name in names):
        raise ValueError("Name at least one entry to read.")
    rows = []
    for name in names:
        operand, operand_error = single_remote_name(tab, name)
        if operand_error:
            raise ValueError(operand_error)
        if getattr(tab, "is_local", False):
            target, contain_error = contained_local_path(tab.remote_dir, name)
            if contain_error:
                raise ValueError(contain_error)
            rows.append(local_properties(target))
            continue
        code, lines, errors = tab.run_many_capture(
            ["stat " + quote_remote(operand), "attr " + quote_remote(operand)])
        if code != 0:
            raise ValueError("\n".join(lines + errors) or
                             "Cannot read the properties of '%s'." % operand)
        row = _parse_remote_attributes("\n".join(lines), operand)
        rows.append(row)
    return rows


def set_rights(tab, names, mode_text, recursive=False):
    """Change the permissions of each named entry, reporting each result."""
    if tab is None or not tab.connected:
        raise ValueError("Not connected.")
    mode_error = check_permission_mode(mode_text)
    if mode_error:
        raise ValueError(mode_error)
    if not isinstance(names, list) or not names:
        raise ValueError("Select at least one entry to change.")
    if recursive and not getattr(tab, "is_local", False):
        raise ValueError("The server applies a recursive change to a "
                         "directory only; select the entries instead.")
    results = []
    for name in names:
        operand, operand_error = single_remote_name(tab, name)
        if operand_error:
            raise ValueError(operand_error)
        if getattr(tab, "is_local", False):
            target, contain_error = contained_local_path(tab.remote_dir, name)
            if contain_error:
                raise ValueError(contain_error)
            targets = [target]
            if recursive and os.path.isdir(target) and \
                    not os.path.islink(target):
                targets = [target]
                for current, directories, files in os.walk(target):
                    targets.extend(os.path.join(current, name)
                                   for name in sorted(directories + files))
            try:
                for changed in targets:
                    apply_local_mode(changed, mode_text)
                results.append({"name": operand, "success": True, "error": ""})
            except (OSError, ValueError) as exc:
                results.append({"name": operand, "success": False,
                                "error": str(exc)})
            continue
        commands = build_chmod_command(tab.remote_dir, mode_text, operand)
        code, lines, errors = tab.run_many_capture(commands)
        results.append({"name": operand, "success": code == 0,
                        "error": "" if code == 0 else
                        ("\n".join(errors or lines) or
                         "Cannot change the permissions.")})
    return results


# ---------------------------------------------------------------------------
# Remote-to-remote transfer: one server's file to another server
# ---------------------------------------------------------------------------

def remote_transfer_targets(tab):
    """The sessions a remote-to-remote copy can target.

    The session the copy starts in is listed first and marked as the
    current one: copying inside it is the one case the server itself can
    do, so it runs as a plain 'cp'. Every other open remote tab and every
    stored site can be targeted too, and those run through a private
    local copy.
    """
    if tab is None or not getattr(tab, "connected", False) or tab.is_local:
        raise ValueError("A remote-to-remote copy starts in a connected "
                         "remote tab.")
    targets = [{"id": "tab:%s" % tab.id, "kind": "tab", "tab": tab.id,
                "label": tab.name, "host": tab.session.get("host", ""),
                "protocol": tab.session.get("protocol", ""),
                "current": True, "connected": True}]
    for other in list(_current_workspace().get("tabs") or []):
        if other is tab or getattr(other, "is_local", False):
            continue
        targets.append({"id": "tab:%s" % other.id, "kind": "tab",
                        "tab": other.id, "label": other.name,
                        "host": other.session.get("host", ""),
                        "protocol": other.session.get("protocol", ""),
                        "current": False, "connected": bool(other.connected)})
    known = {target["label"] for target in targets}
    for site in read_stored_sessions():
        if site.get("protocol") == "local":
            continue
        label = site["name"]
        if label in known:
            continue
        targets.append({"id": "site:%s" % label, "kind": "site",
                        "site": label, "label": label,
                        "host": site.get("host", ""),
                        "protocol": site.get("protocol", ""),
                        "current": False, "connected": False})
    return targets


def _remote_transfer_target(target):
    """Resolve a target id from the dialog into (, session, label) parts."""
    if not isinstance(target, str) or not target:
        raise ValueError("Choose where the files are copied to.")
    kind, _, value = target.partition(":")
    if kind == "tab":
        for candidate in _current_workspace().get("tabs") or []:
            if str(getattr(candidate, "id", "")) == value:
                return candidate, dict(candidate.session), candidate.name
        raise ValueError("That tab is no longer open.")
    if kind == "site":
        for site in read_stored_sessions():
            if site["name"] == value:
                session = dict(site)
                session["site"] = value
                return None, session, value
        raise ValueError("The stored site '%s' no longer exists." % value)
    raise ValueError("The copy target is not known.")


def filter_remote_names(names, filemask):
    """Apply the dialog's file mask to the selected names."""
    if not filemask:
        return list(names)
    patterns = [part.strip() for part in filemask.split("|") if part.strip()]
    if not patterns:
        return list(names)
    return [name for name in names
            if any(fnmatchcase(name, pattern) for pattern in patterns)]


def check_remote_directory(directory):
    if not isinstance(directory, str) or not directory.strip():
        raise ValueError("A destination directory is required.")
    if any(ord(char) < 32 or ord(char) == 127 for char in directory):
        raise ValueError("The destination directory must not contain control "
                         "characters.")
    if not directory.startswith("/"):
        raise ValueError("The destination directory must be an absolute path.")
    return directory


def remote_copy_task(task):
    """Copy files from one remote session into another through a local copy.

    Two servers cannot be made to talk to each other without one of them
    accepting a connection from the other, so each file is downloaded into
    a private directory and uploaded from there. The directory is removed
    whatever happens, and an interruption leaves no partial file in the
    destination: the upload writes its own temporary file first.
    """
    source = get_tab(task.tab_id)
    if source is None or not getattr(source, "connected", False) or source.is_local:
        raise ValueError("The source session is no longer connected.")
    extra = task.extra or {}
    destination_session = extra.get("destination") or {}
    destination_dir = extra.get("directory") or "/"
    names = list(extra.get("names") or [])
    if not names:
        raise ValueError("No file was selected for the copy.")
    directory = tempfile.mkdtemp(prefix="linscp-remote-copy-")
    destination = None
    source_dir = task.source or source.remote_dir or "/"
    try:
        destination = CoreSession("remote-copy-%d" % task.id,
                                  destination_session,
                                  extra.get("label") or None)
        ok, error = destination.start()
        if not ok:
            raise ValueError(error or "The destination session did not start.")
        ok, error = destination.connect()
        if not ok:
            raise ValueError(error or "The destination session did not connect.")
        for index, name in enumerate(names):
            if task.status == "Cancelling":
                raise LocalTransferCancelled()
            local_path = os.path.join(directory, "%d-copy" % index)
            code, lines, errors = source.run_many_capture(
                ["get -transfer=binary %s %s" % (
                    quote_remote(_join_remote(source_dir, name)),
                    quote_local(local_path))],
                timeout=600)
            if code != 0:
                raise ValueError("Cannot read '%s' from the source: %s" % (
                    name, "\n".join(errors or lines) or "the transfer failed."))
            try:
                task.bytes_done += os.path.getsize(local_path)
            except OSError:
                pass
            command = "put -transfer=binary %s %s" % (
                quote_local(local_path),
                quote_remote(_join_remote(destination_dir, name)))
            code, lines, errors = destination.run_many_capture([command],
                                                               timeout=600)
            if code != 0:
                raise ValueError("Cannot write '%s' to the destination: %s" % (
                    name, "\n".join(errors or lines) or "the transfer failed."))
            task.detail = "%d of %d copied" % (index + 1, len(names))
        destination.run("pwd")
    finally:
        if destination is not None:
            destination.close()
        shutil.rmtree(directory, ignore_errors=True)


def _join_remote(directory, name):
    if directory.endswith("/"):
        return directory + name
    return directory + "/" + name


def queue_remote_transfer(tab, names, target, directory, filemask="",
                          policy="ask", priority=False):
    """Queue a copy between two remote sessions.

    The current session copies on the server itself - one 'cp' per file,
    which never moves the bytes over the network. Any other target is a
    second connection, so the copy is queued as a job that downloads and
    uploads each file, and the queue reports it like any other transfer.
    """
    if tab is None or not getattr(tab, "connected", False) or tab.is_local:
        raise ValueError("A remote-to-remote copy starts in a connected "
                         "remote tab.")
    if not isinstance(names, list) or not names:
        raise ValueError("Select at least one file to copy.")
    destination_dir = check_remote_directory(directory)
    selected = filter_remote_names(names, filemask)
    if not selected:
        raise ValueError("No selected file matches the file mask.")
    destination_tab, destination_session, label = _remote_transfer_target(target)
    for name in selected:
        _, name_error = single_remote_name(tab, name)
        if name_error:
            raise ValueError(name_error)
    direct = destination_tab is tab
    if direct:
        # One connection, so the server copies the bytes itself: the files
        # never travel over the network and no temporary copy is written.
        commands = ["cd " + quote_remote(tab.remote_dir)]
        commands.extend(
            "cp %s %s" % (quote_remote(name),
                          quote_remote(_join_remote(destination_dir, name)))
            for name in selected)
        task = TASKS.submit(
            "Copy (remote)", " ; ".join(commands), tab.session,
            tab.remote_dir, destination_dir, tab.id, priority=priority)
        return [task]
    task = TASKS.submit(
        "Copy (remote)", "", tab.session, tab.remote_dir, destination_dir,
        tab.id, priority=priority, native=remote_copy_task)
    task.extra = {"destination": destination_session, "label": label,
                  "directory": destination_dir, "names": selected}
    task.bytes_total = 0
    return [task]


# ---------------------------------------------------------------------------
# Embedded terminal (xterm.js in the page, 'linscp -shell' behind a pty)
# ---------------------------------------------------------------------------

class TerminalProcess:
    """One 'linscp -shell' child behind a pseudo-terminal.

    The browser renders the byte stream with xterm.js; this class only
    owns the pty, the child's output buffer and its size. Output is
    polled by absolute offset so a slow poll loses nothing, and the
    buffer is capped: a terminal nobody reads cannot grow without end.
    """

    BUFFER_LIMIT = 1024 * 1024

    def __init__(self, argv, env):
        master, slave = pty.openpty()
        try:
            self._set_size(slave, 30, 100)
            self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave,
                                         stderr=slave, env=env,
                                         start_new_session=True, close_fds=True)
        except Exception:
            os.close(master)
            os.close(slave)
            raise
        os.close(slave)
        self.master = master
        self.buffer = bytearray()
        self.dropped = 0
        self.lock = threading.Lock()
        self.alive = True
        self.thread = threading.Thread(target=self._pump_output, daemon=True)
        self.thread.start()

    @staticmethod
    def _set_size(fd, rows, cols):
        fcntl.ioctl(fd, termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, cols, 0, 0))

    def _pump_output(self):
        try:
            while True:
                chunk = os.read(self.master, 65536)
                if not chunk:
                    break
                with self.lock:
                    self.buffer += chunk
                    excess = len(self.buffer) - self.BUFFER_LIMIT
                    if excess > 0:
                        del self.buffer[:excess]
                        self.dropped += excess
        except OSError:
            pass
        finally:
            self.alive = False
            try:
                self.proc.wait(timeout=5)
            except Exception:
                pass

    def write(self, data):
        if not data:
            return
        view = memoryview(data)
        while self.alive and view:
            try:
                written = os.write(self.master, view)
            except InterruptedError:
                continue
            if written <= 0:
                raise OSError("The terminal input could not be written.")
            view = view[written:]

    def resize(self, cols, rows):
        # ioctl dimensions are unsigned shorts. Bound them before packing so
        # an invalid or hostile API value cannot crash the terminal pump.
        if 0 < cols <= 1000 and 0 < rows <= 1000:
            self._set_size(self.master, rows, cols)

    def poll(self, after):
        with self.lock:
            start = max(after - self.dropped, 0)
            data = bytes(self.buffer[start:])
            offset = self.dropped + len(self.buffer)
        return data, offset, self.alive, self.proc.poll()

    def close(self):
        self.alive = False
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    self.proc.kill()
                except OSError:
                    pass
                try:
                    self.proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        try:
            os.close(self.master)
        except OSError:
            pass
        if self.thread is not threading.current_thread():
            self.thread.join(timeout=1)


TERMINALS_LOCK = threading.Lock()


def _terminals():
    return _current_workspace().setdefault("terminals", {})


def start_terminal(tab):
    """Open an embedded terminal for a connected tab's session."""
    session = tab.session
    protocol = str(session.get("protocol") or "sftp")
    if protocol not in ("sftp", "scp"):
        raise ValueError("A terminal is only available for "
                         "SSH (sftp:// or scp://) sessions.")
    argv = core_command_line(session) + ["-shell", session_url(session)]
    env = popen_kwargs(session.get("password"), session)["env"]
    term = TerminalProcess(argv, env)
    terminal_id = secrets.token_hex(8)
    with TERMINALS_LOCK:
        _terminals()[terminal_id] = (str(tab.id), term)
    return terminal_id


def get_terminal(terminal_id):
    with TERMINALS_LOCK:
        entry = _terminals().get(str(terminal_id or ""))
    return entry[1] if entry else None


def close_terminal(terminal_id):
    with TERMINALS_LOCK:
        entry = _terminals().pop(str(terminal_id or ""), None)
    if entry:
        entry[1].close()


def close_tab_terminals(tab_id):
    with TERMINALS_LOCK:
        table = _terminals()
        doomed = [key for key, (owner, _term) in table.items()
                  if owner == str(tab_id)]
        terms = [table.pop(key)[1] for key in doomed]
    for term in terms:
        term.close()


def find_challenge(tab_id):
    """The connection parked for a host-key decision, whatever the id's type.

    A tab id arrives from JSON as a number or a string, and the challenge
    table is keyed by the number the server chose. A lookup that missed on
    the type told the user the connection had stopped waiting while its
    core process was still parked with an open socket.
    """
    with STATE_LOCK:
        challenges = STATE["challenges"]
        if tab_id in challenges:
            return challenges[tab_id]
        for key in list(challenges):
            if str(key) == str(tab_id):
                return challenges[key]
    return None


def pop_challenge(tab_id):
    with STATE_LOCK:
        challenges = STATE["challenges"]
        if tab_id in challenges:
            return challenges.pop(tab_id)
        for key in list(challenges):
            if str(key) == str(tab_id):
                return challenges.pop(key)
    return None


# ---------------------------------------------------------------------------
# The transfer queue
# ---------------------------------------------------------------------------

class Task(object):
    def __init__(self, task_id, kind, command, session, source, destination,
                 tab_id, progress_path=None, progress_remote=None, move_source=None,
                 cleanup_path=None, native=None, local_source=None,
                 local_target=None, local_policy="ask", local_move=False,
                 local_root=None, extra=None):
        self.id = task_id
        self.kind = kind
        self.command = command
        self.session = dict(session)
        self.source = source
        self.destination = destination
        self.tab_id = tab_id
        self.status = "Queued"
        self.error = ""
        self.bytes_done = 0
        self.bytes_total = 0
        self.detail = ""
        self.started = ""
        self.finished = ""
        self.proc = None
        self.progress_path = progress_path      # local file that grows
        self.progress_remote = progress_remote  # (tab_id, remote path)
        # A move removes its source only after the copied file is complete.
        self.move_source = move_source
        # Browser-originated uploads use a private temporary source file; keep
        # it available for retry, then remove it on completion or queue clear.
        self.cleanup_path = cleanup_path
        # A local-to-local entry has no core process: it runs this callable
        # in the queue worker instead of a command line.
        self.native = native
        self.local_source = local_source
        self.local_target = local_target
        self.local_policy = local_policy
        self.local_move = local_move
        self.local_root = local_root
        # A job that is not one command line - a copy between two servers -
        # keeps what it needs here instead of in the command text.
        self.extra = dict(extra or {})
        self.skipped = 0

    def as_dict(self):
        percent = 0
        if self.bytes_total and self.bytes_total > 0:
            percent = min(100, int(self.bytes_done * 100 / self.bytes_total))
        return {
            "id": self.id,
            "type": self.kind,
            "source": self.source,
            "destination": self.destination,
            "status": self.status,
            "error": self.error,
            "bytes_done": self.bytes_done,
            "bytes_total": self.bytes_total,
            "percent": percent,
            "skipped": self.skipped,
            "detail": self.detail,
            "start_time": self.started,
            "end_time": self.finished,
            "tab": self.tab_id,
        }

    def poll_progress(self):
        if self.progress_path:
            try:
                self.bytes_done = os.path.getsize(self.progress_path)
            except OSError:
                pass
        elif self.progress_remote:
            tab_id, remote_path = self.progress_remote
            tab = get_tab(tab_id)
            if tab is not None and tab.connected:
                # A session that is busy with a transfer is free to answer:
                # the transfer runs in its own process.
                try:
                    info = remote_stat(tab, remote_path, timeout=10)
                    if info is not None:
                        self.bytes_done = info["size"]
                except Exception:
                    pass


class TaskManager(object):
    def __init__(self, workspace=None):
        self.workspace = workspace if workspace is not None else _DEFAULT_WORKSPACE
        self.condition = threading.Condition()
        threading.Thread(target=self._worker, daemon=True).start()

    def _bind(self):
        previous = getattr(_TLS, "workspace", None)
        _TLS.workspace = getattr(self, "workspace", None) or _DEFAULT_WORKSPACE
        return previous

    def _unbind(self, previous):
        _TLS.workspace = previous

    def _ws(self):
        return getattr(self, "workspace", None) or _DEFAULT_WORKSPACE

    def submit(self, kind, command, session, source, destination, tab_id,
               progress_path=None, progress_remote=None, move_source=None,
               cleanup_path=None, priority=False, native=None,
               local_source=None, local_target=None, local_policy="ask",
               local_move=False, local_root=None, extra=None):
        with STATE_LOCK:
            ws = getattr(self, "workspace", None) or _DEFAULT_WORKSPACE
            task = Task(ws["next_task"], kind, command, session, source,
                        destination, tab_id, progress_path, progress_remote,
                        move_source=move_source, cleanup_path=cleanup_path,
                        native=native, local_source=local_source,
                        local_target=local_target, local_policy=local_policy,
                        local_move=local_move, local_root=local_root,
                        extra=extra)
            ws["next_task"] += 1
            if priority:
                ws["tasks"].append(task)
            else:
                ws["tasks"].insert(0, task)
        with self.condition:
            self.condition.notify_all()
        previous = self._bind()
        try:
            add_log("Queued %s: %s -> %s" % (kind, source, destination), "info")
        finally:
            self._unbind(previous)
        return task

    def _next(self):
        with STATE_LOCK:
            ws = getattr(self, "workspace", None) or _DEFAULT_WORKSPACE
            if ws["paused"]:
                return None
            for task in reversed(ws["tasks"]):
                if task.status == "Queued":
                    return task
        return None

    def _worker(self):
        while True:
            with self.condition:
                task = self._next()
                if task is None:
                    self.condition.wait(1.0)
                    continue
            self._run(task)

    def _run(self, task):
        previous = self._bind()
        try:
            self._run_bound(task)
        finally:
            self._unbind(previous)

    def _run_bound(self, task):
        task.status = "Running"
        task.started = time.strftime("%H:%M:%S")
        task.error = ""
        if task.native is not None:
            return self._run_native(task)
        add_log("%s started: %s" %
                (task.kind, redact_command_for_log(task.command)), "cmd")
        # Each task has its own connection so it can be interrupted without
        # dropping the session the panes are browsing. The open command goes
        # over stdin and the password is isolated in the child environment;
        # neither is exposed in the process arguments.
        runner = CoreCommandProcess(task.session)
        task.proc = None
        captured = []

        def on_output(text):
            safe_text = redact_command_for_log(text)
            if safe_text.startswith(("Uploaded", "Downloaded", "Created", "Removed")):
                task.detail = safe_text
                add_log(safe_text, "info")

        def on_error(text):
            add_log(redact_command_for_log(text), "error")

        def wait_for_command():
            task.poll_progress()

        def cancelled():
            return task.status == "Cancelling"

        code = 1
        failure = ""
        try:
            runner.start()
            task.proc = runner.process
            # The server protocol expands no script placeholders. A file
            # literally named '%TIMESTAMP%.txt' therefore stays that name.
            commands = ["open " + quote_remote(session_url(task.session)),
                        "option confirm off"]
            commands.extend(split_linscp_commands(task.command))
            for command in commands:
                if task.status == "Cancelling":
                    break
                code, lines, errors = runner.run_command(
                    command, timeout=300, on_output=on_output,
                    on_error=on_error, on_wait=wait_for_command,
                    should_cancel=cancelled)
                captured.extend(redact_command_for_log(line) for line in lines)
                if code != 0:
                    failure = "\n".join(
                        redact_command_for_log(line) for line in errors[-6:])
                    break
        except (OSError, RuntimeError, ValueError) as exc:
            failure = redact_command_for_log(str(exc))
            code = 1
        finally:
            runner.close()
            task.proc = None

        if task.status == "Cancelling":
            task.status = "Cancelled"
            task.finished = time.strftime("%H:%M:%S")
            add_log("%s cancelled: %s" % (task.kind, task.source), "info")
            # The staged file is released only after the core has stopped
            # reading it, so cancellation remains safe for retries.
            self.cleanup_source(task)
            return

        move_error = ""
        if code == 0 and task.move_source:
            task.detail = "Transfer complete; removing the source..."
            move_error = self._remove_move_source(task)
            if move_error:
                code = 1
        task.status = "Completed" if code == 0 else "Failed"
        task.finished = time.strftime("%H:%M:%S")
        if code == 0:
            self.cleanup_source(task)
        else:
            task.error = move_error or failure or "\n".join(captured[-6:]) or \
                "The operation failed."
        add_log("%s %s: %s" % (task.kind, task.status.lower(), task.source),
                "success" if code == 0 else "error")
        # Refresh the panes of the tab this task belongs to.
        tab = get_tab(task.tab_id)
        if tab is not None and tab.connected and not getattr(tab, "is_local", False):
            code, lines = tab.run("pwd")
            if code == 0:
                for line in lines:
                    if line.startswith("/"):
                        tab.remote_dir = line.strip()
                        break

    def _run_native(self, task):
        """Run a local copy in the queue worker.

        The operation updates ``task.bytes_done`` as it copies and raises
        LocalTransferCancelled when the queue entry is cancelled. Nothing
        here starts a subprocess or opens a socket.
        """
        add_log("%s started: %s -> %s" % (task.kind, task.source,
                                          task.destination), "cmd")
        failure = ""
        try:
            task.native(task)
        except LocalTransferCancelled:
            task.status = "Cancelled"
            task.finished = time.strftime("%H:%M:%S")
            add_log("%s cancelled: %s" % (task.kind, task.source), "info")
            return
        except (OSError, ValueError, shutil.Error) as exc:
            failure = str(exc)
        except Exception as exc:
            failure = str(exc)
        if task.status == "Cancelling":
            task.status = "Cancelled"
            task.finished = time.strftime("%H:%M:%S")
            add_log("%s cancelled: %s" % (task.kind, task.source), "info")
            return
        if failure:
            task.status = "Failed"
            task.error = failure
            task.finished = time.strftime("%H:%M:%S")
            add_log("%s failed: %s" % (task.kind, failure), "error")
            return
        task.status = "Completed"
        task.finished = time.strftime("%H:%M:%S")
        add_log("%s completed: %s" % (task.kind, task.destination), "success")

    def submit_local(self, kind, source, destination, tab_id, policy,
                     move=False, root=None, bytes_total=0, priority=False):
        """Queue a local copy/move that needs no server connection."""
        def operation(entry):
            local_copy_task(entry)

        with STATE_LOCK:
            ws = self._ws()
            task = Task(ws["next_task"], kind, "", {}, source,
                        destination, tab_id, native=operation,
                        local_source=source, local_target=destination,
                        local_policy=policy, local_move=move, local_root=root)
            task.bytes_total = bytes_total
            ws["next_task"] += 1
            if priority:
                ws["tasks"].append(task)
            else:
                ws["tasks"].insert(0, task)
        with self.condition:
            self.condition.notify_all()
        previous = self._bind()
        try:
            add_log("Queued %s: %s -> %s" % (kind, source, destination), "info")
        finally:
            self._unbind(previous)
        return task

    def _remove_move_source(self, task):
        """Remove a moved file only if its source still matches the queued file."""
        source = task.move_source or {}
        side = source.get("side")
        path = source.get("path") or ""
        if side == "local":
            try:
                current = os.stat(path)
                if os.path.isdir(path) and not os.path.islink(path):
                    return "The transfer completed, but directories are not moved; the source was kept."
                if current.st_size != source.get("size") or \
                        getattr(current, "st_mtime_ns", int(current.st_mtime * 1000000000)) != source.get("mtime_ns"):
                    return "The transfer completed, but the local source changed; it was kept."
                os.remove(path)
            except OSError as exc:
                return "The transfer completed, but the local source could not be removed: %s" % exc
            add_log("Removed moved local file: %s" % path, "success")
            return ""

        if side == "remote":
            with STATE_LOCK:
                tab = next((candidate for candidate in self._ws()["tabs"]
                            if str(candidate.id) == str(task.tab_id)), None)
            if tab is None or not tab.connected:
                return "The transfer completed, but its session closed; the remote source was kept."
            info = remote_stat(tab, path, timeout=30)
            if info is None:
                return "The transfer completed, but the remote source could not be checked; it was kept."
            if info.get("is_dir") or info.get("size") != source.get("size") or \
                    info.get("mtime") != source.get("mtime"):
                return "The transfer completed, but the remote source changed; it was kept."
            command = "open %s ; rm %s" % (
                quote_remote(session_url(task.session)), quote_remote(path))
            code, stdout, stderr = run_linscp(command, task.session, timeout=300)
            if code != 0:
                return "The transfer completed, but the remote source could not be removed: %s" % (
                    stderr.strip() or stdout.strip() or "remove failed")
            add_log("Removed moved remote file: %s" % path, "success")
            return ""
        return "The transfer completed, but its source could not be identified; it was kept."

    # -- queue controls ----------------------------------------------------

    @staticmethod
    def cleanup_source(task):
        path = getattr(task, "cleanup_path", None)
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
            task.cleanup_path = None

    def cancel(self, task_id):
        with STATE_LOCK:
            for task in self._ws()["tasks"]:
                if str(task.id) == str(task_id):
                    if task.status == "Queued":
                        task.status = "Cancelled"
                        task.finished = time.strftime("%H:%M:%S")
                    elif task.status == "Running":
                        task.status = "Cancelling"
                    return True
        return False

    def retry(self, task_id):
        with STATE_LOCK:
            for task in self._ws()["tasks"]:
                if str(task.id) == str(task_id):
                    if task.status not in ("Failed", "Cancelled"):
                        return False
                    task.status = "Queued"
                    task.error = ""
                    task.finished = ""
                    task.bytes_done = 0
                    break
            else:
                return False
        with self.condition:
            self.condition.notify_all()
        return True

    def prioritize(self, task_id, position="top"):
        """Reorder a queued task ('top' runs next; 'up'/'down' shifts one slot)."""
        with STATE_LOCK:
            tasks = self._ws()["tasks"]
            idx = next((i for i, t in enumerate(tasks)
                        if str(t.id) == str(task_id)), None)
            if idx is None or tasks[idx].status != "Queued":
                return False
            task = tasks.pop(idx)
            # Note: _next() scans reversed(STATE["tasks"]), so the end of the
            # list is the head of the execution queue (runs next).
            if position in ("top", "next", "first"):
                tasks.append(task)
            elif position == "up":
                target = min(len(tasks), idx + 1)
                tasks.insert(target, task)
            elif position in ("down", "bottom"):
                target = 0 if position == "bottom" else max(0, idx - 1)
                tasks.insert(target, task)
            else:
                tasks.insert(idx, task)
                return False
        with self.condition:
            self.condition.notify_all()
        return True

    def pause(self):
        with STATE_LOCK:
            self._ws()["paused"] = True
        previous = self._bind()
        try:
            add_log("Queue paused; queued transfers wait.", "info")
        finally:
            self._unbind(previous)

    def resume(self):
        with STATE_LOCK:
            self._ws()["paused"] = False
        with self.condition:
            self.condition.notify_all()
        previous = self._bind()
        try:
            add_log("Queue resumed.", "info")
        finally:
            self._unbind(previous)

    def clear_finished(self):
        with STATE_LOCK:
            kept = []
            removed = []
            for task in self._ws()["tasks"]:
                if task.status in ("Queued", "Running", "Cancelling"):
                    kept.append(task)
                else:
                    removed.append(task)
            self._ws()["tasks"] = kept
        for task in removed:
            self.cleanup_source(task)

    def cancel_all(self):
        staged = []
        with STATE_LOCK:
            for task in self._ws()["tasks"]:
                if task.status == "Queued":
                    task.status = "Cancelled"
                    # Nothing is reading the staged file of a task that
                    # never started, so it can go now. Collecting it and
                    # removing it after the lock is released is what
                    # clear_finished() does too: an unlink that blocks on
                    # a slow file system must not hold up every other
                    # request that reads the queue.
                    staged.append(task)
                elif task.status == "Running":
                    # The core process of a running task is reading its
                    # staged source. Removing it here turned a cancellation
                    # into a failure part way through the file, and left
                    # 'retry' with nothing to retry from. The worker
                    # removes it when the process has actually stopped.
                    task.status = "Cancelling"
        for task in staged:
            self.cleanup_source(task)


_DEFAULT_TASKS = TaskManager(_DEFAULT_WORKSPACE)
_DEFAULT_WORKSPACE["task_manager"] = _DEFAULT_TASKS


class _TasksProxy(object):
    """Route queue operations to the workspace bound to this thread.

    Tests may replace the module-level TASKS object; request handlers then
    talk to that stand-in. Isolation uses the per-login TaskManager.
    """

    def _manager(self):
        ws = _current_workspace()
        manager = ws.get("task_manager")
        if manager is None:
            manager = TaskManager(ws)
            ws["task_manager"] = manager
        return manager

    def __getattr__(self, name):
        return getattr(self._manager(), name)


TASKS = _TasksProxy()


def queue_local_transfers(tab, direction, names, policy="ask", move=False,
                          priority=False):
    """Queue copies between the two local panes of a local-to-local tab.

    'upload' means left pane to right pane and 'download' the reverse,
    exactly as the same two words mean for a remote tab, so the Commander
    keys F5/F6 keep their meaning when there is no server.
    """
    if tab is None or not getattr(tab, "is_local", False):
        raise ValueError("This tab is not a local-to-local session.")
    if direction not in ("upload", "download"):
        raise ValueError("The direction must be upload or download.")
    if direction == "upload":
        source_dir, destination_dir = tab.local_dir, tab.remote_dir
    else:
        source_dir, destination_dir = tab.remote_dir, tab.local_dir
    plans = plan_local_transfers(source_dir, destination_dir, names, policy)
    tasks = []
    for source, target in plans:
        total, _files = _local_source_size(source)
        kind = "Move (local)" if move else "Copy (local)"
        task = TASKS.submit_local(
            kind, source, target, tab.id, policy, move=move,
            root=os.path.realpath(destination_dir), bytes_total=total,
            priority=priority)
        tasks.append(task)
    return tasks


# ---------------------------------------------------------------------------
# Listing helpers
# ---------------------------------------------------------------------------

def split_gui_commands(text):
    """Split terminal input on ';', honouring the client's quoting.

    Mirrors SplitCommands() in source/linux/PathUtil.cpp: a ';' inside
    single or double quotes, or escaped with a backslash, does not end
    a command. The server loop takes one command per line and does not
    split at all, so this is what lets the terminal offer ';' the way
    '-command=' does without breaking quoted names that hold one.
    """
    result = []
    current = []
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote is not None:
            if char == "\\" and quote == '"' and index + 1 < len(text):
                current.append(char)
                index += 1
                current.append(text[index])
            elif char == quote:
                quote = None
                current.append(char)
            else:
                current.append(char)
        elif char in ("'", '"'):
            quote = char
            current.append(char)
        elif char == "\\" and index + 1 < len(text):
            current.append(char)
            index += 1
            current.append(text[index])
        elif char == ";":
            result.append("".join(current))
            current = []
        else:
            current.append(char)
        index += 1
    if current or not result:
        result.append("".join(current))
    return result


def quote_remote(path):
    """Quote a remote path so that it survives the command splitter.

    A control character cannot be quoted at all: the core reads one
    command per line in -server mode, so a name holding a newline is two
    commands, and the second one is whatever the name said. A directory
    on the server can be called anything, so this is reached by listing a
    hostile server as easily as by a crafted API call - refuse the operand
    instead of sending it.

    A backslash needs the quotes as much as a blank does. The client's
    splitter reads a backslash as the start of an escape outside quotes,
    so an unquoted 'a\\b' arrived at the server as 'ab': the name of one
    file was the name of another. Inside double quotes it reads a
    backslash as literal unless the backslash stands in front of a
    double quote or of another backslash, so a doubled backslash is
    what keeps one - and a path that came from a Windows client keeps
    its separators. The local side has always quoted it that way.
    """
    if not isinstance(path, str):
        raise ValueError("A remote path must be text.")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError("A remote path must not contain a control character.")
    if path and not any(ch in path for ch in " \t\"';\\"):
        return path
    return '"' + path.replace('\\', '\\\\').replace('"', '\\"') + '"'


def quote_local(path):
    """Quote a local path for a command line, with the same rule.

    'lcd' and 'put' take a local path too, and it reaches the same
    line-oriented command stream, so it is validated the same way rather
    than being wrapped in quotes that a backslash or a newline defeats.
    """
    if not isinstance(path, str):
        raise ValueError("A local path must be text.")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise ValueError("A local path must not contain a control character.")
    if path and not any(ch in path for ch in " \t\"';\\"):
        return path
    return '"' + path.replace('\\', '\\\\').replace('"', '\\"') + '"'


MODE_CHARACTERS = "01234567ugoaUGOA-+=rwxXst, \t"


def check_permission_mode(mode_text):
    """Validate a chmod mode the way the console client accepts one.

    Returns an error message, or an empty string when the mode is usable.
    The remote chmod interpolated whatever it was given straight into a
    command line, so this is what stands between a permissions field and
    the session's command stream. Both the octal and the symbolic forms
    'chmod' documents are accepted, and nothing else.

    The grammar is the one ParseSymbolicPermissions() and ParseOctalMode()
    in the console client parse, character for character: a mode this
    panel accepts has to be a mode the remote chmod accepts too, and one
    the client would refuse is refused here rather than answered with a
    failure after the user was told the mode was usable.
    """
    text = str(mode_text or "").strip()
    if not text:
        return "Enter a permission mode, such as 644 or u+x."
    if len(text) > 64:
        return "That permission mode is too long."
    # A mode is only ever these characters. A newline, a semicolon or a
    # quote is refused here rather than reaching the command stream.
    if any(ch not in MODE_CHARACTERS for ch in text):
        return ("That permission mode has a character that is not part of "
                "an octal or a symbolic mode.")
    if text[0].isdigit():
        # ParseOctalMode(): one leading zero is a prefix, and what is left
        # is one to four octal digits. '00644' is the client's own spelling
        # of 644, so refusing it here would refuse a mode it accepts.
        digits = text[1:] if len(text) > 1 and text[0] == "0" else text
        if digits and len(digits) <= 4 and all(ch in "01234567" for ch in digits):
            return ""
        return "Permissions must be an octal mode such as 644."
    # Symbolic: one or more '<who>(<op><letters>)+' clauses, separated by
    # commas or blanks. Several operator groups in one clause apply left to
    # right, as chmod(1) applies them: 'u+x-w' is 'u+x' and then 'u-w'.
    clauses = text.replace(",", " ").split()
    if not clauses:
        return "That permission mode states no permission at all."
    for clause in clauses:
        index = 0
        who = ""
        while index < len(clause) and clause[index] in "ugoaUGOA":
            who += clause[index].lower()
            index += 1
        groups = 0
        while index < len(clause) and clause[index] in "-+=":
            operator = clause[index]
            index += 1
            if not who:
                if operator != "=":
                    # '+x' names nobody, and the client refuses it rather
                    # than quietly change nothing.
                    return ("A symbolic mode starts with u, g, o or a, "
                            "as in u+x or a=r,go-w.")
                # '=rwx' with no letters in front applies to everybody,
                # which is what the console client does with it.
                who = "a"
            groups += 1
            letters = 0
            while index < len(clause) and clause[index] in "rwxXstuugo":
                index += 1
                letters += 1
            if letters == 0 and operator != "=":
                # chmod(1) allows the empty list after '=' ('u=' clears
                # the class) but not after '+' or '-', where it states
                # nothing; the console client reads it the same way.
                return ("A symbolic mode needs a permission letter after "
                        "+ or -, from r, w, x, X, s, t, u, g or o.")
        if groups == 0:
            return ("A symbolic mode needs one of -, + or = after "
                    "u, g, o or a, as in u+x or a=r,go-w.")
        if index != len(clause):
            return ("A symbolic mode has something after its permission "
                    "letters that is not another -, + or =.")
    return ""


CHECKSUM_ALGORITHMS = ("sha-256", "sha-1", "md5", "crc32")


def single_remote_name(tab, name):
    """One entry of the remote panel, resolved against its directory.

    Returns (operand, error). The remote operations were given whatever the
    request held, so an absolute path or one with '..' in it named a file
    outside the directory the panel was showing - and the user was told the
    operation had been done on the entry they had selected.
    """
    if not isinstance(name, str) or not name:
        return None, "Select an item in the remote panel first."
    if name in (".", ".."):
        return None, "\"%s\" is not a file name." % name
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        return None, "A file name must not contain a control character."
    base = tab.remote_dir if tab and tab.remote_dir else "/"
    if posixpath.isabs(name):
        return posixpath.normpath(name), ""
    if "\\" in name:
        return None, ("A backslash is not a separator on this server; "
                      "\"%s\" was refused rather than flattened." % name)
    parts = name.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None, ("\"%s\" names more than one entry of this directory."
                      % name)
    return posixpath.normpath(posixpath.join(base, *parts)), ""


def contained_local_path(base, name):
    """Resolve one panel entry against the directory the panel is showing.

    Returns (path, error). The local operations used to be
    ``os.path.join(base, name)`` with a name that came from the request:
    an absolute name replaced the base outright and ``..`` walked out of
    it, so a delete or a rename could land anywhere the user running the
    server could reach. The panel shows one directory, and an entry in it
    is a single name - anything else is refused, which also keeps a second
    browser window from moving the first one's operations somewhere else.
    """
    if not isinstance(name, str) or not name:
        return None, "Select an item first."
    # Reject path separators, NUL and control characters. A backslash is
    # not a separator on POSIX but is rejected for consistency with the
    # browser drop handlers that treat it as a separator attempt.
    if name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
        return None, ("\"%s\" is not a single file name in this directory."
                      % name)
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        return None, "A file name must not contain a control character."
    if len(name.encode("utf-8")) > 255:
        return None, "The file name is too long."
    if not isinstance(base, str) or not base or not os.path.isabs(base):
        return None, "The local directory of this panel is not set."
    jailed_base, jail_error = confined_local_path(base)
    if jail_error:
        return None, jail_error
    base = jailed_base
    # Use realpath to prevent a symlink in the base directory from
    # escaping containment via string-prefix checks alone.
    try:
        real_base = os.path.realpath(base)
        target = os.path.join(base, name)
        # The target itself may be a symlink; realpath would resolve it and
        # hide the fact that the operation would act on the link itself.
        # For containment we only need to ensure the parent is inside base.
        if os.path.commonpath([real_base, os.path.abspath(target)]) != real_base:
            return None, "That name escapes the directory the panel is showing."
    except ValueError:
        return None, "That name escapes the directory the panel is showing."
    confined, jail_error = confined_local_path(target)
    if jail_error:
        return None, jail_error
    return confined, ""


def check_remote_entry_name(name):
    """Validate that a remote name is a single entry in the current panel.

    Returns an error message, or an empty string when the name is safe to
    use as the operand of a mkdir/rm/rmdir/mv/chmod/ln that is run after
    'cd <panel_dir>'. The local panel rejects '.', '..', separators and
    control characters in the name it is given; the remote panel must do
    the same, or a '../../etc' entry from a second browser window or a
    hostile remote listing could operate outside the directory the panel
    is showing.
    """
    if not isinstance(name, str) or not name:
        return "Select an item first."
    if name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
        return ("\"%s\" is not a single file name in this directory." % name)
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        return "A file name must not contain a control character."
    if len(name.encode("utf-8")) > 255:
        return "The file name is too long."
    return ""


def build_chmod_command(remote_dir, mode_text, name):
    """The commands a remote chmod runs: enter the panel, change one entry.

    The mode is an operand of the client's command splitter as much as the
    name is. A symbolic mode may separate its clauses with blanks - the
    client reads 'u=rw g=r' as two clauses - so unquoted it would arrive as
    a second file name and the chmod would run against a path nobody asked
    for. It is validated here too, so the endpoint cannot send a mode the
    client would refuse after the panel called it usable.
    """
    mode_error = check_permission_mode(mode_text)
    if mode_error:
        raise ValueError(mode_error)
    return ["cd " + quote_remote(remote_dir),
            "chmod %s %s" % (quote_remote(mode_text), quote_remote(name))]


def apply_local_mode(path, mode_text):
    """Apply an octal or symbolic mode to a local path.

    The symbolic form is applied through chmod(1)'s own grammar as far as
    this needs it: the console client already parses the same modes for
    the remote side, and a local panel that only understood octal could
    not offer the one the user typed for the other side.
    """
    text = str(mode_text).strip()
    if all(ch in "01234567" for ch in text) and text:
        os.chmod(path, int(text, 8))
        return
    st_mode = os.stat(path).st_mode
    original = stat.S_IMODE(st_mode)
    current = original
    is_dir = stat.S_ISDIR(st_mode)
    # The three permission classes, with the mask that holds them and the
    # shift that puts a class bit in the right place: the owner at 6, the
    # group at 3, the others at 0.
    classes = (("u", 0o700, 6), ("g", 0o070, 3), ("o", 0o007, 0))
    class_bits = {"u": (0o700, 6), "g": (0o070, 3), "o": (0o007, 0)}
    # Commas and blanks separate clauses here exactly as they do in
    # ParseSymbolicPermissions(), so a mode the panel accepted for the
    # remote side means the same thing on the local one.
    for clause in text.replace(",", " ").split():
        index = 0
        who = 0
        while index < len(clause) and clause[index] in "ugoaUGOA":
            letter = clause[index].lower()
            index += 1
            if letter == "u":
                who |= 0o700
            elif letter == "g":
                who |= 0o070
            elif letter == "o":
                who |= 0o007
            else:
                who |= 0o777
        while index < len(clause) and clause[index] in "-+=":
            operator = clause[index]
            index += 1
            if who == 0 and operator == "=":
                # '=rwx' names nobody in front of it, so it is for
                # everybody: the same reading the console client gives it.
                who = 0o777
            letters = []
            while index < len(clause) and clause[index] in "rwxXstugo":
                letters.append(clause[index])
                index += 1
            for name, class_mask, shift in classes:
                if not who & class_mask:
                    continue
                bits = 0
                for letter in letters:
                    if letter == "r":
                        bits |= 0o4 << shift
                    elif letter == "w":
                        bits |= 0o2 << shift
                    elif letter == "x":
                        bits |= 0o1 << shift
                    elif letter == "X":
                        # 'X' is execute for a directory, or for a file
                        # that already has one execute bit set. Like
                        # chmod(1), a later clause reads what an earlier
                        # one left behind, not what the file started
                        # with: 'u+x,g+X' on a 644 file sets the group
                        # bit because the owner gained one first.
                        if is_dir or current & 0o111:
                            bits |= 0o1 << shift
                    elif letter in "ugo":
                        # As a permission letter, u/g/o means "whatever
                        # that class has now", so the bits are copied
                        # out of the class they name - as the mode
                        # stands after the earlier clauses - and into
                        # the class being changed.
                        source_mask, source_shift = class_bits[letter]
                        bits |= ((current & source_mask) >> source_shift) << shift
                # The setuid, setgid and sticky bits live outside the
                # three permission classes. '=' clears the class's own
                # special bit along with its rwx bits, which is what
                # chmod(1) does: 'u=rw' drops setuid, 'g=r' drops setgid
                # and 'o=' drops the sticky bit. 's' is the setuid bit for
                # the owner and the setgid bit for the group, 't' is the
                # sticky bit of the others; the two are independent, so
                # 'o=st' clears the others' bits and sets sticky again.
                class_special = {"u": 0o4000, "g": 0o2000, "o": 0o1000}[name]
                if operator == "+":
                    current |= bits
                elif operator == "-":
                    current &= ~bits
                else:
                    current &= ~(class_mask | class_special)
                    current |= bits & class_mask
                special = 0
                if "s" in letters:
                    special |= 0o4000 if name == "u" else (
                        0o2000 if name == "g" else 0)
                if "t" in letters and name == "o":
                    special |= 0o1000
                if special:
                    if operator == "-":
                        current &= ~special
                    else:
                        current |= special
    os.chmod(path, current & 0o7777)


def browser_destination(remote_dir, relative_path):
    """Return a path beneath the selected pane, never an absolute/escaping drop.

    Desktop drag entries come from a browser, not the local file panel. Validate
    *every* component before joining: posixpath.join discards its base for an
    absolute child, while normpath would silently turn ../ into a sibling of
    the requested destination. A backslash is not a separator on the server
    but browsers disagree about it, so refuse it rather than flattening it.
    """
    if not isinstance(remote_dir, str) or not remote_dir.startswith("/") or \
            not isinstance(relative_path, str) or not relative_path:
        raise ValueError("The drop destination must be a remote directory and a relative path.")
    segments = relative_path.split("/")
    try:
        too_long = (len(relative_path.encode("utf-8")) > 4096 or
                    len(remote_dir.encode("utf-8")) > 4096 or
                    any(len(part.encode("utf-8")) > 255 for part in segments))
    except UnicodeError as exc:
        raise ValueError("The drop path has invalid Unicode.") from exc
    if too_long or len(segments) > 32 or any(
            not segment or segment in (".", "..") or "\\" in segment or
            any(ord(char) < 32 or ord(char) == 127 for char in segment)
            for segment in segments) or \
            any(part in (".", "..") for part in remote_dir.split("/")) or \
            "\\" in remote_dir or \
            any(ord(char) < 32 or ord(char) == 127 for char in remote_dir):
        raise ValueError("The drop path contains an invalid name or escapes the remote directory.")
    base = posixpath.normpath(remote_dir)
    destination = posixpath.join(base, *segments)
    if posixpath.commonpath((base, destination)) != base:
        raise ValueError("The drop path escapes the remote directory.")
    return destination


def queue_browser_directory(tab, remote_dir, relative_path):
    """Queue even empty folders, without treating an existing folder as an error."""
    if getattr(tab, "is_local", False):
        # The right-hand pane is a local directory on disk, so a dropped
        # folder is created here rather than sent as a remote command.
        destination = save_local_browser_directory(remote_dir, relative_path)
        with STATE_LOCK:
            task = Task(STATE["next_task"], "Create directory", "", {},
                        "Browser: " + relative_path, destination, tab.id)
            STATE["next_task"] += 1
            STATE["tasks"].insert(0, task)
        task.status = "Completed"
        task.started = time.strftime("%H:%M:%S")
        task.finished = task.started
        task.detail = "Created " + destination
        return task
    destination = browser_destination(remote_dir, relative_path)
    return TASKS.submit("Create directory",
                        "mkdir -parents " + quote_remote(destination),
                        tab.session, "Browser: " + relative_path,
                        destination, tab.id)


def queue_browser_upload(tab, remote_dir, filename, source_stream,
                         content_length, relative_path=None):
    """Stage a browser File and queue a retry-safe, nested destination."""
    if relative_path is None:
        relative_path = filename
    destination = browser_destination(remote_dir, relative_path)
    if not isinstance(filename, str) or relative_path.split("/")[-1] != filename:
        raise ValueError("The file name does not match the dropped path.")
    fd, source_path = tempfile.mkstemp(prefix="linscp-browser-upload-")
    try:
        remaining = content_length
        with os.fdopen(fd, "wb") as uploaded:
            while remaining:
                chunk = source_stream.read(min(65536, remaining))
                if not chunk:
                    raise IOError("The upload ended before all bytes arrived.")
                uploaded.write(chunk)
                remaining -= len(chunk)
        # This runs in the task's short-lived process. mkdir -parents checks
        # every existing component is a directory and is safe on retry; if
        # any creation fails, batch mode stops before put touches the file.
        parent = posixpath.dirname(destination)
        command = "mkdir -parents %s ; put %s %s" % (
            quote_remote(parent), quote_remote(source_path),
            quote_remote(destination))
        task = TASKS.submit("Upload", command, tab.session,
                            "Browser: " + relative_path, destination, tab.id,
                            progress_remote=(tab.id, destination),
                            cleanup_path=source_path)
        task.bytes_total = content_length
        return task
    except Exception:
        try:
            os.unlink(source_path)
        except OSError:
            pass
        raise


def local_browser_destination(local_dir, relative_path):
    """Validate and resolve a browser drop target beneath a local directory."""
    if not isinstance(local_dir, str) or not os.path.isabs(local_dir) or \
            not isinstance(relative_path, str) or not relative_path:
        raise ValueError("The drop destination must be an absolute local directory and a relative path.")
    jailed_dir, jail_error = confined_local_path(local_dir)
    if jail_error:
        raise ValueError(jail_error)
    local_dir = jailed_dir
    segments = relative_path.split("/")
    try:
        too_long = (len(relative_path.encode("utf-8")) > 4096 or
                    len(local_dir.encode("utf-8")) > 4096 or
                    any(len(part.encode("utf-8")) > 255 for part in segments))
    except UnicodeError as exc:
        raise ValueError("The drop path has invalid Unicode.") from exc
    if too_long or len(segments) > 32 or any(
            not segment or segment in (".", "..") or "\\" in segment or
            any(ord(char) < 32 or ord(char) == 127 for char in segment)
            for segment in segments):
        raise ValueError("The drop path contains an invalid name or escapes the local directory.")
    if not os.path.isdir(local_dir) or os.path.islink(local_dir):
        raise ValueError("The target local directory does not exist.")
    real_base = os.path.realpath(local_dir)
    current = real_base
    for segment in segments:
        current = os.path.join(current, segment)
        if os.path.islink(current):
            raise ValueError("Refusing to overwrite or traverse a symbolic link in the local drop target.")
    if os.path.commonpath([real_base, os.path.abspath(current)]) != real_base:
        raise ValueError("The drop path escapes the local directory.")
    return current


def save_local_browser_directory(local_dir, relative_path):
    """Create an empty or nested directory dropped onto the local panel."""
    destination = local_browser_destination(local_dir, relative_path)
    os.makedirs(destination, exist_ok=True)
    add_log("Created local directory from drop: %s" % destination, "success")
    return destination


def save_local_browser_upload(local_dir, filename, source_stream,
                              content_length, relative_path=None):
    """Save a browser-dropped file into the local panel directory."""
    if relative_path is None:
        relative_path = filename
    destination = local_browser_destination(local_dir, relative_path)
    if not isinstance(filename, str) or relative_path.split("/")[-1] != filename:
        raise ValueError("The file name does not match the dropped path.")
    parent = os.path.dirname(destination)
    os.makedirs(parent, exist_ok=True)
    fd = None
    temp_path = None
    created = False
    try:
        # O_EXCL and a cryptographically random name give mkstemp's
        # collision/symlink protection, while the requested 0666 mode lets
        # the kernel apply the process umask atomically. Record that result,
        # then keep the in-progress upload private until it is complete.
        for _attempt in range(100):
            temp_path = os.path.join(parent,
                                     ".linscp-drop-" + secrets.token_hex(16))
            try:
                fd = os.open(temp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                             0o666)
                created = True
                break
            except FileExistsError:
                continue
        if fd is None:
            raise FileExistsError("Could not allocate a temporary upload file.")
        default_mode = stat.S_IMODE(os.fstat(fd).st_mode)
        os.fchmod(fd, 0o600)
        handle = os.fdopen(fd, "wb")
        fd = None
        with handle:
            remaining = content_length
            while remaining:
                chunk = source_stream.read(min(65536, remaining))
                if not chunk:
                    raise IOError("The upload ended before all bytes arrived.")
                handle.write(chunk)
                remaining -= len(chunk)
        if os.path.exists(destination):
            try:
                final_mode = stat.S_IMODE(os.stat(destination).st_mode)
            except OSError:
                final_mode = default_mode
        else:
            final_mode = default_mode
        os.chmod(temp_path, final_mode)
        os.replace(temp_path, destination)
        add_log("Saved dropped local file: %s" % destination, "success")
        return destination
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if created and temp_path is not None:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
        raise


# A listing line in long format starts with a mode string: the file type,
# nine permission characters and perhaps an ACL or attribute marker, as
# PermissionsString() writes it and as a server's own 'ls -l' does.
LISTING_MODE = re.compile(r"^[-a-zA-Z?][-rwxsStTlL]{9}[+@.]?$")


def parse_ls_output(stdout):
    entries = []
    lines = stdout.splitlines() if isinstance(stdout, str) else list(stdout)
    in_listing = False
    for raw_line in lines:
        raw_line = raw_line.rstrip("\r\n")
        line = raw_line.strip()
        if line.startswith("Reading directory"):
            in_listing = True
            continue
        if line.startswith("sftp>") or line.startswith("Connecting") \
                or line.startswith("Connected") or line.startswith("LSCP-RESULT"):
            continue
        if not in_listing or not line:
            continue

        parts = raw_line.lstrip().split(None, 8)
        # The status line that closes a listing ('3 entries') used to be
        # recognised by its word, anywhere in the line, so a file called
        # 'entries.txt' or a directory called 'log-entries' was not shown
        # in the remote panel at all. What tells an entry from a status
        # line is its mode string, so that is what is checked.
        if len(parts) >= 9 and LISTING_MODE.match(parts[0]):
            perms, links, owner, group, size_str, m1, m2, m3, name = parts
            is_link = perms.startswith("l")
            is_dir = perms.startswith("d")
            # A server that supplies its own 'ls -l' text writes a link as
            # 'name -> target'. The target says where the link points, not
            # what it is called, and every operation below is given the
            # name alone - so keeping the arrow made the panel show an
            # entry that no rename, delete or download could ever find.
            target = ""
            if is_link:
                arrow = name.find(" -> ")
                if arrow != -1:
                    name, target = name[:arrow], name[arrow + 4:]
            try:
                size = int(size_str)
            except ValueError:
                size = 0
            date_str = "%s %s %s" % (m1, m2, m3)
            if name in (".", ".."):
                continue
            entries.append({
                "name": name,
                "is_dir": is_dir,
                "is_link": is_link,
                "link_target": target,
                "size": size,
                "permissions": perms,
                "date": date_str,
                "owner": "%s:%s" % (owner, group)
            })
    # Sort folders first, then files
    entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return entries


def list_local_directory(path):
    if not os.path.isabs(path):
        path = os.path.abspath(os.path.join(os.path.expanduser("~"), path))
    if not os.path.exists(path):
        return None, "Path does not exist"
    if not os.path.isdir(path):
        return None, "Path is not a directory"

    entries = []
    try:
        with os.scandir(path) as it:
            for item in it:
                try:
                    is_link = item.is_symlink()
                    try:
                        st = item.stat()
                    except OSError:
                        # A symbolic link whose target is missing has no
                        # stat(). Reading the link itself is what makes it
                        # appear at all: a panel that hides it is a panel
                        # the user cannot select, rename or delete it in,
                        # and it stays on disk after every refresh.
                        if not is_link:
                            continue
                        st = item.stat(follow_symlinks=False)
                    is_dir = item.is_dir()
                    date_str = time.strftime("%b %d %H:%M", time.localtime(st.st_mtime))
                    perms = stat.filemode(st.st_mode)
                    entries.append({
                        "name": item.name,
                        "is_dir": is_dir,
                        "is_link": is_link,
                        "is_broken": is_link and not os.path.exists(item.path),
                        "size": st.st_size if not is_dir else 0,
                        "permissions": perms,
                        "date": date_str,
                        "mtime": st.st_mtime,
                        "owner": "%s:%s" % (st.st_uid, st.st_gid)
                    })
                except OSError:
                    continue
    except Exception as exc:
        return None, str(exc)

    entries.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
    return entries, None



def local_stat_info(path):
    """The attributes the properties dialog shows for a local pane entry."""
    info = os.lstat(path)
    is_link = stat.S_ISLNK(info.st_mode)
    is_dir = stat.S_ISDIR(info.st_mode)
    target_type = "Symbolic link" if is_link else ("Directory" if is_dir else "File")
    permissions = stat.filemode(info.st_mode)
    mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(info.st_mtime))
    raw = "\n".join([
        "Path: %s" % path,
        "Type: %s" % target_type,
        "SizeBytes: %d" % info.st_size,
        "Permissions: %s" % permissions,
        "Modified: %s" % mtime,
        "Owner: %d:%d" % (info.st_uid, info.st_gid),
    ])
    return {"path": path, "size": info.st_size, "mtime": info.st_mtime,
            "is_dir": is_dir, "is_link": is_link, "permissions": permissions,
            "modified": mtime, "owner": "%d:%d" % (info.st_uid, info.st_gid),
            "raw": raw}


def local_checksum(path, algorithm):
    """Hash one local file with the algorithm names the client accepts."""
    if os.path.isdir(path) and not os.path.islink(path):
        raise ValueError("A checksum is computed for files, not directories.")
    if not os.path.isfile(path):
        raise ValueError("That is not a regular file.")
    algorithm = str(algorithm).lower()
    if algorithm == "crc32":
        value = 0
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                value = zlib.crc32(chunk, value)
        return "%08x" % (value & 0xffffffff)
    names = {"sha-256": "sha256", "sha-1": "sha1", "md5": "md5"}
    if algorithm not in names:
        raise ValueError("The algorithm must be one of: sha-256, sha-1, md5 "
                         "or crc32.")
    digest = hashlib.new(names[algorithm])
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def local_search(start, pattern, limit=500, case_sensitive=False,
                 content_query=None, stats=None):
    """Find local files by name and optionally by contents.

    The result shape is the one /api/remote/search already returns, so the
    same browser dialog can search either pane of a local-to-local tab.
    """
    start = os.path.abspath(start)
    if not os.path.isdir(start):
        raise ValueError("The search directory is not a directory.")
    match_name = fnmatch if case_sensitive else (
        lambda name, mask: fnmatch(name.casefold(), mask.casefold()))
    matches = []
    scanned = 0
    skipped = 0
    bytes_scanned = 0
    truncated = False
    wanted = None
    if content_query is not None:
        wanted = content_query if case_sensitive else content_query.casefold()
    for root, directories, names in os.walk(start, followlinks=False):
        directories.sort()
        names.sort()
        for name in names + directories:
            if len(matches) >= limit:
                truncated = True
                break
            path = os.path.join(root, name)
            relative = os.path.relpath(path, start).replace(os.sep, "/")
            if not match_name(relative, pattern) and not match_name(name, pattern):
                continue
            info = None
            try:
                info = os.lstat(path)
            except OSError:
                skipped += 1
                continue
            is_dir = stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
            if os.path.islink(path):
                skipped += 1
                continue
            hit = None
            if content_query is not None:
                if is_dir:
                    continue
                if info.st_size <= 0:
                    continue
                if info.st_size > MAX_CONTENT_SEARCH_FILE_BYTES:
                    skipped += 1
                    continue
                if scanned >= MAX_CONTENT_SEARCH_FILES or \
                        bytes_scanned + info.st_size > MAX_CONTENT_SEARCH_TOTAL_BYTES:
                    truncated = True
                    break
                try:
                    with open(path, "rb") as handle:
                        data = handle.read(MAX_CONTENT_SEARCH_FILE_BYTES + 1)
                except OSError:
                    skipped += 1
                    continue
                scanned += 1
                if len(data) > MAX_CONTENT_SEARCH_FILE_BYTES or b"\0" in data:
                    skipped += 1
                    if len(data) <= MAX_CONTENT_SEARCH_TOTAL_BYTES:
                        bytes_scanned += len(data)
                    continue
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    skipped += 1
                    bytes_scanned += len(data)
                    continue
                bytes_scanned += len(data)
                for line_number, line in enumerate(text.splitlines(), 1):
                    candidate = line if case_sensitive else line.casefold()
                    position = candidate.find(wanted)
                    if position < 0:
                        continue
                    snippet = " ".join(line.split())
                    if len(snippet) > 240:
                        folded = snippet if case_sensitive else snippet.casefold()
                        position = max(0, folded.find(wanted))
                        left = max(0, min(position - 80, len(snippet) - 234))
                        right = left + 234
                        snippet = ("..." if left else "") + snippet[left:right] + \
                            ("..." if right < len(snippet) else "")
                    snippet = "".join(ch if ch >= " " or ch == "\t" else " "
                                       for ch in snippet)
                    hit = {"line": line_number, "snippet": snippet}
                    break
                if hit is None:
                    continue
            else:
                scanned += 1
            entry_match = {
                "path": path,
                "name": name,
                "is_dir": is_dir,
                "size": 0 if is_dir else info.st_size,
                "date": time.strftime("%Y-%m-%d %H:%M",
                                      time.localtime(info.st_mtime)),
                "permissions": stat.filemode(info.st_mode),
            }
            if hit is not None:
                entry_match["line"] = hit["line"]
                entry_match["snippet"] = hit["snippet"]
            matches.append(entry_match)
        if truncated:
            break
    if stats is not None:
        stats.update({"scanned": scanned, "skipped": skipped,
                      "bytes_scanned": bytes_scanned, "truncated": truncated})
    return matches


# ---------------------------------------------------------------------------
# Local-to-local copies (no server, no core process)
# ---------------------------------------------------------------------------
#
# Upstream's local browser session has two local directories and no remote
# side. The copy engine here is deliberately independent of the console
# client: there is no command stream, no quote parser and no SSH state to
# disturb, and a local operation cannot accidentally become a remote one.
#
# The policy is part of the API, because a browser cannot answer an overwrite
# prompt from a background queue thread. A caller that did not state a policy
# gets "ask": if a destination entry exists the request is refused with the
# list of conflicts and nothing is copied, so the page can confirm once and
# retry with an explicit decision. "skip", "overwrite" and "rename" are the
# three answers WinSCP's copy dialog offers.

LOCAL_OVERWRITE_POLICIES = ("ask", "overwrite", "skip", "rename")


class LocalTransferCancelled(Exception):
    """The queue entry was cancelled while a local copy was running."""


class LocalTransferConflict(ValueError):
    """A destination entry exists and the caller did not decide what to do."""

    def __init__(self, conflicts):
        self.conflicts = list(conflicts)
        super().__init__(
            "The destination already contains: %s." % ", ".join(self.conflicts))


def _local_control_characters(path):
    return any(ord(char) < 32 or ord(char) == 127 for char in path)


def check_local_pane_directory(path, label="directory"):
    """Return a local pane path as an absolute directory, or raise."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("The %s is required." % label)
    if _local_control_characters(path):
        raise ValueError("The %s must not contain control characters." % label)
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        raise ValueError("The %s does not exist or is not a directory." % label)
    return path


def _local_lexical_real(path):
    """Resolve the parent of ``path`` but not a symbolic link at its end.

    Copying a symbolic link copies the link itself, so resolving its target
    would compare the wrong two paths for overlap and could make a safe copy
    look recursive (or the reverse).
    """
    parent = os.path.dirname(os.path.abspath(path))
    name = os.path.basename(os.path.abspath(path))
    return os.path.join(os.path.realpath(parent), name)


def _local_within(parent, child):
    try:
        return os.path.commonpath([parent, child]) == parent
    except ValueError:
        return False


def local_transfer_overlap_error(source, destination):
    """Refuse a copy whose destination is the source or lies inside it."""
    source_real = _local_lexical_real(source)
    destination_real = os.path.realpath(destination)
    if source_real == destination_real:
        return "The source and the destination are the same path."
    if _local_within(source_real, destination_real):
        return ("The destination is inside the source directory; copying it "
                "would repeat for ever.")
    if _local_within(destination_real, source_real):
        return ("The source is inside the destination directory; the copy "
                "would overwrite its own input.")
    return ""


def _local_unique_target(target):
    """A free name next to ``target``: 'name (2).ext', 'name (3).ext', ..."""
    base, extension = os.path.splitext(target)
    counter = 2
    while os.path.lexists("%s (%d)%s" % (base, counter, extension)):
        counter += 1
    return "%s (%d)%s" % (base, counter, extension)


def _local_source_size(source):
    """Bytes and regular-file count below one source entry, without links."""
    if os.path.islink(source):
        return 0, 1
    if os.path.isfile(source):
        return os.path.getsize(source), 1
    if not os.path.isdir(source):
        raise ValueError("Only regular files, directories and symbolic links "
                         "can be copied locally.")
    total = 0
    files = 0
    for root, directories, names in os.walk(source, followlinks=False):
        # os.walk lists a symlink to a directory in 'directories' even
        # though it does not descend into it; it is still one entry.
        for name in directories:
            path = os.path.join(root, name)
            if os.path.islink(path):
                files += 1
        for name in names:
            path = os.path.join(root, name)
            if os.path.islink(path):
                files += 1
            elif os.path.isfile(path):
                try:
                    total += os.path.getsize(path)
                except OSError:
                    pass
                files += 1
            else:
                raise ValueError("Only regular files, directories and "
                                 "symbolic links can be copied locally.")
    return total, files


def _local_remove_target(target):
    """Remove one destination entry without following a symbolic link."""
    if os.path.islink(target) or os.path.isfile(target):
        os.unlink(target)
    elif os.path.isdir(target):
        # An empty directory can be replaced by a file or a link. A
        # non-empty one is a tree the caller did not ask to merge, so it is
        # reported rather than deleted.
        os.rmdir(target)
    else:
        raise ValueError("The destination contains an entry this client "
                         "cannot replace.")


def _local_prepare_parent(base, target):
    """Create the parent of ``target`` below ``base``, refusing links.

    A directory in the destination that is a symbolic link is not followed:
    a copy could otherwise create files outside the pane through a link that
    was already there.
    """
    base = os.path.realpath(base)
    parent = os.path.dirname(os.path.abspath(target))
    try:
        relative = os.path.relpath(parent, base)
    except ValueError:
        raise ValueError("The destination escapes the local pane.")
    if relative == ".." or relative.startswith(".." + os.sep):
        raise ValueError("The destination escapes the local pane.")
    current = base
    for part in relative.split(os.sep):
        if part in ("", "."):
            continue
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise ValueError("The destination contains a symbolic link in a "
                             "directory that would have to be entered.")
        if os.path.exists(current):
            if not os.path.isdir(current):
                raise ValueError("A file is in the way of the destination "
                                 "directory.")
        else:
            os.mkdir(current, 0o755)


def _local_check_cancel(task):
    if task is not None and getattr(task, "status", "") == "Cancelling":
        raise LocalTransferCancelled()


def _local_copy_symlink(source, target, task):
    if os.path.lexists(target):
        if os.path.isdir(target) and not os.path.islink(target):
            raise ValueError("A directory is in the way of a symbolic link.")
        os.unlink(target)
    os.symlink(os.readlink(source), target)
    try:
        source_stat = os.lstat(source)
        os.utime(target, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns),
                 follow_symlinks=False)
    except OSError:
        pass


def _local_copy_file(source, target, task):
    if os.path.isdir(target) and not os.path.islink(target):
        raise ValueError("A directory is in the way of a file.")
    _local_check_cancel(task)
    parent = os.path.dirname(target)
    temp = os.path.join(parent, ".linscp-part-%s" % secrets.token_hex(8))
    handle = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(handle, "wb") as output:
            with open(source, "rb") as input_file:
                while True:
                    _local_check_cancel(task)
                    chunk = input_file.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
                    if task is not None:
                        task.bytes_done += len(chunk)
            output.flush()
            os.fsync(output.fileno())
        shutil.copystat(source, temp)
        os.replace(temp, target)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise


def _local_copy_directory(source, target, policy, task, root):
    """Copy one directory tree, merging into an existing directory."""
    if os.path.lexists(target) and (os.path.islink(target) or
                                    not os.path.isdir(target)):
        if policy == "skip":
            if task is not None:
                task.skipped = getattr(task, "skipped", 0) + 1
            return
        if policy != "overwrite":
            raise ValueError("The destination is not a directory.")
        _local_remove_target(target)
    if not os.path.isdir(target):
        os.mkdir(target, 0o755)
    with os.scandir(source) as scan:
        entries = sorted(scan, key=lambda item: item.name)
    for entry in entries:
        _local_check_cancel(task)
        child_source = entry.path
        child_target = os.path.join(target, entry.name)
        if entry.is_symlink():
            if os.path.lexists(child_target):
                if policy == "skip":
                    if task is not None:
                        task.skipped = getattr(task, "skipped", 0) + 1
                    continue
                if policy == "rename":
                    child_target = _local_unique_target(child_target)
                elif policy != "overwrite":
                    raise LocalTransferConflict([entry.name])
            _local_prepare_parent(root, child_target)
            _local_copy_symlink(child_source, child_target, task)
        elif entry.is_dir(follow_symlinks=False):
            _local_prepare_parent(root, child_target)
            _local_copy_directory(child_source, child_target, policy, task, root)
        elif entry.is_file(follow_symlinks=False):
            if os.path.lexists(child_target):
                if policy == "skip":
                    if task is not None:
                        task.skipped = getattr(task, "skipped", 0) + 1
                    continue
                if policy == "rename":
                    child_target = _local_unique_target(child_target)
                elif not os.path.isdir(child_target) or os.path.islink(child_target):
                    if policy != "overwrite":
                        raise LocalTransferConflict([entry.name])
            _local_prepare_parent(root, child_target)
            _local_copy_file(child_source, child_target, task)
        else:
            raise ValueError("Only regular files, directories and symbolic "
                             "links can be copied locally.")
    try:
        shutil.copystat(source, target, follow_symlinks=False)
    except OSError:
        pass


def copy_local_entry(source, target, policy="ask", task=None, move=False,
                     root=None):
    """Copy one local entry; returns a short result description.

    ``task`` is the queue entry being updated, or None for a synchronous
    caller. Cancellation is checked between chunks and between directory
    entries; an interrupted file leaves no half-written destination because
    bytes go to a temporary file in the destination directory first.
    """
    if policy not in LOCAL_OVERWRITE_POLICIES:
        raise ValueError("The overwrite policy must be one of: %s." %
                         ", ".join(LOCAL_OVERWRITE_POLICIES))
    if not os.path.lexists(source):
        raise ValueError("The source no longer exists.")
    overlap = local_transfer_overlap_error(source, target)
    if overlap:
        raise ValueError(overlap)
    root = os.path.realpath(root or os.path.dirname(os.path.abspath(target)))
    # A direct caller (not the queue) has no Task to count skipped entries
    # on. Moves use the same object so a directory whose child was skipped
    # never loses its source just because there was no queue entry to ask.
    counter = task
    if counter is None:
        counter = type("LocalSkipCounter", (object,), {"skipped": 0,
                                                        "status": ""})()
    if os.path.lexists(target):
        if policy == "skip":
            if task is not None:
                task.skipped = getattr(task, "skipped", 0) + 1
            else:
                counter.skipped += 1
            return "skipped"
        if policy == "rename":
            target = _local_unique_target(target)
        elif policy == "ask":
            raise LocalTransferConflict([os.path.basename(target)])
        # 'overwrite' is the only policy left; the type of the existing
        # entry is handled by the copy helper.
    _local_prepare_parent(root, target)
    if os.path.islink(source):
        if os.path.lexists(target) and policy == "overwrite":
            _local_remove_target(target)
        _local_copy_symlink(source, target, counter)
    elif os.path.isdir(source):
        _local_copy_directory(source, target, policy, counter, root)
    elif os.path.isfile(source):
        if os.path.lexists(target) and policy == "overwrite" and \
                (os.path.islink(target) or not os.path.isdir(target)):
            # _local_copy_file replaces a regular file atomically; a
            # symbolic link is removed first so the link target is never
            # written through.
            if os.path.islink(target):
                os.unlink(target)
        _local_copy_file(source, target, counter)
    else:
        raise ValueError("Only regular files, directories and symbolic links "
                         "can be copied locally.")
    if move:
        if counter.skipped:
            return "copied; the source was kept because an entry was skipped"
        _local_check_cancel(counter)
        if os.path.isdir(source) and not os.path.islink(source):
            shutil.rmtree(source)
        else:
            os.unlink(source)
        return "moved"
    return "copied"


def plan_local_transfers(source_dir, destination_dir, names, policy="ask"):
    """Resolve the names of one pane against the other, before copying.

    Returns ``[(source, target), ...]`` with skip entries marked by their
    target being unchanged; raises LocalTransferConflict for an undecided
    overwrite and ValueError for a name that is not one entry of the pane.
    """
    if policy not in LOCAL_OVERWRITE_POLICIES:
        raise ValueError("The overwrite policy must be one of: %s." %
                         ", ".join(LOCAL_OVERWRITE_POLICIES))
    if not isinstance(names, list) or not names:
        raise ValueError("Select one or more entries to copy.")
    source_dir = check_local_pane_directory(source_dir, "source directory")
    destination_dir = check_local_pane_directory(destination_dir,
                                                 "destination directory")
    plans = []
    conflicts = []
    reserved = set()
    for name in names:
        source, containment = contained_local_path(source_dir, name)
        if containment:
            raise ValueError(containment)
        if not os.path.lexists(source):
            raise ValueError("The source %s no longer exists." % name)
        overlap = local_transfer_overlap_error(source, destination_dir)
        if overlap:
            raise ValueError(overlap)
        target = os.path.join(os.path.realpath(destination_dir), name)
        if os.path.lexists(target) or target in reserved:
            if policy == "ask":
                conflicts.append(name)
            elif policy == "rename":
                target = _local_unique_target(target)
                while target in reserved:
                    target = _local_unique_target(target)
            elif policy == "skip":
                pass
            # overwrite keeps the target
        reserved.add(target)
        plans.append((source, target))
    if conflicts:
        raise LocalTransferConflict(conflicts)
    return plans


def local_copy_task(task):
    """The queue worker body of one local copy/move entry."""
    source = task.local_source
    target = task.local_target
    policy = task.local_policy
    total, _files = _local_source_size(source)
    task.bytes_total = total
    task.bytes_done = 0
    task.detail = "Copying %s" % os.path.basename(source)
    result = copy_local_entry(source, target, policy, task=task,
                              move=task.local_move, root=task.local_root)
    if result == "skipped":
        task.detail = "Skipped an existing destination: %s" % target
    elif task.local_move:
        task.detail = "Moved %s" % os.path.basename(source)
    else:
        task.detail = "Copied %s" % os.path.basename(source)


# ---------------------------------------------------------------------------
# Synchronization plans (the console client does the comparison)
# ---------------------------------------------------------------------------

SYNC_ACTIONS = ("download", "upload", "delete-local", "delete-remote", "conflict")

# The values 'synchronize' accepts. Every one of them is interpolated into
# a command line, so each is checked against its own vocabulary: a mode
# that was not one of these three words used to arrive on the command line
# verbatim, and 'synchronize ' + mode made it the start of a new command.
SYNC_MODES = ("local", "remote", "both")
SYNC_CRITERIA = ("none", "either", "both", "time", "size", "checksum",
                 "time,size", "time,checksum", "size,checksum",
                 "time,size,checksum")
SYNC_CONFLICTS = ("skip", "local", "remote", "newer")


def build_sync_command(mode, local_dir, remote_dir, delete=False, criteria="time",
                       filemask="", recursive=True, preview=False, conflict="skip"):
    if mode not in SYNC_MODES:
        raise ValueError("The direction must be local, remote or both.")
    if criteria not in SYNC_CRITERIA:
        raise ValueError("The comparison must be one of: %s." %
                         ", ".join(SYNC_CRITERIA))
    if conflict not in SYNC_CONFLICTS:
        raise ValueError("The conflict policy must be one of: %s." %
                         ", ".join(SYNC_CONFLICTS))
    command = "synchronize " + mode
    if delete:
        command += " -delete"
    if preview:
        command += " -preview"
    if not recursive:
        command += " -nonrecursive"
    if criteria and criteria != "time":
        command += " -criteria=" + criteria
    if conflict and conflict != "skip":
        command += " -conflict=" + conflict
    if filemask:
        # A mask is the one operand the user is meant to type wildcards
        # into, so it is quoted rather than validated against a list.
        command += " -filemask=" + quote_remote(filemask)
    command += " " + quote_local(local_dir) + " " + quote_remote(remote_dir)
    return command


def parse_sync_preview(output):
    """Turn the 'synchronize -preview' output into a plan the UI can show."""
    items = []
    summary = {}
    header = {}
    for line in output:
        line = line.rstrip("\r\n")
        if line.startswith("SYNCPLAN"):
            # The first field carries 'local=...'; the rest are tab separated.
            for field in line[len("SYNCPLAN"):].split("\t"):
                if "=" in field:
                    key, value = field.split("=", 1)
                    header[key] = value
            continue
        if line.startswith("SYNCSUMMARY"):
            for field in line.split(" ")[1:]:
                if "=" in field:
                    key, value = field.split("=", 1)
                    try:
                        summary[key] = int(value)
                    except ValueError:
                        summary[key] = value
            continue
        parts = line.split("\t")
        if parts and parts[0] in SYNC_ACTIONS and len(parts) >= 2:
            items.append({
                "action": parts[0],
                "path": parts[1],
                "reason": parts[2] if len(parts) > 2 else "",
            })
    return {"header": header, "items": items, "summary": summary}


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------

def save_local_stored_session(name, session):
    """Save a local-to-local site without starting the console client.

    The console client has no local transport, so 'savesession' cannot write
    this kind of site. It is still a stored session for this GUI: two local
    directories, no host and no secret. The other sections of sessions.ini
    are copied through byte for byte, so a site written by the console client
    keeps its encrypted password and every setting this function does not
    know about.
    """
    if not isinstance(name, str):
        return False, "The session name must be text."
    name = name.strip()
    if not name:
        return False, "A session name is required."
    if len(name) > 256 or any(ord(char) < 32 or ord(char) == 127
                              for char in name):
        return False, "The session name is not usable."
    error = validate_local_panes(session.get("local_dir") or "",
                                 session.get("other_local_dir") or "")
    if error:
        return False, error
    block = [
        "[%s]" % _escape(name),
        "protocol=local",
        "local_directory=%s" % _escape(os.path.abspath(session["local_dir"])),
        "other_local_directory=%s" % _escape(
            os.path.abspath(session["other_local_dir"])),
        "last_used=%d" % int(time.time()),
    ]
    path = session_store_path()
    directory = os.path.dirname(path)
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except FileNotFoundError:
            lines = []
        preamble = []
        sections = []
        current = None
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                current = {"header": line, "lines": [line], "name": stripped[1:-1]}
                sections.append(current)
            elif current is None:
                preamble.append(line)
            else:
                current["lines"].append(line)
        replaced = False
        output = list(preamble)
        for section in sections:
            if _unescape(section["name"]) == name:
                if not replaced:
                    output.extend(block)
                    replaced = True
                continue
            output.extend(section["lines"])
        if not replaced:
            if output and output[-1].strip():
                output.append("")
            output.extend(block)
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=directory, prefix=".sessions-",
            delete=False)
        temporary = handle.name
        try:
            os.chmod(temporary, 0o600)
            with handle:
                handle.write("\n".join(output).rstrip("\n") + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    except OSError as exc:
        add_log("Cannot save the local session: %s" % exc, "error")
        return False, "Cannot write the session file: %s" % exc
    add_log("Saved local session '%s'" % name, "success")
    return True, ""


def save_stored_session(name, session, pin_hostkey=False, preserve_tunnel_credentials=False):
    """Write a session through 'savesession', so sessions.ini stays the only
    copy of it. Returns (ok, message)."""
    protocol = str(session.get("protocol") or "sftp").lower()
    protocol_flag = protocol
    tls_settings = []
    if protocol == "ftpes":
        protocol_flag, tls_settings = "ftp", ["Ftps=3"]
    elif protocol == "ftps":
        tls_settings = ["Ftps=1"]
    command = "savesession %s" % quote_remote(name)
    for key, flag in (("host", "-host"), ("port", "-port"), ("username", "-username"),
                      ("protocol", "-protocol"), ("keyfile", "-privatekey"),
                      ("hostkey", "-hostkey"), ("initial_dir", "-remotedir"),
                      ("local_dir", "-localdir")):
        value = session.get(key)
        if value in (None, ""):
            continue
        # A wildcard is a decision about one connection, never a stored
        # setting: only pin it when the caller insists.
        if key == "hostkey" and str(value).strip() == "*" and not pin_hostkey:
            continue
        if key == "protocol":
            value = protocol_flag
        text = str(value)
        # A control character in a session field would become a second
        # command when the core reads one command per line in -server mode.
        # The quoting that protects spaces and semicolons cannot make a
        # newline safe, so the field is refused rather than sent.
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
            return False, "The %s contains a control character and cannot be saved." % key
        command += " %s=%s" % (flag, quote_remote(text))
    # Keep a usable password across edits: the console client encrypts
    # it into sessions.ini itself. A locked one (no readable key file)
    # is not in 'session' and stays as it is in the file. The value
    # travels in the environment (see run_linscp), so '-password' names
    # it without stating it: a '-password=SECRET' here would be visible
    # in the process list and in the GUI log.
    if session.get("password"):
        text = str(session["password"])
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
            return False, "The password contains a control character and cannot be saved."
        command += " -password"
    if "tunnel" in session or tls_settings:
        error = validate_session_data(session)
        if error:
            return False, error
        settings = []
        # Only a session that carries the tunnel flag has tunnel settings to
        # write: a TLS-only session must not gain 'Tunnel=0' it never had.
        if "tunnel" in session:
            for field, raw_name in TUNNEL_RAW_FIELDS.items():
                if preserve_tunnel_credentials and field in ("tunnel_password", "tunnel_passphrase"):
                    continue
                default = 22 if field == "tunnel_port" else (
                    0 if field == "tunnel_local_port" else "")
                value = ("1" if session.get("tunnel") else "0") if field == "tunnel" else session.get(field, default)
                if field != "tunnel" and not session.get("tunnel"):
                    continue
                if field == "tunnel_hostkey" and value == "*" and not pin_hostkey:
                    value = ""  # Never persist a one-connection trust bypass.
                settings.append(raw_name + "=" + quote_remote(str(value)))
        settings += [setting.split("=", 1)[0] + "=" +
                     quote_remote(setting.split("=", 1)[1])
                     for setting in gssapi_raw_settings(session)]
        settings += tls_settings
        if settings:
            command += " -rawsettings " + " ".join(settings)
    code, stdout, stderr = run_linscp(command, session)
    if code == 0:
        add_log("Saved session '%s'" % name, "success")
        return True, ""
    message = stderr.strip() or stdout.strip() or "Cannot save the session"
    add_log(message, "error")
    return False, message


def save_confirmed_hostkey(tab, field, fingerprint, name):
    """Remember just this hop's pin, not transient credentials/other pins.

    A destination challenge may follow a jump challenge. Save each explicit
    choice independently, even if a later hop or authentication fails. Existing
    saved secrets are preserved; merely checking Remember never stores the
    passwords/passphrases used to establish this tab.
    """
    previous = next((site for site in read_stored_sessions() if site["name"] == name), {})
    session = dict(tab.session)
    for key in ("hostkey", "tunnel_hostkey", "password"):
        session[key] = previous.get(key, "")
    session[field] = fingerprint
    session["tunnel_password"] = ""
    session["tunnel_passphrase"] = ""
    return save_stored_session(name, session, preserve_tunnel_credentials=True)


# ---------------------------------------------------------------------------
# File-manager shell integration (opt-in "Upload with LinSCP" actions)
# ---------------------------------------------------------------------------
#
# Windows clients get an Explorer context menu; on Linux the equivalent is
# one small definition per file manager, in per-user directories, all of
# them running this program as "linscp-gui --shell-upload FILES...". That
# invocation never transfers anything by itself: it validates and records
# the selection in a per-user manifest, then starts (or reaches) the GUI,
# where the page offers the upload against a session the user has open.
# Nothing is queued until the page confirms, so a right-click can never
# send files anywhere unattended. Filenames reach us as separate argv
# entries (%F in the desktop definitions, "$@" in the Nautilus script),
# never through a shell command line a name could break out of.

SHELL_MARKER = "linscp-shell-integration"
SHELL_UPLOAD_MAX_FILES = 512
SHELL_MANIFEST_MAX_AGE = 7 * 24 * 3600
_SHELL_MANIFEST_ID = re.compile(r"^[0-9a-f]{32}$")


def _xdg_data_home():
    root = os.environ.get("XDG_DATA_HOME")
    if root:
        return root
    return os.path.join(os.path.expanduser("~"), ".local", "share")


def _shell_launcher():
    """The absolute launcher path the file-manager definitions will run.

    A definition written with a bare name depends on the file manager's
    PATH, which a desktop session can set to almost anything; a path with
    characters the desktop Exec syntax or a POSIX shell would read as
    syntax is refused rather than quoted creatively, because the result
    would be executed on every right-click.
    """
    found = shutil.which("linscp-gui")
    if not found:
        candidate = os.path.abspath(sys.argv[0]) if sys.argv and sys.argv[0] else ""
        if candidate and os.path.isfile(candidate):
            found = candidate
    if not found:
        raise ValueError("the linscp-gui launcher is not on PATH, so there "
                         "is nothing for a file manager to run")
    found = os.path.abspath(found)
    for bad in ('"', "'", '$', '`', '\\', '%', '\n', '\r'):
        if bad in found:
            raise ValueError("the launcher path %r contains %r, which "
                             "cannot be carried safely in a desktop Exec "
                             "line" % (found, bad))
    return found


def _exec_token(path):
    """One launcher path as one desktop Exec argument."""
    return '"%s"' % path if " " in path else path


def shell_integration_definitions(launcher):
    """(file manager, path, content, mode) for every definition we write.

    One canonical location per manager (Dolphin also reads the older
    kservices5 service-menu directory, so both are written; an absent
    extra copy is harmless to the managers that do not look there).
    """
    data = _xdg_data_home()
    note = ("# %s: written by 'linscp-gui --install-shell-integration';\n"
            "# remove it with 'linscp-gui --uninstall-shell-integration'.\n")
    marker_note = note % SHELL_MARKER
    dolphin = (marker_note +
        "[Desktop Entry]\n"
        "Type=Service\n"
        "ServiceTypes=KonqPopupMenu/Plugin\n"
        "MimeType=all/allfiles;inode/directory;\n"
        "Actions=LinSCPUpload;\n"
        "X-KDE-Priority=TopLevel\n"
        "X-LinSCP-Shell-Integration=true\n"
        "\n"
        "[Desktop Action LinSCPUpload]\n"
        "Name=Upload with LinSCP\n"
        "Comment=Send the selected files to a server with LinSCP\n"
        "Icon=linscp\n"
        "Exec=%s --shell-upload %%F\n" % _exec_token(launcher))
    nemo = (marker_note +
        "[Nemo Action]\n"
        "Active=true\n"
        "Name=Upload with LinSCP\n"
        "Comment=Send the selected files to a server with LinSCP\n"
        "Icon-Name=linscp\n"
        "Selection=Any\n"
        "Extensions=any\n"
        "Quote=double\n"
        "Exec=%s --shell-upload %%F\n" % _exec_token(launcher))
    nautilus = ("#!/bin/sh\n" + marker_note +
        'exec "%s" --shell-upload "$@"\n' % launcher)
    return [
        ("Dolphin (KDE)",
         os.path.join(data, "kio", "servicemenus", "linscp-upload.desktop"),
         dolphin, 0o644),
        ("Dolphin (KDE, classic service menus)",
         os.path.join(data, "kservices5", "ServiceMenus",
                      "linscp-upload.desktop"),
         dolphin, 0o644),
        ("Files (GNOME)",
         os.path.join(data, "nautilus", "scripts", "LinSCP Upload"),
         nautilus, 0o755),
        ("Nemo (Cinnamon)",
         os.path.join(data, "nemo", "actions", "linscp-upload.nemo_action"),
         nemo, 0o644),
    ]


def _shell_target_status(path):
    """'missing', 'ours' or 'foreign' for one definition path."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            head = handle.read(4096)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "foreign"
    return "ours" if SHELL_MARKER in head else "foreign"


def install_shell_integration():
    """Write the per-user file-manager definitions.

    Returns one (manager, path, outcome) triple per definition. A file
    that exists without our marker is the user's own and is never
    overwritten; it is reported as 'kept (not written by LinSCP)'.
    """
    launcher = _shell_launcher()
    results = []
    for manager, path, content, mode in shell_integration_definitions(launcher):
        status = _shell_target_status(path)
        if status == "foreign":
            results.append((manager, path, "kept (not written by LinSCP)"))
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(path, mode)
        results.append((manager, path,
                        "updated" if status == "ours" else "installed"))
    return results


def uninstall_shell_integration():
    """Remove definitions install_shell_integration wrote, nothing else."""
    launcher = _shell_launcher()
    results = []
    for manager, path, _content, _mode in shell_integration_definitions(launcher):
        status = _shell_target_status(path)
        if status == "missing":
            results.append((manager, path, "not installed"))
        elif status == "foreign":
            results.append((manager, path, "kept (not written by LinSCP)"))
        else:
            os.unlink(path)
            results.append((manager, path, "removed"))
    return results


def shell_integration_status():
    """Where each definition stands, for --help output and tests."""
    launcher = _shell_launcher()
    return [(manager, path, _shell_target_status(path))
            for manager, path, _c, _m in shell_integration_definitions(launcher)]


def _shell_manifest_dir():
    path = os.path.join(_config_root(), "shell-manifests")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def _shell_manifest_path(manifest_id):
    if not _SHELL_MANIFEST_ID.match(manifest_id or ""):
        raise ValueError("No such file-manager selection.")
    return os.path.join(_shell_manifest_dir(), manifest_id + ".json")


def record_shell_upload(paths):
    """Validate one file-manager selection and store it as a manifest.

    Only absolute paths of existing files and directories are recorded:
    a file manager hands over no other kind, and a relative or vanished
    path means a caller other than one of our definitions.
    """
    if not paths:
        raise ValueError("no files were given")
    if len(paths) > SHELL_UPLOAD_MAX_FILES:
        raise ValueError("too many files in one selection (at most %d)"
                         % SHELL_UPLOAD_MAX_FILES)
    files = []
    seen = set()
    for raw in paths:
        if not isinstance(raw, str) or not raw:
            raise ValueError("an empty path was given")
        if any(ord(char) < 0x20 or ord(char) == 0x7f for char in raw):
            raise ValueError("a path contains a control character: %r" % raw)
        if not os.path.isabs(raw):
            raise ValueError("a relative path was given: %r" % raw)
        path = os.path.realpath(raw)
        if path in seen:
            continue
        seen.add(path)
        try:
            info = os.stat(path)
        except OSError:
            raise ValueError("not found: %s" % raw)
        if stat.S_ISDIR(info.st_mode):
            files.append({"path": path, "name": os.path.basename(path),
                          "is_dir": True, "size": 0})
        elif stat.S_ISREG(info.st_mode):
            files.append({"path": path, "name": os.path.basename(path),
                          "is_dir": False, "size": info.st_size})
        else:
            raise ValueError("not a file or directory: %s" % raw)
        if not files[-1]["name"]:
            raise ValueError("a path has no name to upload under: %s" % raw)
    manifest_id = secrets.token_hex(16)
    record = {"id": manifest_id, "created": time.time(), "files": files}
    target = _shell_manifest_path(manifest_id)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(record, handle)
    return manifest_id, files


def _read_shell_manifest(manifest_id):
    path = _shell_manifest_path(manifest_id)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            record = json.load(handle)
    except FileNotFoundError:
        raise ValueError("That file-manager selection is no longer waiting.")
    except ValueError:
        raise ValueError("That file-manager selection cannot be read.")
    files = record.get("files")
    if record.get("id") != manifest_id or not isinstance(files, list) or \
            not files or len(files) > SHELL_UPLOAD_MAX_FILES:
        raise ValueError("That file-manager selection cannot be read.")
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) \
                or not os.path.isabs(item["path"]):
            raise ValueError("That file-manager selection cannot be read.")
    return record


def list_shell_pending():
    """Selections still waiting, oldest first; stale ones are dropped.

    Read from disk on every call: the process that recorded a selection
    (started by the file manager) is not necessarily the one serving the
    page, because a GUI may already have been running.
    """
    directory = _shell_manifest_dir()
    pending = []
    now = time.time()
    try:
        names = os.listdir(directory)
    except OSError:
        return pending
    for name in names:
        if not name.endswith(".json"):
            continue
        manifest_id = name[:-5]
        if not _SHELL_MANIFEST_ID.match(manifest_id):
            continue
        try:
            record = _read_shell_manifest(manifest_id)
        except ValueError:
            continue
        created = record.get("created") or 0
        if now - created > SHELL_MANIFEST_MAX_AGE:
            try:
                os.unlink(os.path.join(directory, name))
            except OSError:
                pass
            continue
        pending.append({
            "id": manifest_id,
            "created": created,
            "files": [{"name": item.get("name") or os.path.basename(item["path"]),
                       "path": item["path"],
                       "is_dir": bool(item.get("is_dir")),
                       "size": int(item.get("size") or 0)}
                      for item in record["files"]],
        })
    pending.sort(key=lambda item: item["created"])
    return pending


def dismiss_shell_upload(manifest_id):
    """Forget a waiting selection; True when there was one to forget."""
    try:
        os.unlink(_shell_manifest_path(manifest_id))
        return True
    except FileNotFoundError:
        return False


def consume_shell_upload(manifest_id, tab):
    """Queue one waiting selection as uploads into a session tab.

    The manifest is removed whatever the per-file outcome, and the
    outcome is reported per file, so a file deleted since the
    right-click is named once instead of being offered forever.
    """
    record = _read_shell_manifest(manifest_id)
    dismiss_shell_upload(manifest_id)
    remote_dir = tab.remote_dir
    queued, missing = [], []
    for item in record["files"]:
        path = item["path"]
        name = item.get("name") or os.path.basename(path)
        if not os.path.exists(path):
            missing.append(name)
            continue
        remote_target = posixpath.join(remote_dir, name)
        command = "lcd %s ; cd %s ; put %s %s" % (
            quote_local(os.path.dirname(path)), quote_remote(remote_dir),
            transfer_switches({}, protocol=tab.session.get("protocol")),
            quote_local(name))
        task = TASKS.submit("Upload", command, tab.session, path,
                            remote_target, tab.id,
                            progress_remote=(tab.id, remote_target))
        if not item.get("is_dir"):
            try:
                task.bytes_total = os.path.getsize(path)
            except OSError:
                task.bytes_total = 0
        queued.append(name)
    return {"queued": queued, "missing": missing, "remote_dir": remote_dir}


class LinScpGuiHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    # -- access control ----------------------------------------------------

    def _request_host(self):
        host = (self.headers.get("Host") or "").strip()
        # A bracketed IPv6 literal keeps its brackets until here.
        if host.startswith("["):
            host = host[1:host.find("]")] if "]" in host else host
        else:
            host = host.split(":")[0]
        return host.strip().lower()

    def _supplied_token(self):
        header = self.headers.get("X-LSCP-Token") or ""
        if header:
            return header
        auth = self.headers.get("Authorization") or ""
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return ""

    def guarded(self):
        """Check the Host, the token and (optionally) the login session
        of a /api/ request.

        Returns True when the request may go through. The Host check is what
        stops a DNS-rebinding page from using this server: such a page is
        served from another host name, so it arrives with a Host header this
        server does not answer to, even though the browser thinks it is
        talking to itself.

        When ACCOUNTS_FILE is set, the request must also carry a valid login
        cookie (LSCP_SID). POST requests must include the X-LSCP-CSRF header
        matching the CSRF token to prevent cross-site request forgery.
        """
        if not ALLOW_ANY_HOST and self._request_host() not in ALLOWED_HOSTS:
            self.send_json({"success": False,
                            "error": "This host name is not allowed. Start the "
                                     "server with --allow-host=%s to accept it."
                                     % (self._request_host() or "this host")},
                           status=403)
            return False
        if REQUIRE_TOKEN and not hmac.compare_digest(
                self._supplied_token(), API_TOKEN):
            self.send_json({"success": False,
                            "error": "This API needs this run's token in an "
                                     "X-LSCP-Token header."}, status=401)
            return False
        # Multi-user account check: when ACCOUNTS_FILE is configured,
        # every /api/ request (except /api/login itself) must carry a
        # valid login session cookie.
        if ACCOUNTS_FILE:
            path = self.path.split("?")[0]
            if path != "/api/login":
                sid = _extract_login_cookie(self)
                record = _login_session_record(sid)
                username = record.get("username") if record else None
                if not username:
                    self.send_json({"success": False,
                                    "error": "Login required.",
                                    "login_required": True}, status=401)
                    return False
                # CSRF protection: a state-changing request must carry the
                # token issued to this login session, compared in constant
                # time so the answer does not leak how much of it matched.
                if self.command == "POST" and not _csrf_ok(self, sid):
                    self.send_json({"success": False,
                                    "error": "CSRF token missing or "
                                             "invalid.",
                                    "login_required": True}, status=403)
                    return False
                bind_workspace(workspace_for_user(
                    username, record.get("home_dir") or ""))
        return True

    def serve_client(self):
        """Send the page, with this run's token baked into it."""
        for name in ("index.html", "index.htm"):
            target = os.path.join(WEB_DIR, name)
            if not os.path.isfile(target):
                continue
            try:
                with open(target, "rb") as handle:
                    page = handle.read()
            except OSError as exc:
                self.send_error(500, "Cannot read %s: %s" % (name, exc))
                return
            marker = b"</head>"
            # Both values are JSON strings rather than executable source.
            config = json.dumps({"token": API_TOKEN, "language": ui_language()})
            config = config.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            snippet = ("<script>const LSCP_CONFIG = " + config +
                       ";window.LSCP_TOKEN = LSCP_CONFIG.token;" +
                       "window.LSCP_LANGUAGE = LSCP_CONFIG.language;</script>").encode("utf-8")
            if marker in page:
                page = page.replace(marker, snippet + marker, 1)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return
        return super().do_GET()

    def end_headers(self):
        # No wildcard CORS. The page this server hands out carries this
        # run's API token, and 'Access-Control-Allow-Origin: *' let any
        # web site the user visited fetch that page, read the token out of
        # it and then drive the whole API from its own origin - listing,
        # reading, changing and deleting the local file system. The
        # browser client is served by this same server, so it is always
        # same-origin and never needs a CORS header; --allow-origin=NAME
        # is the explicit opt-in for a front end that really is elsewhere.
        origin = self.headers.get("Origin") or ""
        if origin and origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers",
                             "Content-Type, X-LSCP-Token, X-LSCP-CSRF")
            # A cross-origin request that is allowed at all has to be
            # allowed to carry its token, and must not also be allowed to
            # carry cookies it was not issued.
            self.send_header("Vary", "Origin")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        # The token in the page is what protects the API; a frame from
        # another site must not be able to host it.
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def do_OPTIONS(self):
        origin = self.headers.get("Origin") or ""
        if origin and origin not in ALLOWED_ORIGINS:
            self.send_json({"success": False,
                            "error": "This origin is not allowed."}, status=403)
            return
        self.send_response(200)
        self.end_headers()

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def request_content_length(self):
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Transfer-Encoding is not supported.")
        values = self.headers.get_all("Content-Length", [])
        if len(values) > 1:
            raise ValueError("Multiple Content-Length headers are not allowed.")
        if not values:
            return None
        value = values[0].strip()
        if not re.fullmatch(r"[0-9]+", value):
            raise ValueError("The request body length is invalid.")
        return int(value)

    def read_json_body(self):
        content_length = self.request_content_length()
        if content_length is None:
            return {}
        if content_length > MAX_JSON_BODY_BYTES:
            raise RequestTooLarge(
                "JSON request bodies are limited to %d bytes." % MAX_JSON_BODY_BYTES)
        if content_length == 0:
            return {}
        raw = self.rfile.read(content_length)
        if len(raw) != content_length:
            raise ValueError("The request body ended before all bytes arrived.")
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("The request body must be valid UTF-8 JSON.") from exc
        if not isinstance(body, dict):
            raise ValueError("The request body must be a JSON object.")
        return body

    # -- GET ---------------------------------------------------------------

    def do_GET(self):
        try:
            return self._dispatch_get()
        except ValueError as exc:
            # An operand this server will not put on a command line - a path
            # holding a control character, a mode that is not a mode.
            # Answering 400 says why; letting it reach socketserver closes
            # the connection with a traceback and no answer at all.
            return self.send_json({"success": False, "error": str(exc)},
                                  status=400)
        finally:
            unbind_workspace()

    def do_POST(self):
        try:
            return self._dispatch_post()
        except RequestTooLarge as exc:
            self.close_connection = True
            return self.send_json({"success": False, "error": str(exc)},
                                  status=413)
        except ValueError as exc:
            self.close_connection = True
            return self.send_json({"success": False, "error": str(exc)},
                                  status=400)
        finally:
            unbind_workspace()

    def _dispatch_get(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            return self.serve_client()

        # Login status: returns the current username and this session's own
        # CSRF token. It is answered before guarded() because it is how a
        # page that has just been told 'login_required' learns whether it
        # is signed in, and it gives out nothing to a caller with no
        # session cookie.
        if path == "/api/login" and ACCOUNTS_FILE:
            sid = _extract_login_cookie(self)
            record = _login_session_record(sid)
            username = record.get("username") if record else None
            self.send_json({
                "logged_in": username is not None,
                "username": username or "",
                "csrf_token": (record or {}).get("csrf", ""),
                "accounts_enabled": True,
            })
            return

        if path.startswith("/api/") and not self.guarded():
            return

        if path == "/api/accounts":
            # Whether this run asks for a sign-in at all, so a page can show
            # the form instead of failing its first call.
            self.send_json({"accounts_enabled": bool(ACCOUNTS_FILE)})
            return

        if path == "/api/status":
            with STATE_LOCK:
                tabs = [tab.describe() for tab in STATE["tabs"]]
                active = STATE["active_tab"]
            tab = get_tab()
            session = dict(tab.session) if tab else new_session()
            for secret in ("password", "tunnel_password", "tunnel_passphrase"):
                session.pop(secret, None)
            self.send_json({
                "connected": tab is not None and tab.connected,
                "session": session,
                "local_dir": tab.local_dir if tab else default_local_dir(),
                "remote_dir": tab.remote_dir if tab else "/",
                "other_local_dir": tab.other_local_dir if tab else "",
                "is_local": bool(tab and getattr(tab, "is_local", False)),
                "binary": LINSCP_BIN,
                "tabs": tabs,
                "active_tab": active,
                "paused": STATE["paused"],
                "sessions_file": session_store_path(),
            })
            return

        if path == "/api/terminal/output":
            if not self.guarded():
                return
            term = get_terminal(query.get("terminal", [None])[0])
            if term is None:
                self.send_json({"success": False,
                                "error": "No such terminal."}, status=400)
                return
            try:
                after = int(query.get("after", ["0"])[0])
            except ValueError:
                after = 0
            data, offset, alive, exit_code = term.poll(after)
            self.send_json({"success": True,
                            "data": base64.b64encode(data).decode("ascii"),
                            "offset": offset, "alive": alive,
                            "exit_code": exit_code})
            return

        if path == "/api/logs":
            with STATE_LOCK:
                self.send_json({"logs": list(STATE["logs"])})
            return

        if path == "/api/shell/pending":
            # File-manager selections waiting to be offered as uploads.
            # Nothing here transfers; the page asks the user first.
            self.send_json({"success": True, "pending": list_shell_pending()})
            return

        if path == "/api/transfers":
            with STATE_LOCK:
                self.send_json({
                    "transfers": [task.as_dict() for task in STATE["tasks"]],
                    "paused": STATE["paused"],
                })
            return

        if path == "/api/sessions":
            self.send_json({"sessions": read_stored_sessions(),
                            "file": session_store_path()})
            return

        if path == "/api/workspaces":
            try:
                workspaces = list_workspaces()
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json({"success": True, "workspaces": workspaces,
                            "file": workspace_store_path()})
            return

        if path == "/api/bookmarks":
            try:
                side = query.get("side", [None])[0]
                bookmarks = list_bookmarks(side)
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json({"success": True,
                            "bookmarks": bookmarks if side else
                            {"local": bookmarks["local"],
                             "remote": bookmarks["remote"]},
                            "file": bookmark_store_path()})
            return

        if path == "/api/session/url":
            tab = require_tab(query.get("tab", [None])[0])
            if tab is None:
                tab = get_tab()
            include_password = str(
                query.get("password", ["0"])[0]).strip().lower() in (
                    "1", "true", "on", "yes")
            try:
                result = generate_session_url(
                    tab, include_password,
                    query.get("path", [""])[0])
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json(result)
            return

        if path == "/api/sessions/import":
            source = query.get("source", [None])[0]
            path_arg = query.get("path", [""])[0]
            try:
                if source:
                    result = scan_import_source(source, path_arg)
                    self.send_json({"success": True, "sources": [result]})
                else:
                    self.send_json({"success": True,
                                    "sources": scan_import_sources()})
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
            return

        if path == "/api/preferences":
            self.send_json({"success": True,
                            "preferences": read_preferences(),
                            "defaults": PREFERENCE_DEFAULTS,
                            "file": preferences_path()})
            return

        if path == "/api/cleanup":
            locations = cleanup_locations()
            self.send_json({"success": True, "locations": locations,
                            "any": any(item["exists"] for item in locations)})
            return

        if path == "/api/remote/transfer/targets":
            tab = require_tab(query.get("tab", [None])[0])
            try:
                self.send_json({"success": True,
                                "targets": remote_transfer_targets(tab)})
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
            return

        if path == "/api/local/list":
            req_path = query.get("path", [None])[0]
            tab = get_tab(query.get("tab", [None])[0])
            if not req_path:
                req_path = tab.local_dir if tab else default_local_dir()
            req_path, jail_error = confined_local_path(req_path)
            if jail_error:
                self.send_json({"success": False, "error": jail_error},
                               status=403)
                return
            entries, err = list_local_directory(req_path)
            if err:
                self.send_json({"success": False, "error": err}, status=400)
            else:
                if tab is not None:
                    tab.local_dir = req_path
                self.send_json({"success": True, "path": req_path, "entries": entries})
            return

        if path == "/api/local/edit":
            tab = get_tab(query.get("tab", [None])[0])
            local_path = query.get("path", [""])[0]
            if not local_path:
                self.send_json({"success": False, "error": "No file given"}, status=400)
                return
            local_path, path_error = resolve_local_file(tab, local_path)
            if path_error:
                self.send_json({"success": False, "error": path_error}, status=400)
                return
            content, info, error = read_local_text(local_path)
            if error:
                self.send_json({"success": False, "error": error}, status=400)
                return
            self.send_json({"success": True, "path": local_path,
                            "content": content, "info": info})
            return

        if path == "/api/remote/list":
            tab = require_tab(query.get("tab", [None])[0])
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            if getattr(tab, "is_local", False):
                req_path = (query.get("path", [None])[0] or
                            tab.remote_dir or tab.other_local_dir)
                req_path, jail_error = confined_local_path(req_path)
                if jail_error:
                    self.send_json({"success": False, "error": jail_error},
                                   status=403)
                    return
                entries, err = list_local_directory(req_path)
                if err:
                    self.send_json({"success": False, "error": err},
                                   status=400)
                    return
                tab.remote_dir = req_path
                tab.other_local_dir = req_path
                self.send_json({"success": True, "path": req_path,
                                "entries": entries})
                return
            req_path = query.get("path", [None])[0] or tab.remote_dir
            code, lines = tab.run_many(["cd " + quote_remote(req_path), "pwd", "ls -la"])
            if code != 0:
                self.send_json({"success": False,
                                "error": "\n".join(lines) or "Directory read failed"},
                               status=400)
                return
            resolved = req_path
            for line in lines:
                if line.startswith("/"):
                    resolved = line.strip()
                    break
            tab.remote_dir = resolved
            self.send_json({"success": True, "path": resolved,
                            "entries": parse_ls_output(lines)})
            return

        if path == "/api/remote/edit":
            tab = require_tab(query.get("tab", [None])[0])
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            remote_path = query.get("path", [""])[0]
            if not remote_path:
                self.send_json({"success": False, "error": "No file given"}, status=400)
                return
            if getattr(tab, "is_local", False):
                local_path, path_error = resolve_local_pane_file(
                    tab, remote_path, "remote")
                if path_error:
                    self.send_json({"success": False, "error": path_error},
                                   status=400)
                    return
                content, info, error = read_local_text(local_path)
                if error:
                    self.send_json({"success": False, "error": error},
                                   status=400)
                else:
                    self.send_json({"success": True, "path": local_path,
                                    "content": content, "info": info})
                return
            content, info, error = download_remote_text(tab, remote_path)
            if error:
                self.send_json({"success": False, "error": error}, status=400)
                return
            self.send_json({"success": True, "path": remote_path, "content": content,
                            "info": info})
            return

        return super().do_GET()

    # -- POST --------------------------------------------------------------

    def _dispatch_post(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        # Login endpoint is exempt from the auth guard.
        if path == "/api/login" and ACCOUNTS_FILE:
            body = self.read_json_body()
            username = str(body.get("username") or "")
            password = str(body.get("password") or "")
            if not username or not password:
                self.send_json({"success": False,
                                "error": "A user name and a password are "
                                         "required."}, status=400)
                return
            delay = _login_throttle(username)
            if delay:
                self.send_json({"success": False, "retry_after": delay,
                                "error": "Too many failed sign-ins. Try again "
                                         "in %d seconds." % delay}, status=429)
                return
            if _authenticate_user(username, password):
                _login_succeeded(username)
                sid, csrf = _create_login_session(username)
                add_log("User '%s' signed in." % username, "success")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie",
                    "LSCP_SID=%s; Path=/; HttpOnly; SameSite=Strict; Max-Age=%d"
                    % (sid, SESSION_SECS))
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True, "username": username,
                    "csrf_token": csrf}).encode("utf-8"))
            else:
                # A failed sign-in is recorded before the answer is sent, so
                # an endpoint that is open to anything able to reach the
                # port cannot be used to try a password list at speed.
                _login_failed(username)
                add_log("Failed sign-in for '%s'." % username, "error")
                self.send_json({"success": False,
                                "error": "Invalid username or password."},
                               status=401)
            return
        if path == "/api/logout" and ACCOUNTS_FILE:
            sid = _extract_login_cookie(self)
            if sid:
                with _LOGIN_LOCK:
                    _LOGIN_SESSIONS.pop(sid, None)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie",
                "LSCP_SID=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return
        if path.startswith("/api/") and not self.guarded():
            return
        if path == "/api/transfer/drop":
            query = urllib.parse.parse_qs(parsed.query)
            try:
                tab_id = int(query.get("tab", [""])[0])
                content_length = self.request_content_length()
            except (TypeError, ValueError):
                self.close_connection = True
                self.send_json({"success": False,
                                "error": "Invalid upload request."}, status=400)
                return
            if content_length is None:
                self.close_connection = True
                self.send_json({"success": False,
                                "error": "The upload size is missing."}, status=411)
                return
            if content_length > MAX_BROWSER_UPLOAD_BYTES:
                self.close_connection = True
                self.send_json({"success": False,
                                "error": "Browser uploads are limited to 1 GiB."},
                               status=413)
                return
            if self.headers.get_content_type() != "application/octet-stream":
                self.close_connection = True
                self.send_json({"success": False,
                                "error": "Expected an octet-stream file upload."},
                               status=415)
                return
            tab = require_tab(tab_id)
            if tab is None or tab.id != tab_id:
                self.close_connection = True
                self.send_json({"success": False, "error": "Not connected"},
                               status=400)
                return
            filename = query.get("name", [""])[0]
            remote_dir = query.get("remote_dir", [tab.remote_dir])[0]
            relative_path = query.get("relative_path", [filename])[0]
            if getattr(tab, "is_local", False):
                # The "remote" pane of a local-to-local tab is a directory
                # on this machine. The bytes are written exactly where a
                # drop onto that pane means, through the same containment
                # check the local pane uses.
                try:
                    destination = save_local_browser_upload(
                        remote_dir, filename, self.rfile, content_length,
                        relative_path)
                except (IOError, OSError, ValueError) as exc:
                    self.close_connection = True
                    self.send_json({"success": False,
                                    "error": "Could not save the file: %s" % exc},
                                   status=400)
                    return
                self.send_json({"success": True, "path": destination})
                return
            try:
                task = queue_browser_upload(tab, remote_dir, filename,
                                            self.rfile, content_length,
                                            relative_path)
            except (IOError, OSError, ValueError) as exc:
                self.close_connection = True
                self.send_json({"success": False,
                                "error": "Could not receive the file: %s" % exc},
                               status=400)
                return
            self.send_json({"success": True, "task_id": task.id})
            return

        if path == "/api/local/drop":
            query = urllib.parse.parse_qs(parsed.query)
            try:
                content_length = self.request_content_length()
            except (TypeError, ValueError):
                self.close_connection = True
                self.send_json({"success": False,
                                "error": "Invalid upload request."}, status=400)
                return
            if content_length is None:
                self.close_connection = True
                self.send_json({"success": False,
                                "error": "The upload size is missing."}, status=411)
                return
            if content_length > MAX_BROWSER_UPLOAD_BYTES:
                self.close_connection = True
                self.send_json({"success": False,
                                "error": "Browser uploads are limited to 1 GiB."},
                               status=413)
                return
            if self.headers.get_content_type() != "application/octet-stream":
                self.close_connection = True
                self.send_json({"success": False,
                                "error": "Expected an octet-stream file upload."},
                               status=415)
                return
            tab = get_tab(query.get("tab", [None])[0])
            default_local = tab.local_dir if tab else os.path.expanduser("~")
            filename = query.get("name", [""])[0]
            local_dir = query.get("local_dir", [default_local])[0]
            relative_path = query.get("relative_path", [filename])[0]
            try:
                dest = save_local_browser_upload(
                    local_dir, filename, self.rfile, content_length,
                    relative_path)
            except (IOError, OSError, ValueError) as exc:
                self.close_connection = True
                self.send_json({"success": False,
                                "error": "Could not save the dropped file: %s" % exc},
                               status=400)
                return
            self.send_json({"success": True, "path": dest})
            return

        body = self.read_json_body()

        if path == "/api/local/drop-dir":
            if not isinstance(body, dict):
                self.send_json({"success": False, "error": "Invalid drop request"},
                               status=400)
                return
            tab = get_tab(body.get("tab"))
            default_local = tab.local_dir if tab else os.path.expanduser("~")
            try:
                dest = save_local_browser_directory(
                    body.get("local_dir") or default_local,
                    body.get("relative_path"))
            except (OSError, ValueError) as exc:
                self.send_json({"success": False, "error": str(exc)}, status=400)
                return
            self.send_json({"success": True, "path": dest})
            return

        if path == "/api/transfer/drop-dir":
            if not isinstance(body, dict):
                self.send_json({"success": False, "error": "Invalid drop request"},
                               status=400)
                return
            tab = require_tab(body.get("tab"))
            if tab is None or str(tab.id) != str(body.get("tab")):
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            try:
                task = queue_browser_directory(
                    tab, body.get("remote_dir", tab.remote_dir),
                    body.get("relative_path"))
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)}, status=400)
                return
            self.send_json({"success": True, "task_id": task.id})
            return

        if path == "/api/tabs/open":
            session = dict(new_session())
            given = body.get("session")
            if given is None:
                given = {}
            if not isinstance(given, dict):
                self.send_json({"success": False,
                                "error": "The session must be a JSON object."},
                               status=400)
                return
            for key in ("protocol", "ftps", "host", "port", "username", "password",
                        "keyfile", "hostkey", "initial_dir", "local_dir",
                        "other_local_dir", "site",
                        "tunnel", "tunnel_host", "tunnel_port", "tunnel_username",
                        "tunnel_private_key", "tunnel_hostkey", "tunnel_password",
                        "tunnel_passphrase", "tunnel_error", "tunnel_local_port",
                        "auth_gssapi", "auth_gssapi_kex", "gssapi_fwd_tgt",
                        "logical_host"):
                if key in given:
                    session[key] = given[key]
            error = validate_session_data(
                session, require_host=not session_is_local(session))
            requested_name = body.get("name")
            given_name = given.get("name")
            name = requested_name or given_name
            if ((requested_name is not None and not isinstance(requested_name, str)) or
                    (given_name is not None and not isinstance(given_name, str))):
                error = "The tab name must be text."
            if error:
                self.send_json({"success": False, "error": error}, status=400)
                return
            with STATE_LOCK:
                tab = CoreSession(STATE["next_tab"], session, name=name)
                STATE["next_tab"] += 1
            if session_is_local(session):
                add_log("Opening local panes %s and %s..." %
                        (session.get("local_dir"), session.get("other_local_dir")),
                        "info")
            else:
                add_log("Connecting to %s (%s)..." % (session.get("host"),
                                                     session.get("protocol")),
                        "info")
            ok, error = tab.connect()
            with STATE_LOCK:
                if ok:
                    STATE["tabs"].append(tab)
                    STATE["active_tab"] = tab.id
                elif tab.observed_hostkey:
                    # Park it until the user says what to do with this key.
                    STATE["challenges"][tab.id] = tab
                elif not STATE["tabs"]:
                    STATE["tabs"].append(tab)
                    STATE["active_tab"] = tab.id
                else:
                    # A failed connection with no key to ask about is not
                    # reachable from the interface any more, but connect()
                    # already started its core process. Dropping the tab
                    # without terminating it left a linscp -server running
                    # for every failed attempt, with its socket open.
                    tab.terminate()
            if ok:
                add_log("Connected to %s" % tab.name, "success")
                self.send_json({"success": True, "tab": tab.describe()})
                return
            add_log("Connection failed: %s" % error, "error")
            challenge = None
            if tab.observed_hostkey:
                challenge = tab.hostkey_challenge()
                add_log("Host key offered by %s: %s" %
                        (session.get("host"), tab.observed_hostkey), "info")
            self.send_json({"success": False, "error": error, "challenge": challenge,
                            "tab": tab.describe()}, status=400)
            return

        if path == "/api/tabs/verify":
            tab_id = body.get("tab")
            fingerprint = body.get("fingerprint") or ""
            if not isinstance(fingerprint, str) or not fingerprint.strip():
                self.send_json({"success": False, "error": "No host key given"},
                               status=400)
                return
            fingerprint = fingerprint.strip()
            tab = find_challenge(tab_id)
            if tab is None:
                with STATE_LOCK:
                    for candidate in STATE["tabs"]:
                        if candidate.id == tab_id or str(candidate.id) == str(tab_id):
                            tab = candidate
                            break
            if tab is None:
                self.send_json({"success": False,
                                "error": "That connection is no longer waiting"},
                               status=404)
                return
            # Restart the core with the key pinned, so the decision is
            # enforced by the client rather than by the interface.
            expected_role = getattr(tab, "hostkey_role", "destination")
            if (body.get("role", "destination") != expected_role or
                    fingerprint != tab.observed_hostkey):
                self.send_json({"success": False, "error": "The host-key challenge has changed."}, status=409)
                return
            field = "tunnel_hostkey" if expected_role == "tunnel" else "hostkey"
            tab.session[field] = fingerprint
            if body.get("remember"):
                name = body.get("name") or tab.name or ""
                if isinstance(name, str) and name.strip():
                    name = name.strip()
                    ok_save, message = save_confirmed_hostkey(tab, field, fingerprint, name)
                    add_log("Stored the pinned host key in '%s'" % name
                            if ok_save else message, "success" if ok_save else "error")
            tab.terminate()
            ok, error = tab.connect()
            if not ok:
                add_log("Still cannot connect: %s" % error, "error")
                self.send_json({"success": False, "error": error,
                                "challenge": tab.hostkey_challenge()},
                               status=400)
                return
            with STATE_LOCK:
                STATE["challenges"].pop(tab.id, None)
                if tab not in STATE["tabs"]:
                    STATE["tabs"].append(tab)
                STATE["active_tab"] = tab.id
            add_log("Connected to %s (host key pinned)" % tab.name, "success")
            self.send_json({"success": True, "tab": tab.describe()})
            return

        if path == "/api/tabs/close":
            tab_id = body.get("tab")
            # A connection that is waiting for a host-key decision lives in
            # 'challenges', not in the tab list. The id arrives from JSON as
            # a number or a string, and a lookup that missed on the type
            # left the parked core process running with no way to reach it.
            pending = pop_challenge(tab_id)
            if pending is not None:
                pending.terminate()
            close_tab_terminals(tab_id)
            with STATE_LOCK:
                for index, tab in enumerate(STATE["tabs"]):
                    if tab.id == tab_id or str(tab.id) == str(tab_id):
                        STATE["tabs"].pop(index)
                        tab.terminate()
                        if STATE["active_tab"] == tab.id:
                            STATE["active_tab"] = STATE["tabs"][0].id if STATE["tabs"] else None
                        break
            add_log("Closed session tab %s" % tab_id, "info")
            self.send_json({"success": True})
            return

        if path == "/api/tabs/select":
            tab_id = body.get("tab")
            tab = get_tab(tab_id)
            if tab is not None:
                with STATE_LOCK:
                    STATE["active_tab"] = tab.id
                self.send_json({"success": True, "tab": tab.describe()})
            else:
                self.send_json({"success": False, "error": "No such tab"}, status=400)
            return

        if path == "/api/tabs/reconnect":
            tab = get_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "No such tab"}, status=400)
                return
            ok, error = tab.connect()
            self.send_json({"success": ok, "tab": tab.describe(),
                            "error": error if not ok else ""},
                           status=200 if ok else 400)
            return

        if path == "/api/session/terminal":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            try:
                terminal_id = start_terminal(tab)
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)}, status=400)
                return
            except OSError as exc:
                self.send_json({"success": False,
                                "error": "Cannot start the terminal: %s" % exc},
                               status=500)
                return
            add_log("Terminal opened on %s" % session_url(tab.session), "success")
            self.send_json({"success": True, "terminal": terminal_id})
            return

        if path == "/api/terminal/input":
            term = get_terminal(body.get("terminal"))
            if term is None:
                self.send_json({"success": False,
                                "error": "No such terminal."}, status=400)
                return
            encoded = body.get("data") or ""
            if not isinstance(encoded, str):
                self.send_json({"success": False,
                                "error": "Terminal input was not base64."},
                               status=400)
                return
            try:
                data = base64.b64decode(encoded, validate=True)
            except (ValueError, base64.binascii.Error):
                self.send_json({"success": False,
                                "error": "Terminal input was not base64."},
                               status=400)
                return
            try:
                cols = int(body.get("cols") or 0)
                rows = int(body.get("rows") or 0)
            except (TypeError, ValueError):
                self.send_json({"success": False,
                                "error": "Terminal size must be numbers."},
                               status=400)
                return
            if cols and rows:
                term.resize(cols, rows)
            try:
                term.write(data)
            except OSError:
                pass
            self.send_json({"success": True, "alive": term.alive})
            return

        if path == "/api/terminal/close":
            close_terminal(body.get("terminal"))
            self.send_json({"success": True})
            return

        if path == "/api/sessions/save":
            raw_name = body.get("name") or ""
            if not isinstance(raw_name, str):
                self.send_json({"success": False,
                                "error": "The session name must be text."},
                               status=400)
                return
            name = raw_name.strip()
            session = body.get("session")
            if session is None:
                session = {}
            if not isinstance(session, dict):
                self.send_json({"success": False,
                                "error": "The session must be a JSON object."},
                               status=400)
                return
            validation_error = validate_session_data(session)
            if validation_error:
                self.send_json({"success": False, "error": validation_error},
                               status=400)
                return
            if not name:
                self.send_json({"success": False, "error": "A session name is required"},
                               status=400)
                return
            if session_is_local(session):
                ok, message = save_local_stored_session(name, session)
            else:
                ok, message = save_stored_session(
                    name, session or new_session(),
                    pin_hostkey=bool(body.get("pin_hostkey")))
            if ok:
                self.send_json({"success": True, "sessions": read_stored_sessions()})
            else:
                self.send_json({"success": False, "error": message}, status=400)
            return

        if path == "/api/sessions/delete":
            name = (body.get("name") or "").strip()
            is_folder = bool(body.get("folder"))
            if not name:
                self.send_json({"success": False, "error": "A session name is required"},
                               status=400)
                return
            rm_cmd = ("rmsession -folder %s" if is_folder else "rmsession %s") % quote_remote(name)
            code, stdout, stderr = run_linscp(rm_cmd)
            if code == 0:
                add_log("Removed session %s'%s'" % ("folder " if is_folder else "", name), "success")
                self.send_json({"success": True, "sessions": read_stored_sessions()})
            else:
                message = stderr.strip() or stdout.strip() or "Cannot remove the session"
                self.send_json({"success": False, "error": message}, status=400)
            return

        if path == "/api/workspaces/save":
            try:
                saved = save_workspace(body.get("name") or "",
                                       overwrite=bool(body.get("overwrite")))
            except WorkspaceExists as exc:
                self.send_json({"success": False, "error": str(exc),
                                "exists": True}, status=409)
                return
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json({"success": True, "workspace": saved})
            return

        if path == "/api/workspaces/open":
            try:
                result = restore_workspace(body.get("name") or "")
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json(dict(result, success=True))
            return

        if path == "/api/workspaces/delete":
            try:
                delete_workspace(body.get("name") or "")
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json({"success": True})
            return

        if path == "/api/bookmarks/save":
            try:
                result = add_bookmark(body.get("side") or "",
                                      body.get("name") or "",
                                      body.get("path") or "")
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json({"success": True, "bookmark": result,
                            "file": bookmark_store_path()})
            return

        if path == "/api/bookmarks/delete":
            try:
                result = delete_bookmark(body.get("side") or "",
                                         body.get("name") or "")
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json({"success": True, "bookmark": result,
                            "file": bookmark_store_path()})
            return

        if path == "/api/sessions/import":
            try:
                names = body.get("names")
                result = import_sessions(body.get("source") or "",
                                         body.get("path") or "",
                                         names,
                                         bool(body.get("overwrite")))
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json(result)
            return

        if path == "/api/preferences":
            action = str(body.get("action") or "save")
            if action == "reset":
                values = dict(PREFERENCE_DEFAULTS)
            elif action == "save":
                supplied = body.get("preferences")
                if not isinstance(supplied, dict):
                    self.send_json({"success": False,
                                    "error": "The preferences must be a JSON "
                                             "object."}, status=400)
                    return
                # A save is a whole document: every key the dialog shows is
                # written, so leaving one out cannot silently reset it.
                values = dict(PREFERENCE_DEFAULTS)
                values.update(supplied)
            else:
                self.send_json({"success": False,
                                "error": "The preference action is not known."},
                               status=400)
                return
            try:
                stored = write_preferences(values)
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json({"success": True, "preferences": stored,
                            "file": preferences_path()})
            return

        if path == "/api/cleanup":
            if body.get("confirm") is not True:
                self.send_json({"success": False,
                                "error": "Removing stored data has to be "
                                         "confirmed."}, status=400)
                return
            try:
                results = cleanup_data(body.get("ids"))
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            remaining = cleanup_locations()
            self.send_json({"success": True, "removed": results,
                            "locations": remaining,
                            "any": any(item["exists"] for item in remaining)})
            return

        if path == "/api/remote/rights":
            tab = require_tab(body.get("tab"))
            names = body.get("names")
            if names is None and body.get("name"):
                names = [body["name"]]
            try:
                results = set_rights(tab, names or [], str(body.get("mode") or ""),
                                     bool(body.get("recursive")))
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            failures = [item for item in results if not item["success"]]
            add_log("Changed the permissions of %d entr%s." %
                    (len(results) - len(failures),
                     "y" if len(results) - len(failures) == 1 else "ies"),
                    "success" if not failures else "error")
            self.send_json({"success": not failures, "results": results,
                            "changed": len(results) - len(failures),
                            "error": failures[0]["error"] if failures else ""})
            return

        if path == "/api/remote/transfer":
            tab = require_tab(body.get("tab"))
            names = body.get("names")
            if names is None and body.get("name"):
                names = [body["name"]]
            try:
                tasks = queue_remote_transfer(
                    tab, names or [], str(body.get("target") or ""),
                    str(body.get("directory") or ""),
                    str(body.get("filemask") or ""),
                    priority=bool(body.get("priority")))
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json({"success": True,
                            "tasks": [task.as_dict() for task in tasks]})
            return

        if path == "/api/local/mkdir":
            tab = get_tab(body.get("tab"))
            base = tab.local_dir if tab else default_local_dir()
            target, contain_error = contained_local_path(base, body.get("name") or "")
            if contain_error:
                self.send_json({"success": False, "error": contain_error}, status=400)
                return
            try:
                os.makedirs(target, exist_ok=True)
                add_log("Created local directory: %s" % target, "success")
                self.send_json({"success": True})
            except Exception as exc:
                self.send_json({"success": False, "error": str(exc)}, status=400)
            return

        if path == "/api/local/delete":
            tab = get_tab(body.get("tab"))
            base = tab.local_dir if tab else default_local_dir()
            names = body.get("names") or ([body["name"]] if body.get("name") else [])
            errors = []
            for name in names:
                target, contain_error = contained_local_path(base, name)
                if contain_error:
                    errors.append("%s: %s" % (name, contain_error))
                    continue
                try:
                    if os.path.isdir(target) and not os.path.islink(target):
                        shutil.rmtree(target)
                    else:
                        os.remove(target)
                    add_log("Deleted local item: %s" % name, "success")
                except Exception as exc:
                    errors.append("%s: %s" % (name, exc))
            if errors:
                self.send_json({"success": False, "error": "; ".join(errors)}, status=400)
            else:
                self.send_json({"success": True})
            return

        if path == "/api/local/rename":
            tab = get_tab(body.get("tab"))
            base = tab.local_dir if tab else default_local_dir()
            old, new = body.get("old_name"), body.get("new_name")
            if not old or not new:
                self.send_json({"success": False, "error": "Both names are required"},
                               status=400)
                return
            source, contain_error = contained_local_path(base, old)
            if not contain_error:
                _, contain_error = contained_local_path(base, new)
            if contain_error:
                self.send_json({"success": False, "error": contain_error}, status=400)
                return
            try:
                os.rename(source, os.path.join(base, new))
                add_log("Renamed %s to %s" % (old, new), "success")
                self.send_json({"success": True})
            except Exception as exc:
                self.send_json({"success": False, "error": str(exc)}, status=400)
            return

        if path == "/api/local/chmod":
            tab = get_tab(body.get("tab"))
            base = tab.local_dir if tab else default_local_dir()
            name = body.get("name") or ""
            mode_text = str(body.get("permissions") or "")
            mode_error = check_permission_mode(mode_text)
            if not name or mode_error:
                self.send_json({"success": False,
                                "error": mode_error or "Select an item first."},
                               status=400)
                return
            target, contain_error = contained_local_path(base, name)
            if contain_error:
                self.send_json({"success": False, "error": contain_error}, status=400)
                return
            try:
                apply_local_mode(target, mode_text)
                add_log("Changed local permissions: %s" % name, "success")
                self.send_json({"success": True})
            except OSError as exc:
                self.send_json({"success": False, "error": str(exc)}, status=400)
            return

        if path == "/api/local/save":
            tab = get_tab(body.get("tab"))
            local_path = body.get("path") or ""
            if not local_path:
                self.send_json({"success": False, "error": "No file given"}, status=400)
                return
            local_path, path_error = resolve_local_file(tab, local_path)
            if path_error:
                self.send_json({"success": False, "error": path_error}, status=400)
                return
            ok, message, info = write_local_text(
                local_path, body.get("content"), body.get("base_mtime_ns"))
            if ok:
                add_log("Saved local file: %s" % local_path, "success")
                self.send_json({"success": True, "info": info})
            else:
                self.send_json({"success": False, "error": message}, status=400)
            return

        if path == "/api/remote/mkdir":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            name = body.get("name") or ""
            name_error = check_remote_entry_name(name)
            if name_error:
                self.send_json({"success": False, "error": name_error}, status=400)
                return
            if getattr(tab, "is_local", False):
                target, contain_error = contained_local_path(tab.remote_dir, name)
                if contain_error:
                    self.send_json({"success": False, "error": contain_error},
                                   status=400)
                    return
                try:
                    os.makedirs(target, exist_ok=True)
                    add_log("Created local directory: %s" % target, "success")
                    self.send_json({"success": True})
                except OSError as exc:
                    self.send_json({"success": False, "error": str(exc)},
                                   status=400)
                return
            code, lines = tab.run_many(["cd " + quote_remote(tab.remote_dir),
                                        "mkdir " + quote_remote(name)])
            if code == 0:
                add_log("Created remote directory: %s" % name, "success")
                self.send_json({"success": True})
            else:
                self.send_json({"success": False,
                                "error": "\n".join(lines) or "mkdir failed"}, status=400)
            return

        if path == "/api/remote/delete":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            names = body.get("names") or []
            errors, deleted = [], []
            for item in names:
                name = item if isinstance(item, str) else item.get("name")
                name_error = check_remote_entry_name(name or "")
                if name_error:
                    errors.append(name_error)
                    continue
                is_dir = item.get("is_dir", False) if isinstance(item, dict) else False
                if getattr(tab, "is_local", False):
                    target, contain_error = contained_local_path(tab.remote_dir,
                                                                 name or "")
                    if contain_error:
                        errors.append("%s: %s" % (name, contain_error))
                        continue
                    try:
                        if os.path.isdir(target) and not os.path.islink(target):
                            shutil.rmtree(target)
                        else:
                            os.remove(target)
                        deleted.append(name)
                        add_log("Deleted local item: %s" % name, "success")
                    except OSError as exc:
                        errors.append("%s: %s" % (name, exc))
                    continue
                code, lines = tab.run_many([
                    "cd " + quote_remote(tab.remote_dir),
                    ("rmdir" if is_dir else "rm") + " " + quote_remote(name or "")])
                if code == 0:
                    deleted.append(name)
                else:
                    errors.append("\n".join(lines))
            if errors:
                self.send_json({"success": False, "error": "; ".join(errors)}, status=400)
            else:
                add_log("Deleted remote item(s): %s" % ", ".join(deleted), "success")
                self.send_json({"success": True})
            return

        if path == "/api/remote/rename":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            old_name = body.get("old_name") or ""
            new_name = body.get("new_name") or ""
            name_error = (check_remote_entry_name(old_name) or
                          check_remote_entry_name(new_name))
            if name_error:
                self.send_json({"success": False, "error": name_error}, status=400)
                return
            if getattr(tab, "is_local", False):
                source, contain_error = contained_local_path(tab.remote_dir,
                                                             old_name)
                if not contain_error:
                    target, contain_error = contained_local_path(tab.remote_dir,
                                                                 new_name)
                if contain_error:
                    self.send_json({"success": False, "error": contain_error},
                                   status=400)
                    return
                try:
                    os.rename(source, target)
                    add_log("Renamed %s to %s" % (old_name, new_name), "success")
                    self.send_json({"success": True})
                except OSError as exc:
                    self.send_json({"success": False, "error": str(exc)},
                                   status=400)
                return
            code, lines = tab.run_many([
                "cd " + quote_remote(tab.remote_dir),
                "mv " + quote_remote(old_name) + " " + quote_remote(new_name)])
            if code == 0:
                add_log("Renamed %s to %s" % (old_name, new_name), "success")
                self.send_json({"success": True})
            else:
                self.send_json({"success": False,
                                "error": "\n".join(lines) or "Rename failed"}, status=400)
            return

        if path == "/api/remote/chmod":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            name = body.get("name") or ""
            name_error = check_remote_entry_name(name)
            if name_error:
                self.send_json({"success": False, "error": name_error}, status=400)
                return
            mode_text = str(body.get("permissions") or "644")
            if getattr(tab, "is_local", False):
                target, contain_error = contained_local_path(tab.remote_dir, name)
                if contain_error:
                    self.send_json({"success": False, "error": contain_error},
                                   status=400)
                    return
                mode_error = check_permission_mode(mode_text)
                if mode_error:
                    self.send_json({"success": False, "error": mode_error},
                                   status=400)
                    return
                try:
                    apply_local_mode(target, mode_text)
                    add_log("Changed local permissions: %s" % name, "success")
                    self.send_json({"success": True})
                except OSError as exc:
                    self.send_json({"success": False, "error": str(exc)},
                                   status=400)
                return
            try:
                commands = build_chmod_command(tab.remote_dir, mode_text, name)
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)}, status=400)
                return
            code, lines = tab.run_many(commands)
            if code == 0:
                add_log("Changed remote permissions: %s" % body.get("name"), "success")
                self.send_json({"success": True})
            else:
                self.send_json({"success": False,
                                "error": "\n".join(lines) or "chmod failed"}, status=400)
            return

        if path == "/api/remote/search":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            pattern = body.get("pattern") or "*"
            start = body.get("path") or tab.remote_dir
            try:
                limit = max(1, min(1000, int(body.get("limit") or 500)))
            except (TypeError, ValueError):
                self.send_json({"success": False, "error": "The result limit must be a number."}, status=400)
                return
            case_sensitive = body.get("case_sensitive") is True
            search_contents = body.get("search_contents") is True
            content_query = body.get("content_query") or ""
            if search_contents and not isinstance(content_query, str):
                self.send_json({"success": False, "error": "The text query must be a string."}, status=400)
                return
            if search_contents and not content_query:
                self.send_json({"success": False, "error": "Enter text to search for."}, status=400)
                return
            if search_contents and len(content_query) > 1024:
                self.send_json({"success": False, "error": "The text query is too long (maximum 1024 characters)."}, status=400)
                return
            stats = {"scanned": 0, "skipped": 0, "bytes_scanned": 0,
                     "truncated": False}
            try:
                if getattr(tab, "is_local", False):
                    matches = local_search(
                        start, pattern, limit, case_sensitive,
                        content_query=content_query if search_contents else None,
                        stats=stats)
                else:
                    matches = remote_search(tab, start, pattern, limit,
                        case_sensitive,
                        content_query=content_query if search_contents else None,
                        stats=stats)
            except Exception as exc:
                self.send_json({"success": False, "error": str(exc)}, status=400)
                return
            self.send_json({"success": True, "matches": matches,
                "truncated": stats["truncated"], "scanned": stats["scanned"],
                "skipped": stats["skipped"],
                "bytes_scanned": stats["bytes_scanned"]})
            return

        if path == "/api/remote/save":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            remote_path = body.get("path") or ""
            content = body.get("content")
            if not remote_path or content is None:
                self.send_json({"success": False, "error": "A path and content are required"},
                               status=400)
                return
            if getattr(tab, "is_local", False):
                local_path, path_error = resolve_local_pane_file(
                    tab, remote_path, "remote")
                if path_error:
                    self.send_json({"success": False, "error": path_error},
                                   status=400)
                    return
                ok, message, info = write_local_text(
                    local_path, content, body.get("base_mtime_ns") or
                    body.get("base_mtime"))
                if ok:
                    add_log("Saved local file: %s" % local_path, "success")
                    self.send_json({"success": True, "info": info})
                else:
                    self.send_json({"success": False, "error": message},
                                   status=400)
                return
            ok, error = upload_remote_text(tab, remote_path, content,
                                           body.get("base_mtime"))
            if ok:
                self.send_json({"success": True,
                                "info": remote_stat(tab, remote_path) or {}})
            else:
                self.send_json({"success": False, "error": error}, status=400)
            return

        if path == "/api/transfer/download":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            names = body.get("names") or []
            if getattr(tab, "is_local", False):
                try:
                    queue_local_transfers(
                        tab, "download", names,
                        body.get("overwrite") or "ask",
                        priority=bool(body.get("priority")))
                except LocalTransferConflict as exc:
                    self.send_json({"success": False, "error": str(exc),
                                    "conflicts": exc.conflicts}, status=409)
                    return
                except ValueError as exc:
                    self.send_json({"success": False, "error": str(exc)},
                                   status=400)
                    return
                self.send_json({"success": True})
                return
            local_dir = body.get("local_dir") or tab.local_dir
            local_dir, jail_error = confined_local_path(local_dir)
            if jail_error:
                self.send_json({"success": False, "error": jail_error},
                               status=403)
                return
            try:
                switches = transfer_switches(
                    body, protocol=tab.session.get("protocol"))
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            priority = bool(body.get("priority"))
            for name in names:
                name_error = check_remote_entry_name(name or "")
                if name_error:
                    self.send_json({"success": False, "error": name_error}, status=400)
                    return
                remote_path = posixpath.join(tab.remote_dir, name)
                local_target = os.path.join(local_dir, name)
                command = "lcd %s ; cd %s ; get %s %s" % (
                    quote_local(local_dir), quote_remote(tab.remote_dir),
                    switches, quote_remote(name))
                task = TASKS.submit("Download", command, tab.session, remote_path,
                                    local_target, tab.id, progress_path=local_target,
                                    priority=priority)
                try:
                    task.bytes_total = remote_size(tab, remote_path) or 0
                except Exception:
                    task.bytes_total = 0
            self.send_json({"success": True})
            return

        if path == "/api/transfer/upload":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            names = body.get("names") or []
            if getattr(tab, "is_local", False):
                try:
                    queue_local_transfers(
                        tab, "upload", names,
                        body.get("overwrite") or "ask",
                        priority=bool(body.get("priority")))
                except LocalTransferConflict as exc:
                    self.send_json({"success": False, "error": str(exc),
                                    "conflicts": exc.conflicts}, status=409)
                    return
                except ValueError as exc:
                    self.send_json({"success": False, "error": str(exc)},
                                   status=400)
                    return
                self.send_json({"success": True})
                return
            remote_dir = body.get("remote_dir") or tab.remote_dir
            try:
                switches = transfer_switches(
                    body, protocol=tab.session.get("protocol"))
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            priority = bool(body.get("priority"))
            for name in names:
                # A local upload name must also be a single entry: the
                # panel shows one directory, '../../etc/passwd' is not in it.
                local_target, contain_error = contained_local_path(
                    tab.local_dir, name)
                if contain_error:
                    self.send_json({"success": False, "error": contain_error}, status=400)
                    return
                remote_target = posixpath.join(remote_dir, name)
                command = "lcd %s ; cd %s ; put %s %s" % (
                    quote_local(tab.local_dir), quote_remote(remote_dir),
                    switches, quote_local(name))
                task = TASKS.submit("Upload", command, tab.session, local_target,
                                    remote_target, tab.id,
                                    progress_remote=(tab.id, remote_target),
                                    priority=priority)
                try:
                    task.bytes_total = os.path.getsize(local_target)
                except OSError:
                    task.bytes_total = 0
            self.send_json({"success": True})
            return

        if path == "/api/shell/consume":
            tab = require_tab(body.get("tab"))
            if tab is None or getattr(tab, "is_local", False):
                self.send_json(
                    {"success": False,
                     "error": "Files from a file manager can only be sent "
                              "to a session tab."},
                    status=400)
                return
            try:
                result = consume_shell_upload(body.get("id"), tab)
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            result["success"] = True
            self.send_json(result)
            return

        if path == "/api/shell/dismiss":
            try:
                dismiss_shell_upload(body.get("id"))
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            self.send_json({"success": True})
            return

        if path == "/api/transfer/move":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            direction = body.get("direction")
            if direction not in ("upload", "download"):
                self.send_json({"success": False,
                                "error": "Move direction must be upload or download."}, status=400)
                return
            names = body.get("names") or []
            if not isinstance(names, list) or not names:
                self.send_json({"success": False, "error": "Select one or more files to move."},
                               status=400)
                return
            if getattr(tab, "is_local", False):
                try:
                    queue_local_transfers(
                        tab, direction, names,
                        body.get("overwrite") or "ask", move=True,
                        priority=bool(body.get("priority")))
                except LocalTransferConflict as exc:
                    self.send_json({"success": False, "error": str(exc),
                                    "conflicts": exc.conflicts}, status=409)
                    return
                except ValueError as exc:
                    self.send_json({"success": False, "error": str(exc)},
                                   status=400)
                    return
                self.send_json({"success": True})
                return
            local_dir, jail_error = confined_local_path(
                body.get("local_dir") or tab.local_dir)
            if jail_error:
                self.send_json({"success": False, "error": jail_error},
                               status=403)
                return
            local_dir = os.path.abspath(local_dir)
            remote_dir = body.get("remote_dir") or tab.remote_dir
            if not os.path.isdir(local_dir):
                self.send_json({"success": False, "error": "The local directory no longer exists."},
                               status=400)
                return
            records = []
            for name in names:
                if not isinstance(name, str) or not name or name in (".", "..") or \
                        "/" in name:
                    self.send_json({"success": False,
                                    "error": "A move can only select file names from the current panel."},
                                   status=400)
                    return
                if direction == "upload":
                    source_path = os.path.abspath(os.path.join(local_dir, name))
                    try:
                        if os.path.commonpath([local_dir, source_path]) != local_dir or \
                                os.path.islink(source_path) or not os.path.isfile(source_path):
                            raise ValueError("Cross-panel move supports regular files only.")
                        source_info = os.stat(source_path)
                    except (OSError, ValueError) as exc:
                        self.send_json({"success": False, "error": str(exc)}, status=400)
                        return
                    records.append({"name": name, "source": source_path,
                                    "source_info": source_info,
                                    "destination": posixpath.join(remote_dir, name)})
                else:
                    remote_path = posixpath.join(remote_dir, name)
                    source_info = remote_stat(tab, remote_path)
                    if source_info is None:
                        self.send_json({"success": False,
                                        "error": "Cannot read remote source: %s" % name},
                                       status=400)
                        return
                    if source_info.get("is_dir"):
                        self.send_json({"success": False,
                                        "error": "Cross-panel move supports files only; copy folders instead."},
                                       status=400)
                        return
                    records.append({"name": name, "source": remote_path,
                                    "source_info": source_info,
                                    "destination": os.path.join(local_dir, name)})

            try:
                switches = transfer_switches({
                    "resume": body.get("resume", True),
                    "recursive": False,
                    "preserve_time": body.get("preserve_time", True),
                }, protocol=tab.session.get("protocol"))
            except ValueError as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            for record in records:
                name = record["name"]
                if direction == "upload":
                    source_info = record["source_info"]
                    command = "lcd %s ; cd %s ; put %s %s" % (
                        quote_local(local_dir), quote_remote(remote_dir),
                        switches, quote_remote(name))
                    task = TASKS.submit(
                        "Move to remote", command, tab.session, record["source"],
                        record["destination"], tab.id,
                        progress_remote=(tab.id, record["destination"]),
                        move_source={"side": "local", "path": record["source"],
                                     "size": source_info.st_size,
                                     "mtime_ns": getattr(source_info, "st_mtime_ns",
                                                          int(source_info.st_mtime * 1000000000))})
                    task.bytes_total = source_info.st_size
                else:
                    source_info = record["source_info"]
                    command = "lcd %s ; cd %s ; get %s %s" % (
                        quote_local(local_dir), quote_remote(remote_dir),
                        switches, quote_remote(name))
                    task = TASKS.submit(
                        "Move to local", command, tab.session, record["source"],
                        record["destination"], tab.id,
                        progress_path=record["destination"],
                        move_source={"side": "remote", "path": record["source"],
                                     "size": source_info.get("size", 0),
                                     "mtime": source_info.get("mtime", 0)})
                    task.bytes_total = source_info.get("size", 0)
            self.send_json({"success": True})
            return

        if path == "/api/sync/preview":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            local_dir, jail_error = confined_local_path(
                body.get("local_dir") or tab.local_dir)
            if jail_error:
                self.send_json({"success": False, "error": jail_error},
                               status=403)
                return
            command = build_sync_command(
                body.get("mode") or "local",
                local_dir,
                body.get("remote_dir") or tab.remote_dir,
                delete=bool(body.get("delete")),
                criteria=body.get("criteria") or "time",
                filemask=body.get("filemask") or "",
                recursive=body.get("recursive", True),
                preview=True,
                conflict=body.get("conflict") or "skip")
            code, stdout, stderr = run_linscp(
                "open %s ; %s" % (
                    quote_remote(session_url(tab.session, tab.remote_dir)), command),
                tab.session)
            if code != 0:
                self.send_json({"success": False,
                                "error": stderr.strip() or stdout.strip() or
                                "Cannot read the synchronization plan"}, status=400)
                return
            plan = parse_sync_preview(stdout.splitlines())
            plan["command"] = command
            add_log("Synchronization preview: %s item(s)" % len(plan["items"]), "info")
            self.send_json({"success": True, "plan": plan})
            return

        if path == "/api/sync/run":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            local_dir = body.get("local_dir") or tab.local_dir
            local_dir, jail_error = confined_local_path(local_dir)
            if jail_error:
                self.send_json({"success": False, "error": jail_error},
                               status=403)
                return
            remote_dir = body.get("remote_dir") or tab.remote_dir
            command = build_sync_command(
                body.get("mode") or "local", local_dir, remote_dir,
                delete=bool(body.get("delete")),
                criteria=body.get("criteria") or "time",
                filemask=body.get("filemask") or "",
                recursive=body.get("recursive", True),
                conflict=body.get("conflict") or "skip")
            task = TASKS.submit("Synchronize (%s)" % (body.get("mode") or "local"),
                                command, tab.session, local_dir, remote_dir, tab.id)
            self.send_json({"success": True, "task_id": task.id})
            return

        if path == "/api/queue/priority":
            ok = TASKS.prioritize(body.get("task_id"),
                                  body.get("position") or "top")
            self.send_json({"success": ok})
            return

        if path == "/api/queue/cancel":
            ok = TASKS.cancel(body.get("task_id"))
            self.send_json({"success": ok})
            return

        if path == "/api/queue/retry":
            ok = TASKS.retry(body.get("task_id"))
            self.send_json({"success": ok})
            return

        if path == "/api/queue/pause":
            TASKS.pause()
            self.send_json({"success": True})
            return

        if path == "/api/queue/resume":
            TASKS.resume()
            self.send_json({"success": True})
            return

        if path == "/api/queue/clear":
            TASKS.clear_finished()
            self.send_json({"success": True})
            return

        # --- Operations the console client has and the panel did not -----
        #
        # Each of these takes single names from the panel and validates them
        # here, so the operand that reaches the session is one the client
        # would accept and nothing else. Running them through the free-text
        # console endpoint instead would put the quoting back on the page.
        if path == "/api/remote/properties":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"},
                               status=400)
                return
            # One name keeps the single-entry answer the dialog used
            # before; a list answers with one row per entry, so several
            # selected files can be shown together and their shared facts
            # compared instead of opening them one at a time.
            names = body.get("names")
            if names is None:
                names = [body.get("name")] if body.get("name") else []
            try:
                rows = remote_properties(tab, names)
            except (ValueError, OSError) as exc:
                self.send_json({"success": False, "error": str(exc)},
                               status=400)
                return
            answer = {"success": True, "properties": rows,
                      "name": rows[0]["name"] if rows else ""}
            if len(rows) == 1:
                answer["attributes"] = rows[0]
            self.send_json(answer)
            return

        if path == "/api/remote/link":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            target, error = single_remote_name(tab, body.get("target"))
            if not error:
                name, error = single_remote_name(tab, body.get("name"))
            if error:
                self.send_json({"success": False, "error": error}, status=400)
                return
            if getattr(tab, "is_local", False):
                link_name = body.get("name") or ""
                target_text = body.get("target") or ""
                link_path, contain_error = contained_local_path(tab.remote_dir,
                                                                link_name)
                if contain_error:
                    self.send_json({"success": False, "error": contain_error},
                                   status=400)
                    return
                if not isinstance(target_text, str) or not target_text or \
                        any(ord(char) < 32 or ord(char) == 127 for char in target_text):
                    self.send_json({"success": False,
                                    "error": "A link target is required."},
                                   status=400)
                    return
                try:
                    os.symlink(target_text, link_path)
                    add_log("Created local link '%s' -> '%s'" %
                            (link_name, target_text), "success")
                    self.send_json({"success": True})
                except OSError as exc:
                    self.send_json({"success": False, "error": str(exc)},
                                   status=400)
                return
            code, lines = tab.run_many([
                "cd " + quote_remote(tab.remote_dir),
                "ln %s %s" % (quote_remote(target), quote_remote(name))])
            if code == 0:
                add_log("Created remote link '%s' -> '%s'" % (name, target), "success")
                self.send_json({"success": True})
            else:
                self.send_json({"success": False,
                                "error": "\n".join(lines) or "Cannot create the link."},
                               status=400)
            return

        if path == "/api/remote/copy":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            source, error = single_remote_name(tab, body.get("source"))
            if not error:
                destination, error = single_remote_name(tab, body.get("destination"))
            if error:
                self.send_json({"success": False, "error": error}, status=400)
                return
            if getattr(tab, "is_local", False):
                source_name = body.get("source") or ""
                destination_name = body.get("destination") or ""
                source_path, contain_error = contained_local_path(
                    tab.remote_dir, source_name)
                if not contain_error:
                    destination_path, contain_error = contained_local_path(
                        tab.remote_dir, destination_name)
                if contain_error:
                    self.send_json({"success": False, "error": contain_error},
                                   status=400)
                    return
                try:
                    copy_local_entry(source_path, destination_path,
                                     "overwrite", root=tab.remote_dir)
                    add_log("Copied local '%s' to '%s'" %
                            (source_name, destination_name), "success")
                    self.send_json({"success": True})
                except (OSError, ValueError) as exc:
                    self.send_json({"success": False, "error": str(exc)},
                                   status=400)
                return
            code, lines = tab.run_many([
                "cd " + quote_remote(tab.remote_dir),
                "cp %s %s" % (quote_remote(source), quote_remote(destination))])
            if code == 0:
                add_log("Copied remote '%s' to '%s'" % (source, destination), "success")
                self.send_json({"success": True})
            else:
                self.send_json({"success": False,
                                "error": "\n".join(lines) or "Cannot copy."},
                               status=400)
            return

        if path == "/api/remote/checksum":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            algorithm = str(body.get("algorithm") or "sha256").strip().lower()
            if algorithm not in CHECKSUM_ALGORITHMS:
                self.send_json({"success": False,
                                "error": "The algorithm must be one of: %s." %
                                         ", ".join(sorted(CHECKSUM_ALGORITHMS))},
                               status=400)
                return
            names = body.get("names")
            if not isinstance(names, list) or not names:
                self.send_json({"success": False,
                                "error": "Select one or more files."}, status=400)
                return
            if len(names) > 200:
                self.send_json({"success": False,
                                "error": "Too many files selected (maximum 200)."},
                               status=400)
                return
            if getattr(tab, "is_local", False):
                results = []
                for name in names:
                    operand, operand_error = single_remote_name(tab, name)
                    if operand_error:
                        results.append({"name": str(name), "error": operand_error})
                        continue
                    target, contain_error = contained_local_path(
                        tab.remote_dir, name)
                    if contain_error:
                        results.append({"name": operand, "error": contain_error})
                        continue
                    try:
                        results.append({"name": operand,
                                        "checksum": local_checksum(target, algorithm)})
                    except (OSError, ValueError) as exc:
                        results.append({"name": operand, "error": str(exc)})
                self.send_json({"success": True, "algorithm": algorithm,
                                "results": results})
                return
            results = []
            for name in names:
                operand, operand_error = single_remote_name(tab, name)
                if operand_error:
                    results.append({"name": str(name), "error": operand_error})
                    continue
                code, lines = tab.run("checksum %s %s" % (
                    algorithm, quote_remote(operand)))
                if code == 0:
                    results.append({"name": operand,
                                    "checksum": "\n".join(lines).strip()})
                else:
                    results.append({"name": operand,
                                    "error": "\n".join(lines).strip() or
                                             "Cannot read the checksum."})
            self.send_json({"success": True, "algorithm": algorithm,
                            "results": results})
            return

        if path == "/api/session/copyid":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            keyfile = str(body.get("keyfile") or "").strip()
            command = "copyid"
            if keyfile:
                # The key file is a local path, and it is this user's own:
                # it is quoted, not validated against the panel directory.
                command += " " + quote_local(keyfile)
            code, lines, errors = tab.run_many_capture([command])
            text = "\n".join(lines + errors).strip()
            if code == 0:
                add_log("Uploaded the public key to the server", "success")
                self.send_json({"success": True, "output": text})
            else:
                self.send_json({"success": False,
                                "error": text or "Cannot upload the public key."},
                               status=400)
            return

        if path == "/api/transfer/keepuptodate":
            tab = require_tab(body.get("tab"))
            if tab is None:
                self.send_json({"success": False, "error": "Not connected"}, status=400)
                return
            local_dir, jail_error = confined_local_path(
                body.get("local_dir") or tab.local_dir)
            if jail_error:
                self.send_json({"success": False, "error": jail_error},
                               status=403)
                return
            remote_dir = str(body.get("remote_dir") or tab.remote_dir)
            if not os.path.isdir(local_dir):
                self.send_json({"success": False,
                                "error": "The local directory no longer exists."},
                               status=400)
                return
            command = "keepuptodate"
            try:
                interval = int(body.get("interval") or 0)
            except (TypeError, ValueError):
                self.send_json({"success": False,
                                "error": "The interval must be a number of seconds."},
                               status=400)
                return
            if interval:
                if interval < 1 or interval > 86400:
                    self.send_json({"success": False,
                                    "error": "The interval must be between 1 and "
                                             "86400 seconds."}, status=400)
                    return
                command += " -interval=%d" % interval
            try:
                count = int(body.get("count") or 0)
            except (TypeError, ValueError):
                self.send_json({"success": False,
                                "error": "The number of passes must be a number."},
                               status=400)
                return
            if count:
                if count < 1 or count > 1000000:
                    self.send_json({"success": False,
                                    "error": "The number of passes must be between "
                                             "1 and 1000000."}, status=400)
                    return
                command += " -count=%d" % count
            mask = str(body.get("filemask") or "").strip()
            if mask:
                command += " -filemask=" + quote_remote(mask)
            command += " " + quote_local(local_dir) + " " + quote_remote(remote_dir)
            task = TASKS.submit("Keep up to date", command, tab.session,
                                local_dir, remote_dir, tab.id)
            add_log("Queued a watch of %s against %s" % (local_dir, remote_dir), "info")
            self.send_json({"success": True, "task_id": task.id,
                            "command": command})
            return

        if path == "/api/command/exec":
            cmd_text = body.get("command", "")
            if not isinstance(cmd_text, str):
                self.send_json({"success": False,
                                "error": "The command must be text."}, status=400)
                return
            if not cmd_text:
                self.send_json({"success": False, "error": "Empty command"}, status=400)
                return
            tab = get_tab(body.get("tab"))
            if tab is not None and tab.connected:
                # Run it in the live session: 'cd' and 'lcd' then stick.
                # Split at semicolons only outside quoted operands, just as
                # the console command parser does.
                code, lines, errors = tab.run_many_capture(
                    split_linscp_commands(cmd_text))
                if code == 0:
                    code, pwd = tab.run("pwd")
                    for line in pwd:
                        if line.startswith("/"):
                            tab.remote_dir = line.strip()
                            break
                self.send_json({"success": code == 0, "exit_code": code,
                                "stdout": "\n".join(lines),
                                "stderr": "\n".join(errors)})
                return
            if ACCOUNTS_FILE:
                self.send_json({"success": False,
                                "error": "A connected tab of this login is "
                                         "required to run a command."},
                               status=403)
                return
            code, stdout, stderr = run_linscp(cmd_text)
            self.send_json({"success": code == 0, "exit_code": code,
                            "stdout": stdout, "stderr": stderr})
            return

        # --- Custom commands (Explorer-style) ---
        if path == "/api/custom-commands":
            # do_POST has already read the body: every route below it shares
            # the one parse. Reading it a second time here asked the socket
            # for Content-Length more bytes that had been consumed, so the
            # handler blocked until the client gave up and the whole feature
            # answered nothing at all.
            action = body.get("action", "list")
            cmds = _read_custom_commands()
            if action == "list":
                self.send_json({"success": True, "commands": cmds})
            elif action == "save":
                template = normalize_custom_command(body)
                if not template:
                    self.send_json({"success": False,
                                    "error": "A name and a one-line command "
                                             "are required."}, status=400)
                    return
                cmds = [c for c in cmds if c.get("name") != template["name"]]
                cmds.append(template)
                try:
                    _write_custom_commands(cmds)
                except OSError as exc:
                    self.send_json({"success": False,
                                    "error": "Cannot save the commands: %s" % exc},
                                   status=500)
                    return
                add_log("Saved custom command '%s'" % template["name"], "success")
                self.send_json({"success": True, "commands": cmds})
            elif action == "delete":
                name = str(body.get("name") or "").strip()
                remaining = [c for c in cmds if c.get("name") != name]
                if len(remaining) == len(cmds):
                    self.send_json({"success": False,
                                    "error": "There is no command '%s'." % name},
                                   status=404)
                    return
                try:
                    _write_custom_commands(remaining)
                except OSError as exc:
                    self.send_json({"success": False,
                                    "error": "Cannot save the commands: %s" % exc},
                                   status=500)
                    return
                add_log("Removed custom command '%s'" % name, "info")
                self.send_json({"success": True, "commands": remaining})
            elif action == "run":
                name = str(body.get("name") or "").strip()
                filenames = body.get("filenames")
                template = next((c for c in cmds if c.get("name") == name), None)
                if not template:
                    self.send_json({"success": False,
                                    "error": "Unknown command '%s'." % name},
                                   status=404)
                    return
                if not isinstance(filenames, list) or not filenames:
                    self.send_json({"success": False,
                                    "error": "Select one or more files to run "
                                             "it on."}, status=400)
                    return
                if len(filenames) > 500:
                    self.send_json({"success": False,
                                    "error": "Too many files selected "
                                             "(maximum 500)."}, status=400)
                    return
                # A command template runs in the session the panel belongs
                # to, which is the connection the user is looking at. The
                # earlier version opened a fresh process against the default
                # site, so a template ran somewhere other than where the
                # selection was.
                tab = require_tab(body.get("tab"))
                results, run_error = execute_custom_command(
                    template, filenames, tab)
                if run_error:
                    self.send_json({"success": False, "error": run_error},
                                   status=400)
                    return
                self.send_json({"success": True, "results": results,
                                "scope": template.get("scope", "remote")})
            else:
                self.send_json({"success": False,
                                "error": "Unknown action '%s'." % action},
                               status=400)
            return

        self.send_json({"error": "Not Found"}, status=404)


# ---------------------------------------------------------------------------
# Custom commands (persisted command templates for Explorer-style UI)
# ---------------------------------------------------------------------------

def _config_root():
    """The configuration directory this run keeps its own files in.

    Every other file the client writes lives under it, found the same way;
    the custom commands used to look at a differently named variable and
    fall back to ~/.config, so a run started with its own LINSCP_CONFIG_DIR
    still shared them with the user's real configuration - and a test that
    pointed the variable at a temporary directory wrote to the home one.
    With accounts enabled this is the login's private directory, not the
    process-wide one.
    """
    ws = _current_workspace()
    if ws.get("config_dir"):
        os.makedirs(ws["config_dir"], mode=0o700, exist_ok=True)
        return ws["config_dir"]
    return _default_config_root()


def _custom_commands_path():
    return os.path.join(_config_root(), "custom-commands.json")


def _default_custom_commands():
    """The templates the client ships with, until the user saves their own.

    A first run with an empty list gives a dialog that says nothing can be
    run and no way to see what a command template looks like. The shipped
    set is the one in source/gui/explorer-commands.json, next to this
    module or under the installed share directory.
    """
    for candidate in (os.path.join(BASE_DIR, "explorer-commands.json"),
                      os.path.join(WEB_DIR, "..", "explorer-commands.json"),
                      "/usr/share/linscp/gui/explorer-commands.json"):
        try:
            with open(candidate, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            continue
        return [normalize_custom_command(item) for item in data
                if normalize_custom_command(item)]
    return []


def normalize_custom_command(item):
    """One command template in the shape the API and the dialog use.

    Returns None for an entry that is not a usable template, so a file
    edited by hand or written by an older version cannot put a half-read
    command in front of the run button.
    """
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()
    command = str(item.get("command") or "").strip()
    if not name or not command:
        return None
    if len(name) > 128 or len(command) > 1024:
        return None
    # A template is one command line: the core reads one line at a time in
    # server mode, so a stored newline would be a second command nobody
    # asked for.
    if any(ord(char) < 32 or ord(char) == 127 for char in name + command):
        return None
    scope = str(item.get("scope") or "remote").strip().lower()
    if scope not in ("remote", "local"):
        scope = "remote"
    return {"name": name, "command": command, "scope": scope}


def _read_custom_commands():
    path = _custom_commands_path()
    if not os.path.isfile(path):
        return _default_custom_commands()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (ValueError, OSError):
        return _default_custom_commands()
    if not isinstance(data, list):
        return _default_custom_commands()
    commands = [normalize_custom_command(item) for item in data]
    return [item for item in commands if item]


def _write_custom_commands(commands):
    path = _custom_commands_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    # Commands run against the user's own sessions and file system, so the
    # file that stores them is not for anybody else to read or rewrite.
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as f:
        json.dump(commands, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def build_custom_command(template, filename):
    """Substitute {file} in a template for one selected name.

    Returns (command, error). The name is quoted the way the LinSCP command
    splitter reads quotes, not the way a shell would: single quotes are an
    ordinary character to it, so a name with a space arrived as two
    arguments and the command ran against the wrong file. A name is never
    handed to a shell here at all.
    """
    if not isinstance(filename, str) or not filename:
        return None, "A command needs a selected file name."
    if "/" in filename or "\\" in filename or filename in (".", ".."):
        return None, "\"%s\" is not a single file name." % filename
    if any(ord(char) < 32 or ord(char) == 127 for char in filename):
        return None, "A file name must not contain a control character."
    quoted = (quote_remote if template.get("scope") != "local" else quote_local)(
        filename)
    if "{file}" not in template["command"]:
        return template["command"], ""
    return template["command"].replace("{file}", quoted), ""


def execute_custom_command(template, filenames, tab):
    """Run one template against every selected name.

    Returns (results, error). A remote template runs in the session the
    panel belongs to - the connection the user is looking at - while a
    local one runs in a short-lived core process; neither ever reaches
    a shell, and a name that is not one entry of the panel fails its
    own result without stopping the files behind it.
    """
    local = template.get("scope") == "local"
    if not local and tab is None:
        return [], ("Not connected. A remote command needs an open "
                    "session.")
    name = template.get("name", "")
    results = []
    for filename in filenames:
        command, error = build_custom_command(template, filename)
        if error:
            results.append({"file": filename, "success": False,
                            "error": error})
            continue
        add_log("Custom command '%s': %s" % (name, command), "cmd")
        try:
            if local:
                code, stdout, stderr = run_linscp(
                    command, tab.session if tab else None)
            else:
                code, lines, errors = tab.run_many_capture(
                    ["cd " + quote_remote(tab.remote_dir), command])
                stdout, stderr = "\n".join(lines), "\n".join(errors)
        except ValueError as exc:
            results.append({"file": filename, "success": False,
                            "error": str(exc)})
            continue
        results.append({"file": filename, "success": code == 0,
                        "exit_code": code,
                        "stdout": stdout, "stderr": stderr})
    return results, ""


# ---------------------------------------------------------------------------
# Helpers used by the endpoints
# ---------------------------------------------------------------------------

TRANSFER_MODES = ("binary", "ascii", "automatic")


def transfer_switches(body, protocol=None):
    """The get/put switches a transfer dialog asked for.

    Every value is checked against what the console client accepts before
    it reaches a command line: a mode, a mask or a limit that was passed
    through unquoted would have been the start of a new command rather
    than an argument.
    """
    is_scp = str(protocol or "").strip().lower() == "scp"
    switches = []
    if body.get("resume", True) and not is_scp:
        switches.append("-resume")
    if body.get("recursive", True):
        switches.append("-r")
    if body.get("newer_only"):
        switches.append("-neweronly")
    if body.get("preserve_time", True):
        switches.append("-preservetime")
    else:
        switches.append("-nopreservetime")
    if body.get("delete_source"):
        switches.append("-delete")
    mode = str(body.get("transfer") or "").strip().lower()
    if mode and mode != "automatic_default":
        if mode not in TRANSFER_MODES:
            raise ValueError("The transfer mode must be binary, ascii or "
                             "automatic.")
        switches.append("-transfer=" + mode)
    mask = body.get("filemask")
    if mask:
        if not isinstance(mask, str):
            raise ValueError("A file mask must be text.")
        switches.append("-filemask=" + quote_remote(mask.strip()))
    speed = body.get("speed")
    if speed not in (None, "", 0, "0"):
        try:
            value = int(speed)
        except (TypeError, ValueError):
            raise ValueError("The speed limit must be a number of KiB/s.")
        if value < 1 or value > 100000000:
            raise ValueError("The speed limit must be between 1 and "
                             "100000000 KiB/s.")
        switches.append("-speed=%d" % value)
    if body.get("append"):
        switches.append("-append")
    if body.get("no_permissions"):
        switches.append("-nopermissions")
    resume_support = body.get("resumesupport")
    if resume_support not in (None, ""):
        text = str(resume_support).strip().lower()
        if text in ("on", "off"):
            switches.append("-resumesupport=" + text)
        else:
            # The client's -resumesupport= takes a number of KiB, the same
            # unit its manual page, its help and the field the transfer
            # dialog shows all state; a byte count sent here would have
            # been read 1024 times too large.
            try:
                threshold = int(text)
            except ValueError:
                raise ValueError("Resume support must be on, off or a number "
                                 "of KiB.")
            if threshold < 0:
                raise ValueError("Resume support must be on, off or a number "
                                 "of KiB.")
            switches.append("-resumesupport=%d" % threshold)
    return " ".join(part for part in switches if part)


def remote_stat(tab, remote_path, timeout=30):
    """Parse the 'attr' output of the core into a dictionary.

    'attr' is the key/value breakdown of a remote file's attributes; the
    upstream-shaped 'stat' prints a single listing line instead.
    """
    code, lines = tab.run("attr " + quote_remote(remote_path), timeout=timeout)
    if code != 0:
        return None
    info = {"path": remote_path, "size": 0, "mtime": 0, "is_dir": False,
            "permissions": "", "raw": "\n".join(lines)}
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("SizeBytes:"):
            info["size"] = int(stripped.split(":", 1)[1].strip() or 0)
        elif stripped.startswith("ModifiedEpoch:"):
            info["mtime"] = int(stripped.split(":", 1)[1].strip() or 0)
        elif stripped.startswith("Permissions:"):
            info["permissions"] = stripped.split(":", 1)[1].strip()
            info["is_dir"] = info["permissions"].startswith("d")
        elif stripped.startswith("Size:"):
            digits = "".join(ch for ch in stripped.split(":", 1)[1] if ch.isdigit())
            if digits and not info["size"]:
                info["size"] = int(digits)
    return info


def remote_size(tab, remote_path):
    info = remote_stat(tab, remote_path)
    return info["size"] if info else 0


MAX_CONTENT_SEARCH_FILE_BYTES = 8 * 1024 * 1024
MAX_CONTENT_SEARCH_TOTAL_BYTES = 64 * 1024 * 1024
MAX_CONTENT_SEARCH_FILES = 200
MAX_CONTENT_SEARCH_CANDIDATES = 1000
MAX_REMOTE_SEARCH_DEPTH = 12


def _content_match_in_remote_file(tab, remote_path, query, case_sensitive):
    """Download and scan one bounded UTF-8 text file, returning its first hit."""
    directory = tempfile.mkdtemp(prefix="linscp-search-")
    local_path = os.path.join(directory, "content")
    try:
        command = "get -transfer=binary %s %s" % (
            quote_remote(remote_path), quote_remote(local_path))
        code, lines, errors = tab.run_capture(command, timeout=180)
        if code != 0:
            return None, 0, "download"
        actual_size = os.path.getsize(local_path)
        if actual_size > MAX_CONTENT_SEARCH_FILE_BYTES:
            return None, actual_size, "too-large"
        with open(local_path, "rb") as handle:
            data = handle.read(MAX_CONTENT_SEARCH_FILE_BYTES + 1)
        if len(data) > MAX_CONTENT_SEARCH_FILE_BYTES:
            return None, len(data), "too-large"
        if b"\0" in data:
            return None, len(data), "binary"
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return None, len(data), "encoding"
        wanted = query if case_sensitive else query.casefold()
        for line_number, line in enumerate(text.splitlines(), 1):
            candidate = line if case_sensitive else line.casefold()
            position = candidate.find(wanted)
            if position < 0:
                continue
            snippet = " ".join(line.split())
            if len(snippet) > 240:
                folded = snippet if case_sensitive else snippet.casefold()
                position = max(0, folded.find(wanted))
                left = max(0, min(position - 80, len(snippet) - 234))
                right = left + 234
                snippet = ("..." if left else "") + snippet[left:right] + \
                    ("..." if right < len(snippet) else "")
            snippet = "".join(ch if ch >= " " or ch == "\t" else " "
                               for ch in snippet)
            return {"line": line_number, "snippet": snippet}, len(data), ""
        return None, len(data), ""
    except (OSError, IOError, subprocess.SubprocessError):
        return None, 0, "download"
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def remote_search(tab, start, pattern, limit=500, case_sensitive=False,
                  depth=0, matches=None, content_query=None, stats=None,
                  _budget=None):
    """Search names or bounded UTF-8 file contents throughout a remote tree.

    Content mode treats ``pattern`` as a filename mask, scans at most 200
    files/64 MiB (8 MiB per file), and reports files it could not inspect.
    """
    if matches is None:
        matches = []
    if stats is None:
        stats = {"scanned": 0, "skipped": 0, "bytes_scanned": 0,
                 "truncated": False}
    if _budget is None:
        _budget = {"candidates": 0}
    if depth > MAX_REMOTE_SEARCH_DEPTH:
        stats["truncated"] = True
        return matches
    if len(matches) >= limit:
        stats["truncated"] = True
        return matches
    code, lines = tab.run_many(["cd " + quote_remote(start), "ls -la"], timeout=30)
    if code != 0:
        return matches
    entries = parse_ls_output(lines)
    needle = pattern if case_sensitive else pattern.casefold()
    for entry in entries:
        name = entry["name"] if case_sensitive else entry["name"].casefold()
        if content_query is None:
            if fnmatch(name, needle):
                matches.append({
                    "path": posixpath.join(start, entry["name"]),
                    "name": entry["name"],
                    "is_dir": entry["is_dir"],
                    "size": entry.get("size", 0),
                    "date": entry.get("date", ""),
                    "permissions": entry.get("permissions", ""),
                })
                if len(matches) >= limit:
                    stats["truncated"] = True
                    return matches
            continue

        # In content mode the mask filters candidate file names; directories
        # are traversed below, but are not themselves content results.
        if entry["is_dir"] or not fnmatch(name, needle):
            continue
        if _budget["candidates"] >= MAX_CONTENT_SEARCH_CANDIDATES:
            stats["truncated"] = True
            return matches
        _budget["candidates"] += 1
        remote_path = posixpath.join(start, entry["name"])
        info = remote_stat(tab, remote_path, timeout=30)
        if info is None or info.get("is_dir"):
            stats["skipped"] += 1
            continue
        size = int(info.get("size") or 0)
        if size <= 0:
            continue
        if size > MAX_CONTENT_SEARCH_FILE_BYTES:
            stats["skipped"] += 1
            continue
        if stats["scanned"] >= MAX_CONTENT_SEARCH_FILES or \
                stats["bytes_scanned"] + size > MAX_CONTENT_SEARCH_TOTAL_BYTES:
            stats["truncated"] = True
            return matches
        stats["scanned"] += 1
        hit, actual_size, reason = _content_match_in_remote_file(
            tab, remote_path, content_query, case_sensitive)
        if reason:
            stats["skipped"] += 1
            if reason != "download":
                # The actual transfer size may differ from the stat result;
                # account it so a lying listing cannot bypass the budget.
                if actual_size <= MAX_CONTENT_SEARCH_TOTAL_BYTES:
                    stats["bytes_scanned"] += actual_size
            continue
        stats["bytes_scanned"] += actual_size
        if hit is not None:
            matches.append({
                "path": remote_path,
                "name": entry["name"],
                "is_dir": False,
                "size": actual_size,
                "date": entry.get("date", ""),
                "permissions": entry.get("permissions", ""),
                "line": hit["line"],
                "snippet": hit["snippet"],
            })
            if len(matches) >= limit:
                stats["truncated"] = True
                return matches

    for entry in entries:
        if entry["is_dir"]:
            remote_search(tab, posixpath.join(start, entry["name"]), pattern,
                          limit, case_sensitive, depth + 1, matches,
                          content_query, stats, _budget)
            if len(matches) >= limit or stats["truncated"]:
                break
    return matches


def edit_temp_root():
    root = os.path.join(_config_root(), "edit-tmp")
    os.makedirs(root, mode=0o700, exist_ok=True)
    if not os.path.islink(root):
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass
    return root


def temp_path_for(remote_path):
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in remote_path)
    fd, path = tempfile.mkstemp(prefix="edit-", suffix="-" + safe[-48:],
                                dir=edit_temp_root())
    os.close(fd)
    return path


MAX_GUI_EDIT_BYTES = 8 * 1024 * 1024


def resolve_local_pane_file(tab, path, side="local"):
    """Resolve an edit path beneath one of a tab's local pane directories.

    A local-to-local tab has two local roots and the right-hand one is not
    the remote panel, so the containment check has to use the directory of
    the pane the request names rather than always tab.local_dir.
    """
    if side == "remote" and tab is not None and getattr(tab, "is_local", False):
        base = tab.remote_dir or tab.other_local_dir
    else:
        base = tab.local_dir if tab else os.path.expanduser("~")
    candidate = path if os.path.isabs(path) else os.path.join(base, path)
    candidate = os.path.abspath(candidate)
    real_base = os.path.realpath(base)
    real_target = os.path.realpath(candidate)
    try:
        if os.path.commonpath([real_base, real_target]) != real_base:
            return "", "The file is outside the current local panel directory."
    except ValueError:
        return "", "The file is outside the current local panel directory."
    confined, jail_error = confined_local_path(candidate)
    if jail_error:
        return "", jail_error
    return confined, ""


def resolve_local_file(tab, path):
    """Resolve a local edit path beneath the active local panel directory."""
    return resolve_local_pane_file(tab, path, "local")


def read_local_text(local_path, max_size=MAX_GUI_EDIT_BYTES):
    """Read a bounded UTF-8 local file for the Commander viewer/editor."""
    try:
        before = os.stat(local_path)
        if not os.path.isfile(local_path):
            return None, {}, "That is not a regular file."
        if before.st_size > max_size:
            return None, {}, "The file is %d bytes, too large for the editor (limit %d)." % (
                before.st_size, max_size)
        with open(local_path, "rb") as handle:
            data = handle.read(max_size + 1)
        current = os.stat(local_path)
    except OSError as exc:
        return None, {}, str(exc)
    before_ns = getattr(before, "st_mtime_ns", int(before.st_mtime * 1000000000))
    current_ns = getattr(current, "st_mtime_ns", int(current.st_mtime * 1000000000))
    if current_ns != before_ns:
        return None, {}, "The file changed while it was being read; try again."
    if len(data) > max_size:
        return None, {}, "The file is too large for the editor (limit %d bytes)." % max_size
    if b"\0" in data:
        return None, {}, "The file is binary; the editor can only view text files."
    info = {"size": len(data), "mtime": current.st_mtime, "mtime_ns": current_ns}
    return data.decode("utf-8", "replace"), info, ""


def write_local_text(local_path, content, base_mtime_ns,
                     max_size=MAX_GUI_EDIT_BYTES):
    """Atomically save a local text edit only if the original is unchanged."""
    if not isinstance(content, str):
        return False, "The file content must be text.", {}
    data = content.encode("utf-8")
    if len(data) > max_size:
        return False, "The edited file is too large (limit %d bytes)." % max_size, {}
    if not base_mtime_ns:
        return False, "The original file timestamp is missing; reload before saving.", {}
    if os.path.islink(local_path):
        return False, "Editing a symbolic link is not supported; open its target instead.", {}
    try:
        current = os.stat(local_path)
        if not os.path.isfile(local_path):
            return False, "That is not a regular file.", {}
        expected = int(base_mtime_ns)
        current_ns = getattr(current, "st_mtime_ns", int(current.st_mtime * 1000000000))
        if current_ns != expected:
            return False, "The file changed while it was open; reload it before saving.", {}
        mode = stat.S_IMODE(current.st_mode)
        fd, temporary = tempfile.mkstemp(prefix=".linscp-edit-",
                                          dir=os.path.dirname(os.path.abspath(local_path)))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            latest = os.stat(local_path)
            latest_ns = getattr(latest, "st_mtime_ns", int(latest.st_mtime * 1000000000))
            if latest_ns != expected:
                return False, "The file changed while it was open; reload it before saving.", {}
            os.replace(temporary, local_path)
            saved = os.stat(local_path)
        finally:
            try:
                if os.path.exists(temporary):
                    os.remove(temporary)
            except OSError:
                pass
    except (OSError, ValueError) as exc:
        return False, str(exc), {}
    info = {"size": len(data), "mtime": saved.st_mtime,
            "mtime_ns": getattr(saved, "st_mtime_ns", int(saved.st_mtime * 1000000000))}
    return True, "", info


def download_remote_text(tab, remote_path, max_size=8 * 1024 * 1024):
    """Download a remote file for the editor. Returns (content, info, error)."""
    stat_info = remote_stat(tab, remote_path)
    if stat_info is None:
        return None, {}, "Cannot read the file."
    if stat_info["is_dir"]:
        return None, {}, "That is a directory, not a file."
    size = stat_info["size"]
    if size and size > max_size:
        return None, {}, "The file is %d bytes, too large for the editor (limit %d)." % (
            size, max_size)
    local = temp_path_for(remote_path)
    try:
        code, lines = tab.run("get -transfer=binary -preservetime %s %s" % (
            quote_remote(remote_path), quote_local(local)), timeout=300)
        if code != 0:
            return None, {}, "\n".join(lines) or "Cannot download the file."
        try:
            with open(local, "rb") as handle:
                data = handle.read(max_size + 1)
            local_mtime = int(os.path.getmtime(local))
        except OSError as exc:
            return None, {}, str(exc)
        if len(data) > max_size:
            return None, {}, "The file is too large for the editor (limit %d)." % max_size
        if b"\0" in data:
            return None, {}, "The file is binary; the editor can only edit text files."
        info = {"size": len(data),
                "mtime": int(stat_info.get("mtime") or local_mtime),
                "path": remote_path}
        try:
            return data.decode("utf-8"), info, ""
        except UnicodeDecodeError:
            return data.decode("utf-8", "replace"), info, ""
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass


def upload_remote_text(tab, remote_path, content, base_mtime=None):
    """Upload edited content, refusing to clobber a file changed since it
    was opened."""
    if base_mtime:
        info = remote_stat(tab, remote_path)
        if info is not None:
            current = info["mtime"]
            if current and int(base_mtime) and current != int(base_mtime):
                return False, ("The file changed on the server while it was open "
                               "(reload it before saving, or save it under a new name).")
    local = temp_path_for(remote_path)
    try:
        try:
            with open(local, "wb") as handle:
                handle.write(content.encode("utf-8"))
        except OSError as exc:
            return False, str(exc)
        code, lines = tab.run("put -transfer=binary %s %s" % (
            quote_local(local), quote_remote(remote_path)), timeout=300)
        if code != 0:
            return False, "\n".join(lines) or "Cannot upload the file."
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass
    add_log("Saved %s" % remote_path, "success")
    return True, ""


def main():
    global PORT, HOST, API_TOKEN, REQUIRE_TOKEN, ALLOWED_HOSTS, ALLOW_ANY_HOST
    global ACCOUNTS_FILE, ALLOWED_ORIGINS
    port = PORT
    host = HOST
    fixed_token = None
    startup_url = None
    print_token = False
    open_browser = False
    shell_files = None
    argv = sys.argv[1:]
    if "--shell-upload" in argv:
        # Everything after the flag is the file manager's selection -
        # file names are data here, never options of our own.
        cut = argv.index("--shell-upload")
        shell_files = argv[cut + 1:]
        argv = argv[:cut]
    for arg in argv:
        if (startup_url is None and arg.lower().startswith(
                ("sftp://", "ftp://", "ftps://", "ftpes://"))):
            startup_url = arg
            continue
        if arg.startswith("--port="):
            port_text = arg.split("=", 1)[1].strip()
            try:
                port = int(port_text)
            except ValueError:
                print("Invalid port '%s': expected a number from 0 through 65535."
                      % port_text, file=sys.stderr)
                return 2
            if not 0 <= port <= 65535:
                print("Invalid port %d: must be between 0 and 65535." % port,
                      file=sys.stderr)
                return 2
        elif arg.startswith("--host="):
            host = arg.split("=", 1)[1]
            # Listening on an address the Host check refuses is a server
            # that cannot answer its own address: add the bind address to
            # the allowed set so a request for it is not rejected before
            # --allow-any-host is needed. 0.0.0.0 and :: are wildcard
            # binds, not Host header values, and are skipped: a request
            # addressed to the wildcard is always an attempt to talk to
            # something other than this loopback service.
            host_lc = host.strip().lower()
            if host_lc and host_lc not in ("0.0.0.0", "::", "::0"):
                ALLOWED_HOSTS.add(host_lc)
        elif arg.startswith("--token="):
            fixed_token = arg.split("=", 1)[1].strip()
        elif arg == "--no-auth":
            REQUIRE_TOKEN = False
        elif arg.startswith("--allow-host="):
            value = arg.split("=", 1)[1].strip().lower()
            if value:
                ALLOWED_HOSTS.add(value)
        elif arg == "--allow-any-host":
            ALLOW_ANY_HOST = True
        elif arg.startswith("--allow-origin="):
            value = arg.split("=", 1)[1].strip().rstrip("/")
            if value:
                ALLOWED_ORIGINS.add(value)
        elif arg.startswith("--accounts-file="):
            ACCOUNTS_FILE = arg.split("=", 1)[1].strip()
        elif arg in ("--install-shell-integration",
                     "--uninstall-shell-integration"):
            action = (install_shell_integration
                      if arg == "--install-shell-integration"
                      else uninstall_shell_integration)
            try:
                results = action()
            except (OSError, ValueError) as exc:
                print("Cannot change the file-manager integration: %s"
                      % exc, file=sys.stderr)
                return 1
            for manager, path, outcome in results:
                print("%s: %s (%s)" % (manager, path, outcome))
            return 0
        elif arg == "--print-token":
            print_token = True
        elif arg == "--open-browser":
            open_browser = True
        elif arg == "--add-account":
            # Interactive: create a user account and exit.
            if not ACCOUNTS_FILE:
                print("--add-account needs --accounts-file=FILE to say which "
                      "file to add it to.", file=sys.stderr)
                return 2
            user = input("Username: ").strip()
            if not user:
                print("A user name is required.", file=sys.stderr)
                return 2
            pw = getpass.getpass("Password: ")
            again = getpass.getpass("Password again: ")
            if pw != again:
                print("The two passwords do not match.", file=sys.stderr)
                return 2
            if not pw:
                print("An empty password is not accepted.", file=sys.stderr)
                return 2
            home = input("Home directory (optional, blank for none): ").strip()
            try:
                _write_account(user, pw, home)
            except OSError as exc:
                print("Cannot write %s: %s" % (ACCOUNTS_FILE, exc),
                      file=sys.stderr)
                return 1
            print("Account '%s' created in %s." % (user, ACCOUNTS_FILE))
            return 0
        elif arg in ("-h", "--help"):
            print(__doc__)
            print("Options:")
            print("  --port=PORT            listen on PORT (default %d)" % PORT)
            print("  --host=ADDRESS         bind to ADDRESS (default %s," % HOST)
            print("                         i.e. this machine only)")
            print("  --token=TOKEN          use TOKEN instead of a generated one")
            print("  --no-auth              accept API calls without a token")
            print("  --allow-host=NAME      also answer requests addressed to NAME")
            print("  --allow-any-host       answer requests for any host name")
            print("  --allow-origin=URL     let the browser origin URL read responses")
            print("                         (default: none; the client is same-origin)")
            print("  --accounts-file=FILE   enable multi-user accounts (PBKDF2)")
            print("  --add-account          create a user account interactively")
            print("  --install-shell-integration")
            print("                         add an 'Upload with LinSCP'")
            print("                         action to this user's Dolphin (KDE),")
            print("                         Files (GNOME) and Nemo (Cinnamon),")
            print("                         per-user, in the XDG data directory")
            print("  --uninstall-shell-integration")
            print("                         remove those actions again")
            print("  --shell-upload FILES...  what the actions above run:")
            print("                         hold the selected files for the GUI")
            print("                         to offer as uploads (never sends by")
            print("                         itself)")
            print("  --print-token          write the token to the terminal")
            print("  --open-browser         ask the desktop to open the page")
            print("                         in a browser (through xdg-open, so")
            print("                         it works on Wayland as on X11)")
            return 0
    if shell_files is not None:
        if not shell_files:
            print("--shell-upload was given no files.", file=sys.stderr)
            return 2
        try:
            _manifest_id, recorded = record_shell_upload(shell_files)
        except ValueError as exc:
            print("Cannot accept those files: %s" % exc, file=sys.stderr)
            return 2
        print("%d file(s) from the file manager held for LinSCP; the GUI "
              "will offer to upload them." % len(recorded))
        # Started from a context menu there is no terminal to read;
        # opening the page is the whole point of the invocation.
        open_browser = True
    startup_session = None
    if startup_url:
        try:
            startup_session = parse_desktop_site_url(startup_url)
        except ValueError as exc:
            print("Cannot open desktop site URL: %s" % exc, file=sys.stderr)
            return 2
    API_TOKEN = fixed_token or secrets.token_hex(32)

    if ACCOUNTS_FILE and not os.path.isfile(ACCOUNTS_FILE):
        # Silently continuing here would start a server that refuses every
        # request with 'Login required' and can never be signed into,
        # because the file the accounts would be read from does not exist.
        print("Cannot find the accounts file '%s'." % ACCOUNTS_FILE,
              file=sys.stderr)
        print("Create an account first: %s --accounts-file=%s --add-account"
              % (os.path.basename(sys.argv[0]), ACCOUNTS_FILE), file=sys.stderr)
        return 2

    server_address = (host, port)
    try:
        httpd = ThreadingHTTPServer(server_address, LinScpGuiHandler)
    except OSError as exc:
        print("Cannot listen on %s:%d: %s" % (host, port, exc), file=sys.stderr)
        if shell_files:
            print("A GUI appears to be running already; the files from "
                  "the file manager are waiting in it (or for the next "
                  "start).", file=sys.stderr)
        return 1
    # '--port=0' asks the kernel for a free port, so the number to tell the
    # user is the one that was bound, not the one that was asked for.
    # Printing the request left the address of a run nobody could reach.
    bound_port = httpd.server_address[1]
    if startup_session is not None:
        open_desktop_site(startup_session)
    print("LinSCP Commander GUI running at http://localhost:%d/" % bound_port)
    print("Serving web client from: %s" % WEB_DIR)
    print("LinSCP core binary: %s" % LINSCP_BIN)
    print("Stored sessions: %s" % session_store_path())
    if REQUIRE_TOKEN:
        print("API calls need this run's token (X-LSCP-Token header); the")
        print("page served below carries it, and --print-token shows it.")
        if print_token:
            print("Token: %s" % API_TOKEN)
    else:
        print("Warning: the API is open to anything that can reach this port.")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("Warning: listening on %s, so every host that can reach this" % host)
        print("machine can reach this API: use --host=127.0.0.1 unless you")
        print("need a remote or proxied interface.")
    if ALLOW_ANY_HOST:
        print("Warning: the Host header is not checked (--allow-any-host).")
    else:
        print("Answering requests for: %s" % ", ".join(sorted(ALLOWED_HOSTS)))
    if open_browser:
        # Only after the port is bound: a launcher told about the address
        # before anything was listening opened an error page, which is the
        # one thing a user blames the client for.
        address = browser_url_for(host, bound_port)
        reason = open_in_browser(address)
        if reason:
            print("Not opening a browser: %s." % reason)
            print("Open %s in a browser of your own." % address)
    sys.stdout.flush()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping LinSCP GUI server...")
        TASKS.cancel_all()
        for tab in list(STATE["tabs"]):
            tab.terminate()
        httpd.server_close()


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main() or 0)
