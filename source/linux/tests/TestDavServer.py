"""A throwaway WebDAV endpoint for LiveDavTest.py.

TestSftpServer.py covers SFTP, TestS3Server.py covers signed HTTP;
WebDAV is a third dialect (PROPFIND, MKCOL, MOVE, Depth) and needs its
own server. This one is plain HTTP on 127.0.0.1 with HTTP Basic
authentication (testuser / testpass) so that the client's --anyauth
challenge round-trip is exercised, and it speaks only what a filesystem
client needs:

  PROPFIND Depth 0/1 with a 207 multi-status (resourcetype,
  getcontentlength, getlastmodified - the properties LinSCP's parser
  reads), MKCOL, GET/HEAD with ranges, PUT, DELETE (409 on a
  non-empty collection, the conflict rmdir depends on), MOVE, and COPY
  with absolute-URI Destination and Overwrite semantics.

Storage is in memory, one fresh process per test. The XML is written
by this file and parsed independently by the client; neither shares
code, so a parser bug has to survive meeting the other's output.

    LSCP_TEST_PORT=0 python3 TestDavServer.py
prints "READY <port>" once listening.
"""

import calendar
import datetime
import hashlib
import json
import os
import time
import re
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USER = "testuser"
PASSWORD = "testpass"
PROPFIND_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    '<d:multistatus xmlns:d="DAV:">\n'
    "%s"
    "</d:multistatus>\n"
)
XML_DECL = '<?xml version="1.0" encoding="utf-8"?>'


def http_date(epoch):
    moment = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return moment.strftime("%a, %d %b %Y %H:%M:%S GMT")


def xml_escape(value):
    return (value.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&apos;"))


class Store:
    """path -> dict(kind='dir'|'file', mtime=epoch, data=bytes).

    '/' is the root collection and always exists. Paths are
    normalized to a leading slash and no trailing slash (except root).
    """

    def __init__(self):
        self.items = {"/": {"kind": "dir", "mtime": _now()}}
        self.write_lock = threading.Lock()
        # Every write moves the entity tags, even a rewrite of the same
        # bytes within the same second: without this two successive PUTs
        # of identical content could share one tag, and a precondition
        # test could not tell whether the second write changed the
        # version. Real servers version on write, not on content alone.
        self.write_seq = 0
        self.copy_count = 0
        self.reject_next_copy = False
        self.drop_next_get = os.environ.get("LSCP_TEST_DROP_ONCE", "")
        # path -> token, and path -> {name: value} for the dead properties.
        # Both are what a LOCK/UNLOCK/PROPPATCH implementation has to keep,
        # and the If header is checked against the first of them.
        self.locks = {}
        self.properties = {}
        self.lock_count = 0
        # Every If header a request carried, in the order they arrived:
        # a precondition is only worth what the client actually sent, and
        # this is the only place a test can read that back.
        self.if_headers = []

    @staticmethod
    def normalize(path):
        # Callers pass decoded filesystem paths, not URLs. Decoding again
        # would turn a literal '%23' name into '#', while stripping '?' or
        # '#' here would lose legitimate file names altogether.
        if not path.startswith("/"):
            path = "/" + path
        while len(path) > 1 and path.endswith("/"):
            path = path[:-1]
        return path

    def parent_of(self, path):
        if path == "/":
            return None
        return path.rsplit("/", 1)[0] or "/"

    def get(self, path):
        return self.items.get(self.normalize(path))

    def add_dir(self, path):
        path = self.normalize(path)
        if path in self.items:
            return "exists"
        parent = self.parent_of(path)
        item = self.items.get(parent)
        if item is None or item["kind"] != "dir":
            return "no-parent"
        self.items[path] = {"kind": "dir", "mtime": _now()}
        return "created"

    def add_file(self, path, data):
        path = self.normalize(path)
        parent = self.parent_of(path)
        item = self.items.get(parent)
        if item is None or item["kind"] != "dir":
            return "no-parent"
        existed = path in self.items
        self.write_seq += 1
        self.items[path] = {"kind": "file", "mtime": _now(), "data": data,
                            "seq": self.write_seq}
        return "replaced" if existed else "created"

    def delete(self, path):
        path = self.normalize(path)
        item = self.items.get(path)
        if item is None:
            return "missing"
        if item["kind"] == "dir":
            prefix = path if path != "/" else "/"
            children = [p for p in self.items
                        if p != path and p.startswith(
                            prefix + "/" if prefix != "/" else "/")]
            if children:
                return "conflict"
            del self.items[path]
            return "deleted"
        del self.items[path]
        return "deleted"

    def etag_of(self, path):
        """The strong entity tag of a stored resource, or None if absent.

        Derived from what the resource is - its bytes, or for a collection
        the names it holds - and from when it last changed, so a write
        always moves it and a test can tell a stale tag from a current one.
        """
        entry = self.get(path)
        if entry is None:
            return None
        path = self.normalize(path)
        digest = hashlib.sha1()
        digest.update(entry["kind"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(entry["mtime"]).encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(entry.get("seq", 0)).encode("utf-8"))
        if entry["kind"] == "dir":
            digest.update("\0".join(sorted(self.children_of(path)))
                          .encode("utf-8"))
        else:
            digest.update(entry.get("data", b""))
        return '"%s"' % digest.hexdigest()

    def children_of(self, path):
        """Immediate members, sorted - '/' means top-level only."""
        path = self.normalize(path)
        out = []
        for p in sorted(self.items):
            if p == path:
                continue
            if path == "/":
                if p.count("/") == 1:
                    out.append(p)
            elif p.startswith(path + "/") and "/" not in p[len(path) + 1:]:
                out.append(p)
        return out

    def copy(self, src, dest, overwrite):
        src = self.normalize(src)
        dest = self.normalize(dest)
        if src not in self.items:
            return "missing-source"
        if dest == "/" or dest == src or dest.startswith(src + "/") or \
                src.startswith(dest + "/"):
            return "forbidden"
        parent = self.parent_of(dest)
        if parent not in self.items or self.items[parent]["kind"] != "dir":
            return "no-parent"
        replaced = dest in self.items
        if replaced and not overwrite:
            return "precondition"
        source = self.items[src]
        subtree = {p: value for p, value in self.items.items()
                   if p == src or p.startswith(src + "/")}
        if replaced:
            for path in list(self.items):
                if path == dest or path.startswith(dest + "/"):
                    del self.items[path]
        for path, value in subtree.items():
            target = dest + path[len(src):]
            self.items[target] = dict(value)
        self.copy_count += 1
        return "replaced" if replaced else "created"

    def move(self, src, dest, overwrite):
        src = self.normalize(src)
        dest = self.normalize(dest)
        if src not in self.items:
            return "missing-source"
        if dest == src:
            return "created"
        if dest == "/" or dest.startswith(src + "/"):
            return "forbidden"
        item = self.items[src]
        parent = self.parent_of(dest)
        if parent not in self.items or self.items[parent]["kind"] != "dir":
            return "no-parent"
        replaced = dest in self.items
        if replaced and not overwrite:
            return "precondition"
        # Move the subtree: every path under src/ follows src.
        subtree = {p: v for p, v in self.items.items()
                   if p == src or p.startswith(src + "/")}
        for p in sorted(subtree):
            target = dest + p[len(src):]
            self.items[target] = subtree[p]
            if p != src:
                del self.items[p]
        # The source's own key is gone too - the destination replaced it.
        # (dest cannot be inside src: that returned forbidden above.)
        del self.items[src]
        return "replaced" if replaced else "created"


    def lock(self, path, timeout, owner):
        """Takes an exclusive write lock; an existing one is a conflict.

        The token is a real opaque token in the server's spelling, so the
        client stores and sends back exactly what a compliant server
        hands out.
        """
        path = self.normalize(path)
        if path not in self.items:
            return "missing", None
        if path in self.locks:
            return "locked", None
        self.lock_count += 1
        token = "opaquelocktoken:%08x-0000-0000-0000-lscpdavlock" % self.lock_count
        self.locks[path] = {"token": token, "timeout": timeout, "owner": owner}
        return "created", token

    def unlock(self, path, token):
        path = self.normalize(path)
        entry = self.locks.get(path)
        if entry is None:
            return "missing"
        if entry["token"] != token:
            return "conflict"
        del self.locks[path]
        return "unlocked"

    def lock_owner(self, path):
        """The lock guarding a path: its own lock, or a parent's."""
        path = self.normalize(path)
        candidate = path
        while True:
            if candidate in self.locks:
                return self.locks[candidate]
            if candidate == "/":
                return None
            candidate = self.parent_of(candidate)

    def set_property(self, path, name, value):
        path = self.normalize(path)
        if path not in self.items:
            return "missing"
        self.properties.setdefault(path, {})[name] = value
        return "set"

    def get_properties(self, path):
        return self.properties.get(self.normalize(path), {})


def _etag_matches(left, right):
    """Whether two entity tags name the same version.

    A weak tag ('W/"..."') is a claim about equivalence rather than about
    bytes, and comparing one to a strong tag byte for byte would refuse a
    precondition the server meant to honour.
    """
    def strong(value):
        value = value.strip()
        if value.upper().startswith("W/"):
            value = value[2:].strip()
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        return value
    return strong(left) == strong(right)


def _now():
    return calendar.timegm(
        datetime.datetime.now(datetime.timezone.utc).timetuple())


class DavHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def authorized(self):
        header = self.headers.get("Authorization", "")
        if header == "Basic " + _basic_token(USER, PASSWORD):
            return True
        self.send_response(401)
        self.send_header("WWW-Authenticate",
                         'Basic realm="linscp-dav-test"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    # -- helpers -----------------------------------------------------------
    def send_body(self, status, body, content_type="text/plain", extra=()):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD" and body and status not in (204, 304):
            if self.command == "GET" and status == 200 and self.local_path() == SERVER_STORE.drop_next_get:
                SERVER_STORE.drop_next_get = ""
                self.wfile.write(body[:32768])
                self.wfile.flush()
                self.close_connection = True
                self.connection.shutdown(2)
                return
            delay = float(os.environ.get("LSCP_TEST_GET_DELAY", "0"))
            if self.command == "GET" and delay:
                for offset in range(0, len(body), 32768):
                    self.wfile.write(body[offset:offset + 32768])
                    self.wfile.flush()
                    time.sleep(delay)
            else:
                self.wfile.write(body)

    def send_error_text(self, status, text):
        self.send_body(status, text)

    def local_path(self):
        return urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)

    def if_tokens(self):
        """The state tokens of an 'If' header, from any of its lists.

        A state token is a Coded-URL, so it is the '<...>' of a condition;
        an entity tag is '["..."]' and is not one. Taking the whole list
        instead read a list that also carried a precondition as a token
        nobody holds, and the write it guarded was refused as locked.
        """
        header = self.headers.get("If", "")
        return [part.strip() for group in re.findall(r"\(([^)]*)\)", header)
                for part in re.findall(r"<([^>]*)>", group)]

    def precondition_lists(self):
        """The condition lists of an 'If' header.

        Each list is a conjunction and the lists are alternatives, as
        RFC 4918 10.4 reads them, so a request passes when one list holds
        in full. A condition is ('token'|'etag', value, negated).
        """
        header = self.headers.get("If", "")
        lists = []
        for group in re.findall(r"\(([^)]*)\)", header):
            conditions = []
            for match in re.finditer(r"(Not\s+)?(<([^>]*)>|\[([^\]]*)\])",
                                     group):
                negated = bool((match.group(1) or "").strip())
                if match.group(3) is not None:
                    conditions.append(("token", match.group(3).strip(),
                                       negated))
                else:
                    conditions.append(("etag",
                                       match.group(4).strip().strip('"'),
                                       negated))
            if conditions:
                lists.append(conditions)
        return lists

    def precondition_failed(self, path):
        """True when the 'If' header this request carries does not hold.

        A header with no list this server can read is refused rather than
        ignored: a write that went through because its guard could not be
        parsed is the failure a precondition exists to prevent.
        """
        if not self.headers.get("If", "").strip():
            return False
        lists = self.precondition_lists()
        if not lists:
            return True
        current = SERVER_STORE.etag_of(path)
        held = SERVER_STORE.lock_owner(path)
        for conditions in lists:
            holds_all = True
            for kind, value, negated in conditions:
                if kind == "token":
                    holds = held is not None and held["token"] == value
                elif value == "*":
                    # '*' stands for any entity tag: it holds whenever the
                    # resource is there, and negated it is the "only if
                    # absent" a client states with -nomatch=*.
                    holds = current is not None
                else:
                    holds = current is not None and _etag_matches(current,
                                                                  value)
                if negated:
                    holds = not holds
                if not holds:
                    holds_all = False
                    break
            if holds_all:
                return False
        return True

    def record_if_header(self, path):
        header = self.headers.get("If", "")
        if header.strip():
            SERVER_STORE.if_headers.append({"command": self.command,
                                            "path": self.normalize(path),
                                            "header": header})

    def send_precondition_failed(self):
        self.send_error_text(412, "Precondition Failed: the If header this "
                                  "request carries does not hold.")

    def locked_out(self, path):
        """True when a lock guards this path and the request proves no
        ownership: that is the 423 a real server answers, and it is what
        makes a lock more than a stored token."""
        entry = SERVER_STORE.lock_owner(path)
        if entry is None:
            return False
        return entry["token"] not in self.if_tokens()

    def send_locked(self):
        self.send_error_text(423, "Locked: the path is locked by "
                                 "another writer.")

    # -- verbs -------------------------------------------------------------
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("DAV", "1")
        self.send_header("Allow",
                         "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, "
                         "PROPFIND, MOVE, COPY, LOCK, UNLOCK, PROPPATCH")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def drain_body(self):
        length = int(self.headers.get("Content-Length") or "0")
        if length:
            self.rfile.read(length)

    def do_PROPFIND(self):
        self.drain_body()  # before any answer: 401 included, or the
        # retry that follows would read the stale body as a new request
        if not self.authorized():
            return
        path = self.local_path()
        item = SERVER_STORE.get(path)
        if item is None:
            self.send_error_text(404, "Not Found.")
            return
        depth = self.headers.get("Depth", "infinity")
        if depth == "infinity":
            depth = "1"  # this store has no deep trees worth recursing
        host = self.headers.get("Host", "127.0.0.1")
        scheme = "http"  # plain HTTP on the loopback test port
        wanted = [self.normalize(path)] if depth == "0" else (
            [self.normalize(path)] + SERVER_STORE.children_of(path))
        responses = []
        for target in wanted:
            entry = SERVER_STORE.get(target)
            if entry is None:
                continue
            href = "%s://%s%s" % (scheme, host,
                                  urllib.parse.quote(target, safe="/"))
            if entry["kind"] == "dir" and not href.endswith("/"):
                href += "/"
            if entry["kind"] == "dir":
                type_prop = "<d:resourcetype><d:collection/></d:resourcetype>"
                length_prop = "<d:getcontentlength>0</d:getcontentlength>"
            else:
                data = entry.get("data", b"")
                type_prop = "<d:resourcetype/>"
                length_prop = ("<d:getcontentlength>%d</d:getcontentlength>"
                               % len(data))
            # getetag is what a client records a precondition from, so a
            # collection carries one too: it names the version of the
            # listing, which is all a collection has to compare.
            etag = SERVER_STORE.etag_of(target)
            if target == "/dav-weak-tree/weak.txt" and etag:
                etag = "W/" + etag
            if target == "/dav-missing-tree/missing.txt":
                etag = None
            etag_prop = ("<d:getetag>%s</d:getetag>" % xml_escape(etag)
                         if etag else "")
            # The dead properties this store holds, in the namespace the
            # client wrote them in, next to the live ones.
            dead = "".join(
                "<lscp:%s xmlns:lscp=\"urn:linscp:properties\">%s</lscp:%s>"
                % (name, xml_escape(value), name)
                for name, value in sorted(
                    SERVER_STORE.get_properties(target).items()))
            responses.append(
                "<d:response><d:href>%s</d:href>"
                "<d:propstat><d:prop>%s%s%s"
                "<d:getlastmodified>%s</d:getlastmodified>%s"
                "</d:prop>"
                "<d:status>HTTP/1.1 200 OK</d:status>"
                "</d:propstat></d:response>"
                % (xml_escape(href), type_prop, length_prop, etag_prop,
                   http_date(entry["mtime"]), dead))
        body = PROPFIND_BODY % "".join(responses)
        self.send_body(207, body, "application/xml; charset=utf-8")

    @staticmethod
    def normalize(path):
        return Store.normalize(path)

    def do_LOCK(self):
        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        if not self.authorized():
            return
        path = self.local_path()
        stage_created = False
        if os.environ.get("LSCP_TEST_LOCK_STAGING") == "1" and self.headers.get("If-None-Match") == "*" and "/.linscp-lock-" in path:
            with SERVER_STORE.write_lock:
                parent = SERVER_STORE.get(SERVER_STORE.parent_of(SERVER_STORE.normalize(path)))
                if SERVER_STORE.get(path) is not None:
                    self.send_precondition_failed()
                    return
                if parent is None or parent["kind"] != "dir":
                    self.send_error_text(409, "The parent collection does not exist.")
                    return
                SERVER_STORE.add_file(path, b"")
                stage_created = True
        timeout = 0
        header = self.headers.get("Timeout", "")
        if header.lower().startswith("second-"):
            timeout = int(header.split("-", 1)[1] or "0")
        owner = re.search(r"<owner>.*?<href>(.*?)</href>", body, re.S)
        status, token = SERVER_STORE.lock(
            path, timeout, owner.group(1) if owner else "linscp")
        if status == "missing":
            self.send_error_text(404, "Not Found.")
            return
        if status == "locked":
            self.send_error_text(423, "Already locked.")
            return
        href = urllib.parse.quote(SERVER_STORE.normalize(path), safe="/")
        body_out = (
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            "<d:prop xmlns:d=\"DAV:\"><d:lockdiscovery><d:activelock>"
            "<d:locktype><d:write/></d:locktype>"
            "<d:lockscope><d:exclusive/></d:lockscope>"
            "<d:depth>0</d:depth><d:timeout>Second-%d</d:timeout>"
            "<d:locktoken><d:href>%s</d:href></d:locktoken>"
            "</d:activelock></d:lockdiscovery></d:prop>" % (timeout, token))
        self.send_body(201 if stage_created else 200, body_out, "application/xml; charset=utf-8",
                       extra=[("Lock-Token", "<%s>" % token)])

    def do_UNLOCK(self):
        self.drain_body()
        if not self.authorized():
            return
        header = self.headers.get("Lock-Token", "").strip().strip("<>")
        result = SERVER_STORE.unlock(self.local_path(), header)
        if result == "unlocked":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif result == "conflict":
            self.send_error_text(409, "That is not this lock's token.")
        else:
            self.send_error_text(404, "Not locked.")

    def do_PROPPATCH(self):
        length = int(self.headers.get("Content-Length") or "0")
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        if not self.authorized():
            return
        path = self.local_path()
        if self.locked_out(path):
            self.send_locked()
            return
        # <d:set><d:prop><prefix:name>value</prefix:name></d:prop></d:set>
        stored = []
        # A dead property is an element in the client's own namespace: the
        # DAV: elements around it (set, prop, propertyupdate) are the
        # request's own vocabulary, not properties.
        for match in re.finditer(
                r"<(?!d:|D:|DAV:)([A-Za-z0-9_.-]+):([A-Za-z_][A-Za-z0-9_.-]*)"
                r"[^>]*>(.*?)</\1:\2>", body, re.S):
            name, value = match.group(2), match.group(3)
            status = SERVER_STORE.set_property(path, name, value)
            if status == "missing":
                self.send_error_text(404, "Not Found.")
                return
            stored.append(name)
        if not stored:
            self.send_error_text(400, "PROPPATCH needs one property to set.")
            return
        href = urllib.parse.quote(SERVER_STORE.normalize(path), safe="/")
        propstats = "".join(
            "<d:propstat><d:prop><lscp:%s/></d:prop>"
            "<d:status>HTTP/1.1 200 OK</d:status></d:propstat>" % name
            for name in stored)
        self.send_body(
            207,
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            "<d:multistatus xmlns:d=\"DAV:\" "
            "xmlns:lscp=\"urn:linscp:properties\">"
            "<d:response><d:href>%s</d:href>%s</d:response></d:multistatus>"
            % (xml_escape(href), propstats),
            "application/xml; charset=utf-8")

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/__test__/reject-next-copy":
            SERVER_STORE.reject_next_copy = True
            self.send_body(204, b"")
            return
        if parsed.path == "/__test__/state":
            body = json.dumps({
                "copy_count": SERVER_STORE.copy_count,
                "locks": {path: entry["token"] for path, entry
                          in SERVER_STORE.locks.items()},
                "properties": SERVER_STORE.properties,
                "etags": {path: SERVER_STORE.etag_of(path)
                          for path in sorted(SERVER_STORE.items)},
                "if_headers": SERVER_STORE.if_headers,
            }).encode("utf-8")
            self.send_body(200, body, "application/json")
            return
        if not self.authorized():
            return
        path = self.local_path()
        with SERVER_STORE.write_lock:
            item = SERVER_STORE.get(path)
            if item is None:
                self.send_error_text(404, "Not Found.")
                return
            if item["kind"] == "dir":
                self.send_error_text(405, "The collection is not gettable.")
                return
            tag = SERVER_STORE.etag_of(path) or ""
            expected = self.headers.get("If-Match", "").strip()
            if expected and expected != tag:
                self.send_precondition_failed()
                return
            data = item.get("data", b"")
            mtime = item["mtime"]
        extra = (("Last-Modified", http_date(mtime)),
                 ("Accept-Ranges", "bytes"),
                 ("ETag", tag))
        if path == "/move-get-accepted.txt":
            self.send_body(202, data, "application/octet-stream", extra)
            return
        if path == "/move-get-short.txt":
            self.send_body(200, data[:1], "application/octet-stream", extra)
            return
        range_header = self.headers.get("Range")
        if range_header:
            match = re.match(r"bytes=(\d+)-(\d*)$", range_header.strip())
            if match:
                start = int(match.group(1))
                if start >= len(data):
                    self.send_error_text(416, "Range not satisfiable.")
                    return
                end = int(match.group(2)) if match.group(2) else len(data) - 1
                end = min(end, len(data) - 1)
                body = data[start:end + 1]
                content_range = "bytes %d-%d/%d" % (start, end, len(data))
                if path == "/resume-wrong-range.txt" and os.environ.get("LSCP_TEST_BAD_RANGE") == "1":
                    content_range = "bytes %d-%d/%d" % (start + 1, end, len(data))
                extra = extra + (("Content-Range", content_range),)
                self.send_body(206, body,
                               "application/octet-stream", extra)
                return
        self.send_body(200, data, "application/octet-stream", extra)

    def do_HEAD(self):
        self.do_GET()

    def do_PUT(self):
        length = int(self.headers.get("Content-Length") or "0")
        data = self.rfile.read(length) if length else b""
        if len(data) != length:
            self.close_connection = True
            return
        if not self.authorized():
            return
        path = self.local_path()
        if path == "/cross-accepted.txt" and os.environ.get("LSCP_TEST_ACCEPTED_PUT") == "1":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        parent = SERVER_STORE.parent_of(SERVER_STORE.normalize(path))
        item = SERVER_STORE.get(parent)
        if item is None or item["kind"] != "dir":
            self.send_error_text(409, "The parent collection does not exist.")
            return
        self.record_if_header(path)
        if self.locked_out(path):
            self.send_locked()
            return
        if self.precondition_failed(path):
            self.send_precondition_failed()
            return
        with SERVER_STORE.write_lock:
            existed = SERVER_STORE.get(path) is not None
            if self.headers.get("If-None-Match", "").strip() == "*" and existed:
                self.send_precondition_failed()
                return
            expected = self.headers.get("If-Match", "").strip()
            if expected and (not existed or expected != SERVER_STORE.etag_of(path)):
                self.send_precondition_failed()
                return
            SERVER_STORE.add_file(path, data)
        self.send_response(204 if existed else 201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_DELETE(self):
        if not self.authorized():
            return
        path = self.local_path()
        if "/.linscp-lock-" in path and os.environ.get("LSCP_TEST_LOCK_REPLACEMENT") == "1":
            with SERVER_STORE.write_lock:
                SERVER_STORE.locks.pop(SERVER_STORE.normalize(path), None)
                SERVER_STORE.add_file(path, b"replacement by another actor")
        if path == "/cross-delete-accepted.txt":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.record_if_header(path)
        if self.locked_out(path):
            self.send_locked()
            return
        if self.precondition_failed(path):
            self.send_precondition_failed()
            return
        with SERVER_STORE.write_lock:
            expected = self.headers.get("If-Match", "").strip()
            if expected and path == "/move-delete-race.txt" and os.environ.get("LSCP_TEST_DELETE_RACE") == "1":
                time.sleep(0.5)
                SERVER_STORE.add_file(path, b"changed before conditional delete")
            if expected and expected != SERVER_STORE.etag_of(path):
                self.send_precondition_failed()
                return
            result = SERVER_STORE.delete(path)
        if result == "deleted":
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif result == "missing":
            self.send_error_text(404, "Not Found.")
        elif result == "conflict":
            self.send_error_text(409, "The collection is not empty.")
        else:
            self.send_error_text(403, "Forbidden.")

    def do_MKCOL(self):
        if not self.authorized():
            return
        result = SERVER_STORE.add_dir(self.local_path())
        if result == "created":
            self.send_response(201)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif result == "exists":
            self.send_error_text(405, "Already there.")
        elif result == "no-parent":
            self.send_error_text(409, "The parent collection does not exist.")
        else:
            self.send_error_text(403, "Forbidden.")

    def do_MOVE(self):
        if not self.authorized():
            return
        if self.local_path() == "/rename-redirect.txt":
            self.send_response(307)
            self.send_header("Location", "/rename-other.txt")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.local_path() == "/rename-multistatus.txt":
            self.send_response(207)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        destination = self.headers.get("Destination", "")
        if not destination:
            self.send_error_text(400, "Destination required.")
            return
        parsed = urllib.parse.urlsplit(destination)
        dest = urllib.parse.unquote(parsed.path or destination)
        overwrite = self.headers.get("Overwrite", "T").upper() != "F"
        self.record_if_header(self.local_path())
        if self.locked_out(self.local_path()):
            self.send_locked()
            return
        if self.precondition_failed(self.local_path()):
            self.send_precondition_failed()
            return
        with SERVER_STORE.write_lock:
            expected = self.headers.get("If-Match", "").strip()
            if expected and expected != SERVER_STORE.etag_of(self.local_path()):
                self.send_precondition_failed()
                return
            result = SERVER_STORE.move(self.local_path(), dest, overwrite)
        if result in ("created", "replaced"):
            self.send_response(201 if result == "created" else 204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif result == "missing-source":
            self.send_error_text(404, "Not Found.")
        elif result == "precondition":
            self.send_error_text(412, "The destination exists.")
        elif result == "no-parent":
            self.send_error_text(409, "The destination's parent is missing.")
        else:
            self.send_error_text(403, "Forbidden.")

    def do_COPY(self):
        if not self.authorized():
            return
        if SERVER_STORE.reject_next_copy:
            SERVER_STORE.reject_next_copy = False
            self.send_error_text(405, "COPY is disabled for this request.")
            return
        destination = self.headers.get("Destination", "")
        if not destination:
            self.send_error_text(400, "Destination required.")
            return
        parsed = urllib.parse.urlsplit(destination)
        if parsed.netloc and parsed.netloc.lower() != self.headers.get(
                "Host", "").lower():
            self.send_error_text(502, "Destination must be on this server.")
            return
        dest = urllib.parse.unquote(parsed.path or destination)
        overwrite = self.headers.get("Overwrite", "T").upper() != "F"
        self.record_if_header(self.local_path())
        if self.precondition_failed(self.local_path()):
            self.send_precondition_failed()
            return
        result = SERVER_STORE.copy(self.local_path(), dest, overwrite)
        if result in ("created", "replaced"):
            self.send_response(201 if result == "created" else 204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif result == "missing-source":
            self.send_error_text(404, "Not Found.")
        elif result == "precondition":
            self.send_error_text(412, "The destination exists.")
        elif result == "no-parent":
            self.send_error_text(409, "The destination's parent is missing.")
        else:
            self.send_error_text(403, "Forbidden.")

    def do_POST(self):
        self.send_error_text(405, "POST is not part of this test server.")


def _basic_token(user, password):
    import base64
    return base64.b64encode(("%s:%s" % (user, password)).encode()).decode()


SERVER_STORE = Store()


def main():
    import os
    port = int(os.environ.get("LSCP_TEST_PORT", "0"))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), DavHandler)
    print("READY %d" % httpd.server_address[1], flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
