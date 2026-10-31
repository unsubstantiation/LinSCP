"""A throwaway Amazon S3 endpoint that verifies AWS Signature Version 4.

TestSftpServer.py covers the SFTP protocol; Amazon S3 is a different
transport (signed HTTP) and needs its own server. This one speaks the
subset LinSCP's S3 client uses - ListBuckets, ListObjectsV2 with a
delimiter, PUT/GET/HEAD/DELETE of objects, CopyObject for rename,
zero-byte "key/" markers for directories, byte ranges for resumed
downloads - and it refuses anything whose signature it cannot
re-derive.

The verification here is deliberately written from the specification
(hmac/hashlib over the canonical request the client must have built),
not imported from the same code the client uses: a bug shared between
the two sides would make every test pass while real S3 rejects the
requests. The unit suite pins the client to botocore's output and
LiveS3Test pins this server to a botocore-signed request, so both ends
have to agree with the reference implementation.

Run it directly; it prints "READY <port>" when listening over TLS
(the client maps s3:// to https, and the certificate is the test
fixture in fixtures/):

    LSCP_TEST_ROOT=... LSCP_TEST_PORT=0 python3 TestS3Server.py
"""

import base64
import datetime
import hashlib
import hmac
import json
import xml.etree.ElementTree as ET
import os
import pathlib
import re
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = pathlib.Path(__file__).resolve().parent
ACCESS_KEY = os.environ.get("LSCP_TEST_ACCESS", "AKIDTEST")
SECRET_KEY = os.environ.get("LSCP_TEST_SECRET", "testsecret42")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def uri_encode(value, keep_slash=False):
    """The SigV4 percent-encoding: uppercase hex, '~' kept, '/' kept
    only where a path says so."""
    out = []
    for byte in value.encode("utf-8"):
        char = chr(byte)
        if char in UNRESERVED or (keep_slash and char == "/"):
            out.append(char)
        else:
            out.append("%%%02X" % byte)
    return "".join(out)


def canonical_query(raw_query):
    """Decode-and-re-encode every pair (idempotent for a correctly
    encoded client), then sort by name and value."""
    pairs = []
    if raw_query:
        for part in raw_query.split("&"):
            if not part:
                continue
            name, _, value = part.partition("=")
            pairs.append((uri_encode(urllib.parse.unquote(name)),
                          uri_encode(urllib.parse.unquote(value))))
    pairs.sort()
    return "&".join("%s=%s" % pair for pair in pairs)


def canonical_path(raw_path):
    """The S3 canonical URI: percent-encoded once, '/' separators kept.
    A correct client's path is already in that form, so decode then
    re-encode is the identity for it and a mismatch for anyone else."""
    decoded = urllib.parse.unquote(raw_path)
    out = []
    for segment in decoded.split("/"):
        out.append(uri_encode(segment))
    return "/".join(out)


def hmac_sha256(key, data):
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).digest()


def signing_key(secret, date_stamp, region, service):
    key = hmac_sha256("AWS4" + secret, date_stamp)
    key = hmac_sha256(key, region)
    key = hmac_sha256(key, service)
    return hmac_sha256(key, "aws4_request")


class AuthorizationError(Exception):
    """Anything that makes a request unverifiable, with the S3 code to
    answer with."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def verify_signature(method, raw_path, raw_query, headers, body):
    """Re-derives what the client signed. Raises AuthorizationError."""
    authorization = headers.get("authorization", "")
    match = re.match(
        r"^AWS4-HMAC-SHA256\s+"
        r"Credential=(?P<access>[^/]+)/(?P<date>\d{8})/"
        r"(?P<region>[^/]+)/(?P<service>[^/]+)/aws4_request,\s*"
        r"SignedHeaders=(?P<signed>[^,]+),\s*"
        r"Signature=(?P<signature>[0-9a-f]{64})$",
        authorization)
    if not match:
        raise AuthorizationError(
            "InvalidRequest",
            "The request is not signed with AWS Signature Version 4 "
            "(Authorization: %s)." % (authorization[:80] or "<absent>"))
    if match.group("access") != ACCESS_KEY:
        raise AuthorizationError(
            "InvalidAccessKeyId",
            "The AWS Access Key Id you provided does not exist in our "
            "records.")
    for header in ("x-amz-date", "x-amz-content-sha256"):
        if header not in headers:
            raise AuthorizationError(
                "MissingSecurityHeader",
                "Your request is missing the required header %s." % header)

    payload_hash = headers["x-amz-content-sha256"]
    if payload_hash != "UNSIGNED-PAYLOAD":
        digest = hashlib.sha256(body).hexdigest()
        if not hmac.compare_digest(payload_hash, digest):
            raise AuthorizationError(
                "XAmzContentSHA256Mismatch",
                "The provided 'x-amz-content-sha256' header does not "
                "match what was computed.")

    signed_names = [name.strip() for name in match.group("signed").split(";")]
    canonical_headers = []
    for name in signed_names:
        if name not in headers:
            raise AuthorizationError(
                "SignatureDoesNotMatch",
                "The signature does not match the signed header '%s'." % name)
        value = " ".join(headers[name].strip().split())
        canonical_headers.append("%s:%s\n" % (name, value))
    canonical = "\n".join((method, canonical_path(raw_path),
                           canonical_query(raw_query))) + "\n" + \
        "".join(canonical_headers) + "\n" + \
        ";".join(signed_names) + "\n" + payload_hash

    scope = "%s/%s/%s/aws4_request" % (
        match.group("date"), match.group("region"), match.group("service"))
    to_sign = "\n".join((
        "AWS4-HMAC-SHA256",
        headers["x-amz-date"],
        scope,
        hashlib.sha256(canonical.encode("utf-8")).hexdigest()))
    key = signing_key(SECRET_KEY, match.group("date"),
                      match.group("region"), match.group("service"))
    expected = hmac_sha256(key, to_sign).hex()
    if not hmac.compare_digest(expected, match.group("signature")):
        raise AuthorizationError(
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the "
            "signature you provided. Check your key and signing method.")


def xml_escape(value):
    return (value.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;")
            .replace("'", "&apos;"))


def iso8601(epoch):
    moment = datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def http_date(epoch):
    moment = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return moment.strftime("%a, %d %b %Y %H:%M:%S GMT")


class Store:
    """Bucket -> key -> (bytes, last-modified). In memory only."""

    def __init__(self):
        self.write_lock = threading.Lock()
        self.buckets = {}  # name -> creation epoch
        self.objects = {}  # (bucket, key) -> (bytes, mtime), current version only
        self.versions = {}  # (bucket, key) -> oldest-to-newest version records
        self.next_version_id = 1
        self.list_pagination_fault = ""
        self.version_pagination_fault = ""
        self.object_headers = {}  # "bucket/key" -> dict of x-amz-* headers
        self.request_payers = []
        self.uploads = {}  # UploadId -> {bucket, key, parts, headers}
        self.next_upload_id = 1
        self.multipart_history = []
        self.copy_count = 0
        self.embedded_errors = set()

    def ensure_bucket(self, bucket, epoch):
        if bucket not in self.buckets:
            self.buckets[bucket] = epoch

    def _new_version_id(self):
        # Deliberately opaque and URL-hostile: the client has to escape the
        # version marker and the versionId query value without changing it.
        version_id = "v%d+/%%&=?" % self.next_version_id
        self.next_version_id += 1
        return version_id

    def put(self, bucket, key, data, epoch):
        self.ensure_bucket(bucket, epoch)
        version_id = self._new_version_id()
        self.versions.setdefault((bucket, key), []).append({
            "version_id": version_id,
            "data": data,
            "mtime": epoch,
            "delete_marker": False,
        })
        self.objects[(bucket, key)] = (data, epoch)
        return version_id

    def get(self, bucket, key):
        return self.objects.get((bucket, key))

    def get_version(self, bucket, key, version_id):
        for item in reversed(self.versions.get((bucket, key), [])):
            if item["version_id"] == version_id:
                return item
        return None

    def delete_version(self, bucket, key, version_id):
        records = self.versions.get((bucket, key), [])
        for index, item in enumerate(records):
            if item["version_id"] == version_id:
                del records[index]
                if records:
                    latest = records[-1]
                    if latest["delete_marker"]:
                        self.objects.pop((bucket, key), None)
                    else:
                        self.objects[(bucket, key)] = (
                            latest["data"], latest["mtime"])
                else:
                    self.objects.pop((bucket, key), None)
                    self.versions.pop((bucket, key), None)
                return True
        return False

    def delete(self, bucket, key, version_id=None, epoch=None):
        if version_id is not None:
            return self.delete_version(bucket, key, version_id)
        epoch = epoch or datetime.datetime.now(
            datetime.timezone.utc).timestamp()
        self.ensure_bucket(bucket, epoch)
        version_id = self._new_version_id()
        self.versions.setdefault((bucket, key), []).append({
            "version_id": version_id,
            "data": b"",
            "mtime": epoch,
            "delete_marker": True,
        })
        self.objects.pop((bucket, key), None)
        return version_id

    def keys_of(self, bucket):
        return sorted(key for (b, key) in self.objects if b == bucket)


STORE = Store()
if os.environ.get("LSCP_TEST_SEED") == "1":
    STORE.put("photos", "seed.txt", b"S3 verified download", datetime.datetime.now(datetime.timezone.utc).timestamp())
    STORE.put("photos", "slow.bin", b"s" * (4 * 1024 * 1024), datetime.datetime.now(datetime.timezone.utc).timestamp())


class S3Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # -- plumbing ---------------------------------------------------------
    def log_message(self, *args):
        pass

    def headers_dict(self):
        # Lower-cased: the canonical form of a header name is its
        # lower-case spelling, and curl writes "Host" while the
        # signature says "host".
        return {name.lower(): value for name, value in self.headers.items()}

    def read_body(self):
        length = int(self.headers.get("Content-Length") or "0")
        return self.rfile.read(length) if length else b""

    def send_xml(self, status, payload):
        body = payload.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def send_error_xml(self, status, code, message, extra=()):
        body = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                "<Error><Code>%s</Code><Message>%s</Message>"
                "<Resource>%s</Resource><RequestId>test</RequestId>"
                "</Error>" % (xml_escape(code), xml_escape(message),
                              xml_escape(self.path))).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_bytes(self, status, data, extra=(), content_length=None):
        self.send_response(status)
        for name, value in extra:
            self.send_header(name, value)
        if status not in (204, 304):
            length = len(data) if content_length is None else content_length
            self.send_header("Content-Length", str(length))
        self.end_headers()
        if data and self.command != "HEAD" and status not in (204, 304):
            delay = float(os.environ.get("LSCP_TEST_GET_DELAY", "0"))
            if self.command == "GET" and delay:
                for offset in range(0, len(data), 32768):
                    self.wfile.write(data[offset:offset + 32768])
                    self.wfile.flush()
                    time.sleep(delay)
            else:
                self.wfile.write(data)

    # -- dispatch ---------------------------------------------------------
    def split_path(self):
        """'/bucket/key...' -> (bucket, key); '/' -> ('', '')."""
        raw = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(raw.path)
        if path == "/" or path == "":
            return "", "", raw.query
        # Drop exactly the leading separator: splitting a path that
        # still starts with '/' would yield an empty first field and
        # silently file everything under bucket ''.
        if path.startswith("/"):
            path = path[1:]
        parts = path.split("/", 1)
        bucket = parts[0]
        key = parts[1] if len(parts) > 1 else ""
        return bucket, key, raw.query

    def handle_any(self, method, body):
        raw_path = urllib.parse.urlsplit(self.path).path
        raw_query = urllib.parse.urlsplit(self.path).query
        headers = self.headers_dict()
        # The client's canonical host header included the port when the
        # URL did; requests.headers gives Host exactly as sent.
        try:
            verify_signature(method, raw_path, raw_query, headers, body)
        except AuthorizationError as failure:
            self.send_error_xml(403, failure.code, failure.message)
            return

        if "x-amz-request-payer" in headers:
            STORE.request_payers.append(headers["x-amz-request-payer"])

        bucket, key, query = self.split_path()
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        try:
            if method == "GET" and bucket == "" and key == "":
                self.list_buckets()
            elif method == "GET" and key == "":
                if "versions" in params:
                    self.list_object_versions(bucket, query)
                else:
                    self.list_objects(bucket, query)
            elif method == "HEAD" and key == "":
                self.head_bucket(bucket)
            elif method == "PUT" and key == "" and not body:
                self.create_bucket(bucket)
            elif method == "GET":
                self.get_object(bucket, key, params)
            elif method == "HEAD":
                self.head_object(bucket, key, params)
            elif method == "PUT" and "uploadId" in params:
                self.put_multipart_part(params, headers, body)
            elif method == "PUT":
                self.put_object(bucket, key, headers, body)
            elif method == "POST" and "uploads" in params:
                self.initiate_multipart(bucket, key, headers)
            elif method == "POST" and "uploadId" in params:
                self.complete_multipart(params, headers, body)
            elif method == "DELETE" and "uploadId" in params:
                self.abort_multipart(params)
            elif method == "DELETE":
                self.delete_object(bucket, key, params)
            else:
                self.send_error_xml(405, "MethodNotAllowed",
                                    "Method %s is not allowed." % method)
        except BrokenPipeError:
            pass

    def do_GET(self):
        # Diagnostic endpoints consumed only by the live regression suite.
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/__test__/inject-error":
            operation = urllib.parse.parse_qs(parsed.query).get(
                "operation", [""])[0]
            if operation not in ("copy", "complete", "part2"):
                self.send_bytes(400, b"Unknown test error operation.")
                return
            STORE.embedded_errors.add(operation)
            self.send_bytes(204, b"")
            return
        if parsed.path == "/__test__/inject-pagination-fault":
            params = urllib.parse.parse_qs(parsed.query)
            target = params.get("target", [""])[0]
            fault = params.get("fault", [""])[0]
            if target == "objects" and fault in ("repeat-token", "missing-token"):
                STORE.list_pagination_fault = fault
            elif target == "versions" and fault in (
                    "repeat-marker", "missing-version-marker"):
                STORE.version_pagination_fault = fault
            else:
                self.send_bytes(400, b"Unknown pagination fault.")
                return
            self.send_bytes(204, b"")
            return
        if parsed.path == "/__test__/seed-objects":
            # Fill a bucket with flat keys so ListObjectsV2 crosses its
            # default 1000-key page boundary.
            params = urllib.parse.parse_qs(parsed.query)
            bucket = params.get("bucket", ["test-bucket"])[0]
            try:
                count = int(params.get("count", ["0"])[0])
            except ValueError:
                count = 0
            if count < 1 or count > 5000:
                self.send_bytes(400, b"Invalid object count.")
                return
            now = datetime.datetime.now(datetime.timezone.utc).timestamp()
            STORE.ensure_bucket(bucket, now)
            for index in range(count):
                STORE.put(bucket, "item-%04d.txt" % index, b"x", now + index)
            self.send_bytes(204, b"")
            return
        if parsed.path == "/__test__/seed-versions":
            # Create enough history to force ListObjectVersions pagination
            # without making the test launch a thousand curl processes.
            params = urllib.parse.parse_qs(parsed.query)
            bucket = params.get("bucket", ["test-bucket"])[0]
            key = params.get("key", ["pagination/object"])[0]
            try:
                count = int(params.get("count", ["0"])[0])
            except ValueError:
                count = 0
            if count < 1 or count > 5000:
                self.send_bytes(400, b"Invalid version count.")
                return
            now = datetime.datetime.now(datetime.timezone.utc).timestamp()
            STORE.ensure_bucket(bucket, now)
            for index in range(count):
                STORE.put(bucket, key, ("seed-%d" % index).encode("ascii"),
                          now + index)
            self.send_bytes(204, b"")
            return
        if parsed.path == "/__test__/state":
            # This makes the multipart tests prove which API operations ran.
            body = json.dumps({
                "active_uploads": len(STORE.uploads),
                "multipart_history": STORE.multipart_history,
                "copy_count": STORE.copy_count,
                "object_headers": STORE.object_headers,
                "request_payers": STORE.request_payers,
            }).encode("utf-8")
            self.send_bytes(200, body, extra=(("Content-Type",
                "application/json"),))
            return
        self.handle_any("GET", b"")

    def do_HEAD(self):
        self.handle_any("HEAD", b"")

    def do_PUT(self):
        self.handle_any("PUT", self.read_body())

    def do_DELETE(self):
        self.handle_any("DELETE", self.read_body())

    def do_POST(self):
        self.handle_any("POST", self.read_body())

    # -- operations -------------------------------------------------------
    def list_buckets(self):
        entries = "".join(
            "<Bucket><Name>%s</Name><CreationDate>%s</CreationDate>"
            "</Bucket>" % (xml_escape(name), iso8601(creation))
            for name, creation in sorted(STORE.buckets.items()))
        self.send_xml(200,
                      '<?xml version="1.0" encoding="UTF-8"?>\n'
                      "<ListAllMyBucketsResult>"
                      "<Owner><ID>test</ID><DisplayName>test</DisplayName>"
                      "</Owner><Buckets>%s</Buckets>"
                      "</ListAllMyBucketsResult>" % entries)

    def list_objects(self, bucket, query):
        if bucket not in STORE.buckets:
            self.send_error_xml(404, "NoSuchBucket",
                                "The specified bucket does not exist.")
            return
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        prefix = params.get("prefix", [""])[0]
        delimiter = params.get("delimiter", [""])[0]
        max_keys = int(params.get("max-keys", ["1000"])[0])
        token = params.get("continuation-token", [""])[0]
        try:
            offset = int(token) if token else 0
        except ValueError:
            offset = 0

        # Split the matching keys into file entries and sub-prefixes,
        # the way ListObjectsV2 with a delimiter does.
        files = []
        common = set()
        for key in STORE.keys_of(bucket):
            if not key.startswith(prefix):
                continue
            relative = key[len(prefix):]
            if relative == "":
                continue
            if delimiter and delimiter in relative:
                common.add(prefix + relative.split(delimiter, 1)[0] +
                           delimiter)
            else:
                files.append(key)
        entries = sorted(("file", name) for name in files)
        entries += sorted(("dir", name) for name in common)
        page = entries[offset:offset + max_keys]
        truncated = offset + len(page) < len(entries)

        def file_xml(key):
            data, mtime = STORE.objects[(bucket, key)]
            return ("<Contents><Key>%s</Key><LastModified>%s</LastModified>"
                    "<ETag>%s</ETag><Size>%d</Size>"
                    "<StorageClass>STANDARD</StorageClass></Contents>"
                    % (xml_escape(key), iso8601(mtime),
                       hashlib.sha256(data).hexdigest()[:32], len(data)))

        def dir_xml(name):
            return "<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>" % (
                xml_escape(name))

        body = "".join(
            file_xml(value) if kind == "file" else dir_xml(value)
            for kind, value in page)
        continuation = ""
        if truncated:
            continuation = ("<NextContinuationToken>%d</NextContinuationToken>"
                            % (offset + len(page)))
        if STORE.list_pagination_fault == "missing-token" and truncated:
            continuation = ""
        elif STORE.list_pagination_fault == "repeat-token" and token:
            truncated = True
            continuation = ("<NextContinuationToken>%s</NextContinuationToken>"
                            % xml_escape(token))
        self.send_xml(200,
                      '<?xml version="1.0" encoding="UTF-8"?>\n'
                      "<ListBucketResult><Name>%s</Name><Prefix>%s</Prefix>"
                      "<KeyCount>%d</KeyCount><MaxKeys>%d</MaxKeys>"
                      "<Delimiter>%s</Delimiter><IsTruncated>%s</IsTruncated>"
                      "%s%s</ListBucketResult>"
                      % (xml_escape(bucket), xml_escape(prefix), len(page),
                         max_keys, xml_escape(delimiter),
                         "true" if truncated else "false",
                         continuation, body))

    def list_object_versions(self, bucket, query):
        if bucket not in STORE.buckets:
            self.send_error_xml(404, "NoSuchBucket",
                                "The specified bucket does not exist.")
            return
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        prefix = params.get("prefix", [""])[0]
        key_marker = params.get("key-marker", [""])[0]
        version_marker = params.get("version-id-marker", [""])[0]
        try:
            max_keys = max(1, int(params.get("max-keys", ["1000"])[0]))
        except ValueError:
            max_keys = 1000

        items = []
        keys = sorted(key for (stored_bucket, key) in STORE.versions
                      if stored_bucket == bucket and key.startswith(prefix))
        for key in keys:
            records = STORE.versions[(bucket, key)]
            for index in range(len(records) - 1, -1, -1):
                items.append((key, records[index], index == len(records) - 1))

        start = 0
        if key_marker:
            marker_found = False
            for index, (key, record, _) in enumerate(items):
                if key < key_marker:
                    continue
                if key > key_marker:
                    start = index
                    marker_found = True
                    break
                if not version_marker:
                    continue
                if record["version_id"] == version_marker:
                    start = index + 1
                    marker_found = True
                    break
            if not marker_found:
                start = len(items)

        page = items[start:start + max_keys]
        truncated = start + len(page) < len(items)

        def version_xml(key, record, latest):
            tag = "DeleteMarker" if record["delete_marker"] else "Version"
            common = ("<Key>%s</Key><VersionId>%s</VersionId>"
                      "<IsLatest>%s</IsLatest><LastModified>%s</LastModified>"
                      % (xml_escape(key), xml_escape(record["version_id"]),
                         "true" if latest else "false",
                         iso8601(record["mtime"])))
            size = "" if record["delete_marker"] else (
                "<Size>%d</Size>" % len(record["data"]))
            return "<%s>%s%s</%s>" % (tag, common, size, tag)

        body = "".join(version_xml(key, record, latest)
                        for key, record, latest in page)
        next_markers = ""
        if truncated and page:
            last_key, last_record, _ = page[-1]
            next_markers = ("<NextKeyMarker>%s</NextKeyMarker>"
                            "<NextVersionIdMarker>%s</NextVersionIdMarker>"
                            % (xml_escape(last_key),
                               xml_escape(last_record["version_id"])))
        if STORE.version_pagination_fault == "missing-version-marker" and truncated:
            next_markers = ("<NextKeyMarker>%s</NextKeyMarker>" %
                            xml_escape(page[-1][0])) if page else ""
        elif STORE.version_pagination_fault == "repeat-marker" and key_marker:
            truncated = True
            next_markers = ("<NextKeyMarker>%s</NextKeyMarker>"
                            "<NextVersionIdMarker>%s</NextVersionIdMarker>"
                            % (xml_escape(key_marker),
                               xml_escape(version_marker)))
        self.send_xml(200,
                      '<?xml version="1.0" encoding="UTF-8"?>\n'
                      "<ListVersionsResult><Name>%s</Name><Prefix>%s</Prefix>"
                      "<KeyMarker>%s</KeyMarker><VersionIdMarker>%s</VersionIdMarker>"
                      "<MaxKeys>%d</MaxKeys><IsTruncated>%s</IsTruncated>"
                      "%s%s</ListVersionsResult>"
                      % (xml_escape(bucket), xml_escape(prefix),
                         xml_escape(key_marker), xml_escape(version_marker),
                         max_keys, "true" if truncated else "false",
                         next_markers, body))

    def head_bucket(self, bucket):
        if bucket not in STORE.buckets:
            self.send_error_xml(404, "NoSuchBucket",
                                "The specified bucket does not exist.")
            return
        self.send_bytes(200, b"")

    def create_bucket(self, bucket):
        STORE.ensure_bucket(bucket, datetime.datetime.now(
            datetime.timezone.utc).timestamp())
        self.send_bytes(200, b"", extra=(("ETag", '"%s"' % bucket),))

    def _object_record(self, bucket, key, params):
        version_values = params.get("versionId")
        if version_values is None:
            record = STORE.get(bucket, key)
            if record is None:
                self.send_error_xml(404, "NoSuchKey",
                                    "The specified key does not exist.")
                return None, None
            return record, None

        version_id = version_values[0]
        version = STORE.get_version(bucket, key, version_id)
        if version is None:
            self.send_error_xml(404, "NoSuchVersion",
                                "The specified version does not exist.")
            return None, version_id
        if version["delete_marker"]:
            self.send_error_xml(405, "MethodNotAllowed",
                                "The specified version is a delete marker.",
                                extra=(("x-amz-delete-marker", "true"),
                                       ("x-amz-version-id", version_id)))
            return None, version_id
        return (version["data"], version["mtime"]), version_id

    def get_object(self, bucket, key, params):
        record, version_id = self._object_record(bucket, key, params)
        if record is None:
            return
        data, mtime = record
        version_header = (("x-amz-version-id", version_id),) if version_id else ()
        range_header = self.headers.get("Range")
        if range_header:
            match = re.match(r"bytes=(\d+)-(\d*)$", range_header.strip())
            if not match:
                self.send_error_xml(416, "InvalidRange",
                                    "Malformed Range header.")
                return
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else len(data) - 1
            if start >= len(data):
                self.send_error_xml(
                    416, "InvalidRange",
                    "The requested range is not satisfiable.")
                return
            end = min(end, len(data) - 1)
            sliced = data[start:end + 1]
            self.send_bytes(206, sliced, extra=(
                ("Content-Range",
                 "bytes %d-%d/%d" % (start, end, len(data))),
                ("Last-Modified", http_date(mtime)),
                ("Accept-Ranges", "bytes"),
                ("Content-Type", "application/octet-stream"),
            ) + version_header)
            return
        self.send_bytes(200, data, extra=(
            ("Last-Modified", http_date(mtime)),
            ("Accept-Ranges", "bytes"),
            ("Content-Type", "application/octet-stream"),
        ) + version_header)

    def head_object(self, bucket, key, params):
        record, version_id = self._object_record(bucket, key, params)
        if record is None:
            return
        data, mtime = record
        version_header = (("x-amz-version-id", version_id),) if version_id else ()
        self.send_bytes(200, b"", extra=(
            ("Last-Modified", http_date(mtime)),
            ("Content-Type", "application/octet-stream"),
            ("ETag", '"%s"' % hashlib.sha256(data).hexdigest()[:32]),
        ) + version_header, content_length=len(data))

    def put_object(self, bucket, key, headers, body):
        # Model an accepted-but-unconfirmed write and a redirect to another
        # object. Conditional moves must not delete their source in either case.
        if key == "cross-s3-accepted.txt":
            self.send_bytes(202, b"")
            return
        if key == "cross-s3-redirect.txt":
            self.send_bytes(307, b"", extra=(("Location", "/%s/cross-s3-redirect-target.txt" % bucket),))
            return
        if key == "":
            # PUT /bucket with a body has no meaning here.
            self.send_error_xml(400, "InvalidBucketName",
                                "The bucket name is invalid.")
            return
        amz_headers = {
            k: v for k, v in headers.items() if k.startswith("x-amz-")
        }
        copy_source = headers.get("x-amz-copy-source")
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        if copy_source:
            decoded = urllib.parse.unquote(copy_source)
            parts = decoded.lstrip("/").split("/", 1)
            source_bucket, source_key = parts[0], parts[1] if len(parts) > 1 else ""
            record = STORE.get(source_bucket, source_key)
            if record is None:
                self.send_error_xml(404, "NoSuchKey",
                                    "The specified key does not exist.")
                return
            if "copy" in STORE.embedded_errors:
                STORE.embedded_errors.remove("copy")
                self.send_xml(200,
                    "<Error><Code>InjectedCopyError</Code>"
                    "<Message>Embedded copy failure.</Message></Error>")
                return
            STORE.put(bucket, key, record[0], now)
            STORE.object_headers["%s/%s" % (bucket, key)] = amz_headers
            STORE.copy_count += 1
            self.send_xml(200,
                          "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                          "<CopyObjectResult><ETag>%s</ETag>"
                          "<LastModified>%s</LastModified></CopyObjectResult>"
                          % (hashlib.sha256(record[0]).hexdigest()[:32],
                             iso8601(now)))
            return
        if bucket not in STORE.buckets and key.endswith("/"):
            # mkdir creates both the bucket and its marker.
            STORE.ensure_bucket(bucket, now)
        with STORE.write_lock:
            if headers.get("if-none-match", "").strip() == "*" and STORE.get(bucket, key) is not None:
                self.send_error_xml(412, "PreconditionFailed", "The object already exists.")
                return
            match = headers.get("if-match")
            current = STORE.get(bucket, key)
            if match is not None and (current is None or match.strip() != '"%s"' % hashlib.sha256(current[0]).hexdigest()[:32]):
                self.send_error_xml(412, "PreconditionFailed", "The object has changed.")
                return
            STORE.put(bucket, key, body, now)
        STORE.object_headers["%s/%s" % (bucket, key)] = amz_headers
        self.send_bytes(200, b"", extra=(
            ("ETag", '"%s"' % hashlib.sha256(body).hexdigest()[:32]),))

    def initiate_multipart(self, bucket, key, headers=None):
        if bucket not in STORE.buckets or not key:
            self.send_error_xml(404, "NoSuchBucket",
                                "The multipart target bucket does not exist.")
            return
        upload_id = "test-upload-%d" % STORE.next_upload_id
        STORE.next_upload_id += 1
        amz_headers = {
            k: v for k, v in (headers or {}).items() if k.startswith("x-amz-")
        }
        STORE.uploads[upload_id] = {
            "bucket": bucket, "key": key, "parts": {}, "headers": amz_headers,
        }
        STORE.multipart_history.append({
            "action": "initiate", "bucket": bucket, "key": key,
            "upload_id": upload_id,
        })
        self.send_xml(200,
                      '<?xml version="1.0" encoding="UTF-8"?>'
                      "<InitiateMultipartUploadResult>"
                      "<Bucket>%s</Bucket><Key>%s</Key><UploadId>%s</UploadId>"
                      "</InitiateMultipartUploadResult>" %
                      (xml_escape(bucket), xml_escape(key), xml_escape(upload_id)))

    def put_multipart_part(self, params, headers, body):
        upload_id = params.get("uploadId", [""])[0]
        try:
            number = int(params.get("partNumber", ["0"])[0])
        except ValueError:
            number = 0
        upload = STORE.uploads.get(upload_id)
        if upload is None or number < 1 or number > 10000:
            self.send_error_xml(404, "NoSuchUpload",
                                "The multipart upload or part number is invalid.")
            return
        if number == 2 and "part2" in STORE.embedded_errors:
            STORE.embedded_errors.remove("part2")
            self.send_error_xml(500, "InternalError",
                                "Injected multipart part 2 failure.")
            return
        copy_source = (headers or {}).get("x-amz-copy-source")
        if copy_source:
            decoded = urllib.parse.unquote(copy_source)
            parts = decoded.lstrip("/").split("/", 1)
            source_bucket = parts[0]
            source_key = parts[1] if len(parts) > 1 else ""
            record = STORE.get(source_bucket, source_key)
            if record is None:
                self.send_error_xml(404, "NoSuchKey",
                                    "The specified key does not exist.")
                return
            source_bytes = record[0]
            range_header = (headers or {}).get("x-amz-copy-source-range", "")
            if range_header:
                match = re.match(r"bytes=(\d+)-(\d+)$", range_header.strip())
                if not match:
                    self.send_error_xml(400, "InvalidArgument",
                                        "Invalid x-amz-copy-source-range.")
                    return
                start = int(match.group(1))
                end = int(match.group(2))
                if start > end or end >= len(source_bytes):
                    self.send_error_xml(416, "InvalidRange",
                                        "Copy source range out of bounds.")
                    return
                source_bytes = source_bytes[start:end + 1]
            etag_hex = hashlib.sha256(source_bytes).hexdigest()[:32]
            etag = '"%s"' % etag_hex
            upload["parts"][number] = (source_bytes, etag)
            STORE.copy_count += 1
            STORE.multipart_history.append({
                "action": "copy_part", "part": number,
                "size": len(source_bytes), "upload_id": upload_id,
            })
            now = datetime.datetime.now(datetime.timezone.utc).timestamp()
            self.send_xml(200,
                          '<?xml version="1.0" encoding="UTF-8"?>\n'
                          "<CopyPartResult><ETag>%s</ETag>"
                          "<LastModified>%s</LastModified></CopyPartResult>"
                          % (etag, iso8601(now)))
            return
        delay = float(os.environ.get("LSCP_TEST_PART_DELAY", "0"))
        if delay:
            time.sleep(delay)
        etag = '"%s"' % hashlib.sha256(body).hexdigest()[:32]
        upload["parts"][number] = (body, etag)
        STORE.multipart_history.append({
            "action": "part", "part": number, "size": len(body),
            "upload_id": upload_id,
        })
        self.send_bytes(200, b"", extra=(("ETag", etag),))

    def complete_multipart(self, params, headers, body):
        upload_id = params.get("uploadId", [""])[0]
        upload = STORE.uploads.get(upload_id)
        if upload is None:
            self.send_error_xml(404, "NoSuchUpload",
                                "The multipart upload does not exist.")
            return
        try:
            document = ET.fromstring(body)
            requested = []
            for part in document.findall("Part"):
                requested.append((int(part.findtext("PartNumber")),
                                  part.findtext("ETag")))
        except (ET.ParseError, TypeError, ValueError):
            self.send_error_xml(400, "MalformedXML",
                                "The completion document is malformed.")
            return
        if not requested or requested != sorted(requested):
            self.send_error_xml(400, "InvalidPartOrder",
                                "Parts must be listed in ascending order.")
            return
        assembled = []
        for index, (number, etag) in enumerate(requested):
            stored = upload["parts"].get(number)
            if stored is None or stored[1] != etag:
                self.send_error_xml(400, "InvalidPart",
                                    "A completion part is missing or has a wrong ETag.")
                return
            if index + 1 < len(requested) and len(stored[0]) < 5 * 1024 * 1024:
                self.send_error_xml(400, "EntityTooSmall",
                                    "A non-final multipart part is too small.")
                return
            assembled.append(stored[0])

        data = b"".join(assembled)
        if "complete" in STORE.embedded_errors:
            STORE.embedded_errors.remove("complete")
            self.send_xml(200,
                "<Error><Code>InjectedCompleteError</Code>"
                "<Message>Embedded completion failure.</Message></Error>")
            return
        now = datetime.datetime.now(datetime.timezone.utc).timestamp()
        with STORE.write_lock:
            current = STORE.get(upload["bucket"], upload["key"])
            if headers.get("if-none-match", "").strip() == "*" and current is not None:
                self.send_error_xml(412, "PreconditionFailed", "The object already exists.")
                return
            match = headers.get("if-match")
            if match is not None and (current is None or match.strip() != '"%s"' % hashlib.sha256(current[0]).hexdigest()[:32]):
                self.send_error_xml(412, "PreconditionFailed", "The object has changed.")
                return
            STORE.put(upload["bucket"], upload["key"], data, now)
        STORE.object_headers["%s/%s" % (upload["bucket"], upload["key"])] = (
            upload.get("headers", {})
        )
        del STORE.uploads[upload_id]
        STORE.multipart_history.append({
            "action": "complete", "key": upload["key"],
            "size": len(data), "parts": len(requested),
            "upload_id": upload_id,
        })
        etag = '"%s-%d"' % (hashlib.sha256(data).hexdigest()[:32],
                             len(requested))
        self.send_xml(200,
                      '<?xml version="1.0" encoding="UTF-8"?>'
                      "<CompleteMultipartUploadResult>"
                      "<Bucket>%s</Bucket><Key>%s</Key><ETag>%s</ETag>"
                      "</CompleteMultipartUploadResult>" %
                      (xml_escape(upload["bucket"]),
                       xml_escape(upload["key"]), xml_escape(etag)))

    def abort_multipart(self, params):
        upload_id = params.get("uploadId", [""])[0]
        upload = STORE.uploads.pop(upload_id, None)
        if upload is None:
            self.send_error_xml(404, "NoSuchUpload",
                                "The multipart upload does not exist.")
            return
        STORE.multipart_history.append({
            "action": "abort", "key": upload["key"],
            "upload_id": upload_id,
        })
        self.send_bytes(204, b"")

    def delete_object(self, bucket, key, params):
        if bucket not in STORE.buckets:
            self.send_error_xml(404, "NoSuchBucket",
                                "The specified bucket does not exist.")
            return

        version_values = params.get("versionId")
        if version_values is not None:
            version_id = version_values[0]
            if not STORE.delete_version(bucket, key, version_id):
                self.send_error_xml(404, "NoSuchVersion",
                                    "The specified version does not exist.")
                return
            self.send_bytes(204, b"", extra=(("x-amz-version-id", version_id),))
            return

        epoch = datetime.datetime.now(datetime.timezone.utc).timestamp()
        version_id = STORE.delete(bucket, key, epoch=epoch)
        self.send_bytes(204, b"", extra=(("x-amz-delete-marker", "true"),
                                          ("x-amz-version-id", version_id)))


def main():
    port = int(os.environ.get("LSCP_TEST_PORT", "0"))
    cert = HERE / "fixtures" / "s3-server-cert.pem"
    key = HERE / "fixtures" / "s3-server-key.pem"
    if not cert.is_file() or not key.is_file():
        print("MISSING-FIXTURES %s" % (HERE / "fixtures"), flush=True)
        return 1
    httpd = ThreadingHTTPServer(("127.0.0.1", port), S3Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
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
