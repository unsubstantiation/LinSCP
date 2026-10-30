"""Disposable FTP server for native service integration tests (test credentials only)."""
import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler, ThrottledDTPHandler
from pyftpdlib.servers import FTPServer

root = os.environ["LSCP_TEST_ROOT"]
authorizer = DummyAuthorizer()
authorizer.add_user("testuser", "testpass", root, perm="elradfmwMT")
if os.environ.get("LSCP_TEST_FTP_TLS") == "1":
    handler = TLS_FTPHandler
    fixtures = os.path.join(os.path.dirname(__file__), "fixtures")
    handler.certfile = os.path.join(fixtures, "s3-server-cert.pem")
    handler.keyfile = os.path.join(fixtures, "s3-server-key.pem")
    handler.tls_control_required = True
    handler.tls_data_required = True
else:
    handler = FTPHandler
if os.environ.get("LSCP_TEST_FTP_THROTTLE") == "1":
    class SlowDTPHandler(ThrottledDTPHandler):
        write_limit = 256 * 1024
    handler.dtp_handler = SlowDTPHandler
handler.authorizer = authorizer
server = FTPServer(("127.0.0.1", 0), handler)
print("READY %d" % server.socket.getsockname()[1], flush=True)
try:
    server.serve_forever()
finally:
    server.close_all()
