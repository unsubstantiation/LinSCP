"""Disposable FTP server for native service integration tests (test credentials only)."""
import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

root = os.environ["LSCP_TEST_ROOT"]
authorizer = DummyAuthorizer()
authorizer.add_user("testuser", "testpass", root, perm="elradfmwMT")
FTPHandler.authorizer = authorizer
server = FTPServer(("127.0.0.1", 0), FTPHandler)
print("READY %d" % server.socket.getsockname()[1], flush=True)
try:
    server.serve_forever()
finally:
    server.close_all()
