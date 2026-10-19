#!/usr/bin/env python3
"""A throwaway SFTP + exec server for exercising linscp live.

Runs one SSH server on 127.0.0.1:12765, user 'testuser', password 'testpass'.
The SFTP "home" is ROOT (the server process chdir()s there, so relative paths
resolve inside it and canonicalize() makes them absolute). Channel exec
requests run locally (sandbox only) so 'call' works.
"""
import hashlib
import os
import socket
import stat
import subprocess
import sys
import threading

import paramiko
from paramiko.message import Message
from paramiko.sftp import (CMD_EXTENDED, CMD_EXTENDED_REPLY, SFTP_BAD_MESSAGE,
                           SFTP_NO_SUCH_FILE, SFTP_OK, SFTP_OP_UNSUPPORTED)
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle
from paramiko.sftp_server import SFTPServer

HOST = "127.0.0.1"
# A test runner that does not want to collide with another one, or that
# wants its own jail, sets these; port 0 asks the kernel for a free one.
PORT = int(os.environ.get("LSCP_TEST_PORT", "12765"))
USER, PASSWORD = "testuser", "testpass"
ROOT = os.environ.get("LSCP_TEST_ROOT", "/tmp/lscp-sftp-root")
COPY_DATA = os.environ.get("LSCP_TEST_COPY_DATA") == "1"
CHECK_FILE_NAME = os.environ.get("LSCP_TEST_CHECK_FILE_NAME") == "1"

HOST_KEY = paramiko.RSAKey.generate(2048)


def _err(exc_info=None):
    _, e, _ = exc_info or sys.exc_info()
    return paramiko.SFTPServer.convert_errno(e.errno)


class SftpSI(paramiko.SFTPServerInterface):
    """Filesystem-backed SFTP backend with ROOT as the visible '/'."""

    def _map(self, path):
        if path.startswith("/"):
            return ROOT + path
        return path  # relative: resolved against the server cwd (ROOT)

    def canonicalize(self, path):
        real = os.path.realpath(self._map(path))
        if real == ROOT:
            return "/"
        if real.startswith(ROOT + "/"):
            return real[len(ROOT):]
        return "/"  # outside the jail

    def list_folder(self, path):
        try:
            out = []
            for fname in os.listdir(self._map(path)):
                # lstat, as a real sftp-server uses: stat() follows the link
                # and raises for one whose target is missing, which failed
                # the whole listing instead of reporting the link. A
                # directory that cannot be listed because of one broken
                # link is not something a client test should hide.
                attr = SFTPAttributes.from_stat(
                    os.lstat(os.path.join(self._map(path), fname)))
                attr.filename = fname
                out.append(attr)
            return out
        except OSError:
            return _err()

    def stat(self, path):
        try:
            return SFTPAttributes.from_stat(os.stat(self._map(path)))
        except OSError:
            return _err()

    def lstat(self, path):
        try:
            return SFTPAttributes.from_stat(os.lstat(self._map(path)))
        except OSError:
            return _err()

    def open(self, path, flags, attr):
        try:
            fd = os.open(self._map(path), flags)
        except OSError:
            return _err()
        if attr and getattr(attr, "st_mode", None) is not None:
            try:
                os.fchmod(fd, attr.st_mode)
            except OSError:
                pass
        handle = SFTPHandle(fd)
        mode = "r+b"  # both directions; SFTP handles manage offsets
        try:
            handle.readfile = handle.writefile = os.fdopen(fd, mode, 0)
        except OSError:
            return _err()
        return handle

    def remove(self, path):
        try:
            os.remove(self._map(path))
            return paramiko.SFTP_OK
        except OSError:
            return _err()

    def rename(self, oldpath, newpath):
        try:
            os.rename(self._map(oldpath), self._map(newpath))
            return paramiko.SFTP_OK
        except OSError:
            return _err()

    def posix_rename(self, oldpath, newpath):
        return self.rename(oldpath, newpath)

    def mkdir(self, path, attr):
        try:
            os.mkdir(self._map(path))
            if attr and getattr(attr, "st_mode", None) is not None:
                os.chmod(self._map(path), attr.st_mode)
            return paramiko.SFTP_OK
        except OSError:
            return _err()

    def rmdir(self, path):
        try:
            os.rmdir(self._map(path))
            return paramiko.SFTP_OK
        except OSError:
            return _err()

    def symlink(self, target_path, path):
        try:
            os.symlink(self._map(target_path), self._map(path))
            return paramiko.SFTP_OK
        except OSError:
            return _err()

    def readlink(self, path):
        try:
            return os.readlink(self._map(path))
        except OSError:
            return _err()

    def chattr(self, path, attr):
        # paramiko routes SSH_FXP_SETSTAT here (older releases called it
        # 'setstat', which is why the alias below exists).
        try:
            mpath = self._map(path)
            if getattr(attr, "st_mode", None) is not None:
                os.chmod(mpath, attr.st_mode)
            if getattr(attr, "st_size", None) is not None:
                with open(mpath, "r+") as f:
                    f.truncate(attr.st_size)
            times = None
            a = getattr(attr, "st_atime", None)
            m = getattr(attr, "st_mtime", None)
            if a is not None or m is not None:
                st = os.stat(mpath)
                times = (a or st.st_atime, m or st.st_mtime)
            if times:
                os.utime(mpath, times)
            return paramiko.SFTP_OK
        except OSError:
            return _err()

    setstat = chattr  # older paramiko releases


class CopyDataSFTPServer(SFTPServer):
    """Test-only implementation of OpenSSH's copy-data extension."""

    def _process(self, request_type, request_number, message):
        if request_type != CMD_EXTENDED:
            return super()._process(request_type, request_number, message)

        extension = message.get_text()
        if extension == "check-file-name" and CHECK_FILE_NAME:
            path = message.get_text()
            algorithm = message.get_text()
            offset = message.get_int64()
            length = message.get_int64()
            block_size = message.get_int()
            self._check_file_name(request_number, path, algorithm, offset,
                                  length, block_size)
            return

        if extension == "copy-data":
            source_handle = message.get_binary()
            source_offset = message.get_int64()
            length = message.get_int64()
            target_handle = message.get_binary()
            target_offset = message.get_int64()
            source = self.file_table.get(source_handle)
            target = self.file_table.get(target_handle)
            if source is None or target is None:
                self._send_status(request_number, SFTP_BAD_MESSAGE,
                                  "Invalid copy-data handle")
                return

            copied = 0
            while length == 0 or copied < length:
                amount = 65536 if length == 0 else min(65536, length - copied)
                data = source.read(source_offset + copied, amount)
                if isinstance(data, int):
                    self._send_status(request_number, data)
                    return
                if not data:
                    break
                status = target.write(target_offset + copied, data)
                if status != SFTP_OK:
                    self._send_status(request_number, status)
                    return
                copied += len(data)
            self._send_status(request_number, SFTP_OK)
            return

        # Preserve Paramiko's existing extension support when intercepting
        # CMD_EXTENDED so this test server still handles check-file and
        # posix-rename requests as before.
        if extension == "check-file":
            self._check_file(request_number, message)
        elif extension == "posix-rename@openssh.com":
            oldpath = message.get_text()
            newpath = message.get_text()
            self._send_status(request_number,
                              self.server.posix_rename(oldpath, newpath))
        else:
            self._send_status(request_number, SFTP_OP_UNSUPPORTED)

    def _check_file_name(self, request_number, path, algorithm, offset,
                         length, block_size):
        """Implement the SFTP check-file-name extension for tests."""
        algorithms = {"sha-256": "sha256", "sha-1": "sha1", "md5": "md5"}
        digest_name = algorithms.get(algorithm.lower())
        if digest_name is None or block_size != 0 or offset < 0 or length < 0:
            self._send_status(request_number, SFTP_OP_UNSUPPORTED)
            return
        try:
            filename = os.path.realpath(self.server._map(path))
            root = os.path.realpath(ROOT)
            if os.path.commonpath((root, filename)) != root:
                self._send_status(request_number, SFTP_OP_UNSUPPORTED)
                return
            with open(filename, "rb") as source:
                source.seek(offset)
                data = source.read() if length == 0 else source.read(length)
        except FileNotFoundError:
            self._send_status(request_number, SFTP_NO_SUCH_FILE)
            return
        except (OSError, ValueError):
            self._send_status(request_number, SFTP_BAD_MESSAGE)
            return

        response = Message()
        response.add_int(request_number)
        response.add_string(algorithm)
        response.add_int(0)
        response.add_string(hashlib.new(digest_name, data).digest())
        self._send_packet(CMD_EXTENDED_REPLY, response)


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.exec_threads = []
        self.shell_threads = []

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username == USER and password == PASSWORD) else paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        if username != USER:
            return paramiko.AUTH_FAILED
        auth_file = os.path.join(ROOT, ".ssh", "authorized_keys")
        try:
            with open(auth_file, "r", encoding="utf-8") as handle:
                for line in handle:
                    parts = line.strip().split()
                    if (len(parts) >= 2 and parts[0] == key.get_name() and
                            parts[1] == key.get_base64()):
                        return paramiko.AUTH_SUCCESSFUL
        except OSError:
            pass
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        def run():
            proc = subprocess.run(command, shell=True, capture_output=True,
                                  cwd=ROOT)
            if proc.stdout:
                channel.sendall(proc.stdout)
            if proc.stderr:
                channel.sendall_stderr(proc.stderr)
            channel.send_exit_status(proc.returncode)
            channel.close()
        thread = threading.Thread(target=run, daemon=True)
        self.exec_threads.append(thread)
        thread.start()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        def run_shell():
            try:
                channel.sendall(b"TEST-SHELL> ")
                pending = bytearray()
                while True:
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    pending.extend(chunk)
                    while b"\n" in pending:
                        line, _, rest = pending.partition(b"\n")
                        pending = bytearray(rest)
                        command = line.rstrip(b"\r").decode("utf-8", "replace")
                        if command == "pwd":
                            response = os.getcwd().encode("utf-8") + b"\r\n"
                        elif command == "exit":
                            channel.send_exit_status(0)
                            channel.close()
                            return
                        else:
                            response = ("unknown command: " + command).encode() + b"\r\n"
                        channel.sendall(response + b"TEST-SHELL> ")
            except (EOFError, OSError):
                pass
        thread = threading.Thread(target=run_shell, daemon=True)
        self.shell_threads.append(thread)
        thread.start()
        return True
    # No subsystem override: paramiko's default starts the handler that
    # was registered with Transport.set_subsystem_handler.


def handle(client):
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    handler = (CopyDataSFTPServer if COPY_DATA or CHECK_FILE_NAME
               else paramiko.SFTPServer)
    transport.set_subsystem_handler("sftp", handler, SftpSI)
    server = Server()
    try:
        transport.start_server(server=server)
        channel = transport.accept(60)
        if channel is not None:
            while not channel.closed and transport.is_active():
                channel.status_event.wait(0.05)
            for thread in server.exec_threads:
                thread.join(timeout=10)
    except Exception as exc:  # noqa
        print("server error:", exc, file=sys.stderr)
    finally:
        transport.close()


def main():
    os.makedirs(ROOT, exist_ok=True)
    os.chdir(ROOT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(16)
    # The port, because 'LSCP_TEST_PORT=0' means the kernel picked it, and a
    # runner has to learn which one it was.
    print("READY %d" % sock.getsockname()[1], flush=True)
    while True:
        client, _ = sock.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
