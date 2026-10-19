#!/usr/bin/env python3
"""Verified SSH jump-host regressions using disposable Paramiko endpoints.

The jump server deliberately has no shell or SFTP subsystem. Only it can
resolve destination.internal.invalid; a successful transfer proves the
client used direct-tcpip rather than falling back to a direct connection.
No credentials are supplied on a process command line.
"""
import base64
import hashlib
import importlib.util
import logging
import json
import os
import pathlib
import queue
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.request
import urllib.error

BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())
HERE = pathlib.Path(__file__).resolve().parent
if importlib.util.find_spec("paramiko"):
    import paramiko
else:
    paramiko = None


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def quote(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


class JumpEndpoint:
    """Loopback fixture with explicit forwarding policy and two distinct keys."""
    def __init__(self, destination_port):
        self.destination_port = destination_port
        self.key = paramiko.RSAKey.generate(2048)
        self.client_key = paramiko.RSAKey.generate(2048)
        self.password = 'jump secret with spaces'
        self.password_auth = True
        self.reject_forward = False
        self.relay_delay = 0
        self.stall_forward = False
        self.interrupt_after = 0
        self.interrupted = threading.Event()
        self.stop = threading.Event()
        self.changed = threading.Condition()
        self.auth_attempts = []
        self.forwards = []
        self.transports = []
        self.workers = []
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.worker = threading.Thread(target=self.accept, daemon=True)
        self.worker.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self.handle, args=(client,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def handle(self, client):
        endpoint = self
        targets = {}

        class Server(paramiko.ServerInterface):
            def check_auth_password(self, username, password):
                with endpoint.changed:
                    endpoint.auth_attempts.append((username, "password"))
                    endpoint.changed.notify_all()
                return (paramiko.AUTH_SUCCESSFUL if endpoint.password_auth and
                        username == "jump-user" and password == endpoint.password
                        else paramiko.AUTH_FAILED)

            def check_auth_publickey(self, username, key):
                return (paramiko.AUTH_SUCCESSFUL if username == "jump-user" and
                        key == endpoint.client_key else paramiko.AUTH_FAILED)

            def get_allowed_auths(self, username):
                return "password,publickey"

            def check_channel_direct_tcpip_request(self, chanid, origin, destination):
                with endpoint.changed:
                    endpoint.forwards.append(destination)
                    endpoint.changed.notify_all()
                if endpoint.stall_forward:
                    endpoint.stop.wait(10)
                    return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                host, port = destination
                if endpoint.reject_forward or port != endpoint.destination_port or host not in (
                        "destination.internal.invalid", "127.0.0.1"):
                    return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
                targets[chanid] = socket.create_connection(("127.0.0.1", port), timeout=5)
                return paramiko.OPEN_SUCCEEDED

        transport = paramiko.Transport(client)
        self.transports.append(transport)
        transport.add_server_key(self.key)
        try:
            transport.start_server(server=Server())
            channel = transport.accept(10)
            if channel is None:
                return
            target = targets[channel.get_id()]
            # A full-duplex relay with half-close support for channel EOF.
            readable = [channel, target]
            returned = 0
            while readable and transport.is_active() and not self.stop.is_set():
                ready, _, _ = select.select(readable, [], [], 0.2)
                for source in ready:
                    data = source.recv(32768)
                    sink = target if source is channel else channel
                    if not data:
                        readable.remove(source)
                        if sink is channel:
                            sink.shutdown_write()
                        else:
                            sink.shutdown(socket.SHUT_WR)
                        continue
                    if source is target:
                        returned += len(data)
                        if self.interrupt_after and returned > self.interrupt_after:
                            self.interrupted.set()
                            return
                    if self.relay_delay:
                        self.stop.wait(self.relay_delay)
                    sink.sendall(data)
        except (EOFError, OSError, paramiko.SSHException):
            pass  # Expected when the client refuses a key or cancels.
        finally:
            for target in targets.values():
                target.close()
            transport.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        self.worker.join(timeout=3)
        for transport in self.transports:
            transport.close()
        for worker in self.workers:
            worker.join(timeout=3)


class LiveTunnelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if paramiko is None:
            raise unittest.SkipTest("paramiko is not installed; SSH tunnel tests require it")
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="linscp-tunnel-")
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.remote = self.root / "remote"
        self.remote.mkdir()
        self.config = self.root / "config"
        self.config.mkdir()
        self.server = subprocess.Popen(
            [sys.executable, str(HERE / "TestSftpServer.py")],
            env=dict(os.environ, LSCP_TEST_PORT="0", LSCP_TEST_ROOT=str(self.remote)),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(self.stop_server)
        timer = threading.Timer(20, self.server.kill)
        timer.start()
        try:
            line = self.server.stdout.readline()
        finally:
            timer.cancel()
        self.assertTrue(line.startswith("READY "), line)
        self.port = int(line.split()[1])
        transport = paramiko.Transport(("127.0.0.1", self.port))
        try:
            transport.start_client(timeout=5)
            self.destination_key = fingerprint(transport.get_remote_server_key())
        finally:
            transport.close()
        self.jump = JumpEndpoint(self.port)
        self.addCleanup(self.jump.close)

    def stop_server(self):
        self.server.terminate()
        try:
            self.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.server.kill()
            self.server.wait(timeout=5)
        self.server.stdout.close()

    def env(self):
        return dict(os.environ, LINSCP_CONFIG_DIR=str(self.config), SSH_AUTH_SOCK="")

    def settings(self, overrides=None):
        values = dict(Tunnel="1", TunnelHostName="127.0.0.1",
                      TunnelPortNumber=self.jump.port, TunnelUserName="jump-user",
                      TunnelPassword=self.jump.password, TunnelHostKey=fingerprint(self.jump.key))
        values.update(overrides or {})
        return " -rawsettings " + " ".join(name + "=" + quote(value) for name, value in values.items())

    def opening(self, overrides=None, host="destination.internal.invalid", protocol="sftp", pin=None):
        path = str(self.remote) + "/" if protocol == "scp" else "/"
        return ("open %s://testuser@%s:%d%s -password=testpass -hostkey=%s%s" %
                (protocol, host, self.port, path, quote(pin or self.destination_key), self.settings(overrides)))

    def run_script(self, commands, extra_args=(), timeout=30):
        return subprocess.run([BINARY, "-batch", "-script=/dev/stdin", *extra_args],
                              input="option confirm off\n" + commands + "\nexit\n",
                              capture_output=True, text=True, timeout=timeout, env=self.env())

    def test_sftp_transfer_and_exec_use_verified_jump(self):
        payload = os.urandom(2 * 1024 * 1024 + 173)
        source = self.root / "upload file.bin"
        target = self.root / "download file.bin"
        source.write_bytes(payload)
        result = self.run_script(self.opening() + "\nput %s /payload.bin\nget /payload.bin %s\ncall printf tunnel-exec\nstat /payload.bin" %
                                 (quote(source), quote(target)), timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.remote / "payload.bin").read_bytes(), payload)
        self.assertEqual(target.read_bytes(), payload)
        self.assertIn("tunnel-exec", result.stdout)
        self.assertGreaterEqual(len(self.jump.forwards), 2)  # SFTP + one-shot exec.
        self.assertTrue(all(host == "destination.internal.invalid" for host, _ in self.jump.forwards))
        failed = self.run_script(self.opening() + "\ncall exit 7\nmkdir forbidden")
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("return code 7", failed.stderr)
        self.assertFalse((self.remote / "forbidden").exists())

    def test_tunnel_local_port_number_binds_and_fails_when_taken(self):
        """TunnelLocalPortNumber binds that loopback port for the
        session's own connection (so a firewall rule can name it), and
        a port already in use refuses the open instead of sharing."""
        import socket as _socket
        probe = _socket.socket()
        probe.bind(("127.0.0.1", 0))
        chosen = probe.getsockname()[1]
        probe.close()
        payload = os.urandom(65537)
        source = self.root / "port-upload.bin"
        source.write_bytes(payload)
        result = self.run_script(
            self.opening({"TunnelLocalPortNumber": str(chosen)}) +
            "\nput %s /port-payload.bin" % quote(source), timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.remote / "port-payload.bin").read_bytes(),
                         payload)

        holder = _socket.socket()
        holder.bind(("127.0.0.1", chosen))
        holder.listen(1)
        try:
            result = self.run_script(
                self.opening({"TunnelLocalPortNumber": str(chosen)}) +
                "\nmkdir forbidden")
        finally:
            holder.close()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tunnel local port", result.stderr)
        self.assertFalse((self.remote / "forbidden").exists())

    def test_scp_uses_the_same_tunnel_transport(self):
        if not shutil.which("scp"):
            self.skipTest("the SCP fixture needs the OpenSSH scp program")
        source = self.root / "upload.bin"
        source.write_bytes(os.urandom(125000))
        target = self.root / "download.bin"
        result = self.run_script(self.opening(protocol="scp") + "\nput %s upload.bin\nget upload.bin %s" %
                                 (quote(source), quote(target)), timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(source.read_bytes(), target.read_bytes())
        self.assertGreater(len(self.jump.forwards), 1)

    def test_encrypted_private_key_authentication_on_jump(self):
        self.jump.password_auth = False
        keyfile = self.root / "jump-private-key.pem"
        self.jump.client_key.write_private_key_file(str(keyfile), password="key passphrase")
        result = self.run_script(self.opening({"TunnelPassword": "", "TunnelPublicKeyFile": str(keyfile),
                                               "TunnelPassphrase": "key passphrase"}) + "\npwd")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.jump.auth_attempts, "password should not be attempted after key success")

    def test_jump_key_refused_before_authentication_or_forwarding(self):
        for pin in ("SHA256:wrong", ""):
            with self.subTest(pin=pin):
                result = self.run_script(self.opening({"TunnelHostKey": pin}, host="127.0.0.1") + "\nmkdir forbidden")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("TUNNELHOSTKEY ", result.stdout + result.stderr)
                if pin:
                    self.assertIn("HOSTKEYSTATE tunnel changed", result.stdout)
                self.assertNotIn("\nHOSTKEY ", result.stdout + result.stderr)
                self.assertFalse(self.jump.auth_attempts)
                self.assertFalse(self.jump.forwards)
                self.assertFalse((self.remote / "forbidden").exists())

    def test_destination_key_is_checked_independently(self):
        result = self.run_script(self.opening(pin="SHA256:wrong") + "\nmkdir forbidden")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HOSTKEY ", result.stdout + result.stderr)
        self.assertIn("HOSTKEYSTATE destination changed", result.stdout)
        self.assertTrue(self.jump.forwards)
        self.assertFalse((self.remote / "forbidden").exists())

    def test_authentication_and_forward_refusals_never_connect_directly(self):
        result = self.run_script(self.opening({"TunnelPassword": "wrong"}, host="127.0.0.1") + "\nmkdir forbidden")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SSH tunnel", result.stderr)
        self.assertFalse(self.jump.forwards)
        self.jump.reject_forward = True
        result = self.run_script(self.opening(host="127.0.0.1") + "\nmkdir forbidden")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SSH tunnel forwarding", result.stderr)
        self.assertFalse((self.remote / "forbidden").exists())

    def test_jump_disconnect_fails_transfer_without_publishing_partial_file(self):
        (self.remote / "large.bin").write_bytes(os.urandom(2 * 1024 * 1024))
        self.jump.interrupt_after = 256 * 1024
        target = self.root / "download.bin"
        result = self.run_script(self.opening() + "\nget /large.bin " + quote(target))
        self.assertTrue(self.jump.interrupted.is_set(), result.stdout + result.stderr)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(target.exists(), "an incomplete download must not be published")

    def test_backpressure_preserves_upload_and_download_bytes(self):
        self.jump.relay_delay = 0.004
        payload = os.urandom(4 * 1024 * 1024)
        source, downloaded = self.root / "source.bin", self.root / "downloaded.bin"
        source.write_bytes(payload)
        result = self.run_script(self.opening() + "\nput " + quote(source) +
                                 " /slow.bin\nget /slow.bin " + quote(downloaded), timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.remote / "slow.bin").read_bytes(), payload)
        self.assertEqual(downloaded.read_bytes(), payload)

    def test_forwarding_timeout_never_falls_back_to_a_direct_connection(self):
        self.jump.stall_forward = True
        started = time.monotonic()
        result = self.run_script(self.opening(host="127.0.0.1") + "\nmkdir forbidden",
                                 extra_args=["-timeout=1"], timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - started, 8)
        self.assertIn("SSH tunnel", result.stderr)
        self.assertFalse((self.remote / "forbidden").exists())

    def test_cancelling_a_tunneled_transfer_closes_the_jump_and_keeps_staging(self):
        self.jump.relay_delay = 0.03
        (self.remote / "large.bin").write_bytes(os.urandom(8 * 1024 * 1024))
        target = self.root / "cancelled.bin"
        part = self.root / "cancelled.bin.filepart"
        process = subprocess.Popen([BINARY, "-batch", "-script=/dev/stdin"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=self.env())
        try:
            process.stdin.write(self.opening() + "\nget /large.bin " + quote(target) + "\nexit\n")
            process.stdin.flush()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process.poll() is None:
                if part.exists() and part.stat().st_size > 0:
                    break
                time.sleep(0.02)
            self.assertTrue(part.exists() and part.stat().st_size > 0)
            process.terminate()  # The GUI queue's process-cancellation boundary.
            process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0)
            self.assertFalse(target.exists())
            self.assertGreater(part.stat().st_size, 0)
            deadline = time.monotonic() + 5
            while any(t.is_active() for t in self.jump.transports) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(any(t.is_active() for t in self.jump.transports))
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)

    def test_repeated_close_and_failed_open_release_threads_and_sockets(self):
        process = subprocess.Popen([BINARY, "-server", "-batch"], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   text=True, env=self.env())
        lines = queue.Queue()
        def read():
            for line in process.stdout:
                lines.put(line.rstrip())
            lines.put(None)
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        def command(text):
            process.stdin.write(text + "\n")
            process.stdin.flush()
            while True:
                line = lines.get(timeout=20)
                self.assertIsNotNone(line, "core exited before answering")
                if line.startswith("LSCP-RESULT "):
                    return int(line.split()[1])
        try:
            self.assertTrue(lines.get(timeout=10).startswith("LSCP-SERVER "))
            descriptors = lambda: len(list(pathlib.Path("/proc/%d/fd" % process.pid).iterdir()))
            threads = lambda: len(list(pathlib.Path("/proc/%d/task" % process.pid).iterdir()))
            base_fds, base_threads = descriptors(), threads()
            for _ in range(5):
                self.assertEqual(command(self.opening()), 0)
                self.assertGreater(threads(), base_threads)
                self.assertEqual(command("close"), 0)
                self.assertEqual(threads(), base_threads)
                self.assertEqual(descriptors(), base_fds)
                self.assertNotEqual(command(self.opening(pin="SHA256:wrong")), 0)
                self.assertEqual(threads(), base_threads)
                self.assertEqual(descriptors(), base_fds)
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=5)
            process.stdout.close()

    def test_stored_tunnel_credentials_are_encrypted_and_reusable(self):
        command = ("savesession jump-site -host=destination.internal.invalid -port=%d "
                   "-username=testuser -password=testpass -hostkey=%s%s\nopen jump-site\npwd" %
                   (self.port, quote(self.destination_key), self.settings()))
        result = self.run_script(command)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        ini = (self.config / "sessions.ini").read_text()
        self.assertIn("tunnel_password=lscp1$", ini)
        self.assertNotIn(self.jump.password, ini)
        result = self.run_script("open jump-site\npwd")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_proxy_settings_reach_the_jump_host_not_the_destination(self):
        sys.path.insert(0, str(HERE))
        from TestProxyServer import ProxyServer
        proxy = ProxyServer(kind="socks5", credentials="proxy-user:proxy-pass")
        reports = []
        changed = threading.Condition()
        def report(line):
            with changed:
                reports.append(line)
                changed.notify_all()
        proxy.report = report
        proxy.start()
        try:
            result = self.run_script(self.opening({
                "ProxyMethod": "SOCKS5", "ProxyHost": "127.0.0.1", "ProxyPort": proxy.port,
                "ProxyUsername": "proxy-user", "ProxyPassword": "proxy-pass", "ProxyLocalhost": "1"}) + "\npwd")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            with changed:
                self.assertTrue(changed.wait_for(lambda: any(line.startswith("CONNECT ") for line in reports), timeout=5))
            self.assertIn("CONNECT 127.0.0.1:%d" % self.jump.port, reports)
            self.assertFalse(any("destination.internal.invalid" in line for line in reports), reports)
            self.assertTrue(self.jump.forwards)
        finally:
            proxy.close()

    def gui_session(self):
        return dict(protocol="sftp", host="destination.internal.invalid", port=self.port,
                    username="testuser", password="testpass", hostkey=self.destination_key,
                    tunnel=True, tunnel_host="127.0.0.1", tunnel_port=self.jump.port,
                    tunnel_username="jump-user", tunnel_password=self.jump.password,
                    tunnel_hostkey=fingerprint(self.jump.key))

    def test_global_tunnel_defaults_reach_the_embedded_shell(self):
        sys.path.insert(0, str(HERE.parents[1] / "gui"))
        import linscp_gui as gui
        session = self.gui_session()
        with mock.patch.object(gui, "find_linscp_binary", return_value=BINARY), \
                mock.patch.dict(os.environ, self.env()):
            args = gui.core_command_line(session) + ["-shell", gui.session_url(session)]
            env = gui.popen_kwargs(session=session, password=session["password"])["env"]
            self.assertNotIn(self.jump.password, " ".join(args))
            for _ in range(5):
                result = subprocess.run(args, env=env, input="pwd\nexit\n", capture_output=True,
                                        text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("TEST-SHELL>", result.stdout)
        self.assertIn(str(self.remote), result.stdout)
        self.assertTrue(self.jump.forwards)

    def test_shell_output_and_nonzero_status_survive_immediate_server_close(self):
        sys.path.insert(0, str(HERE.parents[1] / "gui"))
        import linscp_gui as gui
        with mock.patch.object(gui, "find_linscp_binary", return_value=BINARY), \
                mock.patch.dict(os.environ, self.env()):
            for tunneled in (False, True):
                session = self.gui_session()
                if not tunneled:
                    session.update(host="127.0.0.1", tunnel=False)
                args = gui.core_command_line(session) + ["-shell", gui.session_url(session)]
                env = gui.popen_kwargs(session=session, password=session["password"])["env"]
                for status in (0, 7) * 5:
                    with self.subTest(tunneled=tunneled, status=status):
                        result = subprocess.run(args, env=env, input="burst\nexit %d\n" % status,
                                                capture_output=True, text=True, timeout=20)
                        self.assertEqual(result.returncode, status, result.stderr)
                        self.assertEqual(result.stdout.count("x"), 256 * 1024)
                        self.assertEqual(result.stdout.count("y"), 128 * 1024)

    def test_shell_status_without_end_of_output_is_not_success(self):
        sys.path.insert(0, str(HERE.parents[1] / "gui"))
        import linscp_gui as gui
        with mock.patch.object(gui, "find_linscp_binary", return_value=BINARY), \
                mock.patch.dict(os.environ, self.env()):
            for tunneled in (False, True):
                session = self.gui_session()
                if not tunneled:
                    session.update(host="127.0.0.1", tunnel=False)
                args = gui.core_command_line(session) + ["-shell", gui.session_url(session)]
                env = gui.popen_kwargs(session=session, password=session["password"])["env"]
                result = subprocess.run(args, env=env, input="truncated-status\n",
                                        capture_output=True, text=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)

    def test_gui_verifies_both_hops_and_queued_commands_keep_the_tunnel(self):
        self._exercise_gui_key_choices(False, False)

    def test_gui_remember_choices_are_independent_and_do_not_store_credentials(self):
        for jump, destination in ((True, False), (False, True), (True, True)):
            with self.subTest(jump=jump, destination=destination):
                self._exercise_gui_key_choices(jump, destination)

    def _exercise_gui_key_choices(self, remember_jump, remember_destination):
        sys.path.insert(0, str(HERE.parents[1] / "gui"))
        import linscp_gui as gui
        session = dict(self.gui_session(), hostkey="", tunnel_hostkey="")
        state = dict(logs=[], tabs=[], active_tab=None, tasks=[], paused=False,
                     next_tab=1, next_task=1, challenges={})
        with mock.patch.object(gui, "find_linscp_binary", return_value=BINARY), \
                mock.patch.object(gui, "STATE", state), \
                mock.patch.object(gui, "API_TOKEN", "tunnel-test-token"), \
                mock.patch.object(gui, "ACCOUNTS_FILE", None), \
                mock.patch.dict(os.environ, self.env()):
            httpd = gui.ThreadingHTTPServer(("127.0.0.1", 0), gui.LinScpGuiHandler)
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()

            def api(path, body=None):
                request = urllib.request.Request(
                    "http://127.0.0.1:%d%s" % (httpd.server_address[1], path),
                    data=json.dumps(body).encode() if body is not None else None,
                    headers={"X-LSCP-Token": "tunnel-test-token", "Content-Type": "application/json"})
                try:
                    response = urllib.request.urlopen(request, timeout=20)
                except urllib.error.HTTPError as exc:
                    response = exc
                with response:
                    return response.status, json.load(response)

            try:
                auth_attempts_before = len(self.jump.auth_attempts)
                name = "remember-%d-%d" % (remember_jump, remember_destination)
                status, data = api("/api/tabs/open", {"session": session, "name": name})
                self.assertEqual(status, 400, data)
                challenge = data["challenge"]
                self.assertEqual(challenge["role"], "tunnel")
                self.assertEqual(challenge["host"], "127.0.0.1")
                self.assertEqual(len(self.jump.auth_attempts), auth_attempts_before)
                # A stale challenge cannot pin the jump key onto the destination.
                status, _ = api("/api/tabs/verify", dict(challenge, role="destination"))
                self.assertEqual(status, 409)
                status, _ = api("/api/tabs/verify", dict(challenge, fingerprint="SHA256:stale"))
                self.assertEqual(status, 409)
                self.assertFalse(challenge["changed"])
                status, data = api("/api/tabs/verify", dict(challenge, remember=remember_jump))
                self.assertEqual(status, 400, data)
                if remember_jump:
                    saved = next(s for s in gui.read_stored_sessions() if s["name"] == name)
                    self.assertEqual(saved["tunnel_hostkey"], fingerprint(self.jump.key))
                    self.assertEqual(saved["hostkey"], "")
                challenge = data["challenge"]
                self.assertEqual(challenge["role"], "destination")
                self.assertEqual(challenge["host"], "destination.internal.invalid")
                status, data = api("/api/tabs/verify", dict(challenge, remember=remember_destination))
                self.assertEqual(status, 200, data)
                self.assertTrue(data["success"])
                tab = state["tabs"][0]
                self.assertEqual(tab.session["hostkey"], self.destination_key)
                self.assertEqual(tab.session["tunnel_hostkey"], fingerprint(self.jump.key))
                if remember_jump or remember_destination:
                    saved = next(s for s in gui.read_stored_sessions() if s["name"] == name)
                    self.assertEqual(saved["hostkey"], self.destination_key if remember_destination else "")
                    self.assertEqual(saved.get("tunnel_hostkey", ""), fingerprint(self.jump.key) if remember_jump else "")
                    self.assertEqual(saved.get("password", ""), "")
                    self.assertEqual(saved.get("tunnel_password", ""), "")
                    self.assertEqual(saved.get("tunnel_passphrase", ""), "")
                self.assertFalse((self.config / "sshhostkeys").exists(), "tab-only pins must not enter the global cache")
                _, data = api("/api/status")
                for description in (data["session"], data["tabs"][0]["session"]):
                    self.assertNotIn("tunnel_password", description)
                    self.assertNotIn("tunnel_passphrase", description)
                code, stdout, stderr = gui.run_linscp(
                    "open " + gui.quote_remote(gui.session_url(tab.session)) + "; mkdir /queued", tab.session)
                self.assertEqual(code, 0, stdout + stderr)
                self.assertTrue((self.remote / "queued").is_dir())
                (self.remote / "queued").rmdir()
                self.assertNotIn(self.jump.password, json.dumps(state["logs"]))
                self.assertEqual(api("/api/tabs/close", {"tab": tab.id})[0], 200)
            finally:
                for tab in state["tabs"] + list(state["challenges"].values()):
                    tab.terminate()
                httpd.shutdown()
                httpd.server_close()
                worker.join(timeout=5)


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(LiveTunnelTests))
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=live-tunnel platform=linux ran=%d skipped=%d failed=%d" %
          (result.testsRun, len(result.skipped), failed))
    sys.exit(0 if result.wasSuccessful() else 1)
