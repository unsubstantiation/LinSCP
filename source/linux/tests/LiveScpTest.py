"""Live tests for the native SCP engine (source/linux/ScpClient.cpp).

SCP is not a filesystem protocol: it is a login shell plus the rcp transfer
protocol that runs on it. So a listing here is an 'ls -l -a' the client parses,
a stat is an 'ls -l -d', a delete is an 'rm', a server-side copy is a 'cp -p',
and the bytes of a transfer go through 'scp -f'/'scp -t' over an SSH channel
whose wire protocol the client speaks itself. None of that can be checked
against a fake: this suite starts a throwaway OpenSSH daemon per test, on a
port the kernel picks, with keys it generated for the test, and drives the
client against it.

What the suite pins down:

  * the host key is checked by this client's own SSH code, in every spelling a
    pin arrives in - the engine is not curl, so nothing depends on which SSH
    library the installed curl linked;
  * listings, stat, 'cd' resolution, mkdir/rmdir/rm/mv/chmod/cp/ln, times and
    permissions reach the server and come back as the server reports them;
  * downloads and uploads carry the bytes intact, through names with spaces,
    for empty files, recursively, at a limited speed, with progress reported,
    and with an ASCII transfer converting line endings;
  * a refusal is a refusal: the server's own words are what the user sees, and
    an operation the protocol cannot do (continuing a partial transfer) is
    refused before any byte moves.

sshd and ssh-keygen are the only requirements, and both are optional: without
them the module skips loudly, per test, rather than turning an empty run into a
passing claim.

Evidence convention:

    evidence: suite=live-scp platform=linux ran=N skipped=N failed=N
"""

import base64
import hashlib
import os
import pathlib
import pty
import pwd
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())
SUITE_NAME = "live-scp"
HERE = pathlib.Path(__file__).resolve().parent

DEPENDENCY_ERROR = ""

# Prefix for a client that has to be interruptible: it restores the default
# SIGINT action and execs the real command, so the process the test signals is
# the client itself. A child inherits the dispositions of whatever started this
# suite, and a runner that ignores SIGINT would otherwise leave the client
# unstoppable. Written as a wrapper rather than preexec_fn because this process
# has threads.
RESET_SIGINT = [sys.executable, "-c",
                "import os, signal, sys\n"
                "signal.signal(signal.SIGINT, signal.SIG_DFL)\n"
                "os.execv(sys.argv[1], sys.argv[1:])"]


def find_executable(*names):
    """The first of 'names' that can be run, or None."""
    for name in names:
        found = shutil.which(name)
        if found is not None:
            return found
        for candidate in ("/usr/sbin/" + name, "/usr/bin/" + name):
            if os.access(candidate, os.X_OK):
                return candidate
    return None


SSHD = find_executable("sshd")
KEYGEN = find_executable("ssh-keygen")
SCP = find_executable("scp")

if SSHD is None:
    DEPENDENCY_ERROR = "sshd is not installed"
elif KEYGEN is None:
    DEPENDENCY_ERROR = "ssh-keygen is not installed"
elif SCP is None:
    # The server runs 'scp -f'/'scp -t' for a transfer; without that binary
    # only the shell half of the protocol could be exercised, and a suite
    # that silently ran half of the engine would claim more than it checked.
    DEPENDENCY_ERROR = "the server has no scp binary to run"


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_for_port(port, process):
    deadline = time.time() + 20
    while time.time() < deadline:
        if process.poll() is not None:
            detail = process.stderr.read() if process.stderr is not None else ""
            raise RuntimeError("sshd exited before listening: " + detail)
        sock = socket.socket()
        sock.settimeout(0.2)
        try:
            sock.connect(("127.0.0.1", port))
            sock.close()
            return
        except OSError:
            sock.close()
            time.sleep(0.05)
    raise RuntimeError("sshd did not listen on port %d" % port)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 16), b""):
            digest.update(block)
    return digest.hexdigest()


def write_random(path, size):
    """A file of 'size' bytes the transfer has to carry intact."""
    with open(path, "wb") as handle:
        block = os.urandom(1 << 16)
        written = 0
        while written < size:
            chunk = block[:size - written]
            handle.write(chunk)
            written += len(chunk)
    return path


class ProxyLines(list):
    """Reports are emitted by the proxy and read on a different thread.

    Waiting on the condition is deterministic: the client may return before
    the reader has drained a CONNECT line, especially on a loaded CI host.
    """

    def __init__(self):
        super().__init__()
        self.updated = threading.Condition()

    def report(self, text):
        with self.updated:
            self.append(text)
            self.updated.notify_all()

    def contains(self, predicate, timeout=5.0):
        deadline = time.time() + timeout
        while True:
            with self.updated:
                if any(predicate(line) for line in self):
                    return True
                if time.time() >= deadline:
                    return False
                self.updated.wait(deadline - time.time())


class LiveScpTests(unittest.TestCase):
    def setUp(self):
        if DEPENDENCY_ERROR:
            self.skipTest(DEPENDENCY_ERROR +
                          "; live SCP coverage needs a throwaway sshd")
        self.workdir = tempfile.TemporaryDirectory(prefix="live-scp-")
        self.addCleanup(self.workdir.cleanup)
        base = pathlib.Path(self.workdir.name)
        self.root = base / "remote"
        self.root.mkdir()
        self.local = base / "local"
        self.local.mkdir()
        self.config = base / "config"
        self.config.mkdir()
        self.proxies = []
        self.addCleanup(self.stop_all)
        self.start_sshd()

    # -- the server ---------------------------------------------------------
    def start_sshd(self):
        """Starts an sshd of its own: its own host key, its own authorized
        key, its own port, and public-key authentication only, so that a test
        never reads or writes anything the run did not create."""
        self.user = pwd.getpwuid(os.getuid()).pw_name
        base = pathlib.Path(self.workdir.name)
        host_key = base / "host_ed25519"
        user_key = base / "user_ed25519"
        for key in (host_key, user_key):
            result = subprocess.run(
                [KEYGEN, "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                capture_output=True, text=True)
            if result.returncode != 0:
                self.skipTest("ssh-keygen could not create the test key: " +
                              result.stderr.strip())
        self.private_key = user_key
        authorized = base / "authorized_keys"
        authorized.write_text(pathlib.Path(str(user_key) + ".pub").read_text())
        authorized.chmod(0o600)

        self.port = free_port()
        config = base / "sshd_config"
        config.write_text("\n".join([
            "Port %d" % self.port,
            "ListenAddress 127.0.0.1",
            "HostKey %s" % host_key,
            "AuthorizedKeysFile %s" % authorized,
            "PubkeyAuthentication yes",
            "PasswordAuthentication no",
            "KbdInteractiveAuthentication no",
            "UsePAM no",
            "StrictModes no",
            "PermitRootLogin no",
            "AllowUsers %s" % self.user,
            "PidFile %s" % (base / "sshd.pid"),
            "LogLevel VERBOSE",
            "",
        ]))
        checked = subprocess.run([SSHD, "-t", "-f", str(config)],
                                 capture_output=True, text=True)
        if checked.returncode != 0:
            self.skipTest("sshd rejected the test configuration: " +
                          checked.stderr.strip())
        self.sshd = subprocess.Popen(
            [SSHD, "-D", "-e", "-f", str(config)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True)
        self.addCleanup(self.stop_sshd)
        try:
            wait_for_port(self.port, self.sshd)
        except RuntimeError as exc:
            self.skipTest(str(exc))

        # The fingerprints of the host key in the spellings a pin may use:
        # OpenSSH's SHA-256 form, its MD5 form, and the same SHA-256 digest as
        # hex - which is what a client that is not curl has to accept too.
        self.sha256_pin = self.fingerprint(host_key, "sha256")
        self.md5_pin = self.fingerprint(host_key, "md5")
        raw = base64.b64decode(self.sha256_pin[len("SHA256:"):] + "==")
        self.sha256_hex = raw.hex()
        self.sha256_hex_colons = ":".join(
            self.sha256_hex[i:i + 2] for i in range(0, len(self.sha256_hex), 2))

    def fingerprint(self, host_key, algorithm):
        listing = subprocess.run(
            [KEYGEN, "-lf", str(host_key) + ".pub", "-E", algorithm],
            capture_output=True, text=True)
        marker = ("SHA256:" if algorithm == "sha256" else "MD5:")
        for field in listing.stdout.split():
            if field.startswith(marker):
                return field
        self.skipTest("ssh-keygen did not report the %s fingerprint: %s%s" %
                      (algorithm, listing.stdout, listing.stderr))

    def stop_sshd(self):
        sshd = getattr(self, "sshd", None)
        if sshd is not None and sshd.poll() is None:
            try:
                os.killpg(os.getpgid(sshd.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                sshd.terminate()
            try:
                sshd.wait(timeout=10)
            except subprocess.TimeoutExpired:
                sshd.kill()
                sshd.wait(timeout=10)
        self.sshd = None

    # -- the proxy ----------------------------------------------------------
    def start_proxy(self, kind="socks5", credentials=""):
        """Start TestProxyServer.py and collect what it reports.

        The proxy prints one line per request, which is the only way to tell a
        session that went through it from one that quietly went around it: a
        successful transfer proves nothing about the path it took.
        """
        env = dict(os.environ, LSCP_TEST_PORT="0", LSCP_TEST_PROXY_KIND=kind,
                   LSCP_TEST_PROXY_AUTH=credentials)
        proxy = subprocess.Popen(
            [sys.executable, str(HERE / "TestProxyServer.py")], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            start_new_session=True)
        lines = ProxyLines()
        port = []
        ready = threading.Event()

        def collect():
            for line in proxy.stdout:
                line = line.strip()
                if not line:
                    continue
                lines.report(line)
                if line.startswith("READY ") and not port:
                    port.append(int(line.split()[1]))
                    ready.set()

        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        if not ready.wait(30.0):
            self.stop_proxy(proxy, reader)
            self.fail("the test proxy did not start")
        self.proxies.append((proxy, reader))
        return port[0], lines

    def stop_proxy(self, proxy, reader):
        if proxy.poll() is None:
            try:
                os.killpg(os.getpgid(proxy.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                proxy.terminate()
            try:
                proxy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=10)
        if proxy.stdout is not None:
            proxy.stdout.close()
        reader.join(timeout=5)

    def stop_all(self):
        while self.proxies:
            self.stop_proxy(*self.proxies.pop())

    # -- the client ---------------------------------------------------------
    def url(self, initial_directory=True):
        if initial_directory:
            return "scp://%s@127.0.0.1:%d%s/" % (
                self.user, self.port, self.root)
        return "scp://%s@127.0.0.1:%d/" % (self.user, self.port)

    def run_script(self, commands, hostkey="*", url=None, extra_args=(),
                   open_args=(), timeout=90):
        """One scripted session. 'extra_args' are switches of the client
        itself, 'open_args' switches of the 'open' command it starts with -
        the difference matters, because a session setting such as a proxy
        belongs to 'open' and not to the process. 'hostkey=None' leaves the
        host key to whatever the client already knows."""
        argv = [BINARY, "-batch", "-timeout=20",
                "-privatekey=" + str(self.private_key),
                "-log=" + str(self.config / "session.log")]
        if hostkey is not None:
            argv.insert(2, "-hostkey=" + hostkey)
        argv += list(extra_args)
        argv.append("-command=open %s %s ; %s" % (
            url if url is not None else self.url(), " ".join(open_args),
            commands))
        env = dict(os.environ, LINSCP_CONFIG_DIR=str(self.config))
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout, env=env, cwd=str(self.local))

    def start_detached(self, commands, hostkey="*"):
        """Run a script without waiting for it, so that it can be
        interrupted."""
        argv = [BINARY, "-batch", "-hostkey=" + hostkey, "-timeout=20",
                "-privatekey=" + str(self.private_key)]
        argv.append("-command=open %s ; %s" % (self.url(), commands))
        env = dict(os.environ, LINSCP_CONFIG_DIR=str(self.config))
        return subprocess.Popen(RESET_SIGINT + argv,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env,
                                cwd=str(self.local), start_new_session=True)

    def succeed(self, commands, **kwargs):
        """Runs a script and asserts it ended the way it was asked to."""
        result = self.run_script(commands, **kwargs)
        self.assertEqual(result.returncode, 0,
                         "%s\n--- stdout ---\n%s\n--- stderr ---\n%s" %
                         (commands, result.stdout, result.stderr))
        return result

    def refused(self, commands, **kwargs):
        """Runs a script and asserts it did not silently succeed."""
        result = self.run_script(commands, **kwargs)
        self.assertNotEqual(result.returncode, 0,
                            "the command was expected to fail: %s\n%s" %
                            (commands, result.stdout))
        return result

    # -- the tests ----------------------------------------------------------
    def test_open_resolves_the_home_directory_and_the_initial_path(self):
        """An scp:// session has no protocol of its own to ask where it is:
        the client asks the shell. The initial path of the site is resolved
        once, in the same connection that opens the session, and 'pwd'
        afterwards reports a real absolute path - the same rule an sftp://
        session follows, so that the two spellings of one server agree."""
        result = self.succeed("pwd ; exit")
        self.assertEqual(result.stdout.strip().splitlines()[-1],
                         os.path.realpath(str(self.root)))
        self.assertIn("Connected, the remote directory is %s" %
                      os.path.realpath(str(self.root)), result.stdout)

        # A site URL that names the root is the root, and one that names no
        # path at all is the home directory the login starts in.
        root_url = self.succeed("pwd ; exit",
                                url="scp://%s@127.0.0.1:%d/" %
                                (self.user, self.port))
        self.assertEqual(root_url.stdout.strip().splitlines()[-1], "/")
        home = self.succeed("pwd ; exit",
                            url="scp://%s@127.0.0.1:%d" % (self.user, self.port))
        self.assertEqual(home.stdout.strip().splitlines()[-1],
                         os.path.realpath(os.path.expanduser("~")))

        # A path the server will not change into is refused where the reason
        # can still be reported, instead of quietly becoming the home
        # directory and listing something else two commands later.
        missing = self.refused(
            "pwd ; exit",
            url="scp://%s@127.0.0.1:%d/no-such-directory" % (
                self.user, self.port))
        self.assertIn("Cannot open session",
                      missing.stdout + missing.stderr)

    def test_cd_reports_the_directory_the_server_changed_into(self):
        """'cd' has to end up where the server's shell went, including out of
        a directory again, and a directory that is not there has to say so
        with the server's own reason."""
        (self.root / "sub dir").mkdir()
        result = self.succeed("cd 'sub dir' ; pwd ; cd .. ; pwd ; exit")
        # 'cd' reports the directory it changed into and 'pwd' reports it
        # again, so each of the two is there twice and in this order.
        paths = [line for line in result.stdout.splitlines()
                 if line.startswith("/")]
        self.assertEqual(paths, [
            os.path.realpath(str(self.root / "sub dir")),
            os.path.realpath(str(self.root / "sub dir")),
            os.path.realpath(str(self.root)),
            os.path.realpath(str(self.root))])
        # 'cd' with no argument is the home directory, as upstream has it.
        home = self.succeed("cd 'sub dir' ; cd ; pwd ; exit")
        self.assertEqual(home.stdout.strip().splitlines()[-1],
                         os.path.realpath(os.path.expanduser("~")))

        missing = self.refused("cd nowhere ; pwd ; exit")
        self.assertIn("Cannot change directory", missing.stdout + missing.stderr)
        self.assertIn("nowhere", missing.stdout + missing.stderr)

    def test_listing_and_stat_come_from_the_server_shell(self):
        """A listing is an 'ls -l -a' the client parses: the names, the sizes,
        the directory flag and the links have to be what the server holds,
        and a name with spaces has to stay one name."""
        write_random(self.root / "file one.txt", 300 * 1024)
        (self.root / ".hidden").write_text("hidden\n")
        (self.root / "sub dir").mkdir()
        os.symlink("file one.txt", str(self.root / "link.txt"))

        result = self.succeed("ls . ; exit")
        listed = result.stdout
        for name in ("file one.txt", ".hidden", "sub dir", "link.txt"):
            self.assertIn(name, listed)
        self.assertIn("4 entries", listed)
        self.assertIn("307200", listed)
        # A symbolic link is a link and keeps its own name: the target the
        # server printed is where it points, not part of what it is called.
        link_lines = [line for line in listed.splitlines()
                      if line.endswith("link.txt -> file one.txt")]
        self.assertEqual(len(link_lines), 1, listed)
        self.assertTrue(link_lines[0].startswith("l"), link_lines[0])

        stat = self.succeed("stat 'file one.txt' ; exit")
        self.assertIn("307200", stat.stdout)
        directory = self.succeed("stat 'sub dir' ; exit")
        self.assertIn("d", directory.stdout.splitlines()[-1])

        missing = self.refused("stat nope ; exit")
        self.assertIn("Cannot read the attributes of", missing.stderr)
        self.assertIn("There is no such file or directory.", missing.stderr)

        # 'ssh://' is the other spelling of the same protocol, so it is the
        # same engine that answers it: the same listing, and a command run on
        # the server's shell.
        over_ssh = self.succeed("ls . ; call echo ssh-spelling ; exit",
                                url=self.url().replace("scp://", "ssh://", 1))
        self.assertIn("file one.txt", over_ssh.stdout)
        self.assertIn("ssh-spelling", over_ssh.stdout)

    def test_download_and_upload_carry_the_bytes_intact(self):
        """The rcp protocol states a size and then sends exactly that many
        bytes: a file of many chunks, a name with spaces and an empty file all
        have to arrive unchanged, both ways."""
        payload = write_random(self.root / "file one.bin", 300 * 1024)
        (self.root / "empty.bin").write_bytes(b"")
        digest = sha256_of(payload)

        downloaded = self.local / "file one.bin"
        empty = self.local / "empty.bin"
        self.succeed("get -nopreservetime 'file one.bin' 'file one.bin' ; "
                     "get empty.bin empty.bin ; exit")
        self.assertEqual(sha256_of(downloaded), digest)
        self.assertEqual(empty.read_bytes(), b"")

        upload = write_random(self.local / "upload.bin", 260 * 1024)
        upload_digest = sha256_of(upload)
        self.succeed("put -nopreservetime upload.bin 'uploaded one.bin' ; exit")
        self.assertEqual(sha256_of(self.root / "uploaded one.bin"),
                         upload_digest)

        # A name the client is given as a directory, and a mask, are the same
        # question the SFTP transport answers: what arrives has to be the file.
        into_directory = self.local / "into-dir"
        into_directory.mkdir()
        self.succeed("get 'file one.bin' into-dir/ ; exit")
        self.assertEqual(sha256_of(into_directory / "file one.bin"), digest)

    def test_host_key_is_verified_by_the_client_not_by_curl(self):
        """A pin is enforced by this client's own SSH code, in every spelling
        it arrives in, and a key that does not match is refused. Nothing here
        depends on the installed curl, which is what made an scp:// session
        unverifiable wherever curl linked libssh instead of libssh2."""
        # First, with nothing pinned and nothing cached: an unknown host key
        # is refused in a run nobody can answer a prompt in, and the key the
        # server offered is printed so that it can be pinned next time.
        argv = [BINARY, "-batch", "-timeout=20",
                "-privatekey=" + str(self.private_key),
                "-command=open %s ; pwd ; echo SHOULD_NOT_RUN ; exit" %
                self.url()]
        env = dict(os.environ, LINSCP_CONFIG_DIR=str(self.config))
        unpinned = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=90, env=env, cwd=str(self.local))
        self.assertNotEqual(unpinned.returncode, 0, unpinned.stdout)
        self.assertIn("HOSTKEY", unpinned.stdout + unpinned.stderr)
        self.assertIn(self.sha256_pin, unpinned.stdout + unpinned.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", unpinned.stdout)

        result = self.succeed("pwd ; exit", hostkey=self.sha256_pin)
        self.assertNotIn("curl", (result.stdout + result.stderr).lower())

        # The same 32 bytes as hex, with and without separators, and as MD5:
        # all of them name a key, so all of them have to be checked.
        for pin in (self.sha256_hex, self.sha256_hex_colons, self.md5_pin):
            checked = self.succeed("pwd ; exit", hostkey=pin)
            self.assertNotIn("hostpubsha256", checked.stdout + checked.stderr)

        wrong = self.refused("pwd ; echo SHOULD_NOT_RUN ; exit",
                             hostkey="SHA256:" + "A" * 43)
        combined = wrong.stdout + wrong.stderr
        self.assertIn("not the expected one", combined.lower())
        self.assertNotIn("SHOULD_NOT_RUN", wrong.stdout)
        self.assertNotIn("hostpubsha256", combined)

        wrong_hex = self.refused("pwd ; exit", hostkey="ab" * 32)
        self.assertIn("not the expected one",
                      (wrong_hex.stdout + wrong_hex.stderr).lower())

        # A key that was checked once is remembered: the run that follows
        # needs no pin and no '*', and it is the cached key that lets it in.
        cached = self.succeed("pwd ; exit", hostkey=None)
        self.assertNotIn("HOSTKEY", cached.stdout)

    def test_directory_and_permission_operations_reach_the_server(self):
        """mkdir, chmod, mv, rm and rmdir are shell commands, and the server's
        filesystem is the only witness that they ran."""
        # Deleting and overwriting ask first, and a batch run has nobody to
        # ask: the option is what a script says when it means it.
        self.succeed("option confirm off ; mkdir newdir ; exit")
        self.assertTrue((self.root / "newdir").is_dir())

        self.succeed("chmod 750 newdir ; exit")
        self.assertEqual((self.root / "newdir").stat().st_mode & 0o7777, 0o750)

        (self.root / "perm.txt").write_bytes(b"permissions\n")
        self.succeed("chmod 604 perm.txt ; exit")
        self.assertEqual((self.root / "perm.txt").stat().st_mode & 0o7777, 0o604)

        self.succeed("option confirm off ; mv perm.txt moved.txt ; exit")
        self.assertFalse((self.root / "perm.txt").exists())
        self.assertEqual((self.root / "moved.txt").read_bytes(),
                         b"permissions\n")

        self.succeed("option confirm off ; rm moved.txt ; rmdir newdir ; exit")
        self.assertFalse((self.root / "moved.txt").exists())
        self.assertFalse((self.root / "newdir").exists())

        # A directory that is not empty is not removed, and the server's own
        # words are what the user reads.
        (self.root / "notempty").mkdir()
        (self.root / "notempty" / "inside.txt").write_text("x\n")
        refused = self.refused("option confirm off ; rmdir notempty ; exit")
        combined = refused.stdout + refused.stderr
        self.assertIn("Cannot remove the directory", combined)
        # The server's own sentence is what tells a directory that is not
        # empty from one that is not there.
        self.assertIn("rmdir: failed to remove", combined)
        self.assertIn("Directory not empty", combined)
        self.assertTrue((self.root / "notempty").is_dir())

        missing = self.refused("option confirm off ; rm nope ; exit")
        self.assertIn("No such file or directory",
                      missing.stdout + missing.stderr)

    def test_rmdir_resolves_relative_directory_after_cd(self):
        """Upstream issue: rmdir directory entries need a full path.

        A script that changes directory and then names a child by its
        leaf must remove that child, not a same-named directory in the
        login home (or nothing at all).
        """
        (self.root / "parent" / "leaf").mkdir(parents=True)
        self.succeed("option confirm off ; cd parent ; rmdir leaf ; exit")
        self.assertFalse((self.root / "parent" / "leaf").exists())
        self.assertTrue((self.root / "parent").is_dir())

    def test_symlink_times_and_upload_permissions_are_set_on_the_server(self):
        """The metadata the shell can set and 'ls -l' can read back: a
        symbolic link, an mtime carried by the rcp timestamp header and by
        'touch', and the mode an upload is given."""
        (self.root / "target.txt").write_text("target\n")
        self.succeed("ln target.txt link.txt ; exit")
        self.assertTrue((self.root / "link.txt").is_symlink())
        # The target is a remote path and is resolved against the working
        # directory, so the link points at the file and not at a name that
        # only means something in the directory the client happened to be in.
        self.assertEqual(os.readlink(str(self.root / "link.txt")),
                         str(self.root / "target.txt"))
        self.succeed("ln target.txt 'spaced link.txt' ; exit")
        self.assertTrue((self.root / "spaced link.txt").is_symlink())
        self.assertEqual((self.root / "spaced link.txt").read_text(),
                         "target\n")

        dated = self.local / "dated.txt"
        dated.write_bytes(b"dated\n")
        os.utime(str(dated), (1000000000, 1000000000))
        self.succeed("put -preservetime dated.txt preserved.txt ; exit")
        uploaded = self.root / "preserved.txt"
        self.assertEqual(uploaded.read_bytes(), b"dated\n")
        self.assertEqual(int(uploaded.stat().st_mtime), 1000000000)

        self.succeed("put -permissions=640 dated.txt restricted.txt ; exit")
        self.assertEqual(
            (self.root / "restricted.txt").stat().st_mode & 0o7777, 0o640)

        # And the other way round: '-preservetime' on a download sets the
        # local file's time from the timestamp header the server sent.
        remote_dated = self.root / "remote-dated.txt"
        remote_dated.write_bytes(b"remote dated\n")
        os.utime(str(remote_dated), (1000000000, 1000000000))
        self.succeed("get -preservetime remote-dated.txt local-dated.txt ; exit")
        local_dated = self.local / "local-dated.txt"
        self.assertEqual(local_dated.read_bytes(), b"remote dated\n")
        self.assertEqual(int(local_dated.stat().st_mtime), 1000000000)

    def test_recursive_transfer_and_server_side_copy(self):
        """A tree goes through the recursive form of the rcp protocol: one
        directory header per level, an 'E' to close it, and the empty
        directories of the tree are directories afterwards too. A server-side
        copy is the shell's own 'cp -p'."""
        tree = self.root / "tree"
        (tree / "nested").mkdir(parents=True)
        (tree / "empty").mkdir()
        inner = write_random(tree / "nested" / "a file.bin", 60 * 1024)
        outer = write_random(tree / "b file.bin", 40 * 1024)
        inner_digest, outer_digest = sha256_of(inner), sha256_of(outer)
        os.utime(str(tree), (1000000000, 1000000000))

        self.succeed("get -preservetime=all tree/ dl/ ; exit")
        downloaded = self.local / "dl"
        self.assertEqual(sha256_of(downloaded / "nested" / "a file.bin"),
                         inner_digest)
        self.assertEqual(sha256_of(downloaded / "b file.bin"), outer_digest)
        self.assertTrue((downloaded / "empty").is_dir())
        self.assertEqual(int(downloaded.stat().st_mtime), 1000000000)

        self.succeed("put dl/ up/ ; exit")
        uploaded = self.root / "up"
        self.assertEqual(sha256_of(uploaded / "nested" / "a file.bin"),
                         inner_digest)
        self.assertEqual(sha256_of(uploaded / "b file.bin"), outer_digest)
        self.assertTrue((uploaded / "empty").is_dir())

        self.succeed("cp 'tree/b file.bin' copied.bin ; exit")
        copied = self.root / "copied.bin"
        self.assertEqual(sha256_of(copied), outer_digest)
        # 'cp -p': the copy carries the time of the file it copied.
        self.assertEqual(int(copied.stat().st_mtime),
                         int(outer.stat().st_mtime))

    def test_a_partial_transfer_is_neither_resumed_nor_left_behind(self):
        """The rcp protocol has no offset, so continuing is refused by name
        rather than answered with a file that starts in the middle, and a
        staging file from a transfer that died is discarded instead of being
        spliced onto."""
        upload = write_random(self.local / "upload.bin", 200 * 1024)
        refused = self.refused("put -resume upload.bin resumed.bin ; exit")
        self.assertIn("cannot resume", (refused.stdout + refused.stderr).lower())
        self.assertFalse((self.root / "resumed.bin").exists())

        big = write_random(self.root / "big.bin", 200 * 1024)
        refused_get = self.refused(
            "get -resumesupport=on big.bin resumed-local.bin ; exit")
        self.assertIn("cannot resume",
                      (refused_get.stdout + refused_get.stderr).lower())

        # 'option resume automatic' would continue anything over the
        # threshold: the staging file is junk and the result has to be the
        # whole file, so it can only have been restarted.
        part = self.local / "big-dl.bin.filepart"
        part.write_bytes(b"junk that no transfer ever wrote\n" * 200)
        self.succeed("option resume automatic ; get big.bin big-dl.bin ; exit")
        self.assertEqual(sha256_of(self.local / "big-dl.bin"), sha256_of(big))
        self.assertFalse(part.exists())

    def test_an_interrupted_download_leaves_nothing_under_the_final_name(self):
        """A transfer stopped half way through is not a file: the name the
        user asked for is written only when the file is whole. What the
        interrupted run leaves in its staging file is bytes this protocol can
        never continue from, so the next run has to start over and still get
        every one of them - it must not splice onto a partial file."""
        payload = write_random(self.root / "slow.bin", 600 * 1024)
        digest = sha256_of(payload)
        target = self.local / "interrupted.bin"
        part = self.local / "interrupted.bin.filepart"

        process = self.start_detached("get -speed=64 slow.bin interrupted.bin")
        deadline = time.time() + 30
        while time.time() < deadline and not part.exists():
            if process.poll() is not None:
                break
            time.sleep(0.05)
        self.assertTrue(part.exists() or process.poll() is not None,
                        "the transfer never started")
        os.killpg(os.getpgid(process.pid), signal.SIGINT)
        try:
            self.assertNotEqual(process.wait(timeout=60), 0)
        except subprocess.TimeoutExpired:
            process.kill()
            self.fail("the client did not stop when it was interrupted")
        process.communicate(timeout=60)

        self.assertFalse(target.exists(),
                         "an interrupted transfer left a file behind")
        self.assertEqual(sha256_of(payload), digest)

        # The default 'option resume automatic' would continue a staging file
        # this size: for SCP it has to be discarded instead, so the run that
        # follows is the whole file and not the rest of it.
        self.succeed("get slow.bin interrupted.bin ; exit")
        self.assertFalse(part.exists())
        self.assertEqual(sha256_of(target), digest)

    def test_an_ascii_transfer_converts_the_line_endings(self):
        """'option transfer ascii' is a property of the transfer, not of the
        transport: an upload reaches the server with the line endings the
        option asks for and comes back as it was written."""
        (self.local / "unix.txt").write_bytes(b"line one\nline two\n")
        self.succeed("option transfer ascii ; put unix.txt converted.txt ; exit")
        self.assertEqual((self.root / "converted.txt").read_bytes(),
                         b"line one\r\nline two\r\n")

        self.succeed("option transfer ascii ; get converted.txt back.txt ; exit")
        self.assertEqual((self.local / "back.txt").read_bytes(),
                         b"line one\nline two\n")

    def test_a_speed_limit_paces_the_transfer(self):
        """'-speed=' is applied between chunks, so a limited transfer takes
        the time the limit says and still carries every byte."""
        payload = write_random(self.root / "paced.bin", 300 * 1024)
        digest = sha256_of(payload)
        started = time.time()
        self.succeed("get -speed=100 paced.bin paced-dl.bin ; exit",
                     timeout=180)
        elapsed = time.time() - started
        self.assertEqual(sha256_of(self.local / "paced-dl.bin"), digest)
        # 300 KiB at 100 KiB/s cannot finish in under about three seconds;
        # the bound is loose enough for a loaded machine to stay honest.
        self.assertGreater(elapsed, 2.0,
                           "the speed limit was not applied (%.2fs)" % elapsed)

    def test_progress_is_reported_while_the_transfer_runs(self):
        """The transfer reports through the same callback the SFTP transport
        uses, so an interactive session shows a percentage that climbs to
        100. The commands are typed into the client the way a user would:
        a scripted run has no terminal to draw a percentage on and reports
        the finished file instead."""
        payload = write_random(self.root / "progress.bin", 256 * 1024)
        target = self.local / "progress-dl.bin"

        master, slave = pty.openpty()
        argv = [BINARY, "-hostkey=*", "-timeout=20",
                "-privatekey=" + str(self.private_key)]
        env = dict(os.environ, LINSCP_CONFIG_DIR=str(self.config))
        process = subprocess.Popen(argv, stdin=slave, stdout=slave,
                                   stderr=slave, cwd=str(self.local), env=env,
                                   close_fds=True)
        os.close(slave)
        captured = bytearray()
        # One line per step, and the step before it has to be answered: a
        # prompt that never comes is a failure of the session, not a race.
        steps = [("> ", "open %s\n" % self.url()),
                 ("Connected", "get -speed=64 progress.bin %s\n" % target),
                 ("100.0%", "exit\n")]
        try:
            for expected, line in steps:
                deadline = time.time() + 60
                while True:
                    text = captured.decode("utf-8", "replace")
                    if expected in text:
                        break
                    if process.poll() is not None:
                        self.fail("the session ended before '%s':\n%s" %
                                  (expected, text))
                    if time.time() > deadline:
                        self.fail("'%s' never appeared:\n%s" % (expected, text))
                    ready, _, _ = select.select([master], [], [], 0.2)
                    if ready:
                        try:
                            chunk = os.read(master, 4096)
                        except OSError:
                            chunk = b""
                        if not chunk:
                            self.fail("the session closed its output before "
                                      "'%s':\n%s" % (expected, text))
                        captured.extend(chunk)
                os.write(master, line.encode("utf-8"))
            process.wait(timeout=60)
            while True:
                ready, _, _ = select.select([master], [], [], 0.5)
                if not ready:
                    break
                try:
                    chunk = os.read(master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                captured.extend(chunk)
        finally:
            os.close(master)

        text = captured.decode("utf-8", "replace")
        self.assertEqual(process.returncode, 0, text)
        self.assertEqual(sha256_of(target), sha256_of(payload))
        # The display a transfer draws: the name, a percentage that starts at
        # zero, and the same percentage finished.
        self.assertIn("progress-dl.bin", text)
        self.assertIn("0.0%", text)
        self.assertIn("100.0%", text)
        self.assertLess(text.index("0.0%"), text.index("100.0%"))

    def test_a_remote_command_runs_on_the_server_and_a_checksum_is_computed(
            self):
        """'call' hands the rest of the line to the server's shell, and
        'checksum' says plainly that it computed the digest from a downloaded
        file because this protocol has no server-side hashing."""
        (self.root / "hashed.bin").write_bytes(b"hash me\n" * 100)
        expected = hashlib.sha256((self.root / "hashed.bin").read_bytes())

        result = self.succeed("call echo hello-from-the-server ; exit")
        self.assertIn("hello-from-the-server", result.stdout)

        marker = self.root / "called.txt"
        self.succeed("call touch %s ; exit" % marker)
        self.assertTrue(marker.exists())

        checksum = self.succeed("checksum sha-256 hashed.bin ; exit")
        self.assertIn(expected.hexdigest(), checksum.stdout)
        self.assertIn("downloaded", checksum.stdout.lower())

    def test_an_operation_the_server_refuses_says_what_the_server_said(self):
        """A refusal has to carry the server's reason: the client did not
        fail, the server said no, and the words it used are the evidence."""
        upload = write_random(self.local / "denied.bin", 4 * 1024)
        readonly = self.root / "readonly"
        readonly.mkdir()
        unreadable = self.root / "unreadable"
        unreadable.mkdir()
        try:
            # The owner may read a 0500 directory but not write into it, and
            # may enter a 0111 one but not list it: two refusals, and each
            # has to arrive as the sentence the server printed.
            readonly.chmod(0o500)
            result = self.refused("option confirm off ; "
                                  "put denied.bin readonly/denied.bin ; exit")
            combined = result.stdout + result.stderr
            self.assertIn("Transfer of", combined)
            self.assertIn("failed", combined)
            self.assertIn("Permission denied", combined)
            self.assertFalse((readonly / "denied.bin").exists())

            unreadable.chmod(0o111)
            listed = self.refused("ls unreadable ; exit")
            self.assertIn("Cannot read directory",
                          listed.stdout + listed.stderr)
            self.assertIn("Permission denied",
                          listed.stdout + listed.stderr)
        finally:
            readonly.chmod(0o755)
            unreadable.chmod(0o755)

        # A transfer of a file that is not there fails with the server's own
        # sentence, not with a generic transport error.
        missing = self.refused("get nope.bin nowhere.bin ; exit")
        combined = missing.stdout + missing.stderr
        self.assertIn("No such file or directory", combined)
        self.assertFalse((self.local / "nowhere.bin").exists())

    def test_a_session_to_an_endpoint_that_is_not_there_is_refused(self):
        """An unreachable port, a refused login and a host that answers
        nothing are all failures of the session, and 'open' is where they are
        reported."""
        closed = free_port()
        result = self.refused(
            "pwd ; exit",
            url="scp://%s@127.0.0.1:%d/" % (self.user, closed))
        self.assertIn("Cannot open session", result.stdout + result.stderr)

        denied = self.refused(
            "pwd ; exit",
            url="scp://no-such-user@127.0.0.1:%d/" % self.port)
        self.assertIn("Cannot open session", denied.stdout + denied.stderr)

    def test_a_socks5_proxy_carries_the_session(self):
        """'-rawsettings ProxyMethod=SOCKS5 ...' has to change the path the
        connection takes, not just be accepted: the proxy must see the
        destination, and a transfer through it must still be byte for byte.
        The SSH code that connects is this client's own, so the proxy is
        honoured without curl's '--proxy'."""
        proxy_port, proxy_lines = self.start_proxy()
        payload = write_random(self.root / "through-proxy.bin", 128 * 1024)
        digest = sha256_of(payload)
        target = self.local / "through-proxy.bin"
        result = self.run_script(
            "get through-proxy.bin %s ; exit" % target,
            open_args=["-rawsettings", "ProxyMethod=SOCKS5",
                       "ProxyHost=127.0.0.1", "ProxyPort=%d" % proxy_port,
                       # Upstream leaves a localhost destination alone unless
                       # the session asks for it explicitly.
                       "ProxyLocalhost=1"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(sha256_of(target), digest)
        self.assertTrue(proxy_lines.contains(
            lambda line: line == "CONNECT 127.0.0.1:%d" % self.port),
            "the session did not go through the proxy: %s" % (proxy_lines,))


def run_and_report():
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    # A failure has to name itself in the evidence lines: CI surfaces those
    # as annotations, and the raw log of a failed run is not always available
    # to whoever has to fix it.
    for test, report in list(result.failures) + list(result.errors):
        lines = [line.strip() for line in report.strip().splitlines()
                 if line.strip()]
        detail = " | ".join(lines[-6:]) if lines else "no detail"
        print("evidence: FAILED %s: %s" %
              (test.id().split(".")[-1], detail[-1200:]))
    line = ("evidence: suite=%s platform=linux ran=%d skipped=%d failed=%d" %
            (SUITE_NAME, result.testsRun, len(result.skipped),
             len(result.failures) + len(result.errors)))
    if not result.testsRun and result.skipped:
        reasons = "; ".join(sorted(set(str(reason)[:160]
                                       for _, reason in result.skipped)))
        line += " because: " + reasons
    print(line)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_and_report())
