"""Server-free CLI regression tests for the Linux client."""
import base64
import hashlib
import hmac
import os
import pathlib
import pty
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())
SUITE_NAME = "script"


def _ssh_string(data):
    return struct.pack(">I", len(data)) + data


def _mpint(number):
    if number == 0:
        return _ssh_string(b"")
    data = number.to_bytes((number.bit_length() + 7) // 8, "big")
    if data[0] & 0x80:
        data = b"\0" + data
    return _ssh_string(data)


def _ppk_rsa_fixture(version=2, valid_mac=True):
    # Small, deterministic RSA values keep this fixture dependency-free.
    # They are for parser regression tests only and must never be used as keys.
    algorithm = b"ssh-rsa"
    comment = b"LinSCP PPK parser test"
    public = _ssh_string(algorithm) + _mpint(17) + _mpint(3233)
    private = _mpint(2753) + _mpint(61) + _mpint(53) + _mpint(38)
    encryption = b"none"
    mac_data = b"".join(_ssh_string(part) for part in
                        (algorithm, encryption, comment, public, private))
    digest = hashlib.sha1 if version == 2 else hashlib.sha256
    mac_key = b"putty-private-key-file-mac-key"
    mac = hmac.new(mac_key, mac_data, digest).hexdigest()
    if not valid_mac:
        mac = ("0" if mac[0] != "0" else "1") + mac[1:]
    lines = [
        "PuTTY-User-Key-File-%d: ssh-rsa" % version,
        "Encryption: none",
        "Comment: " + comment.decode("ascii"),
        "Public-Lines: 1",
        base64.b64encode(public).decode("ascii"),
    ]
    if version == 3:
        lines.append("Key-Derivation: none")
    lines.extend(("Private-Lines: 1", base64.b64encode(private).decode("ascii"),
                  "Private-MAC: " + mac, ""))
    return "\n".join(lines)


class ScriptTests(unittest.TestCase):
    def setUp(self):
        # Every test gets its own configuration directory, so that a test
        # never reads or writes the sessions of the user running them.
        self._config = tempfile.TemporaryDirectory(prefix="linscp-config-")
        self.config = self._config.name
        self.addCleanup(self._config.cleanup)

    def environment(self, extra=None):
        env = dict(os.environ)
        env["LINSCP_CONFIG_DIR"] = self.config
        if extra:
            env.update(extra)
        return env

    def run_commands(self, text, file=False, env=None):
        env = self.environment(env)
        if file:
            with tempfile.TemporaryDirectory() as tmp:
                path = pathlib.Path(tmp) / "commands.txt"
                path.write_text(text.replace(";", "\n"), encoding="utf-8")
                return subprocess.run([BINARY, "-script=" + str(path)],
                                      capture_output=True, text=True, timeout=10,
                                      env=env)
        return subprocess.run([BINARY, "-command=" + text],
                              capture_output=True, text=True, timeout=10, env=env)

    def test_ppk_v2_v3_conversion_and_mac_validation(self):
        with tempfile.TemporaryDirectory(prefix="linscp-ppk-") as temp:
            root = pathlib.Path(temp)
            for version in (2, 3):
                source = root / ("fixture-v%d.ppk" % version)
                target = root / ("converted-v%d.pem" % version)
                source.write_text(_ppk_rsa_fixture(version), encoding="ascii")
                result = subprocess.run(
                    [BINARY, "-convertkey=" + str(source), "-output=" + str(target)],
                    capture_output=True, text=True, timeout=10,
                    env=self.environment())
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("BEGIN PRIVATE KEY", target.read_text(encoding="ascii"))
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

            bad_source = root / "bad-mac.ppk"
            bad_target = root / "must-not-exist.pem"
            bad_source.write_text(_ppk_rsa_fixture(2, valid_mac=False), encoding="ascii")
            result = subprocess.run(
                [BINARY, "-convertkey=" + str(bad_source), "-output=" + str(bad_target)],
                capture_output=True, text=True, timeout=10,
                env=self.environment())
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(bad_target.exists())
            self.assertIn("integrity", result.stderr.lower())

            # Exercise the v2 AES path and ensure conversion keeps the source
            # passphrase on the PEM output. OpenSSL's command is optional in
            # minimal test environments; the core itself links libcrypto.
            if shutil.which("openssl"):
                password = b"test-passphrase"
                algorithm = b"ssh-rsa"
                comment = b"encrypted fixture"
                public = _ssh_string(algorithm) + _mpint(17) + _mpint(3233)
                private = _mpint(2753) + _mpint(61) + _mpint(53) + _mpint(38)
                padding = (-len(private)) % 16
                plaintext = private + bytes(padding)
                plain_path = root / "private-plain.bin"
                cipher_path = root / "private-cipher.bin"
                plain_path.write_bytes(plaintext)
                first = hashlib.sha1(struct.pack(">I", 0) + password).digest()
                second = hashlib.sha1(struct.pack(">I", 1) + password).digest()
                aes_key = (first + second)[:32]
                subprocess.run([
                    "openssl", "enc", "-aes-256-cbc", "-K", aes_key.hex(),
                    "-iv", "00" * 16, "-nosalt", "-nopad", "-in", str(plain_path),
                    "-out", str(cipher_path)], check=True, capture_output=True,
                    timeout=10)
                ciphertext = cipher_path.read_bytes()
                encryption = b"aes256-cbc"
                mac_data = b"".join(_ssh_string(part) for part in
                                    (algorithm, encryption, comment, public, plaintext))
                mac_key = hashlib.sha1(b"putty-private-key-file-mac-key" + password).digest()
                mac = hmac.new(mac_key, mac_data, hashlib.sha1).hexdigest()
                encrypted_source = root / "encrypted-v2.ppk"
                encrypted_target = root / "encrypted-output.pem"
                ppk_lines = [
                    "PuTTY-User-Key-File-2: ssh-rsa",
                    "Encryption: aes256-cbc",
                    "Comment: " + comment.decode("ascii"),
                    "Public-Lines: 1",
                    base64.b64encode(public).decode("ascii"),
                    "Private-Lines: 1",
                    base64.b64encode(ciphertext).decode("ascii"),
                    "Private-MAC: " + mac,
                    "",
                ]
                encrypted_source.write_text("\n".join(ppk_lines), encoding="ascii")
                result = subprocess.run(
                    [BINARY, "-convertkey=" + str(encrypted_source),
                     "-output=" + str(encrypted_target),
                     "-passphrase=" + password.decode("ascii")],
                    capture_output=True, text=True, timeout=10,
                    env=self.environment())
                self.assertEqual(result.returncode, 0, result.stderr)
                check = subprocess.run([
                    "openssl", "pkey", "-in", str(encrypted_target),
                    "-passin", "pass:" + password.decode("ascii"), "-noout"],
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(check.returncode, 0, check.stderr)

    def test_gui_launcher_is_selected_beside_the_running_binary(self):
        with tempfile.TemporaryDirectory(prefix="linscp-install-") as temp:
            binary = pathlib.Path(temp) / "linscp"
            launcher = pathlib.Path(temp) / "linscp-gui"
            shutil.copyfile(BINARY, binary)  # not a symlink: /proc/self/exe is resolved
            binary.chmod(0o755)
            launcher.write_text("#!/bin/sh\necho ADJACENT_GUI\n", encoding="utf-8")
            launcher.chmod(0o755)
            result = subprocess.run([str(binary), "-gui"],
                                    capture_output=True, text=True, timeout=10,
                                    env=self.environment())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ADJACENT_GUI", result.stdout)

    def test_the_gui_launcher_is_asked_for_a_window_only_when_somebody_reads(self):
        # The desktop is asked for a browser window (the way that works on a
        # Wayland session as well as under X11) when a person ran the client
        # from a terminal; a run whose output goes to a pipe or a file is an
        # automation, and an automation never asked for a browser.
        with tempfile.TemporaryDirectory(prefix="linscp-gui-window-") as temp:
            binary = pathlib.Path(temp) / "linscp"
            launcher = pathlib.Path(temp) / "linscp-gui"
            shutil.copyfile(BINARY, binary)  # not a symlink: /proc/self/exe is resolved
            binary.chmod(0o755)
            launcher.write_text('#!/bin/sh\necho "GUIARGS:$*"\n', encoding="utf-8")
            launcher.chmod(0o755)

            piped = subprocess.run([str(binary), "-gui"], capture_output=True,
                                   text=True, timeout=10, env=self.environment())
            self.assertEqual(piped.stdout.strip(), "GUIARGS:", piped.stdout)

            pid, terminal = pty.fork()
            if pid == 0:
                os.execve(str(binary), [str(binary), "-gui"], self.environment())
                os._exit(127)
            # The launcher prints its arguments and exits, and the client is
            # replaced by it, so the read ends at the first line: waiting for
            # the process would wait for a browser nobody opened.
            deadline = time.monotonic() + 10
            output = b""
            try:
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([terminal], [], [], 0.2)
                    if not ready:
                        continue
                    try:
                        chunk = os.read(terminal, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output += chunk
                    if b"GUIARGS:" in output:
                        break
            finally:
                os.close(terminal)
            os.waitpid(pid, 0)
            self.assertIn("GUIARGS:--open-browser",
                          output.decode("utf-8", "replace"))

    def test_gui_launcher_finds_source_tree_from_make_and_cmake_builds(self):
        with tempfile.TemporaryDirectory(prefix="linscp-source-") as temp:
            root = pathlib.Path(temp)
            launcher = root / "source" / "gui" / "linscp-gui"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("#!/bin/sh\necho SOURCE_TREE_GUI\n", encoding="utf-8")
            launcher.chmod(0o755)
            for directory in (root / "source" / "linux" / "build",
                              root / "build"):
                directory.mkdir(parents=True)
                binary = directory / "linscp"
                shutil.copyfile(BINARY, binary)
                binary.chmod(0o755)
                with self.subTest(directory=directory):
                    result = subprocess.run([str(binary), "-gui"],
                                            capture_output=True, text=True,
                                            timeout=10, env=self.environment())
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("SOURCE_TREE_GUI", result.stdout)

    def test_translation_locale_selection_and_literal_placeholders(self):
        for locale in ("es", "es_MX.UTF-8", "es_ES@formal"):
            result = self.run_commands("{reason}", env={"LINSCP_LANGUAGE": locale})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Orden desconocida '{reason}'", result.stdout + result.stderr)
        for locale in ("en", "C", "POSIX", "zz_ZZ.UTF-8", "../../es"):
            result = self.run_commands("nosuchcommand", env={"LINSCP_LANGUAGE": locale})
            self.assertIn("Unknown command", result.stdout + result.stderr)

    def test_translation_locale_environment_precedence(self):
        env = {"LINSCP_LANGUAGE": "", "LC_ALL": "C", "LC_MESSAGES": "es", "LANG": "es"}
        result = self.run_commands("nosuchcommand", env=env)
        self.assertIn("Unknown command", result.stdout + result.stderr)
        env["LC_ALL"] = ""
        result = self.run_commands("nosuchcommand", env=env)
        self.assertIn("Orden desconocida", result.stdout + result.stderr)
        env["LINSCP_LANGUAGE"] = "en"
        result = self.run_commands("nosuchcommand", env=env)
        self.assertIn("Unknown command", result.stdout + result.stderr)

    def test_translated_help_and_option_errors_preserve_command_syntax(self):
        for arguments, expected in [(["-help"], "Órdenes:"),
                                    (["-port=bad"], "Puerto no válido"),
                                    (["-unknown"], "Opción desconocida")]:
            result = subprocess.run([BINARY] + arguments,
                                    capture_output=True, text=True, timeout=10,
                                    env=self.environment({"LINSCP_LANGUAGE": "es"}))
            self.assertIn(expected, result.stdout + result.stderr)
            self.assertEqual(result.returncode, 0 if arguments == ["-help"] else 1)
        result = self.run_commands("echo Delete %1%", env={"LINSCP_LANGUAGE": "es"})
        self.assertIn("Delete", result.stdout)

    def test_translated_command_help_lists_every_command(self):
        english = self.run_commands("help")
        spanish = self.run_commands("help", env={"LINSCP_LANGUAGE": "es"})
        self.assertEqual(english.returncode, 0)
        self.assertEqual(spanish.returncode, 0)
        # The names of the commands are data and stay literal; only the
        # description next to them is translated.
        names = [line.split()[0] for line in english.stdout.splitlines()
                 if line and not line[0].isspace() and line.split()]
        self.assertTrue(names)
        for name in names:
            with self.subTest(command=name):
                self.assertIn(name, spanish.stdout)
        self.assertIn("Descarga archivos.", spanish.stdout)
        self.assertNotIn("Downloads files.", spanish.stdout)
        detail = self.run_commands("help get", env={"LINSCP_LANGUAGE": "es"})
        self.assertIn("get [ <switches> ] <file> [ <file>... ] [ <target> ]",
                      detail.stdout)
        self.assertIn("Descarga archivos.", detail.stdout)
        self.assertIn("-versionid=<ID>", detail.stdout)
        self.assertIn("usa un archivo temporal distinto por versión", detail.stdout)
        version_help = self.run_commands("help versions",
                                         env={"LINSCP_LANGUAGE": "es"})
        self.assertEqual(version_help.returncode, 0, version_help.stderr)
        self.assertIn("Lista las versiones de objetos S3", version_help.stdout)
        usage = subprocess.run([BINARY, "-help"], capture_output=True,
                               text=True, timeout=10, env=self.environment())
        self.assertIn("versions [OBJECT]", usage.stdout)
        self.assertIn("-versionid=ID", usage.stdout)

    def test_translated_engine_workflows_keep_the_data_literal(self):
        spanish = {"LINSCP_LANGUAGE": "es"}
        result = self.run_commands("option batch; option transfer", env=spanish)
        self.assertEqual(result.returncode, 0)
        self.assertIn("batch = ", result.stdout)
        self.assertIn("transfer = ", result.stdout)
        # A wrong switch is reported in the language of the user, and the
        # name of the switch itself stays literal.
        result = self.run_commands("open sftp://host -nonsense", env=spanish)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Opción desconocida '-nonsense'",
                      result.stdout + result.stderr)
        # A value that the option does not accept is named in the message.
        result = self.run_commands("option editmaxsize abc", env=spanish)
        self.assertEqual(result.returncode, 1)
        self.assertIn("El valor de 'editmaxsize' debe ser un número de bytes.",
                      result.stdout + result.stderr)
        # The list of the option names is data, the word before it is not.
        result = self.run_commands("option -nonsense", env=spanish)
        self.assertEqual(result.returncode, 1)
        self.assertIn("admitidos: echo, batch", result.stdout + result.stderr)
        # An unknown command keeps its own name.
        result = self.run_commands("nosuchcommand", env=spanish)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Orden desconocida 'nosuchcommand'",
                      result.stdout + result.stderr)

    def test_translated_synchronization_session_and_transfer_workflows(self):
        spanish = {"LINSCP_LANGUAGE": "es"}
        # The synchronization refuses a criteria it cannot use, and says so
        # in the language of the user.
        result = self.run_commands("synchronize both -criteria=checksum /a /b",
                                   env=spanish)
        self.assertEqual(result.returncode, 1)
        self.assertIn("'-criteria=checksum' no se puede combinar con la "
                      "dirección 'both'",
                      result.stdout + result.stderr)
        # A transfer that is asked for with an unknown switch is refused
        # before it touches the network.
        result = self.run_commands("get -nonsense /tmp/x", env=spanish)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Opción no admitida '-nonsense'",
                      result.stdout + result.stderr)
        for command, message in (
                ("get -versionid= /tmp/x", "no puede estar vacío"),
                ("get -versionid=one -versionid=two /tmp/x",
                 "una sola vez"),
                ("put -versionid=one /tmp/x", "solo está disponible para")):
            with self.subTest(command=command):
                result = self.run_commands(command, env=spanish)
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stdout + result.stderr)
        # The sessions of the user are listed in the language of the user,
        # and the name of the configuration file stays literal.
        result = self.run_commands("sessions list", env=spanish)
        self.assertEqual(result.returncode, 0)
        self.assertIn("No hay ninguna sesión guardada.",
                      result.stdout + result.stderr)
        # The editor refuses a second file with a message of its own.
        result = self.run_commands("edit", env=spanish)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Un archivo a la vez.", result.stdout + result.stderr)
        # A preset that is not there is named, and the path of the
        # configuration file stays literal.
        result = self.run_commands("option preset nosuchpreset", env=spanish)
        self.assertEqual(result.returncode, 1)
        self.assertIn("No hay ningún preajuste de transferencia llamado "
                      "'nosuchpreset'",
                      result.stdout + result.stderr)

    def test_default_abort(self):
        for file in (False, True):
            with self.subTest(file=file):
                result = self.run_commands("invalid-command; echo SHOULD_NOT_RUN", file)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

    def test_batch_modes(self):
        for file in (False, True):
            for mode in ("on", "abort", "off", "continue"):
                with self.subTest(mode=mode, file=file):
                    result = self.run_commands(
                        f"option batch {mode}; invalid-command; echo AFTER_ERROR", file)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual("AFTER_ERROR" in result.stdout,
                                     mode in ("off", "continue"))

    def test_batch_queries(self):
        for mode in ("on", "abort", "off", "continue"):
            with self.subTest(mode=mode):
                result = self.run_commands(f"option batch {mode}; option batch")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("batch = " + mode, result.stdout)

    def test_reject_noop_options(self):
        for command in ("option reconnecttime2 10", "option batch garbage",
                        "option transfer nonsense", "option reconnecttime nope",
                        "option include *.txt|bad|mask"):
            with self.subTest(command=command):
                result = self.run_commands(command + "; echo SHOULD_NOT_RUN")
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

    def test_option_abbreviations(self):
        # An unambiguous abbreviation names one option, like the upstream
        # command table; an ambiguous one is refused instead of guessing.
        result = self.run_commands("option synchdel on; option synchdelete")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("synchdelete = on", result.stdout)
        result = self.run_commands("option transfer asc; option transfer")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("transfer = ascii", result.stdout)
        # 'e' could be echo, editor, editmaxsize or exclude; the client must
        # not guess which one a script meant.
        for command in ("option e on", "option ed nano", "option re 10"):
            with self.subTest(command=command):
                result = self.run_commands(command + "; echo SHOULD_NOT_RUN")
                self.assertEqual(result.returncode, 1)
                self.assertIn("ambiguous", result.stderr)
                self.assertNotIn("SHOULD_NOT_RUN", result.stdout)
        # An unambiguous abbreviation of both name and value is accepted.
        result = self.run_commands("option bat cont; option batch")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("batch = continue", result.stdout)

    def test_command_abbreviations(self):
        result = self.run_commands("opt bat cont; echo AFTER")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("AFTER", result.stdout)
        # 'se' could be session or sessions, and 'l' lcd, lls, ln, lpwd or
        # ls; guessing is refused, while 'co' unambiguously means copyid.
        for command in ("se", "s", "l"):
            with self.subTest(command=command):
                result = self.run_commands(command)
                self.assertEqual(result.returncode, 1)
                self.assertIn("ambiguous", result.stderr)
        # An unambiguous abbreviation reaches the command itself.
        result = self.run_commands("synch local")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("ambiguous", result.stderr)
        self.assertNotIn("Unknown command", result.stderr)
        # A name that matches nothing is still an unknown command.
        result = self.run_commands("nosuchcommand")
        self.assertIn("Unknown command", result.stderr)

    def test_script_parameters(self):
        # %1% .. %9%, environment variables and %TIMESTAMP% are expanded
        # before the command is parsed, as the upstream console does.
        env = {"LSCP_TEST_PARAM": "from-env"}
        with tempfile.TemporaryDirectory() as tmp:
            script = pathlib.Path(tmp) / "s.txt"
            script.write_text("echo %1%-%2%-end\n", encoding="utf-8")
            result = subprocess.run(
                [BINARY, "-script=" + str(script), "-parameter", "one", "two"],
                capture_output=True, text=True, timeout=10,
                env=self.environment(env))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("one-two-end", result.stdout)
        result = subprocess.run(
            [BINARY, "-command=echo [%LSCP_TEST_PARAM%]", "-parameter", "x"],
            capture_output=True, text=True, timeout=10, env=self.environment(env))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[from-env]", result.stdout)
        # An unset variable is left alone rather than turned into nothing,
        # and so is a parameter that was not given.
        result = self.run_commands("echo [%NO_SUCH_VAR%] [%3%]")
        self.assertIn("[%NO_SUCH_VAR%] [%3%]", result.stdout)
        # A malformed timestamp offset fails instead of transferring to a
        # path that still contains the placeholder.
        result = self.run_commands("echo %TIMESTAMP-1Q#yyyymmdd%")
        self.assertEqual(result.returncode, 1)
        self.assertIn("is not valid", result.stderr)
        result = self.run_commands("echo %TIMESTAMP#yyyymmdd%")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout.strip(), r"^[0-9]{8}$")

    def test_literal_commands_preserve_file_names_with_percent_signs(self):
        # The task queue uses -command rather than the persistent -server.
        # Neither a timestamp nor an environment variable in a file name
        # must be expanded on the way to the transfer process.
        env = self.environment({"LSCP_TEST_DROP": "expanded"})
        result = subprocess.run(
            [BINARY, "-literal", "-command=echo %TIMESTAMP% %LSCP_TEST_DROP%"],
            capture_output=True, text=True, timeout=10, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("%TIMESTAMP% %LSCP_TEST_DROP%", result.stdout)
        result = subprocess.run(
            [BINARY, "-command=echo %LSCP_TEST_DROP%"],
            capture_output=True, text=True, timeout=10, env=env)
        self.assertIn("expanded", result.stdout)
        result = subprocess.run([BINARY, "-literal", "-script=-"], input="echo bad\n",
                                capture_output=True, text=True, timeout=10, env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("-literal requires -command", result.stderr)

    def test_parameters_are_not_expanded_in_server_mode(self):
        # The GUI talks to -server and may send a file name that holds a
        # percent sign; those lines are commands, not templates.
        result = subprocess.run([BINARY, "-server"], input="echo %1%\n",
                                capture_output=True, text=True, timeout=10,
                                env=self.environment())
        self.assertIn("LSCP-RESULT 0", result.stdout)
        self.assertIn("%1%", result.stdout)

    def test_transfer_modes_are_real_options(self):
        # ascii/automatic and reconnecttime used to be rejected; they are
        # implemented now, so they must stop the run with success.
        for command in ("option transfer ascii", "option transfer automatic",
                        "ascii", "binary", "option reconnecttime 30",
                        "option echo on", "option failonnomatch on",
                        "option synchdelete on", "option include *.txt",
                        "option exclude *.bak"):
            with self.subTest(command=command):
                result = self.run_commands(command + "; echo OK")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("OK", result.stdout)

    def test_option_listing(self):
        # 'option' with no name lists every supported option.
        result = self.run_commands("option")
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("echo", "batch", "confirm", "resume", "transfer",
                     "include", "exclude", "failonnomatch", "synchdelete",
                     "reconnecttime", "editor", "editmaxsize"):
            self.assertIn(name + " = ", result.stdout)
        # The default resume mode is upstream's 'automatic' (rsSmart):
        # binary files from a 100 KB threshold stage through .filepart.
        self.assertIn("resume = automatic", result.stdout)

    def test_option_resume_values(self):
        for value, shown in (("on", "on"), ("off", "off"),
                             ("automatic", "automatic"), ("aut", "automatic")):
            with self.subTest(value=value):
                result = self.run_commands(f"option resume {value}; option resume")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("resume = " + shown, result.stdout)
        result = self.run_commands("option resume sometimes")
        self.assertEqual(result.returncode, 1)
        self.assertIn("on, off or automatic", result.stderr)
        # 'option resume on' forces binary transfers, so an ASCII transfer
        # is refused before any connection, like an explicit -resume.
        result = self.run_commands("option resume on; get -transfer=ascii x /tmp/")
        self.assertEqual(result.returncode, 1)
        self.assertIn("binary only", result.stderr)
        self.assertNotIn("Not connected", result.stderr)

    def test_option_echo_prints_commands(self):
        result = self.run_commands("option echo on; echo HELLO")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("echo HELLO", result.stdout)
        self.assertIn("HELLO", result.stdout)

    def test_ascii_resume_is_rejected_before_connection(self):
        for command in ("get -transfer=ascii -resume x /tmp/", "put -resume -transfer=automatic x /tmp/"):
            with self.subTest(command=command):
                result = self.run_commands(command)
                self.assertEqual(result.returncode, 1)
                self.assertIn("binary only", result.stderr)
                self.assertNotIn("Not connected", result.stderr)

    def test_reject_transfer_switches_before_connection(self):
        # Implemented switches (filemask, transfer modes, permissions) pass
        # the switch check and stop at the connection; the rest is refused
        # up front instead of being silently ignored.
        for command in ("get", "recv", "mget", "put", "send", "mput"):
            for switch in ("-resumegarbage", "-resume=off", "-speed=x", "-speed=1K",
                           "-unknown", "-latest", "-criteria=time",
                           "-transfer=garbage", "-filemask=",
                           "-filemask=*.txt|*.a|*.b", "-permissions=999",
                           "-preservetime=hours", "-resumesupport=maybe",
                           "-append -resume"):
                with self.subTest(command=command, switch=switch):
                    result = self.run_commands(f"{command} {switch} source destination")
                    self.assertEqual(result.returncode, 1)
                    self.assertTrue("Unsupported switch" in result.stderr or
                                    "Wrong arguments" in result.stderr,
                                    result.stderr)
                    self.assertNotIn("Not connected", result.stderr)

    def test_transfer_switches_are_accepted(self):
        for command in ("get", "recv", "mget", "put", "send", "mput"):
            for switch in ("-filemask=*.txt|*.bak",
                           "-filemask=*.jpg>1K<1M",
                           "-transfer=binary", "-transfer=ascii",
                           "-transfer=asc", "-transfer=automatic",
                           "-speed=10", "-speed=0", "-resumesupport=on",
                           "-resumesupport=off", "-resumesupport=1024",
                           "-preservetime=all", "-noneweronly", "-append",
                           "-nopreservetime", "-neweronly"):
                with self.subTest(command=command, switch=switch):
                    result = self.run_commands(f"{command} {switch} source destination")
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("Not connected", result.stderr)

    def test_transfer_aliases_dispatch(self):
        for command in ("get", "recv", "mget", "put", "send", "mput"):
            with self.subTest(command=command):
                result = self.run_commands(f"{command} -transfer=binary source destination")
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("Unknown command", result.stderr)
                self.assertNotIn("Unsupported switch", result.stderr)

    def test_sync_validation(self):
        for args in ("local -criteria=whenever",
                     "local -filemask=*.txt>garbage", "sideways", "local a b c", ""):
            with self.subTest(args=args):
                result = self.run_commands("synchronize " + args)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Wrong arguments", result.stderr)

    def test_sync_delete_needs_a_connection(self):
        # 'both -delete' is no longer rejected outright: the recorded
        # state decides what is obsolete. It still needs a server.
        result = self.run_commands("synchronize both -delete /tmp /tmp")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Wrong arguments", result.stderr)
        self.assertIn("Not connected", result.stderr)

    def test_sync_criteria_values(self):
        """'-criteria=' takes upstream's words ('none', 'either', 'both') and
        a comma-separated list of the three comparisons, including
        'checksum'. Anything else is refused with the words that are known,
        rather than being quietly dropped as upstream does."""
        for value in ("time", "size", "either", "both", "none", "checksum",
                      "CHECKSUM", "time,size", "time,checksum",
                      "size,checksum", "time,size,checksum"):
            with self.subTest(value=value):
                result = self.run_commands(
                    "synchronize local -criteria=%s /tmp /tmp" % value)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Not connected", result.stderr)
        for value in ("whenever", "sha256", "check", "time,", ",size",
                      "time,,size", "none,time", "either,size",
                      "checksum,none", "time,none"):
            with self.subTest(value=value):
                result = self.run_commands(
                    "synchronize local -criteria=%s /tmp /tmp" % value)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Wrong arguments", result.stderr)
                self.assertNotIn("Not connected", result.stderr)
        # The refusal names every word that is accepted.
        result = self.run_commands("synchronize local -criteria=whenever /tmp /tmp")
        for word in ("none", "either", "both", "time", "size", "checksum"):
            self.assertIn(word, result.stderr)
        # 'keepuptodate' takes the same switches and has no 'both' mode.
        result = self.run_commands("keepuptodate -criteria=time,checksum /tmp /tmp")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Not connected", result.stderr)
        # The help of the command documents the new value.
        result = self.run_commands("help synchronize")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("checksum", result.stdout)

    def test_sync_both_direction_refuses_criteria_it_cannot_honour(self):
        """In the 'both' direction the record of the previous
        synchronization decides, so a criteria value it could not apply is
        refused instead of being ignored (upstream drops the criteria for
        smBoth)."""
        for value, why in (("checksum",
                            "record of the previous synchronization"),
                           ("none", "no way to tell which side changed")):
            with self.subTest(value=value):
                result = self.run_commands(
                    "synchronize both -criteria=%s /tmp /tmp" % value)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Wrong arguments", result.stderr)
                self.assertIn(why, result.stderr)
                self.assertNotIn("Not connected", result.stderr)
        # The comparisons the 'both' direction does make still parse.
        for value in ("time", "size", "either", "both", "time,size"):
            with self.subTest(value=value):
                result = self.run_commands(
                    "synchronize both -criteria=%s /tmp /tmp" % value)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Not connected", result.stderr)

    def test_keepuptodate_validation(self):
        # 'keepuptodate' takes no direction word; its local directory is
        # the source and the remote directory is the target, as upstream
        # documents. Bare directories parse fine and stop at connection check.
        for args in ("", "sideways"):
            with self.subTest(args=args):
                result = self.run_commands("keepuptodate " + args)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Not connected", result.stderr)
        result = self.run_commands("keepuptodate local /tmp /tmp")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Wrong arguments", result.stderr)
        self.assertNotIn("Not connected", result.stderr)
        for args in ("local -bogus", "a b c"):
            with self.subTest(args=args):
                result = self.run_commands("keepuptodate " + args)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Wrong arguments", result.stderr)
        # Without a terminal it needs a fixed number of passes.
        result = self.run_commands("keepuptodate /tmp /tmp")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Not connected", result.stderr)

    def test_edit_needs_a_connection(self):
        result = self.run_commands("edit /tmp/file.txt")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Not connected", result.stderr)

    def test_help_and_delsession_aliases(self):
        result = self.run_commands("?")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.run_commands("help").stdout)
        result = self.run_commands("savesession alias-site -host=example.com; delsession alias-site; sessions")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no stored sessions", result.stdout)

    def test_stored_sessions(self):
        result = self.run_commands("sessions")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no stored sessions", result.stdout)

        result = self.run_commands(
            "savesession demo -host=demo.example.com -username=alice -port=2222")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Stored session 'demo'", result.stdout)

        result = self.run_commands("sessions")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("demo", result.stdout)
        self.assertIn("sftp://alice@demo.example.com:2222", result.stdout)

        # The file the graphical client reads is the one written here.
        stored = pathlib.Path(self.config) / "sessions.ini"
        self.assertTrue(stored.is_file())
        text = stored.read_text(encoding="utf-8")
        self.assertIn("[demo]", text)
        self.assertIn("host=demo.example.com", text)
        self.assertIn("port=2222", text)
        self.assertNotIn("password", text)

        result = self.run_commands("rmsession demo")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_commands("sessions")
        self.assertIn("no stored sessions", result.stdout)

    def test_savesession_stores_password_encrypted(self):
        """A password given to savesession is written encrypted under a
        key file, never in the clear, and the session list stays quiet
        about it."""
        import base64

        result = self.run_commands(
            "savesession secret -host=secret.example.com -username=alice "
            "-password=hunter2-plain")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("stored encrypted", result.stdout)
        self.assertIn("sessions.key", result.stdout)

        stored = pathlib.Path(self.config) / "sessions.ini"
        keyfile = pathlib.Path(self.config) / "sessions.key"
        text = stored.read_text(encoding="utf-8")
        self.assertNotIn("hunter2-plain", text)
        self.assertIn("password=lscp1$", text)
        self.assertTrue(keyfile.is_file())
        key = base64.b64decode(keyfile.read_text().strip())
        self.assertEqual(len(key), 32)
        # Group or world readable is a bug, whatever the umask was.
        self.assertEqual(keyfile.stat().st_mode & 0o077, 0)

        # The listing shows the session, never the password.
        result = self.run_commands("sessions")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("hunter2", result.stdout)

        # Saving again without -password clears a password it could read
        # (the documented way to remove one).
        result = self.run_commands(
            "savesession secret -host=secret.example.com -username=alice")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("password=", stored.read_text(encoding="utf-8"))

    def test_savesession_stores_the_password_from_the_environment(self):
        """'savesession <name> -password' stores the password the run knows
        without stating it: the graphical client passes its password in
        LINSCP_PASSWORD so that it never appears on a command line, and
        this is how it asks for that value to be stored."""
        result = self.run_commands(
            "savesession envstored -host=env.example.com -password",
            env={"LINSCP_PASSWORD": "from-the-environment"})
        self.assertEqual(result.returncode, 0, result.stderr)
        stored = pathlib.Path(self.config) / "sessions.ini"
        text = stored.read_text(encoding="utf-8")
        self.assertIn("password=lscp1$", text)
        self.assertNotIn("from-the-environment", text)

    def test_savesession_keeps_a_password_it_cannot_decrypt(self):
        """Without the key file the encrypted value is unreadable, and an
        unrelated re-save must not destroy what it cannot see."""
        import base64

        result = self.run_commands(
            "savesession locked -host=locked.example.com -password=keepme")
        self.assertEqual(result.returncode, 0, result.stderr)

        stored = pathlib.Path(self.config) / "sessions.ini"
        keyfile = pathlib.Path(self.config) / "sessions.key"
        text = stored.read_text(encoding="utf-8")
        blob = None
        for line in text.splitlines():
            if line.startswith("password="):
                blob = line.split("=", 1)[1]
        self.assertIsNotNone(blob)
        self.assertTrue(blob.startswith("lscp1$"))
        self.assertNotIn("keepme", text)
        saved_key = keyfile.read_bytes()
        keyfile.unlink()

        # Re-save without the password: the entry is replaced, but the
        # value it could not decrypt stays exactly as it was.
        result = self.run_commands(
            "savesession locked -host=locked.example.com -port=22")
        self.assertEqual(result.returncode, 0, result.stderr)
        text = stored.read_text(encoding="utf-8")
        self.assertIn("password=" + blob, text)
        self.assertNotIn("keepme", text)

        # With the key restored the same value decrypts again (the core
        # reports the failure rather than using an empty password; the
        # success side is covered by the live suite).
        keyfile.write_bytes(saved_key)
        key = base64.b64decode(saved_key.decode().strip())
        self.assertEqual(len(key), 32)

    def test_session_export_import(self):
        self.run_commands("savesession one -host=one.example.com")
        exported = pathlib.Path(self.config) / "exported.ini"
        result = self.run_commands(f'sessions export "{exported}"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Exported 1 session", result.stdout)
        self.assertTrue(exported.is_file())

        result = self.run_commands("rmsession one")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_commands(f'sessions import "{exported}"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Imported 1 session", result.stdout)
        result = self.run_commands("sessions")
        self.assertIn("one.example.com", result.stdout)

    def test_savesession_rejects_unknown_switches(self):
        for args in ("demo", "demo -nonsense=1", ""):
            with self.subTest(args=args):
                result = self.run_commands("savesession " + args)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Wrong arguments", result.stderr)

    def test_savesession_rejects_a_port_it_cannot_use(self):
        """A stored site is opened later by a script that cannot ask, so
        its port has to be whole and in range when it is stored.

        atoi() stopped at the first character that was not a digit and
        returned 0 for text: '-port=22x' stored port 22, '-port=99999'
        stored a port nothing listens on, '-port=ssh' stored no port at
        all, and every one of them reported that the site was stored.
        """
        for value in ("abc", "22x", "0", "-5", "65536", "99999",
                      "12345678901234567890"):
            with self.subTest(port=value):
                result = self.run_commands(
                    "savesession demo -host=demo.example.com -port=" + value)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Invalid port number", result.stderr)
        stored = pathlib.Path(self.config) / "sessions.ini"
        if stored.is_file():
            self.assertNotIn("port=", stored.read_text(encoding="utf-8"))

        for value in ("1", "22", "2222", "65535"):
            with self.subTest(port=value):
                result = self.run_commands(
                    "savesession demo -host=demo.example.com -port=" + value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Stored session 'demo'", result.stdout)
                self.assertIn(
                    "port=" + value,
                    (pathlib.Path(self.config) / "sessions.ini").read_text(
                        encoding="utf-8"))
                self.assertEqual(
                    self.run_commands("rmsession demo").returncode, 0)

    def test_savesession_clears_a_preset_with_an_empty_value(self):
        """'-preset=' is the documented way to clear a stored preset.

        The prefix test behind every switch of this command asked for one
        character more than the prefix, so a switch whose value is
        legitimately empty was reported as an unknown switch - including
        this one, which the command's own help offers.
        """
        stored = pathlib.Path(self.config) / "sessions.ini"
        self.assertEqual(
            self.run_commands("savepreset fast transfer=binary").returncode, 0)
        result = self.run_commands(
            "savesession demo -host=demo.example.com -preset=fast")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("preset=fast", stored.read_text(encoding="utf-8"))

        result = self.run_commands(
            "savesession demo -host=demo.example.com -preset=")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Stored session 'demo'", result.stdout)
        self.assertNotIn("preset=", stored.read_text(encoding="utf-8"))

    def test_savesession_rejects_a_protocol_nothing_connects_with(self):
        """A stored site is opened later by a script that cannot ask.

        The protocol was stored as written, so a site could be saved under
        a scheme no engine here serves - an empty one included, which the
        session list then printed as '://@host'.
        """
        for value in ("bogus", "file", "sftp:", "webdav2"):
            with self.subTest(protocol=value):
                result = self.run_commands(
                    "savesession demo -host=demo.example.com -protocol=" + value)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Unsupported protocol", result.stderr)
        stored = pathlib.Path(self.config) / "sessions.ini"
        for value, written in (("sftp", "sftp"), ("SFTP", "sftp"),
                               ("scp", "scp"), ("ftpes", "ftp"),
                               ("ftps", "ftps"), ("webdav", "webdav"),
                               ("s3", "s3")):
            with self.subTest(protocol=value):
                result = self.run_commands(
                    "savesession demo -host=demo.example.com -protocol=" + value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("protocol=" + written,
                              stored.read_text(encoding="utf-8"))
                self.assertEqual(
                    self.run_commands("rmsession demo").returncode, 0)

    def test_savesession_stores_the_port_of_the_protocol(self):
        """A site stored without -port= takes the port of its protocol.

        The session defaults carry the SSH port, and a site saved from
        them with '-protocol=ftp' kept it: 'open' then spoke FTP to port
        22, where an SSH banner answered. An explicit -port=, and the
        SSH port of an SSH protocol, are kept as they are.
        """
        stored = pathlib.Path(self.config) / "sessions.ini"
        cases = (("sftp", "", "22"), ("scp", "", "22"), ("ftp", "", "21"),
                 ("ftps", "", "990"), ("ftp", " -rawsettings Ftps=1", "990"),
                 ("dav", "", "80"), ("webdav", "", "443"), ("s3", "", "443"),
                 ("ftp", " -port=2121", "2121"), ("s3", " -port=9000", "9000"))
        for protocol, extra, port in cases:
            with self.subTest(protocol=protocol, extra=extra):
                result = self.run_commands(
                    "savesession demo -host=demo.example.com -protocol="
                    + protocol + extra)
                self.assertEqual(result.returncode, 0, result.stderr)
                text = stored.read_text(encoding="utf-8")
                self.assertIn("protocol=" + protocol, text)
                self.assertIn("port=" + port + "\n", text)
                self.assertEqual(
                    self.run_commands("rmsession demo").returncode, 0)
        # A port given on the command line is the user's, whatever the
        # protocol's own default is.
        result = subprocess.run(
            [BINARY, "-port=2222",
             "-command=savesession demo -host=demo.example.com -protocol=sftp"],
            capture_output=True, text=True, timeout=10, env=self.environment())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("port=2222\n", stored.read_text(encoding="utf-8"))

    def test_keepuptodate_reads_its_numbers_strictly(self):
        """'-interval=12abc' was 12 seconds and '-count=2xyz' two passes.

        A mistyped value became a different interval rather than an
        error, and the watch ran on it. Both switches are read before the
        connection is asked for, so this needs no server.
        """
        for switch in ("-interval=12abc", "-interval=abc", "-interval=0",
                       "-interval=86401", "-count=2xyz", "-count=0",
                       "-count=-1"):
            with self.subTest(switch=switch):
                result = self.run_commands("keepuptodate %s %s %s"
                                           % (os.devnull, os.devnull, switch))
                self.assertEqual(result.returncode, 1)
                self.assertIn("Wrong arguments of 'keepuptodate'",
                              result.stderr)
        # Values that parse reach the connection, and say so.
        result = self.run_commands(
            "keepuptodate %s %s -interval=30 -count=1" % (os.devnull,
                                                          os.devnull))
        self.assertEqual(result.returncode, 1)
        self.assertIn("Not connected", result.stderr)

    def test_edit_reads_its_monitor_count_strictly(self):
        for value in ("3abc", "abc", "0", "-1"):
            with self.subTest(value=value):
                result = self.run_commands("edit -monitor=%s /no/such/file"
                                           % value)
                self.assertEqual(result.returncode, 1)
                self.assertIn("The value of '-monitor'", result.stderr)
        # A count that parses reaches the connection instead: the switches
        # are read before a session is asked for, the way 'synchronize' and
        # 'keepuptodate' read theirs.
        result = self.run_commands("edit -monitor=2 /no/such/file")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Not connected", result.stderr)

    def test_every_command_the_help_lists_has_its_own_help(self):
        """'help <command>' answers for every command it lists.

        'etag' dispatched but had no help entry, so 'help etag' answered
        "Unknown command 'etag'" for a command that worked - the one place
        a user can ask what a switch does refused the command that had it.
        """
        listing = self.run_commands("help")
        self.assertEqual(listing.returncode, 0, listing.stderr)
        names = [line.split()[0] for line in listing.stdout.splitlines()
                 if line and not line[0].isspace()]
        self.assertIn("etag", names)
        self.assertIn("get", names)
        self.assertGreater(len(names), 40)
        for name in names:
            with self.subTest(command=name):
                result = self.run_commands("help " + name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("Unknown command",
                                 result.stdout + result.stderr)
                self.assertTrue(result.stdout.split("\n")[0].startswith(name))

    def test_editor_options(self):
        result = self.run_commands("option editor vim; option editor")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("editor = vim", result.stdout)
        for value in ("abc", "0", "-5"):
            with self.subTest(value=value):
                result = self.run_commands("option editmaxsize " + value)
                self.assertEqual(result.returncode, 1)
                self.assertIn("Wrong arguments", result.stderr)
        result = self.run_commands("option editmaxsize 4096; option editmaxsize")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("editmaxsize = 4096", result.stdout)

    def test_command_server(self):
        # The graphical client talks to this: one command per line on
        # stdin, with the outcome of each one marked.
        with tempfile.TemporaryDirectory() as tmp:
            script = pathlib.Path(tmp) / "server.txt"
            script.write_text("echo first\necho second\nbogus-command\nexit\n",
                              encoding="utf-8")
            with open(script, "rb") as handle:
                result = subprocess.run([BINARY, "-server"], stdin=handle,
                                        capture_output=True, text=True, timeout=20,
                                        env=self.environment())
        self.assertEqual(result.returncode, 1)  # 'bogus-command' failed
        self.assertIn("LSCP-SERVER 1 ready", result.stdout)
        self.assertEqual(result.stdout.count("LSCP-RESULT"), 4)
        self.assertIn("LSCP-RESULT 0", result.stdout)
        self.assertIn("LSCP-RESULT 1", result.stdout)
        self.assertIn("Unknown command 'bogus-command'", result.stderr)

    def test_server_rejects_command_options(self):
        result = subprocess.run([BINARY, "-server", "-command=echo x"],
                                capture_output=True, text=True, timeout=10,
                                env=self.environment())
        self.assertEqual(result.returncode, 1)
        self.assertIn("-server", result.stderr)

    def test_local_listing(self):
        with tempfile.TemporaryDirectory(prefix="linscp script ") as tmp:
            root = pathlib.Path(tmp)
            (root / "hello world.txt").write_text("data")
            (root / "other.bin").write_bytes(b"data")
            (root / "directory").mkdir()
            result = self.run_commands(f'lls "{root}"')
            self.assertEqual(result.returncode, 0, result.stderr)
            # Upstream's columns: date, time, size (or <DIR>), then name.
            lines = result.stdout.splitlines()
            self.assertEqual(len(lines), 3)
            self.assertRegex(lines[0], r"\d{2}:\d{2} +<DIR> +directory$")
            self.assertRegex(lines[1], r"\d{2}:\d{2} +4 hello world\.txt$")
            self.assertRegex(lines[2], r"\d{2}:\d{2} +4 other\.bin$")
            result = self.run_commands(f'lls "{root / "*.txt"}"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(result.stdout.splitlines()), 1)
            self.assertRegex(result.stdout,
                             r"\d{2}:\d{2} +4 hello world\.txt$")
            # A path that matches nothing is a no-match line, not a
            # failure - unless failonnomatch turns it into one.
            result = self.run_commands(f'lls "{root / "missing"}"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("No files found matching", result.stdout)
            self.assertIn("No such file or directory", result.stdout)
            result = self.run_commands(f'lls "{root / "*.none"}"')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("No files found matching '*.none'", result.stdout)
            result = self.run_commands(
                f'option failonnomatch on; lls "{root / "missing"}"')
            self.assertEqual(result.returncode, 1)
            self.assertIn("No files found matching", result.stderr)

    def test_help_lists_commands_and_command_help(self):
        """'help' lists every command in upstream's name/description
        columns; 'help <command>' (aliases included) prints its help."""
        result = self.run_commands("help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"(?m)^ascii\s+Transfers files")
        self.assertRegex(result.stdout,
                         r"(?m)^session\s+Lists the open sessions")
        self.assertRegex(result.stdout, r"(?m)^attr\s+Prints path, size")
        result = self.run_commands("man")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"(?m)^ascii\s+Transfers files")
        result = self.run_commands("help rename")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mv <source>", result.stdout)
        result = self.run_commands("help nosuchthing")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Unknown command", result.stderr)

    def test_exit_and_bye_end_the_script(self):
        """exit and bye stop the script where they are, like upstream's
        continue flag: nothing after them runs."""
        for stopper in ("exit", "bye"):
            with self.subTest(stopper=stopper):
                result = self.run_commands(f"echo ONE; {stopper}; echo TWO")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("ONE", result.stdout)
                self.assertNotIn("TWO", result.stdout)

    def test_lcd_prints_where_it_went(self):
        """lcd reports the directory it changed into, like cd does."""
        with tempfile.TemporaryDirectory(prefix="linscp lcd ") as tmp:
            result = self.run_commands(f'lpwd; lcd "{tmp}"; lpwd; echo MARK')
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = result.stdout.splitlines()
            changed = lines[1]
            self.assertIn(changed, (str(pathlib.Path(tmp)),
                                    str(pathlib.Path(tmp).resolve())))
            self.assertEqual(lines[2], changed)
            self.assertIn("MARK", result.stdout)
            result = self.run_commands(f'lcd "{tmp}/nope-here"; echo AFTER')
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("AFTER", result.stdout)

    def test_show_is_refused_with_the_reason(self):
        """'show' exists only to say that this build has no shell state:
        the connection runs the SFTP subsystem."""
        result = self.run_commands("show ; echo AFTER")
        self.assertEqual(result.returncode, 1)
        self.assertIn("SFTP subsystem", result.stderr)
        self.assertNotIn("AFTER", result.stdout)

    def test_exit_aliases_end_the_script(self):
        """quit and end stand for exit; '?' stands for help."""
        for stopper in ("quit", "end"):
            with self.subTest(stopper=stopper):
                result = self.run_commands(f"echo ONE; {stopper}; echo TWO")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("ONE", result.stdout)
                self.assertNotIn("TWO", result.stdout)
        result = self.run_commands("?")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, r"(?m)^ascii\s+Transfers files")

    def test_sync_alias_reaches_synchronize(self):
        """'sync' validates as synchronize does - an unknown switch is
        named as such rather than as an unknown command."""
        result = self.run_commands(
            "sync local -criteria=whenever ; echo AFTER")
        self.assertEqual(result.returncode, 1)
        self.assertIn("synchronize", result.stderr)
        self.assertNotIn("Unknown command", result.stderr)

    def test_session_and_close_need_a_connection(self):
        """Like upstream's CheckSession, 'session' and 'close' refuse to
        run before anything is open - argument checks happen after."""
        for command in ("session", "session 1", "close", "close 1",
                        "close 2"):
            with self.subTest(command=command):
                result = self.run_commands(command + "; echo AFTER")
                self.assertEqual(result.returncode, 1)
                self.assertIn("Not connected", result.stderr)
                self.assertNotIn("AFTER", result.stdout)


    def test_xml_action_log(self):
        """'-xmllog=' writes a parseable log of what the script did."""
        import xml.etree.ElementTree as ET
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / "actions.xml"
            # 'batch continue' keeps the run going past the two failures, so
            # that the log holds several commands of each kind.
            result = subprocess.run(
                [BINARY, "-xmllog=" + str(log), "-batch",
                 "-command=option batch continue ; echo text ; "
                 "no-such-command ; open sftp://user:secret@127.0.0.1:1/"],
                capture_output=True, text=True, timeout=30,
                env=self.environment())
            self.assertTrue(log.exists(), result.stderr)
            root = ET.parse(log).getroot()
            self.assertEqual(root.tag, "log_session")
            self.assertIn("LinSCP", root.get("client", ""))
            self.assertTrue(root.get("created"))
            elements = [element.tag for element in root]
            self.assertIn("command", elements)
            self.assertIn("result", elements)
            lines = [element.get("line", "").strip() for element in root
                     if element.tag == "command"]
            self.assertEqual(len(lines), 4, lines)
            self.assertEqual(lines[1], "echo text")
            self.assertEqual(lines[2], "no-such-command")
            statuses = [element.get("status") for element in root
                        if element.tag == "result"]
            self.assertEqual(statuses, ["ok", "ok", "error", "error"])
            kinds = dict((element.get("type"), 0) for element in root
                         if element.tag == "message")
            self.assertEqual(sorted(kinds), ["error", "output"])
            messages = [element.text or "" for element in root
                        if element.tag == "message"]
            self.assertIn("text", "".join(messages))
            self.assertIn("Unknown command", "".join(messages))
            # A password must not be written to a file the user keeps.
            self.assertNotIn("secret", log.read_text(encoding="utf-8"))

    def test_xml_action_log_is_closed(self):
        """The log ends in one complete document, not in a half element."""
        import xml.etree.ElementTree as ET
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / "closed.xml"
            subprocess.run([BINARY, "-xmllog=" + str(log), "-batch",
                            "-command=echo one"],
                           capture_output=True, text=True, timeout=30,
                           env=self.environment())
            root = ET.parse(log).getroot()
            self.assertEqual([element.tag for element in root][-1], "result")

    def test_copyid_arguments(self):
        result = self.run_commands("copyid one two; echo SHOULD_NOT_RUN")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Syntax: copyid", result.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

    def test_chmod_modes_are_parsed(self):
        # A symbolic mode is a mode: only the missing connection may be
        # complained about, and that happens after the arguments are checked.
        for command in ("chmod u+x file", "chmod a=r,go-w file",
                        "chmod 640 file -recursive", "chmod -recursive 700 file",
                        "chmod a+r file +x", "chmod a+r file +q",
                        # chmod(1) allows '=' with no letters after it,
                        # and a '=' clears the class special bit.
                        "chmod a= file", "chmod u=rw,g=,o=r file",
                        "chmod u=-w file"):
            with self.subTest(command=command):
                result = self.run_commands(command)
                self.assertEqual(result.returncode, 1)
                self.assertNotIn("Wrong arguments", result.stderr)
                self.assertIn("Not connected", result.stderr)
        for command in ("chmod 999 file", "chmod u?q file", "chmod a+r",
                        "chmod u+ file", "chmod , file", "chmod -recursive",
                        "chmod 12345 file"):
            # Everything after the mode is a file name, so a stray '+q' is
            # not a syntax error; that case is in the accepted list above.
            with self.subTest(rejected=command):
                result = self.run_commands(command + "; echo SHOULD_NOT_RUN")
                self.assertEqual(result.returncode, 1)
                self.assertIn("Wrong arguments", result.stderr)
                self.assertNotIn("SHOULD_NOT_RUN", result.stdout)


    def test_open_fails_on_unreachable_endpoint(self):
        """'open' has to report an endpoint that is not there.

        Neither SSH protocol keeps a connection open between commands -
        sftp:// opens one per session and scp:// one per command, and the
        curl-backed protocols have none of their own at all - so a dead port
        would otherwise be reported as a successful open and each command
        would fail on its own. The classification of an endpoint that does
        answer is covered by
        test_open_accepts_a_server_that_refuses_the_start_directory.
        """
        for protocol in ("sftp", "scp"):
            with self.subTest(protocol=protocol):
                result = self.run_commands(
                    f"open {protocol}://user:secret@127.0.0.1:1/ ; echo SHOULD_NOT_RUN")
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn("SHOULD_NOT_RUN", result.stdout)
                self.assertIn("Cannot open session", result.stderr)

    def test_open_accepts_a_server_that_refuses_the_start_directory(self):
        """Reaching the server is enough; a start directory it will not list
        is the command's problem, not the connection's. Without that
        distinction the reachability check would reject valid sessions."""
        import functools
        import http.server
        import threading
        with tempfile.TemporaryDirectory() as tmp:
            handler = functools.partial(http.server.SimpleHTTPRequestHandler,
                                        directory=tmp)
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
            port = server.server_address[1]
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                result = self.run_commands(
                    f"open http://127.0.0.1:{port}/missing-dir/ ; echo CONNECTED")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("CONNECTED", result.stdout)
            finally:
                server.shutdown()
                server.server_close()

    def test_transfer_presets_and_permission_switches(self):
        """Transfer presets end to end without a server: store, list,
        update, remove, activate through 'option', per-site storage, and
        the download form of '-permissions' plus '-rawtransfersettings'
        validation."""
        # store, list, update, remove
        result = self.run_commands(
            "savepreset asciitxt -transfer=ascii -preservetime=on "
            "-mask=*.txt; presets")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("transfer=ascii", result.stdout)
        self.assertIn("mask=*.txt", result.stdout)
        result = self.run_commands(
            "savepreset asciitxt -transfer=binary; presets")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("transfer=binary", result.stdout)
        self.assertNotIn("transfer=ascii", result.stdout)
        result = self.run_commands("rmspreset nosuchpreset")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no transfer preset named", result.stderr)

        # activate, show, clear; unknown names are refused loudly
        result = self.run_commands(
            "savepreset p1 -transfer=binary; option preset p1; option")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("preset = p1", result.stdout)
        result = self.run_commands("option preset nosuchpreset")
        self.assertEqual(result.returncode, 1)
        self.assertIn("There is no transfer preset named", result.stderr)
        result = self.run_commands("option preset p1; option preset off; option")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("preset = off", result.stdout)

        # a site stores and validates its preset
        result = self.run_commands(
            "savesession sx -host=host.example -preset=unknownpreset")
        self.assertEqual(result.returncode, 1)
        self.assertIn("no transfer preset named", result.stderr)
        result = self.run_commands(
            "savepreset p1 -transfer=binary; "
            "savesession sx -host=host.example -preset=p1; sessions")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("(preset p1)", result.stdout)

        # '-permissions' without a value is understood on both directions
        # (the run stops at the missing connection, not at the switch)
        for command in ("get -permissions x /tmp/",
                        "put -nopermissions x /tmp/",
                        "put -permissions=640 x /tmp/"):
            with self.subTest(command=command):
                result = self.run_commands(command)
                self.assertEqual(result.returncode, 1, command)
                self.assertNotIn("Unsupported switch", result.stderr)
                self.assertNotIn("applies to uploads only", result.stderr)

        # -rawtransfersettings: the optional cap, upstream's own key
        # names, and honest errors for the settings this build lacks
        result = self.run_commands(
            "get -rawtransfersettings=abc x /tmp/")
        self.assertEqual(result.returncode, 1)
        self.assertIn("number of settings", result.stderr)
        result = self.run_commands(
            "get -rawtransfersettings=1 calculateSize=1024 x /tmp/")
        self.assertEqual(result.returncode, 1)
        self.assertIn("has no equivalent", result.stderr)
        self.assertIn("calculateSize", result.stderr)
        result = self.run_commands(
            "get -rawtransfersettings=1 NoSuchKey=1 x /tmp/")
        self.assertEqual(result.returncode, 1)
        self.assertIn("is not known to this build", result.stderr)
        result = self.run_commands(
            "get -rawtransfersettings=1 TransferMode=1 ResumeSupport=0 x /tmp/")
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("raw transfer setting", result.stderr)
        self.assertIn("Not connected", result.stderr)

        # savepreset vocabulary errors name the setting at fault
        result = self.run_commands("savepreset bad -nosuchsetting=1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("nosuchsetting", result.stderr)
        result = self.run_commands("savepreset bad -speed=lots")
        self.assertEqual(result.returncode, 1)
        self.assertIn("speed", result.stderr)


    def test_an_ssh_session_never_asks_curl_for_anything(self):
        """An scp:// or ssh:// session is served by this client's own SSH
        engine, so the curl on the PATH is not part of it - not for a
        transfer, and not for a host key pin.

        It used to be: curl checked '--hostpubsha256' in its libssh2 backend
        only, so a build that links libssh (Debian 13, Ubuntu 24.04) accepted
        the option and ignored it, and the client had to refuse such a
        session rather than verify less than the pin asked for. A fake curl
        that reported libssh stood in for those systems. The engine that
        verifies the key now is the one that verifies an sftp:// key, so what
        a pin depends on is this build and not whatever SSH library somebody
        else's curl was linked against - and a fake curl that records every
        call is the witness that it is never asked.
        """
        with tempfile.TemporaryDirectory(prefix="linscp-curl-") as temp:
            calls = pathlib.Path(temp) / "calls.log"
            fake = pathlib.Path(temp) / "curl"
            fake.write_text(
                "#!/bin/sh\n"
                "echo \"$@\" >> " + str(calls) + "\n"
                "echo \"curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 \"\n"
                "echo \"OpenSSL/3.0.13 zlib/1.3 libssh/0.10.6/openssl/zlib\"\n"
                "echo \"Protocols: file ftp ftps http https\"\n"
                "exit 1\n",
                encoding="utf-8")
            fake.chmod(0o755)
            env = {"PATH": temp + os.pathsep + os.environ.get("PATH", "")}

            # A real 32-byte digest in OpenSSH's spelling, and a port nothing
            # listens on: what has to be reported is the connection, never the
            # pin, and never the curl that is not being used.
            pin = "SHA256:" + "A" * 43
            for protocol in ("scp", "ssh"):
                refused = self.run_commands(
                    "open %s://alice@127.0.0.1:1/ -hostkey=%s ; "
                    "echo SHOULD_NOT_RUN" % (protocol, pin), env=env)
                self.assertEqual(refused.returncode, 1,
                                 refused.stdout + refused.stderr)
                combined = refused.stdout + refused.stderr
                self.assertIn("Cannot open session", combined)
                self.assertNotIn("hostpubsha256", combined)
                self.assertNotIn("curl", combined.lower())
                self.assertNotIn("SHOULD_NOT_RUN", refused.stdout)

            # An MD5 pin is the other spelling ssh-keygen prints, and it is
            # this client that compares it now.
            md5 = self.run_commands(
                "open scp://alice@127.0.0.1:1/ -hostkey=" + "ab" * 16 +
                " ; echo SHOULD_NOT_RUN", env=env)
            self.assertNotIn("hostpubmd5", md5.stdout + md5.stderr)
            self.assertNotIn("SHOULD_NOT_RUN", md5.stdout)

            self.assertFalse(
                calls.exists(),
                "an SSH session called curl: %s" %
                (calls.read_text() if calls.exists() else ""))

    def test_rawsettings_refuse_a_setting_this_build_would_drop(self):
        """Upstream's '-rawsettings' names session settings. One this build
        does not apply is refused by name - with the names it does apply -
        before any connection is attempted, because a setting silently
        dropped is a session that connects somewhere else than asked."""
        result = self.run_commands(
            "open sftp://alice@example.com/ -rawsettings SFTPUploadQueue=2 ; "
            "echo SHOULD_NOT_RUN")
        self.assertEqual(result.returncode, 1)
        self.assertIn("SFTPUploadQueue", result.stderr)
        self.assertIn("ProxyMethod", result.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

    def test_rawsettings_validate_their_values(self):
        cases = {
            "ProxyMethod=SOCKS9": "proxy method",
            "ProxyPort=99999": "proxy port",
            "ProxyDNS=maybe": "ProxyDNS",
            "ProxyLocalhost=perhaps": "ProxyLocalhost",
        }
        for setting, expected in cases.items():
            with self.subTest(setting=setting):
                result = self.run_commands(
                    "open sftp://alice@example.com/ -rawsettings %s ; "
                    "echo SHOULD_NOT_RUN" % setting)
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

        # A method that needs a host has to have one: the alternative is a
        # connection attempt that fails with a message about the network.
        result = self.run_commands(
            "open sftp://alice@example.com/ -rawsettings ProxyMethod=SOCKS5")
        self.assertEqual(result.returncode, 1)
        self.assertIn("ProxyHost", result.stderr)

        # '-rawsettings=N' takes exactly N parameters, the way upstream's
        # list switches do.
        result = self.run_commands(
            "open sftp://alice@example.com/ -rawsettings=2 ProxyHost=proxy")
        self.assertEqual(result.returncode, 1)
        self.assertIn("-rawsettings=2", result.stderr)

    def test_a_proxy_curl_cannot_speak_is_refused(self):
        """The curl-backed protocols translate SOCKS4, SOCKS5 and HTTP
        proxies into curl options. A telnet or local-command proxy has no
        curl option, and going direct instead would send the session
        somewhere it did not ask to go."""
        for method in ("Telnet", "Cmd"):
            with self.subTest(method=method):
                result = self.run_commands(
                    "open ftp://alice@example.com/ -rawsettings "
                    "ProxyMethod=%s ProxyHost=proxy.example.com "
                    "ProxyTelnetCommand=nc ; echo SHOULD_NOT_RUN" % method)
                self.assertEqual(result.returncode, 1)
                self.assertIn("curl", result.stderr)
                self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

    def test_a_stored_session_keeps_its_proxy(self):
        """'savesession -rawsettings' stores the proxy with the site, its
        password encrypted like a session password, a re-save without the
        switch keeps it, and 'ProxyMethod=None' clears it."""
        result = self.run_commands(
            "savesession proxied -host=demo.example.com -username=alice "
            "-rawsettings ProxyMethod=SOCKS5 ProxyHost=proxy.example.com "
            "ProxyPort=1080 ProxyUsername=proxyuser "
            "ProxyPassword=proxy-secret")
        self.assertEqual(result.returncode, 0, result.stderr)
        stored = pathlib.Path(self.config) / "sessions.ini"
        text = stored.read_text(encoding="utf-8")
        self.assertIn("proxy_method=SOCKS5", text)
        self.assertIn("proxy_host=proxy.example.com", text)
        self.assertIn("proxy_port=1080", text)
        self.assertIn("proxy_username=proxyuser", text)
        self.assertIn("proxy_password=lscp1$", text)
        self.assertNotIn("proxy-secret", text)

        # A re-save that says nothing about the proxy keeps it, and keeps a
        # password value the file holds.
        result = self.run_commands(
            "savesession proxied -host=demo.example.com -username=alice")
        self.assertEqual(result.returncode, 0, result.stderr)
        text = stored.read_text(encoding="utf-8")
        self.assertIn("proxy_method=SOCKS5", text)
        self.assertIn("proxy_password=lscp1$", text)

        # The settings of a stored site are refused by name just the same.
        result = self.run_commands(
            "open proxied -rawsettings Nope=1 ; echo SHOULD_NOT_RUN")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Nope", result.stderr)
        self.assertNotIn("SHOULD_NOT_RUN", result.stdout)

        result = self.run_commands(
            "savesession proxied -host=demo.example.com "
            "-rawsettings ProxyMethod=None")
        self.assertEqual(result.returncode, 0, result.stderr)
        text = stored.read_text(encoding="utf-8")
        self.assertNotIn("proxy_method", text)
        self.assertNotIn("proxy_password", text)

    def test_proxy_passwords_are_masked_in_logs(self):
        """A proxy password authenticates, so it is masked wherever the
        command is repeated: the echoed line, the session log and the XML
        action log."""
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / "session.log"
            actions = pathlib.Path(tmp) / "actions.xml"
            result = subprocess.run(
                [BINARY, "-batch", "-log=" + str(log),
                 "-xmllog=" + str(actions),
                 "-command=option echo on ; open sftp://alice@example.com/ "
                           "-rawsettings ProxyMethod=SOCKS5 "
                           "ProxyHost=127.0.0.1 ProxyPort=1 "
                           "ProxyPassword=proxy-secret ; exit"],
                capture_output=True, text=True, timeout=30,
                env=self.environment())
            self.assertNotEqual(result.returncode, 0, result.stdout)
            # The echoed line is masked, and so is the command the XML
            # action log records.
            self.assertIn("ProxyPassword=***", result.stdout)
            for path in (log, actions):
                text = path.read_text(encoding="utf-8", errors="replace")
                self.assertTrue(text.strip(), path)
                self.assertNotIn("proxy-secret", text)
            recorded = actions.read_text(encoding="utf-8", errors="replace")
            self.assertIn("ProxyPassword=***", recorded)

    def test_session_folder_hierarchy_and_rmsession_folder(self):
        """Stored sessions can be organized into slash-delimited folders,
        listed by folder prefix, and removed by folder."""
        self.assertEqual(self.run_commands(
            "savesession Prod/Web/app1 -host=app1.example.com ; "
            "savesession Prod/DB/db1 -host=db1.example.com ; "
            "savesession Stage/app -host=stage.example.com").returncode, 0)

        folders = self.run_commands("sessions folders")
        self.assertEqual(folders.returncode, 0, folders.stderr)
        self.assertIn("Prod/", folders.stdout)
        self.assertIn("Prod/Web/", folders.stdout)
        self.assertIn("Prod/DB/", folders.stdout)
        self.assertIn("Stage/", folders.stdout)

        filtered = self.run_commands("sessions -folder=Prod")
        self.assertEqual(filtered.returncode, 0, filtered.stderr)
        self.assertIn("Prod/Web/app1", filtered.stdout)
        self.assertIn("Prod/DB/db1", filtered.stdout)
        self.assertNotIn("Stage/app", filtered.stdout)

        removed = self.run_commands("rmsession -folder Prod")
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertIn("Removed 2 stored session(s)", removed.stdout)

        remaining = self.run_commands("sessions")
        self.assertEqual(remaining.returncode, 0, remaining.stderr)
        self.assertNotIn("Prod/", remaining.stdout)
        self.assertIn("Stage/app", remaining.stdout)

    def test_passphrase_redaction_and_build_packaging_smoke(self):
        """Key passphrases are redacted across logs, and the Linux Make,
        CMake, and Debian packaging files stay consistent."""
        with tempfile.TemporaryDirectory() as tmp:
            log = pathlib.Path(tmp) / "session.log"
            actions = pathlib.Path(tmp) / "actions.xml"
            result = subprocess.run(
                [BINARY, "-batch", "-log=" + str(log),
                 "-xmllog=" + str(actions),
                 "-command=option echo on ; open sftp://alice@127.0.0.1:1/ "
                           "-privatekey=/tmp/no-such-key "
                           "-passphrase=my-key-secret ; exit"],
                capture_output=True, text=True, timeout=30,
                env=self.environment())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("-passphrase=***", result.stdout)
            for path in (log, actions):
                text = path.read_text(encoding="utf-8", errors="replace")
                self.assertNotIn("my-key-secret", text)
            self.assertIn("-passphrase=***",
                          actions.read_text(encoding="utf-8", errors="replace"))

            # Verify 'make install' staging into a temporary DESTDIR.
            linux_dir = pathlib.Path(__file__).resolve().parent.parent
            repo_root = linux_dir.parent.parent
            destdir = pathlib.Path(tmp) / "stage"
            # CMake-only checkouts do not have the Makefile binary yet. Build
            # it with a compilation-sized timeout before timing installation;
            # otherwise this smoke test gives a cold serial build only 30s.
            build = subprocess.run(
                ["make", "-C", str(linux_dir), "-j2", "all"],
                capture_output=True, text=True, timeout=300)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            install = subprocess.run(
                ["make", "-C", str(linux_dir), "install",
                 "DESTDIR=" + str(destdir), "PREFIX=/usr"],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(install.returncode, 0, install.stderr)
            self.assertTrue((destdir / "usr/bin/linscp").is_file())
            self.assertTrue((destdir / "usr/bin/linscp-gui").is_file())
            self.assertTrue(
                (destdir / "usr/share/applications/linscp.desktop").is_file())

            # Verify CMakeLists.txt and Debian packaging metadata remain aligned.
            cmake_text = (repo_root / "CMakeLists.txt").read_text(encoding="utf-8")
            self.assertIn("add_executable(linscp", cmake_text)
            self.assertIn("add_executable(linscp-unittest", cmake_text)
            self.assertIn("linscp-gui", cmake_text)
            control_text = (repo_root / "debian/control").read_text(encoding="utf-8")
            self.assertIn("Package: linscp", control_text)
            rules_text = (repo_root / "debian/rules").read_text(encoding="utf-8")
            self.assertIn("source/linux", rules_text)


    def test_tunnel_settings_validation_is_fail_closed(self):
        for settings, expected in (
                ("Tunnel=1", "TunnelHostName"),
                ("Tunnel=2", "Tunnel"),
                ("TunnelPortNumber=22x", "TunnelPortNumber"),
                ("TunnelPortNumber=999999999999999999999", "TunnelPortNumber"),
                ("TunnelLocalPortNumber=8080", "private socket pair"),
                ('Tunnel=1 TunnelHostName="two hosts"', "TunnelHostName")):
            with self.subTest(settings=settings):
                result = self.run_commands("open sftp://127.0.0.1:1/ -rawsettings " + settings)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)
        for protocol in ("ftp", "ftps", "dav", "webdav", "s3"):
            result = self.run_commands("open %s://127.0.0.1:1/ -rawsettings Tunnel=1 TunnelHostName=jump" % protocol)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("will not be connected directly", result.stderr)

    def test_global_rawsettings_have_counted_operands(self):
        for args, expected in ((["-rawsettings=1", "Tunnel=0"], 0),
                               (["-rawsettings", "Tunnel=0"], 0),
                               (["-rawsettings=2", "Tunnel=0"], 1),
                               (["-rawsettings=bad", "Tunnel=0"], 1),
                               (["-rawsettings=1", "ImaginarySetting=1"], 1)):
            result = subprocess.run([BINARY, *args, "-command=echo done"],
                                    capture_output=True, text=True, timeout=10, env=self.environment())
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            if expected == 0:
                self.assertIn("done", result.stdout)

    def test_tunnel_storage_redaction_and_unreadable_credentials(self):
        log = pathlib.Path(self.config) / "actions.xml"
        commands = ('option echo on\nsavesession tunneled -host=destination -rawsettings '
                    'Tunnel=1 TunnelHostName=jump TunnelUserName=jumper '
                    'TunnelHostKey=SHA256:pinned TunnelPublicKeyFile="/keys/jump key" '
                    'TunnelPassword="  password with \\"quotes\\"  " '
                    "'TunnelPassphrase=phrase with spaces'\nexit\n")
        result = subprocess.run([BINARY, "-batch", "-script=/dev/stdin", "-xmllog=" + str(log)],
                                input=commands, capture_output=True, text=True, timeout=10,
                                env=self.environment())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        ini = pathlib.Path(self.config) / "sessions.ini"
        key = pathlib.Path(self.config) / "sessions.key"
        contents = ini.read_text()
        for secret in ('password with', 'phrase with spaces'):
            self.assertNotIn(secret, contents)
            self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertNotIn(secret, log.read_text())
        self.assertIn("TunnelPassword=***", result.stdout)
        self.assertIn("TunnelPassphrase=***", result.stdout)
        self.assertIn("tunnel_password=lscp1$", contents)
        self.assertIn("tunnel_passphrase=lscp1$", contents)
        self.assertEqual(ini.stat().st_mode & 0o777, 0o600)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        saved_key = key.read_bytes()
        encrypted = [line for line in contents.splitlines() if line.startswith(("tunnel_password=", "tunnel_passphrase="))]
        key.unlink()
        # An unrelated edit preserves opaque ciphertext rather than discarding it.
        result = self.run_commands("savesession tunneled -host=destination -rawsettings TunnelUserName=other")
        self.assertEqual(result.returncode, 0, result.stderr)
        for line in encrypted:
            self.assertIn(line, ini.read_text())
        result = self.run_commands("open tunneled")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot be used", result.stderr)
        self.assertNotIn("Connecting to", result.stdout)
        key.write_bytes(saved_key)
        key.chmod(0o600)
        # Disabling the tunnel drops its stored secrets, not the shared key file.
        result = self.run_commands("savesession tunneled -host=destination -rawsettings Tunnel=0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("tunnel_", ini.read_text())
        self.assertTrue(key.exists())

    def test_tunnel_plain_aliases_encrypt_and_replace_locked_credentials(self):
        result = self.run_commands('option echo on; savesession alias -host=destination '
                                  '-rawsettings Tunnel=1 TunnelHostName=jump '
                                  'TunnelPasswordPlain="alias password" '
                                  '\'TunnelPassphrasePlain=alias phrase\'')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("TunnelPasswordPlain=***", result.stdout)
        self.assertIn("TunnelPassphrasePlain=***", result.stdout)
        ini = pathlib.Path(self.config) / "sessions.ini"
        first = ini.read_text()
        self.assertIn("tunnel_password=lscp1$", first)
        self.assertIn("tunnel_passphrase=lscp1$", first)
        for secret in ("alias password", "alias phrase"):
            self.assertNotIn(secret, first + result.stdout + result.stderr)
        # The aliases must also replace, not preserve, opaque old ciphertext.
        (pathlib.Path(self.config) / "sessions.key").unlink()
        result = self.run_commands('savesession alias -host=destination -rawsettings '
                                  'TunnelPasswordPlain="new password" TunnelPassphrasePlain="new phrase"')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        current = ini.read_text()
        self.assertIn("tunnel_password=lscp1$", current)
        for line in first.splitlines():
            if line.startswith(("tunnel_password=", "tunnel_passphrase=")):
                self.assertNotIn(line, current)
        self.assertNotIn("new password", current)

    def test_corrupt_stored_tunnel_toggle_cannot_become_a_direct_connection(self):
        ini = pathlib.Path(self.config) / "sessions.ini"
        ini.write_text('[broken]\nhost=127.0.0.1\nport=1\ntunnel=maybe\ntunnel_host=jump\n')
        result = self.run_commands("open broken")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("stored setting 'tunnel'", result.stderr)
        self.assertNotIn("Connecting to", result.stdout)


def run_and_report():
    """Run the suite, then print one line that says what was actually run.

    'make check' and CI are green whether or not the tests could run, so a
    missing dependency used to be invisible: this line, which the CI jobs
    repeat as an annotation, records the skip count next to the pass count.
    """
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    line = ("evidence: suite=%s platform=linux ran=%d skipped=%d failed=%d" %
            (SUITE_NAME, result.testsRun, len(result.skipped),
             len(result.failures) + len(result.errors)))
    if not result.testsRun and result.skipped:
        # A suite that ran nothing is not a pass, and 'skipped' alone does not
        # say whether that is a platform limit or a missing dependency.
        reasons = "; ".join(sorted(set(str(reason)[:160]
                                       for _, reason in result.skipped)))
        line += " because: " + reasons
    print(line)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(run_and_report())
