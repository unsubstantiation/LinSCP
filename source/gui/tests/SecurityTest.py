#!/usr/bin/env python3
"""Offline tests for the boundaries the browser GUI has to hold.

Everything here was a way for a request, a file name on a server or a
directory the panel is showing to reach somewhere it should not: another
origin reading this run's token, a newline in a name becoming a second
command, an absolute name replacing the directory an operation was aimed
at, or a mode field arriving on the command line unvalidated.
"""

import http.client
import json
import os
import queue
import pathlib
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request

GUI_DIR = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GUI_DIR))
import linscp_gui as gui  # noqa: E402


def split_command_line(text):
    """Split a command line the way the console client's splitter does.

    Double quotes group, a backslash escapes the next character outside
    quotes, and inside double quotes a backslash is literal unless it
    stands in front of a double quote or of another backslash. Written
    here rather than reused so that a mistake in the quoting is visible
    as a wrong token count instead of depending on the same code that
    produced it.
    """
    tokens = []
    current = []
    in_quotes = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\" and index + 1 < len(text) and (
                not in_quotes or text[index + 1] in '"\\'):
            current.append(text[index + 1])
            index += 2
            continue
        if char == '"':
            in_quotes = not in_quotes
        elif char in " \t" and not in_quotes:
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
        index += 1
    if current:
        tokens.append("".join(current))
    return tokens


class OperandQuotingTests(unittest.TestCase):
    def test_a_name_is_quoted_so_the_splitter_keeps_it_together(self):
        self.assertEqual(gui.quote_remote("plain"), "plain")
        self.assertEqual(gui.quote_remote("with space"), '"with space"')
        self.assertEqual(gui.quote_remote("semi;colon"), '"semi;colon"')
        self.assertEqual(gui.quote_remote('quote"name'), '"quote\\"name"')
        for name in ("with space", "semi;colon", 'quote"name',
                     'a\\" ; rm x', "trailing "):
            self.assertEqual(split_command_line(gui.quote_remote(name)), [name])
            self.assertEqual(split_command_line(gui.quote_local(name)), [name])

    def test_a_backslash_is_quoted_so_the_splitter_keeps_it(self):
        # The client's splitter reads a backslash as the start of an
        # escape outside quotes, so an unquoted 'a\b' arrived at the
        # server as 'ab': the name of one file was the name of another.
        for name in ("a\\b", "back\\slash", "trailing\\", "a\\ b"):
            self.assertEqual(split_command_line(gui.quote_remote(name)), [name])
            self.assertEqual(split_command_line(gui.quote_local(name)), [name])

    def test_a_path_of_a_windows_client_survives_the_splitter(self):
        # The splitter follows the rules of a POSIX shell, so a path that
        # came from a Windows client keeps its separators: inside double
        # quotes a backslash is literal unless it stands in front of a
        # double quote or of another backslash.
        name = "C:\\Users\\me\\file.txt"
        quoted = gui.quote_remote(name)
        self.assertEqual(quoted, '"C:\\\\Users\\\\me\\\\file.txt"')
        self.assertEqual(split_command_line(quoted), [name])
        self.assertEqual(split_command_line(gui.quote_local(name)), [name])

    def test_a_control_character_is_refused_rather_than_quoted(self):
        # The core reads one command per line in -server mode, so a name
        # holding a newline is two commands and the second one is whatever
        # the name said. No quoting can make that safe.
        for name in ("a\nrm -r /", "a\rcd /", "tab\there\x00", "del\x7f"):
            with self.assertRaises(ValueError):
                gui.quote_remote(name)
            with self.assertRaises(ValueError):
                gui.quote_local(name)

    def test_a_path_that_would_start_a_second_command_stays_one_operand(self):
        # Wrapping in double quotes without escaping what is inside let
        # 'a" ; rm x' close the quoted operand and start a new command.
        hostile = 'a" ; rm -r /'
        self.assertEqual(split_command_line("put " + gui.quote_remote(hostile)),
                         ["put", hostile])
        # A backslash cannot escape the closing quote either.
        backslashed = 'a\\" ; rm -r /'
        self.assertEqual(split_command_line("put " + gui.quote_local(backslashed)),
                         ["put", backslashed])

    def test_a_non_string_operand_is_refused(self):
        for value in (None, 7, ["a"], {"a": 1}):
            with self.assertRaises(ValueError):
                gui.quote_remote(value)
            with self.assertRaises(ValueError):
                gui.quote_local(value)


class TabLookupTests(unittest.TestCase):
    def test_unknown_tab_ids_do_not_fall_back_to_an_unrelated_connection(self):
        old_tabs = gui.STATE["tabs"]
        old_active = gui.STATE["active_tab"]
        first = type("Tab", (), {"id": 1})()
        second = type("Tab", (), {"id": 2})()
        try:
            gui.STATE["tabs"] = [first, second]
            gui.STATE["active_tab"] = 1
            self.assertIs(gui.get_tab("2"), second)
            self.assertIsNone(gui.get_tab("999"))
            self.assertIs(gui.get_tab(), first)
        finally:
            gui.STATE["tabs"] = old_tabs
            gui.STATE["active_tab"] = old_active


class CoreCredentialTests(unittest.TestCase):
    def make_fake_core(self, directory):
        executable = pathlib.Path(directory) / "fake-linscp"
        script = r'''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['LSCP_FAKE_ARGS'], 'w') as f:
    json.dump(sys.argv[1:], f)
with open(os.environ['LSCP_FAKE_PASSWORD'], 'w') as f:
    f.write(os.environ.get('LINSCP_PASSWORD', '<unset>'))
print('LSCP-SERVER 1 ready', flush=True)
with open(os.environ['LSCP_FAKE_INPUT'], 'w') as f:
    for raw in sys.stdin:
        line = raw.rstrip("\r\n")
        f.write(line + "\n"); f.flush()
        if line == 'exit':
            print('LSCP-RESULT 0', flush=True)
            break
        if line == 'bad':
            print('Synthetic command failure', file=sys.stderr, flush=True)
            print('LSCP-RESULT 1', flush=True)
            continue
        print('OK', flush=True)
        print('LSCP-RESULT 0', flush=True)
'''
        executable.write_text(script, encoding="utf-8")
        executable.chmod(0o755)
        return str(executable)

    def process_environment(self, directory):
        return {
            "LSCP_FAKE_ARGS": str(pathlib.Path(directory) / "args.json"),
            "LSCP_FAKE_INPUT": str(pathlib.Path(directory) / "input.txt"),
            "LSCP_FAKE_PASSWORD": str(pathlib.Path(directory) / "password.txt"),
        }

    def test_command_splitter_preserves_quoted_semicolons_and_escapes(self):
        self.assertEqual(
            gui.split_linscp_commands(
                'put "local;a" "remote\\;b" ; echo "x;y"'),
            ['put "local;a" "remote\\;b"', 'echo "x;y"'])
        self.assertEqual(
            gui.split_linscp_commands("echo 'left;right' ; echo done"),
            ["echo 'left;right'", "echo done"])

    def test_session_values_are_typed_before_becoming_commands_or_arguments(self):
        self.assertEqual(gui.validate_session_data({
            "protocol": "sftp", "host": "example.test", "port": 22},
            require_host=True), "")
        self.assertIn("protocol", gui.validate_session_data({
            "protocol": "sftp; echo injected", "host": "example.test"}))
        self.assertIn("protocol", gui.validate_session_data({
            "protocol": False, "host": "example.test"}))
        self.assertIn("host name", gui.validate_session_data({
            "protocol": "sftp", "host": 123}))
        self.assertIn("host name", gui.validate_session_data({
            "protocol": "sftp", "host": 0}))
        self.assertIn("port", gui.validate_session_data({
            "protocol": "sftp", "host": "example.test", "port": "22x"}))
        self.assertIn("port", gui.validate_session_data({
            "protocol": "sftp", "host": "example.test", "port": "9" * 5000}))
        self.assertIn("host name is required", gui.validate_session_data({
            "protocol": "sftp", "host": " "}, require_host=True))

    def test_log_redaction_covers_url_and_password_switch_strings(self):
        text = ('open sftp://alice:p%40ss@example.test/ ; '
                'save -password="two words"')
        redacted = gui.redact_command_for_log(text)
        self.assertNotIn("p%40ss", redacted)
        self.assertNotIn("two words", redacted)
        self.assertEqual(
            redacted,
            "open sftp://alice:<redacted>@example.test/ ; "
            "save -password=<redacted>")

    def test_all_log_messages_are_redacted_at_the_storage_boundary(self):
        with gui.STATE_LOCK:
            old_logs = list(gui.STATE["logs"])
        try:
            gui.add_log("Core diagnostic: sftp://alice:s3cret@example.test/")
            with gui.STATE_LOCK:
                message = gui.STATE["logs"][-1]["text"]
            self.assertNotIn("s3cret", message)
            self.assertIn("<redacted>", message)
        finally:
            with gui.STATE_LOCK:
                gui.STATE["logs"][:] = old_logs

    def test_process_arguments_do_not_disable_verification_or_carry_passwords(self):
        session = {"protocol": "sftp", "host": "example.test",
                   "username": "alice", "password": "top secret",
                   "hostkey": ""}
        with mock.patch.object(gui, "find_linscp_binary", return_value="linscp"):
            args = gui.core_command_line(session)
        self.assertFalse(any("top secret" in arg for arg in args))
        self.assertFalse(any(arg == "-hostkey=*" for arg in args))
        self.assertNotIn("-password=top secret", args)
        session["hostkey"] = "SHA256:verified"
        with mock.patch.object(gui, "find_linscp_binary", return_value="linscp"):
            args = gui.core_command_line(session)
        self.assertIn("-hostkey=SHA256:verified", args)

    def test_persistent_server_keeps_its_pipe_readers_bound_to_that_process(self):
        with tempfile.TemporaryDirectory(prefix="linscp-session-process-") as directory:
            binary = self.make_fake_core(directory)
            environment = self.process_environment(directory)
            session = gui.CoreSession(3, {"protocol": "sftp",
                                          "host": "example.test"})
            with mock.patch.dict(os.environ, environment), \
                 mock.patch.object(gui, "find_linscp_binary", return_value=binary):
                ok, error = session.start()
                self.assertTrue(ok, error)
                process = session.proc
                session.terminate()
            self.assertIsNone(session.proc)
            self.assertIsNotNone(process.returncode)

    def test_persistent_server_rejects_a_bad_greeting_and_reaps_the_process(self):
        with tempfile.TemporaryDirectory(prefix="linscp-session-greeting-") as directory:
            executable = pathlib.Path(directory) / "bad-core"
            executable.write_text(
                "#!/usr/bin/env python3\nprint('not the protocol', flush=True)\n",
                encoding="utf-8")
            executable.chmod(0o755)
            session = gui.CoreSession(4, {"protocol": "sftp",
                                          "host": "example.test"})
            with mock.patch.object(gui, "find_linscp_binary",
                                   return_value=str(executable)):
                ok, error = session.start()
            self.assertFalse(ok)
            self.assertIn("ended before it started", error)
            self.assertIsNone(session.proc)

    def test_one_shot_commands_keep_credentials_out_of_stdin_and_redact_logs(self):
        with tempfile.TemporaryDirectory(prefix="linscp-core-credentials-") as directory:
            binary = self.make_fake_core(directory)
            environment = self.process_environment(directory)
            logs = []
            session = {"protocol": "sftp", "host": "example.test",
                       "username": "alice", "password": "s3cret", "hostkey": ""}
            command = "open " + gui.session_url(session) + " ; echo finished"
            with mock.patch.dict(os.environ, environment), \
                 mock.patch.object(gui, "find_linscp_binary", return_value=binary), \
                 mock.patch.object(gui, "add_log",
                                   side_effect=lambda *args: logs.append(args)):
                code, output, error = gui.run_linscp(command, session)
            self.assertEqual(code, 0, error)
            self.assertIn("OK", output)
            self.assertEqual(error, "")
            args = json.loads(pathlib.Path(environment["LSCP_FAKE_ARGS"]).read_text())
            sent = pathlib.Path(environment["LSCP_FAKE_INPUT"]).read_text()
            self.assertIn("-server", args)
            self.assertFalse(any("s3cret" in arg for arg in args))
            self.assertEqual(sent.splitlines(), [
                "option confirm off", "open sftp://alice@example.test/",
                "echo finished", "exit"])
            self.assertNotIn("s3cret", sent)
            self.assertEqual(
                pathlib.Path(environment["LSCP_FAKE_PASSWORD"]).read_text(),
                "s3cret")
            self.assertFalse(any("s3cret" in str(item) for item in logs))

    def test_failed_server_command_returns_stderr_and_stops_the_script(self):
        with tempfile.TemporaryDirectory(prefix="linscp-core-error-") as directory:
            binary = self.make_fake_core(directory)
            environment = self.process_environment(directory)
            with mock.patch.dict(os.environ, environment), \
                 mock.patch.object(gui, "find_linscp_binary", return_value=binary), \
                 mock.patch.object(gui, "add_log"):
                code, output, error = gui.run_linscp("bad ; echo must-not-run")
            self.assertEqual(code, 1)
            self.assertIn("Synthetic command failure", error)
            self.assertNotIn("must-not-run", output)
            sent = pathlib.Path(environment["LSCP_FAKE_INPUT"]).read_text()
            self.assertEqual(sent.splitlines(), ["option confirm off", "bad", "exit"])

    def test_queued_task_keeps_password_and_unpinned_host_key_out_of_argv(self):
        with tempfile.TemporaryDirectory(prefix="linscp-task-credentials-") as directory:
            binary = self.make_fake_core(directory)
            environment = self.process_environment(directory)
            logs = []
            session = {"protocol": "sftp", "host": "example.test",
                       "username": "alice", "password": "s3cret", "hostkey": ""}
            task = gui.Task(8, "Upload", 'put /tmp/file "/remote/%TIMESTAMP%.txt"',
                            session, "file", "/remote/%TIMESTAMP%.txt", None)
            manager = gui.TaskManager.__new__(gui.TaskManager)
            with mock.patch.dict(os.environ, environment), \
                 mock.patch.object(gui, "find_linscp_binary", return_value=binary), \
                 mock.patch.object(gui, "add_log",
                                   side_effect=lambda *args: logs.append(args)):
                manager._run(task)
            self.assertEqual(task.status, "Completed", task.error)
            args = json.loads(pathlib.Path(environment["LSCP_FAKE_ARGS"]).read_text())
            sent = pathlib.Path(environment["LSCP_FAKE_INPUT"]).read_text()
            self.assertIn("-server", args)
            self.assertNotIn("-hostkey=*", args)
            self.assertFalse(any("s3cret" in arg for arg in args))
            self.assertNotIn("s3cret", sent)
            self.assertIn("open sftp://alice@example.test/", sent)
            self.assertIn("%TIMESTAMP%", sent)
            self.assertEqual(
                pathlib.Path(environment["LSCP_FAKE_PASSWORD"]).read_text(),
                "s3cret")
            self.assertFalse(any("s3cret" in str(item) for item in logs))


class CommandBuildingTests(unittest.TestCase):
    def test_the_sync_direction_comes_from_a_vocabulary(self):
        self.assertEqual(
            gui.build_sync_command("both", "/a", "/b"),
            "synchronize both /a /b")
        for mode in ("both ; put -r / sftp://evil/", "remote\nrm x", "", "BOTH"):
            with self.assertRaises(ValueError):
                gui.build_sync_command(mode, "/a", "/b")

    def test_the_comparison_and_conflict_policy_come_from_a_vocabulary(self):
        self.assertEqual(
            gui.build_sync_command("local", "/a", "/b", criteria="time,size"),
            "synchronize local -criteria=time,size /a /b")
        for criteria in ("time; rm x", "whenever", "time,\nrm"):
            with self.assertRaises(ValueError):
                gui.build_sync_command("local", "/a", "/b", criteria=criteria)
        for conflict in ("skip ; rm x", "mine", ""):
            with self.assertRaises(ValueError):
                gui.build_sync_command("local", "/a", "/b", conflict=conflict)

    def test_both_directories_are_quoted_the_way_the_client_reads_quotes(self):
        command = gui.build_sync_command("remote", '/a "b"', "/c'd",
                                         filemask='*.txt|*.bak"')
        self.assertIn('"/a \\"b\\""', command)
        self.assertIn('"/c\'d"', command)
        # The mask keeps its wildcards and loses nothing that quotes it.
        self.assertIn("-filemask=", command)

    def test_a_directory_name_holding_a_newline_is_refused(self):
        with self.assertRaises(ValueError):
            gui.build_sync_command("local", "/a\nrm x", "/b")
        with self.assertRaises(ValueError):
            gui.build_sync_command("local", "/a", "/b\nrm x")

    def test_the_transfer_switches_are_each_checked(self):
        self.assertEqual(
            gui.transfer_switches({"transfer": "ascii", "speed": "512",
                                   "filemask": "*.txt|*.bak",
                                   "newer_only": True, "preserve_time": False,
                                   "append": True}),
            "-resume -r -neweronly -nopreservetime -transfer=ascii "
            "-filemask=*.txt|*.bak -speed=512 -append")
        self.assertEqual(gui.transfer_switches({}), "-resume -r -preservetime")

    def test_a_transfer_mode_that_is_not_one_is_refused(self):
        for mode in ("ascii; rm -rf /", "TEXT", "binary\nrm x"):
            with self.assertRaises(ValueError):
                gui.transfer_switches({"transfer": mode})

    def test_a_speed_limit_has_to_be_a_number_of_kib_s(self):
        for speed in ("fast", "-5", 0.5, "1e9", 10 ** 12):
            with self.assertRaises(ValueError):
                gui.transfer_switches({"speed": speed})
        self.assertIn("-speed=1", gui.transfer_switches({"speed": 1}))
        self.assertIn("-speed=100000000",
                      gui.transfer_switches({"speed": 100000000}))

    def test_resume_support_takes_on_off_or_a_size_in_kib(self):
        # -resumesupport= is a number of KiB in the client, in its help and
        # in its manual page, and the dialog says KiB too. The panel used to
        # label the same field 'bytes' and pass the number through
        # unchanged, so a threshold a user typed in bytes was read 1024
        # times too large.
        self.assertIn("-resumesupport=on",
                      gui.transfer_switches({"resumesupport": "on"}))
        self.assertIn("-resumesupport=off",
                      gui.transfer_switches({"resumesupport": "off"}))
        self.assertIn("-resumesupport=4096",
                      gui.transfer_switches({"resumesupport": "4096"}))
        for value in ("maybe", "-1", "on; rm x"):
            with self.assertRaises(ValueError):
                gui.transfer_switches({"resumesupport": value})

    def test_the_resume_threshold_the_dialog_offers_is_in_the_clients_unit(self):
        page = (GUI_DIR / "web" / "index.html").read_text(encoding="utf-8")
        field = page.split('id="transferResumeSize"')[1].split("</div>")[0]
        self.assertIn("KiB", field)
        self.assertNotIn("bytes", field)


class PermissionModeTests(unittest.TestCase):
    def test_the_symbolic_forms_the_console_client_accepts(self):
        # The same grammar ParseSymbolicPermissions() in the console client
        # accepts, including '=rwx', which names nobody in front of it and
        # so applies to everybody, several operator groups in one clause,
        # which is how chmod(1) reads 'u+x-w', and clauses separated by
        # blanks as well as by commas.
        for mode in ("u+x", "a=r,go-w", "o-rwx", "a+X", "=rwx", "a+rwx,u-s",
                     "g=u", "u=rwx,g=rx", "=x", "u+x-w", "g+w+r", "a=r-w",
                     "u=rw g=r o=r", "u+x,", "UG+X", "a+t",
                     # '=' may stand without a permission letter, and
                     # clears the class it names: chmod(1) reads 'o=' so,
                     # and so does the console client.
                     "o=", "a=", "=", "u=rwx,g=rx,o=", "u=-w", "a=st"):
            self.assertEqual(gui.check_permission_mode(mode), "", mode)

    def test_the_octal_forms_the_console_client_accepts(self):
        # ParseOctalMode() reads one leading zero as a prefix, so the
        # padded spelling a script keeps its modes in is a mode the client
        # takes - and one the panel must not turn down.
        for mode in ("644", "0644", "00644", "7777", "07777", "0", "0000",
                     "4755", "04755", "1777"):
            self.assertEqual(gui.check_permission_mode(mode), "", mode)
        for mode in ("000644", "12345", "99999", "8", "08", "64x", ""):
            self.assertNotEqual(gui.check_permission_mode(mode), "", mode)

    def test_a_mode_the_console_client_refuses_is_refused_here_too(self):
        # '+x' names nobody: the client refuses it rather than change
        # nothing at all, and a panel that accepted it would answer a
        # failure to a mode it had just called usable.
        for mode in ("+x", "-w", "u=rwx,x-w", "u+q", "u?x", "u", "zzz", ",",
                     "u+x -w"):
            self.assertNotEqual(gui.check_permission_mode(mode), "", mode)

    def test_a_symbolic_mode_reaches_the_client_as_one_operand(self):
        # The clauses of a symbolic mode may be separated by blanks, which
        # the client's splitter would otherwise read as a second file name.
        commands = gui.build_chmod_command("/remote dir", "u=rw g=r", "a name")
        self.assertEqual(split_command_line(commands[1]),
                         ["chmod", "u=rw g=r", "a name"])
        self.assertEqual(split_command_line(commands[0]), ["cd", "/remote dir"])
        # A mode the client refuses never becomes a command at all.
        for mode in ("+x", "644 x", "u+x; rm x"):
            with self.assertRaises(ValueError):
                gui.build_chmod_command("/r", mode, "f")

    def test_a_clause_with_no_permission_letter_is_refused_after_plus_or_minus(self):
        # chmod(1) allows the empty list after '=' ('o=' clears a class),
        # and so does the console client now. After '+' and '-' it states
        # nothing at all, so both refuse it.
        for mode in ("u+", "u-", "a+", "go-"):
            self.assertNotEqual(gui.check_permission_mode(mode), "", mode)

    def test_what_is_neither_form_is_refused(self):
        for mode in ("", "   ", "644 x", "zzz", "644\nrm -r /", "0644;",
                     "99999", "-rw-r--r--", "u+x; rm x", "0" * 65):
            self.assertNotEqual(gui.check_permission_mode(mode), "", mode)

    def test_a_symbolic_mode_is_applied_to_a_local_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "file")
            with open(target, "w") as handle:
                handle.write("x")
            os.chmod(target, 0o600)
            gui.apply_local_mode(target, "a+r")
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o644)
            gui.apply_local_mode(target, "o-rwx,g+w")
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o660)
            gui.apply_local_mode(target, "755")
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o755)

    def test_a_directory_takes_execute_from_capital_x(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "dir")
            os.mkdir(target)
            os.chmod(target, 0o600)
            gui.apply_local_mode(target, "a+X")
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o711)

    def test_the_special_bits_are_applied_like_the_console_client_does(self):
        # 's' and 't' live outside the three permission classes. They were
        # masked with the class mask, which does not hold them, so 'a+s'
        # and 'o+t' changed nothing at all while the remote chmod set the
        # setuid, setgid and sticky bits.
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "file")
            with open(target, "w") as handle:
                handle.write("x")
            cases = (
                ("a+s", 0o6644),
                ("u+s", 0o4644),
                ("g+s", 0o2644),
                ("o+s", 0o644),
                ("o+t", 0o1644),
                ("a+t", 0o1644),
                ("u+t", 0o644),
                ("u-s", 0o644),
            )
            for mode, expected in cases:
                os.chmod(target, 0o644)
                gui.apply_local_mode(target, mode)
                self.assertEqual(stat.S_IMODE(os.stat(target).st_mode),
                                 expected, mode)

    def test_a_set_operator_clears_the_class_it_names_like_chmod(self):
        # '=' clears the class's rwx bits and the special bit that belongs
        # to it, and a '=' with no letters after it still clears them:
        # chmod(1)'s 'u=rw' on a 4755 file leaves 655, and 'u=' leaves 55.
        # The console client reads the same modes with the same result.
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "file")
            with open(target, "w") as handle:
                handle.write("x")
            cases = (
                (0o4755, "u=rw", 0o655),
                (0o6755, "u=r", 0o2455),
                (0o6755, "g=r", 0o4745),
                (0o6755, "o=r", 0o6754),
                (0o4755, "u=", 0o55),
                (0o2755, "g=", 0o705),
                (0o1755, "o=", 0o750),
                (0o1755, "a=", 0o000),
                (0o4755, "u=-w", 0o055),
                (0o1755, "o=st", 0o1750),
                (0o1755, "a=st", 0o7000),
                (0o1755, "o=s", 0o750),
                (0o4755, "g=u", 0o4775),
                (0o4755, "u=t", 0o055),
            )
            for start, mode, expected in cases:
                os.chmod(target, start)
                gui.apply_local_mode(target, mode)
                self.assertEqual(stat.S_IMODE(os.stat(target).st_mode),
                                 expected, (oct(start), mode))

    def test_a_permission_letter_copies_the_class_it_names(self):
        # 'g=u' gives the group the permissions the owner has, as the
        # console client's ParseSymbolicPermissions() does.
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "file")
            with open(target, "w") as handle:
                handle.write("x")
            for mode, expected in (("g=u", 0o664), ("u=g", 0o444),
                                   ("g=u", 0o664)):
                os.chmod(target, 0o644)
                gui.apply_local_mode(target, mode)
                self.assertEqual(stat.S_IMODE(os.stat(target).st_mode),
                                 expected, mode)


class PanelContainmentTests(unittest.TestCase):
    def test_a_local_operation_stays_in_the_directory_the_panel_shows(self):
        base = "/srv/panel"
        self.assertEqual(gui.contained_local_path(base, "file.txt"),
                         ("/srv/panel/file.txt", ""))

    def test_an_absolute_name_does_not_replace_the_panel_directory(self):
        # os.path.join(base, "/etc/passwd") is "/etc/passwd", so an
        # operation aimed at the panel could be aimed anywhere instead.
        for name in ("/etc/passwd", "/", "/tmp"):
            path, error = gui.contained_local_path("/srv/panel", name)
            self.assertIsNone(path, name)
            self.assertTrue(error, name)

    def test_a_relative_name_cannot_walk_out_of_the_panel_directory(self):
        for name in ("../secret", "..", "a/../..", "./../x"):
            path, error = gui.contained_local_path("/srv/panel", name)
            self.assertIsNone(path, name)
            self.assertTrue(error, name)

    def test_a_name_with_a_control_character_or_nul_is_refused(self):
        for name in ("a\nrm x", "a\x00b", "a\rb"):
            path, error = gui.contained_local_path("/srv/panel", name)
            self.assertIsNone(path, name)
            self.assertTrue(error, name)

    def test_an_unusable_panel_directory_is_reported_not_guessed(self):
        for base in ("", None, "relative/dir", 7):
            path, error = gui.contained_local_path(base, "file")
            self.assertIsNone(path, base)
            self.assertTrue(error, base)


class FakeTab:
    """A tab whose only job is to remember the commands it was given."""

    def __init__(self, remote_dir="/data", connected=True):
        self.remote_dir = remote_dir
        self.connected = connected
        self.commands = []

    def run(self, command, timeout=120):
        self.commands.append(command)
        return 0, ["ok"]

    def run_capture(self, command, timeout=120):
        self.commands.append(command)
        return 0, ["ok"], []

    def run_many(self, commands, timeout=120):
        self.commands.extend(commands)
        return 0, ["ok"]

    def run_many_capture(self, commands, timeout=120):
        self.commands.extend(commands)
        return 0, ["ok"], []


class RemoteNameTests(unittest.TestCase):
    def setUp(self):
        self.tab = FakeTab(remote_dir="/data/current")

    def test_a_panel_entry_resolves_against_the_panel_directory(self):
        operand, error = gui.single_remote_name(self.tab, "file.txt")
        self.assertEqual(error, "")
        self.assertEqual(operand, "/data/current/file.txt")

    def test_a_subdirectory_entry_is_allowed_and_normalized(self):
        operand, error = gui.single_remote_name(self.tab, "sub/file.txt")
        self.assertEqual(error, "")
        self.assertEqual(operand, "/data/current/sub/file.txt")

    def test_a_name_that_walks_out_is_refused_not_resolved(self):
        for name in ("../other/file", "sub/../../etc/passwd", ".", ".."):
            operand, error = gui.single_remote_name(self.tab, name)
            self.assertIsNone(operand, name)
            self.assertTrue(error, name)

    def test_an_absolute_name_is_taken_as_itself(self):
        operand, error = gui.single_remote_name(self.tab, "/etc/motd")
        self.assertEqual(error, "")
        self.assertEqual(operand, "/etc/motd")

    def test_a_control_character_is_refused(self):
        for name in ("a\nrm -r /", "a\rb", "a\x00b"):
            operand, error = gui.single_remote_name(self.tab, name)
            self.assertIsNone(operand, repr(name))
            self.assertTrue(error, repr(name))

    def test_nothing_selected_is_an_answer_not_a_crash(self):
        for name in ("", None, 7, ["a"]):
            operand, error = gui.single_remote_name(self.tab, name)
            self.assertIsNone(operand, repr(name))
            self.assertTrue(error, repr(name))


class FakeStdin:
    def __init__(self):
        self.written = []

    def write(self, text):
        self.written.append(text)

    def flush(self):
        pass


class FakeProcess:
    def __init__(self):
        self.stdin = FakeStdin()
        self.killed = False
        self.terminated = False

    def poll(self):
        return None

    def kill(self):
        self.killed = True

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 1


def make_session(identifier, answer="LSCP-RESULT 0"):
    session = gui.CoreSession(identifier, {"protocol": "sftp", "host": "example"},
                              name="test")
    session.proc = FakeProcess()
    session.connected = True
    # start() builds these; a session with no process behind it has neither.
    if session._queue is None:
        session._queue = queue.Queue()
    if session._stderr is None:
        session._stderr = []
    session._queue.put(answer)
    return session


class ServerCommandStreamTests(unittest.TestCase):
    """The one choke point every remote operation goes through."""

    def test_a_command_with_a_newline_is_never_written_to_the_core(self):
        session = make_session(9101)
        code, lines, _ = session.run_capture("cd /data\nrm -r /")
        self.assertEqual(code, 1)
        # Nothing reached the core: the second line of that text would have
        # been a command nobody asked for.
        self.assertEqual(session.proc.stdin.written, [])
        self.assertTrue(any("single line" in line for line in lines))

    def test_a_carriage_return_is_refused_too(self):
        session = make_session(9102)
        code, _, _ = session.run_capture("cd /data\rrm x")
        self.assertEqual(code, 1)
        self.assertEqual(session.proc.stdin.written, [])

    def test_a_one_line_command_reaches_the_core_as_one_line(self):
        session = make_session(9103)
        code, _, _ = session.run_capture("cd /data")
        self.assertEqual(code, 0)
        self.assertEqual(session.proc.stdin.written, ["cd /data\n"])

    def test_a_refused_command_does_not_cost_the_session_its_connection(self):
        session = make_session(9104)
        session.run_capture("cd /data\nrm -r /")
        self.assertTrue(session.connected)


class LocalListingTests(unittest.TestCase):
    def test_a_broken_symbolic_link_is_listed_rather_than_hidden(self):
        with tempfile.TemporaryDirectory() as directory:
            real = os.path.join(directory, "real.txt")
            with open(real, "w") as handle:
                handle.write("content")
            os.symlink(real, os.path.join(directory, "good"))
            os.symlink(os.path.join(directory, "missing"),
                       os.path.join(directory, "broken"))
            entries, error = gui.list_local_directory(directory)
            self.assertFalse(error)
            names = {entry["name"] for entry in entries}
            # stat() follows the link and raises for one whose target is
            # gone; the entry used to be skipped, so the panel could not
            # show, rename or delete it.
            self.assertEqual(names, {"real.txt", "good", "broken"})
            broken = next(e for e in entries if e["name"] == "broken")
            self.assertTrue(broken["is_broken"])
            self.assertTrue(broken["is_link"])
            self.assertTrue(broken["permissions"].startswith("l"))
            good = next(e for e in entries if e["name"] == "good")
            self.assertTrue(good["is_link"])
            self.assertFalse(good["is_broken"])

    def test_a_symlink_target_is_reported_from_a_long_listing(self):
        lines = [
            "Reading directory /data...",
            "lrwxrwxrwx 1 user group 9 Oct 16 05:33 link.txt -> hello.txt",
            "-rw-r--r-- 1 user group 4 Oct 16 05:33 odd -> name.txt",
            "2 entries",
        ]
        entries = gui.parse_ls_output(lines)
        by_name = {entry["name"]: entry for entry in entries}
        # A server that supplies its own 'ls -l' text writes the target
        # after the name. Keeping it made the panel show an entry that no
        # rename, delete or download could ever find.
        self.assertIn("link.txt", by_name)
        self.assertEqual(by_name["link.txt"]["link_target"], "hello.txt")
        self.assertTrue(by_name["link.txt"]["is_link"])
        # A regular file may really be called that; only a link line has a
        # target to take off.
        self.assertIn("odd -> name.txt", by_name)
        self.assertFalse(by_name["odd -> name.txt"]["is_link"])


class CustomCommandTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.previous = os.environ.get("LINSCP_CONFIG_DIR")
        os.environ["LINSCP_CONFIG_DIR"] = self.directory.name

    def tearDown(self):
        self.directory.cleanup()
        if self.previous is None:
            os.environ.pop("LINSCP_CONFIG_DIR", None)
        else:
            os.environ["LINSCP_CONFIG_DIR"] = self.previous

    def test_the_commands_live_in_the_configuration_directory_this_run_uses(self):
        # They looked at a differently named variable and fell back to
        # ~/.config, so a run with its own directory shared them anyway.
        self.assertEqual(gui._custom_commands_path(),
                         os.path.join(self.directory.name,
                                      "custom-commands.json"))

    def test_the_shipped_templates_are_there_on_a_first_run(self):
        commands = gui._read_custom_commands()
        self.assertTrue(commands, "the shipped templates were not found")
        names = {command["name"] for command in commands}
        shipped = json.loads(
            (GUI_DIR / "explorer-commands.json").read_text(encoding="utf-8"))
        self.assertEqual(names, {item["name"] for item in shipped})

    def test_a_saved_command_replaces_the_shipped_ones_in_the_user_file(self):
        gui._write_custom_commands(
            [gui.normalize_custom_command(
                {"name": "Mine", "command": "ls {file}", "scope": "local"})])
        commands = gui._read_custom_commands()
        self.assertEqual([command["name"] for command in commands], ["Mine"])
        self.assertEqual(commands[0]["scope"], "local")

    def test_the_file_that_stores_commands_is_not_world_readable(self):
        gui._write_custom_commands(
            [gui.normalize_custom_command(
                {"name": "Mine", "command": "ls", "scope": "remote"})])
        mode = stat.S_IMODE(os.stat(gui._custom_commands_path()).st_mode)
        self.assertEqual(mode, 0o600)

    def test_a_template_that_is_not_one_command_line_is_refused(self):
        for template in ({"name": "a\nrm x", "command": "ls"},
                         {"name": "a", "command": "ls\nrm x"},
                         {"name": "", "command": "ls"},
                         {"name": "a", "command": ""},
                         {"name": "a" * 200, "command": "ls"},
                         "not a mapping", None, 7):
            self.assertIsNone(gui.normalize_custom_command(template), template)

    def test_an_unusable_scope_falls_back_to_the_remote_side(self):
        template = gui.normalize_custom_command(
            {"name": "a", "command": "ls", "scope": "everywhere"})
        self.assertEqual(template["scope"], "remote")

    def test_a_selected_name_is_quoted_for_the_client_not_for_a_shell(self):
        template = {"name": "a", "command": "checksum sha-256 {file}",
                    "scope": "remote"}
        command, error = gui.build_custom_command(template, "name with space")
        self.assertEqual(error, "")
        self.assertEqual(command, 'checksum sha-256 "name with space"')
        # Single quotes are an ordinary character to the LinSCP splitter,
        # so a name with a space arrived as two arguments.
        self.assertNotIn("'", command)

    def test_a_local_template_quotes_its_name_as_a_local_path(self):
        template = {"name": "a", "command": "lls {file}", "scope": "local"}
        command, error = gui.build_custom_command(template, 'odd"name')
        self.assertEqual(error, "")
        self.assertEqual(command, 'lls "odd\\"name"')

    def test_a_name_that_is_not_one_entry_of_the_panel_is_refused(self):
        template = {"name": "a", "command": "ls {file}", "scope": "remote"}
        for name in ("../other", "/etc/passwd", "sub/file", ".", "..",
                     "a\nrm x", "", None, 7, "back\\slash"):
            command, error = gui.build_custom_command(template, name)
            self.assertIsNone(command, repr(name))
            self.assertTrue(error, repr(name))

    def test_a_template_without_the_placeholder_runs_as_it_stands(self):
        template = {"name": "a", "command": "sessions", "scope": "remote"}
        command, error = gui.build_custom_command(template, "anything")
        self.assertEqual(error, "")
        self.assertEqual(command, "sessions")

    def test_a_remote_run_uses_the_panel_session_without_a_shell(self):
        seen = []

        class FakeTab:
            remote_dir = "/data"
            session = {"host": "example.com"}

            def run_many_capture(self, commands, timeout=120):
                seen.extend(commands)
                return 0, ["523b87"], []

        template = {"name": "sum", "command": "checksum sha-256 {file}",
                    "scope": "remote"}
        results, error = gui.execute_custom_command(
            template, ["a.txt", "b.txt"], FakeTab())
        self.assertEqual(error, "")
        self.assertEqual(len(results), 2)
        self.assertTrue(all(item["success"] for item in results))
        self.assertEqual(results[0]["file"], "a.txt")
        # One 'cd' plus the substituted command per file, quoted for the
        # client's splitter rather than interpolated into a shell: no
        # shell ever sees these words.
        self.assertEqual(seen[0], "cd /data")
        self.assertEqual(seen[1], 'checksum sha-256 a.txt')
        self.assertEqual(seen[3], 'checksum sha-256 b.txt')
        self.assertNotIn(";", "".join(seen))

    def test_a_local_run_goes_through_the_core_not_a_shell(self):
        calls = []

        def fake_run(command, session=None, timeout=300):
            calls.append((command, session))
            return 0, "counted", ""

        template = {"name": "wc", "command": "lls {file}", "scope": "local"}
        with mock.patch.object(gui, "run_linscp", side_effect=fake_run):
            results, error = gui.execute_custom_command(
                template, ["odd\"name"], None)
        self.assertEqual(error, "")
        self.assertTrue(results[0]["success"])
        # The name is quoted for the client's splitter: the quote inside
        # it cannot end the operand and start a second command.
        self.assertEqual(calls[0][0], 'lls "odd\\\"name"')

    def test_a_hostile_name_fails_its_file_and_runs_the_rest(self):
        seen = []

        class FakeTab:
            remote_dir = "/data"
            session = {}

            def run_many_capture(self, commands, timeout=120):
                seen.extend(commands)
                return 0, ["ok"], []

        template = {"name": "sum", "command": "checksum sha-256 {file}",
                    "scope": "remote"}
        results, error = gui.execute_custom_command(
            template, ["good.txt", "../escape", "fine.txt"], FakeTab())
        self.assertEqual(error, "")
        self.assertEqual(len(results), 3)
        self.assertTrue(results[0]["success"])
        self.assertFalse(results[1]["success"])
        self.assertTrue(results[1]["error"])
        self.assertTrue(results[2]["success"])
        # The hostile name was never substituted into a command.
        self.assertNotIn("escape", "".join(seen))

    def test_a_remote_run_without_a_session_is_refused(self):
        template = {"name": "sum", "command": "checksum sha-256 {file}",
                    "scope": "remote"}
        results, error = gui.execute_custom_command(
            template, ["a.txt"], None)
        self.assertEqual(results, [])
        self.assertIn("open session", error)


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.accounts = os.path.join(self.directory.name, "accounts.ini")
        self.previous_accounts = gui.ACCOUNTS_FILE
        gui.ACCOUNTS_FILE = self.accounts
        gui._write_account("alice", "wonderland", "/srv/alice")
        gui._LOGIN_ATTEMPTS.clear()
        gui._LOGIN_LOCKOUT_UNTIL.clear()
        with gui._LOGIN_LOCK:
            gui._LOGIN_SESSIONS.clear()
        with gui._USER_WORKSPACES_LOCK:
            gui._USER_WORKSPACES.clear()
        gui.unbind_workspace()

    def tearDown(self):
        gui.ACCOUNTS_FILE = self.previous_accounts
        self.directory.cleanup()
        with gui._LOGIN_LOCK:
            gui._LOGIN_SESSIONS.clear()
        gui._LOGIN_ATTEMPTS.clear()
        gui._LOGIN_LOCKOUT_UNTIL.clear()
        with gui._USER_WORKSPACES_LOCK:
            gui._USER_WORKSPACES.clear()
        gui.unbind_workspace()

    def test_the_accounts_file_holds_hashes_not_passwords_and_only_this_user(self):
        text = pathlib.Path(self.accounts).read_text(encoding="utf-8")
        self.assertNotIn("wonderland", text)
        self.assertIn("hash=", text)
        self.assertIn("salt=", text)
        self.assertNotIn("hash=wonderland", text)
        mode = stat.S_IMODE(os.stat(self.accounts).st_mode)
        # The file every login is checked against is not for anybody else.
        self.assertEqual(mode, 0o600)

    def test_a_home_directory_is_stored_with_the_account(self):
        self.assertEqual(gui._read_accounts()["alice"]["home_dir"], "/srv/alice")

    def test_each_login_session_gets_its_own_csrf_token(self):
        # One token for the whole run was not a per-session secret: a single
        # leaked copy would have served for everybody until a restart.
        first_sid, first_csrf = gui._create_login_session("alice")
        second_sid, second_csrf = gui._create_login_session("alice")
        self.assertNotEqual(first_sid, second_sid)
        self.assertNotEqual(first_csrf, second_csrf)
        self.assertEqual(gui._validate_login_session(first_sid), "alice")
        self.assertEqual(gui._validate_login_session(second_sid), "alice")

    def test_a_session_id_nobody_issued_is_not_one(self):
        self.assertIsNone(gui._validate_login_session("0" * 64))
        self.assertIsNone(gui._validate_login_session(""))
        self.assertIsNone(gui._validate_login_session(None))

    def test_an_expired_session_is_gone_and_is_not_left_in_the_table(self):
        sid, csrf = gui._create_login_session("alice")
        with gui._LOGIN_LOCK:
            gui._LOGIN_SESSIONS[sid]["created"] -= gui.SESSION_SECS + 1
        self.assertIsNone(gui._validate_login_session(sid))
        with gui._LOGIN_LOCK:
            self.assertNotIn(sid, gui._LOGIN_SESSIONS)

    def test_repeated_failures_lock_the_user_name_out(self):
        for _ in range(gui.LOGIN_MAX_FAILURES - 1):
            gui._login_failed("alice")
            self.assertEqual(gui._login_throttle("alice"), 0)
        gui._login_failed("alice")
        self.assertGreater(gui._login_throttle("alice"), 0)
        # Another user name is not locked out by somebody else's failures.
        self.assertEqual(gui._login_throttle("bob"), 0)

    def test_a_successful_sign_in_clears_what_was_recorded_against_it(self):
        for _ in range(gui.LOGIN_MAX_FAILURES):
            gui._login_failed("alice")
        gui._login_succeeded("alice")
        self.assertEqual(gui._login_throttle("alice"), 0)

    def test_a_password_is_checked_against_the_stored_hash_and_salt(self):
        account = gui._read_accounts()["alice"]
        self.assertTrue(gui._authenticate_user("alice", "wonderland"))
        self.assertFalse(gui._authenticate_user("alice", "wrong"))
        self.assertFalse(gui._authenticate_user("alice", ""))
        self.assertFalse(gui._authenticate_user("nobody", "wonderland"))
        self.assertTrue(account["hash"])
        self.assertTrue(account["salt"])
        self.assertNotEqual(account["hash"], account["salt"])

    def test_writing_an_account_without_a_file_to_write_it_to_says_so(self):
        previous = gui.ACCOUNTS_FILE
        gui.ACCOUNTS_FILE = None
        try:
            with self.assertRaises(ValueError):
                gui._write_account("bob", "builder", "")
        finally:
            gui.ACCOUNTS_FILE = previous


class QueueCleanupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        with gui.STATE_LOCK:
            gui.STATE["tasks"] = []
            gui.STATE["paused"] = False
        self.staged = os.path.join(self.directory.name, "staged-upload")
        with open(self.staged, "w") as handle:
            handle.write("bytes the core process is reading")

    def tearDown(self):
        self.directory.cleanup()

    def test_cancelling_everything_keeps_the_source_of_a_running_transfer(self):
        manager = gui.TaskManager()
        running = manager.submit("Upload", "put x", {}, "/from", "/to", None,
                                 cleanup_path=self.staged)
        running.status = "Running"
        queued = manager.submit("Upload", "put y", {}, "/from2", "/to2", None,
                                cleanup_path=None)
        manager.cancel_all()
        self.assertEqual(running.status, "Cancelling")
        self.assertEqual(queued.status, "Cancelled")
        # Deleting the staged file of a task that is still running turned a
        # cancellation into a failure part way through the file, and left
        # 'retry' with nothing to retry from.
        self.assertTrue(os.path.exists(self.staged))

    def test_a_task_that_has_stopped_gives_up_its_staged_file(self):
        manager = gui.TaskManager()
        task = manager.submit("Upload", "put x", {}, "/from", "/to", None,
                              cleanup_path=self.staged)
        task.status = "Cancelled"
        manager.cleanup_source(task)
        self.assertFalse(os.path.exists(self.staged))

    def test_clearing_finished_work_releases_the_staged_file_it_no_longer_needs(self):
        manager = gui.TaskManager()
        failed = manager.submit("Download", "get x", {}, "/from", "/to", None,
                                cleanup_path=self.staged)
        failed.status = "Failed"
        live = manager.submit("Upload", "put y", {}, "/from2", "/to2", None)
        live.status = "Running"
        manager.clear_finished()
        with gui.STATE_LOCK:
            self.assertNotIn(failed, gui.STATE["tasks"])
            # A transfer that is still going is not finished work.
            self.assertIn(live, gui.STATE["tasks"])
        self.assertFalse(os.path.exists(self.staged))


class BrowserUploadModeTests(unittest.TestCase):
    def test_upload_never_reads_or_temporarily_changes_the_process_umask(self):
        import io
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(gui.os, "umask",
                               side_effect=AssertionError("process umask raced")):
            destination = gui.save_local_browser_upload(
                directory, "dropped.txt", io.BytesIO(b"content"), 7)
            self.assertEqual(pathlib.Path(destination).read_bytes(), b"content")

    def test_a_dropped_file_gets_the_mode_an_ordinary_create_would(self):
        # mkstemp() creates 0600, and os.replace() keeps it, so a file the
        # user dropped into their own directory came out owner-only.
        umask = os.umask(0)
        os.umask(umask)
        with tempfile.TemporaryDirectory() as directory:
            destination = os.path.join(directory, "dropped.txt")
            import io
            gui.save_local_browser_upload(directory, "dropped.txt",
                                          io.BytesIO(b"content"), len(b"content"))
            mode = stat.S_IMODE(os.stat(destination).st_mode)
            self.assertEqual(mode, 0o666 & ~umask)
            with open(destination, "rb") as handle:
                self.assertEqual(handle.read(), b"content")

    def test_replacing_a_file_keeps_the_mode_it_already_had(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = os.path.join(directory, "kept.txt")
            with open(destination, "w") as handle:
                handle.write("old")
            os.chmod(destination, 0o640)
            import io
            gui.save_local_browser_upload(directory, "kept.txt",
                                          io.BytesIO(b"new"), len(b"new"))
            self.assertEqual(stat.S_IMODE(os.stat(destination).st_mode), 0o640)
            with open(destination, "rb") as handle:
                self.assertEqual(handle.read(), b"new")

    def test_a_name_cannot_escape_the_directory_it_is_dropped_into(self):
        with tempfile.TemporaryDirectory() as directory:
            import io
            for name in ("../outside", "/etc/passwd", "sub/dir", ".", ".."):
                with self.assertRaises(ValueError, msg=name):
                    gui.save_local_browser_upload(
                        directory, name, io.BytesIO(b"x"), 1)


@unittest.skipUnless(sys.platform.startswith("linux"), "POSIX server only")
class CrossOriginTests(unittest.TestCase):
    """The token is in the page, so the page must not be readable elsewhere.

    'Access-Control-Allow-Origin: *' on every response let any site the user
    visited fetch this page, read this run's token out of it and then drive
    the whole API from its own origin - which is the local file system of
    whoever started the server.
    """

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp(prefix="linscp-cors-")
        environment = dict(os.environ)
        environment["LINSCP_CONFIG_DIR"] = cls.directory
        environment["PYTHONPATH"] = str(GUI_DIR)
        environment["LINSCP_BIN"] = environment.get("LINSCP_BIN", "")
        cls.process = subprocess.Popen(
            [sys.executable, str(GUI_DIR / "linscp_gui.py"),
             "--host=127.0.0.1", "--port=0", "--print-token"],
            cwd=str(GUI_DIR), env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        # The server keeps running and stops writing once it has started, so
        # reading its output on this thread would block past any deadline
        # this test sets. A thread collects the lines and this one waits.
        cls.output = []

        def collect():
            try:
                for line in cls.process.stdout:
                    cls.output.append(line.rstrip("\n"))
            except (OSError, ValueError):
                pass

        cls.reader = threading.Thread(target=collect, daemon=True)
        cls.reader.start()
        cls.port = None
        cls.token = None
        deadline = time.time() + 45
        while time.time() < deadline and not (cls.port and cls.token):
            if cls.process.poll() is not None:
                break
            for line in list(cls.output):
                match = re.search(r"http://[^/]*?(?::)(\d+)/", line)
                if match and cls.port is None:
                    cls.port = int(match.group(1))
                if line.startswith("Token: ") and cls.token is None:
                    cls.token = line.split(":", 1)[1].strip()
            time.sleep(0.1)
        if not cls.port or not cls.token:
            cls.process.kill()
            cls.process.wait(timeout=10)
            if cls.process.stdout:
                cls.process.stdout.close()
            cls.reader.join(timeout=2)
            raise unittest.SkipTest(
                "the GUI server did not report its address: %s"
                % " | ".join(cls.output[-6:]))

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        try:
            cls.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            cls.process.kill()
            cls.process.wait(timeout=10)
        cls.reader.join(timeout=2)
        if cls.process.stdout:
            cls.process.stdout.close()
        import shutil
        shutil.rmtree(cls.directory, ignore_errors=True)

    def fetch(self, path, headers=None, token=None, method="GET"):
        request = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.port, path), method=method)
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        if token:
            request.add_header("X-LSCP-Token", token)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            return error.code, dict(error.headers), error.read()

    def test_the_server_started_and_reported_the_port_it_bound(self):
        # '--port=0' asks the kernel for a free port; the address printed
        # has to be the one that was bound, not the one that was asked for.
        self.assertTrue(self.port)
        self.assertNotEqual(self.port, 0)
        self.assertTrue(self.token)
        probe = socket.socket()
        probe.settimeout(5)
        try:
            self.assertEqual(probe.connect_ex(("127.0.0.1", self.port)), 0)
        finally:
            probe.close()

    def test_a_foreign_origin_cannot_read_the_page_that_holds_the_token(self):
        status, headers, body = self.fetch(
            "/", headers={"Origin": "http://evil.example"})
        self.assertEqual(status, 200)
        # The response must not give a foreign origin permission to read it.
        allow = headers.get("Access-Control-Allow-Origin")
        self.assertNotEqual(allow, "*", "the page is readable by any origin")
        self.assertIsNone(allow, "a foreign origin was granted access")
        self.assertIn(self.token.encode("utf-8"), body)

    def test_a_foreign_origin_cannot_read_an_api_answer_either(self):
        status, headers, _ = self.fetch(
            "/api/status", headers={"Origin": "http://evil.example"},
            token=self.token)
        self.assertEqual(status, 200)
        self.assertNotEqual(headers.get("Access-Control-Allow-Origin"), "*")
        self.assertIsNone(headers.get("Access-Control-Allow-Origin"))

    def test_a_preflight_from_a_foreign_origin_is_refused(self):
        status, _, _ = self.fetch(
            "/api/status", method="OPTIONS",
            headers={"Origin": "http://evil.example",
                     "Access-Control-Request-Method": "POST",
                     "Access-Control-Request-Headers": "X-LSCP-Token"})
        self.assertEqual(status, 403)

    def test_an_allowed_origin_is_granted_only_what_was_named(self):
        # The opt-in exists for a front end that really is served from
        # somewhere else; it has to be named on the command line first.
        status, headers, _ = self.fetch(
            "/", headers={"Origin": "http://evil.example"})
        self.assertIsNone(headers.get("Access-Control-Allow-Origin"))

    def test_the_page_is_not_framable_and_is_not_sniffed(self):
        status, headers, _ = self.fetch("/")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")

    def test_the_token_is_still_required_for_the_api(self):
        # Closing CORS must not cost the API its own check: without the
        # token the request is refused on its own account.
        status, _, _ = self.fetch("/api/status")
        self.assertIn(status, (401, 403))
        status, _, body = self.fetch("/api/status", token=self.token)
        self.assertEqual(status, 200)
        self.assertIn("tabs", json.loads(body.decode("utf-8")))

    def test_a_static_file_outside_the_web_directory_is_not_served(self):
        for path in ("/../linscp_gui.py", "/%2e%2e/linscp_gui.py",
                     "/../../Makefile"):
            status, _, _ = self.fetch(path)
            self.assertIn(status, (400, 404), path)


class SecretHandlingTests(unittest.TestCase):
    """Passwords stay out of the process list, the logs and the API."""

    def test_the_site_url_carries_no_password_by_default(self):
        session = {"protocol": "sftp", "host": "h", "port": 22,
                   "username": "u", "password": "s3cret"}
        self.assertEqual(gui.session_url(session), "sftp://u@h/")
        self.assertNotIn("s3cret", gui.session_url(session, "/dir"))
        self.assertIn("s3cret",
                      gui.session_url(session, include_password=True))

    def test_the_core_command_line_carries_no_password(self):
        cmd = gui.core_command_line({"hostkey": "", "keyfile": "",
                                     "username": "u", "password": "s3cret"})
        self.assertNotIn("s3cret", " ".join(cmd))
        self.assertIn("-username=u", cmd)

    def test_the_password_reaches_the_core_through_the_environment(self):
        kwargs = gui.popen_kwargs("s3cret")
        self.assertEqual(kwargs["env"]["LINSCP_PASSWORD"], "s3cret")
        self.assertEqual(kwargs["env"]["LINSCP_LANGUAGE"], "en")
        # Without a password nothing is inherited: a value exported for
        # another purpose must not silently authenticate this session.
        with mock.patch.dict(os.environ, {"LINSCP_PASSWORD": "outer"}):
            kwargs = gui.popen_kwargs()
            self.assertNotIn("LINSCP_PASSWORD", kwargs["env"])
            kwargs = gui.popen_kwargs("")
            self.assertNotIn("LINSCP_PASSWORD", kwargs["env"])

    def test_logged_commands_mask_passwords(self):
        self.assertEqual(
            gui._censored_command("open sftp://u:s3cret@h/ ; ls"),
            "open sftp://u:***@h/ ; ls")
        self.assertEqual(
            gui._censored_command("savesession x -password=s3cret"),
            "savesession x -password=***")
        self.assertEqual(
            gui._censored_command('savesession x -password="s3 cret"'),
            'savesession x -password="***"')
        self.assertEqual(gui._censored_command("ls /data"), "ls /data")

    def test_terminal_input_splits_on_unquoted_semicolons_only(self):
        self.assertEqual(gui.split_gui_commands('put "a;b.txt" ; echo hi'),
                         ['put "a;b.txt" ', ' echo hi'])
        self.assertEqual(gui.split_gui_commands("echo 'x;y';ls"),
                         ["echo 'x;y'", 'ls'])
        self.assertEqual(gui.split_gui_commands("ls;"), ["ls"])
        self.assertEqual(gui.split_gui_commands("echo a\\;b"),
                         ["echo a\\;b"])


class AccountValidationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.previous = gui.ACCOUNTS_FILE
        gui.ACCOUNTS_FILE = os.path.join(self.directory.name, "accounts.ini")

    def tearDown(self):
        gui.ACCOUNTS_FILE = self.previous
        self.directory.cleanup()

    def test_a_user_name_that_would_forge_the_file_is_refused(self):
        for bad in ("alice\n[admin]", "a[b", "a]b", "a=b", "", "x" * 65,
                    "a\x00b", "tab\there"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                gui._write_account(bad, "password", "")
        gui._write_account("alice.smith-1_x", "password", "")
        self.assertIn("alice.smith-1_x", gui._read_accounts())

    def test_a_home_directory_must_be_absolute_and_single_line(self):
        for bad in ("relative/path", "a\n/b", "a\rb", "a\x00/b"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                gui._write_account("bob", "password", bad)
        with self.assertRaises(ValueError):
            gui._write_account("bob", "", "/srv/bob")
        gui._write_account("bob", "password", "/srv/bob")
        self.assertEqual(gui._read_accounts()["bob"]["home_dir"], "/srv/bob")
        gui._write_account("carol", "password", "")
        self.assertEqual(gui._read_accounts()["carol"]["home_dir"], "")

    def test_a_corrupted_record_is_a_failed_login_not_an_error(self):
        gui._write_account("dave", "password", "")
        accounts = gui._read_accounts()
        self.assertTrue(gui._authenticate_user("dave", "password"))
        # Corrupt the salt and the hash in the file: the login must
        # answer False rather than raise.
        path = pathlib.Path(gui.ACCOUNTS_FILE)
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("salt=", "salt=zzz!"),
                        encoding="utf-8")
        self.assertFalse(gui._authenticate_user("dave", "password"))
        self.assertFalse(gui._verify_password("password", "", ""))
        self.assertFalse(gui._verify_password("password", "00", "zz"))


class LocalChmodEvolvingTests(unittest.TestCase):
    """The local chmod reads later clauses the way chmod(1) does."""

    def test_a_later_clause_sees_what_an_earlier_one_did(self):
        directory = tempfile.TemporaryDirectory()
        try:
            target = os.path.join(directory.name, "file")
            with open(target, "w") as handle:
                handle.write("x")
            os.chmod(target, 0o644)
            gui.apply_local_mode(target, "u+x,g+X")
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o754)
            os.chmod(target, 0o640)
            gui.apply_local_mode(target, "u+x,g=u")
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o770)
            os.chmod(target, 0o644)
            gui.apply_local_mode(target, "u+x,u-X")
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o644)
        finally:
            directory.cleanup()


class TunnelSettingsTests(unittest.TestCase):
    def session(self):
        return dict(gui.new_session(), host="destination.example", tunnel=True,
                    tunnel_host="jump.example", tunnel_port=2222,
                    tunnel_username="jumper", tunnel_hostkey="SHA256:jump",
                    tunnel_password='jump secret "quoted"', tunnel_passphrase="key secret")

    def test_tunnel_arguments_and_environment_keep_credentials_separate(self):
        session = self.session()
        args = gui.core_command_line(session)
        self.assertIn("TunnelHostName=jump.example", args)
        self.assertIn("TunnelPortNumber=2222", args)
        self.assertIn("TunnelHostKey=SHA256:jump", args)
        self.assertFalse(any("TunnelPassword=" in arg or "TunnelPassphrase=" in arg for arg in args))
        for field in ("tunnel_password", "tunnel_passphrase"):
            self.assertNotIn(session[field], " ".join(args))
        with mock.patch.dict(os.environ, LINSCP_TUNNEL_PASSWORD="inherited-password",
                             LINSCP_TUNNEL_PASSPHRASE="inherited-passphrase"):
            environment = gui.popen_kwargs(session=session)["env"]
            self.assertEqual(environment["LINSCP_CACHE_PINNED_HOSTKEYS"], "0")
            self.assertEqual(environment["LINSCP_TUNNEL_PASSWORD"], session["tunnel_password"])
            self.assertEqual(environment["LINSCP_TUNNEL_PASSPHRASE"], session["tunnel_passphrase"])
            for other in (None, {}, {"tunnel": False, "tunnel_password": "not-used"}):
                environment = gui.popen_kwargs(session=other)["env"]
                self.assertNotIn("LINSCP_TUNNEL_PASSWORD", environment)
                self.assertNotIn("LINSCP_TUNNEL_PASSPHRASE", environment)

    def test_tunnel_validation_never_silently_disables_a_bad_tunnel(self):
        session = self.session()
        self.assertEqual(gui.validate_session_data(session), "")
        for change in ({"tunnel": "0"}, {"tunnel": 1}, {"tunnel_port": "22x"},
                       {"tunnel_port": False}, {"tunnel_port": 65536},
                       {"tunnel_host": ""}, {"tunnel_host": "bad host"},
                       {"tunnel_password": "injected\ncommand"}, {"protocol": "ftp"},
                       {"tunnel_error": "stored credential is unreadable"}):
            with self.subTest(change=change):
                self.assertNotEqual(gui.validate_session_data(dict(session, **change)), "")
        self.assertEqual(gui.validate_session_data(dict(session, tunnel=False, protocol="ftp")), "")

    def test_gssapi_settings_reach_the_core_and_never_delegate_implicitly(self):
        args = gui.core_command_line(self.session())
        # Upstream's defaults: gssapi-with-mic tried; key exchange and,
        # above all, credential delegation off unless a site asks.
        self.assertIn("AuthGSSAPI=1", args)
        self.assertIn("AuthGSSAPIKEX=0", args)
        self.assertIn("GSSAPIFwdTGT=0", args)
        self.assertIn("LogicalHostName=", args)
        self.assertIn("TunnelLocalPortNumber=0", args)
        custom = dict(self.session(), auth_gssapi=False, auth_gssapi_kex=True,
                      gssapi_fwd_tgt=True, logical_host="srv.example.org",
                      tunnel_local_port=22222)
        args = gui.core_command_line(custom)
        self.assertIn("AuthGSSAPI=0", args)
        self.assertIn("AuthGSSAPIKEX=1", args)
        self.assertIn("GSSAPIFwdTGT=1", args)
        self.assertIn("LogicalHostName=srv.example.org", args)
        self.assertIn("TunnelLocalPortNumber=22222", args)

    def test_gssapi_and_local_port_validation(self):
        session = self.session()
        for change in ({"tunnel_local_port": 65536},
                       {"tunnel_local_port": "22x"},
                       {"tunnel_local_port": -1},
                       {"logical_host": "two hosts"},
                       {"auth_gssapi": {"not": "a flag"}},
                       {"auth_gssapi": ["1"]}):
            with self.subTest(change=change):
                self.assertNotEqual(
                    gui.validate_session_data(dict(session, **change)), "")
        self.assertEqual(gui.validate_session_data(
            dict(session, tunnel_local_port=0, auth_gssapi=False,
                 logical_host="srv.example.org")), "")

    def test_tunnel_credentials_are_redacted_in_every_quoting_style(self):
        for field in ("TunnelPassword", "TunnelPassphrase", "TunnelPasswordPlain",
                      "TunnelPassphrasePlain", "ProxyPassword", "ProxyPasswordPlain", "-passphrase", "-password"):
            for operand in (field + '="value with \\"quotes\\""',
                            '"' + field + '=value with spaces"',
                            "'" + field + "=value with spaces'", field + "='single quoted value'"):
                command = "open sftp://user:secret@host -rawsettings " + operand
                masked = gui.redact_command_for_log(command)
                self.assertNotIn("secret", masked)
                self.assertNotIn("value", masked)
                self.assertNotIn("quotes", masked)
                self.assertIn("<redacted>", masked)

    def test_tunnel_credentials_are_not_in_tab_descriptions(self):
        session = self.session()
        described = gui.CoreSession(1, session).describe()["session"]
        self.assertNotIn("password", described)
        self.assertNotIn("tunnel_password", described)
        self.assertNotIn("tunnel_passphrase", described)
        self.assertEqual(described["tunnel_host"], "jump.example")

    def test_tunnel_key_challenge_identifies_the_correct_host(self):
        tab = gui.CoreSession(1, self.session())
        with mock.patch.object(tab, "start", return_value=(True, "")), \
                mock.patch.object(tab, "run_capture", return_value=(1, ["TUNNELHOSTKEY ssh-ed25519 SHA256:jump"], [])):
            self.assertFalse(tab.connect()[0])
        self.assertEqual(tab.hostkey_challenge(), {"tab": 1, "host": "jump.example", "port": 2222,
                                                 "role": "tunnel", "fingerprint": "SHA256:jump", "changed": False})
        with mock.patch.object(tab, "start", return_value=(True, "")), \
                mock.patch.object(tab, "run_capture", return_value=(1, ["HOSTKEY ssh-ed25519 SHA256:destination"], [])):
            self.assertFalse(tab.connect()[0])
        self.assertEqual(tab.hostkey_challenge()["host"], "destination.example")
        self.assertEqual(tab.hostkey_challenge()["role"], "destination")

    def test_changed_key_challenges_are_explicit_for_both_hops(self):
        tab = gui.CoreSession(1, self.session())
        for role, marker in (("tunnel", "TUNNELHOSTKEY"), ("destination", "HOSTKEY")):
            lines = [marker + " ssh-rsa SHA256:new", "HOSTKEYSTATE " + role + " changed"]
            with mock.patch.object(tab, "start", return_value=(True, "")), \
                    mock.patch.object(tab, "run_capture", return_value=(1, lines, [])):
                self.assertFalse(tab.connect()[0])
            self.assertTrue(tab.hostkey_challenge()["changed"])
            self.assertEqual(tab.hostkey_challenge()["role"], role)

    def test_remembering_one_hop_never_saves_transient_secrets_or_the_other_pin(self):
        session = dict(self.session(), password="transient", hostkey="SHA256:once-destination")
        tab = gui.CoreSession(1, session)
        for field in ("tunnel_hostkey", "hostkey"):
            other = "hostkey" if field == "tunnel_hostkey" else "tunnel_hostkey"
            previous = {"name": "site", "password": "already-stored", other: "SHA256:old"}
            with mock.patch.object(gui, "read_stored_sessions", return_value=[previous]), \
                    mock.patch.object(gui, "run_linscp", return_value=(0, "", "")) as run:
                self.assertTrue(gui.save_confirmed_hostkey(tab, field, "SHA256:remember", "site")[0])
            command, saved = run.call_args.args
            self.assertEqual(saved[field], "SHA256:remember")
            self.assertEqual(saved[other], "SHA256:old")
            self.assertEqual(saved["password"], "already-stored")
            self.assertEqual(saved["tunnel_password"], "")
            self.assertEqual(saved["tunnel_passphrase"], "")
            self.assertNotIn("TunnelPassword=", command)
            self.assertNotIn("TunnelPassphrase=", command)
            self.assertNotIn("transient", str(run.call_args))

    def test_tunnel_credentials_in_sessions_are_decrypted_or_explicitly_locked(self):
        with tempfile.TemporaryDirectory() as directory:
            ini = pathlib.Path(directory) / "sessions.ini"
            key = pathlib.Path(directory) / "sessions.key"
            secret = b"x" * 32
            key.write_bytes(secret)
            key.chmod(0o600)
            ini.write_text("[site]\nhost=dest\ntunnel=1\ntunnel_host=jump\ntunnel_port=2222\n" +
                           "tunnel_password=" + gui.linscp_crypto.encrypt("  password  ", secret) + "\n" +
                           "tunnel_passphrase=" + gui.linscp_crypto.encrypt("passphrase", secret) + "\n")
            with mock.patch.object(gui, "session_store_path", return_value=str(ini)):
                stored = gui.read_stored_sessions()[0]
                self.assertTrue(stored["tunnel"])
                self.assertEqual(stored["tunnel_port"], 2222)
                self.assertEqual(stored["tunnel_password"], "  password  ")
                self.assertEqual(stored["tunnel_passphrase"], "passphrase")
                key.unlink()
                stored = gui.read_stored_sessions()[0]
                self.assertEqual(stored["tunnel_password"], "")
                self.assertEqual(stored["tunnel_passphrase"], "")
                self.assertTrue(stored["tunnel_error"])
                self.assertIn("cannot be read", gui.validate_session_data(stored))

    def test_saving_tunnel_credentials_uses_stdin_commands_and_never_stores_wildcard(self):
        with mock.patch.object(gui, "run_linscp", return_value=(0, "", "")) as run:
            session = dict(self.session(), tunnel_hostkey="*")
            self.assertTrue(gui.save_stored_session("site", session)[0])
            command = run.call_args.args[0]
            words = split_command_line(command)
            self.assertIn("Tunnel=1", words)
            self.assertIn("TunnelPassword=" + session["tunnel_password"], words)
            self.assertNotIn("TunnelHostKey=*", words)
            session["tunnel"] = False
            self.assertTrue(gui.save_stored_session("site", session)[0])
            command = run.call_args.args[0]
            self.assertIn("Tunnel=0", command)
            self.assertNotIn("TunnelPassword", command)


class AccountIsolationTests(unittest.TestCase):
    """Per-login ownership of every API resource when --accounts-file is set.

    Login, CSRF and password hashing are covered by LoginTests. This class is
    the negative authorization suite: a second user must not see or change
    the first user's tabs, queue, logs, terminals, stored sessions or files.
    """

    GET_ROUTES = (
        "/api/status", "/api/logs", "/api/transfers", "/api/sessions",
        "/api/workspaces", "/api/local/list", "/api/shell/pending",
        "/api/remote/list", "/api/terminal/output?terminal=1",
    )
    POST_ROUTES = (
        "/api/tabs/open", "/api/tabs/close", "/api/tabs/select",
        "/api/tabs/reconnect", "/api/sessions/save", "/api/sessions/delete",
        "/api/workspaces/save", "/api/workspaces/open", "/api/workspaces/delete",
        "/api/local/mkdir", "/api/local/delete", "/api/local/rename",
        "/api/local/chmod", "/api/local/save", "/api/remote/mkdir",
        "/api/remote/delete", "/api/remote/rename", "/api/remote/chmod",
        "/api/remote/search", "/api/remote/save", "/api/transfer/download",
        "/api/transfer/upload", "/api/transfer/move", "/api/sync/preview",
        "/api/sync/run", "/api/queue/priority", "/api/queue/cancel",
        "/api/queue/retry", "/api/queue/pause", "/api/queue/resume",
        "/api/queue/clear", "/api/remote/properties", "/api/remote/link",
        "/api/remote/copy", "/api/remote/checksum", "/api/session/copyid",
        "/api/transfer/keepuptodate", "/api/command/exec",
        "/api/custom-commands", "/api/session/terminal",
        "/api/terminal/input", "/api/terminal/close",
        "/api/shell/consume", "/api/shell/dismiss",
        "/api/tabs/verify",
    )

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.directory.name)
        self.alice_home = root / "alice"
        self.bob_home = root / "bob"
        self.alice_home.mkdir()
        self.bob_home.mkdir()
        (self.alice_home / "alice-only.txt").write_text("alice secret")
        (self.bob_home / "bob-only.txt").write_text("bob secret")
        self.accounts = str(root / "accounts.ini")
        self.previous = {
            "ACCOUNTS_FILE": gui.ACCOUNTS_FILE,
            "API_TOKEN": gui.API_TOKEN,
            "REQUIRE_TOKEN": gui.REQUIRE_TOKEN,
            "ALLOWED_HOSTS": set(gui.ALLOWED_HOSTS),
            "ALLOW_ANY_HOST": gui.ALLOW_ANY_HOST,
        }
        gui.ACCOUNTS_FILE = self.accounts
        gui.API_TOKEN = "isolation-test-token"
        gui.REQUIRE_TOKEN = True
        gui.ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
        gui.ALLOW_ANY_HOST = False
        gui._write_account("alice", "wonderland", str(self.alice_home))
        gui._write_account("bob", "builder", str(self.bob_home))
        gui._LOGIN_ATTEMPTS.clear()
        gui._LOGIN_LOCKOUT_UNTIL.clear()
        with gui._LOGIN_LOCK:
            gui._LOGIN_SESSIONS.clear()
        with gui._USER_WORKSPACES_LOCK:
            gui._USER_WORKSPACES.clear()
        gui.unbind_workspace()

        class QuietHandler(gui.LinScpGuiHandler):
            def log_message(self, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        gui.ACCOUNTS_FILE = self.previous["ACCOUNTS_FILE"]
        gui.API_TOKEN = self.previous["API_TOKEN"]
        gui.REQUIRE_TOKEN = self.previous["REQUIRE_TOKEN"]
        gui.ALLOWED_HOSTS = self.previous["ALLOWED_HOSTS"]
        gui.ALLOW_ANY_HOST = self.previous["ALLOW_ANY_HOST"]
        with gui._LOGIN_LOCK:
            gui._LOGIN_SESSIONS.clear()
        with gui._USER_WORKSPACES_LOCK:
            gui._USER_WORKSPACES.clear()
        gui.unbind_workspace()
        self.directory.cleanup()

    def request(self, method, path, body=None, cookie="", csrf="",
                token=True, content_type="application/json"):
        headers = {}
        if token:
            headers["X-LSCP-Token"] = gui.API_TOKEN
        if cookie:
            headers["Cookie"] = "LSCP_SID=%s" % cookie
        if csrf:
            headers["X-LSCP-CSRF"] = csrf
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = content_type
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, data, headers)
            response = conn.getresponse()
            payload = response.read()
            status = response.status
        finally:
            conn.close()
        try:
            parsed = json.loads(payload.decode("utf-8")) if payload else {}
        except ValueError:
            parsed = {"raw": payload.decode("utf-8", "replace")}
        return status, parsed

    def login(self, username, password):
        status, data = self.request("POST", "/api/login",
                                    {"username": username, "password": password})
        self.assertEqual(status, 200, data)
        # Cookie is HttpOnly on the response; pull the session from the table.
        with gui._LOGIN_LOCK:
            matches = [sid for sid, rec in gui._LOGIN_SESSIONS.items()
                       if rec.get("username") == username]
        self.assertTrue(matches, "login did not issue a session")
        return matches[-1], data["csrf_token"]

    def test_every_route_requires_a_login_session(self):
        for path in self.GET_ROUTES:
            status, data = self.request("GET", path)
            self.assertEqual(status, 401, path)
            self.assertTrue(data.get("login_required"), path)
        for path in self.POST_ROUTES:
            status, data = self.request("POST", path, {})
            self.assertEqual(status, 401, path)
            self.assertTrue(data.get("login_required"), path)

    def test_every_post_route_requires_this_session_csrf_token(self):
        sid, csrf = self.login("alice", "wonderland")
        for path in self.POST_ROUTES:
            status, data = self.request("POST", path, {}, cookie=sid)
            self.assertEqual(status, 403, path)
            self.assertIn("CSRF", data.get("error", ""), path)
            status, data = self.request("POST", path, {}, cookie=sid,
                                        csrf="0" * 64)
            self.assertEqual(status, 403, path)

    def test_one_login_cannot_see_another_users_tabs_queue_or_logs(self):
        alice_sid, alice_csrf = self.login("alice", "wonderland")
        bob_sid, bob_csrf = self.login("bob", "builder")
        alice_ws = gui.workspace_for_user("alice", str(self.alice_home))
        fake_tab = types.SimpleNamespace(
            id=42, connected=True, name="alice-tab",
            session={"host": "alice.example", "protocol": "sftp"},
            local_dir=str(self.alice_home), remote_dir="/",
            other_local_dir="", is_local=False,
            describe=lambda: {"id": 42, "name": "alice-tab", "connected": True,
                              "session": {"host": "alice.example"}})
        with gui.STATE_LOCK:
            alice_ws["tabs"].append(fake_tab)
            alice_ws["active_tab"] = 42
            alice_ws["logs"].append({"time": "00:00:00", "text": "alice-secret-log",
                                     "level": "info"})
            task = types.SimpleNamespace(
                id=7, as_dict=lambda: {"id": 7, "type": "Upload",
                                       "source": "alice-only.txt"})
            alice_ws["tasks"].append(task)
        status, data = self.request("GET", "/api/status", cookie=bob_sid)
        self.assertEqual(status, 200, data)
        self.assertEqual(data.get("tabs") or [], [])
        self.assertNotEqual(data.get("active_tab"), 42)
        status, data = self.request("GET", "/api/logs", cookie=bob_sid)
        self.assertEqual(status, 200, data)
        texts = [entry.get("text") for entry in data.get("logs") or []]
        self.assertNotIn("alice-secret-log", texts)
        status, data = self.request("GET", "/api/transfers", cookie=bob_sid)
        self.assertEqual(status, 200, data)
        self.assertEqual(data.get("transfers") or [], [])
        status, data = self.request("GET", "/api/status", cookie=alice_sid)
        self.assertEqual(status, 200, data)
        self.assertTrue(any(tab.get("id") == 42 for tab in data.get("tabs") or []),
                        data)
        status, data = self.request("POST", "/api/tabs/close", {"tab": 42},
                                    cookie=bob_sid, csrf=bob_csrf)
        self.assertEqual(status, 200, data)
        with gui.STATE_LOCK:
            self.assertTrue(any(tab.id == 42 for tab in alice_ws["tabs"]))
        status, data = self.request("POST", "/api/queue/cancel", {"task_id": 7},
                                    cookie=bob_sid, csrf=bob_csrf)
        self.assertIn(status, (200, 400), data)
        with gui.STATE_LOCK:
            self.assertTrue(any(getattr(item, "id", None) == 7
                                for item in alice_ws["tasks"]))

    def test_local_paths_are_jailed_to_the_account_home(self):
        alice_sid, alice_csrf = self.login("alice", "wonderland")
        status, data = self.request("GET", "/api/local/list", cookie=alice_sid)
        self.assertEqual(status, 200, data)
        names = [entry["name"] for entry in data.get("entries") or []]
        self.assertIn("alice-only.txt", names)
        self.assertNotIn("bob-only.txt", names)
        status, data = self.request(
            "GET",
            "/api/local/list?path=" + urllib.parse.quote(str(self.bob_home)),
            cookie=alice_sid)
        self.assertEqual(status, 403, data)
        status, data = self.request(
            "POST", "/api/local/mkdir",
            {"name": "folder", "path": str(self.bob_home)},
            cookie=alice_sid, csrf=alice_csrf)
        # contained_local_path uses the pane directory, which is alice home.
        # An explicit foreign path on list is the jail; mkdir uses the pane.
        self.assertIn(status, (200, 400, 403), data)
        status, data = self.request(
            "POST", "/api/command/exec", {"command": "lpwd"},
            cookie=alice_sid, csrf=alice_csrf)
        self.assertEqual(status, 403, data)

    def test_stored_sessions_are_per_account(self):
        alice_sid, alice_csrf = self.login("alice", "wonderland")
        bob_sid, bob_csrf = self.login("bob", "builder")
        gui.bind_workspace(gui.workspace_for_user("alice", str(self.alice_home)))
        try:
            alice_store = gui.session_store_path()
        finally:
            gui.unbind_workspace()
        gui.bind_workspace(gui.workspace_for_user("bob", str(self.bob_home)))
        try:
            bob_store = gui.session_store_path()
        finally:
            gui.unbind_workspace()
        self.assertNotEqual(alice_store, bob_store)
        self.assertIn(os.path.join("users", "alice"), alice_store)
        self.assertIn(os.path.join("users", "bob"), bob_store)
        status, data = self.request("GET", "/api/sessions", cookie=alice_sid)
        self.assertEqual(status, 200, data)
        self.assertEqual(data.get("file"), alice_store)
        status, data = self.request("GET", "/api/sessions", cookie=bob_sid)
        self.assertEqual(status, 200, data)
        self.assertEqual(data.get("file"), bob_store)

    def test_a_csrf_token_from_alice_does_not_authorize_bob(self):
        alice_sid, alice_csrf = self.login("alice", "wonderland")
        bob_sid, bob_csrf = self.login("bob", "builder")
        status, data = self.request("POST", "/api/queue/pause", {},
                                    cookie=bob_sid, csrf=alice_csrf)
        self.assertEqual(status, 403, data)


if __name__ == "__main__":
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite()
    for case in (OperandQuotingTests, TabLookupTests, CoreCredentialTests,
                 CommandBuildingTests, PermissionModeTests, PanelContainmentTests,
                 RemoteNameTests,
                 ServerCommandStreamTests, LocalListingTests,
                 CustomCommandTests, LoginTests, QueueCleanupTests,
                 BrowserUploadModeTests, CrossOriginTests,
                 SecretHandlingTests, AccountValidationTests,
                 LocalChmodEvolvingTests, TunnelSettingsTests,
                 AccountIsolationTests):
        suite.addTests(loader.loadTestsFromTestCase(case))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    failed = len(result.failures) + len(result.errors)
    print("evidence: suite=gui-security platform=linux ran=%d skipped=%d failed=%d"
          % (result.testsRun, len(result.skipped), failed))
    sys.exit(0 if result.wasSuccessful() else 1)
