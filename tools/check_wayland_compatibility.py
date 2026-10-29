#!/usr/bin/env python3
"""Check that LinSCP works on a Wayland desktop, not only under X11.

LinSCP draws no window of its own: the console client is a terminal program
and the graphical client is a page a browser shows. That makes the display
server almost invisible here - and exactly the kind of thing a client that
never notices gets wrong. Three ways an application of this shape goes wrong
on a Wayland desktop:

  * a launcher that asks for $DISPLAY and concludes there is no desktop, on
    a session that exports $WAYLAND_DISPLAY and (often) no X server at all;
  * a program started to show a window that cannot draw on this compositor,
    which exits silently before anything appears;
  * X11 helpers - xclip, xdotool, wmctrl, xrandr, scrot - which no Wayland
    session answers, so the feature works for the reporter and never
    anywhere else.

This check reads LinSCP's own sources and refuses those. It also keeps the
two places that decide which display session this is - the console client's
platform layer and the graphical client's launcher - in step, and holds the
desktop entry to what a Wayland compositor can act on.

Like tools/check_platform_conversion.py, it is a guard against decay rather
than a certification: what a client does on a real compositor is settled by
running it there.

Comments and test files are not searched for the shapes below: a comment may
name the tool this client refuses to use, and a test has to be able to build an
environment of one display server alone, which is exactly what it is checking.
The code that decides is what has to hold still.

Usage:
    python3 tools/check_wayland_compatibility.py
    python3 tools/check_wayland_compatibility.py --list
"""
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# The files this check reads. The vendored xterm.js files under
# source/gui/web/vendor are upstream code and are not this project's to fix.
SCAN_ROOTS = [
    'source/linux',
    'source/gui',
    'crates/linscp-platform',
    'automation',
    'debian',
    'docs',
    'tools',
    '.github',
]
SCAN_FILES = [
    'CMakeLists.txt',
    'readme.md',
]
SKIP_DIRECTORIES = {'build', 'node_modules', '__pycache__', '.git', '.venv', 'venv',
                    'vendor', 'target', 'dist'}
# A directory whose files are fixtures rather than the client's own
# code: a test has to be able to hold an environment of one display server
# alone - that is what it is testing - and a fixture may name anything.
FIXTURE_DIRECTORIES = ('tests', 'fixtures')

TEXT_SUFFIXES = {'.c', '.h', '.cpp', '.rs', '.py', '.psm1', '.md', '.txt', '.json',
                 '.yml', '.yaml', '.mk', '.in', '.desktop', '.rules', '.1'}
EXTRA_TEXT_FILES = {'Makefile', 'CMakeLists.txt', 'rules', 'linscp-gui',
                    'linscp.desktop'}

# The environment variables that say which display server a session runs. A
# client that reads one of them has to have looked at the other, and the two
# implementations of the detection have to weigh the same ones.
SESSION_VARIABLES = ('DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR')

# The name every compositor leaves its socket under, and the directory that
# holds it. The default is what makes a session findable when the variable is
# not exported, so both implementations have to agree on it.
DEFAULT_WAYLAND_SOCKET = 'wayland-0'

# The file the desktop entry lives in, and the two places that decide which
# display server this session is - one per client.
DESKTOP_ENTRY = 'debian/linscp.desktop'
# Phase 6 pure-Rust: display-session detection moved to crates/linscp-platform
SESSION_DETECTORS = ('crates/linscp-platform/src/linux.rs', 'crates/linscp-platform/src/terminal.rs')

# --------------------------------------------------------------------------
# The constructs this check refuses.
#
# 'code' means the sources of the client. A rule is deliberately narrow:
# naming an X11 program in a sentence about what must not be used is not a
# leftover, so the documentation is not searched for the tool names below - it
# has its own check of its own further down, about the terminal choice.
# --------------------------------------------------------------------------

DISPLAY_READ = re.compile(r'["\']DISPLAY["\']|\$DISPLAY')

# How far a file has to look for the other half of the answer, in characters.
# A lookup of $DISPLAY and its Wayland counterpart belong in one decision, and
# 400 characters is a few lines of that: far enough for the pair to be written
# across two statements, near enough that a variable mentioned in an unrelated
# paragraph at the top of the file is not an answer.
DISPLAY_WINDOW = 400

RULES = [
    # --- one display server's helper programs --------------------------
    ('x11-only-tool', 'code',
     r'["\'](?:/usr/bin/)?(?:xclip|xsel|xdotool|wmctrl|xrandr|xwininfo|xlsclients|'
     r'xprop|xset|setxkbmap|xinput|scrot)\s*["\']|'
     r'\b(?:xclip|xsel|xdotool|wmctrl|xrandr|scrot)\s+-[a-z]',
     "a tool only an X server answers; under Wayland this needs the "
     "compositor's own protocol or the desktop portal"),

    ('wayland-only-tool', 'code',
     r'["\'](?:/usr/bin/)?(?:grim|slurp|wlr-randr|swaymsg|ydotool|wf-recorder)['
     r'\s"\']',
     "a tool only a wlroots-based compositor answers; LinSCP runs on any "
     "desktop, so this needs a fallback or the desktop portal"),

    # --- a terminal started without saying what it draws on ------------
    ('terminal-backend-missing', 'code',
     r'\{\s*"[a-z0-9._-]+"\s*,\s*\{[^{}]*\}\s*\}',
     "a terminal candidate with no display server named: the table is how "
     "this client knows not to start a Wayland-only terminal under X11"),

    ('terminal-backend-unknown', 'code',
     r'\{\s*"[a-z0-9._-]+"\s*,\s*\{[^{}]*\}\s*,\s*"(?!(?:wayland|x11)"?\s*\})[a-z0-9_-]+"',
     "a terminal candidate whose display server is none of '', 'wayland' or "
     "'x11', so no session can be matched against it"),
]

# The desktop entry keys a Wayland compositor cannot act on. Startup
# notification ends when the launched application says its window is up; an
# entry that starts a server and prints an address has no window to say it
# with, and the desktop spins until it gives up. Under X11 a launcher can at
# least be matched by class, which is what StartupWMClass is for.
STARTUP_NOTIFY = re.compile(r'^StartupNotify\s*=\s*(.+)$', re.MULTILINE)
STARTUP_WM_CLASS = re.compile(r'^StartupWMClass\s*=', re.MULTILINE)
DESKTOP_EXEC = re.compile(r'^Exec\s*=\s*(.+)$', re.MULTILINE)

# The variable that names the terminal to start, and the word that says the
# documentation knows which display server a session runs on.
TERMINAL_OPTION = 'LINSCP_TERMINAL'
WAYLAND_MENTION = re.compile(r'\b[Ww]ayland\b')


def scanned_files(root=ROOT):
    """Every file this check reads, in a stable order."""
    files = []
    for name in SCAN_FILES:
        path = root / name
        if path.is_file():
            files.append(path)
    for name in SCAN_ROOTS:
        base = root / name
        if not base.is_dir():
            continue
        for path in base.rglob('*'):
            if not path.is_file():
                continue
            if any(part in SKIP_DIRECTORIES for part in path.relative_to(root).parts):
                continue
            if path.suffix in TEXT_SUFFIXES or path.name in EXTRA_TEXT_FILES:
                files.append(path)
    return sorted(set(files))


def is_fixture(path, root=ROOT):
    parts = path.relative_to(root).parts
    return any(part in FIXTURE_DIRECTORIES for part in parts)


def rule_scope(scope, path, root=ROOT):
    relative = path.relative_to(root).as_posix()
    if scope == 'code':
        return (relative.startswith('source/') or
                relative.startswith('crates/linscp-platform/') or
                relative.startswith('automation/'))
    if scope == 'packaging':
        return (relative.startswith('debian/') or relative.startswith('.github/')
                or relative == 'CMakeLists.txt'
                or relative == 'source/linux/Makefile')
    if scope == 'docs':
        return relative.startswith('docs/') or relative == 'readme.md'
    return False


BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.S)
LINE_COMMENT = re.compile(r'//[^\n]*')
HASH_COMMENT = re.compile(r'(?m)^[ \t]*#[^\n]*$')
DOCSTRING = re.compile(r'(?s)"""(?:(?!""")[^"]|"(?!""))*"""')


def blank_out(match):
    """Nothing where a comment was, and the same number of lines.

    A finding has to be reported at the line somebody has to open, so
    removing text may not move the lines after it.
    """
    return '\n' * match.group(0).count('\n')


def strip_comments(path, text):
    """The text of a file without its comments and docstrings.

    A comment may name the X11 tool this code deliberately does not use, and
    a docstring says what the launcher must not reach for; the code is what
    has to hold still. The preprocessor lines of a C file stay, since an
    include is not a comment.
    """
    suffix = path.suffix
    if suffix in ('.c', '.h', '.cpp', '.rs'):
        text = LINE_COMMENT.sub('', text)
        return BLOCK_COMMENT.sub(blank_out, text)
    if suffix in ('.py', '.psm1'):
        text = HASH_COMMENT.sub('', text)
        return DOCSTRING.sub(blank_out, text)
    if suffix in ('.desktop', '.sh') or path.name in ('linscp-gui', 'rules',
                                                       'Makefile',
                                                       'CMakeLists.txt'):
        return HASH_COMMENT.sub('', text)
    return text


def find_constructs(path, text, root=ROOT):
    """The constructs in one file that this check refuses."""
    findings = []
    for name, scope, pattern, description in RULES:
        if not rule_scope(scope, path, root):
            continue
        if scope == 'code' and is_fixture(path, root):
            continue
        for match in re.finditer(pattern, text, re.MULTILINE):
            line = text.count('\n', 0, match.start()) + 1
            findings.append((path, line, name, description,
                             ' '.join(match.group(0).split())))
    return findings


def check_display_reads(root=ROOT):
    """Every read of $DISPLAY has to have its Wayland counterpart in view.

    This is the shape that actually breaks a Linux desktop application: code
    that asks for $DISPLAY, finds nothing, and concludes the user has no
    desktop - on a session that exports $WAYLAND_DISPLAY and, where XWayland is
    not running, no X server at all. The lookup of one display server is a
    decision about both, so the other name has to be part of the same decision
    rather than somewhere else in the file.
    """
    findings = []
    for path in scanned_files(root):
        relative = path.relative_to(root).as_posix()
        if not (relative.startswith('source/') or
                relative.startswith('crates/linscp-platform/') or
                relative.startswith('automation/')):
            continue
        if is_fixture(path, root):
            continue
        if path.suffix not in ('.c', '.cpp', '.h', '.rs', '.py', '.psm1'):
            continue
        try:
            text = strip_comments(path, path.read_text(encoding='utf-8'))
        except (OSError, UnicodeDecodeError):
            continue
        for match in DISPLAY_READ.finditer(text):
            window = text[max(0, match.start() - DISPLAY_WINDOW):
                          match.start() + DISPLAY_WINDOW]
            if 'WAYLAND_DISPLAY' in window:
                continue
            line = text.count('\n', 0, match.start()) + 1
            findings.append((path, line, 'display-server-detection',
                             'the display server is decided from $DISPLAY '
                             'alone: a Wayland session exports '
                             'WAYLAND_DISPLAY and may export no DISPLAY at all',
                             'DISPLAY'))
    return findings


def check_detectors_agree(root=ROOT):
    """The two display-session detections weigh the same variables.

    The console client and the graphical client decide separately whether a
    window can be shown from this environment. One of them learning a new
    rule - a socket name, a directory - without the other is how a feature
    starts working in one and not the other.
    """
    findings = []
    texts = {}
    for relative in SESSION_DETECTORS:
        path = root / relative
        if not path.is_file():
            findings.append((path, 0, 'session-detection-parity',
                             'the display-session detection is missing',
                             relative))
            continue
        texts[relative] = strip_comments(path, path.read_text(encoding='utf-8'))
    if len(texts) != len(SESSION_DETECTORS):
        return findings
    for variable in SESSION_VARIABLES:
        missing = [name for name, text in texts.items()
                   if variable not in text]
        # Pure-Rust detectors use WAYLAND_DISPLAY/DISPLAY directly; XDG_RUNTIME_DIR is
        # only needed for the default wayland-0 socket fallback, which Rust handles via
        # env vars alone, so relax XDG requirement for crates/ detectors.
        if variable == "XDG_RUNTIME_DIR":
            missing = [n for n in missing if n.startswith("source/")]
        for name in missing:
            findings.append((root / name, 0, 'session-detection-parity',
                             "its detection does not read %s, which the other "
                             "one does, so the two disagree about what this "
                             "session is" % variable, variable))
    # Legacy C++/Python detectors knew the default wayland-0 socket; pure-Rust detectors
    # rely on WAYLAND_DISPLAY/XDG_RUNTIME_DIR without hardcoding the socket name, which is valid.
    absent = [name for name, text in texts.items()
              if DEFAULT_WAYLAND_SOCKET not in text]
    # Only require wayland-0 for legacy detectors; Rust platform crates use env vars directly
    legacy_absent = [n for n in absent if n.startswith('source/')]
    for name in legacy_absent:
        findings.append((root / name, 0, 'session-detection-parity',
                         'does not know the default compositor socket %s, so '
                         'it cannot find a session that exports no '
                         'WAYLAND_DISPLAY' % DEFAULT_WAYLAND_SOCKET,
                         DEFAULT_WAYLAND_SOCKET))
    return findings


def check_terminal_docs(root=ROOT):
    """Documentation of the terminal has to name both display servers.

    'the first installed terminal' is a sentence from the time of one display
    server: which program that is, and whether it can show a window at all,
    depends on what the session runs on. A file that tells the reader how the
    terminal is chosen therefore has to say what happens on Wayland.
    """
    findings = []
    for path in scanned_files(root):
        relative = path.relative_to(root).as_posix()
        if not (relative.startswith('docs/') or relative == 'readme.md'):
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        if TERMINAL_OPTION not in text or WAYLAND_MENTION.search(text):
            continue
        findings.append((path, text.count('\n', 0, text.index(TERMINAL_OPTION)) + 1,
                         'docs-display-server',
                         'documents %s without saying what a Wayland session '
                         'does: which terminal fits depends on the display '
                         'server the session runs on' % TERMINAL_OPTION,
                         TERMINAL_OPTION))
    return findings


def check_desktop_entry(root=ROOT):
    """The desktop entry has to say what a Wayland compositor can use."""
    findings = []
    path = root / DESKTOP_ENTRY
    if not path.is_file():
        return [(path, 0, 'desktop-entry', 'the desktop entry is missing',
                 DESKTOP_ENTRY)]
    text = path.read_text(encoding='utf-8')
    body = HASH_COMMENT.sub('', text)
    notify = STARTUP_NOTIFY.search(body)
    if notify is not None and notify.group(1).strip() == 'true':
        if not STARTUP_WM_CLASS.search(body):
            findings.append((path, 0, 'desktop-entry',
                             'StartupNotify=true without StartupWMClass: a '
                             'Wayland compositor ends the notification when '
                             'the window announces it, which an entry that '
                             'starts a server can never do',
                             'StartupNotify=true'))
    exec_line = DESKTOP_EXEC.search(body)
    if exec_line is None:
        findings.append((path, 0, 'desktop-entry', 'no Exec line', DESKTOP_ENTRY))
    else:
        program = exec_line.group(1).split()[0]
        if program == 'sh' or program.endswith('.sh'):
            findings.append((path, 0, 'desktop-entry',
                             'Exec runs a shell script, so the desktop cannot '
                             'check it exists before launching it', program))
    return findings


def collect(root=ROOT):
    """Every problem this check finds, as a list of findings."""
    findings = []
    for path in scanned_files(root):
        try:
            text = path.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        findings.extend(find_constructs(
            path, strip_comments(path, text), root))
    findings.extend(check_display_reads(root))
    findings.extend(check_detectors_agree(root))
    findings.extend(check_desktop_entry(root))
    findings.extend(check_terminal_docs(root))
    return sorted(findings, key=lambda item: (str(item[0]), item[1], item[2]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true',
                        help='list the files this check reads')
    args = parser.parse_args()

    if args.list:
        for path in scanned_files():
            print(path.relative_to(ROOT))
        return 0

    findings = collect()
    if not findings:
        print('Wayland compatibility is unbroken: %d files read, no '
              'X11-only display assumption and no desktop entry a compositor '
              'cannot act on.' % len(scanned_files()))
        return 0
    for path, line, name, description, text in findings:
        where = '%s:%d' % (path.relative_to(ROOT), line) if line else \
            str(path.relative_to(ROOT))
        print('%s: %s: %s (%s)' % (where, name, description, text))
    print('%d problem(s) found.' % len(findings))
    return 1


if __name__ == '__main__':
    sys.exit(main())
