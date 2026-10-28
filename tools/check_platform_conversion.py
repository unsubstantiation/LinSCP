#!/usr/bin/env python3
"""Check that the Windows-to-Linux conversion of LinSCP is complete.

LinSCP is a Linux-only client; the Windows port is gone (see
debian/changelog, 1.0-2). A claim like that decays quietly: a Windows
API call creeps into the front end, a file manager extension is copied
over half-translated, an installer ships a file another one does not.
This check makes the claim testable instead of a matter of trust.

It reads LinSCP's own sources - the console client, the graphical
client, the automation wrapper, the packaging, the CI workflows and the
documentation - and refuses:

  * Windows API calls, Windows headers and Windows build settings,
  * Windows environment variables, executables and path syntax,
  * files that belong to another platform,
  * an installed file that the Makefile, CMake or the Debian package
    installs and the others do not, and the other way round,
  * an error message whose wording contradicts the template it is
    filled into, and
  * an upstream product name outside the documented external-identifier
    allowlist.

The Windows-construct rules do not search comments or test fixtures:
a comment may name a Windows path to say what the client does with one,
and a test has to be able to hold a name that a POSIX file system allows
and a Windows one does not. The product-name rule searches them, subject
to the external-identifier allowlist below.

The vendored xterm.js files (source/gui/web/vendor) are upstream code
that is not scanned; everything else in the tree is this project's own.

Usage:
    python3 tools/check_platform_conversion.py
    python3 tools/check_platform_conversion.py --list
"""
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# The files this check reads. The vendored xterm.js files under
# source/gui/web/vendor are upstream code and are excluded on purpose.
SCAN_ROOTS = [
    'source/linux',
    'source/gui',
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

# Cross-platform workflows for the Rust/Tauri/TypeScript migration
# intentionally target Windows and Android runners alongside Linux; the
# Linux-only packaging rules below still guard the legacy build.yml,
# CMakeLists.txt, Makefile, and debian/ packaging.
CROSS_PLATFORM_WORKFLOWS = {
    '.github/workflows/rust-cross-platform.yml',
}

# Only these external identifiers may retain the upstream product name:
# upstream repository/API paths, XML namespaces, compatibility API names,
# external documentation URLs, Windows executable patterns and the fork
# notice. The name is assembled so this checker adds no reference.
UPSTREAM_PRODUCT = 'win' + 'scp'
BRAND_REFERENCE = re.compile(UPSTREAM_PRODUCT, re.I)
ALLOWED_BRAND_SPANS = tuple(re.compile(pattern, re.I) for pattern in (
    re.escape('http://' + UPSTREAM_PRODUCT + '.net/schema/session/1.0'),
    re.escape(UPSTREAM_PRODUCT + '/' + UPSTREAM_PRODUCT),
    re.escape(UPSTREAM_PRODUCT + '.net/eng/docs/logging_xml'),
    re.escape(UPSTREAM_PRODUCT + r'\.exe'),
    re.escape(UPSTREAM_PRODUCT + r'\.com'),
    re.escape('namespace ' + UPSTREAM_PRODUCT),
    re.escape('using ' + UPSTREAM_PRODUCT + ';'),
    re.escape(UPSTREAM_PRODUCT + '.sessionremoteexception'),
    re.escape(UPSTREAM_PRODUCT + '.sessionlocalexception'),
    re.escape('LinSCP began as a fork of ' + UPSTREAM_PRODUCT + '.'),
))

# A directory whose files are fixtures rather than the client's own
# code: a test may hold any name a file system allows.
FIXTURE_DIRECTORIES = ('tests', 'fixtures')

# The text files this check reads, by suffix. A binary or a data file
# is not searched: a PNG has no Windows API calls in it.
TEXT_SUFFIXES = {'.c', '.h', '.cpp', '.py', '.psm1', '.md', '.txt', '.json',
                  '.yml', '.yaml', '.mk', '.in', '.desktop', '.svg', '.rules'}

# Files that are not text but are in the tree by name.
EXTRA_TEXT_FILES = {'Makefile', 'CMakeLists.txt', 'rules', 'linscp-gui'}


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
    """Whether a file is a test fixture rather than the client's code."""
    parts = path.relative_to(root).parts
    return any(part in FIXTURE_DIRECTORIES for part in parts)


# --------------------------------------------------------------------------
# The Windows constructs this check refuses.
#
# Each rule is a name, a regular expression and the files it applies to.
# 'code' means the sources of the client (C, C++, Python, PowerShell);
# 'packaging' means the build, the package and the CI; 'docs' means the
# documentation. The rules are deliberately narrow: a mention of
# Windows in a sentence is not a leftover, and the documentation has to
# be able to say that the Windows port is gone.
# --------------------------------------------------------------------------

RULES = [
    # --- Windows API and headers -------------------------------------
    ('win32-api', 'code', r'\b(?:CreateFile[AW]?|CreateDirectory[AW]?|'
     r'DeleteFile[AW]?|MoveFile[AW]?|CopyFile[AW]?|GetWindowsDirectory|'
     r'GetSystemDirectory|GetTempPath[AW]?|GetTempFileName|'
     r'SHGetFolderPath|SHGetKnownFolderPath|SHGetSpecialFolderPath|'
     r'Reg(?:Open|Query|Set|Create|Delete|Close)Key(?:Ex)?|HKEY_'
     r'|MessageBox[AW]?|FindFirstFile[AW]?|FindNextFile[AW]?|'
     r'GetFileAttributes[AW]?|SetFileAttributes[AW]?|'
     r'ShellExecute[AW]?|WinExec|CreateProcess[AW]?|'
     r'GetModuleFileName[AW]?|GetCurrentProcess|'
     r'SetConsoleTextAttribute|WriteConsole[AW]?|'
     r'CoInitialize(?:Ex)?|WSAStartup|closesocket|'
     r'_beginthreadex|CreateThread|WaitForSingleObject)\s*\(',
     'a Windows API call'),

    ('win32-headers', 'code', r'#\s*include\s*[<"](?:windows|winsock2|ws2tcpip|'
     r'direct|io|process|objbase|shlobj|commctrl|windowsx|afxwin|'
     r'vcl|System|Registry|Winapi)\.h[>"]',
     'a Windows header'),

    ('win32-macros', 'code', r'^\s*#\s*(?:if|ifdef|ifndef|elif)\s+'
     r'(?:defined\s*\()?\s*(?:_WIN32|_WIN64|WIN32_LEAN_AND_MEAN|'
     r'_MSC_VER|__MINGW32__|_WIN32_WINNT)\b',
     'a Windows-only compilation branch'),

    ('win32-underscore-api', 'code', r'\b_(?:getcwd|chdir|mkdir|rmdir|unlink|'
     r'stat|stati64|putenv|putwenv|chmod|open|close|read|write|'
     r'fileno|isatty|lseek|strdup|stricmp|strnicmp|sprintf_s|strcpy_s|'
     r'strncpy_s|vsnprintf|snprintf)\s*\(',
     'a Windows-flavoured C runtime function'),

    # --- Windows environment and executables -------------------------
    ('win32-env', 'code', r'\b(?:APPDATA|LOCALAPPDATA|USERPROFILE|'
     r'SystemRoot|SystemDrive|windir|ProgramFiles|ProgramData|'
     r'CommonProgramFiles|HOMEDRIVE|HOMEPATH|COMSPEC)\b',
     'a Windows environment variable'),

    ('win32-exe', 'code', r'\b(?:cmd|notepad|explorer|powershell|'
     r'rundll32|regedit|mmc|wscript|cscript)\.exe\b',
     'a Windows executable'),

    ('win32-drive-letter', 'code', r'["\'][A-Za-z]:[\\/]',
     'a Windows drive letter'),

    # --- Windows build settings -------------------------------------
    ('win32-toolchain', 'packaging', r'\b(?:msvc|mingw|msbuild|nmake|'
     r'Visual Studio|cl\.exe|vcvars(?:32|64)?\.bat)\b',
     'a Windows toolchain'),

    ('win32-project', 'packaging', r'\.(?:sln|vcxproj|vcproj|dsp|dsw)\b',
     'a Windows project file'),

    ('win32-runner', 'packaging', r'runs-on:\s*windows',
     'a Windows CI runner'),

    # --- Documentation that tells the reader to use Windows ---------
    # The two executable names here are external Windows program names;
    # keep them so instructions to run them are still detected.
    ('win32-doc-instruction', 'docs',
     r'\b(?:' + UPSTREAM_PRODUCT + r'\.exe|' + UPSTREAM_PRODUCT + r'\.com|'
     r'regedit\.exe|C:\\Program Files(?: \(x86\))?)\b',
     'an instruction to use a Windows program'),
]

# The suffixes a file of another platform carries. A file with one of
# them in the tree is a leftover of the Windows port.
WINDOWS_FILE_SUFFIXES = ('.bat', '.cmd', '.sln', '.vcxproj', '.vcproj', '.dsp',
                         '.dsw', '.manifest')

# The file manager extension and the public C header that the Windows
# port left behind are gone; a file of either kind is a leftover.
REMOVED_ARTEFACTS = [
    ('source/linux/liblinscp.h',
     'the C ABI header of the Windows automation API; it declared a '
     'library that no build produces'),
    ('debian/linscp-nautilus.py',
     'the half-translated Nautilus extension; it ran no session, so it '
     'uploaded nothing'),
]

# The files an installation has to contain. Every installer named below
# has to install every one of them.
INSTALLED_FILES = [
    'source/gui/linscp_gui.py',
    'source/gui/linscp_crypto.py',
    'source/gui/explorer-commands.json',
    'automation/LinSCP.psm1',
    'automation/dotnet/LinSCP/LinSCP.csproj',
    'automation/dotnet/LinSCP/Session.cs',
    'automation/dotnet/LinSCP/LinSCPCompat.cs',
    'docs/linscp.1',
    'debian/linscp.desktop',
    'debian/linscp.png',
    'debian/linscp.svg',
]

# The installers, and the file that describes each of them.
INSTALLERS = {
    'make': 'source/linux/Makefile',
    'cmake': 'CMakeLists.txt',
    'debian': 'debian/rules',
}

# An operation phrase that ends in a preposition cannot be dropped into
# the template "Local {operation} of '{path}' failed." without saying
# the preposition twice.
PREPOSITIONS = ('of', 'to', 'for', 'on', 'in', 'at', 'from', 'with', 'into')


def rule_scope(rule_scope_name, path, root=ROOT):
    """Whether a rule applies to this file."""
    if rule_scope_name == 'any':
        return True
    relative = path.relative_to(root).as_posix()
    if rule_scope_name == 'code':
        return (relative.startswith('source/') or
                relative.startswith('automation/'))
    if rule_scope_name == 'packaging':
        if relative in CROSS_PLATFORM_WORKFLOWS:
            return False
        return (relative.startswith('debian/') or
                relative.startswith('.github/') or
                relative in INSTALLERS.values() or
                relative == 'CMakeLists.txt')
    if rule_scope_name == 'docs':
        return (relative.startswith('docs/') or
                relative == 'readme.md')
    return False


BLOCK_COMMENT = re.compile(r'/\*.*?\*/', re.S)
LINE_COMMENT = re.compile(r'//[^\n]*')
HASH_COMMENT = re.compile(r'(?m)^[ \t]*#[^\n]*$')


def strip_comments(path, text):
    """The text of a file without its comments.

    The preprocessor lines of a C file stay: a Windows-only branch is
    exactly what the check has to see, and a '#' there starts a
    directive rather than a comment.
    """
    suffix = path.suffix
    if suffix in ('.c', '.h', '.cpp'):
        directives = []
        rest = []
        for line in text.split('\n'):
            if line.lstrip().startswith('#'):
                directives.append(line)
            else:
                rest.append(line)
        rest = LINE_COMMENT.sub('', '\n'.join(rest))
        rest = BLOCK_COMMENT.sub('', rest)
        return '\n'.join(directives) + '\n' + rest
    if suffix in ('.py', '.psm1'):
        return HASH_COMMENT.sub('', text)
    return text


def find_windows_constructs(path, text, root=ROOT):
    """The Windows constructs a file still carries."""
    findings = []
    for name, scope, pattern, description in RULES:
        if not rule_scope(scope, path, root):
            continue
        if scope == 'code' and is_fixture(path, root):
            continue
        for match in re.finditer(pattern, text, re.MULTILINE):
            line = text.count('\n', 0, match.start()) + 1
            findings.append((path, line, name, description,
                             match.group(0).strip()))
    return findings


def check_windows_files(root=ROOT):
    """No file of another platform may sit in the tree."""
    findings = []
    for path in root.rglob('*'):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        # Android Gradle wrapper batch file is required for `gradlew assembleDebug`
        # on Windows hosts and lives under crates/linscp-tauri/gen/android;
        # it is not a leftover of the Windows port.
        if relative.as_posix() == 'crates/linscp-tauri/gen/android/gradlew.bat':
            continue
        if path.suffix.lower() in WINDOWS_FILE_SUFFIXES:
            findings.append((path, 0, 'windows-file',
                             'a file of another platform', path.name))
    return findings


def check_removed_artefacts(root=ROOT):
    """The files the Windows port left behind must stay gone."""
    findings = []
    for name, reason in REMOVED_ARTEFACTS:
        path = root / name
        if path.exists():
            findings.append((path, 0, 'windows-artefact',
                             'a leftover of the Windows port: ' + reason,
                             name))
    return findings


def check_installed_files(root=ROOT):
    """Every installer has to install the same files."""
    findings = []
    texts = {}
    for name, relative in INSTALLERS.items():
        path = root / relative
        if not path.is_file():
            findings.append((path, 0, 'install-layout',
                             'the %s installer is missing' % name,
                             relative))
            continue
        texts[name] = path.read_text(encoding='utf-8')
    for source in INSTALLED_FILES:
        for name, text in texts.items():
            # The Makefile prefixes the repository root; the other two
            # installers are written from the top of the tree.
            needle = source
            if name == 'make':
                needle = '$(TOP)/' + source
            if needle not in text:
                findings.append((root / INSTALLERS[name], 0, 'install-layout',
                                 'the %s installer does not install %s, '
                                 'which the other installers ship'
                                 % (name, source),
                                 source))
    return findings


def check_error_templates(root=ROOT):
    """An operation phrase must fit the template it is dropped into."""
    findings = []
    pattern = re.compile(r'Texts::LocalError\(\s*"([^"]+)"')
    for path in sorted((root / 'source/linux').glob('*.cpp')):
        text = path.read_text(encoding='utf-8')
        for match in pattern.finditer(text):
            phrase = match.group(1)
            last = phrase.rsplit(' ', 1)[-1].lower()
            if last in PREPOSITIONS:
                line = text.count('\n', 0, match.start()) + 1
                findings.append((path, line, 'error-template',
                                 'the operation phrase ends in "%s", which '
                                 'the template "Local {operation} of '
                                 "'{path}' failed.\" would say twice"
                                 % last,
                                 phrase))
    return findings


def check_brand_references(root=ROOT):
    """Only allowlisted external identifiers may retain the upstream name."""
    findings = []
    for path in sorted(root.rglob('*')):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRECTORIES for part in relative.parts):
            continue
        try:
            text = path.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        if not BRAND_REFERENCE.search(text):
            continue
        allowed = []
        for pattern in ALLOWED_BRAND_SPANS:
            for span in pattern.finditer(text):
                allowed.append((span.start(), span.end()))
        for match in BRAND_REFERENCE.finditer(text):
            if any(start <= match.start() and match.end() <= end
                   for start, end in allowed):
                continue
            line = text.count('\n', 0, match.start()) + 1
            findings.append((path, line, 'brand-reference',
                             'an upstream name outside the allowlist',
                             match.group(0)))
    return findings


def collect(root=ROOT):
    """Every problem this check finds, as a list of findings."""
    findings = []
    for path in scanned_files(root):
        try:
            text = path.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        findings.extend(find_windows_constructs(
            path, strip_comments(path, text), root))
    findings.extend(check_windows_files(root))
    findings.extend(check_removed_artefacts(root))
    findings.extend(check_installed_files(root))
    findings.extend(check_error_templates(root))
    findings.extend(check_brand_references(root))
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true',
                        help='list the files the Windows-construct '
                             'rules read')
    args = parser.parse_args()

    if args.list:
        for path in scanned_files():
            print(path.relative_to(ROOT))
        return 0

    findings = collect()
    if not findings:
        print('The Windows-to-Linux conversion is complete: '
              '%d conversion files read, '
              'no Windows construct or unlisted upstream name left.'
              % len(scanned_files()))
        return 0
    for path, line, name, description, text in findings:
        where = '%s:%d' % (path.relative_to(ROOT), line) if line else \
                str(path.relative_to(ROOT))
        print('%s: %s: %s (%s)' % (where, name, description, text))
    print('%d problem(s) found.' % len(findings))
    return 1


if __name__ == '__main__':
    sys.exit(main())
