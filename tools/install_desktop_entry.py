#!/usr/bin/env python3
"""Install a desktop entry pointing at the actual runtime prefix, not DESTDIR."""
import argparse
from pathlib import Path


def desktop_entry(template: str, prefix: str) -> str:
    if not prefix.startswith('/') or any(ord(c) < 32 or ord(c) == 127 for c in prefix):
        raise ValueError('installation prefix must be absolute and contain no control characters')
    executable = prefix.rstrip('/') + '/bin/linscp-gui'
    # Exec values have two escaping layers: desktop-entry string escaping and
    # the quoted command-line grammar. Percent signs must not become field codes.
    quoted = ''.join('\\' + c if c in '\\"`$' else '%%' if c == '%' else c for c in executable)
    exec_value = ('"' + quoted + '"').replace('\\', '\\\\')
    # GIO checks the first Exec word for existence before expanding %%; a
    # literal percent in that word therefore makes a valid entry disappear.
    # env receives the absolute executable as an argument (never a PATH lookup).
    if '%' in executable:
        exec_value = '/usr/bin/env ' + exec_value
    try_exec = executable.replace('\\', '\\\\')
    if template.count('\nExec=linscp-gui %u\n') != 1 or template.count('\nTryExec=linscp-gui\n') != 1:
        raise ValueError('desktop entry template has unexpected launcher fields')
    result = template.replace('\nExec=linscp-gui %u\n', '\nExec=' + exec_value + ' %u\n')
    return result.replace('\nTryExec=linscp-gui\n', '\nTryExec=' + try_exec + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', required=True)
    parser.add_argument('--destdir', default='')
    parser.add_argument('--template', required=True)
    args = parser.parse_args()
    content = desktop_entry(Path(args.template).read_text(encoding='utf-8'), args.prefix)
    destination = Path(args.destdir + args.prefix) / 'share/applications/linscp.desktop'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content, encoding='utf-8')
    destination.chmod(0o644)


if __name__ == '__main__':
    main()
