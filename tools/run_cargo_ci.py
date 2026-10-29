#!/usr/bin/env python3
"""Run a Cargo command in CI and surface failures as GitHub Actions annotations."""
import os
import re
import subprocess
import sys

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def main():
    cmd = sys.argv[1:]
    if not cmd:
        print('Usage: run_cargo_ci.py <command> [args...]', file=sys.stderr)
        return 2
    env = dict(os.environ)
    env['CARGO_TERM_COLOR'] = 'never'
    # On Windows, console commands like `npm` are .cmd shims that
    # CreateProcess cannot start directly; run them through the shell.
    proc = subprocess.run(cmd, text=True, capture_output=True, env=env, shell=(os.name == 'nt'))
    if proc.stdout:
        sys.stdout.write(proc.stdout)
        sys.stdout.flush()
    if proc.stderr:
        sys.stdout.write(proc.stderr)
        sys.stderr.flush()
    if proc.returncode != 0:
        combined = ANSI_RE.sub('', ((proc.stdout or '') + '\n' + (proc.stderr or '')).strip())
        chunk_size = 3800
        tail = combined[-(chunk_size * 9):]
        chunks = [tail[i:i + chunk_size] for i in range(0, len(tail), chunk_size)]
        label = ' '.join(cmd[:4])
        for idx, chunk in enumerate(chunks, start=1):
            escaped = (
                chunk.replace('%', '%25')
                .replace('\r', '%0D')
                .replace('\n', '%0A')
            )
            print(f'::error title={label} ({idx}/{len(chunks)})::{escaped}')
    return proc.returncode


if __name__ == '__main__':
    sys.exit(main())
