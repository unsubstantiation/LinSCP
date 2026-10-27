#!/usr/bin/env python3
"""Run a Cargo command in CI and surface failures as GitHub Actions annotations."""
import os
import subprocess
import sys


def main():
    cmd = sys.argv[1:]
    if not cmd:
        print('Usage: run_cargo_ci.py <command> [args...]', file=sys.stderr)
        return 2
    env = dict(os.environ)
    env.setdefault('CARGO_TERM_COLOR', 'never')
    proc = subprocess.run(cmd, text=True, capture_output=True, env=env)
    if proc.stdout:
        sys.stdout.write(proc.stdout)
        sys.stdout.flush()
    if proc.stderr:
        sys.stderr.write(proc.stderr)
        sys.stderr.flush()
    if proc.returncode != 0:
        combined = ((proc.stdout or '') + '\n' + (proc.stderr or '')).strip()
        chunk_size = 3800
        chunks = [
            combined[i:i + chunk_size]
            for i in range(0, min(len(combined), chunk_size * 9), chunk_size)
        ]
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
