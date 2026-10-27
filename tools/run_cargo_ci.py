#!/usr/bin/env python3
"""Run a Cargo command in CI and surface failures as GitHub Actions annotations."""
import subprocess
import sys


def main():
    cmd = sys.argv[1:]
    if not cmd:
        print('Usage: run_cargo_ci.py <command> [args...]', file=sys.stderr)
        return 2
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if proc.stdout:
        sys.stdout.write(proc.stdout)
        sys.stdout.flush()
    if proc.stderr:
        sys.stderr.write(proc.stderr)
        sys.stderr.flush()
    if proc.returncode != 0:
        combined = ((proc.stdout or '') + '\n' + (proc.stderr or '')).strip()
        tail = combined[-3500:]
        escaped = (
            tail.replace('%', '%25')
            .replace('\r', '%0D')
            .replace('\n', '%0A')
        )
        label = ' '.join(cmd[:4])
        print(f'::error title={label}::{escaped}')
    return proc.returncode


if __name__ == '__main__':
    sys.exit(main())
