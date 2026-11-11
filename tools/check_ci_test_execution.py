#!/usr/bin/env python3
"""Check that every crate's tests run on Linux, not only on Windows.

The Windows job runs `cargo test --workspace`, so every crate's tests do run
somewhere. The Debian job is different: it compiles seven crates' test targets
with `--no-run` and executes only the handful it names. A compact, portable
crate can therefore go years here with its tests compiled and never executed
on the platform the product actually ships on first.

Two crates were in exactly that position. `linscp-terminal` - 28 tests over
the escape-sequence parser, wide and combining glyphs, scrolling, selections
and palette queries, the code the Android terminal draws with - was not even
compiled by the Debian job. `linscp-tauri` - the SAF tree validation and the
grant-as-root listing - was not either. Both were covered only by a Windows
runner, so a Linux-only regression in either would have shipped green.

This check reads the workflow files and fails when a workspace crate whose
source contains tests has no Debian step that runs them.

Usage:
    python3 tools/check_ci_test_execution.py
"""
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / '.github' / 'workflows'
WORKSPACE = ROOT / 'Cargo.toml'
# The job that must run every crate: the Debian build is the Linux gate, and
# Linux is the platform LinSCP ships on first. The Windows job runs the whole
# workspace, which is why a crate can look covered while Linux never runs it.
REQUIRED_WORKFLOW = 'debian-build.yml'

# A test attribute, not a mention of one. The suite is what this counts.
RUST_TEST = re.compile(r'#\[(?:tokio::)?test\b')
# `cargo test -p <crates> [filter] ...` - the whole command, so a `--no-run`
# that follows the crate list is visible.
CARGO_TEST = re.compile(r'cargo\s+test\b([^\n]*)')
CRATE_SELECTION = re.compile(r'-p\s+([A-Za-z0-9_-]+)')


def workspace_crates(root=ROOT):
    """The crates in the workspace, by package name, from the member paths."""
    manifest = (root / 'Cargo.toml').read_text(encoding='utf-8')
    members = re.findall(r'"crates/([A-Za-z0-9_-]+)"', manifest)
    return sorted(members)


def crates_with_tests(root=ROOT):
    """Workspace crates that contain at least one Rust test."""
    found = {}
    for crate in workspace_crates(root):
        directory = root / 'crates' / crate
        if not directory.is_dir():
            continue
        count = 0
        for source in directory.rglob('*.rs'):
            try:
                count += len(RUST_TEST.findall(source.read_text(encoding='utf-8')))
            except (OSError, UnicodeDecodeError):
                continue
        if count:
            found[crate] = count
    return found


YAML_COMMENT = re.compile(r'(?m)#[^\n]*$')


def executed_crates(root=ROOT):
    """Crates selected by a `cargo test` that is not `--no-run`.

    A bare `cargo test` with no `-p` runs the whole workspace, so it counts
    for every crate in it.
    """
    executed = set()
    workflows = root / '.github' / 'workflows'
    selected_workflows = [workflows / REQUIRED_WORKFLOW]
    for workflow in [w for w in selected_workflows if w.is_file()]:
        text = workflow.read_text(encoding='utf-8')
        # A comment that explains the syntax - "`cargo test -p <crate> ...`" -
        # is prose, not a step. Without this, such a line reads as a bare
        # `cargo test` that runs the whole workspace and the check passes
        # while proving nothing.
        text = YAML_COMMENT.sub('', text)
        for match in CARGO_TEST.finditer(text):
            arguments = match.group(1)
            if '--no-run' in arguments:
                continue
            selected = [name for name in CRATE_SELECTION.findall(arguments)
                        if not name.startswith('<')]
            if selected:
                executed.update(selected)
            else:
                executed.update(workspace_crates(root))
    return executed


def collect(root=ROOT):
    """Every crate whose tests are compiled but never executed."""
    executed = executed_crates(root)
    return [
        (crate, count)
        for crate, count in sorted(crates_with_tests(root).items())
        if crate not in executed
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    missing = collect()
    for crate, count in missing:
        print(f'crates/{crate} has {count} tests that no workflow executes: '
              f'add a step that runs `cargo test -p {crate}`', file=sys.stderr)
    if missing:
        return 1
    total = sum(crates_with_tests().values())
    print(f'Every one of the {len(crates_with_tests())} crates with tests is executed by CI '
          f'({total} test attributes).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
