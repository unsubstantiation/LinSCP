#!/usr/bin/env python3
"""Check that every crate with tests has a Debian step that names it.

Every crate in this workspace already has its tests executed on Linux, and by
one line: `debian/rules` runs `cargo test --workspace --all-targets` while
`dpkg-buildpackage` builds the package, and that package build is a step in the
Debian workflow. So this check is not what makes the suites run, and it would
be wrong to describe it as closing a coverage hole - it does not.

What it protects is attribution. That one line is a single opaque step: when a
crate's test fails inside it, the job goes red with a Cargo transcript and no
step of its own to blame, and a crate that a reader believes is covered can sit
there without any step that would visibly break if it stopped executing. A
named `cargo test -p <crate>` step per crate makes the failure name the crate
and makes its absence visible in review.

So the rule this enforces is narrower than "does it run somewhere": a crate
whose source contains tests must have a Debian workflow step that runs them by
name. That is a legibility guarantee, and it is worth stating plainly which
guarantee this is.

Two mistakes shaped the checks below, both of which once made this pass while
proving nothing. A step that only compiles (`--no-run`) is not execution, and
crossing a crate list with a regex that excludes digits silently truncates it.
The Windows job's `cargo test --workspace` is not evidence either: coverage on
another platform says nothing about this one, and reading it as coverage is how
a crate goes untested on the platform that ships first.

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


RULES = 'debian/rules'


def package_build_runs_workspace_tests(root=ROOT):
    """Whether `debian/rules` still runs the whole workspace suite.

    This is the premise the rest of the check rests on. `debian/rules` runs
    `cargo test --workspace --all-targets` while `dpkg-buildpackage` builds the
    package, and the Debian workflow has a step that builds the package - so
    that line, not the named steps, is what makes every crate's tests execute
    on Linux. If somebody removes or narrows it, coverage really would be lost,
    and the named steps alone do not replace it.
    """
    rules = root / RULES
    if not rules.is_file():
        return False
    for line in rules.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        if not re.search(r'cargo\s+test\b', stripped):
            continue
        if '--workspace' in stripped or '-p ' not in stripped:
            return True
    return False


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
    if not package_build_runs_workspace_tests():
        print(f'{RULES} no longer runs `cargo test --workspace --all-targets`, so the '
              f'package build is not executing the workspace suite any more. The named '
              f'steps below cover only the crates they list; restore the workspace run '
              f'or add a step for every crate.',
              file=sys.stderr)
        return 1
    missing = collect()
    for crate, count in missing:
        print(f'crates/{crate} has {count} tests and no Debian step names it, so a '
              f'failure in it would report no crate: add a step that runs '
              f'`cargo test -p {crate}`', file=sys.stderr)
    if missing:
        return 1
    total = sum(crates_with_tests().values())
    print(f'All {len(crates_with_tests())} crates with tests have a Debian step of their own '
          f'({total} test attributes). The workspace-wide `--all-targets` run in '
          f'debian/rules still executes them all; these steps are what names them.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
