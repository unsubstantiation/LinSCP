"""Build workflows run on pull requests and manually, not on pushes.

This catches duplicate post-merge builds while retaining pre-merge feedback and
manual release builds. Every tools test must also be wired into a workflow.
The parser uses only the standard library, as in CI.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github/workflows'


def trigger_names(text):
    """The top-level keys of the workflow's `on:` mapping, in file order.

    Only the mapping form is understood. `on: push` is a scalar and is refused
    rather than guessed at, because the whole point of the check is that a key
    can sit beside `push`.
    """
    lines = text.splitlines()
    start = None
    for number, line in enumerate(lines):
        if line.rstrip() == 'on:':
            start = number
            break
        if line.startswith('on:') and line.rstrip() != 'on:':
            raise AssertionError(
                f'`on:` is a scalar ({line.strip()!r}); triggers have to be a '
                f'mapping so workflow_dispatch can sit beside push')
    if start is None:
        raise AssertionError('the workflow has no `on:` section')
    names = []
    for line in lines[start + 1:]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if not line.startswith(' '):
            break                                     # the next top-level key
        if line.startswith('  ') and not line.startswith('   '):
            names.append(line.strip().split(':')[0])
    return names


def workflow_files():
    return sorted(WORKFLOWS.glob('*.yml'))



def job_blocks(text):
    """Extract top-level job blocks; indented step gates are not job gates."""
    lines = text.splitlines()
    try:
        start = lines.index('jobs:')
    except ValueError:
        raise AssertionError('the workflow has no jobs section')
    blocks = {}
    current = None
    for line in lines[start + 1:]:
        if line and not line.startswith(' '):
            break
        if line.startswith('  ') and not line.startswith('   ') and line.rstrip().endswith(':'):
            current = line.strip()[:-1]
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line)
    return {name: '\n'.join(block) for name, block in blocks.items()}


def job_runs_on_pull_request(block):
    # Keep event conditions simple and explicit; unknown gates fail closed.
    gates = [line.strip()[3:].strip() for line in block.splitlines()
             if line.startswith('    if:')]
    if not gates:
        return True
    return any("github.event_name == 'pull_request'" in gate for gate in gates)


class WorkflowTriggerTests(unittest.TestCase):
    def test_the_repository_has_workflows(self):
        self.assertTrue(workflow_files(), f'no workflows in {WORKFLOWS}')

    def test_every_workflow_can_be_started_by_hand(self):
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                triggers = trigger_names(path.read_text(encoding='utf-8'))
                self.assertIn(
                    'workflow_dispatch', triggers,
                    f'{path.name} cannot be run manually; add workflow_dispatch '
                    f'to its `on:` mapping')

    def test_every_workflow_runs_on_pull_requests_not_pushes(self):
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                triggers = trigger_names(path.read_text(encoding='utf-8'))
                self.assertIn('pull_request', triggers, path.name)
                self.assertNotIn('pull_request_target', triggers, path.name)
                self.assertNotIn('push', triggers, path.name)
                self.assertEqual(set(triggers), {'pull_request', 'workflow_dispatch'}, path.name)

    def test_each_workflow_has_a_job_that_runs_on_pull_requests(self):
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                jobs = job_blocks(path.read_text(encoding='utf-8'))
                self.assertTrue(any(job_runs_on_pull_request(block) for block in jobs.values()),
                                f'{path.name} has no job enabled for pull requests')
                for name, block in jobs.items():
                    if any(line.startswith('    environment:') for line in block.splitlines()):
                        self.assertFalse(job_runs_on_pull_request(block),
                                         f'{path.name} job {name} exposes a protected environment to PRs')

    def test_android_signed_release_is_manual_only(self):
        jobs = job_blocks((WORKFLOWS / 'android-build.yml').read_text(encoding='utf-8'))
        self.assertIn("if: github.event_name == 'workflow_dispatch'", jobs['build'])
        self.assertIn('environment: android-release', jobs['build'])
        self.assertTrue(job_runs_on_pull_request(jobs['check']))

    def test_every_tools_test_is_named_by_some_workflow(self):
        # A repo-state suite that no job runs is a green lie: it passes by
        # hand and rots in CI. Every `tools/tests/test_*.py` file has to be
        # named by at least one workflow (a `-p test_name.py` step, usually in
        # the Debian job's repo-state suite run).
        bodies = [path.read_text(encoding='utf-8') for path in workflow_files()]
        test_files = sorted((ROOT / 'tools' / 'tests').glob('test_*.py'))
        self.assertTrue(test_files, 'no tools tests found')
        for test_file in test_files:
            with self.subTest(suite=test_file.name):
                self.assertTrue(
                    any(test_file.stem in body for body in bodies),
                    f'{test_file.name} runs in no CI job; wire it into a '
                    f'workflow step')

    def test_pull_request_triggers_are_detected_even_with_filters(self):
        self.assertEqual(
            trigger_names('on:\n  push:\n    branches: [master]\n'
                          "  pull_request:\n    paths-ignore:\n      - 'docs/**'\n"
                          '  pull_request_target:\n  workflow_dispatch:\n\njobs:\n'),
            ['push', 'pull_request', 'pull_request_target', 'workflow_dispatch'])

    def test_a_scalar_trigger_is_reported(self):
        with self.assertRaises(AssertionError):
            trigger_names('on: push\n\njobs: {}\n')

    def test_a_missing_trigger_section_is_reported(self):
        with self.assertRaises(AssertionError):
            trigger_names('name: No triggers\n\njobs: {}\n')

    def test_the_parser_reads_the_mapping_form(self):
        self.assertEqual(
            trigger_names('on:\n  push:\n    branches: [master]\n'
                          '  # a comment\n  workflow_dispatch:\n\njobs:\n'),
            ['push', 'workflow_dispatch'])


if __name__ == '__main__':
    unittest.main()
