"""Every workflow builds master, builds pull requests, and can be started by hand.

A build that only runs on a push to `master` cannot be tried before it lands
there: the signed Android APK, for instance, is the first place the release
keystore is exercised, and waiting for a merge to find out that it does not
work is the wrong order. `workflow_dispatch` gives each workflow a "Run
workflow" button and a `gh workflow run` target for a branch, and the
`pull_request` trigger makes that trial automatic: without it a pull request
merges with every build unrun, and master is where the red is found.

The triggers are easy to lose - they live in the same `on:` mapping as the
push filter, and a workflow without one is not an error anywhere, it simply
never starts that way. These tests read the workflows the way GitHub does for
those properties: the `on:` mapping has to keep `push` *and* carry
`workflow_dispatch` and `pull_request`, so a build cannot quietly become
push-only again.

The same quiet-rot rule applies to the repo-state suites themselves: a tools
test no workflow names never runs in CI, however green it is by hand. The last
test below fails the suite that forgets to wire a new test file into a job.

The workflows are parsed as text rather than with a YAML library: the CI jobs
that run these tests install nothing beyond the standard library.
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

    def test_every_workflow_still_builds_master(self):
        # The manual trigger is an addition, not a replacement: a push to master
        # has to keep building, or nothing catches a broken merge.
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                text = path.read_text(encoding='utf-8')
                triggers = trigger_names(text)
                self.assertIn('push', triggers, path.name)
                self.assertIn('branches: [master]', text, path.name)

    def test_every_workflow_builds_pull_requests(self):
        # Same shape as the push-only failure, one level up: a workflow that
        # never runs on a pull request lets the PR merge unbuilt.
        for path in workflow_files():
            with self.subTest(workflow=path.name):
                triggers = trigger_names(path.read_text(encoding='utf-8'))
                self.assertIn(
                    'pull_request', triggers,
                    f'{path.name} never builds a pull request; add pull_request '
                    f'to its `on:` mapping')

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
