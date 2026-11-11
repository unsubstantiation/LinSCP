"""Regressions for tools/check_ci_test_execution.py.

The check exists because a crate's tests can be compiled on every push and
executed on none of them: five crates were in that state, and the terminal
emulator's 28 tests had never run anywhere. These cases prove the check
notices each way that can happen, so the guard cannot quietly stop noticing.
"""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import check_ci_test_execution as check


class CiTestExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='utf-8')
        return path

    def workspace(self, *crates):
        members = '\n'.join(f'    "crates/{crate}",' for crate in crates)
        self.write('Cargo.toml', f'[workspace]\nmembers = [\n{members}\n]\n')

    def crate(self, name, tests=1):
        body = '\n'.join(
            f'    #[test]\n    fn case_{index}() {{}}\n' for index in range(tests))
        self.write(f'crates/{name}/src/lib.rs', f'pub fn thing() {{}}\n'
                   f'#[cfg(test)]\nmod tests {{\n{body}\n}}\n')

    def workflow(self, run):
        self.write('.github/workflows/debian-build.yml',
                   f'jobs:\n  build:\n    steps:\n      - run: {run}\n')

    def missing(self):
        """Crates compiled but not executed, reading this temp tree."""
        return check.collect(self.root)

    def test_the_real_repository_executes_every_crate_with_tests(self):
        # The repository itself must satisfy the rule, or the guard has already
        # failed to keep the property it was written for.
        self.assertEqual(check.collect(), [])

    def test_a_crate_with_no_executing_step_is_reported(self):
        self.workspace('alpha', 'beta')
        self.crate('alpha')
        self.crate('beta')
        self.workflow('cargo test -p alpha')
        self.assertEqual(self.missing(), [('beta', 1)])

    def test_compiling_without_running_does_not_count(self):
        # The step that compiles every test target is not evidence that any of
        # them ran; counting it would hide exactly the bug this checks for.
        self.workspace('alpha')
        self.crate('alpha', tests=3)
        self.workflow('cargo test --no-run -p alpha')
        self.assertEqual(self.missing(), [('alpha', 3)])

    def test_the_windows_workspace_run_does_not_count_as_linux_coverage(self):
        # The Windows job runs `cargo test --workspace`, which really does
        # execute every crate - but on a different platform. A crate covered
        # only there is exactly the state this check exists to catch, so a
        # --workspace in another workflow must not satisfy it.
        self.workspace('alpha')
        self.crate('alpha')
        self.write('.github/workflows/windows-build.yml',
                   'jobs:\n  build:\n    steps:\n      - run: cargo test --workspace\n')
        self.assertEqual(self.missing(), [('alpha', 1)])

    def test_a_comment_naming_the_syntax_is_not_a_step(self):
        # The Debian job explains `cargo test -p <crate> <filter>` in a
        # comment. Reading that line as a bare `cargo test` would mark every
        # crate covered and the check would pass while proving nothing.
        self.workspace('alpha')
        self.crate('alpha')
        self.write('.github/workflows/debian-build.yml',
                   'jobs:\n  build:\n    steps:\n'
                   '      # `cargo test -p <crate> <filter>` runs one crate.\n'
                   '      - run: cargo test -p other\n')
        self.assertEqual(self.missing(), [('alpha', 1)])

    def test_a_step_that_runs_every_crate_covers_all_of_them(self):
        self.workspace('alpha', 'beta')
        self.crate('alpha')
        self.crate('beta')
        self.workflow('cargo test')
        self.assertEqual(self.missing(), [])

    def test_one_step_may_name_several_crates(self):
        self.workspace('alpha', 'beta')
        self.crate('alpha')
        self.crate('beta')
        self.workflow('cargo test -p alpha -p beta -- --nocapture')
        self.assertEqual(self.missing(), [])

    def test_a_crate_without_tests_is_not_required(self):
        # A crate that ships no tests has nothing to execute; demanding a step
        # for it would push a filter into the workflow that runs nothing.
        self.workspace('alpha')
        self.write('crates/alpha/src/lib.rs', 'pub fn thing() {}\n')
        self.workflow('cargo test -p other')
        self.assertEqual(self.missing(), [])

    def test_the_reported_count_is_the_number_of_tests(self):
        self.workspace('alpha')
        self.crate('alpha', tests=4)
        self.workflow('cargo test -p other')
        self.assertEqual(self.missing(), [('alpha', 4)])

    def test_an_async_test_counts(self):
        self.workspace('alpha')
        self.write('crates/alpha/src/lib.rs',
                   'pub fn thing() {}\n#[cfg(test)]\nmod tests {\n'
                   '    #[tokio::test]\n    async fn case() {}\n}\n')
        self.workflow('cargo test -p other')
        self.assertEqual(self.missing(), [('alpha', 1)])


if __name__ == '__main__':
    unittest.main()
