"""Validate the inventory checker, including intentionally failing gates."""
import json
import copy
import contextlib
import io
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import check_upstream_parity as checker
from check_upstream_parity import (check_capabilities, check_verification,
                                   matrix_report, upstream_commands)


class InventoryTests(unittest.TestCase):
    def test_literal_and_constant_registrations(self):
        script = 'FCommands->Register(L"get", x); FCommands->Register(EXIT_COMMAND, x);'
        header = '#define EXIT_COMMAND L"exit"'
        self.assertEqual(upstream_commands(script, header), {"get", "exit"})

    def test_fail_if_source_not_recognized(self):
        with self.assertRaises(ValueError):
            upstream_commands("not a script source file", "")
        with self.assertRaises(KeyError):
            upstream_commands("FCommands->Register(NEW_COMMAND, x);", "")

    def test_full_gate_fails_for_current_gaps(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/check_upstream_parity.py"),
                                 "--require-full"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Full parity gate failed", result.stderr)

    def test_command_drift_detection(self):
        names = json.loads((ROOT / "docs/upstream-parity.json").read_text())["commands"]
        script = "\n".join(f'FCommands->Register(L"{name}", x);' for name in names)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Script.cpp"
            header = pathlib.Path(tmp) / "Script.h"
            header.write_text("")
            args = [sys.executable, str(ROOT / "tools/check_upstream_parity.py"),
                    "--upstream-script", str(path), "--upstream-header", str(header)]
            path.write_text(script)
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            path.write_text(script + '\nFCommands->Register(L"newcommand", x);')
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Untracked upstream command: newcommand", result.stderr)
            path.write_text(script.replace('FCommands->Register(L"get", x);', ''))
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Command no longer registered upstream: get", result.stderr)

    def test_requires_both_files(self):
        result = subprocess.run([sys.executable, str(ROOT / "tools/check_upstream_parity.py"),
                                 "--upstream-script", "unused.cpp"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("Supply both", result.stderr)


    def ledger_errors(self, entries, platforms=None, policy="cite evidence"):
        """Run just the verification rules over a fabricated inventory.

        The fabricated ledger has two platforms on purpose: LinSCP ships on
        Linux alone, but the rule under test is the general one - an entry
        called verified has to cite every platform the ledger names - and a
        single-platform fixture could not tell that rule apart from 'cite
        anything'.
        """
        if platforms is None:
            platforms = {
                "linux": {"how": "make check", "date": "2026-10-14",
                          "suites": {"unit": "the C++ checks",
                                     "manual": "by hand, with the commands"}},
                "bsd": {"how": "ctest", "date": "2026-10-14",
                        "suites": {"unit": "the C++ checks"}},
            }
        errors = []
        check_verification({"verification": {"policy": policy,
                                             "platforms": platforms}},
                           entries, errors)
        return errors

    def test_verified_needs_evidence_from_every_platform(self):
        entry = {"name": "get", "status": "verified", "notes": "works"}
        self.assertTrue(any("cites no evidence" in e for e in
                            self.ledger_errors([entry])))
        entry["verified_on"] = {"linux": ["unit"]}
        errors = self.ledger_errors([entry])
        self.assertTrue(any("without evidence from: bsd" in e for e in errors))
        entry["verified_on"]["bsd"] = ["unit"]
        self.assertEqual(self.ledger_errors([entry]), [])

    def test_cited_suites_have_to_exist(self):
        """'manual' evidence exists on Linux only, so citing it for the second
        platform of the fabricated ledger is a claim nobody can reproduce."""
        entry = {"name": "put", "status": "partial", "notes": "works",
                 "verified_on": {"linux": ["unit"], "bsd": ["manual"]}}
        errors = self.ledger_errors([entry])
        self.assertTrue(any("'bsd' has no suite 'manual'" in e for e in errors))

        entry["verified_on"] = {"linux": ["unit"], "bsd": []}
        self.assertTrue(any("names no suite" in e for e in self.ledger_errors([entry])))
        entry["verified_on"] = {"linux": ["unit"], "beos": ["unit"]}
        self.assertTrue(any("unknown platform" in e for e in self.ledger_errors([entry])))

    def test_an_evidence_ledger_has_to_be_readable(self):
        """A platform that does not say how it produces evidence cannot be
        cited, so the record itself is checked."""
        errors = self.ledger_errors([], platforms={
            "linux": {"how": "", "date": "14/10/2026", "suites": {}}})
        self.assertTrue(any("'linux' has no 'how'" in e for e in errors), errors)
        self.assertTrue(any("is not YYYY-MM-DD" in e for e in errors), errors)
        self.assertTrue(any("lists no test suites" in e for e in errors), errors)

        errors = self.ledger_errors([], platforms={
            "linux": {"how": "make check", "date": "2026-10-14",
                      "suites": {"unit": ""}}})
        self.assertTrue(any("is not described" in e for e in errors), errors)

        self.assertTrue(any("'verification.policy' is empty" in e for e in
                            self.ledger_errors([], policy="")),
                        "a ledger with no policy is not a rule")
        self.assertTrue(any("no 'verification' block" in e for e in
                            self.ledger_errors_no_block()),
                        "a missing ledger has to be an error, not a pass")

    def ledger_errors_no_block(self):
        errors = []
        check_verification({}, [{"name": "get", "status": "verified",
                                 "notes": "works"}], errors)
        return errors

    def test_verified_cannot_cite_a_suite_that_does_not_run_there(self):
        """A suite flagged not runnable executes no case on that platform, so a
        verified entry may not cite it there. A partial entry may: that is how
        the ledger records which cases would cover it once the suite runs."""
        platforms = {
            "linux": {"how": "make check", "date": "2026-10-14",
                      "suites": {"unit": "the C++ checks"},
                      "not_runnable": {"unit": "no build target"}},
            "bsd": {"how": "ctest", "date": "2026-10-14",
                    "suites": {"unit": "the C++ checks"}},
        }
        verified = {"name": "get", "status": "verified", "notes": "works",
                    "verified_on": {"linux": ["unit"], "bsd": ["unit"]}}
        errors = self.ledger_errors([verified], platforms=platforms)
        self.assertTrue(any("'linux' suite 'unit'" in error and
                            "does not run" in error for error in errors),
                        errors)
        partial = dict(verified, status="partial")
        self.assertEqual(self.ledger_errors([partial], platforms=platforms), [])

    def test_not_runnable_flags_have_to_point_at_listed_suites(self):
        errors = self.ledger_errors(
            [], platforms={"linux": {"how": "make check", "date": "2026-10-14",
                                     "suites": {"unit": "the C++ checks"},
                                     "not_runnable": {"ghost": "no such suite",
                                                      "unit": ""}}})
        self.assertTrue(any("flags an unlisted suite" in error for error in errors),
                        errors)
        self.assertTrue(any("without a reason" in error for error in errors),
                        errors)

    def test_every_platform_citation_names_a_checked_suite(self):
        """Windows and Android are validated against the named cases the same
        way Linux is: a platform may cite a subset, but never a suite the row
        never names, and a named suite has to be cited somewhere."""
        base = {"id": "sftp.example", "area": "SFTP", "status": "verified",
                "notes": "A narrowly checked behavior",
                "source": ["crates/linscp-proto/src/sftp.rs"],
                "checks": {"live-sftp": ["test_open_with_a_wrong_password_is_refused"]},
                "verified_on": {"linux": ["live-sftp"]}}
        errors = []
        check_capabilities({"features": [{"name": "SFTP"}],
                            "capabilities": [base]}, errors)
        self.assertEqual(errors, [])
        row = dict(base, verified_on={"linux": ["live-sftp"],
                                      "windows": ["live-sftp", "unit"]})
        errors = []
        check_capabilities({"features": [{"name": "SFTP"}],
                            "capabilities": [row]}, errors)
        self.assertTrue(any("verified_on.windows names suites without named "
                            "cases" in error for error in errors), errors)
        row = dict(
            base,
            checks={"live-sftp": ["test_open_with_a_wrong_password_is_refused"],
                    "unit": ["TestScpHeaderNamesCannotTraverse"]},
            verified_on={"linux": ["live-sftp", "unit"],
                         "windows": ["live-sftp"]})
        errors = []
        check_capabilities({"features": [{"name": "SFTP"}],
                            "capabilities": [row]}, errors)
        self.assertEqual(errors, [])
        row = dict(row, verified_on={"linux": ["live-sftp"],
                                     "windows": ["live-sftp"]})
        errors = []
        check_capabilities({"features": [{"name": "SFTP"}],
                            "capabilities": [row]}, errors)
        self.assertTrue(any("cited by no platform" in error for error in errors),
                        errors)

    def test_capability_matrix_cannot_lose_areas_or_invent_evidence(self):
        valid = {"id": "sftp.example", "area": "SFTP", "status": "verified",
                 "notes": "A narrowly checked behavior", "source": ["crates/linscp-proto/src/sftp.rs"],
                 "checks": {"live-sftp": ["test_open_with_a_wrong_password_is_refused"]},
                 "verified_on": {"linux": ["live-sftp"]}}
        inventory = {"features": [{"name": "SFTP"}],
                     "capabilities": [valid]}
        errors = []
        self.assertEqual(check_capabilities(inventory, errors), [valid])
        self.assertEqual(errors, [])
        for changes, expected in (
                ({"id": "oops"}, "Invalid capability id"),
                ({"area": "made-up"}, "unknown feature area"),
                ({"source": ["../../etc/passwd"]}, "implementation source does not exist"),
                ({"checks": {"live-sftp": ["test_a_made_up_test"]}},
                 "has no test case"),
                ({"checks": {"script": ["test_batch_modes"]}},
                 "names suites without named cases"),
                ({"checks": {}}, "verified without a test case"),
                ({"status": "partial", "checks": {}, "verified_on": {}},
                 "needs a concrete gap"),
                ({"status": "missing", "gap": "implement this"},
                 "missing yet names an implementation")):
            with self.subTest(changes=changes):
                row = dict(valid, **changes)
                errors = []
                check_capabilities({"features": [{"name": "SFTP"}],
                                    "capabilities": [row]}, errors)
                self.assertIn(expected, " | ".join(errors))
        errors = []
        check_capabilities({"features": [{"name": "SFTP"}, {"name": "SCP"}],
                            "capabilities": [valid, dict(valid)]}, errors)
        self.assertTrue(any("Duplicate capability id" in error for error in errors))
        self.assertTrue(any("Feature area has no capability rows: SCP" in error
                            for error in errors))
        errors = []
        check_capabilities({"features": [{"name": "SFTP"}]}, errors)
        self.assertIn("Inventory has no capability matrix", errors)

    def test_pinned_gaps_cannot_be_deleted_to_fake_full_parity(self):
        inventory = json.loads((ROOT / "docs/upstream-parity.json").read_text())
        for capability in ("dav.locks", "gui.local-to-local", "sessions.workspaces"):
            with self.subTest(capability=capability):
                candidate = copy.deepcopy(inventory)
                candidate["capabilities"] = [row for row in candidate["capabilities"]
                                             if row["id"] != capability]
                errors = []
                check_capabilities(candidate, errors)
                self.assertIn("Pinned upstream gap was dropped from the inventory: " + capability,
                              errors)

    def test_baseline_review_is_recorded_with_evidence(self):
        inventory = json.loads((ROOT / "docs/upstream-parity.json").read_text())
        upstream = inventory["upstream"]
        self.assertEqual(upstream["commit"],
                         upstream["latest_command_review"]["commit"])
        review = upstream["behavioral_drift_review"]
        self.assertGreater(review["compared_commits"], 0)
        self.assertTrue(review["relevant_changes"])
        evidence = set()
        for row in inventory["capabilities"]:
            for suite, cases in row.get("checks", {}).items():
                evidence.update("%s: %s" % (suite, case) for case in cases)
        for change in review["relevant_changes"]:
            self.assertRegex(change["commit"], r"^[0-9a-f]{40}$")
            self.assertTrue(change["evidence"])
            self.assertTrue(change["linscp"])
            for item in change["evidence"]:
                self.assertIn(item, evidence)

    def test_pinned_gap_guard_survives_a_baseline_update(self):
        inventory = json.loads((ROOT / "docs/upstream-parity.json").read_text())
        inventory["upstream"]["commit"] = "f" * 40
        candidate = copy.deepcopy(inventory)
        candidate["capabilities"] = [row for row in candidate["capabilities"]
                                     if row["id"] != "dav.locks"]
        errors = []
        check_capabilities(candidate, errors)
        self.assertIn("Pinned upstream gap was dropped from the inventory: dav.locks",
                      errors)

    def test_every_dispatcher_name_is_in_exactly_one_group(self):
        inventory = json.loads((ROOT / "docs/upstream-parity.json").read_text())
        dispatched = checker.command_table((ROOT / "crates/linscp-engine/src/script.rs").read_text())
        errors = []
        checker.check_command_coverage(inventory, dispatched, errors)
        self.assertEqual(errors, [])
        for change, expected in [
                (lambda j: j['linscp_additions'][0]['commands'].append('open'), 'multiple ledger groups'),
                (lambda j: j['linscp_additions'][0]['commands'].append('imaginary'), 'no dispatcher'),
                (lambda j: j['linscp_additions'].pop(), 'absent from inventory'),
                (lambda j: j['linscp_additions'][0].pop('commands'), 'explicit command names')]:
            candidate = copy.deepcopy(inventory)
            change(candidate)
            errors = []
            checker.check_command_coverage(candidate, dispatched, errors)
            self.assertIn(expected, ' | '.join(errors))

    def test_area_status_cannot_hide_known_gaps(self):
        inventory = json.loads((ROOT / "docs/upstream-parity.json").read_text())
        errors = []
        checker.check_feature_rollups(inventory, errors)
        self.assertEqual(errors, [])
        next(f for f in inventory['features']
             if f['name'] == 'Security/authentication')['status'] = 'verified'
        checker.check_feature_rollups(inventory, errors)
        self.assertIn('verified area has tracked gaps', ' | '.join(errors))

    def test_every_gap_has_acceptance_criteria_and_appears_in_plan(self):
        inventory = json.loads((ROOT / "docs/upstream-parity.json").read_text())
        plan = checker.plan_report(inventory)
        self.assertEqual((ROOT / 'docs/remaining-parity-plan.md').read_text(), plan)
        for row in inventory['capabilities']:
            if row['status'] == 'verified':
                self.assertNotIn('## ' + row['id'] + '\n', plan)
            else:
                self.assertIn('## ' + row['id'] + '\n', plan)
                self.assertTrue(row['acceptance'])
                for value in (None, [], [' ']):
                    candidate = copy.deepcopy(inventory)
                    next(r for r in candidate['capabilities'] if r['id'] == row['id'])['acceptance'] = value
                    errors = []
                    check_capabilities(candidate, errors)
                    self.assertIn('needs acceptance criteria', ' | '.join(errors))

    def test_complete_report_contains_all_ledger_sections_and_source_links(self):
        inventory = json.loads((ROOT / 'docs/upstream-parity.json').read_text())
        report = matrix_report(inventory)
        for name in inventory['commands']:
            self.assertIn('| `' + name + '` |', report)
        for addition in inventory['linscp_additions']:
            self.assertIn(addition['name'], report)
        for row in inventory['capabilities']:
            self.assertIn('| `' + row['id'] + '` |', report)
            for path in row.get('source', []):
                self.assertIn('(../' + path + ')', report)
        self.assertIn('UnitTest.cpp#L', report)
        self.assertIn('LiveSftpTest.py#L', report)
        self.assertIn('Evidence suite registry', report)

    def test_gap_plan_drift_fails_the_default_check(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            plan = pathlib.Path(tmp) / 'plan.md'
            plan.write_text('stale plan')
            error_output = io.StringIO()
            with mock.patch.object(checker, 'PLAN_REPORT', plan), \
                 mock.patch.object(sys, 'argv', ['check_upstream_parity.py']), \
                 contextlib.redirect_stdout(io.StringIO()), \
                 contextlib.redirect_stderr(error_output):
                self.assertEqual(checker.main(), 1)
            self.assertIn('out of date', error_output.getvalue())

    def test_verified_rows_cite_only_suites_that_run_where_they_are_cited(self):
        """The B-suite triage guarantee: a verified row's citations are suites
        that execute on the citing platform, naming only checked cases."""
        inventory = json.loads((ROOT / "docs/upstream-parity.json").read_text())
        platforms = inventory["verification"]["platforms"]
        entries = (list(inventory["commands"].values()) + inventory["features"] +
                   inventory.get("linscp_additions", []) +
                   inventory["capabilities"])
        for entry in entries:
            if entry["status"] != "verified":
                continue
            label = entry.get("name") or entry.get("id") or "?"
            for platform, cited in entry["verified_on"].items():
                flagged = platforms[platform].get("not_runnable", {})
                for suite in cited:
                    self.assertNotIn(
                        suite, flagged,
                        label + ": verified on " + platform + " via " + suite +
                        ", which does not run there")
            if "checks" in entry:
                checked = set(entry["checks"])
                for platform, cited in entry["verified_on"].items():
                    self.assertLessEqual(
                        set(cited), checked,
                        label + ": " + platform +
                        " cites suites with no named cases")

    def test_a_cited_case_must_be_a_test_and_not_merely_a_function(self):
        """A helper whose name reads like a case is not a case.

        gui.remote-delete cited `exercise_remote_delete` for a while. It takes
        arguments and returns a future - it is a helper called from
        live_webdav_gui_upload_download - but it matches a bare `fn` lookup, so
        the gate accepted it. The lookup now requires a test attribute.
        """
        import re
        source = ("#[cfg(target_os = \"linux\")]\n"
                  "#[tokio::test]\n"
                  "async fn real_case() { }\n"
                  "\n"
                  "async fn helper_taking_arguments(svc: &u8, id: u64) { }\n")

        def cited(name):
            return re.search(
                r"#\[(?:tokio::)?test[^\]]*\]"
                r"(?:\s*(?://[^\n]*|#\[[^\]]*\]))*"
                r"\s*(?:async\s+)?fn\s+" + re.escape(name) + r"\s*\(", source)

        self.assertIsNotNone(cited("real_case"), "a #[tokio::test] fn is a case")
        self.assertIsNone(cited("helper_taking_arguments"),
                          "a plain fn is not a case, however much it reads like one")

    def test_the_suite_registry_marks_what_does_not_run(self):
        inventory = json.loads((ROOT / "docs/upstream-parity.json").read_text())
        report = matrix_report(inventory)
        platforms = inventory["verification"]["platforms"]
        flagged = sum(len(record.get("not_runnable", {}))
                      for record in platforms.values())
        self.assertGreater(flagged, 0)
        self.assertEqual(report.count("Not runnable on"), flagged)
        # The suites the audit found unrunnable are flagged on every platform.
        # The Python GUI suites and `live-desktop` are absent: they drove the
        # retired HTTP host and its `linscp_gui` shim, so they no longer exist
        # to be runnable or not.
        for suite in ("unit", "script", "live-sftp", "live-scp", "live-s3",
                      "live-dav", "live-curl", "live-tunnel"):
            for platform, record in platforms.items():
                self.assertIn(suite, record.get("not_runnable", {}),
                              suite + " reads as runnable on " + platform)

    def test_the_real_ledger_is_consistent(self):
        """The shipped inventory has to satisfy its own rules, and the evidence
        it claims has to be evidence the platform it ships on produces."""
        inventory = json.loads((ROOT / "docs/upstream-parity.json").read_text())
        errors = []
        capabilities = check_capabilities(inventory, errors)
        entries = (list(inventory["commands"].values()) + inventory["features"] +
                   inventory.get("linscp_additions", []) + capabilities)
        check_verification(inventory, entries, errors)
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(capabilities), 80)
        self.assertEqual((ROOT / "docs/linux-feature-inventory.md").read_text(),
                         matrix_report(inventory))
        # LinSCP ships on Linux, Windows, and Android via Rust+Tauri: the
        # ledger names exactly those platforms, so no entry can cite evidence
        # from a host this client is not built for.
        platforms = inventory["verification"]["platforms"]
        self.assertEqual(sorted(platforms), ["android", "linux", "windows"])
        cited = [e for e in entries if e.get("verified_on")]
        self.assertTrue(cited, "no entry records any evidence at all")
        for entry in cited:
            self.assertTrue(set(entry["verified_on"]).issubset(set(platforms)),
                             str(entry.get("name")) + ": cites a platform the "
                             "ledger does not ship on")
        # Promotion is allowed only when every aspect of the claim is
        # accounted for: the platform the ledger ships on contributes at
        # least one suite that actually ran the behaviours the notes
        # describe, the notes say which suites those are, and no aspect
        # of the entry is still listed as missing inside the claim.
        verified = [e for e in entries if e["status"] == "verified"]
        for entry in verified:
            label = entry.get("name") or entry.get("id") or "?"
            cited = entry.get("verified_on")
            self.assertTrue(cited, label + ": verified with no evidence at all")
            self.assertEqual(sorted(cited), sorted(platforms),
                             label + ": a platform the ledger ships on has "
                             "no evidence for this entry")
            for platform, suites in cited.items():
                self.assertTrue(suites,
                                label + ": " + platform + " cites no suite")
            if entry in capabilities:
                # Unlike the broad ledger, these rows cite the exact cases;
                # a suite name alone is no longer enough for 'verified'.
                self.assertTrue(entry["checks"], label + ": no test cases")
                self.assertNotIn("gap", entry, label + ": still has a gap")
            else:
                self.assertRegex(
                    entry["notes"], r"(?i)covered by|covered on",
                    label + ": the notes never say which evidence covers which "
                    "behaviour")
                self.assertNotIn(
                    "Missing:", entry["notes"],
                    label + ": a verified claim still lists a missing aspect")


if __name__ == "__main__":
    unittest.main()
