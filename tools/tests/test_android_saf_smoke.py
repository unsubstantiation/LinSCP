"""Keep the on-device SAF suite honest about what it drives.

The suite runs on a phone that CI does not have, so nothing here executes it.
What these cases can do is stop it drifting away from the code it claims to
cover - a route renamed in the service, or a `content://` root the harness has
stopped addressing, would otherwise leave a script that still looks like
evidence.

The important property is the last one: every ledger row this suite is meant to
evidence must be one that is still `partial` for the provider reason. When a row
is upgraded, this fails until the suite's claim is updated with it, so the two
never disagree about what has been proven on a device.
"""
import json
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPTS = [ROOT / "tools" / "android_saf_smoke.sh", ROOT / "tools" / "android_saf_smoke.mjs"]
HARNESS = ROOT / "tools" / "android_saf_smoke.mjs"
SERVICE = ROOT / "crates" / "linscp-service" / "src" / "lib.rs"
LEDGER = ROOT / "docs" / "upstream-parity.json"
# The rows whose gap is specifically "no real DocumentsProvider".
DEVICE_ROWS = [
    "platform.android-saf-editing",
    "platform.android-saf-local-copy-move",
]


class AndroidSafSmokeTests(unittest.TestCase):
    def test_the_suite_ships_both_a_driver_and_a_harness(self):
        for script in SCRIPTS:
            self.assertTrue(script.is_file(), str(script))
            self.assertGreater(len(script.read_text(encoding="utf-8").splitlines()), 20,
                               f"{script.name} is too small to be the suite")

    def test_every_route_the_harness_calls_exists_in_the_service(self):
        """A harness that drives a route the service does not serve proves nothing."""
        text = HARNESS.read_text(encoding="utf-8")
        service = SERVICE.read_text(encoding="utf-8")
        called = set(re.findall(r"['\"](/(?:api)/[a-z0-9/?=&-]+)", text))
        # Query strings are part of the call, not the route.
        routes = {path.split("?")[0] for path in called}
        self.assertTrue(routes, "the harness calls no API route at all")
        for route in sorted(routes):
            self.assertIn(f'"{route}"', service,
                          f"{route} is called by the SAF suite but is not a service route")

    def test_the_suite_skips_instead_of_failing_without_a_grant(self):
        """No grant is a fact about the device, not a defect in the build."""
        text = HARNESS.read_text(encoding="utf-8")
        self.assertIn("skip:", text, "the harness must report a skip when nothing is granted")
        driver = SCRIPTS[0].read_text(encoding="utf-8")
        self.assertIn("granted", driver.lower(),
                      "the driver explains how to grant a folder")

    def test_the_suite_never_writes_outside_its_own_run_folder(self):
        """It runs against a real phone with the user's files on it."""
        text = HARNESS.read_text(encoding="utf-8")
        self.assertIn("linscp-saf-", text,
                      "every write must be scoped to a run-named folder")
        # A save or mkdir whose path is a bare name would land in the tree root.
        for match in re.finditer(r"['\"]path['\"]\s*:\s*([^,}]+)", text):
            target = match.group(1).strip()
            self.assertIn("run", target,
                          f"a write targets {target!r}, which is not scoped to the run folder")

    def test_the_suite_addresses_a_content_uri_root(self):
        """The whole point is a provider-backed root, not app-private storage."""
        text = HARNESS.read_text(encoding="utf-8")
        self.assertIn("saf_tree", text, "the harness must require a saf_tree root")
        self.assertIn("content://", text, "the harness must check the URI scheme")

    def test_the_rows_it_evidences_are_still_the_ones_missing_device_proof(self):
        ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
        rows = {row["id"]: row for row in ledger["capabilities"]}
        for row_id in DEVICE_ROWS:
            self.assertIn(row_id, rows, f"{row_id} is gone from the ledger")
            gap = rows[row_id].get("gap") or ""
            self.assertTrue(
                "DocumentsProvider" in gap or "in-memory mock" in gap,
                f"{row_id} no longer has the provider gap this suite answers: {gap!r}",
            )


if __name__ == "__main__":
    unittest.main()
