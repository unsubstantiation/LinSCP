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

    def test_every_write_it_makes_is_namespaced_by_the_run_id(self):
        """It runs against a real phone with the user's files on it.

        The local routes take a single leaf name and refuse a path, so a run
        folder cannot be entered by writing `run/name` - each write is a leaf in
        the granted tree, and the only thing keeping it from colliding with the
        user's own files is the timestamped run id inside the name.
        """
        text = HARNESS.read_text(encoding="utf-8")
        self.assertIn("linscp-saf-", text, "every name must carry the run prefix")

        # Every identifier built from the run id, e.g.
        #   const fileName = run + '.txt'
        derived = {name for name, expression
                   in re.findall(r"const (\w+) = ([^;]*);", text)
                   if "run" in expression and name != "run"}
        self.assertTrue(derived,
                        "no name in the harness is derived from the run id, so a "
                        "write could collide with the user's own file")

        # Every value handed to a write route must be one of those identifiers,
        # or the run id itself. A literal name would be a bug even if it looked
        # harmless, because the next person would copy it.
        # Only the bodies of calls that actually write, so a `name:` that is
        # part of some other object does not stand in for a write here.
        bodies = [m.group(1) for m in
                  re.finditer(r"attempt\('[A-Z]+',\s*'[^']+',\s*\{([^}]*)\}", text, re.S)]
        writes = []
        for body in bodies:
            for value in re.findall(r"\b(?:path|names?)\s*:\s*(\[[^\]]*\]|[A-Za-z_$][\w$]*)", body):
                writes.extend(part.strip() for part in value.strip("[]").split(",") if part.strip())
        self.assertTrue(writes, "the harness performs no write to a granted folder")
        for value in writes:
            self.assertIn(value, derived | {"run"},
                          f"a write uses {value!r}, which is not derived from the run id")
        self.assertIn("names: [run]", text, "the run folder is cleaned up")

    def test_the_suite_addresses_a_content_uri_root(self):
        """The whole point is a provider-backed root, not app-private storage."""
        text = HARNESS.read_text(encoding="utf-8")
        self.assertIn("saf_tree", text, "the harness must require a saf_tree root")
        self.assertIn("content://", text, "the harness must check the URI scheme")

    def test_the_name_to_id_resolution_matches_what_each_provider_returns(self):
        """The plugin resolves a name to the provider's own document id.

        This mirrors `resolveDocument` in LinSCPAndroidPlugin.kt. It cannot run
        the Kotlin, but it pins the rule the Kotlin implements, because the bug
        it fixes is invisible on shared storage and fatal on Google Drive:
        there the id is an opaque token, so `.../document/<name>` names a
        document that does not exist.
        """
        def resolve(segments, listing):
            if "tree" not in segments or "document" not in segments:
                return "tree-root"
            current = segments[segments.index("tree") + 1]
            i = segments.index("document") + 1
            while i < len(segments):
                if segments[i] == "document":
                    i += 1
                    continue
                wanted, found = segments[i], None
                for child_id, name in listing.get(current, []):
                    if child_id == wanted:
                        found = child_id
                        break
                    if name == wanted and found is None:
                        found = child_id
                self.assertIsNotNone(
                    found, f"expected {wanted!r} to resolve through its parent listing")
                current = found
                i += 1
            return current

        # Shared storage: the id is the name, so the old form keeps working.
        shared = {"primary:Download": [("primary:Download/report.pdf", "report.pdf")]}
        self.assertEqual(
            resolve(["tree", "primary:Download", "document", "report.pdf"], shared),
            "primary:Download/report.pdf")

        # Google Drive: the id is opaque, so a name has to be looked up.
        drive = {"treeId": [("1a2B3c", "report.pdf"), ("9zY8x", "Photos")],
                 "9zY8x": [("4kL5m", "beach.jpg")]}
        self.assertEqual(
            resolve(["tree", "treeId", "document", "report.pdf"], drive), "1a2B3c")
        self.assertEqual(
            resolve(["tree", "treeId", "document", "Photos", "document", "beach.jpg"], drive),
            "4kL5m")
        # A URI that already carries a real id resolves to itself, which is the
        # shape the page builds after listing through this plugin.
        self.assertEqual(resolve(["tree", "treeId", "document", "9zY8x"], drive), "9zY8x")

    def test_the_plugin_resolves_before_it_builds_a_document_uri(self):
        """The five commands must not append a name to a parent URI unlooked-up."""
        plugin = (ROOT / "crates" / "linscp-tauri" / "android"
                  / "LinSCPAndroidPlugin.kt").read_text(encoding="utf-8")
        self.assertIn("private fun resolveDocument", plugin)
        for command in ("writeUri", "mkdirUri", "deleteUri", "renameUri", "statUri"):
            start = plugin.index(f"fun {command}(")
            end = plugin.index("@Command", start) if "@Command" in plugin[start:] else len(plugin)
            body = plugin[start:end]
            self.assertIn("resolveDocument(", body,
                          f"{command} builds a document URI without resolving the name")

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
