#!/usr/bin/env python3
"""Check parity inventory completeness, NOT behavioral equivalence.

By default this is offline. To detect upstream command drift supply upstream
source/core/Script.cpp and Script.h from the same commit. --require-full is an
explicit release gate that fails while any tracked gap remains.
"""
import argparse
import json
import pathlib
import re
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPORT = ROOT / "docs/linux-feature-inventory.md"
PLAN_REPORT = ROOT / "docs/remaining-parity-plan.md"

# A suite name in the ledger must resolve to the test source it claims to
# run. These are test files, not implementation files. A method/check quoted
# in the capability matrix must still exist there when the code changes.
# A pinned baseline must not become 'full' by deleting known missing rows.
# New capabilities may be added freely; removing one of these requires a
# deliberate review of the checker and the upstream scope together.
REQUIRED_GAP_IDS = {
    "scp.shell-directory-engine", "scp.command-and-metadata",
    "ftp.active-passive", "ftp.listings-and-mlsd", "ftp.tls-policy",
    "dav.locks", "dav.dead-properties-and-preconditions",
    "s3.multipart-restart-and-copy", "s3.object-options",
    "transfer.curl-progress", "sync.conflict-ui",
    "sessions.folder-tree", "security.curl-pins-and-tls",
    "security.gssapi-and-tunnels", "security.gui-account",
    "gui.desktop-drop-compatibility", "gui.desktop-local-drop",
    "gui.explorer-custom-commands", "editing.monitor-local-changes",
    "editing.encoding-policy", "automation.dotnet", "automation.powershell",
    "desktop.shell-and-extensions", "locale.translations",
    "locale.accessibility", "platform.debian-package",
    "ftp.non-unix-listings", "dav.etag-preconditions",
    "s3.versioned-objects", "editing.non-utf8-encodings",
    "automation.upstream-xml-compatibility",
}

CASE_SOURCES = {
    "unit": "source/linux/tests/UnitTest.cpp",
    "script": "source/linux/tests/ScriptTest.py",
    "live-sftp": "source/linux/tests/LiveSftpTest.py",
    "live-s3": "source/linux/tests/LiveS3Test.py",
    "live-dav": "source/linux/tests/LiveDavTest.py",
    "live-curl": "source/linux/tests/LiveCurlTest.py",
    "live-scp": "source/linux/tests/LiveScpTest.py",
    "gui": "source/gui/tests/ClientTest.js",
    "gui-localization": "source/gui/tests/LocalizationTest.js",
    "gui-search": "source/gui/tests/RemoteSearchTest.py",
    "gui-local-editor": "source/gui/tests/LocalEditorTest.py",
    "gui-browser-upload": "source/gui/tests/BrowserUploadTest.py",
    "gui-security": "source/gui/tests/SecurityTest.py",
    "powershell": "automation/test_psmodule.py",
    "gui-desktop-uri": "source/gui/tests/DesktopUriTest.py",
    "gui-security": "source/gui/tests/SecurityTest.py",
    "platform-conversion": "tools/tests/test_platform_conversion.py",
}


def upstream_commands(script, header):
    constants = dict(re.findall(r'#define\s+(\w+_COMMAND)\s+L"([^"]+)"', header))
    tokens = re.findall(r'FCommands->Register\(\s*(L"[^"]+"|\w+)', script)
    if not tokens:
        raise ValueError("No upstream command registrations found")
    return {token[2:-1] if token.startswith('L"') else constants[token]
            for token in tokens}


def command_table(source):
    """The names the interpreter can abbreviate to, in Script.cpp."""
    block = re.search(r"const char \* const kCommandNames\[\] = \{(.*?)\};",
                      source, re.S)
    if not block:
        raise ValueError("No kCommandNames table in source/linux/Script.cpp")
    return set(re.findall(r'"([^"]+)"', block.group(1)))


VERIFICATION_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def check_verification(inventory, entries, errors):
    """'verified' is a claim about behavior, so it has to cite its evidence.

    A status in this inventory says what the code does, not what somebody
    hoped. An entry may therefore only be called 'verified' when it names the
    platforms whose test evidence covers it, and every platform in the ledger
    has to say how that evidence is produced and what it can prove. Anything
    that cannot be reproduced is not evidence, so the suites an entry cites
    have to be suites the platform actually has.
    """
    verification = inventory.get("verification")
    if not isinstance(verification, dict):
        errors.append("Inventory has no 'verification' block, so no entry can "
                      "claim to be verified: add how each platform produces "
                      "its evidence")
        return None
    if not str(verification.get("policy", "")).strip():
        errors.append("'verification.policy' is empty: say what an entry has "
                      "to show before it may be called verified")
    platforms = verification.get("platforms")
    if not isinstance(platforms, dict) or not platforms:
        errors.append("'verification.platforms' is empty: there is no "
                      "evidence to cite, so nothing may be verified")
        return None
    suites = {}
    for name, record in sorted(platforms.items()):
        for field in ("how", "date"):
            if not str(record.get(field, "")).strip():
                errors.append(f"Verification record for '{name}' has no '{field}'")
        date = str(record.get("date", ""))
        if date and not VERIFICATION_DATE.fullmatch(date):
            errors.append(f"Verification date for '{name}' is not YYYY-MM-DD: {date}")
        listed = record.get("suites")
        if not isinstance(listed, dict) or not listed:
            errors.append(f"Verification record for '{name}' lists no test "
                          "suites, so no entry can cite evidence from it")
            listed = {}
        for suite, description in sorted(listed.items()):
            if not str(description).strip():
                errors.append(f"'{name}' suite '{suite}' is not described: "
                              "say what it proves")
        suites[name] = set(listed)
    covered = {name: 0 for name in suites}
    for entry in entries:
        label = entry.get("name", entry.get("id", entry.get("command", "?")))
        claimed = entry.get("verified_on")
        if entry["status"] == "verified" and not claimed:
            errors.append(f"{label} is verified but cites no evidence: name "
                          "the platform and the suites that checked it")
        if claimed is None:
            continue
        if not isinstance(claimed, dict) or not claimed:
            errors.append(f"{label} has an empty 'verified_on': cite the "
                          "platform and the suites, or record nothing")
            continue
        for platform, cited in sorted(claimed.items()):
            if platform not in suites:
                errors.append(f"'verified_on' names an unknown platform: {platform}")
                continue
            if not isinstance(cited, list) or not cited:
                errors.append(f"'verified_on.{platform}' names no suite: "
                              "evidence has to point at a test")
                continue
            unknown = set(cited) - suites[platform]
            for suite in sorted(unknown):
                errors.append(f"'{platform}' has no suite '{suite}' to cite "
                              f"for {label}")
            covered[platform] += 1
        if entry["status"] == "verified" and set(claimed) != set(suites):
            missing = sorted(set(suites) - set(claimed))
            errors.append(f"{label} is verified without evidence from: "
                          + ", ".join(missing))
    return {"covered": covered,
            "verified": sum(1 for e in entries if e["status"] == "verified"),
            "entries": len(entries)}


def check_capabilities(inventory, errors, root=ROOT):
    """Validate the granular Linux matrix, not just the 15 parent headings.

    Every area must be broken into individually reviewable behaviours. A
    'verified' row names a real test case, not merely a suite that might have
    run something unrelated. An unimplemented row cannot cite implementation
    or evidence, and a partial row must tell the user exactly what is left.
    """
    rows = inventory.get("capabilities")
    if not isinstance(rows, list) or not rows:
        errors.append("Inventory has no capability matrix")
        return []
    areas = {item["name"] for item in inventory["features"]}
    found = Counter()
    seen = set()
    for row in rows:
        label = row.get("id", "?")
        if not re.fullmatch(r"[a-z][a-z0-9-]*\.[a-z][a-z0-9-]*", str(label)):
            errors.append(f"Invalid capability id: {label}")
        if label in seen:
            errors.append(f"Duplicate capability id: {label}")
        seen.add(label)
        area = row.get("area")
        if area not in areas:
            errors.append(f"{label}: unknown feature area: {area}")
        else:
            found[area] += 1
        status = row.get("status")
        if status not in ("verified", "partial", "missing"):
            errors.append(f"{label}: invalid capability status: {status}")
        if not str(row.get("notes", "")).strip():
            errors.append(f"{label}: explain the Linux implementation or absence")
        if status in ("partial", "missing") and not str(row.get("gap", "")).strip():
            errors.append(f"{label}: a {status} capability needs a concrete gap")
        if status == "verified" and row.get("gap"):
            errors.append(f"{label}: verified while still listing a gap")
        acceptance = row.get("acceptance")
        if status in ("partial", "missing") and (
                not isinstance(acceptance, list) or not acceptance or
                any(not isinstance(item, str) or not item.strip() for item in acceptance)):
            errors.append(f"{label}: a {status} capability needs acceptance criteria")
        if status == "verified" and acceptance:
            errors.append(f"{label}: verified while still listing acceptance work")
        source = row.get("source", [])
        if not isinstance(source, list):
            errors.append(f"{label}: source must be a list of repository files")
            source = []
        if status == "missing" and source:
            errors.append(f"{label}: missing yet names an implementation")
        if status in ("verified", "partial") and not source:
            errors.append(f"{label}: no implementation location")
        for path in source:
            if not isinstance(path, str) or pathlib.PurePosixPath(path).is_absolute() or \
                    ".." in pathlib.PurePosixPath(path).parts or \
                    not (root / path).is_file():
                errors.append(f"{label}: implementation source does not exist: {path}")

        checks = row.get("checks", {})
        if not isinstance(checks, dict):
            errors.append(f"{label}: checks must name suites and test cases")
            checks = {}
        if status == "missing" and checks:
            errors.append(f"{label}: missing yet cites test cases")
        if status == "verified" and not checks:
            errors.append(f"{label}: verified without a test case")
        cited = set(row.get("verified_on", {}).get("linux", [])) if isinstance(
            row.get("verified_on"), dict) else set()
        if checks and set(checks) != cited:
            errors.append(f"{label}: verified_on.linux must match checked suites")
        if not checks and row.get("verified_on"):
            errors.append(f"{label}: cites evidence without test cases")
        for suite, cases in checks.items():
            file = CASE_SOURCES.get(suite)
            if not file or not (root / file).is_file():
                errors.append(f"{label}: unknown test suite {suite}")
                continue
            if not isinstance(cases, list) or not cases:
                errors.append(f"{label}: {suite} names no test case")
                continue
            text = (root / file).read_text()
            for case in cases:
                if not isinstance(case, str) or not case.strip():
                    errors.append(f"{label}: empty test case in {suite}")
                    continue
                if suite in ("gui", "gui-localization"):
                    # The JS harness calls check('description', condition).
                    expression = r"check\(\s*['\"]" + re.escape(case) + r"['\"]"
                else:
                    # Python's test_* methods and the named C++ Test* functions.
                    expression = r"\b(?:def|void)\s+" + re.escape(case) + r"\s*\("
                if not re.search(expression, text):
                    errors.append(f"{label}: {suite} has no test case {case}")
    for area in sorted(areas - found.keys()):
        errors.append(f"Feature area has no capability rows: {area}")
    if inventory.get("upstream", {}).get("commit") == \
            "69edabbe2dc2c62661a7d3fc7e2396b5f42d504d":
        for id in sorted(REQUIRED_GAP_IDS - seen):
            errors.append(f"Pinned upstream gap was dropped from the inventory: {id}")
    return rows


def check_command_coverage(inventory, dispatched, errors):
    """Every implemented dispatcher name belongs to exactly one ledger group."""
    known = set(inventory['commands'])
    additions = set()
    for entry in inventory.get('linscp_additions', []):
        names = entry.get('commands')
        if not isinstance(names, list) or not names or any(
                not isinstance(name, str) or not name for name in names):
            errors.append(f"{entry.get('name')}: addition needs explicit command names")
            continue
        for name in names:
            if name in known or name in additions:
                errors.append('Command appears in multiple ledger groups: ' + name)
            additions.add(name)
    for name in sorted(dispatched - known - additions):
        errors.append('Dispatched command is absent from inventory: ' + name)
    for name in sorted(additions - dispatched):
        errors.append('Inventoried addition has no dispatcher: ' + name)


def check_feature_rollups(inventory, errors):
    for feature in inventory['features']:
        gaps = [r['id'] for r in inventory['capabilities']
                if r['area'] == feature['name'] and r['status'] != 'verified']
        if gaps and feature['status'] == 'verified':
            errors.append(feature['name'] + ': verified area has tracked gaps: ' + ', '.join(gaps))
        if feature['status'] != 'verified' and not feature.get('gap', '').strip():
            errors.append(feature['name'] + ': non-verified area needs an explicit gap')


def markdown_cell(text):
    return ' '.join(str(text).split()).replace('|', r'\|')


def source_links(paths):
    return '<br>'.join(f'[{path}](../{path})' for path in paths) or '—'


def suite_links(entry):
    suites = sorted(set(s for values in entry.get('verified_on', {}).values() for s in values))
    return ', '.join(f'[{suite}](../{CASE_SOURCES[suite]})' for suite in suites) or '—'


def case_links(row):
    links = []
    for suite, cases in sorted(row.get('checks', {}).items()):
        path = CASE_SOURCES[suite]
        text = (ROOT / path).read_text()
        for case in cases:
            if suite in ('gui', 'gui-localization'):
                pattern = r"check\(\s*['\"]" + re.escape(case) + r"['\"]"
            else:
                pattern = r'\b(?:def|void)\s+' + re.escape(case) + r'\s*\('
            match = re.search(pattern, text)
            line = text.count('\n', 0, match.start()) + 1 if match else 1
            label = markdown_cell(suite + ': ' + case)
            links.append(f'[{label}](../{path}#L{line})')
    return '<br>'.join(links) or '—'


def matrix_report(inventory):
    """One inventory of every ledger section, not just the capability subset."""
    rows = inventory['capabilities']
    counts = Counter(row['status'] for row in rows)
    commands = inventory['commands']
    additions = inventory.get('linscp_additions', [])
    features = inventory['features']
    lines = [
        '# Linux feature inventory', '',
        'Generated from [upstream-parity.json](upstream-parity.json). Baseline: ' +
        inventory['upstream']['repository'] + ' `' + inventory['upstream']['commit'] + '`.', '',
        '**Inventory completeness is not implementation completeness. Full WinSCP parity is not achieved.**', '',
        inventory.get('scope', {}).get('definition', ''), '',
        f"{len(rows)} capabilities: {counts['verified']} verified for the stated behavior, "
        f"{counts['partial']} partial, {counts['missing']} missing.", '',
        '`verified` applies only to the stated behavior and cited tests; `partial` has a working subset; '
        '`missing` has no implementation of the stated capability. A dependency-skipped test is not a pass. '
        'Consult test-run evidence for what actually ran, not only this source ledger.', '',
        'Regenerate both this inventory and the [remaining plan](remaining-parity-plan.md): '
        '`python3 tools/check_upstream_parity.py --write-report`. The default check rejects drift.', '',
        '## Coverage summary', '',
        '| Ledger section | Total | Verified | Partial | Missing |',
        '| --- | --- | --- | --- | --- |',
    ]
    for name, entries in [('Upstream command registrations', list(commands.values())),
                          ('LinSCP addition groups', additions),
                          ('Feature areas', features), ('Granular capabilities', rows)]:
        c = Counter(e['status'] for e in entries)
        lines.append(f"| {name} | {len(entries)} | {c['verified']} | {c['partial']} | {c['missing']} |")
    lines += ['', 'Area statuses include the known gaps below; verified capability rows do not imply '
              'that their whole protocol or area has full upstream coverage.', '',
              '## Scope and evidence limitations', '']
    lines.extend('- ' + item for item in inventory.get('scope', {}).get('limitations', []))
    lines += ['', '## Upstream script command registrations', '',
              'Aliases are counted as separate registrations exactly as in the pinned upstream interpreter. '
              'Command-level suite citations describe scoped command behavior; the capability tables provide named test cases.', '',
              '| Command | Status | Implementation | Evidence suites | Behavior / boundary |',
              '| --- | --- | --- | --- | --- |']
    for name, entry in sorted(commands.items()):
        lines.append(f"| `{name}` | {entry['status']} | {source_links(entry.get('source', ['source/linux/Script.cpp']))} | "
                     f"{suite_links(entry)} | {markdown_cell(entry['notes'])} |")
    lines += ['', '## LinSCP-specific additions', '',
              'These additions are not counted as upstream command coverage.', '',
              '| Addition group | Status | Implementation | Evidence suites | Behavior / boundary |',
              '| --- | --- | --- | --- | --- |']
    for entry in additions:
        lines.append(f"| {markdown_cell(entry['name'])} | {entry['status']} | "
                     f"{source_links(entry.get('source', ['source/linux/Script.cpp']))} | "
                     f"{suite_links(entry)} | {markdown_cell(entry['notes'])} |")
    lines += ['', '## Feature area overview', '',
              '| Area | Status | Evidence suites | Current scope / boundary |',
              '| --- | --- | --- | --- |']
    for feature in features:
        lines.append(f"| {feature['name']} | {feature['status']} | {suite_links(feature)} | "
                     f"{markdown_cell(feature['notes'])} |")
    lines += ['', '## Granular capabilities']
    for feature in features:
        lines += ['', '### ' + feature['name'], '',
                  '| Capability | Linux status | Implementation | Named automated evidence | Scope / remaining gap |',
                  '| --- | --- | --- | --- | --- |']
        for row in rows:
            if row['area'] != feature['name']:
                continue
            note = row['notes']
            if row.get('gap'):
                note += ' **Next:** ' + row['gap']
            lines.append(f"| `{row['id']}` | {row['status']} | {source_links(row.get('source', []))} | "
                         f"{case_links(row)} | {markdown_cell(note)} |")
    lines += ['', '## Evidence suite registry', '',
              'Suite descriptions are not claims that they ran here. Reproduction commands and dependency limits '
              'are recorded per platform in the ledger.', '']
    for platform, record in sorted(inventory['verification']['platforms'].items()):
        lines += ['### ' + platform, '', '**Reproduce:** ' + record['how'], '']
        for suite, description in sorted(record['suites'].items()):
            lines.append('- [' + suite + '](../' + CASE_SOURCES[suite] + '): ' + markdown_cell(description))
    return '\n'.join(lines) + '\n'


def plan_report(inventory):
    rows = [r for r in inventory['capabilities'] if r['status'] != 'verified']
    lines = ['# Remaining parity implementation plan', '',
             'Generated from [upstream-parity.json](upstream-parity.json); do not edit separately. '
             'Full upstream parity is the target, **not a completed claim**.', '',
             f'{len(rows)} tracked capability gaps. Each requires implementation and acceptance evidence; '
             'recording a plan does not satisfy its tests.', '',
             'Regenerate with `python3 tools/check_upstream_parity.py --write-report`.', '']
    for row in rows:
        lines += ['## ' + row['id'], '', '**Area:** ' + row['area'] + ' · **Status:** ' + row['status'], '',
                  row['notes'], '', '**Next:** ' + row['gap'], '', '**Acceptance criteria:**', '']
        lines.extend('- [ ] ' + criterion for criterion in row['acceptance'])
        lines.append('')
    lines += ['## Cross-cutting release gate', '',
              'Preserve Linux Makefile/CMake and packaging workflows, add positive and negative tests, '
              'report dependency skips, and update the ledger and generated reports. '
              '`python3 tools/check_upstream_parity.py --require-full` fails while any tracked gap remains. '
              'The normal checker validates consistency, not behavioral parity.', '']
    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream-script", type=pathlib.Path)
    parser.add_argument("--upstream-header", type=pathlib.Path)
    parser.add_argument("--require-full", action="store_true")
    parser.add_argument("--write-report", action="store_true",
                        help="regenerate docs/linux-feature-inventory.md")
    parser.add_argument("--list-gaps", action="store_true",
                        help="show unverified Linux capabilities")
    args = parser.parse_args()
    inventory = json.loads((ROOT / "docs/upstream-parity.json").read_text())
    commands = inventory["commands"]
    entries = (list(commands.values()) + inventory["features"] +
               inventory.get("linscp_additions", []))
    errors = []
    for entry in entries:
        if entry["status"] not in {"partial", "missing", "verified"} or not entry["notes"]:
            errors.append("Invalid or unexplained status: " + repr(entry))
    source = (ROOT / "source/linux/Script.cpp").read_text()
    dispatched = set(re.findall(r'command == "([^"]+)"', source))
    for command, entry in commands.items():
        if entry["status"] != "missing" and command not in dispatched:
            errors.append(f"Documented command has no dispatcher: {command}")
    # Abbreviations are resolved against kCommandNames, so that list and the
    # dispatcher have to agree: an unlisted command cannot be abbreviated to,
    # and a listed one that is not dispatched resolves to an error message.
    check_command_coverage(inventory, dispatched, errors)
    table = command_table(source)
    for name in sorted(table - dispatched):
        errors.append(f"Abbreviatable command is not dispatched: {name}")
    for name in sorted(dispatched - table):
        errors.append(f"Dispatched command is not in kCommandNames: {name}")
    if bool(args.upstream_script) != bool(args.upstream_header):
        errors.append("Supply both --upstream-script and --upstream-header")
    elif args.upstream_script:
        actual = upstream_commands(args.upstream_script.read_text(), args.upstream_header.read_text())
        for command in sorted(actual - commands.keys()):
            errors.append(f"Untracked upstream command: {command}")
        for command in sorted(commands.keys() - actual):
            errors.append(f"Command no longer registered upstream: {command}")
    capabilities = check_capabilities(inventory, errors)
    check_feature_rollups(inventory, errors)
    evidence = check_verification(inventory, entries + capabilities, errors)
    gaps = sum(entry["status"] != "verified" for entry in entries)
    capability_gaps = sum(row.get("status") != "verified" for row in capabilities)
    additions = len(inventory.get("linscp_additions", []))
    if evidence:
        summary = ", ".join(f"{name}: {count}"
                            for name, count in sorted(evidence["covered"].items()))
        print(f"Evidence recorded per platform ({summary}); "
              f"{evidence['verified']} of {evidence['entries']} entries verified.")
    print(f"Upstream {inventory['upstream']['commit']}: "
          f"{len(commands)} commands, {additions} LinSCP-specific entries, "
          f"{len(inventory['features'])} feature areas, {gaps} broad gaps; "
          f"{len(capabilities)} granular capabilities, {capability_gaps} "
          "capability gaps. Inventory validation is not a parity certification.")
    if args.require_full and (gaps or capability_gaps):
        errors.append("Full parity gate failed: tracked gaps remain")
    if args.list_gaps:
        for row in capabilities:
            if row.get("status") != "verified":
                print(f"{row.get('id', '?')} ({row.get('status', '?')}): "
                      f"{row.get('gap', '?')}")
    for platform in inventory['verification']['platforms'].values():
        for suite in platform['suites']:
            if suite not in CASE_SOURCES or not (ROOT / CASE_SOURCES[suite]).is_file():
                errors.append('Evidence suite has no existing source mapping: ' + suite)
    if not errors:
        reports = {REPORT: matrix_report(inventory), PLAN_REPORT: plan_report(inventory)}
        for path, text in reports.items():
            if args.write_report:
                path.write_text(text)
                print("Updated " + str(path.relative_to(ROOT)))
            elif not path.is_file() or path.read_text() != text:
                errors.append(str(path.relative_to(ROOT)) + " is missing or out of date: "
                              "run python3 tools/check_upstream_parity.py --write-report")
    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, ValueError, OSError) as exc:
        print(f"Parity inventory check failed: {exc}", file=sys.stderr)
        sys.exit(1)
