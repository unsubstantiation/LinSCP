# WinSCP parity audit and inventory guide

**Full feature parity is not achieved.** LinSCP is a Linux-only client using
an independent implementation with libssh for SSH transport, not a build of
the complete upstream application. A supported URL, similar GUI or passing
build is not proof of behavioral parity.

## Baseline and scope

The inventory is pinned to [winscp/winscp at
69edabbe2dc2c62661a7d3fc7e2396b5f42d504d](https://github.com/winscp/winscp/tree/69edabbe2dc2c62661a7d3fc7e2396b5f42d504d).
It is a development snapshot, not a claim about the latest release. The initial
source review compared upstream `source/core/Script.cpp`, `Script.h`,
`CopyParam.h`, `Terminal.h`, and core/forms inventories with the Linux client,
build configuration and GUI. Linux inventory reconciliation: **2026-10-18**.

The source of truth is [upstream-parity.json](upstream-parity.json). Its generated
[complete ledger view](linux-feature-inventory.md) includes:

- Every pinned upstream script registration, including aliases and `copyid`.
- Every Linux dispatcher command not present upstream, grouped separately so
  Linux extensions are not mistaken for upstream coverage.
- All reviewed feature areas with current implementation boundaries.
- Granular capabilities with implementation paths, named test links and gaps.
- The Linux evidence-suite registry and reproduction instructions.

Counts and statuses live in the generated view rather than in a second,
hand-maintained summary. The generated [remaining implementation
plan](remaining-parity-plan.md) gives acceptance criteria for **every** partial
or missing capability. Recording a gap and its criteria completes an inventory
entry; it does not implement the feature.

## Reconciliation findings

The review corrected stale claims without upgrading unimplemented work:

- S3 multipart upload state/restart, multipart copy, signed object-write
  options and version-aware operations are implemented. `versions` lists object
  history; `get -versionid=` and `rm -versionid=` operate on one exact version,
  and object/version listing fails closed if a paginated response omits or
  repeats its continuation marker.
- Native FTP directory/metadata operations, active/passive policy and TLS
  settings are implemented; non-Unix LIST dialects remain missing.
- Local-pane desktop drops, cross-browser enumeration APIs, local edit
  monitoring, session folders and conflict controls have test evidence. This
  does not certify all real browser/file-manager/server combinations.
- WebDAV session locks, dead properties and ETag preconditions are implemented
  Linux extensions. `etag` records an If-Match/If-None-Match tag per path, a
  WebDAV write of that path sends it in one no-tag `If` list next to any lock
  token, a stale tag is refused by the server with 412 and leaves the
  destination's bytes and listing untouched, `*` is refused rather than sent as
  a tag nothing matches, a protocol with no entity tags is refused by name, and
  a precondition guards the path it was recorded for rather than everything
  below a collection.
- English/Spanish GUI and shared CLI localization exists. Remaining
  human-facing script/engine diagnostics keep localization partial.
- Non-UTF-8 editor transcoding and upstream XML consumer/schema compatibility
  are now explicit capability rows rather than prose-only limitations.
- `?`, `delsession`, `terminal`, `presets`, `savepreset` and `rmspreset` are
  explicitly inventoried rather than left outside the command ledger.
- `scp://` (and `ssh://`) sessions use this client's own SSH code, not curl, so
  a host-key pin does not depend on which SSH library the curl build links.
  The rcp protocol has no offset, so a resume is refused by name and a stale
  staging file is discarded.

Upstream Windows VCL forms, .NET assemblies, Explorer commands and shell
extensions have no Linux substitute. GSSAPI, SSH tunnels, multi-user GUI
isolation, automation APIs and desktop extensions remain in the plan.

## The platform conversion

LinSCP ships on Linux alone. The Windows port was removed in 1.0-2, and an
audit of what it left behind found four things that were still Windows:

- The script command splitter read a backslash as the start of an escape
  inside double quotes, the rule a Windows command line follows. A path
  carried over from a Windows client lost its separators: `"C:\Users\me"`
  arrived as `C:Usersme`, and a file named `a\b.txt` was read as `ab.txt`,
  so the name of one file became the name of another. The splitter now
  follows the rules of a POSIX shell, which is what the names on this
  platform are.
- The error messages carried the operation phrases of the Windows client
  ("change of directory to", "expansion of") inside a template that supplies
  its own preposition, so the client said "Local change of directory to of
  '...' failed." The phrases fit the template now, and the check below
  refuses one that does not.
- The tree still held `source/linux/liblinscp.h`, a public C ABI header for
  a library no build produced, and `debian/linscp-nautilus.py`, a
  half-translated file-manager extension that ran no session and therefore
  uploaded nothing. Both are gone; the automation object model and the
  desktop extensions stay tracked gaps in the plan.
- The three installers - the Makefile, CMake and the Debian package - did
  not install the same files. An installed graphical client started with
  an empty command list, because the file it reads was not installed, and
  the PowerShell module was missing from the package. They agree now.

`tools/check_platform_conversion.py` is what keeps that true. It reads the
client's own sources and refuses a Windows API call, a Windows header, a
Windows-only compilation branch, a Windows environment variable, a Windows
executable, a Windows path, a file of another platform, an installer that
does not ship what the other installers ship, and an error message whose
wording contradicts the template it is filled into. It runs in
`make -C source/linux check`, as the CTest case `platform-conversion-check`,
and in CI. Third-party library sources are not vendored in this repository; the
platform layer and protocol integration maintained here are checked directly.

## The display session

"Linux" is not one desktop. A session runs on Wayland or on X11, and an
application that only asks for X11 does not fail loudly - it asks for
`$DISPLAY`, finds nothing on a Wayland session where XWayland is not running,
and concludes the user has no desktop. LinSCP draws no window of its own, so
three places are where this can go wrong: the terminal window `terminal` opens,
the browser window the graphical client asks to be shown, and the desktop entry
that starts it. They are covered by `desktop.wayland-session`, and
`tools/check_wayland_compatibility.py` keeps them that way: it refuses a
display-session decision that reads `DISPLAY` with no `WAYLAND_DISPLAY` in
view, a terminal candidate that does not say which display server it can draw
on, an X11-only or Wayland-only helper program (`xclip`, `xdotool`, `wmctrl`,
`grim`), a desktop entry whose startup notification no compositor can
complete, documentation of the terminal choice that never mentions Wayland, and
the two detections - the console client's and the graphical client's -
disagreeing about the variables that say what a session is. Its own regressions
are in `tools/tests/test_wayland_compatibility.py`, which is a cited evidence
suite; the check runs in `make -C source/linux check`, as the CTest cases
`wayland-compatibility-check` and `wayland-compatibility-tests`, and in CI.

What no case here establishes is the interaction with a live compositor. The
evidence is source-level plus fixtures that assert what the session is; opening
a terminal on a Wayland desktop and clicking the entry in an application grid
are the checks that would say more, and they are recorded as still needed.

## Evidence and status rules

`verified` means the stated behavior has automated evidence, not every variant
of its upstream feature. `partial` names a working subset and remaining work.
`missing` has no implementation of the stated capability.

The checker enforces:

1. Verified entries cite suites for every declared platform (currently Linux).
2. Capability evidence names existing cases in the correct test-source file;
   generated links point to those cases rather than just to a suite name.
3. Every implemented dispatcher command belongs to one upstream/addition group;
   new commands cannot silently escape the inventory.
4. Every known area has capability rows, and an area with tracked gaps cannot
   be marked verified. Expanded scope may reduce verified counts without a
   code regression.
5. Missing/partial capabilities have concrete next steps and acceptance
   criteria. Known baseline gap IDs cannot be dropped to fake completion.
6. The generated inventory and plan both match the JSON; neither is maintained
   as an independent second source of truth.

The ledger records evidence **definitions**, not test execution history. Suites
that produce `evidence:` lines report actual runs, failures and dependency
skips. A skipped dependency is not a pass. Consult the CI/test output before
claiming a feature was exercised on a particular system. Mock-server and
jsdom tests do not certify all production environments or constitute a
completed security review.

## Reproduce and maintain

```sh
python3 tools/check_upstream_parity.py
python3 tools/tests/test_parity_inventory.py
python3 tools/check_upstream_parity.py --list-gaps
# After reviewing changes to the JSON:
python3 tools/check_upstream_parity.py --write-report
```

To verify command registrations against source files obtained from the pinned
upstream commit:

```sh
python3 tools/check_upstream_parity.py \
  --upstream-script /path/to/upstream/source/core/Script.cpp \
  --upstream-header /path/to/upstream/source/core/Script.h
```

The default check is offline. It validates inventory consistency, not upstream
behavior. `--require-full` is a separate release gate and intentionally fails
while **any** tracked capability or broad-area gap remains. Do not promote a
row, delete it, or narrow its claim merely to make that gate green.
