# Native parity audit — Windows, Debian, Android

**Date:** 2026-11-06 · **Branch:** `arena/a4f5fe10-linscp` · **Mode:** audit, then A1 fixed on request.

> **Update (same day):** A1, A2, A3, A4, A5, A6, A7(b) and A9 below have been implemented, and the
> §3 suites have been triaged (B) — see their **Status** notes for what changed and what still
> needs a compiler to confirm. The rest of this document is the audit as written, so A8 and the
> A7(a) `LocalFs` routing still describe the tree as it was before those changes.

**Question asked:** "Make sure we have full feature parity between the builds."
**Scope, as confirmed:** the three native builds — `linscp-gui` on Windows (MSVC), `linscp-gui` on
Debian, and the Android APK. The browser server (`linscp-web` / `crates/linscp-http`) is **not** in
scope, so HTTP-vs-window asymmetries are excluded by instruction.

**Two different things are being asked in one sentence, and they fail differently:**

| | Meaning | State |
|---|---|---|
| **A. Behavioural parity** | the same click does the same thing on all three builds | **9 defects**, all in shipped code: Windows hit by 7, Debian by 3, Android by 6; 2 are broken on all three. **A1, A2, A3 and A6 are fixed** (see §2) |
| **B. Evidence parity** | the claim "verified on Windows, Debian *and* Android" is true | **triaged** (see §3): the 16 unrunnable suites are flagged per platform (16/20/25 flags), 28 of 176 entries remain verified citing only suites that run where cited, the checker validates every platform's citations and runs in the Debian job; Android still executes no Rust test |

A build can be behaviourally at parity and still fail B, and vice versa. Both are reported below,
separately, because they are fixed by different work.

**Method.** Static reading of the whole Rust workspace plus the two build systems; the Python check
scripts and the UI suite were executed; three of the Python GUI suites were executed to see what
they actually do. **No Rust toolchain exists in this sandbox** (`rustup` install fails:
`curl: (35) … SSL_ERROR_SYSCALL` against `static.rust-lang.org`), so every Rust statement below is a
reading of the source with `file:line`, not a test result. Nothing was compiled or run under cargo.

What *was* executed (all from the repo root, branch `arena/a4f5fe10-linscp`):

```
python3 tools/check_upstream_parity.py            # exit 0 — inventory validates, no behavioural claim
python3 tools/check_platform_conversion.py        # exit 0
python3 tools/check_repo_hygiene.py               # exit 0
(cd ui && npm ci && npm test)                     # exit 0 — typecheck, build, jsdom suites
python3 source/gui/tests/ShellIntegrationTest.py  # 12 ran, 12 failed, exit 0
python3 source/gui/tests/LocalWorkspaceTest.py    # 26 ran, 26 errors + 8 skipped, exit 0
python3 source/gui/tests/SecurityTest.py          # 124 ran, 123 failed, exit 0
```

The last three are the point of §3: they fail, they print an `evidence:` line, and they exit 0.

---

## 1. What is genuinely shared (so the report does not overstate the gap)

One `CommanderService`, one service dispatch table, one `ui/dist` bundle, one page
(`source/gui/web/index.html`, 5480 lines). The per-OS code is confined to `crates/linscp-platform`
(`sys` = `linux.rs` / `windows.rs` / `android.rs`) plus the Tauri/Android bridge. Measured:

- `crates/linscp-engine`, `linscp-proto`, `linscp-http` contain **zero** `cfg(target_os = …)` branches.
- `crates/linscp-service` contains **one**: `lib.rs:8225` (a test).
- All 81 distinct `/api/...` paths the page calls exist as routes in the service dispatch table
  (checked mechanically: every path literal in the page is a quoted route in `linscp-service/src/lib.rs`).
- All three hosts call the **async** dispatcher: `linscp-http/src/lib.rs:333,354`,
  `linscp-tauri/src/lib.rs:59`. So the question "does the native window take a different service
  path than the browser?" answers **no**.

**Checked and cleared** (do not spend effort here):

- `/api/command/exec` sync-table stub returning 501 (`linscp-service/src/lib.rs:3223-3230`) is
  **unreachable from every shipped host**, because all three go through `dispatch_async`, whose table
  serves the real handler at `:258` → `exec_cli_command_async` (`:1411`). The stub is defensive only;
  the service test at `:4908` asserts exactly that an error, not a success, comes back.
- Desktop launch exists in both a sync (`:3294`) and an async (`:3717`) form. Not a gap.
- `platform.rs` symbol coverage is complete: `ensure_private_dir`, `set_mode`, `atomic_replace`,
  `open_private_temp_file`, `create_private_file`, `create_exclusive_private_file`,
  `open_regular_file_no_follow`, `create_fifo`, `format_permissions`, `connect_ssh_agent` all exist
  in `linux.rs`, `windows.rs` **and** `android.rs`. The gaps below are *behaviour inside* those
  functions, not missing symbols.

---

## 2. Behavioural parity defects (Tier A) — same build, different result

Each row is a place where a user on one target gets a different outcome from the same action on
another target. Ordered by user impact.

### A1. On Windows, remote-desktop launch can never start `mstsc.exe` — it always writes a ticket file
**Platforms:** Windows ✗, Debian ✓, Android ✓ (by a different route — see below)
**Evidence:** `crates/linscp-platform/src/desktop.rs:104-128` — `detect_desktop_session_kind()` decides
"Wayland / X11 / Headless", and on `#[cfg(not(target_os = "linux"))]` it returns `Headless` whenever
`WAYLAND_DISPLAY` and `DISPLAY` are unset. Neither variable exists on Windows. `launch_remote_desktop`
then takes `if force_file_ticket || is_headless || viewer_bin.is_none()` (`desktop.rs:258-259`), which
writes the `.rdp` ticket and returns `FileTicket`. `resolve_viewer_binary` (`desktop.rs:150-162`) *does*
resolve `System32\mstsc.exe` — it is simply never reached.
**User-visible:** on Windows, "Remote desktop" writes a `.rdp` file into the config directory and the
page reports *"Headless ticket written"*; `mstsc.exe` is never spawned, so the user has to find the file
and double-click it. On Debian the same click opens `xfreerdp3` directly.
**Android is not affected by A1** — the page branches on `caps.platform === 'android'` before reading
the result (`source/gui/web/index.html:4377-4404`) and opens an intent with the ticket's
`local_endpoint`, which `ticket_from_config` populates regardless of the headless branch. The two
platforms fail differently, so do not fix them as one.
**Fix:** on Windows let "a viewer exists" decide: check `resolve_viewer_binary(&ticket).is_some()`
before the headless test, or add a `#[cfg(windows)]` non-headless default. **Effort:** S (~10 lines in
`detect_desktop_session_kind` / `launch_remote_desktop`, plus a unit test in the existing `desktop.rs`
test module).
**Why no test caught it:** `desktop.remote` is `partial` and cites `live-desktop`
(`source/linux/tests/LiveDesktopTest.py`) — a Linux-only suite, cited for `windows` and `android` too.

**Status: fixed.** The decision now lives in `plan_launch` (`desktop.rs`), which takes "may this host
start a viewer" as an input instead of deriving it from `DISPLAY`; `host_can_spawn_gui_viewer()` is
`true` unconditionally on Windows and macOS and follows `linux::detect_desktop_session` on Linux. The
scripting engine's private `DISPLAY` guess is gone (it now asks the platform layer), and the service
carries an explicit `with_desktop_spawn(bool)` that the Tauri desktop host sets and the HTTP host
clears, so the browser transport keeps its `.rdp` ticket. Tests: `plan_launch` truth table, a
`host_gui_capability_matches_the_platform` assertion, a bridge-level check, and a service test that a
host which may not spawn still gets a written ticket. One adjacent defect was found while moving the
code: on Windows the ticket said `mstsc` while `build_rdp_argv` built the **FreeRDP** flag list, so a
spawned `mstsc.exe` would have received `/v:host:port` plus `/u:`, `/bpp:`, `/clipboard`. The ticket
now carries a `desktop_viewer_plan()` (mstsc / macOS `open` / FreeRDP) and name and argv cannot
disagree; macOS also stopped writing an `.rdp` body it had no use for, and Linux stopped claiming one it could
not open. Covered by `the_viewer_name_and_its_arguments_agree` (proto) and
`a_host_that_cannot_show_a_viewer_gets_a_safe_ticket_body` (service). **Not verified here:** no Rust
toolchain in this sandbox, so these are reading-level changes — the Windows CI job is the first real
compile.

### A2. Custom commands can be saved and listed but never run — on every platform
**Platforms:** Windows ✗, Debian ✗, Android ✗ (all three)
**Evidence:** the page's Run button posts `{action:'run'}` (`source/gui/web/index.html:4231-4233`).
The handler answers **unconditionally** `400 "Not connected"`
(`crates/linscp-service/src/lib.rs:3219`) — it never looks at the tab. The function that would do
the work, `ops::execute_custom_command_template` (`crates/linscp-service/src/ops.rs:810` — since
replaced, see the *Status: fixed* note below), has
**no caller anywhere in `crates/`** (verified by `grep -rn`); neither does
`ops::exec_raw_remote_or_local_command` (`ops.rs:872`). So `list`, `save`, `delete` work and `run`
cannot.
**User-visible:** "Run this command on N item(s)?" → confirm → *"Cannot run the command."* The
ledger nevertheless records `gui.explorer-custom-commands` as **verified** on all three platforms,
citing the jsdom suite (which mocks `/api/custom-commands`) and `SecurityTest.py` (which tests the
legacy Python `gui.execute_custom_command`, not this table).
**Fix:** wire `action: 'run'` to `execute_custom_command_template` with the tab and selection.
**Effort:** S.
**Second-order defect that will surface the moment it is wired:** the local branch of both `ops.rs`
functions spawns `Command::new("sh").arg("-c")` with **no `cfg` split** (`ops.rs:837` and
`ops.rs:886`). On Windows there is no `sh`, so "run a local custom command" would fail there while
working on Debian. Fixing A2 without this makes the gap *worse* (a working feature on 2 platforms,
an unexplained failure on the third). Fix both together; the correct pattern already exists in
`terminal.rs:659-672` (`/bin/sh -c` vs `cmd /C`).

**Status: fixed.** The run path exists on all three builds, and the `sh` problem is gone by
deletion rather than by a `cfg` split, because the split would have been the wrong fix. The dialog
has always said a template "is quoted the way the LinSCP command line reads quotes, **never handed
to a shell**" (`index.html:968-971`), and the interpreter that reads that command line already
exists on every build: `checksum`, `chmod`, `edit`, `lls`, `lcd`, `ls`, `call` and the rest are
dispatched by `linscp-engine`. So a template is now expanded and handed to a fresh
`ScriptInterpreter` per file — `ops::execute_custom_command_template`, which finally has a caller —
and nothing interpolated from a file name reaches a process. `exec_raw_remote_or_local_command` was
replaced by `exec_raw_remote_command`, which *only* runs on a remote session shell and refuses a
local one by name, so the two un-cfg'd `Command::new("sh").arg("-c")` sites (`ops.rs:837`,
`ops.rs:886`) no longer exist. `call`/`!` inside a template stays the single, explicit way a
template reaches a shell.

The routing was the other half: `run` was a stub in the **synchronous** table, and the work needs
the async interpreter (it adopts a live session), so `dispatch_async` gained
`POST /api/custom-commands` → `handle_custom_commands_async`; the sync table keeps
`list`/`save`/`delete` and now answers `run` with "needs the asynchronous service entry point"
rather than the misleading "Not connected".

Seven defects surfaced while wiring it, all inside the same gap:

* **The shipped templates were not the dialect the code expanded.** `explorer-commands.json` writes
  `{file}` (all four defaults); `expand_command_template` only understood upstream's bare `!` and its
  `!!`, `!/`, `!@`, `!#`, `!U`, `!S` escapes. Run would have executed `checksum sha-256 {file}`
  literally. `{file}` and `{files}` are now expanded alongside the `!` forms, and a test asserts
  every shipped template starts with a command the interpreter knows and uses a placeholder
  something expands — so a fifth default cannot be added in a dialect nothing reads.
* **Quoting was for the wrong reader.** The old expansion used `shell_quote_single`, which produces
  POSIX `'…'''…'` — correct for a shell, wrong for the LinSCP tokenizer, which *drops* inner
  quotes and treats backslash as an escape (so `'''` came out as `'`). `quote_operand` now quotes
  for that tokenizer and nothing else: a name with a space, a quote or a backslash stays one operand
  and the entry the user selected comes back byte for byte.
* **A hostile name could not fail its own file.** The audit expected "a hostile name fails its file
  and runs the rest", but nothing validated the names first, so a `..` from a stale page would have
  been pasted into the command line. Each name now goes through `validate_leaf_name`, and a name that
  cannot be an entry of a panel gets its own failed result with the reason and the rest of the
  selection still runs.
* **Scope and pane could disagree.** The template says which side it is for; the selection comes from
  whichever pane has focus. A remote `checksum sha-256 keep.txt` run from the local pane would have
  checked a *different file of the same name* on the server and reported success. That is now
  refused by name, on the page before it posts and again in `resolve_command_target` — the backend
  does not trust the page to have checked. A local-only tab still gets its remote-scoped templates:
  they apply to the pane the page draws on the right.
* **Nothing ran once.** With three files selected, a template like the shipped `terminal` (no `{file}`
  at all) would have run three times. Only a template that names the file runs per file.
* **One interpreter, many files.** A single interpreter reused across the selection keeps the `cd`
  of a failed run, so file 2 would run somewhere file 1 left it. Each file gets a fresh interpreter
  started in the pane's own directory.
* **The ledger cited tests that no longer exist.** `gui.explorer-custom-commands` cited seven
  `SecurityTest.py` cases for the *legacy Python* implementation (`gui.execute_custom_command`), which
  is not in `source/gui/linscp_gui.py` at all — `python3 -m unittest tests.SecurityTest` errors with
  `module 'linscp_gui' has no attribute 'quote_remote'`. Those citations are removed rather than
  re-pointed: the behaviour they described is now covered by tests that run against the code that
  ships, and `desktop.shell-and-extensions` had four of the same dead citations removed too.

Evidence: `service-commands` (`ops.rs`: the tokenizer's view of an expanded hostile name, `{files}`
covering the selection, once-against-per-file, a failure and a refused name not stopping the rest,
every shipped template being a real command, the side/pane refusal, and the store the dialog saves
into being the one the run reads), `service` (`lib.rs`: the page's exact payload answered per file,
a name with a space, an unknown name, and the pane mismatch refused), and `gui` (`ClientTest.js`:
the new side-mismatch refusal, plus the run payload carrying the pane). **Not verified here:** still
no Rust toolchain in this sandbox, so the Rust above is reading-level; the CI jobs are the first
compile. The jsdom suite *was* run (`npm --prefix ui test`, 215 checks) and the refusal it asserts
fails without the page change.

### A3. The whole shell-integration feature is unreachable — the shipped binary ignores its arguments
**Platforms:** Windows ✗, Debian ✗, Android n/a
**Evidence:** `crates/linscp-tauri/src/main.rs` is five lines —
`fn main() { linscp_tauri::run_native_app(tauri::generate_context!()); }`. There is **no argv parsing**
anywhere in `crates/linscp-tauri` (`grep -rn "env::args"` → only `linscp-http/src/main.rs:49` and
`terminal.rs:734-811`). `gui_os::install_shell_integration` (`gui_os.rs:352`) and
`uninstall_shell_integration` (`:424`) have **zero callers**. The page and `locales/en.json` contain
no mention of Dolphin, Nautilus, Nemo, "Send To" or `--install-shell-integration` (0 hits), so there
is no UI route either.
**User-visible:** the documented Dolphin/GNOME Files/Nemo "Upload with LinSCP" actions and the Windows
*Send To* shortcut cannot be installed by any shipped artifact. The definitions themselves are
written correctly (`gui_os.rs:357-420`), and the receiving half of the protocol is fully implemented
— `--shell-upload` manifest recording (`ops.rs:1039`), `/api/shell/pending` (`lib.rs:181`),
`/api/shell/consume` (`:255`), and the Android share flow reusing it (`linscp-tauri/src/lib.rs:43-55`).
Only the entry point is missing.
**Note:** `desktop.shell-and-extensions` is marked **verified** on all three platforms. It is not
reachable on any of them. This is the largest single claim/reality gap in the tree.
**Fix:** parse argv in `main.rs` before `run_native_app`: `--install-shell-integration`,
`--uninstall-shell-integration`, `--shell-upload FILES…` (exit before opening a window), and let
`--shell-upload` write the manifest and exit 0. **Effort:** M (the argv surface plus its own tests;
the platform bodies already exist).
**One trap when wiring it:** both integration functions are split `#[cfg(target_os = "windows")]` /
`#[cfg(not(target_os = "windows"))]`, so the "not Windows" arm — which writes Dolphin/KDE, GNOME Files
and Nemo definitions into `$XDG_DATA_HOME` — is also what an **Android** build would compile
(`gui_os.rs:380-420`, `:448-462`, and `#[allow(dead_code)] fn linux_shell_targets` at `:312`). If the
argv entry point is added without tightening those cfgs to `target_os = "linux"`, the first Android
`--install-shell-integration` would try to create XDG directories inside the app sandbox. Keep Android
out of it (n/a is the correct answer there, not an implementation).
**Then:** `docs/native-feature-audit.md` should stop describing this as available, or A3's fix should
land before the next release note.

**Status: fixed.** The argument surface is small enough to be one tested function, so it is:
`crates/linscp-platform/src/cli_args.rs` turns `argv` into an `Action` — `OpenWindow`,
`InstallShellIntegration`, `UninstallShellIntegration`, `ShellUpload(Vec<PathBuf>)` or `Help` — and
carries the usage text that `--help` prints. `crates/linscp-tauri/src/main.rs` now parses before it
does anything else: a bare launch still reaches the single
`run_native_app(tauri::generate_context!())` call, and every action runs, prints and exits **before**
Tauri starts, so a right-click can no longer open a second window. The rule is that anything
unrecognised opens the window (a desktop `Exec=` line and every existing launch path are unchanged);
`--shell-upload` consumes all trailing arguments, flags included; two action flags at once is
contradictory and opens the window rather than picking a winner; `--help` wins because it cannot do
anything. Execution lives in `crates/linscp-service/src/cli_actions.rs` (`ActionOutcome` plus
install / uninstall / `shell_upload_from`), so it is tested without a display: `install` reports each
manager's path and outcome, `uninstall` reports what it found, and a selection either becomes a
manifest the running window already polls for or fails with the reason on stderr and a non-zero exit.

Five things surfaced while wiring it, all inside the same gap:

* **Android could compile the definitions.** `install_shell_integration` /
  `uninstall_shell_integration` branched on `cfg(not(target_os = "windows"))`, so an Android build
  would have created `$XDG_DATA_HOME` directories inside the app sandbox for menus that do not exist
  there. Both are now `linux` / `windows` / refuse-by-name, `linux_shell_targets` is `linux`-only,
  and Android keeps its share hand-off (the same manifest contract).
* **The Windows path would have been refused.** `validate_shell_launcher_path` rejected a backslash,
  a dollar sign, `;`, `&`, `%`, a single quote and a double quote on every platform — which rejects
  the ordinary install location, whose path contains both a space and a backslash. Each definition
  now refuses only what its own quoting cannot carry, and a launcher path with a space is quoted
  rather than rejected.
* **GNOME Files never passes `"$@"`.** The generated script only read the selection from its
  arguments, but GNOME Files sets `NAUTILUS_SCRIPT_SELECTED_FILE_PATHS` (one path per line) and passes
  nothing. The script now reads the variable, splits on newlines with `set -f` so a `*` in a name
  stays literal, and hands the whole selection over in one call; the argv branch remains for the
  versions that do pass arguments.
* **A `windows_subsystem = "windows"` build says nothing.** The release GUI has no
  console, so `println!` in an action run from a terminal goes nowhere and the user
  who typed `linscp-gui --shell-upload …` learns nothing. The process now attaches to
  its parent's console (`AttachConsole(ATTACH_PARENT_PROCESS)`) and writes to
  `CONOUT$` rather than to a `stdout` nobody inherited — attaching alone is not enough,
  because the inherited handle still points at nothing.
* **The Explorer shortcut's `%*` is left alone.** `%*` re-reads the line through `cmd`, so an
  unquoted name containing `&` is still a hazard; wrapping it as `"%*"` was tried and rejected,
  because that collapses a multi-file selection into one argument (the C runtime strips the inner
  quotes and keeps the spaces). One argument per selected file is the contract the parser is tested
  against, so the shortcut keeps `%*` and the residual `&` case is documented rather than traded for
  a worse one.

Evidence: `gui-cli` (`cli_args.rs`, seven cases: the bare-launch default, the three action flags,
`--help`, a whole selection taken verbatim with each file its own argument, an empty selection, and
two action flags at once), `gui-shell-definitions` (`gui_os.rs`, four cases: quoting a path with a
space, the generated script's shape and executable bit plus `sh -n`, refusal by name, and an
uninstall that removes exactly what install wrote), `gui-shell-actions` (`cli_actions.rs`: a selection
becomes the manifest the window reads, a relative path resolves against the directory it was named in,
an empty or vanished selection is refused out loud, and an install that cannot be carried out reports
the reason), and `gui-shell` / `gui` for the receiving half that was already there. Because a unit test of a parser
is weak evidence that a *shipped binary* runs it, both desktop CI jobs now drive the installed
`linscp-gui`: Debian installs into a scratch `XDG_DATA_HOME`, runs the GNOME Files script the way
GNOME Files runs it with two awkward names, stages a selection and uninstalls; Windows redirects
`APPDATA`, checks the Send To `.cmd`, runs it on a file and reads the manifest back. The parity gate
learned three suites for this (`gui-cli`, `gui-shell-definitions`, `gui-shell-actions`), so
`desktop.shell-and-extensions` now cites evidence that can fail. **Not verified here:** still no Rust
toolchain in this sandbox — nothing above has been compiled; the Debian job is the first real check.

### A4. Local symlink creation has no local implementation
**Platforms:** all three (the feature exists only for a *remote* pane)
**Evidence:** the page only offers the remote form (`source/gui/web/index.html:5154-5175`,
`promptRemoteLink`). If a local tab reaches the endpoint, `link_remote_async`
(`crates/linscp-service/src/lib.rs:806`) sends `tab.is_local` to `handle_remote_link` (`:811`), which
is a hard `501 "A symbolic link needs an SFTP session."` (declared `:3162`).
`gui_os::create_local_symlink` (`gui_os.rs:131`, correct `std::os::unix::fs::symlink` +
Windows dir/file probe) has exactly one caller: the local-copy queue's symlink preservation
(`queue.rs:1220`). So a symlink can be *copied* but never *created* locally, on any build.
**Fix:** a local branch in `link_remote_async` that calls `create_local_symlink` after
`resolve_contained`, and a local variant of the page dialog. **Effort:** S.

**Status: fixed.** Both local panes can create symbolic links now: the other pane of a local tab
goes through a new local branch in `link_remote_async`, and the main pane through a new
`/api/local/link` endpoint (`handle_local_link`); both share one helper, `create_local_link`,
which validates two different single-leaf names, refuses a taken link name, and calls the
previously copy-only `gui_os::create_local_symlink` after `resolve_contained`. The page dialog is
one pane-aware `promptLink(side)` — the Local menu offers it for the local pane, the Commands menu
keeps offering it for the remote pane — reusing the remote form's strings, so no locale changes
were needed. Second-order, same commit: a granted folder is refused by the shared app-storage
message in both layers (a new bundle `symlink` action), since links cannot point into a
`content://` tree. Ledger row `gui.local-symlink` is `partial`: creation is proven on Unix, while
Windows creation needs a symlink privilege the suite cannot grant itself and Android runs no Rust
tests. Reading-level for the Rust, as usual: CI compiles it first.

### A5. Vault is password-only on every build; the two hardware-backed wrappers are dead code
**Platforms:** Windows ✗ (no DPAPI), Android ✗ (no Keystore), Debian n/a (no equivalent)
**Evidence:** `NativeSecretVault::with_windows_dpapi` (`linscp-platform/src/lib.rs:723`) and
`with_android_keystore` (`:730`) have **zero call sites**; `AndroidState::set_keystore`
(`linscp-tauri/src/android.rs:54`) has **zero call sites** and `LinSCPAndroidPlugin.kt` has **no
keystore `@Command`** (the 16 commands are SAF/share/external-uri/foreground only), so
`wrap_key` always fails with *"Android Keystore bridge not registered"*.
`decode_stored_master_key` (`lib.rs:737-791`) still accepts the dead `dpapi1$` and `aks1$` prefixes
and produces a clear error for them, i.e. the read path exists and the write path never ran.
**What actually protects `sessions.key` on all three builds:** `LSCPVLT1` — AES-256-GCM under an
Argon2id key from `PasswordSecretVault::unlock_or_setup`
(`crates/linscp-service/src/lib.rs:1696`). That is real and uniform.
**User-visible:** on Windows and Android the master key is only password-protected; there is no
"unlock with Windows Hello / device credential" behaviour that the docs suggest.
**Docs contradicting the tree:** `docs/cross-platform-rust-migration.md:181,202,287` describe
DPAPI/Keystore as implemented; `docs/android.md:20-21` correctly admits Keystore is unwired. Keep the
`android.md` wording, fix the other two.
**Fix:** either wire both (Windows: `CryptProtectData` is already written in `windows.rs`, just needs
`with_windows_dpapi()` called at vault construction; Android needs a new Kotlin `wrapKey`/`unwrapKey`
command plus `set_keystore`), or delete the dead surface and correct the docs. **Effort:** M (Android
side is the real work) / S (delete-and-document).

**Status: fixed** via the audit's S fallback: delete-and-document. Recon showed the wrappers were
doubly dead — beyond the zero call sites, the only consumer of the DPAPI flag
(`NativeSecretVault::load_or_create_master_key`) never runs in production, because the service
passes the password vault everywhere and uses the native vault only as a migration source. Calling
the constructors would have changed nothing observable, so real wiring would have meant designing
passwordless unlock as a product feature instead. Removed: both constructors, the decoder and
creation branches, the Windows DPAPI functions (plus the `Win32_Security_Cryptography` feature),
the `KeystoreBridge` trait, the Tauri keystore state, and the stale backup and migration-guide
claims, which now say the wrapping was removed or descoped; `android.md`'s honest wording stands.
Ledger row `sessions.vault-password-only` is `partial`: the `LSCPVLT1` round-trip and the new
retired-prefix rejection test run on Linux and Windows CI, while Android runs no Rust tests.
Reading-level for the Rust, as usual: CI compiles it first.

### A6. On Windows the configuration directory is created without an owner-only DACL
**Platforms:** Windows ✗
**Evidence:** `crates/linscp-platform/src/windows.rs:112-115` —
`ensure_private_dir` is `create_dir_all()` and nothing else. It is the function that guards the
config root and the upload staging area (`linscp-platform/src/lib.rs:628`, `:677`).
`docs/cross-platform-rust-migration.md:181` claims an explicit `D:P(A;;FA;;;OW)` DACL there.
`grep -rn "DACL\|SetNamedSecurityInfo\|SDDL"` over `crates/` → **no hits**. Linux applies `0700`
(`linux.rs:81-86`); Android applies `0700` (`android.rs:131`). Windows inherits `%APPDATA%`'s ACL.
**User-visible:** on a shared Windows machine, `%APPDATA%\LinSCP` (sessions, host keys, manifests,
custom commands) is readable by any account that can traverse the profile — a genuine
cross-user confidentiality difference, not a theoretical one. `sessions.ini` and host keys are the
payload.
**Fix:** create the directory, then apply the owner-only DACL with `SetNamedSecurityInfoW` /
`SetFileSecurityW`, or set it via a `SECURITY_ATTRIBUTES` with
`ConvertStringSecurityDescriptorToSecurityDescriptorW`. **Cost note:** `crates/linscp-platform/Cargo.toml:26-33`
enables only `Win32_Foundation`, `Win32_Security_Cryptography`, `Win32_Storage_FileSystem`,
`Win32_System_Console`, `Win32_System_Threading` — the authorization/SDDL features must be **added**,
so this is not a one-liner. **Effort:** S–M.
**Why no test caught it:** the two tests in `windows.rs` (`:322`, `:331`) do not touch permissions,
and `windows-build.yml:42` runs `cargo test --workspace` on a single-user runner where the difference
is invisible.

**Status: fixed.** `ensure_private_dir` on Windows is no longer a bare `create_dir_all`: after
creating the directory it calls the new `apply_owner_only_dacl`, which parses
`D:P(A;OICI;FA;;;OW)` with `ConvertStringSecurityDescriptorToSecurityDescriptorW` and installs the
resulting DACL with `SetNamedSecurityInfoW` (`SE_FILE_OBJECT`, `DACL_SECURITY_INFORMATION`, owner /
group / SACL untouched). The `windows-sys` features the audit's cost note predicted —
`Win32_Security` and `Win32_Security_Authorization` — are added in
`crates/linscp-platform/Cargo.toml`. The string differs from the documented `D:P(A;;FA;;;OW)` by the
`OICI` inherit flags on purpose, and the document now says so: `SeChangeNotifyPrivilege` (bypass
traverse checking) is held by everyone, so a file reached by direct path is governed by *its* DACL,
not the directory's — without inheritance the lock would cover the directory listing while leaving
`sessions.ini` itself readable. Children created inside therefore carry their own owner-only ACE,
which is also what makes `create_private_file`'s "only the current user may read" comment true for
everything under the config root. The small integer constants (`SE_FILE_OBJECT`,
`DACL_SECURITY_INFORMATION`, `SDDL_REVISION_1`, the ACE bits) are local literals with SDK citations
rather than bindings paths, so the applied DACL can be verified by reading.

The DACL is applied on *every* call, not just on creation, so a config directory written before this
fix is locked down on next use; failures fail closed (an error, never a silently shared directory),
matching Linux, where a `chmod` failure propagates. Three second-order defects went with it, all in
the same payload class: the editor staging directory and the shell-manifests directory in
`crates/linscp-service/src/ops.rs` were created with bare `create_dir_all` — the read-path staging
dir never even got a follow-up write that would have locked it — and all three now go through
`create_private_dir`, the same call the `keys/` and `tmp/unlocked-keys/` paths already used; and
`docs/cross-platform-rust-migration.md:181` claimed a DACL the code never applied, which is now true
with the `OICI` reason recorded. Deliberately *not* changed: `create_exclusive_private_file` still
creates user-chosen parents without locking them (re-ACLing a directory the user named would be
wrong — only configuration paths go through `ensure_private_dir`), and pre-existing children keep
their old DACLs, exactly as `chmod` does not recurse on Linux.

Evidence: `platform-windows-acl` (`windows.rs`: a pre-created directory ends up with exactly one
ACE — allow, full-access mask, `OI|CI` flags — a child created inside inherits exactly that ACE, and
a second application changes nothing), cited from `sessions.password-at-rest` for Windows, the row
whose files the DACL protects. The tests read the ACL back with `GetNamedSecurityInfoW` instead of
trusting the call that set it, which answers the audit's "invisible on a single-user runner": an
inherited DACL has several ACEs even for one user, so the count assertion fails pre-fix and passes
post-fix. **Not verified here:** still no Rust toolchain in this sandbox — the FFI signatures, the
new `windows-sys` features and both tests are reading-level; the Windows CI job is the first compile.

### A7. On Android a granted SAF folder supports browsing and create/rename/delete, but not editing, properties, chmod, sync, keep-up-to-date, transfers or copy/move
**Platforms:** Android ✗ (desktop ✓)
**Evidence — the boundary is exactly `LocalFs` vs `std::fs`:**
- SAF-aware, i.e. works on a granted tree: **list**, **new folder**, **delete**, **rename**
  (`handle_local_list`/`_mkdir`/`_delete`/`_rename` all go through `self.local_fs`, `lib.rs:1764`,
  `:2202`, `:2218-2219`, `:2240`) and the drop path (`:2541`). `LocalFs`'s own methods branch on
  `content://` (`linscp-platform/src/lib.rs:446-540`); `resolve_contained` and
  `check_local_pane_directory` have explicit SAF branches (`lib.rs:4608-4611`, `:4785-4788`).
- **Also broken on SAF, and easy to miss because it looks like plain file I/O:** opening or saving a
  file in the built-in editor. `handle_local_edit_get`/`handle_local_save` (`lib.rs:1779`, `:2308`)
  call `ops::read_local_text_file`/`write_local_text_file` (`ops.rs:69`, `:101`), which start with
  `stat_extended(...)` — `std::fs` (`gui_os.rs:51-57`). Properties (`gui_os::stat_extended` at
  `lib.rs:3140`) and `chmod` (`:2292-2294`, `:3113-3121`) take the same bypass. For `chmod` the result
  is worse than a generic failure: the user gets a raw I/O error instead of the message
  `LocalFs::set_permissions_mode` was written to give (`linscp-platform/src/lib.rs:586-590`,
  *"POSIX permissions do not exist on a granted Android folder."*) — and that method has **no caller**
  outside its own test (`:1030`), so the correct message is currently unreachable.
- Not SAF-aware (fails): `SyncOptions` requires `Path::new(&local_root).is_absolute()`
  (`lib.rs:726`, `:1046`) — a `content://` URI is **not** absolute, so `/api/sync/preview`,
  `/api/sync/run` and `/api/transfer/keepuptodate` all answer `400 "An absolute local directory is
  required."` even for a legitimately granted tree; `sync_run_async` additionally requires
  `local_root.is_dir()` (`:1103`); the planner walks with `std::fs::read_dir`
  (`linscp-engine/src/sync_planner.rs:401`); uploads open with `std::fs::File::open`
  (`linscp-engine/src/transfer.rs:990`) and downloads write with `std::fs`
  (`transfer.rs:515-561`); local copy/move walks `std::fs` (`linscp-service/src/queue.rs:1190-1240`).
- Why the editor/save failure is *silent* rather than loud: `write_local_text_file` starts with
  `let existing = stat_extended(path).ok();` (`ops.rs:109`). On a `content://` string `std::fs`
  returns `NotFound`, so `.ok()` yields `None` and the function treats it as a **new** file and goes on
  to create a temp file and rename onto a "path" that is not a pathname. The user sees either a
  confusing error or a write that does not land in the granted folder — never "granted folders cannot
  be edited here". (Per the `std::path` docs `PathBuf::push` does not normalise separators, so the
  `content://` prefix should survive this path; I could not run it here, and it is worth one assertion
  in a unit test before relying on it. The defect is `std::fs`, not normalisation.)

**User-visible:** on Android, a folder the user picked with the system picker can be browsed, and
files can be created, renamed and deleted — but **opening one in the editor**, **properties**,
**chmod**, **Synchronize**, **Keep up to date**, **uploading/downloading out of it** and
**copy/move inside it** all fail, while every one of those works on the same folder on Debian.
**Fix:** two options. (a) Route the transfer and sync trees through `LocalFs` (large, touches
`linscp-engine`). (b) Fail closed with a message that names the limitation ("Sync needs a folder in
app storage, not a granted folder"), and stop *offering* those actions for SAF roots in the page via
`hostCapabilities`. (b) is honest and small; (a) is the real parity fix. **Effort:** S (b) / L (a).
**Ledger status:** `sync.*` and `transfer.*` rows are `verified` on all three platforms and cite
`live-sftp` / `live-dav` — Linux-only suites. Nothing records this boundary.

**Status: fixed** (option (b), the honest refusal; the full `LocalFs` routing stays a separate
decision). Every action of the audit's list now fails closed with a message that names the
limitation, from one helper (`saf_unsupported` in `crates/linscp-service/src/lib.rs`): editing and
saving (`handle_local_edit_get`, `handle_local_save`, plus the other pane's `handle_remote_edit_get`
and `remote_save_async`), properties (a per-row refusal in `handle_remote_properties`, so the
dialogue shows the reason beside the name), synchronization preview and run plus keep-up-to-date
(one shared directory check, `check_plain_local_dir`, used by `sync_options_from` and
`keep_up_to_date_async`), and transfers with local copy/move (both ends checked in
`queue_transfer_async`, with the message naming the transfer, the copy or the move). `chmod` is
routed through the bridge's own `LocalFs::set_permissions_mode`, so the audit's unreachable message
(*"POSIX permissions do not exist on a granted Android folder."*) is now the refusal both panes
return; the method finally has callers outside its test. The page stops offering all of these for
granted folders through the shared bundle (`safLimitationReason` in
`ui/src/platform/capabilities.ts`, next to `hostCapabilities`): the editor, the synchronize and
keep-up-to-date dialogues, transfers, moves, the permissions prompt and the properties rights editor
each show the bundle's reason instead of a control that could only fail. The boundary the audit
found unrecorded is now ledger row `platform.android-saf-refusals` = `verified`, evidenced by four
service tests, one bundle test and eight page checks; Android cites the tests that run there
(`ui-transport`, `gui`) and not the Rust suite, which executes nothing in the Android job.

Two things this deliberately did not do. The other pane of a local tab still cannot edit or save
plain (non-granted) paths — the page sends joined paths where the handlers resolve leaves, so those
fail as before with a path error; only granted other panes changed, from that error to the named
refusal. And the bridge already reads and writes document bytes (`read_bytes`,
`write_bytes_atomic`), which a future option (a) could build the editor on; this fix only refuses.
Both are reading-level claims: no Rust toolchain here, so the new tests compile for the first time
in CI.

### A8. Kerberos/GSSAPI exists only on Linux; Windows has no SSPI backend at all
**Platforms:** Windows ✗, Android ✗ (fail closed), Debian ✓
**Evidence:** `crates/linscp-platform/src/gssapi_sys.rs` is `#[cfg(target_os = "linux")]` for the
whole dlopen path (`:27`, `:31`, `:42`, `:47`, `:54`); engine refuses rather than silently downgrades
(`linscp-engine/src/url_and_raw.rs:811,824,1390,1817-1829`).
`docs/cross-platform-rust-migration.md:96` names an "optional `sspi` crate (or `secur32.dll`)"
integration — `grep -rn sspi Cargo.toml crates/*/Cargo.toml` → **no dependency**.
**User-visible:** an Active Directory environment — the *normal* Windows case — cannot authenticate
with Kerberos through LinSCP on Windows, while the same site works from Debian. This is the single
most Windows-specific functionality gap.
**Status:** already tracked as `security.gssapi-and-tunnels` = `partial`, with **linux-only**
`verified_on` (the only four rows in the ledger that are honest about being Linux-only — see §3).
**Fix:** the SSPI work, or leave it partial and say "Linux only" in the site manager.
**Effort:** L (a real SSPI context provider, not a wrapper).

### A9. SSH agent: two of three builds have one, Android has a hard `None`
**Platforms:** Android ✗
**Evidence:** `linscp-platform/src/android.rs:257-259` — `connect_ssh_agent` is `Ok(None)`.
Linux uses `SSH_AUTH_SOCK` (`linux.rs:179`), Windows the
`\\.\pipe\openssh-ssh-agent` named pipe (`windows.rs:231-233`).
**User-visible:** a site configured for agent authentication works on Debian and Windows and fails on
Android with the generic "no key" path. On Android this is arguably correct (no agent exists on a
stock device), so the parity fix is not a bridge but a **clearer refusal** naming the platform —
right now the user is told nothing about *why*.
**Effort:** S (message + a capability flag), or leave as documented behaviour.

**Status: fixed.** The refusal now names the platform in both layers. The backend's auth chain
asks the connector for a `missing_reason` when its stream comes back empty: `SshAgentConnector`
gains a defaulted method, the system connector answers with a platform reason
(`SSH_AGENT_MISSING_MESSAGE` on Android, none where the build probes for a socket), and the reason
becomes the terminal error instead of the generic auth failure. The site dialog shows the same
story up front through a hint wired to a new bundle `sshAgent` flag via a `hostGap`-style helper,
failing open for non-Android hosts because the page cannot see the server OS. Ledger row
`security.agent-android-refusal` is `partial`: the Android-Rust arm runs in no step, so message
selection on device is review-level until an emulator run attempts agent auth. Reading-level for
the Rust, as usual: CI compiles it first.

---

## 3. Evidence parity (Tier B) — the "verified on all three" claim does not survive inspection

This is the part that matters most for "make sure we have parity", because without it nobody can tell
whether §2 is complete.

`docs/upstream-parity.json` holds 109 capabilities. 100 are `verified`; the
`verification.policy` says a `verified` row must name suites that ran on `linux`, `windows` **and**
`android`. `python3 tools/check_upstream_parity.py` passes (exit 0) and reports
`android: 164, linux: 170, windows: 164` evidence citations.

**B1. The platform suite lists are identical by construction, not by measurement.**
All three platforms list the **same 24 suites**, and **101 of 109** capabilities carry the *identical*
linux/windows/android triple. Only four differ, and all four are missing `windows`+`android`:
`security.gssapi-and-tunnels`, `gui.native-path-drop`, `locale.translations`, `gui.remote-delete`.
A `unit` suite cited for Android, and a Wayland-compatibility suite cited for Windows, are not things
that happened; they are the same list copied. Real per-platform evidence cannot be identical for
`desktop.wayland-session` on Windows.

**B2. The checker never validates the Windows or Android citations.**
`tools/check_upstream_parity.py:257` reads `row.get("verified_on", {}).get("linux", [])` and compares
*that* with `checks`. The `windows` and `android` lists are only checked against the platform's own
suite whitelist (`:170-181`), never against the cited test cases. So an entry can name a suite for
Windows that does not contain the test it cites, and the gate is silent. Also
`check_upstream_parity.py` itself **is not run by any workflow** (`grep` over `.github/workflows/` →
absent), nor is `test_parity_inventory.py`, `test_platform_conversion.py`,
`test_wayland_compatibility.py`, `test_translations.py` or `test_repo_hygiene.py`. CI runs exactly
four `tools/tests` files: `test_android_application_id.py`, `test_android_release_signing.py`
(android-build.yml:39-40), `test_gui_distribution.py`, `test_workflow_triggers.py`
(debian-build.yml:38,45).

**B3. What each cited suite can actually do today.**

| Suite (cited by N caps) | Runs in CI? | Runs here? | Truth |
|---|---|---|---|
| `gui` (ClientTest.js) — 77 | **yes**, all 3 workflows (`npm --prefix ui test` → `node ../source/gui/tests/ClientTest.js dist/index.html`) | passes (part of `ui && npm test`, exit 0) | jsdom against the built page. Real, but it mocks `fetch` — it cannot see a platform. |
| `gui-localization` (LocalizationTest.js) — ≤6 | **yes**, same command | passes | as above |
| `service` (Rust tests in `linscp-service/src/lib.rs`) — 3 | linux: yes (`debian/rules:14` `cargo test --workspace --all-targets`), windows: yes (`windows-build.yml:42`), **android: no** | not run (no toolchain) | the only suite that tests the shared dispatch; genuinely runs on 2 of 3 platforms |
| `service-commands` (Rust tests in `linscp-service/src/ops.rs`, added with A2) | same two workflows, same gap | not run (no toolchain) | `ops.rs` already had no `#[cfg(test)]` module, so this suite is new; Android still runs no Rust test |
| `unit` (UnitTest.cpp) — 101 | **no** | no | no build target: `CMakeLists.txt:3` is `project(LinSCP VERSION 1.0 LANGUAGES NONE)`, `source/linux/Makefile` builds only cargo. It also needs `<libssh/libssh.h>` and `PathUtil.h` (neither vendored). Cited more than any other file in the repo and cannot be compiled. |
| `script`, `live-sftp`, `live-scp`, `live-s3`, `live-dav`, `live-curl`, `live-tunnel`, `live-desktop` — 8 suites, cited by most transfer/protocol rows | **no** | no | all argv-driven: `BINARY = str(pathlib.Path(sys.argv.pop(1)).resolve())` (e.g. `ScriptTest.py:17`). There is **no `linscp` binary** — `crates/linscp-cli` does not exist and `tools/tests/test_gui_distribution.py:13-14` *forbids* it. `linscp-gui` parses no arguments (A3). `LiveDesktopTest.py:188` runs `[$BINARY, "--serve-http", …]`, which nothing accepts (`linscp-web` takes `--port/--print-token/--bind/--allow-host/--allow-remote`, `linscp-http/src/main.rs:52-77`). |
| `gui-security`, `gui-local`, `gui-search`, `gui-browser-upload`, `gui-local-editor`, `gui-desktop-uri`, `gui-shell` — 7 Python suites | **no** | **fail en masse** (measured) | they import `source/gui/linscp_gui.py`, a 116-line docstring shim exporting four helpers and nothing else. Measured: `ShellIntegrationTest` 12 run / 12 failed; `LocalWorkspaceTest` 26 run / 26 errors + 8 skipped (`module 'linscp_gui' has no attribute validate_workspace_name`); `SecurityTest` 124 run / 123 failed. **All three exit 0 anyway**, and each prints `evidence: suite=… platform=linux ran=N failed=N` — a line that reads like evidence regardless of the numbers. |
| `platform-conversion`, `wayland-compatibility`, `translation-tests`, `backup` | **no** | **pass** (exit 0) | real, but Linux-shaped checks of repo state; `wayland-compatibility` cannot mean anything on Windows |
| `ui-transport` (TransportAndPlatform.test.mjs) | **yes**, all 3 (`npm test`) | passes | real, host-agnostic unit tests of the bundle |
| `powershell`, `dotnet` | — | — | `automation/test_psmodule.py` and `automation/test_dotnet.py` **do not exist**. No capability cites them (both rows are `missing`), so the checker stays quiet. |

**Net effect:** of 24 suites cited for every platform, **3 run on all three** (`gui`,
`gui-localization`, `ui-transport` — all via `npm --prefix ui test`), **1 runs on two** (`service`:
Debian via `debian/rules:14`, Windows via `windows-build.yml:42`, not Android), **1 is
unreproducible by construction** (`unit`), **3 are green but Linux-shaped**
(`platform-conversion`, `wayland-compatibility`, `translation-tests`; `backup` is a Rust test file, so
it rides with `service`), **8 need a binary that does not exist** (`script` + the seven `live-*`),
and **7 are currently red** (the Python `gui-*` suites). Android executes **no Rust test
whatsoever** — `android-build.yml` runs `npm run tauri -- android build` (a compile+package check),
`verify_android_apk.py`, and an emulator smoke script; `grep -n cargo .github/workflows/android-build.yml`
shows only the tauri wrapper.

**B4. The reproduce lines in the generated inventory are unrunnable.**
`docs/linux-feature-inventory.md:342` says *"`cargo run -p linscp-cli --release` drives ScriptTest.py …
evidence lines … are emitted as CI annotations on Linux, Windows and Android"*, and `:370` repeats it
for Windows. There is no `linscp-cli`, no `--serve-http`, and no workflow that runs any
`source/*/tests/*.py`. The same text is embedded three times in `docs/upstream-parity.json`
(`verification.platforms.*.how`), including for **android**, whose `how` claims an NDK cross-check on
a *Linux runner*.

**B5. One stale structural claim in the watcher.**
`crates/linscp-platform/src/watcher.rs:1-3` says Android uses `PollWatcher`, "inotify on Linux,
`ReadDirectoryChangesW` on Windows". `notify` 6.1.1 selects `INotifyWatcher` for
`any(target_os = "linux", target_os = "android")`
(`notify/src/lib.rs`, `RecommendedWatcher` cfg). The code is right either way (`RecommendedWatcher`
is used), but the comment would mislead the next person testing Android; and `sync.keepuptodate-inotify`
is `verified` on Android where keep-up-to-date cannot start at all (A7).

**Status: triaged.** Every suite the audit found unrunnable is now flagged `not_runnable`, per
platform, in `docs/upstream-parity.json` — 16 on Linux, 20 on Windows, 25 on Android — each with the
reason it executes nothing there, and the generated registry renders the flag next to the suite, so a
reader of the inventory meets the boundary where the citation used to be. The checker enforces what
the flags say: a `verified` entry may not cite a suite that does not run on the citing platform, and
every platform's citations are validated against the row's named cases the way only Linux was —
`verified_on.<platform>` must name only checked suites, and every checked suite must be cited by at
least one platform. That rule is deliberately subsets, not the strict equality the audit's §5.4
sentence could be read as asking for: strict equality would force the ledger to cite a Wayland guard
for Windows or to throw away the Rust suites that genuinely run on two jobs, and the A3 row had
already anticipated subsets by omitting its Linux-only suite from the other two platforms. Partial
rows are exempt from the runnable rule on purpose — naming the cases that *would* cover them is how
the ledger records the way back — and all 74 downgraded capabilities keep their cases and citations
intact for exactly that reason.

The numbers changed the way the audit said they would: 28 of 176 entries are verified now (26
capabilities, the `synchronize` command, the `terminal` addition), down from 162, and every one of
the 28 cites only suites that run where they are cited. All 15 feature areas are `partial`, each with
a gap naming its downgraded capabilities. The three reproduce lines were rewritten from the workflows
that actually run — no `linscp-cli`, no `--serve-http` — and the evidence criterion is now an exit-0
run with `failed=0`, not the `ran>0` the old lines accepted.

Two corrections to the audit as written. First, the exit-0 claim was a mis-measurement: re-run on
this tree, all seven Python GUI suites exit non-zero on failure (`sys.exit(0 if
result.wasSuccessful() else 1)` was already at every `__main__` block, including at `80c6bef`), with
measured counts from 5/5 to 123-of-124 red. The defect that survived into the ledger was never the
exit code — it was the `ran>0` criterion treating a failing run as evidence, which the rewritten
`how` lines fix. Second, the `service` suite's Android description and both A3 Android descriptions
claimed execution the Android job never performs (`cargo test` runs in no Android step; the emulator
smoke drives the dispatch path without running the Rust cases) — rewritten to state the boundary.

Second-order defects fixed in the same commit: the A3 row's `verified` citations of five red
`gui-shell` cases (dropped from `checks`, the case names preserved in the row's notes for re-citing);
`gui-shell-definitions` silently absent from the Windows and Android suite maps (added, flagged, with
the `#[cfg(target_os = "linux")]` reason a Windows `cargo test` run executes none of its cases);
`backup.full-export-import`, `desktop.wayland-session` and `platform.conversion-completeness` verified
on platforms with no runnable evidence for them (now partial, each naming its runnable residue —
backup on Linux and Windows, the other two on Linux only); B5's watcher comment (it now follows the
code, which uses `RecommendedWatcher` on every target, instead of naming backends per OS); and B2's
silent gate — `check_upstream_parity.py` plus `test_parity_inventory.py`,
`test_platform_conversion.py`, `test_wayland_compatibility.py`, `test_translations.py` and
`test_repo_hygiene.py` now run in the Debian job, all pure-Python repo-state checks that pass here.
Evidence: `tools/tests/test_parity_inventory.py` grew five cases (verified-cannot-cite-unrunnable
with the partial exemption, dangling-flag and missing-reason rejection, per-platform subset
validation in both directions, a whole-ledger runnable-citation invariant, and registry rendering of
all 61 flags) — 23 tests, all passing — and both generated reports were regenerated from the ledger.
What triage does *not* do is repair anything it flags: the live, script, unit and Python GUI suites
are still unrunnable, Android still executes no Rust test (that is why the backup row is partial and
why the A2/A3 rows cite only `gui` on Android), and there is still no platform-scoped `verified`
state for genuinely Linux-only behavior such as the Wayland session — the downgraded rows' acceptance
criteria name all three as the way back.

---

## 4. Platform integrations that need a real device before anyone can claim them

These are not defects — they are claims with no acceptance evidence, which is the second half of the
audit's bar (`docs/native-feature-audit.md`: "each platform-specific integration needs real-device
evidence").

| Integration | Implemented? | Evidence today |
|---|---|---|
| SAF picker + persisted grants | yes (`LinSCPAndroidPlugin.kt:pickTree/grantedTrees`, `android.rs` traits) | emulator smoke lists only app-private storage; no granted-tree run |
| Share intents (`ACTION_SEND`/`SEND_MULTIPLE`) | yes (`stageUris`, `takePendingShares`) | intent filter is added by `tools/prepare_android_project.py:8-51` to a *generated* manifest — nothing in this tree can be inspected as the shipped filter; no test drives a real share |
| Foreground service | yes (`LinSCPTransferService`, `foregroundStart/Update/Stop`) | smoke starts/updates/stops it; nobody verifies a transfer *survives backgrounding* |
| `POST_NOTIFICATIONS` (Android 13+) | yes, requested at first queue (`LinSCPAndroidPlugin.kt:233-235`) | smoke pre-grants it via `pm grant` "to avoid an interactive prompt" (`tools/android_emulator_smoke.sh`), i.e. the request path is deliberately never exercised |
| Keystore | **no** (A5) | — |
| Android application ID | `com.fairuniversal.linscp`, read from `tools/android_application_id.py`, asserted in `test_android_application_id.py:23` | consistent: `tauri.conf.json:5`, the Kotlin `package`, and `register_android_plugin("com.fairuniversal.linscp", …)` (`android.rs:331`). The Rust literal is *not* in the "defined once" list (`test_android_application_id.py` readers list only shell/mjs/py), so a rename in `tauri.conf.json` would leave a silent mismatch in `android.rs:331` — worth adding to that test's reader list. |
| Keep-up-to-date over SAF | **no**, refused by name (A7(b) done) | `platform.android-saf-refusals` is `verified`; the refusal — not a run — is what is evidenced |
| Windows file-drop into the window | yes (`linscp-tauri/src/lib.rs:209-224`) | `gui.native-path-drop` is `partial` and its own note admits jsdom cannot produce a WebKit drop |

---

## 5. What I would fix, in order

Ordered by (user impact × confidence) ÷ effort. All are small except where noted.

1. **A1 Windows remote desktop** — 10 lines, restores a documented feature on one platform, and it is
   provable with a unit test on the existing `desktop.rs` test module. *S*
2. **A3 argv + shell integration** — reintroduces an entire documented feature on Debian and Windows,
   and is a prerequisite for ever running the `gui-shell` / `--shell-upload` cases the ledger already
   cites. *M*
3. **A2 custom-command run (+ the `sh` hardcode in the same commit)** — one action that is broken
   today on all three builds. *S* — **done**, see A2's *Status: fixed*: the shell was removed rather
   than `cfg`-split, seven second-order defects went with it, and the seven dead `SecurityTest.py`
   citations were removed from two ledger rows.
4. **B-suite triage**: mark `unit`, all `live-*`, `script`, and the 7 Python `gui-*` suites as
   **not runnable** in `docs/upstream-parity.json` (they are not evidence), and make
   `check_upstream_parity.py` validate `windows`/`android` against `checks` the way it already
   validates linux. This is the change that makes every other number in the ledger mean something.
   *S, high leverage.* — **done**, see the *Status: triaged* note at the end of §3: per-platform
   flags with reasons, subset validation on every platform plus a runnable rule for `verified`,
   rewritten reproduce lines with a `failed=0` evidence criterion, the checker and five repo-state
   suites wired into the Debian job, and 28 of 176 entries left verified. The audit's exit-0 claim
   about the Python GUI suites was a mis-measurement (all seven exit non-zero; the `ran>0`
   criterion was the real defect).
5. **A6 Windows DACL** — a real confidentiality difference on shared machines. *S–M* — **done**,
   see A6's *Status: fixed*: `D:P(A;OICI;FA;;;OW)` via `SetNamedSecurityInfoW` on every
   `ensure_private_dir` call, the `OICI` flags justified by bypass-traverse-checking, the editor and
   manifest staging directories routed through `create_private_dir`, and read-back tests that fail
   on an inherited DACL even for a single user.
6. **A7 (b) honest refusal for SAF roots** — stop offering sync/keep-up-to-date on a granted folder
   and say why. *S*; the full `LocalFs` routing is *L* and should be a separate decision. —
   **done**, see A7's *Status: fixed*: one shared refusal for edit/save/properties/sync/watch/
   transfer/copy/move, `chmod` routed through the bridge's own message, the page gating every one
   of those through a new bundle reason next to `hostCapabilities`, and the boundary recorded as
   `platform.android-saf-refusals` = `verified`.
7. **A4 local symlink** — **done**, see A4's *Status: fixed*: a shared `create_local_link` helper
   behind `/api/local/link` and a local branch in `link_remote_async`, one pane-aware page dialog,
   and the granted-folder refusal in both layers. **A9 Android agent message** — **done**, see
   A9's *Status: fixed*: a defaulted `missing_reason` on the connector trait, the Android platform
   message, and a site-dialog hint on a new bundle `sshAgent` flag.
8. **A5 vault** — **done**, see A5's *Status: fixed*: decided delete-and-document (the wrappers
   were doubly dead, so wiring would have been a product feature, not a fix). Dead constructors,
   decoder branches, DPAPI functions, the `KeystoreBridge` trait, and Tauri keystore state
   removed; migration-guide claims corrected.
9. **A8 SSPI** — the only item here that is genuinely large. It should stay `partial`, with the
   ledger finally saying *linux-only*, until someone does it.

**Acceptance criterion I propose for "parity" as a claim:** for every row in §2, one test that runs on
all three targets (or a device/emulator run recorded for the platform-only ones), and
`check_upstream_parity.py` in CI with the Windows and Android citations validated. Until then the
honest sentence is: *the three builds share one implementation and one page; Windows has one
GUI-blocking defect and no Kerberos; Android cannot sync a granted folder and has no agent; and the
evidence ledger records Linux-only suites as evidence for all three.*

---

## Appendix — files this report leans on

`crates/linscp-platform/src/{desktop,windows,gui_os,terminal,android,lib,watcher}.rs`,
`crates/linscp-service/src/{lib,ops,queue}.rs`,
`crates/linscp-engine/src/{transfer,sync_planner,script}.rs`,
`crates/linscp-tauri/src/{main,lib,android}.rs` + `android/LinSCPAndroidPlugin.kt`,
`crates/linscp-http/src/main.rs`,
`source/gui/web/index.html`, `source/gui/linscp_gui.py`,
`source/linux/tests/UnitTest.cpp`, `source/linux/tests/ScriptTest.py`,
`.github/workflows/{windows,debian,android}-build.yml`, `debian/rules`, `CMakeLists.txt`,
`tools/check_upstream_parity.py`, `tools/android_emulator_smoke.{sh,mjs}`,
`tools/tests/test_android_application_id.py`, `tools/tests/test_gui_distribution.py`,
`docs/{upstream-parity.json,native-feature-audit.md,linux-feature-inventory.md,android.md,cross-platform-rust-migration.md}`.
