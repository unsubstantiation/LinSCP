# Can LinSCP switch to PolyForm Noncommercial 1.0.0?

**Short answer: not for this tree as it stands — but the barrier is about 1,000 lines, not
the whole SSH engine.**

You can relicense code you wrote yourself. What you cannot do is put the *current*
repository under PolyForm Noncommercial, because part of `source/putty/` is WinSCP's
GPLv3 work. This document measures exactly how much, and what removing it costs.

It is an engineering/licensing review, not legal advice.

---

## 1. What the tree is made of

`source/putty/` is not upstream PuTTY. It is **WinSCP's fork of PuTTY**, carried over
from `winscp/winscp`. Measured against that upstream:

- 197 files; **150 are byte-for-byte identical** to WinSCP's copies.
- 154 of them are compiled into the binary (`source/linux/putty-core.mk`);
  **122 are byte-identical** to WinSCP's copies.
- WinSCP's fork markers survive: `MPEXT`, `WINSCP_BOM`, `WINSCP_LOG_PACKETS`, and
  `puttyexp.h` (WinSCP's exported API header, renamed here: `WINSCP_QUERY_*` →
  `FORK_QUERY_*`, `winscp_query()` → `linscp_query()`).
- The build passes `-DMPEXT` (`source/linux/Makefile` line 58), and the front end
  depends on WinSCP's MPEXT callback-set seam (`source/linux/PuttyGlue.cpp`,
  lines 7–14 and 676 ff.).

The other directories are your own work:

| Path | What it is | Status |
| --- | --- | --- |
| `source/linux/`, `source/gui/`, `tools/`, `debian/`, `docs/` | Original LinSCP code | Yours |
| `libs/putty/` | POSIX platform layer and SFTP library, ported from PuTTY's Unix sources | MIT; your patches are yours |
| `logo/`, `source/gui/web/icon.svg`, `favicon.png` | Original artwork | Already outside the GPL |

A 9-token shingle comparison of the app code against WinSCP's `source/core/` and
`source/console/` found about 20 shared 9-token sequences across 48 files — shared API
names and identifiers, not copied code. That is consistent with the app layer being
independent work. It is a sampling check, not a legal clearance.

---

## 2. The useful measurement: how much is *not* MIT

WinSCP did not invent its PuTTY tree. It vendors pristine PuTTY and then patches it.
That gives a clean baseline:

> `winscp/winscp` commit `b3732d9b7006f1f89b5c7b43d98c93ab23b4ef37`
> ("PuTTY 0.85", 2026-08-26, source commit `c9fb0e3663…`).
> Its `source/putty/` contains **zero** occurrences of `MPEXT` or `WINSCP` — a pure
> MIT drop. Everything WinSCP added comes in later commits.

Diffing LinSCP's compiled tree against that baseline:

| Measure | Count |
| --- | --- |
| Compiled files byte-identical to pristine PuTTY 0.85 (MIT) | **116 of 154** |
| Compiled files differing from it | 34 |
| Total changed lines across those 34 files | **1,003** (+876 / −127) |
| Compiled files that exist only because WinSCP created them | 4 |
| WinSCP-only header (`puttyexp.h`) | 77 lines |

Of the 1,003 changed lines, roughly +316 are LinSCP's own POSIX fixes (measured
against WinSCP's copies). The rest is WinSCP's.

The four WinSCP-created files are smaller than they look:

- `proxy/http_p.c` (817 lines) is **byte-identical** to pristine `proxy/http.c`.
  A rename, no contamination.
- `ssh/common_p.c` (1,309 lines) is pristine `ssh/common.c` plus **~35 changed lines**
  of callback-set threading.
- `crypto/aesold.c` (1,056 lines) is older PuTTY AES code (MIT) kept for the master
  password; only a `FORK_BUILD` comment differs.
- `utils/spr_get_err_message.c` (13 lines) is one function lifted out of upstream.

**So the WinSCP-authored residue in the shipped binary is on the order of 600–900 lines,
concentrated in the MPEXT callback-set plumbing.** The SSH protocol engine itself
(`connection2.c`, `kex2-client.c`, `transport2.c`, `userauth2-client.c`, the crypto)
is 116 of 154 files byte-identical to MIT PuTTY 0.85.

The largest per-file deltas from pristine 0.85:

```
  123  ssh/ssh.c                 62  logging.c
   94  ssh/userauth2-client.c    56  callback.c
   85  ssh/transport2.c          44  proxy/proxy.c
   81  ssh/connection2.c         36  sshpubk.c
   76  crypto/ecc-ssh.c          34  ssh/portfwd.c
```

---

## 3. Why the current tree still cannot be PolyForm Noncommercial

GPLv3 §5(c) requires a work based on the Program to be licensed "as a whole" under
GPLv3; §10 forbids adding further restrictions. PolyForm Noncommercial is exactly such
a restriction (noncommercial only, no sublicensing). The copyright in WinSCP's changes
belongs to Martin Prikryl and the WinSCP contributors; you cannot relicense it.

The MIT parts are not the problem. MIT is permissive and can sit inside a more
restrictive combined licence as long as its notice is retained. The GPLv3 parts are.

Note also that `license.txt` section B currently describes `source/putty/` as MIT-licensed
PuTTY. It is WinSCP's fork, so that needs correcting either way.

*(Old snapshots stay GPLv3 for whoever already has them. That does not constrain what
you ship from now on, and nothing below depends on it.)*

---

## 4. Options

### A — stay GPLv3

Zero work, Debian-friendly, already requires attribution and notice retention.

### B — AGPLv3

Stronger copyleft without any de-contamination: GPLv3 §13 expressly permits combining
GPLv3 and AGPLv3 code, with the GPLv3 terms continuing to apply to the GPLv3 part and
AGPLv3's network-source requirement to the combination. Still open source and
DFSG-free. Does not ban commercial use.

### C — PolyForm Noncommercial after de-contaminating `source/putty/`

Now a bounded job, not a rewrite. The worklist:

1. **Replace the four WinSCP-created files.** Use pristine `proxy/http.c`,
   `ssh/common.c`, an upstream AES, and drop `spr_get_err_message.c` (13 lines;
   fold the helper in yourself). Update `putty-core.mk`.
2. **Delete `puttyexp.h`** and its 27 declarations, or reduce it to the handful of
   symbols actually used. (Nothing outside MPEXT currently calls them, so most can go.)
3. **De-MPEXT the 12 files that thread `callback_set`**: `callback.c`, `ssh/agentf.c`,
   `ssh/common_p.c`, `ssh/connection2.c`, `ssh/connection2-client.c`,
   `ssh/transport2.c`, `ssh/userauth2-client.c`, `proxy/local.c`, `proxy/telnet.c`,
   plus the signatures in `putty.h` and `ssh.h` (`agentf_new`, `CALLBACK_SET_ONLY`,
   `ppl.h`). Revert to stock PuTTY's single global callback queue.
4. **Adapt your own layer to stock APIs.** `libs/putty/unix/platform.h` defines
   `DEFAULT_CALLBACK_SET linscp_posix_callback_set()`, and `network.c`, `fd-socket.c`
   and `cliloop.c` call `queue_toplevel_callback(DEFAULT_CALLBACK_SET, …)`. All of
   that is your code — free to change. `PuttyGlue.cpp`'s ~30-line seam
   (`get_callback_set`, `get_seat_callback_set`, `get_log_callback_set`) goes away.
5. **Re-derive the POSIX build fixes** (the `__clang__` guards, `__WIN32` scoping,
   alignment and warning fixes) against the pristine files rather than carrying them
   over. Working from the MIT baseline, without consulting WinSCP's diff, is what makes
   the result unambiguously yours.
6. **Run the suites**: `make -C source/linux check`, `check-live`, and the GUI tests.
   `get_log_seat()` / `plug_log` and the SFTP transport are the risky spots, since a
   single global queue must still satisfy the one-session console and the
   `-server` subprocess the GUI uses.
7. **Then** apply PolyForm Noncommercial to your code, MIT + notices to `source/putty/`
   and `libs/putty/`, and the existing separate terms to the artwork.

Order of magnitude: a day or two of focused work plus test time, not weeks, because
116 of 154 files need no changes at all.

### D — dual-license only your own files

The binary still contains GPLv3 code, so it must be conveyed under GPLv3, and
recipients get GPLv3 rights to the whole thing. Not useful for control.

---

## 5. About the draft licence text

- **Use PolyForm Noncommercial 1.0.0 verbatim.** Put the attribution in the mechanism
  the licence defines — a `Required Notice:` line:

  ```
  PolyForm Noncommercial License 1.0.0
  https://polyformproject.org/licenses/noncommercial/1.0.0

  Required Notice: Copyright (c) 2026 unsubstantiation (https://fairuniversal.com)
  ```

  The *Notices* section already obliges redistributors to pass on the terms and every
  `Required Notice:` line, so this covers the attribution requirement.

- **Your extra "prominent attribution" sentence is a further condition.** PolyForm's
  Notices clause is about passing licence text and notices along, not about visible
  credit. Keep the extra term in a `NOTICE` file rather than inside the licence text,
  and expect it to be enforceable only on its own footing.

- **Do not claim the whole tree.** Your copyright line is correct for your code; a
  `NOTICE` file must also carry the PuTTY notice (and the WinSCP notice if any of its
  code remains). Use the legal name of the copyright holder — a person, or the company
  that owns fairuniversal.com — not a handle.

- **Link the specific licence URL**, not `https://polyformproject.org`, and ship the
  full text.

- **"Open source" becomes wrong.** PolyForm NC is not OSI-approved; it is
  *source-available*. `readme.md` says "free, open-source".

- **Debian.** PolyForm NC fails the DFSG (free redistribution; no discrimination
  against fields of endeavour). The package would leave Debian main. For a project
  built as a Debian package, that is the real cost of this choice.

- **Noncommercial is broad:** charities, educational institutions, public research,
  public safety and health, environmental and government bodies may all use it,
  regardless of funding.

---

## 6. Fixes independent of the choice

- `license.txt` section B misdescribes `source/putty/` as MIT PuTTY and says the tree
  contains no copied WinSCP source. Correct it.
- `debian/copyright` says `Source: https://github.com/nuipona/linscp`; the repo is
  `unsubstantiation/linscp`.
- README says "GPL version 3"; `debian/copyright` says `GPL-3+`. Pick one and use it
  everywhere.
- Contributors: history shows only the `nuipona`/`unsubstantiation` accounts (same
  GitHub user ID) and Arena agents, so the app code looks clear. The WinSCP notice must
  still be preserved for the forked history.

---

## 7. Bottom line

| Goal | Feasible today? | Cost |
| --- | --- | --- |
| Whole repo under PolyForm NC | No | ~1,000 changed lines + 4 WinSCP files + the MPEXT seam |
| Whole repo under PolyForm NC, later | **Yes** | The worklist in §4C, roughly 1–2 days |
| AGPLv3 today | Yes | Change the licence files only |
| Stay GPLv3 | Yes | Fix the inaccurate notice in `license.txt` |

If the goal is "no company may commercialise this", PolyForm NC is the right licence and
the path is now clearly bounded. If the goal is "no proprietary forks", AGPLv3 gets you
there today without touching the SSH engine.

*Not legal advice. For a commercial launch or an enforcement question, have a lawyer
review the result.*

---

## 8. Outcome (2026-10-18)

Option C was carried out and the licence was applied.

- `source/putty/` was replaced with pristine PuTTY release 0.85. Nine files carry
  small build-compatibility patches (62 added lines, 6 removed): `network.h`,
  `puttymem.h`, `ssh.h`, `version.h`, `ssh/transport2.c`, `ssh/ssh.c`,
  `sshpubk.c`, `ssh/kex2-client.c` and `utils/stripctrl.c`. None of them is
  WinSCP code; they guard SSH-1, GSSAPI, X11 and terminal-only paths that this
  POSIX client does not build, and adapt three prototypes for the C++ front end.
- The MPEXT seam and the WinSCP callback-set plumbing are gone. The only
  remaining connection-policy code (`-timeout`, source address, `SO_SNDBUF`) is
  LinSCP's own, implemented on the stock `sk_new`/`sk_connect` API.
- `libs/putty/unix/` was checked against PuTTY's Unix front end line by line:
  `cliloop.c`, `agent-client.c`, `uxsel.c`, `no-gtk.c` and `noise.c` are
  identical apart from file names, `network.c` is 77.7% and `fd-socket.c` 79.3%
  identical, with the difference being the POSIX port's own adaptations. The
  layer is MIT-derived PuTTY code, not WinSCP code, and `libs/putty/LICENCE` is
  kept.
- Verification: `make -C source/linux check` passes all 1638 checks, the 101
  browser-GUI tests pass, the 71 script tests pass, and a live SFTP session
  against OpenSSH (upload, download, host-key cache, changed-key refusal) works.
- `license.txt` was replaced by `LICENSE` (verbatim PolyForm Noncommercial
  1.0.0 with the `Required Notice:` line) and `NOTICE` (attribution, the MIT
  notice for the PuTTY components, artwork terms, history and privacy). The
  readme, manual page, `logo/readme.md`, `debian/copyright` and `debian/rules`
  were updated to match.
