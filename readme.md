<p align="center">
  <img src="logo/linscp-mark.png" alt="LinSCP logo" width="160" height="160" />
</p>

<img src="pic.jpg" />

# LinSCP

LinSCP is a noncommercial file transfer client for Debian GNU/Linux. It has
a command-line client with a WinSCP-style scripting language, and a
browser-based dual-pane Commander (`linscp-gui`).

LinSCP implements a subset of WinSCP's workflows. It is **not full WinSCP
parity**: see [Protocols](#protocols) and the [parity audit](docs/upstream-parity.md).

## Requirements

- Debian 13 (trixie) or newer, with a GCC or Clang toolchain.
- Build dependencies: `libssh-dev` (0.10 or newer), `libssl-dev`, `libargon2-dev`, `zlib1g-dev` and `pkg-config`.
- `curl` at run time, for FTP transfers, FTPS, WebDAV and S3.
- Python 3, for the graphical client.
- `xdg-utils` (recommended), so `linscp-gui --open-browser` can ask the desktop
  for a browser window on Wayland as well as under X11.
- Node 20.19 or newer with `npm`, for the optional browser test suites
  (`npm install jsdom@29`). Not needed to build or use the client.

```sh
sudo apt install build-essential dpkg-dev pkg-config \
  libssh-dev libssl-dev libargon2-dev zlib1g-dev curl python3
```

LinSCP is Linux-only. The Makefile refuses to build on other systems.

## Building and testing

```sh
make -C source/linux                 # -> source/linux/build/linscp
make -C source/linux check           # unit tests and the platform check
make -C source/linux check-live      # script and live-server suites
```

CMake builds the same client and registers the suites with CTest:

```sh
cmake -S . -B build && cmake --build build -j
ctest --test-dir build --output-on-failure
```

The live suites use optional Python packages: `paramiko` (SFTP),
`botocore` (S3 signature reference), `xmlschema` (XML log schema
validation), and `pyftpdlib` with `pyOpenSSL`
(FTP/FTPS). The SCP suite needs `openssh-server`; it starts its own `sshd` on a
free port. A suite that skips a case says so on its evidence line.

The GUI suites (`source/gui/tests/`) run separately, as in CI. The two browser
suites (`ClientTest.js`, `LocalizationTest.js`) are the ones that need Node and
`jsdom`; CMake registers them only when both are installed. `SecurityTest.py`
drives the server itself, with no browser: tokens, sign-in, the absence of CORS
permission, response headers, command quoting, and the confinement of every
local path to its pane.

`make -C source/linux check` also runs `tools/check_platform_conversion.py`.
LinSCP is a Linux-only client - the Windows port is gone - and that check
reads the sources and refuses a Windows API call, a Windows environment
variable, a Windows path, a file of another platform, an installer that
disagrees with the others, and an error message whose wording contradicts the
template it is filled into. It is what keeps the conversion complete rather
than merely done once.

A second check guards the other half of "runs on Linux": a Wayland desktop,
where an application that only asks for `$DISPLAY` sees no display at all.
`tools/check_wayland_compatibility.py` refuses a display-server test that reads
`DISPLAY` without `WAYLAND_DISPLAY`, a terminal candidate that does not say
which display server it draws on, an X11-only or Wayland-only helper program,
a desktop entry a Wayland compositor cannot act on, and the two
implementations of the detection disagreeing about what a session is. It runs
in `make -C source/linux check`, in CTest as `wayland-compatibility-check`, and
in CI. For the Debian package:

```sh
dpkg-buildpackage -b -us -uc         # -> ../linscp_1.0-5_<arch>.deb
```

## Usage

```sh
linscp -batch -script=script.txt
linscp -batch -command="open sftp://user@example.com/; cd /data; get *.csv /tmp"
linscp-gui                         # browser Commander on 127.0.0.1:8080
linscp-gui --open-browser          # ... and ask the desktop to show it
```

Run `linscp -help` for the options and `man linscp` for the full reference.

## Protocols

| URL | Served by | Notes |
| --- | --- | --- |
| `sftp://` | native SFTP v3 over libssh (copy-data / check-file-name extensions included) | full command set |
| `scp://`, `ssh://` | the client's SSH code: the server's shell for directory work, rcp for bytes | no resume; the protocol has no offset |
| `ftp://` | native FTP engine for listing and metadata; curl for transfers | |
| `ftps://` | curl, implicit TLS | |
| `ftpes://` | curl, explicit TLS on FTP (upstream's spelling; the same session as `ftp://` with `Ftps=2` or `3`) | |
| `dav://`, `webdav://` | curl, with PROPFIND, MOVE, COPY, locks, dead properties and ETag preconditions | |
| `s3://` | curl, with SigV4 signing and multipart transfers | partial |

Host keys are verified. `-hostkey=` takes a SHA-256 or MD5 fingerprint. An
unknown key in a run that cannot prompt is refused, and the key is printed so
it can be pinned.

## Features

- **Transfers:** binary, ASCII and automatic modes; WinSCP file masks; recursive
  `get` and `put`; resume through `.filepart` staging; `-append` (SFTP only);
  `-speed=` limits; `-preservetime`; transfer presets.
- **Synchronization:** `synchronize` in one or both directions, and
  `keepuptodate`, which watches the local tree with inotify.
- **SSH keys:** native PPK v2/v3 parsing for authentication and `copyid`,
  including encrypted keys (Argon2 for encrypted v3), plus
  `linscp -convertkey=input.ppk -output=output.pem` for a validated PEM copy;
  encrypted inputs stay encrypted with the same passphrase.
- **Remote operations:** `chmod` (octal and symbolic), `cp`, `mv`, `ln`,
  `rm`, `mkdir`, `stat`, `checksum`, `edit`, `call`, and `copyid`.
- **Scripting:** unambiguous command and option abbreviations, `%1%`..`%9%`
  parameters, `%TIMESTAMP%` and environment expansion, `option batch` and
  `option confirm`, and an XML action log (`-xmllog=`).
- **Stored sessions:** shared between the CLI and the GUI, with folders,
  encrypted passwords in `sessions.ini` (key in `sessions.key`), and proxy
  settings through `-rawsettings`.
- **SSH jump hosts:** independent jump/destination authentication and host-key
  verification, encrypted saved jump credentials, GUI/queue/terminal support,
  and fail-closed proxy/forwarding behavior. See [SSH tunnels](docs/ssh-tunnels.md)
  for configuration and limits.
- **Graphical client:** dual-pane layout, transfer queue with pause, retry and
  priority reordering, transfer settings, sync preview, `keepuptodate`, remote
  search, checksums, session bookmarks, a session URL, session import, cleanup
  of stored data, a copy between two servers, properties with a rights editor,
  preferences stored by the backend, saved command templates, multi-user
  sign-in, local file editing and drag-and-drop in both panes. Sign-in does not
  isolate users' tabs, files or commands: do not share one backend among
  untrusted users.
- **Localization:** English and Spanish, for the CLI and the GUI.
- **Desktop sessions:** works on Wayland and on X11 alike. The clients draw no
  window of their own; the terminal `terminal` opens is chosen among the ones
  that can draw on this display server, and `--open-browser` asks the desktop's
  own launcher (`xdg-open`, `$BROWSER`) for a browser window. No `xclip`,
  `xdotool`, `wmctrl` or `xrandr`, which is what makes a Linux application
  X11-only.

Full WinSCP parity is **not** implemented. Remaining gaps include complete
compatibility with the upstream .NET object model, broader localization beyond
English/Spanish, and further live Kerberos-realm validation of GSSAPI. Local-to-local sessions with two
local panes, named multi-tab workspaces, directory bookmarks, session import
from OpenSSH/FileZilla and session-URL generation are implemented and covered
by the `gui-local` and `gui` suites.
The .NET-compatible assembly (`LinSCP.Session`, with `WinSCP.Session` aliases)
covers session lifecycle, listing, transfers, synchronization, cancellation and
structured errors; it is not every type of the upstream object model.
`automation/LinSCP.psm1` is a PowerShell 7 CLI wrapper with static tests and
optional live Pester tests, not the WinSCP .NET API. Optional account sign-in
isolates users at the application layer; the backend still runs as one OS user.
See the
[remaining parity plan](docs/remaining-parity-plan.md) for scope and acceptance
criteria; passing the inventory checker is not a full-parity certification.

## Documentation

- [`docs/debian.md`](docs/debian.md): options, commands, protocols,
  authentication, packaging and troubleshooting.
- [`docs/linscp.1`](docs/linscp.1): the manual page.
- [`docs/upstream-parity.md`](docs/upstream-parity.md): the parity audit, its
  evidence rules and how to maintain them.
- [`docs/linux-feature-inventory.md`](docs/linux-feature-inventory.md) and
  [`docs/remaining-parity-plan.md`](docs/remaining-parity-plan.md): generated
  from `docs/upstream-parity.json`. Regenerate them with
  `python3 tools/check_upstream_parity.py --write-report`.
- [`docs/localization.md`](docs/localization.md): language selection and catalogues.

## Repository layout

```
automation/    PowerShell 7 CLI wrapper, static and optional Pester tests
debian/        Debian packaging
docs/          documentation, manual page and parity inventory
logo/          logo artwork
source/gui/    browser Commander: Python server, web client, tests
source/linux/  linscp client: front end, protocol glue, tests, Makefile
source/linux/  console client: libssh transport, native SFTP/SCP
tools/         parity inventory, translation and platform-conversion checkers
```

## Licence

LinSCP is distributed under the [PolyForm Noncommercial License
1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0):
noncommercial use only. This is not an open source licence. The full terms are
in [`LICENSE`](LICENSE); the copyright line, the MIT notice for the
third-party components and the artwork terms are in [`NOTICE`](NOTICE).
