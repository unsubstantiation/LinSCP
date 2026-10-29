# LinSCP on Debian

This is the operator reference for the Debian build of LinSCP: the console
client, its options and commands, protocols, authentication, packaging and
troubleshooting. For an overview, see the top-level [readme.md](../readme.md).

LinSCP is now a **pure-Rust + Tauri v2 + TypeScript** workspace. The console
client (`linscp`), the browser HTTP server (`linscp --serve-http` / `linscp-gui`)
and the native desktop host (`linscp-tauri`) share one Cargo workspace
(`crates/*`) and one TypeScript Commander frontend (`ui/`). No C/C++ cross-
compilation is required for the default build; `debian/rules`, `CMakeLists.txt`
and `source/linux/Makefile` are thin wrappers that delegate to `cargo`.

## Requirements

| What | Why |
| --- | --- |
| `cargo` + `rustc` 1.89+ | builds `crates/*` (`--release --workspace` → `target/release/linscp{,-gui}`) |
| `pkg-config` + `dpkg-dev` | only to build the `.deb` (`debian/rules`) |
| `xdg-utils` (recommended, run time) | `xdg-open` launcher that shows `linscp-gui --open-browser` on Wayland and X11 |
| Node 22+ with `npm` | TypeScript UI build (`ui/`) and its `jsdom` suites (`ClientTest.js`, `LocalizationTest.js`) |
| Python 3 | live regression harnesses that drive `target/release/linscp` and `linscp --serve-http` |
| `openssh-server`, `krb5-kdc`, `krb5-admin-server`, `krb5-user` (live GSSAPI/SCP) | isolated loopback `sshd` + throwaway KDC for `LiveSftpTest.py` / `LiveTunnelTest.py` / `LiveScpTest.py` |
| `python3-paramiko`, `python3-pyftpdlib`, `python3-openssl`, `python3-botocore`, `python3-xmlschema` (live) | SFTP / FTPS / S3 / XML-log reference implementations |

Legacy C++ deps (`libssh-dev`, `libssl-dev`, `libargon2-dev`, `zlib1g-dev`, `build-essential`) are **not**
required for the pure-Rust build; they remain only in git history for the retired
`source/linux/*.cpp` reference implementation.

```sh
sudo apt install dpkg-dev pkg-config cargo rustc xdg-utils python3 nodejs npm
# optional live deps:  sudo apt install openssh-server krb5-kdc krb5-admin-server krb5-user \
#   python3-paramiko python3-pyftpdlib python3-openssl python3-botocore python3-xmlschema
```

## Building

Pure-Rust is primary:

```sh
cargo build --release --workspace      # -> target/release/linscp + linscp-gui (linscp-tauri on desktop)
cargo test --workspace --all-targets   # Rust unit + integration tests
npm --prefix ui install
npm --prefix ui run build              # -> ui/dist (embedded in linscp-http via include_str)
npm --prefix ui test                   # TypeScript UI + jsdom suites
python3 source/linux/tests/ScriptTest.py target/release/linscp
python3 source/linux/tests/LiveSftpTest.py target/release/linscp
# ... LiveTunnel/S3/Dav/Scp/Curl + gui suites via linscp --serve-http
```

Legacy wrappers remain for compatibility and CI parity:

```sh
make -C source/linux            # delegates to cargo build
make -C source/linux check      # delegates to cargo test + hygiene checks
cmake -S . -B build && cmake --build build -j   # delegates to cargo
ctest --test-dir build --output-on-failure
```

Build output is `target/` (git-ignored). Use `cargo --target aarch64-linux-android` (via `cargo ndk`)
and `cargo --target x86_64-pc-windows-msvc` for cross builds; default builds need no C toolchain.

## Packaging

```sh
dpkg-buildpackage -b -us -uc
# -> ../linscp_1.0-6_amd64.deb
sudo dpkg -i ../linscp_1.0-6_amd64.deb
```

`debian/rules` does **not** use debhelper. It runs `cargo test --workspace --all-targets`,
`cargo build --release --workspace`, then installs exactly the tree `cargo` produced plus
desktop integration:

| Path | What |
| --- | --- |
| `/usr/bin/linscp` | console client (also `-server`, `-shell`, `backup`, `-xmllog`) |
| `/usr/bin/linscp-gui` | same Rust binary; `linscp-gui --open-browser` serves `ui/dist` on 127.0.0.1 and asks `xdg-open`/`$BROWSER`/`gio` for a window (Wayland/X11) |
| `/usr/share/linscp/automation/LinSCP.psm1` | PowerShell 7 wrapper over the console client |
| `/usr/share/linscp/dotnet/` | LinSCP .NET assembly sources (`LinSCP.csproj`, `Session.cs`) |
| `/usr/share/man/man1/linscp.1.gz` | manual page (`docs/linscp.1`, pure-Rust/reqwest/suppaftp/russh) |
| `/usr/share/applications/linscp.desktop` | desktop entry, `sftp://`, `ftp://`, `ftps://`, `ftpes://`; `StartupNotify=false`, `TryExec=linscp`, recommends `xdg-utils` |
| `/usr/share/pixmaps/linscp.png`, `/usr/share/icons/hicolor/scalable/apps/linscp.svg` | icons |
| `/usr/share/doc/linscp/` | `copyright`, `LICENSE`, `NOTICE`, this document as `README.Debian` |

The UI assets are **embedded** in the binary (`linscp-http` `include_str!` of `ui/dist`), so no
`/usr/share/linscp/gui/` tree is shipped — browser mode is served from the binary itself.
`linscp -gui` and the desktop entry both exec `linscp-gui`.

`make -C source/linux install` and `cmake --install` lay out the same tree under the prefix they are
given, delegating to `cargo install`-equivalent logic. The installers are kept in step by
`tools/check_repo_hygiene.py` (successor to `check_platform_conversion.py`).

The CI `debian-package` job builds the `.deb`, asserts the paths above exist, installs it,
and starts the installed GUI. A launcher that cannot find its binary therefore fails the build.

`Depends` is generated by `dpkg-shlibdeps` from the Rust binary's linked libs (mostly `libc`).
Update `debian/changelog` and `Maintainer` before publishing.

## Using the client

```sh
linscp [options] [sftp://[user[:password]@]host[:port]/[path]]
linscp -batch -script=script.txt
linscp -batch -command="open sftp://user@example.com/; cd /data; ls; get * /tmp"
```

### Options

| Option | Meaning |
| --- | --- |
| `-script=<file>` | read commands from a file; `-` reads standard input |
| `-command=<cmds>` | run commands; separate several with `;` |
| `-literal` | with `-command`, do not expand `%...%` in paths; used by GUI-generated commands |
| `-hostkey=<fingerprint>` | pin the host key; `*` accepts any key for this connection only |
| `-privatekey=<file>` | OpenSSH or PPK v2/v3 private key for public-key authentication |
| `-passphrase=<text>` | private-key passphrase (prefer an interactive prompt or ssh-agent over putting it on the command line) |
| `-convertkey=<input.ppk> -output=<output.pem>` | verify and convert PPK v2/v3 to a PEM private key; prompts for encrypted-key passphrase when interactive |
| `-username=<name>` | user name |
| `-password=<password>` | password; prefer `LINSCP_PASSWORD`, which keeps it out of the command line |
| `-port=<number>` | port (default 22) |
| `-timeout=<secs>` | connection timeout (default 15) |
| `-log=<file>` | write the session log to a file |
| `-xmllog=<file>` | write an XML log in the upstream session format (namespace `http://winscp.net/schema/session/1.0`, schema pinned as [linscp-session-1.0.xsd](linscp-session-1.0.xsd)): one `<group>` per command and one element per operation, with passwords masked |
| `-parameter <value>...` | script parameters, for `%1%` to `%9%` |
| `-batch` | never ask; fail instead |
| `-server` | read one command per line on standard input and answer each with `LSCP-RESULT`; the GUI drives the client this way |
| `-gui` | launch the graphical client |
| `-verbose` | print SSH event log messages |
| `-version`, `-help` | print the version, or the usage |

With neither `-script` nor `-command`, the client starts an interactive session
and reads from the terminal. It needs a terminal, so use `-script=-` to feed
commands through a pipe.

### Commands

`open`, `close`, `session`, `sessions`, `savesession`, `rmsession`, `cd`, `pwd`,
`ls` (`-a`, `-l`, `-1`), `lcd`, `lpwd`, `lls`, `get`, `put`, `synchronize`,
`keepuptodate`, `edit`, `rm`, `rmdir`, `mkdir`, `mv`, `cp`, `ln`/`symlink`,
`chmod`, `stat`, `checksum`, `copyid`, `presets`, `savepreset`, `rmspreset`,
`option`, `echo`, `call` (`!`), `terminal`, `help`, `exit`.

Compatibility aliases from the upstream scripting language are also accepted:
`recv`/`mget`, `send`/`mput`, `dir`, `rename`, `del`, `md`, `sync`, `man`,
`bye`, `quit` and `end`. `show` is recognised only to refuse it: the
connection runs the SFTP subsystem, so there is no shell to ask for settings.

`lock`, `unlock` and `property` are WebDAV extensions. A lock is an exclusive
write lock, and later uploads, deletes and moves of that path carry its token.
`property` reads and writes dead properties.

Local and remote paths may contain `*` and `?` wildcards, so `get *.txt /tmp`
transfers every match. The exit status is non-zero if any command failed. When
a transfer selects several source files, the destination is treated as a
directory and created if needed. `mkdir <path>` creates one remote directory;
`mkdir -parents <path>` also creates missing parents.

`get` and `put` transfer directories recursively with `-r`, and accept these
switches:

* `-resume`: resume an interrupted transfer at the target byte offset. Bytes
  arrive in a `<name>.filepart` staging file that becomes the destination only
  when complete, so an interrupted transfer never leaves a truncated file under
  the final name.
* `-delete`: remove source files after a successful transfer.
* `-neweronly` / `-noneweronly`: transfer only files newer than the target, or
  ignore dates (the default).
* `-preservetime` / `-nopreservetime`: keep source timestamps.
  `-preservetime=all` also keeps directory timestamps.
* `-append`: append to the destination instead of replacing it. It needs the
  native SFTP transport and cannot be combined with `-resume`.
* `-speed=<KB/s>`: limit the rate; `0` means no limit.
* `-resumesupport=on|off|<KB>`: whether, and from what size, an interrupted file
  is continued. `automatic` (the default, set with `option resume`) stages
  binary files of at least 100 KB through `.filepart`; `on` stages every eligible
  transfer and `off` none.
* `-transfer=binary|ascii|automatic` and `-filemask=<masks>`: as for
  `synchronize`.

An unknown switch, an invalid value, or a switch the transport cannot honour is
reported before anything is transferred. For example, `-append` over curl and
`-resume` over `scp://` are refused, because rcp has no offset to continue from.
If the destination is omitted, `get` uses the local working directory and `put`
uses the remote working directory.

`chmod <mode> <file>... [-recursive]` takes an octal mode (`644`, `0700`) or a
symbolic one (`u+x`, `a=r,go-w`, `u+s`; `X` sets execute only where it is
already set or for directories). `-recursive` walks a remote tree and does not
follow symbolic links.

`copyid [<keyfile>]` appends the public half of the session's private key, or
of `<keyfile>`, to `~/.ssh/authorized_keys` on the server. It creates `~/.ssh`
as `0700` and the file as `0600`, and reports when the key is already
installed. OpenSSH public/private keys and PPK v2/v3 keys are supported;
PPK MAC integrity is verified, so an encrypted PPK needs its passphrase
(interactive prompt or `-passphrase=`). It needs an `sftp://` or `scp://` session.

`synchronize local|remote|both [localdir [remotedir]]` compares directory trees
and copies newer and missing files in the chosen direction. `keepuptodate` is
covered under [Limits](#limits).

A command name, an `option` name, and a value from a fixed set may be
abbreviated to any unique prefix: `synch local` is `synchronize local`, and
`option bat cont` is `option batch continue`. An abbreviation that fits several
names is refused with the candidates, so that a different command is never run
by mistake.

An argument is split on blanks. A word in single quotes is literal, a word in
double quotes keeps its blanks, and a backslash outside quotes stands in front
of the character behind it. Inside double quotes a backslash is literal
unless it stands in front of a double quote or of another backslash, so a path
carried over from a Windows client keeps its separators: `get
"C:\Users\me\file.txt"` downloads the file of that name and not a file called
`C:Usersmefile.txt`. These are the rules of a POSIX shell, because the names
on this platform are POSIX names: a backslash and an apostrophe are ordinary
characters of a file name here, so a script that has to name such a file
quotes it.

In a script or an interactive line, `%1%` to `%9%` are replaced by `-parameter`
values. `%TIMESTAMP%` is the local time; `%TIMESTAMP#yyyy-mm-dd%` sets a
format, and `%TIMESTAMP-1D#yyyymmdd%` applies an offset (`S`, `N`, `H`, `D` or
`Y` for seconds, minutes, hours, days or years), with a trailing `S` to snap to
the start of that unit. `%NAME%` is replaced by an environment variable, and
left in place if the variable is unset. Nothing is expanded inside single
quotes. A timestamp with an offset but no format is an error. For literal text
such as `%TIMESTAMP%` in `-command`, add `-literal`. Inside a script file, use
single quotes instead. `-server` input is not expanded.

Overwrite and delete confirmations are on by default. In an interactive run the
client asks first. In `-batch` or any other non-interactive run, an operation
that needs confirmation fails without reading standard input. Put
`option confirm off` in a trusted script to skip the checks.

Scripts stop at the first error by default. `option batch on|off|abort|continue`
sets this: `on` and `abort` stop, while `off` and `continue` carry on and keep a
non-zero exit status. `echo` prints a message to the script output.

`terminal` opens an interactive shell on the server, as the upstream "Open
Terminal" command does. It starts the system `ssh` client in a local
terminal window. The program is taken from `LINSCP_TERMINAL` (`<program>
[args]`, for example `xterm -e`), or else from these, in this order and among
the ones that are installed: `x-terminal-emulator`, `gnome-terminal`,
`konsole`, `xfce4-terminal`, `mate-terminal`, `lxterminal`, `terminator`,
`alacritty`, `kitty`, `foot`, `wezterm`, `urxvt` and `xterm`.

Which of them is chosen depends on the display server, because a window can
only be shown on one it speaks. A session is found by its socket rather than
by one variable: X11 by `DISPLAY`, Wayland by the compositor's socket in
`XDG_RUNTIME_DIR` — the one `WAYLAND_DISPLAY` names, or the default
`wayland-0` when that variable is not exported, which is how a session
started by a launcher or a user service is still found. A Wayland-only
terminal such as `foot` is therefore never started under X11, where it would
exit before mapping anything, and an X11-only one under Wayland is a fallback
after the terminals that speak the compositor's own protocol: it works through
XWayland, at the cost of a window the compositor does not scale, which the
client says in one line. `wayland(7)` and the portal man pages have the
desktop side. It works only for SSH (`sftp://` and `scp://`) sessions. The
graphical client's "Terminal" button runs the same command.

`call` (and `!`) runs a command over a one-shot SSH exec channel, using a second
connection, so the SFTP session stays open.

The manual page `linscp(1)` has the same reference. Its source is
[linscp.1](linscp.1).

## Sites and protocols

```sh
open sftp://user@example.com:2222/var/data -hostkey=<fingerprint>
```

The password is optional in the URL. Prefer `-password=` or
`LINSCP_PASSWORD`, so that it does not end up in a script file.

**SSH.** `sftp://` uses this client's own SFTP v3 implementation over libssh. `scp://` (and `ssh://`)
uses `source/linux/ScpClient.cpp`: it runs the server's login shell for
listings, `stat`, `cd` and the directory and metadata commands, and the server's
own `scp` for the bytes, over the rcp protocol. Each SCP command opens its own
SSH connection. Every path is quoted for a POSIX shell, and a refusal is shown
as the sentence the server printed.

**Other protocols.** The support table is in the [readme](../readme.md#protocols).
Plain `ftp://` lists and stats through a native engine, `FtpClient.cpp`, and
sends transfers through curl. FTPS (`ftps://`, or `ftp://` with explicit TLS)
is handled entirely by curl. WebDAV has PROPFIND listings, MOVE, COPY (with a
streamed fallback when COPY is refused), locks and dead properties. Its URL
paths are percent-encoded, so spaces, percent signs and query characters in
file names are transferred literally. S3 uses SigV4 signing, object listing,
stat and CRUD, CopyObject and multipart copy, and multipart uploads above
16 MiB, which resume from a local sidecar. It also lists object-version history
with `versions` and supports exact-version downloads and deletions with
`get -versionid=` and `rm -versionid=`. In versioned buckets, a normal delete
creates a delete marker; `rm -versionid=` deletes only the named version or
marker. S3 `-rawsettings` supports `S3StorageClass`, `S3Acl`,
`S3ServerSideEncryption`, `S3KmsKeyId`, `S3RequestPayer` and `S3Metadata`.
Object and version listings validate continuation markers rather than silently
returning incomplete results.

Proxies are set through `-rawsettings` on `open` or `savesession`, using
upstream's names:

```
open -rawsettings ProxyMethod=SOCKS5 ProxyHost=proxy ProxyPort=1080 ...
```

`ProxyMethod` can be `SOCKS4`, `SOCKS5`, `HTTP`, `Telnet` or `Cmd`. The SSH
protocols use the core's own proxy code. SOCKS and HTTP proxies apply to the
curl-backed protocols as `--proxy`. A setting or proxy this build cannot use is
refused by name, never dropped silently.

SSH jump hosts are available for SFTP/SCP/SSH. Enable them with
`-rawsettings Tunnel=1 TunnelHostName=jump.example.com TunnelUserName=jumper
TunnelHostKey=SHA256:...`; `TunnelPortNumber`, `TunnelPublicKeyFile`,
`TunnelPassword` and `TunnelPassphrase` configure the jump independently of the
destination. Global `-rawsettings=N` also supplies defaults to `-shell`.
The parent proxy reaches the jump, and a private socket pair replaces a local
TCP listener by default. A nonzero `TunnelLocalPortNumber` binds that
loopback port for this session's own tunneled connection. GSSAPI/Kerberos
uses libssh when the loaded library advertises it; credential delegation is
off unless `GSSAPIFwdTGT=1` is set. The jump session uses the destination's
Kerberos settings, as upstream does, so a delegated ticket reaches the jump
host too. FTP, FTPS, WebDAV and S3 destinations reach the jump through a SOCKS5
relay on 127.0.0.1; a refused forward never falls back to a direct connection.
See [SSH tunnels](ssh-tunnels.md) for secure examples, storage policy and
regression commands.

The GUI challenges each hop separately. Remembering a key stores only that
hop's pin, not transient credentials or an unchecked key on the other hop.
Changed keys have a distinct warning and do not default to being remembered.

Stored sessions live in `sessions.ini`, in folders with `sessions folders`,
`sessions [folder/]` and `rmsession -folder`. The graphical client reads and
writes the same files.

## Graphical client (`linscp-gui`)

`linscp-gui` and `linscp -gui` start a dark, dual-pane LinSCP Commander in the
browser. Run at a terminal, `linscp -gui` also asks the desktop for the browser
window (`--open-browser`); with its output redirected it does not, so a script
is never interrupted by a window it did not ask for. The Commander offers:

* A dual-pane explorer, with the local filesystem on the left and the server on
  the right, and a single-panel view for a narrow window.
* A background transfer queue with progress, speed, pause, retry, per-item
  cancel and reordering to the front.
* A transfer settings dialog: transfer mode (binary, ASCII or automatic by
  mask), a file mask, a speed limit in KiB/s, resume support, preserve time,
  newer-only, append, and whether to set permissions at all. These are the same
  switches the console client's `get` and `put` take.
* Remote search by file-name mask or literal UTF-8 content, with per-file and
  per-search bounds.
* Synchronization with a preview, a conflict policy and a direction, plus
  `keepuptodate` as a queue item that watches a local directory.
* Properties, checksums, server-side copy, symbolic links and `copyid` from the
  Commands menu.
* Saved command templates with `{file}` for the selected name, scoped to the
  open session or to the local side. Each run asks first and shows the command
  it will use.
* A console log and an embedded command line.
* Drag-and-drop of files and folders from a file manager into either pane.
  Relative paths and empty directories are kept, and unsafe paths are rejected.
* An opt-in **Upload with LinSCP** file-manager action:
  `linscp-gui --install-shell-integration` writes one small per-user
  definition each for Dolphin (KDE), Files (GNOME) and Nemo (Cinnamon)
  under the XDG data directory (`--uninstall-shell-integration` removes
  exactly those, and never a definition it did not write). Choosing the
  action only holds the selection for the Commander, which offers it in
  a dialog; nothing is uploaded until that is confirmed against a
  session tab.
* Multi-user sign-in when the server is started with `--accounts-file=`.
* A desktop entry and URL scheme handlers, from `linscp.desktop`, which starts the
  server with `--open-browser` so the desktop's own launcher shows the page - the
  way that needs no X11 on a Wayland session.

### Reaching the server

The server binds `127.0.0.1:8080` by default and generates a per-run API token.
The page it serves carries that token and every `/api/` call has to present it,
so a process on the machine that did not start the server cannot drive it.

* `--host=` and `--port=` choose the address; `--port=0` asks the kernel for a
  free port and the address printed is the one that was bound.
* `--token=` fixes the token instead of generating one.
* Requests are answered only for a `Host` header naming loopback. `--allow-host=`
  adds a name, for a reverse proxy, and `--allow-any-host` disables the check.
* **No CORS permission is granted.** The browser client is served by this same
  server, so its calls are same-origin and need none. Without that, any page
  the user visited could fetch the served document, read this run's token out
  of it and then drive the whole API — which is the local file system of
  whoever started the server. `--allow-origin=URL` is the explicit opt-in for a
  front end that really is served from somewhere else; it is granted that one
  origin and no other, and `*` is never sent.
* Responses carry `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
  and `Referrer-Policy: no-referrer`.

With `--accounts-file=FILE`, every request also needs a signed-in session:
`--add-account` creates one, passwords are stored as PBKDF2-SHA256 with a
per-account salt, the file is created readable by this account only, state
changes need the CSRF token that the sign-in answered with, and five failed
sign-ins lock a user name out for a minute. Sessions last an hour. Each account
can carry a `home_dir`, which is recorded but not yet enforced as the root of
that user's local pane.

### Desktop sessions (Wayland and X11)

Neither client draws a window, so neither needs a display server to work: the
console client writes to the terminal it was started in, and the graphical
client is a page a browser shows. What has to know about the session is the
small set of places where LinSCP asks the desktop for something.

* `terminal` starts a window, so it picks a terminal that can draw on the
  display server in use — see [`terminal` above](#commands). It reads
  `WAYLAND_DISPLAY`, `XDG_RUNTIME_DIR` and `DISPLAY`, and nothing else.
* `linscp-gui --open-browser` asks the desktop to open the Commander's address.
  The launcher is `$BROWSER` when it is set, otherwise `xdg-open`, otherwise
  `gio open`; on a Wayland session `xdg-open` reaches the browser through the
  desktop portal, which is the one route that needs no X11 at all. `linscp.desktop`
  starts the server with that option, so clicking LinSCP in an application
  grid opens the Commander. If no session can be reached — a server started
  over ssh, say — nothing is launched and the address is printed instead.
* The embedded terminal in the browser page is a pseudo-terminal with xterm.js
  rendering the bytes, so it is not a client of either display server and
  behaves the same on both.
* Drag and drop from a file manager into a pane is the compositor's and the
  browser's business; LinSCP only receives the dropped names. Dropping out of
  the browser onto a native application is a browser limitation on any display
  server, not a Wayland one.
* The desktop entry sets `StartupNotify=false` on purpose: this launcher starts
  a server and prints an address, and a compositor waiting for a window from it
  would wait until it gave up.

Neither client uses `xclip`, `xdotool`, `wmctrl`, `xrandr` or `scrot`, which is
the usual way a Linux desktop application ends up working only under X11.
`python3 tools/check_wayland_compatibility.py` is the guard that keeps it that
way; `make -C source/linux check` runs it and CTest registers it as
`wayland-compatibility-check`.

What it cannot certify is the interaction with a real compositor: the check
reads sources. Running `terminal` on a Wayland session, and `--open-browser`
from a desktop grid, is the test that does.

## Authentication

* **ssh-agent** (recommended): with `SSH_AUTH_SOCK` set, the keys in the agent
  are offered automatically.
* **Private key file**: `-privatekey=` accepts OpenSSH/PEM keys and PPK v2/v3
  files. PPK RSA, DSA, NIST ECDSA, Ed25519 and Ed448 key components are
  decoded and integrity-checked natively. Authentication still depends on
  libssh supporting that SSH algorithm (Ed448 may be conversion-only); server
  policy can also reject legacy DSA. Encrypted PPK v2 and v3 files are
  supported; encrypted v3 uses Argon2 and therefore needs the `libargon2`
  runtime library. To bound untrusted-file resource use, PPK v3 KDF settings
  above 256 MiB, 100 passes or 64-way parallelism are refused. An encrypted
  key asks for its passphrase interactively. In `-batch` mode, supply
  `-passphrase=` to
  `open` or load the key into ssh-agent. To make a standalone PEM copy, run
  `linscp -convertkey=input.ppk -output=output.pem`; this validates the key,
  never overwrites an existing output file, prompts for an encrypted key's
  passphrase when interactive, and retains encryption with that passphrase.
  Keep the passphrase out of shell history
  where possible.
* **Password**: `-password=` or `LINSCP_PASSWORD`. Interactive runs ask for
  one when it is missing. `-batch` runs fail instead of asking.
* **Stored password**: `savesession <name> -password=...` stores it encrypted,
  as `lscp1$...`, in `sessions.ini`, with the key in `sessions.key` next to it.
  The key file is created on first use and readable by this account only. A
  plaintext password from an older version is rewritten encrypted on the next
  save. Without the key file, `open <name>` says the password cannot be used and
  carries on without it. An unrelated re-save keeps the unreadable value rather
  than destroying it. The graphical client uses the same format.

## Host keys

`-hostkey=` compares the fingerprint the server presents with the one given.
`*` accepts any key for that connection only: it suits throwaway targets, and
the key is not added to the persistent cache. With no `-hostkey=`, an unknown
key is accepted only when the client can ask you. In `-batch` mode the
connection fails, and the key is printed so that it can be pinned.

## Limits

Unsupported things are refused, not approximated. Examples:

* `-append` needs native SFTP. `-resume` cannot be combined with ASCII conversion.
* `-rawtransfersettings=` accepts only settings this build implements.
* `synchronize both -delete` consults the previous sync state before it deletes.
  `-mirror` is refused with `both`.
* An unknown switch, an invalid `-permissions=`, a malformed `-filemask` and a
  `%TIMESTAMP%` placeholder with an offset but no format are all errors, since
  an ignored filter would change what a script transfers or deletes.

Resume depends on each backend. S3 uploads above 16 MiB save their upload ID and
completed parts in a local sidecar and resume from there.

`keepuptodate` follows upstream and copies local changes to the remote side. A
recursive inotify watch triggers it, and `-interval=` adds a full rescan. If the
watch cannot be set up, the client falls back to timer polling. It runs in the
foreground until Ctrl-C, or until `-count=` passes complete, so a
non-interactive script must give `-count=`.

The .NET-compatible assembly (`LinSCP.Session`, with an upstream compatibility
namespace) implements session lifecycle, listing, transfers, synchronization,
cancellation and structured errors, but it is not the complete upstream object
model.
Optional account sign-in isolates users at the application layer while the
backend still runs as one OS user. Catalogs for every language upstream ships
(the shipped ones are listed in [Localization](localization.md)) and complete
upstream .NET object-model compatibility are not implemented.
Local-to-local sessions, named workspaces, directory bookmarks, session import
from OpenSSH/FileZilla and session-URL generation are implemented. SSH jump hosts work for SFTP/SCP/SSH
and, through a loopback SOCKS5 relay, for FTP/FTPS/WebDAV/S3.

The live SFTP suite provisions a loopback-only Kerberos realm, with a second,
directly trusted realm. It tests principal selection, credential expiry, the
service identity, cross-realm login and opt-in delegation. Production-KDC
validation and an independent delegation security review remain open; see the
[review brief](gssapi-delegation-review.md). S3
version-aware operations are implemented as described above; S3 and WebDAV
still cover documented subsets rather than every upstream extension.
See the [parity audit](upstream-parity.md) for the full list of verified
capabilities and remaining gaps.

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `No supported authentication methods available` | the server refused every credential. Check `ssh-add -l` and the server's `authorized_keys` |
| `is encrypted; supply -passphrase=<passphrase>` | an encrypted key was used without a passphrase in `-batch` mode. Pass `-passphrase=` to `open`, or load the key into the agent |
| a transfer hangs | `LSCP_TRACE=1 linscp ...` prints the first 32 bytes of each SFTP receive, which shows whether protocol data is arriving |
| you need the connection events | `-verbose` prints SSH event messages; `-log=<file>` writes the session to a file |

## Verification

Automated tests are the evidence for each feature. The
[readme](../readme.md#building-and-testing) lists the commands. Each suite
prints an evidence line that reports its passes, failures and skipped cases.
[`upstream-parity.md`](upstream-parity.md) explains how the evidence is recorded
and checked.

One of those commands guards the repository hygiene and branding. LinSCP is now
**cross-platform** (Linux, Windows, Android) via the pure-Rust workspace, so

```sh
python3 tools/check_repo_hygiene.py
# (legacy: tools/check_platform_conversion.py — now delegates to the above)
```

enforces the branding allowlist, the retired-artefact denylist, and that
`#[cfg(windows)]` / `#[cfg(target_os = "android")]` / `windows-sys` / `jni` appear only
inside `crates/linscp-platform` and `crates/linscp-tauri` (the rest of the workspace
stays OS-agnostic). It also guards `debian/` and `CMakeLists.txt` packaging parity.
`cargo test` (and `make -C source/linux check` as a thin wrapper) runs it, CTest
registers it as `repo-hygiene-check`, and CI runs it on every push.
`tools/tests/test_platform_conversion.py` keeps the legacy name but now exercises the
new hygiene rules to the same standard: it must fail on the things it claims to catch.

A second one guards the display server. LinSCP ships for both Wayland and X11
desktops, and the way an application gets that wrong is to ask for X11 alone,
so

```sh
python3 tools/check_wayland_compatibility.py
```

refuses a display-server test that reads `DISPLAY` without `WAYLAND_DISPLAY`, a
terminal started without saying which display server it draws on, an X11-only
or Wayland-only helper, a desktop entry a Wayland compositor cannot act on, a
documented terminal choice that never mentions Wayland, and the two
implementations of the detection disagreeing about the variables they read.
`make -C source/linux check` runs it, CTest registers it as
`wayland-compatibility-check`, and `tools/tests/test_wayland_compatibility.py`
has to show it failing on each of those.

Backups (`backup export|import <file>` in script mode, `crates/linscp-engine/src/backup.rs`) are distribution-agnostic: LF-only, CRLF-tolerant JSON containing sessions.ini (LF-normalized), unwrapped base64 `sessions.key` (so a Windows `dpapi1$` or Android `aks1$` backup restores on Linux), and the JSON/text stores — Debian → Windows → Android round-trips are covered in `backup`.
