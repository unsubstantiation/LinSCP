# SSH jump hosts

LinSCP supports one authenticated SSH jump host for an SFTP, SCP or SSH
session. It opens an SSH `direct-tcpip` channel to the destination and connects
the destination's independent SSH transport through a private socket pair.
No local TCP listener is opened. The jump host resolves the destination name;
the destination retains its own username, credentials and host-key identity.
Any configured parent proxy is used to reach the **jump host**, not to bypass
it and reach the destination directly.

This is a supported subset, **not full WinSCP tunnel or authentication parity**.
GSSAPI/Kerberos, fixed local listener ports and tunneling to curl-backed
FTP/FTPS/WebDAV/S3 destinations are not implemented. Unsupported or malformed
settings fail rather than silently make a direct connection. See the
[remaining parity plan](remaining-parity-plan.md).

## Command line

Verify **both** fingerprints through an independent trusted source before
connecting. Replace the example fingerprints and key paths below:

```sh
linscp -batch \
  -privatekey="$HOME/.ssh/destination_key" \
  -hostkey='SHA256:DESTINATION_FINGERPRINT' \
  -rawsettings=5 Tunnel=1 TunnelHostName=jump.example.com \
  TunnelUserName=jumper "TunnelPublicKeyFile=$HOME/.ssh/jump_key" \
  'TunnelHostKey=SHA256:JUMP_FINGERPRINT' \
  '-command=open sftp://user@private.internal/; ls; exit'
```

Global `-rawsettings=N` consumes exactly `N` assignments. The uncounted form
consumes the following recognized `name=value` settings. These defaults also
apply to `-shell`. An `open` or `savesession` command can specify its own
`-rawsettings` values, including overrides of a stored site.

| Setting | Meaning / default |
| --- | --- |
| `Tunnel` | `0` (disabled) or `1` (enabled) |
| `TunnelHostName` | Required jump hostname when enabled |
| `TunnelPortNumber` | Jump SSH port; default `22` |
| `TunnelUserName` | Jump username; empty uses the local account name |
| `TunnelPassword` | Jump password, independent of the destination password |
| `TunnelPublicKeyFile` | Jump private key file |
| `TunnelPassphrase` | Passphrase for that private key |
| `TunnelHostKey` | Jump fingerprint; empty uses the host-key cache/confirmation policy |
| `TunnelLocalPortNumber` | Only `0` is accepted; no TCP listener is exposed |

Use `LINSCP_TUNNEL_PASSWORD` and `LINSCP_TUNNEL_PASSPHRASE` when supplying jump
secrets to a process. `LINSCP_PASSWORD` still belongs to the **destination**.
Avoid secrets in shell history, process arguments or scripts readable by
others. Environment variables avoid the argument list but are not a vault:
the same OS user and privileged processes may be able to read them.

The upstream `TunnelPasswordPlain` and `TunnelPassphrasePlain` spellings are
also accepted as aliases for the corresponding plaintext inputs and are masked
in logs. This does not import WinSCP's encrypted password representation.

Passwords and passphrases are not saved merely by connecting. To store jump
secrets explicitly, supply `TunnelPassword`/`TunnelPassphrase` to
`savesession -rawsettings` using a private script or the GUI's save controls.
They are encrypted in `sessions.ini` using the existing per-user
`sessions.key`, with restrictive permissions. A missing/unreadable key fails a
stored tunnel closed and does not discard its ciphertext on an unrelated edit.
Disabling a stored tunnel clears its saved jump secrets.

The CLI reports `TUNNELHOSTKEY` for a refused jump key and `HOSTKEY` for a
refused destination key. `HOSTKEYSTATE <role> changed` distinguishes a mismatch
from an unknown key. Never solve a mismatch by automatically trusting `*`.

## Graphical client

Enable **Use SSH tunnel** in the site manager and supply the jump settings.
The password/passphrase storage checkbox is separate from the destination's
password storage choice. Background operations, queued transfers and the
embedded SSH terminal use the same tunnel policy.

An untrusted jump key is presented first, followed by an independent challenge
for the destination. Changed keys show a warning instead of being described as
new/uncached, and do not default to being remembered. Each hop's **Remember**
choice is independent: accepting the jump does not approve the destination.
A stale key or role confirmation is rejected.

Remembering a fingerprint stores that hop's pin in the selected site, even if
later authentication or the other hop fails. It does **not** implicitly store
the connection's passwords/passphrases or the other hop's transient pin.
Unchecked keys remain pinned only for that tab and its child operations.
The GUI sets `LINSCP_CACHE_PINNED_HOSTKEYS=0` in its core processes to prevent
implicit global caching; ordinary CLI fingerprint caching remains unchanged.
Existing host-key cache entries are still consulted.

## Reproducing the tests

With the native build dependencies (including libssh 0.10 or newer), Python
`paramiko`, and the OpenSSH `scp` executable installed:

```sh
cmake -S . -B build
cmake --build build -j
ctest --test-dir build -R live-tunnel-tests --output-on-failure
# Or, after a Makefile build:
python3 source/linux/tests/LiveTunnelTest.py source/linux/build/linscp
```

`make -C source/linux check-live` and the native CI jobs include this suite.
The fixtures use independent keys and a destination name resolvable only by the
jump server. They test SFTP/SCP bytes, exec and repeated shell exit behavior (including nonzero exits,
full stdout/stderr delivery and rejection of a status without EOF), password and
encrypted-key authentication, independent pin failures, inherited proxy routing,
slow/backpressured transfers, forwarding timeout, cancellation/interruption,
repeated socket/thread cleanup, encrypted storage and the actual GUI HTTP
challenge/remember flow. Offline unit, script, GUI security and jsdom tests
cover validation, credential handling and form behavior too.

These local fixtures are reproducible evidence for that scope, not certification
against every SSH implementation, authentication policy or network condition.
