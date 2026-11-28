# SSH jump hosts

LinSCP supports one SSH jump host for SSH, SFTP and SCP sessions, and for
FTP/FTPS, WebDAV and S3 through a loopback SOCKS relay. Configure **Use SSH
tunnel** and the jump host's connection details in the Site Manager. Verify
both jump and destination host keys through an independent trusted source;
they are checked and remembered separately. A configured parent proxy is used
to reach the jump. Forwarding failure is reported, not silently retried direct.

The jump resolves the destination. For SFTP/SCP/SSH the destination transport uses
its own SSH connection and credentials. FTP/FTPS uses passive data connections;
TLS and S3 signing retain the target hostname. The loopback relay uses a fresh
per-relay SOCKS credential. An explicitly selected local tunnel port is reserved
for the client's own connection. These controls do not defend against a
privileged process or one able to inspect the application's memory; a local
attacker may still cause denial of service.

External RDP/VNC/SPICE viewers use a separate unauthenticated loopback forward
and require a trusted local environment. If a requested forward cannot be
established, the desktop launch fails rather than falling back to direct.
Tunneled SPICE with a separate TLS port is refused. X11/Waypipe jump forwarding
is not supported. See [authentication and IPC boundaries](authentication-ipc-security.md).

## Kerberos

The current Rust SSH implementation uses system GSSAPI on Linux or SSPI on
Windows. Delegation is off by default; explicitly enabling it can expose
credentials to the destination server. Destination GSSAPI settings do **not**
enable GSSAPI or delegation to the jump host. Android system GSSAPI and GSSAPI
key exchange are unsupported. The isolated Linux MIT KDC/OpenSSH fixture tests
missing credentials, wrong service identity, mutual authentication and opt-in
delegation; production KDCs, Windows AD, cross-realm behavior and an independent
security review remain open. See the [delegation review brief](gssapi-delegation-review.md).

## Verification

Linux and Windows Rust tests cover mock SSH jump routing, host-key checks,
authenticated SOCKS relay and proxy failure behavior. The Linux KDC fixture is
run by `bash tools/live_kerberos_ci.sh` in an isolated CI environment with its
required MIT Kerberos, OpenSSH and sudo dependencies. The older
`source/linux/tests/LiveTunnelTest.py` targets the retired `linscp` executable
and is not evidence for the current GUI. See the
[final parity review](final-parity-review.md) for run links and limitations.
