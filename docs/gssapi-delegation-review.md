# Kerberos credential delegation review brief

**Status: awaiting independent security review and production-KDC validation.**
The `security.gssapi-and-tunnels` ledger capability remains partial. This brief
is a starting point, not a security review or a claim of general Kerberos parity.

## Current scope and behavior

The Rust SSH implementation uses the system GSSAPI runtime on Linux and SSPI
on Windows for RFC 4462 `gssapi-with-mic`. Android system GSSAPI is unavailable.
The OS credential cache or Windows logon session supplies the initiator identity.
GSSAPI authentication is enabled by default when the runtime and server support
it; delegation is **off by default**. Explicit `GSSAPIFwdTGT=1` requests
credential delegation to the destination, which may expose a TGT to that
server. Do not enable it for an untrusted server. `LogicalHostName` changes the
service principal host without changing the network destination. GSSAPI key
exchange is not implemented and requests fail closed.

Destination GSSAPI settings do not enable GSSAPI authentication or delegation
to a jump host. Verify host keys independently, including the jump host's key.
The SSH config importers do not import GSSAPI delegation settings. Consult
[SSH jump hosts](ssh-tunnels.md) and
[authentication and IPC security](authentication-ipc-security.md) for the
broader trust boundaries.

## Evidence and limitations

The Linux CI isolated MIT Kerberos/OpenSSH fixture exercises missing
credentials, wrong service identity, mutual authentication and opt-in
delegation. `bash tools/live_kerberos_ci.sh` runs it when its dependencies are
installed; see [final parity review](final-parity-review.md) for the relevant
CI run and scope. Historical `source/linux/tests/LiveSftpTest.py` cases used a
retired executable and are not current-runtime evidence.

Windows SSPI has automated tests but no documented production Active Directory
acceptance; Android, production KDCs, other SSH servers, cross-realm and
transitive trust, encryption variants, delegation policy and jump-host GSSAPI
are not established by the Linux fixture. The delegation implementation and
logging also need independent security review.

## Closing the gap

A reviewer independent of the implementation should record the reviewed commit,
affiliation, findings and resolutions, including opt-in enforcement, service
principal selection, host-key ordering, delegation flags and policy, and logging.
Production-KDC validation should record KDC and client/server versions, realm
and trust layout, and results for authentication, rejection and delegation.
Link that evidence from the ledger before upgrading its status. Even then,
other partial and missing capabilities prevent a full-parity claim.
