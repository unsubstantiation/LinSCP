# Review brief: Kerberos (GSSAPI) credential delegation

**Status: awaiting an independent reviewer.** The parity-ledger row
`security.gssapi-and-tunnels` stays `partial` until a reviewer who did not
write this code signs off as described in [Closing the gap](#closing-the-gap),
and until behaviour against a production KDC is recorded. This brief helps a
reviewer start; it is not a review. Every statement about the code below can
be checked against the named functions.

## 1. Scope

In scope is the **client side** of LinSCP's GSSAPI use:

- when a Kerberos ticket-granting ticket (TGT) is delegated;
- to which hosts it goes;
- how that decision is configured, stored, validated and shown;
- what the automated tests do and do not show.

Out of scope, but relevant to the threat model:

- the GSSAPI implementations themselves (libssh and the system's MIT krb5
  mechanism);
- what an SSH server does with a delegated TGT (for OpenSSH, see
  `GSSAPICleanupCredentials`);
- KDC policy.

LinSCP never reads, copies, stores or logs ticket material itself. It turns
libssh options on or off. libssh and the GSSAPI mechanism acquire the service
ticket from the process's default credential cache (`KRB5CCNAME`) and build the
forwarded credential.

## 2. Behaviour summary

| Setting (upstream name) | Default | Effect |
| --- | --- | --- |
| `AuthGSSAPI` | on (as upstream) | `gssapi-with-mic` is tried first when the server offers it, before agent and key files, keyboard-interactive and password. If it fails, the next method is tried. |
| `GSSAPIFwdTGT` | **off** | When `1`, LinSCP sets `SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS`. libssh then requests credential delegation from GSSAPI, and the mechanism sends a forwarded TGT in the client's first context token. |
| `AuthGSSAPIKEX` | off | Offers the RFC 4462 `gss-*` key exchanges. The server is then authenticated by Kerberos instead of a host key. This is refused when a host key is pinned, and refused when the loaded libssh cannot honour it. |
| `LogicalHostName` | empty | Selects the service principal (`host/<name>`) via `SSH_OPTIONS_GSSAPI_SERVER_IDENTITY`. It never changes where the TCP connection goes. Whitespace and control characters are rejected. |

Facts a reviewer should confirm:

1. **No client identity is pinned.** `SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY` is
   never set, so the default principal of the credential cache is used. That
   includes a principal of another realm (see the cross-realm test).
2. **The delegated TGT belongs to the client's home realm.** Delegating to a
   server in a trusting realm gives that server `krbtgt/HOME@HOME`, not a
   ticket limited to the server's realm. The cross-realm test asserts this.
3. **The jump host receives the TGT too.** With an SSH jump host and
   `GSSAPIFwdTGT=1`, the TGT is delegated to the jump host as well as to the
   destination. `SshJumpTunnel::Start` and `SshJumpTunnel::StartSocks` copy the
   destination's whole GSSAPI policy except `LogicalHostName`. This matches
   upstream: WinSCP's `TSessionData::CreateTunnelData` copies `AuthGSSAPI`,
   `AuthGSSAPIKEX` and `GSSAPIFwdTGT` into the tunnel session.
4. **The delegation notice is not shown by default.** "Kerberos credentials
   will be delegated to the server (GSSAPIFwdTGT)" goes through
   `Console::LogEvent`. It appears only with `-verbose` or in a `-log` file.
5. **Delegation happens before authorization.** The forwarded TGT travels in
   the first `gssapi-with-mic` token. The server can decrypt it as soon as it
   accepts the security context, before it decides whether the principal may
   log in as the requested user. A refused login therefore does not mean the
   TGT stayed private.
6. **The GUI shares one Kerberos identity across accounts.** The GUI backend
   runs as one OS user and uses that user's credential cache for every tab.
   With optional GUI account sign-in, every signed-in account can open
   sessions that authenticate as, or delegate, that one OS user's Kerberos
   identity. The documentation already says sign-in gives no per-user
   isolation of OS resources; the ssh-agent is shared the same way.
7. **Importers never enable delegation.** The OpenSSH-config and FileZilla
   importers do not import GSSAPI settings, so `GSSAPIDelegateCredentials yes`
   in `~/.ssh/config` does not turn delegation on.

## 3. Code map

Function names are stable; line numbers are not given on purpose.

| Location | What to look at |
| --- | --- |
| `source/linux/Session.h`: `GssapiSettings` | Defaults: `auth=true`, `authKex=false`, `forwardTgt=false`. |
| `source/linux/Session.cpp`: `ApplySessionRawSetting` | The one parser for `-rawsettings`, stored sites and scripts. The boolean settings accept only `0` or `1`. |
| `source/linux/Session.cpp`: `ValidateSessionCapabilities` | Fail-closed rules: Kerberos settings are refused when libssh lacks GSSAPI or GSSAPI key exchange, and `AuthGSSAPIKEX` is refused with a pinned host key. |
| `source/linux/Session.cpp`: `Session::Connect` | Sets the delegation flag and the server identity, and logs the delegation notice. Builds the `gss-*` KEX list via `GssapiKeyExchangeList`. |
| `source/linux/Session.cpp`: `VerifyServerKey` | Host-key verification. This runs before user authentication. The `gss-*` path accepts a missing host key only if no key is pinned. |
| `source/linux/Session.cpp`: `AuthenticateServer` | Method order: `gssapi-with-mic` first, then the fallbacks. |
| `source/linux/SshTunnel.cpp`: `IsGssapiSupported`, `IsGssapiKeyExchangeSupported` | Capability detection: a weak reference to `ssh_gssapi_set_creds`, and a KEX probe on an unconnected session. |
| `source/linux/SshTunnel.cpp`: `SshJumpTunnel::Start`, `SshJumpTunnel::StartSocks` | The jump session inherits the destination's GSSAPI policy (fact 3). |
| `source/linux/SessionStore.cpp` | Persistence: `auth_gssapi`, `auth_gssapi_kex`, `gssapi_fwd_tgt`, `logical_host`. Stored values go through `ApplySessionRawSetting`. |
| `source/gui/linscp_gui.py`: `GSSAPI_RAW_FIELDS`, `GSSAPI_DEFAULTS`, `gssapi_raw_settings`, `validate_session_data` | The GUI always passes every Kerberos setting explicitly, including `GSSAPIFwdTGT=0`. |
| `source/gui/web/index.html`: `siteGssapiFwdTgt` | The site editor's delegation checkbox, unchecked by default. |

## 4. Threat model

**Asset.** The user's TGT. Whoever holds it can act as the user towards any
service of the home realm and of every realm that trusts it, until the ticket
expires, or until its renewable lifetime ends if it is renewable. A secondary
asset is the principal name, which is disclosed to the KDC and to the server.

| # | Threat | Current mitigation | Question for the reviewer |
| --- | --- | --- | --- |
| T1 | The TGT is delegated to a host the user did not mean to trust. | Off by default. Only an explicit `GSSAPIFwdTGT=1` (raw setting, stored site or GUI checkbox) enables it, and importers never set it. | Is opt-in per session enough? Should delegation to the **jump host** (fact 3) stay upstream-compatible, need its own setting, or be removed? Should the notice (fact 4) be visible by default? |
| T2 | A ticket is requested for the wrong service principal. With a forged DNS answer and host-name canonicalization, the client may request a ticket for an attacker-held principal; the TGT is encrypted for whoever holds that principal's key. | Host-key verification happens before GSSAPI user authentication, so an attacker also needs the expected host key. `LogicalHostName` can pin the service name. The CI realm uses `rdns = false`. | Should LinSCP require a verified host key or a `LogicalHostName` before it delegates? Is `dns_canonicalize_hostname = false` / `rdns = false` guidance enough? Note that `-hostkey=*` and `AuthGSSAPIKEX=1` remove the host-key layer. |
| T3 | Delegation ignores the KDC's `ok-as-delegate` policy. | None in LinSCP; the libssh option requests unconditional delegation. | Confirm against the libssh version in use (whether `GSS_C_DELEG_FLAG` or `GSS_C_DELEG_POLICY_FLAG` is requested). OpenSSH's `GSSAPIDelegateCredentials` and PuTTY behave alike. Is a policy-respecting mode needed? |
| T4 | A server that refuses the login still obtains the TGT (fact 5). | Inherent to `gssapi-with-mic` delegation. | Document only, or mitigate (for example, delegate only to principals the user pinned)? |
| T5 | Settings injection: an untrusted site file, script or GUI request turns delegation on. | Strict `0`/`1` parsing, one parser for every input path, and no import path. Site files and scripts are the user's own files. | In GUI multi-account mode (fact 6), should GSSAPI, or at least delegation, be disabled or limited to an administrator? |
| T6 | Ticket material leaks through logs. | LinSCP logs only the decision. | Check libssh output at `-verbose` (`SSH_LOG_FUNCTIONS`) for tokens or ticket data. |
| T7 | Kerberos settings are silently dropped by a libssh without GSSAPI. | `ValidateSessionCapabilities` refuses the session instead. | Are there any paths that skip this validation? |
| T8 | A trusted realm's principal is accepted when it should not be. | Authorization belongs to the server (`auth_to_local`, `.k5login`). The tests show that an unmapped principal of a trusted realm is refused. | None for LinSCP, but production guidance may be worth adding. |

## 5. Test evidence

CI (`.github/workflows/build.yml`, the **Linux (Makefile)** and **Linux (CMake)**
jobs) installs MIT krb5 (`krb5-kdc`, `krb5-admin-server`, `krb5-user`) and
`openssh-server`. It runs `source/linux/tests/LiveSftpTest.py` with
`LSCP_REQUIRE_GSSAPI_REALM=1`, and fails unless the evidence line reports
`skipped=0 failed=0`.

`LiveGssapiRealmTests` builds two loopback-only MIT realms in one `krb5kdc`:

- **`LINSCP.TEST`** holds the service principal `host/localhost`, exported to
  sshd's keytab. It also holds the user principal and `otherprincipal`.
- **`PARTNER.TEST`** is directly trusted, through `krbtgt/LINSCP.TEST@PARTNER.TEST`
  stored in both databases and named in `[capaths]`. It holds its own user
  principal and `otherprincipal`.

A private sshd accepts only GSSAPI. Its `auth_to_local` rule maps exactly
`USER@PARTNER.TEST` to the local account. The client gets a cache with no
default ticket unless a test runs `kinit`.

| Test | What it shows |
| --- | --- |
| `test_gssapi_offer_falls_back_to_password_in_order` | GSSAPI is tried first and falls back in the upstream order. |
| `test_gssapi_principal_selection_against_an_isolated_realm` | The cache's principal authenticates. A principal that does not map to the account is refused. |
| `test_gssapi_missing_and_expired_credentials_are_refused` | Missing and expired tickets do not authenticate. |
| `test_gssapi_mutual_authentication_against_an_isolated_realm` | A wrong service identity (`LogicalHostName`) is refused even with wildcard host-key acceptance. GSSAPI key exchange either works or is refused, never silently skipped. |
| `test_gssapi_delegation_stays_off_unless_requested` | By default the server session has no credential cache. With `GSSAPIFwdTGT=1` it has a valid `krbtgt/LINSCP.TEST@LINSCP.TEST`. |
| `test_gssapi_cross_realm_trust_against_an_isolated_realm` | `USER@PARTNER.TEST` logs in to a `LINSCP.TEST` service, and the client cache shows the cross-realm TGT. The unmapped `otherprincipal@PARTNER.TEST` is refused. Delegation is off by default, and on request forwards `krbtgt/PARTNER.TEST@PARTNER.TEST` with `USER@PARTNER.TEST` as the default principal. |
| GUI `SecurityTest`: `test_gssapi_settings_reach_the_core_and_never_delegate_implicitly`, `test_gssapi_and_local_port_validation` | The GUI passes `GSSAPIFwdTGT=0` unless the box is checked, and rejects malformed values. |
| `ScriptTest`: `test_a_stored_session_keeps_its_gssapi_and_tunnel_local_port` | Stored sites keep the Kerberos settings. |

**Not covered**, and needed before claiming general Kerberos parity:

- production KDCs: Active Directory, FreeIPA and Heimdal;
- referral-based and transitive (multi-hop) trust paths (only a direct
  `[capaths]` trust is tested);
- delegation through a jump host;
- non-default encryption types;
- `ok-as-delegate` handling;
- servers other than OpenSSH.

**Reproducing.** Install the packages above and a GSSAPI-enabled `libssh-dev`.
Then:

```sh
make -C source/linux clean all check
LSCP_REQUIRE_GSSAPI_REALM=1 python3 -u source/linux/tests/LiveSftpTest.py source/linux/build/linscp
```

The live suite also needs `paramiko`, `botocore`, `pyftpdlib`, `pyOpenSSL`
and `xmlschema`; CI installs them in a venv. The suite takes the binary as its
first argument and runs every class. To run only the Kerberos cases:

```sh
cd source/linux/tests
LSCP_REQUIRE_GSSAPI_REALM=1 python3 -c 'import sys, unittest
sys.argv[1:1] = ["../build/linscp"]
import LiveSftpTest as t
unittest.TextTestRunner(verbosity=2).run(
    unittest.defaultTestLoader.loadTestsFromTestCase(t.LiveGssapiRealmTests))'
```

The realm, its keytab and its caches live in a temporary directory, and every
listener is bound to `127.0.0.1`.

## 6. Reviewer checklist

- [ ] Delegation cannot happen without an explicit opt-in on any path:
      command line, `-rawsettings`, URL, script, stored site, GUI and import.
- [ ] Decide on jump-host delegation (fact 3, T1).
- [ ] Decide whether the delegation notice must be visible by default (fact 4).
- [ ] Host-key verification precedes GSSAPI user authentication on every path,
      and the effect of `-hostkey=*` and `AuthGSSAPIKEX` on T2 is acceptable or
      documented.
- [ ] Confirm the delegation flag libssh requests (T3) and decide on
      `ok-as-delegate`.
- [ ] Decide on GSSAPI and delegation in GUI multi-account mode (fact 6, T5).
- [ ] No ticket material in LinSCP or libssh output at any verbosity (T6).
- [ ] Fail-closed behaviour when GSSAPI or GSSAPI KEX is unavailable (T7).
- [ ] Cross-realm semantics: the home-realm TGT is what gets delegated (fact 2).
- [ ] The test evidence is adequate; list any missing cases.
- [ ] Agree a production-KDC validation plan (Active Directory, FreeIPA,
      Heimdal; one cross-realm trust).

## Closing the gap

The ledger row may move to `verified` only after both of these exist.

**A written review**, which records:

- the reviewer and their affiliation;
- the date and the commit reviewed;
- findings and severities, with how each was resolved or accepted;
- a link from the ledger's `sources`.

**A production-KDC validation record**, which records:

- the KDC product and version;
- the realm and trust layout;
- the client and server versions;
- the results of the cases in section 5.

Until then, `python3 tools/check_upstream_parity.py --require-full` must keep
failing.
