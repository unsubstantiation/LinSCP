# Authentication and local IPC boundaries

- SSH host keys for the destination and jump host are checked independently.
  File-transfer jump relays for FTP, WebDAV and S3 listen only on loopback and
  require a freshly generated per-relay SOCKS5 credential. Unauthenticated and
  wrong-password clients are refused. Active relay connections are closed when
  the relay stops. This does not isolate the relay from a privileged process or
  a process that can inspect the application's memory; other users may still
  attempt denial of service. An explicitly requested SSH local port accepts only
  the source endpoint reserved by the client, rather than whichever process
  connects first. External desktop-viewer port forwards are a separate,
  unauthenticated loopback interface and require a trusted local environment.
- SSH SOCKS5 proxies with a configured username require username/password
  negotiation; a proxy that selects no-auth is refused. No configured proxy is
  silently retried as a direct connection after a failed proxy handshake.
  Explicit localhost bypass and user-specified proxy exclusion rules still
  intentionally permit direct connections; rules are evaluated for the actual
  network hop (the jump host when present), and loopback IPs are parsed rather
  than inferred from a hostname prefix. Local-command proxy templates execute
  a shell by design; the destination substituted into them rejects shell syntax.
- Linux GSSAPI and Windows SSPI request mutual authentication; the negotiated
  context must confirm it before a MIC is generated. Delegation is off unless
  explicitly enabled and can expose renewable credentials to the server. The
  destination GSSAPI setting does not enable GSSAPI to the SSH jump host.
  Kerberos key exchange and Android system GSSAPI remain unsupported. Production
  KDCs, cross-realm behavior, Windows AD authentication and independent review
  of delegated credential handling remain necessary.
- Tauri IPC is in-process, not a general HTTP API. Capabilities list only local
  application windows, and the packaged CSP restricts connect-src to the IPC
  endpoints. Static policy tests are not proof against cross-origin IPC or
  local-process attacks. The UI currently permits inline scripts and event
  handlers, so CSP is not an XSS boundary: untrusted server-provided text must
  remain inert. Existing Android emulator tests cover selected rendered data and
  native command refusals; existing Linux package smoke only checks an idle GUI
  process. Untrusted navigation, active child processes, other rendering
  surfaces and physical devices still require packaged-runtime testing.
