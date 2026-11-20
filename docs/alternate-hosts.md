# Alternate session hostnames and ports

A saved remote session may specify an **Alt Hostname** (with no scheme, port,
path, or credentials) and an **Alt Port** (`1..65535`, defaulting to the
session's primary port). In the Site Manager, **Port number** sits directly
below **Host name**, and **Alt Port** sits directly below **Alt Hostname**.
**Alt Connect** uses **Alt Hostname** and **Alt Port** immediately with the
session's user, credentials, and other settings. The **Use as fallback** switch
allows the normal Connect action and automatic reconnect to try the alternate
endpoint (`Alt Hostname:Alt Port`) after a definite direct TCP connection
failure to the primary endpoint (`Host name:Port number`). Save the session to
retain the settings.

The alternate SSH endpoint uses its own `[host]:port` known-host entry; a
primary-host SSH pin is not carried across. An unknown or changed alternate key
requires the normal user decision. TLS still verifies the alternate hostname
and any configured TLS pin. No fallback occurs after a host-key, TLS,
authentication, proxy, or ambiguous overall timeout error. Monitoring
connections that request an exact endpoint do not fall back to a different
endpoint.

Automatic fallback currently applies to direct SSH/SFTP/SCP and FTP/FTPS
connections. WebDAV and S3 use request-per-operation clients that do not
establish a network connection when a tab opens; proxy and tunnel failures also
cannot safely be attributed to the destination by the current error interface.
Use **Alt Connect** for those cases. Fallback operations use the same saved
credentials, so configure an alternate only if it is trusted to receive them.
