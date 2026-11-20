# Alternate session hostnames

A saved remote session may specify an **Alt Hostname**, with no scheme, port,
path, or credentials. **Alt Connect** uses that host immediately with the
session's port, user, credentials, and other settings. The **Use as fallback**
switch allows the normal Connect action and automatic reconnect to try the
alternate after a definite direct TCP connection failure to the primary host.
Save the session to retain the settings.

The alternate SSH hostname uses its own known-host entry; a primary-host SSH
pin is not carried across. An unknown or changed alternate key requires the
normal user decision. TLS still verifies the alternate hostname and any
configured TLS pin. No fallback occurs after a host-key, TLS, authentication,
proxy, or ambiguous overall timeout error. Monitoring connections that request
an exact endpoint do not fall back to a different endpoint.

Automatic fallback currently applies to direct SSH/SFTP/SCP and FTP/FTPS
connections. WebDAV and S3 use request-per-operation clients that do not
establish a network connection when a tab opens; proxy and tunnel failures also
cannot safely be attributed to the destination by the current error interface.
Use **Alt Connect** for those cases. Fallback operations use the same saved
credentials, so configure an alternate only if it is trusted to receive them.
