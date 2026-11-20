# Auto reconnect

Each saved remote session has an **Auto reconnect time (seconds)** and an
**Enable** switch. The default is off and 30 seconds; allowed intervals are
whole seconds from 1 to 3600. Save the session to apply a change. Unsaved
connections and local-to-local tabs are not restored automatically.

When a saved session connects, LinSCP records its non-secret identity in a
private `auto-reconnect.json` file. Closing the last tab for that site, deleting
the site, or explicitly locking the vault removes its restore intention. On
startup, after the vault is unlocked, enabled sites with matching recorded
identities are restored. Editing a site's protocol, host, port or username
prevents restoration of the old identity. Passwords and keys are not stored in
this file; restoration uses the saved credentials. Copying a site does not copy
its open-state intention.

The main window checks for retry work once per second while it is running;
requests are reserved by the backend so multiple windows sharing that service
do not launch the same attempt. SSH-based sessions report a lost transport;
FTP/FTPS use an idle-only NOOP probe. Request-per-operation protocols such as
WebDAV and S3 do not maintain a persistent connection to monitor. Mobile
operating systems or a suspended webview can delay timers; this is not an
operating-system background service. The application must be running and the
vault unlocked. New or changed SSH host keys still require user verification.
Authentication and private-key errors pause automatic retries until the user
saves the session or connects manually. Connection results and errors appear in
Logs. If the state file cannot be read or updated, LinSCP reports the error and
does not silently discard it.
