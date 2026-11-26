# Windows session URL handlers

URL registration is opt-in and applies only to the current Windows user. Run
`linscp-gui.exe --install-url-handlers` from a terminal to advertise LinSCP for
SFTP, SCP, FTP/FTPS, WebDAV and S3 URLs. Windows Settings controls which app is
the default for each scheme; registration does not change existing defaults.
Opening a URL offers it for review rather than connecting automatically.

Run `linscp-gui.exe --uninstall-url-handlers` to remove LinSCP's registration.
The installer refuses registry keys or the registered-app name already owned by
another application. Move or reinstall the executable, then repeat registration
to update its path. The command refuses executable paths containing percent signs
or quotation marks, because these are unsafe in a Windows URL command template.

Windows may retain a selected default after removal; change that choice in
Settings. Protocol launch and desktop integration vary by Windows version and
should not be confused with Android deep-link support.
