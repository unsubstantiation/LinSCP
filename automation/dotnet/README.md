# LinSCP .NET assembly

A LinSCP session object model for Linux. It drives `linscp -server` as the
upstream assembly drives its scripting interface.

The compatibility namespace below is retained for existing scripts. New code
should use `LinSCP`.

```csharp
using LinSCP;
// or: using WinSCP;  // compatibility aliases

var session = new Session { ExecutablePath = "/usr/bin/linscp" };
session.Open(new SessionOptions {
    Protocol = Protocol.Sftp,
    HostName = "example.test",
    UserName = "alice",
    Password = "secret",
    SshHostKeyFingerprint = "SHA256:..."
});
session.PutFiles("/tmp/file", "/incoming/file").Check();
var listing = session.ListDirectory("/");
session.Close();
```

Build with `dotnet build automation/dotnet/LinSCP/LinSCP.csproj`.
Installed copies live under `PREFIX/share/linscp/dotnet/`.

Passwords travel on the `open` command sent to the server process stdin,
never on the process command line. Values holding a control character or a
command holding a newline are refused.
