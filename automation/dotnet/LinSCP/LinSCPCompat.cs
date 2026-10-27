// Compatibility aliases for scripts written against the upstream .NET API.
// The namespace keeps its upstream name as an API contract; implementations
// are LinSCP types. New code should use the LinSCP namespace.

namespace WinSCP
{
    public enum Protocol
    {
        Sftp = LinSCP.Protocol.Sftp,
        Scp = LinSCP.Protocol.Scp,
        Ftp = LinSCP.Protocol.Ftp,
        Webdav = LinSCP.Protocol.Webdav,
        S3 = LinSCP.Protocol.S3
    }

    public enum FtpSecure
    {
        None = LinSCP.FtpSecure.None,
        Implicit = LinSCP.FtpSecure.Implicit,
        Explicit = LinSCP.FtpSecure.Explicit
    }

    public enum SynchronizationMode
    {
        Local = LinSCP.SynchronizationMode.Local,
        Remote = LinSCP.SynchronizationMode.Remote,
        Both = LinSCP.SynchronizationMode.Both
    }

    public enum SynchronizationCriteria
    {
        None = LinSCP.SynchronizationCriteria.None,
        Time = LinSCP.SynchronizationCriteria.Time,
        Size = LinSCP.SynchronizationCriteria.Size,
        Either = LinSCP.SynchronizationCriteria.Either,
        Both = LinSCP.SynchronizationCriteria.Both
    }

    public class SessionOptions : LinSCP.SessionOptions { }
    public class TransferOptions : LinSCP.TransferOptions { }
    public class TransferEventArgs : LinSCP.TransferEventArgs { }
    public class TransferOperationResult : LinSCP.TransferOperationResult { }
    public class SynchronizationResult : LinSCP.SynchronizationResult { }
    public class CommandExecutionResult : LinSCP.CommandExecutionResult { }
    public class RemoteFileInfo : LinSCP.RemoteFileInfo { }
    public class RemoteDirectoryInfo : LinSCP.RemoteDirectoryInfo { }
    // These exceptions are bases of the LinSCP ones, not subclasses: a script
    // importing this namespace catches SessionRemoteException, and a subclass
    // here would never match the LinSCP exception actually thrown. Keeping
    // the upstream name as the base makes both spellings work.
    public class SessionRemoteException : System.Exception
    {
        public SessionRemoteException(string message) : base(message) { }
        public SessionRemoteException(string message, System.Exception inner) : base(message, inner) { }
    }
    public class SessionLocalException : System.Exception
    {
        public SessionLocalException(string message) : base(message) { }
    }
    public class Session : LinSCP.Session { }
}
