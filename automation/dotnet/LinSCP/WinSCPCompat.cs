// Compatibility aliases so a script written against WinSCP.Session can
// retarget this assembly. The types are the LinSCP object model.

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
    public class SessionRemoteException : LinSCP.SessionRemoteException
    {
        public SessionRemoteException(string message) : base(message) { }
        public SessionRemoteException(string message, System.Exception inner) : base(message, inner) { }
    }
    public class SessionLocalException : LinSCP.SessionLocalException
    {
        public SessionLocalException(string message) : base(message) { }
    }
    public class Session : LinSCP.Session { }
}
