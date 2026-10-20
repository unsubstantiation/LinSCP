// LinSCP .NET assembly: a WinSCP.Session-shaped object model for Linux.
//
// The upstream WinSCP assembly wraps winscp.com's scripting interface. This
// library does the same for `linscp -server`: one persistent process, one
// command per line, answers ending in `LSCP-RESULT <code>`. The public types
// are the session lifecycle, listing, transfer, synchronization, cancellation,
// structured results and error propagation - not a thin CLI wrapper with no
// object model.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace LinSCP
{
    public enum Protocol
    {
        Sftp = 0,
        Scp = 1,
        Ftp = 2,
        Webdav = 3,
        S3 = 4
    }

    public enum FtpSecure
    {
        None = 0,
        Implicit = 1,
        Explicit = 3
    }

    public enum SynchronizationMode
    {
        Local = 0,
        Remote = 1,
        Both = 2
    }

    public enum SynchronizationCriteria
    {
        None = 0,
        Time = 1,
        Size = 2,
        Either = 3,
        Both = 4
    }

    public class SessionOptions
    {
        public Protocol Protocol { get; set; } = Protocol.Sftp;
        public string HostName { get; set; } = "";
        public int PortNumber { get; set; }
        public string UserName { get; set; } = "";
        public string Password { get; set; } = "";
        public string SshHostKeyFingerprint { get; set; } = "";
        public string SshPrivateKeyPath { get; set; } = "";
        public string SshPrivateKeyPassphrase { get; set; } = "";
        public FtpSecure FtpSecure { get; set; } = FtpSecure.None;
        public string TlsHostCertificateFingerprint { get; set; } = "";
        public string WebdavSecure { get { return FtpSecure == FtpSecure.Implicit ? "1" : "0"; } }
        public string GiveUpSecurityAndAcceptAnySshHostKey { get; set; } = "";
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(15);

        public string BuildUrl()
        {
            string scheme;
            switch (Protocol)
            {
                case Protocol.Scp: scheme = "scp"; break;
                case Protocol.Ftp: scheme = FtpSecure == FtpSecure.Implicit ? "ftps" : "ftp"; break;
                case Protocol.Webdav: scheme = "dav"; break;
                case Protocol.S3: scheme = "s3"; break;
                default: scheme = "sftp"; break;
            }
            int port = PortNumber;
            if (port <= 0)
            {
                if (Protocol == Protocol.Ftp) port = FtpSecure == FtpSecure.Implicit ? 990 : 21;
                else if (Protocol == Protocol.Webdav) port = 80;
                else if (Protocol == Protocol.S3) port = 443;
                else port = 22;
            }
            var user = Uri.EscapeDataString(UserName ?? "");
            var host = HostName ?? "";
            if (host.IndexOf(':') >= 0 && !host.StartsWith("[")) host = "[" + host + "]";
            return string.Format(CultureInfo.InvariantCulture, "{0}://{1}@{2}:{3}/", scheme, user, host, port);
        }
    }

    public class TransferOptions
    {
        public bool PreserveTimestamp { get; set; } = true;
        public string FileMask { get; set; } = "";
        public int SpeedLimit { get; set; }
        public bool ResumeSupport { get; set; }
    }

    public class TransferEventArgs : EventArgs
    {
        public string FileName { get; internal set; } = "";
        public string Destination { get; internal set; } = "";
        public Exception? Error { get; internal set; }
    }

    public class TransferOperationResult
    {
        public bool IsSuccess { get { return Failures.Count == 0; } }
        public List<TransferEventArgs> Transfers { get; } = new List<TransferEventArgs>();
        public List<SessionRemoteException> Failures { get; } = new List<SessionRemoteException>();
        public void Check()
        {
            if (Failures.Count > 0) throw Failures[0];
        }
    }

    public class SynchronizationResult
    {
        public bool IsSuccess { get { return Failures.Count == 0; } }
        public List<TransferEventArgs> Uploads { get; } = new List<TransferEventArgs>();
        public List<TransferEventArgs> Downloads { get; } = new List<TransferEventArgs>();
        public List<SessionRemoteException> Failures { get; } = new List<SessionRemoteException>();
        public void Check()
        {
            if (Failures.Count > 0) throw Failures[0];
        }
    }

    public class CommandExecutionResult
    {
        public string Output { get; internal set; } = "";
        public string ErrorOutput { get; internal set; } = "";
        public int ExitCode { get; internal set; }
        public bool IsSuccess { get { return ExitCode == 0; } }
        public void Check()
        {
            if (ExitCode != 0)
                throw new SessionRemoteException(string.IsNullOrEmpty(ErrorOutput) ? Output : ErrorOutput);
        }
    }

    public class RemoteFileInfo
    {
        public string Name { get; set; } = "";
        public string FullName { get; set; } = "";
        public long Length { get; set; }
        public bool IsDirectory { get; set; }
        public bool IsParentDirectory { get { return Name == ".."; } }
        public bool IsThisDirectory { get { return Name == "."; } }
        public DateTime LastWriteTime { get; set; }
        public string FilePermissions { get; set; } = "";
        public string FileType { get; set; } = "-";
        public string LinkTarget { get; set; } = "";
    }

    public class RemoteDirectoryInfo
    {
        public List<RemoteFileInfo> Files { get; } = new List<RemoteFileInfo>();
    }

    public class SessionRemoteException : Exception
    {
        public SessionRemoteException(string message) : base(message) { }
        public SessionRemoteException(string message, Exception inner) : base(message, inner) { }
    }

    public class FailedEventArgs : EventArgs
    {
        public FailedEventArgs(SessionRemoteException error) { Error = error; }
        public SessionRemoteException Error { get; }
    }

    public class SessionLocalException : Exception
    {
        public SessionLocalException(string message) : base(message) { }
    }

    public class Session : IDisposable
    {
        static readonly Regex ListingMode = new Regex(@"^[-a-zA-Z?][-rwxsStTlL]{9}[+@.]?$", RegexOptions.Compiled);
        static readonly Regex ResultMarker = new Regex(@"^LSCP-RESULT (\d+)\s*$", RegexOptions.Compiled);

        Process? _process;
        StreamWriter? _stdin;
        StreamReader? _stdout;
        StreamReader? _stderr;
        readonly object _gate = new object();
        volatile bool _aborting;
        SessionOptions? _options;

        public string ExecutablePath { get; set; } = "";
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(60);
        public bool Opened { get { return _process != null && !_process.HasExited; } }
        public string HomePath { get; private set; } = "/";
        public string Output { get; private set; } = "";

        public event EventHandler<TransferEventArgs>? FileTransferred;
        public event EventHandler<FailedEventArgs>? Failed;

        public void Open(SessionOptions sessionOptions)
        {
            if (sessionOptions == null) throw new ArgumentNullException(nameof(sessionOptions));
            if (Opened) throw new SessionLocalException("The session is already open.");
            _options = sessionOptions;
            _aborting = false;
            var psi = new ProcessStartInfo
            {
                FileName = ResolveExecutable(),
                Arguments = "-server",
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            psi.Environment["LINSCP_LANGUAGE"] = "en";
            if (!string.IsNullOrEmpty(sessionOptions.Password))
                psi.Environment["SSH_ASKPASS_REQUIRE"] = "never";
            _process = Process.Start(psi);
            if (_process == null)
                throw new SessionLocalException("Could not start the LinSCP server process.");
            _stdin = new StreamWriter(_process.StandardInput.BaseStream, new UTF8Encoding(false)) { AutoFlush = true };
            _stdout = new StreamReader(_process.StandardOutput.BaseStream, Encoding.UTF8);
            _stderr = new StreamReader(_process.StandardError.BaseStream, Encoding.UTF8);
            var banner = ReadLine(_stdout, TimeSpan.FromSeconds(15));
            if (banner == null || !banner.StartsWith("LSCP-SERVER", StringComparison.Ordinal))
            {
                var detail = Drain(_stderr);
                DisposeProcess();
                throw new SessionLocalException(
                    string.IsNullOrEmpty(detail) ? "LinSCP server did not start correctly." : detail);
            }
            var open = "open " + Quote(sessionOptions.BuildUrl());
            if (!string.IsNullOrEmpty(sessionOptions.Password))
                open += " -password=" + Quote(sessionOptions.Password);
            var hostkey = sessionOptions.SshHostKeyFingerprint;
            if (string.Equals(sessionOptions.GiveUpSecurityAndAcceptAnySshHostKey, "1", StringComparison.Ordinal) ||
                string.Equals(hostkey, "*", StringComparison.Ordinal))
                hostkey = "*";
            if (!string.IsNullOrEmpty(hostkey))
                open += " -hostkey=" + Quote(hostkey);
            if (!string.IsNullOrEmpty(sessionOptions.SshPrivateKeyPath))
                open += " -privatekey=" + Quote(sessionOptions.SshPrivateKeyPath);
            if (!string.IsNullOrEmpty(sessionOptions.SshPrivateKeyPassphrase))
                open += " -passphrase=" + Quote(sessionOptions.SshPrivateKeyPassphrase);
            var opened = Run(open, sessionOptions.Timeout);
            if (opened.Code != 0)
            {
                DisposeProcess();
                throw new SessionRemoteException(Failure(opened, "Failed to open session."));
            }
            Run("option confirm off", Timeout);
            var pwd = Run("pwd", Timeout);
            if (pwd.Code == 0)
            {
                foreach (var line in pwd.Output)
                {
                    if (line.StartsWith("/", StringComparison.Ordinal))
                    {
                        HomePath = line.Trim();
                        break;
                    }
                }
            }
        }

        public void Close()
        {
            if (!Opened) return;
            try { Run("close", TimeSpan.FromSeconds(15)); } catch { }
            try { Run("exit", TimeSpan.FromSeconds(15)); } catch { }
            DisposeProcess();
        }

        public void Abort()
        {
            _aborting = true;
            try
            {
                if (_process != null && !_process.HasExited)
                    _process.Kill();
            }
            catch (InvalidOperationException) { }
        }

        public TransferOperationResult GetFiles(string remotePath, string localPath, bool remove = false, TransferOptions? options = null)
        {
            return Transfer("get", remotePath, localPath, remove, options, download: true);
        }

        public TransferOperationResult PutFiles(string localPath, string remotePath, bool remove = false, TransferOptions? options = null)
        {
            return Transfer("put", localPath, remotePath, remove, options, download: false);
        }

        public RemoteDirectoryInfo ListDirectory(string path)
        {
            EnsureOpen();
            var command = "ls -la " + Quote(string.IsNullOrEmpty(path) ? "." : path);
            var response = Run(command, Timeout);
            if (response.Code != 0)
                throw new SessionRemoteException(Failure(response, "Cannot list the directory."));
            var info = new RemoteDirectoryInfo();
            foreach (var entry in ParseListing(response.Output, path))
                info.Files.Add(entry);
            return info;
        }

        public bool FileExists(string path)
        {
            EnsureOpen();
            var response = Run("stat " + Quote(path), Timeout);
            return response.Code == 0;
        }

        public RemoteFileInfo GetFileInfo(string path)
        {
            EnsureOpen();
            var parent = path;
            var name = path;
            var slash = path.LastIndexOf('/');
            if (slash >= 0)
            {
                name = path.Substring(slash + 1);
                parent = slash == 0 ? "/" : path.Substring(0, slash);
            }
            var listing = ListDirectory(string.IsNullOrEmpty(parent) ? "." : parent);
            foreach (var file in listing.Files)
            {
                if (file.Name == name) return file;
            }
            throw new SessionRemoteException("The file does not exist: " + path);
        }

        public CommandExecutionResult ExecuteCommand(string command)
        {
            EnsureOpen();
            if (command != null && command.IndexOfAny(new[] { '\n', '\r' }) >= 0)
                throw new SessionLocalException("A LinSCP command must be a single line.");
            var response = Run("call " + command, Timeout);
            var result = new CommandExecutionResult
            {
                Output = string.Join("\n", response.Output),
                ErrorOutput = string.Join("\n", response.Errors),
                ExitCode = response.Code
            };
            if (result.ExitCode != 0)
                OnFailed(new SessionRemoteException(Failure(response, "The remote command failed.")));
            return result;
        }

        public SynchronizationResult SynchronizeDirectories(
            SynchronizationMode mode, string localPath, string remotePath,
            bool removeFiles = false, bool mirror = false, SynchronizationCriteria criteria = SynchronizationCriteria.Time,
            TransferOptions? options = null)
        {
            EnsureOpen();
            var word = mode == SynchronizationMode.Remote ? "remote" :
                       mode == SynchronizationMode.Both ? "both" : "local";
            var command = new StringBuilder("synchronize " + word);
            if (removeFiles) command.Append(" -delete");
            if (mirror) command.Append(" -mirror");
            switch (criteria)
            {
                case SynchronizationCriteria.None: command.Append(" -criteria=none"); break;
                case SynchronizationCriteria.Size: command.Append(" -criteria=size"); break;
                case SynchronizationCriteria.Either: command.Append(" -criteria=either"); break;
                case SynchronizationCriteria.Both: command.Append(" -criteria=both"); break;
                default: command.Append(" -criteria=time"); break;
            }
            if (options != null && !string.IsNullOrEmpty(options.FileMask))
                command.Append(" -filemask=").Append(Quote(options.FileMask));
            command.Append(' ').Append(Quote(localPath)).Append(' ').Append(Quote(remotePath));
            var response = Run(command.ToString(), Timeout);
            var result = new SynchronizationResult();
            if (response.Code != 0)
            {
                var error = new SessionRemoteException(Failure(response, "Synchronization failed."));
                result.Failures.Add(error);
                OnFailed(error);
            }
            return result;
        }

        public void Dispose()
        {
            Close();
        }

        TransferOperationResult Transfer(string verb, string source, string destination, bool remove, TransferOptions? options, bool download)
        {
            EnsureOpen();
            var command = new StringBuilder(verb);
            if (options != null && options.PreserveTimestamp) command.Append(" -preservetime");
            if (options != null && options.ResumeSupport) command.Append(" -resume");
            if (options != null && options.SpeedLimit > 0)
                command.Append(" -speed=").Append(options.SpeedLimit.ToString(CultureInfo.InvariantCulture));
            if (options != null && !string.IsNullOrEmpty(options.FileMask))
                command.Append(" -filemask=").Append(Quote(options.FileMask));
            command.Append(' ').Append(Quote(source)).Append(' ').Append(Quote(destination));
            var response = Run(command.ToString(), Timeout);
            var result = new TransferOperationResult();
            var transfer = new TransferEventArgs { FileName = source, Destination = destination };
            if (response.Code != 0)
            {
                var error = new SessionRemoteException(Failure(response, download ? "The download failed." : "The upload failed."));
                transfer.Error = error;
                result.Failures.Add(error);
                OnFailed(error);
            }
            else if (remove)
            {
                var rm = download ? Run("rm " + Quote(source), Timeout)
                                  : Run("rm " + Quote(source), Timeout);
                // Local delete of an uploaded source is the caller's, matching WinSCP's
                // TransferOptions. The remote side is removed only for GetFiles.
                if (download && rm.Code != 0)
                {
                    var error = new SessionRemoteException(Failure(rm, "The source could not be removed."));
                    result.Failures.Add(error);
                    OnFailed(error);
                }
            }
            result.Transfers.Add(transfer);
            FileTransferred?.Invoke(this, transfer);
            return result;
        }

        void OnFailed(SessionRemoteException error)
        {
            Failed?.Invoke(this, error);
        }

        void EnsureOpen()
        {
            if (!Opened) throw new SessionLocalException("The session is not open.");
            if (_aborting) throw new SessionLocalException("The session was aborted.");
        }

        sealed class Response
        {
            public int Code;
            public List<string> Output = new List<string>();
            public List<string> Errors = new List<string>();
        }

        Response Run(string command, TimeSpan timeout)
        {
            if (command.IndexOfAny(new[] { '\n', '\r' }) >= 0)
                throw new SessionLocalException("A LinSCP command must be a single line.");
            lock (_gate)
            {
                EnsureOpen();
                _stdin!.WriteLine(command);
                var output = new List<string>();
                var errors = new List<string>();
                var deadline = DateTime.UtcNow + (timeout <= TimeSpan.Zero ? Timeout : timeout);
                while (true)
                {
                    if (_aborting) throw new SessionLocalException("The session was aborted.");
                    var remaining = deadline - DateTime.UtcNow;
                    if (remaining <= TimeSpan.Zero)
                    {
                        Abort();
                        throw new SessionLocalException("The LinSCP command did not answer in time; the session was closed.");
                    }
                    var line = ReadLine(_stdout!, remaining);
                    if (line == null)
                    {
                        var detail = Drain(_stderr!);
                        DisposeProcess();
                        throw new SessionLocalException(string.IsNullOrEmpty(detail)
                            ? "The LinSCP server process ended unexpectedly."
                            : detail);
                    }
                    var match = ResultMarker.Match(line);
                    if (match.Success)
                    {
                        var code = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
                        Output = string.Join("\n", output);
                        return new Response { Code = code, Output = output, Errors = errors };
                    }
                    output.Add(line);
                }
            }
        }

        static string Failure(Response response, string fallback)
        {
            if (response.Errors.Count > 0) return string.Join("\n", response.Errors);
            if (response.Output.Count > 0) return string.Join("\n", response.Output);
            return fallback;
        }

        static IEnumerable<RemoteFileInfo> ParseListing(IEnumerable<string> lines, string directory)
        {
            foreach (var raw in lines)
            {
                var text = (raw ?? "").Trim();
                if (text.Length == 0) continue;
                var parts = text.Split((char[])null, 9, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 9 || !ListingMode.IsMatch(parts[0])) continue;
                var name = parts[8];
                var target = "";
                var isLink = parts[0].StartsWith("l", StringComparison.Ordinal);
                if (isLink)
                {
                    var arrow = name.IndexOf(" -> ", StringComparison.Ordinal);
                    if (arrow >= 0)
                    {
                        target = name.Substring(arrow + 4);
                        name = name.Substring(0, arrow);
                    }
                }
                if (name == "." || name == "..") continue;
                long size;
                if (!long.TryParse(parts[4], NumberStyles.Integer, CultureInfo.InvariantCulture, out size))
                    size = 0;
                var full = directory;
                if (string.IsNullOrEmpty(full) || full == ".") full = name;
                else if (full.EndsWith("/", StringComparison.Ordinal)) full += name;
                else full = full + "/" + name;
                yield return new RemoteFileInfo
                {
                    Name = name,
                    FullName = full,
                    Length = size,
                    IsDirectory = parts[0].StartsWith("d", StringComparison.Ordinal),
                    FilePermissions = parts[0],
                    FileType = parts[0].Substring(0, 1),
                    LinkTarget = target
                };
            }
        }

        string ResolveExecutable()
        {
            if (!string.IsNullOrEmpty(ExecutablePath) && File.Exists(ExecutablePath))
                return ExecutablePath;
            var env = Environment.GetEnvironmentVariable("LINSCP_BIN");
            if (!string.IsNullOrEmpty(env) && File.Exists(env)) return env;
            var candidates = new[]
            {
                "linscp",
                "/usr/bin/linscp",
                "/usr/local/bin/linscp",
                Path.Combine(AppContext.BaseDirectory, "linscp"),
                Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "source", "linux", "build", "linscp"),
            };
            foreach (var candidate in candidates)
            {
                if (candidate == "linscp")
                {
                    var path = Environment.GetEnvironmentVariable("PATH") ?? "";
                    foreach (var dir in path.Split(Path.PathSeparator))
                    {
                        if (string.IsNullOrEmpty(dir)) continue;
                        var full = Path.Combine(dir, "linscp");
                        if (File.Exists(full)) return full;
                    }
                    continue;
                }
                if (File.Exists(candidate)) return Path.GetFullPath(candidate);
            }
            throw new SessionLocalException("linscp binary not found. Set Session.ExecutablePath or LINSCP_BIN.");
        }

        static string Quote(string value)
        {
            if (value == null) value = "";
            foreach (var ch in value)
            {
                if (ch < 32 || ch == 127)
                    throw new SessionLocalException("Value contains a control character and cannot be safely quoted.");
            }
            if (value.Length > 0 && value.IndexOfAny(new[] { ' ', '\t', '"', '\'', ';', '\\' }) < 0)
                return value;
            var escaped = value.Replace("\\", "\\\\").Replace("\"", "\\\"");
            return "\"" + escaped + "\"";
        }

        static string? ReadLine(StreamReader reader, TimeSpan timeout)
        {
            var result = reader.ReadLineAsync();
            if (timeout <= TimeSpan.Zero)
                return result.GetAwaiter().GetResult();
            if (result.Wait(timeout))
                return result.GetAwaiter().GetResult();
            return null;
        }

        static string Drain(StreamReader reader)
        {
            try { return reader.ReadToEnd(); }
            catch { return ""; }
        }

        void DisposeProcess()
        {
            try
            {
                if (_process != null && !_process.HasExited)
                {
                    try { _process.Kill(); } catch { }
                    _process.WaitForExit(2000);
                }
            }
            catch { }
            try { _stdin?.Dispose(); } catch { }
            try { _stdout?.Dispose(); } catch { }
            try { _stderr?.Dispose(); } catch { }
            try { _process?.Dispose(); } catch { }
            _stdin = null;
            _stdout = null;
            _stderr = null;
            _process = null;
        }
    }
}
