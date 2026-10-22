/*
 * Session: one SSH connection to an SFTP server, driving libssh
 * (ssh_session / ssh_channel / sftp_session, held as void * so this
 * header stays free of the library's types).
 *
 * The console client keeps exactly one session at a time; the SFTP
 * client in SftpClient.cpp reaches it through CurrentSession().
 */

#ifndef LINSCP_SESSION_H
#define LINSCP_SESSION_H

#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "Platform.h"
#include "SshTunnel.h"

namespace linscp {

/* True when 'protocol' is served by the native libssh SFTP engine rather
 * than by the curl backend of ProtocolClient. All protocol dispatch in
 * Script goes through this helper, never through a bare comparison
 * against "sftp". */
inline bool UseNativeSftp(const std::string & protocol)
{
    return protocol == "sftp";
}

/*
 * True when 'protocol' is served by the native SCP engine (ScpClient.cpp)
 * rather than by curl: the server's shell answers the directory and
 * metadata operations and the rcp protocol carries the bytes, both over an
 * SSH connection this client makes itself. 'ssh' is the other spelling of
 * the same protocol, kept because a curl URL calls it that. An SSH session
 * of either spelling is therefore never handed to curl, which is what used
 * to make a SHA-256 host key pin depend on how the installed curl was
 * built.
 */
inline bool UseNativeScp(const std::string & protocol)
{
    return protocol == "scp" || protocol == "ssh";
}

/*
 * The proxy of a session, under the names upstream's session settings use
 * ('None;SOCKS4;SOCKS5;HTTP;Telnet;Cmd'). 'Local' is upstream's pmCmd: a
 * command run locally whose standard input and output carry the connection.
 */
enum class ProxyMethod
{
    None,
    Socks4,
    Socks5,
    Http,
    Telnet,
    Local
};

/* Upstream's spelling of a method, as 'ProxyMethod=' accepts it. */
const char * ProxyMethodName(ProxyMethod method);
/* The port a method uses when the session does not name one. */
int ProxyDefaultPort(ProxyMethod method);
/* Accepts upstream's names ('socks5', 'Cmd') and its numbers ('0'..'5'). */
bool ParseProxyMethod(const std::string & text, ProxyMethod & method);

struct ProxySettings
{
    ProxyMethod method;
    std::string host;
    int port;               /* 0: use ProxyDefaultPort(method) */
    std::string userName;
    std::string password;
    /* 'ProxyTelnetCommand': the telnet command, or - for the 'Local'
     * method - the command to run. '%host' and '%port' are substituted. */
    std::string command;
    /* 'ProxyExcludeList': destinations reached without the proxy. */
    std::string excludeList;
    /* 'ProxyDNS': 0 = resolve here, 1 = automatic, 2 = let the proxy
     * resolve. Automatic follows the transport: everything but SOCKS4
     * leaves the name to the proxy. */
    int dns;
    /* 'ProxyLocalhost': send localhost through the proxy too. */
    bool evenLocalhost;

    ProxySettings() : method(ProxyMethod::None), port(0), dns(1),
        evenLocalhost(false) {}

    bool Active() const { return method != ProxyMethod::None; }
    /* The port actually used: the one given, or the method's default. */
    int EffectivePort() const
        { return port > 0 ? port : ProxyDefaultPort(method); }
    /* Whether the proxy resolves the destination name, which is what
     * decides between curl's 'socks5' and 'socks5h'. */
    bool ResolvesRemotely() const
        { return dns == 2 || (dns == 1 && method != ProxyMethod::Socks4); }
    bool operator==(const ProxySettings & other) const;
};

/*
 * One 'name=value' pair of a '-rawsettings' switch. The names are
 * upstream's session setting names; this build applies the proxy ones and
 * refuses the rest by name rather than accepting a setting it would drop.
 * Returns false with 'error' explaining the refusal.
 */
bool ApplyProxyRawSetting(const std::string & name, const std::string & value,
    ProxySettings & proxy, std::string & error);
/* The setting names '-rawsettings' accepts, for error messages and help. */
std::vector<std::string> ProxyRawSettingNames();
/* True when 'name' is a raw setting this build applies. */
bool IsProxyRawSettingName(const std::string & name);
/*
 * Checks a proxy configuration before a connection is made: a method that
 * needs a host has one, a port is in range, and the command of a telnet or
 * local proxy is there. Returns false with 'error' saying what is missing.
 */
bool ValidateProxySettings(const ProxySettings & proxy, std::string & error);

/*
 * Whether a curl-backed protocol can use this proxy. SOCKS and HTTP proxies
 * are curl options; a telnet or local command is not, and connecting
 * without the proxy the session asked for is worse than refusing.
 */
bool ProxyUsableByCurl(const ProxySettings & proxy, std::string & error);

/*
 * The FTP engine's settings, under upstream's session-setting names:
 * 'FtpPasvMode' (true = passive), 'FtpForcePasvIp' (which address a PASV
 * reply may name), 'FtpUseMlsd' (whether MLSD is used and what happens
 * when the server refuses it) and 'FtpAccount' (the ACCT name of an
 * account that needs one). The two auto switches are upstream's
 * TAutoSwitch: 0 = off, 1 = automatic, 2 = on.
 */
struct FtpSettings
{
    bool passiveMode;
    int forcePasvIp;
    int useMlsd;
    std::string account;

    FtpSettings() : passiveMode(true), forcePasvIp(1), useMlsd(1) {}
};

/*
 * TLS policy of the protocols curl serves over TLS (FTPS and HTTPS/DAV).
 * 'ftpsMode' is upstream's TFtps: 0 none, 1 implicit, 2 explicit SSL,
 * 3 explicit TLS; an 'ftps://' URL means implicit, an 'ftpes://' URL
 * explicit TLS. The versions are upstream's numbers (10..13); 0 keeps
 * the library default. The certificate, key and authority files are what
 * a TLS-library-less client can verify with: curl takes files, so
 * 'pinnedPublicKey' is a PEM/DER file or a 'sha256//BASE64' pin.
 */
struct TlsSettings
{
    int ftpsMode;
    int minVersion;
    int maxVersion;
    std::string clientCertificate;
    std::string clientKey;
    std::string caFile;
    std::string caDirectory;
    std::string pinnedPublicKey;

    TlsSettings() : ftpsMode(0), minVersion(0), maxVersion(0) {}
};

/*
 * S3 object write and request policy: storage class, canned ACL,
 * server-side encryption, KMS key ID, requester-pays and custom user
 * metadata headers, all signed with AWS Signature Version 4.
 */
struct S3Settings
{
    std::string storageClass;
    std::string acl;
    std::string serverSideEncryption;
    std::string kmsKeyId;
    bool requestPayer;
    std::map<std::string, std::string> metadata;

    S3Settings() : requestPayer(false) {}

    bool Empty() const
    {
        return storageClass.empty() && acl.empty() &&
            serverSideEncryption.empty() && kmsKeyId.empty() &&
            !requestPayer && metadata.empty();
    }
};

/*
 * Kerberos single-sign-on under upstream's session-setting names:
 * 'AuthGSSAPI' (try gssapi-with-mic when the server offers it),
 * 'AuthGSSAPIKEX' (offer the RFC 4462 key exchanges, under which the
 * server is authenticated by Kerberos instead of a host key),
 * 'GSSAPIFwdTGT' (delegate credentials to the server - off unless a
 * session asks, because a delegated ticket lets the server act as the
 * user elsewhere) and 'LogicalHostName' (the name the service ticket
 * is asked for, when the server's Kerberos identity is not the host
 * name it was reached by). The defaults are upstream's.
 */
struct GssapiSettings
{
    bool auth;
    bool authKex;
    bool forwardTgt;
    std::string logicalHost;

    GssapiSettings() : auth(true), authKex(false), forwardTgt(false) {}
};

struct SessionOptions
{
    std::string protocol;
    std::string hostName;
    int portNumber;
    std::string userName;
    std::string password;
    std::string privateKeyFile;
    std::string keyPassphrase;
    /* Expected host key: empty = use the cache/ask, "*" = accept any. */
    std::string hostKey;
    /* GUI approvals may be tab-only; persist explicit pins only on request. */
    bool cachePinnedHostKeys;
    /* Directory to change to once connected (from the URL path). */
    std::string initialDirectory;
    int timeoutSecs;
    bool verbose;
    /* The proxy this session connects through, if any. */
    ProxySettings proxy;
    /* An authenticated SSH jump host, separate from the destination. */
    SshTunnelSettings tunnel;
    /* Runtime only: loopback SOCKS5 port of an active jump for a
     * curl/FTP destination. 0 means the session has no SOCKS listener.
     * Never persisted; Open() fills it when a non-SSH tunnel starts. */
    int tunnelSocksPort;
    /* Kerberos/GSSAPI authentication policy. */
    GssapiSettings gssapi;
    /* The FTP engine's policy, the TLS policy and S3 object policy. */
    FtpSettings ftp;
    TlsSettings tls;
    S3Settings s3;
    /* WebDAV lock tokens this session holds, by remote path. An upload,
     * delete or move of a locked path carries its token in the If header,
     * so the server refuses the write when the lock is gone instead of
     * accepting one the lock was meant to prevent. */
    std::map<std::string, std::string> davLocks;
    /* WebDAV ETag preconditions: If-Match and If-None-Match values per
     * path, set by the 'etag' command.  If-Match: only write if the
     * server's ETag matches.  If-None-Match: only write if the server's
     * ETag does NOT match (or the resource does not exist). */
    struct EtagPrecondition
    {
        std::string ifMatch;     /* empty: no If-Match header */
        std::string ifNoneMatch; /* empty: no If-None-Match header */
    };
    std::map<std::string, EtagPrecondition> davEtags;

    SessionOptions();
};

/*
 * Applies one 'name=value' pair of '-rawsettings'. The names are
 * upstream's session setting names; this build applies the proxy, FTP and
 * TLS ones and refuses every other name instead of accepting a setting it
 * would drop. Returns false with 'error' explaining the refusal.
 */
bool ApplySessionRawSetting(const std::string & name, const std::string & value,
    SessionOptions & options, std::string & error);
/* The setting names '-rawsettings' accepts, for error messages and help. */
std::vector<std::string> SessionRawSettingNames();
/* True when 'name' is a raw setting this build applies. */
bool IsSessionRawSettingName(const std::string & name);
/*
 * Checks the settings of a session before it is made: the proxy, the TLS
 * policy (a certificate fingerprint cannot be checked by this build, and
 * saying so beats connecting without verification) and the FTP settings.
 */
bool ValidateSessionSettings(const SessionOptions & options, std::string & error);
/* Checks runtime SSH capabilities and setting combinations immediately
 * before a connection; saved preferences may retain settings this build
 * cannot use so they can be carried to a compatible libssh build. */
bool ValidateSessionCapabilities(const SessionOptions & options,
    std::string & error);
/* The key-exchange list to offer when GSSAPI key exchange is on: the
 * RFC 4462 algorithms first, then this client's ordinary ones. Empty
 * when it is off, when the loaded libssh cannot use GSSAPI, or when a
 * host key is pinned - a pinned key must be checked, and a Kerberos
 * key exchange presents none. */
std::string GssapiKeyExchangeList(const SessionOptions & options);
/* The key-exchange list to offer when GSSAPI key exchange is on: the
 * RFC 4462 algorithms first, then this client's ordinary ones. Empty
 * when it is off, when the loaded libssh cannot use GSSAPI, or when a
 * host key is pinned - a pinned key must be checked, and a Kerberos
 * key exchange presents none. */
std::string GssapiKeyExchangeList(const SessionOptions & options);
/* True when the session talks to the FTP server over implicit TLS, which
 * is what an 'ftps://' URL or 'Ftps=1' asks for. */
bool SessionUsesImplicitTls(const SessionOptions & options);
/* True when this session's connection is protected by TLS: ftps://,
 * ftp:// with a TLS mode set, https://, webdav:// or s3://. */
bool SessionUsesTls(const SessionOptions & options);
/* The port the session uses when its URL did not give one, honouring the
 * TLS mode: 990 for implicit FTPS, 21 for FTP and explicit FTPS. */
int SessionDefaultPort(const std::string & protocol, int ftpsMode);
/*
 * The SHA-256 host key pin of a '-hostkey=' value, as unpadded base64
 * (the way OpenSSH prints it). Accepts the hex digest with
 * optional ':' separators, OpenSSH's 'SHA256:base64' and curl's own
 * 'sha256//base64' - all of them the digest of the same host key, so the
 * conversion decodes and does not re-hash. Returns false for a value that
 * is neither.
 */
bool HostKeySha256(const std::string & hostKey, std::string & base64);
/* Whether a URL scheme is one this client connects with, and the protocol
 * name it stands for. Returns false for anything else, an empty scheme
 * included. */
bool ResolveProtocolScheme(const std::string & scheme, std::string & protocol);
/* Parses 'sftp://[user[:password]@]host[:port]/[path]' (the password may
 * also be given by -password= or LINSCP_PASSWORD). */
bool ParseSiteUrl(const std::string & url, SessionOptions & options,
    std::string & error);

class Session
{
public:
    Session();
    ~Session();

    bool Open(const SessionOptions & options, std::string & error);
    void Close();
    bool IsOpen() const { return mOpen; }
    bool IsAlive() const { return mAlive; }

    const SessionOptions & Options() const { return mOptions; }
    /* The WebDAV lock of a path: set by the 'lock' command, used by the
     * upload, delete and move paths, and dropped by 'unlock'. */
    void SetDavLock(const std::string & remotePath, const std::string & token);
    void ClearDavLock(const std::string & remotePath);
    const std::string & DavLockFor(const std::string & remotePath) const;
    /* The WebDAV ETag preconditions the 'etag' command records. They live
     * with the session for the same reason the lock tokens do: an If-Match
     * value belongs to the connection that read the resource. */
    void SetDavEtag(const std::string & remotePath, const std::string & ifMatch,
        const std::string & ifNoneMatch);
    void ClearDavEtag(const std::string & remotePath);
    /* struct ssh_session_s * / struct sftp_session_struct *, for the
     * SFTP client and the key helpers. */
    void * SshHandle() const { return mSsh; }
    void * SftpHandle() const { return mSftp; }
    const std::string & ConnectionError() const { return mConnectionError; }
    int ExitCode() const;
    std::string UserName() const;
    std::string HostDescription() const;

    /* Transport used by the SFTP layer. ReceiveData blocks (running the
     * event loop) until len bytes are available or the session dies. */
    bool SendData(const char * data, size_t len);
    size_t SendBufferSize();
    bool ReceiveData(char * buffer, size_t len);

    /* Called by the seat's output handler and by the main loop. */
    void PushReceivedData(const void * data, size_t len);
    bool Pump();

    /* Receives the channel data (stdout) of this session instead of
     * buffering it for the SFTP protocol layer. Used by exec sessions. */
    typedef void (*OutputSinkFn)(void * ctx, const char * data, size_t len);
    void SetOutputSink(OutputSinkFn sink, void * ctx);
    /* Where the seat hands channel data over: to the output sink of an
     * exec session, or into the SFTP receive buffer. */
    void DeliverChannelData(const void * data, size_t len);

    /* Runs 'command' on the server in a one-shot second SSH connection
     * (the 'exec' request instead of the SFTP subsystem), printing its
     * output as it arrives, and returns when the command ends. The
     * current session, if any, stays connected while this runs. */
    static bool ExecRemote(const SessionOptions & options,
        const std::string & command, std::string & error);

    /* What a captured ExecRemote made of the command: its exit code
     * (INT_MAX when the server sent none) and the two output streams
     * kept apart. */
    struct ExecCaptured
    {
        int exitCode;
        std::string output;
        std::string errorOutput;
    };

    /* ExecRemote that also keeps the output: stdout is printed as it
     * arrives and saved, stderr is saved and printed when the command
     * ends (so the two streams a caller records, as the XML log does,
     * are the server's own and not an interleaving). The result says
     * how the command ended even when it failed. */
    static bool ExecRemoteCaptured(const SessionOptions & options,
        const std::string & command, std::string & error,
        ExecCaptured & captured);

    /*
     * The one-shot exec channel the native SCP engine drives: the command
     * runs in a session of its own (never the one the SFTP transport glue
     * addresses), its standard output is buffered for ReceiveData and
     * TakeAllReceived instead of being printed, its standard input is
     * SendData, and CaptureStderr keeps its error output for the caller's
     * message. Both halves of the SCP protocol live on this channel: a
     * shell command ('ls -l', 'mkdir', 'chmod') answers a directory or
     * metadata operation, and 'scp -f'/'scp -t' carries the bytes of a
     * transfer with the engine speaking the rcp wire protocol itself.
     */
    bool OpenExec(const SessionOptions & options, const std::string & command,
        std::string & error);
    /* Everything the channel has produced so far, drained from the buffer. */
    bool TakeAllReceived(std::string & out);
    /* Tells the server no more input is coming (an SSH channel EOF), so a
     * command that reads its standard input - 'scp -t' does - can finish
     * and report an exit status instead of waiting. */
    bool SendEof();
    /* Runs the event loop until the remote command ends. */
    void PumpUntilExit();
    void CaptureStderr(bool capture) { mCaptureStderr = capture; }
    bool CapturesStderr() const { return mCaptureStderr; }
    void AppendCapturedStderr(const void * data, size_t len);
    const std::string & CapturedStderr() const { return mCapturedStderr; }

    /* Called by the seat. */
    void NotifyRemoteExit();
    void SetConnectionError(const std::string & error);
    void SetUserName(const std::string & userName) { mUserName = userName; }
    bool PasswordUsed() const { return mPasswordUsed; }
    void MarkPasswordUsed() { mPasswordUsed = true; }

    /*
     * An interactive shell on the server: a channel with a PTY, for the
     * embedded terminal of the graphical client (and the '-shell' mode
     * of the console client, which is what the GUI spawns). Output of
     * both the channel's stdout and stderr goes to the output sink (see
     * SetOutputSink); input goes through SendData; Pump() reads what is
     * available. OpenShell connects a session of its own, like OpenExec.
     */
    bool OpenShell(const SessionOptions & options, int columns, int rows,
        std::string & error);
    bool ShellResize(int columns, int rows);

    /* Host key policy, used when the transport verifies the server key. */
    bool HostKeyMatches(const std::string & fingerprint) const;
    bool AcceptAnyHostKey() const { return mOptions.hostKey == "*"; }
    bool IsTunnelTransport() const { return mTunnelTransport; }
    bool ExpectHostKey() const { return !mOptions.hostKey.empty() && mOptions.hostKey != "*"; }
    const std::string & ExpectedHostKey() const { return mOptions.hostKey; }

private:
    Session(const Session &);
    Session & operator=(const Session &);

    bool TakeReceivedData(char * buffer, size_t len);
    void HandleChannelData(const void * data, size_t len, bool isStderr);
    struct ChannelCallbacks;

    SessionOptions mOptions;
    void * mSsh;               /* struct ssh_session_s * */
    int mTransportSocket;      /* caller-owned SSH_OPTIONS_FD (libssh >= 0.10) */
    std::unique_ptr<SshJumpTunnel> mTunnel;
    bool mTunnelTransport;    /* host-key diagnostics name the jump host */
    void * mChannel;           /* struct ssh_channel_s * (exec/shell) */
    std::unique_ptr<ChannelCallbacks> mChannelCallbacks;
    void * mSftp;              /* struct sftp_session_struct * */
    int mExitCode;             /* channel exit status; INT_MAX: none yet */
    bool mShellMode;           /* channel is a PTY shell: stderr merges */
    int mShellColumns;         /* PTY size of a shell channel */
    int mShellRows;
    bool mOpen;
    bool mAlive;
    std::string mConnectionError;
    std::string mUserName;
    bool mPasswordUsed;
    std::vector<char> mReceived;
    size_t mReceivedStart;
    size_t mReceivedEnd;
    OutputSinkFn mOutputSink;
    void * mOutputSinkCtx;
    bool mCaptureStderr;
    std::string mCapturedStderr;

    /* Shared connection setup of Open() and ExecRemote(): connects and
     * starts 'program' (subsystem or exec), optionally becoming the
     * session the SFTP transport glue talks to. */
    friend class SshJumpTunnel;
    /* Authenticated SSH only; no shell, subsystem, or global current session. */
    bool OpenTunnelTransport(const SessionOptions & options, std::string & error);

    bool Connect(const SessionOptions & options, const char * program,
        bool subsystem, bool takeCurrent, std::string & error);
};

/* The one session the console client is driving, or NULL. */
Session * CurrentSession();
void SetCurrentSession(Session * session);

} // namespace linscp

#endif /* LINSCP_SESSION_H */
