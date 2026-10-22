/*
 * SSH jump-host connections for the native SFTP/SCP/SSH transports.
 * A private socket pair carries one verified destination connection over
 * an authenticated direct-tcpip channel. No TCP listener is exposed
 * unless 'TunnelLocalPortNumber' names a port, and then the listener is
 * loopback-only, serves this one session's connection and is closed
 * with it.
 *
 * The legacy -L/-R/-D parsing helpers below are not a forwarding service.
 */

#ifndef LINSCP_SSHTUNNEL_H
#define LINSCP_SSHTUNNEL_H

#include <memory>
#include <string>
#include <vector>

namespace linscp {

struct SessionOptions;

struct SshTunnelSettings
{
    bool enabled;
    std::string hostName;
    int portNumber;
    std::string userName;
    std::string password;
    std::string privateKeyFile;
    std::string keyPassphrase;
    std::string hostKey;
    /* 'TunnelLocalPortNumber': 0 keeps the private socket pair (no
     * listener at all); a port binds that loopback port for the jump
     * session's own connection, so a firewall rule can name it. */
    int localPortNumber;

    SshTunnelSettings() : enabled(false), portNumber(22), localPortNumber(0) {}
};

class SshJumpTunnel
{
public:
    SshJumpTunnel();
    ~SshJumpTunnel();
    /* Returns one owned socket, or -1. The caller must close it after
     * disconnecting its libssh session. Stop() joins the forwarding worker. */
    int Start(const SessionOptions & destination, std::string & error);
    /* SOCKS5 listener on 127.0.0.1 for curl/FTP/WebDAV/S3 destinations.
     * Returns the bound loopback port, or -1. TunnelLocalPortNumber binds
     * that port and fails if it is taken; 0 picks an ephemeral port.
     * Each SOCKS CONNECT opens a fresh direct-tcpip channel. */
    int StartSocks(const SessionOptions & destination, std::string & error);
    int SocksPort() const;
    void Stop();

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
    SshJumpTunnel(const SshJumpTunnel &) = delete;
    SshJumpTunnel & operator=(const SshJumpTunnel &) = delete;
};

/* SOCKS5 CONNECT helpers shared by the jump listener and FTP data
 * connections. ATYP 1/3/4 (IPv4, domain, IPv6) are accepted; '*' and
 * empty destinations are refused. */
bool ParseSocks5ConnectRequest(const unsigned char * data, size_t length,
    std::string & host, int & port, std::string & error);
bool BuildSocks5ConnectRequest(const std::string & host, int port,
    std::vector<unsigned char> & out, std::string & error);
/* Connects to destHost:destPort through a SOCKS5 proxy that already
 * accepted the TCP connection on socksFd. Returns false and closes
 * nothing: the caller owns the fd. */
bool Socks5ConnectOn(int socksFd, const std::string & destHost, int destPort,
    std::string & error);
/* Opens a TCP connection to destHost:destPort through the loopback
 * SOCKS5 listener. Returns an owned socket, or -1. */
int ConnectThroughSocks5(const std::string & socksHost, int socksPort,
    const std::string & destHost, int destPort, int timeoutSecs,
    std::string & error);

/*
 * SSH tunnel specification, as the user would write it on the ssh(1)
 * command line:
 *
 *   local:   -L [bind_address:]port:host:hostport
 *   remote:  -R [bind_address:]port:host:hostport
 *   dynamic: -D [bind_address:]port
 */
enum class TunnelType { Local, Remote, Dynamic };

struct SshTunnel
{
    TunnelType type;
    std::string bindAddress;  /* empty = localhost */
    int bindPort;
    std::string remoteHost;   /* empty for dynamic */
    int remotePort;

    SshTunnel() : type(TunnelType::Local), bindPort(0), remotePort(0) {}
};

/* Parse a tunnel specification string:
 *   local  [bind:]port:host:hostport
 *   remote [bind:]port:host:hostport
 *   dynamic [bind:]port
 * Returns false with 'error' when the format is wrong. */
bool ParseTunnelSpec(const std::string & spec, TunnelType type,
    SshTunnel & tunnel, std::string & error);

/* Builds the ssh(1) command-line flags for one tunnel. */
std::string TunnelSshFlags(const SshTunnel & tunnel);

/* Whether the loaded libssh was built with GSSAPI. The public
 * ssh_gssapi_set_creds symbol is absent from no-GSSAPI builds; checking it
 * through a weak reference works even though the common auth function also
 * exists as a stub. */
bool IsGssapiSupported();
/* Whether this libssh build actually implements the RFC 4462 GSSAPI key
 * exchange algorithms (GSSAPI authentication alone is not sufficient). */
bool IsGssapiKeyExchangeSupported();

} // namespace linscp

#endif /* LINSCP_SSHTUNNEL_H */
