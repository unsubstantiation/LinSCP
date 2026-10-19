/*
 * SSH jump-host connections for the native SFTP/SCP/SSH transports.
 * A private socket pair carries one verified destination connection over
 * an authenticated direct-tcpip channel. No TCP listener is exposed.
 *
 * The legacy -L/-R/-D parsing helpers below are not a forwarding service.
 * GSSAPI remains disabled; detecting a library is not authentication support.
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

    SshTunnelSettings() : enabled(false), portNumber(22) {}
};

class SshJumpTunnel
{
public:
    SshJumpTunnel();
    ~SshJumpTunnel();
    /* Returns one owned socket, or -1. The caller must close it after
     * disconnecting its libssh session. Stop() joins the forwarding worker. */
    int Start(const SessionOptions & destination, std::string & error);
    void Stop();

private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
    SshJumpTunnel(const SshJumpTunnel &) = delete;
    SshJumpTunnel & operator=(const SshJumpTunnel &) = delete;
};

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

/* GSSAPI is deliberately unavailable until authentication and realm tests
 * exist. This check must not imply that removing a build flag enables it. */
bool IsGssapiSupported();
bool ApplyGssapiSetting(const std::string & value, std::string & error);

} // namespace linscp

#endif /* LINSCP_SSHTUNNEL_H */
