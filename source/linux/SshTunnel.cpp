/*
 * SshTunnel: SSH port-forwarding and GSSAPI detection.
 */

#include "SshTunnel.h"
#include "Session.h"
#include "Texts.h"

#include <atomic>
#include <cerrno>
#include <thread>
#include <system_error>
#include <poll.h>
#include <sys/socket.h>
#include <libssh/libssh.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include <unistd.h>

#include "Platform.h"

namespace linscp {

namespace {

/*
 * One port number out of a tunnel specification.
 *
 * atoi() was used here before: it stops at the first character that is
 * not a digit and returns 0 for text, so 'localhost:80x' parsed as 80 and
 * an overflowed '99999999999999' was undefined behaviour rather than an
 * error. A tunnel that binds the wrong port is not something to be
 * approximate about, so the whole field has to be digits and in range.
 */
bool ParsePort(const std::string & text, int & port)
{
    if (text.empty() || text.size() > 5)
    {
        return false;
    }
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] < '0' || text[i] > '9')
        {
            return false;
        }
    }
    const long value = strtol(text.c_str(), NULL, 10);
    if (value < 1 || value > 65535)
    {
        return false;
    }
    port = static_cast<int>(value);
    return true;
}



} // namespace

bool ParseTunnelSpec(const std::string & spec, TunnelType type,
    SshTunnel & tunnel, std::string & error)
{
    tunnel.type = type;
    tunnel.bindAddress.clear();
    tunnel.bindPort = 0;
    tunnel.remoteHost.clear();
    tunnel.remotePort = 0;

    if (spec.empty())
    {
        error = "Empty tunnel specification.";
        return false;
    }

    /* Split on colons.  The formats are:
     *   port:host:hostport    (local/remote)
     *   bind:port:host:hostport (local/remote with bind)
     *   port                  (dynamic)
     *   bind:port             (dynamic with bind) */
    std::vector<std::string> parts;
    std::istringstream stream(spec);
    std::string part;
    while (std::getline(stream, part, ':'))
    {
        parts.push_back(part);
    }

    if (type == TunnelType::Dynamic)
    {
        if (parts.size() == 1)
        {
            if (!ParsePort(parts[0], tunnel.bindPort))
            {
                error = "Dynamic tunnel format: [bind_address:]port, with a "
                    "port from 1 to 65535.";
                return false;
            }
        }
        else if (parts.size() == 2)
        {
            tunnel.bindAddress = parts[0];
            if (!ParsePort(parts[1], tunnel.bindPort))
            {
                error = "Dynamic tunnel format: [bind_address:]port, with a "
                    "port from 1 to 65535.";
                return false;
            }
        }
        else
        {
            error = "Dynamic tunnel format: [bind_address:]port";
            return false;
        }
    }
    else
    {
        if (parts.size() == 3)
        {
            if (!ParsePort(parts[0], tunnel.bindPort))
            {
                error = "Tunnel format: [bind_address:]port:host:hostport, "
                    "with ports from 1 to 65535.";
                return false;
            }
            tunnel.remoteHost = parts[1];
            if (!ParsePort(parts[2], tunnel.remotePort))
            {
                error = "Tunnel format: [bind_address:]port:host:hostport, "
                    "with ports from 1 to 65535.";
                return false;
            }
        }
        else if (parts.size() == 4)
        {
            tunnel.bindAddress = parts[0];
            if (!ParsePort(parts[1], tunnel.bindPort))
            {
                error = "Tunnel format: [bind_address:]port:host:hostport, "
                    "with ports from 1 to 65535.";
                return false;
            }
            tunnel.remoteHost = parts[2];
            if (!ParsePort(parts[3], tunnel.remotePort))
            {
                error = "Tunnel format: [bind_address:]port:host:hostport, "
                    "with ports from 1 to 65535.";
                return false;
            }
        }
        else
        {
            error = "Tunnel format: [bind_address:]port:host:hostport";
            return false;
        }
    }

    if (tunnel.bindPort <= 0 || tunnel.bindPort > 65535)
    {
        error = "Bind port out of range (1-65535).";
        return false;
    }
    if (type != TunnelType::Dynamic)
    {
        if (tunnel.remoteHost.empty())
        {
            error = "Remote host is required for local/remote tunnels.";
            return false;
        }
        if (tunnel.remotePort <= 0 || tunnel.remotePort > 65535)
        {
            error = "Remote port out of range (1-65535).";
            return false;
        }
    }
    return true;
}

std::string TunnelSshFlags(const SshTunnel & tunnel)
{
    std::string flag;
    switch (tunnel.type)
    {
    case TunnelType::Local:   flag = "-L"; break;
    case TunnelType::Remote:  flag = "-R"; break;
    case TunnelType::Dynamic: flag = "-D"; break;
    }
    std::string spec;
    if (!tunnel.bindAddress.empty())
    {
        spec = tunnel.bindAddress + ":";
    }
    spec += std::to_string(tunnel.bindPort);
    if (tunnel.type != TunnelType::Dynamic)
    {
        spec += ":" + tunnel.remoteHost + ":" + std::to_string(tunnel.remotePort);
    }
    return flag + " " + spec;
}

bool IsGssapiSupported()
{
    // Merely finding a Kerberos library does not wire an authentication path.
    return false;
}

bool ApplyGssapiSetting(const std::string & value, std::string & error)
{
    (void)value;
    error = Texts::Translate("GSSAPI/Kerberos is not available: authentication support is "
        "not implemented in this client.");
    return false;
}

struct SshJumpTunnel::Impl
{
    Session jump;
    ssh_channel channel = NULL;
    ssh_event event = NULL;
    int bridge = -1;
    std::atomic<bool> stop{false};
    std::thread worker;

    void Run()
    {
        // Only this thread touches the jump libssh session while it runs.
        // Backpressure is bounded in both directions; do not queue unlimited
        // writes into libssh when the underlying SSH socket cannot drain.
        char toChannel[32768], toSocket[32768];
        size_t channelBegin = 0, channelEnd = 0, socketBegin = 0, socketEnd = 0;
        bool localEof = false, sentEof = false, remoteEof = false;
        ssh_session ssh = static_cast<ssh_session>(jump.SshHandle());
        while (!stop.load())
        {
            if (ssh_event_dopoll(event, 0) == SSH_ERROR || !ssh_is_connected(ssh))
                break;
            bool progress = false;
            if (!localEof && channelBegin == channelEnd)
            {
                const ssize_t n = recv(bridge, toChannel, sizeof(toChannel), 0);
                if (n > 0)
                {
                    channelBegin = 0;
                    channelEnd = static_cast<size_t>(n);
                    progress = true;
                }
                else if (n == 0)
                {
                    localEof = true;
                    progress = true;
                }
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    break;
            }
            if (channelBegin < channelEnd && !(ssh_get_status(ssh) & SSH_WRITE_PENDING))
            {
                const int n = ssh_channel_write(channel, toChannel + channelBegin,
                    static_cast<uint32_t>(channelEnd - channelBegin));
                if (n == SSH_ERROR) break;
                if (n > 0)
                {
                    channelBegin += static_cast<size_t>(n);
                    progress = true;
                }
            }
            if (localEof && channelBegin == channelEnd && !sentEof)
            {
                const int rc = ssh_channel_send_eof(channel);
                if (rc == SSH_ERROR) break;
                if (rc == SSH_OK) { sentEof = true; progress = true; }
            }
            if (!remoteEof && socketBegin == socketEnd)
            {
                const int n = ssh_channel_read_nonblocking(channel, toSocket,
                    sizeof(toSocket), 0);
                if (n == SSH_ERROR) break;
                if (n > 0)
                {
                    socketBegin = 0;
                    socketEnd = static_cast<size_t>(n);
                    progress = true;
                }
                else if (ssh_channel_is_eof(channel) || ssh_channel_is_closed(channel))
                {
                    remoteEof = true;
                    shutdown(bridge, SHUT_WR);
                    progress = true;
                }
            }
            if (socketBegin < socketEnd)
            {
                const ssize_t n = send(bridge, toSocket + socketBegin,
                    socketEnd - socketBegin, MSG_NOSIGNAL);
                if (n > 0)
                {
                    socketBegin += static_cast<size_t>(n);
                    progress = true;
                }
                else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    break;
            }
            if (localEof && remoteEof && channelBegin == channelEnd && socketBegin == socketEnd)
                break;
            if (!progress)
            {
                struct pollfd fds[2] = {
                    {bridge, 0, 0}, {ssh_get_fd(ssh), POLLIN, 0}
                };
                if (!localEof && channelBegin == channelEnd) fds[0].events |= POLLIN;
                if (socketBegin < socketEnd) fds[0].events |= POLLOUT;
                if (ssh_get_poll_flags(ssh) & SSH_WRITE_PENDING) fds[1].events |= POLLOUT;
                // Short, bounded wait makes Stop() independent of a silent peer.
                if (poll(fds, 2, 100) < 0 && errno != EINTR) break;
                if (fds[0].revents & (POLLERR | POLLNVAL | POLLHUP)) break;
            }
        }
        // Wake any destination operation blocked in libssh on failure/stop.
        shutdown(bridge, SHUT_RDWR);
    }
};

SshJumpTunnel::SshJumpTunnel() : mImpl(new Impl()) {}
SshJumpTunnel::~SshJumpTunnel() { Stop(); }

int SshJumpTunnel::Start(const SessionOptions & destination, std::string & error)
{
    Stop();
    mImpl->stop.store(false);
    const SshTunnelSettings & tunnel = destination.tunnel;
    SessionOptions jump;
    jump.protocol = "sftp";
    jump.hostName = tunnel.hostName;
    jump.portNumber = tunnel.portNumber;
    jump.userName = tunnel.userName;
    jump.password = tunnel.password;
    jump.privateKeyFile = tunnel.privateKeyFile;
    jump.keyPassphrase = tunnel.keyPassphrase;
    jump.hostKey = tunnel.hostKey;
    jump.cachePinnedHostKeys = destination.cachePinnedHostKeys;
    jump.timeoutSecs = destination.timeoutSecs;
    jump.verbose = destination.verbose;
    // Match upstream: the proxy reaches the jump host, never the destination.
    jump.proxy = destination.proxy;
    if (!mImpl->jump.OpenTunnelTransport(jump, error))
    {
        error = Texts::Translate("SSH tunnel: {reason}", {{"reason", error}});
        return -1;
    }
    ssh_session ssh = static_cast<ssh_session>(mImpl->jump.SshHandle());
    mImpl->channel = ssh_channel_new(ssh);
    if (mImpl->channel == NULL ||
        ssh_channel_open_forward(mImpl->channel, destination.hostName.c_str(),
            destination.portNumber, "127.0.0.1", 0) != SSH_OK)
    {
        error = Texts::Translate("SSH tunnel forwarding to {host}:{port} failed: {reason}",
            {{"host", destination.hostName}, {"port", std::to_string(destination.portNumber)},
             {"reason", ssh_get_error(ssh)}});
        Stop();
        return -1;
    }
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair) != 0)
    {
        error = Texts::Translate("Cannot create the private SSH tunnel socket pair.");
        Stop();
        return -1;
    }
    mImpl->bridge = pair[1];
    ssh_set_blocking(ssh, 0);
    mImpl->event = ssh_event_new();
    if (mImpl->event == NULL || ssh_event_add_session(mImpl->event, ssh) != SSH_OK)
    {
        error = Texts::Translate("Cannot create the SSH tunnel event loop.");
        close(pair[0]);
        Stop();
        return -1;
    }
    try
    {
        mImpl->worker = std::thread(&Impl::Run, mImpl.get());
    }
    catch (const std::system_error &)
    {
        error = Texts::Translate("Cannot start the SSH tunnel forwarding worker.");
        close(pair[0]);
        Stop();
        return -1;
    }
    return pair[0];
}

void SshJumpTunnel::Stop()
{
    mImpl->stop.store(true);
    if (mImpl->bridge >= 0) shutdown(mImpl->bridge, SHUT_RDWR);
    if (mImpl->worker.joinable()) mImpl->worker.join();
    if (mImpl->event != NULL)
    {
        if (mImpl->jump.SshHandle() != NULL)
            ssh_event_remove_session(mImpl->event,
                static_cast<ssh_session>(mImpl->jump.SshHandle()));
        ssh_event_free(mImpl->event);
        mImpl->event = NULL;
    }
    if (mImpl->channel != NULL)
    {
        ssh_channel_free(mImpl->channel);
        mImpl->channel = NULL;
    }
    if (mImpl->bridge >= 0) { close(mImpl->bridge); mImpl->bridge = -1; }
    mImpl->jump.Close();
}

} // namespace linscp
