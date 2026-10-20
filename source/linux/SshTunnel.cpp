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
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <libssh/libssh.h>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>
#include <vector>

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



int ConnectTcp(const std::string & hostName, int portNumber, int timeoutSecs,
    std::string & error)
{
    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    char portText[16];
    std::snprintf(portText, sizeof(portText), "%d", portNumber);
    struct addrinfo * addresses = NULL;
    const int rc = getaddrinfo(hostName.c_str(), portText, &hints, &addresses);
    if (rc != 0 || addresses == NULL)
    {
        error = std::string("Could not resolve '") + hostName + "': " +
            gai_strerror(rc) + ".";
        return -1;
    }
    int connected = -1;
    std::string lastError;
    for (struct addrinfo * address = addresses; address != NULL;
        address = address->ai_next)
    {
        const int fd = socket(address->ai_family, address->ai_socktype,
            address->ai_protocol);
        if (fd < 0)
        {
            lastError = std::strerror(errno);
            continue;
        }
        const int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        const int result = connect(fd, address->ai_addr, address->ai_addrlen);
        if (result == 0 || errno == EINPROGRESS)
        {
            struct pollfd ready = {fd, POLLOUT, 0};
            const int waitMs = timeoutSecs > 0 ? timeoutSecs * 1000 : 15000;
            if (result == 0 || (poll(&ready, 1, waitMs) == 1 &&
                (ready.revents & POLLOUT)))
            {
                int soError = 0;
                socklen_t length = sizeof(soError);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &length) == 0 &&
                    soError == 0)
                {
                    if (flags >= 0) fcntl(fd, F_SETFL, flags);
                    connected = fd;
                    break;
                }
                lastError = std::strerror(soError == 0 ? ECONNREFUSED : soError);
            }
            else
            {
                lastError = "timed out";
            }
        }
        else
        {
            lastError = std::strerror(errno);
        }
        close(fd);
    }
    freeaddrinfo(addresses);
    if (connected < 0)
    {
        error = "Could not connect to " + hostName + ":" +
            std::to_string(portNumber) + ": " +
            (lastError.empty() ? "no usable address" : lastError) + ".";
        return -1;
    }
    return connected;
}

bool WriteAll(int fd, const void * data, size_t length)
{
    const unsigned char * bytes = static_cast<const unsigned char *>(data);
    size_t sent = 0;
    while (sent < length)
    {
        const ssize_t n = send(fd, bytes + sent, length - sent, MSG_NOSIGNAL);
        if (n < 0)
        {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                struct pollfd ready = {fd, POLLOUT, 0};
                if (poll(&ready, 1, 5000) != 1) return false;
                continue;
            }
            return false;
        }
        if (n == 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool ReadExact(int fd, void * data, size_t length)
{
    unsigned char * bytes = static_cast<unsigned char *>(data);
    size_t got = 0;
    while (got < length)
    {
        const ssize_t n = recv(fd, bytes + got, length - got, 0);
        if (n < 0)
        {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                struct pollfd ready = {fd, POLLIN, 0};
                if (poll(&ready, 1, 5000) != 1) return false;
                continue;
            }
            return false;
        }
        if (n == 0) return false;
        got += static_cast<size_t>(n);
    }
    return true;
}

} // namespace

bool ParseSocks5ConnectRequest(const unsigned char * data, size_t length,
    std::string & host, int & port, std::string & error)
{
    host.clear();
    port = 0;
    if (data == NULL || length < 7)
    {
        error = "The SOCKS request is truncated.";
        return false;
    }
    if (data[0] != 5)
    {
        error = "Only SOCKS5 is supported on the SSH tunnel listener.";
        return false;
    }
    if (data[1] != 1)
    {
        error = "The SSH tunnel SOCKS listener accepts CONNECT only.";
        return false;
    }
    const unsigned char atyp = data[3];
    size_t offset = 4;
    if (atyp == 1)
    {
        if (length < 10)
        {
            error = "The SOCKS IPv4 request is truncated.";
            return false;
        }
        char text[32];
        std::snprintf(text, sizeof(text), "%u.%u.%u.%u",
            data[4], data[5], data[6], data[7]);
        host = text;
        offset = 8;
    }
    else if (atyp == 3)
    {
        const unsigned char nameLength = data[4];
        if (nameLength == 0 || length < static_cast<size_t>(7) + nameLength)
        {
            error = "The SOCKS domain request is truncated.";
            return false;
        }
        host.assign(reinterpret_cast<const char *>(data + 5), nameLength);
        offset = 5 + nameLength;
    }
    else if (atyp == 4)
    {
        if (length < 22)
        {
            error = "The SOCKS IPv6 request is truncated.";
            return false;
        }
        char text[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, data + 4, text, sizeof(text)) == NULL)
        {
            error = "The SOCKS IPv6 address is not usable.";
            return false;
        }
        host = text;
        offset = 20;
    }
    else
    {
        error = "The SOCKS address type is not IPv4, IPv6 or a domain name.";
        return false;
    }
    if (length < offset + 2)
    {
        error = "The SOCKS request has no port.";
        return false;
    }
    port = (static_cast<int>(data[offset]) << 8) | data[offset + 1];
    if (host.empty() || host == "*" || port < 1 || port > 65535)
    {
        error = "The SOCKS destination is not a valid host or port.";
        return false;
    }
    return true;
}

bool BuildSocks5ConnectRequest(const std::string & host, int port,
    std::vector<unsigned char> & out, std::string & error)
{
    out.clear();
    if (host.empty() || host == "*" || port < 1 || port > 65535)
    {
        error = "The SOCKS destination is not a valid host or port.";
        return false;
    }
    out.push_back(5);
    out.push_back(1);
    out.push_back(0);
    in_addr ipv4;
    in6_addr ipv6;
    if (inet_pton(AF_INET, host.c_str(), &ipv4) == 1)
    {
        out.push_back(1);
        const unsigned char * bytes = reinterpret_cast<const unsigned char *>(&ipv4);
        out.insert(out.end(), bytes, bytes + 4);
    }
    else if (inet_pton(AF_INET6, host.c_str(), &ipv6) == 1)
    {
        out.push_back(4);
        const unsigned char * bytes = reinterpret_cast<const unsigned char *>(&ipv6);
        out.insert(out.end(), bytes, bytes + 16);
    }
    else
    {
        if (host.size() > 255)
        {
            error = "The SOCKS destination host name is too long.";
            return false;
        }
        out.push_back(3);
        out.push_back(static_cast<unsigned char>(host.size()));
        out.insert(out.end(), host.begin(), host.end());
    }
    out.push_back(static_cast<unsigned char>((port >> 8) & 0xff));
    out.push_back(static_cast<unsigned char>(port & 0xff));
    return true;
}

bool Socks5ConnectOn(int socksFd, const std::string & destHost, int destPort,
    std::string & error)
{
    const unsigned char greeting[] = {5, 1, 0};
    if (!WriteAll(socksFd, greeting, sizeof(greeting)))
    {
        error = "The SOCKS proxy closed the greeting.";
        return false;
    }
    unsigned char method[2];
    if (!ReadExact(socksFd, method, 2) || method[0] != 5 || method[1] != 0)
    {
        error = "The SOCKS proxy refused an unauthenticated CONNECT.";
        return false;
    }
    std::vector<unsigned char> request;
    if (!BuildSocks5ConnectRequest(destHost, destPort, request, error))
    {
        return false;
    }
    if (!WriteAll(socksFd, request.data(), request.size()))
    {
        error = "The SOCKS proxy closed the CONNECT request.";
        return false;
    }
    unsigned char reply[4];
    if (!ReadExact(socksFd, reply, 4) || reply[0] != 5)
    {
        error = "The SOCKS proxy returned a truncated CONNECT reply.";
        return false;
    }
    if (reply[1] != 0)
    {
        error = "The SOCKS proxy refused CONNECT to " + destHost + ":" +
            std::to_string(destPort) + ".";
        return false;
    }
    size_t rest = 0;
    if (reply[3] == 1) rest = 4 + 2;
    else if (reply[3] == 4) rest = 16 + 2;
    else if (reply[3] == 3)
    {
        unsigned char nameLength = 0;
        if (!ReadExact(socksFd, &nameLength, 1))
        {
            error = "The SOCKS proxy returned a truncated CONNECT reply.";
            return false;
        }
        rest = static_cast<size_t>(nameLength) + 2;
    }
    else
    {
        error = "The SOCKS proxy returned an unknown address type.";
        return false;
    }
    std::vector<unsigned char> skip(rest);
    if (rest > 0 && !ReadExact(socksFd, skip.data(), rest))
    {
        error = "The SOCKS proxy returned a truncated CONNECT reply.";
        return false;
    }
    return true;
}

int ConnectThroughSocks5(const std::string & socksHost, int socksPort,
    const std::string & destHost, int destPort, int timeoutSecs,
    std::string & error)
{
    const int fd = ConnectTcp(socksHost, socksPort, timeoutSecs, error);
    if (fd < 0)
    {
        return -1;
    }
    if (!Socks5ConnectOn(fd, destHost, destPort, error))
    {
        close(fd);
        return -1;
    }
    return fd;
}

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
    /* A libssh built with real GSSAPI names it in its version string
     * (".../gssapi"); a stub build still links ssh_userauth_gssapi but
     * cannot use it, and must not be mistaken for support. */
    const char * version = ssh_version(0);
    return version != NULL &&
        std::string(version).find("gssapi") != std::string::npos;
}

struct Relay
{
    ssh_channel channel = NULL;
    int sock = -1;
    char toChannel[32768];
    char toSocket[32768];
    size_t channelBegin = 0, channelEnd = 0, socketBegin = 0, socketEnd = 0;
    bool localEof = false, sentEof = false, remoteEof = false;
};

struct SshJumpTunnel::Impl
{
    Session jump;
    ssh_channel channel = NULL;
    ssh_event event = NULL;
    int bridge = -1;
    /* The TunnelLocalPortNumber listener, when one was bound: held for
     * the session so the port stays this tunnel's, and closed in
     * Stop(). In SOCKS mode it keeps accepting CONNECTs. */
    int listener = -1;
    int socksPort = 0;
    bool socksMode = false;
    std::vector<Relay> relays;
    std::atomic<bool> stop{false};
    std::thread worker;

    bool HandshakeSocks(int fd, std::string & host, int & port, std::string & error)
    {
        unsigned char greeting[2];
        if (!ReadExact(fd, greeting, 2) || greeting[0] != 5 || greeting[1] == 0)
        {
            error = "The SOCKS client sent no methods.";
            return false;
        }
        std::vector<unsigned char> methods(greeting[1]);
        if (!ReadExact(fd, methods.data(), methods.size()))
        {
            error = "The SOCKS client sent a truncated greeting.";
            return false;
        }
        bool allowsNone = false;
        for (size_t i = 0; i < methods.size(); i++)
        {
            if (methods[i] == 0) allowsNone = true;
        }
        const unsigned char choice[2] = {5, static_cast<unsigned char>(allowsNone ? 0 : 0xff)};
        if (!WriteAll(fd, choice, 2) || !allowsNone)
        {
            error = "The SOCKS client requires authentication this listener does not speak.";
            return false;
        }
        unsigned char header[4];
        if (!ReadExact(fd, header, 4))
        {
            error = "The SOCKS client sent a truncated CONNECT.";
            return false;
        }
        std::vector<unsigned char> request(header, header + 4);
        if (header[3] == 1)
        {
            request.resize(10);
            if (!ReadExact(fd, request.data() + 4, 6)) return false;
        }
        else if (header[3] == 4)
        {
            request.resize(22);
            if (!ReadExact(fd, request.data() + 4, 18)) return false;
        }
        else if (header[3] == 3)
        {
            unsigned char nameLength = 0;
            if (!ReadExact(fd, &nameLength, 1)) return false;
            request.push_back(nameLength);
            request.resize(7 + nameLength);
            if (!ReadExact(fd, request.data() + 5, static_cast<size_t>(nameLength) + 2))
                return false;
        }
        else
        {
            error = "The SOCKS address type is not IPv4, IPv6 or a domain name.";
            return false;
        }
        return ParseSocks5ConnectRequest(request.data(), request.size(),
            host, port, error);
    }

    bool OpenForward(const std::string & host, int port, ssh_channel & out,
        std::string & error)
    {
        ssh_session ssh = static_cast<ssh_session>(jump.SshHandle());
        out = ssh_channel_new(ssh);
        if (out == NULL)
        {
            error = "Cannot allocate an SSH forwarding channel.";
            return false;
        }
        int rc = SSH_AGAIN;
        const time_t deadline = time(NULL) + 15;
        while (rc == SSH_AGAIN && time(NULL) <= deadline && !stop.load())
        {
            rc = ssh_channel_open_forward(out, host.c_str(), port, "127.0.0.1", 0);
            if (rc == SSH_AGAIN)
            {
                if (event != NULL) ssh_event_dopoll(event, 100);
                else poll(NULL, 0, 50);
            }
        }
        if (rc != SSH_OK)
        {
            error = Texts::Translate("SSH tunnel forwarding to {host}:{port} failed: {reason}",
                {{"host", host}, {"port", std::to_string(port)},
                 {"reason", ssh_get_error(ssh)}});
            ssh_channel_free(out);
            out = NULL;
            return false;
        }
        return true;
    }

    void AcceptSocks()
    {
        if (listener < 0) return;
        const int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (client < 0) return;
        const int flags = fcntl(client, F_GETFL, 0);
        if (flags >= 0) fcntl(client, F_SETFL, flags & ~O_NONBLOCK);
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        std::string host, error;
        int port = 0;
        ssh_channel channel = NULL;
        const unsigned char fail[] = {5, 5, 0, 1, 0, 0, 0, 0, 0, 0};
        if (!HandshakeSocks(client, host, port, error) ||
            !OpenForward(host, port, channel, error))
        {
            WriteAll(client, fail, sizeof(fail));
            close(client);
            if (channel != NULL) ssh_channel_free(channel);
            return;
        }
        const unsigned char ok[] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
        if (!WriteAll(client, ok, sizeof(ok)))
        {
            ssh_channel_free(channel);
            close(client);
            return;
        }
        if (flags >= 0) fcntl(client, F_SETFL, flags | O_NONBLOCK);
        Relay relay;
        relay.channel = channel;
        relay.sock = client;
        relays.push_back(relay);
    }

    void PumpRelay(Relay & relay, ssh_session ssh)
    {
        bool progress = true;
        while (progress && !stop.load())
        {
            progress = false;
            if (!relay.localEof && relay.channelBegin == relay.channelEnd)
            {
                const ssize_t n = recv(relay.sock, relay.toChannel, sizeof(relay.toChannel), 0);
                if (n > 0)
                {
                    relay.channelBegin = 0;
                    relay.channelEnd = static_cast<size_t>(n);
                    progress = true;
                }
                else if (n == 0)
                {
                    relay.localEof = true;
                    progress = true;
                }
                else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                {
                    relay.localEof = true;
                    relay.remoteEof = true;
                    break;
                }
            }
            if (relay.channelBegin < relay.channelEnd &&
                !(ssh_get_status(ssh) & SSH_WRITE_PENDING))
            {
                const int n = ssh_channel_write(relay.channel,
                    relay.toChannel + relay.channelBegin,
                    static_cast<uint32_t>(relay.channelEnd - relay.channelBegin));
                if (n == SSH_ERROR)
                {
                    relay.localEof = true;
                    relay.remoteEof = true;
                    break;
                }
                if (n > 0)
                {
                    relay.channelBegin += static_cast<size_t>(n);
                    progress = true;
                }
            }
            if (relay.localEof && relay.channelBegin == relay.channelEnd && !relay.sentEof)
            {
                const int rc = ssh_channel_send_eof(relay.channel);
                if (rc == SSH_ERROR)
                {
                    relay.remoteEof = true;
                    break;
                }
                if (rc == SSH_OK) { relay.sentEof = true; progress = true; }
            }
            if (!relay.remoteEof && relay.socketBegin == relay.socketEnd)
            {
                const int n = ssh_channel_read_nonblocking(relay.channel, relay.toSocket,
                    sizeof(relay.toSocket), 0);
                if (n == SSH_ERROR)
                {
                    relay.remoteEof = true;
                    break;
                }
                if (n > 0)
                {
                    relay.socketBegin = 0;
                    relay.socketEnd = static_cast<size_t>(n);
                    progress = true;
                }
                else if (ssh_channel_is_eof(relay.channel) || ssh_channel_is_closed(relay.channel))
                {
                    relay.remoteEof = true;
                    shutdown(relay.sock, SHUT_WR);
                    progress = true;
                }
            }
            if (relay.socketBegin < relay.socketEnd)
            {
                const ssize_t n = send(relay.sock, relay.toSocket + relay.socketBegin,
                    relay.socketEnd - relay.socketBegin, MSG_NOSIGNAL);
                if (n > 0)
                {
                    relay.socketBegin += static_cast<size_t>(n);
                    progress = true;
                }
                else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                {
                    relay.remoteEof = true;
                    break;
                }
            }
        }
    }

    void CloseRelay(Relay & relay)
    {
        if (relay.sock >= 0)
        {
            shutdown(relay.sock, SHUT_RDWR);
            close(relay.sock);
            relay.sock = -1;
        }
        if (relay.channel != NULL)
        {
            ssh_channel_free(relay.channel);
            relay.channel = NULL;
        }
    }

    void RunSocks()
    {
        ssh_session ssh = static_cast<ssh_session>(jump.SshHandle());
        ssh_set_blocking(ssh, 0);
        while (!stop.load())
        {
            if (ssh_event_dopoll(event, 0) == SSH_ERROR || !ssh_is_connected(ssh))
                break;
            AcceptSocks();
            for (size_t i = 0; i < relays.size(); i++)
                PumpRelay(relays[i], ssh);
            for (size_t i = relays.size(); i-- > 0; )
            {
                Relay & relay = relays[i];
                if ((relay.localEof && relay.remoteEof &&
                     relay.channelBegin == relay.channelEnd &&
                     relay.socketBegin == relay.socketEnd) ||
                    relay.sock < 0)
                {
                    CloseRelay(relay);
                    relays.erase(relays.begin() + static_cast<std::ptrdiff_t>(i));
                }
            }
            std::vector<pollfd> fds;
            if (listener >= 0)
            {
                pollfd ready = {listener, POLLIN, 0};
                fds.push_back(ready);
            }
            pollfd sshfd = {ssh_get_fd(ssh), POLLIN, 0};
            if (ssh_get_poll_flags(ssh) & SSH_WRITE_PENDING) sshfd.events |= POLLOUT;
            fds.push_back(sshfd);
            for (size_t i = 0; i < relays.size(); i++)
            {
                pollfd ready = {relays[i].sock, 0, 0};
                if (!relays[i].localEof && relays[i].channelBegin == relays[i].channelEnd)
                    ready.events |= POLLIN;
                if (relays[i].socketBegin < relays[i].socketEnd)
                    ready.events |= POLLOUT;
                if (ready.events != 0) fds.push_back(ready);
            }
            if (poll(fds.data(), fds.size(), 100) < 0 && errno != EINTR) break;
        }
        for (size_t i = 0; i < relays.size(); i++) CloseRelay(relays[i]);
        relays.clear();
    }

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
    // Kerberos policy travels to the jump host, except the destination's
    // logical host name: the jump's ticket is for the jump's own name.
    jump.gssapi = destination.gssapi;
    jump.gssapi.logicalHost.clear();
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
    /*
     * The local end of the forwarded connection. The ordinary shape is
     * a private socket pair - no port exists for another process to
     * find. 'TunnelLocalPortNumber' instead binds that loopback port
     * (upstream's model, so a firewall rule can name the port): our own
     * destination connection is the one connection accepted on it, the
     * listener then just holds the port for the session, and a port
     * already in use fails the open instead of being shared.
     */
    int pair[2];
    if (tunnel.localPortNumber > 0)
    {
        const int listener = socket(AF_INET,
            SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_in address;
        std::memset(&address, 0, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = htons(
            static_cast<unsigned short>(tunnel.localPortNumber));
        if (listener < 0 ||
            bind(listener, reinterpret_cast<struct sockaddr *>(&address),
                sizeof(address)) != 0 ||
            listen(listener, 1) != 0)
        {
            error = Texts::Translate("Cannot listen on the tunnel local port "
                "127.0.0.1:{port}: {reason}",
                {{"port", std::to_string(tunnel.localPortNumber)},
                 {"reason", std::strerror(errno)}});
            if (listener >= 0) close(listener);
            Stop();
            return -1;
        }
        mImpl->listener = listener;
        const int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct pollfd ready = {listener, POLLIN, 0};
        if (client < 0 ||
            connect(client,
                reinterpret_cast<struct sockaddr *>(&address),
                sizeof(address)) != 0 ||
            poll(&ready, 1, 5000) != 1)
        {
            error = Texts::Translate("Cannot connect through the tunnel local port "
                "127.0.0.1:{port}.",
                {{"port", std::to_string(tunnel.localPortNumber)}});
            if (client >= 0) close(client);
            Stop();
            return -1;
        }
        pair[1] = accept4(listener, NULL, NULL,
            SOCK_CLOEXEC | SOCK_NONBLOCK);
        pair[0] = client;
        if (pair[1] < 0)
        {
            error = Texts::Translate("Cannot connect through the tunnel local port "
                "127.0.0.1:{port}.",
                {{"port", std::to_string(tunnel.localPortNumber)}});
            close(client);
            Stop();
            return -1;
        }
        const int flags = fcntl(pair[0], F_GETFL, 0);
        if (flags >= 0) fcntl(pair[0], F_SETFL, flags | O_NONBLOCK);
    }
    else if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, pair) != 0)
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

int SshJumpTunnel::SocksPort() const
{
    return mImpl->socksPort;
}

int SshJumpTunnel::StartSocks(const SessionOptions & destination, std::string & error)
{
    Stop();
    mImpl->stop.store(false);
    mImpl->socksMode = true;
    mImpl->socksPort = 0;
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
    jump.proxy = destination.proxy;
    jump.gssapi = destination.gssapi;
    jump.gssapi.logicalHost.clear();
    if (!mImpl->jump.OpenTunnelTransport(jump, error))
    {
        error = Texts::Translate("SSH tunnel: {reason}", {{"reason", error}});
        return -1;
    }
    const int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in address;
    std::memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(static_cast<unsigned short>(
        tunnel.localPortNumber > 0 ? tunnel.localPortNumber : 0));
    int reuse = 1;
    if (listener >= 0)
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (listener < 0 ||
        bind(listener, reinterpret_cast<struct sockaddr *>(&address),
            sizeof(address)) != 0 ||
        listen(listener, 16) != 0)
    {
        error = Texts::Translate("Cannot listen on the tunnel local port "
            "127.0.0.1:{port}: {reason}",
            {{"port", std::to_string(tunnel.localPortNumber)},
             {"reason", std::strerror(errno)}});
        if (listener >= 0) close(listener);
        Stop();
        return -1;
    }
    const int flags = fcntl(listener, F_GETFL, 0);
    if (flags >= 0) fcntl(listener, F_SETFL, flags | O_NONBLOCK);
    socklen_t addressLength = sizeof(address);
    if (getsockname(listener, reinterpret_cast<struct sockaddr *>(&address),
            &addressLength) != 0)
    {
        error = Texts::Translate("Cannot listen on the tunnel local port "
            "127.0.0.1:{port}: {reason}",
            {{"port", std::to_string(tunnel.localPortNumber)},
             {"reason", std::strerror(errno)}});
        close(listener);
        Stop();
        return -1;
    }
    mImpl->listener = listener;
    mImpl->socksPort = ntohs(address.sin_port);
    ssh_session ssh = static_cast<ssh_session>(mImpl->jump.SshHandle());
    ssh_set_blocking(ssh, 0);
    mImpl->event = ssh_event_new();
    if (mImpl->event == NULL || ssh_event_add_session(mImpl->event, ssh) != SSH_OK)
    {
        error = Texts::Translate("Cannot create the SSH tunnel event loop.");
        Stop();
        return -1;
    }
    try
    {
        mImpl->worker = std::thread(&Impl::RunSocks, mImpl.get());
    }
    catch (const std::system_error &)
    {
        error = Texts::Translate("Cannot start the SSH tunnel forwarding worker.");
        Stop();
        return -1;
    }
    return mImpl->socksPort;
}

void SshJumpTunnel::Stop()
{
    mImpl->stop.store(true);
    if (mImpl->bridge >= 0) shutdown(mImpl->bridge, SHUT_RDWR);
    if (mImpl->listener >= 0) shutdown(mImpl->listener, SHUT_RDWR);
    for (size_t i = 0; i < mImpl->relays.size(); i++)
    {
        if (mImpl->relays[i].sock >= 0)
            shutdown(mImpl->relays[i].sock, SHUT_RDWR);
    }
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
    if (mImpl->listener >= 0) { close(mImpl->listener); mImpl->listener = -1; }
    for (size_t i = 0; i < mImpl->relays.size(); i++)
        mImpl->CloseRelay(mImpl->relays[i]);
    mImpl->relays.clear();
    mImpl->socksPort = 0;
    mImpl->socksMode = false;
    mImpl->jump.Close();
}

} // namespace linscp
