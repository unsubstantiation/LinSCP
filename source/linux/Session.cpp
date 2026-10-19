#include "Session.h"

#include "Console.h"
#include "PathUtil.h"
#include "ProtocolClient.h"
#include "SftpClient.h"
#include "SshKeys.h"
#include "PpkKey.h"
#include "Texts.h"

#include <cctype>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <libssh/sftp.h>

#if LIBSSH_VERSION_INT < SSH_VERSION_INT(0, 10, 0)
#error "LinSCP requires libssh 0.10 or newer (caller-owned transport sockets)."
#endif

namespace linscp {

namespace {

Session * g_currentSession = NULL;

bool HasWhitespaceOrControl(const std::string & text);

std::string LowerCaseAscii(const std::string & text)
{
    std::string result = text;
    for (size_t i = 0; i < result.size(); i++)
    {
        result[i] = static_cast<char>(tolower(static_cast<unsigned char>(result[i])));
    }
    return result;
}

std::string Base64Encode(const unsigned char * data, size_t length)
{
    static const char digits[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for (size_t i = 0; i < length; i += 3)
    {
        unsigned int value = data[i] << 16;
        const size_t remaining = length - i;
        if (remaining > 1)
        {
            value |= data[i + 1] << 8;
        }
        if (remaining > 2)
        {
            value |= data[i + 2];
        }
        result += digits[(value >> 18) & 63];
        result += digits[(value >> 12) & 63];
        result += remaining > 1 ? digits[(value >> 6) & 63] : '=';
        result += remaining > 2 ? digits[value & 63] : '=';
    }
    return result;
}

/* The SHA-256 fingerprint the way OpenSSH and this client print it:
 * 'SHA256:' plus the unpadded base64 of the digest. */
std::string Sha256Fingerprint(ssh_key key)
{
    unsigned char * hash = NULL;
    size_t length = 0;
    if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256,
            &hash, &length) != SSH_OK)
    {
        return std::string();
    }
    std::string encoded = Base64Encode(hash, length);
    ssh_clean_pubkey_hash(&hash);
    while (!encoded.empty() && encoded[encoded.size() - 1] == '=')
    {
        encoded.erase(encoded.size() - 1);
    }
    return "SHA256:" + encoded;
}

/* The MD5 fingerprint as colon-separated hex, the ssh-keygen spelling. */
std::string Md5Fingerprint(ssh_key key)
{
    unsigned char * hash = NULL;
    size_t length = 0;
    if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_MD5,
            &hash, &length) != SSH_OK)
    {
        return std::string();
    }
    std::string result;
    for (size_t i = 0; i < length; i++)
    {
        char buffer[4];
        snprintf(buffer, sizeof(buffer), "%s%02x", i ? ":" : "", hash[i]);
        result += buffer;
    }
    ssh_clean_pubkey_hash(&hash);
    return result;
}

/*
 * Whether 'host' is named by the proxy exclusion list: a comma or
 * semicolon separated list in which '*' matches any run of characters
 * (the upstream spelling, e.g. '*.example.com,localhost').
 */
bool ProxyExcluded(const ProxySettings & proxy, const std::string & host)
{
    const std::string list = proxy.excludeList;
    size_t start = 0;
    while (start <= list.size())
    {
        size_t end = list.find_first_of(",;", start);
        if (end == std::string::npos)
        {
            end = list.size();
        }
        std::string pattern = list.substr(start, end - start);
        const size_t first = pattern.find_first_not_of(" \t");
        const size_t last = pattern.find_last_not_of(" \t");
        pattern = first == std::string::npos ? std::string() :
            pattern.substr(first, last - first + 1);
        if (!pattern.empty())
        {
            /* Glob match, iterative with backtracking on '*'. */
            size_t p = 0, h = 0, starP = std::string::npos, starH = 0;
            const std::string lowerPattern = LowerCaseAscii(pattern);
            const std::string lowerHost = LowerCaseAscii(host);
            bool matched = false;
            while (h < lowerHost.size())
            {
                if (p < lowerPattern.size() &&
                    (lowerPattern[p] == '?' || lowerPattern[p] == lowerHost[h]))
                {
                    p++;
                    h++;
                }
                else if (p < lowerPattern.size() && lowerPattern[p] == '*')
                {
                    starP = p++;
                    starH = h;
                }
                else if (starP != std::string::npos)
                {
                    p = starP + 1;
                    h = ++starH;
                }
                else
                {
                    break;
                }
                if (h == lowerHost.size())
                {
                    while (p < lowerPattern.size() && lowerPattern[p] == '*')
                    {
                        p++;
                    }
                    matched = p == lowerPattern.size();
                }
            }
            if (matched)
            {
                return true;
            }
        }
        if (end == list.size())
        {
            break;
        }
        start = end + 1;
    }
    return false;
}

/* Connects a TCP socket to host:port. Returns the fd, or -1 with 'error'. */
int TcpConnect(const std::string & host, int port, int timeoutSecs,
    std::string & error)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo * addresses = NULL;
    char portText[16];
    snprintf(portText, sizeof(portText), "%d", port);
    if (getaddrinfo(host.c_str(), portText, &hints, &addresses) != 0)
    {
        error = "Cannot resolve '" + host + "'.";
        return -1;
    }
    int fd = -1;
    for (struct addrinfo * ai = addresses; ai != NULL; ai = ai->ai_next)
    {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0)
        {
            continue;
        }
        struct timeval timeout;
        timeout.tv_sec = timeoutSecs;
        timeout.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0)
        {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd < 0)
    {
        error = "Cannot connect to " + host + ":" + portText + ".";
    }
    return fd;
}

bool SendAll(int fd, const char * data, size_t length)
{
    size_t sent = 0;
    while (sent < length)
    {
        const ssize_t n = send(fd, data + sent, length - sent, 0);
        if (n <= 0)
        {
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

bool RecvSome(int fd, std::string & chunk)
{
    char buffer[4096];
    const ssize_t n = recv(fd, buffer, sizeof(buffer), 0);
    if (n <= 0)
    {
        return false;
    }
    chunk.append(buffer, static_cast<size_t>(n));
    return true;
}

/* Resolves 'host' to an IPv4 address in network order, for SOCKS4. */
bool ResolveIpv4(const std::string & host, unsigned char bytes[4])
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo * addresses = NULL;
    if (getaddrinfo(host.c_str(), NULL, &hints, &addresses) != 0)
    {
        return false;
    }
    bool found = false;
    for (struct addrinfo * ai = addresses; ai != NULL && !found; ai = ai->ai_next)
    {
        const struct sockaddr_in * sin =
            reinterpret_cast<const struct sockaddr_in *>(ai->ai_addr);
        memcpy(bytes, &sin->sin_addr.s_addr, 4);
        found = true;
    }
    freeaddrinfo(addresses);
    return found;
}

/*
 * Opens the transport socket for a proxied connection: speaks SOCKS4,
 * SOCKS5, HTTP CONNECT or the telnet-proxy command dialogue to the
 * proxy, and returns a socket that carries SSH bytes to the target.
 * Returns -1 with 'error' set. (The 'Cmd' proxy is not done here:
 * libssh runs it itself through SSH_OPTIONS_PROXYCOMMAND.)
 */
int ProxySocket(const SessionOptions & options, std::string & error)
{
    const ProxySettings & proxy = options.proxy;
    const std::string & target = options.hostName;
    const int targetPort = options.portNumber;
    int fd = TcpConnect(proxy.host, proxy.EffectivePort(),
        options.timeoutSecs, error);
    if (fd < 0)
    {
        return -1;
    }

    const bool remoteDns = proxy.ResolvesRemotely();
    switch (proxy.method)
    {
    case ProxyMethod::Socks5:
    {
        std::string greeting;
        greeting += '\x05';
        if (proxy.userName.empty())
        {
            greeting += '\x01';
            greeting += '\x00';
        }
        else
        {
            greeting += '\x02';
            greeting += '\x00';
            greeting += '\x02';
        }
        std::string reply;
        if (!SendAll(fd, greeting.data(), greeting.size()) ||
            !RecvSome(fd, reply) || reply.size() < 2 ||
            static_cast<unsigned char>(reply[0]) != 5)
        {
            error = "The SOCKS5 proxy did not answer the greeting.";
            break;
        }
        if (static_cast<unsigned char>(reply[1]) == 2)
        {
            std::string auth;
            auth += '\x01';
            auth += static_cast<char>(proxy.userName.size());
            auth += proxy.userName;
            auth += static_cast<char>(proxy.password.size());
            auth += proxy.password;
            reply.clear();
            if (!SendAll(fd, auth.data(), auth.size()) ||
                !RecvSome(fd, reply) || reply.size() < 2 || reply[1] != 0)
            {
                error = "The SOCKS5 proxy refused the user name and password.";
                break;
            }
        }
        else if (static_cast<unsigned char>(reply[1]) != 0)
        {
            error = "The SOCKS5 proxy refused the authentication method.";
            break;
        }
        std::string request;
        request += '\x05';
        request += '\x01'; /* CONNECT */
        request += '\x00';
        if (remoteDns)
        {
            request += '\x03';
            request += static_cast<char>(target.size());
            request += target;
        }
        else
        {
            unsigned char bytes[4];
            if (!ResolveIpv4(target, bytes))
            {
                error = "Cannot resolve '" + target + "'.";
                break;
            }
            request += '\x01';
            request.append(reinterpret_cast<char *>(bytes), 4);
        }
        request += static_cast<char>((targetPort >> 8) & 0xff);
        request += static_cast<char>(targetPort & 0xff);
        reply.clear();
        if (!SendAll(fd, request.data(), request.size()) ||
            !RecvSome(fd, reply) || reply.size() < 2 || reply[1] != 0)
        {
            error = "The SOCKS5 proxy refused the connection to " + target + ".";
            break;
        }
        return fd;
    }
    case ProxyMethod::Socks4:
    {
        unsigned char bytes[4];
        const bool socks4a = remoteDns && !ResolveIpv4(target, bytes);
        if (!socks4a && !ResolveIpv4(target, bytes))
        {
            error = "Cannot resolve '" + target + "'.";
            break;
        }
        std::string request;
        request += '\x04';
        request += '\x01'; /* CONNECT */
        request += static_cast<char>((targetPort >> 8) & 0xff);
        request += static_cast<char>(targetPort & 0xff);
        if (socks4a)
        {
            request += '\x00';
            request += '\x00';
            request += '\x00';
            request += '\x01';
        }
        else
        {
            request.append(reinterpret_cast<char *>(bytes), 4);
        }
        request += proxy.userName;
        request += '\x00';
        if (socks4a)
        {
            request += target;
            request += '\x00';
        }
        std::string reply;
        if (!SendAll(fd, request.data(), request.size()) ||
            !RecvSome(fd, reply) || reply.size() < 8 ||
            static_cast<unsigned char>(reply[1]) != 90)
        {
            error = "The SOCKS4 proxy refused the connection to " + target + ".";
            break;
        }
        return fd;
    }
    case ProxyMethod::Http:
    {
        std::string request = "CONNECT " + target + ":" +
            std::to_string(targetPort) + " HTTP/1.1\r\nHost: " + target +
            ":" + std::to_string(targetPort) + "\r\n";
        if (!proxy.userName.empty())
        {
            const std::string credentials = proxy.userName + ":" + proxy.password;
            request += "Proxy-Authorization: Basic " +
                Base64Encode(reinterpret_cast<const unsigned char *>(
                    credentials.data()), credentials.size()) + "\r\n";
        }
        request += "\r\n";
        std::string reply;
        if (!SendAll(fd, request.data(), request.size()))
        {
            error = "Cannot write to the HTTP proxy.";
            break;
        }
        while (reply.find("\r\n\r\n") == std::string::npos &&
            reply.size() < 16384)
        {
            if (!RecvSome(fd, reply))
            {
                error = "The HTTP proxy closed the connection.";
                break;
            }
        }
        if (error.empty() &&
            reply.find(" 200") == std::string::npos)
        {
            error = "The HTTP proxy refused the connection to " + target + ".";
            break;
        }
        if (!error.empty())
        {
            break;
        }
        return fd;
    }
    case ProxyMethod::Telnet:
    {
        /* The telnet proxy's dialogue is the configured command with
         * %host and %port substituted, answered by a connection. */
        std::string command = proxy.command.empty() ?
            "connect %host %port" : proxy.command;
        std::string::size_type pos;
        while ((pos = command.find("%host")) != std::string::npos)
        {
            command.replace(pos, 5, target);
        }
        while ((pos = command.find("%port")) != std::string::npos)
        {
            command.replace(pos, 5, std::to_string(targetPort));
        }
        if (!SendAll(fd, command.data(), command.size()) ||
            !SendAll(fd, "\r\n", 2))
        {
            error = "Cannot write to the telnet proxy.";
            break;
        }
        return fd;
    }
    default:
        break;
    }

    if (error.empty())
    {
        error = "Unsupported proxy method.";
    }
    close(fd);
    return -1;
}

} // namespace

SessionOptions::SessionOptions() :
    protocol("sftp"),
    portNumber(22),
    cachePinnedHostKeys(true),
    timeoutSecs(15),
    verbose(false)
{
}

namespace {

std::string LowerAscii(const std::string & text)
{
    std::string result = text;
    for (size_t i = 0; i < result.size(); i++)
    {
        result[i] = static_cast<char>(
            tolower(static_cast<unsigned char>(result[i])));
    }
    return result;
}

std::string TrimAscii(const std::string & text)
{
    const size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos)
    {
        return std::string();
    }
    const size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

/* The methods by their upstream names, in upstream's numeric order. */
struct ProxyMethodEntry
{
    ProxyMethod method;
    const char * name;
    int defaultPort;
};

/* 'a, b and c', for the names a message offers. */
std::string JoinNames(const std::vector<std::string> & names)
{
    std::string result;
    for (size_t i = 0; i < names.size(); i++)
    {
        if (i > 0)
        {
            result += i + 1 == names.size() ? " and " : ", ";
        }
        result += names[i];
    }
    return result;
}

const ProxyMethodEntry kProxyMethods[] = {
    { ProxyMethod::None,   "None",   0 },
    { ProxyMethod::Socks4, "SOCKS4", 1080 },
    { ProxyMethod::Socks5, "SOCKS5", 1080 },
    { ProxyMethod::Http,   "HTTP",   80 },
    { ProxyMethod::Telnet, "Telnet", 23 },
    { ProxyMethod::Local,  "Cmd",    0 }
};

const size_t kProxyMethodCount =
    sizeof(kProxyMethods) / sizeof(kProxyMethods[0]);

/* 'ProxyDNS' as upstream stores it: 0 = off, 1 = automatic, 2 = on. */
bool ParseAutoSwitch(const std::string & text, int & value)
{
    const std::string lower = LowerAscii(TrimAscii(text));
    if (lower == "0" || lower == "off" || lower == "no" || lower == "false")
    {
        value = 0;
    }
    else if (lower == "1" || lower == "auto" || lower == "automatic")
    {
        value = 1;
    }
    else if (lower == "2" || lower == "on" || lower == "yes" || lower == "true")
    {
        value = 2;
    }
    else
    {
        return false;
    }
    return true;
}

bool ParseToggle(const std::string & text, bool & value)
{
    int parsed = 0;
    if (!ParseAutoSwitch(text, parsed))
    {
        return false;
    }
    value = parsed != 0;
    return true;
}

bool ParsePortValue(const std::string & text, int & port)
{
    const std::string trimmed = TrimAscii(text);
    if (trimmed.empty())
    {
        return false;
    }
    unsigned int value = 0;
    for (size_t i = 0; i < trimmed.size(); i++)
    {
        const unsigned char c = static_cast<unsigned char>(trimmed[i]);
        if (c < '0' || c > '9')
        {
            return false;
        }
        const unsigned int digit = c - '0';
        if (value > (65535U - digit) / 10U)
        {
            return false;
        }
        value = value * 10U + digit;
    }
    if (value == 0 || value > 65535U)
    {
        return false;
    }
    port = static_cast<int>(value);
    return true;
}

} // namespace

const char * ProxyMethodName(ProxyMethod method)
{
    for (size_t i = 0; i < kProxyMethodCount; i++)
    {
        if (kProxyMethods[i].method == method)
        {
            return kProxyMethods[i].name;
        }
    }
    return "None";
}

int ProxyDefaultPort(ProxyMethod method)
{
    for (size_t i = 0; i < kProxyMethodCount; i++)
    {
        if (kProxyMethods[i].method == method)
        {
            return kProxyMethods[i].defaultPort;
        }
    }
    return 0;
}

bool ParseProxyMethod(const std::string & text, ProxyMethod & method)
{
    const std::string lower = LowerAscii(TrimAscii(text));
    if (lower.empty())
    {
        return false;
    }
    for (size_t i = 0; i < kProxyMethodCount; i++)
    {
        if (lower == LowerAscii(kProxyMethods[i].name))
        {
            method = kProxyMethods[i].method;
            return true;
        }
    }
    /* Upstream also stores the method as its number, and 'local' is what
     * the local-command proxy is called outside the transport table. */
    if (lower == "local" || lower == "command")
    {
        method = ProxyMethod::Local;
        return true;
    }
    if (lower == "socks")
    {
        method = ProxyMethod::Socks5;
        return true;
    }
    /* Upstream stores the method as its number as well as its name, and
     * the numbers are the indices of the table above: 0 through 5. */
    if (lower.size() == 1 && lower[0] >= '0' &&
        static_cast<size_t>(lower[0] - '0') < kProxyMethodCount)
    {
        method = kProxyMethods[static_cast<size_t>(lower[0] - '0')].method;
        return true;
    }
    return false;
}

bool ProxySettings::operator==(const ProxySettings & other) const
{
    return method == other.method && host == other.host && port == other.port &&
        userName == other.userName && password == other.password &&
        command == other.command && excludeList == other.excludeList &&
        dns == other.dns && evenLocalhost == other.evenLocalhost;
}

std::vector<std::string> ProxyRawSettingNames()
{
    std::vector<std::string> names;
    names.push_back("ProxyMethod");
    names.push_back("ProxyHost");
    names.push_back("ProxyPort");
    names.push_back("ProxyUsername");
    names.push_back("ProxyPassword");
    names.push_back("ProxyTelnetCommand");
    names.push_back("ProxyLocalCommand");
    names.push_back("ProxyDNS");
    names.push_back("ProxyLocalhost");
    names.push_back("ProxyExcludeList");
    return names;
}

bool IsProxyRawSettingName(const std::string & name)
{
    const std::string lower = LowerAscii(TrimAscii(name));
    const std::vector<std::string> names = ProxyRawSettingNames();
    for (size_t i = 0; i < names.size(); i++)
    {
        if (lower == LowerAscii(names[i]))
        {
            return true;
        }
    }
    return false;
}

bool ApplyProxyRawSetting(const std::string & name, const std::string & value,
    ProxySettings & proxy, std::string & error)
{
    error.clear();
    const std::string lower = LowerAscii(TrimAscii(name));
    const std::string text = TrimAscii(value);

    if (lower == "proxymethod")
    {
        if (!ParseProxyMethod(text, proxy.method))
        {
            error = "Unknown proxy method '" + value + "' (use None, SOCKS4, "
                "SOCKS5, HTTP, Telnet or Cmd).";
            return false;
        }
        return true;
    }
    if (lower == "proxyhost")
    {
        proxy.host = text;
        return true;
    }
    if (lower == "proxyport")
    {
        int port = 0;
        if (!ParsePortValue(text, port))
        {
            error = "The proxy port '" + value +
                "' is not a number between 1 and 65535.";
            return false;
        }
        proxy.port = port;
        return true;
    }
    if (lower == "proxyusername")
    {
        proxy.userName = text;
        return true;
    }
    if (lower == "proxypassword")
    {
        /* Not trimmed beyond the ends: a password may hold spaces. */
        size_t start = value.find_first_not_of(" \t\r\n");
        size_t end = value.find_last_not_of(" \t\r\n");
        proxy.password = start == std::string::npos ? std::string() :
            value.substr(start, end - start + 1);
        return true;
    }
    if (lower == "proxytelnetcommand" || lower == "proxylocalcommand")
    {
        /* Upstream keeps one setting for both and reads it into the local
         * command when the method is 'Cmd'; the value is used verbatim, so
         * a trailing '\n' stays the two characters the user wrote. */
        proxy.command = value;
        return true;
    }
    if (lower == "proxydns")
    {
        int dns = 1;
        if (!ParseAutoSwitch(text, dns))
        {
            error = "The value of 'ProxyDNS' must be 0 (off), 1 (automatic) "
                "or 2 (on), not '" + value + "'.";
            return false;
        }
        proxy.dns = dns;
        return true;
    }
    if (lower == "proxylocalhost")
    {
        bool toggle = false;
        if (!ParseToggle(text, toggle))
        {
            error = "The value of 'ProxyLocalhost' must be 0 or 1, not '" +
                value + "'.";
            return false;
        }
        proxy.evenLocalhost = toggle;
        return true;
    }
    if (lower == "proxyexcludelist")
    {
        proxy.excludeList = text;
        return true;
    }

    error = "The session setting '" + name + "' is not one this build "
        "applies (it applies " + JoinNames(ProxyRawSettingNames()) +
        "); it would be dropped.";
    return false;
}

std::vector<std::string> SessionRawSettingNames()
{
    std::vector<std::string> names = ProxyRawSettingNames();
    for (const char * name : {"Tunnel", "TunnelHostName", "TunnelPortNumber",
            "TunnelUserName", "TunnelPassword", "TunnelPublicKeyFile",
            "TunnelPassphrase", "TunnelHostKey", "TunnelLocalPortNumber",
            "TunnelPasswordPlain", "TunnelPassphrasePlain"})
        names.push_back(name);
    /* The FTP engine's policy, under upstream's names. */
    names.push_back("FtpPasvMode");
    names.push_back("FtpForcePasvIp");
    names.push_back("FtpUseMlsd");
    names.push_back("FtpAccount");
    /* TLS policy. 'Ftps', 'MinTlsVersion' and 'TlsCertificateFile' are
     * upstream's names; the remaining three are what a client without a
     * linked TLS library can verify with, and curl takes files, so they
     * are this build's own spelling. */
    names.push_back("Ftps");
    names.push_back("MinTlsVersion");
    names.push_back("MaxTlsVersion");
    names.push_back("TlsCertificateFile");
    names.push_back("TlsCertificateKeyFile");
    names.push_back("CaCertificateFile");
    names.push_back("CaCertificateDir");
    names.push_back("PinnedPublicKey");
    /* S3 object options and requester-pays headers. */
    names.push_back("S3StorageClass");
    names.push_back("S3Acl");
    names.push_back("S3ServerSideEncryption");
    names.push_back("S3KmsKeyId");
    names.push_back("S3RequestPayer");
    names.push_back("S3Metadata");
    return names;
}

bool IsSessionRawSettingName(const std::string & name)
{
    const std::string lower = LowerAscii(TrimAscii(name));
    const std::vector<std::string> names = SessionRawSettingNames();
    for (size_t i = 0; i < names.size(); i++)
    {
        if (lower == LowerAscii(names[i]))
        {
            return true;
        }
    }
    return false;
}

/* Upstream's TTlsVersion: 10..13, with 'default' keeping the library's
 * own floor. Names in the forms people write are accepted. */
bool ParseTlsVersion(const std::string & text, int & version)
{
    std::string lower = LowerAscii(TrimAscii(text));
    if (lower.empty() || lower == "default" || lower == "auto" || lower == "0")
    {
        version = 0;
        return true;
    }
    if (lower.compare(0, 3, "tls") == 0)
    {
        lower.erase(0, 3);
    }
    if (lower.size() == 1 && lower[0] == 'v')
    {
        return false;
    }
    if (!lower.empty() && lower[0] == 'v')
    {
        lower.erase(0, 1);
    }
    int major = 0;
    int minor = 0;
    const size_t dot = lower.find('.');
    if (dot == std::string::npos)
    {
        if (lower.size() == 2)
        {
            /* Upstream's two-digit form: 12 is TLS 1.2. */
            major = lower[0] - '0';
            minor = lower[1] - '0';
        }
        else
        {
            return false;
        }
    }
    else
    {
        if (lower.substr(0, dot) != "1" || dot + 1 >= lower.size())
        {
            return false;
        }
        major = 1;
        minor = lower[dot + 1] - '0';
    }
    if (major != 1 || minor < 0 || minor > 3)
    {
        return false;
    }
    version = 10 + minor;
    return true;
}

/* Upstream's TFtps, by name or number. */
bool ParseFtpsMode(const std::string & text, int & mode)
{
    const std::string lower = LowerAscii(TrimAscii(text));
    if (lower == "0" || lower == "none" || lower == "off" || lower == "no")
    {
        mode = 0;
        return true;
    }
    if (lower == "1" || lower == "implicit")
    {
        mode = 1;
        return true;
    }
    if (lower == "2" || lower == "explicit" || lower == "explicits" ||
        lower == "explicits sl" || lower == "explicitsel")
    {
        mode = 2;
        return true;
    }
    if (lower == "3" || lower == "explicittls" || lower == "tls")
    {
        mode = 3;
        return true;
    }
    return false;
}

bool ApplySessionRawSetting(const std::string & name, const std::string & value,
    SessionOptions & options, std::string & error)
{
    error.clear();
    const std::string lower = LowerAscii(TrimAscii(name));
    const std::string text = TrimAscii(value);

    /* The proxy names keep their own table: they were here first, they
     * have their own validation, and the messages they produce are the
     * ones the sessions in the field already quote. */
    if (lower.compare(0, 5, "proxy") == 0)
    {
        return ApplyProxyRawSetting(name, value, options.proxy, error);
    }

    if (lower == "tunnel")
    {
        if (text != "0" && text != "1")
        {
            error = Texts::Translate("Tunnel must be 0 (off) or 1 (on).");
            return false;
        }
        options.tunnel.enabled = text == "1";
        return true;
    }
    if (lower == "tunnelportnumber")
    {
        int port = 0;
        if (!ParsePortValue(text, port) || port < 1 || port > 65535)
        {
            error = Texts::Translate("TunnelPortNumber must be between 1 and 65535.");
            return false;
        }
        options.tunnel.portNumber = port;
        return true;
    }
    if (lower == "tunnellocalportnumber")
    {
        // Unlike upstream, the native tunnel exposes no listening port.
        if (text != "0")
        {
            error = Texts::Translate("TunnelLocalPortNumber must be 0: native SSH tunnels use "
                "a private socket pair, not a TCP listener.");
            return false;
        }
        return true;
    }
    if (lower == "tunnelhostname") { options.tunnel.hostName = text; return true; }
    if (lower == "tunnelusername") { options.tunnel.userName = text; return true; }
    if (lower == "tunnelhostkey") { options.tunnel.hostKey = text; return true; }
    if (lower == "tunnelpublickeyfile") { options.tunnel.privateKeyFile = value; return true; }
    // Passwords and passphrases are opaque, including leading/trailing spaces.
    if (lower == "tunnelpassword" || lower == "tunnelpasswordplain")
        { options.tunnel.password = value; return true; }
    if (lower == "tunnelpassphrase" || lower == "tunnelpassphraseplain")
        { options.tunnel.keyPassphrase = value; return true; }

    if (lower == "ftppasvmode")
    {
        bool passive = true;
        if (!ParseToggle(text, passive))
        {
            error = "The value of 'FtpPasvMode' must be 0 (active) or 1 "
                "(passive), not '" + value + "'.";
            return false;
        }
        options.ftp.passiveMode = passive;
        return true;
    }
    if (lower == "ftpforcepasvip")
    {
        int mode = 1;
        if (!ParseAutoSwitch(text, mode))
        {
            error = "The value of 'FtpForcePasvIp' must be 0 (off), 1 "
                "(automatic) or 2 (on), not '" + value + "'.";
            return false;
        }
        options.ftp.forcePasvIp = mode;
        return true;
    }
    if (lower == "ftpusemlsd")
    {
        int mode = 1;
        if (!ParseAutoSwitch(text, mode))
        {
            error = "The value of 'FtpUseMlsd' must be 0 (off), 1 "
                "(automatic) or 2 (on), not '" + value + "'.";
            return false;
        }
        options.ftp.useMlsd = mode;
        return true;
    }
    if (lower == "ftpaccount")
    {
        options.ftp.account = text;
        return true;
    }
    if (lower == "ftps")
    {
        int mode = 0;
        if (!ParseFtpsMode(text, mode))
        {
            error = "The value of 'Ftps' must be 0 (none), 1 (implicit), "
                "2 (explicit SSL) or 3 (explicit TLS), not '" + value + "'.";
            return false;
        }
        options.tls.ftpsMode = mode;
        return true;
    }
    if (lower == "mintlsversion" || lower == "maxtlsversion")
    {
        int version = 0;
        if (!ParseTlsVersion(text, version))
        {
            error = "The value of '" + name + "' must be a TLS version "
                "(1.0, 1.1, 1.2, 1.3, or 'default'), not '" + value + "'.";
            return false;
        }
        if (lower == "mintlsversion")
        {
            options.tls.minVersion = version;
        }
        else
        {
            options.tls.maxVersion = version;
        }
        return true;
    }
    if (lower == "tlscertificatefile")
    {
        options.tls.clientCertificate = text;
        return true;
    }
    if (lower == "tlscertificatekeyfile")
    {
        options.tls.clientKey = text;
        return true;
    }
    if (lower == "cacertificatefile")
    {
        options.tls.caFile = text;
        return true;
    }
    if (lower == "cacertificatedir")
    {
        options.tls.caDirectory = text;
        return true;
    }
    if (lower == "pinnedpublickey")
    {
        options.tls.pinnedPublicKey = text;
        return true;
    }
    if (lower == "s3storageclass")
    {
        static const char * const kClasses[] = {
            "STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA",
            "INTELLIGENT_TIERING", "GLACIER", "DEEP_ARCHIVE", "GLACIER_IR",
            "EXPRESS_ONEZONE"
        };
        if (text.empty())
        {
            options.s3.storageClass.clear();
            return true;
        }
        std::string upper = text;
        for (size_t i = 0; i < upper.size(); i++)
        {
            upper[i] = static_cast<char>(toupper(static_cast<unsigned char>(upper[i])));
        }
        bool known = false;
        for (size_t i = 0; i < sizeof(kClasses) / sizeof(kClasses[0]); i++)
        {
            if (upper == kClasses[i])
            {
                known = true;
                break;
            }
        }
        if (!known)
        {
            error = "Unsupported S3StorageClass '" + value +
                "' (use STANDARD, REDUCED_REDUNDANCY, STANDARD_IA, ONEZONE_IA, "
                "INTELLIGENT_TIERING, GLACIER, DEEP_ARCHIVE, GLACIER_IR or "
                "EXPRESS_ONEZONE).";
            return false;
        }
        options.s3.storageClass = upper;
        return true;
    }
    if (lower == "s3acl")
    {
        static const char * const kAcls[] = {
            "private", "public-read", "public-read-write",
            "authenticated-read", "aws-exec-read", "bucket-owner-read",
            "bucket-owner-full-control"
        };
        if (text.empty())
        {
            options.s3.acl.clear();
            return true;
        }
        const std::string aclLower = LowerAscii(text);
        bool known = false;
        for (size_t i = 0; i < sizeof(kAcls) / sizeof(kAcls[0]); i++)
        {
            if (aclLower == kAcls[i])
            {
                known = true;
                break;
            }
        }
        if (!known)
        {
            error = "Unsupported S3Acl '" + value +
                "' (use private, public-read, public-read-write, "
                "authenticated-read, aws-exec-read, bucket-owner-read or "
                "bucket-owner-full-control).";
            return false;
        }
        options.s3.acl = aclLower;
        return true;
    }
    if (lower == "s3serversideencryption")
    {
        if (text.empty() || LowerAscii(text) == "none")
        {
            options.s3.serverSideEncryption.clear();
            return true;
        }
        const std::string sseLower = LowerAscii(text);
        if (sseLower == "aes256")
        {
            options.s3.serverSideEncryption = "AES256";
            return true;
        }
        if (sseLower == "aws:kms" || sseLower == "aws:kms:dsse")
        {
            options.s3.serverSideEncryption = sseLower;
            return true;
        }
        error = "Unsupported S3ServerSideEncryption '" + value +
            "' (use AES256, aws:kms, aws:kms:dsse or none).";
        return false;
    }
    if (lower == "s3kmskeyid")
    {
        for (size_t i = 0; i < text.size(); i++)
        {
            if (text[i] == '\r' || text[i] == '\n')
            {
                error = "The value of 'S3KmsKeyId' cannot contain line breaks.";
                return false;
            }
        }
        options.s3.kmsKeyId = text;
        return true;
    }
    if (lower == "s3requestpayer")
    {
        const std::string payerLower = LowerAscii(text);
        if (payerLower == "requester")
        {
            options.s3.requestPayer = true;
            return true;
        }
        bool toggle = false;
        if (!ParseToggle(text, toggle))
        {
            error = "The value of 'S3RequestPayer' must be 0, 1 or "
                "'requester', not '" + value + "'.";
            return false;
        }
        options.s3.requestPayer = toggle;
        return true;
    }
    if (lower == "s3metadata")
    {
        options.s3.metadata.clear();
        if (text.empty())
        {
            return true;
        }
        size_t pos = 0;
        while (pos < text.size())
        {
            size_t next = text.find_first_of(",;", pos);
            const std::string pair = TrimAscii(next == std::string::npos ?
                text.substr(pos) : text.substr(pos, next - pos));
            pos = next == std::string::npos ? text.size() : next + 1;
            if (pair.empty())
            {
                continue;
            }
            const size_t eq = pair.find('=');
            if (eq == std::string::npos || eq == 0)
            {
                error = "The value of 'S3Metadata' must be KEY=VALUE pairs, "
                    "not '" + pair + "'.";
                return false;
            }
            const std::string metaKey = LowerAscii(TrimAscii(pair.substr(0, eq)));
            const std::string metaVal = TrimAscii(pair.substr(eq + 1));
            if (metaKey.empty())
            {
                error = "An S3Metadata entry has an empty key.";
                return false;
            }
            for (size_t k = 0; k < metaKey.size(); k++)
            {
                const char c = metaKey[k];
                const bool ok = (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
                if (!ok)
                {
                    error = "Invalid S3Metadata key '" + metaKey + "'.";
                    return false;
                }
            }
            for (size_t k = 0; k < metaVal.size(); k++)
            {
                if (metaVal[k] == '\r' || metaVal[k] == '\n')
                {
                    error = "An S3Metadata value cannot contain line breaks.";
                    return false;
                }
            }
            options.s3.metadata[metaKey] = metaVal;
        }
        return true;
    }

    error = "The session setting '" + name + "' is not one this build "
        "applies (it applies " + JoinNames(SessionRawSettingNames()) +
        "); it would be dropped.";
    return false;
}

/* Decodes the base64 of an OpenSSH or 'sha256//' hash into its bytes. */
bool Base64ToBytes(const std::string & text, std::string & out)
{
    static const char * alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    out.clear();
    /* Unsigned, and masked back to the bits that have not been emitted
     * yet: a signed accumulator grew past INT_MAX on the fifth character
     * of any input, which is undefined behaviour rather than a long
     * fingerprint, and a digest is only ever 32 bytes. */
    unsigned int accumulator = 0;
    int bits = 0;
    for (size_t i = 0; i < text.size(); i++)
    {
        const char c = text[i];
        if (c == '=')
        {
            break;
        }
        const char * found = strchr(alphabet, c);
        if (found == NULL)
        {
            return false;
        }
        accumulator = ((accumulator << 6) |
            static_cast<unsigned int>(found - alphabet)) & 0xFFFu;
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out += static_cast<char>((accumulator >> bits) & 0xFFu);
        }
    }
    return true;
}

/*
 * The SHA-256 host key pin of a '-hostkey=' value, as the base64 spelling
 * of the digest (unpadded, the way OpenSSH prints it). Accepted forms are
 * the hex digest with optional ':' separators, OpenSSH's 'SHA256:base64'
 * and curl's old 'sha256//base64' spelling. All of them are the digest of
 * the same host key, so the conversion decodes and re-encodes instead of
 * hashing the key again; both sides of Session::HostKeyMatches go through
 * here, so one pin works in every spelling. No SSH protocol goes through
 * curl any more, so this is an internal comparison, not a curl option.
 */
bool HostKeySha256(const std::string & hostKey, std::string & base64)
{
    base64.clear();
    std::string text = hostKey;
    std::string prefix;
    const size_t colon = text.find(':');
    if (colon != std::string::npos)
    {
        prefix = LowerAscii(text.substr(0, colon));
    }
    if (prefix == "sha256")
    {
        text.erase(0, colon + 1);
    }
    else if (text.size() > 8 && LowerAscii(text.substr(0, 8)) == "sha256//")
    {
        text.erase(0, 8);
    }

    std::string compact;
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] != ':' && text[i] != ' ' && text[i] != '-')
        {
            compact += text[i];
        }
    }

    std::string bytes;
    const bool looksHex = compact.size() == 64;
    if (looksHex)
    {
        for (size_t i = 0; i < compact.size(); i++)
        {
            if (!isxdigit(static_cast<unsigned char>(compact[i])))
            {
                return false;
            }
        }
        for (size_t i = 0; i < compact.size(); i += 2)
        {
            const unsigned char high = static_cast<unsigned char>(compact[i]);
            const unsigned char low = static_cast<unsigned char>(compact[i + 1]);
            const int hi = high <= '9' ? high - '0' : (high | 0x20) - 'a' + 10;
            const int lo = low <= '9' ? low - '0' : (low | 0x20) - 'a' + 10;
            bytes += static_cast<char>((hi << 4) | lo);
        }
    }
    else if (!Base64ToBytes(compact, bytes) || bytes.size() != 32)
    {
        /* Neither a hex digest nor the base64 of one: an MD5 fingerprint
         * or a plain typo, and a pin that cannot be applied is worse than
         * no pin, so the caller has to notice. */
        return false;
    }

    static const char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0; i < bytes.size(); i += 3)
    {
        const unsigned int group =
            (static_cast<unsigned char>(bytes[i]) << 16) |
            ((i + 1 < bytes.size() ? static_cast<unsigned char>(bytes[i + 1]) : 0) << 8) |
            (i + 2 < bytes.size() ? static_cast<unsigned char>(bytes[i + 2]) : 0);
        const int remaining = static_cast<int>(bytes.size() - i);
        base64 += kAlphabet[(group >> 18) & 0x3f];
        base64 += kAlphabet[(group >> 12) & 0x3f];
        if (remaining > 1)
        {
            base64 += kAlphabet[(group >> 6) & 0x3f];
        }
        if (remaining > 2)
        {
            base64 += kAlphabet[group & 0x3f];
        }
    }
    return true;
}

bool SessionUsesImplicitTls(const SessionOptions & options)
{
    const std::string protocol = LowerAscii(options.protocol);
    if (protocol == "ftps")
    {
        return true;
    }
    return protocol == "ftp" && options.tls.ftpsMode == 1;
}

int SessionDefaultPort(const std::string & protocol, int ftpsMode)
{
    const std::string lower = LowerAscii(protocol);
    if (lower == "ftp")
    {
        return ftpsMode == 1 ? 990 : 21;
    }
    if (lower == "ftps")
    {
        return 990;
    }
    if (lower == "http" || lower == "dav")
    {
        return 80;
    }
    if (lower == "https" || lower == "s3" || lower == "webdav")
    {
        return 443;
    }
    return 22;
}

bool SessionUsesTls(const SessionOptions & options)
{
    const std::string lower = LowerAscii(options.protocol);
    if (lower == "ftps")
    {
        return true;
    }
    if (lower == "ftp")
    {
        return options.tls.ftpsMode != 0;
    }
    return lower == "https" || lower == "s3" || lower == "webdav";
}

/* A certificate fingerprint (the 64 hex digits of a SHA-256, with or
 * without separators) cannot be checked by this build: getting the
 * server's certificate would need a TLS library. Saying so beats
 * connecting as if it had been verified. */
bool LooksLikeCertificateFingerprint(const std::string & text)
{
    std::string hex;
    for (size_t i = 0; i < text.size(); i++)
    {
        const char c = text[i];
        if (c == ':' || c == ' ' || c == '-')
        {
            continue;
        }
        if (!isxdigit(static_cast<unsigned char>(c)))
        {
            return false;
        }
        hex += c;
    }
    return hex.size() == 64 || hex.size() == 40 || hex.size() == 32;
}

bool ValidateSessionSettings(const SessionOptions & options, std::string & error)
{
    error.clear();
    if (!ValidateProxySettings(options.proxy, error))
    {
        return false;
    }
    if (options.tunnel.enabled)
    {
        if (!UseNativeSftp(options.protocol) && !UseNativeScp(options.protocol))
        {
            error = Texts::Translate("SSH tunnels currently support sftp://, scp:// and ssh:// "
                "sessions only; this protocol will not be connected directly.");
            return false;
        }
        if (options.tunnel.hostName.empty() ||
            HasWhitespaceOrControl(options.tunnel.hostName))
        {
            error = Texts::Translate("TunnelHostName must be a nonempty host name without "
                "whitespace or control characters.");
            return false;
        }
        if (options.tunnel.portNumber < 1 || options.tunnel.portNumber > 65535)
        {
            error = Texts::Translate("TunnelPortNumber must be between 1 and 65535.");
            return false;
        }
    }
    if (options.tls.minVersion != 0 && options.tls.maxVersion != 0 &&
        options.tls.minVersion > options.tls.maxVersion)
    {
        error = "MinTlsVersion is higher than MaxTlsVersion: no version "
            "would be acceptable.";
        return false;
    }
    const bool tls = SessionUsesTls(options);
    if (options.tls.ftpsMode != 0 && !tls)
    {
        error = "The 'Ftps' setting applies to ftp:// and ftps:// sessions, "
            "not to '" + options.protocol + "'.";
        return false;
    }
    if (!tls &&
        (!options.tls.clientCertificate.empty() ||
         !options.tls.clientKey.empty() ||
         !options.tls.caFile.empty() ||
         !options.tls.caDirectory.empty() ||
         !options.tls.pinnedPublicKey.empty() ||
         options.tls.minVersion != 0 || options.tls.maxVersion != 0))
    {
        error = "The TLS settings apply to a TLS session (ftps://, ftpes:// "
            "or https://), and this is a '" + options.protocol + "' session.";
        return false;
    }
    const std::string protocol = LowerAscii(options.protocol);
    if (!options.s3.Empty() && protocol != "s3")
    {
        error = "The S3 object settings apply to s3:// sessions, not to '" +
            options.protocol + "'.";
        return false;
    }
    if (!options.s3.kmsKeyId.empty() &&
        options.s3.serverSideEncryption != "aws:kms" &&
        options.s3.serverSideEncryption != "aws:kms:dsse")
    {
        error = "S3KmsKeyId requires S3ServerSideEncryption=aws:kms (or "
            "aws:kms:dsse).";
        return false;
    }
    if (tls && !options.hostKey.empty() && options.hostKey != "*" &&
        LooksLikeCertificateFingerprint(options.hostKey))
    {
        error = "This build cannot check a TLS certificate fingerprint (" +
            options.hostKey + "): that needs the server's certificate, and "
            "no TLS library is linked. Pin the public key instead "
            "(-rawsettings PinnedPublicKey=sha256//BASE64, or a PEM/DER "
            "file), or accept any certificate with -hostkey=\"*\".";
        return false;
    }
    return true;
}

bool ValidateProxySettings(const ProxySettings & proxy, std::string & error)
{
    error.clear();
    if (!proxy.Active())
    {
        return true;
    }
    if (proxy.method == ProxyMethod::Local)
    {
        if (TrimAscii(proxy.command).empty())
        {
            error = "A local (Cmd) proxy needs a command: set "
                "ProxyTelnetCommand=COMMAND with %host and %port where the "
                "destination belongs.";
            return false;
        }
        return true;
    }
    if (TrimAscii(proxy.host).empty())
    {
        error = std::string("The ") + ProxyMethodName(proxy.method) +
            " proxy has no host: set ProxyHost=HOST.";
        return false;
    }
    if (proxy.port != 0 && (proxy.port < 1 || proxy.port > 65535))
    {
        error = "The proxy port must be between 1 and 65535.";
        return false;
    }
    if (proxy.method == ProxyMethod::Telnet && TrimAscii(proxy.command).empty())
    {
        error = "A telnet proxy needs its command: set "
            "ProxyTelnetCommand=COMMAND (upstream's default is "
            "'connect %host %port\\n').";
        return false;
    }
    return true;
}

bool ProxyUsableByCurl(const ProxySettings & proxy, std::string & error)
{
    error.clear();
    if (!proxy.Active())
    {
        return true;
    }
    if (proxy.method == ProxyMethod::Telnet || proxy.method == ProxyMethod::Local)
    {
        error = std::string("This protocol connects through curl, which cannot "
            "run a ") +
            (proxy.method == ProxyMethod::Telnet ? "telnet" : "local command") +
            " proxy; use SOCKS4, SOCKS5 or HTTP, or a protocol this build "
            "serves with its own transport.";
        return false;
    }
    return true;
}

namespace {

bool ParsePortNumber(const std::string & text, int & port)
{
    if (text.empty())
    {
        return false;
    }
    unsigned int value = 0;
    for (size_t i = 0; i < text.size(); i++)
    {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c < '0' || c > '9')
        {
            return false;
        }
        const unsigned int digit = c - '0';
        if (value > (65535U - digit) / 10U)
        {
            return false;
        }
        value = value * 10U + digit;
    }
    if (value == 0)
    {
        return false;
    }
    port = static_cast<int>(value);
    return true;
}

int HexDigit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool PercentDecode(const std::string & input, std::string & output)
{
    output.clear();
    for (size_t i = 0; i < input.size(); i++)
    {
        if (input[i] != '%')
        {
            output += input[i];
            continue;
        }
        if (i + 2 >= input.size())
        {
            return false;
        }
        const int high = HexDigit(static_cast<unsigned char>(input[i + 1]));
        const int low = HexDigit(static_cast<unsigned char>(input[i + 2]));
        if (high < 0 || low < 0)
        {
            return false;
        }
        const char decoded = static_cast<char>((high << 4) | low);
        if (decoded == '\0')
        {
            return false;
        }
        output += decoded;
        i += 2;
    }
    return true;
}

bool HasWhitespaceOrControl(const std::string & text)
{
    for (size_t i = 0; i < text.size(); i++)
    {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        if (c <= 0x20 || c == 0x7f)
        {
            return true;
        }
    }
    return false;
}

} // namespace

/*
 * The URL schemes this client connects with, and the protocol name each
 * one stands for: 'ftpes' is FTP with explicit TLS, so it is stored as
 * 'ftp' with the TLS mode set beside it.
 *
 * 'savesession -protocol=' is checked against the same list, so a site
 * cannot be stored under a scheme nothing here can open. Before that the
 * value was stored as written - an empty one included, which came back as
 * '://@host' in the session list and connected to nothing.
 */
bool ResolveProtocolScheme(const std::string & scheme, std::string & protocol)
{
    static const struct
    {
        const char * scheme;
        const char * protocol;
    } kSchemes[] = {
        { "sftp", "sftp" }, { "ssh", "ssh" }, { "scp", "scp" },
        { "ftp", "ftp" }, { "ftps", "ftps" }, { "ftpes", "ftp" },
        { "http", "http" }, { "https", "https" }, { "s3", "s3" },
        { "dav", "dav" }, { "webdav", "webdav" },
    };
    for (size_t i = 0; i < sizeof(kSchemes) / sizeof(kSchemes[0]); i++)
    {
        if (scheme == kSchemes[i].scheme)
        {
            protocol = kSchemes[i].protocol;
            return true;
        }
    }
    protocol.clear();
    return false;
}

bool ParseSiteUrl(const std::string & url, SessionOptions & options, std::string & error)
{
    error.clear();
    SessionOptions parsed = options;
    parsed.hostName.clear();
    parsed.initialDirectory.clear();

    std::string rest = url;
    std::string scheme;
    std::string::size_type pos = rest.find("://");
    const bool hadScheme = (pos != std::string::npos);
    if (pos != std::string::npos)
    {
        scheme = rest.substr(0, pos);
        rest = rest.substr(pos + 3);
    }
    else
    {
        scheme = "sftp";
    }
    for (size_t i = 0; i < scheme.size(); i++)
    {
        scheme[i] = static_cast<char>(tolower(static_cast<unsigned char>(scheme[i])));
    }
    std::string resolved;
    if (!ResolveProtocolScheme(scheme, resolved))
    {
        error = "Unsupported protocol '" + scheme + "'.";
        return false;
    }
    if (url.empty())
    {
        error = "No host name in site URL.";
        return false;
    }

    /* 'ftpes://' is upstream's explicit-TLS spelling of FTP and is the
     * same protocol as 'ftp://' once the TLS mode is set. 'ftps://' means
     * implicit TLS, as upstream's FtpsImplicitPortNumber does. */
    parsed.protocol = resolved;
    if (scheme == "ftps")
    {
        parsed.tls.ftpsMode = 1;
    }
    else if (scheme == "ftpes")
    {
        parsed.tls.ftpsMode = 3;
    }
    int defaultPort = SessionDefaultPort(parsed.protocol, parsed.tls.ftpsMode);
    bool explicitPort = false;

    /* Query and fragment syntax is not meaningful for an SFTP site. */
    if (rest.find('?') != std::string::npos || rest.find('#') != std::string::npos)
    {
        error = "Site URLs must not contain a query or fragment; encode reserved characters with percent escapes.";
        return false;
    }

    /* Split off the path and decode its URI escapes. */
    std::string path;
    pos = rest.find('/');
    if (pos != std::string::npos)
    {
        const std::string encodedPath = rest.substr(pos);
        rest = rest.substr(0, pos);
        if (!PercentDecode(encodedPath, path))
        {
            error = "Invalid percent escape in site URL path.";
            return false;
        }
    }

    /* Split off credentials. A literal '@' in user information must be escaped. */
    std::string::size_type at = rest.find('@');
    if (at != std::string::npos)
    {
        if (rest.find('@', at + 1) != std::string::npos)
        {
            error = "Invalid site URL authority; escape '@' in credentials as '%40'.";
            return false;
        }
        const std::string auth = rest.substr(0, at);
        rest = rest.substr(at + 1);
        const std::string::size_type colon = auth.find(':');
        std::string user;
        std::string password;
        const std::string encodedUser = auth.substr(0, colon);
        if (encodedUser.empty() || !PercentDecode(encodedUser, user) ||
            user.empty())
        {
            error = "Invalid user name in site URL.";
            return false;
        }
        parsed.userName = user;
        if (colon != std::string::npos)
        {
            if (!PercentDecode(auth.substr(colon + 1), password))
            {
                error = "Invalid percent escape in site URL credentials.";
                return false;
            }
            parsed.password = password;
        }
    }

    /* Host and port. IPv6 literals must be bracketed. */
    std::string encodedHost;
    if (!rest.empty() && rest[0] == '[')
    {
        const std::string::size_type close = rest.find(']');
        if (close == std::string::npos || close == 1)
        {
            error = "Malformed bracketed IPv6 address in site URL.";
            return false;
        }
        encodedHost = rest.substr(1, close - 1);
        const std::string tail = rest.substr(close + 1);
        if (!tail.empty())
        {
            if (tail[0] != ':' || !ParsePortNumber(tail.substr(1), parsed.portNumber))
            {
                error = "Invalid port or characters after bracketed host in site URL.";
                return false;
            }
            explicitPort = true;
        }
    }
    else
    {
        const std::string::size_type colon = rest.find(':');
        if (colon != std::string::npos)
        {
            if (rest.find(':', colon + 1) != std::string::npos)
            {
                error = "IPv6 addresses in site URLs must be enclosed in brackets.";
                return false;
            }
            encodedHost = rest.substr(0, colon);
            if (!ParsePortNumber(rest.substr(colon + 1), parsed.portNumber))
            {
                error = "Invalid port number in site URL.";
                return false;
            }
            explicitPort = true;
        }
        else
        {
            encodedHost = rest;
        }
    }

    if (!explicitPort)
    {
        if (hadScheme && (scheme == "ftp" || scheme == "ftps" || scheme == "ftpes" ||
                          scheme == "http" || scheme == "https" ||
                          scheme == "dav" || scheme == "webdav"))
        {
            parsed.portNumber = defaultPort;
        }
        else if (options.portNumber > 0)
        {
            parsed.portNumber = options.portNumber;
        }
        else
        {
            parsed.portNumber = defaultPort;
        }
    }

    if (!PercentDecode(encodedHost, parsed.hostName))
    {
        error = "Invalid percent escape in site URL host name.";
        return false;
    }
    if (parsed.hostName.empty())
    {
        error = "No host name in site URL.";
        return false;
    }
    if (HasWhitespaceOrControl(parsed.hostName))
    {
        error = "Invalid whitespace or control character in site URL host name.";
        return false;
    }
    if (parsed.portNumber <= 0 || parsed.portNumber > 65535)
    {
        error = "Invalid port number in site URL.";
        return false;
    }

    parsed.initialDirectory = path;
    options = parsed;
    return true;
}

// libssh can receive data, exit-status and transport shutdown in one poll.
// A later get_exit_status() rejects a session in SSH_SESSION_STATE_ERROR even
// if the authenticated status was already received. Consume exec/shell data
// and record completion while processing the packets, before that teardown.
// Status alone is NOT completion: require the peer's EOF or channel-close too.
struct Session::ChannelCallbacks
{
    ssh_channel_callbacks_struct callbacks{};
    Session & owner;
    int status = INT_MAX;
    bool remoteEnd = false;
    bool receivedData = false;

    explicit ChannelCallbacks(Session & session) : owner(session)
    {
        ssh_callbacks_init(&callbacks);
        callbacks.userdata = this;
        callbacks.channel_data_function = OnData;
        callbacks.channel_eof_function = OnEnd;
        callbacks.channel_close_function = OnEnd;
        callbacks.channel_exit_status_function = OnStatus;
        callbacks.channel_exit_signal_function = OnSignal;
    }

    void UpdateStatus()
    {
        if (remoteEnd && status != INT_MAX) owner.mExitCode = status;
    }

    static int OnData(ssh_session, ssh_channel, void * data, uint32_t length,
        int isStderr, void * context)
    {
        ChannelCallbacks & self = *static_cast<ChannelCallbacks *>(context);
        self.receivedData = true;
        self.owner.HandleChannelData(data, length, isStderr != 0);
        return static_cast<int>(length); // All bytes delivered; none left buffered in libssh.
    }

    static void OnEnd(ssh_session, ssh_channel, void * context)
    {
        ChannelCallbacks & self = *static_cast<ChannelCallbacks *>(context);
        self.remoteEnd = true;
        self.UpdateStatus();
    }

    static void OnStatus(ssh_session, ssh_channel, int status, void * context)
    {
        ChannelCallbacks & self = *static_cast<ChannelCallbacks *>(context);
        self.status = status >= 0 ? status : 1;
        self.UpdateStatus();
    }

    static void OnSignal(ssh_session, ssh_channel, const char *, int,
        const char *, const char *, void * context)
    {
        ChannelCallbacks & self = *static_cast<ChannelCallbacks *>(context);
        self.status = 1; // A signalled command must never become a successful exit.
        self.UpdateStatus();
    }
};

Session::Session() :
    mSsh(NULL),
    mTransportSocket(-1),
    mTunnelTransport(false),
    mChannel(NULL),
    mSftp(NULL),
    mExitCode(INT_MAX),
    mShellMode(false),
    mShellColumns(80),
    mShellRows(24),
    mOpen(false),
    mAlive(false),
    mPasswordUsed(false),
    mReceivedStart(0),
    mReceivedEnd(0),
    mOutputSink(NULL),
    mOutputSinkCtx(NULL),
    mCaptureStderr(false)
{
}

void Session::AppendCapturedStderr(const void * data, size_t len)
{
    mCapturedStderr.append(static_cast<const char *>(data), len);
}

bool Session::TakeAllReceived(std::string & out)
{
    out.assign(mReceived.begin() + mReceivedStart,
        mReceived.begin() + mReceivedEnd);
    mReceived.clear();
    mReceivedStart = 0;
    mReceivedEnd = 0;
    return true;
}

bool Session::SendEof()
{
    if (mChannel == NULL)
    {
        return false;
    }
    /* The channel EOF: 'scp -t' waits for the end of its input before
     * it exits and reports its status. */
    return ssh_channel_send_eof(static_cast<ssh_channel>(mChannel)) == SSH_OK;
}

void Session::PumpUntilExit()
{
    while (mAlive)
    {
        if (!Pump())
        {
            break;
        }
    }
}

void Session::SetOutputSink(OutputSinkFn sink, void * ctx)
{
    mOutputSink = sink;
    mOutputSinkCtx = ctx;
}

void Session::DeliverChannelData(const void * data, size_t len)
{
    if (mOutputSink != NULL)
    {
        /* An exec session prints its command output instead of feeding
         * the SFTP protocol layer. */
        mOutputSink(mOutputSinkCtx, static_cast<const char *>(data), len);
        return;
    }
    PushReceivedData(data, len);
}

void Session::HandleChannelData(const void * data, size_t len, bool isStderr)
{
    if (isStderr && !mShellMode)
    {
        if (mCaptureStderr) AppendCapturedStderr(data, len);
        else Console::Instance().Write(std::string(static_cast<const char *>(data), len));
    }
    else
    {
        DeliverChannelData(data, len);
    }
}

Session::~Session()
{
    Close();
}

std::string Session::UserName() const
{
    return mUserName;
}

std::string Session::HostDescription() const
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%d", mOptions.portNumber);
    return mOptions.hostName + ":" + buffer;
}

void Session::PushReceivedData(const void * data, size_t len)
{
    if (len == 0)
    {
        return;
    }
    const char * bytes = static_cast<const char *>(data);
    if (getenv("LSCP_TRACE") != NULL)
    {
        std::string dump = "SFTP rx ";
        char hex[8];
        for (size_t i = 0; i < len && i < 32; i++)
        {
            snprintf(hex, sizeof(hex), "%02X ",
                static_cast<unsigned char>(bytes[i]));
            dump += hex;
        }
        Console::Instance().LogEvent(dump);
    }
    Console::Instance().LogTraffic(data, len, true);
    /* Compact the buffer if the consumer has caught up. */
    if (mReceivedStart == mReceivedEnd)
    {
        mReceived.clear();
        mReceivedStart = 0;
        mReceivedEnd = 0;
    }
    mReceived.insert(mReceived.end(), bytes, bytes + len);
    mReceivedEnd = mReceived.size();
}

bool Session::TakeReceivedData(char * buffer, size_t len)
{
    if (mReceivedEnd - mReceivedStart < len)
    {
        return false;
    }
    memcpy(buffer, &mReceived[mReceivedStart], len);
    mReceivedStart += len;
    if (mReceivedStart == mReceivedEnd)
    {
        mReceived.clear();
        mReceivedStart = 0;
        mReceivedEnd = 0;
    }
    return true;
}

bool Session::SendData(const char * data, size_t len)
{
    if (mChannel == NULL)
    {
        return false;
    }
    Console::Instance().LogTraffic(data, len, false);
    ssh_channel channel = static_cast<ssh_channel>(mChannel);
    size_t sent = 0;
    while (sent < len)
    {
        const int written = ssh_channel_write(channel, data + sent,
            static_cast<uint32_t>(len - sent));
        /* A nonblocking libssh channel can report SSH_AGAIN (a negative
         * result); zero also makes no forward progress. Treat either as a
         * failed write instead of converting it to a huge size_t or
         * spinning forever on an interactive terminal input. */
        if (written <= 0)
        {
            return false;
        }
        sent += static_cast<size_t>(written);
    }
    return true;
}

size_t Session::SendBufferSize()
{
    if (mChannel == NULL)
    {
        return 0;
    }
    const int window = ssh_channel_window_size(
        static_cast<ssh_channel>(mChannel));
    return window > 0 ? static_cast<size_t>(window) : 0;
}

/*
 * One pump of an exec or shell channel: reads whatever stdout and
 * stderr are available without blocking for long, delivers them, and
 * notices the end of the command. SFTP responses use the same pump, feeding
 * the native protocol buffer rather than an exec/shell output callback.
 */
bool Session::Pump()
{
    if (mChannel == NULL)
    {
        return mAlive;
    }
    ssh_channel channel = static_cast<ssh_channel>(mChannel);
    bool readAny = false;
    if (mChannelCallbacks) mChannelCallbacks->receivedData = false;
    for (int stream = 0; stream < 2; stream++)
    {
        const int isStderr = stream == 1 ? 1 : 0;
        for (;;)
        {
            char buffer[16384];
            const int got = ssh_channel_read_nonblocking(channel, buffer,
                sizeof(buffer), isStderr);
            if (got == SSH_AGAIN)
            {
                break;
            }
            if (got == SSH_EOF)
            {
                break;
            }
            if (got == SSH_ERROR)
            {
                mAlive = false;
                // Data callbacks consumed every preceding byte, and a known
                // status is published only after authenticated EOF/close.
                // A subsequent transport shutdown cannot invalidate that
                // completed command. A truncated stream still fails below.
                if (mChannelCallbacks && mExitCode != INT_MAX) return false;
                if (mConnectionError.empty())
                {
                    const char * reason = ssh_get_error(
                        static_cast<ssh_session>(mSsh));
                    mConnectionError = reason != NULL && reason[0] != '\0' ?
                        reason : Texts::ConnectionClosed();
                }
                return false;
            }
            if (got == 0)
            {
                break;
            }
            readAny = true;
            HandleChannelData(buffer, static_cast<size_t>(got), isStderr != 0);
        }
    }
    if (ssh_channel_is_eof(channel) || ssh_channel_is_closed(channel))
    {
        if (mExitCode == INT_MAX)
        {
            // EOF can precede the status. This drives pending packets; a
            // callback still retains the status if the getter reports an
            // error after processing it and a transport close together.
            const int exitCode = ssh_channel_get_exit_status(channel);
            if (exitCode >= 0) mExitCode = exitCode;
        }
        mAlive = false;
        return false;
    }
    if (mChannelCallbacks) readAny = readAny || mChannelCallbacks->receivedData;
    if (!readAny && mAlive)
    {
        /* Wait briefly for the channel to produce something, so a
         * PumpUntilExit loop does not spin. */
        ssh_channel_poll_timeout(channel, 50, 0);
    }
    return mAlive;
}

bool Session::ReceiveData(char * buffer, size_t len)
{
    for (;;)
    {
        if (TakeReceivedData(buffer, len))
        {
            return true;
        }
        if (!mAlive)
        {
            Console::Instance().LogEvent(std::string("The session is no longer alive: ") +
                (mConnectionError.empty() ? std::string("closed by the server") : mConnectionError));
            return false;
        }
        /* Pump() may deliver the last bytes and the end of the channel
         * in one call, so the buffer is checked again at the top before
         * the not-alive case can fail the read. */
        Pump();
    }
}

void Session::NotifyRemoteExit()
{
    mAlive = false;
}

void Session::SetConnectionError(const std::string & error)
{
    mConnectionError = error;
}

namespace {

/*
 * A fingerprint the tools print carries the digest it is in front of:
 * 'ssh-keygen -E md5' writes 'MD5:0b:60:52:...' where the SSH core writes
 * the same digest as '0b:60:52:...' with no marker at all, and OpenSSH's
 * SHA-256 spelling 'SHA256:xyz' is one the core also writes. The marker
 * names the digest and is not part of it, so it is not part of the
 * comparison either: a pin copied from ssh-keygen has to check the key
 * ssh-keygen was shown, not fail against the same key.
 */
std::string WithoutFingerprintMarker(const std::string & text)
{
    const std::string::size_type colon = text.find(':');
    if (colon == std::string::npos || colon == 0 || colon > 8)
    {
        return text;
    }
    const std::string marker = LowerAscii(text.substr(0, colon));
    if (marker == "md5" || marker == "sha256" || marker == "sha-256")
    {
        return text.substr(colon + 1);
    }
    return text;
}

} // namespace

bool Session::HostKeyMatches(const std::string & fingerprint) const
{
    const std::string expected = mOptions.hostKey;
    if (expected.empty())
    {
        return false;
    }
    const std::string expectedDigestText = WithoutFingerprintMarker(expected);
    /*
     * A SHA-256 pin also arrives as a hex digest, with or without ':'
     * separators, where the core reports it as base64 - and as curl's
     * 'sha256//base64'. Normalizing both sides to the same 32 bytes is what
     * lets one '-hostkey=' value work in every spelling instead of only the
     * one a transport happened to compare.
     */
    std::string expectedDigest;
    const bool haveDigest = HostKeySha256(expected, expectedDigest);

    /*
     * The core states one fingerprint, either bare ('SHA256:xyz') or as
     * '<key type> <bits> <fingerprint>', so the whole string and the digest
     * on its own are both accepted.
     */
    if (!fingerprint.empty())
    {
        const std::string::size_type lastSpace = fingerprint.find_last_of(" \t");
        const std::string forms[2] = { fingerprint,
            lastSpace == std::string::npos ? fingerprint
                                           : fingerprint.substr(lastSpace + 1) };
        for (int n = 0; n < 2; n++)
        {
            const std::string & form = forms[n];
            if (form == expected)
            {
                return true;
            }
            const std::string digestText = WithoutFingerprintMarker(form);
            if (digestText == expectedDigestText)
            {
                return true;
            }
            std::string serverDigest;
            if (haveDigest && HostKeySha256(form, serverDigest) &&
                serverDigest == expectedDigest)
            {
                return true;
            }
        }
    }
    return false;
}

/*
 * The lock tokens this session holds. They live with the session, not in
 * a file: a lock belongs to the connection that took it, and a token
 * remembered after the lock expired is worse than none because the
 * server would refuse the write the token was supposed to allow.
 */
void Session::SetDavLock(const std::string & remotePath, const std::string & token)
{
    if (token.empty())
    {
        mOptions.davLocks.erase(remotePath);
        return;
    }
    mOptions.davLocks[remotePath] = token;
}

void Session::ClearDavLock(const std::string & remotePath)
{
    mOptions.davLocks.erase(remotePath);
}

const std::string & Session::DavLockFor(const std::string & remotePath) const
{
    static const std::string none;
    std::map<std::string, std::string>::const_iterator found =
        mOptions.davLocks.find(remotePath);
    return found == mOptions.davLocks.end() ? none : found->second;
}

void Session::SetDavEtag(const std::string & remotePath,
    const std::string & ifMatch, const std::string & ifNoneMatch)
{
    SessionOptions::EtagPrecondition precondition;
    precondition.ifMatch = ifMatch;
    precondition.ifNoneMatch = ifNoneMatch;
    mOptions.davEtags[remotePath] = precondition;
}

void Session::ClearDavEtag(const std::string & remotePath)
{
    mOptions.davEtags.erase(remotePath);
}

namespace {

/*
 * The host-key decision preserves the established policy: a pinned key is
 * checked first, '*' accepts without caching, a cached key is trusted or
 * refused on mismatch, and only a genuinely new key is offered to the user
 * (and, in a run that cannot
 * ask, refused with the fingerprint printed so it can be pinned).
 */
bool VerifyServerKey(Session & session, ssh_session ssh, std::string & error)
{
    const SessionOptions & options = session.Options();
    Console & console = Console::Instance();
    const std::string & host = options.hostName;
    const int port = options.portNumber;

    ssh_key key = NULL;
    if (ssh_get_server_publickey(ssh, &key) != SSH_OK || key == NULL)
    {
        error = "The server did not present a host key.";
        return false;
    }
    const std::string keytype = ssh_key_type_to_char(ssh_key_type(key));
    const std::string fingerprint = Sha256Fingerprint(key);
    const std::string md5Fingerprint = Md5Fingerprint(key);
    char * base64 = NULL;
    std::string blob;
    if (ssh_pki_export_pubkey_base64(key, &base64) == SSH_OK && base64 != NULL)
    {
        blob = base64;
        ssh_string_free_char(base64);
    }
    ssh_key_free(key);

    /* One machine readable line for whatever the server just offered, so
     * that a script or the graphical interface can pin this key later.
     * An SCP session opens a connection per command and is offered the
     * same key every time, so the line is printed once per host and key
     * per process. */
    const std::string hostkeyLine = std::string(session.IsTunnelTransport() ?
        "TUNNELHOSTKEY " : "HOSTKEY ") + keytype + " " + fingerprint;
    static std::set<std::string> reportedHostKeys;
    const bool hostKeyAlreadyReported = !reportedHostKeys.insert(
        host + ":" + std::to_string(port) + " " + hostkeyLine).second;

    if (session.ExpectHostKey())
    {
        if (session.HostKeyMatches(fingerprint) ||
            session.HostKeyMatches(md5Fingerprint))
        {
            if (options.cachePinnedHostKeys)
                StoreHostKey(host.c_str(), port, keytype.c_str(), blob.c_str());
            return true;
        }
        console.WriteLine(hostkeyLine);
        console.WriteLine(std::string("HOSTKEYSTATE ") +
            (session.IsTunnelTransport() ? "tunnel" : "destination") + " changed");
        console.Error(Texts::HostKeyUnexpected(host, port, keytype,
            fingerprint, session.ExpectedHostKey()));
        error = "The host key does not match the expected one";
        return false;
    }

    /* '*' is a deliberate one-session override, not a trust decision: do
     * not poison the persistent host-key cache with an unchecked key. */
    if (session.AcceptAnyHostKey())
    {
        if (!hostKeyAlreadyReported)
        {
            console.WriteLine(hostkeyLine);
        }
        return true;
    }

    const int cacheState = CheckCachedHostKey(host.c_str(), port,
        keytype.c_str(), blob.c_str());
    if (cacheState > 0)
    {
        console.LogEvent(Texts::HostKeyCached(host, port));
        return true;
    }
    if (cacheState < 0)
    {
        console.WriteLine(hostkeyLine);
        console.WriteLine(std::string("HOSTKEYSTATE ") +
            (session.IsTunnelTransport() ? "tunnel" : "destination") + " changed");
        console.Error(Texts::HostKeyMismatch(host, port, keytype, fingerprint));
        error = "The host key does not match the cached one";
        return false;
    }

    console.WriteLine(hostkeyLine);
    console.Error(Texts::HostKeyUnknown(host, port, keytype, fingerprint));
    if (!console.IsInteractive())
    {
        error = session.IsTunnelTransport() ?
            Texts::Translate("The tunnel host key is not cached; use -rawsettings TunnelHostKey=FINGERPRINT to accept it") :
            "The host key is not cached; use -hostkey to accept it";
        return false;
    }
    if (console.Confirm(
            Texts::Translate("Continue connecting and cache the host key?"),
            false))
    {
        StoreHostKey(host.c_str(), port, keytype.c_str(), blob.c_str());
        return true;
    }
    error = "Aborted by the user";
    return false;
}

bool ImportPrivateKeyFile(const std::string & keyFile, const char * passphrase,
    ssh_key * key, std::string & error)
{
    if (!IsPpkKeyFile(keyFile))
    {
        if (ssh_pki_import_privkey_file(keyFile.c_str(), passphrase, NULL, NULL,
                key) == SSH_OK)
            return true;
        error = "Cannot read the private key '" + keyFile +
            "' (or its passphrase is wrong).";
        return false;
    }

    std::string pem;
    if (!PpkPrivateKeyPem(keyFile, passphrase != NULL ? passphrase : "", pem, error))
        return false;
    char tempPath[] = "/tmp/linscp-ppk-XXXXXX";
    const int fd = mkstemp(tempPath);
    if (fd < 0)
    {
        OPENSSL_cleanse(pem.data(), pem.size());
        error = "Cannot create a secure temporary file to import the PPK key.";
        return false;
    }
    size_t written = 0;
    while (written < pem.size())
    {
        const ssize_t count = write(fd, pem.data() + written, pem.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        written += static_cast<size_t>(count);
    }
    const bool fileReady = written == pem.size() && fsync(fd) == 0;
    close(fd);
    OPENSSL_cleanse(pem.data(), pem.size());
    if (!fileReady)
    {
        unlink(tempPath);
        error = "Cannot write the temporary PPK key for libssh.";
        return false;
    }
    const int rc = ssh_pki_import_privkey_file(tempPath, NULL, NULL, NULL, key);
    unlink(tempPath);
    if (rc != SSH_OK)
    {
        error = "The PPK key was decoded but could not be imported by libssh.";
        return false;
    }
    return true;
}

/*
 * Authentication: agent and explicit/default key files first, then
 * keyboard-interactive, then the password. The stored password answers
 * password-style keyboard-interactive prompts too, which is how servers
 * that only offer that method still work from a script.
 */
bool AuthenticateServer(Session & session, ssh_session ssh, std::string & error)
{
    const SessionOptions & options = session.Options();
    Console & console = Console::Instance();

    if (ssh_userauth_none(ssh, NULL) == SSH_AUTH_SUCCESS)
    {
        return true;
    }
    const int methods = ssh_userauth_list(ssh, NULL);
    std::string keyError;

    if (methods & SSH_AUTH_METHOD_PUBLICKEY)
    {
        if (ssh_userauth_agent(ssh, NULL) == SSH_AUTH_SUCCESS)
        {
            return true;
        }
        if (!options.privateKeyFile.empty())
        {
            const std::string keyFile = ExpandTilde(options.privateKeyFile);
            std::string keyPassphrase = options.keyPassphrase;
            for (int attempt = 0; attempt < 3; ++attempt)
            {
                ssh_key key = NULL;
                const char * passphrase = keyPassphrase.empty() ? NULL :
                    keyPassphrase.c_str();
                if (ImportPrivateKeyFile(keyFile, passphrase, &key, keyError))
                {
                    const int rc = ssh_userauth_publickey(ssh, NULL, key);
                    ssh_key_free(key);
                    if (rc == SSH_AUTH_SUCCESS)
                    {
                        return true;
                    }
                    break;
                }
                if (!IsPpkKeyFile(keyFile) || !keyPassphrase.empty() ||
                    !console.IsInteractive() || attempt == 2)
                    break;
                if (!console.ReadPassword(Texts::Translate("Private key passphrase: "),
                        keyPassphrase))
                    break;
            }
        }
        if (options.privateKeyFile.empty() &&
            ssh_userauth_publickey_auto(ssh, NULL, NULL) == SSH_AUTH_SUCCESS)
        {
            return true;
        }
    }

    if (methods & SSH_AUTH_METHOD_INTERACTIVE)
    {
        int rc;
        while ((rc = ssh_userauth_kbdint(ssh, NULL, NULL)) == SSH_AUTH_INFO)
        {
            const int prompts = ssh_userauth_kbdint_getnprompts(ssh);
            for (int i = 0; i < prompts; i++)
            {
                char echo = 0;
                const char * prompt =
                    ssh_userauth_kbdint_getprompt(ssh, i, &echo);
                const std::string text = prompt != NULL ? prompt : "";
                const std::string lower = LowerCaseAscii(text);
                const bool isPassword = echo == 0 &&
                    (lower.find("password") != std::string::npos ||
                     lower.find("passphrase") != std::string::npos);
                std::string answer;
                if (isPassword && !options.password.empty())
                {
                    answer = options.password;
                    session.MarkPasswordUsed();
                }
                else if (echo != 0 && !options.userName.empty() &&
                    (lower.find("username") != std::string::npos ||
                     lower.find("user name") != std::string::npos ||
                     lower.find("login") != std::string::npos))
                {
                    answer = options.userName;
                }
                else if (console.IsInteractive())
                {
                    const bool read = echo != 0 ?
                        console.ReadLine(text, answer) :
                        console.ReadPassword(text, answer);
                    if (!read)
                    {
                        error = "No more input available";
                        return false;
                    }
                }
                else
                {
                    error = "The server asked a question this run cannot "
                        "answer ('" + text + "').";
                    return false;
                }
                ssh_userauth_kbdint_setanswer(ssh,
                    static_cast<unsigned int>(i), answer.c_str());
            }
        }
        if (rc == SSH_AUTH_SUCCESS)
        {
            return true;
        }
    }

    if (methods & SSH_AUTH_METHOD_PASSWORD)
    {
        if (!options.password.empty())
        {
            if (ssh_userauth_password(ssh, NULL,
                    options.password.c_str()) == SSH_AUTH_SUCCESS)
            {
                session.MarkPasswordUsed();
                return true;
            }
        }
        else if (console.IsInteractive())
        {
            std::string answer;
            const std::string user = options.userName.empty() ?
                CurrentUserName() : options.userName;
            if (console.ReadPassword(
                    Texts::PasswordPrompt(user, options.hostName), answer) &&
                ssh_userauth_password(ssh, NULL, answer.c_str()) ==
                    SSH_AUTH_SUCCESS)
            {
                session.MarkPasswordUsed();
                return true;
            }
        }
    }

    const char * reason = ssh_get_error(ssh);
    error = "Authentication failed";
    if (!keyError.empty())
    {
        error += ": " + keyError;
    }
    else if (reason != NULL && reason[0] != '\0')
    {
        error += std::string(": ") + reason;
    }
    else if (!options.password.empty() || !options.privateKeyFile.empty())
    {
        error += ": the server refused the credentials offered.";
    }
    else
    {
        error += ": no password or key was offered (use -password or "
            "-privatekey, or the LINSCP_PASSWORD variable).";
    }
    return false;
}

} // namespace

bool Session::Open(const SessionOptions & options, std::string & error)
{
    /*
     * A proxy is checked before anything is connected: a configuration the
     * transport cannot honour would otherwise turn into a direct connection
     * the session never asked for.
     */
    if (!ValidateSessionSettings(options, error))
    {
        return false;
    }
    if (!UseNativeSftp(options.protocol))
    {
        /* A curl-backed session has no connection of its own; it must
         * still become the current session, because ProtocolClient
         * reads its options for every operation. */
        if (options.hostName.empty())
        {
            error = "No host name was specified.";
            return false;
        }
        /* A proxy the curl protocols cannot carry is refused rather than
         * connected around - except for SCP, whose native libssh transport
         * supports telnet and local-command proxy connections as SFTP does. */
        if (!UseNativeScp(options.protocol) &&
            !ProxyUsableByCurl(options.proxy, error))
        {
            return false;
        }
        /*
         * Nothing here proves the host is there, so ask it once, now: an
         * 'open' of a dead port or a misspelled host has to fail here, as a
         * real connection does, and not turn into a puzzle for the first
         * command. Only an endpoint that cannot be reached counts against
         * us; a directory the server refuses to list is the command's
         * business.
         */
        if (!ProtocolClient::CheckEndpoint(options, options.initialDirectory, error))
        {
            return false;
        }
        Close();
        mOptions = options;
        mUserName = options.userName;
        mPasswordUsed = false;
        mAlive = true;
        mConnectionError.clear();
        mOpen = true;
        SetCurrentSession(this);
        Console::Instance().LogEvent(Texts::Translate(
            "Connected via {protocol} to {host}",
            {{"protocol", mOptions.protocol}, {"host", mOptions.hostName}}));
        return true;
    }
    return Connect(options, "sftp", true, true, error);
}

bool Session::Connect(const SessionOptions & options, const char * program,
    bool subsystem, bool takeCurrent, std::string & error)
{
    if (options.hostName.empty())
    {
        error = "No host name was specified.";
        return false;
    }
    if (options.portNumber <= 0 || options.portNumber > 65535)
    {
        error = "The port number must be between 1 and 65535.";
        return false;
    }
    if (options.timeoutSecs <= 0 || options.timeoutSecs > 3600)
    {
        error = "The connection timeout must be a positive number of seconds.";
        return false;
    }
    if (!ValidateSessionSettings(options, error))
    {
        return false;
    }

    /* OpenShell sets mShellMode before connecting; Close() clears it as
     * part of dropping the previous channel, so carry it over. */
    const bool shellMode = mShellMode;
    Close();
    mShellMode = shellMode;

    mOptions = options;
    mUserName = options.userName;
    mPasswordUsed = false;
    mAlive = true;
    mExitCode = INT_MAX;
    mConnectionError.clear();
    mCapturedStderr.clear();

    ssh_session ssh = ssh_new();
    if (ssh == NULL)
    {
        error = "Cannot allocate an SSH session.";
        mAlive = false;
        return false;
    }
    mSsh = ssh;

    ssh_options_set(ssh, SSH_OPTIONS_HOST, mOptions.hostName.c_str());
    unsigned int port = static_cast<unsigned int>(mOptions.portNumber);
    ssh_options_set(ssh, SSH_OPTIONS_PORT, &port);
    long timeout = mOptions.timeoutSecs;
    ssh_options_set(ssh, SSH_OPTIONS_TIMEOUT, &timeout);
    if (!mOptions.userName.empty())
    {
        ssh_options_set(ssh, SSH_OPTIONS_USER, mOptions.userName.c_str());
    }
    if (mOptions.verbose)
    {
        int verbosity = SSH_LOG_FUNCTIONS;
        ssh_options_set(ssh, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
    }

    /*
     * The proxy of the session, under the same names upstream's session
     * settings use. SOCKS4, SOCKS5, HTTP CONNECT and the telnet dialogue
     * are spoken by ProxySocket() and the connected socket is handed to
     * libssh; a 'Cmd' proxy is a command libssh runs itself. An excluded
     * destination (or localhost, unless asked) connects directly.
     */
    const bool directProxy = !mOptions.proxy.Active() ||
        ProxyExcluded(mOptions.proxy, mOptions.hostName) ||
        (!mOptions.proxy.evenLocalhost &&
            (mOptions.hostName == "localhost" ||
             mOptions.hostName == "127.0.0.1" || mOptions.hostName == "::1"));
    if (mOptions.tunnel.enabled)
    {
        mTunnel.reset(new SshJumpTunnel());
        mTransportSocket = mTunnel->Start(mOptions, error);
        if (mTransportSocket < 0)
        {
            Close();
            return false;
        }
        socket_t sock = static_cast<socket_t>(mTransportSocket);
        if (ssh_options_set(ssh, SSH_OPTIONS_FD, &sock) != SSH_OK)
        {
            error = Texts::Translate("Cannot attach the SSH tunnel transport.");
            Close();
            return false;
        }
    }
    else if (!directProxy)
    {
        const ProxySettings & proxy = mOptions.proxy;
        Console::Instance().LogEvent(std::string("Connecting through the ") +
            ProxyMethodName(proxy.method) + " proxy " +
            (proxy.method == ProxyMethod::Local ?
                proxy.command : proxy.host + ":" + std::to_string(proxy.EffectivePort())));
        if (proxy.method == ProxyMethod::Local)
        {
            /* libssh substitutes %h and %p in a proxy command itself;
             * translate the %host/%port spelling this client accepts. */
            std::string command = proxy.command;
            std::string::size_type pos;
            while ((pos = command.find("%host")) != std::string::npos)
            {
                command.replace(pos, 5, "%h");
            }
            while ((pos = command.find("%port")) != std::string::npos)
            {
                command.replace(pos, 5, "%p");
            }
            ssh_options_set(ssh, SSH_OPTIONS_PROXYCOMMAND, command.c_str());
        }
        else
        {
            const int fd = ProxySocket(mOptions, error);
            if (fd < 0)
            {
                Close();
                return false;
            }
            mTransportSocket = fd;
            socket_t sock = static_cast<socket_t>(fd);
            if (ssh_options_set(ssh, SSH_OPTIONS_FD, &sock) != SSH_OK)
            {
                error = Texts::Translate("Cannot attach the proxy transport.");
                Close();
                return false;
            }
        }
    }

    Console::Instance().LogEvent(Texts::Translate(
        "Starting the SSH connection to {host}", {{"host", HostDescription()}}));
    if (ssh_connect(ssh) != SSH_OK)
    {
        const char * reason = ssh_get_error(ssh);
        error = reason != NULL && reason[0] != '\0' ? reason :
            "Cannot connect to " + HostDescription() + ".";
        Close();
        return false;
    }

    if (!VerifyServerKey(*this, ssh, error))
    {
        Close();
        return false;
    }
    if (!AuthenticateServer(*this, ssh, error))
    {
        Close();
        return false;
    }
    if (mUserName.empty())
    {
        /* libssh connects as the local user when none is configured. */
        mUserName = CurrentUserName();
    }

    if (takeCurrent)
    {
        SetCurrentSession(this);
    }

    if (subsystem)
    {
        /* The SFTP protocol itself is spoken by SftpClient.cpp over this
         * subsystem channel (it needs the copy-data and check-file-name
         * extensions, which libssh's own SFTP client cannot send). */
        Console::Instance().LogEvent(Texts::Translate(
            "Waiting for the SSH channel to open"));
        ssh_channel channel = ssh_channel_new(ssh);
        if (channel == NULL || ssh_channel_open_session(channel) != SSH_OK ||
            ssh_channel_request_subsystem(channel, "sftp") != SSH_OK)
        {
            const char * reason = ssh_get_error(ssh);
            error = reason != NULL && reason[0] != '\0' ? reason :
                "The server did not offer an SFTP subsystem.";
            if (channel != NULL)
            {
                ssh_channel_free(channel);
            }
            Close();
            return false;
        }
        mChannel = channel;
    }
    else if (program != NULL)
    {
        ssh_channel channel = ssh_channel_new(ssh);
        if (channel == NULL || ssh_channel_open_session(channel) != SSH_OK)
        {
            const char * reason = ssh_get_error(ssh);
            error = reason != NULL && reason[0] != '\0' ? reason :
                "The server did not open a channel.";
            if (channel != NULL)
            {
                ssh_channel_free(channel);
            }
            Close();
            return false;
        }
        mChannel = channel;
        mChannelCallbacks.reset(new ChannelCallbacks(*this));
        if (ssh_set_channel_callbacks(channel, &mChannelCallbacks->callbacks) != SSH_OK)
        {
            error = Texts::Translate("Cannot register SSH channel callbacks.");
            Close();
            return false;
        }
        int rc;
        if (mShellMode)
        {
            rc = ssh_channel_request_pty_size(channel, "xterm-256color",
                mShellColumns, mShellRows);
            if (rc == SSH_OK)
            {
                rc = ssh_channel_request_shell(channel);
            }
        }
        else
        {
            rc = ssh_channel_request_exec(channel, program);
        }
        if (rc != SSH_OK)
        {
            const char * reason = ssh_get_error(ssh);
            error = reason != NULL && reason[0] != '\0' ? reason :
                "The server refused to run the command.";
            Close();
            return false;
        }
    }

    mOpen = true;
    return true;
}

bool Session::OpenTunnelTransport(const SessionOptions & options, std::string & error)
{
    mTunnelTransport = true;
    return Connect(options, NULL, false, false, error);
}

void Session::Close()
{
    // Only the owner may reset the process-wide SFTP state. An exec or
    // jump transport can close while the main SFTP session is still active.
    if (g_currentSession == this)
    {
        lscp_sftp_cleanup();
        SetCurrentSession(NULL);
    }
    if (mSftp != NULL)
    {
        sftp_free(static_cast<sftp_session>(mSftp));
        mSftp = NULL;
    }
    if (mChannel != NULL)
    {
        ssh_channel channel = static_cast<ssh_channel>(mChannel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        mChannel = NULL;
    }
    if (mSsh != NULL)
    {
        ssh_disconnect(static_cast<ssh_session>(mSsh));
        ssh_free(static_cast<ssh_session>(mSsh));
        mSsh = NULL;
    }
    // libssh can retain a locally freed channel until session teardown;
    // keep callback storage alive through both channel_free and ssh_free.
    mChannelCallbacks.reset();
    if (mTransportSocket >= 0)
    {
        close(mTransportSocket);
        mTransportSocket = -1;
    }
    // Close the destination before joining/releasing its jump transport.
    mTunnel.reset();
    mShellMode = false;
    mReceived.clear();
    mReceivedStart = 0;
    mReceivedEnd = 0;
    mOpen = false;
    mAlive = false;
}

bool Session::OpenShell(const SessionOptions & options, int columns,
    int rows, std::string & error)
{
    mShellMode = true;
    mShellColumns = columns > 0 ? columns : 80;
    mShellRows = rows > 0 ? rows : 24;
    const bool opened = Connect(options, "", false, false, error);
    if (!opened)
    {
        mShellMode = false;
    }
    return opened;
}

bool Session::ShellResize(int columns, int rows)
{
    if (mChannel == NULL || !mShellMode)
    {
        return false;
    }
    mShellColumns = columns;
    mShellRows = rows;
    return ssh_channel_change_pty_size(static_cast<ssh_channel>(mChannel),
        columns, rows) == SSH_OK;
}

namespace {

void ExecOutputSink(void * ctx, const char * data, size_t len)
{
    (void)ctx;
    Console::Instance().Write(std::string(data, len));
}

} // namespace

int Session::ExitCode() const
{
    return mExitCode;
}

bool Session::OpenExec(const SessionOptions & options,
    const std::string & command, std::string & error)
{
    /* A session of its own, exactly like ExecRemote's: it never becomes the
     * session the SFTP transport glue addresses, so an open SFTP session
     * stays connected and buffered while this command runs. */
    return Connect(options, command.c_str(), false, false, error);
}

bool Session::ExecRemote(const SessionOptions & options,
    const std::string & command, std::string & error)
{
    if (!UseNativeSftp(options.protocol) && !UseNativeScp(options.protocol))
    {
        error = "Remote command execution needs an SSH (sftp:// or scp://) session.";
        return false;
    }
    /* A one-shot session of its own: it never becomes the session the
     * SFTP transport glue addresses, so the open session of the script
     * stays connected and buffered while the command runs. */
    Session exec;
    exec.SetOutputSink(ExecOutputSink, NULL);
    if (!exec.Connect(options, command.c_str(), false, false, error))
    {
        return false;
    }
    while (exec.IsAlive())
    {
        if (!exec.Pump())
        {
            break;
        }
    }
    const int exitCode = exec.ExitCode();
    exec.Close();
    if (!exec.ConnectionError().empty())
    {
        error = exec.ConnectionError();
        return false;
    }
    if (exitCode == INT_MAX)
    {
        error = Texts::Translate("The remote command ended without an exit status.");
        return false;
    }
    if (exitCode > 0)
    {
        error = "Command '" + command + "' failed with return code " +
            std::to_string(exitCode) + ".";
        return false;
    }
    return true;
}

Session * CurrentSession()
{
    return g_currentSession;
}

void SetCurrentSession(Session * session)
{
    g_currentSession = session;
}

} // namespace linscp
