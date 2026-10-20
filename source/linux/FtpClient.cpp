/*
 * FtpClient: the native FTP engine (see FtpClient.h).
 *
 * One control connection per call, that connection speaking FTP itself:
 * greeting, USER/PASS/ACCT, FEAT, TYPE, EPSV/PASV or PORT/EPRT, MLSD,
 * MLST, LIST, SIZE, MDTM, MKD, RMD, DELE, RNFR/RNTO and SITE CHMOD. Every
 * decision that a server can disagree about is taken from what the server
 * says (FEAT, then the reply to the command itself), and a command that
 * is refused is reported with the server's own code and text instead of
 * being retried into something else.
 */

#include "FtpClient.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cctype>
#include <fcntl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sstream>
#include <time.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include "PathUtil.h"
#include "Platform.h"
#include "SftpClient.h"

namespace linscp {

namespace {

std::string LowerAscii(const std::string & text)
{
    std::string result = text;
    for (size_t i = 0; i < result.size(); i++)
    {
        result[i] = static_cast<char>(tolower(static_cast<unsigned char>(result[i])));
    }
    return result;
}

std::string TrimAscii(const std::string & text)
{
    size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos)
    {
        return std::string();
    }
    size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

std::string Shortened(const std::string & text, size_t limit = 300)
{
    if (text.size() <= limit)
    {
        return text;
    }
    return text.substr(0, limit) + "...";
}

/* One FTP reply: its code and the human-readable lines the server sent. */
struct Reply
{
    int code;
    std::vector<std::string> lines;

    Reply() : code(0) {}

    /* The reply as one line, for error messages. */
    std::string Text() const
    {
        std::string text;
        for (size_t i = 0; i < lines.size(); i++)
        {
            if (!text.empty())
            {
                text += " ";
            }
            text += TrimAscii(lines[i]);
        }
        return Shortened(text);
    }
};

/* The preliminary reply a data transfer starts with. */
bool IsPreliminary(int code)
{
    return code == 125 || code == 150;
}

bool isdigit_ascii(char c)
{
    return c >= '0' && c <= '9';
}

} // namespace

/*
 * One decimal number out of a PASV/EPSV server reply, with its range
 * checked. Exported for the unit suite (see FtpClient.h).
 *
 * atoi() was used here before: it stops at the first character that is
 * not a digit and has undefined behaviour on overflow, so a PASV reply
 * of '(999,999,999,999,999,999)' built an address nobody asked for and
 * a port past 65535, and an EPSV reply with twenty digits was undefined
 * behaviour rather than a refused reply. A data connection to the wrong
 * port is not something to be approximate about: the whole field has to
 * be digits and in range, or the reply is refused with the server's own
 * text attached.
 */
bool ParseFtpReplyNumber(const std::string & text, int low, int high, int & value)
{
    value = 0;
    if (text.empty() || text.size() > 5)
    {
        return false;
    }
    for (size_t i = 0; i < text.size(); i++)
    {
        if (!isdigit_ascii(text[i]))
        {
            return false;
        }
    }
    long parsed = 0;
    for (size_t i = 0; i < text.size(); i++)
    {
        parsed = parsed * 10 + (text[i] - '0');
    }
    if (parsed < low || parsed > high)
    {
        return false;
    }
    value = static_cast<int>(parsed);
    return true;
}

namespace {

/*
 * Waits until 'fd' is readable (or writable for POLLOUT) for at most
 * 'timeoutMs' milliseconds. Returns 1 when ready, 0 on timeout and -1 on
 * an error, with 'error' set for the caller's message.
 */
int WaitFd(int fd, short events, int timeoutMs, std::string & error)
{
    for (;;)
    {
        struct pollfd item;
        item.fd = fd;
        item.events = events;
        item.revents = 0;
        const int rc = poll(&item, 1, timeoutMs);
        if (rc > 0)
        {
            return 1;
        }
        if (rc == 0)
        {
            return 0;
        }
        if (errno == EINTR)
        {
            if (Interrupted())
            {
                error = "Interrupted.";
                return -1;
            }
            continue;
        }
        error = std::string("Waiting for the FTP server failed: ") + strerror(errno);
        return -1;
    }
}

int ConnectSocket(const std::string & hostName, int portNumber, int timeoutSecs,
    std::string & error, const SessionOptions * tunnel = NULL)
{
    if (tunnel != NULL && tunnel->tunnelSocksPort > 0)
    {
        return ConnectThroughSocks5("127.0.0.1", tunnel->tunnelSocksPort,
            hostName, portNumber, timeoutSecs, error);
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portText[16];
    snprintf(portText, sizeof(portText), "%d", portNumber);

    struct addrinfo * addresses = NULL;
    const int rc = getaddrinfo(hostName.c_str(), portText, &hints, &addresses);
    if (rc != 0 || addresses == NULL)
    {
        error = "Could not resolve the host '" + hostName + "': " +
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
            lastError = strerror(errno);
            continue;
        }
        /* Connect without a timeout is what a wedged server wins at, so
         * the socket is put in non-blocking mode, poll() gives the wait
         * its bound, and the mode is restored once connected. */
        const int fdFlags = fcntl(fd, F_GETFL, 0);
        if (fdFlags >= 0)
        {
            fcntl(fd, F_SETFL, fdFlags | O_NONBLOCK);
        }
        const int result = connect(fd, address->ai_addr, address->ai_addrlen);
        if (result == 0)
        {
            connected = fd;
            break;
        }
        if (errno == EINPROGRESS)
        {
            std::string waitError;
            const int ready = WaitFd(fd, POLLOUT, timeoutSecs * 1000, waitError);
            if (ready == 1)
            {
                int soError = 0;
                socklen_t length = sizeof(soError);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &length) == 0 &&
                    soError == 0)
                {
                    connected = fd;
                    break;
                }
                lastError = strerror(soError == 0 ? ECONNREFUSED : soError);
            }
            else
            {
                lastError = waitError.empty() ? "timed out" : waitError;
            }
        }
        else
        {
            lastError = strerror(errno);
        }
        close(fd);
    }
    freeaddrinfo(addresses);

    if (connected < 0)
    {
        error = "Could not connect to " + hostName + ":" +
            std::to_string(portNumber) + ": " +
            (lastError.empty() ? "no usable address" : Shortened(lastError)) + ".";
        return -1;
    }
    const int connectedFlags = fcntl(connected, F_GETFL, 0);
    if (connectedFlags >= 0)
    {
        fcntl(connected, F_SETFL, connectedFlags & ~O_NONBLOCK);
    }
    return connected;
}

/*
 * The control connection of one FTP command. Nothing is shared between
 * commands: the console's 'open' does not keep an FTP connection, so each
 * call connects, logs in and closes again - the same cost the curl
 * backend pays per invocation.
 */
class FtpSession
{
public:
    FtpSession(const SessionOptions & options, int timeoutSecs)
        : mOptions(options), mTimeoutSecs(timeoutSecs > 0 ? timeoutSecs : 30),
          mControl(-1), mData(-1), mListener(-1), mControlClosed(false),
          mDataConnected(false), mActiveData(false),
          mFeatKnown(false), mEpsvAdvertised(false), mMlsdAdvertised(false),
          mMlstAdvertised(false), mSizeAdvertised(false), mMdtmAdvertised(false),
          mSiteChmodAdvertised(false)
    {
    }

    ~FtpSession()
    {
        CloseData();
        if (mControl >= 0)
        {
            if (!mControlClosed)
            {
                Reply reply;
                std::string error;
                if (Send("QUIT", error))
                {
                    ReadReply(reply, error);
                }
            }
            close(mControl);
            mControl = -1;
        }
    }

    bool Connect(std::string & error);
    bool Login(std::string & error);
    bool Command(const std::string & line, Reply & reply, std::string & error);
    bool Send(const std::string & line, std::string & error);
    bool ReadReply(Reply & reply, std::string & error);

    bool HasFeature(const std::string & name) const;
    bool FeatKnown() const { return mFeatKnown; }
    bool MlsdAdvertised() const { return mMlsdAdvertised; }
    bool MlstAdvertised() const { return mMlstAdvertised; }
    bool EpsvAdvertised() const { return mEpsvAdvertised; }
    bool SizeAdvertised() const { return mSizeAdvertised; }
    bool MdtmAdvertised() const { return mMdtmAdvertised; }
    bool SiteChmodAdvertised() const { return mSiteChmodAdvertised; }

    /* Sends one listing command on the data connection and collects its
     * output: prepare, send, expect a preliminary reply, read the data,
     * then read the reply that closes the transfer. */
    bool RunListing(const std::string & command, std::string & out,
        Reply & final, std::string & error);

    /* Opens the data connection (passive) or the listener and its PORT
     * (active), as 'FtpPasvMode' says. */
    bool PrepareData(std::string & error);
    /* Reads the data connection to its end. */
    bool ReceiveData(std::string & out, std::string & error);
    void CloseData();
    /* The data connection's peer address, for the unit tests. */
    std::string DataPeerAddress() const { return mDataPeerAddress; }
    bool DataWasActive() const { return mActiveData; }

private:
    FtpSession(const FtpSession &);
    FtpSession & operator=(const FtpSession &);

    bool ReadMore(std::string & error);
    bool OpenPassive(std::string & error);
    bool OpenActive(std::string & error);
    bool ParseFeatures(const Reply & reply, std::string & error);
    bool ConnectDataSocket(const std::string & hostName, int portNumber,
        std::string & error);

    SessionOptions mOptions;
    int mTimeoutSecs;
    int mControl;
    int mData;
    int mListener;
    std::string mInbox;
    bool mControlClosed;
    bool mDataConnected;
    bool mActiveData;
    std::string mDataPeerAddress;
    /* What FEAT said; every flag stays false when the server has no FEAT,
     * and then the command is tried and its own reply decides. */
    bool mFeatKnown;
    bool mEpsvAdvertised;
    bool mMlsdAdvertised;
    bool mMlstAdvertised;
    bool mSizeAdvertised;
    bool mMdtmAdvertised;
    bool mSiteChmodAdvertised;
};

bool FtpSession::Connect(std::string & error)
{
    mControl = ConnectSocket(mOptions.hostName, mOptions.portNumber,
        mTimeoutSecs, error, &mOptions);
    if (mControl < 0)
    {
        return false;
    }
    Reply greeting;
    if (!ReadReply(greeting, error))
    {
        return false;
    }
    if (greeting.code != 220)
    {
        error = "The server did not greet us: " + greeting.Text();
        return false;
    }
    return true;
}

bool FtpSession::Login(std::string & error)
{
    Reply reply;
    if (!Command("USER " + mOptions.userName, reply, error))
    {
        return false;
    }
    if (reply.code == 331 || reply.code == 332)
    {
        if (!Command("PASS " + mOptions.password, reply, error))
        {
            return false;
        }
    }
    else if (reply.code != 230)
    {
        error = "Login failed: " + reply.Text();
        return false;
    }
    if (reply.code == 332)
    {
        /* The server wants an account name on top of the credentials. */
        const std::string account = mOptions.ftp.account;
        if (account.empty())
        {
            error = "The server asked for an account name; set "
                "FtpAccount=NAME with -rawsettings.";
            return false;
        }
        if (!Command("ACCT " + account, reply, error))
        {
            return false;
        }
    }
    if (reply.code != 230 && reply.code != 202)
    {
        error = "Login failed: " + reply.Text();
        return false;
    }

    Reply feat;
    std::string featError;
    if (!Command("FEAT", feat, featError))
    {
        error = featError;
        return false;
    }
    if (feat.code == 211)
    {
        /* A server without FEAT (500/502) is not an error: the commands
         * themselves will answer, and 'FeatKnown' stays false so they are
         * all tried. */
        ParseFeatures(feat, error);
        mFeatKnown = true;
    }

    if (HasFeature("UTF8"))
    {
        Reply opts;
        std::string optsError;
        Command("OPTS UTF8 ON", opts, optsError);
    }
    return true;
}

bool FtpSession::ParseFeatures(const Reply & reply, std::string & error)
{
    (void)error;
    for (size_t i = 0; i < reply.lines.size(); i++)
    {
        const std::string line = TrimAscii(reply.lines[i]);
        if (line.empty() || line.compare(0, 3, "211") == 0)
        {
            continue;
        }
        const std::string upper = LowerAscii(line);
        if (upper.find("epsv") != std::string::npos)
        {
            mEpsvAdvertised = true;
        }
        if (upper.find("mlsd") != std::string::npos)
        {
            mMlsdAdvertised = true;
        }
        if (upper.find("mlst") != std::string::npos)
        {
            mMlstAdvertised = true;
        }
        if (upper.find("size") != std::string::npos)
        {
            mSizeAdvertised = true;
        }
        if (upper.find("mdtm") != std::string::npos)
        {
            mMdtmAdvertised = true;
        }
        if (upper.find("site chmod") != std::string::npos ||
            upper.find("chmod") != std::string::npos)
        {
            mSiteChmodAdvertised = true;
        }
    }
    return true;
}

bool FtpSession::HasFeature(const std::string & name) const
{
    const std::string upper = LowerAscii(name);
    if (upper == "epsv") return mEpsvAdvertised;
    if (upper == "mlsd") return mMlsdAdvertised;
    if (upper == "mlst") return mMlstAdvertised;
    if (upper == "size") return mSizeAdvertised;
    if (upper == "mdtm") return mMdtmAdvertised;
    if (upper == "site chmod") return mSiteChmodAdvertised;
    return false;
}

bool FtpSession::Send(const std::string & line, std::string & error)
{
    if (mControl < 0)
    {
        error = "The FTP control connection is not open.";
        return false;
    }
    const std::string text = line + "\r\n";
    size_t sent = 0;
    while (sent < text.size())
    {
        const ssize_t written = send(mControl, text.data() + sent,
            text.size() - sent, MSG_NOSIGNAL);
        if (written < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                const int ready = WaitFd(mControl, POLLOUT, mTimeoutSecs * 1000,
                    error);
                if (ready != 1)
                {
                    if (error.empty())
                    {
                        error = "The FTP server stopped reading in time.";
                    }
                    return false;
                }
                continue;
            }
            error = std::string("Sending to the FTP server failed: ") +
                strerror(errno);
            return false;
        }
        sent += static_cast<size_t>(written);
    }
    return true;
}

bool FtpSession::ReadMore(std::string & error)
{
    char buffer[4096];
    const int ready = WaitFd(mControl, POLLIN, mTimeoutSecs * 1000, error);
    if (ready != 1)
    {
        if (error.empty())
        {
            error = "The FTP server did not answer in time.";
        }
        return false;
    }
    const ssize_t received = recv(mControl, buffer, sizeof(buffer), 0);
    if (received == 0)
    {
        mControlClosed = true;
        error = "The FTP server closed the connection.";
        return false;
    }
    if (received < 0)
    {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return ReadMore(error);
        }
        error = std::string("Reading from the FTP server failed: ") +
            strerror(errno);
        return false;
    }
    mInbox.append(buffer, static_cast<size_t>(received));
    return true;
}

/*
 * Takes one complete reply out of the inbox. A reply is either a single
 * line ('NNN text') or a group of lines ended by 'NNN text' with the same
 * code, which is how FTP sends the text of FEAT and MLST.
 */
bool FtpSession::ReadReply(Reply & reply, std::string & error)
{
    reply.lines.clear();
    reply.code = 0;
    for (;;)
    {
        const size_t newline = mInbox.find('\n');
        if (newline == std::string::npos)
        {
            if (mControlClosed)
            {
                error = "The FTP server closed the connection.";
                return false;
            }
            if (!ReadMore(error))
            {
                return false;
            }
            continue;
        }
        std::string line = mInbox.substr(0, newline);
        mInbox.erase(0, newline + 1);
        if (!line.empty() && line[line.size() - 1] == '\r')
        {
            line.erase(line.size() - 1);
        }
        if (reply.code == 0)
        {
            if (line.size() < 4 || !isdigit_ascii(line[0]) ||
                !isdigit_ascii(line[1]) || !isdigit_ascii(line[2]))
            {
                /* Not a reply line; servers sometimes send a banner
                 * before the greeting. Skip it. */
                error = "Unexpected FTP reply: " + Shortened(line);
                return false;
            }
            reply.code = atoi(line.substr(0, 3).c_str());
            reply.lines.push_back(line);
            if (line[3] != '-')
            {
                return true;
            }
            continue;
        }
        reply.lines.push_back(line);
        if (line.size() >= 4 && isdigit_ascii(line[0]) &&
            isdigit_ascii(line[1]) && isdigit_ascii(line[2]) &&
            atoi(line.substr(0, 3).c_str()) == reply.code && line[3] == ' ')
        {
            return true;
        }
    }
}

bool FtpSession::Command(const std::string & line, Reply & reply,
    std::string & error)
{
    if (!Send(line, error))
    {
        return false;
    }
    if (!ReadReply(reply, error))
    {
        return false;
    }
    return true;
}

bool FtpSession::ConnectDataSocket(const std::string & hostName, int portNumber,
    std::string & error)
{
    mData = ConnectSocket(hostName, portNumber, mTimeoutSecs, error, &mOptions);
    if (mData < 0)
    {
        return false;
    }
    mDataConnected = true;
    return true;
}

/* EPSV first for a passive connection: it exists for IPv6 and needs no
 * address in the reply. PASV is the fallback, with 'FtpForcePasvIp'
 * deciding whose address is used. */
bool FtpSession::OpenPassive(std::string & error)
{
    Reply reply;
    if (!Command("EPSV", reply, error))
    {
        return false;
    }
    if (reply.code == 229)
    {
        const std::string text = reply.Text();
        int port = 0;
        if (!FtpClient::ParseEpsvReply(text, port))
        {
            error = "The server's EPSV reply has no valid port: " + text;
            return false;
        }
        return ConnectDataSocket(mOptions.hostName, port, error);
    }
    if (reply.code != 500 && reply.code != 501 && reply.code != 502 &&
        reply.code != 522)
    {
        error = "Passive mode failed: " + reply.Text();
        return false;
    }

    if (!Command("PASV", reply, error))
    {
        return false;
    }
    if (reply.code != 227)
    {
        error = "Passive mode failed: " + reply.Text();
        return false;
    }
    const std::string text = reply.Text();
    std::string address;
    int port = 0;
    if (!FtpClient::ParsePasvReply(text, address, port))
    {
        error = "The server's PASV reply has no valid address or port: " + text;
        return false;
    }

    if (mOptions.tunnelSocksPort > 0)
    {
        /* The control socket's peer is the loopback SOCKS listener, which
         * is not a data-channel address. Route the PASV port to the original
         * destination through the jump, as EPSV already does. */
        return ConnectDataSocket(mOptions.hostName, port, error);
    }

    /*
     * FtpForcePasvIp: what to do when the address in the reply is not the
     * address the control connection is on, which is what a server behind
     * NAT sends. Auto (upstream's default) keeps the reply's address when
     * it could plausibly be reached and ignores an unroutable one; 'off'
     * always keeps the control connection's address; 'on' uses the reply
     * verbatim.
     */
    std::string peerAddress;
    struct sockaddr_storage peer;
    socklen_t peerLength = sizeof(peer);
    if (getpeername(mControl, reinterpret_cast<struct sockaddr *>(&peer),
        &peerLength) == 0 && peer.ss_family == AF_INET)
    {
        char peerText[INET_ADDRSTRLEN];
        struct sockaddr_in * peerIpv4 = reinterpret_cast<struct sockaddr_in *>(&peer);
        if (inet_ntop(AF_INET, &peerIpv4->sin_addr, peerText, sizeof(peerText)) != NULL)
        {
            peerAddress = peerText;
        }
    }

    std::string useAddress = address;
    const bool sameAddress = !peerAddress.empty() && peerAddress == address;
    if (!sameAddress && !peerAddress.empty())
    {
        /* RFC 1918, loopback and link-local addresses are the ones a NAT
         * server reports about itself instead of about the destination. */
        const bool unroutable =
            strncmp(address.c_str(), "10.", 3) == 0 ||
            strncmp(address.c_str(), "192.168.", 8) == 0 ||
            strncmp(address.c_str(), "172.16.", 7) == 0 ||
            strncmp(address.c_str(), "172.17.", 7) == 0 ||
            strncmp(address.c_str(), "172.18.", 7) == 0 ||
            strncmp(address.c_str(), "172.19.", 7) == 0 ||
            strncmp(address.c_str(), "172.20.", 7) == 0 ||
            strncmp(address.c_str(), "172.21.", 7) == 0 ||
            strncmp(address.c_str(), "172.22.", 7) == 0 ||
            strncmp(address.c_str(), "172.23.", 7) == 0 ||
            strncmp(address.c_str(), "172.24.", 7) == 0 ||
            strncmp(address.c_str(), "172.25.", 7) == 0 ||
            strncmp(address.c_str(), "172.26.", 7) == 0 ||
            strncmp(address.c_str(), "172.27.", 7) == 0 ||
            strncmp(address.c_str(), "172.28.", 7) == 0 ||
            strncmp(address.c_str(), "172.29.", 7) == 0 ||
            strncmp(address.c_str(), "172.30.", 7) == 0 ||
            strncmp(address.c_str(), "172.31.", 7) == 0 ||
            strncmp(address.c_str(), "127.", 4) == 0 ||
            strncmp(address.c_str(), "169.254.", 8) == 0;
        if (mOptions.ftp.forcePasvIp == 0 ||
            (mOptions.ftp.forcePasvIp == 1 && unroutable))
        {
            useAddress = peerAddress;
        }
    }
    return ConnectDataSocket(useAddress, port, error);
}

/* Active mode: bind a listener, tell the server where it is, and let the
 * server open the data connection when the transfer command runs. */
bool FtpSession::OpenActive(std::string & error)
{
    mActiveData = true;

    /* The listener sits on the address the control connection uses, so a
     * multi-homed machine advertises the interface the server already
     * accepts data on. */
    struct sockaddr_storage local;
    socklen_t localLength = sizeof(local);
    if (getsockname(mControl, reinterpret_cast<struct sockaddr *>(&local),
        &localLength) != 0)
    {
        error = std::string("Could not read the local address: ") + strerror(errno);
        return false;
    }
    mListener = socket(local.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (mListener < 0)
    {
        error = std::string("Could not open a listener for active mode: ") +
            strerror(errno);
        return false;
    }
    int reuse = 1;
    setsockopt(mListener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (local.ss_family == AF_INET)
    {
        reinterpret_cast<struct sockaddr_in *>(&local)->sin_port = 0;
    }
    else
    {
        reinterpret_cast<struct sockaddr_in6 *>(&local)->sin6_port = 0;
    }
    if (bind(mListener, reinterpret_cast<struct sockaddr *>(&local),
        localLength) != 0 || listen(mListener, 1) != 0)
    {
        error = std::string("Could not listen for the data connection: ") +
            strerror(errno);
        close(mListener);
        mListener = -1;
        return false;
    }
    struct sockaddr_storage bound;
    socklen_t boundLength = sizeof(bound);
    if (getsockname(mListener, reinterpret_cast<struct sockaddr *>(&bound),
        &boundLength) != 0)
    {
        error = "Could not read the listener's address.";
        return false;
    }

    Reply reply;
    if (bound.ss_family == AF_INET)
    {
        struct sockaddr_in * ipv4 = reinterpret_cast<struct sockaddr_in *>(&bound);
        char addressText[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &ipv4->sin_addr, addressText,
            sizeof(addressText)) == NULL)
        {
            error = "Could not format the listener's address.";
            return false;
        }
        std::string dotted = addressText;
        for (size_t i = 0; i < dotted.size(); i++)
        {
            if (dotted[i] == '.')
            {
                dotted[i] = ',';
            }
        }
        const int port = ntohs(ipv4->sin_port);
        const std::string command = "PORT " + dotted + "," +
            std::to_string(port / 256) + "," + std::to_string(port % 256);
        if (!Command(command, reply, error))
        {
            return false;
        }
        if (reply.code != 200)
        {
            error = "Active mode was refused: " + reply.Text();
            return false;
        }
        return true;
    }

    struct sockaddr_in6 * ipv6 = reinterpret_cast<struct sockaddr_in6 *>(&bound);
    char addressText[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &ipv6->sin6_addr, addressText,
        sizeof(addressText)) == NULL)
    {
        error = "Could not format the listener's address.";
        return false;
    }
    const std::string command = "EPRT |||" + std::to_string(ntohs(ipv6->sin6_port)) + "|";
    if (!Command(command, reply, error))
    {
        return false;
    }
    if (reply.code != 200)
    {
        error = "Active mode was refused: " + reply.Text();
        return false;
    }
    return true;
}

bool FtpSession::PrepareData(std::string & error)
{
    if (mData >= 0)
    {
        close(mData);
        mData = -1;
        mDataConnected = false;
    }
    /* Active FTP through an SSH tunnel would advertise 127.0.0.1 to the
     * server, which cannot open a data connection back through the jump.
     * Passive data sockets go through the same SOCKS listener as control. */
    mActiveData = !mOptions.ftp.passiveMode && mOptions.tunnelSocksPort <= 0;
    if (mActiveData)
    {
        return OpenActive(error);
    }
    return OpenPassive(error);
}

bool FtpSession::ReceiveData(std::string & out, std::string & error)
{
    if (mActiveData && !mDataConnected)
    {
        const int ready = WaitFd(mListener, POLLIN, mTimeoutSecs * 1000, error);
        if (ready != 1)
        {
            if (error.empty())
            {
                error = "The server did not open the data connection in time.";
            }
            return false;
        }
        struct sockaddr_storage peer;
        socklen_t peerLength = sizeof(peer);
        mData = accept(mListener, reinterpret_cast<struct sockaddr *>(&peer),
            &peerLength);
        if (mData < 0)
        {
            error = std::string("Accepting the data connection failed: ") +
                strerror(errno);
            return false;
        }
        close(mListener);
        mListener = -1;
        if (peer.ss_family == AF_INET)
        {
            char text[INET_ADDRSTRLEN];
            struct sockaddr_in * ipv4 = reinterpret_cast<struct sockaddr_in *>(&peer);
            if (inet_ntop(AF_INET, &ipv4->sin_addr, text, sizeof(text)) != NULL)
            {
                mDataPeerAddress = text;
            }
        }
        mDataConnected = true;
    }
    if (mData < 0)
    {
        error = "There is no data connection.";
        return false;
    }

    char buffer[8192];
    for (;;)
    {
        const int ready = WaitFd(mData, POLLIN, mTimeoutSecs * 1000, error);
        if (ready != 1)
        {
            if (error.empty())
            {
                error = "The data connection stalled.";
            }
            return false;
        }
        const ssize_t received = recv(mData, buffer, sizeof(buffer), 0);
        if (received == 0)
        {
            return true;
        }
        if (received < 0)
        {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            {
                continue;
            }
            error = std::string("Reading the data connection failed: ") +
                strerror(errno);
            return false;
        }
        out.append(buffer, static_cast<size_t>(received));
    }
}

void FtpSession::CloseData()
{
    if (mData >= 0)
    {
        close(mData);
        mData = -1;
    }
    if (mListener >= 0)
    {
        close(mListener);
        mListener = -1;
    }
    mDataConnected = false;
}

/*
 * Runs one directory-listing command on the data connection: prepare,
 * send, expect a preliminary reply, read the data, then read the reply
 * that closes the transfer.
 */
bool FtpSession::RunListing(const std::string & command, std::string & out,
    Reply & final, std::string & error)
{
    if (!PrepareData(error))
    {
        return false;
    }
    Reply preliminary;
    if (!Command(command, preliminary, error))
    {
        CloseData();
        return false;
    }
    if (!IsPreliminary(preliminary.code))
    {
        CloseData();
        final = preliminary;
        if (preliminary.code >= 500)
        {
            error = preliminary.Text();
            return false;
        }
        error = preliminary.Text();
        return false;
    }
    if (!ReceiveData(out, error))
    {
        CloseData();
        return false;
    }
    CloseData();
    if (!ReadReply(final, error))
    {
        return false;
    }
    if (final.code >= 400)
    {
        error = final.Text();
        return false;
    }
    return true;
}

/* One MLSD/MLST fact list: 'fact=value;fact=value; name'. */
struct FtpFacts
{
    std::string type;
    bool hasType;
    bool hasSize;
    unsigned long long size;
    bool hasModify;
    unsigned long mtime;
    bool hasMode;
    unsigned long permissions;
    std::string name;
    std::string target;

    FtpFacts() : hasType(false), hasSize(false), size(0), hasModify(false),
        mtime(0), hasMode(false), permissions(0) {}
};

unsigned long ParseMlsdTime(const std::string & text)
{
    /* YYYYMMDDHHMMSS (optionally with .sss) in UTC, as RFC 3659 says. */
    if (text.size() < 14)
    {
        return 0;
    }
    for (size_t i = 0; i < 14; i++)
    {
        if (!isdigit_ascii(text[i]))
        {
            return 0;
        }
    }
    struct tm parts;
    memset(&parts, 0, sizeof(parts));
    parts.tm_year = atoi(text.substr(0, 4).c_str()) - 1900;
    parts.tm_mon = atoi(text.substr(4, 2).c_str()) - 1;
    parts.tm_mday = atoi(text.substr(6, 2).c_str());
    parts.tm_hour = atoi(text.substr(8, 2).c_str());
    parts.tm_min = atoi(text.substr(10, 2).c_str());
    parts.tm_sec = atoi(text.substr(12, 2).c_str());
    const time_t stamp = timegm(&parts);
    return stamp > 0 ? static_cast<unsigned long>(stamp) : 0;
}

bool ParseFactsLine(const std::string & line, FtpFacts & facts)
{
    facts = FtpFacts();
    size_t pos = 0;
    while (pos < line.size() && line[pos] != ' ')
    {
        const size_t semi = line.find(';', pos);
        if (semi == std::string::npos)
        {
            break;
        }
        const std::string fact = line.substr(pos, semi - pos);
        pos = semi + 1;
        const size_t equals = fact.find('=');
        if (equals == std::string::npos)
        {
            continue;
        }
        const std::string name = LowerAscii(fact.substr(0, equals));
        const std::string value = fact.substr(equals + 1);
        if (name == "type")
        {
            facts.hasType = true;
            facts.type = LowerAscii(value);
        }
        else if (name == "size")
        {
            char * end = NULL;
            const unsigned long long parsed = strtoull(value.c_str(), &end, 10);
            if (end != NULL && *end == '\0')
            {
                facts.hasSize = true;
                facts.size = parsed;
            }
        }
        else if (name == "modify")
        {
            const unsigned long stamp = ParseMlsdTime(value);
            if (stamp != 0)
            {
                facts.hasModify = true;
                facts.mtime = stamp;
            }
        }
        else if (name == "unix.mode")
        {
            unsigned long mode = strtoul(value.c_str(), NULL, 8);
            if (mode != 0)
            {
                facts.hasMode = true;
                facts.permissions = mode;
            }
        }
    }
    if (pos < line.size())
    {
        facts.name = TrimAscii(line.substr(pos));
    }
    return true;
}

bool FtpEntryFromFacts(const FtpFacts & facts, ListingEntry & entry)
{
    if (!facts.hasType && !facts.hasMode)
    {
        return false;
    }
    entry.name = facts.name;
    entry.typeKnown = true;
    entry.size = facts.hasSize ? facts.size : 0;
    if (facts.hasType)
    {
        if (facts.type == "dir")
        {
            entry.isDir = true;
            entry.permissions = 0040000UL | (facts.hasMode ? facts.permissions : 0755UL);
        }
        else if (facts.type == "cdir" || facts.type == "pdir")
        {
            return false;
        }
        else if (facts.type.compare(0, 12, "os.unix=slink") == 0)
        {
            entry.permissions = 0120000UL | (facts.hasMode ? facts.permissions : 0777UL);
            const size_t colon = facts.type.find(':');
            if (colon != std::string::npos)
            {
                entry.longname = facts.type.substr(colon + 1);
            }
        }
        else
        {
            entry.isDir = false;
            entry.permissions = 0100000UL | (facts.hasMode ? facts.permissions : 0644UL);
        }
    }
    else if ((facts.permissions & 0040000UL) != 0)
    {
        entry.isDir = true;
        entry.permissions = 0040000UL | facts.permissions;
    }
    else
    {
        entry.permissions = 0100000UL | facts.permissions;
    }
    entry.timeKnown = facts.hasModify;
    entry.mtime = facts.mtime;
    return true;
}

/* The LIST fallback: the same parser the curl backend uses. */
bool ParseListLines(const std::string & text, std::vector<ListingEntry> & entries)
{
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
        if (line.empty() || line == "." || line == "..")
        {
            continue;
        }
        ListingEntry entry;
        entry.longname = line;
        if (!ParseAnyListingLine(line, entry))
        {
            entry.name = line;
            if (!entry.name.empty() && entry.name.back() == '/')
            {
                entry.name.pop_back();
                entry.typeKnown = true;
                entry.isDir = true;
                entry.permissions = 0040755UL;
            }
        }
        if (entry.name.empty() || entry.name == "." || entry.name == "..")
        {
            continue;
        }
        entries.push_back(entry);
    }
    return true;
}

bool ParseMlsdListing(const std::string & text,
    std::vector<ListingEntry> & entries)
{
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
        if (line.empty())
        {
            continue;
        }
        FtpFacts facts;
        ParseFactsLine(line, facts);
        ListingEntry entry;
        if (!FtpEntryFromFacts(facts, entry))
        {
            continue;
        }
        if (entry.name.empty() || entry.name == "." || entry.name == "..")
        {
            continue;
        }
        entries.push_back(entry);
    }
    return true;
}

/* The facts of an MLST reply, which arrives as the lines of a multi-line
 * 250 reply. */
bool MlstFacts(const Reply & reply, FtpFacts & facts)
{
    for (size_t i = 0; i < reply.lines.size(); i++)
    {
        std::string line = reply.lines[i];
        if (line.empty())
        {
            continue;
        }
        if (line.compare(0, 4, "250-") == 0)
        {
            line.erase(0, 4);
        }
        const std::string trimmed = TrimAscii(line);
        /* The fact list is the single line of a multi-line 250 reply and
         * is the only line that has '=' and ';' in it. */
        if (trimmed.find('=') != std::string::npos &&
            trimmed.find(';') != std::string::npos)
        {
            return ParseFactsLine(TrimAscii(trimmed), facts);
        }
    }
    return false;
}

} // namespace

namespace {

bool ParseDecimalRange(const std::string & text, size_t maxDigits,
    int maxValue, int & value)
{
    if (text.empty() || text.size() > maxDigits)
    {
        return false;
    }
    value = 0;
    for (size_t i = 0; i < text.size(); i++)
    {
        if (!isdigit_ascii(text[i]))
        {
            return false;
        }
        const int digit = text[i] - '0';
        if (value > (maxValue - digit) / 10)
        {
            return false;
        }
        value = value * 10 + digit;
    }
    return value <= maxValue;
}

} // namespace

bool FtpClient::ParseEpsvReply(const std::string & replyText, int & port)
{
    port = 0;
    const size_t open = replyText.find('(');
    const size_t close = open == std::string::npos ? std::string::npos :
        replyText.find(')', open + 1);
    if (open == std::string::npos || close == std::string::npos || close <= open)
    {
        return false;
    }
    const std::string fields = replyText.substr(open + 1, close - open - 1);
    if (fields.size() < 5)
    {
        return false;
    }
    const char delimiter = fields[0];
    if (delimiter <= ' ' || delimiter > '~' || isdigit_ascii(delimiter) ||
        delimiter == '(' || delimiter == ')')
    {
        return false;
    }
    if (fields[1] != delimiter || fields[2] != delimiter ||
        fields[fields.size() - 1] != delimiter)
    {
        return false;
    }
    const std::string portText = fields.substr(3, fields.size() - 4);
    int parsedPort = 0;
    if (!ParseDecimalRange(portText, 5, 65535, parsedPort) || parsedPort == 0)
    {
        return false;
    }
    port = parsedPort;
    return true;
}

bool FtpClient::ParsePasvReply(const std::string & replyText,
    std::string & address, int & port)
{
    address.clear();
    port = 0;
    const size_t open = replyText.find('(');
    const size_t close = open == std::string::npos ? std::string::npos :
        replyText.find(')', open + 1);
    if (open == std::string::npos || close == std::string::npos || close <= open)
    {
        return false;
    }

    std::vector<int> numbers;
    size_t start = open + 1;
    while (start <= close)
    {
        size_t end = replyText.find(',', start);
        if (end == std::string::npos || end > close)
        {
            end = close;
        }
        int number = 0;
        if (!ParseDecimalRange(TrimAscii(replyText.substr(start, end - start)),
            3, 255, number))
        {
            return false;
        }
        numbers.push_back(number);
        if (end == close)
        {
            break;
        }
        start = end + 1;
    }
    if (numbers.size() != 6)
    {
        return false;
    }

    const int parsedPort = numbers[4] * 256 + numbers[5];
    if (parsedPort == 0)
    {
        return false;
    }
    char addressText[INET_ADDRSTRLEN];
    snprintf(addressText, sizeof(addressText), "%d.%d.%d.%d", numbers[0],
        numbers[1], numbers[2], numbers[3]);
    address = addressText;
    port = parsedPort;
    return true;
}

bool FtpClient::Handles(const SessionOptions & options)
{
    return LowerAscii(options.protocol) == "ftp" && options.tls.ftpsMode == 0;
}

bool FtpClient::List(const SessionOptions & options, const std::string & remotePath,
    std::vector<ListingEntry> & entries, std::string & error, int * codeOut)
{
    entries.clear();
    if (codeOut != NULL)
    {
        *codeOut = 0;
    }
    FtpSession session(options, options.timeoutSecs);
    if (!session.Connect(error) || !session.Login(error))
    {
        if (codeOut != NULL)
        {
            *codeOut = kFtpTransportFailure;
        }
        return false;
    }

    const std::string path = remotePath.empty() ? std::string("/") : remotePath;
    /* 'FtpUseMlsd' decides whether MLSD is used, and what happens when the
     * server does not offer it: auto falls back to LIST, on refuses, off
     * never asks. */
    if (options.ftp.useMlsd != 0)
    {
        std::string data;
        Reply final;
        std::string listingError;
        if (session.RunListing("MLSD " + path, data, final, listingError))
        {
            ParseMlsdListing(data, entries);
            return true;
        }
        if (options.ftp.useMlsd == 2)
        {
            error = "The server refused MLSD (" + listingError +
                ") and FtpUseMlsd=2 requires it.";
            if (codeOut != NULL)
            {
                *codeOut = final.code != 0 ? final.code : kFtpTransportFailure;
            }
            return false;
        }
        if (final.code != 0 && final.code != 500 && final.code != 501 &&
            final.code != 502 && final.code != 550)
        {
            error = listingError;
            if (codeOut != NULL)
            {
                *codeOut = final.code;
            }
            return false;
        }
    }

    std::string data;
    Reply final;
    std::string listingError;
    if (!session.RunListing("LIST " + path, data, final, listingError))
    {
        if (codeOut != NULL)
        {
            *codeOut = final.code != 0 ? final.code : kFtpTransportFailure;
        }
        error = listingError;
        return false;
    }
    ParseListLines(data, entries);
    return true;
}

int FtpClient::Stat(const SessionOptions & options, const std::string & remotePath,
    LscpAttrs * attrs, std::string & error)
{
    if (attrs != NULL)
    {
        memset(attrs, 0, sizeof(*attrs));
    }
    FtpSession session(options, options.timeoutSecs);
    if (!session.Connect(error) || !session.Login(error))
    {
        return LSCP_SFTP_STAT_ERROR;
    }

    std::string path = remotePath.empty() ? std::string("/") : remotePath;
    while (path.size() > 1 && path.back() == '/')
    {
        path.erase(path.size() - 1);
    }

    /* MLST answers for files and directories alike, with the facts the
     * server keeps about them. */
    if (session.MlstAdvertised() || !session.FeatKnown())
    {
        Reply reply;
        std::string mlstError;
        if (session.Command("MLST " + path, reply, mlstError))
        {
            if (reply.code == 250)
            {
                FtpFacts facts;
                if (MlstFacts(reply, facts))
                {
                    ListingEntry entry;
                    if (FtpEntryFromFacts(facts, entry))
                    {
                        if (attrs != NULL)
                        {
                            attrs->flags = LSCP_ATTR_PERMISSIONS | LSCP_ATTR_SIZE;
                            attrs->permissions = entry.permissions;
                            attrs->size = entry.size;
                            if (entry.timeKnown)
                            {
                                attrs->flags |= LSCP_ATTR_ACMODTIME;
                                attrs->atime = entry.mtime;
                                attrs->mtime = entry.mtime;
                            }
                        }
                        return LSCP_SFTP_STAT_EXISTS;
                    }
                }
            }
            else if (reply.code == 550)
            {
                error = "No such file or directory.";
                return LSCP_SFTP_STAT_MISSING;
            }
        }
        else
        {
            error = mlstError;
            return LSCP_SFTP_STAT_ERROR;
        }
    }

    /* SIZE for a file, CWD for a directory. Both are one command and
     * neither needs the parent to be listed. */
    if (session.SizeAdvertised() || !session.FeatKnown())
    {
        Reply sizeReply;
        std::string sizeError;
        if (session.Command("SIZE " + path, sizeReply, sizeError))
        {
            if (sizeReply.code == 213)
            {
                const std::string text = TrimAscii(sizeReply.Text());
                unsigned long long size = 0;
                bool numeric = !text.empty();
                for (size_t i = 0; i < text.size(); i++)
                {
                    if (!isdigit_ascii(text[i]))
                    {
                        numeric = false;
                        break;
                    }
                }
                if (numeric)
                {
                    size = strtoull(text.c_str(), NULL, 10);
                }
                if (attrs != NULL)
                {
                    attrs->flags = LSCP_ATTR_PERMISSIONS | LSCP_ATTR_SIZE;
                    attrs->permissions = 0100644;
                    attrs->size = size;
                }
                if (session.MdtmAdvertised() || !session.FeatKnown())
                {
                    Reply timeReply;
                    std::string timeError;
                    if (session.Command("MDTM " + path, timeReply, timeError) &&
                        timeReply.code == 213)
                    {
                        const unsigned long stamp =
                            ParseMlsdTime(TrimAscii(timeReply.Text()));
                        if (stamp != 0 && attrs != NULL)
                        {
                            attrs->flags |= LSCP_ATTR_ACMODTIME;
                            attrs->atime = stamp;
                            attrs->mtime = stamp;
                        }
                    }
                }
                return LSCP_SFTP_STAT_EXISTS;
            }
        }
    }

    Reply cwdReply;
    std::string cwdError;
    if (session.Command("CWD " + path, cwdReply, cwdError) && cwdReply.code == 250)
    {
        if (attrs != NULL)
        {
            attrs->flags = LSCP_ATTR_PERMISSIONS;
            attrs->permissions = 0040755;
        }
        return LSCP_SFTP_STAT_EXISTS;
    }

    /* Neither worked: look the name up in its parent, which is also what
     * tells a missing path from a refused one. */
    const size_t slash = path.rfind('/');
    if (slash == std::string::npos)
    {
        error = "No such file or directory.";
        return LSCP_SFTP_STAT_MISSING;
    }
    const std::string parent = slash == 0 ? std::string("/") : path.substr(0, slash);
    const std::string wanted = path.substr(slash + 1);
    std::vector<ListingEntry> entries;
    std::string listingError;
    int code = 0;
    if (!FtpClient::List(options, parent, entries, listingError, &code))
    {
        error = listingError;
        return code == kFtpTransportFailure ? LSCP_SFTP_STAT_ERROR :
            LSCP_SFTP_STAT_MISSING;
    }
    for (size_t i = 0; i < entries.size(); i++)
    {
        if (entries[i].name != wanted)
        {
            continue;
        }
        if (attrs != NULL)
        {
            attrs->flags = LSCP_ATTR_PERMISSIONS | LSCP_ATTR_SIZE;
            attrs->permissions = entries[i].permissions;
            attrs->size = entries[i].size;
            if (entries[i].timeKnown)
            {
                attrs->flags |= LSCP_ATTR_ACMODTIME;
                attrs->atime = entries[i].mtime;
                attrs->mtime = entries[i].mtime;
            }
        }
        return LSCP_SFTP_STAT_EXISTS;
    }
    error = "No such file or directory.";
    return LSCP_SFTP_STAT_MISSING;
}

/*
 * The commands that change the server's filesystem, one connection each.
 * A reply that is not the success code is passed on with the server's
 * text, so 'permission denied' and 'no such directory' reach the user as
 * themselves.
 */
namespace {

int RunCommand(const SessionOptions & options, const std::string & command,
    const int * accepted, size_t acceptedCount, std::string & error)
{
    FtpSession session(options, options.timeoutSecs);
    if (!session.Connect(error) || !session.Login(error))
    {
        return -1;
    }
    Reply reply;
    if (!session.Command(command, reply, error))
    {
        return -1;
    }
    for (size_t i = 0; i < acceptedCount; i++)
    {
        if (reply.code == accepted[i])
        {
            return 0;
        }
    }
    error = reply.Text();
    return -1;
}

} // namespace

int FtpClient::Remove(const SessionOptions & options, const std::string & remotePath,
    std::string & error)
{
    const int accepted[] = { 250, 200 };
    return RunCommand(options, "DELE " + remotePath, accepted, 2, error);
}

int FtpClient::RemoveDir(const SessionOptions & options, const std::string & remotePath,
    std::string & error)
{
    const int accepted[] = { 250, 200 };
    return RunCommand(options, "RMD " + remotePath, accepted, 2, error);
}

int FtpClient::MakeDir(const SessionOptions & options, const std::string & remotePath,
    std::string & error)
{
    const int accepted[] = { 257, 250 };
    return RunCommand(options, "MKD " + remotePath, accepted, 2, error);
}

int FtpClient::Move(const SessionOptions & options, const std::string & fromPath,
    const std::string & toPath, std::string & error)
{
    FtpSession session(options, options.timeoutSecs);
    if (!session.Connect(error) || !session.Login(error))
    {
        return -1;
    }
    Reply reply;
    if (!session.Command("RNFR " + fromPath, reply, error))
    {
        return -1;
    }
    if (reply.code != 350)
    {
        error = reply.Text();
        return -1;
    }
    if (!session.Command("RNTO " + toPath, reply, error))
    {
        return -1;
    }
    if (reply.code != 250 && reply.code != 200)
    {
        error = reply.Text();
        return -1;
    }
    return 0;
}

int FtpClient::SetPermissions(const SessionOptions & options,
    const std::string & remotePath, int permissions, std::string & error)
{
    FtpSession session(options, options.timeoutSecs);
    if (!session.Connect(error) || !session.Login(error))
    {
        return -1;
    }
    if (session.FeatKnown() && !session.SiteChmodAdvertised())
    {
        error = "The server does not support SITE CHMOD.";
        return -1;
    }
    char text[16];
    snprintf(text, sizeof(text), "%o", static_cast<unsigned int>(permissions));
    Reply reply;
    std::string commandError;
    if (!session.Command("SITE CHMOD " + std::string(text) + " " + remotePath,
        reply, commandError))
    {
        error = commandError;
        return -1;
    }
    if (reply.code != 200 && reply.code != 250)
    {
        error = reply.Text();
        return -1;
    }
    return 0;
}

} // namespace linscp
