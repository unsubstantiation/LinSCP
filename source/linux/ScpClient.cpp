/*
 * ScpClient: see ScpClient.h. The shell half runs one command per SSH
 * connection and reads the answer; the transfer half speaks the rcp wire
 * protocol on a channel of its own.
 */

#include "ScpClient.h"

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>
#include <vector>

#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "Console.h"
#include "LocalFs.h"
#include "PathUtil.h"
#include "Platform.h"

namespace linscp {

namespace {

/* 32 KiB is what the SFTP transport moves in one go, so the progress
 * callback of a download or an upload reports at the same granularity
 * whatever protocol is carrying the bytes. */
const size_t kChunkSize = 32 * 1024;

/* A header line longer than this is not a header: it is either junk a
 * shell printed or a server that is not speaking the rcp protocol, and
 * reading it into memory without a limit would be trusting it. */
const size_t kMaxHeaderLine = 8 * 1024;

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

/* Trailing whitespace and newlines removed, and leading whitespace with
 * them: a command's error output is a sentence, not a paragraph. */
std::string TrimText(const std::string & text)
{
    size_t first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
    {
        return std::string();
    }
    size_t last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

unsigned long long NowMilliseconds()
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    {
        return 0;
    }
    return static_cast<unsigned long long>(now.tv_sec) * 1000ULL +
        static_cast<unsigned long long>(now.tv_nsec / 1000000);
}

/*
 * '-speed=<KB/s>' on a transport that is not curl: the bytes are counted
 * against the clock and the loop waits when it is ahead of the schedule.
 * Waiting between chunks is coarse - a chunk is 32 KiB - but it is the
 * same granularity the progress reporting uses, and a limit nobody can
 * measure is not a limit worth pretending about.
 */
class RateLimiter
{
public:
    explicit RateLimiter(unsigned kBytesPerSecond)
        : mLimit(kBytesPerSecond), mBytes(0), mStart(0)
    {
    }

    void Consume(size_t bytes)
    {
        if (mLimit == 0)
        {
            return;
        }
        mBytes += static_cast<unsigned long long>(bytes);
        const unsigned long long now = NowMilliseconds();
        if (mStart == 0)
        {
            mStart = now;
            return;
        }
        const unsigned long long allowed =
            (mBytes * 1000ULL) / (static_cast<unsigned long long>(mLimit) * 1024ULL);
        const unsigned long long elapsed = now > mStart ? now - mStart : 0;
        if (allowed > elapsed)
        {
            SleepMilliseconds(static_cast<unsigned>(allowed - elapsed));
        }
    }

private:
    unsigned mLimit;
    unsigned long long mBytes;
    unsigned long long mStart;
};

/* One shell command and everything the server said about it. */
struct ShellReply
{
    bool connected;      /* the connection was made and the command ran */
    int exitCode;        /* the status the server reported; INT_MAX: none */
    std::string output;  /* the command's standard output */
    std::string errors;  /* its standard error, kept instead of printed */

    ShellReply() : connected(false), exitCode(INT_MAX) {}
    bool Succeeded() const { return connected && exitCode == 0; }
};

/*
 * The reason a command failed, in the server's own words when it gave any.
 * 'ls: cannot access '/x': No such file or directory' says more about a
 * missing directory than an exit status does, and the exit status is what
 * is left when a command failed silently.
 */
std::string ShellReason(const ShellReply & reply, const std::string & command)
{
    const std::string text = TrimText(reply.errors);
    if (!text.empty())
    {
        return text[text.size() - 1] == '.' ? text : text + ".";
    }
    if (reply.exitCode != INT_MAX)
    {
        return "The server's command '" + command + "' failed with exit "
            "status " + std::to_string(reply.exitCode) + ".";
    }
    return "The server's command '" + command + "' failed.";
}

/*
 * Runs one command in one SSH connection of its own. Returns false only
 * when the connection itself could not be made or the command never ran -
 * a command that ran and failed is an answer, which the caller reads in
 * 'reply' (that is how 'stat' tells a missing path from a refused one, and
 * how 'open' tells an unusable endpoint from a directory nobody may list).
 */
bool RunShell(const SessionOptions & options, const std::string & command,
    ShellReply & reply, std::string & error)
{
    reply = ShellReply();
    error.clear();

    Session session;
    session.CaptureStderr(true);
    if (!session.OpenExec(options, command, error))
    {
        session.Close();
        if (error.empty())
        {
            error = "The connection to " + options.hostName + " failed.";
        }
        return false;
    }
    reply.connected = true;
    session.PumpUntilExit();
    session.TakeAllReceived(reply.output);
    reply.errors = session.CapturedStderr();
    reply.exitCode = session.ExitCode();
    const std::string connectionError = session.ConnectionError();
    session.Close();

    if (reply.exitCode == INT_MAX)
    {
        /* No exit status: the channel died instead of ending. That is a
         * transport failure, not an answer. */
        reply.connected = false;
        error = connectionError.empty() ?
            "The connection to " + options.hostName + " closed while '" +
                command + "' was running." :
            connectionError;
        return false;
    }
    return true;
}

/*
 * The channel a transfer runs on. The rcp protocol is bidirectional - the
 * receiving side acknowledges every header and the sending side waits for
 * that acknowledgement - so this is not a command whose output is read at
 * the end: bytes are written and read while the channel is open, and the
 * exit status is collected after the engine has said it is done.
 */
class ScpChannel
{
public:
    ScpChannel() : mOpen(false) {}
    ~ScpChannel() { Close(); }

    bool Open(const SessionOptions & options, const std::string & command,
        std::string & error)
    {
        mCommand = command;
        mSession.CaptureStderr(true);
        if (!mSession.OpenExec(options, command, error))
        {
            mSession.Close();
            return false;
        }
        mOpen = true;
        return true;
    }

    bool SendByte(unsigned char byte)
    {
        return mSession.SendData(reinterpret_cast<const char *>(&byte), 1);
    }

    bool SendBytes(const void * data, size_t len)
    {
        return mSession.SendData(static_cast<const char *>(data), len);
    }

    bool ReadByte(unsigned char & byte)
    {
        return mSession.ReceiveData(reinterpret_cast<char *>(&byte), 1);
    }

    bool ReadBytes(void * buffer, size_t len)
    {
        return mSession.ReceiveData(static_cast<char *>(buffer), len);
    }

    /*
     * Reads one protocol line, including its newline. A line that never
     * ends is a server that is not speaking this protocol; the limit turns
     * that into an error instead of an exhausted client.
     */
    bool ReadLine(std::string & line)
    {
        line.clear();
        for (;;)
        {
            unsigned char byte = 0;
            if (!ReadByte(byte))
            {
                return false;
            }
            line += static_cast<char>(byte);
            if (byte == '\n')
            {
                return true;
            }
            if (line.size() > kMaxHeaderLine)
            {
                return false;
            }
        }
    }

    /*
     * One acknowledgement of the protocol: 0 means the other side is ready
     * for what comes next, 1 and 2 carry a message that explains why it is
     * not. Anything else is not an acknowledgement at all.
     */
    bool ReadAcknowledgement(std::string & message)
    {
        message.clear();
        unsigned char byte = 0;
        if (!ReadByte(byte))
        {
            message = ChannelClosedText();
            return false;
        }
        if (byte == 0)
        {
            return true;
        }
        if (byte == 1 || byte == 2)
        {
            std::string line;
            if (!ReadLine(line))
            {
                message = byte == 2 ?
                    "The server's scp failed fatally and closed the channel." :
                    ChannelClosedText();
                return false;
            }
            message = TrimText(line);
            if (message.empty())
            {
                message = byte == 2 ?
                    "The server's scp reported a fatal error without saying why." :
                    "The server's scp reported an error without saying why.";
            }
            else if (message[message.size() - 1] != '.')
            {
                message += ".";
            }
            return false;
        }
        char described[32];
        snprintf(described, sizeof(described), "0x%02X", byte);
        message = std::string("The server's scp answered with ") + described +
            " where the protocol expects an acknowledgement.";
        return false;
    }

    /* Says that no more input is coming, so 'scp -t' can finish. */
    void SendEof()
    {
        mSession.SendEof();
    }

    /* Waits for the command to end and returns the status the server
     * reported, or INT_MAX when it reported none. */
    int Finish(std::string & errors)
    {
        mSession.PumpUntilExit();
        std::string pending;
        mSession.TakeAllReceived(pending);
        errors = TrimText(mSession.CapturedStderr());
        const int exitCode = mSession.ExitCode();
        const std::string connectionError = mSession.ConnectionError();
        mSession.Close();
        mOpen = false;
        if (exitCode == INT_MAX && errors.empty())
        {
            errors = connectionError;
        }
        return exitCode;
    }

    void Close()
    {
        mSession.Close();
        mOpen = false;
    }

    bool IsOpen() const { return mOpen; }

    /* What the command printed on its error output so far, which is where
     * the reason for a failure that ended the channel usually is. */
    std::string Errors() const { return TrimText(mSession.CapturedStderr()); }

private:
    ScpChannel(const ScpChannel &);
    ScpChannel & operator=(const ScpChannel &);

    std::string ChannelClosedText() const
    {
        const std::string connectionError = mSession.ConnectionError();
        if (!connectionError.empty())
        {
            return connectionError;
        }
        return "The connection closed while the server's scp was running '" +
            mCommand + "'.";
    }

    Session mSession;
    std::string mCommand;
    bool mOpen;
};

/*
 * The path as it goes into a command line: absolute or relative as the
 * caller resolved it, without a trailing separator (the root stays '/'),
 * and refused when it holds a character a listing cannot carry.
 */
bool PrepareRemotePath(const std::string & remotePath, std::string & path,
    std::string & error)
{
    error.clear();
    if (!ScpValidRemotePath(remotePath, error))
    {
        return false;
    }
    path = remotePath;
    while (path.size() > 1 && path[path.size() - 1] == '/')
    {
        path.erase(path.size() - 1);
    }
    if (path.empty())
    {
        path = ".";
    }
    else if (path[0] == '-')
    {
        /* Prefix './' so a relative name starting with '-' is never parsed as
         * a flag by remote shell commands ('ls', 'rm', 'scp', 'touch', ...). */
        path = "./" + path;
    }
    return true;
}

/*
 * The listing and stat commands.
 *
 * They ask for the C locale, because the month names in an 'ls -l' date
 * column are the only way this engine can read a timestamp back and a
 * server in another locale would print names the parser does not know;
 * 'env' is POSIX, so that does not depend on the remote shell accepting an
 * assignment in front of a command.
 *
 * They also ask for '--full-time', which is the difference between a
 * timestamp and an approximation of one: a plain 'ls -l' prints a minute
 * for a file from the last six months and only a year for an older one, so
 * a directory's own time and every comparison the synchronizer makes by
 * time would be that coarse. '--full-time' prints the date, the seconds and
 * the offset they are in, which is exact and needs no assumption about the
 * server's clock or locale. A server whose 'ls' does not have the option
 * says so, and the engine asks again without it - a coarser timestamp is
 * still a listing.
 */
std::string ListingCommand(const std::string & path, bool withLocale,
    bool withFullTime)
{
    return std::string(withLocale ? "env LC_ALL=C " : "") + "ls -l -a " +
        (withFullTime ? "--full-time " : "") + ScpShellQuote(path);
}

std::string StatCommand(const std::string & path, bool withLocale,
    bool withFullTime)
{
    return std::string(withLocale ? "env LC_ALL=C " : "") + "ls -l -d " +
        (withFullTime ? "--full-time " : "") + ScpShellQuote(path);
}

/* Exit status 127 is the shell's 'no such command', which for these two
 * commands means the server has no 'env' to set the locale with. Listing
 * without it still works wherever the server's month names are the C
 * ones, and a timestamp nobody can read is better than no listing. */
bool MissingCommand(const ShellReply & reply)
{
    return reply.connected && reply.exitCode == 127;
}

/* Whether the server's 'ls' refused the command over an option it does not
 * have, which is the only failure worth asking again for: every other
 * failure is an answer about the path. */
bool OptionUnsupported(const ShellReply & reply)
{
    const std::string text = LowerAscii(reply.errors);
    return text.find("unrecognized option") != std::string::npos ||
        text.find("unknown option") != std::string::npos ||
        text.find("invalid option") != std::string::npos ||
        text.find("illegal option") != std::string::npos ||
        text.find("not a valid option") != std::string::npos ||
        text.find("bad option") != std::string::npos ||
        /* BusyBox and its kin answer an option they do not know with the
         * usage text of the whole applet. */
        text.find("usage:") != std::string::npos;
}

/*
 * Runs a listing or a stat command, dropping the parts of it the server's
 * 'ls' does not have, and returns the answer the server gave - which for a
 * path that is not there or may not be read is a failure the caller reports
 * in the server's own words. Only a connection that could not be made or a
 * command that never ran returns false.
 */
bool RunListingCommand(const SessionOptions & options,
    const std::string & path, bool directoryOnly, ShellReply & reply,
    std::string & command, std::string & error)
{
    bool withLocale = true;
    bool withFullTime = true;
    for (int attempt = 0; attempt < 3; attempt++)
    {
        command = directoryOnly ?
            StatCommand(path, withLocale, withFullTime) :
            ListingCommand(path, withLocale, withFullTime);
        if (!RunShell(options, command, reply, error))
        {
            return false;
        }
        if (reply.Succeeded())
        {
            return true;
        }
        if (withFullTime && OptionUnsupported(reply))
        {
            withFullTime = false;
            continue;
        }
        if (withLocale && MissingCommand(reply))
        {
            withLocale = false;
            continue;
        }
        return true;
    }
    return true;
}

/* The last long-listing line of an answer, which is the one that describes
 * the path asked about: anything before it was printed by the shell. */
bool LastListingLine(const std::string & output, ListingEntry & entry)
{
    bool found = false;
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line))
    {
        if (!line.empty() && line[line.size() - 1] == '\r')
        {
            line.erase(line.size() - 1);
        }
        ListingEntry candidate;
        if (ScpParseListingLine(line, candidate))
        {
            entry = candidate;
            entry.longname = line;
            found = true;
        }
    }
    return found;
}

void EntryToAttrs(const ListingEntry & entry, LscpAttrs * attrs)
{
    memset(attrs, 0, sizeof(*attrs));
    attrs->flags = LSCP_ATTR_PERMISSIONS | LSCP_ATTR_SIZE;
    attrs->permissions = entry.permissions;
    attrs->size = entry.size;
    if (entry.timeKnown)
    {
        /* 'ls -l' carries one timestamp, the modification time; the access
         * time is the same value, which is what the listing-based
         * protocols have always reported. */
        attrs->flags |= LSCP_ATTR_ACMODTIME;
        attrs->atime = entry.mtime;
        attrs->mtime = entry.mtime;
    }
}

} // namespace

/* ---- the parts the unit suite pins ----------------------------------- */

std::string ScpShellQuote(const std::string & text)
{
    std::string quoted = "'";
    for (size_t i = 0; i < text.size(); i++)
    {
        if (text[i] == '\'')
        {
            /* Close the quoted word, add an escaped quote and open it
             * again: the only sequence a POSIX shell cannot be given a
             * quote inside of is a single-quoted word. */
            quoted += "'\\''";
        }
        else
        {
            quoted += text[i];
        }
    }
    quoted += "'";
    return quoted;
}

bool ScpValidRemotePath(const std::string & path, std::string & error)
{
    error.clear();
    if (path.empty())
    {
        error = "The remote path is empty.";
        return false;
    }
    for (size_t i = 0; i < path.size(); i++)
    {
        const unsigned char c = static_cast<unsigned char>(path[i]);
        if (c < 0x20 || c == 0x7f)
        {
            error = "The remote path contains a control character, which a "
                "shell command line and an 'ls -l' listing cannot carry "
                "safely.";
            return false;
        }
    }
    return true;
}

unsigned long ScpParseFullTime(const std::string & dateText,
    const std::string & timeText, const std::string & offsetText)
{
    int year = 0;
    int month = 0;
    int day = 0;
    if (sscanf(dateText.c_str(), "%4d-%2d-%2d", &year, &month, &day) != 3)
    {
        return 0;
    }
    int hour = 0;
    int minute = 0;
    int second = 0;
    /* The seconds may carry a fraction, which 'ls' prints and this engine
     * has no field for: sscanf stops at the dot and the whole seconds are
     * what a timestamp comparison needs. */
    if (sscanf(timeText.c_str(), "%2d:%2d:%2d", &hour, &minute, &second) != 3)
    {
        return 0;
    }
    if (year < 1970 || year > 9999 || month < 1 || month > 12 || day < 1 ||
        day > 31 || hour > 23 || minute > 59 || second > 60)
    {
        return 0;
    }

    /* The offset says which clock the two columns were printed in: '+0000',
     * '-0700' and '+05:30' are all shapes GNU ls writes, and 'Z' is the one
     * a server configured for UTC may use. */
    std::string offset = offsetText;
    for (std::string::size_type i = 0; i < offset.size(); i++)
    {
        if (offset[i] == ':')
        {
            offset.erase(i, 1);
            break;
        }
    }
    int offsetSign = 0;
    int offsetHours = 0;
    int offsetMinutes = 0;
    if (LowerAscii(offset) == "z")
    {
        offsetSign = 1;
    }
    else
    {
        char sign = 0;
        const int read = sscanf(offset.c_str(), "%c%2d%2d", &sign, &offsetHours,
            &offsetMinutes);
        if ((read != 3 && read != 2) || (sign != '+' && sign != '-'))
        {
            return 0;
        }
        offsetSign = sign == '+' ? 1 : -1;
    }

    struct tm parts;
    memset(&parts, 0, sizeof(parts));
    parts.tm_year = year - 1900;
    parts.tm_mon = month - 1;
    parts.tm_mday = day;
    parts.tm_hour = hour;
    parts.tm_min = minute;
    parts.tm_sec = second;
    const time_t utc = timegm(&parts);
    if (utc < 0)
    {
        return 0;
    }
    /* Reject non-existent calendar dates such as 2026-02-31 that timegm()
     * normalizes into the next month. */
    if (parts.tm_year != year - 1900 || parts.tm_mon != month - 1 ||
        parts.tm_mday != day)
    {
        return 0;
    }
    /* A timestamp printed in a zone ahead of UTC names a moment earlier
     * than the same reading in UTC, so the offset is taken off. */
    const long long seconds = static_cast<long long>(utc) -
        static_cast<long long>(offsetSign) *
        (offsetHours * 3600LL + offsetMinutes * 60LL);
    return seconds > 0 ? static_cast<unsigned long>(seconds) : 0;
}

bool ScpParseListingLine(const std::string & line, ListingEntry & entry)
{
    if (line.empty())
    {
        return false;
    }
    /* The block count 'ls -l' prints in front of a directory listing is
     * not an entry, and neither is a line the shell printed before the
     * command ran: neither is a long listing, so both are skipped rather
     * than mistaken for a name. */
    if (line.compare(0, 6, "total ") == 0)
    {
        return false;
    }
    if (!ParseUnixListingLine(line, entry))
    {
        return false;
    }
    entry.longname = line;
    if (line[0] == 'l')
    {
        /* 'name -> target': the target is where the link points, not part
         * of the link's own name. A name that holds the same sequence is
         * truncated by this, which is the ambiguity 'ls -l' itself
         * creates and cannot undo. */
        const std::string::size_type arrow = entry.name.find(" -> ");
        if (arrow != std::string::npos)
        {
            entry.name = entry.name.substr(0, arrow);
        }
        entry.isDir = false;
        entry.permissions = (entry.permissions & ~0170000UL) | 0120000UL;
    }
    if (!entry.timeKnown)
    {
        /* The date columns of a '--full-time' listing are not month names,
         * so the shared parser reads no time from them: they are an exact
         * date, an exact time and the offset both are in. */
        std::vector<std::string> fields;
        if (SplitLongListing(line, fields))
        {
            const unsigned long exact = ScpParseFullTime(fields[5], fields[6],
                fields[7]);
            if (exact != 0)
            {
                entry.mtime = exact;
                entry.timeKnown = true;
            }
        }
    }
    if (entry.name.empty() || entry.name == "." || entry.name == "..")
    {
        return false;
    }
    return true;
}

bool ScpParseHeaderLine(const std::string & line, char & kind,
    unsigned int & mode, unsigned long long & size, std::string & name,
    unsigned long & mtime, unsigned long & atime)
{
    kind = 0;
    mode = 0;
    size = 0;
    name.clear();
    mtime = 0;
    atime = 0;
    if (line.empty())
    {
        return false;
    }
    const char first = line[0];
    /* The body without the leading byte and without the newline. */
    std::string body = line.substr(1);
    if (!body.empty() && body[body.size() - 1] == '\n')
    {
        body.erase(body.size() - 1);
    }
    if (!body.empty() && body[body.size() - 1] == '\r')
    {
        body.erase(body.size() - 1);
    }
    if (first == 1 || first == 2)
    {
        kind = first;
        name = TrimText(body);
        return true;
    }
    if (first == 'E')
    {
        if (!body.empty())
        {
            return false;
        }
        kind = 'E';
        return true;
    }
    if (first == 'T')
    {
        /* 'T<mtime> 0 <atime> 0': the two zero fields are the sub-second
         * parts the protocol leaves unused. Reject negative tokens and
         * trailing non-whitespace junk. */
        if (body.find('-') != std::string::npos)
        {
            return false;
        }
        std::istringstream stream(body);
        unsigned long long firstValue = 0;
        unsigned long long firstFraction = 0;
        unsigned long long secondValue = 0;
        unsigned long long secondFraction = 0;
        std::string extra;
        if (!(stream >> firstValue >> firstFraction >> secondValue >>
              secondFraction) || (stream >> extra))
        {
            return false;
        }
        kind = 'T';
        mtime = static_cast<unsigned long>(firstValue);
        atime = static_cast<unsigned long>(secondValue);
        return true;
    }
    if (first == 'C' || first == 'D')
    {
        /* 'C0644 512 name' - the name is the rest of the line and may
         * hold spaces, but never '/', '.', '..', or NUL/control bytes
         * (CVE-2019-6111). */
        std::string modeText;
        unsigned long long sizeValue = 0;
        const std::string::size_type firstSpace = body.find(' ');
        if (firstSpace == std::string::npos)
        {
            return false;
        }
        modeText = body.substr(0, firstSpace);
        std::string rest = body.substr(firstSpace + 1);
        const std::string::size_type secondSpace = rest.find(' ');
        if (secondSpace == std::string::npos)
        {
            return false;
        }
        const std::string sizeText = rest.substr(0, secondSpace);
        name = rest.substr(secondSpace + 1);
        if (modeText.empty() || sizeText.empty() || name.empty())
        {
            return false;
        }
        if (modeText[0] < '0' || modeText[0] > '7' ||
            sizeText[0] < '0' || sizeText[0] > '9')
        {
            return false;
        }
        if (name == "." || name == ".." ||
            name.find('/') != std::string::npos ||
            name.find('\0') != std::string::npos)
        {
            return false;
        }
        for (size_t i = 0; i < name.size(); ++i)
        {
            const unsigned char ch = static_cast<unsigned char>(name[i]);
            if (ch < 0x20U || ch == 0x7fU)
            {
                return false;
            }
        }
        errno = 0;
        char * end = NULL;
        const unsigned long modeValue = strtoul(modeText.c_str(), &end, 8);
        if (errno != 0 || end == NULL || *end != '\0' || modeValue > 07777UL)
        {
            return false;
        }
        errno = 0;
        end = NULL;
        sizeValue = strtoull(sizeText.c_str(), &end, 10);
        if (errno != 0 || end == NULL || *end != '\0')
        {
            return false;
        }
        kind = first;
        mode = static_cast<unsigned int>(modeValue);
        size = first == 'C' ? sizeValue : 0;
        return true;
    }
    return false;
}

std::string ScpFileHeaderLine(unsigned int mode, unsigned long long size,
    const std::string & name)
{
    char header[64];
    snprintf(header, sizeof(header), "C%04o %llu ",
        static_cast<unsigned int>(mode & 07777), size);
    return std::string(header) + name + "\n";
}

std::string ScpDirectoryHeaderLine(unsigned int mode, const std::string & name)
{
    char header[64];
    snprintf(header, sizeof(header), "D%04o 0 ",
        static_cast<unsigned int>(mode & 07777));
    return std::string(header) + name + "\n";
}

std::string ScpTimeHeaderLine(unsigned long mtime, unsigned long atime)
{
    char header[80];
    snprintf(header, sizeof(header), "T%lu 0 %lu 0\n", mtime,
        atime != 0 ? atime : mtime);
    return std::string(header);
}

std::string ScpTouchStamp(unsigned long secondsSinceEpoch)
{
    /* 'touch -t' reads the stamp in the server's local time, so the
     * command that carries it asks for UTC and the stamp is the UTC
     * reading of the moment. */
    const time_t when = static_cast<time_t>(secondsSinceEpoch);
    struct tm parts;
    if (gmtime_r(&when, &parts) == NULL)
    {
        return std::string();
    }
    char stamp[32];
    snprintf(stamp, sizeof(stamp), "%04d%02d%02d%02d%02d.%02d",
        parts.tm_year + 1900, parts.tm_mon + 1, parts.tm_mday, parts.tm_hour,
        parts.tm_min, parts.tm_sec);
    return std::string(stamp);
}

bool ScpSaysMissing(const std::string & text)
{
    const std::string lower = LowerAscii(text);
    return lower.find("no such file or directory") != std::string::npos ||
        lower.find("not a directory") != std::string::npos ||
        lower.find("does not exist") != std::string::npos ||
        lower.find("not found") != std::string::npos;
}

/* ---- which sessions belong to this engine ---------------------------- */

bool ScpClient::Handles(const SessionOptions & options)
{
    const std::string protocol = LowerAscii(options.protocol);
    /* 'ssh' is the spelling of the same protocol a curl URL uses, and this
     * client has always accepted both for one site. */
    return protocol == "scp" || protocol == "ssh";
}

/* ---- the shell half -------------------------------------------------- */

bool ScpClient::List(const SessionOptions & options,
    const std::string & remotePath, std::vector<ListingEntry> & entries,
    std::string & error, int * codeOut)
{
    entries.clear();
    error.clear();
    if (codeOut != NULL)
    {
        *codeOut = 0;
    }

    std::string path;
    if (!PrepareRemotePath(remotePath, path, error))
    {
        return false;
    }
    std::string command;
    ShellReply reply;
    if (!RunListingCommand(options, path, false, reply, command, error))
    {
        if (codeOut != NULL)
        {
            *codeOut = kScpTransportFailure;
        }
        return false;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, command);
        return false;
    }

    std::istringstream stream(reply.output);
    std::string line;
    while (std::getline(stream, line))
    {
        if (!line.empty() && line[line.size() - 1] == '\r')
        {
            line.erase(line.size() - 1);
        }
        ListingEntry entry;
        if (!ScpParseListingLine(line, entry))
        {
            continue;
        }
        entries.push_back(entry);
    }
    return true;
}

int ScpClient::Stat(const SessionOptions & options,
    const std::string & remotePath, LscpAttrs * attrs, std::string & error)
{
    error.clear();
    if (attrs != NULL)
    {
        memset(attrs, 0, sizeof(*attrs));
    }
    std::string path;
    if (!PrepareRemotePath(remotePath, path, error))
    {
        return LSCP_SFTP_STAT_ERROR;
    }
    std::string command;
    ShellReply reply;
    if (!RunListingCommand(options, path, true, reply, command, error))
    {
        return LSCP_SFTP_STAT_ERROR;
    }
    if (reply.exitCode != 0)
    {
        /* A path that is not there is an answer, not a failure: 'stat' has
         * to say "missing" so that an overwrite confirmation, a rename and
         * the synchronizer can tell it from a server that refused. */
        if (ScpSaysMissing(reply.errors))
        {
            error.clear();
            return LSCP_SFTP_STAT_MISSING;
        }
        error = ShellReason(reply, command);
        return LSCP_SFTP_STAT_ERROR;
    }
    ListingEntry entry;
    if (!LastListingLine(reply.output, entry))
    {
        error = "The server's 'ls -l -d' printed no listing line for '" +
            remotePath + "'.";
        return LSCP_SFTP_STAT_ERROR;
    }
    if (attrs != NULL)
    {
        EntryToAttrs(entry, attrs);
    }
    return LSCP_SFTP_STAT_EXISTS;
}

int ScpClient::Remove(const SessionOptions & options,
    const std::string & remotePath, std::string & error)
{
    std::string path;
    if (!PrepareRemotePath(remotePath, path, error))
    {
        return -1;
    }
    /* Plain 'rm': it refuses a directory on its own, which is what 'rm'
     * and 'rmdir' mean in this client and upstream's. '-f' would hide the
     * reason a file could not be removed and report success for a path
     * that was never there. */
    const std::string command = "rm " + ScpShellQuote(path);
    ShellReply reply;
    if (!RunShell(options, command, reply, error))
    {
        return -1;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, command);
        return -1;
    }
    return 0;
}

int ScpClient::RemoveDir(const SessionOptions & options,
    const std::string & remotePath, std::string & error)
{
    std::string path;
    if (!PrepareRemotePath(remotePath, path, error))
    {
        return -1;
    }
    /* 'rmdir' only removes an empty directory; the recursive walk that
     * empties one first is the caller's, as it is for every protocol. */
    const std::string command = "rmdir " + ScpShellQuote(path);
    ShellReply reply;
    if (!RunShell(options, command, reply, error))
    {
        return -1;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, command);
        return -1;
    }
    return 0;
}

int ScpClient::MakeDir(const SessionOptions & options,
    const std::string & remotePath, std::string & error)
{
    std::string path;
    if (!PrepareRemotePath(remotePath, path, error))
    {
        return -1;
    }
    const std::string command = "mkdir " + ScpShellQuote(path);
    ShellReply reply;
    if (!RunShell(options, command, reply, error))
    {
        return -1;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, command);
        return -1;
    }
    return 0;
}

int ScpClient::Move(const SessionOptions & options,
    const std::string & fromPath, const std::string & toPath,
    std::string & error)
{
    std::string from;
    std::string to;
    if (!PrepareRemotePath(fromPath, from, error) ||
        !PrepareRemotePath(toPath, to, error))
    {
        return -1;
    }
    const std::string command = "mv " + ScpShellQuote(from) + " " +
        ScpShellQuote(to);
    ShellReply reply;
    if (!RunShell(options, command, reply, error))
    {
        return -1;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, command);
        return -1;
    }
    return 0;
}

int ScpClient::Copy(const SessionOptions & options,
    const std::string & fromPath, const std::string & toPath,
    std::string & error)
{
    std::string from;
    std::string to;
    if (!PrepareRemotePath(fromPath, from, error) ||
        !PrepareRemotePath(toPath, to, error))
    {
        return -1;
    }
    /* '-p' keeps the mode and the timestamps of the source, which is what
     * a server-side copy of every other protocol in this client does. */
    const std::string command = "cp -p " + ScpShellQuote(from) + " " +
        ScpShellQuote(to);
    ShellReply reply;
    if (!RunShell(options, command, reply, error))
    {
        return -1;
    }
    if (reply.exitCode == 127)
    {
        /* The server has no 'cp' to run. That is not a failure of the copy
         * but the absence of one, so the caller streams the bytes through
         * this client instead. */
        error.clear();
        return 1;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, command);
        return -1;
    }
    return 0;
}

int ScpClient::SetPermissions(const SessionOptions & options,
    const std::string & remotePath, int permissions, std::string & error)
{
    std::string path;
    if (!PrepareRemotePath(remotePath, path, error))
    {
        return -1;
    }
    char mode[16];
    snprintf(mode, sizeof(mode), "%04o",
        static_cast<unsigned int>(permissions) & 07777U);
    const std::string command = std::string("chmod ") + mode + " " +
        ScpShellQuote(path);
    ShellReply reply;
    if (!RunShell(options, command, reply, error))
    {
        return -1;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, command);
        return -1;
    }
    return 0;
}

bool ScpClient::SetTimes(const SessionOptions & options,
    const std::string & remotePath, unsigned long atime, unsigned long mtime,
    std::string & error)
{
    std::string path;
    if (!PrepareRemotePath(remotePath, path, error))
    {
        return false;
    }
    const unsigned long stamp = mtime != 0 ? mtime : atime;
    if (stamp == 0)
    {
        error = "There is no timestamp to set '" + remotePath + "' to.";
        return false;
    }
    const std::string text = ScpTouchStamp(stamp);
    if (text.empty())
    {
        error = "The timestamp of '" + remotePath + "' cannot be formatted.";
        return false;
    }
    /* 'touch -t' sets the access time and the modification time to the one
     * value; the protocol this engine has carries no way to set them
     * separately, and the modification time is the one a comparison reads. */
    std::string command = "env TZ=UTC touch -t " + text + " " +
        ScpShellQuote(path);
    ShellReply reply;
    if (!RunShell(options, command, reply, error))
    {
        return false;
    }
    if (MissingCommand(reply))
    {
        command = "touch -t " + text + " " + ScpShellQuote(path);
        if (!RunShell(options, command, reply, error))
        {
            return false;
        }
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, command);
        return false;
    }
    return true;
}

bool ScpClient::MakeSymlink(const SessionOptions & options,
    const std::string & target, const std::string & linkPath,
    std::string & error)
{
    std::string link;
    if (!PrepareRemotePath(linkPath, link, error))
    {
        return false;
    }
    if (!ScpValidRemotePath(target, error))
    {
        return false;
    }
    /* A shell command can make a link, which the rcp protocol cannot: this
     * is one of the places where having the server's shell is worth more
     * than the transfer protocol alone. The target is quoted like a path
     * and is otherwise left alone, because a link may point at anything. */
    const std::string command = "ln -s " + ScpShellQuote(target) + " " +
        ScpShellQuote(link);
    ShellReply reply;
    if (!RunShell(options, command, reply, error))
    {
        return false;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, command);
        return false;
    }
    return true;
}

bool ScpClient::ResolvePath(const SessionOptions & options,
    const std::string & remotePath, std::string & resolved,
    std::string & error)
{
    resolved.clear();
    std::string path;
    if (!PrepareRemotePath(remotePath, path, error))
    {
        return false;
    }
    /* 'cd' is a shell builtin, so this asks the server's own shell what the
     * path names: a symlink is followed, a relative path is resolved
     * against the directory the login starts in, and a path that is not
     * there fails with the shell's reason. */
    const std::string command = "cd " + ScpShellQuote(path) + " && pwd";
    ShellReply reply;
    if (!RunShell(options, command, reply, error))
    {
        return false;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, command);
        return false;
    }
    std::istringstream stream(reply.output);
    std::string line;
    while (std::getline(stream, line))
    {
        const std::string candidate = TrimText(line);
        /* The answer is the last absolute path the command printed: a
         * shell that announces itself before running the command would
         * otherwise become the directory. */
        if (!candidate.empty() && candidate[0] == '/')
        {
            resolved = candidate;
        }
    }
    if (resolved.empty())
    {
        error = "The server's shell did not report the directory '" +
            remotePath + "' resolved to.";
        return false;
    }
    return true;
}

bool ScpClient::ResolveHomeAndInitial(const SessionOptions & options,
    const std::string & initialPath, std::string & home,
    std::string & resolved, std::string & error)
{
    home.clear();
    resolved.clear();
    std::string path;
    if (!PrepareRemotePath(initialPath.empty() ? std::string(".") : initialPath,
            path, error))
    {
        return false;
    }
    /* Both answers in one connection: the shell starts in the login
     * directory, says so, and then says where the site's path is. */
    const std::string command = "pwd && cd " + ScpShellQuote(path) + " && pwd";
    ShellReply reply;
    if (!RunShell(options, command, reply, error))
    {
        return false;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, "cd " + path);
        return false;
    }
    std::vector<std::string> answers;
    std::istringstream stream(reply.output);
    std::string line;
    while (std::getline(stream, line))
    {
        const std::string candidate = TrimText(line);
        /* Only an absolute path is an answer; a shell that announces
         * itself before running the command is not a directory. */
        if (!candidate.empty() && candidate[0] == '/')
        {
            answers.push_back(candidate);
        }
    }
    if (answers.size() < 2)
    {
        error = "The server's shell did not report the login directory and "
            "'" + path + "' as two absolute paths.";
        return false;
    }
    home = answers.front();
    resolved = answers.back();
    return true;
}

bool ScpClient::CheckEndpoint(const SessionOptions & options,
    const std::string & remotePath, std::string & error)
{
    error.clear();
    (void)remotePath;
    /* 'pwd' asks for nothing but a shell: it proves the host is there, the
     * host key matched, the credentials were accepted and a command can
     * run. The directory a site starts in is resolved by 'open' itself, so
     * a directory the server will not change into is that command's answer
     * to report, not a reason to say the endpoint is unusable. */
    ShellReply reply;
    if (!RunShell(options, "pwd", reply, error))
    {
        if (error.empty())
        {
            error = "The SCP server could not be reached.";
        }
        return false;
    }
    if (!reply.Succeeded())
    {
        error = ShellReason(reply, "pwd");
        return false;
    }
    return true;
}

/* ---- the transfer half ---------------------------------------------- */

int ScpClient::Get(const SessionOptions & options,
    const std::string & remotePath, const std::string & localPath,
    unsigned long long resumeOffset, bool preserveTime,
    unsigned long long * size, LscpProgressFn progress, void * progressCtx,
    std::string & error, unsigned speedKBytesPerSecond)
{
    error.clear();
    if (size != NULL)
    {
        *size = 0;
    }
    if (resumeOffset > 0)
    {
        error = "SCP cannot resume a download: the transfer protocol has no "
            "offset to continue from. Use 'option resume off' or "
            "'-resumesupport=off'.";
        return -1;
    }
    std::string path;
    if (!PrepareRemotePath(remotePath, path, error))
    {
        return -1;
    }
    /* A local destination that ends in a separator is a directory to put
     * the file in; its name is the one the server's header carries, so the
     * path is completed once that has arrived. */
    const bool localIsDirectory = !localPath.empty() &&
        localPath[localPath.size() - 1] == '/';
    std::string destination = localIsDirectory ? std::string() : localPath;

    /* '-p' carries the timestamps in the protocol itself, which is the
     * only way an SCP download can preserve them. */
    const std::string command = std::string("scp -f") +
        (preserveTime ? " -p" : "") + " " + ScpShellQuote(path);
    ScpChannel channel;
    if (!channel.Open(options, command, error))
    {
        return -1;
    }

    /* The receiving side starts the exchange: the source waits for this
     * byte before it sends its first header. */
    if (!channel.SendByte(0))
    {
        error = "The connection to " + options.hostName +
            " closed before the download could start.";
        return -1;
    }

    unsigned long mtime = 0;
    unsigned long atime = 0;
    unsigned int mode = 0;
    unsigned long long fileSize = 0;
    std::string name;
    bool haveFile = false;
    for (;;)
    {
        std::string line;
        if (!channel.ReadLine(line))
        {
            const std::string errors = channel.Errors();
            error = errors.empty() ?
                "The connection closed before the server's scp sent a file "
                "header for '" + remotePath + "'." :
                errors;
            channel.Close();
            return -1;
        }
        char kind = 0;
        unsigned long headerMtime = 0;
        unsigned long headerAtime = 0;
        if (!ScpParseHeaderLine(line, kind, mode, fileSize, name, headerMtime,
                headerAtime))
        {
            error = "The server's scp sent a reply this client cannot read: " +
                TrimText(line);
            channel.Close();
            return -1;
        }
        if (kind == 1 || kind == 2)
        {
            /* The header carries the reason in the same field a file name
             * would be in, so the message the server sent is the error. */
            error = name.empty() ?
                "The server's scp refused the download of '" + remotePath +
                    "' without saying why." :
                name;
            if (error[error.size() - 1] != '.')
            {
                error += ".";
            }
            channel.Close();
            return -1;
        }
        if (kind == 'T')
        {
            mtime = headerMtime;
            atime = headerAtime;
            if (!channel.SendByte(0))
            {
                error = "The connection closed while the download of '" +
                    remotePath + "' was starting.";
                channel.Close();
                return -1;
            }
            continue;
        }
        if (kind == 'D')
        {
            error = "'" + remotePath + "' is a directory, and an SCP transfer "
                "carries one file at a time.";
            channel.Close();
            return -1;
        }
        if (kind == 'E')
        {
            break;
        }
        haveFile = true;
        break;
    }
    if (!haveFile)
    {
        error = "The server's scp sent no file for '" + remotePath + "'.";
        channel.Close();
        return -1;
    }
    /* The mode in the header is the server's, and a download does not
     * apply it: what the local file's permissions are is the local side's
     * business, and '-permissions=' sets them explicitly when asked.
     * Guard against CVE-2019-6111: the server-supplied header filename
     * must match the requested remote basename (when specific) and must
     * never traverse directories. */
    const std::string expectedLeaf = RemoteFileName(path);
    if (!expectedLeaf.empty() && expectedLeaf != "." &&
        !HasWildcard(expectedLeaf) && name != expectedLeaf)
    {
        error = "The server's scp offered '" + name +
            "' instead of the requested file '" + expectedLeaf + "'.";
        channel.Close();
        return -1;
    }
    if (localIsDirectory)
    {
        destination = localPath + name;
    }

    /* Ready for the data. */
    if (!channel.SendByte(0))
    {
        error = "The connection closed before the data of '" + remotePath +
            "' arrived.";
        channel.Close();
        return -1;
    }

    FILE * local = fopen(destination.c_str(), "wb");
    if (local == NULL)
    {
        error = "Cannot open the local file '" + destination + "': " +
            strerror(errno) + ".";
        channel.Close();
        return -1;
    }

    RateLimiter limiter(speedKBytesPerSecond);
    std::vector<char> buffer(kChunkSize);
    unsigned long long remaining = fileSize;
    unsigned long long transferred = 0;
    bool failed = false;
    while (remaining > 0)
    {
        if (Interrupted())
        {
            error = "Interrupted.";
            failed = true;
            break;
        }
        const size_t wanted = static_cast<size_t>(
            remaining < kChunkSize ? remaining : kChunkSize);
        if (!channel.ReadBytes(&buffer[0], wanted))
        {
            error = "The connection closed after " +
                std::to_string(transferred) + " of " +
                std::to_string(fileSize) + " bytes of '" + remotePath + "'.";
            failed = true;
            break;
        }
        if (fwrite(&buffer[0], 1, wanted, local) != wanted)
        {
            error = "Cannot write to the local file '" + destination + "': " +
                strerror(errno) + ".";
            failed = true;
            break;
        }
        remaining -= wanted;
        transferred += wanted;
        limiter.Consume(wanted);
        if (progress != NULL)
        {
            progress(transferred, fileSize, progressCtx);
        }
    }

    if (!failed)
    {
        /* The source ends the file with a NUL byte of its own; an error
         * there means the server could not read the file it was sending. */
        std::string message;
        if (!channel.ReadAcknowledgement(message))
        {
            error = message;
            failed = true;
        }
    }
    if (!failed)
    {
        if (fflush(local) != 0)
        {
            error = "Cannot write to the local file '" + destination + "': " +
                strerror(errno) + ".";
            failed = true;
        }
    }
    fclose(local);
    if (progress != NULL && !failed)
    {
        /* One last report, so a caller that renders a percentage ends at
         * 100 even for a file that fit in no chunk at all. */
        progress(transferred, fileSize, progressCtx);
    }

    if (failed)
    {
        /* Nothing half written is left behind under the name the caller
         * asked for: this protocol cannot continue a partial file, so a
         * truncated one is not a transfer in progress but a file that is
         * wrong. */
        remove(destination.c_str());
        channel.Close();
        return -1;
    }

    if (!channel.SendByte(0))
    {
        error = "The connection closed while the download of '" + remotePath +
            "' was acknowledged.";
        remove(destination.c_str());
        channel.Close();
        return -1;
    }
    channel.SendEof();
    std::string errors;
    const int exitCode = channel.Finish(errors);
    if (exitCode != 0 && exitCode != INT_MAX)
    {
        error = errors.empty() ?
            "The server's scp failed with exit status " +
                std::to_string(exitCode) + " while sending '" + remotePath +
                "'." :
            errors;
        remove(destination.c_str());
        return -1;
    }

    if (preserveTime && mtime != 0)
    {
        /* A local time set after a download is not a remote operation,
         * so the XML log has no '<touch>' for it. */
        SetFileTimes(destination, atime != 0 ? atime : mtime, mtime);
    }
    if (size != NULL)
    {
        *size = transferred;
    }
    return 0;
}

int ScpClient::Put(const SessionOptions & options,
    const std::string & localPath, const std::string & remotePath,
    int permissions, unsigned long long resumeOffset, bool preserveTime,
    unsigned long long * size, LscpProgressFn progress, void * progressCtx,
    std::string & error, unsigned speedKBytesPerSecond)
{
    error.clear();
    if (size != NULL)
    {
        *size = 0;
    }
    if (resumeOffset > 0)
    {
        error = "SCP cannot resume an upload: the transfer protocol has no "
            "offset to continue from. Use 'option resume off' or "
            "'-resumesupport=off'.";
        return -1;
    }
    /* A remote destination that ends in a separator is the directory to
     * upload into; the file keeps its own name, which is also the name the
     * protocol's header carries. */
    std::string target = remotePath;
    if (!target.empty() && target[target.size() - 1] == '/')
    {
        target += RemoteFileName(localPath);
    }
    std::string path;
    if (!PrepareRemotePath(target, path, error))
    {
        return -1;
    }

    const LocalFileInfo info = StatLocal(localPath);
    if (!info.exists)
    {
        error = info.error != 0 ?
            "Cannot read the local file '" + localPath + "': " +
                strerror(info.error) + "." :
            "The local file '" + localPath + "' is not there.";
        return -1;
    }
    if (info.isDir)
    {
        error = "'" + localPath + "' is a directory, and an SCP transfer "
            "carries one file at a time.";
        return -1;
    }

    /* The mode the file is to have on the server: the one '-permissions='
     * asked for, or the local file's own, which is what scp sends. */
    const unsigned int mode = permissions >= 0 ?
        static_cast<unsigned int>(permissions) & 07777U :
        static_cast<unsigned int>(info.permissions) & 07777U;

    const std::string command = std::string("scp -t") +
        (preserveTime ? " -p" : "") + " " + ScpShellQuote(path);
    ScpChannel channel;
    if (!channel.Open(options, command, error))
    {
        return -1;
    }

    std::string message;
    if (!channel.ReadAcknowledgement(message))
    {
        error = message;
        return -1;
    }
    if (preserveTime && info.mtime != 0)
    {
        const std::string header = ScpTimeHeaderLine(info.mtime, info.atime);
        if (!channel.SendBytes(header.data(), header.size()) ||
            !channel.ReadAcknowledgement(message))
        {
            error = message.empty() ?
                "The connection closed while the timestamps of '" +
                    remotePath + "' were sent." :
                message;
            return -1;
        }
    }

    /* The name in the header is the file's own, never a path: the server
     * writes to the destination it was given, and a name with a separator
     * in it is one a careful server refuses. */
    std::string name = RemoteFileName(path);
    if (name.empty())
    {
        name = RemoteFileName(localPath);
    }
    if (name.empty())
    {
        error = "There is no file name to upload '" + localPath + "' as.";
        return -1;
    }
    const std::string header = ScpFileHeaderLine(mode, info.size, name);
    if (!channel.SendBytes(header.data(), header.size()))
    {
        error = "The connection closed before the upload of '" + remotePath +
            "' could start.";
        return -1;
    }
    if (!channel.ReadAcknowledgement(message))
    {
        error = message;
        return -1;
    }

    FILE * local = fopen(localPath.c_str(), "rb");
    if (local == NULL)
    {
        error = "Cannot read the local file '" + localPath + "': " +
            strerror(errno) + ".";
        return -1;
    }

    RateLimiter limiter(speedKBytesPerSecond);
    std::vector<char> buffer(kChunkSize);
    unsigned long long remaining = info.size;
    unsigned long long transferred = 0;
    bool failed = false;
    while (remaining > 0)
    {
        if (Interrupted())
        {
            error = "Interrupted.";
            failed = true;
            break;
        }
        const size_t wanted = static_cast<size_t>(
            remaining < kChunkSize ? remaining : kChunkSize);
        const size_t read = fread(&buffer[0], 1, wanted, local);
        if (read != wanted)
        {
            error = ferror(local) != 0 ?
                "Cannot read the local file '" + localPath + "': " +
                    strerror(errno) + "." :
                "The local file '" + localPath + "' ended after " +
                    std::to_string(transferred + read) + " of " +
                    std::to_string(info.size) + " bytes.";
            failed = true;
            break;
        }
        if (!channel.SendBytes(&buffer[0], wanted))
        {
            error = "The connection closed after " +
                std::to_string(transferred) + " of " +
                std::to_string(info.size) + " bytes of '" + remotePath + "'.";
            failed = true;
            break;
        }
        remaining -= wanted;
        transferred += wanted;
        limiter.Consume(wanted);
        if (progress != NULL)
        {
            progress(transferred, info.size, progressCtx);
        }
    }
    fclose(local);
    if (progress != NULL && !failed)
    {
        progress(transferred, info.size, progressCtx);
    }

    if (!failed)
    {
        /* The NUL that ends the file's data, and the acknowledgement that
         * says the server wrote it. */
        if (!channel.SendByte(0))
        {
            error = "The connection closed while the upload of '" +
                remotePath + "' was ending.";
            failed = true;
        }
    }
    if (!failed && !channel.ReadAcknowledgement(message))
    {
        error = message;
        failed = true;
    }
    if (failed)
    {
        /* Waiting for an exit status here would wait for a server that is
         * waiting for us: the channel is closed instead, which is the only
         * thing left to say. */
        channel.Close();
        return -1;
    }

    channel.SendEof();
    std::string errors;
    const int exitCode = channel.Finish(errors);
    if (exitCode != 0 && exitCode != INT_MAX)
    {
        error = errors.empty() ?
            "The server's scp failed with exit status " +
                std::to_string(exitCode) + " while writing '" + remotePath +
                "'." :
            errors;
        return -1;
    }
    if (size != NULL)
    {
        *size = transferred;
    }
    return 0;
}

} // namespace linscp
